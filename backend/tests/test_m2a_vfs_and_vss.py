"""
Sub-Milestone M2-A Verification Suite (`F7`, `F8`, `F27`, `F28`):
  1. Multi-Partition & Multi-Filesystem VFS Ingestion (`NTFS`, `FAT12/16/32` + `/$OrphanFiles`, `exFAT`, `ISO9660`, pure-Python ECMA-167 `UDF` + Type 2 `VAT` multi-session deleted recovery).
  2. Exact Frozen Interface Contract 2 DuckDB Schemas (`vfs_partitions`, 17-col `vfs_files`, `vfs_shadow_copies`) & indexes.
  3. Windows-Safe Forensic MACB Timestamp Preservation (`apply_forensic_utime` clamping `FILETIME==0`, pre-1970 negative epochs, unset `0 -> NULL`, and 8 `$SI`/`$FN` timestamps).
  4. Offline (`pyvshadow` primary + `DissectVSS` fallback) & Live Volume Shadow Copies (`VSS`) Differential Staging & Fault Tolerance (zero `wmic`, 5s timeouts, non-VSS / 0-store clean skips).
  5. Contract 2 Multi-User Staging Layout Hygiene (`Alice` `/Users` + `Bob` `/Documents and Settings`, `.LOG1/.LOG2`, multi-profile Browsers, `ActivitiesCache`, `WER`, `WLAN`, `wpndatabase.db`, single-archive dict return, aliases, and 16-worker SHA-256 thread safety).
"""
from __future__ import annotations

import hashlib
import io
import os
import struct
import subprocess
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import pytest

import backend.vfs.extractor as extractor_mod
from backend.config import get_case_dir
from backend.db.engine import DuckDBManager
from backend.vfs import (
    EvidenceExtractor,
    ForensicMeta,
    PartitionSubStream,
    apply_forensic_utime,
)
from backend.vfs.extractor import (
    MAX_WIN_UTIME_EPOCH,
    MIN_WIN_UTIME_EPOCH,
    _ActiveFileMeta,
    _dt_to_us,
    _epoch_to_utc,
    _filetime_to_utc,
)

# -----------------------------------------------------------------------------
# Read-Only Reference Forensic Datasets on Host (Strictly Read-Only!)
# -----------------------------------------------------------------------------
CFREDS_RM3_UDF_DD = Path(
    r"C:\Users\2482965\Desktop\cfreds_\cfreds_2015_data_leakage_rm#3_type2\cfreds_2015_data_leakage_rm#3_type2.dd"
)
CFREDS_RM2_FAT32_DD = Path(
    r"C:\Users\2482965\Desktop\cfreds_\cfreds_2015_data_leakage_rm#2\cfreds_2015_data_leakage_rm#2.dd"
)
CFREDS_RM1_EXFAT_E01 = Path(
    r"D:\wft_e2e_scratch\cfreds_e01\cfreds_2015_data_leakage_rm#1.E01"
)
PLASO_VSSTEST_QCOW2 = Path(
    r"C:\Users\2482965\Documents\Tools\plaso-20260512\test_data\vsstest.qcow2"
)
PLASO_MULTIPART_VMDK = Path(
    r"C:\Users\2482965\Documents\Tools\plaso-20260512\test_data\multi_partition_image.vmdk"
)
PLASO_ISO9660_RAW = Path(
    r"C:\Users\2482965\Documents\Tools\plaso-20260512\test_data\iso9660.raw"
)

EXPECTED_VFS_PARTITIONS_COLS = [
    "part_index",
    "label",
    "fs_type",
    "offset_bytes",
    "size_bytes",
    "volume_serial",
    "is_boot",
]
EXPECTED_VFS_FILES_COLS = [
    "part_index",
    "vfs_path",
    "staged_rel_path",
    "file_name",
    "parent_path",
    "size_bytes",
    "is_dir",
    "is_deleted",
    "si_created",
    "si_modified",
    "si_accessed",
    "si_changed",
    "fn_created",
    "fn_modified",
    "fn_accessed",
    "fn_changed",
    "mft_entry",
]
EXPECTED_VFS_SHADOW_COPIES_COLS = [
    "vss_index",
    "part_index",
    "store_id",
    "creation_time",
    "size_bytes",
    "staged_prefix",
    "files_staged",
    "status",
]


def _make_case_ctx(tmp_path: Path, prefix: str = "m2a") -> Tuple[str, Path, Path]:
    """Create an isolated case_id, case_dir, and staging_dir inside pytest tmp_path."""
    case_id = f"{prefix}_{uuid.uuid4().hex[:8]}"
    case_dir = tmp_path / case_id
    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    return case_id, case_dir, staging_dir


def _assert_contract2_schemas(case_id: str) -> None:
    """Verify exact Frozen Interface Contract 2 DuckDB table column names and indexes."""
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=True)
        part_cols = [r[0] for r in conn.execute("DESCRIBE vfs_partitions").fetchall()]
        file_cols = [r[0] for r in conn.execute("DESCRIBE vfs_files").fetchall()]
        vss_cols = [r[0] for r in conn.execute("DESCRIBE vfs_shadow_copies").fetchall()]
        idx_names = {
            r[0]
            for r in conn.execute(
                "SELECT index_name FROM duckdb_indexes() WHERE table_name = 'vfs_files'"
            ).fetchall()
        }
    assert part_cols == EXPECTED_VFS_PARTITIONS_COLS
    assert file_cols == EXPECTED_VFS_FILES_COLS
    assert vss_cols == EXPECTED_VFS_SHADOW_COPIES_COLS
    assert "idx_vfs_files_parent" in idx_names
    assert "idx_vfs_files_staged" in idx_names


def _build_fat16_partition_bytes(
    total_sectors: int,
    vol_label: bytes,
    vol_serial: int,
    files: Sequence[Tuple[bytes, bytes, bool, Tuple[int, int, int, int, int, int], bool]],
) -> bytes:
    """
    Construct a genuine, spec-compliant FAT16 partition byte image in pure Python.
    Each tuple in `files` is:
      (name_8_3_11bytes, payload_bytes, is_deleted, (yr, mo, da, hr, mi, sc), zero_atime)
    Requires total_sectors >= 4200 so cluster count >= 4085 (FAT16 threshold).
    """
    bps = 512
    spc = 1
    res_sec = 1
    num_fats = 2
    root_entries = 512
    root_dir_secs = (root_entries * 32) // bps  # 32 sectors
    spf = 20
    buf = bytearray(total_sectors * bps)

    # BIOS Parameter Block + Extended Boot Record
    buf[0:3] = b"\xeb\x3c\x90"
    buf[3:11] = b"MSDOS5.0"
    tot16 = total_sectors if total_sectors < 65536 else 0
    tot32 = total_sectors if total_sectors >= 65536 else 0
    struct.pack_into(
        "<HBHBHHBHHHII",
        buf,
        11,
        bps,
        spc,
        res_sec,
        num_fats,
        root_entries,
        tot16,
        0xF8,
        spf,
        63,
        255,
        0,
        tot32,
    )
    buf[36] = 0x80
    buf[38] = 0x29
    struct.pack_into("<I", buf, 39, vol_serial)
    buf[43:54] = vol_label[:11].ljust(11, b" ")
    buf[54:62] = b"FAT16   "
    buf[510:512] = b"\x55\xaa"

    for f_i in range(num_fats):
        foff = (res_sec + f_i * spf) * bps
        struct.pack_into("<HH", buf, foff, 0xFFF8, 0xFFFF)

    root_off = (res_sec + num_fats * spf) * bps
    data_sec0 = res_sec + num_fats * spf + root_dir_secs
    next_clus = 2

    # Entry 0: Volume Label directory entry (attr 0x08)
    buf[root_off : root_off + 11] = vol_label[:11].ljust(11, b" ")
    buf[root_off + 11] = 0x08

    for idx, (name83, data, is_del, dt_tuple, zero_atime) in enumerate(files, start=1):
        yr, mo, da, hr, mi, sc = dt_tuple
        n_clus = max(1, (len(data) + bps - 1) // bps)
        start_c = next_clus
        next_clus += n_clus

        for c_idx in range(n_clus):
            clus = start_c + c_idx
            fat_val = 0xFFFF if c_idx == n_clus - 1 else (clus + 1)
            if not is_del:
                for f_i in range(num_fats):
                    foff = (res_sec + f_i * spf) * bps + clus * 2
                    struct.pack_into("<H", buf, foff, fat_val)
            doff = (data_sec0 + (clus - 2) * spc) * bps
            chunk = data[c_idx * bps : (c_idx + 1) * bps]
            buf[doff : doff + len(chunk)] = chunk

        eoff = root_off + idx * 32
        raw_name = bytearray(name83[:11].ljust(11, b" "))
        if is_del:
            raw_name[0] = 0xE5
        buf[eoff : eoff + 11] = raw_name
        buf[eoff + 11] = 0x20  # Archive file attribute

        dos_t = ((hr & 0x1F) << 11) | ((mi & 0x3F) << 5) | ((sc // 2) & 0x1F)
        dos_d = (((yr - 1980) & 0x7F) << 9) | ((mo & 0x0F) << 5) | (da & 0x1F)
        acc_d = 0 if zero_atime else dos_d
        # Offset 14..32: crt_time, crt_date, acc_date, clus_hi, wrt_time, wrt_date, clus_lo, size
        struct.pack_into(
            "<HHHHHHHI",
            buf,
            eoff + 14,
            dos_t,
            dos_d,
            acc_d,
            0,
            dos_t,
            dos_d,
            start_c,
            len(data),
        )

    return bytes(buf)


# =============================================================================
# 1. Forensic Timestamp Clamping, Helpers & Standalone Registration Hygiene
# =============================================================================

def test_forensic_meta_and_utime_clamping_edge_cases(tmp_path: Path) -> None:
    """
    Verify Windows SetFileTime edge cases:
      - Unset 0 / None epoch or FILETIME returns None (never 1970 or host 2026 now()).
      - FILETIME == 0 (1601-01-01T00:00:00Z == -11644473600.0) is clamped to 1601-01-01T00:00:01Z
        so Win32 SetFileTime does not treat 0 as 'leave current host now() unchanged'.
      - Negative pre-1970 epochs (e.g. 1965-05-10) apply cleanly on Windows.
      - Extreme out-of-range years (1500, 9999) clamp cleanly without WinError 87.
    """
    assert _filetime_to_utc(0) is None
    assert _filetime_to_utc(-5) is None
    assert _filetime_to_utc(None) is None
    assert _epoch_to_utc(0) is None
    assert _epoch_to_utc(None) is None

    # 1. FILETIME == 0 boundary: 1601-01-01 00:00:00 UTC
    f_1601 = tmp_path / "epoch_1601.bin"
    f_1601.write_bytes(b"forensic_1601")
    meta_1601 = ForensicMeta(
        vfs_path="/epoch_1601.bin",
        si_modified=datetime(1601, 1, 1, 0, 0, 0),
        si_accessed=datetime(1601, 1, 1, 0, 0, 0),
    )
    apply_forensic_utime(f_1601, meta_1601)
    st_1601 = f_1601.stat()
    assert abs(st_1601.st_mtime - MIN_WIN_UTIME_EPOCH) <= 2.0
    assert st_1601.st_mtime < 0  # Guaranteed NOT 2026 host wall-clock now()!

    # 2. Pre-1970 negative POSIX timestamp (1965-05-10 12:30:00 UTC)
    dt_1965 = _epoch_to_utc(-146575800)
    assert dt_1965 is not None and dt_1965.year == 1965
    f_1965 = tmp_path / "pre_1970.bin"
    f_1965.write_bytes(b"forensic_1965")
    apply_forensic_utime(
        f_1965,
        ForensicMeta(vfs_path="/pre_1970.bin", si_modified=dt_1965, si_accessed=dt_1965),
    )
    mtime_1965 = _epoch_to_utc(f_1965.stat().st_mtime)
    assert mtime_1965 is not None and mtime_1965.year == 1965 and mtime_1965.month == 5

    # 3. Pre-1601 and Year-9999 clamping without raising OSError [WinError 87]
    f_extreme = tmp_path / "extreme_years.bin"
    f_extreme.write_bytes(b"extreme")
    apply_forensic_utime(
        f_extreme,
        ForensicMeta(
            vfs_path="/extreme.bin",
            si_modified=datetime(1500, 1, 1, 0, 0, 0),
            si_accessed=datetime(9999, 12, 31, 23, 59, 59),
        ),
    )
    st_ext = f_extreme.stat()
    assert abs(st_ext.st_mtime - MIN_WIN_UTIME_EPOCH) <= 2.0
    assert st_ext.st_atime <= MAX_WIN_UTIME_EPOCH + 2.0

    # 4. None / unset-timestamp ForensicMeta clamps disk (atime, mtime) to (0.0, 0.0) (never host 2026!)
    f_unset = tmp_path / "unset_meta.bin"
    f_unset.write_bytes(b"unset_ts")
    apply_forensic_utime(f_unset, ForensicMeta(vfs_path="/unset_meta.bin"))
    st_unset = f_unset.stat()
    assert abs(st_unset.st_mtime - 0.0) <= 2.0
    assert abs(st_unset.st_atime - 0.0) <= 2.0

    f_none = tmp_path / "none_meta.bin"
    f_none.write_bytes(b"none_ts")
    apply_forensic_utime(f_none, None)
    st_none = f_none.stat()
    assert abs(st_none.st_mtime - 0.0) <= 2.0
    assert abs(st_none.st_atime - 0.0) <= 2.0


def test_standalone_extractor_case_registration_and_partition_substream(tmp_path: Path) -> None:
    """
    Verify standalone EvidenceExtractor(case_id, staging_dir) registers tmp_path/case_id
    without polluting Desktop\\cases\\default\\staging, and PartitionSubStream bounds reads.
    """
    raw_backing = io.BytesIO(b"HEADER__" + b"0123456789ABCDEF" + b"__TRAILER")
    lock = extractor_mod.threading.Lock()
    sub = PartitionSubStream(raw_backing, offset=8, size=16, read_lock=lock)
    assert sub.readable() and sub.seekable()
    assert sub.read(4) == b"0123"
    assert sub.tell() == 4
    sub.seek(-4, io.SEEK_END)
    assert sub.read(10) == b"CDEF"
    assert sub.read(10) == b""

    case_id, case_dir, staging_dir = _make_case_ctx(tmp_path, "regcheck")
    src_dir = tmp_path / "mini_src"
    src_dir.mkdir()
    sample = src_dir / "Security.evtx"
    sample.write_bytes(b"ElfFile\x00" + b"\x00" * 120)
    old_ts = datetime(2016, 4, 10, 9, 0, 0, tzinfo=timezone.utc).timestamp()
    os.utime(sample, (old_ts, old_ts))

    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=4)
        assert get_case_dir(case_id).resolve() == case_dir.resolve()
        res = ext.extract_from_directory(src_dir)
        assert res["status"] == "SUCCESS"
        assert (case_dir / "case.duckdb").exists()
        _assert_contract2_schemas(case_id)
    finally:
        DuckDBManager.close_connection(case_id)


# =============================================================================
# 2. Real Read-Only CFReDS & Plaso Dataset Extraction Tests (F7, F8)
# =============================================================================

@pytest.mark.skipif(not CFREDS_RM3_UDF_DD.exists(), reason="CFReDS rm#3 UDF image not present")
def test_cfreds_rm3_udf_type2_vat_active_and_deleted_recovery(tmp_path: Path) -> None:
    """
    Verify pure-Python ECMA-167 / UDF 2.01 + Type 2 VAT multi-session reader against
    read-only cfreds_2015_data_leakage_rm#3_type2.dd ('IAMAN CD'):
      - Populates vfs_partitions with fs_type='UDF' and label='IAMAN CD'.
      - Recovers active latest-VAT files (Koala.jpg, Penguins.jpg, Tulips.jpg) with is_deleted=False.
      - Recovers prior-VAT-session deleted directories & files (/design/*, /pricing decision/*,
        /progress/*, /proposal/*, /technical review/*, /de/*) with is_deleted=True.
      - Stages files under staging/Enrichment/Part_0/<rel_path> with preserved ECMA-167 timestamps.
    """
    case_id, _, staging_dir = _make_case_ctx(tmp_path, "rm3_udf")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=8)
        res = ext.extract_from_image(CFREDS_RM3_UDF_DD)
        assert res["status"] == "SUCCESS"
        assert res["partitions_found"] == 1
        _assert_contract2_schemas(case_id)

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=True)
            part = conn.execute(
                "SELECT part_index, label, fs_type, size_bytes FROM vfs_partitions"
            ).fetchone()
            assert part is not None
            assert part[0] == 0
            assert part[1] == "IAMAN CD"
            assert part[2] == "UDF"
            assert part[3] > 100_000_000

            active_names = {
                r[0]
                for r in conn.execute(
                    "SELECT file_name FROM vfs_files WHERE NOT is_dir AND NOT is_deleted"
                ).fetchall()
            }
            assert {"Koala.jpg", "Penguins.jpg", "Tulips.jpg"}.issubset(active_names)

            deleted_paths = {
                r[0]
                for r in conn.execute(
                    "SELECT vfs_path FROM vfs_files WHERE NOT is_dir AND is_deleted"
                ).fetchall()
            }

        assert len(deleted_paths) >= 15
        for expected_prefix in (
            "/design/",
            "/pricing decision/",
            "/progress/",
            "/proposal/",
            "/technical review/",
            "/de/",
        ):
            assert any(p.startswith(expected_prefix) for p in deleted_paths), f"Missing {expected_prefix}"

        koala_staged = staging_dir / "Enrichment" / "Part_0" / "Koala.jpg"
        assert koala_staged.is_file() and koala_staged.stat().st_size > 100_000
        # JPEG SOI header verification
        assert koala_staged.read_bytes()[:3] == b"\xff\xd8\xff"
        # Forensic MACB check: must reflect original media date (< 2020), NEVER 2026 host now()!
        koala_yr = datetime.fromtimestamp(koala_staged.stat().st_mtime, tz=timezone.utc).year
        assert 2005 <= koala_yr <= 2016

        # Verify at least one historical VAT deleted document was also staged intact with forensic mtime
        staged_deleted = [
            staging_dir / "Enrichment" / "Part_0" / p.lstrip("/")
            for p in deleted_paths
        ]
        existing_deleted = [p for p in staged_deleted if p.is_file() and p.stat().st_size > 0]
        assert len(existing_deleted) >= 15
        del_yr = datetime.fromtimestamp(existing_deleted[0].stat().st_mtime, tz=timezone.utc).year
        assert 2005 <= del_yr <= 2016
    finally:
        DuckDBManager.close_connection(case_id)


@pytest.mark.skipif(not CFREDS_RM2_FAT32_DD.exists(), reason="CFReDS rm#2 FAT32 image not present")
def test_cfreds_rm2_fat32_orphan_files_recovery(tmp_path: Path) -> None:
    """
    Verify Tier B pytsk3 FAT32 + /$OrphanFiles inode resolution (fs.open_meta(inode=meta_addr))
    against read-only cfreds_2015_data_leakage_rm#2.dd.
    """
    case_id, _, staging_dir = _make_case_ctx(tmp_path, "rm2_fat32")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=8)
        res = ext.extract_from_image(CFREDS_RM2_FAT32_DD)
        assert res["status"] == "SUCCESS"
        _assert_contract2_schemas(case_id)

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=True)
            fs_types = [r[0] for r in conn.execute("SELECT fs_type FROM vfs_partitions").fetchall()]
            assert "FAT32" in fs_types

            orphan_rows = conn.execute(
                "SELECT vfs_path, staged_rel_path, size_bytes, si_modified FROM vfs_files "
                "WHERE vfs_path LIKE '/$OrphanFiles/%' AND NOT is_dir AND is_deleted"
            ).fetchall()

        # rm#2.dd is a formatted/deleted FAT32 drive where all 29 evidence folders/files sit inside /$OrphanFiles!
        assert len(orphan_rows) >= 15
        staged_orphans = [
            r for r in orphan_rows if r[1] and (staging_dir / r[1]).is_file() and r[2] > 0
        ]
        assert len(staged_orphans) >= 10
        sample_p = staging_dir / staged_orphans[0][1]
        yr = datetime.fromtimestamp(sample_p.stat().st_mtime, tz=timezone.utc).year
        assert yr <= 2016
    finally:
        DuckDBManager.close_connection(case_id)


@pytest.mark.skipif(not CFREDS_RM1_EXFAT_E01.exists(), reason="CFReDS rm#1 E01 image not present")
def test_cfreds_rm1_e01_exfat_extraction(tmp_path: Path) -> None:
    """
    Verify EWF (.E01) container opening + exFAT extraction + MACB preservation
    against read-only cfreds_2015_data_leakage_rm#1.E01.
    """
    case_id, _, staging_dir = _make_case_ctx(tmp_path, "rm1_exfat")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=8)
        res = ext.extract_from_image(CFREDS_RM1_EXFAT_E01)
        assert res["status"] == "SUCCESS"
        _assert_contract2_schemas(case_id)

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=True)
            part = conn.execute("SELECT label, fs_type FROM vfs_partitions WHERE part_index = 0").fetchone()
            assert part is not None
            assert part[1] == "exFAT"
            assert "Authorized USB" in part[0]

            rows = conn.execute(
                "SELECT vfs_path, staged_rel_path, is_deleted, si_modified FROM vfs_files WHERE NOT is_dir"
            ).fetchall()

        assert len(rows) >= 5
        assert any(not r[2] for r in rows)
        assert any(r[2] for r in rows)
        staged_non_empty = [staging_dir / r[1] for r in rows if r[1] and (staging_dir / r[1]).is_file()]
        assert len(staged_non_empty) >= 3
        yr = datetime.fromtimestamp(staged_non_empty[0].stat().st_mtime, tz=timezone.utc).year
        assert yr <= 2016
    finally:
        DuckDBManager.close_connection(case_id)


@pytest.mark.skipif(not PLASO_ISO9660_RAW.exists(), reason="Plaso iso9660.raw test image not present")
def test_iso9660_image_extraction(tmp_path: Path) -> None:
    """Verify Tier B ISO9660 superfloppy extraction and staging."""
    case_id, _, staging_dir = _make_case_ctx(tmp_path, "iso9660")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=4)
        res = ext.extract_from_image(PLASO_ISO9660_RAW)
        assert res["status"] == "SUCCESS"
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=True)
            part = conn.execute("SELECT fs_type FROM vfs_partitions WHERE part_index = 0").fetchone()
            file_cnt = conn.execute("SELECT COUNT(*) FROM vfs_files WHERE NOT is_dir").fetchone()[0]
        assert part is not None and part[0] == "ISO9660"
        assert file_cnt >= 1
    finally:
        DuckDBManager.close_connection(case_id)


# =============================================================================
# 3. Synthetic Multi-Partition MBR + Dual FAT16 & Multi-Partition NTFS VMDK (F7)
# =============================================================================

def test_synthetic_multi_partition_fat16_deleted_and_nested_zip(tmp_path: Path) -> None:
    """
    Build a genuine 2-partition MBR + FAT16 raw image in tmp_path (Part 0 @ sector 64 < 2048,
    Part 1 @ sector 5064) with active files, a deleted 0xE5 FAT entry, unset atime=0,
    and a nested .zip archive. Proves:
      - Multi-partition loop extracts BOTH Part_0 and Part_1 (no single-partition break, no >2048 sector cutoff).
      - Boot flag (is_boot=True on Part 0, False on Part 1) and volume labels are recorded.
      - Deleted entry is indexed with is_deleted=True and staged.
      - Unset FAT timestamp (0) is stored as NULL in DuckDB, never 1970 or 2026.
      - Nested .zip archive inside Part_1 is unpacked with member mtime preserved.
    """
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zi = zipfile.ZipInfo("inner_note.txt", date_time=(2017, 3, 22, 14, 10, 0))
        zf.writestr(zi, b"nested archive forensic note\n")
    zip_bytes = zip_buf.getvalue()

    part0_bytes = _build_fat16_partition_bytes(
        total_sectors=5000,
        vol_label=b"BOOT_PART  ",
        vol_serial=0xAABB1122,
        files=[
            (b"README  TXT", b"partition 0 active content\n", False, (2014, 6, 15, 10, 20, 30), True),
            (b"SECRET  TXT", b"partition 0 deleted secret\n", True, (2013, 5, 2, 8, 12, 0), True),
        ],
    )
    part1_bytes = _build_fat16_partition_bytes(
        total_sectors=5000,
        vol_label=b"DATA_PART  ",
        vol_serial=0xCCDD3344,
        files=[
            (b"REPORT  CSV", b"id,user\n1,alice\n2,bob\n", False, (2018, 11, 3, 8, 15, 0), False),
            (b"BUNDLE  ZIP", zip_bytes, False, (2018, 11, 4, 9, 0, 0), False),
        ],
    )

    p0_lba = 64  # Explicitly < 2048 sectors to prove no >2048 cutoff exists!
    p0_secs = len(part0_bytes) // 512
    p1_lba = p0_lba + p0_secs
    p1_secs = len(part1_bytes) // 512

    disk = bytearray(p0_lba * 512 + len(part0_bytes) + len(part1_bytes))
    disk[p0_lba * 512 : p0_lba * 512 + len(part0_bytes)] = part0_bytes
    disk[p1_lba * 512 : p1_lba * 512 + len(part1_bytes)] = part1_bytes

    # MBR Partition Table @ 446
    disk[446] = 0x80
    disk[446 + 4] = 0x06
    struct.pack_into("<II", disk, 446 + 8, p0_lba, p0_secs)
    disk[462] = 0x00
    disk[462 + 4] = 0x06
    struct.pack_into("<II", disk, 462 + 8, p1_lba, p1_secs)
    disk[510:512] = b"\x55\xaa"

    img_path = tmp_path / "synthetic_dual_fat16.dd"
    img_path.write_bytes(disk)

    case_id, _, staging_dir = _make_case_ctx(tmp_path, "dualfat16")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=8)
        res = ext.extract_from_image(img_path)
        assert res["status"] == "SUCCESS"
        assert res["partitions_found"] == 2
        _assert_contract2_schemas(case_id)

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=True)
            parts = conn.execute(
                "SELECT part_index, label, fs_type, offset_bytes, is_boot FROM vfs_partitions ORDER BY part_index"
            ).fetchall()
            assert len(parts) == 2
            assert parts[0][0] == 0 and parts[0][2] == "FAT16" and parts[0][3] == 64 * 512 and parts[0][4] is True
            assert parts[1][0] == 1 and parts[1][2] == "FAT16" and parts[1][3] == p1_lba * 512 and parts[1][4] is False

            # Check unset atime (0) stored as NULL in DuckDB
            readme_row = conn.execute(
                "SELECT staged_rel_path, is_deleted, si_modified, si_accessed FROM vfs_files "
                "WHERE part_index = 0 AND UPPER(file_name) = 'README.TXT'"
            ).fetchone()
            assert readme_row is not None
            assert readme_row[1] is False
            assert readme_row[2] is not None and readme_row[2].year == 2014
            assert readme_row[3] is None  # zero_atime=True -> NULL, never 1970 or 2026!

            # Deleted entry on Part 0 recovered
            del_rows = conn.execute(
                "SELECT vfs_path, staged_rel_path FROM vfs_files WHERE part_index = 0 AND is_deleted AND NOT is_dir"
            ).fetchall()
            assert len(del_rows) >= 1
            assert any((staging_dir / r[1]).read_bytes() == b"partition 0 deleted secret\n" for r in del_rows if r[1])

            # Nested ZIP member unpacked and indexed on Part 1
            inner_row = conn.execute(
                "SELECT staged_rel_path FROM vfs_files WHERE part_index = 1 AND file_name = 'inner_note.txt'"
            ).fetchone()
            assert inner_row is not None and inner_row[0] is not None

        # Verify staged files & disk MACB timestamps across both partitions + nested ZIP
        p0_readme = staging_dir / "Enrichment" / "Part_0" / "README.TXT"
        p1_report = staging_dir / "Enrichment" / "Part_1" / "REPORT.CSV"
        inner_staged = staging_dir / inner_row[0]
        assert p0_readme.read_bytes() == b"partition 0 active content\n"
        assert p1_report.read_bytes() == b"id,user\n1,alice\n2,bob\n"
        assert inner_staged.read_bytes() == b"nested archive forensic note\n"

        assert datetime.fromtimestamp(p0_readme.stat().st_mtime).year == 2014
        assert datetime.fromtimestamp(p1_report.stat().st_mtime).year == 2018
        assert datetime.fromtimestamp(inner_staged.stat().st_mtime).year == 2017
    finally:
        DuckDBManager.close_connection(case_id)


@pytest.mark.skipif(not PLASO_MULTIPART_VMDK.exists(), reason="Plaso multi_partition_image.vmdk not present")
def test_multi_partition_ntfs_vmdk_8_timestamps(tmp_path: Path) -> None:
    """
    Verify Tier A dissect NTFS across multiple NTFS partitions in a VMDK container:
      - Enumerates both NTFS partitions (no single-NTFS break!).
      - Streams Part_0_$MFT and Part_1_$MFT.
      - Extracts all 8 $SI + $FN timestamps and mft_entry in vfs_files.
    """
    case_id, _, staging_dir = _make_case_ctx(tmp_path, "multipart_ntfs")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=8)
        res = ext.extract_from_image(PLASO_MULTIPART_VMDK)
        assert res["status"] == "SUCCESS"
        assert res["partitions_found"] == 2
        assert (staging_dir / "FileSystem" / "Part_0_$MFT").is_file()
        assert (staging_dir / "FileSystem" / "Part_1_$MFT").is_file()
        assert (staging_dir / "FileSystem" / "$MFT").is_file()

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=True)
            ntfs_parts = conn.execute(
                "SELECT part_index, fs_type FROM vfs_partitions ORDER BY part_index"
            ).fetchall()
            assert ntfs_parts == [(0, "NTFS"), (1, "NTFS")]

            eight_ts_cnt = conn.execute(
                "SELECT COUNT(*) FROM vfs_files WHERE mft_entry IS NOT NULL "
                "AND si_created IS NOT NULL AND si_modified IS NOT NULL "
                "AND si_accessed IS NOT NULL AND si_changed IS NOT NULL "
                "AND fn_created IS NOT NULL AND fn_modified IS NOT NULL "
                "AND fn_accessed IS NOT NULL AND fn_changed IS NOT NULL"
            ).fetchone()[0]
            part1_files = conn.execute(
                "SELECT COUNT(*) FROM vfs_files WHERE part_index = 1 AND NOT is_dir"
            ).fetchone()[0]
        assert eight_ts_cnt >= 5
        assert part1_files >= 1
    finally:
        DuckDBManager.close_connection(case_id)


# =============================================================================
# 4. Offline & Live Volume Shadow Copies (VSS) Differential & Fault Tests (F27)
# =============================================================================

@pytest.mark.skipif(not PLASO_VSSTEST_QCOW2.exists(), reason="Plaso vsstest.qcow2 not present")
def test_offline_vss_real_qcow2_differential_staging_and_flag_gate(tmp_path: Path) -> None:
    """
    Verify offline VSS enumeration & differential staging on read-only vsstest.qcow2:
      1. When enable_vss=False: vfs_shadow_copies is empty and staging/VSS does not exist.
      2. When enable_vss=True:
         - vfs_shadow_copies records both snapshots (vss_index 1 & 2, 2013-12-04 creation_time).
         - Deleted /syslog (1,247 B in VSS_1, absent on active volume) is differentially staged
           to staging/VSS/VSS_1/Enrichment/Part_0/syslog with 2013 mtime and indexed in vfs_files
           with part_index=-1, vfs_path='/VSS_1/syslog', is_deleted=True.
         - Unchanged active files (/another_file, /syslog.gz in VSS_2) are skipped (files_staged=0).
    """
    # A. enable_vss=False gate check
    cid_off, _, stg_off = _make_case_ctx(tmp_path, "vss_off")
    try:
        ext_off = EvidenceExtractor(case_id=cid_off, staging_dir=stg_off, enable_vss=False, max_workers=4)
        res_off = ext_off.extract_from_image(PLASO_VSSTEST_QCOW2, enable_vss=False)
        assert res_off["shadow_copies"] == 0
        assert not (stg_off / "VSS").exists()
        with DuckDBManager.get_lock(cid_off):
            conn = DuckDBManager.get_connection(cid_off, read_only=True)
            assert conn.execute("SELECT COUNT(*) FROM vfs_shadow_copies").fetchone()[0] == 0
    finally:
        DuckDBManager.close_connection(cid_off)

    # B. enable_vss=True differential extraction
    cid_on, _, stg_on = _make_case_ctx(tmp_path, "vss_on")
    try:
        ext_on = EvidenceExtractor(case_id=cid_on, staging_dir=stg_on, enable_vss=True, max_workers=8)
        res_on = ext_on.extract_from_image(PLASO_VSSTEST_QCOW2, enable_vss=True)
        assert res_on["status"] == "SUCCESS"
        assert res_on["shadow_copies"] == 2
        _assert_contract2_schemas(cid_on)

        with DuckDBManager.get_lock(cid_on):
            conn = DuckDBManager.get_connection(cid_on, read_only=True)
            vss_rows = conn.execute(
                "SELECT vss_index, part_index, store_id, creation_time, staged_prefix, files_staged, status "
                "FROM vfs_shadow_copies ORDER BY vss_index"
            ).fetchall()
            assert len(vss_rows) == 2
            assert vss_rows[0][0] == 1 and vss_rows[0][1] == 0
            assert "600f0b69" in vss_rows[0][2].lower()
            assert vss_rows[0][3] is not None and vss_rows[0][3].year == 2013
            assert vss_rows[0][4] == "VSS/VSS_1"
            assert vss_rows[0][5] >= 1 and vss_rows[0][6] == "staged"

            # VSS_2 has only /another_file and /syslog.gz which are identical to active volume -> 0 staged!
            assert vss_rows[1][0] == 2 and vss_rows[1][5] == 0 and vss_rows[1][6] == "no_changes"

            syslog_vss = conn.execute(
                "SELECT part_index, staged_rel_path, size_bytes, is_deleted, si_modified "
                "FROM vfs_files WHERE vfs_path = '/VSS_1/syslog'"
            ).fetchone()
            assert syslog_vss is not None
            assert syslog_vss[0] == -1
            assert syslog_vss[2] == 1247
            assert syslog_vss[3] is True
            assert syslog_vss[4] is not None and syslog_vss[4].year == 2013

        staged_syslog = stg_on / syslog_vss[1]
        assert staged_syslog.is_file() and staged_syslog.stat().st_size == 1247
        assert datetime.fromtimestamp(staged_syslog.stat().st_mtime, tz=timezone.utc).year == 2013
        # Ensure unchanged /another_file was NOT duplicated under VSS_2
        assert not (stg_on / "VSS" / "VSS_2").exists()
    finally:
        DuckDBManager.close_connection(cid_on)


@pytest.mark.skipif(not PLASO_VSSTEST_QCOW2.exists(), reason="Plaso vsstest.qcow2 not present")
def test_offline_vss_dissect_fallback_and_non_vss_clean_handling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify:
      1. Secondary DissectVSS fallback works identically when pyvshadow is unavailable (None).
      2. Non-VSS NTFS partitions (multi_partition_image.vmdk) and 0-store VSS volumes
         return 0 snapshots cleanly without failing extraction.
    """
    # 1. Force DissectVSS fallback by setting extractor_mod.pyvshadow = None
    monkeypatch.setattr(extractor_mod, "pyvshadow", None)
    cid_fb, _, stg_fb = _make_case_ctx(tmp_path, "vss_dissect_fb")
    try:
        ext_fb = EvidenceExtractor(case_id=cid_fb, staging_dir=stg_fb, enable_vss=True, max_workers=4)
        res_fb = ext_fb.extract_from_image(PLASO_VSSTEST_QCOW2, enable_vss=True)
        assert res_fb["status"] == "SUCCESS"
        assert res_fb["shadow_copies"] == 2
        with DuckDBManager.get_lock(cid_fb):
            conn_fb = DuckDBManager.get_connection(cid_fb, read_only=True)
            fb_rows = conn_fb.execute(
                "SELECT vss_index, store_id, creation_time FROM vfs_shadow_copies ORDER BY vss_index"
            ).fetchall()
        assert len(fb_rows) == 2
        assert "600f0b69" in fb_rows[0][1].lower()
        assert fb_rows[0][2] is not None and fb_rows[0][2].year == 2013
    finally:
        DuckDBManager.close_connection(cid_fb)

    # 2. Non-VSS stream & 0-store mocked pyvshadow check
    ext_unit = EvidenceExtractor(staging_dir=tmp_path / "unit_stg")
    lock = extractor_mod.threading.Lock()
    non_vss_stream = io.BytesIO(b"\x00" * 65536)
    stores_empty, cleanup = ext_unit._open_offline_vss_stores(0, non_vss_stream, lock)
    cleanup()
    assert stores_empty == []

    class _ZeroStoreVol:
        number_of_stores = 0
        def open_file_object(self, fh: object) -> None:
            pass
        def close(self) -> None:
            pass

    class _MockPyvshadowZero:
        @staticmethod
        def check_volume_signature_file_object(fh: object) -> bool:
            return True
        @staticmethod
        def volume() -> _ZeroStoreVol:
            return _ZeroStoreVol()

    monkeypatch.setattr(extractor_mod, "pyvshadow", _MockPyvshadowZero)
    stores_z, cleanup_z = ext_unit._open_offline_vss_stores(0, non_vss_stream, lock)
    cleanup_z()
    assert stores_z == []


def test_live_vss_safe_discovery_no_wmic_and_differential_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify:
      1. Unprivileged vssadmin (rc=2, 'don't have the correct permissions') returns ([], 'permission_denied'),
         passes timeout=5, and NEVER executes 'wmic shadowcopy call create'.
      2. _collect_live_vss_differential stages deleted & modified files from an accessible shadow root
         into staging/VSS/VSS_1/... while skipping unchanged files.
    """
    executed_cmds: List[List[str]] = []

    def _fake_run(cmd: Sequence[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
        cmd_list = [str(c) for c in cmd]
        executed_cmds.append(cmd_list)
        assert "wmic" not in cmd_list[0].lower(), "FORBIDDEN wmic call detected!"
        assert kwargs.get("timeout") == 5
        return subprocess.CompletedProcess(
            args=cmd_list,
            returncode=2,
            stdout="vssadmin 1.1\nError: You don't have the correct permissions to run this command.\n",
            stderr="",
        )

    monkeypatch.setattr(extractor_mod.subprocess, "run", _fake_run)

    case_id, _, staging_dir = _make_case_ctx(tmp_path, "live_vss")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, enable_vss=True, max_workers=4)
        snaps, status = ext._discover_live_vss_snapshots()
        assert snaps == []
        assert status == "permission_denied"
        assert len(executed_cmds) == 1  # Short-circuited cleanly on perm_denied without wmic!

        # Build synthetic accessible shadow root with 1 deleted hive, 1 modified evtx, 1 unchanged file
        shadow_root = tmp_path / "mock_shadow_1"
        (shadow_root / "Windows" / "System32" / "config").mkdir(parents=True)
        (shadow_root / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
        (shadow_root / "Users" / "Alice" / "Documents").mkdir(parents=True)

        ts_2021 = datetime(2021, 7, 15, 11, 0, 0, tzinfo=timezone.utc).timestamp()

        # Deleted file (only in shadow_1, absent from active_index)
        del_doc = shadow_root / "Users" / "Alice" / "Documents" / "deleted_passwords.txt"
        del_doc.write_bytes(b"secret_vss_only_password")
        os.utime(del_doc, (ts_2021, ts_2021))

        # Modified EVTX (different content/size vs active)
        mod_evtx = shadow_root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
        mod_evtx.write_bytes(b"ElfFile\x00" + b"OLD_VSS_EVENTS" * 20)
        os.utime(mod_evtx, (ts_2021, ts_2021))

        # Unchanged file (identical size, mtime, and SHA-256 to active staged file)
        same_doc = shadow_root / "Users" / "Alice" / "Documents" / "unchanged.txt"
        same_doc.write_bytes(b"identical_active_content")
        os.utime(same_doc, (ts_2021, ts_2021))

        active_same_staged = staging_dir / "Enrichment" / "Part_0" / "Users" / "Alice" / "Documents" / "unchanged.txt"
        active_same_staged.parent.mkdir(parents=True, exist_ok=True)
        active_same_staged.write_bytes(b"identical_active_content")
        os.utime(active_same_staged, (ts_2021, ts_2021))

        active_evtx_staged = staging_dir / "Logs" / "Security.evtx"
        active_evtx_staged.parent.mkdir(parents=True, exist_ok=True)
        active_evtx_staged.write_bytes(b"ElfFile\x00" + b"NEW_ACTIVE" * 5)

        same_dt = _epoch_to_utc(same_doc.stat().st_mtime)
        active_index: Dict[Tuple[int, str], _ActiveFileMeta] = {
            (0, "/users/alice/documents/unchanged.txt"): _ActiveFileMeta(
                size_bytes=same_doc.stat().st_size,
                si_modified_us=_dt_to_us(same_dt),
                staged_path=active_same_staged,
            ),
            (0, "/windows/system32/winevt/logs/security.evtx"): _ActiveFileMeta(
                size_bytes=active_evtx_staged.stat().st_size,
                si_modified_us=_dt_to_us(datetime(2024, 1, 1)),
                staged_path=active_evtx_staged,
            ),
        }

        vfs_rows: List[Tuple[object, ...]] = []
        vss_rows: List[Tuple[object, ...]] = []
        staged_cnt = ext._collect_live_vss_differential(
            staging_path=staging_dir,
            snapshots=[
                {
                    "store_id": "{11111111-2222-3333-4444-555555555555}",
                    "creation_time": datetime(2021, 7, 15, 12, 0, 0),
                    "device_path": str(shadow_root),
                }
            ],
            active_index=active_index,
            vfs_rows=vfs_rows,
            vss_rows=vss_rows,
            eff_workers=4,
        )
        assert staged_cnt == 2
        ext._persist_vfs_tables([(0, "C:", "LIVE", 0, 1024, "", True)], vfs_rows, vss_rows)
        _assert_contract2_schemas(case_id)

        assert (staging_dir / "VSS" / "VSS_1" / "Logs" / "Security.evtx").is_file()
        del_staged = staging_dir / "VSS" / "VSS_1" / "Enrichment" / "Part_0" / "Users" / "Alice" / "Documents" / "deleted_passwords.txt"
        assert del_staged.is_file()
        assert datetime.fromtimestamp(del_staged.stat().st_mtime, tz=timezone.utc).year == 2021
        assert not (
            staging_dir / "VSS" / "VSS_1" / "Enrichment" / "Part_0" / "Users" / "Alice" / "Documents" / "unchanged.txt"
        ).exists()
    finally:
        DuckDBManager.close_connection(case_id)


# =============================================================================
# 5. Contract 2 Multi-User Staging Hygiene, Single Archive Dict Fix & Concurrency
# =============================================================================

def test_contract2_multi_user_staging_layout_and_macb_hygiene(tmp_path: Path) -> None:
    """
    Verify complete Contract 2 layout across Vista+ (/Users/Alice) and XP (/Documents and Settings/Bob):
      - System, Amcache, and Per-User Registry hives + .LOG1/.LOG2 with ZERO flat Registry/ duplicates.
      - Dynamic discovery of all Chromium profiles (Default, Profile 2, Guest Profile, WorkProfile)
        + Local State + Network/Cookies + Sessions/* + Firefox *.default-release, while excluding ShaderCache.
      - Per-user ActivitiesCache, WER (System + Users), WLAN Interfaces XML, and Notifications wpndatabase.db.
      - Original 2019 forensic mtime preserved across every staged file.
    """
    os_root = tmp_path / "win_evidence_root"
    ts_2019 = datetime(2019, 8, 20, 15, 45, 10, tzinfo=timezone.utc).timestamp()

    def _mkfile(rel: str, payload: bytes = b"forensic_payload") -> Path:
        p = os_root / Path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(payload)
        os.utime(p, (ts_2019, ts_2019))
        return p

    # System & Amcache Registry + Transaction Logs
    _mkfile("Windows/System32/config/SYSTEM", b"regf" + b"\x00" * 4096)
    _mkfile("Windows/System32/config/SYSTEM.LOG1", b"regf_log1")
    _mkfile("Windows/System32/config/SYSTEM.LOG2", b"regf_log2")
    _mkfile("Windows/System32/config/SAM", b"regf" + b"\x00" * 4096)
    _mkfile("Windows/AppCompat/Programs/Amcache.hve", b"regf" + b"\x00" * 4096)
    _mkfile("Windows/AppCompat/Programs/Amcache.hve.LOG1", b"amcache_log1")

    # Vista+ User Alice & XP User Bob Registry Hives + Logs
    _mkfile("Users/Alice/NTUSER.DAT", b"regf_alice_ntuser" + b"\x00" * 4096)
    _mkfile("Users/Alice/NTUSER.DAT.LOG1", b"alice_log1")
    _mkfile("Users/Alice/AppData/Local/Microsoft/Windows/UsrClass.dat", b"regf_alice_usrclass" + b"\x00" * 4096)
    _mkfile("Users/Alice/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1", b"alice_uc_log1")

    _mkfile("Documents and Settings/Bob/NTUSER.DAT", b"regf_bob_ntuser" + b"\x00" * 4096)
    _mkfile("Documents and Settings/Bob/NTUSER.DAT.LOG1", b"bob_log1")
    _mkfile("Documents and Settings/Bob/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat", b"regf_bob_uc" + b"\x00" * 4096)

    # Multi-profile Chrome + Edge + Firefox (plus ShaderCache non-profile noise)
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/Local State", b'{"os_crypt":{}}')
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History", b"SQLite format 3\x00default_hist")
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies", b"SQLite format 3\x00default_cookies")
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/Profile 2/History", b"SQLite format 3\x00prof2_hist")
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/Profile 2/Sessions/Session_13300", b"SNSS_session")
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/Guest Profile/Web Data", b"SQLite format 3\x00guest_web")
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/WorkProfile/Bookmarks", b'{"roots":{}}')
    _mkfile("Users/Alice/AppData/Local/Google/Chrome/User Data/ShaderCache/GPUCache/data_0", b"noisy_shader")
    _mkfile("Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/xyz987.default-release/places.sqlite", b"SQLite format 3\x00ff_places")
    _mkfile("Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/xyz987.default-release/logins.json", b'{"logins":[]}')

    # ActivitiesCache, WER (User + System), WLAN, Notifications wpndatabase.db + WAL
    _mkfile("Users/Alice/AppData/Local/ConnectedDevicesPlatform/L.Alice/ActivitiesCache.db", b"SQLite format 3\x00act_db")
    _mkfile("Users/Alice/AppData/Local/Microsoft/Windows/WER/ReportQueue/AppCrash_notepad_1/Report.wer", b"Version=1\r\n")
    _mkfile("ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_svchost_9/Report.wer", b"Version=1\r\n")
    _mkfile("ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{ABCD-1234}/CorpWiFi.xml", b"<?xml version='1.0'?><WLANProfile/>")
    _mkfile("Users/Alice/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db", b"SQLite format 3\x00wpn_db")
    _mkfile("Users/Alice/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db-wal", b"wpn_wal_bytes")

    case_id, _, staging_dir = _make_case_ctx(tmp_path, "layout_c2")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=8)
        res = ext.extract_from_directory(os_root)
        assert res["status"] == "SUCCESS"
        _assert_contract2_schemas(case_id)

        expected_staged = [
            "Registry/System/SYSTEM",
            "Registry/System/SYSTEM.LOG1",
            "Registry/System/SYSTEM.LOG2",
            "Registry/System/SAM",
            "Registry/Amcache/Amcache.hve",
            "Registry/Amcache/Amcache.hve.LOG1",
            "Registry/Users/Alice/NTUSER.DAT",
            "Registry/Users/Alice/NTUSER.DAT.LOG1",
            "Registry/Users/Alice/UsrClass.dat",
            "Registry/Users/Alice/UsrClass.dat.LOG1",
            "Registry/Users/Bob/NTUSER.DAT",
            "Registry/Users/Bob/NTUSER.DAT.LOG1",
            "Registry/Users/Bob/UsrClass.dat",
            "Browsers/Chrome/Alice/Local State",
            "Browsers/Chrome/Alice/Default/History",
            "Browsers/Chrome/Alice/Default/Network/Cookies",
            "Browsers/Chrome/Alice/Profile 2/History",
            "Browsers/Chrome/Alice/Profile 2/Sessions/Session_13300",
            "Browsers/Chrome/Alice/Guest Profile/Web Data",
            "Browsers/Chrome/Alice/WorkProfile/Bookmarks",
            "Browsers/Firefox/Alice/xyz987.default-release/places.sqlite",
            "Browsers/Firefox/Alice/xyz987.default-release/logins.json",
            "ActivitiesCache/Alice/L.Alice/ActivitiesCache.db",
            "WER/Users/Alice/AppCrash_notepad_1/Report.wer",
            "WER/System/AppCrash_svchost_9/Report.wer",
            "WLAN/Interfaces/{ABCD-1234}/CorpWiFi.xml",
            "Notifications/Alice/wpndatabase.db",
            "Notifications/Alice/wpndatabase.db-wal",
        ]
        for rel in expected_staged:
            p = staging_dir / Path(rel)
            assert p.is_file(), f"Missing Contract 2 staged file: {rel}"
            yr = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).year
            assert yr == 2019, f"MACB mtime clobbered on {rel} (got {yr})"

        # Verify Alice vs Bob hives did NOT overwrite each other and ZERO flat copies exist
        assert b"regf_alice_ntuser" in (staging_dir / "Registry/Users/Alice/NTUSER.DAT").read_bytes()
        assert b"regf_bob_ntuser" in (staging_dir / "Registry/Users/Bob/NTUSER.DAT").read_bytes()
        assert b"default_hist" in (staging_dir / "Browsers/Chrome/Alice/Default/History").read_bytes()
        assert b"prof2_hist" in (staging_dir / "Browsers/Chrome/Alice/Profile 2/History").read_bytes()
        assert not (staging_dir / "Registry" / "NTUSER.DAT").exists()
        assert not (staging_dir / "Registry" / "SYSTEM").is_file()
        assert not (staging_dir / "Registry" / "SAM").exists()
        assert not (staging_dir / "Registry" / "Amcache.hve").exists()
        assert not (staging_dir / "Browsers" / "Chrome" / "Alice" / "ShaderCache").exists()
    finally:
        DuckDBManager.close_connection(case_id)


def test_single_archive_returns_dict_and_aliases_work(tmp_path: Path) -> None:
    """
    Verify:
      1. Passing a single .zip archive to extract_from_directory / extract_from_folder / extract / extract_all
         returns a standardized Dict[str, Any] (fixing the legacy List[Path] early-return bug).
      2. Archive member timestamps are preserved on extracted & staged artifacts.
    """
    arc_path = tmp_path / "triage_bundle.zip"
    with zipfile.ZipFile(arc_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        z1 = zipfile.ZipInfo("Windows/System32/winevt/Logs/System.evtx", date_time=(2020, 4, 12, 9, 30, 0))
        zf.writestr(z1, b"ElfFile\x00" + b"\x00" * 256)
        z2 = zipfile.ZipInfo("Users/Clara/NTUSER.DAT", date_time=(2020, 4, 12, 9, 31, 0))
        zf.writestr(z2, b"regf" + b"\x00" * 4096)

    case_id, _, staging_dir = _make_case_ctx(tmp_path, "single_arc")
    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir, max_workers=4)
        res = ext.extract_from_directory(arc_path)
        assert isinstance(res, dict)
        assert res["status"] == "SUCCESS"
        assert res["mode"] == "archive"
        assert res["total_files_staged"] >= 2

        staged_evtx = staging_dir / "Logs" / "System.evtx"
        staged_ntuser = staging_dir / "Registry" / "Users" / "Clara" / "NTUSER.DAT"
        assert staged_evtx.is_file()
        assert staged_ntuser.is_file()
        assert datetime.fromtimestamp(staged_evtx.stat().st_mtime).year == 2020
        assert datetime.fromtimestamp(staged_ntuser.stat().st_mtime).year == 2020

        # Also verify extract_from_folder and extract_all aliases return Dict[str, Any]
        res_folder = ext.extract_from_folder(arc_path)
        res_all = ext.extract_all(source_path=arc_path, source_type="archive")
        assert isinstance(res_folder, dict) and res_folder["status"] == "SUCCESS"
        assert isinstance(res_all, dict) and res_all["status"] == "SUCCESS"
        _assert_contract2_schemas(case_id)
    finally:
        DuckDBManager.close_connection(case_id)


def test_16_worker_concurrent_image_extraction_sha256_integrity(tmp_path: Path) -> None:
    """
    Verify race-free multi-threaded extraction (max_workers=16 vs max_workers=1) on a 48-file
    disk image: zero torn reads, 100% identical SHA-256 hashes, and identical DuckDB vfs_files rows.
    """
    files_spec = []
    expected_hashes: Dict[str, str] = {}
    for i in range(48):
        fname_83 = f"FILE{i:04d}BIN".encode("ascii")  # 8 + 3 = 11 bytes
        payload = hashlib.sha512(f"seed_{i}".encode()).digest() * ((i % 9) + 3)
        expected_hashes[f"FILE{i:04d}.BIN"] = hashlib.sha256(payload).hexdigest()
        files_spec.append((fname_83, payload, False, (2015, (i % 12) + 1, (i % 27) + 1, 12, i % 60, 0), False))

    part_bytes = _build_fat16_partition_bytes(
        total_sectors=6000,
        vol_label=b"CONCUR16   ",
        vol_serial=0x99887766,
        files=files_spec,
    )
    img_path = tmp_path / "concur_48files.dd"
    img_path.write_bytes(part_bytes)

    cid_1, _, stg_1 = _make_case_ctx(tmp_path, "w1")
    cid_16, _, stg_16 = _make_case_ctx(tmp_path, "w16")
    try:
        res_1 = EvidenceExtractor(case_id=cid_1, staging_dir=stg_1, max_workers=1).extract_from_image(img_path, max_workers=1)
        res_16 = EvidenceExtractor(case_id=cid_16, staging_dir=stg_16, max_workers=16).extract_from_image(img_path, max_workers=16)

        assert res_1["status"] == "SUCCESS" and res_16["status"] == "SUCCESS"
        assert res_1["total_files_staged"] == 48
        assert res_16["total_files_staged"] == 48

        for fn_str, exp_sha in expected_hashes.items():
            p1 = stg_1 / "Enrichment" / "Part_0" / fn_str
            p16 = stg_16 / "Enrichment" / "Part_0" / fn_str
            assert p1.is_file() and p16.is_file()
            assert hashlib.sha256(p1.read_bytes()).hexdigest() == exp_sha
            assert hashlib.sha256(p16.read_bytes()).hexdigest() == exp_sha

        with DuckDBManager.get_lock(cid_1), DuckDBManager.get_lock(cid_16):
            c1 = DuckDBManager.get_connection(cid_1, read_only=True)
            c16 = DuckDBManager.get_connection(cid_16, read_only=True)
            rows_1 = c1.execute("SELECT vfs_path, staged_rel_path, size_bytes FROM vfs_files ORDER BY vfs_path").fetchall()
            rows_16 = c16.execute("SELECT vfs_path, staged_rel_path, size_bytes FROM vfs_files ORDER BY vfs_path").fetchall()
        assert rows_1 == rows_16
    finally:
        DuckDBManager.close_connection(cid_1)
        DuckDBManager.close_connection(cid_16)


# =============================================================================
# 6. Iteration-2 Remediation Regression Suite (Items 1–10)
# =============================================================================

def _assert_full_parent_tree_connectivity(case_id: str) -> None:
    """Assert every non-root row in vfs_files has an existing is_dir=True parent row in the same part_index."""
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=True)
        orphan_cnt = conn.execute(
            """
            SELECT COUNT(*)
            FROM vfs_files c
            WHERE c.vfs_path <> '/'
              AND NOT EXISTS (
                  SELECT 1
                  FROM vfs_files p
                  WHERE p.part_index = c.part_index
                    AND p.vfs_path = c.parent_path
                    AND p.is_dir
              )
            """
        ).fetchone()[0]
    assert orphan_cnt == 0, f"Found {orphan_cnt} disconnected parent_path rows in vfs_files"


def test_remediation_1_win32_sanitization_containment_7z_slip_and_bomb_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Verify Item #1 & #4 archive caps:
      - Hostile traversal (`..`), Users/.. username spoofing, Win32 colons (NTFS ADS), `< > " | ? *`,
        trailing dots/spaces, and reserved names (`CON`, `LPT1`) are deterministically sanitized on staging
        while keeping `vfs_path` faithful, with 0 NTFS ADS created and 100% os.listdir() parity.
      - `_resolve_contained_dst` and `_write_bytes_and_utime` enforce hard containment inside `staging_dir`.
      - `.7z` extraction validates members BEFORE extracting, rejecting `../../7z_escape.txt` and sanitizing
        colon/reserved filenames.
      - Decompression bomb limits (`MAX_ARCHIVE_MEMBER_BYTES` / `MAX_ARCHIVE_TOTAL_BYTES`) abort oversized
        members and unlink partial files cleanly.
    """
    import bz2
    import gzip
    import lzma
    import py7zr

    sentinel_root = tmp_path / "containment_box"
    sentinel_root.mkdir(parents=True, exist_ok=True)
    case_id, _, staging_dir = _make_case_ctx(sentinel_root, "sanit")

    try:
        ext = EvidenceExtractor(case_id=case_id, staging_dir=staging_dir)

        # 1. Hard containment guard unit checks
        with pytest.raises(ValueError):
            EvidenceExtractor._resolve_contained_dst(staging_dir, "../../escape_outside.txt")
        src_probe = tmp_path / "probe_in.txt"
        src_probe.write_bytes(b"evil")
        assert ext._copy_file_safe(
            src_probe, staging_dir / ".." / "escape_outside.txt", root_guard=staging_dir
        ) is False
        assert not (sentinel_root / "escape_outside.txt").exists()

        # 2. Route & stage hostile/illegal/ADS/trailing-dot/reserved paths into real NTFS staging_dir
        hostile_entries = [
            ("/sub/../../../../udf_escape_attempt.txt", "udf_escape_attempt.txt", b"escape_payload"),
            ("/Users/../../spoof_hive/NTUSER.DAT", "NTUSER.DAT", b"regf" + b"\x00" * 512),
            ("/report:secret.txt", "report:secret.txt", b"no_hidden_ntfs_ads"),
            ("/2020-05-01_12:30:45.log", "2020-05-01_12:30:45.log", b"iso_colon_log"),
            ("/bad<chars>|q?.txt", "bad<chars>|q?.txt", b"illegal_win32_chars"),
            ("/trailing_dots.txt...", "trailing_dots.txt...", b"dots_payload"),
            ("/trailing_space.txt   ", "trailing_space.txt   ", b"space_payload"),
            ("/CON.txt", "CON.txt", b"reserved_con"),
            ("/lpt1.log", "lpt1.log", b"reserved_lpt1"),
        ]
        meta_2020 = ForensicMeta(vfs_path="/test", si_modified=datetime(2020, 5, 1, 12, 30, 45))
        vfs_rows: List[Tuple[object, ...]] = []
        for vpath, fname, payload in hostile_entries:
            cat, route_rels = ext._route_vfs_artifact(
                vfs_path=vpath,
                size_bytes=len(payload),
                part_index=0,
                has_windows_os=True,
            )
            assert cat is not None and len(route_rels) >= 1
            primary_rel = route_rels[0]
            assert ".." not in Path(primary_rel).parts
            for r_rel in route_rels:
                dst = EvidenceExtractor._resolve_contained_dst(staging_dir, r_rel)
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(payload)
                apply_forensic_utime(dst, meta_2020)
            parent_p = "/" + "/".join(vpath.strip("/").split("/")[:-1]) if "/" in vpath.strip("/") else "/"
            vfs_rows.append(
                (0, vpath, primary_rel, fname, parent_p, len(payload), False, False,
                 None, meta_2020.si_modified, None, None, None, None, None, None, None)
            )

        ext._persist_vfs_tables([(0, "TEST", "UDF", 0, 4096, "", False)], vfs_rows, [])

        # Zero files escaped outside case_dir / staging_dir
        assert set(p.name for p in sentinel_root.iterdir()) == {case_id}
        # Zero NTFS ADS created (`report` carrier file must NOT exist; `report_secret.txt` holds full bytes)
        part0_enr = staging_dir / "Enrichment" / "Part_0"
        assert not (part0_enr / "report").exists()
        assert (part0_enr / "report_secret.txt").read_bytes() == b"no_hidden_ntfs_ads"
        assert (part0_enr / "2020-05-01_12_30_45.log").read_bytes() == b"iso_colon_log"
        assert (part0_enr / "_CON.txt").read_bytes() == b"reserved_con"
        assert (part0_enr / "_lpt1.log").read_bytes() == b"reserved_lpt1"

        # 100% exact os.listdir() match for every staged_rel_path (trailing dots/spaces preserved as `_`)
        actual_enr_names = set(os.listdir(part0_enr))
        for _, vpath, srel, _, _, _, _, _, *_ in vfs_rows:
            s_path = staging_dir / Path(str(srel))
            assert s_path.is_file(), f"Missing staged file for {vpath} -> {srel}"
            if s_path.parent == part0_enr:
                assert s_path.name in actual_enr_names, f"Win32 stripped trailing chars on {s_path.name}"

        # 3. Genuine .7z archive with path-traversal member + colon filename + reserved device name
        seven_z_dir = tmp_path / "seven_z_test"
        seven_z_dir.mkdir(parents=True, exist_ok=True)
        seven_z_path = seven_z_dir / "hostile_bundle.7z"
        with py7zr.SevenZipFile(seven_z_path, "w") as sz:
            sz.writestr(b"evil_7z_escape", "XX_YY/7z_escape.txt")
            # Rewrite archive header entry name in-memory BEFORE close() writes valid 7z header + CRC!
            list(sz.files)[-1]._file_info["filename"] = "../../7z_escape.txt"
            sz.writestr(b"safe_7z_content", "safe_dir/good.txt")
            sz.writestr(b"colon_7z_log", "2020:10:05.log")
            sz.writestr(b"reserved_7z_nul", "NUL.txt")

        out_7z = seven_z_dir / "sub" / "unpacked"
        extracted_7z = ext.unpack_archive(seven_z_path, out_7z)
        assert not (seven_z_dir / "7z_escape.txt").exists()
        assert not (tmp_path / "7z_escape.txt").exists()
        assert (out_7z / "safe_dir" / "good.txt").read_bytes() == b"safe_7z_content"
        assert (out_7z / "2020_10_05.log").read_bytes() == b"colon_7z_log"
        assert (out_7z / "_NUL.txt").read_bytes() == b"reserved_7z_nul"
        assert len(extracted_7z) == 3

        # 4. Decompression bomb caps on .zip and .gz
        monkeypatch.setattr(extractor_mod, "MAX_ARCHIVE_MEMBER_BYTES", 4096)
        monkeypatch.setattr(extractor_mod, "MAX_ARCHIVE_TOTAL_BYTES", 8192)

        bomb_zip = tmp_path / "mini_bomb.zip"
        with zipfile.ZipFile(bomb_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("small_ok.txt", b"A" * 1024)
            zf.writestr("oversized_bomb.bin", b"Z" * 32768)
        bomb_out = tmp_path / "bomb_zip_out"
        res_bomb = ext.unpack_archive(bomb_zip, bomb_out)
        assert (bomb_out / "small_ok.txt").read_bytes() == b"A" * 1024
        assert not (bomb_out / "oversized_bomb.bin").exists()
        assert len(res_bomb) == 1

        bomb_gz = tmp_path / "oversized_log.gz"
        with gzip.open(bomb_gz, "wb") as gf:
            gf.write(b"G" * 32768)
        gz_bomb_out = tmp_path / "bomb_gz_out"
        assert ext.unpack_archive(bomb_gz, gz_bomb_out) == []
        assert not (gz_bomb_out / "oversized_log").exists()

        # Also sanity check .bz2 and .xz bounded decompression within cap
        bz2_path = tmp_path / "tiny.txt.bz2"
        bz2_path.write_bytes(bz2.compress(b"bz2_ok_payload"))
        xz_path = tmp_path / "tiny.txt.xz"
        xz_path.write_bytes(lzma.compress(b"xz_ok_payload"))
        assert ext.unpack_archive(bz2_path, tmp_path / "bz2_out")[0].read_bytes() == b"bz2_ok_payload"
        assert ext.unpack_archive(xz_path, tmp_path / "xz_out")[0].read_bytes() == b"xz_ok_payload"
    finally:
        DuckDBManager.close_connection(case_id)


def test_remediation_2_windows_immediate_file_handle_release_no_winerror32(tmp_path: Path) -> None:
    """
    Verify Item #2:
      - Immediate `temp_img.unlink()` and `shutil.rmtree(img_dir)` succeed on Windows right after
        `extract_from_image()` on `.dd`, `.E01`, `.vmdk`, and `.qcow2` (with `enable_vss=True`),
        WITHOUT `gc.collect()` and WITHOUT `ignore_errors=True`.
      - `_open_offline_vss_stores` closes `pyvshadow.volume` immediately when 0 stores have in-volume data.
    """
    import shutil

    # Build synthetic .dd + copy real .E01, .vmdk, .qcow2 (if available) into isolated temp dirs
    part_bytes = _build_fat16_partition_bytes(
        total_sectors=2048,
        vol_label=b"UNLINKTEST ",
        vol_serial=0x12345678,
        files=[(b"HELLO   TXT", b"win32_handle_check", False, (2020, 1, 2, 3, 4, 0), False)],
    )
    dd_dir = tmp_path / "hold_dd"
    dd_dir.mkdir()
    dd_copy = dd_dir / "temp_fat16.dd"
    dd_copy.write_bytes(part_bytes)

    candidates: List[Tuple[str, Path, Path]] = [("dd", dd_dir, dd_copy)]
    for tag, src_img in [
        ("e01", CFREDS_RM1_EXFAT_E01),
        ("vmdk", PLASO_MULTIPART_VMDK),
        ("qcow2", PLASO_VSSTEST_QCOW2),
    ]:
        if src_img.exists() and src_img.stat().st_size <= 128 * 1024 * 1024:
            sub = tmp_path / f"hold_{tag}"
            sub.mkdir()
            copied = sub / src_img.name
            shutil.copyfile(src_img, copied)
            candidates.append((tag, sub, copied))

    for tag, hold_dir, img_file in candidates:
        cid, _, stg = _make_case_ctx(tmp_path, f"hdl_{tag}")
        try:
            ext = EvidenceExtractor(case_id=cid, staging_dir=stg, enable_vss=True, max_workers=4)
            res = ext.extract_from_image(img_file, enable_vss=True)
            assert res["status"] in ("SUCCESS", "WARNING")
        finally:
            DuckDBManager.close_connection(cid)

        # CRITICAL: Immediate unlink() and rmtree() with NO gc.collect() and NO ignore_errors=True!
        img_file.unlink()
        shutil.rmtree(hold_dir)
        assert not img_file.exists()
        assert not hold_dir.exists()

    # Verify _open_offline_vss_stores closes vss_vol immediately when 0 stores have in-volume data
    cid_vss, _, stg_vss = _make_case_ctx(tmp_path, "vss_zero_in_vol")
    try:
        ext_vss = EvidenceExtractor(case_id=cid_vss, staging_dir=stg_vss, enable_vss=True)
        closed_tracker = {"closed": False}

        class _FakeNoDataStore:
            def has_in_volume_data(self) -> bool:
                return False

        class _FakePyVShadowVol:
            def open_file_object(self, _fobj: object) -> None:
                pass

            def get_number_of_stores(self) -> int:
                return 2

            def get_store(self, _idx: int) -> _FakeNoDataStore:
                return _FakeNoDataStore()

            def close(self) -> None:
                closed_tracker["closed"] = True

        if extractor_mod.pyvshadow is not None:
            import threading as _th
            orig_vol_fn = extractor_mod.pyvshadow.volume
            orig_sig_fn = extractor_mod.pyvshadow.check_volume_signature_file_object
            extractor_mod.pyvshadow.volume = _FakePyVShadowVol
            extractor_mod.pyvshadow.check_volume_signature_file_object = lambda _fobj: True
            try:
                stores, cleanup = ext_vss._open_offline_vss_stores(
                    0, io.BytesIO(b"\x00" * 65536), _th.Lock()
                )
                assert stores == []
                assert closed_tracker["closed"] is True
                cleanup()
            finally:
                extractor_mod.pyvshadow.volume = orig_vol_fn
                extractor_mod.pyvshadow.check_volume_signature_file_object = orig_sig_fn
    finally:
        DuckDBManager.close_connection(cid_vss)


def test_remediation_3_pyarrow_zero_copy_bulk_insert_and_init_case_db_superset(tmp_path: Path) -> None:
    """
    Verify Item #3:
      - `_persist_vfs_tables` uses the same DuckDB connection for `register` + `INSERT INTO ... SELECT` +
        `unregister`, inserting 25,000 rows in < 3.0s with ZERO `"PyArrow bulk insert notice"` fallback logs.
      - When `init_case_db()` pre-creates the 34-column superset `vfs_files` table + `view_docs_txt`,
        `_persist_vfs_tables` preserves the superset schema, populates `_row_id`, `extension`, `is_directory`,
        `is_allocated`, `partition_index`, `vss_store_index`, and `*_utc`, and `sync_artifact_registry_counts()`
        + `SELECT * FROM view_docs_txt` succeed with zero `BinderException`s.
    """
    import time
    from backend.db.schema import init_schema, sync_artifact_registry_counts

    # Part A: 25,000-row PyArrow zero-copy benchmark & zero fallback log check
    cid_perf, cdir_perf, stg_perf = _make_case_ctx(tmp_path, "pa_25k")
    try:
        ext_perf = EvidenceExtractor(case_id=cid_perf, staging_dir=stg_perf)
        ts_2017 = datetime(2017, 9, 1, 10, 0, 0)
        bulk_rows: List[Tuple[object, ...]] = [
            (0, "/", None, "/", "/", 0, True, False, None, None, None, None, None, None, None, None, 5),
            (0, "/bulk", None, "bulk", "/", 0, True, False, ts_2017, ts_2017, None, None, None, None, None, None, 6),
        ]
        for i in range(25000):
            fn = f"item_{i:05d}.txt"
            bulk_rows.append(
                (
                    0,
                    f"/bulk/{fn}",
                    f"Enrichment/Part_0/bulk/{fn}",
                    fn,
                    "/bulk",
                    128,
                    False,
                    False,
                    ts_2017,
                    ts_2017,
                    ts_2017,
                    ts_2017,
                    ts_2017,
                    ts_2017,
                    ts_2017,
                    ts_2017,
                    100 + i,
                )
            )
        t0 = time.perf_counter()
        ext_perf._persist_vfs_tables([(0, "PERF", "NTFS", 0, 10_000_000, "AABBCCDD", True)], bulk_rows, [])
        elapsed = time.perf_counter() - t0
        assert elapsed < 3.0, f"PyArrow zero-copy bulk insert took {elapsed:.2f}s (expected < 3.0s)"
        _assert_contract2_schemas(cid_perf)

        log_path = cdir_perf / "processing.log"
        if log_path.exists():
            assert "PyArrow bulk insert notice" not in log_path.read_text(encoding="utf-8", errors="replace")
    finally:
        DuckDBManager.close_connection(cid_perf)

    # Part B: Full init_case_db() 34-column superset compatibility + view_docs_txt + sync_artifact_registry_counts
    cid_sup = f"sup_{uuid.uuid4().hex[:8]}"
    cdir_sup = get_case_dir(cid_sup)
    stg_sup = cdir_sup / "staging"
    stg_sup.mkdir(parents=True, exist_ok=True)
    src_dir = tmp_path / "sup_src_evidence"
    (src_dir / "Users" / "Alice" / "Documents").mkdir(parents=True)
    doc_p = src_dir / "Users" / "Alice" / "Documents" / "incident_notes.txt"
    doc_p.write_text("confidential incident notes", encoding="utf-8")
    ts_2021 = datetime(2021, 3, 14, 9, 26, 53, tzinfo=timezone.utc).timestamp()
    os.utime(doc_p, (ts_2021, ts_2021))

    try:
        with DuckDBManager.get_lock(cid_sup):
            conn_init = DuckDBManager.get_connection(cid_sup, read_only=False)
            init_schema(conn_init, case_id=cid_sup)

        ext_sup = EvidenceExtractor(case_id=cid_sup, staging_dir=stg_sup, max_workers=4)
        res_sup = ext_sup.extract_from_directory(src_dir)
        assert res_sup["status"] == "SUCCESS"

        with DuckDBManager.get_lock(cid_sup):
            conn = DuckDBManager.get_connection(cid_sup, read_only=False)
            # Must not raise BinderException on _row_id, extension, is_directory, or view_docs_txt!
            sync_artifact_registry_counts(conn, case_id=cid_sup)
            cols = [r[0] for r in conn.execute("DESCRIBE vfs_files").fetchall()]
            assert set(EXPECTED_VFS_FILES_COLS).issubset(set(cols))
            assert {"_row_id", "extension", "is_directory", "is_allocated", "partition_index", "si_modified_utc"}.issubset(
                set(cols)
            )
            null_row_ids = conn.execute("SELECT COUNT(*) FROM vfs_files WHERE _row_id IS NULL").fetchone()[0]
            assert null_row_ids == 0
            sup_doc = conn.execute(
                "SELECT file_name, extension, is_directory, is_allocated, partition_index "
                "FROM vfs_files WHERE file_name = 'incident_notes.txt'"
            ).fetchone()
            assert sup_doc == ("incident_notes.txt", ".txt", False, True, 0)
            # Verify view_docs_txt query executes cleanly without BinderException
            _ = conn.execute("SELECT _row_id, file_name FROM view_docs_txt").fetchall()
    finally:
        DuckDBManager.close_connection(cid_sup)
        import shutil
        shutil.rmtree(cdir_sup, ignore_errors=True)


def test_remediation_4_corrupt_e01_dd_and_single_stream_gz_bz2_xz(tmp_path: Path) -> None:
    """
    Verify Item #4:
      - 0-byte, random-garbage, and truncated-EVF-header `.E01` files do NOT raise unhandled `libewf`
        `OSError`; `extract_from_image` logs cleanly, creates empty Contract 2 tables, and returns `status="ERROR"`.
      - 0-byte and 17-byte garbage `.dd` files return `status="WARNING"` (never `"SUCCESS"`).
      - Single-file `.gz` (preserving RFC 1952 header mtime) and `vsstest.qcow2` `syslog.gz` unpack with
        ZERO `"Error extracting TAR"` errors in `processing.log`.
    """
    import gzip

    corrupt_e01s = [
        ("empty.E01", b""),
        ("garbage.E01", b"\xde\xad\xbe\xef" * 16),
        ("trunc_evf.E01", b"EVF\x09\x0d\x0a\xff\x00" + b"\x01\x00"),
    ]
    for name, payload in corrupt_e01s:
        p = tmp_path / name
        p.write_bytes(payload)
        cid, _, stg = _make_case_ctx(tmp_path, f"bad_{p.stem}")
        try:
            res = EvidenceExtractor(case_id=cid, staging_dir=stg).extract_from_image(p)
            assert res["status"] == "ERROR", f"Expected ERROR on {name}, got {res}"
            assert len(res["errors"]) >= 1
            _assert_contract2_schemas(cid)
        finally:
            DuckDBManager.close_connection(cid)
        p.unlink()  # Verify handle closed even on corrupt image failure!

    for name, payload in [("zero.dd", b""), ("tiny_garbage.dd", b"not_a_filesystem!")]:
        p = tmp_path / name
        p.write_bytes(payload)
        cid, _, stg = _make_case_ctx(tmp_path, f"baddd_{p.stem}")
        try:
            res = EvidenceExtractor(case_id=cid, staging_dir=stg).extract_from_image(p)
            assert res["status"] == "WARNING", f"Expected WARNING on {name}, got {res}"
            _assert_contract2_schemas(cid)
        finally:
            DuckDBManager.close_connection(cid)
        p.unlink()

    # Malformed CD001 ISO9660 .iso guard (preventing native pytsk3 C stack overflow on zero/OOB path_table)
    for tag, pt_sz, pt_lba in [("zero_pt", 0, 0), ("oob_pt", 10, 999999)]:
        iso_buf = bytearray(32 * 2048)  # 64 KiB (32 sectors)
        pvd_off = 16 * 2048             # 0x8000
        iso_buf[pvd_off] = 1            # Primary Volume Descriptor
        iso_buf[pvd_off + 1 : pvd_off + 6] = b"CD001"
        iso_buf[pvd_off + 6] = 1
        struct.pack_into("<I", iso_buf, pvd_off + 0x84, pt_sz)
        struct.pack_into("<I", iso_buf, pvd_off + 0x8C, pt_lba)
        term_off = 17 * 2048
        iso_buf[term_off] = 255         # Volume Descriptor Set Terminator
        iso_buf[term_off + 1 : term_off + 6] = b"CD001"
        iso_buf[term_off + 6] = 1

        iso_p = tmp_path / f"malformed_{tag}.iso"
        iso_p.write_bytes(bytes(iso_buf))
        cid_iso, _, stg_iso = _make_case_ctx(tmp_path, f"badiso_{tag}")
        try:
            ext_iso = EvidenceExtractor(case_id=cid_iso, staging_dir=stg_iso, enable_vss=True)
            res_iso = ext_iso.extract(source_path=iso_p, source_type="image", enable_vss=True)
            assert isinstance(res_iso, dict)
            assert res_iso["status"] in ("WARNING", "ERROR")
            assert len(res_iso["errors"]) >= 1
            _assert_contract2_schemas(cid_iso)
        finally:
            DuckDBManager.close_connection(cid_iso)
        iso_p.unlink()  # Immediate handle release verified!

    # Single-file .gz with 2018 RFC 1952 header mtime -> zero TAR errors + 2018 mtime preserved
    gz_file = tmp_path / "syslog.gz"
    ts_2018 = int(datetime(2018, 6, 10, 14, 20, 0, tzinfo=timezone.utc).timestamp())
    with open(gz_file, "wb") as raw_f:
        with gzip.GzipFile(filename="syslog", mode="wb", fileobj=raw_f, mtime=ts_2018) as gf:
            gf.write(b"Jun 10 14:20:00 host kernel: Linux version 4.15\n")

    cid_gz, cdir_gz, stg_gz = _make_case_ctx(tmp_path, "single_gz")
    try:
        ext_gz = EvidenceExtractor(case_id=cid_gz, staging_dir=stg_gz)
        out_files = ext_gz.unpack_archive(gz_file, tmp_path / "gz_unpacked")
        assert len(out_files) == 1
        assert out_files[0].name == "syslog"
        assert b"Linux version 4.15" in out_files[0].read_bytes()
        assert datetime.fromtimestamp(out_files[0].stat().st_mtime, tz=timezone.utc).year == 2018
        log_p = cdir_gz / "processing.log"
        if log_p.exists():
            assert "Error extracting TAR" not in log_p.read_text(encoding="utf-8", errors="replace")
    finally:
        DuckDBManager.close_connection(cid_gz)

    if PLASO_VSSTEST_QCOW2.exists():
        cid_q, cdir_q, stg_q = _make_case_ctx(tmp_path, "qcow2_clean_log")
        try:
            res_q = EvidenceExtractor(case_id=cid_q, staging_dir=stg_q, enable_vss=True).extract_from_image(
                PLASO_VSSTEST_QCOW2, enable_vss=True
            )
            assert res_q["status"] == "SUCCESS"
            log_txt = (cdir_q / "processing.log").read_text(encoding="utf-8", errors="replace")
            assert "Error extracting TAR" not in log_txt
            assert "PyArrow bulk insert notice" not in log_txt
            _assert_full_parent_tree_connectivity(cid_q)
        finally:
            DuckDBManager.close_connection(cid_q)


def test_remediation_5_and_8_tree_connectivity_and_zero_2026_timestamp_leaks(tmp_path: Path) -> None:
    """
    Verify Items #5 & #8:
      - Full `parent_path` tree connectivity across RM#3 UDF (nested `.zip_extracted` dirs), copied folders,
        single archives, and deep `/VSS_1/Users/Alice/Documents/secret.txt` hierarchies.
      - ZERO `2026` host wall-clock timestamp leaks in `vfs_files` or staged `st_mtime` across:
        (a) RM#3 UDF nested OOXML `.docx`/`.xlsx`/`.pptx`,
        (b) newly copied host folders with historical `2021` `st_mtime` (where Windows `st_birthtime` is `2026`),
        (c) single `.zip` archives with unset `(1980, 1, 1, 0, 0, 0)` member timestamps.
    """
    # (a) RM#3 UDF image check (if available on host)
    if CFREDS_RM3_UDF_DD.exists():
        cid_udf, _, stg_udf = _make_case_ctx(tmp_path, "rm3_no2026")
        try:
            res_udf = EvidenceExtractor(case_id=cid_udf, staging_dir=stg_udf, max_workers=8).extract_from_image(
                CFREDS_RM3_UDF_DD
            )
            assert res_udf["status"] == "SUCCESS"
            _assert_full_parent_tree_connectivity(cid_udf)
            with DuckDBManager.get_lock(cid_udf):
                conn = DuckDBManager.get_connection(cid_udf, read_only=True)
                leak_cnt = conn.execute(
                    """
                    SELECT COUNT(*) FROM vfs_files
                    WHERE EXTRACT(YEAR FROM si_modified) >= 2026
                       OR EXTRACT(YEAR FROM si_created) >= 2026
                       OR EXTRACT(YEAR FROM si_changed) >= 2026
                    """
                ).fetchone()[0]
            assert leak_cnt == 0, f"Found {leak_cnt} 2026+ host timestamp leaks in RM#3 UDF vfs_files!"
            for f in stg_udf.rglob("*"):
                if f.is_file():
                    yr = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).year
                    assert yr < 2026, f"Staged file {f} leaked host mtime year {yr}"
        finally:
            DuckDBManager.close_connection(cid_udf)

    # (b) Newly copied host folder where Windows NTFS st_birthtime == 2026 today,
    #     with distinct historical atime (2021-04-10) & mtime (2021-05-20) AND a nested .zip
    #     so Pass 1 archive discovery walks directories before Pass 2 builds vfs_files!
    copied_folder = tmp_path / "copied_2021_folder"
    (copied_folder / "sub" / "deep").mkdir(parents=True)
    f_hist = copied_folder / "sub" / "deep" / "evidence_2021.txt"
    f_hist.write_bytes(b"historical_2021_evidence")
    nested_z = copied_folder / "sub" / "mini_2021.zip"
    with zipfile.ZipFile(nested_z, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("inside.txt", date_time=(2021, 5, 20, 8, 15, 0)), b"in_zip")
    ts_atime_2021 = datetime(2021, 4, 10, 6, 30, 0, tzinfo=timezone.utc).timestamp()
    ts_mtime_2021 = datetime(2021, 5, 20, 8, 15, 0, tzinfo=timezone.utc).timestamp()
    # Set utime from deepest leaf up to root so parent dir timestamps stay historical!
    os.utime(f_hist, (ts_atime_2021, ts_mtime_2021))
    os.utime(nested_z, (ts_atime_2021, ts_mtime_2021))
    os.utime(copied_folder / "sub" / "deep", (ts_atime_2021, ts_mtime_2021))
    os.utime(copied_folder / "sub", (ts_atime_2021, ts_mtime_2021))
    os.utime(copied_folder, (ts_atime_2021, ts_mtime_2021))

    cid_fld, _, stg_fld = _make_case_ctx(tmp_path, "fld_no2026")
    try:
        res_fld = EvidenceExtractor(case_id=cid_fld, staging_dir=stg_fld).extract_from_directory(copied_folder)
        assert res_fld["status"] == "SUCCESS"
        _assert_full_parent_tree_connectivity(cid_fld)
        with DuckDBManager.get_lock(cid_fld):
            conn = DuckDBManager.get_connection(cid_fld, read_only=True)
            leaks = conn.execute(
                """
                SELECT vfs_path, si_created, si_modified, si_accessed, si_changed
                FROM vfs_files
                WHERE EXTRACT(YEAR FROM si_created) >= 2026
                   OR EXTRACT(YEAR FROM si_modified) >= 2026
                   OR EXTRACT(YEAR FROM si_accessed) >= 2026
                   OR EXTRACT(YEAR FROM si_changed) >= 2026
                """
            ).fetchall()
            assert leaks == [], f"Host copy 2026 birthtime/atime/ctime leaked into vfs_files: {leaks}"
            row_f = conn.execute(
                "SELECT EXTRACT(YEAR FROM si_created), EXTRACT(YEAR FROM si_modified), "
                "EXTRACT(YEAR FROM si_accessed), EXTRACT(MONTH FROM si_accessed), si_changed "
                "FROM vfs_files WHERE file_name = 'evidence_2021.txt'"
            ).fetchone()
            assert row_f == (2021, 2021, 2021, 4, None)
            dir_atimes = conn.execute(
                "SELECT vfs_path, EXTRACT(YEAR FROM si_accessed), EXTRACT(MONTH FROM si_accessed) "
                "FROM vfs_files WHERE vfs_path IN ('/', '/sub', '/sub/deep') ORDER BY vfs_path"
            ).fetchall()
            assert dir_atimes == [("/", 2021, 4), ("/sub", 2021, 4), ("/sub/deep", 2021, 4)]
    finally:
        DuckDBManager.close_connection(cid_fld)

    # (c) Single .zip with unset (1980, 1, 1, 0, 0, 0) OOXML-style member + VSS ancestor synthesis
    ooxml_zip = tmp_path / "doc_2019.zip"
    with zipfile.ZipFile(ooxml_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zi = zipfile.ZipInfo("[Content_Types].xml", date_time=(1980, 1, 1, 0, 0, 0))
        zf.writestr(zi, b"<Types/>")
    ts_2019 = datetime(2019, 11, 11, 11, 11, 0, tzinfo=timezone.utc).timestamp()
    os.utime(ooxml_zip, (ts_2019, ts_2019))

    cid_arc, _, stg_arc = _make_case_ctx(tmp_path, "arc_no2026")
    try:
        ext_arc = EvidenceExtractor(case_id=cid_arc, staging_dir=stg_arc)
        res_arc = ext_arc.extract_from_directory(ooxml_zip)
        assert res_arc["status"] == "SUCCESS"
        _assert_full_parent_tree_connectivity(cid_arc)
        with DuckDBManager.get_lock(cid_arc):
            conn = DuckDBManager.get_connection(cid_arc, read_only=True)
            arc_leaks = conn.execute(
                "SELECT COUNT(*) FROM vfs_files WHERE EXTRACT(YEAR FROM si_modified) >= 2026 OR EXTRACT(YEAR FROM si_created) >= 2026"
            ).fetchone()[0]
            assert arc_leaks == 0

        # Verify VSS deep path synthesizes `/`, `/VSS_1`, `/VSS_1/Users`, `/VSS_1/Users/Alice`, `/VSS_1/Users/Alice/Documents`
        ext_arc._persist_vfs_tables(
            [(0, "OS", "NTFS", 0, 4096, "", True)],
            [
                (
                    -1,
                    "/VSS_1/Users/Alice/Documents/secret.txt",
                    "VSS/VSS_1/Enrichment/Part_0/Users/Alice/Documents/secret.txt",
                    "secret.txt",
                    "/VSS_1/Users/Alice/Documents",
                    10,
                    False,
                    False,
                    datetime(2020, 1, 1),
                    datetime(2020, 1, 1),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    99,
                )
            ],
            [],
        )
        _assert_full_parent_tree_connectivity(cid_arc)
        with DuckDBManager.get_lock(cid_arc):
            conn = DuckDBManager.get_connection(cid_arc, read_only=True)
            vss_children = conn.execute(
                "SELECT vfs_path, is_dir FROM vfs_files WHERE part_index = -1 AND parent_path = '/VSS_1'"
            ).fetchall()
            assert vss_children == [("/VSS_1/Users", True)]
    finally:
        DuckDBManager.close_connection(cid_arc)


def test_remediation_6_7_9_hardlinks_multipart_mft_vss_fn_collisions_and_selected_artifacts(
    tmp_path: Path,
) -> None:
    """
    Verify Items #6, #7, & #9:
      - Item #6: `_extract_ntfs_fn_links` collapses DOS 8.3 (`flags == 2`) ONLY within the same parent MFT
        segment while preserving multiple hardlinks in the same or different parent directories.
      - Item #7: `extract_meta_dissect` unwraps up to 4 wrapper hops (populating `mft_entry` & `fn_*` on VSS
        rows), and `_route_vfs_artifact("/$MFT", "$MFT", part_index)` routes per-partition `FileSystem/Part_<idx>_$MFT`.
      - Item #9: Concurrent/duplicate routed paths (`Logs/Security.evtx` collisions and active+deleted same-name
        FAT16 entries) disambiguate cleanly without overwriting, and `selected_artifacts=["fs_vss"]` gates VSS.
    """
    # 1. Item #6: Multi-$FILE_NAME (0x30) hardlink preservation vs DOS 8.3 collapse
    def _mk_fn(name: str, flags: int, parent_seg: int) -> object:
        raw_attr = type(
            "FNRaw",
            (),
            {
                "ParentDirectory": parent_seg,
                "CreationTime": 0,
                "LastModificationTime": 0,
                "LastAccessTime": 0,
                "LastChangeTime": 0,
                "FileAttributes": 0x20,
                "FileSize": 64,
            },
        )()
        return type("FNItem", (), {"file_name": name, "flags": flags, "attr": raw_attr})()

    links_raw, _, _ = extractor_mod._extract_ntfs_fn_links(
        [
            _mk_fn("LongReportFile.txt", 1, 5),       # Win32 in dir 5
            _mk_fn("LONGRE~1.TXT", 2, 5),             # DOS 8.3 alias in dir 5 -> collapsed!
            _mk_fn("HardlinkInSameDir.txt", 0, 5),    # POSIX hardlink in dir 5 -> preserved!
            _mk_fn("HardlinkInOtherDir.txt", 3, 42),  # Win32&DOS hardlink in dir 42 -> preserved!
        ]
    )
    assert [(p, nm) for p, nm, _ in links_raw] == [
        (5, "LongReportFile.txt"),
        (5, "HardlinkInSameDir.txt"),
        (42, "HardlinkInOtherDir.txt"),
    ]

    # Optional fast read-only check on cfreds_2015_data_leakage_pc.dd MFT 15356 (< 0.2s, zero full scan!)
    cfreds_pc_dd = Path(r"D:\wft_e2e_scratch\cfreds_pc\cfreds_2015_data_leakage_pc.dd")
    if cfreds_pc_dd.exists() and extractor_mod.dissect is not None:
        tgt = extractor_mod.dissect.target.Target.open(str(cfreds_pc_dd))
        try:
            ntfs_fs = [fs for fs in getattr(tgt, "filesystems", []) if hasattr(fs, "ntfs") and fs.ntfs is not None]
            if ntfs_fs:
                seg_15356 = ntfs_fs[-1].ntfs.mft.get(15356)
                fn_list_15356 = [getattr(f, "attribute", f) for f in seg_15356.attributes.get(48, [])]
                real_links, _, _ = extractor_mod._extract_ntfs_fn_links(fn_list_15356)
                assert len(real_links) >= 2, f"Expected >=2 hardlinks on MFT 15356, got {real_links}"
        finally:
            extractor_mod._close_dissect_target(tgt)

    # 2. Item #7: 4-hop extract_meta_dissect unwrap + per-partition Part_<idx>_$MFT routing
    ts_ft = 132539328000000000  # 2021-01-01T00:00:00Z in NTFS FILETIME
    raw_times = type(
        "RawTimes",
        (),
        {
            "CreationTime": ts_ft,
            "LastModificationTime": ts_ft,
            "LastAccessTime": ts_ft,
            "LastChangeTime": ts_ft,
            "FileSize": 128,
        },
    )()
    fn_inner = type("FN0x30", (), {"flags": 1, "file_name": "test.txt", "attr": raw_times})()
    si_inner = type("SI0x10", (), {"attr": raw_times})()
    mft_rec = type(
        "MftRec",
        (),
        {
            "segment": 4242,
            "attributes": {
                16: [type("A10", (), {"attribute": si_inner})()],
                48: [type("A30", (), {"attribute": fn_inner})()],
            },
        },
    )()
    hop3 = type("Hop3", (), {"record": mft_rec})()
    hop2 = type("Hop2", (), {"_entry": hop3})()
    hop1 = type("Hop1", (), {"_entry": hop2})()
    meta_4hop = extractor_mod.extract_meta_dissect(hop1, "/VSS_1/test.txt", -1, "NTFS", vss_id=1)
    assert meta_4hop.mft_entry == 4242
    assert meta_4hop.fn_modified == datetime(2021, 1, 1, 0, 0, 0)

    cid_sel, _, stg_sel = _make_case_ctx(tmp_path, "sel_art")
    try:
        ext_rt = EvidenceExtractor(cid_sel, stg_sel)
        _, loose_mft_rels = ext_rt._route_vfs_artifact("/$MFT", 4096, 0, False, allow_loose_folder_rules=True)
        assert "FileSystem/$MFT" in loose_mft_rels
        assert EvidenceExtractor(cid_sel, stg_sel, selected_artifacts=["registry", "fs_vss"]).enable_vss is True
        assert EvidenceExtractor(cid_sel, stg_sel, selected_artifacts=["registry"]).enable_vss is False
        ext_sel = EvidenceExtractor(cid_sel, stg_sel, enable_vss=False)
        assert ext_sel._resolve_vss(False, ["fs_vss"]) is True   # Default enable_vss=False + selected_artifacts=["fs_vss"] enables VSS
        assert ext_sel._resolve_vss(False, ["vss"]) is True
        assert ext_sel._resolve_vss(False, ["registry"]) is False
    finally:
        DuckDBManager.close_connection(cid_sel)

    if PLASO_MULTIPART_VMDK.exists():
        cid_mp, _, stg_mp = _make_case_ctx(tmp_path, "mp_mft_rels")
        try:
            res_mp = EvidenceExtractor(case_id=cid_mp, staging_dir=stg_mp).extract_from_image(PLASO_MULTIPART_VMDK)
            assert res_mp["status"] == "SUCCESS"
            with DuckDBManager.get_lock(cid_mp):
                conn = DuckDBManager.get_connection(cid_mp, read_only=True)
                mft_rows = conn.execute(
                    "SELECT part_index, staged_rel_path FROM vfs_files WHERE vfs_path = '/$MFT' ORDER BY part_index"
                ).fetchall()
            for p_idx, s_rel in mft_rows:
                assert s_rel == f"FileSystem/Part_{p_idx}_$MFT"
                assert (stg_mp / Path(s_rel)).is_file()
        finally:
            DuckDBManager.close_connection(cid_mp)

    if PLASO_VSSTEST_QCOW2.exists():
        cid_vfn, _, stg_vfn = _make_case_ctx(tmp_path, "vss_fn4hop")
        try:
            EvidenceExtractor(case_id=cid_vfn, staging_dir=stg_vfn, enable_vss=True).extract_from_image(
                PLASO_VSSTEST_QCOW2, enable_vss=True
            )
            with DuckDBManager.get_lock(cid_vfn):
                conn = DuckDBManager.get_connection(cid_vfn, read_only=True)
                vss_meta_rows = conn.execute(
                    "SELECT mft_entry, fn_modified FROM vfs_files "
                    "WHERE part_index = -1 AND NOT is_dir AND mft_entry IS NOT NULL AND fn_modified IS NOT NULL"
                ).fetchall()
                assert len(vss_meta_rows) >= 1, "Expected VSS NTFS rows to populate mft_entry and fn_modified!"
                part0_mft = conn.execute(
                    "SELECT staged_rel_path FROM vfs_files WHERE part_index = 0 AND vfs_path = '/$MFT'"
                ).fetchone()
                assert part0_mft == ("FileSystem/Part_0_$MFT",)
        finally:
            DuckDBManager.close_connection(cid_vfn)

    # Duplicate routed Logs/Security.evtx in directory ingestion -> neither overwrites the other
    dup_root = tmp_path / "dup_evtx_src"
    p_evtx_1 = dup_root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    p_evtx_2 = dup_root / "BackupCopy" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    p_evtx_1.parent.mkdir(parents=True, exist_ok=True)
    p_evtx_2.parent.mkdir(parents=True, exist_ok=True)
    p_evtx_1.write_bytes(b"ElfFile\x00PRIMARY_EVTX")
    p_evtx_2.write_bytes(b"ElfFile\x00BACKUP_EVTX")

    cid_dup, _, stg_dup = _make_case_ctx(tmp_path, "dup_evtx")
    try:
        res_dup = EvidenceExtractor(cid_dup, stg_dup, max_workers=4).extract_from_directory(dup_root)
        assert res_dup["status"] == "SUCCESS"
        staged_logs = list((stg_dup / "Logs").glob("Security*.evtx"))
        assert len(staged_logs) == 2
        assert {p.read_bytes() for p in staged_logs} == {b"ElfFile\x00PRIMARY_EVTX", b"ElfFile\x00BACKUP_EVTX"}
    finally:
        DuckDBManager.close_connection(cid_dup)

    # Colliding same-name entries + deleted entry in FAT16 -> all staged with distinct disambiguated paths & payloads
    fat_dup_bytes = _build_fat16_partition_bytes(
        total_sectors=2048,
        vol_label=b"DELCOLLIDE ",
        vol_serial=0x55667788,
        files=[
            (b"SECRET  TXT", b"ACTIVE_SECRET_V2", False, (2022, 2, 2, 10, 0, 0), False),
            (b"SECRET  TXT", b"COLLIDE_SECRET_V1", False, (2021, 6, 1, 9, 0, 0), True),
            (b"_ECRET  TXT", b"ACTIVE_UNDERSCORE", False, (2022, 3, 3, 11, 0, 0), False),
            (b"SECRET  TXT", b"DELETED_SECRET_V0", True, (2020, 1, 1, 8, 0, 0), False),
        ],
    )
    fat_dup_img = tmp_path / "fat_collide.dd"
    fat_dup_img.write_bytes(fat_dup_bytes)
    cid_fc, _, stg_fc = _make_case_ctx(tmp_path, "fat_col")
    try:
        res_fc = EvidenceExtractor(cid_fc, stg_fc, max_workers=4).extract_from_image(fat_dup_img)
        assert res_fc["status"] == "SUCCESS"
        with DuckDBManager.get_lock(cid_fc):
            conn = DuckDBManager.get_connection(cid_fc, read_only=True)
            sec_rows = conn.execute(
                "SELECT is_deleted, staged_rel_path FROM vfs_files WHERE NOT is_dir ORDER BY is_deleted, vfs_path"
            ).fetchall()
        assert len(sec_rows) == 4
        assert len({r[1] for r in sec_rows}) == 4
        staged_payloads = {(stg_fc / Path(r[1])).read_bytes() for r in sec_rows}
        assert staged_payloads == {
            b"ACTIVE_SECRET_V2",
            b"COLLIDE_SECRET_V1",
            b"ACTIVE_UNDERSCORE",
            b"DELETED_SECRET_V0",
        }
    finally:
        DuckDBManager.close_connection(cid_fc)

    # 4. Item #10: Clean UTF-8 without BOM (0xEF 0xBB 0xBF) across owned VFS modules
    repo_root = Path(__file__).resolve().parents[2]
    for rel_mod in ("backend/vfs/__init__.py", "backend/vfs/extractor.py", "backend/tests/test_m2a_vfs_and_vss.py"):
        raw_head = (repo_root / rel_mod).read_bytes()[:3]
        assert raw_head != b"\xef\xbb\xbf", f"UTF-8 BOM detected on {rel_mod}!"


def test_remediation_10_iso9660_svd_beyond_16_sectors_and_disk_utime_zero_2026(
    tmp_path: Path,
) -> None:
    """
    Verify Wave-2 Challenger Remediations:
      1. `_validate_iso9660_pvd_before_pytsk3` scans Volume Descriptors across up to 256 sectors
         until Volume Descriptor Set Terminator (`vd_type == 255`), rejecting malformed SVDs/PVDs
         at `sec_i >= 16` (`+0x10800`), missing terminators, and invalid `logical_block_size` so
         child-process `extract_from_image` returns `returncode == 0` (zero `0xC00000FD` stack overflow)
         and immediately releases the `.iso` file handle (`unlink()`).
      2. Single-archive OOXML `1980-01-01` `.zip`, `.bz2`, `mtime=0` `.gz`, folder-with-archives,
         and NTFS `$MFT`/`$J`/nested-archive/VSS staging preserve `staging/Extracted_Archives` while
         ensuring 100% of files under `staging_dir.rglob("*")` satisfy `st_mtime < 2026` and `st_atime < 2026`.
    """
    import bz2
    import gzip
    import sys

    def _assert_zero_2026_disk_stats(root_dir: Path, label: str) -> None:
        files = [f for f in root_dir.rglob("*") if f.is_file()]
        assert len(files) >= 1, f"Expected >=1 staged file in {label} ({root_dir})"
        bad = []
        for f in files:
            st = f.stat()
            m_yr = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).year
            a_yr = datetime.fromtimestamp(st.st_atime, tz=timezone.utc).year
            if m_yr >= 2026 or a_yr >= 2026:
                bad.append((f.relative_to(root_dir).as_posix(), m_yr, a_yr))
        assert bad == [], f"Disk 2026 st_mtime/st_atime leak in {label}: {bad}"

    # -------------------------------------------------------------------------
    # Part (i): ISO9660 sec_i = 17 (+0x10800) malformed SVD child-process guard
    # -------------------------------------------------------------------------
    iso_dir = tmp_path / "iso_svd17_dir"
    iso_dir.mkdir()
    iso_svd17 = iso_dir / "svd_sec17.iso"

    buf_iso = bytearray(96 * 2048)
    pvd = bytearray(2048)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    struct.pack_into("<I", pvd, 0x50, 96)
    struct.pack_into(">I", pvd, 0x54, 96)
    struct.pack_into("<H", pvd, 0x80, 2048)
    struct.pack_into(">H", pvd, 0x82, 2048)
    struct.pack_into("<I", pvd, 0x84, 10)
    struct.pack_into(">I", pvd, 0x88, 10)
    struct.pack_into("<I", pvd, 0x8C, 40)
    buf_iso[16 * 2048 : 17 * 2048] = pvd

    boot_vd = bytearray(2048)
    boot_vd[0] = 0
    boot_vd[1:6] = b"CD001"
    boot_vd[6] = 1
    for i in range(1, 17):  # sec_i = 1..16 (16 Boot Records)
        buf_iso[(16 + i) * 2048 : (17 + i) * 2048] = boot_vd

    # Malformed SVD at sec_i = 17 (LBA 33, offset +0x10800): path_table_size=0, type_l_path_table=0
    svd_bad = bytearray(pvd)
    svd_bad[0] = 2
    struct.pack_into("<I", svd_bad, 0x84, 0)
    struct.pack_into(">I", svd_bad, 0x88, 0)
    struct.pack_into("<I", svd_bad, 0x8C, 0)
    buf_iso[33 * 2048 : 34 * 2048] = svd_bad

    term_vd = bytearray(2048)
    term_vd[0] = 255
    term_vd[1:6] = b"CD001"
    term_vd[6] = 1
    buf_iso[34 * 2048 : 35 * 2048] = term_vd
    iso_svd17.write_bytes(bytes(buf_iso))

    # Also unit-verify missing terminator and invalid logical_block_size=0 rejection
    no_term_buf = bytearray(buf_iso)
    no_term_buf[33 * 2048 : 35 * 2048] = boot_vd * 2
    ok_nt, err_nt = extractor_mod._validate_iso9660_pvd_before_pytsk3(
        io.BytesIO(bytes(no_term_buf)), 0, len(no_term_buf), extractor_mod.threading.Lock()
    )
    assert ok_nt is False and err_nt is not None

    bad_bs_buf = bytearray(36 * 2048)
    pvd_bs0 = bytearray(pvd)
    struct.pack_into("<H", pvd_bs0, 0x80, 0)
    bad_bs_buf[16 * 2048 : 17 * 2048] = pvd_bs0
    bad_bs_buf[17 * 2048 : 18 * 2048] = term_vd
    ok_bs, err_bs = extractor_mod._validate_iso9660_pvd_before_pytsk3(
        io.BytesIO(bytes(bad_bs_buf)), 0, len(bad_bs_buf), extractor_mod.threading.Lock()
    )
    assert ok_bs is False and err_bs is not None

    repo_root = Path(__file__).resolve().parents[2]
    child_stg = tmp_path / "child_iso_stg"
    child_code = (
        "from pathlib import Path\n"
        "from backend.db.engine import DuckDBManager\n"
        "from backend.vfs.extractor import EvidenceExtractor\n"
        f"iso_p = Path({str(iso_svd17)!r})\n"
        f"stg_p = Path({str(child_stg)!r})\n"
        "cid = 'child_svd17'\n"
        "try:\n"
        "    res = EvidenceExtractor(cid, stg_p).extract_from_image(iso_p)\n"
        "    assert res['status'] in ('WARNING', 'ERROR')\n"
        "finally:\n"
        "    DuckDBManager.close_connection(cid)\n"
        "iso_p.unlink()\n"
        "print('ISO_SVD17_CLEAN_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-B", "-c", child_code],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"Child crashed (rc={proc.returncode} / 0x{proc.returncode & 0xFFFFFFFF:08X}): "
        f"stdout={proc.stdout!r}, stderr={proc.stderr!r}"
    )
    assert "ISO_SVD17_CLEAN_OK" in proc.stdout
    assert not iso_svd17.exists()

    # -------------------------------------------------------------------------
    # Part (ii): Zero 2026 disk st_mtime/st_atime leaks + Extracted_Archives kept
    # -------------------------------------------------------------------------
    ts_2018 = datetime(2018, 6, 15, 8, 30, 0, tzinfo=timezone.utc).timestamp()
    ts_2020 = datetime(2020, 1, 10, 14, 45, 0, tzinfo=timezone.utc).timestamp()

    # 1. Single OOXML 1980-01-01 .zip
    single_zip = tmp_path / "single_ooxml_2018.zip"
    with zipfile.ZipFile(single_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("[Content_Types].xml", date_time=(1980, 1, 1, 0, 0, 0)), b"<Types/>")
        zf.writestr(zipfile.ZipInfo("normal_2018.txt", date_time=(2018, 6, 15, 8, 30, 0)), b"dated")
    os.utime(single_zip, (ts_2018, ts_2020))

    cid_sz, _, stg_sz = _make_case_ctx(tmp_path, "r10_szip")
    try:
        res_sz = EvidenceExtractor(cid_sz, stg_sz, max_workers=4).extract_from_directory(single_zip)
        assert res_sz["status"] == "SUCCESS"
        assert (stg_sz / "Extracted_Archives").is_dir()
        _assert_zero_2026_disk_stats(stg_sz, "single_ooxml_zip")
        with DuckDBManager.get_lock(cid_sz):
            conn = DuckDBManager.get_connection(cid_sz, read_only=True)
            ct_row = conn.execute(
                "SELECT si_modified, si_accessed FROM vfs_files WHERE file_name = '[Content_Types].xml'"
            ).fetchone()
            assert ct_row == (None, None)
    finally:
        DuckDBManager.close_connection(cid_sz)

    # 2. Single .bz2 and mtime=0 .gz
    single_bz2 = tmp_path / "single_2020.txt.bz2"
    single_bz2.write_bytes(bz2.compress(b"bzip2 forensic stream payload"))
    os.utime(single_bz2, (ts_2018, ts_2020))

    cid_bz, _, stg_bz = _make_case_ctx(tmp_path, "r10_sbz2")
    try:
        res_bz = EvidenceExtractor(cid_bz, stg_bz).extract_from_directory(single_bz2)
        assert res_bz["status"] == "SUCCESS"
        assert (stg_bz / "Extracted_Archives").is_dir()
        _assert_zero_2026_disk_stats(stg_bz, "single_bz2")
    finally:
        DuckDBManager.close_connection(cid_bz)

    single_gz0 = tmp_path / "zero_hdr.log.gz"
    with open(single_gz0, "wb") as raw_gz:
        with gzip.GzipFile(filename="zero_hdr.log", mode="wb", fileobj=raw_gz, mtime=0) as gf:
            gf.write(b"mtime zero gzip stream\n")
    os.utime(single_gz0, (ts_2018, ts_2020))

    cid_gz0, _, stg_gz0 = _make_case_ctx(tmp_path, "r10_sgz0")
    try:
        res_gz0 = EvidenceExtractor(cid_gz0, stg_gz0).extract_from_directory(single_gz0)
        assert res_gz0["status"] == "SUCCESS"
        assert (stg_gz0 / "Extracted_Archives").is_dir()
        _assert_zero_2026_disk_stats(stg_gz0, "single_gz_mtime0")
    finally:
        DuckDBManager.close_connection(cid_gz0)

    # 3. Folder with nested .zip + .bz2 + regular file
    fld_src = tmp_path / "fld_nested_2018"
    fld_src.mkdir()
    f_reg = fld_src / "readme_2018.txt"
    f_reg.write_bytes(b"folder readme")
    f_arc = fld_src / "bundle.zip"
    with zipfile.ZipFile(f_arc, "w") as zf:
        zf.writestr(zipfile.ZipInfo("ooxml_1980.xml", date_time=(1980, 1, 1, 0, 0, 0)), b"<doc/>")
        zf.writestr(zipfile.ZipInfo("dated_2018.txt", date_time=(2018, 6, 15, 8, 30, 0)), b"hello")
    f_bz = fld_src / "note.txt.bz2"
    f_bz.write_bytes(bz2.compress(b"nested bz2"))
    for p_it in (f_reg, f_arc, f_bz, fld_src):
        os.utime(p_it, (ts_2018, ts_2020))

    cid_fn, _, stg_fn = _make_case_ctx(tmp_path, "r10_fld")
    try:
        res_fn = EvidenceExtractor(cid_fn, stg_fn, max_workers=4).extract_from_directory(fld_src)
        assert res_fn["status"] == "SUCCESS"
        assert (stg_fn / "Extracted_Archives").is_dir()
        _assert_zero_2026_disk_stats(stg_fn, "folder_nested_archives")
    finally:
        DuckDBManager.close_connection(cid_fn)

    # 4. NTFS image ($MFT + $UsnJrnl:$J + nested syslog.gz + VSS) & UDF nested archives
    if PLASO_VSSTEST_QCOW2.exists():
        cid_nt, _, stg_nt = _make_case_ctx(tmp_path, "r10_ntfs_vss")
        try:
            res_nt = EvidenceExtractor(cid_nt, stg_nt, enable_vss=True, max_workers=4).extract_from_image(
                PLASO_VSSTEST_QCOW2, enable_vss=True
            )
            assert res_nt["status"] == "SUCCESS"
            assert (stg_nt / "FileSystem" / "Part_0_$MFT").is_file()
            _assert_zero_2026_disk_stats(stg_nt, "vsstest_qcow2_ntfs_vss")
        finally:
            DuckDBManager.close_connection(cid_nt)

    if PLASO_MULTIPART_VMDK.exists():
        cid_vm, _, stg_vm = _make_case_ctx(tmp_path, "r10_vmdk")
        orig_open = extractor_mod.dissect.target.Target.open if extractor_mod.dissect is not None else None
        try:
            if orig_open is not None:
                def _open_with_synth_usn(path_arg: str):
                    t_obj = orig_open(path_arg)
                    for fs_obj in getattr(t_obj, "filesystems", []):
                        nt_obj = getattr(fs_obj, "ntfs", None)
                        if nt_obj is not None and getattr(nt_obj, "usnjrnl", None) is None:
                            nt_obj.usnjrnl = type("SynthUsn", (), {"fh": io.BytesIO(b"USN_J_STREAM_TEST" * 16), "record": None})()
                    return t_obj
                extractor_mod.dissect.target.Target.open = _open_with_synth_usn
            res_vm = EvidenceExtractor(cid_vm, stg_vm, max_workers=4).extract_from_image(PLASO_MULTIPART_VMDK)
            assert res_vm["status"] == "SUCCESS"
            assert (stg_vm / "FileSystem" / "Part_0_$J").is_file()
            assert (stg_vm / "FileSystem" / "$J").is_file()
            assert (stg_vm / "$J").is_file()
            _assert_zero_2026_disk_stats(stg_vm, "multipart_vmdk_with_usnjrnl")
        finally:
            if orig_open is not None:
                extractor_mod.dissect.target.Target.open = orig_open
            DuckDBManager.close_connection(cid_vm)

    if CFREDS_RM3_UDF_DD.exists():
        cid_u3, _, stg_u3 = _make_case_ctx(tmp_path, "r10_rm3")
        try:
            res_u3 = EvidenceExtractor(cid_u3, stg_u3, max_workers=8).extract_from_image(CFREDS_RM3_UDF_DD)
            assert res_u3["status"] == "SUCCESS"
            _assert_zero_2026_disk_stats(stg_u3, "cfreds_rm3_udf_nested_arcs")
        finally:
            DuckDBManager.close_connection(cid_u3)



