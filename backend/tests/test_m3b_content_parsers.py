"""
Comprehensive Unit, Adversarial Zero-FP & 8-Worker Concurrency Suite for M3-B
Content & Communications Parsers (F15.1–F15.5, F28):
  - EmailParser    (backend/parsers/email_parser.py)
  - ChatParser     (backend/parsers/chat_parser.py)
  - CloudParser    (backend/parsers/cloud_parser.py)
  - DocumentParser (backend/parsers/document_parser.py)
  - MediaParser    (backend/parsers/media_parser.py)
"""
from __future__ import annotations

import ast
import concurrent.futures
import hashlib
import importlib
import io
import json
import mailbox
import os
import sqlite3
import struct
import sys
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest

from backend.config import BASE_DIR, register_case_dir, unregister_case_dir
from backend.db.engine import DuckDBManager, init_case_db
import backend.parsers.chat_parser as chat_mod
import backend.parsers.cloud_parser as cloud_mod
import backend.parsers.document_parser as doc_mod
import backend.parsers.email_parser as email_mod
import backend.parsers.media_parser as media_mod
from backend.parsers.chat_parser import ChatParser, _snappy_decompress_pure_python
from backend.parsers.cloud_parser import CloudParser
from backend.parsers.document_parser import DocumentParser, parse_pdf_date, parse_zone_identifier
from backend.parsers.email_parser import EmailParser, _PST_MPBBI, _PST_MPBBR
from backend.parsers.media_parser import MediaParser, dms_to_decimal, parse_exif_timestamp


VFS_FILES_DDL = """
CREATE TABLE IF NOT EXISTS vfs_files (
    part_index INTEGER,
    vfs_path VARCHAR,
    staged_rel_path VARCHAR,
    file_name VARCHAR,
    parent_path VARCHAR,
    size_bytes BIGINT,
    is_dir BOOLEAN,
    is_deleted BOOLEAN,
    si_created TIMESTAMP,
    si_modified TIMESTAMP,
    si_accessed TIMESTAMP,
    si_changed TIMESTAMP,
    fn_created TIMESTAMP,
    fn_modified TIMESTAMP,
    fn_accessed TIMESTAMP,
    fn_changed TIMESTAMP,
    mft_entry BIGINT
);
"""


def _datetime_to_filetime(dt_utc: datetime) -> int:
    """Convert naive UTC datetime to 64-bit Windows FILETIME (100-ns ticks since 1601-01-01)."""
    epoch_diff = 116444736000000000
    delta = dt_utc - datetime(1970, 1, 1)
    unix_100ns = (delta.days * 86400 + delta.seconds) * 10_000_000 + (delta.microseconds * 10)
    return epoch_diff + unix_100ns


def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def _snappy_compress_literals(raw: bytes) -> bytes:
    """Pure-Python valid Snappy raw block encoder (uncompressed length varint + literal chunks)."""
    out = bytearray(_encode_varint(len(raw)))
    pos = 0
    n = len(raw)
    while pos < n:
        chunk = raw[pos : pos + 60]
        c_len = len(chunk)
        # tag_type 0 (literal), length-1 in upper 6 bits
        out.append(((c_len - 1) << 2) | 0x00)
        out.extend(chunk)
        pos += c_len
    return bytes(out)


def _ensure_vfs_columns(cur: Any) -> None:
    cur.execute(VFS_FILES_DDL)
    for col_ddl in (
        "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS staged_rel_path VARCHAR;",
        "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_created TIMESTAMP;",
        "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_modified TIMESTAMP;",
        "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_created_utc TIMESTAMP;",
        "ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_modified_utc TIMESTAMP;",
    ):
        cur.execute(col_ddl)


def _seed_vfs_row(
    case_id: str,
    vfs_path: str,
    staged_rel_path: str,
    file_name: str,
    size_bytes: int,
    si_modified: str | None,
    si_created: str | None = None,
) -> None:
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id)
        cur = conn.cursor()
        _ensure_vfs_columns(cur)
        cur.execute(
            """
            INSERT INTO vfs_files (
                vfs_path, staged_rel_path, file_name, parent_path,
                size_bytes, is_deleted, si_created, si_modified,
                si_created_utc, si_modified_utc
            ) VALUES (?, ?, ?, ?, ?, FALSE, ?, ?, ?, ?);
            """,
            [
                vfs_path,
                staged_rel_path,
                file_name,
                str(Path(vfs_path).parent).replace("\\", "/"),
                size_bytes,
                si_created,
                si_modified,
                si_created,
                si_modified,
            ],
        )


def _set_case_source_type(case_id: str, source_type: str) -> None:
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id)
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS case_metadata (key VARCHAR PRIMARY KEY, value VARCHAR);"
        )
        cur.execute("DELETE FROM case_metadata WHERE key = 'source_type';")
        cur.execute("INSERT INTO case_metadata (key, value) VALUES ('source_type', ?);", [source_type])


@pytest.fixture()
def isolated_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Tuple[str, Path, Path]]:
    """Create a completely isolated temporary WFT case without touching repo cases/ or %LOCALAPPDATA%."""
    appdata_dir = tmp_path / "wft_appdata"
    appdata_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata_dir))

    case_id = f"m3b_test_{os.getpid()}_{abs(hash(str(tmp_path))) % 100000}"
    case_dir = tmp_path / "cases_root" / case_id
    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    register_case_dir(case_id, case_dir)
    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id)
        conn.cursor().execute(VFS_FILES_DDL)

    try:
        yield case_id, case_dir, staging_dir
    finally:
        DuckDBManager.close_connection(case_id)
        unregister_case_dir(case_id)
        repo_phantom = BASE_DIR / "cases" / case_id
        assert not repo_phantom.exists(), f"Test leaked directory into repo cases/: {repo_phantom}"


# ===========================================================================
# Synthetic Spec-Compliant Binary Builders (CFB/OLE2, MS-PST !BDN, LevelDB,
# BMP/JPEG/PNG, CMMM Thumbcache, ISO BMFF MP4)
# ===========================================================================

def _build_cfb_file(entries: List[Tuple[str, int, bytes, int, int, int]]) -> bytes:
    """
    Build a genuine [MS-CFB] v3 (512-byte sector, 64-byte MiniStream for streams < 4096 bytes)
    Compound File Binary container compatible with both olefile and pure-Python CFB readers.
    entries: list of (name, obj_type [5=root, 1=storage, 2=stream], stream_bytes, left_id, right_id, child_id)
    """
    no_stream = 0xFFFFFFFF
    end_of_chain = 0xFFFFFFFE
    free_sect = 0xFFFFFFFF
    mini_cutoff = 4096

    sector_blobs: List[bytes] = []
    fat: List[int] = []
    mini_blobs: List[bytes] = []
    minifat: List[int] = []

    def _alloc_stream(data: bytes) -> Tuple[int, int]:
        if not data:
            return end_of_chain, 0
        num_s = (len(data) + 511) // 512
        first_sid = len(sector_blobs)
        for i in range(num_s):
            chunk = data[i * 512 : (i + 1) * 512].ljust(512, b"\x00")
            sector_blobs.append(chunk)
            fat.append(first_sid + i + 1 if i + 1 < num_s else end_of_chain)
        return first_sid, len(data)

    def _alloc_mini_stream(data: bytes) -> Tuple[int, int]:
        if not data:
            return end_of_chain, 0
        num_ms = (len(data) + 63) // 64
        first_msid = len(mini_blobs)
        for i in range(num_ms):
            chunk = data[i * 64 : (i + 1) * 64].ljust(64, b"\x00")
            mini_blobs.append(chunk)
            minifat.append(first_msid + i + 1 if i + 1 < num_ms else end_of_chain)
        return first_msid, len(data)

    stream_allocs: List[Tuple[int, int]] = []
    for _name, obj_type, payload, _l, _r, _c in entries:
        if obj_type == 2:
            if 0 < len(payload) < mini_cutoff:
                stream_allocs.append(_alloc_mini_stream(payload))
            else:
                stream_allocs.append(_alloc_stream(payload))
        else:
            stream_allocs.append((end_of_chain if obj_type == 5 else 0, 0))

    # Store concatenated 64-byte MiniStream on Root Entry (index 0, obj_type == 5)
    mini_stream_raw = b"".join(mini_blobs)
    if mini_stream_raw and entries and entries[0][1] == 5:
        stream_allocs[0] = _alloc_stream(mini_stream_raw)

    # Allocate MiniFAT sectors if MiniStream was used
    if minifat:
        while len(minifat) % 128 != 0:
            minifat.append(free_sect)
        minifat_raw = struct.pack(f"<{len(minifat)}I", *minifat)
        first_minifat_sid, _ = _alloc_stream(minifat_raw)
        num_minifat_sects = len(minifat) // 128
    else:
        first_minifat_sid, num_minifat_sects = end_of_chain, 0

    # Build 128-byte directory entries (padded to multiple of 4 per 512B sector)
    dir_raw = bytearray()
    total_dirs = ((len(entries) + 3) // 4) * 4
    for idx in range(total_dirs):
        entry_buf = bytearray(128)
        if idx < len(entries):
            name, obj_type, _payload, left_id, right_id, child_id = entries[idx]
            name_u16 = name.encode("utf-16-le") + b"\x00\x00"
            entry_buf[0 : len(name_u16)] = name_u16
            struct.pack_into("<H", entry_buf, 64, len(name_u16))
            entry_buf[66] = obj_type
            entry_buf[67] = 1  # black node
            struct.pack_into("<III", entry_buf, 68, left_id, right_id, child_id)
            start_sid, sz = stream_allocs[idx]
            struct.pack_into("<II", entry_buf, 116, start_sid, sz)
        else:
            struct.pack_into("<III", entry_buf, 68, no_stream, no_stream, no_stream)
        dir_raw.extend(entry_buf)

    first_dir_sid, _ = _alloc_stream(bytes(dir_raw))

    # Allocate 1 FAT sector covering all sectors + itself
    fat_sid = len(sector_blobs)
    fat.append(0xFFFFFFFD)  # FATSECT
    while len(fat) < 128:
        fat.append(free_sect)
    fat_sector = struct.pack("<128I", *fat[:128])
    sector_blobs.append(fat_sector)

    # 512-byte [MS-CFB] v3 header
    hdr = bytearray(512)
    hdr[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HH", hdr, 24, 0x003E, 0x0003)                      # minor, major=3
    struct.pack_into("<H", hdr, 28, 0xFFFE)                               # little-endian
    struct.pack_into("<HH", hdr, 30, 9, 6)                                # sector shift 9 (512), mini 6 (64)
    struct.pack_into("<I", hdr, 44, 1)                                    # num FAT sectors
    struct.pack_into("<I", hdr, 48, first_dir_sid)                        # first dir sector
    struct.pack_into("<I", hdr, 56, mini_cutoff)                          # mini stream cutoff = 4096 (0x1000)
    struct.pack_into("<II", hdr, 60, first_minifat_sid, num_minifat_sects)  # MiniFAT chain
    struct.pack_into("<II", hdr, 68, end_of_chain, 0)                     # DIFAT
    difat = [fat_sid] + [free_sect] * 108
    struct.pack_into("<109I", hdr, 76, *difat)

    return bytes(hdr) + b"".join(sector_blobs)


def _build_red_black_siblings(names_and_data: List[Tuple[str, int, bytes, int]]) -> List[Tuple[str, int, bytes, int, int]]:
    """Build a balanced binary search tree (sorted by (len(name), name.upper())) for CFB directory."""
    no_stream = 0xFFFFFFFF
    sorted_items = sorted(names_and_data, key=lambda x: (len(x[0]), x[0].upper()))

    # Return nodes indexed 0..N-1 with (name, obj_type, data, child_id, left_rel, right_rel)
    nodes: List[List[Any]] = []
    for name, otype, data, child_id in sorted_items:
        nodes.append([name, otype, data, no_stream, no_stream, child_id])

    def _build_bst(lo: int, hi: int) -> int:
        if lo > hi:
            return no_stream
        mid = (lo + hi) // 2
        nodes[mid][3] = _build_bst(lo, mid - 1)
        nodes[mid][4] = _build_bst(mid + 1, hi)
        return mid

    root_rel = _build_bst(0, len(nodes) - 1)
    return root_rel, [tuple(n) for n in nodes]  # type: ignore[return-value]


def _build_synthetic_msg_cfb(
    subject: str,
    sender_name: str,
    sender_email: str,
    to_addr: str,
    body_text: str,
    submit_dt: datetime,
    delivery_dt: datetime,
    att_name: str,
    att_bytes: bytes,
) -> bytes:
    """Create a spec-compliant Outlook .msg OLE2 Compound File with MAPI streams & attachment."""
    no_stream = 0xFFFFFFFF

    # Root __properties_version1.0: 32-byte header on top-level .msg + 16-byte property entries
    # Prop entry: <HHIIQ? Wait: MAPI [MS-OXMSG] prop entry is 16 bytes:
    # prop_tag (4B: <HH prop_type, prop_id), flags (4B: <I), value (8B: <Q for PtypTime 0x0040)
    submit_ft = _datetime_to_filetime(submit_dt)
    delivery_ft = _datetime_to_filetime(delivery_dt)
    root_props = bytearray(32)
    root_props.extend(struct.pack("<HHIQ", 0x0040, 0x0039, 0x06, submit_ft))   # PR_CLIENT_SUBMIT_TIME
    root_props.extend(struct.pack("<HHIQ", 0x0040, 0x0E06, 0x06, delivery_ft)) # PR_MESSAGE_DELIVERY_TIME

    # Attachment children (indices will start after root + top-level nodes)
    att_raw_children = [
        ("__substg1.0_3707001F", 2, att_name.encode("utf-16-le"), no_stream),
        ("__substg1.0_370E001F", 2, "application/pdf".encode("utf-16-le"), no_stream),
        ("__substg1.0_37010102", 2, att_bytes, no_stream),
        ("__properties_version1.0", 2, struct.pack("<II", 0, 0) + struct.pack("<HHIQ", 0x0003, 0x3705, 0x06, 1), no_stream),
    ]

    # Top-level streams + attachment storage placeholder
    top_raw = [
        ("__substg1.0_001A001F", 2, "IPM.Note".encode("utf-16-le"), no_stream),
        ("__substg1.0_0037001F", 2, subject.encode("utf-16-le"), no_stream),
        ("__substg1.0_0C1A001F", 2, sender_name.encode("utf-16-le"), no_stream),
        ("__substg1.0_0C1F001F", 2, sender_email.encode("utf-16-le"), no_stream),
        ("__substg1.0_0E04001F", 2, to_addr.encode("utf-16-le"), no_stream),
        ("__substg1.0_1000001F", 2, body_text.encode("utf-16-le"), no_stream),
        ("__substg1.0_1035001F", 2, "<msg-unit-test@corp.example>".encode("utf-16-le"), no_stream),
        ("__properties_version1.0", 2, bytes(root_props), no_stream),
        ("__attach_version1.0_#00000000", 1, b"", 9999),  # storage, child_id patched below
    ]

    top_root_rel, top_nodes = _build_red_black_siblings(top_raw)
    att_base_idx = 1 + len(top_nodes)
    att_root_rel, att_nodes = _build_red_black_siblings(att_raw_children)

    cfb_entries: List[Tuple[str, int, bytes, int, int, int]] = [
        ("Root Entry", 5, b"", no_stream, no_stream, 1 + top_root_rel)
    ]
    for name, otype, data, l_rel, r_rel, c_id in top_nodes:
        left_abs = (1 + l_rel) if l_rel != no_stream else no_stream
        right_abs = (1 + r_rel) if r_rel != no_stream else no_stream
        child_abs = (att_base_idx + att_root_rel) if c_id == 9999 else no_stream
        cfb_entries.append((name, otype, data, left_abs, right_abs, child_abs))

    for name, otype, data, l_rel, r_rel, _c_id in att_nodes:
        left_abs = (att_base_idx + l_rel) if l_rel != no_stream else no_stream
        right_abs = (att_base_idx + r_rel) if r_rel != no_stream else no_stream
        cfb_entries.append((name, otype, data, left_abs, right_abs, no_stream))

    return _build_cfb_file(cfb_entries)


def _build_hn_pc_block(props: List[Tuple[int, int, bytes | int]], crypt_permute: bool = True) -> bytes:
    """
    Build a [MS-PST] Heap-on-Node (HN) + BTree-on-Heap (BTH) Property Context (0xBC) leaf block.
    props: list of (prop_id, prop_type, raw_value_or_int)
    """
    allocs: List[bytes] = []

    def _add_alloc(b: bytes) -> int:
        allocs.append(b)
        idx = len(allocs)  # 1-based HID index
        return idx << 5    # hidType=0, hidBlockIndex=0

    # Reserve slot 1 for BTHHEADER (8 bytes) and slot 2 for BTH leaf records
    allocs.append(b"\x00" * 8)
    allocs.append(b"")

    bth_entries = bytearray()
    for prop_id, prop_type, val in sorted(props, key=lambda x: x[0]):
        if isinstance(val, int):
            dw_val = val & 0xFFFFFFFF
        else:
            dw_val = _add_alloc(val)
        bth_entries.extend(struct.pack("<HHI", prop_id, prop_type, dw_val))

    hid_bth_hdr = 1 << 5
    hid_bth_recs = 2 << 5
    allocs[1] = bytes(bth_entries)
    # BTHHEADER: bType=0xB5, cbKey=2, cbEnt=6, bIdxLevels=0, hidRoot=hid_bth_recs
    allocs[0] = struct.pack("<BBBBI", 0xB5, 2, 6, 0, hid_bth_recs)

    # Pack HN block: 12-byte HNHDR: ibHnpm(2), bSig=0xEC(1), bClientSig=0xBC(1), hidUserRoot(4), rgbFillLevel(4)
    body = bytearray()
    offsets = [12]
    for item in allocs:
        body.extend(item)
        offsets.append(12 + len(body))

    ib_hnpm = 12 + len(body)
    hdr = struct.pack("<HBBI4s", ib_hnpm, 0xEC, 0xBC, hid_bth_hdr, b"\x00\x00\x00\x00")
    # HNPAGEMAP: cAlloc (1B in reader: blk[ib_hnpm], actually <HH cAlloc, cFree, then rgibAlloc[cAlloc+1])
    # Wait: reader reads c_alloc = blk[ib_hnpm] (low byte of <H cAlloc) and off_pos = ib_hnpm + 2 + (idx-1)*2?
    # Let's check _PurePythonPSTReader._hn_deref in email_parser.py!
    # Line 489: c_alloc = blk[ib_hnpm]; Line 492: off_pos = ib_hnpm + 2 + (hid_index - 1) * 2 -> wait:
    # In [MS-PST] 2.3.1.5 HNPAGEMAP: cAlloc (WORD, 2B), cFree (WORD, 2B), rgibAlloc (WORD[cAlloc+1])!
    # Wait — let's check line 492 of email_parser.py right now before finalizing!
    pagemap = struct.pack("<HH", len(allocs), 0) + struct.pack(f"<{len(offsets)}H", *offsets)
    raw_blk = hdr + bytes(body) + pagemap
    if crypt_permute:
        return raw_blk.translate(_PST_MPBBR)
    return raw_blk


def _build_synthetic_unicode_pst(
    subject: str,
    sender_name: str,
    sender_email: str,
    to_addr: str,
    body_text: str,
    msg_id: str,
    submit_dt: datetime,
    delivery_dt: datetime,
    att_name: str,
    att_bytes: bytes,
) -> bytes:
    """
    Build a genuine [MS-PST] !BDN Unicode (wVer=23, 64-bit) PST container with:
      - NDB_CRYPT_PERMUTE (crypt_method = 1)
      - 512-byte BBT & NBT pages
      - Message PC block (NID 0x00200024, NID_TYPE_NORMAL_MESSAGE == 0x04)
      - SLBLOCK subnode (btype == 0x02) pointing to Attachment PC block (NID 0x00000685, NID_TYPE_ATTACHMENT == 0x05)
    """
    msg_props: List[Tuple[int, int, bytes | int]] = [
        (0x001A, 0x001F, "IPM.Note".encode("utf-16-le")),
        (0x0037, 0x001F, subject.encode("utf-16-le")),
        (0x0039, 0x0040, struct.pack("<Q", _datetime_to_filetime(submit_dt))),
        (0x0C1A, 0x001F, sender_name.encode("utf-16-le")),
        (0x0C1F, 0x001F, sender_email.encode("utf-16-le")),
        (0x0E04, 0x001F, to_addr.encode("utf-16-le")),
        (0x0E06, 0x0040, struct.pack("<Q", _datetime_to_filetime(delivery_dt))),
        (0x1000, 0x001F, body_text.encode("utf-16-le")),
        (0x1035, 0x001F, msg_id.encode("utf-16-le")),
    ]
    msg_pc_blk = _build_hn_pc_block(msg_props, crypt_permute=True)

    att_props: List[Tuple[int, int, bytes | int]] = [
        (0x3701, 0x0102, att_bytes),
        (0x3705, 0x0003, 1),
        (0x3707, 0x001F, att_name.encode("utf-16-le")),
        (0x370E, 0x001F, "text/plain".encode("utf-16-le")),
    ]
    att_pc_blk = _build_hn_pc_block(att_props, crypt_permute=True)

    # BID assignments:
    # 0x100: msg_pc_blk (external leaf, bit 1 == 0)
    # 0x104: att_pc_blk (external leaf, bit 1 == 0)
    # 0x10A: SLBLOCK internal block (bit 1 == 1 -> 0x10A & 0x02 != 0; unencrypted internal block)
    bid_msg_data = 0x100
    bid_att_data = 0x104
    bid_slblock = 0x10A
    att_sub_nid = 0x00000685  # (0x685 & 0x1F) == 0x05 (NID_TYPE_ATTACHMENT)

    # Unicode SLBLOCK: 8-byte header (btype=0x02, cLevel=0, cEnt=1, dwPadding=0) + 24B entry (<QQQ: nid, bidData, bidSub)
    sl_blk = struct.pack("<BBHI", 0x02, 0, 1, 0) + struct.pack("<QQQ", att_sub_nid, bid_att_data, 0)

    # File layout:
    # 0..1024: PST Header (min 564 bytes, padded to 1024)
    # 1024..1536: BBT root page (512B)
    # 1536..2048: NBT root page (512B)
    # 2048..: data blocks
    ib_bbt = 1024
    ib_nbt = 1536
    off_cur = 2048

    ib_msg = off_cur
    off_cur += ((len(msg_pc_blk) + 63) // 64) * 64
    ib_att = off_cur
    off_cur += ((len(att_pc_blk) + 63) // 64) * 64
    ib_sl = off_cur
    off_cur += ((len(sl_blk) + 63) // 64) * 64

    buf = bytearray(off_cur)
    # Header
    buf[0:4] = b"!BDN"
    struct.pack_into("<H", buf, 10, 23)  # wVer = 23 (Unicode PST)
    buf[513] = 1                         # bCryptMethod = 1 (NDB_CRYPT_PERMUTE)
    struct.pack_into("<QQQQ", buf, 216, 0x20, ib_nbt, 0x30, ib_bbt)

    # BBT Page (Unicode: entries 24B <QQHHI: bid, ib, cb, cRef, pad; meta at 488: cEnt, cEntMax, cbEnt=24, cLevel=0)
    bbt_page = bytearray(512)
    bbt_items = [
        (bid_msg_data, ib_msg, len(msg_pc_blk)),
        (bid_att_data, ib_att, len(att_pc_blk)),
        (bid_slblock, ib_sl, len(sl_blk)),
    ]
    for i, (b_id, b_ib, b_cb) in enumerate(bbt_items):
        struct.pack_into("<QQHHI", bbt_page, i * 24, b_id, b_ib, b_cb, 2, 0)
    bbt_page[488] = len(bbt_items)
    bbt_page[489] = 20
    bbt_page[490] = 24
    bbt_page[491] = 0
    buf[ib_bbt : ib_bbt + 512] = bbt_page

    # NBT Page (Unicode: entries 32B <QQQII: nid, bidData, bidSub, nidParent, pad; meta at 488)
    nbt_page = bytearray(512)
    msg_nid = 0x00200024  # (0x200024 & 0x1F) == 0x04 (NID_TYPE_NORMAL_MESSAGE)
    struct.pack_into("<QQQII", nbt_page, 0, msg_nid, bid_msg_data, bid_slblock, 0x22, 0)
    nbt_page[488] = 1
    nbt_page[489] = 15
    nbt_page[490] = 32
    nbt_page[491] = 0
    buf[ib_nbt : ib_nbt + 512] = nbt_page

    buf[ib_msg : ib_msg + len(msg_pc_blk)] = msg_pc_blk
    buf[ib_att : ib_att + len(att_pc_blk)] = att_pc_blk
    buf[ib_sl : ib_sl + len(sl_blk)] = sl_blk
    return bytes(buf)


def _build_summary_information_stream(
    title: str,
    author: str,
    last_author: str,
    created_dt: datetime,
    modified_dt: datetime,
    page_count: int = 3,
    word_count: int = 128,
) -> bytes:
    """Build an [MS-OLEPS] \\x05SummaryInformation property set stream."""
    # PropertySetStreamHeader (28B) + 1 FMTID/Offset pair (20B) -> PropertySet starts at offset 48
    pset_off = 48
    header = bytearray(pset_off)
    struct.pack_into("<HH", header, 0, 0xFFFE, 0)  # ByteOrder, Version
    struct.pack_into("<I", header, 24, 1)          # NumPropertySets = 1
    # FMTID_SummaryInformation {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
    header[28:44] = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
    struct.pack_into("<I", header, 44, pset_off)

    def _vt_lpstr(s: str) -> bytes:
        raw = s.encode("cp1252") + b"\x00"
        padded = raw + (b"\x00" * ((4 - (len(raw) % 4)) % 4))
        return struct.pack("<II", 0x001E, len(raw)) + padded

    def _vt_i4(v: int) -> bytes:
        return struct.pack("<Ii", 0x0003, v)

    def _vt_filetime(dt: datetime) -> bytes:
        return struct.pack("<IQ", 0x0040, _datetime_to_filetime(dt))

    prop_blobs = [
        (1, struct.pack("<IhH", 0x0002, 1252, 0)),  # CodePage = 1252
        (2, _vt_lpstr(title)),                      # PIDSI_TITLE
        (4, _vt_lpstr(author)),                     # PIDSI_AUTHOR
        (8, _vt_lpstr(last_author)),                # PIDSI_LASTAUTHOR
        (12, _vt_filetime(created_dt)),             # PIDSI_CREATE_DTM
        (13, _vt_filetime(modified_dt)),            # PIDSI_LASTSAVE_DTM
        (14, _vt_i4(page_count)),                   # PIDSI_PAGECOUNT
        (15, _vt_i4(word_count)),                   # PIDSI_WORDCOUNT
    ]

    num_props = len(prop_blobs)
    table_len = 8 + num_props * 8
    values_buf = bytearray()
    id_offsets = bytearray()
    for pid, blob in prop_blobs:
        rel_off = table_len + len(values_buf)
        id_offsets.extend(struct.pack("<II", pid, rel_off))
        values_buf.extend(blob)

    total_pset_size = table_len + len(values_buf)
    pset_hdr = struct.pack("<II", total_pset_size, num_props)
    return bytes(header) + pset_hdr + bytes(id_offsets) + bytes(values_buf)


def _build_synthetic_doc_cfb(
    title: str,
    author: str,
    last_author: str,
    created_dt: datetime,
    modified_dt: datetime,
    with_vba_macros: bool = True,
) -> bytes:
    """Create a legacy Word .doc MS-CFB file with SummaryInformation and optional Macros/VBA storage."""
    no_stream = 0xFFFFFFFF
    sum_bytes = _build_summary_information_stream(
        title=title,
        author=author,
        last_author=last_author,
        created_dt=created_dt,
        modified_dt=modified_dt,
        page_count=4,
        word_count=250,
    )
    top_items: List[Tuple[str, int, bytes, int]] = [
        ("\x05SummaryInformation", 2, sum_bytes, no_stream),
        ("WordDocument", 2, b"Synthetic Word Binary Body https://corp.example/spec.pdf " * 8, no_stream),
    ]
    vba_children: List[Tuple[str, int, bytes, int]] = [
        ("dir", 2, b"VBA_DIR_STREAM", no_stream),
        ("_VBA_PROJECT", 2, b"\xcc\x61VBA_MACRO_CODE", no_stream),
    ]
    if with_vba_macros:
        top_items.append(("Macros", 1, b"", 8888))

    top_root_rel, top_nodes = _build_red_black_siblings(top_items)
    cfb_entries: List[Tuple[str, int, bytes, int, int, int]] = [
        ("Root Entry", 5, b"", no_stream, no_stream, 1 + top_root_rel)
    ]

    vba_base = 1 + len(top_nodes)
    vba_root_rel, vba_nodes = _build_red_black_siblings(vba_children)

    for name, otype, data, l_rel, r_rel, c_id in top_nodes:
        l_abs = (1 + l_rel) if l_rel != no_stream else no_stream
        r_abs = (1 + r_rel) if r_rel != no_stream else no_stream
        c_abs = (vba_base + vba_root_rel) if c_id == 8888 else no_stream
        cfb_entries.append((name, otype, data, l_abs, r_abs, c_abs))

    if with_vba_macros:
        for name, otype, data, l_rel, r_rel, _ in vba_nodes:
            l_abs = (vba_base + l_rel) if l_rel != no_stream else no_stream
            r_abs = (vba_base + r_rel) if r_rel != no_stream else no_stream
            cfb_entries.append((name, otype, data, l_abs, r_abs, no_stream))

    return _build_cfb_file(cfb_entries)


def _build_leveldb_writebatch(kv_pairs: List[Tuple[bytes, bytes]]) -> bytes:
    wb = bytearray(struct.pack("<QI", 42, len(kv_pairs)))
    for k, v in kv_pairs:
        wb.append(0x01)  # kTypeValue
        wb.extend(_encode_varint(len(k)))
        wb.extend(k)
        wb.extend(_encode_varint(len(v)))
        wb.extend(v)
    return bytes(wb)


def _build_leveldb_log_spanning_32kb(record_payload: bytes) -> bytes:
    """
    Frame a LevelDB WriteBatch across 32,768-byte block boundaries using
    FIRST (type=2), MIDDLE (type=3), and LAST (type=4) 7-byte headers (<IHB).
    """
    block_size = 32768
    # Put a filler FULL record in Block 0 leaving exactly 107 bytes (7B hdr + 100B FIRST payload)
    filler_payload_len = block_size - 7 - 107
    filler_hdr = struct.pack("<IHB", 0, filler_payload_len, 1)
    filler_data = b"x" * filler_payload_len

    part1 = record_payload[:100]
    rem = record_payload[100:]
    mid_cut = max(1, len(rem) // 2)
    part2 = rem[:mid_cut]
    part3 = rem[mid_cut:]

    blk0 = filler_hdr + filler_data + struct.pack("<IHB", 0, len(part1), 2) + part1
    assert len(blk0) == block_size

    blk1 = (
        struct.pack("<IHB", 0, len(part2), 3)
        + part2
        + struct.pack("<IHB", 0, len(part3), 4)
        + part3
    )
    return blk0 + blk1


def _build_sstable_prefix_block(kv_pairs: List[Tuple[bytes, bytes]]) -> bytes:
    """Build a LevelDB SSTable block with shared=0 prefix entries and 1 restart point."""
    buf = bytearray()
    for k, v in kv_pairs:
        buf.extend(_encode_varint(0))       # shared = 0
        buf.extend(_encode_varint(len(k)))  # non_shared
        buf.extend(_encode_varint(len(v)))  # value_len
        buf.extend(k)
        buf.extend(v)
    buf.extend(struct.pack("<II", 0, 1))
    return bytes(buf)


def _build_leveldb_sstable(kv_pairs: List[Tuple[bytes, bytes]], use_snappy: bool = True) -> bytes:
    """
    Build a genuine LevelDB .ldb / .sst file with:
      - Snappy-compressed (comp_type=0x01) or raw (0x00) data block
      - Uncompressed metaindex & index blocks
      - 48-byte footer ending with magic 0xDB4775248B80FB57
    """
    raw_data_blk = _build_sstable_prefix_block(kv_pairs)
    if use_snappy:
        if chat_mod.cramjam is not None:
            comp_data = bytes(chat_mod.cramjam.snappy.compress_raw(raw_data_blk))
        else:
            comp_data = _snappy_compress_literals(raw_data_blk)
        comp_type = 0x01
    else:
        comp_data = raw_data_blk
        comp_type = 0x00

    out = bytearray()
    data_off = 0
    data_sz = len(comp_data)
    out.extend(comp_data)
    out.append(comp_type)
    out.extend(struct.pack("<I", 0))

    meta_off = len(out)
    meta_blk = struct.pack("<II", 0, 1)
    meta_sz = len(meta_blk)
    out.extend(meta_blk)
    out.append(0x00)
    out.extend(struct.pack("<I", 0))

    idx_off = len(out)
    data_handle = _encode_varint(data_off) + _encode_varint(data_sz)
    idx_blk = _build_sstable_prefix_block([(b"z\xff", data_handle)])
    idx_sz = len(idx_blk)
    out.extend(idx_blk)
    out.append(0x00)
    out.extend(struct.pack("<I", 0))

    handles = (
        _encode_varint(meta_off)
        + _encode_varint(meta_sz)
        + _encode_varint(idx_off)
        + _encode_varint(idx_sz)
    )
    footer = handles.ljust(40, b"\x00") + struct.pack("<Q", 0xDB4775248B80FB57)
    out.extend(footer)
    return bytes(out)


def _build_valid_bmp(width: int = 4, height: int = 4) -> bytes:
    """Create a strictly valid uncompressed 24-bpp Windows BITMAPINFOHEADER BMP."""
    row_stride = ((width * 24 + 31) // 32) * 4
    pixel_bytes = (b"\x20\x60\xa0" * width).ljust(row_stride, b"\x00") * height
    bf_off_bits = 54
    bf_size = bf_off_bits + len(pixel_bytes)
    file_hdr = b"BM" + struct.pack("<IHHI", bf_size, 0, 0, bf_off_bits)
    dib_hdr = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        height,
        1,
        24,
        0,
        len(pixel_bytes),
        2835,
        2835,
        0,
        0,
    )
    return file_hdr + dib_hdr + pixel_bytes


def _build_valid_png(width: int = 5, height: int = 3) -> bytes:
    """Create a strictly valid RGB PNG with verified zlib CRC32 on all chunks."""
    def _chunk(c_type: bytes, c_data: bytes) -> bytes:
        crc = zlib.crc32(c_type + c_data) & 0xFFFFFFFF
        return struct.pack(">I", len(c_data)) + c_type + c_data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + (b"\x10\x80\xe0" * width) for _ in range(height))
    idat = zlib.compress(raw_scanlines)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _build_exif_app1_tiff(
    ifd0_dt: str,
    exif_dt_orig: str,
    offset_orig: str,
    make: str = "Canon",
    model: str = "EOS R5",
    gps_lat_dms: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]] | None = ((33, 1), (51, 1), (54, 1)),
    gps_lat_ref: bytes = b"S\x00",
    gps_lon_dms: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]] | None = ((151, 1), (12, 1), (36, 1)),
    gps_lon_ref: bytes = b"W\x00",
) -> bytes:
    """Build little-endian TIFF ('II*\\x00') EXIF blob with IFD0, ExifIFD (0x8769), and GPSIFD (0x8825)."""
    def _pack_ifd(
        raw_entries: List[Tuple[int, int, int, bytes]],
        data_start_off: int,
    ) -> Tuple[bytes, bytes]:
        sorted_e = sorted(raw_entries, key=lambda x: x[0])
        tbl = bytearray(struct.pack("<H", len(sorted_e)))
        ext = bytearray()
        for tag_id, ftype, cnt, val_bytes in sorted_e:
            if len(val_bytes) <= 4:
                inline = val_bytes.ljust(4, b"\x00")
                tbl.extend(struct.pack("<HHI", tag_id, ftype, cnt) + inline)
            else:
                cur_off = data_start_off + len(ext)
                ext.extend(val_bytes)
                if len(ext) % 2 == 1:
                    ext.append(0)
                tbl.extend(struct.pack("<HHII", tag_id, ftype, cnt, cur_off))
        tbl.extend(struct.pack("<I", 0))
        return bytes(tbl), bytes(ext)

    def _asc(s: str) -> Tuple[int, int, bytes]:
        b = s.encode("ascii") + b"\x00"
        return 2, len(b), b

    def _rat3(tri: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]) -> Tuple[int, int, bytes]:
        b = b"".join(struct.pack("<II", n, d) for n, d in tri)
        return 5, 3, b

    include_gps = gps_lat_dms is not None and gps_lon_dms is not None
    ifd0_count = 5 if include_gps else 4
    ifd0_tbl_len = 2 + ifd0_count * 12 + 4
    ifd0_data_start = 8 + ifd0_tbl_len

    mk_t, mk_c, mk_b = _asc(make)
    md_t, md_c, md_b = _asc(model)
    dt_t, dt_c, dt_b = _asc(ifd0_dt)
    tmp_entries = [
        (0x010F, mk_t, mk_c, mk_b),
        (0x0110, md_t, md_c, md_b),
        (0x0132, dt_t, dt_c, dt_b),
        (0x8769, 4, 1, struct.pack("<I", 0)),
    ]
    if include_gps:
        tmp_entries.append((0x8825, 4, 1, struct.pack("<I", 0)))
    _, tmp_ext = _pack_ifd(tmp_entries, ifd0_data_start)
    exif_ifd_off = ifd0_data_start + len(tmp_ext)

    dto_t, dto_c, dto_b = _asc(exif_dt_orig)
    off_t, off_c, off_b = _asc(offset_orig)
    exif_entries = [
        (0x9003, dto_t, dto_c, dto_b),
        (0x9011, off_t, off_c, off_b),
    ]
    exif_tbl_len = 2 + len(exif_entries) * 12 + 4
    exif_tbl, exif_ext = _pack_ifd(exif_entries, exif_ifd_off + exif_tbl_len)
    gps_ifd_off = exif_ifd_off + len(exif_tbl) + len(exif_ext)

    real_ifd0_entries = [
        (0x010F, mk_t, mk_c, mk_b),
        (0x0110, md_t, md_c, md_b),
        (0x0132, dt_t, dt_c, dt_b),
        (0x8769, 4, 1, struct.pack("<I", exif_ifd_off)),
    ]
    if include_gps:
        real_ifd0_entries.append((0x8825, 4, 1, struct.pack("<I", gps_ifd_off)))
    ifd0_tbl, ifd0_ext = _pack_ifd(real_ifd0_entries, ifd0_data_start)

    gps_blob = b""
    if include_gps and gps_lat_dms is not None and gps_lon_dms is not None:
        lat_t, lat_c, lat_b = _rat3(gps_lat_dms)
        lon_t, lon_c, lon_b = _rat3(gps_lon_dms)
        gps_entries = [
            (0x0001, 2, len(gps_lat_ref), gps_lat_ref),
            (0x0002, lat_t, lat_c, lat_b),
            (0x0003, 2, len(gps_lon_ref), gps_lon_ref),
            (0x0004, lon_t, lon_c, lon_b),
        ]
        gps_tbl_len = 2 + len(gps_entries) * 12 + 4
        gps_tbl, gps_ext = _pack_ifd(gps_entries, gps_ifd_off + gps_tbl_len)
        gps_blob = gps_tbl + gps_ext

    heap = bytearray(b"II" + struct.pack("<HI", 42, 8))
    heap.extend(ifd0_tbl)
    heap.extend(ifd0_ext)
    heap.extend(exif_tbl)
    heap.extend(exif_ext)
    heap.extend(gps_blob)
    return bytes(heap)


def _build_valid_jpeg(width: int = 8, height: int = 6, exif_tiff: bytes | None = None) -> bytes:
    """Create a valid baseline JPEG with optional APP1 Exif\\x00\\x00 segment."""
    if media_mod.Image is not None:
        buf = io.BytesIO()
        img = media_mod.Image.new("RGB", (width, height), color=(40, 120, 200))
        img.save(buf, format="JPEG")
        base_jpg = buf.getvalue()
    else:
        sof0_payload = struct.pack(">BHHB", 8, height, width, 1) + struct.pack(">BBB", 1, 0x11, 0)
        sof0 = b"\xff\xc0" + struct.pack(">H", len(sof0_payload) + 2) + sof0_payload
        sos_payload = struct.pack(">BBBBBB", 1, 1, 0x00, 0, 63, 0)
        sos = b"\xff\xda" + struct.pack(">H", len(sos_payload) + 2) + sos_payload
        base_jpg = b"\xff\xd8" + sof0 + sos + b"\x7f\xff\xd9"

    if exif_tiff is None:
        return base_jpg
    app1_body = b"Exif\x00\x00" + exif_tiff
    app1_seg = b"\xff\xe1" + struct.pack(">H", len(app1_body) + 2) + app1_body
    return b"\xff\xd8" + app1_seg + base_jpg[2:]


def _build_cmmm_thumbcache(
    version: int,
    entries: List[Tuple[int, str, bytes]],
    first_offset: int = 32,
) -> bytes:
    """
    Build a Windows Explorer thumbcache_*.db ('CMMM') binary container for Win7 (0x15) or Win10 (0x20).
    """
    out = bytearray()
    if version <= 0x15:
        f3, f4 = first_offset, 0
    else:
        f3, f4 = 0, first_offset
    out.extend(b"CMMM" + struct.pack("<5I", version, 2, f3, f4, len(entries)))
    if first_offset > len(out):
        out.extend(b"\x00" * (first_offset - len(out)))

    for e_hash, ident, payload in entries:
        id_bytes = ident.encode("utf-16-le")
        hdr_len = 48 if version == 0x15 else 56
        unaligned = hdr_len + len(id_bytes) + len(payload)
        entry_size = ((unaligned + 7) // 8) * 8
        pad_len = entry_size - unaligned
        if version == 0x15:
            # Win7 48-byte CMMM header: 4s + <IQIIIIQQ (4 + 4 + 8 + 4 + 4 + 4 + 4 + 8 + 8 = 48B)
            e_hdr = b"CMMM" + struct.pack(
                "<IQIIIIQQ", entry_size, e_hash, len(id_bytes), pad_len, len(payload), 0, 0, 0
            )
        else:
            # Win8/10/11 56-byte CMMM header: 4s + <IQIIIIIIQQ (4 + 4 + 8 + 24 + 16 = 56B)
            e_hdr = b"CMMM" + struct.pack(
                "<IQIIIIIIQQ", entry_size, e_hash, len(id_bytes), pad_len, len(payload), 0, 0, 0, 0, 0
            )
        out.extend(e_hdr)
        out.extend(id_bytes)
        out.extend(b"\x00" * pad_len)
        out.extend(payload)

    return bytes(out)


def _bmff_box(box_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", 8 + len(payload), box_type) + payload


def _build_synthetic_mp4(
    c_time_mac: int,
    timescale: int,
    duration: int,
    tracks: List[Tuple[int, int, int]],
) -> bytes:
    """Build an ISO BMFF MP4 container with ftyp + moov(mvhd + multiple trak(tkhd))."""
    ftyp = _bmff_box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41")
    mvhd_payload = (
        struct.pack(">IIII", 0, c_time_mac, c_time_mac, timescale)
        + struct.pack(">I", duration)
        + (b"\x00" * 80)
    )
    mvhd = _bmff_box(b"mvhd", mvhd_payload)

    trak_boxes: List[bytes] = []
    for idx, (ver, w_px, h_px) in enumerate(tracks, start=1):
        w_fixed = (w_px & 0xFFFF) << 16
        h_fixed = (h_px & 0xFFFF) << 16
        if ver == 0:
            tkhd_buf = bytearray(84)
            tkhd_buf[0] = 0
            tkhd_buf[3] = 3
            struct.pack_into(">I", tkhd_buf, 12, idx)
            struct.pack_into(">II", tkhd_buf, 76, w_fixed, h_fixed)
        else:
            tkhd_buf = bytearray(96)
            tkhd_buf[0] = 1
            tkhd_buf[3] = 3
            struct.pack_into(">I", tkhd_buf, 20, idx)
            struct.pack_into(">II", tkhd_buf, 88, w_fixed, h_fixed)
        trak_boxes.append(_bmff_box(b"trak", _bmff_box(b"tkhd", bytes(tkhd_buf))))

    moov = _bmff_box(b"moov", mvhd + b"".join(trak_boxes))
    return ftyp + moov



# ===========================================================================
# 1. TestEmailParser (F15.1)
# ===========================================================================

class TestEmailParser:
    def test_email_parser_purged_fake_strings_and_guarded_imports(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src_path = BASE_DIR / "backend" / "parsers" / "email_parser.py"
        src_text = src_path.read_text(encoding="utf-8-sig")
        lower_src = src_text.lower()

        probe_addr = "@".join(("informant", "secret.com"))
        forbidden_tokens = [
            probe_addr,
            "@wft.local",
            "recovered ost message",
            "pstreader",
        ]
        for tok in forbidden_tokens:
            assert tok not in lower_src, f"Forbidden fake/legacy string still present in email_parser.py: {tok}"

        # Also inspect all string constants in the Python AST
        tree = ast.parse(src_text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val_low = node.value.lower()
                assert probe_addr not in val_low
                assert "wft.local" not in val_low

        # Verify cipher table mathematical identity: mpbbI[mpbbR[k]] == k for all 0..255
        assert len(_PST_MPBBR) == 256 and len(_PST_MPBBI) == 256
        assert all(_PST_MPBBI[_PST_MPBBR[b]] == b for b in range(256))

        # Verify module reloads cleanly when optional C/OLE libraries are absent
        with monkeypatch.context() as mp:
            for mod_name in ("pypff", "extract_msg", "olefile", "compressed_rtf"):
                mp.setitem(sys.modules, mod_name, None)
            reloaded = importlib.reload(email_mod)
            assert reloaded.pypff is None
            assert reloaded.extract_msg is None
            assert reloaded.olefile is None
        importlib.reload(email_mod)

    def test_eml_and_mbox_charset_received_fallback_attachments_and_utc_duckdb(
        self, isolated_case: Tuple[str, Path, Path]
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case
        mail_dir = staging_dir / "Users" / "Alice" / "Mail"
        mail_dir.mkdir(parents=True, exist_ok=True)

        # 1. EML with CP1252 body, NO Date: header, Received: +0530 fallback, and risky .exe attachment
        att_exe_bytes = b"MZ_SYNTHETIC_DROPPER_PAYLOAD_TEST"
        att_exe_sha = hashlib.sha256(att_exe_bytes).hexdigest()
        cp1252_body = "Invoice Café €125 — Wire transfer confirmation.".encode("cp1252")

        eml_msg = EmailMessage()
        eml_msg["Received"] = "from mx1.corp.example by mail.corp.example; Tue, 18 Jul 2023 19:30:00 +0530"
        eml_msg["From"] = "CFO Office <cfo@corp.example>"
        eml_msg["To"] = "alice@corp.example"
        eml_msg["Cc"] = "audit@corp.example"
        eml_msg["Subject"] = "Q3 Payment Approval"
        eml_msg["Message-ID"] = "<eml-cp1252-001@corp.example>"
        eml_msg.set_content(cp1252_body, maintype="text", subtype="plain", cte="8bit")
        eml_msg.replace_header("Content-Type", 'text/plain; charset="windows-1252"')
        eml_msg.add_attachment(
            att_exe_bytes,
            maintype="application",
            subtype="octet-stream",
            filename="invoice_update.pdf.exe",
        )

        eml_path = mail_dir / "approval.eml"
        eml_raw = eml_msg.as_bytes()
        eml_path.write_bytes(eml_raw)
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/Mail/approval.eml",
            staged_rel_path="Users/Alice/Mail/approval.eml",
            file_name="approval.eml",
            size_bytes=len(eml_raw),
            si_modified="2023-07-18 14:05:00",
        )

        # 2. MBOX with 2 messages (-0700 and +0200 offsets) + PDF attachment
        mbox_path = mail_dir / "archive.mbox"
        mb = mailbox.mbox(str(mbox_path), create=True)
        try:
            m1 = EmailMessage()
            m1["From"] = "ops@corp.example"
            m1["To"] = "alice@corp.example"
            m1["Subject"] = "MBOX Item One"
            m1["Date"] = "Mon, 10 Apr 2023 09:15:00 -0700"
            m1["Message-ID"] = "<mbox-1@corp.example>"
            m1.set_content("<html><body><style>.x{color:red}</style><p>Hello <b>MBOX</b> world!</p></body></html>", subtype="html")
            m1.add_attachment(b"%PDF-1.4 benign report", maintype="application", subtype="pdf", filename="report.pdf")
            mb.add(m1)

            m2 = EmailMessage()
            m2["From"] = "hr@corp.example"
            m2["To"] = "alice@corp.example"
            m2["Subject"] = "MBOX Item Two"
            m2["Date"] = "Mon, 10 Apr 2023 18:45:00 +0200"
            m2["Message-ID"] = "<mbox-2@corp.example>"
            m2.set_content("Plain text MBOX body.")
            mb.add(m2)
            mb.flush()
        finally:
            mb.close()

        parser = EmailParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_emails"] == 3

        # Verify mbox file handle was properly closed (can rename/delete on Windows)
        renamed_mbox = mail_dir / "archive_checked.mbox"
        mbox_path.rename(renamed_mbox)
        renamed_mbox.rename(mbox_path)

        conn = DuckDBManager.get_connection(case_id)
        rows = conn.execute(
            """
            SELECT email_format, sender, subject, CAST(date_utc AS VARCHAR),
                   body_snippet, attachments_count, attachment_count,
                   is_suspicious, source_file
            FROM parsed_emails
            ORDER BY message_id;
            """
        ).fetchall()
        assert len(rows) == 3

        by_subj = {r[2]: r for r in rows}
        # 19:30:00 +0530 -> exact 14:00:00 UTC in DuckDB (no +05:30 host shift!)
        eml_row = by_subj["Q3 Payment Approval"]
        assert eml_row[0] == "EML"
        assert eml_row[3] == "2023-07-18 14:00:00"
        assert "Café €125" in eml_row[4]
        assert eml_row[5] == 1 and eml_row[6] == 1
        assert eml_row[7] is True
        assert "staging" not in eml_row[8].lower()
        assert "approval.eml" in eml_row[8]

        # 09:15:00 -0700 -> 16:15:00 UTC; 18:45:00 +0200 -> 16:45:00 UTC
        mb1_row = by_subj["MBOX Item One"]
        assert mb1_row[3] == "2023-04-10 16:15:00"
        assert "Hello MBOX world!" in mb1_row[4]
        assert ".x{color:red}" not in mb1_row[4]
        assert mb1_row[7] is False

        mb2_row = by_subj["MBOX Item Two"]
        assert mb2_row[3] == "2023-04-10 16:45:00"

        att_rows = conn.execute(
            "SELECT file_name, file_size, sha256 FROM parsed_email_attachments ORDER BY file_name;"
        ).fetchall()
        assert len(att_rows) == 2
        att_map = {r[0]: (r[1], r[2]) for r in att_rows}
        assert att_map["invoice_update.pdf.exe"] == (len(att_exe_bytes), att_exe_sha)

    def test_msg_olefile_fallback_and_pure_python_pst_ost_ndb_and_rfc822(
        self, isolated_case: Tuple[str, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case
        outlook_dir = staging_dir / "Users" / "Bob" / "Outlook"
        outlook_dir.mkdir(parents=True, exist_ok=True)

        # 1. Synthetic OLE2 .msg tested with extract_msg=None (pure olefile MAPI fallback)
        msg_bytes = _build_synthetic_msg_cfb(
            subject="OLE2 Fallback Subject",
            sender_name="Dana Scully",
            sender_email="scully@fbi.example",
            to_addr="mulder@fbi.example",
            body_text="Classified case notes inside MAPI substg1.0_1000001F.",
            submit_dt=datetime(2023, 9, 5, 10, 15, 0),
            delivery_dt=datetime(2023, 9, 5, 10, 16, 30),
            att_name="evidence.pdf",
            att_bytes=b"%PDF-1.5 synthetic attachment bytes",
        )
        (outlook_dir / "case_note.msg").write_bytes(msg_bytes)

        # 2. Synthetic Unicode !BDN .pst (CryptPermute + HN/BTH/PC + SLBLOCK attachment) tested with pypff=None
        pst_att_bytes = b"CONFIDENTIAL_EXFIL_MANIFEST_2023"
        pst_bytes = _build_synthetic_unicode_pst(
            subject="NDB BTree PST Subject",
            sender_name="Alex Krycek",
            sender_email="krycek@syndicate.example",
            to_addr="bob@corp.example",
            body_text="Pure-Python [MS-PST] Property Context decoded body.",
            msg_id="<pst-ndb-001@syndicate.example>",
            submit_dt=datetime(2023, 10, 12, 8, 0, 0),
            delivery_dt=datetime(2023, 10, 12, 8, 2, 0),
            att_name="manifest.txt",
            att_bytes=pst_att_bytes,
        )
        (outlook_dir / "backup.pst").write_bytes(pst_bytes)

        # 3. Damaged/Partial .ost containing an undated RFC822 message block (Tier 3 fallback)
        ost_raw = (
            b"\x00" * 512
            + b"From: real.sender@partner.example\r\n"
            + b"To: bob@corp.example\r\n"
            + b"Subject: Undated OST Fragment\r\n"
            + b"Message-ID: <ost-real-999@partner.example>\r\n"
            + b"\r\n"
            + b"Authentic body recovered without fabricated sender or now() timestamp.\r\n"
            + b"\x00" * 512
        )
        (outlook_dir / "damaged.ost").write_bytes(ost_raw)

        monkeypatch.setattr(email_mod, "extract_msg", None)
        monkeypatch.setattr(email_mod, "pypff", None)

        parser = EmailParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_emails"] == 3

        conn = DuckDBManager.get_connection(case_id)
        rows = conn.execute(
            """
            SELECT email_format, sender, recipients, subject,
                   CAST(date_utc AS VARCHAR), CAST(client_submit_time AS VARCHAR),
                   body_snippet, attachments_count, attachment_count
            FROM parsed_emails
            ORDER BY email_format;
            """
        ).fetchall()
        by_fmt = {r[0]: r for r in rows}

        # MSG verification
        msg_r = by_fmt["MSG"]
        assert "scully@fbi.example" in msg_r[1]
        assert msg_r[2] == "mulder@fbi.example"
        assert msg_r[3] == "OLE2 Fallback Subject"
        assert msg_r[4] == "2023-09-05 10:16:30"
        assert msg_r[5] == "2023-09-05 10:15:00"
        assert "Classified case notes" in msg_r[6]
        assert msg_r[7] == 1 and msg_r[8] == 1

        # PST NDB verification
        pst_r = by_fmt["PST"]
        assert "krycek@syndicate.example" in pst_r[1]
        assert pst_r[3] == "NDB BTree PST Subject"
        assert pst_r[4] == "2023-10-12 08:02:00"
        assert pst_r[5] == "2023-10-12 08:00:00"
        assert "Pure-Python [MS-PST]" in pst_r[6]
        assert pst_r[7] == 1 and pst_r[8] == 1

        # OST Tier 3 verification: real sender, NULL date_utc (NEVER now(), NEVER hardcoded dataset email tokens!)
        ost_r = by_fmt["OST"]
        assert ost_r[1] == "real.sender@partner.example"
        assert "@".join(("informant", "secret.com")) not in ost_r[1]
        assert ost_r[3] == "Undated OST Fragment"
        assert ost_r[4] is None


# ===========================================================================
# 2. TestChatParser (F15.2)
# ===========================================================================

class TestChatParser:
    def test_leveldb_log_32kb_spanning_and_snappy_sstable_utf8_utf16le_zero_fp(
        self, isolated_case: Tuple[str, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case

        # Verify pure-Python Snappy decompressor matches cramjam compressed output directly
        sample_plain = (b'{"repeat":"abcd1234"}' * 40) + b"TAIL_MARKER"
        if chat_mod.cramjam is not None:
            snappy_blob = bytes(chat_mod.cramjam.snappy.compress_raw(sample_plain))
        else:
            snappy_blob = _snappy_compress_literals(sample_plain)
        assert _snappy_decompress_pure_python(snappy_blob) == sample_plain

        # 1. LevelDB .log spanning 32KB block boundary (FIRST + MIDDLE + LAST) with UTF-16LE Teams message
        teams_dir = staging_dir / "Users" / "Alice" / "AppData" / "Local" / "Packages" / "MSTeams_8wekyb3d8bbwe" / "IndexedDB"
        teams_dir.mkdir(parents=True, exist_ok=True)
        teams_obj = {
            "id": "1682944200000",
            "clientmessageid": "9988776655",
            "messagetype": "RichText/Html",
            "imdisplayname": "Alice Vance",
            "conversationId": "19:meeting_ops@thread.v2",
            "originalarrivaltime": "2023-05-01T17:30:00+05:30",
            "content": '<div>Stage 2 archive: <a href="https://share.corp.example/stage2.7z">Download</a></div>',
            "padding": "P" * 240,
        }
        teams_u16 = json.dumps(teams_obj).encode("utf-16-le")
        wb_log = _build_leveldb_writebatch([(b"teams_msg_1", teams_u16)])
        (teams_dir / "000003.log").write_bytes(_build_leveldb_log_spanning_32kb(wb_log))

        # 2. LevelDB Snappy SSTable (.ldb) containing nested Discord, Slack, and benign non-chat JSON noise
        discord_dir = staging_dir / "Users" / "Alice" / "AppData" / "Roaming" / "discord" / "Local Storage" / "leveldb"
        discord_dir.mkdir(parents=True, exist_ok=True)

        discord_nested = json.dumps({
            "id": "110220330",
            "channel_id": "88776655",
            "author": {"id": "4455", "username": "redteam_lead", "avatar": {"id": "av1"}},
            "content": "Exfiltration complete",
            "attachments": [{"id": "a1", "url": "https://cdn.discordapp.com/attachments/loot.zip"}],
            "timestamp": "2023-05-01T14:00:00+02:00",
        }).encode("utf-8")

        slack_nested = json.dumps({
            "type": "message",
            "user": "U01ABC",
            "user_profile": {"display_name": "sec_analyst"},
            "channel": "C09INCIDENT",
            "text": "Isolate host &amp; collect RAM",
            "ts": "1682942400.000200",
        }).encode("utf-8")

        benign_noise_1 = json.dumps({"message": "Not Found", "statusCode": 404}).encode("utf-8")
        benign_noise_2 = json.dumps({"theme": "dark", "windowBounds": {"width": 1280, "height": 720}}).encode("utf-8")
        benign_noise_3 = json.dumps({"user": "config_stub", "text": "enabled", "version": 2}).encode("utf-8")

        sst_bytes = _build_leveldb_sstable(
            [
                (b"k1", benign_noise_1),
                (b"k2", discord_nested),
                (b"k3", benign_noise_2),
                (b"k4", slack_nested),
                (b"k5", benign_noise_3),
            ],
            use_snappy=True,
        )
        (discord_dir / "000005.ldb").write_bytes(sst_bytes)

        # Force pure-Python Snappy decompressor by disabling cramjam & python_snappy
        monkeypatch.setattr(chat_mod, "cramjam", None)
        monkeypatch.setattr(chat_mod, "python_snappy", None)

        parser = ChatParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_chat_messages"] == 3

        conn = DuckDBManager.get_connection(case_id)
        rows = conn.execute(
            """
            SELECT app_name, profile, CAST(timestamp_utc AS VARCHAR),
                   sender, recipient_channel, message_text, attachment_url
            FROM parsed_chat_messages
            ORDER BY app_name;
            """
        ).fetchall()
        assert len(rows) == 3
        by_app = {r[0]: r for r in rows}

        # Discord: 14:00:00+02:00 -> 12:00:00 UTC
        d_row = by_app["Discord"]
        assert d_row[1] == "Alice"
        assert d_row[2] == "2023-05-01 12:00:00"
        assert d_row[3] == "redteam_lead"
        assert d_row[5] == "Exfiltration complete"
        assert d_row[6] == "https://cdn.discordapp.com/attachments/loot.zip"

        # Slack: 1682942400.000200 -> 2023-05-01 12:00:00.0002 UTC
        s_row = by_app["Slack"]
        assert s_row[2].startswith("2023-05-01 12:00:00")
        assert s_row[3] == "sec_analyst"
        assert s_row[5] == "Isolate host & collect RAM"

        # Teams UTF-16LE: 17:30:00+05:30 -> 12:00:00 UTC, HTML stripped, link extracted
        t_row = by_app["Teams"]
        assert t_row[1] == "Alice"
        assert t_row[2] == "2023-05-01 12:00:00"
        assert t_row[3] == "Alice Vance"
        assert "<div>" not in t_row[5]
        assert "Stage 2 archive: Download" in t_row[5]
        assert t_row[6] == "https://share.corp.example/stage2.7z"

    def test_sqlite_uncapped_chat_and_wpndatabase_cross_copy_dedup(
        self, isolated_case: Tuple[str, Path, Path]
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case

        # 1. Skype SQLite database with 2,120 rows (> old LIMIT 2000!)
        skype_dir = staging_dir / "Users" / "Bob" / "AppData" / "Roaming" / "Microsoft" / "Skype for Desktop"
        skype_dir.mkdir(parents=True, exist_ok=True)
        skype_db = skype_dir / "main.db"
        sconn = sqlite3.connect(str(skype_db))
        try:
            sconn.execute(
                """
                CREATE TABLE Messages (
                    id INTEGER PRIMARY KEY,
                    author TEXT,
                    convo_id TEXT,
                    timestamp INTEGER,
                    body_xml TEXT
                );
                """
            )
            base_epoch = 1683000000
            batch = [
                (i, "bob_skype", "convo_alpha", base_epoch + i, f"<partlist>Msg #{i}</partlist>")
                for i in range(1, 2121)
            ]
            sconn.executemany("INSERT INTO Messages VALUES (?, ?, ?, ?, ?);", batch)
            sconn.commit()
        finally:
            sconn.close()

        # 2. Duplicate staged copies of wpndatabase.db with exact 64-bit integer FILETIME
        wpn_dt = datetime(2023, 5, 2, 12, 0, 0)
        wpn_ft = _datetime_to_filetime(wpn_dt)
        toast_xml = (
            '<toast launch="https://teams.microsoft.com/l/message/19:abc">'
            "<visual><binding template=\"ToastGeneric\">"
            "<text>Urgent Security Alert</text>"
            "<text>Suspicious login from 185.220.101.5</text>"
            "</binding></visual></toast>"
        )

        for sub_rel in ("Notifications/Bob/wpndatabase.db", "SQLite/wpndatabase.db"):
            db_p = staging_dir / sub_rel
            db_p.parent.mkdir(parents=True, exist_ok=True)
            wconn = sqlite3.connect(str(db_p))
            try:
                wconn.execute("CREATE TABLE NotificationHandler (RecordId INTEGER PRIMARY KEY, PrimaryId TEXT);")
                wconn.execute(
                    """
                    CREATE TABLE Notification (
                        Id INTEGER PRIMARY KEY,
                        HandlerId INTEGER,
                        Type TEXT,
                        Payload BLOB,
                        ArrivalTime INTEGER
                    );
                    """
                )
                wconn.execute("INSERT INTO NotificationHandler VALUES (1, 'MSTeams_App');")
                wconn.execute(
                    "INSERT INTO Notification VALUES (10, 1, 'toast', ?, ?);",
                    (toast_xml.encode("utf-8"), wpn_ft),
                )
                wconn.commit()
            finally:
                wconn.close()

        parser = ChatParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_chat_messages"] == 2120
        assert res["parsed_notifications"] == 1

        conn = DuckDBManager.get_connection(case_id)
        notif = conn.execute(
            "SELECT app_id, CAST(timestamp_utc AS VARCHAR), CAST(arrival_time AS VARCHAR), title, body, action_url FROM parsed_notifications;"
        ).fetchall()
        assert len(notif) == 1
        assert notif[0][0] == "Microsoft Teams"
        assert notif[0][1] == "2023-05-02 12:00:00"
        assert notif[0][2] == "2023-05-02 12:00:00"
        assert notif[0][3] == "Urgent Security Alert"
        assert "185.220.101.5" in notif[0][4]
        assert notif[0][5] == "https://teams.microsoft.com/l/message/19:abc"


# ===========================================================================
# 3. TestCloudParser (F15.3)
# ===========================================================================

class TestCloudParser:
    def test_onedrive_gdrive_dropbox_and_encrypted_dbx_zero_fp(
        self, isolated_case: Tuple[str, Path, Path]
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case

        # 1. OneDrive UTF-16LE (BOM & BOM-less) .ini + .dat + SyncDiagnostics.log + SyncEngineDatabase.db + SafeDelete.db
        od_settings = staging_dir / "Users" / "Alice" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "Business1"
        od_settings.mkdir(parents=True, exist_ok=True)
        od_logs = staging_dir / "Users" / "Alice" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "logs" / "Business1"
        od_logs.mkdir(parents=True, exist_ok=True)

        ini_text = (
            'libraryScope = 1 12345 "Business" "Documents" 2 "C:\\Users\\Alice\\OneDrive - AcmeCorp" "a1b2c3d4e5f60718"\r\n'
            "UserEmail = alice@acmecorp.example\r\n"
            "LastSyncTime = 1689411600\r\n"
        )
        # BOM-less UTF-16LE INI
        ini_path = od_settings / "a1b2c3d4e5f60718.ini"
        ini_path.write_bytes(ini_text.encode("utf-16-le"))

        # Hybrid binary + UTF-16LE BOM .dat with VFS timestamp
        dat_path = od_settings / "a1b2c3d4e5f60718.dat"
        dat_bytes = (
            b"\xff\xfe"
            + "Account=alice@acmecorp.example\r\nSyncRoot=C:\\Users\\Alice\\OneDrive - AcmeCorp\\Vault\r\n".encode("utf-16-le")
        )
        dat_path.write_bytes(dat_bytes)
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/AppData/Local/Microsoft/OneDrive/settings/Business1/a1b2c3d4e5f60718.dat",
            staged_rel_path="Users/Alice/AppData/Local/Microsoft/OneDrive/settings/Business1/a1b2c3d4e5f60718.dat",
            file_name="a1b2c3d4e5f60718.dat",
            size_bytes=len(dat_bytes),
            si_modified="2023-07-15 09:00:00",
        )

        # SyncDiagnostics.log
        diag_path = od_logs / "SyncDiagnostics.log"
        diag_path.write_text(
            "UtcNow: 2023-07-15T09:30:00Z\nAccountType: Business\ncid: a1b2c3d4e5f60718\n"
            "UserFolder: C:\\Users\\Alice\\OneDrive - AcmeCorp\nSyncProgressState: 16777216\n",
            encoding="utf-8",
        )

        # SyncEngineDatabase.db (parent folder reconstruction + lastChange + fileStatus)
        sync_db = od_settings / "SyncEngineDatabase.db"
        od_conn = sqlite3.connect(str(sync_db))
        try:
            od_conn.execute(
                "CREATE TABLE od_ClientFolder_Records (resourceID TEXT, parentResourceID TEXT, folderName TEXT);"
            )
            od_conn.execute(
                "INSERT INTO od_ClientFolder_Records VALUES ('fld_root', '', 'Finance'), ('fld_q3', 'fld_root', 'Q3');"
            )
            od_conn.execute(
                """
                CREATE TABLE od_ClientFile_Records (
                    resourceID TEXT, parentResourceID TEXT, fileName TEXT,
                    size INTEGER, lastChange INTEGER, fileStatus INTEGER
                );
                """
            )
            od_conn.execute(
                "INSERT INTO od_ClientFile_Records VALUES ('res_99', 'fld_q3', 'm_and_a_targets.xlsx', 40960, 1689415200, 1);"
            )
            od_conn.commit()
        finally:
            od_conn.close()

        # SafeDelete.db
        safe_db = od_settings / "SafeDelete.db"
        sd_conn = sqlite3.connect(str(safe_db))
        try:
            sd_conn.execute(
                "CREATE TABLE items_moved_to_recycle_bin (itemId TEXT, originalPath TEXT, fileSize INTEGER, deletionTime INTEGER);"
            )
            sd_conn.execute(
                "INSERT INTO items_moved_to_recycle_bin VALUES ('del_1', 'C:\\Users\\Alice\\OneDrive\\deleted_passwords.kdbx', 8192, 1689418800);"
            )
            sd_conn.commit()
        finally:
            sd_conn.close()

        # 2. Google Drive DriveFS metadata_sqlite_db
        gd_dir = staging_dir / "Users" / "Alice" / "AppData" / "Local" / "Google" / "DriveFS" / "1092837465"
        gd_dir.mkdir(parents=True, exist_ok=True)
        gd_db = gd_dir / "metadata_sqlite_db"
        gd_conn = sqlite3.connect(str(gd_db))
        try:
            gd_conn.execute(
                "CREATE TABLE items (stable_id INTEGER PRIMARY KEY, id TEXT, local_title TEXT, size INTEGER, modified_date INTEGER, trashed INTEGER);"
            )
            gd_conn.execute(
                "INSERT INTO items VALUES (1, 'gdrive_id_77', 'board_deck.pptx', 1048576, 1689422400, 0);"
            )
            gd_conn.commit()
        finally:
            gd_conn.close()

        # 3. Dropbox info.json + SQLite nucleus.sqlite3 + encrypted binary filecache.dbx (adversarial regex bait!)
        dbx_dir = staging_dir / "Users" / "Alice" / "AppData" / "Local" / "Dropbox"
        dbx_inst = dbx_dir / "instance1"
        dbx_inst.mkdir(parents=True, exist_ok=True)
        (dbx_dir / "info.json").write_text(
            json.dumps({
                "business": {
                    "path": "C:\\Users\\Alice\\Dropbox (AcmeCorp)",
                    "email": "alice@acmecorp.example",
                    "host": 556677,
                }
            }),
            encoding="utf-8",
        )
        info_p = dbx_dir / "info.json"
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/AppData/Local/Dropbox/info.json",
            staged_rel_path="Users/Alice/AppData/Local/Dropbox/info.json",
            file_name="info.json",
            size_bytes=info_p.stat().st_size,
            si_modified="2023-07-15 08:00:00",
        )

        nuc_db = dbx_inst / "nucleus.sqlite3"
        n_conn = sqlite3.connect(str(nuc_db))
        try:
            n_conn.execute(
                "CREATE TABLE sync_files (file_id TEXT, local_path TEXT, size INTEGER, mtime INTEGER, status TEXT);"
            )
            n_conn.execute(
                "INSERT INTO sync_files VALUES ('id:dbx1', '/Roadmap/product_keys.txt', 2048, 1689426000, 'SYNCED');"
            )
            n_conn.commit()
        finally:
            n_conn.close()

        # Encrypted/non-SQLite filecache.dbx containing fake paths & emails -> MUST produce ZERO rows!
        encrypted_bait = (
            b"\x88\x19\xa4\xf0ENCRYPTED_DBX_HEADER_NOT_SQLITE\x00\x99"
            + b"C:\\Users\\Alice\\Dropbox\\FAKE_BINARY_BAIT_DO_NOT_PARSE.pdf\x00"
            + b"spurious_bait@evil.example\x00" * 8
        )
        (dbx_inst / "filecache.dbx").write_bytes(encrypted_bait)

        parser = CloudParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_cloud_files"] >= 6
        assert res["parsed_onedrive_files"] >= 4
        assert res["parsed_gdrive_files"] == 1
        assert res["parsed_dropbox_files"] == 2
        assert res["parsed_onedrive_logs"] >= 1

        conn = DuckDBManager.get_connection(case_id)
        rows = conn.execute(
            """
            SELECT cloud_provider, account, local_path, file_size,
                   CAST(modified_time AS VARCHAR), status
            FROM parsed_cloud_files;
            """
        ).fetchall()

        all_paths = [r[2] for r in rows]
        # Encrypted .dbx bait MUST NOT appear!
        assert not any("FAKE_BINARY_BAIT" in p for p in all_paths)
        assert not any("spurious_bait" in (r[1] or "") for r in rows)

        # Parent folder reconstructed on SyncEngineDatabase.db
        assert any(p == "Finance\\Q3\\m_and_a_targets.xlsx" for p in all_paths)
        assert any("deleted_passwords.kdbx" in p and r[5] == "SAFEDELETE" for r in rows for p in [r[2]])
        assert any(p == "board_deck.pptx" and r[0] == "GoogleDrive" for r in rows for p in [r[2]])
        assert any(p == "/Roadmap/product_keys.txt" and r[0] == "Dropbox" for r in rows for p in [r[2]])

        # Verify zero wall-clock now() fabrication
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        for r in rows:
            if r[4] is not None:
                dt_parsed = datetime.fromisoformat(r[4])
                assert abs((now_utc - dt_parsed).total_seconds()) > 3600


# ===========================================================================
# 4. TestDocumentParser (F15.4)
# ===========================================================================

class TestDocumentParser:
    def test_parse_pdf_date_all_iso32000_timezone_variants(self) -> None:
        # Exact UTC math across all PDF ISO 32000-1 offset variants
        assert parse_pdf_date("D:20230715143000+05'30'") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715050000-04'00'") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715090000Z") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715090000Z00'00'") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715143000+05'30") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715050000-0400") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715110000+02:00") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715110000+02") == datetime(2023, 7, 15, 9, 0, 0)
        assert parse_pdf_date("D:20230715040000-5'") == datetime(2023, 7, 15, 9, 0, 0)
        # Midnight year rollover: 2024-01-01 01:30:00 +05'30' -> 2023-12-31 20:00:00 UTC
        assert parse_pdf_date("D:20240101013000+05'30'") == datetime(2023, 12, 31, 20, 0, 0)

    def test_pdf_ooxml_cfb_pure_python_fallbacks_text_docs_and_motw_zero_fp(
        self, isolated_case: Tuple[str, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Verify import-guard reload when all optional document libraries are None
        with monkeypatch.context() as mp:
            for m_name in ("pymupdf", "fitz", "docx", "openpyxl", "pptx", "olefile"):
                mp.setitem(sys.modules, m_name, None)
            reloaded = importlib.reload(doc_mod)
            assert reloaded.HAS_FITZ is False
            assert reloaded.HAS_DOCX is False
            assert reloaded.HAS_OPENPYXL is False
            assert reloaded.HAS_PPTX is False
            assert reloaded.HAS_OLEFILE is False
        importlib.reload(doc_mod)

        case_id, _case_dir, staging_dir = isolated_case
        docs_dir = staging_dir / "Users" / "Alice" / "Documents"
        docs_dir.mkdir(parents=True, exist_ok=True)

        # 1. PDF with +05'30' CreationDate, -04'00' ModDate, /URI, /JavaScript, plus UTF-8-sig Zone.Identifier ADS
        pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [5 0 R] >>\nendobj\n"
            b"4 0 obj\n<< /Length 31 >>\nstream\nBT (Confidential Merger Plan) Tj ET\nendstream\nendobj\n"
            b"5 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://portal.corp.example/deal) >> >>\nendobj\n"
            b"6 0 obj\n<< /Title (Project Horizon) /Author (Alice Chen) "
            b"/CreationDate (D:20230715143000+05'30') /ModDate (D:20230715050000-04'00') >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R /Info 6 0 R >>\n%%EOF\n"
        )
        pdf_path = docs_dir / "horizon.pdf"
        pdf_path.write_bytes(pdf_bytes)

        # Valid UTF-8-sig BOM Zone.Identifier for horizon.pdf
        zone_bom = (
            "\ufeff[ZoneTransfer]\r\n"
            "ZoneId=3\r\n"
            "HostUrl=https://downloads.evil.example/horizon.pdf\r\n"
            "ReferrerUrl=https://mail.corp.example/inbox\r\n"
        ).encode("utf-8")
        (docs_dir / "horizon.pdf.Zone.Identifier").write_bytes(zone_bom)

        # 2. Macro-enabled OOXML .docm (ZIP with core.xml, app.xml, document.xml, .rels, vbaProject.bin)
        docm_path = docs_dir / "macro_spec.docm"
        with zipfile.ZipFile(docm_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "docProps/core.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
                "<dc:title>Q3 Macro Spec</dc:title>"
                "<dc:creator>Bob Builder</dc:creator>"
                "<cp:lastModifiedBy>Eve Auditor</cp:lastModifiedBy>"
                "<dcterms:created>2023-06-10T14:00:00+02:00</dcterms:created>"
                "<dcterms:modified>2023-06-10T15:30:00+02:00</dcterms:modified>"
                "</cp:coreProperties>",
            )
            zf.writestr(
                "docProps/app.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                "<Pages>5</Pages><Words>7</Words></Properties>",
            )
            zf.writestr(
                "word/document.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>One two three four five six seven</w:t></w:r></w:p></w:body></w:document>",
            )
            zf.writestr(
                "word/_rels/document.xml.rels",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="hyperlink" Target="https://wiki.corp.example/macros" TargetMode="External"/>'
                "</Relationships>",
            )
            zf.writestr("word/vbaProject.bin", b"SYNTHETIC_VBA_PROJECT_BIN")

        # 3. Legacy OLE2 .doc with SummaryInformation & Macros/VBA
        doc_cfb_bytes = _build_synthetic_doc_cfb(
            title="Legacy Proposal",
            author="Grace Hopper",
            last_author="Alan Turing",
            created_dt=datetime(2023, 4, 1, 11, 0, 0),
            modified_dt=datetime(2023, 4, 2, 16, 45, 0),
            with_vba_macros=True,
        )
        (docs_dir / "legacy.doc").write_bytes(doc_cfb_bytes)

        # 4. TXT, CSV, RTF documents + VFS timestamp
        txt_path = docs_dir / "notes.txt"
        txt_data = b"Incident timeline line 1\nExfil server https://c2.evil.example/drop\n"
        txt_path.write_bytes(txt_data)
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/Documents/notes.txt",
            staged_rel_path="Users/Alice/Documents/notes.txt",
            file_name="notes.txt",
            size_bytes=len(txt_data),
            si_modified="2023-07-10 07:45:00",
            si_created="2023-07-09 06:00:00",
        )
        (docs_dir / "accounts.csv").write_text("user,role\nalice,admin\nbob,analyst\n", encoding="utf-8")
        (docs_dir / "memo.rtf").write_text(
            r"{\rtf1\ansi{\info{\title RTF Memo}{\author Clara}}\pard Urgent forensic memo text.\par}",
            encoding="utf-8",
        )

        # 5. Orphan UTF-16LE Zone.Identifier (with VFS timestamp) + 3 adversarial INVALID Zone.Identifier files
        orphan_zone = docs_dir / "deleted_installer.msi:Zone.Identifier".replace(":", "_")
        orphan_u16 = (
            "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.evil.example/inst.msi\r\n"
        ).encode("utf-16-le")
        orphan_zone.write_bytes(orphan_u16)
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/Downloads/deleted_installer.msi:Zone.Identifier",
            staged_rel_path="Users/Alice/Documents/deleted_installer.msi_Zone.Identifier",
            file_name=orphan_zone.name,
            size_bytes=len(orphan_u16),
            si_modified="2023-07-12 21:00:00",
        )

        # Adversarial negative MOTW inputs -> MUST yield ZERO false positives!
        (docs_dir / "fake1_zone.identifier").write_text("[General]\nZoneId=3\nHostUrl=https://bad\n", encoding="utf-8")
        (docs_dir / "fake2_zone.identifier").write_text("[ZoneTransfer]\nZoneId=9\nHostUrl=https://bad\n", encoding="utf-8")
        (docs_dir / "fake3_zone.identifier").write_text("Random plain text mentioning ZoneId=3", encoding="utf-8")
        assert parse_zone_identifier("[General]\nZoneId=3")["valid"] is False
        assert parse_zone_identifier("[ZoneTransfer]\nZoneId=9")["valid"] is False

        # Force pure-Python fallbacks for PDF, OOXML, and OLE2 CFB!
        monkeypatch.setattr(doc_mod, "HAS_FITZ", False)
        monkeypatch.setattr(doc_mod, "fitz", None)
        monkeypatch.setattr(doc_mod, "HAS_DOCX", False)
        monkeypatch.setattr(doc_mod, "HAS_OPENPYXL", False)
        monkeypatch.setattr(doc_mod, "HAS_PPTX", False)
        monkeypatch.setattr(doc_mod, "HAS_OLEFILE", False)
        monkeypatch.setattr(doc_mod, "olefile", None)

        parser = DocumentParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_text_documents"] == 3
        assert res["parsed_documents_metadata"] == 7  # pdf + docm + doc + txt + csv + rtf + 1 valid orphan ADS

        conn = DuckDBManager.get_connection(case_id)
        meta_rows = conn.execute(
            """
            SELECT file_name, file_type, title, author, last_modified_by,
                   CAST(created_time AS VARCHAR), CAST(modified_time AS VARCHAR),
                   page_count, has_macros, zone_id, host_url, zone_host_url,
                   referrer_url, zone_referrer_url, embedded_links
            FROM parsed_documents_metadata;
            """
        ).fetchall()
        by_name = {r[0]: r for r in meta_rows}

        # Invalid fake*_zone.identifier files must NOT appear
        assert not any("fake" in k.lower() for k in by_name)

        # PDF verification (exact UTC 09:00:00 + MOTW both host_url & zone_host_url populated!)
        pdf_r = by_name["horizon.pdf"]
        assert pdf_r[2] == "Project Horizon"
        assert pdf_r[3] == "Alice Chen"
        assert pdf_r[5] == "2023-07-15 09:00:00"
        assert pdf_r[6] == "2023-07-15 09:00:00"
        assert pdf_r[7] == 1
        assert pdf_r[8] is True
        assert pdf_r[9] == 3
        assert pdf_r[10] == "https://downloads.evil.example/horizon.pdf"
        assert pdf_r[11] == "https://downloads.evil.example/horizon.pdf"
        assert pdf_r[12] == "https://mail.corp.example/inbox"
        assert pdf_r[13] == "https://mail.corp.example/inbox"
        assert "https://portal.corp.example/deal" in (pdf_r[14] or "")

        # OOXML .docm verification
        docm_r = by_name["macro_spec.docm"]
        assert docm_r[2] == "Q3 Macro Spec"
        assert docm_r[3] == "Bob Builder"
        assert docm_r[4] == "Eve Auditor"
        assert docm_r[5] == "2023-06-10 12:00:00"
        assert docm_r[6] == "2023-06-10 13:30:00"
        assert docm_r[7] == 5
        assert docm_r[8] is True
        assert "https://wiki.corp.example/macros" in (docm_r[14] or "")

        # Legacy CFB .doc verification
        doc_r = by_name["legacy.doc"]
        assert doc_r[2] == "Legacy Proposal"
        assert doc_r[3] == "Grace Hopper"
        assert doc_r[4] == "Alan Turing"
        assert doc_r[5] == "2023-04-01 11:00:00"
        assert doc_r[6] == "2023-04-02 16:45:00"
        assert doc_r[8] is True

        # Text documents & view_docs_txt verification
        txt_rows = conn.execute(
            "SELECT file_name, line_count, text_preview, content_preview, CAST(modified_time AS VARCHAR) FROM parsed_text_documents;"
        ).fetchall()
        txt_map = {r[0]: r for r in txt_rows}
        assert set(txt_map.keys()) == {"notes.txt", "accounts.csv", "memo.rtf"}
        assert txt_map["notes.txt"][2] == txt_map["notes.txt"][3]
        assert txt_map["notes.txt"][4] == "2023-07-10 07:45:00"

        view_txt_cnt = conn.execute("SELECT COUNT(*) FROM view_docs_txt;").fetchone()[0]
        assert view_txt_cnt == 3


# ===========================================================================
# 5. TestMediaParser (F15.5)
# ===========================================================================

class TestMediaParser:
    def test_media_import_guards_and_exif_priority_offset_and_gps(
        self, isolated_case: Tuple[str, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Verify import-guard reload when PIL, cv2, and dissect.thumbcache are absent
        with monkeypatch.context() as mp:
            for m_name in ("PIL", "PIL.Image", "PIL.ExifTags", "cv2", "dissect", "dissect.thumbcache"):
                mp.setitem(sys.modules, m_name, None)
            reloaded = importlib.reload(media_mod)
            assert reloaded.Image is None
            assert reloaded.ThumbcacheFile is None
            assert reloaded.cv2 is None
        importlib.reload(media_mod)

        # Direct unit checks on dms_to_decimal & parse_exif_timestamp
        assert dms_to_decimal(((0, 0), (0, 0), (0, 0)), b"") is None
        assert dms_to_decimal(((33, 1), (51, 1), (54, 1)), b"S\x00", is_lon=False) == -33.865
        assert dms_to_decimal(((151, 1), (12, 1), (36, 1)), b"W\x00", is_lon=True) == -151.21
        assert parse_exif_timestamp("2023:08:20 15:00:00", "+05:30") == datetime(2023, 8, 20, 9, 30, 0)

        case_id, _case_dir, staging_dir = isolated_case
        pics_dir = staging_dir / "Users" / "Alice" / "Pictures"
        pics_dir.mkdir(parents=True, exist_ok=True)

        # Photo 1: IFD0 DateTime='2024:01:01 12:00:00' vs ExifIFD DateTimeOriginal='2023:08:20 15:00:00' + '+05:30'
        exif1 = _build_exif_app1_tiff(
            ifd0_dt="2024:01:01 12:00:00",
            exif_dt_orig="2023:08:20 15:00:00",
            offset_orig="+05:30",
            gps_lat_dms=((33, 1), (51, 1), (54, 1)),
            gps_lat_ref=b"S\x00",
            gps_lon_dms=((151, 1), (12, 1), (36, 1)),
            gps_lon_ref=b"W\x00",
        )
        (pics_dir / "sydney_trip.jpg").write_bytes(_build_valid_jpeg(16, 12, exif1))

        # Photo 2: Uninitialized 0/0 GPS rationals -> latitude/longitude MUST be None (never 0.0, 0.0!)
        exif2 = _build_exif_app1_tiff(
            ifd0_dt="2023:09:10 10:00:00",
            exif_dt_orig="2023:09:10 10:00:00",
            offset_orig="Z",
            gps_lat_dms=((0, 0), (0, 0), (0, 0)),
            gps_lat_ref=b"\x00",
            gps_lon_dms=((0, 0), (0, 0), (0, 0)),
            gps_lon_ref=b"\x00",
        )
        (pics_dir / "uninit_gps.jpg").write_bytes(_build_valid_jpeg(10, 8, exif2))

        # Test pure-Python TIFF/JPEG fallback with Image = None!
        monkeypatch.setattr(media_mod, "Image", None)
        parser = MediaParser(case_id=case_id, staging_dir=staging_dir)
        res = parser.parse()
        assert res["parsed_media_pictures"] == 2
        assert res["parsed_media_exif"] == 2

        conn = DuckDBManager.get_connection(case_id)
        rows = conn.execute(
            """
            SELECT file_name, camera_make, camera_model,
                   CAST(datetime_original AS VARCHAR),
                   image_width, image_height, latitude, longitude
            FROM parsed_media_pictures
            ORDER BY file_name;
            """
        ).fetchall()
        by_name = {r[0]: r for r in rows}

        syd = by_name["sydney_trip.jpg"]
        assert syd[1] == "Canon"
        assert syd[2] == "EOS R5"
        # ExifIFD 15:00:00 - 05:30 -> 09:30:00 UTC (beats IFD0 2024-01-01 AND zero host +05:30 shift!)
        assert syd[3] == "2023-08-20 09:30:00"
        assert syd[4] == 16 and syd[5] == 12
        assert syd[6] == pytest.approx(-33.865, abs=1e-5)
        assert syd[7] == pytest.approx(-151.21, abs=1e-5)

        uninit = by_name["uninit_gps.jpg"]
        assert uninit[3] == "2023-09-10 10:00:00"
        assert uninit[6] is None and uninit[7] is None

    def test_thumbcache_win10_win7_zero_bm_fp_and_mp4_tracks_and_screenshots(
        self, isolated_case: Tuple[str, Path, Path]
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case
        _set_case_source_type(case_id, "image")

        # 1. Win10 (0x20, padded first_offset=40) & Win7 (0x15) thumbcache_*.db with empty slot + BM garbage
        tc_dir = staging_dir / "Users" / "Alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
        tc_dir.mkdir(parents=True, exist_ok=True)

        bmp_img = _build_valid_bmp(4, 4)
        jpg_img = _build_valid_jpeg(8, 6)
        png_img = _build_valid_png(5, 3)
        bm_garbage_1 = b"xxBM\x99\x99corrupt_not_a_bmp_header_at_all_1234567890" * 3
        bm_garbage_2 = b"BM" + struct.pack("<IHHI", 999999, 7, 9, 54) + (b"\xff" * 80)

        tc_entries = [
            (0x1111222233334444, "item_bmp", bmp_img),
            (0x0, "empty_slot", b""),
            (0x5555666677778888, "garbage_bm_1", bm_garbage_1),
            (0x9999AAAABBBBCCCC, "item_jpg", jpg_img),
            (0xDDDDEEEEFFFF0001, "garbage_bm_2", bm_garbage_2),
            (0x2222444466668888, "item_png", png_img),
        ]
        (tc_dir / "thumbcache_256.db").write_bytes(_build_cmmm_thumbcache(0x20, tc_entries, first_offset=40))
        (tc_dir / "thumbcache_96.db").write_bytes(_build_cmmm_thumbcache(0x15, tc_entries[:2], first_offset=24))

        # 2. ISO BMFF MP4 #1: Track 1 = Audio (0x0 tkhd v0), Track 2 = Video (1920x1080 tkhd v1!), mvhd 1904 epoch
        vid_dir = staging_dir / "Users" / "Alice" / "Videos"
        vid_dir.mkdir(parents=True, exist_ok=True)
        mp4_1 = _build_synthetic_mp4(
            c_time_mac=2082844800 + 1700000000,  # 2023-11-14 22:13:20 UTC
            timescale=1000,
            duration=12500,                      # 12.5s
            tracks=[(0, 0, 0), (1, 1920, 1080)],
        )
        (vid_dir / "dashcam.mp4").write_bytes(mp4_1)

        # ISO BMFF .3gp #2: creation_time = 0 -> datetime_original MUST be None (NEVER 1904-01-01!)
        mp4_unset = _build_synthetic_mp4(
            c_time_mac=0,
            timescale=1000,
            duration=0,
            tracks=[(0, 640, 480)],
        )
        (vid_dir / "clip_unset.3gp").write_bytes(mp4_unset)

        # 3. SnippingTool / Screenshots: #1 with VFS si_modified, #2 with NULL VFS timestamps on 'image' case
        snip_dir = staging_dir / "Users" / "Alice" / "Pictures" / "Screenshots"
        snip_dir.mkdir(parents=True, exist_ok=True)
        snip1_bytes = _build_valid_png(12, 9)
        snip2_bytes = _build_valid_bmp(6, 6)
        (snip_dir / "snip_known.png").write_bytes(snip1_bytes)
        (snip_dir / "snip_null_vfs.bmp").write_bytes(snip2_bytes)

        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/Pictures/Screenshots/snip_known.png",
            staged_rel_path="Users/Alice/Pictures/Screenshots/snip_known.png",
            file_name="snip_known.png",
            size_bytes=len(snip1_bytes),
            si_modified="2022-03-10 08:15:00",
        )
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Alice/Pictures/Screenshots/snip_null_vfs.bmp",
            staged_rel_path="Users/Alice/Pictures/Screenshots/snip_null_vfs.bmp",
            file_name="snip_null_vfs.bmp",
            size_bytes=len(snip2_bytes),
            si_modified=None,
            si_created=None,
        )

        parser = MediaParser(case_id=case_id, staging_dir=staging_dir, source_type="image")
        res = parser.parse()
        assert res["parsed_media_videos"] == 2
        # 3 valid in thumbcache_256.db + 1 valid in thumbcache_96.db + 2 screenshots = 6 (ZERO BM false positives!)
        assert res["parsed_thumbcache"] == 6

        conn = DuckDBManager.get_connection(case_id)
        tc_rows = conn.execute(
            """
            SELECT cache_name, entry_hash, file_extension, image_dimensions,
                   cache_type, CAST(timestamp_utc AS VARCHAR)
            FROM parsed_thumbcache;
            """
        ).fetchall()
        tc256 = [r for r in tc_rows if r[0] == "thumbcache_256.db"]
        assert len(tc256) == 3
        assert {r[2]: r[3] for r in tc256} == {"bmp": "4x4", "jpg": "8x6", "png": "5x3"}
        assert all(r[5] is None for r in tc256)

        snips = {r[2]: r for r in tc_rows if r[4] == "SNIPPING_TOOL"}
        assert snips["png"][3] == "12x9"
        assert snips["png"][5] == "2022-03-10 08:15:00"
        assert snips["bmp"][3] == "6x6"
        assert snips["bmp"][5] is None  # NEVER datetime.now()!

        vids = conn.execute(
            "SELECT file_name, CAST(datetime_original AS VARCHAR), duration_seconds, width, height FROM parsed_media_videos;"
        ).fetchall()
        v_map = {r[0]: r for r in vids}
        assert v_map["dashcam.mp4"] == ("dashcam.mp4", "2023-11-14 22:13:20", 12.5, 1920, 1080)
        assert v_map["clip_unset.3gp"] == ("clip_unset.3gp", None, None, 640, 480)


# ===========================================================================
# 6. TestM3BConcurrencyStress (F28 — 8-Worker Parallel DuckDB Stress)
# ===========================================================================

class TestM3BConcurrencyStress:
    def test_m3b_8_worker_concurrent_5_parsers_and_readers_stress(
        self, isolated_case: Tuple[str, Path, Path]
    ) -> None:
        case_id, _case_dir, staging_dir = isolated_case

        # Seed fixtures for ALL 5 M3-B parsers into one shared staging_dir & case.duckdb
        # 1. Email (.eml)
        mail_dir = staging_dir / "Users" / "Concurrent" / "Mail"
        mail_dir.mkdir(parents=True, exist_ok=True)
        em = EmailMessage()
        em["From"] = "secops@corp.example"
        em["To"] = "ir@corp.example"
        em["Subject"] = "Concurrent Incident Report"
        em["Date"] = "Wed, 15 Nov 2023 14:30:00 +0530"
        em["Message-ID"] = "<conc-eml-1@corp.example>"
        em.set_content("Concurrent EML body.")
        em.add_attachment(b"IOC_LIST_DATA", maintype="text", subtype="plain", filename="iocs.txt")
        (mail_dir / "incident.eml").write_bytes(em.as_bytes())

        # 2. Chat (LevelDB SSTable + WPN SQLite)
        chat_dir = staging_dir / "Users" / "Concurrent" / "AppData" / "Roaming" / "discord" / "Local Storage" / "leveldb"
        chat_dir.mkdir(parents=True, exist_ok=True)
        d_payload = json.dumps({
            "id": "901",
            "channel_id": "777",
            "author": {"username": "concurrent_user"},
            "content": "Parallel chat check",
            "timestamp": "2023-11-15T09:00:00Z",
        }).encode("utf-8")
        (chat_dir / "000001.ldb").write_bytes(_build_leveldb_sstable([(b"m1", d_payload)], use_snappy=True))

        wpn_p = staging_dir / "Notifications" / "Concurrent" / "wpndatabase.db"
        wpn_p.parent.mkdir(parents=True, exist_ok=True)
        wc = sqlite3.connect(str(wpn_p))
        try:
            wc.execute("CREATE TABLE NotificationHandler (RecordId INTEGER PRIMARY KEY, PrimaryId TEXT);")
            wc.execute("CREATE TABLE Notification (Id INTEGER, HandlerId INTEGER, Type TEXT, Payload BLOB, ArrivalTime INTEGER);")
            wc.execute("INSERT INTO NotificationHandler VALUES (1, 'Slack');")
            wc.execute(
                "INSERT INTO Notification VALUES (1, 1, 'toast', ?, ?);",
                (b"<toast><visual><binding><text>Ping</text></binding></visual></toast>", _datetime_to_filetime(datetime(2023, 11, 15, 9, 0, 0))),
            )
            wc.commit()
        finally:
            wc.close()

        # 3. Cloud (OneDrive SQLite)
        od_dir = staging_dir / "Users" / "Concurrent" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "Personal"
        od_dir.mkdir(parents=True, exist_ok=True)
        oc = sqlite3.connect(str(od_dir / "SyncEngineDatabase.db"))
        try:
            oc.execute("CREATE TABLE od_ClientFile_Records (resourceID TEXT, fileName TEXT, size INTEGER, lastChange INTEGER, fileStatus TEXT);")
            oc.execute("INSERT INTO od_ClientFile_Records VALUES ('cid1', 'budget_2023.xlsx', 16384, 1700038800, 'SYNCED');")
            oc.commit()
        finally:
            oc.close()

        # 4. Document (PDF + TXT + Zone.Identifier)
        doc_dir = staging_dir / "Users" / "Concurrent" / "Documents"
        doc_dir.mkdir(parents=True, exist_ok=True)
        (doc_dir / "brief.pdf").write_bytes(
            b"%PDF-1.4\n1 0 obj\n<< /Type /Pages /Count 2 >>\nendobj\n"
            b"2 0 obj\n<< /Title (Brief) /Author (IR) /CreationDate (D:20231115090000Z) >>\nendobj\n"
            b"trailer\n<< /Info 2 0 R >>\n%%EOF\n"
        )
        (doc_dir / "brief.pdf.Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.org/brief.pdf\n", encoding="utf-8")
        txt_conc = doc_dir / "readme.txt"
        txt_conc.write_text("Forensic readme line\n", encoding="utf-8")
        _seed_vfs_row(
            case_id,
            vfs_path="/Users/Concurrent/Documents/readme.txt",
            staged_rel_path="Users/Concurrent/Documents/readme.txt",
            file_name="readme.txt",
            size_bytes=txt_conc.stat().st_size,
            si_modified="2023-11-15 09:00:00",
        )

        # 5. Media (JPEG with EXIF + MP4 + CMMM Thumbcache)
        med_dir = staging_dir / "Users" / "Concurrent" / "Pictures"
        med_dir.mkdir(parents=True, exist_ok=True)
        exif_c = _build_exif_app1_tiff("2023:11:15 09:00:00", "2023:11:15 09:00:00", "Z")
        (med_dir / "evidence.jpg").write_bytes(_build_valid_jpeg(12, 10, exif_c))
        (med_dir / "capture.mp4").write_bytes(
            _build_synthetic_mp4(2082844800 + 1700038800, 1000, 5000, [(0, 1280, 720)])
        )
        (med_dir / "thumbcache_256.db").write_bytes(
            _build_cmmm_thumbcache(0x20, [(0xABCDEF0123456789, "ev", _build_valid_png(4, 4))], first_offset=32)
        )

        def _reader_worker(worker_idx: int) -> int:
            total_queries = 0
            for _ in range(12):
                with DuckDBManager.get_lock(case_id):
                    cur = DuckDBManager.get_connection(case_id).cursor()
                    cur.execute("SELECT COUNT(*) FROM artifact_registry;").fetchone()
                    cur.execute("SELECT COUNT(*) FROM parsed_documents_metadata;").fetchone()
                    total_queries += 2
            return total_queries + worker_idx

        tasks = [
            lambda: EmailParser(case_id=case_id, staging_dir=staging_dir).parse(),
            lambda: ChatParser(case_id=case_id, staging_dir=staging_dir).parse(),
            lambda: CloudParser(case_id=case_id, staging_dir=staging_dir).parse(),
            lambda: DocumentParser(case_id=case_id, staging_dir=staging_dir).parse(),
            lambda: MediaParser(case_id=case_id, staging_dir=staging_dir).parse(),
            lambda: _reader_worker(1),
            lambda: _reader_worker(2),
            lambda: _reader_worker(3),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fn) for fn in tasks]
            results = [f.result(timeout=60) for f in futures]

        assert len(results) == 8

        conn = DuckDBManager.get_connection(case_id)
        expected_counts = {
            "parsed_emails": 1,
            "parsed_email_attachments": 1,
            "parsed_chat_messages": 1,
            "parsed_notifications": 1,
            "parsed_cloud_files": 1,
            "parsed_documents_metadata": 2,
            "parsed_text_documents": 1,
            "parsed_media_exif": 2,
            "parsed_media_pictures": 1,
            "parsed_media_videos": 1,
            "parsed_thumbcache": 1,
        }
        for tbl, exp_cnt in expected_counts.items():
            actual = conn.execute(f"SELECT COUNT(*) FROM {tbl};").fetchone()[0]
            assert actual == exp_cnt, f"Table {tbl} count mismatch under 8-worker concurrency: {actual} != {exp_cnt}"

        # Verify ZERO timestamps across all M3-B tables are fabricated wall-clock now()
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        ts_checks = [
            ("parsed_emails", "date_utc"),
            ("parsed_chat_messages", "timestamp_utc"),
            ("parsed_notifications", "timestamp_utc"),
            ("parsed_cloud_files", "modified_time"),
            ("parsed_documents_metadata", "created_time"),
            ("parsed_documents_metadata", "modified_time"),
            ("parsed_text_documents", "modified_time"),
            ("parsed_media_pictures", "datetime_original"),
            ("parsed_media_videos", "datetime_original"),
            ("parsed_thumbcache", "timestamp_utc"),
        ]
        for tbl, col in ts_checks:
            vals = conn.execute(f"SELECT CAST({col} AS VARCHAR) FROM {tbl} WHERE {col} IS NOT NULL;").fetchall()
            for (v_str,) in vals:
                dt_v = datetime.fromisoformat(v_str)
                assert abs((now_utc - dt_v).total_seconds()) > 3600, (
                    f"Suspected wall-clock now() fabrication in {tbl}.{col}: {v_str}"
                )


def test_m3b_iter2_email_chat_cloud_regressions(tmp_path: Path) -> None:
    import time

    os.environ["WFT_APPDATA_DIR"] = str(tmp_path / "appdata_i2a")
    case_id = f"m3b_i2a_{os.getpid()}"
    case_dir = tmp_path / "cases" / case_id
    stg = case_dir / "staging"
    stg.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, case_dir)
    init_case_db(case_id)
    try:
        _set_case_source_type(case_id, "folder")
        mail_dir = stg / "Users" / "Alice" / "Mail"
        mail_dir.mkdir(parents=True, exist_ok=True)
        (mail_dir / "zero.eml").write_bytes(b"")
        pst = bytearray(2048)
        pst[0:4] = b"!BDN"
        struct.pack_into("<H", pst, 10, 23)
        pst[513] = 1
        struct.pack_into("<QQQQ", pst, 216, 0x20, 1536, 0x30, 1024)
        for ib_self in (1024, 1536):
            pg = bytearray(512)
            for idx in range(4):
                struct.pack_into("<QQQ", pg, idx * 24, idx + 1, 0x10 + idx, ib_self)
            pg[488:492] = bytes((4, 20, 24, 1))
            pst[ib_self : ib_self + 512] = pg
        (mail_dir / "loop.pst").write_bytes(bytes(pst))
        t0 = time.perf_counter()
        EmailParser(case_id=case_id, staging_dir=stg).parse()
        assert (time.perf_counter() - t0) < 1.0
        conn = DuckDBManager.get_connection(case_id)
        assert conn.execute("SELECT COUNT(*) FROM parsed_emails;").fetchone()[0] == 0
        (mail_dir / "ok.eml").write_text(
            "From: a@ex.test\nTo: b@ex.test\nSubject: S\nDate: Sat, 15 Jul 2023 09:00:00 +0000\n\nBody\n",
            encoding="utf-8",
        )
        EmailParser(case_id=case_id, staging_dir=stg).parse()
        assert conn.execute("SELECT COUNT(*) FROM parsed_emails;").fetchone()[0] == 1
        cats = [r[0] for r in conn.execute("SELECT DISTINCT category FROM artifact_registry WHERE table_name='parsed_emails';").fetchall()]
        assert cats == ["EMAIL & CALENDAR"]

        ldb_dir = stg / "Users" / "Alice" / "AppData" / "Roaming" / "Slack" / "Local Storage" / "leveldb"
        ldb_dir.mkdir(parents=True, exist_ok=True)
        kv = [
            (b"k1", json.dumps({"author": "linus", "content": "readme"}).encode()),
            (b"k2", json.dumps({"type": "error", "text": "bad", "ts": "1700000001.000"}).encode()),
            (b"k3", json.dumps({"id": "t1", "messageType": "Typing", "content": "..."}).encode()),
            (b"k4", json.dumps({"type": "message", "user": "U1", "text": "parent_ok", "ts": "1700000010.000", "replies": [{"user": "U2", "text": "reply_ok", "ts": "1700000011.000"}]}).encode()),
            (b"k5", json.dumps({"messages": {"901": {"sender_id": "u1", "text": "hi", "timestamp": 1700000002}}}).encode()),
        ]
        wb = _build_leveldb_writebatch(kv)
        (ldb_dir / "000005.log").write_bytes(struct.pack("<IHB", 0, len(wb), 1) + wb)
        ChatParser(case_id=case_id, staging_dir=stg).parse()
        bodies = [r[0] for r in conn.execute("SELECT COALESCE(message_text, '') FROM parsed_chat_messages;").fetchall()]
        assert {"parent_ok", "reply_ok", "hi"}.issubset(set(bodies))
        assert not ({"readme", "bad", "..."} & set(bodies))

        od_rel = "Users/Alice/AppData/Local/Microsoft/OneDrive/settings/Personal/cid01.dat"
        od_p = stg / od_rel
        od_p.parent.mkdir(parents=True, exist_ok=True)
        od_p.write_bytes(b"\xff\xfe" + "Account=alice@od.test\r\nSyncRoot=C:\\Users\\Alice\\OneDrive\r\n".encode("utf-16-le"))
        _seed_vfs_row(case_id, "/" + od_rel, od_rel, "cid01.dat", od_p.stat().st_size, None, "2026-11-17 06:00:00")
        for usr, mail, fname in (("Alice", "alice@dbx.test", "/a.txt"), ("Bob", "bob@dbx.test", "/b.txt")):
            d_base = stg / "Users" / usr / "AppData" / "Local" / "Dropbox"
            (d_base / "instance1").mkdir(parents=True, exist_ok=True)
            inf = d_base / "info.json"
            inf.write_text(json.dumps({"personal": {"path": f"C:\\Users\\{usr}\\Dropbox", "email": mail}}), encoding="utf-8")
            rel_i = f"Users/{usr}/AppData/Local/Dropbox/info.json"
            _seed_vfs_row(case_id, "/" + rel_i, rel_i, "info.json", inf.stat().st_size, None, "2026-11-17 06:00:00")
            s_conn = sqlite3.connect(str(d_base / "instance1" / "nucleus.sqlite3"))
            s_conn.execute("CREATE TABLE sync_files (file_id TEXT, local_path TEXT, size INT, mtime INT, status TEXT);")
            s_conn.execute("INSERT INTO sync_files VALUES (?, ?, 10, NULL, 'SYNCED');", (usr, fname))
            s_conn.commit()
            s_conn.close()
        CloudParser(case_id=case_id, staging_dir=stg).parse()
        c_rows = conn.execute("SELECT account, local_path, CAST(modified_time AS VARCHAR) FROM parsed_cloud_files;").fetchall()
        assert all(r[2] is None for r in c_rows)
        acct_by_path = {r[1]: r[0] for r in c_rows if r[1] in ("/a.txt", "/b.txt")}
        assert acct_by_path == {"/a.txt": "alice@dbx.test", "/b.txt": "bob@dbx.test"}
    finally:
        DuckDBManager.close_connection(case_id)
        unregister_case_dir(case_id)


def test_m3b_iter2_document_media_regressions(tmp_path: Path) -> None:
    import tracemalloc

    os.environ["WFT_APPDATA_DIR"] = str(tmp_path / "appdata_i2b")
    case_id = f"m3b_i2b_{os.getpid()}"
    case_dir = tmp_path / "cases" / case_id
    stg = case_dir / "staging"
    stg.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, case_dir)
    init_case_db(case_id)
    try:
        _set_case_source_type(case_id, "folder")
        txt_dir = stg / "Enrichment" / "Part_0" / "Users" / "Alice" / "Docs"
        txt_dir.mkdir(parents=True, exist_ok=True)
        txt_specs = [
            ("n.txt", "Alpha https://ex.test/link\n"),
            ("c.csv", "col1,col2\n1,2\n"),
            ("m.rtf", r"{\rtf1\ansi\pard Plain RTF text.\par}"),
            ("orphan.exe.Zone.Identifier", "[ZoneTransfer]\nZoneId=3\nHostUrl=https://ex.test/o.exe\n"),
        ]
        for fn, body in txt_specs:
            fp = txt_dir / fn
            fp.write_text(body, encoding="utf-8")
            rel = f"Enrichment/Part_0/Users/Alice/Docs/{fn}"
            _seed_vfs_row(case_id, f"/Users/Alice/Docs/{fn}", rel, fn, fp.stat().st_size, "2021-05-10 14:00:00", "2026-11-17 06:52:35")

        min_pdf = (
            b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        for rel_pdf in ("Enrichment/Part_0/Users/Alice/Downloads/report.pdf", "Enrichment/Part_0/Users/Bob/Documents/report.pdf"):
            p_pdf = stg / rel_pdf
            p_pdf.parent.mkdir(parents=True, exist_ok=True)
            p_pdf.write_bytes(min_pdf)
        z_alice = stg / "ZoneIdentifier" / "Part_0" / "Users" / "Alice" / "Downloads" / "report.pdf.Zone.Identifier"
        z_alice.parent.mkdir(parents=True, exist_ok=True)
        z_alice.write_text("[ZoneTransfer]\nZoneId=3\nHostUrl=https://ex.test/r.pdf\n", encoding="utf-8")
        z_flat = stg / "ZoneIdentifier" / "report.pdf.Zone.Identifier"
        z_flat.write_text("[ZoneTransfer]\nZoneId=3\nHostUrl=https://ex.test/ambig.pdf\n", encoding="utf-8")

        big_docx = txt_dir / "big.docx"
        big_xml = (
            '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
            + (("<w:p><w:r><w:t>" + ("word " * 200) + "</w:t></w:r></w:p>") * 42000)
            + "</w:body></w:document>"
        ).encode("utf-8")
        assert len(big_xml) > 40 * 1024 * 1024
        with zipfile.ZipFile(big_docx, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("word/document.xml", big_xml)
        del big_xml

        tracemalloc.start()
        base_cur, _ = tracemalloc.get_traced_memory()
        DocumentParser(case_id=case_id, staging_dir=stg, source_type="folder").parse()
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert (peak_mem - base_cur) < 64 * 1024 * 1024

        conn = DuckDBManager.get_connection(case_id)
        td_cols = {r[1] for r in conn.execute("PRAGMA table_info('parsed_text_documents');").fetchall()}
        assert {"zone_id", "host_url", "embedded_links", "char_count"}.issubset(td_cols)
        assert conn.execute("SELECT COUNT(*) FROM parsed_documents_metadata WHERE created_time IS NOT NULL;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM parsed_text_documents WHERE created_time IS NOT NULL;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM parsed_documents_metadata WHERE CAST(modified_time AS VARCHAR) LIKE '2026%';").fetchone()[0] == 0
        rep_rows = conn.execute("SELECT file_path, zone_id, host_url FROM parsed_documents_metadata WHERE file_name='report.pdf';").fetchall()
        alice_z = [r for r in rep_rows if "Alice" in r[0]]
        bob_z = [r for r in rep_rows if "Bob" in r[0]]
        assert len(alice_z) == 1 and alice_z[0][1] == 3 and alice_z[0][2] == "https://ex.test/r.pdf"
        assert len(bob_z) == 1 and bob_z[0][1] is None
        dup_zi = conn.execute("SELECT COUNT(*) FROM parsed_documents_metadata WHERE file_type='ZONE_IDENTIFIER' AND file_path LIKE '%Alice%report.pdf%';").fetchone()[0]
        assert dup_zi == 0

        for usr, w_px, h_px in (("Alice", 5, 3), ("Bob", 7, 4)):
            tc_p = stg / "Users" / usr / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer" / "thumbcache_256.db"
            tc_p.parent.mkdir(parents=True, exist_ok=True)
            tc_p.write_bytes(_build_cmmm_thumbcache(0x20, [(0xCAFEBABE12345678, "same_id", _build_valid_png(w_px, h_px))], first_offset=32))
        MediaParser(case_id=case_id, staging_dir=stg, source_type="folder").parse()
        tc_rows = conn.execute("SELECT carved_path, sha256 FROM parsed_thumbcache WHERE cache_name='thumbcache_256.db';").fetchall()
        assert len(tc_rows) == 2 and len({r[0] for r in tc_rows}) == 2 and len({r[1] for r in tc_rows}) == 2
        for c_path, db_sha in tc_rows:
            assert hashlib.sha256(Path(c_path).read_bytes()).hexdigest() == db_sha
    finally:
        DuckDBManager.close_connection(case_id)
        unregister_case_dir(case_id)


def test_m3b_iter3_challenger_and_cloud_concurrency_regressions(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from datetime import timedelta, timezone
    import time

    os.environ["WFT_APPDATA_DIR"] = str(tmp_path / "appdata_i3")
    case_id = f"m3b_i3_{os.getpid()}"
    case_dir = tmp_path / "cases" / case_id
    stg = case_dir / "staging"
    stg.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, case_dir)
    init_case_db(case_id)
    try:
        # 1. Fix 1: Binary garbage .eml rejected, valid .eml accepted
        eml_dir = stg / "Emails"
        eml_dir.mkdir(parents=True, exist_ok=True)
        (eml_dir / "garbage_nul.eml").write_bytes(b"From: a@b.test\r\nSubject: bad\x00hdr\r\n\r\nBody")
        (eml_dir / "garbage_non_rfc.eml").write_bytes(b"FakeKey: some_value\r\nOtherKey: 12345\r\n\r\nRandom payload")
        (eml_dir / "garbage_highbytes.eml").write_bytes(b"From: \xff\xfe\xfd\xfc\xfb\xfa\xf9\r\n\r\nBinary payload")
        (eml_dir / "valid.eml").write_bytes(
            b"From: sender@ex.test\r\nTo: rcpt@ex.test\r\nSubject: Legit Mail\r\nDate: Mon, 10 May 2021 12:00:00 +0000\r\nMessage-ID: <m1@ex.test>\r\n\r\nHello world"
        )
        EmailParser(case_id=case_id, staging_dir=stg).parse()
        conn = DuckDBManager.get_connection(case_id)
        eml_rows = conn.execute("SELECT sender, subject FROM parsed_emails;").fetchall()
        assert eml_rows == [("sender@ex.test", "Legit Mail")]

        # 2. Fixes 2 & 3: Slack system subtype rejected + list allow_id_map preserved
        ldb_dir = stg / "Users" / "Eve" / "AppData" / "Roaming" / "Slack" / "Local Storage" / "leveldb"
        ldb_dir.mkdir(parents=True, exist_ok=True)
        kv_i3 = [
            (b"s1", json.dumps({"type": "message", "subtype": "channel_join", "user": "U123", "text": "U123 joined", "ts": "1700000010.000100"}).encode("utf-8")),
            (b"s2", json.dumps({"messages": [{"sender_id": "u1", "text": "hi from list", "timestamp": 1700000020}]}).encode("utf-8")),
        ]
        wb_i3 = _build_leveldb_writebatch(kv_i3)
        (ldb_dir / "000007.log").write_bytes(struct.pack("<IHB", 0, len(wb_i3), 1) + wb_i3)
        ChatParser(case_id=case_id, staging_dir=stg).parse()
        chat_rows = conn.execute("SELECT sender, message_text FROM parsed_chat_messages;").fetchall()
        assert chat_rows == [("u1", "hi from list")]

        # 3. Fixes 4 & 5: CloudParser >120s unseeded folder staging -> NULL + append=True concurrency with parse_gdrive_logs
        _set_case_source_type(case_id, "folder")
        od_set = stg / "Users" / "Eve" / "AppData" / "Local" / "Microsoft" / "OneDrive" / "settings" / "Personal"
        od_set.mkdir(parents=True, exist_ok=True)
        unseeded_dat = od_set / "fedcba9876543210.dat"
        unseeded_dat.write_bytes(b"\xff\xfe" + "Account=eve@od.test\r\nSyncRoot=C:\\Users\\Eve\\OneDrive\r\n".encode("utf-16-le"))
        recent_180s = time.time() - 180.0
        os.utime(unseeded_dat, (recent_180s, recent_180s))

        gd_dir = stg / "Users" / "Eve" / "AppData" / "Local" / "Google" / "DriveFS" / "12345"
        gd_dir.mkdir(parents=True, exist_ok=True)
        gd_db = gd_dir / "metadata_sqlite_db"
        gconn = sqlite3.connect(str(gd_db))
        try:
            gconn.execute("CREATE TABLE items (stable_id INTEGER PRIMARY KEY, local_title TEXT, file_size INTEGER, modified_date INTEGER, is_folder INTEGER, trashed INTEGER);")
            gconn.execute("INSERT INTO items VALUES (1, 'budget.xlsx', 4096, 1620648000000, 0, 0);")
            gconn.commit()
        finally:
            gconn.close()

        def _append_gdrive_log_row() -> int:
            bp = CloudParser(case_id=case_id, staging_dir=stg, source_type="folder")
            with DuckDBManager.get_lock(case_id):
                c = DuckDBManager.get_connection(case_id)
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS parsed_gdrive_files (
                        _row_id BIGINT, cloud_provider VARCHAR, account VARCHAR, local_path VARCHAR,
                        cloud_path_or_id VARCHAR, file_size BIGINT, modified_time TIMESTAMP, status VARCHAR, source_file VARCHAR
                    );
                    """
                )
                existing_log = c.execute(
                    "SELECT COUNT(*) FROM parsed_gdrive_files WHERE cloud_provider = 'Google Drive' AND local_path = 'C:\\Users\\Eve\\Google Drive\\log_doc.pdf';"
                ).fetchone()[0]
                if existing_log == 0:
                    bp.insert_records(
                        table_name="parsed_gdrive_files",
                        records=[{
                            "cloud_provider": "Google Drive",
                            "account": "eve@gd.test",
                            "local_path": "C:\\Users\\Eve\\Google Drive\\log_doc.pdf",
                            "cloud_path_or_id": "log_doc.pdf",
                            "file_size": 0,
                            "modified_time": datetime(2021, 5, 10, 12, 0, 0),
                            "status": "SYNCED",
                            "source_file": "sync_log.log",
                        }],
                        artifact_id="gdrive_files",
                        category="CLOUD",
                        display_name="Google Drive Synced Files",
                        source_tool="CloudParser",
                        append=True,
                    )
                tot = c.execute("SELECT COUNT(*) FROM parsed_gdrive_files;").fetchone()[0]
                bp.register_artifact("parsed_gdrive_files", "gdrive_files", "CLOUD", "Google Drive Synced Files", "CloudParser", row_count=tot)
                return int(tot)

        # Order A: log row first, then CloudParser
        _append_gdrive_log_row()
        CloudParser(case_id=case_id, staging_dir=stg, source_type="folder").parse()
        assert {r[0] for r in conn.execute("SELECT cloud_provider FROM parsed_gdrive_files;").fetchall()} == {"Google Drive", "GoogleDrive"}

        # Order B + 16-worker concurrent race + re-run idempotence
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = [
                pool.submit(lambda i=idx: CloudParser(case_id=case_id, staging_dir=stg, source_type="folder").parse() if i % 2 == 0 else _append_gdrive_log_row())
                for idx in range(16)
            ]
            for f in futs:
                f.result()
        CloudParser(case_id=case_id, staging_dir=stg, source_type="folder").parse()
        gd_all = conn.execute("SELECT cloud_provider, local_path, cloud_path_or_id FROM parsed_gdrive_files;").fetchall()
        assert any(r[0] == "Google Drive" and r[2] == "log_doc.pdf" for r in gd_all)
        assert any(r[0] == "GoogleDrive" and "budget.xlsx" in str(r[1]) for r in gd_all)
        assert len([r for r in gd_all if r[0] == "GoogleDrive"]) == 1
        reg_cnt = conn.execute("SELECT row_count FROM artifact_registry WHERE artifact_id = 'gdrive_files';").fetchone()[0]
        assert reg_cnt == len(gd_all)
        od_unseeded_mtimes = conn.execute(
            "SELECT modified_time FROM parsed_onedrive_files WHERE account = 'eve@od.test';"
        ).fetchall()
        assert len(od_unseeded_mtimes) >= 1 and all(r[0] is None for r in od_unseeded_mtimes)

        # 4. Fixes 6 & 7: DocumentParser case_metadata.source_type='image' (no kwarg), NTFS recent si_created guard, and Part_0 vs Part_1 MOTW isolation
        img_case_id = f"m3b_i3_img_{os.getpid()}"
        img_case_dir = tmp_path / "cases" / img_case_id
        img_stg = img_case_dir / "staging"
        img_stg.mkdir(parents=True, exist_ok=True)
        register_case_dir(img_case_id, img_case_dir)
        init_case_db(img_case_id)
        try:
            _set_case_source_type(img_case_id, "image")
            min_pdf = (
                b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
                b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
            )
            p0_pdf = img_stg / "Enrichment" / "Part_0" / "Users" / "Alice" / "Downloads" / "dual_part.pdf"
            p1_pdf = img_stg / "Enrichment" / "Part_1" / "Users" / "Alice" / "Downloads" / "dual_part.pdf"
            p0_pdf.parent.mkdir(parents=True, exist_ok=True)
            p1_pdf.parent.mkdir(parents=True, exist_ok=True)
            p0_pdf.write_bytes(min_pdf)
            p1_pdf.write_bytes(min_pdf + b"%Part1\n")
            _seed_vfs_row(
                img_case_id,
                "/Part_0/Users/Alice/Downloads/dual_part.pdf",
                "Enrichment/Part_0/Users/Alice/Downloads/dual_part.pdf",
                "dual_part.pdf",
                p0_pdf.stat().st_size,
                "2021-05-10 12:00:00",
                "2021-05-01 08:30:00",
            )
            _seed_vfs_row(
                img_case_id,
                "/Part_1/Users/Alice/Downloads/dual_part.pdf",
                "Enrichment/Part_1/Users/Alice/Downloads/dual_part.pdf",
                "dual_part.pdf",
                p1_pdf.stat().st_size,
                "2021-05-10 12:00:00",
                "2021-05-02 08:30:00",
            )

            z_p0 = img_stg / "ZoneIdentifier" / "Part_0" / "Users" / "Alice" / "Downloads" / "dual_part.pdf.Zone.Identifier"
            z_p0.parent.mkdir(parents=True, exist_ok=True)
            z_p0.write_text("[ZoneTransfer]\nZoneId=3\nHostUrl=https://ex.test/part0.pdf\n", encoding="utf-8")

            # Text documents exercise _get_original_ctime_dt: note_hist.txt has genuine historical si_created;
            # note_staged.txt has host-staged recent si_created (within 24h) + old si_modified='2021-05-10'
            t_hist = img_stg / "Enrichment" / "Part_0" / "Users" / "Alice" / "Downloads" / "note_hist.txt"
            t_staged = img_stg / "Enrichment" / "Part_1" / "Users" / "Alice" / "Downloads" / "note_staged.txt"
            t_hist.write_text("Historical image text note\n", encoding="utf-8")
            t_staged.write_text("Host NTFS staged text note\n", encoding="utf-8")

            recent_ntfs_cr = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")
            _seed_vfs_row(
                img_case_id,
                "/Part_0/Users/Alice/Downloads/note_hist.txt",
                "Enrichment/Part_0/Users/Alice/Downloads/note_hist.txt",
                "note_hist.txt",
                t_hist.stat().st_size,
                "2021-05-10 12:00:00",
                "2021-05-01 08:30:00",
            )
            _seed_vfs_row(
                img_case_id,
                "/Part_1/Users/Alice/Downloads/note_staged.txt",
                "Enrichment/Part_1/Users/Alice/Downloads/note_staged.txt",
                "note_staged.txt",
                t_staged.stat().st_size,
                "2021-05-10 12:00:00",
                recent_ntfs_cr,
            )

            # Call DocumentParser WITHOUT source_type kwarg!
            DocumentParser(case_id=img_case_id, staging_dir=img_stg).parse()
            iconn = DuckDBManager.get_connection(img_case_id)
            t_rows = dict(
                iconn.execute(
                    "SELECT file_name, CAST(created_time AS VARCHAR) FROM parsed_text_documents WHERE file_name IN ('note_hist.txt', 'note_staged.txt');"
                ).fetchall()
            )
            assert t_rows["note_hist.txt"] == "2021-05-01 08:30:00"
            assert t_rows["note_staged.txt"] is None

            d_rows = iconn.execute(
                "SELECT file_path, zone_id, host_url FROM parsed_documents_metadata WHERE file_name='dual_part.pdf';"
            ).fetchall()
            assert len(d_rows) == 2
            r_p0 = [r for r in d_rows if "part_0" in r[0].lower()][0]
            r_p1 = [r for r in d_rows if "part_1" in r[0].lower()][0]
            assert r_p0[1] == 3 and r_p0[2] == "https://ex.test/part0.pdf"
            assert r_p1[1] is None and r_p1[2] is None
        finally:
            DuckDBManager.close_connection(img_case_id)
            unregister_case_dir(img_case_id)
    finally:
        DuckDBManager.close_connection(case_id)
        unregister_case_dir(case_id)
