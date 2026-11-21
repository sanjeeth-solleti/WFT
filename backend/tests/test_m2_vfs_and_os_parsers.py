"""
Milestone M2-C Isolated Verification Suite:
  1. DataCarver (all 10 formats, cross-8MB-chunk boundaries, zero-FP garbage rejection, and read-only NIST CFReDS rm#3_type2.dd)
  2. USBDeviceCorrelator (zero live winreg contamination, regipy/dissect.regf offline SYSTEM/SOFTWARE/NTUSER hives, signed +/- ActiveTimeBias setupapi.dev.log UTC conversion, UTF-16LE & ParentIdPrefix MountedDevices, MountPoints2)
  3. CorporateIRParser (multi-<Exec>/<ComHandler> UTF-16LE & UTF-8 Scheduled Tasks XML + offline SOFTWARE TaskCache + rip.exe cwd, deduplicated PowerShell -enc history, RMM TIMESTAMP safety, WPN toast XML)
  4. Static Anti-Cheat Source Audit (0 occurrences of hardcoded dataset cheat tokens)
"""
from __future__ import annotations

import gc
import hashlib
import io
import json
import os
import sqlite3
import struct
import subprocess
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from PIL import Image

from backend.config import register_case_dir
from backend.db.engine import DuckDBManager, init_case_db
from backend.parsers.corporate_ir_parser import CorporateIRParser
from backend.parsers.data_carver import CHUNK_SIZE, DataCarver
from backend.parsers.usb_correlator import USBDeviceCorrelator


RM3_DD_PATH = Path(
    r"C:\Users\2482965\Desktop\cfreds_\cfreds_2015_data_leakage_rm#3_type2\cfreds_2015_data_leakage_rm#3_type2.dd"
)


# =============================================================================
# Isolated Case Fixture & Synthetic Binary Artifact Builders
# =============================================================================
@pytest.fixture()
def isolated_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    appdata = tmp_path / "appdata"
    appdata.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(appdata / "custom_locations.json"))

    case_id = f"test_m2_{tmp_path.name}"
    case_dir = (tmp_path / "case_out").resolve()
    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    register_case_dir(case_id, case_dir)
    init_case_db(case_id)
    try:
        yield {
            "case_id": case_id,
            "case_dir": case_dir,
            "staging_dir": staging_dir,
        }
    finally:
        if hasattr(DuckDBManager, "close_connection"):
            DuckDBManager.close_connection(case_id)
        DuckDBManager.close_all()


def datetime_to_filetime(dt: datetime) -> int:
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    epoch_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = utc_dt - epoch_1601
    return int(delta.total_seconds() * 10_000_000)


class RegNodeSpec:
    """Specification node for building genuine binary Windows regf Registry hives."""

    def __init__(self, last_modified_dt: Optional[datetime] = None) -> None:
        self.subkeys: Dict[str, "RegNodeSpec"] = {}
        self.values: List[Tuple[str, int, bytes]] = []
        self.last_modified_ft: int = datetime_to_filetime(
            last_modified_dt or datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        )

    def ensure_path(
        self, rel_path: str, last_modified_dt: Optional[datetime] = None
    ) -> "RegNodeSpec":
        cur = self
        for part in rel_path.strip("\\/").split("\\"):
            if not part:
                continue
            if part not in cur.subkeys:
                cur.subkeys[part] = RegNodeSpec(last_modified_dt=last_modified_dt)
            elif last_modified_dt is not None:
                cur.subkeys[part].last_modified_ft = datetime_to_filetime(last_modified_dt)
            cur = cur.subkeys[part]
        return cur

    def add_sz(self, name: str, val: str) -> None:
        self.values.append((name, 1, val.encode("utf-16-le") + b"\x00\x00"))

    def add_dword(self, name: str, val: int) -> None:
        self.values.append((name, 4, struct.pack("<I", val & 0xFFFFFFFF)))

    def add_binary(self, name: str, raw: bytes, data_type: int = 3) -> None:
        self.values.append((name, data_type, bytes(raw)))

    def add_devprop_filetime(self, name: str, dt: datetime) -> None:
        self.values.append((name, 0xFFFF0010, struct.pack("<Q", datetime_to_filetime(dt))))


def build_synthetic_regf(root_spec: RegNodeSpec, bins_size: int = 0x4000) -> bytes:
    """
    Build a standards-compliant Windows regf binary hive parseable by BOTH
    regipy.registry.RegistryHive and dissect.regf.RegistryHive.
    """
    hbin = bytearray(bins_size)
    default_ft = root_spec.last_modified_ft
    struct.pack_into("<4sIIIIQI", hbin, 0, b"hbin", 0, bins_size, 0, 0, default_ft, 0)
    cur_off = 0x20

    def reserve_cell(payload_len: int) -> Tuple[int, int]:
        nonlocal cur_off
        total = (4 + payload_len + 7) & ~7
        if total < 8:
            total = 8
        assert cur_off + total <= bins_size, "Increase bins_size for synthetic regf"
        off = cur_off
        struct.pack_into("<i", hbin, off, -total)
        cur_off += total
        return off, total

    def alloc_cell(payload: bytes) -> int:
        off, _ = reserve_cell(len(payload))
        hbin[off + 4 : off + 4 + len(payload)] = payload
        return off

    def emit_nk(name: str, spec: RegNodeSpec, parent_off: int, is_root: bool) -> int:
        name_b = name.encode("ascii", errors="replace")
        nk_len = 76 + len(name_b)
        nk_off, _ = reserve_cell(nk_len)  # Root gets reserved at 0x20 first!

        # Emit values
        val_offsets: List[int] = []
        max_vname = 0
        max_vdata = 0
        for v_name, v_type, v_bytes in spec.values:
            data_off = alloc_cell(v_bytes)
            if v_name == "" or v_name.lower() == "(default)":
                vn_b = b""
                v_flags = 0
            else:
                vn_b = v_name.encode("ascii", errors="replace")
                v_flags = 0x0001  # VALUE_COMP_NAME
            max_vname = max(max_vname, len(vn_b) * 2)
            max_vdata = max(max_vdata, len(v_bytes))
            vk_payload = (
                struct.pack(
                    "<2sHIIIHH",
                    b"vk",
                    len(vn_b),
                    len(v_bytes),
                    data_off,
                    v_type & 0xFFFFFFFF,
                    v_flags,
                    0,
                )
                + vn_b
            )
            val_offsets.append(alloc_cell(vk_payload))

        if val_offsets:
            vlist_payload = b"".join(struct.pack("<I", vo) for vo in val_offsets)
            vlist_off = alloc_cell(vlist_payload)
        else:
            vlist_off = 0xFFFFFFFF

        # Emit sorted subkeys + 'lf' fast leaf
        sorted_children = sorted(spec.subkeys.items(), key=lambda kv: kv[0].upper())
        child_entries: List[Tuple[int, bytes]] = []
        max_sk_name = 0
        for ch_name, ch_spec in sorted_children:
            max_sk_name = max(max_sk_name, len(ch_name) * 2)
            ch_off = emit_nk(ch_name, ch_spec, nk_off, is_root=False)
            hint = ch_name.encode("ascii", errors="replace")[:4].ljust(4, b"\x00")
            child_entries.append((ch_off, hint))

        if child_entries:
            lf_payload = bytearray(struct.pack("<2sH", b"lf", len(child_entries)))
            for ch_off, hint in child_entries:
                lf_payload.extend(struct.pack("<I4s", ch_off, hint))
            subkeys_list_off = alloc_cell(bytes(lf_payload))
        else:
            subkeys_list_off = 0xFFFFFFFF

        flags = 0x0020 | (0x0004 if is_root else 0x0000)
        nk_body = (
            struct.pack(
                "<2sHQIIIIIIIIIIIIIIIHH",
                b"nk",
                flags,
                spec.last_modified_ft,
                0,  # access_bits
                parent_off & 0xFFFFFFFF,
                len(child_entries),
                0,  # volatile_subkey_count
                subkeys_list_off,
                0xFFFFFFFF,  # volatile_subkeys_list_offset
                len(val_offsets),
                vlist_off,
                0xFFFFFFFF,  # security_key_offset
                0xFFFFFFFF,  # class_name_offset
                max_sk_name,
                0,
                max_vname,
                max_vdata,
                0,  # unknown
                len(name_b),
                0,  # class_name_size
            )
            + name_b
        )
        hbin[nk_off + 4 : nk_off + 4 + len(nk_body)] = nk_body
        return nk_off

    root_off = emit_nk("CMI-CreateHive", root_spec, 0xFFFFFFFF, is_root=True)
    assert root_off == 0x20

    if cur_off < bins_size:
        struct.pack_into("<i", hbin, cur_off, bins_size - cur_off)

    regf_hdr = bytearray(4096)
    struct.pack_into(
        "<4sIIQIIIIIII",
        regf_hdr,
        0,
        b"regf",
        1,
        1,
        default_ft,
        1,
        5,
        0,
        1,
        0x20,
        bins_size,
        1,
    )
    csum = 0
    for off in range(0, 0x1FC, 4):
        csum ^= struct.unpack_from("<I", regf_hdr, off)[0]
    struct.pack_into("<I", regf_hdr, 0x1FC, csum)

    return bytes(regf_hdr) + bytes(hbin)


def _build_jpeg_with_exif_thumbnail() -> bytes:
    """Build a valid JPEG that embeds a nested JPEG thumbnail inside APP1 before the main SOS."""
    thumb_io = io.BytesIO()
    Image.new("RGB", (8, 8), color=(200, 50, 50)).save(thumb_io, format="JPEG")
    thumb_bytes = thumb_io.getvalue()

    main_io = io.BytesIO()
    img = Image.new("RGB", (32, 24), color=(20, 120, 220))
    img.save(main_io, format="JPEG")
    main_bytes = main_io.getvalue()

    # Inject APP1 (FF E1) segment containing nested FFD8...FFD9 thumbnail right after SOI (FFD8)
    app1_payload = b"Exif\x00\x00" + thumb_bytes
    app1_seg = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    return main_bytes[:2] + app1_seg + main_bytes[2:]


def _build_minimal_pe64(is_dll: bool = False) -> bytes:
    """Build a genuine, minimal PE32+ (AMD64) EXE or DLL verified parseable by pefile."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    characteristics = 0x0022 | (0x2000 if is_dll else 0x0000)
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # AMD64
        1,       # NumberOfSections
        0x66500000,
        0,
        0,
        0xF0,    # SizeOfOptionalHeader (PE32+)
        characteristics,
    )

    opt = bytearray(0xF0)
    struct.pack_into("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", opt, 0,
        0x20B,   # PE32+ Magic
        14, 0,   # Linker
        0x200,   # SizeOfCode
        0, 0,
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        0x140000000,  # ImageBase
        0x1000,  # SectionAlignment
        0x200,   # FileAlignment
        6, 0, 0, 0, 6, 0,
        0,
        0x2000,  # SizeOfImage
        0x200,   # SizeOfHeaders
        0,
        3,       # Subsystem CUI
        0x8160,  # DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0,
        16,      # NumberOfRvaAndSizes
    )

    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,   # VirtualSize
        0x1000,  # VirtualAddress
        0x200,   # SizeOfRawData
        0x200,   # PointerToRawData
        0, 0, 0, 0,
        0x60000020,
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec_hdr
    headers_padded = headers.ljust(0x200, b"\x00")
    code_sec = (b"\x48\x31\xc0\xc3" if not is_dll else b"\xb8\x01\x00\x00\x00\xc3").ljust(0x200, b"\x90")
    return headers_padded + code_sec


def _build_valid_lnk() -> bytes:
    """Build a genuine MS-SHLLINK (.lnk) shortcut binary with IDList, Unicode RelativePath, and ExtraData."""
    clsid = bytes.fromhex("0114020000000000C000000000000046")
    # HasLinkTargetIDList (0x01) | HasRelativePath (0x08) | IsUnicode (0x80)
    link_flags = 0x01 | 0x08 | 0x80
    ft = datetime_to_filetime(datetime(2024, 5, 10, 8, 30, 0, tzinfo=timezone.utc))
    hdr = bytearray(76)
    struct.pack_into("<I", hdr, 0, 0x4C)
    hdr[4:20] = clsid
    struct.pack_into("<IIQQQIIIHHI", hdr, 20, link_flags, 0x20, ft, ft, ft, 4096, 0, 1, 0, 0, 0)
    struct.pack_into("<I", hdr, 72, 0)

    # LinkTargetIDList: 1 item (20 bytes) + 2-byte 0x0000 terminator
    item_body = b"\x1f\x50" + b"\xe0\x4f\xd0\x20\xea\x3a\x69\x10\xa2\xd8\x08\x00\x2b\x30\x30\x9d"
    item = struct.pack("<H", len(item_body) + 2) + item_body
    idlist_bytes = item + b"\x00\x00"
    idlist = struct.pack("<H", len(idlist_bytes)) + idlist_bytes

    # StringData: RELATIVE_PATH (Unicode cch + UTF-16LE chars)
    rel_str = r".\Documents\report.pdf"
    rel_data = struct.pack("<H", len(rel_str)) + rel_str.encode("utf-16-le")

    # ExtraData: SpecialFolderDataBlock (size=16, sig=0xA0000005) + 4-byte TerminalBlock (0x00000000)
    extra = struct.pack("<IIII", 16, 0xA0000005, 5, 0) + struct.pack("<I", 0)
    return bytes(hdr) + idlist + rel_data + extra


def _build_valid_evtx() -> bytes:
    """Build a valid 69,632-byte single-chunk EVTX binary (4096B ElfFile header + 65536B ElfChnk)."""
    hdr = bytearray(4096)
    hdr[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", hdr, 8, 0, 0, 1, 128, 1, 3, 4096, 1)
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    return bytes(hdr) + bytes(chunk)


def _build_valid_sqlite(tmp_dir: Path) -> bytes:
    db_file = tmp_dir / "sample_carve.sqlite"
    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute("PRAGMA page_size = 4096;")
        conn.execute("CREATE TABLE evidence_notes (id INTEGER PRIMARY KEY, note TEXT);")
        conn.execute("INSERT INTO evidence_notes (note) VALUES ('forensic sqlite carve check');")
        conn.commit()
    finally:
        conn.close()
    return db_file.read_bytes()


def _build_valid_docx_with_inner_zip() -> bytes:
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", compression=zipfile.ZIP_STORED) as izf:
        izf.writestr("embedded_note.txt", "Nested archive inside OOXML")
    inner_zip_bytes = inner_buf.getvalue()

    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w", compression=zipfile.ZIP_DEFLATED) as ozf:
        ozf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
        )
        ozf.writestr("word/document.xml", "<w:document><w:body><w:p>Confidential Plan</w:p></w:body></w:document>")
        # Stored uncompressed so inner PK\x05\x06 EOCD exists literally inside the outer .docx byte range!
        zi = zipfile.ZipInfo("word/embeddings/sub.zip")
        zi.compress_type = zipfile.ZIP_STORED
        ozf.writestr(zi, inner_zip_bytes)
    return outer_buf.getvalue()


def _build_valid_pdf_1page(body_text: str = "WFT Forensic Carve") -> bytes:
    """Build a standards-compliant 1-page PDF 1.7 with exact xref byte offsets."""
    header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    stream_payload = f"BT /F1 12 Tf 72 720 Td ({body_text}) Tj ET".encode("ascii")
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n",
        f"4 0 obj\n<< /Length {len(stream_payload)} >>\nstream\n".encode("ascii")
        + stream_payload
        + b"\nendstream\nendobj\n",
    ]
    buf = bytearray(header)
    offsets: List[int] = []
    for obj in objects:
        offsets.append(len(buf))
        buf.extend(obj)
    xref_off = len(buf)
    buf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(buf)


# =============================================================================
# 1. DataCarver Synthetic Stream (All 10 Formats + Cross-Chunk + Zero False Positives)
# =============================================================================
def test_data_carver_all_10_formats_cross_chunk_and_zero_false_positives(
    isolated_case: Dict[str, Any], tmp_path: Path
) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]

    # Build all valid artifacts
    jpg_blob = _build_jpeg_with_exif_thumbnail()

    png_io = io.BytesIO()
    Image.new("RGBA", (20, 20), color=(10, 200, 80, 255)).save(png_io, format="PNG")
    png_blob = png_io.getvalue()

    gif_io = io.BytesIO()
    Image.new("P", (16, 16), color=3).save(gif_io, format="GIF")
    gif_blob = gif_io.getvalue()

    pdf_blob = _build_valid_pdf_1page("Cross-Chunk Forensic PDF")

    zip_io = io.BytesIO()
    with zipfile.ZipFile(zip_io, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"artifact": "standalone_zip"}')
    zip_blob = zip_io.getvalue()

    docx_blob = _build_valid_docx_with_inner_zip()
    sqlite_blob = _build_valid_sqlite(tmp_path)
    evtx_blob = _build_valid_evtx()
    reg_root = RegNodeSpec()
    reg_root.ensure_path("ControlSet001\\Control").add_sz("ComputerName", "WIN-FORENSIC")
    regf_blob = build_synthetic_regf(reg_root, bins_size=0x1000)
    exe_blob = _build_minimal_pe64(is_dll=False)
    dll_blob = _build_minimal_pe64(is_dll=True)
    lnk_blob = _build_valid_lnk()

    # Build corrupted / garbage decoys that MUST produce 0 false positives
    corrupt_mz_1 = b"MZ\x90\x00" + b"\xde\xad\xbe\xef" * 64
    corrupt_mz_2 = bytearray(256)
    corrupt_mz_2[0:2] = b"MZ"
    struct.pack_into("<I", corrupt_mz_2, 0x3C, 0x80)
    corrupt_mz_2[0x80:0x86] = b"PE\x00\x00\x64\x86"  # 0 sections / truncated PE
    corrupt_jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xaa\xbb\xff\xd9"
    corrupt_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    corrupt_gif = b"GIF89a\x10\x00\x10\x00\x80\x00\x00" + b"\xff" * 40 + b"\x3b"
    corrupt_pdf = b"%PDF-1.7\n1 0 obj\n<< /Info (truncated without eof) >>\nendobj\n"
    corrupt_zip = b"PK\x03\x04" + b"\x14\x00" * 30 + b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, 50, 14, 0)
    corrupt_sqlite = b"SQLite format 3\x00" + b"\x10\x00\x01\x01\x00\x40\x20\x20" + b"\xaa" * 200
    corrupt_evtx = b"ElfFile\x00" + b"\x00" * 4120
    corrupt_regf = b"regf" + b"\x00" * 4120

    # Assemble 10 MiB raw image spanning the 8 MiB CHUNK_SIZE boundary!
    total_stream_len = CHUNK_SIZE + 2 * 1024 * 1024  # 10 MiB
    stream = bytearray(b"\x55" * total_stream_len)

    expected_items: List[Tuple[str, str, int, bytes]] = []

    def place_valid(ftype: str, ext: str, offset: int, data: bytes) -> None:
        stream[offset : offset + len(data)] = data
        expected_items.append((ftype, ext, offset, data))

    def place_garbage(offset: int, data: bytes) -> None:
        stream[offset : offset + len(data)] = data

    # Chunk 0 placements
    place_garbage(0x001000, corrupt_mz_1)
    place_garbage(0x002000, bytes(corrupt_mz_2))
    place_valid("jpg", "jpg", 0x010000, jpg_blob)
    place_garbage(0x020000, corrupt_jpg)
    place_valid("png", "png", 0x030000, png_blob)
    place_garbage(0x040000, corrupt_png)
    place_valid("gif", "gif", 0x050000, gif_blob)
    place_garbage(0x060000, corrupt_gif)
    place_valid("zip", "zip", 0x070000, zip_blob)
    place_garbage(0x080000, corrupt_zip)
    place_valid("evtx", "evtx", 0x090000, evtx_blob)
    place_garbage(0x0B0000, corrupt_evtx)
    place_valid("regf", "regf", 0x0C0000, regf_blob)
    place_garbage(0x0D0000, corrupt_regf)
    place_valid("exe", "exe", 0x0E0000, exe_blob)
    place_valid("dll", "dll", 0x0F0000, dll_blob)
    place_valid("lnk", "lnk", 0x100000, lnk_blob)
    place_garbage(0x110000, corrupt_pdf)
    place_garbage(0x120000, corrupt_sqlite)

    # Cross-8MB-chunk boundary placements!
    # 1) PDF starting 10 bytes before CHUNK_SIZE (header & body straddle 8 MiB boundary!)
    pdf_cross_off = CHUNK_SIZE - 10
    place_valid("pdf", "pdf", pdf_cross_off, pdf_blob)

    # 2) DOCX (with nested sub.zip inside!) starting in chunk 0 and EOCD landing in chunk 1!
    # Place at CHUNK_SIZE + 4096 - len(docx)//2? Wait: pdf is at CHUNK_SIZE - 10 .. CHUNK_SIZE + ~170.
    # Let's place DOCX in a second cross-chunk test or place DOCX before PDF? No: if DOCX starts at CHUNK_SIZE - 500
    # and is ~600 bytes, it would overlap CHUNK_SIZE - 10! So put PDF in chunk 0->1? Only ONE file can occupy byte CHUNK_SIZE!
    # Let's make the stream 17 MiB (2 chunk boundaries: 8 MiB and 16 MiB!) so PDF crosses 8 MiB AND DOCX crosses 16 MiB!
    stream.extend(b"\x55" * (7 * 1024 * 1024))  # Total = 17 MiB!
    docx_cross_off = (2 * CHUNK_SIZE) - (len(docx_blob) // 2)
    place_valid("docx", "docx", docx_cross_off, docx_blob)

    # Chunk 1 placement for SQLite
    place_valid("sqlite", "sqlite", CHUNK_SIZE + 0x20000, sqlite_blob)

    raw_img_path = tmp_path / "synthetic_cross_chunk.dd"
    raw_img_path.write_bytes(bytes(stream))

    carver = DataCarver(case_id=case_id, case_dir=case_dir)
    summary = carver.run(raw_img_path, max_workers=8)

    assert summary["status"] == "SUCCESS"
    assert summary["source_regions"] == ["raw_stream"]
    # Exactly 12 valid files (10 format families including zip+docx and exe+dll), 0 inner sub-ZIPs, 0 garbage FPs!
    assert summary["carved_count"] == len(expected_items) == 12

    conn = DuckDBManager.get_connection(case_id)
    rows = conn.execute(
        """
        SELECT carve_id, file_type, extension, offset_bytes, size_bytes, sha256,
               carved_rel_path, source_region, header_sig, validated
        FROM parsed_carved_files
        ORDER BY offset_bytes ASC;
        """
    ).fetchall()
    assert len(rows) == 12

    by_offset = {int(r[3]): r for r in rows}
    for exp_type, exp_ext, exp_off, exp_blob in expected_items:
        assert exp_off in by_offset, f"Missing carved {exp_type} at offset {exp_off}"
        row = by_offset[exp_off]
        assert row[1] == exp_type
        assert row[2] == exp_ext
        assert int(row[4]) == len(exp_blob)
        exp_sha = hashlib.sha256(exp_blob).hexdigest()
        assert row[5] == exp_sha
        assert row[7] == "raw_stream"
        assert row[9] is True
        disk_file = case_dir / row[6]
        assert disk_file.is_file()
        assert hashlib.sha256(disk_file.read_bytes()).hexdigest() == exp_sha


# =============================================================================
# 2. DataCarver on Real Read-Only NIST CFReDS rm#3_type2.dd
# =============================================================================
@pytest.mark.skipif(not RM3_DD_PATH.is_file(), reason="NIST CFReDS rm#3_type2.dd dataset not present on host")
def test_data_carver_real_cfreds_rm3_type2_dd_readonly(isolated_case: Dict[str, Any]) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]

    stat_before = RM3_DD_PATH.stat()
    assert stat_before.st_size == 107_548_672

    carver = DataCarver(case_id=case_id, case_dir=case_dir)
    res = carver.run(RM3_DD_PATH, max_workers=16)

    # Confirm dataset stayed 100% read-only and untouched
    stat_after = RM3_DD_PATH.stat()
    assert stat_after.st_size == stat_before.st_size
    assert stat_after.st_mtime_ns == stat_before.st_mtime_ns

    assert res["status"] == "SUCCESS"
    by_type = res["by_type"]
    assert by_type.get("docx") == 5
    assert by_type.get("xlsx") == 2
    assert by_type.get("pptx") == 2
    assert by_type.get("jpg", 0) >= 3
    assert by_type.get("png", 0) >= 10
    assert by_type.get("gif", 0) >= 1
    # All 1,625 random 'MZ' byte pairs inside UDF/OOXML compressed streams must be rejected!
    assert by_type.get("exe", 0) == 0
    assert by_type.get("dll", 0) == 0

    conn = DuckDBManager.get_connection(case_id)
    unvalidated = conn.execute(
        "SELECT COUNT(*) FROM parsed_carved_files WHERE validated IS DISTINCT FROM TRUE;"
    ).fetchone()[0]
    assert unvalidated == 0

    ooxml_rows = conn.execute(
        """
        SELECT file_type, extension, size_bytes, sha256, carved_rel_path
        FROM parsed_carved_files
        WHERE file_type IN ('docx', 'xlsx', 'pptx')
        ORDER BY offset_bytes ASC;
        """
    ).fetchall()
    assert len(ooxml_rows) == 9
    # Verify cross-8MB-chunk 16.38 MB PPTX and 10.24 MB XLSX were recovered intact and pass SHA-256 + zipfile checks
    sizes = sorted(int(r[2]) for r in ooxml_rows)
    assert any(sz > 15_000_000 for sz in sizes), "16.38 MB cross-chunk .pptx missing"
    assert any(10_000_000 < sz < 11_000_000 for sz in sizes), "10.24 MB cross-chunk .xlsx missing"

    for _ftype, _ext, sz, sha, rel_p in ooxml_rows:
        out_f = case_dir / rel_p
        assert out_f.is_file()
        raw_b = out_f.read_bytes()
        assert len(raw_b) == int(sz)
        assert hashlib.sha256(raw_b).hexdigest() == sha
        with zipfile.ZipFile(io.BytesIO(raw_b), "r") as zf:
            assert "[Content_Types].xml" in zf.namelist()


# =============================================================================
# 3. USBDeviceCorrelator: Zero Host winreg + +/- ActiveTimeBias + Offline Hives
# =============================================================================
def test_usb_correlator_offline_positive_and_negative_bias_zero_winreg(
    isolated_case: Dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.name == "nt":
        import winreg

        def _forbid_winreg(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("Host winreg MUST NEVER be called during offline USB correlation!")

        monkeypatch.setattr(winreg, "OpenKey", _forbid_winreg)
        monkeypatch.setattr(winreg, "OpenKeyEx", _forbid_winreg)

    # --- Subcase A: Positive ActiveTimeBias (+240 EDT = UTC-4), ParentIdPrefix MountedDevices, WPD & MountPoints2 ---
    case_id_a = isolated_case["case_id"]
    staging_a = isolated_case["staging_dir"]
    (staging_a / "Registry" / "System").mkdir(parents=True, exist_ok=True)
    (staging_a / "Registry" / "Users" / "Alice").mkdir(parents=True, exist_ok=True)

    first_install_dt = datetime(2024, 7, 10, 9, 0, 0, tzinfo=timezone.utc)
    last_arrival_dt = datetime(2024, 7, 15, 16, 45, 0, tzinfo=timezone.utc)
    mp2_dt = datetime(2024, 7, 15, 17, 0, 0, tzinfo=timezone.utc)

    sys_spec_a = RegNodeSpec()
    sys_spec_a.ensure_path("Select").add_dword("Current", 2)
    sys_spec_a.ensure_path("ControlSet002\\Control\\TimeZoneInformation").add_dword("ActiveTimeBias", 240)

    inst_node = sys_spec_a.ensure_path(
        "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\\60A44C4138F9FF70&0",
        last_modified_dt=first_install_dt,
    )
    inst_node.add_sz("FriendlyName", "Kingston DataTraveler 3.0 USB Device")
    inst_node.add_sz("ParentIdPrefix", "7&2a8b9c10&0")
    inst_node.add_sz("ContainerID", "{11111111-aaaa-bbbb-cccc-000000000001}")

    # 0064 direct DEVPROP_TYPE_FILETIME (Win10/11 style) + 0066\0000 subkey FILETIME (Win7 style)
    p0064 = sys_spec_a.ensure_path(
        "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\\60A44C4138F9FF70&0\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064"
    )
    p0064.add_devprop_filetime("", first_install_dt)
    p0066_sub = sys_spec_a.ensure_path(
        "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\\60A44C4138F9FF70&0\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066\\0000"
    )
    p0066_sub.add_devprop_filetime("", last_arrival_dt)

    usb_enum_node = sys_spec_a.ensure_path("ControlSet002\\Enum\\USB\\VID_0951&PID_1666\\60A44C4138F9FF70")
    usb_enum_node.add_sz("ContainerID", "{11111111-aaaa-bbbb-cccc-000000000001}")

    md_bytes_a = (
        r"\??\STORAGE#RemovableMedia#7&2a8b9c10&0&RM#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
    ).encode("utf-16-le")
    md_node_a = sys_spec_a.ensure_path("MountedDevices")
    md_node_a.add_binary(r"\DosDevices\F:", md_bytes_a)
    md_node_a.add_binary(r"\??\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", md_bytes_a)

    (staging_a / "Registry" / "System" / "SYSTEM").write_bytes(build_synthetic_regf(sys_spec_a, bins_size=0x4000))

    sw_spec_a = RegNodeSpec()
    wpd_dev = sw_spec_a.ensure_path(
        "Microsoft\\Windows Portable Devices\\Devices\\WPDBUSENUMROOT#UMB#2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP#60A44C4138F9FF70&0#"
    )
    wpd_dev.add_sz("FriendlyName", "CORP_VAULT")
    (staging_a / "Registry" / "System" / "SOFTWARE").write_bytes(build_synthetic_regf(sw_spec_a, bins_size=0x2000))

    nt_spec_a = RegNodeSpec()
    nt_spec_a.ensure_path(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
        last_modified_dt=mp2_dt,
    )
    (staging_a / "Registry" / "Users" / "Alice" / "NTUSER.DAT").write_bytes(
        build_synthetic_regf(nt_spec_a, bins_size=0x2000)
    )

    # Backslash-separated USBSTOR hardware ID in setupapi.dev.log at 10:30:00 local EDT (+240m -> 14:30:00 UTC)
    setupapi_a = (
        "[Device Install Log]\n"
        ">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide&Rev_1.26\\200445269107B5A1&0]\n"
        ">>>  Section start 2024/07/15 10:30:00.000\n"
        "     dvi: {Install Device - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide&Rev_1.26\\200445269107B5A1&0}\n"
        "<<<  Section end 2024/07/15 10:30:02.000\n"
    )
    (staging_a / "setupapi.dev.log").write_text(setupapi_a, encoding="utf-8")

    res_a = USBDeviceCorrelator(case_id=case_id_a, staging_dir=staging_a).parse()
    assert res_a["parsed_usb_devices"] == 2

    conn_a = DuckDBManager.get_connection(case_id_a)
    rows_a = {
        r[0]: r
        for r in conn_a.execute(
            """
            SELECT serial_number, vendor_id, product_id, friendly_name, drive_letter,
                   volume_guid, first_connected_utc, last_connected_utc, source_evidence
            FROM parsed_usb_devices;
            """
        ).fetchall()
    }

    k_row = rows_a["60A44C4138F9FF70"]
    assert k_row[1] == "Kingston"
    assert k_row[4] == "F:"
    assert k_row[5].lower() == "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"
    assert "CORP_VAULT" in k_row[3]
    assert k_row[6].replace(tzinfo=None) == datetime(2024, 7, 10, 9, 0, 0)
    assert k_row[7].replace(tzinfo=None) == datetime(2024, 7, 15, 17, 0, 0)
    assert "MountPoints2(Alice)" in k_row[8]
    assert "VID_0951&PID_1666" in k_row[8]

    s_row = rows_a["200445269107B5A1"]
    # 10:30:00 local EDT + 240 min = 14:30:00 UTC!
    assert s_row[6].replace(tzinfo=None) == datetime(2024, 7, 15, 14, 30, 0)

    # --- Subcase B: Negative ActiveTimeBias (-330 IST = UTC+5:30 -> 0xFFFFFEBA) & UTF-16LE serial MountedDevices ---
    case_id_b = f"{case_id_a}_neg"
    case_dir_b = (tmp_path / "case_neg").resolve()
    staging_b = case_dir_b / "staging"
    (staging_b / "Registry" / "System").mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id_b, case_dir_b)
    init_case_db(case_id_b)

    try:
        sys_spec_b = RegNodeSpec()
        sys_spec_b.ensure_path("Select").add_dword("Current", 1)
        # -330 signed int32 = 0xFFFFFEBA
        sys_spec_b.ensure_path("ControlSet001\\Control\\TimeZoneInformation").add_dword(
            "ActiveTimeBias", (-330) & 0xFFFFFFFF
        )
        sys_spec_b.ensure_path(
            "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Samsung&Prod_Flash_Drive&Rev_1100\\0375921040001999&0",
            last_modified_dt=datetime(2024, 11, 5, 8, 0, 0, tzinfo=timezone.utc),
        ).add_sz("FriendlyName", "Samsung Flash Drive USB Device")

        md_bytes_b = (
            r"\??\USBSTOR#Disk&Ven_Samsung&Prod_Flash_Drive&Rev_1100#0375921040001999&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        ).encode("utf-16-le")
        md_node_b = sys_spec_b.ensure_path("MountedDevices")
        md_node_b.add_binary(r"\DosDevices\G:", md_bytes_b)
        md_node_b.add_binary(r"\??\Volume{12345678-1234-1234-1234-123456789abc}", md_bytes_b)

        (staging_b / "Registry" / "System" / "SYSTEM").write_bytes(build_synthetic_regf(sys_spec_b, bins_size=0x3000))

        # 17:30:00 local IST (-330 min) -> 12:00:00 UTC!
        setupapi_b = (
            "[Device Install Log]\n"
            ">>>  [Device Install - USBSTOR#Disk&Ven_Samsung&Prod_Flash_Drive&Rev_1100#0375921040001999&0]\n"
            ">>>  Section start 2024/11/02 17:30:00.000\n"
            "<<<  Section end 2024/11/02 17:30:05.000\n"
        )
        (staging_b / "setupapi.dev.log").write_text(setupapi_b, encoding="utf-8")

        res_b = USBDeviceCorrelator(case_id=case_id_b, staging_dir=staging_b).parse()
        assert res_b["parsed_usb_devices"] == 1

        conn_b = DuckDBManager.get_connection(case_id_b)
        row_b = conn_b.execute(
            "SELECT drive_letter, volume_guid, first_connected_utc, last_connected_utc FROM parsed_usb_devices WHERE serial_number = '0375921040001999';"
        ).fetchone()
        assert row_b is not None
        assert row_b[0] == "G:"
        assert row_b[1].lower() == "{12345678-1234-1234-1234-123456789abc}"
        assert row_b[2].replace(tzinfo=None) == datetime(2024, 11, 2, 12, 0, 0)
        assert row_b[3].replace(tzinfo=None) == datetime(2024, 11, 5, 8, 0, 0)
    finally:
        if hasattr(DuckDBManager, "close_connection"):
            DuckDBManager.close_connection(case_id_b)


# =============================================================================
# 4. CorporateIRParser: Multi-Exec Tasks XML + TaskCache + PS -enc + RMM + WPN + Anti-Cheat
# =============================================================================
def test_corporate_ir_parser_end_to_end_accuracy(
    isolated_case: Dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    case_id = isolated_case["case_id"]
    staging = isolated_case["staging_dir"]

    # 1. Multi-<Exec> + <ComHandler> UTF-16LE BOM Scheduled Task XML + UTF-8 XML
    tasks_sub = staging / "Tasks" / "CorpOps"
    tasks_sub.mkdir(parents=True, exist_ok=True)
    multi_exec_xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-08-19T09:15:42.7654321Z</Date>
    <Author>CORP\\SecAdmin</Author>
    <URI>\\CorpOps\\NightlyTriage</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger><StartBoundary>2024-08-19T22:00:00</StartBoundary></CalendarTrigger>
  </Triggers>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Tools\\collector.exe</Command>
      <Arguments>--snapshot --quiet</Arguments>
      <WorkingDirectory>C:\\Tools</WorkingDirectory>
    </Exec>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\upload.ps1</Arguments>
      <WorkingDirectory>C:\\Users\\Public</WorkingDirectory>
    </Exec>
    <ComHandler>
      <ClassId>{01234567-89AB-CDEF-0123-456789ABCDEF}</ClassId>
      <Data>sync_mode=fast</Data>
    </ComHandler>
  </Actions>
</Task>"""
    (tasks_sub / "NightlyTriage").write_bytes(b"\xff\xfe" + multi_exec_xml.encode("utf-16-le"))

    utf8_task_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>
  <RegistrationInfo><Date>2024-09-01T12:00:00</Date><Author>SYSTEM</Author></RegistrationInfo>
  <Actions><Exec><Command>C:\\Windows\\System32\\sc.exe</Command><Arguments>query eventlog</Arguments></Exec></Actions>
</Task>"""
    (staging / "Tasks" / "HealthCheck.xml").write_bytes(utf8_task_xml.encode("utf-8"))

    # Offline Registry SOFTWARE hive with TaskCache\Tree + TaskCache\Tasks (0x6666 binary Actions blob)
    (staging / "Registry" / "System").mkdir(parents=True, exist_ok=True)
    sw_spec = RegNodeSpec()
    task_guid = "{99999999-8888-7777-6666-555555555555}"
    sw_spec.ensure_path(
        "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Updater\\PersistenceCheck"
    ).add_sz("Id", task_guid)

    reg_ft = datetime_to_filetime(datetime(2024, 8, 20, 14, 0, 0, tzinfo=timezone.utc))
    run_ft = datetime_to_filetime(datetime(2024, 8, 21, 3, 0, 0, tzinfo=timezone.utc))
    dyn_info = struct.pack("<IQQII", 3, reg_ft, run_ft, 0, 0)

    def _u16_len_prefixed(s: str) -> bytes:
        b = s.encode("utf-16-le")
        return struct.pack("<I", len(b)) + b

    actions_blob = (
        struct.pack("<H", 3)
        + _u16_len_prefixed("Author")
        + struct.pack("<H", 0x6666)
        + _u16_len_prefixed("Act1")
        + _u16_len_prefixed(r"C:\Windows\System32\rundll32.exe")
        + _u16_len_prefixed(r"C:\ProgramData\beacon.dll,Start")
        + _u16_len_prefixed(r"C:\ProgramData")
        + struct.pack("<H", 0)
    )
    t_node = sw_spec.ensure_path(
        f"Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{task_guid}"
    )
    t_node.add_sz("URI", r"\Updater\PersistenceCheck")
    t_node.add_sz("Author", "UpdaterSvc")
    t_node.add_binary("DynamicInfo", dyn_info)
    t_node.add_binary("Actions", actions_blob)
    (staging / "Registry" / "System" / "SOFTWARE").write_bytes(build_synthetic_regf(sw_spec, bins_size=0x3000))

    # Verify rip.exe receives cwd=str(rip_exe.parent) when configured
    fake_rip_dir = tmp_path / "fake_regripper"
    fake_rip_dir.mkdir(parents=True, exist_ok=True)
    fake_rip_exe = fake_rip_dir / "rip.exe"
    fake_rip_exe.write_bytes(b"MZ")
    recorded_cwds: List[Optional[str]] = []
    real_subproc_run = subprocess.run

    def _spy_subproc_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(cmd, list) and cmd and Path(cmd[0]).name.lower() == "rip.exe":
            recorded_cwds.append(kwargs.get("cwd"))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return real_subproc_run(cmd, *args, **kwargs)

    import backend.config as b_cfg
    monkeypatch.setattr(b_cfg, "find_regripper_binary", lambda: fake_rip_exe)
    monkeypatch.setattr(subprocess, "run", _spy_subproc_run)

    # 2. PowerShell ConsoleHost_history.txt (root + nested user subdir — verify 1x count & -enc match)
    (staging / "PowerShell" / "Bob").mkdir(parents=True, exist_ok=True)
    (staging / "PowerShell" / "ALICE_ConsoleHost_history.txt").write_text(
        "Get-ChildItem C:\\Projects\npowershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n",
        encoding="utf-8",
    )
    (staging / "PowerShell" / "Bob" / "ConsoleHost_history.txt").write_text(
        "ipconfig /all\n",
        encoding="utf-8",
    )

    # 3. RMM Logs (missing end_time_utc "" safety + valid start_time_utc)
    (staging / "RMM").mkdir(parents=True, exist_ok=True)
    (staging / "RMM" / "Connections_incoming.txt").write_text(
        "987654321\t2024-08-15 11:20:00\t\tAliceDesktop\tRemoteControl\n",
        encoding="utf-8",
    )
    (staging / "RMM" / "TeamViewer15_Logfile.log").write_text(
        "2024/08/15 11:22:10.500  Participant 987654321 connected from 198.51.100.42\n"
        "Line without timestamp participant closed session\n",
        encoding="utf-8",
    )
    (staging / "RMM" / "ad.trace").write_text(
        "2024-08-16 08:05:12.100 info 100 200 app.session - Incoming session accepted from 555666777 (203.0.113.9)\n",
        encoding="utf-8",
    )

    # 4. Windows Push Notifications (wpndatabase.db)
    (staging / "SQLite").mkdir(parents=True, exist_ok=True)
    wpn_db = staging / "SQLite" / "wpndatabase.db"
    wconn = sqlite3.connect(str(wpn_db))
    try:
        wconn.execute("CREATE TABLE NotificationHandler (RecordId INTEGER PRIMARY KEY, PrimaryId TEXT);")
        wconn.execute(
            """
            CREATE TABLE Notification (
                Id INTEGER PRIMARY KEY, HandlerId INTEGER, Type TEXT,
                ArrivalTime INTEGER, ExpiryTime INTEGER, Payload BLOB
            );
            """
        )
        wconn.execute("INSERT INTO NotificationHandler VALUES (1, 'Microsoft.Windows.SecHealthUI');")
        arr_ft = datetime_to_filetime(datetime(2024, 8, 18, 15, 40, 0, tzinfo=timezone.utc))
        exp_ft = datetime_to_filetime(datetime(2024, 8, 19, 15, 40, 0, tzinfo=timezone.utc))
        toast_xml = (
            '<toast launch="https://portal.corp.local/incidents/42">'
            '<visual><binding template="ToastGeneric">'
            "<text>Endpoint Threat Alert</text>"
            "<text>Quarantined suspicious script in Public folder</text>"
            "</binding></visual>"
            '<header id="sec" title="Defender ATP" arguments="open"/>'
            "</toast>"
        ).encode("utf-8")
        wconn.execute(
            "INSERT INTO Notification VALUES (101, 1, 'toast', ?, ?, ?);",
            (arr_ft, exp_ft, toast_xml),
        )
        wconn.commit()
    finally:
        wconn.close()

    parser = CorporateIRParser(case_id=case_id, staging_dir=staging)
    counts = parser.parse()

    assert recorded_cwds == [str(fake_rip_dir.resolve())]
    assert counts["parsed_scheduled_tasks"] == 5  # 3 from NightlyTriage + 1 HealthCheck + 1 TaskCache
    assert counts["parsed_powershell_history"] == 3  # Exact 3 commands (no 2x duplicate globbing!)
    assert counts["parsed_rmm_sessions"] == 4
    assert counts["parsed_wpn_notifications"] == 1

    conn = DuckDBManager.get_connection(case_id)

    # Verify Scheduled Tasks columns & multi-Exec completeness
    t_rows = conn.execute(
        """
        SELECT task_path, command, arguments, working_dir, date_created, is_suspicious, suspicious_indicators
        FROM parsed_scheduled_tasks
        ORDER BY command ASC;
        """
    ).fetchall()
    cmds = {r[1] for r in t_rows}
    assert r"C:\Tools\collector.exe" in cmds
    assert "powershell.exe" in cmds
    assert "COM:{01234567-89AB-CDEF-0123-456789ABCDEF}" in cmds
    assert r"C:\Windows\System32\sc.exe" in cmds
    assert r"C:\Windows\System32\rundll32.exe" in cmds

    ps_task = [r for r in t_rows if r[1] == "powershell.exe"][0]
    assert ps_task[0] == r"\CorpOps\NightlyTriage"
    assert ps_task[3] == r"C:\Users\Public"
    assert ps_task[4] is not None
    assert ps_task[5] is True
    assert ps_task[6]

    tc_task = [r for r in t_rows if r[1] == r"C:\Windows\System32\rundll32.exe"][0]
    assert tc_task[0] == r"\Updater\PersistenceCheck"
    assert "beacon.dll" in tc_task[2]
    assert tc_task[5] is True

    # Verify PowerShell deduplication, host-path isolation & -enc detection
    ps_rows = conn.execute(
        "SELECT username, command, is_suspicious, matched_pattern FROM parsed_powershell_history ORDER BY username, line_number;"
    ).fetchall()
    assert len(ps_rows) == 3
    assert {r[0] for r in ps_rows} == {"ALICE", "Bob"}
    enc_row = [r for r in ps_rows if "-enc" in r[1]][0]
    assert enc_row[0] == "ALICE"
    assert enc_row[2] is True
    assert enc_row[3] is not None and "enc" in enc_row[3].lower()
    benign_rows = [r for r in ps_rows if "-enc" not in r[1]]
    assert all(r[2] is False and r[3] is None for r in benign_rows)

    # Verify RMM TIMESTAMP safety
    rmm_rows = conn.execute(
        "SELECT rmm_product, remote_identifier, start_time_utc, end_time_utc FROM parsed_rmm_sessions;"
    ).fetchall()
    assert len(rmm_rows) == 4
    assert sum(1 for r in rmm_rows if r[2] is not None) == 3
    assert all(r[3] is None for r in rmm_rows)

    # Verify WPN toast XML columns
    wpn_row = conn.execute(
        "SELECT app_id, timestamp_utc, title, body, header, action_url FROM parsed_wpn_notifications;"
    ).fetchone()
    assert wpn_row is not None
    assert wpn_row[0] == "Microsoft.Windows.SecHealthUI"
    assert wpn_row[1] is not None
    assert wpn_row[2] == "Endpoint Threat Alert"
    assert wpn_row[3] == "Quarantined suspicious script in Public folder"
    assert wpn_row[4] == "Defender ATP"
    assert wpn_row[5] == "https://portal.corp.local/incidents/42"


def test_m2c_owned_parsers_zero_hardcoded_dataset_cheats() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    owned_files = [
        repo_root / "backend" / "parsers" / "data_carver.py",
        repo_root / "backend" / "parsers" / "usb_correlator.py",
        repo_root / "backend" / "parsers" / "corporate_ir_parser.py",
    ]
    forbidden_tokens = (
        "4c53",
        " ".join(("lexar", "jumpdrive")),
        "informant",
        "".join(("imz", "adi")),
        "photorec_win",
    )
    for fp in owned_files:
        assert fp.is_file(), f"Expected parser file missing: {fp}"
        low_src = fp.read_text(encoding="utf-8").lower()
        for tok in forbidden_tokens:
            assert tok not in low_src, f"Forbidden hardcoded token {tok!r} found in {fp.name}!"


# =============================================================================
# 5. Wave 2 Regression Tests: Cross-Chunk PE, Raw-Stream Staging Skip, 8 Hostile
#    Decoys + Orphan PDF Tail, Windows Handle Release + Locked/Open DuckDB,
#    USBSTOR PnP 0066 Preservation, and Severity-Prefixed AnyDesk / VFS RMM Paths
# =============================================================================
def test_data_carver_cross_chunk_pe_and_raw_stream_staging_dedup(
    isolated_case: Dict[str, Any], tmp_path: Path
) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]
    staging_dir = isolated_case["staging_dir"]

    # Stage an allocated PNG inside staging/Enrichment/Part0 that MUST be skipped on raw_stream carving
    alloc_dir = staging_dir / "Enrichment" / "Part0"
    alloc_dir.mkdir(parents=True, exist_ok=True)
    png_io = io.BytesIO()
    Image.new("RGB", (24, 24), color=(12, 99, 201)).save(png_io, format="PNG")
    allocated_png = png_io.getvalue()
    (alloc_dir / "already_allocated.png").write_bytes(allocated_png)

    # Unstaged GIF + EXE starting at CHUNK_SIZE - 7 + DLL starting at 2*CHUNK_SIZE - 7
    gif_io = io.BytesIO()
    Image.new("P", (14, 14), color=7).save(gif_io, format="GIF")
    unstaged_gif = gif_io.getvalue()
    exe_blob = _build_minimal_pe64(is_dll=False)
    dll_blob = _build_minimal_pe64(is_dll=True)

    stream = bytearray(b"\x55" * (2 * CHUNK_SIZE + 65536))
    stream[0x4000 : 0x4000 + len(allocated_png)] = allocated_png
    stream[0x10000 : 0x10000 + len(unstaged_gif)] = unstaged_gif

    exe_off = CHUNK_SIZE - 7
    dll_off = (2 * CHUNK_SIZE) - 7
    stream[exe_off : exe_off + len(exe_blob)] = exe_blob
    stream[dll_off : dll_off + len(dll_blob)] = dll_blob

    raw_img = tmp_path / "cross_chunk_pe_and_staging.dd"
    raw_img.write_bytes(bytes(stream))

    carver = DataCarver(case_id=case_id, case_dir=case_dir)
    res = carver.run(raw_img, staging_dir=staging_dir, max_workers=8)

    assert res["status"] == "SUCCESS"
    assert res["source_regions"] == ["raw_stream"]
    assert res["by_type"] == {"gif": 1, "exe": 1, "dll": 1}
    assert res["carved_count"] == 3

    conn = DuckDBManager.get_connection(case_id)
    rows = {
        int(r[1]): (r[0], int(r[2]), r[3])
        for r in conn.execute(
            "SELECT file_type, offset_bytes, size_bytes, sha256 FROM parsed_carved_files;"
        ).fetchall()
    }
    assert exe_off in rows and rows[exe_off] == ("exe", len(exe_blob), hashlib.sha256(exe_blob).hexdigest())
    assert dll_off in rows and rows[dll_off] == ("dll", len(dll_blob), hashlib.sha256(dll_blob).hexdigest())
    assert 0x10000 in rows and rows[0x10000] == ("gif", len(unstaged_gif), hashlib.sha256(unstaged_gif).hexdigest())
    assert 0x4000 not in rows, "Already-staged allocated PNG must be skipped on raw_stream carving!"


def _build_corrupt_crc_15_entry_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
        )
        for idx in range(1, 14):
            zf.writestr(f"customXml/item{idx}.xml", f"<meta id='{idx}'>payload-{idx}</meta>")
        # Entry #15: word/document.xml
        zi15 = zipfile.ZipInfo("word/document.xml")
        zi15.compress_type = zipfile.ZIP_STORED
        zf.writestr(
            zi15,
            "<w:document><w:body><w:p>" + ("CorruptEntry15Test " * 20) + "</w:p></w:body></w:document>",
        )
        lh_start = zf.getinfo("word/document.xml").header_offset
    raw = bytearray(buf.getvalue())
    # Locate Entry #15 local file header and flip 1 payload byte so CRC32 fails on Entry #15 only
    fname_len, extra_len = struct.unpack_from("<HH", raw, lh_start + 26)
    data_start = lh_start + 30 + fname_len + extra_len
    raw[data_start + 4] ^= 0xFF
    with zipfile.ZipFile(io.BytesIO(bytes(raw)), "r") as check_zf:
        assert check_zf.testzip() == "word/document.xml"
    return bytes(raw)


def _build_png_with_valid_crc_over_corrupt_idat() -> bytes:
    png_io = io.BytesIO()
    Image.new("RGB", (32, 32), color=(80, 140, 200)).save(png_io, format="PNG")
    orig = png_io.getvalue()
    out = bytearray(orig[:8])
    pos = 8
    corrupted = False
    while pos + 12 <= len(orig):
        clen = struct.unpack_from(">I", orig, pos)[0]
        ctype = orig[pos + 4 : pos + 8]
        cdata = bytearray(orig[pos + 8 : pos + 8 + clen])
        if ctype == b"IDAT" and clen >= 6 and not corrupted:
            cdata[0] = 0x78
            cdata[1] = 0x00  # Invalid zlib FCHECK header with recomputed valid PNG chunk CRC!
            cdata[2] ^= 0xFF
            corrupted = True
        new_crc = zlib.crc32(ctype + bytes(cdata)) & 0xFFFFFFFF
        out.extend(struct.pack(">I", clen) + ctype + bytes(cdata) + struct.pack(">I", new_crc))
        pos += 12 + clen
    assert corrupted
    return bytes(out)


def _build_premature_eoi_corrupt_huffman_jpeg() -> bytes:
    jpg_io = io.BytesIO()
    img = Image.new("RGB", (64, 48))
    for y in range(48):
        for x in range(64):
            img.putpixel((x, y), ((x * 37 + y * 13) & 255, (x * 11) & 255, (y * 29) & 255))
    img.save(jpg_io, format="JPEG", quality=92)
    valid_jpg = jpg_io.getvalue()
    sos_idx = valid_jpg.find(b"\xff\xda")
    assert sos_idx > 0
    sos_len = struct.unpack_from(">H", valid_jpg, sos_idx + 2)[0]
    scan_start = sos_idx + 2 + sos_len
    # Truncate scan to 8 entropy bytes followed prematurely by EOI (FF D9) -> libjpeg JWRN_PREMATURE_EOF (defects > 0)
    return valid_jpg[: scan_start + 8] + b"\xff\xd9"


def test_data_carver_all_8_hostile_decoys_and_valid_pdf_before_orphan_tail(
    isolated_case: Dict[str, Any], tmp_path: Path
) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]

    # Decoy 1a & 1b: PDF with non-numeric startxref AND numeric startxref ("xref" inside "startxref") lacking /Root
    decoy_pdf_non_num = (
        b"%PDF-1.7\n1 0 obj\n<< /Producer (CorruptFragment) /Length 12 >>\nendobj\n"
        b"startxref\nGARBAGE_NOT_OFFSET\n%%EOF\n"
    )
    decoy_pdf_tautology = (
        b"%PDF-1.7\n1 0 obj\n<< /Producer (BareStartxrefOnly) /Length 12 >>\nendobj\n"
        b"startxref\n10\n%%EOF\n"
    )

    # Decoy 2: 15-entry DOCX with corrupt CRC in entry #15
    decoy_docx_15 = _build_corrupt_crc_15_entry_docx()

    # Decoy 3: regf with bad 0x1FC base-block XOR checksum
    reg_spec = RegNodeSpec()
    reg_spec.ensure_path("Software\\Test").add_sz("Key", "Val")
    valid_regf = build_synthetic_regf(reg_spec, bins_size=0x1000)
    decoy_regf_bad_csum = bytearray(valid_regf)
    decoy_regf_bad_csum[0x1FC] ^= 0x01

    # Decoy 4: regf with valid 0x1FC checksum but mismatched bins_size = 0x2000 and garbage at +0x2000
    decoy_regf_bad_hbins = bytearray(valid_regf + (b"\xef\xbe\xad\xde" * 1024))
    struct.pack_into("<I", decoy_regf_bad_hbins, 40, 0x2000)
    recalc_csum = 0
    for off in range(0, 0x1FC, 4):
        recalc_csum ^= struct.unpack_from("<I", decoy_regf_bad_hbins, off)[0]
    struct.pack_into("<I", decoy_regf_bad_hbins, 0x1FC, recalc_csum)

    # Decoy 5: PE with invalid alignment (sa=7, fa=3), SizeOfImage < SizeOfHeaders, PointerToRawData=0x50 inside headers
    decoy_pe = bytearray(_build_minimal_pe64(is_dll=False))
    e_lfanew = struct.unpack_from("<I", decoy_pe, 0x3C)[0]
    opt_off = e_lfanew + 24
    struct.pack_into("<II", decoy_pe, opt_off + 32, 7, 3)  # SectionAlignment=7, FileAlignment=3
    struct.pack_into("<II", decoy_pe, opt_off + 56, 0x100, 0x200)  # SizeOfImage=0x100 < SizeOfHeaders=0x200
    sec_off = opt_off + 0xF0
    struct.pack_into("<I", decoy_pe, sec_off + 12, 0xDEAD0000)  # VirtualAddress
    struct.pack_into("<I", decoy_pe, sec_off + 20, 0x50)        # PointerToRawData overlapping headers

    # Decoy 6: PNG with valid chunk CRCs over corrupt IDAT zlib stream
    decoy_png = _build_png_with_valid_crc_over_corrupt_idat()

    # Decoy 7: JPEG with premature EOI / corrupt Huffman scan (im2.defects > 0)
    decoy_jpg_premature = _build_premature_eoi_corrupt_huffman_jpeg()

    # Decoy 8: Truncated outer JPEG (missing outer FFD9) containing valid embedded EXIF APP1 thumbnail
    outer_exif_jpg = _build_jpeg_with_exif_thumbnail()
    decoy_jpg_trunc_exif = outer_exif_jpg[:-24]
    assert not decoy_jpg_trunc_exif.endswith(b"\xff\xd9")

    # Valid 1-page PDF followed 4 KB later by an orphan headless startxref...%%EOF tail
    valid_pdf = _build_valid_pdf_1page("Clean PDF Before Orphan Tail")
    orphan_pdf_tail = (
        b"99 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"xref\n0 1\n0000000000 65535 f \n"
        b"trailer\n<< /Size 100 /Root 99 0 R >>\n"
        b"startxref\n4096\n%%EOF\n"
    )

    stream = bytearray(b"\x55" * (2 * 1024 * 1024))
    cursor = 0x2000
    for decoy in (
        decoy_pdf_non_num,
        decoy_pdf_tautology,
        decoy_docx_15,
        bytes(decoy_regf_bad_csum),
        bytes(decoy_regf_bad_hbins),
        bytes(decoy_pe),
        decoy_png,
        decoy_jpg_premature,
        decoy_jpg_trunc_exif,
    ):
        stream[cursor : cursor + len(decoy)] = decoy
        cursor = ((cursor + len(decoy) + 0x4000) & ~0xFFF)

    valid_pdf_off = cursor
    stream[valid_pdf_off : valid_pdf_off + len(valid_pdf)] = valid_pdf
    orphan_off = valid_pdf_off + len(valid_pdf) + 4096
    stream[orphan_off : orphan_off + len(orphan_pdf_tail)] = orphan_pdf_tail

    hostile_img = tmp_path / "hostile_decoys.dd"
    hostile_img.write_bytes(bytes(stream))

    carver = DataCarver(case_id=case_id, case_dir=case_dir)
    res = carver.run(hostile_img, max_workers=8)

    assert res["status"] == "SUCCESS"
    assert res["carved_count"] == 1, f"Expected ONLY the 1 valid PDF (0 decoys), got: {res}"
    assert res["by_type"] == {"pdf": 1}

    conn = DuckDBManager.get_connection(case_id)
    row = conn.execute(
        "SELECT file_type, offset_bytes, size_bytes, sha256, carved_rel_path FROM parsed_carved_files;"
    ).fetchone()
    assert row is not None
    assert row[0] == "pdf"
    assert int(row[1]) == valid_pdf_off
    assert int(row[2]) == len(valid_pdf), "Valid PDF must NOT swallow 4 KB garbage before orphan %%EOF tail!"
    assert row[3] == hashlib.sha256(valid_pdf).hexdigest()
    assert (case_dir / row[4]).read_bytes() == valid_pdf


def test_data_carver_windows_handle_release_gc_disabled_and_case_dir_open_duckdb(
    isolated_case: Dict[str, Any], tmp_path: Path
) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]

    png_io = io.BytesIO()
    Image.new("RGB", (18, 18), color=(200, 80, 40)).save(png_io, format="PNG")
    png_blob = png_io.getvalue()

    # 1. Immediate source_path unlink on Windows with gc.disable() right after DataCarver.run()
    raw_img = tmp_path / "handle_release_check.dd"
    raw_buf = bytearray(b"\x00" * 131072)
    raw_buf[4096 : 4096 + len(png_blob)] = png_blob
    raw_img.write_bytes(bytes(raw_buf))

    carver = DataCarver(case_id=case_id, case_dir=case_dir)
    was_gc = gc.isenabled()
    gc.disable()
    try:
        res1 = carver.run(raw_img, max_workers=4)
        assert res1["status"] == "SUCCESS"
        assert res1["carved_count"] == 1
        os.unlink(raw_img)
        assert not raw_img.exists()
    finally:
        if was_gc:
            gc.enable()

    # 2. Directory mode on case_dir while case.duckdb is open AND an exclusively locked file exists inside case_dir
    open_conn = DuckDBManager.get_connection(case_id)
    assert open_conn is not None
    assert (case_dir / "case.duckdb").is_file()

    evidence_bin = case_dir / "sample_evidence_blob.bin"
    evidence_bin.write_bytes(b"\x55" * 1024 + png_blob + b"\x55" * 1024)

    locked_path = case_dir / "exclusively_locked.bin"
    locked_path.write_bytes(b"LOCKED_CONTENT" * 64)
    win_lock_handle = None
    if os.name == "nt":
        import _winapi

        win_lock_handle = _winapi.CreateFile(
            str(locked_path),
            _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
            0,  # dwShareMode = 0 (exclusive lock -> open() raises PermissionError!)
            0,
            _winapi.OPEN_EXISTING,
            0x80,  # FILE_ATTRIBUTE_NORMAL
            0,
        )
    try:
        res2 = carver.run(case_dir, max_workers=4)
        assert res2["status"] == "SUCCESS"
        assert res2["carved_count"] == 1
        assert res2["by_type"] == {"png": 1}
    finally:
        if win_lock_handle is not None:
            import _winapi

            _winapi.CloseHandle(win_lock_handle)


def test_usb_correlator_authoritative_pnp_0066_not_clobbered_by_later_nk_last_modified(
    isolated_case: Dict[str, Any]
) -> None:
    case_id = isolated_case["case_id"]
    staging = isolated_case["staging_dir"]
    (staging / "Registry" / "System").mkdir(parents=True, exist_ok=True)

    pnp_first_dt = datetime(2024, 9, 10, 6, 30, 0, tzinfo=timezone.utc)
    pnp_last_dt = datetime(2024, 9, 18, 14, 15, 0, tzinfo=timezone.utc)
    later_os_servicing_nk_dt = datetime(2024, 12, 25, 18, 0, 0, tzinfo=timezone.utc)

    sys_spec = RegNodeSpec()
    sys_spec.ensure_path("Select").add_dword("Current", 1)
    inst = sys_spec.ensure_path(
        "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\\AA9988776655&0",
        last_modified_dt=later_os_servicing_nk_dt,
    )
    inst.add_sz("FriendlyName", "SanDisk Extreme USB 3.2")
    inst.add_sz("ContainerID", "{22222222-bbbb-cccc-dddd-000000000002}")

    p0064 = sys_spec.ensure_path(
        "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\\AA9988776655&0\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064"
    )
    p0064.add_devprop_filetime("", pnp_first_dt)
    p0066 = sys_spec.ensure_path(
        "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\\AA9988776655&0\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066"
    )
    p0066.add_devprop_filetime("", pnp_last_dt)

    # Also touch Enum\USB key with later NK timestamp (without 0066) to verify neither USBSTOR nor Enum\USB NK clobbers 0066
    usb_inst = sys_spec.ensure_path(
        "ControlSet001\\Enum\\USB\\VID_0781&PID_5588\\AA9988776655",
        last_modified_dt=later_os_servicing_nk_dt,
    )
    usb_inst.add_sz("ContainerID", "{22222222-bbbb-cccc-dddd-000000000002}")

    (staging / "Registry" / "System" / "SYSTEM").write_bytes(build_synthetic_regf(sys_spec, bins_size=0x4000))

    correlator = USBDeviceCorrelator(case_id=case_id, staging_dir=staging)
    res = correlator.parse()
    assert res["parsed_usb_devices"] == 1

    conn = DuckDBManager.get_connection(case_id)
    row = conn.execute(
        "SELECT first_connected_utc, last_connected_utc FROM parsed_usb_devices WHERE serial_number = 'AA9988776655';"
    ).fetchone()
    assert row is not None
    assert row[0].replace(tzinfo=None) == datetime(2024, 9, 10, 6, 30, 0)
    assert row[1].replace(tzinfo=None) == datetime(2024, 9, 18, 14, 15, 0)


def test_corporate_ir_rmm_severity_prefixed_anydesk_and_vfs_hierarchy_without_flat_rmm_dir(
    isolated_case: Dict[str, Any]
) -> None:
    case_id = isolated_case["case_id"]
    staging = isolated_case["staging_dir"]

    # Ensure flat staging/RMM does NOT exist!
    assert not (staging / "RMM").exists()

    ad_dir = staging / "ProgramData" / "AnyDesk"
    ad_dir.mkdir(parents=True, exist_ok=True)
    (ad_dir / "ad_svc.trace").write_text(
        "info 2024-08-21 09:15:00.123 lsvc 1420 2048 12 main - Incoming session request: Operator (987654321) from 198.51.100.42\n",
        encoding="utf-8",
    )

    rd_dir = staging / "Users" / "Victor" / "AppData" / "Roaming" / "RustDesk" / "config"
    rd_dir.mkdir(parents=True, exist_ok=True)
    (rd_dir / "peers.json").write_text(
        json.dumps([{"id": "112233445", "alias": "VictorRemote", "platform": "Windows"}]),
        encoding="utf-8",
    )

    tv_dir = staging / "Program Files (x86)" / "TeamViewer"
    tv_dir.mkdir(parents=True, exist_ok=True)
    (tv_dir / "Connections_incoming.txt").write_text(
        "445566778\t2024-08-22 14:00:00\t2024-08-22 14:25:00\tVictorWS\tRemoteControl\n",
        encoding="utf-8",
    )

    parser = CorporateIRParser(case_id=case_id, staging_dir=staging)
    count = parser.parse_rmm_logs()
    assert count == 3

    conn = DuckDBManager.get_connection(case_id)
    rows = {
        r[0]: r
        for r in conn.execute(
            "SELECT rmm_product, remote_identifier, start_time_utc, end_time_utc, remote_ip FROM parsed_rmm_sessions;"
        ).fetchall()
    }
    assert set(rows.keys()) == {"AnyDesk", "RustDesk", "TeamViewer"}

    ad_row = rows["AnyDesk"]
    assert ad_row[1] == "987654321"
    assert ad_row[2] is not None
    assert ad_row[2].replace(tzinfo=None) == datetime(2024, 8, 21, 9, 15, 0, 123000)
    assert ad_row[4] == "198.51.100.42"

    rd_row = rows["RustDesk"]
    assert rd_row[1] == "112233445"
    assert rd_row[2] is None

    tv_row = rows["TeamViewer"]
    assert tv_row[1] == "445566778"
    assert tv_row[2].replace(tzinfo=None) == datetime(2024, 8, 22, 14, 0, 0)
    assert tv_row[3].replace(tzinfo=None) == datetime(2024, 8, 22, 14, 25, 0)

