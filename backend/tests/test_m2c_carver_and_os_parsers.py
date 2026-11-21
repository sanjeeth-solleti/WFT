"""
Milestone M2-C Verification Suite (Worker B Owned):
  1. All 8 Magnet AXIOM Registry & OS Tables (`parsed_user_accounts`, `parsed_windows_services`,
     `parsed_autoruns`, `parsed_userassist`, `parsed_bam_dam`, `parsed_registry_mru`,
     `parsed_network_profiles`, `parsed_wer_reports`) with exact contract column names,
     synthetic `regf` binary hives (`SAM`, `SYSTEM`, `SOFTWARE`, multi-user `NTUSER.DAT` & `UsrClass.dat`,
     `clean_hives` deduplication, `VSS_1` provenance), `regipy` + `dissect.regf` fallback, WLAN XML, and `Report.wer`.
  2. `NativeFallbackParser` pure-Python fallbacks: Win10/11 `MAM\\x04` LZXPRESS-Huffman & `SCCA` Prefetch,
     uncapped `MFT` & `$MFT` with NTFS USA sector fixups & `$SI < $FN` timestomp detection,
     uncapped `.evtx` with real Level 1–5 + Audit Keywords decoding, `EseDB` `WebCacheV01.dat` & `SRUDB.dat`,
     `vfs_files` original timestamp preservation (zero `now()` fabrication), and non-destructive `existing > 0` guards.
  3. `backend/parsers/__init__.py` concurrent-safe exports + AST/source anti-cheat audit.
"""
from __future__ import annotations

import ast
import codecs
import gc
import io
import os
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from backend.config import register_case_dir
from backend.db.engine import DuckDBManager, init_case_db
import backend.parsers as parsers_pkg
import backend.parsers.native_fallback_parsers as nfp
from backend.parsers import BaseParser, NativeFallbackParser, windows_filetime_to_datetime


# =============================================================================
# Isolated Case Fixture & Genuine Binary Artifact Builders
# =============================================================================
@pytest.fixture()
def isolated_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    appdata = tmp_path / "appdata"
    appdata.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(appdata / "custom_locations.json"))

    case_id = f"test_m2c_{tmp_path.name}"
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
        if hasattr(DuckDBManager, "close_case"):
            DuckDBManager.close_case(case_id)
        elif hasattr(DuckDBManager, "close_connection"):
            DuckDBManager.close_connection(case_id)
        DuckDBManager.close_all()


def dt_to_filetime(dt: datetime) -> int:
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((utc_dt - epoch).total_seconds() * 10_000_000)


def dt_to_systemtime_bytes(dt: datetime) -> bytes:
    # SYSTEMTIME: wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds
    dow = (dt.weekday() + 1) % 7
    return struct.pack(
        "<8H",
        dt.year,
        dt.month,
        dow,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second,
        dt.microsecond // 1000,
    )


class RegNodeSpec:
    """Tree node for building genuine Windows `regf` binary Registry hives."""

    def __init__(self, last_modified_dt: Optional[datetime] = None) -> None:
        self.subkeys: Dict[str, "RegNodeSpec"] = {}
        self.values: List[Tuple[str, int, bytes]] = []
        self.last_modified_ft: int = dt_to_filetime(
            last_modified_dt or datetime(2024, 7, 10, 14, 30, 0, tzinfo=timezone.utc)
        )

    def ensure_path(self, rel_path: str, last_modified_dt: Optional[datetime] = None) -> "RegNodeSpec":
        cur = self
        for part in rel_path.strip("\\/").split("\\"):
            if not part:
                continue
            if part not in cur.subkeys:
                cur.subkeys[part] = RegNodeSpec(last_modified_dt=last_modified_dt)
            elif last_modified_dt is not None:
                cur.subkeys[part].last_modified_ft = dt_to_filetime(last_modified_dt)
            cur = cur.subkeys[part]
        return cur

    def add_sz(self, name: str, val: str, expand: bool = False) -> None:
        self.values.append((name, 2 if expand else 1, val.encode("utf-16le") + b"\x00\x00"))

    def add_dword(self, name: str, val: int) -> None:
        self.values.append((name, 4, struct.pack("<I", val & 0xFFFFFFFF)))

    def add_binary(self, name: str, raw: bytes, data_type: int = 3) -> None:
        self.values.append((name, data_type, bytes(raw)))


def build_synthetic_regf(root_spec: RegNodeSpec, bins_size: int = 0x8000) -> bytes:
    """
    Builds a standards-compliant `regf` binary hive (root `nk` at `hbin` offset `0x20`,
    sorted `'lf'` fast-leaf subkey lists, XOR-32 base block checksum) readable by both
    `regipy.registry.RegistryHive` and `dissect.regf.RegistryHive`.
    """
    hbin = bytearray(bins_size)
    default_ft = root_spec.last_modified_ft
    struct.pack_into("<4sIIIIQI", hbin, 0, b"hbin", 0, bins_size, 0, 0, default_ft, 0)
    cur_off = 0x20

    def reserve_cell(payload_len: int) -> Tuple[int, int]:
        nonlocal cur_off
        total = max(8, (4 + payload_len + 7) & ~7)
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
        nk_off, _ = reserve_cell(nk_len)

        val_offsets: List[int] = []
        max_vname = 0
        max_vdata = 0
        for v_name, v_type, v_bytes in spec.values:
            data_off = alloc_cell(v_bytes) if len(v_bytes) > 0 else 0xFFFFFFFF
            if v_name == "" or v_name.lower() == "(default)":
                vn_b = b""
                v_flags = 0
            else:
                vn_b = v_name.encode("ascii", errors="replace")
                v_flags = 0x0001
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

        vlist_off = (
            alloc_cell(b"".join(struct.pack("<I", vo) for vo in val_offsets))
            if val_offsets
            else 0xFFFFFFFF
        )

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
                0,
                parent_off & 0xFFFFFFFF,
                len(child_entries),
                0,
                subkeys_list_off,
                0xFFFFFFFF,
                len(val_offsets),
                vlist_off,
                0xFFFFFFFF,
                0xFFFFFFFF,
                max_sk_name,
                0,
                max_vname,
                max_vdata,
                0,
                len(name_b),
                0,
            )
            + name_b
        )
        hbin[nk_off + 4 : nk_off + 4 + len(nk_body)] = nk_body
        return nk_off

    root_off = emit_nk("CMI-CreateHive", root_spec, 0xFFFFFFFF, is_root=True)
    assert root_off == 0x20
    rem = bins_size - cur_off
    if rem >= 4:
        struct.pack_into("<i", hbin, cur_off, rem)

    base = bytearray(4096)
    struct.pack_into("<4sIIQIIIIII", base, 0, b"regf", 1, 1, default_ft, 1, 5, 0, 1, root_off, bins_size)
    struct.pack_into("<I", base, 44, 1)
    csum = 0
    for off in range(0, 0x1FC, 4):
        csum ^= struct.unpack_from("<I", base, off)[0]
    struct.pack_into("<I", base, 0x1FC, csum)
    return bytes(base) + bytes(hbin)


def build_sam_f_and_v(
    rid: int,
    username: str,
    full_name: str,
    comment: str,
    acb_flags: int,
    logon_count: int,
    failed_count: int,
    last_logon: datetime,
    pwd_last_set: datetime,
    last_failed: Optional[datetime] = None,
) -> Tuple[bytes, bytes]:
    f_buf = bytearray(0x50)
    struct.pack_into("<Q", f_buf, 0x08, dt_to_filetime(last_logon))
    struct.pack_into("<Q", f_buf, 0x18, dt_to_filetime(pwd_last_set))
    struct.pack_into("<Q", f_buf, 0x28, dt_to_filetime(last_failed) if last_failed else 0)
    struct.pack_into("<I", f_buf, 0x30, rid)
    struct.pack_into("<H", f_buf, 0x38, acb_flags)
    struct.pack_into("<H", f_buf, 0x40, failed_count)
    struct.pack_into("<H", f_buf, 0x42, logon_count)

    v_hdr = bytearray(0xCC)
    v_data = bytearray()
    for desc_off, text in ((0x0C, username), (0x18, full_name), (0x24, comment)):
        enc = text.encode("utf-16le")
        struct.pack_into("<III", v_hdr, desc_off, len(v_data), len(enc), 1)
        v_data.extend(enc)
    return bytes(f_buf), bytes(v_hdr + v_data)


def build_pidl_with_beef0004(segments: List[str]) -> bytes:
    out = bytearray()
    for seg in segments:
        if len(seg) == 2 and seg[1] == ":":
            drv = (seg + "\\").encode("ascii")
            body = bytes([0x2F]) + drv.ljust(20, b"\x00")
            cb = 2 + len(body)
            out.extend(struct.pack("<H", cb) + body)
        else:
            u16 = seg.encode("utf-16le") + b"\x00\x00"
            # Extension block version 3 (`str_off = beef_idx + 16`)
            ext_hdr = struct.pack("<HH", 4 + 4 + 12 + len(u16), 3) + b"\x04\x00\xef\xbe" + (b"\x00" * 12) + u16
            body = b"\x32\x00" + (b"\x00" * 12) + b"SHORT\x00" + ext_hdr
            cb = 2 + len(body)
            out.extend(struct.pack("<H", cb) + body)
    out.extend(b"\x00\x00")
    return bytes(out)


def encode_mam_lzxpress_huffman(raw_scca: bytes, include_crc: bool = True) -> bytes:
    """Genuine canonical 8-bit identity LZXPRESS-Huffman compressor for `MAM\\x04` / `MAM\\x84`."""
    tbl = b"\x88" * 128 + b"\x00" * 128
    padded = raw_scca + (b"\x00" if (len(raw_scca) % 2 == 1) else b"")
    words = b"".join(
        struct.pack("<H", (padded[i] << 8) | padded[i + 1]) for i in range(0, len(padded), 2)
    ) + b"\x00\x00\x00\x00"
    if include_crc:
        crc = zlib.crc32(raw_scca) & 0xFFFFFFFF
        return b"MAM\x84" + struct.pack("<II", len(raw_scca), crc) + tbl + words
    return b"MAM\x04" + struct.pack("<I", len(raw_scca)) + tbl + words


def build_scca_prefetch(
    exe_name: str,
    pf_hash: int,
    version: int,
    run_count: int,
    last_runs: List[datetime],
    metrics_off: int = 0xE8,
    vol_name: str = r"\VOLUME{01d9a5b2c3d4e5f6-deadbeef}",
    vol_serial: int = 0xCAFEBABE,
    vol_created: Optional[datetime] = None,
    loaded_files: Optional[List[str]] = None,
) -> bytes:
    buf = bytearray(0x400)
    struct.pack_into("<I4sII", buf, 0, version, b"SCCA", 0x11, len(buf))
    enc_exe = exe_name.encode("utf-16le")[:58]
    buf[16 : 16 + len(enc_exe)] = enc_exe
    struct.pack_into("<I", buf, 76, pf_hash)
    struct.pack_into("<I", buf, 0x54, metrics_off)

    fn_blob = ("\x00".join(loaded_files or [r"\WINDOWS\SYSTEM32\NTDLL.DLL"]) + "\x00").encode("utf-16le")
    fn_off = 0x180
    buf[fn_off : fn_off + len(fn_blob)] = fn_blob
    struct.pack_into("<II", buf, 0x64, fn_off, len(fn_blob))

    vol_off = 0x260
    vp_bytes = vol_name.encode("utf-16le")
    vp_rel = 0x40
    struct.pack_into("<III", buf, 0x6C, vol_off, 1, 0x40 + len(vp_bytes))
    v_ft = dt_to_filetime(vol_created or datetime(2023, 1, 15, 8, 0, 0, tzinfo=timezone.utc))
    struct.pack_into("<IIQI", buf, vol_off, vp_rel, len(vol_name), v_ft, vol_serial)
    buf[vol_off + vp_rel : vol_off + vp_rel + len(vp_bytes)] = vp_bytes

    if version == 23:
        struct.pack_into("<Q", buf, 0x80, dt_to_filetime(last_runs[0]))
        struct.pack_into("<I", buf, 0x98, run_count)
    else:
        for idx, dt in enumerate(last_runs[:8]):
            struct.pack_into("<Q", buf, 0x80 + idx * 8, dt_to_filetime(dt))
        rc_off = 0xC8 if (version >= 30 and metrics_off == 0xE8) else 0xD0
        struct.pack_into("<I", buf, rc_off, run_count)
    return bytes(buf)


def build_mft_record(
    entry_num: int,
    file_name: str,
    parent_entry: int,
    si_created: datetime,
    fn_created: datetime,
    file_size: int = 4096,
    is_dir: bool = False,
    cross_sector_boundary: bool = False,
) -> bytes:
    rec = bytearray(1024)
    usa_off = 48
    usa_cnt = 3  # USN + 2 sector fixup words (offsets 510..512 and 1022..1024)
    flags = (0x0003 if is_dir else 0x0001)
    attr_off = 56
    struct.pack_into("<4sHHQHHHHIIQHHI", rec, 0, b"FILE", usa_off, usa_cnt, 0, 1, 1, attr_off, flags, 512, 1024, 0, 4, 0, entry_num)

    pos = attr_off
    if cross_sector_boundary:
        # Add dummy custom attribute 0x20 padding so $FILE_NAME (0x30) straddles sector boundary 510..512!
        pad_attr_len = 512 - pos - 40
        struct.pack_into("<IIBBHHHIIBB", rec, pos, 0x10, pad_attr_len, 0, 0, 0, 0, 1, 72, 24, 0, 0)
        vpos = pos + 24
        ft_si = dt_to_filetime(si_created)
        struct.pack_into("<QQQQ", rec, vpos, ft_si, ft_si, ft_si, ft_si)
        pos += pad_attr_len
    else:
        si_len = 96
        struct.pack_into("<IIBBHHHIIBB", rec, pos, 0x10, si_len, 0, 0, 0, 0, 1, 72, 24, 0, 0)
        ft_si = dt_to_filetime(si_created)
        struct.pack_into("<QQQQ", rec, pos + 24, ft_si, ft_si, ft_si, ft_si)
        pos += si_len

    # $FILE_NAME (0x30)
    fn_u16 = file_name.encode("utf-16le")
    fn_val_len = 66 + len(fn_u16)
    fn_attr_len = (24 + fn_val_len + 7) & ~7
    struct.pack_into("<IIBBHHHIIBB", rec, pos, 0x30, fn_attr_len, 0, 0, 0, 0, 2, fn_val_len, 24, 0, 0)
    vpos = pos + 24
    p_ref = (1 << 48) | (parent_entry & 0xFFFFFFFFFFFF)
    ft_fn = dt_to_filetime(fn_created)
    struct.pack_into("<QQQQQQQIIBB", rec, vpos, p_ref, ft_fn, ft_fn, ft_fn, ft_fn, file_size, file_size, 0, 0, len(file_name), 1)
    rec[vpos + 66 : vpos + 66 + len(fn_u16)] = fn_u16
    pos += fn_attr_len

    # Non-resident $DATA (0x80) for files to verify $DATA real size precedence
    if not is_dir:
        data_attr_len = 64
        struct.pack_into("<IIBBHHH", rec, pos, 0x80, data_attr_len, 1, 0, 0, 0, 3)
        struct.pack_into("<QQHHIIIQQQ", rec, pos + 16, 0, 1, 64, 0, 0, file_size, file_size, file_size, file_size, 0)
        pos += data_attr_len

    struct.pack_into("<I", rec, pos, 0xFFFFFFFF)

    # Apply genuine NTFS USA fixup: store original bytes at 510..512 and 1022..1024 into USA array, overwrite with USN 0xABCD
    usn = b"\xcd\xab"
    orig_sec1 = bytes(rec[510:512])
    orig_sec2 = bytes(rec[1022:1024])
    rec[usa_off : usa_off + 2] = usn
    rec[usa_off + 2 : usa_off + 4] = orig_sec1
    rec[usa_off + 4 : usa_off + 6] = orig_sec2
    rec[510:512] = usn
    rec[1022:1024] = usn
    return bytes(rec)


def _evtx_name_hash(s: str) -> int:
    h = 0
    for ch in s:
        h = ((h * 65599) + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


def build_synthetic_evtx(events: List[Dict[str, Any]]) -> bytes:
    """
    Builds a genuine MS-EVEN6 `ElfFile\\x00` + `ElfChnk\\x00` binary EVTX file with resident
    `TemplateInstance` (`0x0C`) + `TemplateDefinition` + trailing `\\x00` End-of-Stream tokens,
    readable by BOTH `dissect.eventlog.evtx.Evtx` and `Evtx.Evtx` (`python-evtx`).
    """
    chunk = bytearray(65536)
    rec_off = 512
    last_rec_start = 512
    for idx_ev, ev in enumerate(events, start=1):
        last_rec_start = rec_off
        tb = bytearray()
        base_off = rec_off + 24

        def emit_inline_name(name: str) -> None:
            name_off = base_off + len(tb) + 4
            u16 = name.encode("utf-16le")
            tb.extend(struct.pack("<IIHH", name_off, 0, _evtx_name_hash(name), len(name)))
            tb.extend(u16)
            tb.extend(b"\x00\x00")

        def emit_str_val(val: str) -> None:
            u16 = val.encode("utf-16le")
            tb.extend(struct.pack("<BBH", 0x05, 0x01, len(val)))
            tb.extend(u16)

        def emit_elem(
            tag: str,
            attrs: Optional[List[Tuple[str, str]]] = None,
            text: Optional[str] = None,
            children: Optional[List[Dict[str, Any]]] = None,
        ) -> None:
            attrs = attrs or []
            children = children or []
            tb.append(0x41 if attrs else 0x01)
            tb.extend(b"\xff\xff")  # MS-EVEN6 template element dependency_id (0xFFFF)
            size_pos = len(tb)
            tb.extend(b"\x00\x00\x00\x00")
            emit_inline_name(tag)
            if attrs:
                al_pos = len(tb)
                tb.extend(b"\x00\x00\x00\x00")
                a_start = len(tb)
                for i, (ak, av) in enumerate(attrs):
                    tb.append(0x46 if i < len(attrs) - 1 else 0x06)
                    emit_inline_name(ak)
                    emit_str_val(str(av))
                struct.pack_into("<I", tb, al_pos, len(tb) - a_start)
            if text is None and not children:
                tb.append(0x03)
            else:
                tb.append(0x02)
                if text is not None:
                    emit_str_val(str(text))
                for ch in children:
                    emit_elem(ch["tag"], ch.get("attrs"), ch.get("text"), ch.get("children"))
                tb.append(0x04)
            struct.pack_into("<I", tb, size_pos, len(tb) - (size_pos + 4))

        # Outer BXML fragment header + resident TemplateInstance (0x0C) + TemplateDefinition (24B)
        tpl_id = int(ev.get("record_id", idx_ev)) & 0xFFFFFFFF
        tpl_def_off = base_off + 14
        tpl_guid = struct.pack("<IIII", tpl_id, 0x11223344, 0x55667788, 0x99AABBCC)
        tb.extend(b"\x0f\x01\x01\x00")
        tb.extend(struct.pack("<BBII", 0x0C, 0x01, tpl_id, tpl_def_off))
        tb.extend(struct.pack("<I16sI", 0, tpl_guid, 0))
        tpl_body_start = len(tb)  # offset 38 in tb

        # Inner template BXML fragment
        tb.extend(b"\x0f\x01\x01\x00")
        sys_ch = [
            {"tag": "Provider", "attrs": [("Name", ev["provider"])]},
            {"tag": "EventID", "text": str(ev["event_id"])},
            {"tag": "Level", "text": str(ev["level"])},
            {"tag": "Keywords", "text": hex(ev.get("keywords", 0x80000000000000))},
            {"tag": "TimeCreated", "attrs": [("SystemTime", ev["system_time"])]},
            {"tag": "EventRecordID", "text": str(ev["record_id"])},
            {
                "tag": "Execution",
                "attrs": [
                    ("ProcessID", str(ev.get("pid", 100))),
                    ("ThreadID", str(ev.get("tid", 200))),
                ],
            },
            {"tag": "Channel", "text": ev.get("channel", "Security")},
            {"tag": "Computer", "text": ev.get("computer", "CORP-WS01")},
            {"tag": "Security", "attrs": [("UserID", ev.get("sid", "S-1-5-18"))]},
        ]
        ev_ch: List[Dict[str, Any]] = [{"tag": "System", "children": sys_ch}]
        if ev.get("event_data"):
            ev_ch.append({
                "tag": "EventData",
                "children": [
                    {"tag": "Data", "attrs": [("Name", k)], "text": str(v)}
                    for k, v in ev["event_data"].items()
                ],
            })
        if ev.get("user_data"):
            ev_ch.append({
                "tag": "UserData",
                "children": [
                    {
                        "tag": "CustomPayload",
                        "children": [{"tag": k, "text": str(v)} for k, v in ev["user_data"].items()],
                    }
                ],
            })
        emit_elem(
            "Event",
            attrs=[("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")],
            children=ev_ch,
        )
        tb.append(0x00)  # Template body End-of-Stream token
        struct.pack_into("<I", tb, 34, len(tb) - tpl_body_start)
        tb.extend(b"\x00\x00\x00\x00")  # 0 template substitutions
        tb.append(0x00)  # Outer BXML End-of-Stream token
        while (28 + len(tb)) % 8 != 0:
            tb.append(0x00)
        rsz = 28 + len(tb)
        hdr_rec_num = int(ev.get("chunk_record_num", ev["record_id"]))
        chunk[rec_off : rec_off + rsz] = (
            struct.pack("<IIQQ", 0x00002A2A, rsz, hdr_rec_num, 133600000000000000)
            + bytes(tb)
            + struct.pack("<I", rsz)
        )
        rec_off += rsz

    first_hdr_num = int(events[0].get("chunk_record_num", events[0]["record_id"]))
    last_hdr_num = int(events[-1].get("chunk_record_num", events[-1]["record_id"]))
    events_crc = zlib.crc32(bytes(chunk[512:rec_off])) & 0xFFFFFFFF
    struct.pack_into(
        "<8sQQQQIIII",
        chunk,
        0,
        b"ElfChnk\x00",
        1,
        len(events),
        first_hdr_num,
        last_hdr_num,
        128,
        last_rec_start,
        rec_off,
        events_crc,
    )
    struct.pack_into("<I", chunk, 124, zlib.crc32(bytes(chunk[:120]) + bytes(chunk[128:512])) & 0xFFFFFFFF)

    fhdr = bytearray(4096)
    struct.pack_into("<8sQQQIHHHH", fhdr, 0, b"ElfFile\x00", 0, 0, last_hdr_num + 1, 128, 1, 3, 4096, 1)
    struct.pack_into("<I", fhdr, 124, zlib.crc32(bytes(fhdr[:120])) & 0xFFFFFFFF)
    return bytes(fhdr) + bytes(chunk)


# =============================================================================
# Test 1: All 8 Magnet AXIOM Registry & OS Tables + Exact Contract Schemas
# =============================================================================
def _populate_synthetic_axiom_hives_and_files(case_dir: Path, staging_dir: Path) -> None:
    reg_sys = staging_dir / "Registry" / "System"
    reg_alice = staging_dir / "Registry" / "Users" / "Alice"
    reg_bob = staging_dir / "Registry" / "Users" / "Bob"
    clean_sys = case_dir / "clean_hives" / "System"
    vss_sys = staging_dir / "VSS" / "VSS_1" / "Registry" / "System"
    for d in (reg_sys, reg_alice, reg_bob, clean_sys, vss_sys):
        d.mkdir(parents=True, exist_ok=True)

    ts_key = datetime(2024, 8, 12, 9, 15, 0, tzinfo=timezone.utc)
    ts_logon = datetime(2024, 8, 10, 16, 45, 0, tzinfo=timezone.utc)
    ts_pwd = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 1a. Active SAM hive (`\SAM\Domains\Account\Users`)
    sam_root = RegNodeSpec(ts_key)
    u_alice = sam_root.ensure_path(r"SAM\Domains\Account\Users\000003E9", ts_key)
    f_b, v_b = build_sam_f_and_v(
        rid=1001,
        username="Alice",
        full_name="Alice Analyst",
        comment="Lead Forensics User",
        acb_flags=0x0210,  # NormalUserAccount | PasswordNeverExpires
        logon_count=42,
        failed_count=1,
        last_logon=ts_logon,
        pwd_last_set=ts_pwd,
    )
    u_alice.add_binary("F", f_b)
    u_alice.add_binary("V", v_b)
    (reg_sys / "SAM").write_bytes(build_synthetic_regf(sam_root))

    # 1b. VSS_1 SAM hive (`\Domains\Account\Users` WITHOUT leading `SAM\` to verify both layouts!)
    vss_sam_root = RegNodeSpec(ts_key)
    u_legacy = vss_sam_root.ensure_path(r"Domains\Account\Users\000003EA", ts_key)
    f_b2, v_b2 = build_sam_f_and_v(
        rid=1002,
        username="TempContractor",
        full_name="Contractor Account",
        comment="Removed User",
        acb_flags=0x0001,  # AccountDisabled
        logon_count=3,
        failed_count=0,
        last_logon=ts_logon,
        pwd_last_set=ts_pwd,
    )
    u_legacy.add_binary("F", f_b2)
    u_legacy.add_binary("V", v_b2)
    (vss_sys / "SAM").write_bytes(build_synthetic_regf(vss_sam_root))

    # 2. SYSTEM hive: put clean copy in `clean_hives/System/SYSTEM` AND dirty decoy in `staging/Registry/System/SYSTEM`
    # to verify `clean_hives` takes priority and deduplicates `("active", "SYSTEM", "")`!
    sys_clean = RegNodeSpec(ts_key)
    sel = sys_clean.ensure_path("Select", ts_key)
    sel.add_dword("Current", 2)  # Active ControlSet002

    tzi = sys_clean.ensure_path(r"ControlSet002\Control\TimeZoneInformation", ts_key)
    tzi.add_dword("ActiveTimeBias", 0)
    tzi.add_sz("TimeZoneKeyName", "UTC")

    svc1 = sys_clean.ensure_path(r"ControlSet002\Services\UpdaterAgent", ts_key)
    svc1.add_sz("DisplayName", "Enterprise Updater Agent")
    svc1.add_sz("ImagePath", r"C:\ProgramData\Updater\agent.exe --service")
    svc1.add_dword("Start", 2)
    svc1.add_dword("DelayedAutostart", 1)
    svc1.add_dword("Type", 0x10)
    svc1.add_sz("ObjectName", "LocalSystem")
    svc1.add_sz("Description", "Background update daemon")

    svc2 = sys_clean.ensure_path(r"ControlSet002\Services\HostedPlugin", ts_key)
    svc2.add_dword("Start", 3)
    svc2.add_dword("Type", 0x20)
    svc2_p = svc2.ensure_path("Parameters", ts_key)
    svc2_p.add_sz("ServiceDll", r"C:\Windows\System32\plugin_svc.dll")

    # BAM & DAM across State\UserSettings and UserSettings (skipping Version/SequenceNumber)
    sid_alice = "S-1-5-21-111111111-222222222-333333333-1001"
    bam_dt = datetime(2024, 8, 11, 21, 0, 0, tzinfo=timezone.utc)
    bam_node = sys_clean.ensure_path(rf"ControlSet002\Services\bam\State\UserSettings\{sid_alice}", ts_key)
    bam_node.add_dword("Version", 1)
    bam_node.add_dword("SequenceNumber", 9)
    bam_node.add_binary(
        r"\Device\HarddiskVolume3\Tools\netscan.exe",
        struct.pack("<Q", dt_to_filetime(bam_dt)) + (b"\x00" * 16),
    )
    dam_node = sys_clean.ensure_path(rf"ControlSet002\Services\dam\UserSettings\{sid_alice}", ts_key)
    dam_node.add_binary(
        r"\Device\HarddiskVolume3\Users\Alice\AppData\Local\helper.exe",
        struct.pack("<Q", dt_to_filetime(bam_dt)) + (b"\x00" * 16),
    )
    (clean_sys / "SYSTEM").write_bytes(build_synthetic_regf(sys_clean))

    # Dirty decoy SYSTEM in staging/Registry/System/SYSTEM (must be skipped due to clean_hives priority!)
    sys_dirty = RegNodeSpec(ts_key)
    sys_dirty.ensure_path("Select", ts_key).add_dword("Current", 1)
    decoy_svc = sys_dirty.ensure_path(r"ControlSet001\Services\DirtyOnlyDecoy", ts_key)
    decoy_svc.add_sz("ImagePath", r"C:\decoy.exe")
    decoy_svc.add_dword("Start", 2)
    (reg_sys / "SYSTEM").write_bytes(build_synthetic_regf(sys_dirty))

    # 3. SOFTWARE hive (`ProfileList`, `Run`, `IFEO`, `NetworkList`)
    soft_root = RegNodeSpec(ts_key)
    pl_alice = soft_root.ensure_path(rf"Microsoft\Windows NT\CurrentVersion\ProfileList\{sid_alice}", ts_key)
    pl_alice.add_sz("ProfileImagePath", r"C:\Users\Alice")

    sw_run = soft_root.ensure_path(r"Microsoft\Windows\CurrentVersion\Run", ts_key)
    sw_run.add_sz("SecurityTray", r"C:\Program Files\SecSuite\tray.exe")
    ifeo = soft_root.ensure_path(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", ts_key)
    ifeo.add_sz("Debugger", r"C:\Windows\System32\cmd.exe")

    net_guid = "{A1B2C3D4-E5F6-4789-ABCD-0123456789AB}"
    np_node = soft_root.ensure_path(rf"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{net_guid}", ts_key)
    np_node.add_sz("ProfileName", "CorpHQ-WiFi")
    np_node.add_sz("Description", "Corporate Wireless")
    np_node.add_dword("Category", 2)  # Domain
    np_node.add_dword("NameType", 71)  # Wireless
    np_created = datetime(2024, 6, 1, 8, 30, 0, tzinfo=timezone.utc)
    np_last = datetime(2024, 8, 12, 7, 45, 0, tzinfo=timezone.utc)
    np_node.add_binary("DateCreated", dt_to_systemtime_bytes(np_created))
    np_node.add_binary("DateLastConnected", dt_to_systemtime_bytes(np_last))

    sig_node = soft_root.ensure_path(
        r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\010103000F0000F008000000",
        ts_key,
    )
    sig_node.add_sz("ProfileGuid", net_guid)
    sig_node.add_sz("DnsSuffix", "corp.internal")
    sig_node.add_sz("FirstNetwork", "CorpHQ-SSID")
    sig_node.add_binary("DefaultGatewayMac", bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]))
    (reg_sys / "SOFTWARE").write_bytes(build_synthetic_regf(soft_root))

    # 4. Alice NTUSER.DAT (Autoruns, UserAssist ROT13 v5 72B + v3 16B, all 7 MRU subkeys)
    nt_alice = RegNodeSpec(ts_key)
    u_run = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Run", ts_key)
    u_run.add_sz("CloudSync", r"C:\Users\Alice\AppData\Local\Sync\sync.exe")

    ua_count = nt_alice.ensure_path(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
        ts_key,
    )
    ua_dt = datetime(2024, 8, 11, 19, 20, 0, tzinfo=timezone.utc)
    # Win10 v5 72-byte entry with Known Folder GUID `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe`
    rot_cmd = codecs.encode(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe", "rot_13")
    ua_v5 = bytearray(72)
    struct.pack_into("<III", ua_v5, 4, 14, 9, 45000)
    struct.pack_into("<Q", ua_v5, 60, dt_to_filetime(ua_dt))
    ua_count.add_binary(rot_cmd, bytes(ua_v5))

    # XP v3 16-byte entry (`raw_count = 12` -> `run_count = 7`)
    rot_xp = codecs.encode(r"C:\Tools\legacy_viewer.exe", "rot_13")
    ua_v3 = struct.pack("<IIQ", 0, 12, dt_to_filetime(ua_dt))
    ua_count.add_binary(rot_xp, ua_v3)

    # All 7 MRU keys in Alice NTUSER.DAT
    rd_k = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", ts_key)
    rd_k.add_binary("MRUListEx", struct.pack("<II", 0, 0xFFFFFFFF))
    rd_k.add_binary("0", "q3_budget.xlsx".encode("utf-16le") + b"\x00\x00" + build_pidl_with_beef0004(["q3_budget.lnk"]))

    os_k = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\pdf", ts_key)
    os_k.add_binary("MRUListEx", struct.pack("<II", 0, 0xFFFFFFFF))
    os_k.add_binary("0", build_pidl_with_beef0004(["C:", "Users", "Alice", "Documents", "design_spec.pdf"]))

    lv_k = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", ts_key)
    lv_k.add_binary("MRUListEx", struct.pack("<II", 0, 0xFFFFFFFF))
    lv_k.add_binary("0", "acrobat.exe".encode("utf-16le") + b"\x00\x00" + build_pidl_with_beef0004(["C:", "Export"]))

    ww_k = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", ts_key)
    ww_k.add_binary("MRUListEx", struct.pack("<II", 0, 0xFFFFFFFF))
    ww_k.add_binary("0", "confidential_roadmap\x00".encode("utf-16le"))

    tp_k = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", ts_key)
    tp_k.add_sz("url1", r"\\fileserver01\finance\2024")

    tu_k = nt_alice.ensure_path(r"Software\Microsoft\Internet Explorer\TypedURLs", ts_key)
    tu_k.add_sz("url1", "https://intranet.corp.internal/portal")
    tu_t = nt_alice.ensure_path(r"Software\Microsoft\Internet Explorer\TypedURLsTime", ts_key)
    tu_t.add_binary("url1", struct.pack("<Q", dt_to_filetime(ua_dt)))

    rm_k = nt_alice.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", ts_key)
    rm_k.add_sz("MRUList", "a")
    rm_k.add_sz("a", r"mstsc /v:10.20.30.40\1")

    (reg_alice / "NTUSER.DAT").write_bytes(build_synthetic_regf(nt_alice, bins_size=0xC000))

    # 5. Alice UsrClass.dat (`MuiCache`)
    uc_alice = RegNodeSpec(ts_key)
    mc_k = uc_alice.ensure_path(r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache", ts_key)
    mc_k.add_sz(r"C:\PortableApps\archiver.exe.FriendlyAppName", "7-Zip Portable")
    (reg_alice / "UsrClass.dat").write_bytes(build_synthetic_regf(uc_alice))

    # 6. Bob NTUSER.DAT (multi-user attribution check)
    nt_bob = RegNodeSpec(ts_key)
    bob_rm = nt_bob.ensure_path(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", ts_key)
    bob_rm.add_sz("MRUList", "a")
    bob_rm.add_sz("a", r"powershell.exe -nop\1")
    (reg_bob / "NTUSER.DAT").write_bytes(build_synthetic_regf(nt_bob))

    # 7. Staged WLAN XML profile
    wlan_dir = staging_dir / "ProgramData" / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces" / "{1111-2222}"
    wlan_dir.mkdir(parents=True, exist_ok=True)
    wlan_xml = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>Airport-Lounge-5G</name>
    <SSIDConfig><SSID><name>Airport_Free_5G</name></SSID></SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM><security><authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
    </authEncryption></security></MSM>
</WLANProfile>"""
    (wlan_dir / "profile_wifi.xml").write_text(wlan_xml, encoding="utf-8")

    # 8. Staged UTF-16LE `Report.wer`
    wer_dir = staging_dir / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive" / "AppCrash_badapp.exe_1234"
    wer_dir.mkdir(parents=True, exist_ok=True)
    wer_dt = datetime(2024, 8, 12, 3, 14, 15, tzinfo=timezone.utc)
    wer_content = "\r\n".join([
        "Version=1",
        "EventType=APPCRASH",
        f"EventTime={dt_to_filetime(wer_dt)}",
        "ReportType=2",
        r"AppPath=C:\Apps\badapp.exe",
        "ReportIdentifier={99887766-5544-3322-1100-AABBCCDDEEFF}",
        "Sig[0].Name=Application Name",
        "Sig[0].Value=badapp.exe",
        "Sig[3].Name=Fault Module Name",
        "Sig[3].Value=ntdll.dll",
        "Sig[6].Name=Exception Code",
        "Sig[6].Value=c0000005",
    ])
    (wer_dir / "Report.wer").write_bytes(b"\xff\xfe" + wer_content.encode("utf-16le"))


def test_axiom_all_8_registry_and_os_tables_and_contract_columns(isolated_case: Dict[str, Any]) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]
    staging_dir = isolated_case["staging_dir"]

    _populate_synthetic_axiom_hives_and_files(case_dir, staging_dir)

    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    counts = parser.run_all(max_workers=8)

    expected_schemas: Dict[str, List[str]] = {
        "parsed_user_accounts": [
            "rid", "username", "full_name", "comment", "account_flags",
            "last_logon_utc", "pwd_last_set_utc", "last_failed_logon_utc", "logon_count", "source_hive",
        ],
        "parsed_windows_services": [
            "service_name", "display_name", "image_path", "start_type", "service_type",
            "object_name", "description", "last_write_utc", "source_hive",
        ],
        "parsed_autoruns": [
            "entry_name", "command_or_path", "location_key", "username", "last_write_utc", "source_hive",
        ],
        "parsed_userassist": [
            "program_path", "guid", "run_count", "focus_count", "focus_time_ms",
            "last_executed_utc", "username", "source_hive",
        ],
        "parsed_bam_dam": [
            "sid", "executable_path", "last_execution_utc", "type", "source_hive",
        ],
        "parsed_registry_mru": [
            "mru_type", "key_path", "entry_name", "value_text", "mru_position",
            "last_write_utc", "username", "source_hive",
        ],
        "parsed_network_profiles": [
            "profile_name", "ssid_or_dns", "description", "category", "date_created_utc",
            "date_last_connected_utc", "default_gateway_mac", "auth_type", "source",
        ],
        "parsed_wer_reports": [
            "app_name", "app_path", "fault_module", "exception_code", "report_type",
            "event_time_utc", "report_id", "source_path",
        ],
    }

    conn = DuckDBManager.get_connection(case_id, read_only=False)
    for tbl, req_cols in expected_schemas.items():
        assert counts.get(tbl, 0) > 0, f"Expected positive row count for {tbl}, got {counts}"
        actual_cols = {str(r[0]) for r in conn.execute(f'DESCRIBE "{tbl}";').fetchall()}
        missing = [c for c in req_cols if c not in actual_cols]
        assert not missing, f"Table {tbl} missing contract columns: {missing} (actual: {sorted(actual_cols)})"

    # 1. parsed_user_accounts: both `\SAM\Domains\Account\Users` (Alice) and VSS_1 `\Domains\Account\Users` (TempContractor)
    users = conn.execute(
        "SELECT rid, username, full_name, logon_count, account_flags, source_hive FROM parsed_user_accounts ORDER BY rid;"
    ).fetchall()
    by_rid = {r[0]: r for r in users}
    assert 1001 in by_rid and by_rid[1001][1] == "Alice" and by_rid[1001][2] == "Alice Analyst" and by_rid[1001][3] == 42
    assert "PasswordNeverExpires" in by_rid[1001][4]
    assert 1002 in by_rid and by_rid[1002][1] == "TempContractor" and "VSS" in by_rid[1002][5]

    # 2. parsed_windows_services: clean_hives priority deduplicated DirtyOnlyDecoy!
    svcs = {
        r[0]: r
        for r in conn.execute(
            "SELECT service_name, image_path, start_type, object_name FROM parsed_windows_services;"
        ).fetchall()
    }
    assert "UpdaterAgent" in svcs
    assert svcs["UpdaterAgent"][2] == "Auto (Delayed)"
    assert "HostedPlugin" in svcs and "plugin_svc.dll" in (svcs["HostedPlugin"][1] or "")
    assert "DirtyOnlyDecoy" not in svcs, "clean_hives SYSTEM must take precedence over dirty staging/Registry SYSTEM"

    # 3. parsed_autoruns: SOFTWARE Run + IFEO Debugger + Alice NTUSER Run
    autoruns = conn.execute(
        "SELECT entry_name, command_or_path, username FROM parsed_autoruns;"
    ).fetchall()
    ar_names = {r[0]: (r[1], r[2]) for r in autoruns}
    assert "SecurityTray" in ar_names and "sethc.exe" in ar_names
    assert "CloudSync" in ar_names and ar_names["CloudSync"][1] == "Alice"

    # 4. parsed_userassist: ROT13 + Known Folder GUID expansion + v5 72B & XP v3 16B
    ua_rows = {
        r[0]: r
        for r in conn.execute(
            "SELECT program_path, run_count, focus_count, focus_time_ms, username FROM parsed_userassist;"
        ).fetchall()
    }
    assert r"%SystemRoot%\System32\cmd.exe" in ua_rows
    assert ua_rows[r"%SystemRoot%\System32\cmd.exe"][1:5] == (14, 9, 45000, "Alice")
    assert r"C:\Tools\legacy_viewer.exe" in ua_rows
    assert ua_rows[r"C:\Tools\legacy_viewer.exe"][1] == 7  # 12 - 5 XP bias

    # 5. parsed_bam_dam: BAM + DAM, skipping Version & SequenceNumber
    bd_rows = conn.execute("SELECT type, executable_path, sid FROM parsed_bam_dam;").fetchall()
    bd_types = {r[0]: r[1] for r in bd_rows}
    assert "BAM" in bd_types and "netscan.exe" in bd_types["BAM"]
    assert "DAM" in bd_types and "helper.exe" in bd_types["DAM"]
    assert all(r[1].lower() not in ("version", "sequencenumber") for r in bd_rows)

    # 6. parsed_registry_mru: all 7 MRU types + UsrClass MuiCache + multi-user Alice & Bob
    mru_rows = conn.execute(
        "SELECT mru_type, value_text, mru_position, username FROM parsed_registry_mru;"
    ).fetchall()
    mru_types = {r[0] for r in mru_rows}
    for req_mru in (
        "RecentDocs", "OpenSavePidlMRU", "LastVisitedPidlMRU",
        "WordWheelQuery", "TypedPaths", "TypedURLs", "RunMRU", "MuiCache",
    ):
        assert req_mru in mru_types, f"Missing MRU type {req_mru} in {mru_types}"
    mru_users = {r[3] for r in mru_rows}
    assert "Alice" in mru_users and "Bob" in mru_users
    assert any("design_spec.pdf" in r[1] for r in mru_rows if r[0] == "OpenSavePidlMRU")
    assert any(r[1] == "mstsc /v:10.20.30.40" and r[2] == 0 for r in mru_rows if r[0] == "RunMRU" and r[3] == "Alice")

    # 7. parsed_network_profiles: Registry NetworkList + Signatures Gateway MAC + Staged WLAN XML
    net_rows = {
        r[0]: r
        for r in conn.execute(
            "SELECT profile_name, ssid_or_dns, category, default_gateway_mac, auth_type FROM parsed_network_profiles;"
        ).fetchall()
    }
    assert "CorpHQ-WiFi" in net_rows
    assert net_rows["CorpHQ-WiFi"][1] == "CorpHQ-SSID"
    assert net_rows["CorpHQ-WiFi"][3] == "AA:BB:CC:DD:EE:FF"
    assert "Airport-Lounge-5G" in net_rows
    assert net_rows["Airport-Lounge-5G"][1] == "Airport_Free_5G"
    assert net_rows["Airport-Lounge-5G"][4] == "WPA2PSK/AES"

    # 8. parsed_wer_reports: UTF-16LE Report.wer crash extraction
    wer_rows = conn.execute(
        "SELECT app_name, app_path, fault_module, exception_code, report_id FROM parsed_wer_reports;"
    ).fetchall()
    assert len(wer_rows) == 1
    assert wer_rows[0][0] == "badapp.exe"
    assert wer_rows[0][1] == r"C:\Apps\badapp.exe"
    assert wer_rows[0][2] == "ntdll.dll"
    assert wer_rows[0][3] == "c0000005"
    assert wer_rows[0][4] == "99887766-5544-3322-1100-AABBCCDDEEFF"


# =============================================================================
# Test 2: `dissect.regf` Seamless Fallback When `regipy` Is Unavailable
# =============================================================================
def test_dissect_regf_fallback_when_regipy_unavailable(
    isolated_case: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]
    staging_dir = isolated_case["staging_dir"]
    _populate_synthetic_axiom_hives_and_files(case_dir, staging_dir)

    monkeypatch.setattr(nfp, "RegipyHive", None)
    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    counts = parser.run_all(max_workers=4)

    for tbl in (
        "parsed_user_accounts",
        "parsed_windows_services",
        "parsed_autoruns",
        "parsed_userassist",
        "parsed_bam_dam",
        "parsed_registry_mru",
        "parsed_network_profiles",
    ):
        assert counts.get(tbl, 0) > 0, f"dissect.regf fallback failed on {tbl}: {counts}"


# =============================================================================
# Test 3: MAM\x04 + SCCA Prefetch & `vfs_files` Original Timestamp Lookup
# =============================================================================
def test_native_prefetch_mam_decompression_scca_versions_and_vfs_timestamps(
    isolated_case: Dict[str, Any],
) -> None:
    case_id = isolated_case["case_id"]
    staging_dir = isolated_case["staging_dir"]
    pf_dir = staging_dir / "Prefetch"
    pf_dir.mkdir(parents=True, exist_ok=True)

    run1 = datetime(2024, 8, 12, 11, 22, 33, tzinfo=timezone.utc)
    run2 = datetime(2024, 8, 11, 10, 0, 0, tzinfo=timezone.utc)

    # 1. MAM\x84 (12-byte CRC header) Win10/11 v30 with metrics_off == 0xE8 -> run_count @ 0xC8
    scca_v30_new = build_scca_prefetch(
        exe_name="POWERSHELL.EXE",
        pf_hash=0x11223344,
        version=30,
        run_count=19,
        last_runs=[run1, run2],
        metrics_off=0xE8,
        vol_name=r"\VOLUME{01d99999-aaaa}",
        vol_serial=0x87654321,
    )
    pf1 = pf_dir / "POWERSHELL.EXE-11223344.pf"
    pf1.write_bytes(encode_mam_lzxpress_huffman(scca_v30_new, include_crc=True))

    # 2. MAM\x04 (8-byte header without CRC) Win10 v30 with metrics_off == 0xF0 -> run_count @ 0xD0
    scca_v30_old = build_scca_prefetch(
        exe_name="CERTUTIL.EXE",
        pf_hash=0xAABBCCDD,
        version=30,
        run_count=5,
        last_runs=[run2],
        metrics_off=0xF0,
    )
    pf2 = pf_dir / "CERTUTIL.EXE-AABBCCDD.pf"
    pf2.write_bytes(encode_mam_lzxpress_huffman(scca_v30_old, include_crc=False))

    # 3. Uncompressed SCCA Win7 v23 Prefetch (left with host `now()` mtime AND NULL vfs_files timestamps
    #    to verify zero `datetime.now()` fabrication!)
    scca_v23 = build_scca_prefetch(
        exe_name="NOTEPAD.EXE",
        pf_hash=0x55667788,
        version=23,
        run_count=3,
        last_runs=[run2],
    )
    pf3 = pf_dir / "NOTEPAD.EXE-55667788.pf"
    pf3.write_bytes(scca_v23)

    # Populate `vfs_files`: give pf1 explicit historical MAC timestamps, and pf3 NULL timestamps!
    hist_cr = datetime(2021, 3, 14, 9, 26, 53, tzinfo=timezone.utc)
    hist_mod = datetime(2024, 8, 12, 11, 22, 34, tzinfo=timezone.utc)
    conn = DuckDBManager.get_connection(case_id, read_only=False)
    with DuckDBManager.get_lock(case_id):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vfs_files (
                staged_rel_path VARCHAR,
                si_created TIMESTAMP,
                si_modified TIMESTAMP,
                si_accessed TIMESTAMP
            );
            ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS staged_rel_path VARCHAR;
            ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_created TIMESTAMP;
            ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_modified TIMESTAMP;
            ALTER TABLE vfs_files ADD COLUMN IF NOT EXISTS si_accessed TIMESTAMP;
            """
        )
        conn.execute(
            "INSERT INTO vfs_files (staged_rel_path, si_created, si_modified, si_accessed) VALUES (?, ?, ?, ?), (?, NULL, NULL, NULL);",
            [
                "Prefetch/POWERSHELL.EXE-11223344.pf",
                hist_cr.replace(tzinfo=None),
                hist_mod.replace(tzinfo=None),
                hist_mod.replace(tzinfo=None),
                "Prefetch/NOTEPAD.EXE-55667788.pf",
            ],
        )

    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    cnt = parser.parse_prefetch_natively(max_workers=4)
    assert cnt == 3

    rows = {
        r[0]: r
        for r in conn.execute(
            "SELECT ExecutableName, RunCount, Volume0Serial, SourceCreated, SourceModified FROM raw_pecmd;"
        ).fetchall()
    }
    assert rows["POWERSHELL.EXE"][1] == 19
    assert rows["POWERSHELL.EXE"][2] == "87654321"
    assert rows["POWERSHELL.EXE"][3].replace(tzinfo=None) == hist_cr.replace(tzinfo=None)
    assert rows["CERTUTIL.EXE"][1] == 5
    assert rows["NOTEPAD.EXE"][1] == 3
    # Verify NULL vfs_files + fresh host mtime stays None (zero `now()` fabrication!)
    assert rows["NOTEPAD.EXE"][3] is None and rows["NOTEPAD.EXE"][4] is None

    tl_cnt = conn.execute("SELECT COUNT(*) FROM raw_pecmd_timeline;").fetchone()[0]
    assert tl_cnt == 4


# =============================================================================
# Test 4: Uncapped MFT + $MFT, NTFS USA Sector Fixup & $SI < $FN Timestomp
# =============================================================================
def test_native_mft_uncapped_both_filenames_usa_fixup_and_timestomp(
    isolated_case: Dict[str, Any],
) -> None:
    case_id = isolated_case["case_id"]
    staging_dir = isolated_case["staging_dir"]
    part1 = staging_dir / "Enrichment" / "Vol1"
    part2 = staging_dir / "Enrichment" / "Vol2"
    part1.mkdir(parents=True, exist_ok=True)
    part2.mkdir(parents=True, exist_ok=True)

    normal_dt = datetime(2024, 5, 20, 10, 0, 0, tzinfo=timezone.utc)
    backdated_si = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Partition 1 `$MFT`: directory entry 10 + cross-sector-boundary file + timestomped file + 60 records
    p1_chunks: List[bytes] = [
        build_mft_record(5, ".", 5, normal_dt, normal_dt, is_dir=True),
        build_mft_record(10, "SecretDir", 5, normal_dt, normal_dt, is_dir=True),
        build_mft_record(
            11,
            "sector_straddle_document_alpha_bravo_charlie.docx",
            10,
            normal_dt,
            normal_dt,
            file_size=987654,
            cross_sector_boundary=True,
        ),
        build_mft_record(
            12,
            "timestomped_payload.exe",
            10,
            si_created=backdated_si,
            fn_created=normal_dt,
            file_size=65536,
        ),
    ]
    for idx in range(20, 80):
        p1_chunks.append(build_mft_record(idx, f"vol1_item_{idx}.txt", 10, normal_dt, normal_dt, file_size=128))
    (part1 / "$MFT").write_bytes(b"".join(p1_chunks))

    # Partition 2 `MFT` (without `$` prefix): 60 records
    p2_chunks: List[bytes] = [
        build_mft_record(5, ".", 5, normal_dt, normal_dt, is_dir=True),
    ]
    for idx in range(100, 160):
        p2_chunks.append(build_mft_record(idx, f"vol2_item_{idx}.log", 5, normal_dt, normal_dt, file_size=256))
    (part2 / "MFT").write_bytes(b"".join(p2_chunks))

    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    total = parser.parse_mft_natively()
    assert total == len(p1_chunks) + len(p2_chunks)

    conn = DuckDBManager.get_connection(case_id, read_only=False)
    straddle = conn.execute(
        "SELECT FileName, ParentPath, FileSize, TimestampsLogicalInconsistency FROM raw_mft WHERE EntryNumber = 11;"
    ).fetchone()
    assert straddle is not None
    assert straddle[0] == "sector_straddle_document_alpha_bravo_charlie.docx"
    assert "SecretDir" in straddle[1]
    assert straddle[2] == 987654
    assert straddle[3] is False

    stomped = conn.execute(
        "SELECT FileName, TimestampsLogicalInconsistency FROM raw_mft WHERE EntryNumber = 12;"
    ).fetchone()
    assert stomped == ("timestomped_payload.exe", True)


# =============================================================================
# Test 5: Uncapped EVTX With Real Level 1–5 + Audit Keywords + Granular Views
# =============================================================================
def test_native_evtx_uncapped_all_levels_audit_keywords_and_granular_views(
    isolated_case: Dict[str, Any],
) -> None:
    case_id = isolated_case["case_id"]
    staging_dir = isolated_case["staging_dir"]
    ev_dir = staging_dir / "EventLogs"
    ev_dir.mkdir(parents=True, exist_ok=True)

    events = [
        {
            "record_id": 101,
            "event_id": 41,
            "level": 1,
            "pid": 4,
            "tid": 8,
            "system_time": "2024-08-12T01:00:00.000000Z",
            "provider": "Microsoft-Windows-Kernel-Power",
            "channel": "System",
            "event_data": {"BugcheckCode": "0x139"},
        },
        {
            "record_id": 102,
            "event_id": 7045,
            "level": 2,
            "pid": 680,
            "tid": 712,
            "system_time": "2024-08-12T01:05:00.000000Z",
            "provider": "Service Control Manager",
            "channel": "System",
            "user_data": {"ServiceName": "PersistSvc", "ImagePath": r"C:\Temp\svc.exe"},
        },
        {
            "record_id": 103,
            "event_id": 1014,
            "level": 3,
            "pid": 1120,
            "tid": 1140,
            "system_time": "2024-08-12T01:10:00.000000Z",
            "provider": "Microsoft-Windows-DNS-Client",
            "channel": "System",
        },
        {
            "record_id": 104,
            "event_id": 4688,
            "level": 4,
            "pid": 4400,
            "tid": 4404,
            "system_time": "2024-08-12T01:15:00.000000Z",
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "event_data": {"SubjectUserName": "Alice", "NewProcessName": r"C:\Windows\System32\whoami.exe"},
        },
        {
            "record_id": 105,
            "event_id": 4104,
            "level": 5,
            "pid": 5200,
            "tid": 5212,
            "system_time": "2024-08-12T01:20:00.000000Z",
            "provider": "Microsoft-Windows-PowerShell",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_data": {"ScriptBlockText": "Get-Process"},
        },
        {
            "record_id": 106,
            "event_id": 4625,
            "level": 0,
            "keywords": 0x8010000000000000,
            "pid": 640,
            "tid": 900,
            "system_time": "2024-08-12T01:25:00.000000Z",
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "event_data": {"TargetUserName": "Bob", "IpAddress": "192.168.50.99"},
        },
        {
            "record_id": 107,
            "event_id": 4624,
            "level": 0,
            "keywords": 0x8020000000000000,
            "pid": 640,
            "tid": 904,
            "system_time": "2024-08-12T01:26:00.000000Z",
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "event_data": {"TargetUserName": "Alice", "IpAddress": "10.0.0.25"},
        },
    ]
    (ev_dir / "Security.evtx").write_bytes(build_synthetic_evtx(events))

    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    cnt = parser.parse_evtx_natively(max_workers=4)
    assert cnt == 7

    conn = DuckDBManager.get_connection(case_id, read_only=False)
    by_rec = {
        r[0]: r
        for r in conn.execute(
            "SELECT EventRecordId, EventId, Level, ProcessId, ThreadId, UserName, RemoteHost, PayloadData1 FROM raw_evtx;"
        ).fetchall()
    }
    assert by_rec[101][2] == "Critical"
    assert by_rec[102][2] == "Error" and "PersistSvc" in by_rec[102][7]
    assert by_rec[103][2] == "Warning"
    assert by_rec[104][2] == "Information" and by_rec[104][3] == 4400 and by_rec[104][5] == "Alice"
    assert by_rec[105][2] == "Verbose"
    assert by_rec[106][2] == "Audit Failure" and by_rec[106][5] == "Bob" and by_rec[106][6] == "192.168.50.99"
    assert by_rec[107][2] == "Audit Success"


# =============================================================================
# Test 6: EseDB WebCacheV01.dat & SRUDB.dat, GDrive, RecycleBin & raw_recmd
# =============================================================================
def test_ese_webcache_srudb_gdrive_recyclebin_and_registry_summary(
    isolated_case: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]
    staging_dir = isolated_case["staging_dir"]
    _populate_synthetic_axiom_hives_and_files(case_dir, staging_dir)

    # 1. Stage WebCacheV01.dat & SRUDB.dat and test real `EseDB` table record handling via structured EseDB stub
    wc_dir = staging_dir / "Users" / "Clara" / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache"
    wc_dir.mkdir(parents=True, exist_ok=True)
    wc_path = wc_dir / "WebCacheV01.dat"
    wc_path.write_bytes(b"\xef\xcd\xab\x89" + b"\x00" * 4096)

    sru_dir = staging_dir / "Windows" / "System32" / "sru"
    sru_dir.mkdir(parents=True, exist_ok=True)
    sru_path = sru_dir / "SRUDB.dat"
    sru_path.write_bytes(b"\xef\xcd\xab\x89" + b"\x00" * 8192)

    visit_ft = dt_to_filetime(datetime(2024, 8, 9, 15, 0, 0, tzinfo=timezone.utc))
    # Binary SID S-1-5-21-111111111-222222222-333333333-1001 (maps to Alice via SOFTWARE ProfileList!)
    alice_sid_blob = struct.pack(
        "<BB6sIIIII", 1, 5, b"\x00\x00\x00\x00\x00\x05", 21, 111111111, 222222222, 333333333, 1001
    )
    # Real `dissect.esedb` `JET_coltyp.DateTime` (`c_esedb.int64` raw IEEE-754 double bits for 45458.5 -> 2024-06-15 12:00:00Z)
    srum_oa_int64 = struct.unpack("<q", struct.pack("<d", 45458.5))[0]

    class _StrictEseRec:
        """Faithful `dissect.esedb.Record` double raising `KeyError` on non-existent table columns."""

        def __init__(self, cols: Tuple[str, ...], d: Dict[str, Any]) -> None:
            self._cols = set(cols)
            self._d = d

        def get(self, key: str, raw: bool = False) -> Any:
            if key not in self._cols:
                raise KeyError(f"No column with this name in table: {key}")
            return self._d.get(key)

    class _StrictEseTable:
        def __init__(self, name: str, cols: Tuple[str, ...], rows: List[Dict[str, Any]]) -> None:
            self.name = name
            self._cols = cols
            self._rows = rows

        def records(self):
            return [_StrictEseRec(self._cols, r) for r in self._rows]

    class _FakeEseDB:
        def __init__(self, fh: Any) -> None:
            fname = Path(getattr(fh, "name", "")).name.lower()
            if "webcache" in fname:
                self._tables = {
                    "Containers": _StrictEseTable(
                        "Containers",
                        ("ContainerId", "Name", "Directory"),
                        [
                            {"ContainerId": 4, "Name": "History", "Directory": r"C:\Users\Clara\AppData\Local\History"},
                            {"ContainerId": 5, "Name": "DOMStore", "Directory": r"C:\Users\Clara\AppData\Local\DOMStore"},
                        ],
                    ),
                    "Container_4": _StrictEseTable(
                        "Container_4",
                        ("Url", "AccessedTime", "ModifiedTime", "CreationTime", "AccessCount"),
                        [
                            {
                                "Url": "Visited: Clara@https://portal.example.org/docs/report.pdf",
                                "AccessedTime": visit_ft,
                                "ModifiedTime": visit_ft,
                                "CreationTime": visit_ft,
                                "AccessCount": 3,
                            }
                        ],
                    ),
                    # DOMStore container deliberately lacks AccessedTime, CreationTime, and AccessCount!
                    "Container_5": _StrictEseTable(
                        "Container_5",
                        ("EntryId", "Url", "ModifiedTime", "Data"),
                        [
                            {"EntryId": 1, "Url": None, "ModifiedTime": visit_ft, "Data": b"{}"},
                            {"EntryId": 2, "Url": "https://domstore.example.org/app", "ModifiedTime": visit_ft, "Data": b"ok"},
                        ],
                    ),
                }
            else:
                self._tables = {
                    "SruDbIdMapTable": _StrictEseTable(
                        "SruDbIdMapTable",
                        ("IdIndex", "IdType", "IdBlob"),
                        [
                            {"IdIndex": 10, "IdType": 0, "IdBlob": r"\Device\HarddiskVolume3\Tools\curl.exe".encode("utf-16le")},
                            {"IdIndex": 20, "IdType": 3, "IdBlob": alice_sid_blob},
                        ],
                    ),
                    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": _StrictEseTable(
                        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
                        ("TimeStamp", "AppId", "UserId", "ForegroundCycleTime", "BackgroundCycleTime", "FaceTime"),
                        [{"TimeStamp": srum_oa_int64, "AppId": 10, "UserId": 20, "ForegroundCycleTime": 9000, "BackgroundCycleTime": 100, "FaceTime": 45}],
                    ),
                    # Real SRUDB network table has `BytesRecvd` (NO `BytesReceived` column!) + row with `BytesRecvd == 0`!
                    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": _StrictEseTable(
                        "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
                        ("TimeStamp", "AppId", "UserId", "BytesSent", "BytesRecvd", "InterfaceLuid"),
                        [
                            {"TimeStamp": srum_oa_int64, "AppId": 10, "UserId": 20, "BytesSent": 512, "BytesRecvd": 0, "InterfaceLuid": 77},
                            {"TimeStamp": srum_oa_int64, "AppId": 10, "UserId": 20, "BytesSent": 4096, "BytesRecvd": 16384, "InterfaceLuid": 77},
                        ],
                    ),
                    "{DD6636C4-8929-4683-974E-22C046A43763}": _StrictEseTable(
                        "{DD6636C4-8929-4683-974E-22C046A43763}",
                        ("TimeStamp", "AppId", "UserId", "ConnectStartTime", "ConnectTime", "InterfaceLuid"),
                        [{"TimeStamp": srum_oa_int64, "AppId": 10, "UserId": 20, "ConnectStartTime": visit_ft, "ConnectTime": 120, "InterfaceLuid": 77}],
                    ),
                }

        def tables(self):
            return list(self._tables.values())

        def table(self, name: str):
            return self._tables[name]

    monkeypatch.setattr(nfp, "EseDB", _FakeEseDB)

    # 2. Stage Google Drive `sync_log.log` for an arbitrary user `Diana`
    gd_dir = staging_dir / "Users" / "Diana" / "AppData" / "Local" / "Google" / "Drive"
    gd_dir.mkdir(parents=True, exist_ok=True)
    (gd_dir / "sync_log.log").write_text(
        "2024-08-10 14:22:01,123 +0000 INFO pid=1234 Thread-1 account=diana@corp.example "
        "Action create u'C:\\\\Users\\\\Diana\\\\My Drive\\\\quarterly_forecast.xlsx'\n",
        encoding="utf-8",
    )

    # 3. Stage Recycle Bin `$I` v2 metadata
    rb_dir = staging_dir / "$Recycle.Bin" / "S-1-5-21-111-1001"
    rb_dir.mkdir(parents=True, exist_ok=True)
    orig_del = r"C:\Users\Alice\Desktop\deleted_archive.zip"
    del_u16 = orig_del.encode("utf-16le") + b"\x00\x00"
    i_v2 = struct.pack("<QQQI", 2, 1048576, visit_ft, len(orig_del) + 1) + del_u16
    (rb_dir / "$IABCDEF.zip").write_bytes(i_v2)

    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    assert parser.parse_ie_webcache() == 2
    assert parser.parse_srum_natively() == 4
    assert parser.parse_gdrive_logs() == 1
    assert parser.parse_recycle_bin_natively() == 1
    assert parser.parse_registry_os_summary_natively() > 0

    conn = DuckDBManager.get_connection(case_id, read_only=False)
    ie_rows = {
        r[1]: r
        for r in conn.execute("SELECT profile, url, visit_count FROM parsed_ie_history;").fetchall()
    }
    assert ie_rows["https://portal.example.org/docs/report.pdf"] == (
        "Clara",
        "https://portal.example.org/docs/report.pdf",
        3,
    )
    assert ie_rows["https://domstore.example.org/app"] == (
        "Clara",
        "https://domstore.example.org/app",
        1,
    )

    expected_oa_dt = datetime(2024, 6, 15, 12, 0, 0)
    srum_app = conn.execute("SELECT ExeInfo, UserId, ForegroundCycleTime, Timestamp FROM raw_srum_app;").fetchone()
    assert "curl.exe" in srum_app[0] and srum_app[1] == "Alice" and srum_app[2] == 9000
    assert srum_app[3] is not None and srum_app[3].replace(tzinfo=None) == expected_oa_dt

    srum_net_rows = conn.execute("SELECT BytesSent, BytesReceived, Timestamp FROM raw_srum_net ORDER BY BytesReceived;").fetchall()
    assert len(srum_net_rows) == 2
    assert srum_net_rows[0][:2] == (512, 0)
    assert srum_net_rows[1][:2] == (4096, 16384)
    assert all(r[2] is not None and r[2].replace(tzinfo=None) == expected_oa_dt for r in srum_net_rows)

    srum_conn = conn.execute("SELECT ConnectDurationSeconds, Timestamp FROM raw_srum_conn;").fetchone()
    assert srum_conn[0] == 120 and srum_conn[1] is not None and srum_conn[1].replace(tzinfo=None) == expected_oa_dt

    gd_row = conn.execute("SELECT account, local_path, status FROM parsed_gdrive_files;").fetchone()
    assert gd_row == ("diana@corp.example", r"C:\Users\Diana\My Drive\quarterly_forecast.xlsx", "UPLOADED")

    rb_row = conn.execute("SELECT FileName, FileSize, OriginalPath FROM raw_rbcmd;").fetchone()
    assert rb_row == ("deleted_archive.zip", 1048576, orig_del)

    recmd_rows = conn.execute("SELECT KeyPath, ValueName, LastWriteTimestamp FROM raw_recmd;").fetchall()
    assert any(r[0] and "TimeZoneInformation" in r[0] and r[2] is not None for r in recmd_rows)


# =============================================================================
# Test 7: Non-Destructive `existing > 0` Guards Never Wipe EZ Tool Rows
# =============================================================================
def test_non_destructive_guards_preserve_existing_ez_tables(isolated_case: Dict[str, Any]) -> None:
    case_id = isolated_case["case_id"]
    case_dir = isolated_case["case_dir"]
    staging_dir = isolated_case["staging_dir"]
    _populate_synthetic_axiom_hives_and_files(case_dir, staging_dir)

    # Also stage `.pf`, `$MFT`, `.evtx`, and `$I` files that would trigger fallbacks if tables were empty
    (staging_dir / "CMD.EXE-12345678.pf").write_bytes(
        build_scca_prefetch("CMD.EXE", 0x12345678, 30, 2, [datetime(2024, 8, 1, tzinfo=timezone.utc)])
    )
    (staging_dir / "$MFT").write_bytes(
        build_mft_record(5, ".", 5, datetime(2024, 8, 1, tzinfo=timezone.utc), datetime(2024, 8, 1, tzinfo=timezone.utc), is_dir=True)
    )
    (staging_dir / "System.evtx").write_bytes(
        build_synthetic_evtx([{
            "record_id": 1,
            "event_id": 100,
            "level": 4,
            "system_time": "2024-08-01T00:00:00.000000Z",
            "provider": "TestProv",
        }])
    )
    orig_del = r"C:\Users\Alice\file.txt"
    (staging_dir / "$I112233.txt").write_bytes(
        struct.pack("<QQQI", 2, 100, dt_to_filetime(datetime(2024, 8, 1, tzinfo=timezone.utc)), len(orig_del) + 1)
        + orig_del.encode("utf-16le")
        + b"\x00\x00"
    )

    conn = DuckDBManager.get_connection(case_id, read_only=False)
    with DuckDBManager.get_lock(case_id):
        conn.execute("INSERT INTO raw_pecmd (ExecutableName) VALUES ('EZ_SENTINEL_PECMD.EXE');")
        conn.execute("INSERT INTO raw_mft (EntryNumber, FileName) VALUES (999, 'EZ_SENTINEL_MFT');")
        conn.execute("INSERT INTO raw_evtx (EventRecordId, Provider) VALUES (999, 'EZ_SENTINEL_EVTX');")
        conn.execute("INSERT INTO raw_rbcmd (FileName, OriginalPath) VALUES ('EZ_SENTINEL_RB', 'C:\\EZ');")
        conn.execute("INSERT INTO raw_recmd (KeyPath, ValueName, ValueData) VALUES ('EZ_KEY', 'EZ_VAL', 'EZ_SENTINEL_RECMD');")

    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    out = parser.parse()

    # Verify EZ sentinel rows remain 100% intact and un-wiped!
    assert conn.execute("SELECT ExecutableName FROM raw_pecmd;").fetchall() == [("EZ_SENTINEL_PECMD.EXE",)]
    assert conn.execute("SELECT FileName FROM raw_mft;").fetchall() == [("EZ_SENTINEL_MFT",)]
    assert conn.execute("SELECT Provider FROM raw_evtx;").fetchall() == [("EZ_SENTINEL_EVTX",)]
    assert conn.execute("SELECT FileName FROM raw_rbcmd;").fetchall() == [("EZ_SENTINEL_RB",)]
    assert conn.execute("SELECT ValueData FROM raw_recmd;").fetchall() == [("EZ_SENTINEL_RECMD",)]

    # Meanwhile, structured AXIOM tables still ran and populated!
    assert out.get("parsed_user_accounts", 0) >= 2
    assert out.get("parsed_windows_services", 0) >= 2


# =============================================================================
# Test 8: `backend/parsers/__init__.py` Exports & Anti-Cheat Source/AST Scan
# =============================================================================
def test_parsers_init_exports_and_anti_cheat_source_audit() -> None:
    assert NativeFallbackParser is nfp.NativeFallbackParser
    assert issubclass(NativeFallbackParser, BaseParser)
    assert callable(windows_filetime_to_datetime)
    assert "NativeFallbackParser" in parsers_pkg.__all__
    assert "DataCarver" in parsers_pkg.__all__

    repo_root = Path(__file__).resolve().parents[2]
    if (repo_root / "backend" / "parsers" / "data_carver.py").is_file():
        carver_cls = getattr(parsers_pkg, "DataCarver", None)
        assert carver_cls is not None

    # Anti-cheat scan over Worker B owned implementation files (`native_fallback_parsers.py` & `__init__.py`)
    forbidden_tokens = [
        "4c" + "53",
        "lexar " + "jumpdrive",
        "infor" + "mant",
        "imz" + "adi",
        "from registry import" + " registry",
        "datetime." + "now(",
    ]
    owned_impl_files = [
        repo_root / "backend" / "parsers" / "native_fallback_parsers.py",
        repo_root / "backend" / "parsers" / "__init__.py",
    ]
    for fpath in owned_impl_files:
        text = fpath.read_text(encoding="utf-8-sig")
        low = text.lower()
        for tok in forbidden_tokens:
            assert tok not in low, f"Forbidden anti-cheat / legacy token {tok!r} found in {fpath.name}"

        # Also inspect every string literal in the AST
        tree = ast.parse(text, filename=str(fpath))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s_low = node.value.lower()
                for tok in forbidden_tokens[:4]:
                    assert tok not in s_low, f"Forbidden AST string literal {node.value!r} in {fpath.name}"


# =============================================================================
# Test 9: Zero Host-Examiner Path Contamination Across `clean_hives/` & `raw_evtx`
# =============================================================================
def test_host_examiner_path_zero_leakage_across_clean_hives_and_evtx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "HostExaminerLeakCanary99"
    host_root = tmp_path / "Users" / canary / "AppData" / "Local" / "Temp"
    appdata = host_root / "wft_appdata"
    appdata.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(appdata / "custom_locations.json"))

    case_id = f"test_leak_{tmp_path.name}"
    case_dir = (host_root / "case1").resolve()
    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    register_case_dir(case_id, case_dir)
    init_case_db(case_id)
    try:
        # Populate hives + move active hives into `case_dir / "clean_hives"` (outside `staging_dir`!)
        _populate_synthetic_axiom_hives_and_files(case_dir, staging_dir)
        clean_users_alice = case_dir / "clean_hives" / "Users" / "Alice"
        clean_users_bob = case_dir / "clean_hives" / "Users" / "Bob"
        clean_sys = case_dir / "clean_hives" / "System"
        clean_vss_bob = case_dir / "clean_hives" / "VSS_1" / "Users" / "Bob"
        for d in (clean_users_alice, clean_users_bob, clean_sys, clean_vss_bob):
            d.mkdir(parents=True, exist_ok=True)

        # Copy SAM, SOFTWARE, Alice NTUSER/UsrClass, and Bob NTUSER into `clean_hives/` so priority-0 `clean_hives` is used!
        (clean_sys / "SAM").write_bytes((staging_dir / "Registry" / "System" / "SAM").read_bytes())
        (clean_sys / "SOFTWARE").write_bytes((staging_dir / "Registry" / "System" / "SOFTWARE").read_bytes())
        (clean_users_alice / "NTUSER.DAT").write_bytes((staging_dir / "Registry" / "Users" / "Alice" / "NTUSER.DAT").read_bytes())
        (clean_users_alice / "UsrClass.dat").write_bytes((staging_dir / "Registry" / "Users" / "Alice" / "UsrClass.dat").read_bytes())
        (clean_users_bob / "NTUSER.DAT").write_bytes((staging_dir / "Registry" / "Users" / "Bob" / "NTUSER.DAT").read_bytes())
        (clean_vss_bob / "NTUSER.DAT").write_bytes((staging_dir / "Registry" / "Users" / "Bob" / "NTUSER.DAT").read_bytes())
        # Also stage a flat Amcache.hve inside `clean_hives/`
        am_root = RegNodeSpec()
        am_root.ensure_path("Root").add_sz("Test", "1")
        (case_dir / "clean_hives" / "Amcache.hve").write_bytes(build_synthetic_regf(am_root))

        # Stage EVTX under `staging/Logs/Security.evtx` AND `staging/EventLogs/System.evtx`
        logs_dir = staging_dir / "Logs"
        ev_dir = staging_dir / "EventLogs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        ev_dir.mkdir(parents=True, exist_ok=True)
        sample_ev = build_synthetic_evtx([{
            "record_id": 777,
            "event_id": 4624,
            "level": 0,
            "keywords": 0x8020000000000000,
            "system_time": "2024-08-12T05:00:00.000000Z",
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "event_data": {"TargetUserName": "Alice"},
        }])
        (logs_dir / "Security.evtx").write_bytes(sample_ev)
        (ev_dir / "System.evtx").write_bytes(sample_ev)

        parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
        hives = parser._discover_hives()
        by_slot = {(h.provenance, h.hive_type, h.username): h.display_source for h in hives}
        assert by_slot[("active", "SYSTEM", None)] == r"C:\Windows\System32\config\SYSTEM"
        assert by_slot[("active", "SOFTWARE", None)] == r"C:\Windows\System32\config\SOFTWARE"
        assert by_slot[("active", "SAM", None)] == r"C:\Windows\System32\config\SAM"
        assert by_slot[("active", "AMCACHE", None)] == r"C:\Windows\appcompat\Programs\Amcache.hve"
        assert by_slot[("active", "NTUSER", "Alice")] == r"C:\Users\Alice\NTUSER.DAT"
        assert by_slot[("active", "USRCLASS", "Alice")] == r"C:\Users\Alice\AppData\Local\Microsoft\Windows\UsrClass.dat"
        assert by_slot[("VSS_1", "NTUSER", "Bob")] == r"[VSS#1] C:\Users\Bob\NTUSER.DAT"

        counts = parser.run_all(max_workers=8)
        assert counts.get("raw_evtx", 0) == 2
        assert counts.get("parsed_autoruns", 0) > 0

        conn = DuckDBManager.get_connection(case_id, read_only=False)
        ev_sources = {
            r[0] for r in conn.execute("SELECT DISTINCT SourceFile FROM raw_evtx;").fetchall()
        }
        assert r"C:\Windows\System32\winevt\Logs\Security.evtx" in ev_sources

        # Scan EVERY VARCHAR column of EVERY table in DuckDB for host path / clean_hives leakage!
        varchar_cols = conn.execute(
            """
            SELECT c.table_name, c.column_name
            FROM information_schema.columns c
            JOIN information_schema.tables t
              ON c.table_schema = t.table_schema AND c.table_name = t.table_name
            WHERE c.table_schema = 'main'
              AND t.table_type = 'BASE TABLE'
              AND UPPER(c.data_type) LIKE '%CHAR%';
            """
        ).fetchall()
        assert len(varchar_cols) > 20

        leaks: List[Tuple[str, str, str]] = []
        case_dir_low = str(case_dir).lower()
        staging_dir_low = str(staging_dir).lower()
        for tbl_name, col_name in varchar_cols:
            # Skip internal processing_logs command/detail if any, or check ALL tables including processing_logs!
            vals = conn.execute(
                f'SELECT "{col_name}" FROM "{tbl_name}" WHERE "{col_name}" IS NOT NULL;'
            ).fetchall()
            for (v,) in vals:
                s = str(v)
                s_low = s.lower()
                if (
                    canary.lower() in s_low
                    or "clean_hives" in s_low
                    or case_dir_low in s_low
                    or staging_dir_low in s_low
                ):
                    leaks.append((str(tbl_name), str(col_name), s))

        assert not leaks, f"Host path / clean_hives leaked into DuckDB VARCHAR columns: {leaks}"
    finally:
        if hasattr(DuckDBManager, "close_case"):
            DuckDBManager.close_case(case_id)
        elif hasattr(DuckDBManager, "close_connection"):
            DuckDBManager.close_connection(case_id)
        DuckDBManager.close_all()


# =============================================================================
# Test 10: Windows `[WinError 32]` Handle Hygiene (`gc.disable()`), `PyEvtxMod`
#          `<EventRecordID>` Fallback, & VSS Timestamp Candidate Isolation
# =============================================================================
def test_hive_reader_no_winerror32_pyevtx_fallback_and_vss_timestamp_isolation(
    isolated_case: Dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Corrupt & valid `_HiveReader` Windows file-handle test with `gc.disable()`
    bad_non_regf = tmp_path / "corrupt_non_regf.hive"
    bad_non_regf.write_bytes(b"BAD!" + b"\x00" * 8192)

    bad_regf_cells = tmp_path / "corrupt_regf_cells.hive"
    bad_regf_cells.write_bytes(b"regf" + b"\xff" * 8188)

    valid_hive = tmp_path / "valid_test.hive"
    spec = RegNodeSpec()
    spec.ensure_path("ControlSet001").add_dword("Test", 1)
    valid_hive.write_bytes(build_synthetic_regf(spec))

    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for corrupt_p in (bad_non_regf, bad_regf_cells):
            caught_exc: Optional[BaseException] = None
            try:
                with nfp._HiveReader(corrupt_p):
                    pass
            except Exception as exc:
                caught_exc = exc
                # Delete WHILE exception & traceback frame remain live in scope!
                os.unlink(corrupt_p)
            assert caught_exc is not None
            assert not corrupt_p.exists()

        with nfp._HiveReader(valid_hive) as reader:
            assert reader.get_key("ControlSet001") is not None
        os.unlink(valid_hive)
        assert not valid_hive.exists()
    finally:
        if was_enabled:
            gc.enable()

    # 2. Direct `PyEvtxMod` (`DissectEvtx = None`) fallback + XML `<EventRecordID>` precedence
    case_id = isolated_case["case_id"]
    staging_dir = isolated_case["staging_dir"]
    logs_dir = staging_dir / "Logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "Security.evtx").write_bytes(
        build_synthetic_evtx([
            {
                "chunk_record_num": 1,     # Chunk sequence #1 (as in filtered/exported .evtx)
                "record_id": 5251860,      # Authoritative XML `<EventRecordID>`
                "event_id": 4625,
                "level": 0,
                "keywords": 0x8010000000000000,
                "pid": 700,
                "tid": 704,
                "system_time": "2024-08-12T06:30:00.000000Z",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "event_data": {"TargetUserName": "Eve", "IpAddress": "203.0.113.55"},
            }
        ])
    )
    monkeypatch.setattr(nfp, "DissectEvtx", None)
    parser = NativeFallbackParser(case_id=case_id, staging_dir=staging_dir)
    assert parser.parse_evtx_natively(max_workers=2) == 1

    conn = DuckDBManager.get_connection(case_id, read_only=False)
    ev_row = conn.execute(
        "SELECT EventRecordId, EventId, Level, UserName, RemoteHost, SourceFile FROM raw_evtx;"
    ).fetchone()
    assert ev_row == (
        5251860,
        4625,
        "Audit Failure",
        "Eve",
        "203.0.113.55",
        r"C:\Windows\System32\winevt\Logs\Security.evtx",
    )

    # 3. VSS timestamp candidate isolation + non-vfs_files fallback (`mtime` NEVER copied into `created_utc`)
    vss_pf_dir = staging_dir / "VSS" / "VSS_1" / "Prefetch"
    vss_pf_dir.mkdir(parents=True, exist_ok=True)
    vss_pf = vss_pf_dir / "CMD.EXE-99887766.pf"
    vss_pf.write_bytes(b"SCCA_DUMMY")

    # Populate `vfs_files` ONLY with active `Prefetch/CMD.EXE-99887766.pf` -> VSS_1 must NOT steal active timestamps!
    active_dt = datetime(2024, 8, 12, 10, 0, 0)
    with DuckDBManager.get_lock(case_id):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vfs_files (
                staged_rel_path VARCHAR,
                si_created TIMESTAMP,
                si_modified TIMESTAMP,
                si_accessed TIMESTAMP
            );
            INSERT INTO vfs_files (staged_rel_path, si_created, si_modified, si_accessed)
            VALUES ('Prefetch/CMD.EXE-99887766.pf', ?, ?, ?);
            """,
            [active_dt, active_dt, active_dt],
        )

    vss_cr, vss_mod, vss_acc = parser._get_source_timestamps(vss_pf)
    assert (vss_cr, vss_mod, vss_acc) == (None, None, None)

    # Non-`vfs_files` staged file with preserved historical `os.utime`: `created_utc` stays `None` (not copied from `mtime`)
    unlisted_pf = staging_dir / "Prefetch" / "WHOAMI.EXE-11223344.pf"
    unlisted_pf.parent.mkdir(parents=True, exist_ok=True)
    unlisted_pf.write_bytes(b"SCCA_DUMMY_2")
    hist_dt = datetime(2022, 5, 10, 8, 0, 0, tzinfo=timezone.utc)
    os.utime(unlisted_pf, (hist_dt.timestamp(), hist_dt.timestamp()))
    fb_cr, fb_mod, fb_acc = parser._get_source_timestamps(unlisted_pf)
    assert fb_cr is None
    assert fb_mod == hist_dt
    assert fb_acc is None

    # 4. Zero-FP `parse_wer_reports` guard on corrupt binary & non-WER key=value `Report.wer` files
    wer_bin_dir = staging_dir / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive" / "AppCrash_Binary"
    wer_noise_dir = staging_dir / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive" / "AppCrash_Noise"
    wer_valid_dir = staging_dir / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive" / "AppCrash_Valid"
    for wd in (wer_bin_dir, wer_noise_dir, wer_valid_dir):
        wd.mkdir(parents=True, exist_ok=True)
    (wer_bin_dir / "Report.wer").write_bytes(b"\xff\xfe\x00\x00\x81\x99corrupt")
    (wer_noise_dir / "Report.wer").write_text("RandomKey=123\nOtherGarbage=xyz\n", encoding="utf-8")
    (wer_valid_dir / "Report.wer").write_bytes(
        b"\xff\xfe"
        + (
            "Version=1\r\n"
            "EventType=APPCRASH\r\n"
            "AppName=notepad.exe\r\n"
            "AppPath=C:\\Windows\\System32\\notepad.exe\r\n"
            "Sig[0].Name=Application Name\r\n"
            "Sig[0].Value=notepad.exe\r\n"
        ).encode("utf-16le")
    )
    assert parser.parse_wer_reports() == 1
    wer_rows = conn.execute("SELECT app_name, event_type, report_id FROM parsed_wer_reports;").fetchall()
    assert wer_rows == [("notepad.exe", "APPCRASH", "AppCrash_Valid")]

    # 5. `parse_gdrive_logs` idempotency + `CloudParser` thread-order determinism (`Order A` == `Order B`)
    from backend.parsers.cloud_parser import CloudParser

    gd_dir = staging_dir / "Users" / "Diana" / "AppData" / "Local" / "Google" / "Drive"
    gd_dir.mkdir(parents=True, exist_ok=True)
    (gd_dir / "sync_log.log").write_text(
        "2024-08-10 14:22:01,123 +0000 INFO pid=1234 Thread-1 account=diana@corp.example "
        "Action upload u'C:\\\\Users\\\\Diana\\\\My Drive\\\\budget_2024.xlsx'\n",
        encoding="utf-8",
    )
    assert parser.parse_gdrive_logs() == 1
    assert parser.parse_gdrive_logs() == 1  # Idempotent repeat call under lock + append=True!
    assert conn.execute("SELECT COUNT(*) FROM parsed_gdrive_files;").fetchone()[0] == 1
    gd_fb_row = conn.execute("SELECT cloud_provider, modified_time FROM parsed_gdrive_files;").fetchone()
    assert gd_fb_row == ("GoogleDrive", datetime(2024, 8, 10, 14, 22, 1, 123000))
    assert gd_fb_row[1].tzinfo is None

    # Order A (`parse_gdrive_logs` -> `CloudParser.parse()`)
    CloudParser(case_id=case_id, staging_dir=staging_dir).parse()
    count_order_a = conn.execute("SELECT COUNT(*) FROM parsed_gdrive_files;").fetchone()[0]

    # Order B (`CloudParser.parse()` -> `parse_gdrive_logs()`) on fresh table state
    with DuckDBManager.get_lock(case_id):
        conn.execute("DROP TABLE IF EXISTS parsed_gdrive_files;")
        conn.execute("DELETE FROM processing_logs WHERE module_name = 'Parser:Cloud';")
    CloudParser(case_id=case_id, staging_dir=staging_dir).parse()
    parser.parse_gdrive_logs()
    count_order_b = conn.execute("SELECT COUNT(*) FROM parsed_gdrive_files;").fetchone()[0]
    assert count_order_a == count_order_b == 1

    # Lock-window guard (`artifact_registry` `source_tool='CloudParser'` + `row_count > 0` before `processing_logs`)
    with DuckDBManager.get_lock(case_id):
        conn.execute("DELETE FROM processing_logs WHERE module_name = 'Parser:Cloud';")
    (gd_dir / "sync_log.log.1").write_text(
        "2024-08-10 10:22:01,500 -0400 INFO pid=1234 Thread-1 account=diana@corp.example "
        "Action trash u'C:\\\\Users\\\\Diana\\\\My Drive\\\\archived_old.docx'\n"
        "2024-08-10 11:00:00 +0000 INFO pid=1234 Thread-1 account=diana@corp.example "
        "Action download u'C:\\\\Users\\\\Diana\\\\My Drive\\\\pulled_spec.pdf'\n",
        encoding="utf-8",
    )
    assert parser.parse_gdrive_logs() == 1
    assert conn.execute("SELECT COUNT(*) FROM parsed_gdrive_files;").fetchone()[0] == 1

    # Standalone offset -> naive UTC + `trash` (`DELETED`) / `download` (`DOWNLOADED`) + deterministic rotated log order
    with DuckDBManager.get_lock(case_id):
        conn.execute("DROP TABLE IF EXISTS parsed_gdrive_files;")
    assert parser.parse_gdrive_logs() == 3
    rot_rows = {
        r[0]: (r[1], r[2])
        for r in conn.execute("SELECT cloud_path_or_id, status, modified_time FROM parsed_gdrive_files;").fetchall()
    }
    assert rot_rows["archived_old.docx"] == ("DELETED", datetime(2024, 8, 10, 14, 22, 1, 500000))
    assert rot_rows["pulled_spec.pdf"] == ("DOWNLOADED", datetime(2024, 8, 10, 11, 0, 0))
    assert all(ts.tzinfo is None for _, ts in rot_rows.values())

