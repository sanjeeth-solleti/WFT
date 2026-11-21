"""
Windows Forensic Toolkit (WFT) DFIR Suite - Open-Source bulk_extractor Multi-Threaded Runner
Executes bulk_extractor64.exe (-0 -q -Z -j <workers>) against disk images or directory trees,
applies strict Requirement R3 zero-false-positive context & structural validation across
two-pass feature and histogram outputs, and batch-ingests into DuckDB under per-case lock.
"""
import os
import re
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import backend.config as config
from backend.config import BASE_DIR, get_case_dir, register_case_dir
from backend.db.engine import DuckDBManager

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

DISK_IMAGE_EXTENSIONS: Set[str] = {
    ".e01",
    ".ex01",
    ".ewf",
    ".s01",
    ".dd",
    ".raw",
    ".img",
    ".001",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".iso",
    ".aff",
    ".aff4",
    ".bin",
}

CARVE_MODE_NAMES: Tuple[str, ...] = (
    "evtx_carved_carve_mode",
    "jpeg_carve_mode",
    "kml_carved_carve_mode",
    "ntfsindx_carved_carve_mode",
    "ntfslogfile_carved_carve_mode",
    "ntfsmft_carved_carve_mode",
    "ntfsusn_carved_carve_mode",
    "rar_carve_mode",
    "rtti_carve_mode",
    "sqlite_carved_carve_mode",
    "unrar_carved_carve_mode",
    "utmp_carved_carve_mode",
    "vcard_carve_mode",
    "winpe_carved_carve_mode",
    "zip_carved_carve_mode",
)

CARVING_FLAGS: List[str] = [
    "-S",
    "jpeg_carve_mode=2",
    "-S",
    "zip_carved_carve_mode=2",
    "-S",
    "rar_carve_mode=2",
    "-S",
    "unrar_carved_carve_mode=2",
    "-S",
    "sqlite_carved_carve_mode=2",
]

DISABLE_CARVING_FLAGS: List[str] = [
    flag
    for _mode_name in CARVE_MODE_NAMES
    for flag in ("-S", f"{_mode_name}=0")
]

EXCLUDED_TXT_FILES: Set[str] = {
    "duplicates.txt",
    "alerts.txt",
    "rtti.txt",
    "aes_keys.txt",
}

_BOGUS_FILE_TLDS: Set[str] = {
    "dll", "exe", "sys", "drv", "ocx", "cpl", "mui", "nls", "tlb", "pdb",
    "obj", "lib", "exp", "manifest", "config", "json", "xml", "yaml", "yml",
    "ini", "inf", "cat", "txt", "csv", "log", "evtx", "etl", "pf", "lnk",
    "dat", "hve", "reg", "db", "sqlite", "sqlite3", "mdb", "pst", "ost",
    "eml", "msg", "jpg", "jpeg", "png", "gif", "bmp", "ico", "webp", "svg",
    "mp3", "mp4", "wav", "avi", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
    "pptx", "zip", "rar", "7z", "tar", "gz", "tmp", "bak", "old", "bin",
    "raw", "dd", "e01", "vhd", "vhdx", "vmdk", "ps1", "bat", "cmd", "vbs",
    "js", "ts", "tsx", "jsx", "css", "scss", "html", "htm", "php", "asp",
    "aspx", "jsp", "py", "pyc", "rb", "pl", "cpp", "hpp", "cs", "class",
    "jar", "war", "cab", "msi", "msp", "wim", "esd", "iso", "ttf", "otf",
    "woff", "woff2", "eot", "cur", "ani", "chm", "hlp", "scr", "dmp", "hdmp",
}

_OCTAL_OR_HEX_RE = re.compile(r"\\([0-3][0-7]{2}|[0-7]{1,2})|\\x([0-9A-Fa-f]{2})")

_PE_VERSION_CTX_RE = re.compile(
    r"(?i)(?:fileversion|productversion|assemblyversion|vs_version_info|"
    r"stringfileinfo|varfileinfo|publickeytoken|processorarchitecture|"
    r"manifestversion|\.dll\x00|\.exe\x00|\.sys\x00|MZ\x90\x00|version\s*=)"
)

_OID_CTX_RE = re.compile(
    r"(?:1\.3\.6\.1\.|2\.5\.(?:4|6|8|29)\.|2\.16\.840\.|1\.2\.840\.|"
    r"1\.3\.14\.|1\.3\.132\.|2\.23\.140\.|\x00\d{1,2}\.\d{1,3}\.\d{1,5}\.)"
)

_CARD_CTX_RE = re.compile(
    r"(?i)\b(?:card|ccn|amex|american\s*express|visa|mastercard|discover|"
    r"diners|jcb|exp(?:ir[ey]|ires)?|cvv|cvc|pan|acct|account|payment|"
    r"billing|credit|debit|holder)\b"
)

_NETWORK_HEADING_ALLOWLIST: Set[str] = {
    "allow", "allowed", "deny", "denied", "drop", "dropped", "reject", "rejected",
    "accept", "accepted", "connect", "connected", "connection", "disconnect",
    "gateway", "router", "server", "client", "host", "source", "destination",
    "dest", "port", "online", "offline", "active", "listen", "listening",
    "tcp", "udp", "icmp", "http", "https", "ssh", "dns", "tls", "ssl",
}

_VALID_LEFT_DELIM_BYTES: Set[int] = set(b" \t\r\n\x0b\x0c\x00\"'`<[{(:;,=/|+\\\x07\x13\x14")
_VALID_RIGHT_DELIM_BYTES: Set[int] = set(b" \t\r\n\x0b\x0c\x00\"'`>]});,:.?&/|\\\x07\x13\x15")

_IPV4_EXACT_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)

_RETINA_ASSET_RE = re.compile(r"(?i)^@\d+x\.(?:png|jpg|jpeg|gif|webp|svg|bmp|ico|avif|tiff)$")

_VALID_URL_SCHEMES = (
    "http://",
    "https://",
    "ftp://",
    "ftps://",
    "file://",
    "smb://",
    "ws://",
    "wss://",
    "mailto:",
)


def _bind_case_dir_if_needed(case_id: str, case_dir: Path, db_manager: Any = None) -> None:
    """Ensure get_case_dir(case_id) resolves to case_dir without closing an already-matching connection."""
    resolved_dir = Path(case_dir).resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)
    if db_manager is None or db_manager is DuckDBManager:
        if get_case_dir(case_id).resolve() != resolved_dir:
            register_case_dir(case_id, resolved_dir)


def _ensure_core_audit_tables(cursor: Any) -> None:
    """Guarantee processing_logs + artifact_registry exist even without prior init_case_db()."""
    cursor.execute("CREATE SEQUENCE IF NOT EXISTS seq_log_id START 1;")
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS processing_logs (
            log_id BIGINT,
            timestamp_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            module_name VARCHAR,
            command_executed VARCHAR,
            exit_code INTEGER,
            rows_ingested BIGINT,
            duration_ms BIGINT,
            status VARCHAR,
            error_message VARCHAR
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS artifact_registry (
            artifact_id VARCHAR PRIMARY KEY,
            category VARCHAR NOT NULL,
            display_name VARCHAR NOT NULL,
            table_name VARCHAR NOT NULL,
            source_tool VARCHAR NOT NULL,
            row_count BIGINT DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


def _ensure_be_tables(cursor: Any, reset: bool = True) -> None:
    """Create or upgrade Bulk Extractor tables and optionally clear stale rows."""
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS parsed_bulk_extractor_features (
            _row_id BIGINT,
            scanner VARCHAR,
            offset_str VARCHAR,
            feature VARCHAR,
            context VARCHAR,
            source_file VARCHAR
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS parsed_bulk_extractor_histograms (
            _row_id BIGINT,
            scanner VARCHAR,
            count BIGINT,
            feature VARCHAR,
            source_file VARCHAR
        );
        """
    )
    cursor.execute("ALTER TABLE parsed_bulk_extractor_features ADD COLUMN IF NOT EXISTS _row_id BIGINT;")
    cursor.execute("ALTER TABLE parsed_bulk_extractor_histograms ADD COLUMN IF NOT EXISTS _row_id BIGINT;")
    if reset:
        cursor.execute("DELETE FROM parsed_bulk_extractor_features;")
        cursor.execute("DELETE FROM parsed_bulk_extractor_histograms;")


def _is_valid_pe_or_elf_binary(path: Optional[Path]) -> bool:
    try:
        if path is None or not path.is_file():
            return False
        norm_low = str(path.resolve()).lower()
        if "\\microsoft\\windowsapps\\" in norm_low:
            return False
        st = path.stat()
        if st.st_size < 64:
            return False
        if os.name == "nt" and path.suffix.lower() == ".exe":
            with open(path, "rb") as f:
                return f.read(2) == b"MZ"
        return True
    except OSError:
        return False


def _unescape_be_bytes(escaped: str) -> bytes:
    """Decode bulk_extractor 3-digit octal (\\000) and hex (\\x00) byte escapes."""
    out = bytearray()
    i = 0
    n = len(escaped)
    while i < n:
        if escaped[i] == "\\" and i + 1 < n:
            m = _OCTAL_OR_HEX_RE.match(escaped, i)
            if m:
                val = int(m.group(1), 8) if m.group(1) is not None else int(m.group(2), 16)
                out.append(val & 0xFF)
                i = m.end()
                continue
        ch = ord(escaped[i])
        out.append(ch if ch < 256 else ord("?"))
        i += 1
    return bytes(out)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 11, 12, 13))
    return printable / len(data)


def _utf8_segment_noise_counts(seg: bytes) -> Tuple[int, int]:
    """
    Count (noisy_units, total_units) over raw flanking bytes while treating valid
    printable UTF-8 multi-byte characters and standard ASCII whitespace (TAB/LF/VT/FF/CR) as clean.
    """
    if not seg:
        return (0, 0)
    noisy = 0
    total = 0
    i = 0
    n = len(seg)
    while i < n:
        b = seg[i]
        if 32 <= b <= 126 or b in (9, 10, 11, 12, 13):
            total += 1
            i += 1
            continue
        if b < 32 or b == 127:
            noisy += 1
            total += 1
            i += 1
            continue
        # Attempt valid UTF-8 multi-byte decode (2..4 bytes)
        seq_len = 2 if (0xC2 <= b <= 0xDF) else (3 if (0xE0 <= b <= 0xEF) else (4 if (0xF0 <= b <= 0xF4) else 0))
        if seq_len and i + seq_len <= n:
            try:
                ch = seg[i : i + seq_len].decode("utf-8", errors="strict")
                if ch.isprintable() or ch in ("\t", "\n", "\x0b", "\x0c", "\r"):
                    total += 1
                else:
                    noisy += 1
                    total += 1
                i += seq_len
                continue
            except UnicodeDecodeError:
                pass
        noisy += 1
        total += 1
        i += 1
    return (noisy, total)


def _trim_benign_nul_padding(left_raw: bytes, right_raw: bytes, feat_len: int = 0) -> Tuple[bytes, bytes]:
    """
    Strip legitimate C-string / OLE VT_LPSTR / MS-DOC field / struct zero-padding ONLY when
    structural framing confirms a genuine string boundary, keeping random binary/PE noise intact.
    """
    l_out = left_raw
    r_out = right_raw

    # 1. [MS-OLEPS] length-prefixed CodePageString (uint32 length [feat_len..feat_len+8] + trailing NUL)
    if feat_len >= 4 and len(l_out) >= 4 and r_out.startswith(b"\x00"):
        u32_len = int.from_bytes(l_out[-4:], "little", signed=False)
        if feat_len <= u32_len <= feat_len + 8:
            return (b"", b"")

    # 2. [MS-DOC] HYPERLINK / field-code framing (\x13 HYPERLINK ... \x14display\x15)
    if (b"HYPERLINK" in l_out or b"HYPERLINK" in r_out or (l_out.endswith(b"\x14") and r_out.startswith(b"\x15"))):
        l_out = bytes(b for b in l_out if b not in (0x01, 0x07, 0x13, 0x14, 0x15))
        r_out = bytes(b for b in r_out if b not in (0x01, 0x07, 0x13, 0x14, 0x15))

    # 3. Clean printable prefix followed by C-string NUL termination (\x00...) -> ignore post-NUL struct bytes
    if r_out.startswith(b"\x00"):
        l_core = l_out.lstrip(b"\x00")
        if len(l_core) >= 6 and _printable_ratio(l_core) >= 0.90:
            r_out = b""
        else:
            after_nuls = r_out.lstrip(b"\x00")
            if not after_nuls:
                if not l_core or _printable_ratio(l_core) >= 0.80:
                    r_out = b""
            else:
                r_core = after_nuls.replace(b"\x00", b"")
                if len(r_core) >= 2 and _printable_ratio(r_core) >= 0.85:
                    r_out = r_core

    if l_out.endswith(b"\x00"):
        before_nuls = l_out.rstrip(b"\x00")
        if not before_nuls:
            r_core = r_out.rstrip(b"\x00")
            if not r_core or _printable_ratio(r_core) >= 0.80:
                l_out = b""
        else:
            l_core = before_nuls.replace(b"\x00", b"")
            if len(l_core) >= 2 and _printable_ratio(l_core) >= 0.85:
                l_out = l_core
    elif l_out.startswith(b"\x00"):
        inner_left = l_out.lstrip(b"\x00")
        if len(inner_left) >= 3 and _printable_ratio(inner_left) >= 0.85:
            l_out = inner_left

    return (l_out, r_out)


def _decode_utf16_flank_units(raw_flank: bytes, little_endian: bool = True) -> bytes:
    """Convert aligned 2-byte UTF-16 code units into 1-byte diagnostic stream (ignoring BOMs)."""
    out = bytearray()
    for idx in range(0, len(raw_flank) - 1, 2):
        b0, b1 = raw_flank[idx], raw_flank[idx + 1]
        lo, hi = (b0, b1) if little_endian else (b1, b0)
        if (lo, hi) in ((0xFF, 0xFE), (0xFE, 0xFF)):
            continue
        if lo == 0 and hi == 0:
            out.append(0)
        elif hi == 0:
            out.append(lo)
        else:
            try:
                ch = bytes([b0, b1]).decode("utf-16-le" if little_endian else "utf-16-be")
                out.append(ord(" ") if ch.isprintable() else 0xFF)
            except UnicodeDecodeError:
                out.append(0xFF)
    return bytes(out)


def _analyze_feature_context(context: str, feature: str = "") -> Tuple[str, float, Optional[int], Optional[int]]:
    """
    Decode bulk_extractor context and measure binary noise strictly on the surrounding
    flanking bytes outside the matched `feature` substring (preventing long ASCII features
    from diluting surrounding compressed/binary noise while preserving UTF-16LE/BE with or
    without BOM and NUL-padded OLE/C-strings).

    Returns (clean_text, flanking_noise_ratio, immediate_left_byte, immediate_right_byte).
    """
    if not context:
        return ("", 0.0, None, None)
    raw_ctx = _unescape_be_bytes(context)
    if not raw_ctx:
        return ("", 0.0, None, None)

    feat_clean = feature.strip()

    # 1. Exact UTF-16LE / UTF-16BE substring match (handles odd window offsets & BOMs cleanly)
    if len(feat_clean) >= 3:
        for is_le, enc_name in ((True, "utf-16-le"), (False, "utf-16-be")):
            feat_u16 = feat_clean.encode(enc_name, errors="ignore")
            if feat_u16:
                pos_u16 = raw_ctx.lower().find(feat_u16.lower())
                if pos_u16 >= 0:
                    raw_before = raw_ctx[:pos_u16]
                    raw_after = raw_ctx[pos_u16 + len(feat_u16) :]
                    if len(raw_before) % 2 == 1:
                        raw_before = raw_before[1:]
                    if len(raw_after) % 2 == 1:
                        raw_after = raw_after[:-1]
                    left_dec = _decode_utf16_flank_units(raw_before, little_endian=is_le)
                    right_dec = _decode_utf16_flank_units(raw_after, little_endian=is_le)
                    # UTF-16 length-prefixed / NUL-terminated WCHAR strings (VT_LPWSTR / BSTR / OLE moniker)
                    if is_le and len(raw_before) >= 4 and raw_after.startswith(b"\x00\x00"):
                        u32_chars = int.from_bytes(raw_before[-4:], "little", signed=False)
                        if len(feat_clean) <= u32_chars <= (len(feat_clean) * 2 + 6):
                            left_dec = b""
                            right_dec = b""
                    imm_left = left_dec[-1] if left_dec else None
                    imm_right = right_dec[0] if right_dec else None
                    l_trim, r_trim = _trim_benign_nul_padding(left_dec, right_dec, len(feat_clean))
                    ln, lt = _utf8_segment_noise_counts(l_trim)
                    rn, rt = _utf8_segment_noise_counts(r_trim)
                    flank_noise = ((ln + rn) / (lt + rt)) if (lt + rt) > 0 else 0.0
                    no_bom = raw_ctx.replace(b"\xff\xfe", b"").replace(b"\xfe\xff", b"")
                    stripped = bytes(b for b in no_bom if b != 0)
                    return (stripped.decode("latin-1"), flank_noise, imm_left, imm_right)

    # 2. General UTF-16LE / UTF-16BE window fallback (when BE normalized feature text)
    if len(raw_ctx) >= 6:
        no_bom = raw_ctx.replace(b"\xff\xfe", b"").replace(b"\xfe\xff", b"")
        even_bytes = no_bom[0::2]
        odd_bytes = no_bom[1::2]
        if (
            (odd_bytes and (odd_bytes.count(0) / len(odd_bytes) >= 0.68) and _printable_ratio(even_bytes) >= 0.75)
            or (even_bytes and (even_bytes.count(0) / len(even_bytes) >= 0.68) and _printable_ratio(odd_bytes) >= 0.75)
        ):
            decoded_u16 = bytes(b for b in no_bom if b != 0)
            clean_text = decoded_u16.decode("latin-1")
            feat_b = feat_clean.encode("latin-1", errors="ignore")
            pos = decoded_u16.lower().find(feat_b.lower()) if feat_b else -1
            if pos >= 0 and feat_b:
                l_b = decoded_u16[:pos]
                r_b = decoded_u16[pos + len(feat_b) :]
            else:
                l_b, r_b = decoded_u16, b""
            imm_left = l_b[-1] if l_b else None
            imm_right = r_b[0] if r_b else None
            ln, lt = _utf8_segment_noise_counts(l_b)
            rn, rt = _utf8_segment_noise_counts(r_b)
            flank_noise = ((ln + rn) / (lt + rt)) if (lt + rt) > 0 else 0.0
            return (clean_text, flank_noise, imm_left, imm_right)

    # 3. Standard ASCII / UTF-8 / binary byte window
    clean_text = raw_ctx.decode("latin-1")
    feat_bytes = feat_clean.encode("latin-1", errors="ignore")
    pos = raw_ctx.lower().find(feat_bytes.lower()) if feat_bytes else -1
    if pos >= 0 and feat_bytes:
        left_raw = raw_ctx[:pos]
        right_raw = raw_ctx[pos + len(feat_bytes) :]
    else:
        left_raw = raw_ctx
        right_raw = b""

    imm_left = left_raw[-1] if left_raw else None
    imm_right = right_raw[0] if right_raw else None

    l_trim, r_trim = _trim_benign_nul_padding(left_raw, right_raw, len(feat_bytes))
    ln, lt = _utf8_segment_noise_counts(l_trim)
    rn, rt = _utf8_segment_noise_counts(r_trim)
    flank_noise = ((ln + rn) / (lt + rt)) if (lt + rt) > 0 else 0.0
    return (clean_text, flank_noise, imm_left, imm_right)


def _has_noisy_token_boundary(
    flank_noise: float,
    imm_left: Optional[int],
    imm_right: Optional[int],
) -> bool:
    """
    Detect random compressed/binary coincidences where surrounding context has binary noise
    AND the matched token is immediately flanked by non-delimiter garbage bytes.
    """
    if flank_noise <= 0.0:
        return False
    if imm_left is not None and imm_left not in _VALID_LEFT_DELIM_BYTES:
        return True
    if imm_right is not None and imm_right not in _VALID_RIGHT_DELIM_BYTES:
        return True
    return False


def _inspect_be_context(context: str, feature: str = "") -> Tuple[str, float]:
    """
    Decode bulk_extractor context into (clean_text, flanking_binary_noise_ratio),
    preserving genuine Windows UTF-16LE/BE text and NUL-padded strings.
    """
    clean_text, flank_noise, _l, _r = _analyze_feature_context(context, feature)
    return (clean_text, flank_noise)


def _luhn_valid(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        d = ord(ch) - 48
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (total % 10) == 0


def _is_dms_station_id_15(digits: str) -> bool:
    """Check if a bare 15-digit string matches geographic DMS station ID bounds (DDMMSSDDDMMSSNN)."""
    if len(digits) != 15 or not digits.isdigit():
        return False
    lat_deg = int(digits[0:2])
    lat_min = int(digits[2:4])
    lat_sec = int(digits[4:6])
    lon_deg = int(digits[6:9])
    lon_min = int(digits[9:11])
    lon_sec = int(digits[11:13])
    return (
        0 <= lat_deg <= 90
        and 0 <= lat_min <= 59
        and 0 <= lat_sec <= 59
        and 0 <= lon_deg <= 180
        and 0 <= lon_min <= 59
        and 0 <= lon_sec <= 59
    )


def _is_valid_ipv4(feat: str, clean_ctx: str, noise_ratio: float, has_context: bool) -> bool:
    m = _IPV4_EXACT_RE.match(feat)
    if not m:
        return False
    parts = m.groups()
    octets: List[int] = []
    for p in parts:
        if len(p) > 1 and p.startswith("0"):
            return False
        val = int(p)
        if val < 0 or val > 255:
            return False
        octets.append(val)

    # Reject 0.0.0.0/8, 127.0.0.0/8 loopback, and 224.0.0.0/4+ multicast/reserved/broadcast/netmasks
    if octets[0] == 0 or octets[0] == 127 or octets[0] >= 224:
        return False
    if octets == [255, 255, 255, 255]:
        return False

    # Reject 4-arc ISO/ITU-T X.500/X.509 certificate & directory OIDs (2.5.4.*, 2.5.6.*, 2.5.8.*, 2.5.29.*)
    if octets[0] == 2 and octets[1] == 5 and octets[2] in (4, 6, 8, 29):
        return False

    if has_context and clean_ctx:
        if _PE_VERSION_CTX_RE.search(clean_ctx):
            return False
        if _OID_CTX_RE.search(clean_ctx):
            return False
        if noise_ratio > 0.28:
            return False

        esc = re.escape(feat)
        # 1. Reject alphanumeric/underscore adjacency (e.g. Objects2.5.29.14Subje, v10.0.19041.1) or 5+ arc OIDs
        if re.search(rf"(?:[A-Za-z0-9_]{esc}|{esc}[A-Za-z0-9_]|\d\.{esc}|{esc}\.\d)", clean_ctx):
            return False

        # 2. Reject slash-prefixed product / User-Agent versions (e.g. Chrome/120.0.100.12, Apache/2.4.58.0)
        if re.search(rf"(?<![:/])[A-Za-z][A-Za-z0-9_.\-]*/{esc}(?!:\d{{1,5}}\b)", clean_ctx):
            return False

        # 3. Reject prose version / build / section labels
        if re.search(
            rf"(?i)\b(?:release|version|ver\.?|build|rev(?:ision)?|patch|firmware|sdk|runtime|"
            rf"section|sec\.?|chapter|chap\.?|clause|para(?:graph)?|appendix|table|fig(?:ure)?)\s*[:=#.]?\s*{esc}",
            clean_ctx,
        ):
            return False
        if re.search(rf"(?i){esc}\s+(?:release|version|build)\b", clean_ctx):
            return False

        # 4. Reject numbered document section/outline headings & paragraph cross-reference lists
        if all(1 <= o <= 50 for o in octets) and octets[0] <= 32:
            m_head = re.search(
                rf"(?:^|[\r\n\t\x00\x0b\x0c>])[ \t]*{esc}\.?(?:[ \t]+|\x00+|\r?\n)(?:\([A-Za-z0-9]+\)[ \t]*)?([A-Z][A-Za-z]{{1,}}|\([A-Za-z0-9]+\))",
                clean_ctx,
            )
            if m_head:
                heading_tok = m_head.group(1).strip().lower()
                if heading_tok not in _NETWORK_HEADING_ALLOWLIST:
                    return False
            # OOXML / HTML tag-enclosed outline number (even when opening tag started before BE's 16-byte window)
            if re.search(rf"(?:>[ \t]*{esc}\.?[ \t]*</(?:w:)?[A-Za-z0-9_]+|<w:t[^>]*>[ \t]*{esc})", clean_ctx):
                return False
            # Comma/semicolon/newline cross-reference list alongside 2-part or 3-part section numbers
            if re.search(
                rf"(?:(?<!\d\.)\b\d{{1,2}}\.\d{{1,2}}(?:\.\d{{1,2}})?[ \t]*(?:,|;|and|or|\r?\n)[ \t]*{esc}|"
                rf"{esc}[ \t]*(?:,|;|and|or|\r?\n)[ \t]*\d{{1,2}}\.\d{{1,2}}(?:\.\d{{1,2}})?(?!\.\d))",
                clean_ctx,
            ):
                return False
            # Sequential sibling outline numbers sharing chapter prefix (e.g. "2.1.4.1, 2.1.4.2")
            if octets[0] <= 15 and all(1 <= o <= 30 for o in octets):
                if re.search(
                    rf"(?:\b{octets[0]}\.\d{{1,2}}\.\d{{1,2}}\.\d{{1,2}}\s*,\s*{esc}|"
                    rf"{esc}\s*,\s*{octets[0]}\.\d{{1,2}}\.\d{{1,2}}\.\d{{1,2}}\b)",
                    clean_ctx,
                ):
                    return False

    return True


def _is_valid_domain_name(host: str) -> bool:
    clean_host = host.strip().rstrip(".")
    if len(clean_host) < 4 or len(clean_host) > 253:
        return False
    if not _HOSTNAME_RE.match(clean_host):
        return False
    tld = clean_host.rsplit(".", 1)[-1].lower()
    if tld in _BOGUS_FILE_TLDS:
        return False
    if not ((2 <= len(tld) <= 24 and tld.isalpha()) or (tld.startswith("xn--") and len(tld) >= 6)):
        return False
    return True


def _is_valid_feature(scanner: str, feature: str, context: str, has_context: bool = True) -> bool:
    """Requirement R3 zero-false-positive validator across Bulk Extractor scanners."""
    feat = feature.strip()
    if not feat or len(feat) > 4096:
        return False

    sc = scanner.lower().strip()
    if has_context and context:
        clean_ctx, noise_ratio, imm_left, imm_right = _analyze_feature_context(context, feat)
    else:
        clean_ctx, noise_ratio, imm_left, imm_right = ("", 0.0, None, None)

    if sc == "ip":
        if has_context and context and _has_noisy_token_boundary(noise_ratio, imm_left, imm_right):
            return False
        return _is_valid_ipv4(feat, clean_ctx, noise_ratio, has_context)

    if sc in ("domain", "email_domain"):
        check_val = feat[1:] if (sc == "email_domain" and feat.startswith("@")) else feat
        if re.match(r"^\d+(?:\.\d+){3}$", check_val):
            if has_context and context and _has_noisy_token_boundary(noise_ratio, imm_left, imm_right):
                return False
            return _is_valid_ipv4(check_val, clean_ctx, noise_ratio, has_context)
        if has_context and clean_ctx:
            if (
                noise_ratio > 0.18
                or _has_noisy_token_boundary(noise_ratio, imm_left, imm_right)
                or _PE_VERSION_CTX_RE.search(clean_ctx)
            ):
                return False
        return _is_valid_domain_name(check_val)

    if sc == "email":
        if any(ord(c) < 33 or ord(c) > 126 for c in feat):
            return False
        if feat.count("@") != 1:
            return False
        local, dom = feat.split("@", 1)
        if not (1 <= len(local) <= 64) or local.startswith(".") or local.endswith(".") or ".." in local:
            return False
        if _RETINA_ASSET_RE.match("@" + dom):
            return False
        if has_context and (
            noise_ratio > 0.18
            or _has_noisy_token_boundary(noise_ratio, imm_left, imm_right)
            or (clean_ctx and _PE_VERSION_CTX_RE.search(clean_ctx))
        ):
            return False
        if re.match(r"^\d+(?:\.\d+){3}$", dom):
            return _is_valid_ipv4(dom, clean_ctx, noise_ratio, has_context)
        return _is_valid_domain_name(dom)

    if sc == "telephone":
        if has_context and (noise_ratio > 0.22 or (clean_ctx and _PE_VERSION_CTX_RE.search(clean_ctx))):
            return False
        digits = re.sub(r"\D", "", feat)
        if not (7 <= len(digits) <= 15):
            return False
        if len(set(digits)) < 3:
            return False
        if digits in ("0123456789", "1234567890", "9876543210", "0987654321"):
            return False
        return True

    if sc in ("ccn", "ccn_track2"):
        if has_context and (noise_ratio > 0.20 or (clean_ctx and _PE_VERSION_CTX_RE.search(clean_ctx))):
            return False
        digits = re.sub(r"\D", "", feat.split("=")[0].split("^")[0])
        if not (13 <= len(digits) <= 19):
            return False
        if len(set(digits)) < 3:
            return False
        if not _luhn_valid(digits):
            return False
        if sc == "ccn" and feat.isdigit() and len(digits) == 15 and has_context and clean_ctx:
            has_card_ctx = bool(_CARD_CTX_RE.search(clean_ctx))
            if not has_card_ctx:
                esc_f = re.escape(feat)
                if re.search(rf"<(?:[A-Za-z0-9_]+:)?(?:t|v|c|f|is|si)(?:\s[^>]*)?>\s*{esc_f}\s*</", clean_ctx):
                    return False
                if _is_dms_station_id_15(digits) and any(ch in clean_ctx for ch in ("<", ">", "\t", ",")):
                    return False
        return True

    if sc == "url_services":
        if any(ord(c) < 32 or ord(c) == 127 for c in feat):
            return False
        if not (feat.startswith("://") or feat.lower().startswith(_VALID_URL_SCHEMES)):
            return False
        rest = feat.split("://", 1)[1] if "://" in feat else ""
        host_port = re.split(r"[/\?#]", rest, maxsplit=1)[0]
        if "@" in host_port:
            host_port = host_port.rsplit("@", 1)[-1]
        host = host_port.split(":", 1)[0].strip("[]")
        if not host:
            return False
        if re.match(r"^\d+(?:\.\d+){3}$", host):
            return _is_valid_ipv4(host, clean_ctx, noise_ratio, has_context=False)
        if host.lower() == "localhost":
            return True
        return _is_valid_domain_name(host)

    if sc == "url" or sc.startswith("url_"):
        if any(ord(c) < 32 or ord(c) == 127 for c in feat):
            return False
        low_f = feat.lower()
        if sc == "url":
            if not low_f.startswith(_VALID_URL_SCHEMES):
                return False
        elif not low_f.startswith(_VALID_URL_SCHEMES):
            # Sub-histograms like url_searches may hold search terms; require clean printable text
            return not (has_context and noise_ratio > 0.45)

        if low_f.startswith(("http://", "https://", "ftp://", "ftps://", "ws://", "wss://")):
            after_scheme = feat.split("://", 1)[1]
            host_port = re.split(r"[/\?#]", after_scheme, maxsplit=1)[0]
            if "@" in host_port:
                host_port = host_port.rsplit("@", 1)[-1]
            host = host_port.split(":", 1)[0].strip("[]")
            if not host:
                return False
            if re.match(r"^\d+(?:\.\d+){3}$", host):
                return _is_valid_ipv4(host, clean_ctx, noise_ratio, has_context)
            if host.lower() != "localhost" and not _is_valid_domain_name(host):
                return False
        if has_context and noise_ratio > 0.50:
            return False
        return True

    # General feature scanners (find, exif, gps, winpe, winlnk, winprefetch, httplogs, json, etc.)
    if any(ord(c) < 9 or (14 <= ord(c) < 32) for c in feat):
        return False
    return True


def _canonical_verdict_family(scanner: str) -> str:
    sc = scanner.lower().strip()
    if sc in ("email_domain", "domain"):
        return "domain"
    if sc.startswith("url"):
        return "url"
    if sc.startswith("ccn"):
        return "ccn"
    return sc


def _normalize_verdict_keys(family: str, feat_val: str) -> Set[str]:
    """
    Produce canonical lookup keys so Pass 1 feature verdicts and Pass 2 normalized
    histogram entries (e.g. '415-555-8877' <-> '4155558877' <-> '+1-415-555-8877',
    '@example.org' <-> 'example.org') match across formatting differences.
    """
    low = feat_val.strip().lower()
    keys: Set[str] = {low} if low else set()
    if family == "telephone":
        digits = re.sub(r"\D", "", feat_val)
        if digits:
            keys.add(digits)
            if len(digits) == 11 and digits.startswith("1"):
                keys.add(digits[1:])
            elif len(digits) == 10:
                keys.add("1" + digits)
    elif family == "ccn":
        digits = re.sub(r"\D", "", feat_val.split("=")[0].split("^")[0])
        if digits:
            keys.add(digits)
    elif family == "domain":
        trimmed = low.rstrip(".")
        bare = trimmed[1:] if trimmed.startswith("@") else trimmed
        if bare:
            keys.add(bare)
            keys.add("@" + bare)
    return keys


class BulkExtractorRunner:
    """
    Multi-threaded runner for open-source bulk_extractor (v2.2.0+).
    Populates parsed_bulk_extractor_features and parsed_bulk_extractor_histograms.
    """

    def __init__(
        self,
        case_id: str,
        case_dir: Union[str, Path],
        db_manager: Any = None,
        log_fn: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.case_id = str(case_id).strip()
        self.case_dir = Path(case_dir).resolve()
        self.db_manager = db_manager if db_manager is not None else DuckDBManager
        _bind_case_dir_if_needed(self.case_id, self.case_dir, db_manager=db_manager)
        self.out_dir = (self.case_dir / "bulk_extractor_out").resolve()
        self.log_file = (self.case_dir / "processing.log").resolve()
        self.log_fn = log_fn or self._default_log
        self._file_log_lock = threading.Lock()

    def _default_log(self, msg: str, level: str = "INFO") -> None:
        print(f"[{level}] [BulkExtractorRunner] {msg}")

    def resolve_bulk_extractor_binary(self) -> Optional[Path]:
        """
        Resolve bulk_extractor binary via config.find_bulk_extractor_binary() primary contract,
        respecting None return values when monkeypatched in unit tests.
        """
        finder = getattr(config, "find_bulk_extractor_binary", None)
        if callable(finder):
            cand = finder()
            if cand is not None and _is_valid_pe_or_elf_binary(Path(cand)):
                return Path(cand).resolve()
            return None

        # Local fallback ONLY if config.find_bulk_extractor_binary does not exist
        raw_env = (os.environ.get("WFT_BULK_EXTRACTOR_EXE") or "").strip().strip('"').strip("'")
        candidates: List[Path] = []
        if raw_env:
            candidates.append(Path(raw_env))
        candidates.extend(
            [
                BASE_DIR / "tools" / "bulk_extractor" / "bulk_extractor64.exe",
                BASE_DIR / "tools" / "bulk_extractor" / "bulk_extractor.exe",
                BASE_DIR / "tools" / "bulk_extractor64.exe",
                BASE_DIR / "tools" / "bulk_extractor.exe",
            ]
        )
        for c in candidates:
            if _is_valid_pe_or_elf_binary(c):
                return c.resolve()

        which_hit = shutil.which("bulk_extractor64.exe") or shutil.which("bulk_extractor.exe") or shutil.which("bulk_extractor")
        if which_hit and _is_valid_pe_or_elf_binary(Path(which_hit)):
            return Path(which_hit).resolve()

        return None

    @staticmethod
    def _is_histogram_file(txt_path: Path) -> bool:
        fname_low = txt_path.name.lower()
        if fname_low.endswith("_histogram.txt") or re.search(r"_histogram_\d+\.txt$", fname_low):
            return True
        if fname_low == "url_services.txt":
            return True
        try:
            with open(txt_path, "r", encoding="utf-8-sig", errors="replace") as f:
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    if not line.startswith("#"):
                        break
                    if "histogram-file-version:" in line.lower():
                        return True
        except OSError:
            pass
        return False

    def parse_output_directory(
        self,
        out_dir: Optional[Path] = None,
        enable_carving: bool = True,
    ) -> Tuple[List[Tuple[str, str, str, str, str]], List[Tuple[str, int, str, str]], int]:
        """
        Two-pass parser (Features -> Histograms) over bulk_extractor output folder.
        Returns (feature_rows, histogram_rows, carved_files_count).
        """
        target_dir = Path(out_dir).resolve() if out_dir is not None else self.out_dir
        if not target_dir.is_dir():
            return ([], [], 0)

        carved_count = 0
        if enable_carving:
            for sub in target_dir.iterdir():
                if sub.is_dir():
                    carved_count += sum(1 for p in sub.rglob("*") if p.is_file())

        feature_files: List[Path] = []
        histogram_files: List[Path] = []

        for txt_path in sorted(target_dir.glob("*.txt"), key=lambda p: p.name.lower()):
            if not txt_path.is_file():
                continue
            fname_low = txt_path.name.lower()
            if fname_low in EXCLUDED_TXT_FILES:
                continue
            if fname_low.endswith("_tags.txt") or fname_low.endswith("_stopped.txt"):
                continue
            if not enable_carving and fname_low.endswith("_carved.txt"):
                continue
            try:
                if txt_path.stat().st_size == 0:
                    continue
            except OSError:
                continue

            if self._is_histogram_file(txt_path):
                histogram_files.append(txt_path)
            else:
                feature_files.append(txt_path)

        accepted_by_family: Dict[str, Set[str]] = defaultdict(set)
        rejected_by_family: Dict[str, Set[str]] = defaultdict(set)
        accepted_global: Set[str] = set()
        rejected_global: Set[str] = set()
        parsed_scanners: Set[str] = set()

        feature_rows: List[Tuple[str, str, str, str, str]] = []
        histogram_rows: List[Tuple[str, int, str, str]] = []

        # Pass 1: Feature files (with full flanking-byte context validation)
        for fpath in feature_files:
            scanner = fpath.stem.lower()
            parsed_scanners.add(scanner)
            family = _canonical_verdict_family(scanner)
            source_name = fpath.name
            try:
                with open(fpath, "r", encoding="utf-8-sig", errors="replace") as f:
                    for raw_line in f:
                        line = raw_line.lstrip("\ufeff").rstrip("\r\n")
                        if not line or line.lstrip().startswith("#"):
                            continue
                        parts = line.split("\t", 2)
                        if len(parts) < 2:
                            continue
                        offset_str = parts[0].strip().replace("\U0010001c-", ":").replace("\U0010001c", ":")
                        feat_val = parts[1].strip()
                        ctx_val = parts[2] if len(parts) >= 3 else ""
                        if not offset_str or not feat_val:
                            continue

                        norm_keys = _normalize_verdict_keys(family, feat_val)
                        if _is_valid_feature(scanner, feat_val, ctx_val, has_context=True):
                            clean_ctx, _ = _inspect_be_context(ctx_val, feat_val)
                            feature_rows.append((scanner, offset_str, feat_val, clean_ctx or ctx_val, source_name))
                            accepted_by_family[family].update(norm_keys)
                            accepted_global.update(norm_keys)
                            if scanner == "email" and "@" in feat_val:
                                dom_part = feat_val.split("@", 1)[1].lower()
                                dom_keys = _normalize_verdict_keys("domain", dom_part)
                                accepted_by_family["domain"].update(dom_keys)
                                accepted_global.update(dom_keys)
                        else:
                            rejected_by_family[family].update(norm_keys)
                            rejected_global.update(norm_keys)
                            if scanner == "email" and "@" in feat_val:
                                dom_part = feat_val.split("@", 1)[1].lower()
                                dom_keys = _normalize_verdict_keys("domain", dom_part)
                                rejected_by_family["domain"].update(dom_keys)
            except OSError as ex:
                self.log_fn(f"Warning reading feature file {fpath.name}: {ex}", "WARNING")

        # Pass 2: Histogram files (cross-filtered against Pass 1 context verdicts)
        for hpath in histogram_files:
            scanner = re.sub(r"_histogram(?:_\d+)?$", "", hpath.stem.lower())
            if not enable_carving and scanner.endswith("_carved"):
                continue
            family = _canonical_verdict_family(scanner)
            source_name = hpath.name
            has_pass1_source = (
                (scanner == "domain" and "domain" in parsed_scanners)
                or (scanner == "email_domain" and "email" in parsed_scanners)
                or (scanner in ("ip", "email", "telephone", "ccn") and scanner in parsed_scanners)
            )
            try:
                with open(hpath, "r", encoding="utf-8-sig", errors="replace") as f:
                    for raw_line in f:
                        line = raw_line.lstrip("\ufeff").rstrip("\r\n")
                        if not line or line.lstrip().startswith("#"):
                            continue
                        parts = line.split("\t")
                        if len(parts) < 2:
                            continue
                        m_cnt = re.match(r"^n=(\d+)$", parts[0].strip(), re.IGNORECASE)
                        if not m_cnt:
                            continue
                        cnt = int(m_cnt.group(1))
                        feat_val = parts[1].strip()
                        if cnt <= 0 or not feat_val:
                            continue

                        if not _is_valid_feature(scanner, feat_val, "", has_context=False):
                            continue

                        lookup_keys = _normalize_verdict_keys(family, feat_val)
                        is_accepted_fam = any(k in accepted_by_family[family] for k in lookup_keys)
                        is_rejected_fam = any(k in rejected_by_family[family] for k in lookup_keys)
                        if is_rejected_fam and not is_accepted_fam:
                            continue

                        is_accepted_glob = any(k in accepted_global for k in lookup_keys)
                        is_rejected_glob = any(k in rejected_global for k in lookup_keys)
                        if is_rejected_glob and not is_accepted_glob:
                            continue

                        if has_pass1_source and not is_accepted_fam:
                            continue

                        histogram_rows.append((scanner, cnt, feat_val, source_name))
            except OSError as ex:
                self.log_fn(f"Warning reading histogram file {hpath.name}: {ex}", "WARNING")

        return (feature_rows, histogram_rows, carved_count)

    def _upsert_registry_and_log(
        self,
        cursor: Any,
        feat_count: int,
        hist_count: int,
        command_executed: str,
        exit_code: int,
        duration_ms: int,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        cursor.execute(
            "DELETE FROM artifact_registry WHERE table_name = 'parsed_bulk_extractor_features' AND artifact_id != 'bulk_extractor_features';"
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO artifact_registry (
                artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
            ) VALUES (
                'bulk_extractor_features', 'REFINED RESULTS', 'Bulk Extractor Features & IOCs',
                'parsed_bulk_extractor_features', 'bulk_extractor', ?, CURRENT_TIMESTAMP
            );
            """,
            [feat_count],
        )

        cursor.execute(
            "DELETE FROM artifact_registry WHERE table_name = 'parsed_bulk_extractor_histograms' AND artifact_id != 'bulk_extractor_histograms';"
        )
        cursor.execute(
            """
            INSERT OR REPLACE INTO artifact_registry (
                artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
            ) VALUES (
                'bulk_extractor_histograms', 'REFINED RESULTS', 'Bulk Extractor Feature Histograms',
                'parsed_bulk_extractor_histograms', 'bulk_extractor', ?, CURRENT_TIMESTAMP
            );
            """,
            [hist_count],
        )

        cursor.execute(
            """
            INSERT INTO processing_logs (
                log_id, timestamp_utc, module_name, command_executed,
                exit_code, rows_ingested, duration_ms, status, error_message
            ) VALUES (
                nextval('seq_log_id'), CURRENT_TIMESTAMP, 'BulkExtractor', ?, ?, ?, ?, ?, ?
            );
            """,
            [
                command_executed,
                exit_code,
                feat_count + hist_count,
                duration_ms,
                status,
                error_message,
            ],
        )

        log_line = (
            f"[BulkExtractor] Status={status} ExitCode={exit_code} "
            f"Features={feat_count} Histograms={hist_count} Duration={duration_ms}ms | Cmd: {command_executed}"
        )
        if error_message:
            log_line += f" | Error: {error_message}"
        log_line += "\n"
        try:
            with self._file_log_lock:
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(log_line)
        except OSError:
            pass

    def run(
        self,
        source_path: Union[str, Path],
        max_workers: int = 16,
        enable_carving: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute bulk_extractor64.exe against source_path and ingest validated features & histograms.
        """
        t0 = time.time()
        be_exe = self.resolve_bulk_extractor_binary()

        if be_exe is None:
            warn_msg = (
                "bulk_extractor64.exe not found; configure WFT_BULK_EXTRACTOR_EXE or run Setup-WFTTools.ps1"
            )
            self.log_fn(warn_msg, "WARNING")
            duration_ms = int((time.time() - t0) * 1000)
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                cursor = conn.cursor()
                _ensure_core_audit_tables(cursor)
                _ensure_be_tables(cursor, reset=True)
                self._upsert_registry_and_log(
                    cursor=cursor,
                    feat_count=0,
                    hist_count=0,
                    command_executed="find_bulk_extractor_binary()",
                    exit_code=-1,
                    duration_ms=duration_ms,
                    status="WARNING",
                    error_message=warn_msg,
                )
            return {
                "status": "WARNING",
                "skipped": True,
                "binary_path": None,
                "features_ingested": 0,
                "histograms_ingested": 0,
                "carved_files": 0,
                "output_dir": str(self.out_dir),
                "duration_ms": duration_ms,
                "message": warn_msg,
            }

        raw_src = str(source_path).strip().strip('"').strip("'")
        src = Path(raw_src).resolve()
        if not src.exists():
            err_msg = f"Source path does not exist: {src}"
            self.log_fn(err_msg, "ERROR")
            duration_ms = int((time.time() - t0) * 1000)
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                cursor = conn.cursor()
                _ensure_core_audit_tables(cursor)
                _ensure_be_tables(cursor, reset=True)
                self._upsert_registry_and_log(
                    cursor=cursor,
                    feat_count=0,
                    hist_count=0,
                    command_executed=f"{be_exe} (missing source: {src})",
                    exit_code=-1,
                    duration_ms=duration_ms,
                    status="ERROR",
                    error_message=err_msg,
                )
            return {
                "status": "ERROR",
                "binary_path": str(be_exe),
                "features_ingested": 0,
                "histograms_ingested": 0,
                "carved_files": 0,
                "output_dir": str(self.out_dir),
                "duration_ms": duration_ms,
                "message": err_msg,
            }

        raw_workers = 16 if max_workers is None else int(max_workers)
        clamped_workers = max(1, min(32, raw_workers))

        if self.out_dir.exists():
            shutil.rmtree(self.out_dir, ignore_errors=True)
        self.case_dir.mkdir(parents=True, exist_ok=True)

        # Pass -R ONLY when src is an actual directory (never for disk images or regular files!)
        is_dir_mode = src.is_dir() and (src.suffix.lower() not in DISK_IMAGE_EXTENSIONS)
        if is_dir_mode:
            if os.name == "nt" and src.drive and src == Path(src.drive + "\\"):
                norm_src = f"{src.drive}/"
            else:
                norm_src = str(src).rstrip("\\/")
        else:
            norm_src = str(src)

        def _build_be_cmd(worker_cnt: int) -> List[str]:
            c_list: List[str] = [str(be_exe), "-0", "-q", "-Z", "-j", str(worker_cnt)]
            if enable_carving:
                c_list.extend(CARVING_FLAGS)
            else:
                c_list.extend(DISABLE_CARVING_FLAGS)
            c_list.extend(["-o", str(self.out_dir)])
            if is_dir_mode:
                c_list.append("-R")
            c_list.append(norm_src)
            return c_list

        cmd = _build_be_cmd(clamped_workers)
        cmd_str = " ".join([f'"{c}"' if " " in c else c for c in cmd])
        self.log_fn(f"Executing: {cmd_str}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
                creationflags=_NO_WINDOW,
            )
            exit_code = proc.returncode
            stderr_msg = (proc.stderr or "").strip() or None
            if exit_code != 0 and clamped_workers > 4:
                self.log_fn(
                    f"bulk_extractor exited with code {exit_code} at -j {clamped_workers}; retrying safely with -j 4...",
                    "WARNING",
                )
                if self.out_dir.exists():
                    shutil.rmtree(self.out_dir, ignore_errors=True)
                cmd = _build_be_cmd(4)
                cmd_str = " ".join([f'"{c}"' if " " in c else c for c in cmd])
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=600,
                    creationflags=_NO_WINDOW,
                )
                exit_code = proc.returncode
                stderr_msg = (proc.stderr or "").strip() or None
        except subprocess.TimeoutExpired:
            exit_code = -2
            stderr_msg = f"bulk_extractor timed out after 600s: {cmd_str}"
            self.log_fn(stderr_msg, "WARNING")
        except Exception as exc:
            duration_ms = int((time.time() - t0) * 1000)
            err_msg = f"Failed launching bulk_extractor: {exc}"
            self.log_fn(err_msg, "ERROR")
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                cursor = conn.cursor()
                _ensure_core_audit_tables(cursor)
                _ensure_be_tables(cursor, reset=True)
                self._upsert_registry_and_log(
                    cursor=cursor,
                    feat_count=0,
                    hist_count=0,
                    command_executed=cmd_str,
                    exit_code=-1,
                    duration_ms=duration_ms,
                    status="ERROR",
                    error_message=err_msg,
                )
            return {
                "status": "ERROR",
                "exit_code": -1,
                "binary_path": str(be_exe),
                "command": cmd,
                "output_dir": str(self.out_dir),
                "features_ingested": 0,
                "histograms_ingested": 0,
                "carved_files": 0,
                "duration_ms": duration_ms,
                "message": err_msg,
            }

        if not enable_carving and self.out_dir.is_dir():
            for sub in list(self.out_dir.iterdir()):
                if sub.is_dir():
                    shutil.rmtree(sub, ignore_errors=True)

        feature_rows, histogram_rows, carved_files_count = self.parse_output_directory(
            self.out_dir, enable_carving=enable_carving
        )
        duration_ms = int((time.time() - t0) * 1000)
        run_status = "SUCCESS" if exit_code == 0 else "WARNING"

        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            cursor = conn.cursor()
            _ensure_core_audit_tables(cursor)
            _ensure_be_tables(cursor, reset=True)

            if feature_rows:
                inserted_fast = False
                if len(feature_rows) >= 500:
                    try:
                        import pyarrow as pa

                        pa_feat = pa.table(
                            {
                                "_row_id": list(range(1, len(feature_rows) + 1)),
                                "scanner": [r[0] for r in feature_rows],
                                "offset_str": [r[1] for r in feature_rows],
                                "feature": [r[2] for r in feature_rows],
                                "context": [r[3] for r in feature_rows],
                                "source_file": [r[4] for r in feature_rows],
                            }
                        )
                        cursor.register("_tmp_be_feat", pa_feat)
                        try:
                            cursor.execute(
                                """
                                INSERT INTO parsed_bulk_extractor_features (
                                    _row_id, scanner, offset_str, feature, context, source_file
                                )
                                SELECT _row_id, scanner, offset_str, feature, context, source_file
                                FROM _tmp_be_feat;
                                """
                            )
                            inserted_fast = True
                        finally:
                            try:
                                cursor.unregister("_tmp_be_feat")
                            except Exception:
                                pass
                    except Exception:
                        inserted_fast = False

                if not inserted_fast:
                    numbered_feats = [(i + 1, *r) for i, r in enumerate(feature_rows)]
                    cursor.executemany(
                        """
                        INSERT INTO parsed_bulk_extractor_features (
                            _row_id, scanner, offset_str, feature, context, source_file
                        ) VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        numbered_feats,
                    )

            if histogram_rows:
                inserted_hist_fast = False
                if len(histogram_rows) >= 500:
                    try:
                        import pyarrow as pa

                        pa_hist = pa.table(
                            {
                                "_row_id": list(range(1, len(histogram_rows) + 1)),
                                "scanner": [r[0] for r in histogram_rows],
                                "count": [int(r[1]) for r in histogram_rows],
                                "feature": [r[2] for r in histogram_rows],
                                "source_file": [r[3] for r in histogram_rows],
                            }
                        )
                        cursor.register("_tmp_be_hist", pa_hist)
                        try:
                            cursor.execute(
                                """
                                INSERT INTO parsed_bulk_extractor_histograms (
                                    _row_id, scanner, count, feature, source_file
                                )
                                SELECT _row_id, scanner, count, feature, source_file
                                FROM _tmp_be_hist;
                                """
                            )
                            inserted_hist_fast = True
                        finally:
                            try:
                                cursor.unregister("_tmp_be_hist")
                            except Exception:
                                pass
                    except Exception:
                        inserted_hist_fast = False

                if not inserted_hist_fast:
                    numbered_hists = [(i + 1, *r) for i, r in enumerate(histogram_rows)]
                    cursor.executemany(
                        """
                        INSERT INTO parsed_bulk_extractor_histograms (
                            _row_id, scanner, count, feature, source_file
                        ) VALUES (?, ?, ?, ?, ?);
                        """,
                        numbered_hists,
                    )

            self._upsert_registry_and_log(
                cursor=cursor,
                feat_count=len(feature_rows),
                hist_count=len(histogram_rows),
                command_executed=cmd_str,
                exit_code=exit_code,
                duration_ms=duration_ms,
                status=run_status,
                error_message=stderr_msg if exit_code != 0 else None,
            )

        return {
            "status": run_status,
            "exit_code": exit_code,
            "binary_path": str(be_exe),
            "command": cmd,
            "output_dir": str(self.out_dir),
            "features_ingested": len(feature_rows),
            "histograms_ingested": len(histogram_rows),
            "total_rows": len(feature_rows) + len(histogram_rows),
            "carved_files": carved_files_count,
            "duration_ms": duration_ms,
        }
