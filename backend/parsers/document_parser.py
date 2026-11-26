"""
Windows Forensic Toolkit (WFT) DFIR Suite - Corporate Documents, Text/CSV/RTF & Zone.Identifier Parser
Extracts:
1. Document metadata (Author, Last Modified By, Title, Created/Modified UTC timestamps,
   Page Count, Word Count, Embedded Links, and VBA/JS Macros presence) from:
   - PDF (.pdf) via PyMuPDF (pymupdf/fitz) + pure-Python /Info, FlateDecode & XMP fallback
   - Microsoft Word (.docx, .docm) via python-docx + pure-Python OOXML ZIP/XML fallback
   - Microsoft Excel (.xlsx, .xlsm) via openpyxl + pure-Python OOXML ZIP/XML fallback
   - Microsoft PowerPoint (.pptx, .pptm) via python-pptx + pure-Python OOXML ZIP/XML fallback
   - Legacy Microsoft Office (.doc, .xls, .ppt) via olefile + pure-Python CFB SummaryInformation fallback
   - Plain Text, CSV & Rich Text (.txt, .csv, .rtf) into BOTH parsed_text_documents and parsed_documents_metadata
2. NTFS Alternate Data Stream (ADS) Zone.Identifier (MOTW) download telemetry
   strictly validated for [ZoneTransfer] + ZoneId in {0, 1, 2, 3, 4} (UTF-8-sig & UTF-16LE safe).
Thread-safe under DuckDBManager.get_lock(case_id) with naive UTC timestamps and zero now() fabrication.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import struct
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import pymupdf as fitz  # Non-deprecated import in PyMuPDF >= 1.24
    HAS_FITZ = fitz is not None
except ImportError:
    try:
        import fitz  # type: ignore[no-redef]
        HAS_FITZ = fitz is not None
    except ImportError:
        fitz = None  # type: ignore[assignment]
        HAS_FITZ = False

try:
    import docx
    HAS_DOCX = docx is not None
except ImportError:
    docx = None  # type: ignore[assignment]
    HAS_DOCX = False

try:
    import openpyxl
    HAS_OPENPYXL = openpyxl is not None
except ImportError:
    openpyxl = None  # type: ignore[assignment]
    HAS_OPENPYXL = False

try:
    import pptx
    HAS_PPTX = pptx is not None
except ImportError:
    pptx = None  # type: ignore[assignment]
    HAS_PPTX = False

try:
    import olefile
    HAS_OLEFILE = olefile is not None
except ImportError:
    olefile = None  # type: ignore[assignment]
    HAS_OLEFILE = False

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser


DOCUMENTS_METADATA_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_documents_metadata (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    file_type VARCHAR,
    file_size_bytes BIGINT,
    title VARCHAR,
    author VARCHAR,
    last_modified_by VARCHAR,
    created_time TIMESTAMP,
    modified_time TIMESTAMP,
    page_count INTEGER,
    word_count INTEGER,
    has_macros BOOLEAN,
    embedded_links VARCHAR,
    zone_id INTEGER,
    zone_host_url VARCHAR,
    zone_referrer_url VARCHAR,
    host_url VARCHAR,
    referrer_url VARCHAR,
    sha256 VARCHAR,
    source_file VARCHAR
);
"""

TEXT_DOCUMENTS_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_text_documents (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    file_type VARCHAR,
    extension VARCHAR,
    file_size_bytes BIGINT,
    encoding VARCHAR,
    line_count INTEGER,
    word_count INTEGER,
    char_count BIGINT,
    title VARCHAR,
    author VARCHAR,
    last_modified_by VARCHAR,
    created_time TIMESTAMP,
    modified_time TIMESTAMP,
    content_preview VARCHAR,
    text_preview VARCHAR,
    embedded_links VARCHAR,
    zone_id INTEGER,
    zone_host_url VARCHAR,
    zone_referrer_url VARCHAR,
    host_url VARCHAR,
    referrer_url VARCHAR,
    sha256 VARCHAR,
    source_file VARCHAR
);
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS encoding VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS line_count INTEGER;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS word_count INTEGER;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS char_count BIGINT;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS title VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS author VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS last_modified_by VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS created_time TIMESTAMP;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS modified_time TIMESTAMP;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS content_preview VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS text_preview VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS embedded_links VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS zone_id INTEGER;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS zone_host_url VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS zone_referrer_url VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS host_url VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS referrer_url VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS sha256 VARCHAR;
ALTER TABLE parsed_text_documents ADD COLUMN IF NOT EXISTS source_file VARCHAR;
"""

_PDF_DATE_RE = re.compile(
    r"^(\d{4})"
    r"(?:(\d{2})"
    r"(?:(\d{2})"
    r"(?:(\d{2})"
    r"(?:(\d{2})"
    r"(?:(\d{2}))?)?)?)?)?"
    r"\s*"
    r"(?:"
    r"([Zz])(?:\s*0{1,2}'?\s*0{0,2}'?)?"
    r"|"
    r"([+\-])\s*(\d{2})(?:[':]?(\d{2}))?'?"
    r"|"
    r"([+\-])\s*(\d{1})(?:[':](\d{2}))?'?"
    r")?\s*$"
)

_URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"'\\)\]}]+", re.IGNORECASE)
_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_FILETIME_EPOCH_DIFF_TICKS = 116444736000000000
_NON_DOC_STAGING_SUBTREES: Set[str] = {
    "browsers",
    "chat",
    "cloud",
    "registry",
    "jumplists",
    "lnk",
    "prefetch",
    "recyclebin",
    "sqlite",
    "notifications",
    "thumbcache",
    "activitiescache",
    "powershell",
    "rmm",
    "tasks",
    "logs",
    "carved_thumbnails",
    "extracted_archives",
    "mft",
    "evtx",
    "srum",
    "amcache",
    "wer",
    "wlan",
}


def compute_sha256(file_path: Path) -> str:
    """Compute lowercase hexadecimal SHA256 digest of file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize any datetime to naive UTC so DuckDB TIMESTAMP never shifts by host timezone."""
    if dt is None:
        return None
    norm = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt
    if norm.year < 1971 or norm.year > 2100:
        return None
    return norm


def _parse_iso_to_naive_utc(raw: Optional[str]) -> Optional[datetime]:
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    iso_s = s.replace("Z", "+00:00")
    m_tz = re.match(r"^(.+[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+\-]\d{2})(\d{2})$", iso_s)
    if m_tz:
        iso_s = f"{m_tz.group(1)}{m_tz.group(2)}:{m_tz.group(3)}"
    try:
        return _to_naive_utc(datetime.fromisoformat(iso_s))
    except ValueError:
        return None


def _filetime_int_to_naive_utc(ft_ticks: int) -> Optional[datetime]:
    if ft_ticks <= _FILETIME_EPOCH_DIFF_TICKS:
        return None
    unix_100ns = ft_ticks - _FILETIME_EPOCH_DIFF_TICKS
    sec, rem = divmod(unix_100ns, 10_000_000)
    if sec <= 31536000 or sec > 4102444800:
        return None
    try:
        return _to_naive_utc(datetime(1970, 1, 1) + timedelta(seconds=sec, microseconds=rem // 10))
    except (OverflowError, ValueError):
        return None


def parse_pdf_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse ISO 32000-1 PDF date format D:YYYYMMDDHHmmSS[Z | +HH'mm' | -HH'mm' | ±HHmm | ±HH:mm | ±HH]
    or XMP ISO-8601 date mathematically to naive UTC datetime.
    """
    if not date_str or not isinstance(date_str, str):
        return None
    clean = date_str.strip().strip("\x00")
    if not clean:
        return None
    if clean.startswith(("D:", "d:")):
        clean = clean[2:].strip()

    m = _PDF_DATE_RE.match(clean)
    if m:
        yr_s, mo_s, dy_s, hr_s, mn_s, sc_s = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
        z_flag = m.group(7)
        sign2, h2, m2 = m.group(8), m.group(9), m.group(10)
        sign1, h1, m1 = m.group(11), m.group(12), m.group(13)
        try:
            year = int(yr_s)
            month = int(mo_s) if mo_s else 1
            day = int(dy_s) if dy_s else 1
            hour = int(hr_s) if hr_s else 0
            minute = int(mn_s) if mn_s else 0
            second = min(int(sc_s), 59) if sc_s else 0

            if z_flag or (not sign2 and not sign1):
                return _to_naive_utc(datetime(year, month, day, hour, minute, second))

            sign_str = sign2 or sign1
            tz_h = int(h2 if sign2 else h1)
            tz_m = int((m2 if sign2 else m1) or 0)
            if not (0 <= tz_h <= 23 and 0 <= tz_m <= 59):
                return None
            sign = 1 if sign_str == "+" else -1
            tz = timezone(timedelta(hours=sign * tz_h, minutes=sign * tz_m))
            dt_aware = datetime(year, month, day, hour, minute, second, tzinfo=tz)
            return _to_naive_utc(dt_aware)
        except ValueError:
            return None

    return _parse_iso_to_naive_utc(clean)


def _decode_text_with_encoding(raw: bytes) -> Tuple[str, str, bool]:
    """
    Decode raw bytes with BOM-aware UTF-8-sig / UTF-16LE / UTF-16BE / UTF-8 / CP1252.
    Returns (decoded_text, encoding_name, is_likely_binary).
    """
    if not raw:
        return "", "utf-8", False
    if raw.startswith(b"\xff\xfe"):
        even = ((len(raw) - 2) // 2) * 2
        return raw[2 : 2 + even].decode("utf-16-le", errors="replace"), "utf-16-le", False
    if raw.startswith(b"\xfe\xff"):
        even = ((len(raw) - 2) // 2) * 2
        return raw[2 : 2 + even].decode("utf-16-be", errors="replace"), "utf-16-be", False
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8-sig", False

    sample = raw[:2048]
    if len(sample) >= 4:
        odd = sample[1::2]
        even_b = sample[0::2]
        odd_nul = sum(1 for b in odd if b == 0) / max(1, len(odd))
        even_nul = sum(1 for b in even_b if b == 0) / max(1, len(even_b))
        if odd_nul > 0.30 and even_nul < 0.10:
            even = (len(raw) // 2) * 2
            return raw[:even].decode("utf-16-le", errors="replace"), "utf-16-le", False
        if even_nul > 0.30 and odd_nul < 0.10:
            even = (len(raw) // 2) * 2
            return raw[:even].decode("utf-16-be", errors="replace"), "utf-16-be", False

    # Reject non-UTF16 binary blobs with NUL bytes or excessive control bytes
    nul_count = sample.count(0)
    ctrl_count = sum(1 for b in sample if b < 9 or (13 < b < 32 and b != 27))
    if nul_count > 0 or (len(sample) > 0 and (ctrl_count / len(sample)) > 0.15):
        return "", "binary", True

    try:
        return raw.decode("utf-8", errors="strict"), "utf-8", False
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace"), "cp1252", False


def _read_zone_text(file_path: Path) -> str:
    """Read tiny NTFS Zone.Identifier ADS stream safely across UTF-8-sig, UTF-16LE/BE, and UTF-8."""
    try:
        st = file_path.stat()
        if st.st_size == 0 or st.st_size > 65536:
            return ""
        raw = file_path.read_bytes()
    except OSError:
        return ""
    txt, _, _ = _decode_text_with_encoding(raw)
    return txt.lstrip("\ufeff").replace("\x00", "")


def parse_zone_identifier(content: str) -> Dict[str, Any]:
    """
    Strictly parse NTFS Zone.Identifier INI content.
    Requires an explicit [ZoneTransfer] section header AND an integer ZoneId in {0, 1, 2, 3, 4}.
    Produces ZERO false positives on arbitrary INI or plain text files.
    """
    invalid_res: Dict[str, Any] = {
        "valid": False,
        "zone_id": None,
        "host_url": None,
        "referrer_url": None,
    }
    if not content or not isinstance(content, str):
        return invalid_res

    clean = content.lstrip("\ufeff").replace("\x00", "")
    m_hdr = re.search(r"(?im)^\s*\[ZoneTransfer\]\s*$", clean)
    if not m_hdr:
        return invalid_res

    after_hdr = clean[m_hdr.end() :]
    m_next_sec = re.search(r"(?m)^\s*\[[^\]\r\n]+\]\s*$", after_hdr)
    sec_body = after_hdr[: m_next_sec.start()] if m_next_sec else after_hdr

    zone_id: Optional[int] = None
    host_url: Optional[str] = None
    referrer_url: Optional[str] = None

    for raw_line in sec_body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith((";", "#")) or "=" not in line:
            continue
        k, v = line.split("=", 1)
        key_low = k.strip().lower()
        val_clean = re.sub(r"[\x00-\x1f]", "", v).strip()
        if key_low == "zoneid":
            if not re.match(r"^\d+$", val_clean):
                return invalid_res
            z_int = int(val_clean)
            if z_int not in (0, 1, 2, 3, 4):
                return invalid_res
            zone_id = z_int
        elif key_low == "hosturl":
            host_url = val_clean if val_clean else None
        elif key_low == "referrerurl":
            referrer_url = val_clean if val_clean else None

    if zone_id is None:
        return invalid_res

    return {
        "valid": True,
        "zone_id": zone_id,
        "host_url": host_url,
        "referrer_url": referrer_url,
    }


def _decode_pdf_string_token(token: bytes) -> str:
    """Decode a PDF literal '(...)' or hex '<...>' string token to Unicode."""
    if not token:
        return ""
    if token.startswith(b"<") and token.endswith(b">"):
        hex_body = re.sub(rb"\s+", b"", token[1:-1])
        if len(hex_body) % 2 == 1:
            hex_body += b"0"
        try:
            raw = bytes.fromhex(hex_body.decode("ascii", errors="ignore"))
        except ValueError:
            return ""
    elif token.startswith(b"(") and token.endswith(b")"):
        body = token[1:-1]
        out = bytearray()
        i = 0
        n = len(body)
        while i < n:
            ch = body[i]
            if ch == 0x5C and i + 1 < n:  # backslash escape
                nxt = body[i + 1]
                if nxt == ord("n"):
                    out.append(0x0A)
                    i += 2
                elif nxt == ord("r"):
                    out.append(0x0D)
                    i += 2
                elif nxt == ord("t"):
                    out.append(0x09)
                    i += 2
                elif nxt == ord("b"):
                    out.append(0x08)
                    i += 2
                elif nxt == ord("f"):
                    out.append(0x0C)
                    i += 2
                elif nxt in (ord("("), ord(")"), ord("\\")):
                    out.append(nxt)
                    i += 2
                elif 0x30 <= nxt <= 0x37:
                    oct_digits = bytes([nxt])
                    i += 2
                    for _ in range(2):
                        if i < n and 0x30 <= body[i] <= 0x37:
                            oct_digits += bytes([body[i]])
                            i += 1
                        else:
                            break
                    out.append(int(oct_digits, 8) & 0xFF)
                elif nxt in (0x0D, 0x0A):
                    i += 2
                    if nxt == 0x0D and i < n and body[i] == 0x0A:
                        i += 1
                else:
                    out.append(nxt)
                    i += 2
            else:
                out.append(ch)
                i += 1
        raw = bytes(out)
    else:
        raw = token

    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace").strip("\x00").strip()
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace").strip("\x00").strip()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace").strip("\x00").strip()
    try:
        return raw.decode("utf-8", errors="strict").strip("\x00").strip()
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace").strip("\x00").strip()


def _extract_pdf_fallback_metadata(file_path: Path) -> Dict[str, Any]:
    """Pure-Python PDF /Info + FlateDecode + XMP + /Pages + /URI + /JavaScript parser."""
    res: Dict[str, Any] = {
        "title": None,
        "author": None,
        "last_modified_by": None,
        "created_time": None,
        "modified_time": None,
        "page_count": 0,
        "word_count": 0,
        "has_macros": False,
        "embedded_links": [],
    }
    try:
        fsize = file_path.stat().st_size
        with open(file_path, "rb") as f:
            raw = f.read(min(fsize, 16 * 1024 * 1024))
    except OSError:
        return res

    if not raw.startswith(b"%PDF"):
        idx_pdf = raw.find(b"%PDF-")
        if idx_pdf == -1 or idx_pdf > 1024:
            return res

    # Decompress FlateDecode streams (bounded for safety) to inspect compressed /ObjStm, XMP, and text
    expanded_blobs: List[bytes] = [raw]
    stream_re = re.compile(rb"<<(.*?)>>\s*stream(?:\r\n|\n)", re.DOTALL)
    for sm in stream_re.finditer(raw):
        dict_bytes = sm.group(1)
        if b"/FlateDecode" not in dict_bytes and b"/Fl" not in dict_bytes:
            continue
        s_start = sm.end()
        s_end = raw.find(b"endstream", s_start)
        if s_end == -1 or s_end - s_start > 2 * 1024 * 1024:
            continue
        comp_buf = raw[s_start:s_end].rstrip(b"\r\n")
        decomp: Optional[bytes] = None
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                d_obj = zlib.decompressobj(wbits)
                decomp = d_obj.decompress(comp_buf, 2 * 1024 * 1024)
                break
            except Exception:
                continue
        if decomp:
            expanded_blobs.append(decomp)
        if len(expanded_blobs) >= 64:
            break

    # Narrow /Info object if referenced by trailer '/Info N G R'
    info_blobs: List[bytes] = []
    for m_ref in re.finditer(rb"/Info\s+(\d+)\s+(\d+)\s+R", raw):
        obj_hdr = m_ref.group(1) + b" " + m_ref.group(2) + b" obj"
        pos_obj = raw.find(obj_hdr)
        if pos_obj != -1:
            end_obj = raw.find(b"endobj", pos_obj)
            if end_obj != -1:
                info_blobs.append(raw[pos_obj:end_obj])
    search_Order = info_blobs + expanded_blobs

    def _find_pdf_key_val(key_bytes: bytes) -> Optional[str]:
        pat = re.compile(
            rb"/" + key_bytes + rb"\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)",
            re.DOTALL,
        )
        for blob in search_Order:
            m_kv = pat.search(blob)
            if m_kv:
                val = _decode_pdf_string_token(m_kv.group(1))
                if val:
                    return val
        return None

    res["title"] = _find_pdf_key_val(b"Title")
    res["author"] = _find_pdf_key_val(b"Author")
    c_raw = _find_pdf_key_val(b"CreationDate")
    m_raw = _find_pdf_key_val(b"ModDate")
    res["created_time"] = parse_pdf_date(c_raw) if c_raw else None
    res["modified_time"] = parse_pdf_date(m_raw) if m_raw else None

    # Inspect XMP metadata if present in any raw or decompressed stream
    for blob in expanded_blobs:
        xmp_idx = blob.find(b"<x:xmpmeta")
        if xmp_idx == -1:
            xmp_idx = blob.find(b"<rdf:RDF")
        if xmp_idx != -1:
            xmp_end = blob.find(b"</x:xmpmeta>", xmp_idx)
            if xmp_end == -1:
                xmp_end = min(len(blob), xmp_idx + 131072)
            else:
                xmp_end += 12
            xmp_txt = blob[xmp_idx:xmp_end].decode("utf-8", errors="ignore")
            if not res["last_modified_by"]:
                m_lmb = re.search(r"<(?:xmpMM|pdfx):LastModifiedBy>([^<]+)</", xmp_txt, re.I)
                if m_lmb:
                    res["last_modified_by"] = m_lmb.group(1).strip()
            if not res["title"]:
                m_t = re.search(r"<dc:title>.*?<rdf:li[^>]*>([^<]+)</rdf:li>", xmp_txt, re.I | re.S)
                if m_t:
                    res["title"] = m_t.group(1).strip()
            if not res["author"]:
                m_a = re.search(r"<dc:creator>.*?<rdf:li[^>]*>([^<]+)</rdf:li>", xmp_txt, re.I | re.S)
                if m_a:
                    res["author"] = m_a.group(1).strip()
            if not res["created_time"]:
                m_cd = re.search(r"<xmp:CreateDate>([^<]+)</xmp:CreateDate>", xmp_txt, re.I)
                if m_cd:
                    res["created_time"] = parse_pdf_date(m_cd.group(1).strip())
            if not res["modified_time"]:
                m_md = re.search(r"<xmp:ModifyDate>([^<]+)</xmp:ModifyDate>", xmp_txt, re.I)
                if m_md:
                    res["modified_time"] = parse_pdf_date(m_md.group(1).strip())

    # Page count
    counts = [
        int(m.group(1))
        for blob in expanded_blobs
        for m in re.finditer(rb"/Type\s*/Pages\b[^>]*/Count\s+(\d+)", blob)
    ]
    if not counts:
        counts = [
            int(m.group(1))
            for blob in expanded_blobs
            for m in re.finditer(rb"/Count\s+(\d+)[^>]*/Type\s*/Pages\b", blob)
        ]
    if counts:
        res["page_count"] = max(counts)
    else:
        leaf_pages = sum(len(re.findall(rb"/Type\s*/Page\b(?![A-Za-z])", blob)) for blob in expanded_blobs)
        res["page_count"] = leaf_pages

    # Links, JS/EmbeddedFiles, and pure-Python text operator word count
    links: List[str] = []
    words = 0
    uri_re = re.compile(rb"/URI\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)")
    tj_re = re.compile(rb"\((?:\\.|[^\\)])+\)\s*Tj")
    for blob in expanded_blobs:
        if re.search(rb"/(?:JavaScript|JS|EmbeddedFiles)\b", blob):
            res["has_macros"] = True
        for um in uri_re.finditer(blob):
            u_str = _decode_pdf_string_token(um.group(1))
            if u_str and u_str not in links:
                links.append(u_str)
        for tm in tj_re.finditer(blob):
            lit_end = tm.group(0).rfind(b")")
            if lit_end > 0:
                t_str = _decode_pdf_string_token(tm.group(0)[: lit_end + 1])
                words += len(t_str.split())

    res["embedded_links"] = links
    res["word_count"] = words
    return res


_OOXML_MAX_MEMBER_COUNT = 5000
_OOXML_MAX_TOTAL_UNCOMPRESSED_BYTES = 128 * 1024 * 1024  # 128 MB DOM ceiling
_OOXML_MAX_SINGLE_XML_DOM_BYTES = 32 * 1024 * 1024      # 32 MB single XML DOM ceiling
_OOXML_SMALL_XML_CAP_BYTES = 2 * 1024 * 1024            # 2 MB cap for core.xml / app.xml / .rels
_OOXML_DOC_XML_STREAM_CAP_BYTES = 8 * 1024 * 1024       # 8 MB streamed cap for word/document.xml
_OOXML_ARCHIVE_READ_BUDGET_BYTES = 24 * 1024 * 1024     # 24 MB total decompression budget
_OOXML_WT_SPAN_RE = re.compile(r"<(?:\w+:)?t(?:\s[^>]*)?>([^<]*)</(?:\w+:)?t>")


def _is_ooxml_safe_for_dom_loader(file_path: Path) -> bool:
    """
    Guard third-party DOM loaders (python-docx / openpyxl / python-pptx) against OOXML zip bombs.
    Returns False if archive member count > 5,000, total uncompressed size > 128 MB, or any
    XML/.rels member exceeds 32 MB uncompressed.
    """
    try:
        if not zipfile.is_zipfile(file_path):
            return False
        with zipfile.ZipFile(file_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > _OOXML_MAX_MEMBER_COUNT:
                return False
            total_uncompressed = 0
            for info in infos:
                fsize = max(0, int(getattr(info, "file_size", 0) or 0))
                total_uncompressed += fsize
                if total_uncompressed > _OOXML_MAX_TOTAL_UNCOMPRESSED_BYTES:
                    return False
                n_low = info.filename.lower()
                if (n_low.endswith(".xml") or n_low.endswith(".rels")) and fsize > _OOXML_MAX_SINGLE_XML_DOM_BYTES:
                    return False
        return True
    except Exception:
        return False


def _read_zip_member_bounded(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_bytes: int,
) -> Optional[bytes]:
    """Read at most max_bytes from a ZipInfo stream; returns None if uncompressed size exceeds cap."""
    fsize = max(0, int(getattr(info, "file_size", 0) or 0))
    if fsize > max_bytes:
        return None
    chunks: List[bytes] = []
    read_so_far = 0
    with zf.open(info, "r") as fp:
        while read_so_far <= max_bytes:
            block = fp.read(min(65536, (max_bytes + 1) - read_so_far))
            if not block:
                break
            chunks.append(block)
            read_so_far += len(block)
            if read_so_far > max_bytes:
                return None
    return b"".join(chunks)


def _count_docx_words_streamed(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_stream_bytes: int = _OOXML_DOC_XML_STREAM_CAP_BYTES,
) -> Tuple[int, int]:
    """
    Count words inside <w:t>...</w:t> elements in word/document.xml with strictly bounded RAM.
    Uses ElementTree when uncompressed size <= 2 MB, otherwise streams 64 KB chunks up to max_stream_bytes.
    Returns (word_count, bytes_consumed).
    """
    fsize = max(0, int(getattr(info, "file_size", 0) or 0))
    if fsize <= _OOXML_SMALL_XML_CAP_BYTES:
        raw_doc = _read_zip_member_bounded(zf, info, _OOXML_SMALL_XML_CAP_BYTES)
        if raw_doc is not None:
            try:
                doc_root = ET.fromstring(raw_doc)
                words = sum(
                    len(el.text.split())
                    for el in doc_root.iter()
                    if el.tag.rsplit("}", 1)[-1] == "t" and el.text
                )
                return words, len(raw_doc)
            except Exception:
                pass

    words_total = 0
    consumed = 0
    carry = ""
    with zf.open(info, "r") as fp:
        while consumed < max_stream_bytes:
            to_read = min(65536, max_stream_bytes - consumed)
            chunk = fp.read(to_read)
            if not chunk:
                break
            consumed += len(chunk)
            text_window = carry + chunk.decode("utf-8", errors="ignore")
            last_close = text_window.rfind("</")
            if last_close != -1 and consumed < max_stream_bytes:
                close_gt = text_window.find(">", last_close)
                if close_gt != -1:
                    processable = text_window[: close_gt + 1]
                    carry = text_window[close_gt + 1 :][-4096:]
                else:
                    processable = text_window[:last_close]
                    carry = text_window[last_close:][-4096:]
            else:
                processable = text_window
                carry = ""
            for m in _OOXML_WT_SPAN_RE.finditer(processable):
                span = m.group(1)
                if span:
                    words_total += len(span.split())
    if carry:
        for m in _OOXML_WT_SPAN_RE.finditer(carry):
            span = m.group(1)
            if span:
                words_total += len(span.split())
    return words_total, consumed


def _extract_ooxml_zip_metadata(file_path: Path, ext: str) -> Dict[str, Any]:
    """Bounded pure-Python OOXML (.docx/.docm/.xlsx/.xlsm/.pptx/.pptm) ZIP + XML metadata extractor."""
    res: Dict[str, Any] = {
        "title": None,
        "author": None,
        "last_modified_by": None,
        "created_time": None,
        "modified_time": None,
        "page_count": 1 if ext in ("DOCX", "DOCM", "XLSX", "XLSM") else 0,
        "word_count": 0,
        "has_macros": False,
        "embedded_links": [],
    }
    if not zipfile.is_zipfile(file_path):
        return res

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            infos = zf.infolist()
            info_by_lower: Dict[str, zipfile.ZipInfo] = {}
            for info in infos[: _OOXML_MAX_MEMBER_COUNT * 2]:
                n_low = info.filename.lower()
                if n_low not in info_by_lower:
                    info_by_lower[n_low] = info

            if any(
                "vbaproject.bin" in n_low or "/macros/" in n_low or "macrosheets/" in n_low
                for n_low in info_by_lower
            ):
                res["has_macros"] = True

            budget_left = _OOXML_ARCHIVE_READ_BUDGET_BYTES

            # 1. docProps/core.xml (bounded to 2 MB)
            core_info = info_by_lower.get("docprops/core.xml")
            if core_info is not None and budget_left > 0:
                try:
                    raw_core = _read_zip_member_bounded(
                        zf, core_info, min(_OOXML_SMALL_XML_CAP_BYTES, budget_left)
                    )
                    if raw_core is not None:
                        budget_left -= len(raw_core)
                        root = ET.fromstring(raw_core)
                        for elem in root.iter():
                            local_tag = elem.tag.rsplit("}", 1)[-1].lower()
                            val = (elem.text or "").strip()
                            if not val:
                                continue
                            if local_tag == "title":
                                res["title"] = val
                            elif local_tag == "creator":
                                res["author"] = val
                            elif local_tag == "lastmodifiedby":
                                res["last_modified_by"] = val
                            elif local_tag == "created":
                                res["created_time"] = _parse_iso_to_naive_utc(val)
                            elif local_tag == "modified":
                                res["modified_time"] = _parse_iso_to_naive_utc(val)
                except Exception:
                    pass

            # 2. docProps/app.xml (bounded to 2 MB)
            app_info = info_by_lower.get("docprops/app.xml")
            app_pages: Optional[int] = None
            app_slides: Optional[int] = None
            app_words: Optional[int] = None
            if app_info is not None and budget_left > 0:
                try:
                    raw_app = _read_zip_member_bounded(
                        zf, app_info, min(_OOXML_SMALL_XML_CAP_BYTES, budget_left)
                    )
                    if raw_app is not None:
                        budget_left -= len(raw_app)
                        app_root = ET.fromstring(raw_app)
                        for elem in app_root.iter():
                            local_tag = elem.tag.rsplit("}", 1)[-1].lower()
                            val = (elem.text or "").strip()
                            if not val.isdigit():
                                continue
                            if local_tag == "pages":
                                app_pages = int(val)
                            elif local_tag == "slides":
                                app_slides = int(val)
                            elif local_tag == "words":
                                app_words = int(val)
                except Exception:
                    pass

            if ext in ("DOCX", "DOCM"):
                if app_pages and app_pages > 0:
                    res["page_count"] = app_pages
                if app_words and app_words > 0:
                    res["word_count"] = app_words
                elif "word/document.xml" in info_by_lower and budget_left > 0:
                    try:
                        wc, used_b = _count_docx_words_streamed(
                            zf,
                            info_by_lower["word/document.xml"],
                            min(_OOXML_DOC_XML_STREAM_CAP_BYTES, budget_left),
                        )
                        budget_left -= used_b
                        res["word_count"] = wc
                    except Exception:
                        pass
            elif ext in ("XLSX", "XLSM"):
                sheets = [
                    n for n in info_by_lower
                    if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
                ]
                if sheets:
                    res["page_count"] = len(sheets)
            elif ext in ("PPTX", "PPTM"):
                slides = [
                    n for n in info_by_lower
                    if n.startswith("ppt/slides/slide") and n.endswith(".xml")
                ]
                if slides:
                    res["page_count"] = len(slides)
                elif app_slides is not None:
                    res["page_count"] = app_slides

            # 3. External URLs in *.rels (bounded per member and by remaining archive budget)
            links: List[str] = []
            rels_checked = 0
            for n_low, r_info in info_by_lower.items():
                if budget_left <= 0 or rels_checked >= 250:
                    break
                if n_low.endswith(".rels"):
                    rels_checked += 1
                    try:
                        raw_rels = _read_zip_member_bounded(
                            zf, r_info, min(_OOXML_SMALL_XML_CAP_BYTES, budget_left)
                        )
                        if raw_rels is None:
                            continue
                        budget_left -= len(raw_rels)
                        rels_xml = raw_rels.decode("utf-8", errors="replace")
                        for m in re.finditer(r'Target="([^"]+)"', rels_xml):
                            target = m.group(1).strip()
                            if target.startswith(("http://", "https://", "ftp://", "mailto:")) and target not in links:
                                links.append(target)
                    except Exception:
                        continue
            res["embedded_links"] = links
    except Exception:
        pass

    return res


def _extract_cfb_summary_fallback(file_path: Path) -> Dict[str, Any]:
    """Pure-Python MS-CFB OLE2 Compound File directory & SummaryInformation property set reader."""
    res: Dict[str, Any] = {
        "title": None,
        "author": None,
        "last_modified_by": None,
        "created_time": None,
        "modified_time": None,
        "page_count": 1,
        "word_count": 0,
        "has_macros": False,
    }
    try:
        raw = file_path.read_bytes()
    except OSError:
        return res
    if len(raw) < 512 or raw[:8] != _CFB_MAGIC:
        return res

    sec_shift = struct.unpack_from("<H", raw, 30)[0]
    mini_shift = struct.unpack_from("<H", raw, 32)[0]
    if sec_shift not in (9, 12) or mini_shift != 6:
        return res
    sec_size = 1 << sec_shift
    mini_size = 1 << mini_shift
    num_fat_sects = struct.unpack_from("<I", raw, 44)[0]
    first_dir_sect = struct.unpack_from("<I", raw, 48)[0]
    mini_cutoff = struct.unpack_from("<I", raw, 56)[0]
    first_minifat_sect = struct.unpack_from("<I", raw, 60)[0]
    num_minifat_sects = struct.unpack_from("<I", raw, 64)[0]
    first_difat_sect = struct.unpack_from("<I", raw, 68)[0]
    num_difat_sects = struct.unpack_from("<I", raw, 72)[0]

    def _sect_bytes(sid: int) -> bytes:
        off = 512 + sid * sec_size
        if sid < 0 or off + sec_size > len(raw):
            return b""
        return raw[off : off + sec_size]

    difat: List[int] = list(struct.unpack_from("<109I", raw, 76))
    cur_dif = first_difat_sect
    for _ in range(min(num_difat_sects, 1024)):
        if cur_dif >= 0xFFFFFFFA:
            break
        blk = _sect_bytes(cur_dif)
        if len(blk) < sec_size:
            break
        cnt = (sec_size // 4) - 1
        difat.extend(struct.unpack_from(f"<{cnt}I", blk, 0))
        cur_dif = struct.unpack_from("<I", blk, sec_size - 4)[0]

    fat: List[int] = []
    ints_per_sect = sec_size // 4
    for sid in difat[: min(len(difat), num_fat_sects)]:
        if sid >= 0xFFFFFFFA:
            continue
        blk = _sect_bytes(sid)
        if len(blk) == sec_size:
            fat.extend(struct.unpack_from(f"<{ints_per_sect}I", blk, 0))

    def _read_chain(start_sid: int, max_bytes: int = 4 * 1024 * 1024) -> bytes:
        out = bytearray()
        cur = start_sid
        visited: Set[int] = set()
        while 0 <= cur < 0xFFFFFFFA and cur not in visited and len(out) < max_bytes:
            visited.add(cur)
            blk = _sect_bytes(cur)
            if not blk:
                break
            out.extend(blk)
            cur = fat[cur] if cur < len(fat) else 0xFFFFFFFE
        return bytes(out)

    dir_bytes = _read_chain(first_dir_sect, 2 * 1024 * 1024)
    if len(dir_bytes) < 128:
        return res

    root_start, root_size = struct.unpack_from("<IQ", dir_bytes, 116)
    if sec_shift == 9:
        root_size &= 0xFFFFFFFF

    minifat: List[int] = []
    if num_minifat_sects > 0 and first_minifat_sect < 0xFFFFFFFA:
        mf_bytes = _read_chain(first_minifat_sect, 512 * 1024)
        if len(mf_bytes) >= 4:
            minifat = list(struct.unpack_from(f"<{len(mf_bytes) // 4}I", mf_bytes, 0))
    mini_stream = _read_chain(root_start, min(int(root_size) + sec_size, 4 * 1024 * 1024)) if minifat else b""

    def _read_mini_chain(start_msid: int, size: int) -> bytes:
        out = bytearray()
        cur = start_msid
        visited: Set[int] = set()
        while 0 <= cur < 0xFFFFFFFA and cur not in visited and len(out) < size:
            visited.add(cur)
            off = cur * mini_size
            if off + mini_size > len(mini_stream):
                break
            out.extend(mini_stream[off : off + mini_size])
            cur = minifat[cur] if cur < len(minifat) else 0xFFFFFFFE
        return bytes(out[:size])

    summary_stream: Optional[bytes] = None
    for off in range(0, len(dir_bytes) - 127, 128):
        name_cb = struct.unpack_from("<H", dir_bytes, off + 64)[0]
        obj_type = dir_bytes[off + 66]
        if obj_type == 0 or name_cb < 2 or name_cb > 64:
            continue
        entry_name = dir_bytes[off : off + name_cb - 2].decode("utf-16-le", errors="ignore")
        low_name = entry_name.lower()
        if any(k in low_name for k in ("vba", "macros", "_vba_project")):
            res["has_macros"] = True
        if entry_name == "\x05SummaryInformation" and obj_type == 2:
            st_sect, st_size = struct.unpack_from("<IQ", dir_bytes, off + 116)
            if sec_shift == 9:
                st_size &= 0xFFFFFFFF
            if 0 < st_size < mini_cutoff and mini_stream:
                summary_stream = _read_mini_chain(st_sect, int(st_size))
            elif st_size > 0:
                summary_stream = _read_chain(st_sect, int(st_size) + sec_size)[: int(st_size)]

    if summary_stream and len(summary_stream) >= 48:
        byte_order = struct.unpack_from("<H", summary_stream, 0)[0]
        num_sections = struct.unpack_from("<I", summary_stream, 24)[0]
        if byte_order == 0xFFFE and num_sections >= 1:
            sec_off = struct.unpack_from("<I", summary_stream, 44)[0]
            if sec_off + 8 <= len(summary_stream):
                c_props = struct.unpack_from("<I", summary_stream, sec_off + 4)[0]
                codepage = 1252
                prop_offsets: List[Tuple[int, int]] = []
                for idx in range(min(c_props, 128)):
                    p_pos = sec_off + 8 + idx * 8
                    if p_pos + 8 > len(summary_stream):
                        break
                    pid, rel_off = struct.unpack_from("<II", summary_stream, p_pos)
                    prop_offsets.append((pid, sec_off + rel_off))
                    if pid == 1 and sec_off + rel_off + 8 <= len(summary_stream):
                        vt = struct.unpack_from("<I", summary_stream, sec_off + rel_off)[0] & 0xFFFF
                        if vt == 0x0002:
                            cp_val = struct.unpack_from("<H", summary_stream, sec_off + rel_off + 4)[0]
                            if cp_val == 65001:
                                codepage = 65001
                enc_name = "utf-8" if codepage == 65001 else f"cp{codepage}"

                for pid, v_off in prop_offsets:
                    if v_off + 8 > len(summary_stream):
                        continue
                    vt = struct.unpack_from("<I", summary_stream, v_off)[0] & 0xFFFF
                    val: Any = None
                    if vt == 0x001E and v_off + 8 <= len(summary_stream):  # VT_LPSTR
                        slen = struct.unpack_from("<I", summary_stream, v_off + 4)[0]
                        s_raw = summary_stream[v_off + 8 : v_off + 8 + min(slen, 4096)]
                        try:
                            val = s_raw.decode(enc_name, errors="replace").rstrip("\x00").strip()
                        except LookupError:
                            val = s_raw.decode("cp1252", errors="replace").rstrip("\x00").strip()
                    elif vt == 0x001F and v_off + 8 <= len(summary_stream):  # VT_LPWSTR
                        cch = struct.unpack_from("<I", summary_stream, v_off + 4)[0]
                        s_raw = summary_stream[v_off + 8 : v_off + 8 + min(cch * 2, 8192)]
                        val = s_raw.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
                    elif vt == 0x0003 and v_off + 8 <= len(summary_stream):  # VT_I4
                        val = struct.unpack_from("<i", summary_stream, v_off + 4)[0]
                    elif vt == 0x0040 and v_off + 12 <= len(summary_stream):  # VT_FILETIME
                        ft = struct.unpack_from("<Q", summary_stream, v_off + 4)[0]
                        val = _filetime_int_to_naive_utc(ft)

                    if val is None or val == "":
                        continue
                    if pid == 2 and isinstance(val, str):
                        res["title"] = val
                    elif pid == 4 and isinstance(val, str):
                        res["author"] = val
                    elif pid == 8 and isinstance(val, str):
                        res["last_modified_by"] = val
                    elif pid == 12 and isinstance(val, datetime):
                        res["created_time"] = val
                    elif pid == 13 and isinstance(val, datetime):
                        res["modified_time"] = val
                    elif pid == 14 and isinstance(val, int) and val > 0:
                        res["page_count"] = val
                    elif pid == 15 and isinstance(val, int) and val >= 0:
                        res["word_count"] = val

    return res


def _parse_rtf_time_group(group_text: str) -> Optional[datetime]:
    def _num(tag: str, default: int) -> int:
        m = re.search(rf"\\{tag}(\d+)", group_text)
        return int(m.group(1)) if m else default

    yr = _num("yr", 0)
    if not (1971 <= yr <= 2100):
        return None
    mo = _num("mo", 1)
    dy = _num("dy", 1)
    hr = _num("hr", 0)
    mn = _num("min", 0)
    sc = min(_num("sec", 0), 59)
    try:
        return _to_naive_utc(datetime(yr, mo, dy, hr, mn, sc))
    except ValueError:
        return None


def _strip_rtf_to_plain(rtf_text: str) -> str:
    """Strip RTF destination groups and control words into clean readable plaintext."""
    cleaned = re.sub(
        r"\{\\(?:fonttbl|colortbl|stylesheet|pict|header|footer|info|\*\\[^}\s]+)(?:[^{}]|\{[^{}]*\})*\}",
        " ",
        rtf_text,
        flags=re.DOTALL,
    )
    cleaned = re.sub(r"\\(?:par|line)\b\s?", "\n", cleaned)
    cleaned = re.sub(r"\\tab\b\s?", "\t", cleaned)
    cleaned = re.sub(
        r"\\'([0-9a-fA-F]{2})",
        lambda m: bytes.fromhex(m.group(1)).decode("cp1252", errors="ignore"),
        cleaned,
    )
    cleaned = re.sub(r"\\u(-?\d+)\??", lambda m: chr(int(m.group(1)) & 0xFFFF), cleaned)
    cleaned = re.sub(r"\\[a-zA-Z]+-?\d*\s?", "", cleaned)
    cleaned = cleaned.replace("{", "").replace("}", "")
    return cleaned.strip()


class DocumentParser(BaseParser):
    """
    Parser for corporate documents (.pdf, .docx/.docm, .xlsx/.xlsm, .pptx/.pptm, .doc, .xls, .ppt),
    plain text/CSV/RTF (.txt, .csv, .rtf), and NTFS Zone.Identifier download streams.
    Populates parsed_documents_metadata and parsed_text_documents in DuckDB.
    """

    DOC_EXTENSIONS = {
        ".pdf",
        ".docx",
        ".docm",
        ".xlsx",
        ".xlsm",
        ".pptx",
        ".pptm",
        ".doc",
        ".xls",
        ".ppt",
    }
    TXT_DOC_EXTENSIONS = {
        ".txt", ".rtf", ".log", ".ini", ".cfg", ".conf", ".text", ".csv",
    }
    OTHER_FILE_EXTENSIONS = {
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        ".py", ".pyw", ".html", ".htm", ".xhtml",
        ".css", ".scss", ".sass", ".less", ".vue", ".svelte",
        ".php", ".phtml", ".asp", ".aspx", ".jsp", ".jspx",
        ".rb", ".pl", ".pm", ".sh", ".bash", ".zsh",
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".sct",
        ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".cs", ".java", ".go", ".rs", ".swift", ".kt", ".kts", ".scala", ".lua", ".r", ".m",
        ".sql", ".json", ".jsonl", ".xml", ".yaml", ".yml", ".toml", ".config", ".properties", ".env",
        ".md", ".markdown", ".rst", ".reg", ".inf", ".url", ".vcf", ".ics", ".svg", ".tex", ".bib",
        ".dockerfile", ".makefile", ".gradle", ".cmake",
    }

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Union[str, Path]] = None,
        source_type: Optional[str] = None,
        db_manager: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(case_id, staging_dir, source_type=source_type, db_manager=db_manager)
        except TypeError:
            super().__init__(case_id, staging_dir)  # type: ignore[arg-type]
            if source_type and not getattr(self, "source_type", None):
                self.source_type = source_type
        self.zone_by_target_path: Dict[str, Dict[str, Any]] = {}
        self.zone_by_canonical_subpath: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.zone_by_zone_path: Dict[str, Dict[str, Any]] = {}
        self.zone_staging_by_name: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self.candidate_filename_counts: Dict[str, int] = {}
        self.consumed_zone_paths: Set[str] = set()
        self._parse_init_ts = time.time()
        self._case_start_naive_utc = datetime.fromtimestamp(
            self._parse_init_ts, tz=timezone.utc
        ).replace(tzinfo=None)
        self._vfs_rel_cache: Optional[Dict[str, Tuple[Optional[datetime], Optional[datetime]]]] = None
        self._vfs_path_cache: Optional[Dict[str, Tuple[Optional[datetime], Optional[datetime]]]] = None
        self._cached_eff_source_type: Optional[str] = None
        self._cached_ctime_allowed: Optional[bool] = None
        self._cached_cutoff_utc: Optional[datetime] = None

    def _preload_vfs_time_cache(self) -> None:
        rel_map: Dict[str, Tuple[Optional[datetime], Optional[datetime]]] = {}
        vp_map: Dict[str, Tuple[Optional[datetime], Optional[datetime]]] = {}
        eff_src = (getattr(self, "source_type", None) or "").strip().lower()
        cutoff_utc = self._case_start_naive_utc - timedelta(seconds=120)
        ctime_allowed = not bool(eff_src and eff_src not in self._IMAGE_SOURCE_TYPES)
        try:
            with DuckDBManager.get_lock(self.case_id):
                cur = self._get_conn().cursor()
                tables = {
                    str(r[0])
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if "case_metadata" in tables:
                    m_row = cur.execute(
                        "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                    ).fetchone()
                    if m_row and m_row[0]:
                        db_src = str(m_row[0]).strip().lower()
                        if db_src not in self._IMAGE_SOURCE_TYPES:
                            ctime_allowed = False
                        if not eff_src:
                            eff_src = db_src
                    c_row = cur.execute(
                        "SELECT value FROM case_metadata WHERE LOWER(key) IN ('created_utc', 'created_at', 'case_created_utc') LIMIT 1;"
                    ).fetchone()
                    if c_row and c_row[0]:
                        case_created_dt = (
                            _to_naive_utc(c_row[0])
                            if isinstance(c_row[0], datetime)
                            else _parse_iso_to_naive_utc(str(c_row[0]))
                        )
                        if case_created_dt is not None:
                            cutoff_utc = min(cutoff_utc, case_created_dt - timedelta(seconds=120))
                if eff_src not in self._IMAGE_SOURCE_TYPES:
                    ctime_allowed = False
                if ctime_allowed and "vfs_partitions" in tables:
                    non_img_part = cur.execute(
                        """
                        SELECT 1 FROM "vfs_partitions"
                        WHERE UPPER(TRIM(COALESCE(fs_type, ''))) IN ('FOLDER', 'DIRECTORY', 'ARCHIVE', 'LIVE')
                        LIMIT 1;
                        """
                    ).fetchone()
                    if non_img_part is not None:
                        ctime_allowed = False
                if "vfs_files" in tables:
                    vfs_cols = {
                        str(r[0]).lower(): str(r[0])
                        for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                    }
                    mod_exprs = [
                        self._quote_ident(vfs_cols[c])
                        for c in ("si_modified", "si_modified_utc", "fn_modified", "fn_modified_utc")
                        if c in vfs_cols
                    ]
                    cr_exprs = [
                        self._quote_ident(vfs_cols[c])
                        for c in ("si_created", "si_created_utc", "fn_created", "fn_created_utc")
                        if c in vfs_cols
                    ]
                    srp_sql = (
                        f"LOWER(TRIM(BOTH '/' FROM REPLACE(COALESCE({self._quote_ident(vfs_cols['staged_rel_path'])}, ''), chr(92), '/')))"
                        if "staged_rel_path" in vfs_cols
                        else "''"
                    )
                    vp_sql = (
                        f"LOWER(REPLACE(COALESCE({self._quote_ident(vfs_cols['vfs_path'])}, ''), '/', chr(92)))"
                        if "vfs_path" in vfs_cols
                        else "''"
                    )
                    mod_sql = f"COALESCE({', '.join(mod_exprs)})" if mod_exprs else "NULL"
                    cr_sql = f"COALESCE({', '.join(cr_exprs)})" if cr_exprs else "NULL"
                    for srp_k, vp_k, m_raw, c_raw in cur.execute(
                        f'SELECT {srp_sql}, {vp_sql}, {mod_sql}, {cr_sql} FROM "vfs_files";'
                    ).fetchall():
                        m_dt = (
                            _to_naive_utc(m_raw)
                            if isinstance(m_raw, datetime)
                            else (_parse_iso_to_naive_utc(str(m_raw)) if m_raw is not None else None)
                        )
                        c_dt = (
                            _to_naive_utc(c_raw)
                            if isinstance(c_raw, datetime)
                            else (_parse_iso_to_naive_utc(str(c_raw)) if c_raw is not None else None)
                        )
                        if srp_k and srp_k not in rel_map:
                            rel_map[srp_k] = (m_dt, c_dt)
                        if vp_k and vp_k not in vp_map:
                            vp_map[vp_k] = (m_dt, c_dt)
        except Exception:
            return
        self._vfs_rel_cache = rel_map
        self._vfs_path_cache = vp_map
        self._cached_eff_source_type = eff_src
        self._cached_ctime_allowed = ctime_allowed
        self._cached_cutoff_utc = cutoff_utc

    @staticmethod
    def _quote_ident(ident: str) -> str:
        escaped = ident.replace('"', '""')
        return f'"{escaped}"'

    def _local_vfs_lookup_candidates(self, p: Path) -> Tuple[List[str], List[str]]:
        base_builder = getattr(self, "_build_vfs_lookup_candidates", None)
        if callable(base_builder):
            try:
                rel_c, vfs_c = base_builder(p)
                if rel_c or vfs_c:
                    return list(rel_c), list(vfs_c)
            except Exception:
                pass
        rel_cands: List[str] = []
        try:
            rel_posix = p.resolve().relative_to(self.staging_dir.resolve()).as_posix().strip("/").lower()
            if rel_posix:
                rel_cands.append(rel_posix)
                rel_cands.append(f"staging/{rel_posix}")
        except Exception:
            pass
        return rel_cands, []

    def _get_original_mtime_dt(self, file_path: Union[str, Path]) -> Optional[datetime]:
        """
        Forensic modification-time lookup querying vfs_files modification columns ONLY
        (NEVER si_created, fn_created, or host file creation metadata).
        """
        p = Path(file_path)
        rel_candidates, vfs_cands = self._local_vfs_lookup_candidates(p)
        effective_source_type = (getattr(self, "source_type", None) or "").strip().lower()

        if self._vfs_rel_cache is not None and self._vfs_path_cache is not None:
            if not effective_source_type and self._cached_eff_source_type:
                effective_source_type = self._cached_eff_source_type
            for rc in rel_candidates:
                if rc in self._vfs_rel_cache:
                    return self._vfs_rel_cache[rc][0]
            for vc in vfs_cands:
                if vc in self._vfs_path_cache:
                    return self._vfs_path_cache[vc][0]
        else:
            try:
                with DuckDBManager.get_lock(self.case_id):
                    cur = self._get_conn().cursor()
                    tables = {
                        str(r[0])
                        for r in cur.execute(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                        ).fetchall()
                    }
                    if not effective_source_type and "case_metadata" in tables:
                        m_row = cur.execute(
                            "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                        ).fetchone()
                        if m_row and m_row[0]:
                            effective_source_type = str(m_row[0]).strip().lower()

                    if "vfs_files" in tables:
                        vfs_cols = {
                            str(r[0]).lower(): str(r[0])
                            for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                        }
                        mod_exprs = [
                            self._quote_ident(vfs_cols[c])
                            for c in ("si_modified", "si_modified_utc", "fn_modified", "fn_modified_utc")
                            if c in vfs_cols
                        ]
                        where_clauses: List[str] = []
                        params: List[Any] = []
                        if rel_candidates and "staged_rel_path" in vfs_cols:
                            q_srp = self._quote_ident(vfs_cols["staged_rel_path"])
                            ph = ", ".join(["?"] * len(rel_candidates))
                            where_clauses.append(
                                f"LOWER(TRIM(BOTH '/' FROM REPLACE(COALESCE({q_srp}, ''), chr(92), '/'))) IN ({ph})"
                            )
                            params.extend(rel_candidates)
                        if vfs_cands and "vfs_path" in vfs_cols:
                            q_vp = self._quote_ident(vfs_cols["vfs_path"])
                            ph_v = ", ".join(["?"] * len(vfs_cands))
                            where_clauses.append(
                                f"LOWER(REPLACE(COALESCE({q_vp}, ''), '/', chr(92))) IN ({ph_v})"
                            )
                            params.extend(vfs_cands)

                        if where_clauses:
                            mod_sql = f"COALESCE({', '.join(mod_exprs)})" if mod_exprs else "NULL"
                            where_sql = " OR ".join(where_clauses)
                            row = cur.execute(
                                f'SELECT 1, {mod_sql} FROM "vfs_files" WHERE {where_sql} LIMIT 1;',
                                params,
                            ).fetchone()
                            if row is not None:
                                val = row[1]
                                if val is None:
                                    return None
                                if isinstance(val, datetime):
                                    return _to_naive_utc(val)
                                return _parse_iso_to_naive_utc(str(val))
            except Exception:
                pass

        if effective_source_type in ("image", "disk_image", "e01", "raw", "vhd", "vhdx", "vmdk"):
            return None

        try:
            st_mtime = float(p.stat().st_mtime)
            if st_mtime <= 0 or st_mtime >= (self._parse_init_ts - 120.0):
                return None
            return _to_naive_utc(datetime.fromtimestamp(st_mtime, tz=timezone.utc))
        except OSError:
            return None

    _IMAGE_SOURCE_TYPES = {
        "image", "disk_image", "disk", "e01", "ex01", "ewf",
        "raw", "dd", "img", "vhd", "vhdx", "vmdk", "iso",
    }

    def _get_original_ctime_dt(self, file_path: Union[str, Path]) -> Optional[datetime]:
        """
        Lookup original VFS creation timestamp strictly for real disk images.
        Returns None on folder/directory/archive/live/unscoped cases (where Windows NTFS staging
        records host wall-clock creation time into vfs_files.si_created) and rejects any
        creation timestamp near host wall-clock or suspicious host-staged NTFS creation timestamps.
        """
        raw_src = (getattr(self, "source_type", None) or "").strip().lower()
        if raw_src and raw_src not in self._IMAGE_SOURCE_TYPES:
            return None

        p = Path(file_path)
        rel_candidates, vfs_cands = self._local_vfs_lookup_candidates(p)
        if not rel_candidates and not vfs_cands:
            return None

        if self._vfs_rel_cache is not None and self._vfs_path_cache is not None:
            if not self._cached_ctime_allowed:
                return None
            hit_pair: Optional[Tuple[Optional[datetime], Optional[datetime]]] = None
            for rc in rel_candidates:
                if rc in self._vfs_rel_cache:
                    hit_pair = self._vfs_rel_cache[rc]
                    break
            if hit_pair is None:
                for vc in vfs_cands:
                    if vc in self._vfs_path_cache:
                        hit_pair = self._vfs_path_cache[vc]
                        break
            if hit_pair is None or hit_pair[1] is None:
                return None
            mod_dt_c, dt_c = hit_pair[0], hit_pair[1]
            cutoff_c = self._cached_cutoff_utc or (self._case_start_naive_utc - timedelta(seconds=120))
            if dt_c >= cutoff_c:
                return None
            wallclock_fn = getattr(self, "_is_staging_wallclock_epoch", None)
            if callable(wallclock_fn) and wallclock_fn(dt_c.replace(tzinfo=timezone.utc).timestamp()):
                return None
            if mod_dt_c is not None and dt_c > (mod_dt_c + timedelta(days=1)):
                return None
            if dt_c >= (self._case_start_naive_utc - timedelta(hours=24)):
                if mod_dt_c is None:
                    return None
            return dt_c

        cutoff_utc = self._case_start_naive_utc - timedelta(seconds=120)
        effective_src = raw_src
        try:
            with DuckDBManager.get_lock(self.case_id):
                cur = self._get_conn().cursor()
                tables = {
                    str(r[0])
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if "case_metadata" in tables:
                    m_row = cur.execute(
                        "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                    ).fetchone()
                    if m_row and m_row[0]:
                        db_src = str(m_row[0]).strip().lower()
                        if db_src not in self._IMAGE_SOURCE_TYPES:
                            return None
                        if not effective_src:
                            effective_src = db_src
                    c_row = cur.execute(
                        "SELECT value FROM case_metadata WHERE LOWER(key) IN ('created_utc', 'created_at', 'case_created_utc') LIMIT 1;"
                    ).fetchone()
                    if c_row and c_row[0]:
                        case_created_dt = (
                            _to_naive_utc(c_row[0])
                            if isinstance(c_row[0], datetime)
                            else _parse_iso_to_naive_utc(str(c_row[0]))
                        )
                        if case_created_dt is not None:
                            cutoff_utc = min(cutoff_utc, case_created_dt - timedelta(seconds=120))

                if effective_src not in self._IMAGE_SOURCE_TYPES:
                    return None

                if "vfs_partitions" in tables:
                    non_img_part = cur.execute(
                        """
                        SELECT 1 FROM "vfs_partitions"
                        WHERE UPPER(TRIM(COALESCE(fs_type, ''))) IN ('FOLDER', 'DIRECTORY', 'ARCHIVE', 'LIVE')
                        LIMIT 1;
                        """
                    ).fetchone()
                    if non_img_part is not None:
                        return None

                if "vfs_files" not in tables:
                    return None

                vfs_cols = {
                    str(r[0]).lower(): str(r[0])
                    for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                }
                cr_exprs = [
                    self._quote_ident(vfs_cols[c])
                    for c in ("si_created", "si_created_utc", "fn_created", "fn_created_utc")
                    if c in vfs_cols
                ]
                if not cr_exprs:
                    return None
                mod_exprs = [
                    self._quote_ident(vfs_cols[c])
                    for c in ("si_modified", "si_modified_utc", "fn_modified", "fn_modified_utc")
                    if c in vfs_cols
                ]

                where_clauses: List[str] = []
                params: List[Any] = []
                if rel_candidates and "staged_rel_path" in vfs_cols:
                    q_srp = self._quote_ident(vfs_cols["staged_rel_path"])
                    ph = ", ".join(["?"] * len(rel_candidates))
                    where_clauses.append(
                        f"LOWER(TRIM(BOTH '/' FROM REPLACE(COALESCE({q_srp}, ''), chr(92), '/'))) IN ({ph})"
                    )
                    params.extend(rel_candidates)
                if vfs_cands and "vfs_path" in vfs_cols:
                    q_vp = self._quote_ident(vfs_cols["vfs_path"])
                    ph_v = ", ".join(["?"] * len(vfs_cands))
                    where_clauses.append(
                        f"LOWER(REPLACE(COALESCE({q_vp}, ''), '/', chr(92))) IN ({ph_v})"
                    )
                    params.extend(vfs_cands)

                if not where_clauses:
                    return None

                cr_sql = f"COALESCE({', '.join(cr_exprs)})"
                mod_sql = f"COALESCE({', '.join(mod_exprs)})" if mod_exprs else "NULL"
                where_sql = " OR ".join(where_clauses)
                row = cur.execute(
                    f'SELECT {cr_sql}, {mod_sql} FROM "vfs_files" WHERE {where_sql} LIMIT 1;',
                    params,
                ).fetchone()
                if row and row[0] is not None:
                    dt = (
                        _to_naive_utc(row[0])
                        if isinstance(row[0], datetime)
                        else _parse_iso_to_naive_utc(str(row[0]))
                    )
                    if dt is None or dt >= cutoff_utc:
                        return None
                    wallclock_fn = getattr(self, "_is_staging_wallclock_epoch", None)
                    if callable(wallclock_fn):
                        if wallclock_fn(dt.replace(tzinfo=timezone.utc).timestamp()):
                            return None
                    mod_dt: Optional[datetime] = None
                    if len(row) > 1 and row[1] is not None:
                        mod_dt = (
                            _to_naive_utc(row[1])
                            if isinstance(row[1], datetime)
                            else _parse_iso_to_naive_utc(str(row[1]))
                        )
                    if mod_dt is not None and dt > (mod_dt + timedelta(days=1)):
                        return None
                    if dt >= (self._case_start_naive_utc - timedelta(hours=24)):
                        if mod_dt is None:
                            return None
                    return dt
        except Exception:
            pass
        return None

    @staticmethod
    def _is_zone_identifier_filename(p: Path) -> bool:
        name_low = p.name.lower()
        return "zone.identifier" in name_low or p.name.endswith(":Zone.Identifier")

    _INTERNAL_OS_AND_APP_SUBPATHS: Tuple[str, ...] = (
        "/windows/",
        "/windows.old/",
        "/program files/",
        "/program files (x86)/",
        "/programdata/microsoft/",
        "/programdata/package cache/",
        "/system volume information/",
        "/recovery/",
        "/perflogs/",
        "/msocache/",
        "/$recycle.bin/$i",
        "/appdata/local/packages/",
        "/appdata/local/microsoft/",
        "/appdata/roaming/microsoft/",
        "/appdata/local/google/chrome/",
        "/appdata/local/microsoft/edge/",
        "/appdata/local/bravesoftware/",
        "/appdata/roaming/mozilla/firefox/",
        "/appdata/local/dropbox/",
        "/appdata/roaming/dropbox/",
        "/appdata/local/google/drive",
        "/appdata/local/microsoft/onedrive/",
        "/appdata/roaming/slack/",
        "/appdata/roaming/discord/",
        "/appdata/roaming/microsoft/teams/",
        "/node_modules/",
    )

    _INTERNAL_APP_SUBPATHS: Tuple[str, ...] = _INTERNAL_OS_AND_APP_SUBPATHS

    _SYSTEM_NOISE_FILENAMES: Set[str] = {
        "desktop.ini",
        "thumbs.db",
        "ntuser.ini",
        "msoirmprotector.doc",
        "msoirmprotector.ppt",
        "msoirmprotector.xls",
    }

    def _is_eligible_text_document(self, p: Path) -> bool:
        """Filter TXT/CSV/RTF so internal non-document OS/app artifacts and desktop.ini are excluded."""
        name_low = p.name.lower()
        if name_low in self._SYSTEM_NOISE_FILENAMES or self._is_zone_identifier_filename(p):
            return False
        try:
            rel = p.resolve().relative_to(self.staging_dir.resolve())
            parts_low = [seg.lower() for seg in rel.parts[:-1]]
            if parts_low and parts_low[0] == "vss" and len(parts_low) >= 3:
                top_bucket = parts_low[2]
            elif parts_low:
                top_bucket = parts_low[0]
            else:
                top_bucket = ""
            if top_bucket in _NON_DOC_STAGING_SUBTREES:
                return False
            rel_posix = "/" + rel.as_posix().lower() + "/"
            if any(sub in rel_posix for sub in self._INTERNAL_OS_AND_APP_SUBPATHS):
                return False
            for anc in p.parents:
                if anc.name.lower().endswith("_extracted") and (anc / "[Content_Types].xml").is_file():
                    return False
                if anc == self.staging_dir:
                    break
        except Exception:
            pass
        return True

    def _is_eligible_other_file(self, p: Path) -> bool:
        """Filter Other Files (.js, .py, .html, .css, etc.) so internal OS/app/browser/cloud metadata is excluded."""
        return self._is_eligible_text_document(p)

    _MOTW_STAGING_BUCKETS: Set[str] = {
        "enrichment",
        "zoneidentifier",
        "zoneidentifiers",
        "zone_identifier",
        "documents",
        "userfiles",
        "user_files",
        "media",
        "archives",
        "extracted",
        "carved",
        "files",
    }

    def _normalize_staging_motw_subpath(
        self,
        file_path: Path,
        override_leaf_name: Optional[str] = None,
    ) -> Tuple[str, str, str, str, bool]:
        """
        Normalize a staged path relative to `self.staging_dir.resolve()` into:
        `(vss_prefix, part_prefix, bucket_low, canonical_subpath, is_flat_zone_file)`
        Preserves `Part_<N>` partition isolation so `ZoneIdentifier/Part_0/...` never bleeds onto `Part_1`.
        """
        try:
            rel_parts = list(file_path.resolve().relative_to(self.staging_dir.resolve()).parts)
        except Exception:
            rel_parts = [file_path.name]

        if not rel_parts:
            leaf = (override_leaf_name or file_path.name).lower()
            return "", "", "", leaf, False

        if override_leaf_name is not None:
            rel_parts[-1] = override_leaf_name

        vss_prefix = ""
        if (
            len(rel_parts) >= 3
            and rel_parts[0].lower() == "vss"
            and re.match(r"^vss[_\-#]?\d+$", rel_parts[1], flags=re.IGNORECASE)
        ):
            vss_prefix = f"vss/{rel_parts[1].lower()}"
            rel_parts = rel_parts[2:]
        elif len(rel_parts) >= 2 and re.match(r"^vss[_\-#]?\d+$", rel_parts[0], flags=re.IGNORECASE):
            vss_prefix = f"vss/{rel_parts[0].lower()}"
            rel_parts = rel_parts[1:]

        bucket_low = ""
        if len(rel_parts) >= 2 and rel_parts[0].lower() in self._MOTW_STAGING_BUCKETS:
            bucket_low = rel_parts[0].lower()
            rel_parts = rel_parts[1:]

        part_prefix = ""
        if len(rel_parts) >= 2:
            m_part = re.match(
                r"^(?:part|partition|vol|volume)[_\-]?(\d+)$", rel_parts[0], flags=re.IGNORECASE
            )
            if m_part:
                part_prefix = f"part_{int(m_part.group(1))}"
                rel_parts = rel_parts[1:]

        if (
            bucket_low in ("userfiles", "user_files")
            and len(rel_parts) >= 2
            and rel_parts[0].lower() != "users"
        ):
            rel_parts = ["Users"] + rel_parts

        canonical_subpath = "/".join(seg.lower() for seg in rel_parts if seg)
        is_flat_zone = bucket_low.startswith("zone") and len(rel_parts) == 1
        return vss_prefix, part_prefix, bucket_low, canonical_subpath, is_flat_zone

    def _discover_and_cache_zone_identifiers(self) -> None:
        """Index ONLY strictly validated [ZoneTransfer] Zone.Identifier streams with path-scoped keys."""
        self.zone_by_target_path.clear()
        self.zone_by_canonical_subpath.clear()
        self.zone_by_zone_path.clear()
        self.zone_staging_by_name.clear()
        self.candidate_filename_counts.clear()
        self.consumed_zone_paths.clear()

        if not self.staging_dir.exists():
            return

        staging_res = self.staging_dir.resolve()
        for walk_root, dirs, files in os.walk(staging_res):
            root_p = Path(walk_root)
            if root_p == staging_res:
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in _NON_DOC_STAGING_SUBTREES
                ]
            for fname in files:
                p = root_p / fname
                if not self._is_zone_identifier_filename(p):
                    fn_low = fname.lower()
                    self.candidate_filename_counts[fn_low] = (
                        self.candidate_filename_counts.get(fn_low, 0) + 1
                    )
                    continue

                text = _read_zone_text(p)
                if not text:
                    continue
                meta = parse_zone_identifier(text)
                if not meta.get("valid"):
                    continue

                zone_key = str(p.resolve()).lower()
                meta["_zone_file_path"] = p
                meta["_zone_path_key"] = zone_key
                self.zone_by_zone_path[zone_key] = meta

                clean_name = re.sub(r"(?i)[:._]zone\.identifier.*$", "", p.name)
                if clean_name:
                    same_dir_target = (p.parent / clean_name).resolve()
                    self.zone_by_target_path[str(same_dir_target).lower()] = meta
                    vss_prefix, part_prefix, _bkt, canonical_subpath, is_flat_zone = (
                        self._normalize_staging_motw_subpath(p, override_leaf_name=clean_name)
                    )
                    if is_flat_zone:
                        self.zone_staging_by_name.setdefault(
                            (vss_prefix, clean_name.lower()), []
                        ).append(meta)
                    elif canonical_subpath and "/" in canonical_subpath:
                        self.zone_by_canonical_subpath[(vss_prefix, part_prefix, canonical_subpath)] = meta

    def _get_zone_info_for_file(self, file_path: Path) -> Dict[str, Any]:
        """Path-scoped MOTW lookup supporting EvidenceExtractor Part_<N> trees with zero cross-folder/partition bleed."""
        empty = {"zone_id": None, "host_url": None, "referrer_url": None}
        resolved_key = str(file_path.resolve()).lower()
        if resolved_key in self.zone_by_target_path:
            matched = self.zone_by_target_path[resolved_key]
            zpk = matched.get("_zone_path_key")
            if zpk:
                self.consumed_zone_paths.add(str(zpk))
            return matched

        candidates = [
            file_path.parent / f"{file_path.name}.Zone.Identifier",
            file_path.parent / f"{file_path.name}:Zone.Identifier",
            file_path.parent / f"{file_path.name}_Zone.Identifier",
            file_path.parent / f"{file_path.name}.Zone.Identifier.txt",
        ]
        for cand in candidates:
            if cand.is_file():
                meta = parse_zone_identifier(_read_zone_text(cand))
                if meta.get("valid"):
                    self.consumed_zone_paths.add(str(cand.resolve()).lower())
                    return meta

        vss_prefix, part_prefix, _bkt, canonical_subpath, _ = self._normalize_staging_motw_subpath(file_path)
        if canonical_subpath:
            exact_key = (vss_prefix, part_prefix, canonical_subpath)
            if exact_key in self.zone_by_canonical_subpath:
                matched = self.zone_by_canonical_subpath[exact_key]
                zpk = matched.get("_zone_path_key")
                if zpk:
                    self.consumed_zone_paths.add(str(zpk))
                return matched
            if part_prefix != "":
                unpart_key = (vss_prefix, "", canonical_subpath)
                if unpart_key in self.zone_by_canonical_subpath:
                    matched = self.zone_by_canonical_subpath[unpart_key]
                    zpk = matched.get("_zone_path_key")
                    if zpk:
                        self.consumed_zone_paths.add(str(zpk))
                    return matched
            else:
                part_matches = [
                    m for (vp, pp, cs), m in self.zone_by_canonical_subpath.items()
                    if vp == vss_prefix and pp != "" and cs == canonical_subpath
                ]
                if len(part_matches) == 1:
                    matched = part_matches[0]
                    zpk = matched.get("_zone_path_key")
                    if zpk:
                        self.consumed_zone_paths.add(str(zpk))
                    return matched

        fn_low = file_path.name.lower()
        staged_matches = self.zone_staging_by_name.get((vss_prefix, fn_low), [])
        if len(staged_matches) == 1 and self.candidate_filename_counts.get(fn_low, 0) == 1:
            zpk = staged_matches[0].get("_zone_path_key")
            if zpk:
                self.consumed_zone_paths.add(str(zpk))
            return staged_matches[0]

        return empty

    def _build_doc_record(
        self,
        file_path: Path,
        file_size: int,
        file_type: str,
        title: Optional[str],
        author: Optional[str],
        last_modified_by: Optional[str],
        created_time: Optional[datetime],
        modified_time: Optional[datetime],
        page_count: int,
        word_count: int,
        has_macros: bool,
        embedded_links: List[str],
        zone_info: Dict[str, Any],
        sha256: str,
    ) -> Dict[str, Any]:
        resolved = self.resolve_evidence_path(file_path, file_size)
        host_u = zone_info.get("host_url")
        ref_u = zone_info.get("referrer_url")
        return {
            "file_path": resolved,
            "file_name": file_path.name,
            "file_type": file_type,
            "file_size_bytes": file_size,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": _to_naive_utc(created_time),
            "modified_time": _to_naive_utc(modified_time),
            "page_count": int(page_count or 0),
            "word_count": int(word_count or 0),
            "has_macros": bool(has_macros),
            "embedded_links": json.dumps(embedded_links, ensure_ascii=False),
            "zone_id": zone_info.get("zone_id"),
            "zone_host_url": host_u,
            "zone_referrer_url": ref_u,
            "host_url": host_u,
            "referrer_url": ref_u,
            "sha256": sha256,
            "source_file": resolved,
        }

    def _parse_pdf(self, file_path: Path) -> Dict[str, Any]:
        """Extract PDF metadata, links, and JavaScript/EmbeddedFiles via PyMuPDF + pure-Python fallback."""
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        zone_info = self._get_zone_info_for_file(file_path)

        fb = _extract_pdf_fallback_metadata(file_path)
        title: Optional[str] = fb["title"]
        author: Optional[str] = fb["author"]
        last_modified_by: Optional[str] = fb["last_modified_by"]
        created_time: Optional[datetime] = fb["created_time"]
        modified_time: Optional[datetime] = fb["modified_time"]
        page_count: int = fb["page_count"]
        word_count: int = fb["word_count"]
        has_macros: bool = fb["has_macros"]
        embedded_links: List[str] = list(fb["embedded_links"])

        if HAS_FITZ and fitz is not None:
            doc = None
            try:
                doc = fitz.open(str(file_path))
                page_count = doc.page_count
                meta = doc.metadata or {}

                if meta.get("title"):
                    title = str(meta["title"]).strip() or title
                if meta.get("author"):
                    author = str(meta["author"]).strip() or author
                c_dt = parse_pdf_date(meta.get("creationDate"))
                if c_dt is not None:
                    created_time = c_dt
                m_dt = parse_pdf_date(meta.get("modDate"))
                if m_dt is not None:
                    modified_time = m_dt

                fitz_words = 0
                max_pages = min(page_count, 30)
                for i in range(max_pages):
                    page = doc[i]
                    for link in page.get_links():
                        uri = link.get("uri")
                        if uri and uri not in embedded_links:
                            embedded_links.append(uri)
                    txt = page.get_text()
                    if txt:
                        fitz_words += len(txt.split())
                if fitz_words > 0 or page_count >= 0:
                    word_count = fitz_words if fitz_words > 0 else word_count

                if doc.embfile_count() > 0:
                    has_macros = True
            except Exception as ex:
                self._log(f"PyMuPDF fallback notice reading {file_path.name}: {ex}", "DEBUG")
            finally:
                if doc is not None:
                    try:
                        doc.close()
                    except Exception:
                        pass

        return self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type="PDF",
            title=title,
            author=author,
            last_modified_by=last_modified_by,
            created_time=created_time,
            modified_time=modified_time,
            page_count=page_count,
            word_count=word_count,
            has_macros=has_macros,
            embedded_links=embedded_links,
            zone_info=zone_info,
            sha256=sha256,
        )

    def _parse_docx(self, file_path: Path, ext_override: Optional[str] = None) -> Dict[str, Any]:
        """Extract DOCX/DOCM metadata via python-docx + pure-Python OOXML ZIP/XML fallback."""
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = (ext_override or file_path.suffix).lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        fb = _extract_ooxml_zip_metadata(file_path, ext)
        title = fb["title"]
        author = fb["author"]
        last_modified_by = fb["last_modified_by"]
        created_time = fb["created_time"]
        modified_time = fb["modified_time"]
        page_count = fb["page_count"]
        word_count = fb["word_count"]
        has_macros = fb["has_macros"]
        embedded_links: List[str] = list(fb["embedded_links"])

        if HAS_DOCX and docx is not None and _is_ooxml_safe_for_dom_loader(file_path):
            try:
                with open(file_path, "rb") as _fh:
                    doc = docx.Document(_fh)
                    core = doc.core_properties
                    title = core.title or title
                    author = core.author or author
                    last_modified_by = core.last_modified_by or last_modified_by
                    if core.created:
                        created_time = _to_naive_utc(core.created) or created_time
                    if core.modified:
                        modified_time = _to_naive_utc(core.modified) or modified_time

                    para_words = sum(len(p.text.split()) for p in doc.paragraphs)
                    if para_words > 0:
                        word_count = max(word_count, para_words)

                    if hasattr(doc, "part") and hasattr(doc.part, "rels"):
                        for rel in doc.part.rels.values():
                            if "hyperlink" in str(rel.reltype).lower() and rel.target_ref:
                                if rel.target_ref not in embedded_links:
                                    embedded_links.append(rel.target_ref)
            except Exception as ex:
                self._log(f"python-docx fallback notice on {file_path.name}: {ex}", "DEBUG")

        return self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type=ext,
            title=title,
            author=author,
            last_modified_by=last_modified_by,
            created_time=created_time,
            modified_time=modified_time,
            page_count=page_count,
            word_count=word_count,
            has_macros=has_macros,
            embedded_links=embedded_links,
            zone_info=zone_info,
            sha256=sha256,
        )

    def _parse_xlsx(self, file_path: Path, ext_override: Optional[str] = None) -> Dict[str, Any]:
        """Extract XLSX/XLSM metadata via openpyxl + pure-Python OOXML ZIP/XML fallback."""
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = (ext_override or file_path.suffix).lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        fb = _extract_ooxml_zip_metadata(file_path, ext)
        title = fb["title"]
        author = fb["author"]
        last_modified_by = fb["last_modified_by"]
        created_time = fb["created_time"]
        modified_time = fb["modified_time"]
        sheet_count = fb["page_count"]
        has_macros = fb["has_macros"]
        embedded_links: List[str] = list(fb["embedded_links"])

        if HAS_OPENPYXL and openpyxl is not None and _is_ooxml_safe_for_dom_loader(file_path):
            wb = None
            try:
                with open(file_path, "rb") as _fh:
                    wb = openpyxl.load_workbook(_fh, read_only=True, data_only=True)
                    props = wb.properties
                    title = props.title or title
                    author = props.creator or author
                    last_modified_by = props.lastModifiedBy or last_modified_by
                    if props.created:
                        created_time = _to_naive_utc(props.created) or created_time
                    if props.modified:
                        modified_time = _to_naive_utc(props.modified) or modified_time
                    if wb.sheetnames:
                        sheet_count = len(wb.sheetnames)
                    wb.close()
                    wb = None
            except Exception as ex:
                self._log(f"openpyxl fallback notice on {file_path.name}: {ex}", "DEBUG")
            finally:
                if wb is not None:
                    try:
                        wb.close()
                    except Exception:
                        pass

        return self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type=ext,
            title=title,
            author=author,
            last_modified_by=last_modified_by,
            created_time=created_time,
            modified_time=modified_time,
            page_count=sheet_count,
            word_count=0,
            has_macros=has_macros,
            embedded_links=embedded_links,
            zone_info=zone_info,
            sha256=sha256,
        )

    def _parse_pptx(self, file_path: Path, ext_override: Optional[str] = None) -> Dict[str, Any]:
        """Extract PPTX/PPTM metadata via python-pptx + pure-Python OOXML ZIP/XML fallback."""
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = (ext_override or file_path.suffix).lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        fb = _extract_ooxml_zip_metadata(file_path, ext)
        title = fb["title"]
        author = fb["author"]
        last_modified_by = fb["last_modified_by"]
        created_time = fb["created_time"]
        modified_time = fb["modified_time"]
        slide_count = fb["page_count"]
        has_macros = fb["has_macros"]
        embedded_links: List[str] = list(fb["embedded_links"])

        if HAS_PPTX and pptx is not None and _is_ooxml_safe_for_dom_loader(file_path):
            try:
                with open(file_path, "rb") as _fh:
                    prs = pptx.Presentation(_fh)
                    slide_count = len(prs.slides)
                    core = prs.core_properties
                    title = core.title or title
                    author = core.author or author
                    last_modified_by = core.last_modified_by or last_modified_by
                    if core.created:
                        created_time = _to_naive_utc(core.created) or created_time
                    if core.modified:
                        modified_time = _to_naive_utc(core.modified) or modified_time
            except Exception as ex:
                self._log(f"python-pptx fallback notice on {file_path.name}: {ex}", "DEBUG")

        return self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type=ext,
            title=title,
            author=author,
            last_modified_by=last_modified_by,
            created_time=created_time,
            modified_time=modified_time,
            page_count=slide_count,
            word_count=0,
            has_macros=has_macros,
            embedded_links=embedded_links,
            zone_info=zone_info,
            sha256=sha256,
        )

    def _parse_ole_legacy(self, file_path: Path, ext_override: Optional[str] = None) -> Dict[str, Any]:
        """Extract legacy Office OLE2 metadata via olefile + pure-Python CFB SummaryInformation fallback."""
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = (ext_override or file_path.suffix).lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        title: Optional[str] = None
        author: Optional[str] = None
        last_modified_by: Optional[str] = None
        created_time: Optional[datetime] = None
        modified_time: Optional[datetime] = None
        page_count = 1
        word_count = 0
        has_macros = False
        parsed_via_olefile = False

        if HAS_OLEFILE and olefile is not None:
            try:
                if olefile.isOleFile(str(file_path)):
                    ole = olefile.OleFileIO(str(file_path))
                    try:
                        meta = ole.get_metadata()

                        def _dec_meta(v: Any) -> Optional[str]:
                            if v is None:
                                return None
                            if isinstance(v, bytes):
                                s = v.decode("cp1252", errors="replace").rstrip("\x00").strip()
                                return s or None
                            s = str(v).rstrip("\x00").strip()
                            return s or None

                        title = _dec_meta(meta.title)
                        author = _dec_meta(meta.author)
                        last_modified_by = _dec_meta(meta.last_saved_by)
                        if meta.create_time:
                            created_time = _to_naive_utc(meta.create_time)
                        if meta.last_saved_time:
                            modified_time = _to_naive_utc(meta.last_saved_time)
                        if getattr(meta, "num_pages", None) and int(meta.num_pages) > 0:
                            page_count = int(meta.num_pages)
                        if getattr(meta, "num_words", None) and int(meta.num_words) >= 0:
                            word_count = int(meta.num_words)

                        for stream_parts in ole.listdir():
                            s_lower = "/".join(stream_parts).lower()
                            if any(k in s_lower for k in ("vba", "macros", "_vba_project")):
                                has_macros = True
                                break
                        parsed_via_olefile = True
                    finally:
                        ole.close()
            except Exception as ex:
                self._log(f"olefile fallback notice on {file_path.name}: {ex}", "DEBUG")

        if not parsed_via_olefile:
            fb = _extract_cfb_summary_fallback(file_path)
            title = fb["title"]
            author = fb["author"]
            last_modified_by = fb["last_modified_by"]
            created_time = fb["created_time"]
            modified_time = fb["modified_time"]
            page_count = fb["page_count"]
            word_count = fb["word_count"]
            has_macros = fb["has_macros"]

        return self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type=ext,
            title=title,
            author=author,
            last_modified_by=last_modified_by,
            created_time=created_time,
            modified_time=modified_time,
            page_count=page_count,
            word_count=word_count,
            has_macros=has_macros,
            embedded_links=[],
            zone_info=zone_info,
            sha256=sha256,
        )

    def _parse_text_csv_rtf(
        self,
        file_path: Path,
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """
        Parse .txt, .csv, and .rtf documents, returning (doc_metadata_row, text_document_row)
        or None if file is unreadable/binary garbage.
        """
        try:
            file_size = file_path.stat().st_size
            with open(file_path, "rb") as f:
                raw_sample = f.read(min(file_size, 2 * 1024 * 1024))
        except OSError:
            return None

        sfx = file_path.suffix.lower()
        file_type = sfx.lstrip(".").upper()
        sha256 = compute_sha256(file_path)
        zone_info = self._get_zone_info_for_file(file_path)
        vfs_ctime = self._get_original_ctime_dt(file_path)
        vfs_mtime = self._get_original_mtime_dt(file_path)

        title: Optional[str] = None
        author: Optional[str] = None
        last_modified_by: Optional[str] = None
        created_time: Optional[datetime] = vfs_ctime
        modified_time: Optional[datetime] = vfs_mtime
        page_count = 1

        if sfx == ".rtf":
            raw_ascii = raw_sample.decode("cp1252", errors="replace")
            if not raw_ascii.lstrip().startswith("{\\rtf"):
                decoded, enc_name, is_bin = _decode_text_with_encoding(raw_sample)
                if is_bin:
                    return None
                plain_text = decoded
            else:
                enc_name = "rtf/cp1252"
                m_info = re.search(r"\{\\info\b((?:[^{}]|\{[^{}]*\})*)\}", raw_ascii, re.DOTALL)
                if m_info:
                    info_grp = m_info.group(1)
                    m_t = re.search(r"\{\\title\s+([^{}]+)\}", info_grp)
                    if m_t:
                        title = _strip_rtf_to_plain(m_t.group(1))[:200] or None
                    m_a = re.search(r"\{\\author\s+([^{}]+)\}", info_grp)
                    if m_a:
                        author = _strip_rtf_to_plain(m_a.group(1))[:200] or None
                    m_op = re.search(r"\{\\operator\s+([^{}]+)\}", info_grp)
                    if m_op:
                        last_modified_by = _strip_rtf_to_plain(m_op.group(1))[:200] or None
                    m_cr = re.search(r"\{\\creatim\b([^{}]+)\}", info_grp)
                    if m_cr:
                        created_time = _parse_rtf_time_group(m_cr.group(1)) or created_time
                    m_rv = re.search(r"\{\\revtim\b([^{}]+)\}", info_grp)
                    if m_rv:
                        modified_time = _parse_rtf_time_group(m_rv.group(1)) or modified_time
                    m_pg = re.search(r"\\nofpages(\d+)", info_grp)
                    if m_pg and int(m_pg.group(1)) > 0:
                        page_count = int(m_pg.group(1))
                plain_text = _strip_rtf_to_plain(raw_ascii)
        else:
            decoded, enc_name, is_bin = _decode_text_with_encoding(raw_sample)
            if is_bin:
                return None
            plain_text = decoded
            if sfx == ".csv" and plain_text.strip():
                try:
                    reader = csv.reader(io.StringIO(plain_text[:65536]))
                    first_row = next(reader, None)
                    if first_row:
                        clean_hdrs = [c.strip() for c in first_row if c.strip()]
                        if clean_hdrs:
                            hdr_summary = ", ".join(clean_hdrs[:8])
                            title = f"CSV ({len(first_row)} cols: {hdr_summary})"[:200]
                except Exception:
                    pass
            elif sfx in (".html", ".htm", ".xhtml") and plain_text.strip():
                m_html_t = re.search(r"<title[^>]*>(.*?)</title>", plain_text[:65536], re.IGNORECASE | re.DOTALL)
                if m_html_t and m_html_t.group(1).strip():
                    title = " ".join(m_html_t.group(1).split())[:200]
                else:
                    for ln in plain_text.splitlines():
                        s_ln = ln.strip()
                        if s_ln:
                            title = s_ln[:120]
                            break
            elif plain_text.strip():
                for ln in plain_text.splitlines():
                    s_ln = ln.strip()
                    if s_ln:
                        title = s_ln[:120]
                        break

        lines = plain_text.splitlines()
        line_count = len(lines)
        word_count = len(plain_text.split())
        char_count = len(plain_text)
        preview = " ".join(plain_text.split())[:1000]
        links = list(dict.fromkeys(_URL_EXTRACT_RE.findall(plain_text)))[:50]

        doc_row = self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type=file_type,
            title=title,
            author=author,
            last_modified_by=last_modified_by,
            created_time=created_time,
            modified_time=modified_time,
            page_count=page_count,
            word_count=word_count,
            has_macros=False,
            embedded_links=links,
            zone_info=zone_info,
            sha256=sha256,
        )

        host_u = zone_info.get("host_url")
        ref_u = zone_info.get("referrer_url")
        resolved = doc_row["file_path"]
        txt_row: Dict[str, Any] = {
            "file_path": resolved,
            "file_name": file_path.name,
            "file_type": file_type,
            "extension": sfx,
            "file_size_bytes": file_size,
            "encoding": enc_name,
            "line_count": line_count,
            "word_count": word_count,
            "char_count": char_count,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": _to_naive_utc(created_time),
            "modified_time": _to_naive_utc(modified_time),
            "content_preview": preview,
            "text_preview": preview,
            "embedded_links": json.dumps(links, ensure_ascii=False),
            "zone_id": zone_info.get("zone_id"),
            "zone_host_url": host_u,
            "zone_referrer_url": ref_u,
            "host_url": host_u,
            "referrer_url": ref_u,
            "sha256": sha256,
            "source_file": resolved,
        }
        return doc_row, txt_row

    def _parse_standalone_zone_identifier(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Record strictly validated standalone/orphan [ZoneTransfer] Zone.Identifier activity.
        Skips sidecars already attached to a companion document row in parsed_documents_metadata,
        and returns None (inserting 0 rows) if [ZoneTransfer] or valid ZoneId in {0..4} is absent!
        """
        zone_key = str(file_path.resolve()).lower()
        if zone_key in self.consumed_zone_paths:
            return None
        cached = self.zone_by_zone_path.get(zone_key)
        meta = cached if cached is not None else parse_zone_identifier(_read_zone_text(file_path))
        if not meta.get("valid") or meta.get("zone_id") is None:
            return None

        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ctime = self._get_original_ctime_dt(file_path)
        mtime = self._get_original_mtime_dt(file_path)
        target_name = re.sub(r"(?i)[:._]zone\.identifier.*$", "", file_path.name)
        links = [u for u in (meta.get("host_url"), meta.get("referrer_url")) if u]

        return self._build_doc_record(
            file_path=file_path,
            file_size=file_size,
            file_type="ZONE_IDENTIFIER",
            title=f"Zone.Identifier for {target_name or file_path.stem}",
            author=None,
            last_modified_by=None,
            created_time=ctime,
            modified_time=mtime,
            page_count=1,
            word_count=0,
            has_macros=False,
            embedded_links=links,
            zone_info=meta,
            sha256=sha256,
        )

    @staticmethod
    def _detect_disguised_office_or_pdf(p: Path) -> Optional[str]:
        """
        Forensic magic-header + container-structure detection for extension-masqueraded
        PDF, OOXML (.docx/.xlsx/.pptx), and OLE2 (.doc/.xls/.ppt) documents.
        Skips unpacked OOXML internal sub-parts (`*_extracted/[Content_Types].xml`) and
        non-Office CFB/ZIP files (JumpLists, MSI, Thumbs.db, Outlook MSG, plain ZIP).
        """
        try:
            for anc in p.parents:
                if anc.name.lower().endswith("_extracted") and (anc / "[Content_Types].xml").is_file():
                    return None
                if anc == p.parent.parent.parent.parent.parent:
                    break
            st_sz = p.stat().st_size
            if st_sz < 64 or st_sz > _OOXML_MAX_TOTAL_UNCOMPRESSED_BYTES:
                return None
            with open(p, "rb") as fh:
                head8 = fh.read(8)
            if head8.startswith(b"%PDF-"):
                return ".pdf"
            if head8.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(p, "r") as zf:
                    names = {n.lower().lstrip("/") for n in zf.namelist()[:_OOXML_MAX_MEMBER_COUNT]}
                if "word/document.xml" in names:
                    return ".docx"
                if "xl/workbook.xml" in names:
                    return ".xlsx"
                if "ppt/presentation.xml" in names:
                    return ".pptx"
                return None
            if head8 == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                if HAS_OLEFILE and olefile is not None and olefile.isOleFile(str(p)):
                    ole = olefile.OleFileIO(str(p))
                    try:
                        top_names = {
                            parts[0].lower()
                            for parts in ole.listdir(streams=True, storages=True)
                            if parts
                        }
                    finally:
                        ole.close()
                    if "worddocument" in top_names:
                        return ".doc"
                    if "workbook" in top_names or "book" in top_names:
                        return ".xls"
                    if "powerpoint document" in top_names:
                        return ".ppt"
                    return None
                with open(p, "rb") as fh:
                    blob = fh.read(min(st_sz, 2 * 1024 * 1024))
                if "WordDocument".encode("utf-16le") in blob:
                    return ".doc"
                if "Workbook".encode("utf-16le") in blob:
                    return ".xls"
                if "PowerPoint Document".encode("utf-16le") in blob:
                    return ".ppt"
        except Exception:
            return None
        return None

    def parse(self, max_workers: int = 16) -> Dict[str, int]:
        """
        Scan staging directory for Office/PDF documents, TXT/CSV/RTF files, and Zone.Identifier streams.
        Populates parsed_documents_metadata and parsed_text_documents safely under DuckDBManager.get_lock.
        """
        start_time = time.time()
        workers = max(1, min(32, int(max_workers or 16)))
        self._log(f"Starting DocumentParser across staging directory: {self.staging_dir} (workers={workers})")

        self._preload_vfs_time_cache()
        self._get_vfs_staged_cache()
        self._get_mft_index_cache()
        self._discover_and_cache_zone_identifiers()
        self._log(f"Indexed {len(self.zone_by_zone_path)} validated Zone.Identifier streams.")

        all_doc_records: List[Dict[str, Any]] = []
        all_txt_records: List[Dict[str, Any]] = []
        candidate_docs: List[Tuple[Path, Optional[str]]] = []
        candidate_txt_docs: List[Path] = []
        candidate_other_files: List[Path] = []
        candidate_zones: List[Path] = []

        # Known non-document binary extensions that never need disguised-doc header sniffing
        _SKIP_DISGUISED_EXTS: Set[str] = {
            ".evtx", ".etl", ".pf", ".dll", ".exe", ".sys", ".mui", ".cat", ".nls",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff",
            ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ogg", ".webm",
            ".sqlite", ".sqlite3", ".db", ".db-wal", ".db-shm", ".hve", ".regtrans-ms", ".blf",
            ".log1", ".log2", ".lnk", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".map",
            ".duckdb", ".wal", ".pak", ".asar", ".vdm",
        }

        if self.staging_dir.exists():
            staging_res = self.staging_dir.resolve()
            for walk_root, dirs, files in os.walk(staging_res):
                root_p = Path(walk_root)
                # Prune known non-document OS metadata staging roots at top level (keep ZoneIdentifier)
                if root_p == staging_res:
                    dirs[:] = [
                        d for d in dirs
                        if d.lower() not in _NON_DOC_STAGING_SUBTREES
                    ]
                for fname in files:
                    p = root_p / fname
                    sfx = p.suffix.lower()
                    if self._is_zone_identifier_filename(p):
                        candidate_zones.append(p)
                    elif sfx in self.DOC_EXTENSIONS:
                        candidate_docs.append((p, None))
                    elif sfx in self.TXT_DOC_EXTENSIONS:
                        disguised_sfx = self._detect_disguised_office_or_pdf(p)
                        if disguised_sfx is not None:
                            candidate_docs.append((p, disguised_sfx))
                        elif self._is_eligible_text_document(p):
                            candidate_txt_docs.append(p)
                    elif sfx in self.OTHER_FILE_EXTENSIONS:
                        disguised_sfx = self._detect_disguised_office_or_pdf(p)
                        if disguised_sfx is not None:
                            candidate_docs.append((p, disguised_sfx))
                        elif self._is_eligible_other_file(p):
                            candidate_other_files.append(p)
                    elif sfx not in _SKIP_DISGUISED_EXTS:
                        disguised_sfx = self._detect_disguised_office_or_pdf(p)
                        if disguised_sfx is not None:
                            candidate_docs.append((p, disguised_sfx))

        self._log(
            f"Found {len(candidate_docs)} Office/PDF docs, {len(candidate_txt_docs)} TXT/CSV/RTF docs, "
            f"{len(candidate_other_files)} Other Files (.js/.py/.html/.css/etc.), "
            f"and {len(candidate_zones)} candidate Zone.Identifier files."
        )

        # 1. Parse Office & PDF documents concurrently
        def _parse_one_doc(item: Tuple[Path, Optional[str]]) -> Optional[Dict[str, Any]]:
            doc_file, sfx_override = item
            sfx = sfx_override or doc_file.suffix.lower()
            try:
                if sfx == ".pdf":
                    return self._parse_pdf(doc_file)
                if sfx in (".docx", ".docm"):
                    return self._parse_docx(doc_file, ext_override=sfx_override)
                if sfx in (".xlsx", ".xlsm"):
                    return self._parse_xlsx(doc_file, ext_override=sfx_override)
                if sfx in (".pptx", ".pptm"):
                    return self._parse_pptx(doc_file, ext_override=sfx_override)
                if sfx in (".doc", ".xls", ".ppt"):
                    return self._parse_ole_legacy(doc_file, ext_override=sfx_override)
                return None
            except Exception as ex:
                self._log(f"Error parsing document {doc_file}: {ex}", "WARNING")
                return None

        if workers > 1 and len(candidate_docs) > 2:
            with ThreadPoolExecutor(max_workers=min(workers, len(candidate_docs))) as pool:
                for rec in pool.map(_parse_one_doc, candidate_docs):
                    if rec is not None:
                        all_doc_records.append(rec)
        else:
            for item in candidate_docs:
                rec = _parse_one_doc(item)
                if rec is not None:
                    all_doc_records.append(rec)

        # 2. Parse TXT / CSV / RTF and Other Files (.js, .py, .html, .css, etc.) concurrently into BOTH parsed_text_documents and parsed_documents_metadata
        def _parse_one_txt(txt_file: Path) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
            try:
                return self._parse_text_csv_rtf(txt_file)
            except Exception as ex:
                self._log(f"Error parsing text/other file {txt_file}: {ex}", "WARNING")
                return None

        all_text_like_candidates = candidate_txt_docs + candidate_other_files
        if workers > 1 and len(all_text_like_candidates) > 2:
            with ThreadPoolExecutor(max_workers=min(workers, len(all_text_like_candidates))) as pool:
                for parsed_pair in pool.map(_parse_one_txt, all_text_like_candidates):
                    if parsed_pair is not None:
                        all_doc_records.append(parsed_pair[0])
                        all_txt_records.append(parsed_pair[1])
        else:
            for txt_file in all_text_like_candidates:
                parsed_pair = _parse_one_txt(txt_file)
                if parsed_pair is not None:
                    all_doc_records.append(parsed_pair[0])
                    all_txt_records.append(parsed_pair[1])

        # 3. Parse strictly validated standalone Zone.Identifier files
        for zone_file in candidate_zones:
            try:
                z_rec = self._parse_standalone_zone_identifier(zone_file)
                if z_rec is not None:
                    all_doc_records.append(z_rec)
            except Exception as ex:
                self._log(f"Error parsing Zone.Identifier {zone_file}: {ex}", "WARNING")

        # Deduplicate preserving distinct file paths across folders
        unique_docs: List[Dict[str, Any]] = []
        seen_docs: Set[Tuple[str, str, int, str]] = set()
        for rec in all_doc_records:
            d_key = (
                str(rec.get("file_path") or "").strip().lower(),
                str(rec.get("file_type") or "").strip().lower(),
                int(rec.get("file_size_bytes") or 0),
                str(rec.get("sha256") or "").strip().lower(),
            )
            if d_key not in seen_docs:
                seen_docs.add(d_key)
                unique_docs.append(rec)

        unique_txts: List[Dict[str, Any]] = []
        seen_txts: Set[Tuple[str, int, str]] = set()
        for trec in all_txt_records:
            t_key = (
                str(trec.get("file_path") or "").strip().lower(),
                int(trec.get("file_size_bytes") or 0),
                str(trec.get("sha256") or "").strip().lower(),
            )
            if t_key not in seen_txts:
                seen_txts.add(t_key)
                unique_txts.append(trec)

        with DuckDBManager.get_lock(self.case_id):
            doc_count = self.insert_records(
                table_name="parsed_documents_metadata",
                records=unique_docs,
                schema_ddl=DOCUMENTS_METADATA_SCHEMA_DDL,
            )
            txt_count = self.insert_records(
                table_name="parsed_text_documents",
                records=unique_txts,
                schema_ddl=TEXT_DOCUMENTS_SCHEMA_DDL,
            )
            # Refresh all document category views in artifact_registry if already created
            try:
                cur = self._get_conn().cursor()
                existing_views = {
                    str(r[0])
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema='main' AND table_name LIKE 'view_doc%';"
                    ).fetchall()
                }
                for v_id, v_tbl in (
                    ("docs_pdf", "view_docs_pdf"),
                    ("docs_word", "view_docs_word"),
                    ("docs_excel", "view_docs_excel"),
                    ("docs_ppt", "view_docs_ppt"),
                    ("docs_txt", "view_docs_txt"),
                    ("docs_other", "view_docs_other"),
                    ("view_documents", "view_documents"),
                ):
                    if v_tbl in existing_views:
                        v_cnt_row = cur.execute(f'SELECT COUNT(*) FROM "{v_tbl}";').fetchone()
                        v_cnt = int(v_cnt_row[0] or 0) if v_cnt_row else 0
                        cur.execute(
                            "UPDATE artifact_registry SET row_count = ?, last_updated = now() WHERE artifact_id = ? OR table_name = ?;",
                            [v_cnt, v_id, v_tbl],
                        )
            except Exception:
                pass

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Document",
            command_executed=(
                f"DocumentParser.parse({len(candidate_docs)} docs, "
                f"{len(candidate_txt_docs)} txt, {len(candidate_other_files)} other, {len(candidate_zones)} zones)"
            ),
            exit_code=0,
            rows_ingested=doc_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"DocumentParser complete in {duration_ms}ms: {doc_count} document metadata rows, "
            f"{txt_count} plain-text document rows ingested."
        )
        return {
            "parsed_documents_metadata": doc_count,
            "parsed_text_documents": txt_count,
        }
