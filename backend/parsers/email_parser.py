"""
Windows Forensic Toolkit (WFT) DFIR Suite - Corporate Email & Mail Store Parser
Parses:
1. RFC 822 Email messages (.eml) via standard library email package (charset-aware + Received fallback)
2. MBOX mail storage (.mbox) via standard library mailbox package (safe handle cleanup)
3. Microsoft Outlook Compound File Binary Messages (.msg) via extract_msg + olefile MAPI fallback
4. Microsoft Outlook Personal/Offline Storage Tables (.pst, .ost) via 3-tier engine:
   - Tier 1: pypff (libpff) recursive folder, message, MAPI record-set & attachment extraction
   - Tier 2: Pure-Python [MS-PST] !BDN NDB parser (ANSI 32-bit & Unicode 64-bit BTree,
             CryptPermute/CryptCyclic, XBLOCK/SLBLOCK, HN/BTH Property Context & attachment subnodes)
   - Tier 3: Strict RFC 822 header block scanner (zero fabricated senders, IDs, or timestamps)
Saves all discovered attachments into staging/Extracted_Archives/Email_Attachments/
and populates DuckDB tables parsed_emails and parsed_email_attachments.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import html
import mailbox
import os
import re
import struct
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import pypff
except ImportError:
    pypff = None  # type: ignore[assignment]

try:
    import extract_msg
except ImportError:
    extract_msg = None  # type: ignore[assignment]

try:
    import olefile
except ImportError:
    olefile = None  # type: ignore[assignment]

try:
    import compressed_rtf
except ImportError:
    compressed_rtf = None  # type: ignore[assignment]

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser


EMAIL_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_emails (
    _row_id BIGINT,
    email_format VARCHAR,
    sender VARCHAR,
    recipients VARCHAR,
    cc VARCHAR,
    bcc VARCHAR,
    subject VARCHAR,
    date_utc TIMESTAMP,
    message_id VARCHAR,
    body_snippet VARCHAR,
    attachments_count INTEGER,
    attachment_count INTEGER,
    attachment_names VARCHAR,
    client_submit_time TIMESTAMP,
    is_suspicious BOOLEAN,
    suspicious_indicators VARCHAR,
    source_file VARCHAR
);
"""

EMAIL_ATTACHMENTS_DDL = """
CREATE TABLE IF NOT EXISTS parsed_email_attachments (
    _row_id BIGINT,
    email_id VARCHAR,
    file_name VARCHAR,
    file_size BIGINT,
    mime_type VARCHAR,
    sha256 VARCHAR,
    is_malicious BOOLEAN,
    source_file VARCHAR
);
"""

# [MS-PST] Section 5.1 Permutative & Cyclic Cipher Tables (mpbbR, mpbbS, mpbbI)
_PST_MPBBR: bytes = bytes([
    71, 241, 180, 230, 11, 106, 114, 72, 133, 78, 158, 235, 226, 248, 148, 83,
    224, 187, 160, 2, 232, 90, 9, 171, 219, 227, 186, 198, 124, 195, 16, 221,
    57, 5, 150, 48, 245, 55, 96, 130, 140, 201, 19, 74, 107, 29, 243, 251,
    143, 38, 151, 202, 145, 23, 1, 196, 50, 45, 110, 49, 149, 255, 217, 35,
    209, 0, 94, 121, 220, 68, 59, 26, 40, 197, 97, 87, 32, 144, 61, 131,
    185, 67, 190, 103, 210, 70, 66, 118, 192, 109, 91, 126, 178, 15, 22, 41,
    60, 169, 3, 84, 13, 218, 93, 223, 246, 183, 199, 98, 205, 141, 6, 211,
    105, 92, 134, 214, 20, 247, 165, 102, 117, 172, 177, 233, 69, 33, 112, 12,
    135, 159, 116, 164, 34, 76, 111, 191, 31, 86, 170, 46, 179, 120, 51, 80,
    176, 163, 146, 188, 207, 25, 28, 167, 99, 203, 30, 77, 62, 75, 27, 155,
    79, 231, 240, 238, 173, 58, 181, 89, 4, 234, 64, 85, 37, 81, 229, 122,
    137, 56, 104, 82, 123, 252, 39, 174, 215, 189, 250, 7, 244, 204, 142, 95,
    239, 53, 156, 132, 43, 21, 213, 119, 52, 73, 182, 18, 10, 127, 113, 136,
    253, 157, 24, 65, 125, 147, 216, 88, 44, 206, 254, 36, 175, 222, 184, 54,
    200, 161, 128, 166, 153, 152, 168, 47, 14, 129, 101, 115, 228, 194, 162, 138,
    212, 225, 17, 208, 8, 139, 42, 242, 237, 154, 100, 63, 193, 108, 249, 236,
])

_PST_MPBBS: bytes = bytes([
    20, 83, 15, 86, 179, 200, 122, 156, 235, 101, 72, 23, 22, 21, 159, 2,
    204, 84, 124, 131, 0, 13, 12, 11, 162, 98, 168, 118, 219, 217, 237, 199,
    197, 164, 220, 172, 133, 116, 214, 208, 167, 155, 174, 154, 150, 113, 102, 195,
    99, 153, 184, 221, 115, 146, 142, 132, 125, 165, 94, 209, 93, 147, 177, 87,
    81, 80, 128, 137, 82, 148, 79, 78, 10, 107, 188, 141, 127, 110, 71, 70,
    65, 64, 68, 1, 17, 203, 3, 63, 247, 244, 225, 169, 143, 60, 58, 249,
    251, 240, 25, 48, 130, 9, 46, 201, 157, 160, 134, 73, 238, 111, 77, 109,
    196, 45, 129, 52, 37, 135, 27, 136, 170, 252, 6, 161, 18, 56, 253, 76,
    66, 114, 100, 19, 55, 36, 106, 117, 119, 67, 255, 230, 180, 75, 54, 92,
    228, 216, 53, 61, 69, 185, 44, 236, 183, 49, 43, 41, 7, 104, 163, 14,
    105, 123, 24, 158, 33, 57, 190, 40, 26, 91, 120, 245, 35, 202, 42, 176,
    175, 62, 254, 4, 140, 231, 229, 152, 50, 149, 211, 246, 74, 232, 166, 234,
    233, 243, 213, 47, 112, 32, 242, 31, 5, 103, 173, 85, 16, 206, 205, 227,
    39, 59, 218, 186, 215, 194, 38, 212, 145, 29, 210, 28, 34, 51, 248, 250,
    241, 90, 239, 207, 144, 182, 139, 181, 189, 192, 191, 8, 151, 30, 108, 226,
    97, 224, 198, 193, 89, 171, 187, 88, 222, 95, 223, 96, 121, 126, 178, 138,
])

_PST_MPBBI_LIST = [0] * 256
for _idx_r, _val_r in enumerate(_PST_MPBBR):
    _PST_MPBBI_LIST[_val_r] = _idx_r
_PST_MPBBI: bytes = bytes(_PST_MPBBI_LIST)

_FILETIME_EPOCH_DIFF_TICKS = 116444736000000000
_RISKY_ATTACHMENT_EXTS: Set[str] = {
    ".exe", ".scr", ".hta", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".cpl", ".pif",
    ".com", ".dll", ".lnk", ".iso", ".img", ".vhd", ".vhdx",
}
_HTML_STYLE_SCRIPT_RE = re.compile(r"(?is)<(script|style)\b[^>]*>.*?</\1>")
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def compute_sha256(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA256 digest of bytes."""
    return hashlib.sha256(data).hexdigest().lower()


def sanitize_filename(filename: str, fallback: str = "attachment.bin") -> str:
    """Sanitize filename against path traversal and forbidden characters."""
    if not filename or not isinstance(filename, str):
        return fallback
    normalized = filename.strip().replace("\\", "/")
    clean = os.path.basename(normalized)
    clean = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", clean)
    if not clean or clean in (".", ".."):
        return fallback
    return clean[:200]


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize a datetime to naive UTC so DuckDB TIMESTAMP never shifts by host timezone (+05:30),
    rejecting sentinel/invalid years (e.g. 1601-01-01 or 1970-01-01 00:00:00).
    """
    if dt is None:
        return None
    norm = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt
    if norm.year < 1971 or norm.year > 2100:
        return None
    return norm


def _filetime_int_to_naive_utc(ft_ticks: int) -> Optional[datetime]:
    """Convert 64-bit integer Windows FILETIME (100-ns ticks since 1601-01-01) to naive UTC datetime."""
    if not isinstance(ft_ticks, int) or ft_ticks <= _FILETIME_EPOCH_DIFF_TICKS:
        return None
    unix_100ns = ft_ticks - _FILETIME_EPOCH_DIFF_TICKS
    seconds, rem_100ns = divmod(unix_100ns, 10_000_000)
    if seconds <= 31536000 or seconds > 4102444800:
        return None
    try:
        base = datetime(1970, 1, 1) + timedelta(seconds=seconds, microseconds=rem_100ns // 10)
        return _to_naive_utc(base)
    except (OverflowError, ValueError):
        return None


def parse_rfc2822_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse RFC 2822 / ISO-8601 email Date header mathematically to naive UTC datetime."""
    if not date_str or not isinstance(date_str, str):
        return None
    cleaned = date_str.strip()
    if not cleaned:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(cleaned)
        return _to_naive_utc(dt)
    except Exception:
        pass
    try:
        iso_cand = cleaned.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_cand)
        return _to_naive_utc(dt)
    except Exception:
        return None


def _extract_date_from_received_headers(msg: email.message.Message) -> Optional[datetime]:
    """Fallback date parser inspecting the top-most RFC 822 Received header."""
    received_list = msg.get_all("received") or []
    for rec_hdr in received_list:
        rec_str = str(rec_hdr or "")
        if ";" in rec_str:
            tail = rec_str.rsplit(";", 1)[-1].strip()
            dt = parse_rfc2822_date(tail)
            if dt is not None:
                return dt
    return None


def _decode_bytes_with_charset(payload: bytes, charset_hint: Optional[str] = None) -> str:
    """Decode byte payload honoring MIME charset with UTF-16/UTF-8/CP1252 fallbacks."""
    if not payload:
        return ""
    if payload.startswith(b"\xff\xfe"):
        return payload[2:].decode("utf-16-le", errors="replace")
    if payload.startswith(b"\xfe\xff"):
        return payload[2:].decode("utf-16-be", errors="replace")
    if payload.startswith(b"\xef\xbb\xbf"):
        return payload[3:].decode("utf-8", errors="replace")
    if charset_hint:
        cs = charset_hint.strip().strip('"').strip("'").lower()
        if cs:
            try:
                return payload.decode(cs, errors="replace")
            except LookupError:
                pass
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            return payload.decode("cp1252", errors="replace")
        except Exception:
            return payload.decode("latin-1", errors="replace")


def _clean_body_to_snippet(body_text: str, is_html: bool = False, max_chars: int = 2000) -> str:
    """Convert plaintext or HTML body into clean normalized snippet."""
    if not body_text:
        return ""
    text = str(body_text).replace("\x00", "")
    if is_html or ("<" in text and ">" in text and re.search(r"</?(?:html|body|div|p|br|span|table|a)\b", text, re.I)):
        text = _HTML_STYLE_SCRIPT_RE.sub(" ", text)
        text = _HTML_TAG_RE.sub(" ", text)
        text = html.unescape(text)
    return " ".join(text.split())[:max_chars]


def _decompress_rtf_to_text(rtf_bytes: bytes) -> str:
    """Decompress MAPI LZFu compressed RTF (if compressed_rtf available or raw RTF) and strip control words."""
    if not rtf_bytes:
        return ""
    raw_rtf = rtf_bytes
    if compressed_rtf is not None and len(rtf_bytes) >= 16:
        try:
            raw_rtf = compressed_rtf.decompress(rtf_bytes)
        except Exception:
            raw_rtf = rtf_bytes
    rtf_str = raw_rtf.decode("cp1252", errors="ignore")
    rtf_str = re.sub(r"\{\\(?:fonttbl|colortbl|stylesheet|pict|\*\\[^}]+)[^{}]*\}", " ", rtf_str)
    rtf_str = re.sub(r"\\'[0-9a-fA-F]{2}", " ", rtf_str)
    rtf_str = re.sub(r"\\[a-zA-Z]+-?\d*\s?", " ", rtf_str)
    rtf_str = rtf_str.replace("{", " ").replace("}", " ")
    return " ".join(rtf_str.split())[:2000]


def _evaluate_suspicious_email(attachment_names: List[str]) -> Tuple[bool, Optional[str]]:
    """Calibrated zero-false-positive check for risky executable/double-extension email attachments."""
    indicators: List[str] = []
    for raw_name in attachment_names:
        name = str(raw_name or "").strip()
        if not name:
            continue
        lower_name = name.lower()
        ext = Path(lower_name).suffix
        if ext in _RISKY_ATTACHMENT_EXTS:
            indicators.append(f"executable_or_container_attachment:{name}")
            continue
        parts = [p for p in lower_name.split(".") if p]
        if len(parts) >= 3 and f".{parts[-1]}" in _RISKY_ATTACHMENT_EXTS:
            indicators.append(f"double_extension_attachment:{name}")
    if indicators:
        return True, "; ".join(indicators)
    return False, None


def _pst_decrypt_permute(data: bytes) -> bytes:
    return data.translate(_PST_MPBBI)


def _pst_decrypt_cyclic(data: bytes, bid: int) -> bytes:
    dw_key = bid & 0xFFFFFFFF
    w = ((dw_key >> 16) ^ (dw_key & 0xFFFF)) & 0xFFFF
    out = bytearray(len(data))
    for i, b in enumerate(data):
        b = (b + (w & 0xFF)) & 0xFF
        b = _PST_MPBBR[b]
        b = (b + ((w >> 8) & 0xFF)) & 0xFF
        b = _PST_MPBBS[b]
        b = (b - ((w >> 8) & 0xFF)) & 0xFF
        b = _PST_MPBBI[b]
        b = (b - (w & 0xFF)) & 0xFF
        out[i] = b
        w = (w + 1) & 0xFFFF
    return bytes(out)


class _PurePythonPstNdb:
    """
    Pure-Python [MS-PST] !BDN NDB & LTP Property Context reader supporting:
    - ANSI 32-bit PST/OST (wVer 14, 15) and Unicode 64-bit PST/OST (wVer 21, 23)
    - NDB_CRYPT_NONE (0), NDB_CRYPT_PERMUTE (1), NDB_CRYPT_CYCLIC (2)
    - Recursive NBT & BBT 512-byte BTree traversal
    - Multi-block XBLOCK / XXBLOCK data trees and SLBLOCK / SIBLOCK subnode trees
    - Heap-on-Node (HN), BTree-on-Heap (BTH), and Property Context (0xBC) MAPI properties & attachments
    """

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.valid = False
        self.is_unicode = False
        self.crypt_method = 0
        self.bbt: Dict[int, Tuple[int, int]] = {}
        self.nbt: List[Tuple[int, int, int, int]] = []

        if len(raw) < 564 or raw[:4] != b"!BDN":
            return

        w_ver = struct.unpack_from("<H", raw, 10)[0]
        if w_ver in (14, 15):
            self.is_unicode = False
            self.crypt_method = raw[461]
            bid_nbt, ib_nbt, bid_bbt, ib_bbt = struct.unpack_from("<IIII", raw, 184)
        elif w_ver in (21, 23):
            self.is_unicode = True
            self.crypt_method = raw[513]
            bid_nbt, ib_nbt, bid_bbt, ib_bbt = struct.unpack_from("<QQQQ", raw, 216)
        else:
            return

        if ib_nbt <= 0 or ib_bbt <= 0 or ib_nbt + 512 > len(raw) or ib_bbt + 512 > len(raw):
            return

        self._walk_btree_page(ib_bbt, is_nbt=False, depth=0, visited_pages=set(), parent_c_level=None)
        self._walk_btree_page(ib_nbt, is_nbt=True, depth=0, visited_pages=set(), parent_c_level=None)
        self.valid = bool(self.bbt and self.nbt)

    def _norm_bid(self, bid: int) -> int:
        # Clear reserved LSB bit per [MS-PST] 2.2.2.2
        return bid & ~1

    def _walk_btree_page(
        self,
        ib: int,
        is_nbt: bool,
        depth: int,
        visited_pages: Optional[Set[int]] = None,
        parent_c_level: Optional[int] = None,
    ) -> None:
        if visited_pages is None:
            visited_pages = set()
        if (
            depth > 16
            or ib < 0
            or ib + 512 > len(self.raw)
            or ib in visited_pages
            or len(visited_pages) >= 65536
        ):
            return
        visited_pages.add(ib)

        page = self.raw[ib : ib + 512]
        if self.is_unicode:
            c_ent = page[488]
            cb_ent = page[490]
            c_level = page[491]
            max_bytes = 488
        else:
            c_ent = page[496]
            cb_ent = page[498]
            c_level = page[499]
            max_bytes = 496

        if parent_c_level is not None and c_level >= parent_c_level:
            return
        if c_ent == 0 or cb_ent == 0 or c_ent * cb_ent > max_bytes:
            return

        if c_level > 0:
            for i in range(c_ent):
                if len(visited_pages) >= 65536:
                    break
                off = i * cb_ent
                if self.is_unicode and cb_ent >= 24:
                    _, _, child_ib = struct.unpack_from("<QQQ", page, off)
                elif not self.is_unicode and cb_ent >= 12:
                    _, _, child_ib = struct.unpack_from("<III", page, off)
                else:
                    break
                self._walk_btree_page(
                    child_ib,
                    is_nbt=is_nbt,
                    depth=depth + 1,
                    visited_pages=visited_pages,
                    parent_c_level=c_level,
                )
        elif is_nbt:
            for i in range(c_ent):
                if len(self.nbt) >= 65536:
                    break
                off = i * cb_ent
                if self.is_unicode and cb_ent >= 32:
                    nid, bid_data, bid_sub, nid_parent, _ = struct.unpack_from("<QQQII", page, off)
                elif not self.is_unicode and cb_ent >= 16:
                    nid, bid_data, bid_sub, nid_parent = struct.unpack_from("<IIII", page, off)
                else:
                    break
                self.nbt.append((nid, bid_data, bid_sub, nid_parent))
        else:
            for i in range(c_ent):
                if len(self.bbt) >= 262144:
                    break
                off = i * cb_ent
                if self.is_unicode and cb_ent >= 24:
                    bid, blk_ib, cb, _, _ = struct.unpack_from("<QQHHI", page, off)
                elif not self.is_unicode and cb_ent >= 12:
                    bid, blk_ib, cb, _ = struct.unpack_from("<IIHH", page, off)
                else:
                    break
                if blk_ib >= 0 and cb > 0 and blk_ib + cb <= len(self.raw):
                    self.bbt[self._norm_bid(bid)] = (blk_ib, cb)

    def read_block_list(
        self,
        bid: int,
        depth: int = 0,
        visited_bids: Optional[Set[int]] = None,
        budget: Optional[List[int]] = None,
    ) -> List[bytes]:
        """Resolve a data BID to an ordered list of decoded leaf data blocks (handling XBLOCK/XXBLOCK)."""
        if visited_bids is None:
            visited_bids = set()
        if budget is None:
            # budget[0] = total concatenated leaf bytes, budget[1] = total block nodes visited
            budget = [0, 0]
        max_total_bytes = 32 * 1024 * 1024
        max_visited_nodes = 8192

        norm = self._norm_bid(bid)
        if (
            norm == 0
            or depth > 8
            or norm not in self.bbt
            or norm in visited_bids
            or budget[0] >= max_total_bytes
            or budget[1] >= max_visited_nodes
        ):
            return []

        visited_bids.add(norm)
        budget[1] += 1

        ib, cb = self.bbt[norm]
        blk = self.raw[ib : ib + cb]
        # Internal block flag is bit 1 (0x02) of BID
        if (norm & 0x02) != 0:
            if len(blk) >= 8 and blk[0] == 0x01:  # btype == 0x01: XBLOCK / XXBLOCK
                c_ent = struct.unpack_from("<H", blk, 2)[0]
                out: List[bytes] = []
                step = 8 if self.is_unicode else 4
                fmt = "<Q" if self.is_unicode else "<I"
                for idx in range(c_ent):
                    if budget[0] >= max_total_bytes or budget[1] >= max_visited_nodes:
                        break
                    pos = 8 + idx * step
                    if pos + step > len(blk):
                        break
                    child_bid = struct.unpack_from(fmt, blk, pos)[0]
                    out.extend(self.read_block_list(child_bid, depth + 1, visited_bids, budget))
                return out
            rem = max_total_bytes - budget[0]
            if rem <= 0:
                return []
            clipped = blk[:rem]
            budget[0] += len(clipped)
            return [clipped]

        if self.crypt_method == 1:
            decoded = _pst_decrypt_permute(blk)
        elif self.crypt_method == 2:
            decoded = _pst_decrypt_cyclic(blk, norm)
        else:
            decoded = blk

        rem = max_total_bytes - budget[0]
        if rem <= 0:
            return []
        if len(decoded) > rem:
            decoded = decoded[:rem]
        budget[0] += len(decoded)
        return [decoded]

    def read_subnodes(
        self,
        bid_sub: int,
        depth: int = 0,
        visited_sl_bids: Optional[Set[int]] = None,
        parent_c_level: Optional[int] = None,
    ) -> Dict[int, Tuple[int, int]]:
        """Parse SLBLOCK / SIBLOCK (btype == 0x02) into {sub_nid: (sub_bid_data, sub_bid_sub)}."""
        if visited_sl_bids is None:
            visited_sl_bids = set()
        norm = self._norm_bid(bid_sub)
        if (
            norm == 0
            or depth > 6
            or norm not in self.bbt
            or norm in visited_sl_bids
            or len(visited_sl_bids) >= 4096
        ):
            return {}
        visited_sl_bids.add(norm)

        ib, cb = self.bbt[norm]
        blk = self.raw[ib : ib + cb]
        if len(blk) < 8 or blk[0] != 0x02:
            return {}
        c_level = blk[1]
        if parent_c_level is not None and c_level >= parent_c_level:
            return {}
        c_ent = struct.unpack_from("<H", blk, 2)[0]
        base_off = 8 if self.is_unicode else 4
        res: Dict[int, Tuple[int, int]] = {}
        if c_level == 0:
            step = 24 if self.is_unicode else 12
            fmt = "<QQQ" if self.is_unicode else "<III"
            for i in range(c_ent):
                if len(res) >= 4096:
                    break
                pos = base_off + i * step
                if pos + step > len(blk):
                    break
                s_nid, s_data, s_sub = struct.unpack_from(fmt, blk, pos)
                res[s_nid] = (s_data, s_sub)
        else:
            step = 16 if self.is_unicode else 8
            fmt = "<QQ" if self.is_unicode else "<II"
            for i in range(c_ent):
                if len(visited_sl_bids) >= 4096 or len(res) >= 4096:
                    break
                pos = base_off + i * step
                if pos + step > len(blk):
                    break
                _, child_sl_bid = struct.unpack_from(fmt, blk, pos)
                child_map = self.read_subnodes(
                    child_sl_bid,
                    depth + 1,
                    visited_sl_bids=visited_sl_bids,
                    parent_c_level=c_level,
                )
                for k_sub, v_sub in child_map.items():
                    if len(res) >= 4096 and k_sub not in res:
                        break
                    res[k_sub] = v_sub
        return res

    @staticmethod
    def _hn_deref(blocks: List[bytes], hid: int) -> Optional[bytes]:
        if (hid & 0x1F) != 0:
            return None
        hid_index = (hid >> 5) & 0x7FF
        hid_block = (hid >> 16) & 0xFFFF
        if hid_index == 0 or hid_block >= len(blocks):
            return None
        blk = blocks[hid_block]
        if len(blk) < 4:
            return None
        ib_hnpm = struct.unpack_from("<H", blk, 0)[0]
        if ib_hnpm + 6 > len(blk):
            return None
        c_alloc = struct.unpack_from("<H", blk, ib_hnpm)[0]
        if hid_index > c_alloc:
            return None
        off_pos = ib_hnpm + 4 + (hid_index - 1) * 2
        if off_pos + 4 > len(blk):
            return None
        start_off, end_off = struct.unpack_from("<HH", blk, off_pos)
        if start_off > end_off or end_off > len(blk):
            return None
        return blk[start_off:end_off]

    def _resolve_hnid_bytes(
        self,
        blocks: List[bytes],
        subnodes: Dict[int, Tuple[int, int]],
        hnid: int,
    ) -> Optional[bytes]:
        if hnid == 0:
            return None
        if (hnid & 0x1F) == 0:
            return self._hn_deref(blocks, hnid)
        if hnid in subnodes:
            s_data, _ = subnodes[hnid]
            return b"".join(self.read_block_list(s_data))
        for s_nid, (s_data, _) in subnodes.items():
            if (s_nid & 0xFFFFFFFF) == hnid:
                return b"".join(self.read_block_list(s_data))
        return None

    def _walk_bth(
        self,
        blocks: List[bytes],
        hid: int,
        cb_key: int,
        cb_ent: int,
        level: int,
        out: List[Tuple[bytes, bytes]],
        visited_hids: Optional[Set[Tuple[int, int]]] = None,
    ) -> None:
        if visited_hids is None:
            visited_hids = set()
        if (
            hid == 0
            or level < 0
            or level > 8
            or (hid, level) in visited_hids
            or len(out) >= 4096
            or len(visited_hids) >= 4096
        ):
            return
        visited_hids.add((hid, level))
        rec_bytes = self._hn_deref(blocks, hid)
        if not rec_bytes:
            return
        if level == 0:
            stride = cb_key + cb_ent
            if stride <= 0:
                return
            for pos in range(0, len(rec_bytes) - stride + 1, stride):
                if len(out) >= 4096:
                    break
                out.append((rec_bytes[pos : pos + cb_key], rec_bytes[pos + cb_key : pos + stride]))
        else:
            stride = cb_key + 4
            for pos in range(0, len(rec_bytes) - stride + 1, stride):
                if len(out) >= 4096 or len(visited_hids) >= 4096:
                    break
                child_hid = struct.unpack_from("<I", rec_bytes, pos + cb_key)[0]
                self._walk_bth(blocks, child_hid, cb_key, cb_ent, level - 1, out, visited_hids)

    def parse_property_context(
        self,
        bid_data: int,
        bid_sub: int,
    ) -> Tuple[Dict[int, Any], Dict[int, Tuple[int, int]]]:
        """Parse a Property Context (bClientSig == 0xBC) into {prop_id: decoded_value} + subnodes."""
        blocks = self.read_block_list(bid_data)
        subnodes = self.read_subnodes(bid_sub) if bid_sub else {}
        props: Dict[int, Any] = {}
        if not blocks or len(blocks[0]) < 12:
            return props, subnodes
        b0 = blocks[0]
        if b0[2] != 0xEC or b0[3] != 0xBC:
            return props, subnodes
        hid_user_root = struct.unpack_from("<I", b0, 4)[0]
        bth_hdr = self._hn_deref(blocks, hid_user_root)
        if not bth_hdr or len(bth_hdr) < 8 or bth_hdr[0] != 0xB5:
            return props, subnodes
        cb_key = bth_hdr[1]
        cb_ent = bth_hdr[2]
        b_idx_levels = bth_hdr[3]
        hid_root = struct.unpack_from("<I", bth_hdr, 4)[0]
        if cb_key != 2 or cb_ent < 6:
            return props, subnodes

        entries: List[Tuple[bytes, bytes]] = []
        self._walk_bth(blocks, hid_root, cb_key, cb_ent, b_idx_levels, entries)

        for k_bytes, v_bytes in entries:
            prop_id = struct.unpack_from("<H", k_bytes, 0)[0]
            prop_type = struct.unpack_from("<H", v_bytes, 0)[0]
            dw_val = struct.unpack_from("<I", v_bytes, 2)[0]

            if prop_type == 0x000B:  # PtypBoolean
                props[prop_id] = bool(dw_val & 0xFFFF)
            elif prop_type in (0x0002, 0x0003):  # PtypInteger16 / PtypInteger32
                props[prop_id] = dw_val
            elif prop_type == 0x0040:  # PtypTime (8-byte FILETIME via HNID)
                raw_t = self._resolve_hnid_bytes(blocks, subnodes, dw_val)
                if raw_t and len(raw_t) >= 8:
                    ft_ticks = struct.unpack_from("<Q", raw_t, 0)[0]
                    props[prop_id] = _filetime_int_to_naive_utc(ft_ticks)
            elif prop_type == 0x001F:  # PtypString (UTF-16LE)
                raw_s = self._resolve_hnid_bytes(blocks, subnodes, dw_val)
                if raw_s is not None:
                    props[prop_id] = raw_s.decode("utf-16-le", errors="replace").rstrip("\x00")
            elif prop_type == 0x001E:  # PtypString8
                raw_s8 = self._resolve_hnid_bytes(blocks, subnodes, dw_val)
                if raw_s8 is not None:
                    props[prop_id] = _decode_bytes_with_charset(raw_s8).rstrip("\x00")
            elif prop_type == 0x0102:  # PtypBinary
                raw_bin = self._resolve_hnid_bytes(blocks, subnodes, dw_val)
                if raw_bin is not None:
                    props[prop_id] = raw_bin

        return props, subnodes


class EmailParser(BaseParser):
    """
    Forensic email and mail store parser (.eml, .msg, .mbox, .pst, .ost).
    Populates parsed_emails and parsed_email_attachments, saving attachments to
    staging/Extracted_Archives/Email_Attachments/.
    """

    EMAIL_EXTS = {".eml", ".msg", ".mbox", ".pst", ".ost"}

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
        self.attachments_dir = self.staging_dir / "Extracted_Archives" / "Email_Attachments"
        self.attachments_dir.mkdir(parents=True, exist_ok=True)

    def _save_attachment(
        self,
        filename: str,
        data: bytes,
        resolved_source: str,
        email_id: str,
        mime_type: str,
        attachment_records: List[Dict[str, Any]],
    ) -> Optional[str]:
        """Write attachment bytes to self.attachments_dir and append structured attachment metadata."""
        if not data:
            return None
        clean_name = sanitize_filename(filename)
        digest = compute_sha256(data)
        dest_filename = f"{digest[:8]}_{clean_name}"
        dest_path = self.attachments_dir / dest_filename
        try:
            dest_path.write_bytes(data)
        except Exception as ex:
            self._log(f"Failed to save email attachment {clean_name} from {resolved_source}: {ex}", "WARNING")
            return None

        ext_low = Path(clean_name).suffix.lower()
        is_risky = ext_low in _RISKY_ATTACHMENT_EXTS
        attachment_records.append({
            "email_id": str(email_id or ""),
            "file_name": clean_name,
            "file_size": len(data),
            "mime_type": str(mime_type or "application/octet-stream"),
            "sha256": digest,
            "is_malicious": False,
            "source_file": resolved_source,
            "_is_risky": is_risky,
        })
        return clean_name

    @staticmethod
    def _build_email_record(
        email_format: str,
        sender: str,
        recipients: str,
        cc: str,
        bcc: str,
        subject: str,
        date_utc: Optional[datetime],
        message_id: str,
        body_snippet: str,
        attachment_names: List[str],
        client_submit_time: Optional[datetime],
        resolved_source: str,
    ) -> Dict[str, Any]:
        is_suspicious, indicators = _evaluate_suspicious_email(attachment_names)
        att_cnt = len(attachment_names)
        return {
            "email_format": email_format,
            "sender": str(sender or "").strip(),
            "recipients": str(recipients or "").strip(),
            "cc": str(cc or "").strip(),
            "bcc": str(bcc or "").strip(),
            "subject": str(subject or "").strip(),
            "date_utc": _to_naive_utc(date_utc),
            "message_id": str(message_id or "").strip(),
            "body_snippet": str(body_snippet or "").strip()[:2000],
            "attachments_count": att_cnt,
            "attachment_count": att_cnt,
            "attachment_names": ", ".join(attachment_names),
            "client_submit_time": _to_naive_utc(client_submit_time),
            "is_suspicious": is_suspicious,
            "suspicious_indicators": indicators,
            "source_file": resolved_source,
        }

    def _extract_mime_message_fields(
        self,
        msg: email.message.Message,
        email_format: str,
        resolved_source: str,
        attachment_records: List[Dict[str, Any]],
        att_prefix: str = "att",
    ) -> Dict[str, Any]:
        sender = str(msg.get("from") or "").strip()
        recipients = str(msg.get("to") or "").strip()
        cc = str(msg.get("cc") or "").strip()
        bcc = str(msg.get("bcc") or msg.get("x-env-bcc") or "").strip()
        subject = str(msg.get("subject") or "").strip()
        message_id = str(msg.get("message-id") or "").strip()
        date_utc = parse_rfc2822_date(msg.get("date"))
        if date_utc is None:
            date_utc = _extract_date_from_received_headers(msg)

        plain_parts: List[str] = []
        html_parts: List[str] = []
        saved_attachments: List[str] = []

        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = str(part.get_content_type() or "").lower()
            cdisp = str(part.get("content-disposition") or "").lower()
            fname = part.get_filename()

            if fname or "attachment" in cdisp:
                payload = part.get_payload(decode=True)
                if payload:
                    att_name = fname or f"{att_prefix}_{len(saved_attachments) + 1}.bin"
                    saved_name = self._save_attachment(
                        filename=att_name,
                        data=payload,
                        resolved_source=resolved_source,
                        email_id=message_id or subject,
                        mime_type=ctype or "application/octet-stream",
                        attachment_records=attachment_records,
                    )
                    if saved_name:
                        saved_attachments.append(saved_name)
                continue

            if ctype in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = _decode_bytes_with_charset(payload, part.get_content_charset())
                    if ctype == "text/plain":
                        plain_parts.append(decoded)
                    else:
                        html_parts.append(decoded)
                else:
                    raw_payload = part.get_payload()
                    if isinstance(raw_payload, str) and raw_payload.strip():
                        if ctype == "text/plain":
                            plain_parts.append(raw_payload)
                        else:
                            html_parts.append(raw_payload)

        if plain_parts:
            snippet = _clean_body_to_snippet("\n".join(plain_parts), is_html=False)
        elif html_parts:
            snippet = _clean_body_to_snippet("\n".join(html_parts), is_html=True)
        else:
            snippet = ""

        return self._build_email_record(
            email_format=email_format,
            sender=sender,
            recipients=recipients,
            cc=cc,
            bcc=bcc,
            subject=subject,
            date_utc=date_utc,
            message_id=message_id,
            body_snippet=snippet,
            attachment_names=saved_attachments,
            client_submit_time=None,
            resolved_source=resolved_source,
        )

    def _parse_eml_file(
        self,
        file_path: Path,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Parse RFC 822 .eml email file with charset awareness and Received date fallback."""
        try:
            raw_bytes = file_path.read_bytes()
            if not raw_bytes or not raw_bytes.strip():
                return []
            idx_crlf = raw_bytes.find(b"\r\n\r\n")
            idx_lf = raw_bytes.find(b"\n\n")
            sep_candidates = [i for i in (idx_crlf, idx_lf) if i >= 0]
            if sep_candidates:
                sep_idx = min(sep_candidates)
                hdr_bytes = raw_bytes[:sep_idx][:16384]
            else:
                hdr_bytes = raw_bytes[: min(len(raw_bytes), 4096)]
            if not hdr_bytes or b"\x00" in hdr_bytes:
                return []
            ctrl_cnt = sum(1 for b in hdr_bytes if b < 0x20 and b not in (9, 10, 13))
            if ctrl_cnt > max(1, int(len(hdr_bytes) * 0.02)):
                return []
            high_cnt = sum(1 for b in hdr_bytes if b >= 0x80)
            if high_cnt > int(len(hdr_bytes) * 0.20) and b"=?" not in hdr_bytes:
                try:
                    hdr_bytes.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    return []
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        except Exception as ex:
            self._log(f"Failed to parse .eml file {file_path.name}: {ex}", "WARNING")
            return []

        hdr_keys = {str(k).strip().lower() for k in msg.keys() if k}
        std_rfc_headers = {
            "from", "to", "cc", "bcc", "subject", "date", "message-id",
            "received", "reply-to", "sender", "return-path", "delivered-to", "mime-version",
        }
        if not (hdr_keys & std_rfc_headers):
            return []

        resolved_source = self.resolve_evidence_path(file_path, len(raw_bytes))
        rec = self._extract_mime_message_fields(
            msg=msg,
            email_format="EML",
            resolved_source=resolved_source,
            attachment_records=attachment_records,
            att_prefix="eml_att",
        )
        if not any(
            [
                rec.get("sender"),
                rec.get("recipients"),
                rec.get("cc"),
                rec.get("bcc"),
                rec.get("subject"),
                rec.get("message_id"),
                rec.get("date_utc"),
            ]
        ):
            core_headers = {"from", "to", "subject", "date", "message-id", "received"}
            if not (hdr_keys & core_headers) or b"\x00" in raw_bytes[:4096]:
                return []
        if not any(
            [
                rec.get("sender"),
                rec.get("recipients"),
                rec.get("subject"),
                rec.get("body_snippet"),
                rec.get("attachments_count"),
                rec.get("message_id"),
            ]
        ):
            return []
        return [rec]

    def _parse_mbox_file(
        self,
        file_path: Path,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Parse .mbox email archive ensuring file handles are always closed."""
        records: List[Dict[str, Any]] = []
        resolved_source = self.resolve_evidence_path(file_path)
        mbox_obj: Optional[mailbox.mbox] = None
        try:
            mbox_obj = mailbox.mbox(str(file_path), create=False)
            for idx, msg in enumerate(mbox_obj):
                try:
                    raw_msg_bytes = msg.as_bytes()
                    parsed_msg = email.message_from_bytes(raw_msg_bytes, policy=email.policy.default)
                except Exception:
                    parsed_msg = msg
                rec = self._extract_mime_message_fields(
                    msg=parsed_msg,
                    email_format="MBOX",
                    resolved_source=resolved_source,
                    attachment_records=attachment_records,
                    att_prefix=f"mbox_{idx + 1}_att",
                )
                records.append(rec)
        except Exception as ex:
            self._log(f"Failed to parse .mbox file {file_path.name}: {ex}", "WARNING")
        finally:
            if mbox_obj is not None:
                try:
                    mbox_obj.close()
                except Exception:
                    pass
        return records

    @staticmethod
    def _parse_transport_headers_dict(headers_str: str) -> Dict[str, Any]:
        """Extract RFC 822 header values from a MAPI PR_TRANSPORT_MESSAGE_HEADERS string."""
        if not headers_str or not headers_str.strip():
            return {}
        try:
            hdr_msg = email.message_from_string(headers_str, policy=email.policy.default)
            dt = parse_rfc2822_date(hdr_msg.get("date"))
            if dt is None:
                dt = _extract_date_from_received_headers(hdr_msg)
            return {
                "from": str(hdr_msg.get("from") or "").strip(),
                "to": str(hdr_msg.get("to") or "").strip(),
                "cc": str(hdr_msg.get("cc") or "").strip(),
                "bcc": str(hdr_msg.get("bcc") or hdr_msg.get("x-env-bcc") or "").strip(),
                "subject": str(hdr_msg.get("subject") or "").strip(),
                "message_id": str(hdr_msg.get("message-id") or "").strip(),
                "date_utc": dt,
            }
        except Exception:
            return {}

    def _parse_msg_via_olefile(
        self,
        file_path: Path,
        resolved_source: str,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Fallback .msg MAPI Compound File parser using olefile (__substg1.0_* & __properties_version1.0)."""
        if olefile is None:
            return []
        try:
            if not olefile.isOleFile(str(file_path)):
                return []
        except Exception:
            return []

        ole = olefile.OleFileIO(str(file_path))
        try:
            stream_map: Dict[str, List[str]] = {}
            for entry_parts in ole.listdir(streams=True, storages=False):
                key = "/".join(entry_parts).lower()
                stream_map[key] = entry_parts

            def _read_substg_str(prefix: str, tag_hex: str) -> str:
                u16_key = f"{prefix}__substg1.0_{tag_hex.lower()}001f"
                if u16_key in stream_map:
                    raw_u16 = ole.openstream(stream_map[u16_key]).read()
                    return raw_u16.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
                s8_key = f"{prefix}__substg1.0_{tag_hex.lower()}001e"
                if s8_key in stream_map:
                    raw_s8 = ole.openstream(stream_map[s8_key]).read()
                    return _decode_bytes_with_charset(raw_s8).rstrip("\x00").strip()
                return ""

            def _read_substg_bin(prefix: str, tag_hex: str) -> Optional[bytes]:
                b_key = f"{prefix}__substg1.0_{tag_hex.lower()}0102"
                if b_key in stream_map:
                    return ole.openstream(stream_map[b_key]).read()
                return None

            subject = _read_substg_str("", "0037")
            sender_name = _read_substg_str("", "0c1a") or _read_substg_str("", "0042")
            sender_email = (
                _read_substg_str("", "5d01")
                or _read_substg_str("", "0c1f")
                or _read_substg_str("", "0065")
            )
            display_to = _read_substg_str("", "0e04")
            display_cc = _read_substg_str("", "0e03")
            display_bcc = _read_substg_str("", "0e02")
            msg_id = _read_substg_str("", "1035")
            transport_headers = _read_substg_str("", "007d")
            body_plain = _read_substg_str("", "1000")
            body_html_str = _read_substg_str("", "1013")
            body_html_bin = _read_substg_bin("", "1013")
            body_rtf_bin = _read_substg_bin("", "1009")

            hdr_info = self._parse_transport_headers_dict(transport_headers)

            # Parse 64-bit integer FILETIME properties from root __properties_version1.0
            delivery_dt: Optional[datetime] = None
            submit_dt: Optional[datetime] = None
            if "__properties_version1.0" in stream_map:
                prop_bytes = ole.openstream(stream_map["__properties_version1.0"]).read()
                # Root MSG property stream has a 32-byte header followed by 16-byte property entries
                hdr_off = 32 if len(prop_bytes) >= 32 and (len(prop_bytes) - 32) % 16 == 0 else 24
                if len(prop_bytes) >= hdr_off + 16:
                    for off in range(hdr_off, len(prop_bytes) - 15, 16):
                        p_type, p_id, _, p_val64 = struct.unpack_from("<HHIQ", prop_bytes, off)
                        if p_type == 0x0040:
                            if p_id == 0x0E06:
                                delivery_dt = _filetime_int_to_naive_utc(p_val64)
                            elif p_id == 0x0039:
                                submit_dt = _filetime_int_to_naive_utc(p_val64)

            if sender_name and sender_email and sender_email.lower() not in sender_name.lower():
                sender = f"{sender_name} <{sender_email}>"
            else:
                sender = sender_email or sender_name or hdr_info.get("from", "")

            recipients = display_to or hdr_info.get("to", "")
            cc = display_cc or hdr_info.get("cc", "")
            bcc = display_bcc or hdr_info.get("bcc", "")
            subject = subject or hdr_info.get("subject", "")
            msg_id = msg_id or hdr_info.get("message_id", "")
            date_utc = delivery_dt or submit_dt or hdr_info.get("date_utc")

            if body_plain:
                snippet = _clean_body_to_snippet(body_plain, is_html=False)
            elif body_html_str:
                snippet = _clean_body_to_snippet(body_html_str, is_html=True)
            elif body_html_bin:
                snippet = _clean_body_to_snippet(_decode_bytes_with_charset(body_html_bin), is_html=True)
            elif body_rtf_bin:
                snippet = _decompress_rtf_to_text(body_rtf_bin)
            else:
                snippet = ""

            # Enumerate __attach_version1.0_#* sub-storages
            attach_prefixes = sorted({
                k.split("/")[0] + "/"
                for k in stream_map
                if k.startswith("__attach_version1.0_#") and "/" in k
            })
            saved_attachments: List[str] = []
            for idx, apfx in enumerate(attach_prefixes):
                att_name = (
                    _read_substg_str(apfx, "3707")
                    or _read_substg_str(apfx, "3704")
                    or _read_substg_str(apfx, "3001")
                    or f"msg_att_{idx + 1}.bin"
                )
                att_mime = _read_substg_str(apfx, "370e") or "application/octet-stream"
                att_data = _read_substg_bin(apfx, "3701")
                if att_data:
                    saved_name = self._save_attachment(
                        filename=att_name,
                        data=att_data,
                        resolved_source=resolved_source,
                        email_id=msg_id or subject,
                        mime_type=att_mime,
                        attachment_records=attachment_records,
                    )
                    if saved_name:
                        saved_attachments.append(saved_name)

            if not any([sender, recipients, subject, snippet, saved_attachments, msg_id]):
                return []

            return [
                self._build_email_record(
                    email_format="MSG",
                    sender=sender,
                    recipients=recipients,
                    cc=cc,
                    bcc=bcc,
                    subject=subject,
                    date_utc=date_utc,
                    message_id=msg_id,
                    body_snippet=snippet,
                    attachment_names=saved_attachments,
                    client_submit_time=submit_dt,
                    resolved_source=resolved_source,
                )
            ]
        finally:
            ole.close()

    def _parse_msg_file(
        self,
        file_path: Path,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Parse Microsoft Outlook .msg binary compound file (extract_msg primary + olefile fallback)."""
        resolved_source = self.resolve_evidence_path(file_path)

        if extract_msg is not None:
            msg = None
            try:
                msg = extract_msg.openMsg(str(file_path))
                sender = str(getattr(msg, "sender", "") or "").strip()
                recipients = str(getattr(msg, "to", "") or "").strip()
                cc = str(getattr(msg, "cc", "") or "").strip()
                bcc = str(getattr(msg, "bcc", "") or "").strip()
                subject = str(getattr(msg, "subject", "") or "").strip()
                message_id = str(getattr(msg, "messageId", "") or "").strip()

                hdr_dict = getattr(msg, "headerDict", None) or {}
                if not message_id and hdr_dict:
                    message_id = str(hdr_dict.get("Message-ID") or hdr_dict.get("Message-Id") or "").strip()
                if not bcc and hdr_dict:
                    bcc = str(hdr_dict.get("Bcc") or hdr_dict.get("BCC") or "").strip()

                date_raw = getattr(msg, "date", None)
                date_utc: Optional[datetime] = None
                if isinstance(date_raw, datetime):
                    date_utc = _to_naive_utc(date_raw)
                elif date_raw:
                    date_utc = parse_rfc2822_date(str(date_raw))

                # Also inspect MAPI client submit time if available
                submit_dt: Optional[datetime] = None
                try:
                    props = getattr(msg, " mainProperties", None) or getattr(msg, "mainProperties", None)
                    if props and 0x0039 in props:
                        raw_sub = getattr(props[0x0039], "value", None)
                        if isinstance(raw_sub, datetime):
                            submit_dt = _to_naive_utc(raw_sub)
                except Exception:
                    pass

                body_plain = getattr(msg, "body", None)
                body_html = getattr(msg, "htmlBody", None)
                body_rtf = getattr(msg, "rtfBody", None)
                if body_plain and str(body_plain).strip():
                    snippet = _clean_body_to_snippet(str(body_plain), is_html=False)
                elif body_html:
                    html_txt = (
                        _decode_bytes_with_charset(body_html)
                        if isinstance(body_html, (bytes, bytearray))
                        else str(body_html)
                    )
                    snippet = _clean_body_to_snippet(html_txt, is_html=True)
                elif body_rtf:
                    rtf_b = body_rtf if isinstance(body_rtf, bytes) else str(body_rtf).encode("cp1252", errors="ignore")
                    snippet = _decompress_rtf_to_text(rtf_b)
                else:
                    snippet = ""

                saved_attachments: List[str] = []
                for idx, att in enumerate(getattr(msg, "attachments", []) or []):
                    fname = (
                        getattr(att, "longFilename", None)
                        or getattr(att, "shortFilename", None)
                        or getattr(att, "name", None)
                    )
                    att_mime = str(getattr(att, "mimetype", "") or "application/octet-stream")
                    data = getattr(att, "data", None)
                    if isinstance(data, (bytes, bytearray)) and len(data) > 0:
                        att_name = str(fname or f"msg_att_{idx + 1}.dat")
                        saved_name = self._save_attachment(
                            filename=att_name,
                            data=bytes(data),
                            resolved_source=resolved_source,
                            email_id=message_id or subject,
                            mime_type=att_mime,
                            attachment_records=attachment_records,
                        )
                        if saved_name:
                            saved_attachments.append(saved_name)

                # Enrich client_submit_time via olefile root property stream if extract_msg omitted it
                if submit_dt is None and olefile is not None:
                    try:
                        if olefile.isOleFile(str(file_path)):
                            with olefile.OleFileIO(str(file_path)) as ole_chk:
                                if ole_chk.exists("__properties_version1.0"):
                                    pb = ole_chk.openstream("__properties_version1.0").read()
                                    hoff = 32 if len(pb) >= 32 and (len(pb) - 32) % 16 == 0 else 24
                                    for off in range(hoff, len(pb) - 15, 16):
                                        pt, pid, _, pv = struct.unpack_from("<HHIQ", pb, off)
                                        if pt == 0x0040 and pid == 0x0039:
                                            submit_dt = _filetime_int_to_naive_utc(pv)
                                            break
                    except Exception:
                        pass

                return [
                    self._build_email_record(
                        email_format="MSG",
                        sender=sender,
                        recipients=recipients,
                        cc=cc,
                        bcc=bcc,
                        subject=subject,
                        date_utc=date_utc or submit_dt,
                        message_id=message_id,
                        body_snippet=snippet,
                        attachment_names=saved_attachments,
                        client_submit_time=submit_dt,
                        resolved_source=resolved_source,
                    )
                ]
            except Exception as ex:
                self._log(f"extract_msg fallback triggered on {file_path.name}: {ex}", "DEBUG")
            finally:
                if msg is not None:
                    try:
                        msg.close()
                    except Exception:
                        pass

        return self._parse_msg_via_olefile(file_path, resolved_source, attachment_records)

    @staticmethod
    def _extract_pypff_record_entries(item: Any) -> Dict[int, Any]:
        """Extract MAPI property IDs -> decoded values from a pypff item's record_sets."""
        props: Dict[int, Any] = {}
        try:
            num_sets = getattr(item, "number_of_record_sets", 0) or 0
            for s_idx in range(num_sets):
                rset = item.get_record_set(s_idx)
                num_entries = getattr(rset, "number_of_entries", 0) or 0
                for e_idx in range(num_entries):
                    entry = rset.get_entry(e_idx)
                    e_type = getattr(entry, "entry_type", None)
                    v_type = getattr(entry, "value_type", None)
                    if e_type is None:
                        continue
                    try:
                        if v_type in (0x001F, 0x001E):
                            props[int(e_type)] = str(entry.data_as_string or "").rstrip("\x00").strip()
                        elif v_type == 0x0040:
                            props[int(e_type)] = _to_naive_utc(entry.data_as_datetime)
                        elif v_type in (0x0002, 0x0003):
                            props[int(e_type)] = entry.data_as_integer
                        elif v_type == 0x0102:
                            props[int(e_type)] = entry.data
                    except Exception:
                        continue
        except Exception:
            pass
        return props

    def _parse_pst_ost_via_pypff(
        self,
        file_path: Path,
        ext_fmt: str,
        resolved_source: str,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Tier 1: Parse .pst or .ost personal/offline folder store natively via pypff (libpff)."""
        if pypff is None:
            return []

        records: List[Dict[str, Any]] = []
        pff_file = pypff.file()
        opened = False
        try:
            pff_file.open(str(file_path))
            opened = True
            root = pff_file.get_root_folder()
            if root is None:
                return []

            def _walk_folder(folder: Any, depth: int = 0) -> None:
                if folder is None or depth > 32:
                    return
                try:
                    num_msgs = getattr(folder, "number_of_sub_messages", 0) or 0
                except Exception:
                    num_msgs = 0

                for m_idx in range(num_msgs):
                    try:
                        msg = folder.get_sub_message(m_idx)
                        if msg is None:
                            continue
                        mapi_props = self._extract_pypff_record_entries(msg)

                        subject = str(getattr(msg, "subject", None) or mapi_props.get(0x0037) or "").strip()
                        sender_name = str(
                            getattr(msg, "sender_name", None)
                            or mapi_props.get(0x0C1A)
                            or mapi_props.get(0x0042)
                            or ""
                        ).strip()
                        sender_email = str(
                            mapi_props.get(0x5D01)
                            or mapi_props.get(0x0C1F)
                            or mapi_props.get(0x0065)
                            or ""
                        ).strip()

                        headers_raw = getattr(msg, "transport_headers", None)
                        if isinstance(headers_raw, bytes):
                            headers_str = _decode_bytes_with_charset(headers_raw)
                        else:
                            headers_str = str(headers_raw or mapi_props.get(0x007D) or "")
                        hdr_info = self._parse_transport_headers_dict(headers_str)

                        if sender_name and sender_email and sender_email.lower() not in sender_name.lower():
                            sender = f"{sender_name} <{sender_email}>"
                        else:
                            sender = sender_email or sender_name or hdr_info.get("from", "")

                        recipients = str(mapi_props.get(0x0E04) or hdr_info.get("to") or "").strip()
                        cc = str(mapi_props.get(0x0E03) or hdr_info.get("cc") or "").strip()
                        bcc = str(mapi_props.get(0x0E02) or hdr_info.get("bcc") or "").strip()

                        if not recipients:
                            to_list: List[str] = []
                            cc_list: List[str] = []
                            bcc_list: List[str] = []
                            for rec_item in getattr(msg, "recipients", []) or []:
                                r_props = self._extract_pypff_record_entries(rec_item)
                                r_disp = str(r_props.get(0x3001) or "").strip()
                                r_addr = str(r_props.get(0x39FE) or r_props.get(0x3003) or "").strip()
                                r_type = r_props.get(0x0C15, 1)
                                r_label = f"{r_disp} <{r_addr}>" if r_disp and r_addr and r_addr not in r_disp else (r_addr or r_disp)
                                if not r_label:
                                    continue
                                if r_type == 2:
                                    cc_list.append(r_label)
                                elif r_type == 3:
                                    bcc_list.append(r_label)
                                else:
                                    to_list.append(r_label)
                            if to_list:
                                recipients = ", ".join(to_list)
                            if cc_list and not cc:
                                cc = ", ".join(cc_list)
                            if bcc_list and not bcc:
                                bcc = ", ".join(bcc_list)

                        delivery_dt: Optional[datetime] = None
                        try:
                            delivery_dt = _to_naive_utc(msg.delivery_time)
                        except Exception:
                            delivery_dt = mapi_props.get(0x0E06)

                        submit_dt: Optional[datetime] = None
                        try:
                            submit_dt = _to_naive_utc(msg.client_submit_time)
                        except Exception:
                            submit_dt = mapi_props.get(0x0039)

                        date_utc = delivery_dt or submit_dt or hdr_info.get("date_utc")
                        msg_id = str(mapi_props.get(0x1035) or hdr_info.get("message_id") or "").strip()
                        subject = subject or hdr_info.get("subject", "")

                        snippet = ""
                        try:
                            pt_body = msg.plain_text_body
                            if pt_body:
                                pt_str = (
                                    _decode_bytes_with_charset(pt_body)
                                    if isinstance(pt_body, bytes)
                                    else str(pt_body)
                                )
                                snippet = _clean_body_to_snippet(pt_str, is_html=False)
                        except Exception:
                            pass

                        if not snippet and mapi_props.get(0x1000):
                            snippet = _clean_body_to_snippet(str(mapi_props[0x1000]), is_html=False)

                        if not snippet:
                            try:
                                h_body = msg.html_body
                                if h_body:
                                    h_str = (
                                        _decode_bytes_with_charset(h_body)
                                        if isinstance(h_body, bytes)
                                        else str(h_body)
                                    )
                                    snippet = _clean_body_to_snippet(h_str, is_html=True)
                            except Exception:
                                pass

                        if not snippet:
                            try:
                                r_body = msg.rtf_body
                                if r_body:
                                    r_bytes = r_body if isinstance(r_body, bytes) else str(r_body).encode("cp1252", errors="ignore")
                                    snippet = _decompress_rtf_to_text(r_bytes)
                            except Exception:
                                pass

                        saved_attachments: List[str] = []
                        try:
                            num_atts = getattr(msg, "number_of_attachments", 0) or 0
                        except Exception:
                            num_atts = 0

                        for a_idx in range(num_atts):
                            try:
                                att = msg.get_attachment(a_idx)
                                if att is None:
                                    continue
                                a_props = self._extract_pypff_record_entries(att)
                                att_name = str(
                                    a_props.get(0x3707)
                                    or a_props.get(0x3704)
                                    or a_props.get(0x3001)
                                    or getattr(att, "name", None)
                                    or f"pst_att_{a_idx + 1}.bin"
                                ).strip()
                                att_mime = str(a_props.get(0x370E) or "application/octet-stream").strip()
                                att_data: Optional[bytes] = None
                                try:
                                    sz = att.get_size()
                                    if sz and sz > 0:
                                        att.seek_offset(0, 0)
                                        att_data = att.read_buffer(sz)
                                except Exception:
                                    raw_p = a_props.get(0x3701)
                                    if isinstance(raw_p, bytes):
                                        att_data = raw_p
                                if att_data:
                                    saved_name = self._save_attachment(
                                        filename=att_name,
                                        data=att_data,
                                        resolved_source=resolved_source,
                                        email_id=msg_id or subject,
                                        mime_type=att_mime,
                                        attachment_records=attachment_records,
                                    )
                                    if saved_name:
                                        saved_attachments.append(saved_name)
                            except Exception:
                                continue

                        records.append(
                            self._build_email_record(
                                email_format=ext_fmt,
                                sender=sender,
                                recipients=recipients,
                                cc=cc,
                                bcc=bcc,
                                subject=subject,
                                date_utc=date_utc,
                                message_id=msg_id,
                                body_snippet=snippet,
                                attachment_names=saved_attachments,
                                client_submit_time=submit_dt,
                                resolved_source=resolved_source,
                            )
                        )
                    except Exception as m_ex:
                        self._log(f"Error parsing message in {file_path.name}: {m_ex}", "DEBUG")

                try:
                    num_subs = getattr(folder, "number_of_sub_folders", 0) or 0
                except Exception:
                    num_subs = 0
                for f_idx in range(num_subs):
                    try:
                        sub = folder.get_sub_folder(f_idx)
                        _walk_folder(sub, depth + 1)
                    except Exception:
                        continue

            _walk_folder(root, 0)
        except Exception as ex:
            self._log(f"pypff fallback triggered on {file_path.name}: {ex}", "DEBUG")
        finally:
            if opened:
                try:
                    pff_file.close()
                except Exception:
                    pass

        return records

    def _parse_pst_ost_via_ndb(
        self,
        raw: bytes,
        ext_fmt: str,
        resolved_source: str,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Tier 2: Pure-Python [MS-PST] !BDN NDB BTree + Property Context parser."""
        reader = _PurePythonPstNdb(raw)
        if not reader.valid:
            return []

        records: List[Dict[str, Any]] = []
        seen_nids: Set[int] = set()
        for nid, bid_data, bid_sub, _ in reader.nbt:
            if nid in seen_nids:
                continue
            seen_nids.add(nid)
            nid_type = nid & 0x1F
            # NID_TYPE_NORMAL_MESSAGE (0x04) or NID_TYPE_ASSOC_MESSAGE (0x08)
            if nid_type != 0x04:
                continue
            props, subnodes = reader.parse_property_context(bid_data, bid_sub)
            if not props:
                continue

            subject = str(props.get(0x0037) or "").strip()
            sender_name = str(props.get(0x0C1A) or props.get(0x0042) or "").strip()
            sender_email = str(props.get(0x5D01) or props.get(0x0C1F) or props.get(0x0065) or "").strip()
            display_to = str(props.get(0x0E04) or "").strip()
            display_cc = str(props.get(0x0E03) or "").strip()
            display_bcc = str(props.get(0x0E02) or "").strip()
            msg_id = str(props.get(0x1035) or "").strip()
            headers_str = str(props.get(0x007D) or "")
            hdr_info = self._parse_transport_headers_dict(headers_str)

            if sender_name and sender_email and sender_email.lower() not in sender_name.lower():
                sender = f"{sender_name} <{sender_email}>"
            else:
                sender = sender_email or sender_name or hdr_info.get("from", "")

            recipients = display_to or hdr_info.get("to", "")
            cc = display_cc or hdr_info.get("cc", "")
            bcc = display_bcc or hdr_info.get("bcc", "")
            subject = subject or hdr_info.get("subject", "")
            msg_id = msg_id or hdr_info.get("message_id", "")

            delivery_dt = props.get(0x0E06) if isinstance(props.get(0x0E06), datetime) else None
            submit_dt = props.get(0x0039) if isinstance(props.get(0x0039), datetime) else None
            date_utc = delivery_dt or submit_dt or hdr_info.get("date_utc")

            if props.get(0x1000):
                snippet = _clean_body_to_snippet(str(props[0x1000]), is_html=False)
            elif props.get(0x1013):
                raw_h = props[0x1013]
                h_txt = _decode_bytes_with_charset(raw_h) if isinstance(raw_h, bytes) else str(raw_h)
                snippet = _clean_body_to_snippet(h_txt, is_html=True)
            elif isinstance(props.get(0x1009), bytes):
                snippet = _decompress_rtf_to_text(props[0x1009])
            else:
                snippet = ""

            saved_attachments: List[str] = []
            for s_idx, (sub_nid, (sub_bid_data, sub_bid_sub)) in enumerate(subnodes.items()):
                # NID_TYPE_ATTACHMENT == 0x05
                if (sub_nid & 0x1F) != 0x05:
                    continue
                att_props, _ = reader.parse_property_context(sub_bid_data, sub_bid_sub)
                if not att_props:
                    continue
                att_name = str(
                    att_props.get(0x3707)
                    or att_props.get(0x3704)
                    or att_props.get(0x3001)
                    or f"ndb_att_{s_idx + 1}.bin"
                ).strip()
                att_mime = str(att_props.get(0x370E) or "application/octet-stream").strip()
                att_data = att_props.get(0x3701)
                if isinstance(att_data, bytes) and len(att_data) > 0:
                    saved_name = self._save_attachment(
                        filename=att_name,
                        data=att_data,
                        resolved_source=resolved_source,
                        email_id=msg_id or subject,
                        mime_type=att_mime,
                        attachment_records=attachment_records,
                    )
                    if saved_name:
                        saved_attachments.append(saved_name)

            if not any([sender, recipients, subject, snippet, saved_attachments, msg_id]):
                continue

            records.append(
                self._build_email_record(
                    email_format=ext_fmt,
                    sender=sender,
                    recipients=recipients,
                    cc=cc,
                    bcc=bcc,
                    subject=subject,
                    date_utc=date_utc,
                    message_id=msg_id,
                    body_snippet=snippet,
                    attachment_names=saved_attachments,
                    client_submit_time=submit_dt,
                    resolved_source=resolved_source,
                )
            )

        return records

    def _scan_pst_ost_rfc822_headers(
        self,
        raw: bytes,
        ext_fmt: str,
        resolved_source: str,
    ) -> List[Dict[str, Any]]:
        """
        Tier 3: Strict RFC 822 header block scanner for damaged/partial stores when Tiers 1 & 2 yield 0 rows.
        ZERO fabricated senders, subjects, Message-IDs, or timestamps.
        """
        records: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str, str, str]] = set()
        # Match contiguous RFC 822 header blocks (2+ standard headers terminated by blank line, even after NUL padding)
        block_re = re.compile(
            rb"(?:(?:^|(?<=[\x00-\x1f]))[A-Za-z][A-Za-z0-9\-]{1,40}:\s*[^\r\n]+\r?\n(?:[ \t]+[^\r\n]+\r?\n)*){2,}\r?\n",
            re.MULTILINE,
        )
        for m in block_re.finditer(raw):
            hdr_start = m.start()
            hdr_end = m.end()
            body_end = min(len(raw), hdr_end + 4096)
            candidate_bytes = raw[hdr_start:body_end]
            try:
                msg = email.message_from_bytes(candidate_bytes, policy=email.policy.default)
            except Exception:
                continue

            sender = str(msg.get("from") or "").strip()
            if not sender:
                continue
            subject = str(msg.get("subject") or "").strip()
            recipients = str(msg.get("to") or "").strip()
            cc = str(msg.get("cc") or "").strip()
            bcc = str(msg.get("bcc") or "").strip()
            msg_id = str(msg.get("message-id") or "").strip()
            date_raw = msg.get("date")
            date_utc = parse_rfc2822_date(date_raw) if date_raw else _extract_date_from_received_headers(msg)

            # Require From: PLUS at least one corroborating RFC 822 header
            if not any([subject, recipients, date_raw, msg_id]):
                continue

            dedup_k = (sender.lower(), recipients.lower(), subject.lower(), msg_id.lower())
            if dedup_k in seen_keys:
                continue
            seen_keys.add(dedup_k)

            raw_tail = raw[hdr_end:body_end]
            stop_m = re.search(rb"\x00{2,}", raw_tail)
            if stop_m:
                raw_tail = raw_tail[: stop_m.start()]
            body_txt = _decode_bytes_with_charset(raw_tail)
            snippet = _clean_body_to_snippet(body_txt, is_html=False, max_chars=500)

            records.append(
                self._build_email_record(
                    email_format=ext_fmt,
                    sender=sender,
                    recipients=recipients,
                    cc=cc,
                    bcc=bcc,
                    subject=subject,
                    date_utc=date_utc,
                    message_id=msg_id,
                    body_snippet=snippet,
                    attachment_names=[],
                    client_submit_time=None,
                    resolved_source=resolved_source,
                )
            )
        return records

    def _parse_pst_ost_file(
        self,
        file_path: Path,
        attachment_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """3-Tier authentic .pst / .ost parser (pypff -> Pure-Python !BDN NDB -> Strict RFC822 fallback)."""
        ext_fmt = file_path.suffix.lstrip(".").upper() or "PST"
        resolved_source = self.resolve_evidence_path(file_path)

        # Tier 1: pypff (libpff)
        recs = self._parse_pst_ost_via_pypff(file_path, ext_fmt, resolved_source, attachment_records)
        if recs:
            return recs

        try:
            raw = file_path.read_bytes()
        except Exception as ex:
            self._log(f"Failed reading {file_path.name}: {ex}", "WARNING")
            return []

        # Tier 2: Pure-Python [MS-PST] !BDN NDB BTree & Property Context parser
        recs = self._parse_pst_ost_via_ndb(raw, ext_fmt, resolved_source, attachment_records)
        if recs:
            return recs

        # Tier 3: Strict RFC 822 header block fallback (zero fabricated fields)
        return self._scan_pst_ost_rfc822_headers(raw, ext_fmt, resolved_source)

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for all corporate email stores (.eml, .msg, .mbox, .pst, .ost).
        Ingests parsed_emails and parsed_email_attachments into DuckDB safely under case RLock.
        """
        start_time = time.time()
        self._log(f"Starting EmailParser across staging directory: {self.staging_dir}")

        all_records: List[Dict[str, Any]] = []
        all_attachments: List[Dict[str, Any]] = []
        candidate_emails: List[Path] = []

        if self.staging_dir.exists():
            for p in self.staging_dir.rglob("*"):
                if not p.is_file():
                    continue
                sfx = p.suffix.lower()
                if sfx in self.EMAIL_EXTS:
                    p_low = str(p).lower().replace("\\", "/")
                    if "extracted_archives/email_attachments" in p_low:
                        continue
                    candidate_emails.append(p)

        self._log(f"Discovered {len(candidate_emails)} email mail stores and messages.")

        for ef in candidate_emails:
            sfx = ef.suffix.lower()
            try:
                if sfx == ".eml":
                    recs = self._parse_eml_file(ef, all_attachments)
                elif sfx == ".mbox":
                    recs = self._parse_mbox_file(ef, all_attachments)
                elif sfx == ".msg":
                    recs = self._parse_msg_file(ef, all_attachments)
                elif sfx in (".pst", ".ost"):
                    recs = self._parse_pst_ost_file(ef, all_attachments)
                else:
                    continue
                all_records.extend(recs)
            except Exception as ex:
                self._log(f"Failed parsing email file {ef}: {ex}", "WARNING")

        # Deduplicate email records
        unique_emails: List[Dict[str, Any]] = []
        seen_emails: Set[Tuple[str, ...]] = set()
        for rec in all_records:
            e_key = (
                str(rec.get("email_format") or "").strip().upper(),
                str(rec.get("sender") or "").strip().lower(),
                str(rec.get("recipients") or "").strip().lower(),
                str(rec.get("subject") or "").strip().lower(),
                str(rec.get("date_utc") or "").strip(),
                str(rec.get("message_id") or "").strip(),
                str(rec.get("body_snippet") or "").strip()[:160],
            )
            if e_key not in seen_emails:
                seen_emails.add(e_key)
                unique_emails.append(rec)

        # Deduplicate extracted attachment metadata rows
        unique_attachments: List[Dict[str, Any]] = []
        seen_atts: Set[Tuple[str, str, str]] = set()
        for att in all_attachments:
            clean_att = {k: v for k, v in att.items() if not k.startswith("_")}
            a_key = (
                str(clean_att.get("email_id") or "").strip().lower(),
                str(clean_att.get("file_name") or "").strip().lower(),
                str(clean_att.get("sha256") or "").strip().lower(),
            )
            if a_key not in seen_atts:
                seen_atts.add(a_key)
                unique_attachments.append(clean_att)

        outlook_rows = [r for r in unique_emails if r.get("email_format") in ("PST", "OST", "MSG")]
        mbox_rows = [r for r in unique_emails if r.get("email_format") == "MBOX"]
        eml_rows = [r for r in unique_emails if r.get("email_format") == "EML"]

        with DuckDBManager.get_lock(self.case_id):
            row_count = self.insert_records(
                table_name="parsed_emails",
                records=unique_emails,
                schema_ddl=EMAIL_SCHEMA_DDL,
                artifact_id="emails",
                category="EMAIL & CALENDAR",
                display_name="Emails (Combined)",
                source_tool="EmailParser",
            )
            self.insert_records(
                table_name="parsed_outlook_emails",
                records=outlook_rows,
                schema_ddl=EMAIL_SCHEMA_DDL.replace("parsed_emails", "parsed_outlook_emails"),
                artifact_id="outlook_emails",
                category="EMAIL & CALENDAR",
                display_name="Outlook PST/OST Emails",
                source_tool="EmailParser",
            )
            self.insert_records(
                table_name="parsed_mbox_emails",
                records=mbox_rows,
                schema_ddl=EMAIL_SCHEMA_DDL.replace("parsed_emails", "parsed_mbox_emails"),
                artifact_id="mbox_emails",
                category="EMAIL & CALENDAR",
                display_name="Thunderbird / MBOX Emails",
                source_tool="EmailParser",
            )
            self.insert_records(
                table_name="parsed_winmail_messages",
                records=eml_rows,
                schema_ddl=EMAIL_SCHEMA_DDL.replace("parsed_emails", "parsed_winmail_messages"),
                artifact_id="winmail_messages",
                category="EMAIL & CALENDAR",
                display_name="Windows Mail Messages",
                source_tool="EmailParser",
            )
            att_count = self.insert_records(
                table_name="parsed_email_attachments",
                records=unique_attachments,
                schema_ddl=EMAIL_ATTACHMENTS_DDL,
                artifact_id="email_attachments",
                category="EMAIL & CALENDAR",
                display_name="Email Attachments",
                source_tool="EmailParser",
            )

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Email",
            command_executed=f"EmailParser.parse({len(candidate_emails)} files)",
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"EmailParser complete in {duration_ms}ms: {row_count} email records, {att_count} attachments ingested."
        )
        return {"parsed_emails": row_count, "parsed_email_attachments": att_count}
