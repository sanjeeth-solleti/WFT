"""
Windows Forensic Toolkit (WFT) DFIR Suite - Chat & Collaboration Apps Parser
Parses:
1. Microsoft Teams, Discord, Slack, Skype, WhatsApp, and Telegram message artifacts from:
   - LevelDB Write-Ahead Logs (.log with 32KB block framing & FULL/FIRST/MIDDLE/LAST reassembly)
   - LevelDB SSTables (.ldb / .sst with 48-byte footer magic, index block, raw & Snappy data blocks)
   - UTF-8 and UTF-16LE encoded IndexedDB / Electron Local Storage payloads
   - SQLite chat databases (uncapped, supporting native & JSON-blob schemas)
   into unified DuckDB table parsed_chat_messages with strict zero-false-positive validation.
2. Windows Push Notification databases (wpndatabase.db) - parses Notification table
   XML payloads, exact 64-bit integer FILETIME ArrivalTimes, and Handler IDs into
   deduplicated DuckDB table parsed_notifications.
"""
from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import struct
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

try:
    import cramjam
except ImportError:
    cramjam = None  # type: ignore[assignment]

try:
    import snappy as python_snappy  # type: ignore[import-not-found]
except ImportError:
    python_snappy = None  # type: ignore[assignment]

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser, copy_sqlite_with_wal


CHAT_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_chat_messages (
    _row_id BIGINT,
    app_name VARCHAR,
    profile VARCHAR,
    timestamp_utc TIMESTAMP,
    sender VARCHAR,
    recipient_channel VARCHAR,
    message_text VARCHAR,
    attachment_url VARCHAR,
    source_file VARCHAR
);
"""

NOTIFICATIONS_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_notifications (
    _row_id BIGINT,
    notification_id BIGINT,
    app_id VARCHAR,
    notification_type VARCHAR,
    payload VARCHAR,
    arrival_time TIMESTAMP,
    expiry_time TIMESTAMP,
    timestamp_utc TIMESTAMP,
    title VARCHAR,
    body VARCHAR,
    header VARCHAR,
    action_url VARCHAR,
    source_path VARCHAR,
    source_file VARCHAR
);
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS notification_id BIGINT;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS notification_type VARCHAR;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS payload VARCHAR;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS arrival_time TIMESTAMP;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS expiry_time TIMESTAMP;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS timestamp_utc TIMESTAMP;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS title VARCHAR;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS body VARCHAR;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS header VARCHAR;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS action_url VARCHAR;
ALTER TABLE parsed_notifications ADD COLUMN IF NOT EXISTS source_path VARCHAR;
"""

_LEVELDB_LOG_BLOCK_SIZE = 32768
_LEVELDB_SST_MAGIC = 0xDB4775248B80FB57
_FILETIME_EPOCH_DIFF_TICKS = 116444736000000000
_SLACK_TS_VAL_RE = re.compile(r"^\d{9,11}\.\d{1,9}$")
_ISO_TS_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(Z|[+-]\d{2}:?\d{2})?\s*$",
    re.IGNORECASE,
)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HREF_SRC_RE = re.compile(r'(?:href|src)\s*=\s*["\'](https?://[^"\'>\s]+)["\']', re.IGNORECASE)
_UTF16LE_RUN_RE = re.compile(rb"(?:[\x20-\x7e\r\n\t]\x00){10,}")
_UNSAFE_XML_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CHAT_PATH_KEYWORDS = (
    "discord",
    "slack",
    "team",
    "msteams",
    "skype",
    "whatsapp",
    "telegram",
    "chat",
)
_NON_CHAT_REJECT_KEYS = frozenset({
    "webpack",
    "statuscode",
    "errno",
    "syscall",
    "windowbounds",
    "spellcheck",
    "gpu",
    "crashreporter",
})
_TEAMS_SKIP_MSGTYPES = (
    "threadactivity/",
    "control/",
    "typing",
    "richtext/typing",
    "messagedelete",
    "event/",
)
_PACKAGE_OR_SOURCEMAP_KEYS = frozenset({
    "version",
    "dependencies",
    "devdependencies",
    "peerdependencies",
    "optionaldependencies",
    "scripts",
    "main",
    "mappings",
    "sourcescontent",
})
_NON_MESSAGE_EVENT_TYPES = frozenset({
    "error",
    "typing",
    "user_typing",
    "presence_change",
    "hello",
    "reconnect_url",
    "pong",
    "ping",
    "desktop_notification",
    "channel_marked",
    "im_marked",
})
_MAP_CONTAINER_KEYS = frozenset({
    "messages",
    "messagelist",
    "chatmessages",
    "replychain",
    "replies",
    "records",
    "items",
    "byid",
    "messagemap",
})


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize any datetime to naive UTC so DuckDB TIMESTAMP never shifts by host timezone."""
    if dt is None:
        return None
    norm = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt
    if norm.year < 1990 or norm.year > 2100:
        return None
    return norm


def _filetime_int_to_naive_utc(ft_ticks: int) -> Optional[datetime]:
    """Exact 64-bit integer Windows FILETIME (100-ns ticks since 1601-01-01) -> naive UTC datetime."""
    if ft_ticks <= _FILETIME_EPOCH_DIFF_TICKS:
        return None
    unix_100ns = ft_ticks - _FILETIME_EPOCH_DIFF_TICKS
    seconds, rem_100ns = divmod(unix_100ns, 10_000_000)
    if seconds <= 631152000 or seconds > 4102444800:
        return None
    try:
        dt = datetime(1970, 1, 1) + timedelta(seconds=seconds, microseconds=rem_100ns // 10)
        return _to_naive_utc(dt)
    except (OverflowError, ValueError):
        return None


def _parse_chat_timestamp(raw_ts: Any) -> Optional[datetime]:
    """Convert Unix s/ms/us/ns, FILETIME, Slack ts, or ISO-8601 string mathematically to naive UTC."""
    if raw_ts is None or isinstance(raw_ts, bool):
        return None
    if isinstance(raw_ts, datetime):
        return _to_naive_utc(raw_ts)

    if isinstance(raw_ts, int):
        if raw_ts <= 0:
            return None
        if 116_444_736_000_000_000 <= raw_ts <= 160_000_000_000_000_000:
            return _filetime_int_to_naive_utc(raw_ts)
        if raw_ts > 1_000_000_000_000_000_000:
            epoch_s = raw_ts / 1_000_000_000.0
        elif raw_ts > 1_000_000_000_000_000:
            epoch_s = raw_ts / 1_000_000.0
        elif raw_ts > 100_000_000_000:
            epoch_s = raw_ts / 1_000.0
        else:
            epoch_s = float(raw_ts)
        if 631152000 <= epoch_s <= 4102444800:
            return _to_naive_utc(datetime.fromtimestamp(epoch_s, tz=timezone.utc))
        return None

    if isinstance(raw_ts, float):
        if raw_ts <= 0:
            return None
        epoch_s = raw_ts
        if epoch_s > 1_000_000_000_000_000:
            epoch_s /= 1_000_000.0
        elif epoch_s > 100_000_000_000:
            epoch_s /= 1_000.0
        if 631152000 <= epoch_s <= 4102444800:
            return _to_naive_utc(datetime.fromtimestamp(epoch_s, tz=timezone.utc))
        return None

    if isinstance(raw_ts, str):
        s = raw_ts.strip()
        if not s:
            return None
        if re.match(r"^\d+$", s):
            return _parse_chat_timestamp(int(s))
        if re.match(r"^\d+\.\d+$", s):
            try:
                return _parse_chat_timestamp(float(s))
            except ValueError:
                return None
        m_iso = _ISO_TS_RE.match(s)
        if m_iso:
            d_part, t_part, tz_part = m_iso.group(1), m_iso.group(2), m_iso.group(3)
            iso_norm = f"{d_part}T{t_part}"
            if tz_part:
                tz_u = tz_part.upper()
                if tz_u == "Z":
                    iso_norm += "+00:00"
                elif len(tz_u) == 5 and tz_u[0] in "+-":
                    iso_norm += f"{tz_u[:3]}:{tz_u[3:]}"
                else:
                    iso_norm += tz_u
            try:
                dt = datetime.fromisoformat(iso_norm)
                return _to_naive_utc(dt)
            except ValueError:
                pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return _to_naive_utc(dt)
        except ValueError:
            return None

    return None


def _read_varint(buf: bytes, pos: int, limit: Optional[int] = None) -> Optional[Tuple[int, int]]:
    """Decode unsigned LEB128 varint from buf[pos:limit], returning (value, next_pos) or None."""
    end = len(buf) if limit is None else min(len(buf), limit)
    result = 0
    shift = 0
    while pos < end and shift <= 63:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    return None


def _snappy_decompress_pure_python(data: bytes) -> Optional[bytes]:
    """Pure-Python Snappy raw block format decompressor (fallback when cramjam/python-snappy absent)."""
    if not data:
        return b""
    hdr = _read_varint(data, 0)
    if hdr is None:
        return None
    target_len, pos = hdr
    if target_len < 0 or target_len > 32 * 1024 * 1024:
        return None
    if target_len == 0:
        return b""

    out = bytearray()
    data_len = len(data)

    while pos < data_len and len(out) < target_len:
        tag = data[pos]
        pos += 1
        tag_type = tag & 0x03

        if tag_type == 0:  # Literal
            len_code = tag >> 2
            if len_code < 60:
                lit_len = len_code + 1
            else:
                extra_bytes = len_code - 59
                if pos + extra_bytes > data_len:
                    return None
                lit_len = int.from_bytes(data[pos : pos + extra_bytes], "little") + 1
                pos += extra_bytes
            if pos + lit_len > data_len:
                return None
            out.extend(data[pos : pos + lit_len])
            pos += lit_len
        else:
            if tag_type == 1:  # Copy with 1-byte offset
                if pos >= data_len:
                    return None
                copy_len = 4 + ((tag >> 2) & 0x07)
                offset = ((tag & 0xE0) << 3) | data[pos]
                pos += 1
            elif tag_type == 2:  # Copy with 2-byte offset
                if pos + 2 > data_len:
                    return None
                copy_len = 1 + (tag >> 2)
                offset = struct.unpack_from("<H", data, pos)[0]
                pos += 2
            else:  # Copy with 4-byte offset
                if pos + 4 > data_len:
                    return None
                copy_len = 1 + (tag >> 2)
                offset = struct.unpack_from("<I", data, pos)[0]
                pos += 4

            if offset <= 0 or offset > len(out):
                return None
            if copy_len <= offset:
                start = len(out) - offset
                out.extend(out[start : start + copy_len])
            else:
                for _ in range(copy_len):
                    out.append(out[-offset])

    if len(out) != target_len:
        return None
    return bytes(out)


def _decompress_snappy_raw(payload: bytes) -> Optional[bytes]:
    """Decompress raw Snappy block via cramjam -> python-snappy -> pure-Python fallback."""
    if cramjam is not None:
        try:
            return bytes(cramjam.snappy.decompress_raw(payload))
        except Exception:
            pass
    if python_snappy is not None:
        try:
            return bytes(python_snappy.decompress(payload))
        except Exception:
            pass
    return _snappy_decompress_pure_python(payload)


def _extract_leveldb_log_buffers(raw: bytes) -> List[bytes]:
    """
    Reassemble LevelDB .log 32KB block chunks (FULL=1, FIRST=2, MIDDLE=3, LAST=4)
    and unpack LevelDB WriteBatch records into raw value payloads.
    """
    records: List[bytes] = []
    frag = bytearray()
    in_frag = False

    for block_start in range(0, len(raw), _LEVELDB_LOG_BLOCK_SIZE):
        block = raw[block_start : block_start + _LEVELDB_LOG_BLOCK_SIZE]
        pos = 0
        blk_len = len(block)
        while pos + 7 <= blk_len:
            _, rec_len, rec_type = struct.unpack_from("<IHB", block, pos)
            if rec_len == 0 and rec_type == 0:
                break
            if rec_type not in (1, 2, 3, 4) or pos + 7 + rec_len > blk_len:
                break
            chunk = block[pos + 7 : pos + 7 + rec_len]
            pos += 7 + rec_len

            if rec_type == 1:  # FULL
                frag.clear()
                in_frag = False
                records.append(chunk)
            elif rec_type == 2:  # FIRST
                frag = bytearray(chunk)
                in_frag = True
            elif rec_type == 3:  # MIDDLE
                if in_frag:
                    frag.extend(chunk)
            elif rec_type == 4:  # LAST
                if in_frag:
                    frag.extend(chunk)
                    records.append(bytes(frag))
                    frag.clear()
                    in_frag = False

    if not records:
        return [raw] if raw else []

    unpacked: List[bytes] = []
    for rec in records:
        # LevelDB WriteBatch: 8-byte sequence + 4-byte count, followed by tagged entries
        extracted_any = False
        if len(rec) > 12:
            pos = 12
            rec_end = len(rec)
            while pos < rec_end:
                op_tag = rec[pos]
                pos += 1
                if op_tag == 0x01:  # kTypeValue
                    kh = _read_varint(rec, pos, rec_end)
                    if kh is None:
                        break
                    klen, pos = kh
                    if pos + klen > rec_end:
                        break
                    pos += klen
                    vh = _read_varint(rec, pos, rec_end)
                    if vh is None:
                        break
                    vlen, pos = vh
                    if pos + vlen > rec_end:
                        break
                    val_slice = rec[pos : pos + vlen]
                    pos += vlen
                    if val_slice:
                        unpacked.append(val_slice)
                        extracted_any = True
                elif op_tag == 0x00:  # kTypeDeletion
                    kh = _read_varint(rec, pos, rec_end)
                    if kh is None:
                        break
                    klen, pos = kh
                    if pos + klen > rec_end:
                        break
                    pos += klen
                else:
                    break
        if not extracted_any:
            unpacked.append(rec)

    return unpacked


def _read_sstable_block(raw: bytes, offset: int, size: int) -> Optional[bytes]:
    """Read and decompress a LevelDB SSTable block (5-byte trailer: 1B compression_type + 4B crc)."""
    if offset < 0 or size < 0 or offset + size + 1 > len(raw):
        return None
    payload = raw[offset : offset + size]
    comp_type = raw[offset + size]
    if comp_type == 0x00:
        return payload
    if comp_type == 0x01:
        return _decompress_snappy_raw(payload)
    return None


def _iter_sstable_block_values(block: bytes) -> Iterable[bytes]:
    """Iterate contiguous value slices inside a LevelDB SSTable prefix-compressed block."""
    if len(block) < 4:
        return
    num_restarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    trailer_bytes = 4 * (1 + num_restarts)
    if num_restarts > 65536 or trailer_bytes > len(block):
        return
    entries_end = len(block) - trailer_bytes
    pos = 0
    while pos < entries_end:
        s_res = _read_varint(block, pos, entries_end)
        if s_res is None:
            break
        _, pos = s_res
        ns_res = _read_varint(block, pos, entries_end)
        if ns_res is None:
            break
        non_shared, pos = ns_res
        vl_res = _read_varint(block, pos, entries_end)
        if vl_res is None:
            break
        val_len, pos = vl_res
        if pos + non_shared + val_len > entries_end:
            break
        pos += non_shared
        val_bytes = block[pos : pos + val_len]
        pos += val_len
        yield val_bytes


def _extract_leveldb_sst_buffers(raw: bytes) -> List[bytes]:
    """
    Parse LevelDB .ldb / .sst SSTables via the 48-byte footer (magic 0xDB4775248B80FB57),
    decompressing all Snappy & uncompressed data blocks and extracting value slices.
    Falls back to raw bytes if the file lacks an SSTable footer.
    """
    if len(raw) < 48:
        return [raw] if raw else []
    magic = struct.unpack_from("<Q", raw, len(raw) - 8)[0]
    if magic != _LEVELDB_SST_MAGIC:
        return [raw]

    footer_handles = raw[len(raw) - 48 : len(raw) - 8]
    m_off = _read_varint(footer_handles, 0)
    if m_off is None:
        return [raw]
    _, pos = m_off
    m_sz = _read_varint(footer_handles, pos)
    if m_sz is None:
        return [raw]
    _, pos = m_sz
    i_off = _read_varint(footer_handles, pos)
    if i_off is None:
        return [raw]
    idx_offset, pos = i_off
    i_sz = _read_varint(footer_handles, pos)
    if i_sz is None:
        return [raw]
    idx_size, _ = i_sz

    index_block = _read_sstable_block(raw, idx_offset, idx_size)
    if not index_block:
        return [raw]

    buffers: List[bytes] = []
    for handle_bytes in _iter_sstable_block_values(index_block):
        bo_res = _read_varint(handle_bytes, 0)
        if bo_res is None:
            continue
        blk_off, hpos = bo_res
        bs_res = _read_varint(handle_bytes, hpos)
        if bs_res is None:
            continue
        blk_sz, _ = bs_res
        data_block = _read_sstable_block(raw, blk_off, blk_sz)
        if not data_block:
            continue
        kv_vals = [v for v in _iter_sstable_block_values(data_block) if v]
        if kv_vals:
            buffers.extend(kv_vals)
        else:
            buffers.append(data_block)

    return buffers if buffers else [raw]


def _decode_dual_utf8_utf16le_texts(buf: bytes) -> List[str]:
    """Extract candidate text strings from a LevelDB buffer in BOTH UTF-8 and UTF-16LE."""
    texts: List[str] = []
    if not buf:
        return texts
    if b"{" in buf:
        texts.append(buf.decode("utf-8", errors="replace"))
    if b"{\x00" in buf or b"\x00{" in buf:
        for m in _UTF16LE_RUN_RE.finditer(buf):
            run = m.group(0)
            if b"{\x00" in run:
                texts.append(run.decode("utf-16-le", errors="ignore"))
        # Also support full-buffer UTF-16LE records containing non-ASCII Unicode chat characters
        if len(buf) >= 24:
            for align in (0, 1):
                if b"{\x00" in buf[align:]:
                    even_len = ((len(buf) - align) // 2) * 2
                    if even_len >= 24:
                        cand_u16 = buf[align : align + even_len].decode("utf-16-le", errors="ignore")
                        if "{" in cand_u16 and "}" in cand_u16:
                            texts.append(cand_u16)
    return texts


def _extract_balanced_json_dicts(text: str) -> List[Dict[str, Any]]:
    """
    Scan text for balanced nested JSON objects using json.JSONDecoder().raw_decode.
    Advances past outer broken braces so nested inner message dicts are still recovered.
    """
    results: List[Dict[str, Any]] = []
    if "{" not in text or "}" not in text:
        return results

    decoder = json.JSONDecoder()
    n = len(text)
    idx = text.find("{")
    while 0 <= idx < n:
        try:
            obj, end_idx = decoder.raw_decode(text, idx)
            if isinstance(obj, dict):
                results.append(obj)
            idx = text.find("{", end_idx)
        except json.JSONDecodeError:
            idx = text.find("{", idx + 1)
    return results


def _clean_chat_html(raw_text: str) -> Tuple[str, List[str]]:
    """Strip HTML tags from Teams/Skype rich messages while preserving embedded links."""
    if not raw_text:
        return "", []
    links = list(dict.fromkeys(_HREF_SRC_RE.findall(raw_text)))
    if "<" in raw_text and ">" in raw_text:
        cleaned = _HTML_TAG_RE.sub(" ", raw_text)
        cleaned = html.unescape(cleaned)
    else:
        cleaned = raw_text
    return " ".join(cleaned.split()).strip(), links


class ChatParser(BaseParser):
    """
    Parser for Microsoft Teams, Discord, Slack, Skype, WhatsApp, Telegram,
    and Windows Push Notifications (wpndatabase.db).
    Populates parsed_chat_messages and parsed_notifications.
    """

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

    def _detect_app_and_profile(self, file_path: Path) -> Tuple[str, str]:
        """Infer canonical chat application name and user profile from staged relative path."""
        try:
            rel_path = file_path.resolve().relative_to(self.staging_dir.resolve())
            path_norm = "/" + rel_path.as_posix()
            search_parts = rel_path.parts[:-1]
        except Exception:
            path_norm = str(file_path).replace("\\", "/")
            search_parts = file_path.parts[:-1]

        path_lower = path_norm.lower()

        if "discord" in path_lower:
            app_name = "Discord"
        elif "slack" in path_lower:
            app_name = "Slack"
        elif "msteams" in path_lower or "teams" in path_lower or "8wekyb3d8bbwe" in path_lower:
            app_name = "Teams"
        elif "skype" in path_lower:
            app_name = "Skype"
        elif "whatsapp" in path_lower:
            app_name = "WhatsApp"
        elif "telegram" in path_lower:
            app_name = "Telegram"
        else:
            app_name = "Teams"

        # Prefer explicit Windows username from Users/<User>/... or Browsers/<B>/<User>/... or Chat/<App>/<User>/...
        m_users = re.search(r"(?i)(?:^|/)(?:users|userfiles)/([^/]+)/", path_norm)
        if m_users and m_users.group(1).lower() not in ("public", "default"):
            return app_name, m_users.group(1)

        m_browsers = re.search(r"(?i)(?:^|/)browsers/[^/]+/([^/]+)/", path_norm)
        if m_browsers:
            return app_name, m_browsers.group(1)

        m_chat = re.search(r"(?i)(?:^|/)chat/[^/]+/([^/]+)/", path_norm)
        if m_chat and not m_chat.group(1).lower().endswith((".ldb", ".log", ".db", ".sqlite")):
            return app_name, m_chat.group(1)

        skip_segments = {
            "leveldb",
            "indexeddb",
            "local storage",
            "session storage",
            "ebwebview",
            "default",
            "chat",
            "roaming",
            "local",
            "appdata",
            "packages",
            "localstate",
            "localcache",
            "databases",
            "blob_storage",
            "staging",
            "enrichment",
            "sqlite",
        }
        profile = "Default"
        for part in reversed(search_parts):
            p_low = part.lower()
            if p_low in skip_segments or p_low.endswith(".leveldb") or p_low.endswith(".indexeddb"):
                continue
            if p_low in ("discord", "slack", "teams", "msteams", "skype", "whatsapp", "telegram"):
                continue
            profile = part
            break

        return app_name, profile

    def _extract_single_chat_dict(
        self,
        obj: Dict[str, Any],
        lower_keys: Set[str],
        default_app: str,
        profile: str,
        resolved_source: str,
        in_msg_container: bool = False,
    ) -> List[Dict[str, Any]]:
        """Validate `obj` itself against strict Teams / Discord / Slack / structured chat schemas."""
        # ------------------------------------------------------------------
        # 1. Microsoft Teams (Classic Electron & WebView2 v2 IndexedDB)
        # ------------------------------------------------------------------
        teams_markers = lower_keys & {
            "composetime",
            "originalarrivaltime",
            "imdisplayname",
            "conversationid",
            "clientmessageid",
            "messagetype",
            "composetransactionid",
            "amsreferences",
        }
        if len(teams_markers) >= 2 or (
            "messagetype" in lower_keys and ("composetime" in lower_keys or "originalarrivaltime" in lower_keys)
        ):
            for t_cand in (
                obj.get("messagetype"),
                obj.get("messageType"),
                obj.get("type"),
                obj.get("eventType"),
                obj.get("eventtype"),
            ):
                msg_type = str(t_cand or "").strip().lower()
                if msg_type and (
                    msg_type in _NON_MESSAGE_EVENT_TYPES
                    or "typing" in msg_type
                    or any(msg_type.startswith(sk) for sk in _TEAMS_SKIP_MSGTYPES)
                ):
                    return []

            raw_body: Any = obj.get("content")
            if raw_body is None:
                b_field = obj.get("body")
                if isinstance(b_field, dict):
                    raw_body = b_field.get("content")
                elif isinstance(b_field, str):
                    raw_body = b_field

            clean_txt, html_links = _clean_chat_html(str(raw_body or ""))
            att_urls: List[str] = list(html_links)
            props_field = obj.get("properties")
            if isinstance(props_field, dict):
                files_val = props_field.get("files")
                if isinstance(files_val, str) and files_val.startswith("["):
                    try:
                        files_arr = json.loads(files_val)
                        if isinstance(files_arr, list):
                            for f_item in files_arr:
                                if isinstance(f_item, dict):
                                    f_url = f_item.get("objectUrl") or f_item.get("filePreview", {}).get("previewUrl")
                                    if f_url:
                                        att_urls.append(str(f_url))
                    except Exception:
                        pass
            ams = obj.get("amsreferences")
            if isinstance(ams, list):
                for a_ref in ams:
                    if isinstance(a_ref, str) and a_ref:
                        att_urls.append(a_ref)

            if not clean_txt and not att_urls:
                return []

            ts_dt = _parse_chat_timestamp(
                obj.get("originalarrivaltime")
                or obj.get("originalArrivalTime")
                or obj.get("composetime")
                or obj.get("composeTime")
                or obj.get("createdDateTime")
                or obj.get("timestamp")
            )
            if ts_dt is None:
                return []

            sender = str(
                obj.get("imdisplayname")
                or obj.get("imDisplayName")
                or obj.get("creatorName")
                or ""
            ).strip()
            if not sender:
                from_val = obj.get("from")
                if isinstance(from_val, dict):
                    u_info = from_val.get("user") if isinstance(from_val.get("user"), dict) else from_val
                    sender = str(u_info.get("displayName") or u_info.get("id") or "").strip()
                elif isinstance(from_val, str):
                    sender = from_val.strip()
            if not sender:
                sender = str(obj.get("creator") or "").strip()

            channel = str(
                obj.get("conversationId")
                or obj.get("conversationid")
                or obj.get("threadId")
                or ""
            ).strip()
            return [{
                "app_name": "Teams",
                "profile": profile,
                "timestamp_utc": ts_dt,
                "sender": sender,
                "recipient_channel": channel,
                "message_text": (clean_txt or "[Attachment]")[:4000],
                "attachment_url": att_urls[0] if att_urls else "",
                "source_file": resolved_source,
            }]

        # ------------------------------------------------------------------
        # 2. Discord (Nested author/webhook_id + channel_id + id + valid timestamp)
        # ------------------------------------------------------------------
        if not (lower_keys & _PACKAGE_OR_SOURCEMAP_KEYS):
            author_obj = obj.get("author")
            has_discord_author = isinstance(author_obj, dict) and bool(
                author_obj.get("username") or author_obj.get("global_name") or author_obj.get("id")
            )
            has_webhook_id = bool(str(obj.get("webhook_id") or "").strip())
            discord_channel_id = str(obj.get("channel_id") or "").strip()
            discord_msg_id = str(obj.get("id") or "").strip()
            if discord_channel_id and discord_msg_id and (has_discord_author or has_webhook_id):
                ts_dt = _parse_chat_timestamp(obj.get("timestamp") or obj.get("edited_timestamp"))
                if ts_dt is not None:
                    content_val = obj.get("content")
                    msg_txt = str(content_val).strip() if isinstance(content_val, str) else ""
                    att_url = ""
                    atts = obj.get("attachments")
                    if isinstance(atts, list):
                        for att in atts:
                            if isinstance(att, dict):
                                u = att.get("url") or att.get("proxy_url")
                                if isinstance(u, str) and u.strip():
                                    att_url = u.strip()
                                    break
                    if msg_txt or att_url:
                        sender = ""
                        if isinstance(author_obj, dict):
                            sender = str(
                                author_obj.get("username")
                                or author_obj.get("global_name")
                                or author_obj.get("name")
                                or author_obj.get("id")
                                or ""
                            ).strip()
                        if not sender and has_webhook_id:
                            sender = f"webhook:{str(obj.get('webhook_id')).strip()}"
                        return [{
                            "app_name": "Discord",
                            "profile": profile,
                            "timestamp_utc": ts_dt,
                            "sender": sender,
                            "recipient_channel": discord_channel_id,
                            "message_text": (msg_txt or f"[Attachment] {att_url}")[:4000],
                            "attachment_url": att_url,
                            "source_file": resolved_source,
                        }]

        # ------------------------------------------------------------------
        # 3. Slack (Slack epoch ts '1700000000.000100' + type in ('message','app_mention') + sender marker)
        # ------------------------------------------------------------------
        ts_slack_raw = obj.get("ts")
        if isinstance(ts_slack_raw, str) and _SLACK_TS_VAL_RE.match(ts_slack_raw.strip()):
            raw_slack_type = obj.get("type")
            if raw_slack_type is not None and str(raw_slack_type).strip() != "":
                if str(raw_slack_type).strip().lower() not in ("message", "app_mention"):
                    return []
            slack_subtype = str(obj.get("subtype") or "").strip().lower()
            if slack_subtype in {
                "channel_join", "channel_leave", "channel_topic", "channel_purpose",
                "channel_name", "channel_archive", "channel_unarchive", "group_join",
                "group_leave", "group_topic", "group_purpose", "group_name",
                "group_archive", "group_unarchive", "bot_add", "bot_remove",
                "pinned_item", "unpinned_item", "tombstone", "ekm_access_denied",
                "channel_convert_to_private", "channel_convert_to_public",
            }:
                return []
            u_prof = obj.get("user_profile")
            has_slack_sender_marker = any(
                bool(str(obj.get(k) or "").strip())
                for k in ("user", "username", "bot_id", "client_msg_id")
            ) or (
                isinstance(u_prof, dict)
                and bool(u_prof.get("display_name") or u_prof.get("real_name"))
            )
            ts_dt = _parse_chat_timestamp(ts_slack_raw)
            if has_slack_sender_marker and ts_dt is not None:
                text_val = obj.get("text")
                msg_txt = html.unescape(str(text_val).strip()) if isinstance(text_val, str) else ""
                att_url = ""
                for list_key in ("files", "attachments"):
                    items = obj.get(list_key)
                    if isinstance(items, list):
                        for it in items:
                            if isinstance(it, dict):
                                u = (
                                    it.get("url_private")
                                    or it.get("url_private_download")
                                    or it.get("permalink")
                                    or it.get("image_url")
                                    or it.get("from_url")
                                )
                                if isinstance(u, str) and u.strip():
                                    att_url = u.strip()
                                    break
                    if att_url:
                        break
                if msg_txt or att_url:
                    sender = str(
                        obj.get("username")
                        or obj.get("user")
                        or obj.get("bot_id")
                        or ""
                    ).strip()
                    if isinstance(u_prof, dict) and (u_prof.get("display_name") or u_prof.get("real_name")):
                        sender = str(u_prof.get("display_name") or u_prof.get("real_name")).strip()
                    channel = str(obj.get("channel") or obj.get("team") or "").strip()
                    return [{
                        "app_name": "Slack",
                        "profile": profile,
                        "timestamp_utc": ts_dt,
                        "sender": sender,
                        "recipient_channel": channel,
                        "message_text": (msg_txt or f"[Attachment] {att_url}")[:4000],
                        "attachment_url": att_url,
                        "source_file": resolved_source,
                    }]
            return []

        # ------------------------------------------------------------------
        # 4. Skype / WhatsApp / Telegram / Strict Validated Structured Chat
        #    Requires non-empty text AND explicit sender AND valid timestamp + channel
        # ------------------------------------------------------------------
        if lower_keys & _PACKAGE_OR_SOURCEMAP_KEYS:
            return []
        for t_cand in (obj.get("type"), obj.get("eventType"), obj.get("messageType"), obj.get("messagetype")):
            g_type = str(t_cand or "").strip().lower()
            if g_type and (
                g_type in _NON_MESSAGE_EVENT_TYPES
                or "typing" in g_type
                or any(g_type.startswith(sk) for sk in _TEAMS_SKIP_MSGTYPES)
            ):
                return []

        body_cand = (
            obj.get("body_xml")
            or obj.get("message_text")
            or obj.get("text")
            or obj.get("content")
            or obj.get("body")
        )
        if not isinstance(body_cand, str) or not body_cand.strip():
            return []

        sender_cand = (
            obj.get("from_dispname")
            or obj.get("senderName")
            or obj.get("sender_name")
            or obj.get("sender_id")
            or obj.get("senderId")
            or obj.get("sender")
            or (obj.get("author") if isinstance(obj.get("author"), str) else None)
            or (obj.get("from") if isinstance(obj.get("from"), str) else None)
            or obj.get("from_id")
        )
        channel_cand = (
            obj.get("convo_id")
            or obj.get("conversation_id")
            or obj.get("conversationId")
            or obj.get("channel_id")
            or obj.get("chat_id")
            or obj.get("key_remote_jid")
            or obj.get("room_id")
        )
        ts_cand = _parse_chat_timestamp(
            obj.get("timestamp__ms")
            or obj.get("timestamp")
            or obj.get("created_at")
            or obj.get("sent_at")
            or obj.get("date")
        )
        if not sender_cand or ts_cand is None or (not channel_cand and not in_msg_container):
            return []

        clean_txt, links = _clean_chat_html(body_cand)
        if not clean_txt:
            return []

        inferred_app = default_app
        if "convo_id" in obj or "body_xml" in obj:
            inferred_app = "Skype"
        elif "key_remote_jid" in obj:
            inferred_app = "WhatsApp"
        elif "chat_id" in obj and "from_id" in obj:
            inferred_app = "Telegram"

        return [{
            "app_name": inferred_app,
            "profile": profile,
            "timestamp_utc": ts_cand,
            "sender": str(sender_cand).strip(),
            "recipient_channel": str(channel_cand or "").strip(),
            "message_text": clean_txt[:4000],
            "attachment_url": links[0] if links else "",
            "source_file": resolved_source,
        }]

    def _validate_and_extract_chat_dicts(
        self,
        obj: Any,
        default_app: str,
        profile: str,
        resolved_source: str,
        depth: int = 0,
        allow_id_map: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Recursively unwrap container dicts/lists (including ID-keyed message maps and thread replies)
        and strictly validate platform chat schemas. Produces ZERO false positives on arbitrary
        Electron/Chromium config, package metadata, typing/control events, or HTTP error JSON.
        """
        if depth > 6:
            return []
        if isinstance(obj, list):
            out: List[Dict[str, Any]] = []
            for item in obj[:1000]:
                out.extend(
                    self._validate_and_extract_chat_dicts(
                        item, default_app, profile, resolved_source, depth + 1, allow_id_map=allow_id_map
                    )
                )
            return out
        if not isinstance(obj, dict) or not obj:
            return []

        lower_keys = {str(k).lower() for k in obj.keys()}
        if lower_keys & _NON_CHAT_REJECT_KEYS:
            return []

        # Extract `self_records` from `obj` itself (so parent messages with `replies`/`replyChain` are preserved!)
        self_records = self._extract_single_chat_dict(
            obj, lower_keys, default_app, profile, resolved_source, in_msg_container=allow_id_map
        )

        nested_results: List[Dict[str, Any]] = []
        for container_key in (
            "messages",
            "messagelist",
            "chatmessages",
            "replychain",
            "replies",
            "records",
            "items",
            "byid",
            "messagemap",
            "value",
            "record",
            "data",
        ):
            is_map_container = container_key in _MAP_CONTAINER_KEYS
            for actual_k, actual_v in obj.items():
                if str(actual_k).lower() == container_key and isinstance(actual_v, (dict, list)):
                    nested_results.extend(
                        self._validate_and_extract_chat_dicts(
                            actual_v,
                            default_app,
                            profile,
                            resolved_source,
                            depth + 1,
                            allow_id_map=is_map_container,
                        )
                    )

        if self_records or nested_results:
            return self_records + nested_results

        # If `obj` was reached via a known message-container key (`messages`, `byId`, `messageMap`, etc.)
        # and is a normalized ID-keyed dictionary (`{"1307310009": {...}}`), inspect its values!
        if allow_id_map:
            map_results: List[Dict[str, Any]] = []
            for sub_v in list(obj.values())[:1000]:
                if isinstance(sub_v, (dict, list)):
                    map_results.extend(
                        self._validate_and_extract_chat_dicts(
                            sub_v,
                            default_app,
                            profile,
                            resolved_source,
                            depth + 1,
                            allow_id_map=True,
                        )
                    )
            return map_results

        return []

    def _parse_leveldb_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse LevelDB .log (32KB framed) and .ldb/.sst (SSTable + Snappy) in UTF-8 & UTF-16LE."""
        app_name, profile = self._detect_app_and_profile(file_path)
        try:
            raw_bytes = file_path.read_bytes()
        except Exception as ex:
            self._log(f"Cannot read LevelDB file {file_path}: {ex}", "WARNING")
            return []
        if not raw_bytes:
            return []

        resolved_source = self.resolve_evidence_path(file_path, len(raw_bytes))
        sfx = file_path.suffix.lower()
        if sfx == ".log":
            buffers = _extract_leveldb_log_buffers(raw_bytes)
        else:
            buffers = _extract_leveldb_sst_buffers(raw_bytes)

        records: List[Dict[str, Any]] = []
        for buf in buffers:
            for text in _decode_dual_utf8_utf16le_texts(buf):
                for obj in _extract_balanced_json_dicts(text):
                    records.extend(
                        self._validate_and_extract_chat_dicts(
                            obj=obj,
                            default_app=app_name,
                            profile=profile,
                            resolved_source=resolved_source,
                        )
                    )
        return records

    @staticmethod
    def _pick_priority_col(col_map: Dict[str, str], priorities: Iterable[str]) -> Optional[str]:
        for cand in priorities:
            if cand in col_map:
                return col_map[cand]
        return None

    def _parse_chat_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """Parse SQLite chat databases (Skype, WhatsApp, Telegram, Teams/Slack cache DBs) without row truncation."""
        try:
            with open(db_path, "rb") as fh:
                if fh.read(16) != b"SQLite format 3\x00":
                    return []
        except OSError:
            return []

        app_name, profile = self._detect_app_and_profile(db_path)
        resolved_source = self.resolve_evidence_path(db_path)
        temp_db = copy_sqlite_with_wal(db_path, temp_dir)
        records: List[Dict[str, Any]] = []

        conn = sqlite3.connect(str(temp_db))
        try:
            cursor = conn.cursor()
            tables = [
                str(row[0])
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            ]

            for table in tables:
                t_low = table.lower()
                if t_low in ("meta", "metadata", "migrations", "schema_migrations", "settings", "kv"):
                    continue
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map: Dict[str, str] = {str(c[1]).lower(): str(c[1]) for c in cols_info}

                # 1. Skype v12 JSON table (messagesv12.nsp_data) or JSON-blob cache tables
                json_blob_col = self._pick_priority_col(
                    col_map, ("nsp_data", "json_data", "message_json", "payload", "value")
                )
                text_col = self._pick_priority_col(
                    col_map,
                    ("body_xml", "message_text", "text_data", "content", "text", "body", "message"),
                )
                sender_col = self._pick_priority_col(
                    col_map,
                    ("from_dispname", "sender", "author", "username", "display_name", "user", "from_id", "sender_jid_row_id"),
                )
                time_col = self._pick_priority_col(
                    col_map,
                    ("timestamp__ms", "timestamp", "created_time", "created_at", "sent_at", "time", "date"),
                )
                channel_col = self._pick_priority_col(
                    col_map,
                    ("convo_id", "chatname", "conversation_id", "conversation", "channel_id", "channel", "thread", "room", "chat_row_id", "key_remote_jid"),
                )
                att_col = self._pick_priority_col(
                    col_map,
                    ("attachment_url", "media_url", "file_url"),
                )

                if text_col and (sender_col or time_col):
                    q_txt = text_col.replace('"', '""')
                    s_expr = f'"{sender_col.replace(chr(34), chr(34)*2)}"' if sender_col else "''"
                    t_expr = f'"{time_col.replace(chr(34), chr(34)*2)}"' if time_col else "NULL"
                    c_expr = f'"{channel_col.replace(chr(34), chr(34)*2)}"' if channel_col else "''"
                    a_expr = f'"{att_col.replace(chr(34), chr(34)*2)}"' if att_col else "''"
                    sql = f'SELECT "{q_txt}", {s_expr}, {t_expr}, {c_expr}, {a_expr} FROM "{q_table}" WHERE "{q_txt}" IS NOT NULL;'
                    for raw_text, raw_sender, raw_time, raw_chan, raw_att in cursor.execute(sql):
                        if isinstance(raw_text, (bytes, bytearray)):
                            txt_str = bytes(raw_text).decode("utf-8", errors="replace")
                        else:
                            txt_str = str(raw_text or "")
                        txt_strip = txt_str.strip()
                        if not txt_strip:
                            continue
                        if txt_strip.startswith("{") and txt_strip.endswith("}"):
                            for j_obj in _extract_balanced_json_dicts(txt_strip):
                                records.extend(
                                    self._validate_and_extract_chat_dicts(
                                        j_obj, app_name, profile, resolved_source
                                    )
                                )
                            continue
                        clean_txt, links = _clean_chat_html(txt_strip)
                        if not clean_txt:
                            continue
                        ts_dt = _parse_chat_timestamp(raw_time)
                        att_val = str(raw_att or "").strip() or (links[0] if links else "")
                        inferred = "Skype" if "body_xml" in col_map or "convo_id" in col_map else app_name
                        records.append({
                            "app_name": inferred,
                            "profile": profile,
                            "timestamp_utc": ts_dt,
                            "sender": str(raw_sender or "").strip(),
                            "recipient_channel": str(raw_chan or "").strip(),
                            "message_text": clean_txt[:4000],
                            "attachment_url": att_val,
                            "source_file": resolved_source,
                        })
                elif json_blob_col:
                    q_j = json_blob_col.replace('"', '""')
                    sql_j = f'SELECT "{q_j}" FROM "{q_table}" WHERE "{q_j}" IS NOT NULL;'
                    for (raw_blob,) in cursor.execute(sql_j):
                        if isinstance(raw_blob, (bytes, bytearray)):
                            texts = _decode_dual_utf8_utf16le_texts(bytes(raw_blob))
                        else:
                            s_blob = str(raw_blob or "")
                            texts = [s_blob] if "{" in s_blob else []
                        for t_str in texts:
                            for j_obj in _extract_balanced_json_dicts(t_str):
                                records.extend(
                                    self._validate_and_extract_chat_dicts(
                                        j_obj, app_name, profile, resolved_source
                                    )
                                )
        except sqlite3.DatabaseError as ex:
            self._log(f"SQLite notice on {db_path.name}: {ex}", "DEBUG")
        finally:
            conn.close()

        return records

    @staticmethod
    def _clean_app_id(raw_app: str) -> str:
        """Normalize raw Windows AUMID / Handler PrimaryId to human-readable form."""
        raw_lower = raw_app.lower()
        if "slack" in raw_lower:
            return "Slack"
        if "team" in raw_lower:
            return "Microsoft Teams"
        if "discord" in raw_lower:
            return "Discord"
        if "whatsapp" in raw_lower:
            return "WhatsApp"
        if "skype" in raw_lower:
            return "Skype"
        if "telegram" in raw_lower:
            return "Telegram"
        if "outlook" in raw_lower:
            return "Microsoft Outlook"
        if "chrome" in raw_lower:
            return "Google Chrome"
        if "edge" in raw_lower or "msedge" in raw_lower:
            return "Microsoft Edge"
        if "firefox" in raw_lower:
            return "Mozilla Firefox"
        clean = re.sub(r"^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*!App$", "", raw_app)
        return clean or raw_app

    @staticmethod
    def _decode_notification_payload(payload: Union[bytes, str]) -> str:
        if isinstance(payload, str):
            s = payload
        elif isinstance(payload, (bytes, bytearray)):
            raw = bytes(payload)
            if raw.startswith(b"\xff\xfe"):
                s = raw[2:].decode("utf-16-le", errors="replace")
            elif raw.startswith(b"\xfe\xff"):
                s = raw[2:].decode("utf-16-be", errors="replace")
            elif raw.startswith(b"\xef\xbb\xbf"):
                s = raw[3:].decode("utf-8", errors="replace")
            elif len(raw) >= 4 and raw[1::2][:64].count(0) > len(raw[1::2][:64]) // 3:
                s = raw.decode("utf-16-le", errors="replace")
            else:
                try:
                    s = raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    s = raw.decode("latin-1", errors="replace")
        else:
            s = str(payload)
        s = s.lstrip("\ufeff").strip()
        s = _UNSAFE_XML_CTRL_RE.sub("", s)
        # Strip unsafe DTD/ENTITY declarations if present
        s = re.sub(r"<!DOCTYPE[^>]*>", "", s, flags=re.IGNORECASE)
        s = re.sub(r"<!ENTITY[^>]*>", "", s, flags=re.IGNORECASE)
        return s

    def _parse_notification_xml(self, payload: Union[bytes, str]) -> Dict[str, str]:
        """Parse XML payload of a Windows Toast Notification (UTF-8 & UTF-16LE safe)."""
        res = {"title": "", "body": "", "header": "", "action_url": ""}
        if not payload:
            return res

        xml_str = self._decode_notification_payload(payload)
        lt_pos = xml_str.find("<")
        if lt_pos == -1:
            return res
        if lt_pos > 0:
            xml_str = xml_str[lt_pos:]

        try:
            root = ET.fromstring(xml_str)
            res["action_url"] = root.attrib.get("launch", "")

            header_node = root.find(".//header")
            if header_node is not None:
                res["header"] = header_node.attrib.get("title", "") or header_node.attrib.get("id", "")

            if not res["action_url"]:
                action_node = root.find(".//action")
                if action_node is not None:
                    res["action_url"] = action_node.attrib.get("arguments", "")

            text_nodes = root.findall(".//text")
            texts = [t.text.strip() for t in text_nodes if t.text and t.text.strip()]
            if texts:
                res["title"] = texts[0]
                if len(texts) > 1:
                    res["body"] = " \n ".join(texts[1:])
        except Exception:
            texts = [html.unescape(t.strip()) for t in re.findall(r"<text[^>]*>([^<]+)</text>", xml_str) if t.strip()]
            if texts:
                res["title"] = texts[0]
                if len(texts) > 1:
                    res["body"] = " \n ".join(texts[1:])
            m_launch = re.search(r'launch="([^"]+)"', xml_str)
            if m_launch:
                res["action_url"] = html.unescape(m_launch.group(1))

        return res

    def _parse_wpndatabase(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """
        Parse Windows Push Notification SQLite database (wpndatabase.db) with exact
        64-bit integer FILETIME conversion to naive UTC.
        """
        try:
            with open(db_path, "rb") as fh:
                if fh.read(16) != b"SQLite format 3\x00":
                    return []
        except OSError:
            return []

        resolved_source = self.resolve_evidence_path(db_path)
        temp_db = copy_sqlite_with_wal(db_path, temp_dir)
        records: List[Dict[str, Any]] = []

        conn = sqlite3.connect(str(temp_db))
        try:
            cursor = conn.cursor()
            table_map: Dict[str, str] = {
                str(row[0]).lower(): str(row[0])
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            }

            handler_map: Dict[Any, str] = {}
            for h_low in ("notificationhandler", "handler"):
                if h_low in table_map:
                    actual_h = table_map[h_low].replace('"', '""')
                    try:
                        cols_info = cursor.execute(f'PRAGMA table_info("{actual_h}");').fetchall()
                        col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}
                        id_col = self._pick_priority_col(col_map, ("recordid", "handlerid", "id"))
                        name_col = self._pick_priority_col(col_map, ("primaryid", "handlername", "appid", "name"))
                        if id_col and name_col:
                            qid = id_col.replace('"', '""')
                            qnm = name_col.replace('"', '""')
                            for h_id, h_name in cursor.execute(f'SELECT "{qid}", "{qnm}" FROM "{actual_h}";'):
                                if h_id is not None and h_name:
                                    handler_map[h_id] = str(h_name)
                                    handler_map[str(h_id)] = str(h_name)
                    except Exception:
                        pass

            notif_actual = None
            for cand in ("notification", "notifications"):
                if cand in table_map:
                    notif_actual = table_map[cand]
                    break
            if not notif_actual:
                for t_actual in table_map.values():
                    qt = t_actual.replace('"', '""')
                    c_lows = {str(c[1]).lower() for c in cursor.execute(f'PRAGMA table_info("{qt}");').fetchall()}
                    if "payload" in c_lows:
                        notif_actual = t_actual
                        break

            if not notif_actual:
                return []

            qn = notif_actual.replace('"', '""')
            cols_info = cursor.execute(f'PRAGMA table_info("{qn}");').fetchall()
            n_col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}

            payload_col = self._pick_priority_col(n_col_map, ("payload", "data", "xml", "content"))
            time_col = self._pick_priority_col(n_col_map, ("arrivaltime", "bootid", "timestamp", "createdtime", "time"))
            # Ensure ArrivalTime beats BootId
            if "arrivaltime" in n_col_map:
                time_col = n_col_map["arrivaltime"]
            expiry_col = self._pick_priority_col(n_col_map, ("expirytime", "expirationtime", "expiry"))
            type_col = self._pick_priority_col(n_col_map, ("type", "notificationtype"))
            nid_col = self._pick_priority_col(n_col_map, ("id", "recordid", "notificationid"))
            handler_col = self._pick_priority_col(n_col_map, ("handlerid", "primaryid", "handler", "appid"))

            if not payload_col:
                return []

            def _qcol(cname: Optional[str]) -> str:
                if not cname:
                    return "NULL"
                escaped = cname.replace('"', '""')
                return f'"{escaped}"'

            qp = payload_col.replace('"', '""')
            query = (
                f'SELECT "{qp}", {_qcol(time_col)}, {_qcol(handler_col)}, '
                f'{_qcol(nid_col)}, {_qcol(type_col)}, {_qcol(expiry_col)} '
                f'FROM "{qn}" WHERE "{qp}" IS NOT NULL;'
            )
            for raw_payload, raw_time, raw_handler, raw_nid, raw_ntype, raw_expiry in cursor.execute(query):
                decoded_payload = self._decode_notification_payload(raw_payload)
                xml_data = self._parse_notification_xml(raw_payload)
                if not xml_data["title"] and not xml_data["body"] and not xml_data["header"]:
                    continue

                app_name = "Windows Notification"
                if raw_handler in handler_map:
                    app_name = self._clean_app_id(handler_map[raw_handler])
                elif str(raw_handler) in handler_map:
                    app_name = self._clean_app_id(handler_map[str(raw_handler)])
                elif raw_handler:
                    app_name = self._clean_app_id(str(raw_handler))
                elif xml_data["header"]:
                    app_name = self._clean_app_id(xml_data["header"])

                def _conv_wpn_time(val_t: Any) -> Optional[datetime]:
                    if val_t is None:
                        return None
                    if isinstance(val_t, int):
                        if val_t > 10_000_000_000_000_000:
                            return _filetime_int_to_naive_utc(val_t)
                        return _parse_chat_timestamp(val_t)
                    if isinstance(val_t, str) and val_t.strip().isdigit():
                        iv_local = int(val_t.strip())
                        if iv_local > 10_000_000_000_000_000:
                            return _filetime_int_to_naive_utc(iv_local)
                        return _parse_chat_timestamp(iv_local)
                    return _parse_chat_timestamp(val_t)

                # Exact integer arithmetic for 64-bit Windows FILETIME (zero IEEE-754 float precision loss)
                ts_dt = _conv_wpn_time(raw_time)
                exp_dt = _conv_wpn_time(raw_expiry)
                nid_val: Optional[int] = None
                if isinstance(raw_nid, int):
                    nid_val = raw_nid
                elif isinstance(raw_nid, str) and raw_nid.strip().isdigit():
                    nid_val = int(raw_nid.strip())

                records.append({
                    "notification_id": nid_val,
                    "app_id": app_name,
                    "notification_type": str(raw_ntype or "toast")[:128],
                    "payload": decoded_payload[:16000],
                    "arrival_time": ts_dt,
                    "expiry_time": exp_dt,
                    "timestamp_utc": ts_dt,
                    "title": xml_data["title"][:1000],
                    "body": xml_data["body"][:4000],
                    "header": xml_data["header"][:500],
                    "action_url": xml_data["action_url"][:50000],
                    "source_path": resolved_source,
                    "source_file": resolved_source,
                })
        except sqlite3.DatabaseError as ex:
            self._log(f"WPN SQLite notice on {db_path.name}: {ex}", "DEBUG")
        finally:
            conn.close()

        return records

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for chat collaboration artifacts and wpndatabase.db.
        Ingests parsed_chat_messages and deduplicated parsed_notifications into DuckDB.
        """
        start_time = time.time()
        self._log(f"Starting Chat & Notification parser across staging directory: {self.staging_dir}")

        all_messages: List[Dict[str, Any]] = []
        all_notifications: List[Dict[str, Any]] = []

        candidate_leveldb: List[Path] = []
        candidate_chat_sqlite: List[Path] = []
        candidate_wpn_dbs: List[Path] = []

        if self.staging_dir.exists():
            staging_resolved = self.staging_dir.resolve()
            for p in self.staging_dir.rglob("*"):
                if not p.is_file():
                    continue
                name_lower = p.name.lower()
                try:
                    path_lower = p.resolve().relative_to(staging_resolved).as_posix().lower()
                except Exception:
                    path_lower = p.name.lower()
                suffix_lower = p.suffix.lower()

                if any(name_lower.endswith(sfx) for sfx in ("-wal", "-shm", "-journal")):
                    continue

                if "wpndatabase" in name_lower and (suffix_lower in (".db", "") or "wpndatabase.db" in name_lower):
                    candidate_wpn_dbs.append(p)
                elif suffix_lower in (".ldb", ".log", ".sst") and any(k in path_lower for k in _CHAT_PATH_KEYWORDS):
                    if name_lower not in ("log", "log.old"):
                        candidate_leveldb.append(p)
                elif suffix_lower in (".sqlite", ".sqlite3", ".db") and any(k in path_lower for k in _CHAT_PATH_KEYWORDS):
                    candidate_chat_sqlite.append(p)

        # Sort WPN copies so Notifications/<User>/wpndatabase.db is preferred over flat SQLite/wpndatabase.db
        candidate_wpn_dbs.sort(key=lambda p: (1 if "/sqlite/" in str(p).lower().replace("\\", "/") else 0, str(p)))

        self._log(
            f"Found {len(candidate_leveldb)} LevelDB files, {len(candidate_chat_sqlite)} Chat SQLite DBs, "
            f"and {len(candidate_wpn_dbs)} WPN notification DBs."
        )

        with tempfile.TemporaryDirectory(prefix="wft_chat_") as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            for ldb in candidate_leveldb:
                try:
                    all_messages.extend(self._parse_leveldb_file(ldb))
                except Exception as ex:
                    self._log(f"Error parsing LevelDB {ldb}: {ex}", "WARNING")

            for idx, sqlf in enumerate(candidate_chat_sqlite):
                try:
                    sub_temp = temp_dir / f"chat_{idx}_{uuid.uuid4().hex[:8]}"
                    all_messages.extend(self._parse_chat_sqlite(sqlf, sub_temp))
                except Exception as ex:
                    self._log(f"Error parsing SQLite {sqlf}: {ex}", "WARNING")

            for idx, wpndb in enumerate(candidate_wpn_dbs):
                try:
                    sub_temp = temp_dir / f"wpn_{idx}_{uuid.uuid4().hex[:8]}"
                    all_notifications.extend(self._parse_wpndatabase(wpndb, sub_temp))
                except Exception as ex:
                    self._log(f"Error parsing wpndatabase {wpndb}: {ex}", "WARNING")

        # Deduplicate chat messages
        unique_messages: List[Dict[str, Any]] = []
        seen_msgs: Set[Tuple[str, ...]] = set()
        for msg in all_messages:
            ts_val = msg.get("timestamp_utc")
            ts_key = ts_val.strftime("%Y-%m-%d %H:%M:%S.%f") if isinstance(ts_val, datetime) else str(ts_val or "")
            key = (
                str(msg.get("app_name") or "").strip().lower(),
                str(msg.get("sender") or "").strip().lower(),
                str(msg.get("recipient_channel") or "").strip().lower(),
                " ".join(str(msg.get("message_text") or "").split()),
                ts_key,
            )
            if key not in seen_msgs:
                seen_msgs.add(key)
                unique_messages.append(msg)

        # Deduplicate notifications across duplicate staged copies (excluding source_file from dedup key!)
        unique_notifications: List[Dict[str, Any]] = []
        seen_notifs: Set[Tuple[str, ...]] = set()
        for notif in all_notifications:
            ts_val = notif.get("timestamp_utc")
            ts_key = ts_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts_val, datetime) else str(ts_val or "")
            n_key = (
                str(notif.get("app_id") or "").strip().lower(),
                ts_key,
                " ".join(str(notif.get("title") or "").split()),
                " ".join(str(notif.get("body") or "").split()),
                str(notif.get("action_url") or "").strip(),
            )
            if n_key not in seen_notifs:
                seen_notifs.add(n_key)
                unique_notifications.append(notif)

        per_app_specs = [
            ("Teams", "parsed_teams_messages", "teams_messages", "Microsoft Teams Messages"),
            ("Discord", "parsed_discord_messages", "discord_messages", "Discord Messages"),
            ("Slack", "parsed_slack_messages", "slack_messages", "Slack Messages"),
            ("Skype", "parsed_skype_messages", "skype_messages", "Skype Chat Messages"),
            ("WhatsApp", "parsed_whatsapp_messages", "whatsapp_messages", "WhatsApp Messages"),
            ("Telegram", "parsed_telegram_messages", "telegram_messages", "Telegram Messages"),
        ]

        with DuckDBManager.get_lock(self.case_id):
            msg_count = self.insert_records(
                table_name="parsed_chat_messages",
                records=unique_messages,
                schema_ddl=CHAT_SCHEMA_DDL,
                artifact_id="chat_messages",
                category="CHAT",
                display_name="Chat Messages (Teams / Discord / Slack)",
                source_tool="ChatParser",
            )
            for app_key, tbl_name, art_id, disp_name in per_app_specs:
                app_rows = [m for m in unique_messages if m.get("app_name") == app_key]
                self.insert_records(
                    table_name=tbl_name,
                    records=app_rows,
                    schema_ddl=CHAT_SCHEMA_DDL.replace("parsed_chat_messages", tbl_name),
                    artifact_id=art_id,
                    category="CHAT",
                    display_name=disp_name,
                    source_tool="ChatParser",
                )
            notif_count = self.insert_records(
                table_name="parsed_notifications",
                records=unique_notifications,
                schema_ddl=NOTIFICATIONS_SCHEMA_DDL,
                artifact_id="parsed_notifications",
                category="OPERATING SYSTEM",
                display_name="App Notifications & Toast Alerts",
                source_tool="ChatParser",
            )

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Chat",
            command_executed=(
                f"ChatParser.parse({len(candidate_leveldb)} LevelDB, "
                f"{len(candidate_chat_sqlite)} SQLite, {len(candidate_wpn_dbs)} WPN)"
            ),
            exit_code=0,
            rows_ingested=msg_count + notif_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"ChatParser complete in {duration_ms}ms: {msg_count} messages, {notif_count} notifications."
        )
        return {
            "parsed_chat_messages": msg_count,
            "parsed_notifications": notif_count,
        }
