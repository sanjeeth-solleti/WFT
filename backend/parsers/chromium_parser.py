r"""
Windows Forensic Toolkit (WFT) DFIR Suite - Multi-Profile Thread-Safe Chromium Parser (M3-A / F14.1, F28)
Parses Chrome, Edge, and Brave artifacts across flat, multi-profile, multi-user, and VSS staging trees:
  - History, Visits, Downloads (including downloads_url_chains & legacy schemas), Keyword Search Terms, orphaned URLs
  - Cookies (<Profile>/Cookies and <Profile>/Network/Cookies with v10/v20 AES-GCM & DPAPI detection, zero host win32crypt)
  - Web Data (Autofill + legacy autofill_dates, unit-aware Unix epoch vs WebKit microseconds)
  - Bookmarks JSON (full recursive ' > ' folder hierarchy)
  - Top Sites (top_sites & legacy thumbnails)
  - Login Data (never fabricating blank usernames/origins)
  - Cache (Simple Cache *_0 Stream 0 Pickle/HTTP headers + Blockfile data_*/f_*, falling back ONLY to VFS mtime, NEVER now())
  - Binary SNSS Sessions & Tabs (Current Session, Current Tabs, Last Session, Last Tabs, Sessions/Session_*, Sessions/Tabs_*)
"""
from __future__ import annotations

import email.utils
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import (
    WEBKIT_EPOCH_OFFSET_SECONDS,
    BaseParser,
    copy_sqlite_with_wal,
    safe_sqlite_text_factory,
    webkit_to_datetime,
)

DANGER_TYPE_MAP: Dict[int, str] = {
    0: "NOT_DANGEROUS",
    1: "DANGEROUS_FILE",
    2: "DANGEROUS_URL",
    3: "DANGEROUS_CONTENT",
    4: "MAYBE_DANGEROUS_CONTENT",
    5: "UNCOMMON_CONTENT",
    6: "USER_VALIDATED",
    7: "DANGEROUS_HOST",
    8: "POTENTIALLY_UNWANTED",
    9: "ALLOWLISTED_BY_POLICY",
    10: "ASYNC_SCANNING",
    11: "BLOCKED_PASSWORD_PROTECTED",
    12: "BLOCKED_TOO_LARGE",
    13: "SENSITIVE_CONTENT_WARNING",
    14: "SENSITIVE_CONTENT_BLOCK",
    15: "DEEP_SCANNED_SAFE",
    16: "DEEP_SCANNED_OPENED_DANGEROUS",
    17: "PROMPT_FOR_SCANNING",
}

DOWNLOAD_STATE_MAP: Dict[int, str] = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "CANCELLED",
    3: "INTERRUPTED",
    4: "MAX_DOWNLOAD_STATE",
}

TRANSITION_CORE_MAP: Dict[int, str] = {
    0: "LINK",
    1: "TYPED",
    2: "AUTO_BOOKMARK",
    3: "AUTO_SUBFRAME",
    4: "MANUAL_SUBFRAME",
    5: "GENERATED",
    6: "AUTO_TOPLEVEL",
    7: "FORM_SUBMIT",
    8: "RELOAD",
    9: "KEYWORD",
    10: "KEYWORD_GENERATED",
}

_SIMPLE_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
_SIMPLE_EOF_MAGIC = 0xF4FA6F45970D41D8
_SIMPLE_EOF_MAGIC_BYTES = struct.pack("<Q", _SIMPLE_EOF_MAGIC)

_ARTIFACT_SUBDIRS: Set[str] = {
    "network",
    "sessions",
    "cache",
    "cache_data",
    "code cache",
    "gpucache",
    "media cache",
    "system cache",
    "application cache",
    "service worker",
    "local storage",
    "session storage",
    "indexeddb",
    "leveldb",
    "sync data",
    "extensions",
    "blob_storage",
    "databases",
    "file system",
    "pepper data",
}

_SKIP_PATH_TOKENS: Set[str] = {
    "firefox",
    "mozilla",
    "tor browser",
    "thunderbird",
    "waterfox",
    "palemoon",
    "teams",
    "msteams",
    "discord",
    "slack",
    "onedrive",
    "skype",
    "zoom",
}

_SKIP_FILENAMES: Set[str] = {
    "places.sqlite",
    "cookies.sqlite",
    "formhistory.sqlite",
    "favicons.sqlite",
    "permissions.sqlite",
    "content-prefs.sqlite",
    "protections.sqlite",
    "downloads.sqlite",
    "signons.sqlite",
    "key3.db",
    "key4.db",
    "cert8.db",
    "cert9.db",
    "logins.json",
    "sessionstore.jsonlz4",
    "recovery.jsonlz4",
    "previous.jsonlz4",
    "prefs.js",
    "webcachev01.dat",
    "webcachev24.dat",
    "index.dat",
    "container.dat",
}

_BOOKMARK_ROOT_NAMES: Dict[str, str] = {
    "bookmark_bar": "Bookmarks Bar",
    "other": "Other Bookmarks",
    "synced": "Mobile Bookmarks",
}

_TABLE_DDL_TEMPLATES: Dict[str, str] = {
    "autofill": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, name VARCHAR, value VARCHAR, value_lower VARCHAR, "
        "date_created TIMESTAMP, date_last_used TIMESTAMP, count INTEGER, source_file VARCHAR);"
    ),
    "bookmarks": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, title VARCHAR, url VARCHAR, date_added TIMESTAMP, "
        "date_modified TIMESTAMP, folder VARCHAR, source_file VARCHAR);"
    ),
    "cache": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, url VARCHAR, key VARCHAR, response_time TIMESTAMP, "
        "content_type VARCHAR, size_bytes BIGINT, source_file VARCHAR);"
    ),
    "cookies": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, host_key VARCHAR, name VARCHAR, value VARCHAR, path VARCHAR, "
        "creation_utc TIMESTAMP, expires_utc TIMESTAMP, last_access_utc TIMESTAMP, "
        "is_secure BOOLEAN, is_httponly BOOLEAN, source_file VARCHAR);"
    ),
    "session": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, browser VARCHAR, profile VARCHAR, window_id BIGINT, tab_id BIGINT, "
        "url VARCHAR, title VARCHAR, active BOOLEAN, last_active_time TIMESTAMP, source_file VARCHAR);"
    ),
    "downloads": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, browser VARCHAR, profile VARCHAR, target_path VARCHAR, "
        "tab_url VARCHAR, site_url VARCHAR, total_bytes BIGINT, received_bytes BIGINT, "
        "start_time TIMESTAMP, end_time TIMESTAMP, mime_type VARCHAR, danger_type VARCHAR, "
        "state VARCHAR, opened INTEGER, source_file VARCHAR);"
    ),
    "search_terms": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, term VARCHAR, normalized_term VARCHAR, url VARCHAR, "
        "visit_time TIMESTAMP, source_file VARCHAR);"
    ),
    "logins": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, browser VARCHAR, profile VARCHAR, origin_url VARCHAR, "
        "action_url VARCHAR, username_value VARCHAR, signon_realm VARCHAR, "
        "date_created TIMESTAMP, date_last_used TIMESTAMP, times_used INTEGER, source_file VARCHAR);"
    ),
    "top_sites": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, url VARCHAR, url_rank INTEGER, title VARCHAR, source_file VARCHAR);"
    ),
    "history": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR, "
        "visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, "
        "from_visit BIGINT, transition VARCHAR, source_file VARCHAR);"
    ),
    "visits": (
        "CREATE TABLE IF NOT EXISTS {table_name} ("
        "_row_id BIGINT, url_id BIGINT, visit_time TIMESTAMP, from_visit BIGINT, "
        "transition VARCHAR, visit_duration BIGINT, source_file VARCHAR);"
    ),
}

_VALID_NAV_URI_RE = re.compile(
    r"^(?:https?|ftp|file|chrome|edge|brave|chrome-extension|devtools|view-source|about|data):",
    re.IGNORECASE,
)
_SIMPLE_CACHE_NAME_RE = re.compile(r"^[0-9a-f]{16}_[01s]$", re.IGNORECASE)
_BLOCKFILE_HEX_RE = re.compile(r"^f_[0-9a-f]{6,}$", re.IGNORECASE)
_VSS_PART_RE = re.compile(r"^vss[_\-#]?(\d+)$", re.IGNORECASE)


def _align4(n: int) -> int:
    return (n + 3) & ~3


_UNIX_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_COOKIE_EPOCH_SECONDS = 253402300799.0  # 9999-12-31 23:59:59 UTC
_DIRECT_CHROMIUM_ROOTS: Set[str] = {
    "chrome",
    "google chrome",
    "edge",
    "msedge",
    "microsoft edge",
    "brave",
    "brave-browser",
    "bravesoftware",
    "chromium",
}


def _cookie_webkit_expiry(val: Any) -> Optional[datetime]:
    r"""
    Converts Chromium cookie `expires_utc` (WebKit microseconds since 1601-01-01) to UTC datetime.
    Supports persistent cookies past 2100 up to 9999-12-31 on Windows (pure-Python timedelta, zero CRT OSError)
    while safely returning `None` on `0` or INT64 overflow.
    """
    if val is None or val == "" or isinstance(val, bool):
        return None
    try:
        if isinstance(val, int) or (isinstance(val, str) and val.strip().lstrip("+-").isdigit()):
            iv = int(val)
            if iv <= 0:
                return None
            us = iv - (WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000)
            if us <= 0 or us > 253_402_300_799_999_999:
                return None
            sec_i, rem_us = divmod(us, 1_000_000)
            return _UNIX_EPOCH_UTC + timedelta(seconds=sec_i, microseconds=rem_us)
        fval = float(val)
        if not math.isfinite(fval) or fval <= 0:
            return None
        epoch_seconds = (fval / 1_000_000.0) - WEBKIT_EPOCH_OFFSET_SECONDS
        if epoch_seconds <= 0 or epoch_seconds > _MAX_COOKIE_EPOCH_SECONDS:
            return None
        return _UNIX_EPOCH_UTC + timedelta(seconds=epoch_seconds)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _flex_timestamp(val: Any) -> Optional[datetime]:
    r"""
    Unit-safe timestamp converter for Chromium `autofill` (`Web Data`), where standard Chromium stores
    Unix epoch seconds while custom/modern variants may store WebKit microseconds or Unix ms/µs.
    """
    if val is None or val == "" or isinstance(val, bool):
        return None
    try:
        fval = float(val)
        if not math.isfinite(fval) or fval <= 0:
            return None
        if fval > 11_644_473_600_000_000:
            return webkit_to_datetime(val)
        if 100_000_000_000_000 < fval <= 4_102_444_800_000_000:
            return _UNIX_EPOCH_UTC + timedelta(seconds=fval / 1_000_000.0)
        if 100_000_000_000 < fval <= 4_102_444_800_000:
            return _UNIX_EPOCH_UTC + timedelta(seconds=fval / 1_000.0)
        if 0 < fval <= 4_102_444_800:
            return _UNIX_EPOCH_UTC + timedelta(seconds=fval)
        return None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _parse_http_date_bytes(header_blob: bytes) -> Optional[datetime]:
    norm = header_blob.replace(b"\x00", b"\n")
    for hdr_name in (b"date", b"last-modified"):
        m = re.search(rb"(?im)^" + hdr_name + rb":\s*([^\r\n]+)", norm)
        if m:
            raw_str = m.group(1).decode("latin-1", errors="ignore").strip()
            if not raw_str:
                continue
            try:
                dt = email.utils.parsedate_to_datetime(raw_str)
                if dt is not None:
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    if 1990 <= dt.year <= 2100:
                        return dt
            except Exception:
                continue
    return None


def _extract_content_type_bytes(header_blob: bytes) -> Optional[str]:
    norm = header_blob.replace(b"\x00", b"\n")
    m = re.search(rb"(?im)^content-type:\s*([A-Za-z0-9\-/\+\._]+)", norm)
    if m:
        ct = m.group(1).decode("ascii", errors="ignore").strip()
        if ct:
            return ct
    return None


class ChromiumParser(BaseParser):
    r"""Multi-profile, thread-safe Chromium (Chrome, Edge, Brave) parser (zero Firefox contamination, zero now() fabrication)."""

    def _rel_parts_under_staging(self, file_path: Path) -> Tuple[str, ...]:
        try:
            return file_path.relative_to(self.staging_dir).parts
        except ValueError:
            try:
                return file_path.resolve().relative_to(self.staging_dir.resolve()).parts
            except Exception:
                return file_path.parts

    def _should_skip_path(self, file_path: Path) -> bool:
        fname = file_path.name.lower()
        if fname.endswith(("-wal", "-shm", "-journal")):
            return True
        if fname in _SKIP_FILENAMES:
            return True

        rel_parts = self._rel_parts_under_staging(file_path)
        parts_low = tuple(p.lower() for p in rel_parts)
        if any(p in _SKIP_PATH_TOKENS for p in parts_low):
            return True
        if len(parts_low) >= 2 and parts_low[0] == "browsers" and parts_low[1] in ("ie", "internetexplorer", "webcache", "firefox"):
            return True
        if parts_low and parts_low[0] in ("chat", "cloud", "mail", "email", "notifications"):
            return True
        return False

    def _extract_provenance(self, file_path: Path) -> Tuple[str, str, Tuple[str, str, str, str]]:
        rel_parts = list(self._rel_parts_under_staging(file_path))
        low = [p.lower() for p in rel_parts]

        vss_tag = ""
        if len(low) >= 2 and low[0] == "vss":
            m_v = _VSS_PART_RE.match(rel_parts[1])
            if m_v:
                vss_tag = f"VSS_{m_v.group(1)}"
                rel_parts = rel_parts[2:]
                low = low[2:]
        elif len(low) >= 1:
            m_v = _VSS_PART_RE.match(rel_parts[0])
            if m_v:
                vss_tag = f"VSS_{m_v.group(1)}"
                rel_parts = rel_parts[1:]
                low = low[1:]

        if any(p in ("brave", "brave-browser", "bravesoftware") for p in low):
            browser = "brave"
        elif any(p in ("edge", "msedge") for p in low):
            browser = "edge"
        else:
            browser = "chrome"

        username = ""
        profile = "Default"

        if "browsers" in low:
            b_idx = low.index("browsers")
            if b_idx + 2 < len(rel_parts) - 1:
                username = rel_parts[b_idx + 2]
                rem_dirs = list(rel_parts[b_idx + 3 : -1])
                while rem_dirs and rem_dirs[-1].lower() in _ARTIFACT_SUBDIRS:
                    rem_dirs.pop()
                if rem_dirs and rem_dirs[0].lower() not in _ARTIFACT_SUBDIRS:
                    profile = rem_dirs[0]
                else:
                    profile = "Default"
        elif "user data" in low:
            ud_idx = low.index("user data")
            if ud_idx + 1 < len(rel_parts) - 1:
                cand_prof = rel_parts[ud_idx + 1]
                if cand_prof.lower() not in _ARTIFACT_SUBDIRS:
                    profile = cand_prof
            for u_root in ("users", "userfiles", "documents and settings"):
                if u_root in low:
                    u_idx = low.index(u_root)
                    if u_idx + 1 < ud_idx:
                        username = rel_parts[u_idx + 1]
                        break
        elif (
            len(rel_parts) >= 3
            and low[0] in _DIRECT_CHROMIUM_ROOTS
            and not any(u_r in low for u_r in ("users", "userfiles", "documents and settings"))
        ):
            cand_user = rel_parts[1]
            cand_low = cand_user.lower()
            if cand_low in ("default", "guest profile", "system profile") or cand_low.startswith("profile "):
                profile = cand_user
            elif cand_low not in _ARTIFACT_SUBDIRS:
                username = cand_user
                rem_dirs = list(rel_parts[2:-1])
                while rem_dirs and rem_dirs[-1].lower() in _ARTIFACT_SUBDIRS:
                    rem_dirs.pop()
                if rem_dirs and rem_dirs[0].lower() not in _ARTIFACT_SUBDIRS:
                    profile = rem_dirs[0]
                else:
                    profile = "Default"
        else:
            for part in reversed(rel_parts[:-1]):
                pl = part.lower()
                if pl in ("default", "guest profile", "system profile") or pl.startswith("profile "):
                    profile = part
                    break
            for u_root in ("users", "userfiles", "documents and settings"):
                if u_root in low:
                    u_idx = low.index(u_root)
                    if u_idx + 1 < len(rel_parts) - 1:
                        username = rel_parts[u_idx + 1]
                        break

        profile_display = profile
        if username and username.lower() not in ("unknown", "default", profile.lower()):
            profile_display = f"{username}/{profile}"
        if vss_tag:
            profile_display = f"{profile_display} [{vss_tag}]"

        scope_key = (browser, vss_tag, username.lower(), profile.lower())
        return browser, profile_display, scope_key

    def _safe_original_mtime(self, file_path: Path) -> Optional[datetime]:
        r"""
        Queries `self.get_original_mtime(file_path)` (VFS metadata / preserved os.utime).
        NEVER calls `file_path.stat().st_mtime` directly and NEVER fabricates `datetime.now()`.
        """
        getter = getattr(self, "get_original_mtime", None)
        if not callable(getter):
            return None
        raw_ts = getter(file_path)
        if raw_ts is None:
            return None
        if isinstance(raw_ts, datetime):
            return raw_ts if raw_ts.tzinfo is not None else raw_ts.replace(tzinfo=timezone.utc)
        s = str(raw_ts).strip()
        if not s:
            return None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
        ):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc) if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _is_sqlite(self, path: Path) -> bool:
        try:
            if not path.is_file() or path.stat().st_size < 100:
                return False
            with open(path, "rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except OSError:
            return False

    def _is_simple_cache_magic(self, path: Path) -> bool:
        try:
            if not path.is_file() or path.stat().st_size < 24:
                return False
            with open(path, "rb") as f:
                hdr = f.read(8)
            return len(hdr) == 8 and struct.unpack("<Q", hdr)[0] == _SIMPLE_INITIAL_MAGIC
        except OSError:
            return False

    def _sha256_bundle(self, path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            wal_path = path.parent / f"{path.name}-wal"
            if wal_path.is_file() and wal_path.stat().st_size > 0:
                h.update(b"|WAL|")
                with open(wal_path, "rb") as wf:
                    while True:
                        chunk = wf.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    def _parse_simple_cache_file(
        self, file_path: Path, raw: bytes, scope_key: Tuple[str, str, str, str]
    ) -> Optional[Dict[str, Any]]:
        if len(raw) < 24:
            return None
        magic = struct.unpack_from("<Q", raw, 0)[0]
        if magic != _SIMPLE_INITIAL_MAGIC:
            return None
        _version, key_len, _key_hash = struct.unpack_from("<III", raw, 8)
        if key_len < 1 or key_len > 16384:
            return None

        # 64-bit C++ struct SimpleFileHeader pads bytes 20..24 (zero-initialized), whereas packed headers start key at 20
        if 24 + key_len <= len(raw) and (
            raw[20:24] == b"\x00\x00\x00\x00"
            or not all(32 <= b < 127 for b in raw[20:24])
        ):
            key_offset = 24
        elif 20 + key_len <= len(raw):
            key_offset = 20
        else:
            return None

        key_end = key_offset + key_len
        key_bytes = raw[key_offset:key_end]
        key_str = key_bytes.decode("utf-8", errors="replace").strip("\x00")
        if not key_str:
            return None

        url_matches = re.findall(r"https?://[^\s\x00\"<>]+", key_str)
        url_str = url_matches[-1] if url_matches else key_str

        # Locate Stream 0 HttpResponseInfo before final SimpleFileEOF
        eof_pos = raw.rfind(_SIMPLE_EOF_MAGIC_BYTES)
        if eof_pos != -1 and eof_pos >= key_end and eof_pos + 20 <= len(raw):
            _eof_flags, _eof_crc, stream0_size = struct.unpack_from("<III", raw, eof_pos + 8)
            s0_start = max(key_end, eof_pos - int(stream0_size))
            s0 = raw[s0_start:eof_pos]
        else:
            s0 = raw[key_end:]

        resp_dt: Optional[datetime] = None
        if len(s0) >= 24:
            pickle_len = struct.unpack_from("<I", s0, 0)[0]
            if 16 <= pickle_len <= len(s0) - 4:
                _p_flags, req_ts, resp_ts = struct.unpack_from("<iqq", s0, 4)
                cand_dt = webkit_to_datetime(resp_ts) or webkit_to_datetime(req_ts)
                if cand_dt is not None and 1995 <= cand_dt.year <= 2100:
                    resp_dt = cand_dt

        if resp_dt is None:
            resp_dt = _parse_http_date_bytes(s0) or _parse_http_date_bytes(raw[key_end:])
        if resp_dt is None:
            resp_dt = self._safe_original_mtime(file_path)

        c_type = (
            _extract_content_type_bytes(s0)
            or _extract_content_type_bytes(raw[key_end:])
            or "cached_resource"
        )

        return {
            "url": url_str,
            "key": key_str,
            "response_time": resp_dt,
            "content_type": c_type,
            "size_bytes": len(raw),
            "source_file": str(file_path),
            "_scope_key": list(scope_key),
        }

    def _parse_blockfile_cache(
        self, file_path: Path, raw: bytes, scope_key: Tuple[str, str, str, str]
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if len(raw) < 32:
            return out

        vfs_mtime = self._safe_original_mtime(file_path)
        seen_u: Set[str] = set()
        for m in re.finditer(
            rb"(https?://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{6,512})",
            raw,
        ):
            u_str = m.group(1).decode("utf-8", errors="ignore").rstrip("\x00")
            if not u_str or u_str in seen_u:
                continue
            seen_u.add(u_str)

            win_start = max(0, m.start() - 128)
            win_end = min(len(raw), m.end() + 1024)
            win = raw[win_start:win_end]

            entry_dt = _parse_http_date_bytes(win)
            if entry_dt is None:
                entry_dt = vfs_mtime

            c_type = _extract_content_type_bytes(win) or "cached_resource"
            out.append(
                {
                    "url": u_str,
                    "key": file_path.name,
                    "response_time": entry_dt,
                    "content_type": c_type,
                    "size_bytes": len(raw),
                    "source_file": str(file_path),
                    "_scope_key": list(scope_key),
                }
            )
        return out

    @staticmethod
    def _decode_snss_nav_pickle(
        payload: bytes,
        max_plausible_dt: Optional[datetime] = None,
    ) -> Optional[Tuple[int, int, str, Optional[str], Optional[datetime]]]:
        r"""
        Decodes Chromium `SerializedNavigationEntry` `base::Pickle` inside SNSS `UpdateTabNavigation` commands.
        Probes `(has_pickle_size_hdr, has_tab_id)` layouts and extracts `(tab_id, nav_index, url, title, nav_dt)`.
        """
        plen = len(payload)
        for has_size_hdr, has_tab_id in (
            (True, True),
            (False, True),
            (True, False),
            (False, False),
        ):
            pos = 0
            if has_size_hdr:
                if pos + 4 > plen:
                    continue
                pkl_bytes = struct.unpack_from("<I", payload, pos)[0]
                rem = plen - (pos + 4)
                if pkl_bytes == 0 or not (rem - 4 <= pkl_bytes <= rem):
                    continue
                pos += 4

            tab_id = 0
            if has_tab_id:
                if pos + 4 > plen:
                    continue
                tab_id = struct.unpack_from("<i", payload, pos)[0]
                if tab_id < 0:
                    continue
                pos += 4

            if pos + 8 > plen:
                continue
            nav_index, url_len = struct.unpack_from("<ii", payload, pos)
            pos += 8
            if nav_index < 0 or nav_index > 100000 or url_len <= 0 or url_len > 32768:
                continue
            if pos + url_len > plen:
                continue

            try:
                url_str = payload[pos : pos + url_len].decode("utf-8", errors="strict").strip("\x00")
            except UnicodeDecodeError:
                continue
            if not url_str or not _VALID_NAV_URI_RE.match(url_str):
                continue
            pos += _align4(url_len)

            title_str: Optional[str] = None
            if pos + 4 <= plen:
                title_chars = struct.unpack_from("<i", payload, pos)[0]
                if 0 <= title_chars <= 16384 and pos + 4 + (title_chars * 2) <= plen:
                    pos += 4
                    if title_chars > 0:
                        raw_t = payload[pos : pos + title_chars * 2]
                        title_str = raw_t.decode("utf-16-le", errors="replace").strip("\x00") or None
                    pos += _align4(title_chars * 2)
                else:
                    title_str = None

            # Optional continuation through standard SerializedNavigationEntry Pickle fields for nav_timestamp
            nav_dt: Optional[datetime] = None
            if has_tab_id:
                try:
                    # string page_state
                    if pos + 4 <= plen:
                        ps_len = struct.unpack_from("<i", payload, pos)[0]
                        if 0 <= ps_len <= plen - (pos + 4):
                            pos += 4 + _align4(ps_len)
                            # int32 transition + int32 type_mask (optional depending on Chrome version)
                            if pos + 4 <= plen:
                                pos += 4  # transition
                                # string referrer
                                if pos + 4 <= plen:
                                    ref_len = struct.unpack_from("<i", payload, pos)[0]
                                    if 0 <= ref_len <= 4096 and pos + 4 + _align4(ref_len) <= plen:
                                        pos += 4 + _align4(ref_len)
                except Exception:
                    pass

                # Also check trailing/embedded plausible WebKit timestamps after title if exact struct matches
                for scan_off in range(pos, max(pos, plen - 7), 4):
                    if scan_off + 8 <= plen:
                        cand_wk = struct.unpack_from("<q", payload, scan_off)[0]
                        if 12_500_000_000_000_000 <= cand_wk <= 15_800_000_000_000_000:
                            cand_dt = webkit_to_datetime(cand_wk)
                            if cand_dt is not None and (
                                max_plausible_dt is None or cand_dt <= max_plausible_dt
                            ):
                                nav_dt = cand_dt
                                break

            return (int(tab_id), int(nav_index), url_str, title_str, nav_dt)

        # Fallback regex scan inside valid SNSS command payload
        m_url = re.search(
            rb"((?:https?|ftp|file|chrome|edge|brave)://[^\x00-\x1f\x7f-\xff]{4,2048})",
            payload,
        )
        if m_url:
            u_str = m_url.group(1).decode("utf-8", errors="ignore")
            t_str: Optional[str] = None
            after_pos = _align4(m_url.end())
            if after_pos + 4 <= plen:
                t_chars = struct.unpack_from("<I", payload, after_pos)[0]
                if 0 < t_chars <= 4096 and after_pos + 4 + (t_chars * 2) <= plen:
                    t_str = (
                        payload[after_pos + 4 : after_pos + 4 + t_chars * 2]
                        .decode("utf-16-le", errors="replace")
                        .strip("\x00")
                        or None
                    )
            return (0, 0, u_str, t_str, None)
        return None

    def _parse_snss_file(
        self,
        file_path: Path,
        browser_label: str,
        profile_label: str,
        scope_key: Tuple[str, str, str, str],
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            raw = file_path.read_bytes()
        except OSError:
            return out

        if len(raw) < 8 or raw[:4] != b"SNSS":
            return out
        version = struct.unpack_from("<i", raw, 4)[0]
        if version not in (1, 2, 3, 4):
            return out

        fname = file_path.name.lower()
        is_tabs = "tabs" in fname

        # File-level fallback timestamp: filename WebKit timestamp (`Session_<wk>` / `Tabs_<wk>`), else VFS mtime (NEVER now()!)
        file_fallback_dt: Optional[datetime] = None
        m_fn_ts = re.search(r"(?:session|tabs)_(\d{15,18})", fname, flags=re.IGNORECASE)
        if m_fn_ts:
            file_fallback_dt = webkit_to_datetime(int(m_fn_ts.group(1)))
        if file_fallback_dt is None:
            file_fallback_dt = self._safe_original_mtime(file_path)

        tab_to_win: Dict[int, int] = {}
        selected_nav: Dict[int, int] = {}
        closed_tabs: Set[int] = set()
        tab_time: Dict[int, datetime] = {}
        nav_commands: List[Tuple[int, bytes]] = []

        offset = 8
        total_len = len(raw)
        while offset + 3 <= total_len:
            cmd_size = struct.unpack_from("<H", raw, offset)[0]
            if cmd_size == 0 or offset + 2 + cmd_size > total_len:
                break
            cmd_id = raw[offset + 2]
            payload = raw[offset + 3 : offset + 2 + cmd_size]
            offset += 2 + cmd_size

            if not is_tabs:
                if cmd_id == 0 and len(payload) >= 8:
                    win_id, t_id = struct.unpack_from("<II", payload, 0)
                    tab_to_win[int(t_id)] = int(win_id)
                elif cmd_id == 7 and len(payload) >= 8:
                    t_id, sel_idx = struct.unpack_from("<Ii", payload, 0)
                    selected_nav[int(t_id)] = int(sel_idx)
                elif cmd_id in (16, 21) and len(payload) >= 12:
                    t_id = struct.unpack_from("<I", payload, 0)[0]
                    dt_cmd: Optional[datetime] = None
                    if len(payload) >= 16:
                        wk_aligned = struct.unpack_from("<q", payload, 8)[0]
                        wk_packed = struct.unpack_from("<q", payload, 4)[0]
                        if payload[4:8] == b"\x00\x00\x00\x00":
                            dt_cmd = webkit_to_datetime(wk_aligned) or webkit_to_datetime(wk_packed)
                        else:
                            dt_cmd = webkit_to_datetime(wk_packed) or webkit_to_datetime(wk_aligned)
                    else:
                        wk_packed = struct.unpack_from("<q", payload, 4)[0]
                        dt_cmd = webkit_to_datetime(wk_packed)
                    if cmd_id == 16:
                        closed_tabs.add(int(t_id))
                    if dt_cmd is not None:
                        tab_time[int(t_id)] = dt_cmd
                elif cmd_id in (6, 1):
                    nav_commands.append((cmd_id, payload))
            else:
                if cmd_id == 4 and len(payload) >= 16:
                    t_id, sel_idx, wk_ts = struct.unpack_from("<Iiq", payload, 0)
                    selected_nav[int(t_id)] = int(sel_idx)
                    dt_cmd = webkit_to_datetime(wk_ts)
                    if dt_cmd is not None:
                        tab_time[int(t_id)] = dt_cmd
                elif cmd_id in (1, 6):
                    nav_commands.append((cmd_id, payload))

        # SNSS is an append-only command log: keep the latest UpdateTabNavigation state per (tab_id, nav_index)
        snss_max_dt = (file_fallback_dt + timedelta(days=1)) if file_fallback_dt is not None else None
        latest_by_tab_nav: Dict[Tuple[int, int], Tuple[str, Optional[str], Optional[datetime]]] = {}
        order_keys: List[Tuple[int, int]] = []
        for _cid, payload in nav_commands:
            decoded = self._decode_snss_nav_pickle(payload, max_plausible_dt=snss_max_dt)
            if decoded is None:
                continue
            t_id, n_idx, u_str, title_str, nav_dt = decoded
            key_tn = (t_id, n_idx)
            if key_tn not in latest_by_tab_nav:
                order_keys.append(key_tn)
            latest_by_tab_nav[key_tn] = (u_str, title_str, nav_dt)

        for t_id, n_idx in order_keys:
            u_str, title_str, nav_dt = latest_by_tab_nav[(t_id, n_idx)]
            win_id = int(tab_to_win.get(t_id, 0))
            is_active = bool(
                (not is_tabs)
                and ("last " not in fname)
                and (t_id not in closed_tabs)
                and (selected_nav.get(t_id, n_idx) == n_idx)
            )
            ts_final = nav_dt or tab_time.get(t_id) or file_fallback_dt
            out.append(
                {
                    "browser": browser_label,
                    "profile": profile_label,
                    "window_id": win_id,
                    "tab_id": int(t_id),
                    "url": u_str,
                    "title": title_str,
                    "active": is_active,
                    "last_active_time": ts_final,
                    "source_file": str(file_path),
                    "_scope_key": list(scope_key),
                }
            )

        return out

    def parse(self) -> Dict[str, int]:
        start_time = time.time()
        if not self.staging_dir.exists():
            return {}

        sub_types = (
            "history",
            "visits",
            "downloads",
            "cache",
            "cookies",
            "bookmarks",
            "autofill",
            "search_terms",
            "top_sites",
            "logins",
            "session",
        )
        buckets: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
            b: {st: [] for st in sub_types} for b in ("chrome", "edge", "brave")
        }

        seen_scoped_hashes: Set[Tuple[Tuple[str, str, str, str], str, str]] = set()
        seen_primary_hashes: Set[Tuple[str, str]] = set()
        temp_root = Path(tempfile.mkdtemp(prefix="wft_chromium_"))

        def _file_priority(fp: Path) -> Tuple[int, str]:
            rel_low = [p.lower() for p in self._rel_parts_under_staging(fp)]
            if "browsers" in rel_low:
                prio = 0
            elif "sqlite" in rel_low:
                prio = 2
            else:
                prio = 1
            return (prio, str(fp))

        _SKIP_BROWSER_ROOTS = {
            "registry", "logs", "prefetch", "filesystem", "mft", "srum",
            "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails", "zoneidentifier",
        }
        try:
            all_files: List[Path] = []
            if self.staging_dir.exists():
                staging_res = self.staging_dir.resolve()
                for walk_root, dirs, files in os.walk(staging_res):
                    root_p = Path(walk_root)
                    if root_p == staging_res:
                        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_BROWSER_ROOTS]
                    for fname in files:
                        all_files.append(root_p / fname)
            all_files.sort(key=_file_priority)

            for idx, file_path in enumerate(all_files):
                if self._should_skip_path(file_path):
                    continue

                fname = file_path.name.lower()
                rel_low = [p.lower() for p in self._rel_parts_under_staging(file_path)]
                in_sqlite_dump = len(rel_low) >= 2 and rel_low[0] == "sqlite"

                b_key, profile_label, scope_key = self._extract_provenance(file_path)
                b_label = b_key.capitalize()

                # 1. History, Visits, Orphaned URLs, Downloads (+ downloads_url_chains), Keyword Search Terms
                if (fname == "history" or fname.endswith("_history")) and self._is_sqlite(file_path):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if in_sqlite_dump and ("history", fhash) in seen_primary_hashes:
                            continue
                        if (scope_key, "history", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "history", fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("history", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(file_path, temp_root / f"h_{idx}")
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        try:
                            conn.text_factory = safe_sqlite_text_factory
                            cur = conn.cursor()
                            tables = {
                                r[0]
                                for r in cur.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                ).fetchall()
                            }

                            visited_url_ids: Set[int] = set()
                            if "urls" in tables and "visits" in tables:
                                v_cols = {r[1] for r in cur.execute("PRAGMA table_info(visits)").fetchall()}
                                dur_expr = "v.visit_duration" if "visit_duration" in v_cols else "0"
                                from_expr = "v.from_visit" if "from_visit" in v_cols else "0"
                                trans_expr = "v.transition" if "transition" in v_cols else "0"
                                u_cols = {r[1] for r in cur.execute("PRAGMA table_info(urls)").fetchall()}
                                vc_expr = "u.visit_count" if "visit_count" in u_cols else "1"
                                tc_expr = "u.typed_count" if "typed_count" in u_cols else "0"

                                for u_id, url, title, v_cnt, t_cnt, v_time, from_v, trans, v_dur in cur.execute(
                                    f"SELECT u.id, u.url, u.title, {vc_expr}, {tc_expr}, "
                                    f"v.visit_time, {from_expr}, {trans_expr}, {dur_expr} "
                                    "FROM visits v JOIN urls u ON v.url = u.id "
                                    "WHERE u.url IS NOT NULL AND TRIM(u.url) != ''"
                                ).fetchall():
                                    if u_id is not None:
                                        visited_url_ids.add(int(u_id))
                                    dt = webkit_to_datetime(v_time)
                                    trans_name = TRANSITION_CORE_MAP.get(int(trans or 0) & 0xFF, "LINK")
                                    buckets[b_key]["history"].append(
                                        {
                                            "browser": b_label,
                                            "profile": profile_label,
                                            "url": str(url),
                                            "title": str(title) if title else None,
                                            "visit_count": int(v_cnt) if v_cnt is not None else 0,
                                            "typed_count": int(t_cnt or 0),
                                            "visit_time": dt,
                                            "from_visit": int(from_v or 0),
                                            "transition": trans_name,
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                                    buckets[b_key]["visits"].append(
                                        {
                                            "url_id": int(u_id or 0),
                                            "visit_time": dt,
                                            "from_visit": int(from_v or 0),
                                            "transition": trans_name,
                                            "visit_duration": int(v_dur or 0),
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )

                            # Recover orphaned rows in `urls` whose `visits` rows were pruned/expired
                            if "urls" in tables:
                                u_cols = {r[1] for r in cur.execute("PRAGMA table_info(urls)").fetchall()}
                                vc_expr = "visit_count" if "visit_count" in u_cols else "0"
                                tc_expr = "typed_count" if "typed_count" in u_cols else "0"
                                lvt_expr = "last_visit_time" if "last_visit_time" in u_cols else "NULL"
                                for u_id, url, title, v_cnt, t_cnt, lvt in cur.execute(
                                    f"SELECT id, url, title, {vc_expr}, {tc_expr}, {lvt_expr} "
                                    "FROM urls WHERE url IS NOT NULL AND TRIM(url) != ''"
                                ).fetchall():
                                    if u_id is not None and int(u_id) in visited_url_ids:
                                        continue
                                    buckets[b_key]["history"].append(
                                        {
                                            "browser": b_label,
                                            "profile": profile_label,
                                            "url": str(url),
                                            "title": str(title) if title else None,
                                            "visit_count": int(v_cnt) if v_cnt is not None else 0,
                                            "typed_count": int(t_cnt or 0),
                                            "visit_time": webkit_to_datetime(lvt),
                                            "from_visit": 0,
                                            "transition": "TYPED" if int(t_cnt or 0) > 0 else "LINK",
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )

                            # Downloads + downloads_url_chains + legacy Chrome <26 columns
                            if "downloads" in tables:
                                dl_cols = {r[1] for r in cur.execute("PRAGMA table_info(downloads)").fetchall()}
                                chains: Dict[int, List[str]] = {}
                                if "downloads_url_chains" in tables:
                                    duc_cols = {
                                        r[1]
                                        for r in cur.execute(
                                            "PRAGMA table_info(downloads_url_chains)"
                                        ).fetchall()
                                    }
                                    order_chain = (
                                        "ORDER BY id ASC, chain_index ASC"
                                        if "chain_index" in duc_cols
                                        else "ORDER BY id ASC"
                                    )
                                    for cid, curl in cur.execute(
                                        f"SELECT id, url FROM downloads_url_chains WHERE url IS NOT NULL {order_chain}"
                                    ).fetchall():
                                        if cid is not None and curl:
                                            chains.setdefault(int(cid), []).append(str(curl))

                                id_c = "id" if "id" in dl_cols else "NULL"
                                tp_c = (
                                    "target_path"
                                    if "target_path" in dl_cols
                                    else ("full_path" if "full_path" in dl_cols else "NULL")
                                )
                                cp_c = "current_path" if "current_path" in dl_cols else "NULL"
                                tab_c = "tab_url" if "tab_url" in dl_cols else "NULL"
                                site_c = (
                                    "site_url"
                                    if "site_url" in dl_cols
                                    else (
                                        "referrer"
                                        if "referrer" in dl_cols
                                        else ("tab_referrer_url" if "tab_referrer_url" in dl_cols else "NULL")
                                    )
                                )
                                leg_url_c = "url" if "url" in dl_cols else "NULL"
                                tot_c = "total_bytes" if "total_bytes" in dl_cols else "0"
                                rec_c = "received_bytes" if "received_bytes" in dl_cols else "0"
                                st_c = "start_time" if "start_time" in dl_cols else "NULL"
                                et_c = "end_time" if "end_time" in dl_cols else "NULL"
                                mime_c = (
                                    "mime_type"
                                    if "mime_type" in dl_cols
                                    else ("original_mime_type" if "original_mime_type" in dl_cols else "NULL")
                                )
                                danger_c = "danger_type" if "danger_type" in dl_cols else "NULL"
                                state_c = "state" if "state" in dl_cols else "NULL"
                                opened_c = "opened" if "opened" in dl_cols else "NULL"

                                for (
                                    dl_id,
                                    t_p,
                                    c_p,
                                    tab_u,
                                    site_u,
                                    leg_u,
                                    tot_b,
                                    rec_b,
                                    s_t,
                                    e_t,
                                    mime,
                                    d_type,
                                    st_val,
                                    op_val,
                                ) in cur.execute(
                                    f"SELECT {id_c}, {tp_c}, {cp_c}, {tab_c}, {site_c}, {leg_url_c}, "
                                    f"{tot_c}, {rec_c}, {st_c}, {et_c}, {mime_c}, {danger_c}, {state_c}, {opened_c} "
                                    "FROM downloads"
                                ).fetchall():
                                    final_p = str(t_p or c_p or "").strip()
                                    chain_urls = chains.get(int(dl_id), []) if dl_id is not None else []
                                    resolved_tab = (
                                        (str(tab_u).strip() if tab_u else "")
                                        or (chain_urls[-1] if chain_urls else "")
                                        or (str(leg_u).strip() if leg_u else "")
                                        or (str(site_u).strip() if site_u else "")
                                        or None
                                    )
                                    resolved_site = (
                                        (str(site_u).strip() if site_u else "")
                                        or (chain_urls[0] if len(chain_urls) > 1 else "")
                                        or (str(tab_u).strip() if tab_u else "")
                                        or None
                                    )
                                    if not final_p and not resolved_tab:
                                        continue

                                    danger_str = (
                                        DANGER_TYPE_MAP.get(int(d_type), str(d_type))
                                        if d_type is not None
                                        else None
                                    )
                                    state_str = (
                                        DOWNLOAD_STATE_MAP.get(int(st_val), str(st_val))
                                        if st_val is not None
                                        else None
                                    )
                                    s_dt = webkit_to_datetime(s_t) or _flex_timestamp(s_t)
                                    e_dt = webkit_to_datetime(e_t) or _flex_timestamp(e_t)

                                    buckets[b_key]["downloads"].append(
                                        {
                                            "browser": b_label,
                                            "profile": profile_label,
                                            "target_path": final_p or None,
                                            "tab_url": resolved_tab,
                                            "site_url": resolved_site,
                                            "total_bytes": int(tot_b or 0),
                                            "received_bytes": int(rec_b or 0),
                                            "start_time": s_dt,
                                            "end_time": e_dt,
                                            "mime_type": str(mime) if mime else None,
                                            "danger_type": danger_str,
                                            "state": state_str,
                                            "opened": int(op_val) if op_val is not None else None,
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )

                            if "keyword_search_terms" in tables:
                                kst_cols = {
                                    r[1]
                                    for r in cur.execute(
                                        "PRAGMA table_info(keyword_search_terms)"
                                    ).fetchall()
                                }
                                norm_expr = (
                                    "k.normalized_term"
                                    if "normalized_term" in kst_cols
                                    else ("k.lower_term" if "lower_term" in kst_cols else "LOWER(k.term)")
                                )
                                if "urls" in tables:
                                    kst_sql = (
                                        f"SELECT k.term, {norm_expr}, u.url, u.last_visit_time "
                                        "FROM keyword_search_terms k LEFT JOIN urls u ON k.url_id = u.id "
                                        "WHERE k.term IS NOT NULL"
                                    )
                                else:
                                    kst_sql = (
                                        f"SELECT k.term, {norm_expr}, NULL, NULL "
                                        "FROM keyword_search_terms k WHERE k.term IS NOT NULL"
                                    )
                                for term, norm_t, url, lvt in cur.execute(kst_sql).fetchall():
                                    buckets[b_key]["search_terms"].append(
                                        {
                                            "term": str(term),
                                            "normalized_term": str(norm_t or term),
                                            "url": str(url) if url else None,
                                            "visit_time": webkit_to_datetime(lvt),
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                        finally:
                            conn.close()
                    except Exception as ex:
                        self._log(f"SQLite History parse error on {file_path}: {ex}", "WARNING")

                # 2. Cookies (<Profile>/Cookies and <Profile>/Network/Cookies)
                elif (fname == "cookies" or fname.endswith("_cookies")) and self._is_sqlite(file_path):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if in_sqlite_dump and ("cookies", fhash) in seen_primary_hashes:
                            continue
                        if (scope_key, "cookies", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "cookies", fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("cookies", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(file_path, temp_root / f"c_{idx}")
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        try:
                            conn.text_factory = safe_sqlite_text_factory
                            cur = conn.cursor()
                            tables = {
                                r[0]
                                for r in cur.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                ).fetchall()
                            }
                            if "cookies" in tables:
                                c_cols = {r[1] for r in cur.execute("PRAGMA table_info(cookies)").fetchall()}
                                sec_col = (
                                    "is_secure"
                                    if "is_secure" in c_cols
                                    else ("secure" if "secure" in c_cols else "0")
                                )
                                http_col = (
                                    "is_httponly"
                                    if "is_httponly" in c_cols
                                    else ("httponly" if "httponly" in c_cols else "0")
                                )
                                val_col = "value" if "value" in c_cols else "''"
                                enc_col = "encrypted_value" if "encrypted_value" in c_cols else "NULL"
                                lu_col = "last_update_utc" if "last_update_utc" in c_cols else "NULL"

                                for host, name, val, enc_v, path, c_t, exp_t, la_t, lu_t, sec, http in cur.execute(
                                    f"SELECT host_key, name, {val_col}, {enc_col}, path, "
                                    f"creation_utc, expires_utc, last_access_utc, {lu_col}, {sec_col}, {http_col} "
                                    "FROM cookies"
                                ).fetchall():
                                    if val is not None and str(val) != "":
                                        cookie_val = str(val)
                                    elif enc_v is not None and len(bytes(enc_v)) > 0:
                                        eb = bytes(enc_v)
                                        if eb.startswith(b"v20"):
                                            cookie_val = "[AES-GCM Encrypted (v20)]"
                                        elif eb.startswith((b"v10", b"v11")):
                                            cookie_val = "[AES-GCM Encrypted (v10)]"
                                        else:
                                            cookie_val = "[DPAPI Encrypted]"
                                    else:
                                        cookie_val = ""

                                    c_dt = webkit_to_datetime(c_t)
                                    exp_dt = _cookie_webkit_expiry(exp_t)
                                    la_dt = webkit_to_datetime(la_t) or webkit_to_datetime(lu_t)

                                    buckets[b_key]["cookies"].append(
                                        {
                                            "host_key": str(host) if host is not None else None,
                                            "name": str(name) if name is not None else None,
                                            "value": cookie_val,
                                            "path": str(path or "/"),
                                            "creation_utc": c_dt,
                                            "expires_utc": exp_dt,
                                            "last_access_utc": la_dt,
                                            "is_secure": bool(sec),
                                            "is_httponly": bool(http),
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                        finally:
                            conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Cookies parse error on {file_path}: {ex}", "WARNING")

                # 3. Web Data (Autofill + legacy autofill_dates)
                elif (fname == "web data" or fname.endswith("_web data")) and self._is_sqlite(file_path):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if in_sqlite_dump and ("web_data", fhash) in seen_primary_hashes:
                            continue
                        if (scope_key, "web_data", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "web_data", fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("web_data", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(file_path, temp_root / f"w_{idx}")
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        try:
                            conn.text_factory = safe_sqlite_text_factory
                            cur = conn.cursor()
                            tables = {
                                r[0]
                                for r in cur.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                ).fetchall()
                            }
                            if "autofill" in tables:
                                af_cols = {r[1] for r in cur.execute("PRAGMA table_info(autofill)").fetchall()}
                                cnt_col = "autofill.count" if "count" in af_cols else "1"
                                if "date_created" in af_cols:
                                    du_col = "date_last_used" if "date_last_used" in af_cols else "NULL"
                                    af_sql = (
                                        f"SELECT name, value, date_created, {du_col}, {cnt_col} "
                                        "FROM autofill WHERE value IS NOT NULL"
                                    )
                                elif "autofill_dates" in tables and "pair_id" in af_cols:
                                    af_sql = (
                                        f"SELECT autofill.name, autofill.value, ad.dc, ad.du, {cnt_col} "
                                        "FROM autofill LEFT JOIN ("
                                        "  SELECT pair_id, MIN(date_created) AS dc, MAX(date_created) AS du "
                                        "  FROM autofill_dates GROUP BY pair_id"
                                        ") ad ON autofill.pair_id = ad.pair_id "
                                        "WHERE autofill.value IS NOT NULL"
                                    )
                                else:
                                    af_sql = (
                                        f"SELECT name, value, NULL, NULL, {cnt_col} "
                                        "FROM autofill WHERE value IS NOT NULL"
                                    )

                                for name, val, d_c, d_u, cnt in cur.execute(af_sql).fetchall():
                                    buckets[b_key]["autofill"].append(
                                        {
                                            "name": str(name or "Field"),
                                            "value": str(val),
                                            "value_lower": str(val).lower(),
                                            "date_created": _flex_timestamp(d_c),
                                            "date_last_used": _flex_timestamp(d_u),
                                            "count": int(cnt or 1),
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                        finally:
                            conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Web Data parse error on {file_path}: {ex}", "WARNING")

                # 4. Top Sites
                elif (fname == "top sites" or fname.endswith("_top sites")) and self._is_sqlite(file_path):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if in_sqlite_dump and ("top_sites", fhash) in seen_primary_hashes:
                            continue
                        if (scope_key, "top_sites", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "top_sites", fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("top_sites", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(file_path, temp_root / f"ts_{idx}")
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        try:
                            conn.text_factory = safe_sqlite_text_factory
                            cur = conn.cursor()
                            tables = {
                                r[0]
                                for r in cur.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                ).fetchall()
                            }
                            ts_tbl = (
                                "top_sites"
                                if "top_sites" in tables
                                else ("thumbnails" if "thumbnails" in tables else None)
                            )
                            if ts_tbl:
                                ts_cols = {
                                    r[1]
                                    for r in cur.execute(f"PRAGMA table_info({ts_tbl})").fetchall()
                                }
                                rk_col = "url_rank" if "url_rank" in ts_cols else "0"
                                tt_col = "title" if "title" in ts_cols else "NULL"
                                for url, rank, title in cur.execute(
                                    f"SELECT url, {rk_col}, {tt_col} FROM {ts_tbl} WHERE url IS NOT NULL"
                                ).fetchall():
                                    buckets[b_key]["top_sites"].append(
                                        {
                                            "url": str(url),
                                            "url_rank": int(rank or 0),
                                            "title": str(title) if title else None,
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                        finally:
                            conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Top Sites parse error on {file_path}: {ex}", "WARNING")

                # 5. Login Data (never fabricate blank usernames or origins)
                elif (
                    fname in ("login data", "login data for account")
                    or fname.endswith("_login data")
                ) and self._is_sqlite(file_path):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if in_sqlite_dump and ("login_data", fhash) in seen_primary_hashes:
                            continue
                        if (scope_key, "login_data", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "login_data", fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("login_data", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(file_path, temp_root / f"l_{idx}")
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        try:
                            conn.text_factory = safe_sqlite_text_factory
                            cur = conn.cursor()
                            tables = {
                                r[0]
                                for r in cur.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table'"
                                ).fetchall()
                            }
                            if "logins" in tables:
                                l_cols = {r[1] for r in cur.execute("PRAGMA table_info(logins)").fetchall()}
                                act_col = "action_url" if "action_url" in l_cols else "NULL"
                                uname_col = "username_value" if "username_value" in l_cols else "NULL"
                                realm_col = "signon_realm" if "signon_realm" in l_cols else "NULL"
                                dc_col = "date_created" if "date_created" in l_cols else "NULL"
                                du_col = "date_last_used" if "date_last_used" in l_cols else "NULL"
                                tu_col = "times_used" if "times_used" in l_cols else "0"

                                for orig, act, uname, realm, d_c, d_u, t_u in cur.execute(
                                    f"SELECT origin_url, {act_col}, {uname_col}, {realm_col}, "
                                    f"{dc_col}, {du_col}, {tu_col} FROM logins"
                                ).fetchall():
                                    orig_s = str(orig).strip() if orig is not None else ""
                                    realm_s = str(realm).strip() if realm is not None else ""
                                    if not orig_s and not realm_s:
                                        continue
                                    clean_uname = (
                                        str(uname) if (uname is not None and str(uname) != "") else None
                                    )
                                    buckets[b_key]["logins"].append(
                                        {
                                            "browser": b_label,
                                            "profile": profile_label,
                                            "origin_url": orig_s or realm_s,
                                            "action_url": str(act) if act else None,
                                            "username_value": clean_uname,
                                            "signon_realm": realm_s or orig_s,
                                            "date_created": webkit_to_datetime(d_c),
                                            "date_last_used": webkit_to_datetime(d_u),
                                            "times_used": int(t_u or 0),
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                        finally:
                            conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Login Data parse error on {file_path}: {ex}", "WARNING")

                # 6. Bookmarks JSON (full recursive ' > ' folder path)
                elif fname == "bookmarks" or fname.endswith("_bookmarks"):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if (scope_key, "bookmarks", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "bookmarks", fhash))

                    try:
                        bm_data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
                        roots = bm_data.get("roots", {})
                        if isinstance(roots, dict):

                            def _walk_bm(node: Any, folder_path: str) -> None:
                                if not isinstance(node, dict):
                                    return
                                ntype = node.get("type")
                                if ntype == "url" and node.get("url"):
                                    buckets[b_key]["bookmarks"].append(
                                        {
                                            "title": str(node.get("name") or "Untitled"),
                                            "url": str(node.get("url")),
                                            "date_added": webkit_to_datetime(node.get("date_added")),
                                            "date_modified": webkit_to_datetime(
                                                node.get("date_modified")
                                                or node.get("date_last_used")
                                            ),
                                            "folder": folder_path,
                                            "source_file": str(file_path),
                                            "_scope_key": list(scope_key),
                                        }
                                    )
                                children = node.get("children")
                                if isinstance(children, list):
                                    for ch in children:
                                        if not isinstance(ch, dict):
                                            continue
                                        if ch.get("type") == "folder":
                                            ch_name = str(ch.get("name") or "Folder")
                                            next_folder = (
                                                f"{folder_path} > {ch_name}"
                                                if folder_path
                                                else ch_name
                                            )
                                            _walk_bm(ch, next_folder)
                                        else:
                                            _walk_bm(ch, folder_path)

                            for rk, rv in roots.items():
                                if not isinstance(rv, dict):
                                    continue
                                root_label = _BOOKMARK_ROOT_NAMES.get(
                                    rk, str(rv.get("name") or rk)
                                )
                                _walk_bm(rv, root_label)
                    except Exception as ex:
                        self._log(f"Bookmarks JSON parse notice on {file_path.name}: {ex}", "WARNING")

                # 7. Binary SNSS Sessions & Tabs
                elif fname in (
                    "current session",
                    "current tabs",
                    "last session",
                    "last tabs",
                ) or fname.startswith(("session_", "tabs_")):
                    fhash = self._sha256_bundle(file_path)
                    if fhash:
                        if (scope_key, "session", fhash) in seen_scoped_hashes:
                            continue
                        seen_scoped_hashes.add((scope_key, "session", fhash))
                    sess_rows = self._parse_snss_file(
                        file_path, b_label, profile_label, scope_key
                    )
                    if sess_rows:
                        buckets[b_key]["session"].extend(sess_rows)

                # 8. Simple Cache (*_0) & Blockfile Cache (data_0..3, f_*)
                elif (
                    _SIMPLE_CACHE_NAME_RE.match(fname)
                    or _BLOCKFILE_HEX_RE.match(fname)
                    or fname in ("data_0", "data_1", "data_2", "data_3")
                    or (
                        any(p in ("cache", "cache_data") for p in rel_low)
                        and self._is_simple_cache_magic(file_path)
                    )
                ):
                    try:
                        raw = file_path.read_bytes()
                        if len(raw) >= 24 and struct.unpack_from("<Q", raw, 0)[0] == _SIMPLE_INITIAL_MAGIC:
                            sc_rec = self._parse_simple_cache_file(file_path, raw, scope_key)
                            if sc_rec is not None:
                                buckets[b_key]["cache"].append(sc_rec)
                        elif _BLOCKFILE_HEX_RE.match(fname) or fname in (
                            "data_0",
                            "data_1",
                            "data_2",
                            "data_3",
                        ):
                            bf_recs = self._parse_blockfile_cache(file_path, raw, scope_key)
                            if bf_recs:
                                buckets[b_key]["cache"].extend(bf_recs)
                    except Exception as ex:
                        self._log(f"Cache parse notice on {file_path.name}: {ex}", "WARNING")
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

        # All 33 Chromium tables (ZERO Firefox tables!)
        display_labels = {
            "history": "History",
            "visits": "Web Visits",
            "downloads": "Downloads",
            "cache": "Cache Records",
            "cookies": "Cookies",
            "bookmarks": "Bookmarks",
            "autofill": "Autofill",
            "search_terms": "Keyword Search Terms",
            "top_sites": "Top Sites",
            "logins": "Logins",
            "session": "Current Session & Tabs",
        }

        mapping_specs: List[Tuple[str, str, str, str, str, str]] = []
        for b_key in ("chrome", "edge", "brave"):
            b_disp = b_key.capitalize()
            for sub_key in sub_types:
                tbl_name = f"parsed_{b_key}_{sub_key}"
                art_id = f"{b_key}_{sub_key}"
                disp_name = (
                    "Edge Cache Data"
                    if (b_key == "edge" and sub_key == "cache")
                    else f"{b_disp} {display_labels[sub_key]}"
                )
                ddl = _TABLE_DDL_TEMPLATES[sub_key].format(table_name=tbl_name)
                mapping_specs.append((b_key, sub_key, tbl_name, art_id, disp_name, ddl))

        results: Dict[str, int] = {}
        with DuckDBManager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            existing_tables = {
                str(r[0])
                for r in conn.cursor()
                .execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                )
                .fetchall()
            }

            for b_key, sub_key, tbl_name, art_id, disp_name, ddl in mapping_specs:
                recs = buckets[b_key][sub_key]
                if recs:
                    if sub_key == "session" and tbl_name in existing_tables:
                        scur = conn.cursor()
                        scur.execute(
                            f'ALTER TABLE "{tbl_name}" ADD COLUMN IF NOT EXISTS "browser" VARCHAR;'
                        )
                        scur.execute(
                            f'ALTER TABLE "{tbl_name}" ADD COLUMN IF NOT EXISTS "profile" VARCHAR;'
                        )
                    deduped: List[Dict[str, Any]] = []
                    seen_r: Set[str] = set()
                    for r in recs:
                        k_str = json.dumps(
                            {k: str(v) for k, v in r.items() if k != "source_file"},
                            sort_keys=True,
                        )
                        if k_str not in seen_r:
                            seen_r.add(k_str)
                            clean_r = {k: v for k, v in r.items() if k != "_scope_key"}
                            deduped.append(clean_r)
                    cnt = self.insert_records(
                        table_name=tbl_name,
                        records=deduped,
                        schema_ddl=ddl,
                        artifact_id=art_id,
                        category="WEB RELATED",
                        display_name=disp_name,
                        source_tool="ChromiumParser",
                        append=False,
                    )
                    results[tbl_name] = cnt
                elif tbl_name in existing_tables:
                    # Ensure stale rows from a prior run on the same case are truncated cleanly
                    cur_cnt_row = conn.cursor().execute(f'SELECT COUNT(*) FROM "{tbl_name}";').fetchone()
                    if cur_cnt_row and int(cur_cnt_row[0] or 0) > 0:
                        self.insert_records(
                            table_name=tbl_name,
                            records=[],
                            schema_ddl=ddl,
                            artifact_id=art_id,
                            category="WEB RELATED",
                            display_name=disp_name,
                            source_tool="ChromiumParser",
                            append=False,
                        )

        dur = int((time.time() - start_time) * 1000)
        self._log(
            f"ChromiumParser completed in {dur}ms: {sum(results.values())} rows across {len(results)} tables."
        )
        return results
