r"""
Windows Forensic Toolkit (WFT) DFIR Suite - Base Forensic Parser
Provides standardized, thread-safe base functionality for forensic parsers:
- Serialized DuckDB DDL, queries, DataFrame & pure-Python batch inserts
- Clean optional dependency guarding (pandas optional)
- Safe SQLite file copying with WAL / SHM replay
- Standard DFIR timestamp conversions (WebKit, PRTime, Windows FILETIME)
- Deterministic VFS / staging / parent-aware $MFT evidence path resolution
- Original VFS timestamp resolution (never fabricating host wall-clock now())
- Artifact registration into artifact_registry and audit logging into processing_logs
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import traceback
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import duckdb

try:
    import pandas as pd
except ImportError:  # pragma: no cover - pure-Python fallback path exercised when pandas is absent
    pd = None  # type: ignore[assignment]

from backend.config import get_case_dir, get_case_log_file, get_case_staging_dir
from backend.db.engine import DuckDBManager, log_processing_event


# WebKit microseconds offset between Windows Epoch (1601-01-01) and Unix Epoch (1970-01-01)
WEBKIT_EPOCH_OFFSET_SECONDS = 11644473600

# Module-level lock protecting concurrent appends to case processing.log
_LOG_FILE_LOCK = threading.Lock()

# Generic artifact filenames that appear across many unrelated directories/profiles on Windows.
# Bare filename-only matching against raw_mft WITHOUT parent-directory context is strictly forbidden for these.
GENERIC_FORENSIC_FILENAMES: Set[str] = {
    "history",
    "cookies",
    "bookmarks",
    "bookmarks.bak",
    "web data",
    "login data",
    "login data for account",
    "top sites",
    "shortcuts",
    "favicons",
    "visited links",
    "network action predictor",
    "preferences",
    "secure preferences",
    "local state",
    "current session",
    "current tabs",
    "last session",
    "last tabs",
    "session",
    "tabs",
    "quota",
    "heavyadinterventionoptout.db",
    "places.sqlite",
    "cookies.sqlite",
    "formhistory.sqlite",
    "favicons.sqlite",
    "permissions.sqlite",
    "content-prefs.sqlite",
    "protections.sqlite",
    "storage.sqlite",
    "signons.sqlite",
    "downloads.sqlite",
    "logins.json",
    "key3.db",
    "key4.db",
    "cert8.db",
    "cert9.db",
    "sessionstore.jsonlz4",
    "recovery.jsonlz4",
    "previous.jsonlz4",
    "prefs.js",
    "index.dat",
    "container.dat",
    "webcachev01.dat",
    "webcachev24.dat",
    "web.config",
    "app.config",
    "machine.config",
    "desktop.ini",
    "thumbs.db",
    "iconcache.db",
    "ntuser.dat",
    "usrclass.dat",
    "sam",
    "system",
    "software",
    "security",
    "default",
    "bcd",
    "components",
    "amcache.hve",
    "syscache.hve",
    "settings.dat",
    "roaming.lock",
    "info.json",
    "manifest.json",
    "package.json",
    "config.json",
    "state.json",
    "nucleus.sqlite3",
    "filecache.dbx",
    "aggregation.dbx",
    "deleted.dbx",
    "config.dbx",
    "metadata_sqlite_db",
    "snapshot.db",
    "mirror_sqlite.db",
    "sync_log.log",
    "syncdiagnostics.log",
    "syncenginedatabase.db",
    "safedelete.db",
    "wpndatabase.db",
    "activitiescache.db",
    "srudb.dat",
    "objects.data",
    "$i30",
    "$mft",
    "$logfile",
    "$usnjrnl",
    "current",
    "lock",
    "log",
    "log.old",
    "data_0",
    "data_1",
    "data_2",
    "data_3",
}

_FLAT_STAGING_BUCKETS: Set[str] = {
    "sqlite",
    "enrichment",
    "documents",
    "media",
    "carved",
    "temp",
    "tmp",
    "raw",
    "browsers",
    "mail",
    "chat",
    "cloud",
}

_ISO_OFFSET_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(Z|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)
_PARTITION_LABEL_RE = re.compile(
    r"^(?:part(?:ition)?[_\-]?\d+|vol(?:ume)?[_\-]?\d+|p\d+|[a-zA-Z]_drive|[a-zA-Z])$",
    re.IGNORECASE,
)
_VSS_SEGMENT_RE = re.compile(r"^vss[_\-#]?(\d+)$", re.IGNORECASE)
_CACHE_DATA_FILE_RE = re.compile(r"^(?:f_[0-9a-f]{6,}|[0-9a-f]{16}_[0-9s]+|data_\d+)$", re.IGNORECASE)
_VALID_SQL_IDENT_RE = re.compile(r"^[A-Za-z0-9_]+$")


_UNIX_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_EPOCH_SECONDS = 253402300799.0  # 9999-12-31 23:59:59 UTC


def _epoch_sec_to_utc(epoch_seconds: float, max_sec: float = _MAX_EPOCH_SECONDS) -> Optional[datetime]:
    if not math.isfinite(epoch_seconds) or epoch_seconds <= 0.0 or epoch_seconds > max_sec:
        return None
    try:
        return _UNIX_EPOCH_UTC + timedelta(seconds=epoch_seconds)
    except (OverflowError, ValueError, OSError):
        return None


def webkit_to_datetime(webkit_microseconds: Union[int, float, str, None]) -> Optional[datetime]:
    r"""
    Convert WebKit timestamp (microseconds since Jan 1, 1601 UTC) to UTC datetime.
    Used by Chromium browsers (Chrome, Edge, Brave, Opera).
    Uses pure-Python epoch + timedelta arithmetic (immune to Windows CRT year-3001 OSError).
    """
    if webkit_microseconds is None or webkit_microseconds == "" or isinstance(webkit_microseconds, bool):
        return None
    try:
        if isinstance(webkit_microseconds, int) or (
            isinstance(webkit_microseconds, str) and webkit_microseconds.strip().lstrip("+-").isdigit()
        ):
            iv = int(webkit_microseconds)
            if iv <= 0:
                return None
            us = iv - (WEBKIT_EPOCH_OFFSET_SECONDS * 1_000_000)
            if us <= 0 or us > 253_402_300_799_999_999:
                return None
            sec_i, rem_us = divmod(us, 1_000_000)
            return _UNIX_EPOCH_UTC + timedelta(seconds=sec_i, microseconds=rem_us)
        val = float(webkit_microseconds)
        if not math.isfinite(val) or val <= 0:
            return None
        epoch_seconds = (val / 1_000_000.0) - WEBKIT_EPOCH_OFFSET_SECONDS
        return _epoch_sec_to_utc(epoch_seconds, _MAX_EPOCH_SECONDS)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def prtime_to_datetime(prtime_microseconds: Union[int, float, str, None]) -> Optional[datetime]:
    r"""
    Convert Firefox PRTime timestamp (microseconds, milliseconds, or seconds since Jan 1, 1970 UTC) to UTC datetime.
    Uses pure-Python epoch + timedelta arithmetic (immune to Windows CRT year-3001 OSError)
    with exact integer `divmod` precision on 64-bit microsecond integers (zero `float64` ULP drift).
    """
    if prtime_microseconds is None or prtime_microseconds == "" or isinstance(prtime_microseconds, bool):
        return None
    try:
        if isinstance(prtime_microseconds, int) or (
            isinstance(prtime_microseconds, str) and prtime_microseconds.strip().lstrip("+-").isdigit()
        ):
            iv = int(prtime_microseconds)
            if iv <= 0:
                return None
            if iv > 253_402_300_799_999:
                if iv > 253_402_300_799_999_999:
                    return None
                sec_i, rem_us = divmod(iv, 1_000_000)
                return _UNIX_EPOCH_UTC + timedelta(seconds=sec_i, microseconds=rem_us)
            if iv > 253_402_300_799:
                sec_i, rem_ms = divmod(iv, 1_000)
                return _UNIX_EPOCH_UTC + timedelta(seconds=sec_i, milliseconds=rem_ms)
            return _UNIX_EPOCH_UTC + timedelta(seconds=iv)
        val = float(prtime_microseconds)
        if not math.isfinite(val) or val <= 0:
            return None
        if val > 253_402_300_799_999.0:
            epoch_seconds = val / 1_000_000.0
        elif val > 253_402_300_799.0:
            epoch_seconds = val / 1_000.0
        else:
            epoch_seconds = val
        return _epoch_sec_to_utc(epoch_seconds, _MAX_EPOCH_SECONDS)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def windows_filetime_to_datetime(filetime: Union[int, float, str, None]) -> Optional[datetime]:
    r"""
    Convert Windows 64-bit FILETIME (100-nanosecond intervals since Jan 1, 1601 UTC) to UTC datetime.
    Uses pure-Python epoch + timedelta arithmetic (immune to Windows CRT year-3001 OSError).
    """
    if filetime is None or filetime == "" or isinstance(filetime, bool):
        return None
    try:
        if isinstance(filetime, int) or (
            isinstance(filetime, str) and filetime.strip().lstrip("+-").isdigit()
        ):
            iv = int(filetime)
            if iv <= 0:
                return None
            ticks = iv - (WEBKIT_EPOCH_OFFSET_SECONDS * 10_000_000)
            if ticks <= 0 or ticks > 2_534_023_007_999_999_999:
                return None
            us = ticks // 10
            sec_i, rem_us = divmod(us, 1_000_000)
            return _UNIX_EPOCH_UTC + timedelta(seconds=sec_i, microseconds=rem_us)
        val = float(filetime)
        if not math.isfinite(val) or val <= 0:
            return None
        epoch_seconds = (val / 10_000_000.0) - WEBKIT_EPOCH_OFFSET_SECONDS
        return _epoch_sec_to_utc(epoch_seconds, _MAX_EPOCH_SECONDS)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


# Alias for compatibility
filetime_to_datetime = windows_filetime_to_datetime


def copy_sqlite_with_wal(db_path: Union[str, Path], temp_dir: Optional[Union[str, Path]] = None) -> Path:
    r"""
    Copies a SQLite database along with its associated write-ahead logs (-wal, -shm)
    or rollback journals (-journal) to an isolated temporary directory.
    Thread-safe (zero TOCTOU): whenever `temp_dir` is provided, unconditionally allocates
    an atomic per-call subdirectory inside `temp_dir` via `tempfile.mkdtemp` so concurrent
    threads copying same-named SQLite+WAL files never collide or overwrite companions.
    """
    src_path = Path(db_path).resolve()
    if temp_dir is None:
        dest_dir = Path(tempfile.mkdtemp(prefix="wft_sqlite_"))
    else:
        target_dir = Path(temp_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_dir = Path(
            tempfile.mkdtemp(prefix=f"wft_{threading.get_ident()}_", dir=str(target_dir))
        )

    temp_db_path = dest_dir / src_path.name
    shutil.copy2(src_path, temp_db_path)
    try:
        os.chmod(temp_db_path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass

    base_name = src_path.name
    parent_dir = src_path.parent

    suffixes = [
        f"{base_name}-wal",
        f"{base_name}-shm",
        f"{base_name}-journal",
        f"{src_path.stem}.sqlite-wal",
        f"{src_path.stem}.sqlite-shm",
    ]

    for sfx in suffixes:
        wal_file = parent_dir / sfx
        try:
            if wal_file.is_file() and wal_file.stat().st_size > 0:
                dst_wal = dest_dir / sfx
                shutil.copy2(wal_file, dst_wal)
                try:
                    os.chmod(dst_wal, stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
        except Exception:
            pass

    return temp_db_path


def _quote_sql_ident(col: str) -> str:
    escaped = str(col).replace('"', '""')
    return f'"{escaped}"'


def _is_null_like(val: Any) -> bool:
    if val is None:
        return True
    if isinstance(val, float) and math.isnan(val):
        return True
    if pd is not None:
        try:
            if val is pd.NA or val is pd.NaT:
                return True
        except Exception:
            pass
    return False


def _parse_str_to_utc_naive(raw: str) -> Optional[datetime]:
    s = raw.strip()
    if not s:
        return None
    m = _ISO_OFFSET_RE.match(s)
    if m:
        date_part, time_part, tz_part = m.group(1), m.group(2), m.group(3)
        iso_norm = f"{date_part}T{time_part}"
        if tz_part:
            tz_up = tz_part.upper()
            if tz_up == "Z":
                iso_norm += "+00:00"
            elif len(tz_up) == 5 and (tz_up[0] in "+-"):
                iso_norm += f"{tz_up[:3]}:{tz_up[3:]}"
            else:
                iso_norm += tz_up
        try:
            dt = datetime.fromisoformat(iso_norm)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _format_utc_timestamp(val: Any) -> Optional[str]:
    if _is_null_like(val):
        return None
    if isinstance(val, datetime):
        dt = val.astimezone(timezone.utc).replace(tzinfo=None) if val.tzinfo is not None else val
        if dt.year < 1970 or (
            dt.year == 1970
            and dt.month == 1
            and dt.day == 1
            and dt.hour == 0
            and dt.minute == 0
            and dt.second == 0
        ):
            return None
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(val, date):
        if val.year < 1970:
            return None
        date_str = val.strftime("%Y-%m-%d")
        return f"{date_str} 00:00:00"
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        dt = _epoch_sec_to_utc(float(val), _MAX_EPOCH_SECONDS)
        return dt.strftime("%Y-%m-%d %H:%M:%S") if dt is not None else None
    if isinstance(val, str):
        dt = _parse_str_to_utc_naive(val)
        if dt is None:
            return None
        if dt.year < 1970 or (
            dt.year == 1970
            and dt.month == 1
            and dt.day == 1
            and dt.hour == 0
            and dt.minute == 0
            and dt.second == 0
        ):
            return None
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return None


def _format_utc_timestamp_with_epoch(val: Any) -> Tuple[Optional[str], Optional[float]]:
    formatted = _format_utc_timestamp(val)
    if formatted is None:
        return None, None
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return formatted, float(val)
    try:
        dt_utc = datetime.strptime(formatted, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return formatted, (dt_utc - _UNIX_EPOCH_UTC).total_seconds()
    except ValueError:
        return formatted, None


def _sanitize_utf8_str(val: str) -> str:
    try:
        val.encode("utf-8")
        return val
    except UnicodeEncodeError:
        return val.encode("utf-16", errors="surrogatepass").decode("utf-16", errors="replace")


_CESU8_PAIR_RE = re.compile(rb"\xed[\xa0-\xaf][\x80-\xbf]\xed[\xb0-\xbf][\x80-\xbf]")
_WTF8_SURROGATE_RE = re.compile(rb"\xed[\xa0-\xbf][\x80-\xbf]")


def _cesu8_pair_to_utf8(match: re.Match[bytes]) -> bytes:
    return (
        match.group(0)
        .decode("utf-8", errors="surrogatepass")
        .encode("utf-16", errors="surrogatepass")
        .decode("utf-16", errors="replace")
        .encode("utf-8")
    )


def safe_sqlite_text_factory(raw: Union[bytes, str]) -> str:
    r"""
    Resilient `sqlite3.Connection.text_factory` for browser/forensic SQLite databases.
    - Clean UTF-8 `bytes` decode directly at native C speed (zero overhead).
    - WTF-8 / `sqlite3_bind_text16` surrogates (`0xED 0xA0..0xBF 0x80..0xBF`) map each lone surrogate
      1-to-1 to `\ufffd` while reassembling valid 6-byte CESU-8 surrogate pairs into astral characters.
    - Mixed WTF-8 surrogates + raw invalid non-UTF-8 bytes (`0xFF`, `0xFE`, etc.) never raise an exception.
    """
    if isinstance(raw, str):
        return _sanitize_utf8_str(raw)
    b = bytes(raw) if isinstance(raw, (bytearray, memoryview)) else raw
    if not isinstance(b, bytes):
        return _sanitize_utf8_str(str(b))
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = b.decode("utf-8", errors="surrogatepass")
            return s.encode("utf-16", errors="surrogatepass").decode("utf-16", errors="replace")
        except UnicodeDecodeError:
            try:
                patched = _CESU8_PAIR_RE.sub(_cesu8_pair_to_utf8, b)
                patched = _WTF8_SURROGATE_RE.sub(b"\xef\xbf\xbd", patched)
                return patched.decode("utf-8", errors="replace")
            except Exception:
                return b.decode("utf-8", errors="replace")


def _normalize_cell_for_duckdb(val: Any, col_type_upper: str) -> Any:
    r"""
    Normalizes a Python cell value to match a target DuckDB column type cleanly across
    BOTH `pandas` DataFrame bulk registration and `cursor.executemany` insertion.
    Prevents:
    1) Local-timezone (+05:30) shift when inserting UTC-aware `datetime` into naive `TIMESTAMP`.
    2) ConversionException when inserting `""` into `TIMESTAMP` / numeric / boolean columns.
    3) Unserializable `dict`/`list`/`bytes` crashes on `VARCHAR` columns.
    """
    if _is_null_like(val):
        return None

    t = col_type_upper.upper().strip()

    # 1. TIMESTAMP WITH TIME ZONE / TIMESTAMPTZ vs naive TIMESTAMP
    if "TIMESTAMP" in t:
        is_tz = "WITH TIME ZONE" in t or t == "TIMESTAMPTZ"
        if isinstance(val, datetime):
            if is_tz:
                return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc).replace(tzinfo=None) if val.tzinfo is not None else val
        if isinstance(val, date):
            dt = datetime(val.year, val.month, val.day)
            return dt.replace(tzinfo=timezone.utc) if is_tz else dt
        if isinstance(val, str):
            dt = _parse_str_to_utc_naive(val)
            if dt is None:
                return None
            return dt.replace(tzinfo=timezone.utc) if is_tz else dt
        return None

    if t == "DATE":
        if isinstance(val, datetime):
            dt = val.astimezone(timezone.utc) if val.tzinfo is not None else val
            return dt.date()
        if isinstance(val, date):
            return val
        if isinstance(val, str):
            dt = _parse_str_to_utc_naive(val)
            return dt.date() if dt else None
        return None

    # 2. BOOLEAN
    if "BOOL" in t:
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return bool(val)
        if isinstance(val, str):
            s = val.strip().lower()
            if not s:
                return None
            if s in ("true", "1", "yes", "y", "t"):
                return True
            if s in ("false", "0", "no", "n", "f"):
                return False
            return None
        return bool(val)

    # 3. INTEGER / BIGINT / HUGEINT / SMALLINT / TINYINT / UBIGINT
    if "INT" in t:
        if isinstance(val, bool):
            return int(val)
        if isinstance(val, int):
            return val
        if isinstance(val, float):
            return int(val) if math.isfinite(val) else None
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return None
            try:
                return int(s)
            except ValueError:
                try:
                    f = float(s)
                    return int(f) if math.isfinite(f) else None
                except ValueError:
                    return None
        return None

    # 4. DOUBLE / FLOAT / REAL / DECIMAL / NUMERIC
    if any(k in t for k in ("DOUBLE", "FLOAT", "REAL", "DECIMAL", "NUMERIC")):
        if isinstance(val, bool):
            return float(int(val))
        if isinstance(val, (int, float)):
            f = float(val)
            return f if math.isfinite(f) else None
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return None
            try:
                f = float(s)
                return f if math.isfinite(f) else None
            except ValueError:
                return None
        return None

    # 5. BLOB / BYTEA
    if "BLOB" in t or "BYTEA" in t:
        if isinstance(val, (bytes, bytearray, memoryview)):
            return bytes(val)
        return str(val).encode("utf-8", errors="replace")

    # 6. VARCHAR / TEXT / JSON / fallback string types (sanitize lone UTF-16 surrogates)
    if isinstance(val, str):
        return _sanitize_utf8_str(val)
    if isinstance(val, (dict, list, tuple)):
        try:
            return _sanitize_utf8_str(json.dumps(val, ensure_ascii=False, default=str))
        except Exception:
            return _sanitize_utf8_str(str(val))
    if isinstance(val, (bytes, bytearray)):
        return bytes(val).decode("utf-8", errors="replace")
    if isinstance(val, datetime):
        dt = val.astimezone(timezone.utc).replace(tzinfo=None) if val.tzinfo is not None else val
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return _sanitize_utf8_str(str(val))


def _infer_dynamic_duckdb_type(values: Iterable[Any]) -> str:
    r"""
    Infers an explicit SQL column type when creating a table dynamically (`schema_ddl=None`).
    Never returns `"NULL"` (`SQLNULL`) — all-None columns default cleanly to `VARCHAR`.
    """
    saw_bool = False
    saw_int = False
    saw_float = False
    saw_dt = False
    saw_other = False

    for v in values:
        if _is_null_like(v):
            continue
        if isinstance(v, bool):
            saw_bool = True
        elif isinstance(v, int):
            if -(2**63) <= v <= (2**63 - 1):
                saw_int = True
            else:
                saw_other = True
        elif isinstance(v, float):
            if math.isfinite(v):
                saw_float = True
        elif isinstance(v, (datetime, date)):
            saw_dt = True
        else:
            saw_other = True

    if saw_other:
        return "VARCHAR"
    kinds = sum([1 if (saw_int or saw_float) else 0, 1 if saw_bool else 0, 1 if saw_dt else 0])
    if kinds > 1:
        return "VARCHAR"
    if saw_bool:
        return "BOOLEAN"
    if saw_float:
        return "DOUBLE"
    if saw_int:
        return "BIGINT"
    if saw_dt:
        return "TIMESTAMP"
    return "VARCHAR"


def _validate_identifier(name: str) -> str:
    clean = str(name or "").strip()
    if not clean or not _VALID_SQL_IDENT_RE.match(clean):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return clean


class BaseParser:
    r"""
    Base forensic parser class.
    All custom application parsers (Chromium, Firefox, Chat, Cloud, CorporateIR, Document, Email, Media, USB) inherit from this.
    """

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Union[str, Path]] = None,
        source_type: Optional[str] = None,
        db_manager: Any = None,
    ) -> None:
        self.case_id = str(case_id)
        self.db_manager = db_manager if db_manager is not None else DuckDBManager
        self.case_dir = get_case_dir(self.case_id).resolve()
        self.staging_dir = (
            Path(staging_dir).resolve()
            if staging_dir is not None
            else get_case_staging_dir(self.case_id).resolve()
        )
        self.log_file = get_case_log_file(self.case_id).resolve()
        self.source_type: Optional[str] = (
            str(source_type).strip().lower() if source_type is not None else None
        )
        self._resolved_source_type: Optional[str] = self.source_type
        self._source_type_checked: bool = self.source_type is not None
        self._vfs_staged_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._vfs_part_labels_cache: Optional[Set[str]] = None
        self._last_log_msg: Optional[str] = None

        with self.db_manager.get_lock(self.case_id):
            self.conn = self.db_manager.get_connection(self.case_id, read_only=False)

    def _get_conn(self) -> duckdb.DuckDBPyConnection:
        with self.db_manager.get_lock(self.case_id):
            self.conn = self.db_manager.get_connection(self.case_id, read_only=False)
            return self.conn

    def execute_ddl(self, ddl_sql: str) -> None:
        r"""Thread-safe helper to execute schema DDL on a fresh cursor under case RLock."""
        if not ddl_sql or not ddl_sql.strip():
            return
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cursor = conn.cursor()
            cursor.execute(ddl_sql)

    def _log(self, message: str, level: str = "INFO") -> None:
        norm_msg = re.sub(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\s*UTC)?\]\s*", "", message).strip()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        cls_name = self.__class__.__name__
        formatted = _sanitize_utf8_str(f"[{timestamp}] [{level}] [{cls_name}] {message}")
        with _LOG_FILE_LOCK:
            if getattr(self, "_last_log_msg", None) == norm_msg:
                return
            self._last_log_msg = norm_msg
            try:
                print(formatted)
            except UnicodeEncodeError:
                try:
                    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
                    print(formatted.encode(enc, errors="replace").decode(enc, errors="replace"))
                except Exception:
                    pass
            except Exception:
                pass
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(formatted + "\n")
            except Exception:
                pass

    def log_processing(
        self,
        module_name: str,
        command_executed: str,
        exit_code: int,
        rows_ingested: int,
        duration_ms: int,
        status: str = "SUCCESS",
        error_message: Optional[str] = None,
    ) -> None:
        try:
            log_processing_event(
                case_id=self.case_id,
                module_name=module_name,
                command_executed=command_executed,
                exit_code=exit_code,
                rows_ingested=rows_ingested,
                duration_ms=duration_ms,
                status=status,
                error_message=error_message,
            )
        except Exception as e:
            self._log(f"Warning logging processing event: {e}", "WARNING")

    @staticmethod
    def _ensure_artifact_registry_table(cursor: duckdb.DuckDBPyCursor) -> None:
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

    def remove_artifact(self, artifact_id: str, table_name: str) -> None:
        clean_table = _validate_identifier(table_name)
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cursor = conn.cursor()
            try:
                cursor.execute(f'DROP TABLE IF EXISTS "{clean_table}";')
            except Exception:
                pass
            try:
                cursor.execute(f'DROP VIEW IF EXISTS "{clean_table}";')
            except Exception:
                pass
            try:
                cursor.execute(
                    "DELETE FROM artifact_registry WHERE artifact_id = ? OR table_name = ?;",
                    [artifact_id, clean_table],
                )
            except Exception:
                pass

    def register_artifact(
        self,
        table_name: str,
        artifact_id: str,
        category: str,
        display_name: str,
        source_tool: str,
        row_count: Optional[int] = None,
    ) -> int:
        clean_table = _validate_identifier(table_name)
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cursor = conn.cursor()
            self._ensure_artifact_registry_table(cursor)
            if row_count is None:
                try:
                    row = cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}";').fetchone()
                    row_count = int(row[0]) if row else 0
                except Exception:
                    row_count = 0

            cursor.execute(
                """
                INSERT INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, now())
                ON CONFLICT (artifact_id) DO UPDATE SET
                    category = EXCLUDED.category,
                    display_name = EXCLUDED.display_name,
                    table_name = EXCLUDED.table_name,
                    source_tool = EXCLUDED.source_tool,
                    row_count = EXCLUDED.row_count,
                    last_updated = now();
                """,
                [artifact_id, category, display_name, clean_table, source_tool, int(row_count)],
            )
            return int(row_count)

    def insert_records(
        self,
        table_name: str,
        records: List[Dict[str, Any]],
        schema_ddl: Optional[str] = None,
        artifact_id: Optional[str] = None,
        category: Optional[str] = None,
        display_name: Optional[str] = None,
        source_tool: Optional[str] = None,
        append: bool = False,
    ) -> int:
        clean_table = _validate_identifier(table_name)
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cursor = conn.cursor()

            if schema_ddl:
                cursor.execute(schema_ddl)

            table_exists = (
                cursor.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = ? LIMIT 1;",
                    [clean_table],
                ).fetchone()
                is not None
            )

            if not records:
                if not append:
                    if table_exists:
                        try:
                            cursor.execute(f'DELETE FROM "{clean_table}";')
                        except Exception:
                            pass
                    if artifact_id:
                        try:
                            cursor.execute(
                                "UPDATE artifact_registry SET row_count = 0, last_updated = now() WHERE artifact_id = ? OR table_name = ?;",
                                [artifact_id, clean_table],
                            )
                        except Exception:
                            pass
                if append and table_exists:
                    cnt_row = cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}";').fetchone()
                    return int(cnt_row[0]) if cnt_row else 0
                return 0

            # Preserve deterministic key union order across all input dicts (excluding _row_id)
            record_cols: List[str] = []
            seen_keys: Set[str] = set()
            for rec in records:
                for k in rec.keys():
                    if k != "_row_id" and k not in seen_keys:
                        seen_keys.add(k)
                        record_cols.append(k)

            # Dynamic table creation when no schema_ddl created the table (e.g. parse_universal_sqlite)
            if not table_exists:
                col_defs: List[str] = ['"_row_id" BIGINT']
                for col in record_cols:
                    quoted_col = _quote_sql_ident(col)
                    inferred_sql_type = _infer_dynamic_duckdb_type(rec.get(col) for rec in records)
                    col_defs.append(f"{quoted_col} {inferred_sql_type}")
                col_defs_sql = ", ".join(col_defs)
                cursor.execute(f'CREATE TABLE "{clean_table}" ({col_defs_sql});')
                table_exists = True
            elif not append:
                cursor.execute(f'DELETE FROM "{clean_table}";')

            desc_rows = cursor.execute(f'DESCRIBE "{clean_table}";').fetchall()
            col_type_map: Dict[str, str] = {str(r[0]): str(r[1]) for r in desc_rows}
            existing_cols = [str(r[0]) for r in desc_rows if str(r[0]) != "_row_id"]
            has_row_id = "_row_id" in col_type_map

            max_id = 0
            if has_row_id:
                max_row = cursor.execute(
                    f'SELECT COALESCE(MAX("_row_id"), 0) FROM "{clean_table}";'
                ).fetchone()
                max_id = int(max_row[0] or 0) if max_row else 0

            common_cols = [c for c in existing_cols if c in seen_keys]
            target_cols = (["_row_id"] + common_cols) if has_row_id else list(common_cols)
            if not target_cols:
                return 0

            num_rows = len(records)
            row_ids = list(range(max_id + 1, max_id + num_rows + 1))

            # Normalize each column once according to exact DuckDB target column type
            normalized_columns: Dict[str, List[Any]] = {}
            if has_row_id:
                normalized_columns["_row_id"] = row_ids
            for col in common_cols:
                ctype = col_type_map.get(col, "VARCHAR")
                normalized_columns[col] = [
                    _normalize_cell_for_duckdb(rec.get(col), ctype) for rec in records
                ]

            cols_sql = ", ".join(_quote_sql_ident(c) for c in target_cols)

            inserted_via_df = False
            if pd is not None and num_rows > 0:
                tid_val = threading.get_ident()
                uid_val = uuid.uuid4().hex[:12]
                temp_reg_name = f"temp_df_{clean_table}_{tid_val}_{uid_val}"
                try:
                    series_map: Dict[str, Any] = {}
                    for col in target_cols:
                        vals = normalized_columns[col]
                        ctype_up = (
                            "BIGINT" if col == "_row_id" else col_type_map.get(col, "VARCHAR").upper()
                        )
                        if "INT" in ctype_up:
                            series_map[col] = pd.array(vals, dtype="Int64")
                        elif "BOOL" in ctype_up:
                            series_map[col] = pd.array(vals, dtype="boolean")
                        else:
                            series_map[col] = pd.Series(vals, dtype="object")
                    df = pd.DataFrame(series_map, columns=target_cols)
                    cursor.register(temp_reg_name, df)
                    try:
                        cursor.execute(
                            f'INSERT INTO "{clean_table}" ({cols_sql}) '
                            f'SELECT {cols_sql} FROM "{temp_reg_name}";'
                        )
                        inserted_via_df = True
                    finally:
                        try:
                            cursor.unregister(temp_reg_name)
                        except Exception:
                            pass
                except Exception:
                    inserted_via_df = False

            if not inserted_via_df:
                placeholders = ", ".join(["?"] * len(target_cols))
                insert_sql = f'INSERT INTO "{clean_table}" ({cols_sql}) VALUES ({placeholders});'
                col_lists = [normalized_columns[c] for c in target_cols]
                rows_tuples = list(zip(*col_lists))
                chunk_size = 5000
                for offset in range(0, len(rows_tuples), chunk_size):
                    cursor.executemany(insert_sql, rows_tuples[offset : offset + chunk_size])

            total_row = cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}";').fetchone()
            total_count = int(total_row[0] or 0) if total_row else 0

            if artifact_id and category and display_name and source_tool:
                self.register_artifact(
                    table_name=clean_table,
                    artifact_id=artifact_id,
                    category=category,
                    display_name=display_name,
                    source_tool=source_tool,
                    row_count=total_count,
                )

            return total_count

    # ------------------------------------------------------------------
    # Path Normalization & Staging Context Helpers (F13.2)
    # ------------------------------------------------------------------
    def _compute_staging_rel_parts(self, file_path: Union[str, Path]) -> Tuple[Optional[str], Optional[int]]:
        r"""
        Computes normalized forward-slash relative path inside `self.staging_dir`
        (or after `/staging/`), plus optional `VSS#<N>` shadow copy index if staged under `VSS/VSS_<N>/...`.
        """
        p = Path(file_path)
        rel_posix: Optional[str] = None
        try:
            resolved_p = p.resolve()
            rel_posix = resolved_p.relative_to(self.staging_dir).as_posix()
        except Exception:
            s_norm = str(p).replace("\\", "/")
            stg_norm = str(self.staging_dir).replace("\\", "/").rstrip("/")
            if stg_norm and s_norm.lower().startswith(stg_norm.lower() + "/"):
                rel_posix = s_norm[len(stg_norm) + 1 :]
            else:
                m_stg = re.search(r"(?i)(?:^|/)staging/(.+)$", s_norm)
                if m_stg:
                    rel_posix = m_stg.group(1)

        if not rel_posix:
            return None, None

        rel_posix = rel_posix.strip("/")
        parts = [seg for seg in rel_posix.split("/") if seg and seg != "."]
        vss_idx: Optional[int] = None
        if len(parts) >= 2 and parts[0].lower() == "vss":
            m_vss = _VSS_SEGMENT_RE.match(parts[1])
            if m_vss:
                vss_idx = int(m_vss.group(1))
                parts = parts[2:]
        elif len(parts) >= 2:
            m_vss = _VSS_SEGMENT_RE.match(parts[0])
            if m_vss:
                vss_idx = int(m_vss.group(1))
                parts = parts[1:]

        inner_rel = "/".join(parts) if parts else None
        return inner_rel, vss_idx

    def _raw_staging_rel_posix(self, file_path: Union[str, Path]) -> Optional[str]:
        p = Path(file_path)
        try:
            return p.resolve().relative_to(self.staging_dir).as_posix().strip("/")
        except Exception:
            s_norm = str(p).replace("\\", "/")
            stg_norm = str(self.staging_dir).replace("\\", "/").rstrip("/")
            if stg_norm and s_norm.lower().startswith(stg_norm.lower() + "/"):
                return s_norm[len(stg_norm) + 1 :].strip("/")
            m_stg = re.search(r"(?i)(?:^|/)staging/(.+)$", s_norm)
            if m_stg:
                return m_stg.group(1).strip("/")
        return None

    @staticmethod
    def _format_vfs_windows_path(raw_vfs_path: str, vss_idx: Optional[int] = None) -> str:
        vp = str(raw_vfs_path).strip().replace("/", "\\")
        existing_vss: Optional[str] = None
        m_pre = re.match(
            r"^(?:[\\/]*vss[_\-#]?(\d+)(?:[\\/]+|\s+)|\[vss[_\-#]?(\d+)\]\s*)(.+)$",
            vp,
            flags=re.IGNORECASE,
        )
        if m_pre:
            num_str = m_pre.group(1) or m_pre.group(2)
            existing_vss = f"[VSS#{num_str}]"
            vp = m_pre.group(3).strip()

        if vp.startswith(".\\"):
            vp = "C:\\" + vp[2:]
        elif vp.startswith("."):
            vp = "C:" + vp[1:]
        elif vp.startswith("\\"):
            vp = "C:" + vp
        elif not re.match(r"^[A-Za-z]:", vp):
            vp = "C:\\" + vp.lstrip("\\")

        if existing_vss:
            return f"{existing_vss} {vp}"
        if vss_idx is not None:
            return f"[VSS#{vss_idx}] {vp}"
        return vp

    def _get_vfs_staged_cache(self) -> Optional[Dict[str, Dict[str, Any]]]:
        if self._vfs_staged_cache is not None:
            return self._vfs_staged_cache
        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                has_vfs = (
                    cur.execute(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'vfs_files' LIMIT 1;"
                    ).fetchone()
                    is not None
                )
                if not has_vfs:
                    return None
                cnt_row = cur.execute('SELECT COUNT(*) FROM "vfs_files";').fetchone()
                if not cnt_row or int(cnt_row[0] or 0) <= 500:
                    return None
                vfs_cols = {
                    str(r[0]).lower(): str(r[0])
                    for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                }
                if "staged_rel_path" not in vfs_cols:
                    return None
                q_staged = _quote_sql_ident(vfs_cols["staged_rel_path"])
                want_keys = (
                    "vfs_path",
                    "si_modified",
                    "si_modified_utc",
                    "fn_modified",
                    "fn_modified_utc",
                    "si_created",
                    "si_created_utc",
                    "fn_created",
                    "fn_created_utc",
                )
                sel_exprs = [q_staged] + [
                    _quote_sql_ident(vfs_cols[k]) if k in vfs_cols else "NULL"
                    for k in want_keys
                ]
                rows = cur.execute(
                    f'SELECT {", ".join(sel_exprs)} FROM "vfs_files" WHERE {q_staged} IS NOT NULL;'
                ).fetchall()
                cache: Dict[str, Dict[str, Any]] = {}
                for r in rows:
                    srp = r[0]
                    if not srp:
                        continue
                    norm_k = str(srp).replace("\\", "/").strip("/").lower()
                    if norm_k and norm_k not in cache:
                        entry: Dict[str, Any] = {want_keys[idx]: r[idx + 1] for idx in range(len(want_keys))}
                        cache[norm_k] = entry
                        if not norm_k.startswith("staging/"):
                            cache.setdefault(f"staging/{norm_k}", entry)
                self._vfs_staged_cache = cache
                return cache
        except Exception:
            return None

    def _lookup_vfs_files_path(
        self, raw_rel_posix: Optional[str], inner_rel_posix: Optional[str], vss_idx: Optional[int]
    ) -> Optional[str]:
        primary_candidates: List[str] = []
        if raw_rel_posix:
            c_clean = raw_rel_posix.strip("/").lower()
            if c_clean:
                primary_candidates.append(c_clean)
                primary_candidates.append(f"staging/{c_clean}")
        if vss_idx is not None and inner_rel_posix:
            in_clean = inner_rel_posix.strip("/").lower()
            if in_clean:
                for vss_c in (
                    f"vss/vss_{vss_idx}/{in_clean}",
                    f"staging/vss/vss_{vss_idx}/{in_clean}",
                    f"vss_{vss_idx}/{in_clean}",
                    f"staging/vss_{vss_idx}/{in_clean}",
                ):
                    if vss_c not in primary_candidates:
                        primary_candidates.append(vss_c)

        fallback_candidates: List[str] = []
        if inner_rel_posix:
            in_clean = inner_rel_posix.strip("/").lower()
            if in_clean:
                for fb_c in (in_clean, f"staging/{in_clean}"):
                    if fb_c not in primary_candidates and fb_c not in fallback_candidates:
                        fallback_candidates.append(fb_c)

        if not primary_candidates and not fallback_candidates:
            return None

        staged_cache = self._get_vfs_staged_cache()
        if staged_cache is not None:
            for cand_group in (primary_candidates, fallback_candidates):
                for cand in cand_group:
                    hit = staged_cache.get(cand)
                    if hit and hit.get("vfs_path"):
                        return self._format_vfs_windows_path(str(hit["vfs_path"]), vss_idx=vss_idx)
            return None

        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                has_vfs = (
                    cur.execute(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'vfs_files' LIMIT 1;"
                    ).fetchone()
                    is not None
                )
                if not has_vfs:
                    return None
                vfs_cols = {
                    str(r[0]).lower(): str(r[0])
                    for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                }
                if "staged_rel_path" not in vfs_cols or "vfs_path" not in vfs_cols:
                    return None
                q_staged = _quote_sql_ident(vfs_cols["staged_rel_path"])
                q_vfs = _quote_sql_ident(vfs_cols["vfs_path"])
                norm_expr = f"LOWER(TRIM(BOTH '/' FROM REPLACE({q_staged}, chr(92), '/')))"

                # Strictly prioritize exact/VSS-scoped `raw_rel_posix` matches before falling back to `inner_rel_posix`
                for cand_group in (primary_candidates, fallback_candidates):
                    if not cand_group:
                        continue
                    placeholders = ", ".join(["?"] * len(cand_group))
                    sql = (
                        f'SELECT {q_vfs} FROM "vfs_files" '
                        f"WHERE {q_staged} IS NOT NULL AND {norm_expr} IN ({placeholders}) "
                        f"LIMIT 1;"
                    )
                    row = cur.execute(sql, cand_group).fetchone()
                    if row and row[0]:
                        return self._format_vfs_windows_path(str(row[0]), vss_idx=vss_idx)
        except Exception:
            pass
        return None

    def _is_partition_segment(self, seg: str) -> Tuple[bool, str]:
        r"""
        Checks if `<seg>` in `staging/Enrichment/<seg>/...` is a partition label
        (e.g. `Part0`, `Partition_1`, `Vol1`, `C`, `D_drive`, or a `vfs_partitions.label`).
        Returns `(is_partition, drive_prefix)`.
        """
        s = seg.strip()
        if len(s) == 1 and s.isalpha():
            drv_letter = s.upper()
            return True, f"{drv_letter}:\\"
        m_drv = re.match(r"^([A-Za-z])_drive$", s, flags=re.IGNORECASE)
        if m_drv:
            drv_letter = m_drv.group(1).upper()
            return True, f"{drv_letter}:\\"
        if _PARTITION_LABEL_RE.match(s):
            return True, "C:\\"
        if self._vfs_part_labels_cache is not None:
            return (s.lower() in self._vfs_part_labels_cache), "C:\\"
        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                has_parts = (
                    cur.execute(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'vfs_partitions' LIMIT 1;"
                    ).fetchone()
                    is not None
                )
                if has_parts:
                    rows = cur.execute("SELECT LOWER(COALESCE(label, '')) FROM vfs_partitions;").fetchall()
                    labels = {str(r[0]) for r in rows if r and r[0]}
                    if self._vfs_staged_cache is not None:
                        self._vfs_part_labels_cache = labels
                    if s.lower() in labels:
                        return True, "C:\\"
        except Exception:
            pass
        return False, "C:\\"

    def _reconstruct_from_staging_rel(
        self, inner_rel_posix: str
    ) -> Tuple[Optional[str], Optional[str], bool]:
        r"""
        Reconstructs `(reconstructed_windows_path, parent_hint_for_mft, is_exact)` from
        normalized staging-relative POSIX path `inner_rel_posix` (after stripping `VSS/VSS_<N>/`).
        """
        parts = [p for p in inner_rel_posix.split("/") if p and p != "."]
        if not parts:
            return None, None, False

        top = parts[0].lower()
        bs = "\\"

        def win_join(segs: List[str]) -> str:
            return bs.join(segs)

        # 1. staging/Enrichment/...
        if top == "enrichment" and len(parts) >= 2:
            rem = parts[1:]
            drive = "C:\\"
            if len(rem) >= 2:
                is_part, drv = self._is_partition_segment(rem[0])
                if is_part:
                    drive = drv
                    rem = rem[1:]
            if not rem:
                return None, None, False
            if rem[0].lower() == "userfiles" and len(rem) >= 3:
                rest_joined = win_join(rem[2:])
                return f"{drive}Users\\{rem[1]}\\{rest_joined}", f"Users\\{rem[1]}", True
            if rem[0].lower() == "wwwroot" and len(rem) >= 2:
                sub = win_join(rem)
                return f"{drive}inetpub\\{sub}", sub, False
            if len(rem) >= 2:
                rel_win = win_join(rem)
                parent_win = win_join(rem[:-1])
                return f"{drive}{rel_win}", parent_win, True
            return None, None, False

        # 2. staging/UserFiles/<User>/<rel_path>
        if top == "userfiles" and len(parts) >= 3:
            user = parts[1]
            rest = win_join(parts[2:])
            parent_sub = win_join(parts[2:-1]) if len(parts) > 3 else ""
            parent_hint = f"Users\\{user}\\{parent_sub}" if parent_sub else f"Users\\{user}"
            return f"C:\\Users\\{user}\\{rest}", parent_hint, True

        # 3. Direct Windows root folders under staging
        if top in ("users", "windows", "programdata", "program files", "program files (x86)", "inetpub", "documents and settings") and len(parts) >= 2:
            rel_win = win_join(parts)
            parent_win = win_join(parts[:-1])
            return f"C:\\{rel_win}", parent_win, True

        # 4. staging/Browsers/<Browser>/<User>[/<Profile>]/<rest>
        if top == "browsers" and len(parts) >= 4:
            browser = parts[1].lower()
            user = parts[2]
            b_rem = parts[3:]
            chromium_roots = {
                "chrome": f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data",
                "edge": f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data",
                "brave": f"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",
            }
            if browser in chromium_roots:
                base = chromium_roots[browser]
                base_no_drv = base[3:]
                if len(b_rem) == 1:
                    if b_rem[0].lower() == "local state":
                        return f"{base}\\{b_rem[0]}", base_no_drv, True
                    return f"{base}\\Default\\{b_rem[0]}", f"{base_no_drv}\\Default", True
                first_low = b_rem[0].lower()
                if first_low in (
                    "network",
                    "sessions",
                    "cache",
                    "cache_data",
                    "code cache",
                    "gpucache",
                    "local storage",
                    "session storage",
                    "indexeddb",
                ):
                    sub = win_join(b_rem)
                    sub_parent = win_join(b_rem[:-1])
                    return f"{base}\\Default\\{sub}", f"{base_no_drv}\\Default\\{sub_parent}", True
                sub = win_join(b_rem)
                sub_parent = win_join(b_rem[:-1])
                return f"{base}\\{sub}", f"{base_no_drv}\\{sub_parent}", True

            if browser == "firefox":
                base = f"C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
                base_no_drv = base[3:]
                if len(b_rem) >= 2:
                    sub = win_join(b_rem)
                    sub_parent = win_join(b_rem[:-1])
                    return f"{base}\\{sub}", f"{base_no_drv}\\{sub_parent}", True
                return f"{base}\\default\\{b_rem[0]}", base_no_drv, False

            if browser in ("ie", "internetexplorer", "webcache"):
                base = f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\WebCache"
                sub = win_join(b_rem)
                return f"{base}\\{sub}", base[3:], True

        # 5. Registry, Logs, Prefetch, Tasks, SetupAPI, SRUM, WBEM
        if top == "registry":
            if len(parts) >= 4 and parts[1].lower() == "users":
                user = parts[2]
                fname = win_join(parts[3:])
                if parts[3].lower().startswith("usrclass.dat"):
                    p_dir = f"Users\\{user}\\AppData\\Local\\Microsoft\\Windows"
                    return f"C:\\{p_dir}\\{fname}", p_dir, True
                return f"C:\\Users\\{user}\\{fname}", f"Users\\{user}", True
            if len(parts) >= 3 and parts[1].lower() == "system":
                fname = win_join(parts[2:])
                return f"C:\\Windows\\System32\\config\\{fname}", "Windows\\System32\\config", True
            if len(parts) >= 3 and parts[1].lower() == "amcache":
                fname = win_join(parts[2:])
                return f"C:\\Windows\\AppCompat\\Programs\\{fname}", "Windows\\AppCompat\\Programs", True

        if top == "logs" and len(parts) >= 2:
            rest = win_join(parts[1:])
            return f"C:\\Windows\\System32\\winevt\\Logs\\{rest}", "Windows\\System32\\winevt\\Logs", True
        if top == "prefetch" and len(parts) >= 2:
            rest = win_join(parts[1:])
            return f"C:\\Windows\\Prefetch\\{rest}", "Windows\\Prefetch", True
        if top == "setupapi" and len(parts) >= 2:
            rest = win_join(parts[1:])
            return f"C:\\Windows\\INF\\{rest}", "Windows\\INF", True
        if top == "tasks" and len(parts) >= 2:
            rest = win_join(parts[1:])
            return f"C:\\Windows\\System32\\Tasks\\{rest}", "Windows\\System32\\Tasks", True
        if top == "srum" and len(parts) >= 2:
            rest = win_join(parts[1:])
            return f"C:\\Windows\\System32\\sru\\{rest}", "Windows\\System32\\sru", True
        if top == "wbem" and len(parts) >= 2:
            rest = win_join(parts[1:])
            return f"C:\\Windows\\System32\\wbem\\{rest}", "Windows\\System32\\wbem", True

        # 6. User-scoped Communication, Cloud, Notifications, ActivitiesCache
        if top == "notifications" and len(parts) >= 3:
            user = parts[1]
            rest = win_join(parts[2:])
            p_dir = f"Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\Notifications"
            return f"C:\\{p_dir}\\{rest}", p_dir, True
        if top == "activitiescache" and len(parts) >= 3:
            user = parts[1]
            rest = win_join(parts[2:])
            p_dir = f"Users\\{user}\\AppData\\Local\\ConnectedDevicesPlatform"
            return f"C:\\{p_dir}\\{rest}", p_dir, False
        if top == "chat" and len(parts) >= 4:
            app = parts[1].lower()
            user = parts[2]
            rest = win_join(parts[3:])
            app_roots = {
                "discord": f"Users\\{user}\\AppData\\Roaming\\discord",
                "teams": f"Users\\{user}\\AppData\\Roaming\\Microsoft\\Teams",
                "slack": f"Users\\{user}\\AppData\\Roaming\\Slack",
            }
            p_dir = app_roots.get(app, f"Users\\{user}\\AppData")
            return f"C:\\{p_dir}\\{rest}", p_dir, False
        if top == "cloud" and len(parts) >= 4:
            prov = parts[1].lower()
            user = parts[2]
            rest = win_join(parts[3:])
            prov_roots = {
                "onedrive": f"Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive",
                "googledrive": f"Users\\{user}\\AppData\\Local\\Google\\DriveFS",
                "dropbox": f"Users\\{user}\\AppData\\Local\\Dropbox",
            }
            p_dir = prov_roots.get(prov, f"Users\\{user}\\AppData\\Local")
            return f"C:\\{p_dir}\\{rest}", p_dir, False
        if top == "mail" and len(parts) >= 3:
            user = parts[1]
            rest = win_join(parts[2:])
            return f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Outlook\\{rest}", f"Users\\{user}", False

        # 7. Multi-segment paths with directory context (e.g. Documents/<User>/... or custom subfolder hierarchy)
        if len(parts) >= 3:
            sub_hint = win_join(parts[1:-1]) if top in _FLAT_STAGING_BUCKETS else win_join(parts[:-1])
            return None, sub_hint, False
        if len(parts) == 2 and top not in _FLAT_STAGING_BUCKETS:
            return None, parts[0], False

        return None, None, False

    def _lookup_parent_aware_mft(
        self,
        fname: str,
        parent_hint: Optional[str],
        file_size: Optional[int],
        vss_idx: Optional[int],
    ) -> Optional[str]:
        r"""
        Parent-path-aware `raw_mft` lookup.
        - NEVER matches bare `FileName` alone when `fname` is generic (`History`, `Cookies`, `index.dat`, `web.config`, etc.).
        - NEVER returns a `raw_mft` row whose `ParentPath` contradicts `parent_hint` when `parent_hint` is known.
        - Without `parent_hint`, non-generic filenames match ONLY if `raw_mft` yields a single unambiguous directory.
        """
        fname_low = fname.lower()
        is_generic = (
            fname_low in GENERIC_FORENSIC_FILENAMES
            or bool(_CACHE_DATA_FILE_RE.match(fname_low))
        )
        if not parent_hint and is_generic:
            return None

        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                has_mft = (
                    cur.execute(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'raw_mft' LIMIT 1;"
                    ).fetchone()
                    is not None
                )
                if not has_mft:
                    return None

                mft_cols = {
                    str(r[0]).lower(): str(r[0])
                    for r in cur.execute('DESCRIBE "raw_mft";').fetchall()
                }
                pp_col = _quote_sql_ident(mft_cols.get("parentpath", "ParentPath"))
                fn_col = _quote_sql_ident(mft_cols.get("filename", "FileName"))
                fs_expr = (
                    f"TRY_CAST({_quote_sql_ident(mft_cols['filesize'])} AS BIGINT)"
                    if "filesize" in mft_cols
                    else "NULL"
                )
                order_expr = (
                    f"{_quote_sql_ident(mft_cols['lastmodified0x10'])} DESC NULLS LAST"
                    if "lastmodified0x10" in mft_cols
                    else "1"
                )

                rows = cur.execute(
                    f"""
                    SELECT {pp_col}, {fn_col}, {fs_expr} AS fsize
                    FROM "raw_mft"
                    WHERE LOWER({fn_col}) = LOWER(?)
                      AND {pp_col} IS NOT NULL
                      AND LOWER({pp_col}) NOT LIKE '%$recycle.bin%'
                      AND LOWER({pp_col}) NOT LIKE '%__part%'
                    ORDER BY {order_expr};
                    """,
                    [fname],
                ).fetchall()
                if not rows:
                    return None

                candidates: List[Tuple[str, str, Optional[int]]] = []
                for raw_pp, mft_fname, mft_fsize in rows:
                    if not raw_pp:
                        continue
                    cleaned_pp = str(raw_pp).rstrip("/\\")
                    combined_raw = f"{cleaned_pp}\\{mft_fname}"
                    norm_full = self._format_vfs_windows_path(combined_raw)
                    norm_parent = norm_full.rsplit("\\", 1)[0]
                    candidates.append(
                        (
                            norm_parent,
                            str(mft_fname),
                            int(mft_fsize) if mft_fsize is not None else None,
                        )
                    )

                if not candidates:
                    return None

                if parent_hint:
                    hint_norm = parent_hint.strip("\\/").replace("/", "\\").lower()
                    matched = [
                        c
                        for c in candidates
                        if c[0].lower().endswith("\\" + hint_norm)
                        or c[0].lower().endswith(":\\" + hint_norm)
                        or ("\\" + hint_norm + "\\") in (c[0].lower() + "\\")
                    ]
                    if not matched:
                        # Also support multi-token non-contiguous hints like "Alice\Profile 1"
                        hint_tokens = [tok for tok in hint_norm.split("\\") if tok]
                        if len(hint_tokens) >= 2:
                            def _subseq_match(parent_low: str) -> bool:
                                p_segs = [seg for seg in parent_low.split("\\") if seg]
                                pos = 0
                                for tok in hint_tokens:
                                    found = False
                                    while pos < len(p_segs):
                                        if p_segs[pos] == tok:
                                            found = True
                                            pos += 1
                                            break
                                        pos += 1
                                    if not found:
                                        return False
                                return True

                            matched = [c for c in candidates if _subseq_match(c[0].lower())]
                    if not matched:
                        return None
                    if file_size is not None and file_size > 0:
                        size_matched = [c for c in matched if c[2] == int(file_size)]
                        if len(size_matched) == 1:
                            win_p = f"{size_matched[0][0]}\\{size_matched[0][1]}"
                            return f"[VSS#{vss_idx}] {win_p}" if vss_idx is not None else win_p
                        if len(size_matched) > 1:
                            matched = size_matched
                    unique_dirs = {c[0].lower() for c in matched}
                    if len(unique_dirs) == 1:
                        win_p = f"{matched[0][0]}\\{matched[0][1]}"
                        return f"[VSS#{vss_idx}] {win_p}" if vss_idx is not None else win_p
                    if is_generic:
                        return None
                    win_p = f"{matched[0][0]}\\{matched[0][1]}"
                    return f"[VSS#{vss_idx}] {win_p}" if vss_idx is not None else win_p

                # No parent_hint (already guaranteed `not is_generic`)
                if file_size is not None and file_size > 0:
                    size_matched = [c for c in candidates if c[2] == int(file_size)]
                    if len({c[0].lower() for c in size_matched}) == 1 and size_matched:
                        win_p = f"{size_matched[0][0]}\\{size_matched[0][1]}"
                        return f"[VSS#{vss_idx}] {win_p}" if vss_idx is not None else win_p

                unique_dirs = {c[0].lower() for c in candidates}
                if len(unique_dirs) == 1:
                    win_p = f"{candidates[0][0]}\\{candidates[0][1]}"
                    return f"[VSS#{vss_idx}] {win_p}" if vss_idx is not None else win_p

                return None
        except Exception:
            return None

    def resolve_evidence_path(self, staged_file: Union[str, Path], file_size: Optional[int] = None) -> str:
        r"""
        Deterministically resolves the original forensic evidence path for `staged_file`:
        Priority (a): Exact/normalized `staged_rel_path` lookup in `vfs_files` (with `[VSS#<N>]` provenance if staged from VSS).
        Priority (b): Deterministic staging hierarchy reconstruction (`Enrichment/<part>/<rel>`, `Browsers/...`, `UserFiles/...`, `VSS/VSS_<N>/...`, etc.).
        Priority (c): Parent-path-aware `raw_mft` lookup (NEVER colliding on bare generic filenames like `History`, `Cookies`, `index.dat`, `web.config`).
        Fallback: `[Staged] <rel_path_or_name>`.
        """
        staged_p = Path(staged_file)
        fname = staged_p.name
        raw_rel = self._raw_staging_rel_posix(staged_p)
        inner_rel, vss_idx = self._compute_staging_rel_parts(staged_p)

        # Priority (a): Authoritative `vfs_files` lookup
        vfs_hit = self._lookup_vfs_files_path(raw_rel, inner_rel, vss_idx)
        if vfs_hit:
            return vfs_hit

        # Priority (b): Reconstruct from relative staging path patterns
        reconstructed: Optional[str] = None
        parent_hint: Optional[str] = None
        is_exact = False
        if inner_rel:
            reconstructed, parent_hint, is_exact = self._reconstruct_from_staging_rel(inner_rel)
            if reconstructed and is_exact:
                return f"[VSS#{vss_idx}] {reconstructed}" if vss_idx is not None else reconstructed

        # Fallback regex check if file was outside `self.staging_dir` (e.g. `...\Users\<User>\...`)
        if not inner_rel:
            s_win = str(staged_p).replace("/", "\\")
            m_us = re.search(r"(?i)(?:^|\\)(Users\\[^\\]+\\.+)$", s_win)
            if m_us:
                return f"C:\\{m_us.group(1)}"

        # Priority (c): Parent-path-aware `raw_mft` matching
        mft_hit = self._lookup_parent_aware_mft(
            fname=fname,
            parent_hint=parent_hint,
            file_size=file_size,
            vss_idx=vss_idx,
        )
        if mft_hit:
            return mft_hit

        if reconstructed:
            return f"[VSS#{vss_idx}] {reconstructed}" if vss_idx is not None else reconstructed

        if raw_rel:
            return f"[Staged] {raw_rel}"
        return f"[Staged] {fname}"

    # ------------------------------------------------------------------
    # Original VFS / Forensic Timestamp Resolution (F13.2)
    # ------------------------------------------------------------------
    def _detect_source_type(self) -> Optional[str]:
        r"""
        Determines case `source_type` (`'image'`, `'folder'`, `'live'`, etc.) by checking:
        1. `self.source_type` if explicitly provided.
        2. DuckDB `case_metadata` table (`key = 'source_type'`).
        3. DuckDB `processing_logs` (`Pipeline:Extractor` command string) or `vfs_partitions` rows.
        4. Case JSON metadata files in `self.case_dir` or `self.staging_dir`, or `staging/MFT`.
        """
        if self.source_type:
            return self.source_type
        if self._source_type_checked and self._resolved_source_type is not None:
            return self._resolved_source_type

        detected: Optional[str] = None
        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                existing_tables = {
                    str(r[0])
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if "case_metadata" in existing_tables:
                    cols = {str(r[0]).lower() for r in cur.execute('DESCRIBE "case_metadata";').fetchall()}
                    if "key" in cols and "value" in cols:
                        row = cur.execute(
                            "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                        ).fetchone()
                        if row and row[0]:
                            detected = str(row[0]).strip().lower()
                    elif "source_type" in cols:
                        row = cur.execute("SELECT source_type FROM case_metadata LIMIT 1;").fetchone()
                        if row and row[0]:
                            detected = str(row[0]).strip().lower()

                if not detected and "processing_logs" in existing_tables:
                    row = cur.execute(
                        """
                        SELECT command_executed
                        FROM processing_logs
                        WHERE module_name LIKE '%Extractor%'
                        ORDER BY log_id DESC
                        LIMIT 1;
                        """
                    ).fetchone()
                    if row and row[0]:
                        m_ext = re.search(r"Extractor\s*\(([^)]+)\)", str(row[0]), flags=re.IGNORECASE)
                        if m_ext:
                            detected = m_ext.group(1).strip().lower()

                if not detected and "vfs_partitions" in existing_tables:
                    cnt = cur.execute("SELECT COUNT(*) FROM vfs_partitions;").fetchone()
                    if cnt and int(cnt[0] or 0) > 0:
                        detected = "image"
        except Exception:
            pass

        if not detected:
            for meta_candidate in (
                self.case_dir / "case_metadata.json",
                self.case_dir / "case_info.json",
                self.case_dir / "metadata.json",
                self.staging_dir / "vfs_manifest.json",
            ):
                try:
                    if meta_candidate.is_file():
                        payload = json.loads(meta_candidate.read_text(encoding="utf-8", errors="replace"))
                        if isinstance(payload, dict) and payload.get("source_type"):
                            detected = str(payload["source_type"]).strip().lower()
                            break
                except Exception:
                    continue

        if not detected:
            try:
                mft_dir = self.staging_dir / "MFT"
                if mft_dir.is_dir() and any(mft_dir.iterdir()):
                    detected = "image"
            except Exception:
                pass

        self._source_type_checked = True
        if detected:
            self._resolved_source_type = detected
        return detected

    def _get_staging_dir_ctime(self) -> Optional[float]:
        try:
            if self.staging_dir.exists():
                val = float(self.staging_dir.stat().st_ctime)
                return val if val > 0 else None
        except OSError:
            pass
        return None

    def _is_staging_wallclock_epoch(self, ts_epoch: float, now_ts: Optional[float] = None) -> bool:
        ref_now = time.time() if now_ts is None else now_ts
        if abs(ref_now - ts_epoch) < 300.0:
            return True
        stg_ctime = self._get_staging_dir_ctime()
        if stg_ctime is not None and (stg_ctime - 120.0) <= ts_epoch <= (ref_now + 300.0):
            return True
        return False

    def _build_vfs_lookup_candidates(self, p: Path) -> Tuple[List[str], List[str]]:
        raw_rel = self._raw_staging_rel_posix(p)
        inner_rel, vss_idx = self._compute_staging_rel_parts(p)

        vfs_path_candidate = str(p).strip().replace("/", "\\").lower()
        m_vp_vss = re.match(
            r"^(?:[\\/]*vss[_\-#]?(\d+)(?:[\\/]+|\s+)|\[vss[_\-#]?(\d+)\]\s*)(.+)$",
            vfs_path_candidate,
            flags=re.IGNORECASE,
        )
        effective_vss_idx: Optional[int] = vss_idx
        if effective_vss_idx is None and m_vp_vss:
            effective_vss_idx = int(m_vp_vss.group(1) or m_vp_vss.group(2))

        rel_candidates: List[str] = []
        if effective_vss_idx is not None:
            # VSS artifact: NEVER include non-VSS `inner_rel` (would steal active partition timestamps!)
            if raw_rel:
                r_low = raw_rel.strip("/").lower()
                if r_low:
                    rel_candidates.append(r_low)
                    rel_candidates.append(f"staging/{r_low}")
            if inner_rel:
                in_low = inner_rel.strip("/").lower()
                if in_low:
                    for vc in (
                        f"vss/vss_{effective_vss_idx}/{in_low}",
                        f"staging/vss/vss_{effective_vss_idx}/{in_low}",
                        f"vss_{effective_vss_idx}/{in_low}",
                        f"staging/vss_{effective_vss_idx}/{in_low}",
                    ):
                        if vc not in rel_candidates:
                            rel_candidates.append(vc)
        else:
            for c in (raw_rel, inner_rel):
                if c:
                    c_low = c.strip("/").lower()
                    if c_low and c_low not in rel_candidates:
                        rel_candidates.append(c_low)
                    with_stg = f"staging/{c_low}"
                    if with_stg not in rel_candidates:
                        rel_candidates.append(with_stg)

        vfs_cands: List[str] = []
        if effective_vss_idx is not None:
            # Only match VSS-prefixed vfs_path entries, NEVER bare active-volume vfs_path!
            if m_vp_vss:
                rest_vp = m_vp_vss.group(3).strip().lstrip("\\")
                rest_no_drv = re.sub(r"^[a-z]:\\", "", rest_vp, flags=re.IGNORECASE)
                for vpc in (
                    vfs_path_candidate,
                    f"\\vss_{effective_vss_idx}\\{rest_no_drv}",
                    f"vss_{effective_vss_idx}\\{rest_no_drv}",
                    f"vss#{effective_vss_idx}\\{rest_no_drv}",
                    f"[vss#{effective_vss_idx}] {rest_vp}",
                    f"[vss#{effective_vss_idx}] c:\\{rest_no_drv}",
                ):
                    if vpc and vpc not in vfs_cands:
                        vfs_cands.append(vpc)
        else:
            vfs_path_stripped = re.sub(r"^\[?vss#?\d+\]?\s*", "", vfs_path_candidate, flags=re.IGNORECASE)
            for vpc in (vfs_path_candidate, vfs_path_stripped):
                if vpc and vpc not in vfs_cands:
                    vfs_cands.append(vpc)

        return rel_candidates, vfs_cands

    def _query_vfs_timestamp_row(self, p: Path, col_keys: Tuple[str, ...]) -> Optional[Tuple[Any, ...]]:
        rel_candidates, vfs_cands = self._build_vfs_lookup_candidates(p)
        staged_cache = self._get_vfs_staged_cache()
        if staged_cache is not None:
            for rc in rel_candidates:
                hit = staged_cache.get(rc)
                if hit is not None:
                    return tuple(hit.get(ck) for ck in col_keys)
            if rel_candidates:
                return None
        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                has_vfs = (
                    cur.execute(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'vfs_files' LIMIT 1;"
                    ).fetchone()
                    is not None
                )
                if not has_vfs:
                    return None
                vfs_cols = {
                    str(r[0]).lower(): str(r[0])
                    for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                }
                ts_exprs = [
                    _quote_sql_ident(vfs_cols[col_key]) if col_key in vfs_cols else "NULL"
                    for col_key in col_keys
                ]
                where_clauses: List[str] = []
                params: List[Any] = []
                if rel_candidates and "staged_rel_path" in vfs_cols:
                    q_srp = _quote_sql_ident(vfs_cols["staged_rel_path"])
                    ph = ", ".join(["?"] * len(rel_candidates))
                    where_clauses.append(
                        f"LOWER(TRIM(BOTH '/' FROM REPLACE({q_srp}, chr(92), '/'))) IN ({ph})"
                    )
                    params.extend(rel_candidates)
                if "vfs_path" in vfs_cols and vfs_cands:
                    q_vp = _quote_sql_ident(vfs_cols["vfs_path"])
                    ph_v = ", ".join(["?"] * len(vfs_cands))
                    where_clauses.append(
                        f"LOWER(REPLACE({q_vp}, '/', chr(92))) IN ({ph_v})"
                    )
                    params.extend(vfs_cands)

                if not where_clauses:
                    return None
                ts_select_sql = ", ".join(ts_exprs)
                where_sql = " OR ".join(where_clauses)
                row = cur.execute(
                    f'SELECT {ts_select_sql} FROM "vfs_files" WHERE {where_sql} LIMIT 1;',
                    params,
                ).fetchone()
                return tuple(row) if row is not None else None
        except Exception:
            return None

    def get_original_mtime(self, file_path: Union[str, Path]) -> Optional[str]:
        r"""
        Returns the original forensic modification timestamp (`YYYY-MM-DD HH:MM:SS` UTC)
        for `file_path`, or `None` when unavailable:
        (a) Queries `vfs_files` (if present) by normalized `staged_rel_path` or `vfs_path`
            under `DuckDBManager.get_lock(self.case_id)` with strict VSS isolation.
            - Checks `(si_modified, fn_modified)` first, then `(si_created, fn_created)` ONLY when
              the creation timestamp does NOT reflect host staging wall-clock copy time.
            - If a matching row exists and all valid source timestamps are NULL/wall-clock:
              returns `None` IMMEDIATELY (never falls back to `stat()`!).
        (b) Only when `vfs_files` does not exist or has NO matching row:
            - Inspects `Path(file_path).stat()`, rejecting host staging wall-clock copy time
              and NEVER returning `st_ctime` or fabricating `datetime.now()`!
        """
        p = Path(file_path)
        now_ts = time.time()
        src_type = self._detect_source_type()
        is_explicit_non_image = src_type in ("folder", "directory", "live", "live_triage")
        is_image = src_type in ("image", "disk_image", "e01", "raw", "vhd", "vhdx", "vmdk")

        row = self._query_vfs_timestamp_row(
            p,
            (
                "si_modified",
                "si_modified_utc",
                "fn_modified",
                "fn_modified_utc",
                "si_created",
                "si_created_utc",
                "fn_created",
                "fn_created_utc",
            ),
        )
        if row is not None:
            for ts_val in row[:4]:
                formatted, ts_epoch = _format_utc_timestamp_with_epoch(ts_val)
                if formatted is not None and ts_epoch is not None:
                    if is_image and self._is_staging_wallclock_epoch(ts_epoch, now_ts=now_ts):
                        continue
                    return formatted
            for ts_val in row[4:]:
                formatted, ts_epoch = _format_utc_timestamp_with_epoch(ts_val)
                if formatted is not None and ts_epoch is not None:
                    if self._is_staging_wallclock_epoch(ts_epoch, now_ts=now_ts):
                        continue
                    return formatted
            # Row exists in vfs_files and ALL valid source timestamps are NULL/rejected -> MUST return None!
            return None

        # Fallback ONLY when `vfs_files` does not exist or had NO matching row:
        try:
            if not p.exists():
                return None
            st = p.stat()
        except OSError:
            return None

        mtime = float(st.st_mtime)
        ctime = float(st.st_ctime)
        if mtime <= 0 or self._is_staging_wallclock_epoch(mtime, now_ts=now_ts):
            return None

        if is_explicit_non_image:
            return _format_utc_timestamp(mtime)

        if is_image:
            utime_preserved = abs(ctime - mtime) > 2.0
            return _format_utc_timestamp(mtime) if utime_preserved else None

        return _format_utc_timestamp(mtime)

    def get_original_ctime(self, file_path: Union[str, Path]) -> Optional[str]:
        r"""
        Returns the original forensic creation timestamp (`YYYY-MM-DD HH:MM:SS` UTC)
        for `file_path` from `vfs_files` (`si_created` / `fn_created`), or `None` when
        unavailable or when `si_created` / `fn_created` reflects host Windows NTFS staging
        wall-clock copy time (`shutil.copy2` `st_ctime = now()`).
        NEVER falls back to `Path(file_path).stat().st_ctime`.
        """
        p = Path(file_path)
        now_ts = time.time()
        row = self._query_vfs_timestamp_row(
            p,
            (
                "si_created",
                "si_created_utc",
                "fn_created",
                "fn_created_utc",
            ),
        )
        if row is not None:
            for ts_val in row:
                formatted, ts_epoch = _format_utc_timestamp_with_epoch(ts_val)
                if formatted is not None and ts_epoch is not None:
                    if self._is_staging_wallclock_epoch(ts_epoch, now_ts=now_ts):
                        continue
                    return formatted
        return None

    def parse(self) -> Dict[str, int]:
        self._log("Base parser parse() called", "INFO")
        return {}
