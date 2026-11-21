"""
Windows Forensic Toolkit (WFT) DFIR Suite - Cloud Storage Sync Parser
Extracts synced, deleted, and configured file metadata, cloud identifiers,
user accounts, sync logs, and UTC timestamps from:
1. Microsoft OneDrive:
   - SyncEngineDatabase.db (synced files, lastChange, fileStatus, parent folder reconstruction)
   - SafeDelete.db (deleted files, restoration records, deletion timestamps)
   - UTF-16LE / UTF-8 .dat & .ini configuration files in OneDrive/settings/
   - SyncDiagnostics.log telemetry into parsed_onedrive_logs
2. Google Drive:
   - DriveFS metadata_sqlite_db, legacy Backup & Sync snapshot.db, and sync_log.log
3. Dropbox:
   - info.json, nucleus.sqlite3, and unencrypted SQLite filecache.dbx / config.dbx / config.db / deleted.dbx
     (verified strictly via SQLite3 header — zero raw binary regex scraping on encrypted .dbx)
Populates parsed_cloud_files, parsed_onedrive_files, parsed_gdrive_files, parsed_dropbox_files,
and parsed_onedrive_logs safely under DuckDBManager.get_lock(case_id).
"""
from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser, copy_sqlite_with_wal


CLOUD_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_cloud_files (
    _row_id BIGINT,
    cloud_provider VARCHAR,
    account VARCHAR,
    local_path VARCHAR,
    cloud_path_or_id VARCHAR,
    file_size BIGINT,
    modified_time TIMESTAMP,
    status VARCHAR,
    source_file VARCHAR
);
"""

ONEDRIVE_FILES_DDL = """
CREATE TABLE IF NOT EXISTS parsed_onedrive_files (
    _row_id BIGINT,
    cloud_provider VARCHAR,
    account VARCHAR,
    local_path VARCHAR,
    cloud_path_or_id VARCHAR,
    file_size BIGINT,
    modified_time TIMESTAMP,
    status VARCHAR,
    source_file VARCHAR
);
"""

GDRIVE_FILES_DDL = """
CREATE TABLE IF NOT EXISTS parsed_gdrive_files (
    _row_id BIGINT,
    cloud_provider VARCHAR,
    account VARCHAR,
    local_path VARCHAR,
    cloud_path_or_id VARCHAR,
    file_size BIGINT,
    modified_time TIMESTAMP,
    status VARCHAR,
    source_file VARCHAR
);
"""

DROPBOX_FILES_DDL = """
CREATE TABLE IF NOT EXISTS parsed_dropbox_files (
    _row_id BIGINT,
    cloud_provider VARCHAR,
    account VARCHAR,
    local_path VARCHAR,
    cloud_path_or_id VARCHAR,
    file_size BIGINT,
    modified_time TIMESTAMP,
    status VARCHAR,
    source_file VARCHAR
);
"""

ONEDRIVE_LOGS_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_onedrive_logs (
    _row_id BIGINT,
    account_cid VARCHAR,
    account_tier VARCHAR,
    user_folder VARCHAR,
    last_sync_time TIMESTAMP,
    log_file VARCHAR
);
"""

_FILETIME_EPOCH_DIFF_TICKS = 116444736000000000
_WEBKIT_EPOCH_OFFSET_SEC = 11644473600
_SQLITE_MAGIC = b"SQLite format 3\x00"
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_WIN_PATH_RE = re.compile(r'([A-Za-z]:\\(?:[^<>:"/|?*\x00-\x1f\r\n]+\\)*[^<>:"/|?*\x00-\x1f\r\n]{1,220})')
_CID_HEX_RE = re.compile(r"\b([0-9a-fA-F]{16})\b")
_ISO_STR_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?\s*$",
    re.IGNORECASE,
)


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize any datetime to naive UTC so DuckDB TIMESTAMP never shifts by host timezone."""
    if dt is None:
        return None
    norm = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt
    if norm.year < 1980 or norm.year > 2100:
        return None
    return norm


def _any_epoch_to_naive_utc(val: Any) -> Optional[datetime]:
    """Convert Unix s/ms/us/ns, WebKit, Windows FILETIME, or ISO-8601 strings to naive UTC datetime."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, datetime):
        return _to_naive_utc(val)
    if isinstance(val, (bytes, bytearray)):
        val = bytes(val).decode("utf-8", errors="ignore")

    if isinstance(val, str):
        s = val.strip()
        if not s or s == "0":
            return None
        if re.match(r"^\d+$", s):
            return _any_epoch_to_naive_utc(int(s))
        if re.match(r"^\d+\.\d+$", s):
            try:
                return _any_epoch_to_naive_utc(float(s))
            except ValueError:
                return None
        m = _ISO_STR_RE.match(s)
        if m:
            d_part, t_part, frac_part, tz_part = m.group(1), m.group(2), m.group(3), m.group(4)
            iso_s = f"{d_part}T{t_part}"
            if frac_part:
                iso_s += f".{frac_part[:6]}"
            if tz_part:
                tz_u = tz_part.upper()
                if tz_u == "Z":
                    iso_s += "+00:00"
                elif len(tz_u) == 5 and tz_u[0] in "+-":
                    iso_s += f"{tz_u[:3]}:{tz_u[3:]}"
                else:
                    iso_s += tz_u
            try:
                return _to_naive_utc(datetime.fromisoformat(iso_s))
            except ValueError:
                pass
        try:
            return _to_naive_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
        except ValueError:
            return None

    if isinstance(val, int):
        if val <= 0:
            return None
        if 116_444_736_000_000_000 <= val <= 160_000_000_000_000_000:
            unix_100ns = val - _FILETIME_EPOCH_DIFF_TICKS
            sec, rem = divmod(unix_100ns, 10_000_000)
            if 315532800 <= sec <= 4102444800:
                return _to_naive_utc(datetime(1970, 1, 1) + timedelta(seconds=sec, microseconds=rem // 10))
            return None
        if val > 1_500_000_000_000_000_000:
            epoch_s = val / 1_000_000_000.0
        elif 11_644_473_600_000_000 <= val <= 16_000_000_000_000_000:
            epoch_s = (val / 1_000_000.0) - _WEBKIT_EPOCH_OFFSET_SEC
        elif val >= 100_000_000_000_000:
            epoch_s = val / 1_000_000.0
        elif val > 100_000_000_000:
            epoch_s = val / 1_000.0
        else:
            epoch_s = float(val)
        if 315532800 <= epoch_s <= 4102444800:
            return _to_naive_utc(datetime.fromtimestamp(epoch_s, tz=timezone.utc))
        return None

    if isinstance(val, float):
        if not math.isfinite(val) or val <= 0:
            return None
        if val > 1.5e18:
            epoch_s = val / 1e9
        elif 1.16e17 <= val <= 1.6e17:
            epoch_s = (val / 10_000_000.0) - _WEBKIT_EPOCH_OFFSET_SEC
        elif 1.16e16 <= val <= 1.6e16:
            epoch_s = (val / 1_000_000.0) - _WEBKIT_EPOCH_OFFSET_SEC
        elif val >= 1e14:
            epoch_s = val / 1_000_000.0
        elif val > 1e11:
            epoch_s = val / 1_000.0
        else:
            epoch_s = val
        if 315532800 <= epoch_s <= 4102444800:
            return _to_naive_utc(datetime.fromtimestamp(epoch_s, tz=timezone.utc))
    return None


def _decode_cloud_text(raw: bytes) -> str:
    """Decode UTF-16LE (with or without BOM), UTF-16BE, UTF-8-sig, or UTF-8 text safely."""
    if not raw:
        return ""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace").replace("\x00", "")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace").replace("\x00", "")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace").replace("\x00", "")
    if len(raw) >= 4:
        odd_sample = raw[1::2][:512]
        even_sample = raw[0::2][:512]
        odd_zero_ratio = sum(1 for b in odd_sample if b == 0) / max(1, len(odd_sample))
        even_zero_ratio = sum(1 for b in even_sample if b == 0) / max(1, len(even_sample))
        if odd_zero_ratio > 0.30 and even_zero_ratio < 0.15:
            even_len = (len(raw) // 2) * 2
            return raw[:even_len].decode("utf-16-le", errors="replace").replace("\x00", "")
        if even_zero_ratio > 0.30 and odd_zero_ratio < 0.15:
            even_len = (len(raw) // 2) * 2
            return raw[:even_len].decode("utf-16-be", errors="replace").replace("\x00", "")
    return raw.decode("utf-8", errors="replace").replace("\x00", "")


def _extract_hybrid_dat_strings(raw: bytes) -> List[str]:
    """
    Extract printable text runs from OneDrive binary/hybrid .dat files across BOTH
    UTF-16LE (aligned at even and odd byte offsets) and UTF-8/ASCII encodings.
    """
    if not raw:
        return []
    chunks: List[str] = []
    if raw.startswith(b"\xff\xfe"):
        even_len = ((len(raw) - 2) // 2) * 2
        chunks.append(raw[2 : 2 + even_len].decode("utf-16-le", errors="ignore"))
    elif len(raw) >= 8:
        odd_sample = raw[1::2][:256]
        if sum(1 for b in odd_sample if b == 0) / max(1, len(odd_sample)) > 0.40:
            even_len = (len(raw) // 2) * 2
            chunks.append(raw[:even_len].decode("utf-16-le", errors="ignore"))

    for m_u16 in re.finditer(rb"(?:[\x20-\x7e]\x00){4,260}", raw):
        chunks.append(m_u16.group(0).decode("utf-16-le", errors="ignore"))
    for m_u8 in re.finditer(rb"[\x20-\x7e]{4,260}", raw):
        chunks.append(m_u8.group(0).decode("utf-8", errors="ignore"))
    return chunks


def _has_sqlite_header(file_path: Path) -> bool:
    try:
        with open(file_path, "rb") as fh:
            return fh.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def _pick_priority_col(col_map: Dict[str, str], priorities: Iterable[str]) -> Optional[str]:
    for cand in priorities:
        if cand in col_map:
            return col_map[cand]
    return None


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None or isinstance(val, bool):
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        try:
            return int(float(val))
        except (ValueError, TypeError):
            return default


class CloudParser(BaseParser):
    """
    Parser for Cloud Storage synchronization engines (Microsoft OneDrive, Google Drive, Dropbox).
    Populates parsed_cloud_files, provider-split cloud tables, and parsed_onedrive_logs.
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
        self.email_re = _EMAIL_RE
        self._parse_init_ts = time.time()

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
        case_created_epoch: Optional[float] = getattr(self, "_cached_case_created_epoch", None)
        case_created_checked: bool = bool(getattr(self, "_case_created_checked", False))

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
                    if not effective_source_type:
                        m_row = cur.execute(
                            "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                        ).fetchone()
                        if m_row and m_row[0]:
                            effective_source_type = str(m_row[0]).strip().lower()
                    if not case_created_checked:
                        c_row = cur.execute(
                            "SELECT value FROM case_metadata WHERE LOWER(key) IN ('created_utc', 'created_at', 'case_created_utc') LIMIT 1;"
                        ).fetchone()
                        self._case_created_checked = True
                        if c_row and c_row[0]:
                            c_dt = _any_epoch_to_naive_utc(c_row[0])
                            if c_dt is not None:
                                case_created_epoch = c_dt.replace(tzinfo=timezone.utc).timestamp()
                                self._cached_case_created_epoch = case_created_epoch

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
                            if row[1] is None:
                                return None
                            return _any_epoch_to_naive_utc(row[1])
        except Exception:
            pass

        if effective_source_type in ("image", "disk_image", "disk", "e01", "ex01", "ewf", "raw", "dd", "img", "vhd", "vhdx", "vmdk", "iso"):
            return None

        try:
            st_mtime = float(p.stat().st_mtime)
            if st_mtime <= 0 or st_mtime >= (self._parse_init_ts - 120.0):
                return None
            wallclock_fn = getattr(self, "_is_staging_wallclock_epoch", None)
            if callable(wallclock_fn) and wallclock_fn(st_mtime):
                return None
            if case_created_epoch is not None and st_mtime >= (case_created_epoch - 120.0):
                return None
            try:
                stg_mtime = float(Path(self.staging_dir).stat().st_mtime)
                if stg_mtime >= (self._parse_init_ts - 3600.0) and abs(st_mtime - stg_mtime) <= 600.0:
                    return None
            except OSError:
                pass
            return _to_naive_utc(datetime.fromtimestamp(st_mtime, tz=timezone.utc))
        except OSError:
            return None

    def _dropbox_user_scope_key(self, file_path: Path) -> str:
        """Extract VSS + Windows user profile scope ('Users/<user>/...') to isolate multi-user Dropbox hints."""
        try:
            rel_norm = "/" + file_path.resolve().relative_to(self.staging_dir.resolve()).as_posix()
        except Exception:
            rel_norm = str(file_path).replace("\\", "/")
        vss_m = re.search(r"(?i)(?:^|/)vss/(vss[_\-#]?\d+)/", rel_norm)
        vss_prefix = f"{vss_m.group(1).lower()}:" if vss_m else ""
        m_users = re.search(
            r"(?i)(?:^|/)(?:users|userfiles|documents and settings)/([^/]+)/",
            rel_norm,
        )
        if m_users and m_users.group(1).lower() not in ("public", "default"):
            return f"{vss_prefix}{m_users.group(1).lower()}"
        return vss_prefix

    def _detect_provider_and_account(self, file_path: Path) -> Tuple[str, str]:
        """Infer canonical cloud provider and user/account identifier from staged relative path."""
        try:
            rel_path = file_path.resolve().relative_to(self.staging_dir.resolve())
            rel_norm = "/" + rel_path.as_posix()
            search_parts = rel_path.parts[:-1]
        except Exception:
            rel_norm = str(file_path).replace("\\", "/")
            search_parts = file_path.parts[:-1]

        path_lower = rel_norm.lower()
        if "onedrive" in path_lower:
            provider = "OneDrive"
        elif "dropbox" in path_lower:
            provider = "Dropbox"
        elif "drivefs" in path_lower or "google" in path_lower or "gdrive" in path_lower:
            provider = "GoogleDrive"
        else:
            provider = "OneDrive"

        m_users = re.search(r"(?i)(?:^|/)(?:users|userfiles)/([^/]+)/", rel_norm)
        if m_users and m_users.group(1).lower() not in ("public", "default"):
            return provider, m_users.group(1)

        skip_names = {
            "settings",
            "personal",
            "business1",
            "business2",
            "logs",
            "cloud",
            "onedrive",
            "googledrive",
            "drive",
            "drivefs",
            "dropbox",
            "safedelete",
            "instance",
            "local",
            "roaming",
            "appdata",
            "microsoft",
            "google",
            "staging",
            "enrichment",
            "sqlite",
            "user_default",
        }
        account = "Default"
        for part in reversed(search_parts):
            if part.lower() not in skip_names:
                account = part
                break
        return provider, account

    def _parse_onedrive_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """Parse OneDrive SyncEngineDatabase.db (including lastChange, fileStatus & parent folder hierarchy)."""
        if not _has_sqlite_header(db_path):
            return []
        provider, account = self._detect_provider_and_account(db_path)
        resolved_source = self.resolve_evidence_path(db_path)
        fallback_mtime = self._get_original_mtime_dt(db_path)
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

            # Build parent folder lookup map from folder tables (e.g. od_ClientFolder_Records)
            folder_parents: Dict[str, Tuple[str, str]] = {}
            for table in tables:
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}
                res_id_col = _pick_priority_col(col_map, ("resourceid", "itemid", "folderid", "id"))
                parent_id_col = _pick_priority_col(col_map, ("parentresourceid", "parentid", "parentitemid"))
                fname_col = _pick_priority_col(col_map, ("foldername", "itemname", "filename", "name"))
                if res_id_col and parent_id_col and fname_col and ("folder" in table.lower() or "dir" in table.lower()):
                    q_rid = res_id_col.replace('"', '""')
                    q_pid = parent_id_col.replace('"', '""')
                    q_fnm = fname_col.replace('"', '""')
                    try:
                        for rid, pid, fnm in cursor.execute(f'SELECT "{q_rid}", "{q_pid}", "{q_fnm}" FROM "{q_table}";'):
                            if rid and fnm:
                                folder_parents[str(rid)] = (str(pid or ""), str(fnm))
                    except sqlite3.DatabaseError:
                        pass

            def _reconstruct_parent_prefix(parent_id: str) -> str:
                parts: List[str] = []
                cur_id = parent_id
                visited: Set[str] = set()
                while cur_id and cur_id in folder_parents and cur_id not in visited and len(parts) < 24:
                    visited.add(cur_id)
                    next_pid, folder_name = folder_parents[cur_id]
                    if folder_name:
                        parts.append(folder_name)
                    cur_id = next_pid
                parts.reverse()
                return "\\".join(parts)

            for table in tables:
                t_low = table.lower()
                if t_low in ("meta", "metadata", "schema_version", "properties"):
                    continue
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}

                name_col = _pick_priority_col(
                    col_map,
                    ("localpath", "fullpath", "originalpath", "relativepath", "path", "filename", "itemname", "name"),
                )
                if not name_col:
                    continue

                id_col = _pick_priority_col(
                    col_map,
                    ("resourceid", "cloudid", "itemid", "fileid", "etag", "parentresourceid", "id"),
                )
                parent_col = _pick_priority_col(col_map, ("parentresourceid", "parentid", "parentitemid"))
                size_col = _pick_priority_col(col_map, ("filesize", "size", "contentlength", "bytes"))
                time_col = _pick_priority_col(
                    col_map,
                    ("lastchange", "lastchangetime", "lastmodifiedtime", "lastmodified", "modifiedtime", "mtime", "timestamp"),
                )
                status_col = _pick_priority_col(
                    col_map,
                    ("filestatus", "syncstate", "filestate", "status", "state"),
                )

                qn = name_col.replace('"', '""')
                id_expr = f'"{id_col.replace(chr(34), chr(34)*2)}"' if id_col else "''"
                p_expr = f'"{parent_col.replace(chr(34), chr(34)*2)}"' if parent_col else "''"
                sz_expr = f'"{size_col.replace(chr(34), chr(34)*2)}"' if size_col else "0"
                tm_expr = f'"{time_col.replace(chr(34), chr(34)*2)}"' if time_col else "NULL"
                st_expr = f'"{status_col.replace(chr(34), chr(34)*2)}"' if status_col else "'SYNCED'"

                q = (
                    f'SELECT "{qn}", {id_expr}, {p_expr}, {sz_expr}, {tm_expr}, {st_expr} '
                    f'FROM "{q_table}" WHERE "{qn}" IS NOT NULL AND length(trim(CAST("{qn}" AS TEXT))) > 0;'
                )
                for fname, cid, parent_id, fsize, raw_mtime, raw_status in cursor.execute(q):
                    raw_path = str(fname).strip()
                    if not raw_path:
                        continue
                    if parent_id and "\\" not in raw_path and "/" not in raw_path and folder_parents:
                        prefix = _reconstruct_parent_prefix(str(parent_id))
                        if prefix:
                            raw_path = f"{prefix}\\{raw_path}"

                    mtime_dt = _any_epoch_to_naive_utc(raw_mtime) or fallback_mtime
                    status_str = str(raw_status).strip() if raw_status is not None and str(raw_status).strip() else "SYNCED"
                    records.append({
                        "cloud_provider": provider,
                        "account": account,
                        "local_path": raw_path,
                        "cloud_path_or_id": str(cid or ""),
                        "file_size": _safe_int(fsize, 0),
                        "modified_time": mtime_dt,
                        "status": status_str,
                        "source_file": resolved_source,
                    })
        except sqlite3.DatabaseError as ex:
            self._log(f"OneDrive SQLite notice on {db_path.name}: {ex}", "DEBUG")
        finally:
            conn.close()

        return records

    def _parse_onedrive_safedelete_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """Parse OneDrive SafeDelete.db SQLite file for deleted files and deletion timestamps."""
        if not _has_sqlite_header(db_path):
            return []
        provider, account = self._detect_provider_and_account(db_path)
        resolved_source = self.resolve_evidence_path(db_path)
        fallback_mtime = self._get_original_mtime_dt(db_path)
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
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}

                path_col = _pick_priority_col(
                    col_map,
                    ("localpath", "originalpath", "fullpath", "relativepath", "path", "filename", "itemname", "name"),
                )
                if not path_col:
                    continue
                id_col = _pick_priority_col(col_map, ("resourceid", "itemid", "fileid", "id"))
                size_col = _pick_priority_col(col_map, ("filesize", "size", "bytes"))
                time_col = _pick_priority_col(
                    col_map,
                    ("deletiontime", "deletedtime", "deletedat", "timestamp", "lastchange", "modifiedtime", "lastmodified"),
                )

                qp = path_col.replace('"', '""')
                id_expr = f'"{id_col.replace(chr(34), chr(34)*2)}"' if id_col else "''"
                sz_expr = f'"{size_col.replace(chr(34), chr(34)*2)}"' if size_col else "0"
                tm_expr = f'"{time_col.replace(chr(34), chr(34)*2)}"' if time_col else "NULL"

                q = (
                    f'SELECT "{qp}", {id_expr}, {sz_expr}, {tm_expr} '
                    f'FROM "{q_table}" WHERE "{qp}" IS NOT NULL AND length(trim(CAST("{qp}" AS TEXT))) > 0;'
                )
                for lpath, cid, fsize, dtime in cursor.execute(q):
                    dtime_dt = _any_epoch_to_naive_utc(dtime) or fallback_mtime
                    records.append({
                        "cloud_provider": provider,
                        "account": account,
                        "local_path": str(lpath).strip(),
                        "cloud_path_or_id": str(cid or "SafeDelete"),
                        "file_size": _safe_int(fsize, 0),
                        "modified_time": dtime_dt,
                        "status": "SAFEDELETE",
                        "source_file": resolved_source,
                    })
        except sqlite3.DatabaseError as ex:
            self._log(f"SafeDelete SQLite notice on {db_path.name}: {ex}", "DEBUG")
        finally:
            conn.close()

        return records

    def _parse_onedrive_ini(
        self,
        ini_path: Path,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse UTF-16LE / UTF-8 OneDrive .ini config files into cloud records and OneDrive log summaries."""
        provider, fallback_account = self._detect_provider_and_account(ini_path)
        resolved_source = self.resolve_evidence_path(ini_path)
        records: List[Dict[str, Any]] = []
        log_rows: List[Dict[str, Any]] = []

        try:
            raw = ini_path.read_bytes()
            text = _decode_cloud_text(raw)
            if not text.strip():
                return [], []

            path_low = str(ini_path).lower()
            tier = "Business" if "business" in ini_path.stem.lower() or "business" in path_low else "Personal"

            # Extract quoted paths (e.g. libraryScope = 1 ... "C:\Users\Alice\OneDrive") and unquoted folder settings
            quoted_folders = re.findall(
                r'(?im)^\s*(?:libraryScope|libraryFolder|library|UserFolder|Folder)\b[^\r\n"]*"([A-Za-z]:\\[^"\r\n]+)"',
                text,
            )
            unquoted_folders = re.findall(
                r'(?im)^\s*(?:UserFolder|Folder|Path|LibraryScope)\s*=\s*([A-Za-z]:\\[^\r\n"]+)',
                text,
            )
            folders: List[str] = []
            for fld in quoted_folders + unquoted_folders:
                clean_fld = fld.strip().strip('"')
                if clean_fld and clean_fld not in folders:
                    folders.append(clean_fld)

            kv_user = re.findall(
                r"(?im)^\s*(?:UserEmail|Email|AccountEmail|UserName|UserCID|cid)\s*=\s*([^\r\n;]+)",
                text,
            )
            emails = self.email_re.findall(text)
            cid_match = _CID_HEX_RE.search(ini_path.stem) or _CID_HEX_RE.search(text)
            account_cid = cid_match.group(1) if cid_match else ""

            detected_account = (
                (emails[0] if emails else "")
                or (kv_user[0].strip().strip('"') if kv_user else "")
                or account_cid
            )

            # Look for embedded sync epoch timestamps in INI
            ts_matches = re.findall(
                r"(?im)^\s*(?:LastSyncTime|LastUpdate|RelationshipLastSyncTime|SyncTimestamp)\s*=\s*([^\r\n;]+)",
                text,
            )
            sync_dt = (_any_epoch_to_naive_utc(ts_matches[0].strip()) if ts_matches else None) or self._get_original_mtime_dt(ini_path)

            if not folders and not detected_account:
                return [], []

            final_account = detected_account or fallback_account
            for fld in folders:
                records.append({
                    "cloud_provider": provider,
                    "account": final_account,
                    "local_path": fld,
                    "cloud_path_or_id": account_cid or ini_path.stem,
                    "file_size": 0,
                    "modified_time": sync_dt,
                    "status": "CONFIGURED",
                    "source_file": resolved_source,
                })

            if folders or account_cid or emails:
                log_rows.append({
                    "account_cid": account_cid or final_account,
                    "account_tier": tier,
                    "user_folder": folders[0] if folders else "",
                    "last_sync_time": sync_dt,
                    "log_file": resolved_source,
                })
        except Exception as ex:
            self._log(f"Error reading OneDrive INI {ini_path.name}: {ex}", "DEBUG")

        return records, log_rows

    def _parse_onedrive_dat(
        self,
        dat_path: Path,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse UTF-16LE / hybrid binary OneDrive <cid>.dat files for account emails and sync roots."""
        provider, fallback_account = self._detect_provider_and_account(dat_path)
        resolved_source = self.resolve_evidence_path(dat_path)
        records: List[Dict[str, Any]] = []
        log_rows: List[Dict[str, Any]] = []

        try:
            raw = dat_path.read_bytes()
            if not raw:
                return [], []
            mtime_dt = self._get_original_mtime_dt(dat_path)
            path_low = str(dat_path).lower()
            tier = "Business" if "business" in dat_path.stem.lower() or "business" in path_low else "Personal"

            extracted_chunks = _extract_hybrid_dat_strings(raw)
            joined = "\n".join(extracted_chunks)

            emails = self.email_re.findall(joined)
            cid_m = _CID_HEX_RE.search(dat_path.stem) or _CID_HEX_RE.search(joined)
            cid_val = cid_m.group(1) if cid_m else dat_path.stem
            detected_account = emails[0] if emails else (cid_val or fallback_account)

            found_paths: List[str] = []
            for chunk in extracted_chunks:
                for pm in _WIN_PATH_RE.finditer(chunk):
                    cand_p = pm.group(1).strip().rstrip("\\/. ")
                    if len(cand_p) >= 5 and cand_p not in found_paths:
                        found_paths.append(cand_p)

            for fp in found_paths:
                records.append({
                    "cloud_provider": provider,
                    "account": detected_account,
                    "local_path": fp,
                    "cloud_path_or_id": cid_val,
                    "file_size": 0,
                    "modified_time": mtime_dt,
                    "status": "CONFIGURED",
                    "source_file": resolved_source,
                })

            if emails or found_paths:
                log_rows.append({
                    "account_cid": detected_account,
                    "account_tier": tier,
                    "user_folder": found_paths[0] if found_paths else "",
                    "last_sync_time": mtime_dt,
                    "log_file": resolved_source,
                })
        except Exception as ex:
            self._log(f"Error reading OneDrive DAT {dat_path}: {ex}", "WARNING")

        return records, log_rows

    def _parse_onedrive_sync_diagnostics(
        self,
        log_path: Path,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Parse OneDrive SyncDiagnostics.log (UTF-8 / UTF-16LE) into parsed_onedrive_logs and parsed_cloud_files."""
        provider, fallback_account = self._detect_provider_and_account(log_path)
        resolved_source = self.resolve_evidence_path(log_path)
        records: List[Dict[str, Any]] = []
        log_rows: List[Dict[str, Any]] = []

        try:
            text = _decode_cloud_text(log_path.read_bytes())
            if not text.strip():
                return [], []

            kv: Dict[str, str] = {}
            for m in re.finditer(r"(?im)^\s*([A-Za-z0-9_.\-]+)\s*[:=]\s*(.+?)\s*$", text):
                kv[m.group(1).strip().lower()] = m.group(2).strip().strip('"')

            path_low = str(log_path).lower()
            acct_type = kv.get("accounttype") or ("Business" if "business" in path_low else "Personal")
            emails = self.email_re.findall(text)
            cid_val = (
                kv.get("cid")
                or kv.get("usercid")
                or kv.get("accountcid")
                or (emails[0] if emails else "")
                or fallback_account
            )
            user_folder = kv.get("userfolder") or kv.get("localpath") or kv.get("syncroot") or ""
            if not user_folder:
                p_matches = _WIN_PATH_RE.findall(text)
                if p_matches:
                    user_folder = p_matches[0].strip()

            sync_dt = (
                _any_epoch_to_naive_utc(kv.get("lastsynctime"))
                or _any_epoch_to_naive_utc(kv.get("utcnow"))
                or _any_epoch_to_naive_utc(kv.get("timestamp"))
                or self._get_original_mtime_dt(log_path)
            )

            log_rows.append({
                "account_cid": cid_val,
                "account_tier": acct_type,
                "user_folder": user_folder,
                "last_sync_time": sync_dt,
                "log_file": resolved_source,
            })

            if user_folder:
                progress_state = kv.get("syncprogressstate")
                status_val = f"SYNC_LOG ({progress_state})" if progress_state else "SYNC_LOG"
                records.append({
                    "cloud_provider": provider,
                    "account": emails[0] if emails else cid_val,
                    "local_path": user_folder,
                    "cloud_path_or_id": cid_val,
                    "file_size": 0,
                    "modified_time": sync_dt,
                    "status": status_val,
                    "source_file": resolved_source,
                })
        except Exception as ex:
            self._log(f"Error parsing SyncDiagnostics.log {log_path}: {ex}", "DEBUG")

        return records, log_rows

    def _parse_gdrive_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """Parse Google Drive DriveFS metadata_sqlite_db and legacy Backup & Sync snapshot.db."""
        if not _has_sqlite_header(db_path):
            return []
        _, account = self._detect_provider_and_account(db_path)
        provider = "GoogleDrive"
        resolved_source = self.resolve_evidence_path(db_path)
        fallback_mtime = self._get_original_mtime_dt(db_path)
        temp_db = copy_sqlite_with_wal(db_path, temp_dir)
        records: List[Dict[str, Any]] = []

        conn = sqlite3.connect(str(temp_db))
        try:
            cursor = conn.cursor()
            table_map = {
                str(r[0]).lower(): str(r[0])
                for r in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            }

            handled_tables: Set[str] = set()

            # 1. Dedicated snapshot.db join (cloud_entry + local_entry via mapping)
            if "cloud_entry" in table_map:
                ce_tbl = table_map["cloud_entry"].replace('"', '""')
                ce_cols = {str(c[1]).lower(): str(c[1]) for c in cursor.execute(f'PRAGMA table_info("{ce_tbl}");').fetchall()}
                if "filename" in ce_cols and "doc_id" in ce_cols:
                    handled_tables.add("cloud_entry")
                    fn_c = ce_cols["filename"].replace('"', '""')
                    id_c = ce_cols["doc_id"].replace('"', '""')
                    sz_c = f'"{ce_cols["size"].replace(chr(34), chr(34)*2)}"' if "size" in ce_cols else "0"
                    md_c = f'"{ce_cols["modified"].replace(chr(34), chr(34)*2)}"' if "modified" in ce_cols else "NULL"
                    rm_c = f'"{ce_cols["removed"].replace(chr(34), chr(34)*2)}"' if "removed" in ce_cols else "0"
                    for fname, doc_id, sz, mod, rem in cursor.execute(
                        f'SELECT "{fn_c}", "{id_c}", {sz_c}, {md_c}, {rm_c} FROM "{ce_tbl}" WHERE "{fn_c}" IS NOT NULL;'
                    ):
                        records.append({
                            "cloud_provider": provider,
                            "account": account,
                            "local_path": str(fname).strip(),
                            "cloud_path_or_id": str(doc_id or ""),
                            "file_size": _safe_int(sz, 0),
                            "modified_time": _any_epoch_to_naive_utc(mod) or fallback_mtime,
                            "status": "DELETED" if _safe_int(rem, 0) else "SYNCED",
                            "source_file": resolved_source,
                        })
                    if "local_entry" in table_map:
                        handled_tables.add("local_entry")

            # 2. DriveFS items & generic priority-ordered table introspection
            for t_low, table in table_map.items():
                if t_low in handled_tables or t_low in ("mapping", "relations", "volume_info", "meta", "properties"):
                    continue
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}

                title_col = _pick_priority_col(
                    col_map,
                    ("local_title", "filename", "title", "original_title", "local_path", "path", "name"),
                )
                if not title_col:
                    continue

                id_col = _pick_priority_col(col_map, ("cloud_id", "stable_id", "doc_id", "item_id", "id"))
                size_col = _pick_priority_col(col_map, ("file_size", "size", "bytes"))
                time_col = _pick_priority_col(
                    col_map,
                    ("modified_date", "modified_time", "modified", "mtime", "viewed_by_me_date", "timestamp"),
                )
                trashed_col = _pick_priority_col(col_map, ("trashed", "is_trashed", "removed", "deleted"))

                qt = title_col.replace('"', '""')
                id_expr = f'"{id_col.replace(chr(34), chr(34)*2)}"' if id_col else "''"
                sz_expr = f'"{size_col.replace(chr(34), chr(34)*2)}"' if size_col else "0"
                tm_expr = f'"{time_col.replace(chr(34), chr(34)*2)}"' if time_col else "NULL"
                tr_expr = f'"{trashed_col.replace(chr(34), chr(34)*2)}"' if trashed_col else "0"

                q = (
                    f'SELECT "{qt}", {id_expr}, {sz_expr}, {tm_expr}, {tr_expr} '
                    f'FROM "{q_table}" WHERE "{qt}" IS NOT NULL AND length(trim(CAST("{qt}" AS TEXT))) > 0;'
                )
                for title, cid, fsize, mtime, trashed in cursor.execute(q):
                    status = "TRASHED" if _safe_int(trashed, 0) else "SYNCED"
                    records.append({
                        "cloud_provider": provider,
                        "account": account,
                        "local_path": str(title).strip(),
                        "cloud_path_or_id": str(cid or ""),
                        "file_size": _safe_int(fsize, 0),
                        "modified_time": _any_epoch_to_naive_utc(mtime) or fallback_mtime,
                        "status": status,
                        "source_file": resolved_source,
                    })
        except sqlite3.DatabaseError as ex:
            self._log(f"Google Drive SQLite notice on {db_path.name}: {ex}", "DEBUG")
        finally:
            conn.close()

        return records

    def _parse_gdrive_sync_log(
        self,
        log_path: Path,
        seen_norm_paths: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Parse Google Drive sync_log.log timestamped file activity lines (zero hardcoded accounts)."""
        _, fallback_account = self._detect_provider_and_account(log_path)
        resolved_source = self.resolve_evidence_path(log_path)
        records: List[Dict[str, Any]] = []

        try:
            text = _decode_cloud_text(log_path.read_bytes())
            if not text.strip():
                return []
            emails = self.email_re.findall(text)
            account = emails[0] if emails else fallback_account
            line_re = re.compile(
                r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?)\s+(.*)$"
            )
            quoted_path_re = re.compile(
                r"(?:u'|')([A-Za-z]:\\\\[^'\r\n]+|\\\\\?\\[A-Za-z]:\\[^'\r\n]+|\\\\\\\\\?\\\\[A-Za-z]:\\\\[^'\r\n]+|[A-Za-z]:\\[^'\r\n]+)(?:')"
            )
            eff_seen_paths: Set[str] = seen_norm_paths if seen_norm_paths is not None else set()

            for line in text.splitlines():
                m = line_re.match(line.strip())
                if not m:
                    continue
                ts_dt = _any_epoch_to_naive_utc(m.group(1))
                rest = m.group(2)
                q_match = quoted_path_re.search(rest)
                if q_match:
                    raw_fp = q_match.group(1)
                else:
                    p_match = _WIN_PATH_RE.search(rest)
                    if not p_match:
                        continue
                    raw_fp = p_match.group(1).strip().rstrip("'\",;)")
                fpath = re.sub(
                    r"\\+",
                    r"\\",
                    raw_fp.replace("\\\\\\\\?\\\\", "").replace("\\\\?\\", ""),
                ).strip()
                fname = Path(fpath.replace("\\", "/")).name
                if not fname or fname.lower() in ("google drive", "my drive", "desktop.ini"):
                    continue
                norm_key = fpath.lower()
                if norm_key in eff_seen_paths:
                    continue
                eff_seen_paths.add(norm_key)
                rest_low = rest.lower()
                if "delete" in rest_low or "remove" in rest_low or "trash" in rest_low:
                    status = "DELETED"
                elif "create" in rest_low or "upload" in rest_low:
                    status = "UPLOADED"
                elif "download" in rest_low:
                    status = "DOWNLOADED"
                else:
                    status = "SYNCED"

                records.append({
                    "cloud_provider": "GoogleDrive",
                    "account": account,
                    "local_path": fpath,
                    "cloud_path_or_id": fname,
                    "file_size": 0,
                    "modified_time": ts_dt,
                    "status": status,
                    "source_file": resolved_source,
                })
        except Exception as ex:
            self._log(f"Error parsing Google Drive sync_log.log {log_path}: {ex}", "DEBUG")

        return records

    def _parse_dropbox_info_json(
        self,
        file_path: Path,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Parse Dropbox info.json and return (records, discovered_account_email_or_host)."""
        records: List[Dict[str, Any]] = []
        discovered_account: Optional[str] = None
        resolved_source = self.resolve_evidence_path(file_path)
        mtime_dt = self._get_original_mtime_dt(file_path)

        try:
            text = _decode_cloud_text(file_path.read_bytes())
            data = json.loads(text)
            if not isinstance(data, dict):
                return [], None
            for acct_type, info in data.items():
                if not isinstance(info, dict):
                    continue
                if not any(k in info for k in ("path", "host", "email", "subscription_type")):
                    continue
                acct = str(info.get("email") or info.get("host") or acct_type).strip()
                if info.get("email") and not discovered_account:
                    discovered_account = str(info["email"]).strip()
                elif acct and not discovered_account:
                    discovered_account = acct
                local_p = str(info.get("path") or "").strip()
                if local_p or acct:
                    records.append({
                        "cloud_provider": "Dropbox",
                        "account": acct,
                        "local_path": local_p,
                        "cloud_path_or_id": f"Dropbox ({acct_type})",
                        "file_size": 0,
                        "modified_time": mtime_dt,
                        "status": "CONFIGURED",
                        "source_file": resolved_source,
                    })
        except Exception as ex:
            self._log(f"Dropbox info.json parse notice on {file_path.name}: {ex}", "DEBUG")

        return records, discovered_account

    def _parse_dropbox_sqlite(
        self,
        db_path: Path,
        temp_dir: Path,
        known_account: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Parse unencrypted Dropbox SQLite databases (nucleus.sqlite3, filecache.dbx, config.dbx, config.db, deleted.dbx).
        Verifies SQLite3 magic header first — NEVER runs raw binary regex scraping on encrypted .dbx files!
        """
        if not _has_sqlite_header(db_path):
            self._log(
                f"Skipping encrypted or non-SQLite Dropbox file {db_path.name} (strict zero-FP mode)",
                "INFO",
            )
            return [], known_account

        _, fallback_acct = self._detect_provider_and_account(db_path)
        account = known_account or fallback_acct
        resolved_source = self.resolve_evidence_path(db_path)
        fallback_mtime = self._get_original_mtime_dt(db_path)
        temp_db = copy_sqlite_with_wal(db_path, temp_dir)
        records: List[Dict[str, Any]] = []
        discovered_email: Optional[str] = known_account

        conn = sqlite3.connect(str(temp_db))
        try:
            cursor = conn.cursor()
            tables = [
                str(r[0])
                for r in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            ]

            # Pass 1: inspect config / kv tables for email & dropbox_path
            for table in tables:
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}
                if "key" in col_map and "value" in col_map:
                    qk = col_map["key"].replace('"', '""')
                    qv = col_map["value"].replace('"', '""')
                    cfg_kv: Dict[str, str] = {}
                    for k_raw, v_raw in cursor.execute(f'SELECT "{qk}", "{qv}" FROM "{q_table}";'):
                        if k_raw is not None and v_raw is not None:
                            v_str = (
                                bytes(v_raw).decode("utf-8", errors="ignore")
                                if isinstance(v_raw, (bytes, bytearray))
                                else str(v_raw)
                            )
                            cfg_kv[str(k_raw).strip().lower()] = v_str.strip().strip('"')
                    for ek in ("email", "user_email", "account_email"):
                        if cfg_kv.get(ek):
                            discovered_email = cfg_kv[ek]
                            account = discovered_email
                            break
                    for pk in ("dropbox_path", "root_path", "local_path"):
                        if cfg_kv.get(pk):
                            records.append({
                                "cloud_provider": "Dropbox",
                                "account": account,
                                "local_path": cfg_kv[pk],
                                "cloud_path_or_id": "Dropbox Root",
                                "file_size": 0,
                                "modified_time": fallback_mtime,
                                "status": "CONFIGURED",
                                "source_file": resolved_source,
                            })

            # Pass 2: inspect file journal / sync history / cache tables
            is_deleted_db = "deleted" in db_path.name.lower()
            for table in tables:
                t_low = table.lower()
                if t_low in ("config", "config_table", "meta", "metadata", "schema_version"):
                    continue
                q_table = table.replace('"', '""')
                cols_info = cursor.execute(f'PRAGMA table_info("{q_table}");').fetchall()
                col_map = {str(c[1]).lower(): str(c[1]) for c in cols_info}
                if "key" in col_map and "value" in col_map and len(col_map) == 2:
                    continue

                path_col = _pick_priority_col(
                    col_map,
                    (
                        "local_path",
                        "server_path",
                        "display_path",
                        "lower_path",
                        "target_path",
                        "local_filename",
                        "filename",
                        "path",
                        "name",
                    ),
                )
                if not path_col:
                    continue

                id_col = _pick_priority_col(
                    col_map,
                    ("sjid", "file_obj_id", "ns_id", "cloud_id", "rev", "id", "hash", "blocklist"),
                )
                size_col = _pick_priority_col(col_map, ("size", "file_size", "bytes", "total_size"))
                time_col = _pick_priority_col(
                    col_map,
                    (
                        "mtime",
                        "modified_time",
                        "server_mtime",
                        "local_mtime",
                        "timestamp",
                        "updated_at",
                        "deleted_time",
                        "time",
                    ),
                )
                status_col = _pick_priority_col(
                    col_map,
                    ("status", "sync_status", "action", "event_type"),
                )
                del_flag_col = _pick_priority_col(col_map, ("is_deleted", "deleted"))

                qp = path_col.replace('"', '""')
                id_expr = f'"{id_col.replace(chr(34), chr(34)*2)}"' if id_col else "''"
                sz_expr = f'"{size_col.replace(chr(34), chr(34)*2)}"' if size_col else "0"
                tm_expr = f'"{time_col.replace(chr(34), chr(34)*2)}"' if time_col else "NULL"
                st_expr = f'"{status_col.replace(chr(34), chr(34)*2)}"' if status_col else "NULL"
                dl_expr = f'"{del_flag_col.replace(chr(34), chr(34)*2)}"' if del_flag_col else "0"

                q = (
                    f'SELECT "{qp}", {id_expr}, {sz_expr}, {tm_expr}, {st_expr}, {dl_expr} '
                    f'FROM "{q_table}" WHERE "{qp}" IS NOT NULL AND length(trim(CAST("{qp}" AS TEXT))) > 0;'
                )
                for p_val, cid_val, sz_val, tm_val, st_val, dl_val in cursor.execute(q):
                    p_str = str(p_val).strip()
                    if not p_str:
                        continue
                    if is_deleted_db or "deleted" in t_low or _safe_int(dl_val, 0) == 1:
                        final_status = "DELETED"
                    elif st_val is not None and str(st_val).strip():
                        final_status = str(st_val).strip().upper()
                    else:
                        final_status = "SYNCED"

                    records.append({
                        "cloud_provider": "Dropbox",
                        "account": account,
                        "local_path": p_str,
                        "cloud_path_or_id": str(cid_val if cid_val is not None else Path(p_str).name),
                        "file_size": _safe_int(sz_val, 0),
                        "modified_time": _any_epoch_to_naive_utc(tm_val) or fallback_mtime,
                        "status": final_status,
                        "source_file": resolved_source,
                    })
        except sqlite3.DatabaseError as ex:
            self._log(f"Skipping unreadable Dropbox DB {db_path.name}: {ex}", "INFO")
        finally:
            conn.close()

        return records, discovered_email

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for cloud storage metadata (OneDrive, Google Drive, Dropbox)
        and ingest into parsed_cloud_files, provider-split tables, and parsed_onedrive_logs.
        """
        start_time = time.time()
        self._log(f"Starting Cloud parser across staging directory: {self.staging_dir}")

        all_records: List[Dict[str, Any]] = []
        onedrive_log_records: List[Dict[str, Any]] = []

        candidate_onedrive_db: List[Path] = []
        candidate_safedelete_db: List[Path] = []
        candidate_onedrive_dat: List[Path] = []
        candidate_onedrive_ini: List[Path] = []
        candidate_onedrive_diag: List[Path] = []
        candidate_gdrive_db: List[Path] = []
        candidate_gdrive_log: List[Path] = []
        candidate_dropbox_info: List[Path] = []
        candidate_dropbox_db: List[Path] = []

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

                if any(name_lower.endswith(sfx) for sfx in ("-wal", "-shm", "-journal")):
                    continue

                if "safedelete" in name_lower and name_lower.endswith((".db", ".sqlite", ".sqlite3")):
                    candidate_safedelete_db.append(p)
                elif name_lower == "nucleus.sqlite3" or (
                    "dropbox" in path_lower
                    and (
                        name_lower in ("filecache.dbx", "config.dbx", "config.db", "deleted.dbx")
                        or name_lower.endswith((".sqlite3", ".sqlite", ".dbx", ".db"))
                    )
                ):
                    candidate_dropbox_db.append(p)
                elif name_lower == "info.json" and ("dropbox" in path_lower or "cloud" in path_lower):
                    candidate_dropbox_info.append(p)
                elif "syncenginedatabase" in name_lower or (
                    name_lower.endswith((".db", ".sqlite", ".sqlite3")) and "onedrive" in path_lower
                ):
                    candidate_onedrive_db.append(p)
                elif "syncdiagnostics" in name_lower and name_lower.endswith(".log"):
                    candidate_onedrive_diag.append(p)
                elif name_lower.endswith(".ini") and "onedrive" in path_lower:
                    candidate_onedrive_ini.append(p)
                elif name_lower.endswith(".dat") and "onedrive" in path_lower:
                    candidate_onedrive_dat.append(p)
                elif (
                    "metadata_sqlite_db" in name_lower
                    or name_lower == "snapshot.db"
                    or (
                        name_lower.endswith((".db", ".sqlite", ".sqlite3"))
                        and any(k in path_lower for k in ("drivefs", "google", "gdrive"))
                    )
                ):
                    candidate_gdrive_db.append(p)
                elif (name_lower == "sync_log.log" or name_lower.startswith("sync_log.log.")):
                    candidate_gdrive_log.append(p)

        self._log(
            f"Found {len(candidate_onedrive_db)} OneDrive DBs, {len(candidate_safedelete_db)} SafeDelete DBs, "
            f"{len(candidate_onedrive_ini)} INIs, {len(candidate_onedrive_dat)} DATs, "
            f"{len(candidate_onedrive_diag)} SyncDiagnostics logs, {len(candidate_gdrive_db)} Google Drive DBs, "
            f"{len(candidate_gdrive_log)} Google Drive logs, and "
            f"{len(candidate_dropbox_info) + len(candidate_dropbox_db)} Dropbox files."
        )

        with tempfile.TemporaryDirectory(prefix="wft_cloud_") as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            for idx, odb in enumerate(candidate_onedrive_db):
                try:
                    sub_temp = temp_dir / f"od_{idx}_{uuid.uuid4().hex[:8]}"
                    all_records.extend(self._parse_onedrive_sqlite(odb, sub_temp))
                except Exception as ex:
                    self._log(f"Error parsing OneDrive DB {odb}: {ex}", "WARNING")

            for idx, sdb in enumerate(candidate_safedelete_db):
                try:
                    sub_temp = temp_dir / f"sd_{idx}_{uuid.uuid4().hex[:8]}"
                    all_records.extend(self._parse_onedrive_safedelete_sqlite(sdb, sub_temp))
                except Exception as ex:
                    self._log(f"Error parsing SafeDelete DB {sdb}: {ex}", "WARNING")

            for inif in candidate_onedrive_ini:
                try:
                    recs, logs = self._parse_onedrive_ini(inif)
                    all_records.extend(recs)
                    onedrive_log_records.extend(logs)
                except Exception as ex:
                    self._log(f"Error parsing OneDrive INI {inif}: {ex}", "WARNING")

            for dat in candidate_onedrive_dat:
                try:
                    recs, logs = self._parse_onedrive_dat(dat)
                    all_records.extend(recs)
                    onedrive_log_records.extend(logs)
                except Exception as ex:
                    self._log(f"Error parsing OneDrive DAT {dat}: {ex}", "WARNING")

            for diag in candidate_onedrive_diag:
                try:
                    recs, logs = self._parse_onedrive_sync_diagnostics(diag)
                    all_records.extend(recs)
                    onedrive_log_records.extend(logs)
                except Exception as ex:
                    self._log(f"Error parsing SyncDiagnostics.log {diag}: {ex}", "WARNING")

            for idx, gdb in enumerate(candidate_gdrive_db):
                try:
                    sub_temp = temp_dir / f"gd_{idx}_{uuid.uuid4().hex[:8]}"
                    all_records.extend(self._parse_gdrive_sqlite(gdb, sub_temp))
                except Exception as ex:
                    self._log(f"Error parsing Google Drive DB {gdb}: {ex}", "WARNING")

            seen_gdrive_log_paths: Set[str] = set()
            ordered_gdrive_logs = sorted(
                candidate_gdrive_log,
                key=lambda p: (0 if p.name.lower() == "sync_log.log" else 1, str(p).lower()),
            )
            for glog in ordered_gdrive_logs:
                try:
                    all_records.extend(self._parse_gdrive_sync_log(glog, seen_gdrive_log_paths))
                except Exception as ex:
                    self._log(f"Error parsing Google Drive sync_log.log {glog}: {ex}", "WARNING")

            # Pre-scan Dropbox info.json & config.db* first so discovered email enriches same-user DBs
            dropbox_account_hints: Dict[str, str] = {}
            for info_p in candidate_dropbox_info:
                try:
                    recs, acct_found = self._parse_dropbox_info_json(info_p)
                    all_records.extend(recs)
                    u_scope = self._dropbox_user_scope_key(info_p)
                    if acct_found and u_scope not in dropbox_account_hints:
                        dropbox_account_hints[u_scope] = acct_found
                except Exception as ex:
                    self._log(f"Error parsing Dropbox info.json {info_p}: {ex}", "WARNING")

            ordered_dropbox_dbs = sorted(
                candidate_dropbox_db,
                key=lambda p: (0 if "config" in p.name.lower() else 1, str(p)),
            )
            for idx, dbx_p in enumerate(ordered_dropbox_dbs):
                try:
                    sub_temp = temp_dir / f"dbx_{idx}_{uuid.uuid4().hex[:8]}"
                    u_scope = self._dropbox_user_scope_key(dbx_p)
                    scoped_hint = dropbox_account_hints.get(u_scope)
                    recs, acct_found = self._parse_dropbox_sqlite(dbx_p, sub_temp, scoped_hint)
                    all_records.extend(recs)
                    if acct_found and u_scope not in dropbox_account_hints:
                        dropbox_account_hints[u_scope] = acct_found
                except Exception as ex:
                    self._log(f"Error parsing Dropbox DB {dbx_p}: {ex}", "WARNING")

        # Deduplicate cloud file records
        unique_records: List[Dict[str, Any]] = []
        seen_cloud: Set[Tuple[str, ...]] = set()
        for rec in all_records:
            mt = rec.get("modified_time")
            mt_key = mt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(mt, datetime) else str(mt or "")
            c_key = (
                str(rec.get("cloud_provider") or "").strip().lower(),
                str(rec.get("account") or "").strip().lower(),
                str(rec.get("local_path") or "").strip().lower(),
                str(rec.get("cloud_path_or_id") or "").strip().lower(),
                str(rec.get("status") or "").strip().upper(),
                mt_key,
            )
            if c_key not in seen_cloud:
                seen_cloud.add(c_key)
                unique_records.append(rec)

        # Deduplicate OneDrive account/sync log rows
        unique_od_logs: List[Dict[str, Any]] = []
        seen_logs: Set[Tuple[str, ...]] = set()
        for lrec in onedrive_log_records:
            lt = lrec.get("last_sync_time")
            lt_key = lt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(lt, datetime) else str(lt or "")
            l_key = (
                str(lrec.get("account_cid") or "").strip().lower(),
                str(lrec.get("account_tier") or "").strip().lower(),
                str(lrec.get("user_folder") or "").strip().lower(),
                lt_key,
                str(lrec.get("log_file") or "").strip().lower(),
            )
            if l_key not in seen_logs:
                seen_logs.add(l_key)
                unique_od_logs.append(lrec)

        onedrive_rows = [r for r in unique_records if r.get("cloud_provider") == "OneDrive"]
        gdrive_rows = [r for r in unique_records if r.get("cloud_provider") == "GoogleDrive"]
        dropbox_rows = [r for r in unique_records if r.get("cloud_provider") == "Dropbox"]

        with DuckDBManager.get_lock(self.case_id):
            cur = self._get_conn().cursor()

            def _upsert_cloud_table(
                table_name: str,
                records_list: List[Dict[str, Any]],
                schema_ddl: str,
                artifact_id: str,
                display_name: str,
                where_del_sql: str,
                where_params: Optional[List[Any]] = None,
            ) -> int:
                cur.execute(schema_ddl)
                desc_cols = {str(r[0]).lower(): str(r[0]) for r in cur.execute(f'DESCRIBE "{table_name}";').fetchall()}
                if where_del_sql:
                    if "cloud_provider" in desc_cols or "cloud_provider" not in where_del_sql.lower():
                        cur.execute(f'DELETE FROM "{table_name}" WHERE {where_del_sql};', where_params or [])
                else:
                    cur.execute(f'DELETE FROM "{table_name}";')
                if records_list:
                    self.insert_records(
                        table_name=table_name,
                        records=records_list,
                        schema_ddl=schema_ddl,
                        artifact_id=artifact_id,
                        category="CLOUD",
                        display_name=display_name,
                        source_tool="CloudParser",
                        append=True,
                    )
                cnt_row = cur.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()
                total_cnt = int(cnt_row[0] or 0) if cnt_row else 0
                self.register_artifact(
                    table_name=table_name,
                    artifact_id=artifact_id,
                    category="CLOUD",
                    display_name=display_name,
                    source_tool="CloudParser",
                    row_count=total_cnt,
                )
                return total_cnt

            row_count = _upsert_cloud_table(
                table_name="parsed_cloud_files",
                records_list=unique_records,
                schema_ddl=CLOUD_SCHEMA_DDL,
                artifact_id="cloud_files",
                display_name="Cloud Storage Synced Files (Combined)",
                where_del_sql="cloud_provider IN (?, ?, ?)",
                where_params=["OneDrive", "GoogleDrive", "Dropbox"],
            )
            od_count = _upsert_cloud_table(
                table_name="parsed_onedrive_files",
                records_list=onedrive_rows,
                schema_ddl=ONEDRIVE_FILES_DDL,
                artifact_id="onedrive_files",
                display_name="OneDrive Synced Files",
                where_del_sql="cloud_provider = ?",
                where_params=["OneDrive"],
            )
            gd_count = _upsert_cloud_table(
                table_name="parsed_gdrive_files",
                records_list=gdrive_rows,
                schema_ddl=GDRIVE_FILES_DDL,
                artifact_id="gdrive_files",
                display_name="Google Drive Synced Files",
                where_del_sql="cloud_provider = ?",
                where_params=["GoogleDrive"],
            )
            dbx_count = _upsert_cloud_table(
                table_name="parsed_dropbox_files",
                records_list=dropbox_rows,
                schema_ddl=DROPBOX_FILES_DDL,
                artifact_id="dropbox_files",
                display_name="Dropbox Synced Files",
                where_del_sql="cloud_provider = ?",
                where_params=["Dropbox"],
            )
            od_log_count = _upsert_cloud_table(
                table_name="parsed_onedrive_logs",
                records_list=unique_od_logs,
                schema_ddl=ONEDRIVE_LOGS_SCHEMA_DDL,
                artifact_id="onedrive_logs",
                display_name="OneDrive Account & Sync Logs",
                where_del_sql="",
            )

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Cloud",
            command_executed=(
                f"CloudParser.parse({len(candidate_onedrive_db)} OneDriveDB, "
                f"{len(candidate_gdrive_db)} GDriveDB, {len(candidate_dropbox_db)} DropboxDB)"
            ),
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"Cloud parser completed in {duration_ms}ms: {row_count} cloud files, {od_log_count} OneDrive logs ingested."
        )
        return {
            "parsed_cloud_files": row_count,
            "parsed_onedrive_files": od_count,
            "parsed_gdrive_files": gd_count,
            "parsed_dropbox_files": dbx_count,
            "parsed_onedrive_logs": od_log_count,
        }
