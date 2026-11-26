"""
Windows Forensic Toolkit (WFT) DFIR Suite - DuckDB Database Engine, Pagination & Keyword Search Manager
"""
import gc
import hashlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import duckdb

from backend.config import get_case_db_path, get_case_dir
from backend.db.schema import CORE_TABLES, init_schema, verify_core_tables

DEFAULT_DUCKDB_THREADS = 32

_PARTITION_LABEL_RE = re.compile(
    r"^(?:"
    r"part(?:ition)?[_\-\s]*\d+(?:[_\-\s]+(?:ntfs|fat\d*|exfat|refs|ext\d*|apfs|hfs\+?|iso\d*|udf|efi|os|data|system|primary))?"
    r"|vol(?:ume)?[_\-\s]*\d+(?:[_\-\s]+(?:ntfs|fat\d*|exfat|refs|ext\d*|apfs|hfs\+?|iso\d*|udf|efi|os|data|system|primary))?"
    r"|(?:ntfs|fat\d*|exfat|refs|ext\d*|apfs|hfs\+?|iso\d*|udf)[_\-\s]*\d*"
    r"|[a-zA-Z]_drive"
    r"|p\d+(?:[_\-\s]+(?:ntfs|fat\d*|exfat|refs|ext\d*|iso\d*|udf))?"
    r"|os_partition"
    r"|system_partition"
    r"|basic_data_partition"
    r"|root"
    r")$",
    re.IGNORECASE,
)

_REAL_WIN_SUBDIR_RE = re.compile(r"^[a-zA-Z]:\\[^\\]+\\.+")


def _has_real_win_subdir(path_low: str) -> bool:
    """Return True when path_low is a canonical drive path with at least one directory (e.g. 'c:\\users\\alice\\a.txt')."""
    return bool(_REAL_WIN_SUBDIR_RE.match(path_low))

_RAW_BINARY_SKIP_EXTS: Set[str] = {
    ".evtx", ".pf", ".sqlite", ".sqlite3", ".db", ".db-wal", ".db-shm",
    ".e01", ".ex01", ".e02", ".dd", ".raw", ".img", ".vhd", ".vhdx", ".vmdk", ".iso",
    ".dll", ".exe", ".sys", ".mui", ".ocx", ".drv", ".efi",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff", ".heic",
    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".mp3", ".wav", ".flac",
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".cab", ".msi",
    ".duckdb", ".wal",
}

_MAX_RAW_SCAN_FILE_BYTES = 16 * 1024 * 1024  # 16 MB


def clamp_threads(max_workers: Optional[int]) -> int:
    if max_workers is None:
        return DEFAULT_DUCKDB_THREADS
    try:
        return max(1, min(32, int(max_workers)))
    except (TypeError, ValueError):
        return DEFAULT_DUCKDB_THREADS


def escape_like(val: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters (\\, %, _) for ESCAPE '\\'."""
    return str(val).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _strip_optional_partition_label(rel_path: str) -> Tuple[str, str]:
    """
    Given '<maybe_part_label>\\<rest>' or '<rel_path>', return (drive_prefix, cleaned_rest).
    Preserves real top-level directories like 'Windows\\...', 'Users\\...', 'inetpub\\...'.
    """
    cleaned = rel_path.lstrip("\\")
    drive_prefix = "C:\\"
    if "\\" in cleaned:
        first_seg, remainder = cleaned.split("\\", 1)
        if _PARTITION_LABEL_RE.match(first_seg):
            if len(first_seg) == 7 and first_seg[1:].lower() == "_drive" and first_seg[0].isalpha():
                drive_prefix = f"{first_seg[0].upper()}:\\"
            cleaned = remainder.lstrip("\\")
    if cleaned.lower().startswith("userfiles\\"):
        cleaned = "Users\\" + cleaned[10:]
    return drive_prefix, cleaned


def _restore_staging_subtree(rel_under_staging: str) -> str:
    """Map a relative path under <case_dir>/staging/ back to its canonical evidence path."""
    rel_clean = rel_under_staging.replace("/", "\\").lstrip("\\")
    if not rel_clean:
        return "[STAGED]"

    # 1. Volume Shadow Copy staged path: VSS\VSS_<N>\<inner>
    m_vss = re.match(r"(?i)^VSS\\VSS_(\d+)\\(.+)$", rel_clean)
    if m_vss:
        vss_num = m_vss.group(1)
        inner_restored = _restore_staging_subtree(m_vss.group(2))
        if inner_restored.startswith("[STAGED] "):
            drv, rel = _strip_optional_partition_label(inner_restored[9:])
            inner_restored = f"{drv}{rel}"
        return f"[VSS#{vss_num}] {inner_restored}"

    # 2. Active volume UserFiles staged path
    m_u = re.match(r"(?i)^UserFiles\\([^\\]+)\\(.+)$", rel_clean)
    if m_u:
        return f"C:\\Users\\{m_u.group(1)}\\{m_u.group(2)}"

    # 3. Active volume Enrichment staged path (with or without <part_label>)
    m_e = re.match(r"(?i)^Enrichment\\(.+)$", rel_clean)
    if m_e:
        drv, rel = _strip_optional_partition_label(m_e.group(1))
        return f"{drv}{rel}"

    # 4. Explicit <X>_Drive subtree
    m_drv = re.match(r"(?i)^([A-Za-z])_Drive\\(.+)$", rel_clean)
    if m_drv:
        return f"{m_drv.group(1).upper()}:\\{m_drv.group(2)}"

    # 5. Known EvidenceExtractor artifact subtrees
    m_ps = re.match(r"(?i)^PowerShell\\([^\\]+)\\(.+)$", rel_clean)
    if m_ps:
        user_seg = m_ps.group(1)
        if user_seg.lower() == "default":
            return f"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\{m_ps.group(2)}"
        return f"C:\\Users\\{user_seg}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\{m_ps.group(2)}"

    m_wl = re.match(r"(?i)^WebLogs\\(.+)$", rel_clean)
    if m_wl:
        return f"C:\\Windows\\System32\\LogFiles\\{m_wl.group(1)}"

    m_sum = re.match(r"(?i)^SUM\\(.+)$", rel_clean)
    if m_sum:
        return f"C:\\Windows\\System32\\LogFiles\\SUM\\{m_sum.group(1)}"

    m_tasks = re.match(r"(?i)^Tasks\\(.+)$", rel_clean)
    if m_tasks:
        return f"C:\\Windows\\System32\\Tasks\\{m_tasks.group(1)}"

    m_usb = re.match(r"(?i)^USB\\(.+)$", rel_clean)
    if m_usb:
        return f"C:\\Windows\\inf\\{m_usb.group(1)}"

    m_wer_u = re.match(r"(?i)^WER\\Users\\([^\\]+)\\(.+)$", rel_clean)
    if m_wer_u:
        return f"C:\\Users\\{m_wer_u.group(1)}\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive\\{m_wer_u.group(2)}"

    m_wer_s = re.match(r"(?i)^WER\\System\\(.+)$", rel_clean)
    if m_wer_s:
        return f"C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\{m_wer_s.group(1)}"

    m_wlan = re.match(r"(?i)^WLAN\\(.+)$", rel_clean)
    if m_wlan:
        return f"C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\{m_wlan.group(1)}"

    m_logs = re.match(r"(?i)^(?:Logs|EventLogs)\\(.+)$", rel_clean)
    if m_logs:
        return f"C:\\Windows\\System32\\winevt\\Logs\\{m_logs.group(1)}"

    m_pf = re.match(r"(?i)^Prefetch\\(.+)$", rel_clean)
    if m_pf:
        return f"C:\\Windows\\Prefetch\\{m_pf.group(1)}"

    m_srum = re.match(r"(?i)^SRUM\\(.+)$", rel_clean)
    if m_srum:
        return f"C:\\Windows\\System32\\sru\\{m_srum.group(1)}"

    m_wbem = re.match(r"(?i)^WBEM\\(.+)$", rel_clean)
    if m_wbem:
        return f"C:\\Windows\\System32\\wbem\\Repository\\{m_wbem.group(1)}"

    m_rb = re.match(r"(?i)^RecycleBin\\(.+)$", rel_clean)
    if m_rb:
        return f"C:\\$Recycle.Bin\\{m_rb.group(1)}"

    m_docs = re.match(r"(?i)^Documents\\Users\\(.+)$", rel_clean)
    if m_docs:
        return f"C:\\Users\\{m_docs.group(1)}"

    m_notif = re.match(r"(?i)^(?:SQLite\\)?Notifications\\([^\\]+)\\(.+)$", rel_clean)
    if m_notif:
        return f"C:\\Users\\{m_notif.group(1)}\\AppData\\Local\\Microsoft\\Windows\\Notifications\\{m_notif.group(2)}"

    # Catch-all for RMM, ZoneIdentifier, Documents, Browsers, Registry, CustomSubtree, etc.:
    # NEVER leak host temp/case directory prefixes!
    return f"[STAGED] {rel_clean}"


def _format_vfs_path(vfs_path: str) -> str:
    """Normalize a vfs_files.vfs_path (e.g. '/Users/Alice/note.txt') into Windows evidence notation."""
    vp = vfs_path.strip()
    if not vp:
        return vp
    if vp.startswith("[VSS#") or re.match(r"^[A-Za-z]:[\\/]", vp):
        return vp.replace("/", "\\")
    vp_bs = vp.replace("/", "\\").lstrip("\\")
    drv, rel = _strip_optional_partition_label(vp_bs)
    return f"{drv}{rel}"


def restore_evidence_path(
    path_str: str,
    case_dir: Optional[Union[str, Path]] = None,
    vfs_lookup: Optional[Dict[str, str]] = None,
) -> str:
    """
    Restore a host staging/VSS/carved path back to its canonical forensic volume path
    without ever leaking host temporary/case filesystem directories.
    """
    if not path_str or not isinstance(path_str, str):
        return path_str
    p_norm = path_str.replace("/", "\\")
    rel_from_case = ""
    if case_dir is not None:
        cd_norm = str(case_dir).replace("/", "\\").rstrip("\\")
        if cd_norm and p_norm.lower().startswith(cd_norm.lower() + "\\"):
            rel_from_case = p_norm[len(cd_norm) + 1:]
            p_norm = "\\" + rel_from_case

    if vfs_lookup:
        lookup_candidates: List[str] = []
        if rel_from_case:
            lookup_candidates.append(rel_from_case.lower())
            if rel_from_case.lower().startswith("staging\\"):
                lookup_candidates.append(rel_from_case[8:].lower())
        m_rel_stg = re.search(r"(?i)(?:^|\\)(staging\\.+)$", p_norm)
        if m_rel_stg:
            stg_rel = m_rel_stg.group(1)
            lookup_candidates.append(stg_rel.lower())
            lookup_candidates.append(stg_rel[8:].lower())
        for cand in lookup_candidates:
            cand_slash = cand.replace("\\", "/")
            mapped = vfs_lookup.get(cand) or vfs_lookup.get(cand_slash)
            if mapped:
                return _format_vfs_path(mapped)

    p_low = p_norm.lower()
    if p_low.startswith(("staging\\", "carved\\")):
        p_norm = "\\" + p_norm
        p_low = p_norm.lower()
    if "\\staging\\" not in p_low and "\\carved\\" not in p_low:
        if rel_from_case:
            return f"[STAGED] {rel_from_case}"
        return path_str

    m_stg = re.search(r"(?i)\\staging\\(.+)$", p_norm)
    if m_stg:
        return _restore_staging_subtree(m_stg.group(1))

    m_carved = re.search(r"(?i)\\carved\\(.+)$", p_norm)
    if m_carved:
        return f"[CARVED] {m_carved.group(1).lstrip(chr(92))}"

    return p_norm


class DuckDBManager:
    """
    Thread-safe connection and query execution manager for DuckDB case databases.
    Lock hierarchy (deadlock-free):
      keyword_scan_lock -> per-case RLock -> _instance_lock
    """
    _instance_lock = threading.Lock()
    _connections: Dict[str, duckdb.DuckDBPyConnection] = {}
    _is_read_only: Dict[str, bool] = {}
    _ro_connections: Set[str] = set()
    _schema_initialized: Set[Tuple[str, str]] = set()
    _case_locks: Dict[str, threading.RLock] = {}
    _keyword_scan_locks: Dict[str, threading.Lock] = {}
    _case_threads: Dict[str, int] = {}
    _deleted_cases: Set[str] = set()

    @classmethod
    def _resolve_db_key(cls, case_id: str) -> Tuple[Path, str]:
        db_path = get_case_db_path(case_id)
        db_key = str(db_path.resolve()).lower()
        return db_path, db_key

    @classmethod
    def mark_case_deleted(cls, case_id: str) -> None:
        cid_clean = str(case_id or "").strip().lower()
        if cid_clean:
            with cls._instance_lock:
                cls._deleted_cases.add(cid_clean)
        cls.close_connection(case_id)

    @classmethod
    def unmark_case_deleted(cls, case_id: str) -> None:
        cid_clean = str(case_id or "").strip().lower()
        if cid_clean:
            with cls._instance_lock:
                cls._deleted_cases.discard(cid_clean)

    @classmethod
    def is_case_deleted(cls, case_id: str) -> bool:
        cid_clean = str(case_id or "").strip().lower()
        if not cid_clean:
            return False
        with cls._instance_lock:
            return cid_clean in cls._deleted_cases

    @classmethod
    def has_connection(cls, case_id: str) -> bool:
        with cls._instance_lock:
            _, db_key = cls._resolve_db_key(case_id)
            return db_key in cls._connections

    @classmethod
    def has_rw_connection(cls, case_id: str) -> bool:
        with cls._instance_lock:
            _, db_key = cls._resolve_db_key(case_id)
            return (
                db_key in cls._connections
                and db_key not in cls._ro_connections
                and not cls._is_read_only.get(db_key, False)
            )

    @classmethod
    def has_ro_connection(cls, case_id: str) -> bool:
        with cls._instance_lock:
            _, db_key = cls._resolve_db_key(case_id)
            return db_key in cls._connections and (
                db_key in cls._ro_connections or cls._is_read_only.get(db_key, False)
            )

    @classmethod
    def get_keyword_scan_lock(cls, case_id: str) -> threading.Lock:
        with cls._instance_lock:
            _, db_key = cls._resolve_db_key(case_id)
            if db_key not in cls._keyword_scan_locks:
                cls._keyword_scan_locks[db_key] = threading.Lock()
            return cls._keyword_scan_locks[db_key]

    @classmethod
    def get_lock(cls, case_id: str) -> threading.RLock:
        with cls._instance_lock:
            _, db_key = cls._resolve_db_key(case_id)
            if db_key not in cls._case_locks:
                cls._case_locks[db_key] = threading.RLock()
            return cls._case_locks[db_key]

    @classmethod
    def get_connection(cls, case_id: str, read_only: bool = False) -> duckdb.DuckDBPyConnection:
        if cls.is_case_deleted(case_id):
            raise FileNotFoundError(f"Case '{case_id}' has been deleted.")
        case_lock = cls.get_lock(case_id)
        with case_lock:
            if cls.is_case_deleted(case_id):
                raise FileNotFoundError(f"Case '{case_id}' has been deleted.")
            ro_conn_to_close: Optional[duckdb.DuckDBPyConnection] = None
            cached_conn: Optional[duckdb.DuckDBPyConnection] = None
            with cls._instance_lock:
                db_path, db_key = cls._resolve_db_key(case_id)
                threads = cls._case_threads.get(db_key, DEFAULT_DUCKDB_THREADS)
                if read_only:
                    if db_key in cls._connections:
                        cached_conn = cls._connections[db_key]
                else:
                    if db_key in cls._connections:
                        if db_key in cls._ro_connections or cls._is_read_only.get(db_key, False):
                            ro_conn_to_close = cls._connections.pop(db_key, None)
                            cls._ro_connections.discard(db_key)
                            cls._is_read_only.pop(db_key, None)
                        else:
                            cached_conn = cls._connections[db_key]

            if cached_conn is not None:
                eff_ro = bool(read_only or db_key in cls._ro_connections or cls._is_read_only.get(db_key, False))
                return cls._ensure_healthy_cached_conn(
                    case_id=case_id,
                    db_path=db_path,
                    db_key=db_key,
                    conn=cached_conn,
                    read_only=eff_ro,
                    threads=threads,
                )

            if ro_conn_to_close is not None:
                try:
                    ro_conn_to_close.close()
                except Exception:
                    pass

            if read_only:
                if not db_path.is_file():
                    raise FileNotFoundError(f"Case database does not exist: {db_path}")
                conn = cls._connect_with_retry(db_path=db_path, read_only=True)
                try:
                    conn.cursor().execute(f"PRAGMA threads={threads};")
                except Exception:
                    pass
                with cls._instance_lock:
                    cls._connections[db_key] = conn
                    cls._is_read_only[db_key] = True
                    cls._ro_connections.add(db_key)
                return conn

            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = cls._connect_with_retry(db_path=db_path, read_only=False)
            try:
                conn.cursor().execute(f"PRAGMA threads={threads};")
            except Exception as pragma_err:
                print(f"[DuckDBManager] Notice setting PRAGMA threads={threads}: {pragma_err}")
            with cls._instance_lock:
                cls._connections[db_key] = conn
                cls._is_read_only[db_key] = False
                cls._ro_connections.discard(db_key)
            return conn

    @classmethod
    def _connect_with_retry(
        cls,
        db_path: Path,
        read_only: bool,
        max_attempts: int = 8,
    ) -> duckdb.DuckDBPyConnection:
        """
        Open a DuckDB connection with exponential backoff when the storage volume experiences
        a transient I/O stall (e.g. external USB/HDD spin-up 'The device is not ready').
        """
        last_err: Optional[Exception] = None
        for attempt in range(max_attempts):
            try:
                return duckdb.connect(database=str(db_path), read_only=read_only)
            except Exception as exc:
                last_err = exc
                if attempt + 1 < max_attempts:
                    time.sleep(min(4.0, 0.35 * (attempt + 1)))
        if last_err is not None:
            raise last_err
        return duckdb.connect(database=str(db_path), read_only=read_only)

    @classmethod
    def _ensure_healthy_cached_conn(
        cls,
        case_id: str,
        db_path: Path,
        db_key: str,
        conn: duckdb.DuckDBPyConnection,
        read_only: bool,
        threads: int,
    ) -> duckdb.DuckDBPyConnection:
        """
        Verify that a cached DuckDB connection is not stuck in an aborted transaction
        (e.g. after a transient 'TransactionContext Error: Failed to commit' disk/WAL flush hiccup).
        If unhealthy, attempt ROLLBACK first; if still poisoned, close and reopen cleanly with retry.
        """
        try:
            conn.cursor().execute("SELECT 1;")
            return conn
        except Exception as err:
            err_str = str(err)
            try:
                conn.cursor().execute("ROLLBACK;")
                conn.cursor().execute("SELECT 1;")
                return conn
            except Exception:
                pass
            print(f"[DuckDBManager] Recovering poisoned connection for {case_id} ({err_str})...")
            try:
                conn.close()
            except Exception:
                pass
            new_conn = cls._connect_with_retry(db_path=db_path, read_only=read_only)
            try:
                new_conn.cursor().execute(f"PRAGMA threads={threads};")
            except Exception:
                pass
            with cls._instance_lock:
                cls._connections[db_key] = new_conn
                cls._is_read_only[db_key] = read_only
                if read_only:
                    cls._ro_connections.add(db_key)
                else:
                    cls._ro_connections.discard(db_key)
            return new_conn

    @classmethod
    def configure_threads(cls, case_id: str, max_workers: int = 25) -> int:
        """
        Configure DuckDB intra-query worker threads (clamped 1..32) under the per-case RLock.
        """
        clamped = clamp_threads(max_workers)
        case_lock = cls.get_lock(case_id)
        with case_lock:
            conn = cls.get_connection(case_id, read_only=False)
            with cls._instance_lock:
                _, db_key = cls._resolve_db_key(case_id)
                cls._case_threads[db_key] = clamped
            conn.cursor().execute(f"PRAGMA threads={clamped};")
        return clamped

    @classmethod
    def close_connection(cls, case_id: str) -> None:
        with cls._instance_lock:
            try:
                _, target_key = cls._resolve_db_key(case_id)
            except Exception:
                target_key = ""

            keys_to_close: List[str] = []
            cid_lower = case_id.lower()
            for k in list(cls._connections.keys()):
                if (
                    k == target_key
                    or f"\\{cid_lower}\\" in k
                    or f"/{cid_lower}/" in k
                    or k.endswith(f"\\{cid_lower}")
                    or k.endswith(f"/{cid_lower}")
                    or f"cases\\{cid_lower}" in k
                    or f"cases/{cid_lower}" in k
                ):
                    keys_to_close.append(k)

            if target_key and target_key in cls._connections and target_key not in keys_to_close:
                keys_to_close.append(target_key)

            cls._schema_initialized = {
                pair
                for pair in cls._schema_initialized
                if pair[0] != cid_lower and pair[1] != target_key and pair[1] not in keys_to_close
            }

            lock_pairs: List[Tuple[str, threading.RLock]] = [
                (k, cls._case_locks.get(k) or threading.RLock()) for k in keys_to_close
            ]

        # Acquire case_lock OUTSIDE _instance_lock to preserve global lock ordering
        for k, case_lock in lock_pairs:
            with case_lock:
                with cls._instance_lock:
                    cls._is_read_only.pop(k, None)
                    cls._ro_connections.discard(k)
                    cls._case_threads.pop(k, None)
                    conn = cls._connections.pop(k, None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as ex:
                        print(f"[DuckDBManager] Warning while closing connection for {k}: {ex}")

        gc.collect()

    @classmethod
    def close_all(cls) -> None:
        with cls._instance_lock:
            cls._schema_initialized.clear()
            items = [
                (k, cls._case_locks.get(k) or threading.RLock())
                for k in list(cls._connections.keys())
            ]

        for db_key, case_lock in items:
            with case_lock:
                with cls._instance_lock:
                    cls._is_read_only.pop(db_key, None)
                    cls._ro_connections.discard(db_key)
                    cls._case_threads.pop(db_key, None)
                    conn = cls._connections.pop(db_key, None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as ex:
                        print(f"[DuckDBManager] Warning while closing connection for {db_key}: {ex}")


def init_case_db(case_id: str) -> Path:
    DuckDBManager.unmark_case_deleted(case_id)
    db_path, db_key = DuckDBManager._resolve_db_key(case_id)
    schema_key = (case_id.lower(), db_key)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        with DuckDBManager._instance_lock:
            already_init = schema_key in DuckDBManager._schema_initialized
        if already_init:
            try:
                has_reg = conn.cursor().execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'artifact_registry' LIMIT 1;"
                ).fetchone()
                if has_reg:
                    return db_path
            except Exception:
                pass
        init_schema(conn, case_id=case_id)
        with DuckDBManager._instance_lock:
            DuckDBManager._schema_initialized.add(schema_key)
    return db_path


def validate_table_or_column_name(name: str) -> str:
    if not re.match(r"^[A-Za-z0-9_]+$", name):
        raise ValueError(f"Invalid SQL identifier: '{name}'")
    return name


def get_table_columns(case_id: str, table_name: str, read_only: bool = False) -> List[str]:
    clean_table = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=read_only)
        cursor = conn.cursor()
        describe_rows = cursor.execute(f'DESCRIBE "{clean_table}";').fetchall()
        return [str(row[0]) for row in describe_rows]


def query_paginated(
    case_id: str,
    table_name: str,
    limit: int = 500,
    offset: int = 0,
    search: str = "",
    sort_col: str = "_row_id",
    sort_dir: str = "ASC",
    column_filters: Optional[Union[str, Dict[str, List[Any]]]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    tags: Optional[Union[str, List[str]]] = None,
    read_only: bool = False,
) -> Dict[str, Any]:
    clean_table = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=read_only)
        cursor = conn.cursor()

        columns = get_table_columns(case_id, clean_table, read_only=read_only)
        if not columns:
            return {"columns": [], "rows": [], "total_count": 0, "filtered_count": 0}

        total_count = cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}";').fetchone()[0]

        col_lookup = {c.lower(): c for c in columns}
        sort_direction = "DESC" if str(sort_dir).upper() == "DESC" else "ASC"
        sort_col_clean = str(sort_col).strip().lower()
        if sort_col_clean in col_lookup:
            sort_column = col_lookup[sort_col_clean]
        elif "_row_id" in col_lookup:
            sort_column = col_lookup["_row_id"]
        else:
            sort_column = columns[0]

        parsed_filters: Dict[str, List[Any]] = {}
        if column_filters:
            if isinstance(column_filters, str) and column_filters.strip():
                try:
                    parsed_filters = json.loads(column_filters)
                except Exception as j_err:
                    print(f"[query_paginated] Warning parsing column_filters JSON: {j_err}")
            elif isinstance(column_filters, dict):
                parsed_filters = column_filters

        where_conditions = []
        params: List[Any] = []

        if search and search.strip():
            escaped_term = escape_like(search.strip())
            search_pattern = f"%{escaped_term}%"
            ilike_clauses = [f'CAST("{col}" AS VARCHAR) ILIKE ? ESCAPE \'\\\'' for col in columns]
            where_conditions.append(f"({' OR '.join(ilike_clauses)})")
            params.extend([search_pattern] * len(columns))

        if parsed_filters:
            col_map = {c.lower(): c for c in columns}
            for col_key, filter_vals in parsed_filters.items():
                actual_col = col_map.get(col_key.lower())
                if actual_col and isinstance(filter_vals, (list, tuple, set)) and len(filter_vals) > 0:
                    placeholders = ", ".join(["?"] * len(filter_vals))
                    where_conditions.append(f'CAST("{actual_col}" AS VARCHAR) IN ({placeholders})')
                    params.extend([str(v) for v in filter_vals])

        if (start_time and str(start_time).strip()) or (end_time and str(end_time).strip()):
            time_cols = [c for c in columns if any(t in c.lower() for t in ["time", "date", "created", "modified", "lastrun", "timestamp"])]
            if time_cols:
                primary_time_col = next((c for c in time_cols if "timestamp" in c.lower() or "utc" in c.lower() or "created" in c.lower()), time_cols[0])
                if start_time and str(start_time).strip():
                    where_conditions.append(f'TRY_CAST("{primary_time_col}" AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)')
                    params.append(str(start_time).strip())
                if end_time and str(end_time).strip():
                    where_conditions.append(f'TRY_CAST("{primary_time_col}" AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)')
                    params.append(str(end_time).strip())

        tag_list: List[str] = []
        if tags:
            if isinstance(tags, str):
                try:
                    loaded = json.loads(tags)
                    if isinstance(loaded, list):
                        tag_list = [str(x) for x in loaded if str(x).strip()]
                    else:
                        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
                except Exception:
                    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
            elif isinstance(tags, (list, tuple, set)):
                tag_list = [str(t) for t in tags if str(t).strip()]

        if tag_list:
            row_id_col = "_row_id" if "_row_id" in columns else ("timeline_id" if "timeline_id" in columns else columns[0])
            placeholders = ", ".join(["?"] * len(tag_list))
            where_conditions.append(
                f'"{row_id_col}" IN (SELECT source_row_id FROM bookmarks WHERE (source_table = ? OR source_table = \'master_timeline\') AND tag_name IN ({placeholders}))'
            )
            params.append(clean_table)
            params.extend(tag_list)

        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""

        if where_clause:
            filtered_count = cursor.execute(
                f'SELECT COUNT(*) FROM "{clean_table}" {where_clause};',
                params,
            ).fetchone()[0]
        else:
            filtered_count = total_count

        fetch_query = (
            f'SELECT * FROM "{clean_table}" '
            f'{where_clause} '
            f'ORDER BY "{sort_column}" {sort_direction} '
            f'LIMIT ? OFFSET ?;'
        )
        query_params = params + [limit, offset]
        result_rows = cursor.execute(fetch_query, query_params).fetchall()

        serialized_rows = [dict(zip(columns, row)) for row in result_rows]
        for s_row in serialized_rows:
            fp_val = s_row.get("file_path")
            if isinstance(fp_val, str) and "staging" in fp_val.lower():
                if not s_row.get("source_file"):
                    s_row["source_file"] = fp_val
                s_row["file_path"] = restore_evidence_path(fp_val)

        return {
            "columns": columns,
            "rows": serialized_rows,
            "total_count": total_count,
            "filtered_count": filtered_count,
        }


query_artifact_table = query_paginated


def log_processing_event(
    case_id: str,
    module_name: str,
    command_executed: str,
    exit_code: int,
    rows_ingested: int,
    duration_ms: int,
    status: str,
    error_message: Optional[str] = None,
) -> None:
    if DuckDBManager.is_case_deleted(case_id):
        return
    try:
        with DuckDBManager.get_lock(case_id):
            if DuckDBManager.is_case_deleted(case_id):
                return
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO processing_logs (
                    log_id,
                    timestamp_utc,
                    module_name,
                    command_executed,
                    exit_code,
                    rows_ingested,
                    duration_ms,
                    status,
                    error_message
                ) VALUES (
                    nextval('seq_log_id'),
                    CURRENT_TIMESTAMP,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                );
                """,
                [
                    module_name,
                    command_executed,
                    exit_code,
                    rows_ingested,
                    duration_ms,
                    status,
                    error_message,
                ],
            )
    except Exception as db_log_err:
        print(f"[log_processing_event] Warning inserting processing_logs row for {case_id}: {db_log_err}")

    if DuckDBManager.is_case_deleted(case_id):
        return
    try:
        log_file = get_case_dir(case_id, create_if_missing=False) / "processing.log"
        if DuckDBManager.is_case_deleted(case_id):
            return
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_entry = (
            f"[{module_name}] Status={status} ExitCode={exit_code} "
            f"Rows={rows_ingested} Duration={duration_ms}ms | Cmd: {command_executed}"
        )
        if error_message:
            log_entry += f" | Error: {error_message}"
        log_entry += "\n"

        with open(log_file, "a", encoding="utf-8", errors="replace") as f:
            f.write(log_entry)
    except Exception as log_io_err:
        print(f"[log_processing_event] Warning writing log file for {case_id}: {log_io_err}")


def get_distinct_column_values(
    case_id: str,
    table_name: str,
    column_name: str,
    limit: int = 500,
    read_only: bool = False,
) -> List[Dict[str, Any]]:
    clean_table = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=read_only)
        cursor = conn.cursor()

        columns = [str(r[0]) for r in cursor.execute(f'DESCRIBE "{clean_table}";').fetchall()]
        col_lookup = {c.lower(): c for c in columns}
        col_clean = str(column_name).strip().lower()
        if col_clean not in col_lookup:
            raise ValueError(f"Column '{column_name}' not found in table '{clean_table}'. Valid columns: {columns}")
        actual_col = col_lookup[col_clean]

        query = (
            f'SELECT CAST("{actual_col}" AS VARCHAR) AS val, COUNT(*) AS cnt '
            f'FROM "{clean_table}" '
            f'GROUP BY val '
            f'ORDER BY cnt DESC '
            f'LIMIT ?;'
        )
        rows = cursor.execute(query, [limit]).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]


def _build_centered_snippet(text: str, start_idx: int, end_idx: int, col_label: Optional[str] = None) -> str:
    ctx_start = max(0, start_idx - 80)
    ctx_end = min(len(text), end_idx + 120)
    prefix = "..." if ctx_start > 0 else ""
    suffix = "..." if ctx_end < len(text) else ""
    core = text[ctx_start:ctx_end].replace("\r", " ").replace("\n", " ").replace("\x00", "")
    if col_label:
        return f"[{col_label}] {prefix}{core}{suffix}"
    return f"{prefix}{core}{suffix}"


_COMPAT_ALIAS_PRIMARY: Dict[str, str] = {
    "text_preview": "content_preview",
    "ocr_text": "extracted_text",
    "source_file": "file_path",
    "host_url": "zone_host_url",
    "referrer_url": "zone_referrer_url",
    "user_name": "username",
    "user_sid": "sid",
    "gps_coordinates": "gps_position",
    "visit_time_utc": "visit_time",
    "start_time_utc": "start_time",
    "end_time_utc": "end_time",
    "date_created_utc": "date_created",
    "date_last_used_utc": "date_last_used",
}


def _scan_single_raw_file(
    file_path: Path,
    source_table_label: str,
    artifact_label: str,
    compiled_keywords: List[Dict[str, Any]],
    case_dir: Optional[Path] = None,
    vfs_lookup: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """
    Scan a raw staged or carved file in BOTH UTF-8 and UTF-16LE (using errors='replace'
    so invalid bytes never fuse adjacent ASCII tokens), deduplicating identical matches
    at the same (keyword_id, byte_offset).
    """
    hits: List[Dict[str, Any]] = []
    try:
        st = file_path.stat()
        if st.st_size <= 0 or st.st_size > _MAX_RAW_SCAN_FILE_BYTES:
            return hits
        raw_bytes = file_path.read_bytes()
    except Exception:
        return hits

    if not raw_bytes:
        return hits

    restored_src = restore_evidence_path(str(file_path), case_dir=case_dir, vfs_lookup=vfs_lookup)
    file_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()

    # Prepare UTF-16LE text & BOM offset
    u16_bom = 2 if raw_bytes.startswith(b"\xff\xfe") else 0
    u16_body = raw_bytes[u16_bom:]
    try:
        text_u16 = u16_body.decode("utf-16-le", errors="replace")
    except Exception:
        text_u16 = ""

    # Prepare UTF-8 text & BOM offset + strict UTF-8 validity check
    u8_bom = 3 if raw_bytes.startswith(b"\xef\xbb\xbf") else 0
    u8_body = raw_bytes[u8_bom:]
    try:
        u8_body.decode("utf-8", errors="strict")
        is_strict_utf8 = True
    except UnicodeDecodeError:
        is_strict_utf8 = False
    try:
        text_u8 = u8_body.decode("utf-8", errors="replace")
    except Exception:
        text_u8 = ""

    for kw_spec in compiled_keywords:
        kw_id = kw_spec["keyword_id"]
        kw_str = kw_spec["keyword"]
        is_regex = kw_spec["is_regex"]
        is_case_sens = kw_spec["is_case_sensitive"]
        pattern: re.Pattern = kw_spec["regex"]
        kw_has_non_ascii = any(ord(c) > 127 for c in kw_str)

        seen_byte_offsets: Set[int] = set()
        u16_byte_ranges: List[Tuple[int, int]] = []

        # Pass 1: UTF-16LE scan (run first so genuine UTF-16LE matches claim their byte offsets cleanly)
        if text_u16:
            has_utf16_signal = (
                u16_bom > 0
                or (b"\x00" in u16_body)
                or (
                    len(u16_body) >= 2
                    and (len(u16_body) % 2 == 0)
                    and (kw_has_non_ascii or not is_strict_utf8)
                )
            )
            if has_utf16_signal:
                prev_u16_char_idx = 0
                prev_u16_byte_off = u16_bom
                for m in pattern.finditer(text_u16):
                    matched_txt = m.group(0)
                    if not matched_txt:
                        continue
                    m_start = m.start()
                    m_end = m.end()
                    if m_start >= prev_u16_char_idx:
                        byte_off = prev_u16_byte_off + len(
                            text_u16[prev_u16_char_idx:m_start].encode("utf-16-le", errors="replace")
                        )
                    else:
                        byte_off = u16_bom + len(text_u16[:m_start].encode("utf-16-le", errors="replace"))
                    byte_end = byte_off + len(matched_txt.encode("utf-16-le", errors="replace"))
                    prev_u16_char_idx = m_end
                    prev_u16_byte_off = byte_end
                    if byte_off in seen_byte_offsets:
                        continue
                    seen_byte_offsets.add(byte_off)
                    u16_byte_ranges.append((byte_off, byte_end))
                    snippet = _build_centered_snippet(text_u16, m.start(), m.end(), "utf-16le")
                    hits.append({
                        "keyword_id": kw_id,
                        "keyword": kw_str,
                        "is_regex": is_regex,
                        "is_case_sensitive": is_case_sens,
                        "artifact_name": artifact_label,
                        "source_table": source_table_label,
                        "source_row_id": int(byte_off),
                        "matched_column": "raw_content",
                        "match_offset": int(byte_off),
                        "encoding": "utf-16le",
                        "matched_snippet": snippet,
                        "source_file": restored_src,
                        "_sha256": file_sha256,
                        "_fname_low": file_path.name.lower(),
                    })

        # Pass 2: UTF-8 scan
        if text_u8:
            search_cursor_byte = 0
            prev_u8_char_idx = 0
            prev_u8_byte_off = u8_bom
            for m in pattern.finditer(text_u8):
                matched_txt = m.group(0)
                if not matched_txt:
                    continue
                # Avoid bogus regex matches spanning UTF-16 NUL bytes when keyword has no NUL
                if "\x00" in matched_txt and "\x00" not in kw_str:
                    continue
                encoded_match = matched_txt.encode("utf-8", errors="replace")
                found_idx = raw_bytes.find(encoded_match, search_cursor_byte) if encoded_match else -1
                if found_idx >= 0:
                    byte_off = found_idx
                    search_cursor_byte = found_idx + max(1, len(encoded_match))
                else:
                    m_start = m.start()
                    if m_start >= prev_u8_char_idx:
                        byte_off = prev_u8_byte_off + len(
                            text_u8[prev_u8_char_idx:m_start].encode("utf-8", errors="replace")
                        )
                    else:
                        byte_off = u8_bom + len(text_u8[:m_start].encode("utf-8", errors="replace"))
                    prev_u8_char_idx = m.end()
                    prev_u8_byte_off = byte_off + len(encoded_match)

                if byte_off in seen_byte_offsets:
                    continue
                if any(r_start <= byte_off < r_end for r_start, r_end in u16_byte_ranges):
                    continue
                seen_byte_offsets.add(byte_off)
                snippet = _build_centered_snippet(text_u8, m.start(), m.end(), "utf-8")
                hits.append({
                    "keyword_id": kw_id,
                    "keyword": kw_str,
                    "is_regex": is_regex,
                    "is_case_sensitive": is_case_sens,
                    "artifact_name": artifact_label,
                    "source_table": source_table_label,
                    "source_row_id": int(byte_off),
                    "matched_column": "raw_content",
                    "match_offset": int(byte_off),
                    "encoding": "utf-8",
                    "matched_snippet": snippet,
                    "source_file": restored_src,
                    "_sha256": file_sha256,
                    "_fname_low": file_path.name.lower(),
                })

    return hits


def _collect_raw_scannable_files(case_dir: Path) -> List[Tuple[Path, str, str]]:
    """
    Collect candidate text/log/script/config/carved files under <case_dir>/staging and <case_dir>/carved.
    Orders Enrichment/UserFiles/VSS copies ahead of secondary parser copies so deduplication keeps
    full restored volume paths (C:\\...) over flat staging paths ([STAGED] ...).
    """
    candidates: List[Tuple[Path, str, str]] = []
    staging_dir = case_dir / "staging"
    carved_dir = case_dir / "carved"

    for root_dir, tbl_label, art_label in (
        (staging_dir, "raw_staged_file", "Raw Staged File"),
        (carved_dir, "carved_files", "Carved File"),
    ):
        if not root_dir.exists() or not root_dir.is_dir():
            continue
        for fpath in root_dir.rglob("*"):
            try:
                if not fpath.is_file():
                    continue
                ext = fpath.suffix.lower()
                if ext in _RAW_BINARY_SKIP_EXTS:
                    continue
                parts_low = {p.lower() for p in fpath.parts}
                if ("registry" in parts_low or "clean_hives" in parts_low) and ext not in {
                    ".reg", ".txt", ".log", ".xml", ".json", ".ini", ".cfg", ".csv"
                }:
                    fname_up = fpath.name.upper()
                    if any(
                        fname_up.startswith(h)
                        for h in ("NTUSER.DAT", "USRCLASS.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "AMCACHE.HVE", "DEFAULT")
                    ):
                        continue
                if fpath.name.upper() in {"$MFT", "$J", "$USNJRNL", "SRUDB.DAT", "WEBCACHEV01.DAT"}:
                    continue
                st_size = fpath.stat().st_size
                if 0 < st_size <= _MAX_RAW_SCAN_FILE_BYTES:
                    candidates.append((fpath, tbl_label, art_label))
            except Exception:
                continue

    def _priority_key(item: Tuple[Path, str, str]) -> Tuple[int, str]:
        p_str = str(item[0]).replace("/", "\\").lower()
        if "\\staging\\enrichment\\" in p_str or "\\staging\\userfiles\\" in p_str or "\\staging\\vss\\" in p_str:
            return (0, p_str)
        return (1, p_str)

    candidates.sort(key=_priority_key)
    return candidates


def _build_combined_dedup_filter(
    tbl: str,
    col_names: List[str],
    table_row_counts: Dict[str, int],
    table_cols_map: Dict[str, Set[str]],
) -> Optional[str]:
    """
    Build a SQL WHERE predicate for combined tables whose granular mirror tables
    also hold rows, preventing 2x double-counting while still scanning any unmirrored
    rows in the combined table (and scanning 100% of combined when granular tables are empty).
    Returns '1=0' when the combined table should be completely skipped in favor of granular tables.
    """
    c_cols = {c.lower(): c for c in col_names}
    guards: List[str] = []

    def _not_exists_shared(gran_tbl: str, key_cols: Tuple[str, ...]) -> Optional[str]:
        g_cols = {gc.lower(): gc for gc in table_cols_map.get(gran_tbl, set())}
        shared = [k for k in key_cols if k in c_cols and k in g_cols]
        if not shared:
            return None
        preds = " AND ".join([f'_g."{g_cols[k]}" IS NOT DISTINCT FROM "{tbl}"."{c_cols[k]}"' for k in shared])
        return f'NOT EXISTS (SELECT 1 FROM "{gran_tbl}" _g WHERE {preds})'

    def _not_exists_aliased(
        gran_tbl: str,
        key_groups: Tuple[Tuple[str, ...], ...],
        require_first: bool = True,
    ) -> Optional[str]:
        g_cols = {gc.lower(): gc for gc in table_cols_map.get(gran_tbl, set())}
        pred_parts: List[str] = []
        for idx, aliases in enumerate(key_groups):
            c_match = next((c_cols[a] for a in aliases if a in c_cols), None)
            g_match = next((g_cols[a] for a in aliases if a in g_cols), None)
            if c_match and g_match:
                pred_parts.append(f'_g."{g_match}" IS NOT DISTINCT FROM "{tbl}"."{c_match}"')
            elif idx == 0 and require_first:
                return None
        if not pred_parts:
            return None
        return f'NOT EXISTS (SELECT 1 FROM "{gran_tbl}" _g WHERE {" AND ".join(pred_parts)})'

    if tbl == "parsed_chat_messages":
        app_col = c_cols.get("app_name") or c_cols.get("platform")
        chat_map = (
            ("parsed_teams_messages", "%team%"),
            ("parsed_discord_messages", "%discord%"),
            ("parsed_slack_messages", "%slack%"),
            ("parsed_skype_messages", "%skype%"),
            ("parsed_whatsapp_messages", "%whatsapp%"),
            ("parsed_telegram_messages", "%telegram%"),
            ("parsed_signal_messages", "%signal%"),
        )
        chat_keys = (
            ("message_text", "body", "message_body", "content", "message"),
            ("sender", "author", "from_user"),
        )
        for g_tbl, like_pat in chat_map:
            if table_row_counts.get(g_tbl, 0) > 0:
                ne = _not_exists_aliased(g_tbl, chat_keys, require_first=True)
                if app_col and ne:
                    guards.append(f'(LOWER(COALESCE("{app_col}", \'\')) NOT LIKE \'{like_pat}\' OR {ne})')
                elif ne:
                    guards.append(ne)
                elif app_col:
                    guards.append(f'LOWER(COALESCE("{app_col}", \'\')) NOT LIKE \'{like_pat}\'')

    elif tbl == "parsed_emails":
        fmt_col = c_cols.get("email_format")
        email_map = (
            ("parsed_outlook_emails", "('pst', 'ost', 'msg', 'outlook')"),
            ("parsed_mbox_emails", "('mbox', 'thunderbird')"),
            ("parsed_winmail_messages", "('eml', 'winmail', 'windows mail')"),
        )
        email_keys_primary = (
            ("body_snippet", "body_preview", "body", "plain_body"),
            ("subject",),
            ("sender", "from_addr"),
        )
        email_keys_fallback = (
            ("message_id",),
            ("subject",),
            ("sender", "from_addr"),
        )
        for g_tbl, in_list in email_map:
            if table_row_counts.get(g_tbl, 0) > 0:
                ne = (
                    _not_exists_aliased(g_tbl, email_keys_primary, require_first=True)
                    or _not_exists_aliased(g_tbl, email_keys_fallback, require_first=True)
                    or _not_exists_shared(g_tbl, ("subject", "sender", "date_utc"))
                )
                if fmt_col and ne:
                    guards.append(f'(LOWER(COALESCE("{fmt_col}", \'\')) NOT IN {in_list} OR {ne})')
                elif ne:
                    guards.append(ne)
                elif fmt_col:
                    guards.append(f'LOWER(COALESCE("{fmt_col}", \'\')) NOT IN {in_list}')

    elif tbl == "parsed_cloud_files":
        prov_col = c_cols.get("cloud_provider")
        cloud_map = (
            ("parsed_onedrive_files", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%onedrive%'"),
            ("parsed_gdrive_files", "(LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%google%' AND LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%gdrive%')"),
            ("parsed_dropbox_files", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%dropbox%'"),
            ("parsed_box_files", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%box%'"),
            ("parsed_icloud_files", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%icloud%'"),
        )
        cloud_keys = (
            ("local_path", "file_path"),
            ("cloud_path_or_id", "cloud_path", "file_id", "file_name"),
        )
        for g_tbl, tmpl in cloud_map:
            if table_row_counts.get(g_tbl, 0) > 0:
                ne = _not_exists_aliased(g_tbl, cloud_keys, require_first=False)
                if prov_col and ne:
                    guards.append(f'({tmpl.format(col=prov_col)} OR {ne})')
                elif ne:
                    guards.append(ne)
                elif prov_col:
                    guards.append(tmpl.format(col=prov_col))

    elif tbl == "parsed_notifications":
        if table_row_counts.get("parsed_wpn_notifications", 0) > 0:
            wpn_cols = {gc.lower(): gc for gc in table_cols_map.get("parsed_wpn_notifications", set())}
            c_txt_parts = [f'"{tbl}"."{c_cols[k]}"' for k in ("payload", "body", "title") if k in c_cols]
            g_txt_parts = [f'_g."{wpn_cols[k]}"' for k in ("payload", "body", "title") if k in wpn_cols]
            wpn_preds: List[str] = []
            if c_txt_parts and g_txt_parts:
                c_txt_expr = f"COALESCE({', '.join(c_txt_parts)})" if len(c_txt_parts) > 1 else c_txt_parts[0]
                g_txt_expr = f"COALESCE({', '.join(g_txt_parts)})" if len(g_txt_parts) > 1 else g_txt_parts[0]
                wpn_preds.append(f"{g_txt_expr} IS NOT DISTINCT FROM {c_txt_expr}")
            if "app_id" in c_cols and "app_id" in wpn_cols:
                wpn_preds.append(f'_g."{wpn_cols["app_id"]}" IS NOT DISTINCT FROM "{tbl}"."{c_cols["app_id"]}"')
            if wpn_preds:
                guards.append(f'NOT EXISTS (SELECT 1 FROM "parsed_wpn_notifications" _g WHERE {" AND ".join(wpn_preds)})')

    elif tbl in (
        "parsed_browser_history",
        "parsed_browser_downloads",
        "parsed_browser_logins",
        "parsed_browser_cookies",
        "parsed_browser_autofill",
    ):
        suffix = tbl.replace("parsed_browser_", "")
        br_col = c_cols.get("browser")
        key_lookup = {
            "history": ("url",),
            "downloads": ("target_path",),
            "logins": ("origin_url", "username_value"),
            "cookies": ("host_key", "name"),
            "autofill": ("field_name", "field_value"),
        }
        br_map = (
            (f"parsed_chrome_{suffix}", "LOWER(COALESCE(\"{col}\", '')) NOT IN ('chrome', 'chromium')"),
            (f"parsed_edge_{suffix}", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%edge%'"),
            (f"parsed_brave_{suffix}", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%brave%'"),
            (f"parsed_firefox_{suffix}", "LOWER(COALESCE(\"{col}\", '')) NOT LIKE '%firefox%'"),
        )
        for g_tbl, tmpl in br_map:
            if table_row_counts.get(g_tbl, 0) > 0:
                ne = _not_exists_shared(g_tbl, key_lookup.get(suffix, ("url",)))
                if br_col and ne:
                    guards.append(f'({tmpl.format(col=br_col)} OR {ne})')
                elif ne:
                    guards.append(ne)
                elif br_col:
                    guards.append(tmpl.format(col=br_col))

    elif tbl == "parsed_media_exif":
        for g_tbl in ("parsed_media_pictures", "parsed_media_videos"):
            if table_row_counts.get(g_tbl, 0) > 0:
                ne = _not_exists_shared(g_tbl, ("file_path",)) or _not_exists_shared(g_tbl, ("file_name", "sha256"))
                if ne:
                    guards.append(ne)

    elif tbl == "artifact_ocr_results":
        if table_row_counts.get("media_ocr_results", 0) > 0:
            ne = _not_exists_shared("media_ocr_results", ("file_path",))
            if ne:
                guards.append(ne)
            else:
                return "1=0"

    elif tbl == "parsed_documents_metadata":
        if table_row_counts.get("parsed_text_documents", 0) > 0:
            ptd_cols = table_cols_map.get("parsed_text_documents", set())
            fp_col = c_cols.get("file_path")
            fn_col = c_cols.get("file_name")
            sh_col = c_cols.get("sha256")
            or_parts: List[str] = []
            if fp_col and "file_path" in ptd_cols:
                or_parts.append(
                    f'(COALESCE("{tbl}"."{fp_col}", \'\') <> \'\' '
                    f'AND REPLACE(LOWER("{tbl}"."{fp_col}"), \'/\', \'\\\') = REPLACE(LOWER(_ptd."file_path"), \'/\', \'\\\'))'
                )
            if fn_col and "file_name" in ptd_cols:
                if sh_col and "sha256" in ptd_cols:
                    or_parts.append(
                        f'(COALESCE("{tbl}"."{fn_col}", \'\') <> \'\' '
                        f'AND LOWER("{tbl}"."{fn_col}") = LOWER(COALESCE(_ptd."file_name", \'\')) '
                        f'AND (COALESCE("{tbl}"."{sh_col}", \'\') = \'\' '
                        f'OR COALESCE(_ptd."sha256", \'\') = \'\' '
                        f'OR LOWER("{tbl}"."{sh_col}") = LOWER(_ptd."sha256")))'
                    )
                else:
                    or_parts.append(
                        f'(COALESCE("{tbl}"."{fn_col}", \'\') <> \'\' '
                        f'AND LOWER("{tbl}"."{fn_col}") = LOWER(COALESCE(_ptd."file_name", \'\')))'
                    )
            if or_parts:
                guards.append(f'NOT EXISTS (SELECT 1 FROM "parsed_text_documents" _ptd WHERE {" OR ".join(or_parts)})')

    if not guards:
        return None
    return " AND ".join(guards)


def scan_keywords_for_case(
    case_id: str,
    conn: Optional[duckdb.DuckDBPyConnection] = None,
    max_workers: int = 16,
) -> int:
    """
    Zero-spurious-hit, thread-safe, full-column + multi-threaded raw UTF-8/UTF-16LE keyword scanner (F18):
      - Serialized per case_id via DuckDBManager.get_keyword_scan_lock(case_id) (zero TOCTOU race)
      - Escapes \\, %, and _ wildcards with ESCAPE '\\' and preserves intentional whitespace keywords
      - Evaluates ALL text/searchable columns individually while deduplicating synced combined/granular tables & alias columns
      - Scans raw staged & carved files concurrently in both UTF-8 and UTF-16LE with errors='replace' and staging/SQL deduplication
      - Atomically replaces parsed_keyword_hits & updates case_keywords.hit_count under the final write lock
    """
    workers = clamp_threads(max_workers)
    case_dir = get_case_db_path(case_id).parent

    with DuckDBManager.get_keyword_scan_lock(case_id):
        vfs_lookup: Dict[str, str] = {}
        text_doc_covered_paths: Set[Tuple[str, str]] = set()
        text_doc_covered_hashes: Dict[Tuple[str, str], Set[str]] = {}
        text_doc_unhashed_fnames: Set[Tuple[str, str]] = set()

        with DuckDBManager.get_lock(case_id):
            if conn is None:
                conn = DuckDBManager.get_connection(case_id, read_only=False)
            cursor = conn.cursor()

            # 1. Reconcile case_keywords schema across schema.py, engine.py, and main.py
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS case_keywords (
                    keyword_id VARCHAR PRIMARY KEY,
                    keyword VARCHAR UNIQUE NOT NULL,
                    is_regex BOOLEAN DEFAULT FALSE,
                    is_case_sensitive BOOLEAN DEFAULT FALSE,
                    case_sensitive BOOLEAN DEFAULT FALSE,
                    category VARCHAR DEFAULT 'General',
                    source_file VARCHAR,
                    hit_count BIGINT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            for alter_sql in (
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS is_regex BOOLEAN DEFAULT FALSE;",
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS is_case_sensitive BOOLEAN DEFAULT FALSE;",
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS case_sensitive BOOLEAN DEFAULT FALSE;",
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS category VARCHAR DEFAULT 'General';",
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS source_file VARCHAR;",
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS hit_count BIGINT DEFAULT 0;",
                "ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;",
            ):
                try:
                    cursor.execute(alter_sql)
                except Exception:
                    pass

            # 2. Reconcile parsed_keyword_hits & unified view_keyword_hits (do NOT delete rows yet!)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS parsed_keyword_hits (
                    _row_id BIGINT,
                    keyword_id VARCHAR,
                    keyword VARCHAR,
                    is_regex BOOLEAN DEFAULT FALSE,
                    is_case_sensitive BOOLEAN DEFAULT FALSE,
                    artifact_name VARCHAR,
                    source_table VARCHAR,
                    source_row_id BIGINT,
                    matched_column VARCHAR,
                    match_offset BIGINT,
                    encoding VARCHAR,
                    matched_snippet VARCHAR,
                    source_file VARCHAR,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            for alter_hit_sql in (
                "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS is_case_sensitive BOOLEAN DEFAULT FALSE;",
                "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS matched_column VARCHAR;",
                "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS match_offset BIGINT;",
                "ALTER TABLE parsed_keyword_hits ADD COLUMN IF NOT EXISTS encoding VARCHAR;",
            ):
                try:
                    cursor.execute(alter_hit_sql)
                except Exception:
                    pass

            cursor.execute("""
                CREATE OR REPLACE VIEW view_keyword_hits AS
                SELECT
                    _row_id,
                    keyword_id,
                    keyword,
                    is_regex,
                    is_case_sensitive,
                    artifact_name,
                    source_table,
                    source_row_id,
                    matched_column,
                    match_offset,
                    encoding,
                    matched_snippet,
                    source_file,
                    detected_at
                FROM parsed_keyword_hits
                ORDER BY _row_id ASC;
            """)

            table_types = {
                r[0]: r[1]
                for r in cursor.execute(
                    "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            if table_types.get("keyword_hits") != "BASE TABLE":
                try:
                    cursor.execute("CREATE OR REPLACE VIEW keyword_hits AS SELECT * FROM view_keyword_hits;")
                except Exception:
                    pass

            keywords_rows = cursor.execute("""
                SELECT
                    keyword_id,
                    keyword,
                    COALESCE(is_regex, FALSE),
                    (COALESCE(is_case_sensitive, FALSE) OR COALESCE(case_sensitive, FALSE))
                FROM case_keywords;
            """).fetchall()

            if not keywords_rows:
                cursor.execute("DELETE FROM parsed_keyword_hits;")
                if "artifact_registry" in table_types:
                    cursor.execute("""
                        INSERT INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count
                        ) VALUES ('keyword_hits', 'REFINED RESULTS', 'Keyword Hits', 'view_keyword_hits', 'KeywordScanner', 0)
                        ON CONFLICT (artifact_id) DO UPDATE SET
                            category = 'REFINED RESULTS',
                            display_name = 'Keyword Hits',
                            table_name = 'view_keyword_hits',
                            row_count = 0;
                    """)
                return 0

            # Build staged_rel_path -> vfs_path lookup from vfs_files if populated
            if "vfs_files" in table_types:
                try:
                    vf_cols = {
                        str(r[0]).lower(): str(r[0])
                        for r in cursor.execute('DESCRIBE "vfs_files";').fetchall()
                    }
                    sr_col = vf_cols.get("staged_rel_path") or vf_cols.get("staged_path")
                    vp_col = vf_cols.get("vfs_path") or vf_cols.get("file_path")
                    if sr_col and vp_col:
                        for sr_val, vp_val in cursor.execute(
                            f'SELECT "{sr_col}", "{vp_col}" FROM "vfs_files" '
                            f'WHERE "{sr_col}" IS NOT NULL AND "{vp_col}" IS NOT NULL;'
                        ).fetchall():
                            sr_s = str(sr_val).strip()
                            vp_s = str(vp_val).strip()
                            if sr_s and vp_s:
                                k_bs = sr_s.replace("/", "\\").lstrip("\\").lower()
                                vfs_lookup[k_bs] = vp_s
                                vfs_lookup[k_bs.replace("\\", "/")] = vp_s
                                if k_bs.startswith("staging\\"):
                                    sub_k = k_bs[8:]
                                    vfs_lookup[sub_k] = vp_s
                                    vfs_lookup[sub_k.replace("\\", "/")] = vp_s
                except Exception:
                    pass

            # 3. Pre-validate & compile keywords (preserving intentional leading/trailing whitespace!)
            compiled_keywords: List[Dict[str, Any]] = []
            hit_counts_by_id: Dict[str, int] = {}

            for kw_id, kw_text, is_regex, is_case_sens in keywords_rows:
                kw_id_str = str(kw_id)
                hit_counts_by_id[kw_id_str] = 0
                kw_str = str(kw_text or "")
                if not kw_str or not kw_str.strip():
                    continue

                flags = 0 if bool(is_case_sens) else re.IGNORECASE
                if bool(is_regex):
                    try:
                        compiled_re = re.compile(kw_str, flags)
                    except re.error as rx_err:
                        print(f"[KeywordScanner] WARNING: Invalid regex '{kw_str}' (id={kw_id_str}): {rx_err}")
                        continue
                else:
                    compiled_re = re.compile(re.escape(kw_str), flags)

                compiled_keywords.append({
                    "keyword_id": kw_id_str,
                    "keyword": kw_str,
                    "is_regex": bool(is_regex),
                    "is_case_sensitive": bool(is_case_sens),
                    "regex": compiled_re,
                })

            all_base_tables = [
                t_name for t_name, t_type in table_types.items() if t_type == "BASE TABLE"
            ]
            excluded = {
                "case_metadata",
                "case_keywords",
                "parsed_keyword_hits",
                "keyword_hits",
                "bookmarks",
                "processing_logs",
                "artifact_registry",
                "file_enrichment",
                "master_timeline",
                "entity_connections",
            }
            candidate_tables = [
                t for t in all_base_tables if t not in excluded and not t.startswith("view_")
            ]

            table_row_counts: Dict[str, int] = {}
            table_cols_map: Dict[str, Set[str]] = {}
            table_desc_cache: Dict[str, List[Any]] = {}
            for tbl in candidate_tables:
                try:
                    rc = int(cursor.execute(f'SELECT COUNT(*) FROM "{tbl}";').fetchone()[0] or 0)
                    table_row_counts[tbl] = rc
                    if rc > 0:
                        d_rows = cursor.execute(f'DESCRIBE "{tbl}";').fetchall()
                        table_desc_cache[tbl] = d_rows
                        table_cols_map[tbl] = {str(r[0]).lower() for r in d_rows}
                except Exception:
                    table_row_counts[tbl] = 0

            disp_map: Dict[str, str] = {}
            if "artifact_registry" in table_types:
                for t_n, d_n in cursor.execute("SELECT table_name, display_name FROM artifact_registry;").fetchall():
                    disp_map[str(t_n)] = str(d_n)

            all_emitted_hits: List[List[Any]] = []
            hit_row_id = 1

        # 4. Structured Database Table Scan (acquire per-case DB lock per table query only;
        # process Python regex/snippet extraction outside the DB lock so other threads never block!)
        for tbl in candidate_tables:
            try:
                row_cnt = table_row_counts.get(tbl, 0)
                if row_cnt == 0:
                    continue
                desc_rows = table_desc_cache.get(tbl)
                if not desc_rows:
                    continue

                col_names = [str(r[0]) for r in desc_rows]
                col_lookup_low = {c.lower(): c for c in col_names}
                dedup_filter_sql = _build_combined_dedup_filter(
                    tbl, col_names, table_row_counts, table_cols_map
                )
                if dedup_filter_sql == "1=0":
                    continue

                id_col = "_row_id" if "_row_id" in col_names else col_names[0]
                src_col = next(
                    (
                        c for c in col_names
                        if c.lower() in ("file_path", "source_file", "sourcefile", "sourcefilename", "source_path", "vfs_path", "carved_rel_path")
                    ),
                    None,
                )
                sha_col = col_lookup_low.get("sha256")
                fname_col = col_lookup_low.get("file_name")
                search_cols = [
                    str(r[0])
                    for r in desc_rows
                    if str(r[0]) != "_row_id" and "BLOB" not in str(r[1]).upper() and "BYTEA" not in str(r[1]).upper()
                ]
                if not search_cols:
                    continue

                art_label = disp_map.get(
                    tbl,
                    tbl.replace("parsed_", "").replace("raw_", "").replace("_", " ").title(),
                )
                select_cols = [id_col]
                for extra_meta_col in (src_col, sha_col, fname_col):
                    if extra_meta_col and extra_meta_col not in select_cols:
                        select_cols.append(extra_meta_col)
                extra_search_cols = [c for c in search_cols if c not in select_cols]
                ordered_cols = select_cols + extra_search_cols
                select_list_sql = ", ".join([f'"{c}"' for c in ordered_cols])
                col_idx_map = {c: i for i, c in enumerate(ordered_cols)}

                for kw_spec in compiled_keywords:
                    kw_id_str = kw_spec["keyword_id"]
                    kw_clean = kw_spec["keyword"]
                    is_rx = kw_spec["is_regex"]
                    is_cs = kw_spec["is_case_sensitive"]
                    rx_obj: re.Pattern = kw_spec["regex"]

                    row_limit_sql = " LIMIT 25000" if tbl in ("parsed_bulk_extractor_features", "raw_mft", "raw_usnjrnl") else ""
                    with DuckDBManager.get_lock(case_id):
                        q_conn = conn if conn is not None else DuckDBManager.get_connection(case_id, read_only=False)
                        q_cursor = q_conn.cursor()
                        if is_rx:
                            rx_opt = "c" if is_cs else "i"
                            clauses = [f'regexp_matches(CAST("{c}" AS VARCHAR), ?, \'{rx_opt}\')' for c in search_cols]
                            match_where = f"({' OR '.join(clauses)})"
                            full_where = f"{match_where} AND ({dedup_filter_sql})" if dedup_filter_sql else match_where
                            sql_params = [kw_clean] * len(search_cols)
                            try:
                                candidate_rows = q_cursor.execute(
                                    f'SELECT {select_list_sql} FROM "{tbl}" WHERE {full_where}{row_limit_sql};',
                                    sql_params,
                                ).fetchall()
                            except Exception:
                                fb_where = f"WHERE {dedup_filter_sql}" if dedup_filter_sql else ""
                                candidate_rows = q_cursor.execute(
                                    f'SELECT {select_list_sql} FROM "{tbl}" {fb_where}{row_limit_sql};'
                                ).fetchall()
                        else:
                            like_op = "LIKE" if is_cs else "ILIKE"
                            like_pat = f"%{escape_like(kw_clean)}%"
                            clauses = [f'CAST("{c}" AS VARCHAR) {like_op} ? ESCAPE \'\\\'' for c in search_cols]
                            match_where = f"({' OR '.join(clauses)})"
                            full_where = f"{match_where} AND ({dedup_filter_sql})" if dedup_filter_sql else match_where
                            sql_params = [like_pat] * len(search_cols)
                            candidate_rows = q_cursor.execute(
                                f'SELECT {select_list_sql} FROM "{tbl}" WHERE {full_where}{row_limit_sql};',
                                sql_params,
                            ).fetchall()

                    for r_tuple in candidate_rows:
                        raw_rid = r_tuple[col_idx_map[id_col]]
                        try:
                            s_rid = int(raw_rid) if raw_rid is not None else 0
                        except (TypeError, ValueError):
                            s_rid = 0
                        raw_src = r_tuple[col_idx_map[src_col]] if src_col else ""
                        s_file = restore_evidence_path(
                            str(raw_src or ""), case_dir=case_dir, vfs_lookup=vfs_lookup
                        )
                        row_sha = (
                            str(r_tuple[col_idx_map[sha_col]] or "").strip().lower()
                            if sha_col
                            else ""
                        )
                        row_fname_low = (
                            str(r_tuple[col_idx_map[fname_col]] or "").strip().lower()
                            if fname_col
                            else ""
                        )
                        if not row_fname_low and s_file:
                            row_fname_low = os.path.basename(s_file.replace("/", "\\")).strip().lower()

                        row_emitted_any = False
                        for s_col in search_cols:
                            cell_val = r_tuple[col_idx_map[s_col]]
                            if cell_val is None:
                                continue
                            cell_str = str(cell_val)
                            if not cell_str:
                                continue

                            # DocumentParser synthesizes parsed_text_documents.title from the first line of content_preview;
                            # skip title when content_preview/text_preview/full_text on the same row already carries the match.
                            if tbl == "parsed_text_documents" and s_col.lower() == "title":
                                body_matched = False
                                for body_key in ("content_preview", "text_preview", "full_text"):
                                    b_col = col_lookup_low.get(body_key)
                                    if b_col and b_col in col_idx_map:
                                        b_str = str(r_tuple[col_idx_map[b_col]] or "")
                                        if b_str and (cell_str in b_str or rx_obj.search(b_str)):
                                            body_matched = True
                                            break
                                if body_matched:
                                    continue

                            # Skip file_name when a path column on the same row already carries the filename match
                            if s_col.lower() == "file_name":
                                path_matched = False
                                for path_key in ("file_path", "vfs_path", "local_path", "cloud_path", "cloud_path_or_id", "target_path"):
                                    p_col = col_lookup_low.get(path_key)
                                    if p_col and p_col in col_idx_map:
                                        p_str = str(r_tuple[col_idx_map[p_col]] or "")
                                        if p_str and cell_str.lower() in p_str.lower() and rx_obj.search(p_str):
                                            path_matched = True
                                            break
                                if path_matched:
                                    continue

                            # Skip duplicate compatibility-alias columns holding identical text on the same row
                            prim_low = _COMPAT_ALIAS_PRIMARY.get(s_col.lower())
                            if prim_low and prim_low in col_lookup_low:
                                prim_col = col_lookup_low[prim_low]
                                if prim_col in col_idx_map:
                                    prim_val = str(r_tuple[col_idx_map[prim_col]] or "")
                                    if prim_val:
                                        if prim_val == cell_str:
                                            continue
                                        if s_col.lower() == "source_file" and (
                                            restore_evidence_path(prim_val, case_dir=case_dir, vfs_lookup=vfs_lookup).lower()
                                            == restore_evidence_path(cell_str, case_dir=case_dir, vfs_lookup=vfs_lookup).lower()
                                        ):
                                            continue

                            m = rx_obj.search(cell_str)
                            if m:
                                snippet = _build_centered_snippet(cell_str, m.start(), m.end(), s_col)
                                all_emitted_hits.append([
                                    hit_row_id,
                                    kw_id_str,
                                    kw_clean,
                                    is_rx,
                                    is_cs,
                                    art_label,
                                    tbl,
                                    s_rid,
                                    s_col,
                                    int(m.start()),
                                    "table",
                                    snippet,
                                    s_file,
                                ])
                                hit_row_id += 1
                                hit_counts_by_id[kw_id_str] = hit_counts_by_id.get(kw_id_str, 0) + 1
                                row_emitted_any = True

                        if row_emitted_any and tbl == "parsed_text_documents":
                            canon_doc_low = ""
                            if s_file:
                                s_low = s_file.lower()
                                text_doc_covered_paths.add((kw_id_str, s_low))
                                if not s_low.startswith(("[staged]", "[vss#", "[carved]")):
                                    canon_doc_low = _format_vfs_path(s_file).lower()
                                    text_doc_covered_paths.add((kw_id_str, canon_doc_low))
                                else:
                                    canon_doc_low = s_low
                            if raw_src:
                                raw_src_str = str(raw_src)
                                raw_low = raw_src_str.replace("/", "\\").lower()
                                text_doc_covered_paths.add((kw_id_str, raw_low))
                                if not raw_low.startswith(("[staged]", "[vss#", "[carved]")):
                                    vfs_norm_low = _format_vfs_path(raw_src_str).lower()
                                    text_doc_covered_paths.add((kw_id_str, vfs_norm_low))
                                    if not canon_doc_low:
                                        canon_doc_low = vfs_norm_low
                            if row_sha:
                                text_doc_covered_hashes.setdefault((kw_id_str, row_sha), set()).add(canon_doc_low)
                            elif row_fname_low:
                                text_doc_unhashed_fnames.add((kw_id_str, row_fname_low))
            except Exception as scan_err:
                print(f"[KeywordScanner] Notice scanning table {tbl}: {scan_err}")

        # 5. Multi-threaded Raw Staged & Carved File Scan (outside per-case DB lock, inside per-case scan lock!)
        raw_file_hits: List[Dict[str, Any]] = []
        if compiled_keywords:
            try:
                raw_files = _collect_raw_scannable_files(case_dir)
                if raw_files:
                    pool_size = max(1, min(workers, 32, len(raw_files)))
                    with ThreadPoolExecutor(max_workers=pool_size) as pool:
                        futures = [
                            pool.submit(
                                _scan_single_raw_file,
                                fpath,
                                tbl_lbl,
                                art_lbl,
                                compiled_keywords,
                                case_dir,
                                vfs_lookup,
                            )
                            for fpath, tbl_lbl, art_lbl in raw_files
                        ]
                        for fut in as_completed(futures):
                            try:
                                f_hits = fut.result()
                                if f_hits:
                                    raw_file_hits.extend(f_hits)
                            except Exception as f_err:
                                print(f"[KeywordScanner] Warning scanning raw file: {f_err}")
                    # Prefer canonical multi-segment volume / [VSS#...] paths ahead of flat C:\<file> and [STAGED] copies
                    def _raw_hit_sort_key(h: Dict[str, Any]) -> Tuple[int, str, int, str]:
                        sf_low = str(h.get("source_file") or "").lower()
                        if sf_low.startswith("[vss#") or _has_real_win_subdir(sf_low):
                            rank = 0
                        elif not sf_low.startswith("[staged]"):
                            rank = 1
                        else:
                            rank = 2
                        return (rank, str(h["source_file"]), int(h["match_offset"]), str(h["keyword_id"]))

                    raw_file_hits.sort(key=_raw_hit_sort_key)
            except Exception as raw_scan_err:
                print(f"[KeywordScanner] Notice collecting raw staged files: {raw_scan_err}")

        # 6. Atomically replace parsed_keyword_hits & update exact hit_count under case lock
        for _kw_db_attempt in range(4):
            try:
                with DuckDBManager.get_lock(case_id):
                    write_conn = conn if conn is not None else DuckDBManager.get_connection(case_id, read_only=False)
                    cursor = write_conn.cursor()

                    seen_raw_path_offsets: Set[Tuple[str, str, int]] = set()
                    seen_raw_hash_paths: Dict[Tuple[str, str, str, int], Set[str]] = {}
                    final_emitted_hits = list(all_emitted_hits)
                    final_hit_counts = dict(hit_counts_by_id)
                    final_hit_row_id = hit_row_id

                    for rh in raw_file_hits:
                        kw_id_str = rh["keyword_id"]
                        src_low = str(rh["source_file"] or "").lower()
                        m_off = int(rh["match_offset"])
                        f_sha = str(rh.get("_sha256") or "")
                        f_name_low = str(rh.get("_fname_low") or "")

                        # Deduplicate against SQL parsed_text_documents hits on the exact same evidence file
                        if rh["source_table"] == "raw_staged_file":
                            if src_low and (kw_id_str, src_low) in text_doc_covered_paths:
                                continue
                            if f_sha and (kw_id_str, f_sha) in text_doc_covered_hashes:
                                covered_paths = text_doc_covered_hashes[(kw_id_str, f_sha)]
                                if src_low.startswith("[vss#"):
                                    if src_low in covered_paths:
                                        continue
                                elif _has_real_win_subdir(src_low):
                                    if src_low in covered_paths or not any(_has_real_win_subdir(cp) for cp in covered_paths if cp):
                                        continue
                                else:
                                    # Flat staging copy ([STAGED] Documents\... or root C:\<file>) matching SHA-256 of an active text doc
                                    continue
                            if (
                                f_name_low
                                and (kw_id_str, f_name_low) in text_doc_unhashed_fnames
                                and not src_low.startswith("[vss#")
                                and not _has_real_win_subdir(src_low)
                            ):
                                continue

                        # Deduplicate identical raw file hits across duplicate staging copies (Enrichment vs flat Documents)
                        po_key = (kw_id_str, src_low, m_off)
                        if po_key in seen_raw_path_offsets:
                            continue
                        if rh["source_table"] == "raw_staged_file" and f_sha:
                            ho_key = (kw_id_str, f_sha, f_name_low, m_off)
                            prev_paths = seen_raw_hash_paths.get(ho_key)
                            if prev_paths and not src_low.startswith("[vss#") and not _has_real_win_subdir(src_low):
                                continue
                            seen_raw_hash_paths.setdefault(ho_key, set()).add(src_low)
                        seen_raw_path_offsets.add(po_key)

                        final_emitted_hits.append([
                            final_hit_row_id,
                            kw_id_str,
                            rh["keyword"],
                            rh["is_regex"],
                            rh["is_case_sensitive"],
                            rh["artifact_name"],
                            rh["source_table"],
                            rh["source_row_id"],
                            rh["matched_column"],
                            m_off,
                            rh["encoding"],
                            rh["matched_snippet"],
                            rh["source_file"],
                        ])
                        final_hit_row_id += 1
                        final_hit_counts[kw_id_str] = final_hit_counts.get(kw_id_str, 0) + 1

                    cursor.execute("DELETE FROM parsed_keyword_hits;")

                    if final_emitted_hits:
                        inserted_fast = False
                        if len(final_emitted_hits) >= 250:
                            try:
                                import pyarrow as pa

                                pa_hits = pa.table(
                                    {
                                        "_row_id": [int(r[0]) for r in final_emitted_hits],
                                        "keyword_id": [str(r[1]) for r in final_emitted_hits],
                                        "keyword": [str(r[2]) for r in final_emitted_hits],
                                        "is_regex": [bool(r[3]) for r in final_emitted_hits],
                                        "is_case_sensitive": [bool(r[4]) for r in final_emitted_hits],
                                        "artifact_name": [str(r[5]) for r in final_emitted_hits],
                                        "source_table": [str(r[6]) for r in final_emitted_hits],
                                        "source_row_id": [int(r[7]) for r in final_emitted_hits],
                                        "matched_column": [str(r[8]) for r in final_emitted_hits],
                                        "match_offset": [int(r[9]) for r in final_emitted_hits],
                                        "encoding": [str(r[10]) for r in final_emitted_hits],
                                        "matched_snippet": [str(r[11]) for r in final_emitted_hits],
                                        "source_file": [str(r[12]) for r in final_emitted_hits],
                                    }
                                )
                                cursor.register("_tmp_kw_hits", pa_hits)
                                try:
                                    cursor.execute(
                                        """
                                        INSERT INTO parsed_keyword_hits (
                                            _row_id, keyword_id, keyword, is_regex, is_case_sensitive,
                                            artifact_name, source_table, source_row_id,
                                            matched_column, match_offset, encoding,
                                            matched_snippet, source_file
                                        )
                                        SELECT
                                            _row_id, keyword_id, keyword, is_regex, is_case_sensitive,
                                            artifact_name, source_table, source_row_id,
                                            matched_column, match_offset, encoding,
                                            matched_snippet, source_file
                                        FROM _tmp_kw_hits;
                                        """
                                    )
                                    inserted_fast = True
                                finally:
                                    try:
                                        cursor.unregister("_tmp_kw_hits")
                                    except Exception:
                                        pass
                            except Exception:
                                inserted_fast = False

                        if not inserted_fast:
                            cursor.executemany(
                                """
                                INSERT INTO parsed_keyword_hits (
                                    _row_id, keyword_id, keyword, is_regex, is_case_sensitive,
                                    artifact_name, source_table, source_row_id,
                                    matched_column, match_offset, encoding,
                                    matched_snippet, source_file
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                """,
                                final_emitted_hits,
                            )

                    for kw_id_str, exact_cnt in final_hit_counts.items():
                        cursor.execute(
                            "UPDATE case_keywords SET hit_count = ? WHERE keyword_id = ?;",
                            [int(exact_cnt), kw_id_str],
                        )

                    total_hit_rows = cursor.execute("SELECT COUNT(*) FROM parsed_keyword_hits;").fetchone()[0]
                    tables_after = {
                        r[0] for r in cursor.execute(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                        ).fetchall()
                    }
                    if "artifact_registry" in tables_after:
                        cursor.execute(
                            """
                            INSERT INTO artifact_registry (
                                artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                            ) VALUES ('keyword_hits', 'REFINED RESULTS', 'Keyword Hits', 'view_keyword_hits', 'KeywordScanner', ?, now())
                            ON CONFLICT (artifact_id) DO UPDATE SET
                                category = 'REFINED RESULTS',
                                display_name = 'Keyword Hits',
                                table_name = 'view_keyword_hits',
                                row_count = EXCLUDED.row_count,
                                last_updated = now();
                            """,
                            [int(total_hit_rows)],
                        )

                    return int(total_hit_rows)
            except Exception as kw_db_exc:
                err_low = str(kw_db_exc).lower()
                if _kw_db_attempt < 3 and conn is None and any(
                    tok in err_low
                    for tok in ("transactioncontext", "failed to commit", "device is not ready", "could not flush")
                ):
                    time.sleep(0.5 * (_kw_db_attempt + 1))
                    continue
                raise
