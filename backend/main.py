"""
Windows Forensic Toolkit (WFT) - FastAPI REST Backend
Exposes all Milestone REST endpoints on port 8765 with full CORS,
real-time audit logging, DuckDB query engine, and zero stubs.
"""
import faulthandler
import sys
faulthandler.enable(file=sys.stderr, all_threads=True)

import ctypes
import html
import inspect
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

import duckdb
import backend.config as _cfg
from backend.security import (
    ForensicSecurityHeadersMiddleware,
    resolve_sandboxed_case_file,
    sanitize_sql_identifier,
    validate_tool_binary_path,
)
from fastapi import BackgroundTasks, Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from backend.config import (
    API_HOST,
    API_PORT,
    BASE_DIR,
    BUNDLE_DIR,
    CASES_DIR,
    DEFAULT_YARA_FILE,
    RULES_DIR,
    find_stinger_binary,
    find_hindsight_binary,
    get_case_db_path,
    get_case_dir,
    get_case_log_file,
    get_case_staging_dir,
    get_registered_custom_cases,
    get_tool_paths_status,
    register_case_dir,
    unregister_case_dir,
    reload_config_in_memory,
    save_tool_paths,
    find_all_forensic_tools_fast,
    scan_and_sync_tool_paths,
)
from backend.db.engine import (
    DuckDBManager,
    _strip_optional_partition_label,
    get_table_columns,
    init_case_db,
    query_paginated,
    validate_table_or_column_name,
    get_distinct_column_values,
    scan_keywords_for_case,
)
FileEnrichmentEngine = None  # type: ignore[assignment]
ChromiumParser = None  # type: ignore[assignment]
ProcessingPipeline = None  # type: ignore[assignment]
_pipeline_get_job_status = None  # type: ignore[assignment]
run_pipeline = None  # type: ignore[assignment]


def get_job_status(case_id: str) -> Dict[str, Any]:
    global _pipeline_get_job_status
    if _pipeline_get_job_status is None:
        try:
            from backend.orchestrator.pipeline import get_job_status as _gjs
            _pipeline_get_job_status = _gjs
        except (ImportError, SyntaxError, Exception):
            is_running = case_id in globals().get("_running_cases", set())
            return {
                "case_id": case_id,
                "status": "RUNNING" if is_running else "UNKNOWN",
                "progress": 5 if is_running else 0,
                "current_step": "Processing evidence..." if is_running else "",
                "error": None,
                "start_time": None,
                "end_time": None,
            }
    try:
        return _pipeline_get_job_status(case_id)
    except Exception:
        return {"case_id": case_id, "status": "UNKNOWN", "progress": 0, "current_step": ""}

# ---------------------------------------------------------------------------
# FastAPI Application & CORS Configuration
# ---------------------------------------------------------------------------
import contextlib as _contextlib
import logging as _logging


class _SuppressDuplicate200Filter(_logging.Filter):
    """
    Suppresses excessive uvicorn access noise by deduplicating repeated HTTP 200 OK polling logs.
    If the status is OK, exactly one line is logged per endpoint within the heartbeat window (default 60s).
    Non-200 responses, status transitions, and errors are always logged immediately without suppression.
    """
    def __init__(self, heartbeat_interval: float = 60.0):
        super().__init__()
        self._endpoint_log_times: Dict[str, float] = {}
        self._last_status_per_endpoint: Dict[str, int] = {}
        self._heartbeat = heartbeat_interval
        self._lock = threading.Lock()

    def filter(self, record: _logging.LogRecord) -> bool:
        try:
            status_code: Optional[int] = getattr(record, "status_code", None)
            endpoint: Optional[str] = None

            if record.args and len(record.args) >= 5:
                endpoint = str(record.args[2])
                try:
                    status_code = int(record.args[4])
                except (ValueError, TypeError):
                    status_code = None

            msg = record.getMessage()
            if status_code is None:
                if " 200 OK" in msg or " 200 " in msg:
                    status_code = 200
                    if '"' in msg:
                        parts = msg.split('"')
                        if len(parts) >= 2:
                            req_parts = parts[1].split()
                            if len(req_parts) >= 2:
                                endpoint = req_parts[1]

            if status_code == 200 and endpoint is not None:
                ep_base = endpoint.split("?")[0]
                now = time.time()
                with self._lock:
                    last_time = self._endpoint_log_times.get(ep_base, 0.0)
                    last_status = self._last_status_per_endpoint.get(ep_base)
                    if last_status == 200 and (now - last_time < self._heartbeat):
                        return False
                    self._endpoint_log_times[ep_base] = now
                    self._last_status_per_endpoint[ep_base] = 200
                return True

            if endpoint is not None:
                ep_base = endpoint.split("?")[0]
                with self._lock:
                    self._endpoint_log_times[ep_base] = time.time()
                    if status_code is not None:
                        self._last_status_per_endpoint[ep_base] = status_code
            return True
        except Exception:
            return True


_uv_access_filter = _SuppressDuplicate200Filter()
_logging.getLogger("uvicorn.access").addFilter(_uv_access_filter)


@_contextlib.asynccontextmanager
async def _wft_lifespan(_app: FastAPI):
    try:
        import gc as _gc
        import uvicorn.config as _uv_cfg
        for _obj in _gc.get_objects():
            if isinstance(_obj, _uv_cfg.Config):
                if int(getattr(_obj, "timeout_keep_alive", 5) or 5) < 600:
                    _obj.timeout_keep_alive = 600
    except Exception:
        pass
    try:
        _acc_log = _logging.getLogger("uvicorn.access")
        _acc_log.addFilter(_uv_access_filter)
        for _h in _acc_log.handlers:
            _h.addFilter(_uv_access_filter)
    except Exception:
        pass
    yield


app = FastAPI(
    title="Windows Forensic Toolkit (WFT) API",
    description="Enterprise Windows Digital Forensics & Incident Response REST API (WFT)",
    version="1.0.0",
    lifespan=_wft_lifespan,
)


_http_req_lock = threading.Lock()
_active_http_requests = 0
_pre_http_open_db_keys: set[str] = set()
_pre_http_snapshot_taken = False
_idle_release_timer: Optional[threading.Timer] = None
_IDLE_DB_RELEASE_DELAY_SEC = 1.5


def _release_transient_http_db_connections() -> None:
    """
    Close transient DuckDB connections opened during HTTP requests for idle cases
    (not in _running_cases and not pre-opened by direct Python test fixtures),
    preventing lingering OS file locks on case.duckdb when deleting case folders in Windows Explorer.
    """
    try:
        with _http_req_lock:
            if _active_http_requests > 0:
                return
        with _running_cases_lock:
            running_cids = set(_running_cases)
        running_db_keys: set[str] = set()
        for rcid in running_cids:
            try:
                _, r_key = DuckDBManager._resolve_db_key(rcid)
                running_db_keys.add(r_key)
            except Exception:
                pass

        with DuckDBManager._instance_lock:
            candidate_keys = [
                k
                for k in list(DuckDBManager._connections.keys())
                if k not in _pre_http_open_db_keys and k not in running_db_keys
            ]
            lock_pairs = [
                (k, DuckDBManager._case_locks.get(k))
                for k in candidate_keys
            ]

        for db_key, case_lock in lock_pairs:
            if case_lock is None:
                continue
            with _http_req_lock:
                if _active_http_requests > 0:
                    return
            acquired = case_lock.acquire(timeout=0.02)
            if not acquired:
                continue
            try:
                with DuckDBManager._instance_lock:
                    if db_key in _pre_http_open_db_keys or db_key in running_db_keys:
                        continue
                    is_ro = db_key in DuckDBManager._ro_connections or DuckDBManager._is_read_only.get(db_key, False)
                    conn = DuckDBManager._connections.pop(db_key, None)
                    DuckDBManager._is_read_only.pop(db_key, None)
                    DuckDBManager._ro_connections.discard(db_key)
                    DuckDBManager._case_threads.pop(db_key, None)
                if conn is not None:
                    try:
                        if not is_ro:
                            conn.cursor().execute("CHECKPOINT;")
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
            finally:
                case_lock.release()
    except Exception:
        pass


def _schedule_idle_db_release(delay_sec: float = _IDLE_DB_RELEASE_DELAY_SEC) -> None:
    global _idle_release_timer
    with _http_req_lock:
        if _idle_release_timer is not None:
            try:
                _idle_release_timer.cancel()
            except Exception:
                pass
            _idle_release_timer = None
        if _active_http_requests == 0:
            t = threading.Timer(delay_sec, _release_transient_http_db_connections)
            t.daemon = True
            _idle_release_timer = t
            t.start()


@app.middleware("http")
async def add_pna_and_cors_headers(request, call_next):
    global _active_http_requests, _pre_http_open_db_keys, _pre_http_snapshot_taken, _idle_release_timer
    with _http_req_lock:
        if _idle_release_timer is not None:
            try:
                _idle_release_timer.cancel()
            except Exception:
                pass
            _idle_release_timer = None
        if not _pre_http_snapshot_taken:
            _pre_http_snapshot_taken = True
            with DuckDBManager._instance_lock:
                _pre_http_open_db_keys = set(DuckDBManager._connections.keys())
        _active_http_requests += 1
    try:
        if request.method == "OPTIONS":
            response = JSONResponse(content={})
        else:
            response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
        if request.headers.get("access-control-request-private-network") == "true":
            response.headers["Access-Control-Allow-Private-Network"] = "true"
        return response
    finally:
        should_schedule = False
        with _http_req_lock:
            _active_http_requests = max(0, _active_http_requests - 1)
            if _active_http_requests == 0:
                should_schedule = True
        if should_schedule:
            _schedule_idle_db_release()


app.add_middleware(ForensicSecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8765", "http://localhost:8765", "http://127.0.0.1:8080", "http://localhost:8080", "http://127.0.0.1:8000", "http://localhost:8000", "http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", summary="Fast health check endpoint")
def health_check():
    return {
        "status": "ok",
        "app": "WFT",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------------
class ProcessCaseRequest(BaseModel):
    case_name: str = Field(..., min_length=1, max_length=200, description="Human-readable case name")
    case_number: Optional[str] = Field("", description="Optional case number")
    examiner: Optional[str] = Field("", description="Optional examiner name")
    notes: Optional[str] = Field("", description="Optional case notes")
    source_type: Optional[str] = Field(None, description="Type of evidence source")
    source_path: Optional[str] = Field(None, description="Path to folder or raw disk image")
    target_dir: Optional[str] = Field(None, description="Custom target folder for case DuckDB and evidence staging")
    enable_yara: Optional[bool] = Field(None, description="Enable YARA-X malware scanning")
    enable_ioc: Optional[bool] = Field(None, description="Enable IOC scanning")
    enable_ocr: Optional[bool] = Field(None, description="Enable RapidOCR text extraction")
    enable_stinger: Optional[bool] = Field(None, description="Enable Trellix Stinger AV scanning")
    enable_hindsight: Optional[bool] = Field(None, description="Enable Hindsight browser forensics")
    enable_data_carving: Optional[bool] = Field(None, description="Enable unallocated/deleted file carving")
    enable_carving: Optional[bool] = Field(None, description="Alias for enable_data_carving")
    enable_bulk_extractor: Optional[bool] = Field(None, description="Enable bulk_extractor feature scanner")
    enable_vss: Optional[bool] = Field(None, description="Enable Volume Shadow Copy enumeration")
    max_workers: Optional[int] = Field(None, description="Worker thread count (clamped 1..32)")
    selected_artifacts: Optional[List[str]] = Field(None, description="Optional selected artifact IDs")
    initial_keywords: Optional[List[Any]] = Field(None, description="Initial keywords (strings or dicts)")
    keywords: List[str] = Field(default_factory=list, description="Keywords configured in WFT Process")
    case_id: Optional[str] = Field(None, description="Optional custom case ID")
    run_async: bool = Field(True, description="Run pipeline in background task if True")


class KeywordAddRequest(BaseModel):
    keywords: List[Any] = Field(default_factory=list, description="List of keywords to search")
    source_file: Optional[str] = Field(None, description="Optional source file or label")
    is_regex: bool = Field(False, description="Whether the keywords should be treated as regex patterns")
    case_sensitive: bool = Field(False, description="Whether literal matching is case-sensitive")
    category: Optional[str] = Field("General", description="Keyword category/tag")


class BookmarkCreateRequest(BaseModel):
    source_table: str = Field(..., description="Artifact table name where evidence was found")
    source_row_id: int = Field(..., description="Row identifier in source table")
    tag_name: str = Field(..., description="Tag label")
    examiner_notes: Optional[str] = Field(None, description="Examiner notes or analysis findings")
    bookmark_id: Optional[str] = Field(None, description="Optional unique bookmark ID")


class SaveToFolderRequest(BaseModel):
    file_path: Optional[str] = Field(None, description="Path to evidence file or directory")
    folder_path: Optional[str] = Field(None, description="Optional folder path (implies is_folder=True)")
    path: Optional[str] = Field(None, description="Alias for file_path")
    source_path: Optional[str] = Field(None, description="Alias for file_path")
    destination_dir: Optional[str] = Field(None, description="Headless destination directory path")
    destination_folder: Optional[str] = Field(None, description="Alias for destination_dir")
    dest_dir: Optional[str] = Field(None, description="Alias for destination_dir")
    is_folder: bool = Field(False, description="Whether the target is a folder")
    table_name: Optional[str] = Field(None, description="Artifact table name")
    row_id: Optional[Union[int, str]] = Field(None, description="Row identifier")


class ToolPathsUpdateRequest(BaseModel):
    paths: Dict[str, str] = Field(..., description="Mapping of environment variable keys to directory or file paths")


class AutoSetupToolsRequest(BaseModel):
    skip_full_disk_scan: bool = Field(False, description="Skip full disk scan during auto-setup")
    force_update: bool = Field(False, description="Force re-download/update of tools")


class MalwareScanRequest(BaseModel):
    enable_yara: bool = Field(True, description="Enable YARA-X scanning")
    enable_stinger: bool = Field(True, description="Enable Trellix Stinger AV scanning")
    enable_ocr: bool = Field(False, description="Enable RapidOCR scanning")


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def escape_ilike(val: str) -> str:
    """Escape \\, %, and _ for DuckDB `ILIKE ? ESCAPE '\\'` queries."""
    return str(val).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_list_param(raw: Optional[Union[str, List[Any]]]) -> List[str]:
    """Parse JSON array '["a","b"]', pipe, or comma-separated query param into clean non-empty strings."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [str(x).strip() for x in raw if str(x).strip()]
    s = str(raw).strip()
    if not s:
        return []
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass
    sep = "|" if ("|" in s and "," not in s) else ","
    return [part.strip() for part in s.split(sep) if part.strip()]


def normalize_utc_bound(val: Optional[str], is_end: bool = False) -> Optional[str]:
    """Normalize ISO-8601 ('2026-01-02T03:04:05Z', '+00:00', or 'YYYY-MM-DD') to naive UTC timestamp string."""
    if not val or not str(val).strip():
        return None
    s = str(val).strip()
    if len(s) == 10 and re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return f"{s} 23:59:59.999999" if is_end else f"{s} 00:00:00"
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return s.replace("T", " ").rstrip("Z")


def _filter_kwargs_for_callable(fn: Callable[..., Any], candidate_kwargs: Dict[str, Any]) -> Dict[str, Any]:
    sig = inspect.signature(fn)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return dict(candidate_kwargs)
    return {k: v for k, v in candidate_kwargs.items() if k in sig.parameters}


def _normalize_canonical_category(raw_cat: Any) -> str:
    """Normalize category names to CANONICAL_CATEGORIES (mapping legacy 'EMAIL' -> 'EMAIL & CALENDAR')."""
    s = str(raw_cat or "").strip()
    if not s:
        return "OPERATING SYSTEM"
    if s.upper() in ("EMAIL", "EMAIL & CALENDAR", "EMAIL_AND_CALENDAR"):
        return "EMAIL & CALENDAR"
    return s


def _sql_coalesce_present_cols(
    present_cols: set[str],
    candidates: List[str],
    fallback_sql: str = "NULL",
    cast_as: Optional[str] = None,
    nullif_empty: bool = False,
) -> str:
    """Build a DuckDB-safe COALESCE(...) referencing ONLY columns actually present in present_cols."""
    col_exprs: List[str] = []
    for c in candidates:
        if c in present_cols:
            col_exprs.append(f"NULLIF({c}, '')" if nullif_empty else c)
    if not col_exprs:
        base = fallback_sql
    elif fallback_sql == "NULL":
        base = col_exprs[0] if len(col_exprs) == 1 else f"COALESCE({', '.join(col_exprs)})"
    else:
        base = f"COALESCE({', '.join(col_exprs)}, {fallback_sql})"
    if cast_as and base != "NULL":
        return f"CAST({base} AS {cast_as})"
    return base


def _validate_existing_table_or_raise(case_id: str, raw_table_name: Optional[str]) -> str:
    """Validate SQL identifier strictly (400 on invalid chars) and verify table existence in DuckDB (404 if missing)."""
    t_str = str(raw_table_name or "")
    if not t_str or not re.fullmatch(r"[A-Za-z0-9_]+", t_str):
        raise HTTPException(status_code=400, detail="Invalid table name")
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tbl_map = {
            str(r[0]).lower(): str(r[0])
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
            if r and r[0]
        }
    actual_tbl = tbl_map.get(t_str.lower())
    if not actual_tbl:
        raise HTTPException(status_code=404, detail="Table not found")
    return actual_tbl


def _ensure_bookmarks_table_canonical(cursor: duckdb.DuckDBPyConnection) -> None:
    """Ensure bookmarks table uses the canonical schema from backend/db/schema.py:96-103."""
    tables = {
        r[0]
        for r in cursor.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
        ).fetchall()
    }
    if "bookmarks" in tables:
        cols = {r[1] for r in cursor.execute("PRAGMA table_info('bookmarks');").fetchall()}
        if "source_table" not in cols:
            cnt = cursor.execute("SELECT COUNT(*) FROM bookmarks;").fetchone()[0]
            if cnt == 0:
                cursor.execute("DROP TABLE bookmarks;")
                tables.discard("bookmarks")
    if "bookmarks" not in tables:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookmarks (
                bookmark_id VARCHAR PRIMARY KEY,
                source_table VARCHAR NOT NULL,
                source_row_id BIGINT NOT NULL,
                tag_name VARCHAR NOT NULL,
                examiner_notes VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def _normalize_keyword_specs(
    raw_items: Optional[List[Any]],
    default_is_regex: bool = False,
    default_case_sensitive: bool = False,
    default_category: str = "General",
    default_source: str = "WFT Process",
) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    seen_keys: set[Tuple[str, bool, bool]] = set()
    for item in raw_items or []:
        if isinstance(item, dict):
            kw_raw = item.get("keyword") or item.get("term") or item.get("pattern") or ""
            kw_str = str(kw_raw).strip()
            is_rx = bool(item.get("is_regex", default_is_regex))
            is_cs = bool(item.get("case_sensitive", default_case_sensitive))
            cat = str(item.get("category") or item.get("tag") or default_category).strip() or "General"
            src = str(item.get("source_file") or default_source).strip() or default_source
        else:
            kw_str = str(item or "").strip()
            is_rx = bool(default_is_regex)
            is_cs = bool(default_case_sensitive)
            cat = default_category or "General"
            src = default_source or "WFT Process"
        if not kw_str:
            continue
        dedupe_k = (kw_str, is_rx, is_cs)
        if dedupe_k in seen_keys:
            continue
        seen_keys.add(dedupe_k)
        normalized.append({
            "keyword": kw_str,
            "is_regex": is_rx,
            "case_sensitive": is_cs,
            "category": cat,
            "source_file": src,
        })
    return normalized


def _ensure_case_keywords_columns(cursor: duckdb.DuckDBPyConnection) -> set[str]:
    tables = {
        r[0]
        for r in cursor.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
        ).fetchall()
    }
    if "case_keywords" not in tables:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS case_keywords (
                keyword_id VARCHAR PRIMARY KEY,
                keyword VARCHAR UNIQUE,
                is_regex BOOLEAN DEFAULT FALSE,
                source_file VARCHAR,
                hit_count BIGINT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
    cols = {r[1] for r in cursor.execute("PRAGMA table_info('case_keywords');").fetchall()}
    if "case_sensitive" not in cols:
        cursor.execute("ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS case_sensitive BOOLEAN DEFAULT FALSE;")
        cols.add("case_sensitive")
    if "is_case_sensitive" not in cols:
        cursor.execute("ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS is_case_sensitive BOOLEAN DEFAULT FALSE;")
        cols.add("is_case_sensitive")
    if "category" not in cols:
        cursor.execute("ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS category VARCHAR DEFAULT 'General';")
        cols.add("category")
    if "source_file" not in cols:
        cursor.execute("ALTER TABLE case_keywords ADD COLUMN IF NOT EXISTS source_file VARCHAR DEFAULT 'Manual';")
        cols.add("source_file")
    return cols


def _upsert_case_keywords(
    cursor: duckdb.DuckDBPyConnection,
    specs: List[Dict[str, Any]],
    ensure_schema: bool = True,
) -> None:
    if not specs:
        return
    if ensure_schema:
        _ensure_case_keywords_columns(cursor)
    for spec in specs:
        kw_str = spec["keyword"]
        existing = cursor.execute(
            "SELECT keyword_id FROM case_keywords WHERE keyword = ? LIMIT 1;",
            [kw_str],
        ).fetchone()
        if existing:
            cursor.execute(
                """
                UPDATE case_keywords
                SET is_regex = ?,
                    case_sensitive = ?,
                    is_case_sensitive = ?,
                    category = COALESCE(NULLIF(?, ''), category),
                    source_file = COALESCE(NULLIF(?, ''), source_file)
                WHERE keyword_id = ?;
                """,
                [
                    bool(spec["is_regex"]),
                    bool(spec["case_sensitive"]),
                    bool(spec["case_sensitive"]),
                    spec.get("category") or "General",
                    spec.get("source_file") or "Manual",
                    existing[0],
                ],
            )
        else:
            kw_id = f"kw_{uuid.uuid4().hex[:12]}"
            cursor.execute(
                """
                INSERT INTO case_keywords (
                    keyword_id, keyword, is_regex, case_sensitive, is_case_sensitive, category, source_file, hit_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP);
                """,
                [
                    kw_id,
                    kw_str,
                    bool(spec["is_regex"]),
                    bool(spec["case_sensitive"]),
                    bool(spec["case_sensitive"]),
                    spec.get("category") or "General",
                    spec.get("source_file") or "Manual",
                ],
            )


def _norm_kw_doc_path_key(raw_sf: Any) -> str:
    """Normalize evidence/staged file path for cross-source keyword hit deduplication."""
    s = str(raw_sf or "").strip().replace("/", "\\").lower()
    if s.startswith("[staged]"):
        s = s[8:].strip().lstrip("\\")
    elif s.startswith("[carved]"):
        s = s[8:].strip().lstrip("\\")
    if len(s) >= 2 and s[1] == ":":
        s = s[2:].lstrip("\\")
    m_stg = re.search(r"\\staging\\(?:enrichment\\|documents\\)?(.+)$", "\\" + s)
    if m_stg:
        s = m_stg.group(1).lstrip("\\")
    if s.startswith("userfiles\\"):
        s = "users\\" + s[10:]
    return s.strip("\\")


def _kw_paths_refer_same_file(p_a: str, p_b: str) -> bool:
    if not p_a or not p_b:
        return False
    return p_a == p_b or p_a.endswith("\\" + p_b) or p_b.endswith("\\" + p_a)


def _deduplicate_keyword_hits_in_db(case_id: str) -> Optional[int]:
    """Idempotently deduplicate text-document vs raw_staged_file hits in parsed_keyword_hits and sync hit_count."""
    deduped_total: Optional[int] = None
    try:
        with DuckDBManager.get_lock(case_id):
            is_ro = case_id not in globals().get("_running_cases", set())
            conn = DuckDBManager.get_connection(case_id, read_only=is_ro)
            cursor = conn.cursor()
            tables = {
                r[0]
                for r in cursor.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            if "parsed_keyword_hits" in tables:
                rows = cursor.execute(
                    """
                    SELECT _row_id, keyword_id, source_table, source_row_id, matched_column, match_offset, source_file
                    FROM parsed_keyword_hits
                    ORDER BY _row_id ASC;
                    """
                ).fetchall()
                doc_tables = {"parsed_text_documents", "docs_txt", "view_docs_txt", "view_documents"}
                staged_tables = {"raw_staged_file", "staged_file"}
                doc_paths_by_kw: Dict[str, List[str]] = {}
                seen_doc_row_offsets: set[Tuple[str, str, int, int]] = set()
                drop_ids: List[int] = []

                for rid, kw_id, s_tbl, s_rid, _m_col, m_off, s_file in rows:
                    kw_k = str(kw_id or "")
                    tbl_k = str(s_tbl or "")
                    if tbl_k in doc_tables:
                        ro_key = (kw_k, tbl_k, int(s_rid or 0), int(m_off or 0))
                        if ro_key in seen_doc_row_offsets:
                            drop_ids.append(int(rid))
                            continue
                        seen_doc_row_offsets.add(ro_key)
                        norm_p = _norm_kw_doc_path_key(s_file)
                        if norm_p:
                            doc_paths_by_kw.setdefault(kw_k, []).append(norm_p)

                if doc_paths_by_kw:
                    for rid, kw_id, s_tbl, _s_rid, _m_col, _m_off, s_file in rows:
                        if int(rid) in drop_ids:
                            continue
                        kw_k = str(kw_id or "")
                        tbl_k = str(s_tbl or "")
                        if tbl_k in staged_tables and kw_k in doc_paths_by_kw:
                            norm_raw = _norm_kw_doc_path_key(s_file)
                            if norm_raw and any(
                                _kw_paths_refer_same_file(dp, norm_raw) for dp in doc_paths_by_kw[kw_k]
                            ):
                                drop_ids.append(int(rid))

                if drop_ids:
                    if is_ro:
                        conn = DuckDBManager.get_connection(case_id, read_only=False)
                        cursor = conn.cursor()
                    phs = ", ".join(["?"] * len(drop_ids))
                    cursor.execute(f"DELETE FROM parsed_keyword_hits WHERE _row_id IN ({phs});", drop_ids)
                    if "case_keywords" in tables:
                        cursor.execute(
                            """
                            UPDATE case_keywords
                            SET hit_count = COALESCE(
                                (SELECT COUNT(*) FROM parsed_keyword_hits p WHERE p.keyword_id = case_keywords.keyword_id),
                                0
                            );
                            """
                        )
                    deduped_total = int(cursor.execute("SELECT COUNT(*) FROM parsed_keyword_hits;").fetchone()[0] or 0)
                    if "artifact_registry" in tables:
                        cursor.execute(
                            "UPDATE artifact_registry SET row_count = ? WHERE artifact_id = 'keyword_hits' OR table_name = 'view_keyword_hits';",
                            [deduped_total],
                        )
    except Exception as dedup_err:
        print(f"[_deduplicate_keyword_hits_in_db] Warning deduplicating keyword hits for '{case_id}': {dedup_err}")
    return deduped_total


def _scan_keywords_safe(case_id: str) -> Dict[str, Any]:
    """Run wildcard-safe keyword hit scan across DuckDB tables and staged files, deduplicating text doc vs staged hits."""
    res = scan_keywords_for_case(case_id)
    deduped_total = _deduplicate_keyword_hits_in_db(case_id)
    if isinstance(res, dict):
        if deduped_total is not None:
            res["total_hits"] = deduped_total
        return res
    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "total_hits": deduped_total if deduped_total is not None else (int(res) if isinstance(res, int) else 0),
    }


def _persist_case_intake_metadata_and_keywords(
    case_id: str,
    meta_dict: Dict[str, Any],
    keyword_specs: List[Dict[str, Any]],
    close_after: bool = False,
) -> None:
    with DuckDBManager.get_lock(case_id):
        init_case_db(case_id)
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS case_metadata (
                key VARCHAR PRIMARY KEY,
                value VARCHAR
            );
            """
        )
        meta_cols = {r[1] for r in cursor.execute("PRAGMA table_info('case_metadata');").fetchall()}
        if keyword_specs:
            _ensure_case_keywords_columns(cursor)
        now_ts = datetime.now(timezone.utc).replace(tzinfo=None)
        has_updated_at = "updated_at" in meta_cols
        cursor.execute("BEGIN TRANSACTION;")
        try:
            if meta_dict:
                if has_updated_at:
                    meta_params = [
                        [
                            str(k),
                            "" if v is None else (json.dumps(v) if isinstance(v, (list, dict)) else str(v)),
                            now_ts,
                            now_ts,
                        ]
                        for k, v in meta_dict.items()
                    ]
                    cursor.executemany(
                        """
                        INSERT INTO case_metadata (key, value, updated_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = ?;
                        """,
                        meta_params,
                    )
                else:
                    meta_params = [
                        [
                            str(k),
                            "" if v is None else (json.dumps(v) if isinstance(v, (list, dict)) else str(v)),
                        ]
                        for k, v in meta_dict.items()
                    ]
                    cursor.executemany(
                        """
                        INSERT INTO case_metadata (key, value)
                        VALUES (?, ?)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
                        """,
                        meta_params,
                    )
            if keyword_specs:
                _upsert_case_keywords(cursor, keyword_specs, ensure_schema=False)
            cursor.execute("COMMIT;")
            if close_after:
                try:
                    cursor.execute("CHECKPOINT;")
                except Exception:
                    pass
                DuckDBManager.close_connection(case_id)
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            if close_after:
                try:
                    DuckDBManager.close_connection(case_id)
                except Exception:
                    pass
            raise


def _invoke_pipeline_compat(
    case_id: str,
    target_dir: Optional[str],
    run_kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    global ProcessingPipeline
    if ProcessingPipeline is None:
        from backend.orchestrator.pipeline import ProcessingPipeline as _PP
        ProcessingPipeline = _PP
    init_candidates = {
        "case_id": case_id,
        "target_dir": target_dir,
        "max_workers": run_kwargs.get("max_workers"),
    }
    filtered_init = _filter_kwargs_for_callable(ProcessingPipeline.__init__, init_candidates)
    pipeline = ProcessingPipeline(**filtered_init)
    filtered_run = _filter_kwargs_for_callable(pipeline.run, run_kwargs)
    return pipeline.run(**filtered_run)


def serialize_db_value(val: Any) -> Any:
    if isinstance(val, (datetime, date)):
        return val.isoformat()
    return val


def serialize_rows(columns: List[str], raw_rows: List[tuple]) -> List[Dict[str, Any]]:
    result = []
    for row in raw_rows:
        row_dict = {}
        for col_name, val in zip(columns, row):
            row_dict[col_name] = serialize_db_value(val)
        result.append(row_dict)
    return result


def sanitize_case_id(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_\-]", "_", name.strip())
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug or f"case_{int(datetime.now().timestamp())}"


def ensure_case_exists(
    case_id: str,
    auto_create: bool = False,
    read_only: Optional[bool] = None,
) -> duckdb.DuckDBPyConnection:
    db_path = get_case_db_path(case_id)
    if not db_path.exists():
        if auto_create:
            init_case_db(case_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case '{case_id}' database does not exist at {db_path}.",
            )
    if auto_create:
        eff_ro = False
    elif read_only is None:
        eff_ro = case_id not in globals().get("_running_cases", set())
    else:
        eff_ro = bool(read_only)
    return DuckDBManager.get_connection(case_id, read_only=eff_ro)


# ---------------------------------------------------------------------------
# 0. Cases Listing & Deletion
# ---------------------------------------------------------------------------
@app.get("/api/cases", summary="List all cases in the cases directory")
def list_cases() -> Dict[str, Any]:
    """
    Scan registered custom locations and CASES_DIR, deduplicating by resolved path
    and filtering out empty 0-row phantom target folders.
    """
    cases_list = []
    seen_paths = set()
    seen_cids = set()
    entries_to_check: List[tuple] = []
    active_cases_dir = Path(getattr(_cfg, "CASES_DIR", CASES_DIR)).resolve()

    for cid, cpath_str in get_registered_custom_cases().items():
        cp = Path(cpath_str).resolve()
        path_key = str(cp).lower()
        if cp.is_dir() and (cp / "case.duckdb").exists() and path_key not in seen_paths:
            entries_to_check.append((cid, cp))
            seen_paths.add(path_key)
            seen_cids.add(cid.lower())
            seen_cids.add(cp.name.lower())

    check_dirs = [active_cases_dir]
    tool_cases = (_cfg.BASE_DIR / "cases").resolve()
    if not os.environ.get("WFT_CASES_DIR") and tool_cases.exists() and tool_cases != active_cases_dir:
        check_dirs.append(tool_cases)

    for c_dir in check_dirs:
        if c_dir.is_dir():
            for case_entry in sorted(c_dir.iterdir()):
                if case_entry.is_dir():
                    resolved_entry = case_entry.resolve()
                    path_key = str(resolved_entry).lower()
                    cid = case_entry.name
                    if path_key in seen_paths or cid.lower() in seen_cids:
                        continue
                    if (resolved_entry / "case.duckdb").exists():
                        entries_to_check.append((cid, resolved_entry))
                        seen_paths.add(path_key)
                        seen_cids.add(cid.lower())

            if c_dir == tool_cases:
                try:
                    if not any(tool_cases.iterdir()):
                        tool_cases.rmdir()
                except Exception:
                    pass

    for cid, case_entry in entries_to_check:
        db_path = case_entry / "case.duckdb"
        has_db = db_path.exists()
        db_size = db_path.stat().st_size if has_db else 0
        stat_info = case_entry.stat()
        created_ts = datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc).isoformat()
        modified_ts = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat()

        total_artifacts = 0
        timeline_count = 0
        connections_count = 0
        has_case_activity = False

        is_running_cid = cid in _running_cases or get_job_status(cid).get("status") == "RUNNING"
        if is_running_cid:
            has_case_activity = True
        elif has_db:
            case_lk = DuckDBManager.get_lock(cid)
            acquired = case_lk.acquire(timeout=0.05)
            if not acquired:
                has_case_activity = True
            else:
                was_open_before = DuckDBManager.has_connection(cid)
                try:
                    conn = DuckDBManager.get_connection(cid, read_only=True)
                    cursor = conn.cursor()
                    existing_tables = {
                        r[0]
                        for r in cursor.execute(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
                        ).fetchall()
                    }
                    if "artifact_registry" in existing_tables:
                        reg_res = cursor.execute(
                            "SELECT COALESCE(SUM(row_count), 0) FROM artifact_registry WHERE row_count > 0;"
                        ).fetchone()
                        total_artifacts = int(reg_res[0] or 0) if reg_res else 0
                    if "master_timeline" in existing_tables:
                        tl_res = cursor.execute("SELECT COUNT(*) FROM master_timeline;").fetchone()
                        timeline_count = int(tl_res[0] or 0) if tl_res else 0
                    if "entity_connections" in existing_tables:
                        ent_res = cursor.execute("SELECT COUNT(*) FROM entity_connections;").fetchone()
                        connections_count = int(ent_res[0] or 0) if ent_res else 0
                    if "processing_logs" in existing_tables:
                        log_cnt = cursor.execute("SELECT COUNT(*) FROM processing_logs;").fetchone()
                        if log_cnt and int(log_cnt[0] or 0) > 0:
                            has_case_activity = True
                    if "case_metadata" in existing_tables:
                        meta_cnt = cursor.execute("SELECT COUNT(*) FROM case_metadata;").fetchone()
                        if meta_cnt and int(meta_cnt[0] or 0) > 0:
                            has_case_activity = True
                except Exception as ex:
                    print(f"[API] Warning reading metadata for case {cid}: {ex}")
                finally:
                    if not was_open_before and not is_running_cid:
                        try:
                            DuckDBManager.close_connection(cid)
                        except Exception:
                            pass
                    case_lk.release()

        # Skip and clean up empty 0-row phantom target folders that have never processed a case
        job_state = get_job_status(cid).get("status")
        if (
            total_artifacts == 0
            and timeline_count == 0
            and not has_case_activity
            and job_state != "RUNNING"
            and cid not in _running_cases
        ):
            try:
                DuckDBManager.close_connection(cid)
                unregister_case_dir(cid)
            except Exception:
                pass
            continue

        cases_list.append({
            "case_id": cid,
            "case_path": str(case_entry.resolve()),
            "has_db": has_db,
            "db_size_bytes": db_size,
            "created_at": created_ts,
            "modified_at": modified_ts,
            "total_artifact_rows": total_artifacts,
            "timeline_count": timeline_count,
            "connections_count": connections_count,
        })

    cases_list.sort(key=lambda c: (c["has_db"], c["total_artifact_rows"]), reverse=True)
    return {"cases": cases_list, "total_cases": len(cases_list)}


_running_cases: set[str] = set()
_running_cases_lock = threading.Lock()


def _terminate_case_subprocesses(clean_cid: str, dirs_to_delete: List[Path]) -> None:
    """Terminate any lingering forensic tool child processes locking files inside dirs_to_delete."""
    try:
        import psutil
        dir_prefixes = [str(d.resolve()).lower() for d in dirs_to_delete if d]
        cid_low = clean_cid.lower()
        curr_proc = psutil.Process(os.getpid())
        for child in curr_proc.children(recursive=True):
            try:
                cmdline_str = " ".join(child.cmdline() or []).lower()
                cwd_str = ""
                try:
                    cwd_str = (child.cwd() or "").lower()
                except Exception:
                    pass
                matched = False
                for dp in dir_prefixes:
                    if dp and (dp in cmdline_str or dp in cwd_str):
                        matched = True
                        break
                if not matched and f"\\{cid_low}\\" in cmdline_str:
                    matched = True
                if matched:
                    child.kill()
                    try:
                        child.wait(timeout=1.5)
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass


def _clear_tree_readonly_attributes(root_dir: Path) -> None:
    """Recursively clear Windows Read-Only/System/Hidden attributes on all files and directories."""
    if not root_dir.exists():
        return
    win32_set_attr = getattr(getattr(ctypes, "windll", None), "kernel32", None) if sys.platform == "win32" else None
    for cur_root, dirs, files in os.walk(root_dir, topdown=False):
        for name in files:
            fp = os.path.join(cur_root, name)
            try:
                if win32_set_attr is not None:
                    win32_set_attr.SetFileAttributesW(str(fp), 0x80)
                os.chmod(fp, 0o600)
            except Exception:
                pass
        for name in dirs:
            dp = os.path.join(cur_root, name)
            try:
                if win32_set_attr is not None:
                    win32_set_attr.SetFileAttributesW(str(dp), 0x80)
                os.chmod(dp, 0o700)
            except Exception:
                pass
    try:
        if win32_set_attr is not None:
            win32_set_attr.SetFileAttributesW(str(root_dir), 0x80)
        os.chmod(str(root_dir), 0o700)
    except Exception:
        pass


@app.delete("/api/cases/{case_id}", summary="Delete an entire case and its storage cleanly")
def delete_case(case_id: str) -> Dict[str, Any]:
    clean_cid = case_id.strip()
    if not clean_cid or ".." in clean_cid or "/" in clean_cid or "\\" in clean_cid:
        raise HTTPException(status_code=400, detail="Invalid case_id")

    # 1. Mark case deleted immediately so background worker threads cannot resurrect case.duckdb or processing.log
    try:
        DuckDBManager.mark_case_deleted(clean_cid)
    except Exception as ex:
        print(f"[delete_case] Warning marking/closing DuckDB connection for {clean_cid}: {ex}")

    with _running_cases_lock:
        _running_cases.discard(clean_cid)

    with IMAGE_READ_LOCK:
        _IMAGE_TARGET_CACHE.pop(clean_cid, None)
    try:
        from backend.orchestrator.pipeline import PIPELINE_JOBS
        PIPELINE_JOBS.pop(clean_cid, None)
    except Exception:
        pass

    active_cases_dir = Path(getattr(_cfg, "CASES_DIR", CASES_DIR)).resolve()
    dirs_to_delete: List[Path] = []
    try:
        primary_dir = get_case_dir(clean_cid, create_if_missing=False)
        if primary_dir and primary_dir.exists() and primary_dir.is_dir():
            dirs_to_delete.append(primary_dir.resolve())
    except Exception:
        pass

    fallback_cases_dir = (active_cases_dir / clean_cid).resolve()
    if fallback_cases_dir.exists() and fallback_cases_dir.is_dir() and fallback_cases_dir not in dirs_to_delete:
        dirs_to_delete.append(fallback_cases_dir)

    if not os.environ.get("WFT_CASES_DIR"):
        desktop_case = (Path.home() / "Desktop" / "cases" / clean_cid).resolve()
        if desktop_case.exists() and desktop_case.is_dir() and desktop_case not in dirs_to_delete:
            dirs_to_delete.append(desktop_case)

    try:
        custom_cases = get_registered_custom_cases()
        if clean_cid in custom_cases:
            cp = Path(custom_cases[clean_cid]).resolve()
            if cp.exists() and cp.is_dir() and cp not in dirs_to_delete:
                dirs_to_delete.append(cp)
    except Exception:
        pass

    _terminate_case_subprocesses(clean_cid, dirs_to_delete)

    import gc
    gc.collect()

    def _handle_remove_readonly(func, path, exc_info):
        try:
            if sys.platform == "win32":
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)
                except Exception:
                    pass
            os.chmod(path, 0o700 if Path(path).is_dir() else 0o600)
            time.sleep(0.05)
            func(path)
        except Exception as retry_err:
            print(f"[delete_case] Warning removing path '{path}': {retry_err}")

    deleted_paths: List[str] = []
    errors: List[str] = []

    for c_dir in dirs_to_delete:
        last_rm_err: Optional[Exception] = None
        for attempt in range(8):
            if not c_dir.exists():
                break
            try:
                DuckDBManager.close_connection(clean_cid)
                gc.collect()
                _clear_tree_readonly_attributes(c_dir)
                shutil.rmtree(c_dir, onerror=_handle_remove_readonly)
            except Exception as rm_err:
                last_rm_err = rm_err
            if c_dir.exists():
                time.sleep(0.15 * (attempt + 1))

        if not c_dir.exists():
            deleted_paths.append(str(c_dir))
        elif last_rm_err is not None:
            errors.append(f"Failed deleting '{c_dir}': {last_rm_err}")
        else:
            errors.append(f"Directory '{c_dir}' could not be deleted")

    try:
        unregister_case_dir(clean_cid)
    except Exception as unreg_err:
        print(f"[delete_case] Warning unregistering custom location for {clean_cid}: {unreg_err}")

    if errors:
        raise HTTPException(
            status_code=500,
            detail=f"Errors occurred while deleting case '{clean_cid}': {'; '.join(errors)}",
        )

    return {
        "status": "SUCCESS",
        "message": f"Case '{clean_cid}' deleted successfully",
        "deleted_case_id": clean_cid,
        "deleted_paths": deleted_paths,
    }


def safe_background_pipeline(
    case_id: str,
    target_dir: Optional[str] = None,
    run_kwargs: Optional[Dict[str, Any]] = None,
):
    try:
        if DuckDBManager.is_case_deleted(case_id):
            return
        if target_dir and str(target_dir).strip():
            register_case_dir(case_id, str(target_dir).strip())
        _invoke_pipeline_compat(
            case_id=case_id,
            target_dir=target_dir,
            run_kwargs=run_kwargs or {},
        )
    except Exception as exc:
        print(f"[Pipeline Background Job Error] Case '{case_id}': {exc}")
    finally:
        try:
            with DuckDBManager.get_lock(case_id):
                if not DuckDBManager.is_case_deleted(case_id) and DuckDBManager.has_rw_connection(case_id):
                    try:
                        DuckDBManager.get_connection(case_id, read_only=False).cursor().execute("CHECKPOINT;")
                    except Exception:
                        pass
                DuckDBManager.close_connection(case_id)
        except Exception:
            pass
        with _running_cases_lock:
            _running_cases.discard(case_id)


# ---------------------------------------------------------------------------
# 1. Processing Trigger & Status
# ---------------------------------------------------------------------------
@app.post("/api/cases/process", summary="Initiate evidence processing job")
def process_case(
    request: ProcessCaseRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    case_id = sanitize_case_id(request.case_id) if (request.case_id and request.case_id.strip()) else sanitize_case_id(request.case_name)
    DuckDBManager.unmark_case_deleted(case_id)
    clean_source = request.source_path.strip().strip('"').strip("'").strip() if (request.source_path and request.source_path.strip()) else None
    clean_target = request.target_dir.strip().strip('"').strip("'").strip() if (request.target_dir and request.target_dir.strip()) else None

    raw_stype = (request.source_type or "").strip().lower()
    if not raw_stype:
        if not clean_source:
            norm_source_type = "live_triage"
        elif Path(clean_source).exists() and Path(clean_source).is_dir():
            norm_source_type = "folder"
        else:
            norm_source_type = "image"
    elif raw_stype == "directory":
        norm_source_type = "folder"
    elif raw_stype in ("folder", "image", "live_triage"):
        norm_source_type = raw_stype
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported source_type '{request.source_type}'. Expected folder, directory, image, or live_triage.",
        )

    default_workers = 25
    try:
        clamped_workers = max(1, min(32, int(request.max_workers))) if request.max_workers is not None else default_workers
    except (TypeError, ValueError):
        clamped_workers = default_workers

    # Safe target_dir resolution: NEVER write case.duckdb or staging/ into source_path!
    default_cases_root = Path(getattr(_cfg, "CASES_DIR", CASES_DIR)).resolve()
    src_resolved: Optional[Path] = None
    if clean_source:
        src_norm_chk = clean_source.replace("/", "\\")
        if not src_norm_chk.startswith("\\\\"):
            try:
                src_resolved = Path(clean_source).resolve()
            except Exception:
                src_resolved = None

    custom_case_path = (default_cases_root / case_id).resolve()
    if clean_target:
        tgt_norm_chk = clean_target.replace("/", "\\")
        if tgt_norm_chk.startswith("\\\\"):
            raise HTTPException(status_code=400, detail="Remote UNC target_dir paths are forbidden.")
        try:
            t_path = Path(clean_target).resolve()
        except (OSError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid target_dir path.")
        if (
            t_path.name.lower() == case_id.lower()
            or not t_path.exists()
            or (t_path / "case.duckdb").exists()
            or (t_path / "rules").exists()
        ):
            candidate_path = t_path
        else:
            candidate_path = (t_path / case_id).resolve()
        pollutes_source = False
        if src_resolved is not None:
            if t_path == src_resolved or candidate_path == src_resolved:
                pollutes_source = True
            elif (src_resolved.exists() and src_resolved.is_dir()) or norm_source_type == "folder":
                try:
                    if t_path.is_relative_to(src_resolved) or candidate_path.is_relative_to(src_resolved):
                        pollutes_source = True
                except ValueError:
                    pass
        if pollutes_source:
            raise HTTPException(
                status_code=400,
                detail="target_dir must not equal or reside inside source_path",
            )
        if t_path.name.lower() != case_id.lower():
            unregister_case_dir(t_path.name)
        custom_case_path = candidate_path

    custom_case_path.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, custom_case_path)
    resolved_target_dir = str(custom_case_path)

    # Bidirectional sync between selected_artifacts and enable_* flags
    vss_ids = {"fs_vss", "vss", "volume_shadow_copies"}
    carve_ids = {"carve_files", "data_carving"}
    be_ids = {"bulk_extractor"}
    stinger_ids = {"artifact_stinger_hits", "malware_stinger_hits", "stinger", "trellix_stinger"}
    yara_ids = {"artifact_yara_hits", "malware_yara_hits", "yara", "yara_scan"}
    ocr_ids = {"artifact_ocr_results", "ocr", "rapidocr"}
    ioc_ids = {"ioc_matching", "ioc"}
    hindsight_ids = {"web_hindsight", "hindsight", "raw_hindsight"}

    fields_set = getattr(request, "model_fields_set", set())

    def _explicit_bool_flag(*fnames: str) -> Optional[bool]:
        vals = [getattr(request, fn) for fn in fnames if fn in fields_set and getattr(request, fn) is not None]
        if not vals:
            vals = [getattr(request, fn) for fn in fnames if getattr(request, fn) is not None]
        if not vals:
            return None
        return any(bool(v) for v in vals)

    if request.selected_artifacts is not None:
        sel_list = [str(a).strip() for a in request.selected_artifacts if str(a).strip()]

        def _sync_sel_flag(
            explicit_val: Optional[bool],
            aliases: set[str],
            canonical_id: str,
            default_on: bool = True,
        ) -> bool:
            nonlocal sel_list
            sel_lower = {a.lower() for a in sel_list}
            if not default_on:
                if explicit_val is True or bool(sel_lower & aliases):
                    if canonical_id.lower() not in sel_lower:
                        sel_list.append(canonical_id)
                    return True
                sel_list = [a for a in sel_list if a.lower() not in aliases]
                return False
            if explicit_val is True:
                if canonical_id.lower() not in sel_lower:
                    sel_list.append(canonical_id)
                return True
            if explicit_val is False:
                sel_list = [a for a in sel_list if a.lower() not in aliases]
                return False
            matched = bool(sel_lower & aliases)
            if matched and canonical_id.lower() not in sel_lower:
                sel_list.append(canonical_id)
            return matched

        eff_vss = _sync_sel_flag(_explicit_bool_flag("enable_vss"), vss_ids, "fs_vss", default_on=False)
        eff_carve = _sync_sel_flag(_explicit_bool_flag("enable_data_carving", "enable_carving"), carve_ids, "carve_files", default_on=False)
        eff_be = _sync_sel_flag(_explicit_bool_flag("enable_bulk_extractor"), be_ids, "bulk_extractor", default_on=False)
        eff_stinger = _sync_sel_flag(_explicit_bool_flag("enable_stinger"), stinger_ids, "artifact_stinger_hits")
        eff_yara = _sync_sel_flag(_explicit_bool_flag("enable_yara"), yara_ids, "artifact_yara_hits")
        eff_ocr = _sync_sel_flag(_explicit_bool_flag("enable_ocr"), ocr_ids, "artifact_ocr_results")
        eff_ioc = _sync_sel_flag(_explicit_bool_flag("enable_ioc"), ioc_ids, "ioc_matching")
        eff_hindsight = _sync_sel_flag(_explicit_bool_flag("enable_hindsight"), hindsight_ids, "web_hindsight")
        synced_selected_artifacts: Optional[List[str]] = sel_list
    else:
        eff_vss = bool(_explicit_bool_flag("enable_vss") or False)
        eff_carve = bool(_explicit_bool_flag("enable_data_carving", "enable_carving") or False)
        eff_be = bool(_explicit_bool_flag("enable_bulk_extractor") or False)
        exp_stinger = _explicit_bool_flag("enable_stinger")
        exp_yara = _explicit_bool_flag("enable_yara")
        exp_ocr = _explicit_bool_flag("enable_ocr")
        exp_ioc = _explicit_bool_flag("enable_ioc")
        exp_hindsight = _explicit_bool_flag("enable_hindsight")
        eff_stinger = True if exp_stinger is None else exp_stinger
        eff_yara = True if exp_yara is None else exp_yara
        eff_ocr = True if exp_ocr is None else exp_ocr
        eff_ioc = True if exp_ioc is None else exp_ioc
        eff_hindsight = True if exp_hindsight is None else exp_hindsight
        synced_selected_artifacts = None

    combined_kw_inputs: List[Any] = list(request.initial_keywords or []) + list(request.keywords or [])
    normalized_keywords = _normalize_keyword_specs(combined_kw_inputs, default_source="WFT Process")
    plain_keyword_strings = [d["keyword"] for d in normalized_keywords]

    img_size_str = ""
    if src_resolved is not None and src_resolved.exists() and src_resolved.is_file():
        try:
            img_size_str = str(src_resolved.stat().st_size)
        except Exception:
            img_size_str = ""

    created_utc_str = datetime.now(timezone.utc).isoformat()
    meta_dict: Dict[str, Any] = {
        "case_name": request.case_name,
        "case_number": (request.case_number or "").strip(),
        "examiner": (request.examiner or "").strip(),
        "notes": (request.notes or "").strip(),
        "source_path": clean_source or "",
        "source_type": norm_source_type,
        "target_dir": resolved_target_dir,
        "image_size": img_size_str,
        "sha256": "",
        "max_workers": clamped_workers,
        "enable_yara": bool(eff_yara),
        "enable_ioc": bool(eff_ioc),
        "enable_ocr": bool(eff_ocr),
        "enable_stinger": bool(eff_stinger),
        "enable_hindsight": bool(eff_hindsight),
        "enable_data_carving": bool(eff_carve),
        "enable_bulk_extractor": bool(eff_be),
        "enable_vss": bool(eff_vss),
        "selected_artifacts": synced_selected_artifacts if synced_selected_artifacts is not None else [],
        "created_utc": created_utc_str,
    }

    with _running_cases_lock:
        job_status = get_job_status(case_id)
        if case_id in _running_cases or job_status.get("status") == "RUNNING":
            return {
                "status": "RUNNING",
                "case_id": case_id,
                "case_name": request.case_name,
                "target_dir": resolved_target_dir,
                "message": f"Processing job is already in progress for case '{case_id}'.",
                "progress": job_status.get("progress", 0),
                "current_step": job_status.get("current_step", "Processing evidence..."),
            }
        _running_cases.add(case_id)

    with IMAGE_READ_LOCK:
        _IMAGE_TARGET_CACHE.pop(case_id, None)

    _persist_case_intake_metadata_and_keywords(
        case_id=case_id,
        meta_dict=meta_dict,
        keyword_specs=normalized_keywords,
    )

    pipeline_run_kwargs: Dict[str, Any] = {
        "source_type": norm_source_type,
        "source_path": clean_source,
        "enable_yara": bool(eff_yara),
        "enable_ioc": bool(eff_ioc),
        "enable_ocr": bool(eff_ocr),
        "enable_stinger": bool(eff_stinger),
        "enable_hindsight": bool(eff_hindsight),
        "enable_data_carving": bool(eff_carve),
        "enable_carving": bool(eff_carve),
        "enable_bulk_extractor": bool(eff_be),
        "enable_vss": bool(eff_vss),
        "max_workers": clamped_workers,
        "selected_artifacts": synced_selected_artifacts,
        "initial_keywords": normalized_keywords,
        "keywords": plain_keyword_strings,
        "case_metadata": meta_dict,
    }

    if request.run_async:
        try:
            from backend.orchestrator.pipeline import PIPELINE_JOBS
            PIPELINE_JOBS[case_id] = {
                "case_id": case_id,
                "status": "RUNNING",
                "progress": 5,
                "current_step": "Initializing case environment...",
                "error": None,
                "start_time": time.time(),
                "end_time": None,
            }
        except Exception:
            pass

        threading.Thread(
            target=safe_background_pipeline,
            kwargs={
                "case_id": case_id,
                "target_dir": resolved_target_dir,
                "run_kwargs": pipeline_run_kwargs,
            },
            name=f"wft-pipeline-{case_id}",
            daemon=True,
        ).start()
        return {
            "status": "RUNNING",
            "case_id": case_id,
            "case_name": request.case_name,
            "target_dir": resolved_target_dir,
            "max_workers": clamped_workers,
            "enable_yara": eff_yara,
            "enable_stinger": eff_stinger,
            "enable_ocr": eff_ocr,
            "enable_ioc": eff_ioc,
            "enable_hindsight": eff_hindsight,
            "enable_vss": eff_vss,
            "enable_data_carving": eff_carve,
            "enable_bulk_extractor": eff_be,
            "selected_artifacts": synced_selected_artifacts,
            "message": f"Processing job initiated in background for case '{case_id}'.",
        }
    else:
        try:
            pipeline_result = _invoke_pipeline_compat(
                case_id=case_id,
                target_dir=resolved_target_dir,
                run_kwargs=pipeline_run_kwargs,
            )
            # Re-persist intake metadata & keywords in case pre-M4 init_case_db ran inside pipeline
            _persist_case_intake_metadata_and_keywords(
                case_id=case_id,
                meta_dict=meta_dict,
                keyword_specs=normalized_keywords,
                close_after=True,
            )
            return {
                "status": "SUCCESS",
                "case_id": case_id,
                "case_name": request.case_name,
                "target_dir": resolved_target_dir,
                "max_workers": clamped_workers,
                "enable_yara": eff_yara,
                "enable_stinger": eff_stinger,
                "enable_ocr": eff_ocr,
                "enable_ioc": eff_ioc,
                "enable_hindsight": eff_hindsight,
                "enable_vss": eff_vss,
                "enable_data_carving": eff_carve,
                "enable_bulk_extractor": eff_be,
                "selected_artifacts": synced_selected_artifacts,
                "message": f"Processing completed successfully for case '{case_id}'.",
                "result": pipeline_result,
            }
        finally:
            try:
                with DuckDBManager.get_lock(case_id):
                    _, db_key = DuckDBManager._resolve_db_key(case_id)
                    if db_key in DuckDBManager._connections:
                        try:
                            if db_key not in DuckDBManager._ro_connections:
                                DuckDBManager.get_connection(case_id, read_only=False).cursor().execute("CHECKPOINT;")
                        except Exception:
                            pass
                        DuckDBManager.close_connection(case_id)
            except Exception:
                pass
            with _running_cases_lock:
                _running_cases.discard(case_id)


@app.get("/api/cases/{case_id}/status", summary="Get case processing status and audit logs")
def get_case_status(case_id: str) -> Dict[str, Any]:
    status_info = get_job_status(case_id)
    db_path = get_case_db_path(case_id)
    is_running = case_id in _running_cases or status_info.get("status") == "RUNNING"

    logs_list = []
    case_meta: Dict[str, Any] = {}
    if db_path.exists():
        case_lk = DuckDBManager.get_lock(case_id)
        acquired = case_lk.acquire(timeout=0.25 if is_running else 5.0)
        if acquired:
            try:
                conn = DuckDBManager.get_connection(case_id, read_only=True)
                cursor = conn.cursor()
                raw_logs = cursor.execute(
                    """
                    SELECT log_id, timestamp_utc, module_name, command_executed,
                           exit_code, rows_ingested, duration_ms, status, error_message
                    FROM processing_logs
                    ORDER BY log_id ASC;
                    """
                ).fetchall()
                log_cols = [
                    "log_id",
                    "timestamp_utc",
                    "module_name",
                    "command_executed",
                    "exit_code",
                    "rows_ingested",
                    "duration_ms",
                    "status",
                    "error_message",
                ]
                logs_list = serialize_rows(log_cols, raw_logs)
                try:
                    for mk, mv in cursor.execute("SELECT key, value FROM case_metadata;").fetchall():
                        if mk is not None and mv is not None:
                            case_meta[str(mk)] = str(mv)
                except Exception:
                    pass
            except Exception as ex:
                if not is_running:
                    print(f"[API] Error reading processing_logs for {case_id}: {ex}")
            finally:
                case_lk.release()

    return {
        "case_id": case_id,
        "case_name": case_meta.get("case_name") or case_id,
        "case_metadata": case_meta,
        "status": status_info.get("status", "UNKNOWN"),
        "progress": status_info.get("progress", 0),
        "current_step": status_info.get("current_step", ""),
        "error": status_info.get("error"),
        "start_time": status_info.get("start_time"),
        "end_time": status_info.get("end_time"),
        "logs": logs_list,
        "total_logs": len(logs_list),
    }


@app.get("/api/cases/{case_id}/logs", summary="Get structured processing logs for a case")
def get_case_logs(case_id: str, limit: int = Query(5000, ge=1, le=50000), offset: int = Query(0, ge=0)) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "processing_logs" not in tables:
            return {"case_id": case_id, "logs": [], "rows": [], "total_logs": 0, "total_count": 0}
        total = int(cursor.execute("SELECT COUNT(*) FROM processing_logs;").fetchone()[0] or 0)
        raw_logs = cursor.execute(
            """
            SELECT log_id, timestamp_utc, module_name, command_executed,
                   exit_code, rows_ingested, duration_ms, status, error_message
            FROM processing_logs
            ORDER BY log_id ASC
            LIMIT ? OFFSET ?;
            """,
            [limit, offset],
        ).fetchall()
        log_cols = [
            "log_id",
            "timestamp_utc",
            "module_name",
            "command_executed",
            "exit_code",
            "rows_ingested",
            "duration_ms",
            "status",
            "error_message",
        ]
        logs_list = serialize_rows(log_cols, raw_logs)
        return {
            "case_id": case_id,
            "logs": logs_list,
            "rows": logs_list,
            "total_logs": total,
            "total_count": total,
        }


@app.get("/api/cases/{case_id}/ioc-matches", summary="Get IOC hash/indicator matches for a case")
def get_case_ioc_matches(case_id: str, limit: int = Query(1000, ge=1, le=50000), offset: int = Query(0, ge=0)) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        matches_list: List[Dict[str, Any]] = []
        total = 0
        if "artifact_ioc_hits" in tables:
            cols = [str(r[0]) for r in cursor.execute("DESCRIBE artifact_ioc_hits;").fetchall()]
            total = int(cursor.execute("SELECT COUNT(*) FROM artifact_ioc_hits;").fetchone()[0] or 0)
            raw_rows = cursor.execute(
                "SELECT * FROM artifact_ioc_hits LIMIT ? OFFSET ?;",
                [limit, offset],
            ).fetchall()
            matches_list = serialize_rows(cols, raw_rows)
        elif "file_enrichment" in tables:
            fe_cols = [str(r[0]) for r in cursor.execute("DESCRIBE file_enrichment;").fetchall()]
            if "ioc_hit_count" in fe_cols:
                total = int(
                    cursor.execute(
                        "SELECT COUNT(*) FROM file_enrichment WHERE COALESCE(ioc_hit_count, 0) > 0;"
                    ).fetchone()[0]
                    or 0
                )
                raw_rows = cursor.execute(
                    "SELECT * FROM file_enrichment WHERE COALESCE(ioc_hit_count, 0) > 0 LIMIT ? OFFSET ?;",
                    [limit, offset],
                ).fetchall()
                matches_list = serialize_rows(fe_cols, raw_rows)
        return {
            "case_id": case_id,
            "matches": matches_list,
            "rows": matches_list,
            "total_matches": total,
            "total_count": total,
        }


# ---------------------------------------------------------------------------
# 3. Artifact Registry & Dashboard
# ---------------------------------------------------------------------------
INTERNAL_HIDDEN_REGISTRY_TABLES = {
    "parsed_media_exif",
    "parsed_documents_metadata",
    "view_all_malware_detections",
}

CANONICAL_CATEGORIES = [
    "REFINED RESULTS",
    "WEB RELATED",
    "CHAT",
    "EMAIL & CALENDAR",
    "CLOUD",
    "MEDIA",
    "DOCUMENTS",
    "EVENT LOGS",
    "OPERATING SYSTEM",
    "MALWARE & YARA",
]


def _restore_missing_core_registry_entries(
    cursor: duckdb.DuckDBPyConnection,
    tables_set: set[str],
    case_id: Optional[str] = None,
    can_write: bool = True,
) -> duckdb.DuckDBPyConnection:
    """Ensure os_evtx (raw_evtx) and registry_recmd (raw_recmd) exist in artifact_registry when populated."""
    if "artifact_registry" not in tables_set:
        return cursor
    now_ts = datetime.now(timezone.utc).replace(tzinfo=None)
    upgraded = False
    if "raw_evtx" in tables_set:
        evtx_cnt = int(cursor.execute("SELECT COUNT(*) FROM raw_evtx;").fetchone()[0] or 0)
        if evtx_cnt > 0:
            existing_evtx = cursor.execute(
                "SELECT row_count, category, table_name FROM artifact_registry WHERE artifact_id = 'os_evtx' LIMIT 1;"
            ).fetchone()
            needs_evtx_write = (
                not existing_evtx
                or int(existing_evtx[0] or 0) != evtx_cnt
                or existing_evtx[1] != "EVENT LOGS"
                or existing_evtx[2] != "raw_evtx"
            )
            if needs_evtx_write and can_write:
                if case_id and not upgraded:
                    cursor = DuckDBManager.get_connection(case_id, read_only=False).cursor()
                    upgraded = True
                cursor.execute(
                    """
                    INSERT INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES ('os_evtx', 'EVENT LOGS', 'All Event Logs', 'raw_evtx', 'EvtxECmd.exe', ?, ?)
                    ON CONFLICT (artifact_id) DO UPDATE SET
                        category = 'EVENT LOGS',
                        display_name = EXCLUDED.display_name,
                        table_name = 'raw_evtx',
                        row_count = EXCLUDED.row_count,
                        last_updated = ?;
                    """,
                    [evtx_cnt, now_ts, now_ts],
                )
    if "raw_recmd" in tables_set:
        recmd_cnt = int(cursor.execute("SELECT COUNT(*) FROM raw_recmd;").fetchone()[0] or 0)
        if recmd_cnt > 0:
            existing_recmd = cursor.execute(
                "SELECT artifact_id, row_count FROM artifact_registry WHERE table_name = 'raw_recmd' LIMIT 1;"
            ).fetchone()
            needs_recmd_write = (not existing_recmd) or (int(existing_recmd[1] or 0) != recmd_cnt)
            if needs_recmd_write and can_write:
                if case_id and not upgraded:
                    cursor = DuckDBManager.get_connection(case_id, read_only=False).cursor()
                    upgraded = True
                target_id = existing_recmd[0] if existing_recmd else "registry_recmd"
                cursor.execute(
                    """
                    INSERT INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (?, 'OPERATING SYSTEM', 'Registry Hive Batch Analysis (RECmd)', 'raw_recmd', 'RECmd.exe', ?, ?)
                    ON CONFLICT (artifact_id) DO UPDATE SET
                        table_name = 'raw_recmd',
                        row_count = EXCLUDED.row_count,
                        last_updated = ?;
                    """,
                    [target_id, recmd_cnt, now_ts, now_ts],
                )
    return cursor


def _filter_visible_registry_items(raw_artifacts_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    has_split_browser_views = any(
        str(a.get("table_name") or "").startswith("view_browser_") and int(a.get("row_count") or 0) > 0
        for a in raw_artifacts_data
    )
    seen_tables: set[str] = set()
    artifacts_data: List[Dict[str, Any]] = []
    for art in raw_artifacts_data:
        tname = str(art.get("table_name") or "")
        rc = int(art.get("row_count") or 0)
        if not tname or rc <= 0 or tname in seen_tables:
            continue
        if tname in INTERNAL_HIDDEN_REGISTRY_TABLES:
            continue
        if has_split_browser_views and tname in (
            "parsed_browser_history",
            "parsed_browser_downloads",
            "parsed_browser_logins",
        ):
            continue
        disp = str(art.get("display_name") or "")
        if "(Combined)" in disp and tname not in ("raw_evtx", "raw_recmd"):
            # Hide deprecated combined tables (e.g. legacy media/docs/chat/email combined) if split tables exist
            if tname in ("parsed_chat_messages", "parsed_cloud_files", "parsed_emails"):
                has_split_sibling = any(
                    str(x.get("table_name") or "").startswith("view_")
                    and x.get("category") == art.get("category")
                    and int(x.get("row_count") or 0) > 0
                    for x in raw_artifacts_data
                )
                if has_split_sibling:
                    continue
        if tname == "raw_evtx" and "(Combined)" in disp:
            art = dict(art)
            art["display_name"] = disp.replace(" (Combined)", "").strip() or "All Event Logs"
        else:
            art = dict(art)
        art["category"] = _normalize_canonical_category(art.get("category"))
        seen_tables.add(tname)
        artifacts_data.append(art)
    return artifacts_data


def _build_subview_dedup_predicate(artifacts_data: List[Dict[str, Any]]) -> Callable[[str], bool]:
    present_nonzero = {
        str(a.get("table_name") or "")
        for a in artifacts_data
        if int(a.get("row_count") or 0) > 0
    }
    has_raw_evtx = "raw_evtx" in present_nonzero
    has_view_docs = "view_documents" in present_nonzero
    has_raw_recmd = "raw_recmd" in present_nonzero
    recmd_slice_views = {"view_usb_devices", "view_autoruns", "view_userassist", "view_bam_dam"}

    def _is_duplicate(tname: str) -> bool:
        if has_raw_evtx and tname.startswith("view_evtx_"):
            return True
        if has_view_docs and tname.startswith("view_docs_"):
            return True
        if has_raw_recmd and tname in recmd_slice_views:
            return True
        return False

    return _is_duplicate


@app.get("/api/cases/{case_id}/registry", summary="Get populated artifact registry and super-counts")
@app.get("/api/cases/{case_id}/artifacts", include_in_schema=False)
@app.get("/api/cases/{case_id}/artifacts/tree", include_in_schema=False)
def get_artifact_registry(
    case_id: str,
    hide_empty: bool = False,
    force_sync: bool = False,
) -> Dict[str, Any]:
    status_info = get_job_status(case_id)
    pipeline_running = status_info.get("status") == "RUNNING"

    with DuckDBManager.get_lock(case_id):
        was_rw = DuckDBManager.has_rw_connection(case_id)
        if force_sync and not pipeline_running:
            conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
            cursor = conn.cursor()
            try:
                from backend.db.schema import sync_artifact_registry_counts
                sync_artifact_registry_counts(conn, case_id=case_id)
            except Exception as sync_ex:
                print(f"[API] Warning synchronizing artifact registry: {sync_ex}")
        else:
            conn = ensure_case_exists(case_id, auto_create=False)
            cursor = conn.cursor()
            try:
                reg_count = cursor.execute("SELECT COUNT(*) FROM artifact_registry;").fetchone()[0]
                if reg_count == 0 and not pipeline_running:
                    conn = DuckDBManager.get_connection(case_id, read_only=False)
                    cursor = conn.cursor()
                    from backend.db.schema import sync_artifact_registry_counts
                    sync_artifact_registry_counts(conn, case_id=case_id)
            except Exception as sync_ex:
                print(f"[API] Notice checking artifact registry: {sync_ex}")

        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        try:
            cursor = _restore_missing_core_registry_entries(
                cursor,
                tables_set,
                case_id=case_id,
                can_write=not pipeline_running,
            )
        except Exception as restore_ex:
            print(f"[API] Notice restoring core registry entries: {restore_ex}")

        query = """
            SELECT artifact_id, category, display_name, table_name,
                   source_tool, row_count, last_updated
            FROM artifact_registry
            WHERE row_count > 0
            ORDER BY category ASC, display_name ASC;
        """

        try:
            raw_artifacts = cursor.execute(query).fetchall()
        except Exception:
            init_case_db(case_id)
            cursor = DuckDBManager.get_connection(case_id, read_only=False).cursor()
            raw_artifacts = cursor.execute(query).fetchall()

        tl_row = cursor.execute("SELECT COUNT(*) FROM master_timeline;").fetchone() if "master_timeline" in tables_set else (0,)
        timeline_total = int(tl_row[0] or 0) if tl_row else 0
        ent_row = cursor.execute("SELECT COUNT(*) FROM entity_connections;").fetchone() if "entity_connections" in tables_set else (0,)
        connections_total = int(ent_row[0] or 0) if ent_row else 0
        if not was_rw and not pipeline_running and DuckDBManager.has_rw_connection(case_id):
            try:
                cursor.execute("CHECKPOINT;")
            except Exception:
                pass
            DuckDBManager.close_connection(case_id)

    reg_cols = [
        "artifact_id",
        "category",
        "display_name",
        "table_name",
        "source_tool",
        "row_count",
        "last_updated",
    ]
    raw_artifacts_data = serialize_rows(reg_cols, raw_artifacts)
    artifacts_data = _filter_visible_registry_items(raw_artifacts_data)
    is_subview_dup = _build_subview_dedup_predicate(artifacts_data)

    grouped_cats: Dict[str, List[Dict[str, Any]]] = {}
    for art in artifacts_data:
        cat = _normalize_canonical_category(art.get("category", "OPERATING SYSTEM"))
        art["category"] = cat
        if cat not in grouped_cats:
            grouped_cats[cat] = []
        grouped_cats[cat].append(art)

    category_tree = []
    for cat_name in CANONICAL_CATEGORIES:
        cat_arts = grouped_cats.pop(cat_name, [])
        cat_arts = [a for a in cat_arts if a.get("row_count", 0) > 0]
        cat_total = sum(int(a["row_count"]) for a in cat_arts if not is_subview_dup(str(a["table_name"])))
        if cat_total == 0 and cat_arts:
            cat_total = sum(int(a["row_count"]) for a in cat_arts)
        if cat_total > 0 and len(cat_arts) > 0:
            category_tree.append({
                "category": cat_name,
                "total_category_rows": cat_total,
                "artifacts": cat_arts,
            })

    for cat_name, cat_arts in sorted(grouped_cats.items()):
        cat_arts = [a for a in cat_arts if a.get("row_count", 0) > 0]
        cat_total = sum(int(a["row_count"]) for a in cat_arts if not is_subview_dup(str(a["table_name"])))
        if cat_total == 0 and cat_arts:
            cat_total = sum(int(a["row_count"]) for a in cat_arts)
        if cat_total > 0 and len(cat_arts) > 0:
            category_tree.append({
                "category": cat_name,
                "total_category_rows": cat_total,
                "artifacts": cat_arts,
            })

    all_evidence_total = sum(
        int(a["row_count"]) for a in artifacts_data if not is_subview_dup(str(a["table_name"]))
    )

    return {
        "case_id": case_id,
        "all_evidence_total": all_evidence_total,
        "all_evidence": {
            "display_name": "ALL EVIDENCE",
            "total_count": all_evidence_total,
        },
        "categories": category_tree,
        "grouped": {c["category"]: c["artifacts"] for c in category_tree},
        "artifacts": artifacts_data,
        "total_artifact_categories": len(category_tree),
        "total_artifact_tables": len(artifacts_data),
        "timeline_total": timeline_total,
        "connections_total": connections_total,
    }


def _parse_bool_flag(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off", ""):
        return False
    return default


def _format_maybe_epoch_utc(raw_val: Any) -> Optional[str]:
    if raw_val is None:
        return None
    s = str(raw_val).strip()
    if not s:
        return None
    if s.isdigit():
        try:
            epoch_val = int(s)
            if 315532800 < epoch_val < 4102444800:
                return datetime.fromtimestamp(epoch_val, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass
    return s


def _extract_os_info_waterfall(cursor: duckdb.DuckDBPyConnection, tables_set: set[str]) -> Dict[str, Any]:
    os_info: Dict[str, Any] = {
        "hostname": None,
        "os_name": None,
        "os_edition": None,
        "os_build": None,
        "install_date": None,
        "system_root": None,
        "timezone": None,
        "last_shutdown": None,
        "registered_owner": None,
        "domain_or_workgroup": None,
        "users": [],
    }
    seen_users_lower: set[str] = set()
    users_list: List[str] = []

    def _add_user(u_raw: Any) -> None:
        if u_raw is None:
            return
        for part in str(u_raw).split(","):
            u = part.strip().strip("\\")
            if "\\" in u:
                u = u.split("\\")[-1].strip()
            if not u or u.lower() in {
                "public", "default", "default user", "all users", "desktop.ini",
                "temp", "systemprofile", "localservice", "networkservice", "-", "n/a", "system",
            }:
                continue
            if u.endswith("$"):
                continue
            low = u.lower()
            if low not in seen_users_lower:
                seen_users_lower.add(low)
                users_list.append(u)

    def _set_if_empty(field: str, val: Any, is_date: bool = False) -> None:
        if os_info.get(field):
            return
        if val is None:
            return
        s = _format_maybe_epoch_utc(val) if is_date else str(val).strip()
        if s and s.lower() not in ("none", "null", "n/a"):
            os_info[field] = s

    # 1. Dedicated OS info table if present
    for tbl in ("os_system_info", "parsed_os_info"):
        if tbl in tables_set:
            try:
                cols = [r[0] for r in cursor.execute(f'DESCRIBE "{tbl}";').fetchall()]
                row = cursor.execute(f'SELECT * FROM "{tbl}" LIMIT 1;').fetchone()
                if row:
                    row_map = {cols[i].lower(): row[i] for i in range(len(cols))}
                    _set_if_empty("hostname", row_map.get("hostname") or row_map.get("computer_name") or row_map.get("computername"))
                    _set_if_empty("os_name", row_map.get("os_name") or row_map.get("product_name") or row_map.get("productname"))
                    _set_if_empty("os_edition", row_map.get("os_edition") or row_map.get("edition_id") or row_map.get("edition"))
                    _set_if_empty("os_build", row_map.get("os_build") or row_map.get("current_build") or row_map.get("build"))
                    _set_if_empty("install_date", row_map.get("install_date"), is_date=True)
                    _set_if_empty("system_root", row_map.get("system_root") or row_map.get("path_name"))
                    _set_if_empty("timezone", row_map.get("timezone") or row_map.get("time_zone"))
                    _set_if_empty("last_shutdown", row_map.get("last_shutdown") or row_map.get("shutdown_time"), is_date=True)
                    _set_if_empty("registered_owner", row_map.get("registered_owner"))
                    _set_if_empty("domain_or_workgroup", row_map.get("domain_or_workgroup") or row_map.get("domain") or row_map.get("workgroup"))
            except Exception:
                pass

    # 2. raw_recmd (RECmd + NativeFallbackParser)
    if "raw_recmd" in tables_set:
        try:
            r_cols = {r[0] for r in cursor.execute("DESCRIBE raw_recmd;").fetchall()}
            if {"ValueName", "Description", "ValueData"}.issubset(r_cols):
                recmd_rows = cursor.execute(
                    """
                    SELECT COALESCE(ValueName, ''), COALESCE(Description, ''), ValueData
                    FROM raw_recmd
                    WHERE ValueData IS NOT NULL AND TRIM(CAST(ValueData AS VARCHAR)) != ''
                    LIMIT 2500;
                    """
                ).fetchall()
                for vname, desc, vdata in recmd_rows:
                    vn_l = str(vname).strip().lower()
                    ds_l = str(desc).strip().lower()
                    if vn_l == "computername" or "computer name" in ds_l or "hostname" in ds_l:
                        _set_if_empty("hostname", vdata)
                    elif vn_l == "productname" or "os product name" in ds_l:
                        _set_if_empty("os_name", vdata)
                    elif vn_l in ("editionid", "displayversion") or "edition" in ds_l:
                        _set_if_empty("os_edition", vdata)
                    elif vn_l in ("currentbuild", "currentbuildnumber", "buildlabex") or "build" in ds_l:
                        _set_if_empty("os_build", vdata)
                    elif vn_l == "installdate" or "install date" in ds_l:
                        _set_if_empty("install_date", vdata, is_date=True)
                    elif vn_l in ("systemroot", "pathname") or "systemroot" in ds_l:
                        _set_if_empty("system_root", vdata)
                    elif vn_l in ("timezonekeyname", "standardname") or "time zone" in ds_l or "timezone" in ds_l:
                        _set_if_empty("timezone", vdata)
                    elif vn_l == "shutdowntime" or "shutdown" in ds_l:
                        _set_if_empty("last_shutdown", vdata, is_date=True)
                    elif vn_l == "registeredowner" or "registered owner" in ds_l:
                        _set_if_empty("registered_owner", vdata)
                    elif vn_l in ("domain", "workgroup", "nv domain"):
                        _set_if_empty("domain_or_workgroup", vdata)
                    elif vn_l == "localusers" or "local user accounts" in ds_l:
                        _add_user(vdata)
        except Exception:
            pass

    # 3. raw_regripper
    if "raw_regripper" in tables_set:
        try:
            rr_rows = cursor.execute(
                """
                SELECT LOWER(COALESCE(plugin_name, '')), COALESCE(report_text, '')
                FROM raw_regripper
                WHERE LOWER(plugin_name) IN ('compname', 'winver', 'timezone', 'shutdown', 'samparse', 'networklist')
                LIMIT 50;
                """
            ).fetchall()
            patterns = [
                ("hostname", r"(?im)^\s*ComputerName\s*[=:]\s*(.+)$", False),
                ("os_name", r"(?im)^\s*ProductName\s*[=:]\s*(.+)$", False),
                ("os_edition", r"(?im)^\s*EditionID\s*[=:]\s*(.+)$", False),
                ("os_build", r"(?im)^\s*(?:CurrentBuild|CurrentBuildNumber|BuildLabEx)\s*[=:]\s*(.+)$", False),
                ("install_date", r"(?im)^\s*InstallDate\s*[=:]\s*(.+)$", True),
                ("system_root", r"(?im)^\s*(?:SystemRoot|PathName)\s*[=:]\s*(.+)$", False),
                ("timezone", r"(?im)^\s*(?:TimeZoneKeyName|StandardName)\s*[=:]\s*(.+)$", False),
                ("last_shutdown", r"(?im)^\s*ShutdownTime\s*[=:]\s*(.+)$", True),
                ("registered_owner", r"(?im)^\s*RegisteredOwner\s*[=:]\s*(.+)$", False),
            ]
            for pname, rtext in rr_rows:
                for field, pat, is_dt in patterns:
                    m = re.search(pat, rtext)
                    if m:
                        _set_if_empty(field, m.group(1).strip(), is_date=is_dt)
                if pname == "samparse":
                    for um in re.finditer(r"(?im)^\s*Username\s*:\s*([^\r\n\[]+)", rtext):
                        _add_user(um.group(1).strip())
        except Exception:
            pass

    # 4. raw_evtx fallback for hostname
    if not os_info["hostname"] and "raw_evtx" in tables_set:
        try:
            ev_cols = {r[0] for r in cursor.execute("DESCRIBE raw_evtx;").fetchall()}
            if "Computer" in ev_cols:
                comp_row = cursor.execute(
                    "SELECT Computer FROM raw_evtx WHERE Computer IS NOT NULL AND TRIM(CAST(Computer AS VARCHAR)) != '' LIMIT 1;"
                ).fetchone()
                if comp_row and comp_row[0]:
                    _set_if_empty("hostname", comp_row[0])
        except Exception:
            pass

    # 5. Users waterfall: parsed_user_accounts -> vfs_files -> raw_mft -> view_refined_users
    if "parsed_user_accounts" in tables_set:
        try:
            ua_cols = [r[0] for r in cursor.execute("DESCRIBE parsed_user_accounts;").fetchall()]
            u_col = next((c for c in ua_cols if c.lower() in ("username", "user_name", "account_name", "name")), None)
            if u_col:
                for (u_val,) in cursor.execute(f'SELECT "{u_col}" FROM parsed_user_accounts WHERE "{u_col}" IS NOT NULL LIMIT 100;').fetchall():
                    _add_user(u_val)
        except Exception:
            pass

    if "vfs_files" in tables_set:
        try:
            vf_cols = {r[0] for r in cursor.execute("DESCRIBE vfs_files;").fetchall()}
            if "vfs_path" in vf_cols:
                for (u_val,) in cursor.execute(
                    "SELECT DISTINCT regexp_extract(vfs_path, '(?i)[/\\\\]Users[/\\\\]([^/\\\\]+)', 1) FROM vfs_files WHERE vfs_path ILIKE '%Users%' LIMIT 50;"
                ).fetchall():
                    _add_user(u_val)
        except Exception:
            pass

    if not users_list and "raw_mft" in tables_set:
        try:
            mft_cols = {r[0] for r in cursor.execute("DESCRIBE raw_mft;").fetchall()}
            if {"ParentPath", "FileName"}.issubset(mft_cols):
                for (u_val,) in cursor.execute(
                    "SELECT DISTINCT FileName FROM raw_mft WHERE (ParentPath = '.\\Users' OR ParentPath = '\\Users' OR ParentPath ILIKE '%:\\Users') AND COALESCE(IsDirectory, TRUE) = TRUE LIMIT 50;"
                ).fetchall():
                    _add_user(u_val)
        except Exception:
            pass

    if not users_list and "view_refined_users" in tables_set:
        try:
            ru_cols = {r[0] for r in cursor.execute("DESCRIBE view_refined_users;").fetchall()}
            if "user_identifier" in ru_cols:
                for (u_val,) in cursor.execute(
                    "SELECT user_identifier FROM view_refined_users ORDER BY total_occurrences DESC LIMIT 20;"
                ).fetchall():
                    _add_user(u_val)
        except Exception:
            pass

    os_info["users"] = users_list
    return os_info


def _extract_case_metadata_dict(
    case_id: str,
    case_dir: Path,
    cursor: duckdb.DuckDBPyConnection,
    tables_set: set[str],
) -> Dict[str, Any]:
    raw_meta: Dict[str, Any] = {}
    manifest_file = case_dir / "case_manifest.json"
    if manifest_file.is_file():
        try:
            loaded = json.loads(manifest_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw_meta.update(loaded)
        except Exception:
            pass

    if "case_metadata" in tables_set:
        try:
            for k, v in cursor.execute("SELECT key, value FROM case_metadata;").fetchall():
                if k:
                    raw_meta[str(k)] = v
        except Exception:
            pass

    source_path = str(raw_meta.get("source_path") or "").strip()
    if not source_path and "processing_logs" in tables_set:
        try:
            row = cursor.execute(
                "SELECT command_executed FROM processing_logs WHERE command_executed LIKE 'Extractor (%' ORDER BY log_id DESC LIMIT 1;"
            ).fetchone()
            if row and row[0] and ":" in str(row[0]):
                source_path = str(row[0]).split(":", 1)[1].strip()
        except Exception:
            pass

    source_type = str(raw_meta.get("source_type") or "").strip()
    if not source_type and source_path:
        ext = Path(source_path).suffix.lower()
        if ext in (".e01", ".ex01"):
            source_type = "E01"
        elif ext in (".vhd", ".vhdx"):
            source_type = "VHDX"
        elif ext == ".vmdk":
            source_type = "VMDK"
        elif ext in (".dd", ".raw", ".img", ".001"):
            source_type = "RAW"
        elif Path(source_path).exists() and Path(source_path).is_dir():
            source_type = "Directory"
        else:
            source_type = "folder"

    img_size_val: Optional[int] = None
    raw_img_sz = raw_meta.get("image_size")
    if raw_img_sz is not None and str(raw_img_sz).strip().isdigit():
        img_size_val = int(str(raw_img_sz).strip())
    elif source_path:
        try:
            sp = Path(source_path)
            if sp.exists() and sp.is_file():
                img_size_val = sp.stat().st_size
        except Exception:
            img_size_val = None

    max_workers_val = 25
    if raw_meta.get("max_workers") is not None:
        try:
            max_workers_val = max(1, min(32, int(str(raw_meta["max_workers"]).strip())))
        except Exception:
            pass

    created_utc = str(raw_meta.get("created_utc") or "").strip() or None
    if not created_utc and case_dir.exists():
        try:
            created_utc = datetime.fromtimestamp(case_dir.stat().st_ctime, tz=timezone.utc).isoformat()
        except Exception:
            created_utc = None

    return {
        "case_name": str(raw_meta.get("case_name") or case_id),
        "case_number": str(raw_meta.get("case_number") or ""),
        "examiner": str(raw_meta.get("examiner") or ""),
        "notes": str(raw_meta.get("notes") or ""),
        "source_path": source_path,
        "source_type": source_type,
        "image_size": img_size_val,
        "sha256": str(raw_meta.get("sha256") or "") or None,
        "max_workers": max_workers_val,
        "enable_data_carving": _parse_bool_flag(raw_meta.get("enable_data_carving"), False),
        "enable_bulk_extractor": _parse_bool_flag(raw_meta.get("enable_bulk_extractor"), False),
        "enable_vss": _parse_bool_flag(raw_meta.get("enable_vss"), False),
        "created_utc": created_utc,
    }


@app.get("/api/cases/{case_id}/dashboard", summary="WFT Places to Start Case Dashboard")
def get_case_dashboard(case_id: str) -> Dict[str, Any]:
    case_dir = get_case_dir(case_id, create_if_missing=False)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        try:
            _restore_missing_core_registry_entries(cursor, tables_set)
        except Exception:
            pass

        raw_reg = (
            cursor.execute(
                """
                SELECT artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                FROM artifact_registry
                WHERE row_count > 0
                ORDER BY row_count DESC;
                """
            ).fetchall()
            if "artifact_registry" in tables_set
            else []
        )
        reg_cols = ["artifact_id", "category", "display_name", "table_name", "source_tool", "row_count", "last_updated"]
        visible_arts = _filter_visible_registry_items(serialize_rows(reg_cols, raw_reg))
        is_subview_dup = _build_subview_dedup_predicate(visible_arts)

        category_counts: Dict[str, int] = {}
        total_artifact_rows = 0
        top_artifacts: List[Dict[str, Any]] = []

        for art in sorted(visible_arts, key=lambda x: int(x.get("row_count") or 0), reverse=True):
            cat = str(art.get("category") or "OPERATING SYSTEM")
            dname = str(art.get("display_name") or "")
            tname = str(art.get("table_name") or "")
            cnt = int(art.get("row_count") or 0)
            if not is_subview_dup(tname):
                total_artifact_rows += cnt
                category_counts[cat] = category_counts.get(cat, 0) + cnt
            if len(top_artifacts) < 8 and not is_subview_dup(tname):
                top_artifacts.append({"category": cat, "display_name": dname, "table_name": tname, "row_count": cnt})

        categories_list = [
            {
                "category": cat,
                "count": cnt,
                "percentage": round((cnt / total_artifact_rows * 100), 1) if total_artifact_rows > 0 else 0,
            }
            for cat, cnt in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        timeline_total = 0
        min_timestamp_utc: Optional[str] = None
        max_timestamp_utc: Optional[str] = None
        if "master_timeline" in tables_set:
            timeline_total = int(cursor.execute("SELECT COUNT(*) FROM master_timeline;").fetchone()[0] or 0)
            bounds = cursor.execute(
                """
                SELECT MIN(timestamp_utc), MAX(timestamp_utc)
                FROM master_timeline
                WHERE timestamp_utc IS NOT NULL
                  AND timestamp_utc > '1970-01-02'::TIMESTAMP
                  AND timestamp_utc < '2099-01-01'::TIMESTAMP;
                """
            ).fetchone()
            if bounds:
                min_timestamp_utc = serialize_db_value(bounds[0])
                max_timestamp_utc = serialize_db_value(bounds[1])

        connections_total = (
            int(cursor.execute("SELECT COUNT(*) FROM entity_connections;").fetchone()[0] or 0)
            if "entity_connections" in tables_set
            else 0
        )

        top_users: List[Dict[str, Any]] = []
        top_domains: List[Dict[str, Any]] = []
        top_executables: List[Dict[str, Any]] = []
        if "entity_connections" in tables_set:
            top_users = [
                {"value": r[0], "count": int(r[1] or 0)}
                for r in cursor.execute(
                    """
                    SELECT entity_value, COUNT(*) as cnt
                    FROM entity_connections
                    WHERE entity_type IN ('USER_ACCOUNT', 'IDENTIFIER')
                    GROUP BY entity_value
                    ORDER BY cnt DESC
                    LIMIT 5;
                    """
                ).fetchall()
            ]
            top_domains = [
                {"value": r[0], "count": int(r[1] or 0)}
                for r in cursor.execute(
                    """
                    SELECT entity_value, COUNT(*) as cnt
                    FROM entity_connections
                    WHERE entity_type IN ('DOMAIN', 'URL')
                    GROUP BY entity_value
                    ORDER BY cnt DESC
                    LIMIT 5;
                    """
                ).fetchall()
            ]
            top_executables = [
                {"value": r[0], "count": int(r[1] or 0)}
                for r in cursor.execute(
                    """
                    SELECT entity_value, COUNT(*) as cnt
                    FROM entity_connections
                    WHERE entity_type = 'EXECUTABLE'
                    GROUP BY entity_value
                    ORDER BY cnt DESC
                    LIMIT 5;
                    """
                ).fetchall()
            ]

        yara_hits: List[Dict[str, Any]] = []
        yara_total_cnt = 0
        if "artifact_yara_hits" in tables_set:
            yara_total_cnt = int(cursor.execute("SELECT COUNT(*) FROM artifact_yara_hits;").fetchone()[0] or 0)
            hits_raw = cursor.execute(
                """
                SELECT rule_name, file_name, file_path, COUNT(*) AS matched_strings_count, MAX(scanned_at)
                FROM artifact_yara_hits
                GROUP BY rule_name, file_name, file_path
                ORDER BY matched_strings_count DESC
                LIMIT 10;
                """
            ).fetchall()
            for r in hits_raw:
                yara_hits.append({
                    "rule_name": r[0],
                    "file_name": r[1],
                    "file_path": r[2],
                    "match_count": int(r[3] or 0),
                    "scanned_at": str(r[4]) if r[4] is not None else "",
                })

        stinger_total_cnt = (
            int(cursor.execute("SELECT COUNT(*) FROM artifact_stinger_hits;").fetchone()[0] or 0)
            if "artifact_stinger_hits" in tables_set
            else 0
        )

        bookmarks_list: List[Dict[str, Any]] = []
        bookmarks_total_cnt = 0
        if "bookmarks" in tables_set:
            bm_cols = {r[1] for r in cursor.execute("PRAGMA table_info('bookmarks');").fetchall()}
            if "source_table" in bm_cols:
                bookmarks_total_cnt = int(cursor.execute("SELECT COUNT(*) FROM bookmarks;").fetchone()[0] or 0)
                b_raw = cursor.execute(
                    """
                    SELECT bookmark_id, source_table, source_row_id, tag_name, examiner_notes, created_at
                    FROM bookmarks
                    ORDER BY created_at DESC
                    LIMIT 10;
                    """
                ).fetchall()
                for r in b_raw:
                    bookmarks_list.append({
                        "bookmark_id": r[0],
                        "source_table": r[1],
                        "source_row_id": r[2],
                        "tag_name": r[3],
                        "examiner_notes": r[4],
                        "created_at": str(r[5]) if r[5] is not None else "",
                    })

        case_metadata = _extract_case_metadata_dict(case_id, case_dir, cursor, tables_set)
        os_info = _extract_os_info_waterfall(cursor, tables_set)

        partitions: List[Dict[str, Any]] = []
        if "vfs_partitions" in tables_set:
            try:
                vp_cols = {r[1] for r in cursor.execute("PRAGMA table_info('vfs_partitions');").fetchall()}
                p_idx_expr = _sql_coalesce_present_cols(vp_cols, ["part_index", "partition_index"], "0")
                lbl_expr = _sql_coalesce_present_cols(vp_cols, ["label", "volume_label", "description"], "''", nullif_empty=True)
                fs_expr = _sql_coalesce_present_cols(vp_cols, ["fs_type", "filesystem"], "'UNKNOWN'", nullif_empty=True)
                off_expr = _sql_coalesce_present_cols(vp_cols, ["offset_bytes", "start_offset", "start_offset_bytes"], "0")
                sz_expr = _sql_coalesce_present_cols(vp_cols, ["size_bytes", "length_bytes"], "0")
                ser_expr = _sql_coalesce_present_cols(vp_cols, ["volume_serial", "serial_number"], "''")
                boot_expr = _sql_coalesce_present_cols(vp_cols, ["is_boot", "is_bootable"], "FALSE")
                for pr in cursor.execute(
                    f"SELECT {p_idx_expr}, {lbl_expr}, {fs_expr}, {off_expr}, {sz_expr}, {ser_expr}, {boot_expr} FROM vfs_partitions ORDER BY 1 ASC;"
                ).fetchall():
                    partitions.append({
                        "part_index": int(pr[0] or 0),
                        "label": str(pr[1] or ""),
                        "fs_type": str(pr[2] or "UNKNOWN"),
                        "offset_bytes": int(pr[3] or 0),
                        "size_bytes": int(pr[4] or 0),
                        "volume_serial": str(pr[5] or ""),
                        "is_boot": bool(pr[6]),
                    })
            except Exception:
                partitions = []

        shadow_copies: List[Dict[str, Any]] = []
        if "vfs_shadow_copies" in tables_set:
            try:
                vs_cols = {r[1] for r in cursor.execute("PRAGMA table_info('vfs_shadow_copies');").fetchall()}
                vi_expr = _sql_coalesce_present_cols(vs_cols, ["vss_index", "store_index"], "0")
                pi_expr = _sql_coalesce_present_cols(vs_cols, ["part_index", "partition_index"], "0")
                sid_expr = _sql_coalesce_present_cols(vs_cols, ["store_id", "vss_id", "shadow_copy_guid"], "''")
                ct_expr = _sql_coalesce_present_cols(vs_cols, ["creation_time", "creation_time_utc"], "NULL", cast_as="VARCHAR")
                vsz_expr = _sql_coalesce_present_cols(vs_cols, ["size_bytes", "shadow_copy_size", "store_size_bytes"], "0")
                sp_expr = _sql_coalesce_present_cols(vs_cols, ["staged_prefix"], "''")
                fst_expr = _sql_coalesce_present_cols(vs_cols, ["files_staged"], "0")
                st_expr = _sql_coalesce_present_cols(vs_cols, ["status"], "'DETECTED'")
                for vr in cursor.execute(
                    f"SELECT {vi_expr}, {pi_expr}, {sid_expr}, {ct_expr}, {vsz_expr}, {sp_expr}, {fst_expr}, {st_expr} FROM vfs_shadow_copies ORDER BY 1 ASC;"
                ).fetchall():
                    shadow_copies.append({
                        "vss_index": int(vr[0] or 0),
                        "part_index": int(vr[1] or 0),
                        "store_id": str(vr[2] or ""),
                        "creation_time": vr[3],
                        "size_bytes": int(vr[4] or 0),
                        "staged_prefix": str(vr[5] or ""),
                        "files_staged": int(vr[6] or 0),
                        "status": str(vr[7] or "DETECTED"),
                    })
            except Exception:
                shadow_copies = []

        tool_execution_summary: List[Dict[str, Any]] = []
        if "processing_logs" in tables_set:
            try:
                l_rows = cursor.execute(
                    """
                    SELECT module_name, command_executed, exit_code, rows_ingested, duration_ms, status, error_message, timestamp_utc
                    FROM processing_logs
                    ORDER BY log_id ASC;
                    """
                ).fetchall()
                for r in l_rows:
                    mod = str(r[0] or "")
                    if ":" in mod:
                        stage, tool_name = mod.split(":", 1)[0].strip(), mod.split(":", 1)[1].strip()
                    else:
                        stage, tool_name = "Pipeline", mod
                    tool_execution_summary.append({
                        "tool_name": tool_name or mod,
                        "stage": stage,
                        "status": str(r[5] or "UNKNOWN"),
                        "row_count": int(r[3] or 0),
                        "duration_ms": int(r[4] or 0),
                        "message": str(r[6]) if r[6] else str(r[1] or ""),
                        "exit_code": r[2],
                        "timestamp_utc": serialize_db_value(r[7]),
                    })
            except Exception:
                tool_execution_summary = []

        refined_domains: List[Dict[str, Any]] = []
        if "view_refined_domains" in tables_set:
            try:
                rd_cols = {r[0] for r in cursor.execute("DESCRIBE view_refined_domains;").fetchall()}
                if {"domain", "total_occurrences"}.issubset(rd_cols):
                    for d_val, d_cnt in cursor.execute(
                        "SELECT domain, total_occurrences FROM view_refined_domains ORDER BY total_occurrences DESC LIMIT 10;"
                    ).fetchall():
                        refined_domains.append({"domain": d_val, "value": d_val, "count": int(d_cnt or 0)})
            except Exception:
                pass
        if not refined_domains:
            refined_domains = [{"domain": d["value"], **d} for d in top_domains]

        refined_users: List[Dict[str, Any]] = []
        if "view_refined_users" in tables_set:
            try:
                ru_cols = {r[0] for r in cursor.execute("DESCRIBE view_refined_users;").fetchall()}
                if {"user_identifier", "total_occurrences"}.issubset(ru_cols):
                    for u_val, u_cnt in cursor.execute(
                        "SELECT user_identifier, SUM(total_occurrences) AS cnt FROM view_refined_users GROUP BY user_identifier ORDER BY cnt DESC LIMIT 10;"
                    ).fetchall():
                        refined_users.append({"user": u_val, "value": u_val, "count": int(u_cnt or 0)})
            except Exception:
                pass
        if not refined_users:
            refined_users = [{"user": u["value"], **u} for u in top_users]

        keyword_hits_count = 0
        if "parsed_keyword_hits" in tables_set:
            keyword_hits_count = int(cursor.execute("SELECT COUNT(*) FROM parsed_keyword_hits;").fetchone()[0] or 0)
        elif "case_keywords" in tables_set:
            keyword_hits_count = int(cursor.execute("SELECT COALESCE(SUM(hit_count), 0) FROM case_keywords;").fetchone()[0] or 0)

        carved_files_count = (
            int(cursor.execute("SELECT COUNT(*) FROM parsed_carved_files;").fetchone()[0] or 0)
            if "parsed_carved_files" in tables_set
            else 0
        )
        bulk_extractor_hits_count = 0
        if "parsed_bulk_extractor_features" in tables_set:
            bulk_extractor_hits_count = int(
                cursor.execute("SELECT COUNT(*) FROM parsed_bulk_extractor_features;").fetchone()[0] or 0
            )
        elif "parsed_bulk_extractor_histograms" in tables_set:
            bulk_extractor_hits_count = int(
                cursor.execute("SELECT COALESCE(SUM(count), 0) FROM parsed_bulk_extractor_histograms;").fetchone()[0] or 0
            )

        refined_highlights = {
            "domains": refined_domains,
            "users": refined_users,
            "keyword_hits_count": keyword_hits_count,
            "carved_files_count": carved_files_count,
            "bulk_extractor_hits_count": bulk_extractor_hits_count,
            "malware_hits_count": yara_total_cnt + stinger_total_cnt,
            "bookmarks_count": bookmarks_total_cnt,
        }

    case_db_path = get_case_db_path(case_id)
    db_size = case_db_path.stat().st_size if case_db_path.exists() else 0

    return {
        "case_id": case_id,
        "db_size_bytes": db_size,
        "total_artifact_rows": total_artifact_rows,
        "total_artifacts": total_artifact_rows,
        "timeline_total": timeline_total,
        "timeline_events": timeline_total,
        "connections_total": connections_total,
        "min_timestamp_utc": min_timestamp_utc,
        "max_timestamp_utc": max_timestamp_utc,
        "category_counts": category_counts,
        "categories": categories_list,
        "top_artifacts": top_artifacts,
        "top_users": top_users,
        "top_domains": top_domains,
        "top_executables": top_executables,
        "yara_hits": yara_hits,
        "bookmarks": bookmarks_list,
        "case_metadata": case_metadata,
        "os_info": os_info,
        "partitions": partitions,
        "shadow_copies": shadow_copies,
        "tool_execution_summary": tool_execution_summary,
        "refined_highlights": refined_highlights,
    }


# ---------------------------------------------------------------------------
# 4. Table Data Grid & Column Distinct Values
# ---------------------------------------------------------------------------
def _query_table_paginated_safe(
    case_id: str,
    clean_table: str,
    limit: int = 500,
    offset: int = 0,
    search: str = "",
    sort_col: str = "_row_id",
    sort_dir: str = "ASC",
    column_filters: Optional[Union[str, Dict[str, Any]]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    keywords: Optional[str] = None,
    tags: Optional[str] = None,
    bookmarked_only: bool = False,
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        is_ro = case_id not in _running_cases
        conn = DuckDBManager.get_connection(case_id, read_only=is_ro)
        cursor = conn.cursor()

        columns = get_table_columns(case_id, clean_table, read_only=is_ro)
        if not columns:
            return {"columns": [], "rows": [], "total_count": 0, "filtered_count": 0}

        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        total_count = int(cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}";').fetchone()[0] or 0)

        col_lookup = {c.lower(): c for c in columns}
        sort_direction = "DESC" if str(sort_dir).upper() == "DESC" else "ASC"
        sort_col_clean = str(sort_col).strip().lower()
        if sort_col_clean in col_lookup:
            sort_column = col_lookup[sort_col_clean]
        elif "_row_id" in col_lookup:
            sort_column = col_lookup["_row_id"]
        else:
            sort_column = columns[0]

        parsed_filters: Dict[str, Any] = {}
        if column_filters:
            if isinstance(column_filters, str) and column_filters.strip():
                try:
                    loaded = json.loads(column_filters)
                    if isinstance(loaded, dict):
                        parsed_filters = loaded
                except Exception as j_err:
                    print(f"[_query_table_paginated_safe] Warning parsing column_filters JSON: {j_err}")
            elif isinstance(column_filters, dict):
                parsed_filters = column_filters

        where_conditions: List[str] = []
        params: List[Any] = []

        if search and search.strip():
            search_pattern = f"%{escape_ilike(search.strip())}%"
            ilike_clauses = [f"CAST(\"{col}\" AS VARCHAR) ILIKE ? ESCAPE '\\'" for col in columns]
            where_conditions.append(f"({' OR '.join(ilike_clauses)})")
            params.extend([search_pattern] * len(columns))

        kw_list = parse_list_param(keywords)
        if kw_list:
            kw_or_groups: List[str] = []
            for kw in kw_list:
                kw_pat = f"%{escape_ilike(kw)}%"
                kw_or_groups.append(
                    "(" + " OR ".join([f"CAST(\"{col}\" AS VARCHAR) ILIKE ? ESCAPE '\\'" for col in columns]) + ")"
                )
                params.extend([kw_pat] * len(columns))
            where_conditions.append("(" + " OR ".join(kw_or_groups) + ")")

        if parsed_filters:
            col_map = {c.lower(): c for c in columns}
            for col_key, filter_vals in parsed_filters.items():
                actual_col = col_map.get(col_key.lower())
                if not actual_col:
                    continue
                if isinstance(filter_vals, (list, tuple, set)) and len(filter_vals) > 0:
                    placeholders = ", ".join(["?"] * len(filter_vals))
                    where_conditions.append(f'CAST("{actual_col}" AS VARCHAR) IN ({placeholders})')
                    params.extend([str(v) for v in filter_vals])
                elif isinstance(filter_vals, dict):
                    op = str(filter_vals.get("op") or "contains").lower()
                    val = str(filter_vals.get("value") or "")
                    if val:
                        if op == "eq":
                            where_conditions.append(f'CAST("{actual_col}" AS VARCHAR) = ?')
                            params.append(val)
                        elif op == "starts_with":
                            where_conditions.append(f"CAST(\"{actual_col}\" AS VARCHAR) ILIKE ? ESCAPE '\\'")
                            params.append(f"{escape_ilike(val)}%")
                        else:
                            where_conditions.append(f"CAST(\"{actual_col}\" AS VARCHAR) ILIKE ? ESCAPE '\\'")
                            params.append(f"%{escape_ilike(val)}%")
                elif isinstance(filter_vals, bool):
                    where_conditions.append(f'LOWER(CAST("{actual_col}" AS VARCHAR)) = ?')
                    params.append(str(filter_vals).lower())
                elif isinstance(filter_vals, (int, float)):
                    where_conditions.append(f'CAST("{actual_col}" AS VARCHAR) = ?')
                    params.append(str(filter_vals))
                elif isinstance(filter_vals, str) and filter_vals != "":
                    where_conditions.append(f"CAST(\"{actual_col}\" AS VARCHAR) ILIKE ? ESCAPE '\\'")
                    params.append(f"%{escape_ilike(filter_vals)}%")

        eff_from = normalize_utc_bound(date_from or start_time, is_end=False)
        eff_to = normalize_utc_bound(date_to or end_time, is_end=True)
        if eff_from or eff_to:
            time_cols = [
                c for c in columns
                if any(t in c.lower() for t in ("time", "date", "created", "modified", "lastrun", "timestamp"))
            ]
            if time_cols:
                primary_time_col = next(
                    (c for c in time_cols if "timestamp" in c.lower() or "utc" in c.lower() or "created" in c.lower()),
                    time_cols[0],
                )
                if eff_from:
                    where_conditions.append(f'TRY_CAST("{primary_time_col}" AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)')
                    params.append(eff_from)
                if eff_to:
                    where_conditions.append(f'TRY_CAST("{primary_time_col}" AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)')
                    params.append(eff_to)

        tag_list = parse_list_param(tags)
        if tag_list or bookmarked_only:
            if "bookmarks" not in tables_set:
                where_conditions.append("1=0")
            else:
                bm_cols = {r[1] for r in cursor.execute("PRAGMA table_info('bookmarks');").fetchall()}
                if "source_table" not in bm_cols:
                    where_conditions.append("1=0")
                else:
                    row_id_col = "_row_id" if "_row_id" in columns else ("timeline_id" if "timeline_id" in columns else columns[0])
                    candidate_src_tables = [clean_table]
                    if clean_table.startswith("view_evtx_"):
                        candidate_src_tables.append("raw_evtx")
                    elif clean_table == "view_keyword_hits":
                        candidate_src_tables.append("parsed_keyword_hits")
                    elif clean_table.startswith("view_docs_"):
                        candidate_src_tables.append("parsed_documents_metadata")
                    src_placeholders = ", ".join(["?"] * len(candidate_src_tables))
                    bm_cond = f"b.source_table IN ({src_placeholders}) AND b.source_row_id = TRY_CAST(\"{row_id_col}\" AS BIGINT)"
                    params.extend(candidate_src_tables)
                    if tag_list:
                        tag_placeholders = ", ".join(["?"] * len(tag_list))
                        bm_cond += f" AND b.tag_name IN ({tag_placeholders})"
                        params.extend(tag_list)
                    where_conditions.append(f"EXISTS (SELECT 1 FROM bookmarks b WHERE {bm_cond})")

        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        if where_clause:
            filtered_count = int(
                cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}" {where_clause};', params).fetchone()[0] or 0
            )
        else:
            filtered_count = total_count

        fetch_query = (
            f'SELECT * FROM "{clean_table}" '
            f'{where_clause} '
            f'ORDER BY "{sort_column}" {sort_direction} '
            f'LIMIT ? OFFSET ?;'
        )
        result_rows = cursor.execute(fetch_query, params + [limit, offset]).fetchall()

        serialized_rows = [dict(zip(columns, row)) for row in result_rows]
        for s_row in serialized_rows:
            fp_val = s_row.get("file_path")
            if isinstance(fp_val, str) and "staging" in fp_val.lower():
                if not s_row.get("source_file"):
                    s_row["source_file"] = fp_val
                p_norm = fp_val.replace("/", "\\")
                m_u = re.search(r"(?i)(?:^|\\)staging\\UserFiles\\([^\\]+)\\(.+)$", p_norm)
                m_e = re.search(r"(?i)(?:^|\\)staging\\Enrichment\\(.+)$", p_norm)
                if m_u:
                    s_row["file_path"] = f"C:\\Users\\{m_u.group(1)}\\{m_u.group(2)}"
                elif m_e:
                    drv, rel = _strip_optional_partition_label(m_e.group(1))
                    if rel.lower().startswith("userfiles\\"):
                        rel = "Users\\" + rel[10:]
                    s_row["file_path"] = f"{drv}{rel.lstrip(chr(92))}"

        return {
            "columns": columns,
            "rows": serialized_rows,
            "total_count": total_count,
            "filtered_count": filtered_count,
        }


@app.get("/api/cases/{case_id}/table/{table_name}", summary="Paginated data grid with dynamic search and column filters")
@app.get("/api/cases/{case_id}/artifacts/{table_name}/query", include_in_schema=False)
def get_table_data(
    case_id: str,
    table_name: str,
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    search: str = Query(""),
    sort_col: str = Query("_row_id"),
    sort_dir: Literal["ASC", "DESC", "asc", "desc"] = Query("ASC"),
    column_filters: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
) -> Dict[str, Any]:
    clean_table = _validate_existing_table_or_raise(case_id, table_name)

    paginated_result = _query_table_paginated_safe(
        case_id=case_id,
        clean_table=clean_table,
        limit=limit,
        offset=offset,
        search=search,
        sort_col=sort_col,
        sort_dir=sort_dir,
        column_filters=column_filters,
        start_time=start_time,
        end_time=end_time,
        date_from=date_from,
        date_to=date_to,
        keywords=keywords,
        tags=tags,
        bookmarked_only=bookmarked_only,
    )

    clean_rows = [{k: serialize_db_value(v) for k, v in r.items()} for r in paginated_result["rows"]]

    return {
        "case_id": case_id,
        "table_name": clean_table,
        "columns": paginated_result["columns"],
        "rows": clean_rows,
        "total_count": paginated_result["total_count"],
        "filtered_count": paginated_result["filtered_count"],
        "limit": limit,
        "offset": offset,
    }


@app.post("/api/cases/{case_id}/artifacts/{table_name}/query", include_in_schema=False)
def post_table_data_query(
    case_id: str,
    table_name: str,
    payload: Optional[Dict[str, Any]] = Body(default=None),
) -> Dict[str, Any]:
    clean_table = _validate_existing_table_or_raise(case_id, table_name)
    body = payload if isinstance(payload, dict) else {}
    raw_cf = body.get("column_filters")
    cf_str = json.dumps(raw_cf) if isinstance(raw_cf, dict) else (str(raw_cf) if raw_cf is not None else None)
    raw_kw = body.get("keywords")
    kw_str = json.dumps(raw_kw) if isinstance(raw_kw, list) else (str(raw_kw) if raw_kw is not None else None)
    raw_tags = body.get("tags")
    tags_str = json.dumps(raw_tags) if isinstance(raw_tags, list) else (str(raw_tags) if raw_tags is not None else None)
    lim = max(1, min(50000, int(body.get("limit") or 500)))
    off = max(0, int(body.get("offset") or 0))
    s_dir = str(body.get("sort_dir") or "ASC")
    paginated_result = _query_table_paginated_safe(
        case_id=case_id,
        clean_table=clean_table,
        limit=lim,
        offset=off,
        search=str(body.get("search") or ""),
        sort_col=str(body.get("sort_col") or "_row_id"),
        sort_dir="DESC" if s_dir.upper() == "DESC" else "ASC",
        column_filters=cf_str,
        start_time=body.get("start_time"),
        end_time=body.get("end_time"),
        date_from=body.get("date_from"),
        date_to=body.get("date_to"),
        keywords=kw_str,
        tags=tags_str,
        bookmarked_only=bool(body.get("bookmarked_only") or False),
    )
    clean_rows = [{k: serialize_db_value(v) for k, v in r.items()} for r in paginated_result["rows"]]
    return {
        "case_id": case_id,
        "table_name": clean_table,
        "columns": paginated_result["columns"],
        "rows": clean_rows,
        "total_count": paginated_result["total_count"],
        "filtered_count": paginated_result["filtered_count"],
        "limit": lim,
        "offset": off,
    }


@app.get(
    "/api/cases/{case_id}/table/{table_name}/distinct/{column_name}",
    summary="Distinct column values with occurrence counts",
)
def get_table_column_distinct(
    case_id: str,
    table_name: str,
    column_name: str,
) -> List[Dict[str, Any]]:
    clean_table = _validate_existing_table_or_raise(case_id, table_name)
    if not column_name or not re.fullmatch(r"[A-Za-z0-9_]+", column_name):
        raise HTTPException(status_code=400, detail="Invalid column name")

    with DuckDBManager.get_lock(case_id):
        try:
            distinct_rows = get_distinct_column_values(
                case_id,
                clean_table,
                column_name,
                limit=500,
                read_only=case_id not in _running_cases,
            )
        except ValueError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    return [{"value": serialize_db_value(item["value"]), "count": item["count"]} for item in distinct_rows]


# ---------------------------------------------------------------------------
# 4.2 RegRipper Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/regripper/plugins", summary="List all RegRipper plugins parsed for the case")
@app.get("/api/cases/{case_id}/regripper/entries", include_in_schema=False)
def get_regripper_plugins(
    case_id: str,
    hive: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
    limit: int = Query(5000, ge=1, le=50000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "raw_regripper" not in tables_set:
            return {"case_id": case_id, "total": 0, "plugins": [], "entries": []}

        where_clauses: List[str] = []
        params: List[Any] = []
        if hive and hive.strip():
            where_clauses.append("(hive_name ILIKE ? ESCAPE '\\' OR hive_type ILIKE ? ESCAPE '\\')")
            h_pat = f"%{escape_ilike(hive.strip())}%"
            params.extend([h_pat, h_pat])
        if category and category.strip():
            where_clauses.append("category ILIKE ? ESCAPE '\\'")
            params.append(f"%{escape_ilike(category.strip())}%")
        if search and search.strip():
            s_pat = f"%{escape_ilike(search.strip())}%"
            where_clauses.append(
                "(plugin_name ILIKE ? ESCAPE '\\' OR description ILIKE ? ESCAPE '\\' OR summary_line ILIKE ? ESCAPE '\\' OR report_text ILIKE ? ESCAPE '\\')"
            )
            params.extend([s_pat, s_pat, s_pat, s_pat])

        kw_list = parse_list_param(keywords)
        if kw_list:
            kw_groups = []
            for kw in kw_list:
                kp = f"%{escape_ilike(kw)}%"
                kw_groups.append(
                    "(plugin_name ILIKE ? ESCAPE '\\' OR description ILIKE ? ESCAPE '\\' OR summary_line ILIKE ? ESCAPE '\\' OR report_text ILIKE ? ESCAPE '\\')"
                )
                params.extend([kp, kp, kp, kp])
            where_clauses.append("(" + " OR ".join(kw_groups) + ")")

        eff_from = normalize_utc_bound(date_from or start_time, is_end=False)
        eff_to = normalize_utc_bound(date_to or end_time, is_end=True)
        if eff_from:
            where_clauses.append("TRY_CAST(parsed_at AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)")
            params.append(eff_from)
        if eff_to:
            where_clauses.append("TRY_CAST(parsed_at AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)")
            params.append(eff_to)

        tag_list = parse_list_param(tags)
        if tag_list or bookmarked_only:
            if "bookmarks" not in tables_set:
                where_clauses.append("1=0")
            else:
                bm_sql = "b.source_table = 'raw_regripper' AND b.source_row_id = raw_regripper._row_id"
                if tag_list:
                    phs = ", ".join(["?"] * len(tag_list))
                    bm_sql += f" AND b.tag_name IN ({phs})"
                    params.extend(tag_list)
                where_clauses.append(f"EXISTS (SELECT 1 FROM bookmarks b WHERE {bm_sql})")

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        total_filtered = int(
            cursor.execute(f"SELECT COUNT(*) FROM raw_regripper {where_sql};", params).fetchone()[0] or 0
        )
        query = f"""
            SELECT _row_id, plugin_name, plugin_version, hive_name, hive_type,
                   category, mitre_attack, description, summary_line, output_lines_count, parsed_at
            FROM raw_regripper
            {where_sql}
            ORDER BY hive_type ASC, plugin_name ASC
            LIMIT ? OFFSET ?;
        """
        rows = cursor.execute(query, params + [limit, offset]).fetchall()
        cols = [
            "_row_id",
            "plugin_name",
            "plugin_version",
            "hive_name",
            "hive_type",
            "category",
            "mitre_attack",
            "description",
            "summary_line",
            "output_lines_count",
            "parsed_at",
        ]
        plugins = [dict(zip(cols, [serialize_db_value(v) for v in r])) for r in rows]
        return {"case_id": case_id, "total": total_filtered, "plugins": plugins, "entries": plugins}


@app.get("/api/cases/{case_id}/regripper/categories", include_in_schema=False)
def get_regripper_categories(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "raw_regripper" not in tables:
            return {"case_id": case_id, "categories": []}
        rows = cursor.execute(
            "SELECT COALESCE(category, 'General'), COUNT(*) FROM raw_regripper GROUP BY 1 ORDER BY 2 DESC;"
        ).fetchall()
        return {"case_id": case_id, "categories": [{"category": r[0], "count": int(r[1] or 0)} for r in rows]}


@app.get("/api/cases/{case_id}/regripper/plugin/{plugin_name}", summary="Get detailed report for a specific RegRipper plugin")
def get_regripper_plugin_detail(
    case_id: str,
    plugin_name: str,
    hive: Optional[str] = Query(None),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables = [
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_name = 'raw_regripper';"
            ).fetchall()
        ]
        if not tables:
            raise HTTPException(status_code=404, detail="RegRipper table raw_regripper not found")

        where_sql = "WHERE LOWER(plugin_name) = LOWER(?)"
        params = [plugin_name.strip()]
        if hive and hive.strip():
            where_sql += " AND (hive_name ILIKE ? ESCAPE '\\' OR hive_type ILIKE ? ESCAPE '\\')"
            h_pat = f"%{escape_ilike(hive.strip())}%"
            params.extend([h_pat, h_pat])

        query = f"""
            SELECT _row_id, plugin_name, plugin_version, hive_name, hive_type,
                   category, mitre_attack, description, report_text, summary_line, output_lines_count, parsed_at
            FROM raw_regripper
            {where_sql}
            LIMIT 1;
        """
        row = cursor.execute(query, params).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Plugin '{plugin_name}' not found for case '{case_id}'")

        cols = [
            "_row_id",
            "plugin_name",
            "plugin_version",
            "hive_name",
            "hive_type",
            "category",
            "mitre_attack",
            "description",
            "report_text",
            "summary_line",
            "output_lines_count",
            "parsed_at",
        ]
        return dict(zip(cols, [serialize_db_value(v) for v in row]))


@app.post("/api/cases/{case_id}/regripper/run", summary="Trigger RegRipper analysis on demand")
def trigger_regripper_analysis(case_id: str) -> Dict[str, Any]:
    from backend.orchestrator.regripper_runner import RegRipperRunner
    was_rw = DuckDBManager.has_rw_connection(case_id)
    case_dir = get_case_dir(case_id)
    runner = RegRipperRunner(case_id=case_id, case_dir=case_dir)
    res = runner.run()
    if not was_rw and case_id not in _running_cases:
        with DuckDBManager.get_lock(case_id):
            if DuckDBManager.has_rw_connection(case_id):
                try:
                    DuckDBManager.get_connection(case_id, read_only=False).cursor().execute("CHECKPOINT;")
                except Exception:
                    pass
                DuckDBManager.close_connection(case_id)
    return res


# ---------------------------------------------------------------------------
# 5. Chronological Super-Timeline
# ---------------------------------------------------------------------------
_SYNTHESIZED_MACB_SQL = """CONCAT(
    CASE WHEN timestamp_type ILIKE '%Modif%' OR timestamp_type ILIKE '%Write%' THEN 'M' ELSE '.' END,
    CASE WHEN timestamp_type ILIKE '%Access%' OR timestamp_type ILIKE '%Visit%' OR timestamp_type ILIKE '%LastRun%' OR timestamp_type ILIKE '%Execut%' THEN 'A' ELSE '.' END,
    CASE WHEN timestamp_type ILIKE '%Change%' OR timestamp_type ILIKE '%Record%' OR timestamp_type ILIKE '%Metadata%' THEN 'C' ELSE '.' END,
    CASE WHEN timestamp_type ILIKE '%Creat%' OR timestamp_type ILIKE '%Birth%' THEN 'B' ELSE '.' END
)"""


@app.get("/api/cases/{case_id}/timeline/stats", summary="Master timeline bounds, total events, and category breakdown")
def get_master_timeline_stats(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "master_timeline" not in tables_set:
            return {
                "case_id": case_id,
                "total_events": 0,
                "total_count": 0,
                "min_timestamp_utc": None,
                "max_timestamp_utc": None,
                "categories": {},
            }
        base_guard = "timestamp_utc IS NOT NULL AND timestamp_utc > '1970-01-02'::TIMESTAMP AND timestamp_utc < '2099-01-01'::TIMESTAMP"
        cnt, min_ts, max_ts = cursor.execute(
            f"SELECT COUNT(*), MIN(timestamp_utc), MAX(timestamp_utc) FROM master_timeline WHERE {base_guard};"
        ).fetchone()
        cat_rows = cursor.execute(
            f"SELECT COALESCE(category, 'OTHER'), COUNT(*) FROM master_timeline WHERE {base_guard} GROUP BY 1 ORDER BY 2 DESC;"
        ).fetchall()
        norm_cats: Dict[str, int] = {}
        for r in cat_rows:
            raw_c = str(r[0] or "OTHER")
            c_key = "OTHER" if raw_c == "OTHER" else _normalize_canonical_category(raw_c)
            norm_cats[c_key] = norm_cats.get(c_key, 0) + int(r[1] or 0)
        return {
            "case_id": case_id,
            "total_events": int(cnt or 0),
            "total_count": int(cnt or 0),
            "min_timestamp_utc": serialize_db_value(min_ts),
            "max_timestamp_utc": serialize_db_value(max_ts),
            "categories": norm_cats,
        }


@app.get("/api/cases/{case_id}/timeline", summary="Chronological super-timeline with histogram")
def get_master_timeline(
    case_id: str,
    limit: int = Query(1000, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    search: str = Query(""),
    category: str = Query(""),
    source: Optional[str] = Query(None),
    start_time: str = Query(""),
    end_time: str = Query(""),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    sort_dir: str = Query("desc"),
    macb: Optional[str] = Query(None),
    around_timestamp: Optional[str] = Query(None),
    window_minutes: int = Query(5, ge=1, le=10080),
    keywords: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "master_timeline" not in tables_set:
            return {
                "case_id": case_id,
                "total_count": 0,
                "filtered_count": 0,
                "min_timestamp_utc": None,
                "max_timestamp_utc": None,
                "sort_dir": "asc" if str(sort_dir).strip().lower() == "asc" else "desc",
                "timeline": [],
                "histogram": [],
                "limit": limit,
                "offset": offset,
            }

        actual_cols = [r[0] for r in cursor.execute("DESCRIBE master_timeline;").fetchall()]
        has_macb = "macb" in actual_cols
        macb_expr = f"COALESCE(NULLIF(TRIM(CAST(macb AS VARCHAR)), ''), {_SYNTHESIZED_MACB_SQL})" if has_macb else _SYNTHESIZED_MACB_SQL

        base_guard = "timestamp_utc IS NOT NULL AND timestamp_utc > '1970-01-02'::TIMESTAMP AND timestamp_utc < '2099-01-01'::TIMESTAMP"
        total_count, min_ts_raw, max_ts_raw = cursor.execute(
            f"SELECT COUNT(*), MIN(timestamp_utc), MAX(timestamp_utc) FROM master_timeline WHERE {base_guard};"
        ).fetchone()

        where_parts = [base_guard]
        params: List[Any] = []

        eff_cat = (category or source or "").strip()
        if eff_cat and eff_cat.upper() != "ALL":
            if eff_cat.upper() in ("EVENT LOGS", "EVENT_LOGS", "LOGS"):
                where_parts.append("UPPER(COALESCE(category, '')) = 'EVENT LOGS'")
            elif eff_cat.upper() in ("EMAIL", "EMAIL & CALENDAR", "EMAIL_AND_CALENDAR"):
                where_parts.append("UPPER(COALESCE(category, '')) IN ('EMAIL', 'EMAIL & CALENDAR')")
            else:
                esc_cat = escape_ilike(eff_cat)
                alt_cat = escape_ilike(eff_cat.replace("_", " "))
                where_parts.append("(category ILIKE ? ESCAPE '\\' OR category ILIKE ? ESCAPE '\\' OR source_table = ?)")
                params.extend([esc_cat, alt_cat, eff_cat])

        if around_timestamp and around_timestamp.strip():
            raw_pivot = around_timestamp.strip()
            try:
                pivot_dt = datetime.fromisoformat(raw_pivot.replace("Z", "+00:00"))
                if pivot_dt.tzinfo is not None:
                    pivot_dt = pivot_dt.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid around_timestamp '{around_timestamp}'. Expected ISO-8601 UTC timestamp.",
                )
            win_start = (pivot_dt - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S.%f")
            win_end = (pivot_dt + timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S.%f")
            where_parts.append("timestamp_utc >= TRY_CAST(? AS TIMESTAMP) AND timestamp_utc <= TRY_CAST(? AS TIMESTAMP)")
            params.extend([win_start, win_end])

        eff_from = normalize_utc_bound(date_from or start_time, is_end=False)
        eff_to = normalize_utc_bound(date_to or end_time, is_end=True)
        if eff_from:
            where_parts.append("timestamp_utc >= TRY_CAST(? AS TIMESTAMP)")
            params.append(eff_from)
        if eff_to:
            where_parts.append("timestamp_utc <= TRY_CAST(? AS TIMESTAMP)")
            params.append(eff_to)

        if macb and macb.strip():
            req_flags = [ch for ch in ("M", "A", "C", "B") if ch in macb.upper()]
            if req_flags:
                flag_clauses = [f"(UPPER({macb_expr}) LIKE '%{ch}%')" for ch in req_flags]
                where_parts.append("(" + " OR ".join(flag_clauses) + ")")

        if search and search.strip():
            term = f"%{escape_ilike(search.strip())}%"
            where_parts.append(
                """(
                    primary_entity ILIKE ? ESCAPE '\\' OR
                    secondary_entity ILIKE ? ESCAPE '\\' OR
                    summary ILIKE ? ESCAPE '\\' OR
                    artifact_name ILIKE ? ESCAPE '\\' OR
                    timestamp_type ILIKE ? ESCAPE '\\' OR
                    source_file ILIKE ? ESCAPE '\\'
                )"""
            )
            params.extend([term] * 6)

        kw_list = parse_list_param(keywords)
        if kw_list:
            kw_or_parts = []
            for kw in kw_list:
                kp = f"%{escape_ilike(kw)}%"
                kw_or_parts.append(
                    "("
                    "primary_entity ILIKE ? ESCAPE '\\' OR "
                    "secondary_entity ILIKE ? ESCAPE '\\' OR "
                    "summary ILIKE ? ESCAPE '\\' OR "
                    "artifact_name ILIKE ? ESCAPE '\\' OR "
                    "source_file ILIKE ? ESCAPE '\\'"
                    ")"
                )
                params.extend([kp] * 5)
            where_parts.append("(" + " OR ".join(kw_or_parts) + ")")

        tag_list = parse_list_param(tags)
        if tag_list or bookmarked_only:
            if "bookmarks" not in tables_set:
                where_parts.append("1=0")
            else:
                bm_cols = {r[1] for r in cursor.execute("PRAGMA table_info('bookmarks');").fetchall()}
                if "source_table" not in bm_cols:
                    where_parts.append("1=0")
                else:
                    bm_pred = (
                        "("
                        "(b.source_table = master_timeline.source_table AND b.source_row_id = master_timeline.source_row_id) "
                        "OR (b.source_table = 'master_timeline' AND b.source_row_id = master_timeline.timeline_id)"
                        ")"
                    )
                    if tag_list:
                        t_phs = ", ".join(["?"] * len(tag_list))
                        bm_pred += f" AND b.tag_name IN ({t_phs})"
                        params.extend(tag_list)
                    where_parts.append(f"EXISTS (SELECT 1 FROM bookmarks b WHERE {bm_pred})")

        where_sql = f"WHERE {' AND '.join(where_parts)}"
        filtered_count = int(
            cursor.execute(f"SELECT COUNT(*) FROM master_timeline {where_sql};", params).fetchone()[0] or 0
        )

        order_dir = "ASC" if str(sort_dir).strip().lower() == "asc" else "DESC"
        select_cols = [
            "timeline_id",
            "timestamp_utc",
            "timestamp_type",
            f"{macb_expr} AS macb",
            "category",
            "artifact_name",
            "primary_entity",
            "secondary_entity",
            "summary",
            "source_table",
            "source_row_id",
            "source_file",
        ]
        out_col_names = [
            "timeline_id",
            "timestamp_utc",
            "timestamp_type",
            "macb",
            "category",
            "artifact_name",
            "primary_entity",
            "secondary_entity",
            "summary",
            "source_table",
            "source_row_id",
            "source_file",
        ]
        for extra_c in ("is_deleted", "timestomped", "vss_index", "host", "user_account"):
            if extra_c in actual_cols:
                select_cols.append(extra_c)
                out_col_names.append(extra_c)

        stratify_date_window = (
            offset == 0
            and filtered_count > limit
            and limit >= 50
            and not (eff_cat and eff_cat.upper() != "ALL")
            and not (around_timestamp and around_timestamp.strip())
            and bool(eff_from or eff_to)
        )
        if stratify_date_window:
            per_cat = min(10, max(3, limit // 25))
            fetch_sql = f"""
                WITH _matched AS (
                    SELECT {', '.join(select_cols)},
                           ROW_NUMBER() OVER (
                               PARTITION BY UPPER(COALESCE(category, ''))
                               ORDER BY timestamp_utc {order_dir}, timeline_id {order_dir}
                           ) AS _cat_rn,
                           ROW_NUMBER() OVER (
                               ORDER BY timestamp_utc {order_dir}, timeline_id {order_dir}
                           ) AS _glob_rn
                    FROM master_timeline
                    {where_sql}
                ),
                _picked AS (
                    SELECT *
                    FROM _matched
                    ORDER BY CASE WHEN _cat_rn <= {per_cat} THEN 0 ELSE 1 END ASC, _glob_rn ASC
                    LIMIT ?
                )
                SELECT {', '.join(out_col_names)}
                FROM _picked
                ORDER BY timestamp_utc {order_dir}, timeline_id {order_dir};
            """
            raw_events = cursor.execute(fetch_sql, params + [limit]).fetchall()
        else:
            fetch_sql = f"""
                SELECT {', '.join(select_cols)}
                FROM master_timeline
                {where_sql}
                ORDER BY timestamp_utc {order_dir}, timeline_id {order_dir}
                LIMIT ? OFFSET ?;
            """
            raw_events = cursor.execute(fetch_sql, params + [limit, offset]).fetchall()
        serialized_events = serialize_rows(out_col_names, raw_events)
        for ev in serialized_events:
            if ev.get("category"):
                ev["category"] = _normalize_canonical_category(ev["category"])

        hist_sql = f"""
            SELECT CAST(DATE_TRUNC('day', timestamp_utc) AS VARCHAR) AS day_bucket,
                   COUNT(*) AS event_count
            FROM master_timeline
            {where_sql}
            GROUP BY DATE_TRUNC('day', timestamp_utc)
            ORDER BY DATE_TRUNC('day', timestamp_utc) ASC;
        """
        raw_hist = cursor.execute(hist_sql, params).fetchall()
        histogram = [{"day": row[0], "count": int(row[1] or 0)} for row in raw_hist]

    resp_payload: Dict[str, Any] = {
        "case_id": case_id,
        "total_count": int(total_count or 0),
        "filtered_count": filtered_count,
        "min_timestamp_utc": serialize_db_value(min_ts_raw),
        "max_timestamp_utc": serialize_db_value(max_ts_raw),
        "sort_dir": order_dir.lower(),
        "around_timestamp": around_timestamp,
        "timeline": serialized_events,
        "histogram": histogram,
        "limit": limit,
        "offset": offset,
    }
    if around_timestamp:
        resp_payload["window_minutes"] = window_minutes
    return resp_payload


# ---------------------------------------------------------------------------
# 6. Connections Entity Graph
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/connections", summary="Interactive entity graph & cross-correlations")
@app.get("/api/cases/{case_id}/entities", include_in_schema=False)
def get_entity_connections(
    case_id: str,
    entity_value: Optional[str] = Query(""),
    search: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "entity_connections" not in tables_set:
            return {
                "case_id": case_id,
                "nodes": [],
                "edges": [],
                "top_entities": [],
                "occurrences": [],
                "total_occurrences": 0,
            }

        conn_cols = [
            "connection_id",
            "entity_type",
            "entity_value",
            "category",
            "artifact_name",
            "source_table",
            "source_row_id",
            "context_label",
            "timestamp_utc",
        ]

        if entity_value and entity_value.strip():
            target_val = entity_value.strip()
            raw_rows = cursor.execute(
                """
                SELECT connection_id, entity_type, entity_value, category, artifact_name,
                       source_table, source_row_id, context_label, timestamp_utc
                FROM entity_connections
                WHERE UPPER(entity_value) = UPPER(?)
                ORDER BY timestamp_utc DESC NULLS LAST;
                """,
                [target_val],
            ).fetchall()

            occurrences = serialize_rows(conn_cols, raw_rows)
            if not occurrences:
                return {
                    "case_id": case_id,
                    "entity_value": target_val,
                    "nodes": [],
                    "edges": [],
                    "occurrences": [],
                    "total_occurrences": 0,
                }

            primary_type = occurrences[0]["entity_type"]
            nodes = [
                {
                    "data": {
                        "id": f"entity_{target_val}",
                        "label": target_val,
                        "type": "PRIMARY_ENTITY",
                        "entity_type": primary_type,
                        "count": len(occurrences),
                    }
                }
            ]
            edges = []

            artifact_groups: Dict[str, Dict[str, Any]] = {}
            for row in occurrences:
                art = row["artifact_name"]
                cat = row["category"]
                if art not in artifact_groups:
                    artifact_groups[art] = {"category": cat, "count": 0}
                artifact_groups[art]["count"] += 1

            for art_name, meta in artifact_groups.items():
                art_node_id = f"artifact_{re.sub(r'[^A-Za-z0-9_]', '_', art_name)}"
                nodes.append({
                    "data": {
                        "id": art_node_id,
                        "label": art_name,
                        "type": "ARTIFACT_NODE",
                        "category": meta["category"],
                        "count": meta["count"],
                    }
                })
                edges.append({
                    "data": {
                        "id": f"edge_{target_val}_{art_node_id}",
                        "source": f"entity_{target_val}",
                        "target": art_node_id,
                        "label": f"{meta['count']} events",
                        "count": meta["count"],
                    }
                })

            return {
                "case_id": case_id,
                "entity_value": target_val,
                "entity_type": primary_type,
                "nodes": nodes,
                "edges": edges,
                "occurrences": occurrences,
                "total_occurrences": len(occurrences),
            }

        filter_clauses: List[str] = []
        filter_params: List[Any] = []
        if search and search.strip():
            sp = f"%{escape_ilike(search.strip())}%"
            filter_clauses.append(
                "(entity_value ILIKE ? ESCAPE '\\' OR artifact_name ILIKE ? ESCAPE '\\' OR COALESCE(context_label, '') ILIKE ? ESCAPE '\\')"
            )
            filter_params.extend([sp, sp, sp])
        kw_list = parse_list_param(keywords)
        if kw_list:
            kw_or = []
            for kw in kw_list:
                kp = f"%{escape_ilike(kw)}%"
                kw_or.append("(entity_value ILIKE ? ESCAPE '\\' OR artifact_name ILIKE ? ESCAPE '\\')")
                filter_params.extend([kp, kp])
            filter_clauses.append("(" + " OR ".join(kw_or) + ")")

        where_conn = f"WHERE {' AND '.join(filter_clauses)}" if filter_clauses else ""
        top_entities_raw = cursor.execute(
            f"""
            SELECT entity_type, entity_value,
                   COUNT(DISTINCT artifact_name) AS artifact_count,
                   COUNT(*) AS total_occurrences
            FROM entity_connections
            {where_conn}
            GROUP BY entity_type, entity_value
            ORDER BY artifact_count DESC, total_occurrences DESC
            LIMIT 50;
            """,
            filter_params,
        ).fetchall()

        top_entities = [
            {
                "entity_type": row[0],
                "entity_value": row[1],
                "artifact_count": row[2],
                "total_occurrences": row[3],
            }
            for row in top_entities_raw
        ]

        nodes = []
        edges = []
        seen_artifacts = set()

        for item in top_entities[:25]:
            val = item["entity_value"]
            ent_node_id = f"entity_{val}"
            nodes.append({
                "data": {
                    "id": ent_node_id,
                    "label": val,
                    "type": "PRIMARY_ENTITY",
                    "entity_type": item["entity_type"],
                    "occurrences": item["total_occurrences"],
                    "artifact_count": item["artifact_count"],
                }
            })

            linked_arts = cursor.execute(
                """
                SELECT artifact_name, category, COUNT(*) as cnt
                FROM entity_connections
                WHERE UPPER(entity_value) = UPPER(?)
                GROUP BY artifact_name, category;
                """,
                [val],
            ).fetchall()

            for art_name, cat, cnt in linked_arts:
                art_node_id = f"artifact_{re.sub(r'[^A-Za-z0-9_]', '_', art_name)}"
                if art_node_id not in seen_artifacts:
                    seen_artifacts.add(art_node_id)
                    nodes.append({
                        "data": {
                            "id": art_node_id,
                            "label": art_name,
                            "type": "ARTIFACT_NODE",
                            "category": cat,
                        }
                    })
                edges.append({
                    "data": {
                        "id": f"edge_{val}_{art_node_id}",
                        "source": ent_node_id,
                        "target": art_node_id,
                        "count": cnt,
                        "label": f"{cnt} hits",
                    }
                })

    return {
        "case_id": case_id,
        "nodes": nodes,
        "edges": edges,
        "top_entities": top_entities,
        "occurrences": [],
    }


# ---------------------------------------------------------------------------
# 7. Forensic File Resolution, Hex Viewer, Document & Media Streaming
# ---------------------------------------------------------------------------
IMAGE_READ_LOCK = threading.RLock()
_IMAGE_TARGET_CACHE: Dict[str, Any] = {}
_IMAGE_TARGET_LOCK = IMAGE_READ_LOCK

REJECTED_NTFS_DIRECTORIES = {
    "$recycle.bin",
    "system volume information",
    "config.msi",
    "perflogs",
    "$extend",
}

LOCKED_NTFS_METADATA_STREAMS = {
    "$mft",
    "$attrdef",
    "$badclus",
    "$bitmap",
    "$boot",
    "$logfile",
    "$secure",
    "$upcase",
    "$volume",
}


_RECYCLE_SID_RE = re.compile(r"^s-\d+(?:-\d+)+$", re.IGNORECASE)


def _has_path_traversal_segment(raw_path_str: str) -> bool:
    if not raw_path_str or not isinstance(raw_path_str, str):
        return False
    norm_bs = raw_path_str.strip().replace("/", "\\")
    return any(seg.strip() == ".." for seg in norm_bs.split("\\") if seg.strip())


def _is_forbidden_internal_or_unc_path(raw_path_str: str) -> bool:
    if not raw_path_str or not isinstance(raw_path_str, str):
        return True
    stripped = raw_path_str.strip()
    if not stripped or "\x00" in stripped:
        return True
    norm_bs = stripped.replace("/", "\\")
    if norm_bs.startswith("\\\\"):
        return True
    raw_segs = [seg.strip() for seg in norm_bs.split("\\") if seg.strip()]
    if any(seg == ".." for seg in raw_segs):
        return True
    leaf_low = raw_segs[-1].split(":")[0].strip().lower() if raw_segs else ""
    if leaf_low.startswith("case.duckdb") or leaf_low == "processing.log":
        return True
    if any(seg.lower().startswith("case.duckdb") or seg.lower() == "processing.log" for seg in raw_segs):
        return True
    return False


def is_rejected_or_non_regular_file(raw_path_str: str) -> bool:
    if _is_forbidden_internal_or_unc_path(raw_path_str):
        return True

    clean_p = raw_path_str.strip().replace("/", "\\")
    first_seg_low = clean_p.split("\\")[0].strip().lower()
    if first_seg_low.startswith("part") and ":" in first_seg_low:
        clean_p = "\\".join(clean_p.split("\\")[1:])
    elif first_seg_low.startswith("vss #") or first_seg_low.startswith("vss_"):
        clean_p = "\\".join(clean_p.split("\\")[1:])
    elif first_seg_low == "carved files":
        parts_cf = [p for p in clean_p.split("\\") if p and p != "."]
        return len(parts_cf) <= 1

    while clean_p.startswith(".\\") or clean_p.startswith("\\"):
        clean_p = clean_p[1:] if clean_p.startswith("\\") else clean_p[2:]
    if len(clean_p) >= 2 and clean_p[1] == ":":
        clean_p = clean_p[2:].lstrip("\\")

    parts = [part.lower() for part in clean_p.split("\\") if part and part != "."]
    if not parts:
        return True

    target_name = parts[-1].split(":")[0].strip()
    if target_name in LOCKED_NTFS_METADATA_STREAMS:
        return True
    if any(p.split(":")[0].strip() in LOCKED_NTFS_METADATA_STREAMS for p in parts):
        return True

    if target_name in REJECTED_NTFS_DIRECTORIES:
        return True
    if parts[0] == "$extend":
        return True
    if parts[0] == "$recycle.bin" and len(parts) == 2 and _RECYCLE_SID_RE.match(target_name):
        return True

    return False


KNOWN_TEXT_EXTS = {
    ".txt", ".log", ".csv", ".tsv", ".ini", ".inf", ".bat", ".cmd", ".ps1",
    ".reg", ".py", ".js", ".json", ".xml", ".html", ".htm", ".css", ".yaml",
    ".yml", ".md", ".cfg", ".conf", ".sql", ".vbs", ".sh", ".rtf", ".reb",
    ".map", ".def", ".props", ".targets", ".config",
}
KNOWN_IMAGE_EXTS_DICT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".svg": "image/svg+xml",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
}
KNOWN_MEDIA_EXTS_DICT = {
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".ogg": "video/ogg",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
}


def get_case_dissect_target(case_id: str) -> Optional[Any]:
    global _IMAGE_TARGET_CACHE
    with IMAGE_READ_LOCK:
        if case_id in _IMAGE_TARGET_CACHE:
            return _IMAGE_TARGET_CACHE[case_id]

        img_path: Optional[Path] = None
        try:
            db_path = get_case_db_path(case_id)
            if db_path.exists():
                with DuckDBManager.get_lock(case_id):
                    conn = DuckDBManager.get_connection(case_id, read_only=True)
                    cursor = conn.cursor()
                    tables = {
                        r[0]
                        for r in cursor.execute(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                        ).fetchall()
                    }
                    if "case_metadata" in tables:
                        meta_res = cursor.execute(
                            "SELECT value FROM case_metadata WHERE key = 'source_path' LIMIT 1;"
                        ).fetchone()
                        if meta_res and meta_res[0]:
                            sp_str = str(meta_res[0]).strip()
                            if sp_str and not sp_str.replace("/", "\\").startswith("\\\\"):
                                cand_m = Path(sp_str).resolve()
                                if cand_m.is_file():
                                    img_path = cand_m
                    if not img_path and "processing_logs" in tables:
                        res = cursor.execute(
                            "SELECT command_executed FROM processing_logs WHERE command_executed LIKE 'Extractor (%' ORDER BY log_id DESC LIMIT 1;"
                        ).fetchone()
                        if res and res[0] and ":" in res[0]:
                            parts = res[0].split(":", 1)
                            p_str = parts[1].strip()
                            if p_str and not p_str.replace("/", "\\").startswith("\\\\"):
                                cand = Path(p_str).resolve()
                                if cand.is_file():
                                    img_path = cand
        except Exception:
            pass

        if not img_path:
            log_file = get_case_log_file(case_id)
            if log_file.exists():
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if "Opening forensic image '" in line:
                                m = re.search(r"Opening forensic image '([^']+)'", line)
                                if m:
                                    p_str = m.group(1).strip()
                                    if p_str and not p_str.replace("/", "\\").startswith("\\\\"):
                                        cand = Path(p_str).resolve()
                                        if cand.is_file():
                                            img_path = cand
                                            break
                except Exception:
                    pass

        if img_path and img_path.exists():
            try:
                import dissect.target
                target = dissect.target.Target.open(str(img_path))
                _IMAGE_TARGET_CACHE[case_id] = target
                return target
            except Exception as ex:
                print(f"[backend] Notice opening dissect target for case {case_id}: {ex}")
                return None

        return None


def _check_confined_candidate(cand: Path, allowed_root: Path) -> Tuple[Optional[Path], bool]:
    """Return (resolved_file, is_directory_inside_root) strictly confined within allowed_root."""
    try:
        resolved = cand.resolve()
        if not resolved.is_relative_to(allowed_root):
            return None, False
        if resolved.name.lower().startswith("case.duckdb") or resolved.name.lower() == "processing.log":
            return None, False
        if resolved.is_dir():
            return None, True
        if resolved.is_file():
            return resolved, False
    except Exception:
        pass
    return None, False


def resolve_evidence_data(
    case_id: str,
    raw_path_str: str,
    offset: int = 0,
    length: Optional[int] = None,
) -> Tuple[Optional[bytes], int, str, str]:
    if is_rejected_or_non_regular_file(raw_path_str):
        return None, 0, Path(raw_path_str or "unknown").name, raw_path_str

    case_dir = get_case_dir(case_id, create_if_missing=False)
    if not case_dir.exists():
        return None, 0, Path(raw_path_str).name, raw_path_str

    case_root = case_dir.resolve()
    staging_dir = get_case_staging_dir(case_id)
    staging_root = staging_dir.resolve()
    carved_root = (case_dir / "carved").resolve()

    norm_p = raw_path_str.replace("\\", "/").strip()
    while norm_p.startswith("./"):
        norm_p = norm_p[2:]

    # Translate virtual filesystem prefixes ("Carved Files/...", "VSS #<N>/...", "Part<N>:/...")
    first_seg = norm_p.split("/")[0].strip() if norm_p else ""
    rest_after_first = "/".join(norm_p.split("/")[1:]).lstrip("/") if "/" in norm_p else ""
    is_carved_virtual = False
    vss_num: Optional[int] = None

    if first_seg.lower() == "carved files":
        is_carved_virtual = True
        norm_p = f"carved/{rest_after_first}" if rest_after_first else "carved"
    elif first_seg.lower().startswith("vss #"):
        m_vss = re.match(r"(?i)^vss\s*#\s*(\d+)$", first_seg)
        if m_vss:
            vss_num = int(m_vss.group(1))
            norm_p = f"staging/VSS/VSS_{vss_num}/{rest_after_first}".rstrip("/")
    elif first_seg.lower().startswith("part") and first_seg.endswith(":"):
        norm_p = rest_after_first

    if len(norm_p) >= 2 and norm_p[1] == ":":
        # Check if raw_path_str itself is an absolute host path strictly inside case_root
        raw_host_cand = Path(raw_path_str.strip())
        if raw_host_cand.is_absolute():
            allowed_for_abs = carved_root if "carved" in [p.lower() for p in raw_host_cand.parts] and not ("staging" in [p.lower() for p in raw_host_cand.parts]) else case_root
            f_abs, d_abs = _check_confined_candidate(raw_host_cand, allowed_for_abs)
            if d_abs:
                return None, 0, raw_host_cand.name, f"[DIRECTORY] {raw_path_str}"
            if f_abs:
                file_size = f_abs.stat().st_size
                chunk = b""
                if offset < file_size:
                    with open(f_abs, "rb") as fh:
                        if offset > 0:
                            fh.seek(offset)
                        chunk = fh.read(length if length is not None else file_size)
                return chunk, file_size, f_abs.name, str(f_abs)
        norm_p = norm_p[2:].lstrip("/")

    norm_p = norm_p.lstrip("/")
    rel_p = Path(norm_p) if norm_p else Path(".")
    if any(part == ".." for part in rel_p.parts):
        return None, 0, rel_p.name, raw_path_str
    file_stem_name = rel_p.name

    target_file: Optional[Path] = None

    # 1. Check DuckDB vfs_files and parsed_carved_files mappings first when DB exists
    db_path = get_case_db_path(case_id)
    if db_path.exists():
        try:
            with DuckDBManager.get_lock(case_id):
                conn = DuckDBManager.get_connection(case_id, read_only=True)
                cur = conn.cursor()
                tables = {
                    r[0]
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if "parsed_carved_files" in tables and (is_carved_virtual or norm_p.lower().startswith("carved/") or file_stem_name):
                    try:
                        pc_cols = {r[1] for r in cur.execute("PRAGMA table_info('parsed_carved_files');").fetchall()}
                        cp_expr = _sql_coalesce_present_cols(pc_cols, ["carved_rel_path", "carved_path"], "''")
                        fn_expr = _sql_coalesce_present_cols(
                            pc_cols,
                            ["file_name"],
                            f"regexp_extract({cp_expr}, '([^\\\\\\\\/]+)$', 1)",
                        )
                        cid_expr = _sql_coalesce_present_cols(pc_cols, ["carve_id"], "''", cast_as="VARCHAR")
                        c_row = cur.execute(
                            f"""
                            SELECT {cp_expr} FROM parsed_carved_files
                            WHERE LOWER(REPLACE({cp_expr}, '\\', '/')) = LOWER(?)
                               OR LOWER(COALESCE({fn_expr}, '')) = LOWER(?)
                               OR LOWER(COALESCE({cid_expr}, '')) = LOWER(?)
                            LIMIT 1;
                            """,
                            [norm_p, file_stem_name, Path(file_stem_name).stem],
                        ).fetchone()
                        if c_row and c_row[0]:
                            c_raw = str(c_row[0]).strip()
                            c_cand_list = [Path(c_raw)] if Path(c_raw).is_absolute() else []
                            c_rel = c_raw.replace("\\", "/").lstrip("/")
                            c_cand_list.extend([case_dir / c_rel, case_dir / "carved" / c_rel])
                            for c_cand in c_cand_list:
                                f_ok, _ = _check_confined_candidate(c_cand, carved_root)
                                if f_ok:
                                    target_file = f_ok
                                    break
                    except Exception:
                        pass

                if target_file is None and vss_num is not None and "vfs_shadow_copies" in tables:
                    try:
                        vs_cols = {r[1] for r in cur.execute("PRAGMA table_info('vfs_shadow_copies');").fetchall()}
                        if "staged_prefix" in vs_cols:
                            vi_col = _sql_coalesce_present_cols(vs_cols, ["vss_index", "store_index"], "0")
                            v_row = cur.execute(
                                f"SELECT staged_prefix FROM vfs_shadow_copies WHERE {vi_col} = ? LIMIT 1;",
                                [vss_num],
                            ).fetchone()
                            if v_row and v_row[0] and rest_after_first:
                                v_pref = str(v_row[0]).replace("\\", "/").strip("/")
                                for v_cand in (case_dir / v_pref / rest_after_first, staging_dir / v_pref / rest_after_first):
                                    f_ok, d_ok = _check_confined_candidate(v_cand, case_root)
                                    if d_ok:
                                        return None, 0, v_cand.name, f"[DIRECTORY] {raw_path_str}"
                                    if f_ok:
                                        target_file = f_ok
                                        break
                    except Exception:
                        pass

                if target_file is None and "vfs_files" in tables and norm_p:
                    try:
                        vf_cols = {r[1] for r in cur.execute("PRAGMA table_info('vfs_files');").fetchall()}
                        srp_expr = _sql_coalesce_present_cols(vf_cols, ["staged_rel_path", "staged_path"], "''")
                        dir_expr = _sql_coalesce_present_cols(vf_cols, ["is_dir", "is_directory"], "FALSE")
                        vp_expr = _sql_coalesce_present_cols(vf_cols, ["vfs_path"], "''")
                        p_col = "part_index" if "part_index" in vf_cols else ("partition_index" if "partition_index" in vf_cols else None)
                        norm_bs = norm_p.replace("/", "\\")
                        vf_where = [
                            f"LOWER(REPLACE({srp_expr}, '\\', '/')) = LOWER(?)",
                            f"LOWER(LTRIM(REPLACE({vp_expr}, '\\', '/'), './')) = LOWER(?)",
                            f"LOWER({vp_expr}) = LOWER(?)",
                        ]
                        vf_params: List[Any] = [norm_p, norm_p, f"C:\\{norm_bs}"]
                        if vss_num is not None and rest_after_first:
                            vss_vp = f"/VSS_{vss_num}/{rest_after_first.lstrip('/')}"
                            vf_where.append(f"LOWER(REPLACE({vp_expr}, '\\', '/')) = LOWER(?)")
                            vf_params.append(vss_vp)
                            if p_col:
                                vf_where.append(
                                    f"({p_col} = ? AND LOWER(LTRIM(REPLACE({vp_expr}, '\\', '/'), './')) = LOWER(?))"
                                )
                                vf_params.extend([-int(vss_num), rest_after_first.lstrip("/")])
                        vf_row = cur.execute(
                            f"""
                            SELECT {srp_expr}, {dir_expr} FROM vfs_files
                            WHERE {' OR '.join(vf_where)}
                            LIMIT 1;
                            """,
                            vf_params,
                        ).fetchone()
                        if vf_row:
                            if bool(vf_row[1]):
                                return None, 0, file_stem_name, f"[DIRECTORY] {raw_path_str}"
                            if vf_row[0]:
                                s_rel = str(vf_row[0]).replace("\\", "/").lstrip("/")
                                for s_cand in (staging_dir / s_rel, case_dir / s_rel):
                                    f_ok, d_ok = _check_confined_candidate(s_cand, case_root)
                                    if d_ok:
                                        return None, 0, s_cand.name, f"[DIRECTORY] {raw_path_str}"
                                    if f_ok:
                                        target_file = f_ok
                                        break
                    except Exception:
                        pass
        except Exception:
            pass

    # 2. Check deterministic host directories strictly confined under case_root / carved_root
    if target_file is None and norm_p:
        is_carved_rel = norm_p.lower() == "carved" or norm_p.lower().startswith("carved/")
        cand_pairs: List[Tuple[Path, Path]] = []
        if is_carved_rel or is_carved_virtual:
            sub_carved = Path(norm_p[7:]) if norm_p.lower().startswith("carved/") else rel_p
            cand_pairs.append((case_dir / norm_p, carved_root))
            cand_pairs.append((case_dir / "carved" / sub_carved, carved_root))
        else:
            cand_pairs.extend([
                (staging_dir / rel_p, staging_root),
                (case_dir / rel_p, case_root),
                (staging_dir / "Enrichment" / rel_p, staging_root),
                (staging_dir / "VSS" / rel_p, staging_root),
                (case_dir / "carved" / rel_p, carved_root),
            ])
            enr_root = staging_dir / "Enrichment"
            if enr_root.is_dir():
                for child_part in sorted(enr_root.iterdir()):
                    if child_part.is_dir():
                        cand_pairs.append((child_part / rel_p, staging_root))

        for cand_p, root_guard in cand_pairs:
            f_ok, d_ok = _check_confined_candidate(cand_p, root_guard)
            if d_ok:
                return None, 0, cand_p.name, f"[DIRECTORY] {raw_path_str}"
            if f_ok:
                target_file = f_ok
                break

    # 3. Fallback to flat staged category directories & suffix-preferring search inside staging/ & carved/
    if target_file is None and file_stem_name and file_stem_name not in (".", ".."):
        for flat_sub in ("Documents", "Carved_Thumbnails", "Notifications", "ActivitiesCache"):
            f_ok, _ = _check_confined_candidate(staging_dir / flat_sub / file_stem_name, staging_root)
            if f_ok:
                target_file = f_ok
                break

    if target_file is None and file_stem_name and file_stem_name not in (".", ".."):
        candidate_name = file_stem_name.lower()
        norm_suffix = norm_p.lower()
        fallback_match: Optional[Path] = None
        for scan_root, guard_root in ((staging_dir, staging_root), (case_dir / "carved", carved_root)):
            if not scan_root.is_dir():
                continue
            for cand in scan_root.rglob("*"):
                if cand.is_file() and cand.name.lower() == candidate_name:
                    f_ok, _ = _check_confined_candidate(cand, guard_root)
                    if f_ok:
                        rel_posix = str(f_ok.relative_to(case_root)).replace("\\", "/").lower()
                        if rel_posix.endswith(norm_suffix):
                            target_file = f_ok
                            break
                        if fallback_match is None:
                            fallback_match = f_ok
            if target_file is not None:
                break
        if target_file is None and fallback_match is not None:
            target_file = fallback_match

    if target_file and target_file.is_file():
        file_size = target_file.stat().st_size
        chunk = b""
        if offset < file_size:
            with open(target_file, "rb") as f:
                if offset > 0:
                    f.seek(offset)
                chunk = f.read(length if length is not None else file_size)
        return chunk, file_size, target_file.name, str(target_file.resolve())

    with IMAGE_READ_LOCK:
        target = get_case_dissect_target(case_id)
        if target:
            p = raw_path_str.replace("\\", "/").replace("//", "/")
            while p.startswith("./") or p.startswith("/"):
                p = p[1:] if p.startswith("/") else p[2:]
            if len(p) >= 2 and p[1] == ":":
                p = p[2:].lstrip("/")

            for fs in target.filesystems:
                try:
                    cand = fs.path(p)
                    if cand.exists():
                        if cand.is_dir():
                            return None, 0, cand.name, f"[DIRECTORY] vfs://{p}"
                        elif cand.is_file():
                            file_size = cand.stat().st_size
                            chunk = b""
                            if offset < file_size:
                                with cand.open("rb") as f:
                                    if offset > 0:
                                        f.seek(offset)
                                    chunk = f.read(length if length is not None else file_size)
                            return chunk, file_size, cand.name, f"vfs://{p}"
                except Exception:
                    continue

            parts = [x for x in p.split("/") if x]
            for fs in target.filesystems:
                try:
                    curr = fs.path("/")
                    matched = True
                    for part in parts:
                        found = False
                        for child in curr.iterdir():
                            if child.name.lower() == part.lower():
                                curr = child
                                found = True
                                break
                        if not found:
                            matched = False
                            break
                    if matched and curr.exists():
                        if curr.is_dir():
                            return None, 0, curr.name, f"[DIRECTORY] vfs://{p}"
                        elif curr.is_file():
                            file_size = curr.stat().st_size
                            chunk = b""
                            if offset < file_size:
                                with curr.open("rb") as f:
                                    if offset > 0:
                                        f.seek(offset)
                                    chunk = f.read(length if length is not None else file_size)
                            return chunk, file_size, curr.name, f"vfs://{p}"
                except Exception:
                    continue

    return None, 0, Path(raw_path_str).name, raw_path_str


def decode_text_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16be", errors="replace")
    if len(data) >= 4 and data[1::2].count(0) > (len(data) // 4):
        try:
            return data.decode("utf-16le", errors="replace")
        except Exception:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return data.decode("latin-1", errors="replace")


def extract_office_text(data: bytes, ext: str) -> Optional[str]:
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if ext == ".docx" and "word/document.xml" in z.namelist():
                xml = z.read("word/document.xml").decode("utf-8", errors="ignore")
                xml = re.sub(r"</w:p>", "\n", xml)
                return re.sub(r"<[^>]+>", "", xml).strip()
            elif ext == ".pptx" and any(n.startswith("ppt/slides/slide") for n in z.namelist()):
                slides = []
                for n in sorted(z.namelist()):
                    if n.startswith("ppt/slides/slide") and n.endswith(".xml"):
                        xml = z.read(n).decode("utf-8", errors="ignore")
                        slides.append(re.sub(r"<[^>]+>", " ", xml))
                return "\n\n--- Slide ---\n\n".join(slides)
            elif ext == ".xlsx" and "xl/sharedStrings.xml" in z.namelist():
                xml = z.read("xl/sharedStrings.xml").decode("utf-8", errors="ignore")
                strings = re.findall(r"<t[^>]*>(.*?)</t>", xml)
                return "\n".join(strings)
    except Exception:
        pass
    return None


def _require_target_file_param(file_path: Optional[str], path: Optional[str]) -> str:
    eff = (file_path if file_path is not None else path) or ""
    if not eff.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Query parameter 'file_path' (or 'path') is required.")
    return eff


@app.get("/api/cases/{case_id}/hex", summary="Hex & ASCII inspection of evidentiary files")
@app.get("/api/cases/{case_id}/vfs/hex", include_in_schema=False)
def get_hex_viewer(
    case_id: str,
    file_path: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    length: int = Query(4096, ge=16, le=65536),
    optional: bool = Query(False),
) -> Dict[str, Any]:
    eff_path = _require_target_file_param(file_path, path)
    if _has_path_traversal_segment(eff_path) or eff_path.strip().replace("/", "\\").startswith("\\\\"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal ('..') or remote UNC evidence export is forbidden.",
        )

    def _missing_hex_resp(detail_msg: str) -> Dict[str, Any]:
        if optional and get_case_dir(case_id, create_if_missing=False).is_dir():
            return {
                "case_id": case_id,
                "found": False,
                "error": detail_msg,
                "file_path": eff_path,
                "file_name": Path(eff_path).name,
                "file_size": 0,
                "offset": offset,
                "length": 0,
                "lines": [],
            }
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail_msg)

    if is_rejected_or_non_regular_file(eff_path):
        return _missing_hex_resp(f"Target is a directory or locked NTFS metadata stream: '{eff_path}'.")

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=eff_path,
            offset=offset,
            length=length,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        return _missing_hex_resp(f"Cannot inspect directory as a hex file: '{eff_path}'.")

    if chunk is None and file_size == 0:
        return _missing_hex_resp(f"Evidence file not found on disk or in image: '{eff_path}'.")

    lines = []
    if chunk:
        for i in range(0, len(chunk), 16):
            block = chunk[i : i + 16]
            block_offset = offset + i
            hex_bytes = " ".join(f"{b:02X}" for b in block)
            ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in block)
            lines.append({
                "offset": block_offset,
                "offset_hex": f"{block_offset:08X}",
                "hex_bytes": hex_bytes,
                "ascii_repr": ascii_chars,
            })

    return {
        "case_id": case_id,
        "found": True,
        "file_path": resolved_path,
        "file_name": file_name,
        "file_size": file_size,
        "offset": offset,
        "length": len(chunk) if chunk else 0,
        "lines": lines,
    }


@app.get("/api/cases/{case_id}/file/content", summary="Document & text content preview")
@app.get("/api/cases/{case_id}/vfs/preview", include_in_schema=False)
def get_file_content(
    case_id: str,
    file_path: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
    max_bytes: int = Query(2_000_000),
    optional: bool = Query(False),
) -> Dict[str, Any]:
    eff_path = _require_target_file_param(file_path, path)
    if _has_path_traversal_segment(eff_path) or eff_path.strip().replace("/", "\\").startswith("\\\\"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal ('..') or remote UNC evidence export is forbidden.",
        )

    def _missing_content_resp(detail_msg: str) -> Dict[str, Any]:
        if optional and get_case_dir(case_id, create_if_missing=False).is_dir():
            return {
                "case_id": case_id,
                "found": False,
                "error": detail_msg,
                "file_name": Path(eff_path).name,
                "file_path": eff_path,
                "file_size": 0,
                "extension": Path(eff_path).suffix.lower(),
                "mime_type": "application/octet-stream",
                "is_text": False,
                "is_image": False,
                "is_pdf": False,
                "is_media": False,
                "is_office": False,
                "text_content": None,
                "truncated": False,
                "raw_url": "",
            }
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail_msg)

    if is_rejected_or_non_regular_file(eff_path):
        return _missing_content_resp(f"Target is a directory or locked NTFS metadata stream: '{eff_path}'.")

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=eff_path,
            offset=0,
            length=max_bytes,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        return _missing_content_resp(f"Cannot preview directory content: '{eff_path}'.")

    if chunk is None and file_size == 0:
        return _missing_content_resp(f"Evidence file not found: '{eff_path}'.")

    ext = Path(file_name).suffix.lower()
    is_text = ext in KNOWN_TEXT_EXTS
    is_image = ext in KNOWN_IMAGE_EXTS_DICT
    is_pdf = ext == ".pdf"
    is_media = ext in KNOWN_MEDIA_EXTS_DICT or is_image
    is_office = ext in {".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt"}

    text_content: Optional[str] = None
    truncated = False

    if is_text and chunk:
        text_content = decode_text_bytes(chunk)
        if file_size > len(chunk):
            truncated = True
    elif is_office and chunk:
        office_text = extract_office_text(chunk, ext)
        if office_text:
            text_content = office_text
            is_text = True
    elif not is_image and not is_pdf and not is_media and chunk:
        if chunk and b"\x00" not in chunk[:512]:
            text_content = decode_text_bytes(chunk)
            is_text = True
            if file_size > len(chunk):
                truncated = True

    import urllib.parse
    raw_url = f"/api/cases/{case_id}/file/raw?file_path={urllib.parse.quote(eff_path)}"

    mime_type = "application/octet-stream"
    if is_image:
        mime_type = KNOWN_IMAGE_EXTS_DICT.get(ext, "image/png")
    elif is_pdf:
        mime_type = "application/pdf"
    elif is_text:
        mime_type = "text/plain"
    elif ext in KNOWN_MEDIA_EXTS_DICT:
        mime_type = KNOWN_MEDIA_EXTS_DICT[ext]

    return {
        "case_id": case_id,
        "file_name": file_name,
        "file_path": resolved_path,
        "file_size": file_size,
        "extension": ext,
        "mime_type": mime_type,
        "is_text": is_text,
        "is_image": is_image,
        "is_pdf": is_pdf,
        "is_media": is_media,
        "is_office": is_office,
        "text_content": text_content,
        "truncated": truncated,
        "raw_url": raw_url,
    }


@app.get("/api/cases/{case_id}/file/raw", summary="Stream raw evidentiary file bytes")
@app.get("/api/cases/{case_id}/vfs/download", include_in_schema=False)
@app.get("/api/cases/{case_id}/raw-file", include_in_schema=False)
def get_file_raw(
    case_id: str,
    file_path: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
    download: bool = Query(False),
):
    eff_path = _require_target_file_param(file_path, path)
    if _has_path_traversal_segment(eff_path) or eff_path.strip().replace("/", "\\").startswith("\\\\"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal ('..') or remote UNC evidence export is forbidden.",
        )
    if is_rejected_or_non_regular_file(eff_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target is a directory or locked NTFS metadata stream: '{eff_path}'.",
        )

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=eff_path,
            offset=0,
            length=None,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot stream directory bytes: '{eff_path}'.",
        )

    if chunk is None and file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found: '{eff_path}'.",
        )

    ext = Path(file_name).suffix.lower()
    mime_type = "application/octet-stream"
    if ext in KNOWN_IMAGE_EXTS_DICT:
        mime_type = KNOWN_IMAGE_EXTS_DICT[ext]
    elif ext == ".pdf":
        mime_type = "application/pdf"
    elif ext in KNOWN_TEXT_EXTS:
        mime_type = "text/plain; charset=utf-8"
    elif ext in KNOWN_MEDIA_EXTS_DICT:
        mime_type = KNOWN_MEDIA_EXTS_DICT[ext]

    disposition = "attachment" if download else "inline"
    headers = {
        "Content-Disposition": f'{disposition}; filename="{file_name}"',
        "Content-Length": str(file_size),
        "Accept-Ranges": "bytes",
    }
    return Response(content=chunk or b"", media_type=mime_type, headers=headers)


@app.get("/api/cases/{case_id}/pe-analysis", summary="Portable Executable (PE) structural & header analysis")
@app.get("/api/cases/{case_id}/vfs/pe-analysis", include_in_schema=False)
def get_pe_analysis(
    case_id: str,
    file_path: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
) -> Dict[str, Any]:
    import hashlib
    eff_path = _require_target_file_param(file_path, path)
    if _has_path_traversal_segment(eff_path) or eff_path.strip().replace("/", "\\").startswith("\\\\"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal ('..') or remote UNC evidence export is forbidden.",
        )
    if is_rejected_or_non_regular_file(eff_path):
        raise HTTPException(status_code=404, detail=f"Target is a directory or locked NTFS metadata stream: '{eff_path}'.")

    with IMAGE_READ_LOCK:
        data, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=eff_path,
            offset=0,
            length=32 * 1024 * 1024,
        )

    if resolved_path.startswith("[DIRECTORY]") or (data is None and file_size == 0):
        raise HTTPException(status_code=404, detail=f"Evidence file not found: '{eff_path}'.")

    raw_bytes = data or b""
    sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
    md5_hex = hashlib.md5(raw_bytes).hexdigest()
    if len(raw_bytes) < 64 or not raw_bytes.startswith(b"MZ"):
        return {
            "case_id": case_id,
            "file_name": file_name,
            "file_path": resolved_path,
            "file_size": file_size,
            "is_pe": False,
            "sha256": sha256_hex,
            "md5": md5_hex,
            "sections": [],
            "imports": [],
            "exports": [],
            "message": "File does not have a valid DOS MZ / PE header.",
        }

    try:
        import pefile
        pe = pefile.PE(data=raw_bytes, fast_load=False)
        compile_ts = int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0)
        compile_utc = (
            datetime.fromtimestamp(compile_ts, tz=timezone.utc).isoformat()
            if compile_ts > 0
            else None
        )
        machine = int(getattr(pe.FILE_HEADER, "Machine", 0) or 0)
        arch = "x64" if machine == 0x8664 else ("x86" if machine == 0x014C else f"0x{machine:04X}")
        sections = []
        for sec in getattr(pe, "sections", []):
            sec_name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            sections.append({
                "name": sec_name,
                "virtual_address": hex(sec.VirtualAddress),
                "virtual_size": int(sec.Misc_VirtualSize),
                "raw_size": int(sec.SizeOfRawData),
                "entropy": round(float(sec.get_entropy()), 3),
            })
        imports_list = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:50]:
            dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
            funcs = [
                (imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}")
                for imp in entry.imports[:50]
            ]
            imports_list.append({"dll": dll_name, "functions": funcs, "count": len(entry.imports)})
        exports_list = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", [])[:100]:
                if sym.name:
                    exports_list.append(sym.name.decode("utf-8", errors="replace"))
        imphash = ""
        try:
            imphash = pe.get_imphash()
        except Exception:
            imphash = ""
        return {
            "case_id": case_id,
            "file_name": file_name,
            "file_path": resolved_path,
            "file_size": file_size,
            "is_pe": True,
            "architecture": arch,
            "compile_timestamp_utc": compile_utc,
            "entry_point": hex(int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0)),
            "image_base": hex(int(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0) or 0)),
            "imphash": imphash,
            "sha256": sha256_hex,
            "md5": md5_hex,
            "sections": sections,
            "imports": imports_list,
            "exports": exports_list,
        }
    except Exception as pe_err:
        return {
            "case_id": case_id,
            "file_name": file_name,
            "file_path": resolved_path,
            "file_size": file_size,
            "is_pe": False,
            "sha256": sha256_hex,
            "md5": md5_hex,
            "sections": [],
            "imports": [],
            "exports": [],
            "error": str(pe_err),
        }


# ---------------------------------------------------------------------------
# 7.0 Forensic File, Folder & Artifact Export Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/export/file", summary="Export / Download raw evidence file")
def export_evidence_file(
    case_id: str,
    file_path: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
):
    eff_path = _require_target_file_param(file_path, path)
    if _has_path_traversal_segment(eff_path) or eff_path.strip().replace("/", "\\").startswith("\\\\"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal ('..') or remote UNC evidence export is forbidden.",
        )
    if is_rejected_or_non_regular_file(eff_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target is a directory or locked NTFS metadata stream: '{eff_path}'.",
        )

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=eff_path,
            offset=0,
            length=None,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target is a directory, not a file: '{eff_path}'. Please use folder export.",
        )

    if chunk is None and file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found on disk or in image: '{eff_path}'.",
        )

    safe_name = Path(file_name).name or "evidence_file"
    ext = Path(safe_name).suffix.lower()
    mime_type = "application/octet-stream"
    if ext in KNOWN_IMAGE_EXTS_DICT:
        mime_type = KNOWN_IMAGE_EXTS_DICT[ext]
    elif ext == ".pdf":
        mime_type = "application/pdf"
    elif ext in KNOWN_TEXT_EXTS:
        mime_type = "text/plain; charset=utf-8"
    elif ext in KNOWN_MEDIA_EXTS_DICT:
        mime_type = KNOWN_MEDIA_EXTS_DICT[ext]

    headers = {
        "Content-Disposition": f'attachment; filename="{safe_name}"',
        "Content-Length": str(file_size if file_size else (len(chunk) if chunk else 0)),
        "Accept-Ranges": "bytes",
    }
    return Response(content=chunk or b"", media_type=mime_type, headers=headers)


def _is_excluded_export_entry_name(name: str) -> bool:
    base = (name or "").split(":")[0].strip().lower().rstrip(".")
    if not base:
        return False
    if base.startswith("case.duckdb") or base == "processing.log":
        return True
    if base == "$extend" or base.startswith("$usnjrnl"):
        return True
    if base in LOCKED_NTFS_METADATA_STREAMS:
        return True
    return False


def _is_rejected_export_folder(raw_folder: str) -> bool:
    clean_p = (raw_folder or "").strip().replace("/", "\\")
    if not clean_p:
        return True
    first_seg_low = clean_p.split("\\")[0].strip().lower()
    if first_seg_low.startswith("part") and ":" in first_seg_low:
        clean_p = "\\".join(clean_p.split("\\")[1:])
    elif first_seg_low.startswith("vss #") or first_seg_low.startswith("vss_"):
        clean_p = "\\".join(clean_p.split("\\")[1:])
    elif first_seg_low in ("carved files", "carved"):
        rem_cf = "\\".join(clean_p.split("\\")[1:])
        if not rem_cf.strip("\\."):
            return False
        clean_p = rem_cf

    while clean_p.startswith(".\\") or clean_p.startswith("\\"):
        clean_p = clean_p[1:] if clean_p.startswith("\\") else clean_p[2:]
    if len(clean_p) >= 2 and clean_p[1] == ":":
        clean_p = clean_p[2:].lstrip("\\")

    parts = [p.split(":")[0].strip().lower().rstrip(".") for p in clean_p.split("\\") if p and p != "."]
    if not parts or parts == ["root"]:
        return False

    if any(p == "$extend" or p.startswith("$usnjrnl") or p in LOCKED_NTFS_METADATA_STREAMS for p in parts):
        return True
    target_name = parts[-1]
    if target_name in REJECTED_NTFS_DIRECTORIES or target_name in LOCKED_NTFS_METADATA_STREAMS:
        return True
    if parts[0] == "$recycle.bin" and len(parts) == 2 and _RECYCLE_SID_RE.match(target_name):
        return True
    return False


def _resolve_export_folder_confined(case_id: str, raw_folder: str) -> Tuple[Optional[Path], str]:
    if _is_forbidden_internal_or_unc_path(raw_folder):
        raise HTTPException(status_code=400, detail=f"Forbidden folder export path: '{raw_folder}'.")
    if _is_rejected_export_folder(raw_folder):
        raise HTTPException(status_code=404, detail=f"Restricted NTFS directory cannot be exported: '{raw_folder}'.")
    case_dir = get_case_dir(case_id, create_if_missing=False)
    if not case_dir.exists():
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    staging_dir = get_case_staging_dir(case_id)
    staging_root = staging_dir.resolve()
    carved_root = (case_dir / "carved").resolve()

    norm_f = raw_folder.strip().replace("\\", "/").strip("/")
    while norm_f.startswith("./"):
        norm_f = norm_f[2:].strip("/")
    if norm_f in (".", "root"):
        norm_f = ""
    first_seg = norm_f.split("/")[0].strip() if norm_f else ""
    rest_seg = "/".join(norm_f.split("/")[1:]).lstrip("/") if "/" in norm_f else ""

    is_carved_folder = False
    vss_idx_num: Optional[int] = None
    if first_seg.lower() in ("carved files", "carved"):
        is_carved_folder = True
        norm_f = rest_seg
    elif first_seg.lower().startswith("vss #") or re.match(r"(?i)^vss_\d+$", first_seg):
        m_vss = re.match(r"(?i)^vss(?:\s*#\s*|_)?(\d+)$", first_seg)
        if m_vss:
            vss_idx_num = int(m_vss.group(1))
            norm_f = rest_seg
    elif first_seg.lower().startswith("part") and first_seg.endswith(":"):
        norm_f = rest_seg

    if len(norm_f) >= 2 and norm_f[1] == ":":
        norm_f = norm_f[2:].lstrip("/")

    clean_p = Path(norm_f) if norm_f else None
    if clean_p and any(part == ".." for part in clean_p.parts):
        raise HTTPException(status_code=400, detail="Directory traversal in folder export is forbidden.")

    if is_carved_folder:
        safe_folder_name = clean_p.name if clean_p else "carved"
    elif vss_idx_num is not None:
        safe_folder_name = clean_p.name if clean_p else f"VSS_{vss_idx_num}"
    else:
        safe_folder_name = clean_p.name if clean_p else "root"
    if not safe_folder_name or safe_folder_name in (".", "..", "\\", "/"):
        safe_folder_name = "evidence_folder"

    cand_pairs: List[Tuple[Path, Path]] = []
    if is_carved_folder:
        cand_pairs.append(((carved_root / clean_p) if clean_p else carved_root, carved_root))
    elif vss_idx_num is not None:
        for v_base in (staging_dir / "VSS" / f"VSS_{vss_idx_num}", staging_dir / "VSS" / f"vss_{vss_idx_num}", staging_dir / f"vss_{vss_idx_num}"):
            cand_pairs.append(((v_base / clean_p) if clean_p else v_base, staging_root))
    elif clean_p:
        if norm_f.lower().startswith("staging/"):
            sub_stg = Path(norm_f[8:]) if len(norm_f) > 8 else None
            cand_pairs.append(((staging_dir / sub_stg) if sub_stg else staging_dir, staging_root))
        cand_pairs.append((staging_dir / clean_p, staging_root))
        cand_pairs.append((staging_dir / "Enrichment" / clean_p, staging_root))
        if (staging_dir / "Enrichment").is_dir():
            for p_sub in sorted((staging_dir / "Enrichment").iterdir()):
                if p_sub.is_dir():
                    cand_pairs.append((p_sub / clean_p, staging_root))
    else:
        cand_pairs.append((staging_dir, staging_root))

    for c_dir, allowed_root in cand_pairs:
        try:
            res_d = c_dir.resolve()
            if res_d.is_relative_to(allowed_root) and res_d.is_dir():
                return res_d, safe_folder_name
        except Exception:
            continue
    return None, safe_folder_name


@app.get("/api/cases/{case_id}/export/folder-zip", summary="Export folder as streaming .zip archive")
@app.get("/api/cases/{case_id}/export/folder", include_in_schema=False)
def export_folder_zip(
    case_id: str,
    folder_path: Optional[str] = Query(None),
    path: Optional[str] = Query(None),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    if folder_path is None and path is None:
        raise HTTPException(status_code=400, detail="Query parameter 'folder_path' or 'path' is required")
    eff_folder = folder_path if folder_path is not None else (path or "")
    with IMAGE_READ_LOCK:
        cand_dir, safe_folder_name = _resolve_export_folder_confined(case_id, eff_folder or "root")
        if not cand_dir or not cand_dir.is_dir():
            raise HTTPException(status_code=404, detail="Evidence folder not found")

        temp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        temp_zip_path = temp_zip.name
        temp_zip.close()

        files_written = 0
        with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(cand_dir):
                dirs[:] = [d for d in dirs if not _is_excluded_export_entry_name(d)]
                for file in files:
                    if _is_excluded_export_entry_name(file):
                        continue
                    fp = Path(root) / file
                    arcname = str(fp.relative_to(cand_dir)).replace("\\", "/")
                    try:
                        zf.write(fp, arcname=arcname)
                        files_written += 1
                    except Exception:
                        pass
                    if files_written >= 3000:
                        break
                if files_written >= 3000:
                    break

        background_tasks.add_task(os.unlink, temp_zip_path)
        return FileResponse(
            path=temp_zip_path,
            filename=f"{safe_folder_name}_export.zip",
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{safe_folder_name}_export.zip"'},
            background=background_tasks,
        )


@app.post("/api/cases/{case_id}/export/save-to-folder", summary="Export file, folder or artifact to custom Windows folder")
def save_to_folder(
    case_id: str,
    payload: SaveToFolderRequest,
):
    case_dir = get_case_dir(case_id, create_if_missing=False)
    case_root_resolved = case_dir.resolve() if case_dir.exists() else None
    recorded_source_resolved: Optional[Path] = None
    db_path = get_case_db_path(case_id)
    if db_path.exists():
        try:
            with DuckDBManager.get_lock(case_id):
                conn_chk = DuckDBManager.get_connection(case_id, read_only=case_id not in _running_cases)
                cur_chk = conn_chk.cursor()
                tbls_chk = {
                    r[0]
                    for r in cur_chk.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if "case_metadata" in tbls_chk:
                    sp_row = cur_chk.execute(
                        "SELECT value FROM case_metadata WHERE key = 'source_path' LIMIT 1;"
                    ).fetchone()
                    if sp_row and sp_row[0]:
                        sp_s = str(sp_row[0]).strip()
                        if sp_s and not sp_s.replace("/", "\\").startswith("\\\\"):
                            recorded_source_resolved = Path(sp_s).resolve()
        except Exception:
            recorded_source_resolved = None

    raw_dest = (payload.destination_dir or payload.destination_folder or payload.dest_dir or "").strip().strip('"').strip("'").strip()
    if raw_dest:
        if raw_dest.replace("/", "\\").startswith("\\\\"):
            raise HTTPException(status_code=400, detail="Remote UNC destination directories are forbidden.")
        try:
            dest_dir = Path(raw_dest).resolve()
        except (OSError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid destination_dir path.")
        if case_root_resolved is not None and (
            dest_dir == case_root_resolved or dest_dir.is_relative_to(case_root_resolved)
        ):
            raise HTTPException(
                status_code=400,
                detail="destination_dir must not equal or reside inside the case directory.",
            )
        if recorded_source_resolved is not None:
            if dest_dir == recorded_source_resolved or (
                recorded_source_resolved.exists()
                and recorded_source_resolved.is_dir()
                and dest_dir.is_relative_to(recorded_source_resolved)
            ):
                raise HTTPException(
                    status_code=400,
                    detail="destination_dir must not equal or reside inside source_path.",
                )
        if dest_dir.exists() and not dest_dir.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Selected destination '{dest_dir}' is not a directory.",
            )
        if not dest_dir.exists():
            try:
                dest_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot create destination directory '{dest_dir}': {exc}",
                )
    else:
        picker_res = _run_native_picker(mode="folder")
        if picker_res.get("cancelled") or not picker_res.get("path"):
            return {"success": False, "cancelled": True, "message": "Export cancelled by examiner."}
        dest_dir = Path(picker_res["path"]).resolve()
        if not dest_dir.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Selected destination directory '{dest_dir}' does not exist.",
            )
        if case_root_resolved is not None and (
            dest_dir == case_root_resolved or dest_dir.is_relative_to(case_root_resolved)
        ):
            raise HTTPException(
                status_code=400,
                detail="destination_dir must not equal or reside inside the case directory.",
            )

    target_path_str = (payload.file_path or payload.folder_path or payload.path or payload.source_path or "").strip()
    is_folder_req = bool(payload.is_folder or (payload.folder_path and str(payload.folder_path).strip()))
    if target_path_str:
        if is_folder_req:
            cand_dir, safe_folder_name = _resolve_export_folder_confined(case_id, target_path_str)
            if not cand_dir or not cand_dir.is_dir():
                raise HTTPException(status_code=404, detail=f"Evidence folder not found: '{target_path_str}'.")

            target_folder = dest_dir / safe_folder_name
            shutil.copytree(
                cand_dir,
                target_folder,
                dirs_exist_ok=True,
                ignore=lambda _d, names: [n for n in names if _is_excluded_export_entry_name(n)],
            )
            return {
                "success": True,
                "cancelled": False,
                "destination_folder": str(dest_dir),
                "destination_dir": str(dest_dir),
                "saved_path": str(target_folder),
                "message": f"Successfully exported folder {safe_folder_name} to {dest_dir}",
            }

        if is_rejected_or_non_regular_file(target_path_str):
            raise HTTPException(status_code=404, detail=f"Target is a directory or locked NTFS metadata stream: '{target_path_str}'.")

        with IMAGE_READ_LOCK:
            chunk, file_size, file_name, resolved_p = resolve_evidence_data(
                case_id=case_id,
                raw_path_str=target_path_str,
                offset=0,
                length=None,
            )
        if resolved_p.startswith("[DIRECTORY]") or (chunk is None and file_size == 0):
            raise HTTPException(status_code=404, detail=f"Evidence file not found: '{target_path_str}'.")
        safe_name = Path(file_name).name or "evidence_file"
        target_file = dest_dir / safe_name
        target_file.write_bytes(chunk or b"")
        return {
            "success": True,
            "cancelled": False,
            "destination_folder": str(dest_dir),
            "destination_dir": str(dest_dir),
            "saved_path": str(target_file),
            "message": f"Successfully exported {safe_name} to {dest_dir}",
        }

    if payload.table_name:
        clean_tbl = _validate_existing_table_or_raise(case_id, payload.table_name)
        if payload.row_id is not None:
            out_file = dest_dir / f"{clean_tbl}_row_{payload.row_id}.json"
            with DuckDBManager.get_lock(case_id):
                conn = ensure_case_exists(case_id, auto_create=False)
                cursor = conn.cursor()
                cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{clean_tbl}");').fetchall()]
                if "_row_id" in cols:
                    row = cursor.execute(f'SELECT * FROM "{clean_tbl}" WHERE _row_id = ?;', [payload.row_id]).fetchone()
                else:
                    row = cursor.execute(f'SELECT * FROM "{clean_tbl}" LIMIT 1;').fetchone()

            if not row:
                raise HTTPException(status_code=404, detail=f"Row '{payload.row_id}' not found in table '{clean_tbl}'.")

            row_dict = {cols[i]: serialize_db_value(row[i]) for i in range(len(cols))}
            out_file.write_text(json.dumps(row_dict, indent=2), encoding="utf-8")
            return {
                "success": True,
                "cancelled": False,
                "destination_folder": str(dest_dir),
                "destination_dir": str(dest_dir),
                "saved_path": str(out_file),
                "message": f"Successfully exported row to {out_file}",
            }

        out_file = dest_dir / f"{clean_tbl}_export.csv"
        with DuckDBManager.get_lock(case_id):
            conn = ensure_case_exists(case_id, auto_create=False)
            cursor = conn.cursor()
            cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{clean_tbl}");').fetchall()]
            rows = cursor.execute(f'SELECT * FROM "{clean_tbl}";').fetchall()

        import csv
        with open(out_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(cols)
            for r in rows:
                writer.writerow([serialize_db_value(v) for v in r])

        return {
            "success": True,
            "cancelled": False,
            "destination_folder": str(dest_dir),
            "destination_dir": str(dest_dir),
            "saved_path": str(out_file),
            "message": f"Successfully exported table to {out_file}",
        }

    raise HTTPException(status_code=400, detail="Missing export parameters.")


@app.get("/api/cases/{case_id}/table/{table_name}/export/csv", summary="Export table to downloadable CSV")
@app.get("/api/cases/{case_id}/artifacts/{table_name}/export", include_in_schema=False)
@app.get("/api/cases/{case_id}/export/csv", include_in_schema=False)
def export_table_csv(
    case_id: str,
    table_name: Optional[str] = None,
    table: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
):
    eff_table = table_name if table_name is not None else table
    clean_tbl = _validate_existing_table_or_raise(case_id, eff_table)

    paginated = _query_table_paginated_safe(
        case_id=case_id,
        clean_table=clean_tbl,
        limit=1_000_000,
        offset=0,
        search=search or "",
        start_time=start_time,
        end_time=end_time,
        date_from=date_from,
        date_to=date_to,
        keywords=keywords,
        tags=tags,
        bookmarked_only=bookmarked_only,
    )
    cols = paginated["columns"]

    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(cols)
    for r_dict in paginated["rows"]:
        writer.writerow([serialize_db_value(r_dict.get(c)) for c in cols])

    csv_bytes = output.getvalue().encode("utf-8")
    headers = {
        "Content-Disposition": f'attachment; filename="{clean_tbl}_export.csv"',
        "Content-Length": str(len(csv_bytes)),
    }
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)


@app.get("/api/cases/{case_id}/table/{table_name}/export/json", summary="Export table to downloadable JSON")
@app.get("/api/cases/{case_id}/artifacts/{table_name}/export/json", include_in_schema=False)
@app.get("/api/cases/{case_id}/export/json", include_in_schema=False)
def export_table_json(
    case_id: str,
    table_name: Optional[str] = None,
    table: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
):
    eff_table = table_name if table_name is not None else table
    clean_tbl = _validate_existing_table_or_raise(case_id, eff_table)

    paginated = _query_table_paginated_safe(
        case_id=case_id,
        clean_table=clean_tbl,
        limit=1_000_000,
        offset=0,
        search=search or "",
        start_time=start_time,
        end_time=end_time,
        date_from=date_from,
        date_to=date_to,
        keywords=keywords,
        tags=tags,
        bookmarked_only=bookmarked_only,
    )
    rows_out = [{k: serialize_db_value(v) for k, v in r_dict.items()} for r_dict in paginated["rows"]]
    json_bytes = json.dumps(rows_out, indent=2).encode("utf-8")
    headers = {
        "Content-Disposition": f'attachment; filename="{clean_tbl}_export.json"',
        "Content-Length": str(len(json_bytes)),
    }
    return Response(content=json_bytes, media_type="application/json", headers=headers)


# ---------------------------------------------------------------------------
# 7.1 File System Browser
# ---------------------------------------------------------------------------
def _normalize_filesystem_path(p: Any) -> str:
    if not isinstance(p, str):
        return "."
    s = p.strip().replace("/", "\\")
    if s in ("", ".", "\\", ".\\", "/"):
        return "."
    if s.startswith(".\\"):
        s = s[2:]
    s = s.strip("\\")
    if not s:
        return "."
    return f".\\{s}"


def _parse_vfs_virtual_prefix(raw_path: Optional[str]) -> Tuple[str, Optional[int], Optional[int], str]:
    """Classify virtual VFS paths into ('root'|'carved'|'vss'|'part'|'folder', part_idx, vss_idx, inner_rel)."""
    s = (raw_path or "").strip().replace("/", "\\")
    if s in ("", ".", "\\", ".\\"):
        return ("root", None, None, ".")
    s_clean = s[2:] if s.startswith(".\\") else s
    s_clean = s_clean.strip("\\")
    low = s_clean.lower()
    if low in ("carved files", "carved", "__carved__"):
        return ("carved", None, None, ".")
    for cpfx in ("carved files\\", "carved\\", "__carved__\\"):
        if low.startswith(cpfx):
            rem = s_clean[len(cpfx):].strip("\\")
            return ("carved", None, None, f".\\{rem}" if rem else ".")
    m_vss = re.match(r"^(?:vss\s*#?\s*(\d+)|vss_(\d+)|__vss_?(\d+)__)(?:\\(.*))?$", s_clean, flags=re.IGNORECASE)
    if m_vss:
        v_idx = int(m_vss.group(1) or m_vss.group(2) or m_vss.group(3))
        rem = (m_vss.group(4) or "").strip("\\")
        return ("vss", None, v_idx, f".\\{rem}" if rem else ".")
    m_part = re.match(r"^(?:part_?(\d+):?|partition\s*(\d+):?|__part(\d+)__)(?:\\(.*))?$", s_clean, flags=re.IGNORECASE)
    if m_part:
        p_idx = int(m_part.group(1) or m_part.group(2) or m_part.group(3))
        rem = (m_part.group(4) or "").strip("\\")
        return ("part", p_idx, None, f".\\{rem}" if rem else ".")
    return ("folder", None, None, f".\\{s_clean}")


def _is_timestomped_pair(si_created: Any, fn_created: Any, si_modified: Any = None, fn_modified: Any = None) -> bool:
    """Detect NTFS $SI vs $FN timestomping (>2s drift where $SI predates $FN or zeroed fractional anomalies)."""
    for si_val, fn_val in ((si_created, fn_created), (si_modified, fn_modified)):
        if not si_val or not fn_val:
            continue
        try:
            si_dt = si_val if isinstance(si_val, datetime) else datetime.fromisoformat(str(si_val).replace("Z", "+00:00"))
            fn_dt = fn_val if isinstance(fn_val, datetime) else datetime.fromisoformat(str(fn_val).replace("Z", "+00:00"))
            if si_dt.tzinfo is not None:
                si_dt = si_dt.astimezone(timezone.utc).replace(tzinfo=None)
            if fn_dt.tzinfo is not None:
                fn_dt = fn_dt.astimezone(timezone.utc).replace(tzinfo=None)
            if (fn_dt - si_dt).total_seconds() > 2.0:
                return True
        except Exception:
            continue
    return False


def _clean_legacy_synthetic_mft(cur: duckdb.DuckDBPyConnection) -> None:
    """Purge any legacy synthetic partition placeholder rows from raw_mft."""
    try:
        cur.execute("DELETE FROM raw_mft WHERE regexp_matches(COALESCE(ParentPath, ''), '^\\.\\\\__[A-Z]+[0-9]+__');")
    except Exception:
        pass


def _make_tree_folder_dict(
    folder_name: str,
    folder_path: str,
    parent_path: str,
    file_count: int = 0,
    in_use: bool = True,
    mft_entry: int = 0,
    seq_num: int = 0,
    node_type: str = "folder",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "folder_name": folder_name,
        "name": folder_name,
        "folder_path": folder_path,
        "path": folder_path,
        "parent_path": parent_path,
        "mft_entry_number": int(mft_entry or 0),
        "mft_entry": int(mft_entry or 0),
        "sequence_number": int(seq_num or 0),
        "in_use": bool(in_use),
        "is_deleted": not bool(in_use),
        "file_count": int(file_count or 0),
        "is_directory": True,
        "is_dir": True,
        "node_type": node_type,
    }
    if extra:
        d.update(extra)
    return d


@app.get("/api/cases/{case_id}/filesystem/tree", summary="Real VFS/VSS/Carved Multi-Partition Directory Tree")
@app.get("/api/cases/{case_id}/vfs/tree", include_in_schema=False)
def get_filesystem_tree(
    case_id: str,
    parent_path: Optional[str] = Query(None, description="Parent folder path"),
    path: Optional[str] = Query(None, description="Alias for parent_path"),
    part_index: Optional[int] = Query(None, description="Optional partition index"),
    vss_index: Optional[int] = Query(None, description="Optional VSS store index"),
) -> Dict[str, Any]:
    raw_parent = parent_path if parent_path is not None else (path or "")
    kind, parsed_part, parsed_vss, inner_rel = _parse_vfs_virtual_prefix(raw_parent)
    eff_part = part_index if part_index is not None else parsed_part
    eff_vss = vss_index if vss_index is not None else parsed_vss

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cur = conn.cursor()
        tables = {
            r[0]
            for r in cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='main';"
            ).fetchall()
        }
        if "raw_mft" in tables:
            _clean_legacy_synthetic_mft(cur)

        case_dir = get_case_dir(case_id, create_if_missing=False)
        staging_dir = (case_dir / "staging").resolve() if case_dir.is_dir() else None
        carved_dir = (case_dir / "carved").resolve() if case_dir.is_dir() else None

        partitions_meta: List[Dict[str, Any]] = []
        if "vfs_partitions" in tables:
            vp_cols = {r[1] for r in cur.execute("PRAGMA table_info('vfs_partitions');").fetchall()}
            p_idx_expr = _sql_coalesce_present_cols(vp_cols, ["part_index", "partition_index"], "0")
            lbl_expr = _sql_coalesce_present_cols(vp_cols, ["label", "volume_label", "description"], "''", nullif_empty=True)
            fs_expr = _sql_coalesce_present_cols(vp_cols, ["fs_type", "filesystem"], "'UNKNOWN'", nullif_empty=True)
            off_expr = _sql_coalesce_present_cols(vp_cols, ["offset_bytes", "start_offset", "start_offset_bytes"], "0")
            sz_expr = _sql_coalesce_present_cols(vp_cols, ["size_bytes", "length_bytes"], "0")
            ser_expr = _sql_coalesce_present_cols(vp_cols, ["volume_serial", "serial_number"], "''")
            boot_expr = _sql_coalesce_present_cols(vp_cols, ["is_boot", "is_bootable"], "FALSE")
            for pr in cur.execute(
                f"SELECT {p_idx_expr}, {lbl_expr}, {fs_expr}, {off_expr}, {sz_expr}, {ser_expr}, {boot_expr} FROM vfs_partitions ORDER BY 1 ASC;"
            ).fetchall():
                partitions_meta.append({
                    "part_index": int(pr[0] or 0),
                    "label": str(pr[1] or ""),
                    "fs_type": str(pr[2] or "UNKNOWN"),
                    "offset_bytes": int(pr[3] or 0),
                    "size_bytes": int(pr[4] or 0),
                    "volume_serial": str(pr[5] or ""),
                    "is_boot": bool(pr[6]),
                })

        vss_meta: List[Dict[str, Any]] = []
        if "vfs_shadow_copies" in tables:
            vs_cols = {r[1] for r in cur.execute("PRAGMA table_info('vfs_shadow_copies');").fetchall()}
            vi_expr = _sql_coalesce_present_cols(vs_cols, ["vss_index", "store_index"], "0")
            pi_expr = _sql_coalesce_present_cols(vs_cols, ["part_index", "partition_index"], "0")
            sid_expr = _sql_coalesce_present_cols(vs_cols, ["store_id", "vss_id", "shadow_copy_guid"], "''")
            ct_expr = _sql_coalesce_present_cols(vs_cols, ["creation_time", "creation_time_utc"], "NULL", cast_as="VARCHAR")
            vsz_expr = _sql_coalesce_present_cols(vs_cols, ["size_bytes", "shadow_copy_size", "store_size_bytes"], "0")
            fst_expr = _sql_coalesce_present_cols(vs_cols, ["files_staged"], "0")
            st_expr = _sql_coalesce_present_cols(vs_cols, ["status"], "'DETECTED'")
            sp_expr = _sql_coalesce_present_cols(vs_cols, ["staged_prefix"], "''")
            for vr in cur.execute(
                f"SELECT {vi_expr}, {pi_expr}, {sid_expr}, {ct_expr}, {vsz_expr}, {fst_expr}, {st_expr}, {sp_expr} FROM vfs_shadow_copies ORDER BY 1 ASC;"
            ).fetchall():
                vss_meta.append({
                    "vss_index": int(vr[0] or 0),
                    "part_index": int(vr[1] or 0),
                    "store_id": str(vr[2] or ""),
                    "creation_time": vr[3],
                    "size_bytes": int(vr[4] or 0),
                    "files_staged": int(vr[5] or 0),
                    "status": str(vr[6] or "DETECTED"),
                    "staged_prefix": str(vr[7] or ""),
                })

        carved_cnt = 0
        if "parsed_carved_files" in tables:
            carved_cnt = int(cur.execute("SELECT COUNT(*) FROM parsed_carved_files;").fetchone()[0] or 0)
        elif carved_dir and carved_dir.is_dir():
            carved_cnt = sum(1 for p in carved_dir.rglob("*") if p.is_file())

        folders: List[Dict[str, Any]] = []
        seen_names: set[str] = set()

        if kind == "carved":
            return {
                "case_id": case_id,
                "folders": [],
                "items": [],
                "nodes": [],
                "total_folders": 0,
                "partitions": partitions_meta,
                "shadow_copies": vss_meta,
                "carved_files_count": carved_cnt,
            }

        if kind == "root" and eff_part is None and eff_vss is None:
            for pm in partitions_meta:
                pidx = pm["part_index"]
                sz_lbl = f" ({format_bytes_human(pm['size_bytes'])})" if pm["size_bytes"] > 0 else ""
                p_title = f"Partition {pidx}: {pm['label'] or pm['fs_type']}{sz_lbl}".strip(": ")
                if len(partitions_meta) > 1 or "vfs_files" in tables:
                    folders.append(_make_tree_folder_dict(
                        folder_name=p_title,
                        folder_path=f"Part{pidx}:",
                        parent_path=".",
                        file_count=0,
                        node_type="partition",
                        extra=pm,
                    ))
            for vm in vss_meta:
                vidx = vm["vss_index"]
                ct_lbl = f" ({vm['creation_time']})" if vm.get("creation_time") else ""
                folders.append(_make_tree_folder_dict(
                    folder_name=f"VSS #{vidx}{ct_lbl}",
                    folder_path=f"VSS #{vidx}",
                    parent_path=".",
                    file_count=vm.get("files_staged", 0),
                    node_type="vss",
                    extra=vm,
                ))
            if carved_cnt > 0:
                folders.append(_make_tree_folder_dict(
                    folder_name=f"Carved Files ({carved_cnt})",
                    folder_path="Carved Files",
                    parent_path=".",
                    file_count=carved_cnt,
                    node_type="carved",
                ))
            if len(partitions_meta) > 1 and "vfs_files" in tables:
                return {
                    "case_id": case_id,
                    "folders": folders,
                    "items": folders,
                    "nodes": folders,
                    "total_folders": len(folders),
                    "partitions": partitions_meta,
                    "shadow_copies": vss_meta,
                    "carved_files_count": carved_cnt,
                }

        norm_rel = inner_rel if kind in ("part", "vss", "folder") else "."
        path_prefix = f"Part{eff_part}:" if eff_part is not None and len(partitions_meta) > 1 else (f"VSS #{eff_vss}" if eff_vss is not None else ".")

        def _qualify_child_path(child_name: str) -> Tuple[str, str]:
            if path_prefix != ".":
                pp = path_prefix if norm_rel == "." else f"{path_prefix}\\{norm_rel[2:]}"
                return (f"{pp}\\{child_name}", pp)
            pp = norm_rel
            return (f".\\{child_name}" if pp == "." else f"{pp}\\{child_name}", pp)

        # 1. Check vfs_files first
        if "vfs_files" in tables:
            vf_cols = {r[1] for r in cur.execute("PRAGMA table_info('vfs_files');").fetchall()}
            p_col = "part_index" if "part_index" in vf_cols else ("partition_index" if "partition_index" in vf_cols else None)
            dir_expr = _sql_coalesce_present_cols(vf_cols, ["is_dir", "is_directory"], "FALSE")
            fn_expr = _sql_coalesce_present_cols(vf_cols, ["file_name", "name"], "''")
            parent_expr = _sql_coalesce_present_cols(vf_cols, ["parent_path"], "''")
            alloc_parts: List[str] = []
            if "is_allocated" in vf_cols:
                alloc_parts.append("is_allocated")
            if "is_deleted" in vf_cols:
                alloc_parts.append("NOT COALESCE(is_deleted, FALSE)")
            alloc_expr = f"COALESCE({', '.join(alloc_parts)}, TRUE)" if alloc_parts else "TRUE"
            ent_parts: List[str] = []
            if "mft_entry" in vf_cols:
                ent_parts.append("TRY_CAST(mft_entry AS BIGINT)")
            if "inode" in vf_cols:
                ent_parts.append("TRY_CAST(inode AS BIGINT)")
            ent_expr = f"COALESCE({', '.join(ent_parts)}, 0)" if ent_parts else "0"

            slash_parent = "/" if norm_rel == "." else ("/" + norm_rel[2:].replace("\\", "/"))
            bslash_parent = norm_rel
            bare_parent = bslash_parent[2:] if bslash_parent.startswith(".\\") else bslash_parent
            v_clauses = [
                f"{dir_expr} = TRUE",
                f"COALESCE({fn_expr}, '') NOT IN ('', '.', '..')",
                f"NOT (COALESCE({parent_expr}, '') IN ('/', '\\', '.', '') AND regexp_matches(COALESCE({fn_expr}, ''), '(?i)^VSS_[0-9]+$'))",
            ]
            v_params: List[Any] = []
            if "vss_store_index" in vf_cols:
                if eff_vss is not None:
                    v_clauses.append("vss_store_index = ?")
                    v_params.append(int(eff_vss))
                else:
                    v_clauses.append("vss_store_index IS NULL")
                    if eff_part is None and p_col:
                        v_clauses.append(f"COALESCE(TRY_CAST({p_col} AS INTEGER), 0) >= 0")
                    if norm_rel == ".":
                        v_clauses.append(f"NOT regexp_matches(COALESCE({fn_expr}, ''), '(?i)^VSS_[0-9]+$')")
            else:
                if eff_vss is not None:
                    if p_col:
                        v_clauses.append(f"TRY_CAST({p_col} AS INTEGER) = ?")
                        v_params.append(-int(eff_vss))
                else:
                    if eff_part is None and p_col:
                        v_clauses.append(f"COALESCE(TRY_CAST({p_col} AS INTEGER), 0) >= 0")
                    if norm_rel == ".":
                        v_clauses.append(f"NOT regexp_matches(COALESCE({fn_expr}, ''), '(?i)^VSS_[0-9]+$')")
            if eff_part is not None and p_col:
                v_clauses.append(f"TRY_CAST({p_col} AS INTEGER) = ?")
                v_params.append(int(eff_part))

            parent_cands = [slash_parent, bslash_parent, bare_parent]
            if norm_rel == ".":
                parent_cands.extend(["", "\\"])
            else:
                parent_cands.append("\\" + bare_parent)
            if eff_vss is not None:
                v_slash = f"/VSS_{int(eff_vss)}" if norm_rel == "." else f"/VSS_{int(eff_vss)}/" + norm_rel[2:].replace("\\", "/")
                v_bslash = f"\\VSS_{int(eff_vss)}" if norm_rel == "." else f"\\VSS_{int(eff_vss)}\\" + norm_rel[2:]
                parent_cands.extend([v_slash, v_bslash])
            p_phs = ", ".join(["?"] * len(parent_cands))
            v_clauses.append(f"COALESCE({parent_expr}, '') IN ({p_phs})")
            v_params.extend(parent_cands)

            vf_rows = cur.execute(
                f"SELECT {fn_expr}, {ent_expr}, {alloc_expr} FROM vfs_files WHERE {' AND '.join(v_clauses)} ORDER BY 1 ASC;",
                v_params,
            ).fetchall()
            for fn, ent, in_use in vf_rows:
                low_fn = str(fn).lower()
                if low_fn in seen_names:
                    continue
                seen_names.add(low_fn)
                fp, pp = _qualify_child_path(str(fn))
                folders.append(_make_tree_folder_dict(str(fn), fp, pp, in_use=bool(in_use), mft_entry=int(ent or 0), extra={"part_index": eff_part, "vss_index": eff_vss}))

        # 2. Check raw_mft (for primary volume when not browsing a specific VSS store)
        if eff_vss is None and (eff_part in (None, 0) or not partitions_meta) and "raw_mft" in tables:
            mft_rows = cur.execute(
                """
                SELECT
                    FileName,
                    COALESCE(TRY_CAST(EntryNumber AS BIGINT), 0),
                    COALESCE(TRY_CAST(SequenceNumber AS BIGINT), 0),
                    COALESCE(InUse, TRUE)
                FROM raw_mft
                WHERE ParentPath = ?
                  AND COALESCE(IsDirectory, FALSE) = TRUE
                  AND FileName NOT IN ('.', '..')
                  AND NOT regexp_matches(COALESCE(FileName, ''), '^__[A-Z]+[0-9]+__$')
                ORDER BY FileName ASC;
                """,
                [norm_rel],
            ).fetchall()
            for fn, ent, seq, in_use in mft_rows:
                low_fn = str(fn).lower()
                if low_fn in seen_names:
                    continue
                seen_names.add(low_fn)
                child_mft_parent = f".\\{fn}" if norm_rel == "." else f"{norm_rel}\\{fn}"
                sub_cnt = cur.execute(
                    "SELECT COUNT(*) FROM raw_mft WHERE ParentPath = ? AND FileName NOT IN ('.', '..');",
                    [child_mft_parent],
                ).fetchone()[0]
                fp, pp = _qualify_child_path(str(fn))
                folders.append(_make_tree_folder_dict(
                    str(fn), fp, pp, file_count=int(sub_cnt or 0), in_use=bool(in_use), mft_entry=int(ent or 0), seq_num=int(seq or 0)
                ))

        # 3. Staged directory fallback (VSS staging or folder triage cases without MFT)
        disk_base: Optional[Path] = None
        if eff_vss is not None and staging_dir and staging_dir.is_dir():
            for cand_vss in (
                staging_dir / "VSS" / f"VSS_{eff_vss}",
                staging_dir / "VSS" / f"vss_{eff_vss}",
                staging_dir / f"VSS_{eff_vss}",
                staging_dir / f"vss_{eff_vss}",
            ):
                if cand_vss.is_dir():
                    disk_base = cand_vss
                    break
        elif not seen_names and staging_dir and staging_dir.is_dir():
            cand_part = (staging_dir / f"Part{eff_part}") if eff_part is not None else staging_dir
            disk_base = cand_part if cand_part.is_dir() else staging_dir

        if disk_base and disk_base.is_dir():
            target_disk = disk_base if norm_rel == "." else (disk_base / norm_rel[2:])
            try:
                resolved_target = target_disk.resolve()
                if resolved_target.is_dir() and resolved_target.is_relative_to(disk_base.resolve()):
                    for child in sorted(resolved_target.iterdir(), key=lambda x: x.name.lower()):
                        if child.is_dir():
                            if eff_vss is None and norm_rel == "." and child.name.upper() == "VSS":
                                continue
                            low_fn = child.name.lower()
                            if low_fn in seen_names:
                                continue
                            seen_names.add(low_fn)
                            cnt = sum(1 for _ in child.iterdir()) if child.is_dir() else 0
                            fp, pp = _qualify_child_path(child.name)
                            folders.append(_make_tree_folder_dict(child.name, fp, pp, file_count=cnt, extra={"part_index": eff_part, "vss_index": eff_vss}))
            except OSError:
                pass

        return {
            "case_id": case_id,
            "folders": folders,
            "items": folders,
            "nodes": folders,
            "total_folders": len(folders),
            "partitions": partitions_meta,
            "shadow_copies": vss_meta,
            "carved_files_count": carved_cnt,
        }


def _build_file_item_dict(
    file_name: str,
    full_path: str,
    parent_path: str,
    file_size: int = 0,
    is_directory: bool = False,
    in_use: bool = True,
    extension: str = "",
    mft_entry: Optional[int] = None,
    seq_num: Optional[int] = None,
    si_created: Optional[str] = None,
    si_modified: Optional[str] = None,
    si_accessed: Optional[str] = None,
    si_changed: Optional[str] = None,
    fn_created: Optional[str] = None,
    fn_modified: Optional[str] = None,
    fn_accessed: Optional[str] = None,
    fn_changed: Optional[str] = None,
    staged_file_path: Optional[str] = None,
    part_index: Optional[int] = None,
    vss_index: Optional[int] = None,
    sha256: Optional[str] = None,
    carve_id: Optional[str] = None,
    carved_rel_path: Optional[str] = None,
    source_region: Optional[str] = None,
    row_id: Optional[int] = None,
) -> Dict[str, Any]:
    ext_clean = extension or (Path(file_name).suffix.lstrip(".") if "." in file_name else "")
    ts_flag = _is_timestomped_pair(si_created, fn_created, si_modified, fn_modified)
    return {
        "_row_id": row_id,
        "file_name": file_name,
        "name": file_name,
        "full_path": full_path,
        "path": full_path,
        "parent_path": parent_path,
        "extension": ext_clean,
        "file_size": int(file_size or 0),
        "size_bytes": int(file_size or 0),
        "size": int(file_size or 0),
        "is_directory": bool(is_directory),
        "is_dir": bool(is_directory),
        "in_use": bool(in_use),
        "is_deleted": not bool(in_use),
        "mft_entry_number": int(mft_entry) if mft_entry is not None else None,
        "mft_entry": int(mft_entry) if mft_entry is not None else None,
        "sequence_number": int(seq_num) if seq_num is not None else None,
        "si_created": si_created,
        "si_modified": si_modified,
        "si_accessed": si_accessed,
        "si_mft_modified": si_changed,
        "si_changed": si_changed,
        "fn_created": fn_created,
        "fn_modified": fn_modified,
        "fn_accessed": fn_accessed,
        "fn_mft_modified": fn_changed,
        "fn_changed": fn_changed,
        "timestomped": ts_flag,
        "staged_file_path": staged_file_path,
        "part_index": part_index,
        "vss_index": vss_index,
        "sha256": sha256,
        "carve_id": carve_id,
        "carved_rel_path": carved_rel_path,
        "source_region": source_region,
    }


@app.get("/api/cases/{case_id}/filesystem/files", summary="Real VFS/VSS/Carved File Listing with $SI/$FN MACB")
@app.get("/api/cases/{case_id}/vfs/files", include_in_schema=False)
def get_filesystem_files(
    case_id: str,
    folder_path: Optional[str] = Query(None, description="Folder path"),
    path: Optional[str] = Query(None, description="Alias for folder_path"),
    part_index: Optional[int] = Query(None, description="Optional partition index"),
    vss_index: Optional[int] = Query(None, description="Optional VSS store index"),
    include_deleted: bool = Query(True, description="Include deleted/unallocated entries"),
    carved_only: bool = Query(False, description="Return carved files only"),
    sort_col: Optional[str] = Query(None),
    sort_dir: str = Query("asc"),
    search: Optional[str] = Query(None),
    keywords: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(150, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    raw_folder = folder_path if folder_path is not None else (path if path is not None else ".")
    kind, parsed_part, parsed_vss, inner_rel = _parse_vfs_virtual_prefix(raw_folder)
    eff_part = part_index if part_index is not None else parsed_part
    eff_vss = vss_index if vss_index is not None else parsed_vss
    kw_terms = parse_list_param(keywords)
    tag_terms = parse_list_param(tags)
    dt_from = normalize_utc_bound(date_from or start_time, is_end=False)
    dt_to = normalize_utc_bound(date_to or end_time, is_end=True)
    desc_flag = str(sort_dir or "asc").strip().upper() == "DESC"

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cur = conn.cursor()
        tables = {
            r[0]
            for r in cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='main';"
            ).fetchall()
        }
        if "raw_mft" in tables:
            _clean_legacy_synthetic_mft(cur)

        case_dir = get_case_dir(case_id, create_if_missing=False)
        staging_dir = (case_dir / "staging").resolve() if case_dir.is_dir() else None
        carved_dir = (case_dir / "carved").resolve() if case_dir.is_dir() else None

        # A. Carved Files listing
        if carved_only or kind == "carved":
            items: List[Dict[str, Any]] = []
            if "parsed_carved_files" in tables:
                pc_cols = {r[1] for r in cur.execute("PRAGMA table_info('parsed_carved_files');").fetchall()}
                rid_expr = "_row_id" if "_row_id" in pc_cols else "ROW_NUMBER() OVER ()"
                cid_expr = _sql_coalesce_present_cols(pc_cols, ["carve_id"], "''", cast_as="VARCHAR")
                rel_expr = _sql_coalesce_present_cols(pc_cols, ["carved_rel_path", "carved_path", "file_name"], "''")
                fn_expr = _sql_coalesce_present_cols(
                    pc_cols,
                    ["file_name"],
                    f"COALESCE(NULLIF(regexp_extract({rel_expr}, '([^\\\\\\\\/]+)$', 1), ''), {cid_expr})",
                )
                ext_expr = _sql_coalesce_present_cols(pc_cols, ["extension", "file_type"], "''")
                sz_expr = _sql_coalesce_present_cols(pc_cols, ["size_bytes"], "0")
                sha_expr = _sql_coalesce_present_cols(pc_cols, ["sha256"], "''")
                reg_expr = _sql_coalesce_present_cols(pc_cols, ["source_region", "source_evidence"], "''")
                ts_expr = _sql_coalesce_present_cols(pc_cols, ["carved_at", "timestamp_utc"], "NULL", cast_as="VARCHAR")
                pidx_expr = _sql_coalesce_present_cols(pc_cols, ["partition_index", "part_index"], "NULL")
                c_clauses: List[str] = ["1=1"]
                c_params: List[Any] = []
                if search and search.strip():
                    esc_s = f"%{escape_ilike(search.strip())}%"
                    c_clauses.append(
                        f"(COALESCE({fn_expr}, '') ILIKE ? ESCAPE '\\' OR COALESCE({sha_expr}, '') ILIKE ? ESCAPE '\\' OR COALESCE({rel_expr}, '') ILIKE ? ESCAPE '\\')"
                    )
                    c_params.extend([esc_s, esc_s, esc_s])
                if kw_terms:
                    kw_ors = []
                    for kw in kw_terms:
                        esc_k = f"%{escape_ilike(kw)}%"
                        kw_ors.append(
                            f"(COALESCE({fn_expr}, '') ILIKE ? ESCAPE '\\' OR COALESCE({sha_expr}, '') ILIKE ? ESCAPE '\\' OR COALESCE({rel_expr}, '') ILIKE ? ESCAPE '\\')"
                        )
                        c_params.extend([esc_k, esc_k, esc_k])
                    c_clauses.append("(" + " OR ".join(kw_ors) + ")")
                c_where = " AND ".join(c_clauses)
                total_carved = int(cur.execute(f"SELECT COUNT(*) FROM parsed_carved_files WHERE {c_where};", c_params).fetchone()[0] or 0)
                c_rows = cur.execute(
                    f"""
                    SELECT {rid_expr}, {cid_expr}, {fn_expr}, {ext_expr}, {sz_expr},
                           {sha_expr}, {rel_expr}, {reg_expr}, {ts_expr}, {pidx_expr}
                    FROM parsed_carved_files
                    WHERE {c_where}
                    ORDER BY {fn_expr} {'DESC' if desc_flag else 'ASC'}
                    LIMIT ? OFFSET ?;
                    """,
                    c_params + [limit, offset],
                ).fetchall()
                for cr in c_rows:
                    fn_str = str(cr[2] or cr[1] or "carved.bin")
                    rel_p = str(cr[6] or fn_str)
                    items.append(_build_file_item_dict(
                        file_name=fn_str,
                        full_path=f"Carved Files\\{fn_str}",
                        parent_path="Carved Files",
                        file_size=int(cr[4] or 0),
                        is_directory=False,
                        in_use=False,
                        extension=str(cr[3] or ""),
                        si_created=cr[8],
                        staged_file_path=rel_p,
                        part_index=cr[9],
                        sha256=cr[5],
                        carve_id=cr[1],
                        carved_rel_path=rel_p,
                        source_region=str(cr[7] or ""),
                        row_id=cr[0],
                    ))
                return {"case_id": case_id, "files": items, "items": items, "total_files": total_carved, "total_count": total_carved}
            elif carved_dir and carved_dir.is_dir():
                disk_carved = [p for p in sorted(carved_dir.rglob("*")) if p.is_file()]
                if search and search.strip():
                    q_low = search.strip().lower()
                    disk_carved = [p for p in disk_carved if q_low in p.name.lower()]
                total_carved = len(disk_carved)
                for p in disk_carved[offset : offset + limit]:
                    rel_s = str(p.relative_to(carved_dir)).replace("\\", "/")
                    items.append(_build_file_item_dict(
                        file_name=p.name,
                        full_path=f"Carved Files\\{rel_s.replace('/', chr(92))}",
                        parent_path="Carved Files",
                        file_size=p.stat().st_size,
                        is_directory=False,
                        in_use=False,
                        staged_file_path=rel_s,
                        carved_rel_path=rel_s,
                    ))
                return {"case_id": case_id, "files": items, "items": items, "total_files": total_carved, "total_count": total_carved}
            return {"case_id": case_id, "files": [], "items": [], "total_files": 0, "total_count": 0}

        norm_rel = inner_rel if kind in ("part", "vss", "folder") else "."
        multi_parts = False
        if "vfs_partitions" in tables:
            multi_parts = int(cur.execute("SELECT COUNT(*) FROM vfs_partitions;").fetchone()[0] or 0) > 1
        path_prefix = f"Part{eff_part}:" if (eff_part is not None and multi_parts) else (f"VSS #{eff_vss}" if eff_vss is not None else ".")

        def _qualify_item_path(fn_val: str) -> Tuple[str, str]:
            if path_prefix != ".":
                pp = path_prefix if norm_rel == "." else f"{path_prefix}\\{norm_rel[2:]}"
                return (f"{pp}\\{fn_val}", pp)
            pp = norm_rel
            return (f".\\{fn_val}" if pp == "." else f"{pp}\\{fn_val}", pp)

        # B. vfs_files table listing (if populated for requested partition / VSS)
        if "vfs_files" in tables:
            vf_cnt = int(cur.execute("SELECT COUNT(*) FROM vfs_files;").fetchone()[0] or 0)
            if vf_cnt > 0:
                vf_cols = {r[1] for r in cur.execute("PRAGMA table_info('vfs_files');").fetchall()}
                p_col = "part_index" if "part_index" in vf_cols else ("partition_index" if "partition_index" in vf_cols else None)
                rid_expr = "_row_id" if "_row_id" in vf_cols else "ROW_NUMBER() OVER ()"
                fn_expr = _sql_coalesce_present_cols(vf_cols, ["file_name", "name"], "''")
                parent_expr = _sql_coalesce_present_cols(vf_cols, ["parent_path"], "''")
                ext_expr = "COALESCE(extension, '')" if "extension" in vf_cols else "''"
                sz_expr = _sql_coalesce_present_cols(vf_cols, ["size_bytes", "file_size"], "0")
                dir_expr = _sql_coalesce_present_cols(vf_cols, ["is_dir", "is_directory"], "FALSE")
                if "is_allocated" in vf_cols and "is_deleted" in vf_cols:
                    alloc_expr = "COALESCE(is_allocated, NOT COALESCE(is_deleted, FALSE), TRUE)"
                elif "is_allocated" in vf_cols:
                    alloc_expr = "COALESCE(is_allocated, TRUE)"
                elif "is_deleted" in vf_cols:
                    alloc_expr = "NOT COALESCE(is_deleted, FALSE)"
                else:
                    alloc_expr = "TRUE"
                ent_base = _sql_coalesce_present_cols(vf_cols, ["mft_entry", "inode"], "NULL")
                ent_expr = f"TRY_CAST({ent_base} AS BIGINT)" if ent_base != "NULL" else "NULL"
                sic_col = _sql_coalesce_present_cols(vf_cols, ["si_created", "si_created_utc"], "NULL")
                sim_col = _sql_coalesce_present_cols(vf_cols, ["si_modified", "si_modified_utc"], "NULL")
                sia_col = _sql_coalesce_present_cols(vf_cols, ["si_accessed", "si_accessed_utc"], "NULL")
                sich_col = _sql_coalesce_present_cols(vf_cols, ["si_changed", "si_changed_utc"], "NULL")
                fnc_col = _sql_coalesce_present_cols(vf_cols, ["fn_created", "fn_created_utc"], "NULL")
                fnm_col = _sql_coalesce_present_cols(vf_cols, ["fn_modified", "fn_modified_utc"], "NULL")
                fna_col = _sql_coalesce_present_cols(vf_cols, ["fn_accessed", "fn_accessed_utc"], "NULL")
                fnch_col = _sql_coalesce_present_cols(vf_cols, ["fn_changed", "fn_changed_utc"], "NULL")
                srel_expr = "staged_rel_path" if "staged_rel_path" in vf_cols else "NULL"
                vp_expr = "vfs_path" if "vfs_path" in vf_cols else "NULL"
                vp_search_expr = "COALESCE(vfs_path, '')" if "vfs_path" in vf_cols else ("COALESCE(parent_path, '')" if "parent_path" in vf_cols else "''")

                rel_clean = "" if norm_rel == "." else norm_rel[2:].replace("\\", "/").strip("/")
                slash_parent = "/" if not rel_clean else f"/{rel_clean}"
                v_clauses = [
                    f"{fn_expr} NOT IN ('', '.', '..')",
                    f"NOT (COALESCE({parent_expr}, '') IN ('/', '\\', '.', '') AND regexp_matches(COALESCE({fn_expr}, ''), '(?i)^VSS_[0-9]+$'))",
                ]
                v_params: List[Any] = []
                if eff_vss is not None:
                    if "vss_store_index" in vf_cols:
                        v_clauses.append("vss_store_index = ?")
                        v_params.append(int(eff_vss))
                    elif p_col:
                        v_clauses.append(f"TRY_CAST({p_col} AS INTEGER) = ?")
                        v_params.append(-abs(int(eff_vss)))
                else:
                    if "vss_store_index" in vf_cols:
                        v_clauses.append("vss_store_index IS NULL")
                    if eff_part is not None and p_col:
                        v_clauses.append(f"TRY_CAST({p_col} AS INTEGER) = ?")
                        v_params.append(int(eff_part))
                    elif p_col:
                        v_clauses.append(f"COALESCE(TRY_CAST({p_col} AS INTEGER), 0) >= 0")
                    v_clauses.append(f"NOT regexp_matches(COALESCE({fn_expr}, ''), '(?i)^VSS_[0-9]+$')")

                explicit_folder_given = (folder_path is not None or path is not None)
                if "parent_path" in vf_cols:
                    if not rel_clean:
                        cand_parents = ["/", ".", "", "\\"]
                        if eff_vss is not None:
                            cand_parents.extend([f"/VSS_{int(eff_vss)}", f"\\VSS_{int(eff_vss)}", f"VSS_{int(eff_vss)}"])
                    else:
                        win_rel = rel_clean.replace("/", "\\")
                        cand_parents = [slash_parent, rel_clean, norm_rel, f"\\{win_rel}"]
                        if eff_vss is not None:
                            cand_parents.extend([f"/VSS_{int(eff_vss)}/{rel_clean}", f"\\VSS_{int(eff_vss)}\\{win_rel}"])
                    cand_parents = list(dict.fromkeys(cand_parents))
                    ph_pp = ", ".join(["?"] * len(cand_parents))
                    if not (search and search.strip()) and not kw_terms:
                        v_clauses.append(f"COALESCE(parent_path, '') IN ({ph_pp})")
                        v_params.extend(cand_parents)
                    elif rel_clean:
                        subtree_likes = [f"{escape_ilike(slash_parent)}/%"]
                        if eff_vss is not None:
                            subtree_likes.append(f"/VSS_{int(eff_vss)}{escape_ilike(slash_parent)}/%")
                        like_ors = " OR ".join(["REPLACE(COALESCE(parent_path, ''), '\\', '/') ILIKE ? ESCAPE '\\'"] * len(subtree_likes))
                        v_clauses.append(f"(COALESCE(parent_path, '') IN ({ph_pp}) OR {like_ors})")
                        v_params.extend(cand_parents)
                        v_params.extend(subtree_likes)

                if not include_deleted and eff_vss is None:
                    v_clauses.append(f"{alloc_expr} = TRUE")
                if search and search.strip():
                    esc_s = f"%{escape_ilike(search.strip())}%"
                    v_clauses.append(f"({fn_expr} ILIKE ? ESCAPE '\\' OR {vp_search_expr} ILIKE ? ESCAPE '\\')")
                    v_params.extend([esc_s, esc_s])
                if kw_terms:
                    kw_ors = []
                    for kw in kw_terms:
                        esc_k = f"%{escape_ilike(kw)}%"
                        kw_ors.append(f"({fn_expr} ILIKE ? ESCAPE '\\' OR {vp_search_expr} ILIKE ? ESCAPE '\\')")
                        v_params.extend([esc_k, esc_k])
                    v_clauses.append("(" + " OR ".join(kw_ors) + ")")
                ts_vf_expr = _sql_coalesce_present_cols(vf_cols, ["si_modified", "si_modified_utc", "si_created", "si_created_utc"], "NULL")
                if dt_from and ts_vf_expr != "NULL":
                    v_clauses.append(f"TRY_CAST({ts_vf_expr} AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)")
                    v_params.append(dt_from)
                if dt_to and ts_vf_expr != "NULL":
                    v_clauses.append(f"TRY_CAST({ts_vf_expr} AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)")
                    v_params.append(dt_to)

                v_where = " AND ".join(v_clauses)
                vf_total = int(cur.execute(f"SELECT COUNT(*) FROM vfs_files WHERE {v_where};", v_params).fetchone()[0] or 0)
                vss_nested_reg_cnt = 0
                if eff_vss is not None and not explicit_folder_given and not (search and search.strip()) and not kw_terms:
                    vss_only_clause = "vss_store_index = ?" if "vss_store_index" in vf_cols else (f"TRY_CAST({p_col} AS INTEGER) = ?" if p_col else "1=0")
                    vss_only_param = [int(eff_vss)] if "vss_store_index" in vf_cols else ([-abs(int(eff_vss))] if p_col else [])
                    vss_nested_reg_cnt = int(
                        cur.execute(
                            f"SELECT COUNT(*) FROM vfs_files WHERE {vss_only_clause} AND COALESCE({dir_expr}, FALSE) = FALSE AND COALESCE({sz_expr}, 0) > 0;",
                            vss_only_param,
                        ).fetchone()[0]
                        or 0
                    )
                if vf_total > 0 or vss_nested_reg_cnt > 0 or eff_part not in (None, 0):
                    vf_rows = cur.execute(
                        f"""
                        SELECT {rid_expr}, {fn_expr}, {ext_expr}, {sz_expr},
                               {dir_expr}, {alloc_expr}, {ent_expr},
                               CAST({sic_col} AS VARCHAR), CAST({sim_col} AS VARCHAR), CAST({sia_col} AS VARCHAR), CAST({sich_col} AS VARCHAR),
                               CAST({fnc_col} AS VARCHAR), CAST({fnm_col} AS VARCHAR), CAST({fna_col} AS VARCHAR), CAST({fnch_col} AS VARCHAR),
                               {srel_expr}, {p_col or 'NULL'}, {vp_expr}
                        FROM vfs_files
                        WHERE {v_where}
                        ORDER BY {dir_expr} DESC, {fn_expr} {'DESC' if desc_flag else 'ASC'}
                        LIMIT ? OFFSET ?;
                        """,
                        v_params + [limit, offset],
                    ).fetchall()
                    out_vf = []
                    for vr in vf_rows:
                        fname_s = str(vr[1] or "")
                        is_dir_b = bool(vr[4])
                        fp, pp = _qualify_item_path(fname_s)
                        if vr[17] and (search or kw_terms):
                            vp_clean = str(vr[17]).strip("/").replace("/", "\\")
                            if eff_vss is not None and vp_clean.upper().startswith(f"VSS_{int(eff_vss)}\\"):
                                vp_clean = vp_clean.split("\\", 1)[1]
                            fp = f"{path_prefix}\\{vp_clean}" if path_prefix != "." else f".\\{vp_clean}"
                        ext_val = str(vr[2] or "") or (Path(fname_s).suffix.lstrip(".").lower() if (not is_dir_b and "." in fname_s) else "")
                        out_vf.append(_build_file_item_dict(
                            file_name=fname_s,
                            full_path=fp,
                            parent_path=pp,
                            file_size=int(vr[3] or 0),
                            is_directory=is_dir_b,
                            in_use=bool(vr[5]),
                            extension=ext_val,
                            mft_entry=vr[6],
                            si_created=vr[7],
                            si_modified=vr[8],
                            si_accessed=vr[9],
                            si_changed=vr[10],
                            fn_created=vr[11],
                            fn_modified=vr[12],
                            fn_accessed=vr[13],
                            fn_changed=vr[14],
                            staged_file_path=vr[15],
                            part_index=eff_part if (eff_vss is not None and isinstance(vr[16], int) and vr[16] < 0) else vr[16],
                            vss_index=eff_vss,
                            row_id=vr[0],
                        ))
                    if (
                        vss_nested_reg_cnt > 0
                        and offset == 0
                        and len(out_vf) < limit
                        and not any(not it["is_directory"] and it["file_size"] > 0 for it in out_vf)
                    ):
                        rem_lim = limit - len(out_vf)
                        srel_order = f"CASE WHEN COALESCE({srel_expr}, '') <> '' THEN 0 ELSE 1 END," if srel_expr != "NULL" else ""
                        reg_rows = cur.execute(
                            f"""
                            SELECT {rid_expr}, {fn_expr}, {ext_expr}, {sz_expr},
                                   {dir_expr}, {alloc_expr}, {ent_expr},
                                   CAST({sic_col} AS VARCHAR), CAST({sim_col} AS VARCHAR), CAST({sia_col} AS VARCHAR), CAST({sich_col} AS VARCHAR),
                                   CAST({fnc_col} AS VARCHAR), CAST({fnm_col} AS VARCHAR), CAST({fna_col} AS VARCHAR), CAST({fnch_col} AS VARCHAR),
                                   {srel_expr}, {p_col or 'NULL'}, {vp_expr}
                            FROM vfs_files
                            WHERE {vss_only_clause}
                              AND COALESCE({dir_expr}, FALSE) = FALSE
                              AND COALESCE({sz_expr}, 0) > 0
                            ORDER BY {srel_order} {fn_expr} ASC
                            LIMIT ?;
                            """,
                            vss_only_param + [rem_lim],
                        ).fetchall()
                        seen_fp = {str(it.get("full_path", "")).lower() for it in out_vf}
                        for vr in reg_rows:
                            fname_s = str(vr[1] or "")
                            vp_clean = str(vr[17] or fname_s).strip("/").replace("/", "\\")
                            if eff_vss is not None and vp_clean.upper().startswith(f"VSS_{int(eff_vss)}\\"):
                                vp_clean = vp_clean.split("\\", 1)[1]
                            fp = f"{path_prefix}\\{vp_clean}" if path_prefix != "." else f".\\{vp_clean}"
                            if fp.lower() in seen_fp:
                                continue
                            seen_fp.add(fp.lower())
                            pp = fp.rsplit("\\", 1)[0] if "\\" in fp else path_prefix
                            ext_val = str(vr[2] or "") or (Path(fname_s).suffix.lstrip(".").lower() if "." in fname_s else "")
                            out_vf.append(_build_file_item_dict(
                                file_name=fname_s,
                                full_path=fp,
                                parent_path=pp,
                                file_size=int(vr[3] or 0),
                                is_directory=False,
                                in_use=bool(vr[5]),
                                extension=ext_val,
                                mft_entry=vr[6],
                                si_created=vr[7],
                                si_modified=vr[8],
                                si_accessed=vr[9],
                                si_changed=vr[10],
                                fn_created=vr[11],
                                fn_modified=vr[12],
                                fn_accessed=vr[13],
                                fn_changed=vr[14],
                                staged_file_path=vr[15],
                                part_index=eff_part if (eff_vss is not None and isinstance(vr[16], int) and vr[16] < 0) else vr[16],
                                vss_index=eff_vss,
                                row_id=vr[0],
                            ))
                            vf_total += 1
                    if eff_vss is not None and staging_dir and staging_dir.is_dir() and offset == 0:
                        for cand_vss_d in (
                            staging_dir / "VSS" / f"VSS_{eff_vss}",
                            staging_dir / "VSS" / f"vss_{eff_vss}",
                            staging_dir / f"VSS_{eff_vss}",
                            staging_dir / f"vss_{eff_vss}",
                        ):
                            if cand_vss_d.is_dir():
                                sub_d = cand_vss_d if not rel_clean else (cand_vss_d / rel_clean)
                                try:
                                    res_sub = sub_d.resolve()
                                    if res_sub.is_dir() and res_sub.is_relative_to(cand_vss_d.resolve()):
                                        seen_names = {str(it.get("file_name", "")).lower() for it in out_vf}
                                        q_low_v = search.strip().lower() if (search and search.strip()) else ""
                                        for de in sorted(res_sub.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                                            if de.name.lower() in seen_names or (q_low_v and q_low_v not in de.name.lower()):
                                                continue
                                            st_d = de.stat()
                                            fp_d, pp_d = _qualify_item_path(de.name)
                                            out_vf.append(_build_file_item_dict(
                                                file_name=de.name,
                                                full_path=fp_d,
                                                parent_path=pp_d,
                                                file_size=0 if de.is_dir() else int(st_d.st_size),
                                                is_directory=de.is_dir(),
                                                in_use=True,
                                                extension="" if de.is_dir() else de.suffix.lstrip(".").lower(),
                                                staged_file_path=str(de.relative_to(staging_dir)),
                                                vss_index=eff_vss,
                                            ))
                                            seen_names.add(de.name.lower())
                                            vf_total += 1
                                except Exception:
                                    pass
                                break
                    return {"case_id": case_id, "files": out_vf, "items": out_vf, "total_files": vf_total, "total_count": vf_total}

        # C. raw_mft table listing (with full $SI 0x10 and $FN 0x30 MACB introspection)
        if eff_vss is None and "raw_mft" in tables:
            mft_cols = {r[1] for r in cur.execute("PRAGMA table_info('raw_mft');").fetchall()}
            m_clauses = [
                "FileName NOT IN ('.', '..')",
                "NOT regexp_matches(COALESCE(FileName, ''), '^__[A-Z]+[0-9]+__$')",
            ]
            m_params: List[Any] = []
            if not (search and search.strip()) and not kw_terms and norm_rel:
                m_clauses.append("ParentPath = ?")
                m_params.append(norm_rel)
            if not include_deleted and "InUse" in mft_cols:
                m_clauses.append("COALESCE(InUse, TRUE) = TRUE")
            if search and search.strip():
                esc_s = f"%{escape_ilike(search.strip())}%"
                m_clauses.append("(COALESCE(FileName, '') ILIKE ? ESCAPE '\\' OR COALESCE(ParentPath, '') ILIKE ? ESCAPE '\\')")
                m_params.extend([esc_s, esc_s])
            if kw_terms:
                kw_ors = []
                for kw in kw_terms:
                    esc_k = f"%{escape_ilike(kw)}%"
                    kw_ors.append("(COALESCE(FileName, '') ILIKE ? ESCAPE '\\' OR COALESCE(ParentPath, '') ILIKE ? ESCAPE '\\')")
                    m_params.extend([esc_k, esc_k])
                m_clauses.append("(" + " OR ".join(kw_ors) + ")")
            if (tag_terms or bookmarked_only) and "bookmarks" in tables and "_row_id" in mft_cols:
                _ensure_bookmarks_table_canonical(cur)
                if tag_terms:
                    ph = ", ".join(["?"] * len(tag_terms))
                    m_clauses.append(f"_row_id IN (SELECT source_row_id FROM bookmarks WHERE source_table = 'raw_mft' AND tag_name IN ({ph}))")
                    m_params.extend(tag_terms)
                else:
                    m_clauses.append("_row_id IN (SELECT source_row_id FROM bookmarks WHERE source_table = 'raw_mft')")
            if dt_from and "LastModified0x10" in mft_cols:
                m_clauses.append("TRY_CAST(COALESCE(LastModified0x10, Created0x10) AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)")
                m_params.append(dt_from)
            if dt_to and "LastModified0x10" in mft_cols:
                m_clauses.append("TRY_CAST(COALESCE(LastModified0x10, Created0x10) AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)")
                m_params.append(dt_to)

            def _mcol(cname: str) -> str:
                return f"CAST({cname} AS VARCHAR)" if cname in mft_cols else "NULL"

            row_id_expr = "_row_id" if "_row_id" in mft_cols else "NULL"
            where_sql = " AND ".join(m_clauses)
            total_files = int(cur.execute(f"SELECT COUNT(*) FROM raw_mft WHERE {where_sql};", m_params).fetchone()[0] or 0)
            if total_files > 0:
                sort_map = {
                    "file_name": "FileName",
                    "name": "FileName",
                    "file_size": "TRY_CAST(FileSize AS BIGINT)",
                    "size_bytes": "TRY_CAST(FileSize AS BIGINT)",
                    "si_created": "Created0x10" if "Created0x10" in mft_cols else "FileName",
                    "si_modified": "LastModified0x10" if "LastModified0x10" in mft_cols else "FileName",
                }
                ord_expr = sort_map.get((sort_col or "").lower(), "FileName")
                rows = cur.execute(
                    f"""
                    SELECT
                        {row_id_expr},
                        FileName,
                        CASE WHEN ParentPath = '.' THEN '.\\' || FileName ELSE ParentPath || '\\' || FileName END AS full_p,
                        ParentPath,
                        COALESCE(Extension, ''),
                        COALESCE(TRY_CAST(FileSize AS BIGINT), 0),
                        COALESCE(IsDirectory, FALSE),
                        COALESCE(InUse, TRUE),
                        TRY_CAST(EntryNumber AS BIGINT),
                        TRY_CAST(SequenceNumber AS BIGINT),
                        {_mcol('Created0x10')},
                        {_mcol('LastModified0x10')},
                        {_mcol('LastAccess0x10')},
                        {_mcol('LastRecordChange0x10')},
                        {_mcol('Created0x30')},
                        {_mcol('LastModified0x30')},
                        {_mcol('LastAccess0x30')},
                        {_mcol('LastRecordChange0x30')}
                    FROM raw_mft
                    WHERE {where_sql}
                    ORDER BY COALESCE(IsDirectory, FALSE) DESC, {ord_expr} {'DESC' if desc_flag else 'ASC'} NULLS LAST
                    LIMIT ? OFFSET ?;
                    """,
                    m_params + [limit, offset],
                ).fetchall()
                files_out = [
                    _build_file_item_dict(
                        row_id=r[0],
                        file_name=str(r[1] or ""),
                        full_path=str(r[2] or ""),
                        parent_path=str(r[3] or "."),
                        extension=str(r[4] or ""),
                        file_size=int(r[5] or 0),
                        is_directory=bool(r[6]),
                        in_use=bool(r[7]),
                        mft_entry=r[8],
                        seq_num=r[9],
                        si_created=r[10],
                        si_modified=r[11],
                        si_accessed=r[12],
                        si_changed=r[13],
                        fn_created=r[14],
                        fn_modified=r[15],
                        fn_accessed=r[16],
                        fn_changed=r[17],
                        part_index=eff_part,
                    )
                    for r in rows
                ]
                return {"case_id": case_id, "files": files_out, "items": files_out, "total_files": total_files, "total_count": total_files}

        # D. Staged folder fallback (for VSS staged stores or folder-mode cases)
        disk_base: Optional[Path] = None
        if eff_vss is not None and staging_dir and staging_dir.is_dir():
            for cand_vss in (
                staging_dir / "VSS" / f"VSS_{eff_vss}",
                staging_dir / "VSS" / f"vss_{eff_vss}",
                staging_dir / f"VSS_{eff_vss}",
                staging_dir / f"vss_{eff_vss}",
            ):
                if cand_vss.is_dir():
                    disk_base = cand_vss
                    break
        elif staging_dir and staging_dir.is_dir():
            cand_part = (staging_dir / f"Part{eff_part}") if eff_part is not None else staging_dir
            disk_base = cand_part if cand_part.is_dir() else staging_dir

        if disk_base and disk_base.is_dir():
            target_disk = disk_base if norm_rel == "." else (disk_base / norm_rel[2:])
            try:
                resolved_target = target_disk.resolve()
                if resolved_target.is_dir() and resolved_target.is_relative_to(disk_base.resolve()):
                    entries = list(resolved_target.iterdir())
                    if eff_vss is None and norm_rel == ".":
                        entries = [e for e in entries if not (e.is_dir() and e.name.upper() == "VSS")]
                    if search and search.strip():
                        q_low = search.strip().lower()
                        entries = [e for e in entries if q_low in e.name.lower()]
                    entries.sort(key=lambda e: (not e.is_dir(), e.name.lower()), reverse=desc_flag)
                    total_disk = len(entries)
                    out_disk: List[Dict[str, Any]] = []
                    for child in entries[offset : offset + limit]:
                        is_d = child.is_dir()
                        st = child.stat()
                        mtime_iso = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
                        ctime_iso = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
                        atime_iso = datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat()
                        fp, pp = _qualify_item_path(child.name)
                        rel_stage = str(child.relative_to(staging_dir.resolve())).replace("\\", "/") if staging_dir else None
                        out_disk.append(_build_file_item_dict(
                            file_name=child.name,
                            full_path=fp,
                            parent_path=pp,
                            file_size=0 if is_d else st.st_size,
                            is_directory=is_d,
                            in_use=True,
                            si_created=ctime_iso,
                            si_modified=mtime_iso,
                            si_accessed=atime_iso,
                            staged_file_path=rel_stage,
                            part_index=eff_part,
                            vss_index=eff_vss,
                        ))
                    return {"case_id": case_id, "files": out_disk, "items": out_disk, "total_files": total_disk, "total_count": total_disk}
            except OSError:
                pass

        return {"case_id": case_id, "files": [], "items": [], "total_files": 0, "total_count": 0}


def _release_transient_rw_if_idle(case_id: str, was_rw: bool) -> None:
    if not was_rw and case_id not in _running_cases:
        if DuckDBManager.has_rw_connection(case_id):
            try:
                DuckDBManager.get_connection(case_id, read_only=False).cursor().execute("CHECKPOINT;")
            except Exception:
                pass
            DuckDBManager.close_connection(case_id)


@app.post("/api/cases/{case_id}/bookmarks", summary="Bookmark / Tag evidence row")
def create_bookmark(case_id: str, payload: BookmarkCreateRequest) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        was_rw = DuckDBManager.has_rw_connection(case_id)
        conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
        cursor = conn.cursor()
        _ensure_bookmarks_table_canonical(cursor)

        b_id = payload.bookmark_id or str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO bookmarks (
                bookmark_id, source_table, source_row_id, tag_name, examiner_notes, created_at
            ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
            """,
            [b_id, payload.source_table, payload.source_row_id, payload.tag_name, payload.examiner_notes],
        )

        created_row = cursor.execute(
            """
            SELECT bookmark_id, source_table, source_row_id, tag_name, examiner_notes, created_at
            FROM bookmarks WHERE bookmark_id = ?;
            """,
            [b_id],
        ).fetchone()

        cols = ["bookmark_id", "source_table", "source_row_id", "tag_name", "examiner_notes", "created_at"]
        res = {"status": "SUCCESS", "bookmark": dict(zip(cols, [serialize_db_value(v) for v in created_row]))}
        _release_transient_rw_if_idle(case_id, was_rw)
        return res


@app.get("/api/cases/{case_id}/bookmarks", summary="List examiner bookmarks")
def list_bookmarks(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "bookmarks" not in tables:
            return {"case_id": case_id, "bookmarks": [], "total_bookmarks": 0}
        bm_cols = {r[1] for r in cursor.execute("PRAGMA table_info('bookmarks');").fetchall()}
        if "source_table" not in bm_cols:
            return {"case_id": case_id, "bookmarks": [], "total_bookmarks": 0}
        raw_bookmarks = cursor.execute(
            """
            SELECT bookmark_id, source_table, source_row_id, tag_name, examiner_notes, created_at
            FROM bookmarks
            ORDER BY created_at DESC;
            """
        ).fetchall()
        cols = ["bookmark_id", "source_table", "source_row_id", "tag_name", "examiner_notes", "created_at"]
        bookmarks_list = serialize_rows(cols, raw_bookmarks)
        return {"case_id": case_id, "bookmarks": bookmarks_list, "total_bookmarks": len(bookmarks_list)}


@app.get("/api/cases/{case_id}/tags", summary="List distinct bookmark tags and counts")
def list_case_tags(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "bookmarks" not in tables:
            return {"case_id": case_id, "tags": [], "total_tags": 0}
        bm_cols = {r[1] for r in cursor.execute("PRAGMA table_info('bookmarks');").fetchall()}
        if "source_table" not in bm_cols:
            return {"case_id": case_id, "tags": [], "total_tags": 0}
        rows = cursor.execute(
            """
            SELECT tag_name, COUNT(*) AS cnt
            FROM bookmarks
            WHERE COALESCE(TRIM(tag_name), '') <> ''
            GROUP BY tag_name
            ORDER BY cnt DESC, tag_name ASC;
            """
        ).fetchall()
        tags_out = [{"tag_name": str(r[0]), "name": str(r[0]), "count": int(r[1] or 0)} for r in rows]
        return {"case_id": case_id, "tags": tags_out, "total_tags": len(tags_out)}


@app.delete("/api/cases/{case_id}/bookmarks/{bookmark_id}", summary="Delete examiner bookmark")
def delete_bookmark(case_id: str, bookmark_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        was_rw = DuckDBManager.has_rw_connection(case_id)
        conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
        cursor = conn.cursor()
        _ensure_bookmarks_table_canonical(cursor)
        cursor.execute("DELETE FROM bookmarks WHERE bookmark_id = ?;", [bookmark_id])
        _release_transient_rw_if_idle(case_id, was_rw)
    return {"status": "SUCCESS", "bookmark_id": bookmark_id}


@app.delete("/api/cases/{case_id}/bookmarks", summary="Delete examiner bookmark by table and row_id")
def delete_bookmark_by_row(
    case_id: str,
    source_table: str = Query(...),
    source_row_id: int = Query(...),
    tag_name: Optional[str] = Query(None),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        was_rw = DuckDBManager.has_rw_connection(case_id)
        conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
        cursor = conn.cursor()
        _ensure_bookmarks_table_canonical(cursor)
        if tag_name:
            cursor.execute(
                "DELETE FROM bookmarks WHERE source_table = ? AND source_row_id = ? AND tag_name = ?;",
                [source_table, source_row_id, tag_name],
            )
        else:
            cursor.execute(
                "DELETE FROM bookmarks WHERE source_table = ? AND source_row_id = ?;",
                [source_table, source_row_id],
            )
        _release_transient_rw_if_idle(case_id, was_rw)
    return {"status": "SUCCESS", "source_table": source_table, "source_row_id": source_row_id}


# ---------------------------------------------------------------------------
# 9. Keyword Lists & Scanning Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/keywords", summary="List all case keywords and hit counts")
def get_case_keywords(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        ensure_case_exists(case_id, auto_create=False)
    _deduplicate_keyword_hits_in_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "case_keywords" not in tables:
            return {"case_id": case_id, "keywords": [], "total_keywords": 0}
        kw_cols = {r[1] for r in cursor.execute("PRAGMA table_info('case_keywords');").fetchall()}
        cs_expr = (
            "COALESCE(case_sensitive, is_case_sensitive, FALSE)"
            if ("case_sensitive" in kw_cols and "is_case_sensitive" in kw_cols)
            else ("COALESCE(case_sensitive, FALSE)" if "case_sensitive" in kw_cols else "FALSE")
        )
        cat_expr = "COALESCE(category, 'General')" if "category" in kw_cols else "'General'"
        sf_expr = "source_file" if "source_file" in kw_cols else "NULL"
        raw_keywords = cursor.execute(f"""
            SELECT keyword_id, keyword, COALESCE(is_regex, FALSE),
                   {cs_expr},
                   {cat_expr}, {sf_expr},
                   COALESCE(hit_count, 0), created_at
            FROM case_keywords
            ORDER BY hit_count DESC, created_at ASC;
        """).fetchall()
        cols = ["keyword_id", "keyword", "is_regex", "case_sensitive", "category", "source_file", "hit_count", "created_at"]
        keywords_list = serialize_rows(cols, raw_keywords)
        for item in keywords_list:
            item["is_case_sensitive"] = item["case_sensitive"]
        return {"case_id": case_id, "keywords": keywords_list, "total_keywords": len(keywords_list)}


@app.get("/api/cases/{case_id}/keywords/hits", include_in_schema=False)
def get_case_keyword_hits(
    case_id: str,
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        ensure_case_exists(case_id, auto_create=False)
    _deduplicate_keyword_hits_in_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables_set = {
            r[0]
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        for cand_tbl in ("view_keyword_hits", "parsed_keyword_hits"):
            if cand_tbl not in tables_set:
                continue
            try:
                cols = [r[0] for r in cursor.execute(f'DESCRIBE "{cand_tbl}";').fetchall()]
                total = int(cursor.execute(f'SELECT COUNT(*) FROM "{cand_tbl}";').fetchone()[0] or 0)
                order_sql = 'ORDER BY "_row_id" ASC' if "_row_id" in cols else ""
                raw_rows = cursor.execute(
                    f'SELECT * FROM "{cand_tbl}" {order_sql} LIMIT ? OFFSET ?;',
                    [limit, offset],
                ).fetchall()
                rows = serialize_rows(cols, raw_rows)
                return {
                    "case_id": case_id,
                    "hits": rows,
                    "rows": rows,
                    "total_hits": total,
                    "total_count": total,
                }
            except duckdb.Error:
                continue
        return {
            "case_id": case_id,
            "hits": [],
            "rows": [],
            "total_hits": 0,
            "total_count": 0,
        }


@app.post("/api/cases/{case_id}/keywords", summary="Add keywords and compute hit counts across case")
def add_case_keywords(case_id: str, payload: KeywordAddRequest) -> Dict[str, Any]:
    specs = _normalize_keyword_specs(
        payload.keywords,
        default_is_regex=bool(payload.is_regex),
        default_case_sensitive=bool(payload.case_sensitive),
        default_category=payload.category or "General",
        default_source=payload.source_file or "Manual",
    )
    was_rw = DuckDBManager.has_rw_connection(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
        cursor = conn.cursor()
        _upsert_case_keywords(cursor, specs)
    _scan_keywords_safe(case_id)
    with DuckDBManager.get_lock(case_id):
        _release_transient_rw_if_idle(case_id, was_rw)
    return get_case_keywords(case_id)


@app.post("/api/cases/{case_id}/keywords/upload", summary="Upload keyword text or CSV file and scan")
async def upload_case_keywords(
    case_id: str,
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    source_name: Optional[str] = Form(None),
    is_regex: bool = Form(False),
    case_sensitive: bool = Form(False),
    category: str = Form("Uploaded"),
) -> Dict[str, Any]:
    raw_text = ""
    eff_source = (source_name or "").strip() or "uploaded_keywords.txt"
    if file is not None:
        eff_source = file.filename or eff_source
        file_bytes = await file.read()
        raw_text = file_bytes.decode("utf-8", errors="replace")
    elif content is not None and content.strip():
        raw_text = content
    else:
        raise HTTPException(status_code=400, detail="Either a file upload or non-empty text content must be provided.")

    lines = raw_text.splitlines()
    extracted_keywords: List[str] = []
    seen: set[str] = set()
    for line in lines:
        parts = line.split(",") if eff_source.lower().endswith(".csv") else [line]
        for part in parts:
            clean_kw = part.strip().strip('"').strip("'")
            if clean_kw and not clean_kw.startswith("#") and clean_kw not in seen:
                seen.add(clean_kw)
                extracted_keywords.append(clean_kw)

    if not extracted_keywords:
        raise HTTPException(status_code=400, detail="No non-empty keywords found.")

    specs = _normalize_keyword_specs(
        extracted_keywords,
        default_is_regex=bool(is_regex),
        default_case_sensitive=bool(case_sensitive),
        default_category=category or "Uploaded",
        default_source=eff_source,
    )
    was_rw = DuckDBManager.has_rw_connection(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
        cursor = conn.cursor()
        _upsert_case_keywords(cursor, specs)
    _scan_keywords_safe(case_id)
    with DuckDBManager.get_lock(case_id):
        _release_transient_rw_if_idle(case_id, was_rw)
    return get_case_keywords(case_id)


@app.post("/api/cases/{case_id}/keywords/scan", summary="Re-scan case keywords across DuckDB and staged files")
def trigger_case_keyword_scan(case_id: str) -> Dict[str, Any]:
    was_rw = DuckDBManager.has_rw_connection(case_id)
    with DuckDBManager.get_lock(case_id):
        ensure_case_exists(case_id, auto_create=False, read_only=False)
    scan_res = _scan_keywords_safe(case_id)
    with DuckDBManager.get_lock(case_id):
        _release_transient_rw_if_idle(case_id, was_rw)
    kw_state = get_case_keywords(case_id)
    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "scan_result": scan_res,
        "keywords": kw_state["keywords"],
        "total_keywords": kw_state["total_keywords"],
    }


@app.delete("/api/cases/{case_id}/keywords/{keyword_id}", summary="Delete specific keyword from case")
def delete_case_keyword(case_id: str, keyword_id: str) -> Dict[str, Any]:
    was_rw = DuckDBManager.has_rw_connection(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
        cursor = conn.cursor()
        _ensure_case_keywords_columns(cursor)
        cursor.execute("DELETE FROM case_keywords WHERE keyword_id = ?;", [keyword_id])
    _scan_keywords_safe(case_id)
    with DuckDBManager.get_lock(case_id):
        _release_transient_rw_if_idle(case_id, was_rw)
    return {"status": "SUCCESS", "case_id": case_id, "keyword_id": keyword_id}


# ---------------------------------------------------------------------------
# 10. System Endpoints: Native File Dialogs & Path Validation
# ---------------------------------------------------------------------------
class ValidatePathRequest(BaseModel):
    path: str


def format_bytes_human(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


KNOWN_FORENSIC_IMAGE_EXTS = {".e01", ".ex01", ".vhdx", ".vhd", ".vmdk", ".raw", ".dd", ".img", ".iso", ".001"}
KNOWN_FORENSIC_ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"}


def _run_native_picker(mode: str = "folder", initial_dir: Optional[str] = None) -> Dict[str, Any]:
    # Allow test harness mock path strictly during automated pytest execution
    if "PYTEST_CURRENT_TEST" in os.environ and os.getenv("WFT_MOCK_BROWSE_PATH"):
        mock_p = os.getenv("WFT_MOCK_BROWSE_PATH")
        if mock_p and os.path.exists(mock_p):
            return {"cancelled": False, "path": mock_p}

    target_mode = "file" if str(mode).strip().lower() == "file" else "folder"
    init_dir = initial_dir if (initial_dir and os.path.exists(initial_dir)) else ""
    title = "Select Forensic Disk Image or Evidence File" if target_mode == "file" else "Select Target Directory"
    dialog_timeout = int(os.getenv("WFT_BROWSE_TIMEOUT", "120"))

    try:
        if target_mode == "file":
            init_filter = f"$f.InitialDirectory = '{init_dir}'; " if init_dir else ""
            ps_script = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$top = New-Object System.Windows.Forms.Form; $top.TopMost = $true; "
                "$f = New-Object System.Windows.Forms.OpenFileDialog; "
                f"$f.Title = '{title}'; "
                + init_filter
                + "$f.Filter = 'Forensic Disk Images (*.E01;*.Ex01;*.VHDX;*.VHD;*.VMDK;*.RAW;*.DD;*.IMG;*.ISO;*.001)|*.E01;*.Ex01;*.e01;*.vhdx;*.vhd;*.vmdk;*.raw;*.dd;*.img;*.iso;*.001|All Files (*.*)|*.*'; "
                "if ($f.ShowDialog($top) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.FileName }"
            )
        else:
            init_filter = f"$d.SelectedPath = '{init_dir}'; " if init_dir else ""
            ps_script = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$top = New-Object System.Windows.Forms.Form; $top.TopMost = $true; "
                "$d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                f"$d.Description = '{title}'; "
                + init_filter
                + "$d.ShowNewFolderButton = $true; "
                "if ($d.ShowDialog($top) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $d.SelectedPath }"
            )

        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Sta", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=dialog_timeout,
        )
        selected = proc.stdout.strip()
        if selected:
            lines = [l.strip() for l in selected.splitlines() if l.strip()]
            final_path = lines[-1] if lines else ""
            if final_path and os.path.exists(final_path):
                clean_p = str(Path(final_path).resolve())
                return {"path": clean_p, "selected_path": clean_p, "cancelled": False, "exists": True}
        return {"path": "", "selected_path": "", "cancelled": True, "exists": False}
    except Exception as ex:
        return {"path": "", "selected_path": "", "cancelled": True, "error": str(ex), "exists": False}


@app.get("/api/system/browse", summary="Native Windows file/folder browse dialog")
def system_browse(
    target_type: str = Query("folder"),
    initial_dir: Optional[str] = Query(None),
) -> Dict[str, Any]:
    clean_target = "file" if target_type.strip().lower() == "file" else "folder"
    res = _run_native_picker(mode=clean_target, initial_dir=initial_dir)
    return {"selected_path": res.get("selected_path") or res.get("path") or ""}


@app.get("/api/system/browse-file", summary="Native Windows file picker dialog")
def browse_file(initial_dir: Optional[str] = Query(None)) -> Dict[str, Any]:
    return _run_native_picker("file", initial_dir=initial_dir)


@app.get("/api/system/browse-folder", summary="Native Windows folder picker dialog")
def browse_folder(initial_dir: Optional[str] = Query(None)) -> Dict[str, Any]:
    return _run_native_picker("folder", initial_dir=initial_dir)


@app.get("/api/system/list-dir", summary="List directory contents, Windows drives, and quick access folders")
def list_directory(path: Optional[str] = Query(None)) -> Dict[str, Any]:
    drives = []
    if os.name == "nt":
        try:
            import string
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    d_path = f"{letter}:\\"
                    if os.path.exists(d_path):
                        drives.append({"name": f"{letter}:", "path": d_path})
                bitmask >>= 1
        except Exception:
            pass
    if not drives:
        drives.append({"name": "C:", "path": "C:\\"} if os.path.exists("C:\\") else {"name": "Root", "path": "/"})

    home = Path.home()
    quick_access = [
        {"name": "Desktop", "path": str(home / "Desktop"), "exists": (home / "Desktop").exists()},
        {"name": "Downloads", "path": str(home / "Downloads"), "exists": (home / "Downloads").exists()},
        {"name": "Documents", "path": str(home / "Documents"), "exists": (home / "Documents").exists()},
        {"name": "User Profile", "path": str(home), "exists": home.exists()},
        {
            "name": "Windows Forensic Toolkit (WFT) Cases",
            "path": str(Path(getattr(_cfg, "CASES_DIR", CASES_DIR)).resolve()),
            "exists": Path(getattr(_cfg, "CASES_DIR", CASES_DIR)).exists(),
        },
    ]

    clean_path = path.strip().strip('"').strip("'").strip() if path else ""
    if not clean_path:
        entries = [
            {
                "name": d["name"],
                "path": d["path"],
                "is_dir": True,
                "is_drive": True,
                "size_bytes": 0,
                "formatted_size": None,
                "is_image": False,
                "is_archive": False,
                "extension": "",
                "modified_at": None,
            }
            for d in drives
        ]
        return {
            "current_path": "",
            "parent_path": None,
            "is_drive_root": False,
            "drives": drives,
            "quick_access": quick_access,
            "entries": entries,
            "total_entries": len(entries),
            "total_folders": len(entries),
            "total_images": 0,
            "error": None,
        }

    p = Path(clean_path).resolve()
    if not p.exists():
        return {
            "current_path": str(p),
            "parent_path": str(p.parent) if p != p.parent else "",
            "is_drive_root": False,
            "drives": drives,
            "quick_access": quick_access,
            "entries": [],
            "total_entries": 0,
            "total_folders": 0,
            "total_images": 0,
            "error": f"Path not found on disk: {p}",
        }

    if p.is_file():
        p = p.parent

    is_drive_root = p == p.parent
    parent_path = "" if is_drive_root else str(p.parent)
    folders = []
    files = []
    error_msg = None

    try:
        for child in p.iterdir():
            try:
                is_d = child.is_dir()
                ext = child.suffix.lower()
                st = child.stat() if not is_d else None
                sz = st.st_size if st else 0
                item = {
                    "name": child.name,
                    "path": str(child.resolve()),
                    "is_dir": is_d,
                    "is_drive": False,
                    "size_bytes": sz,
                    "formatted_size": format_bytes_human(sz) if (not is_d and sz > 0) else None,
                    "is_image": ext in KNOWN_FORENSIC_IMAGE_EXTS,
                    "is_archive": ext in KNOWN_FORENSIC_ARCHIVE_EXTS,
                    "extension": ext,
                    "modified_at": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat() if st else None,
                }
                (folders if is_d else files).append(item)
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError) as access_err:
        error_msg = f"Access denied to folder: {access_err}"

    folders.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["name"].lower())
    all_entries = folders + files

    return {
        "current_path": str(p),
        "parent_path": parent_path,
        "is_drive_root": is_drive_root,
        "drives": drives,
        "quick_access": quick_access,
        "entries": all_entries,
        "total_entries": len(all_entries),
        "total_folders": len(folders),
        "total_images": sum(1 for f in files if f["is_image"]),
        "error": error_msg,
    }


@app.post("/api/system/validate-path", summary="Validate existence and inspect typed/pasted Windows path")
def validate_path(payload: ValidatePathRequest) -> Dict[str, Any]:
    raw_str = payload.path or ""
    clean_str = raw_str.strip().strip('"').strip("'").strip()
    if not clean_str:
        return {"valid": False, "exists": False, "path": raw_str, "clean_path": "", "error": "Path cannot be empty."}

    try:
        resolved_p = Path(clean_str).resolve()
    except Exception as ex:
        return {"valid": False, "exists": False, "path": clean_str, "clean_path": clean_str, "error": str(ex)}

    if not resolved_p.exists():
        return {"valid": False, "exists": False, "path": str(resolved_p), "clean_path": str(resolved_p), "error": f"Path not found: {resolved_p}"}

    is_file = resolved_p.is_file()
    is_dir = resolved_p.is_dir()
    size_bytes = resolved_p.stat().st_size if is_file else 0
    ext = resolved_p.suffix.lower() if is_file else ""
    detected_type = "Directory / Folder" if is_dir else f"File ({ext.upper() if ext else 'Binary'})"

    return {
        "valid": True,
        "exists": True,
        "path": str(resolved_p),
        "clean_path": str(resolved_p),
        "raw_path": raw_str,
        "is_file": is_file,
        "is_dir": is_dir,
        "is_image": is_file and ext in KNOWN_FORENSIC_IMAGE_EXTS,
        "is_archive": is_file and ext in KNOWN_FORENSIC_ARCHIVE_EXTS,
        "size_bytes": size_bytes,
        "formatted_size": format_bytes_human(size_bytes) if is_file else None,
        "detected_type": detected_type,
        "contained_images": [],
    }


# ---------------------------------------------------------------------------
# Section 14: System Tool Paths Management
# ---------------------------------------------------------------------------
@app.get("/api/system/tool-paths")
@app.get("/api/settings/tools")
@app.get("/api/config/tool-paths")
@app.get("/api/tools/paths")
def get_system_tool_paths_endpoint(scan: bool = Query(False)) -> Dict[str, Any]:
    if scan:
        res = _cfg.scan_and_sync_tool_paths(apply_to_env=True)
        return res.get("tools", res)
    _cfg.reload_dotenv(override=False)
    return _cfg.get_tool_paths_status()


@app.get("/api/system/scan-tools")
@app.post("/api/system/scan-tools")
@app.get("/api/tools/scan")
@app.post("/api/tools/scan")
def scan_system_tools_endpoint(save_to_env: bool = Query(True)) -> Dict[str, Any]:
    return _cfg.scan_and_sync_tool_paths(apply_to_env=save_to_env)


@app.post("/api/system/tool-paths")
@app.put("/api/system/tool-paths")
@app.post("/api/settings/tools")
@app.put("/api/settings/tools")
@app.post("/api/config/tool-paths")
@app.post("/api/tools/paths")
def update_system_tool_paths_endpoint(payload: Union[ToolPathsUpdateRequest, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(payload, ToolPathsUpdateRequest):
        paths_to_save = dict(payload.paths)
    elif isinstance(payload, dict):
        if "paths" in payload and isinstance(payload["paths"], dict):
            paths_to_save = dict(payload["paths"])
        elif "tools" in payload and isinstance(payload["tools"], dict):
            paths_to_save = {
                k: (v.get("path") or v.get("configured_path") or "") if isinstance(v, dict) else v
                for k, v in payload["tools"].items()
            }
        else:
            paths_to_save = dict(payload)
    else:
        paths_to_save = {}

    for _, v in list(paths_to_save.items()):
        if v and isinstance(v, str) and v.strip():
            try:
                validate_tool_binary_path(v)
            except ValueError as val_err:
                raise HTTPException(status_code=400, detail=str(val_err))

    updated_tools = _cfg.save_tool_paths(paths_to_save)
    _cfg.reload_dotenv(override=False)
    refreshed = _cfg.get_tool_paths_status()
    return {
        "status": "success",
        "message": "Tool paths updated successfully.",
        "tools": refreshed or updated_tools,
        "env_file_path": str(_cfg.get_env_file()),
        "tool_paths_file": str(_cfg.get_tool_paths_file()),
        "saved_to_env": True,
    }


@app.post("/api/system/auto-setup-tools", summary="Run Setup-WFTTools.ps1 and reload tool status")
@app.post("/api/settings/tools/auto-setup", include_in_schema=False)
def auto_setup_system_tools_endpoint(
    payload: Optional[AutoSetupToolsRequest] = Body(None),
) -> Dict[str, Any]:
    req = payload or AutoSetupToolsRequest()
    script_path = (_cfg.BASE_DIR / "Setup-WFTTools.ps1").resolve()
    env_file_path = _cfg.get_env_file()
    stdout_str = ""
    stderr_str = ""
    exit_code = 0

    if script_path.is_file():
        ps_exe = shutil.which("pwsh") or shutil.which("powershell.exe") or "powershell.exe"
        cmd = [
            ps_exe,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-ProjectRoot",
            str(_cfg.BASE_DIR.resolve()),
            "-EnvFilePath",
            str(env_file_path),
        ]
        if req.skip_full_disk_scan:
            cmd.append("-SkipFullDiskScan")
        if req.force_update:
            cmd.append("-ForceUpdate")

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(_cfg.BASE_DIR.resolve()),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=int(os.getenv("WFT_AUTO_SETUP_TIMEOUT", "300")),
                creationflags=creationflags,
            )
            exit_code = int(proc.returncode)
            stdout_str = (proc.stdout or "")[-8000:]
            stderr_str = (proc.stderr or "")[-4000:]
        except subprocess.TimeoutExpired as tex:
            raise HTTPException(status_code=504, detail=f"Setup-WFTTools.ps1 timed out: {tex}")
        except OSError as oex:
            raise HTTPException(status_code=500, detail=f"Failed launching Setup-WFTTools.ps1: {oex}")
    else:
        scan_res = _cfg.scan_and_sync_tool_paths(apply_to_env=True)
        stdout_str = f"Setup-WFTTools.ps1 not found; ran fast Python scanner ({scan_res.get('discovered_count', 0)} tools)."

    _cfg.reload_dotenv(env_file=env_file_path, override=True)
    tools_status = _cfg.get_tool_paths_status()
    found_count = sum(1 for v in tools_status.values() if isinstance(v, dict) and v.get("status") == "FOUND")
    return {
        "status": "success" if exit_code == 0 else "warning",
        "exit_code": exit_code,
        "found_count": found_count,
        "total_tools": len(tools_status),
        "tools": tools_status,
        "env_file_path": str(env_file_path),
        "stdout": stdout_str,
        "stderr": stderr_str,
    }


@app.post("/api/system/shutdown")
def shutdown_system(background_tasks: BackgroundTasks) -> Dict[str, str]:
    def _do_shutdown():
        time.sleep(0.4)
        DuckDBManager.close_all()
        os._exit(0)

    background_tasks.add_task(_do_shutdown)
    return {"status": "shutting_down"}


# ---------------------------------------------------------------------------
# Section 15: Event Logs Workbench (Read-Only Built-In + External Custom CRUD)
# ---------------------------------------------------------------------------
EVENT_PROFILES_FILE: Path = (BASE_DIR / "rules" / "event_profiles.json").resolve()
_EVENT_PROFILES_LOCK = threading.Lock()
_FORBIDDEN_PROFILE_SQL_RE = re.compile(
    r"(;|--|/\*|\*/"
    r"|\b(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|ATTACH|DETACH|COPY|PRAGMA|EXPORT|IMPORT|CALL|LOAD|INSTALL"
    r"|SELECT|UNION|EXCEPT|INTERSECT|FROM|JOIN|INTO|WITH|WINDOW|QUALIFY|HAVING|GROUP|ORDER|LIMIT|OFFSET"
    r"|VALUES|SET|TRUNCATE|VACUUM|CHECKPOINT|SUMMARIZE|DESCRIBE|SHOW|EXPLAIN|PREPARE|EXECUTE|UESCAPE)\b"
    r"|\b(?:read_\w+|parquet_\w+|glob|duckdb_\w+|sqlite_\w+|pragma_\w+|information_schema|pg_\w+|current_setting|getenv)\b)",
    flags=re.IGNORECASE,
)


def _is_unsafe_profile_sql(raw_sql: str) -> bool:
    """Single-pass character lexer rejecting dollar/escaped/prefixed literals, comments, bad identifiers, and forbidden SQL."""
    if not raw_sql:
        return False
    if "\x00" in raw_sql:
        return True

    def _is_ident_char(c: str) -> bool:
        return ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c == "_"

    n = len(raw_sql)
    i = 0
    depth = 0
    stripped_buf: List[str] = []

    while i < n:
        ch = raw_sql[i]

        # Reject dollar-quoting ($), backslash escapes (\), statement separators (;), and comments outside literals
        if ch in ("$", "\\", ";"):
            return True
        if ch == "-" and i + 1 < n and raw_sql[i + 1] == "-":
            return True
        if ch == "/" and i + 1 < n and raw_sql[i + 1] == "*":
            return True
        if ch == "*" and i + 1 < n and raw_sql[i + 1] == "/":
            return True

        # Reject prefixed string/identifier literals: [eExXbB]' and Unicode U&' / u&' / U&" / u&"
        prev_is_ident = i > 0 and _is_ident_char(raw_sql[i - 1])
        if not prev_is_ident:
            if ch in ("e", "E", "x", "X", "b", "B") and i + 1 < n and raw_sql[i + 1] == "'":
                return True
            if ch in ("u", "U") and i + 2 < n and raw_sql[i + 1] == "&" and raw_sql[i + 2] in ("'", '"'):
                return True

        # Standard SQL single-quoted string literal ('...' with '' doubled-quote escape only)
        if ch == "'":
            i += 1
            closed = False
            while i < n:
                if raw_sql[i] == "'":
                    if i + 1 < n and raw_sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                return True
            stripped_buf.append("''")
            continue

        # Double-quoted SQL identifier ("..." must close, be non-empty, and contain only [A-Za-z0-9_])
        if ch == '"':
            i += 1
            ident_start = i
            closed_ident = False
            while i < n:
                if raw_sql[i] == '"':
                    if i + 1 < n and raw_sql[i + 1] == '"':
                        return True
                    ident_body = raw_sql[ident_start:i]
                    i += 1
                    closed_ident = True
                    break
                if not _is_ident_char(raw_sql[i]):
                    return True
                i += 1
            if not closed_ident or not ident_body:
                return True
            stripped_buf.append(f'"{ident_body}"')
            continue

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return True

        stripped_buf.append(ch)
        i += 1

    if depth != 0:
        return True
    return bool(_FORBIDDEN_PROFILE_SQL_RE.search("".join(stripped_buf)))


def _get_custom_event_profiles_file() -> Path:
    """Resolve writable external custom event profiles path (NEVER rules/event_profiles.json)."""
    explicit_env = os.environ.get("WFT_EVENT_PROFILES_FILE", "").strip()
    if explicit_env:
        cand = Path(explicit_env).resolve()
    elif os.environ.get("WFT_TOOL_PATHS_FILE", "").strip():
        cand = (Path(os.environ["WFT_TOOL_PATHS_FILE"]).resolve().parent / "custom_event_profiles.json").resolve()
    else:
        cand = (_cfg.get_appdata_dir() / "custom_event_profiles.json").resolve()
    if cand == EVENT_PROFILES_FILE:
        cand = (_cfg.get_appdata_dir() / "custom_event_profiles.json").resolve()
    return cand


def _load_builtin_event_profiles() -> List[Dict[str, Any]]:
    """Read built-in rules/event_profiles.json strictly READ-ONLY."""
    builtin_path = (_cfg.RULES_DIR / "event_profiles.json").resolve()
    if not builtin_path.is_file():
        builtin_path = EVENT_PROFILES_FILE
    if builtin_path.is_file() and builtin_path.stat().st_size > 0:
        try:
            with open(builtin_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                out = []
                for item in data:
                    if isinstance(item, dict):
                        cp = dict(item)
                        cp.setdefault("builtin", True)
                        out.append(cp)
                return out
        except Exception:
            pass
    return []


def _load_custom_profiles_store() -> Tuple[List[Dict[str, Any]], set[str]]:
    custom_file = _get_custom_event_profiles_file()
    if not custom_file.is_file() or custom_file.stat().st_size == 0:
        return ([], set())
    try:
        with open(custom_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, list):
            return ([dict(x) for x in raw if isinstance(x, dict)], set())
        if isinstance(raw, dict):
            c_list = [dict(x) for x in (raw.get("custom_profiles") or []) if isinstance(x, dict)]
            del_ids = {str(x) for x in (raw.get("deleted_ids") or []) if str(x).strip()}
            return (c_list, del_ids)
    except Exception:
        pass
    return ([], set())


def _save_custom_profiles_store(custom_profiles: List[Dict[str, Any]], deleted_ids: set[str]) -> Path:
    custom_file = _get_custom_event_profiles_file()
    if custom_file.resolve() == EVENT_PROFILES_FILE.resolve():
        raise RuntimeError("Refusing to write to read-only rules/event_profiles.json")
    custom_file.parent.mkdir(parents=True, exist_ok=True)
    clean_custom = []
    for item in custom_profiles:
        if isinstance(item, dict):
            d = {k: v for k, v in item.items() if not str(k).startswith("_")}
            clean_custom.append(d)
    payload = {
        "custom_profiles": clean_custom,
        "deleted_ids": sorted(deleted_ids),
    }
    tmp_path = custom_file.with_suffix(f".tmp_{os.getpid()}_{time.time_ns()}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp_path, custom_file)
    return custom_file


def load_event_profiles() -> List[Dict[str, Any]]:
    builtins = _load_builtin_event_profiles()
    custom_list, deleted_ids = _load_custom_profiles_store()
    merged_by_id: Dict[str, Dict[str, Any]] = {}
    ordered_ids: List[str] = []

    for bp in builtins:
        pid = str(bp.get("id") or "").strip()
        if not pid or pid in deleted_ids:
            continue
        entry = dict(bp)
        entry["_trusted_builtin_sql"] = True
        merged_by_id[pid] = entry
        ordered_ids.append(pid)

    for cp in custom_list:
        pid = str(cp.get("id") or "").strip()
        if not pid:
            continue
        entry = dict(cp)
        entry["builtin"] = False
        entry["_trusted_builtin_sql"] = False
        if pid not in merged_by_id:
            ordered_ids.append(pid)
        merged_by_id[pid] = entry

    return [{k: v for k, v in merged_by_id[pid].items() if not k.startswith("_")} for pid in ordered_ids if pid in merged_by_id]


def build_profile_sql(profile: Dict[str, Any]) -> str:
    raw_sql = str(profile.get("sql") or "").strip()
    if raw_sql and not _is_unsafe_profile_sql(raw_sql):
        return raw_sql

    clauses: List[str] = []
    eids = profile.get("event_ids") or []
    if isinstance(eids, (list, tuple, set)):
        clean_ids = [str(int(x)) for x in eids if str(x).strip().isdigit()]
        if clean_ids:
            clauses.append(f"TRY_CAST(EventId AS BIGINT) IN ({', '.join(clean_ids)})")

    channels = profile.get("channels") or ([] if not profile.get("channel") else [profile.get("channel")])
    if isinstance(channels, (list, tuple, set)):
        ch_ors = []
        for ch in channels:
            ch_s = str(ch or "").strip()
            if ch_s:
                esc_ch = escape_ilike(ch_s).replace("'", "''")
                ch_ors.append(f"COALESCE(Channel, '') ILIKE '%{esc_ch}%' ESCAPE '\\'")
        if ch_ors:
            clauses.append("(" + " OR ".join(ch_ors) + ")")

    kws = profile.get("keywords") or []
    if isinstance(kws, (list, tuple, set)):
        kw_ors = []
        for kw in kws:
            kw_s = str(kw or "").strip()
            if kw_s:
                esc_kw = escape_ilike(kw_s).replace("'", "''")
                kw_ors.append(
                    f"(COALESCE(MapDescription, '') ILIKE '%{esc_kw}%' ESCAPE '\\' OR COALESCE(PayloadData1, '') ILIKE '%{esc_kw}%' ESCAPE '\\' OR COALESCE(PayloadData2, '') ILIKE '%{esc_kw}%' ESCAPE '\\')"
                )
        if kw_ors:
            clauses.append("(" + " OR ".join(kw_ors) + ")")

    return " AND ".join(clauses) if clauses else "1=1"


def _normalize_event_profile_input(raw_item: Dict[str, Any]) -> Dict[str, Any]:
    name = str(raw_item.get("name") or raw_item.get("title") or "").strip()
    pid = str(raw_item.get("id") or "").strip()
    if not pid and name:
        pid = re.sub(r"[^a-z0-9_\-]+", "_", name.lower()).strip("_") or f"custom_{uuid.uuid4().hex[:8]}"
    if not pid:
        raise HTTPException(status_code=400, detail="Event profile requires 'id' or 'name'.")
    if not name:
        name = pid
    raw_sql = str(raw_item.get("sql") or "").strip()
    if raw_sql and _is_unsafe_profile_sql(raw_sql):
        raise HTTPException(status_code=400, detail="Unsafe SQL statement in custom event profile.")

    eids_raw = raw_item.get("event_ids") or []
    if isinstance(eids_raw, str):
        eids_list = [int(x.strip()) for x in eids_raw.split(",") if x.strip().isdigit()]
    elif isinstance(eids_raw, list):
        eids_list = [int(x) for x in eids_raw if str(x).strip().isdigit()]
    else:
        eids_list = []

    channels_raw = raw_item.get("channels") or ([] if not raw_item.get("channel") else [raw_item.get("channel")])
    channels_list = parse_list_param(channels_raw) if not isinstance(channels_raw, list) else [str(x).strip() for x in channels_raw if str(x).strip()]
    kws_raw = raw_item.get("keywords") or []
    kws_list = parse_list_param(kws_raw) if not isinstance(kws_raw, list) else [str(x).strip() for x in kws_raw if str(x).strip()]

    out: Dict[str, Any] = {
        "id": pid,
        "name": name,
        "description": str(raw_item.get("description") or "").strip(),
        "badge_color": str(raw_item.get("badge_color") or "indigo").strip() or "indigo",
        "event_ids": eids_list,
        "channels": channels_list,
        "keywords": kws_list,
        "builtin": False,
    }
    if raw_sql:
        out["sql"] = raw_sql
    return out


@app.get("/api/event-profiles")
def get_event_profiles_endpoint(case_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    profiles = load_event_profiles()
    raw_content = json.dumps(profiles, indent=2)
    custom_file = _get_custom_event_profiles_file()
    return {
        "profiles": profiles,
        "total_profiles": len(profiles),
        "profile_file_name": custom_file.name,
        "profile_file_path": str(custom_file),
        "builtin_file_path": "rules/event_profiles.json",
        "raw_content": raw_content,
        "raw_json": raw_content,
    }


@app.post("/api/event-profiles", summary="Create or update a custom event profile without mutating rules/event_profiles.json")
def create_or_update_event_profile(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    norm_prof = _normalize_event_profile_input(payload)
    pid = norm_prof["id"]
    with _EVENT_PROFILES_LOCK:
        custom_list, deleted_ids = _load_custom_profiles_store()
        deleted_ids.discard(pid)
        replaced = False
        new_custom: List[Dict[str, Any]] = []
        for item in custom_list:
            if str(item.get("id") or "") == pid:
                new_custom.append(norm_prof)
                replaced = True
            else:
                new_custom.append(item)
        if not replaced:
            new_custom.append(norm_prof)
        saved_path = _save_custom_profiles_store(new_custom, deleted_ids)
    profiles = load_event_profiles()
    raw_content = json.dumps(profiles, indent=2)
    return {
        "status": "SUCCESS",
        "profile": norm_prof,
        "profiles": profiles,
        "total_profiles": len(profiles),
        "profile_file_path": str(saved_path),
        "raw_content": raw_content,
        "raw_json": raw_content,
    }


@app.put("/api/event-profiles/raw", summary="Save edited event profiles JSON to external custom store")
def update_event_profiles_raw(payload: Union[Dict[str, Any], List[Any]] = Body(...)) -> Dict[str, Any]:
    if isinstance(payload, list):
        parsed_list = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("profiles"), list):
            parsed_list = payload["profiles"]
        else:
            raw_str = payload.get("raw_content") if payload.get("raw_content") is not None else (
                payload.get("raw_json") if payload.get("raw_json") is not None else payload.get("content")
            )
            if not isinstance(raw_str, str):
                raise HTTPException(status_code=400, detail="Expected JSON string in 'raw_content'/'raw_json' or 'profiles' list.")
            try:
                parsed_list = json.loads(raw_str)
            except Exception as jerr:
                raise HTTPException(status_code=400, detail=f"Invalid JSON in event profiles payload: {jerr}")
    else:
        raise HTTPException(status_code=400, detail="Invalid payload format.")

    if not isinstance(parsed_list, list):
        raise HTTPException(status_code=400, detail="Event profiles JSON root must be a list of profile objects.")

    normalized_incoming: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in parsed_list:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail="Each event profile entry must be an object.")
        np = _normalize_event_profile_input(entry)
        if np["id"] not in seen_ids:
            seen_ids.add(np["id"])
            normalized_incoming.append(np)

    with _EVENT_PROFILES_LOCK:
        builtins = {str(b.get("id")): b for b in _load_builtin_event_profiles() if b.get("id")}
        deleted_ids = {bid for bid in builtins.keys() if bid not in seen_ids}
        custom_overrides: List[Dict[str, Any]] = []
        for np in normalized_incoming:
            bid = np["id"]
            if bid in builtins:
                b_orig = builtins[bid]
                same = (
                    str(b_orig.get("name") or "") == np["name"]
                    and str(b_orig.get("description") or "") == np["description"]
                    and str(b_orig.get("sql") or "").strip() == str(np.get("sql") or "").strip()
                    and list(b_orig.get("event_ids") or []) == list(np.get("event_ids") or [])
                )
                if not same:
                    custom_overrides.append(np)
            else:
                custom_overrides.append(np)
        saved_path = _save_custom_profiles_store(custom_overrides, deleted_ids)

    profiles = load_event_profiles()
    raw_content = json.dumps(profiles, indent=2)
    return {
        "status": "SUCCESS",
        "profiles": profiles,
        "total_profiles": len(profiles),
        "profile_file_path": str(saved_path),
        "raw_content": raw_content,
        "raw_json": raw_content,
    }


@app.delete("/api/event-profiles/{profile_id}", summary="Delete or hide an event profile via external custom store")
def delete_event_profile_endpoint(profile_id: str) -> Dict[str, Any]:
    clean_id = (profile_id or "").strip()
    if not clean_id:
        raise HTTPException(status_code=400, detail="Invalid profile_id")
    with _EVENT_PROFILES_LOCK:
        current_ids = {str(p.get("id")) for p in load_event_profiles() if p.get("id")}
        if clean_id not in current_ids:
            raise HTTPException(status_code=404, detail=f"Event profile '{clean_id}' not found.")
        builtins = {str(b.get("id")) for b in _load_builtin_event_profiles() if b.get("id")}
        custom_list, deleted_ids = _load_custom_profiles_store()
        new_custom = [c for c in custom_list if str(c.get("id") or "") != clean_id]
        if clean_id in builtins:
            deleted_ids.add(clean_id)
        saved_path = _save_custom_profiles_store(new_custom, deleted_ids)

    profiles = load_event_profiles()
    raw_content = json.dumps(profiles, indent=2)
    return {
        "status": "SUCCESS",
        "deleted_id": clean_id,
        "profiles": profiles,
        "total_profiles": len(profiles),
        "profile_file_path": str(saved_path),
        "raw_content": raw_content,
        "raw_json": raw_content,
    }


@app.get("/api/cases/{case_id}/evtx/profiles")
def get_evtx_profiles(case_id: str) -> Dict[str, Any]:
    profiles = load_event_profiles()
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables_found = [
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        ]
        if "raw_evtx" not in tables_found:
            return {"case_id": case_id, "total_evtx_count": 0, "profiles": [], "files": []}

        total_evtx = cursor.execute("SELECT COUNT(*) FROM raw_evtx;").fetchone()[0]
        profiles_out = []
        for p in profiles:
            try:
                sql_cond = build_profile_sql(p)
                cnt = cursor.execute(f"SELECT COUNT(*) FROM raw_evtx WHERE {sql_cond};").fetchone()[0]
            except Exception:
                cnt = 0
            profiles_out.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description"),
                "badge_color": p.get("badge_color", "indigo"),
                "hit_count": cnt,
            })

        files_out = []
        try:
            raw_files = cursor.execute("""
                SELECT SourceFile, regexp_extract(SourceFile, '([^\\\\/]+)$', 1) as fname, Channel, COUNT(*) as cnt
                FROM raw_evtx
                GROUP BY SourceFile, fname, Channel
                ORDER BY cnt DESC;
            """).fetchall()
            for sf, fn, ch, c in raw_files:
                clean_title = fn.replace("%4", "/").replace(".evtx", "") if fn else "Unknown"
                files_out.append({
                    "source_file": sf,
                    "file_name": fn,
                    "display_name": clean_title,
                    "channel": ch or clean_title,
                    "row_count": c,
                })
        except Exception:
            pass

        return {"case_id": case_id, "total_evtx_count": total_evtx, "profiles": profiles_out, "files": files_out}


@app.get("/api/cases/{case_id}/evtx/rows")
@app.get("/api/cases/{case_id}/eventlogs/query", include_in_schema=False)
def get_evtx_rows(
    case_id: str,
    profile_id: Optional[str] = Query(None),
    file_name: Optional[str] = Query(None),
    event_id: Optional[int] = Query(None),
    level: Optional[str] = Query(None),
    channel: Optional[str] = Query(None),
    search: str = Query(""),
    keywords: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    sort_col: str = Query("TimeCreated"),
    sort_dir: Literal["ASC", "DESC", "asc", "desc"] = Query("DESC"),
) -> Dict[str, Any]:
    kw_terms = parse_list_param(keywords)
    tag_terms = parse_list_param(tags)
    dt_from = normalize_utc_bound(date_from or start_time, is_end=False)
    dt_to = normalize_utc_bound(date_to or end_time, is_end=True)

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables_found = {
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "raw_evtx" not in tables_found:
            return {"case_id": case_id, "columns": [], "rows": [], "total_count": 0, "filtered_count": 0, "limit": limit, "offset": offset}

        cols_info = cursor.execute("DESCRIBE raw_evtx;").fetchall()
        col_names = [c[0] for c in cols_info]
        where_clauses: List[str] = []
        params: List[Any] = []

        if profile_id:
            profiles = load_event_profiles()
            matched_profile = next((p for p in profiles if p.get("id") == profile_id), None)
            if matched_profile:
                raw_prof_sql = str(matched_profile.get("sql") or "").strip()
                if raw_prof_sql and not matched_profile.get("builtin", False) and _is_unsafe_profile_sql(raw_prof_sql):
                    raise HTTPException(status_code=400, detail="Unsafe SQL statement in custom event profile.")
                where_clauses.append(f"({build_profile_sql(matched_profile)})")
        if file_name and file_name.strip():
            fn_clean = file_name.strip()
            fn_no_ext = fn_clean[:-5] if fn_clean.lower().endswith(".evtx") else fn_clean
            fn_enc = fn_no_ext.replace("/", "%4")
            fn_dec = fn_no_ext.replace("%4", "/")
            if "SourceFile" in col_names:
                where_clauses.append(
                    "(COALESCE(SourceFile, '') ILIKE ? ESCAPE '\\' OR COALESCE(SourceFile, '') ILIKE ? ESCAPE '\\' OR COALESCE(Channel, '') ILIKE ? ESCAPE '\\')"
                )
                params.extend([f"%{escape_ilike(fn_clean)}%", f"%{escape_ilike(fn_enc)}%", f"%{escape_ilike(fn_dec)}%"])
            else:
                where_clauses.append("(COALESCE(Channel, '') ILIKE ? ESCAPE '\\' OR COALESCE(Channel, '') ILIKE ? ESCAPE '\\')")
                params.extend([f"%{escape_ilike(fn_no_ext)}%", f"%{escape_ilike(fn_dec)}%"])
        if event_id is not None:
            where_clauses.append("TRY_CAST(EventId AS BIGINT) = ?")
            params.append(int(event_id))
        if level and level.strip():
            where_clauses.append("COALESCE(Level, '') ILIKE ? ESCAPE '\\'")
            params.append(escape_ilike(level.strip()))
        if channel and channel.strip():
            ch_raw = channel.strip()
            ch_no_ext = ch_raw[:-5] if ch_raw.lower().endswith(".evtx") else ch_raw
            ch_dec = ch_no_ext.replace("%4", "/")
            ch_enc = ch_dec.replace("/", "%4")
            if "SourceFile" in col_names:
                where_clauses.append(
                    "(COALESCE(Channel, '') ILIKE ? ESCAPE '\\' OR COALESCE(Channel, '') ILIKE ? ESCAPE '\\' OR COALESCE(SourceFile, '') ILIKE ? ESCAPE '\\')"
                )
                params.extend([f"%{escape_ilike(ch_dec)}%", f"%{escape_ilike(ch_no_ext)}%", f"%{escape_ilike(ch_enc)}%"])
            else:
                where_clauses.append("(COALESCE(Channel, '') ILIKE ? ESCAPE '\\' OR COALESCE(Channel, '') ILIKE ? ESCAPE '\\')")
                params.extend([f"%{escape_ilike(ch_dec)}%", f"%{escape_ilike(ch_no_ext)}%"])

        search_cols = [c for c in ["MapDescription", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "Payload", "ExecutableInfo", "UserName", "Computer", "Provider", "Channel", "SourceFile"] if c in col_names]
        if search and search.strip() and search_cols:
            s_term = f"%{escape_ilike(search.strip())}%"
            where_clauses.append("(" + " OR ".join([f"CAST({col} AS VARCHAR) ILIKE ? ESCAPE '\\'" for col in search_cols]) + ")")
            params.extend([s_term] * len(search_cols))
        if kw_terms and search_cols:
            kw_ors: List[str] = []
            for kw in kw_terms:
                k_term = f"%{escape_ilike(kw)}%"
                kw_ors.append("(" + " OR ".join([f"CAST({col} AS VARCHAR) ILIKE ? ESCAPE '\\'" for col in search_cols]) + ")")
                params.extend([k_term] * len(search_cols))
            where_clauses.append("(" + " OR ".join(kw_ors) + ")")

        if (tag_terms or bookmarked_only) and "_row_id" in col_names:
            _ensure_bookmarks_table_canonical(cursor)
            if tag_terms:
                ph = ", ".join(["?"] * len(tag_terms))
                where_clauses.append(f"_row_id IN (SELECT source_row_id FROM bookmarks WHERE source_table = 'raw_evtx' AND tag_name IN ({ph}))")
                params.extend(tag_terms)
            else:
                where_clauses.append("_row_id IN (SELECT source_row_id FROM bookmarks WHERE source_table = 'raw_evtx')")

        ts_col = "TimeCreated" if "TimeCreated" in col_names else None
        if ts_col and dt_from:
            where_clauses.append(f"TRY_CAST({ts_col} AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)")
            params.append(dt_from)
        if ts_col and dt_to:
            where_clauses.append(f"TRY_CAST({ts_col} AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)")
            params.append(dt_to)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        total_count = cursor.execute("SELECT COUNT(*) FROM raw_evtx;").fetchone()[0]
        clean_sort = sort_col if sort_col in col_names else ("TimeCreated" if "TimeCreated" in col_names else col_names[0])
        clean_dir = "DESC" if sort_dir.upper() == "DESC" else "ASC"
        try:
            filtered_count = cursor.execute(f"SELECT COUNT(*) FROM raw_evtx {where_sql};", params).fetchone()[0]
            raw_rows = cursor.execute(
                f"SELECT * FROM raw_evtx {where_sql} ORDER BY {clean_sort} {clean_dir} NULLS LAST LIMIT ? OFFSET ?;",
                params + [limit, offset],
            ).fetchall()
        except duckdb.Error as exc:
            raise HTTPException(status_code=400, detail=f"Invalid event log SQL filter: {exc}")

        return {
            "case_id": case_id,
            "columns": col_names,
            "rows": serialize_rows(col_names, raw_rows),
            "total_count": int(total_count),
            "filtered_count": int(filtered_count),
            "limit": limit,
            "offset": offset,
        }


# ---------------------------------------------------------------------------
# Section 16: Deep Malware & Trellix Stinger / YARA-X Workbench
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/malware/summary")
def get_malware_summary(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_found = {
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }

        stinger_hits = int(cursor.execute("SELECT COUNT(*) FROM artifact_stinger_hits;").fetchone()[0] or 0) if "artifact_stinger_hits" in tables_found else 0
        yara_matches = int(cursor.execute("SELECT COUNT(*) FROM artifact_yara_hits;").fetchone()[0] or 0) if "artifact_yara_hits" in tables_found else 0
        total_detections = (
            int(cursor.execute("SELECT COUNT(*) FROM view_all_malware_detections;").fetchone()[0] or 0)
            if "view_all_malware_detections" in tables_found
            else (stinger_hits + yara_matches)
        )
        heuristics_count = (
            int(cursor.execute(
                "SELECT COUNT(*) FROM artifact_stinger_hits WHERE detection_type ILIKE '%Heuristic%' OR detection_type ILIKE '%Threat%';"
            ).fetchone()[0] or 0)
            if "artifact_stinger_hits" in tables_found
            else 0
        )

        stinger_bin = _cfg.find_stinger_binary()
        rules_dir = _cfg.RULES_DIR
        rule_files = [f.name for f in sorted(rules_dir.glob("**/*.yar*")) if f.is_file() and f.suffix.lower() in [".yar", ".yara"]] if rules_dir.exists() else []

        return {
            "case_id": case_id,
            "total_detections": total_detections,
            "stinger_hits": stinger_hits,
            "yara_matches": yara_matches,
            "heuristics_count": heuristics_count,
            "stinger_installed": stinger_bin is not None,
            "stinger_path": str(stinger_bin) if stinger_bin else None,
            "yara_rules_count": len(rule_files),
            "rule_files": rule_files,
        }


@app.get("/api/cases/{case_id}/malware/rows")
@app.get("/api/cases/{case_id}/malware/hits", include_in_schema=False)
def get_malware_rows(
    case_id: str,
    category: Optional[str] = Query("all"),
    severity: Optional[str] = Query(None),
    search: str = Query(""),
    keywords: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    bookmarked_only: bool = Query(False),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    sort_col: str = Query("_row_id"),
    sort_dir: Literal["ASC", "DESC", "asc", "desc"] = Query("ASC"),
) -> Dict[str, Any]:
    kw_terms = parse_list_param(keywords)
    tag_terms = parse_list_param(tags)
    dt_from = normalize_utc_bound(date_from or start_time, is_end=False)
    dt_to = normalize_utc_bound(date_to or end_time, is_end=True)
    cat_low = (category or "all").strip().lower()

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_found = {
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }

        if "view_all_malware_detections" in tables_found:
            target_table: Optional[str] = "view_all_malware_detections"
        elif cat_low == "yara" and "artifact_yara_hits" in tables_found:
            target_table = "artifact_yara_hits"
        elif cat_low in ("stinger", "heuristics") and "artifact_stinger_hits" in tables_found:
            target_table = "artifact_stinger_hits"
        elif "artifact_yara_hits" in tables_found and "artifact_stinger_hits" in tables_found:
            y_cnt = cursor.execute("SELECT COUNT(*) FROM artifact_yara_hits;").fetchone()[0]
            target_table = "artifact_yara_hits" if y_cnt > 0 else "artifact_stinger_hits"
        elif "artifact_yara_hits" in tables_found:
            target_table = "artifact_yara_hits"
        elif "artifact_stinger_hits" in tables_found:
            target_table = "artifact_stinger_hits"
        else:
            target_table = None

        if not target_table:
            return {"case_id": case_id, "columns": [], "rows": [], "hits": [], "total_count": 0, "filtered_count": 0, "limit": limit, "offset": offset}

        cols_info = cursor.execute(f"DESCRIBE {target_table};").fetchall()
        col_names = [c[0] for c in cols_info]

        where_clauses: List[str] = []
        params: List[Any] = []

        if cat_low == "stinger" and "engine" in col_names:
            where_clauses.append("engine ILIKE '%Stinger%'")
        elif cat_low == "yara" and "engine" in col_names:
            where_clauses.append("engine ILIKE '%YARA%'")
        elif cat_low == "heuristics" and "detection_type" in col_names:
            where_clauses.append("(detection_type ILIKE '%Heuristic%' OR detection_type ILIKE '%Threat%')")

        if severity and severity.strip() and "severity" in col_names:
            where_clauses.append("COALESCE(severity, '') ILIKE ? ESCAPE '\\'")
            params.append(f"%{escape_ilike(severity.strip())}%")

        searchable = [
            c for c in ["file_name", "file_path", "sha256", "detection_name", "threat_name", "malware_name", "rule_name", "description", "details"]
            if c in col_names
        ]
        if search and search.strip() and searchable:
            s_term = f"%{escape_ilike(search.strip())}%"
            where_clauses.append("(" + " OR ".join([f"CAST({c} AS VARCHAR) ILIKE ? ESCAPE '\\'" for c in searchable]) + ")")
            params.extend([s_term] * len(searchable))
        if kw_terms and searchable:
            kw_ors = []
            for kw in kw_terms:
                k_term = f"%{escape_ilike(kw)}%"
                kw_ors.append("(" + " OR ".join([f"CAST({c} AS VARCHAR) ILIKE ? ESCAPE '\\'" for c in searchable]) + ")")
                params.extend([k_term] * len(searchable))
            where_clauses.append("(" + " OR ".join(kw_ors) + ")")

        if (tag_terms or bookmarked_only) and "_row_id" in col_names:
            _ensure_bookmarks_table_canonical(cursor)
            src_tbl_col = (
                "table_name"
                if "table_name" in col_names
                else ("source_table" if "source_table" in col_names else None)
            )
            if target_table == "view_all_malware_detections" and src_tbl_col and "source_row_id" in col_names:
                if tag_terms:
                    ph = ", ".join(["?"] * len(tag_terms))
                    where_clauses.append(
                        f"(EXISTS (SELECT 1 FROM bookmarks b WHERE b.source_table = {src_tbl_col} AND b.source_row_id = TRY_CAST(source_row_id AS BIGINT) AND b.tag_name IN ({ph})) "
                        f"OR EXISTS (SELECT 1 FROM bookmarks b WHERE b.source_table = 'view_all_malware_detections' AND b.source_row_id = TRY_CAST(_row_id AS BIGINT) AND b.tag_name IN ({ph})))"
                    )
                    params.extend(tag_terms + tag_terms)
                else:
                    where_clauses.append(
                        f"(EXISTS (SELECT 1 FROM bookmarks b WHERE b.source_table = {src_tbl_col} AND b.source_row_id = TRY_CAST(source_row_id AS BIGINT)) "
                        "OR EXISTS (SELECT 1 FROM bookmarks b WHERE b.source_table = 'view_all_malware_detections' AND b.source_row_id = TRY_CAST(_row_id AS BIGINT)))"
                    )
            else:
                if tag_terms:
                    ph = ", ".join(["?"] * len(tag_terms))
                    where_clauses.append(
                        f"EXISTS (SELECT 1 FROM bookmarks b WHERE b.source_table = ? AND b.source_row_id = TRY_CAST(_row_id AS BIGINT) AND b.tag_name IN ({ph}))"
                    )
                    params.extend([target_table] + tag_terms)
                else:
                    where_clauses.append(
                        "EXISTS (SELECT 1 FROM bookmarks b WHERE b.source_table = ? AND b.source_row_id = TRY_CAST(_row_id AS BIGINT))"
                    )
                    params.append(target_table)

        ts_col = "scanned_at" if "scanned_at" in col_names else ("detected_at" if "detected_at" in col_names else None)
        if ts_col and dt_from:
            where_clauses.append(f"TRY_CAST({ts_col} AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)")
            params.append(dt_from)
        if ts_col and dt_to:
            where_clauses.append(f"TRY_CAST({ts_col} AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)")
            params.append(dt_to)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        total_count = int(cursor.execute(f"SELECT COUNT(*) FROM {target_table};").fetchone()[0] or 0)
        filtered_count = int(cursor.execute(f"SELECT COUNT(*) FROM {target_table} {where_sql};", params).fetchone()[0] or 0)

        clean_sort = sort_col if sort_col in col_names else col_names[0]
        clean_dir = "DESC" if sort_dir.upper() == "DESC" else "ASC"

        raw_rows = cursor.execute(
            f"SELECT * FROM {target_table} {where_sql} ORDER BY {clean_sort} {clean_dir} NULLS LAST LIMIT ? OFFSET ?;",
            params + [limit, offset],
        ).fetchall()
        serialized = serialize_rows(col_names, raw_rows)

        return {
            "case_id": case_id,
            "columns": col_names,
            "rows": serialized,
            "hits": serialized,
            "total_count": total_count,
            "filtered_count": filtered_count,
            "limit": limit,
            "offset": offset,
        }


_MALWARE_SCAN_LOCKS_GUARD = threading.Lock()
_MALWARE_SCAN_LOCKS: Dict[str, threading.Lock] = {}


def _get_malware_scan_lock(case_id: str) -> threading.Lock:
    with _MALWARE_SCAN_LOCKS_GUARD:
        lk = _MALWARE_SCAN_LOCKS.get(case_id)
        if lk is None:
            lk = threading.Lock()
            _MALWARE_SCAN_LOCKS[case_id] = lk
        return lk


@app.post("/api/cases/{case_id}/malware/scan")
def trigger_malware_scan(case_id: str, req: MalwareScanRequest) -> Dict[str, Any]:
    global FileEnrichmentEngine
    scan_lock = _get_malware_scan_lock(case_id)
    with scan_lock:
        was_rw = DuckDBManager.has_rw_connection(case_id)
        # Phase 1: Pre-scan check & targeted clear under DuckDBManager lock (never held across engine.run!)
        with DuckDBManager.get_lock(case_id):
            conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
            cur = conn.cursor()
            pre_tables = {
                r[0]
                for r in cur.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            if req.enable_yara and "artifact_yara_hits" in pre_tables:
                cur.execute("DELETE FROM artifact_yara_hits;")
            if req.enable_stinger and "artifact_stinger_hits" in pre_tables:
                cur.execute("DELETE FROM artifact_stinger_hits;")
            if req.enable_ocr:
                for ocr_tbl in ("artifact_ocr_results", "media_ocr_results"):
                    if ocr_tbl in pre_tables:
                        cur.execute(f"DELETE FROM {ocr_tbl};")

        # Phase 2: Run FileEnrichmentEngine OUTSIDE DuckDBManager.get_lock(case_id)
        if FileEnrichmentEngine is None:
            from backend.orchestrator.enrichment import FileEnrichmentEngine as _FEE
            FileEnrichmentEngine = _FEE
        engine = FileEnrichmentEngine(case_id=case_id)
        scan_kwargs = _filter_kwargs_for_callable(
            engine.run,
            {
                "enable_yara": req.enable_yara,
                "enable_ocr": req.enable_ocr,
                "enable_stinger": req.enable_stinger,
                "enable_ioc": req.enable_stinger,
            },
        )
        scan_results = engine.run(**scan_kwargs)

        # Phase 3: Post-scan bogus Stinger self-log purge, natural-key dedupe, and artifact_registry sync
        with DuckDBManager.get_lock(case_id):
            conn = ensure_case_exists(case_id, auto_create=False, read_only=False)
            cur = conn.cursor()
            post_tables = {
                r[0]
                for r in cur.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            if "artifact_stinger_hits" in post_tables:
                cur.execute(
                    """
                    DELETE FROM artifact_stinger_hits
                    WHERE LOWER(COALESCE(file_path, '')) LIKE '%stinger_logs%'
                       OR LOWER(COALESCE(file_name, '')) LIKE 'stinger_scan%.log%'
                       OR LOWER(COALESCE(file_name, '')) LIKE 'stinger_scan%.html%'
                       OR (
                           LOWER(COALESCE(details, '')) LIKE '%infected files: 0%'
                           AND LOWER(COALESCE(malware_name, 'clean')) IN ('', 'clean', 'none', '0')
                       );
                    """
                )
                cur.execute(
                    """
                    DELETE FROM artifact_stinger_hits
                    WHERE rowid NOT IN (
                        SELECT MIN(rowid)
                        FROM artifact_stinger_hits
                        GROUP BY COALESCE(file_path, ''), COALESCE(malware_name, ''), COALESCE(detection_type, '')
                    );
                    """
                )
            if "artifact_yara_hits" in post_tables:
                cur.execute(
                    """
                    DELETE FROM artifact_yara_hits
                    WHERE LOWER(COALESCE(file_path, '')) LIKE '%stinger_logs%';
                    """
                )
                cur.execute(
                    """
                    DELETE FROM artifact_yara_hits
                    WHERE rowid NOT IN (
                        SELECT MIN(rowid)
                        FROM artifact_yara_hits
                        GROUP BY COALESCE(file_path, ''), COALESCE(rule_name, ''), COALESCE(pattern_identifier, ''), COALESCE(match_offset, -1)
                    );
                    """
                )
            if "file_enrichment" in post_tables:
                cur.execute(
                    """
                    DELETE FROM file_enrichment
                    WHERE LOWER(COALESCE(file_path, '')) LIKE '%stinger_logs%';
                    """
                )
                cur.execute(
                    """
                    DELETE FROM file_enrichment
                    WHERE rowid NOT IN (
                        SELECT MIN(rowid)
                        FROM file_enrichment
                        GROUP BY COALESCE(file_path, '')
                    );
                    """
                )
            if "artifact_registry" in post_tables:
                cur.execute(
                    "DELETE FROM artifact_registry WHERE artifact_id IN ('malware_yara', 'malware_stinger');"
                )
                now_ts = datetime.now(timezone.utc).replace(tzinfo=None)
                for art_id, cat_name, disp_name, tbl_name, src_tool in (
                    ("malware_yara_hits", "MALWARE & YARA", "YARA Rule Hits", "artifact_yara_hits", "YARA-X"),
                    ("malware_stinger_hits", "MALWARE & YARA", "Trellix Stinger & PE Threat Hits", "artifact_stinger_hits", "TrellixStingerEngine"),
                    ("malware_all_detections", "MALWARE & YARA", "All Malware & Threat Detections", "view_all_malware_detections", "MalwareScanner"),
                ):
                    if tbl_name in post_tables:
                        cnt = int(cur.execute(f"SELECT COUNT(*) FROM {tbl_name};").fetchone()[0] or 0)
                        if cnt > 0:
                            cur.execute(
                                """
                                INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT (artifact_id) DO UPDATE SET
                                    category = EXCLUDED.category,
                                    display_name = EXCLUDED.display_name,
                                    table_name = EXCLUDED.table_name,
                                    source_tool = EXCLUDED.source_tool,
                                    row_count = EXCLUDED.row_count,
                                    last_updated = ?;
                                """,
                                [art_id, cat_name, disp_name, tbl_name, src_tool, cnt, now_ts, now_ts],
                            )
                        else:
                            cur.execute("DELETE FROM artifact_registry WHERE artifact_id = ?;", [art_id])
            _release_transient_rw_if_idle(case_id, was_rw)

        summary = get_malware_summary(case_id)
        return {
            "status": "success",
            "case_id": case_id,
            "results": scan_results,
            "summary": summary,
        }


@app.post("/api/cases/{case_id}/malware/rules/upload")
async def upload_yara_rule(case_id: str, file: UploadFile = File(...)) -> Dict[str, Any]:
    fname = Path(file.filename or "").name
    if not (fname.endswith(".yar") or fname.endswith(".yara")):
        raise HTTPException(status_code=400, detail="Uploaded rule file must have a .yar or .yara extension.")

    content = await file.read()
    rule_str = content.decode("utf-8", errors="replace")

    try:
        import yara_x
        compiler = yara_x.Compiler()
        compiler.add_source(rule_str)
        compiler.build()
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"YARA syntax compilation error: {err}")

    rules_dir = _cfg.RULES_DIR
    rules_dir.mkdir(parents=True, exist_ok=True)
    target_rule_file = (rules_dir / fname).resolve()
    if not target_rule_file.is_relative_to(rules_dir.resolve()):
        raise HTTPException(status_code=400, detail="Invalid YARA rule filename.")
    target_rule_file.write_text(rule_str, encoding="utf-8")

    return {
        "status": "success",
        "message": f"YARA rule '{fname}' uploaded and compiled successfully.",
        "path": str(target_rule_file),
    }


def _render_fallback_case_html_report(case_id: str) -> str:
    """Self-contained XSS-safe HTML5 forensic report fallback directly from DuckDB."""
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cur = conn.cursor()
        tables = {
            r[0]
            for r in cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        meta: Dict[str, str] = {}
        if "case_metadata" in tables:
            for k, v in cur.execute("SELECT key, value FROM case_metadata;").fetchall():
                if k is not None:
                    meta[str(k)] = str(v or "")

        reg_rows = (
            cur.execute(
                "SELECT category, display_name, table_name, COALESCE(row_count, 0) FROM artifact_registry WHERE COALESCE(row_count, 0) > 0 ORDER BY category ASC, row_count DESC;"
            ).fetchall()
            if "artifact_registry" in tables
            else []
        )
        bm_rows = []
        if "bookmarks" in tables:
            bm_cols = {r[1] for r in cur.execute("PRAGMA table_info('bookmarks');").fetchall()}
            if "source_table" in bm_cols:
                bm_rows = cur.execute(
                    "SELECT tag_name, source_table, source_row_id, COALESCE(examiner_notes, ''), CAST(created_at AS VARCHAR) FROM bookmarks ORDER BY created_at DESC LIMIT 200;"
                ).fetchall()
        kw_rows = (
            cur.execute(
                "SELECT keyword, COALESCE(hit_count, 0), COALESCE(source_file, '') FROM case_keywords ORDER BY hit_count DESC LIMIT 100;"
            ).fetchall()
            if "case_keywords" in tables
            else []
        )

    esc = lambda v: html.escape(str(v if v is not None else ""), quote=True)
    case_title = esc(meta.get("case_name") or case_id)
    examiner = esc(meta.get("examiner") or "N/A")
    case_num = esc(meta.get("case_number") or "N/A")
    src_path = esc(meta.get("source_path") or "N/A")
    notes_val = esc(meta.get("notes") or "")
    gen_utc = esc(datetime.now(timezone.utc).isoformat())

    reg_tr = "".join(
        f"<tr><td>{esc(r[0])}</td><td>{esc(r[1])}</td><td><code>{esc(r[2])}</code></td><td>{int(r[3] or 0)}</td></tr>"
        for r in reg_rows
    ) or "<tr><td colspan='4'>No populated artifacts recorded.</td></tr>"
    bm_tr = "".join(
        f"<tr><td>{esc(b[0])}</td><td><code>{esc(b[1])}</code> #{esc(b[2])}</td><td>{esc(b[3])}</td><td>{esc(b[4])}</td></tr>"
        for b in bm_rows
    ) or "<tr><td colspan='4'>No bookmarks recorded.</td></tr>"
    kw_tr = "".join(
        f"<tr><td><code>{esc(k[0])}</code></td><td>{int(k[1] or 0)}</td><td>{esc(k[2])}</td></tr>"
        for k in kw_rows
    ) or "<tr><td colspan='3'>No keywords configured.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>WFT Forensic Report — {case_title}</title>
<style>
body {{ font-family: Segoe UI, system-ui, sans-serif; margin: 2rem; color: #0f172a; background: #f8fafc; }}
h1, h2 {{ color: #1e293b; }}
.card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
th, td {{ border: 1px solid #e2e8f0; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; }}
th {{ background: #f1f5f9; }}
</style>
</head>
<body>
<h1>Windows Forensic Toolkit (WFT) — Case Report: {case_title}</h1>
<div class="card">
  <p><strong>Case ID:</strong> {esc(case_id)} | <strong>Case Number:</strong> {case_num} | <strong>Examiner:</strong> {examiner}</p>
  <p><strong>Source Evidence:</strong> <code>{src_path}</code></p>
  <p><strong>Notes:</strong> {notes_val}</p>
  <p><strong>Generated (UTC):</strong> {gen_utc}</p>
</div>
<div class="card"><h2>Populated Artifacts</h2><table><thead><tr><th>Category</th><th>Artifact</th><th>Table</th><th>Rows</th></tr></thead><tbody>{reg_tr}</tbody></table></div>
<div class="card"><h2>Examiner Bookmarks</h2><table><thead><tr><th>Tag</th><th>Source</th><th>Notes</th><th>Created</th></tr></thead><tbody>{bm_tr}</tbody></table></div>
<div class="card"><h2>Keyword Search Summary</h2><table><thead><tr><th>Keyword</th><th>Hits</th><th>Source</th></tr></thead><tbody>{kw_tr}</tbody></table></div>
</body>
</html>"""


@app.get("/api/cases/{case_id}/report/html", summary="Generate Portable HTML Forensic Case Report")
def export_case_report_html(case_id: str, download: bool = Query(False)):
    clean_cid = (case_id or "").strip()
    if not clean_cid or ".." in clean_cid or "/" in clean_cid or "\\" in clean_cid:
        raise HTTPException(status_code=404, detail="Case not found")
    case_dir = get_case_dir(clean_cid, create_if_missing=False)
    if not case_dir.is_dir() or not (case_dir / "case.duckdb").is_file():
        raise HTTPException(status_code=404, detail=f"Case '{clean_cid}' database does not exist.")

    html_content: Optional[str] = None
    try:
        from backend.orchestrator.report_generator import generate_case_html_report
        generated = generate_case_html_report(clean_cid)
        if isinstance(generated, str) and "<html" in generated.lower():
            html_content = generated
    except (ImportError, SyntaxError, Exception) as rep_err:
        print(f"[report/html] Falling back to built-in DuckDB HTML renderer for '{clean_cid}': {rep_err}")

    if not html_content:
        html_content = _render_fallback_case_html_report(clean_cid)

    headers: Dict[str, str] = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{clean_cid}_forensic_report.html"'
    return HTMLResponse(content=html_content, status_code=200, headers=headers)


# ---------------------------------------------------------------------------
# Static Frontend SPA Serving (dist fallback)
# ---------------------------------------------------------------------------
dist_dir = (
    (BUNDLE_DIR / "frontend" / "dist").resolve()
    if (BUNDLE_DIR / "frontend" / "dist").exists()
    else (BASE_DIR / "frontend" / "dist").resolve()
)
if dist_dir.exists():
    from fastapi.staticfiles import StaticFiles

    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="frontend_static_assets")


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_frontend_spa(full_path: str, request: Request):
    raw_path_bytes = request.scope.get("raw_path") or b""
    raw_path_str = raw_path_bytes.decode("latin-1", errors="ignore") if isinstance(raw_path_bytes, (bytes, bytearray)) else ""
    scope_path_str = str(request.scope.get("path") or "")
    unquoted_once = urllib.parse.unquote(full_path or "")
    if (
        (full_path or "").startswith("/")
        or unquoted_once.startswith("/")
        or urllib.parse.unquote(unquoted_once).startswith("/")
        or scope_path_str.startswith("//")
        or raw_path_str.startswith("//")
        or urllib.parse.unquote(raw_path_str).startswith("//")
    ):
        raise HTTPException(status_code=403, detail="Path traversal blocked")
    for probe in (full_path or "", unquoted_once):
        if (
            "\x00" in probe
            or "\\" in probe
            or ":" in probe
            or probe.startswith("//")
            or ".." in probe.replace("\\", "/").split("/")
        ):
            raise HTTPException(status_code=403, detail="Path traversal blocked")
    raw_low = raw_path_str.lower()
    if "%5c" in raw_low or "%2e%2e" in raw_low or "%00" in raw_low:
        raise HTTPException(status_code=403, detail="Path traversal blocked")

    if full_path == "api" or full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
        raise HTTPException(status_code=404, detail="Not Found")

    if not dist_dir.exists():
        raise HTTPException(status_code=404, detail="Frontend file not found")

    dist_resolved = dist_dir.resolve()
    try:
        cand_resolved = (dist_dir / full_path.lstrip("/\\")).resolve()
    except (OSError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not cand_resolved.is_relative_to(dist_resolved):
        raise HTTPException(status_code=403, detail="Path traversal blocked")
    if full_path.strip("/") and cand_resolved.is_relative_to(dist_resolved) and cand_resolved.is_file():
        extra_headers = {}
        if cand_resolved.suffix.lower() in (".html", ".htm", ".json"):
            extra_headers = {
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        return FileResponse(cand_resolved, headers=extra_headers)
    index_file = dist_resolved / "index.html"
    if index_file.is_file():
        return FileResponse(
            index_file,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    raise HTTPException(status_code=404, detail="Frontend file not found")


if __name__ == "__main__":
    import uvicorn

    print(f"[Windows Forensic Toolkit (WFT) Backend] Starting Uvicorn on {API_HOST}:{API_PORT}...")
    try:
        uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT, reload=False, timeout_keep_alive=600)
    finally:
        os._exit(0)