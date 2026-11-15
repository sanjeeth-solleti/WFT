"""
Windows Forensic Toolkit (WFT) - FastAPI REST Backend
Exposes all Milestone REST endpoints on port 8765 with full CORS,
real-time audit logging, DuckDB query engine, and zero stubs.
"""
import faulthandler
import sys
faulthandler.enable(file=sys.stderr, all_threads=True)

import ctypes
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import duckdb
from backend.security import (
    ForensicSecurityHeadersMiddleware,
    resolve_sandboxed_case_file,
    sanitize_sql_identifier,
    validate_tool_binary_path,
)
from fastapi import BackgroundTasks, Body, FastAPI, File, Form, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
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
    get_table_columns,
    init_case_db,
    query_paginated,
    validate_table_or_column_name,
    get_distinct_column_values,
    scan_keywords_for_case,
)
from backend.orchestrator.enrichment import FileEnrichmentEngine
from backend.parsers.chromium_parser import ChromiumParser
from backend.orchestrator.pipeline import (
    ProcessingPipeline,
    get_job_status,
    run_pipeline,
)

# ---------------------------------------------------------------------------
# FastAPI Application & CORS Configuration
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Windows Forensic Toolkit (WFT) API",
    description="Enterprise Windows Digital Forensics & Incident Response REST API (WFT)",
    version="1.0.0",
)


@app.middleware("http")
async def add_pna_and_cors_headers(request, call_next):
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
    case_name: str = Field(..., description="Human-readable case name")
    source_type: Literal["folder", "live_triage", "image", "directory"] = Field(
        ..., description="Type of evidence source"
    )
    source_path: Optional[str] = Field(None, description="Path to folder or raw disk image")
    target_dir: Optional[str] = Field(None, description="Custom target folder for case DuckDB and evidence staging")
    enable_yara: bool = Field(False, description="Enable YARA-X malware scanning")
    enable_ocr: bool = Field(False, description="Enable RapidOCR text extraction")
    keywords: List[str] = Field(default_factory=list, description="Keywords configured in WFT Process")
    case_id: Optional[str] = Field(None, description="Optional custom case ID")
    run_async: bool = Field(True, description="Run pipeline in background task if True")


class KeywordAddRequest(BaseModel):
    keywords: List[str] = Field(..., description="List of keywords to search")
    source_file: Optional[str] = Field(None, description="Optional source file or label")
    is_regex: bool = Field(False, description="Whether the keywords should be treated as regex patterns")


class BookmarkCreateRequest(BaseModel):
    source_table: str = Field(..., description="Artifact table name where evidence was found")
    source_row_id: int = Field(..., description="Row identifier in source table")
    tag_name: str = Field(..., description="Tag label")
    examiner_notes: Optional[str] = Field(None, description="Examiner notes or analysis findings")
    bookmark_id: Optional[str] = Field(None, description="Optional unique bookmark ID")


class SaveToFolderRequest(BaseModel):
    file_path: Optional[str] = Field(None, description="Path to evidence file or directory")
    is_folder: bool = Field(False, description="Whether the target is a folder")
    table_name: Optional[str] = Field(None, description="Artifact table name")
    row_id: Optional[Union[int, str]] = Field(None, description="Row identifier")


class ToolPathsUpdateRequest(BaseModel):
    paths: Dict[str, str] = Field(..., description="Mapping of environment variable keys to directory or file paths")


class MalwareScanRequest(BaseModel):
    enable_yara: bool = Field(True, description="Enable YARA-X scanning")
    enable_stinger: bool = Field(True, description="Enable Trellix Stinger AV scanning")
    enable_ocr: bool = Field(False, description="Enable RapidOCR scanning")


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
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


def ensure_case_exists(case_id: str, auto_create: bool = False) -> duckdb.DuckDBPyConnection:
    db_path = get_case_db_path(case_id)
    if not db_path.exists():
        if auto_create:
            init_case_db(case_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case '{case_id}' database does not exist at {db_path}.",
            )
    return DuckDBManager.get_connection(case_id, read_only=False)


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

    for cid, cpath_str in get_registered_custom_cases().items():
        cp = Path(cpath_str).resolve()
        path_key = str(cp).lower()
        if cp.is_dir() and (cp / "case.duckdb").exists() and path_key not in seen_paths:
            entries_to_check.append((cid, cp))
            seen_paths.add(path_key)
            seen_cids.add(cid.lower())
            # Also mark the folder's own name as seen so it is never re-added as a second case
            seen_cids.add(cp.name.lower())

    check_dirs = [CASES_DIR]
    tool_cases = (BASE_DIR / "cases").resolve()
    if tool_cases.exists() and tool_cases != CASES_DIR:
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

        if has_db:
            try:
                with DuckDBManager.get_lock(cid):
                    conn = DuckDBManager.get_connection(cid, read_only=False)
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
            except Exception as ex:
                print(f"[API] Warning reading metadata for case {cid}: {ex}")

        # Skip and clean up empty 0-row phantom target folders that are not actively running
        job_state = get_job_status(cid).get("status")
        if total_artifacts == 0 and timeline_count == 0 and job_state != "RUNNING" and cid not in _running_cases:
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


@app.delete("/api/cases/{case_id}", summary="Delete an entire case and its storage cleanly")
def delete_case(case_id: str) -> Dict[str, Any]:
    clean_cid = case_id.strip()
    if not clean_cid:
        raise HTTPException(status_code=400, detail="Invalid case_id")

    try:
        DuckDBManager.close_connection(clean_cid)
    except Exception as ex:
        print(f"[delete_case] Warning closing DuckDB connection for {clean_cid}: {ex}")

    import gc
    gc.collect()

    with _running_cases_lock:
        _running_cases.discard(clean_cid)

    with IMAGE_READ_LOCK:
        _IMAGE_TARGET_CACHE.pop(clean_cid, None)
    try:
        from backend.orchestrator.pipeline import PIPELINE_JOBS
        PIPELINE_JOBS.pop(clean_cid, None)
    except Exception:
        pass

    dirs_to_delete: List[Path] = []
    try:
        primary_dir = get_case_dir(clean_cid, create_if_missing=False)
        if primary_dir and primary_dir.exists() and primary_dir.is_dir():
            dirs_to_delete.append(primary_dir.resolve())
    except Exception:
        pass

    fallback_cases_dir = (CASES_DIR / clean_cid).resolve()
    if fallback_cases_dir.exists() and fallback_cases_dir.is_dir() and fallback_cases_dir not in dirs_to_delete:
        dirs_to_delete.append(fallback_cases_dir)

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

    def _handle_remove_readonly(func, path, exc_info):
        try:
            os.chmod(path, 0o700 if Path(path).is_dir() else 0o600)
            if sys.platform == "win32":
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)
                except Exception:
                    pass
            time.sleep(0.05)
            func(path)
        except Exception as retry_err:
            print(f"[delete_case] Warning removing path '{path}': {retry_err}")

    deleted_paths: List[str] = []
    errors: List[str] = []

    for c_dir in dirs_to_delete:
        try:
            shutil.rmtree(c_dir, onerror=_handle_remove_readonly)
            if not c_dir.exists():
                deleted_paths.append(str(c_dir))
            else:
                errors.append(f"Directory '{c_dir}' could not be deleted")
        except Exception as rm_err:
            errors.append(f"Failed deleting '{c_dir}': {rm_err}")

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
    source_type: str,
    source_path: Optional[str] = None,
    enable_yara: bool = True,
    enable_ocr: bool = False,
    keywords: Optional[List[str]] = None,
    target_dir: Optional[str] = None,
):
    try:
        if target_dir and str(target_dir).strip():
            register_case_dir(case_id, str(target_dir).strip())
        init_case_db(case_id)
        run_pipeline(
            case_id=case_id,
            source_type=source_type,
            source_path=source_path,
            enable_yara=enable_yara,
            enable_ocr=enable_ocr,
            keywords=keywords,
            target_dir=target_dir,
        )
    except Exception as exc:
        print(f"[Pipeline Background Job Error] Case '{case_id}': {exc}")
    finally:
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
    case_id = request.case_id if request.case_id else sanitize_case_id(request.case_name)

    custom_case_path: Optional[Path] = None
    if request.target_dir and request.target_dir.strip():
        clean_target = request.target_dir.strip().strip('"').strip("'").strip()
        if clean_target:
            t_path = Path(clean_target).resolve()
            # Unregister the raw target folder name if it differs from case_id so it never shows as a 0-row case
            if t_path.name.lower() != case_id.lower():
                unregister_case_dir(t_path.name)
            custom_case_path = t_path if t_path.name.lower() == case_id.lower() else (t_path / case_id)
            custom_case_path.mkdir(parents=True, exist_ok=True)
            register_case_dir(case_id, custom_case_path)
    elif request.source_path and request.source_path.strip():
        clean_src = request.source_path.strip().strip('"').strip("'").strip()
        sp = Path(clean_src).resolve()
        if sp.exists():
            base_parent = sp if sp.is_dir() else sp.parent
            custom_case_path = base_parent / case_id if base_parent.name.lower() != case_id.lower() else base_parent
            custom_case_path.mkdir(parents=True, exist_ok=True)
            register_case_dir(case_id, custom_case_path)

    with _running_cases_lock:
        job_status = get_job_status(case_id)
        if case_id in _running_cases or job_status.get("status") == "RUNNING":
            return {
                "status": "RUNNING",
                "case_id": case_id,
                "case_name": request.case_name,
                "message": f"Processing job is already in progress for case '{case_id}'.",
                "progress": job_status.get("progress", 0),
                "current_step": job_status.get("current_step", "Processing evidence..."),
            }
        _running_cases.add(case_id)

    with IMAGE_READ_LOCK:
        _IMAGE_TARGET_CACHE.pop(case_id, None)

    clean_source = request.source_path.strip().strip('"').strip("'").strip() if request.source_path else None

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

        background_tasks.add_task(
            safe_background_pipeline,
            case_id=case_id,
            source_type=request.source_type,
            source_path=clean_source,
            enable_yara=request.enable_yara,
            enable_ocr=request.enable_ocr,
            keywords=request.keywords,
            target_dir=str(custom_case_path) if custom_case_path else None,
        )
        return {
            "status": "RUNNING",
            "case_id": case_id,
            "case_name": request.case_name,
            "message": f"Processing job initiated in background for case '{case_id}'.",
        }
    else:
        try:
            init_case_db(case_id)
            pipeline_result = run_pipeline(
                case_id=case_id,
                source_type=request.source_type,
                source_path=clean_source,
                enable_yara=request.enable_yara,
                enable_ocr=request.enable_ocr,
                keywords=request.keywords,
                target_dir=str(custom_case_path) if custom_case_path else None,
            )
            return {
                "status": "SUCCESS",
                "case_id": case_id,
                "case_name": request.case_name,
                "message": f"Processing completed successfully for case '{case_id}'.",
                "result": pipeline_result,
            }
        finally:
            with _running_cases_lock:
                _running_cases.discard(case_id)


@app.get("/api/cases/{case_id}/status", summary="Get case processing status and audit logs")
def get_case_status(case_id: str) -> Dict[str, Any]:
    status_info = get_job_status(case_id)
    db_path = get_case_db_path(case_id)

    logs_list = []
    if db_path.exists():
        try:
            with DuckDBManager.get_lock(case_id):
                conn = DuckDBManager.get_connection(case_id, read_only=False)
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
        except Exception as ex:
            print(f"[API] Error reading processing_logs for {case_id}: {ex}")

    return {
        "case_id": case_id,
        "status": status_info.get("status", "UNKNOWN"),
        "progress": status_info.get("progress", 0),
        "current_step": status_info.get("current_step", ""),
        "error": status_info.get("error"),
        "start_time": status_info.get("start_time"),
        "end_time": status_info.get("end_time"),
        "logs": logs_list,
        "total_logs": len(logs_list),
    }


# ---------------------------------------------------------------------------
# 3. Artifact Registry & Dashboard
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/registry", summary="Get populated artifact registry and super-counts")
def get_artifact_registry(
    case_id: str,
    hide_empty: bool = False,
    force_sync: bool = False,
) -> Dict[str, Any]:
    status_info = get_job_status(case_id)
    pipeline_running = status_info.get("status") == "RUNNING"

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        if force_sync and not pipeline_running:
            try:
                from backend.db.schema import sync_artifact_registry_counts
                sync_artifact_registry_counts(conn, case_id=case_id)
            except Exception as sync_ex:
                print(f"[API] Warning synchronizing artifact registry: {sync_ex}")
        else:
            try:
                reg_count = cursor.execute("SELECT COUNT(*) FROM artifact_registry;").fetchone()[0]
                if reg_count == 0 and not pipeline_running:
                    from backend.db.schema import sync_artifact_registry_counts
                    sync_artifact_registry_counts(conn, case_id=case_id)
            except Exception as sync_ex:
                print(f"[API] Notice checking artifact registry: {sync_ex}")

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
            raw_artifacts = cursor.execute(query).fetchall()

        tl_row = cursor.execute("SELECT COUNT(*) FROM master_timeline;").fetchone()
        timeline_total = tl_row[0] if tl_row else 0
        ent_row = cursor.execute("SELECT COUNT(*) FROM entity_connections;").fetchone()
        connections_total = ent_row[0] if ent_row else 0

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

    seen_tables = set()
    artifacts_data = []
    for art in raw_artifacts_data:
        tname = art.get("table_name")
        rc = art.get("row_count", 0)
        disp = str(art.get("display_name", ""))
        if tname in ("parsed_media_exif", "parsed_documents_metadata", "view_all_malware_detections") or "(Combined)" in disp:
            continue
        if rc > 0 and tname and tname not in seen_tables:
            seen_tables.add(tname)
            artifacts_data.append(art)

    CANONICAL_CATEGORIES = [
        "REFINED RESULTS",
        "WEB RELATED",
        "CHAT",
        "EMAIL",
        "CLOUD",
        "MEDIA",
        "DOCUMENTS",
        "EVENT LOGS",
        "OPERATING SYSTEM",
        "MALWARE & YARA",
    ]

    grouped_cats: Dict[str, List[Dict[str, Any]]] = {}
    for art in artifacts_data:
        cat = art.get("category", "OPERATING SYSTEM")
        if cat not in grouped_cats:
            grouped_cats[cat] = []
        grouped_cats[cat].append(art)

    category_tree = []
    for cat_name in CANONICAL_CATEGORIES:
        cat_arts = grouped_cats.pop(cat_name, [])
        cat_arts = [a for a in cat_arts if a.get("row_count", 0) > 0]
        cat_total = sum(a["row_count"] for a in cat_arts)
        if cat_total > 0 and len(cat_arts) > 0:
            category_tree.append({
                "category": cat_name,
                "total_category_rows": cat_total,
                "artifacts": cat_arts,
            })

    for cat_name, cat_arts in sorted(grouped_cats.items()):
        cat_arts = [a for a in cat_arts if a.get("row_count", 0) > 0]
        cat_total = sum(a["row_count"] for a in cat_arts)
        if cat_total > 0 and len(cat_arts) > 0:
            category_tree.append({
                "category": cat_name,
                "total_category_rows": cat_total,
                "artifacts": cat_arts,
            })

    all_evidence_total = sum(a["row_count"] for a in artifacts_data)

    return {
        "case_id": case_id,
        "all_evidence_total": all_evidence_total,
        "all_evidence": {
            "display_name": "ALL EVIDENCE",
            "total_count": all_evidence_total,
        },
        "categories": category_tree,
        "artifacts": artifacts_data,
        "total_artifact_categories": len(category_tree),
        "total_artifact_tables": len(artifacts_data),
        "timeline_total": timeline_total,
        "connections_total": connections_total,
    }


@app.get("/api/cases/{case_id}/dashboard", summary="WFT Places to Start Case Dashboard")
def get_case_dashboard(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        reg_rows = cursor.execute("""
            SELECT category, display_name, table_name, row_count
            FROM artifact_registry
            WHERE row_count > 0
            ORDER BY row_count DESC;
        """).fetchall()

        category_counts: Dict[str, int] = {}
        total_artifact_rows = 0
        top_artifacts = []
        seen_tables = set()

        for cat, dname, tname, cnt in reg_rows:
            if tname in seen_tables or tname in ("view_all_malware_detections", "parsed_media_exif", "parsed_documents_metadata"):
                continue
            seen_tables.add(tname)
            total_artifact_rows += cnt
            category_counts[cat] = category_counts.get(cat, 0) + cnt
            if len(top_artifacts) < 8:
                top_artifacts.append({"category": cat, "display_name": dname, "table_name": tname, "row_count": cnt})

        categories_list = [
            {
                "category": cat,
                "count": cnt,
                "percentage": round((cnt / total_artifact_rows * 100), 1) if total_artifact_rows > 0 else 0,
            }
            for cat, cnt in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        timeline_total = cursor.execute("SELECT COUNT(*) FROM master_timeline;").fetchone()[0]
        connections_total = cursor.execute("SELECT COUNT(*) FROM entity_connections;").fetchone()[0]

        top_users = [
            {"value": r[0], "count": r[1]}
            for r in cursor.execute("""
                SELECT entity_value, COUNT(*) as cnt
                FROM entity_connections
                WHERE entity_type IN ('USER_ACCOUNT', 'IDENTIFIER')
                GROUP BY entity_value
                ORDER BY cnt DESC
                LIMIT 5;
            """).fetchall()
        ]

        top_domains = [
            {"value": r[0], "count": r[1]}
            for r in cursor.execute("""
                SELECT entity_value, COUNT(*) as cnt
                FROM entity_connections
                WHERE entity_type IN ('DOMAIN', 'URL')
                GROUP BY entity_value
                ORDER BY cnt DESC
                LIMIT 5;
            """).fetchall()
        ]

        top_executables = [
            {"value": r[0], "count": r[1]}
            for r in cursor.execute("""
                SELECT entity_value, COUNT(*) as cnt
                FROM entity_connections
                WHERE entity_type = 'EXECUTABLE'
                GROUP BY entity_value
                ORDER BY cnt DESC
                LIMIT 5;
            """).fetchall()
        ]

        yara_hits = []
        tables = [t[0] for t in cursor.execute("SHOW TABLES;").fetchall()]
        if "artifact_yara_hits" in tables:
            hits_raw = cursor.execute("""
                SELECT rule_name, file_name, file_path, COUNT(*) AS matched_strings_count, MAX(scanned_at)
                FROM artifact_yara_hits
                GROUP BY rule_name, file_name, file_path
                ORDER BY matched_strings_count DESC
                LIMIT 10;
            """).fetchall()
            for r in hits_raw:
                yara_hits.append({
                    "rule_name": r[0],
                    "file_name": r[1],
                    "file_path": r[2],
                    "match_count": r[3],
                    "scanned_at": str(r[4]),
                })

        bookmarks_list = []
        if "bookmarks" in tables:
            b_raw = cursor.execute("""
                SELECT bookmark_id, source_table, source_row_id, tag_name, examiner_notes, created_at
                FROM bookmarks
                ORDER BY created_at DESC
                LIMIT 10;
            """).fetchall()
            for r in b_raw:
                bookmarks_list.append({
                    "bookmark_id": r[0],
                    "source_table": r[1],
                    "source_row_id": r[2],
                    "tag_name": r[3],
                    "examiner_notes": r[4],
                    "created_at": str(r[5]),
                })

    case_db_path = get_case_db_path(case_id)
    db_size = case_db_path.stat().st_size if case_db_path.exists() else 0

    return {
        "case_id": case_id,
        "db_size_bytes": db_size,
        "total_artifact_rows": total_artifact_rows,
        "timeline_total": timeline_total,
        "connections_total": connections_total,
        "categories": categories_list,
        "top_artifacts": top_artifacts,
        "top_users": top_users,
        "top_domains": top_domains,
        "top_executables": top_executables,
        "yara_hits": yara_hits,
        "bookmarks": bookmarks_list,
    }


# ---------------------------------------------------------------------------
# 4. Table Data Grid & Column Distinct Values
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/table/{table_name}", summary="Paginated data grid with dynamic search and column filters")
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
    tags: Optional[str] = Query(None),
) -> Dict[str, Any]:
    clean_table = validate_table_or_column_name(table_name)

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables_found = [
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        ]
        if clean_table not in tables_found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Table '{clean_table}' does not exist in case '{case_id}'.",
            )

    paginated_result = query_paginated(
        case_id=case_id,
        table_name=clean_table,
        limit=limit,
        offset=offset,
        search=search,
        sort_col=sort_col,
        sort_dir=sort_dir,
        column_filters=column_filters,
        start_time=start_time,
        end_time=end_time,
        tags=tags,
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


@app.get(
    "/api/cases/{case_id}/table/{table_name}/distinct/{column_name}",
    summary="Distinct column values with occurrence counts",
)
def get_table_column_distinct(
    case_id: str,
    table_name: str,
    column_name: str,
) -> List[Dict[str, Any]]:
    clean_table = validate_table_or_column_name(table_name)
    validate_table_or_column_name(column_name)

    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        tables_found = [
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        ]
        if clean_table not in tables_found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Table '{clean_table}' does not exist in case '{case_id}'.",
            )

        try:
            distinct_rows = get_distinct_column_values(case_id, clean_table, column_name, limit=500)
        except ValueError as err:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err))
    return [{"value": serialize_db_value(item["value"]), "count": item["count"]} for item in distinct_rows]


# ---------------------------------------------------------------------------
# 4.2 RegRipper Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/regripper/plugins", summary="List all RegRipper plugins parsed for the case")
def get_regripper_plugins(
    case_id: str,
    hive: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
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
            return {"case_id": case_id, "total": 0, "plugins": []}

        where_clauses = []
        params = []
        if hive and hive.strip():
            where_clauses.append("(hive_name ILIKE ? OR hive_type ILIKE ?)")
            h_pat = f"%{hive.strip()}%"
            params.extend([h_pat, h_pat])
        if category and category.strip():
            where_clauses.append("category ILIKE ?")
            params.append(f"%{category.strip()}%")
        if search and search.strip():
            s_pat = f"%{search.strip()}%"
            where_clauses.append(
                "(plugin_name ILIKE ? OR description ILIKE ? OR summary_line ILIKE ? OR report_text ILIKE ?)"
            )
            params.extend([s_pat, s_pat, s_pat, s_pat])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        query = f"""
            SELECT _row_id, plugin_name, plugin_version, hive_name, hive_type,
                   category, mitre_attack, description, summary_line, output_lines_count, parsed_at
            FROM raw_regripper
            {where_sql}
            ORDER BY hive_type ASC, plugin_name ASC;
        """
        rows = cursor.execute(query, params).fetchall()
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
        return {"case_id": case_id, "total": len(plugins), "plugins": plugins}


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
            where_sql += " AND (hive_name ILIKE ? OR hive_type ILIKE ?)"
            h_pat = f"%{hive.strip()}%"
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
    case_dir = get_case_dir(case_id)
    runner = RegRipperRunner(case_id=case_id, case_dir=case_dir)
    return runner.run()


# ---------------------------------------------------------------------------
# 5. Chronological Super-Timeline
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/timeline", summary="Chronological super-timeline with histogram")
def get_master_timeline(
    case_id: str,
    limit: int = Query(1000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    search: str = Query(""),
    category: str = Query(""),
    start_time: str = Query(""),
    end_time: str = Query(""),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        base_guard = "timestamp_utc IS NOT NULL AND timestamp_utc > '1990-01-01'::TIMESTAMP AND timestamp_utc < '2099-01-01'::TIMESTAMP"
        total_count = cursor.execute(f"SELECT COUNT(*) FROM master_timeline WHERE {base_guard};").fetchone()[0]

        where_parts = [base_guard]
        params: List[Any] = []

        if category and category.strip():
            cat_clean = category.strip()
            if cat_clean.upper() in ["EVENT LOGS", "EVENT_LOGS", "LOGS"]:
                where_parts.append("(category ILIKE 'EVENT LOGS' OR category ILIKE 'Event Logs')")
            else:
                where_parts.append("(category ILIKE ? OR category = ?)")
                params.extend([cat_clean, cat_clean])

        if start_time and start_time.strip():
            st_val = start_time.strip()
            if len(st_val) == 10:
                st_val += " 00:00:00"
            where_parts.append("timestamp_utc >= TRY_CAST(? AS TIMESTAMP)")
            params.append(st_val)

        if end_time and end_time.strip():
            et_val = end_time.strip()
            if len(et_val) == 10:
                et_val += " 23:59:59"
            where_parts.append("timestamp_utc <= TRY_CAST(? AS TIMESTAMP)")
            params.append(et_val)

        if search and search.strip():
            term = f"%{search.strip()}%"
            where_parts.append(
                """(
                    primary_entity ILIKE ? OR
                    secondary_entity ILIKE ? OR
                    summary ILIKE ? OR
                    artifact_name ILIKE ? OR
                    timestamp_type ILIKE ? OR
                    source_file ILIKE ?
                )"""
            )
            params.extend([term] * 6)

        where_sql = f"WHERE {' AND '.join(where_parts)}"
        filtered_count = cursor.execute(f"SELECT COUNT(*) FROM master_timeline {where_sql};", params).fetchone()[0]

        timeline_cols = [
            "timeline_id",
            "timestamp_utc",
            "timestamp_type",
            "category",
            "artifact_name",
            "primary_entity",
            "secondary_entity",
            "summary",
            "source_table",
            "source_row_id",
            "source_file",
        ]
        fetch_sql = f"""
            SELECT {', '.join(timeline_cols)}
            FROM master_timeline
            {where_sql}
            ORDER BY timestamp_utc DESC
            LIMIT ? OFFSET ?;
        """
        raw_events = cursor.execute(fetch_sql, params + [limit, offset]).fetchall()
        serialized_events = serialize_rows(timeline_cols, raw_events)

        hist_sql = f"""
            SELECT CAST(DATE_TRUNC('day', timestamp_utc) AS VARCHAR) AS day_bucket,
                   COUNT(*) AS event_count
            FROM master_timeline
            {where_sql}
            GROUP BY DATE_TRUNC('day', timestamp_utc)
            ORDER BY DATE_TRUNC('day', timestamp_utc) ASC;
        """
        raw_hist = cursor.execute(hist_sql, params).fetchall()
        histogram = [{"day": row[0], "count": row[1]} for row in raw_hist]

    return {
        "case_id": case_id,
        "total_count": total_count,
        "filtered_count": filtered_count,
        "timeline": serialized_events,
        "histogram": histogram,
        "limit": limit,
        "offset": offset,
    }


# ---------------------------------------------------------------------------
# 6. Connections Entity Graph
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/connections", summary="Interactive entity graph & cross-correlations")
def get_entity_connections(
    case_id: str,
    entity_value: Optional[str] = Query(""),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

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

        top_entities_raw = cursor.execute(
            """
            SELECT entity_type, entity_value,
                   COUNT(DISTINCT artifact_name) AS artifact_count,
                   COUNT(*) AS total_occurrences
            FROM entity_connections
            GROUP BY entity_type, entity_value
            ORDER BY artifact_count DESC, total_occurrences DESC
            LIMIT 50;
            """
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


def is_rejected_or_non_regular_file(raw_path_str: str) -> bool:
    if not raw_path_str or not isinstance(raw_path_str, str):
        return True

    clean_p = raw_path_str.strip().replace("/", "\\")
    while clean_p.startswith(".\\") or clean_p.startswith("\\"):
        clean_p = clean_p[1:] if clean_p.startswith("\\") else clean_p[2:]
    if len(clean_p) >= 2 and clean_p[1] == ":":
        clean_p = clean_p[2:].lstrip("\\")

    parts = [part.lower() for part in clean_p.split("\\") if part]
    if not parts:
        return True

    target_name = parts[-1].split(":")[0].strip()
    if target_name in LOCKED_NTFS_METADATA_STREAMS:
        return True
    if any(p.split(":")[0].strip() in LOCKED_NTFS_METADATA_STREAMS for p in parts):
        return True
    if target_name in REJECTED_NTFS_DIRECTORIES or any(p in REJECTED_NTFS_DIRECTORIES for p in parts):
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
                    conn = DuckDBManager.get_connection(case_id, read_only=False)
                    cursor = conn.cursor()
                    res = cursor.execute(
                        "SELECT command_executed FROM processing_logs WHERE command_executed LIKE 'Extractor (%' ORDER BY log_id DESC LIMIT 1;"
                    ).fetchone()
                    if res and res[0] and ":" in res[0]:
                        parts = res[0].split(":", 1)
                        cand = Path(parts[1].strip()).resolve()
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
                                    cand = Path(m.group(1)).resolve()
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


def resolve_evidence_data(
    case_id: str,
    raw_path_str: str,
    offset: int = 0,
    length: Optional[int] = None,
) -> Tuple[Optional[bytes], int, str, str]:
    if is_rejected_or_non_regular_file(raw_path_str):
        return None, 0, Path(raw_path_str).name, raw_path_str

    staging_dir = get_case_staging_dir(case_id)
    case_dir = get_case_dir(case_id)
    raw_path = Path(raw_path_str)

    norm_p = raw_path_str.replace("\\", "/").strip()
    if len(norm_p) >= 2 and norm_p[1] == ":":
        norm_p = norm_p[2:].lstrip("/")
    norm_p = norm_p.lstrip("/")
    rel_p = Path(norm_p)
    file_stem_name = rel_p.name

    if raw_path.is_dir() or (rel_p.is_dir() if norm_p else False):
        return None, 0, (raw_path if raw_path.is_dir() else rel_p).name, f"[DIRECTORY] {raw_path_str}"
    if (staging_dir / rel_p).is_dir():
        return None, 0, (staging_dir / rel_p).name, f"[DIRECTORY] {raw_path_str}"
    if (case_dir / rel_p).is_dir():
        return None, 0, (case_dir / rel_p).name, f"[DIRECTORY] {raw_path_str}"

    target_file: Optional[Path] = None
    case_root = case_dir.resolve()

    if raw_path.is_file():
        try:
            if raw_path.resolve().is_relative_to(case_root):
                target_file = raw_path.resolve()
        except Exception:
            pass
    elif rel_p.is_file():
        try:
            if rel_p.resolve().is_relative_to(case_root):
                target_file = rel_p.resolve()
        except Exception:
            pass
    elif (staging_dir / rel_p).is_file():
        try:
            cand = (staging_dir / rel_p).resolve()
            if cand.is_relative_to(case_root):
                target_file = cand
        except Exception:
            pass
    elif (case_dir / rel_p).is_file():
        try:
            cand = (case_dir / rel_p).resolve()
            if cand.is_relative_to(case_root):
                target_file = cand
        except Exception:
            pass
    elif file_stem_name and (staging_dir / "Documents" / file_stem_name).is_file():
        target_file = staging_dir / "Documents" / file_stem_name
    elif file_stem_name and (staging_dir / "Carved_Thumbnails" / file_stem_name).is_file():
        target_file = staging_dir / "Carved_Thumbnails" / file_stem_name
    elif file_stem_name and (staging_dir / "Notifications" / file_stem_name).is_file():
        target_file = staging_dir / "Notifications" / file_stem_name
    elif file_stem_name and (staging_dir / "ActivitiesCache" / file_stem_name).is_file():
        target_file = staging_dir / "ActivitiesCache" / file_stem_name
    else:
        candidate_name = file_stem_name.lower()
        if candidate_name and candidate_name not in (".", ".."):
            for cand in staging_dir.rglob("*"):
                if cand.is_file() and cand.name.lower() == candidate_name:
                    try:
                        if cand.resolve().is_relative_to(case_root):
                            target_file = cand.resolve()
                            break
                    except Exception:
                        pass

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

    return None, 0, raw_path.name, raw_path_str


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


@app.get("/api/cases/{case_id}/hex", summary="Hex & ASCII inspection of evidentiary files")
def get_hex_viewer(
    case_id: str,
    file_path: str = Query(...),
    offset: int = Query(0, ge=0),
    length: int = Query(4096, ge=16, le=65536),
) -> Dict[str, Any]:
    if is_rejected_or_non_regular_file(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target is a directory or locked NTFS metadata stream: '{file_path}'.",
        )

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=file_path,
            offset=offset,
            length=length,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot inspect directory as a hex file: '{file_path}'.",
        )

    if chunk is None and file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found on disk or in image: '{file_path}'.",
        )

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
        "file_path": resolved_path,
        "file_name": file_name,
        "file_size": file_size,
        "offset": offset,
        "length": len(lines) * 16 if lines else 0,
        "lines": lines,
    }


@app.get("/api/cases/{case_id}/file/content", summary="Document & text content preview")
def get_file_content(
    case_id: str,
    file_path: str = Query(...),
    max_bytes: int = Query(2_000_000),
) -> Dict[str, Any]:
    if is_rejected_or_non_regular_file(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target is a directory or locked NTFS metadata stream: '{file_path}'.",
        )

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=file_path,
            offset=0,
            length=max_bytes,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot preview directory content: '{file_path}'.",
        )

    if chunk is None and file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found: '{file_path}'.",
        )

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
    raw_url = f"/api/cases/{case_id}/file/raw?file_path={urllib.parse.quote(file_path)}"

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
def get_file_raw(
    case_id: str,
    file_path: str = Query(...),
    download: bool = Query(False),
):
    if is_rejected_or_non_regular_file(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target is a directory or locked NTFS metadata stream: '{file_path}'.",
        )

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=file_path,
            offset=0,
            length=None,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot stream directory bytes: '{file_path}'.",
        )

    if chunk is None and file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found: '{file_path}'.",
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
    return Response(content=chunk, media_type=mime_type, headers=headers)


# ---------------------------------------------------------------------------
# 7.0 Forensic File, Folder & Artifact Export Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/export/file", summary="Export / Download raw evidence file")
def export_evidence_file(
    case_id: str,
    file_path: str = Query(...),
):
    if is_rejected_or_non_regular_file(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target is a directory or locked NTFS metadata stream: '{file_path}'.",
        )

    with IMAGE_READ_LOCK:
        chunk, file_size, file_name, resolved_path = resolve_evidence_data(
            case_id=case_id,
            raw_path_str=file_path,
            offset=0,
            length=None,
        )

    if resolved_path.startswith("[DIRECTORY]"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target is a directory, not a file: '{file_path}'. Please use folder export.",
        )

    if chunk is None and file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found on disk or in image: '{file_path}'.",
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


@app.get("/api/cases/{case_id}/export/folder-zip", summary="Export folder as streaming .zip archive")
def export_folder_zip(
    case_id: str,
    folder_path: str = Query(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    with IMAGE_READ_LOCK:
        staging_dir = get_case_staging_dir(case_id)
        case_dir = get_case_dir(case_id, create_if_missing=False)

        norm_f = folder_path.strip().replace("\\", "/").strip("/")
        if norm_f.startswith("./"):
            norm_f = norm_f[2:]
        if len(norm_f) >= 2 and norm_f[1] == ":":
            norm_f = norm_f[2:].lstrip("/")
        clean_p = Path(norm_f) if norm_f else None

        safe_folder_name = clean_p.name if clean_p else "root"
        if not safe_folder_name or safe_folder_name in (".", "..", "\\", "/"):
            safe_folder_name = "evidence_folder"

        temp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        temp_zip_path = temp_zip.name
        temp_zip.close()

        files_written = 0
        cand_dir = staging_dir / clean_p if clean_p else staging_dir
        if not cand_dir.is_dir() and clean_p and (case_dir / clean_p).is_dir():
            cand_dir = case_dir / clean_p

        with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if cand_dir.is_dir():
                for root, _, files in os.walk(cand_dir):
                    for file in files:
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
    picker_res = _run_native_picker(mode="folder")
    if picker_res.get("cancelled") or not picker_res.get("path"):
        return {"success": False, "cancelled": True, "message": "Export cancelled by examiner."}

    dest_dir = Path(picker_res["path"]).resolve()
    if not dest_dir.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Selected destination directory '{dest_dir}' does not exist.",
        )

    if payload.file_path:
        if payload.is_folder:
            staging_dir = get_case_staging_dir(case_id)
            case_dir = get_case_dir(case_id, create_if_missing=False)
            norm_f = payload.file_path.strip().replace("\\", "/").strip("/")
            if norm_f.startswith("./"):
                norm_f = norm_f[2:]
            if len(norm_f) >= 2 and norm_f[1] == ":":
                norm_f = norm_f[2:].lstrip("/")
            clean_p = Path(norm_f) if norm_f else None

            cand_dir = staging_dir / clean_p if clean_p else staging_dir
            if not cand_dir.is_dir() and clean_p and (case_dir / clean_p).is_dir():
                cand_dir = case_dir / clean_p

            if not cand_dir.is_dir():
                raise HTTPException(status_code=404, detail=f"Evidence folder not found: '{payload.file_path}'.")

            safe_folder_name = clean_p.name if clean_p else "evidence_folder"
            target_folder = dest_dir / safe_folder_name
            shutil.copytree(cand_dir, target_folder, dirs_exist_ok=True)
            return {
                "success": True,
                "cancelled": False,
                "destination_folder": str(dest_dir),
                "saved_path": str(target_folder),
                "message": f"Successfully exported folder {safe_folder_name} to {dest_dir}",
            }

        with IMAGE_READ_LOCK:
            chunk, file_size, file_name, _ = resolve_evidence_data(
                case_id=case_id,
                raw_path_str=payload.file_path,
                offset=0,
                length=None,
            )
        if not chunk and file_size == 0:
            raise HTTPException(status_code=404, detail=f"Evidence file not found: '{payload.file_path}'.")
        safe_name = Path(file_name).name or "evidence_file"
        target_file = dest_dir / safe_name
        target_file.write_bytes(chunk or b"")
        return {
            "success": True,
            "cancelled": False,
            "destination_folder": str(dest_dir),
            "saved_path": str(target_file),
            "message": f"Successfully exported {safe_name} to {dest_dir}",
        }

    if payload.table_name:
        clean_tbl = validate_table_or_column_name(payload.table_name)
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
            "saved_path": str(out_file),
            "message": f"Successfully exported table to {out_file}",
        }

    raise HTTPException(status_code=400, detail="Missing export parameters.")


@app.get("/api/cases/{case_id}/table/{table_name}/export/csv", summary="Export table to downloadable CSV")
def export_table_csv(
    case_id: str,
    table_name: str,
    search: Optional[str] = Query(None),
):
    clean_tbl = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        cols = [r[1] for r in cursor.execute(f'PRAGMA table_info("{clean_tbl}");').fetchall()]
        if search and search.strip():
            text_cols = [c for c in cols if c != "_row_id"]
            if text_cols:
                like_clauses = " OR ".join([f'CAST("{c}" AS VARCHAR) ILIKE ?' for c in text_cols])
                params = [f"%{search.strip()}%"] * len(text_cols)
                rows = cursor.execute(f'SELECT * FROM "{clean_tbl}" WHERE {like_clauses};', params).fetchall()
            else:
                rows = cursor.execute(f'SELECT * FROM "{clean_tbl}";').fetchall()
        else:
            rows = cursor.execute(f'SELECT * FROM "{clean_tbl}";').fetchall()

    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(cols)
    for r in rows:
        writer.writerow([serialize_db_value(v) for v in r])

    csv_bytes = output.getvalue().encode("utf-8")
    headers = {
        "Content-Disposition": f'attachment; filename="{clean_tbl}_export.csv"',
        "Content-Length": str(len(csv_bytes)),
    }
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)


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


@app.get("/api/cases/{case_id}/filesystem/tree", summary="FTK Imager-style hierarchical directory tree")
def get_case_filesystem_tree(
    case_id: str,
    parent_path: Optional[str] = Query(""),
) -> Dict[str, Any]:
    with IMAGE_READ_LOCK:
        if not isinstance(parent_path, str):
            parent_path = ""
        staging_dir = get_case_staging_dir(case_id)
        case_dir = get_case_dir(case_id, create_if_missing=False)
        db_file = get_case_db_path(case_id)
        if not db_file.exists() and not staging_dir.exists() and not case_dir.exists():
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' does not exist.")

        norm_parent = _normalize_filesystem_path(parent_path)
        target_dir = staging_dir if norm_parent == "." else (staging_dir / Path(norm_parent[2:].replace("\\", "/"))).resolve()
        if not str(target_dir).startswith(str(staging_dir.resolve())):
            target_dir = staging_dir

        folders = []
        if target_dir.is_dir():
            for item in sorted(target_dir.iterdir(), key=lambda x: x.name.lower()):
                if item.is_dir():
                    f_count = sum(1 for f in item.iterdir() if f.is_file())
                    rel_path = str(item.relative_to(staging_dir)).replace("/", "\\")
                    folders.append({
                        "folder_name": item.name,
                        "folder_path": f".\\{rel_path}",
                        "parent_path": parent_path or "",
                        "mft_entry_number": None,
                        "sequence_number": None,
                        "in_use": True,
                        "file_count": f_count,
                        "is_directory": True,
                    })

        return {
            "case_id": case_id,
            "parent_path": parent_path or "",
            "normalized_parent": str(target_dir),
            "folders": folders,
            "total_folders": len(folders),
            "source": "staging",
        }


@app.get("/api/cases/{case_id}/filesystem/files", summary="FTK Imager-style file list for a directory")
def get_case_filesystem_files(
    case_id: str,
    folder_path: Optional[str] = Query(""),
    search: Optional[str] = Query(""),
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    with IMAGE_READ_LOCK:
        staging_dir = get_case_staging_dir(case_id)
        norm_folder = _normalize_filesystem_path(folder_path)
        target_dir = staging_dir if norm_folder == "." else (staging_dir / Path(norm_folder[2:].replace("\\", "/"))).resolve()
        if not str(target_dir).startswith(str(staging_dir.resolve())):
            target_dir = staging_dir

        all_items = []
        clean_search = search.strip().lower() if isinstance(search, str) else ""
        if target_dir.is_dir():
            for entry in sorted(target_dir.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                if clean_search and (clean_search not in entry.name.lower()):
                    continue
                try:
                    st = entry.stat()
                    is_d = entry.is_dir()
                    rel_p = str(entry.relative_to(staging_dir)).replace("/", "\\")
                    full_p = f".\\{rel_p}" if not rel_p.startswith(".\\") else rel_p
                    all_items.append({
                        "file_name": entry.name,
                        "full_path": full_p,
                        "extension": entry.suffix if not is_d else None,
                        "file_size": st.st_size if not is_d else 0,
                        "is_directory": is_d,
                        "in_use": True,
                        "mft_entry_number": None,
                        "sequence_number": None,
                        "si_created": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "si_modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "si_accessed": datetime.fromtimestamp(st.st_atime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "si_mft_modified": None,
                        "fn_created": None,
                        "fn_modified": None,
                        "staged_file_path": str(entry.resolve()) if not is_d else None,
                    })
                except Exception:
                    continue

        return {
            "case_id": case_id,
            "folder_path": folder_path or "",
            "normalized_folder": str(target_dir),
            "files": all_items[offset : offset + limit],
            "total_files": len(all_items),
            "limit": limit,
            "offset": offset,
            "source": "staging",
        }


# ---------------------------------------------------------------------------
# 8. Bookmarks
# ---------------------------------------------------------------------------
@app.post("/api/cases/{case_id}/bookmarks", summary="Bookmark / Tag evidence row")
def create_bookmark(case_id: str, payload: BookmarkCreateRequest) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

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
        return {"status": "SUCCESS", "bookmark": dict(zip(cols, [serialize_db_value(v) for v in created_row]))}


@app.get("/api/cases/{case_id}/bookmarks", summary="List examiner bookmarks")
def list_bookmarks(case_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS bookmarks (bookmark_id VARCHAR PRIMARY KEY, artifact_type VARCHAR, record_id VARCHAR, label VARCHAR, notes VARCHAR, Examiner VARCHAR, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, row_json VARCHAR)")
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


@app.delete("/api/cases/{case_id}/bookmarks/{bookmark_id}", summary="Delete examiner bookmark")
def delete_bookmark(case_id: str, bookmark_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        conn.cursor().execute("DELETE FROM bookmarks WHERE bookmark_id = ?;", [bookmark_id])
    return {"status": "SUCCESS", "bookmark_id": bookmark_id}


@app.delete("/api/cases/{case_id}/bookmarks", summary="Delete examiner bookmark by table and row_id")
def delete_bookmark_by_row(
    case_id: str,
    source_table: str = Query(...),
    source_row_id: int = Query(...),
    tag_name: Optional[str] = Query(None),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
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
    return {"status": "SUCCESS", "source_table": source_table, "source_row_id": source_row_id}


# ---------------------------------------------------------------------------
# 9. Keyword Lists & Scanning Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/cases/{case_id}/keywords", summary="List all case keywords and hit counts")
def get_case_keywords(case_id: str) -> Dict[str, Any]:
    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        raw_keywords = cursor.execute("""
            SELECT keyword_id, keyword, is_regex, source_file, hit_count, created_at
            FROM case_keywords
            ORDER BY hit_count DESC, created_at ASC;
        """).fetchall()
        cols = ["keyword_id", "keyword", "is_regex", "source_file", "hit_count", "created_at"]
        keywords_list = serialize_rows(cols, raw_keywords)
        return {"case_id": case_id, "keywords": keywords_list, "total_keywords": len(keywords_list)}


@app.post("/api/cases/{case_id}/keywords", summary="Add keywords and compute hit counts across case")
def add_case_keywords(case_id: str, payload: KeywordAddRequest) -> Dict[str, Any]:
    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        for kw in payload.keywords:
            clean_kw = kw.strip()
            if not clean_kw:
                continue
            kw_id = f"kw_{uuid.uuid4().hex[:12]}"
            cursor.execute(
                """
                INSERT INTO case_keywords (
                    keyword_id, keyword, is_regex, source_file, hit_count, created_at
                ) VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
                ON CONFLICT (keyword) DO UPDATE SET
                    source_file = COALESCE(EXCLUDED.source_file, case_keywords.source_file);
                """,
                [kw_id, clean_kw, payload.is_regex, payload.source_file],
            )
        scan_keywords_for_case(case_id, conn)
    return get_case_keywords(case_id)


@app.post("/api/cases/{case_id}/keywords/upload", summary="Upload keyword text or CSV file and scan")
async def upload_case_keywords(
    case_id: str,
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
) -> Dict[str, Any]:
    raw_text = ""
    source_name = "uploaded_keywords.txt"
    if file is not None:
        source_name = file.filename or "uploaded_keywords.txt"
        file_bytes = await file.read()
        raw_text = file_bytes.decode("utf-8", errors="replace")
    elif content is not None and content.strip():
        raw_text = content
    else:
        raise HTTPException(status_code=400, detail="Either a file upload or non-empty text content must be provided.")

    lines = raw_text.splitlines()
    extracted_keywords: List[str] = []
    seen = set()
    for line in lines:
        parts = line.split(",") if source_name.lower().endswith(".csv") else [line]
        for part in parts:
            clean_kw = part.strip().strip('"').strip("'")
            if clean_kw and clean_kw not in seen:
                seen.add(clean_kw)
                extracted_keywords.append(clean_kw)

    if not extracted_keywords:
        raise HTTPException(status_code=400, detail="No non-empty keywords found.")

    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        for kw in extracted_keywords:
            kw_id = f"kw_{uuid.uuid4().hex[:12]}"
            cursor.execute(
                """
                INSERT INTO case_keywords (
                    keyword_id, keyword, is_regex, source_file, hit_count, created_at
                ) VALUES (?, ?, FALSE, ?, 0, CURRENT_TIMESTAMP)
                ON CONFLICT (keyword) DO UPDATE SET
                    source_file = COALESCE(EXCLUDED.source_file, case_keywords.source_file);
                """,
                [kw_id, kw, source_name],
            )
        scan_keywords_for_case(case_id, conn)
    return get_case_keywords(case_id)


@app.delete("/api/cases/{case_id}/keywords/{keyword_id}", summary="Delete specific keyword from case")
def delete_case_keyword(case_id: str, keyword_id: str) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM case_keywords WHERE keyword_id = ?;", [keyword_id])
        scan_keywords_for_case(case_id, conn)
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
        {"name": "Windows Forensic Toolkit (WFT) Cases", "path": str(CASES_DIR.resolve()), "exists": CASES_DIR.exists()},
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
@app.get("/api/config/tool-paths")
@app.get("/api/tools/paths")
def get_system_tool_paths_endpoint(scan: bool = Query(False)) -> Dict[str, Any]:
    if scan:
        res = scan_and_sync_tool_paths(apply_to_env=True)
        return res.get("tools", res)
    return get_tool_paths_status()


@app.get("/api/system/scan-tools")
@app.post("/api/system/scan-tools")
@app.get("/api/tools/scan")
@app.post("/api/tools/scan")
def scan_system_tools_endpoint(save_to_env: bool = Query(True)) -> Dict[str, Any]:
    return scan_and_sync_tool_paths(apply_to_env=save_to_env)


@app.post("/api/system/tool-paths")
@app.post("/api/config/tool-paths")
@app.post("/api/tools/paths")
def update_system_tool_paths_endpoint(payload: Union[ToolPathsUpdateRequest, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(payload, ToolPathsUpdateRequest):
        paths_to_save = payload.paths
    elif isinstance(payload, dict):
        paths_to_save = payload["paths"] if ("paths" in payload and isinstance(payload["paths"], dict)) else payload
    else:
        paths_to_save = {}

    for _, v in list(paths_to_save.items()):
        if v and isinstance(v, str) and v.strip():
            try:
                validate_tool_binary_path(v)
            except ValueError as val_err:
                raise HTTPException(status_code=400, detail=str(val_err))

    updated_tools = save_tool_paths(paths_to_save)
    return {
        "status": "success",
        "message": "Tool paths updated successfully.",
        "tools": updated_tools,
        "env_file_path": str((BASE_DIR / ".env").resolve()),
        "saved_to_env": True,
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
# Section 15: Event Logs Workbench
# ---------------------------------------------------------------------------
EVENT_PROFILES_FILE: Path = (BASE_DIR / "rules" / "event_profiles.json").resolve()


def load_event_profiles() -> List[Dict[str, Any]]:
    if EVENT_PROFILES_FILE.exists() and EVENT_PROFILES_FILE.stat().st_size > 0:
        try:
            with open(EVENT_PROFILES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    return data
        except Exception:
            pass
    return []


def build_profile_sql(profile: Dict[str, Any]) -> str:
    if profile.get("sql") and str(profile["sql"]).strip():
        return str(profile["sql"]).strip()
    clauses: List[str] = []
    eids = profile.get("event_ids", [])
    if eids:
        clean_ids = [str(int(x)) for x in eids if str(x).isdigit()]
        if clean_ids:
            clauses.append(f"EventId IN ({', '.join(clean_ids)})")
    return " AND ".join(clauses) if clauses else "1=1"


@app.get("/api/event-profiles")
def get_event_profiles_endpoint(case_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    profiles = load_event_profiles()
    raw_content = json.dumps(profiles, indent=2)
    return {
        "profiles": profiles,
        "total_profiles": len(profiles),
        "profile_file_name": "event_profiles.json",
        "profile_file_path": "rules/event_profiles.json",
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
def get_evtx_rows(
    case_id: str,
    profile_id: Optional[str] = Query(None),
    file_name: Optional[str] = Query(None),
    event_id: Optional[int] = Query(None),
    level: Optional[str] = Query(None),
    channel: Optional[str] = Query(None),
    search: str = Query(""),
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    sort_col: str = Query("TimeCreated"),
    sort_dir: Literal["ASC", "DESC", "asc", "desc"] = Query("DESC"),
) -> Dict[str, Any]:
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
            return {"case_id": case_id, "columns": [], "rows": [], "total_count": 0, "filtered_count": 0, "limit": limit, "offset": offset}

        cols_info = cursor.execute("DESCRIBE raw_evtx;").fetchall()
        col_names = [c[0] for c in cols_info]
        where_clauses: List[str] = []
        params: List[Any] = []

        if profile_id:
            profiles = load_event_profiles()
            matched_profile = next((p for p in profiles if p.get("id") == profile_id), None)
            if matched_profile:
                where_clauses.append(f"({build_profile_sql(matched_profile)})")
        if file_name:
            where_clauses.append("(SourceFile ILIKE ? OR SourceFile ILIKE ?)")
            params.extend([f"%{file_name}%", f"%{file_name.replace('/', '%4')}%"])
        if event_id is not None:
            where_clauses.append("EventId = ?")
            params.append(event_id)
        if level:
            where_clauses.append("Level ILIKE ?")
            params.append(level)
        if channel:
            where_clauses.append("Channel ILIKE ?")
            params.append(f"%{channel}%")
        if search and search.strip():
            s_term = f"%{search.strip()}%"
            search_cols = [c for c in ["MapDescription", "PayloadData1", "PayloadData2", "ExecutableInfo", "UserName", "Computer", "Provider", "Channel"] if c in col_names]
            if search_cols:
                where_clauses.append("(" + " OR ".join([f"{col} ILIKE ?" for col in search_cols]) + ")")
                params.extend([s_term] * len(search_cols))

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        total_count = cursor.execute("SELECT COUNT(*) FROM raw_evtx;").fetchone()[0]
        filtered_count = cursor.execute(f"SELECT COUNT(*) FROM raw_evtx {where_sql};", params).fetchone()[0]

        clean_sort = sort_col if sort_col in col_names else "TimeCreated"
        clean_dir = "DESC" if sort_dir.upper() == "DESC" else "ASC"
        raw_rows = cursor.execute(
            f"SELECT * FROM raw_evtx {where_sql} ORDER BY {clean_sort} {clean_dir} NULLS LAST LIMIT ? OFFSET ?;",
            params + [limit, offset],
        ).fetchall()

        return {
            "case_id": case_id,
            "columns": col_names,
            "rows": serialize_rows(col_names, raw_rows),
            "total_count": total_count,
            "filtered_count": filtered_count,
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

        tables_found = set(
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        )

        stinger_hits = cursor.execute("SELECT COUNT(*) FROM artifact_stinger_hits;").fetchone()[0] if "artifact_stinger_hits" in tables_found else 0
        yara_matches = cursor.execute("SELECT COUNT(*) FROM artifact_yara_hits;").fetchone()[0] if "artifact_yara_hits" in tables_found else 0
        total_detections = (
            cursor.execute("SELECT COUNT(*) FROM view_all_malware_detections;").fetchone()[0]
            if "view_all_malware_detections" in tables_found
            else (stinger_hits + yara_matches)
        )
        heuristics_count = (
            cursor.execute(
                "SELECT COUNT(*) FROM artifact_stinger_hits WHERE detection_type ILIKE '%Heuristic%' OR detection_type ILIKE '%Threat%';"
            ).fetchone()[0]
            if "artifact_stinger_hits" in tables_found
            else 0
        )

        stinger_bin = find_stinger_binary()
        rule_files = [f.name for f in sorted(RULES_DIR.glob("**/*.yar*")) if f.is_file() and f.suffix.lower() in [".yar", ".yara"]] if RULES_DIR.exists() else []

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
def get_malware_rows(
    case_id: str,
    category: Optional[str] = Query("all"),
    search: str = Query(""),
    limit: int = Query(500, ge=1, le=50000),
    offset: int = Query(0, ge=0),
    sort_col: str = Query("_row_id"),
    sort_dir: Literal["ASC", "DESC", "asc", "desc"] = Query("ASC"),
) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        conn = ensure_case_exists(case_id, auto_create=False)
        cursor = conn.cursor()

        tables_found = set(
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        )

        target_table = (
            "view_all_malware_detections"
            if "view_all_malware_detections" in tables_found
            else ("artifact_stinger_hits" if "artifact_stinger_hits" in tables_found else None)
        )

        if not target_table:
            return {"case_id": case_id, "columns": [], "rows": [], "total_count": 0, "filtered_count": 0, "limit": limit, "offset": offset}

        cols_info = cursor.execute(f"DESCRIBE {target_table};").fetchall()
        col_names = [c[0] for c in cols_info]

        where_clauses: List[str] = []
        params: List[Any] = []

        if category == "stinger" and "engine" in col_names:
            where_clauses.append("engine ILIKE '%Stinger%'")
        elif category == "yara" and "engine" in col_names:
            where_clauses.append("engine ILIKE '%YARA%'")
        elif category == "heuristics" and "detection_type" in col_names:
            where_clauses.append("(detection_type ILIKE '%Heuristic%' OR detection_type ILIKE '%Threat%')")

        if search and search.strip():
            s_term = f"%{search.strip()}%"
            searchable = [
                c for c in ["file_name", "file_path", "sha256", "detection_name", "threat_name", "malware_name", "details"]
                if c in col_names
            ]
            if searchable:
                where_clauses.append("(" + " OR ".join([f"{c} ILIKE ?" for c in searchable]) + ")")
                params.extend([s_term] * len(searchable))

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        total_count = cursor.execute(f"SELECT COUNT(*) FROM {target_table};").fetchone()[0]
        filtered_count = cursor.execute(f"SELECT COUNT(*) FROM {target_table} {where_sql};", params).fetchone()[0]

        clean_sort = sort_col if sort_col in col_names else col_names[0]
        clean_dir = "DESC" if sort_dir.upper() == "DESC" else "ASC"

        raw_rows = cursor.execute(
            f"SELECT * FROM {target_table} {where_sql} ORDER BY {clean_sort} {clean_dir} NULLS LAST LIMIT ? OFFSET ?;",
            params + [limit, offset],
        ).fetchall()

        return {
            "case_id": case_id,
            "columns": col_names,
            "rows": serialize_rows(col_names, raw_rows),
            "total_count": total_count,
            "filtered_count": filtered_count,
            "limit": limit,
            "offset": offset,
        }


@app.post("/api/cases/{case_id}/malware/scan")
def trigger_malware_scan(case_id: str, req: MalwareScanRequest) -> Dict[str, Any]:
    with DuckDBManager.get_lock(case_id):
        ensure_case_exists(case_id, auto_create=False)
    engine = FileEnrichmentEngine(case_id=case_id)
    scan_results = engine.run(
        enable_yara=req.enable_yara,
        enable_ocr=req.enable_ocr,
        enable_stinger=req.enable_stinger,
    )
    return {
        "status": "success",
        "case_id": case_id,
        "results": scan_results,
        "summary": get_malware_summary(case_id),
    }


@app.post("/api/cases/{case_id}/malware/rules/upload")
async def upload_yara_rule(case_id: str, file: UploadFile = File(...)) -> Dict[str, Any]:
    if not (file.filename.endswith(".yar") or file.filename.endswith(".yara")):
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

    RULES_DIR.mkdir(parents=True, exist_ok=True)
    target_rule_file = RULES_DIR / file.filename
    target_rule_file.write_text(rule_str, encoding="utf-8")

    return {
        "status": "success",
        "message": f"YARA rule '{file.filename}' uploaded and compiled successfully.",
        "path": str(target_rule_file.resolve()),
    }


@app.get("/api/cases/{case_id}/report/html", summary="Generate Portable HTML Forensic Case Report")
def export_case_report_html(case_id: str):
    from fastapi.responses import HTMLResponse
    from backend.orchestrator.report_generator import generate_case_html_report
    html_content = generate_case_html_report(case_id)
    return HTMLResponse(content=html_content, status_code=200)


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
    async def serve_frontend_spa(full_path: str):
        if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = dist_dir / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        index_file = dist_dir / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Frontend file not found")


if __name__ == "__main__":
    import uvicorn

    print(f"[Windows Forensic Toolkit (WFT) Backend] Starting Uvicorn on {API_HOST}:{API_PORT}...")
    try:
        uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT, reload=False)
    finally:
        os._exit(0)