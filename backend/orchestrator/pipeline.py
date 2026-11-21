"""
Windows Forensic Toolkit (WFT) DFIR Suite - Master Processing Pipeline
Chains EvidenceExtractor -> Concurrent Runners & Parsers -> FileEnrichmentEngine
-> TimelineNormalizer -> Artifact Registry Sync -> Keyword Search
with selected_artifacts gating, DuckDB multi-threading, structured processing_logs
telemetry, case_metadata persistence, and zero silent exception swallowing.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union
import uuid

from backend.config import (
    get_case_db_path,
    get_case_dir,
    register_case_dir,
)
from backend.db.engine import (
    DuckDBManager,
    init_case_db,
    log_processing_event,
    scan_keywords_for_case,
)
from backend.db.schema import sync_artifact_registry_counts
from backend.orchestrator.enrichment import FileEnrichmentEngine
from backend.orchestrator.ez_runner import EZToolRunner
from backend.orchestrator.normalizer import TimelineNormalizer
from backend.orchestrator.regripper_runner import RegRipperRunner
from backend.vfs.extractor import EvidenceExtractor

DEFAULT_MAX_WORKERS: int = min(16, max(1, os.cpu_count() or 8))

# In-memory status tracker for live API queries
PIPELINE_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def clamp_max_workers(val: Optional[int]) -> int:
    """Clamp worker count safely into [1, 32]."""
    if val is None:
        return DEFAULT_MAX_WORKERS
    try:
        return max(1, min(32, int(val)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_WORKERS


def _call_with_supported_kwargs(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """
    Invoke `fn(*args, **filtered_kwargs)` by introspecting `inspect.signature(fn)`
    so peer milestones can evolve callee signatures independently without mismatch errors.
    """
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(*args)
    params = sig.parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fn(*args, **kwargs)
    filtered = {k: v for k, v in kwargs.items() if k in params}
    return fn(*args, **filtered)


# ---------------------------------------------------------------------------
# Artifact Selection ID Sets (`F29`)
# Maps all 38 ProcessWizard.tsx catalog IDs + canonical schema/table aliases
# ---------------------------------------------------------------------------
VSS_IDS: Set[str] = {
    "fs_vss", "vss", "volume_shadow_copies", "shadow_copies",
    "parsed_vss_snapshots", "vfs_shadow_copies",
}
CARVING_IDS: Set[str] = {
    "carve_files", "data_carving", "carving", "parsed_carved_files",
    "unallocated_carving",
}
BULK_EXTRACTOR_IDS: Set[str] = {
    "bulk_extractor", "bulk_extractor_scan", "bulk_extractor_features",
    "bulk_extractor_histograms", "parsed_bulk_extractor_features",
    "parsed_bulk_extractor_histograms", "raw_bulk_extractor",
}

EZ_TOOL_GROUPS: List[Tuple[str, Set[str], bool]] = [
    # (EZToolRunner method_name, matching_selection_ids, requires_rla)
    ("run_evtx", {"os_evtx", "evtx", "event_logs", "raw_evtx"}, False),
    ("run_wxt", {"os_wxt_activity", "wxt", "windows_timeline", "raw_wxt"}, False),
    ("run_pecmd", {"os_prefetch", "prefetch", "pecmd", "raw_pecmd", "raw_pecmd_timeline"}, False),
    (
        "run_amcache",
        {
            "os_amcache", "os_amcache_files", "os_amcache_programs", "os_amcache_shortcuts",
            "os_amcache_devices", "amcache", "raw_amcache", "raw_amcache_files",
        },
        True,
    ),
    ("run_appcompatcache", {"os_shimcache", "shimcache", "appcompatcache", "raw_appcompatcache", "raw_shimcache"}, True),
    ("run_recentfilecache", {"os_recentfilecache", "recentfilecache", "raw_recentfilecache"}, False),
    ("run_mftecmd_mft", {"fs_mft", "os_mft", "mft", "raw_mft"}, False),
    ("run_mftecmd_usnjrnl", {"fs_usnjrnl", "os_usnjrnl", "usnjrnl", "raw_usnjrnl"}, False),
    ("run_sbecmd", {"fs_shellbags", "os_shellbags", "shellbags", "sbecmd", "raw_sbecmd", "raw_shellbags"}, True),
    ("run_lecmd", {"fs_lnk", "os_lnk_files", "lnk", "lecmd", "raw_lecmd"}, False),
    ("run_jlecmd", {"fs_jumplist_auto", "fs_jumplist_custom", "os_jumplists", "jumplists", "jlecmd", "raw_jlecmd"}, False),
    ("run_rbcmd", {"fs_recyclebin", "os_recycle_bin", "recyclebin", "rbcmd", "raw_rbcmd", "raw_recycle_bin"}, False),
    (
        "run_recmd",
        {
            "registry_recmd", "os_registry", "view_autoruns", "view_userassist", "view_bam_dam",
            "view_usb_devices", "recmd", "raw_recmd", "os_autoruns", "os_userassist",
            "os_bam_dam", "os_user_accounts", "os_windows_services", "os_registry_mru",
            "os_network_profiles", "user_accounts", "windows_services", "registry_mru",
            "network_profiles",
        },
        True,
    ),
    (
        "run_srum",
        {
            "network_srum_app", "network_srum_net", "network_srum_conn",
            "os_srum_app", "os_srum_net", "os_srum_conn",
            "srum", "srumecmd", "raw_srum_app",
        },
        True,
    ),
    ("run_sum", {"network_sum", "os_sum", "sum", "sumecmd", "raw_sum"}, False),
    ("run_sqlecmd", {"sqlecmd", "sqlite_hunting", "raw_sqlecmd"}, False),
]

REGRIPPER_IDS: Set[str] = {
    "registry_recmd", "os_registry", "regripper", "regripper_plugins", "raw_regripper",
    "view_autoruns", "view_userassist", "view_bam_dam", "view_usb_devices",
    "os_user_accounts", "os_windows_services", "os_autoruns", "os_userassist",
    "os_bam_dam", "os_registry_mru", "os_network_profiles",
    "user_accounts", "windows_services", "registry_mru", "network_profiles",
}

CHROMIUM_IDS: Set[str] = {
    "browser_history", "browser_downloads", "browser_logins", "browser_cookies",
    "browser_autofill", "browser_bookmarks", "browser_sessions", "browser_cache",
    "browser_search_terms", "browser_top_sites", "web_related", "chromium",
    "chrome_history", "chrome_downloads", "chrome_cookies", "chrome_logins",
    "chrome_autofill", "chrome_bookmarks", "chrome_extensions", "chrome_session",
    "edge_history", "edge_downloads", "edge_cookies", "edge_logins",
    "edge_autofill", "edge_bookmarks", "edge_extensions", "edge_session",
    "brave_history", "brave_downloads", "brave_cookies", "brave_logins",
    "brave_autofill", "brave_bookmarks", "brave_extensions", "brave_session",
}

FIREFOX_IDS: Set[str] = {
    "browser_history", "browser_downloads", "browser_logins", "browser_cookies",
    "browser_bookmarks", "web_related", "firefox",
    "firefox_history", "firefox_downloads", "firefox_cookies",
    "firefox_bookmarks", "firefox_formhistory", "firefox_logins",
    "firefox_extensions",
}

HINDSIGHT_IDS: Set[str] = CHROMIUM_IDS | {
    "web_hindsight", "raw_hindsight", "hindsight",
}

CHAT_IDS: Set[str] = {
    "chat_messages", "parsed_notifications", "chat", "teams", "discord", "slack",
    "skype", "whatsapp", "telegram", "teams_messages", "discord_messages",
    "slack_messages", "skype_messages", "whatsapp_messages", "telegram_messages",
    "parsed_chat_messages",
}

CLOUD_IDS: Set[str] = {
    "cloud_files", "cloud", "onedrive", "gdrive", "dropbox",
    "onedrive_files", "gdrive_files", "dropbox_files", "parsed_cloud_files",
}

USB_IDS: Set[str] = {
    "usb_devices", "view_usb_devices", "parsed_usb_devices", "usb",
}

CORPORATE_IR_TASKS_IDS: Set[str] = {"os_tasks", "tasks_scheduled", "scheduled_tasks", "parsed_scheduled_tasks"}
CORPORATE_IR_PS_IDS: Set[str] = {"os_powershell", "powershell_console_history", "powershell_history", "parsed_powershell_history"}
CORPORATE_IR_RMM_IDS: Set[str] = {"parsed_rmm_sessions", "rmm_sessions", "rdp_rmm"}
CORPORATE_IR_WPN_IDS: Set[str] = {"os_wpn_notifications", "wpn_notifications", "parsed_wpn_notifications", "parsed_notifications"}
CORPORATE_IR_WER_IDS: Set[str] = {"os_wer_reports", "wer_reports", "parsed_wer_reports"}
CORPORATE_IR_IDS: Set[str] = (
    CORPORATE_IR_TASKS_IDS
    | CORPORATE_IR_PS_IDS
    | CORPORATE_IR_RMM_IDS
    | CORPORATE_IR_WPN_IDS
    | CORPORATE_IR_WER_IDS
    | {"corporate_ir"}
)

MEDIA_IDS: Set[str] = {
    "media_files", "media", "media_exif", "media_pictures", "media_videos",
    "media_thumbcache", "windows_thumbcache", "parsed_thumbcache", "exif",
}

DOCUMENT_IDS: Set[str] = {
    "documents_metadata", "documents", "view_documents", "docs_pdf", "docs_word",
    "docs_excel", "docs_ppt", "docs_txt", "parsed_text_documents",
    "zone_identifier", "motw", "pdf", "office",
}

EMAIL_IDS: Set[str] = {
    "emails", "email", "outlook_emails", "mbox_emails", "winmail_messages",
    "pst", "ost", "eml", "msg", "mbox", "parsed_emails",
}

ENRICHMENT_IOC_IDS: Set[str] = {"file_enrichment", "ioc", "sha256"}
ENRICHMENT_YARA_IDS: Set[str] = {"artifact_yara_hits", "malware_yara_hits", "malware_all_detections", "yara", "malware_yara"}
ENRICHMENT_STINGER_IDS: Set[str] = {"artifact_stinger_hits", "malware_stinger_hits", "malware_all_detections", "stinger", "trellix_stinger"}
ENRICHMENT_OCR_IDS: Set[str] = {"artifact_ocr_results", "media_ocr_results", "ocr", "rapidocr"}
ENRICHMENT_ALL_IDS: Set[str] = (
    ENRICHMENT_IOC_IDS | ENRICHMENT_YARA_IDS | ENRICHMENT_STINGER_IDS | ENRICHMENT_OCR_IDS
)

ALL_KNOWN_SELECTION_IDS: Set[str] = (
    VSS_IDS
    | CARVING_IDS
    | BULK_EXTRACTOR_IDS
    | REGRIPPER_IDS
    | CHROMIUM_IDS
    | FIREFOX_IDS
    | HINDSIGHT_IDS
    | CHAT_IDS
    | CLOUD_IDS
    | USB_IDS
    | CORPORATE_IR_IDS
    | MEDIA_IDS
    | DOCUMENT_IDS
    | EMAIL_IDS
    | ENRICHMENT_ALL_IDS
    | {aid for _, grp, _ in EZ_TOOL_GROUPS for aid in grp}
)

_METADATA_METRIC_KEYS: Set[str] = {
    "duration_ms",
    "elapsed_ms",
    "exit_code",
    "returncode",
    "status_code",
    "threads",
    "max_workers",
    "pid",
    "errors",
    "error_count",
    "warnings",
    "skipped",
    "files_scanned",
}

_EXPLICIT_ROW_COUNT_KEYS: Tuple[str, ...] = (
    "total_rows",
    "rows_ingested",
    "records_ingested",
    "rows",
    "row_count",
    "carved_count",
    "carved_files",
    "files_carved",
    "plugins_parsed",
    "total_features",
)


def _is_num_not_bool(val: Any) -> bool:
    return isinstance(val, (int, float)) and not isinstance(val, bool)


def _extract_row_count(res: Any) -> int:
    """
    Extract exact ingested row count from runner/parser/carver return values without
    falsy `0 or ...` bugs or summing metadata fields like `duration_ms` / `exit_code`.
    """
    if res is None or isinstance(res, bool):
        return 0
    if isinstance(res, (int, float)):
        return max(0, int(res))
    if isinstance(res, dict):
        for explicit_k in _EXPLICIT_ROW_COUNT_KEYS:
            if explicit_k in res and _is_num_not_bool(res[explicit_k]):
                return max(0, int(res[explicit_k]))
        if "features_ingested" in res or "histograms_ingested" in res:
            f_val = res.get("features_ingested")
            h_val = res.get("histograms_ingested")
            f_cnt = int(f_val) if _is_num_not_bool(f_val) else 0
            h_cnt = int(h_val) if _is_num_not_bool(h_val) else 0
            return max(0, f_cnt + h_cnt)
        if "count" in res and _is_num_not_bool(res["count"]):
            return max(0, int(res["count"]))
        total = 0
        for k, v in res.items():
            if str(k).lower() in _METADATA_METRIC_KEYS:
                continue
            if _is_num_not_bool(v):
                total += max(0, int(v))
        return total
    return 0


def _extract_table_counts_dict(res: Any) -> Dict[str, int]:
    """Extract per-table `{table_name: count}` mappings while excluding non-row metadata keys."""
    if not isinstance(res, dict):
        return {}
    cleaned: Dict[str, int] = {}
    for k, v in res.items():
        k_str = str(k)
        if k_str.lower() in _METADATA_METRIC_KEYS:
            continue
        if _is_num_not_bool(v):
            cleaned[k_str] = max(0, int(v))
    return cleaned


def _clean_hindsight_timestamp(val: Any) -> Optional[str]:
    """Normalize Hindsight JSONL timestamp to ISO UTC string or None (never empty string or 1970 epoch)."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        num = float(val)
        if num <= 0:
            return None
        if num > 1e14:  # WebKit microseconds since 1601-01-01 or Unix microseconds
            if num > 11644473600000000:
                num = (num - 11644473600000000) / 1_000_000.0
            else:
                num = num / 1_000_000.0
        elif num > 1e11:  # Unix milliseconds
            num = num / 1000.0
        if num <= 86400:
            return None
        try:
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            if dt.year <= 1970:
                return None
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (OSError, OverflowError, ValueError):
            return None
    s = str(val).strip()
    if not s or s.lower() in {"none", "null", "n/a", "0"} or s.startswith("1970-01-01") or s.startswith("1601-01-01"):
        return None
    # Verify DuckDB-compatible ISO-like date prefix YYYY-MM-DD
    if len(s) >= 10 and s[4] in ("-", "/") and s[7] in ("-", "/"):
        yr = s[:4]
        if yr.isdigit() and int(yr) > 1970:
            return s.replace("T", " ").rstrip("Z")
    return None


def get_job_status(case_id: str) -> Dict[str, Any]:
    """
    Retrieve live in-memory job status for a given case_id.
    If not in memory, attempts to infer status from DuckDB processing_logs.
    """
    with _JOBS_LOCK:
        if case_id in PIPELINE_JOBS:
            return dict(PIPELINE_JOBS[case_id])

    db_path = get_case_db_path(case_id)
    if not db_path.exists():
        return {
            "case_id": case_id,
            "status": "IDLE",
            "progress": 0,
            "current_step": "Not started",
            "error": None,
            "start_time": None,
            "end_time": None,
        }

    try:
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cursor = conn.cursor()
            logs = cursor.execute(
                """
                SELECT status, module_name, error_message, timestamp_utc
                FROM processing_logs
                ORDER BY log_id DESC
                LIMIT 1;
                """
            ).fetchall()

            if not logs:
                return {
                    "case_id": case_id,
                    "status": "IDLE",
                    "progress": 0,
                    "current_step": "Initialized",
                    "error": None,
                    "start_time": None,
                    "end_time": None,
                }

            last_status, module_name, err_msg, ts = logs[0]
            if last_status == "ERROR":
                return {
                    "case_id": case_id,
                    "status": "ERROR",
                    "progress": 100,
                    "current_step": f"Failed at {module_name}",
                    "error": err_msg or "Unknown error",
                    "start_time": None,
                    "end_time": str(ts),
                }

            pipeline_done = cursor.execute(
                """
                SELECT COUNT(*) FROM processing_logs
                WHERE module_name = 'Pipeline' AND status = 'SUCCESS';
                """
            ).fetchone()[0] > 0

        return {
            "case_id": case_id,
            "status": "SUCCESS" if pipeline_done else "COMPLETED",
            "progress": 100,
            "current_step": f"Completed at {module_name}",
            "error": None,
            "start_time": None,
            "end_time": str(ts),
        }
    except Exception as ex:
        return {
            "case_id": case_id,
            "status": "UNKNOWN",
            "progress": 0,
            "current_step": f"Status check error: {ex}",
            "error": str(ex),
            "start_time": None,
            "end_time": None,
        }


class ProcessingPipeline:
    """
    Master forensic pipeline coordinator.
    Chains:
      1. DuckDB Initialization, PRAGMA threads, case_metadata & keyword seeding
      2. EvidenceExtractor (VFS disk image / directory / live triage + optional VSS)
      3. Concurrent External Runners, Carving & Application Parsers (ThreadPoolExecutor)
      4. FileEnrichmentEngine (SHA256/IOC, YARA-X, Trellix Stinger, RapidOCR)
      5. TimelineNormalizer, Artifact Registry Synchronization & Keyword Search
    """

    def __init__(
        self,
        case_id: str,
        target_dir: Optional[Union[str, Path]] = None,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> None:
        self.case_id = case_id
        self.max_workers = clamp_max_workers(max_workers)

        # CRITICAL: Register custom target_dir BEFORE any get_case_dir() or DB init call
        # so `(BASE_DIR / "cases")` is never created when target_dir is supplied.
        if target_dir and str(target_dir).strip():
            self.case_dir = register_case_dir(case_id, str(target_dir).strip())
        else:
            self.case_dir = get_case_dir(case_id)

        self.staging_dir = (self.case_dir / "staging").resolve()
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.csv_out_dir = (self.case_dir / "csv_out").resolve()
        self.csv_out_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = (self.case_dir / "processing.log").resolve()

        init_case_db(case_id)
        DuckDBManager.configure_threads(case_id, self.max_workers)

        # Initialize core components under case lock for safe DuckDB connection access
        self.extractor = _call_with_supported_kwargs(
            EvidenceExtractor,
            case_id=case_id,
            staging_dir=self.staging_dir,
            log_file=self.log_file,
            max_workers=self.max_workers,
        )
        with DuckDBManager.get_lock(case_id):
            self.runner = _call_with_supported_kwargs(
                EZToolRunner,
                case_id=case_id,
                staging_dir=self.staging_dir,
                csv_out_dir=self.csv_out_dir,
                max_workers=self.max_workers,
            )
            self.enricher = _call_with_supported_kwargs(
                FileEnrichmentEngine,
                case_id=case_id,
                staging_dir=self.staging_dir,
                max_workers=self.max_workers,
            )
            self.normalizer = TimelineNormalizer(case_id=case_id)

    def _log(self, message: str, level: str = "INFO") -> None:
        """Append timestamped logs to the case processing log file and console."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level}] [Pipeline] {message}")
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] [{level}] {message}\n")
            except OSError as log_os_err:
                print(f"[{ts}] [WARNING] [Pipeline] Could not write to log file {self.log_file}: {log_os_err}")

    def _record_stage_telemetry(
        self,
        module_name: str,
        command: str,
        status: str,
        rows: int = 0,
        duration_ms: int = 0,
        exit_code: int = 0,
        error: Optional[str] = None,
    ) -> None:
        """Write deterministic structured stage telemetry into DuckDB `processing_logs`."""
        level = "ERROR" if status == "ERROR" else ("WARNING" if status == "WARNING" else "INFO")
        summary = f"{module_name} [{status}] rows={rows} duration={duration_ms}ms"
        if error:
            summary += f" error={error}"
        self._log(summary, level=level)
        log_processing_event(
            case_id=self.case_id,
            module_name=module_name,
            command_executed=command,
            exit_code=int(exit_code),
            rows_ingested=int(rows or 0),
            duration_ms=max(0, int(duration_ms or 0)),
            status=status,
            error_message=error,
        )

    def _update_status(
        self,
        status: str,
        progress: int,
        step: str,
        error: Optional[str] = None,
        progress_callback: Optional[Callable[..., None]] = None,
    ) -> None:
        """Update in-memory job tracker and invoke 2-arg or 3-arg progress_callback."""
        now_str = datetime.now(timezone.utc).isoformat()
        with _JOBS_LOCK:
            current_job = PIPELINE_JOBS.get(self.case_id, {})
            start_time = current_job.get("start_time", now_str)
            PIPELINE_JOBS[self.case_id] = {
                "case_id": self.case_id,
                "status": status,
                "progress": progress,
                "current_step": step,
                "error": error,
                "start_time": start_time,
                "end_time": now_str if status in ["SUCCESS", "ERROR"] else None,
            }

        if progress_callback:
            try:
                sig = inspect.signature(progress_callback)
                pos_params = [
                    p
                    for p in sig.parameters.values()
                    if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                ]
                has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
                if len(pos_params) >= 3 and not has_varargs:
                    progress_callback(status, progress, step)
                else:
                    progress_callback(progress, step)
            except Exception as cb_err:
                self._log(f"progress_callback error: {cb_err}", "WARNING")

    @staticmethod
    def _normalize_selected_set(selected_artifacts: Optional[Iterable[Any]]) -> Optional[Set[str]]:
        if selected_artifacts is None:
            return None
        return {str(item).strip().lower() for item in selected_artifacts if item is not None and str(item).strip()}

    def _persist_case_metadata(
        self,
        norm_source_type: str,
        clean_source_path: Optional[str],
        workers: int,
        should_run_carving: bool,
        should_run_bulk_extractor: bool,
        should_run_vss: bool,
        selected_set: Optional[Set[str]],
        case_metadata: Optional[Dict[str, Any]],
    ) -> int:
        """Persist canonical + caller-supplied metadata key/values into `case_metadata`."""
        meta_in = dict(case_metadata or {})
        image_size = str(meta_in.get("image_size", "0") or "0")
        if clean_source_path:
            try:
                p = Path(clean_source_path)
                if p.exists() and p.is_file():
                    image_size = str(p.stat().st_size)
            except OSError:
                pass

        now_iso = datetime.now(timezone.utc).isoformat()
        payload: Dict[str, str] = {
            "case_id": str(self.case_id),
            "case_name": str(meta_in.get("case_name") or meta_in.get("caseName") or self.case_id),
            "case_number": str(meta_in.get("case_number") or meta_in.get("caseNumber") or ""),
            "examiner": str(meta_in.get("examiner") or meta_in.get("examiner_name") or meta_in.get("examinerName") or ""),
            "notes": str(meta_in.get("notes") or meta_in.get("case_notes") or meta_in.get("caseNotes") or ""),
            "source_path": str(clean_source_path or ""),
            "source_type": str(norm_source_type),
            "image_size": image_size,
            "sha256": str(meta_in.get("sha256") or ""),
            "max_workers": str(workers),
            "enable_data_carving": str(bool(should_run_carving)).lower(),
            "enable_bulk_extractor": str(bool(should_run_bulk_extractor)).lower(),
            "enable_vss": str(bool(should_run_vss)).lower(),
            "selected_artifacts": json.dumps(sorted(selected_set)) if selected_set is not None else "ALL",
        }
        for k, v in meta_in.items():
            k_str = str(k).strip()
            if k_str and v is not None and k_str not in payload:
                payload[k_str] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS case_metadata (
                    key VARCHAR PRIMARY KEY,
                    value VARCHAR,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                INSERT INTO case_metadata (key, value)
                VALUES ('created_utc', ?)
                ON CONFLICT (key) DO NOTHING;
                """,
                [now_iso],
            )
            for k, v in payload.items():
                cur.execute(
                    """
                    INSERT INTO case_metadata (key, value)
                    VALUES (?, ?)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
                    """,
                    [k, v],
                )
        return len(payload) + 1

    def _seed_keywords(
        self,
        keywords: Optional[Union[List[Any], str]],
        initial_keywords: Optional[Union[List[Any], str]] = None,
    ) -> int:
        """Normalize and seed both `keywords` and `initial_keywords` into `case_keywords`."""
        raw_items: List[Any] = []
        for src in (keywords, initial_keywords):
            if not src:
                continue
            if isinstance(src, str):
                for line in src.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
                    if line and line.strip():
                        raw_items.append(line)
            elif isinstance(src, Iterable):
                raw_items.extend(list(src))

        if not raw_items:
            return 0

        normalized: List[Tuple[str, bool, bool, str, str]] = []
        seen: Set[Tuple[str, bool, bool]] = set()
        for item in raw_items:
            if isinstance(item, dict):
                term = None
                for tk in ("keyword", "term", "pattern", "value"):
                    if item.get(tk) is not None and str(item.get(tk)).strip():
                        term = str(item.get(tk))
                        break
                clean_kw = term if term is not None else ""
                is_regex = bool(item.get("is_regex") or item.get("regex", False))
                is_cs = bool(item.get("is_case_sensitive") or item.get("case_sensitive", False))
                category = str(item.get("category") or item.get("list_name") or "General").strip() or "General"
                source_file = str(item.get("source_file") or item.get("list_name") or "WFT Process").strip() or "WFT Process"
            else:
                clean_kw = str(item) if item is not None else ""
                is_regex = False
                is_cs = False
                category = "General"
                source_file = "WFT Process"

            if not clean_kw or not clean_kw.strip():
                continue
            dedup_key = (clean_kw, is_regex, is_cs)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            normalized.append((clean_kw, is_regex, is_cs, category, source_file))

        if not normalized:
            return 0

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            cols = {
                str(r[0]).lower()
                for r in cur.execute("DESCRIBE case_keywords;").fetchall()
            }
            seeded = 0
            for clean_kw, is_regex, is_cs, category, source_file in normalized:
                kw_id = f"kw_{uuid.uuid4().hex[:12]}"
                insert_cols = ["keyword_id", "keyword", "is_regex"]
                insert_vals: List[Any] = [kw_id, clean_kw, is_regex]
                update_clauses = ["is_regex = EXCLUDED.is_regex"]

                if "is_case_sensitive" in cols:
                    insert_cols.append("is_case_sensitive")
                    insert_vals.append(is_cs)
                    update_clauses.append("is_case_sensitive = EXCLUDED.is_case_sensitive")
                if "case_sensitive" in cols:
                    insert_cols.append("case_sensitive")
                    insert_vals.append(is_cs)
                    update_clauses.append("case_sensitive = EXCLUDED.case_sensitive")
                if "category" in cols:
                    insert_cols.append("category")
                    insert_vals.append(category)
                    update_clauses.append("category = EXCLUDED.category")
                if "source_file" in cols:
                    insert_cols.append("source_file")
                    insert_vals.append(source_file)
                    update_clauses.append("source_file = EXCLUDED.source_file")
                if "hit_count" in cols:
                    insert_cols.append("hit_count")
                    insert_vals.append(0)

                placeholders = ", ".join(["?"] * len(insert_cols))
                col_sql = ", ".join(insert_cols)
                upd_sql = ", ".join(update_clauses)
                cur.execute(
                    f"""
                    INSERT INTO case_keywords ({col_sql})
                    VALUES ({placeholders})
                    ON CONFLICT (keyword) DO UPDATE SET {upd_sql};
                    """,
                    insert_vals,
                )
                seeded += 1
        return seeded

    def _run_ez_stage(
        self,
        selected_set: Optional[Set[str]],
        workers: int,
        enable_hindsight: bool,
    ) -> Dict[str, int]:
        """Run EZToolRunner (either full `run_all` or strictly selected `run_*` methods)."""
        t0 = time.time()
        results: Dict[str, int] = {}

        if selected_set is None:
            res = _call_with_supported_kwargs(
                self.runner.run_all,
                max_workers=workers,
                enable_hindsight=enable_hindsight,
                selected_artifacts=None,
            )
            if isinstance(res, dict):
                results.update(_extract_table_counts_dict(res))
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:EZRunner",
                "EZToolRunner.run_all",
                "SUCCESS",
                rows=sum(results.values()),
                duration_ms=dur,
            )
            return results

        # Selected mode: check if EZToolRunner.run_all natively supports `selected_artifacts`
        try:
            sig = inspect.signature(self.runner.run_all)
            supports_sel = (
                "selected_artifacts" in sig.parameters
                or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            )
        except (TypeError, ValueError):
            supports_sel = False

        matched_methods: List[str] = []
        needs_rla = False
        for method_name, id_group, req_rla in EZ_TOOL_GROUPS:
            if selected_set & id_group:
                matched_methods.append(method_name)
                if req_rla:
                    needs_rla = True

        if not matched_methods:
            self._record_stage_telemetry(
                "Pipeline:EZRunner",
                "EZToolRunner (deselected)",
                "SKIPPED",
                rows=0,
                duration_ms=0,
            )
            return {}

        if supports_sel:
            res = _call_with_supported_kwargs(
                self.runner.run_all,
                max_workers=workers,
                enable_hindsight=enable_hindsight and bool(selected_set & HINDSIGHT_IDS),
                selected_artifacts=sorted(selected_set),
            )
            if isinstance(res, dict):
                results.update(_extract_table_counts_dict(res))
        else:
            if needs_rla and hasattr(self.runner, "run_rla"):
                try:
                    self.runner.run_rla()
                except Exception as rla_err:
                    self._log(f"Notice running rla pre-pass: {rla_err}", "WARNING")

            ez_workers = max(1, min(workers, len(matched_methods)))
            with ThreadPoolExecutor(max_workers=ez_workers) as ez_pool:
                fut_map = {}
                for m_name in matched_methods:
                    fn = getattr(self.runner, m_name, None)
                    if callable(fn):
                        fut_map[ez_pool.submit(fn)] = m_name
                for fut in as_completed(fut_map):
                    m_name = fut_map[fut]
                    try:
                        val = fut.result()
                        if isinstance(val, dict):
                            results.update(_extract_table_counts_dict(val))
                        elif _is_num_not_bool(val):
                            results[m_name] = max(0, int(val))
                    except Exception as tool_err:
                        self._record_stage_telemetry(
                            f"EZRunner:{m_name}",
                            f"EZToolRunner.{m_name}",
                            "WARNING",
                            exit_code=1,
                            error=str(tool_err),
                        )

        dur = int((time.time() - t0) * 1000)
        self._record_stage_telemetry(
            "Pipeline:EZRunner",
            f"EZToolRunner ({','.join(matched_methods)})",
            "SUCCESS",
            rows=sum(results.values()),
            duration_ms=dur,
        )
        return results

    def _run_native_fallbacks_stage(
        self,
        selected_set: Optional[Set[str]],
        workers: int,
    ) -> Dict[str, int]:
        """Execute NativeFallbackParser after EZToolRunner to fill 0-row raw tables + AXIOM OS/Registry tables."""
        t0 = time.time()
        NativeFallbackParserCls = None
        for mod_name in ("backend.parsers.native_fallback_parsers", "backend.parsers.native_fallbacks"):
            try:
                mod = __import__(mod_name, fromlist=["NativeFallbackParser"])
                NativeFallbackParserCls = getattr(mod, "NativeFallbackParser", None)
                if NativeFallbackParserCls is not None:
                    break
            except ImportError:
                continue

        if NativeFallbackParserCls is None:
            self._record_stage_telemetry(
                "Pipeline:NativeFallbackParser",
                "NativeFallbackParser",
                "SKIPPED",
                error="NativeFallbackParser module not available",
            )
            return {}

        granular_map: List[Tuple[str, Set[str]]] = [
            ("parse_prefetch_natively", {"os_prefetch", "prefetch", "pecmd", "raw_pecmd"}),
            ("parse_mft_natively", {"fs_mft", "os_mft", "mft", "raw_mft"}),
            ("parse_evtx_natively", {"os_evtx", "evtx", "event_logs", "raw_evtx"}),
            ("parse_ie_webcache", CHROMIUM_IDS | {"ie_history", "parsed_ie_history"}),
            ("parse_gdrive_logs", CLOUD_IDS),
            ("parse_recycle_bin_natively", {"fs_recyclebin", "os_recycle_bin", "recyclebin", "rbcmd", "raw_rbcmd", "raw_recycle_bin"}),
            ("parse_registry_os_summary_natively", REGRIPPER_IDS),
            ("parse_user_accounts", REGRIPPER_IDS),
            ("parse_windows_services", REGRIPPER_IDS),
            ("parse_autoruns", REGRIPPER_IDS),
            ("parse_userassist", REGRIPPER_IDS),
            ("parse_bam_dam", REGRIPPER_IDS),
            ("parse_registry_mru", REGRIPPER_IDS),
            ("parse_network_profiles", REGRIPPER_IDS),
            ("parse_srum_natively", {"network_srum_app", "network_srum_net", "network_srum_conn", "os_srum_app", "os_srum_net", "os_srum_conn", "srum", "srumecmd"}),
        ]

        if selected_set is not None:
            any_nfp = any(bool(selected_set & ids) for _, ids in granular_map)
            if not any_nfp:
                self._record_stage_telemetry(
                    "Pipeline:NativeFallbackParser",
                    "NativeFallbackParser (deselected)",
                    "SKIPPED",
                )
                return {}

        try:
            with DuckDBManager.get_lock(self.case_id):
                nfp = _call_with_supported_kwargs(
                    NativeFallbackParserCls,
                    case_id=self.case_id,
                    staging_dir=self.staging_dir,
                )

            results: Dict[str, int] = {}
            if selected_set is None:
                fn = getattr(nfp, "run_all", None) or getattr(nfp, "parse", None)
                if callable(fn):
                    res = _call_with_supported_kwargs(fn, max_workers=workers)
                    if isinstance(res, dict):
                        results.update(_extract_table_counts_dict(res))
            else:
                run_all_fn = getattr(nfp, "run_all", None)
                can_pass_sel = False
                if callable(run_all_fn):
                    try:
                        sig = inspect.signature(run_all_fn)
                        can_pass_sel = "selected_artifacts" in sig.parameters
                    except (TypeError, ValueError):
                        can_pass_sel = False
                if can_pass_sel and callable(run_all_fn):
                    res = _call_with_supported_kwargs(
                        run_all_fn,
                        max_workers=workers,
                        selected_artifacts=sorted(selected_set),
                    )
                    if isinstance(res, dict):
                        results.update(_extract_table_counts_dict(res))
                else:
                    for m_name, ids in granular_map:
                        if selected_set & ids:
                            m_fn = getattr(nfp, m_name, None)
                            if callable(m_fn):
                                val = m_fn()
                                if isinstance(val, dict):
                                    results.update(_extract_table_counts_dict(val))
                                elif _is_num_not_bool(val):
                                    results[m_name] = max(0, int(val))

            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:NativeFallbackParser",
                "NativeFallbackParser",
                "SUCCESS",
                rows=sum(results.values()),
                duration_ms=dur,
            )
            return results
        except Exception as nfp_err:
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:NativeFallbackParser",
                "NativeFallbackParser",
                "WARNING",
                duration_ms=dur,
                exit_code=1,
                error=str(nfp_err),
            )
            return {}

    def _run_hindsight_stage(
        self,
        selected_set: Optional[Set[str]],
        enable_hindsight: bool,
        ez_results: Dict[str, int],
        workers: int,
    ) -> Dict[str, int]:
        """Run Hindsight browser forensics if enabled & selected and not already executed by EZToolRunner."""
        if not enable_hindsight:
            self._record_stage_telemetry("Pipeline:Hindsight", "Hindsight (disabled)", "SKIPPED")
            return {}
        if selected_set is not None and not (selected_set & HINDSIGHT_IDS):
            self._record_stage_telemetry("Pipeline:Hindsight", "Hindsight (deselected)", "SKIPPED")
            return {}
        if "raw_hindsight" in ez_results:
            return {"raw_hindsight": int(ez_results["raw_hindsight"])}

        t0 = time.time()
        try:
            if hasattr(self.runner, "run_hindsight"):
                res = _call_with_supported_kwargs(
                    self.runner.run_hindsight,
                    browsers_dir=self.staging_dir / "Browsers",
                    max_workers=min(16, workers),
                )
                rows = _extract_row_count(res)
                dur = int((time.time() - t0) * 1000)
                self._record_stage_telemetry(
                    "Pipeline:Hindsight",
                    "EZToolRunner.run_hindsight",
                    "SUCCESS",
                    rows=rows,
                    duration_ms=dur,
                )
                return {"raw_hindsight": rows}

            # Fallback: check config binary locator if available
            find_hs = None
            try:
                from backend import config as cfg_mod
                find_hs = getattr(cfg_mod, "find_hindsight_binary", None)
            except ImportError:
                find_hs = None

            hs_bin = find_hs() if callable(find_hs) else None
            browsers_root = self.staging_dir / "Browsers"
            if not hs_bin or not Path(hs_bin).exists() or not browsers_root.exists():
                self._record_stage_telemetry(
                    "Pipeline:Hindsight",
                    "Hindsight fallback check",
                    "SKIPPED",
                    duration_ms=int((time.time() - t0) * 1000),
                )
                return {}

            hs_out_dir = self.csv_out_dir / "hindsight"
            hs_out_dir.mkdir(parents=True, exist_ok=True)
            profile_dirs = {
                p.parent
                for marker in ("History", "Preferences", "Cookies")
                for p in browsers_root.rglob(marker)
                if p.is_file()
            }
            ingested = 0
            for idx, prof_dir in enumerate(sorted(profile_dirs)):
                out_base = hs_out_dir / f"profile_{idx}"
                proc = subprocess.run(
                    [str(hs_bin), "-i", str(prof_dir), "-o", str(out_base), "-f", "jsonl"],
                    capture_output=True,
                    text=True,
                    timeout=180,
                    check=False,
                )
                jsonl_path = Path(f"{out_base}.jsonl")
                if proc.returncode == 0 and jsonl_path.exists() and jsonl_path.stat().st_size > 0:
                    parsed_objs: List[Dict[str, Any]] = []
                    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as jf:
                        for line in jf:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if isinstance(obj, dict):
                                parsed_objs.append(obj)
                    if parsed_objs:
                        with DuckDBManager.get_lock(self.case_id):
                            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                            cur = conn.cursor()
                            for hs_alt in (
                                "ALTER TABLE raw_hindsight ADD COLUMN IF NOT EXISTS timestamp_utc TIMESTAMP;",
                                "ALTER TABLE raw_hindsight ADD COLUMN IF NOT EXISTS visit_time_utc TIMESTAMP;",
                                "ALTER TABLE raw_hindsight ADD COLUMN IF NOT EXISTS source_file VARCHAR;",
                                "ALTER TABLE raw_hindsight ADD COLUMN IF NOT EXISTS source_path VARCHAR;",
                                "ALTER TABLE raw_hindsight ADD COLUMN IF NOT EXISTS profile_path VARCHAR;",
                            ):
                                try:
                                    cur.execute(hs_alt)
                                except Exception:
                                    pass
                            hs_cols = {
                                str(r[0]).lower(): str(r[0])
                                for r in cur.execute('DESCRIBE "raw_hindsight";').fetchall()
                            }
                            max_hs_id = int(
                                cur.execute('SELECT COALESCE(MAX("_row_id"), 0) FROM "raw_hindsight";').fetchone()[0] or 0
                            ) if "_row_id" in hs_cols else 0

                            target_col_keys = [
                                k for k in (
                                    "_row_id",
                                    "browser",
                                    "profile_path",
                                    "source_file",
                                    "source_path",
                                    "record_type",
                                    "url",
                                    "title",
                                    "value",
                                    "timestamp_utc",
                                    "visit_time_utc",
                                    "interpretation",
                                )
                                if k in hs_cols
                            ]
                            actual_cols_sql = ", ".join([f'"{hs_cols[k]}"' for k in target_col_keys])
                            placeholders_sql = ", ".join(["?"] * len(target_col_keys))

                            rows_to_insert: List[List[Any]] = []
                            for r_offset, obj in enumerate(parsed_objs, start=1):
                                clean_ts = (
                                    _clean_hindsight_timestamp(obj.get("datetime"))
                                    or _clean_hindsight_timestamp(obj.get("timestamp"))
                                    or _clean_hindsight_timestamp(obj.get("visit_time_utc"))
                                    or _clean_hindsight_timestamp(obj.get("timestamp_utc"))
                                )
                                prof_str = str(prof_dir)
                                val_lookup: Dict[str, Any] = {
                                    "_row_id": max_hs_id + r_offset,
                                    "browser": str(obj.get("browser_type") or obj.get("browser") or "Chromium"),
                                    "profile_path": prof_str,
                                    "source_file": str(obj.get("source_path") or prof_str),
                                    "source_path": str(obj.get("source_path") or prof_str),
                                    "record_type": str(obj.get("artifact_type") or obj.get("type") or "Hindsight"),
                                    "url": str(obj.get("url") or ""),
                                    "title": str(obj.get("title") or obj.get("value") or ""),
                                    "value": str(obj.get("value") or ""),
                                    "timestamp_utc": clean_ts,
                                    "visit_time_utc": clean_ts,
                                    "interpretation": str(obj.get("interpretation") or json.dumps(obj)[:4000]),
                                }
                                rows_to_insert.append([val_lookup[k] for k in target_col_keys])

                            cur.executemany(
                                f'INSERT INTO "raw_hindsight" ({actual_cols_sql}) VALUES ({placeholders_sql});',
                                rows_to_insert,
                            )
                        ingested += len(parsed_objs)

            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:Hindsight",
                "hindsight CLI",
                "SUCCESS",
                rows=ingested,
                duration_ms=dur,
            )
            return {"raw_hindsight": ingested}
        except Exception as hs_err:
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:Hindsight",
                "Hindsight",
                "WARNING",
                duration_ms=dur,
                exit_code=1,
                error=str(hs_err),
            )
            return {}

    def _run_regripper_stage(
        self,
        selected_set: Optional[Set[str]],
        workers: int,
    ) -> Dict[str, Any]:
        """Execute RegRipper 4.0 hive plugin analysis when registry artifacts are enabled."""
        if selected_set is not None and not (selected_set & REGRIPPER_IDS):
            self._record_stage_telemetry("Pipeline:RegRipper", "RegRipperRunner (deselected)", "SKIPPED")
            return {"status": "SKIPPED", "plugins_parsed": 0}

        t0 = time.time()
        try:
            rr_runner = _call_with_supported_kwargs(
                RegRipperRunner,
                case_id=self.case_id,
                case_dir=self.case_dir,
                log_fn=self._log,
            )
            rr_res = _call_with_supported_kwargs(rr_runner.run, max_workers=workers)
            rows = _extract_row_count(rr_res)
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:RegRipper",
                "RegRipperRunner.run",
                "SUCCESS",
                rows=rows,
                duration_ms=dur,
            )
            return rr_res if isinstance(rr_res, dict) else {"status": "SUCCESS", "plugins_parsed": rows}
        except Exception as rr_err:
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:RegRipper",
                "RegRipperRunner.run",
                "WARNING",
                duration_ms=dur,
                exit_code=1,
                error=str(rr_err),
            )
            return {"status": "WARNING", "plugins_parsed": 0, "error": str(rr_err)}

    def _run_bulk_extractor_stage(
        self,
        should_run: bool,
        evidence_target: Path,
        should_run_carving: bool,
        workers: int,
    ) -> Dict[str, Any]:
        """Lazy-import and execute BulkExtractorRunner when opted-in (`F27`)."""
        if not should_run:
            self._record_stage_telemetry("Pipeline:BulkExtractor", "BulkExtractorRunner (disabled)", "SKIPPED")
            return {"status": "SKIPPED", "rows": 0}

        t0 = time.time()
        BulkExtractorCls = None
        for mod_name in ("backend.orchestrator.bulk_extractor_runner", "backend.runners.bulk_extractor_runner"):
            try:
                mod = __import__(mod_name, fromlist=["BulkExtractorRunner"])
                BulkExtractorCls = getattr(mod, "BulkExtractorRunner", None)
                if BulkExtractorCls is not None:
                    break
            except ImportError:
                continue

        if BulkExtractorCls is None:
            self._record_stage_telemetry(
                "Pipeline:BulkExtractor",
                "BulkExtractorRunner",
                "WARNING",
                error="BulkExtractorRunner module not available",
            )
            return {"status": "WARNING", "rows": 0}

        try:
            be_runner = _call_with_supported_kwargs(
                BulkExtractorCls,
                case_id=self.case_id,
                case_dir=self.case_dir,
                db_manager=DuckDBManager,
            )
            be_res = _call_with_supported_kwargs(
                be_runner.run,
                source_path=evidence_target,
                max_workers=workers,
                enable_carving=should_run_carving,
            )
            rows = _extract_row_count(be_res)
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:BulkExtractor",
                "BulkExtractorRunner.run",
                "SUCCESS",
                rows=rows,
                duration_ms=dur,
            )
            return be_res if isinstance(be_res, dict) else {"status": "SUCCESS", "rows": rows}
        except Exception as be_err:
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:BulkExtractor",
                "BulkExtractorRunner.run",
                "ERROR",
                duration_ms=dur,
                exit_code=1,
                error=str(be_err),
            )
            return {"status": "ERROR", "rows": 0, "error": str(be_err)}

    def _run_data_carver_stage(
        self,
        should_run: bool,
        evidence_target: Path,
        workers: int,
    ) -> Dict[str, Any]:
        """Lazy-import and execute DataCarver when opted-in (`F26`)."""
        if not should_run:
            self._record_stage_telemetry("Pipeline:DataCarver", "DataCarver (disabled)", "SKIPPED")
            return {"status": "SKIPPED", "rows": 0}

        t0 = time.time()
        DataCarverCls = None
        for mod_name in ("backend.parsers.data_carver", "backend.parsers.carver"):
            try:
                mod = __import__(mod_name, fromlist=["DataCarver"])
                DataCarverCls = getattr(mod, "DataCarver", None)
                if DataCarverCls is not None:
                    break
            except ImportError:
                continue

        if DataCarverCls is None:
            self._record_stage_telemetry(
                "Pipeline:DataCarver",
                "DataCarver",
                "WARNING",
                error="DataCarver module not available",
            )
            return {"status": "WARNING", "rows": 0}

        try:
            with DuckDBManager.get_lock(self.case_id):
                carver = _call_with_supported_kwargs(
                    DataCarverCls,
                    case_id=self.case_id,
                    case_dir=self.case_dir,
                    staging_dir=self.staging_dir,
                    db_manager=DuckDBManager,
                )
            fn = getattr(carver, "run", None) or getattr(carver, "carve", None) or getattr(carver, "parse", None)
            carve_res = _call_with_supported_kwargs(
                fn,
                source_path=evidence_target,
                staging_dir=self.staging_dir,
                max_workers=workers,
            )
            rows = _extract_row_count(carve_res)
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:DataCarver",
                "DataCarver.run",
                "SUCCESS",
                rows=rows,
                duration_ms=dur,
            )
            return carve_res if isinstance(carve_res, dict) else {"status": "SUCCESS", "rows": rows}
        except Exception as dc_err:
            dur = int((time.time() - t0) * 1000)
            self._record_stage_telemetry(
                "Pipeline:DataCarver",
                "DataCarver.run",
                "ERROR",
                duration_ms=dur,
                exit_code=1,
                error=str(dc_err),
            )
            return {"status": "ERROR", "rows": 0, "error": str(dc_err)}

    def run_custom_parsers(
        self,
        selected_artifacts: Optional[Iterable[str]] = None,
        max_workers: Optional[int] = None,
    ) -> Dict[str, int]:
        """
        Execute custom forensic parsers concurrently via ThreadPoolExecutor,
        gated by `selected_artifacts` and serialized safely on DuckDB writes.
        """
        selected_set = self._normalize_selected_set(selected_artifacts)
        workers = clamp_max_workers(max_workers if max_workers is not None else self.max_workers)

        from backend.parsers import (
            ChatParser,
            ChromiumParser,
            CloudParser,
            CorporateIRParser,
            DocumentParser,
            EmailParser,
            FirefoxParser,
            MediaParser,
            USBDeviceCorrelator,
        )

        parser_specs: List[Tuple[str, Any, Set[str]]] = [
            ("Chromium", ChromiumParser, CHROMIUM_IDS),
            ("Firefox", FirefoxParser, FIREFOX_IDS),
            ("Chat", ChatParser, CHAT_IDS),
            ("Cloud", CloudParser, CLOUD_IDS),
            ("USBCorrelator", USBDeviceCorrelator, USB_IDS),
            ("CorporateIR", CorporateIRParser, CORPORATE_IR_IDS),
            ("Media", MediaParser, MEDIA_IDS),
            ("Document", DocumentParser, DOCUMENT_IDS),
            ("Email", EmailParser, EMAIL_IDS),
        ]

        # Optional RegistryParser if M3/M2 provides it separately
        try:
            from backend.parsers.registry_parser import RegistryParser  # type: ignore
            parser_specs.append(("Registry", RegistryParser, REGRIPPER_IDS))
        except ImportError:
            pass

        enabled_instances: List[Tuple[str, Any]] = []
        for name, cls, id_set in parser_specs:
            if selected_set is not None and not (selected_set & id_set):
                self._record_stage_telemetry(f"Parser:{name}", f"{name}.parse (deselected)", "SKIPPED")
                continue
            try:
                with DuckDBManager.get_lock(self.case_id):
                    inst = _call_with_supported_kwargs(
                        cls,
                        case_id=self.case_id,
                        staging_dir=self.staging_dir,
                        max_workers=workers,
                    )
                enabled_instances.append((name, inst))
            except Exception as init_err:
                self._record_stage_telemetry(
                    f"Parser:{name}",
                    f"{name}.__init__",
                    "ERROR",
                    exit_code=1,
                    error=str(init_err),
                )

        if not enabled_instances:
            return {}

        combined_results: Dict[str, int] = {}
        results_lock = threading.Lock()

        def _exec_single_parser(p_name: str, p_inst: Any) -> None:
            t0 = time.time()
            try:
                res: Dict[str, int] = {}
                if p_name == "CorporateIR" and selected_set is not None and "corporate_ir" not in selected_set:
                    # Check if CorporateIRParser.parse itself accepts selected_artifacts
                    parse_fn = getattr(p_inst, "parse")
                    sig = inspect.signature(parse_fn)
                    if "selected_artifacts" in sig.parameters:
                        raw_res = _call_with_supported_kwargs(
                            parse_fn,
                            selected_artifacts=sorted(selected_set),
                            max_workers=workers,
                        )
                        if isinstance(raw_res, dict):
                            res.update({str(k): int(v or 0) for k, v in raw_res.items()})
                    else:
                        sub_calls = [
                            (CORPORATE_IR_TASKS_IDS, "parse_scheduled_tasks", "parsed_scheduled_tasks"),
                            (CORPORATE_IR_PS_IDS, "parse_powershell_history", "parsed_powershell_history"),
                            (CORPORATE_IR_RMM_IDS, "parse_rmm_logs", "parsed_rmm_sessions"),
                            (CORPORATE_IR_WPN_IDS, "parse_wpn_database", "parsed_wpn_notifications"),
                            (CORPORATE_IR_WER_IDS, "parse_wer_reports", "parsed_wer_reports"),
                        ]
                        ran_granular = False
                        for sub_ids, sub_method, tbl_key in sub_calls:
                            if selected_set & sub_ids and hasattr(p_inst, sub_method):
                                ran_granular = True
                                sub_val = getattr(p_inst, sub_method)()
                                if isinstance(sub_val, dict):
                                    res.update(_extract_table_counts_dict(sub_val))
                                elif _is_num_not_bool(sub_val):
                                    res[tbl_key] = max(0, int(sub_val))
                        if not ran_granular:
                            raw_res = _call_with_supported_kwargs(parse_fn, max_workers=workers)
                            if isinstance(raw_res, dict):
                                res.update(_extract_table_counts_dict(raw_res))
                else:
                    raw_res = _call_with_supported_kwargs(
                        p_inst.parse,
                        selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        max_workers=workers,
                    )
                    if isinstance(raw_res, dict):
                        res.update(_extract_table_counts_dict(raw_res))

                dur = int((time.time() - t0) * 1000)
                with results_lock:
                    combined_results.update(res)
                self._record_stage_telemetry(
                    f"Parser:{p_name}",
                    f"{p_name}.parse()",
                    "SUCCESS",
                    rows=sum(res.values()),
                    duration_ms=dur,
                )
            except Exception as exc:
                dur = int((time.time() - t0) * 1000)
                self._record_stage_telemetry(
                    f"Parser:{p_name}",
                    f"{p_name}.parse()",
                    "ERROR",
                    rows=0,
                    duration_ms=dur,
                    exit_code=1,
                    error=str(exc),
                )

        pool_size = max(1, min(workers, len(enabled_instances)))
        with ThreadPoolExecutor(max_workers=pool_size) as pool:
            futs = [pool.submit(_exec_single_parser, name, inst) for name, inst in enabled_instances]
            for fut in as_completed(futs):
                fut.result()

        return combined_results

    def run(
        self,
        source_type: str,
        source_path: Optional[Union[str, Path]] = None,
        enable_yara: bool = True,
        enable_stinger: bool = True,
        enable_ocr: bool = True,
        enable_hindsight: bool = True,
        enable_ioc: bool = True,
        enable_data_carving: bool = False,
        enable_bulk_extractor: bool = False,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        selected_artifacts: Optional[List[str]] = None,
        initial_keywords: Optional[Union[List[Any], str]] = None,
        case_metadata: Optional[Dict[str, Any]] = None,
        keywords: Optional[Union[List[Any], str]] = None,
        progress_callback: Optional[Callable[..., None]] = None,
    ) -> Dict[str, Any]:
        """
        Execute full concurrent forensic pipeline workflow end-to-end.
        """
        pipeline_start = time.time()
        workers = clamp_max_workers(max_workers if max_workers is not None else self.max_workers)
        self.max_workers = workers

        selected_set = self._normalize_selected_set(selected_artifacts)
        if selected_set is not None and len(selected_set) > 0 and not (selected_set & ALL_KNOWN_SELECTION_IDS):
            self._record_stage_telemetry(
                "Pipeline:ArtifactFilter",
                f"Unknown selected_artifacts={sorted(selected_set)}",
                "WARNING",
                error="No known artifact IDs matched; falling back to standard parser suite",
            )
            selected_set = None

        should_run_vss = bool(enable_vss) or (selected_set is not None and bool(selected_set & VSS_IDS))
        should_run_carving = bool(enable_data_carving) or (selected_set is not None and bool(selected_set & CARVING_IDS))
        should_run_bulk_extractor = bool(enable_bulk_extractor) or (
            selected_set is not None and bool(selected_set & BULK_EXTRACTOR_IDS)
        )

        # Effective Enrichment booleans (`M4 SCOPE.md` §52 + selected_artifacts gating; enable_*=False ALWAYS disables!)
        if selected_set is None:
            eff_yara = bool(enable_yara)
            eff_stinger = bool(enable_stinger)
            eff_ocr = bool(enable_ocr)
            eff_ioc = bool(enable_ioc)
        else:
            eff_yara = bool(enable_yara) and bool(selected_set & (ENRICHMENT_YARA_IDS | ENRICHMENT_IOC_IDS))
            eff_stinger = bool(enable_stinger) and bool(
                selected_set & (ENRICHMENT_STINGER_IDS | ENRICHMENT_YARA_IDS | ENRICHMENT_IOC_IDS)
            )
            eff_ocr = bool(enable_ocr) and bool(selected_set & ENRICHMENT_OCR_IDS)
            eff_ioc = bool(enable_ioc) and bool(selected_set & ENRICHMENT_IOC_IDS)

        self._update_status(
            "RUNNING",
            5,
            f"Initializing DuckDB Schema (threads={workers})...",
            progress_callback=progress_callback,
        )

        try:
            # -------------------------------------------------------------
            # STEP 1: Initialize Database Schema, Threads, Metadata & Keywords
            # -------------------------------------------------------------
            t_init = time.time()
            init_case_db(self.case_id)
            configured_threads = DuckDBManager.configure_threads(self.case_id, workers)
            with DuckDBManager.get_lock(self.case_id):
                fresh_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                if hasattr(self.enricher, "conn"):
                    self.enricher.conn = fresh_conn
                if hasattr(self.normalizer, "_ensure_open_conn"):
                    self.normalizer._ensure_open_conn()

            raw_src_type = str(source_type or "").strip().lower()
            if raw_src_type in {"folder", "directory", "dir", "logical"}:
                norm_source_type = "folder"
            elif raw_src_type in {"live", "live_triage"}:
                norm_source_type = "live"
            elif raw_src_type in {
                "image", "disk_image", "disk", "e01", "ex01", "ewf",
                "raw", "dd", "img", "vhdx", "vhd", "vmdk", "iso",
            }:
                norm_source_type = "image"
            else:
                raise ValueError(
                    f"Unsupported source_type '{source_type}'. "
                    f"Must be one of: 'folder', 'directory', 'live', 'live_triage', 'image', 'disk_image'."
                )

            clean_source_path = (
                str(source_path).strip().strip('"').strip("'").strip()
                if source_path is not None and str(source_path).strip()
                else None
            )

            meta_count = self._persist_case_metadata(
                norm_source_type=norm_source_type,
                clean_source_path=clean_source_path,
                workers=configured_threads,
                should_run_carving=should_run_carving,
                should_run_bulk_extractor=should_run_bulk_extractor,
                should_run_vss=should_run_vss,
                selected_set=selected_set,
                case_metadata=case_metadata,
            )

            seeded_kw = self._seed_keywords(keywords=keywords, initial_keywords=initial_keywords)
            if seeded_kw > 0:
                self._record_stage_telemetry(
                    "Pipeline:KeywordsInit",
                    "Seed case_keywords",
                    "SUCCESS",
                    rows=seeded_kw,
                    duration_ms=int((time.time() - t_init) * 1000),
                )

            self._record_stage_telemetry(
                "Pipeline:Init",
                f"init_case_db(threads={configured_threads})",
                "SUCCESS",
                rows=meta_count,
                duration_ms=int((time.time() - t_init) * 1000),
            )

            # -------------------------------------------------------------
            # STEP 2: Evidence Extraction (+ optional VSS)
            # -------------------------------------------------------------
            IMAGE_EXTENSIONS = {
                ".e01", ".ex01", ".vhdx", ".vhd", ".vmdk", ".raw", ".dd", ".img", ".iso",
            }
            ARCHIVE_EXTENSIONS = {
                ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
            }

            self._update_status(
                "RUNNING",
                15,
                f"Extracting evidence from {norm_source_type}...",
                progress_callback=progress_callback,
            )

            extractor_start = time.time()
            extractor_res: Dict[str, Any] = {}
            effective_evidence_target: Path = self.staging_dir
            logged_source_target: str = clean_source_path or "live"

            if norm_source_type == "folder":
                if not clean_source_path:
                    raise ValueError("source_path is required when source_type is 'folder' or 'directory'")
                resolved_src = Path(clean_source_path).resolve()
                if not resolved_src.exists():
                    raise FileNotFoundError(f"Source folder does not exist: {resolved_src}")
                effective_evidence_target = resolved_src
                logged_source_target = str(resolved_src)

                if resolved_src.is_file():
                    ext = resolved_src.suffix.lower()
                    if ext in IMAGE_EXTENSIONS:
                        extractor_res = _call_with_supported_kwargs(
                            self.extractor.extract_from_image,
                            image_path=resolved_src,
                            staging_dir=self.staging_dir,
                            enable_vss=should_run_vss,
                            max_workers=workers,
                            selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        )
                    else:
                        extractor_res = _call_with_supported_kwargs(
                            self.extractor.extract_from_directory,
                            source_dir=resolved_src.parent,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                            enable_vss=should_run_vss,
                            max_workers=workers,
                            selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        )
                else:
                    extractor_res = _call_with_supported_kwargs(
                        self.extractor.extract_from_directory,
                        source_dir=resolved_src,
                        staging_dir=self.staging_dir,
                        unpack_archives=True,
                        enable_vss=should_run_vss,
                        max_workers=workers,
                        selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                    )

            elif norm_source_type == "live":
                extractor_res = _call_with_supported_kwargs(
                    self.extractor.collect_live_triage,
                    staging_dir=self.staging_dir,
                    enable_vss=should_run_vss,
                    max_workers=workers,
                    selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                )
                effective_evidence_target = self.staging_dir
                logged_source_target = "live"

            elif norm_source_type == "image":
                if not clean_source_path:
                    raise ValueError("source_path is required when source_type is 'image'")
                resolved_src = Path(clean_source_path).resolve()
                if not resolved_src.exists():
                    raise FileNotFoundError(f"Source disk image does not exist: {resolved_src}")

                if resolved_src.is_dir():
                    contained_images = [
                        child
                        for child in sorted(resolved_src.iterdir())
                        if child.is_file() and child.suffix.lower() in IMAGE_EXTENSIONS
                    ]
                    e01_candidates = [c for c in contained_images if c.suffix.lower() in {".e01", ".ex01"}]
                    target_image = e01_candidates[0] if e01_candidates else (contained_images[0] if contained_images else None)
                    if target_image:
                        effective_evidence_target = target_image
                        logged_source_target = str(target_image)
                        extractor_res = _call_with_supported_kwargs(
                            self.extractor.extract_from_image,
                            image_path=target_image,
                            staging_dir=self.staging_dir,
                            enable_vss=should_run_vss,
                            max_workers=workers,
                            selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        )
                    else:
                        effective_evidence_target = resolved_src
                        logged_source_target = str(resolved_src)
                        extractor_res = _call_with_supported_kwargs(
                            self.extractor.extract_from_directory,
                            source_dir=resolved_src,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                            enable_vss=should_run_vss,
                            max_workers=workers,
                            selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        )
                else:
                    effective_evidence_target = resolved_src
                    logged_source_target = str(resolved_src)
                    ext = resolved_src.suffix.lower()
                    if ext in ARCHIVE_EXTENSIONS:
                        extractor_res = _call_with_supported_kwargs(
                            self.extractor.extract_from_directory,
                            source_dir=resolved_src.parent,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                            enable_vss=should_run_vss,
                            max_workers=workers,
                            selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        )
                    else:
                        extractor_res = _call_with_supported_kwargs(
                            self.extractor.extract_from_image,
                            image_path=resolved_src,
                            staging_dir=self.staging_dir,
                            enable_vss=should_run_vss,
                            max_workers=workers,
                            selected_artifacts=sorted(selected_set) if selected_set is not None else None,
                        )

            extractor_duration = int((time.time() - extractor_start) * 1000)
            files_staged = int((extractor_res or {}).get("total_files_staged", 0) or 0)
            ext_status = str((extractor_res or {}).get("status", "SUCCESS") or "SUCCESS")

            # CRITICAL contract for `backend/main.py:1467` (`command_executed LIKE 'Extractor (%'`)
            self._record_stage_telemetry(
                "Pipeline:Extractor",
                f"Extractor ({norm_source_type}): {logged_source_target}",
                ext_status,
                rows=files_staged,
                duration_ms=extractor_duration,
                exit_code=0 if ext_status in {"SUCCESS", "WARNING"} else 1,
            )

            # -------------------------------------------------------------
            # STEP 3: Concurrent Runners, Carving & Application Parsers
            # -------------------------------------------------------------
            self._update_status(
                "RUNNING",
                40,
                f"Extraction complete ({files_staged} files staged). Running concurrent artifact engines...",
                progress_callback=progress_callback,
            )

            # Pre-run `rla.exe` once if registry-backed tools will run concurrently
            any_reg_needed = (
                selected_set is None
                or bool(selected_set & REGRIPPER_IDS)
                or bool(selected_set & USB_IDS)
                or any(req_rla and bool(selected_set & grp) for _, grp, req_rla in EZ_TOOL_GROUPS)
            )
            if any_reg_needed and hasattr(self.runner, "run_rla"):
                try:
                    self.runner.run_rla()
                except Exception as rla_pre_err:
                    self._log(f"Notice during upfront rla hive transaction replay: {rla_pre_err}", "WARNING")

            ez_results: Dict[str, int] = {}
            native_fallback_results: Dict[str, int] = {}
            hindsight_results: Dict[str, int] = {}
            regripper_res: Dict[str, Any] = {}
            bulk_extractor_res: Dict[str, Any] = {}
            carver_res: Dict[str, Any] = {}
            parser_results: Dict[str, int] = {}

            def _ez_and_fallbacks_worker() -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
                ez_r = self._run_ez_stage(selected_set=selected_set, workers=workers, enable_hindsight=enable_hindsight)
                nfp_r = self._run_native_fallbacks_stage(selected_set=selected_set, workers=workers)
                hs_r = self._run_hindsight_stage(
                    selected_set=selected_set,
                    enable_hindsight=enable_hindsight,
                    ez_results=ez_r,
                    workers=workers,
                )
                return ez_r, nfp_r, hs_r

            stage_workers = max(1, min(workers, 32))
            with ThreadPoolExecutor(max_workers=stage_workers) as stage_pool:
                f_ez = stage_pool.submit(_ez_and_fallbacks_worker)
                f_rr = stage_pool.submit(self._run_regripper_stage, selected_set, workers)
                f_be = stage_pool.submit(
                    self._run_bulk_extractor_stage,
                    should_run_bulk_extractor,
                    effective_evidence_target,
                    should_run_carving,
                    workers,
                )
                f_dc = stage_pool.submit(
                    self._run_data_carver_stage,
                    should_run_carving,
                    effective_evidence_target,
                    workers,
                )
                f_parsers = stage_pool.submit(
                    self.run_custom_parsers,
                    sorted(selected_set) if selected_set is not None else None,
                    workers,
                )

                ez_results, native_fallback_results, hindsight_results = f_ez.result()
                regripper_res = f_rr.result()
                bulk_extractor_res = f_be.result()
                carver_res = f_dc.result()
                parser_results = f_parsers.result()

            # -------------------------------------------------------------
            # STEP 4: File Enrichment (IOC/SHA256, YARA-X, Stinger, RapidOCR)
            # -------------------------------------------------------------
            enrichment_results: Dict[str, int] = {}
            if any([eff_yara, eff_stinger, eff_ocr, eff_ioc]):
                self._update_status(
                    "RUNNING",
                    72,
                    "Executing File Enrichment (IOC / YARA-X / Stinger / RapidOCR)...",
                    progress_callback=progress_callback,
                )
                t_enr = time.time()
                try:
                    enr_fn = getattr(self.enricher, "run_full_enrichment", None) or getattr(self.enricher, "run")
                    enr_raw = _call_with_supported_kwargs(
                        enr_fn,
                        enable_yara=eff_yara,
                        enable_stinger=eff_stinger,
                        enable_ocr=eff_ocr,
                        enable_ioc=eff_ioc,
                        max_workers=workers,
                    )
                    if isinstance(enr_raw, dict):
                        enrichment_results = _extract_table_counts_dict(enr_raw)
                    self._record_stage_telemetry(
                        "Pipeline:Enrichment",
                        "FileEnrichmentEngine.run",
                        "SUCCESS",
                        rows=sum(enrichment_results.values()),
                        duration_ms=int((time.time() - t_enr) * 1000),
                    )
                except Exception as enrich_err:
                    self._record_stage_telemetry(
                        "Pipeline:Enrichment",
                        "FileEnrichmentEngine.run",
                        "WARNING",
                        rows=0,
                        duration_ms=int((time.time() - t_enr) * 1000),
                        exit_code=1,
                        error=str(enrich_err),
                    )
            else:
                self._record_stage_telemetry("Pipeline:Enrichment", "FileEnrichmentEngine (disabled)", "SKIPPED")

            total_raw_rows = sum(ez_results.values()) + sum(native_fallback_results.values()) + sum(hindsight_results.values())
            total_parsed_rows = sum(parser_results.values())
            total_enrich_rows = sum(enrichment_results.values())
            regripper_rows = _extract_row_count(regripper_res)
            be_rows = _extract_row_count(bulk_extractor_res)
            carved_rows = _extract_row_count(carver_res)
            total_artifact_rows = (
                total_raw_rows + total_parsed_rows + total_enrich_rows + regripper_rows + be_rows + carved_rows
            )

            # -------------------------------------------------------------
            # STEP 5: Timeline & Entity Graph Normalization
            # -------------------------------------------------------------
            self._update_status(
                "RUNNING",
                84,
                f"Artifacts ingested ({total_artifact_rows} rows). Building MACB Super-Timeline...",
                progress_callback=progress_callback,
            )
            normalizer_start = time.time()
            norm_results = _call_with_supported_kwargs(
                self.normalizer.normalize_all,
                sync_registry=False,
            )
            normalizer_duration = int((time.time() - normalizer_start) * 1000)

            total_tl_rows = int(norm_results.get("total_timeline_rows", 0) or 0)
            total_ent_rows = int(norm_results.get("total_entity_rows", 0) or 0)
            self._record_stage_telemetry(
                "Pipeline:Normalizer",
                "TimelineNormalizer.normalize_all",
                "SUCCESS",
                rows=total_tl_rows + total_ent_rows,
                duration_ms=normalizer_duration,
            )

            # -------------------------------------------------------------
            # STEP 5b: Artifact Registry Synchronization + Keyword Search
            # -------------------------------------------------------------
            self._update_status(
                "RUNNING",
                93,
                "Synchronizing artifact registry and executing keyword search...",
                progress_callback=progress_callback,
            )
            t_sync = time.time()
            try:
                with DuckDBManager.get_lock(self.case_id):
                    sync_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                    synced_counts = sync_artifact_registry_counts(sync_conn, case_id=self.case_id)
                sync_rows = int(synced_counts) if isinstance(synced_counts, (int, float)) else len(synced_counts or {})
                self._record_stage_telemetry(
                    "Pipeline:RegistrySync",
                    "sync_artifact_registry_counts",
                    "SUCCESS",
                    rows=sync_rows,
                    duration_ms=int((time.time() - t_sync) * 1000),
                )
            except Exception as sync_err:
                self._record_stage_telemetry(
                    "Pipeline:RegistrySync",
                    "sync_artifact_registry_counts",
                    "WARNING",
                    duration_ms=int((time.time() - t_sync) * 1000),
                    exit_code=1,
                    error=str(sync_err),
                )

            keyword_res: Dict[str, Any] = {"keywords_scanned": 0, "total_hits": 0}
            t_kw = time.time()
            try:
                with DuckDBManager.get_lock(self.case_id):
                    kw_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                    kw_cnt = int(kw_conn.cursor().execute("SELECT COUNT(*) FROM case_keywords;").fetchone()[0] or 0)
                if kw_cnt > 0:
                    kw_scan_out = _call_with_supported_kwargs(
                        scan_keywords_for_case,
                        self.case_id,
                        max_workers=workers,
                    )
                    if isinstance(kw_scan_out, dict):
                        keyword_res.update(kw_scan_out)
                    elif isinstance(kw_scan_out, (int, float)):
                        keyword_res = {"keywords_scanned": kw_cnt, "total_hits": int(kw_scan_out)}
                    with DuckDBManager.get_lock(self.case_id):
                        sync_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                        sync_artifact_registry_counts(sync_conn, case_id=self.case_id)
                    self._record_stage_telemetry(
                        "Pipeline:KeywordSearch",
                        "scan_keywords_for_case",
                        "SUCCESS",
                        rows=int(keyword_res.get("total_hits", 0) or 0),
                        duration_ms=int((time.time() - t_kw) * 1000),
                    )
                else:
                    self._record_stage_telemetry(
                        "Pipeline:KeywordSearch",
                        "scan_keywords_for_case (0 keywords)",
                        "SKIPPED",
                        rows=0,
                        duration_ms=int((time.time() - t_kw) * 1000),
                    )
            except Exception as kw_scan_err:
                self._record_stage_telemetry(
                    "Pipeline:KeywordSearch",
                    "scan_keywords_for_case",
                    "WARNING",
                    duration_ms=int((time.time() - t_kw) * 1000),
                    exit_code=1,
                    error=str(kw_scan_err),
                )

            # -------------------------------------------------------------
            # STEP 6: Final Wrap-up
            # -------------------------------------------------------------
            total_duration_ms = int((time.time() - pipeline_start) * 1000)
            self._record_stage_telemetry(
                "Pipeline",
                f"Pipeline Completed for case {self.case_id}",
                "SUCCESS",
                rows=total_artifact_rows,
                duration_ms=total_duration_ms,
            )

            try:
                with DuckDBManager.get_lock(self.case_id):
                    _, db_key = DuckDBManager._resolve_db_key(self.case_id)
                    if db_key in DuckDBManager._connections:
                        try:
                            if db_key not in DuckDBManager._ro_connections:
                                final_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                                final_conn.cursor().execute("CHECKPOINT;")
                        except Exception:
                            pass
                        DuckDBManager.close_connection(self.case_id)
            except Exception:
                pass

            self._update_status(
                "SUCCESS",
                100,
                (
                    f"Processing complete! {total_artifact_rows} artifact rows, "
                    f"{total_tl_rows} timeline events, {total_ent_rows} connections."
                ),
                progress_callback=progress_callback,
            )

            return {
                "status": "SUCCESS",
                "case_id": self.case_id,
                "duration_ms": total_duration_ms,
                "max_workers": configured_threads,
                "extractor": extractor_res,
                "ez_results": ez_results,
                "native_fallback_results": native_fallback_results,
                "hindsight_results": hindsight_results,
                "regripper_results": regripper_res,
                "bulk_extractor_results": bulk_extractor_res,
                "carver_results": carver_res,
                "parser_results": parser_results,
                "enrichment_results": enrichment_results,
                "norm_results": norm_results,
                "keyword_results": keyword_res,
                "total_artifact_rows": total_artifact_rows,
                "total_timeline_rows": total_tl_rows,
                "total_entity_rows": total_ent_rows,
            }

        except Exception as exc:
            duration_ms = int((time.time() - pipeline_start) * 1000)
            try:
                self._record_stage_telemetry(
                    "Pipeline",
                    f"Pipeline execution for {self.case_id}",
                    "ERROR",
                    rows=0,
                    duration_ms=duration_ms,
                    exit_code=1,
                    error=str(exc),
                )
            except Exception as log_err:
                self._log(f"Failed to record error event in DB: {log_err}", "WARNING")

            try:
                with DuckDBManager.get_lock(self.case_id):
                    _, db_key = DuckDBManager._resolve_db_key(self.case_id)
                    if db_key in DuckDBManager._connections:
                        try:
                            if db_key not in DuckDBManager._ro_connections:
                                err_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                                err_conn.cursor().execute("CHECKPOINT;")
                        except Exception:
                            pass
                        DuckDBManager.close_connection(self.case_id)
            except Exception:
                pass

            self._update_status(
                "ERROR",
                100,
                f"Pipeline failed: {exc}",
                error=str(exc),
                progress_callback=progress_callback,
            )
            raise
        finally:
            try:
                with DuckDBManager.get_lock(self.case_id):
                    _, db_key = DuckDBManager._resolve_db_key(self.case_id)
                    if db_key in DuckDBManager._connections:
                        try:
                            if db_key not in DuckDBManager._ro_connections:
                                final_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                                final_conn.cursor().execute("CHECKPOINT;")
                        except Exception:
                            pass
                        DuckDBManager.close_connection(self.case_id)
            except Exception:
                pass


def run_pipeline(
    case_id: str,
    source_type: str,
    source_path: Optional[Union[str, Path]] = None,
    enable_yara: bool = True,
    enable_ocr: bool = True,
    keywords: Optional[Union[List[Any], str]] = None,
    target_dir: Optional[Union[str, Path]] = None,
    progress_callback: Optional[Callable[..., None]] = None,
    enable_stinger: bool = True,
    enable_hindsight: bool = True,
    enable_ioc: bool = True,
    enable_data_carving: bool = False,
    enable_bulk_extractor: bool = False,
    enable_vss: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
    selected_artifacts: Optional[List[str]] = None,
    initial_keywords: Optional[Union[List[Any], str]] = None,
    case_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience function to instantiate and run ProcessingPipeline while preserving
    100% positional and keyword argument compatibility with all callers.
    """
    pipeline = ProcessingPipeline(
        case_id=case_id,
        target_dir=target_dir,
        max_workers=max_workers,
    )
    return pipeline.run(
        source_type=source_type,
        source_path=source_path,
        enable_yara=enable_yara,
        enable_stinger=enable_stinger,
        enable_ocr=enable_ocr,
        enable_hindsight=enable_hindsight,
        enable_ioc=enable_ioc,
        enable_data_carving=enable_data_carving,
        enable_bulk_extractor=enable_bulk_extractor,
        enable_vss=enable_vss,
        max_workers=max_workers,
        selected_artifacts=selected_artifacts,
        initial_keywords=initial_keywords,
        case_metadata=case_metadata,
        keywords=keywords,
        progress_callback=progress_callback,
    )
