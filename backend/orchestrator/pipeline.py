"""
Windows Forensic Toolkit (WFT) DFIR Suite - Master Processing Pipeline
Chains EvidenceExtractor -> EZToolRunner -> TimelineNormalizer
with real-time progress tracking, audit logging, and zero stubs.
"""
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from backend.config import (
    BASE_DIR,
    get_case_dir,
    get_case_log_file,
    get_case_staging_dir,
    get_case_csv_out_dir,
    get_case_db_path,
    register_case_dir,
)
from backend.db.engine import DuckDBManager, init_case_db, log_processing_event
from backend.orchestrator.enrichment import FileEnrichmentEngine
from backend.orchestrator.ez_runner import EZToolRunner
from backend.orchestrator.regripper_runner import RegRipperRunner
from backend.orchestrator.normalizer import TimelineNormalizer
from backend.vfs.extractor import EvidenceExtractor
from backend.parsers import (
    ChromiumParser,
    FirefoxParser,
    ChatParser,
    CloudParser,
    CorporateIRParser,
    DocumentParser,
    EmailParser,
    MediaParser,
    USBDeviceCorrelator,
)

# In-memory status tracker for live API queries
PIPELINE_JOBS: Dict[str, Dict[str, Any]] = {}


def get_job_status(case_id: str) -> Dict[str, Any]:
    """
    Retrieve live in-memory job status for a given case_id.
    If not in memory, attempts to infer status from DuckDB processing_logs.
    """
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

            # Check if pipeline finished
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
      1. EvidenceExtractor (VFS collection / directory extraction / live triage)
      2. EZToolRunner (Runs Eric Zimmerman CLI tools and ingests CSVs into DuckDB raw_* tables)
      3. TimelineNormalizer (Introspects raw tables and populates master_timeline and entity_connections)
    """

    def __init__(self, case_id: str, target_dir: Optional[Union[str, Path]] = None) -> None:
        self.case_id = case_id
        if target_dir and str(target_dir).strip():
            from backend.config import register_case_dir
            self.case_dir = register_case_dir(case_id, str(target_dir).strip())
        else:
            self.case_dir = get_case_dir(case_id)
        self.staging_dir = (self.case_dir / "staging").resolve()
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.csv_out_dir = (self.case_dir / "csv_out").resolve()
        self.csv_out_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = (self.case_dir / "processing.log").resolve()

        # Initialize core components
        self.extractor = EvidenceExtractor(
            case_id=case_id,
            staging_dir=self.staging_dir,
            log_file=self.log_file,
        )
        self.runner = EZToolRunner(
            case_id=case_id,
            staging_dir=self.staging_dir,
            csv_out_dir=self.csv_out_dir,
        )
        self.enricher = FileEnrichmentEngine(
            case_id=case_id,
            staging_dir=self.staging_dir,
        )
        self.normalizer = TimelineNormalizer(case_id=case_id)

    def _log(self, message: str, level: str = "INFO") -> None:
        """Helper to append timestamped logs to the case processing log file and console."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level}] [Pipeline] {message}")
        try:
            if self.log_file:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] [{level}] {message}\n")
        except Exception:
            pass

    def run_custom_parsers(self) -> Dict[str, int]:
        """
        Execute all custom forensic parsers:
          - ChromiumParser (Chrome, Edge, Brave History, Downloads, Logins)
          - FirefoxParser (places.sqlite, cookies.sqlite, logins.json)
          - ChatParser (Teams, Discord, Slack LevelDB & SQLite messages)
          - CloudParser (OneDrive & Google Drive metadata)
          - USBDeviceCorrelator (setupapi.dev.log + SYSTEM/SOFTWARE Registry hives)
        """
        print(f"\n{'='*70}\n[ProcessingPipeline] Executing Non-EZ Forensic Parsers\n{'='*70}")
        parser_start = time.time()
        combined_results: Dict[str, int] = {}

        parsers = [
            ("Chromium", ChromiumParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("Firefox", FirefoxParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("Chat", ChatParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("Cloud", CloudParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("USBCorrelator", USBDeviceCorrelator(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("CorporateIR", CorporateIRParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("Media", MediaParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("Document", DocumentParser(case_id=self.case_id, staging_dir=self.staging_dir)),
            ("Email", EmailParser(case_id=self.case_id, staging_dir=self.staging_dir)),
        ]

        for name, parser in parsers:
            try:
                res = parser.parse()
                combined_results.update(res)
            except Exception as exc:
                print(f"[ProcessingPipeline] [WARNING] Parser {name} failed: {exc}\n{traceback.format_exc()}")
                log_processing_event(
                    case_id=self.case_id,
                    module_name=f"Parser:{name}",
                    command_executed=f"{name}.parse()",
                    exit_code=1,
                    rows_ingested=0,
                    duration_ms=0,
                    status="ERROR",
                    error_message=str(exc),
                )

        duration_ms = int((time.time() - parser_start) * 1000)
        total_parsed = sum(combined_results.values())
        print(f"[ProcessingPipeline] Non-EZ Parsers complete in {duration_ms}ms: {total_parsed} rows across {len(combined_results)} tables")
        return combined_results

    def _update_status(
        self,
        status: str,
        progress: int,
        step: str,
        error: Optional[str] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        """
        Update in-memory job tracker and invoke callback if provided.
        """
        now_str = datetime.now(timezone.utc).isoformat()
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
                progress_callback(progress, step)
            except Exception as cb_err:
                print(f"[Pipeline] Warning: progress_callback error: {cb_err}")

    def run(
        self,
        source_type: str,
        source_path: Optional[Union[str, Path]] = None,
        enable_yara: bool = False,
        enable_ocr: bool = False,
        keywords: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Execute full pipeline workflow end-to-end:
          Step 1: Database Initialization
          Step 2: Evidence Extraction (Directory / Live Triage / Disk Image)
          Step 3: EZ Tools Execution & Zero-Copy CSV Ingestion
          Step 4: Timeline & Entity Graph Normalization
        """
        pipeline_start = time.time()
        print(f"\n{'='*80}\n[ProcessingPipeline] Starting run for case '{self.case_id}'\n{'='*80}")
        print(f"Source Type: {source_type} | Source Path: {source_path}")
        print(f"YARA Enabled: {enable_yara} | OCR Enabled: {enable_ocr}")

        self._update_status("RUNNING", 5, "Initializing DuckDB Schema...", progress_callback)

        try:
            # -------------------------------------------------------------
            # STEP 1: Initialize Database Schema & Pre-configured Keywords
            # -------------------------------------------------------------
            init_case_db(self.case_id)
            if keywords:
                try:
                    import uuid
                    with DuckDBManager.get_lock(self.case_id):
                        kw_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                        kw_cursor = kw_conn.cursor()
                        for kw_item in keywords:
                            clean_kw = str(kw_item).strip()
                            if clean_kw:
                                kw_id = f"kw_{uuid.uuid4().hex[:12]}"
                                kw_cursor.execute("""
                                    INSERT INTO case_keywords (
                                        keyword_id, keyword, is_regex, source_file, hit_count, created_at
                                    ) VALUES (?, ?, FALSE, 'WFT Process', 0, CURRENT_TIMESTAMP)
                                    ON CONFLICT (keyword) DO NOTHING;
                                """, [kw_id, clean_kw])
                except Exception as kw_e:
                    print(f"[Pipeline] Notice initializing keywords: {kw_e}")
            log_processing_event(
                case_id=self.case_id,
                module_name="Pipeline:Init",
                command_executed="init_case_db",
                exit_code=0,
                rows_ingested=0,
                duration_ms=0,
                status="SUCCESS",
            )

            # -------------------------------------------------------------
            # STEP 2: Evidence Extraction
            # -------------------------------------------------------------
            norm_source_type = source_type.strip().lower()
            clean_source_path = (
                str(source_path).strip().strip('"').strip("'").strip()
                if source_path is not None
                else None
            )

            IMAGE_EXTENSIONS = {
                ".e01", ".ex01", ".vhdx", ".vhd", ".vmdk", ".raw", ".dd", ".img", ".iso"
            }
            ARCHIVE_EXTENSIONS = {
                ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"
            }

            self._update_status(
                "RUNNING",
                15,
                f"Extracting evidence from {norm_source_type}...",
                progress_callback=progress_callback,
            )

            extractor_start = time.time()
            extractor_res: Dict[str, Any] = {}

            if norm_source_type in ["folder", "directory"]:
                if not clean_source_path:
                    raise ValueError("source_path is required when source_type is 'folder' or 'directory'")
                resolved_src = Path(clean_source_path).resolve()
                if not resolved_src.exists():
                    raise FileNotFoundError(f"Source folder does not exist: {resolved_src}")

                # Auto-detect if user pointed to an image file or archive file instead of a folder
                if resolved_src.is_file():
                    ext = resolved_src.suffix.lower()
                    if ext in IMAGE_EXTENSIONS:
                        print(f"[Pipeline] Auto-detection: source_type is 'folder' but '{resolved_src.name}' is a disk image. Routing to extract_from_image().")
                        extractor_res = self.extractor.extract_from_image(
                            image_path=resolved_src,
                            staging_dir=self.staging_dir,
                        )
                    elif ext in ARCHIVE_EXTENSIONS:
                        print(f"[Pipeline] Auto-detection: source_type is 'folder' but '{resolved_src.name}' is an archive. Routing to archive extractor.")
                        extractor_res = self.extractor.extract_from_directory(
                            source_dir=resolved_src.parent,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                        )
                    else:
                        print(f"[Pipeline] User pointed to single file '{resolved_src.name}'. Extracting from parent directory {resolved_src.parent}.")
                        extractor_res = self.extractor.extract_from_directory(
                            source_dir=resolved_src.parent,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                        )
                else:
                    extractor_res = self.extractor.extract_from_directory(
                        source_dir=resolved_src,
                        staging_dir=self.staging_dir,
                        unpack_archives=True,
                    )

            elif norm_source_type in ["live", "live_triage"]:
                extractor_res = self.extractor.collect_live_triage(staging_dir=self.staging_dir)

            elif norm_source_type in ["image", "disk_image"]:
                if not clean_source_path:
                    raise ValueError("source_path is required when source_type is 'image'")
                resolved_src = Path(clean_source_path).resolve()
                if not resolved_src.exists():
                    raise FileNotFoundError(f"Source disk image does not exist: {resolved_src}")

                # Auto-detect if user selected 'image' but pointed to a directory
                if resolved_src.is_dir():
                    print(f"[Pipeline] Auto-detection: source_type is 'image' but '{resolved_src}' is a directory. Checking for forensic images...")
                    contained_images = [
                        child for child in sorted(resolved_src.iterdir())
                        if child.is_file() and child.suffix.lower() in IMAGE_EXTENSIONS
                    ]
                    e01_candidates = [c for c in contained_images if c.suffix.lower() in [".e01", ".ex01"]]
                    target_image = e01_candidates[0] if e01_candidates else (contained_images[0] if contained_images else None)

                    if target_image:
                        print(f"[Pipeline] Auto-detection: Found image '{target_image.name}' in directory. Passing to extract_from_image().")
                        extractor_res = self.extractor.extract_from_image(
                            image_path=target_image,
                            staging_dir=self.staging_dir,
                        )
                    else:
                        print(f"[Pipeline] Auto-detection: No disk image found in directory. Falling back to extract_from_directory().")
                        extractor_res = self.extractor.extract_from_directory(
                            source_dir=resolved_src,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                        )
                else:
                    # File
                    ext = resolved_src.suffix.lower()
                    if ext in ARCHIVE_EXTENSIONS:
                        print(f"[Pipeline] Auto-detection: source_type is 'image' but '{resolved_src.name}' is an archive. Routing to archive extractor.")
                        extractor_res = self.extractor.extract_from_directory(
                            source_dir=resolved_src.parent,
                            staging_dir=self.staging_dir,
                            unpack_archives=True,
                        )
                    else:
                        extractor_res = self.extractor.extract_from_image(
                            image_path=resolved_src,
                            staging_dir=self.staging_dir,
                        )
            else:
                raise ValueError(
                    f"Unsupported source_type '{source_type}'. "
                    f"Must be one of: 'folder', 'live_triage', 'image'."
                )

            extractor_duration = int((time.time() - extractor_start) * 1000)
            files_staged = extractor_res.get("total_files_staged", 0)

            log_processing_event(
                case_id=self.case_id,
                module_name="Pipeline:Extractor",
                command_executed=f"Extractor ({norm_source_type}): {source_path or 'live'}",
                exit_code=0 if extractor_res.get("status") in ["SUCCESS", "WARNING"] else 1,
                rows_ingested=files_staged,
                duration_ms=extractor_duration,
                status=extractor_res.get("status", "SUCCESS"),
            )

            self._update_status(
                "RUNNING",
                45,
                f"Extraction complete ({files_staged} files staged). Executing EZ Tools...",
                progress_callback=progress_callback,
            )

            # -------------------------------------------------------------
            # STEP 3: EZ Tools Execution & DuckDB Ingestion
            # -------------------------------------------------------------
            runner_start = time.time()
            ez_results = self.runner.run_all()
            runner_duration = int((time.time() - runner_start) * 1000)
            total_raw_rows = sum(ez_results.values())

            log_processing_event(
                case_id=self.case_id,
                module_name="Pipeline:EZRunner",
                command_executed="EZToolRunner.run_all",
                exit_code=0,
                rows_ingested=total_raw_rows,
                duration_ms=runner_duration,
                status="SUCCESS",
            )

            self._update_status(
                "RUNNING",
                60,
                f"EZ Tools complete ({total_raw_rows} rows ingested). Running non-EZ parsers...",
                progress_callback=progress_callback,
            )

            # -------------------------------------------------------------
            # STEP 4: Custom Forensic Parsers (Browsers, Chat, Cloud, USB)
            # -------------------------------------------------------------
            parser_results = self.run_custom_parsers()
            total_parsed_rows = sum(parser_results.values())

            # -------------------------------------------------------------
            # STEP 4b: File Enrichment (Hashing, YARA-X, RapidOCR)
            # -------------------------------------------------------------
            enrichment_results: Dict[str, int] = {}
            if enable_yara or enable_ocr:
                self._update_status(
                    "RUNNING",
                    70,
                    "Executing File Enrichment (YARA-X / RapidOCR)...",
                    progress_callback=progress_callback,
                )
                try:
                    enrichment_results = self.enricher.run(
                        enable_yara=enable_yara,
                        enable_ocr=enable_ocr,
                    )
                except Exception as enrich_err:
                    print(f"[ProcessingPipeline] Warning: File enrichment error: {enrich_err}\n{traceback.format_exc()}")
                    log_processing_event(
                        case_id=self.case_id,
                        module_name="Pipeline:Enrichment",
                        command_executed="FileEnrichmentEngine.run",
                        exit_code=1,
                        rows_ingested=0,
                        duration_ms=0,
                        status="WARNING",
                        error_message=str(enrich_err),
                    )

            # -------------------------------------------------------------
            # STEP 4c: RegRipper 4.0 Plugin Analysis
            # -------------------------------------------------------------
            self._update_status(
                "RUNNING",
                73,
                "Executing RegRipper 4.0 analysis across all registry hives...",
                progress_callback=progress_callback,
            )
            regripper_rows = 0
            try:
                regripper_runner = RegRipperRunner(case_id=self.case_id, case_dir=self.case_dir)
                rr_res = regripper_runner.run()
                regripper_rows = rr_res.get("plugins_parsed", 0)
                self._log(f"RegRipper 4.0 complete: {regripper_rows} plugin reports ingested.")
            except Exception as rr_err:
                self._log(f"Notice executing RegRipper: {rr_err}", "WARNING")

            total_enrich_rows = sum(enrichment_results.values())
            total_artifact_rows = total_raw_rows + total_parsed_rows + total_enrich_rows + regripper_rows

            self._update_status(
                "RUNNING",
                75,
                f"Parsers, enrichment & RegRipper complete ({total_artifact_rows} total rows). Normalizing timeline...",
                progress_callback=progress_callback,
            )

            # -------------------------------------------------------------
            # STEP 5: Timeline & Entity Graph Normalization
            # -------------------------------------------------------------
            normalizer_start = time.time()
            norm_results = self.normalizer.normalize_all()
            normalizer_duration = int((time.time() - normalizer_start) * 1000)

            total_tl_rows = norm_results.get("total_timeline_rows", 0)
            total_ent_rows = norm_results.get("total_entity_rows", 0)

            log_processing_event(
                case_id=self.case_id,
                module_name="Pipeline:Normalizer",
                command_executed="TimelineNormalizer.normalize_all",
                exit_code=0,
                rows_ingested=total_tl_rows + total_ent_rows,
                duration_ms=normalizer_duration,
                status="SUCCESS",
            )

            # -------------------------------------------------------------
            # STEP 5b: Keyword Scanning
            # -------------------------------------------------------------
            try:
                from backend.db.engine import scan_keywords_for_case
                scan_keywords_for_case(self.case_id)
            except Exception as kw_scan_err:
                print(f"[Pipeline] Notice scanning keywords: {kw_scan_err}")

            # -------------------------------------------------------------
            # STEP 5c: Artifact Registry & Live Row Count Synchronization
            # -------------------------------------------------------------
            try:
                from backend.db.schema import sync_artifact_registry_counts
                sync_artifact_registry_counts(self.conn, case_id=self.case_id)
            except Exception as sync_err:
                print(f"[Pipeline] Warning synchronizing artifact registry: {sync_err}")

            # -------------------------------------------------------------
            # STEP 5: Final Wrap-up
            # -------------------------------------------------------------
            total_duration_ms = int((time.time() - pipeline_start) * 1000)
            log_processing_event(
                case_id=self.case_id,
                module_name="Pipeline",
                command_executed=f"Pipeline Completed for case {self.case_id}",
                exit_code=0,
                rows_ingested=total_raw_rows,
                duration_ms=total_duration_ms,
                status="SUCCESS",
            )

            self._update_status(
                "SUCCESS",
                100,
                f"Processing complete! {total_raw_rows} artifact rows, {total_tl_rows} timeline events, {total_ent_rows} connections.",
                progress_callback=progress_callback,
            )

            print(f"\n{'='*80}")
            print(f"[ProcessingPipeline] SUCCESS for case '{self.case_id}' in {total_duration_ms}ms")
            print(f"  Artifact Rows: {total_raw_rows}")
            print(f"  Timeline Events: {total_tl_rows}")
            print(f"  Entity Connections: {total_ent_rows}")
            print(f"{'='*80}\n")

            return {
                "status": "SUCCESS",
                "case_id": self.case_id,
                "duration_ms": total_duration_ms,
                "extractor": extractor_res,
                "ez_results": ez_results,
                "parser_results": parser_results,
                "enrichment_results": enrichment_results,
                "norm_results": norm_results,
                "total_artifact_rows": total_artifact_rows,
                "total_timeline_rows": total_tl_rows,
                "total_entity_rows": total_ent_rows,
            }

        except Exception as exc:
            duration_ms = int((time.time() - pipeline_start) * 1000)
            err_trace = traceback.format_exc()
            err_msg = f"{exc}\n{err_trace}"
            print(f"\n[ProcessingPipeline] [ERROR] Pipeline failed: {err_msg}")

            try:
                log_processing_event(
                    case_id=self.case_id,
                    module_name="Pipeline",
                    command_executed=f"Pipeline execution for {self.case_id}",
                    exit_code=1,
                    rows_ingested=0,
                    duration_ms=duration_ms,
                    status="ERROR",
                    error_message=str(exc),
                )
            except Exception as log_err:
                print(f"[Pipeline] Warning: Failed to record error event in DB: {log_err}")

            self._update_status(
                "ERROR",
                100,
                f"Pipeline failed: {exc}",
                error=str(exc),
                progress_callback=progress_callback,
            )
            # Never silently swallow errors
            raise


def run_pipeline(
    case_id: str,
    source_type: str,
    source_path: Optional[Union[str, Path]] = None,
    enable_yara: bool = False,
    enable_ocr: bool = False,
    keywords: Optional[List[str]] = None,
    target_dir: Optional[Union[str, Path]] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> Dict[str, Any]:
    """
    Convenience function to instantiate and run ProcessingPipeline.
    """
    pipeline = ProcessingPipeline(case_id=case_id, target_dir=target_dir)
    return pipeline.run(
        source_type=source_type,
        source_path=source_path,
        enable_yara=enable_yara,
        enable_ocr=enable_ocr,
        keywords=keywords,
        progress_callback=progress_callback,
    )
