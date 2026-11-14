"""
Windows Forensic Toolkit (WFT) DFIR Suite - Eric Zimmerman Tools Orchestration Engine
Executes rla.exe and all 11 EZ Tools, ingests generated CSVs into DuckDB,
and updates artifact_registry and processing_logs.
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb

from backend.config import (
    BASE_DIR,
    find_ez_binary,
    find_ez_file,
    get_case_csv_out_dir,
    get_case_db_path,
    get_case_dir,
    get_case_log_file,
    get_case_staging_dir,
)
from backend.db.engine import DuckDBManager, init_case_db, log_processing_event
from backend.db.schema import register_evtx_granular_views, sync_granular_artifacts


class EZToolRunner:
    """
    Forensic runner orchestrating rla.exe and all Eric Zimmerman CLI utilities.
    Ingests all resulting CSV files into DuckDB raw_* tables and tracks them
    inside artifact_registry and processing_logs.
    """

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Path] = None,
        csv_out_dir: Optional[Path] = None,
    ) -> None:
        self.case_id = case_id
        self.case_dir = get_case_dir(case_id).resolve()
        self.staging_dir = (
            staging_dir.resolve() if staging_dir else get_case_staging_dir(case_id).resolve()
        )
        self.csv_out_dir = (
            csv_out_dir.resolve() if csv_out_dir else get_case_csv_out_dir(case_id).resolve()
        )
        self.clean_hives_dir = (self.case_dir / "clean_hives").resolve()
        self.log_file = get_case_log_file(case_id).resolve()

        # Ensure base directories exist
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.csv_out_dir.mkdir(parents=True, exist_ok=True)
        self.clean_hives_dir.mkdir(parents=True, exist_ok=True)

        # Initialize DuckDB case schema
        init_case_db(self.case_id)

    def _log(self, message: str, level: str = "INFO") -> None:
        """Helper to append timestamped logs to the case processing log file and console."""
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level}] [EZToolRunner] {message}")
        try:
            if getattr(self, "log_file", None):
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{ts}] [{level}] [EZToolRunner] {message}\n")
        except Exception:
            pass

    def _execute_subprocess(
        self, module_name: str, cmd_list: List[str], timeout: Optional[int] = 45
    ) -> subprocess.CompletedProcess:
        """
        Execute an external tool binary with exact logging of command, exit code,
        stdout, stderr, and execution duration. Never swallows exceptions silently.
        """
        cmd_str = " ".join([f'"{c}"' if " " in c else c for c in cmd_list])
        print(f"\n[EZToolRunner][{module_name}] Executing: {cmd_str}")

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as tex:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = f"Subprocess timed out after {timeout}s: {cmd_str}"
            print(f"[EZToolRunner][{module_name}] WARNING: {err_msg}")
            log_processing_event(
                case_id=self.case_id,
                module_name=module_name,
                command_executed=cmd_str,
                exit_code=-2,
                rows_ingested=0,
                duration_ms=duration_ms,
                status="WARNING",
                error_message=err_msg,
            )
            return subprocess.CompletedProcess(args=cmd_list, returncode=-2, stdout="", stderr=err_msg)
        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = f"Subprocess launch failed: {exc}"
            print(f"[EZToolRunner][{module_name}] ERROR: {err_msg}")
            log_processing_event(
                case_id=self.case_id,
                module_name=module_name,
                command_executed=cmd_str,
                exit_code=-1,
                rows_ingested=0,
                duration_ms=duration_ms,
                status="ERROR",
                error_message=err_msg,
            )
            raise

        duration_ms = int((time.time() - start_time) * 1000)
        status = "SUCCESS" if proc.returncode == 0 else "WARNING"
        err_msg = proc.stderr.strip() if proc.stderr else None

        print(
            f"[EZToolRunner][{module_name}] Finished with ExitCode={proc.returncode} "
            f"in {duration_ms}ms"
        )
        if proc.stdout and proc.stdout.strip():
            print(f"--- stdout ({module_name}) ---\n{proc.stdout.strip()[:1000]}")
        if proc.stderr and proc.stderr.strip():
            print(f"--- stderr ({module_name}) ---\n{proc.stderr.strip()[:1000]}")

        # Append detailed execution output to processing.log on disk
        log_entry = (
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{module_name}] ExitCode={proc.returncode} "
            f"Duration={duration_ms}ms | Cmd: {cmd_str}\n"
        )
        if proc.stdout and proc.stdout.strip():
            log_entry += f"STDOUT:\n{proc.stdout.strip()}\n"
        if proc.stderr and proc.stderr.strip():
            log_entry += f"STDERR:\n{proc.stderr.strip()}\n"
        log_entry += "-" * 80 + "\n"

        with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
            f.write(log_entry)

        log_processing_event(
            case_id=self.case_id,
            module_name=module_name,
            command_executed=cmd_str,
            exit_code=proc.returncode,
            rows_ingested=0,
            duration_ms=duration_ms,
            status=status,
            error_message=err_msg,
        )

        return proc

    def map_csv_to_table_info(self, tool_name: str, csv_path: Path) -> Dict[str, str]:
        """
        Map a generated CSV filename to table_name, artifact_id, category, display_name,
        and source_tool per GEMINI.md Section 4.3 specification.
        """
        fname = csv_path.name.lower()
        clean_stem = re.sub(r"[^A-Za-z0-9_]+", "_", csv_path.stem).strip("_").lower()

        if tool_name == "pecmd":
            if "timeline" in fname:
                return {
                    "table_name": "raw_pecmd_timeline",
                    "artifact_id": "raw_pecmd_timeline",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Prefetch Execution Timeline",
                    "source_tool": "PECmd",
                }
            return {
                "table_name": "raw_pecmd",
                "artifact_id": "os_prefetch",
                "category": "OPERATING SYSTEM",
                "display_name": "Prefetch (PECmd)",
                "source_tool": "PECmd",
            }

        if tool_name == "amcache":
            if "unassociatedfileentries" in fname:
                return {
                    "table_name": "raw_amcache_files",
                    "artifact_id": "os_amcache_files",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache File Entries",
                    "source_tool": "AmcacheParser",
                }
            if "programentries" in fname:
                return {
                    "table_name": "raw_amcache_programs",
                    "artifact_id": "os_amcache_programs",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Installed Programs",
                    "source_tool": "AmcacheParser",
                }
            if "shortcuts" in fname:
                return {
                    "table_name": "raw_amcache_shortcuts",
                    "artifact_id": "os_amcache_shortcuts",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Shortcuts",
                    "source_tool": "AmcacheParser",
                }
            if "devicecontainers" in fname:
                return {
                    "table_name": "raw_amcache_devices",
                    "artifact_id": "os_amcache_devices",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Device Containers",
                    "source_tool": "AmcacheParser",
                }
            return {
                "table_name": f"raw_amcache_{clean_stem}",
                "artifact_id": f"os_amcache_{clean_stem}",
                "category": "OPERATING SYSTEM",
                "display_name": f"Amcache ({clean_stem})",
                "source_tool": "AmcacheParser",
            }

        if tool_name == "shimcache":
            return {
                "table_name": "raw_shimcache",
                "artifact_id": "os_shimcache",
                "category": "OPERATING SYSTEM",
                "display_name": "AppCompatCache (ShimCache)",
                "source_tool": "AppCompatCacheParser",
            }

        if tool_name == "recentfilecache":
            return {
                "table_name": "raw_recentfilecache",
                "artifact_id": "os_recentfilecache",
                "category": "OPERATING SYSTEM",
                "display_name": "RecentFileCache",
                "source_tool": "RecentFileCacheParser",
            }

        if tool_name == "evtx":
            return {
                "table_name": "raw_evtx",
                "artifact_id": "os_evtx",
                "category": "EVENT LOGS",
                "display_name": "All Event Logs (Combined)",
                "source_tool": "EvtxECmd",
            }

        if tool_name == "mft":
            return {
                "table_name": "raw_mft",
                "artifact_id": "fs_mft",
                "category": "OPERATING SYSTEM",
                "display_name": "Master File Table ($MFT)",
                "source_tool": "MFTECmd",
            }

        if tool_name == "usnjrnl":
            return {
                "table_name": "raw_usnjrnl",
                "artifact_id": "fs_usnjrnl",
                "category": "OPERATING SYSTEM",
                "display_name": "USN Change Journal ($J)",
                "source_tool": "MFTECmd",
            }

        if tool_name == "lecmd":
            return {
                "table_name": "raw_lecmd",
                "artifact_id": "fs_lnk",
                "category": "OPERATING SYSTEM",
                "display_name": "LNK Shortcuts",
                "source_tool": "LECmd",
            }

        if tool_name == "jlecmd":
            if "automaticdestinations" in fname:
                return {
                    "table_name": "raw_jlecmd_auto",
                    "artifact_id": "fs_jumplist_auto",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Automatic Jump Lists",
                    "source_tool": "JLECmd",
                }
            if "customdestinations" in fname:
                return {
                    "table_name": "raw_jlecmd_custom",
                    "artifact_id": "fs_jumplist_custom",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Custom Jump Lists",
                    "source_tool": "JLECmd",
                }
            return {
                "table_name": f"raw_jlecmd_{clean_stem}",
                "artifact_id": f"fs_jumplist_{clean_stem}",
                "category": "OPERATING SYSTEM",
                "display_name": f"Jump Lists ({clean_stem})",
                "source_tool": "JLECmd",
            }

        if tool_name == "shellbags":
            return {
                "table_name": "raw_shellbags",
                "artifact_id": "fs_shellbags",
                "category": "OPERATING SYSTEM",
                "display_name": "Shellbags (Folder Access)",
                "source_tool": "SBECmd",
            }

        if tool_name == "recmd":
            return {
                "table_name": "raw_recmd",
                "artifact_id": "registry_recmd",
                "category": "OPERATING SYSTEM",
                "display_name": "Registry Hives (RECmd)",
                "source_tool": "RECmd",
            }

        if tool_name == "srum":
            if "appresourceuseinfo" in fname:
                return {
                    "table_name": "raw_srum_app",
                    "artifact_id": "network_srum_app",
                    "category": "OPERATING SYSTEM",
                    "display_name": "SRUM Application Resource Usage",
                    "source_tool": "SrumECmd",
                }
            if "networkdatausage" in fname:
                return {
                    "table_name": "raw_srum_net",
                    "artifact_id": "network_srum_net",
                    "category": "OPERATING SYSTEM",
                    "display_name": "SRUM Network Data Usage",
                    "source_tool": "SrumECmd",
                }
            if "networkconnections" in fname:
                return {
                    "table_name": "raw_srum_conn",
                    "artifact_id": "network_srum_conn",
                    "category": "OPERATING SYSTEM",
                    "display_name": "SRUM Network Connections",
                    "source_tool": "SrumECmd",
                }
            return {
                "table_name": f"raw_srum_{clean_stem}",
                "artifact_id": f"network_srum_{clean_stem}",
                "category": "OPERATING SYSTEM",
                "display_name": f"SRUM ({clean_stem})",
                "source_tool": "SrumECmd",
            }

        if tool_name == "sum":
            return {
                "table_name": "raw_sum",
                "artifact_id": "network_sum",
                "category": "OPERATING SYSTEM",
                "display_name": "User Access Logging (SUM)",
                "source_tool": "SumECmd",
            }

        if tool_name == "wxt":
            stem_low = csv_path.stem.lower()
            if "packageid" in stem_low or "package_id" in stem_low:
                return {
                    "table_name": "raw_wxt_package_ids",
                    "artifact_id": "os_wxt_package_ids",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Timeline Package IDs",
                    "source_tool": "WxTCmd",
                }
            elif "operation" in stem_low:
                return {
                    "table_name": "raw_wxt_operations",
                    "artifact_id": "os_wxt_operations",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Timeline Operations",
                    "source_tool": "WxTCmd",
                }
            else:
                return {
                    "table_name": "raw_wxt_activity",
                    "artifact_id": "os_wxt_activity",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Timeline Activities",
                    "source_tool": "WxTCmd",
                }

        if tool_name == "rbcmd":
            return {
                "table_name": "raw_rbcmd",
                "artifact_id": "fs_recyclebin",
                "category": "OPERATING SYSTEM",
                "display_name": "Recycle Bin ($I)",
                "source_tool": "RBCmd",
            }

        if tool_name == "sqlecmd":
            # Strip timestamp prefix (\d{8,25}_) and GUID suffix
            stem_no_ts = re.sub(r"^\d{8,25}_+", "", csv_path.stem)
            stem_no_guid = re.sub(r"_[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}$", "", stem_no_ts)
            stem_no_guid = re.sub(r"_[0-9a-fA-F\-]{32,38}$", "", stem_no_guid)
            clean_core = re.sub(r"[^A-Za-z0-9_]+", "_", stem_no_guid).strip("_").lower()

            if "activitiescache" in clean_core:
                return {
                    "table_name": "raw_sqlecmd_activitiescache",
                    "artifact_id": "os_sqlecmd_activitiescache",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Timeline Activities (SQLECmd)",
                    "source_tool": "SQLECmd",
                }
            if "activityoperation" in clean_core:
                return {
                    "table_name": "raw_sqlecmd_activity_operations",
                    "artifact_id": "os_sqlecmd_activity_operations",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Activity Operations",
                    "source_tool": "SQLECmd",
                }
            if "activitypackageid" in clean_core:
                return {
                    "table_name": "raw_sqlecmd_activity_package_ids",
                    "artifact_id": "os_sqlecmd_activity_package_ids",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Activity Packages",
                    "source_tool": "SQLECmd",
                }
            if any(k in clean_core for k in ["notification", "wpn", "push"]):
                return {
                    "table_name": "raw_sqlecmd_windows_notifications",
                    "artifact_id": "os_sqlecmd_notifications",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Windows Push Notifications (SQLECmd)",
                    "source_tool": "SQLECmd",
                }

            cat = "Operating System"
            if any(k in clean_core for k in ["browser", "chrome", "edge", "firefox", "download", "url", "history"]):
                cat = "Web Related"
            elif any(k in clean_core for k in ["chat", "teams", "slack", "message", "sms", "call"]):
                cat = "Chat & Collaboration"

            human_name = clean_core.replace("_", " ").title()
            return {
                "table_name": f"raw_sqlecmd_{clean_core}",
                "artifact_id": f"sqlecmd_{clean_core}",
                "category": cat,
                "display_name": f"{human_name} (SQLECmd)",
                "source_tool": "SQLECmd",
            }

        # Fallback for any unexpected EZ tool or parser
        return {
            "table_name": f"raw_{tool_name}_{clean_stem}",
            "artifact_id": f"artifact_{tool_name}_{clean_stem}",
            "category": "OPERATING SYSTEM",
            "display_name": f"{tool_name.upper()} ({clean_stem})",
            "source_tool": tool_name,
        }

    def ingest_csv_file(
        self,
        csv_path: Path,
        table_name: str,
        category: str,
        display_name: str,
        source_tool: str,
        artifact_id: str,
    ) -> int:
        """
        Zero-copy CSV ingestion into DuckDB using read_csv_auto with _row_id.
        Immediately updates artifact_registry and processing_logs.
        """
        resolved_csv = csv_path.resolve()
        if not resolved_csv.exists() or resolved_csv.stat().st_size == 0:
            print(f"[EZToolRunner] Skipping empty or missing CSV: {resolved_csv}")
            return 0

        csv_posix = resolved_csv.as_posix()
        start_time = time.time()
        print(f"[EZToolRunner] Ingesting CSV: {resolved_csv.name} -> Table: '{table_name}'")

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cursor = conn.cursor()

            # Ingestion SQL using read_csv_auto per Section 4.4
            ingest_sql = f"""
            CREATE OR REPLACE TABLE "{table_name}" AS
            SELECT
                row_number() OVER () AS _row_id,
                *
            FROM read_csv_auto('{csv_posix}', ignore_errors=true, sample_size=-1, all_varchar=false);
            """

            try:
                cursor.execute(ingest_sql)
            except Exception as exc:
                print(
                    f"[EZToolRunner] Warning: all_varchar=false ingestion failed ({exc}). Retrying with all_varchar=true..."
                )
                fallback_sql = f"""
                CREATE OR REPLACE TABLE "{table_name}" AS
                SELECT
                    row_number() OVER () AS _row_id,
                    *
                FROM read_csv_auto('{csv_posix}', ignore_errors=true, sample_size=-1, all_varchar=true);
                """
                cursor.execute(fallback_sql)

            # Count ingested rows
            count_row = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()
            row_count = int(count_row[0]) if count_row else 0
            if row_count == 0:
                try:
                    varchar_sql = f"""
                    CREATE OR REPLACE TABLE "{table_name}" AS
                    SELECT
                        row_number() OVER () AS _row_id,
                        *
                    FROM read_csv_auto('{csv_posix}', all_varchar=true);
                    """
                    cursor.execute(varchar_sql)
                    count_row = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()
                    row_count = int(count_row[0]) if count_row else 0
                except Exception:
                    pass
            duration_ms = int((time.time() - start_time) * 1000)

            # Update artifact_registry (strictly one entry per table_name, skip raw_recmd per specification)
            if table_name != "raw_recmd":
                cursor.execute(
                    "DELETE FROM artifact_registry WHERE table_name = ? AND artifact_id != ?;",
                    [table_name, artifact_id],
                )
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id,
                        category,
                        display_name,
                        table_name,
                        source_tool,
                        row_count,
                        last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
                    """,
                    [artifact_id, category, display_name, table_name, source_tool, row_count],
                )

            # If raw_recmd was populated, register virtual filtered views per Section 5.1
            if table_name == "raw_recmd" and row_count > 0:
                self._create_recmd_virtual_views(cursor)

        # Log to processing_logs
        log_processing_event(
            case_id=self.case_id,
            module_name=f"Ingest:{source_tool}",
            command_executed=f"read_csv_auto('{csv_posix}') -> {table_name}",
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
            error_message=None,
        )

        print(
            f"[EZToolRunner] Ingested {row_count} rows into table '{table_name}' "
            f"in {duration_ms}ms (artifact_id='{artifact_id}')"
        )
        return row_count

    def _create_recmd_virtual_views(self, cursor: duckdb.DuckDBPyConnection) -> None:
        """
        Create virtual filtered views from raw_recmd mapped to authentic WFT taxonomy:
        view_usb_devices, view_autoruns, view_userassist, view_bam_dam.
        """
        describe_rows = cursor.execute('DESCRIBE "raw_recmd";').fetchall()
        col_names = [str(r[0]).lower() for r in describe_rows]

        # Ensure KeyPath exists
        has_keypath = "keypath" in col_names
        has_category = "category" in col_names
        has_desc = "description" in col_names

        views: List[Tuple[str, str, str, str, str]] = []

        if has_keypath:
            usb_filter = "KeyPath ILIKE '%USBSTOR%' OR KeyPath ILIKE '%MountedDevices%' OR KeyPath ILIKE '%EMDMgmt%'"
            if has_desc:
                usb_filter += " OR Description ILIKE '%USB%'"
            views.append(
                (
                    "view_usb_devices",
                    "USB & External Devices",
                    "USB Registry Activity",
                    "view_usb_devices",
                    f'SELECT * FROM "raw_recmd" WHERE ({usb_filter})',
                )
            )

            autorun_filter = "KeyPath ILIKE '%CurrentVersion\\Run%' OR KeyPath ILIKE '%Services%'"
            if has_category:
                autorun_filter = "Category ILIKE '%Run%' OR " + autorun_filter
            views.append(
                (
                    "view_autoruns",
                    "Registry & OS",
                    "AutoRuns & Services",
                    "view_autoruns",
                    f'SELECT * FROM "raw_recmd" WHERE ({autorun_filter})',
                )
            )

            userassist_filter = "KeyPath ILIKE '%UserAssist%'"
            if has_desc:
                userassist_filter += " OR Description ILIKE '%UserAssist%'"
            views.append(
                (
                    "view_userassist",
                    "Program Execution",
                    "UserAssist Execution",
                    "view_userassist",
                    f'SELECT * FROM "raw_recmd" WHERE ({userassist_filter})',
                )
            )

            views.append(
                (
                    "view_bam_dam",
                    "Program Execution",
                    "Background Activity Moderator (BAM/DAM)",
                    "view_bam_dam",
                    'SELECT * FROM "raw_recmd" WHERE (KeyPath ILIKE \'%bam%\' OR KeyPath ILIKE \'%dam%\')',
                )
            )

        for view_name, category, display_name, artifact_id, query_sql in views:
            try:
                cursor.execute(f'CREATE OR REPLACE VIEW "{view_name}" AS {query_sql};')
                v_count_row = cursor.execute(f'SELECT COUNT(*) FROM "{view_name}";').fetchone()
                v_count = int(v_count_row[0]) if v_count_row else 0
                # Delete any stale duplicate keys pointing to this view
                cursor.execute(
                    "DELETE FROM artifact_registry WHERE table_name = ? AND artifact_id != ?;",
                    [view_name, artifact_id],
                )
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id,
                        category,
                        display_name,
                        table_name,
                        source_tool,
                        row_count,
                        last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
                    """,
                    [artifact_id, category, display_name, view_name, "RECmd", v_count],
                )
                print(f"[EZToolRunner] Created virtual registry view '{view_name}' ({v_count} rows)")
            except Exception as ex:
                print(f"[EZToolRunner] Failed creating view '{view_name}': {ex}")

    def ingest_csv_directory(self, tool_name: str, csv_dir: Path) -> Dict[str, int]:
        """
        Scan a dedicated tool directory for all non-empty CSV files and ingest them.
        Returns mapping of {table_name: row_count}.
        """
        results: Dict[str, int] = {}
        if not csv_dir.exists():
            csv_dir.mkdir(parents=True, exist_ok=True)

        def has_data_rows(p: Path) -> bool:
            try:
                if not p.exists() or p.stat().st_size == 0:
                    return False
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    line1 = f.readline()
                    if not line1:
                        return False
                    line2 = f.readline()
                    return bool(line2 and line2.strip())
            except Exception:
                return False

        csv_files = sorted(csv_dir.glob("*.csv"))
        has_data = any(has_data_rows(f) for f in csv_files)
        if not has_data:
            return {}

        for csv_f in csv_files:
            if not has_data_rows(csv_f):
                continue
            meta = self.map_csv_to_table_info(tool_name, csv_f)
            count = self.ingest_csv_file(
                csv_path=csv_f,
                table_name=meta["table_name"],
                category=meta["category"],
                display_name=meta["display_name"],
                source_tool=meta["source_tool"],
                artifact_id=meta["artifact_id"],
            )
            results[meta["table_name"]] = count

        return results

    # =========================================================================
    # TOOL 0: rla.exe (Registry Transaction Log Replay)
    # =========================================================================
    def run_rla(self, staged_registry_dir: Optional[Path] = None) -> bool:
        """
        Execute rla.exe to replay dirty .LOG1 and .LOG2 transaction logs into clean hives.
        Saves updated hives to self.clean_hives_dir.
        """
        reg_dir = (staged_registry_dir or (self.staging_dir / "Registry")).resolve()
        if not reg_dir.exists():
            reg_dir = self.staging_dir

        # Check if there are any files to replay
        if not any(reg_dir.iterdir()):
            print(f"[EZToolRunner][rla] Staged registry directory '{reg_dir}' has no files. Skipping.")
            return False

        rla_exe = find_ez_binary("rla.exe")
        self.clean_hives_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(rla_exe),
            "-d",
            str(reg_dir),
            "--out",
            str(self.clean_hives_dir),
            "--ca",
            "--cn",
            "false",
        ]

        proc = self._execute_subprocess("rla", cmd)

        # Fallback copy for any hives from reg_dir not copied by rla
        try:
            for f in reg_dir.rglob("*"):
                if f.is_file() and not any(f.name.lower().endswith(sfx) for sfx in [".log", ".log1", ".log2"]):
                    dest_f = self.clean_hives_dir / f.name
                    if not dest_f.exists():
                        shutil.copy2(f, dest_f)
        except Exception as copy_ex:
            print(f"[EZToolRunner][rla] Notice copying remaining hives: {copy_ex}")

        cleaned_files = list(self.clean_hives_dir.glob("*"))
        print(f"[EZToolRunner][rla] Cleaned hives count in '{self.clean_hives_dir}': {len(cleaned_files)}")
        return len(cleaned_files) > 0

    # =========================================================================
    # TOOL 1: PECmd.exe (Prefetch)
    # =========================================================================
    def run_pecmd(self, pf_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute PECmd.exe on staged Prefetch directory or individual .pf file.
        Ingests pecmd.csv -> raw_pecmd and pecmd_Timeline.csv -> raw_pecmd_timeline.
        """
        target = pf_input.resolve() if pf_input else (self.staging_dir / "Prefetch").resolve()
        if not target.exists():
            target = self.staging_dir

        pecmd_exe = find_ez_binary("PECmd.exe")
        out_dir = (self.csv_out_dir / "pecmd").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(pecmd_exe),
            flag,
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "pecmd.csv",
            "--mp",
            "-q",
        ]

        self._execute_subprocess("PECmd", cmd)
        return self.ingest_csv_directory("pecmd", out_dir)

    # =========================================================================
    # TOOL 2: AmcacheParser.exe
    # =========================================================================
    def run_amcache(self, amcache_hve: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute AmcacheParser.exe on Amcache.hve hive.
        Ingests UnassociatedFileEntries, ProgramEntries, ShortCuts, DeviceContainers.
        """
        target = amcache_hve.resolve() if amcache_hve else None
        if target is None or not target.exists():
            # Search clean_hives_dir first, then staging_dir
            for search_root in [self.clean_hives_dir, self.staging_dir / "Registry", self.staging_dir]:
                if search_root.exists():
                    for f in search_root.rglob("*"):
                        if f.is_file() and f.name.lower() == "amcache.hve":
                            target = f.resolve()
                            break
                if target:
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][AmcacheParser] Amcache.hve not found. Skipping.")
            return {}

        amcache_exe = find_ez_binary("AmcacheParser.exe")
        out_dir = (self.csv_out_dir / "amcache").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(amcache_exe),
            "-f",
            str(target),
            "-i",
            "--csv",
            str(out_dir),
            "--csvf",
            "amcache.csv",
            "--mp",
        ]

        self._execute_subprocess("AmcacheParser", cmd)
        return self.ingest_csv_directory("amcache", out_dir)

    # =========================================================================
    # TOOL 3: AppCompatCacheParser.exe (Shimcache)
    # =========================================================================
    def run_appcompatcache(self, system_hive: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute AppCompatCacheParser.exe on SYSTEM hive.
        Ingests shimcache.csv -> raw_shimcache.
        """
        target = system_hive.resolve() if system_hive else None
        if target is None or not target.exists():
            for search_root in [self.clean_hives_dir, self.staging_dir / "Registry", self.staging_dir]:
                if search_root.exists():
                    for f in search_root.rglob("*"):
                        if f.is_file() and f.name.lower() == "system":
                            target = f.resolve()
                            break
                if target:
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][AppCompatCacheParser] SYSTEM hive not found. Skipping.")
            return {}

        shimcache_exe = find_ez_binary("AppCompatCacheParser.exe")
        out_dir = (self.csv_out_dir / "shimcache").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(shimcache_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "shimcache.csv",
        ]

        self._execute_subprocess("AppCompatCacheParser", cmd)
        return self.ingest_csv_directory("shimcache", out_dir)

    # =========================================================================
    # TOOL 4: EvtxECmd.exe (Event Logs)
    # =========================================================================
    def run_evtx(self, logs_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute EvtxECmd.exe on staged Logs directory or individual .evtx file.
        Ingests evtx.csv -> raw_evtx.
        """
        target = logs_input.resolve() if logs_input else (self.staging_dir / "Logs").resolve()
        if not target.exists():
            alt_logs = (self.staging_dir / "winevt" / "Logs").resolve()
            target = alt_logs if alt_logs.exists() else self.staging_dir

        evtx_exe = find_ez_binary("EvtxECmd.exe")
        out_dir = (self.csv_out_dir / "evtx").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(evtx_exe),
            flag,
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "evtx.csv",
        ]

        self._execute_subprocess("EvtxECmd", cmd)
        res = self.ingest_csv_directory("evtx", out_dir)
        try:
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                register_evtx_granular_views(conn, case_id=self.case_id)
                sync_granular_artifacts(conn, case_id=self.case_id)
        except Exception as ex:
            print(f"[EZToolRunner] Warning registering evtx views: {ex}")
        return res

    # =========================================================================
    # TOOL 5: MFTECmd.exe ($MFT)
    # =========================================================================
    def run_mftecmd_mft(self, mft_file: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute MFTECmd.exe on staged $MFT file.
        Ingests mft.csv -> raw_mft.
        """
        target = mft_file.resolve() if mft_file else None
        if target is None or not target.exists():
            for search_root in [
                self.staging_dir / "$MFT",
                self.staging_dir / "FileSystem" / "$MFT",
                self.staging_dir / "MFT",
                self.staging_dir / "FileSystem",
                self.staging_dir,
            ]:
                if search_root.is_file():
                    target = search_root.resolve()
                    break
                if search_root.is_dir():
                    for f in search_root.iterdir():
                        if f.is_file() and f.name.lower() in ["$mft", "mft"]:
                            target = f.resolve()
                            break
                if target:
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][MFTECmd:$MFT] $MFT file not found. Skipping.")
            return {}

        mftecmd_exe = find_ez_binary("MFTECmd.exe")
        out_dir = (self.csv_out_dir / "mft").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(mftecmd_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "mft.csv",
        ]

        self._execute_subprocess("MFTECmd_MFT", cmd, timeout=30000)
        return self.ingest_csv_directory("mft", out_dir)

    # =========================================================================
    # TOOL 6: MFTECmd.exe ($J / USN Journal)
    # =========================================================================
    def run_mftecmd_usnjrnl(
        self, usn_file: Optional[Path] = None, mft_file: Optional[Path] = None
    ) -> Dict[str, int]:
        """
        Execute MFTECmd.exe on staged USN Journal ($J) file.
        Ingests usnjrnl.csv -> raw_usnjrnl.
        """
        target = usn_file.resolve() if usn_file else None
        if target is None or not target.exists():
            for search_root in [
                self.staging_dir / "$J",
                self.staging_dir / "FileSystem" / "$J",
                self.staging_dir / "UsnJrnl",
                self.staging_dir / "FileSystem",
                self.staging_dir,
            ]:
                if search_root.is_file():
                    target = search_root.resolve()
                    break
                if search_root.is_dir():
                    for f in search_root.iterdir():
                        if f.is_file() and ("$j" in f.name.lower() or "usnjrnl" in f.name.lower()):
                            target = f.resolve()
                            break
                if target:
                    break

        out_dir = (self.csv_out_dir / "usnjrnl").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        if target is None or not target.exists():
            print("[EZToolRunner][MFTECmd:$J] USN journal ($J) file not found. Skipping.")
            return {}

        # Safeguard against zero-filled sparse dummy $J files which cause MFTECmd to loop infinitely
        if target.exists() and target.stat().st_size <= 16384:
            try:
                with open(target, "rb") as test_f:
                    head = test_f.read(512)
                    if head and all(b == 0 for b in head):
                        print("[EZToolRunner][MFTECmd:$J] Sparse zero-filled $J detected. Skipping.")
                        return {}
            except Exception:
                pass

        mftecmd_exe = find_ez_binary("MFTECmd.exe")

        cmd = [
            str(mftecmd_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "usnjrnl.csv",
        ]

        # Add -m <mft_file> if $MFT exists to resolve parent directory paths
        if mft_file and mft_file.exists():
            cmd.extend(["-m", str(mft_file.resolve())])

        self._execute_subprocess("MFTECmd_USN", cmd, timeout=30000)
        return self.ingest_csv_directory("usnjrnl", out_dir)

    # =========================================================================
    # TOOL 7: LECmd.exe (LNK Shortcut Files)
    # =========================================================================
    def run_lecmd(self, lnk_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute LECmd.exe on staged LNK shortcut directory or individual .lnk file.
        Ingests lecmd.csv -> raw_lecmd.
        """
        target = lnk_input.resolve() if lnk_input else (self.staging_dir / "LNK").resolve()
        if not target.exists():
            alt_lnk = (self.staging_dir / "Recent").resolve()
            target = alt_lnk if alt_lnk.exists() else self.staging_dir

        lecmd_exe = find_ez_binary("LECmd.exe")
        out_dir = (self.csv_out_dir / "lecmd").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(lecmd_exe),
            flag,
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "lecmd.csv",
            "--mp",
            "-q",
        ]

        self._execute_subprocess("LECmd", cmd)
        return self.ingest_csv_directory("lecmd", out_dir)

    # =========================================================================
    # TOOL 8: JLECmd.exe (Jump Lists)
    # =========================================================================
    def run_jlecmd(self, jl_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute JLECmd.exe on staged JumpLists directory.
        Ingests AutomaticDestinations and CustomDestinations jump lists.
        """
        target = jl_input.resolve() if jl_input else (self.staging_dir / "JumpLists").resolve()
        if not target.exists():
            target = self.staging_dir

        jlecmd_exe = find_ez_binary("JLECmd.exe")
        out_dir = (self.csv_out_dir / "jlecmd").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(jlecmd_exe),
            flag,
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "jlecmd.csv",
            "--mp",
            "-q",
        ]

        self._execute_subprocess("JLECmd", cmd)
        return self.ingest_csv_directory("jlecmd", out_dir)

    # =========================================================================
    # TOOL 9: SBECmd.exe (ShellBags)
    # =========================================================================
    def run_sbecmd(self, hives_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute SBECmd.exe on cleaned hives directory.
        Ingests shellbags.csv -> raw_shellbags.
        """
        target = hives_dir.resolve() if hives_dir else self.clean_hives_dir
        if not target.exists() or not any(target.iterdir()):
            target = (self.staging_dir / "Registry").resolve()
            if not target.exists():
                target = self.staging_dir

        sbecmd_exe = find_ez_binary("SBECmd.exe")
        out_dir = (self.csv_out_dir / "shellbags").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(sbecmd_exe),
            "-d",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "shellbags.csv",
        ]

        self._execute_subprocess("SBECmd", cmd)
        return self.ingest_csv_directory("shellbags", out_dir)

    # =========================================================================
    # TOOL 10: RECmd.exe (Registry Batch Parser)
    # =========================================================================
    def run_recmd(
        self,
        hives_dir: Optional[Path] = None,
        batch_reb_file: Optional[Path] = None,
    ) -> Dict[str, int]:
        """
        Execute RECmd.exe with Kroll_Batch.reb across all staged registry hives.
        Ingests recmd.csv -> raw_recmd and builds virtual filtered views.
        """
        target = hives_dir.resolve() if hives_dir else self.clean_hives_dir
        if not target.exists() or not any(target.iterdir()):
            target = (self.staging_dir / "Registry").resolve()
            if not target.exists():
                target = self.staging_dir

        batch_file = batch_reb_file.resolve() if batch_reb_file else None
        if batch_file is None or not batch_file.exists():
            batch_file = find_ez_file("Kroll_Batch.reb")

        recmd_exe = find_ez_binary("RECmd.exe")
        out_dir = (self.csv_out_dir / "recmd").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(recmd_exe),
            "-d",
            str(target),
            "--bn",
            str(batch_file),
            "--csv",
            str(out_dir),
            "--csvf",
            "recmd.csv",
            "--nl",
        ]

        self._execute_subprocess("RECmd", cmd)
        return self.ingest_csv_directory("recmd", out_dir)

    # =========================================================================
    # TOOL 11: SrumECmd.exe (System Resource Usage Monitor)
    # =========================================================================
    def run_srum(
        self,
        srudb_file: Optional[Path] = None,
        software_hive: Optional[Path] = None,
    ) -> Dict[str, int]:
        """
        Execute SrumECmd.exe on staged SRUDB.dat with SOFTWARE hive.
        Ingests AppResourceUseInfo, NetworkDataUsage, NetworkConnections.
        """
        target_srudb = srudb_file.resolve() if srudb_file else None
        if target_srudb is None or not target_srudb.exists():
            for search_root in [self.staging_dir / "SRUDB.dat", self.staging_dir / "sru", self.staging_dir]:
                if search_root.is_file() and search_root.name.lower() == "srudb.dat":
                    target_srudb = search_root.resolve()
                    break
                if search_root.is_dir():
                    for f in search_root.rglob("*"):
                        if f.is_file() and f.name.lower() == "srudb.dat":
                            target_srudb = f.resolve()
                            break
                if target_srudb:
                    break

        if target_srudb is None or not target_srudb.exists():
            print("[EZToolRunner][SrumECmd] SRUDB.dat not found. Skipping.")
            return {}

        target_software = software_hive.resolve() if software_hive else None
        if target_software is None or not target_software.exists():
            for search_root in [self.clean_hives_dir, self.staging_dir / "Registry", self.staging_dir]:
                if search_root.exists():
                    for f in search_root.rglob("*"):
                        if f.is_file() and f.name.lower() == "software":
                            target_software = f.resolve()
                            break
                if target_software:
                    break

        srum_exe = find_ez_binary("SrumECmd.exe")
        out_dir = (self.csv_out_dir / "srum").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(srum_exe),
            "-f",
            str(target_srudb),
            "--csv",
            str(out_dir),
        ]
        if target_software and target_software.exists():
            cmd.extend(["-r", str(target_software)])

        self._execute_subprocess("SrumECmd", cmd)
        return self.ingest_csv_directory("srum", out_dir)

    # =========================================================================
    # TOOL 12: WxTCmd.exe (Windows Timeline)
    # =========================================================================
    def run_wxt(self, wxt_file: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute WxTCmd.exe on staged ActivitiesCache.db.
        Ingests Activity.csv -> raw_wxt_activity.
        """
        target = wxt_file.resolve() if wxt_file else None
        if target is None or not target.exists():
            for search_root in [self.staging_dir / "ActivitiesCache.db", self.staging_dir]:
                if search_root.is_file() and search_root.name.lower() == "activitiescache.db":
                    target = search_root.resolve()
                    break
                if search_root.is_dir():
                    for f in search_root.rglob("*"):
                        if f.is_file() and f.name.lower() == "activitiescache.db":
                            target = f.resolve()
                            break
                if target:
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][WxTCmd] ActivitiesCache.db not found. Skipping.")
            return {}

        wxt_exe = find_ez_binary("WxTCmd.exe")
        out_dir = (self.csv_out_dir / "wxt").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(wxt_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
        ]

        self._execute_subprocess("WxTCmd", cmd)
        return self.ingest_csv_directory("wxt", out_dir)

    # =========================================================================
    # TOOL 13: RBCmd.exe (Recycle Bin Parser)
    # =========================================================================
    def run_rbcmd(self, recycle_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute RBCmd.exe on staged RecycleBin directory ($I* files).
        Ingests rbcmd.csv -> raw_rbcmd.
        """
        target = recycle_dir.resolve() if recycle_dir else (self.staging_dir / "RecycleBin").resolve()
        if not target.exists():
            target = self.staging_dir

        # Check if there are any files to parse
        has_files = False
        if target.is_dir():
            has_files = any(f.is_file() for f in target.rglob("*"))
        elif target.is_file():
            has_files = True

        if not has_files:
            print("[EZToolRunner][RBCmd] No Recycle Bin files found. Skipping.")
            return {"raw_rbcmd": 0}

        rbcmd_exe = find_ez_binary("RBCmd.exe")
        out_dir = (self.csv_out_dir / "rbcmd").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(rbcmd_exe),
            flag,
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "rbcmd.csv",
            "-q",
        ]

        self._execute_subprocess("RBCmd", cmd)
        res = self.ingest_csv_directory("rbcmd", out_dir)
        if not res:
            res = {"raw_rbcmd": 0}
        return res

    # =========================================================================
    # TOOL 14: SQLECmd.exe (Universal SQLite Parser with Community Maps)
    # =========================================================================
    def run_sqlecmd(
        self,
        sqlite_dir: Optional[Path] = None,
        maps_dir: Optional[Path] = None,
    ) -> Dict[str, int]:
        """
        Execute SQLECmd.exe on staged SQLite databases directory using maps in EZTools/SQLECmd/Maps.
        Ingests all generated CSVs into DuckDB raw_sqlecmd_* tables.
        """
        target = sqlite_dir.resolve() if sqlite_dir else (self.staging_dir / "SQLite").resolve()
        if not target.exists():
            target = self.staging_dir

        has_sqlite = False
        if target.is_dir():
            has_sqlite = any(
                f.is_file() and (
                    f.suffix.lower() in [".db", ".sqlite", ".sqlite3"]
                    or "history" in f.name.lower()
                    or "data" in f.name.lower()
                    or "places" in f.name.lower()
                )
                for f in target.rglob("*")
            )
        elif target.is_file():
            has_sqlite = True

        if not has_sqlite:
            print("[EZToolRunner][SQLECmd] No SQLite databases found in target. Skipping.")
            return {}

        sqlecmd_exe = find_ez_binary("SQLECmd.exe")
        out_dir = (self.csv_out_dir / "sqlecmd").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        # Clear prior SQLECmd CSVs to prevent timestamped accumulation across multiple runs
        for old_csv in out_dir.glob("*.csv"):
            try:
                old_csv.unlink()
            except Exception:
                pass

        maps_path = maps_dir.resolve() if maps_dir else None
        if maps_path is None or not maps_path.exists():
            candidate_maps = [
                BASE_DIR / "EZTools" / "SQLECmd" / "Maps",
                BASE_DIR / "tools" / "ez_tools" / "SQLECmd" / "Maps",
                sqlecmd_exe.parent / "Maps",
            ]
            for m in candidate_maps:
                if m.is_dir() and any(m.glob("*.smap")):
                    maps_path = m.resolve()
                    break

        flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(sqlecmd_exe),
            flag,
            str(target),
            "--csv",
            str(out_dir),
            "--hunt",
        ]
        if maps_path and maps_path.exists():
            cmd.extend(["--maps", str(maps_path)])

        self._execute_subprocess("SQLECmd", cmd)
        return self.ingest_csv_directory("sqlecmd", out_dir)

    # =========================================================================
    # TOOL 15: RecentFileCacheParser.exe
    # =========================================================================
    def run_recentfilecache(self, rfc_file: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute RecentFileCacheParser.exe on RecentFileCache.bcf.
        """
        target = rfc_file.resolve() if rfc_file else None
        if target is None or not target.exists():
            for search_root in [
                self.staging_dir / "RecentFileCache.bcf",
                self.staging_dir / "Registry" / "RecentFileCache.bcf",
                self.staging_dir / "AppCompat" / "Programs" / "RecentFileCache.bcf",
                self.staging_dir,
            ]:
                if search_root.is_file() and search_root.name.lower() == "recentfilecache.bcf":
                    target = search_root.resolve()
                    break
                if search_root.is_dir():
                    for f in search_root.rglob("RecentFileCache.bcf"):
                        if f.is_file():
                            target = f.resolve()
                            break
                if target:
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][RecentFileCacheParser] RecentFileCache.bcf not found. Skipping.")
            return {}

        try:
            rfc_exe = find_ez_binary("RecentFileCacheParser.exe")
        except FileNotFoundError:
            return {}

        out_dir = (self.csv_out_dir / "recentfilecache").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(rfc_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "recentfilecache.csv",
            "-q",
        ]

        self._execute_subprocess("RecentFileCacheParser", cmd)
        return self.ingest_csv_directory("recentfilecache", out_dir)

    # =========================================================================
    # TOOL 16: SumECmd.exe (User Access Logging)
    # =========================================================================
    def run_sum(self, sum_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute SumECmd.exe on staged User Access Logging (SUM) directory.
        """
        target = sum_dir.resolve() if sum_dir else None
        if target is None or not target.exists():
            for search_root in [
                self.staging_dir / "SUM",
                self.staging_dir / "LogFiles" / "SUM",
                self.staging_dir,
            ]:
                if search_root.is_dir() and any(search_root.glob("*.mdb")):
                    target = search_root.resolve()
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][SumECmd] SUM database directory not found. Skipping.")
            return {}

        try:
            sum_exe = find_ez_binary("SumECmd.exe")
        except FileNotFoundError:
            return {}

        out_dir = (self.csv_out_dir / "sum").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(sum_exe),
            "-d",
            str(target),
            "--csv",
            str(out_dir),
        ]

        self._execute_subprocess("SumECmd", cmd)
        return self.ingest_csv_directory("sum", out_dir)

    # =========================================================================
    # MASTER RUNNER: Inspects Staging & Runs All Present Artifact Types
    # =========================================================================
    def run_all(self) -> Dict[str, int]:
        """
        Master orchestrator: executes rla.exe and ALL 15 Eric Zimmerman tools,
        ingests all generated CSVs, and ensures all catalog artifacts are registered.
        """
        print(f"\n{'='*70}\n[EZToolRunner] Starting run_all for case: '{self.case_id}'\n{'='*70}")
        all_results: Dict[str, int] = {}

        # 0. Replay dirty transaction logs if any registry hive files exist
        has_registry = False
        reg_candidates = ["system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "amcache.hve"]
        staged_files = []
        for _root, _dirs, _files in os.walk(self.staging_dir, onerror=lambda _e: None):
            staged_files.extend([_f.lower() for _f in _files])
        if any(c in staged_files for c in reg_candidates):
            has_registry = True
            staged_reg_dir = (
                (self.staging_dir / "Registry")
                if (self.staging_dir / "Registry").is_dir()
                else self.staging_dir
            )
            try:
                self.run_rla(staged_reg_dir)
            except Exception as rla_err:
                self._log(f'RLA skipped or unavailable: {rla_err}', 'WARNING')

        # 1. MFTECmd ($MFT)
        try:
            res = self.run_mftecmd_mft()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] MFTECmd MFT warning: {ex}")

        # 2. MFTECmd ($J / USN Journal)
        try:
            mft_cand = self.staging_dir / "$MFT"
            if not mft_cand.exists():
                mft_cand = self.staging_dir / "FileSystem" / "$MFT"
            if not mft_cand.exists():
                mft_cand = self.staging_dir / "MFT"
            res = self.run_mftecmd_usnjrnl(mft_file=mft_cand if mft_cand.exists() else None)
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] MFTECmd USN warning: {ex}")

        # 3. PECmd (Prefetch)
        try:
            res = self.run_pecmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] PECmd warning: {ex}")

        # 4. AmcacheParser (Amcache.hve)
        try:
            res = self.run_amcache()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] AmcacheParser warning: {ex}")

        # 5. AppCompatCacheParser (Shimcache)
        try:
            res = self.run_appcompatcache()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] AppCompatCache warning: {ex}")

        # 6. SBECmd (ShellBags)
        try:
            res = self.run_sbecmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] SBECmd warning: {ex}")

        # 7. SrumECmd (SRUDB.dat + SOFTWARE)
        try:
            res = self.run_srum()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] SrumECmd warning: {ex}")

        # 8. EvtxECmd (Event Logs)
        try:
            res = self.run_evtx()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] EvtxECmd warning: {ex}")

        # 9. RECmd (Registry Hives with Kroll_Batch.reb)
        try:
            res = self.run_recmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] RECmd warning: {ex}")

        # 10. LECmd (LNK Shortcuts)
        try:
            res = self.run_lecmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] LECmd warning: {ex}")

        # 11. JLECmd (Jump Lists)
        try:
            res = self.run_jlecmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] JLECmd warning: {ex}")

        # 12. RBCmd (Recycle Bin)
        try:
            res = self.run_rbcmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] RBCmd warning: {ex}")

        # 13. WxTCmd (Windows Timeline)
        try:
            res = self.run_wxt()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] WxTCmd warning: {ex}")

        # 14. SQLECmd (Universal SQLite Hunting)
        try:
            res = self.run_sqlecmd()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] SQLECmd warning: {ex}")

        # 15. RecentFileCacheParser
        try:
            res = self.run_recentfilecache()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] RecentFileCacheParser warning: {ex}")

        # 16. SumECmd (User Access Logging)
        try:
            res = self.run_sum()
            all_results.update(res)
        except Exception as ex:
            print(f"[EZToolRunner] SumECmd warning: {ex}")

        print(f"\n[EZToolRunner] run_all complete. Total tables populated: {len(all_results)}")
        for tbl, count in all_results.items():
            print(f"  -> {tbl}: {count} rows")

        return all_results
