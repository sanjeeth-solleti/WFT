"""
Windows Forensic Toolkit (WFT) DFIR Suite - Eric Zimmerman Tools & Hindsight Orchestration Engine
Executes rla.exe, all 15 EZ Tools in parallel, and Hindsight Chromium analysis,
ingests generated CSVs/JSONL into DuckDB under per-case lock, and updates artifact_registry and processing_logs.
"""
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

import duckdb

import backend.config as wft_config
from backend.config import (
    BASE_DIR,
    find_ez_binary,
    find_ez_file,
    get_case_csv_out_dir,
    get_case_db_path,
    get_case_dir,
    get_case_log_file,
    get_case_staging_dir,
    register_case_dir,
)
from backend.db.engine import DuckDBManager, init_case_db, log_processing_event
from backend.db.schema import register_evtx_granular_views, sync_granular_artifacts

_CLEAN_HIVES_GUARD = threading.Lock()
_CLEAN_HIVES_DIR_LOCKS: Dict[str, threading.RLock] = {}
_SQLECMD_MAPS_LOCK = threading.Lock()
_SQLECMD_MAPS_CACHE: Dict[Tuple[str, int, int], Path] = {}


@contextlib.contextmanager
def _acquire_clean_hives_lock(case_id: str, case_dir: Path) -> Iterator[None]:
    """
    Acquire process-wide per-case_dir RLock and DuckDBManager clean-hives lock in fixed order
    so concurrent rla.exe staging calls never race on clean_hives/ or block main DuckDB queries.
    """
    dir_key = str(Path(case_dir).resolve()).lower()
    with _CLEAN_HIVES_GUARD:
        dir_lock = _CLEAN_HIVES_DIR_LOCKS.get(dir_key)
        if dir_lock is None:
            dir_lock = threading.RLock()
            _CLEAN_HIVES_DIR_LOCKS[dir_key] = dir_lock
    with dir_lock:
        with DuckDBManager.get_lock(f"{case_id}__clean_hives"):
            yield


def _bind_case_dir_if_needed(case_id: str, case_dir: Path) -> None:
    """Bind unregistered custom/temp case_dir so DuckDBManager never leaks to Desktop/cases."""
    resolved_dir = Path(case_dir).resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)
    if get_case_dir(case_id).resolve() != resolved_dir:
        register_case_dir(case_id, resolved_dir)


def _file_digest_key(path: Path) -> Tuple[int, str]:
    """Return (file_size, sha256_hex) for exact duplicate staging detection."""
    st = path.stat()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return (st.st_size, h.hexdigest())


_NON_SQLITE_EXTS: Set[str] = {
    ".exe", ".dll", ".sys", ".mui", ".cat", ".nls", ".pf", ".evtx", ".etl",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ogg", ".webm",
    ".pdf", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".doc", ".xls", ".ppt",
    ".txt", ".csv", ".rtf", ".html", ".htm", ".xml", ".json", ".jsonl", ".js", ".css",
    ".ps1", ".bat", ".cmd", ".vbs", ".py", ".sh", ".ini", ".cfg", ".conf", ".reg",
    ".lnk", ".url", ".zip", ".7z", ".rar", ".gz", ".tar", ".cab", ".msi",
    ".hve", ".regtrans-ms", ".blf", ".log1", ".log2", ".ttf", ".otf", ".woff", ".woff2",
    ".duckdb", ".pak", ".asar", ".vdm", ".eml", ".msg", ".pst", ".ost", ".mbox",
}


def _is_sqlite3_file(path: Path) -> bool:
    """Verify 16-byte SQLite3 magic header, excluding WAL/SHM/journal sidecars and known non-SQLite extensions."""
    try:
        low_name = path.name.lower()
        if low_name.endswith(("-wal", "-shm", "-journal", ".wal", ".shm", ".journal")):
            return False
        dot_idx = low_name.rfind(".")
        if dot_idx != -1 and low_name[dot_idx:] in _NON_SQLITE_EXTS:
            return False
        if not path.is_file():
            return False
        if path.stat().st_size < 100:
            return False
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _is_hive_candidate(path: Path) -> bool:
    """Return True if path is a Windows Registry hive candidate (excluding logs & non-hive artifacts)."""
    try:
        if not path.is_file():
            return False
        fname = path.name.lower()
        if fname.endswith("_consolelog.txt") or "regtrans-ms" in fname or ".tmcontainer" in fname:
            return False
        bad_suffixes = (
            ".log", ".log1", ".log2", ".tm", ".blf", ".txt", ".csv", ".json",
            ".xml", ".db", ".sqlite", ".sqlite3", ".evtx", ".pf", ".lnk",
            ".mdb", ".bcf", ".smap", ".reb", ".map", ".exe", ".dll", ".pf",
        )
        if fname.endswith(bad_suffixes):
            return False
        known_names = {
            "system", "software", "sam", "security", "amcache.hve",
            "ntuser.dat", "usrclass.dat", "default", "components", "bcd",
        }
        if fname in known_names:
            return path.stat().st_size > 0
        if ("ntuser" in fname and fname.endswith(".dat")) or ("usrclass" in fname and fname.endswith(".dat")):
            return path.stat().st_size > 0
        if path.stat().st_size >= 4096:
            with open(path, "rb") as f:
                return f.read(4) == b"regf"
        return False
    except OSError:
        return False


class EZToolRunner:
    """
    Forensic runner orchestrating rla.exe, all 15 Eric Zimmerman CLI utilities, and Hindsight.
    Ingests all resulting CSV/JSONL files into DuckDB raw_* tables and tracks them
    inside artifact_registry and processing_logs.
    """

    EZ_TOOL_ARTIFACT_ALIASES: Dict[str, Set[str]] = {
        "mftecmd_mft": {"fs_mft", "os_mft", "mft", "raw_mft", "mftecmd", "file_system"},
        "mftecmd_usn": {"fs_usnjrnl", "os_usnjrnl", "usnjrnl", "raw_usnjrnl", "mftecmd", "file_system"},
        "pecmd": {"os_prefetch", "raw_pecmd", "raw_pecmd_timeline", "pecmd", "prefetch", "program_execution"},
        "amcache": {
            "os_amcache", "os_amcache_files", "os_amcache_programs", "os_amcache_shortcuts",
            "os_amcache_devices", "os_amcache_drivers", "os_amcache_assoc_files",
            "os_amcache_driver_packages", "os_amcache_device_pnps",
            "raw_amcache_files", "amcache", "amcacheparser", "program_execution",
        },
        "shimcache": {"os_shimcache", "raw_shimcache", "shimcache", "appcompatcache", "program_execution"},
        "sbecmd": {"fs_shellbags", "os_shellbags", "raw_shellbags", "shellbags", "sbecmd"},
        "srum": {
            "network_srum_app", "network_srum_net", "network_srum_conn",
            "os_srum_app", "os_srum_net", "os_srum_conn", "srum", "srumecmd",
        },
        "evtx": {"os_evtx", "raw_evtx", "evtx", "evtxecmd", "event_logs"},
        "recmd": {
            "registry_recmd", "os_recmd", "os_registry", "view_autoruns", "view_userassist", "view_bam_dam",
            "view_usb_devices", "usb_devices", "recmd", "raw_recmd", "registry",
        },
        "lecmd": {"fs_lnk", "os_lnk_files", "raw_lecmd", "lecmd", "lnk"},
        "jlecmd": {"fs_jumplist_auto", "fs_jumplist_custom", "os_jumplists", "jlecmd", "jumplists", "raw_jlecmd_auto", "raw_jlecmd_custom"},
        "rbcmd": {"fs_recyclebin", "os_recycle_bin", "raw_rbcmd", "rbcmd", "recyclebin"},
        "wxt": {"os_wxt_activity", "os_wxt_operations", "os_wxt_package_ids", "wxt", "wxtcmd"},
        "sqlecmd": {
            "sqlecmd", "os_sqlecmd_activitiescache", "os_sqlecmd_notifications",
            "os_wpn_notifications", "parsed_notifications", "os_wxt_activity",
            "browser_history", "browser_downloads", "chat_messages", "cloud_files",
        },
        "recentfilecache": {"os_recentfilecache", "raw_recentfilecache", "recentfilecache"},
        "sum": {"network_sum", "os_sum", "raw_sum", "sum", "sumecmd"},
        "hindsight": {
            "hindsight", "web_hindsight", "raw_hindsight", "web_related",
            "browser_history", "browser_downloads", "browser_logins",
            "chrome_history", "chrome_downloads", "chrome_cookies", "chrome_autofill",
            "chrome_bookmarks", "chrome_logins", "chrome_cache", "chrome_session",
            "edge_history", "edge_downloads", "edge_cookies", "brave_history",
        },
    }

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Path] = None,
        csv_out_dir: Optional[Path] = None,
        max_workers: int = 25,
    ) -> None:
        self.case_id = case_id
        if staging_dir is not None and Path(staging_dir).resolve().name.lower() == "staging":
            _bind_case_dir_if_needed(self.case_id, Path(staging_dir).resolve().parent)
        elif csv_out_dir is not None and Path(csv_out_dir).resolve().name.lower() == "csv_out":
            _bind_case_dir_if_needed(self.case_id, Path(csv_out_dir).resolve().parent)

        self.case_dir = get_case_dir(case_id).resolve()
        self.staging_dir = (
            Path(staging_dir).resolve() if staging_dir else get_case_staging_dir(case_id).resolve()
        )
        self.csv_out_dir = (
            Path(csv_out_dir).resolve() if csv_out_dir else get_case_csv_out_dir(case_id).resolve()
        )
        self.clean_hives_dir = (self.case_dir / "clean_hives").resolve()
        self.hindsight_out_dir = (self.case_dir / "hindsight_out").resolve()
        self.log_file = get_case_log_file(case_id).resolve()
        self.max_workers = max(1, min(32, 25 if max_workers is None else int(max_workers)))
        self._log_lock = threading.Lock()
        self._last_log_msg: Optional[str] = None

        # Ensure base directories exist
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.csv_out_dir.mkdir(parents=True, exist_ok=True)
        self.clean_hives_dir.mkdir(parents=True, exist_ok=True)

        # Initialize DuckDB case schema
        init_case_db(self.case_id)

    def _log(self, message: str, level: str = "INFO") -> None:
        """Helper to append timestamped logs to the case processing log file and console."""
        norm_msg = re.sub(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*", "", message).strip()
        with self._log_lock:
            if getattr(self, "_last_log_msg", None) == norm_msg:
                return
            self._last_log_msg = norm_msg
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level}] [EZToolRunner] {message}")
        try:
            if getattr(self, "log_file", None):
                with self._log_lock:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(f"[{ts}] [{level}] [EZToolRunner] {message}\n")
        except Exception:
            pass

    def _find_ez_binary_with_fallback(self, exe_name: str, env_var: Optional[str] = None) -> Path:
        """Resolve an EZ tool binary via config.find_ez_binary with sibling-dir fallback when no explicit env override is set."""
        eff_env_var = env_var or getattr(wft_config, "EZ_BINARY_TO_ENV", {}).get(
            (exe_name if exe_name.lower().endswith(".exe") else f"{exe_name}.exe").lower()
        )
        try:
            return find_ez_binary(exe_name)
        except FileNotFoundError as orig_err:
            if eff_env_var and (os.environ.get(eff_env_var) or "").strip():
                raise orig_err
            stem = Path(exe_name).stem
            for probe in ("PECmd.exe", "RECmd.exe", "RBCmd.exe"):
                if probe.lower() == exe_name.lower():
                    continue
                try:
                    sib = find_ez_binary(probe)
                except FileNotFoundError:
                    continue
                for cand in (
                    sib.parent / exe_name,
                    sib.parent / stem / exe_name,
                    sib.parent.parent / exe_name,
                    sib.parent.parent / stem / exe_name,
                ):
                    if cand.is_file() and cand.stat().st_size >= 64:
                        return cand.resolve()
            raise orig_err

    @staticmethod
    def _prepare_tool_out_dir(out_dir: Path) -> Path:
        """Create tool CSV output dir and purge stale CSVs/subdirs from prior runs."""
        resolved = out_dir.resolve()
        if resolved.exists():
            for child in list(resolved.iterdir()):
                try:
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    elif child.suffix.lower() == ".csv":
                        child.unlink(missing_ok=True)
                except OSError:
                    pass
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    def _execute_subprocess(
        self,
        module_name: str,
        cmd_list: List[str],
        timeout: Optional[int] = 300,
        cwd: Optional[Path] = None,
        extra_env: Optional[Dict[str, str]] = None,
        log_to_db: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Execute an external tool binary with DOTNET_ROLL_FORWARD=Major, CREATE_NO_WINDOW,
        thread-safe disk logging, and lock-serialized processing_logs telemetry.
        """
        cmd_str = " ".join([f'"{c}"' if " " in c else c for c in cmd_list])
        print(f"\n[EZToolRunner][{module_name}] Executing: {cmd_str}")

        env = os.environ.copy()
        env.setdefault("DOTNET_ROLL_FORWARD", "Major")
        if extra_env:
            env.update(extra_env)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        auto_cwd: Optional[Path] = None
        if cwd is not None:
            run_cwd_path = cwd.resolve()
            run_cwd_path.mkdir(parents=True, exist_ok=True)
            run_cwd = str(run_cwd_path)
        else:
            # Isolate per-invocation CWD inside case_dir so parallel .NET EZ binaries
            # (WxTCmd, SQLECmd, SrumECmd, SBECmd) never race on SQLite.Interop.dll or pollute BASE_DIR.
            safe_mod = re.sub(r"[^A-Za-z0-9_.-]+", "_", module_name)[:32] or "ez"
            auto_cwd = (self.case_dir / "_proc_cwd" / f"{safe_mod}_{uuid.uuid4().hex[:8]}").resolve()
            auto_cwd.mkdir(parents=True, exist_ok=True)
            run_cwd = str(auto_cwd)

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=run_cwd,
                env=env,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = f"Subprocess timed out after {timeout}s: {cmd_str}"
            print(f"[EZToolRunner][{module_name}] WARNING: {err_msg}")
            with DuckDBManager.get_lock(self.case_id):
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
            with DuckDBManager.get_lock(self.case_id):
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
        finally:
            if auto_cwd is not None:
                shutil.rmtree(auto_cwd, ignore_errors=True)
                try:
                    if auto_cwd.parent.is_dir() and not any(auto_cwd.parent.iterdir()):
                        auto_cwd.parent.rmdir()
                except OSError:
                    pass

        duration_ms = int((time.time() - start_time) * 1000)
        status = "SUCCESS" if proc.returncode == 0 else "WARNING"
        raw_stderr = proc.stderr.strip() if proc.stderr else ""
        if raw_stderr:
            if "Traceback (most recent call last)" in raw_stderr:
                non_empty_lines = [
                    ln.strip()
                    for ln in raw_stderr.splitlines()
                    if ln.strip() and "Traceback (most recent call last)" not in ln
                ]
                tail_err = non_empty_lines[-1] if non_empty_lines else "External tool error"
                err_msg = f"External tool exited with code {proc.returncode}: {tail_err}"[:500]
            else:
                err_msg = raw_stderr[:1000]
        else:
            err_msg = None

        print(
            f"[EZToolRunner][{module_name}] Finished with ExitCode={proc.returncode} "
            f"in {duration_ms}ms"
        )
        if proc.stdout and proc.stdout.strip():
            print(f"--- stdout ({module_name}) ---\n{proc.stdout.strip()[:1000]}")
        if raw_stderr:
            print(f"--- stderr ({module_name}) ---\n{raw_stderr[:1000]}")

        log_entry = (
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{module_name}] ExitCode={proc.returncode} "
            f"Duration={duration_ms}ms | Cmd: {cmd_str}\n"
        )
        if proc.stdout and proc.stdout.strip():
            log_entry += f"STDOUT:\n{proc.stdout.strip()}\n"
        if raw_stderr:
            log_entry += f"STDERR:\n{raw_stderr}\n"
        log_entry += "-" * 80 + "\n"

        try:
            with self._log_lock:
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(log_entry)
        except OSError:
            pass

        if log_to_db:
            with DuckDBManager.get_lock(self.case_id):
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
        and source_tool using canonical WFT categories.
        """
        fname = csv_path.name.lower()
        stem_no_leading_ts = re.sub(r"^\d{8,25}_+", "", csv_path.stem)
        clean_stem = re.sub(r"[^A-Za-z0-9_]+", "_", stem_no_leading_ts).strip("_").lower() or "output"

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
            if "associatedfileentries" in fname:
                return {
                    "table_name": "raw_amcache_assoc_files",
                    "artifact_id": "os_amcache_assoc_files",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Associated File Entries",
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
            if "drivebinaries" in fname or "driverbinaries" in fname:
                return {
                    "table_name": "raw_amcache_drivers",
                    "artifact_id": "os_amcache_drivers",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Driver Binaries",
                    "source_tool": "AmcacheParser",
                }
            if "driverpackages" in fname:
                return {
                    "table_name": "raw_amcache_driver_packages",
                    "artifact_id": "os_amcache_driver_packages",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Driver Packages",
                    "source_tool": "AmcacheParser",
                }
            if "devicepnps" in fname:
                return {
                    "table_name": "raw_amcache_device_pnps",
                    "artifact_id": "os_amcache_device_pnps",
                    "category": "OPERATING SYSTEM",
                    "display_name": "Amcache Device PnPs",
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
            if "roleinfo" in fname:
                return {
                    "table_name": "raw_sum",
                    "artifact_id": "network_sum",
                    "category": "OPERATING SYSTEM",
                    "display_name": "User Access Logging (SUM)",
                    "source_tool": "SumECmd",
                }
            if "detail" in fname:
                return {
                    "table_name": "raw_sum_details",
                    "artifact_id": "network_sum_details",
                    "category": "OPERATING SYSTEM",
                    "display_name": "SUM Client Access Details",
                    "source_tool": "SumECmd",
                }
            if "systemident" in fname:
                return {
                    "table_name": "raw_sum_system_identity",
                    "artifact_id": "network_sum_system_identity",
                    "category": "OPERATING SYSTEM",
                    "display_name": "SUM System Identity",
                    "source_tool": "SumECmd",
                }
            if "chaineddb" in fname:
                return {
                    "table_name": "raw_sum_chained_dbs",
                    "artifact_id": "network_sum_chained_dbs",
                    "category": "OPERATING SYSTEM",
                    "display_name": "SUM Chained Databases",
                    "source_tool": "SumECmd",
                }
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
            stem_no_ts = re.sub(r"^\d{8,25}_+", "", csv_path.stem)
            stem_no_guid = re.sub(r"_[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}$", "", stem_no_ts)
            stem_no_guid = re.sub(r"_[0-9a-fA-F\-]{32,38}$", "", stem_no_guid)
            clean_core = re.sub(r"[^A-Za-z0-9_]+", "_", stem_no_guid).strip("_").lower() or "sqlite"

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

            cat = "OPERATING SYSTEM"
            if any(k in clean_core for k in ["browser", "chrome", "edge", "firefox", "download", "url", "history", "cookie"]):
                cat = "WEB RELATED"
            elif any(k in clean_core for k in ["chat", "teams", "slack", "discord", "message", "sms", "call"]):
                cat = "CHAT"

            human_name = clean_core.replace("_", " ").title()
            return {
                "table_name": f"raw_sqlecmd_{clean_core}",
                "artifact_id": f"sqlecmd_{clean_core}",
                "category": cat,
                "display_name": f"{human_name} (SQLECmd)",
                "source_tool": "SQLECmd",
            }

        return {
            "table_name": f"raw_{tool_name}_{clean_stem}",
            "artifact_id": f"artifact_{tool_name}_{clean_stem}",
            "category": "OPERATING SYSTEM",
            "display_name": f"{tool_name.upper()} ({clean_stem})",
            "source_tool": tool_name,
        }

    def ingest_csv_files(
        self,
        csv_paths: List[Path],
        table_name: str,
        category: str,
        display_name: str,
        source_tool: str,
        artifact_id: str,
    ) -> int:
        """
        Zero-copy multi-CSV union ingestion into DuckDB using read_csv_auto with _row_id.
        Strictly serialized under DuckDBManager.get_lock(self.case_id).
        """
        valid_csvs = [p.resolve() for p in csv_paths if p.exists() and p.stat().st_size > 0]
        if not valid_csvs:
            print(f"[EZToolRunner] Skipping empty or missing CSV list for '{table_name}'")
            return 0

        if len(valid_csvs) == 1:
            escaped_single = valid_csvs[0].as_posix().replace("'", "''")
            src_expr = f"'{escaped_single}'"
            union_opt = ""
        else:
            joined = ", ".join("'" + p.as_posix().replace("'", "''") + "'" for p in valid_csvs)
            src_expr = f"[{joined}]"
            union_opt = ", union_by_name=true"

        start_time = time.time()
        print(
            f"[EZToolRunner] Ingesting {len(valid_csvs)} CSV(s) -> Table: '{table_name}'"
        )

        for _csv_attempt in range(4):
            try:
                return self._ingest_csv_files_once(
                    valid_csvs=valid_csvs,
                    src_expr=src_expr,
                    union_opt=union_opt,
                    table_name=table_name,
                    category=category,
                    display_name=display_name,
                    source_tool=source_tool,
                    artifact_id=artifact_id,
                    start_time=start_time,
                )
            except Exception as csv_exc:
                err_low = str(csv_exc).lower()
                if _csv_attempt < 3 and any(
                    tok in err_low
                    for tok in ("transactioncontext", "failed to commit", "device is not ready", "could not flush")
                ):
                    time.sleep(0.5 * (_csv_attempt + 1))
                    continue
                raise
        return 0

    def _ingest_csv_files_once(
        self,
        valid_csvs: List[Path],
        src_expr: str,
        union_opt: str,
        table_name: str,
        category: str,
        display_name: str,
        source_tool: str,
        artifact_id: str,
        start_time: float,
    ) -> int:
        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cursor = conn.cursor()

            ingest_sql = f"""
            CREATE OR REPLACE TABLE "{table_name}" AS
            SELECT
                row_number() OVER () AS _row_id,
                *
            FROM read_csv_auto({src_expr}{union_opt}, ignore_errors=true, sample_size=-1, all_varchar=false);
            """

            try:
                cursor.execute(ingest_sql)
            except Exception as exc:
                if "Conversion Error" not in str(exc) or "out of range for the destination type INT32" not in str(exc):
                    print(
                        f"[EZToolRunner] Warning: all_varchar=false ingestion failed ({exc}). Retrying with all_varchar=true..."
                    )
                fallback_sql = f"""
                CREATE OR REPLACE TABLE "{table_name}" AS
                SELECT
                    row_number() OVER () AS _row_id,
                    *
                FROM read_csv_auto({src_expr}{union_opt}, ignore_errors=true, sample_size=-1, all_varchar=true);
                """
                try:
                    cursor.execute(fallback_sql)
                except Exception as fb_exc:
                    print(
                        f"[EZToolRunner] Warning: read_csv_auto fallback failed ({fb_exc}). Retrying with explicit CSV dialect..."
                    )
                    explicit_csv_sql = f"""
                    CREATE OR REPLACE TABLE "{table_name}" AS
                    SELECT
                        row_number() OVER () AS _row_id,
                        *
                    FROM read_csv({src_expr}{union_opt}, delim=',', quote='"', escape='"', header=true, ignore_errors=true, null_padding=true, strict_mode=false, all_varchar=true);
                    """
                    try:
                        cursor.execute(explicit_csv_sql)
                    except Exception as exp_exc:
                        print(
                            f"[EZToolRunner] Warning: explicit read_csv failed for '{table_name}' ({exp_exc}); skipping CSV ingestion."
                        )
                        return 0

            count_row = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()
            row_count = int(count_row[0]) if count_row else 0
            if row_count == 0:
                try:
                    varchar_sql = f"""
                    CREATE OR REPLACE TABLE "{table_name}" AS
                    SELECT
                        row_number() OVER () AS _row_id,
                        *
                    FROM read_csv_auto({src_expr}{union_opt}, all_varchar=true);
                    """
                    cursor.execute(varchar_sql)
                    count_row = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()
                    row_count = int(count_row[0]) if count_row else 0
                except Exception:
                    pass

            duration_ms = int((time.time() - start_time) * 1000)

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

            if table_name == "raw_recmd" and row_count > 0:
                self._create_recmd_virtual_views(cursor)

            log_processing_event(
                case_id=self.case_id,
                module_name=f"Ingest:{source_tool}",
                command_executed=f"read_csv_auto({len(valid_csvs)} file(s)) -> {table_name}",
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

    def ingest_csv_file(
        self,
        csv_path: Path,
        table_name: str,
        category: str,
        display_name: str,
        source_tool: str,
        artifact_id: str,
    ) -> int:
        """Backward-compatible single-CSV wrapper delegating to ingest_csv_files."""
        return self.ingest_csv_files(
            csv_paths=[csv_path],
            table_name=table_name,
            category=category,
            display_name=display_name,
            source_tool=source_tool,
            artifact_id=artifact_id,
        )

    def _create_recmd_virtual_views(self, cursor: duckdb.DuckDBPyConnection) -> None:
        """
        Create virtual filtered views from raw_recmd mapped to canonical WFT taxonomy:
        view_usb_devices, view_autoruns, view_userassist, view_bam_dam.
        Preserves UNION ALL with parsed_autoruns, parsed_bam_dam, and parsed_userassist
        whenever those native parser tables exist in DuckDB.
        """
        describe_rows = cursor.execute('DESCRIBE "raw_recmd";').fetchall()
        raw_cols = {str(r[0]).lower(): str(r[0]) for r in describe_rows}

        has_keypath = "keypath" in raw_cols
        has_category = "category" in raw_cols
        has_desc = "description" in raw_cols

        existing_base_tables = {
            str(r[0]).lower()
            for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'main' AND table_type = 'BASE TABLE';"
            ).fetchall()
        }

        def _rc(col_name: str) -> str:
            actual = raw_cols.get(col_name.lower())
            return f'"{actual}"' if actual else "NULL"

        def _rc_ts(col_name: str) -> str:
            actual = raw_cols.get(col_name.lower())
            return f'TRY_CAST("{actual}" AS TIMESTAMP)' if actual else "CAST(NULL AS TIMESTAMP)"

        views: List[Tuple[str, str, str, str, str, str]] = []

        if has_keypath:
            kp = _rc("KeyPath")
            cat_col = _rc("Category")
            desc_col = _rc("Description")

            usb_filter = f"{kp} ILIKE '%USBSTOR%' OR {kp} ILIKE '%MountedDevices%' OR {kp} ILIKE '%EMDMgmt%'"
            if has_desc:
                usb_filter += f" OR {desc_col} ILIKE '%USB%'"
            views.append(
                (
                    "view_usb_devices",
                    "OPERATING SYSTEM",
                    "USB Registry Activity",
                    "view_usb_devices",
                    "RECmd.exe",
                    f'SELECT * FROM "raw_recmd" WHERE ({usb_filter})',
                )
            )

            autorun_filter = f"{kp} ILIKE '%CurrentVersion\\Run%' OR {kp} ILIKE '%Services%'"
            if has_category:
                autorun_filter = f"{cat_col} ILIKE '%Run%' OR " + autorun_filter
            raw_autoruns_branch = f"""
                SELECT
                    CAST({_rc('ValueName')} AS VARCHAR) AS entry_name,
                    CAST({_rc('Category')} AS VARCHAR) AS Category,
                    CAST({kp} AS VARCHAR) AS KeyPath,
                    CAST({_rc('ValueName')} AS VARCHAR) AS ValueName,
                    CAST({_rc('ValueData')} AS VARCHAR) AS ValueData,
                    CAST({_rc('ValueData2')} AS VARCHAR) AS image_path,
                    CAST(NULL AS VARCHAR) AS username,
                    {_rc_ts('LastWriteTimestamp')} AS LastWriteTimestamp,
                    CAST({_rc('HivePath')} AS VARCHAR) AS HivePath,
                    'raw_recmd' AS source_table
                FROM "raw_recmd"
                WHERE ({autorun_filter})
            """
            if "parsed_autoruns" in existing_base_tables:
                parsed_autoruns_branch = """
                SELECT
                    CAST(COALESCE(entry_name, value_name) AS VARCHAR) AS entry_name,
                    CAST(COALESCE(autorun_type, category, 'Autorun') AS VARCHAR) AS Category,
                    CAST(COALESCE(key_path, location) AS VARCHAR) AS KeyPath,
                    CAST(COALESCE(value_name, entry_name) AS VARCHAR) AS ValueName,
                    CAST(COALESCE(command, launch_string, image_path) AS VARCHAR) AS ValueData,
                    CAST(image_path AS VARCHAR) AS image_path,
                    CAST(username AS VARCHAR) AS username,
                    TRY_CAST(COALESCE(last_modified_utc, last_write_utc) AS TIMESTAMP) AS LastWriteTimestamp,
                    CAST(COALESCE(hive_path, source_file) AS VARCHAR) AS HivePath,
                    'parsed_autoruns' AS source_table
                FROM "parsed_autoruns"
                """
                autoruns_sql = (
                    f"SELECT row_number() OVER () AS _row_id, u.* "
                    f"FROM ({parsed_autoruns_branch} UNION ALL {raw_autoruns_branch}) u"
                )
            else:
                autoruns_sql = f"SELECT row_number() OVER () AS _row_id, u.* FROM ({raw_autoruns_branch}) u"
            views.append(
                (
                    "view_autoruns",
                    "OPERATING SYSTEM",
                    "Autorun & Startup Items",
                    "view_autoruns",
                    "RECmd.exe / RegistryParser",
                    autoruns_sql,
                )
            )

            userassist_filter = f"{kp} ILIKE '%UserAssist%'"
            if has_category:
                userassist_filter = f"{cat_col} ILIKE '%UserAssist%' OR " + userassist_filter
            if has_desc:
                userassist_filter += f" OR {desc_col} ILIKE '%UserAssist%'"
            raw_ua_branch = f"""
                SELECT
                    CAST({_rc('Category')} AS VARCHAR) AS Category,
                    CAST({_rc('ValueName')} AS VARCHAR) AS program_path,
                    CAST(NULL AS VARCHAR) AS rot13_name,
                    CAST(NULL AS VARCHAR) AS guid,
                    TRY_CAST({_rc('ValueData2')} AS INTEGER) AS run_count,
                    CAST(NULL AS INTEGER) AS focus_count,
                    CAST(NULL AS BIGINT) AS focus_time_ms,
                    CAST(NULL AS VARCHAR) AS username,
                    CAST({kp} AS VARCHAR) AS KeyPath,
                    CAST({_rc('ValueName')} AS VARCHAR) AS ValueName,
                    CAST({_rc('ValueData')} AS VARCHAR) AS ValueData,
                    {_rc_ts('LastWriteTimestamp')} AS LastWriteTimestamp,
                    CAST({_rc('HivePath')} AS VARCHAR) AS HivePath,
                    'raw_recmd' AS source_table
                FROM "raw_recmd"
                WHERE ({userassist_filter})
            """
            if "parsed_userassist" in existing_base_tables:
                parsed_ua_branch = """
                SELECT
                    'UserAssist' AS Category,
                    CAST(program_path AS VARCHAR) AS program_path,
                    CAST(rot13_name AS VARCHAR) AS rot13_name,
                    CAST(guid AS VARCHAR) AS guid,
                    TRY_CAST(run_count AS INTEGER) AS run_count,
                    TRY_CAST(focus_count AS INTEGER) AS focus_count,
                    TRY_CAST(focus_time_ms AS BIGINT) AS focus_time_ms,
                    CAST(username AS VARCHAR) AS username,
                    COALESCE(CAST(key_path AS VARCHAR), 'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\' || COALESCE(CAST(guid AS VARCHAR), '')) AS KeyPath,
                    CAST(COALESCE(program_path, rot13_name) AS VARCHAR) AS ValueName,
                    'RunCount=' || COALESCE(CAST(run_count AS VARCHAR), '0') AS ValueData,
                    TRY_CAST(COALESCE(last_executed_utc, last_run_utc) AS TIMESTAMP) AS LastWriteTimestamp,
                    CAST(COALESCE(hive_path, source_file) AS VARCHAR) AS HivePath,
                    'parsed_userassist' AS source_table
                FROM "parsed_userassist"
                """
                ua_sql = (
                    f"SELECT row_number() OVER () AS _row_id, u.* "
                    f"FROM ({parsed_ua_branch} UNION ALL {raw_ua_branch}) u"
                )
            else:
                ua_sql = f"SELECT row_number() OVER () AS _row_id, u.* FROM ({raw_ua_branch}) u"
            views.append(
                (
                    "view_userassist",
                    "OPERATING SYSTEM",
                    "UserAssist GUI Execution",
                    "view_userassist",
                    "RECmd.exe / RegistryParser",
                    ua_sql,
                )
            )

            bam_filter = f"{kp} ILIKE '%bam%' OR {kp} ILIKE '%dam%'"
            if has_desc:
                bam_filter += f" OR {desc_col} ILIKE '%bam%' OR {desc_col} ILIKE '%dam%'"
            raw_bam_branch = f"""
                SELECT
                    CAST({_rc('Category')} AS VARCHAR) AS Category,
                    CAST({_rc('ValueName')} AS VARCHAR) AS executable_path,
                    CAST(NULL AS VARCHAR) AS user_sid,
                    CAST(NULL AS VARCHAR) AS username,
                    CAST({kp} AS VARCHAR) AS KeyPath,
                    CAST({_rc('ValueName')} AS VARCHAR) AS ValueName,
                    CAST({_rc('ValueData')} AS VARCHAR) AS ValueData,
                    {_rc_ts('LastWriteTimestamp')} AS LastWriteTimestamp,
                    CAST({_rc('HivePath')} AS VARCHAR) AS HivePath,
                    'raw_recmd' AS source_table
                FROM "raw_recmd"
                WHERE ({bam_filter})
            """
            if "parsed_bam_dam" in existing_base_tables:
                parsed_bam_branch = """
                SELECT
                    COALESCE(CAST(service_type AS VARCHAR), 'BAM') AS Category,
                    CAST(COALESCE(executable_path, app_name) AS VARCHAR) AS executable_path,
                    CAST(user_sid AS VARCHAR) AS user_sid,
                    CAST(username AS VARCHAR) AS username,
                    COALESCE(CAST(key_path AS VARCHAR), 'SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\' || COALESCE(CAST(user_sid AS VARCHAR), '')) AS KeyPath,
                    CAST(COALESCE(executable_path, app_name) AS VARCHAR) AS ValueName,
                    COALESCE(CAST(COALESCE(last_execution_utc, execution_time_utc) AS VARCHAR), '') AS ValueData,
                    TRY_CAST(COALESCE(last_execution_utc, execution_time_utc) AS TIMESTAMP) AS LastWriteTimestamp,
                    CAST(COALESCE(hive_path, source_file) AS VARCHAR) AS HivePath,
                    'parsed_bam_dam' AS source_table
                FROM "parsed_bam_dam"
                """
                bam_sql = (
                    f"SELECT row_number() OVER () AS _row_id, u.* "
                    f"FROM ({parsed_bam_branch} UNION ALL {raw_bam_branch}) u"
                )
            else:
                bam_sql = f"SELECT row_number() OVER () AS _row_id, u.* FROM ({raw_bam_branch}) u"
            views.append(
                (
                    "view_bam_dam",
                    "OPERATING SYSTEM",
                    "Background Activity Moderator (BAM/DAM)",
                    "view_bam_dam",
                    "RECmd.exe / RegistryParser",
                    bam_sql,
                )
            )

        for view_name, category, display_name, artifact_id, src_tool, query_sql in views:
            try:
                cursor.execute(f'CREATE OR REPLACE VIEW "{view_name}" AS {query_sql};')
                v_count_row = cursor.execute(f'SELECT COUNT(*) FROM "{view_name}";').fetchone()
                v_count = int(v_count_row[0]) if v_count_row else 0
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
                    [artifact_id, category, display_name, view_name, src_tool, v_count],
                )
                print(f"[EZToolRunner] Created virtual registry view '{view_name}' ({v_count} rows)")
            except Exception as ex:
                print(f"[EZToolRunner] Failed creating view '{view_name}': {ex}")

    def ingest_csv_directory(self, tool_name: str, csv_dir: Path) -> Dict[str, int]:
        """
        Recursively scan a dedicated tool directory for all non-empty CSV files,
        group by target table_name, and union-ingest into DuckDB without overwrites.
        """
        results: Dict[str, int] = {}
        if not csv_dir.exists():
            csv_dir.mkdir(parents=True, exist_ok=True)
            return results

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

        csv_files = sorted(
            p for p in csv_dir.rglob("*.csv")
            if "_staged_inputs" not in p.parts and has_data_rows(p)
        )
        if not csv_files:
            return {}

        grouped: Dict[str, Tuple[Dict[str, str], List[Path]]] = {}
        for csv_f in csv_files:
            meta = self.map_csv_to_table_info(tool_name, csv_f)
            tname = meta["table_name"]
            if tname not in grouped:
                grouped[tname] = (meta, [])
            grouped[tname][1].append(csv_f)

        for tname, (meta, paths) in grouped.items():
            count = self.ingest_csv_files(
                csv_paths=paths,
                table_name=tname,
                category=meta["category"],
                display_name=meta["display_name"],
                source_tool=meta["source_tool"],
                artifact_id=meta["artifact_id"],
            )
            results[tname] = count

        # Amcache fallback: if AssociatedFileEntries had rows while UnassociatedFileEntries was absent/empty,
        # populate raw_amcache_files and create backward-compatible raw_amcache view.
        if tool_name == "amcache":
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cursor = conn.cursor()
                if results.get("raw_amcache_files", 0) == 0 and results.get("raw_amcache_assoc_files", 0) > 0:
                    assoc_cnt = results["raw_amcache_assoc_files"]
                    cursor.execute('CREATE OR REPLACE TABLE "raw_amcache_files" AS SELECT * FROM "raw_amcache_assoc_files";')
                    cursor.execute(
                        "DELETE FROM artifact_registry WHERE table_name = 'raw_amcache_files' AND artifact_id != 'os_amcache_files';"
                    )
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                        ) VALUES ('os_amcache_files', 'OPERATING SYSTEM', 'Amcache File Entries', 'raw_amcache_files', 'AmcacheParser', ?, CURRENT_TIMESTAMP);
                        """,
                        [assoc_cnt],
                    )
                    results["raw_amcache_files"] = assoc_cnt
                if results.get("raw_amcache_files", 0) > 0:
                    try:
                        cursor.execute('CREATE OR REPLACE VIEW "raw_amcache" AS SELECT * FROM "raw_amcache_files";')
                    except Exception:
                        pass

        # SumECmd fallback: if SUMMARY_RoleInfos was empty/absent while DETAIL_* had rows, populate raw_sum too.
        if tool_name == "sum":
            if results.get("raw_sum", 0) == 0 and results.get("raw_sum_details", 0) > 0:
                det_cnt = results["raw_sum_details"]
                with DuckDBManager.get_lock(self.case_id):
                    conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                    cursor = conn.cursor()
                    cursor.execute('CREATE OR REPLACE TABLE "raw_sum" AS SELECT * FROM "raw_sum_details";')
                    cursor.execute(
                        "DELETE FROM artifact_registry WHERE table_name = 'raw_sum' AND artifact_id != 'network_sum';"
                    )
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                        ) VALUES ('network_sum', 'OPERATING SYSTEM', 'User Access Logging (SUM)', 'raw_sum', 'SumECmd', ?, CURRENT_TIMESTAMP);
                        """,
                        [det_cnt],
                    )
                results["raw_sum"] = det_cnt

        return results

    # =========================================================================
    # TOOL 0: rla.exe (Registry Transaction Log Replay)
    # =========================================================================
    def _collect_staged_hive_roots(
        self, staged_registry_dir: Optional[Path] = None
    ) -> List[Tuple[Path, Path, List[Path]]]:
        """Collect (src_root, rel_prefix, candidate_hives) across active & VSS registry staging roots."""
        source_roots: List[Tuple[Path, Path, bool]] = []
        if staged_registry_dir is not None:
            sr = Path(staged_registry_dir).resolve()
            if sr.exists():
                source_roots.append((sr, Path("."), False))
        else:
            reg_dir = (self.staging_dir / "Registry").resolve()
            if reg_dir.is_dir():
                source_roots.append((reg_dir, Path("."), False))
            elif self.staging_dir.is_dir():
                source_roots.append((self.staging_dir.resolve(), Path("."), True))

            vss_root = (self.staging_dir / "VSS").resolve()
            if vss_root.is_dir():
                for vss_sub in sorted(vss_root.iterdir(), key=lambda p: p.name.lower()):
                    if vss_sub.is_dir():
                        vss_reg = (vss_sub / "Registry").resolve()
                        src_vss = vss_reg if vss_reg.is_dir() else vss_sub.resolve()
                        source_roots.append((src_vss, Path("VSS") / vss_sub.name, False))

        active_roots: List[Tuple[Path, Path, List[Path]]] = []
        for src_root, rel_prefix, skip_vss_subtree in source_roots:
            if not src_root.exists():
                continue
            cands: List[Path] = []
            if src_root.is_file():
                if _is_hive_candidate(src_root):
                    cands.append(src_root)
            else:
                for p in src_root.rglob("*"):
                    if skip_vss_subtree and "vss" in [pt.lower() for pt in p.relative_to(src_root).parts[:-1]]:
                        continue
                    if _is_hive_candidate(p):
                        cands.append(p)
            if cands:
                active_roots.append((src_root, rel_prefix, cands))
        return active_roots

    def _clean_hives_are_warm(self, staged_registry_dir: Optional[Path] = None) -> bool:
        """
        Return True if self.clean_hives_dir already holds non-empty up-to-date cleaned hives
        covering every staged source hive (and transaction logs).
        """
        if not self.clean_hives_dir.is_dir():
            return False
        active_roots = self._collect_staged_hive_roots(staged_registry_dir=staged_registry_dir)
        if not active_roots:
            return False
        for src_root, rel_prefix, cands in active_roots:
            for src_hive in cands:
                try:
                    rel_subpath = src_hive.relative_to(src_root) if src_root.is_dir() else Path(src_hive.name)
                    dest_hive = (self.clean_hives_dir / rel_prefix / rel_subpath).resolve()
                    if not dest_hive.is_file():
                        return False
                    dest_st = dest_hive.stat()
                    if dest_st.st_size <= 0:
                        return False
                    src_mtime = src_hive.stat().st_mtime
                    for log_suf in (".LOG", ".LOG1", ".LOG2", ".log", ".log1", ".log2"):
                        sib_log = src_hive.parent / f"{src_hive.name}{log_suf}"
                        if sib_log.is_file():
                            src_mtime = max(src_mtime, sib_log.stat().st_mtime)
                    if dest_st.st_mtime + 0.005 < src_mtime:
                        return False
                except OSError:
                    return False
        return True

    def _stage_clean_hives_with_rla(self, staged_registry_dir: Optional[Path] = None) -> bool:
        """
        Execute rla.exe v2026.10.1 (--ca --nop false --co false) inside an isolated temporary
        sibling build directory (<case_dir>/_clean_hives_build_<uuid8>) and atomically replace
        targets into self.clean_hives_dir under a per-case clean-hives lock so concurrent readers
        (e.g. RegRipperRunner) NEVER see missing or partially written hive files.
        """
        with _acquire_clean_hives_lock(self.case_id, self.case_dir):
            active_roots = self._collect_staged_hive_roots(staged_registry_dir=staged_registry_dir)
            if not active_roots:
                print(f"[EZToolRunner][rla] No staged registry hives found under '{self.staging_dir}'. Skipping.")
                return False

            self.clean_hives_dir.mkdir(parents=True, exist_ok=True)
            build_dir = (self.case_dir / f"_clean_hives_build_{uuid.uuid4().hex[:8]}").resolve()
            build_dir.mkdir(parents=True, exist_ok=True)

            try:
                try:
                    rla_exe: Optional[Path] = self._find_ez_binary_with_fallback("rla.exe", "WFT_EZ_RLA_EXE")
                except FileNotFoundError as fnf:
                    self._log(f"rla.exe unavailable ({fnf}); falling back to relative-path hive copy.", "WARNING")
                    rla_exe = None

                for src_root, rel_prefix, cands in active_roots:
                    if rla_exe is not None and src_root.is_dir():
                        rla_tmp = Path(tempfile.mkdtemp(prefix="wft_rla_"))
                        try:
                            cmd = [
                                str(rla_exe),
                                "-d",
                                str(src_root),
                                "--out",
                                str(rla_tmp),
                                "--nop",
                                "false",
                                "--cn",
                                "false",
                            ]
                            self._execute_subprocess("rla", cmd, timeout=300)

                            drive_part = src_root.drive.rstrip(":\\/")
                            anchor_rel = src_root.relative_to(src_root.anchor)
                            reconstructed_root = (
                                (rla_tmp / drive_part / anchor_rel)
                                if drive_part
                                else (rla_tmp / anchor_rel)
                            )

                            for f in cands:
                                rel_sub = f.relative_to(src_root) if src_root.is_dir() else Path(f.name)
                                flat_full = str(f.resolve()).replace(":", "").replace("\\", "_").replace("/", "_")
                                flat_dir = str(f.parent.resolve()).replace(":", "").replace("\\", "_").replace("/", "_")
                                for cand_out in (
                                    reconstructed_root / rel_sub,
                                    rla_tmp / flat_dir / f.name,
                                    rla_tmp / flat_full,
                                ):
                                    if cand_out.is_file() and cand_out.stat().st_size > 0:
                                        dest = (build_dir / rel_prefix / rel_sub).resolve()
                                        dest.parent.mkdir(parents=True, exist_ok=True)
                                        shutil.move(str(cand_out), str(dest))
                                        break
                        except Exception as rla_ex:
                            self._log(f"rla replay notice for '{src_root}': {rla_ex}", "WARNING")
                        finally:
                            shutil.rmtree(rla_tmp, ignore_errors=True)

                    # Relative-path fallback copy into build_dir for any hive candidate not yet replayed
                    for f in cands:
                        try:
                            rel_subpath = f.relative_to(src_root) if src_root.is_dir() else Path(f.name)
                            dest_f = (build_dir / rel_prefix / rel_subpath).resolve()
                            if not dest_f.exists():
                                dest_f.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(f, dest_f)
                        except Exception as copy_ex:
                            print(f"[EZToolRunner][rla] Notice copying remaining hive '{f}': {copy_ex}")

                # Atomically publish built hives into self.clean_hives_dir without ever deleting live targets first
                installed_targets: Set[Path] = set()
                for built_f in build_dir.rglob("*"):
                    if not built_f.is_file():
                        continue
                    rel_p = built_f.relative_to(build_dir)
                    final_dest = (self.clean_hives_dir / rel_p).resolve()
                    final_dest.parent.mkdir(parents=True, exist_ok=True)
                    installed_targets.add(final_dest)

                    # Skip rewrite if identical non-empty cleaned hive is already in place
                    if final_dest.is_file():
                        try:
                            if _file_digest_key(final_dest) == _file_digest_key(built_f):
                                now_ts = time.time()
                                try:
                                    os.utime(final_dest, (now_ts, max(now_ts, final_dest.stat().st_mtime)))
                                except OSError:
                                    pass
                                continue
                        except OSError:
                            pass

                    tmp_target = final_dest.parent / f".tmp_{final_dest.name}_{uuid.uuid4().hex[:8]}"
                    try:
                        shutil.copy2(built_f, tmp_target)
                        replaced = False
                        for attempt in range(5):
                            try:
                                os.replace(str(tmp_target), str(final_dest))
                                replaced = True
                                break
                            except PermissionError:
                                if attempt < 4:
                                    time.sleep(0.05)
                        if not replaced and not final_dest.exists():
                            shutil.copy2(built_f, final_dest)
                    finally:
                        try:
                            tmp_target.unlink(missing_ok=True)
                        except OSError:
                            pass

                # Prune only obsolete files no longer part of the staged hive manifest
                for existing_f in list(self.clean_hives_dir.rglob("*")):
                    if existing_f.is_file() and not existing_f.name.startswith(".tmp_"):
                        if existing_f.resolve() not in installed_targets:
                            try:
                                existing_f.unlink(missing_ok=True)
                            except OSError:
                                pass
                for existing_d in sorted(
                    (p for p in self.clean_hives_dir.rglob("*") if p.is_dir()),
                    key=lambda p: len(p.parts),
                    reverse=True,
                ):
                    try:
                        if not any(existing_d.iterdir()):
                            existing_d.rmdir()
                    except OSError:
                        pass
            finally:
                shutil.rmtree(build_dir, ignore_errors=True)

            cleaned_files = [p for p in self.clean_hives_dir.rglob("*") if p.is_file()]
            print(f"[EZToolRunner][rla] Cleaned hives count in '{self.clean_hives_dir}': {len(cleaned_files)}")
            return len(cleaned_files) > 0

    def run_rla(self, staged_registry_dir: Optional[Path] = None) -> bool:
        """Backward-compatible alias for _stage_clean_hives_with_rla."""
        return self._stage_clean_hives_with_rla(staged_registry_dir=staged_registry_dir)

    # =========================================================================
    # TOOL 1: PECmd.exe (Prefetch)
    # =========================================================================
    def run_pecmd(self, pf_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute PECmd.exe on staged Prefetch directory or individual .pf file.
        Ingests pecmd.csv -> raw_pecmd and pecmd_Timeline.csv -> raw_pecmd_timeline.
        """
        target = Path(pf_input).resolve() if pf_input else (self.staging_dir / "Prefetch").resolve()
        if not target.exists():
            target = self.staging_dir

        if target.is_dir() and not any(f.is_file() and f.suffix.lower() == ".pf" for f in target.rglob("*")):
            print("[EZToolRunner][PECmd] No .pf Prefetch files found. Skipping.")
            return {}

        pecmd_exe = self._find_ez_binary_with_fallback("PECmd.exe", "WFT_EZ_PECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "pecmd")

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

        self._execute_subprocess("PECmd", cmd, timeout=300)
        return self.ingest_csv_directory("pecmd", out_dir)

    # =========================================================================
    # TOOL 2: AmcacheParser.exe
    # =========================================================================
    def run_amcache(self, amcache_hve: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute AmcacheParser.exe across all unique Amcache.hve hives (active + VSS).
        Ingests UnassociatedFileEntries, AssociatedFileEntries, ProgramEntries,
        ShortCuts, DeviceContainers, DriveBinaries, DriverPackages, DevicePnps.
        """
        targets: List[Path] = []
        seen_digests: Set[Tuple[int, str]] = set()

        if amcache_hve and Path(amcache_hve).exists():
            targets.append(Path(amcache_hve).resolve())
        else:
            search_roots = (
                [self.clean_hives_dir]
                if self.clean_hives_dir.exists() and any(p.is_file() for p in self.clean_hives_dir.rglob("*"))
                else [self.staging_dir / "Registry", self.staging_dir]
            )
            for search_root in search_roots:
                if not search_root.exists():
                    continue
                for f in sorted(search_root.rglob("*"), key=lambda p: str(p).lower()):
                    if f.is_file() and f.name.lower() == "amcache.hve" and f.stat().st_size > 0:
                        try:
                            dkey = _file_digest_key(f)
                        except OSError:
                            continue
                        if dkey not in seen_digests:
                            seen_digests.add(dkey)
                            targets.append(f.resolve())

        if not targets:
            print("[EZToolRunner][AmcacheParser] Amcache.hve not found. Skipping.")
            return {}

        amcache_exe = self._find_ez_binary_with_fallback("AmcacheParser.exe", "WFT_EZ_AMCACHE_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "amcache")

        for idx, target in enumerate(targets):
            sub_out = (out_dir / f"hive_{idx:03d}").resolve() if len(targets) > 1 else out_dir
            sub_out.mkdir(parents=True, exist_ok=True)
            cmd = [
                str(amcache_exe),
                "-f",
                str(target),
                "-i",
                "--csv",
                str(sub_out),
                "--csvf",
                "amcache.csv",
                "--mp",
            ]
            self._execute_subprocess("AmcacheParser", cmd, timeout=600)

        return self.ingest_csv_directory("amcache", out_dir)

    # =========================================================================
    # TOOL 3: AppCompatCacheParser.exe (Shimcache)
    # =========================================================================
    def run_appcompatcache(self, system_hive: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute AppCompatCacheParser.exe on SYSTEM hive(s).
        Ingests shimcache.csv -> raw_shimcache.
        """
        targets: List[Path] = []
        seen_digests: Set[Tuple[int, str]] = set()

        if system_hive and Path(system_hive).exists():
            targets.append(Path(system_hive).resolve())
        else:
            search_roots = (
                [self.clean_hives_dir]
                if self.clean_hives_dir.exists() and any(p.is_file() for p in self.clean_hives_dir.rglob("*"))
                else [self.staging_dir / "Registry", self.staging_dir]
            )
            for search_root in search_roots:
                if not search_root.exists():
                    continue
                for f in sorted(search_root.rglob("*"), key=lambda p: str(p).lower()):
                    if f.is_file() and f.name.lower() == "system" and f.stat().st_size > 0:
                        try:
                            dkey = _file_digest_key(f)
                        except OSError:
                            continue
                        if dkey not in seen_digests:
                            seen_digests.add(dkey)
                            targets.append(f.resolve())

        if not targets:
            print("[EZToolRunner][AppCompatCacheParser] SYSTEM hive not found. Skipping.")
            return {}

        shimcache_exe = self._find_ez_binary_with_fallback("AppCompatCacheParser.exe", "WFT_EZ_SHIMCACHE_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "shimcache")

        for idx, target in enumerate(targets):
            sub_out = (out_dir / f"hive_{idx:03d}").resolve() if len(targets) > 1 else out_dir
            sub_out.mkdir(parents=True, exist_ok=True)
            cmd = [
                str(shimcache_exe),
                "-f",
                str(target),
                "--csv",
                str(sub_out),
                "--csvf",
                "shimcache.csv",
            ]
            self._execute_subprocess("AppCompatCacheParser", cmd, timeout=300)

        return self.ingest_csv_directory("shimcache", out_dir)

    # =========================================================================
    # TOOL 4: EvtxECmd.exe (Event Logs)
    # =========================================================================
    def run_evtx(self, logs_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute EvtxECmd.exe on staged Logs directory or individual .evtx file.
        Ingests evtx.csv -> raw_evtx.
        """
        target = Path(logs_input).resolve() if logs_input else (self.staging_dir / "Logs").resolve()
        if not target.exists():
            alt_logs = (self.staging_dir / "winevt" / "Logs").resolve()
            target = alt_logs if alt_logs.exists() else self.staging_dir

        if target.is_dir() and not any(f.is_file() and f.suffix.lower() == ".evtx" for f in target.rglob("*")):
            print("[EZToolRunner][EvtxECmd] No .evtx files found. Skipping.")
            return {}

        evtx_exe = self._find_ez_binary_with_fallback("EvtxECmd.exe", "WFT_EZ_EVTXECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "evtx")

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

        self._execute_subprocess("EvtxECmd", cmd, timeout=1800)
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
        target = Path(mft_file).resolve() if mft_file else None
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

        mftecmd_exe = self._find_ez_binary_with_fallback("MFTECmd.exe", "WFT_EZ_MFTECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "mft")

        cmd = [
            str(mftecmd_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "mft.csv",
        ]

        self._execute_subprocess("MFTECmd_MFT", cmd, timeout=600)
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
        target = Path(usn_file).resolve() if usn_file else None
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

        mftecmd_exe = self._find_ez_binary_with_fallback("MFTECmd.exe", "WFT_EZ_MFTECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "usnjrnl")

        cmd = [
            str(mftecmd_exe),
            "-f",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "usnjrnl.csv",
        ]

        if mft_file and Path(mft_file).exists():
            cmd.extend(["-m", str(Path(mft_file).resolve())])

        self._execute_subprocess("MFTECmd_USN", cmd, timeout=600)
        return self.ingest_csv_directory("usnjrnl", out_dir)

    # =========================================================================
    # TOOL 7: LECmd.exe (LNK Shortcut Files)
    # =========================================================================
    def run_lecmd(self, lnk_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute LECmd.exe on staged LNK shortcut directory or individual .lnk file.
        Ingests lecmd.csv -> raw_lecmd.
        """
        target = Path(lnk_input).resolve() if lnk_input else (self.staging_dir / "LNK").resolve()
        if not target.exists():
            alt_lnk = (self.staging_dir / "Recent").resolve()
            target = alt_lnk if alt_lnk.exists() else self.staging_dir

        if target.is_dir() and not any(f.is_file() and f.suffix.lower() == ".lnk" for f in target.rglob("*")):
            print("[EZToolRunner][LECmd] No .lnk shortcut files found. Skipping.")
            return {}

        lecmd_exe = self._find_ez_binary_with_fallback("LECmd.exe", "WFT_EZ_LECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "lecmd")

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

        self._execute_subprocess("LECmd", cmd, timeout=300)
        return self.ingest_csv_directory("lecmd", out_dir)

    # =========================================================================
    # TOOL 8: JLECmd.exe (Jump Lists)
    # =========================================================================
    def run_jlecmd(self, jl_input: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute JLECmd.exe across deduplicated JumpLists (AutomaticDestinations & CustomDestinations).
        Ingests raw_jlecmd_auto and raw_jlecmd_custom without flat+subfolder double counting.
        """
        if jl_input is not None:
            explicit_target = Path(jl_input).resolve()
            if not explicit_target.exists():
                return {}
            if explicit_target.is_file():
                jlecmd_exe = self._find_ez_binary_with_fallback("JLECmd.exe", "WFT_EZ_JLECMD_EXE")
                out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "jlecmd")
                cmd = [
                    str(jlecmd_exe),
                    "-f",
                    str(explicit_target),
                    "--csv",
                    str(out_dir),
                    "--csvf",
                    "jlecmd.csv",
                    "--mp",
                    "-q",
                ]
                self._execute_subprocess("JLECmd", cmd, timeout=300)
                return self.ingest_csv_directory("jlecmd", out_dir)
            search_roots = [explicit_target]
        else:
            search_roots = []
            jl_dir = (self.staging_dir / "JumpLists").resolve()
            if jl_dir.is_dir():
                search_roots.append(jl_dir)
            vss_dir = (self.staging_dir / "VSS").resolve()
            if vss_dir.is_dir():
                for vss_sub in sorted(vss_dir.iterdir(), key=lambda p: p.name.lower()):
                    if (vss_sub / "JumpLists").is_dir():
                        search_roots.append((vss_sub / "JumpLists").resolve())
            if not search_roots:
                search_roots.append(self.staging_dir)

        unique_jls: List[Path] = []
        seen_jl: Set[Tuple[str, int, str]] = set()
        for s_root in search_roots:
            if not s_root.is_dir():
                continue
            for p in sorted(s_root.rglob("*"), key=lambda x: (-len(x.parts), str(x).lower())):
                if not p.is_file():
                    continue
                low_name = p.name.lower()
                if not (
                    low_name.endswith(".automaticdestinations-ms")
                    or low_name.endswith(".customdestinations-ms")
                ):
                    continue
                try:
                    sz, digest = _file_digest_key(p)
                except OSError:
                    continue
                if sz == 0:
                    continue
                key = (low_name, sz, digest)
                if key not in seen_jl:
                    seen_jl.add(key)
                    unique_jls.append(p.resolve())

        if not unique_jls:
            print("[EZToolRunner][JLECmd] No JumpList files found. Skipping.")
            return {}

        jlecmd_exe = self._find_ez_binary_with_fallback("JLECmd.exe", "WFT_EZ_JLECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "jlecmd")
        staged_inputs = (out_dir / "_staged_inputs").resolve()
        staged_inputs.mkdir(parents=True, exist_ok=True)

        try:
            for idx, jl_f in enumerate(unique_jls):
                sub = staged_inputs / f"jl_{idx:04d}"
                sub.mkdir(parents=True, exist_ok=True)
                shutil.copy2(jl_f, sub / jl_f.name)

            cmd = [
                str(jlecmd_exe),
                "-d",
                str(staged_inputs),
                "--csv",
                str(out_dir),
                "--csvf",
                "jlecmd.csv",
                "--mp",
                "-q",
            ]
            self._execute_subprocess("JLECmd", cmd, timeout=300)
        finally:
            shutil.rmtree(staged_inputs, ignore_errors=True)

        return self.ingest_csv_directory("jlecmd", out_dir)

    # =========================================================================
    # TOOL 9: SBECmd.exe (ShellBags)
    # =========================================================================
    def run_sbecmd(self, hives_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute SBECmd.exe on cleaned hives directory.
        Ingests shellbags.csv -> raw_shellbags.
        """
        target = Path(hives_dir).resolve() if hives_dir else self.clean_hives_dir
        if not target.exists() or not any(p.is_file() for p in target.rglob("*")):
            target = (self.staging_dir / "Registry").resolve()
            if not target.exists() or not any(p.is_file() for p in target.rglob("*")):
                target = self.staging_dir

        if not any(_is_hive_candidate(p) for p in (target.rglob("*") if target.is_dir() else [target])):
            print("[EZToolRunner][SBECmd] No registry hives found for ShellBags. Skipping.")
            return {}

        sbecmd_exe = self._find_ez_binary_with_fallback("SBECmd.exe", "WFT_EZ_SBECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "shellbags")

        cmd = [
            str(sbecmd_exe),
            "-d",
            str(target),
            "--csv",
            str(out_dir),
            "--csvf",
            "shellbags.csv",
        ]

        self._execute_subprocess("SBECmd", cmd, timeout=300)
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
        Execute RECmd.exe with Kroll_Batch.reb across all staged/cleaned registry hives.
        Ingests recmd.csv -> raw_recmd and builds virtual filtered views.
        """
        target = Path(hives_dir).resolve() if hives_dir else self.clean_hives_dir
        if not target.exists() or not any(p.is_file() for p in target.rglob("*")):
            target = (self.staging_dir / "Registry").resolve()
            if not target.exists() or not any(p.is_file() for p in target.rglob("*")):
                target = self.staging_dir

        if not any(_is_hive_candidate(p) for p in (target.rglob("*") if target.is_dir() else [target])):
            print("[EZToolRunner][RECmd] No registry hives found. Skipping.")
            return {}

        recmd_exe = self._find_ez_binary_with_fallback("RECmd.exe", "WFT_EZ_RECMD_EXE")

        batch_file = Path(batch_reb_file).resolve() if (batch_reb_file and Path(batch_reb_file).exists()) else None
        if batch_file is None:
            batch_file = find_ez_file("Kroll_Batch.reb", raise_if_missing=False)
        if batch_file is None or not batch_file.exists():
            for cand in (
                recmd_exe.parent / "BatchExamples" / "Kroll_Batch.reb",
                recmd_exe.parent / "Kroll_Batch.reb",
                recmd_exe.parent.parent / "RECmd" / "BatchExamples" / "Kroll_Batch.reb",
                recmd_exe.parent.parent / "BatchExamples" / "Kroll_Batch.reb",
                BASE_DIR / "EZTools" / "RECmd" / "BatchExamples" / "Kroll_Batch.reb",
                BASE_DIR / "tools" / "ez_tools" / "net" / "RECmd" / "BatchExamples" / "Kroll_Batch.reb",
                BASE_DIR / "tools" / "ez_tools" / "RECmd" / "BatchExamples" / "Kroll_Batch.reb",
            ):
                if cand.is_file():
                    batch_file = cand.resolve()
                    break

        if batch_file is None or not batch_file.exists():
            self._log("Kroll_Batch.reb not found for RECmd; skipping.", "WARNING")
            return {}

        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "recmd")

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

        self._execute_subprocess("RECmd", cmd, timeout=600)
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
        target_srudb = Path(srudb_file).resolve() if srudb_file else None
        if target_srudb is None or not target_srudb.exists():
            for search_root in [
                self.staging_dir / "SRUM",
                self.staging_dir / "srum",
                self.staging_dir / "SRUDB.dat",
                self.staging_dir / "sru",
                self.staging_dir,
            ]:
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

        target_software = Path(software_hive).resolve() if software_hive else None
        if target_software is None or not target_software.exists():
            for search_root in [self.clean_hives_dir, self.staging_dir / "Registry", self.staging_dir]:
                if search_root.exists():
                    for f in search_root.rglob("*"):
                        if f.is_file() and f.name.lower() == "software":
                            target_software = f.resolve()
                            break
                if target_software:
                    break

        srum_exe = self._find_ez_binary_with_fallback("SrumECmd.exe", "WFT_EZ_SRUMECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "srum")

        cmd = [
            str(srum_exe),
            "-f",
            str(target_srudb),
            "--csv",
            str(out_dir),
        ]
        if target_software and target_software.exists():
            cmd.extend(["-r", str(target_software)])

        self._execute_subprocess("SrumECmd", cmd, timeout=300)
        return self.ingest_csv_directory("srum", out_dir)

    # =========================================================================
    # TOOL 12: WxTCmd.exe (Windows Timeline — All Users & VSS)
    # =========================================================================
    def run_wxt(self, wxt_file: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute WxTCmd.exe across ALL unique staged ActivitiesCache.db files (multi-user + VSS).
        Unions all per-user CSV outputs into raw_wxt_activity / raw_wxt_operations / raw_wxt_package_ids.
        """
        targets: List[Path] = []
        seen_digests: Set[Tuple[int, str]] = set()

        if wxt_file and Path(wxt_file).exists():
            p = Path(wxt_file).resolve()
            if p.is_file():
                targets.append(p)
            else:
                for f in sorted(p.rglob("*"), key=lambda x: str(x).lower()):
                    if f.is_file() and f.name.lower() == "activitiescache.db" and f.stat().st_size > 0:
                        try:
                            dkey = _file_digest_key(f)
                        except OSError:
                            continue
                        if dkey not in seen_digests:
                            seen_digests.add(dkey)
                            targets.append(f.resolve())
        else:
            primary_roots = [
                self.staging_dir / "ActivitiesCache",
                self.staging_dir / "Timeline",
                self.staging_dir / "SQLite",
                self.staging_dir / "VSS",
            ]
            for root in primary_roots:
                if not root.exists():
                    continue
                if root.is_file() and root.name.lower() == "activitiescache.db":
                    try:
                        dkey = _file_digest_key(root)
                    except OSError:
                        continue
                    if dkey not in seen_digests:
                        seen_digests.add(dkey)
                        targets.append(root.resolve())
                elif root.is_dir():
                    for walk_root, _dirs, files in os.walk(root):
                        for fname in sorted(files):
                            if fname.lower() == "activitiescache.db":
                                f = Path(walk_root) / fname
                                try:
                                    if f.stat().st_size <= 0:
                                        continue
                                    dkey = _file_digest_key(f)
                                except OSError:
                                    continue
                                if dkey not in seen_digests:
                                    seen_digests.add(dkey)
                                    targets.append(f.resolve())

            if not targets and self.staging_dir.exists():
                staging_res = self.staging_dir.resolve()
                _SKIP_WXT_ROOTS = {
                    "activitiescache", "timeline", "sqlite", "vss",
                    "registry", "logs", "prefetch", "filesystem", "mft", "srum",
                    "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails",
                    "zoneidentifier", "recyclebin", "wbem", "wer", "wlan", "usb",
                    "browsers", "chat", "cloud", "mail", "media", "documents",
                    "notifications",
                }
                for walk_root, dirs, files in os.walk(staging_res):
                    root_p = Path(walk_root)
                    if root_p == staging_res:
                        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_WXT_ROOTS]
                    for fname in sorted(files):
                        if fname.lower() == "activitiescache.db":
                            f = root_p / fname
                            try:
                                if f.stat().st_size <= 0:
                                    continue
                                dkey = _file_digest_key(f)
                            except OSError:
                                continue
                            if dkey not in seen_digests:
                                seen_digests.add(dkey)
                                targets.append(f.resolve())

        if not targets:
            print("[EZToolRunner][WxTCmd] ActivitiesCache.db not found. Skipping.")
            with DuckDBManager.get_lock(self.case_id):
                log_processing_event(
                    case_id=self.case_id,
                    module_name="WxTCmd",
                    command_executed="WxTCmd (skipped)",
                    exit_code=0,
                    rows_ingested=0,
                    duration_ms=0,
                    status="SKIPPED",
                    error_message="ActivitiesCache.db not found",
                )
            return {}

        try:
            wxt_exe = self._find_ez_binary_with_fallback("WxTCmd.exe", "WFT_EZ_WXTCMD_EXE")
        except FileNotFoundError as fnf:
            self._log(f"WxTCmd.exe missing: {fnf}", "WARNING")
            with DuckDBManager.get_lock(self.case_id):
                log_processing_event(
                    case_id=self.case_id,
                    module_name="WxTCmd",
                    command_executed="find_ez_binary('WxTCmd.exe')",
                    exit_code=-1,
                    rows_ingested=0,
                    duration_ms=0,
                    status="SKIPPED",
                    error_message=str(fnf),
                )
            return {}
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "wxt")

        for idx, target in enumerate(targets):
            sub_out = (out_dir / f"db_{idx:03d}").resolve()
            sub_out.mkdir(parents=True, exist_ok=True)
            # Ensure SQLite schema compatibility for WxTCmd (e.g. missing IsRead column in older/partial schemas)
            try:
                import sqlite3
                with sqlite3.connect(str(target)) as s_conn:
                    tbls = [r[0] for r in s_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Activity';").fetchall()]
                    if tbls:
                        cols = [r[1] for r in s_conn.execute("PRAGMA table_info(Activity);").fetchall()]
                        if "IsRead" not in cols:
                            s_conn.execute("ALTER TABLE Activity ADD COLUMN IsRead INTEGER DEFAULT 0;")
                            s_conn.commit()
            except Exception:
                pass
            cmd = [
                str(wxt_exe),
                "-f",
                str(target),
                "--csv",
                str(sub_out),
            ]
            self._execute_subprocess("WxTCmd", cmd, timeout=300)

        return self.ingest_csv_directory("wxt", out_dir)

    def run_wxtcmd(self, wxt_file: Optional[Path] = None) -> Dict[str, int]:
        """Alias for run_wxt."""
        return self.run_wxt(wxt_file=wxt_file)

    # =========================================================================
    # TOOL 13: RBCmd.exe (Recycle Bin Parser)
    # =========================================================================
    def run_rbcmd(self, recycle_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute RBCmd.exe on staged RecycleBin directory ($I* files).
        Ingests rbcmd.csv -> raw_rbcmd.
        """
        target = Path(recycle_dir).resolve() if recycle_dir else (self.staging_dir / "RecycleBin").resolve()
        if not target.exists():
            target = self.staging_dir

        has_files = False
        if target.is_dir():
            has_files = any(f.is_file() and f.name.upper().startswith("$I") for f in target.rglob("*"))
            if not has_files and recycle_dir is not None:
                has_files = any(f.is_file() for f in target.rglob("*"))
            elif not has_files and target.name.lower() == "recyclebin":
                has_files = any(f.is_file() for f in target.rglob("*"))
        elif target.is_file():
            has_files = True

        if not has_files:
            print("[EZToolRunner][RBCmd] No Recycle Bin files found. Skipping.")
            return {"raw_rbcmd": 0}

        rbcmd_exe = self._find_ez_binary_with_fallback("RBCmd.exe", "WFT_EZ_RBCMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "rbcmd")

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

        self._execute_subprocess("RBCmd", cmd, timeout=300)
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
        Execute SQLECmd.exe across all staged SQLite3 databases (fixing empty staging/SQLite
        short-circuit by scanning SQLite, Browsers, Notifications, ActivitiesCache, Timeline,
        StickyNotes, Cloud, Chat, UserFiles, Enrichment, and VSS for 16-byte SQLite3 magic).
        """
        unique_dbs: List[Path] = []
        seen_digests: Set[Tuple[int, str]] = set()

        def _collect_from(root_path: Path, recursive: bool = True) -> None:
            if not root_path.exists():
                return
            if root_path.is_file():
                if _is_sqlite3_file(root_path):
                    try:
                        dkey = _file_digest_key(root_path)
                    except OSError:
                        return
                    if dkey not in seen_digests:
                        seen_digests.add(dkey)
                        unique_dbs.append(root_path.resolve())
                return
            iterator = root_path.rglob("*") if recursive else root_path.iterdir()
            for p in sorted(iterator, key=lambda x: str(x).lower()):
                if _is_sqlite3_file(p):
                    try:
                        dkey = _file_digest_key(p)
                    except OSError:
                        continue
                    if dkey not in seen_digests:
                        seen_digests.add(dkey)
                        unique_dbs.append(p.resolve())

        if sqlite_dir is not None and Path(sqlite_dir).exists():
            _collect_from(Path(sqlite_dir).resolve(), recursive=True)

        if not unique_dbs and sqlite_dir is None:
            for sub_name in (
                "SQLite",
                "Browsers",
                "Notifications",
                "ActivitiesCache",
                "Timeline",
                "StickyNotes",
                "Cloud",
                "Chat",
                "VSS",
            ):
                _collect_from(self.staging_dir / sub_name, recursive=True)
            if not unique_dbs:
                for sub_name in ("UserFiles", "Enrichment"):
                    _collect_from(self.staging_dir / sub_name, recursive=True)
            _collect_from(self.staging_dir, recursive=False)

        if not unique_dbs:
            print("[EZToolRunner][SQLECmd] No SQLite3 databases found in staging. Skipping.")
            return {}

        sqlecmd_exe = self._find_ez_binary_with_fallback("SQLECmd.exe", "WFT_EZ_SQLECMD_EXE")
        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "sqlecmd")

        maps_path = Path(maps_dir).resolve() if (maps_dir and Path(maps_dir).exists()) else None
        if maps_path is None:
            found_maps = find_ez_file("Maps", raise_if_missing=False)
            if found_maps and found_maps.is_dir() and any(found_maps.glob("*.smap")):
                maps_path = found_maps.resolve()
        if maps_path is None or not maps_path.exists():
            for cand_m in (
                sqlecmd_exe.parent / "Maps",
                sqlecmd_exe.parent.parent / "SQLECmd" / "Maps",
                BASE_DIR / "EZTools" / "SQLECmd" / "Maps",
                BASE_DIR / "tools" / "ez_tools" / "net" / "SQLECmd" / "Maps",
                BASE_DIR / "tools" / "ez_tools" / "SQLECmd" / "Maps",
            ):
                if cand_m.is_dir() and any(cand_m.glob("*.smap")):
                    maps_path = cand_m.resolve()
                    break

        safe_cid = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.case_id)[:24] or "case"
        staged_inputs = (Path(tempfile.gettempdir()) / f"wft_sqlecmd_in_{safe_cid}_{uuid.uuid4().hex[:8]}").resolve()
        staged_inputs.mkdir(parents=True, exist_ok=True)

        try:
            for idx, db_file in enumerate(unique_dbs):
                sidecars = [
                    db_file.parent / f"{db_file.name}{sidecar_sfx}"
                    for sidecar_sfx in ("-wal", "-shm", "-journal")
                    if (db_file.parent / f"{db_file.name}{sidecar_sfx}").is_file()
                ]
                flat_dest = staged_inputs / db_file.name
                if not flat_dest.exists() and not any(
                    (staged_inputs / sc.name).exists() for sc in sidecars
                ):
                    shutil.copy2(db_file, flat_dest)
                    for sc in sidecars:
                        shutil.copy2(sc, staged_inputs / sc.name)
                elif not sidecars:
                    shutil.copy2(db_file, staged_inputs / f"db_{idx:04d}_{db_file.name}")
                else:
                    db_slot = staged_inputs / f"db_{idx:04d}"
                    db_slot.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(db_file, db_slot / db_file.name)
                    for sc in sidecars:
                        shutil.copy2(sc, db_slot / sc.name)

            effective_maps: Optional[Path] = None
            cached_maps_dir: Optional[Path] = None
            if maps_path and maps_path.is_dir():
                with _SQLECMD_MAPS_LOCK:
                    smap_files = sorted(maps_path.rglob("*.smap"), key=lambda p: p.name.lower())
                    max_mt = max((p.stat().st_mtime_ns for p in smap_files), default=0) if smap_files else 0
                    cache_key = (str(maps_path).lower(), len(smap_files), max_mt)
                    cached_maps_dir = _SQLECMD_MAPS_CACHE.get(cache_key)
                    if cached_maps_dir is None or not cached_maps_dir.is_dir() or not any(cached_maps_dir.glob("*.smap")):
                        digest_hex = hashlib.sha1(f"{cache_key[0]}|{cache_key[1]}|{cache_key[2]}".encode("utf-8")).hexdigest()[:12]
                        cached_maps_dir = (Path(tempfile.gettempdir()) / f"wft_sqlecmd_maps_{digest_hex}").resolve()
                        shutil.rmtree(cached_maps_dir, ignore_errors=True)
                        cached_maps_dir.mkdir(parents=True, exist_ok=True)
                        seen_map_ids: Set[str] = set()
                        copied_maps = 0
                        for smap in smap_files:
                            try:
                                txt = smap.read_text(encoding="utf-8", errors="replace")
                            except OSError:
                                continue
                            if "IdentifyQuery:" not in txt:
                                continue
                            m_id = re.search(r"(?mi)^\s*Id:\s*(\S+)", txt)
                            if m_id:
                                map_uuid = m_id.group(1).strip().lower()
                                if map_uuid in seen_map_ids:
                                    continue
                                seen_map_ids.add(map_uuid)
                            shutil.copy2(smap, cached_maps_dir / smap.name)
                            copied_maps += 1
                        if copied_maps > 0:
                            _SQLECMD_MAPS_CACHE[cache_key] = cached_maps_dir
                        else:
                            shutil.rmtree(cached_maps_dir, ignore_errors=True)
                            cached_maps_dir = None
                effective_maps = cached_maps_dir if cached_maps_dir is not None else maps_path

            cmd = [
                str(sqlecmd_exe),
                "-d",
                str(staged_inputs),
                "--csv",
                str(out_dir),
                "--hunt",
            ]
            if effective_maps and effective_maps.exists():
                cmd.extend(["--maps", str(effective_maps)])

            proc = self._execute_subprocess("SQLECmd", cmd, timeout=600)
            if (
                cached_maps_dir is not None
                and effective_maps == cached_maps_dir
                and proc.stdout
                and "The following maps had errors" in proc.stdout
            ):
                after_hdr = proc.stdout.split("The following maps had errors", 1)[1]
                removed_any = False
                with _SQLECMD_MAPS_LOCK:
                    for raw_ln in after_hdr.splitlines()[1:]:
                        bad_name = raw_ln.strip()
                        if bad_name.lower().endswith(".smap"):
                            bad_file = cached_maps_dir / Path(bad_name).name
                            if bad_file.is_file():
                                bad_file.unlink(missing_ok=True)
                                removed_any = True
                if removed_any and any(cached_maps_dir.glob("*.smap")):
                    self._execute_subprocess("SQLECmd", cmd, timeout=600)
        finally:
            shutil.rmtree(staged_inputs, ignore_errors=True)

        return self.ingest_csv_directory("sqlecmd", out_dir)

    # =========================================================================
    # TOOL 15: RecentFileCacheParser.exe
    # =========================================================================
    def run_recentfilecache(self, rfc_file: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute RecentFileCacheParser.exe on RecentFileCache.bcf.
        """
        target = Path(rfc_file).resolve() if rfc_file else None
        if target is None or not target.exists():
            _SKIP_RFC_ROOTS = {
                "logs", "prefetch", "filesystem", "mft", "srum",
                "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails",
                "zoneidentifier", "recyclebin", "wbem", "wer", "wlan", "usb",
                "browsers", "chat", "cloud", "mail", "media", "documents",
                "notifications", "activitiescache", "sqlite", "userfiles",
            }
            for search_root in [
                self.staging_dir / "RecentFileCache.bcf",
                self.staging_dir / "Registry" / "RecentFileCache.bcf",
                self.staging_dir / "AppCompat" / "Programs" / "RecentFileCache.bcf",
                self.staging_dir / "Registry",
                self.staging_dir / "AppCompat",
                self.staging_dir,
            ]:
                if search_root.is_file() and search_root.name.lower() == "recentfilecache.bcf":
                    target = search_root.resolve()
                    break
                if search_root.is_dir():
                    sr_res = search_root.resolve()
                    for walk_root, dirs, files in os.walk(sr_res):
                        if search_root == self.staging_dir and Path(walk_root) == sr_res:
                            dirs[:] = [d for d in dirs if d.lower() not in _SKIP_RFC_ROOTS]
                        for fname in files:
                            if fname.lower() == "recentfilecache.bcf":
                                target = (Path(walk_root) / fname).resolve()
                                break
                        if target:
                            break
                if target:
                    break

        if target is None or not target.exists():
            print("[EZToolRunner][RecentFileCacheParser] RecentFileCache.bcf not found. Skipping.")
            return {}

        try:
            rfc_exe = self._find_ez_binary_with_fallback("RecentFileCacheParser.exe", "WFT_EZ_RECENTFILECACHE_EXE")
        except FileNotFoundError:
            return {}

        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "recentfilecache")

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

        self._execute_subprocess("RecentFileCacheParser", cmd, timeout=300)
        return self.ingest_csv_directory("recentfilecache", out_dir)

    # =========================================================================
    # TOOL 16: SumECmd.exe (User Access Logging)
    # =========================================================================
    def run_sum(self, sum_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Execute SumECmd.exe on staged User Access Logging (SUM) directory.
        """
        target = Path(sum_dir).resolve() if sum_dir else None
        if target is None or not target.exists():
            _SKIP_SUM_ROOTS = {
                "registry", "logs", "prefetch", "filesystem", "mft", "srum",
                "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails",
                "zoneidentifier", "recyclebin", "wbem", "wer", "wlan", "usb",
                "browsers", "chat", "cloud", "mail", "media", "documents",
                "notifications", "activitiescache", "sqlite", "userfiles",
            }
            for search_root in [
                self.staging_dir / "SUM",
                self.staging_dir / "LogFiles" / "SUM",
                self.staging_dir,
            ]:
                if search_root.is_dir():
                    if any(search_root.glob("*.mdb")):
                        target = search_root.resolve()
                        break
                    sr_res = search_root.resolve()
                    for walk_root, dirs, files in os.walk(sr_res):
                        root_p = Path(walk_root)
                        if search_root == self.staging_dir and root_p == sr_res:
                            dirs[:] = [d for d in dirs if d.lower() not in _SKIP_SUM_ROOTS]
                        if root_p.name.lower() == "sum" and any(fn.lower().endswith(".mdb") for fn in files):
                            target = root_p.resolve()
                            break
                    if target:
                        break

        if target is None or not target.exists():
            print("[EZToolRunner][SumECmd] SUM database directory not found. Skipping.")
            with DuckDBManager.get_lock(self.case_id):
                log_processing_event(
                    case_id=self.case_id,
                    module_name="SumECmd",
                    command_executed="SumECmd (skipped)",
                    exit_code=0,
                    rows_ingested=0,
                    duration_ms=0,
                    status="SKIPPED",
                    error_message="SUM database directory not found",
                )
            return {}

        try:
            sum_exe = self._find_ez_binary_with_fallback("SumECmd.exe", "WFT_EZ_SUMECMD_EXE")
        except FileNotFoundError as fnf:
            self._log(f"SumECmd.exe missing: {fnf}", "WARNING")
            with DuckDBManager.get_lock(self.case_id):
                log_processing_event(
                    case_id=self.case_id,
                    module_name="SumECmd",
                    command_executed="find_ez_binary('SumECmd.exe')",
                    exit_code=-1,
                    rows_ingested=0,
                    duration_ms=0,
                    status="SKIPPED",
                    error_message=str(fnf),
                )
            return {}

        out_dir = self._prepare_tool_out_dir(self.csv_out_dir / "sum")

        cmd = [
            str(sum_exe),
            "-d",
            str(target),
            "--csv",
            str(out_dir),
        ]

        self._execute_subprocess("SumECmd", cmd, timeout=300)
        return self.ingest_csv_directory("sum", out_dir)

    # =========================================================================
    # TOOL 17: Hindsight (Multi-Profile Chromium Forensics)
    # =========================================================================
    def _resolve_hindsight_runner(self) -> Tuple[Optional[str], Optional[Path]]:
        """
        Resolve Hindsight execution backend:
        Returns (mode, path) where mode is 'exe', 'py', 'library', or None.
        """
        hs_fn = getattr(wft_config, "find_hindsight_binary", None)
        hs_path: Optional[Path] = None
        monkeypatched_none = False
        raw_hs_env = (os.environ.get("WFT_HINDSIGHT_EXE") or "").strip().strip('"').strip("'")
        placeholders = getattr(wft_config, "_DEFAULT_HINDSIGHT_PLACEHOLDERS", set())
        explicit_hs_override = bool(raw_hs_env and raw_hs_env not in placeholders)

        if callable(hs_fn):
            hs_path = hs_fn()
            if hs_path is None and (getattr(hs_fn, "__module__", "") != "backend.config" or explicit_hs_override):
                monkeypatched_none = True
        else:
            cands: List[Path] = []
            if raw_hs_env:
                cands.append(Path(raw_hs_env))
            if not explicit_hs_override:
                cands.extend([
                    BASE_DIR / "tools" / "hindsight" / "hindsight.exe",
                    BASE_DIR / "tools" / "hindsight" / "hindsight.py",
                    BASE_DIR / "hindsight.exe",
                ])
            for c in cands:
                if c.is_file() and c.stat().st_size > 0:
                    hs_path = c.resolve()
                    break
            if hs_path is None and explicit_hs_override:
                monkeypatched_none = True

        if hs_path is not None and hs_path.is_file():
            resolved = hs_path.resolve()
            if resolved.suffix.lower() == ".py":
                return ("py", resolved)
            return ("exe", resolved)

        if not monkeypatched_none:
            try:
                from pyhindsight.analysis import AnalysisSession  # noqa: F401
                return ("library", None)
            except Exception:
                pass

        return (None, None)

    def _discover_chromium_profiles(
        self, browsers_dir: Optional[Path] = None
    ) -> List[Tuple[str, str, Path]]:
        """
        Discover all staged Chromium-family profile directories across active & VSS roots.
        Returns list of (browser_name, profile_label, profile_dir_path).
        """
        marker_names = {
            "history", "cookies", "web data", "login data", "bookmarks",
            "top sites", "preferences", "current session", "sessions", "local storage",
        }
        excluded_leaf_names = {
            "network", "sessions", "local storage", "indexeddb", "cache",
            "code cache", "gpucache", "extensions", "file system", "service worker",
            "blob_storage", "session storage", "sync data", "databases",
        }
        non_chromium_tokens = {"firefox", "mozilla", "safari", "ie", "iexplore", "webcache"}
        browser_map = {
            "chrome": "Chrome",
            "edge": "Edge",
            "msedge": "Edge",
            "brave": "Brave",
            "brave-browser": "Brave",
            "chromium": "Chromium",
            "opera": "Opera",
            "vivaldi": "Vivaldi",
        }

        search_roots: List[Tuple[Path, str]] = []
        default_browsers_dir = (self.staging_dir / "Browsers").resolve()
        if browsers_dir is not None:
            bd = Path(browsers_dir).resolve()
            if bd.exists():
                search_roots.append((bd, ""))
            if bd == default_browsers_dir:
                vss_root = (self.staging_dir / "VSS").resolve()
                if vss_root.is_dir():
                    for vss_sub in sorted(vss_root.iterdir(), key=lambda p: p.name.lower()):
                        if vss_sub.is_dir():
                            vss_bd = (vss_sub / "Browsers").resolve()
                            search_roots.append((vss_bd if vss_bd.is_dir() else vss_sub.resolve(), vss_sub.name))
        else:
            if default_browsers_dir.is_dir():
                search_roots.append((default_browsers_dir, ""))
            vss_root = (self.staging_dir / "VSS").resolve()
            if vss_root.is_dir():
                for vss_sub in sorted(vss_root.iterdir(), key=lambda p: p.name.lower()):
                    if vss_sub.is_dir():
                        vss_bd = (vss_sub / "Browsers").resolve()
                        search_roots.append((vss_bd if vss_bd.is_dir() else vss_sub.resolve(), vss_sub.name))
            if not search_roots and self.staging_dir.is_dir():
                search_roots.append((self.staging_dir.resolve(), ""))

        discovered: List[Tuple[str, str, Path]] = []
        seen_dirs: Set[str] = set()

        def _is_profile_dir(d: Path) -> bool:
            if not d.is_dir() or d.name.lower() in excluded_leaf_names:
                return False
            try:
                children_low = {c.name.lower() for c in d.iterdir()}
            except OSError:
                return False
            if children_low & marker_names:
                return True
            if (d / "Network" / "Cookies").is_file():
                return True
            return False

        for root_dir, vss_tag in search_roots:
            candidate_dirs = [root_dir] + [p for p in root_dir.rglob("*") if p.is_dir()]
            for d in sorted(candidate_dirs, key=lambda p: (len(p.parts), str(p).lower())):
                d_resolved = d.resolve()
                d_key = str(d_resolved).lower()
                if d_key in seen_dirs:
                    continue
                rel_parts = d_resolved.relative_to(root_dir).parts if d_resolved != root_dir else ()
                if any(pt.lower() in non_chromium_tokens for pt in rel_parts):
                    continue
                if any(pt.lower() in excluded_leaf_names for pt in rel_parts):
                    continue
                if not _is_profile_dir(d_resolved):
                    continue

                seen_dirs.add(d_key)

                # Infer browser_name and disambiguated profile_label
                browser_name = "Chrome"
                label_parts: List[str] = []
                if vss_tag:
                    label_parts.append(vss_tag)

                matched_browser_idx: Optional[int] = None
                for idx_pt, pt in enumerate(rel_parts):
                    pt_low = pt.lower()
                    for token, canonical_b in browser_map.items():
                        if token in pt_low:
                            browser_name = canonical_b
                            matched_browser_idx = idx_pt
                            break
                    if matched_browser_idx is not None:
                        break

                if matched_browser_idx is not None:
                    trailing = [
                        pt for pt in rel_parts[matched_browser_idx + 1 :]
                        if pt.lower() not in {"user data", "userdata", "profiles"}
                    ]
                    label_parts.extend(trailing if trailing else [d_resolved.name])
                elif rel_parts:
                    label_parts.extend(rel_parts)
                else:
                    for parent_pt in reversed(d_resolved.parts[-3:]):
                        for token, canonical_b in browser_map.items():
                            if token in parent_pt.lower():
                                browser_name = canonical_b
                                break
                    label_parts.append(d_resolved.name)

                profile_label = "/".join(label_parts) if label_parts else "Default"
                discovered.append((browser_name, profile_label, d_resolved))

        return discovered

    @staticmethod
    def _ensure_hindsight_table(cursor: Any) -> None:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_hindsight (
                _row_id BIGINT,
                timestamp_utc TIMESTAMP,
                browser VARCHAR,
                profile VARCHAR,
                record_type VARCHAR,
                url VARCHAR,
                title VARCHAR,
                value VARCHAR,
                interpretation VARCHAR,
                source_path VARCHAR,
                extra_json VARCHAR
            );
            """
        )
        cursor.execute("ALTER TABLE raw_hindsight ADD COLUMN IF NOT EXISTS _row_id BIGINT;")

    @staticmethod
    def _parse_hindsight_timestamp(raw_dt: str, ts_desc: str) -> Optional[datetime]:
        """Convert valid ISO-8601 strings to naive UTC datetime; reject epoch/timeless sentinels to None."""
        dt_str = (raw_dt or "").strip()
        desc_low = (ts_desc or "").strip().lower()
        if not dt_str or desc_low == "not a time":
            return None
        if dt_str.startswith(("1970-01-01T00:00:00", "1970-01-01 00:00:00", "1601-01-01", "0001-01-01")):
            return None
        norm = dt_str[:-1] + "+00:00" if dt_str.endswith("Z") else dt_str
        try:
            dt_obj = datetime.fromisoformat(norm)
            if dt_obj.tzinfo is not None:
                dt_obj = dt_obj.astimezone(timezone.utc).replace(tzinfo=None)
            if dt_obj.year <= 1970 and dt_obj.month == 1 and dt_obj.day == 1 and dt_obj.hour == 0 and dt_obj.minute == 0 and dt_obj.second == 0:
                return None
            return dt_obj
        except ValueError:
            return None

    @staticmethod
    def _profile_has_broken_chromium_cache(prof_dir: Path) -> bool:
        """
        Return True if prof_dir contains a Chromium Cache / Cache_Data directory whose
        blockfile index exists without all required data_0..data_3 files (which triggers
        FileNotFoundError inside ccl_chromium_cache).
        """
        for cache_rel in (
            Path("Cache") / "Cache_Data",
            Path("Cache"),
            Path("Cache_Data"),
        ):
            cdir = prof_dir / cache_rel
            if not cdir.is_dir():
                continue
            if (cdir / "index").is_file():
                for d_idx in range(4):
                    if not (cdir / f"data_{d_idx}").is_file():
                        return True
        return False

    @staticmethod
    def _build_nocache_profile_dir(prof_dir: Path, nocache_prof: Path) -> Path:
        nocache_prof.mkdir(parents=True, exist_ok=True)
        skip_cache_names = {
            "cache",
            "cache_data",
            "code cache",
            "gpucache",
            "media cache",
            "application cache",
            "dawngraphitecache",
            "dawnwebgpucache",
            "grshadercache",
            "shadercache",
        }
        for child in prof_dir.iterdir():
            if child.name.lower() in skip_cache_names:
                continue
            dst_child = nocache_prof / child.name
            try:
                if child.is_dir():
                    for root, dirs, files in os.walk(child):
                        dirs[:] = [d for d in dirs if d.lower() not in skip_cache_names]
                        rel_r = Path(root).relative_to(child)
                        target_r = dst_child / rel_r
                        target_r.mkdir(parents=True, exist_ok=True)
                        for fn in files:
                            src_f = Path(root) / fn
                            dst_f = target_r / fn
                            try:
                                os.link(src_f, dst_f)
                            except OSError:
                                shutil.copy2(src_f, dst_f)
                elif child.is_file():
                    try:
                        os.link(child, dst_child)
                    except OSError:
                        shutil.copy2(child, dst_child)
            except OSError:
                continue
        return nocache_prof

    def run_hindsight(
        self,
        browsers_dir: Optional[Path] = None,
        max_workers: int = 8,
    ) -> Dict[str, int]:
        """
        Execute Hindsight across all staged Chromium-family profiles in parallel,
        strictly isolating cwd=self.hindsight_out_dir and --temp_dir per worker so
        hindsight.log and hindsight-temp NEVER pollute the project root.
        Returns {"raw_hindsight": rows_ingested} matching EZToolRunner.run_* contract.
        """
        t0 = time.time()
        self.hindsight_out_dir.mkdir(parents=True, exist_ok=True)
        mode, hs_path = self._resolve_hindsight_runner()

        if mode is None:
            warn_msg = "Hindsight binary/library unavailable; skipping Chromium Hindsight analysis."
            self._log(warn_msg, "WARNING")
            duration_ms = int((time.time() - t0) * 1000)
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cursor = conn.cursor()
                self._ensure_hindsight_table(cursor)
                cursor.execute("DELETE FROM raw_hindsight;")
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'web_hindsight', 'WEB RELATED', 'Chromium Forensics (Hindsight)', 'raw_hindsight', 'Hindsight', 0, CURRENT_TIMESTAMP
                    );
                    """
                )
                log_processing_event(
                    case_id=self.case_id,
                    module_name="Hindsight",
                    command_executed="find_hindsight_binary()",
                    exit_code=-1,
                    rows_ingested=0,
                    duration_ms=duration_ms,
                    status="WARNING",
                    error_message=warn_msg,
                )
            return {"raw_hindsight": 0}

        profiles = self._discover_chromium_profiles(browsers_dir=browsers_dir)
        if not profiles:
            duration_ms = int((time.time() - t0) * 1000)
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cursor = conn.cursor()
                self._ensure_hindsight_table(cursor)
                cursor.execute("DELETE FROM raw_hindsight;")
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'web_hindsight', 'WEB RELATED', 'Chromium Forensics (Hindsight)', 'raw_hindsight', 'Hindsight', 0, CURRENT_TIMESTAMP
                    );
                    """
                )
                log_processing_event(
                    case_id=self.case_id,
                    module_name="Hindsight",
                    command_executed=str(hs_path or "pyhindsight"),
                    exit_code=0,
                    rows_ingested=0,
                    duration_ms=duration_ms,
                    status="SKIPPED",
                    error_message="No Chromium profiles found",
                )
            return {"raw_hindsight": 0}

        effective_workers = max(1, min(16, int(max_workers or 8), len(profiles)))

        def _process_profile(task: Tuple[int, str, str, Path]) -> List[Tuple[Any, ...]]:
            idx, browser_name, profile_label, prof_dir = task
            out_base = (self.hindsight_out_dir / f"hs_{idx:03d}").resolve()
            jsonl_path = Path(f"{out_base}.jsonl")
            jsonl_path.unlink(missing_ok=True)
            worker_tmp = (self.hindsight_out_dir / f"_tmp_{idx:03d}_{uuid.uuid4().hex[:6]}").resolve()
            worker_tmp.mkdir(parents=True, exist_ok=True)
            log_path = (self.hindsight_out_dir / f"hs_{idx:03d}.log").resolve()

            # Hindsight's `-b Brave` invokes the legacy 2016-2018 Muon Brave parser (`session-store-1`).
            # Modern Chromium-based Brave profiles use standard Chromium SQLite/JSON format (`Chrome`),
            # while we still preserve `browser_name = "Brave"` in `raw_hindsight.browser`.
            is_legacy_muon_brave = (
                browser_name.lower() == "brave"
                and (prof_dir / "session-store-1").is_file()
                and not (prof_dir / "History").is_file()
            )

            try:
                sqlite_fallback_path = Path(f"{out_base}.sqlite")
                sqlite_fallback_path.unlink(missing_ok=True)
                use_nocache_upfront = self._profile_has_broken_chromium_cache(prof_dir)
                active_prof_dir = (
                    self._build_nocache_profile_dir(prof_dir, worker_tmp / "profile_nocache")
                    if use_nocache_upfront
                    else prof_dir
                )
                if mode in ("exe", "py") and hs_path is not None:
                    base_cmd = [sys.executable, str(hs_path)] if mode == "py" else [str(hs_path)]
                    extra_env: Optional[Dict[str, str]] = None
                    if mode == "py":
                        existing_pp = os.environ.get("PYTHONPATH", "")
                        extra_env = {
                            "PYTHONPATH": str(hs_path.parent) + (os.pathsep + existing_pp if existing_pp else "")
                        }
                    cmd = base_cmd + [
                        "-i",
                        str(active_prof_dir),
                        "-o",
                        str(out_base),
                        "-f",
                        "jsonl",
                        "-l",
                        str(log_path),
                        "--temp_dir",
                        str(worker_tmp),
                    ]
                    if is_legacy_muon_brave:
                        cmd.extend(["-b", "Brave"])

                    # CRITICAL M1 RUNTIME CONTRACT: ALWAYS pass cwd=self.hindsight_out_dir
                    proc_hs = self._execute_subprocess(
                        f"Hindsight:{profile_label}",
                        cmd,
                        timeout=300,
                        cwd=self.hindsight_out_dir,
                        extra_env=extra_env,
                        log_to_db=False,
                    )
                    hs_stderr = proc_hs.stderr or ""
                    has_jsonl = jsonl_path.is_file() and jsonl_path.stat().st_size > 0
                    if (
                        not use_nocache_upfront
                        and (proc_hs.returncode != 0 or not has_jsonl)
                        and any(
                            tok in hs_stderr
                            for tok in ("ccl_chromium_cache", "get_cache", "OverflowError")
                        )
                    ):
                        active_prof_dir = self._build_nocache_profile_dir(
                            prof_dir, worker_tmp / "profile_nocache"
                        )
                        cmd_nocache = base_cmd + [
                            "-i",
                            str(active_prof_dir),
                            "-o",
                            str(out_base),
                            "-f",
                            "jsonl",
                            "-l",
                            str(log_path),
                            "--temp_dir",
                            str(worker_tmp),
                        ]
                        if is_legacy_muon_brave:
                            cmd_nocache.extend(["-b", "Brave"])
                        proc_hs = self._execute_subprocess(
                            f"Hindsight:{profile_label}",
                            cmd_nocache,
                            timeout=300,
                            cwd=self.hindsight_out_dir,
                            extra_env=extra_env,
                            log_to_db=False,
                        )
                        hs_stderr = proc_hs.stderr or ""
                        has_jsonl = jsonl_path.is_file() and jsonl_path.stat().st_size > 0
                        cmd = cmd_nocache

                    # If pyhindsight write_jsonl crashed with KeyError: 'value' in HindsightEncoder.default,
                    # retry with -f sqlite so the timeline records are not lost.
                    if (proc_hs.returncode != 0 or not has_jsonl) and (
                        "KeyError: 'value'" in hs_stderr or "generate_jsonl" in hs_stderr or "write_jsonl" in hs_stderr
                    ):
                        cmd_sqlite = base_cmd + [
                            "-i",
                            str(active_prof_dir),
                            "-o",
                            str(out_base),
                            "-f",
                            "sqlite",
                            "-l",
                            str(log_path),
                            "--temp_dir",
                            str(worker_tmp),
                        ]
                        if is_legacy_muon_brave:
                            cmd_sqlite.extend(["-b", "Brave"])
                        proc_sq = self._execute_subprocess(
                            f"Hindsight:{profile_label}",
                            cmd_sqlite,
                            timeout=300,
                            cwd=self.hindsight_out_dir,
                            extra_env=extra_env,
                            log_to_db=False,
                        )
                        if proc_sq.returncode == 0 or (
                            sqlite_fallback_path.is_file() and sqlite_fallback_path.stat().st_size > 0
                        ):
                            proc_hs = proc_sq
                            hs_stderr = proc_sq.stderr or ""
                            cmd = cmd_sqlite

                    cmd_str = " ".join([f'"{c}"' if " " in c else c for c in cmd])
                    err_summary: Optional[str] = None
                    if hs_stderr.strip():
                        if "Traceback (most recent call last)" in hs_stderr:
                            lines_ne = [
                                ln.strip()
                                for ln in hs_stderr.splitlines()
                                if ln.strip() and "Traceback (most recent call last)" not in ln
                            ]
                            err_summary = (
                                f"External tool exited with code {proc_hs.returncode}: "
                                f"{lines_ne[-1] if lines_ne else 'Hindsight error'}"
                            )[:500]
                        else:
                            err_summary = hs_stderr.strip()[:1000]
                    with DuckDBManager.get_lock(self.case_id):
                        log_processing_event(
                            case_id=self.case_id,
                            module_name=f"Hindsight:{profile_label}",
                            command_executed=cmd_str,
                            exit_code=proc_hs.returncode,
                            rows_ingested=0,
                            duration_ms=0,
                            status="SUCCESS" if proc_hs.returncode == 0 else "WARNING",
                            error_message=err_summary,
                        )
                else:
                    from pyhindsight.analysis import AnalysisSession

                    session = AnalysisSession()
                    session.input_path = str(active_prof_dir)
                    session.output_name = str(out_base)
                    session.selected_output_format = "jsonl"
                    session.browser_type = "Brave" if is_legacy_muon_brave else "Chrome"
                    session.temp_dir = str(worker_tmp)
                    session.log_path = str(log_path)
                    session.run()
                    if hasattr(session, "generate_jsonl"):
                        try:
                            session.generate_jsonl(str(jsonl_path))
                        except KeyError:
                            if hasattr(session, "generate_sqlite"):
                                session.generate_sqlite(str(sqlite_fallback_path))
            finally:
                shutil.rmtree(worker_tmp, ignore_errors=True)

            parsed_rows: List[Tuple[Any, ...]] = []
            # When -f jsonl crashed and the -f sqlite fallback produced a populated database, prefer the
            # complete SQLite timeline over a partial/truncated JSONL file; fall back to JSONL otherwise.
            if sqlite_fallback_path.is_file() and sqlite_fallback_path.stat().st_size > 0:
                try:
                    import sqlite3 as _hs_sqlite3
                    with _hs_sqlite3.connect(str(sqlite_fallback_path)) as sq_conn:
                        sq_conn.row_factory = _hs_sqlite3.Row
                        sq_cur = sq_conn.cursor()
                        tbls = {
                            str(r[0])
                            for r in sq_cur.execute(
                                "SELECT name FROM sqlite_master WHERE type='table';"
                            ).fetchall()
                        }
                        if "timeline" in tbls:
                            for sq_row in sq_cur.execute("SELECT * FROM timeline;").fetchall():
                                obj = {k: sq_row[k] for k in sq_row.keys()}
                                raw_dt = str(obj.get("timestamp") or obj.get("datetime") or "")
                                ts_desc = str(obj.get("type") or obj.get("timestamp_desc") or "")
                                ts_val = self._parse_hindsight_timestamp(raw_dt, ts_desc)
                                rec_type = str(obj.get("type") or obj.get("record_type") or "chrome:artifact")
                                url_val = str(obj.get("url") or "") or None
                                title_val = str(obj.get("title") or obj.get("name") or "") or None
                                val_raw = obj.get("value") if obj.get("value") is not None else obj.get("data")
                                val_str = str(val_raw) if val_raw is not None else None
                                interp_raw = obj.get("interpretation")
                                interp_str = str(interp_raw) if interp_raw not in (None, "") else None
                                src_path = str(obj.get("source") or obj.get("profile") or prof_dir)
                                extra_json = json.dumps(obj, ensure_ascii=False, default=str)
                                parsed_rows.append(
                                    (
                                        ts_val,
                                        browser_name,
                                        profile_label,
                                        rec_type,
                                        url_val,
                                        title_val,
                                        val_str,
                                        interp_str,
                                        src_path,
                                        extra_json,
                                    )
                                )
                except Exception:
                    parsed_rows = []
            if not parsed_rows and jsonl_path.is_file() and jsonl_path.stat().st_size > 0:
                with open(jsonl_path, "r", encoding="utf-8", errors="replace") as jf:
                    for raw_line in jf:
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(obj, dict):
                            continue

                        raw_dt = str(obj.get("datetime") or "")
                        ts_desc = str(obj.get("timestamp_desc") or "")
                        ts_val = self._parse_hindsight_timestamp(raw_dt, ts_desc)

                        rec_type = str(
                            obj.get("data_type") or obj.get("source_long") or ts_desc or "chrome:artifact"
                        )
                        url_val = str(obj.get("url") or obj.get("original_url") or obj.get("origin") or "") or None
                        title_val = (
                            str(
                                obj.get("title")
                                or obj.get("name")
                                or obj.get("cookie_name")
                                or obj.get("field_name")
                                or obj.get("key")
                                or ""
                            )
                            or None
                        )
                        val_raw = (
                            obj.get("value")
                            if obj.get("value") is not None
                            else (
                                obj.get("data")
                                if obj.get("data") is not None
                                else (obj.get("target_path") or obj.get("message"))
                            )
                        )
                        val_str = str(val_raw) if val_raw is not None else None
                        interp_raw = obj.get("interpretation")
                        interp_str = str(interp_raw) if interp_raw not in (None, "") else None
                        src_path = str(obj.get("source_path") or obj.get("profile") or prof_dir)
                        extra_json = json.dumps(obj, ensure_ascii=False)

                        parsed_rows.append(
                            (
                                ts_val,
                                browser_name,
                                profile_label,
                                rec_type,
                                url_val,
                                title_val,
                                val_str,
                                interp_str,
                                src_path,
                                extra_json,
                            )
                        )
            return parsed_rows

        indexed_tasks = [(i, b, lbl, pdir) for i, (b, lbl, pdir) in enumerate(profiles)]
        all_rows: List[Tuple[Any, ...]] = []
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            for prof_rows in pool.map(_process_profile, indexed_tasks):
                all_rows.extend(prof_rows)

        numbered_rows = [(idx + 1, *row) for idx, row in enumerate(all_rows)]
        duration_ms = int((time.time() - t0) * 1000)

        for _hs_attempt in range(4):
            try:
                with DuckDBManager.get_lock(self.case_id):
                    conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                    cursor = conn.cursor()
                    self._ensure_hindsight_table(cursor)
                    cursor.execute("DELETE FROM raw_hindsight;")

                    if numbered_rows:
                        cursor.executemany(
                            """
                            INSERT INTO raw_hindsight (
                                _row_id, timestamp_utc, browser, profile, record_type,
                                url, title, value, interpretation, source_path, extra_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                            """,
                            numbered_rows,
                        )

                    cursor.execute(
                        "DELETE FROM artifact_registry WHERE table_name = 'raw_hindsight' AND artifact_id != 'web_hindsight';"
                    )
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                        ) VALUES (
                            'web_hindsight', 'WEB RELATED', 'Chromium Forensics (Hindsight)',
                            'raw_hindsight', 'Hindsight', ?, CURRENT_TIMESTAMP
                        );
                        """,
                        [len(numbered_rows)],
                    )

                    log_processing_event(
                        case_id=self.case_id,
                        module_name="Hindsight",
                        command_executed=f"{hs_path or 'pyhindsight'} ({len(profiles)} profile(s), workers={effective_workers})",
                        exit_code=0,
                        rows_ingested=len(numbered_rows),
                        duration_ms=duration_ms,
                        status="SUCCESS",
                        error_message=None,
                    )
                break
            except Exception as hs_db_exc:
                err_low = str(hs_db_exc).lower()
                if _hs_attempt < 3 and any(
                    tok in err_low
                    for tok in ("transactioncontext", "failed to commit", "device is not ready", "could not flush")
                ):
                    time.sleep(0.5 * (_hs_attempt + 1))
                    continue
                raise

        return {"raw_hindsight": len(numbered_rows)}

    # =========================================================================
    # MASTER RUNNER: Parallel Execution of Selected EZ Tools + Hindsight
    # =========================================================================
    def _should_run_tool(self, tool_key: str, selected_set: Optional[Set[str]]) -> bool:
        if selected_set is None:
            return True
        aliases = self.EZ_TOOL_ARTIFACT_ALIASES.get(tool_key, {tool_key})
        return bool(selected_set & aliases)

    def run_all(
        self,
        max_workers: int = 25,
        enable_hindsight: bool = True,
        selected_artifacts: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """
        Master orchestrator: executes rla.exe transaction-log replay first (when registry tools
        are selected and clean_hives/ is not already warm), then fans out all selected Eric
        Zimmerman tools (+ Hindsight when enabled) across ThreadPoolExecutor workers while
        serializing all DuckDB writes via DuckDBManager.get_lock(self.case_id).
        """
        effective_workers = max(1, min(32, self.max_workers if max_workers is None else int(max_workers)))
        selected_set: Optional[Set[str]] = (
            {str(a).strip().lower() for a in selected_artifacts if str(a).strip()}
            if selected_artifacts is not None
            else None
        )

        print(
            f"\n{'='*70}\n[EZToolRunner] Starting parallel run_all for case: '{self.case_id}' "
            f"(max_workers={effective_workers}, enable_hindsight={enable_hindsight})\n{'='*70}"
        )
        all_results: Dict[str, int] = {}

        # Step 0: Replay dirty transaction logs FIRST when any registry hive consumer is selected
        needs_registry_hives = any(
            self._should_run_tool(t, selected_set)
            for t in ("recmd", "amcache", "shimcache", "sbecmd", "srum", "sum")
        )
        if needs_registry_hives:
            with _acquire_clean_hives_lock(self.case_id, self.case_dir):
                has_registry = bool(self._collect_staged_hive_roots())
                if has_registry and not self._clean_hives_are_warm():
                    try:
                        self._stage_clean_hives_with_rla()
                    except Exception as rla_err:
                        self._log(f"RLA skipped or unavailable: {rla_err}", "WARNING")

        def _run_usn_task() -> Dict[str, int]:
            mft_cand = self.staging_dir / "$MFT"
            if not mft_cand.exists():
                mft_cand = self.staging_dir / "FileSystem" / "$MFT"
            if not mft_cand.exists():
                mft_cand = self.staging_dir / "MFT"
            return self.run_mftecmd_usnjrnl(mft_file=mft_cand if mft_cand.exists() else None)

        def _run_hindsight_task() -> Dict[str, int]:
            hs_res = self.run_hindsight(max_workers=min(8, effective_workers))
            rows = int(hs_res.get("raw_hindsight", 0) or 0) if isinstance(hs_res, dict) else int(hs_res or 0)
            return {"raw_hindsight": rows}

        tool_specs: List[Tuple[str, Callable[[], Dict[str, int]]]] = [
            ("mftecmd_mft", self.run_mftecmd_mft),
            ("mftecmd_usn", _run_usn_task),
            ("pecmd", self.run_pecmd),
            ("amcache", self.run_amcache),
            ("shimcache", self.run_appcompatcache),
            ("sbecmd", self.run_sbecmd),
            ("srum", self.run_srum),
            ("evtx", self.run_evtx),
            ("recmd", self.run_recmd),
            ("lecmd", self.run_lecmd),
            ("jlecmd", self.run_jlecmd),
            ("rbcmd", self.run_rbcmd),
            ("wxt", self.run_wxt),
            ("sqlecmd", self.run_sqlecmd),
            ("recentfilecache", self.run_recentfilecache),
            ("sum", self.run_sum),
        ]

        tasks: List[Tuple[str, Callable[[], Dict[str, int]]]] = [
            (key, fn) for key, fn in tool_specs if self._should_run_tool(key, selected_set)
        ]
        if enable_hindsight and self._should_run_tool("hindsight", selected_set):
            tasks.append(("hindsight", _run_hindsight_task))

        if tasks:
            pool_size = max(1, min(effective_workers, len(tasks)))
            results_lock = threading.Lock()
            with ThreadPoolExecutor(max_workers=pool_size) as pool:
                future_to_name = {pool.submit(fn): name for name, fn in tasks}
                for fut in as_completed(future_to_name):
                    t_name = future_to_name[fut]
                    try:
                        res = fut.result()
                        if res:
                            with results_lock:
                                all_results.update(res)
                    except FileNotFoundError as fnf:
                        self._log(f"{t_name} binary missing: {fnf}", "WARNING")
                        with DuckDBManager.get_lock(self.case_id):
                            log_processing_event(
                                case_id=self.case_id,
                                module_name=t_name,
                                command_executed=f"{t_name} (missing binary)",
                                exit_code=-1,
                                rows_ingested=0,
                                duration_ms=0,
                                status="SKIPPED",
                                error_message=str(fnf),
                            )
                    except Exception as ex:
                        self._log(f"{t_name} warning: {ex}", "WARNING")

        print(f"\n[EZToolRunner] run_all complete. Total tables populated: {len(all_results)}")
        for tbl, count in all_results.items():
            print(f"  -> {tbl}: {count} rows")

        return all_results
