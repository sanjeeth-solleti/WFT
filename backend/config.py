"""
Windows Forensic Toolkit (WFT) - Configuration & Path Resolver
Loads environment variables from .env and custom settings from tool_paths.json.
Provides centralized path discovery and health status verification for all forensic engines.
"""
import ctypes
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

_REPO_ROOT_DIR: Path = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent
)
if getattr(sys, "frozen", False):
    BUNDLE_DIR: Path = Path(sys._MEIPASS)
else:
    BUNDLE_DIR: Path = _REPO_ROOT_DIR

_base_dir_override = os.environ.get("WFT_BASE_DIR", "").strip()
BASE_DIR: Path = Path(_base_dir_override).resolve() if _base_dir_override else _REPO_ROOT_DIR


def get_appdata_dir() -> Path:
    """Resolves writable per-user WFT AppData directory (honoring WFT_APPDATA_DIR override)."""
    override = os.environ.get("WFT_APPDATA_DIR", "").strip()
    if override:
        p = Path(override)
        app_dir = p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
    else:
        local_app = os.environ.get("LOCALAPPDATA", "").strip()
        app_dir = (Path(local_app) / "WFT").resolve() if local_app else (Path.home() / ".wft").resolve()
    try:
        app_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return app_dir


APP_DATA_DIR: Path = get_appdata_dir()


def _is_dir_writable(dir_path: Path) -> bool:
    try:
        if not dir_path.is_dir():
            return False
        probe = dir_path / f".wft_cfg_probe_{os.getpid()}_{time.time_ns()}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def get_runtime_log_dir() -> Path:
    """Standardized enterprise log directory honoring WFT_BASE_DIR write probe and WFT_APPDATA_DIR isolation."""
    has_base_override = bool(os.environ.get("WFT_BASE_DIR", "").strip())
    has_appdata_override = bool(os.environ.get("WFT_APPDATA_DIR", "").strip())

    if has_appdata_override and not has_base_override:
        appdata_logs = get_appdata_dir() / "logs"
        try:
            appdata_logs.mkdir(parents=True, exist_ok=True)
            if _is_dir_writable(appdata_logs):
                return appdata_logs
        except OSError:
            pass

    logs_dir = BASE_DIR / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        if _is_dir_writable(logs_dir):
            return logs_dir
    except OSError:
        pass

    fallback = get_appdata_dir() / "logs"
    try:
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback
    except OSError:
        return logs_dir


LOGS_DIR: Path = get_runtime_log_dir()
LOG_FILE: Path = LOGS_DIR / "wft_runtime.log"


def get_env_file() -> Path:
    """Resolves active .env file (honoring WFT_ENV_FILE, then BASE_DIR/.env, then AppData/.env fallback)."""
    env_override = os.environ.get("WFT_ENV_FILE", "").strip()
    if env_override:
        p = Path(env_override)
        return p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
    base_env = (BASE_DIR / ".env").resolve()
    if base_env.is_file():
        return base_env
    appdata_env = (get_appdata_dir() / ".env").resolve()
    if appdata_env.is_file():
        return appdata_env
    return base_env


def _parse_env_file(env_file: Path) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not env_file.is_file():
        return parsed
    try:
        with open(env_file, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                s_line = line.strip()
                if s_line and not s_line.startswith("#") and "=" in s_line:
                    k, v = s_line.split("=", 1)
                    k = k.strip()
                    if k.lower().startswith("export "):
                        k = k[7:].strip()
                    v = v.strip().strip('"').strip("'")
                    if k:
                        parsed[k] = v
    except Exception as ex:
        print(f"[config] Warning reading {env_file}: {ex}")
    return parsed


def load_root_env(override: bool = False, env_file: Optional[Union[str, Path]] = None) -> Dict[str, str]:
    """Loads environment variables from .env. Uses override=False on initial import so explicit process env wins."""
    target_env = Path(env_file).resolve() if env_file else get_env_file()
    loaded = _parse_env_file(target_env)
    if target_env.is_file():
        try:
            from dotenv import load_dotenv
            load_dotenv(target_env, override=override)
        except Exception:
            pass
        for k, v in loaded.items():
            if override or k not in os.environ:
                os.environ[k] = v
    return loaded


load_root_env(override=False)

TOOL_PATHS_FILE: Path = (APP_DATA_DIR / "tool_paths.json").resolve()
LEGACY_TOOL_PATHS_FILE: Path = (BASE_DIR / "cases" / "tool_paths.json").resolve()
_CUSTOM_TOOL_PATHS: Dict[str, str] = {}


def get_tool_paths_file() -> Path:
    """Resolves active tool_paths.json path (honoring WFT_TOOL_PATHS_FILE and WFT_APPDATA_DIR)."""
    env_override = os.environ.get("WFT_TOOL_PATHS_FILE", "").strip()
    if env_override:
        p = Path(env_override)
        return p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
    if os.environ.get("WFT_APPDATA_DIR", "").strip():
        return (get_appdata_dir() / "tool_paths.json").resolve()
    return TOOL_PATHS_FILE


def _resolve_candidate_path(raw_val: str) -> Path:
    p = Path(str(raw_val).strip().strip('"').strip("'"))
    return p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()


EZ_BINARIES_SPEC: List[Dict[str, str]] = [
    {"key": "ez_rla", "env_var": "WFT_EZ_RLA_EXE", "binary": "rla.exe", "name": "rla.exe (Registry Transaction Replay)", "description": "Replays uncommitted dirty registry transaction logs (.LOG1/.LOG2)"},
    {"key": "ez_pecmd", "env_var": "WFT_EZ_PECMD_EXE", "binary": "PECmd.exe", "name": "PECmd.exe (Prefetch Parser)", "description": "Parses Windows Prefetch files (.pf) for program execution artifacts"},
    {"key": "ez_mftecmd", "env_var": "WFT_EZ_MFTECMD_EXE", "binary": "MFTECmd.exe", "name": "MFTECmd.exe ($MFT & $J)", "description": "Parses NTFS $MFT, $J (USN Journal), and $LogFile file system metadata"},
    {"key": "ez_evtxecmd", "env_var": "WFT_EZ_EVTXECMD_EXE", "binary": "EvtxECmd.exe", "name": "EvtxECmd.exe (Event Logs)", "description": "Parses Windows EVTX event logs with event map definitions"},
    {"key": "ez_recmd", "env_var": "WFT_EZ_RECMD_EXE", "binary": "RECmd.exe", "name": "RECmd.exe (Registry Batch)", "description": "Batch extracts key/value registry artifacts using RECmd batch scripts"},
    {"key": "ez_lecmd", "env_var": "WFT_EZ_LECMD_EXE", "binary": "LECmd.exe", "name": "LECmd.exe (LNK Shortcuts)", "description": "Parses Windows Shell LNK shortcut files for target paths and serials"},
    {"key": "ez_jlecmd", "env_var": "WFT_EZ_JLECMD_EXE", "binary": "JLECmd.exe", "name": "JLECmd.exe (Jump Lists)", "description": "Parses AutomaticDestinations and CustomDestinations Jump Lists"},
    {"key": "ez_amcache", "env_var": "WFT_EZ_AMCACHE_EXE", "binary": "AmcacheParser.exe", "name": "AmcacheParser.exe (Amcache)", "description": "Parses Amcache.hve for SHA-1 hashes and unassociated executable entries"},
    {"key": "ez_shimcache", "env_var": "WFT_EZ_SHIMCACHE_EXE", "binary": "AppCompatCacheParser.exe", "name": "AppCompatCacheParser.exe (Shimcache)", "description": "Parses Application Compatibility Cache from SYSTEM hive"},
    {"key": "ez_sbecmd", "env_var": "WFT_EZ_SBECMD_EXE", "binary": "SBECmd.exe", "name": "SBECmd.exe (ShellBags)", "description": "Parses ShellBags for folder access history across NTUSER.DAT & UsrClass.dat"},
    {"key": "ez_srumecmd", "env_var": "WFT_EZ_SRUMECMD_EXE", "binary": "SrumECmd.exe", "name": "SrumECmd.exe (SRUM)", "description": "Parses System Resource Usage Monitor (SRUDB.dat) database"},
    {"key": "ez_wxtcmd", "env_var": "WFT_EZ_WXTCMD_EXE", "binary": "WxTCmd.exe", "name": "WxTCmd.exe (Windows Timeline)", "description": "Parses Windows 10/11 Timeline (ActivitiesCache.db) database"},
    {"key": "ez_sqlecmd", "env_var": "WFT_EZ_SQLECMD_EXE", "binary": "SQLECmd.exe", "name": "SQLECmd.exe (SQLite Extractor)", "description": "Parses SQLite databases with pre-built maps for forensics"},
    {"key": "ez_rbcmd", "env_var": "WFT_EZ_RBCMD_EXE", "binary": "RBCmd.exe", "name": "RBCmd.exe (Recycle Bin)", "description": "Parses $Recycle.Bin $I index and metadata files"},
    {"key": "ez_recentfilecache", "env_var": "WFT_EZ_RECENTFILECACHE_EXE", "binary": "RecentFileCacheParser.exe", "name": "RecentFileCacheParser.exe (RecentFileCache)", "description": "Parses RecentFileCache.bcf from legacy Windows systems"},
    {"key": "ez_sumecmd", "env_var": "WFT_EZ_SUMECMD_EXE", "binary": "SumECmd.exe", "name": "SumECmd.exe (User Access Logging)", "description": "Parses Microsoft User Access Logging (UAL) database (Current.mdb)"},
]

EZ_BINARY_TO_ENV: Dict[str, str] = {
    item["binary"].lower(): item["env_var"] for item in EZ_BINARIES_SPEC
}

KEY_TO_ENV_MAP: Dict[str, str] = {
    "ez_tools": "WFT_EZTOOLS_DIR",
    "wft_eztools_dir": "WFT_EZTOOLS_DIR",
    "WFT_EZTOOLS_DIR": "WFT_EZTOOLS_DIR",
    "regripper": "WFT_REGRIPPER_EXE",
    "regripper_dir": "WFT_REGRIPPER_DIR",
    "wft_regripper_dir": "WFT_REGRIPPER_DIR",
    "WFT_REGRIPPER_DIR": "WFT_REGRIPPER_DIR",
    "wft_regripper_exe": "WFT_REGRIPPER_EXE",
    "WFT_REGRIPPER_EXE": "WFT_REGRIPPER_EXE",
    "hindsight": "WFT_HINDSIGHT_EXE",
    "wft_hindsight_exe": "WFT_HINDSIGHT_EXE",
    "WFT_HINDSIGHT_EXE": "WFT_HINDSIGHT_EXE",
    "stinger": "WFT_STINGER_EXE",
    "wft_stinger_exe": "WFT_STINGER_EXE",
    "WFT_STINGER_EXE": "WFT_STINGER_EXE",
    "bulk_extractor": "WFT_BULK_EXTRACTOR_EXE",
    "wft_bulk_extractor_exe": "WFT_BULK_EXTRACTOR_EXE",
    "WFT_BULK_EXTRACTOR_EXE": "WFT_BULK_EXTRACTOR_EXE",
    "rip.exe": "WFT_REGRIPPER_EXE",
    "hindsight.exe": "WFT_HINDSIGHT_EXE",
    "hindsight.py": "WFT_HINDSIGHT_EXE",
    "stinger.exe": "WFT_STINGER_EXE",
    "stinger32.exe": "WFT_STINGER_EXE",
    "stinger64.exe": "WFT_STINGER_EXE",
    "bulk_extractor64.exe": "WFT_BULK_EXTRACTOR_EXE",
    "bulk_extractor.exe": "WFT_BULK_EXTRACTOR_EXE",
}
for _item in EZ_BINARIES_SPEC:
    KEY_TO_ENV_MAP[_item["key"]] = _item["env_var"]
    KEY_TO_ENV_MAP[_item["binary"].lower()] = _item["env_var"]
    KEY_TO_ENV_MAP[_item["env_var"].lower()] = _item["env_var"]
    KEY_TO_ENV_MAP[_item["env_var"]] = _item["env_var"]


_REGRIPPER_VALIDATION_CACHE: Dict[Tuple[str, int], bool] = {}
_REGRIPPER_AUTO_FLAG_RE = re.compile(r"(?m)^\s*-a\b")
_BOUNDED_EZ_CONTAINERS: Set[str] = {
    "net", "net4", "net6", "net8", "net9", "net10",
    "ez_tools", "eztools", "ez-tools", "bin",
}


def _has_pe_mz_header(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        if r"\microsoft\windowsapps\\" in (str(path).lower() + "\\"):
            return False
        if path.stat().st_size < 64:
            return False
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _is_valid_hindsight_binary(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        low_name = path.name.lower()
        if "gui" in low_name:
            return False
        if path.suffix.lower() == ".exe":
            return _has_pe_mz_header(path)
        if path.suffix.lower() == ".py":
            return low_name == "hindsight.py" and path.stat().st_size > 32
        return path.stat().st_size > 0
    except OSError:
        return False


def validate_regripper_binary(candidate: Union[str, Path]) -> bool:
    """Verifies candidate rip.exe is a valid PE executable with adjacent plugins/*.pl AND -a support (rejecting Autopsy Rip v2.8)."""
    try:
        resolved = Path(candidate).resolve()
        if not _has_pe_mz_header(resolved):
            return False
        st = resolved.stat()
    except OSError:
        return False

    cache_key = (str(resolved).lower(), st.st_mtime_ns)
    if cache_key in _REGRIPPER_VALIDATION_CACHE:
        return _REGRIPPER_VALIDATION_CACHE[cache_key]

    plugins_dir = resolved.parent / "plugins"
    try:
        has_plugins = plugins_dir.is_dir() and any(plugins_dir.glob("*.pl"))
    except OSError:
        has_plugins = False

    if not has_plugins:
        _REGRIPPER_VALIDATION_CACHE[cache_key] = False
        return False

    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        cp = subprocess.run(
            [str(resolved), "-h"],
            cwd=str(resolved.parent),
            capture_output=True,
            text=True,
            timeout=5,
            errors="replace",
            creationflags=creationflags,
        )
        combined = f"{cp.stdout or ''}\n{cp.stderr or ''}"
        if re.search(r"Rip v\.2\.", combined):
            is_valid = False
        else:
            is_valid = bool(_REGRIPPER_AUTO_FLAG_RE.search(combined))
    except (OSError, subprocess.SubprocessError):
        is_valid = False

    _REGRIPPER_VALIDATION_CACHE[cache_key] = is_valid
    return is_valid


def _is_valid_tool_override_value(env_key: str, raw_val: str) -> bool:
    val = (raw_val or "").strip().strip('"').strip("'")
    if not val:
        return False
    canon = KEY_TO_ENV_MAP.get(env_key.lower(), env_key)
    try:
        cand_p = _resolve_candidate_path(val)
    except OSError:
        return False
    if canon == "WFT_REGRIPPER_EXE":
        return validate_regripper_binary(cand_p)
    if canon == "WFT_HINDSIGHT_EXE":
        return _is_valid_hindsight_binary(cand_p)
    if canon in ("WFT_STINGER_EXE", "WFT_BULK_EXTRACTOR_EXE") or canon.endswith("_EXE"):
        return _has_pe_mz_header(cand_p)
    if canon in ("WFT_EZTOOLS_DIR", "WFT_REGRIPPER_DIR", "WFT_RULES_DIR", "WFT_CASES_DIR"):
        return cand_p.is_dir()
    return cand_p.exists()


def _read_raw_persisted_tool_paths() -> Dict[str, str]:
    explicit_isolated = bool(
        os.environ.get("WFT_TOOL_PATHS_FILE", "").strip()
        or os.environ.get("WFT_APPDATA_DIR", "").strip()
    )
    primary_fp = get_tool_paths_file()
    candidates = [primary_fp] if explicit_isolated else [primary_fp, LEGACY_TOOL_PATHS_FILE]
    for fp in candidates:
        if fp.is_file():
            try:
                with open(fp, "r", encoding="utf-8-sig") as f:
                    raw_data = json.load(f)
                if isinstance(raw_data, dict):
                    cleaned: Dict[str, str] = {}
                    for k, v in raw_data.items():
                        if isinstance(k, str) and isinstance(v, str) and v.strip():
                            cleaned[k.strip()] = v.strip().strip('"').strip("'")
                    return cleaned
                return {}
            except Exception as ex:
                print(f"[config] Warning loading tool_paths.json from {fp}: {ex}")
                return {}
    return {}


def _load_persisted_tool_paths() -> None:
    global _CUSTOM_TOOL_PATHS
    raw_cleaned = _read_raw_persisted_tool_paths()
    valid_map: Dict[str, str] = {}
    for k, v in raw_cleaned.items():
        canon = KEY_TO_ENV_MAP.get(k.lower(), k)
        if _is_valid_tool_override_value(canon, v):
            valid_map[canon] = v
    _CUSTOM_TOOL_PATHS = valid_map


_load_persisted_tool_paths()


def _get_path_setting(env_var: str, fallback_relative: str) -> Path:
    _load_persisted_tool_paths()
    env_val = (os.getenv(env_var) or "").strip()
    custom_val = (_CUSTOM_TOOL_PATHS.get(env_var) or "").strip()

    if env_val:
        env_p = _resolve_candidate_path(env_val)
        if env_p.exists():
            return env_p
    if custom_val:
        custom_p = _resolve_candidate_path(custom_val)
        if custom_p.exists():
            return custom_p
    if env_val:
        return _resolve_candidate_path(env_val)
    if custom_val:
        return _resolve_candidate_path(custom_val)

    return (BASE_DIR / fallback_relative).resolve()


def _get_default_cases_dir() -> Path:
    _load_persisted_tool_paths()
    env_val = (os.getenv("WFT_CASES_DIR") or "").strip()
    if env_val:
        return _resolve_candidate_path(env_val)
    custom_val = (_CUSTOM_TOOL_PATHS.get("WFT_CASES_DIR") or "").strip()
    if custom_val:
        return _resolve_candidate_path(custom_val)
    desktop_cases = Path.home() / "Desktop" / "cases"
    return desktop_cases.resolve()


CASES_DIR: Path = _get_default_cases_dir()
TOOL_CASES_DIR: Path = (BASE_DIR / "cases").resolve()
RULES_DIR: Path = (
    (BUNDLE_DIR / "rules").resolve()
    if (getattr(sys, "frozen", False) and (BUNDLE_DIR / "rules").exists())
    else _get_path_setting("WFT_RULES_DIR", "rules")
)
DEFAULT_YARA_FILE: Path = (RULES_DIR / "default_malware.yar").resolve()

CUSTOM_LOCATIONS_FILE: Path = (APP_DATA_DIR / "custom_locations.json").resolve()
LEGACY_LOCATIONS_FILE: Path = (BASE_DIR / "custom_locations.json").resolve()
_CUSTOM_CASE_DIRS: Dict[str, str] = {}


def get_custom_locations_file() -> Path:
    override = os.environ.get("WFT_CUSTOM_LOCATIONS_FILE", "").strip()
    if override:
        p = Path(override)
        return p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
    if os.environ.get("WFT_APPDATA_DIR", "").strip():
        return (get_appdata_dir() / "custom_locations.json").resolve()
    return CUSTOM_LOCATIONS_FILE


def _load_custom_case_dirs() -> None:
    global _CUSTOM_CASE_DIRS
    changed = False
    raw_cases: Dict[str, str] = {}
    active_loc_file = get_custom_locations_file()
    explicit_isolated = bool(
        os.environ.get("WFT_CUSTOM_LOCATIONS_FILE", "").strip()
        or os.environ.get("WFT_APPDATA_DIR", "").strip()
    )

    if active_loc_file.exists():
        try:
            with open(active_loc_file, "r", encoding="utf-8-sig") as f:
                raw_cases = json.load(f)
        except Exception:
            raw_cases = {}

    if not explicit_isolated:
        for legacy_f in [
            LEGACY_LOCATIONS_FILE,
            (TOOL_CASES_DIR / "custom_locations.json").resolve(),
            (CASES_DIR / "custom_locations.json").resolve(),
        ]:
            if legacy_f != active_loc_file and legacy_f.exists():
                try:
                    with open(legacy_f, "r", encoding="utf-8-sig") as f:
                        legacy_dict = json.load(f)
                    for k, v in legacy_dict.items():
                        if k not in raw_cases:
                            raw_cases[k] = v
                except Exception:
                    pass

    pruned_cases: Dict[str, str] = {}
    seen_paths: Set[str] = set()
    for k, v in raw_cases.items():
        if isinstance(v, str) and v.strip() and Path(v).is_dir():
            resolved_str = str(Path(v).resolve())
            norm_path_key = resolved_str.lower()
            if norm_path_key in seen_paths:
                changed = True
                continue
            seen_paths.add(norm_path_key)
            pruned_cases[k.strip()] = resolved_str
        else:
            changed = True

    _CUSTOM_CASE_DIRS = pruned_cases

    if not explicit_isolated:
        desktop_cases = Path.home() / "Desktop" / "cases"
        if desktop_cases.is_dir():
            for candidate in desktop_cases.iterdir():
                if candidate.is_dir() and (candidate / "case.duckdb").exists():
                    resolved_cand = str(candidate.resolve())
                    if resolved_cand.lower() in seen_paths:
                        continue
                    cid = candidate.name
                    if not any(k.strip().lower() == cid.lower() for k in _CUSTOM_CASE_DIRS):
                        _CUSTOM_CASE_DIRS[cid] = resolved_cand
                        seen_paths.add(resolved_cand.lower())
                        changed = True

    if changed:
        try:
            active_loc_file.parent.mkdir(parents=True, exist_ok=True)
            with open(active_loc_file, "w", encoding="utf-8") as f:
                json.dump(_CUSTOM_CASE_DIRS, f, indent=2)
        except Exception as ex:
            print(f"[config] Warning auto-persisting custom_locations.json: {ex}")


def register_case_dir(case_id: str, custom_dir: Union[str, Path]) -> Path:
    """
    Register and persist custom storage folder for a case using a single canonical key.
    """
    global _CUSTOM_CASE_DIRS
    clean_cid = (case_id or "").strip()

    resolved_p = Path(custom_dir).resolve()
    resolved_p.mkdir(parents=True, exist_ok=True)
    resolved_str = str(resolved_p)

    _load_custom_case_dirs()

    keys_to_remove = [
        k for k, v in _CUSTOM_CASE_DIRS.items()
        if k.strip().lower() == clean_cid.lower() or str(Path(v).resolve()).lower() == resolved_str.lower()
    ]
    for k in keys_to_remove:
        del _CUSTOM_CASE_DIRS[k]

    _CUSTOM_CASE_DIRS[clean_cid] = resolved_str
    active_loc_file = get_custom_locations_file()

    try:
        active_loc_file.parent.mkdir(parents=True, exist_ok=True)
        with open(active_loc_file, "w", encoding="utf-8") as f:
            json.dump(_CUSTOM_CASE_DIRS, f, indent=2)
    except Exception as ex:
        print(f"[config] Warning saving custom_locations.json: {ex}")

    try:
        from backend.db.engine import DuckDBManager
        DuckDBManager.close_connection(clean_cid)
    except Exception:
        pass

    try:
        tool_cases_dir = (BASE_DIR / "cases").resolve()
        if tool_cases_dir.exists() and tool_cases_dir.is_dir():
            phantom_p = (tool_cases_dir / clean_cid).resolve()
            if phantom_p != resolved_p and phantom_p.exists() and phantom_p.is_dir():
                if not (phantom_p / "case.duckdb").exists():
                    shutil.rmtree(phantom_p, ignore_errors=True)
            for sub in list(tool_cases_dir.iterdir()):
                if sub.is_dir() and not any(sub.iterdir()):
                    try:
                        sub.rmdir()
                    except Exception:
                        pass
            if not any(tool_cases_dir.iterdir()):
                try:
                    tool_cases_dir.rmdir()
                except Exception:
                    pass
    except Exception:
        pass

    return resolved_p


def unregister_case_dir(case_id: str) -> None:
    global _CUSTOM_CASE_DIRS
    _load_custom_case_dirs()
    changed = False
    clean_cid = (case_id or "").strip().lower()
    active_loc_file = get_custom_locations_file()

    keys_to_del = [k for k in _CUSTOM_CASE_DIRS if k.strip().lower() == clean_cid]
    for k in keys_to_del:
        del _CUSTOM_CASE_DIRS[k]
        changed = True

    if active_loc_file.exists():
        try:
            with open(active_loc_file, "r", encoding="utf-8-sig") as f:
                locs = json.load(f)
            locs_to_del = [k for k in locs if k.strip().lower() == clean_cid]
            if locs_to_del:
                for k in locs_to_del:
                    del locs[k]
                changed = True
                _CUSTOM_CASE_DIRS = locs
        except Exception:
            pass

    if changed:
        try:
            active_loc_file.parent.mkdir(parents=True, exist_ok=True)
            with open(active_loc_file, "w", encoding="utf-8") as f:
                json.dump(_CUSTOM_CASE_DIRS, f, indent=2)
        except Exception as ex:
            print(f"[config] Warning updating custom_locations.json on unregister: {ex}")


def get_registered_custom_cases() -> Dict[str, str]:
    _load_custom_case_dirs()
    return dict(_CUSTOM_CASE_DIRS)


def get_case_dir(case_id: str, create_if_missing: bool = False) -> Path:
    _load_custom_case_dirs()
    cid_clean = (case_id or "").strip()
    cid_lower = cid_clean.lower()

    if cid_clean in _CUSTOM_CASE_DIRS:
        custom_dir = Path(_CUSTOM_CASE_DIRS[cid_clean]).resolve()
        if create_if_missing:
            custom_dir.mkdir(parents=True, exist_ok=True)
        return custom_dir

    for k, v in _CUSTOM_CASE_DIRS.items():
        if k.strip().lower() == cid_lower:
            custom_dir = Path(v).resolve()
            if create_if_missing:
                custom_dir.mkdir(parents=True, exist_ok=True)
            return custom_dir

    for k, v in _CUSTOM_CASE_DIRS.items():
        p = Path(v).resolve()
        if p.name.lower() == cid_lower:
            if create_if_missing:
                p.mkdir(parents=True, exist_ok=True)
            return p

    cid_norm = cid_lower.replace("_", " ").replace("-", " ")
    for k, v in _CUSTOM_CASE_DIRS.items():
        k_norm = k.strip().lower().replace("_", " ").replace("-", " ")
        if k_norm == cid_norm:
            custom_dir = Path(v).resolve()
            if create_if_missing:
                custom_dir.mkdir(parents=True, exist_ok=True)
            return custom_dir

    desktop_case = Path.home() / "Desktop" / "cases" / cid_clean
    if (desktop_case / "case.duckdb").exists():
        return desktop_case.resolve()

    case_dir = (CASES_DIR / cid_clean).resolve()
    if create_if_missing:
        case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


API_HOST: str = os.getenv("WFT_HOST", "127.0.0.1")
API_PORT: int = int(os.getenv("WFT_PORT", "8765"))


def get_ez_tools_dirs() -> List[Path]:
    explicit_env_dir = (os.environ.get("WFT_EZTOOLS_DIR") or "").strip()
    if explicit_env_dir:
        wft_env_override = (os.environ.get("WFT_ENV_FILE") or "").strip()
        if wft_env_override and Path(wft_env_override).resolve().parent != BASE_DIR:
            return [_resolve_candidate_path(explicit_env_dir)]
    configured = _get_path_setting("WFT_EZTOOLS_DIR", "EZTools")
    candidates = [
        configured,
        (BASE_DIR / "EZTools").resolve(),
        (BASE_DIR / "tools" / "ez_tools").resolve(),
        (get_appdata_dir() / "tools" / "ez_tools").resolve(),
    ]
    unique: List[Path] = []
    for c in candidates:
        if c not in unique:
            unique.append(c)
    return unique


def get_regripper_dirs() -> List[Path]:
    configured = _get_path_setting("WFT_REGRIPPER_DIR", "RegRipper4.0")
    candidates = [
        configured,
        (BASE_DIR / "RegRipper4.0").resolve(),
        (BASE_DIR / "tools" / "regripper").resolve(),
        (BASE_DIR / "RegRipper").resolve(),
        (get_appdata_dir() / "tools" / "regripper").resolve(),
    ]
    unique: List[Path] = []
    for c in candidates:
        if c not in unique:
            unique.append(c)
    return unique


def find_regripper_binary(exe_name: str = "rip.exe") -> Path:
    _load_persisted_tool_paths()

    for override_val in (os.getenv("WFT_REGRIPPER_EXE"), _CUSTOM_TOOL_PATHS.get("WFT_REGRIPPER_EXE")):
        if override_val and override_val.strip():
            resolved = _resolve_candidate_path(override_val)
            if validate_regripper_binary(resolved):
                return resolved

    normalized_name = exe_name.strip()
    if not normalized_name.lower().endswith(".exe"):
        normalized_name += ".exe"
    target_lower = normalized_name.lower()

    search_dirs = get_regripper_dirs()
    for d in search_dirs:
        if d.is_dir():
            try:
                for p in d.rglob("*"):
                    if p.is_file() and p.name.lower() == target_lower and validate_regripper_binary(p):
                        return p.resolve()
            except OSError:
                continue

    rip_direct = (BASE_DIR / "RegRipper4.0" / "rip.exe").resolve()
    if validate_regripper_binary(rip_direct):
        return rip_direct

    which_rip = shutil.which("rip.exe") or shutil.which("rip")
    if which_rip:
        p = Path(which_rip).resolve()
        if validate_regripper_binary(p):
            return p

    raise FileNotFoundError(
        f"Valid RegRipper v3/v4 binary '{exe_name}' (supporting -a with plugins/) not found in {[str(p) for p in search_dirs]}"
    )


def find_ez_binary(exe_name: str) -> Path:
    normalized_name = exe_name.strip()
    if not normalized_name.lower().endswith(".exe"):
        normalized_name += ".exe"
    target_lower = normalized_name.lower()

    _load_persisted_tool_paths()

    env_var_key = EZ_BINARY_TO_ENV.get(target_lower)
    if env_var_key:
        explicit_env = (os.environ.get(env_var_key) or "").strip()
        if explicit_env:
            resolved_env = _resolve_candidate_path(explicit_env)
            if _has_pe_mz_header(resolved_env):
                return resolved_env
            raise FileNotFoundError(
                f"Configured {env_var_key}={explicit_env!r} is missing or not a valid PE executable."
            )
        custom_override = (_CUSTOM_TOOL_PATHS.get(env_var_key) or "").strip()
        if custom_override:
            resolved_custom = _resolve_candidate_path(custom_override)
            if _has_pe_mz_header(resolved_custom):
                return resolved_custom

    search_dirs = get_ez_tools_dirs()
    for search_root in search_dirs:
        if search_root.is_dir() and len(search_root.resolve().parts) > 1:
            try:
                for candidate in search_root.rglob("*.exe"):
                    if candidate.name.lower() == target_lower and _has_pe_mz_header(candidate):
                        return candidate.resolve()
            except OSError:
                continue

    which_hit = shutil.which(normalized_name)
    if which_hit:
        p = Path(which_hit).resolve()
        if _has_pe_mz_header(p):
            return p

    searched_paths = [str(p) for p in search_dirs]
    env_hint = f", individual env key: {env_var_key}" if env_var_key else ""
    raise FileNotFoundError(
        f"Eric Zimmerman tool binary '{normalized_name}' not found via individual override ({env_hint}), "
        f"search paths ({searched_paths}), or system PATH."
    )


def find_ez_file(filename: str, raise_if_missing: bool = True) -> Optional[Path]:
    """
    Locates an EZ auxiliary file (e.g. 'Kroll_Batch.reb'), glob ('*.smap'), or subfolder ('Maps')
    by checking individual EZ binary directories (affinity-ordered, all .parent before bounded .parent.parent)
    AND get_ez_tools_dirs(). For 'Maps', prefers directories containing '*.smap' files.
    """
    clean_name = filename.strip()
    target_lower = clean_name.lower()
    is_glob = ("*" in clean_name) or ("?" in clean_name)
    wants_smap_maps_dir = (not is_glob) and (target_lower == "maps")

    if target_lower == "maps" or target_lower.endswith(".smap"):
        ordered_ez_bins = ("SQLECmd.exe", "RECmd.exe", "EvtxECmd.exe")
    elif target_lower.endswith(".reb") or "batch" in target_lower:
        ordered_ez_bins = ("RECmd.exe", "SQLECmd.exe", "EvtxECmd.exe")
    elif target_lower.endswith(".map"):
        ordered_ez_bins = ("EvtxECmd.exe", "SQLECmd.exe", "RECmd.exe")
    else:
        ordered_ez_bins = ("RECmd.exe", "SQLECmd.exe", "EvtxECmd.exe")

    search_dirs: List[Path] = []
    seen_dirs: Set[str] = set()

    def _add_dir(cand_dir: Path) -> None:
        try:
            rp = cand_dir.resolve()
            if len(rp.parts) <= 1:
                return
            key = str(rp).lower()
            if key not in seen_dirs:
                seen_dirs.add(key)
                search_dirs.append(rp)
        except OSError:
            pass

    resolved_bins: List[Path] = []
    for ez_bin in ordered_ez_bins:
        try:
            resolved_bins.append(find_ez_binary(ez_bin))
        except FileNotFoundError:
            pass

    for bin_path in resolved_bins:
        _add_dir(bin_path.parent)

    for bin_path in resolved_bins:
        gp = bin_path.parent.parent
        if gp.name.lower() in _BOUNDED_EZ_CONTAINERS:
            _add_dir(gp)

    for d in get_ez_tools_dirs():
        _add_dir(d)

    fallback_maps_dir: Optional[Path] = None

    for search_root in search_dirs:
        if not search_root.is_dir():
            continue
        if not is_glob:
            direct = search_root / clean_name
            try:
                if direct.is_file():
                    return direct.resolve()
                if direct.is_dir() and any(direct.iterdir()):
                    if wants_smap_maps_dir:
                        if any(direct.glob("*.smap")):
                            return direct.resolve()
                        if fallback_maps_dir is None:
                            fallback_maps_dir = direct.resolve()
                    else:
                        return direct.resolve()
            except OSError:
                pass

        try:
            for candidate in search_root.rglob("*"):
                cand_name_low = candidate.name.lower()
                if is_glob:
                    if candidate.is_file() and fnmatch.fnmatch(cand_name_low, target_lower):
                        return candidate.resolve()
                else:
                    if candidate.is_file() and cand_name_low == target_lower:
                        return candidate.resolve()
                    if candidate.is_dir() and cand_name_low == target_lower and any(candidate.iterdir()):
                        if wants_smap_maps_dir:
                            if any(candidate.glob("*.smap")):
                                return candidate.resolve()
                            if fallback_maps_dir is None:
                                fallback_maps_dir = candidate.resolve()
                        else:
                            return candidate.resolve()
        except OSError:
            continue

    if fallback_maps_dir is not None:
        return fallback_maps_dir

    if raise_if_missing:
        searched_paths = [str(p) for p in search_dirs]
        raise FileNotFoundError(
            f"Support file '{filename}' not found in EZ tools search paths: {searched_paths}"
        )
    return None


def find_bulk_extractor_binary() -> Optional[Path]:
    _load_persisted_tool_paths()
    for custom_val in (os.getenv("WFT_BULK_EXTRACTOR_EXE"), _CUSTOM_TOOL_PATHS.get("WFT_BULK_EXTRACTOR_EXE")):
        if custom_val and custom_val.strip():
            resolved = _resolve_candidate_path(custom_val)
            if _has_pe_mz_header(resolved):
                return resolved

    env_override_raw = os.environ.get("WFT_ENV_FILE", "").strip()
    isolated_env_root: Optional[Path] = None
    if env_override_raw:
        try:
            env_p = Path(env_override_raw).resolve()
            if env_p.parent != BASE_DIR.resolve():
                isolated_env_root = env_p.parent
        except OSError:
            isolated_env_root = None

    search_base = isolated_env_root if isolated_env_root is not None else BASE_DIR
    candidates = [
        search_base / "tools" / "bulk_extractor" / "bulk_extractor64.exe",
        search_base / "tools" / "bulk_extractor" / "bulk_extractor.exe",
        search_base / "tools" / "bulk_extractor64.exe",
        search_base / "tools" / "bulk_extractor.exe",
        search_base / "bulk_extractor64.exe",
        search_base / "bulk_extractor.exe",
        get_appdata_dir() / "tools" / "bulk_extractor" / "bulk_extractor64.exe",
        get_appdata_dir() / "tools" / "bulk_extractor" / "bulk_extractor.exe",
    ]
    for c in candidates:
        if _has_pe_mz_header(c):
            return c.resolve()

    if isolated_env_root is not None:
        return None

    which_be = (
        shutil.which("bulk_extractor64.exe")
        or shutil.which("bulk_extractor.exe")
        or shutil.which("bulk_extractor")
    )
    if which_be:
        p = Path(which_be).resolve()
        if _has_pe_mz_header(p):
            return p

    return None


def find_stinger_binary() -> Optional[Path]:
    _load_persisted_tool_paths()
    for custom_val in (os.getenv("WFT_STINGER_EXE"), _CUSTOM_TOOL_PATHS.get("WFT_STINGER_EXE")):
        if custom_val and custom_val.strip():
            resolved = _resolve_candidate_path(custom_val)
            if _has_pe_mz_header(resolved):
                return resolved

    candidates = [
        BASE_DIR / "stinger64.exe",
        BASE_DIR / "stinger32.exe",
        BASE_DIR / "tools" / "stinger" / "stinger64.exe",
        BASE_DIR / "tools" / "stinger" / "stinger32.exe",
        BASE_DIR / "tools" / "stinger.exe",
        get_appdata_dir() / "tools" / "stinger" / "stinger64.exe",
        get_appdata_dir() / "tools" / "stinger" / "stinger32.exe",
    ]
    for c in candidates:
        if _has_pe_mz_header(c):
            return c.resolve()

    which_stinger = shutil.which("stinger64.exe") or shutil.which("stinger32.exe") or shutil.which("stinger.exe")
    if which_stinger:
        p = Path(which_stinger).resolve()
        if _has_pe_mz_header(p):
            return p

    return None


_DEFAULT_HINDSIGHT_PLACEHOLDERS: Set[str] = {
    "./hindsight-main/hindsight.py",
    ".\\hindsight-main\\hindsight.py",
    "hindsight-main/hindsight.py",
    "hindsight-main\\hindsight.py",
    "./tools/hindsight.exe",
    ".\\tools\\hindsight.exe",
}


def find_hindsight_binary() -> Optional[Path]:
    _load_persisted_tool_paths()
    raw_hs_env = (os.environ.get("WFT_HINDSIGHT_EXE") or "").strip().strip('"').strip("'")
    if raw_hs_env and raw_hs_env not in _DEFAULT_HINDSIGHT_PLACEHOLDERS:
        resolved_env = _resolve_candidate_path(raw_hs_env)
        if _is_valid_hindsight_binary(resolved_env):
            return resolved_env
        return None
    for custom_val in (raw_hs_env, _CUSTOM_TOOL_PATHS.get("WFT_HINDSIGHT_EXE")):
        if custom_val and custom_val.strip():
            resolved = _resolve_candidate_path(custom_val)
            if _is_valid_hindsight_binary(resolved):
                return resolved

    candidates: List[Path] = [
        BASE_DIR / "tools" / "hindsight" / "hindsight.exe",
        BASE_DIR / "tools" / "hindsight.exe",
        BASE_DIR / "hindsight.exe",
        BASE_DIR / "hindsight-main" / "hindsight.py",
        BASE_DIR / "tools" / "hindsight" / "hindsight.py",
        get_appdata_dir() / "tools" / "hindsight" / "hindsight.exe",
        get_appdata_dir() / "tools" / "hindsight" / "hindsight.py",
    ]

    try:
        import sysconfig
        scripts_dir = sysconfig.get_path("scripts")
        if scripts_dir:
            sp = Path(scripts_dir)
            candidates.extend([sp / "hindsight.exe", sp / "hindsight-cli.exe", sp / "hindsight.py"])
    except Exception:
        pass

    for c in candidates:
        if _is_valid_hindsight_binary(c):
            return c.resolve()

    which_hindsight = shutil.which("hindsight.exe") or shutil.which("hindsight")
    if which_hindsight:
        p = Path(which_hindsight).resolve()
        if _is_valid_hindsight_binary(p):
            return p

    return None


def _get_valid_configured_str(env_var: str) -> str:
    for raw_v in (os.getenv(env_var), _CUSTOM_TOOL_PATHS.get(env_var)):
        if raw_v and raw_v.strip() and _is_valid_tool_override_value(env_var, raw_v):
            return raw_v.strip().strip('"').strip("'")
    return ""


def get_tool_paths_status() -> Dict[str, Dict[str, Any]]:
    _load_persisted_tool_paths()
    result: Dict[str, Dict[str, Any]] = {}

    individual_entries: Dict[str, Dict[str, Any]] = {}
    first_resolved_ez_parent: Optional[Path] = None
    for item in EZ_BINARIES_SPEC:
        k = item["key"]
        env_var = item["env_var"]
        bin_name = item["binary"]
        resolved_bin: Optional[Path] = None
        try:
            resolved_bin = find_ez_binary(bin_name)
            if first_resolved_ez_parent is None:
                first_resolved_ez_parent = resolved_bin.parent
        except Exception:
            pass

        configured_val = _get_valid_configured_str(env_var)
        individual_entries[k] = {
            "name": item["name"],
            "env_var": env_var,
            "binary": bin_name,
            "configured_path": configured_val or (str(resolved_bin) if resolved_bin else ""),
            "resolved_path": str(resolved_bin) if resolved_bin else None,
            "path": str(resolved_bin) if resolved_bin else configured_val,
            "status": "FOUND" if resolved_bin is not None else "MISSING",
            "description": item["description"],
            "category": "individual_ez",
        }

    ez_dirs = get_ez_tools_dirs()
    ez_found = False
    ez_path_str = str(ez_dirs[0])
    known_ez_names = {i["binary"].lower() for i in EZ_BINARIES_SPEC}
    for d in ez_dirs:
        if d.is_dir():
            try:
                if any(
                    p.is_file() and p.name.lower() in known_ez_names and _has_pe_mz_header(p)
                    for p in d.rglob("*.exe")
                ):
                    ez_found = True
                    ez_path_str = str(d)
                    break
            except OSError:
                continue
    if not ez_found and first_resolved_ez_parent is not None:
        ez_found = True
        ez_path_str = str(first_resolved_ez_parent)

    configured_ez = _get_valid_configured_str("WFT_EZTOOLS_DIR") or (ez_path_str if ez_found else "./EZTools")
    result["ez_tools"] = {
        "name": "Eric Zimmerman Tools Directory",
        "env_var": "WFT_EZTOOLS_DIR",
        "configured_path": configured_ez,
        "resolved_path": ez_path_str if ez_found else None,
        "path": ez_path_str if ez_found else configured_ez,
        "status": "FOUND" if ez_found else "MISSING",
        "description": "Master folder containing Eric Zimmerman CLI forensic tools (.NET 6/9/10)",
        "category": "main",
    }

    rr_binary: Optional[Path] = None
    try:
        rr_binary = find_regripper_binary()
    except Exception:
        pass
    configured_rr = (
        _get_valid_configured_str("WFT_REGRIPPER_EXE")
        or (str(rr_binary) if rr_binary is not None else "")
        or _get_valid_configured_str("WFT_REGRIPPER_DIR")
        or "./RegRipper4.0"
    )
    result["regripper"] = {
        "name": "RegRipper 4.0",
        "env_var": "WFT_REGRIPPER_EXE",
        "configured_path": configured_rr,
        "resolved_path": str(rr_binary) if rr_binary else None,
        "path": str(rr_binary) if rr_binary is not None else configured_rr,
        "status": "FOUND" if rr_binary is not None else "MISSING",
        "description": "Registry hive fast analysis engine (rip.exe)",
        "category": "main",
    }

    pyhindsight_installed = False
    hindsight_ver = "unknown"
    try:
        import pyhindsight
        pyhindsight_installed = True
        hindsight_ver = getattr(pyhindsight, "__version__", "installed")
    except Exception:
        pass

    hs_binary = find_hindsight_binary()
    hs_status = "FOUND" if (pyhindsight_installed or hs_binary is not None) else "MISSING"
    configured_hs = (
        _get_valid_configured_str("WFT_HINDSIGHT_EXE")
        or (str(hs_binary) if hs_binary else "./hindsight-main/hindsight.py")
    )
    result["hindsight"] = {
        "name": "Hindsight (pyhindsight)",
        "env_var": "WFT_HINDSIGHT_EXE",
        "configured_path": configured_hs,
        "resolved_path": str(hs_binary) if hs_binary else ("pyhindsight (Python module)" if pyhindsight_installed else None),
        "path": str(hs_binary) if hs_binary else configured_hs,
        "status": hs_status,
        "version": hindsight_ver,
        "description": "Chromium browser forensic extraction engine",
        "category": "main",
    }

    stinger_bin = find_stinger_binary()
    stinger_status = "FOUND" if (stinger_bin and stinger_bin.is_file()) else "HEURISTICS READY"
    configured_stinger = (
        _get_valid_configured_str("WFT_STINGER_EXE")
        or (str(stinger_bin) if stinger_bin else "./stinger32.exe")
    )
    result["stinger"] = {
        "name": "Trellix Stinger / PE Threat Scanner",
        "env_var": "WFT_STINGER_EXE",
        "configured_path": configured_stinger,
        "resolved_path": str(stinger_bin) if stinger_bin else "Built-in PE Threat & Heuristics Analyzer",
        "path": str(stinger_bin) if stinger_bin else configured_stinger,
        "status": stinger_status,
        "description": "Trellix Stinger standalone AV scanner + PE heuristic threat engine",
        "category": "main",
    }

    be_bin = find_bulk_extractor_binary()
    be_status = "FOUND" if (be_bin and be_bin.is_file()) else "MISSING"
    configured_be = (
        _get_valid_configured_str("WFT_BULK_EXTRACTOR_EXE")
        or (str(be_bin) if be_bin else "./tools/bulk_extractor/bulk_extractor64.exe")
    )
    result["bulk_extractor"] = {
        "name": "Bulk Extractor (bulk_extractor64.exe)",
        "env_var": "WFT_BULK_EXTRACTOR_EXE",
        "configured_path": configured_be,
        "resolved_path": str(be_bin) if be_bin else None,
        "path": str(be_bin) if be_bin else configured_be,
        "status": be_status,
        "description": "Multi-threaded raw stream & E01 feature, IOC, and carving extractor",
        "category": "main",
    }

    result.update(individual_entries)
    return result


get_tool_paths = get_tool_paths_status


def reload_dotenv(env_file: Optional[Union[str, Path]] = None, override: bool = True) -> Dict[str, str]:
    """Reloads .env into os.environ, reconciles stale/invalid tool_paths.json entries, and refreshes module globals."""
    global _CUSTOM_TOOL_PATHS, APP_DATA_DIR, CASES_DIR, RULES_DIR, DEFAULT_YARA_FILE, CUSTOM_LOCATIONS_FILE, API_HOST, API_PORT
    APP_DATA_DIR = get_appdata_dir()
    loaded_env = load_root_env(override=override, env_file=env_file)
    raw_tp = _read_raw_persisted_tool_paths()

    if raw_tp:
        mutated = False
        reconciled: Dict[str, str] = {}
        for k, raw_v in raw_tp.items():
            canon = KEY_TO_ENV_MAP.get(k.lower(), k)
            if canon in loaded_env and loaded_env[canon]:
                env_v = loaded_env[canon]
                if _is_valid_tool_override_value(canon, env_v):
                    reconciled[canon] = env_v
                    if k != canon or raw_v != env_v:
                        mutated = True
                else:
                    mutated = True
            elif (
                canon == "WFT_REGRIPPER_EXE"
                and "WFT_REGRIPPER_DIR" in loaded_env
                and loaded_env["WFT_REGRIPPER_DIR"]
            ):
                rr_dir_p = _resolve_candidate_path(loaded_env["WFT_REGRIPPER_DIR"])
                cand_p = _resolve_candidate_path(raw_v)
                if _is_valid_tool_override_value(canon, raw_v) and cand_p.is_relative_to(rr_dir_p):
                    reconciled[canon] = raw_v
                    if k != canon:
                        mutated = True
                else:
                    mutated = True
            elif _is_valid_tool_override_value(canon, raw_v):
                reconciled[canon] = raw_v
                if k != canon:
                    mutated = True
            else:
                mutated = True

        _CUSTOM_TOOL_PATHS = reconciled
        tp_file = get_tool_paths_file()
        if mutated and tp_file.is_file():
            try:
                with open(tp_file, "w", encoding="utf-8") as f:
                    json.dump(_CUSTOM_TOOL_PATHS, f, indent=2)
            except Exception:
                pass
    else:
        _CUSTOM_TOOL_PATHS = {}

    CASES_DIR = _get_default_cases_dir()
    RULES_DIR = (
        (BUNDLE_DIR / "rules").resolve()
        if (getattr(sys, "frozen", False) and (BUNDLE_DIR / "rules").exists())
        else _get_path_setting("WFT_RULES_DIR", "rules")
    )
    DEFAULT_YARA_FILE = (RULES_DIR / "default_malware.yar").resolve()
    CUSTOM_LOCATIONS_FILE = get_custom_locations_file()
    API_HOST = os.getenv("WFT_HOST", "127.0.0.1")
    API_PORT = int(os.getenv("WFT_PORT", "8765"))
    return loaded_env


def reload_config_in_memory() -> None:
    reload_dotenv(override=True)


def save_tool_paths(new_paths: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    global _CUSTOM_TOOL_PATHS
    _load_persisted_tool_paths()

    clean_updates: Dict[str, str] = {}
    forbidden_keys = {
        "WFT_RULES_DIR", "WFT_CASES_DIR",
        "rules", "cases", "yara_x", "cases_dir", "wft_rules_dir", "wft_cases_dir"
    }

    for k, v in new_paths.items():
        k_clean = str(k).strip()
        if not k_clean or k_clean.lower() in forbidden_keys:
            continue

        canonical_env = KEY_TO_ENV_MAP.get(k_clean.lower(), k_clean)
        if canonical_env.lower() in forbidden_keys:
            continue

        v_clean = str(v).strip().strip('"').strip("'") if v is not None else ""
        if canonical_env != k_clean:
            _CUSTOM_TOOL_PATHS.pop(k_clean, None)

        if v_clean:
            _CUSTOM_TOOL_PATHS[canonical_env] = v_clean
            os.environ[canonical_env] = v_clean
            clean_updates[canonical_env] = v_clean
            if canonical_env == "WFT_REGRIPPER_EXE":
                p = Path(v_clean)
                parent_dir = str(p.parent.resolve() if p.is_absolute() else (BASE_DIR / p).parent.resolve())
                _CUSTOM_TOOL_PATHS["WFT_REGRIPPER_DIR"] = parent_dir
                os.environ["WFT_REGRIPPER_DIR"] = parent_dir
                clean_updates["WFT_REGRIPPER_DIR"] = parent_dir
        else:
            _CUSTOM_TOOL_PATHS.pop(canonical_env, None)
            os.environ.pop(canonical_env, None)
            clean_updates[canonical_env] = ""

    tp_file = get_tool_paths_file()
    try:
        tp_file.parent.mkdir(parents=True, exist_ok=True)
        with open(tp_file, "w", encoding="utf-8") as f:
            json.dump(_CUSTOM_TOOL_PATHS, f, indent=2)
    except Exception as ex:
        print(f"[config] Warning writing tool_paths.json: {ex}")

    env_file = get_env_file()
    existing_lines: List[str] = []
    if env_file.exists():
        try:
            existing_lines = env_file.read_text(encoding="utf-8-sig").splitlines()
        except Exception:
            existing_lines = []

    seen_keys = set()
    new_lines: List[str] = []
    for line in existing_lines:
        line_s = line.strip()
        if "=" in line_s and not line_s.startswith("#"):
            k = line_s.split("=", 1)[0].strip()
            if k in clean_updates:
                if k not in seen_keys:
                    val = clean_updates[k]
                    if val:
                        new_lines.append(f"{k}={val}")
                    seen_keys.add(k)
                continue
            elif k in seen_keys:
                continue
            else:
                seen_keys.add(k)
        new_lines.append(line)

    for k, v in clean_updates.items():
        if k not in seen_keys and v:
            new_lines.append(f"{k}={v}")
            seen_keys.add(k)

    try:
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception as ex:
        print(f"[config] Warning writing .env: {ex}")

    reload_config_in_memory()
    for k, v in clean_updates.items():
        if v:
            os.environ[k] = v
            _CUSTOM_TOOL_PATHS[k] = v
        else:
            os.environ.pop(k, None)
            _CUSTOM_TOOL_PATHS.pop(k, None)
    return get_tool_paths_status()


save_custom_tool_paths = save_tool_paths

ALL_18_FORENSIC_TOOLS: List[str] = [
    "rla.exe", "PECmd.exe", "MFTECmd.exe", "EvtxECmd.exe", "RECmd.exe",
    "LECmd.exe", "JLECmd.exe", "AmcacheParser.exe", "AppCompatCacheParser.exe",
    "SBECmd.exe", "SrumECmd.exe", "WxTCmd.exe", "SQLECmd.exe", "RBCmd.exe",
    "RecentFileCacheParser.exe", "SumECmd.exe",
    "rip.exe", "hindsight.exe", "stinger64.exe", "bulk_extractor64.exe",
]
ALL_FORENSIC_TOOLS = ALL_18_FORENSIC_TOOLS

TOOL_EXE_TO_ENV_VAR: Dict[str, str] = {
    item["binary"].lower(): item["env_var"] for item in EZ_BINARIES_SPEC
}
TOOL_EXE_TO_ENV_VAR.update({
    "rip.exe": "WFT_REGRIPPER_EXE",
    "hindsight.exe": "WFT_HINDSIGHT_EXE",
    "hindsight.py": "WFT_HINDSIGHT_EXE",
    "stinger64.exe": "WFT_STINGER_EXE",
    "stinger32.exe": "WFT_STINGER_EXE",
    "stinger.exe": "WFT_STINGER_EXE",
    "bulk_extractor64.exe": "WFT_BULK_EXTRACTOR_EXE",
    "bulk_extractor.exe": "WFT_BULK_EXTRACTOR_EXE",
})


def _is_valid_discovered_tool(target_name: str, candidate_path: Path) -> bool:
    low = target_name.lower()
    if low == "rip.exe":
        return validate_regripper_binary(candidate_path)
    if low in ("hindsight.exe", "hindsight.py"):
        return _is_valid_hindsight_binary(candidate_path)
    if low.endswith(".exe"):
        return _has_pe_mz_header(candidate_path)
    try:
        return candidate_path.is_file() and candidate_path.stat().st_size > 0
    except OSError:
        return False


def find_all_forensic_tools_fast(
    project_root: Optional[Path] = None,
    target_exes: Optional[List[str]] = None,
    search_roots: Optional[List[Path]] = None,
    skip_full_disk_scan: bool = False,
) -> Dict[str, str]:
    if project_root is None:
        project_root = BASE_DIR
    if target_exes is None:
        target_exes = list(ALL_18_FORENSIC_TOOLS)

    t0 = time.perf_counter()
    results: Dict[str, str] = {}
    remaining: Dict[str, str] = {t.lower(): t for t in target_exes}

    python_script_dirs: List[Path] = []
    if not skip_full_disk_scan:
        try:
            import sysconfig
            s_path = sysconfig.get_path("scripts")
            if s_path and os.path.isdir(s_path):
                python_script_dirs.append(Path(s_path).resolve())
        except Exception:
            pass

        try:
            import site
            u_site = site.getusersitepackages()
            if u_site:
                u_scripts = Path(u_site).parent / "Scripts"
                if u_scripts.is_dir():
                    python_script_dirs.append(u_scripts.resolve())
        except Exception:
            pass

        local_app_data = os.getenv("LOCALAPPDATA")
        if local_app_data:
            py_win_pkg = Path(local_app_data) / "Packages"
            if py_win_pkg.is_dir():
                for p in py_win_pkg.glob("PythonSoftwareFoundation.Python*"):
                    candidate = p / "LocalCache" / "local-packages"
                    if candidate.is_dir():
                        for py_dir in candidate.glob("Python*"):
                            s_dir = py_dir / "Scripts"
                            if s_dir.is_dir() and s_dir not in python_script_dirs:
                                python_script_dirs.append(s_dir.resolve())

    explicit_dirs = [Path(d).resolve() for d in (search_roots or []) if d and Path(d).is_dir()]
    local_priority_dirs: List[Path] = explicit_dirs + [
        (project_root / "tools").resolve(),
        (project_root / "EZTools").resolve(),
        (project_root / "RegRipper4.0").resolve(),
        (project_root / "RegRipper").resolve(),
        (project_root / "hindsight-main").resolve(),
        project_root.resolve(),
    ] + python_script_dirs

    existing_priority_dirs: List[Path] = []
    seen_pdirs: Set[str] = set()
    for d in local_priority_dirs:
        if d.is_dir():
            k = str(d).lower()
            if k not in seen_pdirs:
                seen_pdirs.add(k)
                existing_priority_dirs.append(d)

    skip_dirs: Set[str] = {
        "windows", "$recycle.bin", "system volume information", "recovery",
        "node_modules", ".git", ".venv", "venv", "__pycache__", "package cache",
        "appdata", "programdata", "cfreds_", "wft_e2e_scratch", "steamlibrary", "onedrive",
        "playwright-report", "test-results"
    }

    if not skip_full_disk_scan:
        for common_p in (
            Path.home() / "Downloads",
            Path.home() / "Documents",
            Path("C:/Tools"),
            Path("C:/DFIR"),
            Path("C:/Forensics"),
            Path("C:/EZTools"),
            Path("D:/Tools"),
        ):
            if common_p.is_dir():
                rp_c = common_p.resolve()
                kc = str(rp_c).lower()
                if kc not in seen_pdirs:
                    seen_pdirs.add(kc)
                    existing_priority_dirs.append(rp_c)

    if not skip_full_disk_scan:
        for flow, orig in list(remaining.items()):
            which_path = shutil.which(orig)
            if which_path and _is_valid_discovered_tool(orig, Path(which_path)):
                results[orig] = str(Path(which_path).resolve())
                del remaining[flow]

    for pdir in existing_priority_dirs:
        if not remaining:
            break
        try:
            for root, dirs, files in os.walk(str(pdir)):
                dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
                for f in files:
                    flow = f.lower()
                    if flow in remaining:
                        orig = remaining[flow]
                        cand_p = (Path(root) / f).resolve()
                        if _is_valid_discovered_tool(orig, cand_p):
                            results[orig] = str(cand_p)
                            del remaining[flow]
                            if not remaining:
                                break
                if not remaining:
                    break
        except Exception:
            pass

    if not remaining or skip_full_disk_scan:
        return results

    if os.name == "nt" and remaining:
        try:
            import win32com.client
            conn = win32com.client.Dispatch("ADODB.Connection")
            conn.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
            where_clauses = " OR ".join([f"System.FileName = '{remaining[k]}'" for k in remaining])
            sql = f"SELECT System.FileName, System.ItemPathDisplay FROM SystemIndex WHERE {where_clauses}"
            res = conn.Execute(sql)
            rs = res[0] if isinstance(res, tuple) else res
            while not rs.EOF:
                fname = str(rs.Fields.Item("System.FileName").Value)
                fpath = str(rs.Fields.Item("System.ItemPathDisplay").Value)
                flow = fname.lower()
                if flow in remaining and fpath:
                    orig = remaining[flow]
                    cand_p = Path(fpath)
                    if _is_valid_discovered_tool(orig, cand_p):
                        results[orig] = str(cand_p.resolve())
                        del remaining[flow]
                rs.MoveNext()
            conn.Close()
        except Exception:
            pass

    if not remaining:
        return results

    fixed_drives: List[str] = []
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            bitmask = kernel32.GetLogicalDrives()
            for letter_code in range(26):
                if bitmask & (1 << letter_code):
                    drive_letter = f"{chr(65 + letter_code)}:\\"
                    drive_type = kernel32.GetDriveTypeW(drive_letter)
                    if drive_type == 3:
                        vol_buf = ctypes.create_unicode_buffer(261)
                        fs_buf = ctypes.create_unicode_buffer(261)
                        kernel32.GetVolumeInformationW(
                            drive_letter, vol_buf, 261, None, None, None, fs_buf, 261
                        )
                        vol_name = vol_buf.value.lower()
                        if "google drive" not in vol_name:
                            fixed_drives.append(drive_letter)
        except Exception:
            fixed_drives = ["C:\\"]
    else:
        fixed_drives = ["/"]

    drive_t0 = time.perf_counter()
    max_drive_scan_sec = 12.0

    for drive_root in fixed_drives:
        if not remaining or (time.perf_counter() - drive_t0) >= max_drive_scan_sec:
            break
        stack = [drive_root]
        while stack and remaining and (time.perf_counter() - drive_t0) < max_drive_scan_sec:
            current_dir = stack.pop()
            if current_dir.rstrip("\\/").lower() in seen_pdirs:
                continue
            try:
                with os.scandir(current_dir) as it:
                    for entry in it:
                        try:
                            if entry.is_file(follow_symlinks=False):
                                flow = entry.name.lower()
                                if flow in remaining:
                                    orig = remaining[flow]
                                    cand_p = Path(entry.path)
                                    if _is_valid_discovered_tool(orig, cand_p):
                                        results[orig] = str(cand_p.resolve())
                                        del remaining[flow]
                                        if not remaining:
                                            break
                            elif entry.is_dir(follow_symlinks=False):
                                dname_low = entry.name.lower()
                                if dname_low not in skip_dirs and entry.path.rstrip("\\/").lower() not in seen_pdirs:
                                    stack.append(entry.path)
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

    elapsed = (time.perf_counter() - t0) * 1000
    print(f"[scanner] Full disk scan completed in {elapsed:.1f} ms. Found {len(results)}/{len(target_exes)} tools.")
    return results


def scan_and_sync_tool_paths(apply_to_env: bool = True) -> Dict[str, Any]:
    t0 = time.perf_counter()
    discovered = find_all_forensic_tools_fast()
    if "hindsight.exe" not in discovered:
        discovered.update(find_all_forensic_tools_fast(target_exes=["hindsight.py"]))
    if "stinger64.exe" not in discovered:
        discovered.update(find_all_forensic_tools_fast(target_exes=["stinger32.exe", "stinger.exe"]))
    if "bulk_extractor64.exe" not in discovered:
        discovered.update(find_all_forensic_tools_fast(target_exes=["bulk_extractor.exe"]))
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    paths_to_save: Dict[str, str] = {}
    ez_dirs: List[Path] = []

    for exe_name, fpath in discovered.items():
        env_key = TOOL_EXE_TO_ENV_VAR.get(exe_name.lower())
        if env_key:
            paths_to_save[env_key] = fpath
            if env_key.startswith("WFT_EZ_"):
                parent_p = Path(fpath).parent
                if parent_p not in ez_dirs:
                    ez_dirs.append(parent_p)
            elif env_key == "WFT_REGRIPPER_EXE":
                parent_p = Path(fpath).parent
                paths_to_save["WFT_REGRIPPER_DIR"] = str(parent_p)

    known_ez_names = {i["binary"].lower() for i in EZ_BINARIES_SPEC}
    project_ez = (BASE_DIR / "EZTools").resolve()
    if project_ez.is_dir() and any(
        p.is_file() and p.name.lower() in known_ez_names and _has_pe_mz_header(p)
        for p in project_ez.rglob("*.exe")
    ):
        paths_to_save["WFT_EZTOOLS_DIR"] = str(project_ez)
    elif ez_dirs:
        paths_to_save["WFT_EZTOOLS_DIR"] = str(ez_dirs[0].resolve())

    if apply_to_env and paths_to_save:
        save_tool_paths(paths_to_save)

    refreshed_status = get_tool_paths_status()
    return {
        "status": "success",
        "duration_ms": elapsed_ms,
        "discovered_count": len(discovered),
        "discovered_tools": discovered,
        "tools": refreshed_status,
        "saved_to_env": apply_to_env,
    }


def get_case_db_path(case_id: str) -> Path:
    return (get_case_dir(case_id) / "case.duckdb").resolve()


def get_case_staging_dir(case_id: str) -> Path:
    staging_dir = (get_case_dir(case_id) / "staging").resolve()
    staging_dir.mkdir(parents=True, exist_ok=True)
    return staging_dir


def get_case_csv_out_dir(case_id: str) -> Path:
    csv_out_dir = (get_case_dir(case_id) / "csv_out").resolve()
    csv_out_dir.mkdir(parents=True, exist_ok=True)
    return csv_out_dir


def get_case_log_file(case_id: str) -> Path:
    return (get_case_dir(case_id) / "processing.log").resolve()
