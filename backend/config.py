"""
Windows Forensic Toolkit (WFT) - Configuration & Path Resolver
Loads environment variables from .env and custom settings from cases/tool_paths.json.
Provides centralized path discovery and health status verification for all forensic engines.
"""
import ctypes
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Root repository directory
# Root repository or executable directory
if getattr(sys, "frozen", False):
    BUNDLE_DIR: Path = Path(sys._MEIPASS)
    BASE_DIR: Path = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR: Path = Path(__file__).resolve().parent.parent
    BASE_DIR: Path = Path(__file__).resolve().parent.parent

# Store app metadata in %LOCALAPPDATA%\WFT so WFT's own directory stays 100% clean
APP_DATA_DIR: Path = Path(os.environ.get("LOCALAPPDATA", str(BASE_DIR))) / "WFT"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

def get_runtime_log_dir() -> Path:
    """Standardized enterprise log directory where WFT.exe presents (BASE_DIR / logs)."""
    logs_dir = BASE_DIR / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir
    except Exception:
        fallback = Path.cwd() / "logs"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

LOGS_DIR: Path = get_runtime_log_dir()
LOG_FILE: Path = LOGS_DIR / "wft_runtime.log"

def load_root_env() -> None:
    """
    Loads environment variables from the project root .env file on startup and refresh.
    Updates os.environ directly and via python-dotenv if installed.
    """
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file, override=True)
        except Exception:
            pass
        try:
            with open(env_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s_line = line.strip()
                    if s_line and not s_line.startswith("#") and "=" in s_line:
                        k, v = s_line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        os.environ[k] = v
        except Exception as ex:
            print(f"[config] Warning loading .env directly: {ex}")


# Load root .env immediately on startup
load_root_env()

# Tool Paths Configuration Storage File
TOOL_PATHS_FILE: Path = (APP_DATA_DIR / "tool_paths.json").resolve()
LEGACY_TOOL_PATHS_FILE: Path = (BASE_DIR / "cases" / "tool_paths.json").resolve()
_CUSTOM_TOOL_PATHS: Dict[str, str] = {}


def _load_persisted_tool_paths() -> None:
    global _CUSTOM_TOOL_PATHS
    for fp in [TOOL_PATHS_FILE, LEGACY_TOOL_PATHS_FILE]:
        if fp.exists():
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    _CUSTOM_TOOL_PATHS = json.load(f)
                    return
            except Exception as ex:
                print(f"[config] Warning loading tool_paths.json from {fp}: {ex}")
                _CUSTOM_TOOL_PATHS = {}


_load_persisted_tool_paths()


def _get_path_setting(env_var: str, fallback_relative: str) -> Path:
    """
    Resolve path priority:
      1. UI-persisted tool_paths.json
      2. Environment variable
      3. Fallback relative to BASE_DIR
    """
    _load_persisted_tool_paths()
    keys_to_check = [env_var]

    for k in keys_to_check:
        if k in _CUSTOM_TOOL_PATHS and _CUSTOM_TOOL_PATHS[k]:
            custom_val = Path(_CUSTOM_TOOL_PATHS[k])
            return custom_val.resolve() if custom_val.is_absolute() else (BASE_DIR / custom_val).resolve()

    for k in keys_to_check:
        env_val = os.getenv(k)
        if env_val:
            p = Path(env_val.strip())
            return p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()

    return (BASE_DIR / fallback_relative).resolve()


# Core filesystem locations
CASES_DIR: Path = _get_path_setting("WFT_CASES_DIR", "cases")
RULES_DIR: Path = (BUNDLE_DIR / "rules").resolve() if (BUNDLE_DIR / "rules").exists() else _get_path_setting("WFT_RULES_DIR", "rules")
DEFAULT_YARA_FILE: Path = (RULES_DIR / "default_malware.yar").resolve()

# Custom case locations storage file (persisted in BASE_DIR so CASES_DIR is never forcibly created)
CUSTOM_LOCATIONS_FILE: Path = (APP_DATA_DIR / "custom_locations.json").resolve()
LEGACY_LOCATIONS_FILE: Path = (BASE_DIR / "custom_locations.json").resolve()
_CUSTOM_CASE_DIRS: Dict[str, str] = {}


def _load_custom_case_dirs() -> None:
    global _CUSTOM_CASE_DIRS
    changed = False

    raw_cases: Dict[str, str] = {}

    # 1. Primary storage: BASE_DIR / custom_locations.json
    if CUSTOM_LOCATIONS_FILE.exists():
        try:
            with open(CUSTOM_LOCATIONS_FILE, "r", encoding="utf-8") as f:
                raw_cases = json.load(f)
        except Exception:
            raw_cases = {}

    # 2. Legacy fallback check: CASES_DIR / custom_locations.json (preserve existing entries)
    legacy_loc_file = (CASES_DIR / "custom_locations.json").resolve()
    if legacy_loc_file != CUSTOM_LOCATIONS_FILE and legacy_loc_file.exists():
        try:
            with open(legacy_loc_file, "r", encoding="utf-8") as f:
                legacy_dict = json.load(f)
            for k, v in legacy_dict.items():
                if k not in raw_cases:
                    raw_cases[k] = v
        except Exception:
            pass

    # 3. Filter out any entries whose directories no longer exist on disk
    pruned_cases: Dict[str, str] = {}
    for k, v in raw_cases.items():
        if isinstance(v, str) and v.strip() and Path(v).is_dir():
            pruned_cases[k] = str(Path(v).resolve())
        else:
            changed = True

    _CUSTOM_CASE_DIRS = pruned_cases

    # 4. Auto-discover cases in common sibling/external directories (e.g., Desktop/cases)
    desktop_cases = Path.home() / "Desktop" / "cases"
    if desktop_cases.is_dir():
        for candidate in desktop_cases.iterdir():
            if candidate.is_dir() and (candidate / "case.duckdb").exists():
                cid = candidate.name
                if cid not in _CUSTOM_CASE_DIRS:
                    _CUSTOM_CASE_DIRS[cid] = str(candidate.resolve())
                    changed = True

    if changed:
        try:
            CUSTOM_LOCATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CUSTOM_LOCATIONS_FILE, "w", encoding="utf-8") as f:
                json.dump(_CUSTOM_CASE_DIRS, f, indent=2)
        except Exception as ex:
            print(f"[config] Warning auto-persisting custom_locations.json: {ex}")


def register_case_dir(case_id: str, custom_dir: Union[str, Path]) -> Path:
    """
    Register and persist custom storage folder for a case.
    Ensures that if the user selects a custom folder, no redundant phantom case folder
    is created in the WFT cases directory.
    """
    global _CUSTOM_CASE_DIRS
    import shutil
    clean_cid = (case_id or "").strip()

    _load_custom_case_dirs()
    resolved_p = Path(custom_dir).resolve()
    resolved_p.mkdir(parents=True, exist_ok=True)

    _CUSTOM_CASE_DIRS[clean_cid] = str(resolved_p)
    folder_name = resolved_p.name
    if folder_name.lower() != clean_cid.lower():
        _CUSTOM_CASE_DIRS[folder_name] = str(resolved_p)

    try:
        CUSTOM_LOCATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CUSTOM_LOCATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(_CUSTOM_CASE_DIRS, f, indent=2)
    except Exception as ex:
        print(f"[config] Warning saving custom_locations.json: {ex}")

    try:
        from backend.db.engine import DuckDBManager
        DuckDBManager.close_connection(clean_cid)
    except Exception:
        pass

    # Remove any redundant empty phantom folder in CASES_DIR for this case
    try:
        phantom_p = (CASES_DIR / clean_cid).resolve()
        if phantom_p != resolved_p and phantom_p.exists() and phantom_p.is_dir():
            if not (phantom_p / "case.duckdb").exists():
                shutil.rmtree(phantom_p, ignore_errors=True)
        phantom_folder = (CASES_DIR / folder_name).resolve()
        if phantom_folder != resolved_p and phantom_folder.exists() and phantom_folder.is_dir():
            if not (phantom_folder / "case.duckdb").exists():
                shutil.rmtree(phantom_folder, ignore_errors=True)
    except Exception:
        pass

    return resolved_p


def unregister_case_dir(case_id: str) -> None:
    """
    Remove case_id from registered custom locations and persist to custom_locations.json.
    """
    global _CUSTOM_CASE_DIRS
    _load_custom_case_dirs()
    changed = False
    clean_cid = (case_id or "").strip().lower()

    keys_to_del = [k for k in _CUSTOM_CASE_DIRS if k.strip().lower() == clean_cid]
    for k in keys_to_del:
        del _CUSTOM_CASE_DIRS[k]
        changed = True

    if CUSTOM_LOCATIONS_FILE.exists():
        try:
            with open(CUSTOM_LOCATIONS_FILE, "r", encoding="utf-8") as f:
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
            CUSTOM_LOCATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CUSTOM_LOCATIONS_FILE, "w", encoding="utf-8") as f:
                json.dump(_CUSTOM_CASE_DIRS, f, indent=2)
        except Exception as ex:
            print(f"[config] Warning updating custom_locations.json on unregister: {ex}")


def get_registered_custom_cases() -> Dict[str, str]:
    """
    Return dictionary mapping case_id -> custom directory path.
    """
    _load_custom_case_dirs()
    return dict(_CUSTOM_CASE_DIRS)


def get_case_dir(case_id: str, create_if_missing: bool = False) -> Path:
    """
    Resolve and return directory path for a given case_id.
    Checks registered custom locations first (exact, case-insensitive, and folder-name matches),
    falling back to CASES_DIR / case_id only when no custom directory is specified.
    Only creates the folder on disk when create_if_missing is True.
    """
    _load_custom_case_dirs()
    cid_clean = (case_id or "").strip()
    cid_lower = cid_clean.lower()

    # 1. Exact match in registered custom locations
    if cid_clean in _CUSTOM_CASE_DIRS:
        custom_dir = Path(_CUSTOM_CASE_DIRS[cid_clean]).resolve()
        if custom_dir.is_dir() or create_if_missing:
            if create_if_missing:
                custom_dir.mkdir(parents=True, exist_ok=True)
            return custom_dir

    # 2. Case-insensitive match in registered custom locations
    for k, v in _CUSTOM_CASE_DIRS.items():
        if k.strip().lower() == cid_lower:
            custom_dir = Path(v).resolve()
            if custom_dir.is_dir() or create_if_missing:
                if create_if_missing:
                    custom_dir.mkdir(parents=True, exist_ok=True)
                return custom_dir

    # 3. Match by folder name
    for k, v in _CUSTOM_CASE_DIRS.items():
        p = Path(v).resolve()
        if p.name.lower() == cid_lower:
            if p.is_dir() or create_if_missing:
                if create_if_missing:
                    p.mkdir(parents=True, exist_ok=True)
                return p

    # 4. Check external desktop cases
    desktop_case = Path.home() / "Desktop" / "cases" / cid_clean
    if (desktop_case / "case.duckdb").exists():
        register_case_dir(cid_clean, desktop_case)
        return desktop_case.resolve()

    # 5. Default fallback to CASES_DIR / case_id
    case_dir = (CASES_DIR / cid_clean).resolve()
    if create_if_missing:
        case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


# Server settings
API_HOST: str = os.getenv("WFT_HOST", "127.0.0.1")
API_PORT: int = int(os.getenv("WFT_PORT", "8765"))


def get_ez_tools_dirs() -> List[Path]:
    """
    Return ordered list of directories where Eric Zimmerman tools may reside.
    """
    configured = _get_path_setting("WFT_EZTOOLS_DIR", "EZTools")
    candidates = [
        configured,
        (BASE_DIR / "EZTools").resolve(),
        (BASE_DIR / "tools" / "ez_tools").resolve(),
    ]
    unique: List[Path] = []
    for c in candidates:
        if c not in unique:
            unique.append(c)
    return unique


def get_regripper_dirs() -> List[Path]:
    """
    Return ordered list of directories where RegRipper tools reside.
    """
    configured = _get_path_setting("WFT_REGRIPPER_DIR", "RegRipper4.0")
    candidates = [
        configured,
        (BASE_DIR / "RegRipper4.0").resolve(),
        (BASE_DIR / "tools" / "regripper").resolve(),
        (BASE_DIR / "RegRipper").resolve(),
    ]
    unique: List[Path] = []
    for c in candidates:
        if c not in unique:
            unique.append(c)
    return unique


# ---------------------------------------------------------------------------
# Eric Zimmerman CLI Tools Specification & Environment Key Mappings
# ---------------------------------------------------------------------------
EZ_BINARIES_SPEC: List[Dict[str, str]] = [
    {
        "key": "ez_rla",
        "env_var": "WFT_EZ_RLA_EXE",
        "binary": "rla.exe",
        "name": "rla.exe (Registry Transaction Replay)",
        "description": "Replays uncommitted dirty registry transaction logs (.LOG1/.LOG2)",
    },
    {
        "key": "ez_pecmd",
        "env_var": "WFT_EZ_PECMD_EXE",
        "binary": "PECmd.exe",
        "name": "PECmd.exe (Prefetch Parser)",
        "description": "Parses Windows Prefetch files (.pf) for program execution artifacts",
    },
    {
        "key": "ez_mftecmd",
        "env_var": "WFT_EZ_MFTECMD_EXE",
        "binary": "MFTECmd.exe",
        "name": "MFTECmd.exe ($MFT & $J)",
        "description": "Parses NTFS $MFT, $J (USN Journal), and $LogFile file system metadata",
    },
    {
        "key": "ez_evtxecmd",
        "env_var": "WFT_EZ_EVTXECMD_EXE",
        "binary": "EvtxECmd.exe",
        "name": "EvtxECmd.exe (Event Logs)",
        "description": "Parses Windows EVTX event logs with event map definitions",
    },
    {
        "key": "ez_recmd",
        "env_var": "WFT_EZ_RECMD_EXE",
        "binary": "RECmd.exe",
        "name": "RECmd.exe (Registry Batch)",
        "description": "Batch extracts key/value registry artifacts using RECmd batch scripts",
    },
    {
        "key": "ez_lecmd",
        "env_var": "WFT_EZ_LECMD_EXE",
        "binary": "LECmd.exe",
        "name": "LECmd.exe (LNK Shortcuts)",
        "description": "Parses Windows Shell LNK shortcut files for target paths and serials",
    },
    {
        "key": "ez_jlecmd",
        "env_var": "WFT_EZ_JLECMD_EXE",
        "binary": "JLECmd.exe",
        "name": "JLECmd.exe (Jump Lists)",
        "description": "Parses AutomaticDestinations and CustomDestinations Jump Lists",
    },
    {
        "key": "ez_amcache",
        "env_var": "WFT_EZ_AMCACHE_EXE",
        "binary": "AmcacheParser.exe",
        "name": "AmcacheParser.exe (Amcache)",
        "description": "Parses Amcache.hve for SHA-1 hashes and unassociated executable entries",
    },
    {
        "key": "ez_shimcache",
        "env_var": "WFT_EZ_SHIMCACHE_EXE",
        "binary": "AppCompatCacheParser.exe",
        "name": "AppCompatCacheParser.exe (Shimcache)",
        "description": "Parses Application Compatibility Cache from SYSTEM hive",
    },
    {
        "key": "ez_sbecmd",
        "env_var": "WFT_EZ_SBECMD_EXE",
        "binary": "SBECmd.exe",
        "name": "SBECmd.exe (ShellBags)",
        "description": "Parses ShellBags for folder access history across NTUSER.DAT & UsrClass.dat",
    },
    {
        "key": "ez_srumecmd",
        "env_var": "WFT_EZ_SRUMECMD_EXE",
        "binary": "SrumECmd.exe",
        "name": "SrumECmd.exe (SRUM)",
        "description": "Parses System Resource Usage Monitor (SRUDB.dat) database",
    },
    {
        "key": "ez_wxtcmd",
        "env_var": "WFT_EZ_WXTCMD_EXE",
        "binary": "WxTCmd.exe",
        "name": "WxTCmd.exe (Windows Timeline)",
        "description": "Parses Windows 10/11 Timeline (ActivitiesCache.db) database",
    },
    {
        "key": "ez_sqlecmd",
        "env_var": "WFT_EZ_SQLECMD_EXE",
        "binary": "SQLECmd.exe",
        "name": "SQLECmd.exe (SQLite Extractor)",
        "description": "Parses SQLite databases with pre-built maps for forensics",
    },
    {
        "key": "ez_rbcmd",
        "env_var": "WFT_EZ_RBCMD_EXE",
        "binary": "RBCmd.exe",
        "name": "RBCmd.exe (Recycle Bin)",
        "description": "Parses $Recycle.Bin $I index and metadata files",
    },
    {
        "key": "ez_recentfilecache",
        "env_var": "WFT_EZ_RECENTFILECACHE_EXE",
        "binary": "RecentFileCacheParser.exe",
        "name": "RecentFileCacheParser.exe (RecentFileCache)",
        "description": "Parses RecentFileCache.bcf from legacy Windows systems",
    },
]

EZ_BINARY_TO_ENV: Dict[str, str] = {
    item["binary"].lower(): item["env_var"] for item in EZ_BINARIES_SPEC
}

# Map short UI keys, filenames, and environment variables to canonical env variable names
KEY_TO_ENV_MAP: Dict[str, str] = {
    "ez_tools": "WFT_EZTOOLS_DIR",
    "regripper": "WFT_REGRIPPER_EXE",
    "hindsight": "WFT_HINDSIGHT_EXE",
    "stinger": "WFT_STINGER_EXE",
    "rip.exe": "WFT_REGRIPPER_EXE",
    "hindsight.exe": "WFT_HINDSIGHT_EXE",
    "stinger.exe": "WFT_STINGER_EXE",
    "stinger32.exe": "WFT_STINGER_EXE",
    "stinger64.exe": "WFT_STINGER_EXE",
}
for _item in EZ_BINARIES_SPEC:
    KEY_TO_ENV_MAP[_item["key"]] = _item["env_var"]
    KEY_TO_ENV_MAP[_item["binary"].lower()] = _item["env_var"]
    KEY_TO_ENV_MAP[_item["env_var"].lower()] = _item["env_var"]
    KEY_TO_ENV_MAP[_item["env_var"]] = _item["env_var"]


def find_regripper_binary(exe_name: str = "rip.exe") -> Path:
    """
    Search for RegRipper CLI binary (rip.exe).
    Priority 1: WFT_REGRIPPER_EXE override in tool_paths.json or os.environ.
    Priority 2: Recursive search in get_regripper_dirs().
    Priority 3: System PATH search.
    """
    _load_persisted_tool_paths()
    custom_val = (
        _CUSTOM_TOOL_PATHS.get("WFT_REGRIPPER_EXE")
        or os.getenv("WFT_REGRIPPER_EXE")
    )
    if custom_val and custom_val.strip():
        p = Path(custom_val.strip())
        resolved = p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
        if resolved.is_file():
            return resolved

    normalized_name = exe_name.strip()
    if not normalized_name.lower().endswith(".exe"):
        normalized_name += ".exe"
    target_lower = normalized_name.lower()

    search_dirs = get_regripper_dirs()
    for d in search_dirs:
        if d.is_dir():
            for p in d.rglob("*"):
                if p.is_file() and p.name.lower() == target_lower:
                    return p.resolve()

    rip_direct = (BASE_DIR / "RegRipper4.0" / "rip.exe").resolve()
    if rip_direct.is_file():
        return rip_direct

    which_rip = shutil.which("rip.exe") or shutil.which("rip")
    if which_rip:
        p = Path(which_rip).resolve()
        if p.is_file():
            return p

    raise FileNotFoundError(f"RegRipper binary '{exe_name}' not found in {[str(p) for p in search_dirs]}")


def find_ez_binary(exe_name: str) -> Path:
    """
    Search for an Eric Zimmerman executable using 3-tier resolution:
      Priority 1: Individual .env override key (e.g. os.environ.get("WFT_EZ_PECMD_EXE"))
                  or custom tool path persisted in tool_paths.json.
      Priority 2: Recursive search inside WFT_EZTOOLS_DIR, tools/ez_tools/, and EZTools/.
      Priority 3: System PATH search via shutil.which(exe_name).
    Raises FileNotFoundError if binary cannot be found across all 3 tiers.
    """
    normalized_name = exe_name.strip()
    if not normalized_name.lower().endswith(".exe"):
        normalized_name += ".exe"
    target_lower = normalized_name.lower()

    _load_persisted_tool_paths()

    # Priority 1: Check individual .env / custom setting override
    env_var_key = EZ_BINARY_TO_ENV.get(target_lower)
    if env_var_key:
        custom_override = (
            _CUSTOM_TOOL_PATHS.get(env_var_key)
            or os.getenv(env_var_key)
        )
        if custom_override and custom_override.strip():
            candidate = Path(custom_override.strip())
            resolved = candidate.resolve() if candidate.is_absolute() else (BASE_DIR / candidate).resolve()
            if resolved.is_file():
                return resolved

    # Priority 2: Recursive search in EZ tools directories (WFT_EZTOOLS_DIR, tools/ez_tools, EZTools)
    search_dirs = get_ez_tools_dirs()
    for search_root in search_dirs:
        if search_root.is_dir():
            for candidate in search_root.rglob("*.exe"):
                if candidate.name.lower() == target_lower:
                    return candidate.resolve()

    # Priority 3: System PATH search
    which_hit = shutil.which(normalized_name)
    if which_hit:
        p = Path(which_hit).resolve()
        if p.is_file():
            return p

    searched_paths = [str(p) for p in search_dirs]
    env_hint = f", individual env key: {env_var_key}" if env_var_key else ""
    raise FileNotFoundError(
        f"Eric Zimmerman tool binary '{normalized_name}' not found via individual override ({env_hint}), "
        f"search paths ({searched_paths}), or system PATH."
    )


def find_ez_file(filename: str) -> Path:
    """
    Search recursively inside EZ tools directories for a support file (such as Kroll_Batch.reb).
    Raises FileNotFoundError if file cannot be found.
    """
    target_lower = filename.strip().lower()
    search_dirs = get_ez_tools_dirs()
    for search_root in search_dirs:
        if search_root.is_dir():
            for candidate in search_root.rglob("*"):
                if candidate.is_file() and candidate.name.lower() == target_lower:
                    return candidate.resolve()

    searched_paths = [str(p) for p in search_dirs]
    raise FileNotFoundError(
        f"Support file '{filename}' not found in EZ tools search paths: {searched_paths}"
    )


def find_stinger_binary() -> Optional[Path]:
    """
    Search for Trellix Stinger CLI binary (stinger64.exe or stinger32.exe).
    Returns resolved path or None if not found.
    """
    _load_persisted_tool_paths()
    custom_val = (
        _CUSTOM_TOOL_PATHS.get("WFT_STINGER_EXE")
        or os.getenv("WFT_STINGER_EXE")
    )
    if custom_val and custom_val.strip():
        p = Path(custom_val.strip())
        resolved = p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
        if resolved.is_file():
            return resolved

    # Common discovery candidates
    candidates = [
        BASE_DIR / "stinger64.exe",
        BASE_DIR / "stinger32.exe",
        BASE_DIR / "tools" / "stinger" / "stinger64.exe",
        BASE_DIR / "tools" / "stinger" / "stinger32.exe",
        BASE_DIR / "tools" / "stinger.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()

    which_stinger = shutil.which("stinger64.exe") or shutil.which("stinger32.exe") or shutil.which("stinger.exe")
    if which_stinger:
        p = Path(which_stinger).resolve()
        if p.is_file():
            return p

    return None


def find_hindsight_binary() -> Optional[Path]:
    """
    Search for Hindsight executable or python entry point.
    """
    _load_persisted_tool_paths()
    custom_val = (
        _CUSTOM_TOOL_PATHS.get("WFT_HINDSIGHT_EXE")
        or os.getenv("WFT_HINDSIGHT_EXE")
    )
    if custom_val and custom_val.strip():
        p = Path(custom_val.strip())
        resolved = p.resolve() if p.is_absolute() else (BASE_DIR / p).resolve()
        if resolved.is_file():
            return resolved

    candidates = [
        BASE_DIR / "hindsight-main" / "hindsight.py",
        BASE_DIR / "tools" / "hindsight.exe",
        BASE_DIR / "tools" / "hindsight" / "hindsight.exe",
        BASE_DIR / "hindsight.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()

    # Check which on PATH
    which_hindsight = shutil.which("hindsight.exe") or shutil.which("hindsight")
    if which_hindsight:
        return Path(which_hindsight).resolve()

    return None


def get_tool_paths_status() -> Dict[str, Dict[str, Any]]:
    """
    Returns the resolved path and verification status (FOUND / MISSING)
    for all master tools (EZTools, RegRipper, Hindsight, Trellix Stinger)
    and all 15 individual Eric Zimmerman CLI binaries.
    WFT_RULES_DIR and WFT_CASES_DIR are strictly excluded.
    """
    _load_persisted_tool_paths()
    result: Dict[str, Dict[str, Any]] = {}

    # 1. EZTools Master Directory
    ez_dirs = get_ez_tools_dirs()
    ez_found = False
    ez_path_str = str(ez_dirs[0])
    for d in ez_dirs:
        if d.is_dir() and any(d.glob("*.exe")):
            ez_found = True
            ez_path_str = str(d)
            break
    configured_ez = (
        _CUSTOM_TOOL_PATHS.get("WFT_EZTOOLS_DIR")
        or os.getenv("WFT_EZTOOLS_DIR", "./EZTools")
    )
    result["ez_tools"] = {
        "name": "Eric Zimmerman Tools Directory",
        "env_var": "WFT_EZTOOLS_DIR",
        "configured_path": configured_ez,
        "resolved_path": ez_path_str if ez_found else None,
        "path": configured_ez,
        "status": "FOUND" if ez_found else "MISSING",
        "description": "Master folder containing Eric Zimmerman CLI forensic tools (.NET 6/9)",
        "category": "main",
    }

    # 2. RegRipper
    rr_binary: Optional[Path] = None
    try:
        rr_binary = find_regripper_binary()
    except Exception:
        pass
    configured_rr = (
        _CUSTOM_TOOL_PATHS.get("WFT_REGRIPPER_EXE")
        or os.getenv("WFT_REGRIPPER_EXE")
        or _CUSTOM_TOOL_PATHS.get("WFT_REGRIPPER_DIR")
        or os.getenv("WFT_REGRIPPER_DIR", "./RegRipper4.0")
    )
    result["regripper"] = {
        "name": "RegRipper 4.0",
        "env_var": "WFT_REGRIPPER_EXE",
        "configured_path": configured_rr,
        "resolved_path": str(rr_binary) if rr_binary else None,
        "path": configured_rr,
        "status": "FOUND" if rr_binary is not None else "MISSING",
        "description": "Registry hive fast analysis engine (rip.exe)",
        "category": "main",
    }

    # 3. Hindsight (pyhindsight & hindsight.exe)
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
        _CUSTOM_TOOL_PATHS.get("WFT_HINDSIGHT_EXE")
        or os.getenv("WFT_HINDSIGHT_EXE", "./hindsight-main/hindsight.py")
    )
    result["hindsight"] = {
        "name": "Hindsight (pyhindsight)",
        "env_var": "WFT_HINDSIGHT_EXE",
        "configured_path": configured_hs,
        "resolved_path": str(hs_binary) if hs_binary else ("pyhindsight (Python module)" if pyhindsight_installed else None),
        "path": configured_hs,
        "status": hs_status,
        "version": hindsight_ver,
        "description": "Chromium browser forensic extraction engine",
        "category": "main",
    }

    # 4. Trellix Stinger
    stinger_bin = find_stinger_binary()
    stinger_status = "FOUND" if (stinger_bin and stinger_bin.is_file()) else "HEURISTICS READY"
    configured_stinger = (
        _CUSTOM_TOOL_PATHS.get("WFT_STINGER_EXE")
        or os.getenv("WFT_STINGER_EXE", "./stinger32.exe")
    )
    result["stinger"] = {
        "name": "Trellix Stinger / PE Threat Scanner",
        "env_var": "WFT_STINGER_EXE",
        "configured_path": configured_stinger,
        "resolved_path": str(stinger_bin) if stinger_bin else "Built-in PE Threat & Heuristics Analyzer",
        "path": configured_stinger,
        "status": stinger_status,
        "description": "Trellix Stinger standalone AV scanner + PE heuristic threat engine",
        "category": "main",
    }

    # 5. Individual Eric Zimmerman CLI Binaries
    for item in EZ_BINARIES_SPEC:
        k = item["key"]
        env_var = item["env_var"]
        bin_name = item["binary"]
        resolved_bin: Optional[Path] = None
        try:
            resolved_bin = find_ez_binary(bin_name)
        except Exception:
            pass

        configured_val = (
            _CUSTOM_TOOL_PATHS.get(env_var)
            or os.getenv(env_var, "")
        )
        result[k] = {
            "name": item["name"],
            "env_var": env_var,
            "binary": bin_name,
            "configured_path": configured_val,
            "resolved_path": str(resolved_bin) if resolved_bin else None,
            "path": configured_val or (str(resolved_bin) if resolved_bin else ""),
            "status": "FOUND" if resolved_bin is not None else "MISSING",
            "description": item["description"],
            "category": "individual_ez",
        }

    return result


def reload_config_in_memory() -> None:
    """
    Reloads all configuration variables in memory from the root .env and persisted paths.
    """
    global CASES_DIR, RULES_DIR, DEFAULT_YARA_FILE, CUSTOM_LOCATIONS_FILE, API_HOST, API_PORT
    load_root_env()
    _load_persisted_tool_paths()
    CASES_DIR = _get_path_setting("WFT_CASES_DIR", "cases")
    RULES_DIR = _get_path_setting("WFT_RULES_DIR", "rules")
    DEFAULT_YARA_FILE = (RULES_DIR / "default_malware.yar").resolve()
    CUSTOM_LOCATIONS_FILE = (APP_DATA_DIR / "custom_locations.json").resolve()
    API_HOST = os.getenv("WFT_HOST", "127.0.0.1")
    API_PORT = int(os.getenv("WFT_PORT", "8765"))


def save_tool_paths(new_paths: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    """
    Persist custom tool paths:
    1. Writes all updated keys/paths directly into root .env file without duplicate lines.
    2. Updates os.environ for every key in-place.
    3. Updates cases/tool_paths.json.
    4. Reloads backend.config variables in memory.
    Returns the refreshed get_tool_paths_status().
    """
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
        if v_clean:
            _CUSTOM_TOOL_PATHS[canonical_env] = v_clean
            _CUSTOM_TOOL_PATHS[k_clean] = v_clean
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
            _CUSTOM_TOOL_PATHS.pop(k_clean, None)
            os.environ.pop(canonical_env, None)
            clean_updates[canonical_env] = ""

    # Save to cases/tool_paths.json
    TOOL_PATHS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(TOOL_PATHS_FILE, "w", encoding="utf-8") as f:
            json.dump(_CUSTOM_TOOL_PATHS, f, indent=2)
    except Exception as ex:
        print(f"[config] Warning writing tool_paths.json: {ex}")

    # Idempotently update root .env file without duplicating lines
    env_file = BASE_DIR / ".env"
    existing_lines: List[str] = []
    if env_file.exists():
        try:
            existing_lines = env_file.read_text(encoding="utf-8").splitlines()
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
                # Any duplicate lines of this key in .env are dropped
                continue
            elif k in seen_keys:
                # Pre-existing duplicate line of another key is dropped
                continue
            else:
                seen_keys.add(k)
        new_lines.append(line)

    # Append any brand new keys that were not already in .env
    for k, v in clean_updates.items():
        if k not in seen_keys and v:
            new_lines.append(f"{k}={v}")
            seen_keys.add(k)

    try:
        env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception as ex:
        print(f"[config] Warning writing .env: {ex}")

    # Reload variables in-memory
    reload_config_in_memory()
    return get_tool_paths_status()


# ---------------------------------------------------------------------------
# Ultra-Fast 3-Stage Full-Disk Forensic Tool Scanner (Find-AllForensicToolsFast)
# ---------------------------------------------------------------------------
ALL_18_FORENSIC_TOOLS: List[str] = [
    "rla.exe", "PECmd.exe", "MFTECmd.exe", "EvtxECmd.exe", "RECmd.exe",
    "LECmd.exe", "JLECmd.exe", "AmcacheParser.exe", "AppCompatCacheParser.exe",
    "SBECmd.exe", "SrumECmd.exe", "WxTCmd.exe", "SQLECmd.exe", "RBCmd.exe",
    "RecentFileCacheParser.exe", "rip.exe", "hindsight.exe", "stinger64.exe"
]

TOOL_EXE_TO_ENV_VAR: Dict[str, str] = {
    "rla.exe": "WFT_EZ_RLA_EXE",
    "pecmd.exe": "WFT_EZ_PECMD_EXE",
    "mftecmd.exe": "WFT_EZ_MFTECMD_EXE",
    "evtxecmd.exe": "WFT_EZ_EVTXECMD_EXE",
    "recmd.exe": "WFT_EZ_RECMD_EXE",
    "lecmd.exe": "WFT_EZ_LECMD_EXE",
    "jlecmd.exe": "WFT_EZ_JLECMD_EXE",
    "amcacheparser.exe": "WFT_EZ_AMCACHE_EXE",
    "appcompatcacheparser.exe": "WFT_EZ_SHIMCACHE_EXE",
    "sbecmd.exe": "WFT_EZ_SBECMD_EXE",
    "srumecmd.exe": "WFT_EZ_SRUMECMD_EXE",
    "wxtcmd.exe": "WFT_EZ_WXTCMD_EXE",
    "sqlecmd.exe": "WFT_EZ_SQLECMD_EXE",
    "rbcmd.exe": "WFT_EZ_RBCMD_EXE",
    "recentfilecacheparser.exe": "WFT_EZ_RECENTFILECACHE_EXE",
    "rip.exe": "WFT_REGRIPPER_EXE",
    "hindsight.exe": "WFT_HINDSIGHT_EXE",
    "hindsight.py": "WFT_HINDSIGHT_EXE",
    "stinger64.exe": "WFT_STINGER_EXE",
    "stinger32.exe": "WFT_STINGER_EXE",
    "stinger.exe": "WFT_STINGER_EXE",
}


def find_all_forensic_tools_fast(
    project_root: Optional[Path] = None,
    target_exes: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Ultra-fast 3-stage full-disk scanner (Find-AllForensicToolsFast):
    1. Stage 1: Checks System PATH, project local folders (tools, EZTools, RegRipper4.0, hindsight-main, root),
       and standard Python Scripts folders in ~5ms.
    2. Stage 2: Queries the live Windows Search Index (Windows.db/Windows.edb via ADODB CollatorDSO COM query) in ~20ms.
    3. Stage 3: Single-pass .NET/os.scandir tree walker across all ready fixed drives (skipping OS noise directories
       like C:\\Windows, $Recycle.Bin, System Volume Information, node_modules, .git) in ~1s.
    Returns: Mapping of canonical exe name -> resolved absolute file path.
    """
    if project_root is None:
        project_root = BASE_DIR
    if target_exes is None:
        target_exes = list(ALL_18_FORENSIC_TOOLS)

    t0 = time.perf_counter()
    results: Dict[str, str] = {}
    remaining: Dict[str, str] = {t.lower(): t for t in target_exes}

    # Discover python scripts directories for tools like hindsight.exe
    python_script_dirs: List[Path] = []
    try:
        import sysconfig
        s_path = sysconfig.get_path("scripts")
        if s_path and os.path.isdir(s_path):
            python_script_dirs.append(Path(s_path).resolve())
    except Exception as ex:
        print(f"[scanner] Note checking sysconfig scripts: {ex}")

    try:
        import site
        u_site = site.getusersitepackages()
        if u_site:
            u_scripts = Path(u_site).parent / "Scripts"
            if u_scripts.is_dir():
                python_script_dirs.append(u_scripts.resolve())
    except Exception as ex:
        print(f"[scanner] Note checking site user scripts: {ex}")

    # Standard Windows Python AppData paths
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

    # -------------------------------------------------------------------------
    # STAGE 1: Check System PATH & Project Priority Directories (~5ms)
    # -------------------------------------------------------------------------
    local_priority_dirs: List[Path] = [
        (project_root / "tools").resolve(),
        (project_root / "EZTools").resolve(),
        (project_root / "RegRipper4.0").resolve(),
        (project_root / "RegRipper").resolve(),
        (project_root / "hindsight-main").resolve(),
        project_root.resolve(),
    ] + python_script_dirs

    existing_priority_dirs = [d for d in local_priority_dirs if d.is_dir()]

    # 1.1 Check system PATH
    for flow, orig in list(remaining.items()):
        which_path = shutil.which(orig)
        if which_path and os.path.isfile(which_path):
            results[orig] = str(Path(which_path).resolve())
            del remaining[flow]

    # 1.2 Check priority local folders
    for pdir in existing_priority_dirs:
        if not remaining:
            break
        try:
            for root, dirs, files in os.walk(str(pdir)):
                for f in files:
                    flow = f.lower()
                    if flow in remaining:
                        orig = remaining[flow]
                        resolved = str((Path(root) / f).resolve())
                        results[orig] = resolved
                        del remaining[flow]
                        if not remaining:
                            break
                if not remaining:
                    break
        except Exception as ex:
            print(f"[scanner] Notice inspecting priority dir {pdir}: {ex}")

    if not remaining:
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"[scanner] Stage 1 priority folder scan completed in {elapsed:.1f} ms. Found all {len(results)} tools.")
        return results

    # -------------------------------------------------------------------------
    # STAGE 2: Query Windows Search Index (~20ms)
    # -------------------------------------------------------------------------
    t2_start = time.perf_counter()
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
                if flow in remaining and os.path.isfile(fpath):
                    orig = remaining[flow]
                    results[orig] = str(Path(fpath).resolve())
                    del remaining[flow]
                rs.MoveNext()
            conn.Close()
        except Exception as ex:
            print(f"[scanner] Stage 2 Windows Search query notice: {ex}")

    if not remaining:
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"[scanner] Stage 2 Windows Search completed in {elapsed:.1f} ms. Found all {len(results)} tools.")
        return results

    # -------------------------------------------------------------------------
    # STAGE 3: Single-Pass Parallel/Optimized Tree Walker Across Fixed Drives (~1s)
    # -------------------------------------------------------------------------
    t3_start = time.perf_counter()
    skip_dirs: Set[str] = {
        "windows", "$recycle.bin", "system volume information", "recovery",
        "node_modules", ".git", ".venv", "__pycache__", "package cache"
    }

    # Discover fixed ready drives on Windows (excluding Google Drive virtual drive)
    fixed_drives: List[str] = []
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            bitmask = kernel32.GetLogicalDrives()
            for letter_code in range(26):
                if bitmask & (1 << letter_code):
                    drive_letter = f"{chr(65 + letter_code)}:\\"
                    drive_type = kernel32.GetDriveTypeW(drive_letter)
                    # DRIVE_FIXED is 3
                    if drive_type == 3:
                        vol_buf = ctypes.create_unicode_buffer(261)
                        fs_buf = ctypes.create_unicode_buffer(261)
                        res = kernel32.GetVolumeInformationW(
                            drive_letter, vol_buf, 261, None, None, None, fs_buf, 261
                        )
                        vol_name = vol_buf.value.lower()
                        if "google drive" not in vol_name:
                            fixed_drives.append(drive_letter)
        except Exception as ex:
            print(f"[scanner] Notice discovering fixed drives via win32: {ex}")
            fixed_drives = ["C:\\"]
    else:
        fixed_drives = ["/"]

    for drive_root in fixed_drives:
        if not remaining:
            break
        stack = [drive_root]
        while stack and remaining:
            current_dir = stack.pop()
            try:
                with os.scandir(current_dir) as it:
                    for entry in it:
                        try:
                            if entry.is_file(follow_symlinks=False):
                                flow = entry.name.lower()
                                if flow in remaining:
                                    orig = remaining[flow]
                                    results[orig] = str(Path(entry.path).resolve())
                                    del remaining[flow]
                                    if not remaining:
                                        break
                            elif entry.is_dir(follow_symlinks=False):
                                dname_low = entry.name.lower()
                                if dname_low not in skip_dirs:
                                    stack.append(entry.path)
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

    elapsed = (time.perf_counter() - t0) * 1000
    print(f"[scanner] Full disk scan completed in {elapsed:.1f} ms. Found {len(results)}/{len(target_exes)} tools.")
    return results


def scan_and_sync_tool_paths(apply_to_env: bool = True) -> Dict[str, Any]:
    """
    Executes the ultra-fast 3-stage full-disk scanner, maps all discovered binaries
    to their canonical environment variables, writes to .env in-place if apply_to_env is True,
    and returns refreshed tool status and timing metrics.
    """
    t0 = time.perf_counter()
    discovered = find_all_forensic_tools_fast()
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

    # Fallbacks for Trellix Stinger if 64-bit wasn't found but 32-bit exists
    if "WFT_STINGER_EXE" not in paths_to_save:
        for stinger_cand in ["stinger64.exe", "stinger32.exe", "stinger.exe"]:
            p = BASE_DIR / stinger_cand
            if p.is_file():
                paths_to_save["WFT_STINGER_EXE"] = str(p.resolve())
                break

    # Fallbacks for Hindsight if executable wasn't found but script exists
    if "WFT_HINDSIGHT_EXE" not in paths_to_save:
        hs_script = BASE_DIR / "hindsight-main" / "hindsight.py"
        if hs_script.is_file():
            paths_to_save["WFT_HINDSIGHT_EXE"] = str(hs_script.resolve())

    # Resolve master WFT_EZTOOLS_DIR
    project_ez = (BASE_DIR / "EZTools").resolve()
    if project_ez.is_dir():
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
    """
    Get the full resolved path to case.duckdb for a given case_id.
    """
    return (get_case_dir(case_id) / "case.duckdb").resolve()


def get_case_staging_dir(case_id: str) -> Path:
    """
    Get the staging directory where raw evidence artifacts are placed.
    """
    staging_dir = (get_case_dir(case_id) / "staging").resolve()
    staging_dir.mkdir(parents=True, exist_ok=True)
    return staging_dir


def get_case_csv_out_dir(case_id: str) -> Path:
    """
    Get the output directory where EZ tools and parsers output CSV files.
    """
    csv_out_dir = (get_case_dir(case_id) / "csv_out").resolve()
    csv_out_dir.mkdir(parents=True, exist_ok=True)
    return csv_out_dir


def get_case_log_file(case_id: str) -> Path:
    """
    Get the processing.log file path for audit logs.
    """
    return (get_case_dir(case_id) / "processing.log").resolve()
