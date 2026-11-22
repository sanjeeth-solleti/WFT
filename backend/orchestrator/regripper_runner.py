"""
Windows Forensic Toolkit (WFT) RegRipper 4.0 Orchestrator & Parser Runner
Executes rip.exe in parallel across Windows Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY,
NTUSER, USRCLASS, AMCACHE, including multi-user & VSS snapshots), parses plugin reports
(including exact 40-dash delimiters and headerless plugins), and batch-ingests into DuckDB raw_regripper.
"""
import csv
import hashlib
import io
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from backend.config import (
    BASE_DIR,
    find_regripper_binary,
    get_case_db_path,
    get_case_dir,
    register_case_dir,
)
from backend.db.engine import DuckDBManager

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

_RR_TRIGGER_IDS: Set[str] = {
    "regripper",
    "regripper_plugins",
    "raw_regripper",
    "registry",
    "registry_recmd",
    "os_recmd",
    "view_autoruns",
    "view_userassist",
    "view_bam_dam",
    "view_usb_devices",
    "usb_devices",
    "fs_shellbags",
    "os_shimcache",
    "os_amcache_files",
}

_RESERVED_USER_DIR_TOKENS: Set[str] = {
    "appdata",
    "local",
    "roaming",
    "locallow",
    "microsoft",
    "windows",
    "registry",
    "staging",
    "clean_hives",
    "vss",
    "system",
    "system32",
    "config",
    "usrclass",
    "amcache",
    "users",
    "documents and settings",
}

_GENERIC_HEADER_TOKENS: Set[str] = {
    "mitre",
    "ref",
    "lastwrite",
    "key",
    "value",
    "total",
    "error",
    "warning",
    "note",
    "analysis",
}


def _file_digest_key(path: Path) -> Tuple[int, str]:
    st = path.stat()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return (st.st_size, h.hexdigest())


def _ensure_core_audit_tables(cursor: Any) -> None:
    cursor.execute("CREATE SEQUENCE IF NOT EXISTS seq_log_id START 1;")
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS processing_logs (
            log_id BIGINT,
            timestamp_utc TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            module_name VARCHAR,
            command_executed VARCHAR,
            exit_code INTEGER,
            rows_ingested BIGINT,
            duration_ms BIGINT,
            status VARCHAR,
            error_message VARCHAR
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS artifact_registry (
            artifact_id VARCHAR PRIMARY KEY,
            category VARCHAR NOT NULL,
            display_name VARCHAR NOT NULL,
            table_name VARCHAR NOT NULL,
            source_tool VARCHAR NOT NULL,
            row_count BIGINT DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


class RegRipperRunner:
    """
    Executes RegRipper 4.0 against staged and cleaned Windows registry hives in parallel,
    splitting individual plugin reports into structured, queryable database records.
    """

    def __init__(
        self,
        case_id: str,
        case_dir: Optional[Union[str, Path]] = None,
        log_fn: Optional[Callable[[str, str], None]] = None,
        max_workers: int = 25,
        db_manager: Any = None,
    ):
        self.case_id = str(case_id).strip()
        self.db_manager = db_manager if db_manager is not None else DuckDBManager
        resolved_dir = (
            Path(case_dir).resolve()
            if case_dir is not None
            else get_case_dir(self.case_id, create_if_missing=True).resolve()
        )
        self.case_dir = resolved_dir
        self.case_dir.mkdir(parents=True, exist_ok=True)

        if (
            self.db_manager is DuckDBManager
            and get_case_dir(self.case_id).resolve() != self.case_dir
        ):
            register_case_dir(self.case_id, self.case_dir)

        self.log_fn = log_fn or self._default_log
        self.max_workers = max(1, min(25 if max_workers is None else int(max_workers), 32))
        self.regripper_out_dir = (self.case_dir / "regripper").resolve()
        self.regripper_out_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = (self.case_dir / "processing.log").resolve()
        self._plugin_catalog: Optional[Dict[str, Dict[str, str]]] = None
        self._fallback_hive_paths: Dict[str, Path] = {}
        self._catalog_lock = threading.Lock()
        self._file_log_lock = threading.Lock()

    def _default_log(self, msg: str, level: str = "INFO") -> None:
        print(f"[{level}] [RegRipperRunner] {msg}")

    def _record_processing_log(
        self,
        command_executed: str,
        exit_code: int,
        rows_ingested: int,
        duration_ms: int,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            cursor = conn.cursor()
            _ensure_core_audit_tables(cursor)
            cursor.execute(
                """
                INSERT INTO processing_logs (
                    log_id, timestamp_utc, module_name, command_executed,
                    exit_code, rows_ingested, duration_ms, status, error_message
                ) VALUES (nextval('seq_log_id'), CURRENT_TIMESTAMP, 'RegRipper', ?, ?, ?, ?, ?, ?);
                """,
                [command_executed, exit_code, rows_ingested, duration_ms, status, error_message],
            )

        line = (
            f"[RegRipper] Status={status} ExitCode={exit_code} "
            f"Rows={rows_ingested} Duration={duration_ms}ms | Cmd: {command_executed}"
        )
        if error_message:
            line += f" | Error: {error_message}"
        line += "\n"
        try:
            with self._file_log_lock:
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(line)
        except OSError:
            pass

    @staticmethod
    def _is_incompatible_v2_rip(rip_exe: Path) -> bool:
        """
        Return True ONLY if rip_exe is legacy Autopsy RegRipper v2.x lacking -a batch mode.
        Mock-safe for unit tests stubbing subprocess.run.
        """
        try:
            res = subprocess.run(
                [str(rip_exe), "-h"],
                cwd=str(rip_exe.parent),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=_NO_WINDOW,
            )
            combined = f"{res.stdout or ''}\n{res.stderr or ''}"
            if re.search(r"Rip v\.2\.", combined, re.IGNORECASE):
                return True
            if "CLI RegRipper tool" in combined and not re.search(r"(?:^|\s)-a\b", combined):
                return True
            return False
        except Exception:
            return False

    def _resolve_regripper_binary(self) -> Path:
        """Resolve a valid RegRipper v3/v4 rip.exe supporting -a with adjacent plugins/."""
        finder_mod = getattr(find_regripper_binary, "__module__", "")
        is_monkeypatched = finder_mod != "backend.config"

        try:
            cand = Path(find_regripper_binary()).resolve()
            if cand.is_file() and not self._is_incompatible_v2_rip(cand):
                return cand
        except FileNotFoundError:
            if is_monkeypatched:
                raise

        candidate_paths: List[Path] = []
        raw_exe = (os.environ.get("WFT_REGRIPPER_EXE") or "").strip().strip('"').strip("'")
        raw_dir = (os.environ.get("WFT_REGRIPPER_DIR") or "").strip().strip('"').strip("'")
        if raw_exe:
            candidate_paths.append(Path(raw_exe))
        if raw_dir:
            candidate_paths.append(Path(raw_dir) / "rip.exe")

        candidate_paths.extend(
            [
                BASE_DIR / "RegRipper4.0" / "rip.exe",
                BASE_DIR / "tools" / "regripper" / "rip.exe",
            ]
        )

        is_isolated_test = bool(os.environ.get("WFT_ENV_FILE") or os.environ.get("WFT_TOOL_PATHS_FILE"))
        if not is_isolated_test:
            candidate_paths.extend(
                [
                    Path.home() / "Downloads" / "axiom-dongle" / "RegRipper4.0-main" / "rip.exe",
                    Path.home() / "Documents" / "Tools" / "RegRipper4.0-main" / "RegRipper4.0-main" / "rip.exe",
                    Path.home() / "Documents" / "Tools" / "RegRipper4.0-main" / "rip.exe",
                ]
            )

        for p in candidate_paths:
            try:
                rp = p.resolve()
                if (
                    rp.is_file()
                    and rp.stat().st_size >= 64
                    and (rp.parent / "plugins").is_dir()
                    and any((rp.parent / "plugins").glob("*.pl"))
                    and not self._is_incompatible_v2_rip(rp)
                ):
                    return rp
            except OSError:
                continue

        raise FileNotFoundError(
            "Valid RegRipper v3/v4 binary 'rip.exe' (supporting -a with adjacent plugins/) not found."
        )

    def get_plugin_catalog(self, rip_exe: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
        """
        Loads and caches the RegRipper plugin catalog by querying `rip.exe -l -c` with cwd=rip_exe.parent.
        Thread-safe via _catalog_lock.
        """
        if self._plugin_catalog is not None:
            return self._plugin_catalog

        with self._catalog_lock:
            if self._plugin_catalog is not None:
                return self._plugin_catalog

            catalog: Dict[str, Dict[str, str]] = {}
            try:
                exe = Path(rip_exe).resolve() if rip_exe is not None else self._resolve_regripper_binary()
                cmd = [str(exe), "-l", "-c"]
                res = subprocess.run(
                    cmd,
                    cwd=str(exe.parent),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                    creationflags=_NO_WINDOW,
                )
                if res.returncode == 0 and res.stdout:
                    reader = csv.reader(io.StringIO(res.stdout))
                    next(reader, None)  # skip header
                    for row in reader:
                        if len(row) >= 6:
                            pname = row[0].strip().lower()
                            if pname:
                                catalog[pname] = {
                                    "plugin_name": row[0].strip(),
                                    "version": row[1].strip(),
                                    "hive": row[2].strip(),
                                    "mitre": row[3].strip(),
                                    "category": row[4].strip(),
                                    "description": row[5].strip(),
                                }
            except Exception as ex:
                self.log_fn(f"Notice loading RegRipper plugin catalog: {ex}", "WARNING")

            self._plugin_catalog = catalog
            return self._plugin_catalog

    def _discover_hive_targets(self) -> List[Tuple[str, str, Path, str]]:
        """
        Discover candidate registry hives in priority order:
        clean_hives -> staging/Registry -> staging/VSS -> staging.
        Returns list of (hive_type, hive_display_name, hive_path, unique_key).
        """
        targets: List[Tuple[str, str, Path, str]] = []
        seen_keys: Set[str] = set()
        fallback_paths: Dict[str, Path] = {}
        named_user_digests: Dict[Tuple[str, str], Set[Tuple[int, str]]] = {}
        clean_hives_root = (self.case_dir / "clean_hives").resolve()

        search_dirs = [
            self.case_dir / "clean_hives",
            self.case_dir / "staging" / "Registry",
            self.case_dir / "staging" / "VSS",
            self.case_dir / "staging",
        ]

        excluded_roots = {
            self.regripper_out_dir.resolve(),
            (self.case_dir / "csv_out").resolve(),
            (self.case_dir / "carved").resolve(),
            (self.case_dir / "bulk_extractor_out").resolve(),
            (self.case_dir / "hindsight_out").resolve(),
        }

        hive_specs = [
            ("SYSTEM", r"^(?:vss[_\-]?\d+_)?system$"),
            ("SOFTWARE", r"^(?:vss[_\-]?\d+_)?software$"),
            ("SAM", r"^(?:vss[_\-]?\d+_)?sam$"),
            ("SECURITY", r"^(?:vss[_\-]?\d+_)?security$"),
            ("AMCACHE", r"^(?:vss[_\-]?\d+_)?amcache\.hve$"),
            ("NTUSER", r"ntuser.*\.dat$"),
            ("USRCLASS", r"usrclass.*\.dat$"),
        ]

        bad_suffixes = (
            ".log", ".log1", ".log2", ".tm", ".blf", ".txt", ".csv",
            ".json", ".xml", ".db", ".sqlite", ".sqlite3", ".pf", ".lnk",
            ".evtx", ".mdb", ".bcf", ".exe", ".dll",
        )

        for s_dir in search_dirs:
            if not s_dir.is_dir():
                continue
            s_dir_res = s_dir.resolve()
            all_files: List[Path] = []
            for p in s_dir_res.rglob("*"):
                fn_low = p.name.lower()
                if fn_low.endswith(bad_suffixes) or "regtrans-ms" in fn_low or ".tmcontainer" in fn_low:
                    continue
                if any(re.search(pat, p.name, re.IGNORECASE) for _, pat in hive_specs) and p.is_file():
                    all_files.append(p)
            # Deeper structured paths (Users/<User>/NTUSER.DAT) sort BEFORE flat root copies
            all_files.sort(key=lambda p: (-len(p.relative_to(s_dir_res).parts), str(p).lower()))

            for fpath in all_files:
                fpath_res = fpath.resolve()
                if any(fpath_res == ex or ex in fpath_res.parents for ex in excluded_roots):
                    continue
                try:
                    if fpath_res.stat().st_size == 0:
                        continue
                except OSError:
                    continue

                fname_lower = fpath_res.name.lower()
                if (
                    fname_lower.endswith(bad_suffixes)
                    or "regtrans-ms" in fname_lower
                    or ".tmcontainer" in fname_lower
                ):
                    continue

                matched_type: Optional[str] = None
                for h_type, pattern in hive_specs:
                    if re.search(pattern, fpath_res.name, re.IGNORECASE):
                        matched_type = h_type
                        break
                if matched_type is None:
                    continue

                rel_parts = fpath_res.relative_to(self.case_dir).parts

                # Detect VSS snapshot prefix (e.g. VSS_1 -> vss1)
                vss_prefix = ""
                for pt in rel_parts[:-1]:
                    m_vss = re.match(r"(?i)^vss[_\-]?(\d+)$", pt)
                    if m_vss:
                        vss_prefix = f"vss{m_vss.group(1)}"
                        break
                if not vss_prefix:
                    m_vss_fn = re.match(r"(?i)^vss[_\-]?(\d+)_", fpath_res.name)
                    if m_vss_fn:
                        vss_prefix = f"vss{m_vss_fn.group(1)}"

                if matched_type in ("NTUSER", "USRCLASS"):
                    canonical_base = "NTUSER.DAT" if matched_type == "NTUSER" else "UsrClass.dat"
                    username = ""

                    # 1) Folder-based user identity: Users/<Username>/... or Documents and Settings/<Username>/...
                    for idx_pt, pt in enumerate(rel_parts[:-1]):
                        if pt.lower() in ("users", "documents and settings") and idx_pt + 1 < len(rel_parts) - 1:
                            cand_user = rel_parts[idx_pt + 1].strip()
                            if cand_user and cand_user.lower() not in _RESERVED_USER_DIR_TOKENS:
                                username = cand_user
                                break

                    # Also support clean_hives/<Username>/NTUSER.DAT if direct parent is a username
                    if not username and len(rel_parts) >= 2:
                        parent_token = rel_parts[-2].strip()
                        if (
                            parent_token
                            and parent_token.lower() not in _RESERVED_USER_DIR_TOKENS
                            and not re.match(r"(?i)^vss[_\-]?\d+$", parent_token)
                        ):
                            username = parent_token

                    # 2) Filename-based user identity fallback (legacy flat staging)
                    if not username:
                        fn = fpath_res.name
                        if matched_type == "NTUSER":
                            for rx in (
                                r"(?i)^(?:vss[_\-]?\d+_)?ntuser_(.+?)_ntuser\.dat$",
                                r"(?i)^(?:vss[_\-]?\d+_)?(.+?)_ntuser\.dat$",
                                r"(?i)^(?:vss[_\-]?\d+_)?ntuser_(.+?)\.dat$",
                            ):
                                m_u = re.match(rx, fn)
                                if m_u and m_u.group(1).strip().lower() not in ("ntuser", ""):
                                    username = m_u.group(1).strip()
                                    break
                        else:
                            for rx in (
                                r"(?i)^(?:vss[_\-]?\d+_)?usrclass_(.+?)_usrclass\.dat$",
                                r"(?i)^(?:vss[_\-]?\d+_)?(.+?)_usrclass\.dat$",
                                r"(?i)^(?:vss[_\-]?\d+_)?usrclass_(.+?)\.dat$",
                            ):
                                m_u = re.match(rx, fn)
                                if m_u and m_u.group(1).strip().lower() not in ("usrclass", ""):
                                    username = m_u.group(1).strip()
                                    break

                    user_slug = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", username).strip("_").lower()

                    if user_slug:
                        unique_key = f"{vss_prefix + '_' if vss_prefix else ''}{matched_type.lower()}_{user_slug}"
                        display_name = (
                            f"{vss_prefix.upper()}/{username}/{canonical_base}"
                            if vss_prefix
                            else f"{username}/{canonical_base}"
                        )
                        if unique_key not in seen_keys:
                            seen_keys.add(unique_key)
                            targets.append((matched_type, display_name, fpath_res, unique_key))
                            try:
                                dkey = _file_digest_key(fpath_res)
                                named_user_digests.setdefault((vss_prefix, matched_type), set()).add(dkey)
                            except OSError:
                                pass
                        elif unique_key not in fallback_paths and clean_hives_root not in fpath_res.parents:
                            fallback_paths[unique_key] = fpath_res
                    else:
                        # Bare root NTUSER.DAT / UsrClass.dat: skip if identical copy of an already-discovered user hive
                        known_digests = named_user_digests.get((vss_prefix, matched_type), set())
                        if known_digests:
                            try:
                                if _file_digest_key(fpath_res) in known_digests:
                                    continue
                            except OSError:
                                pass
                        unique_key = f"{vss_prefix + '_' if vss_prefix else ''}{matched_type.lower()}"
                        display_name = f"{vss_prefix.upper()}/{canonical_base}" if vss_prefix else canonical_base
                        if unique_key not in seen_keys:
                            seen_keys.add(unique_key)
                            targets.append((matched_type, display_name, fpath_res, unique_key))
                        elif unique_key not in fallback_paths and clean_hives_root not in fpath_res.parents:
                            fallback_paths[unique_key] = fpath_res
                else:
                    canonical_base = "Amcache.hve" if matched_type == "AMCACHE" else matched_type
                    unique_key = f"{vss_prefix + '_' if vss_prefix else ''}{matched_type.lower()}"
                    display_name = f"{vss_prefix.upper()}/{canonical_base}" if vss_prefix else canonical_base
                    if unique_key not in seen_keys:
                        seen_keys.add(unique_key)
                        targets.append((matched_type, display_name, fpath_res, unique_key))
                    elif unique_key not in fallback_paths and clean_hives_root not in fpath_res.parents:
                        fallback_paths[unique_key] = fpath_res

        self._fallback_hive_paths = fallback_paths
        self.log_fn(f"Discovered {len(targets)} candidate registry hives: {[t[1] for t in targets]}")
        return targets

    def find_registry_hives(self) -> List[Tuple[str, str, Path]]:
        """
        Finds candidate registry hives in clean_hives (first priority) or staging.
        Returns list of tuples: (hive_type, hive_display_name, hive_path)
        """
        return [(h_type, h_name, h_path) for h_type, h_name, h_path, _uk in self._discover_hive_targets()]

    def parse_plugin_blocks(
        self,
        raw_text: str,
        hive_name: str,
        hive_type: str,
    ) -> List[Dict[str, Any]]:
        """
        Parses rip.exe output stream into structured per-plugin report records.
        Splits on rip.pl's exact 40-dash line (`^-{38,40}`) so internal plugin tables
        (e.g. radar.pl's 65/45/42-dash lines) stay intact, and recovers headerless plugins.
        """
        if not raw_text or not raw_text.strip():
            return []

        catalog = self.get_plugin_catalog()
        records: List[Dict[str, Any]] = []

        if re.search(r"(?m)^-{38,40}(?!-)[ \t]*\r?$", raw_text):
            sections = re.split(r"(?m)^-{38,40}(?!-)[ \t]*(?:\r?\n|$)", raw_text)
        else:
            sections = re.split(r"(?m)^-{30,}[ \t]*(?:\r?\n|$)", raw_text)

        for sec in sections:
            sec_clean = sec.strip()
            if not sec_clean:
                continue

            lines = sec_clean.splitlines()
            first_line = lines[0].strip() if lines else ""

            pname = ""
            pver = ""

            # 1. Standard '<plugin> v.<version>' or 'Launching <plugin> v.<version>' in first 3 lines
            m = re.search(r"(?:Launching\s+)?([a-zA-Z0-9_\-]+)\s+v\.([\w\.]+)", first_line)
            if not m:
                for l in lines[:3]:
                    m = re.search(r"^(?:Launching\s+)?([a-zA-Z0-9_\-]+)\s+v\.([\w\.]+)", l.strip())
                    if m:
                        break

            if m:
                pname = m.group(1).strip()
                pver = m.group(2).strip()
            else:
                sec_low = sec_clean.lower()
                first_low = first_line.lower()

                # 2. Exact catalog match on headerless plugin title (e.g. UserAssist, OSVersion, AppSpecific)
                if first_low in catalog:
                    pname = catalog[first_low].get("plugin_name") or first_low
                    pver = catalog[first_low].get("version", "")
                # 3. Known headerless RegRipper 4.0 plugin content signatures
                elif "landesk\\managementsuite" in sec_low or "landesk" in sec_low:
                    pname = "landesk"
                elif "intellipoint\\appspecific" in sec_low:
                    pname = "appspecific"
                elif "security-spp-lastwindowsactivationtime" in sec_low or "control\\productoptions" in sec_low:
                    pname = "productpolicy"
                elif "software\\microsoft not found" in sec_low and hive_type.upper() == "NTUSER":
                    pname = "osversion"
                else:
                    # 4. Single-token fallback excluding generic metadata words
                    words = first_line.split()
                    if words:
                        cand_tok = words[0].rstrip(":")
                        if (
                            re.match(r"^[a-zA-Z0-9_\-]+$", words[0])
                            and cand_tok.lower() not in _GENERIC_HEADER_TOKENS
                        ):
                            pname = words[0]

            if not pname:
                continue

            cat_info = catalog.get(pname.lower(), {})
            if not pver:
                pver = cat_info.get("version", "")
            category = cat_info.get("category", "")
            mitre_attack = cat_info.get("mitre", "")
            description = cat_info.get("description", "")

            for l in lines[:6]:
                l_s = l.strip()
                if not mitre_attack and "MITRE:" in l_s:
                    mitre_attack = l_s.replace("MITRE:", "").strip()
                if not description and (
                    l_s.startswith("(") or "Parse" in l_s or "Check" in l_s or "Get" in l_s
                ):
                    description = l_s.strip("()")

            summary_line = ""
            for l in lines[1:]:
                l_s = l.strip()
                if (
                    l_s
                    and not l_s.startswith("(")
                    and not l_s.startswith("MITRE:")
                    and not l_s.startswith("Launching")
                    and not l_s.startswith("Ref:")
                    and not l_s.startswith("Analysis Tip:")
                ):
                    summary_line = l_s[:200]
                    break
            if not summary_line and first_line:
                summary_line = first_line[:200]

            records.append(
                {
                    "plugin_name": pname,
                    "plugin_version": pver,
                    "hive_name": hive_name,
                    "hive_type": hive_type,
                    "category": category or "Registry & OS",
                    "mitre_attack": mitre_attack,
                    "description": description or f"RegRipper {pname} plugin analysis",
                    "report_text": sec_clean,
                    "summary_line": summary_line or f"Analysis for {pname}",
                    "output_lines_count": len(lines),
                }
            )

        return records

    def _resolve_raw_fallback_hive(self, unique_key: str, h_path: Path) -> Optional[Path]:
        """Resolve a raw staged counterpart hive when a clean_hives copy disappears or fails."""
        cached = self._fallback_hive_paths.get(unique_key)
        if cached is not None and cached.is_file():
            return cached

        clean_root = (self.case_dir / "clean_hives").resolve()
        try:
            h_res = h_path.resolve()
        except OSError:
            h_res = h_path
        if clean_root not in h_res.parents:
            return None

        try:
            rel_parts = h_res.relative_to(clean_root).parts
        except ValueError:
            return None

        candidate_paths: List[Path] = []
        if len(rel_parts) >= 3 and rel_parts[0].lower() == "vss":
            vss_sub = Path(*rel_parts[1:])
            vss_id = rel_parts[1]
            tail_parts = rel_parts[2:]
            candidate_paths.append(self.case_dir / "staging" / "VSS" / vss_id / "Registry" / Path(*tail_parts))
            candidate_paths.append(self.case_dir / "staging" / "VSS" / vss_sub)
        else:
            rel_sub = Path(*rel_parts)
            candidate_paths.append(self.case_dir / "staging" / "Registry" / rel_sub)
            candidate_paths.append(self.case_dir / "staging" / rel_sub)

        for cand in candidate_paths:
            try:
                rcand = cand.resolve()
                if rcand.is_file() and rcand.stat().st_size > 0:
                    return rcand
            except OSError:
                continue
        return None

    @staticmethod
    def _invoke_rip_on_hive(
        rip_exe: Path,
        hive_path: Path,
        h_type: str,
    ) -> Tuple[subprocess.CompletedProcess, str]:
        cmd = [str(rip_exe), "-r", str(hive_path), "-a"]
        proc = subprocess.run(
            cmd,
            cwd=str(rip_exe.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            creationflags=_NO_WINDOW,
        )
        stdout_text = proc.stdout or ""

        # Amcache fallback when synthetic/cleaned Amcache.hve lacks embedded header filename
        if h_type == "AMCACHE" and not stdout_text.strip() and proc.returncode == 0:
            fb_proc = subprocess.run(
                [str(rip_exe), "-r", str(hive_path), "-p", "amcache"],
                cwd=str(rip_exe.parent),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                creationflags=_NO_WINDOW,
            )
            if (fb_proc.stdout or "").strip():
                return (fb_proc, fb_proc.stdout or "")

        return (proc, stdout_text)

    def _run_single_hive(
        self,
        rip_exe: Path,
        target: Tuple[str, str, Path, str],
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Worker method executed inside ThreadPoolExecutor. Performs ZERO DuckDB access.
        """
        h_type, h_name, h_path, unique_key = target
        self.log_fn(f"Executing RegRipper plugins on hive: {h_name} ({h_type})...")
        out_txt_file = self.regripper_out_dir / f"{unique_key}_rip.txt"
        clean_root = (self.case_dir / "clean_hives").resolve()

        try:
            active_path = Path(h_path)
            try:
                is_clean_target = clean_root in active_path.resolve().parents
            except OSError:
                is_clean_target = "clean_hives" in [p.lower() for p in active_path.parts]

            if is_clean_target and not active_path.is_file():
                fb_pre = self._resolve_raw_fallback_hive(unique_key, active_path)
                if fb_pre is not None:
                    self.log_fn(
                        f"Clean hive {h_name} unavailable; falling back to staged hive {fb_pre}",
                        "WARNING",
                    )
                    active_path = fb_pre

            proc, stdout_text = self._invoke_rip_on_hive(rip_exe, active_path, h_type)

            if is_clean_target and active_path == Path(h_path) and (
                not active_path.is_file() or proc.returncode != 0 or not stdout_text.strip()
            ):
                fb_post = self._resolve_raw_fallback_hive(unique_key, active_path)
                if fb_post is not None and fb_post != active_path:
                    self.log_fn(
                        f"Retrying RegRipper on raw staged hive for {h_name} "
                        f"(clean_hives rc={proc.returncode}): {fb_post}",
                        "WARNING",
                    )
                    fb_proc, fb_stdout = self._invoke_rip_on_hive(rip_exe, fb_post, h_type)
                    if fb_stdout.strip() or fb_proc.returncode == 0:
                        active_path = fb_post
                        proc = fb_proc
                        stdout_text = fb_stdout

            out_txt_file.write_text(stdout_text, encoding="utf-8", errors="replace")
            records = self.parse_plugin_blocks(stdout_text, h_name, h_type)
            if not records and (not active_path.is_file() or proc.returncode != 0):
                stderr_raw = (proc.stderr or "").strip()
                stderr_snip = (
                    stderr_raw.splitlines()[0][:240]
                    if stderr_raw
                    else ("hive file missing" if not active_path.is_file() else "empty rip.exe output")
                )
                err_diag = f"{h_name} (returncode={proc.returncode}, stderr={stderr_snip})"
                self.log_fn(f"RegRipper warning on hive {err_diag}", "WARNING")
                return ([], err_diag)

            self.log_fn(f"Hive {h_name}: parsed {len(records)} plugin reports.")
            return (records, None)
        except Exception as ex:
            err = f"{h_name}: {ex}"
            self.log_fn(f"Error executing RegRipper on hive {h_name}: {ex}", "WARNING")
            return ([], err)

    def run(
        self,
        max_workers: Optional[int] = None,
        selected_artifacts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes RegRipper in parallel across all detected hives, batch-ingests into DuckDB
        under a single per-case lock, registers regripper_plugins (NEVER deleting raw_recmd),
        and writes telemetry to processing_logs.
        """
        t0 = time.time()

        if selected_artifacts is not None:
            norm_selected = {str(a).strip().lower() for a in selected_artifacts if str(a).strip()}
            if norm_selected.isdisjoint(_RR_TRIGGER_IDS):
                duration_ms = int((time.time() - t0) * 1000)
                self._record_processing_log(
                    command_executed="RegRipper (filtered by selected_artifacts)",
                    exit_code=0,
                    rows_ingested=0,
                    duration_ms=duration_ms,
                    status="SKIPPED",
                    error_message="Registry artifacts not selected",
                )
                return {
                    "status": "SKIPPED",
                    "message": "Registry artifacts not selected",
                    "plugins_parsed": 0,
                    "hives_processed": 0,
                    "duration_seconds": round(duration_ms / 1000.0, 2),
                    "output_directory": str(self.regripper_out_dir),
                }

        self.log_fn("Starting RegRipper 4.0 parallel analysis pipeline...")

        try:
            rip_exe = self._resolve_regripper_binary()
        except FileNotFoundError as fnf:
            duration_ms = int((time.time() - t0) * 1000)
            self.log_fn(f"RegRipper binary rip.exe not available: {fnf}", "ERROR")
            self._record_processing_log(
                command_executed="find_regripper_binary()",
                exit_code=-1,
                rows_ingested=0,
                duration_ms=duration_ms,
                status="ERROR",
                error_message=str(fnf),
            )
            return {
                "status": "ERROR",
                "message": str(fnf),
                "plugins_parsed": 0,
                "hives_processed": 0,
                "duration_seconds": round(duration_ms / 1000.0, 2),
                "output_directory": str(self.regripper_out_dir),
            }

        hive_targets = self._discover_hive_targets()
        if not hive_targets:
            duration_ms = int((time.time() - t0) * 1000)
            self.log_fn("No registry hives found for RegRipper analysis.", "WARNING")
            self._record_processing_log(
                command_executed=f"{rip_exe} -a (0 hives)",
                exit_code=0,
                rows_ingested=0,
                duration_ms=duration_ms,
                status="SKIPPED",
                error_message="No registry hives found",
            )
            return {
                "status": "SKIPPED",
                "message": "No registry hives found",
                "plugins_parsed": 0,
                "hives_processed": 0,
                "duration_seconds": round(duration_ms / 1000.0, 2),
                "output_directory": str(self.regripper_out_dir),
            }

        # Pre-warm plugin catalog once before parallel hive workers launch
        self.get_plugin_catalog(rip_exe=rip_exe)

        effective_workers = max(
            1,
            min(int(self.max_workers if max_workers is None else max_workers), 32, len(hive_targets)),
        )

        all_records: List[Dict[str, Any]] = []
        hive_errors: List[str] = []

        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            outcomes = list(pool.map(lambda target: self._run_single_hive(rip_exe, target), hive_targets))

        for recs, err_str in outcomes:
            all_records.extend(recs)
            if err_str:
                hive_errors.append(err_str)

        total_ingested = 0
        duration_sec = round(time.time() - t0, 2)
        duration_ms = int((time.time() - t0) * 1000)
        err_summary = "; ".join(hive_errors) if hive_errors else None

        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            cursor = conn.cursor()

            _ensure_core_audit_tables(cursor)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_regripper (
                    _row_id BIGINT,
                    plugin_name VARCHAR NOT NULL,
                    plugin_version VARCHAR,
                    hive_name VARCHAR NOT NULL,
                    hive_type VARCHAR NOT NULL,
                    category VARCHAR,
                    mitre_attack VARCHAR,
                    description VARCHAR,
                    report_text VARCHAR NOT NULL,
                    summary_line VARCHAR,
                    output_lines_count INTEGER,
                    parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cursor.execute("DELETE FROM raw_regripper;")

            if all_records:
                inserted_via_arrow = False
                if len(all_records) >= 200:
                    try:
                        import pyarrow as pa

                        pa_tbl = pa.table(
                            {
                                "_row_id": list(range(1, len(all_records) + 1)),
                                "plugin_name": [r["plugin_name"] for r in all_records],
                                "plugin_version": [r["plugin_version"] for r in all_records],
                                "hive_name": [r["hive_name"] for r in all_records],
                                "hive_type": [r["hive_type"] for r in all_records],
                                "category": [r["category"] for r in all_records],
                                "mitre_attack": [r["mitre_attack"] for r in all_records],
                                "description": [r["description"] for r in all_records],
                                "report_text": [r["report_text"] for r in all_records],
                                "summary_line": [r["summary_line"] for r in all_records],
                                "output_lines_count": [int(r["output_lines_count"]) for r in all_records],
                            }
                        )
                        tmp_view = "_tmp_rr_batch"
                        cursor.register(tmp_view, pa_tbl)
                        try:
                            cursor.execute(
                                f"""
                                INSERT INTO raw_regripper (
                                    _row_id, plugin_name, plugin_version, hive_name, hive_type,
                                    category, mitre_attack, description, report_text,
                                    summary_line, output_lines_count
                                )
                                SELECT
                                    _row_id, plugin_name, plugin_version, hive_name, hive_type,
                                    category, mitre_attack, description, report_text,
                                    summary_line, output_lines_count
                                FROM {tmp_view};
                                """
                            )
                            total_ingested = len(all_records)
                            inserted_via_arrow = True
                        finally:
                            try:
                                cursor.unregister(tmp_view)
                            except Exception:
                                pass
                    except Exception:
                        inserted_via_arrow = False

                if not inserted_via_arrow:
                    insert_stmt = """
                    INSERT INTO raw_regripper (
                        _row_id, plugin_name, plugin_version, hive_name, hive_type,
                        category, mitre_attack, description, report_text,
                        summary_line, output_lines_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """
                    rows_to_insert = [
                        (
                            idx + 1,
                            r["plugin_name"],
                            r["plugin_version"],
                            r["hive_name"],
                            r["hive_type"],
                            r["category"],
                            r["mitre_attack"],
                            r["description"],
                            r["report_text"],
                            r["summary_line"],
                            r["output_lines_count"],
                        )
                        for idx, r in enumerate(all_records)
                    ]
                    cursor.executemany(insert_stmt, rows_to_insert)
                    total_ingested = len(rows_to_insert)

            # Register raw_regripper in artifact_registry (NEVER delete raw_recmd!)
            cursor.execute(
                """
                INSERT OR REPLACE INTO artifact_registry
                (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                VALUES ('regripper_plugins', 'OPERATING SYSTEM', 'RegRipper Plugins Analysis', 'raw_regripper', 'RegRipper 4.0', ?, CURRENT_TIMESTAMP);
                """,
                [total_ingested],
            )

            cursor.execute(
                """
                INSERT INTO processing_logs (
                    log_id, timestamp_utc, module_name, command_executed,
                    exit_code, rows_ingested, duration_ms, status, error_message
                ) VALUES (
                    nextval('seq_log_id'), CURRENT_TIMESTAMP, 'RegRipper', ?, 0, ?, ?, ?, ?
                );
                """,
                [
                    f"{rip_exe} -a ({len(hive_targets)} hives, workers={effective_workers})",
                    total_ingested,
                    duration_ms,
                    "SUCCESS" if not hive_errors else "WARNING",
                    err_summary,
                ],
            )

        try:
            with self._file_log_lock:
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(
                        f"[RegRipper] Status={'SUCCESS' if not hive_errors else 'WARNING'} "
                        f"Hives={len(hive_targets)} Rows={total_ingested} Duration={duration_ms}ms\n"
                    )
        except OSError:
            pass

        self.log_fn(
            f"RegRipper 4.0 analysis completed in {duration_sec}s across {len(hive_targets)} hives: "
            f"{total_ingested} plugin reports ingested."
        )

        return {
            "status": "SUCCESS" if not hive_errors else "WARNING",
            "plugins_parsed": total_ingested,
            "hives_processed": len(hive_targets),
            "duration_seconds": duration_sec,
            "output_directory": str(self.regripper_out_dir),
        }
