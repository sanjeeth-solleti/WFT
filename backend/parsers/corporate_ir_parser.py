"""
Windows Forensic Toolkit (WFT) DFIR Suite - Corporate Incident Response & Universal SQLite Parser
Parses:
1. Windows Scheduled Tasks XMLs & Registry TaskCache -> parsed_scheduled_tasks
2. PowerShell ConsoleHost_history.txt -> parsed_powershell_history
3. Remote Monitoring & Management (RMM) Logs -> parsed_rmm_sessions
4. Windows Push Notifications (wpndatabase.db) -> parsed_wpn_notifications
5. Universal SQLite Fallback Parser -> parsed_sqlite_*
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    windows_filetime_to_datetime,
)
from backend.security import strip_unsafe_xml_entities

try:
    from regipy.registry import RegistryHive as RegipyHive
    HAS_REGIPY = True
except ImportError:  # pragma: no cover
    RegipyHive = None  # type: ignore[assignment]
    HAS_REGIPY = False

try:
    from dissect.regf import RegistryHive as DissectRegfHive
    HAS_DISSECT_REGF = True
except ImportError:  # pragma: no cover
    DissectRegfHive = None  # type: ignore[assignment]
    HAS_DISSECT_REGF = False


# Suspicious PowerShell command patterns for corporate threat hunting
SUSPICIOUS_PS_PATTERNS = [
    r"\bmimikatz\b",
    r"\bdownloadstring\b",
    r"\binvoke-expression\b",
    r"\biex\b",
    r"\binvoke-webrequest\b",
    r"\biwr\b",
    r"\bcertutil\b",
    r"\bbypass\b",
    r"(?:^|\s)-(?:enc|encodedcommand|e)\b",
    r"\bfrombase64string\b",
    r"\bbitstransfer\b",
    r"\bnet\s+user\b",
    r"\bnet\s+(?:local)?group\b",
    r"\bwhoami\b",
    r"\brundll32\b",
    r"\bvssadmin\b",
    r"\bwbadmin\b",
    r"\bbcdedit\b",
    r"\bwmic\b",
    r"\b(?:powershell|pwsh)(?:\.exe)?\s+-(?:w(?:indowstyle)?\s+hidden|nop(?:rofile)?|noni(?:nteractive)?|enc(?:odedcommand)?|e\b)",
    r"\bmshta\b",
    r"\bregsvr32\b",
    r"\bcscript\b",
    r"\bwscript\b",
    r"\bstart-process\b",
    r"\bget-wmiobject\b",
    r"\bshadowcopy\b",
]
SUSPICIOUS_REGEX = re.compile("|".join(SUSPICIOUS_PS_PATTERNS), re.IGNORECASE)

# Generic suspicious task command/path indicators (zero dataset-specific strings)
SUSPICIOUS_TASK_KEYWORDS = (
    "powershell",
    "pwsh",
    "cmd.exe",
    "cmd /c",
    "rundll32",
    "mshta",
    "certutil",
    "bitsadmin",
    "vssadmin",
    "wscript",
    "cscript",
    "regsvr32",
    "sdelete",
    "downloadstring",
    "frombase64string",
    "encodedcommand",
    "\\temp\\",
    "/temp/",
    "\\appdata\\",
    "/appdata/",
    "\\programdata\\",
    "\\users\\public\\",
)

_XML_NS_ATTR_RE = re.compile(r"""\s+xmlns(?::[A-Za-z0-9_\-]+)?\s*=\s*(?:"[^"]*"|'[^']*')""")
_SIDE_CAR_SUFFIXES = (
    ".log",
    ".log1",
    ".log2",
    ".blf",
    ".regtrans-ms",
    ".sav",
    ".bak",
    ".txt",
    ".csv",
    ".json",
    ".db",
    ".sqlite",
    ".duckdb",
)


def _decode_text_bytes(raw_bytes: bytes) -> str:
    """Deterministically decode UTF-16LE/BE (BOM or null-interleaved) or UTF-8-sig text."""
    if not raw_bytes:
        return ""
    if raw_bytes.startswith(b"\xff\xfe"):
        return raw_bytes[2:].decode("utf-16-le", errors="replace")
    if raw_bytes.startswith(b"\xfe\xff"):
        return raw_bytes[2:].decode("utf-16-be", errors="replace")
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return raw_bytes[3:].decode("utf-8", errors="replace")

    head = raw_bytes[:256]
    if b"\x00<\x00" in head or b"<\x00T\x00a\x00s\x00k" in head or head.count(0) > len(head) // 3:
        try:
            return raw_bytes.decode("utf-16-le", errors="replace")
        except Exception:
            pass

    try:
        return raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1", errors="replace")


def _parse_any_timestamp(val: Any) -> Optional[datetime]:
    """Safely parse ISO-8601 (including 7-digit Windows fractional seconds), slash dates, or ctime strings."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.astimezone(timezone.utc) if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    s = str(val).strip()
    if not s:
        return None

    # Handle 7-digit Windows XML fractional seconds e.g. 2024-05-10T14:22:31.1234567Z or +02:00
    m_iso = re.match(
        r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$",
        s,
        re.IGNORECASE,
    )
    if m_iso:
        d_part, t_part, frac, tz_part = m_iso.groups()
        usec = f".{frac[:6].ljust(6, '0')}" if frac else ""
        tz_norm = "+00:00"
        if tz_part and tz_part.upper() != "Z":
            tz_norm = f"{tz_part[:3]}:{tz_part[3:]}" if len(tz_part) == 5 else tz_part
        try:
            dt = datetime.fromisoformat(f"{d_part}T{t_part}{usec}{tz_norm}")
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    s_dash = s.replace("/", "-")
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S %Y UTC",
    ):
        try:
            dt = datetime.strptime(s_dash if "-" in fmt else s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _evaluate_task_suspicion(
    command: str, arguments: str, working_dir: str = ""
) -> Tuple[bool, Optional[str]]:
    combined = f"{command} {arguments} {working_dir}".strip()
    if not combined:
        return (False, None)
    low = combined.lower()
    reasons: List[str] = []
    for kw in SUSPICIOUS_TASK_KEYWORDS:
        if kw in low:
            reasons.append(f"Indicator: {kw}")
    m_ps = SUSPICIOUS_REGEX.search(combined)
    if m_ps:
        hit = m_ps.group(0).strip()
        tag = f"Pattern: {hit}"
        if tag not in reasons:
            reasons.append(tag)
    if reasons:
        return (True, "; ".join(reasons))
    return (False, None)


def _decode_taskcache_actions_blob(blob: bytes) -> List[Tuple[str, str, str]]:
    """
    Decode Windows TaskCache\\Tasks\\{GUID}\\Actions binary structure.
    Returns list of (command, arguments, working_dir) tuples.
    """
    if not blob or len(blob) < 6:
        return []

    actions: List[Tuple[str, str, str]] = []
    try:
        ver = struct.unpack_from("<H", blob, 0)[0]
        if ver in (1, 2, 3) and len(blob) >= 8:
            pos = 2
            ctx_len = struct.unpack_from("<I", blob, pos)[0]
            pos += 4
            if ctx_len <= 512 and pos + ctx_len <= len(blob):
                pos += ctx_len
                while pos + 2 <= len(blob):
                    act_magic = struct.unpack_from("<H", blob, pos)[0]
                    pos += 2
                    if act_magic == 0x6666:  # ExecAction
                        strs: List[str] = []
                        ok = True
                        for _ in range(4):  # id, command, args, working_dir
                            if pos + 4 > len(blob):
                                ok = False
                                break
                            slen = struct.unpack_from("<I", blob, pos)[0]
                            pos += 4
                            if slen > 65536 or pos + slen > len(blob):
                                ok = False
                                break
                            sval = (
                                blob[pos : pos + slen]
                                .decode("utf-16-le", errors="ignore")
                                .strip("\x00 ")
                            )
                            pos += slen
                            strs.append(sval)
                        if ver >= 3 and pos + 2 <= len(blob):
                            pos += 2  # flags
                        if ok and len(strs) == 4 and strs[1]:
                            actions.append((strs[1], strs[2], strs[3]))
                        else:
                            break
                    elif act_magic == 0x7777:  # ComHandlerAction
                        if pos + 4 > len(blob):
                            break
                        id_len = struct.unpack_from("<I", blob, pos)[0]
                        pos += 4 + id_len
                        if pos + 16 <= len(blob):
                            clsid_b = blob[pos : pos + 16]
                            pos += 16
                            d1, d2, d3 = struct.unpack_from("<IHH", clsid_b, 0)
                            d4 = clsid_b[8:10].hex()
                            d5 = clsid_b[10:16].hex()
                            clsid_str = f"{{{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}}}".upper()
                            data_str = ""
                            if pos + 4 <= len(blob):
                                d_len = struct.unpack_from("<I", blob, pos)[0]
                                pos += 4
                                if d_len <= 16384 and pos + d_len <= len(blob):
                                    data_str = (
                                        blob[pos : pos + d_len]
                                        .decode("utf-16-le", errors="ignore")
                                        .strip("\x00 ")
                                    )
                                    pos += d_len
                            actions.append((f"COM:{clsid_str}", data_str, ""))
                        else:
                            break
                    else:
                        break
    except Exception:
        pass

    if actions:
        return actions

    # Fallback: extract UTF-16LE or UTF-8 command strings from synthetic or alternate Actions blobs
    u16_runs = [
        m.group(0).decode("utf-16-le", errors="ignore").strip("\x00 ")
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", blob)
    ]
    u16_runs = [s for s in u16_runs if s and s.lower() not in ("author", "system", "localservice", "networkservice")]
    if u16_runs:
        cmd = u16_runs[0]
        args = u16_runs[1] if len(u16_runs) > 1 else ""
        wd = u16_runs[2] if len(u16_runs) > 2 else ""
        return [(cmd, args, wd)]

    try:
        txt = blob.decode("utf-8", errors="ignore").strip("\x00 ")
        if txt and any(c.isalpha() for c in txt):
            parts = txt.split(" ", 1)
            return [(parts[0], parts[1] if len(parts) > 1 else "", "")]
    except Exception:
        pass

    return []


class _SimpleHiveReader:
    """Context-managed offline hive reader over regipy (primary) and dissect.regf (fallback)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._backend = ""
        self._hive: Any = None
        self._fh: Any = None

    def __enter__(self) -> Optional["_SimpleHiveReader"]:
        if HAS_REGIPY:
            try:
                self._hive = RegipyHive(str(self.path))
                self._backend = "regipy"
                return self
            except Exception:
                self._close()
        if HAS_DISSECT_REGF:
            try:
                self._fh = open(self.path, "rb")
                self._hive = DissectRegfHive(self._fh)
                self._backend = "dissect"
                return self
            except Exception:
                self._close()
        return None

    def _close(self) -> None:
        if self._hive is not None:
            st = getattr(self._hive, "_stream", None)
            if st is not None:
                try:
                    st.close()
                except Exception:
                    pass
            self._hive = None
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._close()

    def get_key(self, rel_path: str) -> Any:
        cleaned = rel_path.strip("\\/")
        if self._backend == "regipy":
            try:
                return self._hive.root if not cleaned else self._hive.get_key("\\" + cleaned)
            except Exception:
                cur = self._hive.root
                for seg in cleaned.split("\\"):
                    if not seg:
                        continue
                    nxt = None
                    for sk in cur.iter_subkeys():
                        if str(sk.name).lower() == seg.lower():
                            nxt = sk
                            break
                    if nxt is None:
                        return None
                    cur = nxt
                return cur
        elif self._backend == "dissect":
            try:
                return self._hive.root() if not cleaned else self._hive.open(cleaned)
            except Exception:
                return None
        return None

    def iter_subkeys(self, key: Any) -> Iterator[Any]:
        if key is None:
            return
        try:
            if self._backend == "regipy":
                yield from key.iter_subkeys()
            else:
                yield from key.subkeys()
        except Exception:
            return

    @staticmethod
    def key_name(key: Any) -> str:
        return str(getattr(key, "name", "") or "")

    def get_values(self, key: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if key is None:
            return out
        try:
            if self._backend == "regipy":
                for v in key.iter_values(trim_values=False):
                    out[str(v.name).lower()] = v.value
            else:
                for v in key.values():
                    vname = (str(v.name) or "(default)").lower()
                    try:
                        val = v.value
                    except Exception:
                        val = bytes(v.data)
                    out[vname] = val
        except Exception:
            pass
        return out


class CorporateIRParser(BaseParser):
    """
    Forensic parser for enterprise corporate incident response artifacts:
    Windows Scheduled Tasks, PowerShell history, RMM remote sessions,
    Windows Push Notifications, and Universal SQLite databases.
    """

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        super().__init__(case_id=case_id, staging_dir=staging_dir)
        self.tasks_dir = (self.staging_dir / "Tasks").resolve()
        self.ps_dir = (self.staging_dir / "PowerShell").resolve()
        self.rmm_dir = (self.staging_dir / "RMM").resolve()
        self.sqlite_dir = (self.staging_dir / "SQLite").resolve()

    # =========================================================================
    # 1. Windows Scheduled Tasks XML & Registry TaskCache Parser
    # =========================================================================
    def _discover_task_xml_files(self) -> List[Path]:
        seen: Set[Path] = set()
        out: List[Path] = []

        roots_to_scan: List[Path] = []
        if self.tasks_dir.is_dir():
            roots_to_scan.append(self.tasks_dir)

        # Also check Windows\System32\Tasks if staged under Enrichment or VSS
        if self.staging_dir.is_dir():
            for p in self.staging_dir.rglob("Tasks"):
                if p.is_dir() and p.resolve() != self.tasks_dir:
                    parent_low = str(p.parent).lower().replace("/", "\\")
                    if "system32" in parent_low or "syswow64" in parent_low or parent_low.endswith("\\windows"):
                        roots_to_scan.append(p.resolve())

        for base_dir in roots_to_scan:
            for root, _, files in os.walk(base_dir):
                for f in sorted(files):
                    if f.lower().endswith(_SIDE_CAR_SUFFIXES) and not f.lower().endswith(".xml"):
                        continue
                    fpath = (Path(root) / f).resolve()
                    if fpath in seen:
                        continue
                    try:
                        if fpath.is_file() and fpath.stat().st_size > 0:
                            seen.add(fpath)
                            out.append(fpath)
                    except OSError:
                        continue
        return out

    def _discover_software_hives(self) -> List[Path]:
        candidates: List[Path] = []
        seen_paths: Set[Path] = set()
        seen_slots: Set[str] = set()

        search_roots = [
            self.case_dir / "clean_hives",
            self.staging_dir / "Registry",
            self.staging_dir / "VSS",
        ]
        for root_dir in search_roots:
            if not root_dir.is_dir():
                continue
            for dirpath, _, filenames in os.walk(root_dir):
                for fn in sorted(filenames):
                    fn_low = fn.lower()
                    if fn_low.endswith(_SIDE_CAR_SUFFIXES):
                        continue
                    if not (fn_low in ("software", "software.hive", "software.dat") or fn_low.endswith("_software")):
                        continue
                    fp = (Path(dirpath) / fn).resolve()
                    if fp in seen_paths:
                        continue
                    seen_paths.add(fp)
                    try:
                        if fp.stat().st_size < 4096:
                            continue
                        with open(fp, "rb") as fh:
                            if fh.read(4) != b"regf":
                                continue
                    except OSError:
                        continue

                    m_vss = re.search(r"(?i)(?:^|[\\/])(vss[_\-]?\d+)(?:[\\/]|$)", str(fp))
                    slot = m_vss.group(1).upper() if m_vss else "ACTIVE"
                    if slot in seen_slots:
                        continue
                    seen_slots.add(slot)
                    candidates.append(fp)
        return candidates

    def _extract_actions_from_task_xml(self, root: ET.Element) -> List[Tuple[str, str, str]]:
        """Extract ALL <Exec> and <ComHandler> actions from a parsed Scheduled Task <Task> element."""
        extracted: List[Tuple[str, str, str]] = []
        actions_parent = root.find(".//Actions")
        search_root = actions_parent if actions_parent is not None else root

        for elem in search_root.iter():
            tag_low = elem.tag.lower()
            if tag_low == "exec":
                cmd = (elem.findtext("Command") or elem.findtext(".//Command") or "").strip()
                args = (elem.findtext("Arguments") or elem.findtext(".//Arguments") or "").strip()
                wdir = (
                    elem.findtext("WorkingDirectory")
                    or elem.findtext(".//WorkingDirectory")
                    or ""
                ).strip()
                if cmd or args:
                    extracted.append((cmd, args, wdir))
            elif tag_low == "comhandler":
                clsid = (elem.findtext("ClassId") or elem.findtext(".//ClassId") or "").strip()
                data = (elem.findtext("Data") or elem.findtext(".//Data") or "").strip()
                if clsid:
                    extracted.append((f"COM:{clsid}", data, ""))

        if not extracted:
            # Check ShowMessage / SendEmail fallback so task metadata is still preserved
            msg_body = (root.findtext(".//ShowMessage/Body") or "").strip()
            email_srv = (root.findtext(".//SendEmail/Server") or "").strip()
            if msg_body:
                extracted.append(("ShowMessage", msg_body, ""))
            elif email_srv:
                extracted.append(("SendEmail", email_srv, ""))
            else:
                extracted.append(("", "", ""))

        return extracted

    def _extract_taskcache_offline(
        self,
        software_hive: Path,
        existing_keys: Set[Tuple[str, str]],
        records: List[Dict[str, Any]],
    ) -> None:
        """Pure-Python offline extraction of Schedule\\TaskCache\\Tree + Tasks from SOFTWARE hive."""
        with _SimpleHiveReader(software_hive) as reader:
            if reader is None:
                return

            guid_to_tree_path: Dict[str, str] = {}
            tree_key = reader.get_key("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree")
            if tree_key is not None:
                def _walk_tree(node: Any, prefix: str) -> None:
                    vals = reader.get_values(node)
                    tid = vals.get("id")
                    if tid:
                        guid_norm = str(tid).strip("\x00 ").lower()
                        if guid_norm:
                            guid_to_tree_path[guid_norm] = prefix
                    for sk in reader.iter_subkeys(node):
                        sk_name = reader.key_name(sk)
                        child_path = f"{prefix}\\{sk_name}" if prefix else f"\\{sk_name}"
                        _walk_tree(sk, child_path)

                _walk_tree(tree_key, "")

            tasks_key = reader.get_key("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks")
            if tasks_key is not None:
                for t_sk in reader.iter_subkeys(tasks_key):
                    guid_key = reader.key_name(t_sk).strip()
                    vals = reader.get_values(t_sk)

                    uri_val = str(vals.get("uri") or vals.get("path") or "").strip("\x00 ")
                    t_path = uri_val or guid_to_tree_path.get(guid_key.lower(), "") or guid_key
                    if t_path and not t_path.startswith("\\") and not t_path.startswith("{"):
                        t_path = "\\" + t_path
                    t_name = t_path.rsplit("\\", 1)[-1] if "\\" in t_path else t_path

                    author = str(vals.get("author") or vals.get("source") or "").strip("\x00 ")

                    # Decode DynamicInfo FILETIMEs (offset 4: registration time, offset 12: last run time)
                    reg_dt: Optional[datetime] = None
                    last_run_dt: Optional[datetime] = None
                    dyn_raw = vals.get("dynamicinfo")
                    if isinstance(dyn_raw, str):
                        try:
                            dyn_raw = bytes.fromhex(dyn_raw)
                        except ValueError:
                            dyn_raw = None
                    if isinstance(dyn_raw, (bytes, bytearray)) and len(dyn_raw) >= 20:
                        ft_reg = struct.unpack_from("<Q", dyn_raw, 4)[0]
                        ft_run = struct.unpack_from("<Q", dyn_raw, 12)[0]
                        reg_dt = windows_filetime_to_datetime(ft_reg)
                        last_run_dt = windows_filetime_to_datetime(ft_run)

                    if reg_dt is None and vals.get("date"):
                        reg_dt = _parse_any_timestamp(vals.get("date"))

                    # Extract actions from Actions binary or explicit Command/Action values
                    parsed_actions: List[Tuple[str, str, str]] = []
                    act_raw = vals.get("actions")
                    if isinstance(act_raw, str):
                        try:
                            act_bytes = bytes.fromhex(act_raw)
                            parsed_actions = _decode_taskcache_actions_blob(act_bytes)
                        except ValueError:
                            parts = act_raw.strip().split(" ", 1)
                            parsed_actions = [(parts[0], parts[1] if len(parts) > 1 else "", "")]
                    elif isinstance(act_raw, (bytes, bytearray)):
                        parsed_actions = _decode_taskcache_actions_blob(bytes(act_raw))

                    if not parsed_actions:
                        explicit_cmd = str(vals.get("command") or vals.get("action") or "").strip("\x00 ")
                        explicit_args = str(vals.get("arguments") or "").strip("\x00 ")
                        explicit_wd = str(vals.get("workingdirectory") or "").strip("\x00 ")
                        parsed_actions = [(explicit_cmd, explicit_args, explicit_wd)]

                    trig_parts = ["Registry TaskCache"]
                    if last_run_dt is not None:
                        trig_parts.append(f"LastRun={last_run_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    trig_summary = " | ".join(trig_parts)

                    for cmd, args, wdir in parsed_actions:
                        exec_full = f"{cmd} {args}".strip() if args else cmd
                        dedup_k = (t_path.lower().strip("\\/"), exec_full.lower())
                        if dedup_k in existing_keys or (not exec_full and (t_path.lower().strip("\\/"), "*") in existing_keys):
                            continue
                        existing_keys.add(dedup_k)
                        existing_keys.add((t_path.lower().strip("\\/"), "*"))

                        is_susp, susp_ind = _evaluate_task_suspicion(cmd, args, wdir)
                        records.append(
                            {
                                "task_name": t_name or t_path,
                                "task_path": t_path,
                                "enabled": True,
                                "execute_command": exec_full,
                                "command": cmd,
                                "arguments": args,
                                "working_dir": wdir,
                                "author": author,
                                "date_created": reg_dt,
                                "triggers_summary": trig_summary,
                                "triggers": trig_summary,
                                "is_suspicious": is_susp,
                                "suspicious_indicators": susp_ind,
                                "source_file": f"SOFTWARE\\Schedule\\TaskCache ({software_hive.name})",
                            }
                        )

            # Tree-only entries that had no matching Tasks\{GUID} subkey
            for guid_low, tree_path in guid_to_tree_path.items():
                norm_tp = tree_path.lower().strip("\\/")
                if (norm_tp, "*") in existing_keys:
                    continue
                existing_keys.add((norm_tp, "*"))
                t_name = tree_path.rsplit("\\", 1)[-1] if "\\" in tree_path else tree_path
                records.append(
                    {
                        "task_name": t_name or tree_path,
                        "task_path": tree_path,
                        "enabled": True,
                        "execute_command": "",
                        "command": "",
                        "arguments": "",
                        "working_dir": "",
                        "author": "",
                        "date_created": None,
                        "triggers_summary": f"Registry TaskCache Tree ({guid_low})",
                        "triggers": f"Registry TaskCache Tree ({guid_low})",
                        "is_suspicious": False,
                        "suspicious_indicators": None,
                        "source_file": f"SOFTWARE\\Schedule\\TaskCache\\Tree ({software_hive.name})",
                    }
                )

    def parse_scheduled_tasks(self) -> int:
        """
        Parses Windows Scheduled Tasks XML files and SOFTWARE TaskCache Registry entries.
        Extracts ALL <Exec> and <ComHandler> actions per task with zero truncation.
        """
        self._log("Starting parse_scheduled_tasks...")
        records: List[Dict[str, Any]] = []
        existing_keys: Set[Tuple[str, str]] = set()

        task_files = self._discover_task_xml_files()
        self._log(f"Discovered {len(task_files)} candidate task XML files")

        for t_file in task_files:
            try:
                raw_bytes = t_file.read_bytes()
                text = _decode_text_bytes(raw_bytes)
                if not text or "<Task" not in text:
                    continue

                clean_text = re.sub(r"<\?xml[\s\S]*?\?>", "", text)
                clean_text = re.sub(r"<!--[\s\S]*?-->", "", clean_text).strip()

                task_blocks = re.findall(r"<Task\b[\s\S]*?</Task>", clean_text, flags=re.IGNORECASE)
                if not task_blocks:
                    task_blocks = [clean_text]

                rel_task_path = ""
                try:
                    if self.tasks_dir in t_file.parents:
                        rel_task_path = "\\" + t_file.relative_to(self.tasks_dir).as_posix().replace("/", "\\")
                except Exception:
                    rel_task_path = ""

                for block_idx, block in enumerate(task_blocks):
                    block_sanitized = strip_unsafe_xml_entities(_XML_NS_ATTR_RE.sub("", block))
                    try:
                        root = ET.fromstring(block_sanitized)
                    except ET.ParseError as pe:
                        self._log(f"Failed parsing task XML block in {t_file.name}: {pe}", "WARNING")
                        continue

                    for elem in root.iter():
                        if "}" in elem.tag:
                            elem.tag = elem.tag.split("}", 1)[1]
                        elif ":" in elem.tag:
                            elem.tag = elem.tag.split(":", 1)[1]

                    task_uri = (root.findtext(".//URI") or "").strip()
                    task_path = task_uri or rel_task_path or f"\\{t_file.name}"
                    if not task_path.startswith("\\"):
                        task_path = "\\" + task_path

                    base_name = task_uri.rsplit("\\", 1)[-1] if task_uri else t_file.name
                    if len(task_blocks) > 1:
                        base_name = f"{base_name}_{block_idx + 1}"

                    author = (
                        root.findtext(".//RegistrationInfo/Author")
                        or root.findtext(".//Author")
                        or root.findtext(".//Principal/UserId")
                        or ""
                    ).strip()
                    created_dt = _parse_any_timestamp(
                        root.findtext(".//RegistrationInfo/Date") or root.findtext(".//Date")
                    )

                    enabled_str = (root.findtext(".//Settings/Enabled") or "").strip()
                    enabled = enabled_str.lower() != "false" if enabled_str else True

                    triggers_list: List[str] = []
                    triggers_node = root.find(".//Triggers")
                    if triggers_node is not None:
                        for trg in triggers_node:
                            trg_tag = trg.tag
                            trg_start = (trg.findtext(".//StartBoundary") or "").strip()
                            trg_sched = f"{trg_tag}({trg_start})" if trg_start else trg_tag
                            triggers_list.append(trg_sched)
                    triggers_summary = ", ".join(triggers_list) if triggers_list else "None"

                    actions = self._extract_actions_from_task_xml(root)
                    for cmd, args, wdir in actions:
                        exec_full = f"{cmd} {args}".strip() if args else cmd
                        is_susp, susp_ind = _evaluate_task_suspicion(cmd, args, wdir)
                        norm_tp = task_path.lower().strip("\\/")
                        existing_keys.add((norm_tp, exec_full.lower()))
                        existing_keys.add((norm_tp, "*"))

                        records.append(
                            {
                                "task_name": base_name,
                                "task_path": task_path,
                                "enabled": enabled,
                                "execute_command": exec_full,
                                "command": cmd,
                                "arguments": args,
                                "working_dir": wdir,
                                "author": author,
                                "date_created": created_dt,
                                "triggers_summary": triggers_summary,
                                "triggers": triggers_summary,
                                "is_suspicious": is_susp,
                                "suspicious_indicators": susp_ind,
                                "source_file": t_file.name,
                            }
                        )
            except Exception as ex:
                self._log(f"Error parsing task file {t_file}: {ex}", "WARNING")

        # Offline SOFTWARE TaskCache extraction (regipy/dissect.regf primary + optional RegRipper tasks.pl)
        software_hives = self._discover_software_hives()
        for sw_hive in software_hives:
            try:
                self._extract_taskcache_offline(sw_hive, existing_keys, records)
            except Exception as tc_err:
                self._log(f"Notice parsing offline TaskCache from {sw_hive.name}: {tc_err}", "WARNING")

            try:
                from backend.config import find_regripper_binary

                rip_exe = find_regripper_binary()
                if rip_exe and Path(rip_exe).is_file():
                    rip_path = Path(rip_exe).resolve()
                    cmd = [str(rip_path), "-r", str(sw_hive), "-p", "tasks"]
                    proc = subprocess.run(
                        cmd,
                        cwd=str(rip_path.parent),
                        capture_output=True,
                        text=True,
                        errors="replace",
                        timeout=60,
                    )
                    if proc.stdout and "Path: " in proc.stdout:
                        for sec in proc.stdout.split("Path: ")[1:]:
                            lines = sec.strip().splitlines()
                            if not lines:
                                continue
                            t_path = lines[0].strip()
                            t_uri = ""
                            t_reg_time = ""
                            t_last_run = ""
                            t_completed = ""
                            t_user = ""
                            t_action = ""

                            for ln in lines[1:]:
                                ls = ln.strip()
                                if ls.startswith("URI :"):
                                    t_uri = ls.replace("URI :", "", 1).strip()
                                elif ls.startswith("Task Reg Time :"):
                                    t_reg_time = ls.replace("Task Reg Time :", "", 1).strip()
                                elif ls.startswith("Task Last Run :"):
                                    t_last_run = ls.replace("Task Last Run :", "", 1).strip()
                                elif ls.startswith("Task Completed:"):
                                    t_completed = ls.replace("Task Completed:", "", 1).strip()
                                elif ls.startswith("User   :"):
                                    t_user = ls.replace("User   :", "", 1).strip()
                                elif ls.startswith("Action :"):
                                    t_action = ls.replace("Action :", "", 1).strip()

                            full_path = t_path or t_uri
                            norm_key = full_path.lower().strip("\\/")
                            if norm_key and (norm_key, t_action.lower()) not in existing_keys and (norm_key, "*") not in existing_keys:
                                existing_keys.add((norm_key, t_action.lower()))
                                existing_keys.add((norm_key, "*"))

                                trig_parts = []
                                if t_last_run:
                                    trig_parts.append(f"Last Run: {t_last_run}")
                                if t_completed:
                                    trig_parts.append(f"Completed: {t_completed}")
                                trig_summary = " | ".join(trig_parts) if trig_parts else "Registry TaskCache Registered"

                                cmd_tok = t_action.split(" ", 1)[0] if t_action else ""
                                args_tok = t_action.split(" ", 1)[1] if " " in t_action else ""
                                is_susp, susp_ind = _evaluate_task_suspicion(cmd_tok, args_tok, "")

                                records.append(
                                    {
                                        "task_name": full_path.rsplit("\\", 1)[-1] if "\\" in full_path else full_path,
                                        "task_path": full_path,
                                        "enabled": True,
                                        "execute_command": t_action,
                                        "command": cmd_tok,
                                        "arguments": args_tok,
                                        "working_dir": "",
                                        "author": t_user,
                                        "date_created": _parse_any_timestamp(t_reg_time),
                                        "triggers_summary": trig_summary,
                                        "triggers": trig_summary,
                                        "is_suspicious": is_susp,
                                        "suspicious_indicators": susp_ind,
                                        "source_file": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache",
                                    }
                                )
            except Exception:
                pass

        self._log(f"Extracted {len(records)} scheduled task records. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_scheduled_tasks",
            records=records,
            artifact_id="tasks_scheduled",
            category="OPERATING SYSTEM",
            display_name="Scheduled Tasks",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 2. PowerShell History Parser
    # =========================================================================
    def _discover_powershell_files(self) -> List[Path]:
        seen: Set[Path] = set()
        ps_files: List[Path] = []

        if self.ps_dir.is_dir():
            for p in sorted(self.ps_dir.rglob("*.txt")):
                if p.is_file():
                    rp = p.resolve()
                    if rp not in seen:
                        seen.add(rp)
                        ps_files.append(rp)

        if self.staging_dir.is_dir():
            for p in sorted(self.staging_dir.rglob("*ConsoleHost_history.txt")):
                if p.is_file():
                    rp = p.resolve()
                    if rp not in seen:
                        seen.add(rp)
                        ps_files.append(rp)

        return ps_files

    @staticmethod
    def _derive_ps_username(ps_file: Path, ps_root: Path, staging_root: Optional[Path] = None) -> str:
        fname = ps_file.name
        if "_ConsoleHost_history" in fname:
            prefix = fname.split("_ConsoleHost_history", 1)[0].strip("_- ")
            if prefix:
                return prefix

        rel_parts: Tuple[str, ...] = ()
        if staging_root is not None:
            try:
                rel_parts = ps_file.resolve().relative_to(staging_root.resolve()).parts
            except ValueError:
                rel_parts = ()
        if not rel_parts:
            try:
                rel_parts = ps_file.resolve().relative_to(ps_root.resolve()).parts
            except ValueError:
                rel_parts = (ps_file.parent.name, ps_file.name)

        parts_low = [seg.lower() for seg in rel_parts]
        for idx, seg in enumerate(parts_low):
            if seg in ("users", "userfiles", "documents and settings") and idx + 1 < len(rel_parts):
                cand = rel_parts[idx + 1]
                if cand.lower() not in ("appdata", "powershell"):
                    return cand

        if ps_file.parent.resolve() != ps_root and ps_file.parent.name.lower() not in (
            "powershell",
            "psreadline",
            "staging",
        ):
            return ps_file.parent.name

        if "_" in fname and fname.lower() != "consolehost_history.txt":
            return fname.split("_", 1)[0]

        return "Default"

    def parse_powershell_history(self) -> int:
        """
        Parses PowerShell ConsoleHost_history.txt files without duplicate globbing.
        Extracts username, line number, command, length, and matched suspicious pattern.
        """
        self._log("Starting parse_powershell_history...")
        records: List[Dict[str, Any]] = []

        ps_files = self._discover_powershell_files()
        self._log(f"Discovered {len(ps_files)} deduplicated PowerShell history files")

        for ps_file in ps_files:
            try:
                if ps_file.stat().st_size == 0:
                    continue
                user_name = self._derive_ps_username(ps_file, self.ps_dir, self.staging_dir)
                content = _decode_text_bytes(ps_file.read_bytes())
                lines = content.splitlines()

                for line_idx, line in enumerate(lines):
                    cmd_clean = line.strip()
                    if not cmd_clean:
                        continue

                    susp_hits = list(
                        dict.fromkeys(
                            m.group(0).strip()
                            for m in SUSPICIOUS_REGEX.finditer(cmd_clean)
                            if m.group(0).strip()
                        )
                    )
                    is_suspicious = bool(susp_hits)
                    matched_pat = " | ".join(susp_hits) if susp_hits else None

                    records.append(
                        {
                            "username": user_name,
                            "user_name": user_name,
                            "line_number": line_idx + 1,
                            "command": cmd_clean,
                            "command_length": len(cmd_clean),
                            "is_suspicious": is_suspicious,
                            "contains_suspicious": is_suspicious,
                            "matched_pattern": matched_pat,
                            "source_file": ps_file.name,
                        }
                    )
            except Exception as ex:
                self._log(f"Error reading PowerShell history file {ps_file}: {ex}", "WARNING")

        self._log(f"Extracted {len(records)} PowerShell command entries. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_powershell_history",
            records=records,
            artifact_id="powershell_console_history",
            category="OPERATING SYSTEM",
            display_name="PowerShell Console Host History",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 3. RMM Remote Monitoring & Management Parser
    # =========================================================================
    def _discover_rmm_files(self) -> List[Path]:
        """Discover RMM log/config artifacts across both flat staging/RMM/ and preserved Windows paths under staging_dir."""
        all_files: List[Path] = []
        seen_files: Set[Path] = set()

        if self.rmm_dir.is_dir():
            for root, _, files in os.walk(self.rmm_dir):
                for f in sorted(files):
                    fp = (Path(root) / f).resolve()
                    try:
                        if fp not in seen_files and fp.is_file() and fp.stat().st_size > 0:
                            seen_files.add(fp)
                            all_files.append(fp)
                    except OSError:
                        continue

        if self.staging_dir.is_dir():
            for root, dirs, files in os.walk(self.staging_dir):
                root_p = Path(root).resolve()
                if root_p == self.rmm_dir or self.rmm_dir in root_p.parents:
                    dirs[:] = []
                    continue
                dirs[:] = [d for d in dirs if (root_p / d).resolve() != self.rmm_dir]

                try:
                    rel_dir_parts = [seg.lower() for seg in root_p.relative_to(self.staging_dir.resolve()).parts]
                except ValueError:
                    rel_dir_parts = [root_p.name.lower()]

                in_anydesk_dir = any("anydesk" in seg for seg in rel_dir_parts)
                in_rustdesk_dir = any("rustdesk" in seg for seg in rel_dir_parts)
                in_teamviewer_dir = any("teamviewer" in seg for seg in rel_dir_parts)

                for f in sorted(files):
                    fn_low = f.lower()
                    is_candidate = False
                    if in_anydesk_dir and (
                        fn_low.endswith((".trace", ".log")) or "trace" in fn_low
                    ):
                        is_candidate = True
                    elif in_rustdesk_dir and (
                        fn_low == "peers.json"
                        or fn_low.endswith((".log", ".trace", ".txt"))
                        or ("rustdesk" in fn_low and fn_low.endswith(".json"))
                    ):
                        is_candidate = True
                    elif in_teamviewer_dir and (
                        (fn_low.startswith("connections") and fn_low.endswith(".txt"))
                        or (("teamviewer" in fn_low or "logfile" in fn_low) and fn_low.endswith((".log", ".txt")))
                    ):
                        is_candidate = True
                    elif fn_low in ("ad.trace", "ad_svc.trace", "anydesk.trace", "connections_incoming.txt") or (
                        fn_low.startswith("teamviewer") and fn_low.endswith("_logfile.log")
                    ) or (
                        fn_low.startswith("rustdesk") and fn_low.endswith(".log")
                    ):
                        is_candidate = True

                    if not is_candidate:
                        continue

                    fp = (root_p / f).resolve()
                    try:
                        if fp not in seen_files and fp.is_file() and fp.stat().st_size > 0:
                            seen_files.add(fp)
                            all_files.append(fp)
                    except OSError:
                        continue

        return all_files

    def _rmm_rel_parts_lower(self, fp: Path) -> List[str]:
        try:
            return [seg.lower() for seg in fp.resolve().relative_to(self.staging_dir.resolve()).parts]
        except ValueError:
            return [fp.parent.name.lower(), fp.name.lower()]

    def parse_rmm_logs(self) -> int:
        """
        Parses AnyDesk (*.trace), TeamViewer (Connections*.txt, Logfile*.log),
        and RustDesk logs staged under staging/RMM/ or preserved Windows hierarchies
        under staging_dir with strict TIMESTAMP safety (None vs datetime).
        """
        self._log("Starting parse_rmm_logs...")
        records: List[Dict[str, Any]] = []

        all_files = self._discover_rmm_files()
        if not all_files:
            self._log(f"No RMM log files discovered under {self.rmm_dir} or {self.staging_dir}", "INFO")
            return 0

        claimed_files: Set[Path] = set()

        # 1. AnyDesk Logs (*.trace or under anydesk folder)
        for ad_f in all_files:
            rel_low = self._rmm_rel_parts_lower(ad_f)
            if not (
                ad_f.suffix.lower() == ".trace"
                or "anydesk" in ad_f.name.lower()
                or any("anydesk" in seg for seg in rel_low[:-1])
            ):
                continue
            claimed_files.add(ad_f)
            try:
                lines = _decode_text_bytes(ad_f.read_bytes()).splitlines()
                for line in lines:
                    line_s = line.strip()
                    if not line_s:
                        continue

                    ts_match = re.search(
                        r"(?:^\[?[a-zA-Z]+\]?\s+|^)(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
                        line_s,
                    )
                    start_dt = _parse_any_timestamp(ts_match.group(1)) if ts_match else None

                    low_l = line_s.lower()
                    if not any(
                        kw in low_l
                        for kw in ("session", "connecting", "accepted", "logged in", "incoming", "closed", "desk_rt")
                    ):
                        continue

                    id_match = re.search(r"\b(\d{7,10})\b", line_s)
                    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line_s)
                    rem_id = id_match.group(1) if id_match else ""
                    rem_ip = ip_match.group(1) if ip_match else ""
                    remote_identifier = rem_id or rem_ip

                    conn_type = "AnyDesk Session"
                    conn_res = "Observed"
                    if "incoming" in low_l:
                        conn_type = "Incoming Connection"
                    elif "connecting" in low_l or "outgoing" in low_l:
                        conn_type = "Outgoing Connection"
                    elif "accepted" in low_l or "logged in" in low_l:
                        conn_type = "Connection Accepted"
                        conn_res = "Accepted"
                    elif "closed" in low_l:
                        conn_type = "Session Terminated"
                        conn_res = "Closed"

                    records.append(
                        {
                            "app_name": "AnyDesk",
                            "rmm_product": "AnyDesk",
                            "session_id": "",
                            "remote_identifier": remote_identifier,
                            "connection_type": conn_type,
                            "start_time_utc": start_dt,
                            "end_time_utc": None,
                            "remote_ip": rem_ip or None,
                            "remote_id": rem_id or None,
                            "alias": None,
                            "local_user": None,
                            "auth_type": None,
                            "connection_result": conn_res,
                            "details": line_s[:500],
                            "source_file": ad_f.name,
                        }
                    )
            except Exception as ad_ex:
                self._log(f"Error parsing AnyDesk log {ad_f}: {ad_ex}", "WARNING")

        # 2. RustDesk (peers.json or rustdesk*.log)
        for rd_f in all_files:
            if rd_f in claimed_files:
                continue
            rel_low = self._rmm_rel_parts_lower(rd_f)
            if not (
                "rustdesk" in rd_f.name.lower()
                or rd_f.name.lower() == "peers.json"
                or any("rustdesk" in seg for seg in rel_low[:-1])
            ):
                continue
            claimed_files.add(rd_f)
            try:
                if rd_f.suffix.lower() == ".json":
                    data = json.loads(_decode_text_bytes(rd_f.read_bytes()))
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        if isinstance(item, dict):
                            peer_id = str(item.get("id", item.get("peer_id", "")) or "")
                            alias = str(item.get("alias", item.get("username", "")) or "")
                            platform = str(item.get("platform", "") or "")
                            records.append(
                                {
                                    "app_name": "RustDesk",
                                    "rmm_product": "RustDesk",
                                    "session_id": peer_id,
                                    "remote_identifier": peer_id,
                                    "connection_type": "Configured Peer",
                                    "start_time_utc": None,
                                    "end_time_utc": None,
                                    "remote_ip": None,
                                    "remote_id": peer_id or None,
                                    "alias": alias or None,
                                    "local_user": None,
                                    "auth_type": None,
                                    "connection_result": "Configured",
                                    "details": f"Alias: {alias} | Platform: {platform}",
                                    "source_file": rd_f.name,
                                }
                            )
                else:
                    lines = _decode_text_bytes(rd_f.read_bytes()).splitlines()
                    for line in lines:
                        line_s = line.strip()
                        if not line_s:
                            continue
                        if "connect" in line_s.lower() or "peer" in line_s.lower():
                            ts_match = re.search(r"(\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2})", line_s)
                            ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line_s)
                            rem_ip = ip_match.group(1) if ip_match else ""
                            records.append(
                                {
                                    "app_name": "RustDesk",
                                    "rmm_product": "RustDesk",
                                    "session_id": "",
                                    "remote_identifier": rem_ip,
                                    "connection_type": "RustDesk Event",
                                    "start_time_utc": _parse_any_timestamp(ts_match.group(1)) if ts_match else None,
                                    "end_time_utc": None,
                                    "remote_ip": rem_ip or None,
                                    "remote_id": None,
                                    "alias": None,
                                    "local_user": None,
                                    "auth_type": None,
                                    "connection_result": "Observed",
                                    "details": line_s[:500],
                                    "source_file": rd_f.name,
                                }
                            )
            except Exception as rd_ex:
                self._log(f"Error parsing RustDesk file {rd_f}: {rd_ex}", "WARNING")

        # 3. TeamViewer Logs (Connections*.txt, Logfile*.log)
        for tv_f in all_files:
            if tv_f in claimed_files:
                continue
            rel_low = self._rmm_rel_parts_lower(tv_f)
            if not (
                "teamviewer" in tv_f.name.lower()
                or "connection" in tv_f.name.lower()
                or "logfile" in tv_f.name.lower()
                or any("teamviewer" in seg for seg in rel_low[:-1])
            ):
                continue
            claimed_files.add(tv_f)
            try:
                lines = _decode_text_bytes(tv_f.read_bytes()).splitlines()
                is_conn_txt = "connection" in tv_f.name.lower() and tv_f.suffix.lower() == ".txt"

                for line in lines:
                    line_s = line.strip()
                    if not line_s or line_s.startswith("#"):
                        continue

                    if is_conn_txt and "\t" in line_s:
                        parts = [p.strip() for p in line_s.split("\t")]
                        remote_id = parts[0] if parts else ""

                        def _looks_like_ts(s: str) -> bool:
                            return bool(re.search(r"^\d{2,4}[-/\.]\d{2}[-/\.]\d{2,4}", s))

                        if len(parts) > 1 and _looks_like_ts(parts[1]):
                            start_raw = parts[1]
                            end_raw = parts[2] if len(parts) > 2 else ""
                            user_name = parts[3] if len(parts) > 3 else ""
                            conn_t = parts[4] if len(parts) > 4 else "RemoteControl"
                        else:
                            user_name = parts[1] if len(parts) > 1 else ""
                            start_raw = parts[2] if len(parts) > 2 else ""
                            end_raw = parts[3] if len(parts) > 3 else ""
                            conn_t = parts[5] if len(parts) > 5 else (parts[4] if len(parts) > 4 else "RemoteControl")

                        start_dt = _parse_any_timestamp(start_raw)
                        end_dt = _parse_any_timestamp(end_raw)

                        records.append(
                            {
                                "app_name": "TeamViewer",
                                "rmm_product": "TeamViewer",
                                "session_id": "",
                                "remote_identifier": remote_id,
                                "connection_type": conn_t or "RemoteControl",
                                "start_time_utc": start_dt,
                                "end_time_utc": end_dt,
                                "remote_ip": None,
                                "remote_id": remote_id or None,
                                "alias": None,
                                "local_user": user_name or None,
                                "auth_type": None,
                                "connection_result": "Connected",
                                "details": f"User: {user_name} | Type: {conn_t}",
                                "source_file": tv_f.name,
                            }
                        )
                    else:
                        ts_match = re.search(r"^(\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", line_s)
                        if any(kw in line_s.lower() for kw in ("carrier", "participant", "connected", "closed")):
                            id_match = re.search(r"['\"]?(\d{8,10})['\"]?", line_s)
                            ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line_s)
                            remote_id = id_match.group(1) if id_match else ""
                            rem_ip = ip_match.group(1) if ip_match else ""
                            records.append(
                                {
                                    "app_name": "TeamViewer",
                                    "rmm_product": "TeamViewer",
                                    "session_id": "",
                                    "remote_identifier": remote_id or rem_ip,
                                    "connection_type": "Log Event",
                                    "start_time_utc": _parse_any_timestamp(ts_match.group(1)) if ts_match else None,
                                    "end_time_utc": None,
                                    "remote_ip": rem_ip or None,
                                    "remote_id": remote_id or None,
                                    "alias": None,
                                    "local_user": None,
                                    "auth_type": None,
                                    "connection_result": "Observed",
                                    "details": line_s[:500],
                                    "source_file": tv_f.name,
                                }
                            )
            except Exception as tv_ex:
                self._log(f"Error parsing TeamViewer log {tv_f}: {tv_ex}", "WARNING")

        self._log(f"Extracted {len(records)} RMM remote session entries. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_rmm_sessions",
            records=records,
            artifact_id="parsed_rmm_sessions",
            category="OPERATING SYSTEM",
            display_name="Remote Desktop & RMM Logs (AnyDesk / TeamViewer)",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 4. Windows Push Notifications (wpndatabase.db)
    # =========================================================================
    @staticmethod
    def _parse_wpn_payload(payload_text: str, notif_type: str) -> Tuple[str, str, str, str, str]:
        """
        Extract (clean_summary, title, body, header, action_url) from WPN XML or JSON payload.
        """
        if not payload_text:
            return ("", "", "", notif_type or "", "")

        stripped = payload_text.strip()
        title = ""
        body = ""
        header = ""
        action_url = ""
        clean_summary = ""

        if "<" in stripped and ">" in stripped:
            try:
                xml_clean = strip_unsafe_xml_entities(_XML_NS_ATTR_RE.sub("", stripped))
                xml_clean = re.sub(r"<\?xml[\s\S]*?\?>", "", xml_clean).strip()
                root = ET.fromstring(xml_clean)
                for el in root.iter():
                    if "}" in el.tag:
                        el.tag = el.tag.split("}", 1)[1]

                action_url = (root.attrib.get("launch") or "").strip()
                texts: List[str] = []
                for el in root.iter():
                    t_low = el.tag.lower()
                    if t_low == "text" and el.text and el.text.strip():
                        texts.append(el.text.strip())
                    elif t_low == "header":
                        header = (el.attrib.get("title") or el.text or "").strip() or header
                    elif t_low == "action" and not action_url:
                        cand_arg = (el.attrib.get("arguments") or "").strip()
                        if cand_arg:
                            action_url = cand_arg

                if texts:
                    title = texts[0]
                    body = " | ".join(texts[1:]) if len(texts) > 1 else ""
                    clean_summary = " — ".join(texts)
            except Exception:
                summary_parts = [p.strip() for p in re.findall(r">([^<]+)<", stripped) if p.strip()]
                if summary_parts:
                    title = summary_parts[0]
                    body = " | ".join(summary_parts[1:]) if len(summary_parts) > 1 else ""
                    clean_summary = " ".join(summary_parts)
                m_launch = re.search(r"""launch\s*=\s*['"]([^'"]+)['"]""", stripped, re.IGNORECASE)
                if m_launch:
                    action_url = m_launch.group(1).strip()
                m_hdr = re.search(r"""<header[^>]*\btitle\s*=\s*['"]([^'"]+)['"]""", stripped, re.IGNORECASE)
                if m_hdr:
                    header = m_hdr.group(1).strip()
        elif stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    title = str(obj.get("title") or obj.get("heading") or "")
                    body = str(obj.get("body") or obj.get("message") or obj.get("text") or "")
                    header = str(obj.get("header") or "")
                    action_url = str(obj.get("url") or obj.get("launch") or "")
                    clean_summary = " — ".join(x for x in (title, body) if x) or stripped[:300]
            except Exception:
                clean_summary = stripped[:300]
        else:
            clean_summary = stripped[:300]
            title = stripped[:120]

        if not clean_summary:
            clean_summary = stripped[:300]
        if not header:
            header = notif_type or "toast"

        return (clean_summary, title, body, header, action_url)

    def parse_wpn_database(self) -> int:
        """
        Parses Windows Push Notifications database (wpndatabase.db) across staging_dir.
        Populates all schema.py columns including timestamp_utc, title, body, header, action_url.
        """
        self._log("Starting parse_wpn_database...")
        records: List[Dict[str, Any]] = []

        wpn_candidates: List[Path] = []
        seen_wpn: Set[Path] = set()
        for base_dir in (self.sqlite_dir, self.staging_dir):
            if not base_dir.is_dir():
                continue
            for p in sorted(base_dir.rglob("*wpndatabase*")):
                if not p.is_file():
                    continue
                if p.name.lower().endswith(("-wal", "-shm", "-journal")):
                    continue
                rp = p.resolve()
                if rp not in seen_wpn and rp.stat().st_size > 0:
                    seen_wpn.add(rp)
                    wpn_candidates.append(rp)

        self._log(f"Discovered {len(wpn_candidates)} wpndatabase candidate files")

        for wpn_f in wpn_candidates:
            with tempfile.TemporaryDirectory() as td:
                temp_db = copy_sqlite_with_wal(wpn_f, Path(td))
                conn = None
                try:
                    conn = sqlite3.connect(f"file:{temp_db.resolve().as_posix()}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tbls = {r[0] for r in cursor.fetchall()}

                    if "Notification" in tbls:
                        has_handler = "NotificationHandler" in tbls
                        if has_handler:
                            query = """
                            SELECT
                                n.Id AS notif_id,
                                h.PrimaryId AS app_id,
                                n."Type" AS notif_type,
                                n.ArrivalTime AS arrival_time,
                                n.ExpiryTime AS expiry_time,
                                n.Payload AS payload
                            FROM Notification n
                            LEFT JOIN NotificationHandler h ON n.HandlerId = h.RecordId;
                            """
                        else:
                            query = """
                            SELECT
                                n.Id AS notif_id,
                                CAST(n.HandlerId AS TEXT) AS app_id,
                                n."Type" AS notif_type,
                                n.ArrivalTime AS arrival_time,
                                n.ExpiryTime AS expiry_time,
                                n.Payload AS payload
                            FROM Notification n;
                            """
                        try:
                            cursor.execute(query)
                            rows = cursor.fetchall()
                            for r in rows:
                                arr_dt = windows_filetime_to_datetime(r["arrival_time"])
                                exp_dt = windows_filetime_to_datetime(r["expiry_time"])

                                payload_raw = r["payload"]
                                if isinstance(payload_raw, (bytes, bytearray)):
                                    payload_text = _decode_text_bytes(bytes(payload_raw))
                                elif payload_raw is not None:
                                    payload_text = str(payload_raw)
                                else:
                                    payload_text = ""

                                notif_type = str(r["notif_type"] or "")
                                clean_summary, title, body, header, action_url = self._parse_wpn_payload(
                                    payload_text, notif_type
                                )

                                records.append(
                                    {
                                        "notification_id": str(r["notif_id"]),
                                        "app_id": str(r["app_id"] or "Unknown"),
                                        "notification_type": notif_type,
                                        "arrival_time_utc": arr_dt,
                                        "expiry_time_utc": exp_dt,
                                        "payload": payload_text[:2000],
                                        "payload_text": clean_summary,
                                        "timestamp_utc": arr_dt,
                                        "title": title,
                                        "body": body,
                                        "header": header,
                                        "action_url": action_url,
                                        "source_file": wpn_f.name,
                                    }
                                )
                        except Exception as q_err:
                            self._log(f"Error querying Notification table in {wpn_f.name}: {q_err}", "WARNING")
                except Exception as db_err:
                    self._log(f"Error connecting to wpndatabase {wpn_f}: {db_err}", "WARNING")
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass

        self._log(f"Extracted {len(records)} Windows Push Notification records. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_wpn_notifications",
            records=records,
            artifact_id="os_wpn_notifications",
            category="OPERATING SYSTEM",
            display_name="Windows Push Notifications (WPN)",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 5. Universal SQLite Fallback Parser
    # =========================================================================
    def parse_universal_sqlite(self) -> Dict[str, int]:
        """
        Universal SQLite fallback engine:
        Iterates over generic SQLite databases in staging/SQLite/,
        skipping wpndatabase, activitiescache, and browser tables.
        """
        self._log("Starting parse_universal_sqlite...")
        results: Dict[str, int] = {}

        if not self.sqlite_dir.exists():
            return results

        skip_db_keywords = (
            "wpndatabase",
            "activitiescache",
            "history",
            "places",
            "cookies",
            "web data",
            "web_data",
            "login data",
            "login_data",
            "favicons",
            "top sites",
            "form history",
            "formhistory",
            "signons",
            "quota",
        )

        skip_tables = (
            "manualsequence",
            "metadata",
            "dataencryption",
            "dataencryptionkeys",
            "sqlite_sequence",
            "sqlite_stat1",
            "sqlite_stat4",
            "android_metadata",
            "schema_version",
            "meta",
        )

        candidate_dbs: List[Path] = []
        for root, _, files in os.walk(self.sqlite_dir):
            for f in sorted(files):
                fpath = Path(root) / f
                if fpath.is_file() and fpath.stat().st_size > 0:
                    fname_low = fpath.name.lower()
                    if fname_low.endswith(("-wal", "-shm", "-journal")):
                        continue
                    if any(k in fname_low for k in skip_db_keywords):
                        continue
                    try:
                        with open(fpath, "rb") as test_f:
                            header = test_f.read(16)
                            if header.startswith(b"SQLite format 3\x00") or fname_low.endswith(
                                (".db", ".sqlite", ".sqlite3")
                            ):
                                candidate_dbs.append(fpath)
                    except Exception:
                        continue

        self._log(f"Discovered {len(candidate_dbs)} generic SQLite database candidates")

        for db_file in candidate_dbs:
            db_clean_stem = re.sub(r"[^A-Za-z0-9_]+", "_", db_file.stem).strip("_").lower()
            with tempfile.TemporaryDirectory() as td:
                temp_db = copy_sqlite_with_wal(db_file, Path(td))
                conn = None
                try:
                    conn = sqlite3.connect(f"file:{temp_db.resolve().as_posix()}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
                    tables = [r[0] for r in cursor.fetchall()]

                    for tbl in tables:
                        tbl_low = tbl.lower()
                        if any(tbl_low == s or tbl_low.startswith(s) for s in skip_tables):
                            continue

                        tbl_clean = re.sub(r"[^A-Za-z0-9_]+", "_", tbl).strip("_").lower()
                        target_tbl_name = f"parsed_sqlite_{db_clean_stem}_{tbl_clean}"

                        try:
                            safe_tbl_sql = tbl.replace('"', '""')
                            cursor.execute(f'SELECT * FROM "{safe_tbl_sql}" LIMIT 10000;')
                            rows = cursor.fetchall()
                            if not rows:
                                continue

                            cols = [d[0] for d in cursor.description]
                            tbl_records = []
                            for r in rows:
                                rec: Dict[str, Any] = {}
                                for c in cols:
                                    val = r[c]
                                    if isinstance(val, (bytes, bytearray)):
                                        rec[c] = f"<BLOB {len(val)} bytes: {val[:32].hex()}>"
                                    else:
                                        rec[c] = val
                                rec["_source_sqlite"] = db_file.name
                                tbl_records.append(rec)

                            count = self.insert_records(
                                table_name=target_tbl_name,
                                records=tbl_records,
                                artifact_id=f"sqlite_{db_clean_stem}_{tbl_clean}",
                                category="OPERATING SYSTEM",
                                display_name=f"SQLite: {db_file.stem} ({tbl})",
                                source_tool="UniversalSQLiteParser",
                            )
                            results[target_tbl_name] = count
                            self._log(f"Universal SQLite: {target_tbl_name} -> {count} rows")
                        except Exception as tbl_err:
                            self._log(f"Error reading table {tbl} in {db_file.name}: {tbl_err}", "WARNING")
                except Exception as db_err:
                    self._log(f"Error opening SQLite database {db_file}: {db_err}", "WARNING")
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass

        return results

    # =========================================================================
    # MASTER PARSE EXECUTION
    # =========================================================================
    def parse(self) -> Dict[str, int]:
        """
        Executes all corporate incident response and universal SQLite parsing routines.
        Returns mapping of table names to ingested row counts.
        """
        start_time = time.time()
        self._log(f"Starting CorporateIRParser for case: '{self.case_id}'")
        counts: Dict[str, int] = {}

        counts["parsed_scheduled_tasks"] = self.parse_scheduled_tasks()
        counts["parsed_powershell_history"] = self.parse_powershell_history()
        counts["parsed_rmm_logs_alias"] = 0  # removed before return
        rmm_count = self.parse_rmm_logs()
        del counts["parsed_rmm_logs_alias"]
        counts["parsed_rmm_sessions"] = rmm_count
        counts["parsed_wpn_notifications"] = self.parse_wpn_database()
        counts.update(self.parse_universal_sqlite())

        duration_ms = int((time.time() - start_time) * 1000)
        total_rows = sum(counts.values())
        status = "SUCCESS" if total_rows > 0 else "WARNING"

        self.log_processing(
            module_name="CorporateIRParser",
            command_executed="CorporateIRParser.parse()",
            exit_code=0,
            rows_ingested=total_rows,
            duration_ms=duration_ms,
            status=status,
            error_message=None if total_rows > 0 else "No corporate IR records extracted from staging",
        )

        self._log(f"CorporateIRParser finished in {duration_ms}ms with {total_rows} total rows.")
        return counts
