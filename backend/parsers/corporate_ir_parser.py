"""
Windows Forensic Toolkit (WFT) DFIR Suite - Corporate Incident Response & Universal SQLite Parser
Parses:
1. Windows Scheduled Tasks XMLs -> parsed_scheduled_tasks
2. PowerShell ConsoleHost_history.txt -> parsed_powershell_history
3. Remote Monitoring & Management (RMM) Logs -> parsed_rmm_sessions
4. Windows Push Notifications (wpndatabase.db) -> parsed_wpn_notifications
5. Universal SQLite Fallback Parser -> parsed_sqlite_*
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import duckdb
import pandas as pd

from backend.config import get_case_dir, get_case_log_file, get_case_staging_dir
from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    windows_filetime_to_datetime,
)


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
    r"\bencodedcommand\b",
    r"\b-enc\b",
    r"\bbitstransfer\b",
    r"\bnet\s+user\b",
    r"\bnet\s+group\b",
    r"\bwhoami\b",
    r"\brundll32\b",
    r"\bvssadmin\b",
    r"\bwbadmin\b",
    r"\bbcdedit\b",
    r"\bwmic\b",
    r"\bpowershell\.exe\s+-[w|e]",
    r"\bmshta\b",
    r"\bregsvr32\b",
    r"\bcscript\b",
    r"\bwscript\b",
    r"\bstart-process\b",
    r"\bget-wmiobject\b",
    r"\bshadowcopy\b",
    r"\bpowershell_ise\b",
]
SUSPICIOUS_REGEX = re.compile("|".join(SUSPICIOUS_PS_PATTERNS), re.IGNORECASE)


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
    # 1. Windows Scheduled Tasks XML Parser
    # =========================================================================
    def parse_scheduled_tasks(self) -> int:
        """
        Parses Windows Scheduled Tasks XML files staged under staging/Tasks/
        Extracts task name, author, command, arguments, triggers, runlevel, etc.
        Ingests into parsed_scheduled_tasks table in DuckDB.
        """
        self._log("Starting parse_scheduled_tasks...")
        records: List[Dict[str, Any]] = []

        if not self.tasks_dir.exists():
            self._log(f"Tasks directory not found: {self.tasks_dir}", "WARNING")
            return 0

        task_files: List[Path] = []
        for root, _, files in os.walk(self.tasks_dir):
            for f in files:
                fpath = Path(root) / f
                if fpath.is_file() and fpath.stat().st_size > 0:
                    task_files.append(fpath)

        self._log(f"Discovered {len(task_files)} candidate task files in {self.tasks_dir}")

        for t_file in task_files:
            try:
                raw_bytes = t_file.read_bytes()
                # Try UTF-16LE then UTF-8
                text = ""
                for enc in ["utf-16le", "utf-8", "latin-1"]:
                    try:
                        text = raw_bytes.decode(enc)
                        if "<Task" in text:
                            break
                    except (UnicodeDecodeError, LookupError):
                        continue

                if not text or "<Task" not in text:
                    continue

                # Strip xml declarations and comments that might break ET parsing
                clean_text = re.sub(r"<\?xml.*?\?>", "", text)
                clean_text = re.sub(r"<!--[\s\S]*?-->", "", clean_text).strip()

                # Extract individual Task blocks if file contains multiple (e.g. schtasks export)
                task_blocks = re.findall(r"<Task\b[\s\S]*?</Task>", clean_text)
                if not task_blocks:
                    # Maybe single Task tag without closing or standard root
                    task_blocks = [clean_text]

                for block_idx, block in enumerate(task_blocks):
                    try:
                        root = ET.fromstring(block)
                    except ET.ParseError as pe:
                        # Attempt to wrap with xmlns strip
                        try:
                            block_no_ns = re.sub(r'\sxmlns="[^"]+"', '', block)
                            root = ET.fromstring(block_no_ns)
                        except Exception as inner_pe:
                            self._log(f"Failed parsing task XML block in {t_file.name}: {pe}", "WARNING")
                            continue

                    # Strip namespaces from tags
                    for elem in root.iter():
                        if "}" in elem.tag:
                            elem.tag = elem.tag.split("}", 1)[1]

                    # Extract fields
                    task_uri = root.findtext(".//URI")
                    task_name = task_uri.strip() if task_uri else t_file.stem
                    if len(task_blocks) > 1:
                        task_name = f"{task_name}_{block_idx+1}"

                    author = root.findtext(".//Author") or root.findtext(".//RegistrationInfo/Author")
                    description = root.findtext(".//Description")
                    created_date = root.findtext(".//Date")
                    version = root.attrib.get("version", "1.0")

                    # Principals / RunLevel / User
                    user_id = root.findtext(".//Principal/UserId") or root.findtext(".//GroupId")
                    run_level = root.findtext(".//Principal/RunLevel")
                    logon_type = root.findtext(".//Principal/LogonType")

                    # Settings
                    enabled_str = root.findtext(".//Settings/Enabled")
                    enabled = enabled_str.lower() != "false" if enabled_str else True
                    hidden_str = root.findtext(".//Settings/Hidden")
                    hidden = hidden_str.lower() == "true" if hidden_str else False

                    # Actions (Exec / ComHandler)
                    command = root.findtext(".//Exec/Command")
                    arguments = root.findtext(".//Exec/Arguments")
                    working_dir = root.findtext(".//Exec/WorkingDirectory")
                    com_handler = root.findtext(".//ComHandler/ClassId")

                    if not command and com_handler:
                        command = f"COM:{com_handler}"

                    # Triggers summary
                    triggers_list = []
                    triggers_node = root.find(".//Triggers")
                    if triggers_node is not None:
                        for trg in triggers_node:
                            trg_tag = trg.tag
                            trg_start = trg.findtext(".//StartBoundary") or ""
                            trg_sched = f"{trg_tag}({trg_start})" if trg_start else trg_tag
                            triggers_list.append(trg_sched)
                    triggers_summary = ", ".join(triggers_list) if triggers_list else "None"

                    records.append({
                        "task_name": task_name,
                        "author": author or "",
                        "command": command or "",
                        "execute_command": command or "",
                        "arguments": arguments or "",
                        "working_directory": working_dir or "",
                        "triggers": triggers_summary,
                        "triggers_summary": triggers_summary,
                        "run_level": run_level or "Normal",
                        "logon_type": logon_type or "",
                        "enabled": enabled,
                        "hidden": hidden,
                        "created_date": created_date if created_date else None,
                        "date_created": created_date if created_date else None,
                        "user_id": user_id or "",
                        "description": description or "",
                        "source_file": str(t_file.name),
                    })
            except Exception as ex:
                self._log(f"Error parsing task file {t_file}: {ex}", "WARNING")

        # Also extract Scheduled Tasks from SOFTWARE registry hive via RegRipper tasks.pl / TaskCache
        # so that all tasks (including system maintenance and background tasks) are fully captured
        existing_task_names = {r["task_name"].lower().strip("\\/"): True for r in records}
        try:
            software_candidates = [
                self.case_dir / "clean_hives" / "SOFTWARE",
                self.case_dir / "staging" / "Registry" / "SOFTWARE",
            ]
            software_hive = next((h for h in software_candidates if h.is_file() and h.stat().st_size > 0), None)
            if software_hive:
                from backend.config import find_regripper_binary
                try:
                    rip_exe = find_regripper_binary()
                    cmd = [str(rip_exe), "-r", str(software_hive), "-p", "tasks"]
                    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=60)
                    if proc.stdout and "Path: " in proc.stdout:
                        task_sections = proc.stdout.split("Path: ")
                        for sec in task_sections[1:]:
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

                            for l in lines[1:]:
                                ls = l.strip()
                                if ls.startswith("URI :"):
                                    t_uri = ls.replace("URI :", "").strip()
                                elif ls.startswith("Task Reg Time :"):
                                    t_reg_time = ls.replace("Task Reg Time :", "").strip()
                                elif ls.startswith("Task Last Run :"):
                                    t_last_run = ls.replace("Task Last Run :", "").strip()
                                elif ls.startswith("Task Completed:"):
                                    t_completed = ls.replace("Task Completed:", "").strip()
                                elif ls.startswith("User   :"):
                                    t_user = ls.replace("User   :", "").strip()
                                elif ls.startswith("Action :"):
                                    t_action = ls.replace("Action :", "").strip()

                            normalized_key = (t_path or t_uri).lower().strip("\\/")
                            if normalized_key and normalized_key not in existing_task_names:
                                existing_task_names[normalized_key] = True
                                trig_summary = ""
                                if t_last_run:
                                    trig_summary = f"Last Run: {t_last_run}"
                                if t_completed:
                                    trig_summary += f" | Completed: {t_completed}"

                                is_susp = False
                                susp_reasons = []
                                act_lower = t_action.lower()
                                for kw in ["powershell", "cmd.exe", "rundll32", "mshta", "certutil", "vssadmin", "wscript", "cscript", "sdelete", "imzadi", "temp\\", "appdata\\", "programdata\\"]:
                                    if kw in act_lower:
                                        is_susp = True
                                        susp_reasons.append(f"Keyword match: {kw}")

                                records.append({
                                    "task_name": t_path or t_uri,
                                    "task_path": t_path or t_uri,
                                    "author": t_user,
                                    "command": t_action.split(" ")[0] if t_action else "",
                                    "execute_command": t_action,
                                    "arguments": " ".join(t_action.split(" ")[1:]) if len(t_action.split(" ")) > 1 else "",
                                    "working_directory": "",
                                    "triggers": trig_summary or "Registry TaskCache Registered",
                                    "triggers_summary": trig_summary or "Registry TaskCache Registered",
                                    "run_level": "HighestAvailable" if "admin" in t_user.lower() or "system" in t_user.lower() else "Normal",
                                    "logon_type": "Interactive" if "user" in t_user.lower() else "Service",
                                    "enabled": True,
                                    "hidden": False,
                                    "created_date": t_reg_time if t_reg_time else None,
                                    "date_created": t_reg_time if t_reg_time else None,
                                    "user_id": t_user,
                                    "description": f"Scheduled task registered in SOFTWARE hive ({t_user})",
                                    "source_file": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache",
                                    "is_suspicious": is_susp,
                                    "suspicious_indicators": ", ".join(susp_reasons) if susp_reasons else None,
                                })
                except Exception as rip_err:
                    self._log(f"Notice running tasks.pl for registry tasks: {rip_err}", "WARNING")
        except Exception as reg_err:
            self._log(f"Notice checking registry tasks: {reg_err}", "WARNING")

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
    def parse_powershell_history(self) -> int:
        """
        Parses PowerShell ConsoleHost_history.txt files staged under staging/PowerShell/
        Extracts username, line number, command, length, and flags suspicious syntax.
        Ingests into parsed_powershell_history table in DuckDB.
        """
        self._log("Starting parse_powershell_history...")
        records: List[Dict[str, Any]] = []

        if not self.ps_dir.exists():
            self._log(f"PowerShell directory not found: {self.ps_dir}", "WARNING")
            return 0

        ps_files = list(self.ps_dir.glob("*ConsoleHost_history.txt")) + list(self.ps_dir.glob("*.txt"))
        self._log(f"Discovered {len(ps_files)} PowerShell history files")

        for ps_file in ps_files:
            if not ps_file.is_file() or ps_file.stat().st_size == 0:
                continue

            # Determine username from filename e.g. "SANJEETH_ConsoleHost_history.txt"
            fname = ps_file.name
            user_name = "Default"
            if "_ConsoleHost_history" in fname:
                user_name = fname.split("_ConsoleHost_history")[0]
            elif "_" in fname:
                user_name = fname.split("_")[0]

            try:
                content = ps_file.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()

                for line_idx, line in enumerate(lines):
                    cmd_clean = line.strip()
                    if not cmd_clean:
                        continue

                    # Check for suspicious corporate threat patterns
                    is_suspicious = bool(SUSPICIOUS_REGEX.search(cmd_clean))

                    records.append({
                        "username": user_name,
                        "user_name": user_name,
                        "line_number": line_idx + 1,
                        "command": cmd_clean,
                        "command_length": len(cmd_clean),
                        "is_suspicious": is_suspicious,
                        "contains_suspicious": is_suspicious,
                        "matched_pattern": None,
                        "source_file": ps_file.name,
                    })
            except Exception as ex:
                self._log(f"Error reading PowerShell history file {ps_file}: {ex}", "WARNING")

        self._log(f"Extracted {len(records)} PowerShell command entries. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_powershell_history",
            records=records,
            artifact_id="powershell_console_history",
            category="OPERATING SYSTEM",
            display_name="PowerShell Console History",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 3. RMM Remote Monitoring & Management Parser
    # =========================================================================
    def parse_rmm_logs(self) -> int:
        """
        Parses AnyDesk (ad.trace), TeamViewer (Connections*.txt, Logfile*.log),
        and RustDesk logs staged under staging/RMM/
        Extracts session IDs, remote peer addresses, connection timestamps, and status.
        Ingests into parsed_rmm_sessions table in DuckDB.
        """
        self._log("Starting parse_rmm_logs...")
        records: List[Dict[str, Any]] = []

        if not self.rmm_dir.exists():
            self._log(f"RMM directory not found: {self.rmm_dir}", "WARNING")
            return 0

        # 1. AnyDesk Logs (*.trace)
        anydesk_files: List[Path] = []
        for root, _, files in os.walk(self.rmm_dir):
            for f in files:
                fpath = Path(root) / f
                if fpath.suffix.lower() == ".trace" or "anydesk" in fpath.parent.name.lower():
                    anydesk_files.append(fpath)

        for ad_f in anydesk_files:
            try:
                lines = ad_f.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines:
                    line_s = line.strip()
                    if not line_s:
                        continue

                    # AnyDesk line format: 2026-03-15 14:22:31.123   info 12345 67890 app.session - ...
                    ts_match = re.search(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line_s)
                    timestamp_utc = ts_match.group(1) if ts_match else None

                    # Check for session events
                    is_session_event = any(kw in line_s.lower() for kw in [
                        "session", "connecting", "accepted", "logged in", "incoming", "closed", "desk_rt"
                    ])
                    if not is_session_event:
                        continue

                    # Look for remote ID (numeric ID 9-10 digits or IPv4 address)
                    id_match = re.search(r"\b(\d{7,10})\b", line_s)
                    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line_s)
                    remote_id = id_match.group(1) if id_match else (ip_match.group(1) if ip_match else "")

                    conn_type = "AnyDesk Session"
                    if "incoming" in line_s.lower():
                        conn_type = "Incoming Connection"
                    elif "connecting" in line_s.lower() or "outgoing" in line_s.lower():
                        conn_type = "Outgoing Connection"
                    elif "accepted" in line_s.lower():
                        conn_type = "Connection Accepted"
                    elif "closed" in line_s.lower():
                        conn_type = "Session Terminated"

                    records.append({
                        "app_name": "AnyDesk",
                        "session_id": "",
                        "remote_identifier": remote_id,
                        "connection_type": conn_type,
                        "start_time_utc": timestamp_utc if timestamp_utc else None,
                        "end_time_utc": None,
                        "details": line_s[:500],
                        "source_file": ad_f.name,
                    })
            except Exception as ad_ex:
                self._log(f"Error parsing AnyDesk log {ad_f}: {ad_ex}", "WARNING")

        # 2. TeamViewer Logs (Connections.txt, Connections_incoming.txt, Logfile)
        tv_files: List[Path] = []
        for root, _, files in os.walk(self.rmm_dir):
            for f in files:
                fpath = Path(root) / f
                if "teamviewer" in fpath.name.lower() or "connection" in fpath.name.lower() or "teamviewer" in fpath.parent.name.lower():
                    tv_files.append(fpath)

        for tv_f in tv_files:
            try:
                lines = tv_f.read_text(encoding="utf-8", errors="replace").splitlines()
                is_conn_txt = "connection" in tv_f.name.lower() and tv_f.suffix.lower() == ".txt"

                for line in lines:
                    line_s = line.strip()
                    if not line_s or line_s.startswith("#"):
                        continue

                    if is_conn_txt and "\t" in line_s:
                        # Tab-separated connection log: ID, User/Start, Start/End, End/User, Type
                        parts = [p.strip() for p in line_s.split("\t")]
                        remote_id = parts[0] if len(parts) > 0 else ""
                        
                        # Detect column layout by timestamp location
                        def is_ts(s: str) -> bool:
                            return bool(re.search(r"^\d{4}-\d{2}-\d{2}", s))

                        if len(parts) > 1 and is_ts(parts[1]):
                            # Format: ID, Start, End, User, Type
                            start_t = parts[1] if len(parts) > 1 else ""
                            end_t = parts[2] if len(parts) > 2 else ""
                            user_name = parts[3] if len(parts) > 3 else ""
                            conn_t = parts[4] if len(parts) > 4 else "RemoteControl"
                        else:
                            # Format: ID, User, Start, End, Duration, Type
                            user_name = parts[1] if len(parts) > 1 else ""
                            start_t = parts[2] if len(parts) > 2 else ""
                            end_t = parts[3] if len(parts) > 3 else ""
                            conn_t = parts[5] if len(parts) > 5 else (parts[4] if len(parts) > 4 else "RemoteControl")

                        clean_start = start_t if is_ts(start_t) else None
                        clean_end = end_t if is_ts(end_t) else None

                        records.append({
                            "app_name": "TeamViewer",
                            "session_id": "",
                            "remote_identifier": remote_id,
                            "connection_type": conn_t,
                            "start_time_utc": clean_start,
                            "end_time_utc": clean_end,
                            "details": f"User: {user_name} | Type: {conn_t}",
                            "source_file": tv_f.name,
                        })
                    else:
                        # Logfile.log line: 2026/03/15 10:00:00.123 ...
                        ts_match = re.search(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})", line_s)
                        if any(kw in line_s.lower() for kw in ["carrier", "participant", "connected", "closed"]):
                            id_match = re.search(r"['\"]?(\d{8,10})['\"]?", line_s)
                            remote_id = id_match.group(1) if id_match else ""
                            records.append({
                                "app_name": "TeamViewer",
                                "session_id": "",
                                "remote_identifier": remote_id,
                                "connection_type": "Log Event",
                                "start_time_utc": ts_match.group(1) if ts_match else "",
                                "end_time_utc": "",
                                "details": line_s[:500],
                                "source_file": tv_f.name,
                            })
            except Exception as tv_ex:
                self._log(f"Error parsing TeamViewer log {tv_f}: {tv_ex}", "WARNING")

        # 3. RustDesk (peers.json or rustdesk.log)
        rd_files: List[Path] = []
        for root, _, files in os.walk(self.rmm_dir):
            for f in files:
                fpath = Path(root) / f
                if "rustdesk" in fpath.name.lower() or "peers.json" in fpath.name.lower() or "rustdesk" in fpath.parent.name.lower():
                    rd_files.append(fpath)

        for rd_f in rd_files:
            try:
                if rd_f.suffix.lower() == ".json":
                    data = json.loads(rd_f.read_text(encoding="utf-8", errors="replace"))
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        if isinstance(item, dict):
                            peer_id = str(item.get("id", item.get("peer_id", "")))
                            alias = item.get("alias", item.get("username", ""))
                            platform = item.get("platform", "")
                            records.append({
                                "app_name": "RustDesk",
                                "session_id": peer_id,
                                "remote_identifier": peer_id,
                                "connection_type": "Configured Peer",
                                "start_time_utc": None,
                                "end_time_utc": None,
                                "details": f"Alias: {alias} | Platform: {platform}",
                                "source_file": rd_f.name,
                            })
                else:
                    lines = rd_f.read_text(encoding="utf-8", errors="replace").splitlines()
                    for line in lines:
                        if "connect" in line.lower() or "peer" in line.lower():
                            ts_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                            ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
                            records.append({
                                "app_name": "RustDesk",
                                "session_id": "",
                                "remote_identifier": ip_match.group(1) if ip_match else "",
                                "connection_type": "RustDesk Event",
                                "start_time_utc": ts_match.group(1) if ts_match else None,
                                "end_time_utc": None,
                                "details": line[:500],
                                "source_file": rd_f.name,
                            })
            except Exception as rd_ex:
                self._log(f"Error parsing RustDesk file {rd_f}: {rd_ex}", "WARNING")

        self._log(f"Extracted {len(records)} RMM remote session entries. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_rmm_sessions",
            records=records,
            artifact_id="parsed_rmm_sessions",
            category="OPERATING SYSTEM",
            display_name="Remote Desktop & RMM Sessions",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 4. Windows Push Notifications (wpndatabase.db)
    # =========================================================================
    def parse_wpn_database(self) -> int:
        """
        Parses Windows Push Notifications database (wpndatabase.db) staged under
        staging/SQLite/ or staging/SQLite/Notifications/
        Extracts application ID, notification type, timestamps, and XML/text payloads.
        Ingests into parsed_wpn_notifications table in DuckDB.
        """
        self._log("Starting parse_wpn_database...")
        records: List[Dict[str, Any]] = []

        if not self.sqlite_dir.exists():
            self._log(f"SQLite directory not found: {self.sqlite_dir}", "WARNING")
            return 0

        wpn_candidates: List[Path] = []
        for root, _, files in os.walk(self.sqlite_dir):
            for f in files:
                fpath = Path(root) / f
                if fpath.is_file() and "wpndatabase" in fpath.name.lower() and not fpath.name.endswith(("-wal", "-shm", "-journal")):
                    wpn_candidates.append(fpath)

        self._log(f"Discovered {len(wpn_candidates)} wpndatabase candidate files")

        for wpn_f in wpn_candidates:
            with tempfile.TemporaryDirectory() as td:
                temp_db = copy_sqlite_with_wal(wpn_f, Path(td))
                try:
                    conn = sqlite3.connect(f"file:{temp_db.resolve().as_posix()}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    # Check for Notification and NotificationHandler tables
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tbls = [r[0] for r in cursor.fetchall()]

                    if "Notification" in tbls:
                        query = """
                        SELECT
                            n.Id AS notif_id,
                            h.PrimaryId AS app_id,
                            n."Type" AS notif_type,
                            n.ArrivalTime AS arrival_time,
                            n.ExpiryTime AS expiry_time,
                            n.Payload AS payload,
                            n.Tag AS notif_tag,
                            n."Group" AS notif_group
                        FROM Notification n
                        LEFT JOIN NotificationHandler h ON n.HandlerId = h.RecordId;
                        """
                        try:
                            cursor.execute(query)
                            rows = cursor.fetchall()
                            for r in rows:
                                arr_dt = windows_filetime_to_datetime(r["arrival_time"])
                                exp_dt = windows_filetime_to_datetime(r["expiry_time"])
                                arr_str = arr_dt.isoformat() if arr_dt else None
                                exp_str = exp_dt.isoformat() if exp_dt else None

                                # Decode payload bytes or text
                                payload_raw = r["payload"]
                                payload_text = ""
                                if isinstance(payload_raw, bytes):
                                    for enc in ["utf-8", "utf-16le", "latin-1"]:
                                        try:
                                            payload_text = payload_raw.decode(enc)
                                            break
                                        except UnicodeDecodeError:
                                            continue
                                elif payload_raw is not None:
                                    payload_text = str(payload_raw)

                                # Extract readable inner text from XML if applicable
                                clean_summary = ""
                                if "<" in payload_text and ">" in payload_text:
                                    try:
                                        summary_parts = re.findall(r">([^<]+)<", payload_text)
                                        clean_summary = " ".join([p.strip() for p in summary_parts if p.strip()])
                                    except Exception:
                                        clean_summary = payload_text[:300]
                                else:
                                    clean_summary = payload_text[:300]

                                records.append({
                                    "notification_id": str(r["notif_id"]),
                                    "app_id": str(r["app_id"] or "Unknown"),
                                    "notification_type": str(r["notif_type"] or ""),
                                    "arrival_time_utc": arr_str,
                                    "expiry_time_utc": exp_str,
                                    "payload": payload_text[:2000],
                                    "payload_text": clean_summary,
                                    "tag": str(r["notif_tag"] or ""),
                                    "group_name": str(r["notif_group"] or ""),
                                    "source_file": wpn_f.name,
                                })
                        except Exception as q_err:
                            self._log(f"Error querying Notification table in {wpn_f.name}: {q_err}", "WARNING")
                    conn.close()
                except Exception as db_err:
                    self._log(f"Error connecting to wpndatabase {wpn_f}: {db_err}", "WARNING")

        self._log(f"Extracted {len(records)} Windows Push Notification records. Ingesting into DuckDB...")
        total_rows = self.insert_records(
            table_name="parsed_wpn_notifications",
            records=records,
            artifact_id="os_wpn_notifications",
            category="OPERATING SYSTEM",
            display_name="Windows Push Notifications",
            source_tool="CorporateIRParser",
        )
        return total_rows

    # =========================================================================
    # 5. Universal SQLite Fallback Parser
    # =========================================================================
    def parse_universal_sqlite(self) -> Dict[str, int]:
        """
        Universal SQLite fallback engine:
        Iterates over all SQLite databases in staging/SQLite/ (and subdirectories),
        skipping wpndatabase.db, activitiescache, and already-parsed browser/timeline tables.
        For every database, inspects sqlite_master, extracts records from user tables,
        skipping internal SQLite system/metadata tables, and registers into DuckDB.
        """
        self._log("Starting parse_universal_sqlite...")
        results: Dict[str, int] = {}

        if not self.sqlite_dir.exists():
            return results

        skip_db_keywords = [
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
            "signons",
            "quota",
        ]

        skip_tables = [
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
        ]

        candidate_dbs: List[Path] = []
        for root, _, files in os.walk(self.sqlite_dir):
            for f in files:
                fpath = Path(root) / f
                if fpath.is_file() and fpath.stat().st_size > 0:
                    fname_low = fpath.name.lower()
                    if fname_low.endswith(("-wal", "-shm", "-journal")):
                        continue
                    if any(k in fname_low for k in skip_db_keywords):
                        continue

                    # Check magic header
                    try:
                        with open(fpath, "rb") as test_f:
                            header = test_f.read(16)
                            if header.startswith(b"SQLite format 3\x00") or fname_low.endswith((".db", ".sqlite", ".sqlite3")):
                                candidate_dbs.append(fpath)
                    except Exception:
                        continue

        self._log(f"Discovered {len(candidate_dbs)} generic SQLite database candidates")

        for db_file in candidate_dbs:
            db_clean_stem = re.sub(r"[^A-Za-z0-9_]+", "_", db_file.stem).strip("_").lower()
            with tempfile.TemporaryDirectory() as td:
                temp_db = copy_sqlite_with_wal(db_file, Path(td))
                try:
                    conn = sqlite3.connect(f"file:{temp_db.resolve().as_posix()}?mode=ro", uri=True)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    # Get user tables
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
                    tables = [r[0] for r in cursor.fetchall()]

                    for tbl in tables:
                        tbl_low = tbl.lower()
                        if any(tbl_low == s or tbl_low.startswith(s) for s in skip_tables):
                            continue

                        tbl_clean = re.sub(r"[^A-Za-z0-9_]+", "_", tbl).strip("_").lower()
                        target_tbl_name = f"parsed_sqlite_{db_clean_stem}_{tbl_clean}"

                        try:
                            # Read rows (up to 10,000 per table for forensic safety)
                            cursor.execute(f'SELECT * FROM "{tbl}" LIMIT 10000;')
                            rows = cursor.fetchall()
                            if not rows:
                                continue

                            cols = [d[0] for d in cursor.description]
                            tbl_records = []
                            for r in rows:
                                rec = {}
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
                    conn.close()
                except Exception as db_err:
                    self._log(f"Error opening SQLite database {db_file}: {db_err}", "WARNING")

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

        # 1. Scheduled Tasks
        t_count = self.parse_scheduled_tasks()
        counts["parsed_scheduled_tasks"] = t_count

        # 2. PowerShell History
        ps_count = self.parse_powershell_history()
        counts["parsed_powershell_history"] = ps_count

        # 3. RMM Sessions
        rmm_count = self.parse_rmm_logs()
        counts["parsed_rmm_sessions"] = rmm_count

        # 4. Windows Push Notifications
        wpn_count = self.parse_wpn_database()
        counts["parsed_wpn_notifications"] = wpn_count

        # 5. Universal SQLite Fallback
        sql_counts = self.parse_universal_sqlite()
        counts.update(sql_counts)

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
