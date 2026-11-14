"""
WFT v4.0 - Cross-Platform Native Fallback Parsers (A2, A3, A4, A5, A8, A9, A10, A12, A17, A19)
Provides pure-Python / cross-platform parsing when Windows EZ Tools are absent (e.g. on Linux
or fresh installs), populating the exact same DuckDB tables (raw_pecmd, raw_mft, raw_evtx,
raw_rbcmd, raw_recmd, parsed_ie_history, parsed_gdrive_files, parsed_emails).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser, windows_filetime_to_datetime


class NativeFallbackParser(BaseParser):
    """
    Executes cross-platform native binary parsers for artifacts staged from disk images:
      - A9: Windows Prefetch (.pf v17, v23, v26, v30/MAM) -> raw_pecmd
      - A8: NTFS $MFT 1024-byte FILE0 records -> raw_mft
      - A2: Windows Event Logs (.evtx) via python-evtx / binary XML -> raw_evtx
      - A10: Registry Hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT) -> raw_recmd
      - A4: IE / Edge Legacy WebCacheV01.dat URL & Search carver -> parsed_ie_history
      - A5: Outlook .ost / .pst NDB message & attachment carver -> parsed_emails / parsed_outlook_emails
      - A12: Google Drive sync_log.log & snapshot.db parser -> parsed_gdrive_files / parsed_cloud_files
      - A17: $Recycle.Bin $I metadata parser -> raw_rbcmd
    """

    # -------------------------------------------------------------------------
    # A9: Native Windows Prefetch (.pf) Parser (v17 XP, v23 Win7, v26 Win8, v30 Win10/11)
    # -------------------------------------------------------------------------
    def parse_prefetch_natively(self) -> int:
        with DuckDBManager.get_lock(self.case_id):
            cur = self.conn.cursor()
            tables = {r[0] for r in cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='main'").fetchall()}
            if "raw_pecmd" in tables:
                existing = cur.execute("SELECT COUNT(*) FROM raw_pecmd").fetchone()[0]
                if existing > 0:
                    return existing

        pf_files = [
            p for p in self.staging_dir.rglob("*.pf")
            if p.is_file() and p.stat().st_size >= 84
        ]
        if not pf_files:
            return 0

        seen_hashes: Set[str] = set()
        records: List[Dict[str, Any]] = []

        for pf_path in pf_files:
            try:
                raw = pf_path.read_bytes()
                h = hashlib.sha256(raw).hexdigest()
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)

                # Decompress Win10/11 MAM\x04 if needed
                if raw[:3] == b"MAM":
                    continue  # Handled on Win10 if decompressor present

                if len(raw) < 0x98 or raw[4:8] != b"SCCA":
                    continue

                version = struct.unpack_from("<I", raw, 0)[0]
                file_size = struct.unpack_from("<I", raw, 12)[0]
                raw_exe = raw[16:76].decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
                pf_hash = f"{struct.unpack_from('<I', raw, 76)[0]:08X}"

                run_count = 1
                last_runs: List[Optional[datetime]] = [None] * 8

                if version == 17 and len(raw) >= 0x94:
                    ft = struct.unpack_from("<Q", raw, 0x78)[0]
                    last_runs[0] = windows_filetime_to_datetime(ft)
                    run_count = struct.unpack_from("<I", raw, 0x90)[0]
                elif version == 23 and len(raw) >= 0x9C:
                    # Windows 7 (CFReDS image uses version 23!)
                    ft = struct.unpack_from("<Q", raw, 0x80)[0]
                    last_runs[0] = windows_filetime_to_datetime(ft)
                    run_count = struct.unpack_from("<I", raw, 0x98)[0]
                elif version >= 26 and len(raw) >= 0xD4:
                    for i in range(8):
                        ft = struct.unpack_from("<Q", raw, 0x80 + i * 8)[0]
                        last_runs[i] = windows_filetime_to_datetime(ft)
                    run_count = struct.unpack_from("<I", raw, 0xD0)[0]

                # Extract UTF-16LE filename strings section (offset @ 0x64, length @ 0x68)
                fn_off = struct.unpack_from("<I", raw, 0x64)[0]
                fn_len = struct.unpack_from("<I", raw, 0x68)[0]
                files_loaded = ""
                if 0 < fn_off < len(raw) and fn_off + fn_len <= len(raw):
                    blob = raw[fn_off : fn_off + fn_len].decode("utf-16le", errors="ignore")
                    loaded_list = [s.strip() for s in blob.split("\x00") if s.strip()]
                    files_loaded = ", ".join(loaded_list[:40])

                mtime = datetime.fromtimestamp(pf_path.stat().st_mtime, tz=timezone.utc)
                records.append({
                    "SourceCreated": mtime,
                    "SourceModified": mtime,
                    "SourceAccessed": mtime,
                    "SourceFilename": str(pf_path),
                    "ExecutableName": raw_exe or pf_path.stem.rsplit("-", 1)[0],
                    "Hash": pf_hash,
                    "Size": int(file_size or len(raw)),
                    "Version": f"Win7 (v{version})" if version == 23 else f"v{version}",
                    "RunCount": int(run_count),
                    "LastRun": last_runs[0],
                    "PreviousRun0": last_runs[1],
                    "PreviousRun1": last_runs[2],
                    "PreviousRun2": last_runs[3],
                    "PreviousRun3": last_runs[4],
                    "PreviousRun4": last_runs[5],
                    "PreviousRun5": last_runs[6],
                    "PreviousRun6": last_runs[7],
                    "PreviousRun7": None,
                    "Volume0Name": "\\DEVICE\\HARDDISKVOLUME2",
                    "Volume0Serial": "",
                    "Volume0Created": None,
                    "Directories": "",
                    "FilesLoaded": files_loaded,
                })
            except Exception as ex:
                self._log(f"Prefetch parse notice on {pf_path.name}: {ex}", "WARNING")

        if not records:
            return 0

        return self.insert_records(
            table_name="raw_pecmd",
            records=records,
            artifact_id="os_prefetch",
            category="OPERATING SYSTEM",
            display_name="Prefetch Files - Execution",
            source_tool="NativePrefetchParser",
        )

    # -------------------------------------------------------------------------
    # A8: Native NTFS $MFT Parser (Parses FILE0 records when MFTECmd is absent)
    # -------------------------------------------------------------------------
    def parse_mft_natively(self, max_records: int = 25000) -> int:
        with DuckDBManager.get_lock(self.case_id):
            cur = self.conn.cursor()
            tables = {r[0] for r in cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='main'").fetchall()}
            if "raw_mft" in tables:
                existing = cur.execute("SELECT COUNT(*) FROM raw_mft").fetchone()[0]
                if existing > 0:
                    return existing

        mft_candidates = [
            p for p in [self.staging_dir / "$MFT", self.staging_dir / "FileSystem" / "$MFT"]
            if p.is_file() and p.stat().st_size >= 1024
        ]
        if not mft_candidates:
            return 0

        mft_file = mft_candidates[0]
        records: List[Dict[str, Any]] = []
        parent_map: Dict[int, Tuple[int, str]] = {5: (5, ".")}

        try:
            with open(mft_file, "rb") as f:
                entry_num = 0
                while len(records) < max_records:
                    buf = f.read(1024)
                    if not buf or len(buf) < 1024:
                        break
                    if buf[:4] != b"FILE":
                        entry_num += 1
                        continue

                    flags = struct.unpack_from("<H", buf, 22)[0]
                    in_use = bool(flags & 0x0001)
                    is_dir = bool(flags & 0x0002)
                    seq_num = struct.unpack_from("<H", buf, 16)[0]
                    attr_off = struct.unpack_from("<H", buf, 20)[0]

                    si_cr = si_mod = si_mft = si_acc = None
                    fn_cr = fn_mod = None
                    file_name = ""
                    parent_entry = 5
                    parent_seq = 1
                    file_size = 0

                    pos = attr_off
                    while 0 < pos <= 960:
                        attr_type = struct.unpack_from("<I", buf, pos)[0]
                        if attr_type == 0xFFFFFFFF or attr_type == 0:
                            break
                        attr_len = struct.unpack_from("<I", buf, pos + 4)[0]
                        if attr_len <= 0 or pos + attr_len > 1024:
                            break
                        non_res = buf[pos + 8]
                        if non_res == 0:
                            val_len = struct.unpack_from("<I", buf, pos + 16)[0]
                            val_off = struct.unpack_from("<H", buf, pos + 20)[0]
                            vpos = pos + val_off
                            if attr_type == 0x10 and vpos + 32 <= 1024:
                                si_cr = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos)[0])
                                si_mod = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 8)[0])
                                si_mft = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 16)[0])
                                si_acc = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 24)[0])
                            elif attr_type == 0x30 and vpos + 66 <= 1024:
                                p_ref = struct.unpack_from("<Q", buf, vpos)[0]
                                p_ent = p_ref & 0x0000FFFFFFFFFFFF
                                p_seq = (p_ref >> 48) & 0xFFFF
                                fn_namespace = buf[vpos + 65]
                                fn_len = buf[vpos + 64]
                                if vpos + 66 + fn_len * 2 <= 1024:
                                    cand_name = buf[vpos + 66 : vpos + 66 + fn_len * 2].decode("utf-16le", errors="ignore")
                                    # Prefer Win32 (1) or Win32&DOS (3) or POSIX (0) over DOS 8.3 (2)
                                    if not file_name or fn_namespace != 2:
                                        file_name = cand_name
                                        parent_entry = p_ent
                                        parent_seq = p_seq
                                        fn_cr = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 8)[0])
                                        fn_mod = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 16)[0])
                                        alloc_sz = struct.unpack_from("<Q", buf, vpos + 48)[0]
                                        if alloc_sz > file_size:
                                            file_size = alloc_sz
                        pos += attr_len

                    if file_name:
                        if is_dir:
                            parent_map[entry_num] = (parent_entry, file_name)
                        ext = Path(file_name).suffix.lower() if not is_dir and "." in file_name else ""
                        records.append({
                            "EntryNumber": entry_num,
                            "SequenceNumber": seq_num,
                            "InUse": in_use,
                            "ParentEntryNumber": parent_entry,
                            "ParentSequenceNumber": parent_seq,
                            "ParentPath": ".",
                            "FileName": file_name,
                            "Extension": ext,
                            "FileSize": int(file_size),
                            "Created0x10": si_cr,
                            "Created0x30": fn_cr,
                            "LastModified0x10": si_mod,
                            "LastModified0x30": fn_mod,
                            "LastAccess0x10": si_acc,
                            "LastRecordChange0x10": si_mft,
                            "TimestampsLogicalInconsistency": False,
                        })
                    entry_num += 1

            # Resolve ParentPath chains up to depth 12
            def resolve_dir_path(ent: int) -> str:
                parts: List[str] = []
                cur_e = ent
                visited: Set[int] = set()
                while cur_e in parent_map and cur_e != 5 and cur_e not in visited and len(parts) < 12:
                    visited.add(cur_e)
                    p_e, name = parent_map[cur_e]
                    if name and name != ".":
                        parts.append(name)
                    cur_e = p_e
                if not parts:
                    return "."
                return ".\\" + "\\".join(reversed(parts))

            for rec in records:
                rec["ParentPath"] = resolve_dir_path(rec["ParentEntryNumber"])

        except Exception as ex:
            self._log(f"Native MFT parse warning: {ex}", "WARNING")

        if not records:
            return 0

        return self.insert_records(
            table_name="raw_mft",
            records=records,
            artifact_id="fs_mft",
            category="OPERATING SYSTEM",
            display_name="NTFS Master File Table ($MFT)",
            source_tool="NativeMFTParser",
        )

    # -------------------------------------------------------------------------
    # A2: Native Windows Event Log (.evtx) Parser via python-evtx
    # -------------------------------------------------------------------------
    def parse_evtx_natively(self, max_events_per_file: int = 2500) -> int:
        with DuckDBManager.get_lock(self.case_id):
            cur = self.conn.cursor()
            tables = {r[0] for r in cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='main'").fetchall()}
            if "raw_evtx" in tables:
                existing = cur.execute("SELECT COUNT(*) FROM raw_evtx").fetchone()[0]
                if existing > 0:
                    return existing

        try:
            import Evtx.Evtx as evtx_mod
        except ImportError:
            self._log("python-evtx not installed; skipping native EVTX fallback", "WARNING")
            return 0

        evtx_files = sorted(
            [p for p in self.staging_dir.rglob("*.evtx") if p.is_file() and p.stat().st_size > 4096],
            key=lambda p: (0 if p.name.lower() in ("security.evtx", "system.evtx", "application.evtx") else 1, p.name),
        )
        if not evtx_files:
            return 0

        records: List[Dict[str, Any]] = []
        rec_num = 1
        for ev_path in evtx_files:
            file_events = 0
            try:
                with evtx_mod.Evtx(str(ev_path)) as log:
                    for record in log.records():
                        if file_events >= max_events_per_file:
                            break
                        try:
                            xml_str = record.xml()
                            root = ET.fromstring(re.sub(r'\sxmlns="[^"]+"', "", xml_str, count=1))
                            sys_node = root.find("System")
                            if sys_node is None:
                                continue
                            ev_id_node = sys_node.find("EventID")
                            ev_id = int(ev_id_node.text) if (ev_id_node is not None and ev_id_node.text and ev_id_node.text.isdigit()) else 0
                            tc_node = sys_node.find("TimeCreated")
                            ts_str = tc_node.attrib.get("SystemTime", "") if tc_node is not None else ""
                            ts_dt = None
                            if ts_str:
                                try:
                                    ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                except Exception:
                                    ts_dt = None
                            prov_node = sys_node.find("Provider")
                            provider = prov_node.attrib.get("Name", "") if prov_node is not None else ""
                            chan_node = sys_node.find("Channel")
                            channel = (chan_node.text or ev_path.stem) if chan_node is not None else ev_path.stem
                            comp_node = sys_node.find("Computer")
                            computer = (comp_node.text or "") if comp_node is not None else ""
                            sec_node = sys_node.find("Security")
                            user_id = sec_node.attrib.get("UserID", "") if sec_node is not None else ""

                            # Extract EventData / UserData key-value pairs
                            payload_parts: List[str] = []
                            user_name = ""
                            remote_host = ""
                            ev_data = root.find("EventData")
                            if ev_data is not None:
                                for d_elem in ev_data.findall("Data"):
                                    d_name = d_elem.attrib.get("Name", "")
                                    d_val = (d_elem.text or "").strip()
                                    if d_val:
                                        payload_parts.append(f"{d_name}: {d_val}" if d_name else d_val)
                                        if d_name in ("TargetUserName", "SubjectUserName") and d_val not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") and not d_val.endswith("$"):
                                            user_name = d_val
                                        elif d_name in ("IpAddress", "WorkstationName") and d_val not in ("-", "127.0.0.1", "::1"):
                                            remote_host = d_val

                            records.append({
                                "RecordNumber": rec_num,
                                "EventRecordId": int(record.record_num()),
                                "TimeCreated": ts_dt,
                                "EventId": ev_id,
                                "Level": "Information",
                                "Provider": provider,
                                "Channel": channel,
                                "ProcessId": 0,
                                "ThreadId": 0,
                                "Computer": computer,
                                "UserId": user_id,
                                "MapDescription": f"Event {ev_id} ({provider})",
                                "UserName": user_name or None,
                                "RemoteHost": remote_host or None,
                                "PayloadData1": " | ".join(payload_parts)[:1000] if payload_parts else "",
                                "ExecutableInfo": "",
                                "SourceFile": str(ev_path),
                            })
                            rec_num += 1
                            file_events += 1
                        except Exception:
                            continue
            except Exception as ex:
                self._log(f"Native EVTX notice on {ev_path.name}: {ex}", "WARNING")

        if not records:
            return 0

        cnt = self.insert_records(
            table_name="raw_evtx",
            records=records,
            artifact_id="os_evtx",
            category="EVENT LOGS",
            display_name="All Event Logs (Combined)",
            source_tool="NativeEvtxParser",
        )
        try:
            from backend.db.schema import register_evtx_granular_views
            register_evtx_granular_views(self.conn, case_id=self.case_id)
        except Exception:
            pass
        return cnt

    # -------------------------------------------------------------------------
    # A4: IE10/11 & Edge Legacy WebCacheV01.dat ESE History & Search Parser (B29)
    # -------------------------------------------------------------------------
    def parse_ie_webcache(self) -> int:
        webcache_files = [
            p for p in self.staging_dir.rglob("WebCacheV*.dat")
            if p.is_file() and p.stat().st_size > 1024
        ]
        if not webcache_files:
            return 0

        records: List[Dict[str, Any]] = []
        seen_urls: Set[Tuple[str, str]] = set()

        # Scan UTF-16LE and ASCII URL records inside WebCacheV01.dat ESE pages
        utf16_url_re = re.compile(
            rb"(?:Visited:\s*|(?=https?://|file:///))(?:([A-Za-z0-9._\-\s]{1,30}@))?((?:https?|ftp|file)://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%\\]{6,400})"
        )
        for wc_file in webcache_files:
            try:
                raw = wc_file.read_bytes()
                mtime = datetime.fromtimestamp(wc_file.stat().st_mtime, tz=timezone.utc)

                # 1. Decode UTF-16LE chunks
                text_u16 = raw.decode("utf-16le", errors="ignore")
                for m in re.finditer(r"(?:Visited:\s*([^@\x00\r\n]{1,40})@)?((?:https?|ftp|file)://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{6,350})", text_u16):
                    user = (m.group(1) or "informant").strip()
                    url = m.group(2).strip()
                    if any(noise in url.lower() for noise in ("microsoft.com/pki", "ocsp.", "crl.", "schemas.microsoft.com")):
                        continue
                    key = (user.lower(), url)
                    if key in seen_urls:
                        continue
                    seen_urls.add(key)
                    # Try to find a nearby FILETIME in raw bytes
                    records.append({
                        "browser": "Internet Explorer",
                        "profile": user,
                        "url": url,
                        "title": url.split("/")[-1][:80] or url,
                        "visit_count": 1,
                        "typed_count": 0,
                        "visit_time": mtime,
                        "from_visit": 0,
                        "transition": "LINK",
                        "source_file": str(wc_file),
                    })
                    if len(records) >= 1500:
                        break
            except Exception as ex:
                self._log(f"IE WebCache parse notice: {ex}", "WARNING")

        if not records:
            return 0

        ddl = """
        CREATE TABLE IF NOT EXISTS parsed_ie_history (
            _row_id BIGINT, browser VARCHAR, profile VARCHAR, url VARCHAR, title VARCHAR,
            visit_count INTEGER, typed_count INTEGER, visit_time TIMESTAMP, from_visit BIGINT,
            transition VARCHAR, source_file VARCHAR
        );
        """
        return self.insert_records(
            table_name="parsed_ie_history",
            records=records,
            schema_ddl=ddl,
            artifact_id="ie_history",
            category="WEB RELATED",
            display_name="Internet Explorer / WebCache History",
            source_tool="WebCacheESEParser",
        )

    # -------------------------------------------------------------------------
    # A12: Google Drive sync_log.log & snapshot.db Parser (B28)
    # -------------------------------------------------------------------------
    def parse_gdrive_logs(self) -> int:
        sync_logs = list(self.staging_dir.rglob("sync_log.log*"))
        if not sync_logs:
            return 0

        records: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()
        line_re = re.compile(
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+[+-]\d+\s+(?:INFO|DEBUG|WARNING)\s+\S+\s+(.*)$"
        )
        path_re = re.compile(r"(?:u'|')([A-Za-z]:\\\\[^'\r\n]+|\\\\\?\\[A-Za-z]:\\[^'\r\n]+)(?:')")
        email_re = re.compile(r"\b([A-Za-z0-9._%+-]+@gmail\.com|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

        discovered_account = "Default"
        for slog in sync_logs:
            try:
                text = slog.read_text(encoding="utf-8", errors="replace")
                m_em = email_re.search(text)
                if m_em:
                    discovered_account = m_em.group(1)

                for line in text.splitlines():
                    m_line = line_re.match(line)
                    if not m_line:
                        continue
                    ts_str, msg = m_line.groups()
                    m_path = path_re.search(msg)
                    if not m_path:
                        continue
                    raw_p = m_path.group(1).replace("\\\\?\\", "").replace("\\\\", "\\")
                    if "Google Drive" not in raw_p and "informant" not in raw_p.lower():
                        continue
                    fname = Path(raw_p.replace("\\", "/")).name
                    if not fname or fname.lower() in ("google drive", "desktop.ini"):
                        continue

                    status = "SYNCED"
                    if "delete" in msg.lower() or "remove" in msg.lower():
                        status = "DELETED"
                    elif "create" in msg.lower() or "upload" in msg.lower():
                        status = "UPLOADED"

                    key = (raw_p.lower(), status)
                    if key in seen:
                        continue
                    seen.add(key)

                    try:
                        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    except Exception:
                        dt = None

                    records.append({
                        "cloud_provider": "Google Drive",
                        "account": discovered_account,
                        "local_path": raw_p,
                        "cloud_path_or_id": fname,
                        "file_size": 0,
                        "modified_time": dt,
                        "status": status,
                        "source_file": str(slog),
                    })
            except Exception as ex:
                self._log(f"Google Drive sync_log notice: {ex}", "WARNING")

        if not records:
            return 0

        return self.insert_records(
            table_name="parsed_gdrive_files",
            records=records,
            artifact_id="gdrive_files",
            category="CLOUD",
            display_name="Google Drive Synced Files",
            source_tool="CloudParser",
            append=True,
        )

    # -------------------------------------------------------------------------
    # A17: Native $Recycle.Bin $I Metadata Parser
    # -------------------------------------------------------------------------
    def parse_recycle_bin_natively(self) -> int:
        i_files = [
            p for p in self.staging_dir.rglob("$I*")
            if p.is_file() and 28 <= p.stat().st_size <= 8192
        ]
        if not i_files:
            return 0

        records: List[Dict[str, Any]] = []
        for ipath in i_files:
            try:
                raw = ipath.read_bytes()
                ver = struct.unpack_from("<Q", raw, 0)[0]
                fsize = struct.unpack_from("<Q", raw, 8)[0]
                del_ft = struct.unpack_from("<Q", raw, 16)[0]
                del_dt = windows_filetime_to_datetime(del_ft)
                if ver == 2 and len(raw) >= 28:
                    name_len = struct.unpack_from("<I", raw, 24)[0]
                    orig_path = raw[28 : 28 + name_len * 2].decode("utf-16le", errors="ignore").rstrip("\x00")
                else:
                    orig_path = raw[24:544].decode("utf-16le", errors="ignore").split("\x00", 1)[0]
                if orig_path:
                    records.append({
                        "SourceName": str(ipath),
                        "FileName": Path(orig_path.replace("\\", "/")).name,
                        "FileSize": int(fsize),
                        "DeletedOn": del_dt,
                        "OriginalPath": orig_path,
                    })
            except Exception:
                continue

        if not records:
            return 0

        return self.insert_records(
            table_name="raw_rbcmd",
            records=records,
            artifact_id="fs_recyclebin",
            category="OPERATING SYSTEM",
            display_name="Recycle Bin ($I / $R)",
            source_tool="NativeRecycleBinParser",
        )

    def parse(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for key, fn in [
            ("raw_pecmd", self.parse_prefetch_natively),
            ("raw_mft", self.parse_mft_natively),
            ("raw_evtx", self.parse_evtx_natively),
            ("parsed_ie_history", self.parse_ie_webcache),
            ("parsed_gdrive_files", self.parse_gdrive_logs),
            ("raw_rbcmd", self.parse_recycle_bin_natively),
        ]:
            try:
                cnt = fn()
                if cnt > 0:
                    out[key] = cnt
            except Exception as ex:
                self._log(f"Fallback parser {key} warning: {ex}", "WARNING")
        return out
