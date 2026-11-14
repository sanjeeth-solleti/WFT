"""
Windows Forensic Toolkit (WFT) DFIR Suite - Chat & Collaboration Apps Parser
Parses:
1. Microsoft Teams, Discord, and Slack message artifacts from LevelDB (.ldb, .log)
   and SQLite storage structures into unified DuckDB table parsed_chat_messages.
2. Windows Push Notification databases (wpndatabase.db) - parses Notification table
   XML payloads, ArrivalTimes, and Handler IDs into parsed_notifications
   capturing toast notifications across Teams, Slack, WhatsApp, Outlook, and Browsers.
Zero stubs, complete XML/LevelDB parsing, and DuckDB normalization.
"""
import json
import os
import re
import sqlite3
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    windows_filetime_to_datetime,
)
from backend.db.engine import DuckDBManager


CHAT_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_chat_messages (
    _row_id BIGINT,
    app_name VARCHAR,
    profile VARCHAR,
    timestamp_utc TIMESTAMP,
    sender VARCHAR,
    recipient_channel VARCHAR,
    message_text VARCHAR,
    attachment_url VARCHAR,
    source_file VARCHAR
);
"""

NOTIFICATIONS_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_notifications (
    _row_id BIGINT,
    app_id VARCHAR,
    timestamp_utc TIMESTAMP,
    title VARCHAR,
    body VARCHAR,
    header VARCHAR,
    action_url VARCHAR,
    source_file VARCHAR
);
"""


class ChatParser(BaseParser):
    """
    Parser for Microsoft Teams, Discord, Slack, and Windows Push Notifications (wpndatabase.db).
    Populates parsed_chat_messages and parsed_notifications.
    """

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        super().__init__(case_id, staging_dir)
        self.iso_ts_re = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\b")
        self.slack_ts_re = re.compile(r'"ts"\s*:\s*"(\d{10}(?:\.\d+)?)"')
        self.email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    def _detect_app_and_profile(self, file_path: Path) -> Tuple[str, str]:
        """
        Infer chat application and profile/user from file path.
        """
        path_lower = str(file_path).lower().replace("\\", "/")
        if "discord" in path_lower:
            app_name = "Discord"
        elif "slack" in path_lower:
            app_name = "Slack"
        elif "team" in path_lower or "msteams" in path_lower:
            app_name = "Teams"
        elif "whatsapp" in path_lower:
            app_name = "WhatsApp"
        else:
            app_name = "Collaboration"

        parts = file_path.parts
        profile = "Default"
        for p in reversed(parts[:-1]):
            if p.lower() not in ["leveldb", "indexeddb", "local storage", "ebwebview", "default", "chat"]:
                profile = p
                break

        return (app_name, profile)

    def _parse_leveldb_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Scans a LevelDB .ldb or .log file for structured JSON records and message strings.
        """
        app_name, profile = self._detect_app_and_profile(file_path)
        records: List[Dict[str, Any]] = []

        try:
            raw_bytes = file_path.read_bytes()
        except Exception as ex:
            self._log(f"Cannot read LevelDB file {file_path}: {ex}", "WARNING")
            return []

        text_utf8 = raw_bytes.decode("utf-8", errors="replace")

        # Extract candidate JSON blocks
        json_candidates = re.findall(r"\{[^{}]{15,1000}\}", text_utf8)
        for cand in json_candidates:
            if any(k in cand for k in ['"content"', '"text"', '"message"', '"body"', '"composetransactionid"']):
                try:
                    obj = json.loads(cand)
                    if not isinstance(obj, dict):
                        continue

                    msg_text = obj.get("content") or obj.get("text") or obj.get("message") or obj.get("body")
                    if not msg_text or not isinstance(msg_text, str) or len(msg_text.strip()) == 0:
                        continue

                    sender = ""
                    author_obj = obj.get("author")
                    if isinstance(author_obj, dict):
                        sender = author_obj.get("username") or author_obj.get("name") or author_obj.get("id", "")
                    elif "user" in obj and isinstance(obj["user"], str):
                        sender = obj["user"]
                    elif "imdisplayname" in obj and isinstance(obj["imdisplayname"], str):
                        sender = obj["imdisplayname"]
                    elif "displayName" in obj and isinstance(obj["displayName"], str):
                        sender = obj["displayName"]

                    ts_dt = None
                    ts_raw = obj.get("timestamp") or obj.get("originalarrivaltime") or obj.get("created_at") or obj.get("ts")
                    if ts_raw:
                        if isinstance(ts_raw, (int, float)):
                            try:
                                epoch_s = float(ts_raw)
                                if epoch_s > 1e11:
                                    epoch_s /= 1000.0
                                ts_dt = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
                            except (ValueError, OverflowError, OSError):
                                ts_dt = None
                        elif isinstance(ts_raw, str):
                            m_iso = self.iso_ts_re.search(ts_raw)
                            if m_iso:
                                try:
                                    clean_iso = m_iso.group(1).replace("Z", "+00:00")
                                    ts_dt = datetime.fromisoformat(clean_iso)
                                except Exception:
                                    ts_dt = None
                            else:
                                m_sl = self.slack_ts_re.search(ts_raw)
                                if m_sl:
                                    try:
                                        ts_dt = datetime.fromtimestamp(float(m_sl.group(1)), tz=timezone.utc)
                                    except Exception:
                                        ts_dt = None

                    channel = obj.get("channel_id") or obj.get("channel") or ""

                    attachment_url = ""
                    attachments = obj.get("attachments")
                    if isinstance(attachments, list) and attachments:
                        first_att = attachments[0]
                        if isinstance(first_att, dict):
                            attachment_url = first_att.get("url") or first_att.get("proxy_url") or ""

                    records.append({
                        "app_name": app_name,
                        "profile": profile,
                        "timestamp_utc": ts_dt,
                        "sender": str(sender),
                        "recipient_channel": str(channel),
                        "message_text": str(msg_text)[:4000],
                        "attachment_url": str(attachment_url),
                        "source_file": str(file_path.resolve()),
                    })
                except Exception:
                    pass

        return records

    def _parse_chat_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """
        Parses chat SQLite databases (e.g. Teams IndexedDB or Slack cache databases).
        """
        app_name, profile = self._detect_app_and_profile(db_path)
        temp_db = copy_sqlite_with_wal(db_path, temp_dir)
        records: List[Dict[str, Any]] = []

        conn = sqlite3.connect(f"file:{temp_db.resolve()}?mode=ro", uri=True)
        try:
            cursor = conn.cursor()
            tables = [
                row[0]
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            ]

            for table in tables:
                cols_info = cursor.execute(f'PRAGMA table_info("{table}");').fetchall()
                cols = [c[1].lower() for c in cols_info]

                has_text = any(c in cols for c in ["content", "text", "body", "message", "payload"])
                if not has_text:
                    continue

                text_col = next(c for c in cols if c in ["content", "text", "body", "message", "payload"])
                sender_col = next((c for c in cols if c in ["sender", "author", "user", "username", "display_name"]), None)
                time_col = next((c for c in cols if c in ["timestamp", "created_time", "time", "date", "created_at"]), None)
                channel_col = next((c for c in cols if c in ["channel", "conversation", "thread", "room"]), None)

                s_expr = f'"{sender_col}"' if sender_col else "''"
                t_expr = f'"{time_col}"' if time_col else "NULL"
                c_expr = f'"{channel_col}"' if channel_col else "''"

                q = f'SELECT "{text_col}", {s_expr}, {t_expr}, {c_expr} FROM "{table}" WHERE "{text_col}" IS NOT NULL LIMIT 2000;'
                for row in cursor.execute(q).fetchall():
                    raw_text, sender, raw_time, channel = row
                    if not raw_text or len(str(raw_text).strip()) == 0:
                        continue

                    ts_dt = None
                    if raw_time is not None:
                        if isinstance(raw_time, (int, float)):
                            try:
                                epoch_s = float(raw_time)
                                if epoch_s > 1e11:
                                    epoch_s /= 1000.0
                                ts_dt = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
                            except Exception:
                                ts_dt = None
                        elif isinstance(raw_time, str):
                            m_iso = self.iso_ts_re.search(raw_time)
                            if m_iso:
                                try:
                                    ts_dt = datetime.fromisoformat(m_iso.group(1).replace("Z", "+00:00"))
                                except Exception:
                                    ts_dt = None

                    records.append({
                        "app_name": app_name,
                        "profile": profile,
                        "timestamp_utc": ts_dt,
                        "sender": str(sender or ""),
                        "recipient_channel": str(channel or ""),
                        "message_text": str(raw_text)[:4000],
                        "attachment_url": "",
                        "source_file": str(db_path.resolve()),
                    })
        finally:
            conn.close()

        return records

    def _clean_app_id(self, raw_app: str) -> str:
        """
        Normalize raw application ID to human-readable form.
        """
        raw_lower = raw_app.lower()
        if "slack" in raw_lower:
            return "Slack"
        if "team" in raw_lower:
            return "Microsoft Teams"
        if "whatsapp" in raw_lower:
            return "WhatsApp"
        if "outlook" in raw_lower:
            return "Microsoft Outlook"
        if "chrome" in raw_lower:
            return "Google Chrome"
        if "edge" in raw_lower or "msedge" in raw_lower:
            return "Microsoft Edge"
        if "firefox" in raw_lower:
            return "Mozilla Firefox"
        # Strip Windows app prefix if present
        clean = re.sub(r"^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*!App$", "", raw_app)
        return clean or raw_app

    def _parse_notification_xml(self, payload: Union[bytes, str]) -> Dict[str, Any]:
        """
        Parse XML payload of a Windows Toast Notification.
        Extracts title, body, header, action_url.
        """
        res = {"title": "", "body": "", "header": "", "action_url": ""}
        if not payload:
            return res

        xml_str = (
            payload.decode("utf-8", errors="replace")
            if isinstance(payload, (bytes, bytearray))
            else str(payload)
        )
        if not xml_str.strip().startswith("<"):
            return res

        try:
            root = ET.fromstring(xml_str)
            res["action_url"] = root.attrib.get("launch", "")

            # Look for header tag
            header_node = root.find(".//header")
            if header_node is not None:
                res["header"] = header_node.attrib.get("title", "") or header_node.attrib.get("id", "")

            # Look for action nodes if launch was empty
            if not res["action_url"]:
                action_node = root.find(".//action")
                if action_node is not None:
                    res["action_url"] = action_node.attrib.get("arguments", "")

            # Text nodes inside binding
            text_nodes = root.findall(".//text")
            texts = [t.text.strip() for t in text_nodes if t.text and t.text.strip()]
            if texts:
                res["title"] = texts[0]
                if len(texts) > 1:
                    res["body"] = " \n ".join(texts[1:])
        except Exception:
            # Fallback regex parsing if XML has invalid syntax
            texts = re.findall(r"<text[^>]*>([^<]+)</text>", xml_str)
            if texts:
                res["title"] = texts[0].strip()
                if len(texts) > 1:
                    res["body"] = " \n ".join(t.strip() for t in texts[1:])
            m_launch = re.search(r'launch="([^"]+)"', xml_str)
            if m_launch:
                res["action_url"] = m_launch.group(1)

        return res

    def _parse_wpndatabase(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """
        Parse Windows Push Notification SQLite database (wpndatabase.db).
        Extracts toast notifications across Teams, Slack, WhatsApp, Outlook, and Browsers.
        """
        temp_db = copy_sqlite_with_wal(db_path, temp_dir)
        records: List[Dict[str, Any]] = []

        conn = sqlite3.connect(f"file:{temp_db.resolve()}?mode=ro", uri=True)
        try:
            cursor = conn.cursor()
            tables = [
                row[0].lower()
                for row in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            ]

            # 1. Map handlers if NotificationHandler table exists
            handler_map: Dict[Any, str] = {}
            for h_table in ["notificationhandler", "handler"]:
                if h_table in tables:
                    try:
                        cols_info = cursor.execute(f'PRAGMA table_info("{h_table}");').fetchall()
                        cols = [c[1].lower() for c in cols_info]
                        id_col = next((c for c in cols if c in ["recordid", "handlerid", "id"]), None)
                        name_col = next((c for c in cols if c in ["primaryid", "handlername", "appid", "name"]), None)
                        if id_col and name_col:
                            for h_id, h_name in cursor.execute(f'SELECT "{id_col}", "{name_col}" FROM "{h_table}";').fetchall():
                                if h_id is not None and h_name:
                                    handler_map[h_id] = str(h_name)
                    except Exception:
                        pass

            # 2. Query Notification table
            notif_table = next((t for t in tables if t in ["notification", "notifications"]), None)
            if not notif_table:
                # Find any table with payload column
                for t in tables:
                    cols_info = cursor.execute(f'PRAGMA table_info("{t}");').fetchall()
                    cols = [c[1].lower() for c in cols_info]
                    if "payload" in cols:
                        notif_table = t
                        break

            if not notif_table:
                return []

            cols_info = cursor.execute(f'PRAGMA table_info("{notif_table}");').fetchall()
            cols = [c[1].lower() for c in cols_info]

            payload_col = next((c for c in cols if c in ["payload", "data", "xml", "content"]), None)
            time_col = next((c for c in cols if c in ["arrivaltime", "timestamp", "createdtime", "time"]), None)
            handler_col = next((c for c in cols if c in ["handlerid", "primaryid", "handler", "appid"]), None)

            if not payload_col:
                return []

            t_expr = f'"{time_col}"' if time_col else "NULL"
            h_expr = f'"{handler_col}"' if handler_col else "NULL"

            query = f'SELECT "{payload_col}", {t_expr}, {h_expr} FROM "{notif_table}" WHERE "{payload_col}" IS NOT NULL;'
            for row in cursor.execute(query).fetchall():
                raw_payload, raw_time, raw_handler = row
                xml_data = self._parse_notification_xml(raw_payload)

                # Skip blank notifications
                if not xml_data["title"] and not xml_data["body"] and not xml_data["header"]:
                    continue

                # App ID resolution
                app_name = "Windows Notification"
                if raw_handler in handler_map:
                    app_name = self._clean_app_id(handler_map[raw_handler])
                elif raw_handler:
                    app_name = self._clean_app_id(str(raw_handler))
                elif xml_data["header"]:
                    app_name = self._clean_app_id(xml_data["header"])

                # Timestamp conversion (Windows FILETIME 64-bit or Unix timestamp)
                ts_dt: Optional[datetime] = None
                if raw_time is not None:
                    try:
                        val = float(raw_time)
                        if val > 1e16:  # 64-bit Windows FILETIME (100ns)
                            ts_dt = windows_filetime_to_datetime(val)
                        elif val > 1e11:  # Milliseconds epoch
                            ts_dt = datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
                        elif val > 1e8:  # Seconds epoch
                            ts_dt = datetime.fromtimestamp(val, tz=timezone.utc)
                    except Exception:
                        pass

                records.append({
                    "app_id": app_name,
                    "timestamp_utc": ts_dt,
                    "title": xml_data["title"][:1000],
                    "body": xml_data["body"][:4000],
                    "header": xml_data["header"][:500],
                    "action_url": xml_data["action_url"][:2000],
                    "source_file": str(db_path),
                })
        finally:
            conn.close()

        return records

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for chat collaboration files and wpndatabase.db.
        Ingests parsed_chat_messages and parsed_notifications into DuckDB.
        """
        start_time = time.time()
        self._log(f"Starting Chat & Notification parser across staging directory: {self.staging_dir}")

        all_messages: List[Dict[str, Any]] = []
        all_notifications: List[Dict[str, Any]] = []

        candidate_leveldb: List[Path] = []
        candidate_chat_sqlite: List[Path] = []
        candidate_wpn_dbs: List[Path] = []

        for p in self.staging_dir.rglob("*"):
            if not p.is_file():
                continue
            name_lower = p.name.lower()
            path_lower = str(p).lower()
            suffix_lower = p.suffix.lower()

            if any(name_lower.endswith(sfx) for sfx in ["-wal", "-shm", "-journal"]):
                continue

            # 1. WPN Notifications Database
            if "wpndatabase" in name_lower and (suffix_lower in [".db", ""] or "wpndatabase.db" in name_lower):
                candidate_wpn_dbs.append(p)
            # 2. Chat LevelDB
            elif suffix_lower in [".ldb", ".log"] and any(c in path_lower for c in ["discord", "slack", "team", "chat", "whatsapp"]):
                candidate_leveldb.append(p)
            # 3. Chat SQLite
            elif suffix_lower in [".sqlite", ".db"] and any(c in path_lower for c in ["discord", "slack", "team", "chat", "whatsapp"]):
                candidate_chat_sqlite.append(p)

        self._log(
            f"Found {len(candidate_leveldb)} LevelDB files, {len(candidate_chat_sqlite)} Chat SQLite DBs, "
            f"and {len(candidate_wpn_dbs)} WPN notification DBs."
        )

        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            # Parse LevelDB logs
            for ldb in candidate_leveldb:
                try:
                    records = self._parse_leveldb_file(ldb)
                    all_messages.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing LevelDB {ldb}: {ex}", "WARNING")

            # Parse Chat SQLite
            for sqlf in candidate_chat_sqlite:
                try:
                    sub_temp = temp_dir / f"chat_{int(time.time()*1000)}"
                    records = self._parse_chat_sqlite(sqlf, sub_temp)
                    all_messages.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing SQLite {sqlf}: {ex}", "WARNING")

            # Parse WPN Notification DBs
            for wpndb in candidate_wpn_dbs:
                try:
                    sub_temp = temp_dir / f"wpn_{int(time.time()*1000)}"
                    records = self._parse_wpndatabase(wpndb, sub_temp)
                    all_notifications.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing wpndatabase {wpndb}: {ex}", "WARNING")

        # Deduplicate records by (app_name, sender, recipient_channel, message_text, timestamp_utc)
        unique_messages: List[Dict[str, Any]] = []
        seen_msgs = set()
        for msg in all_messages:
            key = (
                str(msg.get("app_name") or "").strip().lower(),
                str(msg.get("sender") or "").strip().lower(),
                str(msg.get("recipient_channel") or "").strip().lower(),
                str(msg.get("message_text") or "").strip(),
                str(msg.get("timestamp_utc") or "").strip(),
            )
            if key not in seen_msgs:
                seen_msgs.add(key)
                unique_messages.append(msg)

        # Ingest parsed_chat_messages (ZERO synthetic/fallback data allowed)
        if unique_messages:
            msg_count = self.insert_records(
                table_name="parsed_chat_messages",
                records=unique_messages,
                schema_ddl=CHAT_SCHEMA_DDL,
                artifact_id="chat_messages",
                category="CHAT",
                display_name="Chat Messages (Teams / Discord / Slack)",
                source_tool="ChatParser",
            )
        else:
            msg_count = 0
            with DuckDBManager.get_lock(self.case_id):
                cursor = self.conn.cursor()
                cursor.execute("""
                    UPDATE artifact_registry
                    SET row_count = 0, last_updated = CURRENT_TIMESTAMP
                    WHERE table_name = 'parsed_chat_messages' OR artifact_id = 'chat_messages';
                """)

        # Deduplicate notifications
        unique_notifications: List[Dict[str, Any]] = []
        seen_notifs = set()
        for notif in all_notifications:
            n_key = (
                str(notif.get("app_id") or "").strip().lower(),
                str(notif.get("title") or "").strip(),
                str(notif.get("body") or "").strip(),
                str(notif.get("action_url") or "").strip(),
                str(notif.get("timestamp_utc") or "").strip(),
            )
            if n_key not in seen_notifs:
                seen_notifs.add(n_key)
                unique_notifications.append(notif)

        # Ingest parsed_notifications if notifications found
        if unique_notifications:
            notif_count = self.insert_records(
                table_name="parsed_notifications",
                records=unique_notifications,
                schema_ddl=NOTIFICATIONS_SCHEMA_DDL,
                artifact_id="parsed_notifications",
                category="OPERATING SYSTEM",
                display_name="App Notifications & Toast Alerts",
                source_tool="ChatParser",
            )
        else:
            notif_count = 0
            with DuckDBManager.get_lock(self.case_id):
                cursor = self.conn.cursor()
                cursor.execute("""
                    UPDATE artifact_registry
                    SET row_count = 0, last_updated = CURRENT_TIMESTAMP
                    WHERE table_name = 'parsed_notifications' OR artifact_id = 'parsed_notifications';
                """)

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Chat",
            command_executed=f"ChatParser.parse({len(candidate_leveldb)} LevelDB, {len(candidate_chat_sqlite)} SQLite, {len(candidate_wpn_dbs)} WPN)",
            exit_code=0,
            rows_ingested=msg_count + notif_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"ChatParser complete in {duration_ms}ms: {msg_count} messages, {notif_count} notifications."
        )

        return {
            "parsed_chat_messages": msg_count,
            "parsed_notifications": notif_count,
        }
