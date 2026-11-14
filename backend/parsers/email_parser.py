"""
Windows Forensic Toolkit (WFT) DFIR Suite - Corporate Email & Mail Store Parser
Parses:
1. RFC 822 Email messages (.eml) via standard library email package
2. MBOX mail storage (.mbox) via standard library mailbox package
3. Microsoft Outlook Compound File Binary Messages (.msg) via extract_msg
4. Microsoft Outlook Personal Storage Tables (.pst, .ost) via pstreader
Extracts:
  - Sender, Recipients, CC, BCC, Subject, DateUTC, MessageID, BodySnippet, AttachmentNames
Saves all discovered attachments back into staging/Extracted_Archives/Email_Attachments/
so YARA-X compiled scanning and RapidOCR automatically inspect corporate email payloads!
Populates DuckDB table parsed_emails with zero stubs.
"""
import email
import email.policy
import email.utils
import hashlib
import json
import mailbox
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# MSG and PST parser imports
try:
    import extract_msg
except ImportError:
    extract_msg = None

try:
    import pstreader
except ImportError:
    pstreader = None

from backend.parsers.base_parser import BaseParser
from backend.db.engine import DuckDBManager


EMAIL_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_emails (
    _row_id BIGINT,
    email_format VARCHAR,
    sender VARCHAR,
    recipients VARCHAR,
    cc VARCHAR,
    bcc VARCHAR,
    subject VARCHAR,
    date_utc TIMESTAMP,
    message_id VARCHAR,
    body_snippet VARCHAR,
    attachment_count INTEGER,
    attachment_names VARCHAR,
    extracted_attachments_dir VARCHAR,
    source_file VARCHAR
);
"""


def compute_sha256(data: bytes) -> str:
    """
    Compute lowercase hexadecimal SHA256 digest of bytes.
    """
    return hashlib.sha256(data).hexdigest().lower()


def sanitize_filename(filename: str, fallback: str = "attachment.bin") -> str:
    """
    Sanitize filename against path traversal and forbidden characters.
    """
    if not filename or not isinstance(filename, str):
        return fallback
    clean = os.path.basename(filename.strip().replace("\\", "/"))
    clean = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", clean)
    if not clean or clean in [".", ".."]:
        return fallback
    return clean[:200]


def parse_rfc2822_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse RFC 2822 email Date header to UTC datetime.
    """
    if not date_str:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    # Fallback to ISO format
    try:
        dt = datetime.fromisoformat(str(date_str).strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


class EmailParser(BaseParser):
    """
    Forensic email and mail store parser (.eml, .msg, .mbox, .pst, .ost).
    Populates parsed_emails and extracts attachments to staging/Extracted_Archives/Email_Attachments/.
    """

    EMAIL_EXTS = {".eml", ".msg", ".mbox", ".pst", ".ost"}

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        super().__init__(case_id, staging_dir)
        # Direct attachment destination into Extracted_Archives so YARA & OCR pick them up
        self.attachments_dir = self.staging_dir / "Extracted_Archives" / "Email_Attachments"
        self.attachments_dir.mkdir(parents=True, exist_ok=True)

    def _save_attachment(self, filename: str, data: bytes, email_source: str) -> Optional[str]:
        """
        Write attachment bytes safely to self.attachments_dir.
        Returns the saved file name.
        """
        if not data or len(data) == 0:
            return None
        clean_name = sanitize_filename(filename)
        h = compute_sha256(data)
        dest_filename = f"{h[:8]}_{clean_name}"
        dest_path = self.attachments_dir / dest_filename
        try:
            dest_path.write_bytes(data)
            return dest_filename
        except Exception as ex:
            self._log(f"Failed to save email attachment {filename} from {email_source}: {ex}", "WARNING")
            return None

    def _parse_eml_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse .eml email file.
        """
        records: List[Dict[str, Any]] = []
        try:
            with open(file_path, "rb") as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
        except Exception as ex:
            self._log(f"Failed to parse .eml file {file_path.name}: {ex}", "WARNING")
            return []

        sender = str(msg.get("from") or "").strip()
        recipients = str(msg.get("to") or "").strip()
        cc = str(msg.get("cc") or "").strip()
        bcc = str(msg.get("bcc") or "").strip()
        subject = str(msg.get("subject") or "").strip()
        message_id = str(msg.get("message-id") or "").strip()
        date_utc = parse_rfc2822_date(msg.get("date"))

        # Extract body snippet
        body_text = ""
        try:
            body_part = msg.get_body(preferencelist=("plain", "html"))
            if body_part:
                body_text = body_part.get_content()
        except Exception:
            pass

        if not body_text:
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode("utf-8", errors="replace")
                        break

        # Clean HTML tags for body snippet
        snippet = re.sub(r"<[^>]+>", " ", str(body_text))
        snippet = " ".join(snippet.split())[:2000]

        # Extract attachments
        saved_attachments: List[str] = []
        for part in msg.walk():
            # Skip container multipart
            if part.is_multipart():
                continue
            cdisp = str(part.get("content-disposition", "")).lower()
            fname = part.get_filename()
            if fname or "attachment" in cdisp:
                payload = part.get_payload(decode=True)
                if payload:
                    att_name = fname or f"attachment_{len(saved_attachments)+1}.bin"
                    saved = self._save_attachment(att_name, payload, file_path.name)
                    if saved:
                        saved_attachments.append(att_name)

        records.append({
            "email_format": "EML",
            "sender": sender,
            "recipients": recipients,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "date_utc": date_utc,
            "message_id": message_id,
            "body_snippet": snippet,
            "attachment_count": len(saved_attachments),
            "attachments_count": len(saved_attachments),
            "attachment_names": ", ".join(saved_attachments),
            "extracted_attachments_dir": str(self.attachments_dir),
            "source_file": str(file_path),
        })

        return records

    def _parse_mbox_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse .mbox email archive.
        """
        records: List[Dict[str, Any]] = []
        try:
            mbox = mailbox.mbox(str(file_path))
        except Exception as ex:
            self._log(f"Failed to open .mbox file {file_path.name}: {ex}", "WARNING")
            return []

        for idx, msg in enumerate(mbox):
            sender = str(msg.get("from") or "").strip()
            recipients = str(msg.get("to") or "").strip()
            cc = str(msg.get("cc") or "").strip()
            bcc = str(msg.get("bcc") or "").strip()
            subject = str(msg.get("subject") or "").strip()
            message_id = str(msg.get("message-id") or "").strip()
            date_utc = parse_rfc2822_date(msg.get("date"))

            # Extract body
            body_text = ""
            saved_attachments: List[str] = []
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdisp = str(part.get("content-disposition", "")).lower()
                    fname = part.get_filename()
                    if fname or "attachment" in cdisp:
                        payload = part.get_payload(decode=True)
                        if payload:
                            att_name = fname or f"mbox_att_{idx}_{len(saved_attachments)+1}.bin"
                            saved = self._save_attachment(att_name, payload, file_path.name)
                            if saved:
                                saved_attachments.append(att_name)
                    elif ctype in ["text/plain", "text/html"] and not body_text:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode("utf-8", errors="replace")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode("utf-8", errors="replace")

            snippet = re.sub(r"<[^>]+>", " ", str(body_text))
            snippet = " ".join(snippet.split())[:2000]

            records.append({
                "email_format": "MBOX",
                "sender": sender,
                "recipients": recipients,
                "cc": cc,
                "bcc": bcc,
                "subject": subject,
                "date_utc": date_utc,
                "message_id": message_id,
                "body_snippet": snippet,
                "attachment_count": len(saved_attachments),
            "attachments_count": len(saved_attachments),
                "attachment_names": ", ".join(saved_attachments),
                "extracted_attachments_dir": str(self.attachments_dir),
                "source_file": str(file_path),
            })

        return records

    def _parse_msg_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse Microsoft Outlook .msg binary compound file.
        """
        if extract_msg is None:
            self._log("extract-msg package is not available, skipping .msg parsing", "WARNING")
            return []

        records: List[Dict[str, Any]] = []
        try:
            msg = extract_msg.openMsg(str(file_path))
            sender = str(msg.sender or "").strip()
            recipients = str(msg.to or "").strip()
            cc = str(msg.cc or "").strip()
            bcc = str(msg.bcc or "").strip()
            subject = str(msg.subject or "").strip()
            message_id = str(getattr(msg, "messageId", "") or "").strip()

            date_raw = msg.date
            date_utc: Optional[datetime] = None
            if isinstance(date_raw, datetime):
                date_utc = date_raw.replace(tzinfo=timezone.utc) if date_raw.tzinfo is None else date_raw.astimezone(timezone.utc)
            elif date_raw:
                date_utc = parse_rfc2822_date(str(date_raw))

            body = str(msg.body or "").strip()
            snippet = " ".join(body.split())[:2000]

            saved_attachments: List[str] = []
            for att in getattr(msg, "attachments", []):
                fname = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
                data = getattr(att, "data", None)
                if data:
                    att_name = fname or f"msg_att_{len(saved_attachments)+1}.dat"
                    saved = self._save_attachment(att_name, data, file_path.name)
                    if saved:
                        saved_attachments.append(att_name)

            msg.close()

            records.append({
                "email_format": "MSG",
                "sender": sender,
                "recipients": recipients,
                "cc": cc,
                "bcc": bcc,
                "subject": subject,
                "date_utc": date_utc,
                "message_id": message_id,
                "body_snippet": snippet,
                "attachment_count": len(saved_attachments),
            "attachments_count": len(saved_attachments),
                "attachment_names": ", ".join(saved_attachments),
                "extracted_attachments_dir": str(self.attachments_dir),
                "source_file": str(file_path),
            })
        except Exception as ex:
            self._log(f"Error parsing .msg file {file_path.name}: {ex}", "WARNING")

        return records

    def _parse_pst_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse Microsoft Outlook .pst or .ost personal folder store via pstreader.
        """
        if pstreader is None:
            self._log("pstreader package is not available, skipping .pst/.ost parsing", "WARNING")
            return []

        records: List[Dict[str, Any]] = []
        ext_fmt = file_path.suffix.lstrip(".").upper()

        try:
            store = pstreader.open(str(file_path))
            root = store.root_folder

            def _traverse(folder: Any) -> None:
                for msg in folder.messages:
                    try:
                        subject = str(getattr(msg, "subject", "") or "").strip()
                        sender_name = getattr(msg, "sender_name", "") or ""
                        sender_email = getattr(msg, "sender_email", "") or getattr(msg, "sender_smtp", "") or ""
                        sender = f"{sender_name} <{sender_email}>".strip() if sender_name and sender_email else (sender_email or sender_name or "")

                        # Extract recipients
                        recip_list: List[str] = []
                        cc_list: List[str] = []
                        for r in getattr(msg, "recipients", []):
                            r_name = getattr(r, "name", "") or ""
                            r_email = getattr(r, "email", "") or getattr(r, "smtp", "") or ""
                            r_str = f"{r_name} <{r_email}>".strip() if r_name and r_email else (r_email or r_name)
                            r_type = getattr(r, "type", None)
                            if str(r_type) in ["2", "CC", "RecipientType.CC"]:
                                cc_list.append(r_str)
                            else:
                                recip_list.append(r_str)

                        # Timestamp
                        dt_raw = getattr(msg, "delivery_time", None) or getattr(msg, "client_submit_time", None)
                        date_utc: Optional[datetime] = None
                        if isinstance(dt_raw, datetime):
                            date_utc = dt_raw.replace(tzinfo=timezone.utc) if dt_raw.tzinfo is None else dt_raw.astimezone(timezone.utc)

                        # Body snippet
                        body = getattr(msg, "body_text", "") or ""
                        if not body:
                            body = getattr(msg, "body_html", "") or ""
                        snippet = re.sub(r"<[^>]+>", " ", str(body))
                        snippet = " ".join(snippet.split())[:2000]

                        # Message ID from transport headers
                        msg_id = ""
                        headers = getattr(msg, "transport_headers", "") or ""
                        if headers:
                            m_id = re.search(r"(?i)Message-ID:\s*<([^>]+)>", headers)
                            if m_id:
                                msg_id = m_id.group(1)

                        # Attachments
                        saved_attachments: List[str] = []
                        for att in getattr(msg, "attachments", []):
                            fname = getattr(att, "filename", None) or getattr(att, "long_filename", None)
                            data = getattr(att, "data", None)
                            if data:
                                att_name = fname or f"pst_att_{len(saved_attachments)+1}.dat"
                                saved = self._save_attachment(att_name, data, file_path.name)
                                if saved:
                                    saved_attachments.append(att_name)

                        records.append({
                            "email_format": ext_fmt,
                            "sender": sender,
                            "recipients": ", ".join(recip_list),
                            "cc": ", ".join(cc_list),
                            "bcc": "",
                            "subject": subject,
                            "date_utc": date_utc,
                            "message_id": msg_id,
                            "body_snippet": snippet,
                            "attachment_count": len(saved_attachments),
            "attachments_count": len(saved_attachments),
                            "attachment_names": ", ".join(saved_attachments),
                            "extracted_attachments_dir": str(self.attachments_dir),
                            "source_file": str(file_path),
                        })
                    except Exception as m_ex:
                        self._log(f"Error parsing message in PST {file_path.name}: {m_ex}", "DEBUG")

                for sub in getattr(folder, "subfolders", []):
                    _traverse(sub)

            _traverse(root)
            store.close()

        except Exception as ex:
            self._log(f"Error opening PST/OST {file_path.name}: {ex}", "WARNING")

        return records

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for all corporate email stores (.eml, .msg, .mbox, .pst, .ost).
        Ingests parsed_emails table and saves attachments to staging/Extracted_Archives/Email_Attachments/.
        """
        start_time = time.time()
        self._log(f"Starting EmailParser across staging directory: {self.staging_dir}")

        all_records: List[Dict[str, Any]] = []
        candidate_emails: List[Path] = []

        for p in self.staging_dir.rglob("*"):
            if not p.is_file():
                continue
            sfx = p.suffix.lower()
            if sfx in self.EMAIL_EXTS:
                # Skip files inside already extracted attachment dirs
                if "extracted_archives" in str(p).lower() and "email_attachments" in str(p).lower():
                    continue
                candidate_emails.append(p)

        self._log(f"Discovered {len(candidate_emails)} email mail stores and messages.")

        for ef in candidate_emails:
            sfx = ef.suffix.lower()
            try:
                if sfx == ".eml":
                    recs = self._parse_eml_file(ef)
                elif sfx == ".mbox":
                    recs = self._parse_mbox_file(ef)
                elif sfx == ".msg":
                    recs = self._parse_msg_file(ef)
                elif sfx in [".pst", ".ost"]:
                    recs = self._parse_pst_file(ef)
                else:
                    continue
                all_records.extend(recs)
            except Exception as ex:
                self._log(f"Failed parsing email file {ef}: {ex}", "WARNING")

        # Deduplicate email records
        unique_emails: List[Dict[str, Any]] = []
        seen_emails = set()
        for rec in all_records:
            e_key = (
                str(rec.get("sender") or "").strip().lower(),
                str(rec.get("recipients") or "").strip().lower(),
                str(rec.get("subject") or "").strip().lower(),
                str(rec.get("date_utc") or "").strip(),
                str(rec.get("message_id") or "").strip(),
            )
            if e_key not in seen_emails:
                seen_emails.add(e_key)
                unique_emails.append(rec)

        # Ingest into DuckDB (ZERO synthetic/fallback data allowed)
        if unique_emails:
            row_count = self.insert_records(
                table_name="parsed_emails",
                records=unique_emails,
                schema_ddl=EMAIL_SCHEMA_DDL,
                artifact_id="emails",
                category="EMAIL",
                display_name="Emails (PST / OST / MSG / EML)",
                source_tool="EmailParser",
            )
        else:
            row_count = 0
            with DuckDBManager.get_lock(self.case_id):
                cursor = self.conn.cursor()
                cursor.execute("""
                    UPDATE artifact_registry
                    SET row_count = 0, last_updated = CURRENT_TIMESTAMP
                    WHERE table_name = 'parsed_emails' OR artifact_id = 'emails';
                """)

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Email",
            command_executed=f"EmailParser.parse({len(candidate_emails)} files)",
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(f"EmailParser complete in {duration_ms}ms with {row_count} email records ingested.")
        return {"parsed_emails": row_count}
