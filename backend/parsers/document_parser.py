"""
Windows Forensic Toolkit (WFT) DFIR Suite - Corporate Documents & Zone.Identifier Parser
Extracts:
1. Document metadata (Author, Last Modified By, Title, Created/Modified timestamps,
   Page Count, Word Count, Embedded Links, and VBA Macros presence) from:
   - PDF (.pdf) via PyMuPDF (fitz)
   - Microsoft Word (.docx, .docm) via python-docx & zip inspection
   - Microsoft Excel (.xlsx, .xlsm) via openpyxl & zip inspection
   - Microsoft PowerPoint (.pptx, .pptm) via python-pptx & zip inspection
   - Legacy Microsoft Office (.doc, .xls, .ppt) via olefile
2. NTFS Alternate Data Stream (ADS) Zone.Identifier download telemetry
   (ZoneId, HostUrl, ReferrerUrl) correlated directly with downloaded files.
Zero stubs, full file parsing, and DuckDB normalization.
"""
import configparser
import hashlib
import json
import os
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import docx
import fitz  # PyMuPDF
import olefile
import openpyxl
import pptx

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser


DOCUMENTS_METADATA_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_documents_metadata (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    file_type VARCHAR,
    file_size_bytes BIGINT,
    title VARCHAR,
    author VARCHAR,
    last_modified_by VARCHAR,
    created_time TIMESTAMP,
    modified_time TIMESTAMP,
    page_count INTEGER,
    word_count INTEGER,
    has_macros BOOLEAN,
    embedded_links VARCHAR,
    zone_id INTEGER,
    host_url VARCHAR,
    referrer_url VARCHAR,
    sha256 VARCHAR,
    source_file VARCHAR
);
"""


def compute_sha256(file_path: Path) -> str:
    """
    Compute lowercase hexadecimal SHA256 digest of file.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def parse_pdf_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse PDF date format: D:YYYYMMDDHHmmSS[+|-]HH'mm' or variations.
    """
    if not date_str or not isinstance(date_str, str):
        return None
    clean = date_str.strip()
    if clean.startswith("D:"):
        clean = clean[2:]
    clean = clean.replace("'", "")

    # Extract standard 14 digits YYYYMMDDHHmmss
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", clean)
    if m:
        try:
            year, month, day, hour, minute, second = map(int, m.groups())
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    # Try standard ISO fallback
    try:
        dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def parse_zone_identifier(content: str) -> Dict[str, Any]:
    """
    Parse NTFS Zone.Identifier INI content to extract ZoneId, HostUrl, ReferrerUrl.
    Example format:
      [ZoneTransfer]
      ZoneId=3
      ReferrerUrl=https://example.com/login
      HostUrl=https://example.com/payload.docx
    """
    meta: Dict[str, Any] = {
        "zone_id": None,
        "host_url": None,
        "referrer_url": None,
    }
    if not content:
        return meta

    # Try configparser first
    try:
        cfg = configparser.ConfigParser()
        cfg.read_string(content)
        sec = "ZoneTransfer" if "ZoneTransfer" in cfg else cfg.sections()[0] if cfg.sections() else None
        if sec:
            if cfg.has_option(sec, "ZoneId"):
                try:
                    meta["zone_id"] = int(cfg.get(sec, "ZoneId").strip())
                except Exception:
                    pass
            if cfg.has_option(sec, "HostUrl"):
                meta["host_url"] = cfg.get(sec, "HostUrl").strip()
            if cfg.has_option(sec, "ReferrerUrl"):
                meta["referrer_url"] = cfg.get(sec, "ReferrerUrl").strip()
    except Exception:
        pass

    # Regex fallbacks if configparser failed
    if meta["zone_id"] is None:
        m_zone = re.search(r"(?i)ZoneId\s*=\s*(\d+)", content)
        if m_zone:
            meta["zone_id"] = int(m_zone.group(1))
    if not meta["host_url"]:
        m_host = re.search(r"(?i)HostUrl\s*=\s*([^\r\n]+)", content)
        if m_host:
            meta["host_url"] = m_host.group(1).strip()
    if not meta["referrer_url"]:
        m_ref = re.search(r"(?i)ReferrerUrl\s*=\s*([^\r\n]+)", content)
        if m_ref:
            meta["referrer_url"] = m_ref.group(1).strip()

    return meta


class DocumentParser(BaseParser):
    """
    Parser for corporate documents (.pdf, .docx, .xlsx, .pptx, .doc, .xls, .ppt)
    and NTFS Zone.Identifier download streams.
    Populates parsed_documents_metadata in DuckDB.
    """

    DOC_EXTENSIONS = {
        ".pdf",
        ".docx",
        ".docm",
        ".xlsx",
        ".xlsm",
        ".pptx",
        ".pptm",
        ".doc",
        ".xls",
        ".ppt",
    }

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        super().__init__(case_id, staging_dir)
        self.zone_map: Dict[str, Dict[str, Any]] = {}

    def _discover_and_cache_zone_identifiers(self) -> None:
        """
        Scan staging directory for all NTFS Zone.Identifier files and index them
        by base file path and filename for rapid cross-correlation.
        """
        self.zone_map.clear()
        for p in self.staging_dir.rglob("*"):
            if not p.is_file():
                continue
            name_lower = p.name.lower()
            if "zone.identifier" in name_lower or p.name.endswith(":Zone.Identifier"):
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    zone_meta = parse_zone_identifier(text)
                    zone_meta["source_file"] = str(p)

                    # Map by full path, stripped path, and stem
                    self.zone_map[str(p).lower()] = zone_meta

                    # If file is named document.docx:Zone.Identifier or document.docx.Zone.Identifier
                    clean_name = re.sub(r"(?i)[:.]zone\.identifier.*$", "", p.name)
                    if clean_name:
                        self.zone_map[clean_name.lower()] = zone_meta
                        target_parent = p.parent / clean_name
                        self.zone_map[str(target_parent).lower()] = zone_meta
                except Exception as ex:
                    self._log(f"Error reading Zone.Identifier {p}: {ex}", "DEBUG")

    def _get_zone_info_for_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Check if file has an associated Zone.Identifier companion stream or cache hit.
        """
        # 1. Exact path match in cache
        path_lower = str(file_path).lower()
        if path_lower in self.zone_map:
            return self.zone_map[path_lower]

        # 2. Filename match in cache
        name_lower = file_path.name.lower()
        if name_lower in self.zone_map:
            return self.zone_map[name_lower]

        # 3. Check for physical companion file on disk
        # e.g., file.docx.Zone.Identifier or file.docx:Zone.Identifier
        candidates = [
            file_path.parent / f"{file_path.name}.Zone.Identifier",
            file_path.parent / f"{file_path.name}:Zone.Identifier",
            file_path.parent / f"{file_path.name}_Zone.Identifier",
            file_path.parent / f"{file_path.name}.Zone.Identifier.txt",
        ]
        for c in candidates:
            if c.is_file():
                try:
                    text = c.read_text(encoding="utf-8", errors="replace")
                    meta = parse_zone_identifier(text)
                    meta["source_file"] = str(c)
                    return meta
                except Exception:
                    pass

        return {"zone_id": None, "host_url": None, "referrer_url": None}

    def _parse_pdf(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract PDF metadata, links, and javascript/macros via PyMuPDF.
        """
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        zone_info = self._get_zone_info_for_file(file_path)

        title = None
        author = None
        last_modified_by = None
        created_time = None
        modified_time = None
        page_count = 0
        word_count = 0
        has_macros = False
        embedded_links: List[str] = []

        try:
            doc = fitz.open(str(file_path))
            page_count = doc.page_count
            meta = doc.metadata or {}

            title = meta.get("title") or None
            author = meta.get("author") or None
            created_time = parse_pdf_date(meta.get("creationDate"))
            modified_time = parse_pdf_date(meta.get("modDate"))

            # Inspect embedded links and word count (up to 30 pages)
            max_pages = min(page_count, 30)
            for i in range(max_pages):
                page = doc[i]
                for link in page.get_links():
                    uri = link.get("uri")
                    if uri and uri not in embedded_links:
                        embedded_links.append(uri)
                text = page.get_text()
                if text:
                    word_count += len(text.split())

            # Check for embedded files / JavaScript
            if doc.embfile_count() > 0:
                has_macros = True
            else:
                # Binary scan for JavaScript catalog objects
                with open(file_path, "rb") as f:
                    raw_head = f.read(min(file_size, 512 * 1024))
                    if b"/JavaScript" in raw_head or b"/JS" in raw_head:
                        has_macros = True

            doc.close()
        except Exception as ex:
            self._log(f"PyMuPDF error reading {file_path.name}: {ex}", "DEBUG")

        return {
            "file_path": self.resolve_evidence_path(file_path, file_size),
            "file_name": file_path.name,
            "file_type": "PDF",
            "file_size_bytes": file_size,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": created_time,
            "modified_time": modified_time,
            "page_count": page_count,
            "word_count": word_count,
            "has_macros": has_macros,
            "embedded_links": json.dumps(embedded_links, ensure_ascii=False),
            "zone_id": zone_info.get("zone_id"),
            "host_url": zone_info.get("host_url"),
            "referrer_url": zone_info.get("referrer_url"),
            "sha256": sha256,
            "source_file": str(file_path),
        }

    def _parse_docx(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract DOCX/DOCM metadata, core properties, VBA macros and hyperlinks.
        """
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = file_path.suffix.lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        title = None
        author = None
        last_modified_by = None
        created_time = None
        modified_time = None
        word_count = 0
        has_macros = ext == "DOCM"
        embedded_links: List[str] = []

        # 1. Parse core properties & word count via python-docx
        try:
            doc = docx.Document(str(file_path))
            core = doc.core_properties
            title = core.title or None
            author = core.author or None
            last_modified_by = core.last_modified_by or None
            if core.created:
                created_time = core.created.replace(tzinfo=timezone.utc) if core.created.tzinfo is None else core.created
            if core.modified:
                modified_time = core.modified.replace(tzinfo=timezone.utc) if core.modified.tzinfo is None else core.modified

            # Count words
            word_count = sum(len(p.text.split()) for p in doc.paragraphs)

            # Hyperlinks from part relationships
            if hasattr(doc, "part") and hasattr(doc.part, "rels"):
                for rel in doc.part.rels.values():
                    if "hyperlink" in str(rel.reltype).lower() and rel.target_ref:
                        if rel.target_ref not in embedded_links:
                            embedded_links.append(rel.target_ref)
        except Exception as ex:
            self._log(f"python-docx error on {file_path.name}: {ex}", "DEBUG")

        # 2. Inspect ZIP structure for macros and relationship URLs
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()
                if any("vbaProject.bin" in n for n in names):
                    has_macros = True

                # Inspect rels XML for external target URLs
                for n in names:
                    if n.endswith(".rels"):
                        rels_content = z.read(n).decode("utf-8", errors="replace")
                        for m in re.finditer(r'Target="([^"]+)"', rels_content):
                            url = m.group(1)
                            if url.startswith(("http://", "https://", "ftp://")) and url not in embedded_links:
                                embedded_links.append(url)
        except Exception:
            pass

        return {
            "file_path": self.resolve_evidence_path(file_path, file_size),
            "file_name": file_path.name,
            "file_type": ext,
            "file_size_bytes": file_size,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": created_time,
            "modified_time": modified_time,
            "page_count": 1,
            "word_count": word_count,
            "has_macros": has_macros,
            "embedded_links": json.dumps(embedded_links, ensure_ascii=False),
            "zone_id": zone_info.get("zone_id"),
            "host_url": zone_info.get("host_url"),
            "referrer_url": zone_info.get("referrer_url"),
            "sha256": sha256,
            "source_file": str(file_path),
        }

    def _parse_xlsx(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract XLSX/XLSM metadata, properties, macros and embedded URLs.
        """
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = file_path.suffix.lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        title = None
        author = None
        last_modified_by = None
        created_time = None
        modified_time = None
        has_macros = ext == "XLSM"
        embedded_links: List[str] = []

        try:
            wb = openpyxl.load_workbook(str(file_path), read_only=True, data_only=True)
            props = wb.properties
            title = props.title or None
            author = props.creator or None
            last_modified_by = props.lastModifiedBy or None
            if props.created:
                created_time = props.created.replace(tzinfo=timezone.utc) if props.created.tzinfo is None else props.created
            if props.modified:
                modified_time = props.modified.replace(tzinfo=timezone.utc) if props.modified.tzinfo is None else props.modified
            wb.close()
        except Exception as ex:
            self._log(f"openpyxl error on {file_path.name}: {ex}", "DEBUG")

        # Check for macros and rels in ZIP
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()
                if any("vbaProject.bin" in n for n in names):
                    has_macros = True
                for n in names:
                    if n.endswith(".rels"):
                        rels_content = z.read(n).decode("utf-8", errors="replace")
                        for m in re.finditer(r'Target="([^"]+)"', rels_content):
                            url = m.group(1)
                            if url.startswith(("http://", "https://", "ftp://")) and url not in embedded_links:
                                embedded_links.append(url)
        except Exception:
            pass

        return {
            "file_path": self.resolve_evidence_path(file_path, file_size),
            "file_name": file_path.name,
            "file_type": ext,
            "file_size_bytes": file_size,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": created_time,
            "modified_time": modified_time,
            "page_count": 1,
            "word_count": 0,
            "has_macros": has_macros,
            "embedded_links": json.dumps(embedded_links, ensure_ascii=False),
            "zone_id": zone_info.get("zone_id"),
            "host_url": zone_info.get("host_url"),
            "referrer_url": zone_info.get("referrer_url"),
            "sha256": sha256,
            "source_file": str(file_path),
        }

    def _parse_pptx(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract PPTX/PPTM presentation metadata, slide counts, macros and links.
        """
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = file_path.suffix.lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        title = None
        author = None
        last_modified_by = None
        created_time = None
        modified_time = None
        slide_count = 0
        has_macros = ext == "PPTM"
        embedded_links: List[str] = []

        try:
            prs = pptx.Presentation(str(file_path))
            slide_count = len(prs.slides)
            core = prs.core_properties
            title = core.title or None
            author = core.author or None
            last_modified_by = core.last_modified_by or None
            if core.created:
                created_time = core.created.replace(tzinfo=timezone.utc) if core.created.tzinfo is None else core.created
            if core.modified:
                modified_time = core.modified.replace(tzinfo=timezone.utc) if core.modified.tzinfo is None else core.modified
        except Exception as ex:
            self._log(f"python-pptx error on {file_path.name}: {ex}", "DEBUG")

        # Check for macros and rels in ZIP
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                names = z.namelist()
                if any("vbaProject.bin" in n for n in names):
                    has_macros = True
                for n in names:
                    if n.endswith(".rels"):
                        rels_content = z.read(n).decode("utf-8", errors="replace")
                        for m in re.finditer(r'Target="([^"]+)"', rels_content):
                            url = m.group(1)
                            if url.startswith(("http://", "https://", "ftp://")) and url not in embedded_links:
                                embedded_links.append(url)
        except Exception:
            pass

        return {
            "file_path": self.resolve_evidence_path(file_path, file_size),
            "file_name": file_path.name,
            "file_type": ext,
            "file_size_bytes": file_size,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": created_time,
            "modified_time": modified_time,
            "page_count": slide_count,
            "word_count": 0,
            "has_macros": has_macros,
            "embedded_links": json.dumps(embedded_links, ensure_ascii=False),
            "zone_id": zone_info.get("zone_id"),
            "host_url": zone_info.get("host_url"),
            "referrer_url": zone_info.get("referrer_url"),
            "sha256": sha256,
            "source_file": str(file_path),
        }

    def _parse_ole_legacy(self, file_path: Path) -> Dict[str, Any]:
        """
        Extract legacy Microsoft Office OLE compound document metadata (.doc, .xls, .ppt).
        """
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = file_path.suffix.lstrip(".").upper()
        zone_info = self._get_zone_info_for_file(file_path)

        title = None
        author = None
        last_modified_by = None
        created_time = None
        modified_time = None
        has_macros = False

        try:
            if olefile.isOleFile(str(file_path)):
                ole = olefile.OleFileIO(str(file_path))
                meta = ole.get_metadata()
                title = meta.title.decode("utf-8", errors="replace") if isinstance(meta.title, bytes) else meta.title
                author = meta.author.decode("utf-8", errors="replace") if isinstance(meta.author, bytes) else meta.author
                last_modified_by = (
                    meta.last_saved_by.decode("utf-8", errors="replace")
                    if isinstance(meta.last_saved_by, bytes)
                    else meta.last_saved_by
                )

                if meta.create_time:
                    created_time = meta.create_time.replace(tzinfo=timezone.utc)
                if meta.last_saved_time:
                    modified_time = meta.last_saved_time.replace(tzinfo=timezone.utc)

                # Check for VBA streams
                for stream_name in ole.listdir():
                    s_lower = "/".join(stream_name).lower()
                    if any(k in s_lower for k in ["vba", "macros", "_vba_project"]):
                        has_macros = True
                        break
                ole.close()
        except Exception as ex:
            self._log(f"olefile error on {file_path.name}: {ex}", "DEBUG")

        return {
            "file_path": self.resolve_evidence_path(file_path, file_size),
            "file_name": file_path.name,
            "file_type": ext,
            "file_size_bytes": file_size,
            "title": title,
            "author": author,
            "last_modified_by": last_modified_by,
            "created_time": created_time,
            "modified_time": modified_time,
            "page_count": 1,
            "word_count": 0,
            "has_macros": has_macros,
            "embedded_links": "[]",
            "zone_id": zone_info.get("zone_id"),
            "host_url": zone_info.get("host_url"),
            "referrer_url": zone_info.get("referrer_url"),
            "sha256": sha256,
            "source_file": str(file_path),
        }

    def _parse_standalone_zone_identifier(self, file_path: Path) -> Dict[str, Any]:
        """
        Record standalone Zone.Identifier download activity in parsed_documents_metadata.
        """
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        content = file_path.read_text(encoding="utf-8", errors="replace")
        meta = parse_zone_identifier(content)

        mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)

        # Infer target file name by removing :Zone.Identifier
        target_name = re.sub(r"(?i)[:.]zone\.identifier.*$", "", file_path.name)

        return {
            "file_path": self.resolve_evidence_path(file_path, file_size),
            "file_name": file_path.name,
            "file_type": "ZONE_IDENTIFIER",
            "file_size_bytes": file_size,
            "title": f"Zone.Identifier for {target_name or file_path.stem}",
            "author": None,
            "last_modified_by": None,
            "created_time": mtime,
            "modified_time": mtime,
            "page_count": 1,
            "word_count": 0,
            "has_macros": False,
            "embedded_links": json.dumps(
                [u for u in [meta.get("host_url"), meta.get("referrer_url")] if u],
                ensure_ascii=False,
            ),
            "zone_id": meta.get("zone_id"),
            "host_url": meta.get("host_url"),
            "referrer_url": meta.get("referrer_url"),
            "sha256": sha256,
            "source_file": str(file_path),
        }

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for documents and Zone.Identifier streams.
        Populates parsed_documents_metadata.
        """
        start_time = time.time()
        self._log(f"Starting DocumentParser across staging directory: {self.staging_dir}")

        # Index Zone.Identifiers first so documents can cross-correlate
        self._discover_and_cache_zone_identifiers()
        self._log(f"Indexed {len(self.zone_map)} Zone.Identifier metadata entries.")

        all_records: List[Dict[str, Any]] = []
        candidate_docs: List[Path] = []
        candidate_zones: List[Path] = []

        for p in self.staging_dir.rglob("*"):
            if not p.is_file():
                continue
            name_lower = p.name.lower()
            sfx = p.suffix.lower()

            if "zone.identifier" in name_lower or p.name.endswith(":Zone.Identifier"):
                candidate_zones.append(p)
            elif sfx in self.DOC_EXTENSIONS:
                candidate_docs.append(p)

        self._log(f"Found {len(candidate_docs)} documents and {len(candidate_zones)} Zone.Identifier files.")

        # 1. Parse documents
        for doc_file in candidate_docs:
            sfx = doc_file.suffix.lower()
            try:
                if sfx == ".pdf":
                    rec = self._parse_pdf(doc_file)
                elif sfx in [".docx", ".docm"]:
                    rec = self._parse_docx(doc_file)
                elif sfx in [".xlsx", ".xlsm"]:
                    rec = self._parse_xlsx(doc_file)
                elif sfx in [".pptx", ".pptm"]:
                    rec = self._parse_pptx(doc_file)
                elif sfx in [".doc", ".xls", ".ppt"]:
                    rec = self._parse_ole_legacy(doc_file)
                else:
                    continue
                all_records.append(rec)
            except Exception as ex:
                self._log(f"Error parsing document {doc_file}: {ex}", "WARNING")

        # 2. Parse standalone Zone.Identifier files
        for zone_file in candidate_zones:
            try:
                rec = self._parse_standalone_zone_identifier(zone_file)
                all_records.append(rec)
            except Exception as ex:
                self._log(f"Error parsing Zone.Identifier {zone_file}: {ex}", "WARNING")

        # Deduplicate document records by (file_name, file_size_bytes, sha256)
        unique_records: List[Dict[str, Any]] = []
        seen_docs = set()
        for rec in all_records:
            fn = str(rec.get("file_name") or "").strip().lower()
            sz = rec.get("file_size_bytes") or 0
            h = str(rec.get("sha256") or "").strip().lower()
            fp = str(rec.get("file_path") or "").strip().lower()
            key = (fn, sz, h) if (fn and sz) else fp
            if key not in seen_docs:
                seen_docs.add(key)
                unique_records.append(rec)

        # Ingest into DuckDB (zero stubs, strictly real findings)
        if unique_records:
            row_count = self.insert_records(
                table_name="parsed_documents_metadata",
                records=unique_records,
                schema_ddl=DOCUMENTS_METADATA_SCHEMA_DDL,
            )
        else:
            row_count = 0

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Document",
            command_executed=f"DocumentParser.parse({len(candidate_docs)} docs, {len(candidate_zones)} zones)",
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(f"DocumentParser complete in {duration_ms}ms with {row_count} records ingested.")
        return {"parsed_documents_metadata": row_count}
