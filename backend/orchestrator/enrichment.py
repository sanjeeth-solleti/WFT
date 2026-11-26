"""
Windows Forensic Toolkit (WFT) DFIR Suite - File Enrichment & Deep Malware Engine
Combines:
  1. Multi-Threaded YARA-X Deep Scanning Engine (Compiled rules in rules/ + custom .yar rules)
  2. Isolated Headless Trellix Stinger AV Scanner CLI + Zero-FP Multi-Indicator PE/Script Heuristics
  3. RapidOCR Optical Character Recognition on Screenshots & Images
  4. Cryptographic SHA-256 file hashing & logical forensic path restoration for all staged files
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import duckdb
from PIL import Image

from backend.config import (
    DEFAULT_YARA_FILE,
    RULES_DIR,
    find_stinger_binary,
    get_case_dir,
    get_case_staging_dir,
)
from backend.db.engine import DuckDBManager

try:
    import yara_x
except ImportError:
    yara_x = None

RapidOCR: Optional[Any] = None
_RAPIDOCR_IMPORT_ATTEMPTED = False


def _get_rapidocr_cls() -> Optional[Any]:
    global RapidOCR, _RAPIDOCR_IMPORT_ATTEMPTED
    if RapidOCR is not None:
        return RapidOCR
    if not _RAPIDOCR_IMPORT_ATTEMPTED:
        _RAPIDOCR_IMPORT_ATTEMPTED = True
        try:
            from rapidocr_onnxruntime import RapidOCR as _LoadedRapidOCR
            RapidOCR = _LoadedRapidOCR
        except ImportError:
            RapidOCR = None
    return RapidOCR


try:
    import pefile
except ImportError:
    pefile = None


_PARTITION_PREFIX_RE = re.compile(
    r"^(?:part(?:ition)?[_-]?\d+|vol(?:ume)?[_-]?\d+|ntfs[_-]?\d+|fat\d*[_-]?\d+|exfat[_-]?\d+|c_drive|drive_[a-z])$",
    re.IGNORECASE,
)

_VSS_PREFIX_RE = re.compile(r"^vss[_-]?(\d+)$", re.IGNORECASE)

_STINGER_EXCLUDE_LINE_PREFIXES = (
    "trellix stinger version",
    "mcafee stinger version",
    "copyright",
    "av engine version",
    "virus data file",
    "ready to scan for",
    "custom scan initiated",
    "summary report on",
    "file(s)",
    "totalfiles:",
    "clean:",
    "not scanned:",
    "possibly infected:",
    "number of infected",
    "infected files:",
    "threats detected:",
    "scan summary:",
    "time:",
    "scan completed on",
)

_STINGER_ZERO_SUMMARY_RES = (
    re.compile(r"Possibly\s+Infected:?[\s.]*0\b", re.IGNORECASE),
    re.compile(r"Number\s+of\s+infected\s+files:?\s*0\b", re.IGNORECASE),
    re.compile(r"Infected\s+files:?\s*0\b", re.IGNORECASE),
    re.compile(r"Threats\s+detected:?\s*0\b", re.IGNORECASE),
    re.compile(r"\b0\s+threats\s+detected\b", re.IGNORECASE),
)

_STINGER_MULTILINE_DETECT_RES = (
    re.compile(r"^Found\s+the\s+(?P<threat>.+?)\s*!+\s*$", re.IGNORECASE),
    re.compile(r"^Found\s+potentially\s+unwanted\s+program\s+(?P<threat>.+?)(?:\s*!+)?\s*$", re.IGNORECASE),
    re.compile(r"^MACRO\s+found:\s*(?P<threat>.+?)(?:\s*!+)?\s*$", re.IGNORECASE),
    re.compile(r"^is\s+infected\s+with\s+(?P<threat>.+?)(?:\s*!+)?\s*$", re.IGNORECASE),
)

_STINGER_CELL_DETECT_RE = re.compile(
    r"^(?:Found\s+the\s+|Found\s+potentially\s+unwanted\s+program\s+|MACRO\s+found:\s*|Found:\s+|(?:is\s+)?infected\s+with\s+)"
    r"(?P<threat>[^\r\n!]+?)(?:\s*!+)?\s*$",
    re.IGNORECASE,
)

_STINGER_NON_THREAT_CELLS: Set[str] = {
    "0", "clean", "none", "ok", "n/a", "-", "normal", "safe", "benign",
    "not scanned", "unscanned", "skipped", "scanned", "checked",
    "encrypted", "password protected", "password-protected", "corrupted",
    "damaged", "locked", "access denied", "in use", "archive", "packed",
    "compressed", "timeout", "timed out", "error", "read error",
    "scan path", "scan target", "target", "target path", "report path",
    "report", "log path", "directory", "folder", "file", "object", "path",
    "summary", "status", "result", "infected files", "possibly infected",
    "number of infected files", "threats detected", "total files", "totalfiles",
}

_STINGER_NON_THREAT_PREFIXES = (
    "clean",
    "not scanned",
    "scan path",
    "scan target",
    "target path",
    "report path",
    "log path",
    "directory",
    "password protected",
    "password-protected",
    "encrypted",
    "corrupted",
    "damaged",
    "locked",
    "skipped",
    "scanned",
    "archive",
    "access denied",
    "summary report",
    "infected files",
    "possibly infected",
    "number of infected",
    "threats detected",
    "totalfiles",
    "total files",
)

_STINGER_SINGLELINE_DETECT_RE = re.compile(
    r"^(?P<path>(?:[A-Za-z]:[\\/]|\\\\|/)[^\t\r\n]+?)\s+"
    r"(?:Found\s+the\s+|Found\s+potentially\s+unwanted\s+program\s+|MACRO\s+found:\s*|Found:\s+|is\s+infected\s+with\s+)"
    r"(?P<threat>[^\r\n!]+?)(?:\s*!+)?\s*$",
    re.IGNORECASE,
)

_FILE_PATH_LINE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)[^\r\n\t]+$")

_PS_ENC_CMD_RE = re.compile(
    r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*?\s-(?:e|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{40,})",
    re.IGNORECASE,
)
_PS_HIDDEN_RE = re.compile(r"\s-(?:w|windowstyle)\s+hidden\b", re.IGNORECASE)
_PS_BYPASS_RE = re.compile(
    r"\s-(?:nop|noprofile|ep\s+bypass|executionpolicy\s+bypass)\b",
    re.IGNORECASE,
)
_PS_DECODED_MAL_RE = re.compile(
    r"(?:\biex\b|invoke-expression|downloadstring|downloaddata|frombase64string|"
    r"reflection\.assembly|amsiutils|amsiscanbuffer|virtualalloc|wscript\.shell|"
    r"net\.sockets\.tcpclient|" + "sekurlsa::" + r")",
    re.IGNORECASE,
)
_PS_DIRECT_CRADLE_FETCH_RE = re.compile(
    r"\b(?:DownloadString|DownloadData)\s*\(",
    re.IGNORECASE,
)
_PS_ALT_FETCH_RE = re.compile(
    r"\b(?:New-Object\s+(?:System\.)?Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b",
    re.IGNORECASE,
)
_PS_INMEM_EXEC_RE = re.compile(
    r"(?:\bIEX\b|\bInvoke-Expression\b|\[Ref\]\.Assembly|Assembly::Load)",
    re.IGNORECASE,
)
_MIMIKATZ_CMD_RE = re.compile(
    r"(?:"
    + "sekurlsa::"
    + r"(?:logonpasswords|wdigest|tickets|pth|ekeys|minidump)|"
    + "lsadump::"
    + r"(?:sam|secrets|dcsync|lsa)|"
    + "kerberos::"
    + r"(?:ptt|golden|list)|"
    + r"\bInvoke-"
    + "Mimikatz"
    + r"\b)",
    re.IGNORECASE,
)


def parse_stinger_report_content(content: str) -> List[Dict[str, str]]:
    """
    Parse Trellix Stinger HTML/text report content strictly for positive per-file detections.
    Never matches clean summary counters ('Possibly Infected:..... 0', 'Infected files: 0')
    or engine banner lines ('Ready to scan for 10123 viruses, trojans and variants.').
    """
    if not content or not content.strip():
        return []

    raw = content.lstrip("\ufeff")
    detections: List[Dict[str, str]] = []
    seen_pairs: Set[Tuple[str, str]] = set()

    engine_ver = "Trellix Stinger"
    ver_match = re.search(r"Trellix\s+Stinger\s+Version\s+([\d.]+)", raw, re.IGNORECASE)
    av_match = re.search(r"AV\s+Engine\s+version\s+(v[\d.]+)", raw, re.IGNORECASE)
    if ver_match and av_match:
        engine_ver = f"Stinger {ver_match.group(1)} ({av_match.group(1)})"
    elif ver_match:
        engine_ver = f"Stinger {ver_match.group(1)}"

    # Pre-normalize HTML to plain text so zero-infection summary counters can also gate HTML table noise
    norm = re.sub(r"<\s*br\s*/?\s*>", "\n", raw, flags=re.IGNORECASE)
    norm = re.sub(r"</\s*(?:td|th)\s*>", "\t", norm, flags=re.IGNORECASE)
    norm = re.sub(r"</\s*(?:p|div|tr|li|h\d|pre)\s*>", "\n", norm, flags=re.IGNORECASE)
    norm = re.sub(r"<[^>]+>", "", norm)
    norm = html.unescape(norm)
    has_zero_summary = any(zero_re.search(norm) for zero_re in _STINGER_ZERO_SUMMARY_RES)

    # 1. Check structured HTML table rows if present (<tr ...><td ...>...</td></tr>)
    # Require explicit class="infected" on <tr>/<td> OR explicit Stinger threat phrase in threat cell
    for tr_match in re.finditer(r"<tr\b[^>]*>(.*?)</tr>", raw, re.IGNORECASE | re.DOTALL):
        tr_full = tr_match.group(0)
        tr_inner = tr_match.group(1)
        cells = [
            html.unescape(re.sub(r"<[^>]+>", "", td_m.group(1))).strip()
            for td_m in re.finditer(r"<td\b[^>]*>(.*?)</td>", tr_inner, re.IGNORECASE | re.DOTALL)
        ]
        if len(cells) >= 2:
            has_infected_class = bool(
                re.search(
                    r'class\s*=\s*(?:["\'][^"\']*\binfected\b[^"\']*["\']|infected\b)',
                    tr_full,
                    re.IGNORECASE,
                )
            )
            cand_path = next((c for c in cells if _FILE_PATH_LINE_RE.match(c)), "")
            if cand_path:
                other_cells = [
                    c for c in cells
                    if c != cand_path and c.strip().lower().rstrip(":") not in ("file", "object", "path")
                ]
                if other_cells:
                    threat_cell = other_cells[0].strip()
                    low_t = threat_cell.lower().strip()
                    low_t_norm = low_t.rstrip(":").strip()
                    is_non_threat = (
                        not threat_cell
                        or low_t_norm in _STINGER_NON_THREAT_CELLS
                        or any(low_t_norm.startswith(pref) for pref in _STINGER_NON_THREAT_PREFIXES)
                        or low_t_norm.isdigit()
                    )
                    if is_non_threat:
                        continue

                    cell_det_m = _STINGER_CELL_DETECT_RE.match(threat_cell)
                    if has_infected_class or cell_det_m is not None:
                        if has_zero_summary and not has_infected_class and cell_det_m is None:
                            continue
                        threat_clean = (
                            _clean_stinger_threat_name(cell_det_m.group("threat"))
                            if cell_det_m is not None
                            else threat_cell
                        )
                        action = other_cells[1].strip() if len(other_cells) > 1 and other_cells[1].strip() else "Reported"
                        key = (cand_path.lower(), threat_clean.lower())
                        if key not in seen_pairs:
                            seen_pairs.add(key)
                            detections.append(
                                {
                                    "file_path": cand_path,
                                    "malware_name": threat_clean,
                                    "action_taken": action,
                                    "engine_version": engine_ver,
                                    "details": f"{cand_path} -> {threat_clean}",
                                }
                            )

    # 2. Scan normalized plain-text lines for Stinger <PRE> / text report detections
    lines = [ln.rstrip("\r") for ln in norm.splitlines()]
    last_candidate_path: Optional[str] = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue

        low = stripped.lower()
        if any(low.startswith(pref) for pref in _STINGER_EXCLUDE_LINE_PREFIXES):
            last_candidate_path = None
            continue

        # Single-line format: C:\path\evil.exe   Found the Trojan-Test trojan !!!
        single_m = _STINGER_SINGLELINE_DETECT_RE.match(stripped)
        if single_m:
            det_path = single_m.group("path").strip()
            threat_raw = single_m.group("threat").strip()
            threat_clean = _clean_stinger_threat_name(threat_raw)
            if det_path and threat_clean:
                key = (det_path.lower(), threat_clean.lower())
                if key not in seen_pairs:
                    seen_pairs.add(key)
                    detections.append(
                        {
                            "file_path": det_path,
                            "malware_name": threat_clean,
                            "action_taken": "Reported",
                            "engine_version": engine_ver,
                            "details": stripped,
                        }
                    )
            last_candidate_path = None
            continue

        # Multi-line detection line paired with preceding path line
        matched_multi = False
        for det_re in _STINGER_MULTILINE_DETECT_RES:
            mm = det_re.match(stripped)
            if mm and last_candidate_path:
                threat_raw = mm.group("threat").strip()
                threat_clean = _clean_stinger_threat_name(threat_raw)
                if threat_clean:
                    key = (last_candidate_path.lower(), threat_clean.lower())
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        detections.append(
                            {
                                "file_path": last_candidate_path,
                                "malware_name": threat_clean,
                                "action_taken": "Reported",
                                "engine_version": engine_ver,
                                "details": f"{last_candidate_path} | {stripped}",
                            }
                        )
                matched_multi = True
                break

        if matched_multi:
            continue

        if _FILE_PATH_LINE_RE.match(stripped):
            last_candidate_path = stripped
        else:
            last_candidate_path = None

    if not detections and has_zero_summary:
        return []

    return detections


def _clean_stinger_threat_name(raw_threat: str) -> str:
    cleaned = raw_threat.strip().rstrip("!").strip()
    # Strip trailing generic Stinger type suffix while keeping meaningful family name
    cleaned = re.sub(r"\s+(?:virus|trojan|worm|variant)\s*$", "", cleaned, flags=re.IGNORECASE).strip()
    return cleaned or raw_threat.strip()


def _decode_script_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16be", errors="replace")
    if len(data) >= 4 and data[1::2].count(0) > (len(data) // 4):
        try:
            return data.decode("utf-16le", errors="replace")
        except Exception:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


class FileEnrichmentEngine:
    """
    Thread-safe forensic file enrichment & zero-false-positive malware coordinator.
    """

    YARA_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".msi", ".cab",
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".sct", ".hta", ".lnk", ".dmp", ".jsp", ".jspx", ".war", ".jar", ".class",
        ".aspx", ".ashx", ".asmx", ".asp", ".php", ".phtml", ".py", ".sh", ".elf",
        ".bin", ".conf", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".xml", ".json", ".txt",
        ".profile", ".reg", ".url", ".doc", ".xls",
        ".ppt", ".docm", ".xlsm", ".pptm", ".payloads",
    }
    YARA_SCAN_EXTENSIONS: Set[str] = YARA_EXTENSIONS

    IMAGE_EXTENSIONS: Set[str] = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tiff", ".tif"}
    PE_EXTENSIONS: Set[str] = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com"}
    SCRIPT_EXTENSIONS: Set[str] = {
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sct", ".hta"
    }

    _NON_YARA_BINARY_EXTENSIONS: Set[str] = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".ico", ".svg",
        ".mp4", ".mp3", ".wav", ".webm", ".ogg", ".avi", ".mov", ".mkv", ".flac",
        ".duckdb", ".wal", ".evtx", ".etl", ".sqlite", ".sqlite3", ".db", ".db-wal", ".db-shm",
        ".pf", ".dat", ".edb", ".hve", ".regtrans-ms", ".blf", ".log1", ".log2",
        ".mui", ".cat", ".nls", ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".pak", ".asar", ".vdm", ".css", ".map",
    }
    _EXCLUDED_WALK_DIRS: Set[str] = {
        "stinger_reports", "stinger_logs", "bulk_extractor_out", "__pycache__", ".git",
        "clean_hives", "carved_thumbnails",
    }
    _YARA_SKIP_STAGING_ROOTS: Set[str] = {
        "registry", "mft", "usnjrnl", "logs", "evtx", "eventlogs",
        "srum", "wbem", "prefetch", "amcache", "shimcache",
        "shellbags", "jumplists", "thumbcache",
    }
    _YARA_SKIP_PATH_FRAGMENTS: Tuple[str, ...] = (
        "\\windows defender\\definition updates\\",
        "\\windows defender\\scans\\",
        "\\windows defender\\quarantine\\",
        "\\windows\\winsxs\\backup\\",
        "\\windows\\winsxs\\manifests\\",
        "\\cache\\cache_data\\",
        "\\code cache\\",
        "\\gpucache\\",
    )
    _BINARY_CONTAINER_MAGICS: Tuple[bytes, ...] = (
        b"ElfFile\x00",          # EVTX
        b"regf",                 # Registry hive
        b"SQLite format 3\x00",  # SQLite
        b"MAM\x04",              # Win10/11 compressed Prefetch
        b"SCCA",                 # Prefetch
        b"\x1f\x8b",             # GZIP
        b"%PDF-",                # PDF
    )

    def _log(self, message: str, level: str = "INFO") -> None:
        print(f"[{level}] [FileEnrichmentEngine] {message}")

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Union[str, Path]] = None,
        rules_path: Optional[Union[str, Path]] = None,
        max_workers: int = 25,
    ) -> None:
        self.case_id = case_id
        self.staging_dir = (
            Path(staging_dir).resolve()
            if staging_dir is not None
            else get_case_staging_dir(case_id).resolve()
        )
        self._explicit_rules_path: Optional[Path] = (
            Path(rules_path).resolve() if rules_path is not None else None
        )
        self.rules_path: Path = self._explicit_rules_path or DEFAULT_YARA_FILE
        default_workers = 25
        raw_workers = default_workers if max_workers is None else int(max_workers)
        self.max_workers: int = max(1, min(32, raw_workers if raw_workers > 0 else default_workers))
        self._ocr_engine: Optional[Any] = None
        self._ocr_lock = threading.Lock()

        with DuckDBManager.get_lock(self.case_id):
            self.conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = self.conn.cursor()
            self._ensure_tables(cur)

    def _resolve_workers(self, max_workers: Optional[int] = None) -> int:
        if max_workers is None:
            return self.max_workers
        return max(1, min(32, int(max_workers)))

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest().lower()

    @staticmethod
    def parse_stinger_report(report_path: Union[str, Path]) -> List[Dict[str, str]]:
        p = Path(report_path)
        if not p.is_file():
            return []
        content = p.read_text(encoding="utf-8", errors="replace")
        return parse_stinger_report_content(content)

    @staticmethod
    def parse_stinger_report_content(content: str) -> List[Dict[str, str]]:
        return parse_stinger_report_content(content)

    def _get_or_create_ocr(self) -> Optional[Any]:
        with self._ocr_lock:
            if self._ocr_engine is None:
                ocr_cls = _get_rapidocr_cls()
                if ocr_cls is None:
                    return None
                try:
                    self._ocr_engine = ocr_cls()
                except Exception as ex:
                    self._log(f"Notice: RapidOCR initialization skipped ({ex})", level="WARNING")
                    return None
            return self._ocr_engine

    def _ensure_tables(self, cursor: Any) -> None:
        cursor.execute("CREATE SEQUENCE IF NOT EXISTS seq_enrichment_id START 1;")
        cursor.execute("CREATE SEQUENCE IF NOT EXISTS seq_yara_id START 1;")
        cursor.execute("CREATE SEQUENCE IF NOT EXISTS seq_stinger_id START 1;")
        cursor.execute("CREATE SEQUENCE IF NOT EXISTS seq_ocr_id START 1;")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_registry (
                artifact_id VARCHAR PRIMARY KEY,
                category VARCHAR NOT NULL,
                display_name VARCHAR NOT NULL,
                table_name VARCHAR NOT NULL,
                source_tool VARCHAR,
                row_count BIGINT DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS file_enrichment (
                _row_id BIGINT PRIMARY KEY DEFAULT nextval('seq_enrichment_id'),
                file_path VARCHAR NOT NULL,
                file_name VARCHAR NOT NULL,
                extension VARCHAR,
                size_bytes BIGINT,
                sha256 VARCHAR,
                yara_rules_matched VARCHAR,
                yara_match_offsets VARCHAR,
                ocr_extracted_text VARCHAR,
                archive_parent VARCHAR,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_yara_hits (
                _row_id BIGINT PRIMARY KEY DEFAULT nextval('seq_yara_id'),
                file_path VARCHAR NOT NULL,
                file_name VARCHAR NOT NULL,
                extension VARCHAR,
                size_bytes BIGINT,
                sha256 VARCHAR,
                rule_name VARCHAR NOT NULL,
                rule_namespace VARCHAR,
                pattern_identifier VARCHAR,
                match_offset BIGINT,
                match_length BIGINT,
                match_data_hex VARCHAR,
                severity VARCHAR,
                category VARCHAR,
                description VARCHAR,
                mitre_attack VARCHAR,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        for col_name in ("severity", "category", "description", "mitre_attack"):
            try:
                cursor.execute(
                    f"ALTER TABLE artifact_yara_hits ADD COLUMN IF NOT EXISTS {col_name} VARCHAR;"
                )
            except Exception:
                pass

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_stinger_hits (
                _row_id BIGINT PRIMARY KEY DEFAULT nextval('seq_stinger_id'),
                file_path VARCHAR NOT NULL,
                file_name VARCHAR NOT NULL,
                sha256 VARCHAR,
                malware_name VARCHAR NOT NULL,
                detection_type VARCHAR NOT NULL,
                action_taken VARCHAR,
                engine_version VARCHAR,
                engine VARCHAR DEFAULT 'Trellix Stinger',
                details VARCHAR,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        try:
            cursor.execute(
                "ALTER TABLE artifact_stinger_hits ADD COLUMN IF NOT EXISTS engine VARCHAR DEFAULT 'Trellix Stinger';"
            )
        except Exception:
            pass

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_ocr_results (
                _row_id BIGINT PRIMARY KEY DEFAULT nextval('seq_ocr_id'),
                file_path VARCHAR NOT NULL,
                file_name VARCHAR NOT NULL,
                dimensions VARCHAR,
                sha256 VARCHAR,
                extracted_text VARCHAR,
                confidence DOUBLE,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

    @staticmethod
    def _sync_file_enrichment_registry(cursor: Any) -> int:
        enrich_cnt = int(cursor.execute("SELECT COUNT(*) FROM file_enrichment;").fetchone()[0] or 0)
        cursor.execute(
            """
            INSERT OR REPLACE INTO artifact_registry (
                artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
            ) VALUES (
                'file_enrichment', 'MALWARE & YARA', 'File Entropy, Hashes & IOC Enrichment',
                'file_enrichment', 'FileEnrichmentEngine', ?, CURRENT_TIMESTAMP
            );
            """,
            [enrich_cnt],
        )
        return enrich_cnt

    def _ensure_all_malware_view(self, cursor: Optional[Any] = None) -> None:
        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            self._ensure_tables(cur)
            cur.execute(
                """
                CREATE OR REPLACE VIEW view_all_malware_detections AS
                SELECT
                    row_number() OVER () AS _row_id,
                    sub.file_name,
                    sub.file_path,
                    sub.sha256,
                    sub.detection_name,
                    sub.threat_name,
                    sub.detection_type,
                    sub.severity,
                    sub.action_taken,
                    sub.engine,
                    sub.details,
                    sub.scanned_at,
                    sub.table_name,
                    sub.source_row_id
                FROM (
                    SELECT
                        file_name,
                        file_path,
                        sha256,
                        malware_name AS detection_name,
                        malware_name AS threat_name,
                        detection_type,
                        CASE WHEN detection_type ILIKE '%Heuristic%' THEN 'High' ELSE 'Critical' END AS severity,
                        COALESCE(action_taken, 'Reported') AS action_taken,
                        COALESCE(engine, 'Trellix Stinger') AS engine,
                        details,
                        scanned_at,
                        'artifact_stinger_hits' AS table_name,
                        _row_id AS source_row_id
                    FROM artifact_stinger_hits
                    UNION ALL
                    SELECT
                        file_name,
                        file_path,
                        sha256,
                        rule_name AS detection_name,
                        rule_name AS threat_name,
                        'YARA-X Rule Match' AS detection_type,
                        COALESCE(severity, 'High') AS severity,
                        'Flagged' AS action_taken,
                        'YARA-X' AS engine,
                        COALESCE(description, 'Rule: ' || rule_name)
                            || ' | Severity: ' || COALESCE(severity, 'High')
                            || ' | Pattern: ' || COALESCE(pattern_identifier, 'string')
                            || ' @ ' || COALESCE(CAST(match_offset AS VARCHAR), '0') AS details,
                        scanned_at,
                        'artifact_yara_hits' AS table_name,
                        _row_id AS source_row_id
                    FROM artifact_yara_hits
                ) sub;
                """
            )
            all_cnt = cur.execute("SELECT COUNT(*) FROM view_all_malware_detections;").fetchone()[0]
            cur.execute(
                """
                INSERT OR REPLACE INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES (
                    'malware_all_detections', 'MALWARE & YARA', 'All Malware & Threat Detections',
                    'view_all_malware_detections', 'MalwareCoordinator', ?, CURRENT_TIMESTAMP
                );
                """,
                [all_cnt],
            )

    def _load_path_lookups(self) -> Tuple[Dict[str, str], Dict[Tuple[str, int], str]]:
        vfs_lookup: Dict[str, str] = {}
        mft_lookup: Dict[Tuple[str, int], str] = {}
        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            tables = {
                r[0]
                for r in cur.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            if "vfs_files" in tables:
                try:
                    cols = {c[0].lower(): c[0] for c in cur.execute("DESCRIBE vfs_files;").fetchall()}
                    if "staged_rel_path" in cols and "vfs_path" in cols:
                        rows = cur.execute(
                            f'SELECT "{cols["staged_rel_path"]}", "{cols["vfs_path"]}" '
                            f'FROM vfs_files WHERE "{cols["staged_rel_path"]}" IS NOT NULL AND "{cols["vfs_path"]}" IS NOT NULL;'
                        ).fetchall()
                        for s_rel, v_path in rows:
                            key = str(s_rel).strip().replace("\\", "/").lstrip("/").lower()
                            val = str(v_path).strip().replace("/", "\\")
                            if key and val:
                                if not re.match(r"^(?:\[VSS#\d+\]\s*)?[A-Za-z]:\\", val):
                                    val = "C:\\" + val.lstrip("\\")
                                vfs_lookup[key] = val
                except Exception:
                    pass

            if "raw_mft" in tables:
                try:
                    cols = {c[0].lower(): c[0] for c in cur.execute("DESCRIBE raw_mft;").fetchall()}
                    fn_col = cols.get("filename") or cols.get("file_name")
                    pp_col = cols.get("parentpath") or cols.get("parent_path")
                    sz_col = cols.get("filesize") or cols.get("size_bytes")
                    if fn_col and pp_col and sz_col:
                        rows = cur.execute(
                            f'SELECT "{fn_col}", "{pp_col}", TRY_CAST("{sz_col}" AS BIGINT) '
                            f'FROM raw_mft WHERE "{fn_col}" IS NOT NULL LIMIT 100000;'
                        ).fetchall()
                        for fn, pp, sz in rows:
                            if fn and sz is not None:
                                parent = str(pp or "").strip().replace("/", "\\").lstrip(".\\")
                                full = f"C:\\{parent}\\{fn}" if parent else f"C:\\{fn}"
                                full = re.sub(r"\\{2,}", r"\\", full)
                                mft_lookup.setdefault((str(fn).lower(), int(sz)), full)
                except Exception:
                    pass
        return vfs_lookup, mft_lookup

    def resolve_logical_path(
        self,
        file_path: Path,
        vfs_lookup: Optional[Dict[str, str]] = None,
        mft_lookup: Optional[Dict[Tuple[str, int], str]] = None,
        file_size: Optional[int] = None,
    ) -> str:
        resolved = file_path.resolve()
        case_dir = get_case_dir(self.case_id).resolve()
        carved_dir = (case_dir / "carved").resolve()

        try:
            rel_staging = resolved.relative_to(self.staging_dir).as_posix()
        except ValueError:
            rel_staging = None

        if rel_staging is not None:
            rel_low = rel_staging.lower().lstrip("/")
            if vfs_lookup and rel_low in vfs_lookup:
                return vfs_lookup[rel_low]

            parts = [p for p in rel_staging.split("/") if p]
            if not parts:
                return str(resolved)

            head_low = parts[0].lower()

            # staging/VSS/VSS_<N>/...
            if head_low == "vss" and len(parts) >= 3:
                vss_m = _VSS_PREFIX_RE.match(parts[1])
                vss_idx = vss_m.group(1) if vss_m else parts[1]
                rem = parts[2:]
                if rem and _PARTITION_PREFIX_RE.match(rem[0]) and len(rem) >= 2:
                    rem = rem[1:]
                win_rel = "\\".join(rem)
                return f"[VSS#{vss_idx}] C:\\{win_rel}"

            # staging/UserFiles/<user>/<rest>
            if head_low == "userfiles" and len(parts) >= 3:
                user = parts[1]
                win_rel = "\\".join(parts[2:])
                return f"C:\\Users\\{user}\\{win_rel}"

            # staging/Enrichment/...
            if head_low == "enrichment" and len(parts) >= 2:
                sub = parts[1:]
                sub0_low = sub[0].lower()
                if sub0_low == "userfiles" and len(sub) >= 3:
                    return f"C:\\Users\\{sub[1]}\\" + "\\".join(sub[2:])
                if sub0_low == "wwwroot" and len(sub) >= 2:
                    return "C:\\inetpub\\wwwroot\\" + "\\".join(sub[1:])
                if _PARTITION_PREFIX_RE.match(sub[0]) and len(sub) >= 2:
                    return "C:\\" + "\\".join(sub[1:])
                if len(sub) == 1:
                    sz = file_size if file_size is not None else (resolved.stat().st_size if resolved.exists() else 0)
                    if mft_lookup and (sub[0].lower(), sz) in mft_lookup:
                        return mft_lookup[(sub[0].lower(), sz)]
                return "C:\\" + "\\".join(sub)

            # staging/System32/... -> C:\Windows\System32\...
            if head_low == "system32" and len(parts) >= 2:
                return "C:\\Windows\\System32\\" + "\\".join(parts[1:])

            return "C:\\" + "\\".join(parts)

        try:
            rel_carved = resolved.relative_to(carved_dir).as_posix()
            return f"[Carved] {rel_carved}"
        except ValueError:
            pass

        return str(resolved)

    def _collect_scan_files(
        self,
        target_dir: Optional[Union[str, Path]],
        vfs_lookup: Dict[str, str],
        mft_lookup: Dict[Tuple[str, int], str],
    ) -> List[Tuple[Path, str]]:
        """
        Walk scan root(s), exclude Stinger/tool output folders and .yar rule files,
        and order richer staging paths (UserFiles, VSS, deep Enrichment) ahead of flat
        Enrichment copies so duplicate staged files are deduplicated cleanly.
        """
        roots: List[Path] = []
        if target_dir is not None:
            t_root = Path(target_dir).resolve()
            if t_root.exists():
                roots.append(t_root)
        else:
            if self.staging_dir.exists():
                roots.append(self.staging_dir)
            carved_dir = (get_case_dir(self.case_id) / "carved").resolve()
            if carved_dir.exists() and carved_dir not in roots:
                roots.append(carved_dir)

        case_rules_dir = (get_case_dir(self.case_id) / "rules").resolve()
        global_rules_dir = RULES_DIR.resolve()
        raw_entries: List[Tuple[int, Path, str]] = []

        for r_dir in roots:
            if r_dir.is_file():
                log_p = self.resolve_logical_path(r_dir, vfs_lookup, mft_lookup)
                raw_entries.append((0, r_dir, log_p))
                continue

            for walk_root, dirs, files in os.walk(r_dir):
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in self._EXCLUDED_WALK_DIRS
                ]
                w_path = Path(walk_root).resolve()
                if w_path == case_rules_dir or w_path == global_rules_dir:
                    dirs[:] = []
                    continue

                for fname in files:
                    fname_up = fname.upper()
                    if target_dir is None and (
                        fname_up in ("$MFT", "$J") or fname_up.endswith(("_$MFT", "_$J"))
                    ):
                        continue
                    p = (w_path / fname).resolve()
                    ext = p.suffix.lower()
                    if ext in (".yar", ".yara"):
                        continue
                    try:
                        st_size = p.stat().st_size
                    except OSError:
                        continue
                    if st_size > 150 * 1024 * 1024:
                        continue

                    logical = self.resolve_logical_path(p, vfs_lookup, mft_lookup, file_size=st_size)
                    # Priority: prefer paths with richer directory hierarchy over flat staging/Enrichment/<file>
                    is_flat_enrichment = False
                    try:
                        rel_parts = p.relative_to(self.staging_dir).parts
                        if len(rel_parts) == 2 and rel_parts[0].lower() == "enrichment":
                            is_flat_enrichment = True
                    except ValueError:
                        pass
                    prio = 1 if is_flat_enrichment else 0
                    raw_entries.append((prio, p, logical))

        raw_entries.sort(key=lambda item: (item[0], str(item[1]).lower()))
        return [(p, logical) for _, p, logical in raw_entries]

    def _is_yara_candidate(
        self, file_path: Path, data: bytes, logical_path: str = "", file_size: Optional[int] = None
    ) -> bool:
        if not data:
            return False

        # Skip Defender signature updates, WinSxS manifests, and browser cache blobs
        low_logical = logical_path.replace("/", "\\").lower()
        if any(frag in low_logical for frag in self._YARA_SKIP_PATH_FRAGMENTS):
            return False

        # Skip forensic OS metadata staging roots (Registry, MFT, EVTX, Prefetch, SRUM, etc.)
        try:
            rel_parts = file_path.resolve().relative_to(self.staging_dir).parts
            if rel_parts and rel_parts[0].lower() in self._YARA_SKIP_STAGING_ROOTS:
                return False
        except ValueError:
            pass

        ext = file_path.suffix.lower()
        if ext in self._NON_YARA_BINARY_EXTENSIONS:
            return False

        # Always scan PEs (MZ header) and LNK files
        if len(data) >= 2 and data[:2] == b"MZ":
            return True
        if len(data) >= 8 and data[:8] == b"\x4c\x00\x00\x00\x01\x14\x02\x00":
            return True

        # Reject known binary forensic containers by magic bytes
        if any(data.startswith(magic) for magic in self._BINARY_CONTAINER_MAGICS):
            return False

        if ext in self.YARA_EXTENSIONS:
            return True

        # Only scan extensionless files if small and mostly printable text (e.g. scripts/configs)
        actual_size = file_size if file_size is not None else len(data)
        if ext == "" and actual_size <= 512 * 1024:
            sample = data[:4096]
            if b"\x00" not in sample:
                return True

        return False

    def compile_yara_rules(self) -> Any:
        if yara_x is None:
            raise ImportError("yara-x is not installed. Please install via requirements.txt")

        compiler = yara_x.Compiler()
        sources_added = 0
        compiled_paths: Set[Path] = set()

        if RULES_DIR.is_dir():
            for rule_file in sorted(RULES_DIR.glob("**/*.yar*")):
                if rule_file.is_file() and rule_file.suffix.lower() in (".yar", ".yara"):
                    try:
                        rf_res = rule_file.resolve()
                        rule_text = rf_res.read_text(encoding="utf-8", errors="replace")
                        compiler.new_namespace(rf_res.stem)
                        compiler.add_source(rule_text, origin=str(rf_res))
                        compiled_paths.add(rf_res)
                        sources_added += 1
                    except Exception as ex:
                        self._log(f"Warning loading rule file {rule_file}: {ex}", level="WARNING")

        case_rules_dir = (get_case_dir(self.case_id) / "rules").resolve()
        if case_rules_dir.is_dir():
            for rule_file in sorted(case_rules_dir.glob("**/*.yar*")):
                if rule_file.is_file() and rule_file.suffix.lower() in (".yar", ".yara"):
                    rf_res = rule_file.resolve()
                    if rf_res in compiled_paths:
                        continue
                    try:
                        rule_text = rf_res.read_text(encoding="utf-8", errors="replace")
                        compiler.new_namespace(f"case_{rf_res.stem}")
                        compiler.add_source(rule_text, origin=str(rf_res))
                        compiled_paths.add(rf_res)
                        sources_added += 1
                    except Exception as ex:
                        self._log(f"Warning loading case rule file {rule_file}: {ex}", level="WARNING")

        # Always compile explicit custom rules_path if provided and not already compiled
        if self._explicit_rules_path is not None and self._explicit_rules_path.exists():
            if self._explicit_rules_path.is_dir():
                for rule_file in sorted(self._explicit_rules_path.glob("**/*.yar*")):
                    if rule_file.is_file() and rule_file.suffix.lower() in (".yar", ".yara"):
                        rf_res = rule_file.resolve()
                        if rf_res not in compiled_paths:
                            rule_text = rf_res.read_text(encoding="utf-8", errors="replace")
                            compiler.new_namespace(f"custom_{rf_res.stem}")
                            compiler.add_source(rule_text, origin=str(rf_res))
                            compiled_paths.add(rf_res)
                            sources_added += 1
            elif self._explicit_rules_path.is_file() and self._explicit_rules_path not in compiled_paths:
                rule_text = self._explicit_rules_path.read_text(encoding="utf-8", errors="replace")
                compiler.new_namespace(f"custom_{self._explicit_rules_path.stem}")
                compiler.add_source(rule_text, origin=str(self._explicit_rules_path))
                compiled_paths.add(self._explicit_rules_path)
                sources_added += 1
        elif sources_added == 0 and self.rules_path.exists():
            rule_text = self.rules_path.read_text(encoding="utf-8", errors="replace")
            compiler.new_namespace(self.rules_path.stem)
            compiler.add_source(rule_text, origin=str(self.rules_path))
            sources_added += 1

        if sources_added == 0:
            raise FileNotFoundError(f"No YARA rules found in {RULES_DIR} or {self.rules_path}")

        return compiler.build()

    def scan_yara(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_workers: Optional[int] = None,
        _precollected: Optional[Tuple[Dict[str, str], Dict[Tuple[str, int], str], List[Tuple[Path, str]]]] = None,
    ) -> Tuple[int, int]:
        workers = self._resolve_workers(max_workers)
        if _precollected is not None:
            vfs_lookup, mft_lookup, scan_items = _precollected
        else:
            vfs_lookup, mft_lookup = self._load_path_lookups()
            scan_items = self._collect_scan_files(target_dir, vfs_lookup, mft_lookup)

        if not scan_items:
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cur = conn.cursor()
                self._ensure_tables(cur)
                if target_dir is None:
                    cur.execute("DELETE FROM artifact_yara_hits;")
                    cur.execute("DELETE FROM file_enrichment;")
                hits_count = cur.execute("SELECT COUNT(*) FROM artifact_yara_hits;").fetchone()[0]
                cur.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'malware_yara_hits', 'MALWARE & YARA', 'YARA Rule Hits', 'artifact_yara_hits', 'YARA-X', ?, CURRENT_TIMESTAMP
                    );
                    """,
                    [hits_count],
                )
                self._sync_file_enrichment_registry(cur)
            self._ensure_all_malware_view()
            return (0, 0)

        compiled_rules = self.compile_yara_rules()
        thread_local = threading.local()
        sha_cache_lock = threading.Lock()
        # Cache YARA scan outcomes per SHA-256 to avoid rescanning duplicate WinSxS/VSS copies
        sha_yara_cache: Dict[str, Tuple[List[str], List[Dict[str, Any]], List[Tuple[Any, ...]]]] = {}

        def _get_thread_scanner() -> Any:
            scanner = getattr(thread_local, "scanner", None)
            if scanner is None:
                scanner = yara_x.Scanner(compiled_rules)
                try:
                    scanner.set_timeout(15)
                except Exception:
                    pass
                try:
                    scanner.max_matches_per_pattern(50)
                except Exception:
                    pass
                thread_local.scanner = scanner
            return scanner

        def _scan_single_file(item: Tuple[Path, str]) -> Optional[Dict[str, Any]]:
            file_path, logical_path = item
            try:
                file_size = file_path.stat().st_size
            except OSError:
                return None

            ext = file_path.suffix.lower()
            if file_size == 0:
                data = b""
                sha256 = hashlib.sha256(b"").hexdigest().lower()
                is_candidate = False
            else:
                try:
                    with open(file_path, "rb") as fh:
                        header_sample = fh.read(4096)
                except OSError:
                    return None
                is_candidate = self._is_yara_candidate(file_path, header_sample, logical_path, file_size=file_size)
                if not is_candidate:
                    # Avoid loading up to 150 MiB non-YARA files into RAM across 32 threads; stream-hash in O(1) memory
                    data = b""
                    if file_size <= 4096:
                        sha256 = hashlib.sha256(header_sample).hexdigest().lower()
                    else:
                        sha256 = self.compute_sha256(file_path)
                else:
                    try:
                        data = header_sample if file_size <= 4096 else file_path.read_bytes()
                    except OSError:
                        return None
                    file_size = len(data)
                    sha256 = hashlib.sha256(data).hexdigest().lower()

            yara_hit_rows: List[List[Any]] = []
            matched_rule_names: List[str] = []
            file_offsets_list: List[Dict[str, Any]] = []

            if is_candidate and file_size > 0:
                with sha_cache_lock:
                    cached = sha_yara_cache.get(sha256)

                if cached is not None:
                    matched_rule_names, file_offsets_list, cached_rule_tuples = cached
                else:
                    matched_rule_names = []
                    file_offsets_list = []
                    cached_rule_tuples: List[Tuple[Any, ...]] = []
                    scanner = _get_thread_scanner()
                    try:
                        scan_results = scanner.scan(data)
                        matching_rules = list(scan_results.matching_rules)
                    except Exception as scan_err:
                        self._log(
                            f"Warning: YARA-X scan skipped on {file_path.name} ({scan_err})",
                            level="WARNING",
                        )
                        matching_rules = []

                    for rule in matching_rules:
                        rule_name = rule.identifier
                        rule_ns = rule.namespace or "default"
                        matched_rule_names.append(rule_name)

                        meta_dict = dict(rule.metadata) if hasattr(rule, "metadata") else {}
                        severity = str(meta_dict.get("severity", "High"))
                        cat = str(meta_dict.get("category", "Malware & YARA"))
                        desc = str(meta_dict.get("description", f"Rule {rule_name} matched"))
                        mitre = str(meta_dict.get("mitre_attack", ""))

                        primary_pat_id = "condition"
                        primary_offset = 0
                        primary_length = 0
                        primary_hex = ""
                        total_rule_matches = 0
                        rule_offsets_recorded = 0

                        for pattern in rule.patterns:
                            pat_matches = list(pattern.matches)
                            if not pat_matches:
                                continue
                            pat_id = pattern.identifier
                            for match in pat_matches:
                                total_rule_matches += 1
                                offset = int(match.offset)
                                length = int(match.length)
                                if total_rule_matches == 1:
                                    primary_pat_id = pat_id
                                    primary_offset = offset
                                    primary_length = length
                                    primary_hex = data[offset : offset + min(length, 256)].hex()
                                if rule_offsets_recorded < 25:
                                    rule_offsets_recorded += 1
                                    match_hex = data[offset : offset + min(length, 128)].hex()
                                    file_offsets_list.append(
                                        {
                                            "rule": rule_name,
                                            "identifier": pat_id,
                                            "offset": offset,
                                            "length": length,
                                            "data_hex": match_hex,
                                            "severity": severity,
                                            "category": cat,
                                            "description": desc,
                                            "mitre_attack": mitre,
                                        }
                                    )

                        desc_with_count = (
                            f"{desc} ({total_rule_matches} pattern matches)"
                            if total_rule_matches > 1
                            else desc
                        )
                        cached_rule_tuples.append(
                            (
                                rule_name,
                                rule_ns,
                                primary_pat_id,
                                primary_offset,
                                primary_length,
                                primary_hex,
                                severity,
                                cat,
                                desc_with_count,
                                mitre,
                            )
                        )

                    with sha_cache_lock:
                        sha_yara_cache[sha256] = (
                            matched_rule_names,
                            file_offsets_list,
                            cached_rule_tuples,
                        )

                # Emit exactly ONE row per (file, rule) to prevent offset row explosion
                for rule_tuple in cached_rule_tuples:
                    yara_hit_rows.append(
                        [
                            logical_path,
                            file_path.name,
                            ext,
                            file_size,
                            sha256,
                            *rule_tuple,
                        ]
                    )

            json_rules = json.dumps(sorted(set(matched_rule_names))) if matched_rule_names else None
            json_offsets = json.dumps(file_offsets_list) if file_offsets_list else None

            return {
                "file_path": file_path,
                "logical_path": logical_path,
                "file_name": file_path.name,
                "ext": ext,
                "size_bytes": file_size,
                "sha256": sha256,
                "json_rules": json_rules,
                "json_offsets": json_offsets,
                "yara_hits": yara_hit_rows,
                "matched": bool(matched_rule_names),
            }

        with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
            worker_results = list(pool.map(_scan_single_file, scan_items))

        # Deduplicate identical staged copies (e.g. UserFiles/<u>/foo.ps1 vs flat Enrichment/foo.ps1)
        seen_logical: Set[Tuple[str, str]] = set()
        seen_rich_sha_name: Set[Tuple[str, str]] = set()
        enrichment_rows: List[List[Any]] = []
        all_yara_rows: List[List[Any]] = []
        matched_files_count = 0

        for res in worker_results:
            if res is None:
                continue
            sha = res["sha256"]
            lpath = res["logical_path"]
            fname_low = res["file_name"].lower()

            is_flat_c_root = bool(re.match(r"^[A-Za-z]:\\[^\\]+$", lpath))
            if is_flat_c_root and (sha, fname_low) in seen_rich_sha_name:
                continue

            dedup_key = (sha, lpath.lower())
            if dedup_key in seen_logical:
                continue
            seen_logical.add(dedup_key)
            if not is_flat_c_root:
                seen_rich_sha_name.add((sha, fname_low))

            enrichment_rows.append(
                [
                    lpath,
                    res["file_name"],
                    res["ext"],
                    res["size_bytes"],
                    sha,
                    res["json_rules"],
                    res["json_offsets"],
                ]
            )
            if res["matched"]:
                matched_files_count += 1
                all_yara_rows.extend(res["yara_hits"])

        total_hits = len(all_yara_rows)

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            self._ensure_tables(cur)

            # Preserve any existing OCR text by file_path before refreshing file_enrichment
            existing_ocr: Dict[str, str] = {}
            for fp_old, ocr_txt in cur.execute(
                "SELECT file_path, ocr_extracted_text FROM file_enrichment WHERE ocr_extracted_text IS NOT NULL;"
            ).fetchall():
                existing_ocr[str(fp_old)] = str(ocr_txt)

            cur.execute("BEGIN TRANSACTION;")
            try:
                cur.execute("DELETE FROM artifact_yara_hits;")
                if target_dir is None:
                    cur.execute("DELETE FROM file_enrichment;")
                elif enrichment_rows:
                    cur.executemany(
                        "DELETE FROM file_enrichment WHERE file_path = ?;",
                        [[r[0]] for r in enrichment_rows],
                    )

                if enrichment_rows:
                    full_enrich_params = [
                        [r[0], r[1], r[2], r[3], r[4], r[5], r[6], existing_ocr.get(r[0])]
                        for r in enrichment_rows
                    ]
                    cur.executemany(
                        """
                        INSERT INTO file_enrichment (
                            _row_id, file_path, file_name, extension, size_bytes, sha256,
                            yara_rules_matched, yara_match_offsets, ocr_extracted_text, archive_parent, scanned_at
                        ) VALUES (
                            nextval('seq_enrichment_id'), ?, ?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP
                        );
                        """,
                        full_enrich_params,
                    )

                if all_yara_rows:
                    cur.executemany(
                        """
                        INSERT INTO artifact_yara_hits (
                            _row_id, file_path, file_name, extension, size_bytes, sha256,
                            rule_name, rule_namespace, pattern_identifier,
                            match_offset, match_length, match_data_hex,
                            severity, category, description, mitre_attack, scanned_at
                        ) VALUES (
                            nextval('seq_yara_id'),
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
                        );
                        """,
                        all_yara_rows,
                    )

                hits_count = cur.execute("SELECT COUNT(*) FROM artifact_yara_hits;").fetchone()[0]
                cur.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'malware_yara_hits', 'MALWARE & YARA', 'YARA Rule Hits', 'artifact_yara_hits', 'YARA-X', ?, CURRENT_TIMESTAMP
                    );
                    """,
                    [hits_count],
                )
                self._sync_file_enrichment_registry(cur)
                cur.execute("COMMIT;")
            except Exception:
                try:
                    cur.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

        self._ensure_all_malware_view()
        return total_hits, matched_files_count

    @staticmethod
    def _is_microsoft_os_pe(pe: Any, data: bytes) -> bool:
        try:
            if hasattr(pe, "FileInfo"):
                for fileinfo in pe.FileInfo:
                    entries = fileinfo if isinstance(fileinfo, list) else [fileinfo]
                    for entry in entries:
                        if getattr(entry, "Key", b"") == b"StringFileInfo":
                            for st in getattr(entry, "StringTable", []):
                                s_dict = {
                                    k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore")
                                    for k, v in st.entries.items()
                                }
                                comp = s_dict.get("CompanyName", "")
                                prod = s_dict.get("ProductName", "")
                                if "Microsoft Corporation" in comp and "Windows" in prod and "Operating System" in prod:
                                    return True
        except Exception:
            pass

        ms_corp_wide = "Microsoft Corporation".encode("utf-16le")
        win_os_wide_1 = "Microsoft\u00ae Windows\u00ae Operating System".encode("utf-16le")
        win_os_wide_2 = "Microsoft Windows Operating System".encode("utf-16le")
        if ms_corp_wide in data and (win_os_wide_1 in data or win_os_wide_2 in data):
            return True
        return False

    @classmethod
    def _analyze_pe_bytes(
        cls,
        file_path: Path,
        logical_path: str,
        data: bytes,
        sha256: str,
    ) -> List[List[Any]]:
        """
        Zero-false-positive multi-indicator PE heuristics on unsigned non-OS PE binaries only:
          - PE-1: Unsigned PE + >=4 hollowing/remote-injection APIs + packed/high-entropy RWX section
          - PE-2: Unsigned PE + simultaneous RWX section (>=4096 B, entropy > 7.75) + suspicious network/injection APIs
        """
        if pefile is None or len(data) < 64 or data[:2] != b"MZ":
            return []

        pe = None
        hits: List[List[Any]] = []
        try:
            pe = pefile.PE(data=data, fast_load=True)

            # Guard 1: Skip Authenticode-signed binaries (e.g. stinger64.exe, Microsoft/vendor tools)
            try:
                sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_idx:
                    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
                    if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                        return []
            except Exception:
                pass

            packer_markers = {
                ".upx0", ".upx1", ".upx2", "upx0", "upx1", ".aspack", ".adata",
                ".mpress1", ".mpress2", ".themida", ".vmp0", ".vmp1", ".enigma",
            }
            has_packer_sec = False
            matched_packer_sec = ""
            has_rwx_765 = False
            has_rwx_775_4k = False
            max_rwx_entropy = 0.0

            for section in getattr(pe, "sections", []):
                try:
                    sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00").strip()
                    sec_low = sec_name.lower()
                    if sec_low in packer_markers or any(p in sec_low for p in (".upx", "themida", ".vmp")):
                        has_packer_sec = True
                        matched_packer_sec = sec_name
                    chars = int(getattr(section, "Characteristics", 0))
                    is_exec = bool(chars & 0x20000000)
                    is_write = bool(chars & 0x80000000)
                    if is_exec and is_write:
                        ent = float(section.get_entropy())
                        if ent > max_rwx_entropy:
                            max_rwx_entropy = ent
                        if ent > 7.65:
                            has_rwx_765 = True
                        if int(getattr(section, "SizeOfRawData", 0)) >= 4096 and ent > 7.75:
                            has_rwx_775_4k = True
                except Exception:
                    continue

            # Both PE-1 and PE-2 require a packer section or high-entropy RWX section;
            # skip expensive directory parsing on benign/standard unsigned PEs & installers.
            if not (has_packer_sec or has_rwx_765):
                return []

            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                ]
            )

            # Guard 2: Skip Microsoft Windows OS binaries via VS_VERSIONINFO
            if cls._is_microsoft_os_pe(pe, data):
                return []

            imported_apis: Set[str] = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imported_apis.add(imp.name.decode("utf-8", errors="ignore"))

            # Rule PE-1: Trojan.Injector.HollowingMultiIndicator
            exec_thread_apis = {
                "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
                "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "Wow64SetThreadContext",
            }
            unmap_resume_apis = {"NtUnmapViewOfSection", "ZwUnmapViewOfSection", "ResumeThread"}
            if (
                "VirtualAllocEx" in imported_apis
                and "WriteProcessMemory" in imported_apis
                and bool(imported_apis & exec_thread_apis)
                and bool(imported_apis & unmap_resume_apis)
                and (has_packer_sec or has_rwx_765)
            ):
                hits.append(
                    [
                        logical_path,
                        file_path.name,
                        sha256,
                        "Trojan.Injector.HollowingMultiIndicator",
                        "PE Heuristic: Process Hollowing & Packed/RWX Anomaly",
                        "Flagged",
                        "Heuristics-Engine 3.0",
                        "Threat Heuristics Engine",
                        (
                            f"Unsigned PE imports multi-stage hollowing chain "
                            f"(VirtualAllocEx, WriteProcessMemory, thread/unmap APIs) "
                            f"with {'packer section ' + matched_packer_sec if has_packer_sec else f'high-entropy RWX section ({max_rwx_entropy:.2f})'}"
                        ),
                    ]
                )

            # Rule PE-2: Packer.Suspicious.RWXHighEntropy
            net_or_inj_apis = {
                "URLDownloadToFileA", "URLDownloadToFileW",
                "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpOpen",
            }
            has_susp_imports = bool(imported_apis & net_or_inj_apis) or (
                "VirtualAllocEx" in imported_apis and "CreateRemoteThread" in imported_apis
            )
            if has_rwx_775_4k and has_susp_imports and not hits:
                hits.append(
                    [
                        logical_path,
                        file_path.name,
                        sha256,
                        "Packer.Suspicious.RWXHighEntropy",
                        "PE Heuristic: Unsigned RWX High-Entropy Stub",
                        "Flagged",
                        "Heuristics-Engine 3.0",
                        "Threat Heuristics Engine",
                        (
                            f"Unsigned PE contains simultaneous Executable+Writable (RWX) section "
                            f"(>=4KB, entropy {max_rwx_entropy:.2f} > 7.75) with "
                            f"{'packer section ' + matched_packer_sec + ' and ' if has_packer_sec else ''}"
                            f"suspicious network/injection imports"
                        ),
                    ]
                )
        except Exception:
            return []
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception:
                    pass
        return hits

    @classmethod
    def _analyze_script_bytes(
        cls,
        file_path: Path,
        logical_path: str,
        data: bytes,
        sha256: str,
    ) -> List[List[Any]]:
        """
        Zero-false-positive multi-indicator script heuristics (UTF-8 & UTF-16LE aware):
          - SC-1: PowerShell -EncodedCommand (>=40 base64 chars) with decoded malicious primitives OR hidden+bypass flags
          - SC-2: Active non-comment download cradle combining HTTP(S) fetch + in-memory IEX/Assembly execution
          - SC-3: Explicit Mimikatz module execution commands (sekurlsa::*, lsadump::*, Invoke-Mimikatz)
        """
        if not data or len(data) > 5 * 1024 * 1024:
            return []
        if len(data) >= 2 and data[:2] == b"MZ":
            return []

        ext = file_path.suffix.lower()
        text = _decode_script_bytes(data)
        if not text.strip():
            return []

        # Skip minified web/Node JS bundles unless explicit Windows Script Host objects are used
        if ext in (".js", ".jse"):
            low_js = text.lower()
            if "wscript.shell" not in low_js and "activexobject" not in low_js:
                return []

        active_lines: List[str] = []
        for raw_ln in text.splitlines():
            s = raw_ln.strip()
            if not s or s.startswith("#") or s.startswith("//") or s.lower().startswith("rem "):
                continue
            active_lines.append(s)
        if not active_lines:
            return []

        active_text = "\n".join(active_lines)
        hits: List[List[Any]] = []

        # Rule SC-1: Suspicious.PowerShell.EncodedPayload
        for enc_m in _PS_ENC_CMD_RE.finditer(active_text):
            b64_tok = enc_m.group(1)
            full_match_line = enc_m.group(0)
            decoded_malicious = False
            try:
                padded = b64_tok + ("=" * ((4 - len(b64_tok) % 4) % 4))
                raw_dec = base64.b64decode(padded, validate=False)
                dec_str = _decode_script_bytes(raw_dec)
                if _PS_DECODED_MAL_RE.search(dec_str):
                    decoded_malicious = True
            except Exception:
                pass

            has_evasion_combo = bool(
                _PS_HIDDEN_RE.search(full_match_line) and _PS_BYPASS_RE.search(full_match_line)
            )
            if decoded_malicious or has_evasion_combo:
                hits.append(
                    [
                        logical_path,
                        file_path.name,
                        sha256,
                        "Suspicious.PowerShell.EncodedPayload",
                        "Script Heuristic: Obfuscated PowerShell Payload",
                        "Flagged",
                        "Heuristics-Engine 3.0",
                        "Threat Heuristics Engine",
                        "PowerShell encoded command contains verified in-memory execution primitives or hidden/bypass evasion flags",
                    ]
                )
                break

        # Rule SC-2: Dropper.PowerShell.DownloadCradle
        has_url = bool(re.search(r"https?://", active_text, re.IGNORECASE))
        has_inmem = bool(_PS_INMEM_EXEC_RE.search(active_text))
        has_direct_dl_string = bool(_PS_DIRECT_CRADLE_FETCH_RE.search(active_text))
        has_alt_fetch_with_evasion = bool(
            _PS_ALT_FETCH_RE.search(active_text)
            and (_PS_HIDDEN_RE.search(active_text) or _PS_BYPASS_RE.search(active_text))
        )
        if has_url and has_inmem and (has_direct_dl_string or has_alt_fetch_with_evasion):
            hits.append(
                [
                    logical_path,
                    file_path.name,
                    sha256,
                    "Dropper.PowerShell.DownloadCradle",
                    "Script Heuristic: In-Memory Download Cradle",
                    "Flagged",
                    "Heuristics-Engine 3.0",
                    "Threat Heuristics Engine",
                    "Script fetches remote HTTP(S) payload and executes directly in memory via IEX / Reflection",
                ]
            )

        # Rule SC-3: HackTool.CredentialAccess.Mimikatz
        if _MIMIKATZ_CMD_RE.search(active_text):
            hits.append(
                [
                    logical_path,
                    file_path.name,
                    sha256,
                    "HackTool.CredentialAccess.Mimikatz",
                    "Script Heuristic: Credential Dumping Commands",
                    "Flagged",
                    "Heuristics-Engine 3.0",
                    "Threat Heuristics Engine",
                    "Script invokes explicit LSASS/SAM credential dumping module commands",
                ]
            )

        return hits

    def scan_stinger(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_workers: Optional[int] = None,
        _precollected: Optional[Tuple[Dict[str, str], Dict[Tuple[str, int], str], List[Tuple[Path, str]]]] = None,
    ) -> int:
        start_time = time.time()
        workers = self._resolve_workers(max_workers)
        scan_root = Path(target_dir).resolve() if target_dir is not None else self.staging_dir

        if not scan_root.exists():
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cur = conn.cursor()
                self._ensure_tables(cur)
                if target_dir is None:
                    cur.execute("DELETE FROM artifact_stinger_hits;")
                cnt = cur.execute("SELECT COUNT(*) FROM artifact_stinger_hits;").fetchone()[0]
                cur.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'malware_stinger_hits', 'MALWARE & YARA', 'Trellix Stinger & PE Threat Hits',
                        'artifact_stinger_hits', 'Trellix/PE-Heuristic', ?, CURRENT_TIMESTAMP
                    );
                    """,
                    [cnt],
                )
            self._ensure_all_malware_view()
            return 0

        if _precollected is not None:
            vfs_lookup, mft_lookup, scan_items = _precollected
        else:
            vfs_lookup, mft_lookup = self._load_path_lookups()
            scan_items = self._collect_scan_files(target_dir, vfs_lookup, mft_lookup)
        stinger_rows: List[List[Any]] = []

        # 1. Isolated Headless Trellix Stinger CLI Scan
        stinger_bin = find_stinger_binary()
        stinger_report_dir = (get_case_dir(self.case_id) / "stinger_reports").resolve()

        if stinger_bin and stinger_bin.is_file():
            stinger_mirror_dir: Optional[Path] = None
            try:
                stinger_report_dir.mkdir(parents=True, exist_ok=True)
                for old_report in stinger_report_dir.glob("*"):
                    if old_report.is_file():
                        try:
                            old_report.unlink()
                        except OSError:
                            pass

                effective_scan_root = scan_root
                if target_dir is None and scan_items:
                    total_stg_bytes = 0
                    exceeds_threshold = False
                    for cand_f, _lpath in scan_items:
                        try:
                            total_stg_bytes += cand_f.stat().st_size
                        except OSError:
                            continue
                        if total_stg_bytes > 64 * 1024 * 1024:
                            exceeds_threshold = True
                            break
                    if exceeds_threshold:
                        # Create mirror inside case_dir (same volume as staging_dir) so os.link() hardlinks with zero disk copy
                        mirror_parent = get_case_dir(self.case_id).resolve()
                        mirror_parent.mkdir(parents=True, exist_ok=True)
                        stinger_mirror_dir = Path(tempfile.mkdtemp(prefix="wft_stinger_in_", dir=str(mirror_parent))).resolve()
                        stinger_eligible_exts = (
                            self.PE_EXTENSIONS
                            | self.SCRIPT_EXTENSIONS
                            | {
                                ".msi", ".cab", ".jar", ".class", ".war", ".lnk", ".url",
                                ".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm",
                                ".docx", ".xlsx", ".pptx", ".pdf", ".rtf",
                                ".zip", ".7z", ".rar", ".gz", ".tar", ".iso",
                                ".php", ".asp", ".aspx", ".jsp", ".jspx", ".py", ".sh", ".elf", ".bin",
                            }
                        )
                        skip_stinger_names = {"$mft", "$j", "$usnjrnl", "$logfile", "srudb.dat", "objects.data"}
                        linked_count = 0
                        for item_path, _logical in scan_items:
                            low_n = item_path.name.lower()
                            ext_low = item_path.suffix.lower()
                            if low_n in skip_stinger_names or (ext_low and ext_low not in stinger_eligible_exts):
                                continue
                            try:
                                rel_p = item_path.resolve().relative_to(self.staging_dir)
                            except ValueError:
                                continue
                            if rel_p.parts and rel_p.parts[0].lower() in ("registry", "mft", "usnjrnl", "logs", "srum", "wbem"):
                                continue
                            try:
                                f_sz = item_path.stat().st_size
                            except OSError:
                                continue
                            if f_sz <= 0 or f_sz > 32 * 1024 * 1024:
                                continue
                            dst_link = stinger_mirror_dir / rel_p
                            try:
                                dst_link.parent.mkdir(parents=True, exist_ok=True)
                                try:
                                    os.link(item_path, dst_link)
                                except OSError:
                                    shutil.copy2(item_path, dst_link)
                                linked_count += 1
                            except OSError:
                                continue
                        effective_scan_root = stinger_mirror_dir

                env = os.environ.copy()
                env["__COMPAT_LAYER"] = "RunAsInvoker"
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

                cmd = [
                    str(stinger_bin),
                    "--GO",
                    "--SILENT",
                    "--REPORTONLY",
                    "--NOPROCESS",
                    "--NOREGISTRY",
                    "--NOROOTKIT",
                    "--NOBOOT",
                    "--NOWMI",
                    "--NOARTEMIS",
                    f"--SCANPATH={str(effective_scan_root)}",
                    f"--REPORTPATH={str(stinger_report_dir)}",
                ]
                st_proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    creationflags=creationflags,
                )
                try:
                    st_proc.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    if os.name == "nt":
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/T", "/PID", str(st_proc.pid)],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                creationflags=creationflags,
                                timeout=10,
                            )
                        except Exception:
                            try:
                                st_proc.kill()
                            except Exception:
                                pass
                    else:
                        st_proc.kill()
                    try:
                        st_proc.wait(timeout=10)
                    except Exception:
                        pass

                for rfile in sorted(stinger_report_dir.glob("*.*")):
                    if rfile.suffix.lower() in (".html", ".htm", ".txt", ".log"):
                        try:
                            parsed_hits = self.parse_stinger_report(rfile)
                            for hit in parsed_hits:
                                det_raw_path = Path(hit["file_path"])
                                if stinger_mirror_dir is not None:
                                    try:
                                        rel_mirror = det_raw_path.resolve().relative_to(stinger_mirror_dir)
                                        orig_cand = (self.staging_dir / rel_mirror).resolve()
                                        if orig_cand.is_file():
                                            det_raw_path = orig_cand
                                    except Exception:
                                        pass
                                if det_raw_path.is_file():
                                    det_sha = self.compute_sha256(det_raw_path)
                                    det_logical = self.resolve_logical_path(
                                        det_raw_path, vfs_lookup, mft_lookup
                                    )
                                    det_fname = det_raw_path.name
                                else:
                                    det_sha = None
                                    det_logical = hit["file_path"]
                                    det_fname = Path(hit["file_path"].replace("\\", "/")).name or hit["file_path"]

                                stinger_rows.append(
                                    [
                                        det_logical,
                                        det_fname,
                                        det_sha,
                                        hit["malware_name"],
                                        "Trellix Stinger AV",
                                        hit.get("action_taken", "Reported"),
                                        hit.get("engine_version", "Trellix Stinger"),
                                        "Trellix Stinger",
                                        hit.get("details", ""),
                                    ]
                                )
                        except Exception as log_err:
                            self._log(f"Warning parsing Stinger report {rfile}: {log_err}", level="WARNING")
            except Exception as stinger_err:
                self._log(
                    f"Notice on Trellix Stinger execution: {stinger_err}. Continuing with Threat Heuristics.",
                    level="WARNING",
                )
            finally:
                if stinger_mirror_dir is not None:
                    shutil.rmtree(stinger_mirror_dir, ignore_errors=True)

        # 2. Parallel Multi-Indicator PE & Script Heuristics (deduplicated by SHA-256 cache)
        heur_sha_cache: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
        heur_cache_lock = threading.Lock()

        def _eval_heuristics(item: Tuple[Path, str]) -> Optional[Tuple[str, str, str, List[List[Any]]]]:
            file_path, logical_path = item
            ext = file_path.suffix.lower()
            try:
                st_size = file_path.stat().st_size
                if st_size == 0 or st_size > 150 * 1024 * 1024:
                    return None
                if ext not in self.PE_EXTENSIONS and ext not in self.SCRIPT_EXTENSIONS:
                    with open(file_path, "rb") as fh:
                        magic = fh.read(2)
                    if magic != b"MZ":
                        return None
                data = file_path.read_bytes()
            except OSError:
                return None

            sha256 = hashlib.sha256(data).hexdigest().lower()
            with heur_cache_lock:
                cached_templates = heur_sha_cache.get(sha256)

            if cached_templates is None:
                raw_hits: List[List[Any]] = []
                if len(data) >= 64 and data[:2] == b"MZ":
                    raw_hits.extend(self._analyze_pe_bytes(file_path, logical_path, data, sha256))
                elif ext in self.SCRIPT_EXTENSIONS:
                    raw_hits.extend(self._analyze_script_bytes(file_path, logical_path, data, sha256))
                cached_templates = [
                    (str(h[3]), str(h[4]), str(h[5]), str(h[6]), str(h[7]), str(h[8]))
                    for h in raw_hits
                ]
                with heur_cache_lock:
                    heur_sha_cache[sha256] = cached_templates

            if not cached_templates:
                return None

            local_hits = [
                [logical_path, file_path.name, sha256, *tmpl]
                for tmpl in cached_templates
            ]
            return (sha256, logical_path, file_path.name.lower(), local_hits)

        if scan_items:
            with ThreadPoolExecutor(max_workers=max(1, min(workers, 6))) as pool:
                heur_results = list(pool.map(_eval_heuristics, scan_items))

            seen_heur_logical: Set[Tuple[str, str, str]] = set()
            seen_heur_rich_name: Set[Tuple[str, str, str]] = set()
            for hres in heur_results:
                if hres is None:
                    continue
                sha, lpath, fname_low, h_rows = hres
                is_flat_c_root = bool(re.match(r"^[A-Za-z]:\\[^\\]+$", lpath))
                for hr in h_rows:
                    mal_name = hr[3]
                    if is_flat_c_root and (sha, fname_low, mal_name) in seen_heur_rich_name:
                        continue
                    key = (sha, lpath.lower(), mal_name)
                    if key in seen_heur_logical:
                        continue
                    seen_heur_logical.add(key)
                    if not is_flat_c_root:
                        seen_heur_rich_name.add((sha, fname_low, mal_name))
                    stinger_rows.append(hr)

        # Deduplicate exact (file_path, malware_name, engine) rows
        deduped_stinger_rows: List[List[Any]] = []
        seen_stinger_keys: Set[Tuple[str, str, str]] = set()
        for row in stinger_rows:
            k = (str(row[0]).lower(), str(row[3]).lower(), str(row[7]).lower())
            if k not in seen_stinger_keys:
                seen_stinger_keys.add(k)
                deduped_stinger_rows.append(row)

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            self._ensure_tables(cur)
            cur.execute("BEGIN TRANSACTION;")
            try:
                cur.execute("DELETE FROM artifact_stinger_hits;")

                if deduped_stinger_rows:
                    cur.executemany(
                        """
                        INSERT INTO artifact_stinger_hits (
                            _row_id, file_path, file_name, sha256, malware_name,
                            detection_type, action_taken, engine_version, engine, details, scanned_at
                        ) VALUES (
                            nextval('seq_stinger_id'), ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
                        );
                        """,
                        deduped_stinger_rows,
                    )

                stinger_count = cur.execute("SELECT COUNT(*) FROM artifact_stinger_hits;").fetchone()[0]
                cur.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'malware_stinger_hits', 'MALWARE & YARA', 'Trellix Stinger & PE Threat Hits',
                        'artifact_stinger_hits', 'Trellix/PE-Heuristic', ?, CURRENT_TIMESTAMP
                    );
                    """,
                    [stinger_count],
                )
                cur.execute("COMMIT;")
            except Exception:
                try:
                    cur.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

        self._ensure_all_malware_view()
        duration_ms = int((time.time() - start_time) * 1000)
        self._log(f"Stinger & Threat scan complete in {duration_ms}ms: {stinger_count} detections found.")
        return stinger_count

    @staticmethod
    def _insert_ocr_records_into_table(
        cursor: Any,
        table_name: str,
        records: List[Dict[str, Any]],
        use_seq_id: bool = False,
        row_id_offset: int = 0,
    ) -> None:
        if not records:
            return
        col_map = {
            str(r[0]).lower(): str(r[0])
            for r in cursor.execute(f'DESCRIBE "{table_name}";').fetchall()
        }
        ordered_keys = [
            "file_path",
            "file_name",
            "dimensions",
            "sha256",
            "extracted_text",
            "ocr_text",
            "confidence",
            "avg_confidence",
            "engine",
            "line_count",
            "char_count",
            "source_file",
        ]
        present_keys = [k for k in ordered_keys if k in col_map]
        if not present_keys:
            return

        sql_cols: List[str] = []
        sql_vals: List[str] = []
        has_row_id = "_row_id" in col_map
        if has_row_id:
            sql_cols.append(f'"{col_map["_row_id"]}"')
            sql_vals.append("nextval('seq_ocr_id')" if use_seq_id else "?")

        for k in present_keys:
            sql_cols.append(f'"{col_map[k]}"')
            sql_vals.append("?")

        if "scanned_at" in col_map:
            sql_cols.append(f'"{col_map["scanned_at"]}"')
            sql_vals.append("CURRENT_TIMESTAMP")

        params_batch: List[List[Any]] = []
        for idx, rec in enumerate(records, start=1):
            row_params: List[Any] = []
            if has_row_id and not use_seq_id:
                row_params.append(row_id_offset + idx)
            for k in present_keys:
                row_params.append(rec.get(k))
            params_batch.append(row_params)

        cursor.executemany(
            f'INSERT INTO "{table_name}" ({", ".join(sql_cols)}) VALUES ({", ".join(sql_vals)});',
            params_batch,
        )

    def scan_ocr(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_workers: Optional[int] = None,
        _precollected: Optional[Tuple[Dict[str, str], Dict[Tuple[str, int], str], List[Tuple[Path, str]]]] = None,
    ) -> int:
        scan_root = Path(target_dir).resolve() if target_dir is not None else self.staging_dir
        if not scan_root.exists():
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cur = conn.cursor()
                self._ensure_tables(cur)
                tables = {
                    r[0]
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                has_media_ocr = "media_ocr_results" in tables
                if target_dir is None:
                    cur.execute("DELETE FROM artifact_ocr_results;")
                    if has_media_ocr:
                        cur.execute("DELETE FROM media_ocr_results;")
                reg_table = "media_ocr_results" if has_media_ocr else "artifact_ocr_results"
                ocr_cnt = cur.execute(f'SELECT COUNT(*) FROM "{reg_table}";').fetchone()[0]
                cur.execute(
                    """
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                    ) VALUES (
                        'media_ocr_results', 'MEDIA', 'OCR Extracted Text', ?, 'RapidOCR', ?, CURRENT_TIMESTAMP
                    );
                    """,
                    [reg_table, ocr_cnt],
                )
            return 0

        if _precollected is not None:
            vfs_lookup, mft_lookup, scan_items = _precollected
        else:
            vfs_lookup, mft_lookup = self._load_path_lookups()
            scan_items = self._collect_scan_files(target_dir, vfs_lookup, mft_lookup)
        candidate_images = [
            (p, lpath)
            for p, lpath in scan_items
            if p.suffix.lower() in self.IMAGE_EXTENSIONS
        ]

        ocr_records: List[Dict[str, Any]] = []
        seen_ocr_keys: Set[Tuple[str, str]] = set()
        workers = self._resolve_workers(max_workers)

        if candidate_images:
            base_engine = self._get_or_create_ocr()
            if base_engine is None:
                return 0
            ocr_cls = _get_rapidocr_cls()
            is_standard_rapidocr = bool(ocr_cls is not None and isinstance(base_engine, ocr_cls))

            # Phase 1: Parallel pre-filter (size/dimensions/RecycleBin $I metadata) + SHA-256 deduplication across workers
            def _prep_image(item: Tuple[Path, str]) -> Optional[Tuple[Path, str, str, str]]:
                img_path, logical_path = item
                try:
                    fname_up = img_path.name.upper()
                    if fname_up.startswith("$I") and (
                        "recyclebin" in str(img_path).lower() or "$recycle.bin" in logical_path.lower()
                    ):
                        return None
                    st_size = img_path.stat().st_size
                    if st_size < 100:
                        return None
                    if is_standard_rapidocr and logical_path.startswith("[Carved]") and st_size < 16384:
                        return None
                    dim_str = "unknown"
                    try:
                        with Image.open(img_path) as img:
                            w, h = img.size
                            if (w < 30 and h < 30) or (w * h < 1200):
                                return None
                            if is_standard_rapidocr and logical_path.startswith("[Carved]") and (w < 80 or h < 40 or (w * h < 6400)):
                                return None
                            dim_str = f"{w}x{h}"
                    except Exception:
                        if is_standard_rapidocr:
                            return None
                    sha256 = self.compute_sha256(img_path)
                    return (img_path, logical_path, dim_str, sha256)
                except Exception as exc:
                    self._log(f"Warning: Failed OCR pre-check on {img_path}: {exc}", level="WARNING")
                    return None

            if workers > 1 and len(candidate_images) > 1:
                with ThreadPoolExecutor(max_workers=max(1, min(workers, 32, len(candidate_images)))) as prep_pool:
                    prepped = [r for r in prep_pool.map(_prep_image, candidate_images) if r is not None]
            else:
                prepped = [r for r in (_prep_image(it) for it in candidate_images) if r is not None]

            # Group by unique SHA-256 so duplicate images are only OCR'd once
            unique_sha_samples: Dict[str, Path] = {}
            for img_path, _lpath, _dim, sha256 in prepped:
                if sha256 not in unique_sha_samples:
                    unique_sha_samples[sha256] = img_path

            if unique_sha_samples:
                ocr_local = threading.local()

                cpu_cnt = os.cpu_count() or 4
                ocr_workers = max(1, min(workers, max(1, cpu_cnt // 2), 4, len(unique_sha_samples)))
                intra_threads = max(1, cpu_cnt // ocr_workers)

                def _get_worker_ocr() -> Any:
                    eng = getattr(ocr_local, "engine", None)
                    if eng is not None:
                        return eng
                    # Reuse base_engine if running single-threaded or if RapidOCR class isn't standard
                    if ocr_workers <= 1 or ocr_cls is None or not isinstance(base_engine, ocr_cls):
                        ocr_local.engine = base_engine
                        return base_engine
                    try:
                        eng = ocr_cls(
                            intra_op_num_threads=intra_threads,
                            inter_op_num_threads=1,
                        )
                    except TypeError:
                        try:
                            eng = ocr_cls()
                        except Exception:
                            eng = base_engine
                    except Exception:
                        eng = base_engine
                    ocr_local.engine = eng
                    return eng

                def _run_ocr_on_sample(pair: Tuple[str, Path]) -> Tuple[str, Optional[Tuple[str, float, int]]]:
                    sha256, img_path = pair
                    try:
                        eng = _get_worker_ocr()
                        if eng is base_engine and ocr_workers > 1:
                            with self._ocr_lock:
                                result, _ = eng(str(img_path))
                        else:
                            result, _ = eng(str(img_path))
                        if not result:
                            return (sha256, None)

                        extracted_lines: List[str] = []
                        confidences: List[float] = []
                        for line in result:
                            if not isinstance(line, (list, tuple)):
                                continue
                            txt_val: Optional[str] = None
                            raw_conf: Optional[float] = None
                            try:
                                if len(line) >= 3 and isinstance(line[1], str):
                                    txt_val = line[1]
                                    raw_conf = float(line[2])
                                elif (
                                    len(line) >= 2
                                    and isinstance(line[1], (list, tuple))
                                    and len(line[1]) >= 2
                                ):
                                    txt_val = str(line[1][0])
                                    raw_conf = float(line[1][1])
                                elif len(line) == 2 and isinstance(line[0], str):
                                    txt_val = line[0]
                                    raw_conf = float(line[1])
                            except (TypeError, ValueError, IndexError):
                                continue

                            if txt_val is not None and raw_conf is not None:
                                if 1.0 < raw_conf <= 100.0:
                                    raw_conf = raw_conf / 100.0
                                conf_clamped = max(0.0, min(1.0, raw_conf))
                                extracted_lines.append(txt_val)
                                confidences.append(conf_clamped)

                        extracted_text = "\n".join(extracted_lines).strip()
                        if not extracted_text:
                            return (sha256, None)

                        avg_conf = (
                            max(0.0, min(1.0, sum(confidences) / len(confidences)))
                            if confidences
                            else 1.0
                        )
                        non_empty_line_cnt = len([ln for ln in extracted_text.splitlines() if ln.strip()])
                        return (sha256, (extracted_text, avg_conf, non_empty_line_cnt))
                    except Exception as exc:
                        self._log(f"Warning: Failed OCR on {img_path}: {exc}", level="WARNING")
                        return (sha256, None)

                ocr_sha_cache: Dict[str, Optional[Tuple[str, float, int]]] = {}
                if ocr_workers > 1:
                    with ThreadPoolExecutor(max_workers=ocr_workers) as ocr_pool:
                        for sha_k, ocr_val in ocr_pool.map(_run_ocr_on_sample, list(unique_sha_samples.items())):
                            ocr_sha_cache[sha_k] = ocr_val
                else:
                    for pair in unique_sha_samples.items():
                        sha_k, ocr_val = _run_ocr_on_sample(pair)
                        ocr_sha_cache[sha_k] = ocr_val

                for img_path, logical_path, dim_str, sha256 in prepped:
                    key = (sha256, logical_path.lower())
                    if key in seen_ocr_keys:
                        continue
                    cached_ocr = ocr_sha_cache.get(sha256)
                    if cached_ocr is None:
                        continue
                    extracted_text, avg_conf, non_empty_line_cnt = cached_ocr
                    seen_ocr_keys.add(key)
                    ocr_records.append(
                        {
                            "file_path": logical_path,
                            "file_name": img_path.name,
                            "dimensions": dim_str,
                            "sha256": sha256,
                            "extracted_text": extracted_text,
                            "ocr_text": extracted_text,
                            "confidence": avg_conf,
                            "avg_confidence": avg_conf,
                            "engine": "RapidOCR",
                            "line_count": non_empty_line_cnt,
                            "char_count": len(extracted_text),
                            "source_file": logical_path,
                        }
                    )

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            self._ensure_tables(cur)
            tables = {
                r[0]
                for r in cur.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            has_media_ocr = "media_ocr_results" in tables

            if target_dir is None:
                cur.execute("DELETE FROM artifact_ocr_results;")
                if has_media_ocr:
                    cur.execute("DELETE FROM media_ocr_results;")
            elif ocr_records:
                del_paths = [[rec["file_path"]] for rec in ocr_records]
                cur.executemany("DELETE FROM artifact_ocr_results WHERE file_path = ?;", del_paths)
                if has_media_ocr:
                    cur.executemany("DELETE FROM media_ocr_results WHERE file_path = ?;", del_paths)

            if ocr_records:
                self._insert_ocr_records_into_table(
                    cur, "artifact_ocr_results", ocr_records, use_seq_id=True
                )
                if has_media_ocr:
                    max_m_id = int(
                        cur.execute("SELECT COALESCE(MAX(_row_id), 0) FROM media_ocr_results;").fetchone()[0] or 0
                    )
                    self._insert_ocr_records_into_table(
                        cur,
                        "media_ocr_results",
                        ocr_records,
                        use_seq_id=False,
                        row_id_offset=max_m_id,
                    )
                cur.executemany(
                    "UPDATE file_enrichment SET ocr_extracted_text = ? WHERE file_path = ?;",
                    [[rec["extracted_text"], rec["file_path"]] for rec in ocr_records],
                )

            reg_table = "media_ocr_results" if has_media_ocr else "artifact_ocr_results"
            ocr_count = cur.execute(f'SELECT COUNT(*) FROM "{reg_table}";').fetchone()[0]
            cur.execute(
                """
                INSERT OR REPLACE INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES (
                    'media_ocr_results', 'MEDIA', 'OCR Extracted Text', ?, 'RapidOCR', ?, CURRENT_TIMESTAMP
                );
                """,
                [reg_table, ocr_count],
            )
        return ocr_count

    def _hash_all_files_only(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_workers: Optional[int] = None,
        _precollected: Optional[Tuple[Dict[str, str], Dict[Tuple[str, int], str], List[Tuple[Path, str]]]] = None,
    ) -> int:
        workers = self._resolve_workers(max_workers)
        if _precollected is not None:
            vfs_lookup, mft_lookup, scan_items = _precollected
        else:
            vfs_lookup, mft_lookup = self._load_path_lookups()
            scan_items = self._collect_scan_files(target_dir, vfs_lookup, mft_lookup)
        if not scan_items:
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cur = conn.cursor()
                self._ensure_tables(cur)
                if target_dir is None:
                    cur.execute("DELETE FROM file_enrichment;")
                return self._sync_file_enrichment_registry(cur)

        def _hash_item(item: Tuple[Path, str]) -> Optional[List[Any]]:
            fp, lpath = item
            try:
                sz = fp.stat().st_size
                sha = self.compute_sha256(fp)
                return [lpath, fp.name, fp.suffix.lower(), sz, sha]
            except OSError:
                return None

        with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
            hashed = [r for r in pool.map(_hash_item, scan_items) if r is not None]

        deduped: List[List[Any]] = []
        seen: Set[Tuple[str, str]] = set()
        for r in hashed:
            k = (r[4], r[0].lower())
            if k not in seen:
                seen.add(k)
                deduped.append(r)

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            self._ensure_tables(cur)
            existing_ocr: Dict[str, str] = {}
            for fp_old, ocr_txt in cur.execute(
                "SELECT file_path, ocr_extracted_text FROM file_enrichment WHERE ocr_extracted_text IS NOT NULL;"
            ).fetchall():
                existing_ocr[str(fp_old)] = str(ocr_txt)

            if target_dir is None:
                cur.execute("DELETE FROM file_enrichment;")
            elif deduped:
                cur.executemany(
                    "DELETE FROM file_enrichment WHERE file_path = ?;",
                    [[r[0]] for r in deduped],
                )
            if deduped:
                params = [[r[0], r[1], r[2], r[3], r[4], existing_ocr.get(r[0])] for r in deduped]
                cur.executemany(
                    """
                    INSERT INTO file_enrichment (
                        _row_id, file_path, file_name, extension, size_bytes, sha256,
                        yara_rules_matched, yara_match_offsets, ocr_extracted_text, archive_parent, scanned_at
                    ) VALUES (
                        nextval('seq_enrichment_id'), ?, ?, ?, ?, ?, NULL, NULL, ?, NULL, CURRENT_TIMESTAMP
                    );
                    """,
                    params,
                )
            return self._sync_file_enrichment_registry(cur)

    def run(
        self,
        enable_yara: bool = True,
        enable_ocr: bool = True,
        enable_stinger: bool = True,
        enable_ioc: bool = True,
        max_workers: Optional[int] = None,
        target_dir: Optional[Union[str, Path]] = None,
        progress_hook: Optional[Any] = None,
    ) -> Dict[str, int]:
        workers = self._resolve_workers(max_workers)
        results: Dict[str, int] = {}
        if callable(progress_hook):
            try:
                progress_hook(73, "Indexing staged files for File Enrichment (IOC / YARA-X / Stinger / RapidOCR)...")
            except Exception:
                pass
        vfs_lookup, mft_lookup = self._load_path_lookups()
        scan_items = self._collect_scan_files(target_dir, vfs_lookup, mft_lookup)
        precollected = (vfs_lookup, mft_lookup, scan_items)

        def _run_yara_or_hash() -> Tuple[str, Optional[int]]:
            if enable_yara:
                yara_hits, _ = self.scan_yara(
                    target_dir=target_dir, max_workers=workers, _precollected=precollected
                )
                if callable(progress_hook):
                    try:
                        progress_hook(76, f"YARA-X & IOC hashing complete ({yara_hits} YARA detections).")
                    except Exception:
                        pass
                return ("artifact_yara_hits", yara_hits)
            self._hash_all_files_only(
                target_dir=target_dir, max_workers=workers, _precollected=precollected
            )
            if callable(progress_hook):
                try:
                    progress_hook(76, "IOC & SHA-256 file hashing complete.")
                except Exception:
                    pass
            return ("_hashed", None)

        tasks_to_run: List[Any] = [_run_yara_or_hash]
        if enable_stinger:
            def _run_stinger_task() -> Tuple[str, int]:
                st_hits = self.scan_stinger(target_dir=target_dir, max_workers=workers, _precollected=precollected)
                if callable(progress_hook):
                    try:
                        progress_hook(79, f"Trellix Stinger & PE Heuristics complete ({st_hits} detections).")
                    except Exception:
                        pass
                return ("artifact_stinger_hits", st_hits)

            tasks_to_run.append(_run_stinger_task)
        if enable_ocr:
            def _run_ocr_task() -> Tuple[str, int]:
                ocr_cnt = self.scan_ocr(target_dir=target_dir, max_workers=workers, _precollected=precollected)
                if callable(progress_hook):
                    try:
                        progress_hook(82, f"RapidOCR image text extraction complete ({ocr_cnt} images with text).")
                    except Exception:
                        pass
                return ("artifact_ocr_results", ocr_cnt)

            tasks_to_run.append(_run_ocr_task)

        if len(tasks_to_run) > 1 and workers > 1:
            with ThreadPoolExecutor(max_workers=len(tasks_to_run)) as stage_pool:
                futs = [stage_pool.submit(fn) for fn in tasks_to_run]
                for fut in as_completed(futs):
                    k, v = fut.result()
                    if v is not None:
                        results[k] = v
        else:
            for fn in tasks_to_run:
                k, v = fn()
                if v is not None:
                    results[k] = v

        # Ensure OCR text is synced into file_enrichment even when scan_ocr finished before scan_yara
        if enable_ocr and results.get("artifact_ocr_results", 0) > 0:
            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        UPDATE file_enrichment
                        SET ocr_extracted_text = o.extracted_text
                        FROM artifact_ocr_results o
                        WHERE file_enrichment.file_path = o.file_path
                          AND (file_enrichment.ocr_extracted_text IS NULL OR file_enrichment.ocr_extracted_text = '');
                        """
                    )
                except Exception:
                    pass

        self._ensure_all_malware_view()

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cur = conn.cursor()
            self._ensure_tables(cur)
            enrich_count = self._sync_file_enrichment_registry(cur)
        results["file_enrichment"] = enrich_count
        return results

    # Backward-compatible aliases required by M4 SCOPE.md & callers
    run_full_enrichment = run
    run_stinger_scan = scan_stinger
    run_ocr = scan_ocr