"""
Windows Forensic Toolkit (WFT) DFIR Suite - Cloud Storage Sync Parser
Extracts synced, deleted, and configured file metadata, cloud identifiers,
user accounts, and timestamps from:
1. Microsoft OneDrive:
   - SyncEngineDatabase.db (synced files, cloud IDs, statuses)
   - SafeDelete.db (deleted files, restoration records, deletion timestamps)
   - .dat & .ini configuration logs in AppData/Local/Microsoft/OneDrive/settings/
2. Google Drive:
   - metadata_sqlite_db & DriveFS databases
Populates unified DuckDB table parsed_cloud_files with zero stubs.
"""
import configparser
import os
import re
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser, copy_sqlite_with_wal


CLOUD_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_cloud_files (
    _row_id BIGINT,
    cloud_provider VARCHAR,
    account VARCHAR,
    local_path VARCHAR,
    cloud_path_or_id VARCHAR,
    file_size BIGINT,
    modified_time TIMESTAMP,
    status VARCHAR,
    source_file VARCHAR
);
"""


class CloudParser(BaseParser):
    """
    Parser for Cloud Storage synchronization engines (Microsoft OneDrive, Google Drive).
    Handles SyncEngineDatabase.db, SafeDelete.db, .dat/.ini settings, and metadata_sqlite_db.
    """

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        super().__init__(case_id, staging_dir)
        self.email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    def _detect_provider_and_account(self, file_path: Path) -> Tuple[str, str]:
        """
        Infer cloud provider and account name from path.
        """
        path_lower = str(file_path).lower().replace("\\", "/")
        if "onedrive" in path_lower:
            provider = "OneDrive"
        elif "drivefs" in path_lower or "google" in path_lower:
            provider = "GoogleDrive"
        else:
            provider = "CloudStorage"

        parts = file_path.parts
        account = "Default"
        for p in reversed(parts[:-1]):
            if p.lower() not in ["settings", "personal", "cloud", "onedrive", "googledrive", "safedelete"]:
                account = p
                break

        return (provider, account)

    def _parse_onedrive_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """
        Parses OneDrive SyncEngineDatabase.db SQLite file.
        """
        provider, account = self._detect_provider_and_account(db_path)
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

                has_name = any(c in cols for c in ["filename", "name", "localpath", "path", "itemname", "relativepath"])
                if not has_name:
                    continue

                name_col = next(c for c in cols if c in ["filename", "name", "localpath", "path", "itemname", "relativepath"])
                id_col = next((c for c in cols if c in ["resourceid", "fileid", "cloudid", "itemid", "parentresourceid"]), None)
                size_col = next((c for c in cols if c in ["size", "filesize", "contentlength"]), None)
                time_col = next((c for c in cols if c in ["lastmodifiedtime", "lastmodified", "modifiedtime", "timestamp", "lastchangetime"]), None)
                status_col = next((c for c in cols if c in ["status", "syncstate", "filestate"]), None)

                id_expr = f'"{id_col}"' if id_col else "''"
                size_expr = f'"{size_col}"' if size_col else "0"
                time_expr = f'"{time_col}"' if time_col else "NULL"
                status_expr = f'"{status_col}"' if status_col else "'SYNCED'"

                q = f"""
                SELECT "{name_col}", {id_expr}, {size_expr}, {time_expr}, {status_expr}
                FROM "{table}"
                WHERE "{name_col}" IS NOT NULL AND length(trim("{name_col}")) > 0
                LIMIT 5000;
                """

                for row in cursor.execute(q).fetchall():
                    fname, cid, fsize, mtime, status = row
                    mtime_dt = None
                    if mtime is not None:
                        try:
                            if isinstance(mtime, (int, float)):
                                epoch_s = float(mtime)
                                if epoch_s > 1e11:  # milliseconds
                                    epoch_s /= 1000.0
                                mtime_dt = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
                            elif isinstance(mtime, str):
                                mtime_dt = datetime.fromisoformat(mtime.replace("Z", "+00:00"))
                        except Exception:
                            mtime_dt = None

                    records.append({
                        "cloud_provider": provider,
                        "account": account,
                        "local_path": str(fname),
                        "cloud_path_or_id": str(cid or ""),
                        "file_size": int(fsize) if fsize is not None else 0,
                        "modified_time": mtime_dt,
                        "status": str(status or "SYNCED"),
                        "source_file": str(db_path),
                    })
        finally:
            conn.close()

        return records

    def _parse_onedrive_safedelete_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """
        Parses OneDrive SafeDelete.db SQLite file for deleted files and restoration logs.
        """
        provider, account = self._detect_provider_and_account(db_path)
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

                has_path = any(c in cols for c in ["path", "filename", "name", "originalpath", "localpath", "relativepath"])
                if not has_path:
                    continue

                path_col = next(c for c in cols if c in ["path", "filename", "name", "originalpath", "localpath", "relativepath"])
                id_col = next((c for c in cols if c in ["resourceid", "itemid", "fileid", "id"]), None)
                size_col = next((c for c in cols if c in ["size", "filesize", "bytes"]), None)
                time_col = next((c for c in cols if c in ["deletiontime", "deletedtime", "timestamp", "modifiedtime", "lastmodified"]), None)

                id_expr = f'"{id_col}"' if id_col else "''"
                size_expr = f'"{size_col}"' if size_col else "0"
                time_expr = f'"{time_col}"' if time_col else "NULL"

                q = f"""
                SELECT "{path_col}", {id_expr}, {size_expr}, {time_expr}
                FROM "{table}"
                WHERE "{path_col}" IS NOT NULL AND length(trim("{path_col}")) > 0
                LIMIT 5000;
                """

                for row in cursor.execute(q).fetchall():
                    lpath, cid, fsize, dtime = row
                    dtime_dt = None
                    if dtime is not None:
                        try:
                            if isinstance(dtime, (int, float)):
                                epoch_s = float(dtime)
                                if epoch_s > 1e11:
                                    epoch_s /= 1000.0
                                dtime_dt = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
                            elif isinstance(dtime, str):
                                dtime_dt = datetime.fromisoformat(dtime.replace("Z", "+00:00"))
                        except Exception:
                            dtime_dt = None

                    records.append({
                        "cloud_provider": provider,
                        "account": account,
                        "local_path": str(lpath),
                        "cloud_path_or_id": str(cid or "SafeDelete"),
                        "file_size": int(fsize) if fsize is not None else 0,
                        "modified_time": dtime_dt,
                        "status": "SAFEDELETE",
                        "source_file": str(db_path),
                    })
        finally:
            conn.close()

        return records

    def _parse_gdrive_sqlite(self, db_path: Path, temp_dir: Path) -> List[Dict[str, Any]]:
        """
        Parses Google Drive metadata_sqlite_db SQLite file.
        """
        provider, account = self._detect_provider_and_account(db_path)
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

                has_title = any(c in cols for c in ["title", "local_title", "filename", "name", "original_title"])
                if not has_title:
                    continue

                title_col = next(c for c in cols if c in ["title", "local_title", "filename", "name", "original_title"])
                id_col = next((c for c in cols if c in ["cloud_id", "stable_id", "item_id", "doc_id"]), None)
                size_col = next((c for c in cols if c in ["file_size", "size", "bytes"]), None)
                time_col = next((c for c in cols if c in ["modified_date", "modified_time", "mtime", "modified"]), None)

                id_expr = f'"{id_col}"' if id_col else "''"
                size_expr = f'"{size_col}"' if size_col else "0"
                time_expr = f'"{time_col}"' if time_col else "NULL"

                q = f"""
                SELECT "{title_col}", {id_expr}, {size_expr}, {time_expr}
                FROM "{table}"
                WHERE "{title_col}" IS NOT NULL AND length(trim("{title_col}")) > 0
                LIMIT 5000;
                """

                for row in cursor.execute(q).fetchall():
                    title, cid, fsize, mtime = row
                    mtime_dt = None
                    if mtime is not None:
                        try:
                            if isinstance(mtime, (int, float)):
                                epoch_s = float(mtime)
                                if epoch_s > 1e11:
                                    epoch_s /= 1000.0
                                mtime_dt = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
                            elif isinstance(mtime, str):
                                mtime_dt = datetime.fromisoformat(mtime.replace("Z", "+00:00"))
                        except Exception:
                            mtime_dt = None

                    records.append({
                        "cloud_provider": provider,
                        "account": account,
                        "local_path": str(title),
                        "cloud_path_or_id": str(cid or ""),
                        "file_size": int(fsize) if fsize is not None else 0,
                        "modified_time": mtime_dt,
                        "status": "SYNCED",
                        "source_file": str(db_path),
                    })
        finally:
            conn.close()

        return records

    def _parse_onedrive_ini(self, ini_path: Path) -> List[Dict[str, Any]]:
        """
        Parses OneDrive configuration .ini files (Personal.ini, Business1.ini, global.ini).
        Extracts user account IDs, CID, and mapped OneDrive local roots.
        """
        provider, account = self._detect_provider_and_account(ini_path)
        records: List[Dict[str, Any]] = []

        try:
            content_str = ini_path.read_text(encoding="utf-8", errors="replace")
            mtime = datetime.fromtimestamp(ini_path.stat().st_mtime, tz=timezone.utc)

            # Look for UserFolder / Folder paths
            folder_matches = re.findall(r"(?i)(?:UserFolder|Folder|LibraryScope)\s*=\s*([A-Za-z]:\\[^\r\n]+)", content_str)
            user_matches = re.findall(r"(?i)(?:UserEmail|Email|UserName|UserCID|CID)\s*=\s*([^\r\n]+)", content_str)
            detected_account = user_matches[0].strip() if user_matches else account

            for fld in set(folder_matches):
                records.append({
                    "cloud_provider": provider,
                    "account": detected_account,
                    "local_path": fld.strip(),
                    "cloud_path_or_id": ini_path.stem,
                    "file_size": 0,
                    "modified_time": mtime,
                    "status": "CONFIGURED",
                    "source_file": str(ini_path),
                })

            # If no paths found, record the configuration entry itself
            if not folder_matches:
                records.append({
                    "cloud_provider": provider,
                    "account": detected_account,
                    "local_path": f"{ini_path.stem} Settings",
                    "cloud_path_or_id": ini_path.name,
                    "file_size": os.path.getsize(ini_path),
                    "modified_time": mtime,
                    "status": "CONFIGURED",
                    "source_file": str(ini_path),
                })
        except Exception as ex:
            self._log(f"Error reading OneDrive INI {ini_path.name}: {ex}", "DEBUG")

        return records

    def _parse_onedrive_dat(self, dat_path: Path) -> List[Dict[str, Any]]:
        """
        Parses OneDrive .dat settings files for account emails and folder mappings.
        """
        provider, account = self._detect_provider_and_account(dat_path)
        records: List[Dict[str, Any]] = []

        try:
            content_bytes = dat_path.read_bytes()
            content_str = content_bytes.decode("utf-8", errors="replace")
            mtime = datetime.fromtimestamp(dat_path.stat().st_mtime, tz=timezone.utc)

            emails = self.email_re.findall(content_str)
            detected_account = emails[0] if emails else account

            paths = re.findall(r"([A-Za-z]:\\[A-Za-z0-9_\-\.\s\\]{5,150})", content_str)
            for p in set(paths):
                records.append({
                    "cloud_provider": provider,
                    "account": detected_account,
                    "local_path": p.strip(),
                    "cloud_path_or_id": dat_path.stem,
                    "file_size": 0,
                    "modified_time": mtime,
                    "status": "CONFIGURED",
                    "source_file": str(dat_path),
                })
        except Exception as ex:
            self._log(f"Error reading OneDrive dat file {dat_path}: {ex}", "WARNING")

        return records

    def parse(self) -> Dict[str, int]:
        """
        Scan staging directory for cloud storage metadata and ingest into DuckDB.
        """
        start_time = time.time()
        self._log(f"Starting Cloud parser across staging directory: {self.staging_dir}")

        all_records: List[Dict[str, Any]] = []

        candidate_onedrive_db: List[Path] = []
        candidate_safedelete_db: List[Path] = []
        candidate_onedrive_dat: List[Path] = []
        candidate_onedrive_ini: List[Path] = []
        candidate_gdrive_db: List[Path] = []

        for p in self.staging_dir.rglob("*"):
            if not p.is_file():
                continue
            name_lower = p.name.lower()
            path_lower = str(p).lower().replace("\\", "/")

            if any(name_lower.endswith(sfx) for sfx in ["-wal", "-shm", "-journal"]):
                continue

            if "safedelete" in name_lower and name_lower.endswith(".db"):
                candidate_safedelete_db.append(p)
            elif "syncenginedatabase" in name_lower or (name_lower.endswith(".db") and "onedrive" in path_lower):
                candidate_onedrive_db.append(p)
            elif name_lower.endswith(".ini") and "onedrive" in path_lower:
                candidate_onedrive_ini.append(p)
            elif name_lower.endswith(".dat") and "onedrive" in path_lower:
                candidate_onedrive_dat.append(p)
            elif "metadata_sqlite_db" in name_lower or (name_lower.endswith(".db") and ("drivefs" in path_lower or "google" in path_lower)):
                candidate_gdrive_db.append(p)

        self._log(
            f"Found {len(candidate_onedrive_db)} OneDrive DBs, {len(candidate_safedelete_db)} SafeDelete DBs, "
            f"{len(candidate_onedrive_ini)} INIs, {len(candidate_onedrive_dat)} DATs, and {len(candidate_gdrive_db)} Google Drive DBs."
        )

        with tempfile.TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            # 1. Parse SyncEngineDatabase
            for odb in candidate_onedrive_db:
                try:
                    sub_temp = temp_dir / f"od_{int(time.time()*1000)}"
                    records = self._parse_onedrive_sqlite(odb, sub_temp)
                    all_records.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing OneDrive DB {odb}: {ex}", "WARNING")

            # 2. Parse SafeDelete
            for sdb in candidate_safedelete_db:
                try:
                    sub_temp = temp_dir / f"sd_{int(time.time()*1000)}"
                    records = self._parse_onedrive_safedelete_sqlite(sdb, sub_temp)
                    all_records.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing SafeDelete DB {sdb}: {ex}", "WARNING")

            # 3. Parse Google Drive
            for gdb in candidate_gdrive_db:
                try:
                    sub_temp = temp_dir / f"gd_{int(time.time()*1000)}"
                    records = self._parse_gdrive_sqlite(gdb, sub_temp)
                    all_records.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing Google Drive DB {gdb}: {ex}", "WARNING")

            # 4. Parse OneDrive INI configs
            for inif in candidate_onedrive_ini:
                try:
                    records = self._parse_onedrive_ini(inif)
                    all_records.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing OneDrive INI {inif}: {ex}", "WARNING")

            # 5. Parse OneDrive DAT configs
            for dat in candidate_onedrive_dat:
                try:
                    records = self._parse_onedrive_dat(dat)
                    all_records.extend(records)
                except Exception as ex:
                    self._log(f"Error parsing OneDrive DAT {dat}: {ex}", "WARNING")

        if all_records:
            row_count = self.insert_records(
                table_name="parsed_cloud_files",
                records=all_records,
                schema_ddl=CLOUD_SCHEMA_DDL,
                artifact_id="cloud_storage_files",
                category="CLOUD",
                display_name="Cloud Storage Files (OneDrive / Google Drive)",
                source_tool="CloudParser",
            )
        else:
            row_count = 0
            with DuckDBManager.get_lock(self.case_id):
                cursor = self.conn.cursor()
                cursor.execute("""
                    UPDATE artifact_registry
                    SET row_count = 0, last_updated = CURRENT_TIMESTAMP
                    WHERE table_name = 'parsed_cloud_files' OR artifact_id = 'cloud_storage_files';
                """)

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:Cloud",
            command_executed=f"CloudParser.parse({len(candidate_onedrive_db)} OneDrive, {len(candidate_safedelete_db)} SafeDelete, {len(candidate_gdrive_db)} GDrive)",
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(f"Cloud parser completed in {duration_ms}ms with {row_count} files ingested.")
        return {"parsed_cloud_files": row_count}
