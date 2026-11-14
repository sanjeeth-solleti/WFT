"""
Windows Forensic Toolkit (WFT) DFIR Suite - Base Forensic Parser
Provides standardized base functionality for non-EZ forensic parsers:
- DuckDB table creation & zero-copy DataFrame ingestion
- Safe SQLite file copying with WAL / SHM replay
- Standard DFIR timestamp conversions (WebKit, PRTime, Windows FILETIME)
- In-image evidence path resolution via $MFT
- Artifact registration into artifact_registry and audit logging into processing_logs
"""
import os
import re
import shutil
import sqlite3
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import duckdb
import pandas as pd

from backend.config import get_case_dir, get_case_log_file, get_case_staging_dir
from backend.db.engine import DuckDBManager, log_processing_event


# WebKit microseconds offset between Windows Epoch (1601-01-01) and Unix Epoch (1970-01-01)
WEBKIT_EPOCH_OFFSET_SECONDS = 11644473600


def webkit_to_datetime(webkit_microseconds: Union[int, float, None]) -> Optional[datetime]:
    """
    Convert WebKit timestamp (microseconds since Jan 1, 1601 UTC) to UTC datetime.
    Used by Chromium browsers (Chrome, Edge, Brave, Opera).
    """
    if webkit_microseconds is None:
        return None
    try:
        val = float(webkit_microseconds)
        if val <= 0:
            return None
        epoch_seconds = (val / 1_000_000.0) - WEBKIT_EPOCH_OFFSET_SECONDS
        if epoch_seconds < 0 or epoch_seconds > 4102444800:
            return None
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def prtime_to_datetime(prtime_microseconds: Union[int, float, None]) -> Optional[datetime]:
    """
    Convert Firefox PRTime timestamp (microseconds or milliseconds since Jan 1, 1970 UTC) to UTC datetime.
    """
    if prtime_microseconds is None:
        return None
    try:
        val = float(prtime_microseconds)
        if val <= 0:
            return None
        if val > 100_000_000_000_000:
            epoch_seconds = val / 1_000_000.0
        elif val > 100_000_000_000:
            epoch_seconds = val / 1_000.0
        else:
            epoch_seconds = val
        if epoch_seconds < 0 or epoch_seconds > 4102444800:
            return None
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def windows_filetime_to_datetime(filetime: Union[int, float, None]) -> Optional[datetime]:
    """
    Convert Windows 64-bit FILETIME (100-nanosecond intervals since Jan 1, 1601 UTC) to UTC datetime.
    """
    if filetime is None:
        return None
    try:
        val = float(filetime)
        if val <= 0:
            return None
        epoch_seconds = (val / 10_000_000.0) - WEBKIT_EPOCH_OFFSET_SECONDS
        if epoch_seconds < 0 or epoch_seconds > 4102444800:
            return None
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


# Alias for compatibility
filetime_to_datetime = windows_filetime_to_datetime


def copy_sqlite_with_wal(db_path: Path, temp_dir: Optional[Path] = None) -> Path:
    """
    Copies a SQLite database along with its associated write-ahead logs (-wal, -shm)
    or rollback journals (-journal) to a temporary directory.
    """
    db_path = Path(db_path).resolve()
    if temp_dir is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="wft_sqlite_"))
    else:
        temp_dir = Path(temp_dir)
        temp_dir.mkdir(parents=True, exist_ok=True)

    temp_db_path = temp_dir / db_path.name
    shutil.copy2(db_path, temp_db_path)

    base_name = db_path.name
    parent_dir = db_path.parent

    suffixes = [
        f"{base_name}-wal",
        f"{base_name}-shm",
        f"{base_name}-journal",
        f"{db_path.stem}.sqlite-wal",
        f"{db_path.stem}.sqlite-shm",
    ]

    for sfx in suffixes:
        wal_file = parent_dir / sfx
        if wal_file.is_file() and wal_file.stat().st_size > 0:
            try:
                shutil.copy2(wal_file, temp_dir / sfx)
            except Exception:
                pass

    return temp_db_path


class BaseParser:
    """
    Base forensic parser class.
    All custom application parsers (Chromium, Firefox, Chat, Cloud, CorporateIR, Document, Email, Media, USB) inherit from this.
    """

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        self.case_id = case_id
        self.case_dir = get_case_dir(case_id).resolve()
        self.staging_dir = (
            staging_dir.resolve() if staging_dir else get_case_staging_dir(case_id).resolve()
        )
        self.log_file = get_case_log_file(case_id).resolve()
        self.conn = DuckDBManager.get_connection(case_id, read_only=False)

    def _get_conn(self) -> duckdb.DuckDBPyConnection:
        return DuckDBManager.get_connection(self.case_id, read_only=False)

    def _log(self, message: str, level: str = "INFO") -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        formatted = f"[{timestamp}] [{level}] [{self.__class__.__name__}] {message}"
        print(formatted)
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                f.write(formatted + "\n")
        except Exception:
            pass

    def log_processing(
        self,
        module_name: str,
        command_executed: str,
        exit_code: int,
        rows_ingested: int,
        duration_ms: int,
        status: str = "SUCCESS",
        error_message: Optional[str] = None,
    ) -> None:
        try:
            log_processing_event(
                case_id=self.case_id,
                module_name=module_name,
                command_executed=command_executed,
                exit_code=exit_code,
                rows_ingested=rows_ingested,
                duration_ms=duration_ms,
                status=status,
                error_message=error_message,
            )
        except Exception as e:
            self._log(f"Warning logging processing event: {e}", "WARNING")

    def remove_artifact(self, artifact_id: str, table_name: str) -> None:
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()
            try:
                cursor.execute(f'DROP TABLE IF EXISTS "{table_name}";')
            except Exception:
                pass
            try:
                cursor.execute(f'DROP VIEW IF EXISTS "{table_name}";')
            except Exception:
                pass
            try:
                cursor.execute(
                    "DELETE FROM artifact_registry WHERE artifact_id = ? OR table_name = ?;",
                    [artifact_id, table_name],
                )
            except Exception:
                pass

    def register_artifact(
        self,
        table_name: str,
        artifact_id: str,
        category: str,
        display_name: str,
        source_tool: str,
        row_count: Optional[int] = None,
    ) -> int:
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()
            if row_count is None:
                try:
                    row_count = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()[0]
                except Exception:
                    row_count = 0

            cursor.execute(
                """
                INSERT INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, now())
                ON CONFLICT (artifact_id) DO UPDATE SET
                    category = EXCLUDED.category,
                    display_name = EXCLUDED.display_name,
                    table_name = EXCLUDED.table_name,
                    source_tool = EXCLUDED.source_tool,
                    row_count = EXCLUDED.row_count,
                    last_updated = now();
                """,
                [artifact_id, category, display_name, table_name, source_tool, int(row_count)],
            )
            return int(row_count)

    def insert_records(
        self,
        table_name: str,
        records: List[Dict[str, Any]],
        schema_ddl: Optional[str] = None,
        artifact_id: Optional[str] = None,
        category: Optional[str] = None,
        display_name: Optional[str] = None,
        source_tool: Optional[str] = None,
        append: bool = False,
    ) -> int:
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()

            if schema_ddl:
                cursor.execute(schema_ddl)

            if not records:
                if not append and artifact_id:
                    try:
                        cursor.execute(
                            "UPDATE artifact_registry SET row_count = 0, last_updated = now() WHERE artifact_id = ? OR table_name = ?;",
                            [artifact_id, table_name],
                        )
                    except Exception:
                        pass
                return 0

            df = pd.DataFrame(records)
            if "_row_id" in df.columns:
                df = df.drop(columns=["_row_id"])

            tables_existing = [
                r[0]
                for r in cursor.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            ]
            table_exists = table_name in tables_existing

            if table_exists and not append:
                cursor.execute(f'DELETE FROM "{table_name}";')

            temp_reg_name = f"temp_df_{table_name}_{int(time.time() * 1000)}"
            cursor.register(temp_reg_name, df)

            try:
                if not table_exists:
                    cursor.execute(
                        f"""
                        CREATE TABLE "{table_name}" AS
                        SELECT row_number() OVER () AS _row_id, *
                        FROM {temp_reg_name};
                        """
                    )
                else:
                    existing_cols_rows = cursor.execute(f'DESCRIBE "{table_name}";').fetchall()
                    existing_cols = [r[0] for r in existing_cols_rows if r[0] != "_row_id"]
                    max_id = cursor.execute(
                        f'SELECT COALESCE(MAX(_row_id), 0) FROM "{table_name}";'
                    ).fetchone()[0]

                    df_cols = list(df.columns)
                    common_cols = [c for c in existing_cols if c in df_cols]

                    cols_clause = ", ".join([f'"{c}"' for c in common_cols])
                    cursor.execute(
                        f"""
                        INSERT INTO "{table_name}" (_row_id, {cols_clause})
                        SELECT row_number() OVER () + {max_id} AS _row_id, {cols_clause}
                        FROM {temp_reg_name};
                        """
                    )
            finally:
                try:
                    cursor.unregister(temp_reg_name)
                except Exception:
                    pass

            total_count = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()[0]

            if artifact_id and category and display_name and source_tool:
                self.register_artifact(
                    table_name=table_name,
                    artifact_id=artifact_id,
                    category=category,
                    display_name=display_name,
                    source_tool=source_tool,
                    row_count=total_count,
                )

            return total_count

    def resolve_evidence_path(self, staged_file: Path, file_size: Optional[int] = None) -> str:
        r"""
        Resolves the original file path inside the forensic image using `raw_mft`
        or reconstructs C:\Users\... from the staging directory hierarchy, so
        `file_path` always shows the suspect's disk path while `source_file` holds the host staging path.
        """
        fname = staged_file.name
        try:
            with DuckDBManager.get_lock(self.case_id):
                cur = self.conn.cursor()
                tables = [
                    r[0]
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_name = 'raw_mft';"
                    ).fetchall()
                ]
                if tables:
                    row = cur.execute(
                        """
                        SELECT ParentPath, FileName
                        FROM raw_mft
                        WHERE LOWER(FileName) = LOWER(?)
                          AND LOWER(COALESCE(ParentPath, '')) NOT LIKE '%$recycle.bin%'
                        ORDER BY (CASE WHEN TRY_CAST(FileSize AS BIGINT) = ? THEN 0 ELSE 1 END) ASC,
                                 LastModified0x10 DESC NULLS LAST
                        LIMIT 1;
                        """,
                        [fname, int(file_size or 0)],
                    ).fetchone()
                    if row and row[0]:
                        pp = str(row[0]).replace("/", "\\")
                        if pp.startswith(".\\"):
                            pp = "C:\\" + pp[2:]
                        elif pp.startswith("."):
                            pp = "C:" + pp[1:]
                        elif pp.startswith("\\"):
                            pp = "C:" + pp
                        elif not re.match(r"^[A-Za-z]:", pp):
                            pp = "C:\\" + pp.lstrip("\\")
                        return f"{pp.rstrip('\\')}\\{row[1]}"
        except Exception:
            pass

        s_str = str(staged_file).replace("/", "\\")
        m_uf = re.search(r"(?i)\\staging\\UserFiles\\([^\\]+)\\(.+)$", s_str)
        if m_uf:
            return f"C:\\Users\\{m_uf.group(1)}\\{m_uf.group(2)}"
        m_en = re.search(r"(?i)\\staging\\Enrichment\\(.+)$", s_str)
        if m_en:
            return f"C:\\{m_en.group(1)}"
        m_us = re.search(r"(?i)\\(Users\\.+)$", s_str)
        if m_us:
            return f"C:\\{m_us.group(1)}"
        return f"C:\\Users\\Public\\{fname}"

    def parse(self) -> Dict[str, int]:
        self._log("Base parser parse() called", "INFO")
        return {}