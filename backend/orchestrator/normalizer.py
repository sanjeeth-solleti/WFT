"""
Windows Forensic Toolkit (WFT) DFIR Suite - Timeline & Connections Normalization Engine
Introspects populated raw_* forensic tables in case.duckdb, extracts chronological
timestamps into master_timeline, and normalizes high-value indicators into entity_connections.
Zero stubs, full SQL execution, and schema-introspecting design.
"""
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import duckdb

from backend.db.engine import DuckDBManager, log_processing_event
from backend.db.schema import CANONICAL_CATEGORIES


class _NoopCursorResult:
    def fetchall(self) -> List[Any]:
        return []

    def fetchone(self) -> Optional[Any]:
        return (0,)


class TimelineConnectionProxy:
    """
    Lightweight wrapper that skips entity_connections table population during
    forensic normalization while delegating all real SELECT/DESCRIBE/timeline queries.
    """
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        sql_str = str(sql)
        if "INSERT INTO entity_connections" in sql_str:
            return _NoopCursorResult()
        return self._conn.execute(sql, *args, **kwargs)

    def cursor(self) -> "TimelineConnectionProxy":
        return TimelineConnectionProxy(self._conn.cursor())

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


class TimelineNormalizer:
    """
    Forensic normalization engine that reads raw_* and parsed_* tables populated by EZ tools,
    disk/VFS extractors, and custom parsers, introspects column schemas dynamically, and populates
    master_timeline (with 4-char MACB flags) and entity_connections.
    """

    def __init__(self, case_id: str, populate_entities: bool = True) -> None:
        self.case_id = case_id
        self.populate_entities = populate_entities
        self._skip_per_table_clear = False
        with DuckDBManager.get_lock(case_id):
            real_conn = DuckDBManager.get_connection(case_id, read_only=False)
            try:
                real_conn.cursor().execute(
                    "ALTER TABLE master_timeline ADD COLUMN IF NOT EXISTS macb VARCHAR DEFAULT '';"
                )
            except Exception:
                pass
        self.conn = real_conn if populate_entities else TimelineConnectionProxy(real_conn)

    @staticmethod
    def _valid_ts_sql(expr: str) -> str:
        """
        SQL predicate ensuring expr is a real historical forensic timestamp
        (rejects NULL, 1601 Windows FILETIME zero, 1970 Unix epoch zero, and >= 2100 garbage).
        """
        return (
            f"(TRY_CAST({expr} AS TIMESTAMP) IS NOT NULL "
            f"AND TRY_CAST({expr} AS TIMESTAMP) > TIMESTAMP '1970-01-02 00:00:00' "
            f"AND TRY_CAST({expr} AS TIMESTAMP) < TIMESTAMP '2100-01-01 00:00:00')"
        )

    @classmethod
    def _clean_ts_expr(cls, expr: str) -> str:
        return f"CASE WHEN {cls._valid_ts_sql(expr)} THEN TRY_CAST({expr} AS TIMESTAMP) ELSE NULL END"

    @classmethod
    def _coalesce_ts_sql(cls, cols: Dict[str, str], *names: str, prefix: str = "") -> Optional[str]:
        found: List[str] = []
        for n in names:
            col = cols.get(n.lower())
            if col and col not in found:
                found.append(col)
        if not found:
            return None
        parts = [cls._clean_ts_expr(f'{prefix}"{c}"') for c in found]
        if len(parts) == 1:
            return parts[0]
        return "COALESCE(" + ", ".join(parts) + ")"

    @staticmethod
    def _coalesce_str_sql(
        cols: Dict[str, str], *names: str, prefix: str = "", default_sql: str = "NULL"
    ) -> str:
        found: List[str] = []
        for n in names:
            col = cols.get(n.lower())
            if col and col not in found:
                found.append(col)
        if not found:
            return default_sql
        parts = [f"NULLIF(TRIM(CAST({prefix}\"{c}\" AS VARCHAR)), '')" for c in found]
        if default_sql != "NULL":
            parts.append(default_sql)
        if len(parts) == 1:
            return parts[0]
        return "COALESCE(" + ", ".join(parts) + ")"

    @classmethod
    def _non_wallclock_ctime_sql(cls, ctime_expr: str, mtime_expr: Optional[str]) -> str:
        """
        Suppress Windows NTFS folder-staging/copy wall-clock st_ctime leaks where
        created/changed is within 2 hours of wall-clock now() while the same row's
        modified timestamp is historical (> 1 day older).
        Handles both UTC-naive (timezone('UTC', now())) and local-naive (CAST(now() AS TIMESTAMP)).
        """
        c_clean = cls._clean_ts_expr(ctime_expr)
        if not mtime_expr:
            return c_clean
        m_clean = cls._clean_ts_expr(mtime_expr)
        near_now = (
            f"(ABS(epoch({c_clean}) - epoch(timezone('UTC', now()))) <= 7200 "
            f"OR ABS(epoch({c_clean}) - epoch(CAST(now() AS TIMESTAMP))) <= 7200)"
        )
        return (
            f"(CASE WHEN ({c_clean}) IS NOT NULL AND NOT ("
            f"{near_now} AND ({m_clean}) IS NOT NULL "
            f"AND ({m_clean}) < (({c_clean}) - INTERVAL '1 day')"
            f") THEN ({c_clean}) ELSE NULL END)"
        )

    @staticmethod
    def _clean_path_sql(expr: str) -> str:
        """
        SQL expression restoring internal staging/VSS/Enrichment paths to clean forensic paths.
        """
        norm = f"REPLACE(TRIM(CAST({expr} AS VARCHAR)), '/', '\\')"
        return f"""CASE
            WHEN {expr} IS NULL THEN NULL
            WHEN regexp_matches({norm}, '(?i).*\\\\staging\\\\vss\\\\vss_([0-9]+)\\\\(.+)$') THEN
                '[VSS#' || regexp_extract({norm}, '(?i).*\\\\staging\\\\vss\\\\vss_([0-9]+)\\\\(.+)$', 1) || '] C:\\' ||
                regexp_replace(
                    regexp_extract({norm}, '(?i).*\\\\staging\\\\vss\\\\vss_([0-9]+)\\\\(.+)$', 2),
                    '^(?i)(?:part(?:ition)?[_-]?[0-9]+|vol(?:ume)?[_-]?[0-9]+|ntfs[_-]?[0-9]*|fat[0-9]*[_-]?[0-9]*|exfat[_-]?[0-9]*|[a-z]_drive|p[0-9]+)\\\\',
                    ''
                )
            WHEN regexp_matches({norm}, '(?i).*\\\\staging\\\\enrichment\\\\(.+)$') THEN
                'C:\\' || regexp_replace(
                    regexp_extract({norm}, '(?i).*\\\\staging\\\\enrichment\\\\(.+)$', 1),
                    '^(?i)(?:part(?:ition)?[_-]?[0-9]+|vol(?:ume)?[_-]?[0-9]+|ntfs[_-]?[0-9]*|fat[0-9]*[_-]?[0-9]*|exfat[_-]?[0-9]*|[a-z]_drive|p[0-9]+)\\\\',
                    ''
                )
            WHEN regexp_matches({norm}, '(?i).*\\\\staging\\\\userfiles\\\\([^\\\\]+)\\\\(.+)$') THEN
                'C:\\Users\\' || regexp_extract({norm}, '(?i).*\\\\staging\\\\userfiles\\\\([^\\\\]+)\\\\(.+)$', 1) || '\\' ||
                regexp_extract({norm}, '(?i).*\\\\staging\\\\userfiles\\\\([^\\\\]+)\\\\(.+)$', 2)
            ELSE TRIM(CAST({expr} AS VARCHAR))
        END"""

    def _get_columns(self, table_name: str) -> Dict[str, str]:
        """
        Introspect existing columns in table_name via DESCRIBE.
        Returns a dict mapping lowercase column names to their exact case-preserved names.
        """
        cursor = self.conn.cursor()
        describe_rows = cursor.execute(f'DESCRIBE "{table_name}";').fetchall()
        return {row[0].lower(): row[0] for row in describe_rows}

    def _table_exists(self, table_name: str) -> bool:
        """
        Check if table exists in the DuckDB database and has at least one row.
        """
        cursor = self.conn.cursor()
        tables = {
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if table_name not in tables:
            return False

        row_count = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()[0]
        return bool(row_count and row_count > 0)

    def _clear_table_normalizations(self, source_table: str) -> None:
        """
        Ensure idempotency by removing existing records for source_table before normalizing.
        """
        if getattr(self, "_skip_per_table_clear", False):
            return
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM master_timeline WHERE source_table = ?", [source_table])
        cursor.execute("DELETE FROM entity_connections WHERE source_table = ?", [source_table])

    # -------------------------------------------------------------------------
    # 1. raw_evtx (Security & System Event Logs)
    # -------------------------------------------------------------------------
    def _normalize_raw_evtx(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_evtx"
        time_created_col = cols.get("timecreated")
        if not time_created_col:
            return (0, 0)

        event_id_col = cols.get("eventid", "EventId")
        exec_info_col = cols.get("executableinfo")
        user_name_col = cols.get("username")
        remote_host_col = cols.get("remotehost")
        channel_col = cols.get("channel", "Channel")
        map_desc_col = cols.get("mapdescription")
        payload1_col = cols.get("payloaddata1")
        source_file_col = cols.get("sourcefile", "SourceFile")
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        # 1. Timeline SQL
        primary_expr = (
            f"COALESCE(NULLIF(TRIM(CAST(\"{exec_info_col}\" AS VARCHAR)), ''), NULLIF(TRIM(CAST(\"{user_name_col}\" AS VARCHAR)), ''), 'EID ' || CAST(\"{event_id_col}\" AS VARCHAR))"
            if (exec_info_col and user_name_col)
            else f"'EID ' || CAST(\"{event_id_col}\" AS VARCHAR)"
        )
        desc_expr = (
            f"COALESCE(NULLIF(TRIM(CAST(\"{map_desc_col}\" AS VARCHAR)), ''), NULLIF(TRIM(CAST(\"{payload1_col}\" AS VARCHAR)), ''), CAST(\"{channel_col}\" AS VARCHAR), '')"
            if (map_desc_col and payload1_col)
            else f"COALESCE(\"{channel_col}\", '')"
        )

        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{time_created_col}" AS TIMESTAMP),
            'Event Logged (EID ' || COALESCE(CAST("{event_id_col}" AS VARCHAR), 'Unknown') || ')',
            'EVENT LOGS',
            'Security & System Event Logs',
            {primary_expr},
            "{channel_col}",
            'EID ' || CAST("{event_id_col}" AS VARCHAR) || ': ' || {desc_expr},
            '{table_name}',
            "{row_id_col}",
            "{source_file_col}"
        FROM "{table_name}"
        WHERE TRY_CAST("{time_created_col}" AS TIMESTAMP) IS NOT NULL
          AND TRY_CAST("{time_created_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
          AND TRY_CAST("{time_created_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: ExecutableInfo -> FILE_PATH
        if exec_info_col:
            exec_entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                TRIM(CAST("{exec_info_col}" AS VARCHAR)),
                'EVENT LOGS',
                'Security & System Event Logs',
                '{table_name}',
                "{row_id_col}",
                'Event Log process path (EID ' || CAST("{event_id_col}" AS VARCHAR) || ')',
                TRY_CAST("{time_created_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{exec_info_col}" IS NOT NULL
              AND TRIM(CAST("{exec_info_col}" AS VARCHAR)) != '';
            """
            self.conn.execute(exec_entity_sql)

            # Executable name extraction if executable path/name present
            exec_bin_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EXECUTABLE',
                UPPER(TRIM(regexp_extract(CAST("{exec_info_col}" AS VARCHAR), '([^\\\\/]+)$', 1))),
                'OPERATING SYSTEM',
                'Security & System Event Logs',
                '{table_name}',
                "{row_id_col}",
                'Event Log process executable (EID ' || CAST("{event_id_col}" AS VARCHAR) || ')',
                TRY_CAST("{time_created_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{exec_info_col}" IS NOT NULL
              AND regexp_extract(CAST("{exec_info_col}" AS VARCHAR), '(?i)([^\\\\/]+\\.exe)$', 1) != '';
            """
            self.conn.execute(exec_bin_sql)

        # 3. Entity Connections: UserName -> USER_ACCOUNT
        if user_name_col:
            user_entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'USER_ACCOUNT',
                TRIM(CAST("{user_name_col}" AS VARCHAR)),
                'EVENT LOGS',
                'Security & System Event Logs',
                '{table_name}',
                "{row_id_col}",
                'Event Log user account (EID ' || CAST("{event_id_col}" AS VARCHAR) || ')',
                TRY_CAST("{time_created_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{user_name_col}" IS NOT NULL
              AND TRIM(CAST("{user_name_col}" AS VARCHAR)) != ''
              AND TRIM(CAST("{user_name_col}" AS VARCHAR)) NOT IN ('-', 'N/A', 'SYSTEM');
            """
            self.conn.execute(user_entity_sql)

        # 4. Entity Connections: RemoteHost -> IP_ADDRESS
        if remote_host_col:
            ip_entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'IP_ADDRESS',
                LOWER(TRIM(CAST("{remote_host_col}" AS VARCHAR))),
                'EVENT LOGS',
                'Security & System Event Logs',
                '{table_name}',
                "{row_id_col}",
                'Remote host connection (EID ' || CAST("{event_id_col}" AS VARCHAR) || ')',
                TRY_CAST("{time_created_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{remote_host_col}" IS NOT NULL
              AND TRIM(CAST("{remote_host_col}" AS VARCHAR)) != ''
              AND TRIM(CAST("{remote_host_col}" AS VARCHAR)) NOT IN ('-', '127.0.0.1', '::1');
            """
            self.conn.execute(ip_entity_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 2. raw_lecmd & raw_jlecmd_auto (LNK & JumpLists)
    # -------------------------------------------------------------------------
    def _normalize_raw_lecmd_generic(
        self,
        table_name: str,
        artifact_name: str,
        cols: Dict[str, str],
    ) -> Tuple[int, int]:
        local_path_col = cols.get("localpath") or cols.get("path")
        rel_path_col = cols.get("relativepath")
        serial_col = cols.get("volumeserialnumber") or cols.get("driveserialnumber")
        args_col = cols.get("arguments")
        source_file_col = cols.get("sourcefile", "SourceFile")
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        path_expr = (
            f"COALESCE(NULLIF(TRIM(CAST(\"{local_path_col}\" AS VARCHAR)), ''), NULLIF(TRIM(CAST(\"{rel_path_col}\" AS VARCHAR)), ''), CAST(\"{source_file_col}\" AS VARCHAR))"
            if (local_path_col and rel_path_col)
            else f"COALESCE(CAST(\"{local_path_col or source_file_col}\" AS VARCHAR), '')"
        )
        serial_expr = f"CAST(\"{serial_col}\" AS VARCHAR)" if serial_col else "NULL"
        args_expr = (
            f"CASE WHEN \"{args_col}\" IS NOT NULL AND TRIM(CAST(\"{args_col}\" AS VARCHAR)) != '' THEN ' [Args: ' || CAST(\"{args_col}\" AS VARCHAR) || ']' ELSE '' END"
            if args_col
            else "''"
        )

        # Timeline columns: SourceCreated, SourceModified, TargetCreated, TargetModified
        hist_ref_parts: List[str] = []
        for ref_k in ("sourcemodified", "targetmodified", "targetcreated", "lastmodified", "creationtime", "trackercreatedon"):
            rc = cols.get(ref_k)
            if rc:
                hist_ref_parts.append(self._clean_ts_expr(f'"{rc}"'))
        hist_ref_expr = ("COALESCE(" + ", ".join(hist_ref_parts) + ")") if hist_ref_parts else None

        target_ref_parts: List[str] = []
        for ref_k in ("targetmodified", "targetcreated", "lastmodified", "creationtime", "trackercreatedon"):
            rc = cols.get(ref_k)
            if rc:
                target_ref_parts.append(self._clean_ts_expr(f'"{rc}"'))
        target_ref_expr = ("COALESCE(" + ", ".join(target_ref_parts) + ")") if target_ref_parts else None

        timestamp_mappings = [
            ("sourcecreated", "Shortcut Created"),
            ("sourcemodified", "Shortcut Modified"),
            ("targetcreated", "Target File Created"),
            ("targetmodified", "Target File Modified"),
        ]

        for col_key, ts_type in timestamp_mappings:
            ts_col = cols.get(col_key)
            if ts_col:
                if col_key == "sourcecreated":
                    ts_val_expr = self._non_wallclock_ctime_sql(f'"{ts_col}"', hist_ref_expr)
                elif col_key == "sourcemodified":
                    ts_val_expr = self._non_wallclock_ctime_sql(f'"{ts_col}"', target_ref_expr)
                else:
                    ts_val_expr = self._clean_ts_expr(f'"{ts_col}"')
                timeline_sql = f"""
                INSERT INTO master_timeline (
                    timeline_id,
                    timestamp_utc,
                    timestamp_type,
                    category,
                    artifact_name,
                    primary_entity,
                    secondary_entity,
                    summary,
                    source_table,
                    source_row_id,
                    source_file
                )
                SELECT
                    nextval('seq_timeline_id'),
                    {ts_val_expr},
                    '{ts_type}',
                    'OPERATING SYSTEM',
                    '{artifact_name}',
                    {path_expr},
                    {serial_expr},
                    'Shortcut to: ' || {path_expr} || {args_expr},
                    '{table_name}',
                    "{row_id_col}",
                    "{source_file_col}"
                FROM "{table_name}"
                WHERE ({ts_val_expr}) IS NOT NULL;
                """
                self.conn.execute(timeline_sql)

        # Reference timestamp for entity connections
        best_ts = cols.get("sourcemodified") or cols.get("sourcecreated") or cols.get("targetcreated")
        ts_expr = f"TRY_CAST(\"{best_ts}\" AS TIMESTAMP)" if best_ts else "NULL"

        # Entity Connections: LocalPath / Path -> FILE_PATH
        if local_path_col:
            file_path_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                TRIM(CAST("{local_path_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                '{artifact_name}',
                '{table_name}',
                "{row_id_col}",
                'Shortcut target path',
                {ts_expr}
            FROM "{table_name}"
            WHERE "{local_path_col}" IS NOT NULL
              AND TRIM(CAST("{local_path_col}" AS VARCHAR)) != '';
            """
            self.conn.execute(file_path_sql)

            # Executable name extraction -> EXECUTABLE
            exec_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EXECUTABLE',
                UPPER(TRIM(regexp_extract(CAST("{local_path_col}" AS VARCHAR), '([^\\\\/]+)$', 1))),
                'OPERATING SYSTEM',
                '{artifact_name}',
                '{table_name}',
                "{row_id_col}",
                'Shortcut target executable',
                {ts_expr}
            FROM "{table_name}"
            WHERE "{local_path_col}" IS NOT NULL
              AND TRIM(CAST("{local_path_col}" AS VARCHAR)) != ''
              AND regexp_extract(CAST("{local_path_col}" AS VARCHAR), '([^\\\\/]+)$', 1) != '';
            """
            self.conn.execute(exec_sql)

        # Entity Connections: VolumeSerialNumber / DriveSerialNumber -> USB_SERIAL
        if serial_col:
            serial_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'USB_SERIAL',
                UPPER(TRIM(CAST("{serial_col}" AS VARCHAR))),
                'OPERATING SYSTEM',
                '{artifact_name}',
                '{table_name}',
                "{row_id_col}",
                'Volume/Drive serial number for shortcut target',
                {ts_expr}
            FROM "{table_name}"
            WHERE "{serial_col}" IS NOT NULL
              AND TRIM(CAST("{serial_col}" AS VARCHAR)) != '';
            """
            self.conn.execute(serial_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 3. raw_pecmd (Prefetch)
    # -------------------------------------------------------------------------
    def _normalize_raw_pecmd(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_pecmd"
        last_run_col = cols.get("lastrun")
        exec_name_col = cols.get("executablename")
        hash_col = cols.get("hash")
        run_count_col = cols.get("runcount")
        vol_name_col = cols.get("volume0name")
        src_file_col = cols.get("sourcefilename") or cols.get("sourcefile", "SourceFilename")
        row_id_col = cols.get("_row_id", "_row_id")

        if not exec_name_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)

        summary_expr = (
            f"'Run Count: ' || COALESCE(CAST(\"{run_count_col}\" AS VARCHAR), '0') || ' | Volume: ' || COALESCE(CAST(\"{vol_name_col}\" AS VARCHAR), '')"
            if (run_count_col and vol_name_col)
            else f"COALESCE(CAST(\"{run_count_col}\" AS VARCHAR), 'Run Count N/A')"
            if run_count_col
            else "''"
        )
        hash_expr = f"CAST(\"{hash_col}\" AS VARCHAR)" if hash_col else "NULL"

        # 1. Timeline: LastRun (Run 1 of 8)
        if last_run_col:
            last_run_sql = f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                TRY_CAST("{last_run_col}" AS TIMESTAMP),
                'Executable Last Run (Run 1 of 8)',
                'OPERATING SYSTEM',
                'Prefetch (PECmd)',
                \"{exec_name_col}\",
                {hash_expr},
                {summary_expr} || ' | Run 1 of 8 (Latest)',
                '{table_name}',
                \"{row_id_col}\",
                \"{src_file_col}\"
            FROM "{table_name}"
            WHERE TRY_CAST("{last_run_col}" AS TIMESTAMP) IS NOT NULL
              AND TRY_CAST("{last_run_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
              AND TRY_CAST("{last_run_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
            """
            self.conn.execute(last_run_sql)

        # 2. Timeline: Previous runs (Runs 2 to 8 of 8)
        # Supports both 0-indexed (PreviousRun0..PreviousRun6) and 1-indexed (PreviousRun1..PreviousRun7)
        for i in range(10):
            prev_col = cols.get(f"previousrun{i}")
            if prev_col:
                run_num = i + 2 if cols.get("previousrun0") else i + 1
                run_label = f"Run {min(run_num, 8)} of 8"
                prev_sql = f"""
                INSERT INTO master_timeline (
                    timeline_id,
                    timestamp_utc,
                    timestamp_type,
                    category,
                    artifact_name,
                    primary_entity,
                    secondary_entity,
                    summary,
                    source_table,
                    source_row_id,
                    source_file
                )
                SELECT
                    nextval('seq_timeline_id'),
                    TRY_CAST("{prev_col}" AS TIMESTAMP),
                    'Executable Previous Run ({run_label})',
                    'OPERATING SYSTEM',
                    'Prefetch (PECmd)',
                    \"{exec_name_col}\",
                    {hash_expr},
                    'Run Count: ' || COALESCE(CAST(\"{run_count_col}\" AS VARCHAR), '0') || ' | Execution {run_label}',
                    '{table_name}',
                    \"{row_id_col}\",
                    \"{src_file_col}\"
                FROM "{table_name}"
                WHERE TRY_CAST("{prev_col}" AS TIMESTAMP) IS NOT NULL
                  AND TRY_CAST("{prev_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
                  AND TRY_CAST("{prev_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
                """
                self.conn.execute(prev_sql)

        # 3. Timeline: SourceCreated (guarded against NTFS host staging copy wall-clock st_ctime)
        src_created_col = cols.get("sourcecreated")
        src_mod_col = cols.get("sourcemodified")
        if src_created_col:
            pecmd_ref_parts: List[str] = []
            for pk in (src_mod_col, last_run_col):
                if pk:
                    pecmd_ref_parts.append(self._clean_ts_expr(f'"{pk}"'))
            pecmd_ref_expr = ("COALESCE(" + ", ".join(pecmd_ref_parts) + ")") if pecmd_ref_parts else None
            pecmd_ctime_expr = self._non_wallclock_ctime_sql(f'"{src_created_col}"', pecmd_ref_expr)
            created_sql = f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {pecmd_ctime_expr},
                'Prefetch File Created',
                'OPERATING SYSTEM',
                'Prefetch (PECmd)',
                \"{exec_name_col}\",
                {hash_expr},
                'Prefetch file created on disk',
                '{table_name}',
                \"{row_id_col}\",
                \"{src_file_col}\"
            FROM "{table_name}"
            WHERE ({pecmd_ctime_expr}) IS NOT NULL;
            """
            self.conn.execute(created_sql)

        # 4. Entity Connections: ExecutableName -> EXECUTABLE
        ref_ts = last_run_col or src_created_col
        ts_expr = f"TRY_CAST(\"{ref_ts}\" AS TIMESTAMP)" if ref_ts else "NULL"

        exec_entity_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER(TRIM(CAST(\"{exec_name_col}\" AS VARCHAR))),
            'OPERATING SYSTEM',
            'Prefetch (PECmd)',
            '{table_name}',
            \"{row_id_col}\",
            'Executed binary (Prefetch)',
            {ts_expr}
        FROM "{table_name}"
        WHERE \"{exec_name_col}\" IS NOT NULL
          AND TRIM(CAST(\"{exec_name_col}\" AS VARCHAR)) != '';
        """
        self.conn.execute(exec_entity_sql)

        # 5. Entity Connections: Hash -> PREFETCH_HASH
        if hash_col:
            hash_entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'PREFETCH_HASH',
                UPPER(TRIM(CAST(\"{hash_col}\" AS VARCHAR))),
                'OPERATING SYSTEM',
                'Prefetch (PECmd)',
                '{table_name}',
                \"{row_id_col}\",
                'Prefetch hash for ' || COALESCE(\"{exec_name_col}\", 'binary'),
                {ts_expr}
            FROM "{table_name}"
            WHERE \"{hash_col}\" IS NOT NULL
              AND TRIM(CAST(\"{hash_col}\" AS VARCHAR)) != '';
            """
            self.conn.execute(hash_entity_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 4. raw_mft ($MFT — Full 8-Timestamp $SI + $FN MACB Unpivot & Timestomp Detection)
    # -------------------------------------------------------------------------
    def _normalize_raw_mft(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_mft"
        filename_col = cols.get("filename")
        if not filename_col:
            return (0, 0)

        parentpath_col = cols.get("parentpath")
        ext_col = cols.get("extension")
        filesize_col = cols.get("filesize")
        inuse_col = cols.get("inuse")
        isdir_col = cols.get("isdirectory")
        inconsist_col = cols.get("timestampslogicalinconsistency")
        row_id_col = cols.get("_row_id")

        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        row_id_expr = f'COALESCE("{row_id_col}", rowid, 0)' if row_id_col else "COALESCE(rowid, 0)"
        parent_expr = f'COALESCE(CAST("{parentpath_col}" AS VARCHAR), \'\')' if parentpath_col else "''"
        fname_expr = f'COALESCE(CAST("{filename_col}" AS VARCHAR), \'\')'
        full_path_expr = (
            f"CASE WHEN {parent_expr} = '' OR {parent_expr} = '.' THEN {fname_expr} "
            f"WHEN right({parent_expr}, 1) IN ('\\', '/') THEN {parent_expr} || {fname_expr} "
            f"ELSE {parent_expr} || '\\' || {fname_expr} END"
        )
        del_prefix_expr = (
            f"CASE WHEN \"{inuse_col}\" IS NOT NULL AND (\"{inuse_col}\" = FALSE OR LOWER(CAST(\"{inuse_col}\" AS VARCHAR)) IN ('false', '0')) "
            f"THEN '[DELETED] ' ELSE '' END"
            if inuse_col
            else "''"
        )
        kind_expr = (
            f"CASE WHEN \"{isdir_col}\" IS NOT NULL AND (\"{isdir_col}\" = TRUE OR LOWER(CAST(\"{isdir_col}\" AS VARCHAR)) IN ('true', '1')) "
            f"THEN 'Directory ' ELSE 'File ' END"
            if isdir_col
            else "'File '"
        )
        size_meta_expr = (
            f"' (' || COALESCE(NULLIF(CAST(\"{ext_col}\" AS VARCHAR), ''), CASE WHEN {kind_expr} = 'Directory ' THEN 'DIR' ELSE 'no-ext' END) || ', ' || COALESCE(CAST(\"{filesize_col}\" AS VARCHAR), '0') || ' bytes)'"
            if (ext_col and filesize_col)
            else f"' (' || COALESCE(CAST(\"{filesize_col}\" AS VARCHAR), '0') || ' bytes)'"
            if filesize_col
            else "''"
        )

        c10 = cols.get("created0x10")
        c30 = cols.get("created0x30")
        if c10 and c30:
            c10_q = f'"{c10}"'
            c30_q = f'"{c30}"'
            ts_stomp_cond = (
                f"({self._valid_ts_sql(c10_q)} AND {self._valid_ts_sql(c30_q)} "
                f"AND TRY_CAST({c10_q} AS TIMESTAMP) < TRY_CAST({c30_q} AS TIMESTAMP))"
            )
            if inconsist_col:
                ts_stomp_cond = f"({ts_stomp_cond} OR \"{inconsist_col}\" = TRUE)"
            timestomp_suffix_expr = f"CASE WHEN {ts_stomp_cond} THEN ' [TIMESTOMP: $SI < $FN]' ELSE '' END"
        elif inconsist_col:
            timestomp_suffix_expr = f"CASE WHEN \"{inconsist_col}\" = TRUE THEN ' [TIMESTOMP: $SI < $FN]' ELSE '' END"
        else:
            timestomp_suffix_expr = "''"

        # Collect available 8-timestamp columns across $SI (0x10) and $FN (0x30)
        # Canonical DFIR / SleuthKit mactime: M=Modified, A=Accessed, C=Entry/Metadata Changed, B=Born/Created
        ts_specs = [
            ("$SI", "lastmodified0x10", 1, 0, 0, 0, "Modified", 1),
            ("$SI", "lastaccess0x10", 0, 1, 0, 0, "Accessed", 2),
            ("$SI", "created0x10", 0, 0, 0, 1, "Created", 3),
            ("$SI", "lastrecordchange0x10", 0, 0, 1, 0, "Entry Modified", 4),
            ("$FN", "lastmodified0x30", 1, 0, 0, 0, "Modified", 1),
            ("$FN", "lastaccess0x30", 0, 1, 0, 0, "Accessed", 2),
            ("$FN", "created0x30", 0, 0, 0, 1, "Created", 3),
            ("$FN", "lastrecordchange0x30", 0, 0, 1, 0, "Entry Modified", 4),
        ]
        union_branches = []
        for family, col_key, m_f, a_f, c_f, b_f, label, ord_idx in ts_specs:
            actual_col = cols.get(col_key)
            if not actual_col:
                continue
            col_ref = f'b."{actual_col}"'
            union_branches.append(f"""
                SELECT
                    b._src_row_id,
                    b._fname,
                    b._parent,
                    b._full_path,
                    b._base_summary,
                    '{family}' AS attr_family,
                    TRY_CAST({col_ref} AS TIMESTAMP) AS ts_val,
                    {m_f} AS m_flag,
                    {a_f} AS a_flag,
                    {c_f} AS c_flag,
                    {b_f} AS b_flag,
                    '{label}' AS role_label,
                    {ord_idx} AS role_ord
                FROM mft_base b
                WHERE {self._valid_ts_sql(col_ref)}
            """)

        if union_branches:
            unpivot_sql = "\nUNION ALL\n".join(union_branches)
            timeline_sql = f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                macb,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            WITH mft_base AS (
                SELECT
                    {row_id_expr} AS _src_row_id,
                    {fname_expr} AS _fname,
                    {parent_expr} AS _parent,
                    {full_path_expr} AS _full_path,
                    ({del_prefix_expr} || {kind_expr} || {fname_expr} || {size_meta_expr} || {timestomp_suffix_expr}) AS _base_summary,
                    *
                FROM "{table_name}"
                WHERE "{filename_col}" IS NOT NULL AND TRIM(CAST("{filename_col}" AS VARCHAR)) != ''
            ),
            mft_unpivoted AS (
                {unpivot_sql}
            ),
            mft_grouped AS (
                SELECT
                    _src_row_id,
                    _fname,
                    _parent,
                    _full_path,
                    _base_summary,
                    attr_family,
                    ts_val,
                    (CASE WHEN MAX(m_flag) = 1 THEN 'M' ELSE '.' END) ||
                    (CASE WHEN MAX(a_flag) = 1 THEN 'A' ELSE '.' END) ||
                    (CASE WHEN MAX(c_flag) = 1 THEN 'C' ELSE '.' END) ||
                    (CASE WHEN MAX(b_flag) = 1 THEN 'B' ELSE '.' END) AS macb_str,
                    string_agg(DISTINCT role_label, '/' ORDER BY role_label) AS roles_str
                FROM mft_unpivoted
                GROUP BY _src_row_id, _fname, _parent, _full_path, _base_summary, attr_family, ts_val
            )
            SELECT
                nextval('seq_timeline_id'),
                ts_val,
                attr_family || ' ' || roles_str || ' [' || macb_str || ']',
                macb_str,
                'OPERATING SYSTEM',
                '$MFT',
                _fname,
                _parent,
                _base_summary || ' [' || attr_family || ' ' || macb_str || ']',
                '{table_name}',
                _src_row_id,
                _full_path
            FROM mft_grouped;
            """
            cursor.execute(timeline_sql)

        # Entity Connections for high-signal user/executable/script/archive/document files (avoids WinSxS noise explosion while keeping deleted/user items)
        ref_ts = cols.get("lastmodified0x10") or cols.get("created0x10")
        ts_expr = self._clean_ts_expr(f'"{ref_ts}"') if ref_ts else "NULL"
        ext_pred = (
            f"LOWER(COALESCE(CAST(\"{ext_col}\" AS VARCHAR), '')) IN ('.exe', '.dll', '.sys', '.ps1', '.bat', '.vbs', '.cmd', '.lnk', '.pf', '.zip', '.7z', '.rar', '.iso', '.docx', '.doc', '.pdf', '.xlsx', '.xls', '.pptx', '.txt', '.csv')"
            if ext_col
            else "1=0"
        )
        parent_pred = f"CAST(\"{parentpath_col}\" AS VARCHAR) ILIKE '%Users%'" if parentpath_col else "1=1"
        del_pred = (
            f"(\"{inuse_col}\" = FALSE OR LOWER(CAST(\"{inuse_col}\" AS VARCHAR)) IN ('false', '0'))"
            if inuse_col
            else "1=0"
        )
        ent_where = f"WHERE \"{filename_col}\" IS NOT NULL AND TRIM(CAST(\"{filename_col}\" AS VARCHAR)) != '' AND ({ext_pred} OR {parent_pred} OR {del_pred})"

        ent_type_expr = (
            f"CASE WHEN LOWER(COALESCE(CAST(\"{ext_col}\" AS VARCHAR), '')) IN ('.exe', '.dll', '.sys', '.ps1', '.bat', '.vbs', '.cmd') THEN 'EXECUTABLE' ELSE 'FILE_NAME' END"
            if ext_col
            else "'FILE_NAME'"
        )
        cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                {ent_type_expr},
                UPPER(TRIM(CAST("{filename_col}" AS VARCHAR))),
                'OPERATING SYSTEM',
                '$MFT',
                '{table_name}',
                {row_id_expr},
                ({del_prefix_expr} || 'MFT file record'),
                {ts_expr}
            FROM "{table_name}"
            {ent_where};
        """)

        if parentpath_col:
            cursor.execute(f"""
                INSERT INTO entity_connections (
                    connection_id, entity_type, entity_value, category, artifact_name,
                    source_table, source_row_id, context_label, timestamp_utc
                )
                SELECT
                    nextval('seq_connection_id'),
                    'FILE_PATH',
                    TRIM({full_path_expr}),
                    'OPERATING SYSTEM',
                    '$MFT',
                    '{table_name}',
                    {row_id_expr},
                    ({del_prefix_expr} || 'MFT full path'),
                    {ts_expr}
                FROM "{table_name}"
                {ent_where} AND "{parentpath_col}" IS NOT NULL;
            """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 4b. vfs_files (Fallback 8-Timestamp MACB File System Timeline when raw_mft is absent or non-NTFS)
    # -------------------------------------------------------------------------
    def _normalize_vfs_files(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "vfs_files"
        fname_col = cols.get("file_name") or cols.get("filename")
        if not fname_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        # Avoid duplicating NTFS MFT timeline when raw_mft already has rows; still include non-NTFS partitions!
        mft_populated = self._table_exists("raw_mft")
        fs_type_col = cols.get("fs_type")
        if mft_populated and not fs_type_col:
            return (0, 0)
        fs_filter = (
            f"AND UPPER(COALESCE(CAST(\"{fs_type_col}\" AS VARCHAR), '')) NOT LIKE '%NTFS%'"
            if (mft_populated and fs_type_col)
            else ""
        )

        row_id_col = cols.get("_row_id") or cols.get("mft_entry") or cols.get("inode")
        row_id_expr = f'COALESCE("{row_id_col}", rowid, 0)' if row_id_col else "COALESCE(rowid, 0)"
        parent_col = cols.get("parent_path")
        vfs_path_col = cols.get("vfs_path")
        size_col = cols.get("size_bytes")
        ext_col = cols.get("extension")
        isdir_col = cols.get("is_dir") or cols.get("is_directory")
        isdel_col = cols.get("is_deleted")
        isalloc_col = cols.get("is_allocated")

        parent_expr = f'COALESCE(CAST("{parent_col}" AS VARCHAR), \'\')' if parent_col else "''"
        fname_expr = f'COALESCE(CAST("{fname_col}" AS VARCHAR), \'\')'
        full_path_expr = (
            f'COALESCE(NULLIF(TRIM(CAST("{vfs_path_col}" AS VARCHAR)), \'\'), {parent_expr} || \'\\\' || {fname_expr})'
            if vfs_path_col
            else f"{parent_expr} || '\\' || {fname_expr}"
        )

        if isdel_col:
            del_cond = f'("{isdel_col}" = TRUE OR LOWER(CAST("{isdel_col}" AS VARCHAR)) IN (\'true\', \'1\'))'
        elif isalloc_col:
            del_cond = f'("{isalloc_col}" = FALSE OR LOWER(CAST("{isalloc_col}" AS VARCHAR)) IN (\'false\', \'0\'))'
        else:
            del_cond = "1=0"

        del_prefix_expr = f"CASE WHEN {del_cond} THEN '[DELETED] ' ELSE '' END"
        kind_expr = (
            f"CASE WHEN \"{isdir_col}\" = TRUE OR LOWER(CAST(\"{isdir_col}\" AS VARCHAR)) IN ('true', '1') THEN 'Directory ' ELSE 'File ' END"
            if isdir_col
            else "'File '"
        )
        size_meta_expr = (
            f"' (' || COALESCE(CAST(\"{size_col}\" AS VARCHAR), '0') || ' bytes)'"
            if size_col
            else "''"
        )

        def _pick_ts(a: str, b: str) -> Optional[str]:
            ca, cb = cols.get(a), cols.get(b)
            if ca and cb:
                return f'COALESCE(b."{ca}", b."{cb}")'
            if ca:
                return f'b."{ca}"'
            if cb:
                return f'b."{cb}"'
            return None

        si_c_raw = cols.get("si_created") or cols.get("si_created_utc")
        fn_c_raw = cols.get("fn_created") or cols.get("fn_created_utc")
        if si_c_raw and fn_c_raw:
            si_c_q = f'"{si_c_raw}"'
            fn_c_q = f'"{fn_c_raw}"'
            timestomp_expr = (
                f"CASE WHEN {self._valid_ts_sql(si_c_q)} AND {self._valid_ts_sql(fn_c_q)} "
                f"AND TRY_CAST({si_c_q} AS TIMESTAMP) < TRY_CAST({fn_c_q} AS TIMESTAMP) "
                f"THEN ' [TIMESTOMP: $SI < $FN]' ELSE '' END"
            )
        else:
            timestomp_expr = "''"

        si_mod_ref = _pick_ts("si_modified", "si_modified_utc")
        fn_mod_ref = _pick_ts("fn_modified", "fn_modified_utc")
        combined_mod_parts = [p for p in (si_mod_ref, fn_mod_ref) if p]
        combined_mod_ref = (
            ("COALESCE(" + ", ".join(combined_mod_parts) + ")")
            if len(combined_mod_parts) > 1
            else (combined_mod_parts[0] if combined_mod_parts else None)
        )

        vfs_specs = [
            ("$SI", si_mod_ref, 1, 0, 0, 0, "Modified", False),
            ("$SI", _pick_ts("si_accessed", "si_accessed_utc"), 0, 1, 0, 0, "Accessed", False),
            ("$SI", _pick_ts("si_created", "si_created_utc"), 0, 0, 0, 1, "Created", True),
            ("$SI", _pick_ts("si_changed", "si_changed_utc"), 0, 0, 1, 0, "Entry Modified", True),
            ("$FN", fn_mod_ref, 1, 0, 0, 0, "Modified", False),
            ("$FN", _pick_ts("fn_accessed", "fn_accessed_utc"), 0, 1, 0, 0, "Accessed", False),
            ("$FN", _pick_ts("fn_created", "fn_created_utc"), 0, 0, 0, 1, "Created", True),
            ("$FN", _pick_ts("fn_changed", "fn_changed_utc"), 0, 0, 1, 0, "Entry Modified", True),
        ]
        branches = []
        for family, ts_ref, m_f, a_f, c_f, b_f, role_lbl, guard_ctime in vfs_specs:
            if not ts_ref:
                continue
            ts_val_expr = (
                self._non_wallclock_ctime_sql(ts_ref, combined_mod_ref)
                if guard_ctime
                else self._clean_ts_expr(ts_ref)
            )
            branches.append(f"""
                SELECT
                    b._src_row_id, b._fname, b._parent, b._full_path, b._base_summary,
                    '{family}' AS attr_family,
                    {ts_val_expr} AS ts_val,
                    {m_f} AS m_flag, {a_f} AS a_flag, {c_f} AS c_flag, {b_f} AS b_flag,
                    '{role_lbl}' AS role_label
                FROM vfs_base b
                WHERE ({ts_val_expr}) IS NOT NULL
            """)

        if branches:
            cursor.execute(f"""
                INSERT INTO master_timeline (
                    timeline_id, timestamp_utc, timestamp_type, macb, category, artifact_name,
                    primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
                )
                WITH vfs_base AS (
                    SELECT
                        {row_id_expr} AS _src_row_id,
                        {fname_expr} AS _fname,
                        {parent_expr} AS _parent,
                        {full_path_expr} AS _full_path,
                        ({del_prefix_expr} || {kind_expr} || {fname_expr} || {size_meta_expr} || {timestomp_expr}) AS _base_summary,
                        *
                    FROM "{table_name}"
                    WHERE "{fname_col}" IS NOT NULL AND TRIM(CAST("{fname_col}" AS VARCHAR)) != '' {fs_filter}
                ),
                vfs_unpivoted AS (
                    {" UNION ALL ".join(branches)}
                ),
                vfs_grouped AS (
                    SELECT
                        _src_row_id, _fname, _parent, _full_path, _base_summary, attr_family, ts_val,
                        (CASE WHEN MAX(m_flag)=1 THEN 'M' ELSE '.' END) ||
                        (CASE WHEN MAX(a_flag)=1 THEN 'A' ELSE '.' END) ||
                        (CASE WHEN MAX(c_flag)=1 THEN 'C' ELSE '.' END) ||
                        (CASE WHEN MAX(b_flag)=1 THEN 'B' ELSE '.' END) AS macb_str,
                        string_agg(DISTINCT role_label, '/' ORDER BY role_label) AS roles_str
                    FROM vfs_unpivoted
                    GROUP BY _src_row_id, _fname, _parent, _full_path, _base_summary, attr_family, ts_val
                )
                SELECT
                    nextval('seq_timeline_id'),
                    ts_val,
                    attr_family || ' ' || roles_str || ' [' || macb_str || ']',
                    macb_str,
                    'OPERATING SYSTEM',
                    'File System (VFS)',
                    _fname,
                    _parent,
                    _base_summary || ' [' || attr_family || ' ' || macb_str || ']',
                    '{table_name}',
                    _src_row_id,
                    _full_path
                FROM vfs_grouped;
            """)

        ref_col = cols.get("si_modified") or cols.get("si_modified_utc") or cols.get("si_created") or cols.get("si_created_utc")
        ref_ts_expr = self._clean_ts_expr(f'"{ref_col}"') if ref_col else "NULL"
        ent_type_expr = (
            f"CASE WHEN LOWER(COALESCE(CAST(\"{ext_col}\" AS VARCHAR), '')) IN ('.exe', '.dll', '.sys', '.ps1', '.bat', '.vbs', '.cmd') "
            f"OR LOWER(CAST(\"{fname_col}\" AS VARCHAR)) SIMILAR TO '.*\\.(exe|dll|sys|ps1|bat|vbs|cmd)$' THEN 'EXECUTABLE' ELSE 'FILE_NAME' END"
            if ext_col
            else f"CASE WHEN LOWER(CAST(\"{fname_col}\" AS VARCHAR)) SIMILAR TO '.*\\.(exe|dll|sys|ps1|bat|vbs|cmd)$' THEN 'EXECUTABLE' ELSE 'FILE_NAME' END"
        )
        cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                {ent_type_expr},
                UPPER(TRIM(CAST("{fname_col}" AS VARCHAR))),
                'OPERATING SYSTEM',
                'File System (VFS)',
                '{table_name}',
                {row_id_expr},
                ({del_prefix_expr} || 'VFS file entry'),
                {ref_ts_expr}
            FROM "{table_name}"
            WHERE "{fname_col}" IS NOT NULL AND TRIM(CAST("{fname_col}" AS VARCHAR)) != '' {fs_filter};
        """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 5. raw_amcache_files (Amcache UnassociatedFileEntries)
    # -------------------------------------------------------------------------
    def _normalize_raw_amcache_files(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_amcache_files"
        ts_col = cols.get("filekeylastwritetimestamp")
        name_col = cols.get("name")
        path_col = cols.get("fullpath")
        sha1_col = cols.get("sha1")
        row_id_col = cols.get("_row_id", "_row_id")

        if not ts_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)

        primary_expr = (
            f"COALESCE(NULLIF(TRIM(CAST(\"{name_col}\" AS VARCHAR)), ''), CAST(\"{path_col}\" AS VARCHAR))"
            if (name_col and path_col)
            else f"COALESCE(CAST(\"{name_col or path_col}\" AS VARCHAR), 'Unknown Amcache Entry')"
        )
        sec_expr = f"CAST(\"{sha1_col}\" AS VARCHAR)" if sha1_col else "NULL"
        summary_expr = (
            f"'Amcache entry: ' || COALESCE(CAST(\"{name_col}\" AS VARCHAR), '') || ' | SHA1: ' || COALESCE(CAST(\"{sha1_col}\" AS VARCHAR), 'None')"
            if (name_col and sha1_col)
            else f"'Amcache entry: ' || {primary_expr}"
        )
        src_file_expr = f"CAST(\"{path_col}\" AS VARCHAR)" if path_col else "NULL"

        # 1. Timeline SQL
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{ts_col}" AS TIMESTAMP),
            'Amcache Key Last Write',
            'OPERATING SYSTEM',
            'Amcache',
            {primary_expr},
            {sec_expr},
            {summary_expr},
            '{table_name}',
            \"{row_id_col}\",
            {src_file_expr}
        FROM "{table_name}"
        WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity: Name -> EXECUTABLE
        if name_col:
            name_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EXECUTABLE',
                UPPER(TRIM(CAST(\"{name_col}\" AS VARCHAR))),
                'OPERATING SYSTEM',
                'Amcache',
                '{table_name}',
                \"{row_id_col}\",
                'Amcache unassociated file entry',
                TRY_CAST("{ts_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE \"{name_col}\" IS NOT NULL
              AND TRIM(CAST(\"{name_col}\" AS VARCHAR)) != '';
            """
            self.conn.execute(name_sql)

        # 3. Entity: FullPath -> FILE_PATH
        if path_col:
            path_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                TRIM(CAST(\"{path_col}\" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Amcache',
                '{table_name}',
                \"{row_id_col}\",
                'Amcache file full path',
                TRY_CAST("{ts_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE \"{path_col}\" IS NOT NULL
              AND TRIM(CAST(\"{path_col}\" AS VARCHAR)) != '';
            """
            self.conn.execute(path_sql)

        # 4. Entity: SHA1 -> SHA1
        if sha1_col:
            sha1_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'SHA1',
                LOWER(TRIM(CAST(\"{sha1_col}\" AS VARCHAR))),
                'OPERATING SYSTEM',
                'Amcache',
                '{table_name}',
                \"{row_id_col}\",
                'Amcache SHA1 hash',
                TRY_CAST("{ts_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE \"{sha1_col}\" IS NOT NULL
              AND TRIM(CAST(\"{sha1_col}\" AS VARCHAR)) != ''
              AND TRIM(CAST(\"{sha1_col}\" AS VARCHAR)) != '0000000000000000000000000000000000000000';
            """
            self.conn.execute(sha1_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 6. raw_shimcache (AppCompatCache)
    # -------------------------------------------------------------------------
    def _normalize_raw_shimcache(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_shimcache"
        ts_col = cols.get("lastmodifiedtimeutc")
        path_col = cols.get("path")
        row_id_col = cols.get("_row_id", "_row_id")

        if not ts_col or not path_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)

        # 1. Timeline SQL
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{ts_col}" AS TIMESTAMP),
            'ShimCache Last Modified',
            'OPERATING SYSTEM',
            'AppCompatCache',
            COALESCE(regexp_extract(CAST(CAST(\"{path_col}\" AS VARCHAR) AS VARCHAR), '([^\\\\/]+)$', 1), CAST(\"{path_col}\" AS VARCHAR)),
            \"{path_col}\",
            'ShimCache recorded entry for ' || COALESCE(regexp_extract(CAST(CAST(\"{path_col}\" AS VARCHAR) AS VARCHAR), '([^\\\\/]+)$', 1), CAST(\"{path_col}\" AS VARCHAR)),
            '{table_name}',
            \"{row_id_col}\",
            \"{path_col}\"
        FROM "{table_name}"
        WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity: Path -> FILE_PATH
        path_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_PATH',
            TRIM(CAST(\"{path_col}\" AS VARCHAR)),
            'OPERATING SYSTEM',
            'AppCompatCache',
            '{table_name}',
            \"{row_id_col}\",
            'ShimCache application path',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE \"{path_col}\" IS NOT NULL
          AND TRIM(CAST(\"{path_col}\" AS VARCHAR)) != '';
        """
        self.conn.execute(path_sql)

        # 3. Entity: regexp_extract(Path) -> EXECUTABLE
        exec_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER(TRIM(regexp_extract(CAST(\"{path_col}\" AS VARCHAR), '([^\\\\/]+)$', 1))),
            'OPERATING SYSTEM',
            'AppCompatCache',
            '{table_name}',
            \"{row_id_col}\",
            'ShimCache executable',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE \"{path_col}\" IS NOT NULL
          AND regexp_extract(CAST(\"{path_col}\" AS VARCHAR), '([^\\\\/]+)$', 1) != '';
        """
        self.conn.execute(exec_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 7. raw_recmd (Registry Batch Output)
    # -------------------------------------------------------------------------
    def _normalize_raw_recmd(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_recmd"
        ts_col = cols.get("lastwritetimestamp")
        key_col = cols.get("keypath")
        val_name_col = cols.get("valuename")
        val_data_col = cols.get("valuedata")
        cat_col = cols.get("category")
        desc_col = cols.get("description")
        hive_col = cols.get("hivepath")
        row_id_col = cols.get("_row_id", "_row_id")

        if not ts_col or not key_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)

        summary_expr = (
            f"'Key: ' || COALESCE(CAST(\"{key_col}\" AS VARCHAR), '') || ' | Value: ' || COALESCE(CAST(\"{val_name_col}\" AS VARCHAR), '') || ' = ' || COALESCE(CAST(\"{val_data_col}\" AS VARCHAR), '')"
            if (val_name_col and val_data_col)
            else f"'Key: ' || COALESCE(CAST(\"{key_col}\" AS VARCHAR), '')"
        )
        ts_type_expr = (
            f"'Registry Key Modified: ' || COALESCE(CAST(\"{cat_col}\" AS VARCHAR), CAST(\"{desc_col}\" AS VARCHAR), '')"
            if (cat_col and desc_col)
            else "'Registry Key Modified'"
        )
        hive_expr = f"COALESCE(CAST(\"{hive_col}\" AS VARCHAR), 'Registry Hive')" if hive_col else "'Registry Hive'"

        # 1. Timeline SQL
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{ts_col}" AS TIMESTAMP),
            {ts_type_expr},
            'OPERATING SYSTEM',
            'Registry (RECmd)',
            \"{key_col}\",
            \"{val_name_col or key_col}\",
            {summary_expr},
            '{table_name}',
            \"{row_id_col}\",
            {hive_expr}
        FROM "{table_name}"
        WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity: KeyPath -> REGISTRY_KEY
        key_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'REGISTRY_KEY',
            UPPER(TRIM(CAST(\"{key_col}\" AS VARCHAR))),
            'OPERATING SYSTEM',
            'Registry (RECmd)',
            '{table_name}',
            \"{row_id_col}\",
            'Registry key modified',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE \"{key_col}\" IS NOT NULL
          AND TRIM(CAST(\"{key_col}\" AS VARCHAR)) != '';
        """
        self.conn.execute(key_sql)

        # 3. Entity: ValueData -> FILE_PATH (when containing drive letter or .exe)
        if val_data_col:
            val_path_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                TRIM(CAST(\"{val_data_col}\" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Registry (RECmd)',
                '{table_name}',
                \"{row_id_col}\",
                'Registry value data file path',
                TRY_CAST("{ts_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE \"{val_data_col}\" IS NOT NULL
              AND (CAST(\"{val_data_col}\" AS VARCHAR) LIKE '%:\\%' OR LOWER(CAST(\"{val_data_col}\" AS VARCHAR)) LIKE '%.exe%');
            """
            self.conn.execute(val_path_sql)

        # 4. Create Virtual Category Views & Register them
        self._create_recmd_virtual_views(cols)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)

    def _create_recmd_virtual_views(self, cols: Dict[str, str]) -> None:
        """
        Refresh RECmd / Registry unioned views via schema.sync_artifact_registry_counts
        so parsed_autoruns / parsed_userassist / parsed_bam_dam rows are never clobbered
        and non-canonical category strings are never written to artifact_registry.
        """
        try:
            from backend.db.schema import MASTER_ARTIFACT_CATALOG
            cursor = self.conn.cursor()
            for entry in MASTER_ARTIFACT_CATALOG:
                if entry["table_name"] in ("view_usb_devices", "view_autoruns", "view_userassist", "view_bam_dam"):
                    try:
                        cursor.execute(entry["ddl"])
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Normalizer] Warning refreshing recmd views: {e}")


    # -------------------------------------------------------------------------
    # 8. raw_srum_app & raw_srum_net (SRUM)
    # -------------------------------------------------------------------------
    def _normalize_raw_srum_generic(
        self,
        table_name: str,
        artifact_name: str,
        cols: Dict[str, str],
        is_network: bool = False,
    ) -> Tuple[int, int]:
        ts_col = cols.get("timestamp")
        exe_col = cols.get("exeinfo")
        user_col = cols.get("username") or cols.get("userid") or cols.get("sid")
        row_id_col = cols.get("_row_id", "_row_id")

        if not ts_col or not exe_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)

        if is_network:
            sent_col = cols.get("bytessent")
            rcvd_col = cols.get("bytesreceived") or cols.get("bytesrecvd")
            summary_expr = (
                f"'SRUM Net: ' || COALESCE(CAST(\"{exe_col}\" AS VARCHAR), '') || ' | Sent: ' || COALESCE(CAST(\"{sent_col}\" AS VARCHAR), '0') || ' | Rcvd: ' || COALESCE(CAST(\"{rcvd_col}\" AS VARCHAR), '0')"
                if (sent_col and rcvd_col)
                else f"'SRUM Net: ' || COALESCE(CAST(\"{exe_col}\" AS VARCHAR), '')"
            )
            ts_type = "SRUM Network Recorded"
        else:
            fg_col = cols.get("foregroundcycletime")
            summary_expr = (
                f"'SRUM App: ' || COALESCE(CAST(\"{exe_col}\" AS VARCHAR), '') || CASE WHEN \"{fg_col}\" IS NOT NULL THEN ' | FG Cycles: ' || CAST(\"{fg_col}\" AS VARCHAR) ELSE '' END"
                if fg_col
                else f"'SRUM App: ' || COALESCE(CAST(\"{exe_col}\" AS VARCHAR), '')"
            )
            ts_type = "SRUM Resource Recorded"

        user_expr = f"COALESCE(CAST(\"{user_col}\" AS VARCHAR), '')" if user_col else "''"

        # 1. Timeline SQL
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{ts_col}" AS TIMESTAMP),
            '{ts_type}',
            'OPERATING SYSTEM',
            '{artifact_name}',
            COALESCE(regexp_extract(CAST(\"{exe_col}\" AS VARCHAR), '([^\\\\/]+)$', 1), CAST(\"{exe_col}\" AS VARCHAR), 'Application'),
            {user_expr},
            {summary_expr},
            '{table_name}',
            \"{row_id_col}\",
            'SRUDB.dat'
        FROM "{table_name}"
        WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity: ExeInfo -> FILE_PATH
        path_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_PATH',
            TRIM(CAST(\"{exe_col}\" AS VARCHAR)),
            'OPERATING SYSTEM',
            '{artifact_name}',
            '{table_name}',
            \"{row_id_col}\",
            'SRUM application path',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE \"{exe_col}\" IS NOT NULL
          AND TRIM(CAST(\"{exe_col}\" AS VARCHAR)) != '';
        """
        self.conn.execute(path_sql)

        # 3. Entity: regexp_extract(ExeInfo) -> EXECUTABLE
        exec_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER(TRIM(regexp_extract(CAST(\"{exe_col}\" AS VARCHAR), '([^\\\\/]+)$', 1))),
            'OPERATING SYSTEM',
            '{artifact_name}',
            '{table_name}',
            \"{row_id_col}\",
            'SRUM executable',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE \"{exe_col}\" IS NOT NULL
          AND regexp_extract(CAST(\"{exe_col}\" AS VARCHAR), '([^\\\\/]+)$', 1) != '';
        """
        self.conn.execute(exec_sql)

        # 4. Entity: UserName/UserId -> USER_ACCOUNT
        if user_col:
            user_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'USER_ACCOUNT',
                TRIM(CAST(\"{user_col}\" AS VARCHAR)),
                'OPERATING SYSTEM',
                '{artifact_name}',
                '{table_name}',
                \"{row_id_col}\",
                'SRUM user account',
                TRY_CAST("{ts_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE \"{user_col}\" IS NOT NULL
              AND TRIM(CAST(\"{user_col}\" AS VARCHAR)) != ''
              AND TRIM(CAST(\"{user_col}\" AS VARCHAR)) NOT IN ('-', 'N/A');
            """
            self.conn.execute(user_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # Additional Handlers: JumpLists Custom, ShellBags, USN Jrnl, WinTimeline
    # -------------------------------------------------------------------------
    def _normalize_raw_shellbags(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_shellbags"
        # Support BOTH SBECmd CSV columns (AbsolutePath, Value, LastWriteTime, ModifiedOn, CreatedOn, AccessedOn, FirstInteracted, LastInteracted)
        # AND schema.py columns (BagPath, ValueName, FolderType, Created, Modified, Accessed)
        path_candidates = [
            cols[k] for k in ("absolutepath", "bagpath", "value", "valuename") if k in cols
        ]
        if not path_candidates:
            return (0, 0)

        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        row_id_col = cols.get("_row_id")
        row_id_expr = f'COALESCE("{row_id_col}", rowid, 0)' if row_id_col else "COALESCE(rowid, 0)"
        path_expr = "COALESCE(" + ", ".join([f'NULLIF(TRIM(CAST("{c}" AS VARCHAR)), \'\')' for c in path_candidates]) + ")"
        ftype_col = cols.get("foldertype") or cols.get("shelltype")
        sec_expr = f'CAST("{ftype_col}" AS VARCHAR)' if ftype_col else "NULL"

        ts_candidates = [
            ("modified", 1, 0, 0, 0, "Modified"),
            ("modifiedon", 1, 0, 0, 0, "Modified"),
            ("lastwritetime", 0, 0, 1, 0, "Registry LastWrite"),
            ("accessed", 0, 1, 0, 0, "Accessed"),
            ("accessedon", 0, 1, 0, 0, "Accessed"),
            ("lastinteracted", 0, 1, 0, 0, "Last Interacted"),
            ("created", 0, 0, 0, 1, "Created"),
            ("createdon", 0, 0, 0, 1, "Created"),
            ("firstinteracted", 0, 0, 0, 1, "First Interacted"),
        ]
        branches = []
        for col_key, m_f, a_f, c_f, b_f, lbl in ts_candidates:
            actual = cols.get(col_key)
            if not actual:
                continue
            branches.append(f"""
                SELECT
                    s._src_row_id, s._bag_path, s._sec,
                    TRY_CAST(s."{actual}" AS TIMESTAMP) AS ts_val,
                    {m_f} AS m_flag, {a_f} AS a_flag, {c_f} AS c_flag, {b_f} AS b_flag,
                    '{lbl}' AS role_label
                FROM sb_base s
                WHERE {self._valid_ts_sql(f's."{actual}"')}
            """)

        if branches:
            cursor.execute(f"""
                INSERT INTO master_timeline (
                    timeline_id, timestamp_utc, timestamp_type, macb, category, artifact_name,
                    primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
                )
                WITH sb_base AS (
                    SELECT
                        {row_id_expr} AS _src_row_id,
                        {path_expr} AS _bag_path,
                        {sec_expr} AS _sec,
                        *
                    FROM "{table_name}"
                    WHERE {path_expr} IS NOT NULL
                ),
                sb_unpivoted AS (
                    {" UNION ALL ".join(branches)}
                ),
                sb_grouped AS (
                    SELECT
                        _src_row_id, _bag_path, _sec, ts_val,
                        (CASE WHEN MAX(m_flag)=1 THEN 'M' ELSE '.' END) ||
                        (CASE WHEN MAX(a_flag)=1 THEN 'A' ELSE '.' END) ||
                        (CASE WHEN MAX(c_flag)=1 THEN 'C' ELSE '.' END) ||
                        (CASE WHEN MAX(b_flag)=1 THEN 'B' ELSE '.' END) AS macb_str,
                        string_agg(DISTINCT role_label, '/' ORDER BY role_label) AS roles_str
                    FROM sb_unpivoted
                    GROUP BY _src_row_id, _bag_path, _sec, ts_val
                )
                SELECT
                    nextval('seq_timeline_id'),
                    ts_val,
                    'ShellBag ' || roles_str || ' [' || macb_str || ']',
                    macb_str,
                    'OPERATING SYSTEM',
                    'ShellBags',
                    _bag_path,
                    _sec,
                    'ShellBag path: ' || _bag_path || ' [' || macb_str || ']',
                    '{table_name}',
                    _src_row_id,
                    'UsrClass.dat'
                FROM sb_grouped;
            """)

        ref_ts_cols = [cols[k] for k in ("lastwritetime", "modifiedon", "modified", "accessedon", "accessed", "createdon", "created") if k in cols]
        ref_ts_expr = (
            "COALESCE(" + ", ".join([self._clean_ts_expr(f'"{c}"') for c in ref_ts_cols]) + ")"
            if ref_ts_cols
            else "NULL"
        )
        cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                {path_expr},
                'OPERATING SYSTEM',
                'ShellBags',
                '{table_name}',
                {row_id_expr},
                'Explorer browsed directory path',
                {ref_ts_expr}
            FROM "{table_name}"
            WHERE {path_expr} IS NOT NULL;
        """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # 14b. raw_usnjrnl ($J Change Journal)
    # -------------------------------------------------------------------------
    def _normalize_raw_usnjrnl(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_usnjrnl"
        self._clear_table_normalizations(table_name)

        filename_col = cols.get("name") or cols.get("filename", "Name")
        ts_col = cols.get("updatetimestamp", "UpdateTimestamp")
        reasons_col = cols.get("updatereasons", "UpdateReasons")
        usn_col = cols.get("updatesequencenumber", "UpdateSequenceNumber")
        row_id_col = cols.get("_row_id", "_row_id")

        if not filename_col or not ts_col:
            return (0, 0)

        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{ts_col}" AS TIMESTAMP),
            'USN Journal Record',
            'OPERATING SYSTEM',
            'USN Change Journal ($J)',
            "{filename_col}",
            COALESCE("{reasons_col}", ''),
            'USN Reason: ' || COALESCE("{reasons_col}", '') || ' | USN: ' || COALESCE(CAST("{usn_col}" AS VARCHAR), ''),
            '{table_name}',
            "{row_id_col}",
            '{table_name}'
        FROM "{table_name}"
        WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        entity_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            CASE
                WHEN LOWER(CAST("{filename_col}" AS VARCHAR)) LIKE '%.exe' THEN 'EXECUTABLE'
                ELSE 'FILE_NAME'
            END,
            UPPER(TRIM(CAST("{filename_col}" AS VARCHAR))),
            'OPERATING SYSTEM',
            'USN Change Journal ($J)',
            '{table_name}',
            "{row_id_col}",
            'USN Record (' || COALESCE("{reasons_col}", '') || ')',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{filename_col}" IS NOT NULL AND TRIM(CAST("{filename_col}" AS VARCHAR)) != '';
        """
        self.conn.execute(entity_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)

    # 15. parsed_browser_history (Chromium & Firefox — 1x Deduplicated)
    # -------------------------------------------------------------------------
    def _browser_dedup_clause(self, alias: str, table_name: str, per_browser_tables: Tuple[str, ...], match_expr_fn) -> str:
        """
        When normalizing a legacy combined table (e.g. parsed_browser_history), skip rows
        already present in any populated per-browser table so dual-populated DBs emit 1x events
        while single-table DBs still emit 1x events.
        """
        if table_name not in ("parsed_browser_history", "parsed_browser_downloads", "parsed_browser_logins"):
            return ""
        checks = []
        for pb_tbl in per_browser_tables:
            if self._table_exists(pb_tbl):
                pb_cols = self._get_columns(pb_tbl)
                pred = match_expr_fn(alias, pb_tbl, pb_cols)
                if pred:
                    checks.append(f"NOT EXISTS (SELECT 1 FROM \"{pb_tbl}\" _pb WHERE {pred})")
        return (" AND " + " AND ".join(checks)) if checks else ""

    def _normalize_parsed_browser_history(self, cols: Dict[str, str], table_name: str = "parsed_browser_history") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        ts_expr = self._coalesce_ts_sql(
            cols,
            "visit_time",
            "visit_time_utc",
            "last_visit_date",
            "last_visit_time",
            "timestamp_utc",
            prefix="src.",
        )
        url_col = cols.get("url")
        if not ts_expr or not url_col:
            return (0, 0)

        title_col = cols.get("title")
        browser_col = cols.get("browser")
        visits_col = cols.get("visit_count")
        row_id_col = cols.get("_row_id")
        src_col = cols.get("source_file") or cols.get("file_path")

        row_id_expr = f'COALESCE(src."{row_id_col}", src.rowid, 0)' if row_id_col else "COALESCE(src.rowid, 0)"
        default_browser = (
            "Chrome" if "chrome" in table_name else
            "Edge" if "edge" in table_name else
            "Brave" if "brave" in table_name else
            "Firefox" if "firefox" in table_name else "Browser"
        )
        browser_expr = f'COALESCE(CAST(src."{browser_col}" AS VARCHAR), \'{default_browser}\')' if browser_col else f"'{default_browser}'"
        title_expr = f'COALESCE(NULLIF(TRIM(CAST(src."{title_col}" AS VARCHAR)), \'\'), \'(No Title)\')' if title_col else "'(No Title)'"
        visits_expr = f'CAST(COALESCE(src."{visits_col}", 1) AS VARCHAR)' if visits_col else "'1'"
        src_expr = self._clean_path_sql(f'src."{src_col}"') if src_col else f"'{table_name}'"

        def _pb_hist_match(a: str, pb: str, pbc: Dict[str, str]) -> Optional[str]:
            if "url" not in pbc:
                return None
            pb_ts = self._coalesce_ts_sql(
                pbc,
                "visit_time",
                "visit_time_utc",
                "last_visit_date",
                "last_visit_time",
                "timestamp_utc",
                prefix="_pb.",
            )
            if not pb_ts:
                return None
            pb_url_col = pbc["url"]
            return (
                f'COALESCE(CAST(_pb."{pb_url_col}" AS VARCHAR), \'\') = COALESCE(CAST({a}."{url_col}" AS VARCHAR), \'\') '
                f'AND ({pb_ts}) IS NOT DISTINCT FROM ({ts_expr})'
            )

        dedup_sql = self._browser_dedup_clause(
            "src",
            table_name,
            ("parsed_chrome_history", "parsed_edge_history", "parsed_brave_history", "parsed_firefox_history"),
            _pb_hist_match,
        )

        cursor.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name,
            primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            {ts_expr},
            'Web Page Visit',
            'WEB RELATED',
            'Browser History (' || {browser_expr} || ')',
            CAST(src."{url_col}" AS VARCHAR),
            lower(regexp_extract(CAST(src."{url_col}" AS VARCHAR), '^(?:https?://)?([^/:]+)', 1)),
            'Title: ' || {title_expr} || ' | URL: ' || CAST(src."{url_col}" AS VARCHAR) || ' | Visits: ' || {visits_expr} || ' | Browser: ' || {browser_expr},
            '{table_name}',
            {row_id_expr},
            {src_expr}
        FROM "{table_name}" src
        WHERE ({ts_expr}) IS NOT NULL{dedup_sql};
        """)

        cursor.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name,
            source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'DOMAIN',
            lower(trim(regexp_extract(CAST(src."{url_col}" AS VARCHAR), '^(?:https?://)?([^/:]+)', 1))),
            'WEB RELATED',
            'Browser History (' || {browser_expr} || ')',
            '{table_name}',
            {row_id_expr},
            'Visited domain via ' || {browser_expr},
            {ts_expr}
        FROM "{table_name}" src
        WHERE src."{url_col}" IS NOT NULL
          AND regexp_extract(CAST(src."{url_col}" AS VARCHAR), '^(?:https?://)?([^/:]+)', 1) != ''{dedup_sql};
        """)

        cursor.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name,
            source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'URL',
            CAST(src."{url_col}" AS VARCHAR),
            'WEB RELATED',
            'Browser History (' || {browser_expr} || ')',
            '{table_name}',
            {row_id_expr},
            'Visited URL: ' || {title_expr},
            {ts_expr}
        FROM "{table_name}" src
        WHERE src."{url_col}" IS NOT NULL AND length(trim(CAST(src."{url_col}" AS VARCHAR))) > 0{dedup_sql};
        """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 16. parsed_browser_downloads (Chromium & Firefox — 1x Deduplicated)
    # -------------------------------------------------------------------------
    def _normalize_parsed_browser_downloads(self, cols: Dict[str, str], table_name: str = "parsed_browser_downloads") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        ts_sql = self._coalesce_ts_sql(
            cols,
            "start_time",
            "start_time_utc",
            "end_time",
            "end_time_utc",
            prefix="src.",
        )
        target_col = cols.get("target_path")
        tab_url_col = cols.get("tab_url") or cols.get("url") or cols.get("site_url")
        browser_col = cols.get("browser")
        bytes_col = cols.get("total_bytes") or cols.get("received_bytes")
        row_id_col = cols.get("_row_id")
        src_col = cols.get("source_file") or cols.get("file_path")

        if not ts_sql and not target_col:
            return (0, 0)

        row_id_expr = f'COALESCE(src."{row_id_col}", src.rowid, 0)' if row_id_col else "COALESCE(src.rowid, 0)"
        default_browser = (
            "Chrome" if "chrome" in table_name else
            "Edge" if "edge" in table_name else
            "Brave" if "brave" in table_name else
            "Firefox" if "firefox" in table_name else "Browser"
        )
        browser_expr = f'COALESCE(CAST(src."{browser_col}" AS VARCHAR), \'{default_browser}\')' if browser_col else f"'{default_browser}'"
        ts_expr = ts_sql if ts_sql else "NULL"
        target_expr = f'CAST(src."{target_col}" AS VARCHAR)' if target_col else "''"
        tab_expr = f'CAST(src."{tab_url_col}" AS VARCHAR)' if tab_url_col else "NULL"
        bytes_expr = f'CAST(COALESCE(src."{bytes_col}", 0) AS VARCHAR)' if bytes_col else "'0'"
        src_expr = self._clean_path_sql(f'src."{src_col}"') if src_col else f"'{table_name}'"

        dedup_sql = self._browser_dedup_clause(
            "src",
            table_name,
            ("parsed_chrome_downloads", "parsed_edge_downloads", "parsed_brave_downloads", "parsed_firefox_downloads"),
            lambda a, pb, pbc: (
                f'COALESCE(CAST(_pb."{pbc["target_path"]}" AS VARCHAR), \'\') = COALESCE({target_expr}, \'\')'
                if ("target_path" in pbc and target_col)
                else None
            ),
        )

        if ts_sql:
            cursor.execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, category, artifact_name,
                primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {ts_expr},
                'File Download Started',
                'WEB RELATED',
                'Browser Downloads (' || {browser_expr} || ')',
                COALESCE(NULLIF(TRIM({target_expr}), ''), {tab_expr}),
                {tab_expr},
                'Downloaded: ' || COALESCE(regexp_extract({target_expr}, '([^\\\\/]+)$', 1), {target_expr}) || ' (' || {bytes_expr} || ' bytes) via ' || {browser_expr},
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}" src
            WHERE ({ts_expr}) IS NOT NULL{dedup_sql};
            """)

        if target_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                {target_expr},
                'WEB RELATED',
                'Browser Downloads (' || {browser_expr} || ')',
                '{table_name}',
                {row_id_expr},
                'Downloaded file path via ' || {browser_expr},
                {ts_expr}
            FROM "{table_name}" src
            WHERE src."{target_col}" IS NOT NULL AND length(trim({target_expr})) > 0{dedup_sql};
            """)

            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EXECUTABLE',
                UPPER(TRIM(regexp_extract({target_expr}, '([^\\\\/]+)$', 1))),
                'WEB RELATED',
                'Browser Downloads (' || {browser_expr} || ')',
                '{table_name}',
                {row_id_expr},
                'Executable downloaded via ' || {browser_expr},
                {ts_expr}
            FROM "{table_name}" src
            WHERE src."{target_col}" IS NOT NULL
              AND (
                  {target_expr} ILIKE '%.exe' OR {target_expr} ILIKE '%.dll' OR
                  {target_expr} ILIKE '%.ps1' OR {target_expr} ILIKE '%.bat' OR
                  {target_expr} ILIKE '%.vbs' OR {target_expr} ILIKE '%.js' OR
                  {target_expr} ILIKE '%.zip' OR {target_expr} ILIKE '%.7z' OR
                  {target_expr} ILIKE '%.iso' OR {target_expr} ILIKE '%.msi'
              )
              AND regexp_extract({target_expr}, '([^\\\\/]+)$', 1) != ''{dedup_sql};
            """)

        if tab_url_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'DOMAIN',
                lower(trim(regexp_extract({tab_expr}, '^(?:https?://)?([^/:]+)', 1))),
                'WEB RELATED',
                'Browser Downloads (' || {browser_expr} || ')',
                '{table_name}',
                {row_id_expr},
                'Download source domain via ' || {browser_expr},
                {ts_expr}
            FROM "{table_name}" src
            WHERE src."{tab_url_col}" IS NOT NULL
              AND regexp_extract({tab_expr}, '^(?:https?://)?([^/:]+)', 1) != ''{dedup_sql};
            """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 17. parsed_browser_logins (Chromium & Firefox — 1x Deduplicated)
    # -------------------------------------------------------------------------
    def _normalize_parsed_browser_logins(self, cols: Dict[str, str], table_name: str = "parsed_browser_logins") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        used_ts_sql = self._coalesce_ts_sql(
            cols, "date_last_used", "date_last_used_utc", "time_last_used", prefix="src."
        )
        created_ts_sql = self._coalesce_ts_sql(
            cols, "date_created", "date_created_utc", "time_created", prefix="src."
        )
        user_col = cols.get("username_value") or cols.get("username")
        orig_col = cols.get("origin_url") or cols.get("hostname")
        browser_col = cols.get("browser")
        times_col = cols.get("times_used")
        row_id_col = cols.get("_row_id")
        src_col = cols.get("source_file") or cols.get("file_path")

        if not user_col and not orig_col:
            return (0, 0)

        row_id_expr = f'COALESCE(src."{row_id_col}", src.rowid, 0)' if row_id_col else "COALESCE(src.rowid, 0)"
        default_browser = (
            "Chrome" if "chrome" in table_name else
            "Edge" if "edge" in table_name else
            "Brave" if "brave" in table_name else
            "Firefox" if "firefox" in table_name else "Browser"
        )
        browser_expr = f'COALESCE(CAST(src."{browser_col}" AS VARCHAR), \'{default_browser}\')' if browser_col else f"'{default_browser}'"
        ts_parts = [p for p in (used_ts_sql, created_ts_sql) if p]
        ts_expr = f"COALESCE({', '.join(ts_parts)})" if ts_parts else "NULL"
        user_expr = f'CAST(src."{user_col}" AS VARCHAR)' if user_col else "''"
        orig_expr = f'CAST(src."{orig_col}" AS VARCHAR)' if orig_col else "''"
        times_expr = f'CAST(COALESCE(src."{times_col}", 0) AS VARCHAR)' if times_col else "'0'"
        src_expr = self._clean_path_sql(f'src."{src_col}"') if src_col else f"'{table_name}'"

        dedup_sql = self._browser_dedup_clause(
            "src",
            table_name,
            ("parsed_chrome_logins", "parsed_edge_logins", "parsed_brave_logins", "parsed_firefox_logins"),
            lambda a, pb, pbc: (
                f'COALESCE(CAST(_pb."{pbc.get("origin_url") or pbc.get("hostname")}" AS VARCHAR), \'\') = COALESCE({orig_expr}, \'\') '
                f'AND COALESCE(CAST(_pb."{pbc.get("username_value") or pbc.get("username")}" AS VARCHAR), \'\') = COALESCE({user_expr}, \'\')'
                if ((pbc.get("origin_url") or pbc.get("hostname")) and (pbc.get("username_value") or pbc.get("username")))
                else None
            ),
        )

        if ts_parts:
            if used_ts_sql:
                ts_type_expr = f"CASE WHEN ({used_ts_sql}) IS NOT NULL THEN 'Saved Login Used' ELSE 'Saved Login Created' END"
            else:
                ts_type_expr = "'Saved Login Created'"
            cursor.execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, category, artifact_name,
                primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {ts_expr},
                {ts_type_expr},
                'WEB RELATED',
                'Saved Logins (' || {browser_expr} || ')',
                COALESCE(NULLIF(TRIM({user_expr}), ''), '(empty)'),
                {orig_expr},
                'Saved login for ' || COALESCE(NULLIF(TRIM({user_expr}), ''), '(empty)') || ' at ' || {orig_expr} || ' (Used ' || {times_expr} || ' times)',
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}" src
            WHERE ({ts_expr}) IS NOT NULL{dedup_sql};
            """)

        if user_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'USER_ACCOUNT',
                TRIM({user_expr}),
                'WEB RELATED',
                'Saved Logins (' || {browser_expr} || ')',
                '{table_name}',
                {row_id_expr},
                'Browser saved credential at ' || {orig_expr},
                {ts_expr}
            FROM "{table_name}" src
            WHERE src."{user_col}" IS NOT NULL AND length(trim({user_expr})) > 0{dedup_sql};
            """)
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EMAIL_ADDRESS',
                LOWER(TRIM({user_expr})),
                'WEB RELATED',
                'Saved Logins (' || {browser_expr} || ')',
                '{table_name}',
                {row_id_expr},
                'Browser saved email credential at ' || {orig_expr},
                {ts_expr}
            FROM "{table_name}" src
            WHERE src."{user_col}" IS NOT NULL
              AND regexp_matches(TRIM({user_expr}), '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}}$'){dedup_sql};
            """)

        if orig_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'DOMAIN',
                lower(trim(regexp_extract({orig_expr}, '^(?:https?://)?([^/:]+)', 1))),
                'WEB RELATED',
                'Saved Logins (' || {browser_expr} || ')',
                '{table_name}',
                {row_id_expr},
                'Domain with saved login credentials via ' || {browser_expr},
                {ts_expr}
            FROM "{table_name}" src
            WHERE src."{orig_col}" IS NOT NULL
              AND regexp_extract({orig_expr}, '^(?:https?://)?([^/:]+)', 1) != ''{dedup_sql};
            """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 18. parsed_chat_messages (Teams, Discord, Slack)
    # -------------------------------------------------------------------------
    def _normalize_parsed_chat_messages(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_chat_messages"
        self._clear_table_normalizations(table_name)

        time_col = cols.get("timestamp_utc", "timestamp_utc")
        app_col = cols.get("app_name", "app_name")
        sender_col = cols.get("sender", "sender")
        channel_col = cols.get("recipient_channel", "recipient_channel")
        text_col = cols.get("message_text", "message_text")
        row_id_col = cols.get("_row_id", "_row_id")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        # 1. Timeline
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{time_col}" AS TIMESTAMP),
            'Chat Message',
            'CHAT',
            'Chat Messages (' || COALESCE("{app_col}", 'Chat') || ')',
            COALESCE(NULLIF(TRIM(CAST("{sender_col}" AS VARCHAR)), ''), 'Unknown Sender'),
            "{channel_col}",
            '[' || COALESCE("{app_col}", 'Chat') || '] ' || COALESCE("{sender_col}", '') || ': ' || substring("{text_col}", 1, 100),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{time_col}" IS NOT NULL AND TRY_CAST("{time_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: USER_ACCOUNT
        user_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'USER_ACCOUNT',
            TRIM(CAST("{sender_col}" AS VARCHAR)),
            'CHAT',
            'Chat Messages (' || COALESCE("{app_col}", 'Chat') || ')',
            '{table_name}',
            "{row_id_col}",
            'Chat sender in ' || COALESCE("{app_col}", 'Chat'),
            TRY_CAST("{time_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{sender_col}" IS NOT NULL AND length(trim(CAST("{sender_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(user_sql)

        chat_email_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EMAIL_ADDRESS',
            LOWER(regexp_extract(COALESCE(CAST("{sender_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{text_col}" AS VARCHAR), ''), '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}})', 1)),
            'CHAT',
            'Chat Messages (' || COALESCE("{app_col}", 'Chat') || ')',
            '{table_name}',
            "{row_id_col}",
            'Email referenced in ' || COALESCE("{app_col}", 'Chat'),
            TRY_CAST("{time_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE regexp_extract(COALESCE(CAST("{sender_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{text_col}" AS VARCHAR), ''), '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{{2,}})', 1) != '';
        """
        self.conn.execute(chat_email_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 19. parsed_cloud_files (OneDrive & Google Drive)
    # -------------------------------------------------------------------------
    def _normalize_parsed_cloud_files(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_cloud_files"
        self._clear_table_normalizations(table_name)

        time_col = cols.get("modified_time", "modified_time")
        provider_col = cols.get("cloud_provider", "cloud_provider")
        path_col = cols.get("local_path", "local_path")
        cid_col = cols.get("cloud_path_or_id", "cloud_path_or_id")
        acct_col = cols.get("account", "account")
        row_id_col = cols.get("_row_id", "_row_id")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        # 1. Timeline
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{time_col}" AS TIMESTAMP),
            'Cloud File Modified',
            'CLOUD',
            'Cloud Storage Files (' || COALESCE("{provider_col}", 'Cloud') || ')',
            "{path_col}",
            "{cid_col}",
            '[' || COALESCE("{provider_col}", 'Cloud') || '] Synced file: ' || "{path_col}",
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE {self._valid_ts_sql(f'"{time_col}"')};
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: FILE_PATH
        path_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_PATH',
            "{path_col}",
            'CLOUD',
            'Cloud Storage Files (' || COALESCE("{provider_col}", 'Cloud') || ')',
            '{table_name}',
            "{row_id_col}",
            'Cloud synced file in ' || COALESCE("{provider_col}", 'Cloud'),
            {self._clean_ts_expr(f'"{time_col}"')}
        FROM "{table_name}"
        WHERE "{path_col}" IS NOT NULL AND length(trim(CAST("{path_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(path_sql)

        acct_email_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            CASE
                WHEN CAST("{acct_col}" AS VARCHAR) LIKE '%@%' THEN 'EMAIL_ADDRESS'
                ELSE 'USER_ACCOUNT'
            END,
            CASE
                WHEN CAST("{acct_col}" AS VARCHAR) LIKE '%@%' THEN LOWER(TRIM(CAST("{acct_col}" AS VARCHAR)))
                ELSE TRIM(CAST("{acct_col}" AS VARCHAR))
            END,
            'CLOUD',
            'Cloud Storage Files (' || COALESCE("{provider_col}", 'Cloud') || ')',
            '{table_name}',
            "{row_id_col}",
            'Cloud sync account in ' || COALESCE("{provider_col}", 'Cloud'),
            {self._clean_ts_expr(f'"{time_col}"')}
        FROM "{table_name}"
        WHERE "{acct_col}" IS NOT NULL AND length(trim(CAST("{acct_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(acct_email_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 20. parsed_usb_devices (setupapi.dev.log + Registry USBSTOR/MountedDevices)
    # -------------------------------------------------------------------------
    def _normalize_parsed_usb_devices(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_usb_devices"
        self._clear_table_normalizations(table_name)

        first_col = cols.get("first_connected_utc", "first_connected_utc")
        last_col = cols.get("last_connected_utc", "last_connected_utc")
        serial_col = cols.get("serial_number", "serial_number")
        name_col = cols.get("friendly_name", "friendly_name")
        ven_col = cols.get("vendor_id", "vendor_id")
        prod_col = cols.get("product_id", "product_id")
        dl_col = cols.get("drive_letter", "drive_letter")
        row_id_col = cols.get("_row_id", "_row_id")
        src_col = cols.get("source_evidence", "source_evidence")

        # 1. Timeline (First Connected)
        first_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{first_col}" AS TIMESTAMP),
            'USB Device First Connected',
            'OPERATING SYSTEM',
            'USB Devices',
            "{serial_col}",
            "{name_col}",
            'USB Device First Connected: ' || COALESCE(NULLIF(TRIM(CAST("{name_col}" AS VARCHAR)), ''), CAST("{ven_col}" AS VARCHAR) || ' ' || CAST("{prod_col}" AS VARCHAR)) || ' (SN: ' || "{serial_col}" || ')' || COALESCE(' Drive: ' || "{dl_col}", ''),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{first_col}" IS NOT NULL AND TRY_CAST("{first_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(first_sql)

        # 2. Timeline (Last Connected - when different from first connected)
        last_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{last_col}" AS TIMESTAMP),
            'USB Device Last Connected',
            'OPERATING SYSTEM',
            'USB Devices',
            "{serial_col}",
            "{name_col}",
            'USB Device Last Connected: ' || COALESCE(NULLIF(TRIM(CAST("{name_col}" AS VARCHAR)), ''), CAST("{ven_col}" AS VARCHAR) || ' ' || CAST("{prod_col}" AS VARCHAR)) || ' (SN: ' || "{serial_col}" || ')' || COALESCE(' Drive: ' || "{dl_col}", ''),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{last_col}" IS NOT NULL
          AND TRY_CAST("{last_col}" AS TIMESTAMP) IS NOT NULL
          AND ("{first_col}" IS NULL OR TRY_CAST("{last_col}" AS TIMESTAMP) != TRY_CAST("{first_col}" AS TIMESTAMP));
        """
        self.conn.execute(last_sql)

        # 3. Entity Connections: USB_SERIAL (per GEMINI.md Section 6.5)
        serial_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'USB_SERIAL',
            UPPER(TRIM(CAST("{serial_col}" AS VARCHAR))),
            'OPERATING SYSTEM',
            'USB Devices',
            '{table_name}',
            "{row_id_col}",
            'USB Serial: ' || COALESCE(NULLIF(TRIM(CAST("{name_col}" AS VARCHAR)), ''), CAST("{ven_col}" AS VARCHAR) || ' ' || CAST("{prod_col}" AS VARCHAR)) || COALESCE(' [Drive ' || "{dl_col}" || ']', ''),
            COALESCE(TRY_CAST("{last_col}" AS TIMESTAMP), TRY_CAST("{first_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{serial_col}" IS NOT NULL AND length(trim(CAST("{serial_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(serial_sql)

        # 4. Entity Connections: DRIVE_LETTER (when present)
        dl_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'DRIVE_LETTER',
            UPPER(TRIM(CAST("{dl_col}" AS VARCHAR))),
            'OPERATING SYSTEM',
            'USB Devices',
            '{table_name}',
            "{row_id_col}",
            'USB Drive Letter mounted for SN: ' || "{serial_col}",
            COALESCE(TRY_CAST("{last_col}" AS TIMESTAMP), TRY_CAST("{first_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{dl_col}" IS NOT NULL AND length(trim(CAST("{dl_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(dl_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 21. artifact_yara_hits (YARA-X Malware Rule Hits)
    # -------------------------------------------------------------------------
    def _normalize_artifact_yara_hits(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "artifact_yara_hits"
        scanned_at_col = cols.get("scanned_at", "scanned_at")
        rule_name_col = cols.get("rule_name", "rule_name")
        file_name_col = cols.get("file_name", "file_name")
        file_path_col = cols.get("file_path", "file_path")
        sha256_col = cols.get("sha256", "sha256")
        pattern_col = cols.get("pattern_identifier", "pattern_identifier")
        offset_col = cols.get("match_offset", "match_offset")
        row_id_col = cols.get("_row_id", "_row_id")
        desc_col = cols.get("description")
        summary_expr = (
            f"COALESCE(\"{desc_col}\", 'YARA Rule ' || \"{rule_name_col}\") || ' matched in ' || \"{file_name_col}\" || ' (Pattern: ' || COALESCE(\"{pattern_col}\", '') || ', Offset: ' || CAST(\"{offset_col}\" AS VARCHAR) || ')'"
            if desc_col
            else f"'YARA Rule ' || \"{rule_name_col}\" || ' matched in ' || \"{file_name_col}\" || ' (Pattern: ' || COALESCE(\"{pattern_col}\", '') || ', Offset: ' || CAST(\"{offset_col}\" AS VARCHAR) || ')'"
        )

        self._clear_table_normalizations(table_name)

        # 1. Timeline SQL: Excluded from master_timeline because scanned_at is forensic tool execution time,
        # not a historical event on the evidence system. entity_connections.timestamp_utc is also NULL!
        clean_fpath_expr = self._clean_path_sql(f'"{file_path_col}"')

        # 2. Entity Connections: YARA_RULE
        yara_sql = f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name,
            source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'YARA_RULE',
            UPPER(TRIM(CAST("{rule_name_col}" AS VARCHAR))),
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'YARA rule matched in ' || "{file_name_col}",
            CAST(NULL AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{rule_name_col}" IS NOT NULL AND length(trim(CAST("{rule_name_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(yara_sql)

        # 3. Entity Connections: EXECUTABLE or FILE_NAME
        file_sql = f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name,
            source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            CASE
                WHEN LOWER(CAST("{file_name_col}" AS VARCHAR)) LIKE '%.exe'
                  OR LOWER(CAST("{file_name_col}" AS VARCHAR)) LIKE '%.dll'
                  OR LOWER(CAST("{file_name_col}" AS VARCHAR)) LIKE '%.sys'
                  OR LOWER(CAST("{file_name_col}" AS VARCHAR)) LIKE '%.ps1'
                  OR LOWER(CAST("{file_name_col}" AS VARCHAR)) LIKE '%.bat'
                  OR LOWER(CAST("{file_name_col}" AS VARCHAR)) LIKE '%.vbs'
                THEN 'EXECUTABLE'
                ELSE 'FILE_NAME'
            END,
            UPPER(TRIM(CAST("{file_name_col}" AS VARCHAR))),
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'Suspicious file matched YARA rule ' || "{rule_name_col}",
            CAST(NULL AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{file_name_col}" IS NOT NULL AND length(trim(CAST("{file_name_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(file_sql)

        # 4. Entity Connections: SHA256 (when present)
        sha_sql = f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name,
            source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'SHA256',
            LOWER(TRIM(CAST("{sha256_col}" AS VARCHAR))),
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'SHA256 for ' || "{file_name_col}" || ' (Rule: ' || "{rule_name_col}" || ')',
            CAST(NULL AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{sha256_col}" IS NOT NULL AND length(trim(CAST("{sha256_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(sha_sql)

        # 5. Entity Connections: FILE_PATH
        path_sql = f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name,
            source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_PATH',
            {clean_fpath_expr},
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'Path to suspicious file ' || "{file_name_col}",
            CAST(NULL AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{file_path_col}" IS NOT NULL AND length(trim(CAST("{file_path_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(path_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 22. artifact_ocr_results & media_ocr_results (RapidOCR Extracted Text)
    # -------------------------------------------------------------------------
    def _normalize_ocr_table(self, cols: Dict[str, str], table_name: str) -> Tuple[int, int]:
        file_name_col = cols.get("file_name")
        file_path_col = cols.get("file_path")
        sha256_col = cols.get("sha256")
        text_col = cols.get("extracted_text") or cols.get("ocr_text")
        row_id_col = cols.get("_row_id")

        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()
        if not file_name_col and not file_path_col:
            return (0, 0)

        # Deduplicate artifact_ocr_results when media_ocr_results already holds the synced rows
        dedup_clause = ""
        if table_name == "artifact_ocr_results" and self._table_exists("media_ocr_results"):
            m_cols = self._get_columns("media_ocr_results")
            if "file_path" in m_cols and file_path_col:
                dedup_clause = (
                    f' AND NOT EXISTS (SELECT 1 FROM "media_ocr_results" _m '
                    f'WHERE COALESCE(CAST(_m."{m_cols["file_path"]}" AS VARCHAR), \'\') = COALESCE(CAST(src."{file_path_col}" AS VARCHAR), \'\'))'
                )

        row_id_expr = f'COALESCE(src."{row_id_col}", src.rowid, 0)' if row_id_col else "COALESCE(src.rowid, 0)"
        text_expr = f'SUBSTR(COALESCE(CAST(src."{text_col}" AS VARCHAR), \'\'), 1, 60)' if text_col else "''"

        if file_name_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_NAME',
                UPPER(TRIM(CAST(src."{file_name_col}" AS VARCHAR))),
                'MEDIA',
                'RapidOCR Extracted Text',
                '{table_name}',
                {row_id_expr},
                'Image with OCR text: ' || {text_expr},
                CAST(NULL AS TIMESTAMP)
            FROM "{table_name}" src
            WHERE src."{file_name_col}" IS NOT NULL AND length(trim(CAST(src."{file_name_col}" AS VARCHAR))) > 0{dedup_clause};
            """)

        if sha256_col:
            fname_lbl = f'COALESCE(CAST(src."{file_name_col}" AS VARCHAR), \'\')' if file_name_col else "''"
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'SHA256',
                LOWER(TRIM(CAST(src."{sha256_col}" AS VARCHAR))),
                'MEDIA',
                'RapidOCR Extracted Text',
                '{table_name}',
                {row_id_expr},
                'SHA256 of image ' || {fname_lbl},
                CAST(NULL AS TIMESTAMP)
            FROM "{table_name}" src
            WHERE src."{sha256_col}" IS NOT NULL AND length(trim(CAST(src."{sha256_col}" AS VARCHAR))) > 0{dedup_clause};
            """)

        if file_path_col:
            fname_lbl = f'COALESCE(CAST(src."{file_name_col}" AS VARCHAR), \'\')' if file_name_col else "''"
            clean_fp = self._clean_path_sql(f'src."{file_path_col}"')
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                {clean_fp},
                'MEDIA',
                'RapidOCR Extracted Text',
                '{table_name}',
                {row_id_expr},
                'File path to image ' || {fname_lbl},
                CAST(NULL AS TIMESTAMP)
            FROM "{table_name}" src
            WHERE src."{file_path_col}" IS NOT NULL AND length(trim(CAST(src."{file_path_col}" AS VARCHAR))) > 0{dedup_clause};
            """)

        t_count = cursor.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = cursor.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)

    def _normalize_artifact_ocr_results(self, cols: Dict[str, str]) -> Tuple[int, int]:
        return self._normalize_ocr_table(cols, "artifact_ocr_results")

    def _normalize_media_ocr_results(self, cols: Dict[str, str]) -> Tuple[int, int]:
        return self._normalize_ocr_table(cols, "media_ocr_results")

    # -------------------------------------------------------------------------
    # 22. raw_rbcmd (Recycle Bin - RBCmd)
    # -------------------------------------------------------------------------
    def _normalize_raw_rbcmd(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_rbcmd"
        del_col = cols.get("deletedon")
        fname_col = cols.get("filename")
        size_col = cols.get("filesize")
        src_col = cols.get("sourcename", "SourceName")
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        if del_col:
            timeline_sql = f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                TRY_CAST("{del_col}" AS TIMESTAMP),
                'File Recycled / Deleted',
                'OPERATING SYSTEM',
                'Recycle Bin (RBCmd)',
                COALESCE("{fname_col}", 'Unknown Deleted File'),
                'Size: ' || COALESCE(CAST("{size_col}" AS VARCHAR), '0') || ' bytes',
                'Recycled file: ' || COALESCE("{fname_col}", '') || ' (Size: ' || COALESCE(CAST("{size_col}" AS VARCHAR), '0') || ' bytes)',
                '{table_name}',
                "{row_id_col}",
                "{src_col}"
            FROM "{table_name}"
            WHERE TRY_CAST("{del_col}" AS TIMESTAMP) IS NOT NULL;
            """
            self.conn.execute(timeline_sql)

        if fname_col:
            entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_PATH',
                TRIM(CAST("{fname_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Recycle Bin (RBCmd)',
                '{table_name}',
                "{row_id_col}",
                'Recycled file original path',
                TRY_CAST("{del_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0;
            """
            self.conn.execute(entity_sql)

            exe_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EXECUTABLE',
                UPPER(regexp_extract(CAST("{fname_col}" AS VARCHAR), '([^\\\\/]+)$', 1)),
                'OPERATING SYSTEM',
                'Recycle Bin (RBCmd)',
                '{table_name}',
                "{row_id_col}",
                'Recycled executable binary',
                TRY_CAST("{del_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{fname_col}" ILIKE '%.exe'
               OR "{fname_col}" ILIKE '%.dll'
               OR "{fname_col}" ILIKE '%.bat'
               OR "{fname_col}" ILIKE '%.ps1';
            """
            self.conn.execute(exe_sql)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 22b. raw_recentfilecache (Windows 7 RecentFileCache.bcf)
    # -------------------------------------------------------------------------
    def _normalize_raw_recentfilecache(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_recentfilecache"
        fname_col = (
            cols.get("filename")
            or cols.get("targetpath")
            or next(
                (
                    c
                    for k, c in cols.items()
                    if k != "sourcefile" and ("filename" in k or "path" in k or "file" in k)
                ),
                None,
            )
        )
        mod_col = cols.get("sourcemodified") or next((c for k, c in cols.items() if "modified" in k), None)
        crt_col = cols.get("sourcecreated") or next((c for k, c in cols.items() if "created" in k), None)
        other_ts_col = next(
            (
                c
                for k, c in cols.items()
                if k not in ("sourcemodified", "sourcecreated", "sourceaccessed")
                and ("time" in k or "date" in k)
            ),
            None,
        )
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)
        if not fname_col:
            return (0, 0)

        ts_parts: List[str] = []
        if other_ts_col:
            ts_parts.append(self._clean_ts_expr(f'"{other_ts_col}"'))
        if mod_col:
            ts_parts.append(self._clean_ts_expr(f'"{mod_col}"'))
        if crt_col:
            ts_parts.append(
                self._non_wallclock_ctime_sql(
                    f'"{crt_col}"',
                    self._clean_ts_expr(f'"{mod_col}"') if mod_col else None,
                )
            )
        ts_expr = ("COALESCE(" + ", ".join(ts_parts) + ")") if ts_parts else "NULL"

        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            {ts_expr},
            'Recent File Recorded (Win 7)',
            'OPERATING SYSTEM',
            'RecentFileCache (Windows 7)',
            regexp_extract(CAST("{fname_col}" AS VARCHAR), '([^\\\\/]+)$', 1),
            CAST("{fname_col}" AS VARCHAR),
            'RecentFileCache executable: ' || CAST("{fname_col}" AS VARCHAR),
            '{table_name}',
            "{row_id_col}",
            'RecentFileCache.bcf'
        FROM "{table_name}"
        WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0 AND {ts_expr} IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        entity_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_PATH',
            TRIM(CAST("{fname_col}" AS VARCHAR)),
            'OPERATING SYSTEM',
            'RecentFileCache (Windows 7)',
            '{table_name}',
            "{row_id_col}",
            'RecentFileCache recorded path',
            {ts_expr}
        FROM "{table_name}"
        WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(entity_sql)

        exe_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER(regexp_extract(CAST("{fname_col}" AS VARCHAR), '([^\\\\/]+)$', 1)),
            'OPERATING SYSTEM',
            'RecentFileCache (Windows 7)',
            '{table_name}',
            "{row_id_col}",
            'RecentFileCache executable',
            {ts_expr}
        FROM "{table_name}"
        WHERE "{fname_col}" ILIKE '%.exe'
           OR "{fname_col}" ILIKE '%.dll'
           OR "{fname_col}" ILIKE '%.bat'
           OR "{fname_col}" ILIKE '%.ps1';
        """
        self.conn.execute(exe_sql)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 23. parsed_scheduled_tasks (Scheduled Tasks)
    # -------------------------------------------------------------------------
    def _normalize_parsed_scheduled_tasks(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_scheduled_tasks"
        task_col = cols.get("task_name", "task_name")
        cmd_col = cols.get("execute_command", cols.get("command", "execute_command"))
        args_col = cols.get("arguments", "arguments")
        author_col = cols.get("author", "author")
        date_col = cols.get("date_created", cols.get("created_date", "date_created"))
        user_col = cols.get("author", cols.get("user_id", "author"))
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{date_col}" AS TIMESTAMP),
            'Scheduled Task Created',
            'OPERATING SYSTEM',
            'Scheduled Tasks',
            "{task_col}",
            COALESCE(NULLIF(TRIM(CAST("{cmd_col}" AS VARCHAR)), ''), CAST("{author_col}" AS VARCHAR), 'Task Action'),
            'Task ' || "{task_col}" || ' -> Exec: ' || COALESCE("{cmd_col}", '') || ' ' || COALESCE("{args_col}", ''),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE TRY_CAST("{date_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        entity_path_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_PATH',
            TRIM(CAST("{cmd_col}" AS VARCHAR)),
            'OPERATING SYSTEM',
            'Scheduled Tasks',
            '{table_name}',
            "{row_id_col}",
            'Scheduled Task Exec Path: ' || "{task_col}",
            TRY_CAST("{date_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{cmd_col}" IS NOT NULL AND length(trim(CAST("{cmd_col}" AS VARCHAR))) > 0 AND CAST("{cmd_col}" AS VARCHAR) NOT LIKE 'COM:%';
        """
        self.conn.execute(entity_path_sql)

        entity_exe_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER(regexp_extract(trim(replace(CAST("{cmd_col}" AS VARCHAR), '"', '')), '([^\\\\/]+)$', 1)),
            'OPERATING SYSTEM',
            'Scheduled Tasks',
            '{table_name}',
            "{row_id_col}",
            'Scheduled task binary for ' || "{task_col}",
            TRY_CAST("{date_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{cmd_col}" IS NOT NULL AND length(trim(CAST("{cmd_col}" AS VARCHAR))) > 0 AND CAST("{cmd_col}" AS VARCHAR) NOT LIKE 'COM:%';
        """
        self.conn.execute(entity_exe_sql)

        entity_user_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'USER_ACCOUNT',
            TRIM(CAST("{user_col}" AS VARCHAR)),
            'OPERATING SYSTEM',
            'Scheduled Tasks',
            '{table_name}',
            "{row_id_col}",
            'Principal for task ' || "{task_col}",
            TRY_CAST("{date_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{user_col}" IS NOT NULL AND length(trim(CAST("{user_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(entity_user_sql)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 24. parsed_powershell_history (PowerShell Console History)
    # -------------------------------------------------------------------------
    def _normalize_parsed_powershell_history(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_powershell_history"
        user_col = cols.get("username", cols.get("user_name", "username"))
        cmd_col = cols.get("execute_command", cols.get("command", "execute_command"))
        line_col = cols.get("line_number", "line_number")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        entity_user_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'USER_ACCOUNT',
            TRIM(CAST("{user_col}" AS VARCHAR)),
            'OPERATING SYSTEM',
            'PowerShell Console History',
            '{table_name}',
            "{row_id_col}",
            'PowerShell console user (line ' || CAST("{line_col}" AS VARCHAR) || ')',
            NULL
        FROM "{table_name}"
        WHERE "{user_col}" IS NOT NULL AND length(trim(CAST("{user_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(entity_user_sql)

        entity_cmd_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER(regexp_extract(CAST("{cmd_col}" AS VARCHAR), '^(?:[a-zA-Z]:[\\\\/][^ ]*[\\\\/])?([a-zA-Z0-9_.-]+\\.(?:exe|ps1|bat|vbs|cmd))', 1)),
            'OPERATING SYSTEM',
            'PowerShell Console History',
            '{table_name}',
            "{row_id_col}",
            'PowerShell invoked script/binary: ' || SUBSTR("{cmd_col}", 1, 60),
            NULL
        FROM "{table_name}"
        WHERE CAST("{cmd_col}" AS VARCHAR) ~ '(?i)\\.(exe|ps1|bat|vbs|cmd)';
        """
        self.conn.execute(entity_cmd_sql)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 25. parsed_rmm_sessions (RMM Sessions)
    # -------------------------------------------------------------------------
    def _normalize_parsed_rmm_sessions(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_rmm_sessions"
        app_col = cols.get("app_name", "app_name")
        remote_col = cols.get("remote_identifier", "remote_identifier")
        conn_type_col = cols.get("connection_type", "connection_type")
        start_col = cols.get("start_time_utc", "start_time_utc")
        details_col = cols.get("details", "details")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id,
            timestamp_utc,
            timestamp_type,
            category,
            artifact_name,
            primary_entity,
            secondary_entity,
            summary,
            source_table,
            source_row_id,
            source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{start_col}" AS TIMESTAMP),
            'RMM Session Event',
            'OPERATING SYSTEM',
            'Remote Access & RMM Sessions',
            COALESCE(NULLIF(TRIM(CAST("{remote_col}" AS VARCHAR)), ''), CAST("{app_col}" AS VARCHAR)),
            "{conn_type_col}",
            "{app_col}" || ' [' || COALESCE("{conn_type_col}", 'Session') || ']: ' || COALESCE("{details_col}", ''),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE TRY_CAST("{start_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        ip_entity_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'IP_ADDRESS',
            regexp_extract(COALESCE(CAST("{remote_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{details_col}" AS VARCHAR), ''), '([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})', 1),
            'OPERATING SYSTEM',
            'Remote Access & RMM Sessions',
            '{table_name}',
            "{row_id_col}",
            "{app_col}" || ' remote peer IP',
            TRY_CAST("{start_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE regexp_extract(COALESCE(CAST("{remote_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{details_col}" AS VARCHAR), ''), '([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})', 1) != '';
        """
        self.conn.execute(ip_entity_sql)

        app_entity_sql = f"""
        INSERT INTO entity_connections (
            connection_id,
            entity_type,
            entity_value,
            category,
            artifact_name,
            source_table,
            source_row_id,
            context_label,
            timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EXECUTABLE',
            UPPER("{app_col}" || '.EXE'),
            'OPERATING SYSTEM',
            'Remote Access & RMM Sessions',
            '{table_name}',
            "{row_id_col}",
            'RMM remote tool client',
            TRY_CAST("{start_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{app_col}" IS NOT NULL AND length(trim(CAST("{app_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(app_entity_sql)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 26. parsed_wpn_notifications (Windows Push Notifications)
    # -------------------------------------------------------------------------
    def _normalize_parsed_wpn_notifications(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_wpn_notifications"
        app_col = cols.get("app_id")
        app_expr = self._coalesce_str_sql(cols, "app_id", default_sql="'Windows'")
        sec_type_expr = self._coalesce_str_sql(cols, "header", "notification_type", default_sql="'Notification'")
        toast_type_expr = self._coalesce_str_sql(cols, "header", "notification_type", default_sql="'toast'")
        arr_expr = self._coalesce_ts_sql(cols, "timestamp_utc", "arrival_time_utc")
        txt_parts = [f'NULLIF(TRIM(CAST("{cols[k]}" AS VARCHAR)), \'\')' for k in ("body", "title", "payload_text", "payload") if k in cols]
        txt_expr = f"COALESCE({', '.join(txt_parts)}, '')" if txt_parts else "''"
        src_col = cols.get("source_file", cols.get("file_path"))
        src_expr = f'"{src_col}"' if src_col else f"'{table_name}'"
        row_id_col = cols.get("_row_id")
        row_id_expr = f'COALESCE("{row_id_col}", rowid, 0)' if row_id_col else "COALESCE(rowid, 0)"

        self._clear_table_normalizations(table_name)

        if arr_expr:
            timeline_sql = f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {arr_expr},
                'Push Notification Arrived',
                'OPERATING SYSTEM',
                'Windows Push Notifications',
                {app_expr},
                {sec_type_expr},
                'Notification from ' || {app_expr} || ' [' || {toast_type_expr} || ']: ' || SUBSTR({txt_expr}, 1, 100),
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}"
            WHERE ({arr_expr}) IS NOT NULL;
            """
            self.conn.execute(timeline_sql)

        if app_col:
            ent_ts_expr = arr_expr if arr_expr else "CAST(NULL AS TIMESTAMP)"
            app_entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'APPLICATION',
                TRIM(CAST("{app_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Windows Push Notifications',
                '{table_name}',
                {row_id_expr},
                'Application posting push notification',
                {ent_ts_expr}
            FROM "{table_name}"
            WHERE "{app_col}" IS NOT NULL AND length(trim(CAST("{app_col}" AS VARCHAR))) > 0;
            """
            self.conn.execute(app_entity_sql)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 27. Universal SQLite / SQLECmd Generic Normalizer
    # -------------------------------------------------------------------------
    def _normalize_generic_sqlite_table(self, table_name: str, cols: Dict[str, str]) -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)
        row_id_col = cols.get("_row_id", "_row_id")

        ts_col = None
        for col_low, col_orig in cols.items():
            if any(k in col_low for k in ["time", "date", "timestamp", "created", "modified"]):
                ts_col = col_orig
                break

        path_or_name_col = None
        for col_low, col_orig in cols.items():
            if any(k in col_low for k in ["path", "file", "url", "user", "name", "id", "title"]):
                path_or_name_col = col_orig
                break

        if ts_col:
            prim_expr = f'"{path_or_name_col}"' if path_or_name_col else f"'{table_name}'"
            timeline_sql = f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                TRY_CAST("{ts_col}" AS TIMESTAMP),
                'Database Record Event',
                'OPERATING SYSTEM',
                '{table_name}',
                {prim_expr},
                '{ts_col}',
                'SQLite record in {table_name}: ' || COALESCE(CAST({prim_expr} AS VARCHAR), ''),
                '{table_name}',
                "{row_id_col}",
                '{table_name}'
            FROM "{table_name}"
            WHERE {self._valid_ts_sql(f'"{ts_col}"')};
            """
            try:
                self.conn.execute(timeline_sql)
            except Exception as ex:
                print(f"[Normalizer] Notice: Generic timeline insert skipped for {table_name}: {ex}")

        if path_or_name_col:
            entity_sql = f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'IDENTIFIER',
                TRIM(CAST("{path_or_name_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                '{table_name}',
                '{table_name}',
                "{row_id_col}",
                'Database identifier in {table_name}',
                {self._clean_ts_expr(f'"{ts_col}"') if ts_col else 'NULL'}
            FROM "{table_name}"
            WHERE "{path_or_name_col}" IS NOT NULL AND length(trim(CAST("{path_or_name_col}" AS VARCHAR))) > 0;
            """
            try:
                self.conn.execute(entity_sql)
            except Exception as ex:
                print(f"[Normalizer] Notice: Generic entity insert skipped for {table_name}: {ex}")

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

# -------------------------------------------------------------------------
    # 28. parsed_media_exif (Image & Video EXIF Metadata)
    # -------------------------------------------------------------------------
    def _normalize_parsed_media_exif(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_media_exif"
        self._clear_table_normalizations(table_name)
        row_id_col = cols.get("_row_id", "_row_id")
        dt_col = cols.get("datetime_original", "datetime_original")
        fname_col = cols.get("file_name", "file_name")
        fpath_col = cols.get("file_path", "file_path")
        make_col = cols.get("camera_make", "camera_make")
        model_col = cols.get("camera_model", "camera_model")
        ftype_col = cols.get("file_type", "file_type")
        gps_col = cols.get("gps_position", cols.get("gps_coordinates"))
        sha_col = cols.get("sha256", "sha256")
        w_col = cols.get("image_width", cols.get("width"))
        h_col = cols.get("image_height", cols.get("height"))
        dur_col = cols.get("duration_seconds")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        dim_expr = f"'Dimensions: ' || CAST(\"{w_col}\" AS VARCHAR) || 'x' || CAST(\"{h_col}\" AS VARCHAR)" if (w_col and h_col) else "''"
        dur_expr = f"CASE WHEN \"{dur_col}\" > 0 THEN ' | Duration: ' || CAST(\"{dur_col}\" AS VARCHAR) || 's' ELSE '' END" if dur_col else "''"
        gps_expr = f"CASE WHEN \"{gps_col}\" IS NOT NULL AND length(\"{gps_col}\") > 0 THEN ' | GPS: ' || \"{gps_col}\" ELSE '' END" if gps_col else "''"

        # 1. Timeline
        timeline_sql = f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            "{dt_col}",
            'Media Captured (EXIF)',
            'MEDIA',
            'Media EXIF Metadata',
            "{fname_col}",
            COALESCE(NULLIF(TRIM(COALESCE(CAST("{make_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{model_col}" AS VARCHAR), '')), ''), CAST("{ftype_col}" AS VARCHAR)),
            {dim_expr} || {dur_expr} || {gps_expr},
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{dt_col}" IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: FILE_NAME
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_NAME',
            UPPER(TRIM(CAST("{fname_col}" AS VARCHAR))),
            'MEDIA',
            'Media EXIF Metadata',
            '{table_name}',
            "{row_id_col}",
            'Media file name (' || "{ftype_col}" || ')',
            "{dt_col}"
        FROM "{table_name}"
        WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: SHA256
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'SHA256',
            LOWER(TRIM(CAST("{sha_col}" AS VARCHAR))),
            'MEDIA',
            'Media EXIF Metadata',
            '{table_name}',
            "{row_id_col}",
            'Media SHA256 hash',
            "{dt_col}"
        FROM "{table_name}"
        WHERE "{sha_col}" IS NOT NULL AND length(trim(CAST("{sha_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: CAMERA_DEVICE
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'CAMERA_DEVICE',
            UPPER(TRIM(COALESCE(CAST("{make_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{model_col}" AS VARCHAR), ''))),
            'MEDIA',
            'Media EXIF Metadata',
            '{table_name}',
            "{row_id_col}",
            'Camera hardware EXIF identifier',
            "{dt_col}"
        FROM "{table_name}"
        WHERE length(trim(COALESCE(CAST("{make_col}" AS VARCHAR), '') || ' ' || COALESCE(CAST("{model_col}" AS VARCHAR), ''))) > 0;
        """)

        # Entity Connections: GEOLOCATION
        if gps_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'GEOLOCATION',
                "{gps_col}",
                'MEDIA',
                'Media EXIF Metadata',
                '{table_name}',
                "{row_id_col}",
                'Media capture GPS coordinates',
                "{dt_col}"
            FROM "{table_name}"
            WHERE "{gps_col}" IS NOT NULL AND length(trim(CAST("{gps_col}" AS VARCHAR))) > 0;
            """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 29. parsed_thumbcache (Windows Thumbcache & Screenshots)
    # -------------------------------------------------------------------------
    def _normalize_parsed_thumbcache(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_thumbcache"
        self._clear_table_normalizations(table_name)
        row_id_col = cols.get("_row_id", "_row_id")
        cache_col = cols.get("cache_file", "cache_file")
        hash_col = cols.get("entry_hash", "entry_hash")
        ext_col = cols.get("extension", "extension")
        size_col = cols.get("image_size_bytes", "image_size_bytes")
        sha_col = cols.get("sha256", "sha256")
        type_col = cols.get("source_type", "source_type")
        time_col = cols.get("timestamp_utc", "timestamp_utc")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        # 1. Timeline (for entries with valid historical timestamp)
        self.conn.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            TRY_CAST("{time_col}" AS TIMESTAMP),
            'Thumbnail Cached / Screen Captured',
            'MEDIA',
            'Windows Thumbcache & Screenshots',
            COALESCE("{hash_col}", "{sha_col}"),
            "{type_col}",
            "{type_col}" || ' (' || "{ext_col}" || ', ' || CAST("{size_col}" AS VARCHAR) || ' bytes) in ' || "{cache_col}",
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE {self._valid_ts_sql(f'"{time_col}"')};
        """)

        # 2. Entity Connections: THUMBCACHE_HASH
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'THUMBCACHE_HASH',
            UPPER(TRIM(CAST("{hash_col}" AS VARCHAR))),
            'MEDIA',
            'Windows Thumbcache & Screenshots',
            '{table_name}',
            "{row_id_col}",
            "{type_col}" || ' entry hash in ' || "{cache_col}",
            {self._clean_ts_expr(f'"{time_col}"')}
        FROM "{table_name}"
        WHERE "{hash_col}" IS NOT NULL AND length(trim(CAST("{hash_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: SHA256
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'SHA256',
            LOWER(TRIM(CAST("{sha_col}" AS VARCHAR))),
            'MEDIA',
            'Windows Thumbcache & Screenshots',
            '{table_name}',
            "{row_id_col}",
            'Carved thumbnail SHA256 digest',
            {self._clean_ts_expr(f'"{time_col}"')}
        FROM "{table_name}"
        WHERE "{sha_col}" IS NOT NULL AND length(trim(CAST("{sha_col}" AS VARCHAR))) > 0;
        """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 30. parsed_documents_metadata (Documents & Zone.Identifier)
    # -------------------------------------------------------------------------
    def _normalize_parsed_documents_metadata(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_documents_metadata"
        self._clear_table_normalizations(table_name)
        row_id_col = cols.get("_row_id")
        row_id_expr = f'COALESCE("{row_id_col}", rowid, 0)' if row_id_col else "COALESCE(rowid, 0)"
        fname_col = cols.get("file_name", "file_name")
        ftype_col = cols.get("file_type")
        ftype_expr = f'CAST("{ftype_col}" AS VARCHAR)' if ftype_col else "'doc'"
        title_col = cols.get("title")
        title_expr = f'COALESCE(NULLIF(TRIM(CAST("{title_col}" AS VARCHAR)), \'\'), CAST("{fname_col}" AS VARCHAR))' if title_col else f'CAST("{fname_col}" AS VARCHAR)'
        author_col = cols.get("author")
        author_expr = f'CAST("{author_col}" AS VARCHAR)' if author_col else "NULL"
        mod_by_col = cols.get("last_modified_by")
        mod_by_expr = f'CAST("{mod_by_col}" AS VARCHAR)' if mod_by_col else "NULL"
        ctime_col = cols.get("created_time")
        mtime_col = cols.get("modified_time")
        macros_col = cols.get("has_macros")
        macros_expr = f'CASE WHEN "{macros_col}" = true THEN \' [VBA MACROS DETECTED]\' ELSE \'\' END' if macros_col else "''"
        host_col = cols.get("zone_host_url", cols.get("host_url"))
        host_suffix_expr = (
            f'CASE WHEN "{host_col}" IS NOT NULL AND length(CAST("{host_col}" AS VARCHAR)) > 0 THEN \' | Downloaded from: \' || CAST("{host_col}" AS VARCHAR) ELSE \'\' END'
            if host_col
            else "''"
        )
        sha_col = cols.get("sha256")
        src_col = cols.get("source_file", cols.get("file_path"))
        src_expr = self._clean_path_sql(f'"{src_col}"') if src_col else f"'{table_name}'"

        mtime_ref = f'"{mtime_col}"' if mtime_col else None
        ctime_safe_expr = (
            self._non_wallclock_ctime_sql(f'"{ctime_col}"', mtime_ref)
            if ctime_col
            else "CAST(NULL AS TIMESTAMP)"
        )
        mtime_safe_expr = (
            self._clean_ts_expr(f'"{mtime_col}"')
            if mtime_col
            else "CAST(NULL AS TIMESTAMP)"
        )

        # 1. Timeline: Created (canonical DFIR Born/Created = ...B)
        if ctime_col:
            self.conn.execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, macb, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {ctime_safe_expr},
                'Document Created',
                '...B',
                'DOCUMENTS',
                'Corporate Documents',
                "{fname_col}",
                COALESCE({author_expr}, {ftype_expr}),
                'Title: ' || {title_expr} || {macros_expr} || {host_suffix_expr},
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}"
            WHERE ({ctime_safe_expr}) IS NOT NULL;
            """)

        # Timeline: Modified
        if mtime_col:
            self.conn.execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, macb, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {mtime_safe_expr},
                'Document Modified',
                'M...',
                'DOCUMENTS',
                'Corporate Documents',
                "{fname_col}",
                COALESCE({mod_by_expr}, {author_expr}),
                'Title: ' || {title_expr} || ' | Last modified by: ' || COALESCE({mod_by_expr}, 'Unknown'),
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}"
            WHERE ({mtime_safe_expr}) IS NOT NULL
              AND (({ctime_safe_expr}) IS NULL OR ({mtime_safe_expr}) != ({ctime_safe_expr}));
            """)

        # 2. Entity Connections: FILE_NAME
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_NAME',
            UPPER(TRIM(CAST("{fname_col}" AS VARCHAR))),
            'DOCUMENTS',
            'Corporate Documents',
            '{table_name}',
            {row_id_expr},
            'Corporate document file name (' || {ftype_expr} || ')',
            COALESCE({mtime_safe_expr}, {ctime_safe_expr})
        FROM "{table_name}"
        WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: USER_ACCOUNT (Author)
        if author_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'USER_ACCOUNT',
                TRIM(CAST("{author_col}" AS VARCHAR)),
                'DOCUMENTS',
                'Corporate Documents',
                '{table_name}',
                {row_id_expr},
                'Document author of ' || "{fname_col}",
                COALESCE({ctime_safe_expr}, {mtime_safe_expr})
            FROM "{table_name}"
            WHERE "{author_col}" IS NOT NULL AND length(trim(CAST("{author_col}" AS VARCHAR))) > 0;
            """)

        # Entity Connections: USER_ACCOUNT (Last Modified By)
        if mod_by_col:
            author_diff_pred = f'("{author_col}" IS NULL OR "{mod_by_col}" != "{author_col}")' if author_col else "1=1"
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'USER_ACCOUNT',
                TRIM(CAST("{mod_by_col}" AS VARCHAR)),
                'DOCUMENTS',
                'Corporate Documents',
                '{table_name}',
                {row_id_expr},
                'Document last modifier of ' || "{fname_col}",
                {mtime_safe_expr}
            FROM "{table_name}"
            WHERE "{mod_by_col}" IS NOT NULL AND length(trim(CAST("{mod_by_col}" AS VARCHAR))) > 0 AND {author_diff_pred};
            """)

        # Entity Connections: SHA256
        if sha_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'SHA256',
                LOWER(TRIM(CAST("{sha_col}" AS VARCHAR))),
                'DOCUMENTS',
                'Corporate Documents',
                '{table_name}',
                {row_id_expr},
                'Document SHA256 digest',
                COALESCE({mtime_safe_expr}, {ctime_safe_expr})
            FROM "{table_name}"
            WHERE "{sha_col}" IS NOT NULL AND length(trim(CAST("{sha_col}" AS VARCHAR))) > 0;
            """)

        # Entity Connections: URL & DOMAIN from HostUrl
        if host_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'URL',
                TRIM(CAST("{host_col}" AS VARCHAR)),
                'DOCUMENTS',
                'Corporate Documents',
                '{table_name}',
                {row_id_expr},
                'Zone.Identifier download HostUrl for ' || "{fname_col}",
                COALESCE({mtime_safe_expr}, {ctime_safe_expr})
            FROM "{table_name}"
            WHERE "{host_col}" IS NOT NULL AND length(trim(CAST("{host_col}" AS VARCHAR))) > 0;
            """)

            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'DOMAIN',
                LOWER(regexp_extract(CAST("{host_col}" AS VARCHAR), '://([^/:]+)', 1)),
                'DOCUMENTS',
                'Corporate Documents',
                '{table_name}',
                {row_id_expr},
                'Zone.Identifier download host domain',
                COALESCE({mtime_safe_expr}, {ctime_safe_expr})
            FROM "{table_name}"
            WHERE "{host_col}" IS NOT NULL AND regexp_extract(CAST("{host_col}" AS VARCHAR), '://([^/:]+)', 1) IS NOT NULL AND length(regexp_extract(CAST("{host_col}" AS VARCHAR), '://([^/:]+)', 1)) > 0;
            """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 31. parsed_emails (Emails & Mail Stores)
    # -------------------------------------------------------------------------
    def _normalize_parsed_emails(self, cols: Dict[str, str], table_name: str = "parsed_emails") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)
        # Avoid 2x duplication when granular email tables are synced alongside combined parsed_emails
        if table_name != "parsed_emails" and self._table_exists("parsed_emails"):
            return (0, 0)

        row_id_col = cols.get("_row_id")
        row_id_expr = f'COALESCE("{row_id_col}", rowid, 0)' if row_id_col else "COALESCE(rowid, 0)"
        fmt_expr = self._coalesce_str_sql(cols, "email_format", default_sql="'Email'")
        sender_col = cols.get("sender")
        sender_expr = self._coalesce_str_sql(cols, "sender", default_sql="'(Unknown Sender)'")
        recip_col = cols.get("recipients")
        recip_expr = self._coalesce_str_sql(cols, "recipients", default_sql="''")
        subj_expr = self._coalesce_str_sql(cols, "subject", default_sql="'(No Subject)'")
        ts_expr = self._coalesce_ts_sql(cols, "date_utc", "sent_time_utc", "received_time_utc", "timestamp_utc")
        msg_id_col = cols.get("message_id")
        att_cnt_col = cols.get("attachments_count", cols.get("attachment_count"))
        att_names_col = cols.get("attachment_names")
        src_col = cols.get("source_file", cols.get("file_path"))
        src_expr = self._clean_path_sql(f'"{src_col}"') if src_col else f"'{table_name}'"

        att_suffix_expr = (
            f'CASE WHEN COALESCE("{att_cnt_col}", 0) > 0 THEN \' | Attachments (\' || CAST("{att_cnt_col}" AS VARCHAR) || \'): \' || COALESCE(CAST("{att_names_col}" AS VARCHAR), \'\') ELSE \'\' END'
            if (att_cnt_col and att_names_col)
            else "''"
        )

        # 1. Timeline (strict canonical category: 'EMAIL & CALENDAR')
        if ts_expr:
            self.conn.execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                {ts_expr},
                'Email Sent/Received (' || {fmt_expr} || ')',
                'EMAIL & CALENDAR',
                'Corporate Email Stores',
                {sender_expr},
                {subj_expr},
                'Subject: ' || {subj_expr} || ' | To: ' || {recip_expr} || {att_suffix_expr},
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}"
            WHERE ({ts_expr}) IS NOT NULL;
            """)

        ent_ts_expr = ts_expr if ts_expr else "CAST(NULL AS TIMESTAMP)"

        # 2. Entity Connections: EMAIL_ADDRESS (Sender)
        if sender_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EMAIL_ADDRESS',
                LOWER(TRIM(CAST("{sender_col}" AS VARCHAR))),
                'EMAIL & CALENDAR',
                'Corporate Email Stores',
                '{table_name}',
                {row_id_expr},
                'Email sender (' || {fmt_expr} || ')',
                {ent_ts_expr}
            FROM "{table_name}"
            WHERE "{sender_col}" IS NOT NULL AND length(trim(CAST("{sender_col}" AS VARCHAR))) > 0;
            """)

        # Entity Connections: EMAIL_ADDRESS (Recipients)
        if recip_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'EMAIL_ADDRESS',
                LOWER(TRIM(CAST("{recip_col}" AS VARCHAR))),
                'EMAIL & CALENDAR',
                'Corporate Email Stores',
                '{table_name}',
                {row_id_expr},
                'Email recipient (' || {fmt_expr} || ')',
                {ent_ts_expr}
            FROM "{table_name}"
            WHERE "{recip_col}" IS NOT NULL AND length(trim(CAST("{recip_col}" AS VARCHAR))) > 0;
            """)

        # Entity Connections: MESSAGE_ID
        if msg_id_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'MESSAGE_ID',
                TRIM(CAST("{msg_id_col}" AS VARCHAR)),
                'EMAIL & CALENDAR',
                'Corporate Email Stores',
                '{table_name}',
                {row_id_expr},
                'Email internet message ID',
                {ent_ts_expr}
            FROM "{table_name}"
            WHERE "{msg_id_col}" IS NOT NULL AND length(trim(CAST("{msg_id_col}" AS VARCHAR))) > 0;
            """)

        # Entity Connections: FILE_NAME (Attachments)
        if att_cnt_col and att_names_col:
            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'FILE_NAME',
                UPPER(TRIM(CAST("{att_names_col}" AS VARCHAR))),
                'EMAIL & CALENDAR',
                'Corporate Email Stores',
                '{table_name}',
                {row_id_expr},
                'Email attachment payload',
                {ent_ts_expr}
            FROM "{table_name}"
            WHERE COALESCE("{att_cnt_col}", 0) > 0 AND "{att_names_col}" IS NOT NULL AND length(trim(CAST("{att_names_col}" AS VARCHAR))) > 0;
            """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 32. parsed_notifications (Windows Push Notifications — 1x Deduplicated against parsed_wpn_notifications)
    # -------------------------------------------------------------------------
    def _normalize_parsed_notifications(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_notifications"
        self._clear_table_normalizations(table_name)
        cursor = self.conn.cursor()

        row_id_col = cols.get("_row_id")
        app_col = cols.get("app_id")
        time_col = cols.get("timestamp_utc") or cols.get("arrival_time_utc") or cols.get("arrival_time")
        title_col = cols.get("title") or cols.get("header")
        body_col = cols.get("body") or cols.get("payload_text") or cols.get("payload")
        action_col = cols.get("action_url")
        src_col = cols.get("source_file") or cols.get("file_path")

        if not app_col and not time_col:
            return (0, 0)

        row_id_expr = f'COALESCE(src."{row_id_col}", src.rowid, 0)' if row_id_col else "COALESCE(src.rowid, 0)"
        app_expr = f'COALESCE(CAST(src."{app_col}" AS VARCHAR), \'Windows Notification\')' if app_col else "'Windows Notification'"
        title_expr = f'COALESCE(CAST(src."{title_col}" AS VARCHAR), \'\')' if title_col else "''"
        body_expr = (
            f'CASE WHEN src."{body_col}" IS NOT NULL AND length(CAST(src."{body_col}" AS VARCHAR)) > 0 THEN \': \' || CAST(src."{body_col}" AS VARCHAR) ELSE \'\' END'
            if body_col
            else "''"
        )
        src_expr = self._clean_path_sql(f'src."{src_col}"') if src_col else f"'{table_name}'"

        dedup_clause = ""
        if self._table_exists("parsed_wpn_notifications"):
            w_cols = self._get_columns("parsed_wpn_notifications")
            w_app = w_cols.get("app_id")
            w_ts_cols = [w_cols[k] for k in ("timestamp_utc", "arrival_time_utc") if k in w_cols]
            if w_app and app_col and w_ts_cols and time_col:
                w_ts_expr = "COALESCE(" + ", ".join([f'TRY_CAST(_w."{c}" AS TIMESTAMP)' for c in w_ts_cols]) + ")"
                dedup_clause = (
                    f' AND NOT EXISTS (SELECT 1 FROM "parsed_wpn_notifications" _w '
                    f'WHERE COALESCE(CAST(_w."{w_app}" AS VARCHAR), \'\') = COALESCE(CAST(src."{app_col}" AS VARCHAR), \'\') '
                    f'AND ({w_ts_expr}) IS NOT DISTINCT FROM TRY_CAST(src."{time_col}" AS TIMESTAMP))'
                )
            elif w_app and app_col:
                dedup_clause = (
                    f' AND NOT EXISTS (SELECT 1 FROM "parsed_wpn_notifications" _w '
                    f'WHERE COALESCE(CAST(_w."{w_app}" AS VARCHAR), \'\') = COALESCE(CAST(src."{app_col}" AS VARCHAR), \'\'))'
                )

        if time_col:
            cursor.execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, category, artifact_name,
                primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                TRY_CAST(src."{time_col}" AS TIMESTAMP),
                'Toast Notification Received',
                'OPERATING SYSTEM',
                'Windows Push Notifications',
                {app_expr},
                {title_expr},
                '[' || {app_expr} || '] ' || {title_expr} || {body_expr},
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}" src
            WHERE {self._valid_ts_sql(f'src."{time_col}"')}{dedup_clause};
            """)

        ts_clean = self._clean_ts_expr(f'src."{time_col}"') if time_col else "NULL"
        if app_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'APPLICATION',
                TRIM(CAST(src."{app_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Windows Push Notifications',
                '{table_name}',
                {row_id_expr},
                'Notification generating application',
                {ts_clean}
            FROM "{table_name}" src
            WHERE src."{app_col}" IS NOT NULL AND length(trim(CAST(src."{app_col}" AS VARCHAR))) > 0{dedup_clause};
            """)

        if action_col:
            cursor.execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'URL',
                TRIM(CAST(src."{action_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Windows Push Notifications',
                '{table_name}',
                {row_id_expr},
                'Notification launch action URL',
                {ts_clean}
            FROM "{table_name}" src
            WHERE src."{action_col}" IS NOT NULL AND length(trim(CAST(src."{action_col}" AS VARCHAR))) > 0{dedup_clause};
            """)

        t_count = cursor.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = cursor.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    def _normalize_raw_wxt_activity(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_wxt_activity"
        time_col = cols.get("starttime") or cols.get("lastmodifiedtime") or cols.get("createdtime") or cols.get("lastmodifiedonclient")
        app_col = cols.get("executable") or cols.get("appid") or cols.get("packagename") or cols.get("application") or cols.get("appdisplayname")
        desc_col = cols.get("displaytext") or cols.get("contentinfo") or cols.get("payload") or cols.get("description")
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)

        if time_col and app_col:
            self.conn.execute(f"""
            INSERT INTO master_timeline (
                timeline_id,
                timestamp_utc,
                timestamp_type,
                category,
                artifact_name,
                primary_entity,
                secondary_entity,
                summary,
                source_table,
                source_row_id,
                source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                TRY_CAST("{time_col}" AS TIMESTAMP),
                'Windows Timeline Activity',
                'OPERATING SYSTEM',
                'Windows Timeline (ActivitiesCache)',
                COALESCE("{app_col}", 'Unknown Application'),
                COALESCE("{desc_col}", ''),
                'Timeline Activity: ' || COALESCE("{app_col}", '') || CASE WHEN "{desc_col}" IS NOT NULL THEN ' - ' || CAST("{desc_col}" AS VARCHAR) ELSE '' END,
                '{table_name}',
                "{row_id_col}",
                'ActivitiesCache.db'
            FROM "{table_name}"
            WHERE TRY_CAST("{time_col}" AS TIMESTAMP) IS NOT NULL;
            """)

            self.conn.execute(f"""
            INSERT INTO entity_connections (
                connection_id,
                entity_type,
                entity_value,
                category,
                artifact_name,
                source_table,
                source_row_id,
                context_label,
                timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                'APPLICATION',
                TRIM(CAST("{app_col}" AS VARCHAR)),
                'OPERATING SYSTEM',
                'Windows Timeline (ActivitiesCache)',
                '{table_name}',
                "{row_id_col}",
                'Application executed via Windows Timeline',
                TRY_CAST("{time_col}" AS TIMESTAMP)
            FROM "{table_name}"
            WHERE "{app_col}" IS NOT NULL AND length(trim(CAST("{app_col}" AS VARCHAR))) > 0;
            """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 33. M1/M2/M3/M4-B New Artifact Normalizers (Hindsight, VSS,Carved, BulkExtractor, Sessions, TextDocs, Stinger, 8 AXIOM Registry/OS Tables)
    # -------------------------------------------------------------------------
    def _pick_col(self, cols: Dict[str, str], *names: str) -> Optional[str]:
        for n in names:
            if n.lower() in cols:
                return cols[n.lower()]
        return None

    def _emit_tl(
        self, table_name: str, ts_expr: str, ts_type: str, macb: str, category: str,
        artifact_name: str, primary_expr: str, secondary_expr: str, summary_expr: str,
        row_id_expr: str, src_expr: str, extra_where: str = "1=1"
    ) -> None:
        self.conn.cursor().execute(f"""
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, macb, category, artifact_name,
                primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
            )
            SELECT
                nextval('seq_timeline_id'),
                TRY_CAST({ts_expr} AS TIMESTAMP),
                '{ts_type}',
                '{macb}',
                '{category}',
                '{artifact_name}',
                {primary_expr},
                {secondary_expr},
                {summary_expr},
                '{table_name}',
                {row_id_expr},
                {src_expr}
            FROM "{table_name}"
            WHERE {self._valid_ts_sql(ts_expr)} AND ({extra_where});
        """)

    def _emit_ent(
        self, table_name: str, ent_type: str, val_expr: str, category: str,
        artifact_name: str, row_id_expr: str, ctx_expr: str, ts_expr: str = "CAST(NULL AS TIMESTAMP)",
        extra_where: str = "1=1"
    ) -> None:
        self.conn.cursor().execute(f"""
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            )
            SELECT
                nextval('seq_connection_id'),
                '{ent_type}',
                {val_expr},
                '{category}',
                '{artifact_name}',
                '{table_name}',
                {row_id_expr},
                {ctx_expr},
                {ts_expr}
            FROM "{table_name}"
            WHERE ({val_expr}) IS NOT NULL AND length(trim(CAST({val_expr} AS VARCHAR))) > 0 AND ({extra_where});
        """)

    def _finish_counts(self, table_name: str) -> Tuple[int, int]:
        cur = self.conn.cursor()
        t_c = cur.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_c = cur.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_c, e_c)

    def _normalize_raw_hindsight(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "raw_hindsight"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        ts_sql = self._coalesce_ts_sql(
            cols, "timestamp_utc", "visit_time_utc", "datetime", "visit_time", "timestamp"
        )
        url_e = self._coalesce_str_sql(cols, "url", "value", default_sql="'(Hindsight Record)'")
        has_url_col = any(k in cols for k in ("url", "value"))
        title_e = self._coalesce_str_sql(cols, "title", "interpretation", "description", default_sql="''")
        atype_e = self._coalesce_str_sql(cols, "artifact_type", "record_type", default_sql="'Browser Artifact'")
        src_raw_e = self._coalesce_str_sql(cols, "source_file", "source_path", "profile_path", "profile")
        src_e = f"COALESCE({self._clean_path_sql(src_raw_e)}, '{t}')" if src_raw_e != "NULL" else f"'{t}'"

        browser_src_list = (
            "'parsed_chrome_history', 'parsed_edge_history', 'parsed_brave_history', "
            "'parsed_firefox_history', 'parsed_browser_history', "
            "'parsed_chrome_downloads', 'parsed_edge_downloads', 'parsed_brave_downloads', "
            "'parsed_firefox_downloads', 'parsed_browser_downloads'"
        )

        if ts_sql:
            tl_dedup = (
                f"NOT EXISTS ("
                f"SELECT 1 FROM master_timeline mt "
                f"WHERE mt.source_table IN ({browser_src_list}) "
                f"AND mt.timestamp_utc IS NOT NULL "
                f"AND ABS(epoch(mt.timestamp_utc) - epoch({ts_sql})) <= 2 "
                f"AND ("
                f"LOWER(TRIM(COALESCE(mt.primary_entity, ''))) = LOWER(TRIM({url_e})) "
                f"OR (LENGTH(TRIM({url_e})) > 4 AND POSITION(LOWER(TRIM({url_e})) IN LOWER(COALESCE(mt.summary, ''))) > 0)"
                f")"
                f")"
            )
            self._emit_tl(
                t,
                ts_sql,
                "Hindsight Web Activity",
                ".A..",
                "WEB RELATED",
                "Hindsight Deep Browser Analysis",
                url_e,
                atype_e,
                f"{atype_e} || ': ' || {url_e} || CASE WHEN {title_e} != '' THEN ' (' || {title_e} || ')' ELSE '' END",
                rid,
                src_e,
                tl_dedup,
            )

        ts_clean = ts_sql if ts_sql else "CAST(NULL AS TIMESTAMP)"
        if has_url_col:
            url_ent_dedup = (
                f"{url_e} ILIKE 'http%' AND NOT EXISTS ("
                f"SELECT 1 FROM entity_connections ec "
                f"WHERE ec.source_table IN ({browser_src_list}) "
                f"AND ec.entity_type = 'URL' "
                f"AND LOWER(TRIM(COALESCE(ec.entity_value, ''))) = LOWER(TRIM({url_e}))"
                f")"
            )
            dom_val_e = f"LOWER(TRIM(regexp_extract({url_e}, '^(?:https?://)?([^/:]+)', 1)))"
            dom_ent_dedup = (
                f"{url_e} ILIKE 'http%' AND NOT EXISTS ("
                f"SELECT 1 FROM entity_connections ec "
                f"WHERE ec.source_table IN ({browser_src_list}) "
                f"AND ec.entity_type = 'DOMAIN' "
                f"AND LOWER(TRIM(COALESCE(ec.entity_value, ''))) = {dom_val_e} "
                f"AND (({ts_clean}) IS NULL OR ec.timestamp_utc IS NULL OR ABS(epoch(ec.timestamp_utc) - epoch({ts_clean})) <= 2)"
                f")"
            )
            self._emit_ent(t, "URL", f"TRIM({url_e})", "WEB RELATED", "Hindsight Deep Browser Analysis", rid, f"'Hindsight URL (' || {atype_e} || ')'", ts_clean, url_ent_dedup)
            self._emit_ent(t, "DOMAIN", dom_val_e, "WEB RELATED", "Hindsight Deep Browser Analysis", rid, "'Hindsight visited domain'", ts_clean, dom_ent_dedup)
        return self._finish_counts(t)

    def _normalize_vfs_shadow_copies(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "vfs_shadow_copies"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        ts_e = self._coalesce_ts_sql(cols, "creation_time", "creation_time_utc")
        id_e = self._coalesce_str_sql(
            cols, "store_id", "vss_id", "shadow_copy_guid", "vss_index", "store_index", default_sql="'VSS Snapshot'"
        )
        mach_e = self._coalesce_str_sql(cols, "machine_name", "originating_machine", default_sql="''")
        if ts_e:
            self._emit_tl(t, ts_e, "VSS Snapshot Created", "...B", "OPERATING SYSTEM", "Volume Shadow Copies (VSS)", id_e, mach_e, f"'Volume Shadow Copy created: ' || {id_e}", rid, "'Volume Shadow Copy'")
        return self._finish_counts(t)

    def _normalize_parsed_carved_files(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_carved_files"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        has_fn_or_id = any(k in cols for k in ("file_name", "carve_id"))
        has_fp = any(k in cols for k in ("carved_path", "carved_rel_path", "file_path"))
        sha_c = self._pick_col(cols, "sha256")
        ts_sql = self._coalesce_ts_sql(cols, "timestamp_utc")  # NEVER use carved_at tool run time!
        fn_e = self._coalesce_str_sql(cols, "file_name", "carve_id", default_sql="'carved_file'")
        fp_raw_e = self._coalesce_str_sql(cols, "carved_path", "carved_rel_path", "file_path")
        fp_e = f"COALESCE({self._clean_path_sql(fp_raw_e)}, '{t}')" if has_fp else f"'{t}'"
        if ts_sql:
            self._emit_tl(t, ts_sql, "Carved File Timestamp", "...B", "OPERATING SYSTEM", "Carved Unallocated Files", fn_e, fp_e, f"'Carved file: ' || {fn_e}", rid, fp_e)
        ts_clean = ts_sql if ts_sql else "CAST(NULL AS TIMESTAMP)"
        if has_fn_or_id:
            self._emit_ent(t, "FILE_NAME", f"UPPER(TRIM({fn_e}))", "OPERATING SYSTEM", "Carved Unallocated Files", rid, "'Carved unallocated file'", ts_clean)
        if sha_c:
            self._emit_ent(t, "SHA256", f'LOWER(TRIM(CAST("{sha_c}" AS VARCHAR)))', "OPERATING SYSTEM", "Carved Unallocated Files", rid, f"'Carved file SHA256 (' || {fn_e} || ')'", ts_clean)
        if has_fp:
            self._emit_ent(t, "FILE_PATH", self._clean_path_sql(fp_raw_e), "OPERATING SYSTEM", "Carved Unallocated Files", rid, "'Carved file output path'", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_bulk_extractor_features(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_bulk_extractor_features"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        ft_c = self._pick_col(cols, "feature_type", "scanner")
        fv_c = self._pick_col(cols, "feature_value", "feature")
        ts_c = self._pick_col(cols, "timestamp_utc")
        src_c = self._pick_col(cols, "source_file", "forensic_path")
        if not fv_c:
            return (0, 0)
        fv_e = f'TRIM(CAST("{fv_c}" AS VARCHAR))'
        ft_e = f'LOWER(COALESCE(CAST("{ft_c}" AS VARCHAR), \'\'))' if ft_c else "''"
        src_e = f'COALESCE(CAST("{src_c}" AS VARCHAR), \'{t}\')' if src_c else f"'{t}'"
        if ts_c:
            self._emit_tl(t, f'"{ts_c}"', "Bulk Extractor Feature", "....", "REFINED RESULTS", "Bulk Extractor Features", fv_e, ft_e, f"'Bulk Extractor (' || {ft_e} || '): ' || {fv_e}", rid, src_e)
        ts_clean = self._clean_ts_expr(f'"{ts_c}"') if ts_c else "CAST(NULL AS TIMESTAMP)"
        self._emit_ent(t, "EMAIL_ADDRESS", f"LOWER({fv_e})", "REFINED RESULTS", "Bulk Extractor Features", rid, "'Bulk Extractor carved email'", ts_clean, f"{ft_e} LIKE '%email%' AND {fv_e} LIKE '%@%'")
        self._emit_ent(t, "URL", fv_e, "REFINED RESULTS", "Bulk Extractor Features", rid, "'Bulk Extractor carved URL'", ts_clean, f"{ft_e} LIKE '%url%' AND {fv_e} ILIKE 'http%'")
        self._emit_ent(t, "DOMAIN", f"LOWER(COALESCE(NULLIF(regexp_extract({fv_e}, '^(?:https?://)?([^/:]+)', 1), ''), {fv_e}))", "REFINED RESULTS", "Bulk Extractor Features", rid, "'Bulk Extractor carved domain'", ts_clean, f"({ft_e} IN ('domain', 'httplogs', 'dns') OR ({ft_e} LIKE '%url%' AND {fv_e} ILIKE 'http%'))")
        self._emit_ent(t, "IP_ADDRESS", fv_e, "REFINED RESULTS", "Bulk Extractor Features", rid, "'Bulk Extractor carved IP'", ts_clean, f"{ft_e} IN ('ip', 'net', 'pcap') AND regexp_matches({fv_e}, '^[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}$')")
        self._emit_ent(t, "EXECUTABLE", f"UPPER({fv_e})", "REFINED RESULTS", "Bulk Extractor Features", rid, "'Bulk Extractor carved PE/executable'", ts_clean, f"{ft_e} IN ('winpe', 'elf', 'executable')")
        return self._finish_counts(t)

    def _normalize_browser_session(self, cols: Dict[str, str], table_name: str) -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        ts_sql = self._coalesce_ts_sql(
            cols,
            "last_active_utc",
            "last_active_time",
            "timestamp_utc",
            "navigation_time",
            "last_visit_time",
        )
        url_c = self._pick_col(cols, "url")
        title_e = self._coalesce_str_sql(cols, "title", default_sql="''")
        src_raw_e = self._coalesce_str_sql(cols, "source_file", "source_path", "profile_path", "profile")
        bname = "Chrome" if "chrome" in table_name else ("Edge" if "edge" in table_name else "Brave")
        url_e = f'COALESCE(CAST("{url_c}" AS VARCHAR), \'\')' if url_c else "''"
        src_e = f"COALESCE({self._clean_path_sql(src_raw_e)}, '{table_name}')" if src_raw_e != "NULL" else f"'{table_name}'"
        if ts_sql and url_c:
            self._emit_tl(table_name, ts_sql, f"{bname} Session Tab Active", ".A..", "WEB RELATED", f"{bname} Sessions & Open Tabs", url_e, title_e, f"'{bname} open tab: ' || {url_e} || CASE WHEN {title_e} != '' THEN ' (' || {title_e} || ')' ELSE '' END", rid, src_e, f"length(trim({url_e})) > 0")
        ts_clean = ts_sql if ts_sql else "CAST(NULL AS TIMESTAMP)"
        if url_c:
            self._emit_ent(table_name, "URL", f"TRIM({url_e})", "WEB RELATED", f"{bname} Sessions & Open Tabs", rid, f"'{bname} session tab URL'", ts_clean)
            self._emit_ent(table_name, "DOMAIN", f"LOWER(TRIM(regexp_extract({url_e}, '^(?:https?://)?([^/:]+)', 1)))", "WEB RELATED", f"{bname} Sessions & Open Tabs", rid, f"'{bname} session tab domain'", ts_clean, f"{url_e} ILIKE 'http%'")
        return self._finish_counts(table_name)

    def _normalize_parsed_text_documents(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_text_documents"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        fn_c = self._pick_col(cols, "file_name")
        fp_c = self._pick_col(cols, "file_path", "source_file")
        ct_c = self._pick_col(cols, "created_time")
        mt_c = self._pick_col(cols, "modified_time")
        sha_c = self._pick_col(cols, "sha256")
        prev_c = self._pick_col(cols, "text_preview", "content_preview")
        if not fn_c:
            return (0, 0)
        fn_e = f'CAST("{fn_c}" AS VARCHAR)'
        fp_e = self._clean_path_sql(f'"{fp_c}"') if fp_c else f"'{t}'"
        prev_e = f'SUBSTR(COALESCE(CAST("{prev_c}" AS VARCHAR), \'\'), 1, 80)' if prev_c else "''"

        # Deduplicate against parsed_documents_metadata so .txt/.csv/.rtf indexed in both emit 1x events
        doc_dedup = "1=1"
        if self._table_exists("parsed_documents_metadata"):
            dm_cols = self._get_columns("parsed_documents_metadata")
            dm_fp = dm_cols.get("file_path") or dm_cols.get("source_file")
            dm_fn = dm_cols.get("file_name")
            dm_sha = dm_cols.get("sha256")
            or_conds: List[str] = []
            if fp_c and dm_fp:
                dm_fp_clean = self._clean_path_sql(f'_dm."{dm_fp}"')
                ptd_fp_clean = self._clean_path_sql(f'"{t}"."{fp_c}"')
                or_conds.append(
                    f"(LOWER(TRIM(COALESCE({dm_fp_clean}, ''))) = LOWER(TRIM(COALESCE({ptd_fp_clean}, ''))) "
                    f"AND TRIM(COALESCE({ptd_fp_clean}, '')) != '')"
                )
            if dm_fn and sha_c and dm_sha:
                or_conds.append(
                    f"(LOWER(TRIM(COALESCE(CAST(_dm.\"{dm_fn}\" AS VARCHAR), ''))) = LOWER(TRIM(CAST(\"{t}\".\"{fn_c}\" AS VARCHAR))) "
                    f"AND LOWER(TRIM(COALESCE(CAST(_dm.\"{dm_sha}\" AS VARCHAR), ''))) = LOWER(TRIM(COALESCE(CAST(\"{t}\".\"{sha_c}\" AS VARCHAR), ''))) "
                    f"AND TRIM(COALESCE(CAST(\"{t}\".\"{sha_c}\" AS VARCHAR), '')) != '')"
                )
            if or_conds:
                doc_dedup = f"NOT EXISTS (SELECT 1 FROM parsed_documents_metadata _dm WHERE {' OR '.join(or_conds)})"

        mt_ref = f'"{mt_c}"' if mt_c else None
        ct_safe = self._non_wallclock_ctime_sql(f'"{ct_c}"', mt_ref) if ct_c else None
        mt_clean = self._clean_ts_expr(f'"{mt_c}"') if mt_c else "CAST(NULL AS TIMESTAMP)"
        ct_clean = ct_safe if ct_safe else "CAST(NULL AS TIMESTAMP)"

        if ct_safe:
            self._emit_tl(t, ct_safe, "Text Document Created", "...B", "DOCUMENTS", "Plain Text & Configuration Files", fn_e, fp_e, f"'Text file created: ' || {fn_e} || CASE WHEN {prev_e} != '' THEN ' | ' || {prev_e} ELSE '' END", rid, fp_e, doc_dedup)
        if mt_c:
            extra = (
                f"(({ct_clean}) IS NULL OR ({mt_clean}) != ({ct_clean})) AND ({doc_dedup})"
                if ct_safe
                else doc_dedup
            )
            self._emit_tl(t, mt_clean, "Text Document Modified", "M...", "DOCUMENTS", "Plain Text & Configuration Files", fn_e, fp_e, f"'Text file modified: ' || {fn_e}", rid, fp_e, extra)
        ts_clean = f"COALESCE({mt_clean}, {ct_clean})"
        self._emit_ent(t, "FILE_NAME", f"UPPER(TRIM({fn_e}))", "DOCUMENTS", "Plain Text & Configuration Files", rid, "'Plain text/config file'", ts_clean, doc_dedup)
        if fp_c:
            self._emit_ent(t, "FILE_PATH", fp_e, "DOCUMENTS", "Plain Text & Configuration Files", rid, "'Plain text/config path'", ts_clean, doc_dedup)
        if sha_c:
            self._emit_ent(t, "SHA256", f'LOWER(TRIM(CAST("{sha_c}" AS VARCHAR)))', "DOCUMENTS", "Plain Text & Configuration Files", rid, f"'SHA256 of ' || {fn_e}", ts_clean, doc_dedup)
        return self._finish_counts(t)

    def _normalize_artifact_stinger_hits(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "artifact_stinger_hits"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        fn_c = self._pick_col(cols, "file_name")
        fp_c = self._pick_col(cols, "file_path")
        sha_c = self._pick_col(cols, "sha256")
        mal_c = self._pick_col(cols, "malware_name", "detection_type")
        mal_e = f'COALESCE(CAST("{mal_c}" AS VARCHAR), \'Threat Detection\')' if mal_c else "'Threat Detection'"
        # 0 timeline rows (scanned_at is examiner run time, not historical evidence event)
        if fn_c:
            self._emit_ent(t, "EXECUTABLE", f'UPPER(TRIM(CAST("{fn_c}" AS VARCHAR)))', "MALWARE & YARA", "Trellix Stinger & PE Threat Hits", rid, f"'Threat hit: ' || {mal_e}")
        if sha_c:
            self._emit_ent(t, "SHA256", f'LOWER(TRIM(CAST("{sha_c}" AS VARCHAR)))', "MALWARE & YARA", "Trellix Stinger & PE Threat Hits", rid, f"'Threat SHA256 (' || {mal_e} || ')'")
        if fp_c:
            self._emit_ent(t, "FILE_PATH", self._clean_path_sql(f'"{fp_c}"'), "MALWARE & YARA", "Trellix Stinger & PE Threat Hits", rid, f"'Threat path (' || {mal_e} || ')'")
        return self._finish_counts(t)

    def _normalize_parsed_user_accounts(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_user_accounts"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        u_c = self._pick_col(cols, "username", "full_name")
        if not u_c:
            return (0, 0)
        sid_c = self._pick_col(cols, "user_sid", "sid")
        src_c = self._pick_col(cols, "hive_path", "source_file")
        u_e = f'TRIM(CAST("{u_c}" AS VARCHAR))'
        sid_e = f'COALESCE(CAST("{sid_c}" AS VARCHAR), \'\')' if sid_c else "''"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'SAM'"
        for ts_names, lbl, macb in [
            (("account_created_utc", "created_utc"), "User Account Created", "...B"),
            (("last_login_utc", "last_logon_utc"), "User Account Last Login", ".A.."),
            (("last_password_change_utc", "password_reset_utc"), "User Password Changed", "M..."),
            (("last_failed_login_utc",), "User Failed Login", ".A.."),
        ]:
            avail = [cols[k] for k in ts_names if k in cols]
            if avail:
                ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in avail]) + ")"
                self._emit_tl(t, ts_e, lbl, macb, "OPERATING SYSTEM", "Windows User Accounts", u_e, sid_e, f"'{lbl}: ' || {u_e} || CASE WHEN {sid_e} != '' THEN ' (' || {sid_e} || ')' ELSE '' END", rid, src_e)
        ref_c = self._pick_col(cols, "last_login_utc", "last_logon_utc", "account_created_utc", "created_utc")
        ts_clean = self._clean_ts_expr(f'"{ref_c}"') if ref_c else "CAST(NULL AS TIMESTAMP)"
        self._emit_ent(t, "USER_ACCOUNT", u_e, "OPERATING SYSTEM", "Windows User Accounts", rid, "'SAM/Registry local user account'", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_windows_services(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_windows_services"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        sn_c = self._pick_col(cols, "service_name", "display_name")
        img_c = self._pick_col(cols, "image_path", "service_dll")
        acct_c = self._pick_col(cols, "object_name", "account_name")
        ts_cols = [cols[k] for k in ("last_modified_utc", "last_write_utc") if k in cols]
        src_c = self._pick_col(cols, "hive_path", "source_file")
        sn_e = f'COALESCE(CAST("{sn_c}" AS VARCHAR), \'Service\')' if sn_c else "'Service'"
        img_e = f'COALESCE(CAST("{img_c}" AS VARCHAR), \'\')' if img_c else "''"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'SYSTEM'"
        ts_clean = "CAST(NULL AS TIMESTAMP)"
        if ts_cols:
            ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in ts_cols]) + ")"
            ts_clean = self._clean_ts_expr(ts_e)
            self._emit_tl(t, ts_e, "Windows Service Registry Modified", "..C.", "OPERATING SYSTEM", "Windows Services", sn_e, img_e, f"'Service ' || {sn_e} || ' -> ' || {img_e}", rid, src_e)
        if img_c:
            self._emit_ent(t, "FILE_PATH", f"TRIM({img_e})", "OPERATING SYSTEM", "Windows Services", rid, f"'Service ImagePath for ' || {sn_e}", ts_clean)
            self._emit_ent(t, "EXECUTABLE", f"UPPER(TRIM(regexp_extract(replace({img_e}, '\"', ''), '([^\\\\/ ]+\\.(?:exe|dll|sys))', 1)))", "OPERATING SYSTEM", "Windows Services", rid, f"'Service binary for ' || {sn_e}", ts_clean, f"regexp_extract(replace({img_e}, '\"', ''), '([^\\\\/ ]+\\.(?:exe|dll|sys))', 1) != ''")
        if acct_c:
            self._emit_ent(t, "USER_ACCOUNT", f'TRIM(CAST("{acct_c}" AS VARCHAR))', "OPERATING SYSTEM", "Windows Services", rid, f"'Service logon account for ' || {sn_e}", ts_clean, f'LOWER(TRIM(CAST("{acct_c}" AS VARCHAR))) NOT IN (\'localsystem\', \'nt authority\\localservice\', \'nt authority\\networkservice\', \'\')')
        return self._finish_counts(t)

    def _normalize_parsed_autoruns(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_autoruns"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        en_c = self._pick_col(cols, "entry_name", "value_name")
        cmd_cols = [cols[k] for k in ("command", "launch_string", "image_path") if k in cols]
        kp_c = self._pick_col(cols, "key_path", "location")
        u_c = self._pick_col(cols, "username")
        ts_cols = [cols[k] for k in ("last_modified_utc", "last_write_utc") if k in cols]
        src_c = self._pick_col(cols, "hive_path", "source_file")
        en_e = f'COALESCE(CAST("{en_c}" AS VARCHAR), \'Autorun\')' if en_c else "'Autorun'"
        cmd_e = ("COALESCE(" + ", ".join([f'NULLIF(TRIM(CAST("{c}" AS VARCHAR)), \'\')' for c in cmd_cols]) + ")") if cmd_cols else "''"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'Registry'"
        ts_clean = "CAST(NULL AS TIMESTAMP)"
        if ts_cols:
            ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in ts_cols]) + ")"
            ts_clean = self._clean_ts_expr(ts_e)
            self._emit_tl(t, ts_e, "Autorun Persistence Modified", "..C.", "OPERATING SYSTEM", "Autorun & Startup Items", en_e, cmd_e, f"'Autorun ' || {en_e} || ': ' || COALESCE({cmd_e}, '')", rid, src_e)
        if cmd_cols:
            self._emit_ent(t, "FILE_PATH", cmd_e, "OPERATING SYSTEM", "Autorun & Startup Items", rid, f"'Autorun command for ' || {en_e}", ts_clean)
            self._emit_ent(t, "EXECUTABLE", f"UPPER(TRIM(regexp_extract(replace({cmd_e}, '\"', ''), '([^\\\\/ ]+\\.(?:exe|dll|bat|ps1|vbs|cmd))', 1)))", "OPERATING SYSTEM", "Autorun & Startup Items", rid, f"'Autorun executable for ' || {en_e}", ts_clean, f"regexp_extract(replace({cmd_e}, '\"', ''), '([^\\\\/ ]+\\.(?:exe|dll|bat|ps1|vbs|cmd))', 1) != ''")
        if kp_c:
            self._emit_ent(t, "REGISTRY_KEY", f'UPPER(TRIM(CAST("{kp_c}" AS VARCHAR)))', "OPERATING SYSTEM", "Autorun & Startup Items", rid, "'Autorun registry key'", ts_clean)
        if u_c:
            self._emit_ent(t, "USER_ACCOUNT", f'TRIM(CAST("{u_c}" AS VARCHAR))', "OPERATING SYSTEM", "Autorun & Startup Items", rid, "'Autorun owner user'", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_userassist(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_userassist"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        prog_c = self._pick_col(cols, "program_path", "rot13_name")
        rc_c = self._pick_col(cols, "run_count")
        u_c = self._pick_col(cols, "username")
        ts_cols = [cols[k] for k in ("last_executed_utc", "last_run_utc") if k in cols]
        src_c = self._pick_col(cols, "hive_path", "source_file")
        if not prog_c:
            return (0, 0)
        prog_e = f'TRIM(CAST("{prog_c}" AS VARCHAR))'
        u_e = f'COALESCE(CAST("{u_c}" AS VARCHAR), \'\')' if u_c else "''"
        rc_e = f'CAST(COALESCE("{rc_c}", 0) AS VARCHAR)' if rc_c else "'0'"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'NTUSER.DAT'"
        ts_clean = "CAST(NULL AS TIMESTAMP)"
        if ts_cols:
            ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in ts_cols]) + ")"
            ts_clean = self._clean_ts_expr(ts_e)
            self._emit_tl(t, ts_e, "UserAssist GUI Program Executed", ".A..", "OPERATING SYSTEM", "UserAssist GUI Execution", prog_e, u_e, f"'UserAssist executed: ' || {prog_e} || ' (RunCount: ' || {rc_e} || ')'", rid, src_e)
        self._emit_ent(t, "FILE_PATH", prog_e, "OPERATING SYSTEM", "UserAssist GUI Execution", rid, "'UserAssist program path'", ts_clean)
        self._emit_ent(t, "EXECUTABLE", f"UPPER(TRIM(regexp_extract({prog_e}, '([^\\\\/]+)$', 1)))", "OPERATING SYSTEM", "UserAssist GUI Execution", rid, "'UserAssist executable'", ts_clean, f"regexp_extract({prog_e}, '([^\\\\/]+)$', 1) != ''")
        if u_c:
            self._emit_ent(t, "USER_ACCOUNT", f'TRIM(CAST("{u_c}" AS VARCHAR))', "OPERATING SYSTEM", "UserAssist GUI Execution", rid, "'UserAssist user'", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_bam_dam(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_bam_dam"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        exe_c = self._pick_col(cols, "executable_path", "app_name")
        u_c = self._pick_col(cols, "username", "user_sid")
        st_c = self._pick_col(cols, "service_type")
        ts_cols = [cols[k] for k in ("last_execution_utc", "execution_time_utc") if k in cols]
        src_c = self._pick_col(cols, "hive_path", "source_file")
        if not exe_c:
            return (0, 0)
        exe_e = f'TRIM(CAST("{exe_c}" AS VARCHAR))'
        u_e = f'COALESCE(CAST("{u_c}" AS VARCHAR), \'\')' if u_c else "''"
        st_e = f'COALESCE(CAST("{st_c}" AS VARCHAR), \'BAM\')' if st_c else "'BAM'"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'SYSTEM'"
        ts_clean = "CAST(NULL AS TIMESTAMP)"
        if ts_cols:
            ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in ts_cols]) + ")"
            ts_clean = self._clean_ts_expr(ts_e)
            self._emit_tl(t, ts_e, "BAM/DAM Executable Run", ".A..", "OPERATING SYSTEM", "BAM / DAM Execution", exe_e, u_e, f"{st_e} || ' execution: ' || {exe_e}", rid, src_e)
        self._emit_ent(t, "FILE_PATH", exe_e, "OPERATING SYSTEM", "BAM / DAM Execution", rid, "'BAM/DAM executable path'", ts_clean)
        self._emit_ent(t, "EXECUTABLE", f"UPPER(TRIM(regexp_extract({exe_e}, '([^\\\\/]+)$', 1)))", "OPERATING SYSTEM", "BAM / DAM Execution", rid, "'BAM/DAM executable'", ts_clean, f"regexp_extract({exe_e}, '([^\\\\/]+)$', 1) != ''")
        if u_c:
            self._emit_ent(t, "USER_ACCOUNT", f'TRIM(CAST("{u_c}" AS VARCHAR))', "OPERATING SYSTEM", "BAM / DAM Execution", rid, "'BAM/DAM SID/user'", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_registry_mru(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_registry_mru"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        tp_cols = [cols[k] for k in ("target_path", "entry_value", "target_name") if k in cols]
        mt_c = self._pick_col(cols, "mru_type", "category")
        kp_c = self._pick_col(cols, "key_path")
        u_c = self._pick_col(cols, "username")
        ts_cols = [cols[k] for k in ("last_modified_utc", "last_write_utc") if k in cols]
        src_c = self._pick_col(cols, "hive_path", "source_file")
        if not tp_cols:
            return (0, 0)
        tp_e = "COALESCE(" + ", ".join([f'NULLIF(TRIM(CAST("{c}" AS VARCHAR)), \'\')' for c in tp_cols]) + ")"
        mt_e = f'COALESCE(CAST("{mt_c}" AS VARCHAR), \'MRU\')' if mt_c else "'MRU'"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'NTUSER.DAT'"
        ts_clean = "CAST(NULL AS TIMESTAMP)"
        if ts_cols:
            ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in ts_cols]) + ")"
            ts_clean = self._clean_ts_expr(ts_e)
            self._emit_tl(t, ts_e, "Registry MRU Accessed", ".A..", "OPERATING SYSTEM", "Registry MRU", tp_e, mt_e, f"{mt_e} || ': ' || {tp_e}", rid, src_e, f"{tp_e} IS NOT NULL")
        self._emit_ent(t, "FILE_PATH", tp_e, "OPERATING SYSTEM", "Registry MRU", rid, f"'MRU item (' || {mt_e} || ')'", ts_clean)
        if kp_c:
            self._emit_ent(t, "REGISTRY_KEY", f'UPPER(TRIM(CAST("{kp_c}" AS VARCHAR)))', "OPERATING SYSTEM", "Registry MRU", rid, "'MRU registry key'", ts_clean)
        if u_c:
            self._emit_ent(t, "USER_ACCOUNT", f'TRIM(CAST("{u_c}" AS VARCHAR))', "OPERATING SYSTEM", "Registry MRU", rid, "'MRU user'", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_network_profiles(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_network_profiles"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        pn_c = self._pick_col(cols, "profile_name", "ssid", "description")
        dns_c = self._pick_col(cols, "dns_suffix")
        ip_c = self._pick_col(cols, "ip_address", "dhcp_server")
        src_c = self._pick_col(cols, "hive_path", "source_file")
        pn_e = f'COALESCE(CAST("{pn_c}" AS VARCHAR), \'Network Profile\')' if pn_c else "'Network Profile'"
        dns_e = f'COALESCE(CAST("{dns_c}" AS VARCHAR), \'\')' if dns_c else "''"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'SOFTWARE'"
        c_cols = [cols[k] for k in ("date_created_utc", "first_connected_utc") if k in cols]
        l_cols = [cols[k] for k in ("date_last_connected_utc", "last_connected_utc") if k in cols]
        if c_cols:
            ce = "COALESCE(" + ", ".join([f'"{c}"' for c in c_cols]) + ")"
            self._emit_tl(t, ce, "Network Profile First Connected", "...B", "OPERATING SYSTEM", "Windows Network Profiles", pn_e, dns_e, f"'Network first connected: ' || {pn_e}", rid, src_e)
        if l_cols:
            le = "COALESCE(" + ", ".join([f'"{c}"' for c in l_cols]) + ")"
            self._emit_tl(t, le, "Network Profile Last Connected", ".A..", "OPERATING SYSTEM", "Windows Network Profiles", pn_e, dns_e, f"'Network last connected: ' || {pn_e}", rid, src_e)
        ref_c = (l_cols or c_cols or [None])[0]
        ts_clean = self._clean_ts_expr(f'"{ref_c}"') if ref_c else "CAST(NULL AS TIMESTAMP)"
        if dns_c:
            self._emit_ent(t, "DOMAIN", f'LOWER(TRIM(CAST("{dns_c}" AS VARCHAR)))', "OPERATING SYSTEM", "Windows Network Profiles", rid, f"'Network DNS suffix for ' || {pn_e}", ts_clean)
        if ip_c:
            self._emit_ent(t, "IP_ADDRESS", f'TRIM(CAST("{ip_c}" AS VARCHAR))', "OPERATING SYSTEM", "Windows Network Profiles", rid, f"'Network IP/DHCP for ' || {pn_e}", ts_clean)
        return self._finish_counts(t)

    def _normalize_parsed_wer_reports(self, cols: Dict[str, str]) -> Tuple[int, int]:
        t = "parsed_wer_reports"
        self._clear_table_normalizations(t)
        rid = f'COALESCE("{cols["_row_id"]}", rowid, 0)' if "_row_id" in cols else "COALESCE(rowid, 0)"
        app_c = self._pick_col(cols, "app_name", "fault_module_name")
        ap_c = self._pick_col(cols, "app_path")
        exc_c = self._pick_col(cols, "exception_code", "event_type")
        u_c = self._pick_col(cols, "username")
        ts_cols = [cols[k] for k in ("report_timestamp_utc", "report_time_utc") if k in cols]
        src_c = self._pick_col(cols, "source_file")
        app_e = f'COALESCE(CAST("{app_c}" AS VARCHAR), \'Application Crash\')' if app_c else "'Application Crash'"
        exc_e = f'COALESCE(CAST("{exc_c}" AS VARCHAR), \'\')' if exc_c else "''"
        src_e = self._clean_path_sql(f'"{src_c}"') if src_c else "'Report.wer'"
        ts_clean = "CAST(NULL AS TIMESTAMP)"
        if ts_cols:
            ts_e = "COALESCE(" + ", ".join([f'"{c}"' for c in ts_cols]) + ")"
            ts_clean = self._clean_ts_expr(ts_e)
            self._emit_tl(t, ts_e, "Windows Error Report (Crash)", "...B", "OPERATING SYSTEM", "Windows Error Reporting (WER)", app_e, exc_e, f"'WER Crash: ' || {app_e} || CASE WHEN {exc_e} != '' THEN ' (' || {exc_e} || ')' ELSE '' END", rid, src_e)
        if app_c:
            self._emit_ent(t, "EXECUTABLE", f"UPPER({app_e})", "OPERATING SYSTEM", "Windows Error Reporting (WER)", rid, "'Faulting application in WER'", ts_clean)
        if ap_c:
            self._emit_ent(t, "FILE_PATH", f'TRIM(CAST("{ap_c}" AS VARCHAR))', "OPERATING SYSTEM", "Windows Error Reporting (WER)", rid, "'Faulting application path in WER'", ts_clean)
        if u_c:
            self._emit_ent(t, "USER_ACCOUNT", f'TRIM(CAST("{u_c}" AS VARCHAR))', "OPERATING SYSTEM", "Windows Error Reporting (WER)", rid, "'WER user'", ts_clean)
        return self._finish_counts(t)

    # -------------------------------------------------------------------------
    # Public Execution & Normalization Orchestrator
    # -------------------------------------------------------------------------
    def normalize_table(self, table_name: str, _bulk_mode: bool = False) -> Tuple[int, int]:
        """
        Normalize a single populated table by discovering its columns via DESCRIBE
        and executing its dedicated SQL mapping under the per-case RLock. Returns (timeline_rows, entity_rows).
        """
        with DuckDBManager.get_lock(self.case_id):
            if not _bulk_mode and not self._table_exists(table_name):
                return (0, 0)

            cols = self._get_columns(table_name)
            start_time = time.time()

            handlers = {
                "raw_evtx": self._normalize_raw_evtx,
                "raw_lecmd": lambda c: self._normalize_raw_lecmd_generic("raw_lecmd", "LNK Shortcut Files", c),
                "raw_pecmd": self._normalize_raw_pecmd,
                "raw_mft": self._normalize_raw_mft,
                "vfs_files": self._normalize_vfs_files,
                "vfs_shadow_copies": self._normalize_vfs_shadow_copies,
                "raw_amcache_files": self._normalize_raw_amcache_files,
                "raw_shimcache": self._normalize_raw_shimcache,
                "raw_jlecmd_auto": lambda c: self._normalize_raw_lecmd_generic("raw_jlecmd_auto", "Automatic Jump Lists", c),
                "raw_jlecmd_custom": lambda c: self._normalize_raw_lecmd_generic("raw_jlecmd_custom", "Custom Jump Lists", c),
                "raw_recmd": self._normalize_raw_recmd,
                "raw_srum_app": lambda c: self._normalize_raw_srum_generic("raw_srum_app", "SRUM App Usage", c, is_network=False),
                "raw_srum_net": lambda c: self._normalize_raw_srum_generic("raw_srum_net", "SRUM Network Usage", c, is_network=True),
                "raw_shellbags": self._normalize_raw_shellbags,
                "raw_usnjrnl": self._normalize_raw_usnjrnl,
                "raw_wxt_activity": self._normalize_raw_wxt_activity,
                "raw_hindsight": self._normalize_raw_hindsight,
                "parsed_carved_files": self._normalize_parsed_carved_files,
                "parsed_bulk_extractor_features": self._normalize_parsed_bulk_extractor_features,
                "parsed_chrome_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_chrome_history"),
                "parsed_edge_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_edge_history"),
                "parsed_brave_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_brave_history"),
                "parsed_firefox_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_firefox_history"),
                "parsed_browser_history": self._normalize_parsed_browser_history,
                "parsed_chrome_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_chrome_downloads"),
                "parsed_edge_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_edge_downloads"),
                "parsed_brave_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_brave_downloads"),
                "parsed_firefox_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_firefox_downloads"),
                "parsed_browser_downloads": self._normalize_parsed_browser_downloads,
                "parsed_chrome_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_chrome_logins"),
                "parsed_edge_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_edge_logins"),
                "parsed_brave_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_brave_logins"),
                "parsed_firefox_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_firefox_logins"),
                "parsed_browser_logins": self._normalize_parsed_browser_logins,
                "parsed_chrome_session": lambda c: self._normalize_browser_session(c, "parsed_chrome_session"),
                "parsed_edge_session": lambda c: self._normalize_browser_session(c, "parsed_edge_session"),
                "parsed_brave_session": lambda c: self._normalize_browser_session(c, "parsed_brave_session"),
                "parsed_chat_messages": self._normalize_parsed_chat_messages,
                "parsed_cloud_files": self._normalize_parsed_cloud_files,
                "parsed_usb_devices": self._normalize_parsed_usb_devices,
                "artifact_yara_hits": self._normalize_artifact_yara_hits,
                "artifact_stinger_hits": self._normalize_artifact_stinger_hits,
                "media_ocr_results": self._normalize_media_ocr_results,
                "artifact_ocr_results": self._normalize_artifact_ocr_results,
                "raw_rbcmd": self._normalize_raw_rbcmd,
                "raw_recentfilecache": self._normalize_raw_recentfilecache,
                "parsed_scheduled_tasks": self._normalize_parsed_scheduled_tasks,
                "parsed_powershell_history": self._normalize_parsed_powershell_history,
                "parsed_rmm_sessions": self._normalize_parsed_rmm_sessions,
                "parsed_wpn_notifications": self._normalize_parsed_wpn_notifications,
                "parsed_notifications": self._normalize_parsed_notifications,
                "parsed_media_exif": self._normalize_parsed_media_exif,
                "parsed_thumbcache": self._normalize_parsed_thumbcache,
                "parsed_documents_metadata": self._normalize_parsed_documents_metadata,
                "parsed_text_documents": self._normalize_parsed_text_documents,
                "parsed_emails": self._normalize_parsed_emails,
                "parsed_outlook_emails": lambda c: self._normalize_parsed_emails(c, "parsed_outlook_emails"),
                "parsed_mbox_emails": lambda c: self._normalize_parsed_emails(c, "parsed_mbox_emails"),
                "parsed_winmail_messages": lambda c: self._normalize_parsed_emails(c, "parsed_winmail_messages"),
                "parsed_user_accounts": self._normalize_parsed_user_accounts,
                "parsed_windows_services": self._normalize_parsed_windows_services,
                "parsed_autoruns": self._normalize_parsed_autoruns,
                "parsed_userassist": self._normalize_parsed_userassist,
                "parsed_bam_dam": self._normalize_parsed_bam_dam,
                "parsed_registry_mru": self._normalize_parsed_registry_mru,
                "parsed_network_profiles": self._normalize_parsed_network_profiles,
                "parsed_wer_reports": self._normalize_parsed_wer_reports,
            }

            handler = handlers.get(table_name)
            if not handler:
                if table_name.startswith("raw_srum_"):
                    handler = lambda c: self._normalize_raw_srum_generic(
                        table_name,
                        f"SRUM ({table_name.replace('raw_srum_', '')})",
                        c,
                        is_network=("net" in table_name or "network" in table_name),
                    )
                elif table_name.startswith("raw_sqlecmd_") or table_name.startswith("parsed_sqlite_"):
                    handler = lambda c: self._normalize_generic_sqlite_table(table_name, c)
                else:
                    return (0, 0)

            try:
                cur = self.conn.cursor()
                if _bulk_mode:
                    cur.execute("BEGIN TRANSACTION;")
                    try:
                        t_count, e_count = handler(cols)
                        cur.execute("COMMIT;")
                    except Exception:
                        try:
                            cur.execute("ROLLBACK;")
                        except Exception:
                            pass
                        raise
                    return (int(t_count or 0), int(e_count or 0))

                t_count, e_count = handler(cols)
                cur.execute(
                    """
                    DELETE FROM master_timeline
                    WHERE source_table = ?
                      AND (timestamp_utc IS NULL
                           OR timestamp_utc <= TIMESTAMP '1970-01-02 00:00:00'
                           OR timestamp_utc >= TIMESTAMP '2100-01-01 00:00:00');
                    """,
                    [table_name],
                )
                cur.execute(
                    """
                    UPDATE entity_connections
                    SET timestamp_utc = NULL
                    WHERE source_table = ?
                      AND timestamp_utc IS NOT NULL
                      AND (timestamp_utc <= TIMESTAMP '1970-01-02 00:00:00'
                           OR timestamp_utc >= TIMESTAMP '2100-01-01 00:00:00');
                    """,
                    [table_name],
                )
                t_count = cur.execute(
                    "SELECT COUNT(*) FROM master_timeline WHERE source_table = ?;",
                    [table_name],
                ).fetchone()[0]
                e_count = cur.execute(
                    "SELECT COUNT(*) FROM entity_connections WHERE source_table = ?;",
                    [table_name],
                ).fetchone()[0]
                duration_ms = int((time.time() - start_time) * 1000)

                log_processing_event(
                    case_id=self.case_id,
                    module_name=f"Normalizer:{table_name}",
                    command_executed=f"SQL Introspection & Normalization for {table_name}",
                    exit_code=0,
                    rows_ingested=t_count + e_count,
                    duration_ms=duration_ms,
                    status="SUCCESS",
                )
                return (t_count, e_count)

            except Exception as exc:
                duration_ms = int((time.time() - start_time) * 1000)
                err_msg = f"Failed normalizing '{table_name}': {exc}"
                print(f"[Normalizer] ERROR: {err_msg}")
                if not _bulk_mode:
                    log_processing_event(
                        case_id=self.case_id,
                        module_name=f"Normalizer:{table_name}",
                        command_executed=f"SQL Introspection & Normalization for {table_name}",
                        exit_code=1,
                        rows_ingested=0,
                        duration_ms=duration_ms,
                        status="ERROR",
                        error_message=err_msg,
                    )
                raise

    def _create_refined_views(self, cursor: Any) -> None:
        """
        Create and register WFT 'Refined Results' views defensively from entity_connections
        and existing tables without ever clobbering view_keyword_hits or deleting registry rows.
        """
        tbls = {
            t[0]
            for t in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "entity_connections" not in tbls:
            return

        cursor.execute("""
            CREATE OR REPLACE VIEW view_refined_domains AS
            SELECT
                row_number() OVER (ORDER BY COUNT(*) DESC, domain ASC) AS _row_id,
                domain,
                domain AS domain_or_url,
                domain AS indicator,
                entity_type,
                COUNT(*) AS event_count,
                COUNT(*) AS total_occurrences,
                COUNT(*) AS occurrence_count,
                COUNT(DISTINCT source_artifact) AS distinct_artifacts_count,
                MIN(timestamp_utc) AS first_seen,
                MIN(timestamp_utc) AS first_observed_utc,
                MIN(timestamp_utc) AS first_seen_utc,
                MAX(timestamp_utc) AS last_seen,
                MAX(timestamp_utc) AS last_observed_utc,
                MAX(timestamp_utc) AS last_seen_utc,
                string_agg(DISTINCT source_artifact, ', ') AS observed_in_artifacts,
                string_agg(DISTINCT source_artifact, ', ') AS sources
            FROM (
                SELECT
                    CASE
                        WHEN UPPER(entity_type) = 'URL' THEN COALESCE(NULLIF(LOWER(regexp_extract(entity_value, '^(?:https?://)?([^/:]+)', 1)), ''), LOWER(entity_value))
                        ELSE LOWER(TRIM(entity_value))
                    END AS domain,
                    UPPER(entity_type) AS entity_type,
                    COALESCE(artifact_name, source_table) AS source_artifact,
                    timestamp_utc
                FROM entity_connections
                WHERE UPPER(entity_type) IN ('DOMAIN', 'URL', 'IP_ADDRESS')
                  AND entity_value IS NOT NULL AND length(trim(entity_value)) > 0
            ) d_sub
            WHERE domain IS NOT NULL AND length(trim(domain)) > 0
            GROUP BY domain, entity_type
            ORDER BY event_count DESC, domain ASC;
        """)
        dom_cnt = cursor.execute("SELECT COUNT(*) FROM view_refined_domains;").fetchone()[0]
        cursor.execute(
            """
            INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
            VALUES ('refined_domains', 'REFINED RESULTS', 'Extracted URLs & Domains', 'view_refined_domains', 'RefinedResults', ?, now())
            ON CONFLICT (artifact_id) DO UPDATE SET
                category = 'REFINED RESULTS',
                table_name = 'view_refined_domains',
                row_count = EXCLUDED.row_count,
                last_updated = now();
            """,
            [dom_cnt],
        )

        # Preserve unified view_keyword_hits over parsed_keyword_hits (NEVER overwrite with case_keywords!)
        if "parsed_keyword_hits" in tbls:
            try:
                cursor.execute("CREATE OR REPLACE VIEW view_keyword_hits AS SELECT * FROM parsed_keyword_hits ORDER BY _row_id ASC;")
                cursor.execute("CREATE OR REPLACE VIEW keyword_hits AS SELECT * FROM view_keyword_hits;")
                kw_cnt = cursor.execute("SELECT COUNT(*) FROM parsed_keyword_hits;").fetchone()[0] or 0
                cursor.execute(
                    """
                    INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                    VALUES ('keyword_hits', 'REFINED RESULTS', 'Keyword Hits', 'view_keyword_hits', 'KeywordScanner', ?, now())
                    ON CONFLICT (artifact_id) DO UPDATE SET
                        category = 'REFINED RESULTS',
                        display_name = 'Keyword Hits',
                        table_name = 'view_keyword_hits',
                        row_count = EXCLUDED.row_count,
                        last_updated = now();
                    """,
                    [kw_cnt],
                )
            except Exception as kw_ex:
                print(f"[Normalizer] Notice on view_keyword_hits: {kw_ex}")

        user_branches = ["""
            SELECT
                TRIM(entity_value) AS user_identifier,
                UPPER(entity_type) AS entity_type,
                COALESCE(artifact_name, source_table) AS source_artifact,
                timestamp_utc
            FROM entity_connections
            WHERE UPPER(entity_type) IN ('USER_ACCOUNT', 'EMAIL_ADDRESS')
              AND entity_value IS NOT NULL
              AND TRIM(entity_value) NOT IN ('', '-', 'N/A', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')
        """]
        if "parsed_user_accounts" in tbls:
            ua_cols = self._get_columns("parsed_user_accounts")
            if "username" in ua_cols:
                ts_ua = ua_cols.get("last_login_utc") or ua_cols.get("last_logon_utc") or ua_cols.get("account_created_utc")
                ts_ua_expr = self._clean_ts_expr(f'"{ts_ua}"') if ts_ua else "CAST(NULL AS TIMESTAMP)"
                user_branches.append(f"""
                    SELECT
                        TRIM(CAST("{ua_cols['username']}" AS VARCHAR)) AS user_identifier,
                        'USER_ACCOUNT' AS entity_type,
                        'Windows User Accounts (SAM)' AS source_artifact,
                        {ts_ua_expr} AS timestamp_utc
                    FROM parsed_user_accounts
                    WHERE "{ua_cols['username']}" IS NOT NULL AND TRIM(CAST("{ua_cols['username']}" AS VARCHAR)) != ''
                """)

        cursor.execute(f"""
            CREATE OR REPLACE VIEW view_refined_users AS
            SELECT
                row_number() OVER (ORDER BY COUNT(*) DESC, user_identifier ASC) AS _row_id,
                user_identifier,
                user_identifier AS username,
                entity_type,
                string_agg(DISTINCT source_artifact, ', ') AS source_artifact,
                COUNT(*) AS total_occurrences,
                COUNT(*) AS occurrence_count,
                MIN(timestamp_utc) AS first_observed_utc,
                MIN(timestamp_utc) AS first_seen_utc,
                MAX(timestamp_utc) AS last_observed_utc,
                MAX(timestamp_utc) AS last_seen_utc,
                string_agg(DISTINCT source_artifact, ', ') AS observed_in_artifacts,
                string_agg(DISTINCT source_artifact, ', ') AS sources
            FROM (
                {" UNION ALL ".join(user_branches)}
            ) u_sub
            WHERE user_identifier IS NOT NULL AND length(trim(user_identifier)) > 0
            GROUP BY user_identifier, entity_type
            ORDER BY total_occurrences DESC, user_identifier ASC;
        """)
        usr_cnt = cursor.execute("SELECT COUNT(*) FROM view_refined_users;").fetchone()[0]
        cursor.execute(
            """
            INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
            VALUES ('refined_users', 'REFINED RESULTS', 'User Accounts & Identifiers', 'view_refined_users', 'RefinedResults', ?, now())
            ON CONFLICT (artifact_id) DO UPDATE SET
                category = 'REFINED RESULTS',
                table_name = 'view_refined_users',
                row_count = EXCLUDED.row_count,
                last_updated = now();
            """,
            [usr_cnt],
        )

    def _ensure_open_conn(self) -> None:
        real_conn = DuckDBManager.get_connection(self.case_id, read_only=False)
        self.conn = real_conn if self.populate_entities else TimelineConnectionProxy(real_conn)

    def normalize_all(self, sync_registry: bool = True) -> Dict[str, Any]:
        """
        Discovers all populated tables in case.duckdb and executes normalization
        queries for each recognized table in deterministic deduplication order.
        """
        with DuckDBManager.get_lock(self.case_id):
            self._ensure_open_conn()
            cursor = self.conn.cursor()

            try:
                from backend.db.schema import sync_granular_artifacts
                sync_granular_artifacts(self.conn, case_id=self.case_id)
            except Exception:
                pass

            base_tables = [
                row[0]
                for row in cursor.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_type = 'BASE TABLE';"
                ).fetchall()
            ]

            excluded = {
                "master_timeline", "entity_connections", "artifact_registry", "bookmarks",
                "processing_logs", "case_keywords", "case_metadata", "parsed_keyword_hits",
                "file_enrichment", "vfs_partitions", "parsed_bulk_extractor_histograms",
            }

            candidate_tables = []
            for tbl in base_tables:
                if tbl in excluded or tbl.startswith("view_") or tbl.startswith("sqlite_"):
                    continue
                try:
                    cnt = cursor.execute(f'SELECT COUNT(*) FROM "{tbl}";').fetchone()[0]
                    if cnt > 0:
                        candidate_tables.append(tbl)
                except Exception:
                    continue

            deferred_combined = {
                "parsed_browser_history",
                "parsed_browser_downloads",
                "parsed_browser_logins",
                "parsed_notifications",
                "artifact_ocr_results",
                "vfs_files",
                "parsed_outlook_emails",
                "parsed_mbox_emails",
                "parsed_winmail_messages",
            }
            deferred_post_browser = {
                "raw_hindsight",
            }
            candidate_tables.sort(
                key=lambda t: (
                    2 if t in deferred_post_browser else (1 if t in deferred_combined else 0),
                    t,
                )
            )

            results: Dict[str, Dict[str, int]] = {}
            total_tl = 0
            total_ent = 0
            bulk_log_events: List[List[Any]] = []

            for drop_sql in (
                "DROP INDEX IF EXISTS idx_mt_timestamp;",
                "DROP INDEX IF EXISTS idx_mt_category;",
                "DROP INDEX IF EXISTS idx_mt_source_table;",
                "DROP INDEX IF EXISTS idx_ec_entity_val;",
                "DROP INDEX IF EXISTS idx_ec_source_table;",
            ):
                try:
                    cursor.execute(drop_sql)
                except Exception:
                    pass

            try:
                if candidate_tables:
                    ph_tbls = ", ".join(["?"] * len(candidate_tables))
                    cursor.execute("BEGIN TRANSACTION;")
                    try:
                        cursor.execute(f"DELETE FROM master_timeline WHERE source_table IN ({ph_tbls});", candidate_tables)
                        cursor.execute(f"DELETE FROM entity_connections WHERE source_table IN ({ph_tbls});", candidate_tables)
                        cursor.execute("COMMIT;")
                        self._skip_per_table_clear = True
                    except Exception:
                        try:
                            cursor.execute("ROLLBACK;")
                        except Exception:
                            pass
                        self._skip_per_table_clear = False

                for tbl in candidate_tables:
                    t_tbl_start = time.time()
                    try:
                        t_cnt, e_cnt = self.normalize_table(tbl, _bulk_mode=True)
                        dur_ms = int((time.time() - t_tbl_start) * 1000)
                        bulk_log_events.append([
                            f"Normalizer:{tbl}",
                            f"SQL Introspection & Normalization for {tbl}",
                            0,
                            int(t_cnt + e_cnt),
                            dur_ms,
                            "SUCCESS",
                            None,
                        ])
                        if t_cnt > 0 or e_cnt > 0:
                            results[tbl] = {"timeline_rows": t_cnt, "entity_rows": e_cnt}
                    except Exception as table_err:
                        dur_ms = int((time.time() - t_tbl_start) * 1000)
                        err_msg = f"Failed normalizing '{tbl}': {table_err}"
                        print(f"[Normalizer] Warning: {err_msg}")
                        bulk_log_events.append([
                            f"Normalizer:{tbl}",
                            f"SQL Introspection & Normalization for {tbl}",
                            1,
                            0,
                            dur_ms,
                            "ERROR",
                            err_msg,
                        ])

                try:
                    cursor.execute("BEGIN TRANSACTION;")
                    try:
                        if bulk_log_events:
                            cursor.executemany(
                                """
                                INSERT INTO processing_logs (
                                    log_id, timestamp_utc, module_name, command_executed,
                                    exit_code, rows_ingested, duration_ms, status, error_message
                                ) VALUES (
                                    nextval('seq_log_id'), CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?
                                );
                                """,
                                bulk_log_events,
                            )
                        cursor.execute("""
                            DELETE FROM master_timeline
                            WHERE source_table IN ('artifact_yara_hits', 'artifact_stinger_hits', 'artifact_ocr_results', 'media_ocr_results', 'file_enrichment')
                               OR timestamp_type IN ('YARA Match', 'OCR Extracted')
                               OR timestamp_utc IS NULL
                               OR timestamp_utc <= TIMESTAMP '1970-01-02 00:00:00'
                               OR timestamp_utc >= TIMESTAMP '2100-01-01 00:00:00';

                            UPDATE entity_connections
                            SET timestamp_utc = NULL
                            WHERE source_table IN ('artifact_yara_hits', 'artifact_stinger_hits', 'artifact_ocr_results', 'media_ocr_results', 'file_enrichment')
                               OR (timestamp_utc IS NOT NULL AND (timestamp_utc <= TIMESTAMP '1970-01-02 00:00:00' OR timestamp_utc >= TIMESTAMP '2100-01-01 00:00:00'));

                            UPDATE master_timeline SET category = 'EMAIL & CALENDAR' WHERE UPPER(TRIM(COALESCE(category, ''))) IN ('EMAIL', 'EMAILS', 'MAIL', 'EMAIL & CALENDAR');
                            UPDATE master_timeline SET category = 'WEB RELATED' WHERE category IN ('Web Browsers', 'Web Related');
                            UPDATE master_timeline SET category = 'CLOUD' WHERE category IN ('Cloud Storage', 'Cloud');
                            UPDATE master_timeline SET category = 'MEDIA' WHERE category IN ('Media & OCR', 'Media & Pictures', 'Media');
                            UPDATE master_timeline SET category = 'DOCUMENTS' WHERE category IN ('Documents & Metadata', 'Documents');
                            UPDATE master_timeline SET category = 'OPERATING SYSTEM' WHERE category IN ('Database & SQLite', 'USB & External Devices', 'Operating System');

                            UPDATE entity_connections SET category = 'EMAIL & CALENDAR' WHERE UPPER(TRIM(COALESCE(category, ''))) IN ('EMAIL', 'EMAILS', 'MAIL', 'EMAIL & CALENDAR');
                            UPDATE entity_connections SET category = 'WEB RELATED' WHERE category IN ('Web Browsers', 'Web Related');
                            UPDATE entity_connections SET category = 'CLOUD' WHERE category IN ('Cloud Storage', 'Cloud');
                            UPDATE entity_connections SET category = 'MEDIA' WHERE category IN ('Media & OCR', 'Media & Pictures', 'Media');
                            UPDATE entity_connections SET category = 'DOCUMENTS' WHERE category IN ('Documents & Metadata', 'Documents');
                            UPDATE entity_connections SET category = 'OPERATING SYSTEM' WHERE category IN ('Database & SQLite', 'USB & External Devices', 'Operating System');
                        """)

                        # Non-live case staging-window guard: remove wall-clock Windows NTFS copy/mkdir timestamps
                        # from vfs_files, parsed_documents_metadata, and parsed_text_documents when historical
                        # forensic events (> 1 day old) exist in master_timeline.
                        is_live_case = False
                        try:
                            live_logs = cursor.execute(
                                "SELECT COUNT(*) FROM processing_logs WHERE command_executed ILIKE 'Extractor (live)%';"
                            ).fetchone()[0]
                            live_meta = cursor.execute(
                                "SELECT COUNT(*) FROM case_metadata WHERE LOWER(TRIM(key)) = 'source_type' AND LOWER(TRIM(value)) = 'live';"
                            ).fetchone()[0]
                            is_live_case = bool((live_logs and live_logs > 0) or (live_meta and live_meta > 0))
                        except Exception:
                            is_live_case = False

                        if not is_live_case:
                            hist_events = cursor.execute(
                                "SELECT COUNT(*) FROM master_timeline WHERE timestamp_utc < (timezone('UTC', now()) - INTERVAL '1 day');"
                            ).fetchone()[0]
                            if hist_events and hist_events > 0:
                                cursor.execute(
                                    """
                                    DELETE FROM master_timeline
                                    WHERE source_table IN ('vfs_files', 'parsed_documents_metadata', 'parsed_text_documents')
                                      AND (
                                          (timestamp_utc >= (timezone('UTC', now()) - INTERVAL '2 hours')
                                           AND timestamp_utc <= (timezone('UTC', now()) + INTERVAL '10 minutes'))
                                          OR
                                          (timestamp_utc >= (CAST(now() AS TIMESTAMP) - INTERVAL '2 hours')
                                           AND timestamp_utc <= (CAST(now() AS TIMESTAMP) + INTERVAL '10 minutes'))
                                      );
                                    """
                                )
                        cursor.execute("COMMIT;")
                    except Exception:
                        try:
                            cursor.execute("ROLLBACK;")
                        except Exception:
                            pass
                        raise
                except Exception as clean_err:
                    print(f"[Normalizer] Warning during post-normalization cleanup: {clean_err}")

                try:
                    self._create_refined_views(cursor)
                except Exception as e:
                    print(f"[Normalizer] Warning creating refined views: {e}")

                if sync_registry:
                    try:
                        from backend.db.schema import sync_artifact_registry_counts
                        sync_artifact_registry_counts(self.conn, case_id=self.case_id)
                    except Exception as sync_err:
                        print(f"[Normalizer] Warning synchronizing artifact registry: {sync_err}")
            finally:
                self._skip_per_table_clear = False
                for idx_sql in (
                    "CREATE INDEX IF NOT EXISTS idx_mt_timestamp ON master_timeline(timestamp_utc);",
                    "CREATE INDEX IF NOT EXISTS idx_mt_category ON master_timeline(category);",
                    "CREATE INDEX IF NOT EXISTS idx_mt_source_table ON master_timeline(source_table);",
                    "CREATE INDEX IF NOT EXISTS idx_ec_entity_val ON entity_connections(entity_value);",
                    "CREATE INDEX IF NOT EXISTS idx_ec_source_table ON entity_connections(source_table);",
                ):
                    try:
                        cursor.execute(idx_sql)
                    except Exception:
                        pass

            # Refresh accurate post-cleanup per-table counts in ONE GROUP BY query each
            tl_by_tbl = {
                str(r[0]): int(r[1] or 0)
                for r in cursor.execute("SELECT source_table, COUNT(*) FROM master_timeline GROUP BY source_table;").fetchall()
                if r[0] is not None
            }
            ent_by_tbl = {
                str(r[0]): int(r[1] or 0)
                for r in cursor.execute("SELECT source_table, COUNT(*) FROM entity_connections GROUP BY source_table;").fetchall()
                if r[0] is not None
            }
            results = {}
            for tbl in candidate_tables:
                tc = tl_by_tbl.get(tbl, 0)
                ec = ent_by_tbl.get(tbl, 0)
                if tc > 0 or ec > 0:
                    results[tbl] = {"timeline_rows": tc, "entity_rows": ec}

            total_tl = sum(tl_by_tbl.values())
            total_ent = sum(ent_by_tbl.values())
            return {
                "tables": results,
                "total_timeline_rows": total_tl,
                "total_entity_rows": total_ent,
            }

    def get_timeline_count(self) -> int:
        """
        Return the total number of records in master_timeline.
        """
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()
            return cursor.execute("SELECT COUNT(*) FROM master_timeline;").fetchone()[0]

    def get_entity_counts(self) -> List[Tuple[str, int]]:
        """
        Return count of records per entity_type in entity_connections.
        """
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()
            return cursor.execute(
                """
                SELECT entity_type, COUNT(*) AS count
                FROM entity_connections
                GROUP BY entity_type
                ORDER BY count DESC;
                """
            ).fetchall()

    def run(self) -> Dict[str, Any]:
        """
        Alias for normalize_all to support standard pipeline coordinator protocol.
        """
        return self.normalize_all()
