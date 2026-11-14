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


class TimelineConnectionProxy:
    """
    Lightweight wrapper that skips entity_connections table population during
    forensic normalization while allowing full timeline and view generation.
    """
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        sql_str = str(sql)
        if "INSERT INTO entity_connections" in sql_str:
            return self
        return self._conn.execute(sql, *args, **kwargs)

    def cursor(self) -> Any:
        return self

    def fetchall(self) -> List[Any]:
        return []

    def fetchone(self) -> Optional[Any]:
        return (0,)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


class TimelineNormalizer:
    """
    Forensic normalization engine that reads raw_* tables populated by EZ tools
    and custom parsers, introspects column schemas dynamically, and populates
    master_timeline and entity_connections.
    """

    def __init__(self, case_id: str, populate_entities: bool = True) -> None:
        self.case_id = case_id
        self.populate_entities = populate_entities
        real_conn = DuckDBManager.get_connection(case_id, read_only=False)
        self.conn = real_conn if populate_entities else TimelineConnectionProxy(real_conn)

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
        tables = [
            row[0]
            for row in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        ]
        if table_name not in tables:
            return False

        row_count = cursor.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()[0]
        return row_count > 0

    def _clear_table_normalizations(self, source_table: str) -> None:
        """
        Ensure idempotency by removing existing records for source_table before normalizing.
        """
        self.conn.execute("DELETE FROM master_timeline WHERE source_table = ?", [source_table])
        self.conn.execute("DELETE FROM entity_connections WHERE source_table = ?", [source_table])

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

        # Timeline columns: SourceCreated, SourceModified, TargetCreated
        timestamp_mappings = [
            ("sourcecreated", "Shortcut Created"),
            ("sourcemodified", "Shortcut Modified"),
            ("targetcreated", "Target File Created"),
        ]

        for col_key, ts_type in timestamp_mappings:
            ts_col = cols.get(col_key)
            if ts_col:
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
                    {path_expr},
                    {serial_expr},
                    'Shortcut to: ' || {path_expr} || {args_expr},
                    '{table_name}',
                    "{row_id_col}",
                    "{source_file_col}"
                FROM "{table_name}"
                WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
                  AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
                  AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
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

        # 3. Timeline: SourceCreated
        src_created_col = cols.get("sourcecreated")
        if src_created_col:
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
                TRY_CAST("{src_created_col}" AS TIMESTAMP),
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
            WHERE TRY_CAST("{src_created_col}" AS TIMESTAMP) IS NOT NULL
              AND TRY_CAST("{src_created_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
              AND TRY_CAST("{src_created_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
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
    # 4. raw_mft ($MFT)
    # -------------------------------------------------------------------------
    def _normalize_raw_mft(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "raw_mft"
        filename_col = cols.get("filename")
        parentpath_col = cols.get("parentpath")
        ext_col = cols.get("extension")
        filesize_col = cols.get("filesize")
        inuse_col = cols.get("inuse")
        row_id_col = cols.get("_row_id", "_row_id")

        if not filename_col or not parentpath_col:
            return (0, 0)

        self._clear_table_normalizations(table_name)

        # InUse filter + important extensions / Users filter per GEMINI.md Section 5.1
        inuse_filter = (
            f"(\"{inuse_col}\" = true OR CAST(\"{inuse_col}\" AS VARCHAR) IN ('true', 'True', '1'))"
            if inuse_col
            else "1=1"
        )
        ext_filter = (
            f"(LOWER(COALESCE(CAST(\"{ext_col}\" AS VARCHAR), '')) IN ('.exe', '.dll', '.ps1', '.bat', '.vbs', '.lnk', '.pf', '.zip', '.7z', '.rar', '.iso', '.docx', '.pdf', '.xlsx') OR CAST(\"{parentpath_col}\" AS VARCHAR) LIKE '%Users%')"
            if ext_col
            else f"CAST(\"{parentpath_col}\" AS VARCHAR) LIKE '%Users%'"
        )
        filter_clause = f"WHERE {inuse_filter} AND {ext_filter}"

        # Timeline mappings: Created0x10, LastModified0x10, Created0x30
        ts_mappings = [
            ("created0x10", "$SI Created"),
            ("lastmodified0x10", "$SI Modified"),
            ("created0x30", "$FN Created"),
        ]

        summary_expr = (
            f"'File ' || COALESCE(CAST(\"{filename_col}\" AS VARCHAR), '') || ' (' || COALESCE(CAST(\"{ext_col}\" AS VARCHAR), '') || ', ' || COALESCE(CAST(\"{filesize_col}\" AS VARCHAR), '0') || ' bytes)'"
            if (ext_col and filesize_col)
            else f"'File ' || COALESCE(CAST(\"{filename_col}\" AS VARCHAR), '')"
        )

        for col_key, ts_type in ts_mappings:
            ts_col = cols.get(col_key)
            if ts_col:
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
                    '$MFT',
                    \"{filename_col}\",
                    \"{parentpath_col}\",
                    {summary_expr},
                    '{table_name}',
                    \"{row_id_col}\",
                    COALESCE(\"{parentpath_col}\" || '\\' || \"{filename_col}\", \"{filename_col}\")
                FROM "{table_name}"
                {filter_clause}
                  AND TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
                  AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
                  AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
                """
                self.conn.execute(timeline_sql)

        # Entity Connections: FileName -> EXECUTABLE or FILE_NAME
        ref_ts = cols.get("lastmodified0x10") or cols.get("created0x10")
        ts_expr = f"TRY_CAST(\"{ref_ts}\" AS TIMESTAMP)" if ref_ts else "NULL"

        name_entity_sql = f"""
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
                WHEN LOWER(COALESCE(CAST(\"{ext_col}\" AS VARCHAR), '')) IN ('.exe', '.dll', '.ps1', '.bat', '.vbs', '.cmd') THEN 'EXECUTABLE'
                ELSE 'FILE_NAME'
            END,
            UPPER(TRIM(CAST(\"{filename_col}\" AS VARCHAR))),
            'OPERATING SYSTEM',
            '$MFT',
            '{table_name}',
            \"{row_id_col}\",
            'MFT file record',
            {ts_expr}
        FROM "{table_name}"
        {filter_clause}
          AND \"{filename_col}\" IS NOT NULL
          AND TRIM(CAST(\"{filename_col}\" AS VARCHAR)) != '';
        """
        self.conn.execute(name_entity_sql)

        # Entity Connections: ParentPath || '\' || FileName -> FILE_PATH
        full_path_sql = f"""
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
            TRIM(CAST(\"{parentpath_col}\" AS VARCHAR) || '\\' || CAST(\"{filename_col}\" AS VARCHAR)),
            'OPERATING SYSTEM',
            '$MFT',
            '{table_name}',
            \"{row_id_col}\",
            'MFT full path',
            {ts_expr}
        FROM "{table_name}"
        {filter_clause}
          AND \"{filename_col}\" IS NOT NULL
          AND TRIM(CAST(\"{filename_col}\" AS VARCHAR)) != ''
          AND \"{parentpath_col}\" IS NOT NULL;
        """
        self.conn.execute(full_path_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
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
        cursor = self.conn.cursor()
        has_keypath = "keypath" in cols
        has_category = "category" in cols
        has_desc = "description" in cols

        views = []
        if has_keypath:
            usb_filter = "KeyPath ILIKE '%USBSTOR%' OR KeyPath ILIKE '%MountedDevices%' OR KeyPath ILIKE '%EMDMgmt%'"
            if has_desc:
                usb_filter += " OR Description ILIKE '%USB%'"
            views.append((
                "view_usb_devices",
                "USB & External Devices",
                "USB Registry Artifacts",
                "view_usb_devices",
                f'SELECT * FROM "raw_recmd" WHERE ({usb_filter})',
            ))

            autorun_filter = "KeyPath ILIKE '%CurrentVersion\\Run%' OR KeyPath ILIKE '%Services%'"
            if has_category:
                autorun_filter = "Category ILIKE '%Run%' OR " + autorun_filter
            views.append((
                "view_autoruns",
                "Operating System",
                "AutoRuns & Services",
                "view_autoruns",
                f'SELECT * FROM "raw_recmd" WHERE ({autorun_filter})',
            ))

            userassist_filter = "KeyPath ILIKE '%UserAssist%'"
            if has_desc:
                userassist_filter += " OR Description ILIKE '%UserAssist%'"
            views.append((
                "view_userassist",
                "Operating System",
                "UserAssist",
                "view_userassist",
                f'SELECT * FROM "raw_recmd" WHERE ({userassist_filter})',
            ))

            views.append((
                "view_bam_dam",
                "Operating System",
                "BAM / DAM Execution",
                "view_bam_dam",
                "SELECT * FROM \"raw_recmd\" WHERE (KeyPath ILIKE '%bam%' OR KeyPath ILIKE '%dam%')",
            ))

        for view_name, category, display_name, artifact_id, query_sql in views:
            try:
                cursor.execute(f'CREATE OR REPLACE VIEW "{view_name}" AS {query_sql};')
                v_count_row = cursor.execute(f'SELECT COUNT(*) FROM "{view_name}";').fetchone()
                v_count = int(v_count_row[0]) if v_count_row else 0
                cursor.execute("DELETE FROM artifact_registry WHERE table_name = ? AND artifact_id != ?;", [view_name, artifact_id])
                cursor.execute(
                    '''
                    INSERT OR REPLACE INTO artifact_registry (
                        artifact_id,
                        category,
                        display_name,
                        table_name,
                        source_tool,
                        row_count,
                        last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
                    ''',
                    [artifact_id, category, display_name, view_name, "RECmd.exe", v_count],
                )
            except Exception as e:
                print(f"[Normalizer] Warning creating virtual view {view_name}: {e}")


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
        ts_col = cols.get("lastwritetime") or cols.get("modifiedon") or cols.get("createdon")
        val_col = cols.get("value") or cols.get("absolutepath")
        row_id_col = cols.get("_row_id", "_row_id")

        if not ts_col or not val_col:
            return (0, 0)

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
            TRY_CAST("{ts_col}" AS TIMESTAMP),
            'Folder Accessed (ShellBag)',
            'OPERATING SYSTEM',
            'ShellBags',
            \"{val_col}\",
            NULL,
            'ShellBag path: ' || COALESCE(\"{val_col}\", ''),
            '{table_name}',
            \"{row_id_col}\",
            'UsrClass.dat'
        FROM "{table_name}"
        WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) > '1601-01-02'::TIMESTAMP
          AND TRY_CAST("{ts_col}" AS TIMESTAMP) < '2200-01-01'::TIMESTAMP;
        """
        self.conn.execute(timeline_sql)

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
            TRIM(CAST(\"{val_col}\" AS VARCHAR)),
            'OPERATING SYSTEM',
            'ShellBags',
            '{table_name}',
            \"{row_id_col}\",
            'Explorer browsed directory path',
            TRY_CAST("{ts_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE \"{val_col}\" IS NOT NULL
          AND TRIM(CAST(\"{val_col}\" AS VARCHAR)) != '';
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

    # 15. parsed_browser_history (Chromium & Firefox)
    # -------------------------------------------------------------------------
    def _normalize_parsed_browser_history(self, cols: Dict[str, str], table_name: str = "parsed_browser_history") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)

        time_col = cols.get("visit_time", "visit_time")
        url_col = cols.get("url", "url")
        title_col = cols.get("title", "title")
        browser_col = cols.get("browser", "browser")
        visits_col = cols.get("visit_count", "visit_count")
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
            'Web Page Visit',
            'Web Browsers',
            'Browser History (' || COALESCE("{browser_col}", 'Browser') || ')',
            "{url_col}",
            lower(regexp_extract(CAST("{url_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1)),
            'Title: ' || COALESCE(NULLIF(TRIM(CAST("{title_col}" AS VARCHAR)), ''), '(No Title)') || ' | Visits: ' || CAST(COALESCE("{visits_col}", 1) AS VARCHAR) || ' | Browser: ' || COALESCE("{browser_col}", 'Browser'),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{time_col}" IS NOT NULL AND TRY_CAST("{time_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: DOMAIN
        domain_sql = f"""
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
            'DOMAIN',
            lower(trim(regexp_extract(CAST("{url_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1))),
            'Web Browsers',
            'Browser History (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Visited domain via ' || COALESCE("{browser_col}", 'Browser'),
            TRY_CAST("{time_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{url_col}" IS NOT NULL
          AND regexp_extract(CAST("{url_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1) != '';
        """
        self.conn.execute(domain_sql)

        # 3. Entity Connections: URL
        url_sql = f"""
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
            'URL',
            "{url_col}",
            'Web Browsers',
            'Browser History (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Visited URL: ' || COALESCE("{title_col}", ''),
            TRY_CAST("{time_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{url_col}" IS NOT NULL AND length(trim(CAST("{url_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(url_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 16. parsed_browser_downloads (Chromium & Firefox)
    # -------------------------------------------------------------------------
    def _normalize_parsed_browser_downloads(self, cols: Dict[str, str], table_name: str = "parsed_browser_downloads") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)

        start_col = cols.get("start_time", "start_time")
        end_col = cols.get("end_time", "end_time")
        target_col = cols.get("target_path", "target_path")
        tab_url_col = cols.get("tab_url", "tab_url")
        browser_col = cols.get("browser", "browser")
        bytes_col = cols.get("total_bytes", "total_bytes")
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
            COALESCE(TRY_CAST("{start_col}" AS TIMESTAMP), TRY_CAST("{end_col}" AS TIMESTAMP)),
            'File Download Started',
            'Web Browsers',
            'Browser Downloads (' || COALESCE("{browser_col}", 'Browser') || ')',
            COALESCE(NULLIF(TRIM(CAST("{target_col}" AS VARCHAR)), ''), CAST("{tab_url_col}" AS VARCHAR)),
            "{tab_url_col}",
            'Downloaded: ' || COALESCE(regexp_extract(CAST("{target_col}" AS VARCHAR), '([^\\\\/]+)$', 1), CAST("{target_col}" AS VARCHAR)) || ' (' || CAST(COALESCE("{bytes_col}", 0) AS VARCHAR) || ' bytes) via ' || COALESCE(CAST("{browser_col}" AS VARCHAR), 'Browser'),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE COALESCE(TRY_CAST("{start_col}" AS TIMESTAMP), TRY_CAST("{end_col}" AS TIMESTAMP)) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: FILE_PATH
        filepath_sql = f"""
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
            "{target_col}",
            'Web Browsers',
            'Browser Downloads (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Downloaded file path via ' || COALESCE("{browser_col}", 'Browser'),
            COALESCE(TRY_CAST("{start_col}" AS TIMESTAMP), TRY_CAST("{end_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{target_col}" IS NOT NULL AND length(trim(CAST("{target_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(filepath_sql)

        # 3. Entity Connections: EXECUTABLE
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
            UPPER(TRIM(regexp_extract(CAST("{target_col}" AS VARCHAR), '([^\\\\/]+)$', 1))),
            'Web Browsers',
            'Browser Downloads (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Executable downloaded via ' || COALESCE("{browser_col}", 'Browser'),
            COALESCE(TRY_CAST("{start_col}" AS TIMESTAMP), TRY_CAST("{end_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{target_col}" IS NOT NULL
          AND (
              "{target_col}" ILIKE '%.exe' OR "{target_col}" ILIKE '%.dll' OR
              "{target_col}" ILIKE '%.ps1' OR "{target_col}" ILIKE '%.bat' OR
              "{target_col}" ILIKE '%.vbs' OR "{target_col}" ILIKE '%.js' OR
              "{target_col}" ILIKE '%.zip' OR "{target_col}" ILIKE '%.7z' OR
              "{target_col}" ILIKE '%.iso' OR "{target_col}" ILIKE '%.msi'
          )
          AND regexp_extract(CAST("{target_col}" AS VARCHAR), '([^\\\\/]+)$', 1) != '';
        """
        self.conn.execute(exec_sql)

        # 4. Entity Connections: DOMAIN
        domain_sql = f"""
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
            'DOMAIN',
            lower(trim(regexp_extract(CAST("{tab_url_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1))),
            'Web Browsers',
            'Browser Downloads (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Download source domain via ' || COALESCE("{browser_col}", 'Browser'),
            COALESCE(TRY_CAST("{start_col}" AS TIMESTAMP), TRY_CAST("{end_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{tab_url_col}" IS NOT NULL
          AND regexp_extract(CAST("{tab_url_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1) != '';
        """
        self.conn.execute(domain_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
            f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        return (t_count, e_count)


    # -------------------------------------------------------------------------
    # 17. parsed_browser_logins (Chromium & Firefox)
    # -------------------------------------------------------------------------
    def _normalize_parsed_browser_logins(self, cols: Dict[str, str], table_name: str = "parsed_browser_logins") -> Tuple[int, int]:
        self._clear_table_normalizations(table_name)

        used_col = cols.get("date_last_used", "date_last_used")
        created_col = cols.get("date_created", "date_created")
        user_col = cols.get("username_value", "username_value")
        orig_col = cols.get("origin_url", "origin_url")
        browser_col = cols.get("browser", "browser")
        times_col = cols.get("times_used", "times_used")
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
            COALESCE(TRY_CAST("{used_col}" AS TIMESTAMP), TRY_CAST("{created_col}" AS TIMESTAMP)),
            CASE WHEN "{used_col}" IS NOT NULL THEN 'Saved Login Used' ELSE 'Saved Login Created' END,
            'Web Browsers',
            'Saved Logins (' || COALESCE("{browser_col}", 'Browser') || ')',
            "{user_col}",
            "{orig_col}",
            'Saved login for ' || COALESCE("{user_col}", '(empty)') || ' at ' || COALESCE("{orig_col}", '') || ' (Used ' || CAST(COALESCE("{times_col}", 0) AS VARCHAR) || ' times)',
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE COALESCE(TRY_CAST("{used_col}" AS TIMESTAMP), TRY_CAST("{created_col}" AS TIMESTAMP)) IS NOT NULL;
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
            TRIM(CAST("{user_col}" AS VARCHAR)),
            'Web Browsers',
            'Saved Logins (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Browser saved credential at ' || COALESCE("{orig_col}", ''),
            COALESCE(TRY_CAST("{used_col}" AS TIMESTAMP), TRY_CAST("{created_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{user_col}" IS NOT NULL AND length(trim(CAST("{user_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(user_sql)

        # 3. Entity Connections: DOMAIN
        domain_sql = f"""
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
            'DOMAIN',
            lower(trim(regexp_extract(CAST("{orig_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1))),
            'Web Browsers',
            'Saved Logins (' || COALESCE("{browser_col}", 'Browser') || ')',
            '{table_name}',
            "{row_id_col}",
            'Domain with saved login credentials via ' || COALESCE("{browser_col}", 'Browser'),
            COALESCE(TRY_CAST("{used_col}" AS TIMESTAMP), TRY_CAST("{created_col}" AS TIMESTAMP))
        FROM "{table_name}"
        WHERE "{orig_col}" IS NOT NULL
          AND regexp_extract(CAST("{orig_col}" AS VARCHAR), '^(?:https?://)?([^/]+)', 1) != '';
        """
        self.conn.execute(domain_sql)

        t_count = self.conn.execute(
            f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';"
        ).fetchone()[0]
        e_count = self.conn.execute(
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
            'Cloud Storage',
            'Cloud Storage Files (' || COALESCE("{provider_col}", 'Cloud') || ')',
            "{path_col}",
            "{cid_col}",
            '[' || COALESCE("{provider_col}", 'Cloud') || '] Synced file: ' || "{path_col}",
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{time_col}" IS NOT NULL AND TRY_CAST("{time_col}" AS TIMESTAMP) IS NOT NULL;
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
            'Cloud Storage',
            'Cloud Storage Files (' || COALESCE("{provider_col}", 'Cloud') || ')',
            '{table_name}',
            "{row_id_col}",
            'Cloud synced file in ' || COALESCE("{provider_col}", 'Cloud'),
            TRY_CAST("{time_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{path_col}" IS NOT NULL AND length(trim(CAST("{path_col}" AS VARCHAR))) > 0;
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
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP),
            'YARA Match',
            'MALWARE & YARA',
            'YARA-X Matches',
            "{file_name_col}",
            "{rule_name_col}",
            {summary_expr},
            '{table_name}',
            "{row_id_col}",
            "{file_path_col}"
        FROM "{table_name}"
        WHERE "{scanned_at_col}" IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: YARA_RULE
        yara_sql = f"""
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
            'YARA_RULE',
            UPPER(TRIM(CAST("{rule_name_col}" AS VARCHAR))),
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'YARA rule matched in ' || "{file_name_col}",
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{rule_name_col}" IS NOT NULL AND length(trim(CAST("{rule_name_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(yara_sql)

        # 3. Entity Connections: EXECUTABLE or FILE_NAME
        file_sql = f"""
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
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{file_name_col}" IS NOT NULL AND length(trim(CAST("{file_name_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(file_sql)

        # 4. Entity Connections: SHA256 (when present)
        sha_sql = f"""
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
            'SHA256',
            LOWER(TRIM(CAST("{sha256_col}" AS VARCHAR))),
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'SHA256 for ' || "{file_name_col}" || ' (Rule: ' || "{rule_name_col}" || ')',
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{sha256_col}" IS NOT NULL AND length(trim(CAST("{sha256_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(sha_sql)

        # 5. Entity Connections: FILE_PATH
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
            TRIM(CAST("{file_path_col}" AS VARCHAR)),
            'MALWARE & YARA',
            'YARA-X Matches',
            '{table_name}',
            "{row_id_col}",
            'Path to suspicious file ' || "{file_name_col}",
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
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
    # 22. artifact_ocr_results (RapidOCR Extracted Text)
    # -------------------------------------------------------------------------
    def _normalize_artifact_ocr_results(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "artifact_ocr_results"
        scanned_at_col = cols.get("scanned_at", "scanned_at")
        file_name_col = cols.get("file_name", "file_name")
        file_path_col = cols.get("file_path", "file_path")
        sha256_col = cols.get("sha256", "sha256")
        dim_col = cols.get("dimensions", "dimensions")
        text_col = cols.get("extracted_text", "extracted_text")
        conf_col = cols.get("confidence", "confidence")
        row_id_col = cols.get("_row_id", "_row_id")

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
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP),
            'OCR Extracted',
            'Media & OCR',
            'RapidOCR Extracted Text',
            "{file_name_col}",
            COALESCE("{dim_col}", 'Image'),
            'OCR text extracted from ' || "{file_name_col}" || ' (Conf: ' || CAST(ROUND(COALESCE("{conf_col}", 0.0), 2) AS VARCHAR) || '): ' || SUBSTR(COALESCE("{text_col}", ''), 1, 100),
            '{table_name}',
            "{row_id_col}",
            "{file_path_col}"
        FROM "{table_name}"
        WHERE "{scanned_at_col}" IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

        # 2. Entity Connections: FILE_NAME
        fn_sql = f"""
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
            'FILE_NAME',
            UPPER(TRIM(CAST("{file_name_col}" AS VARCHAR))),
            'Media & OCR',
            'RapidOCR Extracted Text',
            '{table_name}',
            "{row_id_col}",
            'Image with OCR text: ' || SUBSTR(COALESCE("{text_col}", ''), 1, 60),
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{file_name_col}" IS NOT NULL AND length(trim(CAST("{file_name_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(fn_sql)

        # 3. Entity Connections: SHA256 (when present)
        sha_sql = f"""
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
            'SHA256',
            LOWER(TRIM(CAST("{sha256_col}" AS VARCHAR))),
            'Media & OCR',
            'RapidOCR Extracted Text',
            '{table_name}',
            "{row_id_col}",
            'SHA256 of image ' || "{file_name_col}",
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE "{sha256_col}" IS NOT NULL AND length(trim(CAST("{sha256_col}" AS VARCHAR))) > 0;
        """
        self.conn.execute(sha_sql)

        # 4. Entity Connections: FILE_PATH
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
            TRIM(CAST("{file_path_col}" AS VARCHAR)),
            'Media & OCR',
            'RapidOCR Extracted Text',
            '{table_name}',
            "{row_id_col}",
            'File path to image ' || "{file_name_col}",
            TRY_CAST("{scanned_at_col}" AS TIMESTAMP)
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
        fname_col = next((c for k, c in cols.items() if "filename" in k or "path" in k or "file" in k), None)
        ts_col = next((c for k, c in cols.items() if "created" in k or "time" in k or "date" in k or "modified" in k), None)
        row_id_col = cols.get("_row_id", "_row_id")

        self._clear_table_normalizations(table_name)
        if not fname_col:
            return (0, 0)

        ts_expr = f'TRY_CAST("{ts_col}" AS TIMESTAMP)' if ts_col else "CURRENT_TIMESTAMP"

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
            COALESCE({ts_expr}, CURRENT_TIMESTAMP),
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
        WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0;
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
            TRIM(CAST("{remote_col}" AS VARCHAR)),
            'OPERATING SYSTEM',
            'Remote Access & RMM Sessions',
            '{table_name}',
            "{row_id_col}",
            "{app_col}" || ' remote peer IP',
            TRY_CAST("{start_col}" AS TIMESTAMP)
        FROM "{table_name}"
        WHERE CAST("{remote_col}" AS VARCHAR) ~ '^[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}$';
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
        app_col = cols.get("app_id", "app_id")
        type_col = cols.get("header", cols.get("notification_type", "header"))
        arr_col = cols.get("timestamp_utc", cols.get("arrival_time_utc", "timestamp_utc"))
        text_col = cols.get("body", cols.get("title", cols.get("payload_text", "body")))
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
            TRY_CAST("{arr_col}" AS TIMESTAMP),
            'Push Notification Arrived',
            'OPERATING SYSTEM',
            'Windows Push Notifications',
            "{app_col}",
            "{type_col}",
            'Notification from ' || "{app_col}" || ' [' || "{type_col}" || ']: ' || SUBSTR(COALESCE("{text_col}", ''), 1, 100),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE TRY_CAST("{arr_col}" AS TIMESTAMP) IS NOT NULL;
        """
        self.conn.execute(timeline_sql)

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
            "{row_id_col}",
            'Application posting push notification',
            TRY_CAST("{arr_col}" AS TIMESTAMP)
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
                'Database & SQLite',
                '{table_name}',
                {prim_expr},
                '{ts_col}',
                'SQLite record in {table_name}: ' || COALESCE(CAST({prim_expr} AS VARCHAR), ''),
                '{table_name}',
                "{row_id_col}",
                '{table_name}'
            FROM "{table_name}"
            WHERE TRY_CAST("{ts_col}" AS TIMESTAMP) IS NOT NULL;
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
                'Database & SQLite',
                '{table_name}',
                '{table_name}',
                "{row_id_col}",
                'Database identifier in {table_name}',
                {f'TRY_CAST("{ts_col}" AS TIMESTAMP)' if ts_col else 'NULL'}
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

        # 1. Timeline (for entries with timestamp)
        self.conn.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            "{time_col}",
            'Thumbnail Cached / Screen Captured',
            'Media & OCR',
            'Windows Thumbcache & Screenshots',
            COALESCE("{hash_col}", "{sha_col}"),
            "{type_col}",
            "{type_col}" || ' (' || "{ext_col}" || ', ' || CAST("{size_col}" AS VARCHAR) || ' bytes) in ' || "{cache_col}",
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{time_col}" IS NOT NULL;
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
            'Media & OCR',
            'Windows Thumbcache & Screenshots',
            '{table_name}',
            "{row_id_col}",
            "{type_col}" || ' entry hash in ' || "{cache_col}",
            "{time_col}"
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
            'Media & OCR',
            'Windows Thumbcache & Screenshots',
            '{table_name}',
            "{row_id_col}",
            'Carved thumbnail SHA256 digest',
            "{time_col}"
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
        row_id_col = cols.get("_row_id", "_row_id")
        fname_col = cols.get("file_name", "file_name")
        ftype_col = cols.get("file_type", "file_type")
        title_col = cols.get("title", "title")
        author_col = cols.get("author", "author")
        mod_by_col = cols.get("last_modified_by", "last_modified_by")
        ctime_col = cols.get("created_time", "created_time")
        mtime_col = cols.get("modified_time", "modified_time")
        macros_col = cols.get("has_macros", "has_macros")
        host_col = cols.get("zone_host_url", cols.get("host_url", "zone_host_url"))
        ref_col = cols.get("zone_referrer_url", cols.get("referrer_url", "zone_referrer_url"))
        sha_col = cols.get("sha256", "sha256")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        # 1. Timeline: Created
        self.conn.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            "{ctime_col}",
            'Document Created',
            'Documents & Metadata',
            'Corporate Documents',
            "{fname_col}",
            COALESCE("{author_col}", "{ftype_col}"),
            'Title: ' || COALESCE("{title_col}", "{fname_col}") ||
            CASE WHEN "{macros_col}" = true THEN ' [VBA MACROS DETECTED]' ELSE '' END ||
            CASE WHEN "{host_col}" IS NOT NULL AND length("{host_col}") > 0 THEN ' | Downloaded from: ' || "{host_col}" ELSE '' END,
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{ctime_col}" IS NOT NULL;
        """)

        # Timeline: Modified
        self.conn.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            "{mtime_col}",
            'Document Modified',
            'Documents & Metadata',
            'Corporate Documents',
            "{fname_col}",
            COALESCE("{mod_by_col}", "{author_col}"),
            'Title: ' || COALESCE("{title_col}", "{fname_col}") || ' | Last modified by: ' || COALESCE("{mod_by_col}", 'Unknown'),
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{mtime_col}" IS NOT NULL AND ("{ctime_col}" IS NULL OR "{mtime_col}" != "{ctime_col}");
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
            'Documents & Metadata',
            'Corporate Documents',
            '{table_name}',
            "{row_id_col}",
            'Corporate document file name (' || "{ftype_col}" || ')',
            COALESCE("{ctime_col}", "{mtime_col}")
        FROM "{table_name}"
        WHERE "{fname_col}" IS NOT NULL AND length(trim(CAST("{fname_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: USER_ACCOUNT (Author)
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'USER_ACCOUNT',
            TRIM(CAST("{author_col}" AS VARCHAR)),
            'Documents & Metadata',
            'Corporate Documents',
            '{table_name}',
            "{row_id_col}",
            'Document author of ' || "{fname_col}",
            "{ctime_col}"
        FROM "{table_name}"
        WHERE "{author_col}" IS NOT NULL AND length(trim(CAST("{author_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: USER_ACCOUNT (Last Modified By)
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'USER_ACCOUNT',
            TRIM(CAST("{mod_by_col}" AS VARCHAR)),
            'Documents & Metadata',
            'Corporate Documents',
            '{table_name}',
            "{row_id_col}",
            'Document last modifier of ' || "{fname_col}",
            "{mtime_col}"
        FROM "{table_name}"
        WHERE "{mod_by_col}" IS NOT NULL AND length(trim(CAST("{mod_by_col}" AS VARCHAR))) > 0 AND ("{author_col}" IS NULL OR "{mod_by_col}" != "{author_col}");
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
            'Documents & Metadata',
            'Corporate Documents',
            '{table_name}',
            "{row_id_col}",
            'Document SHA256 digest',
            COALESCE("{ctime_col}", "{mtime_col}")
        FROM "{table_name}"
        WHERE "{sha_col}" IS NOT NULL AND length(trim(CAST("{sha_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: URL & DOMAIN from HostUrl
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'URL',
            TRIM(CAST("{host_col}" AS VARCHAR)),
            'Documents & Metadata',
            'Corporate Documents',
            '{table_name}',
            "{row_id_col}",
            'Zone.Identifier download HostUrl for ' || "{fname_col}",
            COALESCE("{ctime_col}", "{mtime_col}")
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
            'Documents & Metadata',
            'Corporate Documents',
            '{table_name}',
            "{row_id_col}",
            'Zone.Identifier download host domain',
            COALESCE("{ctime_col}", "{mtime_col}")
        FROM "{table_name}"
        WHERE "{host_col}" IS NOT NULL AND regexp_extract(CAST("{host_col}" AS VARCHAR), '://([^/:]+)', 1) IS NOT NULL AND length(regexp_extract(CAST("{host_col}" AS VARCHAR), '://([^/:]+)', 1)) > 0;
        """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 31. parsed_emails (Emails & Mail Stores)
    # -------------------------------------------------------------------------
    def _normalize_parsed_emails(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_emails"
        self._clear_table_normalizations(table_name)
        row_id_col = cols.get("_row_id", "_row_id")
        fmt_col = cols.get("email_format", "email_format")
        sender_col = cols.get("sender", "sender")
        recip_col = cols.get("recipients", "recipients")
        cc_col = cols.get("cc", "cc")
        subj_col = cols.get("subject", "subject")
        date_col = cols.get("date_utc", "date_utc")
        msg_id_col = cols.get("message_id", "message_id")
        att_cnt_col = cols.get("attachments_count", cols.get("attachment_count", "attachments_count"))
        att_names_col = cols.get("attachment_names", "attachment_names")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        # 1. Timeline
        self.conn.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            "{date_col}",
            'Email Sent/Received (' || "{fmt_col}" || ')',
            'EMAIL',
            'Corporate Email Stores',
            "{sender_col}",
            COALESCE("{subj_col}", '(No Subject)'),
            'Subject: ' || COALESCE("{subj_col}", '(No Subject)') || ' | To: ' || COALESCE("{recip_col}", '') ||
            CASE WHEN "{att_cnt_col}" > 0 THEN ' | Attachments (' || CAST("{att_cnt_col}" AS VARCHAR) || '): ' || COALESCE("{att_names_col}", '') ELSE '' END,
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{date_col}" IS NOT NULL;
        """)

        # 2. Entity Connections: EMAIL_ADDRESS (Sender)
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EMAIL_ADDRESS',
            LOWER(TRIM(CAST("{sender_col}" AS VARCHAR))),
            'EMAIL',
            'Corporate Email Stores',
            '{table_name}',
            "{row_id_col}",
            'Email sender (' || "{fmt_col}" || ')',
            "{date_col}"
        FROM "{table_name}"
        WHERE "{sender_col}" IS NOT NULL AND length(trim(CAST("{sender_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: EMAIL_ADDRESS (Recipients)
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'EMAIL_ADDRESS',
            LOWER(TRIM(CAST("{recip_col}" AS VARCHAR))),
            'EMAIL',
            'Corporate Email Stores',
            '{table_name}',
            "{row_id_col}",
            'Email recipient (' || "{fmt_col}" || ')',
            "{date_col}"
        FROM "{table_name}"
        WHERE "{recip_col}" IS NOT NULL AND length(trim(CAST("{recip_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: MESSAGE_ID
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'MESSAGE_ID',
            TRIM(CAST("{msg_id_col}" AS VARCHAR)),
            'EMAIL',
            'Corporate Email Stores',
            '{table_name}',
            "{row_id_col}",
            'Email internet message ID',
            "{date_col}"
        FROM "{table_name}"
        WHERE "{msg_id_col}" IS NOT NULL AND length(trim(CAST("{msg_id_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: FILE_NAME (Attachments)
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'FILE_NAME',
            UPPER(TRIM(CAST("{att_names_col}" AS VARCHAR))),
            'EMAIL',
            'Corporate Email Stores',
            '{table_name}',
            "{row_id_col}",
            'Email attachment payload',
            "{date_col}"
        FROM "{table_name}"
        WHERE "{att_cnt_col}" > 0 AND "{att_names_col}" IS NOT NULL AND length(trim(CAST("{att_names_col}" AS VARCHAR))) > 0;
        """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
        return (t_count, e_count)

    # -------------------------------------------------------------------------
    # 32. parsed_notifications (Windows Push Notifications)
    # -------------------------------------------------------------------------
    def _normalize_parsed_notifications(self, cols: Dict[str, str]) -> Tuple[int, int]:
        table_name = "parsed_notifications"
        self._clear_table_normalizations(table_name)
        row_id_col = cols.get("_row_id", "_row_id")
        app_col = cols.get("app_id", "app_id")
        time_col = cols.get("timestamp_utc", "timestamp_utc")
        title_col = cols.get("title", "title")
        body_col = cols.get("body", "body")
        action_col = cols.get("action_url", "action_url")
        src_col = cols.get("source_file", cols.get("file_path", "file_path"))

        # 1. Timeline
        self.conn.execute(f"""
        INSERT INTO master_timeline (
            timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file
        )
        SELECT
            nextval('seq_timeline_id'),
            "{time_col}",
            'Toast Notification Received',
            'CHAT',
            'Windows Push Notifications',
            COALESCE("{app_col}", 'Windows Notification'),
            COALESCE("{title_col}", ''),
            '[' || COALESCE("{app_col}", 'App') || '] ' || COALESCE("{title_col}", '') ||
            CASE WHEN "{body_col}" IS NOT NULL AND length("{body_col}") > 0 THEN ': ' || "{body_col}" ELSE '' END,
            '{table_name}',
            "{row_id_col}",
            "{src_col}"
        FROM "{table_name}"
        WHERE "{time_col}" IS NOT NULL;
        """)

        # 2. Entity Connections: APPLICATION
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'APPLICATION',
            UPPER(TRIM(CAST("{app_col}" AS VARCHAR))),
            'CHAT',
            'Windows Push Notifications',
            '{table_name}',
            "{row_id_col}",
            'Notification generating application',
            "{time_col}"
        FROM "{table_name}"
        WHERE "{app_col}" IS NOT NULL AND length(trim(CAST("{app_col}" AS VARCHAR))) > 0;
        """)

        # Entity Connections: URL
        self.conn.execute(f"""
        INSERT INTO entity_connections (
            connection_id, entity_type, entity_value, category, artifact_name, source_table, source_row_id, context_label, timestamp_utc
        )
        SELECT
            nextval('seq_connection_id'),
            'URL',
            TRIM(CAST("{action_col}" AS VARCHAR)),
            'CHAT',
            'Windows Push Notifications',
            '{table_name}',
            "{row_id_col}",
            'Notification launch action URL',
            "{time_col}"
        FROM "{table_name}"
        WHERE "{action_col}" IS NOT NULL AND length(trim(CAST("{action_col}" AS VARCHAR))) > 0;
        """)

        t_count = self.conn.execute(f"SELECT COUNT(*) FROM master_timeline WHERE source_table = '{table_name}';").fetchone()[0]
        e_count = self.conn.execute(f"SELECT COUNT(*) FROM entity_connections WHERE source_table = '{table_name}';").fetchone()[0]
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
    # Public Execution & Normalization Orchestrator
    # -------------------------------------------------------------------------
    def normalize_table(self, table_name: str) -> Tuple[int, int]:
        """
        Normalize a single populated table by discovering its columns via DESCRIBE
        and executing its dedicated SQL mapping. Returns (timeline_rows, entity_rows).
        """
        with DuckDBManager.get_lock(self.case_id):
            if not self._table_exists(table_name):
                return (0, 0)

            cols = self._get_columns(table_name)
            start_time = time.time()

        handlers = {
            "raw_evtx": self._normalize_raw_evtx,
            "raw_lecmd": lambda c: self._normalize_raw_lecmd_generic("raw_lecmd", "LNK Shortcut Files", c),
            "raw_pecmd": self._normalize_raw_pecmd,
            "raw_mft": self._normalize_raw_mft,
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
            "parsed_browser_history": self._normalize_parsed_browser_history,
            "parsed_chrome_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_chrome_history"),
            "parsed_edge_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_edge_history"),
            "parsed_brave_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_brave_history"),
            "parsed_firefox_history": lambda c: self._normalize_parsed_browser_history(c, "parsed_firefox_history"),
            "parsed_chrome_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_chrome_downloads"),
            "parsed_edge_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_edge_downloads"),
            "parsed_brave_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_brave_downloads"),
            "parsed_firefox_downloads": lambda c: self._normalize_parsed_browser_downloads(c, "parsed_firefox_downloads"),
            "parsed_chrome_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_chrome_logins"),
            "parsed_edge_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_edge_logins"),
            "parsed_brave_logins": lambda c: self._normalize_parsed_browser_logins(c, "parsed_brave_logins"),
            "parsed_browser_downloads": self._normalize_parsed_browser_downloads,
            "parsed_browser_logins": self._normalize_parsed_browser_logins,
            "parsed_chat_messages": self._normalize_parsed_chat_messages,
            "parsed_cloud_files": self._normalize_parsed_cloud_files,
            "parsed_usb_devices": self._normalize_parsed_usb_devices,
            "artifact_yara_hits": self._normalize_artifact_yara_hits,
            "artifact_ocr_results": self._normalize_artifact_ocr_results,
            "raw_rbcmd": self._normalize_raw_rbcmd,
            "raw_recentfilecache": self._normalize_raw_recentfilecache,
            "parsed_scheduled_tasks": self._normalize_parsed_scheduled_tasks,
            "parsed_powershell_history": self._normalize_parsed_powershell_history,
            "parsed_rmm_sessions": self._normalize_parsed_rmm_sessions,
            "parsed_wpn_notifications": self._normalize_parsed_wpn_notifications,
            "parsed_media_exif": self._normalize_parsed_media_exif,
            "parsed_thumbcache": self._normalize_parsed_thumbcache,
            "parsed_documents_metadata": self._normalize_parsed_documents_metadata,
            "parsed_emails": self._normalize_parsed_emails,
            "parsed_notifications": self._normalize_parsed_notifications,
        }

        handler = handlers.get(table_name)
        if not handler:
            if table_name.startswith("raw_srum_"):
                handler = lambda c: self._normalize_raw_srum_generic(
                    table_name,
                    f"SRUM ({table_name.replace('raw_srum_', '')})",
                    c,
                    is_network=("net" in table_name or "network" in table_name)
                )
            elif table_name.startswith("raw_sqlecmd_") or table_name.startswith("parsed_sqlite_"):
                handler = lambda c: self._normalize_generic_sqlite_table(table_name, c)
            else:
                print(f"[Normalizer] No dedicated normalization handler for table: '{table_name}'")
                return (0, 0)

        try:
            t_count, e_count = handler(cols)
            duration_ms = int((time.time() - start_time) * 1000)

            print(
                f"[Normalizer] '{table_name}' normalized: {t_count} timeline events, "
                f"{e_count} entity connections ({duration_ms}ms)"
            )
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


    def _create_refined_views(self, cursor: duckdb.DuckDBPyConnection) -> None:
        """
        Create and register WFT 'Refined Results' views:
        view_refined_domains (Top Domains & URLs) and view_refined_users (User Accounts & Identifiers).
        """
        tbls = [t[0] for t in cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';").fetchall()]
        if "entity_connections" not in tbls:
            return

        cursor.execute("""
            CREATE OR REPLACE VIEW view_refined_domains AS
            SELECT 
                row_number() OVER () AS _row_id,
                domain,
                domain AS domain_or_url,
                'DOMAIN' AS entity_type,
                COUNT(*) AS event_count,
                COUNT(*) AS total_occurrences,
                COUNT(DISTINCT source_artifact) AS distinct_artifacts_count,
                MIN(timestamp_utc) AS first_seen,
                MIN(timestamp_utc) AS first_observed_utc,
                MAX(timestamp_utc) AS last_seen,
                MAX(timestamp_utc) AS last_observed_utc,
                string_agg(DISTINCT source_artifact, ', ') AS observed_in_artifacts
            FROM (
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Edge Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_edge_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Chrome Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_chrome_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Brave Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_brave_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(url, 'https?://([^/:]+)', 1) AS domain, 'Firefox Web History' AS source_artifact, TRY_CAST(visit_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_firefox_history WHERE url IS NOT NULL AND length(url) > 0
                UNION ALL
                SELECT regexp_extract(COALESCE(tab_url, site_url), 'https?://([^/:]+)', 1) AS domain, 'Edge Downloads' AS source_artifact, TRY_CAST(start_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_edge_downloads WHERE COALESCE(tab_url, site_url) IS NOT NULL AND length(COALESCE(tab_url, site_url)) > 0
                UNION ALL
                SELECT regexp_extract(COALESCE(tab_url, site_url), 'https?://([^/:]+)', 1) AS domain, 'Chrome Downloads' AS source_artifact, TRY_CAST(start_time AS TIMESTAMP) AS timestamp_utc
                FROM parsed_chrome_downloads WHERE COALESCE(tab_url, site_url) IS NOT NULL AND length(COALESCE(tab_url, site_url)) > 0
            ) d_sub
            WHERE domain IS NOT NULL AND length(trim(domain)) > 0
            GROUP BY domain
            ORDER BY event_count DESC;
        """)
        dom_cnt = cursor.execute("SELECT COUNT(*) FROM view_refined_domains;").fetchone()[0]
        cursor.execute("DELETE FROM artifact_registry WHERE table_name = 'view_refined_domains' AND artifact_id != 'refined_domains';")
        cursor.execute("""
            INSERT OR REPLACE INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
            VALUES ('refined_domains', 'REFINED RESULTS', 'Extracted URLs & Domains', 'view_refined_domains', 'RefinedResults', ?, CURRENT_TIMESTAMP);
        """, [dom_cnt])

        # Keyword Hits view
        try:
            cursor.execute("""
                CREATE OR REPLACE VIEW view_keyword_hits AS
                SELECT
                    row_number() OVER () AS _row_id,
                    keyword_id,
                    keyword,
                    is_regex,
                    source_file,
                    hit_count,
                    created_at
                FROM case_keywords
                WHERE hit_count > 0;
            """)
            kw_cnt = cursor.execute("SELECT COUNT(*) FROM view_keyword_hits;").fetchone()[0]
            cursor.execute("DELETE FROM artifact_registry WHERE table_name = 'view_keyword_hits' AND artifact_id != 'refined_keyword_hits';")
            cursor.execute("""
                INSERT OR REPLACE INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                VALUES ('refined_keyword_hits', 'REFINED RESULTS', 'Keyword Hits', 'view_keyword_hits', 'KeywordScanner', ?, CURRENT_TIMESTAMP);
            """, [kw_cnt])
        except Exception as kw_ex:
            print(f"[Normalizer] Notice on view_keyword_hits: {kw_ex}")

        # Discovered Documents view
        try:
            cursor.execute("""
                CREATE OR REPLACE VIEW view_documents AS
                SELECT
                    row_number() OVER () AS _row_id,
                    file_name,
                    file_path,
                    extension,
                    file_size_bytes,
                    created_time,
                    modified_time,
                    source_evidence
                FROM (
                    SELECT
                        FileName AS file_name,
                        COALESCE(ParentPath, '') || '\\' || COALESCE(FileName, '') AS file_path,
                        LOWER(Extension) AS extension,
                        FileSize AS file_size_bytes,
                        Created0x10 AS created_time,
                        LastModified0x10 AS modified_time,
                        'raw_mft' AS source_evidence
                    FROM raw_mft
                    WHERE LOWER(Extension) IN ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv')
                    UNION ALL
                    SELECT
                        regexp_extract(CAST(COALESCE(LocalPath, SourceFile, '') AS VARCHAR), '([^\\\\]+)$', 1) AS file_name,
                        COALESCE(LocalPath, SourceFile, '') AS file_path,
                        LOWER(regexp_extract(CAST(COALESCE(LocalPath, SourceFile, '') AS VARCHAR), '(\\.[a-zA-Z0-9]+)$', 1)) AS extension,
                        CAST(NULL AS BIGINT) AS file_size_bytes,
                        TargetCreated AS created_time,
                        TargetModified AS modified_time,
                        'raw_lecmd' AS source_evidence
                    FROM raw_lecmd
                    WHERE LOWER(COALESCE(LocalPath, '')) SIMILAR TO '.*\\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv)$'
                ) doc_sub;
            """)
            doc_cnt = cursor.execute("SELECT COUNT(*) FROM view_documents;").fetchone()[0]
            cursor.execute("DELETE FROM artifact_registry WHERE table_name = 'view_documents' AND artifact_id != 'view_documents';")
            cursor.execute("""
                INSERT OR REPLACE INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
                VALUES ('view_documents', 'DOCUMENTS', 'Discovered Documents', 'view_documents', 'FileSystemNormalizer', ?, CURRENT_TIMESTAMP);
            """, [doc_cnt])
        except Exception as doc_ex:
            print(f"[Normalizer] Notice on view_documents: {doc_ex}")

        cursor.execute("""
            CREATE OR REPLACE VIEW view_refined_users AS
            SELECT 
                row_number() OVER () AS _row_id,
                user_identifier,
                'USER_ACCOUNT' AS entity_type,
                source_artifact,
                COUNT(*) AS total_occurrences,
                MIN(timestamp_utc) AS first_observed_utc,
                MAX(timestamp_utc) AS last_observed_utc,
                source_artifact AS observed_in_artifacts
            FROM (
                SELECT CAST(UserName AS VARCHAR) AS user_identifier, 'Security & System Event Logs' AS source_artifact, TRY_CAST(TimeCreated AS TIMESTAMP) AS timestamp_utc
                FROM raw_evtx WHERE UserName IS NOT NULL AND TRIM(CAST(UserName AS VARCHAR)) NOT IN ('', '-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'N/A')
                UNION ALL
                SELECT CAST(username AS VARCHAR) AS user_identifier, 'PowerShell Console Host History' AS source_artifact, CAST(NULL AS TIMESTAMP) AS timestamp_utc
                FROM parsed_powershell_history WHERE username IS NOT NULL AND TRIM(CAST(username AS VARCHAR)) != ''
                UNION ALL
                SELECT CAST(UserId AS VARCHAR) AS user_identifier, 'SRUM Application Resource Usage' AS source_artifact, TRY_CAST(Timestamp AS TIMESTAMP) AS timestamp_utc
                FROM raw_srum_app WHERE UserId IS NOT NULL AND TRIM(CAST(UserId AS VARCHAR)) NOT IN ('', '0')
                UNION ALL
                SELECT CAST(username_value AS VARCHAR) AS user_identifier, 'Edge Logins' AS source_artifact, TRY_CAST(date_created AS TIMESTAMP) AS timestamp_utc
                FROM parsed_edge_logins WHERE username_value IS NOT NULL AND TRIM(CAST(username_value AS VARCHAR)) != ''
                UNION ALL
                SELECT CAST(username_value AS VARCHAR) AS user_identifier, 'Chrome Logins' AS source_artifact, TRY_CAST(date_created AS TIMESTAMP) AS timestamp_utc
                FROM parsed_chrome_logins WHERE username_value IS NOT NULL AND TRIM(CAST(username_value AS VARCHAR)) != ''
                UNION ALL
                SELECT CAST(sender AS VARCHAR) AS user_identifier, 'Microsoft Teams Messages' AS source_artifact, TRY_CAST(timestamp_utc AS TIMESTAMP) AS timestamp_utc
                FROM parsed_teams_messages WHERE sender IS NOT NULL AND TRIM(CAST(sender AS VARCHAR)) != ''
            ) u_sub
            WHERE user_identifier IS NOT NULL AND length(trim(user_identifier)) > 0
            GROUP BY user_identifier, source_artifact
            ORDER BY total_occurrences DESC;
        """)
        usr_cnt = cursor.execute("SELECT COUNT(*) FROM view_refined_users;").fetchone()[0]
        cursor.execute("DELETE FROM artifact_registry WHERE table_name = 'view_refined_users' AND artifact_id != 'refined_users';")
        cursor.execute("""
            INSERT OR REPLACE INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
            VALUES ('refined_users', 'REFINED RESULTS', 'User Accounts & Identifiers', 'view_refined_users', 'RefinedResults', ?, CURRENT_TIMESTAMP);
        """, [usr_cnt])

    def normalize_all(self) -> Dict[str, Any]:
        """
        Discovers all populated tables in case.duckdb and executes normalization
        queries for each recognized table. Returns comprehensive run metrics.
        """
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()

            # Query only base tables in main schema (excluding views and system tables)
            base_tables = [
                row[0]
                for row in cursor.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_type = 'BASE TABLE';"
                ).fetchall()
            ]

            excluded = {
                "master_timeline", "entity_connections", "artifact_registry", "bookmarks",
                "processing_logs", "case_keywords", "file_enrichment"
            }

            candidate_tables = []
            for tbl in base_tables:
                if tbl in excluded or tbl.startswith("view_") or tbl.startswith("sqlite_"):
                    continue
                # Only include base tables that actually have > 0 rows
                try:
                    cnt = cursor.execute(f'SELECT COUNT(*) FROM "{tbl}";').fetchone()[0]
                    if cnt > 0:
                        candidate_tables.append(tbl)
                except Exception:
                    continue

            print(f"\n[Normalizer] Discovered {len(candidate_tables)} populated candidate base tables to normalize: {candidate_tables}")

            results: Dict[str, Dict[str, int]] = {}
            total_tl = 0
            total_ent = 0

            for tbl in candidate_tables:
                try:
                    t_cnt, e_cnt = self.normalize_table(tbl)
                    if t_cnt > 0 or e_cnt > 0:
                        results[tbl] = {"timeline_rows": t_cnt, "entity_rows": e_cnt}
                        total_tl += t_cnt
                        total_ent += e_cnt
                except Exception as table_err:
                    print(f"[Normalizer] Warning: Failed normalizing table '{tbl}': {table_err}")

            try:
                self._create_refined_views(cursor)
            except Exception as e:
                print(f"[Normalizer] Warning creating refined views: {e}")

            # Synchronize all artifact registry counts and views once normalization finishes
            try:
                from backend.db.schema import sync_artifact_registry_counts
                sync_artifact_registry_counts(self.conn, case_id=self.case_id)
            except Exception as sync_err:
                print(f"[Normalizer] Warning synchronizing artifact registry: {sync_err}")

            print(
                f"[Normalizer] Normalization complete. Total Timeline Events: {total_tl}, "
                f"Total Entity Connections: {total_ent}\n"
            )
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
