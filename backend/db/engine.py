"""
Windows Forensic Toolkit (WFT) DFIR Suite - DuckDB Database Engine & Pagination Manager
"""
import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import duckdb

from backend.config import get_case_db_path, get_case_dir
from backend.db.schema import CORE_TABLES, init_schema, verify_core_tables


class DuckDBManager:
    """
    Thread-safe connection and query execution manager for DuckDB case databases.
    """
    _instance_lock = threading.Lock()
    _connections: Dict[str, duckdb.DuckDBPyConnection] = {}
    _is_read_only: Dict[str, bool] = {}
    _case_locks: Dict[str, threading.RLock] = {}

    @classmethod
    def get_lock(cls, case_id: str) -> threading.RLock:
        """
        Get or create a re-entrant lock (RLock) dedicated to the given case_id.
        All concurrent threads synchronize on this per-case lock.
        """
        with cls._instance_lock:
            db_path = get_case_db_path(case_id)
            db_key = str(db_path.resolve()).lower()
            if db_key not in cls._case_locks:
                cls._case_locks[db_key] = threading.RLock()
            return cls._case_locks[db_key]

    @classmethod
    def get_connection(cls, case_id: str, read_only: bool = False) -> duckdb.DuckDBPyConnection:
        """
        Get or open a connection to the case.duckdb file for a given case_id.
        DuckDB connections are thread-safe when using cursors.
        Always maintains a unified read-write connection to eliminate configuration conflicts.
        """
        with cls._instance_lock:
            db_path = get_case_db_path(case_id)
            db_key = str(db_path.resolve()).lower()

            if db_key in cls._connections:
                return cls._connections[db_key]

            # Ensure directory exists before connecting
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = duckdb.connect(database=str(db_path), read_only=False)
            cls._connections[db_key] = conn
            cls._is_read_only[db_key] = False
            return conn

    @classmethod
    def close_connection(cls, case_id: str) -> None:
        """
        Close connection for a given case_id if open.
        Immediately releases all DuckDB PyConnection handles and locks to release .duckdb and .wal files.
        """
        import gc
        with cls._instance_lock:
            try:
                db_path = get_case_db_path(case_id)
                target_key = str(db_path.resolve()).lower()
            except Exception:
                target_key = ""

            keys_to_close = []
            cid_lower = case_id.lower()
            for k in list(cls._connections.keys()):
                if (
                    k == target_key
                    or f"\\{cid_lower}\\" in k
                    or f"/{cid_lower}/" in k
                    or k.endswith(f"\\{cid_lower}")
                    or k.endswith(f"/{cid_lower}")
                    or f"cases\\{cid_lower}" in k
                    or f"cases/{cid_lower}" in k
                ):
                    keys_to_close.append(k)

            if target_key and target_key in cls._connections and target_key not in keys_to_close:
                keys_to_close.append(target_key)

            for k in keys_to_close:
                cls._is_read_only.pop(k, None)
                cls._case_locks.pop(k, None)
                conn = cls._connections.pop(k, None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as ex:
                        print(f"[DuckDBManager] Warning while closing connection for {k}: {ex}")

        # Explicit garbage collection to release OS file handles on Windows
        gc.collect()

    @classmethod
    def close_all(cls) -> None:
        """
        Close all active connections.
        """
        with cls._instance_lock:
            cls._is_read_only.clear()
            cls._case_locks.clear()
            for db_key, conn in list(cls._connections.items()):
                try:
                    conn.close()
                except Exception as ex:
                    print(f"[DuckDBManager] Warning while closing connection for {db_key}: {ex}")
            cls._connections.clear()


def init_case_db(case_id: str) -> Path:
    """
    Initialize cases/<case_id>/case.duckdb with core forensic tables.
    Returns the resolved Path to the initialized database.
    """
    db_path = get_case_db_path(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        init_schema(conn, case_id=case_id)
    return db_path


def validate_table_or_column_name(name: str) -> str:
    """
    Validate that table or column name contains only alphanumeric and underscore characters.
    """
    if not re.match(r"^[A-Za-z0-9_]+$", name):
        raise ValueError(f"Invalid SQL identifier: '{name}'")
    return name


def get_table_columns(case_id: str, table_name: str) -> List[str]:
    """
    Discover column names for a given table via DESCRIBE.
    """
    clean_table = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()
        describe_rows = cursor.execute(f'DESCRIBE "{clean_table}";').fetchall()
        return [str(row[0]) for row in describe_rows]


def query_paginated(
    case_id: str,
    table_name: str,
    limit: int = 500,
    offset: int = 0,
    search: str = "",
    sort_col: str = "_row_id",
    sort_dir: str = "ASC",
    column_filters: Optional[Union[str, Dict[str, List[Any]]]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    tags: Optional[Union[str, List[str]]] = None,
) -> Dict[str, Any]:
    """
    Query paginated records with dynamic multi-column ILIKE search filter, column ordering,
    optional timestamp range, and forensic tags.
    """
    clean_table = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()

        columns = get_table_columns(case_id, clean_table)
        if not columns:
            return {"columns": [], "rows": [], "total_count": 0, "filtered_count": 0}

        # Total count in the table
        total_count = cursor.execute(f'SELECT COUNT(*) FROM "{clean_table}";').fetchone()[0]

        # Validate sorting strictly against DESCRIBE columns
        col_lookup = {c.lower(): c for c in columns}
        sort_direction = "DESC" if str(sort_dir).upper() == "DESC" else "ASC"
        sort_col_clean = str(sort_col).strip().lower()
        if sort_col_clean in col_lookup:
            sort_column = col_lookup[sort_col_clean]
        elif "_row_id" in col_lookup:
            sort_column = col_lookup["_row_id"]
        else:
            sort_column = columns[0]

        # Parse column_filters if provided
        parsed_filters: Dict[str, List[Any]] = {}
        if column_filters:
            if isinstance(column_filters, str) and column_filters.strip():
                try:
                    parsed_filters = json.loads(column_filters)
                except Exception as j_err:
                    print(f"[query_paginated] Warning parsing column_filters JSON: {j_err}")
            elif isinstance(column_filters, dict):
                parsed_filters = column_filters

        # Build WHERE conditions combining search and column_filters with AND
        where_conditions = []
        params: List[Any] = []

        if search and search.strip():
            search_pattern = f"%{search.strip()}%"
            ilike_clauses = [f'CAST("{col}" AS VARCHAR) ILIKE ?' for col in columns]
            where_conditions.append(f"({' OR '.join(ilike_clauses)})")
            params.extend([search_pattern] * len(columns))

        if parsed_filters:
            col_map = {c.lower(): c for c in columns}
            for col_key, filter_vals in parsed_filters.items():
                actual_col = col_map.get(col_key.lower())
                if actual_col and isinstance(filter_vals, (list, tuple, set)) and len(filter_vals) > 0:
                    placeholders = ", ".join(["?"] * len(filter_vals))
                    where_conditions.append(f'CAST("{actual_col}" AS VARCHAR) IN ({placeholders})')
                    params.extend([str(v) for v in filter_vals])

        # Date & Time range filtering across primary timestamp column
        if (start_time and str(start_time).strip()) or (end_time and str(end_time).strip()):
            time_cols = [c for c in columns if any(t in c.lower() for t in ["time", "date", "created", "modified", "lastrun", "timestamp"])]
            if time_cols:
                primary_time_col = next((c for c in time_cols if "timestamp" in c.lower() or "utc" in c.lower() or "created" in c.lower()), time_cols[0])
                if start_time and str(start_time).strip():
                    where_conditions.append(f'TRY_CAST("{primary_time_col}" AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)')
                    params.append(str(start_time).strip())
                if end_time and str(end_time).strip():
                    where_conditions.append(f'TRY_CAST("{primary_time_col}" AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)')
                    params.append(str(end_time).strip())

        # Forensic Tags & Bookmarks filtering
        tag_list: List[str] = []
        if tags:
            if isinstance(tags, str):
                try:
                    loaded = json.loads(tags)
                    if isinstance(loaded, list):
                        tag_list = [str(x) for x in loaded if str(x).strip()]
                    else:
                        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
                except Exception:
                    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
            elif isinstance(tags, (list, tuple, set)):
                tag_list = [str(t) for t in tags if str(t).strip()]

        if tag_list:
            row_id_col = "_row_id" if "_row_id" in columns else ("timeline_id" if "timeline_id" in columns else columns[0])
            placeholders = ", ".join(["?"] * len(tag_list))
            where_conditions.append(
                f'"{row_id_col}" IN (SELECT source_row_id FROM bookmarks WHERE (source_table = ? OR source_table = \'master_timeline\') AND tag_name IN ({placeholders}))'
            )
            params.append(clean_table)
            params.extend(tag_list)

        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""

        # Filtered count
        if where_clause:
            filtered_count = cursor.execute(
                f'SELECT COUNT(*) FROM "{clean_table}" {where_clause};',
                params,
            ).fetchone()[0]
        else:
            filtered_count = total_count

        # Fetch rows
        fetch_query = (
            f'SELECT * FROM "{clean_table}" '
            f'{where_clause} '
            f'ORDER BY "{sort_column}" {sort_direction} '
            f'LIMIT ? OFFSET ?;'
        )
        query_params = params + [limit, offset]
        result_rows = cursor.execute(fetch_query, query_params).fetchall()

        # Convert to list of dicts for JSON serialization
        serialized_rows = [dict(zip(columns, row)) for row in result_rows]
        for s_row in serialized_rows:
            fp_val = s_row.get("file_path")
            if isinstance(fp_val, str) and "staging" in fp_val.lower():
                if not s_row.get("source_file"):
                    s_row["source_file"] = fp_val
                p_norm = fp_val.replace("/", "\\")
                m_u = re.search(r"(?i)\\staging\\UserFiles\\([^\\]+)\\(.+)$", p_norm)
                m_e = re.search(r"(?i)\\staging\\Enrichment\\(.+)$", p_norm)
                if m_u:
                    s_row["file_path"] = f"C:\\Users\\{m_u.group(1)}\\{m_u.group(2)}"
                elif m_e:
                    rest = m_e.group(1)
                    if rest.lower().startswith("userfiles\\"):
                        rest = "Users\\" + rest[10:]
                    s_row["file_path"] = f"C:\\{rest.lstrip('\\')}"

        return {
            "columns": columns,
            "rows": serialized_rows,
            "total_count": total_count,
            "filtered_count": filtered_count,
        }


def log_processing_event(
    case_id: str,
    module_name: str,
    command_executed: str,
    exit_code: int,
    rows_ingested: int,
    duration_ms: int,
    status: str,
    error_message: Optional[str] = None,
) -> None:
    """
    Log an entry to processing_logs and append to cases/<case_id>/processing.log on disk.
    """
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO processing_logs (
                log_id,
                timestamp_utc,
                module_name,
                command_executed,
                exit_code,
                rows_ingested,
                duration_ms,
                status,
                error_message
            ) VALUES (
                nextval('seq_log_id'),
                CURRENT_TIMESTAMP,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            );
            """,
            [
                module_name,
                command_executed,
                exit_code,
                rows_ingested,
                duration_ms,
                status,
                error_message,
            ],
        )

    # Also append to processing.log file
    log_file = get_case_dir(case_id) / "processing.log"
    log_entry = (
        f"[{module_name}] Status={status} ExitCode={exit_code} "
        f"Rows={rows_ingested} Duration={duration_ms}ms | Cmd: {command_executed}"
    )
    if error_message:
        log_entry += f" | Error: {error_message}"
    log_entry += "\n"

    with open(log_file, "a", encoding="utf-8", errors="replace") as f:
        f.write(log_entry)


def get_distinct_column_values(
    case_id: str,
    table_name: str,
    column_name: str,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """
    Run: SELECT CAST("{column_name}" AS VARCHAR) AS val, COUNT(*) AS cnt
    FROM "{table_name}" GROUP BY val ORDER BY cnt DESC LIMIT {limit}
    Validates column_name against table's actual DESCRIBE column set before executing SQL.
    """
    clean_table = validate_table_or_column_name(table_name)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()

        # Validate column name against table's actual DESCRIBE column set
        columns = [str(r[0]) for r in cursor.execute(f'DESCRIBE "{clean_table}";').fetchall()]
        col_lookup = {c.lower(): c for c in columns}
        col_clean = str(column_name).strip().lower()
        if col_clean not in col_lookup:
            raise ValueError(f"Column '{column_name}' not found in table '{clean_table}'. Valid columns: {columns}")
        actual_col = col_lookup[col_clean]

        query = (
            f'SELECT CAST("{actual_col}" AS VARCHAR) AS val, COUNT(*) AS cnt '
            f'FROM "{clean_table}" '
            f'GROUP BY val '
            f'ORDER BY cnt DESC '
            f'LIMIT ?;'
        )
        rows = cursor.execute(query, [limit]).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]


def scan_keywords_for_case(case_id: str, conn: Optional[duckdb.DuckDBPyConnection] = None) -> int:
    """
    Scans all populated forensic tables in case.duckdb against case_keywords,
    populating both `parsed_keyword_hits` (with exact matching evidence rows and snippets)
    and updating `case_keywords.hit_count` and `view_keyword_hits`.
    """
    with DuckDBManager.get_lock(case_id):
        if conn is None:
            conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()

        tables = {
            r[0] for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
            ).fetchall()
        }
        if "case_keywords" not in tables:
            return 0

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS parsed_keyword_hits (
                _row_id BIGINT,
                keyword_id VARCHAR,
                keyword VARCHAR,
                is_regex BOOLEAN,
                artifact_name VARCHAR,
                source_table VARCHAR,
                source_row_id BIGINT,
                matched_snippet VARCHAR,
                source_file VARCHAR,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("DELETE FROM parsed_keyword_hits;")

        cursor.execute("""
            CREATE OR REPLACE VIEW view_keyword_hits AS
            SELECT
                _row_id,
                keyword,
                artifact_name,
                source_table,
                source_row_id,
                matched_snippet,
                source_file,
                detected_at
            FROM parsed_keyword_hits
            ORDER BY _row_id ASC;
        """)

        keywords_rows = cursor.execute(
            "SELECT keyword_id, keyword, is_regex FROM case_keywords;"
        ).fetchall()
        if not keywords_rows:
            cursor.execute("UPDATE artifact_registry SET row_count = 0 WHERE artifact_id = 'refined_keyword_hits';")
            return 0

        all_base_tables = [
            r[0] for r in cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_type = 'BASE TABLE';"
            ).fetchall()
        ]
        excluded = {
            "case_keywords", "parsed_keyword_hits", "bookmarks", "processing_logs",
            "artifact_registry", "file_enrichment", "master_timeline", "entity_connections"
        }
        candidate_tables = [t for t in all_base_tables if t not in excluded and not t.startswith("view_")]

        # Map table_name -> friendly display_name
        disp_map = {}
        if "artifact_registry" in tables:
            for t_n, d_n in cursor.execute("SELECT table_name, display_name FROM artifact_registry;").fetchall():
                disp_map[t_n] = d_n

        hit_row_id = 1
        for kw_id, kw_text, is_regex in keywords_rows:
            kw_str = str(kw_text or "").strip()
            if not kw_str:
                continue
            total_kw_hits = 0

            for tbl in candidate_tables:
                try:
                    row_cnt = cursor.execute(f'SELECT COUNT(*) FROM "{tbl}";').fetchone()[0]
                    if row_cnt == 0:
                        continue
                    col_names = [r[0] for r in cursor.execute(f'DESCRIBE "{tbl}";').fetchall()]
                    if not col_names:
                        continue

                    id_col = "_row_id" if "_row_id" in col_names else col_names[0]
                    src_col = next((c for c in col_names if c.lower() in ("source_file", "sourcefile", "sourcefilename", "file_path")), None)
                    src_expr = f'CAST("{src_col}" AS VARCHAR)' if src_col else "''"
                    text_cols = [c for c in col_names if c != "_row_id"]
                    if not text_cols:
                        continue
                    col_concat = "CONCAT_WS(' | ', " + ", ".join([f'COALESCE(CAST("{c}" AS VARCHAR), '')' for c in text_cols[:12]]) + ")"

                    if is_regex:
                        where_sql = f"regexp_matches({col_concat}, ?)"
                        param = kw_str
                    else:
                        where_sql = f"{col_concat} ILIKE ?"
                        param = f"%{kw_str}%"

                    cnt_this_tbl = cursor.execute(
                        f'SELECT COUNT(*) FROM "{tbl}" WHERE {where_sql};',
                        [param],
                    ).fetchone()[0]
                    total_kw_hits += int(cnt_this_tbl or 0)

                    if cnt_this_tbl > 0:
                        matched_samples = cursor.execute(
                            f'SELECT TRY_CAST("{id_col}" AS BIGINT), SUBSTR({col_concat}, 1, 300), {src_expr} '
                            f'FROM "{tbl}" WHERE {where_sql} LIMIT 250;',
                            [param],
                        ).fetchall()
                        art_label = disp_map.get(tbl, tbl.replace("parsed_", "").replace("raw_", "").replace("_", " ").title())
                        batch = []
                        for s_rid, snippet, s_file in matched_samples:
                            batch.append([
                                hit_row_id,
                                str(kw_id),
                                kw_str,
                                bool(is_regex),
                                art_label,
                                tbl,
                                int(s_rid or 0),
                                str(snippet or ""),
                                str(s_file or ""),
                            ])
                            hit_row_id += 1
                        cursor.executemany(
                            """
                            INSERT INTO parsed_keyword_hits (
                                _row_id, keyword_id, keyword, is_regex, artifact_name,
                                source_table, source_row_id, matched_snippet, source_file
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                            """,
                            batch,
                        )
                except Exception as scan_err:
                    print(f"[KeywordScanner] Notice scanning {tbl} for '{kw_str}': {scan_err}")

            cursor.execute(
                "UPDATE case_keywords SET hit_count = ? WHERE keyword_id = ?;",
                [total_kw_hits, kw_id],
            )

        total_hit_rows = cursor.execute("SELECT COUNT(*) FROM parsed_keyword_hits;").fetchone()[0]
        if "artifact_registry" in tables:
            cursor.execute(
                """
                INSERT INTO artifact_registry (
                    artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                ) VALUES ('refined_keyword_hits', 'REFINED RESULTS', 'Keyword Hits', 'view_keyword_hits', 'KeywordScanner', ?, CURRENT_TIMESTAMP)
                ON CONFLICT (artifact_id) DO UPDATE SET
                    row_count = EXCLUDED.row_count,
                    table_name = 'view_keyword_hits',
                    last_updated = CURRENT_TIMESTAMP;
                """,
                [total_hit_rows],
            )
        return int(total_hit_rows)
