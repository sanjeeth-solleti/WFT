"""
WFT v4.0 - Portable HTML Case Report Generator
Generates a self-contained, defensive, XSS-safe HTML forensic case report including:
  - Case Metadata & Source Image Hash Manifest (case_metadata + case_manifest.json)
  - Executive KPI Summary & Chronological Super-Timeline Activity Window
  - Evidence Volumes & Volume Shadow Copies (vfs_partitions + vfs_shadow_copies)
  - Data Carving & Bulk Extractor Summary (parsed_carved_files + parsed_bulk_extractor_*)
  - Malware, YARA-X & Threat Detections (view_all_malware_detections / backing tables)
  - Deduplicated Populated Artifact Coverage (artifact_registry)
  - Examiner Bookmarks & Tagged Findings (bookmarks)
  - External Toolchain Status (get_tool_paths_status) & Pipeline Telemetry (processing_logs)
"""
from __future__ import annotations

from datetime import datetime, timezone
import html
import json
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from backend.config import get_case_dir, get_tool_paths_status
except ImportError:
    from backend.config import get_case_dir, get_tool_paths as get_tool_paths_status

from backend.db.engine import DuckDBManager

_INTERNAL_BACKING_TABLES: Set[str] = {
    "view_all_malware_detections",
    "parsed_media_exif",
    "parsed_documents_metadata",
    "parsed_browser_history",
    "parsed_browser_downloads",
    "parsed_browser_logins",
}


def _esc(val: Any, default: str = "&mdash;") -> str:
    if val is None:
        return default
    s = str(val).strip()
    return html.escape(s, quote=True) if s else default


def _fmt_bytes(val: Any) -> str:
    try:
        num = int(val)
    except (TypeError, ValueError):
        return _esc(val)
    if num < 0:
        return _esc(val)
    if num < 1024:
        return f"{num:,} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    if num < 1024 * 1024 * 1024:
        return f"{num / (1024 * 1024):.2f} MB"
    return f"{num / (1024 * 1024 * 1024):.2f} GB"


def _safe_int(val: Any, default: int = 0) -> int:
    if val is None or isinstance(val, bool):
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    s = str(val).strip().replace(",", "")
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        try:
            return int(float(s))
        except (ValueError, OverflowError):
            return default


def _is_present(val: Any) -> bool:
    if val is None:
        return False
    if isinstance(val, str) and val.strip() == "":
        return False
    return True


def _fmt_carved_path_cell(c: Dict[str, Any]) -> str:
    base = f"<code>{_esc(c.get('carved_rel_path'))}</code>"
    off = c.get("offset_bytes")
    if off is not None:
        return f"{base} <small>(@{_fmt_bytes(off)})</small>"
    return base


def _quote_ident(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


def _get_existing_tables(cur: Any) -> Set[str]:
    try:
        rows = cur.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
        ).fetchall()
        return {str(r[0]) for r in rows if r and r[0]}
    except Exception:
        return set()


def _get_columns(cur: Any, table_name: str) -> Dict[str, str]:
    try:
        rows = cur.execute(f"DESCRIBE {_quote_ident(table_name)};").fetchall()
        return {str(r[0]).lower(): str(r[0]) for r in rows if r and r[0]}
    except Exception:
        return {}


def _safe_count(cur: Any, tables: Set[str], table_name: str) -> int:
    if table_name not in tables:
        return 0
    try:
        row = cur.execute(f"SELECT COUNT(*) FROM {_quote_ident(table_name)};").fetchone()
        return _safe_int(row[0]) if row else 0
    except Exception:
        return 0


def _fetch_dicts(
    cur: Any,
    tables: Set[str],
    table_name: str,
    wanted_cols: List[Tuple[str, List[str]]],
    order_candidates: Optional[List[Tuple[str, str]]] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    if table_name not in tables:
        return []
    col_map = _get_columns(cur, table_name)
    if not col_map:
        return []

    needed_actual_cols: List[str] = []
    needed_seen: Set[str] = set()
    key_to_actuals: List[Tuple[str, List[str]]] = []

    for out_key, candidates in wanted_cols:
        matched_actuals: List[str] = []
        seen_for_key: Set[str] = set()
        for cand in candidates:
            actual = col_map.get(cand.lower())
            if actual and actual.lower() not in seen_for_key:
                seen_for_key.add(actual.lower())
                matched_actuals.append(actual)
                if actual.lower() not in needed_seen:
                    needed_seen.add(actual.lower())
                    needed_actual_cols.append(actual)
        key_to_actuals.append((out_key, matched_actuals))

    select_sql = (
        ", ".join(_quote_ident(col) for col in needed_actual_cols)
        if needed_actual_cols
        else "NULL"
    )

    numeric_order_cols = {
        "count",
        "row_count",
        "size_bytes",
        "offset_bytes",
        "byte_offset",
        "part_index",
        "partition_index",
        "vss_index",
        "store_index",
        "log_id",
    }
    order_sql = ""
    if order_candidates:
        order_parts: List[str] = []
        seen_order: Set[str] = set()
        for cand_col, direction in order_candidates:
            actual = col_map.get(cand_col.lower())
            if actual and actual.lower() not in seen_order:
                seen_order.add(actual.lower())
                dir_clean = "DESC" if direction.upper() == "DESC" else "ASC"
                q_actual = _quote_ident(actual)
                if cand_col.lower() in numeric_order_cols:
                    order_parts.append(f"TRY_CAST({q_actual} AS DOUBLE) {dir_clean} NULLS LAST")
                else:
                    order_parts.append(f"{q_actual} {dir_clean} NULLS LAST")
        if order_parts:
            order_sql = " ORDER BY " + ", ".join(order_parts)

    sql = f"SELECT {select_sql} FROM {_quote_ident(table_name)}{order_sql} LIMIT {_safe_int(limit, 200)};"
    try:
        rows = cur.execute(sql).fetchall()
    except Exception:
        return []

    col_idx = {col: idx for idx, col in enumerate(needed_actual_cols)}
    out: List[Dict[str, Any]] = []
    for raw_row in rows:
        item: Dict[str, Any] = {}
        for out_key, matched_actuals in key_to_actuals:
            chosen: Any = None
            for actual in matched_actuals:
                val = raw_row[col_idx[actual]]
                if _is_present(val):
                    chosen = val
                    break
            item[out_key] = chosen
        out.append(item)
    return out


def generate_case_html_report(case_id: str) -> str:
    case_dir = get_case_dir(case_id)
    manifest_path = case_dir / "case_manifest.json"
    meta: Dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                meta.update(loaded)
        except Exception:
            pass

    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cur = conn.cursor()
        tables = _get_existing_tables(cur)

        # 1. Case Metadata
        if "case_metadata" in tables:
            cm_cols = _get_columns(cur, "case_metadata")
            if "key" in cm_cols and "value" in cm_cols:
                try:
                    for k, v in cur.execute(
                        f'SELECT {_quote_ident(cm_cols["key"])}, {_quote_ident(cm_cols["value"])} FROM "case_metadata";'
                    ).fetchall():
                        if k is not None and v is not None and str(v).strip() != "":
                            meta[str(k)] = v
                except Exception:
                    pass

        # 2. Artifact Registry & Deduplicated Evidence Row Count
        reg_dicts = _fetch_dicts(
            cur,
            tables,
            "artifact_registry",
            [
                ("artifact_id", ["artifact_id"]),
                ("category", ["category"]),
                ("display_name", ["display_name"]),
                ("table_name", ["table_name"]),
                ("source_tool", ["source_tool"]),
                ("row_count", ["row_count"]),
                ("last_updated", ["last_updated"]),
            ],
            order_candidates=[("category", "ASC"), ("row_count", "DESC"), ("display_name", "ASC")],
            limit=1000,
        )

        populated: List[Dict[str, Any]] = []
        unpopulated_count = 0
        seen_tables: Set[str] = set()
        has_raw_evtx_counted = any(
            str(r.get("table_name") or "").lower() == "raw_evtx" and _safe_int(r.get("row_count")) > 0
            for r in reg_dicts
        )

        total_distinct_rows = 0
        for r in reg_dicts:
            tname = str(r.get("table_name") or "").strip()
            tlow = tname.lower()
            rcnt = _safe_int(r.get("row_count"))
            if tlow.startswith("view_all_malware"):
                continue
            if rcnt <= 0:
                unpopulated_count += 1
                continue
            if tlow in seen_tables:
                continue
            seen_tables.add(tlow)
            populated.append(r)

            if tlow in _INTERNAL_BACKING_TABLES:
                continue
            if has_raw_evtx_counted and tlow.startswith("view_evtx_"):
                continue
            total_distinct_rows += rcnt

        # 3. Super-Timeline Stats
        tl_total = 0
        tl_min: Optional[Any] = None
        tl_max: Optional[Any] = None
        tl_days = 0
        if "master_timeline" in tables:
            tl_cols = _get_columns(cur, "master_timeline")
            ts_col = tl_cols.get("timestamp_utc")
            if ts_col:
                try:
                    q_ts = _quote_ident(ts_col)
                    tl_row = cur.execute(
                        f"""
                        SELECT
                            COUNT(*),
                            MIN(TRY_CAST({q_ts} AS TIMESTAMP)),
                            MAX(TRY_CAST({q_ts} AS TIMESTAMP)),
                            COUNT(DISTINCT DATE_TRUNC('day', TRY_CAST({q_ts} AS TIMESTAMP)))
                        FROM "master_timeline";
                        """
                    ).fetchone()
                    if tl_row:
                        tl_total = _safe_int(tl_row[0])
                        tl_min = tl_row[1]
                        tl_max = tl_row[2]
                        tl_days = _safe_int(tl_row[3])
                except Exception:
                    tl_total = _safe_count(cur, tables, "master_timeline")
            else:
                tl_total = _safe_count(cur, tables, "master_timeline")

        # 4. Partitions & Volume Shadow Copies
        partitions = _fetch_dicts(
            cur,
            tables,
            "vfs_partitions",
            [
                ("part_index", ["part_index", "partition_index", "addr"]),
                ("label", ["label", "volume_label", "description"]),
                ("fs_type", ["fs_type"]),
                ("offset_bytes", ["offset_bytes", "start_offset_bytes"]),
                ("size_bytes", ["size_bytes"]),
                ("volume_serial", ["volume_serial", "serial_number"]),
                ("is_boot", ["is_boot", "is_bootable"]),
            ],
            order_candidates=[("part_index", "ASC"), ("partition_index", "ASC")],
            limit=100,
        )

        shadow_copies = _fetch_dicts(
            cur,
            tables,
            "vfs_shadow_copies",
            [
                ("vss_index", ["vss_index", "store_index"]),
                ("part_index", ["part_index", "partition_index"]),
                ("store_id", ["store_id", "vss_id", "shadow_copy_guid", "volume_guid"]),
                ("creation_time", ["creation_time", "creation_time_utc"]),
                ("size_bytes", ["size_bytes", "shadow_copy_size", "store_size_bytes"]),
                ("files_staged", ["files_staged"]),
                ("status", ["status"]),
            ],
            order_candidates=[("vss_index", "ASC"), ("store_index", "ASC")],
            limit=100,
        )

        # 5. Data Carving & Bulk Extractor
        carved_total = _safe_count(cur, tables, "parsed_carved_files")
        carved_validated = 0
        carved_bytes_total = 0
        carved_by_type: List[Tuple[str, int]] = []
        if "parsed_carved_files" in tables:
            c_cols = _get_columns(cur, "parsed_carved_files")
            try:
                if "validated" in c_cols:
                    v_row = cur.execute(
                        f'SELECT COUNT(*) FROM "parsed_carved_files" WHERE TRY_CAST({_quote_ident(c_cols["validated"])} AS BOOLEAN) = TRUE;'
                    ).fetchone()
                    carved_validated = _safe_int(v_row[0]) if v_row else 0
                if "size_bytes" in c_cols:
                    b_row = cur.execute(
                        f'SELECT COALESCE(SUM(TRY_CAST({_quote_ident(c_cols["size_bytes"])} AS BIGINT)), 0) FROM "parsed_carved_files";'
                    ).fetchone()
                    carved_bytes_total = _safe_int(b_row[0]) if b_row else 0
                ft_col = c_cols.get("file_type") or c_cols.get("extension")
                if ft_col:
                    carved_by_type = [
                        (str(r[0] or "unknown"), _safe_int(r[1]))
                        for r in cur.execute(
                            f'SELECT {_quote_ident(ft_col)}, COUNT(*) AS cnt FROM "parsed_carved_files" '
                            f'GROUP BY 1 ORDER BY cnt DESC LIMIT 15;'
                        ).fetchall()
                    ]
            except Exception:
                pass

        carved_rows = _fetch_dicts(
            cur,
            tables,
            "parsed_carved_files",
            [
                ("carve_id", ["carve_id", "file_name"]),
                ("file_type", ["file_type", "extension", "mime_type"]),
                ("offset_bytes", ["offset_bytes", "byte_offset"]),
                ("size_bytes", ["size_bytes"]),
                ("sha256", ["sha256", "md5"]),
                ("carved_rel_path", ["carved_rel_path", "carved_path", "file_path", "file_name"]),
                ("validated", ["validated", "is_unallocated"]),
            ],
            order_candidates=[("size_bytes", "DESC"), ("offset_bytes", "ASC"), ("byte_offset", "ASC")],
            limit=50,
        )

        be_features_total = _safe_count(cur, tables, "parsed_bulk_extractor_features")
        be_scanner_counts: List[Tuple[str, int]] = []
        if "parsed_bulk_extractor_features" in tables:
            be_cols = _get_columns(cur, "parsed_bulk_extractor_features")
            if "scanner" in be_cols:
                try:
                    be_scanner_counts = [
                        (str(r[0] or "unknown"), _safe_int(r[1]))
                        for r in cur.execute(
                            f'SELECT {_quote_ident(be_cols["scanner"])}, COUNT(*) AS cnt '
                            f'FROM "parsed_bulk_extractor_features" GROUP BY 1 ORDER BY cnt DESC LIMIT 15;'
                        ).fetchall()
                    ]
                except Exception:
                    pass

        be_top_histograms = _fetch_dicts(
            cur,
            tables,
            "parsed_bulk_extractor_histograms",
            [
                ("scanner", ["scanner"]),
                ("feature", ["feature"]),
                ("count", ["count"]),
                ("source_file", ["source_file"]),
            ],
            order_candidates=[("count", "DESC")],
            limit=30,
        )
        be_top_histograms.sort(key=lambda h: _safe_int(h.get("count")), reverse=True)

        # 6. Enrichment & Malware Detections
        enrichment_cnt = _safe_count(cur, tables, "file_enrichment")
        yara_cnt = _safe_count(cur, tables, "artifact_yara_hits")
        stinger_cnt = _safe_count(cur, tables, "artifact_stinger_hits")

        malware_rows: List[Dict[str, Any]] = []
        if "view_all_malware_detections" in tables:
            total_malware_cnt = _safe_count(cur, tables, "view_all_malware_detections")
            malware_rows = _fetch_dicts(
                cur,
                tables,
                "view_all_malware_detections",
                [
                    ("file_name", ["file_name"]),
                    ("file_path", ["file_path"]),
                    ("sha256", ["sha256"]),
                    ("detection_name", ["detection_name", "threat_name", "malware_name", "rule_name"]),
                    ("detection_type", ["detection_type"]),
                    ("engine", ["engine"]),
                    ("details", ["details"]),
                    ("scanned_at", ["scanned_at"]),
                ],
                order_candidates=[("scanned_at", "DESC")],
                limit=200,
            )
        else:
            total_malware_cnt = yara_cnt + stinger_cnt
            s_rows = _fetch_dicts(
                cur,
                tables,
                "artifact_stinger_hits",
                [
                    ("file_name", ["file_name"]),
                    ("file_path", ["file_path"]),
                    ("sha256", ["sha256"]),
                    ("detection_name", ["malware_name"]),
                    ("detection_type", ["detection_type"]),
                    ("engine", ["engine"]),
                    ("details", ["details"]),
                    ("scanned_at", ["scanned_at"]),
                ],
                order_candidates=[("scanned_at", "DESC")],
                limit=100,
            )
            for sr in s_rows:
                if not sr.get("engine"):
                    sr["engine"] = "Trellix Stinger"
            y_rows = _fetch_dicts(
                cur,
                tables,
                "artifact_yara_hits",
                [
                    ("file_name", ["file_name"]),
                    ("file_path", ["file_path"]),
                    ("sha256", ["sha256"]),
                    ("detection_name", ["rule_name"]),
                    ("detection_type", ["category"]),
                    ("details", ["description"]),
                    ("scanned_at", ["scanned_at"]),
                ],
                order_candidates=[("scanned_at", "DESC")],
                limit=100,
            )
            for yr in y_rows:
                yr["engine"] = "YARA-X"
                yr["detection_type"] = yr.get("detection_type") or "YARA-X Rule Match"
            malware_rows = s_rows + y_rows

        # 7. Bookmarks
        bookmarks = _fetch_dicts(
            cur,
            tables,
            "bookmarks",
            [
                ("bookmark_id", ["bookmark_id"]),
                ("source_table", ["source_table"]),
                ("source_row_id", ["source_row_id"]),
                ("tag_name", ["tag_name"]),
                ("examiner_notes", ["examiner_notes"]),
                ("created_at", ["created_at"]),
            ],
            order_candidates=[("created_at", "DESC")],
            limit=500,
        )

        # 8. Processing Logs
        proc_logs = _fetch_dicts(
            cur,
            tables,
            "processing_logs",
            [
                ("module_name", ["module_name", "module"]),
                ("status", ["status"]),
                ("rows_ingested", ["rows_ingested", "rows", "row_count"]),
                ("duration_ms", ["duration_ms", "elapsed_ms"]),
                ("exit_code", ["exit_code"]),
                ("error_message", ["error_message", "error"]),
            ],
            order_candidates=[("log_id", "ASC"), ("timestamp_utc", "ASC")],
            limit=300,
        )

    # 9. External Toolchain Health (outside DB lock)
    tool_status_dict: Dict[str, Any] = {}
    try:
        raw_tools = get_tool_paths_status()
        if isinstance(raw_tools, dict):
            tool_status_dict = raw_tools
    except Exception:
        tool_status_dict = {}

    main_tools: List[Tuple[str, Dict[str, Any]]] = []
    ez_found = 0
    ez_total = 0
    for t_key, t_val in tool_status_dict.items():
        if not isinstance(t_val, dict):
            continue
        cat = str(t_val.get("category") or "main")
        st = str(t_val.get("status") or "UNKNOWN").upper()
        if cat == "individual_ez":
            ez_total += 1
            if st == "FOUND":
                ez_found += 1
        else:
            main_tools.append((t_key, t_val))

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Render Metadata Table
    case_name = _esc(meta.get("case_name") or case_id)
    case_number = _esc(meta.get("case_number"))
    examiner = _esc(meta.get("examiner"))
    source_path = _esc(meta.get("source_path"))
    source_type = _esc(meta.get("source_type"))
    image_sha256 = _esc(meta.get("sha256"), default="Computed on intake")
    image_size_str = _fmt_bytes(meta["image_size"]) if "image_size" in meta and meta["image_size"] is not None else "&mdash;"
    created_utc = _esc(meta.get("created_utc"))
    max_workers_str = _esc(meta.get("max_workers"))
    flags_summary = (
        f"VSS: {_esc(meta.get('enable_vss', 'false'))} | "
        f"Carving: {_esc(meta.get('enable_data_carving', 'false'))} | "
        f"Bulk Extractor: {_esc(meta.get('enable_bulk_extractor', 'false'))}"
    )
    case_notes = _esc(meta.get("notes"))

    # Render Volumes & VSS
    if partitions:
        part_rows_html = "\n".join(
            f"<tr><td>{_esc(p['part_index'])}</td><td>{_esc(p['label'])}</td>"
            f"<td><code>{_esc(p['fs_type'])}</code></td><td>{_fmt_bytes(p['offset_bytes'])}</td>"
            f"<td>{_fmt_bytes(p['size_bytes'])}</td><td><code>{_esc(p['volume_serial'])}</code></td>"
            f"<td>{_esc(p['is_boot'])}</td></tr>"
            for p in partitions
        )
    else:
        part_rows_html = "<tr><td colspan='7' class='empty'>No partition records recorded for this case.</td></tr>"

    if shadow_copies:
        vss_rows_html = "\n".join(
            f"<tr><td>VSS#{_esc(v['vss_index'])}</td><td>{_esc(v['part_index'])}</td>"
            f"<td><code>{_esc(v['store_id'])}</code></td><td>{_esc(v['creation_time'])}</td>"
            f"<td>{_fmt_bytes(v['size_bytes'])}</td><td>{_esc(v['files_staged'])}</td>"
            f"<td><span class='badge ok'>{_esc(v['status'])}</span></td></tr>"
            for v in shadow_copies
        )
    else:
        vss_rows_html = "<tr><td colspan='7' class='empty'>No Volume Shadow Copies (VSS) enumerated or enabled.</td></tr>"

    # Render Carving & Bulk Extractor
    carve_type_summary = (
        ", ".join(f"{_esc(ft)}: <strong>{cnt:,}</strong>" for ft, cnt in carved_by_type)
        if carved_by_type
        else "None"
    )
    if carved_rows:
        carve_html = "\n".join(
            f"<tr><td><code>{_esc(c['carve_id'])}</code></td><td>{_esc(c['file_type'])}</td>"
            f"<td>{_fmt_bytes(c['size_bytes'])}</td><td><code>{_esc(c['sha256'])}</code></td>"
            f"<td>{_fmt_carved_path_cell(c)}</td>"
            f"<td><span class='badge ok'>{_esc(c['validated'])}</span></td></tr>"
            for c in carved_rows
        )
    else:
        carve_html = "<tr><td colspan='6' class='empty'>No carved files recorded.</td></tr>"

    be_scanner_summary = (
        ", ".join(f"{_esc(sc)}: <strong>{cnt:,}</strong>" for sc, cnt in be_scanner_counts)
        if be_scanner_counts
        else "None"
    )
    if be_top_histograms:
        be_hist_html = "\n".join(
            f"<tr><td><code>{_esc(h['scanner'])}</code></td><td>{_esc(h['feature'])}</td>"
            f"<td style='text-align:right;font-weight:700'>{_safe_int(h.get('count')):,}</td>"
            f"<td><code>{_esc(h['source_file'])}</code></td></tr>"
            for h in be_top_histograms
        )
    else:
        be_hist_html = "<tr><td colspan='4' class='empty'>No Bulk Extractor histogram records recorded.</td></tr>"

    # Render Malware Detections
    malware_badge_html = (
        "<span class='badge ok'>0 DETECTIONS (CLEAN)</span>"
        if total_malware_cnt == 0
        else f"<span class='badge crit'>{total_malware_cnt:,} DETECTIONS FLAGGED</span>"
    )
    if malware_rows:
        malware_html = "\n".join(
            f"<tr><td><strong>{_esc(m.get('detection_name'))}</strong></td>"
            f"<td><span class='badge crit'>{_esc(m.get('engine'))}</span></td>"
            f"<td>{_esc(m.get('detection_type'))}</td>"
            f"<td><code>{_esc(m.get('file_path'))}</code></td>"
            f"<td><code>{_esc(m.get('sha256'))}</code></td>"
            f"<td>{_esc(m.get('details'))}</td></tr>"
            for m in malware_rows
        )
    else:
        malware_html = "<tr><td colspan='6' class='empty'>Zero malware, YARA-X, or threat heuristic detections found.</td></tr>"

    # Render Populated Artifacts
    if populated:
        rows_html = "\n".join(
            f"<tr><td>{_esc(r.get('category'))}</td><td><strong>{_esc(r.get('display_name'))}</strong></td>"
            f"<td><code>{_esc(r.get('table_name'))}</code></td><td>{_esc(r.get('source_tool'))}</td>"
            f"<td style='text-align:right;font-weight:bold;color:#0284c7'>{_safe_int(r.get('row_count')):,}</td>"
            f"<td><span class='badge ok'>PARSED</span></td></tr>"
            for r in populated
        )
    else:
        rows_html = "<tr><td colspan='6' class='empty'>No populated artifact tables recorded yet.</td></tr>"

    # Render Bookmarks (100% HTML-escaped including source_row_id)
    if bookmarks:
        bm_html = "\n".join(
            f"<tr><td><code>{_esc(b.get('source_table'))} #{_esc(b.get('source_row_id'))}</code></td>"
            f"<td><span class='badge warn'>{_esc(b.get('tag_name'))}</span></td>"
            f"<td>{_esc(b.get('examiner_notes'))}</td><td>{_esc(b.get('created_at'))}</td></tr>"
            for b in bookmarks
        )
    else:
        bm_html = "<tr><td colspan='4' class='empty'>No examiner bookmarks recorded yet.</td></tr>"

    # Render Toolchain Health & Processing Telemetry
    if main_tools:
        tool_rows_html = "\n".join(
            f"<tr><td><strong>{_esc(tv.get('name') or tk)}</strong></td>"
            f"<td><code>{_esc(tv.get('env_var'))}</code></td>"
            f"<td><code>{_esc(tv.get('resolved_path') or tv.get('path') or tv.get('configured_path'))}</code></td>"
            f"<td><span class='badge {'ok' if str(tv.get('status', '')).upper() in ('FOUND', 'HEURISTICS READY') else 'warn'}'>"
            f"{_esc(tv.get('status'))}</span></td></tr>"
            for tk, tv in main_tools
        )
        if ez_total > 0:
            tool_rows_html += (
                f"\n<tr><td><strong>Eric Zimmerman Individual CLI Binaries</strong></td>"
                f"<td><code>WFT_EZ_*_EXE</code></td>"
                f"<td>{ez_found} / {ez_total} binaries verified</td>"
                f"<td><span class='badge {'ok' if ez_found == ez_total else 'warn'}'>{ez_found}/{ez_total} FOUND</span></td></tr>"
            )
    else:
        tool_rows_html = "<tr><td colspan='4' class='empty'>Toolchain status unavailable.</td></tr>"

    if proc_logs:
        proc_logs_html = "\n".join(
            f"<tr><td><strong>{_esc(pl.get('module_name'))}</strong></td>"
            f"<td><span class='badge {'ok' if str(pl.get('status') or '').upper() in ('SUCCESS', 'OK', 'COMPLETED', 'DONE') else 'warn'}'>"
            f"{_esc(pl.get('status'))}</span></td>"
            f"<td style='text-align:right'>{_safe_int(pl.get('rows_ingested')):,}</td>"
            f"<td style='text-align:right'>{_safe_int(pl.get('duration_ms')):,} ms</td>"
            f"<td>{_esc(pl.get('error_message'))}</td></tr>"
            for pl in proc_logs
        )
    else:
        proc_logs_html = "<tr><td colspan='5' class='empty'>No pipeline execution telemetry logged yet.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>WFT Forensic Case Report &mdash; {_esc(case_id)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 32px; }}
  .container {{ max-width: 1180px; margin: 0 auto; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 32px; }}
  h1 {{ margin: 0 0 8px 0; font-size: 22px; color: #0f172a; }}
  h2 {{ margin-top: 28px; font-size: 15px; text-transform: uppercase; letter-spacing: 0.05em; color: #0369a1; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }}
  h3 {{ margin-top: 18px; margin-bottom: 6px; font-size: 13px; color: #334155; text-transform: uppercase; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }}
  .card {{ background: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; }}
  .card .lbl {{ font-size: 11px; text-transform: uppercase; color: #475569; font-weight: 700; }}
  .card .val {{ font-size: 20px; font-weight: 800; color: #0f172a; margin-top: 4px; font-family: monospace; }}
  .card .sub {{ font-size: 11px; color: #475569; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12.5px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 7px 10px; text-align: left; vertical-align: top; word-break: break-word; }}
  th {{ background: #f1f5f9; font-weight: 700; text-transform: uppercase; font-size: 11px; color: #334155; }}
  td.empty {{ text-align: center; color: #64748b; font-style: italic; }}
  .badge {{ padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; font-family: monospace; display: inline-block; }}
  .badge.ok {{ background: #dcfce7; color: #166534; }}
  .badge.warn {{ background: #fef3c7; color: #92400e; }}
  .badge.crit {{ background: #fee2e2; color: #991b1b; }}
</style>
</head>
<body>
<div class="container">
  <h1>Windows Forensic Toolkit (WFT) &mdash; Investigative Case Report</h1>
  <p style="color:#475569;font-size:12px;margin:0">
    Case ID: <strong>{_esc(case_id)}</strong> | Case Name: <strong>{case_name}</strong> |
    Generated: <code>{now_utc}</code> | Image SHA-256: <code>{image_sha256}</code>
  </p>

  <table>
    <tbody>
      <tr>
        <th style="width:16%">Case Number</th><td style="width:34%">{case_number}</td>
        <th style="width:16%">Examiner</th><td style="width:34%">{examiner}</td>
      </tr>
      <tr>
        <th>Source Path</th><td><code>{source_path}</code></td>
        <th>Source Type / Size</th><td>{source_type} ({image_size_str})</td>
      </tr>
      <tr>
        <th>Created (UTC)</th><td><code>{created_utc}</code></td>
        <th>Engine Options</th><td>Workers: <code>{max_workers_str}</code> | {flags_summary}</td>
      </tr>
      <tr>
        <th>Examiner Notes</th><td colspan="3">{case_notes}</td>
      </tr>
    </tbody>
  </table>

  <div class="meta-grid">
    <div class="card">
      <div class="lbl">Distinct Evidence Rows</div>
      <div class="val">{total_distinct_rows:,}</div>
      <div class="sub">{len(populated)} active artifact tables</div>
    </div>
    <div class="card">
      <div class="lbl">Super-Timeline Events</div>
      <div class="val">{tl_total:,}</div>
      <div class="sub">Window: {_esc(tl_min)} &rarr; {_esc(tl_max)} ({tl_days:,} active days)</div>
    </div>
    <div class="card">
      <div class="lbl">Files Hashed (SHA-256)</div>
      <div class="val">{enrichment_cnt:,}</div>
      <div class="sub">Carved: {carved_total:,} | Bulk Features: {be_features_total:,}</div>
    </div>
    <div class="card">
      <div class="lbl">Malware &amp; Threat Detections</div>
      <div class="val">{total_malware_cnt:,}</div>
      <div class="sub">Stinger/Heuristics: {stinger_cnt:,} | YARA-X: {yara_cnt:,}</div>
    </div>
  </div>

  <h2>1. Evidence Volumes &amp; Volume Shadow Copies ({len(partitions)} Partitions, {len(shadow_copies)} VSS Snapshots)</h2>
  <table>
    <thead><tr><th>#</th><th>Label</th><th>Filesystem</th><th>Offset</th><th>Size</th><th>Volume Serial</th><th>Boot</th></tr></thead>
    <tbody>{part_rows_html}</tbody>
  </table>
  <h3>Volume Shadow Copies (VSS)</h3>
  <table>
    <thead><tr><th>Snapshot</th><th>Partition</th><th>Store ID</th><th>Creation Time (UTC)</th><th>Size</th><th>Files Staged</th><th>Status</th></tr></thead>
    <tbody>{vss_rows_html}</tbody>
  </table>

  <h2>2. Data Carving &amp; Bulk Extractor Summary ({carved_total:,} Carved / {carved_validated:,} Validated [{_fmt_bytes(carved_bytes_total)}], {be_features_total:,} Features)</h2>
  <p style="font-size:12px;color:#334155;margin:6px 0">
    <strong>Carved Breakdown:</strong> {carve_type_summary} &nbsp;|&nbsp;
    <strong>Bulk Extractor Scanners:</strong> {be_scanner_summary}
  </p>
  <table>
    <thead><tr><th>Carve ID</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Path</th><th>Validated</th></tr></thead>
    <tbody>{carve_html}</tbody>
  </table>
  <h3>Top Bulk Extractor Histogram Artifacts</h3>
  <table>
    <thead><tr><th>Scanner</th><th>Feature / Indicator</th><th>Occurrences</th><th>Source</th></tr></thead>
    <tbody>{be_hist_html}</tbody>
  </table>

  <h2>3. Malware, YARA-X &amp; Threat Detections &nbsp; {malware_badge_html}</h2>
  <table>
    <thead><tr><th>Detection / Rule</th><th>Engine</th><th>Category / Type</th><th>Logical File Path</th><th>SHA-256</th><th>Details</th></tr></thead>
    <tbody>{malware_html}</tbody>
  </table>

  <h2>4. Populated Artifact Coverage ({len(populated)} Active Tables, {unpopulated_count} Unpopulated/Skipped)</h2>
  <table>
    <thead><tr><th>Category</th><th>Artifact Name</th><th>DuckDB Table</th><th>Parser / Engine</th><th>Row Count</th><th>Status</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>

  <h2>5. Examiner Bookmarks &amp; Tagged Findings ({len(bookmarks)})</h2>
  <table>
    <thead><tr><th>Source Record</th><th>Tag</th><th>Examiner Notes</th><th>Timestamp (UTC)</th></tr></thead>
    <tbody>{bm_html}</tbody>
  </table>

  <h2>6. External Toolchain Health &amp; Pipeline Telemetry ({len(proc_logs)} Modules Logged)</h2>
  <table>
    <thead><tr><th>Forensic Tool Suite</th><th>Env Variable</th><th>Resolved Path / Summary</th><th>Status</th></tr></thead>
    <tbody>{tool_rows_html}</tbody>
  </table>
  <h3>Module Execution Telemetry</h3>
  <table>
    <thead><tr><th>Module</th><th>Status</th><th>Rows Ingested</th><th>Duration</th><th>Error / Diagnostic</th></tr></thead>
    <tbody>{proc_logs_html}</tbody>
  </table>
</div>
</body>
</html>"""
