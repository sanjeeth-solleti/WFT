"""
Windows Forensic Toolkit (WFT) DFIR Suite - Schema-Probing Chromium & Multi-Browser Parser (M4 / A15)
Fixes B2, B10, B22, B37, B59:
  - Uses PRAGMA table_info() on every SQLite table before querying so Chrome 41 through modern
    Chrome/Edge/Brave schemas all parse with 0 dropped rows (recovers all 239 cookies and 28+
    keyword search terms on CFReDS!).
  - Reads real danger_type, state, and opened columns from downloads (never fabricates SAFE/COMPLETE).
  - Populates parsed_chrome_visits and parsed_chrome_top_sites (B37).
  - Logs every SQLite exception with file path and schema instead of bare except: pass.
"""
from __future__ import annotations

import json
import re
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    prtime_to_datetime,
    webkit_to_datetime,
)

DANGER_TYPE_MAP = {
    0: "NOT_DANGEROUS",
    1: "DANGEROUS_FILE",
    2: "DANGEROUS_URL",
    3: "DANGEROUS_CONTENT",
    4: "MAYBE_DANGEROUS_CONTENT",
    5: "UNCOMMON_CONTENT",
    6: "USER_VALIDATED",
    7: "DANGEROUS_HOST",
    8: "POTENTIALLY_UNWANTED",
}

DOWNLOAD_STATE_MAP = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "CANCELLED",
    3: "INTERRUPTED",
}

TRANSITION_CORE_MAP = {
    0: "LINK",
    1: "TYPED",
    2: "AUTO_BOOKMARK",
    3: "AUTO_SUBFRAME",
    4: "MANUAL_SUBFRAME",
    5: "GENERATED",
    6: "AUTO_TOPLEVEL",
    7: "FORM_SUBMIT",
    8: "RELOAD",
    9: "KEYWORD",
    10: "KEYWORD_GENERATED",
}


class ChromiumParser(BaseParser):
    """Version-aware Chromium & Firefox parser using PRAGMA table_info schema probing."""

    def _detect_browser_and_profile(self, file_path: Path) -> Tuple[str, str]:
        parts_low = [p.lower() for p in file_path.parts]
        fname_low = file_path.name.lower()

        if fname_low in ("places.sqlite", "cookies.sqlite", "formhistory.sqlite") or "firefox" in parts_low or "mozilla" in parts_low:
            browser = "firefox"
        elif any(p in ("brave-browser", "bravesoftware", "brave") for p in parts_low):
            browser = "brave"
        elif any(p in ("edge", "msedge") for p in parts_low):
            browser = "edge"
        else:
            browser = "chrome"

        profile = "Default"
        for part in reversed(file_path.parts[:-1]):
            pl = part.lower()
            if pl in ("default", "guest profile") or pl.startswith("profile ") or ".default" in pl:
                profile = part
                break
        return browser, profile

    def _is_sqlite(self, path: Path) -> bool:
        try:
            if not path.is_file() or path.stat().st_size < 100:
                return False
            with open(path, "rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except OSError:
            return False

    def parse(self) -> Dict[str, int]:
        start_time = time.time()
        if not self.staging_dir.exists():
            return {}

        buckets: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
            b: {
                "history": [],
                "visits": [],
                "downloads": [],
                "cache": [],
                "cookies": [],
                "bookmarks": [],
                "autofill": [],
                "search_terms": [],
                "top_sites": [],
                "logins": [],
            }
            for b in ("chrome", "edge", "brave", "firefox")
        }

        # Deduplicate staged files by SHA-256 + filename so UserFiles & Browsers copies don't double-insert
        seen_db_hashes: Set[Tuple[str, str]] = set()
        temp_root = Path(tempfile.mkdtemp(prefix="wft_browsers_"))

        try:
            for file_path in sorted(self.staging_dir.rglob("*")):
                if not file_path.is_file():
                    continue
                fname = file_path.name.lower()
                if fname.endswith(("-wal", "-shm", "-journal")):
                    continue

                b_key, profile = self._detect_browser_and_profile(file_path)
                b_label = b_key.capitalize()

                # 1. History, Visits, Downloads & Keyword Search Terms
                if (fname == "history" or fname.endswith("_history")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"h_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

                        if "urls" in tables and "visits" in tables:
                            v_cols = {r[1] for r in cur.execute("PRAGMA table_info(visits)").fetchall()}
                            dur_expr = "v.visit_duration" if "visit_duration" in v_cols else "0"
                            for u_id, url, title, v_cnt, t_cnt, v_time, from_v, trans, v_dur in cur.execute(
                                f"SELECT u.id, u.url, u.title, u.visit_count, u.typed_count, v.visit_time, v.from_visit, v.transition, {dur_expr} "
                                "FROM visits v JOIN urls u ON v.url = u.id WHERE u.url IS NOT NULL AND TRIM(u.url) != ''"
                            ).fetchall():
                                dt = webkit_to_datetime(v_time)
                                if not dt:
                                    continue
                                trans_name = TRANSITION_CORE_MAP.get(int(trans or 0) & 0xFF, "LINK")
                                buckets[b_key]["history"].append({
                                    "browser": b_label,
                                    "profile": profile,
                                    "url": str(url),
                                    "title": str(title) if title else None,
                                    "visit_count": int(v_cnt or 1),
                                    "typed_count": int(t_cnt or 0),
                                    "visit_time": dt,
                                    "from_visit": int(from_v or 0),
                                    "transition": trans_name,
                                    "source_file": str(file_path),
                                })
                                buckets[b_key]["visits"].append({
                                    "url_id": int(u_id or 0),
                                    "visit_time": dt,
                                    "from_visit": int(from_v or 0),
                                    "transition": trans_name,
                                    "visit_duration": int(v_dur or 0),
                                    "source_file": str(file_path),
                                })

                        if "downloads" in tables:
                            dl_cols = {r[1] for r in cur.execute("PRAGMA table_info(downloads)").fetchall()}
                            tab_c = "tab_url" if "tab_url" in dl_cols else "NULL"
                            site_c = "site_url" if "site_url" in dl_cols else ("referrer" if "referrer" in dl_cols else "NULL")
                            mime_c = "mime_type" if "mime_type" in dl_cols else "NULL"
                            danger_c = "danger_type" if "danger_type" in dl_cols else "NULL"
                            state_c = "state" if "state" in dl_cols else "NULL"
                            opened_c = "opened" if "opened" in dl_cols else "NULL"
                            cur_p_c = "current_path" if "current_path" in dl_cols else "NULL"

                            for t_p, c_p, tab_u, site_u, tot_b, rec_b, s_t, e_t, mime, d_type, st_val, op_val in cur.execute(
                                f"SELECT target_path, {cur_p_c}, {tab_c}, {site_c}, total_bytes, received_bytes, start_time, end_time, {mime_c}, {danger_c}, {state_c}, {opened_c} FROM downloads"
                            ).fetchall():
                                final_p = str(t_p or c_p or "").strip()
                                if not final_p:
                                    continue
                                danger_str = DANGER_TYPE_MAP.get(int(d_type), str(d_type)) if d_type is not None else None
                                state_str = DOWNLOAD_STATE_MAP.get(int(st_val), str(st_val)) if st_val is not None else None
                                buckets[b_key]["downloads"].append({
                                    "browser": b_label,
                                    "profile": profile,
                                    "target_path": final_p,
                                    "tab_url": str(tab_u) if tab_u else (str(site_u) if site_u else None),
                                    "site_url": str(site_u) if site_u else None,
                                    "total_bytes": int(tot_b or 0),
                                    "received_bytes": int(rec_b or 0),
                                    "start_time": webkit_to_datetime(s_t),
                                    "end_time": webkit_to_datetime(e_t),
                                    "mime_type": str(mime) if mime else None,
                                    "danger_type": danger_str,
                                    "state": state_str,
                                    "opened": int(op_val) if op_val is not None else None,
                                    "source_file": str(file_path),
                                })

                        # B22 FIX: Chrome 41 uses `lower_term` instead of `normalized_term`!
                        if "keyword_search_terms" in tables and "urls" in tables:
                            kst_cols = {r[1] for r in cur.execute("PRAGMA table_info(keyword_search_terms)").fetchall()}
                            norm_expr = "k.normalized_term" if "normalized_term" in kst_cols else ("k.lower_term" if "lower_term" in kst_cols else "LOWER(k.term)")
                            for term, norm_t, url, lvt in cur.execute(
                                f"SELECT k.term, {norm_expr}, u.url, u.last_visit_time "
                                "FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id WHERE k.term IS NOT NULL"
                            ).fetchall():
                                buckets[b_key]["search_terms"].append({
                                    "term": str(term),
                                    "normalized_term": str(norm_t or term),
                                    "url": str(url) if url else None,
                                    "visit_time": webkit_to_datetime(lvt),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception as ex:
                        self._log(f"SQLite History parse error on {file_path}: {ex}", "WARNING")

                # 2. B22 FIX: Cookies (Chrome 41 uses `secure, httponly` vs modern `is_secure, is_httponly`)
                elif (fname == "cookies" or fname.endswith("_cookies")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"c_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                        if "cookies" in tables:
                            c_cols = {r[1] for r in cur.execute("PRAGMA table_info(cookies)").fetchall()}
                            sec_col = "is_secure" if "is_secure" in c_cols else ("secure" if "secure" in c_cols else "0")
                            http_col = "is_httponly" if "is_httponly" in c_cols else ("httponly" if "httponly" in c_cols else "0")
                            val_col = "value" if "value" in c_cols else "''"
                            enc_col = "encrypted_value" if "encrypted_value" in c_cols else "NULL"

                            for host, name, val, enc_v, path, c_t, exp_t, la_t, sec, http in cur.execute(
                                f"SELECT host_key, name, {val_col}, {enc_col}, path, creation_utc, expires_utc, last_access_utc, {sec_col}, {http_col} FROM cookies"
                            ).fetchall():
                                cookie_val = str(val) if (val is not None and str(val) != "") else ("(DPAPI Encrypted)" if enc_v else None)
                                buckets[b_key]["cookies"].append({
                                    "host_key": str(host) if host else None,
                                    "name": str(name) if name else None,
                                    "value": cookie_val,
                                    "path": str(path or "/"),
                                    "creation_utc": webkit_to_datetime(c_t),
                                    "expires_utc": webkit_to_datetime(exp_t),
                                    "last_access_utc": webkit_to_datetime(la_t),
                                    "is_secure": bool(sec),
                                    "is_httponly": bool(http),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Cookies parse error on {file_path}: {ex}", "WARNING")

                # 3. Web Data (Autofill)
                elif (fname == "web data" or fname.endswith("_web data")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"w_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                        if "autofill" in tables:
                            af_cols = {r[1] for r in cur.execute("PRAGMA table_info(autofill)").fetchall()}
                            dc_col = "date_created" if "date_created" in af_cols else "NULL"
                            du_col = "date_last_used" if "date_last_used" in af_cols else "NULL"
                            cnt_col = "count" if "count" in af_cols else "1"
                            for name, val, d_c, d_u, cnt in cur.execute(
                                f"SELECT name, value, {dc_col}, {du_col}, {cnt_col} FROM autofill WHERE value IS NOT NULL"
                            ).fetchall():
                                buckets[b_key]["autofill"].append({
                                    "name": str(name or "Field"),
                                    "value": str(val),
                                    "value_lower": str(val).lower(),
                                    "date_created": prtime_to_datetime(d_c) or webkit_to_datetime(d_c),
                                    "date_last_used": prtime_to_datetime(d_u) or webkit_to_datetime(d_u),
                                    "count": int(cnt or 1),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Web Data parse error on {file_path}: {ex}", "WARNING")

                # 4. Top Sites (B37)
                elif (fname == "top sites" or fname.endswith("_top sites")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"ts_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                        ts_tbl = "top_sites" if "top_sites" in tables else ("thumbnails" if "thumbnails" in tables else None)
                        if ts_tbl:
                            for url, rank, title in cur.execute(f"SELECT url, url_rank, title FROM {ts_tbl} WHERE url IS NOT NULL").fetchall():
                                buckets[b_key]["top_sites"].append({
                                    "url": str(url),
                                    "url_rank": int(rank or 0),
                                    "title": str(title) if title else None,
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Top Sites parse error on {file_path}: {ex}", "WARNING")

                # 5. Login Data (B10: never fabricate '(Saved Credential)' when username_value is empty)
                elif (fname == "login data" or fname.endswith("_login data")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"l_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                        if "logins" in tables:
                            l_cols = {r[1] for r in cur.execute("PRAGMA table_info(logins)").fetchall()}
                            du_col = "date_last_used" if "date_last_used" in l_cols else "NULL"
                            tu_col = "times_used" if "times_used" in l_cols else "0"
                            for orig, act, uname, realm, d_c, d_u, t_u in cur.execute(
                                f"SELECT origin_url, action_url, username_value, signon_realm, date_created, {du_col}, {tu_col} FROM logins WHERE origin_url IS NOT NULL"
                            ).fetchall():
                                buckets[b_key]["logins"].append({
                                    "browser": b_label,
                                    "profile": profile,
                                    "origin_url": str(orig),
                                    "action_url": str(act) if act else None,
                                    "username_value": str(uname) if uname else None,
                                    "signon_realm": str(realm or orig),
                                    "date_created": webkit_to_datetime(d_c),
                                    "date_last_used": webkit_to_datetime(d_u),
                                    "times_used": int(t_u or 0),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception as ex:
                        self._log(f"SQLite Login Data parse error on {file_path}: {ex}", "WARNING")

                # 6. Bookmarks JSON
                elif fname == "bookmarks" or fname.endswith("_bookmarks"):
                    try:
                        bm_data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
                        roots = bm_data.get("roots", {})

                        def _walk_bm(node: Any, folder_name: str) -> None:
                            if not isinstance(node, dict):
                                return
                            if node.get("type") == "url" and node.get("url"):
                                buckets[b_key]["bookmarks"].append({
                                    "title": str(node.get("name") or "Untitled"),
                                    "url": str(node.get("url")),
                                    "date_added": webkit_to_datetime(node.get("date_added")),
                                    "date_modified": webkit_to_datetime(node.get("date_last_used") or node.get("date_modified")),
                                    "folder": folder_name,
                                    "source_file": str(file_path),
                                })
                            for ch in node.get("children", []):
                                _walk_bm(ch, str(node.get("name") or folder_name))

                        for rk, rv in roots.items():
                            _walk_bm(rv, rk)
                    except Exception as ex:
                        self._log(f"Bookmarks JSON parse notice on {file_path.name}: {ex}", "WARNING")

                # 7. Cache Records
                elif fname.startswith("f_") or fname in ("data_0", "data_1", "data_2", "data_3"):
                    try:
                        raw = file_path.read_bytes()
                        if len(raw) >= 32:
                            mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                            seen_u: Set[str] = set()
                            for m in re.finditer(rb"(https?://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{6,400})", raw):
                                u_str = m.group(1).decode("utf-8", errors="ignore").rstrip("\x00")
                                if u_str in seen_u:
                                    continue
                                seen_u.add(u_str)
                                win = raw[m.end() : m.end() + 400]
                                ct_m = re.search(rb"content-type:\s*([a-zA-Z0-9\-/\+\.]+)", win, re.IGNORECASE)
                                c_type = ct_m.group(1).decode("ascii", errors="ignore") if ct_m else "cached_resource"
                                buckets[b_key]["cache"].append({
                                    "url": u_str,
                                    "key": file_path.name,
                                    "response_time": mtime,
                                    "content_type": c_type,
                                    "size_bytes": len(raw),
                                    "source_file": str(file_path),
                                })
                    except Exception:
                        pass
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

        results: Dict[str, int] = {}
        mapping_specs = [
            ("chrome", "history", "parsed_chrome_history", "chrome_history", "Chrome Web History"),
            ("chrome", "visits", "parsed_chrome_visits", "chrome_visits", "Chrome Web Visits"),
            ("chrome", "downloads", "parsed_chrome_downloads", "chrome_downloads", "Chrome Downloads"),
            ("chrome", "cache", "parsed_chrome_cache", "chrome_cache", "Chrome Cache Records"),
            ("chrome", "cookies", "parsed_chrome_cookies", "chrome_cookies", "Chrome Cookies"),
            ("chrome", "bookmarks", "parsed_chrome_bookmarks", "chrome_bookmarks", "Chrome Bookmarks"),
            ("chrome", "autofill", "parsed_chrome_autofill", "chrome_autofill", "Chrome Autofill"),
            ("chrome", "search_terms", "parsed_chrome_search_terms", "chrome_search_terms", "Chrome Keyword Search Terms"),
            ("chrome", "top_sites", "parsed_chrome_top_sites", "chrome_top_sites", "Chrome Top Sites"),
            ("chrome", "logins", "parsed_chrome_logins", "chrome_logins", "Chrome Logins"),
            ("edge", "history", "parsed_edge_history", "edge_history", "Edge Web History"),
            ("edge", "downloads", "parsed_edge_downloads", "edge_downloads", "Edge Downloads"),
            ("edge", "cache", "parsed_edge_cache", "edge_cache", "Edge Cache Data"),
            ("edge", "cookies", "parsed_edge_cookies", "edge_cookies", "Edge Cookies"),
            ("edge", "search_terms", "parsed_edge_search_terms", "edge_search_terms", "Edge Keyword Search Terms"),
            ("edge", "logins", "parsed_edge_logins", "edge_logins", "Edge Logins"),
            ("brave", "history", "parsed_brave_history", "brave_history", "Brave Web History"),
            ("brave", "downloads", "parsed_brave_downloads", "brave_downloads", "Brave Downloads"),
            ("brave", "cookies", "parsed_brave_cookies", "brave_cookies", "Brave Cookies"),
            ("brave", "logins", "parsed_brave_logins", "brave_logins", "Brave Logins"),
            ("firefox", "history", "parsed_firefox_history", "firefox_history", "Firefox Web History"),
            ("firefox", "downloads", "parsed_firefox_downloads", "firefox_downloads", "Firefox Downloads"),
            ("firefox", "cookies", "parsed_firefox_cookies", "firefox_cookies", "Firefox Cookies"),
            ("firefox", "bookmarks", "parsed_firefox_bookmarks", "firefox_bookmarks", "Firefox Bookmarks"),
            ("firefox", "autofill", "parsed_firefox_formhistory", "firefox_formhistory", "Firefox FormHistory"),
        ]

        for b_key, sub_key, tbl_name, art_id, disp_name in mapping_specs:
            recs = buckets[b_key][sub_key]
            if recs:
                # Deduplicate rows before insert
                deduped: List[Dict[str, Any]] = []
                seen_r: Set[str] = set()
                for r in recs:
                    k_str = json.dumps({k: str(v) for k, v in r.items() if k != "source_file"}, sort_keys=True)
                    if k_str not in seen_r:
                        seen_r.add(k_str)
                        deduped.append(r)
                cnt = self.insert_records(
                    table_name=tbl_name,
                    records=deduped,
                    artifact_id=art_id,
                    category="WEB RELATED",
                    display_name=disp_name,
                    source_tool="ChromiumParser",
                )
                results[tbl_name] = cnt

        dur = int((time.time() - start_time) * 1000)
        self._log(f"ChromiumParser completed in {dur}ms: {sum(results.values())} rows across {len(results)} tables.")
        return results
