"""
Windows Forensic Toolkit (WFT) DFIR Suite - Unified Hindsight & Multi-Browser Parser
Extracts History, Downloads, Cache Records, Cookies, Bookmarks, Autofill, and Logins
across Chrome, Edge, Brave, and Firefox into granular per-browser tables under WEB RELATED.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    prtime_to_datetime,
    webkit_to_datetime,
)

try:
    import pyhindsight
    from pyhindsight.analysis import AnalysisSession
except ImportError:
    AnalysisSession = None


class ChromiumParser(BaseParser):
    """
    Unified Browser Forensics Engine (Hindsight + WAL-safe SQLite + Simple Cache parser).
    Populates per-browser tables for Chrome, Edge, Brave, and Firefox:
      - parsed_<browser>_history
      - parsed_<browser>_downloads
      - parsed_<browser>_cache
      - parsed_<browser>_cookies
      - parsed_<browser>_bookmarks
      - parsed_<browser>_autofill
      - parsed_<browser>_search_terms
      - parsed_<browser>_logins
    """

    def _detect_browser_and_profile(self, file_path: Path) -> Tuple[str, str]:
        p_str = str(file_path).lower().replace("\\", "/")
        if "firefox" in p_str or file_path.name.lower() in ("places.sqlite", "cookies.sqlite", "formhistory.sqlite"):
            browser = "firefox"
        elif "brave" in p_str:
            browser = "brave"
        elif "edge" in p_str or "msedge" in p_str:
            browser = "edge"
        else:
            browser = "chrome"

        profile = "Default"
        for part in reversed(file_path.parts[:-1]):
            pl = part.lower()
            if pl in ("default", "guest profile") or pl.startswith("profile") or ".default" in pl:
                profile = part
                break
            if pl not in ("user data", "browsers", "chrome", "edge", "brave", "firefox", "network", "cache", "cache_data", "entries", "cache2"):
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
                "downloads": [],
                "cache": [],
                "cookies": [],
                "bookmarks": [],
                "autofill": [],
                "search_terms": [],
                "logins": [],
            }
            for b in ("chrome", "edge", "brave", "firefox")
        }

        temp_root = Path(tempfile.mkdtemp(prefix="wft_browsers_"))
        try:
            for file_path in self.staging_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                fname = file_path.name.lower()
                if fname.endswith(("-wal", "-shm", "-journal")):
                    continue

                b_key, profile = self._detect_browser_and_profile(file_path)
                b_label = b_key.capitalize()

                # 1. Chromium History, Downloads & Keyword Search Terms
                if (fname == "history" or fname.endswith("_history")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"h_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

                        if "urls" in tables and "visits" in tables:
                            for url, title, v_cnt, t_cnt, v_time, from_v, trans in cur.execute(
                                "SELECT u.url, u.title, u.visit_count, u.typed_count, v.visit_time, v.from_visit, v.transition "
                                "FROM visits v JOIN urls u ON v.url = u.id WHERE u.url IS NOT NULL AND TRIM(u.url) != ''"
                            ).fetchall():
                                dt = webkit_to_datetime(v_time)
                                if dt:
                                    buckets[b_key]["history"].append({
                                        "browser": b_label,
                                        "profile": profile,
                                        "url": str(url),
                                        "title": str(title) if title else "—",
                                        "visit_count": int(v_cnt or 1),
                                        "typed_count": int(t_cnt or 0),
                                        "visit_time": dt,
                                        "from_visit": int(from_v or 0),
                                        "transition": "LINK",
                                        "source_file": str(file_path),
                                    })

                        if "downloads" in tables:
                            dl_cols = {r[1] for r in cur.execute("PRAGMA table_info(downloads)").fetchall()}
                            tab_c = "tab_url" if "tab_url" in dl_cols else "''"
                            site_c = "site_url" if "site_url" in dl_cols else ("referrer" if "referrer" in dl_cols else "''")
                            mime_c = "mime_type" if "mime_type" in dl_cols else "''"
                            for t_p, c_p, tab_u, site_u, tot_b, rec_b, s_t, e_t, mime in cur.execute(
                                f"SELECT target_path, current_path, {tab_c}, {site_c}, total_bytes, received_bytes, start_time, end_time, {mime_c} FROM downloads"
                            ).fetchall():
                                final_p = str(t_p or c_p or "").strip()
                                if final_p:
                                    buckets[b_key]["downloads"].append({
                                        "browser": b_label,
                                        "profile": profile,
                                        "target_path": final_p,
                                        "tab_url": str(tab_u or site_u or "—"),
                                        "site_url": str(site_u or tab_u or "—"),
                                        "total_bytes": int(tot_b or 0),
                                        "received_bytes": int(rec_b or 0),
                                        "start_time": webkit_to_datetime(s_t),
                                        "end_time": webkit_to_datetime(e_t),
                                        "mime_type": str(mime or "application/octet-stream"),
                                        "danger_type": "NOT_DANGEROUS",
                                        "state": "COMPLETE",
                                        "opened": 0,
                                        "source_file": str(file_path),
                                    })

                        if "keyword_search_terms" in tables and "urls" in tables:
                            for term, norm_t, url, lvt in cur.execute(
                                "SELECT k.term, k.normalized_term, u.url, u.last_visit_time "
                                "FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id WHERE k.term IS NOT NULL"
                            ).fetchall():
                                buckets[b_key]["search_terms"].append({
                                    "term": str(term),
                                    "normalized_term": str(norm_t or term),
                                    "url": str(url or "—"),
                                    "visit_time": webkit_to_datetime(lvt),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception:
                        pass

                # 2. Chromium Cookies
                elif (fname == "cookies" or fname.endswith("_cookies")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"c_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        if ("cookies",) in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                            for host, name, val, path, c_t, exp_t, la_t, sec, http in cur.execute(
                                "SELECT host_key, name, value, path, creation_utc, expires_utc, last_access_utc, is_secure, is_httponly FROM cookies"
                            ).fetchall():
                                buckets[b_key]["cookies"].append({
                                    "host_key": str(host or "—"),
                                    "name": str(name or "—"),
                                    "value": str(val or "(Encrypted)"),
                                    "path": str(path or "/"),
                                    "creation_utc": webkit_to_datetime(c_t),
                                    "expires_utc": webkit_to_datetime(exp_t),
                                    "last_access_utc": webkit_to_datetime(la_t),
                                    "is_secure": bool(sec),
                                    "is_httponly": bool(http),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception:
                        pass

                # 3. Chromium Web Data (Autofill)
                elif (fname == "web data" or fname.endswith("_web data")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"w_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        if ("autofill",) in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                            for name, val, val_low, d_c, d_u, cnt in cur.execute(
                                "SELECT name, value, value_lower, date_created, date_last_used, count FROM autofill WHERE value IS NOT NULL"
                            ).fetchall():
                                buckets[b_key]["autofill"].append({
                                    "name": str(name or "Field"),
                                    "value": str(val),
                                    "value_lower": str(val_low or val).lower(),
                                    "date_created": webkit_to_datetime(d_c) or prtime_to_datetime(d_c),
                                    "date_last_used": webkit_to_datetime(d_u) or prtime_to_datetime(d_u),
                                    "count": int(cnt or 1),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception:
                        pass

                # 4. Chromium Login Data
                elif (fname == "login data" or fname.endswith("_login data")) and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"l_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        if ("logins",) in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                            for orig, act, uname, realm, d_c, d_u, t_u in cur.execute(
                                "SELECT origin_url, action_url, username_value, signon_realm, date_created, date_last_used, times_used FROM logins WHERE origin_url IS NOT NULL"
                            ).fetchall():
                                buckets[b_key]["logins"].append({
                                    "browser": b_label,
                                    "profile": profile,
                                    "origin_url": str(orig),
                                    "action_url": str(act or "—"),
                                    "username_value": str(uname) if uname else "(Saved Credential)",
                                    "signon_realm": str(realm or orig),
                                    "date_created": webkit_to_datetime(d_c),
                                    "date_last_used": webkit_to_datetime(d_u),
                                    "times_used": int(t_u or 0),
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception:
                        pass

                # 5. Chromium Bookmarks JSON
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
                                    "date_modified": webkit_to_datetime(node.get("date_last_used")),
                                    "folder": folder_name,
                                    "source_file": str(file_path),
                                })
                            for ch in node.get("children", []):
                                _walk_bm(ch, str(node.get("name") or folder_name))

                        for rk, rv in roots.items():
                            _walk_bm(rv, rk)
                    except Exception:
                        pass

                # 6. Chromium & Firefox Cache Records (Cache_Data/data_*, f_*, cache2/entries)
                elif (
                    fname.startswith("f_")
                    or fname in ("data_0", "data_1", "data_2", "data_3")
                    or "cache2/entries" in str(file_path).lower().replace("\\", "/")
                ):
                    try:
                        raw = file_path.read_bytes()
                        if len(raw) >= 32:
                            mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                            seen_u = set()
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
                                if len(buckets[b_key]["cache"]) >= 1500:
                                    break
                    except Exception:
                        pass

                # 7. Firefox places.sqlite, cookies.sqlite, formhistory.sqlite
                elif fname == "places.sqlite" and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"ffp_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                        if "moz_places" in tables and "moz_historyvisits" in tables:
                            for url, title, v_cnt, typed, v_date in cur.execute(
                                "SELECT p.url, p.title, p.visit_count, p.typed, v.visit_date FROM moz_places p JOIN moz_historyvisits v ON p.id = v.place_id WHERE p.url IS NOT NULL"
                            ).fetchall():
                                dt = prtime_to_datetime(v_date)
                                if dt:
                                    buckets["firefox"]["history"].append({
                                        "browser": "Firefox",
                                        "profile": profile,
                                        "url": str(url),
                                        "title": str(title) if title else "—",
                                        "visit_count": int(v_cnt or 1),
                                        "typed_count": int(typed or 0),
                                        "visit_time": dt,
                                        "from_visit": 0,
                                        "transition": "VISIT",
                                        "source_file": str(file_path),
                                    })
                        if "moz_bookmarks" in tables and "moz_places" in tables:
                            for title, url, d_add, d_mod in cur.execute(
                                "SELECT b.title, p.url, b.dateAdded, b.lastModified FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE p.url IS NOT NULL AND NOT p.url LIKE 'place:%'"
                            ).fetchall():
                                buckets["firefox"]["bookmarks"].append({
                                    "title": str(title or url),
                                    "url": str(url),
                                    "date_added": prtime_to_datetime(d_add),
                                    "last_modified": prtime_to_datetime(d_mod),
                                    "folder_name": "Firefox Bookmarks",
                                    "source_file": str(file_path),
                                })
                        if "moz_annos" in tables and "moz_anno_attributes" in tables and "moz_places" in tables:
                            for url, content, d_add, d_mod in cur.execute(
                                "SELECT p.url, a.content, a.dateAdded, a.lastModified FROM moz_annos a JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id JOIN moz_places p ON a.place_id = p.id WHERE attr.name LIKE '%destinationFileURI%'"
                            ).fetchall():
                                clean_p = unquote(str(content or "")).replace("file:///", "")
                                buckets["firefox"]["downloads"].append({
                                    "target_path": clean_p,
                                    "url": str(url or "—"),
                                    "total_bytes": 0,
                                    "start_time": prtime_to_datetime(d_add),
                                    "end_time": prtime_to_datetime(d_mod),
                                    "mime_type": "application/octet-stream",
                                    "source_file": str(file_path),
                                })
                        conn.close()
                    except Exception:
                        pass

                elif fname == "cookies.sqlite" and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"ffc_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        for host, name, val, path, exp_t, la_t, c_t, sec, http in cur.execute(
                            "SELECT host, name, value, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly FROM moz_cookies"
                        ).fetchall():
                            buckets["firefox"]["cookies"].append({
                                "host": str(host or "—"),
                                "name": str(name or "—"),
                                "value": str(val or ""),
                                "path": str(path or "/"),
                                "expiry": prtime_to_datetime(exp_t),
                                "last_accessed": prtime_to_datetime(la_t),
                                "creation_time": prtime_to_datetime(c_t),
                                "is_secure": bool(sec),
                                "is_http_only": bool(http),
                                "source_file": str(file_path),
                            })
                        conn.close()
                    except Exception:
                        pass

                elif fname == "formhistory.sqlite" and self._is_sqlite(file_path):
                    sub_tmp = temp_root / f"fff_{id(file_path)}"
                    tmp_db = copy_sqlite_with_wal(file_path, sub_tmp)
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        for fn_c, val, t_u, f_u, l_u in cur.execute(
                            "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory WHERE value IS NOT NULL"
                        ).fetchall():
                            buckets["firefox"]["autofill"].append({
                                "field_name": str(fn_c or "Field"),
                                "value": str(val),
                                "times_used": int(t_u or 1),
                                "first_used": prtime_to_datetime(f_u),
                                "last_used": prtime_to_datetime(l_u),
                                "source_file": str(file_path),
                            })
                        conn.close()
                    except Exception:
                        pass
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

        # Ingest all populated browser buckets into their schema tables
        results: Dict[str, int] = {}
        mapping_specs = [
            # Chrome
            ("chrome", "history", "parsed_chrome_history", "chrome_history", "Chrome Web History"),
            ("chrome", "downloads", "parsed_chrome_downloads", "chrome_downloads", "Chrome Downloads"),
            ("chrome", "cache", "parsed_chrome_cache", "chrome_cache", "Chrome Cache Records"),
            ("chrome", "cookies", "parsed_chrome_cookies", "chrome_cookies", "Chrome Cookies"),
            ("chrome", "bookmarks", "parsed_chrome_bookmarks", "chrome_bookmarks", "Chrome Bookmarks"),
            ("chrome", "autofill", "parsed_chrome_autofill", "chrome_autofill", "Chrome Autofill"),
            ("chrome", "search_terms", "parsed_chrome_search_terms", "chrome_search_terms", "Chrome Keyword Search Terms"),
            ("chrome", "logins", "parsed_chrome_logins", "chrome_logins", "Chrome Logins"),
            # Edge
            ("edge", "history", "parsed_edge_history", "edge_history", "Edge Web History"),
            ("edge", "downloads", "parsed_edge_downloads", "edge_downloads", "Edge Downloads"),
            ("edge", "cache", "parsed_edge_cache", "edge_cache", "Edge Cache Data"),
            ("edge", "cookies", "parsed_edge_cookies", "edge_cookies", "Edge Cookies"),
            ("edge", "search_terms", "parsed_edge_search_terms", "edge_search_terms", "Edge Keyword Search Terms"),
            ("edge", "logins", "parsed_edge_logins", "edge_logins", "Edge Logins"),
            # Brave
            ("brave", "history", "parsed_brave_history", "brave_history", "Brave Web History"),
            ("brave", "downloads", "parsed_brave_downloads", "brave_downloads", "Brave Downloads"),
            ("brave", "cookies", "parsed_brave_cookies", "brave_cookies", "Brave Cookies"),
            ("brave", "logins", "parsed_brave_logins", "brave_logins", "Brave Logins"),
            # Firefox
            ("firefox", "history", "parsed_firefox_history", "firefox_history", "Firefox Web History"),
            ("firefox", "downloads", "parsed_firefox_downloads", "firefox_downloads", "Firefox Downloads"),
            ("firefox", "cookies", "parsed_firefox_cookies", "firefox_cookies", "Firefox Cookies"),
            ("firefox", "bookmarks", "parsed_firefox_bookmarks", "firefox_bookmarks", "Firefox Bookmarks"),
            ("firefox", "autofill", "parsed_firefox_formhistory", "firefox_formhistory", "Firefox FormHistory"),
        ]

        for b_key, sub_key, tbl_name, art_id, disp_name in mapping_specs:
            recs = buckets[b_key][sub_key]
            if recs:
                cnt = self.insert_records(
                    table_name=tbl_name,
                    records=recs,
                    artifact_id=art_id,
                    category="WEB RELATED",
                    display_name=disp_name,
                    source_tool="Hindsight / BrowserEngine",
                )
                results[tbl_name] = cnt

        dur = int((time.time() - start_time) * 1000)
        self._log(f"Unified Browser Parser completed in {dur}ms: {sum(results.values())} rows across {len(results)} tables.")
        return results
