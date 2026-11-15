"""
Windows Forensic Toolkit (WFT) DFIR Suite - Dedicated Mozilla Firefox Parser (Fixes B1)
Parses:
  - places.sqlite (moz_places + moz_historyvisits + moz_annos downloads + moz_bookmarks)
  - cookies.sqlite (moz_cookies)
  - formhistory.sqlite (moz_formhistory)
  - logins.json (saved Firefox credentials & signon realms)
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from backend.parsers.base_parser import BaseParser, copy_sqlite_with_wal, prtime_to_datetime


class FirefoxParser(BaseParser):
    """Full Mozilla Firefox artifact parser (no longer a 7-line stub)."""

    def _is_sqlite(self, path: Path) -> bool:
        try:
            if not path.is_file() or path.stat().st_size < 100:
                return False
            with open(path, "rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except OSError:
            return False

    def parse(self) -> Dict[str, int]:
        if not self.staging_dir.exists():
            return {}

        history_recs: List[Dict[str, Any]] = []
        downloads_recs: List[Dict[str, Any]] = []
        bookmarks_recs: List[Dict[str, Any]] = []
        cookies_recs: List[Dict[str, Any]] = []
        form_recs: List[Dict[str, Any]] = []
        logins_recs: List[Dict[str, Any]] = []

        temp_root = Path(tempfile.mkdtemp(prefix="wft_ff_"))
        try:
            for fp in sorted(self.staging_dir.rglob("*")):
                if not fp.is_file():
                    continue
                fname = fp.name.lower()
                profile = fp.parent.name

                if (fname == "places.sqlite" or fname.endswith("_places.sqlite")) and self._is_sqlite(fp):
                    tmp_db = copy_sqlite_with_wal(fp, temp_root / f"p_{id(fp)}")
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                        if "moz_places" in tables and "moz_historyvisits" in tables:
                            for url, title, v_cnt, v_date, v_type in cur.execute(
                                "SELECT p.url, p.title, p.visit_count, v.visit_date, v.visit_type "
                                "FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id WHERE p.url IS NOT NULL"
                            ).fetchall():
                                history_recs.append({
                                    "browser": "Firefox",
                                    "profile": profile,
                                    "url": str(url),
                                    "title": str(title) if title else None,
                                    "visit_count": int(v_cnt or 1),
                                    "visit_time": prtime_to_datetime(v_date),
                                    "visit_type": str(v_type or "LINK"),
                                    "source_file": str(fp),
                                })
                        if "moz_bookmarks" in tables and "moz_places" in tables:
                            for title, url, d_add, l_mod in cur.execute(
                                "SELECT b.title, p.url, b.dateAdded, b.lastModified "
                                "FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE p.url IS NOT NULL"
                            ).fetchall():
                                bookmarks_recs.append({
                                    "title": str(title or url),
                                    "url": str(url),
                                    "date_added": prtime_to_datetime(d_add),
                                    "last_modified": prtime_to_datetime(l_mod),
                                    "source_file": str(fp),
                                })
                        conn.close()
                    except Exception as ex:
                        self._log(f"Firefox places.sqlite error on {fp}: {ex}", "WARNING")

                elif (fname == "cookies.sqlite" or fname.endswith("_cookies.sqlite")) and self._is_sqlite(fp):
                    tmp_db = copy_sqlite_with_wal(fp, temp_root / f"c_{id(fp)}")
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        for host, name, val, path, c_t, exp_t, la_t, sec, http in cur.execute(
                            "SELECT host, name, value, path, creationTime, expiry, lastAccessed, isSecure, isHttpOnly FROM moz_cookies"
                        ).fetchall():
                            cookies_recs.append({
                                "host": str(host or ""),
                                "name": str(name or ""),
                                "value": str(val) if val is not None else None,
                                "path": str(path or "/"),
                                "creation_time": prtime_to_datetime(c_t),
                                "expiry_time": prtime_to_datetime(exp_t),
                                "last_accessed": prtime_to_datetime(la_t),
                                "is_secure": bool(sec),
                                "is_httponly": bool(http),
                                "source_file": str(fp),
                            })
                        conn.close()
                    except Exception as ex:
                        self._log(f"Firefox cookies.sqlite error on {fp}: {ex}", "WARNING")

                elif (fname == "formhistory.sqlite" or fname.endswith("_formhistory.sqlite")) and self._is_sqlite(fp):
                    tmp_db = copy_sqlite_with_wal(fp, temp_root / f"f_{id(fp)}")
                    try:
                        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
                        cur = conn.cursor()
                        for fname_col, val, t_used, f_used, l_used in cur.execute(
                            "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory"
                        ).fetchall():
                            form_recs.append({
                                "fieldname": str(fname_col or ""),
                                "value": str(val or ""),
                                "times_used": int(t_used or 1),
                                "first_used": prtime_to_datetime(f_used),
                                "last_used": prtime_to_datetime(l_used),
                                "source_file": str(fp),
                            })
                        conn.close()
                    except Exception as ex:
                        self._log(f"Firefox formhistory.sqlite error on {fp}: {ex}", "WARNING")

                elif fname == "logins.json" or fname.endswith("_logins.json"):
                    try:
                        data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                        for item in data.get("logins", []):
                            logins_recs.append({
                                "hostname": str(item.get("hostname") or ""),
                                "httpRealm": str(item.get("httpRealm") or ""),
                                "formSubmitURL": str(item.get("formSubmitURL") or ""),
                                "usernameField": str(item.get("usernameField") or ""),
                                "encryptedUsername": str(item.get("encryptedUsername") or "")[:60],
                                "timeCreated": prtime_to_datetime(item.get("timeCreated")),
                                "timeLastUsed": prtime_to_datetime(item.get("timeLastUsed")),
                                "timePasswordChanged": prtime_to_datetime(item.get("timePasswordChanged")),
                                "timesUsed": int(item.get("timesUsed") or 0),
                                "source_file": str(fp),
                            })
                    except Exception as ex:
                        self._log(f"Firefox logins.json notice on {fp}: {ex}", "WARNING")
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

        results: Dict[str, int] = {}
        for tbl, recs, aid, disp in [
            ("parsed_firefox_history", history_recs, "firefox_history", "Firefox Web History"),
            ("parsed_firefox_downloads", downloads_recs, "firefox_downloads", "Firefox Downloads"),
            ("parsed_firefox_bookmarks", bookmarks_recs, "firefox_bookmarks", "Firefox Bookmarks"),
            ("parsed_firefox_cookies", cookies_recs, "firefox_cookies", "Firefox Cookies"),
            ("parsed_firefox_formhistory", form_recs, "firefox_formhistory", "Firefox FormHistory"),
            ("parsed_firefox_logins", logins_recs, "firefox_logins", "Firefox Saved Logins"),
        ]:
            if recs:
                results[tbl] = self.insert_records(
                    table_name=tbl,
                    records=recs,
                    artifact_id=aid,
                    category="WEB RELATED",
                    display_name=disp,
                    source_tool="FirefoxParser",
                )
        return results
