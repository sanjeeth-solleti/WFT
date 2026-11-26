r"""
Windows Forensic Toolkit (WFT) DFIR Suite - Multi-Profile Thread-Safe Mozilla Firefox Parser (M3-A / F14.2, F28)
Parses:
  - places.sqlite (moz_places + moz_historyvisits + moz_annos/moz_anno_attributes downloads + moz_bookmarks folder hierarchy)
  - downloads.sqlite (legacy Firefox <26 moz_downloads)
  - cookies.sqlite (moz_cookies with PRAGMA user_version ms/sec expiry & >2100 persistent cookie support)
  - formhistory.sqlite (moz_formhistory)
  - logins.json & signons.sqlite (un-truncated encryptedUsername + encryptedPassword + signon realms)
Aligns both unified F14/F17 columns and existing schema.py/normalizer.py columns under DuckDBManager.get_lock(case_id).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser, copy_sqlite_with_wal, safe_sqlite_text_factory

FF_TRANSITION_MAP: Dict[int, str] = {
    1: "LINK",
    2: "TYPED",
    3: "BOOKMARK",
    4: "EMBED",
    5: "REDIRECT_PERMANENT",
    6: "REDIRECT_TEMPORARY",
    7: "DOWNLOAD",
    8: "FRAMED_LINK",
    9: "RELOAD",
}

FF_DOWNLOAD_STATE_MAP: Dict[int, str] = {
    0: "IN_PROGRESS",
    1: "COMPLETE",
    2: "FAILED",
    3: "CANCELLED",
    4: "PAUSED",
    5: "QUEUED",
    6: "BLOCKED_PARENTAL",
    7: "SCANNING",
    8: "DIRTY",
    9: "BLOCKED_POLICY",
}

FF_SAME_SITE_MAP: Dict[int, str] = {
    0: "NONE",
    1: "LAX",
    2: "STRICT",
}

FF_ROOT_FOLDER_GUIDS: Dict[str, str] = {
    "menu________": "Bookmarks Menu",
    "toolbar_____": "Bookmarks Toolbar",
    "unfiled_____": "Other Bookmarks",
    "mobile______": "Mobile Bookmarks",
    "root________": "",
    "tags________": "Tags",
}

_VSS_SEG_RE = re.compile(r"^vss[_\-#]?(\d+)$", re.IGNORECASE)

# Canonical + backward-compatible column specifications per Firefox table
_FIREFOX_TABLE_SPECS: Dict[str, List[Tuple[str, str]]] = {
    "parsed_firefox_history": [
        ("_row_id", "BIGINT"),
        ("browser", "VARCHAR"),
        ("username", "VARCHAR"),
        ("profile", "VARCHAR"),
        ("url", "VARCHAR"),
        ("title", "VARCHAR"),
        ("visit_count", "INTEGER"),
        ("typed_count", "INTEGER"),
        ("visit_time", "TIMESTAMP"),
        ("from_visit", "BIGINT"),
        ("transition", "VARCHAR"),
        ("source_file", "VARCHAR"),
    ],
    "parsed_firefox_downloads": [
        ("_row_id", "BIGINT"),
        ("browser", "VARCHAR"),
        ("username", "VARCHAR"),
        ("profile", "VARCHAR"),
        ("target_path", "VARCHAR"),
        ("file_name", "VARCHAR"),
        ("url", "VARCHAR"),
        ("tab_url", "VARCHAR"),
        ("site_url", "VARCHAR"),
        ("total_bytes", "BIGINT"),
        ("received_bytes", "BIGINT"),
        ("start_time", "TIMESTAMP"),
        ("end_time", "TIMESTAMP"),
        ("state", "VARCHAR"),
        ("mime_type", "VARCHAR"),
        ("source_file", "VARCHAR"),
    ],
    "parsed_firefox_bookmarks": [
        ("_row_id", "BIGINT"),
        ("browser", "VARCHAR"),
        ("username", "VARCHAR"),
        ("profile", "VARCHAR"),
        ("title", "VARCHAR"),
        ("url", "VARCHAR"),
        ("date_added", "TIMESTAMP"),
        ("date_modified", "TIMESTAMP"),
        ("last_modified", "TIMESTAMP"),
        ("folder", "VARCHAR"),
        ("folder_name", "VARCHAR"),
        ("source_file", "VARCHAR"),
    ],
    "parsed_firefox_cookies": [
        ("_row_id", "BIGINT"),
        ("browser", "VARCHAR"),
        ("username", "VARCHAR"),
        ("profile", "VARCHAR"),
        ("host_key", "VARCHAR"),
        ("host", "VARCHAR"),
        ("name", "VARCHAR"),
        ("value", "VARCHAR"),
        ("path", "VARCHAR"),
        ("creation_utc", "TIMESTAMP"),
        ("creation_time", "TIMESTAMP"),
        ("expires_utc", "TIMESTAMP"),
        ("expiry", "TIMESTAMP"),
        ("last_access_utc", "TIMESTAMP"),
        ("last_accessed", "TIMESTAMP"),
        ("is_secure", "BOOLEAN"),
        ("is_httponly", "BOOLEAN"),
        ("is_http_only", "BOOLEAN"),
        ("same_site", "VARCHAR"),
        ("source_file", "VARCHAR"),
    ],
    "parsed_firefox_formhistory": [
        ("_row_id", "BIGINT"),
        ("browser", "VARCHAR"),
        ("username", "VARCHAR"),
        ("profile", "VARCHAR"),
        ("fieldname", "VARCHAR"),
        ("field_name", "VARCHAR"),
        ("value", "VARCHAR"),
        ("times_used", "INTEGER"),
        ("first_used", "TIMESTAMP"),
        ("last_used", "TIMESTAMP"),
        ("source_file", "VARCHAR"),
    ],
    "parsed_firefox_logins": [
        ("_row_id", "BIGINT"),
        ("browser", "VARCHAR"),
        ("username", "VARCHAR"),
        ("profile", "VARCHAR"),
        ("hostname", "VARCHAR"),
        ("origin_url", "VARCHAR"),
        ("action_url", "VARCHAR"),
        ("httpRealm", "VARCHAR"),
        ("http_realm", "VARCHAR"),
        ("signon_realm", "VARCHAR"),
        ("formSubmitURL", "VARCHAR"),
        ("usernameField", "VARCHAR"),
        ("username_field", "VARCHAR"),
        ("passwordField", "VARCHAR"),
        ("password_field", "VARCHAR"),
        ("encryptedUsername", "VARCHAR"),
        ("encrypted_username", "VARCHAR"),
        ("encryptedPassword", "VARCHAR"),
        ("encrypted_password", "VARCHAR"),
        ("username_value", "VARCHAR"),
        ("guid", "VARCHAR"),
        ("encType", "INTEGER"),
        ("enc_type", "INTEGER"),
        ("timeCreated", "TIMESTAMP"),
        ("time_created", "TIMESTAMP"),
        ("date_created", "TIMESTAMP"),
        ("timeLastUsed", "TIMESTAMP"),
        ("time_last_used", "TIMESTAMP"),
        ("date_last_used", "TIMESTAMP"),
        ("timePasswordChanged", "TIMESTAMP"),
        ("time_password_changed", "TIMESTAMP"),
        ("timesUsed", "INTEGER"),
        ("times_used", "INTEGER"),
        ("source_file", "VARCHAR"),
    ],
}


_UNIX_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_EPOCH_SECONDS = 253402300799.0  # 9999-12-31 23:59:59 UTC


def _sec_to_utc_dt(sec: float, clamp_max: bool = False) -> Optional[datetime]:
    if not math.isfinite(sec) or sec <= 0.0:
        return None
    if sec > _MAX_EPOCH_SECONDS:
        if clamp_max:
            sec = _MAX_EPOCH_SECONDS
        else:
            return None
    try:
        return _UNIX_EPOCH_UTC + timedelta(seconds=sec)
    except (OverflowError, ValueError, OSError):
        return None


def _epoch_seconds_to_dt(val: Any) -> Optional[datetime]:
    r"""Converts Unix epoch seconds to UTC datetime using pure-Python timedelta (immune to Windows CRT OSError)."""
    if val is None or val == "" or isinstance(val, bool):
        return None
    try:
        return _sec_to_utc_dt(float(val), clamp_max=False)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _prtime_us_to_dt(val: Any) -> Optional[datetime]:
    r"""Converts Firefox PRTime microseconds (since 1970-01-01 UTC) to UTC datetime."""
    if val is None or val == "" or isinstance(val, bool):
        return None
    try:
        if isinstance(val, int) and val > 253_402_300_799_999:
            if val > 253_402_300_799_999_999:
                return None
            sec_i, rem_us = divmod(val, 1_000_000)
            return _UNIX_EPOCH_UTC + timedelta(seconds=sec_i, microseconds=rem_us)
        fval = float(val)
        if not math.isfinite(fval) or fval <= 0:
            return None
        if fval > 253_402_300_799_999.0:
            sec = fval / 1_000_000.0
        elif fval > 253_402_300_799.0:
            sec = fval / 1_000.0
        else:
            sec = fval
        return _sec_to_utc_dt(sec, clamp_max=False)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _epoch_ms_to_dt(val: Any) -> Optional[datetime]:
    r"""Converts Firefox Unix epoch milliseconds (logins.json, moz_annos metaData.endTime) to UTC datetime."""
    if val is None or val == "" or isinstance(val, bool):
        return None
    try:
        fval = float(val)
        if not math.isfinite(fval) or fval <= 0:
            return None
        if fval > 253_402_300_799_999.0:
            sec = fval / 1_000_000.0
        elif fval >= 10_000_000_000.0:
            sec = fval / 1_000.0
        else:
            sec = fval
        return _sec_to_utc_dt(sec, clamp_max=False)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _cookie_expiry_to_dt(val: Any, user_version: int = 0) -> Optional[datetime]:
    r"""
    Converts `moz_cookies.expiry` to UTC datetime:
    - Firefox < 126 (`user_version < 15`) stores Unix epoch SECONDS (including persistent cookies > 2100 up to 9999-12-31).
    - Firefox 126+ (`user_version >= 15`) stores Unix epoch MILLISECONDS (including persistent cookies up to 9999-12-31).
    Uses pure-Python epoch + timedelta arithmetic (immune to Windows CRT year-3001 OSError).
    """
    if val is None or val == "" or isinstance(val, bool):
        return None
    try:
        fval = float(val)
        if not math.isfinite(fval) or fval <= 0:
            return None
        if user_version >= 15:
            if fval > 253_402_300_799_999.0:
                sec = fval / 1_000_000.0
            elif fval >= 10_000_000_000.0:
                sec = fval / 1_000.0
            else:
                sec = fval
        elif fval > 253_402_300_799_999.0:
            sec = fval / 1_000_000.0
        elif 1_000_000_000_000.0 <= fval <= 253_402_300_799_999.0:
            # Millisecond epoch value in an unversioned/synthetic cookies.sqlite
            sec = fval / 1_000.0
        else:
            sec = fval

        return _sec_to_utc_dt(sec, clamp_max=True)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _file_uri_to_path(uri_or_path: Any) -> Optional[str]:
    if uri_or_path is None:
        return None
    s = str(uri_or_path).strip()
    if not s:
        return None
    low = s.lower()
    if low.startswith("file:///"):
        rest = unquote(s[8:])
        rest = rest.lstrip("/")
        if re.match(r"^[A-Za-z]:", rest):
            return rest.replace("/", "\\")
        return "/" + rest
    if low.startswith("file://"):
        rest = unquote(s[7:])
        if re.match(r"^/[A-Za-z]:", rest):
            return rest[1:].replace("/", "\\")
        return "\\\\" + rest.lstrip("/").replace("/", "\\")
    return unquote(s)


class FirefoxParser(BaseParser):
    r"""Multi-profile, thread-safe Mozilla Firefox parser."""

    def _is_sqlite(self, path: Path) -> bool:
        try:
            if not path.is_file() or path.stat().st_size < 100:
                return False
            with open(path, "rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except OSError:
            return False

    def _rel_parts_under_staging(self, fp: Path) -> Tuple[str, ...]:
        try:
            return fp.relative_to(self.staging_dir).parts
        except ValueError:
            try:
                return fp.resolve().relative_to(self.staging_dir.resolve()).parts
            except Exception:
                return fp.parts

    def _extract_provenance(self, fp: Path) -> Tuple[Optional[str], str]:
        rel_parts = list(self._rel_parts_under_staging(fp))
        low = [p.lower() for p in rel_parts]

        vss_tag: Optional[str] = None
        if len(low) >= 2 and low[0] == "vss":
            m_v = _VSS_SEG_RE.match(rel_parts[1])
            if m_v:
                vss_tag = f"VSS_{m_v.group(1)}"
                rel_parts = rel_parts[2:]
                low = low[2:]
        elif len(low) >= 1:
            m_v = _VSS_SEG_RE.match(rel_parts[0])
            if m_v:
                vss_tag = f"VSS_{m_v.group(1)}"
                rel_parts = rel_parts[1:]
                low = low[1:]

        username: Optional[str] = None
        profile: str = "Default"

        # 1. Browsers/Firefox/<User>[/<Profile>]/<file>
        if len(low) >= 4 and low[0] == "browsers" and low[1] == "firefox":
            username = rel_parts[2]
            if len(rel_parts) >= 5:
                profile = rel_parts[3]
            else:
                profile = username
        # 1b. Direct Firefox/<User>[/<Profile>]/<file> without Browsers/ root
        elif (
            len(low) >= 3
            and low[0] in ("firefox", "mozilla firefox")
            and "profiles" not in low
            and not any(u_r in low for u_r in ("users", "userfiles", "documents and settings"))
        ):
            username = rel_parts[1]
            if len(rel_parts) >= 4:
                profile = rel_parts[2]
            else:
                fname = fp.name
                m_pref = re.match(
                    r"^(.+)_(?:places|cookies|formhistory|downloads|signons)\.sqlite$",
                    fname,
                    flags=re.IGNORECASE,
                )
                if not m_pref:
                    m_pref = re.match(r"^(.+)_logins\.json$", fname, flags=re.IGNORECASE)
                profile = m_pref.group(1) if m_pref else username
        # 2. .../[Users|UserFiles|Documents and Settings]/<User>/.../Firefox/Profiles/<Profile>/...
        elif "profiles" in low:
            p_idx = low.index("profiles")
            if p_idx + 1 < len(rel_parts) - 1:
                profile = rel_parts[p_idx + 1]
            for u_root in ("users", "userfiles", "documents and settings"):
                if u_root in low:
                    u_idx = low.index(u_root)
                    if u_idx + 1 < p_idx:
                        username = rel_parts[u_idx + 1]
                        break
        else:
            for u_root in ("users", "userfiles", "documents and settings"):
                if u_root in low:
                    u_idx = low.index(u_root)
                    if u_idx + 1 < len(rel_parts) - 1:
                        username = rel_parts[u_idx + 1]
                        break

            # Prefix `<prof>_places.sqlite` or immediate parent dir if inside a subfolder
            fname = fp.name
            m_pref = re.match(
                r"^(.+)_(?:places|cookies|formhistory|downloads|signons)\.sqlite$",
                fname,
                flags=re.IGNORECASE,
            )
            if not m_pref:
                m_pref = re.match(r"^(.+)_logins\.json$", fname, flags=re.IGNORECASE)
            if m_pref:
                profile = m_pref.group(1)
            elif len(rel_parts) >= 2 and low[-2] not in ("sqlite", "browsers", "firefox", "staging"):
                profile = rel_parts[-2]
            else:
                profile = "Default"

        if vss_tag:
            profile = f"{profile} ({vss_tag})"

        return username, profile

    def _sha256_bundle(self, fp: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(fp, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            wal_p = fp.parent / f"{fp.name}-wal"
            if wal_p.is_file() and wal_p.stat().st_size > 0:
                h.update(b"|WAL|")
                with open(wal_p, "rb") as wf:
                    while True:
                        chunk = wf.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    def _ensure_firefox_table_schema(
        self, table_name: str, col_specs: Sequence[Tuple[str, str]]
    ) -> str:
        col_defs = ", ".join(f'"{cname}" {ctype}' for cname, ctype in col_specs)
        ddl = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({col_defs});'
        with DuckDBManager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cur = conn.cursor()
            cur.execute(ddl)
            for cname, ctype in col_specs:
                if cname == "_row_id":
                    continue
                cur.execute(f'ALTER TABLE "{table_name}" ADD COLUMN IF NOT EXISTS "{cname}" {ctype};')
        return ddl

    def _parse_places_sqlite(
        self,
        tmp_db: Path,
        orig_fp: Path,
        username: Optional[str],
        profile: str,
        history_recs: List[Dict[str, Any]],
        downloads_recs: List[Dict[str, Any]],
        bookmarks_recs: List[Dict[str, Any]],
    ) -> None:
        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
        try:
            conn.text_factory = safe_sqlite_text_factory
            cur = conn.cursor()
            tables = {
                r[0]
                for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }

            # 1. History (moz_historyvisits + moz_places, plus orphaned visited moz_places)
            visited_place_ids: Set[int] = set()
            if "moz_places" in tables:
                p_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_places)").fetchall()}
                vc_expr = "p.visit_count" if "visit_count" in p_cols else "0"
                typed_expr = "p.typed" if "typed" in p_cols else "0"

                if "moz_historyvisits" in tables:
                    hv_cols = {
                        r[1] for r in cur.execute("PRAGMA table_info(moz_historyvisits)").fetchall()
                    }
                    fv_expr = "v.from_visit" if "from_visit" in hv_cols else "0"
                    vt_expr = "v.visit_type" if "visit_type" in hv_cols else "1"

                    for p_id, url, title, v_cnt, typed_cnt, v_date, from_v, v_type in cur.execute(
                        f"SELECT p.id, p.url, p.title, {vc_expr}, {typed_expr}, "
                        f"v.visit_date, {fv_expr}, {vt_expr} "
                        "FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id "
                        "WHERE p.url IS NOT NULL AND TRIM(p.url) != '' AND p.url NOT LIKE 'place:%'"
                    ).fetchall():
                        if p_id is not None:
                            visited_place_ids.add(int(p_id))
                        trans_str = FF_TRANSITION_MAP.get(int(v_type or 1), "LINK")
                        history_recs.append(
                            {
                                "browser": "Firefox",
                                "username": username,
                                "profile": profile,
                                "url": str(url),
                                "title": str(title) if title else None,
                                "visit_count": int(v_cnt) if v_cnt is not None else 0,
                                "typed_count": int(typed_cnt or 0),
                                "visit_time": _prtime_us_to_dt(v_date),
                                "from_visit": int(from_v or 0),
                                "transition": trans_str,
                                "source_file": str(orig_fp),
                            }
                        )

                if "last_visit_date" in p_cols:
                    for p_id, url, title, v_cnt, typed_cnt, lvd in cur.execute(
                        f"SELECT p.id, p.url, p.title, {vc_expr}, {typed_expr}, p.last_visit_date "
                        "FROM moz_places p "
                        "WHERE p.url IS NOT NULL AND TRIM(p.url) != '' "
                        "AND p.url NOT LIKE 'place:%' AND p.last_visit_date IS NOT NULL"
                    ).fetchall():
                        if p_id is not None and int(p_id) in visited_place_ids:
                            continue
                        dt_lvd = _prtime_us_to_dt(lvd)
                        if dt_lvd is None:
                            continue
                        history_recs.append(
                            {
                                "browser": "Firefox",
                                "username": username,
                                "profile": profile,
                                "url": str(url),
                                "title": str(title) if title else None,
                                "visit_count": int(v_cnt) if v_cnt is not None else 0,
                                "typed_count": int(typed_cnt or 0),
                                "visit_time": dt_lvd,
                                "from_visit": 0,
                                "transition": "TYPED" if int(typed_cnt or 0) > 0 else "LINK",
                                "source_file": str(orig_fp),
                            }
                        )

            # 2. Downloads via Firefox 26+ moz_annos + moz_anno_attributes + moz_places
            if (
                "moz_annos" in tables
                and "moz_anno_attributes" in tables
                and "moz_places" in tables
            ):
                an_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_annos)").fetchall()}
                da_expr = "a.dateAdded" if "dateAdded" in an_cols else "NULL"
                lm_expr = "a.lastModified" if "lastModified" in an_cols else "NULL"
                mt_expr = "a.mime_type" if "mime_type" in an_cols else "NULL"

                dl_groups: Dict[int, Dict[str, Any]] = {}
                for place_id, place_url, attr_name, content, d_add, l_mod, a_mime in cur.execute(
                    f"SELECT a.place_id, p.url, attr.name, a.content, {da_expr}, {lm_expr}, {mt_expr} "
                    "FROM moz_annos a "
                    "JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id "
                    "JOIN moz_places p ON a.place_id = p.id "
                    "WHERE attr.name LIKE 'downloads/%'"
                ).fetchall():
                    if place_id is None:
                        continue
                    pid = int(place_id)
                    grp = dl_groups.setdefault(
                        pid,
                        {
                            "url": str(place_url) if place_url else None,
                            "dest_uri": None,
                            "dest_name": None,
                            "meta_raw": None,
                            "date_added_list": [],
                            "last_mod_list": [],
                            "anno_mime": None,
                        },
                    )
                    aname = str(attr_name or "")
                    if aname == "downloads/destinationFileURI" and content:
                        grp["dest_uri"] = str(content)
                    elif aname == "downloads/destinationFileName" and content:
                        grp["dest_name"] = str(content)
                    elif aname == "downloads/metaData" and content:
                        grp["meta_raw"] = str(content)
                    if d_add:
                        grp["date_added_list"].append(d_add)
                    if l_mod:
                        grp["last_mod_list"].append(l_mod)
                    if a_mime and not grp["anno_mime"]:
                        grp["anno_mime"] = str(a_mime)

                # Optional fallback start_time from moz_historyvisits (visit_type = 7 DOWNLOAD)
                dl_visit_times: Dict[int, Any] = {}
                if dl_groups and "moz_historyvisits" in tables:
                    hv_cols = {
                        r[1] for r in cur.execute("PRAGMA table_info(moz_historyvisits)").fetchall()
                    }
                    vt_filter = "AND visit_type = 7" if "visit_type" in hv_cols else ""
                    for v_pid, v_dt in cur.execute(
                        f"SELECT place_id, MIN(visit_date) FROM moz_historyvisits WHERE place_id IS NOT NULL {vt_filter} GROUP BY place_id"
                    ).fetchall():
                        if v_pid is not None and v_dt:
                            dl_visit_times[int(v_pid)] = v_dt

                for pid, grp in dl_groups.items():
                    meta: Dict[str, Any] = {}
                    if grp["meta_raw"]:
                        try:
                            parsed_m = json.loads(grp["meta_raw"])
                            if isinstance(parsed_m, dict):
                                meta = parsed_m
                        except Exception:
                            meta = {}

                    target_path = _file_uri_to_path(grp["dest_uri"]) or grp["dest_name"]
                    file_name = grp["dest_name"]
                    if not file_name and target_path:
                        file_name = target_path.replace("/", "\\").rsplit("\\", 1)[-1]

                    raw_state = meta.get("state")
                    state_str = (
                        FF_DOWNLOAD_STATE_MAP.get(int(raw_state), str(raw_state))
                        if raw_state is not None
                        else ("COMPLETE" if target_path else None)
                    )
                    fsize_val = meta.get("fileSize")
                    total_bytes = int(fsize_val) if fsize_val is not None else None
                    rec_bytes = total_bytes if state_str == "COMPLETE" else None

                    end_dt = _epoch_ms_to_dt(meta.get("endTime"))
                    if end_dt is None and grp["last_mod_list"]:
                        end_dt = _prtime_us_to_dt(max(grp["last_mod_list"]))

                    start_dt = (
                        _prtime_us_to_dt(min(grp["date_added_list"]))
                        if grp["date_added_list"]
                        else None
                    )
                    if start_dt is None and pid in dl_visit_times:
                        start_dt = _prtime_us_to_dt(dl_visit_times[pid])
                    if start_dt is None:
                        start_dt = end_dt

                    mime_str = (
                        str(meta["contentType"])
                        if meta.get("contentType")
                        else grp["anno_mime"]
                    )
                    url_val = grp["url"]
                    if not target_path and not url_val:
                        continue

                    downloads_recs.append(
                        {
                            "browser": "Firefox",
                            "username": username,
                            "profile": profile,
                            "target_path": target_path,
                            "file_name": file_name,
                            "url": url_val,
                            "tab_url": url_val,
                            "site_url": str(meta["referrer"]) if meta.get("referrer") else url_val,
                            "total_bytes": total_bytes,
                            "received_bytes": rec_bytes,
                            "start_time": start_dt,
                            "end_time": end_dt,
                            "state": state_str,
                            "mime_type": mime_str,
                            "source_file": str(orig_fp),
                        }
                    )

            # 3. Bookmarks (moz_bookmarks + moz_places with full parent folder hierarchy)
            if "moz_bookmarks" in tables and "moz_places" in tables:
                bm_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_bookmarks)").fetchall()}
                has_parent = "parent" in bm_cols and "id" in bm_cols
                has_type = "type" in bm_cols
                has_guid = "guid" in bm_cols

                folder_nodes: Dict[int, Tuple[Optional[int], str]] = {}
                if has_parent:
                    p_sel_guid = "guid" if has_guid else "NULL"
                    p_sel_type = "type" if has_type else "2"
                    for b_id, b_parent, b_type, b_title, b_guid in cur.execute(
                        f"SELECT id, parent, {p_sel_type}, title, {p_sel_guid} FROM moz_bookmarks"
                    ).fetchall():
                        if b_id is None:
                            continue
                        guid_s = str(b_guid or "")
                        if guid_s in FF_ROOT_FOLDER_GUIDS:
                            lbl = FF_ROOT_FOLDER_GUIDS[guid_s]
                        else:
                            lbl = str(b_title or "").strip()
                        folder_nodes[int(b_id)] = (
                            int(b_parent) if b_parent is not None else None,
                            lbl,
                        )

                def _resolve_folder_path(parent_id: Optional[int]) -> str:
                    if parent_id is None or not folder_nodes:
                        return "Bookmarks"
                    segs: List[str] = []
                    visited: Set[int] = set()
                    curr: Optional[int] = int(parent_id)
                    while curr is not None and curr in folder_nodes and curr not in visited:
                        visited.add(curr)
                        next_parent, lbl = folder_nodes[curr]
                        if lbl:
                            segs.append(lbl)
                        if next_parent == curr:
                            break
                        curr = next_parent
                    segs.reverse()
                    return " > ".join(segs) if segs else "Bookmarks"

                parent_expr = "b.parent" if "parent" in bm_cols else "NULL"
                da_expr = "b.dateAdded" if "dateAdded" in bm_cols else "NULL"
                lm_expr = "b.lastModified" if "lastModified" in bm_cols else "NULL"
                type_where = "AND COALESCE(b.type, 1) = 1" if has_type else ""

                for b_parent, b_title, p_url, d_add, l_mod in cur.execute(
                    f"SELECT {parent_expr}, b.title, p.url, {da_expr}, {lm_expr} "
                    "FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id "
                    f"WHERE p.url IS NOT NULL AND TRIM(p.url) != '' AND p.url NOT LIKE 'place:%' {type_where}"
                ).fetchall():
                    dt_added = _prtime_us_to_dt(d_add)
                    dt_mod = _prtime_us_to_dt(l_mod) or dt_added
                    folder_str = _resolve_folder_path(
                        int(b_parent) if b_parent is not None else None
                    )
                    title_str = str(b_title) if b_title else str(p_url)
                    bookmarks_recs.append(
                        {
                            "browser": "Firefox",
                            "username": username,
                            "profile": profile,
                            "title": title_str,
                            "url": str(p_url),
                            "date_added": dt_added,
                            "date_modified": dt_mod,
                            "last_modified": dt_mod,
                            "folder": folder_str,
                            "folder_name": folder_str,
                            "source_file": str(orig_fp),
                        }
                    )
        finally:
            conn.close()

    def _parse_downloads_sqlite(
        self,
        tmp_db: Path,
        orig_fp: Path,
        username: Optional[str],
        profile: str,
        downloads_recs: List[Dict[str, Any]],
    ) -> None:
        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
        try:
            conn.text_factory = safe_sqlite_text_factory
            cur = conn.cursor()
            tables = {
                r[0]
                for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "moz_downloads" not in tables:
                return
            d_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_downloads)").fetchall()}
            nm_c = "name" if "name" in d_cols else "NULL"
            src_c = "source" if "source" in d_cols else ("url" if "url" in d_cols else "NULL")
            tgt_c = "target" if "target" in d_cols else ("target_path" if "target_path" in d_cols else "NULL")
            st_c = "startTime" if "startTime" in d_cols else "NULL"
            et_c = "endTime" if "endTime" in d_cols else "NULL"
            state_c = "state" if "state" in d_cols else "NULL"
            ref_c = "referrer" if "referrer" in d_cols else "NULL"
            cb_c = "currBytes" if "currBytes" in d_cols else "NULL"
            mb_c = "maxBytes" if "maxBytes" in d_cols else "NULL"
            mt_c = "mimeType" if "mimeType" in d_cols else "NULL"

            for nm, src, tgt, s_t, e_t, st_v, ref_u, c_b, m_b, m_t in cur.execute(
                f"SELECT {nm_c}, {src_c}, {tgt_c}, {st_c}, {et_c}, {state_c}, "
                f"{ref_c}, {cb_c}, {mb_c}, {mt_c} FROM moz_downloads"
            ).fetchall():
                t_path = _file_uri_to_path(tgt) or (str(nm) if nm else None)
                u_val = str(src) if src else None
                if not t_path and not u_val:
                    continue
                fname_val = str(nm) if nm else (t_path.replace("/", "\\").rsplit("\\", 1)[-1] if t_path else None)
                state_str = (
                    FF_DOWNLOAD_STATE_MAP.get(int(st_v), str(st_v))
                    if st_v is not None
                    else None
                )
                tot_b = int(m_b) if (m_b is not None and int(m_b) >= 0) else (int(c_b) if c_b is not None else None)
                rec_b = int(c_b) if c_b is not None else tot_b

                downloads_recs.append(
                    {
                        "browser": "Firefox",
                        "username": username,
                        "profile": profile,
                        "target_path": t_path,
                        "file_name": fname_val,
                        "url": u_val,
                        "tab_url": u_val,
                        "site_url": str(ref_u) if ref_u else u_val,
                        "total_bytes": tot_b,
                        "received_bytes": rec_b,
                        "start_time": _prtime_us_to_dt(s_t),
                        "end_time": _prtime_us_to_dt(e_t),
                        "state": state_str,
                        "mime_type": str(m_t) if m_t else None,
                        "source_file": str(orig_fp),
                    }
                )
        finally:
            conn.close()

    def _parse_cookies_sqlite(
        self,
        tmp_db: Path,
        orig_fp: Path,
        username: Optional[str],
        profile: str,
        cookies_recs: List[Dict[str, Any]],
    ) -> None:
        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
        try:
            conn.text_factory = safe_sqlite_text_factory
            cur = conn.cursor()
            tables = {
                r[0]
                for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "moz_cookies" not in tables:
                return
            uv_row = cur.execute("PRAGMA user_version").fetchone()
            user_version = int(uv_row[0] or 0) if uv_row else 0

            c_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_cookies)").fetchall()}
            host_c = "host" if "host" in c_cols else ("baseDomain" if "baseDomain" in c_cols else "''")
            name_c = "name" if "name" in c_cols else "''"
            val_c = "value" if "value" in c_cols else "''"
            path_c = "path" if "path" in c_cols else "'/'"
            ct_c = "creationTime" if "creationTime" in c_cols else "NULL"
            exp_c = "expiry" if "expiry" in c_cols else "NULL"
            la_c = "lastAccessed" if "lastAccessed" in c_cols else "NULL"
            sec_c = "isSecure" if "isSecure" in c_cols else "0"
            http_c = "isHttpOnly" if "isHttpOnly" in c_cols else "0"
            ss_c = "sameSite" if "sameSite" in c_cols else "NULL"

            for host, name, val, path, c_t, exp_t, la_t, sec, http, ss_v in cur.execute(
                f"SELECT {host_c}, {name_c}, {val_c}, {path_c}, {ct_c}, {exp_c}, {la_c}, "
                f"{sec_c}, {http_c}, {ss_c} FROM moz_cookies"
            ).fetchall():
                host_s = str(host) if host is not None else ""
                name_s = str(name) if name is not None else ""
                val_s = str(val) if val is not None else ""
                path_s = str(path) if path else "/"
                c_dt = _prtime_us_to_dt(c_t)
                exp_dt = _cookie_expiry_to_dt(exp_t, user_version=user_version)
                la_dt = _prtime_us_to_dt(la_t)
                sec_b = bool(sec)
                http_b = bool(http)
                ss_str = (
                    FF_SAME_SITE_MAP.get(int(ss_v), str(ss_v)) if ss_v is not None else None
                )

                cookies_recs.append(
                    {
                        "browser": "Firefox",
                        "username": username,
                        "profile": profile,
                        "host_key": host_s,
                        "host": host_s,
                        "name": name_s,
                        "value": val_s,
                        "path": path_s,
                        "creation_utc": c_dt,
                        "creation_time": c_dt,
                        "expires_utc": exp_dt,
                        "expiry": exp_dt,
                        "last_access_utc": la_dt,
                        "last_accessed": la_dt,
                        "is_secure": sec_b,
                        "is_httponly": http_b,
                        "is_http_only": http_b,
                        "same_site": ss_str,
                        "source_file": str(orig_fp),
                    }
                )
        finally:
            conn.close()

    def _parse_formhistory_sqlite(
        self,
        tmp_db: Path,
        orig_fp: Path,
        username: Optional[str],
        profile: str,
        form_recs: List[Dict[str, Any]],
    ) -> None:
        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
        try:
            conn.text_factory = safe_sqlite_text_factory
            cur = conn.cursor()
            tables = {
                r[0]
                for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "moz_formhistory" not in tables:
                return
            fh_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_formhistory)").fetchall()}
            fn_c = "fieldname" if "fieldname" in fh_cols else ("field_name" if "field_name" in fh_cols else "''")
            val_c = "value" if "value" in fh_cols else "''"
            tu_c = "timesUsed" if "timesUsed" in fh_cols else ("times_used" if "times_used" in fh_cols else "1")
            fu_c = "firstUsed" if "firstUsed" in fh_cols else ("first_used" if "first_used" in fh_cols else "NULL")
            lu_c = "lastUsed" if "lastUsed" in fh_cols else ("last_used" if "last_used" in fh_cols else "NULL")

            for fname_col, val, t_used, f_used, l_used in cur.execute(
                f"SELECT {fn_c}, {val_c}, {tu_c}, {fu_c}, {lu_c} FROM moz_formhistory"
            ).fetchall():
                fn_s = str(fname_col or "")
                val_s = str(val) if val is not None else ""
                tu_i = int(t_used) if t_used is not None else 1
                form_recs.append(
                    {
                        "browser": "Firefox",
                        "username": username,
                        "profile": profile,
                        "fieldname": fn_s,
                        "field_name": fn_s,
                        "value": val_s,
                        "times_used": tu_i,
                        "first_used": _prtime_us_to_dt(f_used),
                        "last_used": _prtime_us_to_dt(l_used),
                        "source_file": str(orig_fp),
                    }
                )
        finally:
            conn.close()

    def _parse_signons_sqlite(
        self,
        tmp_db: Path,
        orig_fp: Path,
        username: Optional[str],
        profile: str,
        logins_recs: List[Dict[str, Any]],
    ) -> None:
        conn = sqlite3.connect(f"file:{tmp_db.resolve()}?mode=ro", uri=True)
        try:
            conn.text_factory = safe_sqlite_text_factory
            cur = conn.cursor()
            tables = {
                r[0]
                for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "moz_logins" not in tables:
                return
            lg_cols = {r[1] for r in cur.execute("PRAGMA table_info(moz_logins)").fetchall()}
            hn_c = "hostname" if "hostname" in lg_cols else "''"
            hr_c = "httpRealm" if "httpRealm" in lg_cols else "NULL"
            fs_c = "formSubmitURL" if "formSubmitURL" in lg_cols else "NULL"
            uf_c = "usernameField" if "usernameField" in lg_cols else "''"
            pf_c = "passwordField" if "passwordField" in lg_cols else "''"
            eu_c = "encryptedUsername" if "encryptedUsername" in lg_cols else "''"
            ep_c = "encryptedPassword" if "encryptedPassword" in lg_cols else "''"
            gd_c = "guid" if "guid" in lg_cols else "NULL"
            et_c = "encType" if "encType" in lg_cols else "NULL"
            tc_c = "timeCreated" if "timeCreated" in lg_cols else "NULL"
            tlu_c = "timeLastUsed" if "timeLastUsed" in lg_cols else "NULL"
            tpc_c = "timePasswordChanged" if "timePasswordChanged" in lg_cols else "NULL"
            tu_c = "timesUsed" if "timesUsed" in lg_cols else "0"

            for hn, hr, fs_u, uf, pf, eu, ep, gd, enc_t, tc, tlu, tpc, tu in cur.execute(
                f"SELECT {hn_c}, {hr_c}, {fs_c}, {uf_c}, {pf_c}, {eu_c}, {ep_c}, "
                f"{gd_c}, {et_c}, {tc_c}, {tlu_c}, {tpc_c}, {tu_c} FROM moz_logins"
            ).fetchall():
                hn_s = str(hn or "")
                hr_s = str(hr) if hr is not None else None
                fs_s = str(fs_u) if fs_u is not None else None
                uf_s = str(uf or "")
                pf_s = str(pf or "")
                eu_s = str(eu or "")
                ep_s = str(ep or "")
                enc_i = int(enc_t) if enc_t is not None else None
                dt_c = _epoch_ms_to_dt(tc)
                dt_lu = _epoch_ms_to_dt(tlu)
                dt_pc = _epoch_ms_to_dt(tpc)
                tu_i = int(tu or 0)
                logins_recs.append(
                    {
                        "browser": "Firefox",
                        "username": username,
                        "profile": profile,
                        "hostname": hn_s,
                        "origin_url": hn_s,
                        "action_url": fs_s,
                        "httpRealm": hr_s,
                        "http_realm": hr_s,
                        "signon_realm": hr_s or hn_s,
                        "formSubmitURL": fs_s,
                        "usernameField": uf_s,
                        "username_field": uf_s,
                        "passwordField": pf_s,
                        "password_field": pf_s,
                        "encryptedUsername": eu_s,
                        "encrypted_username": eu_s,
                        "encryptedPassword": ep_s,
                        "encrypted_password": ep_s,
                        "username_value": None,
                        "guid": str(gd) if gd else None,
                        "encType": enc_i,
                        "enc_type": enc_i,
                        "timeCreated": dt_c,
                        "time_created": dt_c,
                        "date_created": dt_c,
                        "timeLastUsed": dt_lu,
                        "time_last_used": dt_lu,
                        "date_last_used": dt_lu,
                        "timePasswordChanged": dt_pc,
                        "time_password_changed": dt_pc,
                        "timesUsed": tu_i,
                        "times_used": tu_i,
                        "source_file": str(orig_fp),
                    }
                )
        finally:
            conn.close()

    def parse(self) -> Dict[str, int]:
        start_time = time.time()
        if not self.staging_dir.exists():
            return {}

        history_recs: List[Dict[str, Any]] = []
        downloads_recs: List[Dict[str, Any]] = []
        bookmarks_recs: List[Dict[str, Any]] = []
        cookies_recs: List[Dict[str, Any]] = []
        form_recs: List[Dict[str, Any]] = []
        logins_recs: List[Dict[str, Any]] = []

        seen_profile_hashes: Set[Tuple[str, str, str, str]] = set()
        seen_primary_hashes: Set[Tuple[str, str]] = set()
        temp_root = Path(tempfile.mkdtemp(prefix="wft_ff_"))

        def _ff_priority(fp: Path) -> Tuple[int, str]:
            rel_low = [p.lower() for p in self._rel_parts_under_staging(fp)]
            if "browsers" in rel_low:
                prio = 0
            elif "sqlite" in rel_low:
                prio = 2
            else:
                prio = 1
            return (prio, str(fp))

        _FF_CANDIDATE_SUFFIXES = (
            "places.sqlite",
            "downloads.sqlite",
            "cookies.sqlite",
            "formhistory.sqlite",
            "signons.sqlite",
            "logins.json",
        )
        _SKIP_FF_ROOTS = {
            "registry", "logs", "prefetch", "filesystem", "mft", "srum",
            "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails",
            "zoneidentifier", "recyclebin", "wbem", "wer", "wlan", "usb",
        }
        try:
            self._get_vfs_staged_cache()
            all_files: List[Path] = []
            if self.staging_dir.exists():
                staging_res = self.staging_dir.resolve()
                for walk_root, dirs, files in os.walk(staging_res):
                    root_p = Path(walk_root)
                    if root_p == staging_res:
                        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_FF_ROOTS]
                    for fname in files:
                        if fname.lower().endswith(_FF_CANDIDATE_SUFFIXES):
                            all_files.append(root_p / fname)
            all_files.sort(key=_ff_priority)

            for idx, fp in enumerate(all_files):
                fname = fp.name.lower()
                if fname.endswith(("-wal", "-shm", "-journal")):
                    continue

                rel_low = [p.lower() for p in self._rel_parts_under_staging(fp)]
                in_sqlite_dump = len(rel_low) >= 2 and rel_low[0] == "sqlite"
                username, profile = self._extract_provenance(fp)
                u_key = (username or "").lower()
                p_key = profile.lower()

                if (fname == "places.sqlite" or fname.endswith("_places.sqlite")) and self._is_sqlite(fp):
                    fhash = self._sha256_bundle(fp)
                    if fhash:
                        if in_sqlite_dump and ("places", fhash) in seen_primary_hashes:
                            continue
                        if ("places", u_key, p_key, fhash) in seen_profile_hashes:
                            continue
                        seen_profile_hashes.add(("places", u_key, p_key, fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("places", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(fp, temp_root / f"ff_{idx}")
                        self._parse_places_sqlite(
                            tmp_db=tmp_db,
                            orig_fp=fp,
                            username=username,
                            profile=profile,
                            history_recs=history_recs,
                            downloads_recs=downloads_recs,
                            bookmarks_recs=bookmarks_recs,
                        )
                    except Exception as ex:
                        self._log(f"Firefox places.sqlite error on {fp}: {ex}", "WARNING")

                elif (fname == "downloads.sqlite" or fname.endswith("_downloads.sqlite")) and self._is_sqlite(fp):
                    fhash = self._sha256_bundle(fp)
                    if fhash:
                        if in_sqlite_dump and ("downloads", fhash) in seen_primary_hashes:
                            continue
                        if ("downloads", u_key, p_key, fhash) in seen_profile_hashes:
                            continue
                        seen_profile_hashes.add(("downloads", u_key, p_key, fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("downloads", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(fp, temp_root / f"ff_{idx}")
                        self._parse_downloads_sqlite(
                            tmp_db=tmp_db,
                            orig_fp=fp,
                            username=username,
                            profile=profile,
                            downloads_recs=downloads_recs,
                        )
                    except Exception as ex:
                        self._log(f"Firefox downloads.sqlite error on {fp}: {ex}", "WARNING")

                elif (fname == "cookies.sqlite" or fname.endswith("_cookies.sqlite")) and self._is_sqlite(fp):
                    fhash = self._sha256_bundle(fp)
                    if fhash:
                        if in_sqlite_dump and ("cookies", fhash) in seen_primary_hashes:
                            continue
                        if ("cookies", u_key, p_key, fhash) in seen_profile_hashes:
                            continue
                        seen_profile_hashes.add(("cookies", u_key, p_key, fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("cookies", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(fp, temp_root / f"ff_{idx}")
                        self._parse_cookies_sqlite(
                            tmp_db=tmp_db,
                            orig_fp=fp,
                            username=username,
                            profile=profile,
                            cookies_recs=cookies_recs,
                        )
                    except Exception as ex:
                        self._log(f"Firefox cookies.sqlite error on {fp}: {ex}", "WARNING")

                elif (fname == "formhistory.sqlite" or fname.endswith("_formhistory.sqlite")) and self._is_sqlite(fp):
                    fhash = self._sha256_bundle(fp)
                    if fhash:
                        if in_sqlite_dump and ("formhistory", fhash) in seen_primary_hashes:
                            continue
                        if ("formhistory", u_key, p_key, fhash) in seen_profile_hashes:
                            continue
                        seen_profile_hashes.add(("formhistory", u_key, p_key, fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("formhistory", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(fp, temp_root / f"ff_{idx}")
                        self._parse_formhistory_sqlite(
                            tmp_db=tmp_db,
                            orig_fp=fp,
                            username=username,
                            profile=profile,
                            form_recs=form_recs,
                        )
                    except Exception as ex:
                        self._log(f"Firefox formhistory.sqlite error on {fp}: {ex}", "WARNING")

                elif (fname == "signons.sqlite" or fname.endswith("_signons.sqlite")) and self._is_sqlite(fp):
                    fhash = self._sha256_bundle(fp)
                    if fhash:
                        if in_sqlite_dump and ("signons", fhash) in seen_primary_hashes:
                            continue
                        if ("signons", u_key, p_key, fhash) in seen_profile_hashes:
                            continue
                        seen_profile_hashes.add(("signons", u_key, p_key, fhash))
                        if not in_sqlite_dump:
                            seen_primary_hashes.add(("signons", fhash))

                    try:
                        tmp_db = copy_sqlite_with_wal(fp, temp_root / f"ff_{idx}")
                        self._parse_signons_sqlite(
                            tmp_db=tmp_db,
                            orig_fp=fp,
                            username=username,
                            profile=profile,
                            logins_recs=logins_recs,
                        )
                    except Exception as ex:
                        self._log(f"Firefox signons.sqlite error on {fp}: {ex}", "WARNING")

                elif fname == "logins.json" or fname.endswith("_logins.json"):
                    fhash = self._sha256_bundle(fp)
                    if fhash:
                        if ("logins_json", u_key, p_key, fhash) in seen_profile_hashes:
                            continue
                        seen_profile_hashes.add(("logins_json", u_key, p_key, fhash))

                    try:
                        data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
                        if isinstance(data, dict):
                            for item in data.get("logins", []):
                                if not isinstance(item, dict):
                                    continue
                                hn_s = str(item.get("hostname") or "")
                                hr_s = (
                                    str(item["httpRealm"])
                                    if item.get("httpRealm") is not None
                                    else None
                                )
                                fs_s = (
                                    str(item["formSubmitURL"])
                                    if item.get("formSubmitURL") is not None
                                    else None
                                )
                                uf_s = str(item.get("usernameField") or "")
                                pf_s = str(item.get("passwordField") or "")
                                eu_s = str(item.get("encryptedUsername") or "")
                                ep_s = str(item.get("encryptedPassword") or "")
                                enc_i = (
                                    int(item["encType"])
                                    if item.get("encType") is not None
                                    else None
                                )
                                dt_c = _epoch_ms_to_dt(item.get("timeCreated"))
                                dt_lu = _epoch_ms_to_dt(item.get("timeLastUsed"))
                                dt_pc = _epoch_ms_to_dt(item.get("timePasswordChanged"))
                                tu_i = int(item.get("timesUsed") or 0)
                                logins_recs.append(
                                    {
                                        "browser": "Firefox",
                                        "username": username,
                                        "profile": profile,
                                        "hostname": hn_s,
                                        "origin_url": hn_s,
                                        "action_url": fs_s,
                                        "httpRealm": hr_s,
                                        "http_realm": hr_s,
                                        "signon_realm": hr_s or hn_s,
                                        "formSubmitURL": fs_s,
                                        "usernameField": uf_s,
                                        "username_field": uf_s,
                                        "passwordField": pf_s,
                                        "password_field": pf_s,
                                        "encryptedUsername": eu_s,
                                        "encrypted_username": eu_s,
                                        "encryptedPassword": ep_s,
                                        "encrypted_password": ep_s,
                                        "username_value": None,
                                        "guid": str(item["guid"]) if item.get("guid") else None,
                                        "encType": enc_i,
                                        "enc_type": enc_i,
                                        "timeCreated": dt_c,
                                        "time_created": dt_c,
                                        "date_created": dt_c,
                                        "timeLastUsed": dt_lu,
                                        "time_last_used": dt_lu,
                                        "date_last_used": dt_lu,
                                        "timePasswordChanged": dt_pc,
                                        "time_password_changed": dt_pc,
                                        "timesUsed": tu_i,
                                        "times_used": tu_i,
                                        "source_file": str(fp),
                                    }
                                )
                    except Exception as ex:
                        self._log(f"Firefox logins.json notice on {fp}: {ex}", "WARNING")
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

        results: Dict[str, int] = {}
        table_specs = [
            ("parsed_firefox_history", history_recs, "firefox_history", "Firefox History"),
            ("parsed_firefox_downloads", downloads_recs, "firefox_downloads", "Firefox Downloads"),
            ("parsed_firefox_bookmarks", bookmarks_recs, "firefox_bookmarks", "Firefox Bookmarks"),
            ("parsed_firefox_cookies", cookies_recs, "firefox_cookies", "Firefox Cookies"),
            ("parsed_firefox_formhistory", form_recs, "firefox_formhistory", "Firefox FormHistory"),
            ("parsed_firefox_logins", logins_recs, "firefox_logins", "Firefox Saved Logins"),
        ]

        with DuckDBManager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            existing_tables = {
                str(r[0])
                for r in conn.cursor()
                .execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                )
                .fetchall()
            }

            for tbl, recs, aid, disp in table_specs:
                col_specs = _FIREFOX_TABLE_SPECS[tbl]
                if recs:
                    ddl = self._ensure_firefox_table_schema(tbl, col_specs)
                    results[tbl] = self.insert_records(
                        table_name=tbl,
                        records=recs,
                        schema_ddl=ddl,
                        artifact_id=aid,
                        category="WEB RELATED",
                        display_name=disp,
                        source_tool="FirefoxParser",
                        append=False,
                    )
                elif tbl in existing_tables:
                    cur_cnt_row = conn.cursor().execute(f'SELECT COUNT(*) FROM "{tbl}";').fetchone()
                    if cur_cnt_row and int(cur_cnt_row[0] or 0) > 0:
                        ddl = self._ensure_firefox_table_schema(tbl, col_specs)
                        self.insert_records(
                            table_name=tbl,
                            records=[],
                            schema_ddl=ddl,
                            artifact_id=aid,
                            category="WEB RELATED",
                            display_name=disp,
                            source_tool="FirefoxParser",
                            append=False,
                        )

        dur = int((time.time() - start_time) * 1000)
        self._log(
            f"FirefoxParser completed in {dur}ms: {sum(results.values())} rows across {len(results)} tables."
        )
        return results
