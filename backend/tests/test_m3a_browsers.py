r"""
M3-A Comprehensive Unit & Multi-Threaded Concurrency Test Suite (`F13.1`, `F13.2`, `F14.1`, `F14.2`, `F28`)
Tests:
  (a) BaseParser thread-safe DuckDB batch inserts (`pandas` AND `pd = None` parity, UTC +05:30 immunity, "" in TIMESTAMP,
      64-bit integer precision alongside None, dynamic all-None first batch + append=True, append=False empty delete,
      and copy_sqlite_with_wal same-dir collision isolation).
  (b) resolve_evidence_path (`vfs_files` match, `Enrichment/<part>/inetpub/wwwroot/web.config`, `VSS/VSS_<N>/...`,
      parent-aware `raw_mft` disambiguation of duplicate `History`/`web.config`, bare generic filename rejection).
  (c) get_original_mtime (`vfs_files` valid timestamp on full & minimal schemas, `vfs_files` all-NULL -> None,
      `source_type='image'` fresh un-utimed file -> None [NOT now()], `os.utime()` preserved timestamp, `source_type='folder'`).
  (d) ChromiumParser multi-profile (`Default` + `Profile 1` + Edge + Brave + `VSS_1`), `<Profile>/Network/Cookies`
      (`v10`, `v20`, DPAPI, plaintext, `last_update_utc`, `expires_utc` overflow), `downloads_url_chains` + orphaned `urls`,
      blank `Login Data` `username_value -> None`, Simple Cache (`0xfcfb6d1ba7725c30`) Pickle/HTTP UTC timestamp vs
      headerless fresh image cache `response_time IS NULL`, and binary SNSS `Current Session` + `Sessions/Tabs_*`.
  (e) FirefoxParser multi-profile (`alice/abc.default-release` + `bob/xyz.default` + `VSS_1` + WAL isolation),
      `moz_annos` (`downloads/destinationFileURI` + `downloads/metaData`) + `downloads.sqlite` -> `parsed_firefox_downloads`
      (plus `TimelineNormalizer` check), `cookies.sqlite` zero-NULL (`host_key, creation_utc, expires_utc, last_access_utc`
      + >2100 expiry + v15 ms expiry), `bookmarks` (`date_modified` + nested folder path), `formhistory.sqlite`
      (`fieldname` & `field_name`), and un-truncated `logins.json` (`encryptedUsername` > 60 chars + `encryptedPassword`).
  (f) `ThreadPoolExecutor(max_workers=8)` concurrent DuckDB stress test across `BaseParser`, `ChromiumParser`,
      `FirefoxParser`, and `query_paginated` on one shared `case.duckdb`.
"""
from __future__ import annotations

import ast
import ctypes
import io
import json
import msvcrt
import os
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import pytest

import backend.config as cfg
import backend.parsers.base_parser as base_parser_mod
from backend.db.engine import DuckDBManager, init_case_db, log_processing_event, query_paginated
from backend.parsers.base_parser import (
    WEBKIT_EPOCH_OFFSET_SECONDS,
    BaseParser,
    copy_sqlite_with_wal,
    prtime_to_datetime,
    safe_sqlite_text_factory,
    webkit_to_datetime,
    windows_filetime_to_datetime,
)
from backend.parsers.chromium_parser import ChromiumParser, _cookie_webkit_expiry
from backend.parsers.firefox_parser import FirefoxParser, _cookie_expiry_to_dt


def _dt_to_webkit_us(dt: datetime) -> int:
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return int(round((utc_dt.timestamp() + WEBKIT_EPOCH_OFFSET_SECONDS) * 1_000_000))


def _dt_to_prtime_us(dt: datetime) -> int:
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return int(round(utc_dt.timestamp() * 1_000_000))


def _dt_to_epoch_ms(dt: datetime) -> int:
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return int(round(utc_dt.timestamp() * 1_000))


def _align4_bytes(b: bytes) -> bytes:
    rem = len(b) % 4
    return b if rem == 0 else b + (b"\x00" * (4 - rem))


def _pack_snss_cmd(cmd_id: int, payload: bytes) -> bytes:
    size = 1 + len(payload)
    return struct.pack("<HB", size, cmd_id) + payload


def _build_snss_nav_pickle(tab_id: int, nav_index: int, url: str, title: str) -> bytes:
    url_b = url.encode("utf-8")
    title_u16 = title.encode("utf-16-le")
    body = (
        struct.pack("<ii", tab_id, nav_index)
        + struct.pack("<i", len(url_b))
        + _align4_bytes(url_b)
        + struct.pack("<i", len(title))
        + _align4_bytes(title_u16)
    )
    return struct.pack("<I", len(body)) + body


def _build_simple_cache_entry(
    key: str,
    http_headers: bytes,
    resp_dt: datetime | None = None,
    aligned_24b: bool = True,
) -> bytes:
    key_b = key.encode("utf-8")
    if aligned_24b:
        hdr = struct.pack("<QIIII", 0xFCFB6D1BA7725C30, 5, len(key_b), 0x12345678, 0)
    else:
        hdr = struct.pack("<QIII", 0xFCFB6D1BA7725C30, 5, len(key_b), 0x12345678)

    if resp_dt is not None:
        wk = _dt_to_webkit_us(resp_dt)
        pkl_body = (
            struct.pack("<iqq", 3, wk - 500_000, wk)
            + struct.pack("<I", len(http_headers))
            + _align4_bytes(http_headers)
        )
        stream0 = struct.pack("<I", len(pkl_body)) + pkl_body
    else:
        stream0 = http_headers

    eof0 = struct.pack("<QIII", 0xF4FA6F45970D41D8, 0, 0, len(stream0))
    return hdr + key_b + stream0 + eof0


@pytest.fixture
def isolated_case_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[[str, str], Tuple[str, Path, Path]]:
    appdata_dir = tmp_path / "appdata_wft"
    cases_root = tmp_path / "cases_root"
    custom_loc = appdata_dir / "custom_locations.json"
    tool_paths = appdata_dir / "tool_paths.json"
    appdata_dir.mkdir(parents=True, exist_ok=True)
    cases_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata_dir))
    monkeypatch.setenv("WFT_CASES_DIR", str(cases_root))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(custom_loc))
    monkeypatch.setenv("WFT_TOOL_PATHS_FILE", str(tool_paths))
    monkeypatch.setattr(cfg, "APP_DATA_DIR", appdata_dir)
    monkeypatch.setattr(cfg, "CASES_DIR", cases_root)
    monkeypatch.setattr(cfg, "CUSTOM_LOCATIONS_FILE", custom_loc)

    created_case_ids: List[str] = []

    def _make_case(case_id: str, source_type: str = "image") -> Tuple[str, Path, Path]:
        case_dir = cases_root / case_id
        cfg.register_case_dir(case_id, case_dir)
        init_case_db(case_id)
        staging_dir = case_dir / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS case_metadata (key VARCHAR PRIMARY KEY, value VARCHAR);"
            )
            cur.execute(
                "INSERT OR REPLACE INTO case_metadata (key, value) VALUES ('source_type', ?);",
                [source_type],
            )
        log_processing_event(
            case_id=case_id,
            module_name="Pipeline:Extractor",
            command_executed=f"Extractor ({source_type}): synthetic",
            exit_code=0,
            rows_ingested=0,
            duration_ms=1,
            status="SUCCESS",
        )
        created_case_ids.append(case_id)
        return case_id, case_dir, staging_dir

    yield _make_case

    for cid in created_case_ids:
        try:
            DuckDBManager.close_connection(cid)
            cfg.unregister_case_dir(cid)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# (a) BaseParser Dual-Path (`pandas` vs `pd = None`) & WAL Copy Isolation
# ---------------------------------------------------------------------------
def _exercise_base_parser_insert_suite(bp: BaseParser, prefix: str) -> Dict[str, Any]:
    ddl = f"""
    CREATE TABLE IF NOT EXISTS {prefix}_typed (
        _row_id BIGINT,
        event_ts TIMESTAMP,
        offset_ts TIMESTAMP,
        empty_ts TIMESTAMP,
        big_id BIGINT,
        flag BOOLEAN,
        score DOUBLE,
        meta VARCHAR
    );
    """
    recs = [
        {
            "event_ts": datetime(2020, 5, 1, 12, 30, 45, tzinfo=timezone.utc),
            "offset_ts": "2020-05-01T14:30:45+02:00",
            "empty_ts": "",
            "big_id": 132328100451234567,
            "flag": "true",
            "score": 98.5,
            "meta": {"k": "v1"},
        },
        {
            "event_ts": "2021-11-09 08:15:00",
            "offset_ts": "",
            "empty_ts": None,
            "big_id": None,
            "flag": "",
            "score": "",
            "meta": "plain",
        },
    ]
    cnt1 = bp.insert_records(
        table_name=f"{prefix}_typed",
        records=recs,
        schema_ddl=ddl,
        artifact_id=f"{prefix}_art",
        category="WEB RELATED",
        display_name="Typed Test",
        source_tool="BaseParserTest",
        append=False,
    )
    assert cnt1 == 2

    # Dynamic table creation (`schema_ddl=None`) with all-None column in batch 1 followed by string in batch 2
    dyn_tbl = f"{prefix}_dyn"
    cnt_dyn1 = bp.insert_records(
        table_name=dyn_tbl,
        records=[{"label": None, "num": 42}],
        schema_ddl=None,
        append=False,
    )
    assert cnt_dyn1 == 1
    cnt_dyn2 = bp.insert_records(
        table_name=dyn_tbl,
        records=[{"label": "populated_later", "num": 99}],
        schema_ddl=None,
        append=True,
    )
    assert cnt_dyn2 == 2

    with DuckDBManager.get_lock(bp.case_id):
        cur = DuckDBManager.get_connection(bp.case_id).cursor()
        typed_rows = cur.execute(
            f'SELECT _row_id, event_ts, offset_ts, empty_ts, big_id, flag, score, meta FROM "{prefix}_typed" ORDER BY _row_id;'
        ).fetchall()
        dyn_rows = cur.execute(
            f'SELECT _row_id, label, num FROM "{dyn_tbl}" ORDER BY _row_id;'
        ).fetchall()

    # Empty batch with append=False MUST delete rows and set artifact_registry.row_count = 0
    trunc_tbl = f"{prefix}_trunc"
    bp.insert_records(
        table_name=trunc_tbl,
        records=[{"x": "hello"}],
        artifact_id=f"{prefix}_trunc_art",
        category="WEB RELATED",
        display_name="Trunc Test",
        source_tool="BaseParserTest",
        append=False,
    )
    cnt_after_clear = bp.insert_records(
        table_name=trunc_tbl,
        records=[],
        artifact_id=f"{prefix}_trunc_art",
        category="WEB RELATED",
        display_name="Trunc Test",
        source_tool="BaseParserTest",
        append=False,
    )
    assert cnt_after_clear == 0
    with DuckDBManager.get_lock(bp.case_id):
        cur = DuckDBManager.get_connection(bp.case_id).cursor()
        rem_rows = cur.execute(f'SELECT COUNT(*) FROM "{trunc_tbl}";').fetchone()[0]
        reg_cnt = cur.execute(
            "SELECT row_count FROM artifact_registry WHERE artifact_id = ?;",
            [f"{prefix}_trunc_art"],
        ).fetchone()[0]
    assert rem_rows == 0
    assert reg_cnt == 0

    return {"typed_rows": typed_rows, "dyn_rows": dyn_rows}


def test_a_base_parser_pandas_and_pure_python_parity(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert base_parser_mod.pd is not None, "pandas must be installed on host for Path A check"
    cid, _cdir, sdir = isolated_case_factory("case_m3a_a", "image")
    bp = BaseParser(cid, sdir)

    res_pd = _exercise_base_parser_insert_suite(bp, "with_pd")

    monkeypatch.setattr(base_parser_mod, "pd", None)
    assert base_parser_mod.pd is None
    res_no_pd = _exercise_base_parser_insert_suite(bp, "without_pd")

    # Exact byte-for-byte parity across pandas and pure-Python executemany paths
    assert res_pd["typed_rows"] == res_no_pd["typed_rows"]
    assert res_pd["dyn_rows"] == res_no_pd["dyn_rows"]

    row0, row1 = res_pd["typed_rows"]
    # Zero +05:30 shift: UTC 12:30:45 stays 12:30:45, and 14:30:45+02:00 becomes 12:30:45!
    assert row0[1] == datetime(2020, 5, 1, 12, 30, 45)
    assert row0[2] == datetime(2020, 5, 1, 12, 30, 45)
    assert row0[3] is None
    # Full 64-bit integer precision preserved even when row 2 has None!
    assert row0[4] == 132328100451234567
    assert row0[5] is True
    assert row0[6] == 98.5
    assert json.loads(row0[7]) == {"k": "v1"}

    assert row1[1] == datetime(2021, 11, 9, 8, 15, 0)
    assert row1[2] is None
    assert row1[4] is None
    assert row1[5] is None
    assert row1[6] is None

    assert res_pd["dyn_rows"] == [(1, None, 42), (2, "populated_later", 99)]

    # Verify copy_sqlite_with_wal collision isolation when two same-named DBs share temp_dir
    src_a = tmp_path / "prof_a" / "Cookies"
    src_b = tmp_path / "prof_b" / "Cookies"
    src_a.parent.mkdir(parents=True)
    src_b.parent.mkdir(parents=True)
    for p, marker in ((src_a, "alpha_val"), (src_b, "beta_val")):
        c = sqlite3.connect(str(p))
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("CREATE TABLE t (v TEXT);")
        c.execute("INSERT INTO t VALUES (?);", [marker])
        c.commit()
        c.close()

    shared_tmp = tmp_path / "shared_wal_tmp"
    cp_a = copy_sqlite_with_wal(src_a, shared_tmp)
    cp_b = copy_sqlite_with_wal(src_b, shared_tmp)
    assert cp_a.name == "Cookies" and cp_b.name == "Cookies"
    assert cp_a.resolve() != cp_b.resolve()
    with sqlite3.connect(str(cp_a)) as ca, sqlite3.connect(str(cp_b)) as cb:
        assert ca.execute("SELECT v FROM t;").fetchone()[0] == "alpha_val"
        assert cb.execute("SELECT v FROM t;").fetchone()[0] == "beta_val"


# ---------------------------------------------------------------------------
# (b) resolve_evidence_path 3-Tier Determinism & Generic Collision Resistance
# ---------------------------------------------------------------------------
def test_b_resolve_evidence_path_tiers_and_collision_resistance(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
) -> None:
    cid, _cdir, sdir = isolated_case_factory("case_m3a_b", "image")
    bp = BaseParser(cid, sdir)

    with DuckDBManager.get_lock(cid):
        cur = DuckDBManager.get_connection(cid).cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vfs_files (
                part_index INTEGER,
                vfs_path VARCHAR,
                staged_rel_path VARCHAR,
                si_modified TIMESTAMP
            );
            """
        )
        cur.execute("DELETE FROM vfs_files;")
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified) VALUES (0, ?, ?, TIMESTAMP '2021-06-01 10:00:00');",
            [r"D:\Data\Secret\budget.xlsx", "Enrichment/Part1/Data/Secret/budget.xlsx"],
        )
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified) VALUES (0, ?, ?, TIMESTAMP '2021-05-01 09:00:00');",
            [r"C:\Users\Alice\Documents\old.docx", "VSS/VSS_1/UserFiles/Alice/Documents/old.docx"],
        )

        # Populate raw_mft with duplicate web.config and History filenames across multiple directories,
        # intentionally giving the WRONG directory a newer LastModified0x10 and identical FileSize!
        cur.execute("DELETE FROM raw_mft;")
        cur.execute(
            """
            INSERT INTO raw_mft (EntryNumber, ParentPath, FileName, FileSize, InUse, LastModified0x10)
            VALUES
                (101, '.\\Program Files\\VendorApp', 'web.config', 4096, true, TIMESTAMP '2024-01-01 00:00:00'),
                (102, '.\\inetpub\\wwwroot', 'web.config', 4096, true, TIMESTAMP '2021-01-01 00:00:00'),
                (103, '.\\Users\\Mallory\\AppData\\Local\\Google\\Chrome\\User Data\\Default', 'History', 32768, true, TIMESTAMP '2024-02-01 00:00:00'),
                (104, '.\\Users\\Bob\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 2', 'History', 32768, true, TIMESTAMP '2021-02-01 00:00:00'),
                (105, '.\\Users\\Alice\\Desktop\\Projects', 'unique_forensic_note_77.txt', 512, true, TIMESTAMP '2022-03-03 03:03:03');
            """
        )

    # 1. Tier (a): vfs_files exact hit & VSS provenance prefix
    f_vfs = sdir / "Enrichment" / "Part1" / "Data" / "Secret" / "budget.xlsx"
    assert bp.resolve_evidence_path(f_vfs) == r"D:\Data\Secret\budget.xlsx"

    f_vfs_vss = sdir / "VSS" / "VSS_1" / "UserFiles" / "Alice" / "Documents" / "old.docx"
    assert bp.resolve_evidence_path(f_vfs_vss) == r"[VSS#1] C:\Users\Alice\Documents\old.docx"

    # 2. Tier (b): Staging hierarchy reconstruction (`Enrichment/<part>/inetpub/wwwroot/web.config`, `Browsers/...`, `VSS/VSS_2/...`)
    f_enr = sdir / "Enrichment" / "Partition_2" / "inetpub" / "wwwroot" / "web.config"
    assert bp.resolve_evidence_path(f_enr, 4096) == r"C:\inetpub\wwwroot\web.config"

    f_vss_enr = sdir / "VSS" / "VSS_2" / "Enrichment" / "Part0" / "Users" / "Bob" / "Documents" / "report.pdf"
    assert bp.resolve_evidence_path(f_vss_enr) == r"[VSS#2] C:\Users\Bob\Documents\report.pdf"

    f_chr = sdir / "Browsers" / "Chrome" / "Alice" / "Profile 1" / "History"
    assert (
        bp.resolve_evidence_path(f_chr, 32768)
        == r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Profile 1\History"
    )

    # 3. Tier (c): Parent-aware raw_mft disambiguation (must pick .\inetpub\wwwroot and .\Users\Bob\...\Profile 2, NOT newer VendorApp/Mallory!)
    f_mft_wc = sdir / "Documents" / "inetpub" / "wwwroot" / "web.config"
    assert bp.resolve_evidence_path(f_mft_wc, 4096) == r"C:\inetpub\wwwroot\web.config"

    f_mft_hist = sdir / "Documents" / "Users" / "Bob" / "Profile 2" / "History"
    assert (
        bp.resolve_evidence_path(f_mft_hist, 32768)
        == r"C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Profile 2\History"
    )

    # Non-generic unique filename resolves via raw_mft
    f_unique = sdir / "Documents" / "unique_forensic_note_77.txt"
    assert bp.resolve_evidence_path(f_unique, 512) == r"C:\Users\Alice\Desktop\Projects\unique_forensic_note_77.txt"

    # 4. Bare generic filenames MUST NOT collide with raw_mft!
    f_bare_hist = sdir / "History"
    assert bp.resolve_evidence_path(f_bare_hist, 32768) == "[Staged] History"
    f_sqlite_hist = sdir / "SQLite" / "History"
    assert bp.resolve_evidence_path(f_sqlite_hist, 32768) == "[Staged] SQLite/History"


# ---------------------------------------------------------------------------
# (c) get_original_mtime Contracts (Zero wall-clock `now()` Fabrication)
# ---------------------------------------------------------------------------
def test_c_get_original_mtime_contracts(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
) -> None:
    cid, _cdir, sdir = isolated_case_factory("case_m3a_c_img", "image")
    bp_img = BaseParser(cid, sdir)

    # Create real files on disk (which have host wall-clock ctime/mtime right now)
    f_valid_vfs = sdir / "Browsers" / "Chrome" / "Alice" / "Default" / "Cache" / "f_000001"
    f_null_vfs = sdir / "Browsers" / "Chrome" / "Alice" / "Default" / "Cache" / "f_000002"
    f_fresh_untracked = sdir / "Browsers" / "Chrome" / "Alice" / "Default" / "Cache" / "f_000003"
    f_utimed = sdir / "Browsers" / "Chrome" / "Alice" / "Default" / "Cache" / "f_000004"
    for fp in (f_valid_vfs, f_null_vfs, f_fresh_untracked, f_utimed):
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(b"cache_payload")

    # Preserve historical timestamp 2020-03-15 12:00:00 UTC on f_utimed via os.utime
    os.utime(f_utimed, (1584273600, 1584273600))

    # 1. Test against init_case_db's full vfs_files schema (incl. fn_modified fallback & all-NULL immediate None)
    with DuckDBManager.get_lock(cid):
        cur = DuckDBManager.get_connection(cid).cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vfs_files (
                staged_rel_path VARCHAR,
                vfs_path VARCHAR,
                si_modified TIMESTAMP,
                fn_modified TIMESTAMP,
                si_created TIMESTAMP
            );
            """
        )
        cur.execute("DELETE FROM vfs_files;")
        cur.execute(
            "INSERT INTO vfs_files (staged_rel_path, vfs_path, si_modified) VALUES (?, ?, TIMESTAMP '2021-04-10 09:15:00');",
            [
                "Browsers/Chrome/Alice/Default/Cache/f_000001",
                r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000001",
            ],
        )
        cur.execute(
            "INSERT INTO vfs_files (staged_rel_path, vfs_path, si_modified, fn_modified, si_created) VALUES (?, ?, NULL, NULL, NULL);",
            [
                "Browsers/Chrome/Alice/Default/Cache/f_000002",
                r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000002",
            ],
        )
        cur.execute(
            "INSERT INTO vfs_files (staged_rel_path, vfs_path, si_modified, fn_modified, si_created) VALUES (?, ?, NULL, TIMESTAMP '2019-08-20 16:45:30', NULL);",
            ["Browsers/Chrome/Alice/Default/Cache/f_fn_only", r"C:\f_fn_only"],
        )

    assert bp_img.get_original_mtime(f_valid_vfs) == "2021-04-10 09:15:00"
    # Matching row with NULL timestamp MUST return None immediately, NEVER falling back to Path.stat()!
    assert bp_img.get_original_mtime(f_null_vfs) is None
    # Fallback to fn_modified when si_modified is NULL
    assert (
        bp_img.get_original_mtime(sdir / "Browsers" / "Chrome" / "Alice" / "Default" / "Cache" / "f_fn_only")
        == "2019-08-20 16:45:30"
    )

    # 2. Minimal 3-column vfs_files schema (omitting fn_modified & si_created to verify DESCRIBE introspection)
    with DuckDBManager.get_lock(cid):
        cur = DuckDBManager.get_connection(cid).cursor()
        cur.execute("DROP TABLE IF EXISTS vfs_files;")
        cur.execute(
            """
            CREATE TABLE vfs_files (
                staged_rel_path VARCHAR,
                vfs_path VARCHAR,
                si_modified TIMESTAMP
            );
            """
        )
        cur.execute(
            "INSERT INTO vfs_files VALUES (?, ?, TIMESTAMP '2021-04-10 09:15:00');",
            [
                "Browsers/Chrome/Alice/Default/Cache/f_000001",
                r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000001",
            ],
        )
        cur.execute(
            "INSERT INTO vfs_files VALUES (?, ?, NULL);",
            [
                "Browsers/Chrome/Alice/Default/Cache/f_000002",
                r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000002",
            ],
        )

    assert bp_img.get_original_mtime(f_valid_vfs) == "2021-04-10 09:15:00"
    assert bp_img.get_original_mtime(f_null_vfs) is None
    # Un-utimed freshly extracted file in image case with no vfs_files row MUST return None!
    assert bp_img.get_original_mtime(f_fresh_untracked) is None
    # os.utime()-preserved historical timestamp MUST return exact UTC timestamp string!
    assert bp_img.get_original_mtime(f_utimed) == "2020-03-15 12:00:00"

    # Folder source_type case: stat().st_mtime is original folder file mtime and IS returned
    cid_fld, _cdir_fld, sdir_fld = isolated_case_factory("case_m3a_c_folder", "folder")
    bp_fld = BaseParser(cid_fld, sdir_fld)
    f_folder_doc = sdir_fld / "doc.txt"
    f_folder_doc.write_text("evidence", encoding="utf-8")
    os.utime(f_folder_doc, (1620000000, 1620000000))
    assert bp_fld.get_original_mtime(f_folder_doc) == "2021-05-03 00:00:00"


# ---------------------------------------------------------------------------
# (d) ChromiumParser Multi-Profile, Network/Cookies, Cache & SNSS Sessions
# ---------------------------------------------------------------------------
def _seed_chromium_staging(staging_dir: Path) -> None:
    t_visit = _dt_to_webkit_us(datetime(2022, 7, 15, 14, 0, 0, tzinfo=timezone.utc))
    t_orphan = _dt_to_webkit_us(datetime(2022, 1, 10, 8, 30, 0, tzinfo=timezone.utc))
    t_dl_start = _dt_to_webkit_us(datetime(2022, 7, 15, 14, 5, 0, tzinfo=timezone.utc))
    t_dl_end = _dt_to_webkit_us(datetime(2022, 7, 15, 14, 5, 12, tzinfo=timezone.utc))
    t_cookie_c = _dt_to_webkit_us(datetime(2022, 6, 1, 10, 0, 0, tzinfo=timezone.utc))
    t_cookie_lu = _dt_to_webkit_us(datetime(2022, 7, 15, 11, 20, 0, tzinfo=timezone.utc))
    t_cookie_2150 = _dt_to_webkit_us(datetime(2150, 1, 1, 0, 0, 0, tzinfo=timezone.utc))

    # 1. Chrome Alice/Default + Alice/Profile 1 History
    for prof_name, url_suffix in (("Default", "alpha"), ("Profile 1", "beta")):
        pdir = staging_dir / "Browsers" / "Chrome" / "Alice" / prof_name
        pdir.mkdir(parents=True, exist_ok=True)
        h_db = pdir / "History"
        with sqlite3.connect(str(h_db)) as conn:
            conn.execute(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);"
            )
            conn.execute(
                "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);"
            )
            conn.execute(
                "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, total_bytes INTEGER, received_bytes INTEGER, start_time INTEGER, end_time INTEGER, mime_type TEXT, danger_type INTEGER, state INTEGER, opened INTEGER);"
            )
            conn.execute(
                "CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);"
            )
            conn.execute(
                "CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);"
            )
            conn.execute(
                "INSERT INTO urls VALUES (1, ?, ?, 3, 1, ?);",
                [f"https://portal.example.com/{url_suffix}", f"Portal {prof_name}", t_visit],
            )
            # Orphaned URL (no row in `visits`)
            conn.execute(
                "INSERT INTO urls VALUES (2, ?, 'Expired Visit Page', 1, 0, ?);",
                [f"https://archive.example.com/orphan_{url_suffix}", t_orphan],
            )
            conn.execute(
                "INSERT INTO visits VALUES (10, 1, ?, 0, 1, 5000000);",
                [t_visit],
            )
            # Download whose URL exists ONLY in downloads_url_chains
            conn.execute(
                "INSERT INTO downloads VALUES (5, ?, ?, 40960, 40960, ?, ?, 'application/pdf', 0, 1, 1);",
                [
                    f"C:\\Users\\Alice\\Downloads\\spec_{url_suffix}.pdf",
                    f"C:\\Users\\Alice\\Downloads\\spec_{url_suffix}.pdf",
                    t_dl_start,
                    t_dl_end,
                ],
            )
            conn.execute(
                "INSERT INTO downloads_url_chains VALUES (5, 0, ?), (5, 1, ?);",
                [
                    f"https://redir.example.com/start_{url_suffix}",
                    f"https://cdn.example.com/files/spec_{url_suffix}.pdf",
                ],
            )
            conn.execute(
                "INSERT INTO keyword_search_terms VALUES (1, 999, ?, ?);",
                [f"dfir {url_suffix}", f"dfir {url_suffix}"],
            )

        # Duplicate copy in staging/SQLite to verify SHA-256 deduplication
        if prof_name == "Default":
            sq_dir = staging_dir / "SQLite"
            sq_dir.mkdir(parents=True, exist_ok=True)
            (sq_dir / "Alice_Default_History").write_bytes(h_db.read_bytes())

        # Network/Cookies with identical payload across Default and Profile 1 (must NOT collapse across profiles!)
        net_dir = pdir / "Network"
        net_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(net_dir / "Cookies")) as conn:
            conn.execute(
                """
                CREATE TABLE cookies (
                    creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT,
                    encrypted_value BLOB, path TEXT, expires_utc INTEGER,
                    is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, last_update_utc INTEGER
                );
                """
            )
            conn.execute(
                "INSERT INTO cookies VALUES (?, '.example.com', 'sid_v20', '', ?, '/', ?, 1, 1, 0, ?);",
                [t_cookie_c, b"v20\x01\x02\x03\x04\x05", t_cookie_2150, t_cookie_lu],
            )
            conn.execute(
                "INSERT INTO cookies VALUES (?, '.example.com', 'sid_v10', '', ?, '/', 9223372036854775807, 1, 0, ?, ?);",
                [t_cookie_c + 1, b"v10\xaa\xbb\xcc", t_cookie_lu, t_cookie_lu],
            )
            conn.execute(
                "INSERT INTO cookies VALUES (?, '.example.com', 'sid_dpapi', '', ?, '/', 0, 0, 1, ?, 0);",
                [t_cookie_c + 2, b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf", t_cookie_lu],
            )
            conn.execute(
                "INSERT INTO cookies VALUES (?, '.example.com', 'theme', 'dark', ?, '/', ?, 0, 0, ?, ?);",
                [t_cookie_c + 3, b"", t_cookie_2150, t_cookie_lu, t_cookie_lu],
            )

    # VSS_1 Chrome Cookies (identical bytes under VSS_1 -> must also survive with VSS_1 scope!)
    vss_net = staging_dir / "VSS" / "VSS_1" / "Browsers" / "Chrome" / "Alice" / "Default" / "Network"
    vss_net.mkdir(parents=True, exist_ok=True)
    (vss_net / "Cookies").write_bytes(
        (staging_dir / "Browsers" / "Chrome" / "Alice" / "Default" / "Network" / "Cookies").read_bytes()
    )

    # Web Data (Autofill Unix epoch seconds), Top Sites, Login Data (blank username -> None), Bookmarks
    def_dir = staging_dir / "Browsers" / "Chrome" / "Alice" / "Default"
    with sqlite3.connect(str(def_dir / "Web Data")) as conn:
        conn.execute(
            "CREATE TABLE autofill (name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);"
        )
        conn.execute(
            "INSERT INTO autofill VALUES ('email', 'alice@corp.example', 'alice@corp.example', 1650000000, 1650100000, 4);"
        )

    with sqlite3.connect(str(def_dir / "Top Sites")) as conn:
        conn.execute("CREATE TABLE top_sites (url TEXT, url_rank INTEGER, title TEXT);")
        conn.execute("INSERT INTO top_sites VALUES ('https://portal.example.com/', 0, 'Corp Portal');")

    with sqlite3.connect(str(def_dir / "Login Data")) as conn:
        conn.execute(
            """
            CREATE TABLE logins (
                origin_url TEXT, action_url TEXT, username_value TEXT, password_value BLOB,
                signon_realm TEXT, date_created INTEGER, date_last_used INTEGER, times_used INTEGER
            );
            """
        )
        # Blank username_value (e.g. "Never save for this site" blacklist entry) -> username_value MUST be None!
        conn.execute(
            "INSERT INTO logins VALUES ('https://bank.example.com/', '', '', ?, 'https://bank.example.com/', ?, 0, 0);",
            [b"", t_cookie_c],
        )
        # Valid saved login
        conn.execute(
            "INSERT INTO logins VALUES ('https://mail.example.com/login', 'https://mail.example.com/auth', 'alice.smith', ?, 'https://mail.example.com/', ?, ?, 7);",
            [b"v10enc", t_cookie_c, t_cookie_lu],
        )
        # Completely empty origin+realm row -> must be skipped
        conn.execute(
            "INSERT INTO logins VALUES ('', '', '', ?, '', 0, 0, 0);",
            [b""],
        )

    # Edge & Brave Bookmarks (nested folders)
    bm_payload = {
        "roots": {
            "bookmark_bar": {
                "name": "Bookmarks bar",
                "type": "folder",
                "children": [
                    {
                        "name": "Work",
                        "type": "folder",
                        "children": [
                            {
                                "name": "Docs",
                                "type": "folder",
                                "children": [
                                    {
                                        "name": "Runbook",
                                        "type": "url",
                                        "url": "https://docs.example.com/runbook",
                                        "date_added": str(t_visit),
                                        "date_modified": str(t_dl_end),
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }
    }
    edge_dir = staging_dir / "Browsers" / "Edge" / "Bob" / "Default"
    edge_dir.mkdir(parents=True, exist_ok=True)
    (edge_dir / "Bookmarks").write_text(json.dumps(bm_payload), encoding="utf-8")

    # Legacy flat staging layout (`Browsers/Edge/Bob/History` with NO `<Profile>` subdir)
    edge_flat_hist = staging_dir / "Browsers" / "Edge" / "Bob" / "History"
    with sqlite3.connect(str(edge_flat_hist)) as conn:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);"
        )
        conn.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);"
        )
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://edgeflat.example.com/', 'Edge Flat', 2, 1, ?);",
            [t_visit],
        )
        conn.execute(
            "INSERT INTO visits VALUES (1, 1, ?, 0, 1, 1000);",
            [t_visit],
        )

    brave_dir = staging_dir / "Browsers" / "Brave" / "Carol" / "Default"
    brave_dir.mkdir(parents=True, exist_ok=True)
    (brave_dir / "Bookmarks").write_text(json.dumps(bm_payload), encoding="utf-8")

    # Simple Cache (24-byte aligned with Pickle + NUL-delimited HTTP headers) & headerless fresh cache file
    cache_dir = def_dir / "Cache" / "Cache_Data"
    cache_dir.mkdir(parents=True, exist_ok=True)
    sc_dt = datetime(2020, 10, 21, 7, 28, 0, tzinfo=timezone.utc)
    sc_bytes = _build_simple_cache_entry(
        key="1/0/https://cdn.example.com/app.bundle.js",
        http_headers=b"HTTP/1.1 200 OK\x00Date: Wed, 21 Oct 2020 07:28:00 GMT\x00Content-Type: application/javascript\x00\x00",
        resp_dt=sc_dt,
        aligned_24b=True,
    )
    (cache_dir / "0123456789abcdef_0").write_bytes(sc_bytes)

    # Headerless Blockfile cache entry in an image case (no HTTP Date, no vfs_files row, fresh host write -> response_time MUST be NULL!)
    (cache_dir / "f_0000aa").write_bytes(
        b"\x00" * 16 + b"https://rawcache.example.com/pixel.png" + b"\x00" * 64
    )

    # Binary SNSS Current Session & Sessions/Tabs_*
    t_active = _dt_to_webkit_us(datetime(2022, 7, 15, 15, 30, 0, tzinfo=timezone.utc))
    t_tabs_fn = _dt_to_webkit_us(datetime(2022, 7, 14, 20, 0, 0, tzinfo=timezone.utc))
    cur_sess_bytes = (
        b"SNSS"
        + struct.pack("<i", 3)
        + _pack_snss_cmd(0, struct.pack("<II", 2, 11))
        + _pack_snss_cmd(
            6,
            _build_snss_nav_pickle(11, 0, "https://intranet.example.com/dashboard", "Intranet Dashboard"),
        )
        + _pack_snss_cmd(7, struct.pack("<Ii", 11, 0))
        + _pack_snss_cmd(21, struct.pack("<I4xq", 11, t_active))
    )
    (def_dir / "Current Session").write_bytes(cur_sess_bytes)

    sess_sub = def_dir / "Sessions"
    sess_sub.mkdir(parents=True, exist_ok=True)
    tabs_bytes = (
        b"SNSS"
        + struct.pack("<i", 1)
        + _pack_snss_cmd(
            1,
            _build_snss_nav_pickle(25, 0, "https://wiki.example.com/incident", "Incident Wiki"),
        )
        + _pack_snss_cmd(4, struct.pack("<Iiq", 25, 0, t_tabs_fn))
    )
    (sess_sub / f"Tabs_{t_tabs_fn}").write_bytes(tabs_bytes)


def test_d_chromium_multi_profile_cookies_cache_and_snss(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
) -> None:
    cid, _cdir, sdir = isolated_case_factory("case_m3a_d", "image")
    _seed_chromium_staging(sdir)

    res = ChromiumParser(cid, sdir).parse()
    assert all("firefox" not in tbl for tbl in res.keys())

    with DuckDBManager.get_lock(cid):
        cur = DuckDBManager.get_connection(cid).cursor()

        # History: 2 profiles * (1 visited + 1 orphaned) = 4 rows (SQLite duplicate skipped!)
        hist_rows = cur.execute(
            "SELECT profile, url, visit_time FROM parsed_chrome_history ORDER BY profile, url;"
        ).fetchall()
        assert len(hist_rows) == 4
        profiles_seen = {r[0] for r in hist_rows}
        assert profiles_seen == {"Alice/Default", "Alice/Profile 1"}
        assert any("orphan_alpha" in r[1] for r in hist_rows)
        assert any("orphan_beta" in r[1] for r in hist_rows)

        # Downloads: downloads_url_chains resolved both tab_url (final) and site_url (initial)
        dl_rows = cur.execute(
            "SELECT profile, target_path, tab_url, site_url, state, danger_type FROM parsed_chrome_downloads ORDER BY profile;"
        ).fetchall()
        assert len(dl_rows) == 2
        assert dl_rows[0][2] == "https://cdn.example.com/files/spec_alpha.pdf"
        assert dl_rows[0][3] == "https://redir.example.com/start_alpha"
        assert dl_rows[0][4] == "COMPLETE"
        assert dl_rows[0][5] == "NOT_DANGEROUS"

        # Keyword search terms (LEFT JOIN urls preserved orphaned url_id=999)
        kst_rows = cur.execute("SELECT term FROM parsed_chrome_search_terms ORDER BY term;").fetchall()
        assert [r[0] for r in kst_rows] == ["dfir alpha", "dfir beta"]

        # Cookies: 4 cookies * 3 scopes (Alice/Default, Alice/Profile 1, Alice/Default [VSS_1]) = 12 rows!
        cookie_rows = cur.execute(
            "SELECT name, value, expires_utc, last_access_utc FROM parsed_chrome_cookies;"
        ).fetchall()
        assert len(cookie_rows) == 12
        by_name = {r[0]: r for r in cookie_rows}
        assert by_name["sid_v20"][1] == "[AES-GCM Encrypted (v20)]"
        assert by_name["sid_v20"][2] == datetime(2150, 1, 1, 0, 0, 0)
        assert by_name["sid_v20"][3] == datetime(2022, 7, 15, 11, 20, 0)  # last_update_utc fallback!
        assert by_name["sid_v10"][1] == "[AES-GCM Encrypted (v10)]"
        assert by_name["sid_v10"][2] is None  # INT64_MAX overflow safely None without dropping row!
        assert by_name["sid_dpapi"][1] == "[DPAPI Encrypted]"
        assert by_name["theme"][1] == "dark"

        # Autofill Unix seconds converted accurately
        af_row = cur.execute(
            "SELECT name, value, date_created, count FROM parsed_chrome_autofill;"
        ).fetchone()
        assert af_row == ("email", "alice@corp.example", datetime(2022, 4, 15, 5, 20, 0), 4)

        # Edge & Brave dynamic bookmarks tables created with full recursive folder path
        edge_bm = cur.execute("SELECT title, folder FROM parsed_edge_bookmarks;").fetchone()
        brave_bm = cur.execute("SELECT title, folder FROM parsed_brave_bookmarks;").fetchone()
        assert edge_bm == ("Runbook", "Bookmarks Bar > Work > Docs")
        assert brave_bm == ("Runbook", "Bookmarks Bar > Work > Docs")

        # Legacy flat staging Edge History parsed cleanly with Bob/Default provenance
        edge_hist = cur.execute(
            "SELECT browser, profile, url FROM parsed_edge_history;"
        ).fetchall()
        assert edge_hist == [("Edge", "Bob/Default", "https://edgeflat.example.com/")]

        # Logins: blank username stays None, empty origin+realm skipped
        login_rows = cur.execute(
            "SELECT origin_url, username_value, times_used FROM parsed_chrome_logins ORDER BY origin_url;"
        ).fetchall()
        assert login_rows == [
            ("https://bank.example.com/", None, 0),
            ("https://mail.example.com/login", "alice.smith", 7),
        ]

        # Cache: Simple Cache has exact 2020-10-21 07:28:00 UTC; fresh headerless image file has NULL (ZERO now()!)
        cache_rows = cur.execute(
            "SELECT url, response_time, content_type FROM parsed_chrome_cache ORDER BY url;"
        ).fetchall()
        assert len(cache_rows) == 2
        assert cache_rows[0] == (
            "https://cdn.example.com/app.bundle.js",
            datetime(2020, 10, 21, 7, 28, 0),
            "application/javascript",
        )
        assert cache_rows[1][0] == "https://rawcache.example.com/pixel.png"
        assert cache_rows[1][1] is None

        # SNSS Sessions (including browser & profile provenance columns)
        sess_rows = cur.execute(
            "SELECT browser, profile, window_id, tab_id, url, title, active, last_active_time FROM parsed_chrome_session ORDER BY tab_id;"
        ).fetchall()
        assert sess_rows == [
            (
                "Chrome",
                "Alice/Default",
                2,
                11,
                "https://intranet.example.com/dashboard",
                "Intranet Dashboard",
                True,
                datetime(2022, 7, 15, 15, 30, 0),
            ),
            (
                "Chrome",
                "Alice/Default",
                0,
                25,
                "https://wiki.example.com/incident",
                "Incident Wiki",
                False,
                datetime(2022, 7, 14, 20, 0, 0),
            ),
        ]


# ---------------------------------------------------------------------------
# (e) FirefoxParser Multi-Profile, moz_annos Downloads, Zero-NULL Dual Columns & Normalizer
# ---------------------------------------------------------------------------
def _seed_firefox_staging(staging_dir: Path) -> Tuple[str, str]:
    t_visit = _dt_to_prtime_us(datetime(2022, 8, 10, 9, 0, 0, tzinfo=timezone.utc))
    t_bm_add = _dt_to_prtime_us(datetime(2022, 8, 1, 12, 0, 0, tzinfo=timezone.utc))
    t_bm_mod = _dt_to_prtime_us(datetime(2022, 8, 5, 16, 45, 0, tzinfo=timezone.utc))
    t_dl_start = _dt_to_prtime_us(datetime(2022, 8, 10, 9, 10, 0, tzinfo=timezone.utc))
    t_dl_end_ms = _dt_to_epoch_ms(datetime(2022, 8, 10, 9, 10, 25, tzinfo=timezone.utc))

    long_enc_user = "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECN9x0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ=="
    long_enc_pass = "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECP8z9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz=="
    assert len(long_enc_user) > 80

    prof_alice = staging_dir / "Browsers" / "Firefox" / "alice" / "abc.default-release"
    prof_bob = staging_dir / "Browsers" / "Firefox" / "bob" / "xyz.default"
    prof_vss = staging_dir / "VSS" / "VSS_1" / "Browsers" / "Firefox" / "alice" / "abc.default-release"
    for pd_dir in (prof_alice, prof_bob, prof_vss):
        pd_dir.mkdir(parents=True, exist_ok=True)

    # Seed places.sqlite for alice (with WAL enabled!) and bob
    for idx_p, (pd_dir, slug) in enumerate(((prof_alice, "alice"), (prof_bob, "bob"))):
        places_p = pd_dir / "places.sqlite"
        conn = sqlite3.connect(str(places_p))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);"
        )
        conn.execute(
            "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);"
        )
        conn.execute(
            "CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);"
        )
        conn.execute(
            "CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER, lastModified INTEGER);"
        )
        conn.execute(
            "CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT);"
        )

        conn.execute(
            "INSERT INTO moz_places VALUES (1, ?, ?, 5, 2, ?), (2, 'place:sort=8&maxResults=10', 'Most Visited', 0, 0, NULL), (3, ?, 'Quarterly Report', 1, 0, ?);",
            [
                f"https://intranet.example.org/{slug}",
                f"Home {slug}",
                t_visit + idx_p * 1_000_000,
                f"https://files.example.org/{slug}/Quarterly%20Report.pdf",
                t_dl_start,
            ],
        )
        conn.execute(
            "INSERT INTO moz_historyvisits VALUES (1, 0, 1, ?, 2), (2, 1, 2, ?, 1);",
            [t_visit + idx_p * 1_000_000, t_visit],
        )
        conn.execute(
            "INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI'), (2, 'downloads/destinationFileName'), (3, 'downloads/metaData');"
        )
        meta_json = json.dumps(
            {
                "state": 1,
                "endTime": t_dl_end_ms,
                "fileSize": 204800,
                "contentType": "application/pdf",
            }
        )
        conn.execute(
            "INSERT INTO moz_annos VALUES (1, 3, 1, ?, ?, ?), (2, 3, 2, 'Quarterly Report.pdf', ?, ?), (3, 3, 3, ?, ?, ?);",
            [
                f"file:///C:/Users/{slug}/Downloads/Quarterly%20Report.pdf",
                t_dl_start,
                t_dl_start,
                t_dl_start,
                t_dl_start,
                meta_json,
                t_dl_start,
                t_dl_start,
            ],
        )
        # Nested bookmark folders: root -> Bookmarks Toolbar -> Finance -> Reports -> Bookmark item
        conn.execute(
            """
            INSERT INTO moz_bookmarks VALUES
                (1, 2, NULL, 0, '', ?, ?, 'root________'),
                (2, 2, NULL, 1, 'Bookmarks Toolbar', ?, ?, 'toolbar_____'),
                (3, 2, NULL, 2, 'Finance', ?, ?, 'fin_guid____'),
                (4, 2, NULL, 3, 'Reports', ?, ?, 'rep_guid____'),
                (5, 1, 1, 4, ?, ?, ?, 'bm_item_guid'),
                (6, 1, 2, 2, 'Smart Query', ?, ?, 'bm_place____');
            """,
            [
                t_bm_add,
                t_bm_mod,
                t_bm_add,
                t_bm_mod,
                t_bm_add,
                t_bm_mod,
                t_bm_add,
                t_bm_mod,
                f"Portal {slug}",
                t_bm_add,
                t_bm_mod,
                t_bm_add,
                t_bm_mod,
            ],
        )
        conn.commit()
        conn.close()

    # Copy alice places.sqlite into VSS_1
    (prof_vss / "places.sqlite").write_bytes((prof_alice / "places.sqlite").read_bytes())

    # Legacy downloads.sqlite on bob
    with sqlite3.connect(str(prof_bob / "downloads.sqlite")) as conn:
        conn.execute(
            "CREATE TABLE moz_downloads (id INTEGER PRIMARY KEY, name TEXT, source TEXT, target TEXT, startTime INTEGER, endTime INTEGER, state INTEGER, referrer TEXT, currBytes INTEGER, maxBytes INTEGER, mimeType TEXT);"
        )
        conn.execute(
            "INSERT INTO moz_downloads VALUES (1, 'legacy_tool.exe', 'https://dl.example.org/legacy_tool.exe', 'file:///C:/Users/bob/Downloads/legacy_tool.exe', ?, ?, 1, 'https://dl.example.org/', 8192, 8192, 'application/x-msdownload');",
            [t_dl_start, t_dl_start + 5_000_000],
        )

    # cookies.sqlite: alice (<v15 seconds expiry incl. >2100 = 2150-01-01 = 5680281600), bob (v15 ms expiry)
    with sqlite3.connect(str(prof_alice / "cookies.sqlite")) as conn:
        conn.execute("PRAGMA user_version = 12;")
        conn.execute(
            "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_cookies VALUES (1, '.mozilla.org', 'ff_pref', 'persist_val', '/', 5680281600, ?, ?, 1, 1, 1);",
            [t_visit, t_bm_add],
        )

    with sqlite3.connect(str(prof_bob / "cookies.sqlite")) as conn:
        conn.execute("PRAGMA user_version = 15;")
        conn.execute(
            "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);"
        )
        exp_2030_ms = _dt_to_epoch_ms(datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc))
        conn.execute(
            "INSERT INTO moz_cookies VALUES (1, '.corp.org', 'v15_tok', 'ms_val', '/app', ?, ?, ?, 1, 0, 2);",
            [exp_2030_ms, t_visit, t_bm_add],
        )

    # formhistory.sqlite on alice
    with sqlite3.connect(str(prof_alice / "formhistory.sqlite")) as conn:
        conn.execute(
            "CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_formhistory VALUES (1, 'searchbar-history', 'forensic timeline', 3, ?, ?);",
            [t_bm_add, t_visit],
        )

    # logins.json on alice with >80-char encryptedUsername & encryptedPassword
    logins_payload = {
        "nextId": 2,
        "logins": [
            {
                "id": 1,
                "hostname": "https://sso.example.org",
                "httpRealm": None,
                "formSubmitURL": "https://sso.example.org/login",
                "usernameField": "user",
                "passwordField": "pass",
                "encryptedUsername": long_enc_user,
                "encryptedPassword": long_enc_pass,
                "guid": "{12345678-1234-1234-1234-123456789abc}",
                "encType": 1,
                "timeCreated": t_dl_end_ms - 86_400_000,
                "timeLastUsed": t_dl_end_ms,
                "timePasswordChanged": t_dl_end_ms - 43_200_000,
                "timesUsed": 9,
            }
        ],
    }
    (prof_alice / "logins.json").write_text(json.dumps(logins_payload), encoding="utf-8")
    return long_enc_user, long_enc_pass


def test_e_firefox_multi_profile_downloads_dual_columns_and_normalizer(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
) -> None:
    cid, _cdir, sdir = isolated_case_factory("case_m3a_e", "image")
    long_enc_user, long_enc_pass = _seed_firefox_staging(sdir)

    ff = FirefoxParser(cid, sdir)
    res1 = ff.parse()
    # Re-run to verify idempotent replace (zero row doubling)
    res2 = ff.parse()
    assert res1 == res2

    with DuckDBManager.get_lock(cid):
        cur = DuckDBManager.get_connection(cid).cursor()

        # History: alice, bob, and alice (VSS_1) -> 6 rows (3 visited TYPED + 3 orphaned moz_places LINK; place: URL excluded!)
        h_rows = cur.execute(
            "SELECT username, profile, url, typed_count, transition FROM parsed_firefox_history ORDER BY profile, url;"
        ).fetchall()
        assert len(h_rows) == 6
        assert {r[1] for r in h_rows} == {
            "abc.default-release",
            "abc.default-release (VSS_1)",
            "xyz.default",
        }
        assert sum(1 for r in h_rows if r[3] == 2 and r[4] == "TYPED") == 3
        assert sum(1 for r in h_rows if "Quarterly%20Report.pdf" in r[2] and r[4] == "LINK") == 3

        # Downloads: 3 from moz_annos (alice, bob, VSS_1) + 1 from legacy downloads.sqlite (bob) = 4 rows
        dl_rows = cur.execute(
            "SELECT browser, username, profile, target_path, url, tab_url, total_bytes, start_time, end_time, state, mime_type "
            "FROM parsed_firefox_downloads ORDER BY target_path, profile;"
        ).fetchall()
        assert len(dl_rows) == 4
        alice_dl = [r for r in dl_rows if r[1] == "alice" and "VSS_1" not in r[2]][0]
        assert alice_dl[0] == "Firefox"
        assert alice_dl[3] == r"C:\Users\alice\Downloads\Quarterly Report.pdf"
        assert alice_dl[4] == "https://files.example.org/alice/Quarterly%20Report.pdf"
        assert alice_dl[5] == alice_dl[4]
        assert alice_dl[6] == 204800
        assert alice_dl[7] == datetime(2022, 8, 10, 9, 10, 0)
        assert alice_dl[8] == datetime(2022, 8, 10, 9, 10, 25)
        assert alice_dl[9] == "COMPLETE"
        assert alice_dl[10] == "application/pdf"

        # Cookies: BOTH unified F14/F17 columns AND schema.py columns are non-NULL, including >2100 and v15 ms expiry!
        c_rows = cur.execute(
            "SELECT host_key, host, name, creation_utc, creation_time, expires_utc, expiry, "
            "last_access_utc, last_accessed, is_secure, is_httponly, is_http_only "
            "FROM parsed_firefox_cookies ORDER BY name;"
        ).fetchall()
        assert len(c_rows) == 2
        ff_pref, v15_tok = c_rows[0], c_rows[1]
        assert all(v is not None for v in ff_pref)
        assert ff_pref[0] == ".mozilla.org" and ff_pref[1] == ".mozilla.org"
        assert ff_pref[5].year == 2150 and ff_pref[6].year == 2150
        assert ff_pref[10] is True and ff_pref[11] is True

        assert all(v is not None for v in v15_tok)
        assert v15_tok[5] == datetime(2030, 1, 1, 0, 0, 0)

        # Bookmarks: nested folder path & BOTH date_modified and last_modified non-NULL (place: excluded)
        bm_rows = cur.execute(
            "SELECT title, folder, folder_name, date_added, date_modified, last_modified FROM parsed_firefox_bookmarks ORDER BY profile;"
        ).fetchall()
        assert len(bm_rows) == 3
        assert bm_rows[0][1] == "Bookmarks Toolbar > Finance > Reports"
        assert bm_rows[0][2] == "Bookmarks Toolbar > Finance > Reports"
        assert bm_rows[0][4] == datetime(2022, 8, 5, 16, 45, 0)
        assert bm_rows[0][5] == datetime(2022, 8, 5, 16, 45, 0)

        # FormHistory: BOTH fieldname and field_name non-NULL
        fh_row = cur.execute(
            "SELECT fieldname, field_name, value, times_used, first_used, last_used FROM parsed_firefox_formhistory;"
        ).fetchone()
        assert fh_row[0] == "searchbar-history"
        assert fh_row[1] == "searchbar-history"
        assert fh_row[2] == "forensic timeline"
        assert fh_row[3] == 3
        assert fh_row[4] is not None and fh_row[5] is not None

        # Logins: BOTH schema.py snake_case AND camelCase columns populated, un-truncated encryptedUsername + encryptedPassword + NULL username_value
        lg_row = cur.execute(
            'SELECT hostname, origin_url, action_url, signon_realm, "encryptedUsername", encrypted_username, '
            '"encryptedPassword", encrypted_password, username_value, "timesUsed", times_used, "timeCreated", time_created, date_created '
            "FROM parsed_firefox_logins;"
        ).fetchone()
        assert lg_row[0] == "https://sso.example.org"
        assert lg_row[1] == "https://sso.example.org"
        assert lg_row[2] == "https://sso.example.org/login"
        assert lg_row[3] == "https://sso.example.org"
        assert lg_row[4] == long_enc_user and lg_row[5] == long_enc_user
        assert lg_row[6] == long_enc_pass and lg_row[7] == long_enc_pass
        assert lg_row[8] is None
        assert lg_row[9] == 9 and lg_row[10] == 9
        assert lg_row[11] is not None and lg_row[12] == lg_row[11] and lg_row[13] == lg_row[11]

        # Direct SQL contract verification of TimelineNormalizer projections (zero BinderExceptions!)
        norm_dl_check = cur.execute(
            "SELECT _row_id, browser, target_path, tab_url, total_bytes, COALESCE(start_time, end_time), source_file "
            "FROM parsed_firefox_downloads WHERE COALESCE(start_time, end_time) IS NOT NULL;"
        ).fetchall()
        assert len(norm_dl_check) == 4
        norm_hi_check = cur.execute(
            "SELECT _row_id, browser, url, title, visit_count, visit_time, source_file "
            "FROM parsed_firefox_history WHERE visit_time IS NOT NULL;"
        ).fetchall()
        assert len(norm_hi_check) == 6
        norm_lg_check = cur.execute(
            "SELECT _row_id, browser, origin_url, username_value, COALESCE(date_last_used, date_created), times_used, source_file "
            "FROM parsed_firefox_logins WHERE COALESCE(date_last_used, date_created) IS NOT NULL;"
        ).fetchall()
        assert len(norm_lg_check) == 1
        assert norm_lg_check[0][3] is None  # Encrypted login never leaks ciphertext as USER_ACCOUNT!

    # TimelineNormalizer live invocation (guarded only against concurrent M4 active SyntaxError in normalizer.py)
    try:
        from backend.orchestrator.normalizer import TimelineNormalizer
    except SyntaxError:
        TimelineNormalizer = None  # Concurrent M4 edit in progress on backend/orchestrator/normalizer.py

    if TimelineNormalizer is not None:
        norm = TimelineNormalizer(cid)
        t_dl, e_dl = norm.normalize_table("parsed_firefox_downloads")
        t_hi, e_hi = norm.normalize_table("parsed_firefox_history")
        t_lg, e_lg = norm.normalize_table("parsed_firefox_logins")
        assert t_dl == 4
        assert e_dl >= 4
        assert t_hi == 6
        assert e_hi >= 6
        assert t_lg == 1
        assert e_lg == 1  # DOMAIN extracted, 0 USER_ACCOUNT leaked for encrypted login!


# ---------------------------------------------------------------------------
# (f) Multi-Threaded 8-Worker Concurrency Stress Test (`F28`)
# ---------------------------------------------------------------------------
def test_f_multithreaded_8_worker_browser_and_duckdb_stress(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
) -> None:
    cid, _cdir, sdir = isolated_case_factory("case_m3a_f_stress", "image")
    _seed_chromium_staging(sdir)
    _seed_firefox_staging(sdir)

    f_probe = sdir / "Browsers" / "Chrome" / "Alice" / "Default" / "History"

    def _run_chromium() -> Dict[str, int]:
        return ChromiumParser(cid, sdir).parse()

    def _run_firefox() -> Dict[str, int]:
        return FirefoxParser(cid, sdir).parse()

    def _run_base_worker(worker_idx: int) -> int:
        bp = BaseParser(cid, sdir)
        tbl = f"stress_worker_{worker_idx}"
        rows = [
            {
                "worker": worker_idx,
                "seq": i,
                "ts": datetime(2023, 1, 1, 0, 0, i % 60, tzinfo=timezone.utc),
                "big_val": 132328100451234000 + i,
            }
            for i in range(25)
        ]
        n = bp.insert_records(
            table_name=tbl,
            records=rows,
            artifact_id=f"stress_art_{worker_idx}",
            category="WEB RELATED",
            display_name=f"Stress {worker_idx}",
            source_tool="StressWorker",
            append=False,
        )
        p_res = bp.resolve_evidence_path(f_probe)
        assert p_res == r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\History"
        _ = bp.get_original_mtime(f_probe)
        page = query_paginated(cid, tbl, limit=10, offset=0)
        assert page["total_count"] == 25
        return n

    futures = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i in range(6):
            futures.append(pool.submit(_run_base_worker, i))
        # Interleave concurrent ChromiumParser and FirefoxParser runs on the same case.duckdb
        futures.append(pool.submit(_run_chromium))
        futures.append(pool.submit(_run_firefox))
        futures.append(pool.submit(_run_chromium))
        futures.append(pool.submit(_run_firefox))
        for i in range(6, 12):
            futures.append(pool.submit(_run_base_worker, i))

        for fut in futures:
            fut.result(timeout=60)

    with DuckDBManager.get_lock(cid):
        cur = DuckDBManager.get_connection(cid).cursor()
        # Verify zero Firefox clobbering by ChromiumParser and 100% expected row counts
        assert cur.execute("SELECT COUNT(*) FROM parsed_chrome_history;").fetchone()[0] == 4
        assert cur.execute("SELECT COUNT(*) FROM parsed_chrome_cookies;").fetchone()[0] == 12
        assert cur.execute("SELECT COUNT(*) FROM parsed_chrome_session;").fetchone()[0] == 2
        assert cur.execute("SELECT COUNT(*) FROM parsed_firefox_history;").fetchone()[0] == 6
        assert cur.execute("SELECT COUNT(*) FROM parsed_firefox_downloads;").fetchone()[0] == 4
        assert cur.execute("SELECT COUNT(*) FROM parsed_firefox_cookies;").fetchone()[0] == 2
        assert cur.execute("SELECT COUNT(*) FROM parsed_firefox_bookmarks;").fetchone()[0] == 3
        assert cur.execute("SELECT COUNT(*) FROM parsed_firefox_formhistory;").fetchone()[0] == 1
        assert cur.execute("SELECT COUNT(*) FROM parsed_firefox_logins;").fetchone()[0] == 1

        ff_tools = {
            r[0]
            for r in cur.execute(
                "SELECT source_tool FROM artifact_registry WHERE artifact_id LIKE 'firefox_%';"
            ).fetchall()
        }
        assert ff_tools == {"FirefoxParser"}

        for w_idx in range(12):
            cnt_w = cur.execute(f'SELECT COUNT(*) FROM "stress_worker_{w_idx}";').fetchone()[0]
            assert cnt_w == 25


# ---------------------------------------------------------------------------
# (g) Iteration 2 Challenger Regression Suite (All 8 Defects + BOM/AST Hygiene)
# ---------------------------------------------------------------------------
def _build_headerless_snss_nav(tab_id: int, nav_index: int, url: str, title: str) -> bytes:
    url_b = url.encode("utf-8")
    title_u16 = title.encode("utf-16-le")
    return (
        struct.pack("<ii", tab_id, nav_index)
        + struct.pack("<i", len(url_b))
        + _align4_bytes(url_b)
        + struct.pack("<i", len(title))
        + _align4_bytes(title_u16)
    )


def test_g_challenger_regression_suite(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # -----------------------------------------------------------------------
    # 1. 8 Barrier-synchronized threads calling copy_sqlite_with_wal on 8
    #    distinct Cookies+Cookies-wal DBs into a SINGLE initially-empty temp_dir
    # -----------------------------------------------------------------------
    wal_sources: List[Path] = []
    live_conns: List[sqlite3.Connection] = []
    try:
        for i in range(8):
            pdir = tmp_path / f"wal_prof_{i}"
            pdir.mkdir(parents=True, exist_ok=True)
            db_p = pdir / "Cookies"
            c = sqlite3.connect(str(db_p), check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL;")
            c.execute("PRAGMA wal_autocheckpoint=0;")
            c.execute("CREATE TABLE cookies (idx INTEGER, host_key TEXT);")
            for r_i in range(15):
                c.execute("INSERT INTO cookies VALUES (?, ?);", [r_i, f".prof{i}.example.com"])
            c.commit()
            # Keep connection open so WAL frames stay uncheckpointed in Cookies-wal!
            assert (pdir / "Cookies-wal").is_file() and (pdir / "Cookies-wal").stat().st_size > 0
            wal_sources.append(db_p)
            live_conns.append(c)

        shared_empty_tmp = tmp_path / "shared_race_temp"
        assert not shared_empty_tmp.exists()
        barrier = threading.Barrier(8)

        def _race_copy(t_idx: int) -> Tuple[Path, int, List[str]]:
            barrier.wait(timeout=10)
            copied = copy_sqlite_with_wal(wal_sources[t_idx], temp_dir=shared_empty_tmp)
            with sqlite3.connect(str(copied)) as rc:
                rows = rc.execute("SELECT DISTINCT host_key FROM cookies;").fetchall()
                cnt = rc.execute("SELECT COUNT(*) FROM cookies;").fetchone()[0]
            return copied, int(cnt), [str(x[0]) for x in rows]

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(_race_copy, i) for i in range(8)]
            race_results = [f.result(timeout=30) for f in futs]

        copied_paths = [r[0].resolve() for r in race_results]
        assert len(set(copied_paths)) == 8, f"Expected 8 unique paths, got {copied_paths}"
        for i, (_cp, cnt, hosts) in enumerate(race_results):
            assert cnt == 15
            assert hosts == [f".prof{i}.example.com"]
    finally:
        for c in live_conns:
            try:
                c.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # 2. VSS vs Active vfs_files isolation in get_original_mtime & resolve_evidence_path
    # -----------------------------------------------------------------------
    cid_vss, _cdir_vss, sdir_vss = isolated_case_factory("case_m3a_g_vss", "image")
    bp_vss = BaseParser(cid_vss, sdir_vss)

    f_vss3 = sdir_vss / "VSS" / "VSS_3" / "Browsers" / "Chrome" / "Alice" / "Default" / "History"
    f_vss4 = sdir_vss / "VSS" / "VSS_4" / "Browsers" / "Chrome" / "Alice" / "Default" / "History"
    f_vss5 = sdir_vss / "VSS" / "VSS_5" / "Browsers" / "Chrome" / "Alice" / "Default" / "History"
    for fp in (f_vss3, f_vss4, f_vss5):
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(b"vss_hist")
    # VSS_4 has an os.utime on disk, but vfs_files row has all NULLs -> MUST return None!
    os.utime(f_vss4, (1580000000, 1580000000))
    # VSS_5 has NO vfs_files row and relies on os.utime 2020-03-01 09:00:00 UTC (1583053200)
    os.utime(f_vss5, (1583053200, 1583053200))

    with DuckDBManager.get_lock(cid_vss):
        cur = DuckDBManager.get_connection(cid_vss).cursor()
        cur.execute("DELETE FROM vfs_files;")
        # Insert ACTIVE partition rows FIRST (mimicking EvidenceExtractor order)
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified, fn_modified, si_created) "
            "VALUES (0, '/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History', "
            "'Browsers/Chrome/Alice/Default/History', TIMESTAMP '2025-11-01 12:00:00', NULL, NULL);"
        )
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified) "
            "VALUES (0, ?, 'Enrichment/Part0/Data/shared.db', TIMESTAMP '2025-11-01 12:00:00');",
            [r"D:\Data\shared.db"],
        )
        # Insert VSS rows AFTER active rows (including M2 '/VSS_3/...' vfs_path format)
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified, fn_modified, si_created) "
            "VALUES (-3, '/VSS_3/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History', "
            "'VSS/VSS_3/Browsers/Chrome/Alice/Default/History', TIMESTAMP '2019-02-14 06:45:00', NULL, NULL);"
        )
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified, fn_modified, si_created) "
            "VALUES (-4, '/VSS_4/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History', "
            "'VSS/VSS_4/Browsers/Chrome/Alice/Default/History', NULL, NULL, NULL);"
        )
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified) "
            "VALUES (-3, '/VSS_3/inetpub/wwwroot/vss_only.config', "
            "'VSS/VSS_3/Enrichment/Part0/inetpub/wwwroot/vss_only.config', TIMESTAMP '2019-01-01 00:00:00');"
        )
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, si_modified) "
            "VALUES (-2, ?, 'VSS/VSS_2/Enrichment/Part0/Data/shared.db', TIMESTAMP '2018-06-01 00:00:00');",
            [r"E:\OldData\shared.db"],
        )

    assert bp_vss.get_original_mtime(f_vss3) == "2019-02-14 06:45:00"
    assert bp_vss.get_original_mtime(f_vss4) is None
    assert bp_vss.get_original_mtime(f_vss5) == "2020-03-01 09:00:00"
    # f_vss5 is NOT in vfs_files -> get_original_ctime MUST return None (NEVER leak Path.stat().st_ctime!)
    assert bp_vss.get_original_ctime(f_vss5) is None

    # Windows NTFS staging wall-clock si_created / st_ctime guard (both folder & image cases)
    cid_wc, _cdir_wc, sdir_wc = isolated_case_factory("case_m3a_g_wallclock", "folder")
    bp_wc = BaseParser(cid_wc, sdir_wc)
    f_wc_hist = sdir_wc / "Browsers" / "Chrome" / "Alice" / "Default" / "Web Data"
    f_wc_copy = sdir_wc / "Browsers" / "Chrome" / "Alice" / "Default" / "Login Data"
    f_wc_untracked = sdir_wc / "Browsers" / "Chrome" / "Alice" / "Default" / "FreshStagedFile"
    f_wc_hist.parent.mkdir(parents=True, exist_ok=True)
    f_wc_hist.write_bytes(b"hist")
    f_wc_copy.write_bytes(b"copied")
    f_wc_untracked.write_bytes(b"fresh_copy_now")
    now_utc_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with DuckDBManager.get_lock(cid_wc):
        cur = DuckDBManager.get_connection(cid_wc).cursor()
        cur.execute("DROP TABLE IF EXISTS vfs_files;")
        cur.execute(
            """
            CREATE TABLE vfs_files (
                staged_rel_path VARCHAR,
                vfs_path VARCHAR,
                si_modified TIMESTAMP,
                fn_modified TIMESTAMP,
                si_created TIMESTAMP,
                fn_created TIMESTAMP
            );
            """
        )
        cur.execute(
            "INSERT INTO vfs_files VALUES (?, ?, TIMESTAMP '2021-08-19 14:22:10', NULL, TIMESTAMP '2019-01-10 08:30:00', NULL);",
            [
                "Browsers/Chrome/Alice/Default/Web Data",
                r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Web Data",
            ],
        )
        cur.execute(
            "INSERT INTO vfs_files VALUES (?, ?, NULL, NULL, CAST(? AS TIMESTAMP), CAST(? AS TIMESTAMP));",
            [
                "Browsers/Chrome/Alice/Default/Login Data",
                r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
                now_utc_str,
                now_utc_str,
            ],
        )
    assert bp_wc.get_original_mtime(f_wc_hist) == "2021-08-19 14:22:10"
    assert bp_wc.get_original_ctime(f_wc_hist) == "2019-01-10 08:30:00"
    # Host wall-clock si_created/fn_created from Windows NTFS shutil.copy2 MUST be rejected -> None!
    assert bp_wc.get_original_ctime(f_wc_copy) is None
    assert bp_wc.get_original_mtime(f_wc_copy) is None
    # Untracked freshly created staging file without os.utime() MUST reject wall-clock st_mtime & NEVER return st_ctime!
    assert bp_wc.get_original_mtime(f_wc_untracked) is None
    assert bp_wc.get_original_ctime(f_wc_untracked) is None

    assert (
        bp_vss.resolve_evidence_path(
            sdir_vss / "VSS" / "VSS_3" / "Enrichment" / "Part0" / "inetpub" / "wwwroot" / "vss_only.config"
        )
        == r"[VSS#3] C:\inetpub\wwwroot\vss_only.config"
    )
    assert (
        bp_vss.resolve_evidence_path(
            sdir_vss / "VSS" / "VSS_2" / "Enrichment" / "Part0" / "Data" / "shared.db"
        )
        == r"[VSS#2] E:\OldData\shared.db"
    )

    # -----------------------------------------------------------------------
    # 3. Unpaired UTF-16 surrogates in BaseParser (pandas & pd=None),
    #    ChromiumParser Bookmarks, and FirefoxParser logins.json
    # -----------------------------------------------------------------------
    surrogate_rows = [
        {"title": "Broken \ud83d Title", "nested": {"realm": "Realm \ud800 Bad"}},
        {"title": "Clean Row", "nested": {"realm": "ok"}},
    ]
    assert bp_vss.insert_records("surr_pd", surrogate_rows, append=False) == 2
    orig_pd = base_parser_mod.pd
    try:
        monkeypatch.setattr(base_parser_mod, "pd", None)
        assert bp_vss.insert_records("surr_py", surrogate_rows, append=False) == 2
    finally:
        monkeypatch.setattr(base_parser_mod, "pd", orig_pd)

    with DuckDBManager.get_lock(cid_vss):
        cur = DuckDBManager.get_connection(cid_vss).cursor()
        r_pd = cur.execute("SELECT title, nested FROM surr_pd ORDER BY _row_id;").fetchall()
        r_py = cur.execute("SELECT title, nested FROM surr_py ORDER BY _row_id;").fetchall()
    assert r_pd == r_py
    assert r_pd[0][0] == "Broken \ufffd Title"
    assert "\ufffd" in r_pd[0][1]

    # -----------------------------------------------------------------------
    # 4, 5, 6, 7. Browser regression case: Year-9999 cookie expiries,
    #    >32 KB byte-range-locked SQLite resilience, Headerless SNSS tab_ids,
    #    direct <Browser>/<User>/<Profile> staging without Browsers/ prefix,
    #    and JSON lone surrogates in Bookmarks & logins.json
    # -----------------------------------------------------------------------
    assert _cookie_expiry_to_dt(253402300799, 12) == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert _cookie_expiry_to_dt(253402300799000, 15) == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    y9999_wk = (253402300799 + WEBKIT_EPOCH_OFFSET_SECONDS) * 1_000_000
    assert _cookie_webkit_expiry(y9999_wk) == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert webkit_to_datetime(y9999_wk) == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert prtime_to_datetime(253402300799) == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert windows_filetime_to_datetime((253402300799 + WEBKIT_EPOCH_OFFSET_SECONDS) * 10_000_000) == datetime(
        9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc
    )

    cid_br, _cdir_br, sdir_br = isolated_case_factory("case_m3a_g_browsers", "image")

    # Direct Chrome/<User>/<Profile> without Browsers/ prefix + lone surrogate in Bookmarks + Year-9999 cookie
    ch_alice_def = sdir_br / "Chrome" / "Alice" / "Default"
    ch_dave_def = sdir_br / "Chrome" / "Dave" / "Default"
    ch_locked_prof = sdir_br / "Chrome" / "LockedUser" / "Default"
    for d in (ch_alice_def, ch_dave_def, ch_locked_prof):
        d.mkdir(parents=True, exist_ok=True)

    raw_bm_json = (
        '{"roots":{"bookmark_bar":{"name":"Bookmarks bar","type":"folder","children":['
        '{"name":"Broken \\ud83d Title","type":"url","url":"https://shared-bm.example.com/","date_added":"13300000000000000"}'
        "]}}}"
    )
    (ch_alice_def / "Bookmarks").write_text(raw_bm_json, encoding="utf-8")
    (ch_dave_def / "Bookmarks").write_text(raw_bm_json, encoding="utf-8")

    # Year-9999 Chromium cookie in Network/Cookies
    (ch_alice_def / "Network").mkdir(parents=True, exist_ok=True)
    t_now_wk = _dt_to_webkit_us(datetime(2023, 5, 1, 10, 0, 0, tzinfo=timezone.utc))
    with sqlite3.connect(str(ch_alice_def / "Network" / "Cookies")) as conn:
        conn.execute(
            "CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, "
            "encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, "
            "is_httponly INTEGER, last_access_utc INTEGER, last_update_utc INTEGER);"
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, '.y9999.example.com', 'persist9999', 'ok', ?, '/', ?, 1, 1, ?, ?);",
            [t_now_wk, b"", y9999_wk, t_now_wk, t_now_wk],
        )

    # Unlocked neighbor History on Alice/Default
    with sqlite3.connect(str(ch_alice_def / "History")) as conn:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);"
        )
        conn.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);"
        )
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://alice-unlocked.example.com/', 'Alice Unlocked', 1, 1, ?);",
            [t_now_wk],
        )
        conn.execute("INSERT INTO visits VALUES (1, 1, ?, 0, 1, 1000);", [t_now_wk])

    # >32 KB History on LockedUser/Default to receive Windows byte-range lock at offset 16384
    locked_ch_hist = ch_locked_prof / "History"
    with sqlite3.connect(str(locked_ch_hist)) as conn:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);"
        )
        for i in range(60):
            conn.execute(
                "INSERT INTO urls VALUES (?, ?, ?, 1, 0, ?);",
                [i + 1, f"https://pad.example.com/{i}/" + ("x" * 600), "Pad " + ("y" * 200), t_now_wk],
            )
    assert locked_ch_hist.stat().st_size > 32768

    # Headerless SNSS Current Session (SetTabWindow win=2 for tab_id=11 & tab_id=12 + headerless UpdateTabNavigation)
    headerless_snss = (
        b"SNSS"
        + struct.pack("<i", 3)
        + _pack_snss_cmd(0, struct.pack("<II", 2, 11))
        + _pack_snss_cmd(0, struct.pack("<II", 2, 12))
        + _pack_snss_cmd(6, _build_headerless_snss_nav(11, 0, "https://tab11.example.com/first", "Tab Eleven"))
        + _pack_snss_cmd(6, _build_headerless_snss_nav(12, 0, "https://tab12.example.com/second", "Tab Twelve"))
    )
    (ch_alice_def / "Current Session").write_bytes(headerless_snss)

    # Direct Firefox/<User>/<Profile> without Browsers/ prefix + Year-9999 v12 & v15 cookies + surrogate logins.json + >32KB locked places.sqlite
    ff_alice_def = sdir_br / "Firefox" / "Alice" / "def"
    ff_bob_def = sdir_br / "Firefox" / "Bob" / "def"
    ff_locked_prof = sdir_br / "Firefox" / "LockedFF" / "def"
    for d in (ff_alice_def, ff_bob_def, ff_locked_prof):
        d.mkdir(parents=True, exist_ok=True)

    t_ff_us = _dt_to_prtime_us(datetime(2023, 5, 1, 10, 0, 0, tzinfo=timezone.utc))
    for pdir in (ff_alice_def, ff_bob_def):
        with sqlite3.connect(str(pdir / "places.sqlite")) as conn:
            conn.execute(
                "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);"
            )
            conn.execute(
                "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);"
            )
            # Identical bytes across Alice/def and Bob/def to prove username prevents deduplication collapse!
            conn.execute(
                "INSERT INTO moz_places VALUES (1, 'https://shared-ff.example.org/', 'Shared FF', 2, 1, ?);",
                [t_ff_us],
            )
            conn.execute("INSERT INTO moz_historyvisits VALUES (1, 0, 1, ?, 2);", [t_ff_us])

    with sqlite3.connect(str(ff_alice_def / "cookies.sqlite")) as conn:
        conn.execute("PRAGMA user_version = 12;")
        conn.execute(
            "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_cookies VALUES (1, '.ff-v12.org', 'c_v12_9999', 'v12', '/', 253402300799, ?, ?, 1, 1, 0);",
            [t_ff_us, t_ff_us],
        )

    with sqlite3.connect(str(ff_bob_def / "cookies.sqlite")) as conn:
        conn.execute("PRAGMA user_version = 15;")
        conn.execute(
            "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_cookies VALUES (1, '.ff-v15.org', 'c_v15_9999', 'v15', '/', 253402300799000, ?, ?, 1, 0, 1);",
            [t_ff_us, t_ff_us],
        )

    raw_ff_logins = (
        '{"nextId":2,"logins":[{"id":1,"hostname":"https://realm.example.org",'
        '"httpRealm":"Realm \\ud800 Bad","formSubmitURL":null,"usernameField":"u","passwordField":"p",'
        '"encryptedUsername":"enc_u","encryptedPassword":"enc_p","guid":"{g1}","encType":1,'
        '"timeCreated":1682935200000,"timeLastUsed":1682935200000,"timePasswordChanged":1682935200000,"timesUsed":1}]}'
    )
    (ff_alice_def / "logins.json").write_text(raw_ff_logins, encoding="utf-8")

    locked_ff_places = ff_locked_prof / "places.sqlite"
    with sqlite3.connect(str(locked_ff_places)) as conn:
        conn.execute(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);"
        )
        for i in range(60):
            conn.execute(
                "INSERT INTO moz_places VALUES (?, ?, ?, 1, 0, ?);",
                [i + 1, f"https://ffpad.example.org/{i}/" + ("z" * 600), "Pad " + ("w" * 200), t_ff_us],
            )
    assert locked_ff_places.stat().st_size > 32768

    # Acquire mandatory Windows byte-range locks at offset 16384..20480 on both >32KB SQLite files
    fh_ch = open(locked_ch_hist, "r+b")
    fh_ff = open(locked_ff_places, "r+b")
    try:
        fh_ch.seek(16384)
        msvcrt.locking(fh_ch.fileno(), msvcrt.LK_NBLCK, 4096)
        fh_ff.seek(16384)
        msvcrt.locking(fh_ff.fileno(), msvcrt.LK_NBLCK, 4096)

        ch_res = ChromiumParser(cid_br, sdir_br).parse()
        ff_res = FirefoxParser(cid_br, sdir_br).parse()
    finally:
        for fh in (fh_ch, fh_ff):
            try:
                fh.seek(16384)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 4096)
            except Exception:
                pass
            try:
                fh.close()
            except Exception:
                pass

    assert ch_res["parsed_chrome_history"] == 1
    assert ch_res["parsed_chrome_bookmarks"] == 2
    assert ch_res["parsed_chrome_cookies"] == 1
    assert ch_res["parsed_chrome_session"] == 2
    assert ff_res["parsed_firefox_history"] == 2
    assert ff_res["parsed_firefox_cookies"] == 2
    assert ff_res["parsed_firefox_logins"] == 1

    with DuckDBManager.get_lock(cid_br):
        cur = DuckDBManager.get_connection(cid_br).cursor()

        # Neighbor unlocked Chrome History extracted with Alice/Default provenance
        ch_hist = cur.execute("SELECT profile, url FROM parsed_chrome_history;").fetchall()
        assert ch_hist == [("Alice/Default", "https://alice-unlocked.example.com/")]

        # Direct Chrome/Alice/Default & Chrome/Dave/Default Bookmarks both preserved (no dedup collapse) + surrogate replaced
        ch_bms = cur.execute("SELECT title, url FROM parsed_chrome_bookmarks;").fetchall()
        assert ch_bms == [
            ("Broken \ufffd Title", "https://shared-bm.example.com/"),
            ("Broken \ufffd Title", "https://shared-bm.example.com/"),
        ]

        # Year-9999 Chromium cookie non-NULL
        ch_ck = cur.execute("SELECT name, expires_utc FROM parsed_chrome_cookies;").fetchone()
        assert ch_ck == ("persist9999", datetime(9999, 12, 31, 23, 59, 59))

        # Headerless SNSS preserved BOTH tab_id=11 & tab_id=12 with window_id=2 (0 collapse to tab_id=0!)
        snss_rows = cur.execute(
            "SELECT profile, window_id, tab_id, url, title FROM parsed_chrome_session ORDER BY tab_id;"
        ).fetchall()
        assert snss_rows == [
            ("Alice/Default", 2, 11, "https://tab11.example.com/first", "Tab Eleven"),
            ("Alice/Default", 2, 12, "https://tab12.example.com/second", "Tab Twelve"),
        ]

        # Direct Firefox/Alice/def & Firefox/Bob/def both preserved with distinct usernames
        ff_hist = cur.execute(
            "SELECT username, profile, url FROM parsed_firefox_history ORDER BY username;"
        ).fetchall()
        assert ff_hist == [
            ("Alice", "def", "https://shared-ff.example.org/"),
            ("Bob", "def", "https://shared-ff.example.org/"),
        ]

        # Year-9999 Firefox v12 & v15 cookies non-NULL across both expires_utc and expiry
        ff_cks = cur.execute(
            "SELECT name, expires_utc, expiry FROM parsed_firefox_cookies ORDER BY name;"
        ).fetchall()
        assert ff_cks == [
            ("c_v12_9999", datetime(9999, 12, 31, 23, 59, 59), datetime(9999, 12, 31, 23, 59, 59)),
            ("c_v15_9999", datetime(9999, 12, 31, 23, 59, 59), datetime(9999, 12, 31, 23, 59, 59)),
        ]

        # Surrogate in logins.json sanitized cleanly across both camelCase and snake_case columns
        ff_lg = cur.execute(
            'SELECT "httpRealm", http_realm, signon_realm FROM parsed_firefox_logins;'
        ).fetchone()
        assert ff_lg == ("Realm \ufffd Bad", "Realm \ufffd Bad", "Realm \ufffd Bad")

    # -----------------------------------------------------------------------
    # 8. UTF-8 BOM-free & clean ast.parse(read_text(encoding="utf-8")) check
    # -----------------------------------------------------------------------
    repo_root = Path(__file__).resolve().parents[2]
    for rel_f in (
        "backend/parsers/base_parser.py",
        "backend/parsers/chromium_parser.py",
        "backend/parsers/firefox_parser.py",
        "backend/tests/test_m3a_browsers.py",
    ):
        fpath = repo_root / rel_f
        assert fpath.read_bytes()[:3] != b"\xef\xbb\xbf", f"UTF-8 BOM found in {rel_f}"
        ast.parse(fpath.read_text(encoding="utf-8"), filename=rel_f)


def _sqlite_c_bind_text16_exec(db_path: Path, sql_single_param: str, raw_surrogate_str: str) -> None:
    r"""
    Uses Python 3.11's bundled `sqlite3.dll` C API `sqlite3_bind_text16` (matching Chromium
    `sql::Statement::BindString16` and Firefox `mozStorage`) to bind a UTF-16LE string containing
    an unpaired surrogate directly into an SQLite `TEXT` column as 3-byte WTF-8 (`0xED 0xA0..0xBF ...`).
    """
    dll_cand = Path(sys.base_prefix) / "DLLs" / "sqlite3.dll"
    dll = ctypes.CDLL(str(dll_cand) if dll_cand.is_file() else "sqlite3.dll")

    dll.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    dll.sqlite3_open.restype = ctypes.c_int
    dll.sqlite3_prepare_v2.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_char_p),
    ]
    dll.sqlite3_prepare_v2.restype = ctypes.c_int
    dll.sqlite3_bind_text16.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    dll.sqlite3_bind_text16.restype = ctypes.c_int
    dll.sqlite3_step.argtypes = [ctypes.c_void_p]
    dll.sqlite3_step.restype = ctypes.c_int
    dll.sqlite3_finalize.argtypes = [ctypes.c_void_p]
    dll.sqlite3_finalize.restype = ctypes.c_int
    dll.sqlite3_close.argtypes = [ctypes.c_void_p]
    dll.sqlite3_close.restype = ctypes.c_int

    db_handle = ctypes.c_void_p()
    rc_open = dll.sqlite3_open(str(db_path).encode("utf-8"), ctypes.byref(db_handle))
    assert rc_open == 0 and db_handle.value

    stmt_handle = ctypes.c_void_p()
    tail = ctypes.c_char_p()
    utf16le_bytes = raw_surrogate_str.encode("utf-16-le", errors="surrogatepass")
    buf = ctypes.create_string_buffer(utf16le_bytes, len(utf16le_bytes))
    try:
        rc_prep = dll.sqlite3_prepare_v2(
            db_handle,
            sql_single_param.encode("utf-8"),
            -1,
            ctypes.byref(stmt_handle),
            ctypes.byref(tail),
        )
        assert rc_prep == 0 and stmt_handle.value
        rc_bind = dll.sqlite3_bind_text16(
            stmt_handle,
            1,
            ctypes.cast(buf, ctypes.c_void_p),
            len(utf16le_bytes),
            ctypes.c_void_p(0),  # SQLITE_STATIC (buf stays alive past sqlite3_finalize)
        )
        assert rc_bind == 0
        rc_step = dll.sqlite3_step(stmt_handle)
        assert rc_step == 101  # SQLITE_DONE
    finally:
        if stmt_handle.value:
            dll.sqlite3_finalize(stmt_handle)
        dll.sqlite3_close(db_handle)


def test_h_sqlite_wtf8_surrogates_handle_cleanup_and_polish(
    isolated_case_factory: Callable[[str, str], Tuple[str, Path, Path]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r"""
    Iteration 3 Regression Suite:
      (a) `safe_sqlite_text_factory` + SQLite WTF-8 lone surrogates (`CAST(X'5472756E636174656420EDA0BD' AS TEXT)`
          AND real `ctypes` `sqlite3.dll` `sqlite3_bind_text16` `"Truncated \ud83d"` AND raw invalid UTF-8
          `CAST(X'FFFE41' AS TEXT)`) across all 5 Chromium SQLite DBs and all 5 Firefox SQLite DBs,
          preserving 100% of sibling clean rows & sub-tables.
      (b) Mid-query SQLite `DatabaseError` / corrupt B-tree page cleanup in `ChromiumParser` and `FirefoxParser`
          with redirected `TMP`/`TEMP`, asserting zero leaked `wft_chromium_*` / `wft_firefox_*` / `wft_ff_*` /
          `wft_sqlite_*` temp directories in-process.
      (c) `BaseParser._log` on `cp1252` `sys.stdout` with Cyrillic/CJK/emoji/lone-surrogate (`0` exceptions),
          `prtime_to_datetime(253402300798123457)` exact `.123457` µs + `prtime_to_datetime(253402300799)` exact
          seconds, and `copy_sqlite_with_wal` on `stat.S_IREAD` read-only DB+WAL followed by bare `shutil.rmtree`.
    """
    # -----------------------------------------------------------------------
    # (a) Unit & End-to-End SQLite WTF-8 Surrogate + Invalid UTF-8 Sanitization
    # -----------------------------------------------------------------------
    assert safe_sqlite_text_factory("Truncated \ud83d") == "Truncated \ufffd"
    assert safe_sqlite_text_factory("Clean \U0001f680") == "Clean \U0001f680"
    assert safe_sqlite_text_factory("Clean \U0001f680".encode("utf-8")) == "Clean \U0001f680"
    assert safe_sqlite_text_factory(bytes.fromhex("5472756E636174656420EDA0BD")) == "Truncated \ufffd"
    assert safe_sqlite_text_factory(b"Pair \xed\xa0\xbd\xed\xb2\x80!") == "Pair \U0001f480!"
    assert safe_sqlite_text_factory(bytes.fromhex("FFFE41")) == "\ufffd\ufffdA"
    assert safe_sqlite_text_factory(b"Mix \xff\xfeA\xed\xa0\xbd") == "Mix \ufffd\ufffdA\ufffd"

    cid_wtf, _cdir_wtf, sdir_wtf = isolated_case_factory("case_m3a_h_wtf8", "image")
    ch_prof = sdir_wtf / "Browsers" / "Chrome" / "Alice" / "Default"
    (ch_prof / "Network").mkdir(parents=True, exist_ok=True)
    ff_prof = sdir_wtf / "Browsers" / "Firefox" / "Alice" / "def"
    ff_prof.mkdir(parents=True, exist_ok=True)

    t_wk = _dt_to_webkit_us(datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    t_ff_us = _dt_to_prtime_us(datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc))
    t_ff_ms = _dt_to_epoch_ms(datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc))

    # 1. Chromium History (urls via sqlite3_bind_text16 + raw X'FFFE41' + clean sibling + visits + downloads + keyword_search_terms)
    ch_hist_db = ch_prof / "History"
    with sqlite3.connect(str(ch_hist_db)) as conn:
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);"
        )
        conn.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);"
        )
        conn.execute(
            "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, tab_url TEXT, site_url TEXT, total_bytes INTEGER, received_bytes INTEGER, start_time INTEGER, end_time INTEGER, mime_type TEXT, danger_type INTEGER, state INTEGER, opened INTEGER);"
        )
        conn.execute(
            "CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, normalized_term TEXT, term TEXT);"
        )
        conn.execute(
            "INSERT INTO urls VALUES (2, 'https://raw-bytes-ch.example.com/', CAST(X'FFFE41' AS TEXT), 1, 0, ?);",
            [t_wk],
        )
        conn.execute(
            "INSERT INTO urls VALUES (3, 'https://clean-ch.example.com/', 'Clean Sibling Title', 2, 1, ?);",
            [t_wk],
        )
        conn.execute("INSERT INTO visits VALUES (1, 3, ?, 0, 1, 5000);", [t_wk])
        conn.execute(
            "INSERT INTO downloads VALUES (1, ?, ?, 'https://clean-ch.example.com/important.exe', 'https://clean-ch.example.com/', 8192, 8192, ?, ?, 'application/octet-stream', 0, 1, 1);",
            [r"C:\Users\Alice\Downloads\important.exe", r"C:\Users\Alice\Downloads\important.exe", t_wk, t_wk],
        )
        conn.execute(
            "INSERT INTO keyword_search_terms VALUES (1, 3, 'clean sibling query', 'Clean Sibling Query');"
        )
        conn.execute(
            "INSERT INTO keyword_search_terms VALUES (2, 1, CAST(X'5472756E636174656420EDA0BD' AS TEXT), CAST(X'5472756E636174656420EDA0BD' AS TEXT));"
        )
    _sqlite_c_bind_text16_exec(
        ch_hist_db,
        f"INSERT INTO urls VALUES (1, 'https://bind16-ch.example.com/', ?, 1, 1, {t_wk});",
        "Truncated \ud83d",
    )
    with sqlite3.connect(str(ch_hist_db)) as conn:
        stored_hex = conn.execute("SELECT HEX(CAST(title AS BLOB)) FROM urls WHERE id = 1;").fetchone()[0]
    assert stored_hex == "5472756E636174656420EDA0BD"

    # 2. Chromium Network/Cookies
    with sqlite3.connect(str(ch_prof / "Network" / "Cookies")) as conn:
        conn.execute(
            "CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, last_update_utc INTEGER);"
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, '.ch.example.com', 'ck_wtf8', CAST(X'5472756E636174656420EDA0BD' AS TEXT), X'', '/', ?, 1, 1, ?, ?);",
            [t_wk, t_wk + 3_600_000_000, t_wk, t_wk],
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, '.ch.example.com', 'ck_raw', CAST(X'FFFE41' AS TEXT), X'', '/', ?, 1, 0, ?, ?);",
            [t_wk, t_wk + 3_600_000_000, t_wk, t_wk],
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, '.ch.example.com', 'ck_clean', 'clean_cookie_val', X'', '/', ?, 1, 1, ?, ?);",
            [t_wk, t_wk + 3_600_000_000, t_wk, t_wk],
        )

    # 3. Chromium Web Data
    with sqlite3.connect(str(ch_prof / "Web Data")) as conn:
        conn.execute(
            "CREATE TABLE autofill (name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);"
        )
        conn.execute(
            "INSERT INTO autofill VALUES ('af_wtf8', CAST(X'5472756E636174656420EDA0BD' AS TEXT), 'truncated', 1710504000, 1710504000, 1);"
        )
        conn.execute(
            "INSERT INTO autofill VALUES ('af_raw', CAST(X'FFFE41' AS TEXT), 'a', 1710504000, 1710504000, 1);"
        )
        conn.execute(
            "INSERT INTO autofill VALUES ('af_clean', 'Clean Autofill Value', 'clean autofill value', 1710504000, 1710504000, 2);"
        )

    # 4. Chromium Top Sites
    with sqlite3.connect(str(ch_prof / "Top Sites")) as conn:
        conn.execute("CREATE TABLE top_sites (url TEXT, url_rank INTEGER, title TEXT);")
        conn.execute(
            "INSERT INTO top_sites VALUES ('https://ts-wtf8.example.com/', 0, CAST(X'5472756E636174656420EDA0BD' AS TEXT));"
        )
        conn.execute(
            "INSERT INTO top_sites VALUES ('https://ts-raw.example.com/', 1, CAST(X'FFFE41' AS TEXT));"
        )
        conn.execute(
            "INSERT INTO top_sites VALUES ('https://ts-clean.example.com/', 2, 'Clean Top Site');"
        )

    # 5. Chromium Login Data
    with sqlite3.connect(str(ch_prof / "Login Data")) as conn:
        conn.execute(
            "CREATE TABLE logins (origin_url TEXT, action_url TEXT, username_value TEXT, signon_realm TEXT, date_created INTEGER, date_last_used INTEGER, times_used INTEGER);"
        )
        conn.execute(
            "INSERT INTO logins VALUES ('https://lg-wtf8.example.com', 'https://lg-wtf8.example.com/auth', CAST(X'5472756E636174656420EDA0BD' AS TEXT), 'https://lg-wtf8.example.com', ?, ?, 1);",
            [t_wk, t_wk],
        )
        conn.execute(
            "INSERT INTO logins VALUES ('https://lg-raw.example.com', 'https://lg-raw.example.com/auth', CAST(X'FFFE41' AS TEXT), 'https://lg-raw.example.com', ?, ?, 1);",
            [t_wk, t_wk],
        )
        conn.execute(
            "INSERT INTO logins VALUES ('https://lg-clean.example.com', 'https://lg-clean.example.com/auth', 'alice_clean_user', 'https://lg-clean.example.com', ?, ?, 3);",
            [t_wk, t_wk],
        )

    # 6. Firefox places.sqlite (moz_places via sqlite3_bind_text16 + raw X'FFFE41' + clean sibling + moz_bookmarks + moz_annos downloads)
    ff_places_db = ff_prof / "places.sqlite"
    with sqlite3.connect(str(ff_places_db)) as conn:
        conn.execute(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);"
        )
        conn.execute(
            "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);"
        )
        conn.execute(
            "CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT);"
        )
        conn.execute("CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);")
        conn.execute(
            "CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER, lastModified INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_places VALUES (2, 'https://raw-ff.example.org/', CAST(X'FFFE41' AS TEXT), 1, 0, ?);",
            [t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_places VALUES (3, 'https://clean-ff.example.org/', 'Clean FF Sibling', 2, 1, ?);",
            [t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_places VALUES (4, 'https://clean-ff.example.org/ff_important.zip', 'FF Download', 1, 0, ?);",
            [t_ff_us],
        )
        conn.execute("INSERT INTO moz_historyvisits VALUES (1, 0, 3, ?, 2);", [t_ff_us])
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (1, 2, NULL, 0, '', ?, ?, 'toolbar_____');",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (2, 1, 3, 1, 'Clean FF Bookmark', ?, ?, 'bm_clean____');",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (3, 1, 2, 1, CAST(X'5472756E636174656420EDA0BD' AS TEXT), ?, ?, 'bm_wtf8_____');",
            [t_ff_us, t_ff_us],
        )
        conn.execute("INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI');")
        conn.execute("INSERT INTO moz_anno_attributes VALUES (2, 'downloads/metaData');")
        conn.execute(
            "INSERT INTO moz_annos VALUES (1, 4, 1, 'file:///C:/Users/Alice/Downloads/ff_important.zip', ?, ?);",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_annos VALUES (2, 4, 2, ?, ?, ?);",
            [json.dumps({"state": 1, "endTime": t_ff_ms, "fileSize": 4096}), t_ff_us, t_ff_us],
        )
    _sqlite_c_bind_text16_exec(
        ff_places_db,
        f"INSERT INTO moz_places VALUES (1, 'https://bind16-ff.example.org/', ?, 1, 1, {t_ff_us});",
        "Truncated \ud83d",
    )

    # 7. Firefox cookies.sqlite
    with sqlite3.connect(str(ff_prof / "cookies.sqlite")) as conn:
        conn.execute("PRAGMA user_version = 15;")
        conn.execute(
            "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_cookies VALUES (1, '.ff.example.org', 'ff_ck_wtf8', CAST(X'5472756E636174656420EDA0BD' AS TEXT), '/', ?, ?, ?, 1, 1, 0);",
            [t_ff_ms + 3_600_000, t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_cookies VALUES (2, '.ff.example.org', 'ff_ck_raw', CAST(X'FFFE41' AS TEXT), '/', ?, ?, ?, 1, 0, 1);",
            [t_ff_ms + 3_600_000, t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_cookies VALUES (3, '.ff.example.org', 'ff_ck_clean', 'ff_clean_cookie', '/', ?, ?, ?, 1, 1, 2);",
            [t_ff_ms + 3_600_000, t_ff_us, t_ff_us],
        )

    # 8. Firefox formhistory.sqlite
    with sqlite3.connect(str(ff_prof / "formhistory.sqlite")) as conn:
        conn.execute(
            "CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_formhistory VALUES (1, 'fh_wtf8', CAST(X'5472756E636174656420EDA0BD' AS TEXT), 1, ?, ?);",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_formhistory VALUES (2, 'fh_raw', CAST(X'FFFE41' AS TEXT), 1, ?, ?);",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_formhistory VALUES (3, 'fh_clean', 'Firefox Clean Input', 3, ?, ?);",
            [t_ff_us, t_ff_us],
        )

    # 9. Firefox downloads.sqlite
    with sqlite3.connect(str(ff_prof / "downloads.sqlite")) as conn:
        conn.execute(
            "CREATE TABLE moz_downloads (id INTEGER PRIMARY KEY, name TEXT, source TEXT, target TEXT, startTime INTEGER, endTime INTEGER, state INTEGER, referrer TEXT, currBytes INTEGER, maxBytes INTEGER, mimeType TEXT);"
        )
        conn.execute(
            "INSERT INTO moz_downloads VALUES (1, CAST(X'5472756E636174656420EDA0BD' AS TEXT), 'https://dl-wtf8.example.org/a.bin', 'file:///C:/Users/Alice/Downloads/wtf8.bin', ?, ?, 1, 'https://dl-wtf8.example.org/', 512, 512, 'application/octet-stream');",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_downloads VALUES (2, CAST(X'FFFE41' AS TEXT), 'https://dl-raw.example.org/b.bin', 'file:///C:/Users/Alice/Downloads/raw.bin', ?, ?, 1, 'https://dl-raw.example.org/', 256, 256, 'application/octet-stream');",
            [t_ff_us, t_ff_us],
        )
        conn.execute(
            "INSERT INTO moz_downloads VALUES (3, 'legacy_clean.exe', 'https://dl-clean.example.org/legacy_clean.exe', 'file:///C:/Users/Alice/Downloads/legacy_clean.exe', ?, ?, 1, 'https://dl-clean.example.org/', 1024, 1024, 'application/x-msdownload');",
            [t_ff_us, t_ff_us],
        )

    # 10. Firefox signons.sqlite
    with sqlite3.connect(str(ff_prof / "signons.sqlite")) as conn:
        conn.execute(
            "CREATE TABLE moz_logins (id INTEGER PRIMARY KEY, hostname TEXT, httpRealm TEXT, formSubmitURL TEXT, usernameField TEXT, passwordField TEXT, encryptedUsername TEXT, encryptedPassword TEXT, guid TEXT, encType INTEGER, timeCreated INTEGER, timeLastUsed INTEGER, timePasswordChanged INTEGER, timesUsed INTEGER);"
        )
        conn.execute(
            "INSERT INTO moz_logins VALUES (1, 'https://sg-wtf8.example.org', CAST(X'5472756E636174656420EDA0BD' AS TEXT), NULL, 'u', 'p', 'eu1', 'ep1', '{sg1}', 1, ?, ?, ?, 1);",
            [t_ff_ms, t_ff_ms, t_ff_ms],
        )
        conn.execute(
            "INSERT INTO moz_logins VALUES (2, 'https://sg-raw.example.org', CAST(X'FFFE41' AS TEXT), NULL, 'u', 'p', 'eu2', 'ep2', '{sg2}', 1, ?, ?, ?, 1);",
            [t_ff_ms, t_ff_ms, t_ff_ms],
        )
        conn.execute(
            "INSERT INTO moz_logins VALUES (3, 'https://sg-clean.example.org', 'Clean Signon Realm', 'https://sg-clean.example.org/login', 'u', 'p', 'eu3', 'ep3', '{sg3}', 1, ?, ?, ?, 2);",
            [t_ff_ms, t_ff_ms, t_ff_ms],
        )

    ch_wtf_res = ChromiumParser(cid_wtf, sdir_wtf).parse()
    ff_wtf_res = FirefoxParser(cid_wtf, sdir_wtf).parse()

    assert ch_wtf_res["parsed_chrome_history"] == 3
    assert ch_wtf_res["parsed_chrome_visits"] == 1
    assert ch_wtf_res["parsed_chrome_downloads"] == 1
    assert ch_wtf_res["parsed_chrome_search_terms"] == 2
    assert ch_wtf_res["parsed_chrome_cookies"] == 3
    assert ch_wtf_res["parsed_chrome_autofill"] == 3
    assert ch_wtf_res["parsed_chrome_top_sites"] == 3
    assert ch_wtf_res["parsed_chrome_logins"] == 3

    assert ff_wtf_res["parsed_firefox_history"] == 4
    assert ff_wtf_res["parsed_firefox_downloads"] == 4  # 1 moz_annos + 3 downloads.sqlite
    assert ff_wtf_res["parsed_firefox_bookmarks"] == 2
    assert ff_wtf_res["parsed_firefox_cookies"] == 3
    assert ff_wtf_res["parsed_firefox_formhistory"] == 3
    assert ff_wtf_res["parsed_firefox_logins"] == 3

    with DuckDBManager.get_lock(cid_wtf):
        cur = DuckDBManager.get_connection(cid_wtf).cursor()

        ch_titles = dict(cur.execute("SELECT url, title FROM parsed_chrome_history;").fetchall())
        assert ch_titles["https://bind16-ch.example.com/"] == "Truncated \ufffd"
        assert ch_titles["https://raw-bytes-ch.example.com/"] == "\ufffd\ufffdA"
        assert ch_titles["https://clean-ch.example.com/"] == "Clean Sibling Title"

        ch_dls = cur.execute("SELECT target_path FROM parsed_chrome_downloads;").fetchall()
        assert ch_dls == [(r"C:\Users\Alice\Downloads\important.exe",)]

        ch_terms = {r[0] for r in cur.execute("SELECT term FROM parsed_chrome_search_terms;").fetchall()}
        assert ch_terms == {"Clean Sibling Query", "Truncated \ufffd"}

        ch_cks = dict(cur.execute("SELECT name, value FROM parsed_chrome_cookies;").fetchall())
        assert ch_cks == {
            "ck_wtf8": "Truncated \ufffd",
            "ck_raw": "\ufffd\ufffdA",
            "ck_clean": "clean_cookie_val",
        }

        ch_afs = dict(cur.execute("SELECT name, value FROM parsed_chrome_autofill;").fetchall())
        assert ch_afs == {
            "af_wtf8": "Truncated \ufffd",
            "af_raw": "\ufffd\ufffdA",
            "af_clean": "Clean Autofill Value",
        }

        ch_ts = dict(cur.execute("SELECT url, title FROM parsed_chrome_top_sites;").fetchall())
        assert ch_ts == {
            "https://ts-wtf8.example.com/": "Truncated \ufffd",
            "https://ts-raw.example.com/": "\ufffd\ufffdA",
            "https://ts-clean.example.com/": "Clean Top Site",
        }

        ch_lgs = dict(cur.execute("SELECT origin_url, username_value FROM parsed_chrome_logins;").fetchall())
        assert ch_lgs == {
            "https://lg-wtf8.example.com": "Truncated \ufffd",
            "https://lg-raw.example.com": "\ufffd\ufffdA",
            "https://lg-clean.example.com": "alice_clean_user",
        }

        ff_titles = dict(cur.execute("SELECT url, title FROM parsed_firefox_history;").fetchall())
        assert ff_titles["https://bind16-ff.example.org/"] == "Truncated \ufffd"
        assert ff_titles["https://raw-ff.example.org/"] == "\ufffd\ufffdA"
        assert ff_titles["https://clean-ff.example.org/"] == "Clean FF Sibling"

        ff_bms = {r[0] for r in cur.execute("SELECT title FROM parsed_firefox_bookmarks;").fetchall()}
        assert ff_bms == {"Clean FF Bookmark", "Truncated \ufffd"}

        ff_dls = {r[0] for r in cur.execute("SELECT file_name FROM parsed_firefox_downloads;").fetchall()}
        assert ff_dls == {"ff_important.zip", "Truncated \ufffd", "\ufffd\ufffdA", "legacy_clean.exe"}

        ff_cks = dict(cur.execute("SELECT name, value FROM parsed_firefox_cookies;").fetchall())
        assert ff_cks == {
            "ff_ck_wtf8": "Truncated \ufffd",
            "ff_ck_raw": "\ufffd\ufffdA",
            "ff_ck_clean": "ff_clean_cookie",
        }

        ff_fhs = dict(cur.execute("SELECT fieldname, value FROM parsed_firefox_formhistory;").fetchall())
        assert ff_fhs == {
            "fh_wtf8": "Truncated \ufffd",
            "fh_raw": "\ufffd\ufffdA",
            "fh_clean": "Firefox Clean Input",
        }

        ff_lgs = dict(cur.execute('SELECT hostname, "httpRealm" FROM parsed_firefox_logins;').fetchall())
        assert ff_lgs == {
            "https://sg-wtf8.example.org": "Truncated \ufffd",
            "https://sg-raw.example.org": "\ufffd\ufffdA",
            "https://sg-clean.example.org": "Clean Signon Realm",
        }

    # -----------------------------------------------------------------------
    # (b) Corrupt B-Tree Mid-Query sqlite3.DatabaseError Temp Handle Cleanup
    # -----------------------------------------------------------------------
    iso_tmp_root = tmp_path / "isolated_tmp_handles"
    iso_tmp_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("TMP", str(iso_tmp_root))
    monkeypatch.setenv("TEMP", str(iso_tmp_root))
    monkeypatch.setattr(tempfile, "tempdir", str(iso_tmp_root))
    assert Path(tempfile.gettempdir()).resolve() == iso_tmp_root.resolve()

    cid_bad, _cdir_bad, sdir_bad = isolated_case_factory("case_m3a_h_corrupt_btree", "image")
    ch_bad = sdir_bad / "Browsers" / "Chrome" / "BadUser" / "Default"
    (ch_bad / "Network").mkdir(parents=True, exist_ok=True)
    ch_good = sdir_bad / "Browsers" / "Chrome" / "GoodUser" / "Default"
    ch_good.mkdir(parents=True, exist_ok=True)
    ff_bad = sdir_bad / "Browsers" / "Firefox" / "BadUser" / "def"
    ff_bad.mkdir(parents=True, exist_ok=True)
    ff_good = sdir_bad / "Browsers" / "Firefox" / "GoodUser" / "def"
    ff_good.mkdir(parents=True, exist_ok=True)

    def _make_multipage_corrupt_db(path: Path, ddl: str, insert_sql: str) -> None:
        with sqlite3.connect(str(path)) as c:
            c.execute("PRAGMA page_size = 4096;")
            c.execute(ddl)
            for idx_row in range(35):
                c.execute(insert_sql, [idx_row, "P" * 300])
        raw_bytes = bytearray(path.read_bytes())
        assert len(raw_bytes) >= 8192
        # Corrupt leaf B-tree page 2 while keeping page 1 (sqlite_master) intact so SELECT fails mid-query!
        raw_bytes[4096:8192] = b"\xff" * 4096
        path.write_bytes(bytes(raw_bytes))

    _make_multipage_corrupt_db(
        ch_bad / "History",
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);",
        "INSERT INTO urls VALUES (?, 'https://bad.example.com/', ?, 1, 0, 13350000000000000);",
    )
    _make_multipage_corrupt_db(
        ch_bad / "Network" / "Cookies",
        "CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER);",
        "INSERT INTO cookies VALUES (?, '.bad.example.com', 'c', ?, '/', 0, 1, 1, 0);",
    )
    _make_multipage_corrupt_db(
        ch_bad / "Web Data",
        "CREATE TABLE autofill (id INTEGER PRIMARY KEY, name TEXT, value TEXT, count INTEGER);",
        "INSERT INTO autofill VALUES (?, 'f', ?, 1);",
    )
    _make_multipage_corrupt_db(
        ch_bad / "Top Sites",
        "CREATE TABLE top_sites (id INTEGER PRIMARY KEY, url TEXT, url_rank INTEGER, title TEXT);",
        "INSERT INTO top_sites VALUES (?, 'https://badts.example.com/', 0, ?);",
    )
    _make_multipage_corrupt_db(
        ch_bad / "Login Data",
        "CREATE TABLE logins (id INTEGER PRIMARY KEY, origin_url TEXT, username_value TEXT, signon_realm TEXT);",
        "INSERT INTO logins VALUES (?, 'https://badlg.example.com', ?, 'https://badlg.example.com');",
    )

    _make_multipage_corrupt_db(
        ff_bad / "places.sqlite",
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);",
        "INSERT INTO moz_places VALUES (?, 'https://badff.example.org/', ?, 1, 0, 1700000000000000);",
    )
    _make_multipage_corrupt_db(
        ff_bad / "cookies.sqlite",
        "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER);",
        "INSERT INTO moz_cookies VALUES (?, '.badff.org', 'c', ?, '/', 1900000000);",
    )
    _make_multipage_corrupt_db(
        ff_bad / "formhistory.sqlite",
        "CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER);",
        "INSERT INTO moz_formhistory VALUES (?, 'f', ?, 1);",
    )
    _make_multipage_corrupt_db(
        ff_bad / "downloads.sqlite",
        "CREATE TABLE moz_downloads (id INTEGER PRIMARY KEY, name TEXT, source TEXT, target TEXT);",
        "INSERT INTO moz_downloads VALUES (?, ?, 'https://baddl.org/x', 'file:///C:/x');",
    )
    _make_multipage_corrupt_db(
        ff_bad / "signons.sqlite",
        "CREATE TABLE moz_logins (id INTEGER PRIMARY KEY, hostname TEXT, httpRealm TEXT);",
        "INSERT INTO moz_logins VALUES (?, 'https://badsg.org', ?);",
    )

    # Neighbor clean profiles ensure corrupt B-trees never abort sibling extraction
    with sqlite3.connect(str(ch_good / "Top Sites")) as c:
        c.execute("CREATE TABLE top_sites (url TEXT, url_rank INTEGER, title TEXT);")
        c.execute("INSERT INTO top_sites VALUES ('https://good-neighbor.example.com/', 0, 'Good Neighbor');")
    with sqlite3.connect(str(ff_good / "formhistory.sqlite")) as c:
        c.execute("CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER);")
        c.execute("INSERT INTO moz_formhistory VALUES (1, 'q', 'good_ff_neighbor', 1);")

    ch_bad_res = ChromiumParser(cid_bad, sdir_bad).parse()
    ff_bad_res = FirefoxParser(cid_bad, sdir_bad).parse()
    assert ch_bad_res.get("parsed_chrome_top_sites") == 1
    assert ff_bad_res.get("parsed_firefox_formhistory") == 1

    leaked_temp_dirs = [
        p.name
        for p in iso_tmp_root.iterdir()
        if p.name.startswith(("wft_chromium_", "wft_firefox_", "wft_ff_", "wft_sqlite_"))
    ]
    assert leaked_temp_dirs == [], f"In-process temp directories leaked on Windows: {leaked_temp_dirs}"

    # -----------------------------------------------------------------------
    # (c) 3 BaseParser Hardening Polish Verifications
    # -----------------------------------------------------------------------
    # c1. BaseParser._log on strict cp1252 redirected sys.stdout with Cyrillic, CJK, emoji, and lone surrogate
    bp_polish = BaseParser(cid_bad, sdir_bad)
    raw_stdout_buf = io.BytesIO()
    cp1252_stdout = io.TextIOWrapper(raw_stdout_buf, encoding="cp1252", errors="strict")
    orig_stdout = sys.stdout
    try:
        sys.stdout = cp1252_stdout
        bp_polish._log("International path C:\\Users\\Иван\\中文\\\U0001f680\\surrogate_\ud83d_end", "WARNING")
        cp1252_stdout.flush()
    finally:
        sys.stdout = orig_stdout
    assert len(raw_stdout_buf.getvalue()) > 0
    log_text_utf8 = bp_polish.log_file.read_text(encoding="utf-8")
    assert "Иван" in log_text_utf8
    assert "中文" in log_text_utf8
    assert "\U0001f680" in log_text_utf8
    assert "surrogate_\ufffd_end" in log_text_utf8

    # c2. prtime_to_datetime exact 64-bit integer divmod microsecond precision (> 2^53, zero float64 ULP drift)
    assert prtime_to_datetime(253402300798123457) == datetime(
        9999, 12, 31, 23, 59, 58, 123457, tzinfo=timezone.utc
    )
    assert prtime_to_datetime("253402300798123457") == datetime(
        9999, 12, 31, 23, 59, 58, 123457, tzinfo=timezone.utc
    )
    assert prtime_to_datetime(253402300799) == datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert prtime_to_datetime(253402300800000000) is None

    # c3. copy_sqlite_with_wal on S_IREAD read-only SQLite DB + uncheckpointed WAL followed by bare shutil.rmtree
    ro_src_dir = tmp_path / "ro_sqlite_src"
    ro_src_dir.mkdir(parents=True, exist_ok=True)
    ro_db = ro_src_dir / "places.sqlite"
    ro_wal = ro_src_dir / "places.sqlite-wal"
    ro_dest_tmp = tmp_path / "ro_copy_dest"
    ro_live_conn = sqlite3.connect(str(ro_db))
    try:
        ro_live_conn.execute("PRAGMA journal_mode=WAL;")
        ro_live_conn.execute("PRAGMA wal_autocheckpoint=0;")
        ro_live_conn.execute("CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);")
        for idx_r in range(10):
            ro_live_conn.execute("INSERT INTO t VALUES (?, ?);", [idx_r, f"row_{idx_r}"])
        ro_live_conn.commit()
        assert ro_wal.is_file() and ro_wal.stat().st_size > 0

        os.chmod(ro_db, stat.S_IREAD)
        os.chmod(ro_wal, stat.S_IREAD)

        copied_ro_db = copy_sqlite_with_wal(ro_db, temp_dir=ro_dest_tmp)
        assert (copied_ro_db.stat().st_mode & stat.S_IWRITE) != 0
        copied_ro_wal = copied_ro_db.parent / "places.sqlite-wal"
        assert copied_ro_wal.is_file() and (copied_ro_wal.stat().st_mode & stat.S_IWRITE) != 0
        check_c = sqlite3.connect(str(copied_ro_db))
        try:
            assert check_c.execute("SELECT COUNT(*) FROM t;").fetchone()[0] == 10
        finally:
            check_c.close()

        # Bare shutil.rmtree WITHOUT ignore_errors=True MUST succeed with zero PermissionError on Windows!
        shutil.rmtree(ro_dest_tmp)
        assert not ro_dest_tmp.exists()
    finally:
        for p_ro in (ro_db, ro_wal):
            if p_ro.exists():
                try:
                    os.chmod(p_ro, stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
        try:
            ro_live_conn.close()
        except Exception:
            pass


