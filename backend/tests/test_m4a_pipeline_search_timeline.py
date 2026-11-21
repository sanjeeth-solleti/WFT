"""
Comprehensive M4-A Unit & Integration Test Suite:
  (A) High-Speed DuckDB Engine, RLock Concurrency, PRAGMA threads & Indexes
  (B) Complete Schema, MASTER_ARTIFACT_CATALOG & Non-Destructive Registry Sync
  (C) F18 Zero-Spurious-Hit Multi-Threaded Keyword Search & Evidence Path Restoration
  (D) F19 8-Timestamp $MFT/$FN MACB Super-Timeline, Deduplication & Canonical Categories
  (E) F16 / F25-F29 Concurrent ProcessingPipeline, selected_artifacts Gating & Telemetry
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time
from typing import Generator, Tuple
from unittest.mock import MagicMock, patch
import uuid

import pytest

from backend import config as wft_config
from backend.config import BASE_DIR, register_case_dir
from backend.db.engine import (
    DuckDBManager,
    escape_like,
    init_case_db,
    log_processing_event,
    query_paginated,
    restore_evidence_path,
    scan_keywords_for_case,
)
from backend.db.schema import (
    CANONICAL_CATEGORIES,
    CORE_TABLES,
    sync_artifact_registry_counts,
    sync_granular_artifacts,
    verify_core_tables,
)
from backend.orchestrator.ez_runner import EZToolRunner
from backend.orchestrator.normalizer import TimelineNormalizer
from backend.orchestrator.pipeline import (
    ProcessingPipeline,
    clamp_max_workers,
    get_job_status,
    run_pipeline,
)


def _cleanup_registered_case(case_id: str) -> None:
    DuckDBManager.close_connection(case_id)
    unreg = getattr(wft_config, "unregister_case_dir", None)
    if callable(unreg):
        unreg(case_id)
    else:
        custom_map = getattr(wft_config, "CUSTOM_CASE_DIRS", None)
        if isinstance(custom_map, dict):
            custom_map.pop(case_id, None)


@pytest.fixture
def isolated_case(tmp_path: Path) -> Generator[Tuple[str, Path], None, None]:
    """
    Create a completely isolated forensic case directory inside pytest's `tmp_path`,
    verifying that `(BASE_DIR / "cases")` is NEVER created by M4-A operations.
    """
    cases_root = BASE_DIR / "cases"
    existed_before = cases_root.exists()

    case_id = f"m4a_test_{uuid.uuid4().hex[:10]}"
    case_dir = (tmp_path / case_id).resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, str(case_dir))
    init_case_db(case_id)

    try:
        yield case_id, case_dir
    finally:
        _cleanup_registered_case(case_id)
        if not existed_before:
            assert not cases_root.exists(), "(BASE_DIR / 'cases') must NEVER be created when custom target_dir is registered!"


# ===========================================================================
# (A) DuckDB Engine, Multi-Threading, Indexes & Concurrency
# ===========================================================================
class TestDuckDBEngineAndConcurrency:
    def test_rlock_reentrancy_and_configure_threads_clamping(self, isolated_case: Tuple[str, Path]) -> None:
        case_id, _ = isolated_case
        lock_a = DuckDBManager.get_lock(case_id)
        lock_b = DuckDBManager.get_lock(case_id)
        assert lock_a is lock_b

        # RLock must allow nested acquisition on the same thread without deadlocking
        with lock_a:
            with lock_b:
                assert DuckDBManager.configure_threads(case_id, 0) == 1
                assert DuckDBManager.configure_threads(case_id, -5) == 1
                assert DuckDBManager.configure_threads(case_id, 99) == 32
                assert DuckDBManager.configure_threads(case_id, 8) == 8

                conn = DuckDBManager.get_connection(case_id)
                active_threads = int(conn.cursor().execute("SELECT current_setting('threads');").fetchone()[0])
                assert active_threads == 8

        assert clamp_max_workers(0) == 1
        assert clamp_max_workers(128) == 32
        assert clamp_max_workers(12) == 12

    def test_master_timeline_indexes_and_case_metadata_table(self, isolated_case: Tuple[str, Path]) -> None:
        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # Verify macb column and SQL indexes exist on master_timeline
            mt_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE master_timeline;").fetchall()}
            assert "macb" in mt_cols

            idx_names = {
                str(r[0]).lower()
                for r in cur.execute(
                    "SELECT index_name FROM duckdb_indexes() WHERE table_name = 'master_timeline';"
                ).fetchall()
            }
            assert any("timestamp" in n for n in idx_names)
            assert any("category" in n for n in idx_names)
            assert any("source" in n for n in idx_names)

            # Verify case_metadata 2-column INSERT ... ON CONFLICT works cleanly
            cur.execute("INSERT INTO case_metadata (key, value) VALUES ('examiner', 'Alice') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;")
            cur.execute("INSERT INTO case_metadata (key, value) VALUES ('examiner', 'Bob') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;")
            val = cur.execute("SELECT value FROM case_metadata WHERE key = 'examiner';").fetchone()[0]
            assert val == "Bob"

    def test_concurrent_multithreaded_reads_writes_and_like_escaping(self, isolated_case: Tuple[str, Path]) -> None:
        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()
            cur.execute("CREATE TABLE concurrent_probe (id INTEGER, label VARCHAR);")
            cur.executemany(
                "INSERT INTO concurrent_probe VALUES (?, ?);",
                [(1, "100% literal"), (2, "1000 false_hit"), (3, r"C:\Windows\System32\cmd.exe")],
            )

        assert escape_like("100%_\\test") == r"100\%\_\\test"

        errors: list[Exception] = []

        def _worker(tid: int) -> None:
            try:
                for step in range(8):
                    log_processing_event(
                        case_id=case_id,
                        module_name=f"Worker:{tid}",
                        command_executed=f"step-{step}",
                        exit_code=0,
                        rows_ingested=1,
                        duration_ms=1,
                        status="SUCCESS",
                    )
                    page = query_paginated(
                        case_id=case_id,
                        table_name="concurrent_probe",
                        limit=25,
                        offset=0,
                        search="100%",
                    )
                    rows = page.get("rows") or page.get("data") or []
                    assert len(rows) == 1
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(_worker, range(10)))

        assert errors == []
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cnt = conn.cursor().execute("SELECT COUNT(*) FROM processing_logs WHERE module_name LIKE 'Worker:%';").fetchone()[0]
            assert cnt == 80


# ===========================================================================
# (B) Complete Schema, MASTER_ARTIFACT_CATALOG & Non-Destructive Registry Sync
# ===========================================================================
class TestSchemaAndRegistryIntegrity:
    def test_all_new_tables_views_and_canonical_categories_exist(self, isolated_case: Tuple[str, Path]) -> None:
        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            assert set(verify_core_tables(conn, case_id=case_id)) == set(CORE_TABLES)
            cur = conn.cursor()

            existing = {
                str(r[0]).lower()
                for r in cur.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            required_objects = {
                "case_metadata",
                "vfs_partitions",
                "vfs_files",
                "vfs_shadow_copies",
                "parsed_carved_files",
                "parsed_bulk_extractor_features",
                "parsed_bulk_extractor_histograms",
                "raw_hindsight",
                "parsed_user_accounts",
                "parsed_windows_services",
                "parsed_autoruns",
                "parsed_userassist",
                "parsed_bam_dam",
                "parsed_registry_mru",
                "parsed_network_profiles",
                "parsed_wer_reports",
                "parsed_chrome_session",
                "parsed_firefox_logins",
                "parsed_text_documents",
                "media_ocr_results",
                "view_keyword_hits",
                "view_refined_domains",
                "view_refined_users",
                "view_documents",
                "view_docs_txt",
                "view_autoruns",
                "view_userassist",
                "view_bam_dam",
            }
            missing = required_objects - existing
            assert not missing, f"Missing required schema tables/views: {missing}"

            # Firefox compatibility columns
            ff_cookie_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE parsed_firefox_cookies;").fetchall()}
            assert {"host_key", "creation_utc", "expires_utc", "last_access_utc"}.issubset(ff_cookie_cols)
            ff_bm_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE parsed_firefox_bookmarks;").fetchall()}
            assert "date_modified" in ff_bm_cols

            # Every registered artifact must use strictly CANONICAL_CATEGORIES
            reg_cats = {
                str(r[0])
                for r in cur.execute("SELECT DISTINCT category FROM artifact_registry;").fetchall()
            }
            assert reg_cats.issubset(set(CANONICAL_CATEGORIES)), f"Non-canonical categories found: {reg_cats - set(CANONICAL_CATEGORIES)}"

    def test_registry_and_granular_sync_are_non_destructive_and_union_axiom_views(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # Insert media picture while parsed_media_exif is completely empty (0 rows)
            cur.execute(
                """
                INSERT INTO parsed_media_pictures (file_name, file_path, file_size_bytes)
                VALUES ('evidence.jpg', 'C:\\Users\\Alice\\Pictures\\evidence.jpg', 4096);
                """
            )
            # Insert browser history into both legacy combined & per-browser table to test safe_sync_table dedup
            cur.execute(
                """
                INSERT INTO parsed_browser_history (browser, url, title, visit_time_utc, visit_count, source_path)
                VALUES ('Chrome', 'https://example.org/login', 'Login', '2025-05-01 10:00:00', 1, 'C:\\History');
                """
            )

            # Insert AXIOM parsed_* AND raw_recmd rows to verify unioned views surface BOTH
            cur.execute(
                """
                INSERT INTO parsed_autoruns (entry_name, image_path, location, last_write_utc)
                VALUES ('Updater', 'C:\\ProgramData\\updater.exe', 'HKLM\\Run', '2025-05-01 08:00:00');
                """
            )
            cur.execute(
                """
                INSERT INTO raw_recmd (HivePath, HiveType, Category, Description, ValueName, ValueData, LastWriteTimestamp)
                VALUES ('NTUSER.DAT', 'NTUSER', 'Autoruns', 'Run Key', 'Persistence', 'C:\\Temp\\evil.exe', '2025-05-01 09:00:00');
                """
            )

            # Run sync multiple times to prove idempotence and zero row duplication/deletion
            sync_granular_artifacts(conn)
            sync_granular_artifacts(conn)
            sync_artifact_registry_counts(conn, case_id=case_id)
            sync_artifact_registry_counts(conn, case_id=case_id)

            pic_cnt = cur.execute("SELECT COUNT(*) FROM parsed_media_pictures;").fetchone()[0]
            assert pic_cnt == 1, "parsed_media_pictures must NOT be wiped when parsed_media_exif has 0 rows!"

            chrome_cnt = cur.execute("SELECT COUNT(*) FROM parsed_chrome_history WHERE url = 'https://example.org/login';").fetchone()[0]
            assert chrome_cnt == 1, "safe_sync_table must NOT duplicate rows across repeated syncs!"

            autorun_cnt = cur.execute("SELECT COUNT(*) FROM view_autoruns;").fetchone()[0]
            assert autorun_cnt >= 2, "view_autoruns must surface both parsed_autoruns and raw_recmd rows!"

            # Verify REFINED RESULTS, media_ocr_results, docs_txt, etc. were NOT deleted from artifact_registry
            preserved_ids = {
                str(r[0]): str(r[1])
                for r in cur.execute(
                    """
                    SELECT artifact_id, category FROM artifact_registry
                    WHERE artifact_id IN ('keyword_hits', 'refined_domains', 'refined_users', 'media_ocr_results', 'docs_txt');
                    """
                ).fetchall()
            }
            assert preserved_ids.get("keyword_hits") == "REFINED RESULTS"
            assert preserved_ids.get("refined_domains") == "REFINED RESULTS"
            assert preserved_ids.get("refined_users") == "REFINED RESULTS"
            assert "media_ocr_results" in preserved_ids
            assert "docs_txt" in preserved_ids


# ===========================================================================
# (C) F18 Zero-Spurious-Hit Keyword Search & Evidence Path Restoration
# ===========================================================================
class TestKeywordSearchEngine:
    def test_restore_evidence_path_variants(self, tmp_path: Path) -> None:
        case_dir = tmp_path / "case_paths"
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "Enrichment" / "Part0" / "Users" / "Alice" / "secret.txt"),
                case_dir=case_dir,
            )
            == r"C:\Users\Alice\secret.txt"
        )
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "Enrichment" / "Users" / "Bob" / "notes.txt"),
                case_dir=case_dir,
            )
            == r"C:\Users\Bob\notes.txt"
        )
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "VSS" / "VSS_2" / "Users" / "Alice" / "old.docx"),
                case_dir=case_dir,
            )
            == r"[VSS#2] C:\Users\Alice\old.docx"
        )
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "UserFiles" / "Alice" / "Desktop" / "creds.txt"),
                case_dir=case_dir,
            )
            == r"C:\Users\Alice\Desktop\creds.txt"
        )
        carved_restored = restore_evidence_path(
            str(case_dir / "carved" / "pdf" / "carved_001.pdf"),
            case_dir=case_dir,
        )
        assert carved_restored.startswith("[CARVED]")

    def test_zero_spurious_hits_wide_columns_300_rows_regex_and_raw_files(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        case_id, case_dir = isolated_case

        # Create staged UTF-8, UTF-16LE, VSS, and carved files for raw disk/staged search
        enr_file = case_dir / "staging" / "Enrichment" / "Partition_1" / "Users" / "Alice" / "vault.txt"
        enr_file.parent.mkdir(parents=True, exist_ok=True)
        enr_file.write_text("Header padding\nCONFIDENTIAL_PROJECT_OMEGA_TOKEN\nFooter\n", encoding="utf-8")

        utf16_file = case_dir / "staging" / "VSS" / "VSS_1" / "Windows" / "Temp" / "ps_log.txt"
        utf16_file.parent.mkdir(parents=True, exist_ok=True)
        utf16_file.write_bytes("Invoke-Mimikatz UTF16_SECRET_MARKER -DumpCreds".encode("utf-16-le"))

        carved_file = case_dir / "carved" / "txt" / "00001.txt"
        carved_file.parent.mkdir(parents=True, exist_ok=True)
        carved_file.write_text("Recovered unallocated CVE-2025-42424 exploit payload", encoding="utf-8")

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # 1. Create a 26-column table to prove >20 columns (`col_25`) are scanned AND
            #    adjacent columns (`col_1='alpha'`, `col_2='beta'`) NEVER match `'alpha | beta'`.
            col_defs = ", ".join([f"col_{i} VARCHAR" for i in range(1, 27)])
            cur.execute(f"CREATE TABLE parsed_wide_forensic_test ({col_defs});")

            row_boundary = ["alpha" if i == 1 else ("beta" if i == 2 else "") for i in range(1, 27)]
            long_prefix = "A" * 420
            row_col25 = [
                f"{long_prefix} DEEP_COL25_NEEDLE trailing_context" if i == 25 else ""
                for i in range(1, 27)
            ]
            row_wildcards = [
                "Discount 100% approved for admin_user" if i == 5 else ("Discount 1000 approved for adminXuser" if i == 6 else "")
                for i in range(1, 27)
            ]
            row_case = ["ExactCaseToken" if i == 3 else "exactcasetoken" if i == 4 else "" for i in range(1, 27)]

            placeholders = ", ".join(["?"] * 26)
            cur.executemany(
                f"INSERT INTO parsed_wide_forensic_test VALUES ({placeholders});",
                [row_boundary, row_col25, row_wildcards, row_case],
            )

            # 2. Insert 305 matching rows to prove the old `LIMIT 250` cap is completely removed
            cur.execute("CREATE TABLE parsed_bulk_hits_probe (row_num INTEGER, payload VARCHAR);")
            cur.executemany(
                "INSERT INTO parsed_bulk_hits_probe VALUES (?, ?);",
                [(i, f"Event #{i} BULK_305_MARKER") for i in range(305)],
            )

            # 3. Seed keywords including literal `%`/`_`, case-sensitive, valid regex, and INVALID regex
            keywords_to_insert = [
                ("kw_boundary", "alpha | beta", False, False),
                ("kw_col25", "DEEP_COL25_NEEDLE", False, False),
                ("kw_pct", "100%", False, False),
                ("kw_under", "admin_user", False, False),
                ("kw_cs", "ExactCaseToken", False, True),
                ("kw_305", "BULK_305_MARKER", False, False),
                ("kw_utf8", "CONFIDENTIAL_PROJECT_OMEGA_TOKEN", False, False),
                ("kw_utf16", "UTF16_SECRET_MARKER", False, False),
                ("kw_regex", r"CVE-\d{4}-\d{4,7}", True, False),
                ("kw_bad_re", "[unclosed_group(", True, False),
            ]
            for kid, kw, is_re, is_cs in keywords_to_insert:
                cur.execute(
                    """
                    INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, case_sensitive, hit_count)
                    VALUES (?, ?, ?, ?, ?, 0);
                    """,
                    [kid, kw, is_re, is_cs, is_cs],
                )

        total_hits = scan_keywords_for_case(case_id, max_workers=8)
        assert total_hits >= 311

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()
            counts = {
                str(r[0]): int(r[1])
                for r in cur.execute("SELECT keyword_id, hit_count FROM case_keywords;").fetchall()
            }

            # Zero spurious cross-column `' | '` boundary match
            assert counts["kw_boundary"] == 0

            # Column #25 (>20) matched with centered `[col_25]` snippet
            assert counts["kw_col25"] == 1
            snip = cur.execute(
                "SELECT matched_snippet, matched_column FROM view_keyword_hits WHERE keyword_id = 'kw_col25';"
            ).fetchone()
            assert snip is not None
            assert "DEEP_COL25_NEEDLE" in str(snip[0])
            assert "col_25" in str(snip[1]) or "[col_25]" in str(snip[0])

            # Wildcard escaping: `100%` and `admin_user` match ONLY the literal row, never `1000` or `adminXuser`
            assert counts["kw_pct"] == 1
            assert counts["kw_under"] == 1

            # Case sensitivity honored
            assert counts["kw_cs"] == 1

            # No 250-row cap! All 305 rows captured
            assert counts["kw_305"] == 305

            # Invalid regex caught gracefully with 0 hits and 0 crashes
            assert counts["kw_bad_re"] == 0

            # Raw UTF-8, UTF-16LE, and Regex carved files found with restored forensic paths
            assert counts["kw_utf8"] == 1
            utf8_path = cur.execute(
                "SELECT source_file FROM view_keyword_hits WHERE keyword_id = 'kw_utf8';"
            ).fetchone()[0]
            assert utf8_path == r"C:\Users\Alice\vault.txt"

            assert counts["kw_utf16"] == 1
            utf16_path = cur.execute(
                "SELECT source_file FROM view_keyword_hits WHERE keyword_id = 'kw_utf16';"
            ).fetchone()[0]
            assert utf16_path == r"[VSS#1] C:\Windows\Temp\ps_log.txt"

            assert counts["kw_regex"] == 1
            carved_path = cur.execute(
                "SELECT source_file FROM view_keyword_hits WHERE keyword_id = 'kw_regex';"
            ).fetchone()[0]
            assert str(carved_path).startswith("[CARVED]")


# ===========================================================================
# (D) F19 8-Timestamp MACB Super-Timeline & Entity Deduplication
# ===========================================================================
class TestSuperTimelineAndEntityDeduplication:
    def test_mft_8_timestamp_macb_deleted_directory_timestomp_and_deduplication(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # 1. Populate BOTH legacy `parsed_browser_*` AND granular `parsed_chrome_*` (+ `parsed_firefox_logins`)
            cur.execute(
                """
                INSERT INTO parsed_browser_history (browser, url, title, visit_time, visit_time_utc, visit_count, source_path)
                VALUES ('Chrome', 'https://portal.corp.local/app', 'Corp Portal', '2025-06-10 12:00:00', '2025-06-10 12:00:00', 2, 'C:\\History');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_chrome_history (browser, url, title, visit_time, visit_count, profile)
                VALUES ('Chrome', 'https://portal.corp.local/app', 'Corp Portal', '2025-06-10 12:00:00', 2, 'Default');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_browser_downloads (browser, url, tab_url, target_path, start_time, start_time_utc, total_bytes)
                VALUES ('Chrome', 'https://portal.corp.local/payload.zip', 'https://portal.corp.local/payload.zip', 'C:\\Downloads\\payload.zip', '2025-06-10 12:05:00', '2025-06-10 12:05:00', 1024);
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_chrome_downloads (browser, tab_url, site_url, target_path, start_time, total_bytes, profile)
                VALUES ('Chrome', 'https://portal.corp.local/payload.zip', 'https://portal.corp.local/payload.zip', 'C:\\Downloads\\payload.zip', '2025-06-10 12:05:00', 1024, 'Default');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_browser_logins (browser, origin_url, username_value, date_created, date_created_utc)
                VALUES ('Firefox', 'https://mail.corp.local', 'jdoe', '2025-06-10 12:10:00', '2025-06-10 12:10:00');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_firefox_logins (browser, hostname, origin_url, username_value, time_created, date_created, time_last_used, date_last_used)
                VALUES ('Firefox', 'https://mail.corp.local', 'https://mail.corp.local', 'jdoe', '2025-06-10 12:10:00', '2025-06-10 12:10:00', '2025-06-10 12:15:00', '2025-06-10 12:15:00');
                """
            )

            # 2. Populate BOTH WPN tables (`parsed_notifications` & `parsed_wpn_notifications`)
            cur.execute(
                """
                INSERT INTO parsed_notifications (app_id, notification_type, payload, arrival_time)
                VALUES ('Microsoft.Teams', 'toast', 'Message from C2', '2025-06-10 13:00:00');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_wpn_notifications (app_id, notification_type, payload, arrival_time_utc)
                VALUES ('Microsoft.Teams', 'toast', 'Message from C2', '2025-06-10 13:00:00');
                """
            )

            # 3. Populate $MFT rows testing:
            #    - Row 1: Deleted custom-extension file with TIMESTOMP ($SI Created 2022 < $FN Created 2025) and distinct M, A, C, B
            #    - Row 2: Directory with identical M/A/C/B timestamps collapsing into 'MACB'
            #    - Row 3: Epoch bogus timestamp 1970-01-01 / 1601-01-01 (must be filtered out!)
            cur.execute(
                """
                INSERT INTO raw_mft (
                    EntryNumber, ParentPath, FileName, Extension, FileSize, InUse, IsDirectory,
                    Created0x10, LastModified0x10, LastRecordChange0x10, LastAccess0x10,
                    Created0x30, LastModified0x30, LastRecordChange0x30, LastAccess0x30
                ) VALUES
                (
                    101, '.\\Users\\Alice\\AppData', 'stager.xyzcustom', '.xyzcustom', 8192, FALSE, FALSE,
                    '2022-01-01 00:00:00', '2025-06-11 01:00:00', '2025-06-11 02:00:00', '2025-06-11 03:00:00',
                    '2025-06-11 00:30:00', '2025-06-11 01:30:00', '2025-06-11 02:30:00', '2025-06-11 03:30:00'
                ),
                (
                    102, '.\\Users\\Alice', 'StagingFolder', '', 0, TRUE, TRUE,
                    '2025-06-12 05:00:00', '2025-06-12 05:00:00', '2025-06-12 05:00:00', '2025-06-12 05:00:00',
                    NULL, NULL, NULL, NULL
                ),
                (
                    103, '.\\Windows', 'epoch_noise.dll', '.dll', 128, TRUE, FALSE,
                    '1970-01-01 00:00:00', '1601-01-01 00:00:00', NULL, NULL,
                    NULL, NULL, NULL, NULL
                );
                """
            )

            # 4. Populate Shellbags (default schema), AXIOM tables, Hindsight, VSS, Carved, Bulk Extractor
            cur.execute(
                """
                INSERT INTO raw_shellbags (BagPath, ValueName, Created, Modified, Accessed)
                VALUES ('BagMRU\\0', 'SecretUSB', '2025-06-13 09:00:00', '2025-06-13 09:05:00', '2025-06-13 09:10:00');
                """
            )
            cur.execute(
                """
                INSERT INTO raw_hindsight (browser, record_type, url, title, timestamp_utc)
                VALUES ('Chrome', 'cache', 'https://cdn.attacker.io/drop.js', 'drop.js', '2025-06-14 04:00:00');
                """
            )
            cur.execute(
                """
                INSERT INTO vfs_shadow_copies (vss_id, volume_label, creation_time_utc)
                VALUES ('VSS_1', 'OS', '2025-06-01 00:00:00');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_user_accounts (username, rid, last_logon_utc, account_type)
                VALUES ('backdoor_admin', 1005, '2025-06-14 06:00:00', 'Admin');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_bam_dam (executable_path, user_sid, execution_time_utc)
                VALUES ('\\Device\\HarddiskVolume3\\Temp\\beacon.exe', 'S-1-5-21-1001', '2025-06-14 06:05:00');
                """
            )
            # Populate file_enrichment with tool `scanned_at` — must NEVER pollute master_timeline!
            cur.execute(
                """
                INSERT INTO file_enrichment (file_path, file_name, sha256, scanned_at)
                VALUES ('C:\\Temp\\beacon.exe', 'beacon.exe', 'deadbeef', '2026-11-16 12:00:00');
                """
            )

        res = TimelineNormalizer(case_id).normalize_all()
        assert res["total_timeline_rows"] > 0

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # 1x Browser History, 1x Downloads, no 2x duplication!
            hist_cnt = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE summary LIKE '%portal.corp.local/app%';"
            ).fetchone()[0]
            assert hist_cnt == 1, f"Expected 1 browser history event, got {hist_cnt}"

            dl_cnt = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE summary LIKE '%payload.zip%';"
            ).fetchone()[0]
            assert dl_cnt == 1, f"Expected 1 browser download event, got {dl_cnt}"

            # 1x WPN notification (no 2x duplication!)
            wpn_cnt = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE summary LIKE '%Message from C2%';"
            ).fetchone()[0]
            assert wpn_cnt == 1, f"Expected 1 WPN event, got {wpn_cnt}"

            # $MFT 8-timestamp unpivot: 8 distinct timestamps for stager.xyzcustom!
            stager_rows = cur.execute(
                "SELECT macb, summary FROM master_timeline WHERE summary LIKE '%stager.xyzcustom%' ORDER BY timestamp_utc;"
            ).fetchall()
            assert len(stager_rows) == 8
            macbs = {str(r[0]) for r in stager_rows}
            assert {"M...", ".A..", "..C.", "...B"}.issubset(macbs)
            assert all("[DELETED]" in str(r[1]) for r in stager_rows)
            assert any("[TIMESTOMP: $SI < $FN]" in str(r[1]) for r in stager_rows)

            # Directory with identical M, A, C, B collapses into single 'MACB' row
            dir_rows = cur.execute(
                "SELECT macb, summary FROM master_timeline WHERE summary LIKE '%StagingFolder%';"
            ).fetchall()
            assert len(dir_rows) == 1
            assert dir_rows[0][0] == "MACB"
            assert "Directory" in str(dir_rows[0][1])

            # Zero epoch (`<= 1970-01-02`) or `file_enrichment.scanned_at` events
            bad_epoch = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE timestamp_utc <= TIMESTAMP '1970-01-02 00:00:00';"
            ).fetchone()[0]
            assert bad_epoch == 0
            enr_tl = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE source_table = 'file_enrichment';"
            ).fetchone()[0]
            assert enr_tl == 0

            # New M2/M3/AXIOM tables normalized
            src_tables = {
                str(r[0]) for r in cur.execute("SELECT DISTINCT source_table FROM master_timeline;").fetchall()
            }
            assert {"raw_shellbags", "raw_hindsight", "vfs_shadow_copies", "parsed_user_accounts", "parsed_bam_dam"}.issubset(src_tables)

            # All categories strictly in CANONICAL_CATEGORIES
            tl_cats = {
                str(r[0]) for r in cur.execute("SELECT DISTINCT category FROM master_timeline;").fetchall()
            }
            assert tl_cats.issubset(set(CANONICAL_CATEGORIES)), f"Non-canonical timeline categories: {tl_cats - set(CANONICAL_CATEGORIES)}"

            # view_keyword_hits preserved after TimelineNormalizer._create_refined_views
            cur.execute("SELECT COUNT(*) FROM view_keyword_hits;").fetchone()

    def test_sbecmd_shellbags_schema_and_vfs_files_macb_fallback(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # Replace raw_shellbags with SBECmd CSV schema (`Value`, `AbsolutePath`, `CreatedOn`, `ModifiedOn`, `AccessedOn`, `LastWriteTime`)
            cur.execute("DROP TABLE IF EXISTS raw_shellbags;")
            cur.execute(
                """
                CREATE TABLE raw_shellbags (
                    _row_id BIGINT,
                    BagPath VARCHAR,
                    Value VARCHAR,
                    AbsolutePath VARCHAR,
                    CreatedOn TIMESTAMP,
                    ModifiedOn TIMESTAMP,
                    AccessedOn TIMESTAMP,
                    LastWriteTime TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                INSERT INTO raw_shellbags VALUES (
                    1, 'BagMRU\\1', 'ExfilDrive', 'F:\\ExfilDrive',
                    '2025-07-01 10:00:00', '2025-07-01 10:05:00', '2025-07-01 10:10:00', '2025-07-01 10:15:00'
                );
                """
            )

            # With raw_mft empty (0 rows), populate vfs_files with $SI/$FN timestamps & deleted flag
            cur.execute(
                """
                INSERT INTO vfs_files (
                    file_name, parent_path, vfs_path, size_bytes, is_dir, is_deleted,
                    si_created, si_modified, si_accessed, si_changed,
                    fn_created
                ) VALUES (
                    'ghost_implant.bin', '\\Windows\\Temp', 'C:\\Windows\\Temp\\ghost_implant.bin', 2048, FALSE, TRUE,
                    '2023-01-01 00:00:00', '2025-07-02 01:00:00', '2025-07-02 02:00:00', '2025-07-02 03:00:00',
                    '2025-07-02 00:00:00'
                );
                """
            )

        res = TimelineNormalizer(case_id).normalize_all()
        assert res["total_timeline_rows"] >= 9

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()
            sb_cnt = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE source_table = 'raw_shellbags' AND summary LIKE '%ExfilDrive%';"
            ).fetchone()[0]
            assert sb_cnt == 4

            vfs_rows = cur.execute(
                "SELECT macb, summary FROM master_timeline WHERE source_table = 'vfs_files' AND summary LIKE '%ghost_implant.bin%';"
            ).fetchall()
            assert len(vfs_rows) == 5
            assert all("[DELETED]" in str(r[1]) for r in vfs_rows)
            assert any("[TIMESTOMP: $SI < $FN]" in str(r[1]) for r in vfs_rows)


# ===========================================================================
# (E) F16 / F25-F29 Concurrent ProcessingPipeline, selected_artifacts & Telemetry
# ===========================================================================
class TestConcurrentProcessingPipeline:
    def test_pipeline_selected_artifacts_metadata_keywords_concurrency_and_error_isolation(
        self, tmp_path: Path
    ) -> None:
        cases_root = BASE_DIR / "cases"
        existed_before = cases_root.exists()

        case_id = f"m4a_pipe_{uuid.uuid4().hex[:10]}"
        case_dir = (tmp_path / "case_out").resolve()
        evidence_dir = (tmp_path / "evidence_src").resolve()
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "mission_brief.txt").write_text(
            "Operation Nightfall key: PIPELINE_AUTO_KEYWORD_7788\n",
            encoding="utf-8",
        )

        active_counter = 0
        peak_concurrency = 0
        counter_lock = threading.Lock()
        invoked_components: list[str] = []

        def _make_concurrent_parse(name: str, should_fail: bool = False):
            def _parse(*args, **kwargs):
                nonlocal active_counter, peak_concurrency
                with counter_lock:
                    invoked_components.append(name)
                    active_counter += 1
                    peak_concurrency = max(peak_concurrency, active_counter)
                time.sleep(0.06)
                with counter_lock:
                    active_counter -= 1
                if should_fail:
                    raise RuntimeError(f"Simulated {name} parser defect")
                return {f"parsed_{name.lower()}": 3}

            return _parse

        try:
            with (
                patch("backend.parsers.ChromiumParser.parse", new=_make_concurrent_parse("Chromium")),
                patch("backend.parsers.FirefoxParser.parse", new=_make_concurrent_parse("Firefox")),
                patch("backend.parsers.ChatParser.parse", new=_make_concurrent_parse("Chat", should_fail=True)),
                patch("backend.parsers.EmailParser.parse", new=_make_concurrent_parse("Email")),
                patch.object(EZToolRunner, "run_evtx", return_value=5) as mock_evtx,
                patch.object(EZToolRunner, "run_pecmd", return_value=4) as mock_pecmd,
            ):
                progress_events: list[Tuple[int, str]] = []
                result = run_pipeline(
                    case_id=case_id,
                    source_type="folder",
                    source_path=str(evidence_dir),
                    target_dir=str(case_dir),
                    enable_yara=False,
                    enable_stinger=False,
                    enable_ocr=False,
                    enable_hindsight=False,
                    enable_ioc=False,
                    enable_data_carving=False,
                    enable_bulk_extractor=False,
                    enable_vss=False,
                    max_workers=8,
                    selected_artifacts=["browser_history", "chat_messages", "os_evtx"],
                    initial_keywords=[
                        {"keyword": "PIPELINE_AUTO_KEYWORD_7788", "is_regex": False, "is_case_sensitive": True, "category": "Ops"}
                    ],
                    case_metadata={
                        "case_name": "Nightfall IR",
                        "case_number": "INC-2026-042",
                        "examiner": "DFIR Lead",
                        "notes": "Unit test validation",
                    },
                    progress_callback=lambda pct, msg: progress_events.append((pct, msg)),
                )

            assert result["status"] == "SUCCESS"
            assert progress_events and progress_events[-1][0] == 100

            # Selected parsers (Chromium, Firefox, Chat) ran concurrently; unselected Email & PECmd were NOT invoked!
            assert {"Chromium", "Firefox", "Chat"}.issubset(set(invoked_components))
            assert "Email" not in invoked_components
            assert mock_evtx.called
            assert not mock_pecmd.called
            assert peak_concurrency >= 2, "Enabled custom parsers must execute concurrently in ThreadPoolExecutor!"

            status_info = get_job_status(case_id)
            assert status_info["status"] == "SUCCESS"

            with DuckDBManager.get_lock(case_id):
                conn = DuckDBManager.get_connection(case_id)
                cur = conn.cursor()

                # Verify case_metadata persisted
                meta = {
                    str(r[0]): str(r[1])
                    for r in cur.execute("SELECT key, value FROM case_metadata;").fetchall()
                }
                assert meta["case_name"] == "Nightfall IR"
                assert meta["case_number"] == "INC-2026-042"
                assert meta["examiner"] == "DFIR Lead"
                assert meta["max_workers"] == "8"

                # Verify Extractor log contract for main.py:1467 (`LIKE 'Extractor (%'`)
                ext_cmd = cur.execute(
                    "SELECT command_executed FROM processing_logs WHERE command_executed LIKE 'Extractor (%' LIMIT 1;"
                ).fetchone()
                assert ext_cmd is not None and str(evidence_dir) in str(ext_cmd[0])

                # Verify Chat failure was isolated & recorded in processing_logs as ERROR while Pipeline succeeded
                chat_err = cur.execute(
                    "SELECT status, error_message FROM processing_logs WHERE module_name = 'Parser:Chat';"
                ).fetchone()
                assert chat_err is not None
                assert chat_err[0] == "ERROR"
                assert "Simulated Chat parser defect" in str(chat_err[1])

                # Verify deselected Email was logged as SKIPPED
                email_skip = cur.execute(
                    "SELECT status FROM processing_logs WHERE module_name = 'Parser:Email';"
                ).fetchone()
                assert email_skip is not None and email_skip[0] == "SKIPPED"

                # Verify initial_keywords were seeded AND automatically scanned across staged evidence!
                kw_hits = cur.execute(
                    "SELECT COUNT(*) FROM view_keyword_hits WHERE keyword = 'PIPELINE_AUTO_KEYWORD_7788';"
                ).fetchone()[0]
                assert kw_hits >= 1
        finally:
            _cleanup_registered_case(case_id)
            if not existed_before:
                assert not cases_root.exists()

    def test_empty_selected_artifacts_and_optional_vss_carving_bulk_forwarding(
        self, tmp_path: Path
    ) -> None:
        case_id = f"m4a_opt_{uuid.uuid4().hex[:10]}"
        case_dir = (tmp_path / "case_opt").resolve()
        fake_img = (tmp_path / "disk.raw").resolve()
        fake_img.write_bytes(b"\x00" * 4096)

        captured_extractor_kwargs: dict = {}

        def _fake_extract_image(image_path, staging_dir=None, enable_vss=False, max_workers=1):
            captured_extractor_kwargs["image_path"] = Path(image_path)
            captured_extractor_kwargs["enable_vss"] = enable_vss
            captured_extractor_kwargs["max_workers"] = max_workers
            return {"status": "SUCCESS", "total_files_staged": 0}

        mock_carver_cls = MagicMock()
        mock_carver_cls.return_value.run.return_value = {"carved_files": 2}
        mock_be_cls = MagicMock()
        mock_be_cls.return_value.run.return_value = {"total_features": 7}

        try:
            pipeline = ProcessingPipeline(case_id=case_id, target_dir=case_dir, max_workers=6)
            with (
                patch.object(pipeline.extractor, "extract_from_image", new=_fake_extract_image),
                patch.dict(
                    "sys.modules",
                    {
                        "backend.parsers.data_carver": MagicMock(DataCarver=mock_carver_cls),
                        "backend.orchestrator.bulk_extractor_runner": MagicMock(BulkExtractorRunner=mock_be_cls),
                    },
                ),
            ):
                # Selecting ONLY fs_vss + carve_files + bulk_extractor must forward kwargs & skip standard parsers
                res = pipeline.run(
                    source_type="image",
                    source_path=str(fake_img),
                    enable_yara=False,
                    enable_stinger=False,
                    enable_ocr=False,
                    enable_hindsight=False,
                    enable_ioc=False,
                    selected_artifacts=["fs_vss", "carve_files", "bulk_extractor"],
                    max_workers=6,
                )

            assert res["status"] == "SUCCESS"
            assert captured_extractor_kwargs["enable_vss"] is True
            assert captured_extractor_kwargs["max_workers"] == 6
            assert mock_carver_cls.return_value.run.called
            assert mock_be_cls.return_value.run.called
            assert res["parser_results"] == {}
            assert res["ez_results"] == {}
        finally:
            _cleanup_registered_case(case_id)


# ===========================================================================
# (F) Iteration 2 Remediation & Live Tier-2 E2E Regression Suite
# ===========================================================================
class TestIteration2KeywordSearchAndEngineRemediation:
    def test_db_reexports_and_concurrent_keyword_scan_race_free(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        import backend.db as db_pkg

        for sym in ("clamp_threads", "validate_table_or_column_name", "register_dynamic_evtx_views"):
            assert hasattr(db_pkg, sym), f"backend.db missing re-export: {sym}"
            assert sym in db_pkg.__all__, f"backend.db.__all__ missing: {sym}"

        case_id, case_dir = isolated_case
        staged_note = case_dir / "staging" / "UserFiles" / "Alice" / "race_probe.txt"
        staged_note.parent.mkdir(parents=True, exist_ok=True)
        staged_note.write_text("Alpha RACE_FILE_TOKEN_991 Omega\n", encoding="utf-8")

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()
            cur.execute("CREATE TABLE parsed_race_probe (_row_id BIGINT, msg VARCHAR);")
            cur.executemany(
                "INSERT INTO parsed_race_probe VALUES (?, ?);",
                [(1, "First RACE_DB_TOKEN_992 row"), (2, "Second RACE_DB_TOKEN_992 row")],
            )
            cur.execute(
                """
                INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, case_sensitive, hit_count)
                VALUES
                    ('kw_race_f', 'RACE_FILE_TOKEN_991', FALSE, FALSE, FALSE, 0),
                    ('kw_race_db', 'RACE_DB_TOKEN_992', FALSE, FALSE, FALSE, 0);
                """
            )

        errors: list[Exception] = []
        totals: list[int] = []

        def _hammer_scan(_: int) -> None:
            try:
                totals.append(scan_keywords_for_case(case_id, max_workers=4))
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(_hammer_scan, range(4)))

        assert errors == []
        assert all(t == 3 for t in totals), f"Expected 3 deterministic hits per scan, got {totals}"

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            view_cnt = cur.execute("SELECT COUNT(*) FROM view_keyword_hits;").fetchone()[0]
            sum_cnt = cur.execute("SELECT SUM(hit_count) FROM case_keywords;").fetchone()[0]
            assert view_cnt == 3
            assert sum_cnt == 3

    def test_errors_replace_no_byte_fusion_whitespace_keywords_and_bomless_cyrillic_utf16le(
        self, isolated_case: Tuple[str, Path], tmp_path: Path
    ) -> None:
        case_id, case_dir = isolated_case

        # 1. Invalid UTF-8 bytes (\xa0, \xff) must be replaced with U+FFFD, NEVER stripped to fuse tokens!
        bad_bytes_file = case_dir / "staging" / "Enrichment" / "Users" / "Bob" / "corrupt.bin.txt"
        bad_bytes_file.parent.mkdir(parents=True, exist_ok=True)
        bad_bytes_file.write_bytes(b"Header Split\xa0Token middle Fuse\xffMeNow trailer")

        # 2. BOM-less non-ASCII Cyrillic UTF-16LE (zero 0x00 bytes in Cyrillic range U+0410..U+044F)
        cyrillic_file = case_dir / "staging" / "Enrichment" / "Users" / "Bob" / "cyrillic_utf16.txt"
        cyrillic_payload = "СекретБезНулей важная улика".encode("utf-16-le")
        assert b"\x00" not in cyrillic_payload[:28]
        cyrillic_file.write_bytes(cyrillic_payload)

        # 3. Seed intentional whitespace-bounded keyword ' admin ' via ProcessingPipeline._seed_keywords
        pipe = ProcessingPipeline(case_id=case_id, target_dir=case_dir, max_workers=4)
        seeded = pipe._seed_keywords([" admin ", {"keyword": "SplitToken"}, {"keyword": "FuseMeNow"}, {"keyword": "СекретБезНулей"}])
        assert seeded == 4

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            cur.execute("CREATE TABLE parsed_ws_probe (_row_id BIGINT, line VARCHAR);")
            cur.executemany(
                "INSERT INTO parsed_ws_probe VALUES (?, ?);",
                [(1, "sysadmin123"), (2, "administrator"), (3, "user admin ok")],
            )

        scan_keywords_for_case(case_id, max_workers=4)

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            by_kw = {
                str(r[0]): int(r[1])
                for r in cur.execute("SELECT keyword, hit_count FROM case_keywords;").fetchall()
            }
            assert " admin " in by_kw, f"Whitespace keyword was stripped: {by_kw}"
            assert by_kw[" admin "] == 1
            assert by_kw["SplitToken"] == 0
            assert by_kw["FuseMeNow"] == 0
            assert by_kw["СекретБезНулей"] == 1

    def test_synced_combined_granular_dedup_raw_txt_dedup_and_restore_evidence_path_subtrees(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        import hashlib

        case_id, case_dir = isolated_case

        # Stage a .txt file that is ALSO indexed in parsed_text_documents & parsed_documents_metadata -> must yield 1x hit!
        dup_body = "Unique DUP_TXT_OMEGA_4455 content\n"
        dup_sha = hashlib.sha256(dup_body.encode("utf-8")).hexdigest()
        staged_dup = case_dir / "staging" / "Documents" / "Users" / "Alice" / "notes.txt"
        staged_dup.parent.mkdir(parents=True, exist_ok=True)
        staged_dup.write_text(dup_body, encoding="utf-8")

        # Stage a .txt file containing ExactCaseSecret_Alpha once (reproducing DocumentParser title+content_preview+text_preview + metadata + raw file!)
        alpha_body = "ExactCaseSecret_Alpha\nsecond line with exactcasesecret_alpha lowercase\n"
        staged_alpha = case_dir / "staging" / "Documents" / "secret_alpha.txt"
        staged_alpha.parent.mkdir(parents=True, exist_ok=True)
        staged_alpha.write_text(alpha_body, encoding="utf-8")

        # Stage a standalone unparsed .ps1 script under staging/PowerShell -> must yield 1x hit with raw_staged_file & zero host leak!
        ps_file = case_dir / "staging" / "PowerShell" / "Alice" / "ConsoleHost_history.txt"
        ps_file.parent.mkdir(parents=True, exist_ok=True)
        ps_file.write_text("Invoke-WebRequest RAW_PS1_ONLY_8899\n", encoding="utf-8")

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # Combined + granular synced pairs
            cur.execute(
                "INSERT INTO parsed_chat_messages (app_name, sender, message_text, timestamp_utc) VALUES ('Teams', 'alice', 'CHAT_DEDUP_1122', '2025-05-01 10:00:00');"
            )
            cur.execute(
                "INSERT INTO parsed_emails (email_format, sender, subject, body_snippet, date_utc) VALUES ('PST', 'bob@corp.local', 'Subj', 'EMAIL_DEDUP_3344', '2025-05-01 11:00:00');"
            )
            cur.execute(
                "INSERT INTO parsed_cloud_files (cloud_provider, local_path, cloud_path_or_id, modified_time) VALUES ('OneDrive', 'C:\\Users\\Alice\\OneDrive\\CLOUD_DEDUP_5566.docx', 'od_item_998877', '2025-05-01 12:00:00');"
            )
            cur.execute(
                "INSERT INTO parsed_notifications (app_id, notification_type, payload, arrival_time) VALUES ('Microsoft.Outlook', 'toast', 'WPN_DEDUP_7788', '2025-05-01 13:00:00');"
            )
            cur.execute(
                "INSERT INTO parsed_wpn_notifications (app_id, notification_type, payload, arrival_time_utc) VALUES ('Microsoft.Outlook', 'toast', 'WPN_DEDUP_7788', '2025-05-01 13:00:00');"
            )
            sync_granular_artifacts(conn, case_id=case_id)

            # Index staged_dup in both parsed_text_documents and parsed_documents_metadata
            cur.execute(
                """
                INSERT INTO parsed_text_documents (file_name, file_path, sha256, title, content_preview, text_preview, modified_time)
                VALUES ('notes.txt', ?, ?, 'Unique DUP_TXT_OMEGA_4455 content', ?, ?, '2025-05-01 14:00:00');
                """,
                [str(staged_dup), dup_sha, dup_body, dup_body],
            )
            cur.execute(
                """
                INSERT INTO parsed_documents_metadata (file_name, file_path, file_type, sha256, title, modified_time)
                VALUES ('notes.txt', ?, 'txt', ?, 'Unique DUP_TXT_OMEGA_4455 content', '2025-05-01 14:00:00');
                """,
                [str(staged_dup), dup_sha],
            )

            # Live Tier-1 E2E test_f18_04 ExactCaseSecret_Alpha reproduction (/Part0/... path vs staging/Documents/... + NULL sha256 + DocumentParser title/content_preview/text_preview)
            cur.execute(
                """
                INSERT INTO parsed_text_documents (file_name, file_path, sha256, title, content_preview, text_preview, modified_time)
                VALUES ('secret_alpha.txt', '/Part0/Users/Alice/secret_alpha.txt', NULL, 'ExactCaseSecret_Alpha', ?, ?, '2025-05-01 14:05:00');
                """,
                [alpha_body, alpha_body],
            )
            cur.execute(
                """
                INSERT INTO parsed_documents_metadata (file_name, file_path, file_type, sha256, title, modified_time)
                VALUES ('secret_alpha.txt', '/Part0/Users/Alice/secret_alpha.txt', 'txt', NULL, 'ExactCaseSecret_Alpha', '2025-05-01 14:05:00');
                """
            )

            for kid, kw, cs in [
                ("k_chat", "CHAT_DEDUP_1122", False),
                ("k_mail", "EMAIL_DEDUP_3344", False),
                ("k_cloud", "CLOUD_DEDUP_5566", False),
                ("k_wpn", "WPN_DEDUP_7788", False),
                ("k_txt", "DUP_TXT_OMEGA_4455", False),
                ("k_alpha", "ExactCaseSecret_Alpha", True),
                ("k_ps", "RAW_PS1_ONLY_8899", False),
            ]:
                cur.execute(
                    "INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, case_sensitive, hit_count) VALUES (?, ?, FALSE, ?, ?, 0);",
                    [kid, kw, cs, cs],
                )

        scan_keywords_for_case(case_id, max_workers=4)

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            counts = {
                str(r[0]): int(r[1])
                for r in cur.execute("SELECT keyword_id, hit_count FROM case_keywords;").fetchall()
            }
            assert counts["k_chat"] == 1
            assert counts["k_mail"] == 1
            assert counts["k_cloud"] == 1
            assert counts["k_wpn"] == 1
            assert counts["k_txt"] == 1
            assert counts["k_alpha"] == 1
            assert counts["k_ps"] == 1

            alpha_view_cnt = cur.execute(
                "SELECT COUNT(*) FROM view_keyword_hits WHERE keyword_id = 'k_alpha';"
            ).fetchone()[0]
            assert alpha_view_cnt == 1

            ps_row = cur.execute(
                "SELECT source_table, source_file FROM view_keyword_hits WHERE keyword_id = 'k_ps';"
            ).fetchone()
            assert ps_row is not None
            assert ps_row[0] == "raw_staged_file"
            assert ps_row[1] == r"C:\Users\Alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            assert str(case_dir).lower() not in str(ps_row[1]).lower()

        # Verify all EvidenceExtractor subtrees + catch-all + vfs_lookup never leak host case_dir
        vfs_map = {"staging\\documents\\flat_share.txt": r"D:\ForensicShare\flat_share.txt"}
        subtree_expectations = [
            (case_dir / "staging" / "WebLogs" / "W3SVC1" / "u_ex.log", r"C:\Windows\System32\LogFiles\W3SVC1\u_ex.log"),
            (case_dir / "staging" / "SUM" / "Current.mdb", r"C:\Windows\System32\LogFiles\SUM\Current.mdb"),
            (case_dir / "staging" / "Tasks" / "Updater", r"C:\Windows\System32\Tasks\Updater"),
            (case_dir / "staging" / "USB" / "setupapi.dev.log", r"C:\Windows\inf\setupapi.dev.log"),
            (case_dir / "staging" / "WER" / "System" / "AppCrash" / "Report.wer", r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash\Report.wer"),
            (case_dir / "staging" / "WLAN" / "Interfaces" / "prof.xml", r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\prof.xml"),
            (case_dir / "staging" / "RMM" / "AnyDesk" / "ad.trace", r"[STAGED] RMM\AnyDesk\ad.trace"),
            (case_dir / "staging" / "ZoneIdentifier" / "payload.exe.zone", r"[STAGED] ZoneIdentifier\payload.exe.zone"),
            (case_dir / "staging" / "CustomSubtree" / "artifact.dat", r"[STAGED] CustomSubtree\artifact.dat"),
            (case_dir / "staging" / "Documents" / "flat_share.txt", r"D:\ForensicShare\flat_share.txt"),
        ]
        for host_p, expected_forensic in subtree_expectations:
            restored = restore_evidence_path(str(host_p), case_dir=case_dir, vfs_lookup=vfs_map)
            assert restored == expected_forensic
            assert str(case_dir).lower() not in restored.lower()


class TestIteration2SchemaPipelineNormalizerAndLiveE2EAddendum:
    def test_contract2_17col_vfs_files_view_docs_txt_malware_view_evtx_payloads_and_wildcard_escape(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        from backend.db.schema import register_evtx_granular_views

        case_id, _ = isolated_case
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # 1. Verify vfs_partitions.description, raw_evtx PayloadData2..6 + Payload, Contract 2 columns
            vp_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE vfs_partitions;").fetchall()}
            assert {
                "part_index",
                "label",
                "fs_type",
                "offset_bytes",
                "size_bytes",
                "volume_serial",
                "is_boot",
                "description",
            }.issubset(vp_cols)

            evtx_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE raw_evtx;").fetchall()}
            assert {"payloaddata1", "payloaddata2", "payloaddata3", "payloaddata4", "payloaddata5", "payloaddata6", "payload"}.issubset(evtx_cols)

            # 2. Replace vfs_files with strict 17-column Contract 2 schema ONLY (no extension/is_directory/created_utc)
            cur.execute("DROP VIEW IF EXISTS view_docs_txt;")
            cur.execute("DROP TABLE IF EXISTS vfs_files;")
            cur.execute(
                """
                CREATE TABLE vfs_files (
                    vfs_path VARCHAR,
                    parent_path VARCHAR,
                    file_name VARCHAR,
                    part_index INTEGER,
                    inode BIGINT,
                    is_dir BOOLEAN,
                    is_deleted BOOLEAN,
                    size_bytes BIGINT,
                    si_created TIMESTAMP,
                    si_modified TIMESTAMP,
                    si_accessed TIMESTAMP,
                    si_changed TIMESTAMP,
                    fn_created TIMESTAMP,
                    fn_modified TIMESTAMP,
                    fn_accessed TIMESTAMP,
                    fn_changed TIMESTAMP,
                    staged_rel_path VARCHAR
                );
                """
            )
            cur.execute(
                """
                INSERT INTO vfs_files (vfs_path, parent_path, file_name, part_index, inode, is_dir, is_deleted, size_bytes, si_created, si_modified)
                VALUES
                    ('/Users/Alice/readme.txt', '/Users/Alice', 'readme.txt', 0, 10, FALSE, FALSE, 512, '2023-03-01 00:00:00', '2023-03-02 00:00:00'),
                    ('/Users/Alice/deploy.ps1', '/Users/Alice', 'deploy.ps1', 0, 11, FALSE, FALSE, 1024, '2023-03-01 00:00:00', '2023-03-02 00:00:00');
                """
            )

            # 3. Populate BOTH artifact_yara_hits AND artifact_stinger_hits
            cur.execute(
                """
                INSERT INTO artifact_yara_hits (_row_id, file_path, file_name, sha256, rule_name, rule_namespace, severity, pattern_identifier)
                VALUES (1, 'C:\\Temp\\a.exe', 'a.exe', 'aaaa', 'Mal_Beacon', 'apt', 'CRITICAL', '$s1');
                """
            )
            cur.execute(
                """
                INSERT INTO artifact_stinger_hits (_row_id, file_path, file_name, sha256, malware_name, detection_type, action_taken)
                VALUES (1, 'C:\\Temp\\b.exe', 'b.exe', 'bbbb', 'Trojan-Downloader', 'Trojan', 'Reported');
                """
            )

            # 4. Populate raw_evtx with '%4' literal filename vs 'X4' false-wildcard filename
            cur.execute(
                """
                INSERT INTO raw_evtx (_row_id, EventId, Channel, TimeCreated, PayloadData1, SourceFile)
                VALUES
                    (1, 4104, 'Microsoft-Windows-PowerShell/Operational', '2024-04-01 10:00:00', 'Invoke-Test', 'C:\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx'),
                    (2, 4104, 'Microsoft-Windows-PowerShellX4Operational', '2024-04-01 10:01:00', 'Rogue-Wildcard', 'C:\\Logs\\Microsoft-Windows-PowerShellX4Operational.evtx');
                """
            )

            sync_artifact_registry_counts(conn, case_id=case_id)
            evtx_views = register_evtx_granular_views(conn, case_id=case_id)

            # Verify view_docs_txt works on pure 17-column Contract 2 vfs_files
            docs_txt_rows = cur.execute("SELECT file_name, source_evidence FROM view_docs_txt ORDER BY file_name;").fetchall()
            assert docs_txt_rows == [("deploy.ps1", "vfs_files"), ("readme.txt", "vfs_files")]
            reg_docs_cnt = cur.execute("SELECT row_count FROM artifact_registry WHERE artifact_id = 'docs_txt';").fetchone()[0]
            assert reg_docs_cnt == 2

            # Verify 14-column view_all_malware_detections with unique _row_id and engine fallback
            mal_cols = [str(r[0]) for r in cur.execute("DESCRIBE view_all_malware_detections;").fetchall()]
            assert len(mal_cols) == 14
            assert {"_row_id", "threat_name", "severity", "engine"}.issubset(set(mal_cols))
            mal_rows = cur.execute("SELECT _row_id, engine, threat_name, severity FROM view_all_malware_detections ORDER BY _row_id;").fetchall()
            assert len(mal_rows) == 2
            assert len({r[0] for r in mal_rows}) == 2
            assert any(r[1] == "Trellix Stinger" and r[2] == "Trojan-Downloader" for r in mal_rows)

            # Verify '%4' EVTX view escaped '%' and did NOT match 'X4'
            pct4_meta = [m for m in evtx_views if "PowerShell/Operational" in m["display_name"]]
            assert len(pct4_meta) == 1
            pct4_view_cnt = cur.execute(f'SELECT COUNT(*) FROM "{pct4_meta[0]["table_name"]}";').fetchone()[0]
            assert pct4_view_cnt == 1

    def test_pipeline_enrichment_boolean_gating_zero_counts_vss_forwarding_and_hindsight_empty_ts(
        self, tmp_path: Path
    ) -> None:
        from backend.orchestrator.pipeline import _clean_hindsight_timestamp, _extract_row_count

        assert _extract_row_count({"carved_count": 0}) == 0
        assert _extract_row_count({"carved_count": 3}) == 3
        assert _extract_row_count({"features_ingested": 0}) == 0
        assert _clean_hindsight_timestamp("") is None
        assert _clean_hindsight_timestamp("1970-01-01T00:00:00Z") is None
        assert _clean_hindsight_timestamp("2024-08-15T12:30:00Z") is not None

        ev_dir = (tmp_path / "src_ev").resolve()
        ev_dir.mkdir(parents=True, exist_ok=True)

        # Case 1: ProcessWizard selection + enable_yara=True, enable_stinger=True, enable_ocr=False -> runs Stinger, skips OCR
        cid1 = f"m4a_gate1_{uuid.uuid4().hex[:8]}"
        cdir1 = (tmp_path / cid1).resolve()
        enr_calls: list[dict] = []

        class _FakeEnricherInstance:
            def run_full_enrichment(self, enable_yara=True, enable_stinger=True, enable_ocr=True, enable_ioc=True, max_workers=4):
                enr_calls.append(
                    {
                        "enable_yara": enable_yara,
                        "enable_stinger": enable_stinger,
                        "enable_ocr": enable_ocr,
                        "enable_ioc": enable_ioc,
                        "max_workers": max_workers,
                    }
                )
                return {"files_scanned": 2, "yara_hits": 1, "stinger_hits": 1, "ocr_results": 0}

        vss_seen: list[bool] = []

        def _fake_extract_dir(source_dir, staging_dir=None, enable_vss=False, max_workers=1):
            vss_seen.append(bool(enable_vss))
            return {"status": "SUCCESS", "total_files_staged": 0}

        try:
            p1 = ProcessingPipeline(case_id=cid1, target_dir=cdir1, max_workers=4)
            p1.enricher = _FakeEnricherInstance()
            with patch.object(p1.extractor, "extract_from_directory", new=_fake_extract_dir):
                p1.run(
                    source_type="folder",
                    source_path=str(ev_dir),
                    enable_yara=True,
                    enable_stinger=True,
                    enable_ocr=False,
                    enable_vss=True,
                    selected_artifacts=["malware_yara", "media_ocr"],  # ProcessWizard omits malware_stinger ID
                )
                assert vss_seen == [True]
                assert len(enr_calls) == 1
                assert enr_calls[0]["enable_yara"] is True
                assert enr_calls[0]["enable_stinger"] is True
                assert enr_calls[0]["enable_ocr"] is False

                # Case 2: Explicit enable_*=False ALWAYS disables enrichment even if selected_artifacts names them
                enr_calls.clear()
                p1.run(
                    source_type="folder",
                    source_path=str(ev_dir),
                    enable_yara=False,
                    enable_stinger=False,
                    enable_ocr=False,
                    selected_artifacts=["malware_yara", "malware_stinger", "media_ocr"],
                )
                assert enr_calls == []

                # Case 3: Narrow non-enrichment selection ['docs_txt'] skips Stinger even when enable_stinger=True
                enr_calls.clear()
                p1.run(
                    source_type="folder",
                    source_path=str(ev_dir),
                    enable_yara=False,
                    enable_stinger=True,
                    enable_ocr=False,
                    selected_artifacts=["docs_txt"],
                )
                assert enr_calls == []
        finally:
            _cleanup_registered_case(cid1)

    def test_normalizer_canonical_macb_coalesce_wpn_carved_txt_dedup_email_hindsight_and_ntfs_ctime_guard(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        from datetime import datetime, timezone

        case_id, _ = isolated_case
        wallclock_utc_now = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # 1. Canonical MACB verification across vfs_files (with raw_mft empty), VSS, Carved, AXIOM tables
            cur.execute(
                """
                INSERT INTO vfs_files (
                    file_name, parent_path, vfs_path, size_bytes, is_dir, is_deleted,
                    si_created, si_modified, si_accessed, si_changed
                ) VALUES
                (
                    'macb_probe.dll', '\\Windows\\System32', 'C:\\Windows\\System32\\macb_probe.dll', 4096, FALSE, FALSE,
                    '2021-06-10 01:00:00', '2021-06-10 02:00:00', '2021-06-10 03:00:00', '2021-06-10 04:00:00'
                ),
                (
                    'staged_copy_leak.docx', '\\Users\\Alice', 'C:\\Users\\Alice\\staged_copy_leak.docx', 2048, FALSE, FALSE,
                    ?, '2021-06-14 08:00:00', '2021-06-14 08:00:00', ?
                ),
                (
                    'StagedFolderNow', '\\Users', 'C:\\Users\\StagedFolderNow', 0, TRUE, FALSE,
                    ?, ?, ?, ?
                );
                """,
                [
                    wallclock_utc_now,
                    wallclock_utc_now,
                    wallclock_utc_now,
                    wallclock_utc_now,
                    wallclock_utc_now,
                    wallclock_utc_now,
                ],
            )

            # 2. Contract 2 parsed_carved_files (carve_id + carved_rel_path, no file_name/carved_path)
            cur.execute(
                """
                INSERT INTO parsed_carved_files (carve_id, file_type, extension, size_bytes, sha256, carved_rel_path, timestamp_utc)
                VALUES ('carve_0007', 'PDF', '.pdf', 8192, 'cafebabe1234', 'carved/pdf/carve_0007.pdf', '2021-06-11 05:00:00');
                """
            )

            # 3. Minimal 4-column parsed_wpn_notifications WITHOUT header / notification_type
            cur.execute("DROP TABLE IF EXISTS parsed_wpn_notifications;")
            cur.execute(
                """
                CREATE TABLE parsed_wpn_notifications (
                    _row_id BIGINT,
                    app_id VARCHAR,
                    body VARCHAR,
                    timestamp_utc TIMESTAMP
                );
                """
            )
            cur.execute(
                "INSERT INTO parsed_wpn_notifications VALUES (1, 'Microsoft.Teams', 'Minimal WPN Body', '2021-06-12 06:00:00');"
            )

            # 4. Overlap between parsed_documents_metadata & parsed_text_documents + wall-clock created_time leak
            cur.execute(
                """
                INSERT INTO parsed_documents_metadata (file_name, file_path, file_type, sha256, created_time, modified_time)
                VALUES
                    ('shared_notes.txt', 'C:\\Users\\Alice\\shared_notes.txt', 'txt', 'sha_shared_1', '2021-06-13 07:00:00', '2021-06-13 08:00:00'),
                    ('wallclock_doc.pdf', 'C:\\Users\\Alice\\wallclock_doc.pdf', 'pdf', 'sha_pdf_2', ?, '2021-06-14 09:00:00');
                """,
                [wallclock_utc_now],
            )
            cur.execute(
                """
                INSERT INTO parsed_text_documents (file_name, file_path, sha256, created_time, modified_time, content_preview)
                VALUES
                    ('shared_notes.txt', 'C:\\Users\\Alice\\shared_notes.txt', 'sha_shared_1', '2021-06-13 07:00:00', '2021-06-13 08:00:00', 'duplicate text'),
                    ('standalone_cfg.ini', 'C:\\Users\\Alice\\standalone_cfg.ini', 'sha_ini_3', ?, '2021-06-14 10:00:00', 'standalone config');
                """,
                [wallclock_utc_now],
            )

            # 5. parsed_chrome_session with last_active_time + multi-col COALESCE when both visit_time & visit_time_utc exist
            cur.execute(
                """
                INSERT INTO parsed_chrome_session (url, title, last_active_time, profile)
                VALUES ('https://intranet.corp.internal/home', 'Intranet', '2021-06-14 10:30:00', 'Default');
                """
            )
            cur.execute("ALTER TABLE parsed_chrome_history ADD COLUMN IF NOT EXISTS visit_time_utc TIMESTAMP;")
            cur.execute(
                """
                INSERT INTO parsed_chrome_history (browser, url, title, visit_time, visit_time_utc, visit_count)
                VALUES ('Chrome', 'https://portal.corp.internal/dashboard', 'Dashboard', NULL, '2021-06-14 11:00:00', 1);
                """
            )

            # 6. raw_hindsight: 1 duplicate matching parsed_chrome_history (within <=2s) + 1 unique Hindsight cache entry
            cur.execute(
                """
                INSERT INTO raw_hindsight (browser, record_type, url, title, timestamp_utc, visit_time_utc, source_path)
                VALUES
                    ('Chrome', 'chrome:history:page_visited', 'https://portal.corp.internal/dashboard', 'Dashboard', NULL, '2021-06-14 11:00:01', 'C:\\History'),
                    ('Chrome', 'cache', 'https://cdn.corp.internal/unique_bundle.js', 'Bundle', NULL, '2021-06-14 11:05:00', 'C:\\Cache');
                """
            )

            # 7. Canonical 'EMAIL & CALENDAR' category in parsed_emails + AXIOM MACB tables
            cur.execute(
                """
                INSERT INTO parsed_emails (email_format, sender, recipients, subject, date_utc)
                VALUES ('EML', 'cfo@corp.internal', 'ceo@corp.internal', 'Q2 Report', '2021-06-14 12:00:00');
                """
            )
            cur.execute(
                "INSERT INTO parsed_windows_services (service_name, image_path, last_write_utc) VALUES ('EvilSvc', 'C:\\Temp\\svc.exe', '2021-06-14 12:30:00');"
            )
            cur.execute(
                "INSERT INTO parsed_user_accounts (username, created_utc) VALUES ('svc_acct', '2021-06-14 12:15:00');"
            )

        TimelineNormalizer(case_id).normalize_all()

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()

            # A. Canonical DFIR MACB: Created/Born == '...B', Entry/Registry Changed == '..C.'
            vfs_macb = {
                str(r[0]): str(r[1])
                for r in cur.execute(
                    "SELECT timestamp_type, macb FROM master_timeline WHERE primary_entity = 'macb_probe.dll';"
                ).fetchall()
            }
            assert vfs_macb["$SI Created [...B]"] == "...B"
            assert vfs_macb["$SI Entry Modified [..C.]"] == "..C."
            assert vfs_macb["$SI Modified [M...]"] == "M..."
            assert vfs_macb["$SI Accessed [.A..]"] == ".A.."

            carve_macb = cur.execute(
                "SELECT macb, primary_entity FROM master_timeline WHERE source_table = 'parsed_carved_files';"
            ).fetchone()
            assert carve_macb == ("...B", "carve_0007")
            carve_ents = {
                str(r[0]) for r in cur.execute("SELECT entity_type FROM entity_connections WHERE source_table = 'parsed_carved_files';").fetchall()
            }
            assert {"FILE_NAME", "FILE_PATH", "SHA256"}.issubset(carve_ents)

            svc_macb = cur.execute(
                "SELECT macb FROM master_timeline WHERE source_table = 'parsed_windows_services';"
            ).fetchone()[0]
            assert svc_macb == "..C."
            usr_macb = cur.execute(
                "SELECT macb FROM master_timeline WHERE source_table = 'parsed_user_accounts';"
            ).fetchone()[0]
            assert usr_macb == "...B"
            doc_created_macb = cur.execute(
                "SELECT macb FROM master_timeline WHERE timestamp_type = 'Document Created' AND primary_entity = 'shared_notes.txt';"
            ).fetchone()[0]
            assert doc_created_macb == "...B"

            # B. Minimal parsed_wpn_notifications normalized without BinderException
            wpn_cnt = cur.execute("SELECT COUNT(*) FROM master_timeline WHERE source_table = 'parsed_wpn_notifications';").fetchone()[0]
            assert wpn_cnt == 1

            # C. parsed_chrome_session.last_active_time normalized
            sess_cnt = cur.execute("SELECT COUNT(*) FROM master_timeline WHERE source_table = 'parsed_chrome_session';").fetchone()[0]
            assert sess_cnt == 1

            # D. 1x .txt deduplication between parsed_documents_metadata & parsed_text_documents
            shared_txt_tl = cur.execute(
                "SELECT source_table, COUNT(*) FROM master_timeline WHERE primary_entity = 'shared_notes.txt' GROUP BY source_table;"
            ).fetchall()
            assert shared_txt_tl == [("parsed_documents_metadata", 2)]  # Created + Modified from metadata ONLY, 0 from text_documents!
            standalone_ini_cnt = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE primary_entity = 'standalone_cfg.ini';"
            ).fetchone()[0]
            assert standalone_ini_cnt == 1

            # E. Addendum #1: ZERO bare 'EMAIL' anywhere; strictly canonical 'EMAIL & CALENDAR'
            for tbl in ("artifact_registry", "master_timeline", "entity_connections"):
                bare_email = cur.execute(f"SELECT COUNT(*) FROM {tbl} WHERE category = 'EMAIL';").fetchone()[0]
                assert bare_email == 0, f"{tbl} still contains non-canonical 'EMAIL' category!"
            email_cal_tl = cur.execute("SELECT COUNT(*) FROM master_timeline WHERE category = 'EMAIL & CALENDAR';").fetchone()[0]
            assert email_cal_tl == 1

            # F. Addendum #2: 1x Chromium History + Hindsight deduplication (<=2s duplicate suppressed, unique cache row kept!)
            dash_rows = cur.execute(
                "SELECT source_table FROM master_timeline WHERE primary_entity = 'https://portal.corp.internal/dashboard' OR summary LIKE '%portal.corp.internal/dashboard%';"
            ).fetchall()
            assert dash_rows == [("parsed_chrome_history",)]
            uniq_hs = cur.execute(
                "SELECT COUNT(*) FROM master_timeline WHERE source_table = 'raw_hindsight' AND primary_entity = 'https://cdn.corp.internal/unique_bundle.js';"
            ).fetchone()[0]
            assert uniq_hs == 1

            # G. Addendum #3: Zero wall-clock 2026 NTFS staging st_ctime / mkdir leaks on historical 2021 case!
            max_ts = cur.execute("SELECT MAX(timestamp_utc) FROM master_timeline;").fetchone()[0]
            assert max_ts is not None and max_ts.year == 2021, f"Wall-clock staging timestamp leaked into 2021 timeline: max_ts={max_ts}"



# ===========================================================================
# (G) Iteration 3 Surgical Remediation Regression Suite (Challenges 1-4)
# ===========================================================================
class TestIteration3SurgicalRemediation:
    def test_vss_and_multiuser_same_basename_preserved_while_duplicate_staged_copies_deduped(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        import hashlib

        case_id, case_dir = isolated_case

        # 1. Three distinct evidence files sharing basename 'notes.txt':
        #    - Active C:\Users\Alice\Desktop\notes.txt (in parsed_text_documents + staged)
        #    - [VSS#1] C:\Users\Alice\Desktop\notes.txt (historical VSS snapshot with different SHA-256)
        #    - C:\Users\Bob\Desktop\notes.txt (distinct user path)
        alice_txt = "Active Alice NOTE_BASENAME_PROBE_7001 entry\n"
        vss_txt = "Deleted shadow NOTE_BASENAME_PROBE_7001 secret from yesterday\n"
        bob_txt = "Bob independent NOTE_BASENAME_PROBE_7001 workspace file\n"

        p_alice = case_dir / "staging" / "UserFiles" / "Alice" / "Desktop" / "notes.txt"
        p_vss1 = case_dir / "staging" / "VSS" / "VSS_1" / "Users" / "Alice" / "Desktop" / "notes.txt"
        p_bob = case_dir / "staging" / "UserFiles" / "Bob" / "Desktop" / "notes.txt"
        for p, body in ((p_alice, alice_txt), (p_vss1, vss_txt), (p_bob, bob_txt)):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        alice_sha = hashlib.sha256(p_alice.read_bytes()).hexdigest()

        # 2. ExactCaseSecret_Alpha duplicated across parsed_text_documents + parsed_documents_metadata
        #    + staging/Documents/secret_alpha.txt + staging/Enrichment/Part1_NTFS/Users/Alice/secret_alpha.txt
        alpha_txt = "ExactCaseSecret_Alpha\nfollow-up line\n"
        p_alpha_doc = case_dir / "staging" / "Documents" / "secret_alpha.txt"
        p_alpha_enr = case_dir / "staging" / "Enrichment" / "Part1_NTFS" / "Users" / "Alice" / "secret_alpha.txt"
        for p in (p_alpha_doc, p_alpha_enr):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(alpha_txt, encoding="utf-8")
        alpha_sha = hashlib.sha256(p_alpha_doc.read_bytes()).hexdigest()

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO parsed_text_documents (file_name, file_path, sha256, title, content_preview, text_preview, modified_time)
                VALUES
                    ('notes.txt', 'C:\\Users\\Alice\\Desktop\\notes.txt', ?, 'Active Alice', ?, ?, '2025-06-01 09:00:00'),
                    ('secret_alpha.txt', 'C:\\Users\\Alice\\secret_alpha.txt', ?, 'ExactCaseSecret_Alpha', ?, ?, '2025-06-01 09:05:00');
                """,
                [alice_sha, alice_txt, alice_txt, alpha_sha, alpha_txt, alpha_txt],
            )
            cur.execute(
                """
                INSERT INTO parsed_documents_metadata (file_name, file_path, file_type, sha256, title, modified_time)
                VALUES ('secret_alpha.txt', 'C:\\Users\\Alice\\secret_alpha.txt', 'txt', ?, 'ExactCaseSecret_Alpha', '2025-06-01 09:05:00');
                """,
                [alpha_sha],
            )
            cur.execute(
                """
                INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, case_sensitive, hit_count)
                VALUES
                    ('kw_notes_3x', 'NOTE_BASENAME_PROBE_7001', FALSE, FALSE, FALSE, 0),
                    ('kw_alpha_1x', 'ExactCaseSecret_Alpha', FALSE, TRUE, TRUE, 0);
                """
            )

        scan_keywords_for_case(case_id, max_workers=4)

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            notes_srcs = sorted(
                str(r[0])
                for r in cur.execute(
                    "SELECT source_file FROM view_keyword_hits WHERE keyword_id = 'kw_notes_3x';"
                ).fetchall()
            )
            assert notes_srcs == sorted(
                [
                    r"C:\Users\Alice\Desktop\notes.txt",
                    r"[VSS#1] C:\Users\Alice\Desktop\notes.txt",
                    r"C:\Users\Bob\Desktop\notes.txt",
                ]
            )
            notes_hc = cur.execute("SELECT hit_count FROM case_keywords WHERE keyword_id = 'kw_notes_3x';").fetchone()[0]
            assert notes_hc == 3

            alpha_view_cnt = cur.execute(
                "SELECT COUNT(*) FROM view_keyword_hits WHERE keyword_id = 'kw_alpha_1x';"
            ).fetchone()[0]
            alpha_hc = cur.execute("SELECT hit_count FROM case_keywords WHERE keyword_id = 'kw_alpha_1x';").fetchone()[0]
            assert alpha_view_cnt == 1
            assert alpha_hc == 1

    def test_combined_dedup_demorgan_or_and_exact_schema_columns_zero_false_negatives(
        self, isolated_case: Tuple[str, Path]
    ) -> None:
        case_id, _ = isolated_case

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id)
            cur = conn.cursor()

            # 1. Chat: Alice has a synced Teams message AND a separate 'Chat' SQLite message + another Teams message
            cur.execute(
                """
                INSERT INTO parsed_chat_messages (_row_id, app_name, sender, message_text, timestamp_utc)
                VALUES
                    (1, 'Teams', 'alice@corp.local', 'SYNCED_TEAMS_TOKEN_801', '2025-06-02 10:00:00'),
                    (2, 'Chat', 'alice@corp.local', 'CROSS_APP_CHAT_TOKEN_802', '2025-06-02 10:05:00'),
                    (3, 'Teams', 'alice@corp.local', 'UNSYNCED_TEAMS_TOKEN_803', '2025-06-02 10:10:00');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_teams_messages (_row_id, app_name, sender, message_text, timestamp_utc)
                VALUES (1, 'Teams', 'alice@corp.local', 'SYNCED_TEAMS_TOKEN_801', '2025-06-02 10:00:00');
                """
            )

            # 2. Email: PST synced email + reply/archive email with SAME (sender, subject) and DIFFERENT body_snippet
            cur.execute(
                """
                INSERT INTO parsed_emails (_row_id, email_format, sender, subject, body_snippet, date_utc)
                VALUES
                    (1, 'PST', 'cfo@corp.local', 'Wire Approval', 'Initial request MAIL_SYNCED_804', '2025-06-02 11:00:00'),
                    (2, 'PST', 'cfo@corp.local', 'Wire Approval', 'Follow-up urgent MAIL_DIFF_BODY_805', '2025-06-02 11:15:00'),
                    (3, 'MSG_ARCHIVE', 'cfo@corp.local', 'Wire Approval', 'Archived copy MAIL_CUSTOM_FMT_806', '2025-06-02 11:30:00');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_outlook_emails (_row_id, email_format, sender, subject, body_snippet, date_utc)
                VALUES (1, 'PST', 'cfo@corp.local', 'Wire Approval', 'Initial request MAIL_SYNCED_804', '2025-06-02 11:00:00');
                """
            )

            # 3. Cloud: synced OneDrive row + distinct Nextcloud row in parsed_cloud_files
            cur.execute(
                """
                INSERT INTO parsed_cloud_files (_row_id, cloud_provider, local_path, cloud_path_or_id, modified_time)
                VALUES
                    (1, 'OneDrive', 'C:\\Users\\Alice\\OneDrive\\CLOUD_SYNCED_807.xlsx', 'od_1', '2025-06-02 12:00:00'),
                    (2, 'Nextcloud', 'C:\\Users\\Alice\\Nextcloud\\CLOUD_OTHER_808.xlsx', 'nc_2', '2025-06-02 12:05:00');
                """
            )
            cur.execute(
                """
                INSERT INTO parsed_onedrive_files (_row_id, cloud_provider, local_path, cloud_path_or_id, modified_time)
                VALUES (1, 'OneDrive', 'C:\\Users\\Alice\\OneDrive\\CLOUD_SYNCED_807.xlsx', 'od_1', '2025-06-02 12:00:00');
                """
            )

            for kid, kw in (
                ("k_801", "SYNCED_TEAMS_TOKEN_801"),
                ("k_802", "CROSS_APP_CHAT_TOKEN_802"),
                ("k_803", "UNSYNCED_TEAMS_TOKEN_803"),
                ("k_804", "MAIL_SYNCED_804"),
                ("k_805", "MAIL_DIFF_BODY_805"),
                ("k_806", "MAIL_CUSTOM_FMT_806"),
                ("k_807", "CLOUD_SYNCED_807"),
                ("k_808", "CLOUD_OTHER_808"),
            ):
                cur.execute(
                    "INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, case_sensitive, hit_count) VALUES (?, ?, FALSE, FALSE, FALSE, 0);",
                    [kid, kw],
                )

        scan_keywords_for_case(case_id, max_workers=4)

        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            got = {
                str(r[0]): int(r[1])
                for r in cur.execute("SELECT keyword_id, hit_count FROM case_keywords;").fetchall()
            }
            for kid in ("k_801", "k_802", "k_803", "k_804", "k_805", "k_806", "k_807", "k_808"):
                assert got[kid] == 1, f"Expected exact 1x hit for {kid}, got {got[kid]}"

    def test_enrichment_part_fs_label_stripping_and_core_schema_superset_columns(
        self, isolated_case: Tuple[str, Path], tmp_path: Path
    ) -> None:
        import duckdb

        case_id, case_dir = isolated_case

        # 1. Verify <PartN>_<FSType> and <VolN>_<FSType> partition labels strip cleanly
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "Enrichment" / "Part1_NTFS" / "Users" / "Alice" / "long_report.txt"),
                case_dir=case_dir,
            )
            == r"C:\Users\Alice\long_report.txt"
        )
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "Enrichment" / "Vol0_FAT32" / "Users" / "Alice" / "a.txt"),
                case_dir=case_dir,
            )
            == r"C:\Users\Alice\a.txt"
        )
        assert (
            restore_evidence_path(
                str(case_dir / "staging" / "VSS" / "VSS_2" / "Enrichment" / "Part0_exFAT" / "Users" / "Bob" / "b.txt"),
                case_dir=case_dir,
            )
            == r"[VSS#2] C:\Users\Bob\b.txt"
        )

        # 2. Verify brand-new init_case_db() exposes all superset columns with zero BinderExceptions
        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id).cursor()
            notif_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE parsed_notifications;").fetchall()}
            assert {
                "_row_id",
                "notification_id",
                "app_id",
                "notification_type",
                "payload",
                "arrival_time",
                "expiry_time",
                "timestamp_utc",
                "title",
                "body",
                "header",
                "action_url",
                "source_path",
                "source_file",
            }.issubset(notif_cols)

            txt_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE parsed_text_documents;").fetchall()}
            assert {
                "char_count",
                "last_modified_by",
                "embedded_links",
                "zone_id",
                "zone_host_url",
                "zone_referrer_url",
                "host_url",
                "referrer_url",
                "content_preview",
                "text_preview",
                "extension",
            }.issubset(txt_cols)

            fe_cols = {str(r[0]).lower() for r in cur.execute("DESCRIBE file_enrichment;").fetchall()}
            assert {
                "_row_id",
                "enrichment_id",
                "md5",
                "sha256",
                "shannon_entropy",
                "is_pe",
                "pe_imphash",
                "pe_compile_time",
                "pe_sections_info",
                "is_high_entropy",
                "yara_hit_count",
                "ioc_hit_count",
                "yara_rules_matched",
                "ocr_extracted_text",
            }.issubset(fe_cols)

        # 3. Verify legacy DB upgrade path via init_case_db() migration_statements
        legacy_cid = f"m4a_leg_mig_{uuid.uuid4().hex[:8]}"
        legacy_dir = (tmp_path / legacy_cid).resolve()
        legacy_dir.mkdir(parents=True, exist_ok=True)
        register_case_dir(legacy_cid, legacy_dir)
        try:
            legacy_db = legacy_dir / "case.duckdb"
            raw_conn = duckdb.connect(str(legacy_db))
            raw_conn.execute("CREATE TABLE parsed_notifications (_row_id BIGINT, app_id VARCHAR, payload VARCHAR);")
            raw_conn.execute("CREATE TABLE parsed_text_documents (_row_id BIGINT, file_name VARCHAR, file_path VARCHAR, content_preview VARCHAR);")
            raw_conn.execute("CREATE TABLE file_enrichment (_row_id BIGINT, file_path VARCHAR NOT NULL, file_name VARCHAR NOT NULL, sha256 VARCHAR);")
            raw_conn.close()

            init_case_db(legacy_cid)
            with DuckDBManager.get_lock(legacy_cid):
                lcur = DuckDBManager.get_connection(legacy_cid).cursor()
                assert "timestamp_utc" in {str(r[0]).lower() for r in lcur.execute("DESCRIBE parsed_notifications;").fetchall()}
                assert "char_count" in {str(r[0]).lower() for r in lcur.execute("DESCRIBE parsed_text_documents;").fetchall()}
                assert "shannon_entropy" in {str(r[0]).lower() for r in lcur.execute("DESCRIBE file_enrichment;").fetchall()}
                lcur.execute("SELECT COUNT(*) FROM view_docs_txt;").fetchone()
        finally:
            _cleanup_registered_case(legacy_cid)
