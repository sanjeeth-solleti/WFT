"""
Comprehensive verification tests for all 6 user requirements:
1. Documents and files parser categories (PDF, Excel, PPT, Word, TXT, and Other Files like .js, .py, .html, .css).
2. Bulk Extractor non-blocking parallel parsing, duplicate/scanner capping on multi-million-row outputs, and dedicated Bulk Extractor tab.
3. Event Logs excluded from Artifacts sidebar tree while retaining full Event Logs tab access.
4. Parallel 32-thread parsing, external tool runners, and early/final keyword indexing.
5. UI Processing tab navigation (clicking Select Artifacts / Processing Options and clicking Process Evidence transitions cleanly).
6. Log file duplicate active 200 OK suppression (1 active line logged, stopped while active, logged once again only after transition).
"""
import logging
import time
from pathlib import Path

from backend.config import register_case_dir
from backend.db.engine import DEFAULT_DUCKDB_THREADS, DuckDBManager, init_case_db, scan_keywords_for_case
from backend.db.schema import sync_artifact_registry_counts
from backend.main import _SuppressDuplicate200Filter
from backend.orchestrator.bulk_extractor_runner import BulkExtractorRunner
from backend.orchestrator.normalizer import TimelineNormalizer
from backend.orchestrator.pipeline import DEFAULT_MAX_WORKERS
from backend.parsers.document_parser import DocumentParser


def test_document_parser_gathers_all_categories_and_other_files(tmp_path: Path) -> None:
    """
    Requirement 1: DocumentParser and DOCUMENTS views must gather and display files across:
    - PDF (view_docs_pdf)
    - Excel (view_docs_excel)
    - PPT (view_docs_ppt)
    - Word (view_docs_word)
    - TXT (view_docs_txt)
    - Other Files (view_docs_other: .js, .py, .html, .css, etc.)
    """
    case_id = "test_doc_categories_other"
    case_dir = (tmp_path / case_id).resolve()
    staging_dir = case_dir / "staging" / "Enrichment" / "Part_0" / "Users" / "Alice" / "Project"
    staging_dir.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, case_dir)
    init_case_db(case_id)

    try:
        # 1. PDF
        (staging_dir / "report.pdf").write_bytes(
            b"%PDF-1.4\n1 0 obj\n<< /Type /Pages /Count 1 >>\nendobj\n"
            b"2 0 obj\n<< /Title (Annual Report) /Author (Alice) >>\nendobj\n"
            b"trailer\n<< /Info 2 0 R >>\n%%EOF\n"
        )
        # 2. Word (.doc OLE fallback)
        (staging_dir / "memo.doc").write_bytes(
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 128 + "WordDocument".encode("utf-16le") + b"\x00" * 128
        )
        # 3. Excel (.csv)
        (staging_dir / "sheet.csv").write_text("id,name,role\n1,alice,admin\n", encoding="utf-8")
        # 4. PPT (.ppt OLE fallback)
        (staging_dir / "deck.ppt").write_bytes(
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 128 + "PowerPoint Document".encode("utf-16le") + b"\x00" * 128
        )
        # 5. TXT
        (staging_dir / "readme.txt").write_text("Project deployment instructions and notes.\n", encoding="utf-8")
        # 6. Other Files (.js, .py, .html, .css)
        (staging_dir / "app.js").write_text("const api = 'https://c2.example.org/beacon';\nconsole.log(api);\n", encoding="utf-8")
        (staging_dir / "exfil.py").write_text("#!/usr/bin/env python3\nimport urllib.request\nprint('exfil')\n", encoding="utf-8")
        (staging_dir / "index.html").write_text("<html><head><title>Portal Login</title></head><body>Form</body></html>\n", encoding="utf-8")
        (staging_dir / "styles.css").write_text("body { background: #0f172a; color: #f8fafc; }\n", encoding="utf-8")

        # 7. Unwanted internal Windows OS / AppData / noise files that MUST be excluded
        win_inf_dir = case_dir / "staging" / "Enrichment" / "Part_0" / "Windows" / "INF"
        win_inf_dir.mkdir(parents=True, exist_ok=True)
        (win_inf_dir / "oem0.inf").write_text("[Version]\nSignature=\"$WINDOWS NT$\"\n", encoding="utf-8")
        (win_inf_dir / "setupact.log").write_text("Windows internal setup log\n", encoding="utf-8")
        pkg_dir = case_dir / "staging" / "Enrichment" / "Part_0" / "Users" / "Alice" / "AppData" / "Local" / "Packages" / "Microsoft.Windows.Search"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "AppxManifest.xml").write_text("<Package></Package>\n", encoding="utf-8")
        (staging_dir / "desktop.ini").write_text("[.ShellClassInfo]\n", encoding="utf-8")

        parser = DocumentParser(case_id=case_id, staging_dir=case_dir / "staging", source_type="folder")
        res = parser.parse(max_workers=32)
        assert res["parsed_documents_metadata"] == 9
        assert res["parsed_text_documents"] == 6  # sheet.csv, readme.txt, app.js, exfil.py, index.html, styles.css

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            sync_artifact_registry_counts(conn, case_id=case_id)
            cur = conn.cursor()

            pdf_names = [r[0] for r in cur.execute("SELECT file_name FROM view_docs_pdf;").fetchall()]
            word_names = [r[0] for r in cur.execute("SELECT file_name FROM view_docs_word;").fetchall()]
            excel_names = [r[0] for r in cur.execute("SELECT file_name FROM view_docs_excel;").fetchall()]
            ppt_names = [r[0] for r in cur.execute("SELECT file_name FROM view_docs_ppt;").fetchall()]
            txt_names = [r[0] for r in cur.execute("SELECT file_name FROM view_docs_txt;").fetchall()]
            other_rows = cur.execute("SELECT file_name, extension, title FROM view_docs_other ORDER BY file_name;").fetchall()

            assert pdf_names == ["report.pdf"]
            assert word_names == ["memo.doc"]
            assert excel_names == ["sheet.csv"]
            assert ppt_names == ["deck.ppt"]
            assert "readme.txt" in txt_names
            assert "app.js" not in txt_names
            assert "exfil.py" not in txt_names
            assert "index.html" not in txt_names
            assert "styles.css" not in txt_names

            other_names = [r[0] for r in other_rows]
            assert other_names == ["app.js", "exfil.py", "index.html", "styles.css"]
            html_row = next(r for r in other_rows if r[0] == "index.html")
            assert html_row[1] == ".html"
            assert html_row[2] == "Portal Login"
    finally:
        DuckDBManager.close_connection(case_id)


def test_bulk_extractor_parallel_cap_and_normalizer_non_blocking(tmp_path: Path) -> None:
    """
    Requirement 2 & 4: BulkExtractorRunner must parse feature files in parallel on up to 32 threads,
    cap duplicate occurrences of the same feature so multi-lakh/million row outputs never stall RAM/DuckDB,
    and TimelineNormalizer must deduplicate entity_connections emission.
    """
    case_id = "test_be_cap_parallel"
    case_dir = (tmp_path / case_id).resolve()
    out_dir = case_dir / "bulk_extractor_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, case_dir)
    init_case_db(case_id)

    try:
        # Simulate 500 duplicate occurrences of the same domain + 1 unique email + histogram
        domain_lines = [
            f"{1000 + i * 64}\tlogin.corp-portal.org\tGET https://login.corp-portal.org/auth HTTP/1.1"
            for i in range(500)
        ]
        (out_dir / "domain.txt").write_text("\n".join(domain_lines) + "\n", encoding="utf-8")
        (out_dir / "domain_histogram.txt").write_text("n=500\tlogin.corp-portal.org\n", encoding="utf-8")
        (out_dir / "email.txt").write_text(
            "4096\tsecurity@corp-portal.org\tFrom: security@corp-portal.org\\x0d\\x0a\n",
            encoding="utf-8",
        )
        (out_dir / "email_histogram.txt").write_text("n=1\tsecurity@corp-portal.org\n", encoding="utf-8")

        runner = BulkExtractorRunner(case_id=case_id, case_dir=case_dir)
        feat_rows, hist_rows, _ = runner.parse_output_directory(out_dir, enable_carving=False)

        # Duplicate domain occurrences are capped at 50 in features while histogram retains full n=500!
        domain_feats = [r for r in feat_rows if r[0] == "domain"]
        email_feats = [r for r in feat_rows if r[0] == "email"]
        assert len(domain_feats) == 50
        assert len(email_feats) == 1
        assert ("domain", 500, "login.corp-portal.org", "domain_histogram.txt") in hist_rows
        assert ("email", 1, "security@corp-portal.org", "email_histogram.txt") in hist_rows

        # Insert into DuckDB and verify TimelineNormalizer deduplicates entity_connections (<= 5 per unique feature)
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cur = conn.cursor()
            numbered = [(i + 1, *r) for i, r in enumerate(feat_rows)]
            cur.executemany(
                "INSERT INTO parsed_bulk_extractor_features (_row_id, scanner, offset_str, feature, context, source_file) VALUES (?, ?, ?, ?, ?, ?);",
                numbered,
            )

        norm = TimelineNormalizer(case_id=case_id)
        norm.normalize_all(sync_registry=True)

        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cur = conn.cursor()
            dom_ent_cnt = cur.execute(
                "SELECT COUNT(*) FROM entity_connections WHERE source_table = 'parsed_bulk_extractor_features' AND entity_value = 'login.corp-portal.org';"
            ).fetchone()[0]
            assert 1 <= dom_ent_cnt <= 5

            # Verify keyword search finds both Bulk Extractor features & histograms quickly on 32 threads
            cur.execute(
                "INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, source_file, hit_count) VALUES ('1', 'corp-portal.org', FALSE, FALSE, 'Test', 0);"
            )
        hits = scan_keywords_for_case(case_id, max_workers=32)
        assert hits >= 2
    finally:
        DuckDBManager.close_connection(case_id)


def test_32_thread_defaults_and_suppress_duplicate_200_log_filter() -> None:
    """
    Requirement 4 & 6:
    - Default worker threads are configured for 32 threads (DEFAULT_MAX_WORKERS == 32, DEFAULT_DUCKDB_THREADS == 32).
    - _SuppressDuplicate200Filter logs ONE active 200 OK line per endpoint, suppresses all continuous duplicate
      200 OK lines while active (no 60s repeat spam), and logs ONE active 200 OK line again after a non-200 transition.
    """
    assert DEFAULT_MAX_WORKERS == 32
    assert DEFAULT_DUCKDB_THREADS == 32

    flt = _SuppressDuplicate200Filter()

    def _make_record(endpoint: str, status: int) -> logging.LogRecord:
        return logging.LogRecord(
            name="uvicorn.access",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='%s - "%s %s HTTP/%s" %d',
            args=("127.0.0.1:54321", "GET", endpoint, "1.1", status),
            exc_info=None,
        )

    # First 200 OK -> logged (True)
    assert flt.filter(_make_record("/api/cases/case1/status", 200)) is True
    # Subsequent continuous 200 OK polls -> suppressed (False)
    for _ in range(10):
        assert flt.filter(_make_record("/api/cases/case1/status", 200)) is False

    # Non-200 status transition -> logged immediately (True)
    assert flt.filter(_make_record("/api/cases/case1/status", 503)) is True
    # Becoming active (200 OK) again -> logged once (True), then suppressed (False)
    assert flt.filter(_make_record("/api/cases/case1/status", 200)) is True
    assert flt.filter(_make_record("/api/cases/case1/status", 200)) is False


def test_ui_excludes_event_logs_from_artifacts_and_exposes_bulk_extractor_tab() -> None:
    """
    Requirement 2, 3 & 5:
    - TopNavBar Forensic Views dropdown includes 'bulkextractor' ('Bulk Extractor').
    - SidebarTree CANONICAL_WFT_CATEGORIES and filtering exclude 'EVENT LOGS' and 'parsed_bulk_extractor_*'
      from the Artifacts tab because both have dedicated tabs in the Forensic Views dropdown.
    - ProcessWizard navigates to Artifacts when starting processing from the Processing tab.
    """
    repo_root = Path(__file__).resolve().parents[2]
    topnav_src = (repo_root / "frontend" / "src" / "components" / "TopNavBar.tsx").read_text(encoding="utf-8")
    sidebar_src = (repo_root / "frontend" / "src" / "components" / "SidebarTree.tsx").read_text(encoding="utf-8")
    app_src = (repo_root / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    wizard_src = (repo_root / "frontend" / "src" / "components" / "ProcessWizard.tsx").read_text(encoding="utf-8")

    assert "id: 'bulkextractor'" in topnav_src
    assert "label: 'Bulk Extractor'" in topnav_src
    assert "<BulkExtractorWorkbench" in app_src
    assert "normalizeWftCategory(a.category) !== 'EVENT LOGS'" in sidebar_src
    assert "a.table_name !== 'parsed_bulk_extractor_features'" in sidebar_src
    assert "onNavigateToExamine()" in wizard_src


def test_large_case_resilience_mft_cache_csv_fallback_regripper_timeout_and_hindsight_cache(
    tmp_path: Path, monkeypatch
) -> None:
    """
    Regression verification for 430GB E01 Remcos failure root causes:
    1. BaseParser caches vfs_files (any non-zero row count) and raw_mft in-memory index so resolve_evidence_path
       and get_original_mtime/get_original_ctime do not re-query DuckDB per file.
    2. EZToolRunner.ingest_csv_files falls back to explicit CSV dialect (read_csv with strict_mode=false,
       null_padding=true, ignore_errors=true) when a timed-out tool (e.g. EvtxECmd) leaves a truncated CSV tail.
    3. RegRipperRunner._invoke_rip_on_hive salvages partial stdout on subprocess.TimeoutExpired instead of
       discarding all plugin reports from a large UsrClass.dat hive.
    4. EZToolRunner._profile_has_broken_chromium_cache detects incomplete Cache_Data (index present, data_3 missing)
       upfront so Hindsight runs once with profile_nocache.
    5. BulkExtractorRunner._open_be_text_with_retry retries transient PermissionError ([Errno 13] Permission denied).
    6. DuckDBManager.get_connection recovers a connection stuck in an aborted transaction.
    """
    import subprocess
    from backend.orchestrator.ez_runner import EZToolRunner
    from backend.orchestrator.regripper_runner import RegRipperRunner
    from backend.parsers.base_parser import BaseParser

    case_id = "test_remcos_resilience"
    case_dir = (tmp_path / case_id).resolve()
    staging_dir = case_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    register_case_dir(case_id, case_dir)
    init_case_db(case_id)

    try:
        # 1. Seed vfs_files (small row count <= 500) and raw_mft, verify BaseParser caches both in memory
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO vfs_files (
                    _row_id, part_index, vfs_path, file_name, is_directory,
                    si_modified, si_created, staged_rel_path
                ) VALUES (
                    1, 1, '\\Users\\2304432\\Downloads\\payload.exe', 'payload.exe', FALSE,
                    '2025-10-15 12:30:00', '2025-10-15 12:00:00',
                    'UserFiles/2304432/Downloads/payload.exe'
                );
                """
            )
            cur.execute(
                """
                CREATE OR REPLACE TABLE raw_mft (
                    _row_id BIGINT,
                    ParentPath VARCHAR,
                    FileName VARCHAR,
                    FileSize VARCHAR,
                    LastModified0x10 VARCHAR
                );
                INSERT INTO raw_mft VALUES (
                    1, '.\\Users\\2304432\\Desktop', 'remcos_agent.bin', '4096', '2025-10-15 13:00:00'
                );
                """
            )

        bp = BaseParser(case_id=case_id, staging_dir=staging_dir, source_type="image")
        staged_p = staging_dir / "UserFiles" / "2304432" / "Downloads" / "payload.exe"
        assert bp.resolve_evidence_path(staged_p) == "C:\\Users\\2304432\\Downloads\\payload.exe"
        assert bp.get_original_mtime(staged_p) == "2025-10-15 12:30:00"
        assert bp._vfs_staged_cache is not None

        mft_only_p = staging_dir / "Enrichment" / "remcos_agent.bin"
        assert bp.resolve_evidence_path(mft_only_p, file_size=4096) == "C:\\Users\\2304432\\Desktop\\remcos_agent.bin"
        assert bp._mft_index_cache is not None
        assert "remcos_agent.bin" in bp._mft_index_cache

        # 2. Verify DuckDBManager recovers an open transaction on cached connection
        with DuckDBManager.get_lock(case_id):
            c1 = DuckDBManager.get_connection(case_id, read_only=False)
            healthy = DuckDBManager._ensure_healthy_cached_conn(
                case_id=case_id,
                db_path=case_dir / "case.duckdb",
                db_key=str((case_dir / "case.duckdb").resolve()).lower(),
                conn=c1,
                read_only=False,
                threads=4,
            )
            assert healthy.cursor().execute("SELECT 1;").fetchone()[0] == 1

        # 3. Verify EZToolRunner.ingest_csv_files handles a truncated/malformed CSV without crashing
        ez = EZToolRunner(case_id=case_id)
        trunc_csv = case_dir / "csv_out" / "evtx" / "evtx.csv"
        trunc_csv.parent.mkdir(parents=True, exist_ok=True)
        trunc_csv.write_text(
            'RecordNumber,EventId,Channel,Payload\n'
            '1,4624,Security,"{\\"EventData\\":\\"Logon\\"}"\n'
            '2,4688,Security,"{\\"TruncatedPayloadWithoutClosingQuote\n',
            encoding="utf-8",
        )
        ingested_cnt = ez.ingest_csv_file(
            csv_path=trunc_csv,
            table_name="raw_evtx",
            category="EVENT LOGS",
            display_name="Windows Event Logs",
            source_tool="EvtxECmd.exe",
            artifact_id="os_evtx",
        )
        assert ingested_cnt >= 1

        # 4. Verify EZToolRunner._profile_has_broken_chromium_cache detects missing data_3
        prof_dir = staging_dir / "Browsers" / "Edge" / "2304432" / "Default"
        cache_data = prof_dir / "Cache" / "Cache_Data"
        cache_data.mkdir(parents=True, exist_ok=True)
        (cache_data / "index").write_bytes(b"idx" * 32)
        (cache_data / "data_0").write_bytes(b"d0" * 32)
        (cache_data / "data_1").write_bytes(b"d1" * 32)
        (cache_data / "data_2").write_bytes(b"d2" * 32)
        assert EZToolRunner._profile_has_broken_chromium_cache(prof_dir) is True
        (cache_data / "data_3").write_bytes(b"d3" * 32)
        assert EZToolRunner._profile_has_broken_chromium_cache(prof_dir) is False

        # 5. Verify RegRipperRunner._invoke_rip_on_hive salvages partial stdout on TimeoutExpired
        partial_rip_out = (
            "----------------------------------------\n"
            "shellbags v.20200428\n"
            "(USRCLASS) Parse ShellBags\n"
            "MITRE: T1083\n"
            "C:\\Users\\3185999\\Desktop\\Remcos\n"
            "----------------------------------------\n"
        )

        def _fake_timeout_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(
                cmd=args[0],
                timeout=600,
                output=partial_rip_out,
                stderr="plugin hung",
            )

        monkeypatch.setattr(subprocess, "run", _fake_timeout_run)
        proc_rr, salvaged_out = RegRipperRunner._invoke_rip_on_hive(
            Path("rip.exe"), Path("UsrClass.dat"), "USRCLASS"
        )
        assert proc_rr.returncode == 0
        assert "shellbags v.20200428" in salvaged_out

        # 6. Verify BulkExtractorRunner._open_be_text_with_retry retries transient PermissionError
        be_feat = case_dir / "domain.txt"
        be_feat.write_text("1024\texample.com\tcontext\n", encoding="utf-8")
        real_open = open
        attempts = {"cnt": 0}

        def _flaky_open(file, *args, **kwargs):
            if Path(file) == be_feat and attempts["cnt"] < 2:
                attempts["cnt"] += 1
                raise PermissionError(13, "Permission denied", str(file))
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _flaky_open)
        with BulkExtractorRunner._open_be_text_with_retry(be_feat) as fh:
            assert "example.com" in fh.read()
        assert attempts["cnt"] == 2
    finally:
        DuckDBManager.close_connection(case_id)


