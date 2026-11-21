import concurrent.futures
import json
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.config as _cfg
from backend.config import (
    BASE_DIR,
    _load_custom_case_dirs,
    get_case_db_path,
    get_case_dir,
    get_registered_custom_cases,
    register_case_dir,
)
from backend.db.engine import (
    DuckDBManager,
    get_distinct_column_values,
    init_case_db,
    query_paginated,
)
from backend.main import app, is_rejected_or_non_regular_file


@pytest.fixture(scope="module", autouse=True)
def isolated_stability_env(tmp_path_factory):
    tmp_root = tmp_path_factory.mktemp("wft_stability_isolated")
    cases_dir = (tmp_root / "cases").resolve()
    appdata_dir = (tmp_root / "appdata").resolve()
    cases_dir.mkdir(parents=True, exist_ok=True)
    appdata_dir.mkdir(parents=True, exist_ok=True)

    mp = pytest.MonkeyPatch()
    mp.setenv("WFT_CASES_DIR", str(cases_dir))
    mp.setenv("WFT_APPDATA_DIR", str(appdata_dir))
    mp.setattr(_cfg, "CASES_DIR", cases_dir)
    mp.setattr(_cfg, "APP_DATA_DIR", appdata_dir)
    mp.setattr(_cfg, "CUSTOM_LOCATIONS_FILE", (appdata_dir / "custom_locations.json").resolve())
    _load_custom_case_dirs()
    yield {"cases_dir": cases_dir, "appdata_dir": appdata_dir, "tmp_root": tmp_root}
    DuckDBManager.close_all()
    mp.undo()
    _load_custom_case_dirs()


@pytest.fixture(scope="module")
def client(isolated_stability_env):
    return TestClient(app)


@pytest.fixture(scope="module")
def audit_case(isolated_stability_env):
    case_id = "test_audit_case"
    case_dir = get_case_dir(case_id, create_if_missing=True)
    init_case_db(case_id)

    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_test_table (
                _row_id BIGINT PRIMARY KEY,
                FileName VARCHAR,
                FileSize BIGINT,
                Category VARCHAR
            );
        """)
        cursor.execute("""
            INSERT INTO audit_test_table (_row_id, FileName, FileSize, Category)
            VALUES 
                (1, 'calc.exe', 1024, 'Executable'),
                (2, 'notes.txt', 2048, 'Document'),
                (3, 'photo.jpg', 4096, 'Image');
        """)

    yield {"case_id": case_id, "case_dir": case_dir}

    # Teardown
    try:
        DuckDBManager.close_all()
        if case_dir.exists():
            shutil.rmtree(case_dir, ignore_errors=True)
    except Exception:
        pass


def test_duckdb_concurrency_multithreaded(audit_case):
    """
    Verify that concurrent threads accessing DuckDB via DuckDBManager execute safely
    without connection corruption or exit code 4294967295.
    """
    case_id = audit_case["case_id"]

    def run_query(thread_id: int):
        with DuckDBManager.get_lock(case_id):
            conn = DuckDBManager.get_connection(case_id, read_only=False)
            cursor = conn.cursor()
            rows = cursor.execute("SELECT COUNT(*) FROM audit_test_table;").fetchone()
            assert rows[0] == 3
            res = query_paginated(case_id, "audit_test_table", limit=10, offset=0)
            assert len(res["rows"]) == 3
            return thread_id, True

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(run_query, i) for i in range(20)]
        for f in concurrent.futures.as_completed(futures):
            tid, success = f.result()
            assert success is True


def test_rejected_ntfs_metadata_and_directories(client, audit_case):
    """
    Verify /hex, /file/content, and /file/raw return immediate clean 404 responses
    for locked virtual NTFS metadata streams and restricted directories.
    """
    case_id = audit_case["case_id"]

    rejected_paths = [
        # Locked NTFS metadata streams
        r"C:\$MFT",
        r"\$MFT",
        "$MFT",
        r"C:\$AttrDef",
        r"C:\$LogFile",
        r"C:\$Bitmap",
        r"C:\$Boot",
        r"C:\$BadClus",
        r"C:\$Secure",
        r"C:\$UpCase",
        r"C:\$Volume",
        r"C:\$MFT::$DATA",
        # Restricted directories
        r"C:\$Recycle.Bin",
        r"C:\$Recycle.Bin\S-1-5-21",
        r"C:\System Volume Information",
        r"C:\Config.Msi",
        r"C:\PerfLogs",
        r"C:\$Extend",
        r"C:\$Extend\$RmMetadata",
    ]

    for p in rejected_paths:
        assert is_rejected_or_non_regular_file(p) is True

        # Test /hex
        res_hex = client.get(f"/api/cases/{case_id}/hex", params={"file_path": p})
        assert res_hex.status_code == 404, f"Expected 404 for hex on {p}, got {res_hex.status_code}"

        # Test /file/content
        res_content = client.get(f"/api/cases/{case_id}/file/content", params={"file_path": p})
        assert res_content.status_code == 404, f"Expected 404 for content on {p}, got {res_content.status_code}"

        # Test /file/raw
        res_raw = client.get(f"/api/cases/{case_id}/file/raw", params={"file_path": p})
        assert res_raw.status_code == 404, f"Expected 404 for raw on {p}, got {res_raw.status_code}"

    # Regular files INSIDE $Recycle.Bin\<SID>\..., PerfLogs\..., Config.Msi\... MUST be allowed
    staging_dir = (audit_case["case_dir"] / "staging").resolve()
    allowed_staged = [
        (r"C:\$Recycle.Bin\S-1-5-21-1001\$Rtest.txt", staging_dir / "$Recycle.Bin" / "S-1-5-21-1001" / "$Rtest.txt"),
        (r"C:\PerfLogs\System\perf_diag.log", staging_dir / "PerfLogs" / "System" / "perf_diag.log"),
        (r"C:\Config.Msi\1a2b3c.rbf", staging_dir / "Config.Msi" / "1a2b3c.rbf"),
    ]
    for vpath, disk_file in allowed_staged:
        disk_file.parent.mkdir(parents=True, exist_ok=True)
        disk_file.write_bytes(b"Recovered regular forensic artifact bytes")
        assert is_rejected_or_non_regular_file(vpath) is False
        assert client.get(f"/api/cases/{case_id}/hex", params={"file_path": vpath}).status_code == 200
        assert client.get(f"/api/cases/{case_id}/file/content", params={"file_path": vpath}).status_code == 200
        assert client.get(f"/api/cases/{case_id}/file/raw", params={"file_path": vpath}).status_code == 200


def test_column_validation_against_describe(audit_case):
    """
    Verify engine.py strictly validates sort_col, distinct column names,
    and column_filters against the table's actual DESCRIBE columns.
    """
    case_id = audit_case["case_id"]

    # 1. Invalid sort_col falls back safely to first column without error
    res = query_paginated(case_id, "audit_test_table", sort_col="non_existent_column")
    assert len(res["rows"]) == 3

    # 2. Valid sort_col works
    res_sorted = query_paginated(case_id, "audit_test_table", sort_col="FileSize", sort_dir="DESC")
    assert res_sorted["rows"][0]["FileSize"] == 4096

    # 3. Invalid column_filter key is ignored safely
    res_filtered = query_paginated(
        case_id,
        "audit_test_table",
        column_filters={"invalid_col_name": ["some_value"]},
    )
    assert len(res_filtered["rows"]) == 3

    # 4. Valid column_filter works
    res_filtered_valid = query_paginated(
        case_id,
        "audit_test_table",
        column_filters={"Category": ["Document"]},
    )
    assert len(res_filtered_valid["rows"]) == 1
    assert res_filtered_valid["rows"][0]["FileName"] == "notes.txt"

    # 5. Distinct column validation: valid column succeeds
    distinct_vals = get_distinct_column_values(case_id, "audit_test_table", "Category")
    assert len(distinct_vals) == 3

    # 6. Distinct column validation: invalid column raises ValueError
    with pytest.raises(ValueError) as excinfo:
        get_distinct_column_values(case_id, "audit_test_table", "malicious_or_missing_col")
    assert "not found in table" in str(excinfo.value)


def test_pruning_missing_custom_locations():
    """
    Verify config.py ignores and prunes any entries in custom_locations.json
    whose target directories no longer exist on disk.
    """
    temp_dir = tempfile.mkdtemp()
    temp_path = Path(temp_dir).resolve()
    fake_case_id = "temp_disappearing_case"

    # Register temporary case folder
    registered = register_case_dir(fake_case_id, temp_path)
    assert registered.exists()
    assert fake_case_id in get_registered_custom_cases()

    # Delete folder from disk
    shutil.rmtree(temp_path, ignore_errors=True)
    assert not temp_path.exists()

    # Re-loading custom cases must now ignore the missing directory
    _load_custom_case_dirs()
    active_cases = get_registered_custom_cases()
    assert fake_case_id not in active_cases


def test_no_tool_cases_created_with_custom_target_dir(client, isolated_stability_env, tmp_path):
    """
    Verify that when processing a case with a distinct custom target_dir (temp_src != temp_target),
    case storage goes to temp_target, source_path is untouched, and BASE_DIR / 'cases' is untouched.
    """
    temp_src = (tmp_path / "evidence_source").resolve()
    temp_target = (tmp_path / "custom_case_storage").resolve()
    temp_src.mkdir(parents=True, exist_ok=True)
    temp_target.mkdir(parents=True, exist_ok=True)
    (temp_src / "triage_note.txt").write_text("Forensic triage sample", encoding="utf-8")
    custom_cid = "test_external_storage_case"

    tool_cases = (BASE_DIR / "cases").resolve()
    pre_existing_tool_cases = set(tool_cases.iterdir()) if tool_cases.exists() else None

    try:
        res = client.post(
            "/api/cases/process",
            json={
                "case_name": custom_cid,
                "case_id": custom_cid,
                "source_type": "directory",
                "source_path": str(temp_src),
                "target_dir": str(temp_target),
                "enable_yara": False,
                "enable_ioc": False,
                "enable_ocr": False,
                "enable_stinger": False,
                "enable_hindsight": False,
                "run_async": False,
            },
        )
        assert res.status_code == 200

        expected_case_dir = (temp_target / custom_cid).resolve()
        assert (expected_case_dir / "case.duckdb").exists()
        assert not (temp_src / "case.duckdb").exists()
        assert not (temp_src / "staging").exists()

        if pre_existing_tool_cases is None:
            assert not tool_cases.exists(), f"Found unexpected cases folder in tool repo: {tool_cases}"
        else:
            assert not (tool_cases / custom_cid).exists()

        resolved_case = get_case_dir(custom_cid)
        assert resolved_case == expected_case_dir

        list_res = client.get("/api/cases")
        assert list_res.status_code == 200
        cases = list_res.json()["cases"]
        matching = [c for c in cases if c["case_id"] == custom_cid]
        assert len(matching) == 1
        assert matching[0]["case_path"] == str(expected_case_dir)
    finally:
        DuckDBManager.close_connection(custom_cid)


def test_source_path_never_polluted_when_target_equals_source_or_none(client, isolated_stability_env, tmp_path):
    """Verify target_dir=None/'' defaults safely to CASES_DIR / case_id while target_dir == source_path (or nested) returns 400."""
    src_dir = (tmp_path / "readonly_evidence_folder").resolve()
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "sample.txt").write_text("Immutable evidence", encoding="utf-8")

    for bad_cid, bad_tgt in (
        ("reject_same_as_src", str(src_dir)),
        ("reject_nested_in_src", str(src_dir / "nested_out")),
    ):
        bad_res = client.post(
            "/api/cases/process",
            json={
                "case_name": bad_cid,
                "case_id": bad_cid,
                "source_type": "folder",
                "source_path": str(src_dir),
                "target_dir": bad_tgt,
                "enable_yara": False,
                "enable_ioc": False,
                "enable_ocr": False,
                "enable_stinger": False,
                "enable_hindsight": False,
                "run_async": False,
            },
        )
        assert bad_res.status_code == 400
        assert not (src_dir / "case.duckdb").exists()
        assert not (src_dir / "staging").exists()
        assert not (src_dir / "nested_out").exists()

    for cid, tgt_val in (
        ("safe_default_none_case", None),
        ("safe_default_blank_case", ""),
    ):
        res = client.post(
            "/api/cases/process",
            json={
                "case_name": cid,
                "case_id": cid,
                "source_type": "folder",
                "source_path": str(src_dir),
                "target_dir": tgt_val,
                "enable_yara": False,
                "enable_ioc": False,
                "enable_ocr": False,
                "enable_stinger": False,
                "enable_hindsight": False,
                "run_async": False,
            },
        )
        assert res.status_code == 200
        body = res.json()
        expected_dir = (isolated_stability_env["cases_dir"] / cid).resolve()
        assert Path(body["target_dir"]).resolve() == expected_dir
        assert (expected_dir / "case.duckdb").exists()
        assert not (src_dir / "case.duckdb").exists()
        assert not (src_dir / "staging").exists()
        DuckDBManager.close_connection(cid)


