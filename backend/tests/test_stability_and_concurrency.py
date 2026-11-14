import concurrent.futures
import json
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import (
    BASE_DIR,
    CASES_DIR,
    CUSTOM_LOCATIONS_FILE,
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


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def audit_case():
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
