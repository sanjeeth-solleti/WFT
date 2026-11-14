import io
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

import duckdb
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.config import CASES_DIR, get_case_staging_dir, get_case_db_path, get_case_dir
from backend.db.engine import DuckDBManager, init_case_db
from backend.db.schema import sync_artifact_registry_counts, MASTER_ARTIFACT_CATALOG


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def sample_case():
    case_id = "test_export_case"
    case_dir = get_case_dir(case_id, create_if_missing=True)
    staging_dir = get_case_staging_dir(case_id)
    staging_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy staging files & subdirectories
    sub_dir = staging_dir / "Documents"
    sub_dir.mkdir(parents=True, exist_ok=True)
    sample_file = sub_dir / "evidence_doc.txt"
    sample_file.write_text("Confidential DFIR forensic findings 12345", encoding="utf-8")

    sub_img = staging_dir / "Pictures"
    sub_img.mkdir(parents=True, exist_ok=True)
    img_file = sub_img / "artifact.png"
    img_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01")

    # Initialize case database
    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()
        # Insert a sample row into parsed_documents_metadata or custom table
        cursor.execute("""
            INSERT INTO parsed_documents_metadata (
                _row_id, file_path, file_name, file_type, file_size_bytes, title, author, sha256
            ) VALUES (1, 'C:\\Users\\Admin\\Documents\\secret.docx', 'secret.docx', 'docx', 1024, 'Top Secret', 'Examiner1', 'abcdef123456');
        """)
        # Insert sample row into bookmarks
        cursor.execute("""
            INSERT INTO bookmarks (bookmark_id, source_table, source_row_id, tag_name, examiner_notes)
            VALUES ('bm_test_1', 'parsed_documents_metadata', 1, 'Key Evidence', 'Crucial finding');
        """)

    yield {
        "case_id": case_id,
        "sample_file": sample_file,
        "staging_dir": staging_dir,
        "sub_dir": sub_dir,
    }

    # Teardown
    try:
        DuckDBManager.close_all()
        if case_dir.exists():
            shutil.rmtree(case_dir, ignore_errors=True)
    except Exception:
        pass


def test_schema_combined_cleanup(sample_case):
    """Verify that Pictures & Video EXIF (Combined) and Documents & Zone.Identifier (Combined) are purged."""
    case_id = sample_case["case_id"]
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cursor = conn.cursor()

        # Intentionally insert deprecated combined rows to test auto-clean
        cursor.execute("""
            INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count)
            VALUES 
                ('media_exif', 'MEDIA', 'Pictures & Video EXIF (Combined)', 'parsed_media_exif', 'MediaParser', 10),
                ('documents_metadata', 'DOCUMENTS', 'Documents & Zone.Identifier (Combined)', 'parsed_documents_metadata', 'DocumentParser', 15)
            ON CONFLICT (artifact_id) DO UPDATE SET display_name = EXCLUDED.display_name;
        """)

        # Run sync_artifact_registry_counts
        sync_artifact_registry_counts(conn, case_id=case_id)

        # Verify they were deleted from artifact_registry
        res = cursor.execute("""
            SELECT artifact_id, display_name, table_name 
            FROM artifact_registry 
            WHERE display_name LIKE '%(Combined)%' 
               OR artifact_id IN ('media_exif', 'documents_metadata')
               OR table_name IN ('parsed_media_exif', 'parsed_documents_metadata');
        """).fetchall()
        assert len(res) == 0, f"Combined entries should be deleted from artifact_registry: {res}"

        # But underlying tables should still exist in DuckDB
        tables = [r[0] for r in cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';").fetchall()]
        assert "parsed_media_exif" in tables
        assert "parsed_documents_metadata" in tables


def test_export_raw_file(client, sample_case):
    """Verify GET /api/cases/{case_id}/export/file streams original file with Content-Disposition."""
    case_id = sample_case["case_id"]
    rel_path = "Documents\\evidence_doc.txt"
    resp = client.get(f"/api/cases/{case_id}/export/file?file_path={rel_path}")
    assert resp.status_code == 200
    assert 'attachment; filename="evidence_doc.txt"' in resp.headers.get("Content-Disposition", "")
    assert resp.content == b"Confidential DFIR forensic findings 12345"


def test_export_folder_zip(client, sample_case):
    """Verify GET /api/cases/{case_id}/export/folder-zip packages folder into a zip archive."""
    case_id = sample_case["case_id"]
    resp = client.get(f"/api/cases/{case_id}/export/folder-zip?folder_path=Documents")
    assert resp.status_code == 200
    assert 'attachment; filename="Documents_export.zip"' in resp.headers.get("Content-Disposition", "")

    # Inspect zip contents in-memory
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        namelist = zf.namelist()
        assert any("evidence_doc.txt" in n for n in namelist)
        content = zf.read(namelist[0])
        assert content == b"Confidential DFIR forensic findings 12345"


def test_export_save_to_folder(client, sample_case, monkeypatch):
    """Verify POST /api/cases/{case_id}/export/save-to-folder exports file/folder to selected path."""
    case_id = sample_case["case_id"]
    dest_temp = tempfile.mkdtemp(prefix="wft_test_dest_")
    monkeypatch.setenv("WFT_MOCK_BROWSE_PATH", dest_temp)

    try:
        # 1. Export file
        payload = {
            "file_path": "Documents\\evidence_doc.txt",
            "is_folder": False,
        }
        resp = client.post(f"/api/cases/{case_id}/export/save-to-folder", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        saved_file = Path(dest_temp) / "evidence_doc.txt"
        assert saved_file.is_file()
        assert saved_file.read_text(encoding="utf-8") == "Confidential DFIR forensic findings 12345"

        # 2. Export folder
        payload_folder = {
            "file_path": "Documents",
            "is_folder": True,
        }
        resp_folder = client.post(f"/api/cases/{case_id}/export/save-to-folder", json=payload_folder)
        assert resp_folder.status_code == 200
        data_f = resp_folder.json()
        assert data_f["success"] is True
        saved_sub = Path(dest_temp) / "Documents" / "evidence_doc.txt"
        assert saved_sub.is_file()

        # 3. Export table CSV
        payload_csv = {
            "table_name": "parsed_documents_metadata",
            "is_folder": False,
        }
        resp_csv = client.post(f"/api/cases/{case_id}/export/save-to-folder", json=payload_csv)
        assert resp_csv.status_code == 200
        saved_csv = Path(dest_temp) / "parsed_documents_metadata_export.csv"
        assert saved_csv.is_file()
        assert "secret.docx" in saved_csv.read_text(encoding="utf-8")

        # 4. Export row JSON
        payload_json = {
            "table_name": "parsed_documents_metadata",
            "row_id": 1,
            "is_folder": False,
        }
        resp_json = client.post(f"/api/cases/{case_id}/export/save-to-folder", json=payload_json)
        assert resp_json.status_code == 200
        saved_json = Path(dest_temp) / "parsed_documents_metadata_row_1.json"
        assert saved_json.is_file()
        parsed_row = json.loads(saved_json.read_text(encoding="utf-8"))
        assert parsed_row["file_name"] == "secret.docx"
    finally:
        shutil.rmtree(dest_temp, ignore_errors=True)


def test_delete_bookmark_by_row(client, sample_case):
    """Verify DELETE /api/cases/{case_id}/bookmarks deletes bookmark by table and row_id."""
    case_id = sample_case["case_id"]
    # Verify bookmark exists
    list_res = client.get(f"/api/cases/{case_id}/bookmarks")
    assert list_res.status_code == 200
    bms = list_res.json()["bookmarks"]
    assert any(b["source_table"] == "parsed_documents_metadata" and b["source_row_id"] == 1 for b in bms)

    # Delete by row
    del_res = client.delete(f"/api/cases/{case_id}/bookmarks?source_table=parsed_documents_metadata&source_row_id=1")
    assert del_res.status_code == 200

    # Verify deleted
    list_res2 = client.get(f"/api/cases/{case_id}/bookmarks")
    bms2 = list_res2.json()["bookmarks"]
    assert not any(b["source_table"] == "parsed_documents_metadata" and b["source_row_id"] == 1 for b in bms2)
