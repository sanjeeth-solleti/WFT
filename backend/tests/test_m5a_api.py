"""
Sub-Milestone M5-A Comprehensive FastAPI Contract & Security Verification Suite.
100% isolated via tmp_path and monkeypatch — never touches real cases/, .env,
rules/event_profiles.json, or port 8765.
"""
import hashlib
import struct
import subprocess
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

import backend.config as _cfg
import backend.main as _main
from backend.config import _load_custom_case_dirs, get_case_dir, get_case_staging_dir
from backend.db.engine import DuckDBManager, init_case_db
from backend.main import app


@pytest.fixture(autouse=True)
def isolated_m5a_env(tmp_path, monkeypatch):
    cases_dir = (tmp_path / "cases").resolve()
    appdata_dir = (tmp_path / "appdata").resolve()
    cases_dir.mkdir(parents=True, exist_ok=True)
    appdata_dir.mkdir(parents=True, exist_ok=True)

    env_file = (appdata_dir / ".env.test").resolve()
    env_file.write_text("", encoding="utf-8")
    tool_paths_file = (appdata_dir / "tool_paths.json").resolve()
    event_profiles_file = (appdata_dir / "custom_event_profiles.json").resolve()
    custom_locs_file = (appdata_dir / "custom_locations.json").resolve()

    monkeypatch.setenv("WFT_CASES_DIR", str(cases_dir))
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata_dir))
    monkeypatch.setenv("WFT_ENV_FILE", str(env_file))
    monkeypatch.setenv("WFT_TOOL_PATHS_FILE", str(tool_paths_file))
    monkeypatch.setenv("WFT_EVENT_PROFILES_FILE", str(event_profiles_file))

    monkeypatch.setattr(_cfg, "CASES_DIR", cases_dir)
    monkeypatch.setattr(_cfg, "APP_DATA_DIR", appdata_dir)
    monkeypatch.setattr(_cfg, "TOOL_PATHS_FILE", tool_paths_file)
    monkeypatch.setattr(_cfg, "CUSTOM_LOCATIONS_FILE", custom_locs_file)
    monkeypatch.setattr(_cfg, "_CUSTOM_TOOL_PATHS", {})
    _load_custom_case_dirs()

    yield {
        "tmp_path": tmp_path,
        "cases_dir": cases_dir,
        "appdata_dir": appdata_dir,
        "env_file": env_file,
        "tool_paths_file": tool_paths_file,
        "event_profiles_file": event_profiles_file,
    }

    DuckDBManager.close_all()


@pytest.fixture()
def client():
    return TestClient(app)


def _build_minimal_valid_pe_bytes() -> bytes:
    """Construct a minimal valid PE32 executable so pefile parses headers & sections cleanly."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0x65000000, 0, 0, 0xE0, 0x0102)

    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x010B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 92, 16)

    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIIIIIHHI", sec, 8, 0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    headers = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(sec)
    padded_headers = headers.ljust(0x200, b"\x00")
    code_sec = (b"\x90\xc3").ljust(0x200, b"\x00")
    return padded_headers + code_sec


# ---------------------------------------------------------------------------
# §1. ProcessCaseRequest Forwarding, Bidirectional Sync, Workers & Isolation
# ---------------------------------------------------------------------------
def test_process_case_forwarding_sync_metadata_and_target_isolation(client, isolated_m5a_env, monkeypatch):
    captured: Dict[str, Any] = {}

    class SpyPipeline:
        def __init__(self, case_id: str, target_dir: str = None, max_workers: int = 8):
            captured["init"] = {"case_id": case_id, "target_dir": target_dir, "max_workers": max_workers}

        def run(
            self,
            source_type: str,
            source_path: str = None,
            enable_yara: bool = True,
            enable_stinger: bool = True,
            enable_ocr: bool = True,
            enable_ioc: bool = True,
            enable_hindsight: bool = True,
            enable_vss: bool = False,
            enable_data_carving: bool = False,
            enable_bulk_extractor: bool = False,
            max_workers: int = 8,
            selected_artifacts=None,
            initial_keywords=None,
        ):
            captured["run"] = {
                "source_type": source_type,
                "source_path": source_path,
                "enable_yara": enable_yara,
                "enable_stinger": enable_stinger,
                "enable_ocr": enable_ocr,
                "enable_ioc": enable_ioc,
                "enable_hindsight": enable_hindsight,
                "enable_vss": enable_vss,
                "enable_data_carving": enable_data_carving,
                "enable_bulk_extractor": enable_bulk_extractor,
                "max_workers": max_workers,
                "selected_artifacts": selected_artifacts,
                "initial_keywords": initial_keywords,
            }
            return {"ingested": True}

    monkeypatch.setattr(_main, "ProcessingPipeline", SpyPipeline)

    src_folder = (isolated_m5a_env["tmp_path"] / "evidence_folder").resolve()
    src_folder.mkdir(parents=True, exist_ok=True)
    (src_folder / "artifact.txt").write_text("evidence", encoding="utf-8")

    # Explicit target_dir == source_path or nested inside source_path MUST return HTTP 400 (SCOPE.md §9(e))
    nested_bad_target = src_folder / "sub_out"
    for bad_tgt in (str(src_folder), str(nested_bad_target)):
        bad_res = client.post(
            "/api/cases/process",
            json={
                "case_name": "M5A Bad Target",
                "case_id": "m5a_bad_tgt",
                "source_path": str(src_folder),
                "target_dir": bad_tgt,
                "run_async": False,
            },
        )
        assert bad_res.status_code == 400
        assert not (src_folder / "case.duckdb").exists()
        assert not nested_bad_target.exists()

    # Blank/omitted target_dir defaults safely to CASES_DIR / case_id + max_workers=99 + selected_artifacts sync
    res = client.post(
        "/api/cases/process",
        json={
            "case_name": "M5A Intake Case",
            "case_id": "m5a_intake_1",
            "case_number": "INC-2026-42",
            "examiner": "Alice Examiner",
            "notes": "Priority triage <review>",
            "source_path": str(src_folder),
            "target_dir": "",
            "max_workers": 99,
            "selected_artifacts": ["fs_vss", "carve_files", "os_prefetch"],
            "enable_bulk_extractor": True,
            "initial_keywords": [
                "alpha_term",
                {"keyword": "beta_100%", "case_sensitive": True, "category": "IOC"},
            ],
            "run_async": False,
        },
    )
    assert res.status_code == 200
    body = res.json()
    expected_safe_dir = (isolated_m5a_env["cases_dir"] / "m5a_intake_1").resolve()
    assert Path(body["target_dir"]).resolve() == expected_safe_dir
    assert not (src_folder / "case.duckdb").exists()
    assert not nested_bad_target.exists()

    # Clamped max_workers (99 -> 32) and bidirectional selected_artifacts <-> enable_*
    assert body["max_workers"] == 32
    assert body["enable_vss"] is True
    assert body["enable_data_carving"] is True
    assert body["enable_bulk_extractor"] is True
    assert "bulk_extractor" in body["selected_artifacts"]
    assert captured["init"]["max_workers"] == 32
    assert captured["run"]["enable_vss"] is True
    assert captured["run"]["enable_data_carving"] is True
    assert captured["run"]["enable_bulk_extractor"] is True

    # Verify case_metadata and case_keywords persisted in DuckDB
    with DuckDBManager.get_lock("m5a_intake_1"):
        conn = DuckDBManager.get_connection("m5a_intake_1", read_only=False)
        meta = dict(conn.execute("SELECT key, value FROM case_metadata;").fetchall())
        assert meta["case_number"] == "INC-2026-42"
        assert meta["examiner"] == "Alice Examiner"
        assert meta["max_workers"] == "32"
        kws = conn.execute("SELECT keyword, case_sensitive, category FROM case_keywords ORDER BY keyword ASC;").fetchall()
        assert ("alpha_term", False, "General") in kws
        assert ("beta_100%", True, "IOC") in kws

    # Verify bidirectional engine gating sync: enable_yara=False / enable_ocr=False strip IDs; enable_stinger=True adds ID
    res_sync = client.post(
        "/api/cases/process",
        json={
            "case_name": "M5A Engine Sync Case",
            "case_id": "m5a_intake_sync_2",
            "source_path": str(src_folder),
            "selected_artifacts": ["artifact_yara_hits", "artifact_ocr_results", "os_prefetch"],
            "enable_yara": False,
            "enable_ocr": False,
            "enable_stinger": True,
            "run_async": False,
        },
    )
    assert res_sync.status_code == 200
    sync_body = res_sync.json()
    assert sync_body["enable_yara"] is False
    assert sync_body["enable_ocr"] is False
    assert sync_body["enable_stinger"] is True
    assert "artifact_yara_hits" not in sync_body["selected_artifacts"]
    assert "artifact_ocr_results" not in sync_body["selected_artifacts"]
    assert "artifact_stinger_hits" in sync_body["selected_artifacts"]
    assert captured["run"]["enable_yara"] is False
    assert captured["run"]["enable_ocr"] is False
    assert captured["run"]["enable_stinger"] is True
    assert "artifact_yara_hits" not in captured["run"]["selected_artifacts"]
    assert "artifact_stinger_hits" in captured["run"]["selected_artifacts"]


# ---------------------------------------------------------------------------
# §2. System Tool Paths (/api/settings/tools) & Auto-Setup Tools
# ---------------------------------------------------------------------------
def test_settings_tools_aliases_and_auto_setup_tools(client, isolated_m5a_env, monkeypatch):
    fake_bin_dir = (isolated_m5a_env["tmp_path"] / "fake_bins").resolve()
    fake_bin_dir.mkdir(parents=True, exist_ok=True)
    fake_pe = _build_minimal_valid_pe_bytes()

    be_exe = fake_bin_dir / "bulk_extractor64.exe"
    be_exe.write_bytes(fake_pe)
    sum_exe = fake_bin_dir / "SumECmd.exe"
    sum_exe.write_bytes(fake_pe)
    rla_exe = fake_bin_dir / "rla.exe"
    rla_exe.write_bytes(fake_pe)

    get_res = client.get("/api/settings/tools")
    assert get_res.status_code == 200
    initial_map = get_res.json()
    assert "bulk_extractor" in initial_map
    assert "ez_sumecmd" in initial_map
    assert "ez_rla" in initial_map

    put_res = client.put(
        "/api/settings/tools",
        json={
            "paths": {
                "bulk_extractor": str(be_exe),
                "ez_sumecmd": str(sum_exe),
            }
        },
    )
    assert put_res.status_code == 200
    put_data = put_res.json()
    assert put_data["tools"]["bulk_extractor"]["status"] == "FOUND"
    assert Path(put_data["tools"]["bulk_extractor"]["resolved_path"]).resolve() == be_exe
    assert put_data["tools"]["ez_sumecmd"]["status"] == "FOUND"
    assert isolated_m5a_env["tool_paths_file"].is_file()

    # Forbidden UNC tool binary path must return 400
    bad_res = client.post(
        "/api/system/tool-paths",
        json={"paths": {"WFT_BULK_EXTRACTOR_EXE": r"\\attacker_host\share\evil_tool.exe"}},
    )
    assert bad_res.status_code == 400

    # Mock Setup-WFTTools.ps1 subprocess execution writing WFT_EZ_RLA_EXE to WFT_ENV_FILE
    def _fake_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(str(c) for c in (cmd if isinstance(cmd, list) else [cmd]))
        if "Setup-WFTTools.ps1" in cmd_str:
            env_f = isolated_m5a_env["env_file"]
            existing = env_f.read_text(encoding="utf-8") if env_f.exists() else ""
            env_f.write_text(existing + f"\nWFT_EZ_RLA_EXE={rla_exe}\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="Setup completed OK", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(_main.subprocess, "run", _fake_subprocess_run)
    auto_res = client.post("/api/system/auto-setup-tools", json={"skip_full_disk_scan": True})
    assert auto_res.status_code == 200
    auto_body = auto_res.json()
    assert auto_body["status"] == "success"
    assert auto_body["tools"]["ez_rla"]["status"] == "FOUND"
    assert Path(auto_body["tools"]["ez_rla"]["resolved_path"]).resolve() == rla_exe


# ---------------------------------------------------------------------------
# §3. Malware Scan Multi-Run Idempotency, Bogus Stinger Purge & /malware/hits
# ---------------------------------------------------------------------------
def test_malware_scan_idempotency_bogus_stinger_purge_and_hits_alias(client, isolated_m5a_env, monkeypatch):
    case_id = "m5a_malware_case"
    init_case_db(case_id)

    class FakeEnrichmentEngine:
        def __init__(self, case_id: str):
            self.case_id = case_id

        def run(self, enable_yara: bool = True, enable_ocr: bool = False, enable_stinger: bool = True):
            # Intentionally verify DuckDBManager RLock is NOT held across engine.run by acquiring it on a worker thread
            import threading
            acquired_in_worker = {"ok": False}

            def _probe_lock():
                with DuckDBManager.get_lock(self.case_id):
                    acquired_in_worker["ok"] = True

            t = threading.Thread(target=_probe_lock)
            t.start()
            t.join(timeout=2.0)
            assert acquired_in_worker["ok"] is True, "DuckDBManager RLock must NOT be held across engine.run()"

            with DuckDBManager.get_lock(self.case_id):
                conn = DuckDBManager.get_connection(self.case_id, read_only=False)
                cur = conn.cursor()
                if enable_yara:
                    # Insert duplicate YARA hits + bogus stinger_logs hit
                    for rid in (1, 2):
                        cur.execute(
                            """
                            INSERT INTO artifact_yara_hits (_row_id, file_path, file_name, sha256, rule_name, pattern_identifier, match_offset, severity)
                            VALUES (?, 'C:\\Temp\\drop_100%_bad.exe', 'drop_100%_bad.exe', 'deadbeef', 'APT_Dropper_Rule', '$s1', 64, 'CRITICAL');
                            """,
                            [rid],
                        )
                    cur.execute(
                        """
                        INSERT INTO artifact_yara_hits (_row_id, file_path, file_name, sha256, rule_name, pattern_identifier, match_offset, severity)
                        VALUES (3, 'C:\\cases\\stinger_logs\\stinger_scan_1.log', 'stinger_scan_1.log', '0000', 'Log_Noise', '$s0', 0, 'LOW');
                        """
                    )
                if enable_stinger:
                    # Insert duplicate real Stinger hit + bogus clean summary ("Infected files: 0") + stinger_logs self-hit
                    for rid in (10, 11):
                        cur.execute(
                            """
                            INSERT INTO artifact_stinger_hits (_row_id, file_path, file_name, sha256, malware_name, detection_type, details)
                            VALUES (?, 'C:\\Temp\\drop_100%_bad.exe', 'drop_100%_bad.exe', 'deadbeef', 'Trojan-Test!100%', 'Threat', 'Infected files: 1');
                            """,
                            [rid],
                        )
                    cur.execute(
                        """
                        INSERT INTO artifact_stinger_hits (_row_id, file_path, file_name, sha256, malware_name, detection_type, details)
                        VALUES
                            (12, 'C:\\Temp\\benign.exe', 'benign.exe', 'aaaa', 'Clean', 'Summary', 'Number of infected files: 0'),
                            (13, 'C:\\cases\\stinger_logs\\stinger_scan.html', 'stinger_scan.html', 'bbbb', 'SelfLog', 'Log', 'stinger log');
                        """
                    )
            return {"yara_scanned": 1, "stinger_scanned": 1}

    monkeypatch.setattr(_main, "FileEnrichmentEngine", FakeEnrichmentEngine)

    # Pre-seed legacy non-canonical malware_yara / malware_stinger registry rows to verify cleanup
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        conn.execute(
            """
            INSERT OR REPLACE INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count)
            VALUES
                ('malware_yara', 'MALWARE & YARA', 'Legacy YARA', 'artifact_yara_hits', 'YARA-X', 99),
                ('malware_stinger', 'MALWARE & YARA', 'Legacy Stinger', 'artifact_stinger_hits', 'Stinger', 99);
            """
        )

    r1 = client.post(f"/api/cases/{case_id}/malware/scan", json={"enable_yara": True, "enable_stinger": True, "enable_ocr": False})
    assert r1.status_code == 200
    s1 = r1.json()["summary"]
    assert s1["yara_matches"] == 1
    assert s1["stinger_hits"] == 1

    # Run scan a SECOND time — counts must remain 100% identical (zero accumulation!)
    r2 = client.post(f"/api/cases/{case_id}/malware/scan", json={"enable_yara": True, "enable_stinger": True, "enable_ocr": False})
    assert r2.status_code == 200
    s2 = r2.json()["summary"]
    assert s2["yara_matches"] == 1
    assert s2["stinger_hits"] == 1

    # Verify artifact_registry contains ONLY canonical malware artifact_ids (zero stale malware_yara / malware_stinger)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        mal_reg = dict(
            conn.execute(
                "SELECT artifact_id, row_count FROM artifact_registry WHERE category = 'MALWARE & YARA';"
            ).fetchall()
        )
        assert "malware_yara" not in mal_reg
        assert "malware_stinger" not in mal_reg
        assert mal_reg.get("malware_yara_hits") == 1
        assert mal_reg.get("malware_stinger_hits") == 1
        assert mal_reg.get("malware_all_detections") == 2

    # Verify /malware/hits alias + wildcard literal % escaping
    hits_match = client.get(f"/api/cases/{case_id}/malware/hits", params={"search": "100%"})
    assert hits_match.status_code == 200
    assert hits_match.json()["filtered_count"] >= 1
    assert len(hits_match.json()["hits"]) >= 1

    hits_nomatch = client.get(f"/api/cases/{case_id}/malware/hits", params={"search": "999%"})
    assert hits_nomatch.status_code == 200
    assert hits_nomatch.json()["filtered_count"] == 0


# ---------------------------------------------------------------------------
# §4. Real VFS/VSS/Carved Tree & Files, PE Analysis, & Path Confinement
# ---------------------------------------------------------------------------
def test_real_vfs_vss_carved_endpoints_pe_analysis_and_security_confinement(client, isolated_m5a_env):
    case_id = "m5a_vfs_case"
    case_dir = get_case_dir(case_id, create_if_missing=True)
    staging_dir = get_case_staging_dir(case_id)
    carved_dir = (case_dir / "carved").resolve()
    vss1_dir = (staging_dir / "VSS" / "vss_1" / "Users" / "Alice").resolve()
    carved_dir.mkdir(parents=True, exist_ok=True)
    vss1_dir.mkdir(parents=True, exist_ok=True)

    pe_bytes = _build_minimal_valid_pe_bytes()
    staged_exe = staging_dir / "Windows" / "System32" / "tool_sample.exe"
    staged_exe.parent.mkdir(parents=True, exist_ok=True)
    staged_exe.write_bytes(pe_bytes)

    carved_jpg = carved_dir / "carved_0001.jpg"
    carved_jpg.write_bytes(b"\xff\xd8\xff\xe0JFIF_CARVED_PAYLOAD")

    vss_secret = vss1_dir / "shadow_note.txt"
    vss_secret.write_text("Recovered from VSS shadow copy #1", encoding="utf-8")

    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vfs_partitions (_row_id, part_index, label, fs_type, offset_bytes, size_bytes, volume_serial, is_boot)
            VALUES (1, 0, 'OS_Volume', 'NTFS', 1048576, 21474836480, 'A1B2-C3D4', TRUE);
            """
        )
        cur.execute(
            """
            INSERT INTO vfs_shadow_copies (_row_id, vss_index, part_index, store_id, creation_time, size_bytes, staged_prefix, files_staged, status)
            VALUES (1, 1, 0, '{11111111-2222-3333-4444-555555555555}', '2026-02-01 08:00:00', 104857600, 'VSS/vss_1', 1, 'STAGED');
            """
        )
        cur.execute(
            """
            INSERT INTO parsed_carved_files (_row_id, carve_id, file_name, extension, size_bytes, sha256, carved_path, source_evidence)
            VALUES (1, 'carve_0001', 'carved_0001.jpg', 'jpg', 23, '1234abcd', 'carved/carved_0001.jpg', 'unallocated');
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_mft (
                _row_id BIGINT, EntryNumber BIGINT, SequenceNumber BIGINT, InUse BOOLEAN,
                ParentPath VARCHAR, FileName VARCHAR, Extension VARCHAR, FileSize BIGINT,
                IsDirectory BOOLEAN, Created0x10 TIMESTAMP, LastModified0x10 TIMESTAMP,
                LastAccess0x10 TIMESTAMP, LastRecordChange0x10 TIMESTAMP,
                Created0x30 TIMESTAMP, LastModified0x30 TIMESTAMP,
                LastAccess0x30 TIMESTAMP, LastRecordChange0x30 TIMESTAMP
            );
            """
        )
        # Include a timestomped file ($SI Created0x10 is years earlier than $FN Created0x30) + a deleted file
        cur.execute(
            """
            INSERT INTO raw_mft (
                _row_id, EntryNumber, SequenceNumber, InUse, ParentPath, FileName, Extension, FileSize,
                IsDirectory, Created0x10, LastModified0x10, LastAccess0x10, LastRecordChange0x10,
                Created0x30, LastModified0x30, LastAccess0x30, LastRecordChange0x30
            ) VALUES
                (1, 100, 1, TRUE, '.', 'Windows', '', 0, TRUE, '2026-01-01 00:00:00', '2026-01-01 00:00:00', '2026-01-01 00:00:00', '2026-01-01 00:00:00', '2026-01-01 00:00:00', '2026-01-01 00:00:00', '2026-01-01 00:00:00', '2026-01-01 00:00:00'),
                (2, 101, 1, TRUE, '.\\Windows\\System32', 'tool_sample.exe', '.exe', 1024, FALSE, '2020-01-01 00:00:00', '2020-01-01 00:00:00', '2026-01-10 00:00:00', '2026-01-10 00:00:00', '2026-01-10 00:00:00', '2026-01-10 00:00:00', '2026-01-10 00:00:00', '2026-01-10 00:00:00'),
                (3, 102, 2, FALSE, '.\\Windows\\System32', 'deleted_stage.dll', '.dll', 512, FALSE, '2026-01-05 00:00:00', '2026-01-05 00:00:00', '2026-01-05 00:00:00', '2026-01-05 00:00:00', '2026-01-05 00:00:00', '2026-01-05 00:00:00', '2026-01-05 00:00:00', '2026-01-05 00:00:00');
            """
        )

    # 1. /vfs/tree & /filesystem/tree expose real partitions, VSS #1, Carved Files, and Windows folder
    tree_res = client.get(f"/api/cases/{case_id}/vfs/tree")
    assert tree_res.status_code == 200
    tree_body = tree_res.json()
    assert len(tree_body["partitions"]) == 1
    assert tree_body["partitions"][0]["label"] == "OS_Volume"
    assert len(tree_body["shadow_copies"]) == 1
    assert tree_body["carved_files_count"] == 1
    folder_paths = {f["folder_path"] for f in tree_body["folders"]}
    assert "VSS #1" in folder_paths
    assert "Carved Files" in folder_paths
    assert ".\\Windows" in folder_paths

    # 2. /vfs/files checks $SI/$FN MACB + timestomped=True + include_deleted filter
    sys32_all = client.get(f"/api/cases/{case_id}/vfs/files", params={"folder_path": r".\Windows\System32", "include_deleted": True})
    assert sys32_all.status_code == 200
    files_all = sys32_all.json()["files"]
    assert len(files_all) == 2
    exe_entry = next(f for f in files_all if f["file_name"] == "tool_sample.exe")
    assert exe_entry["timestomped"] is True
    assert exe_entry["fn_created"] is not None

    sys32_alloc = client.get(f"/api/cases/{case_id}/filesystem/files", params={"folder_path": r".\Windows\System32", "include_deleted": False})
    assert sys32_alloc.status_code == 200
    assert [f["file_name"] for f in sys32_alloc.json()["files"]] == ["tool_sample.exe"]

    # 3. Carved Files listing + /vfs/hex + /vfs/download + VSS #1 preview + /vfs/pe-analysis
    carved_list = client.get(f"/api/cases/{case_id}/vfs/files", params={"carved_only": True})
    assert carved_list.status_code == 200
    assert carved_list.json()["total_files"] == 1
    assert carved_list.json()["files"][0]["file_name"] == "carved_0001.jpg"

    dl_carved = client.get(f"/api/cases/{case_id}/vfs/download", params={"path": r"Carved Files\carved_0001.jpg"})
    assert dl_carved.status_code == 200
    assert dl_carved.content == b"\xff\xd8\xff\xe0JFIF_CARVED_PAYLOAD"

    vss_prev = client.get(f"/api/cases/{case_id}/vfs/preview", params={"path": r"VSS #1\Users\Alice\shadow_note.txt"})
    assert vss_prev.status_code == 200
    assert "Recovered from VSS shadow copy #1" in vss_prev.json()["text_content"]

    pe_res = client.get(f"/api/cases/{case_id}/vfs/pe-analysis", params={"path": r"Windows\System32\tool_sample.exe"})
    assert pe_res.status_code == 200
    pe_json = pe_res.json()
    assert pe_json["is_pe"] is True
    assert any(s["name"] == ".text" for s in pe_json["sections"])

    # 4. Path traversal, case.duckdb, processing.log, UNC, and server CWD leak blocking
    (case_dir / "processing.log").write_text("internal log", encoding="utf-8")
    for forbidden_path in (
        r"..\..\Windows\win.ini",
        "case.duckdb",
        "case.duckdb.wal",
        "processing.log",
        r"\\10.0.0.1\c$\secret.txt",
        "pyproject.toml",
        "README.md",
    ):
        for ep in ("/vfs/hex", "/vfs/preview", "/vfs/download"):
            r_forb = client.get(f"/api/cases/{case_id}{ep}", params={"path": forbidden_path})
            assert r_forb.status_code in (400, 403, 404), f"Expected 4xx for {forbidden_path} on {ep}, got {r_forb.status_code}"


# ---------------------------------------------------------------------------
# §5. Bookmarks/Tags, Registry/Dashboard, Report HTML, Timeline, Escaping & Event Profiles
# ---------------------------------------------------------------------------
def test_bookmarks_dashboard_report_timeline_wildcards_and_readonly_event_profiles(client, isolated_m5a_env, monkeypatch):
    case_id = "m5a_query_case"
    init_case_db(case_id)

    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO case_metadata (key, value) VALUES
                ('case_name', 'XSS <script>alert(1)</script> Case'),
                ('examiner', 'Bob <b>DFIR</b>');
            """
        )
        cur.execute(
            """
            INSERT INTO raw_evtx (
                _row_id, EventId, Level, Provider, Channel, Computer, UserName,
                TimeCreated, MapDescription, PayloadData1, SourceFile
            ) VALUES
                (1, 4624, 'Information', 'Security-Auditing', 'Microsoft-Windows-PowerShell/Operational', 'WIN-HOST', 'alice', '2026-03-01 12:00:00', '100%_cpu_spike', 'C:\\Temp\\run_a.ps1', 'C:\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx'),
                (2, 4625, 'Warning', 'Security-Auditing', 'Security', 'WIN-HOST', 'bob', '2026-03-01 14:00:00', '2000_normal_event', 'C:\\Temp\\other.ps1', 'C:\\Logs\\Security.evtx');
            """
        )
        cur.execute(
            """
            INSERT INTO raw_recmd (
                _row_id, HivePath, KeyPath, ValueName, ValueData, LastWriteTimestamp
            ) VALUES
                (1, 'NTUSER.DAT', 'Software\\Run', 'Updater_100%', 'C:\\Updater\\up.exe', '2026-03-01 11:55:00');
            """
        )
        cur.execute(
            """
            INSERT INTO master_timeline (timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file, macb)
            VALUES
                (1, '2026-03-01 11:58:00', 'Created (Birth)', 'OPERATING SYSTEM', 'MFT', 'drop_100%.exe', 'C:\\Temp', 'File created 100%_literal', 'raw_recmd', 1, 'MFT', ''),
                (2, '2026-03-01 12:02:00', 'Last Modified', 'EVENT LOGS', 'EVTX', 'powershell.exe', 'alice', 'Script executed', 'raw_evtx', 1, 'PowerShell', 'M...'),
                (3, '2026-03-01 18:30:00', 'Last Accessed', 'WEB RELATED', 'Chrome', 'https://example.org', 'bob', 'Browser visit', 'raw_evtx', 2, 'History', '..A.');
            """
        )
        cur.execute(
            """
            INSERT INTO raw_regripper (_row_id, plugin_name, hive_name, hive_type, category, report_text, summary_line, output_lines_count)
            VALUES
                (1, 'run_key_100%', 'NTUSER.DAT', 'NTUSER', 'Autoruns', 'Key has 100%_ persistence', 'Autorun entry', 4),
                (2, 'services', 'SYSTEM', 'SYSTEM', 'Services', 'Key has 1000X normal service', 'Service entry', 3);
            """
        )

    # 1. Fresh GET /bookmarks BEFORE POST /bookmarks uses canonical DDL + GET /tags
    bm_init = client.get(f"/api/cases/{case_id}/bookmarks")
    assert bm_init.status_code == 200
    assert bm_init.json()["bookmarks"] == []

    bm_post = client.post(
        f"/api/cases/{case_id}/bookmarks",
        json={"source_table": "raw_evtx", "source_row_id": 1, "tag_name": "Lateral Movement", "examiner_notes": "Suspicious <tag>"},
    )
    assert bm_post.status_code == 200
    tags_res = client.get(f"/api/cases/{case_id}/tags")
    assert tags_res.status_code == 200
    assert tags_res.json()["tags"][0]["tag_name"] == "Lateral Movement"
    assert tags_res.json()["tags"][0]["count"] == 1

    # 2. /registry (/artifacts) exposes os_evtx & raw_recmd and matches /dashboard (11 SCOPE + 12 legacy keys)
    reg_res = client.get(f"/api/cases/{case_id}/artifacts")
    assert reg_res.status_code == 200
    reg_tables = {a["table_name"] for a in reg_res.json()["artifacts"]}
    assert "raw_evtx" in reg_tables
    assert "raw_recmd" in reg_tables

    dash_res = client.get(f"/api/cases/{case_id}/dashboard")
    assert dash_res.status_code == 200
    dash = dash_res.json()
    for scope_key in (
        "case_id", "case_metadata", "os_info", "partitions", "shadow_copies",
        "tool_execution_summary", "refined_highlights", "category_counts",
        "total_artifacts", "timeline_events", "min_timestamp_utc", "max_timestamp_utc",
    ):
        assert scope_key in dash, f"Missing SCOPE.md key {scope_key} in /dashboard"
    for rh_key in (
        "domains", "users", "keyword_hits_count", "carved_files_count",
        "bulk_extractor_hits_count", "malware_hits_count", "bookmarks_count",
    ):
        assert rh_key in dash["refined_highlights"], f"Missing refined_highlights.{rh_key} in /dashboard"
    for legacy_key in (
        "db_size_bytes", "total_artifact_rows", "timeline_total", "connections_total",
        "categories", "top_artifacts", "top_users", "top_domains", "top_executables",
        "yara_hits", "bookmarks",
    ):
        assert legacy_key in dash, f"Missing legacy key {legacy_key} in /dashboard"

    # 3. /report/html: 404 on unknown case with zero stray directory + XSS-escaped fallback HTML on valid case
    missing_cid = "totally_nonexistent_case_999"
    rep_404 = client.get(f"/api/cases/{missing_cid}/report/html")
    assert rep_404.status_code == 404
    assert not (isolated_m5a_env["cases_dir"] / missing_cid).exists()

    import backend.orchestrator.report_generator as _rep_mod
    monkeypatch.setattr(_rep_mod, "generate_case_html_report", lambda cid: (_ for _ in ()).throw(RuntimeError("Simulated report failure")))
    rep_ok = client.get(f"/api/cases/{case_id}/report/html")
    assert rep_ok.status_code == 200
    assert "<script>alert(1)</script>" not in rep_ok.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rep_ok.text

    # 4. /timeline/stats + /timeline sort_dir, synthesized macb='B', around_timestamp pivot, & bookmarked_only
    tl_stats = client.get(f"/api/cases/{case_id}/timeline/stats")
    assert tl_stats.status_code == 200
    assert tl_stats.json()["total_events"] == 3
    assert tl_stats.json()["min_timestamp_utc"] is not None
    assert tl_stats.json()["max_timestamp_utc"] is not None

    tl_asc = client.get(f"/api/cases/{case_id}/timeline", params={"sort_dir": "ASC"})
    assert tl_asc.status_code == 200
    ts_list = [r["timestamp_utc"] for r in tl_asc.json()["timeline"]]
    assert ts_list == sorted(ts_list)

    tl_birth = client.get(f"/api/cases/{case_id}/timeline", params={"macb": "B"})
    assert tl_birth.status_code == 200
    assert tl_birth.json()["filtered_count"] == 1
    assert "B" in tl_birth.json()["timeline"][0]["macb"]

    tl_pivot = client.get(
        f"/api/cases/{case_id}/timeline",
        params={"around_timestamp": "2026-03-01T12:00:00Z", "window_minutes": 10},
    )
    assert tl_pivot.status_code == 200
    assert tl_pivot.json()["filtered_count"] == 2

    # 5. Wildcard literal escaping (%, _, \) across /evtx/rows (%4), /table/{t}, /regripper/plugins, & /keywords
    evtx_pct = client.get(
        f"/api/cases/{case_id}/evtx/rows",
        params={"file_name": "Microsoft-Windows-PowerShell%4Operational.evtx", "search": "100%_cpu"},
    )
    assert evtx_pct.status_code == 200
    assert evtx_pct.json()["filtered_count"] == 1

    tbl_pct = client.get(f"/api/cases/{case_id}/table/raw_recmd", params={"search": "100%"})
    assert tbl_pct.status_code == 200
    assert tbl_pct.json()["filtered_count"] == 1

    rr_pct = client.get(f"/api/cases/{case_id}/regripper/plugins", params={"search": "100%_"})
    assert rr_pct.status_code == 200
    assert rr_pct.json()["total"] == 1
    assert len(rr_pct.json()["plugins"]) == 1

    kw_add = client.post(f"/api/cases/{case_id}/keywords", json={"keywords": ["100%_cpu"], "is_regex": False})
    assert kw_add.status_code == 200
    kw_entry = next(k for k in kw_add.json()["keywords"] if k["keyword"] == "100%_cpu")
    assert kw_entry["hit_count"] >= 1
    kw_rescan = client.post(f"/api/cases/{case_id}/keywords/scan")
    assert kw_rescan.status_code == 200

    # 6. Custom Event Profiles CRUD strictly READ-ONLY on rules/event_profiles.json
    builtin_rules_file = (_cfg.BASE_DIR / "rules" / "event_profiles.json").resolve()
    sha_before = hashlib.sha256(builtin_rules_file.read_bytes()).hexdigest()

    ep_get0 = client.get("/api/event-profiles")
    assert ep_get0.status_code == 200
    base_count = ep_get0.json()["total_profiles"]
    assert base_count >= 1

    ep_create = client.post(
        "/api/event-profiles",
        json={
            "id": "custom_ps_hunt",
            "name": "Custom PowerShell Hunt",
            "description": "Detect PowerShell 4624",
            "event_ids": [4624],
            "channels": ["PowerShell"],
        },
    )
    assert ep_create.status_code == 200
    assert ep_create.json()["total_profiles"] == base_count + 1
    assert isolated_m5a_env["event_profiles_file"].is_file()

    # Unsafe SQL injection in custom profile must be rejected with 400
    ep_bad = client.post(
        "/api/event-profiles",
        json={"id": "bad_sql", "name": "Bad", "sql": "1=1; DROP TABLE raw_evtx;"},
    )
    assert ep_bad.status_code == 400

    # PUT /api/event-profiles/raw updates profiles in external custom store
    updated_list = ep_create.json()["profiles"]
    for item in updated_list:
        if item["id"] == "custom_ps_hunt":
            item["description"] = "Updated via raw JSON editor"
    ep_put = client.put("/api/event-profiles/raw", json={"profiles": updated_list})
    assert ep_put.status_code == 200
    edited = next(p for p in ep_put.json()["profiles"] if p["id"] == "custom_ps_hunt")
    assert edited["description"] == "Updated via raw JSON editor"

    # DELETE /api/event-profiles/custom_ps_hunt removes custom profile
    ep_del = client.delete("/api/event-profiles/custom_ps_hunt")
    assert ep_del.status_code == 200
    assert all(p["id"] != "custom_ps_hunt" for p in ep_del.json()["profiles"])

    sha_after = hashlib.sha256(builtin_rules_file.read_bytes()).hexdigest()
    assert sha_after == sha_before, "rules/event_profiles.json MUST NEVER be modified!"


def test_persist_case_intake_metadata_double_call_2col_and_3col_schemas(isolated_m5a_env):
    """
    Regression test for DuckDB 2.0.0 ON CONFLICT DO UPDATE SQL binder:
    Verify _persist_case_intake_metadata_and_keywords succeeds across repeated calls
    (triggering ON CONFLICT update path) on BOTH 2-column (key, value) and 3-column
    (key, value, updated_at) case_metadata schemas.
    """
    kw_specs_1 = _main._normalize_keyword_specs(["first_ioc"])
    kw_specs_2 = _main._normalize_keyword_specs(["first_ioc", {"keyword": "second_ioc", "case_sensitive": True}])

    # 1. 3-column (key, value, updated_at) schema from init_case_db / CORE_SCHEMA_SQL
    cid_3col = "m5a_meta_3col_case"
    _main._persist_case_intake_metadata_and_keywords(cid_3col, {"case_name": "Run 1", "examiner": "Ex1"}, kw_specs_1)
    _main._persist_case_intake_metadata_and_keywords(cid_3col, {"case_name": "Run 2", "examiner": "Ex2"}, kw_specs_2)
    with DuckDBManager.get_lock(cid_3col):
        conn3 = DuckDBManager.get_connection(cid_3col, read_only=False)
        cols3 = {r[1] for r in conn3.execute("PRAGMA table_info('case_metadata');").fetchall()}
        assert "updated_at" in cols3
        meta3 = dict(conn3.execute("SELECT key, value FROM case_metadata;").fetchall())
        assert meta3["case_name"] == "Run 2"
        assert meta3["examiner"] == "Ex2"

    # 2. Strictly 2-column (key VARCHAR PRIMARY KEY, value VARCHAR) schema
    cid_2col = "m5a_meta_2col_case"
    init_case_db(cid_2col)
    with DuckDBManager.get_lock(cid_2col):
        conn2 = DuckDBManager.get_connection(cid_2col, read_only=False)
        conn2.execute("DROP TABLE IF EXISTS case_metadata;")
        conn2.execute("CREATE TABLE case_metadata (key VARCHAR PRIMARY KEY, value VARCHAR);")

    # Note: _persist_case_intake_metadata_and_keywords calls init_case_db which uses CREATE TABLE IF NOT EXISTS,
    # keeping our 2-column table intact!
    _main._persist_case_intake_metadata_and_keywords(cid_2col, {"case_name": "TwoCol 1", "notes": "v1"}, kw_specs_1)
    _main._persist_case_intake_metadata_and_keywords(cid_2col, {"case_name": "TwoCol 2", "notes": "v2"}, kw_specs_2)
    with DuckDBManager.get_lock(cid_2col):
        conn2 = DuckDBManager.get_connection(cid_2col, read_only=False)
        cols2 = [r[1] for r in conn2.execute("PRAGMA table_info('case_metadata');").fetchall()]
        assert cols2 == ["key", "value"]
        meta2 = dict(conn2.execute("SELECT key, value FROM case_metadata;").fetchall())
        assert meta2["case_name"] == "TwoCol 2"
        assert meta2["notes"] == "v2"


# ---------------------------------------------------------------------------
# §6. Iteration 2 Remediation Regression Suite (Fixes 1–8 / SCOPE.md §§8–9)
# ---------------------------------------------------------------------------
def test_r2_spa_path_traversal_and_encoded_backslash_confinement(client, tmp_path, monkeypatch):
    """SCOPE.md §8: serve_frontend_spa blocks %5c, %2e%2e, .., colons, and NUL with HTTP 403."""
    import httpx
    import io
    import json
    import zipfile

    fake_dist = (tmp_path / "fake_dist").resolve()
    fake_dist.mkdir(parents=True, exist_ok=True)
    (fake_dist / "index.html").write_text("<!DOCTYPE html><html><body>WFT SPA</body></html>", encoding="utf-8")
    (fake_dist / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    monkeypatch.setattr(_main, "dist_dir", fake_dist)

    # 1. Encoded backslash (%5c) and un-normalized raw_path %2e%2e MUST return 403 (never 200 index.html or host file)
    r_bs = client.get("/..%5c..%5crules%5cevent_profiles.json")
    assert r_bs.status_code == 403
    assert "event_ids" not in r_bs.text
    assert "WFT SPA" not in r_bs.text

    for raw_payload in (
        b"/%2e%2e/%2e%2e/requirements.txt",
        b"/..%5c..%5cpyproject.toml",
        b"/assets/..%5c..%5crules%5cevent_profiles.json",
        b"/C:%5cWindows%5cwin.ini",
    ):
        req = client.build_request("GET", httpx.URL("http://testserver", raw_path=raw_payload))
        resp = client.send(req)
        assert resp.status_code in (403, 404), f"Unexpected status {resp.status_code} for {raw_payload!r}"
        if raw_payload.startswith((b"/%2e%2e", b"/..%5c", b"/C:")):
            assert resp.status_code == 403
        assert "fastapi" not in resp.text.lower()
        assert "WFT SPA" not in resp.text

    # 2. Valid static asset & valid client-side SPA route serve cleanly; unknown /api/* returns 404
    r_asset = client.get("/favicon.svg")
    assert r_asset.status_code == 200
    assert "<svg/>" in r_asset.text

    r_spa = client.get("/cases/demo-case/timeline")
    assert r_spa.status_code == 200
    assert "WFT SPA" in r_spa.text

    r_api_404 = client.get("/api/unknown_endpoint_xyz")
    assert r_api_404.status_code == 404


def test_r2_contract2_contract3_vfs_fat16_vss_and_carved_schemas(client, isolated_m5a_env):
    """SCOPE.md §9(a)(b): Strict 17-col vfs_files, FAT16 vfs_files-only, 8-col vfs_shadow_copies, 10-col parsed_carved_files, and real process_case."""
    cid = "m5a_contract23_fat16"
    init_case_db(cid)
    case_dir = get_case_dir(cid, create_if_missing=True)
    staging_dir = get_case_staging_dir(cid)
    staging_dir.mkdir(parents=True, exist_ok=True)
    carved_dir = (case_dir / "carved").resolve()
    carved_dir.mkdir(parents=True, exist_ok=True)

    (staging_dir / "Docs").mkdir(parents=True, exist_ok=True)
    (staging_dir / "Docs" / "P1NOTE.TXT").write_text("FAT16 note content", encoding="utf-8")
    (staging_dir / "VSS" / "VSS_1" / "Users" / "alice").mkdir(parents=True, exist_ok=True)
    (staging_dir / "VSS" / "VSS_1" / "Users" / "alice" / "vss_secret.txt").write_text("VSS1 secret payload", encoding="utf-8")
    (carved_dir / "00001.pdf").write_bytes(b"%PDF-1.7-CARVED-DOC")

    with DuckDBManager.get_lock(cid):
        conn = DuckDBManager.get_connection(cid, read_only=False)
        cur = conn.cursor()
        # Replace tables with strict Contract 2 & Contract 3 schemas (NO _row_id/description/inode/extension/vss_store_index/file_name)
        for tbl in ("vfs_partitions", "vfs_shadow_copies", "vfs_files", "parsed_carved_files"):
            cur.execute(f"DROP TABLE IF EXISTS {tbl};")
        cur.execute("DELETE FROM raw_mft;")
        cur.execute(
            """
            CREATE TABLE vfs_partitions (
                part_index INTEGER, fs_type VARCHAR, start_offset BIGINT,
                size_bytes BIGINT, volume_label VARCHAR, is_bootable BOOLEAN
            );
            INSERT INTO vfs_partitions VALUES (0, 'FAT16', 1048576, 67108864, 'FAT16_VOL', TRUE);

            CREATE TABLE vfs_shadow_copies (
                vss_index INTEGER, store_id VARCHAR, creation_time_utc VARCHAR,
                part_index INTEGER, status VARCHAR, shadow_copy_size BIGINT,
                files_staged INTEGER, staged_prefix VARCHAR
            );
            INSERT INTO vfs_shadow_copies VALUES (1, 'guid-vss-1', '2026-03-01T10:00:00Z', 2, 'STAGED', 4096000, 1, 'VSS/VSS_1');

            CREATE TABLE vfs_files (
                part_index INTEGER, vfs_path VARCHAR, staged_rel_path VARCHAR, file_name VARCHAR,
                parent_path VARCHAR, size_bytes BIGINT, is_dir BOOLEAN, is_deleted BOOLEAN,
                si_created_utc VARCHAR, si_modified_utc VARCHAR, si_accessed_utc VARCHAR, si_changed_utc VARCHAR,
                fn_created_utc VARCHAR, fn_modified_utc VARCHAR, fn_accessed_utc VARCHAR, fn_changed_utc VARCHAR,
                mft_entry BIGINT
            );
            INSERT INTO vfs_files VALUES
                (0, '/Docs', 'Docs', 'Docs', '/', 0, TRUE, FALSE, '2026-03-01T08:00:00Z', '2026-03-01T08:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL, 10),
                (0, '/Docs/P1NOTE.TXT', 'Docs/P1NOTE.TXT', 'P1NOTE.TXT', '/Docs', 18, FALSE, FALSE, '2026-03-01T08:05:00Z', '2026-03-01T08:05:00Z', NULL, NULL, NULL, NULL, NULL, NULL, 11),
                (-1, '/VSS_1', 'VSS/VSS_1', 'VSS_1', '/', 0, TRUE, FALSE, '2026-02-28T08:00:00Z', '2026-02-28T08:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL, 20),
                (-1, '/VSS_1/Users', 'VSS/VSS_1/Users', 'Users', '/VSS_1', 0, TRUE, FALSE, '2026-02-28T08:00:00Z', '2026-02-28T08:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL, 21),
                (-1, '/VSS_1/Users/alice', 'VSS/VSS_1/Users/alice', 'alice', '/VSS_1/Users', 0, TRUE, FALSE, '2026-02-28T08:00:00Z', '2026-02-28T08:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL, 22),
                (-1, '/VSS_1/Users/alice/vss_secret.txt', 'VSS/VSS_1/Users/alice/vss_secret.txt', 'vss_secret.txt', '/VSS_1/Users/alice', 19, FALSE, FALSE, '2026-02-28T08:10:00Z', '2026-02-28T08:10:00Z', NULL, NULL, NULL, NULL, NULL, NULL, 23);

            CREATE TABLE parsed_carved_files (
                carve_id INTEGER, file_type VARCHAR, extension VARCHAR, carved_rel_path VARCHAR,
                size_bytes BIGINT, sha256 VARCHAR, img_offset BIGINT, source_region VARCHAR,
                part_index INTEGER, is_valid BOOLEAN
            );
            INSERT INTO parsed_carved_files VALUES (1, 'PDF', 'pdf', 'carved/00001.pdf', 19, 'abcd', 4096, 'unallocated', 0, TRUE);
            """
        )

    # 1. /filesystem/tree preserves vfs_partitions label without description col, vss part_index=2, and isolates VSS_1 from live root
    tree_r = client.get(f"/api/cases/{cid}/filesystem/tree")
    assert tree_r.status_code == 200
    tree_j = tree_r.json()
    assert tree_j["partitions"][0]["label"] == "FAT16_VOL"
    assert tree_j["shadow_copies"][0]["part_index"] == 2
    live_folder_names = {f["name"] for f in tree_j["folders"]}
    assert "Docs" in live_folder_names
    assert "VSS_1" not in live_folder_names

    # 2. FAT16 vfs_files-only /filesystem/files with ?part_index=0, ?path=/Docs, and ?search=P1NOTE
    f_root = client.get(f"/api/cases/{cid}/filesystem/files")
    assert f_root.status_code == 200
    assert [x["file_name"] for x in f_root.json()["files"]] == ["Docs"]

    f_docs = client.get(f"/api/cases/{cid}/filesystem/files", params={"part_index": 0, "path": "/Docs"})
    assert f_docs.status_code == 200
    assert [x["file_name"] for x in f_docs.json()["files"]] == ["P1NOTE.TXT"]
    assert f_docs.json()["files"][0]["extension"] == "txt"

    f_search = client.get(f"/api/cases/{cid}/filesystem/files", params={"part_index": 0, "path": "/Docs", "search": "P1NOTE"})
    assert f_search.status_code == 200
    assert [x["file_name"] for x in f_search.json()["files"]] == ["P1NOTE.TXT"]

    # 3. Negative part_index=-1 VSS #1 listing & preview + 10-col parsed_carved_files listing & download
    f_vss = client.get(f"/api/cases/{cid}/filesystem/files", params={"vss_index": 1, "path": "/Users/alice"})
    assert f_vss.status_code == 200
    assert any(x["file_name"] == "vss_secret.txt" for x in f_vss.json()["files"])
    p_vss = client.get(f"/api/cases/{cid}/vfs/preview", params={"path": r"VSS #1\Users\alice\vss_secret.txt"})
    assert p_vss.status_code == 200
    assert "VSS1 secret payload" in p_vss.json()["text_content"]

    f_carved = client.get(f"/api/cases/{cid}/filesystem/files", params={"carved_only": True})
    assert f_carved.status_code == 200
    assert f_carved.json()["files"][0]["file_name"] == "00001.pdf"
    dl_carved = client.get(f"/api/cases/{cid}/vfs/download", params={"path": r"Carved Files\00001.pdf"})
    assert dl_carved.status_code == 200
    assert dl_carved.content == b"%PDF-1.7-CARVED-DOC"

    # 4. Real POST /api/cases/process (unmocked pipeline) -> /filesystem/tree & /filesystem/files return 200
    real_src = (isolated_m5a_env["tmp_path"] / "real_folder_src").resolve()
    (real_src / "SubFolder").mkdir(parents=True, exist_ok=True)
    (real_src / "SubFolder" / "hello.txt").write_text("real pipeline test", encoding="utf-8")
    real_proc = client.post(
        "/api/cases/process",
        json={
            "case_name": "Real Folder Pipeline",
            "case_id": "m5a_real_pipe",
            "source_type": "folder",
            "source_path": str(real_src),
            "enable_yara": False,
            "enable_ioc": False,
            "enable_ocr": False,
            "enable_stinger": False,
            "enable_hindsight": False,
            "run_async": False,
        },
    )
    assert real_proc.status_code == 200
    assert client.get("/api/cases/m5a_real_pipe/filesystem/tree").status_code == 200
    assert client.get("/api/cases/m5a_real_pipe/filesystem/files").status_code == 200


def test_r2_canonical_email_category_table_validation_and_ntfs_export_confinement(client, isolated_m5a_env, tmp_path):
    """SCOPE.md §9(c)(d)(f): 'EMAIL & CALENDAR', 400/404 table validation, NTFS export confinement, & copytree ignore."""
    cid = "m5a_email_export_case"
    init_case_db(cid)
    case_dir = get_case_dir(cid, create_if_missing=True)
    staging_dir = get_case_staging_dir(cid)
    staging_dir.mkdir(parents=True, exist_ok=True)
    src_evidence = (tmp_path / "src_evidence_guard").resolve()
    src_evidence.mkdir(parents=True, exist_ok=True)
    (case_dir / "processing.log").write_text("internal processing log", encoding="utf-8")

    # Populate valid staged folder alongside decoy NTFS metadata & DB files inside it
    user_docs = staging_dir / "Users" / "Alice" / "Documents"
    user_docs.mkdir(parents=True, exist_ok=True)
    (user_docs / "clean_report.txt").write_text("Legitimate exported document", encoding="utf-8")
    (user_docs / "$MFT").write_bytes(b"NTFS_META")
    (user_docs / "$UsnJrnl").write_bytes(b"USN_META")
    (user_docs / "$Extend").mkdir(exist_ok=True)
    (user_docs / "$Extend" / "$RmMetadata").write_bytes(b"EXTEND_META")
    (user_docs / "case.duckdb").write_bytes(b"DECOY_DB")
    (user_docs / "processing.log").write_text("DECOY_LOG", encoding="utf-8")

    # Also stage restricted NTFS folders to ensure export endpoints still block them
    for sys_f in ("$Recycle.Bin", "PerfLogs", "Config.Msi", "System Volume Information", "$Extend"):
        d = staging_dir / sys_f
        d.mkdir(parents=True, exist_ok=True)
        (d / "secret.bin").write_bytes(b"SYSTEM_RESTRICTED")

    with DuckDBManager.get_lock(cid):
        conn = DuckDBManager.get_connection(cid, read_only=False)
        cur = conn.cursor()
        cur.execute("INSERT INTO case_metadata (key, value) VALUES ('source_path', ?);", [str(src_evidence)])
        cur.execute("DROP TABLE IF EXISTS parsed_emails;")
        cur.execute("CREATE TABLE parsed_emails (_row_id BIGINT, sender VARCHAR, subject VARCHAR);")
        cur.execute("INSERT INTO parsed_emails VALUES (1, 'soc@corp.local', 'Incident Alert');")
        cur.execute(
            """
            INSERT INTO artifact_registry (artifact_id, category, display_name, table_name, source_tool, row_count)
            VALUES ('email_pst', 'EMAIL', 'PST & MBOX Emails', 'parsed_emails', 'EmailParser', 1);
            """
        )
        cur.execute(
            """
            INSERT INTO master_timeline (timeline_id, timestamp_utc, timestamp_type, category, artifact_name, primary_entity, secondary_entity, summary, source_table, source_row_id, source_file, macb)
            VALUES (1, '2026-03-02 09:00:00', 'Sent', 'EMAIL', 'PST Email', 'soc@corp.local', 'cto@corp.local', 'Incident Alert', 'parsed_emails', 1, 'outlook.pst', 'M...');
            """
        )

    # 1. Canonical 'EMAIL & CALENDAR' across /registry, /artifacts/tree, /dashboard, and /timeline
    assert "EMAIL & CALENDAR" in _main.CANONICAL_CATEGORIES
    assert "EMAIL" not in _main.CANONICAL_CATEGORIES
    for ep in (f"/api/cases/{cid}/registry", f"/api/cases/{cid}/artifacts/tree"):
        r_reg = client.get(ep)
        assert r_reg.status_code == 200
        cats = {a["category"] for a in r_reg.json()["artifacts"]}
        assert "EMAIL & CALENDAR" in cats
        assert "EMAIL" not in cats
        assert "EMAIL & CALENDAR" in r_reg.json()["grouped"]

    r_dash = client.get(f"/api/cases/{cid}/dashboard")
    assert r_dash.status_code == 200
    assert r_dash.json()["category_counts"].get("EMAIL & CALENDAR", 0) >= 1
    assert "EMAIL" not in r_dash.json()["category_counts"]

    for tl_cat in ("EMAIL", "EMAIL & CALENDAR"):
        r_tl = client.get(f"/api/cases/{cid}/timeline", params={"category": tl_cat})
        assert r_tl.status_code == 200
        assert r_tl.json()["filtered_count"] == 1
        assert r_tl.json()["timeline"][0]["category"] == "EMAIL & CALENDAR"

    # 2. Strict Table Validation: 400 on SQL injection / invalid chars, 404 on missing table, 200 on valid CSV/JSON export
    sqli_tbl = "parsed_emails; DROP TABLE parsed_emails;--"
    assert client.get(f"/api/cases/{cid}/table/{sqli_tbl}").status_code == 400
    assert client.post(f"/api/cases/{cid}/artifacts/{sqli_tbl}/query", json={}).status_code == 400
    assert client.get(f"/api/cases/{cid}/table/{sqli_tbl}/export/csv").status_code == 400
    assert client.get(f"/api/cases/{cid}/table/{sqli_tbl}/export/json").status_code == 400

    assert client.get(f"/api/cases/{cid}/table/nonexistent_table_xyz").status_code == 404
    assert client.get(f"/api/cases/{cid}/table/nonexistent_table_xyz/export/csv").status_code == 404
    assert client.get(f"/api/cases/{cid}/table/nonexistent_table_xyz/export/json").status_code == 404

    r_json_exp = client.get(f"/api/cases/{cid}/table/parsed_emails/export/json")
    assert r_json_exp.status_code == 200
    assert r_json_exp.json()[0]["sender"] == "soc@corp.local"

    # 3. NTFS folder export confinement & save_to_folder copytree ignore filter
    safe_out = (tmp_path / "safe_export_out").resolve()
    for bad_folder in (
        r"C:\$Recycle.Bin",
        r"C:\$Recycle.Bin\S-1-5-21-1000",
        r"C:\PerfLogs",
        r"C:\Config.Msi",
        r"C:\System Volume Information",
        r"C:\$Extend",
        r"C:\NonExistentFolder999",
    ):
        rz = client.get(f"/api/cases/{cid}/export/folder-zip", params={"folder_path": bad_folder})
        assert rz.status_code in (400, 404), f"Expected 400/404 for {bad_folder}, got {rz.status_code}"
        rs = client.post(f"/api/cases/{cid}/export/save-to-folder", json={"folder_path": bad_folder, "dest_dir": str(safe_out)})
        assert rs.status_code in (400, 404), f"Expected 400/404 save-to-folder for {bad_folder}, got {rs.status_code}"

    # Reject dest_dir overlapping case_dir or source_path
    assert client.post(
        f"/api/cases/{cid}/export/save-to-folder",
        json={"folder_path": r"C:\Users\Alice\Documents", "dest_dir": str(case_dir / "inside_case")},
    ).status_code == 400
    assert client.post(
        f"/api/cases/{cid}/export/save-to-folder",
        json={"folder_path": r"C:\Users\Alice\Documents", "dest_dir": str(src_evidence / "inside_src")},
    ).status_code == 400

    # Valid folder export strips $MFT, $UsnJrnl, $Extend, case.duckdb, and processing.log
    r_save = client.post(
        f"/api/cases/{cid}/export/save-to-folder",
        json={"folder_path": r"C:\Users\Alice\Documents", "dest_dir": str(safe_out)},
    )
    assert r_save.status_code == 200
    exported_dir = Path(r_save.json()["saved_path"])
    exported_names = {p.name for p in exported_dir.rglob("*")}
    assert "clean_report.txt" in exported_names
    assert exported_names.isdisjoint({"$MFT", "$UsnJrnl", "$Extend", "$RmMetadata", "case.duckdb", "processing.log"})


def test_r2_event_profile_sql_sandbox_evtx_channel_malware_ioc_and_entity_guards(client, isolated_m5a_env, monkeypatch):
    """SCOPE.md §9(g) + Fix 8: Profile SQL sandbox, built-in compatibility, %4 channel, enable_ioc, scalar filters, missing entity_connections."""
    # 1. 100% of built-in rules/event_profiles.json pass _is_unsafe_profile_sql
    builtins = _main._load_builtin_event_profiles()
    assert len(builtins) >= 10
    for bp in builtins:
        sql_s = str(bp.get("sql") or "").strip()
        if sql_s:
            assert not _main._is_unsafe_profile_sql(sql_s), f"Built-in profile {bp.get('id')} flagged as unsafe: {sql_s}"

    # 2. Custom profile blocks SELECT, UNION, read_*, glob, information_schema, and unbalanced parens with 400
    for unsafe_expr in (
        "1=1 UNION SELECT * FROM case_metadata",
        "EXISTS (SELECT 1 FROM information_schema.tables)",
        "Payload ILIKE read_text('secret.txt')",
        "Channel IN (SELECT * FROM glob('*'))",
        "1=1) OR (1=1",
    ):
        r_u = client.post("/api/event-profiles", json={"id": "bad_p", "name": "Bad", "sql": unsafe_expr})
        assert r_u.status_code == 400, f"Expected 400 for unsafe SQL: {unsafe_expr}"

    # 3. %4 channel decoding with escape_ilike (excludes X4 / _4 wildcard decoys) + scalar column_filters + missing entity_connections
    cid = "m5a_evtx_guard_case"
    init_case_db(cid)
    with DuckDBManager.get_lock(cid):
        conn = DuckDBManager.get_connection(cid, read_only=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO raw_evtx (_row_id, EventId, Level, Channel, UserName, TimeCreated, SourceFile) VALUES
                (1, 1, 'Information', 'Microsoft-Windows-Sysmon/Operational', 'alice', '2026-03-01 10:00:00', 'C:\\Logs\\Sysmon.evtx'),
                (2, 1, 'Information', 'Microsoft-Windows-SysmonX4Operational', 'bob', '2026-03-01 10:01:00', 'C:\\Logs\\DecoyX4.evtx'),
                (3, 1, 'Information', 'Microsoft-Windows-Sysmon_4Operational', 'eve', '2026-03-01 10:02:00', 'C:\\Logs\\Decoy_4.evtx');
            """
        )
        cur.execute("DROP TABLE IF EXISTS entity_connections;")

    r_ch = client.get(
        f"/api/cases/{cid}/eventlogs/query",
        params={"channel": "Microsoft-Windows-Sysmon%4Operational.evtx"},
    )
    assert r_ch.status_code == 200
    assert r_ch.json()["filtered_count"] == 1
    assert r_ch.json()["rows"][0]["Channel"] == "Microsoft-Windows-Sysmon/Operational"

    r_sc = client.post(
        f"/api/cases/{cid}/artifacts/raw_evtx/query",
        json={"column_filters": {"EventId": 1, "UserName": "alice"}},
    )
    assert r_sc.status_code == 200
    assert r_sc.json()["filtered_count"] == 1

    r_sc_get = client.get(
        f"/api/cases/{cid}/table/raw_evtx",
        params={"column_filters": '{"EventId": 1, "UserName": "alice"}'},
    )
    assert r_sc_get.status_code == 200
    assert r_sc_get.json()["filtered_count"] == 1

    r_ent = client.get(f"/api/cases/{cid}/entities")
    assert r_ent.status_code == 200
    assert r_ent.json()["nodes"] == []
    assert r_ent.json()["edges"] == []

    # 4. trigger_malware_scan forwards enable_ioc=req.enable_stinger when enable_stinger=False
    captured_scan: Dict[str, Any] = {}

    class SpyEnrichment:
        def __init__(self, case_id: str):
            captured_scan["case_id"] = case_id

        def run(self, enable_yara: bool = True, enable_ioc: bool = True, enable_ocr: bool = True, enable_stinger: bool = True):
            captured_scan["kwargs"] = {
                "enable_yara": enable_yara,
                "enable_ioc": enable_ioc,
                "enable_ocr": enable_ocr,
                "enable_stinger": enable_stinger,
            }
            return {"yara_hits": 0, "stinger_hits": 0}

    monkeypatch.setattr(_main, "FileEnrichmentEngine", SpyEnrichment)
    r_scan = client.post(
        f"/api/cases/{cid}/malware/scan",
        json={"enable_yara": True, "enable_stinger": False, "enable_ocr": False},
    )
    assert r_scan.status_code == 200
    assert captured_scan["kwargs"]["enable_stinger"] is False
    assert captured_scan["kwargs"]["enable_ioc"] is False

    # 5. Single .txt file keyword deduplication (parsed_text_documents + staged file -> hit_count == 1)
    stg_guard = get_case_staging_dir(cid)
    stg_guard.mkdir(parents=True, exist_ok=True)
    (stg_guard / "secret_note.txt").write_text("Token ExactCaseSecret_Alpha once", encoding="utf-8")
    with DuckDBManager.get_lock(cid):
        conn = DuckDBManager.get_connection(cid, read_only=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO parsed_text_documents (_row_id, file_path, file_name, file_type, extension, file_size_bytes, content_preview, text_preview, source_file)
            VALUES (1, 'C:\\EvidenceSrc\\secret_note.txt', 'secret_note.txt', 'txt', '.txt', 32, 'Token ExactCaseSecret_Alpha once', 'Token ExactCaseSecret_Alpha once', 'C:\\EvidenceSrc\\secret_note.txt');
            """
        )
        # Also populate Stinger (_row_id=1) & YARA (_row_id=1) and bookmark ONLY Stinger _row_id=1
        cur.execute(
            """
            INSERT INTO artifact_stinger_hits (_row_id, file_path, file_name, malware_name, detection_type, engine)
            VALUES (1, 'C:\\Temp\\stinger_hit.exe', 'stinger_hit.exe', 'Trojan.StingerTest', 'Threat', 'Trellix Stinger');
            INSERT INTO artifact_yara_hits (_row_id, file_path, file_name, rule_name, severity)
            VALUES (1, 'C:\\Temp\\yara_hit.exe', 'yara_hit.exe', 'Rule_YaraTest', 'High');
            """
        )

    r_kw1 = client.post(
        f"/api/cases/{cid}/keywords",
        json={"keywords": ["ExactCaseSecret_Alpha"], "case_sensitive": True},
    )
    assert r_kw1.status_code == 200
    kw_obj = next(k for k in r_kw1.json()["keywords"] if k["keyword"] == "ExactCaseSecret_Alpha")
    assert kw_obj["hit_count"] == 1

    # 6. /malware/hits?bookmarked_only=true tuple match does not conflate Stinger _row_id=1 with YARA _row_id=1
    bm_m = client.post(
        f"/api/cases/{cid}/bookmarks",
        json={"source_table": "artifact_stinger_hits", "source_row_id": 1, "tag_name": "Confirmed Malware"},
    )
    assert bm_m.status_code == 200
    r_mhits = client.get(f"/api/cases/{cid}/malware/hits", params={"bookmarked_only": True})
    assert r_mhits.status_code == 200
    assert r_mhits.json()["filtered_count"] == 1
    assert r_mhits.json()["hits"][0]["file_name"] == "stinger_hit.exe"


# ---------------------------------------------------------------------------
# §7. Iteration 3 Surgical Remediation Suite (All 6 Fixes)
# ---------------------------------------------------------------------------
def test_r3_spa_double_slash_vss_wrapper_dashboard_labels_sql_lexer_and_tx_batch(
    client, isolated_m5a_env, tmp_path, monkeypatch
):
    """
    Iteration 3 regression test verifying:
    1. serve_frontend_spa double-slash / UNC 403 guard (//evil/share, /%2fevil/share) while keeping / & SPA routes 200 and /api/* 404.
    2. _is_unsafe_profile_sql single-pass character lexer (18/18 built-in profiles pass; $$, $q$, E'\\'', x'', b'', U&'', \"bad'id\" -> 400).
    3. Unconditional root VSS_<N> wrapper exclusion in /filesystem/tree & /filesystem/files (?vss_index=1) while keeping nested /VSS_1/Users/VSS_1.
    4. Normalized partitions & shadow_copies in GET /api/cases/{case_id}/dashboard on 6-col vfs_partitions & variant vfs_shadow_copies.
    5. Single-transaction batching + ROLLBACK atomicity in _persist_case_intake_metadata_and_keywords.
    6. Exact scalar bool/numeric column_filters (4624 != 46240) + /export/folder and /keywords/hits route aliases.
    """
    import httpx
    import io
    import json
    import zipfile

    # --- 1. serve_frontend_spa double-slash / UNC 403 guard ---
    fake_dist = (tmp_path / "r3_fake_dist").resolve()
    fake_dist.mkdir(parents=True, exist_ok=True)
    (fake_dist / "index.html").write_text("<!DOCTYPE html><html><body>WFT R3 SPA</body></html>", encoding="utf-8")
    monkeypatch.setattr(_main, "dist_dir", fake_dist)

    for raw_unc in (b"//evil/share", b"//evil.example/share", b"/%2fevil/share", b"/%2Fevil/share", b"/%252fevil/share"):
        req_unc = httpx.Request("GET", httpx.URL(scheme="http", host="testserver", raw_path=raw_unc))
        resp_unc = client.send(req_unc)
        assert resp_unc.status_code == 403, f"Expected 403 for {raw_unc!r}, got {resp_unc.status_code}"
        assert "WFT R3 SPA" not in resp_unc.text

    assert client.get("/%2fevil/share").status_code == 403

    # Also verify direct ASGI scope handoff (matching Uvicorn HTTP parser for GET //evil/share)
    import asyncio

    async def _probe_asgi(path_s: str, raw_b: bytes) -> int:
        captured_status = 0
        sent_req = False

        async def _recv():
            nonlocal sent_req
            if not sent_req:
                sent_req = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.Future()

        async def _send(msg):
            nonlocal captured_status
            if msg.get("type") == "http.response.start":
                captured_status = int(msg["status"])

        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": path_s,
                "raw_path": raw_b,
                "query_string": b"",
                "headers": [(b"host", b"127.0.0.1:8765")],
                "client": ("127.0.0.1", 50000),
                "server": ("127.0.0.1", 8765),
            },
            _recv,
            _send,
        )
        return captured_status

    assert asyncio.run(_probe_asgi("//evil/share", b"//evil/share")) == 403
    assert asyncio.run(_probe_asgi("/%2fevil/share", b"/%2fevil/share")) == 403
    assert asyncio.run(_probe_asgi("/", b"/")) == 200
    assert asyncio.run(_probe_asgi("/cases/123/timeline", b"/cases/123/timeline")) == 200

    r_root = client.get("/")
    assert r_root.status_code == 200 and "WFT R3 SPA" in r_root.text
    r_spa = client.get("/cases/123/timeline")
    assert r_spa.status_code == 200 and "WFT R3 SPA" in r_spa.text
    assert client.get("/api/nonexistent").status_code == 404

    # --- 2. _is_unsafe_profile_sql single-pass character lexer ---
    builtins = _main._load_builtin_event_profiles()
    assert len(builtins) == 18
    for bp in builtins:
        sql_expr = str(bp.get("sql") or "").strip()
        assert sql_expr and not _main._is_unsafe_profile_sql(sql_expr), f"Built-in {bp.get('id')} rejected!"

    # Valid SQL with doubled quotes, regex $ inside '...', backslash inside '...', and clean quoted identifier
    valid_sql = r"""Channel = 'O''Reilly' AND "EventId" = 4624 AND regexp_matches(PayloadData1, 'admin\s+9($|[^0-9])', 'i')"""
    assert _main._is_unsafe_profile_sql(valid_sql) is False
    r_valid_ep = client.post("/api/event-profiles", json={"id": "r3_valid_prof", "name": "R3 Valid", "sql": valid_sql})
    assert r_valid_ep.status_code == 200

    cid_r3 = "m5a_r3_case"
    init_case_db(cid_r3)
    case_dir = get_case_dir(cid_r3, create_if_missing=True)
    stg_dir = get_case_staging_dir(cid_r3)
    (stg_dir / "Exports").mkdir(parents=True, exist_ok=True)
    (stg_dir / "Exports" / "report_ok.txt").write_text("Exportable R3 report", encoding="utf-8")
    (stg_dir / "Exports" / "$MFT").write_bytes(b"HIDDEN_MFT")
    (stg_dir / "$Recycle.Bin").mkdir(parents=True, exist_ok=True)

    with DuckDBManager.get_lock(cid_r3):
        conn = DuckDBManager.get_connection(cid_r3, read_only=False)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO raw_evtx (_row_id, EventId, Level, Channel, UserName, TimeCreated, SourceFile) VALUES
                (1, 4624, 'Information', 'Security', 'alice', '2026-03-05 10:00:00', 'Security.evtx'),
                (2, 46240, 'Information', 'Security', 'bob', '2026-03-05 10:01:00', 'Security.evtx'),
                (3, 1, 'Information', 'Sysmon', 'alice', '2026-03-05 10:02:00', 'Sysmon.evtx');
            """
        )

    lexer_bypass_payloads = [
        "EventId = 4624 AND $$'$$ != $$x$$ AND EXISTS (SELECT 1 FROM case_metadata) AND $$y$$ != $$'$$",
        "EventId = 4624 AND $q$'$q$ != $q$x$q$ AND EXISTS (SELECT 1 FROM read_text($p$secret.txt$p$)) AND $q$y$q$ != $q$'$q$",
        r"EventId = 4624 AND E'\'' != '' AND EXISTS (SELECT 1 FROM case_metadata) AND E'\'' != ''",
        "PayloadData1 = $$hello$$",
        "PayloadData1 = $tag$hello$tag$",
        r"PayloadData1 = E'\''",
        "PayloadData1 = x'27'",
        "PayloadData1 = b'01'",
        r"PayloadData1 = U&'\0027'",
        r' "U&" = U&"\0022" ',
        ' "bad\'id" = 1 ',
        ' "bad""id" = 1 ',
        ' "" = 1 ',
        "EventId = 4624 -- trailing comment",
        "EventId = /* block */ 4624",
    ]
    for bad_sql in lexer_bypass_payloads:
        assert _main._is_unsafe_profile_sql(bad_sql) is True, f"Lexer failed to block: {bad_sql!r}"
        assert client.post("/api/event-profiles", json={"id": "r3_bad", "name": "Bad", "sql": bad_sql}).status_code == 400
        assert client.put(
            "/api/event-profiles/raw",
            json={"profiles": [{"id": "r3_bad_raw", "name": "Bad Raw", "sql": bad_sql}]},
        ).status_code == 400

    # Even if custom_event_profiles.json is tampered on disk (with builtin=true spoof), GET /eventlogs/query returns 400
    custom_ep_path = Path(isolated_m5a_env["event_profiles_file"])
    custom_ep_path.write_text(
        json.dumps({
            "custom_profiles": [{
                "id": "disk_smuggled_dq",
                "name": "Smuggled",
                "builtin": True,
                "sql": lexer_bypass_payloads[0],
            }],
            "deleted_ids": [],
        }),
        encoding="utf-8",
    )
    r_smug_q = client.get(f"/api/cases/{cid_r3}/eventlogs/query", params={"profile_id": "disk_smuggled_dq"})
    assert r_smug_q.status_code == 400

    # --- 3 & 4. VSS synthetic root wrapper exclusion + Dashboard 6-col partition & shadow_copy normalization ---
    with DuckDBManager.get_lock(cid_r3):
        conn = DuckDBManager.get_connection(cid_r3, read_only=False)
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS vfs_partitions;")
        cur.execute("DROP TABLE IF EXISTS vfs_shadow_copies;")
        cur.execute("DROP TABLE IF EXISTS vfs_files;")
        cur.execute(
            """
            CREATE TABLE vfs_partitions (
                part_index INTEGER, fs_type VARCHAR, start_offset BIGINT,
                size_bytes BIGINT, volume_label VARCHAR, is_bootable BOOLEAN
            );
            INSERT INTO vfs_partitions VALUES (0, 'FAT16', 1048576, 67108864, 'FAT16_VOL', TRUE);

            CREATE TABLE vfs_shadow_copies (
                vss_index INTEGER, partition_index INTEGER, shadow_copy_guid VARCHAR,
                creation_time_utc VARCHAR, shadow_copy_size BIGINT, staged_prefix VARCHAR,
                files_staged INTEGER, status VARCHAR
            );
            INSERT INTO vfs_shadow_copies VALUES (1, 2, 'guid-vss-1', '2026-03-01 10:00:00', 4096000, 'VSS/VSS_1', 2, 'STAGED');

            CREATE TABLE vfs_files (
                part_index INTEGER, vfs_path VARCHAR, staged_rel_path VARCHAR,
                file_name VARCHAR, parent_path VARCHAR, size_bytes BIGINT,
                is_dir BOOLEAN, is_deleted BOOLEAN, mft_entry BIGINT,
                si_created_utc VARCHAR, si_modified_utc VARCHAR, si_accessed_utc VARCHAR, si_changed_utc VARCHAR,
                fn_created_utc VARCHAR, fn_modified_utc VARCHAR, fn_accessed_utc VARCHAR, fn_changed_utc VARCHAR
            );
            INSERT INTO vfs_files VALUES
                (-1, '/VSS_1', NULL, 'VSS_1', '/', 0, TRUE, FALSE, 5, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
                (-1, '/VSS_1/Users', NULL, 'Users', '/VSS_1', 0, TRUE, FALSE, 20, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
                (-1, '/VSS_1/Users/VSS_1', NULL, 'VSS_1', '/VSS_1/Users', 0, TRUE, FALSE, 21, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            """
        )

    for vss_tree_params in ({"vss_index": 1}, {"path": "VSS #1"}):
        rt = client.get(f"/api/cases/{cid_r3}/filesystem/tree", params=vss_tree_params)
        assert rt.status_code == 200
        assert [f["name"] for f in rt.json()["folders"]] == ["Users"]

    rf_vss_root = client.get(f"/api/cases/{cid_r3}/filesystem/files", params={"vss_index": 1})
    assert rf_vss_root.status_code == 200
    assert [f["file_name"] for f in rf_vss_root.json()["files"]] == ["Users"]

    # Nested legitimate /VSS_1/Users/VSS_1 MUST remain visible
    rt_nested = client.get(f"/api/cases/{cid_r3}/filesystem/tree", params={"vss_index": 1, "path": "/Users"})
    assert rt_nested.status_code == 200
    assert [f["name"] for f in rt_nested.json()["folders"]] == ["VSS_1"]
    rf_nested = client.get(f"/api/cases/{cid_r3}/filesystem/files", params={"vss_index": 1, "path": "/Users"})
    assert rf_nested.status_code == 200
    assert [f["file_name"] for f in rf_nested.json()["files"]] == ["VSS_1"]

    # Dashboard normalizes 6-col vfs_partitions & variant vfs_shadow_copies
    r_dash = client.get(f"/api/cases/{cid_r3}/dashboard")
    assert r_dash.status_code == 200
    dash_j = r_dash.json()
    assert dash_j["partitions"] == [{
        "part_index": 0,
        "label": "FAT16_VOL",
        "fs_type": "FAT16",
        "offset_bytes": 1048576,
        "size_bytes": 67108864,
        "volume_serial": "",
        "is_boot": True,
    }]
    assert dash_j["shadow_copies"] == [{
        "vss_index": 1,
        "part_index": 2,
        "store_id": "guid-vss-1",
        "creation_time": "2026-03-01 10:00:00",
        "size_bytes": 4096000,
        "staged_prefix": "VSS/VSS_1",
        "files_staged": 2,
        "status": "STAGED",
    }]

    # --- 5. _persist_case_intake_metadata_and_keywords single-transaction batching + ROLLBACK ---
    tx_cid = "m5a_r3_tx_case"
    _main._persist_case_intake_metadata_and_keywords(
        tx_cid,
        {"case_name": "Initial", "examiner": "Alice"},
        _main._normalize_keyword_specs(["alpha_kw"]),
    )
    orig_upsert = _main._upsert_case_keywords

    def _boom_upsert(cursor, specs, ensure_schema=True):
        raise RuntimeError("Simulated mid-transaction failure")

    monkeypatch.setattr(_main, "_upsert_case_keywords", _boom_upsert)
    with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
        _main._persist_case_intake_metadata_and_keywords(
            tx_cid,
            {"case_name": "ShouldRollback", "examiner": "Mallory"},
            _main._normalize_keyword_specs(["beta_kw"]),
        )
    monkeypatch.setattr(_main, "_upsert_case_keywords", orig_upsert)

    with DuckDBManager.get_lock(tx_cid):
        tx_conn = DuckDBManager.get_connection(tx_cid, read_only=False)
        tx_meta = dict(tx_conn.execute("SELECT key, value FROM case_metadata;").fetchall())
        assert tx_meta["case_name"] == "Initial"
        assert tx_meta["examiner"] == "Alice"

    # --- 6. Exact scalar bool/numeric column_filters + /export/folder & /keywords/hits aliases ---
    with DuckDBManager.get_lock(cid_r3):
        conn = DuckDBManager.get_connection(cid_r3, read_only=False)
        cur = conn.cursor()
        cur.execute("CREATE TABLE parsed_r3_events (_row_id BIGINT, EventId BIGINT, UserName VARCHAR, is_admin BOOLEAN);")
        cur.execute(
            """
            INSERT INTO parsed_r3_events VALUES
                (1, 4624, 'alice', TRUE),
                (2, 46240, 'bob', FALSE),
                (3, 1, 'alice_sys', FALSE);
            """
        )

    r_num = client.post(
        f"/api/cases/{cid_r3}/artifacts/parsed_r3_events/query",
        json={"column_filters": {"EventId": 4624}},
    )
    assert r_num.status_code == 200
    assert r_num.json()["filtered_count"] == 1
    assert r_num.json()["rows"][0]["EventId"] == 4624

    r_bool_t = client.post(
        f"/api/cases/{cid_r3}/artifacts/parsed_r3_events/query",
        json={"column_filters": {"is_admin": True}},
    )
    assert r_bool_t.status_code == 200
    assert r_bool_t.json()["filtered_count"] == 1
    assert r_bool_t.json()["rows"][0]["UserName"] == "alice"

    r_combo = client.post(
        f"/api/cases/{cid_r3}/artifacts/parsed_r3_events/query",
        json={"column_filters": {"EventId": 1, "UserName": "alice"}},
    )
    assert r_combo.status_code == 200
    assert r_combo.json()["filtered_count"] == 1
    assert r_combo.json()["rows"][0]["EventId"] == 1

    # /export/folder alias with folder_path= and path=
    for qp in ({"folder_path": "Exports"}, {"path": "Exports"}):
        r_ef = client.get(f"/api/cases/{cid_r3}/export/folder", params=qp)
        assert r_ef.status_code == 200
        with zipfile.ZipFile(io.BytesIO(r_ef.content)) as zf:
            assert zf.namelist() == ["report_ok.txt"]
    assert client.get(f"/api/cases/{cid_r3}/export/folder", params={"path": "$Recycle.Bin"}).status_code == 404
    assert client.get(f"/api/cases/{cid_r3}/export/folder", params={"path": "MissingDir"}).status_code == 404

    # /keywords/hits clean empty fallback when view_keyword_hits & parsed_keyword_hits are absent, then populated hits
    empty_kw_cid = "m5a_r3_empty_kw"
    init_case_db(empty_kw_cid)
    with DuckDBManager.get_lock(empty_kw_cid):
        e_conn = DuckDBManager.get_connection(empty_kw_cid, read_only=False)
        e_conn.execute("DROP VIEW IF EXISTS view_keyword_hits;")
        e_conn.execute("DROP TABLE IF EXISTS parsed_keyword_hits;")
    r_kh_empty = client.get(f"/api/cases/{empty_kw_cid}/keywords/hits")
    assert r_kh_empty.status_code == 200
    assert r_kh_empty.json() == {
        "case_id": empty_kw_cid,
        "hits": [],
        "rows": [],
        "total_hits": 0,
        "total_count": 0,
    }

    r_add_kw = client.post(
        f"/api/cases/{cid_r3}/keywords",
        json={"keywords": ["Exportable R3 report"], "case_sensitive": True},
    )
    assert r_add_kw.status_code == 200
    r_kh_pop = client.get(f"/api/cases/{cid_r3}/keywords/hits")
    assert r_kh_pop.status_code == 200
    assert r_kh_pop.json()["total_hits"] == 1
    assert r_kh_pop.json()["total_count"] == 1
    assert len(r_kh_pop.json()["hits"]) == 1

