"""
Sub-Milestone M2-B Target-Scoped Unit & Live Integration Test Suite
Covers:
  1. BulkExtractorRunner (missing-binary skip, CLI flags -R / -j / -S *_carve_mode=2,
     two-pass R3 zero-FP filtering, compressed offsets, UTF-16LE octal escapes, live v2.2.0 binary).
  2. RegRipperRunner (Autopsy v2.8 rejection, cwd=rip_exe.parent, multi-user + VSS hive preservation,
     clean_hives priority, exact 40-dash + 5 headerless plugins, preservation of raw_recmd, live v4.0 binary).
  3. EZToolRunner + Hindsight (rla.exe v2026.10.1 clean_hives multi-user + VSS layout, parallel ThreadPoolExecutor
     + DuckDB lock serialization, SQLECmd empty staging/SQLite fix, RECmd Kroll_Batch.reb, Amcache/JLECmd/SumECmd
     multi-CSV unioning, multi-user WxTCmd, live Hindsight execution + strict Desktop/WFT cwd hygiene).
"""
import json
import os
import sqlite3
import struct
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

import backend
import backend.config as wft_config
from backend.config import BASE_DIR
from backend.db.engine import DuckDBManager

try:
    from backend.orchestrator.bulk_extractor_runner import BulkExtractorRunner
    from backend.orchestrator.ez_runner import EZToolRunner
    from backend.orchestrator.regripper_runner import RegRipperRunner
except SyntaxError as exc:
    # Guard only against in-flight sibling edits in unowned modules re-exported by backend/orchestrator/__init__.py
    if exc.filename and Path(exc.filename).name not in {
        "bulk_extractor_runner.py",
        "ez_runner.py",
        "regripper_runner.py",
    }:
        pkg = types.ModuleType("backend.orchestrator")
        pkg.__path__ = [str((BASE_DIR / "backend" / "orchestrator").resolve())]
        sys.modules["backend.orchestrator"] = pkg
        setattr(backend, "orchestrator", pkg)
        import backend.orchestrator.bulk_extractor_runner as _be_mod
        import backend.orchestrator.ez_runner as _ez_mod
        import backend.orchestrator.regripper_runner as _rr_mod

        setattr(pkg, "bulk_extractor_runner", _be_mod)
        setattr(pkg, "ez_runner", _ez_mod)
        setattr(pkg, "regripper_runner", _rr_mod)
        BulkExtractorRunner = _be_mod.BulkExtractorRunner
        EZToolRunner = _ez_mod.EZToolRunner
        RegRipperRunner = _rr_mod.RegRipperRunner
    else:
        raise

CSC_CANDIDATES = [
    Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"),
]


def _find_csc() -> Path:
    for p in CSC_CANDIDATES:
        if p.is_file():
            return p
    pytest.skip("csc.exe not available on host")


def _compile_csharp_exe(src_code: str, out_exe: Path) -> Path:
    csc = _find_csc()
    cs_path = out_exe.with_suffix(".cs")
    cs_path.write_text(src_code, encoding="utf-8")
    proc = subprocess.run(
        [str(csc), "/nologo", "/target:exe", f"/out:{out_exe}", str(cs_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"csc.exe failed: {proc.stdout}\n{proc.stderr}"
    assert out_exe.is_file() and out_exe.stat().st_size > 512
    return out_exe


# ---------------------------------------------------------------------------
# Pure-Python Standards-Compliant Forensic Artifact Builders
# ---------------------------------------------------------------------------

def build_minimal_regf_hive(
    dest_path: Path,
    embedded_name: str,
    subkey_chain: List[str],
    str_values: Dict[str, str],
) -> Path:
    """
    Build a genuine 8,192-byte Windows Registry `regf` + `hbin` binary hive
    with valid XOR-32 header checksum, `nk`/`lf`/`vk` cells, and REG_SZ values.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    filetime_2024 = 133500000000000000  # 2024-01-18 UTC

    hbin = bytearray(4096)
    hbin[0:4] = b"hbin"
    struct.pack_into("<I", hbin, 4, 0)
    struct.pack_into("<I", hbin, 8, 4096)
    cursor = 0x20

    def alloc_cell(payload: bytes) -> int:
        nonlocal cursor
        total_len = (4 + len(payload) + 7) & ~7
        cell_off = cursor
        struct.pack_into("<i", hbin, cell_off, -total_len)
        hbin[cell_off + 4 : cell_off + 4 + len(payload)] = payload
        cursor += total_len
        return cell_off

    def make_nk(
        name: str,
        parent_off: int,
        is_root: bool = False,
        num_subkeys: int = 0,
        subkeys_off: int = -1,
        num_vals: int = 0,
        vals_off: int = -1,
    ) -> bytes:
        name_b = name.encode("ascii")
        flags = 0x002C if is_root else 0x0020
        hdr = struct.pack(
            "<2sHQIiIIiiIiiiIIIIIHH",
            b"nk",
            flags,
            filetime_2024,
            0,
            parent_off,
            num_subkeys,
            0,
            subkeys_off,
            -1,
            num_vals,
            vals_off,
            -1,
            -1,
            0,
            0,
            0,
            0,
            0,
            len(name_b),
            0,
        )
        return hdr + name_b

    # Allocate value data + vk cells + value list first so leaf nk knows offsets
    vk_offsets: List[int] = []
    for vname, vval in str_values.items():
        data_bytes = (vval + "\x00").encode("utf-16-le")
        data_off = alloc_cell(data_bytes)
        vname_b = vname.encode("ascii")
        vk_body = (
            struct.pack(
                "<2sHIIIHH",
                b"vk",
                len(vname_b),
                len(data_bytes),
                data_off,
                1,  # REG_SZ
                1 if vname_b else 0,  # ASCII name flag
                0,
            )
            + vname_b
        )
        vk_offsets.append(alloc_cell(vk_body))

    vals_list_off = -1
    if vk_offsets:
        vals_list_off = alloc_cell(b"".join(struct.pack("<I", o) for o in vk_offsets))

    # Reserve root + chain nk cells top-down, then patch subkey lf lists
    all_names = ["CMI-CreateHive{00000000-0000-0000-0000-000000000000}"] + list(subkey_chain)
    nk_offsets: List[int] = []
    for idx, kname in enumerate(all_names):
        is_root = idx == 0
        is_leaf = idx == len(all_names) - 1
        parent = -1 if is_root else nk_offsets[idx - 1]
        placeholder = make_nk(
            name=kname,
            parent_off=parent,
            is_root=is_root,
            num_subkeys=0 if is_leaf else 1,
            subkeys_off=-1,
            num_vals=len(vk_offsets) if is_leaf else 0,
            vals_off=vals_list_off if is_leaf else -1,
        )
        nk_offsets.append(alloc_cell(placeholder))

    # Allocate lf lists and patch non-leaf nk cells
    for idx in range(len(all_names) - 1):
        child_off = nk_offsets[idx + 1]
        child_hint = all_names[idx + 1].encode("ascii")[:4].ljust(4, b"\x00")
        lf_body = struct.pack("<2sH", b"lf", 1) + struct.pack("<I4s", child_off, child_hint)
        lf_off = alloc_cell(lf_body)
        # Patch subkeys_list_offset inside nk cell (cell header 4B + offset 28 inside nk = +32)
        struct.pack_into("<i", hbin, nk_offsets[idx] + 4 + 28, lf_off)

    # Trailing free cell filling remainder of 4096-byte hbin
    remaining = 4096 - cursor
    if remaining >= 8:
        struct.pack_into("<i", hbin, cursor, remaining)

    # Build 4096-byte regf header with valid XOR-32 checksum
    regf = bytearray(4096)
    regf[0:4] = b"regf"
    struct.pack_into("<I", regf, 0x04, 1)  # primary seq
    struct.pack_into("<I", regf, 0x08, 1)  # secondary seq
    struct.pack_into("<Q", regf, 0x0C, filetime_2024)
    struct.pack_into("<I", regf, 0x14, 1)  # major
    struct.pack_into("<I", regf, 0x18, 5)  # minor
    struct.pack_into("<I", regf, 0x1C, 0)  # type = primary hive
    struct.pack_into("<I", regf, 0x20, 1)  # format = direct memory load
    struct.pack_into("<I", regf, 0x24, nk_offsets[0])  # root cell offset (0x20+)
    struct.pack_into("<I", regf, 0x28, 4096)  # hbin data size
    struct.pack_into("<I", regf, 0x2C, 1)  # clustering factor
    emb_utf16 = embedded_name.encode("utf-16-le")[:62]
    regf[0x30 : 0x30 + len(emb_utf16)] = emb_utf16

    xor_sum = 0
    for off in range(0, 0x1FC, 4):
        xor_sum ^= struct.unpack_from("<I", regf, off)[0]
    if xor_sum == 0xFFFFFFFF:
        xor_sum = 0xFFFFFFFE
    elif xor_sum == 0:
        xor_sum = 1
    struct.pack_into("<I", regf, 0x1FC, xor_sum)

    dest_path.write_bytes(bytes(regf) + bytes(hbin))
    return dest_path


def build_win10_recycle_bin_i_file(dest_path: Path, original_win_path: str, file_size: int = 4096) -> Path:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    path_null = original_win_path + "\x00"
    path_bytes = path_null.encode("utf-16-le")
    deleted_ft = 133500000000000000
    blob = struct.pack("<QQQI", 2, file_size, deleted_ft, len(path_null)) + path_bytes
    dest_path.write_bytes(blob)
    return dest_path


def build_chromium_profile(profile_dir: Path, url: str, title: str) -> Path:
    profile_dir.mkdir(parents=True, exist_ok=True)
    hist_db = profile_dir / "History"
    if hist_db.exists():
        hist_db.unlink()

    # Chrome epoch: microseconds since 1601-01-01 UTC (2024-02-01T10:00:00Z = 13351255200000000)
    chrome_ts = 13351255200000000
    conn = sqlite3.connect(str(hist_db))
    try:
        conn.executescript(
            """
            CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
            INSERT INTO meta VALUES ('version', '96');
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url LONGVARCHAR,
                title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0,
                typed_count INTEGER DEFAULT 0,
                last_visit_time INTEGER NOT NULL,
                hidden INTEGER DEFAULT 0
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER,
                transition INTEGER DEFAULT 0,
                segment_id INTEGER,
                visit_duration INTEGER DEFAULT 0,
                incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE,
                opener_visit INTEGER
            );
            CREATE TABLE visit_source (
                id INTEGER PRIMARY KEY,
                source INTEGER NOT NULL
            );
            CREATE TABLE keyword_search_terms (
                keyword_id INTEGER NOT NULL,
                url_id INTEGER NOT NULL,
                term LONGVARCHAR NOT NULL,
                normalized_term LONGVARCHAR NOT NULL
            );
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                guid VARCHAR NOT NULL,
                current_path LONGVARCHAR NOT NULL,
                target_path LONGVARCHAR NOT NULL,
                start_time INTEGER NOT NULL,
                received_bytes INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                state INTEGER NOT NULL,
                danger_type INTEGER NOT NULL,
                interrupt_reason INTEGER NOT NULL,
                hash BLOB NOT NULL,
                end_time INTEGER NOT NULL,
                opened INTEGER NOT NULL,
                last_access_time INTEGER NOT NULL,
                transient INTEGER NOT NULL,
                referrer LONGVARCHAR NOT NULL,
                site_url LONGVARCHAR NOT NULL,
                tab_url LONGVARCHAR NOT NULL,
                tab_referrer_url LONGVARCHAR NOT NULL,
                http_method VARCHAR NOT NULL,
                by_ext_id VARCHAR NOT NULL,
                by_ext_name VARCHAR NOT NULL,
                etag VARCHAR NOT NULL,
                last_modified VARCHAR NOT NULL,
                mime_type VARCHAR(255) NOT NULL,
                original_mime_type VARCHAR(255) NOT NULL
            );
            CREATE TABLE downloads_url_chains (
                id INTEGER NOT NULL,
                chain_index INTEGER NOT NULL,
                url LONGVARCHAR NOT NULL,
                PRIMARY KEY (id, chain_index)
            );
            CREATE TABLE segments (
                id INTEGER PRIMARY KEY,
                name VARCHAR,
                url_id INTEGER NOT NULL
            );
            CREATE TABLE typed_url_sync_metadata (
                storage_key INTEGER PRIMARY KEY NOT NULL,
                value BLOB
            );
            """
        )
        conn.execute(
            "INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (1, ?, ?, 2, 1, ?, 0);",
            (url, title, chrome_ts),
        )
        conn.execute(
            "INSERT INTO visits (id, url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (1, 1, ?, 0, 805306368, 0, 5000000);",
            (chrome_ts,),
        )
        conn.commit()
    finally:
        conn.close()

    # Include Bookmarks + Preferences (Bookmarks root folders have no date_modified -> timeless record in Hindsight!)
    bookmarks_obj = {
        "checksum": "00000000000000000000000000000000",
        "roots": {
            "bookmark_bar": {
                "children": [
                    {
                        "date_added": str(chrome_ts),
                        "guid": "00000000-0000-4000-8000-000000000001",
                        "id": "2",
                        "name": title,
                        "type": "url",
                        "url": url,
                    }
                ],
                "date_added": "0",
                "date_last_used": "0",
                "date_modified": "0",
                "guid": "00000000-0000-4000-a000-000000000001",
                "id": "1",
                "name": "Bookmarks bar",
                "type": "folder",
            },
            "other": {
                "children": [],
                "date_added": "0",
                "date_modified": "0",
                "id": "3",
                "name": "Other bookmarks",
                "type": "folder",
            },
            "synced": {
                "children": [],
                "date_added": "0",
                "date_modified": "0",
                "id": "4",
                "name": "Mobile bookmarks",
                "type": "folder",
            },
        },
        "version": 1,
    }
    (profile_dir / "Bookmarks").write_text(json.dumps(bookmarks_obj), encoding="utf-8")
    (profile_dir / "Preferences").write_text(
        json.dumps({"profile": {"name": title}, "content_settings": {"exceptions": {}}}),
        encoding="utf-8",
    )
    return profile_dir


def build_wxt_activities_db(db_path: Path, activity_guid_hex: str, app_name: str, display_text: str) -> Path:
    """Build a genuine Windows 10 Timeline ActivitiesCache.db matching WxTCmd & SQLECmd schemas."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    guid_bytes = bytes.fromhex(activity_guid_hex)
    unix_ts = 1706781600  # 2024-02-01T10:00:00Z

    app_id_json = json.dumps([{"application": app_name, "platform": "x_exe_path"}])
    payload_bytes = json.dumps({"displayText": display_text, "appDisplayName": app_name}).encode("utf-8")

    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE SmartLookup (URI TEXT PRIMARY KEY, Domain TEXT NOT NULL);
            CREATE TABLE Metadata (Key TEXT PRIMARY KEY NOT NULL, Value TEXT);
            INSERT INTO Metadata VALUES ('Version', '5');
            CREATE TABLE Activity (
                Id BLOB PRIMARY KEY,
                AppId TEXT NOT NULL,
                PackageIdHash TEXT,
                AppActivityId TEXT,
                ActivityType INT NOT NULL,
                ActivityStatus INT NOT NULL,
                ParentActivityId BLOB,
                Tag TEXT,
                "Group" TEXT,
                MatchId TEXT,
                LastModifiedTime INTEGER NOT NULL,
                ExpirationTime INTEGER,
                Payload BLOB,
                Priority INT,
                IsLocalOnly INT,
                PlatformDeviceId TEXT,
                CreatedInCloud INTEGER,
                StartTime INTEGER,
                EndTime INTEGER,
                LastModifiedOnClient INTEGER,
                GroupAppActivityId TEXT,
                ClipboardPayload BLOB,
                EnterpriseId TEXT,
                OriginalPayload BLOB,
                UserActionState INT,
                ETag INT NOT NULL
            );
            CREATE TABLE ActivityOperation (
                OperationOrder INTEGER PRIMARY KEY ASC,
                Id BLOB NOT NULL,
                OperationType INT NOT NULL,
                AppId TEXT NOT NULL,
                PackageIdHash TEXT,
                AppActivityId TEXT,
                ActivityType INT NOT NULL,
                ParentActivityId BLOB,
                Tag TEXT,
                "Group" TEXT,
                MatchId TEXT,
                LastModifiedTime INTEGER NOT NULL,
                ExpirationTime INTEGER,
                Payload BLOB,
                Priority INT,
                CreatedTime INTEGER,
                Attachments TEXT,
                PlatformDeviceId TEXT,
                CreatedInCloud INTEGER,
                StartTime INTEGER,
                EndTime INTEGER,
                LastModifiedOnClient INTEGER,
                CorrelationVector TEXT,
                GroupAppActivityId TEXT,
                ClipboardPayload BLOB,
                EnterpriseId TEXT,
                OriginalPayload BLOB,
                UserActionState INT,
                ETag INT NOT NULL
            );
            CREATE TABLE Activity_PackageId (
                ActivityId BLOB NOT NULL,
                Platform TEXT NOT NULL,
                PackageName TEXT NOT NULL,
                ExpirationTime INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            INSERT INTO Activity (
                Id, AppId, PackageIdHash, AppActivityId, ActivityType, ActivityStatus,
                ParentActivityId, Tag, "Group", MatchId, LastModifiedTime, ExpirationTime,
                Payload, Priority, IsLocalOnly, PlatformDeviceId, CreatedInCloud,
                StartTime, EndTime, LastModifiedOnClient, ETag
            ) VALUES (?, ?, 'hash1', 'act1', 5, 1, NULL, '', '', '', ?, ?, ?, 1, 0, 'DEV1', 0, ?, ?, ?, 1);
            """,
            (guid_bytes, app_id_json, unix_ts, unix_ts + 86400, payload_bytes, unix_ts, unix_ts + 60, unix_ts),
        )
        conn.execute(
            "INSERT INTO Activity_PackageId VALUES (?, 'x_exe_path', ?, ?);",
            (guid_bytes, app_name, unix_ts + 86400),
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_wft_env(tmp_path, monkeypatch):
    """
    Redirect WFT_APPDATA_DIR, WFT_CASES_DIR, WFT_TOOL_PATHS_FILE, and WFT_CUSTOM_LOCATIONS_FILE
    into tmp_path while preserving provisioned .env tool paths unless overridden by a test.
    """
    DuckDBManager.close_all()
    env_root = tmp_path / "_wft_isolated"
    appdata = env_root / "appdata"
    cases_dir = env_root / "cases"
    appdata.mkdir(parents=True, exist_ok=True)
    cases_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata))
    monkeypatch.setenv("WFT_CASES_DIR", str(cases_dir))
    monkeypatch.setenv("WFT_TOOL_PATHS_FILE", str(appdata / "tool_paths.json"))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(appdata / "custom_locations.json"))
    monkeypatch.setattr(wft_config, "CASES_DIR", cases_dir.resolve(), raising=False)
    monkeypatch.setattr(wft_config, "_CUSTOM_CASE_DIRS", {}, raising=False)
    monkeypatch.setattr(wft_config, "_CUSTOM_TOOL_PATHS", {}, raising=False)

    # Ensure host .env tool paths are loaded into os.environ for live binary tests
    wft_config.load_root_env(override=False, env_file=BASE_DIR / ".env")

    yield env_root

    DuckDBManager.close_all()


@pytest.fixture(scope="module")
def compiled_be_recorder_exe(tmp_path_factory) -> Path:
    """Compile a genuine 64-bit PE MZ executable CLI recorder for BulkExtractorRunner flag tests."""
    build_dir = tmp_path_factory.mktemp("be_shim")
    cs_code = r"""
using System;
using System.IO;

class Program {
    static int Main(string[] args) {
        string outDir = "";
        for (int i = 0; i < args.Length - 1; i++) {
            if (args[i] == "-o") {
                outDir = args[i + 1];
                break;
            }
        }
        if (!string.IsNullOrEmpty(outDir)) {
            Directory.CreateDirectory(outDir);
            File.WriteAllLines(Path.Combine(outDir, "_recorded_args.txt"), args);
            File.WriteAllText(Path.Combine(outDir, "email.txt"),
                "# BANNER FILE\n# Bulk Extractor Recorder\n4096\trecorder@forensics-lab.org\tFrom: recorder@forensics-lab.org\n");
            File.WriteAllText(Path.Combine(outDir, "email_histogram.txt"),
                "# Histogram-File-Version: 1.1\nn=1\trecorder@forensics-lab.org\n");
        }
        return 0;
    }
}
"""
    return _compile_csharp_exe(cs_code, build_dir / "bulk_extractor_recorder.exe")


@pytest.fixture(scope="module")
def compiled_rip_shims(tmp_path_factory) -> Tuple[Path, Path]:
    """
    Compile two genuine PE MZ executables:
      1) Legacy Autopsy rip.exe v2.8 (lacks -a flag)
      2) Valid RegRipper v4.0 recorder shim (records cwd & args, emits radar.pl 65/45/42-dash lines
         + 5 headerless plugins separated by exact 40-dash lines).
    """
    root = tmp_path_factory.mktemp("rip_shims")

    v28_dir = root / "autopsy_rr_v28"
    (v28_dir / "plugins").mkdir(parents=True, exist_ok=True)
    (v28_dir / "plugins" / "dummy.pl").write_text("# v2.8 plugin\n", encoding="utf-8")
    v28_cs = r"""
using System;
class Program {
    static int Main(string[] args) {
        Console.WriteLine("Rip v.2.8_20190318 - CLI RegRipper tool");
        Console.WriteLine("  -r <hive>  -p <plugin>  -l  -c");
        return 0;
    }
}
"""
    v28_exe = _compile_csharp_exe(v28_cs, v28_dir / "rip.exe")

    v40_dir = root / "regripper_v40"
    (v40_dir / "plugins").mkdir(parents=True, exist_ok=True)
    (v40_dir / "plugins" / "radar.pl").write_text("# v4.0 plugin\n", encoding="utf-8")
    v40_cs = r"""
using System;
using System.IO;

class Program {
    static int Main(string[] args) {
        string logFile = Environment.GetEnvironmentVariable("WFT_TEST_RIP_LOG") ?? "";
        if (!string.IsNullOrEmpty(logFile)) {
            File.AppendAllText(logFile, Environment.CurrentDirectory + "|" + string.Join(" ", args) + "\n");
        }
        if (args.Length > 0 && args[0] == "-h") {
            Console.WriteLine("Rip v.4.0 - CLI RegRipper tool");
            Console.WriteLine("  -r [Reg hive file]");
            Console.WriteLine("  -a [Automatically run hive-specific plugins]");
            return 0;
        }
        if (args.Length >= 2 && args[0] == "-l" && args[1] == "-c") {
            Console.WriteLine("Plugin,Version,Hive,MITRE ATT&CK,Category,Description");
            Console.WriteLine("radar,20200517,SOFTWARE,T1082,Program Execution,Parse RADAR Heap Leak Detection");
            Console.WriteLine("landesk,20220930,SOFTWARE,T1204,Execution,Get LANDesk ManagementSuite info");
            Console.WriteLine("appspecific,20200515,NTUSER.DAT,T1547,Persistence,IntelliPoint AppSpecific");
            Console.WriteLine("osversion,20200511,NTUSER.DAT,T1082,Discovery,Checks OSVersion value");
            Console.WriteLine("userassist,20200921,NTUSER.DAT,T1204,User Execution,Parse UserAssist entries");
            Console.WriteLine("productpolicy,20200518,SYSTEM,T1082,Discovery,Parse ProductPolicy");
            return 0;
        }
        string d40 = new string('-', 40);
        string d65 = new string('-', 65);
        string d45 = new string('-', 45);
        string d42 = new string('-', 42);

        Console.WriteLine("radar v.20200517");
        Console.WriteLine("(SOFTWARE) Parse RADAR Heap Leak Detection");
        Console.WriteLine(d65);
        Console.WriteLine("DiagnosedApplications subkeys");
        Console.WriteLine(d45);
        Console.WriteLine("evil_loader.exe  LastWrite: 2024-02-01 10:00:00Z");
        Console.WriteLine(d42);
        Console.WriteLine("Total Diagnosed: 1");
        Console.WriteLine(d40);

        Console.WriteLine("MITRE: T1204 (execution)");
        Console.WriteLine("LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring not found.");
        Console.WriteLine(d40);

        Console.WriteLine("Software\\Microsoft\\IntelliPoint\\AppSpecific not found.");
        Console.WriteLine(d40);

        Console.WriteLine("UserAssist");
        Console.WriteLine("cmd.exe (3)");
        Console.WriteLine(d40);

        Console.WriteLine("Security-SPP-LastWindowsActivationTime : 2024-01-15");
        Console.WriteLine(d40);

        Console.WriteLine("OSVersion");
        Console.WriteLine("Windows 10 Enterprise");
        Console.WriteLine(d40);
        return 0;
    }
}
"""
    v40_exe = _compile_csharp_exe(v40_cs, v40_dir / "rip.exe")
    return (v28_exe, v40_exe)


# ===========================================================================
# 1. BulkExtractorRunner Tests
# ===========================================================================

def test_bulk_extractor_missing_binary_graceful_skip(isolated_wft_env, tmp_path, monkeypatch):
    monkeypatch.setattr(wft_config, "find_bulk_extractor_binary", lambda: None)
    case_id = "m2b_missing_be"
    case_dir = tmp_path / "unregistered_case_missing_be"

    runner = BulkExtractorRunner(case_id=case_id, case_dir=case_dir)
    img = tmp_path / "dummy.raw"
    img.write_bytes(b"test evidence bytes" * 64)

    res = runner.run(source_path=img, max_workers=8, enable_carving=False)
    assert res["status"] in ("WARNING", "SKIPPED")
    assert res.get("skipped") is True
    assert res["features_ingested"] == 0
    assert res["histograms_ingested"] == 0

    # Verify case.duckdb was created inside case_dir (NOT leaked to Desktop/cases)
    assert (case_dir / "case.duckdb").is_file()
    conn = DuckDBManager.get_connection(case_id)
    feat_cols = [r[0] for r in conn.execute("DESCRIBE parsed_bulk_extractor_features;").fetchall()]
    hist_cols = [r[0] for r in conn.execute("DESCRIBE parsed_bulk_extractor_histograms;").fetchall()]
    assert {"scanner", "offset_str", "feature", "context", "source_file"}.issubset(set(feat_cols))
    assert {"scanner", "count", "feature", "source_file"}.issubset(set(hist_cols))

    reg_rows = conn.execute(
        "SELECT artifact_id, category, row_count FROM artifact_registry WHERE artifact_id LIKE 'bulk_extractor_%' ORDER BY artifact_id;"
    ).fetchall()
    assert reg_rows == [
        ("bulk_extractor_features", "REFINED RESULTS", 0),
        ("bulk_extractor_histograms", "REFINED RESULTS", 0),
    ]

    logs = conn.execute(
        "SELECT module_name, status FROM processing_logs WHERE module_name = 'BulkExtractor';"
    ).fetchall()
    assert logs == [("BulkExtractor", "WARNING")]


def test_bulk_extractor_cli_flags_image_vs_dir_carving_and_worker_clamping(
    isolated_wft_env, compiled_be_recorder_exe, tmp_path, monkeypatch
):
    monkeypatch.setenv("WFT_BULK_EXTRACTOR_EXE", str(compiled_be_recorder_exe))
    case_dir = tmp_path / "case_be_flags"
    runner = BulkExtractorRunner(case_id="m2b_be_flags", case_dir=case_dir)

    # 1) .E01 image, enable_carving=False, max_workers=999 -> clamped to 32, NO -R, NO -S *_carve_mode=2
    e01_file = tmp_path / "disk01.E01"
    e01_file.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 512)
    res_e01 = runner.run(source_path=e01_file, max_workers=999, enable_carving=False)
    assert res_e01["status"] == "SUCCESS"
    args_e01 = (runner.out_dir / "_recorded_args.txt").read_text(encoding="utf-8").splitlines()
    assert args_e01[:5] == ["-0", "-q", "-Z", "-j", "32"]
    assert "-R" not in args_e01
    assert "zip_carved_carve_mode=0" in args_e01
    assert "jpeg_carve_mode=0" in args_e01
    assert not any(a.endswith("=2") or a.endswith("=1") for a in args_e01)
    assert args_e01[-1] == str(e01_file.resolve())

    # 2) .dd image, enable_carving=True, max_workers=0 -> clamped to 1, NO -R, ALL 5 -S *_carve_mode=2 flags
    dd_file = tmp_path / "usb.dd"
    dd_file.write_bytes(b"\x00" * 1024)
    res_dd = runner.run(source_path=dd_file, max_workers=0, enable_carving=True)
    assert res_dd["status"] == "SUCCESS"
    args_dd = (runner.out_dir / "_recorded_args.txt").read_text(encoding="utf-8").splitlines()
    assert args_dd[:5] == ["-0", "-q", "-Z", "-j", "1"]
    assert "-R" not in args_dd
    for expected_carve in (
        "jpeg_carve_mode=2",
        "zip_carved_carve_mode=2",
        "rar_carve_mode=2",
        "unrar_carved_carve_mode=2",
        "sqlite_carved_carve_mode=2",
    ):
        assert expected_carve in args_dd

    # 3) Directory source with trailing backslash -> MUST include -R and strip trailing backslash
    src_folder = tmp_path / "logical_evidence_folder"
    src_folder.mkdir()
    (src_folder / "note.txt").write_text("hello", encoding="utf-8")
    res_dir = runner.run(source_path=str(src_folder) + "\\", max_workers=12, enable_carving=False)
    assert res_dir["status"] == "SUCCESS"
    args_dir = (runner.out_dir / "_recorded_args.txt").read_text(encoding="utf-8").splitlines()
    assert "-R" in args_dir
    assert args_dir[args_dir.index("-j") + 1] == "12"
    assert not args_dir[-1].endswith("\\")


def test_bulk_extractor_r3_zero_false_positive_filtering_and_compressed_offsets(
    isolated_wft_env, tmp_path
):
    case_dir = tmp_path / "case_be_r3"
    runner = BulkExtractorRunner(case_id="m2b_be_r3", case_dir=case_dir)
    out_dir = case_dir / "synthetic_be_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Valid + invalid emails (UTF-8 BOM, # headers, compressed offset, UTF-16LE octal escapes, Retina @2x.png)
    (out_dir / "email.txt").write_text(
        "\ufeff# BANNER FILE\n"
        "# Feature-Recorder: email\n"
        "512\tsuspect@evil-corp.org\tFrom: suspect@evil-corp.org\\015\\012\n"
        "1048576-ZIP-0\tzip_insider@exfil-ops.net\tmailto:zip_insider@exfil-ops.net\n"
        "2048\tu@corp.org\tu\\000@\\000c\\000o\\000r\\000p\\000.\\000o\\000r\\000g\\000\n"
        "4096\tlogo@2x.png\t<img src=\"logo@2x.png\">\n"
        "8192\tbad@kernel32.dll\tMZ\\220\\000\\377\\001\\200\\376bad@kernel32.dll\\000\\377\n",
        encoding="utf-8",
    )

    # domain.txt (dotted-quads + hostnames + PE version quad + DLL pseudo-domains)
    (out_dir / "domain.txt").write_text(
        "# Feature-Recorder: domain\n"
        "100\t198.51.100.44\tConnect 198.51.100.44:443\n"
        "150\t10.20.30.40\tSRC=10.20.30.40 DST=198.51.100.44\n"
        "200\tc2.evil-corp.org\thttps://c2.evil-corp.org/gate\n"
        "250\t0.0.0.0\tbind 0.0.0.0\n"
        "300\t255.255.255.255\tbroadcast 255.255.255.255\n"
        "350\t127.0.0.1\tlocalhost 127.0.0.1\n"
        "400\t999.1.2.3\tinvalid 999.1.2.3\n"
        "450\t10.0.19041.1\tMZ\\220\\000FileVersion\\00010.0.19041.1\\000\n"
        "500\tkernel32.dll\tImport kernel32.dll\n"
        "550\tntoskrnl.exe\tSystem32\\ntoskrnl.exe\n",
        encoding="utf-8",
    )

    # domain_histogram.txt — must cross-reject 10.0.19041.1 rejected in Pass 1 due to PE context!
    (out_dir / "domain_histogram.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        "n=5\t198.51.100.44\n"
        "n=2\t10.20.30.40\n"
        "n=4\tc2.evil-corp.org\n"
        "n=9\t10.0.19041.1\n"
        "n=7\t255.255.255.255\n"
        "n=6\t127.0.0.1\n"
        "n=3\tkernel32.dll\n",
        encoding="utf-8",
    )

    # telephone.txt & ccn.txt
    (out_dir / "telephone.txt").write_text(
        "# Feature-Recorder: telephone\n"
        "600\t+1-415-555-2671\tCall +1-415-555-2671 immediately\n"
        "650\t000-000-0000\t000-000-0000\n"
        "700\t415-555-9988\t\\220\\000\\377\\001\\201\\376\\002\\003415-555-9988\\377\\220\\001\n",
        encoding="utf-8",
    )
    (out_dir / "ccn.txt").write_text(
        "# Feature-Recorder: ccn\n"
        "800\t4532015112830366\tCard: 4532015112830366 EXP 12/27\n"
        "850\t4532015112830367\tCard: 4532015112830367 bad luhn\n"
        "900\t4532015112830366\t\\220\\000\\377\\001\\250\\3764532015112830366\\377\\001\\220\n",
        encoding="utf-8",
    )

    # url_services.txt (non-_histogram filename with Histogram-File-Version header)
    (out_dir / "url_services.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        "n=3\t://c2.evil-corp.org\n"
        "n=2\t://127.0.0.1\n",
        encoding="utf-8",
    )

    # Excluded metadata/noise files that MUST NOT be ingested
    (out_dir / "report.xml").write_text("<dfxml>noise@evil-corp.org</dfxml>", encoding="utf-8")
    (out_dir / "duplicates.txt").write_text("100\tdup@evil-corp.org\tctx\n", encoding="utf-8")
    (out_dir / "rtti.txt").write_text("100\t.?AVbad_alloc@std@@\tctx\n", encoding="utf-8")
    (out_dir / "aes_keys.txt").write_text("100\t001122334455\tctx\n", encoding="utf-8")
    (out_dir / "email_tags.txt").write_text("100\ttag@evil-corp.org\tctx\n", encoding="utf-8")
    (out_dir / "email_stopped.txt").write_text("100\tstop@evil-corp.org\tctx\n", encoding="utf-8")

    feats, hists, _ = runner.parse_output_directory(out_dir)
    feat_map = {(sc, f): off for sc, off, f, _ctx, _src in feats}

    # Positive ground-truth assertions
    assert ("email", "suspect@evil-corp.org") in feat_map
    assert feat_map[("email", "zip_insider@exfil-ops.net")] == "1048576-ZIP-0"
    assert ("email", "u@corp.org") in feat_map
    assert ("domain", "198.51.100.44") in feat_map
    assert ("domain", "10.20.30.40") in feat_map
    assert ("domain", "c2.evil-corp.org") in feat_map
    assert ("telephone", "+1-415-555-2671") in feat_map
    assert ("ccn", "4532015112830366") in feat_map

    # Strict R3 zero-false-positive rejections
    all_feat_values = {f for _sc, _off, f, _ctx, _src in feats}
    for forbidden in (
        "logo@2x.png",
        "bad@kernel32.dll",
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "999.1.2.3",
        "10.0.19041.1",
        "kernel32.dll",
        "ntoskrnl.exe",
        "000-000-0000",
        "415-555-9988",
        "4532015112830367",
        "dup@evil-corp.org",
        "tag@evil-corp.org",
        "stop@evil-corp.org",
    ):
        assert forbidden not in all_feat_values, f"False positive leaked into features: {forbidden}"

    hist_map = {(sc, f): cnt for sc, cnt, f, _src in hists}
    assert hist_map.get(("domain", "198.51.100.44")) == 5
    assert hist_map.get(("domain", "10.20.30.40")) == 2
    assert hist_map.get(("domain", "c2.evil-corp.org")) == 4
    assert hist_map.get(("url_services", "://c2.evil-corp.org")) == 3
    assert ("domain", "10.0.19041.1") not in hist_map
    assert ("domain", "255.255.255.255") not in hist_map
    assert ("domain", "127.0.0.1") not in hist_map
    assert ("domain", "kernel32.dll") not in hist_map
    assert ("url_services", "://127.0.0.1") not in hist_map


def test_bulk_extractor_live_binary_execution_image_and_directory(isolated_wft_env, tmp_path):
    be_bin = wft_config.find_bulk_extractor_binary()
    assert be_bin is not None and be_bin.is_file(), "Live bulk_extractor64.exe must be provisioned from M1"

    # Build a 32 KB raw image containing genuine IOCs + valid minimal JPEG + PE version/broadcast noise
    minimal_jpeg = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
        b"\xff\xdb\x00C\x00" + bytes([8] * 64)
        + b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
        + b"\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x7f\xff\xd9"
    )
    clean_block = (
        b"Incident Log Entry:\r\n"
        b"Attacker Email: operator@dark-nexus.org\r\n"
        b"Exfil Endpoint: https://drop.dark-nexus.org/upload\r\n"
        b"Callback IP: 198.51.100.77\r\n"
        b"Operator Phone: +1-202-555-0194\r\n"
    )
    noise_block = (
        b"MZ\x90\x00\x03\x00\x00\x00FileVersion\x0010.0.19041.1\x00"
        b"255.255.255.255\x00127.0.0.1\x000.0.0.0\x00kernel32.dll\x00"
    )
    raw_img = tmp_path / "live_sample.raw"
    raw_img.write_bytes(clean_block.ljust(8192, b" ") + minimal_jpeg.ljust(8192, b"\x00") + noise_block.ljust(16384, b"\x00"))

    case_img_dir = tmp_path / "case_live_be_img"
    runner_img = BulkExtractorRunner(case_id="m2b_live_be_img", case_dir=case_img_dir)
    res_img = runner_img.run(source_path=raw_img, max_workers=4, enable_carving=True)
    assert res_img["status"] == "SUCCESS"
    assert "-R" not in res_img["command"]
    assert res_img["features_ingested"] > 0

    conn_img = DuckDBManager.get_connection("m2b_live_be_img")
    db_feats = {
        r[0]
        for r in conn_img.execute("SELECT feature FROM parsed_bulk_extractor_features;").fetchall()
    }
    db_hists = {
        r[0]
        for r in conn_img.execute("SELECT feature FROM parsed_bulk_extractor_histograms;").fetchall()
    }
    assert "operator@dark-nexus.org" in db_feats
    assert any("drop.dark-nexus.org" in f for f in db_feats)
    assert "198.51.100.77" in db_feats
    for fp_val in ("255.255.255.255", "127.0.0.1", "0.0.0.0", "10.0.19041.1", "kernel32.dll"):
        assert fp_val not in db_feats
        assert fp_val not in db_hists

    # Live directory recursion (-R)
    ev_dir = tmp_path / "live_dir_evidence"
    (ev_dir / "subdir").mkdir(parents=True)
    (ev_dir / "subdir" / "chat.log").write_text(
        "Contact folder_agent@cyber-triage.net at https://portal.cyber-triage.net/login\n",
        encoding="utf-8",
    )
    case_dir_mode = tmp_path / "case_live_be_dir"
    runner_dir = BulkExtractorRunner(case_id="m2b_live_be_dir", case_dir=case_dir_mode)
    res_dir = runner_dir.run(source_path=ev_dir, max_workers=4, enable_carving=False)
    assert res_dir["status"] == "SUCCESS"
    assert "-R" in res_dir["command"]

    conn_dir = DuckDBManager.get_connection("m2b_live_be_dir")
    dir_feats = {
        r[0]
        for r in conn_dir.execute("SELECT feature FROM parsed_bulk_extractor_features;").fetchall()
    }
    assert "folder_agent@cyber-triage.net" in dir_feats


# ===========================================================================
# 2. RegRipperRunner Tests
# ===========================================================================

def test_regripper_v28_rejection_cwd_40dash_and_headerless_plugins(
    isolated_wft_env, compiled_rip_shims, tmp_path, monkeypatch
):
    v28_exe, v40_exe = compiled_rip_shims
    rip_log = tmp_path / "rip_invocations.log"
    monkeypatch.setenv("WFT_TEST_RIP_LOG", str(rip_log))

    # Point find_regripper_binary() to legacy v2.8 while WFT_REGRIPPER_EXE points to v4.0
    monkeypatch.setattr("backend.orchestrator.regripper_runner.find_regripper_binary", lambda: v28_exe)
    monkeypatch.setenv("WFT_REGRIPPER_EXE", str(v40_exe))

    case_dir = tmp_path / "case_rr_shim"
    build_minimal_regf_hive(
        case_dir / "staging" / "Registry" / "System" / "SOFTWARE",
        embedded_name="\\SystemRoot\\System32\\Config\\SOFTWARE",
        subkey_chain=["Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"Updater": "C:\\Program Files\\App\\updater.exe"},
    )

    runner = RegRipperRunner(case_id="m2b_rr_shim", case_dir=case_dir, max_workers=4)

    # Verify selected_artifacts gating skips cleanly when registry not selected
    skip_res = runner.run(selected_artifacts=["browser_history", "docs_pdf"])
    assert skip_res["status"] == "SKIPPED"
    assert skip_res["plugins_parsed"] == 0

    # Full run with cwd changed to unrelated folder to verify cwd=str(rip_exe.parent)
    orig_cwd = Path.cwd()
    other_cwd = tmp_path / "unrelated_cwd"
    other_cwd.mkdir()
    os.chdir(other_cwd)
    try:
        res = runner.run(max_workers=4)
    finally:
        os.chdir(orig_cwd)

    assert res["status"] == "SUCCESS"
    # Exactly 6 plugins: radar (NOT split into 3 fragments!) + 5 headerless plugins
    assert res["plugins_parsed"] == 6

    invocations = rip_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(invocations) >= 2
    for inv in invocations:
        recorded_cwd = inv.split("|", 1)[0]
        assert Path(recorded_cwd).resolve() == v40_exe.parent.resolve()

    conn = DuckDBManager.get_connection("m2b_rr_shim")
    rows = conn.execute(
        "SELECT plugin_name, plugin_version, report_text FROM raw_regripper ORDER BY _row_id;"
    ).fetchall()
    parsed_names = [r[0] for r in rows]
    assert parsed_names == ["radar", "landesk", "appspecific", "userassist", "productpolicy", "osversion"]
    assert "Total" not in parsed_names
    versions = {r[0]: r[1] for r in rows}
    assert versions["userassist"] == "20200921"
    assert versions["landesk"] == "20220930"
    assert "Total Diagnosed: 1" in rows[0][2]


def test_regripper_live_multi_user_vss_parallel_and_preserves_raw_recmd(
    isolated_wft_env, tmp_path
):
    case_id = "m2b_rr_live"
    case_dir = tmp_path / "case_rr_live"

    # 1) clean_hives Alice NTUSER.DAT (must take priority over staging/Registry/Users/Alice/NTUSER.DAT)
    build_minimal_regf_hive(
        case_dir / "clean_hives" / "Users" / "Alice" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"AliceCleanAgent": "C:\\Users\\Alice\\AppData\\Roaming\\alice_clean.exe"},
    )
    build_minimal_regf_hive(
        case_dir / "staging" / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"AliceDirtyStale": "C:\\Users\\Alice\\dirty_should_not_win.exe"},
    )
    # 2) staging/Registry/Users/Bob/NTUSER.DAT (distinct user — must NOT collide with Alice!)
    build_minimal_regf_hive(
        case_dir / "staging" / "Registry" / "Users" / "Bob" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Bob\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"BobSyncDaemon": "C:\\Users\\Bob\\AppData\\Local\\bob_sync.exe"},
    )
    # 3) VSS snapshot hive for Alice (must also execute without colliding with active Alice!)
    build_minimal_regf_hive(
        case_dir / "staging" / "VSS" / "VSS_1" / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"AliceVSSHistory": "C:\\Users\\Alice\\old_vss_tool.exe"},
    )

    runner = RegRipperRunner(case_id=case_id, case_dir=case_dir, max_workers=4)

    # Pre-seed artifact_registry with raw_recmd to prove RegRipperRunner NEVER deletes it
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS artifact_registry (
                artifact_id VARCHAR PRIMARY KEY,
                category VARCHAR NOT NULL,
                display_name VARCHAR NOT NULL,
                table_name VARCHAR NOT NULL,
                source_tool VARCHAR NOT NULL,
                row_count BIGINT DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO artifact_registry VALUES (
                'registry_recmd', 'OPERATING SYSTEM', 'Registry Hive Batch Analysis (RECmd)',
                'raw_recmd', 'RECmd', 42, CURRENT_TIMESTAMP
            );
            """
        )

    res = runner.run(max_workers=4)
    assert res["status"] == "SUCCESS"
    assert res["hives_processed"] == 3
    assert res["plugins_parsed"] > 30

    # Verify unique _rip.txt reports exist per user & VSS snapshot
    assert (runner.regripper_out_dir / "ntuser_alice_rip.txt").is_file()
    assert (runner.regripper_out_dir / "ntuser_bob_rip.txt").is_file()
    assert (runner.regripper_out_dir / "vss1_ntuser_alice_rip.txt").is_file()

    conn = DuckDBManager.get_connection(case_id)
    hive_names = {r[0] for r in conn.execute("SELECT DISTINCT hive_name FROM raw_regripper;").fetchall()}
    assert hive_names == {"Alice/NTUSER.DAT", "Bob/NTUSER.DAT", "VSS1/Alice/NTUSER.DAT"}

    full_reports = "\n".join(r[0] for r in conn.execute("SELECT report_text FROM raw_regripper;").fetchall())
    assert "AliceCleanAgent" in full_reports
    assert "BobSyncDaemon" in full_reports
    assert "AliceVSSHistory" in full_reports
    assert "AliceDirtyStale" not in full_reports

    # Verify raw_recmd was NOT deleted from artifact_registry!
    recmd_reg = conn.execute(
        "SELECT artifact_id, row_count FROM artifact_registry WHERE table_name = 'raw_recmd';"
    ).fetchone()
    assert recmd_reg == ("registry_recmd", 42)

    rr_reg = conn.execute(
        "SELECT artifact_id, row_count FROM artifact_registry WHERE table_name = 'raw_regripper';"
    ).fetchone()
    assert rr_reg == ("regripper_plugins", res["plugins_parsed"])

    rr_log = conn.execute(
        "SELECT status, rows_ingested FROM processing_logs WHERE module_name = 'RegRipper';"
    ).fetchone()
    assert rr_log == ("SUCCESS", res["plugins_parsed"])


# ===========================================================================
# 3. EZToolRunner + Hindsight Tests
# ===========================================================================

def test_ez_runner_rla_clean_hives_multi_user_vss_and_multi_csv_ingestion(
    isolated_wft_env, tmp_path
):
    case_id = "m2b_ez_rla_csv"
    case_dir = tmp_path / "case_ez_rla"
    staging_dir = case_dir / "staging"
    csv_out_dir = case_dir / "csv_out"

    # Stage multi-user + System + Amcache + VSS hives (+ dummy .LOG1 file that must not copy to clean_hives)
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        "\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        ["Software", "AliceKey"],
        {"User": "Alice"},
    )
    (staging_dir / "Registry" / "Users" / "Alice" / "NTUSER.DAT.LOG1").write_bytes(b"regf" + b"\x00" * 512)
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Bob" / "NTUSER.DAT",
        "\\??\\C:\\Users\\Bob\\NTUSER.DAT",
        ["Software", "BobKey"],
        {"User": "Bob"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Alice" / "UsrClass.dat",
        "\\??\\C:\\Users\\Alice\\UsrClass.dat",
        ["Local Settings"],
        {"Shell": "AliceShell"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "System" / "SYSTEM",
        "\\SystemRoot\\System32\\Config\\SYSTEM",
        ["ControlSet001", "Control"],
        {"ComputerName": "WORKSTATION-01"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Amcache" / "Amcache.hve",
        "\\??\\C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
        ["Root", "InventoryApplicationFile"],
        {"ProgramId": "0001"},
    )
    build_minimal_regf_hive(
        staging_dir / "VSS" / "VSS_1" / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        "\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        ["Software", "AliceVSSKey"],
        {"User": "AliceVSS1"},
    )

    runner = EZToolRunner(case_id=case_id, staging_dir=staging_dir, csv_out_dir=csv_out_dir, max_workers=8)
    assert runner.case_dir == case_dir.resolve()
    assert runner._stage_clean_hives_with_rla() is True

    # Verify exact clean_hives layout with ZERO multi-user overwrites and ZERO .txt/.log* files
    expected_clean = [
        runner.clean_hives_dir / "Users" / "Alice" / "NTUSER.DAT",
        runner.clean_hives_dir / "Users" / "Bob" / "NTUSER.DAT",
        runner.clean_hives_dir / "Users" / "Alice" / "UsrClass.dat",
        runner.clean_hives_dir / "System" / "SYSTEM",
        runner.clean_hives_dir / "Amcache" / "Amcache.hve",
        runner.clean_hives_dir / "VSS" / "VSS_1" / "Users" / "Alice" / "NTUSER.DAT",
    ]
    for p in expected_clean:
        assert p.is_file(), f"Missing expected cleaned hive at {p}"

    all_clean_files = [p for p in runner.clean_hives_dir.rglob("*") if p.is_file()]
    assert not any(p.name.lower().endswith((".txt", ".log", ".log1", ".log2")) for p in all_clean_files)
    assert (runner.clean_hives_dir / "Users" / "Alice" / "NTUSER.DAT").read_bytes() != (
        runner.clean_hives_dir / "Users" / "Bob" / "NTUSER.DAT"
    ).read_bytes()

    # Verify multi-CSV Amcache mapping (AssociatedFileEntries fallback -> raw_amcache_files + DriveBinaries spelling!)
    amc_dir = csv_out_dir / "amcache"
    amc_dir.mkdir(parents=True, exist_ok=True)
    (amc_dir / "20261116_amcache_AssociatedFileEntries.csv").write_text(
        "FullPath,SHA1\nC:\\Tools\\psexec.exe,1111\n", encoding="utf-8"
    )
    (amc_dir / "20261116_amcache_DriveBinaries.csv").write_text(
        "DriverName,Service\nmaldrv.sys,maldrv\n", encoding="utf-8"
    )
    (amc_dir / "20261116_amcache_ProgramEntries.csv").write_text(
        "Name,Version\n7-Zip,24.0\n", encoding="utf-8"
    )
    amc_res = runner.ingest_csv_directory("amcache", amc_dir)
    assert amc_res["raw_amcache_assoc_files"] == 1
    assert amc_res["raw_amcache_files"] == 1
    assert amc_res["raw_amcache_drivers"] == 1
    assert amc_res["raw_amcache_programs"] == 1

    # Verify JLECmd multi-CSV (AutomaticDestinations + CustomDestinations)
    jl_dir = csv_out_dir / "jlecmd"
    jl_dir.mkdir(parents=True, exist_ok=True)
    (jl_dir / "jlecmd_AutomaticDestinations.csv").write_text(
        "SourceFile,Path\na.automaticDestinations-ms,C:\\secret1.docx\n", encoding="utf-8"
    )
    (jl_dir / "jlecmd_CustomDestinations.csv").write_text(
        "SourceFile,LocalPath\nb.customDestinations-ms,C:\\secret2.docx\n", encoding="utf-8"
    )
    jl_res = runner.ingest_csv_directory("jlecmd", jl_dir)
    assert jl_res == {"raw_jlecmd_auto": 1, "raw_jlecmd_custom": 1}

    # Verify SumECmd multi-CSV (SUMMARY_RoleInfos vs DETAIL_* never wipes raw_sum!)
    sum_dir = csv_out_dir / "sum"
    sum_dir.mkdir(parents=True, exist_ok=True)
    (sum_dir / "20261116_SumECmd_SUMMARY_RoleInfos_Output.csv").write_text(
        "RoleGuid,RoleName,TotalAccesses\n{10A9226F},File Server,15\n", encoding="utf-8"
    )
    (sum_dir / "20261116_SumECmd_DETAIL_Clients_Output.csv").write_text(
        "AuthenticatedUserName,IpAddress,TotalAccesses\nCORP\\alice,10.0.0.5,15\n", encoding="utf-8"
    )
    sum_res = runner.ingest_csv_directory("sum", sum_dir)
    assert sum_res["raw_sum"] == 1
    assert sum_res["raw_sum_details"] == 1

    conn = DuckDBManager.get_connection(case_id)
    role_row = conn.execute("SELECT RoleName FROM raw_sum;").fetchone()
    assert role_row == ("File Server",)
    amc_view_cnt = conn.execute("SELECT COUNT(*) FROM raw_amcache;").fetchone()[0]
    assert amc_view_cnt == 1


def test_ez_runner_live_parallel_rbcmd_recmd_sqlecmd_wxt_and_hindsight_cwd_hygiene(
    isolated_wft_env, tmp_path
):
    # Pre-check clean workspace state before test
    assert not (BASE_DIR / "hindsight.log").exists()
    assert not (BASE_DIR / "hindsight-temp").exists()

    case_id = "m2b_ez_live_parallel"
    case_dir = tmp_path / "case_ez_live"
    staging_dir = case_dir / "staging"
    csv_out_dir = case_dir / "csv_out"

    # Deliberately create an EMPTY staging/SQLite folder to test the SQLECmd short-circuit fix!
    (staging_dir / "SQLite").mkdir(parents=True, exist_ok=True)

    # 1) Recycle Bin $I file
    build_win10_recycle_bin_i_file(
        staging_dir / "RecycleBin" / "$I987654.docx",
        original_win_path="C:\\Users\\Alice\\Documents\\secret_plan.docx",
        file_size=16384,
    )

    # 2) Multi-user NTUSER.DAT hives with Run keys (for rla.exe + RECmd Kroll_Batch.reb)
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"AliceStartupCmd": "C:\\Users\\Alice\\alice_autorun.exe"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Bob" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Bob\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"BobStartupCmd": "C:\\Users\\Bob\\bob_autorun.exe"},
    )

    # 3) Multi-user Windows Timeline ActivitiesCache.db files (for WxTCmd multi-user union + SQLECmd)
    build_wxt_activities_db(
        staging_dir / "ActivitiesCache" / "Alice" / "ActivitiesCache.db",
        activity_guid_hex="11111111222233334444555566667777",
        app_name="C:\\Tools\\alice_tool.exe",
        display_text="AliceDocument.xlsx",
    )
    build_wxt_activities_db(
        staging_dir / "ActivitiesCache" / "Bob" / "ActivitiesCache.db",
        activity_guid_hex="888888889999aaaabbbbccccddddeeee",
        app_name="C:\\Tools\\bob_tool.exe",
        display_text="BobReport.pdf",
    )

    # 4) Multi-user Chromium profiles (for live Hindsight + SQLECmd browser hunting)
    build_chromium_profile(
        staging_dir / "Browsers" / "Chrome" / "Alice" / "Default",
        url="https://intranet.corp.example/alice-secret",
        title="Alice Secret Portal",
    )
    build_chromium_profile(
        staging_dir / "Browsers" / "Edge" / "Bob" / "Profile 1",
        url="https://fileshare.corp.example/bob-archive",
        title="Bob Archive Portal",
    )

    runner = EZToolRunner(case_id=case_id, staging_dir=staging_dir, csv_out_dir=csv_out_dir, max_workers=8)
    results = runner.run_all(
        max_workers=8,
        enable_hindsight=True,
        selected_artifacts=[
            "fs_recyclebin",
            "registry_recmd",
            "os_wxt_activity",
            "sqlecmd",
            "web_hindsight",
        ],
    )

    # CRITICAL M1 RUNTIME CONTRACT: Verify hindsight.log, hindsight-temp, and SQLite.Interop.dll NEVER polluted Desktop/WFT!
    assert not (BASE_DIR / "hindsight.log").exists(), "hindsight.log leaked into Desktop/WFT!"
    assert not (BASE_DIR / "hindsight-temp").exists(), "hindsight-temp leaked into Desktop/WFT!"
    assert not (BASE_DIR / "SQLite.Interop.dll").exists(), "SQLite.Interop.dll leaked into Desktop/WFT!"
    assert not any(p.name.startswith("_tmp_") for p in runner.hindsight_out_dir.iterdir())
    assert not (csv_out_dir / "sqlecmd" / "_staged_inputs").exists()

    conn = DuckDBManager.get_connection(case_id)

    # 1) RBCmd verification
    assert results.get("raw_rbcmd", 0) >= 1
    rb_paths = [r[0] for r in conn.execute("SELECT FileName FROM raw_rbcmd;").fetchall()]
    assert any("secret_plan.docx" in str(p) for p in rb_paths)

    # 2) RECmd + virtual views verification (both Alice & Bob Run keys parsed!)
    assert results.get("raw_recmd", 0) >= 2
    recmd_dump = "\n".join(
        str(r) for r in conn.execute("SELECT * FROM raw_recmd;").fetchall()
    )
    assert "alice_autorun.exe" in recmd_dump
    assert "bob_autorun.exe" in recmd_dump
    autorun_cat = conn.execute(
        "SELECT category FROM artifact_registry WHERE artifact_id = 'view_autoruns';"
    ).fetchone()
    assert autorun_cat == ("OPERATING SYSTEM",)

    # 3) WxTCmd multi-user union verification (both Alice and Bob present, zero overwrite!)
    assert results.get("raw_wxt_activity", 0) >= 2
    wxt_dump = "\n".join(str(r) for r in conn.execute("SELECT * FROM raw_wxt_activity;").fetchall())
    assert "alice_tool.exe" in wxt_dump
    assert "bob_tool.exe" in wxt_dump

    # 4) SQLECmd verification (bypassed empty staging/SQLite and parsed staged DBs!)
    sqle_tables = [t for t in results if t.startswith("raw_sqlecmd_")]
    assert len(sqle_tables) >= 1, f"Expected SQLECmd tables despite empty staging/SQLite, got {results}"

    # 5) Live Hindsight verification (both profiles parsed + zero 1970-01-01 epoch fabrication!)
    assert results.get("raw_hindsight", 0) >= 2
    hs_profiles = {r[0] for r in conn.execute("SELECT DISTINCT profile FROM raw_hindsight;").fetchall()}
    assert "Alice/Default" in hs_profiles
    assert "Bob/Profile 1" in hs_profiles

    hs_urls = {r[0] for r in conn.execute("SELECT DISTINCT url FROM raw_hindsight WHERE url IS NOT NULL;").fetchall()}
    assert "https://intranet.corp.example/alice-secret" in hs_urls
    assert "https://fileshare.corp.example/bob-archive" in hs_urls

    epoch_rows = conn.execute(
        "SELECT COUNT(*) FROM raw_hindsight WHERE CAST(timestamp_utc AS VARCHAR) LIKE '1970-01-01%';"
    ).fetchone()[0]
    assert epoch_rows == 0, "Timeless Hindsight items must have NULL timestamp_utc, never 1970-01-01!"

    hs_reg = conn.execute(
        "SELECT category, table_name, row_count FROM artifact_registry WHERE artifact_id = 'web_hindsight';"
    ).fetchone()
    assert hs_reg == ("WEB RELATED", "raw_hindsight", results["raw_hindsight"])


# ===========================================================================
# 4. Iteration 2 (2B.b) Remediation Regression Tests
# ===========================================================================

def test_ez_hindsight_modern_brave_vss_discovery_and_return_contract(
    isolated_wft_env, tmp_path
):
    case_id = "m2b_hs_brave_vss"
    case_dir = tmp_path / "case_hs_brave"
    staging_dir = case_dir / "staging"
    csv_out_dir = case_dir / "csv_out"

    # 1) Modern Chromium-based Brave profile (History + Bookmarks, NO legacy Muon session-store-1)
    build_chromium_profile(
        staging_dir / "Browsers" / "Brave" / "Dana" / "Profile 2",
        url="https://brave-portal.corp.example/dana-dashboard",
        title="Dana Brave Dashboard",
    )
    # 2) VSS snapshot Chromium profile that MUST still be discovered when pipeline passes staging_dir / "Browsers"
    build_chromium_profile(
        staging_dir / "VSS" / "VSS_1" / "Browsers" / "Chrome" / "Eve" / "Default",
        url="https://vss-portal.corp.example/eve-shadow",
        title="Eve Shadow Copy History",
    )

    runner = EZToolRunner(case_id=case_id, staging_dir=staging_dir, csv_out_dir=csv_out_dir, max_workers=4)
    res = runner.run_hindsight(browsers_dir=staging_dir / "Browsers", max_workers=4)

    # Verify Dict[str, int] contract: sum(res.values()) evaluates cleanly to int with zero TypeError
    assert isinstance(res, dict)
    assert list(res.keys()) == ["raw_hindsight"]
    total_rows = sum(res.values())
    assert isinstance(total_rows, int)
    assert total_rows >= 2

    conn = DuckDBManager.get_connection(case_id)
    brave_rows = conn.execute(
        "SELECT browser, profile, url FROM raw_hindsight WHERE browser = 'Brave';"
    ).fetchall()
    assert len(brave_rows) >= 1, "Modern Chromium Brave profile must produce rows (never 0-row Muon skip)!"
    assert any(r[1] == "Dana/Profile 2" and r[2] == "https://brave-portal.corp.example/dana-dashboard" for r in brave_rows)

    all_urls = {
        r[0] for r in conn.execute("SELECT DISTINCT url FROM raw_hindsight WHERE url IS NOT NULL;").fetchall()
    }
    assert "https://vss-portal.corp.example/eve-shadow" in all_urls

    # Verify 0-profile image run_all(enable_hindsight=True) unconditionally includes "raw_hindsight": 0
    empty_case_dir = tmp_path / "case_hs_zero_profiles"
    empty_runner = EZToolRunner(
        case_id="m2b_hs_zero",
        staging_dir=empty_case_dir / "staging",
        csv_out_dir=empty_case_dir / "csv_out",
        max_workers=4,
    )
    empty_all = empty_runner.run_all(
        max_workers=4,
        enable_hindsight=True,
        selected_artifacts=["web_hindsight"],
    )
    assert "raw_hindsight" in empty_all
    assert empty_all["raw_hindsight"] == 0
    assert sum(empty_all.values()) == 0


def test_concurrent_warm_clean_hives_race_and_regripper_corrupt_hive_warning(
    isolated_wft_env, tmp_path
):
    from concurrent.futures import ThreadPoolExecutor

    case_id = "m2b_clean_hives_race"
    case_dir = tmp_path / "case_race"
    staging_dir = case_dir / "staging"
    csv_out_dir = case_dir / "csv_out"

    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        "\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        ["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        {"AliceRun": "C:\\Users\\Alice\\alice.exe"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Bob" / "NTUSER.DAT",
        "\\??\\C:\\Users\\Bob\\NTUSER.DAT",
        ["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        {"BobRun": "C:\\Users\\Bob\\bob.exe"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Alice" / "UsrClass.dat",
        "\\??\\C:\\Users\\Alice\\UsrClass.dat",
        ["Local Settings", "Software"],
        {"ShellState": "1"},
    )
    build_minimal_regf_hive(
        staging_dir / "Registry" / "System" / "SYSTEM",
        "\\SystemRoot\\System32\\Config\\SYSTEM",
        ["ControlSet001", "Control", "ComputerName", "ComputerName"],
        {"ComputerName": "RACE-HOST-01"},
    )
    build_minimal_regf_hive(
        staging_dir / "VSS" / "VSS_1" / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        "\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        ["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        {"AliceVSSRun": "C:\\Users\\Alice\\alice_vss.exe"},
    )

    ez = EZToolRunner(case_id=case_id, staging_dir=staging_dir, csv_out_dir=csv_out_dir, max_workers=8)
    rr = RegRipperRunner(case_id=case_id, case_dir=case_dir, max_workers=8)

    # Warm clean_hives upfront (matching pipeline.py run_rla() stage)
    assert ez.run_rla() is True
    assert ez._clean_hives_are_warm() is True

    baseline = rr.run(max_workers=8)
    assert baseline["status"] == "SUCCESS"
    assert baseline["hives_processed"] == 5
    baseline_plugins = baseline["plugins_parsed"]
    assert baseline_plugins > 40

    # Concurrently force _stage_clean_hives_with_rla() while RegRipperRunner.run() reads clean_hives/
    def _delayed_rla() -> bool:
        time.sleep(0.05)
        return ez._stage_clean_hives_with_rla()

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_rla = pool.submit(_delayed_rla)
        fut_rr = pool.submit(rr.run, 8)
        rla_ok = fut_rla.result()
        race_res = fut_rr.result()

    assert rla_ok is True
    assert race_res["status"] == "SUCCESS"
    assert race_res["hives_processed"] == 5
    assert race_res["plugins_parsed"] == baseline_plugins

    # Verify temporary _clean_hives_build_* directory was cleaned up
    assert not any(p.name.startswith("_clean_hives_build_") for p in case_dir.iterdir())

    # Part B: Corrupt hive with non-zero rip.exe exit code MUST report status="WARNING"
    bad_case_id = "m2b_rr_corrupt"
    bad_case_dir = tmp_path / "case_rr_corrupt"
    corrupt_hive = bad_case_dir / "staging" / "Registry" / "System" / "SYSTEM"
    corrupt_hive.parent.mkdir(parents=True, exist_ok=True)
    corrupt_hive.write_bytes(b"regf" + b"\xff\x00\xfe\x01" * 32)  # truncated invalid hive -> rip.exe rc != 0

    bad_rr = RegRipperRunner(case_id=bad_case_id, case_dir=bad_case_dir, max_workers=2)
    bad_res = bad_rr.run(max_workers=2)
    assert bad_res["status"] == "WARNING"
    bad_conn = DuckDBManager.get_connection(bad_case_id)
    log_row = bad_conn.execute(
        "SELECT status, error_message FROM processing_logs WHERE module_name = 'RegRipper' ORDER BY log_id DESC LIMIT 1;"
    ).fetchone()
    assert log_row is not None
    assert log_row[0] == "WARNING"
    assert "returncode=" in (log_row[1] or "")


def test_ez_recmd_updates_artifact_registry_and_preserves_parsed_union_views(
    isolated_wft_env, tmp_path
):
    case_id = "m2b_recmd_union_views"
    case_dir = tmp_path / "case_recmd_union"
    staging_dir = case_dir / "staging"
    csv_out_dir = case_dir / "csv_out"

    build_minimal_regf_hive(
        staging_dir / "Registry" / "Users" / "Alice" / "NTUSER.DAT",
        embedded_name="\\??\\C:\\Users\\Alice\\NTUSER.DAT",
        subkey_chain=["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        str_values={"AlicePersist": "C:\\Users\\Alice\\persist_agent.exe"},
    )

    ez = EZToolRunner(case_id=case_id, staging_dir=staging_dir, csv_out_dir=csv_out_dir, max_workers=4)

    # Pre-seed real schema.py parsed_autoruns, parsed_userassist, and parsed_bam_dam tables
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id)
        conn.execute(
            """
            INSERT INTO parsed_autoruns (
                _row_id, entry_name, autorun_type, category, key_path, value_name,
                command, image_path, username, last_write_utc, hive_path
            ) VALUES (
                1, 'FallbackServiceRun', 'Run Key', 'Run Key',
                'NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'FallbackServiceRun', 'C:\\Fallback\\svc.exe --daemon',
                'C:\\Fallback\\svc.exe', 'FallbackUser', CURRENT_TIMESTAMP, 'NTUSER.DAT'
            );
            INSERT INTO parsed_userassist (
                _row_id, username, guid, rot13_name, program_path, run_count,
                focus_count, focus_time_ms, last_executed_utc, hive_path
            ) VALUES (
                1, 'FallbackUser', '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}',
                'P:\\Gbbyf\\snyyonpx_hn.rkr', 'C:\\Tools\\fallback_ua.exe',
                5, 2, 1200, CURRENT_TIMESTAMP, 'NTUSER.DAT'
            );
            INSERT INTO parsed_bam_dam (
                _row_id, service_type, user_sid, username, executable_path,
                last_execution_utc, key_path, hive_path
            ) VALUES (
                1, 'BAM', 'S-1-5-21-1001', 'FallbackUser',
                '\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe',
                CURRENT_TIMESTAMP,
                'SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1001',
                'SYSTEM'
            );
            """
        )

    assert ez._stage_clean_hives_with_rla() is True
    recmd_res = ez.run_recmd()
    assert recmd_res.get("raw_recmd", 0) >= 1

    conn = DuckDBManager.get_connection(case_id)
    reg_cnt = conn.execute(
        "SELECT row_count FROM artifact_registry WHERE artifact_id = 'registry_recmd';"
    ).fetchone()
    assert reg_cnt is not None and reg_cnt[0] >= 1

    # Verify view_autoruns preserves BOTH parsed_autoruns AND raw_recmd via UNION ALL
    parsed_ar_cnt = conn.execute(
        "SELECT COUNT(*) FROM view_autoruns WHERE source_table = 'parsed_autoruns';"
    ).fetchone()[0]
    recmd_ar_cnt = conn.execute(
        "SELECT COUNT(*) FROM view_autoruns WHERE source_table = 'raw_recmd';"
    ).fetchone()[0]
    assert parsed_ar_cnt == 1
    assert recmd_ar_cnt >= 1

    # Verify view_userassist and view_bam_dam also preserve parsed_* fallback rows
    assert conn.execute("SELECT COUNT(*) FROM view_userassist WHERE source_table = 'parsed_userassist';").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM view_bam_dam WHERE source_table = 'parsed_bam_dam';").fetchone()[0] == 1


def test_bulk_extractor_iteration2_carving_off_flanking_noise_oids_headings_phones_and_pua_offsets(
    isolated_wft_env, tmp_path
):
    import gzip
    import shutil
    import zipfile

    be_bin = wft_config.find_bulk_extractor_binary()
    assert be_bin is not None and be_bin.is_file()

    # Part A: Live directory scan (-R) with enable_carving=False, ZIP archive, n=1 encodings, NUL-padded phone, and crypt32.dll
    ev_dir = tmp_path / "iter2_live_dir"
    ev_dir.mkdir(parents=True, exist_ok=True)

    # 1) Real ZIP archive (would produce zip_carved files if default carvers were not disabled!)
    zip_path = ev_dir / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", "Archive note for carving suppression test.\n")

    # 2) Single-occurrence (n=1) genuine IOCs across ASCII, HTML, UTF-16LE BOM, UTF-16LE no-BOM, GZIP, and NUL-padded OLE string
    (ev_dir / "ascii_ioc.txt").write_bytes(
        b"Single exfil contact: one_shot_exfil@secret-target.org and https://lone-drop.beta-target.org/exfil/991\r\n"
    )
    (ev_dir / "page.html").write_bytes(
        b'<html><body><a href="mailto:html_once@gamma-target.net">Contact</a>'
        b'<img src="banner@2x.png"><img src="icon@3x.webp"></body></html>\r\n'
    )
    (ev_dir / "utf16_bom.bin").write_bytes(
        b"\xff\xfe" + "Alert: utf16bom_once@epsilon-target.net https://utf16bom-c2.delta-target.net/stage1\r\n".encode("utf-16-le")
    )
    (ev_dir / "utf16_raw.bin").write_bytes(
        "RawNote: utf16raw_once@zeta-target.net https://utf16raw-c2.eta-target.net/ping\r\n".encode("utf-16-le")
    )
    (ev_dir / "stream.gz").write_bytes(
        gzip.compress(b"Compressed payload: gzip_once@theta-target.org https://gzip-c2.iota-target.org/upload\n")
    )
    (ev_dir / "ole_summary.bin").write_bytes(
        b"\x00" * 64 + b"Field Office\rSeattle, WA\r206-526-6653" + b"\x00\x00\xaa\x0f\x0a\x00\x00\x00" + b"\x00" * 64
    )

    sys_crypt32 = Path(r"C:\Windows\System32\crypt32.dll")
    if sys_crypt32.is_file():
        shutil.copy2(sys_crypt32, ev_dir / "crypt32.dll")

    live_case_dir = tmp_path / "case_iter2_live_be"
    live_runner = BulkExtractorRunner(case_id="m2b_iter2_live_be", case_dir=live_case_dir)
    live_res = live_runner.run(source_path=ev_dir, max_workers=8, enable_carving=False)
    assert live_res["status"] == "SUCCESS"
    assert live_res["carved_files"] == 0

    conn = DuckDBManager.get_connection("m2b_iter2_live_be")
    carved_scanner_rows = conn.execute(
        "SELECT COUNT(*) FROM parsed_bulk_extractor_features WHERE scanner LIKE '%carved%';"
    ).fetchone()[0]
    assert carved_scanner_rows == 0

    # Directory-mode offset_str must contain ZERO Private-Use U+10001C characters
    pua_offsets = conn.execute(
        "SELECT COUNT(*) FROM parsed_bulk_extractor_features WHERE instr(offset_str, chr(1048604)) > 0;"
    ).fetchone()[0]
    assert pua_offsets == 0

    # Zero 4-arc X.509 OIDs (2.5.*) leaked into domain/ip features or histograms
    oid_leaks = conn.execute(
        "SELECT feature FROM parsed_bulk_extractor_features WHERE scanner IN ('domain', 'ip') AND feature LIKE '2.5.%';"
    ).fetchall()
    assert oid_leaks == []
    oid_hist_leaks = conn.execute(
        "SELECT feature FROM parsed_bulk_extractor_histograms WHERE scanner IN ('domain', 'ip') AND feature LIKE '2.5.%';"
    ).fetchall()
    assert oid_hist_leaks == []

    feat_emails = {
        r[0].lower()
        for r in conn.execute("SELECT feature FROM parsed_bulk_extractor_features WHERE scanner = 'email';").fetchall()
    }
    hist_emails = {
        r[0].lower()
        for r in conn.execute("SELECT feature FROM parsed_bulk_extractor_histograms WHERE scanner = 'email';").fetchall()
    }
    for expected_n1_email in (
        "one_shot_exfil@secret-target.org",
        "html_once@gamma-target.net",
        "utf16bom_once@epsilon-target.net",
        "utf16raw_once@zeta-target.net",
        "gzip_once@theta-target.org",
    ):
        assert expected_n1_email in feat_emails, f"Dropped genuine n=1 email from features: {expected_n1_email}"
        assert expected_n1_email in hist_emails, f"Dropped genuine n=1 email from histograms: {expected_n1_email}"

    feat_phones = {
        r[0] for r in conn.execute("SELECT feature FROM parsed_bulk_extractor_features WHERE scanner = 'telephone';").fetchall()
    }
    hist_phones = {
        r[0] for r in conn.execute("SELECT feature FROM parsed_bulk_extractor_histograms WHERE scanner = 'telephone';").fetchall()
    }
    assert "206-526-6653" in feat_phones
    assert "2065266653" in hist_phones

    # Part B: Deterministic synthetic precision test (flanking noise dilution, OIDs, section headings, UA versions, phone/CCN cross-pass)
    syn_case_dir = tmp_path / "case_iter2_syn_be"
    syn_runner = BulkExtractorRunner(case_id="m2b_iter2_syn_be", case_dir=syn_case_dir)
    syn_out = syn_case_dir / "syn_out"
    syn_out.mkdir(parents=True, exist_ok=True)

    # Compute a Luhn-valid 15-digit DMS station ID (37 deg 45' 12" N, 122 deg 25' 08" W + 2-digit seq)
    be_mod_ref = sys.modules["backend.orchestrator.bulk_extractor_runner"]
    dms_prefix14 = "37451212225080"
    dms_station_luhn15 = next(
        dms_prefix14 + str(d)
        for d in range(10)
        if be_mod_ref._luhn_valid(dms_prefix14 + str(d))
    )

    # Note: whole-window noise on noisy_diluted@random-stream.bb is only 9/49 = 0.18,
    # whereas flanking-only noise is 9/21 = 0.43 (> 0.18) + non-delimiter '~' / ')=='!
    (syn_out / "email.txt").write_text(
        "# Feature-Recorder: email\n"
        "100\tnoisy_diluted@random-stream.bb\t\\336\\324\\222\\235q|~noisy_diluted@random-stream.bb)==/@A\\035\\021\\204\\376\n"
        "200\tclean.analyst@agency.gov\t(email address: clean.analyst@agency.gov)\\015\\014\\015PREFACE\n",
        encoding="utf-8",
    )
    (syn_out / "email_histogram.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        "n=1\tnoisy_diluted@random-stream.bb\n"
        "n=1\tclean.analyst@agency.gov\n",
        encoding="utf-8",
    )
    (syn_out / "email_domain_histogram.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        "n=1\t@random-stream.bb\n"
        "n=1\t@agency.gov\n",
        encoding="utf-8",
    )
    (syn_out / "domain.txt").write_text(
        "# Feature-Recorder: domain\n"
        "300\t2.5.29.14\t\\0002.5.29.14\\000SubjectKeyIdentifier\n"
        "310\t2.5.4.6\tOID=2.5.4.6 Country\n"
        "320\t2.5.29.14\tObjects2.5.29.14Subje\n"
        "330\t3.13.4.1\t\\0123.13.4.1  Requirements and Scope\n"
        "340\t3.13.4.2\tpace=\"preserve\">3.13.4.2  </w:t></w:r>\n"
        "350\t120.0.100.12\tMozilla/5.0 Chrome/120.0.100.12 Safari/537.36\n"
        "360\t192.168.1.1\tGateway=192.168.1.1 Mask=255.255.255.0\n",
        encoding="utf-8",
    )
    (syn_out / "domain_histogram.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        "n=4\t2.5.29.14\n"
        "n=2\t2.5.4.6\n"
        "n=8\t3.13.4.1\n"
        "n=3\t3.13.4.2\n"
        "n=5\t120.0.100.12\n"
        "n=2\t192.168.1.1\n",
        encoding="utf-8",
    )
    (syn_out / "telephone.txt").write_text(
        "# Feature-Recorder: telephone\n"
        "400\t415-555-8877\t\\336\\324\\220\\001\\377\\201415-555-8877\\377\\220\\001\\376\n"
        "410\t206-526-6653\tice\\015Seattle, WA\\015206-526-6653\\000\\000\\252\\017\\012\\000\\000\\000\n",
        encoding="utf-8",
    )
    (syn_out / "telephone_histogram.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        "n=1\t4155558877\n"
        "n=1\t2065266653\n",
        encoding="utf-8",
    )
    (syn_out / "ccn.txt").write_text(
        "# Feature-Recorder: ccn\n"
        f"500\t{dms_station_luhn15}\t<si><t>{dms_station_luhn15}</t></si>\n"
        "510\t378282246310005\tAmex Card: 378282246310005 EXP 08/28\n",
        encoding="utf-8",
    )
    (syn_out / "ccn_histogram.txt").write_text(
        "# Histogram-File-Version: 1.1\n"
        f"n=2\t{dms_station_luhn15}\n"
        "n=1\t378282246310005\n",
        encoding="utf-8",
    )

    s_feats, s_hists, _ = syn_runner.parse_output_directory(syn_out, enable_carving=False)
    s_feat_set = {(sc, f) for sc, _off, f, _ctx, _src in s_feats}
    s_hist_set = {(sc, f) for sc, _cnt, f, _src in s_hists}

    # Retained true positives
    assert ("email", "clean.analyst@agency.gov") in s_feat_set
    assert ("email", "clean.analyst@agency.gov") in s_hist_set
    assert ("email_domain", "@agency.gov") in s_hist_set
    assert ("domain", "192.168.1.1") in s_feat_set
    assert ("domain", "192.168.1.1") in s_hist_set
    assert ("telephone", "206-526-6653") in s_feat_set
    assert ("telephone", "2065266653") in s_hist_set
    assert ("ccn", "378282246310005") in s_feat_set
    assert ("ccn", "378282246310005") in s_hist_set

    # Rejected false positives across BOTH features and histograms
    for bad_pair in (
        ("email", "noisy_diluted@random-stream.bb"),
        ("email_domain", "@random-stream.bb"),
        ("domain", "2.5.29.14"),
        ("domain", "2.5.4.6"),
        ("domain", "3.13.4.1"),
        ("domain", "3.13.4.2"),
        ("domain", "120.0.100.12"),
        ("telephone", "415-555-8877"),
        ("telephone", "4155558877"),
        ("ccn", dms_station_luhn15),
    ):
        assert bad_pair not in s_feat_set, f"False positive leaked into features: {bad_pair}"
        assert bad_pair not in s_hist_set, f"False positive leaked into histograms: {bad_pair}"

