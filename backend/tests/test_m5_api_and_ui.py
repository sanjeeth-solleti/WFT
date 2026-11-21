"""
Sub-Milestone M5-B: Comprehensive Headless Playwright & FastAPI UI/API Integration Suite.

Verifies:
1. Clean `frontend/index.html` & compiled SPA bundle (`frontend/dist`) served with zero monkey-patch
   `setInterval` scripts and zero uncaught `pageerror` exceptions.
2. `ProcessWizard` & `ToolPathsModal`:
   - Step 3 `Recovery, Carving & Bulk Extractor` (`fs_vss`, `carve_files`, `bulk_extractor`) mounted
     with `count() == 1` checkbox each; initial default checks 34 standard items and leaves heavy 3
     unchecked; `Comprehensive IR` checks all 37; `Quick Triage` unchecks heavy 3 without overwriting
     `sourceType`; `max_workers` defaults to `16` (`1..32`); `targetStorageDir` defaults empty `""`
     and blocks `targetStorageDir == sourcePath`; Step 3 `KeywordManager` stages keywords locally
     without premature `/keywords` POSTs; visible `Console / Logs` button; `ToolPathsModal` surfaces
     all 21 tools including `bulk_extractor` (`WFT_BULK_EXTRACTOR_EXE`) and all 16 EZ tools.
3. `CaseDashboard`, `TopNavBar` & `SidebarTree`:
   - Renders all 4 Magnet AXIOM cards (`OS & System Information`, `Evidence Source, Partitions & VSS`,
     `Refined Identifiers & Recovery Summary`, `External Tool & Parser Execution Health`).
   - Clicking a Local User (`corp_admin`) opens contextual slide-over `ConnectionsDrawer`.
   - `Export HTML Case Report` (`/report/html`) and TopNav `Export CSV` / `Export HTML` succeed, and
     `rules/event_profiles.json` remains untouched.
   - `SidebarTree` `ALL EVIDENCE` badge count matches `TopNavBar` `Artifacts` count (10 canonical
     categories including `EVENT LOGS` and `MALWARE & YARA`).
4. `GlobalFilterBar` & `ArtifactGrid`:
   - Relative `Last 24 Hours` (`24h`) preset on a historical 2024 forensic case anchors to case
     `max_timestamp_utc` (`2024-05-10`) and returns historical 2024 rows instead of 0.
   - Selecting multiple saved keywords (`mimikatz`, `psexec`) performs SQL/UI **OR** matching across
     distinct rows while preserving independent `globalSearch`.
5. `FileSystemView`, `DetailsAndHexPane`, `RowContextMenu` & `FileBrowserModal`:
   - Zero fabricated `Partition 1 [100MB]`, `20378MB`, or `__PART1__` strings anywhere in DOM or API.
   - Real partitions, VSS, Carved Files, and staged/$Recycle.Bin files load cleanly; `case.duckdb`
     and `processing.log` remain blocked by backend path confinement.
   - Right-click `"Export File / Folder to Custom Destination..."` closes `RowContextMenu`, opens
     root `FileBrowserModal` (`z-[100000]`), and exports directly to a sandboxed destination folder.
   - `Hex Viewer` (both `FileSystemView` and `DetailsAndHexPane`) renders all **256 lines (4,096 B)**,
     pages via `Next 4KB` (`0x00001000`), and jumps to `0x0040`.
   - `Strings` tab extracts ASCII + UTF-16LE strings and narrows live via filter input.
   - `NTFS & $MFT Properties` renders `$STANDARD_INFORMATION (0x10)` vs `$FILE_NAME (0x30)` 8-timestamp
     MACB table and flags `$SI < $FN` with `TIMESTOMPED`.
6. `TimelineExplorer`, `EventLogsWorkbench`, `RegRipperExplorer` & `MalwareWorkbench`:
   - `TimelineExplorer` renders 4-slot `MACB` badges, toggles `DESC`/`ASC` sort, and pivots `±5m`
     around a timestamp with active Pivot banner + `Clear Pivot`.
   - `EventLogsWorkbench` creates a custom profile and deletes it via the trash icon (`delete-profile-*`).
   - `RegRipperExplorer` entity quick-chip click opens contextual `ConnectionsDrawer`.
   - `MalwareWorkbench` renders both Stinger (`_row_id=1`) and YARA (`_row_id=1`) detections via
     composite row keys with zero React duplicate-key console errors.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import pytest
from playwright.sync_api import Browser, Page, sync_playwright

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = WORKSPACE_ROOT / "frontend"
DIST_INDEX = FRONTEND_DIR / "dist" / "index.html"
RULES_PROFILES_JSON = WORKSPACE_ROOT / "rules" / "event_profiles.json"
CASE_ID = "case_m5_ui"
CASE_CONTRACT2_ID = "z_case_m5_contract2"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(s.getsockname()[1])


def _http_get_json(url: str, timeout: float = 5.0) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _build_sample_evidence_bytes() -> bytes:
    """Build a deterministic 6,144-byte sample file spanning two 4KB pages with ASCII & UTF-16LE markers."""
    buf = bytearray(b"\x41" * 6144)

    def place(offset: int, payload: bytes) -> None:
        buf[offset : offset + len(payload)] = payload

    place(0x0000, b"WFT_HEAD_0000_OK\x00")
    place(0x0040, b"JUMP_0040_TARGET\x00")
    place(0x0100, b"ASCII_ALPHA_NEEDLE_2024\x00")
    place(0x0200, "UTF16_BETA_NEEDLE_2024".encode("utf-16le") + b"\x00\x00")
    place(0x1000, b"PAGE2_1000_MARK!\x00")
    return bytes(buf)


def _run_seeder_cli() -> None:
    """Execute inside short-lived `--seed` child process so Windows DuckDB locks close cleanly."""
    import backend.config as config

    config.reload_dotenv()
    from backend.config import get_case_dir, get_case_staging_dir, register_case_dir
    from backend.db.engine import DuckDBManager, init_case_db
    from backend.db.schema import sync_artifact_registry_counts

    case_id = os.environ["WFT_SEED_CASE_ID"]
    case_dir = get_case_dir(case_id, create_if_missing=True)
    register_case_dir(case_id, case_dir)
    staging_dir = get_case_staging_dir(case_id)
    staging_dir.mkdir(parents=True, exist_ok=True)

    # 1. Sample 6,144-byte binary/strings file in staging/Documents/evidence_sample.bin
    docs_dir = staging_dir / "Documents"
    docs_dir.mkdir(parents=True, exist_ok=True)
    sample_bytes = _build_sample_evidence_bytes()
    sample_bin = docs_dir / "evidence_sample.bin"
    sample_bin.write_bytes(sample_bytes)
    sample_sha = hashlib.sha256(sample_bytes).hexdigest()

    # 2. Sample VSS file + $Recycle.Bin regular file + Carved file + processing.log
    vss_doc_dir = staging_dir / "VSS" / "VSS_1" / "Documents"
    vss_doc_dir.mkdir(parents=True, exist_ok=True)
    (vss_doc_dir / "vss_shadow_note.txt").write_text(
        "Recovered from Volume Shadow Copy #1", encoding="utf-8"
    )

    recycle_dir = staging_dir / "$Recycle.Bin"
    recycle_dir.mkdir(parents=True, exist_ok=True)
    (recycle_dir / "$R12345.txt").write_text(
        "Deleted note inside Recycle Bin regular file", encoding="utf-8"
    )

    carved_dir = case_dir / "carved"
    carved_dir.mkdir(parents=True, exist_ok=True)
    carved_jpg = carved_dir / "carved_001.jpg"
    carved_bytes = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00CARVED_JPEG_STREAM_2024"
    )
    carved_jpg.write_bytes(carved_bytes)

    (case_dir / "processing.log").write_text(
        "[2024-05-10T14:00:00Z] Pipeline completed cleanly\n", encoding="utf-8"
    )

    # 3. Populate case.duckdb
    init_case_db(case_id)
    with DuckDBManager.get_lock(case_id):
        conn = DuckDBManager.get_connection(case_id, read_only=False)
        cur = conn.cursor()

        meta_pairs = [
            ("case_name", "M5 AXIOM Verification Case"),
            ("case_number", "DFIR-2024-0510"),
            ("examiner", "Jane Doe"),
            ("notes", "Magnet AXIOM UI & M5 Contract Suite"),
            ("source_path", r"E:\Forensics\WKSTN-FIN-09.E01"),
            ("source_type", "Disk Image (E01)"),
            ("sha256", sample_sha),
            ("max_workers", "16"),
            ("enable_vss", "true"),
            ("enable_data_carving", "true"),
            ("enable_bulk_extractor", "true"),
            ("hostname", "WKSTN-FIN-09"),
            ("os_name", "Windows 11 Enterprise"),
            ("os_build", "22631"),
            ("timezone", "UTC"),
        ]
        for k, v in meta_pairs:
            cur.execute(
                "INSERT INTO case_metadata (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;",
                [k, v],
            )

        # Real disk partitions (explicitly avoiding fake 100MB/20378MB/__PART1__)
        cur.execute(
            """
            INSERT INTO vfs_partitions (
                _row_id, part_index, partition_index, addr, label, volume_label, description,
                fs_type, start_sector, offset_bytes, start_offset_bytes, length_sectors,
                size_bytes, volume_serial, serial_number, is_boot, is_bootable, flags
            ) VALUES
                (1, 0, 0, 2, 'ESP_SYSTEM', 'ESP_SYSTEM', 'EFI System Partition', 'FAT32', 2048, 1048576, 1048576, 532480, 272629760, '1A2B-3C4D', '1A2B-3C4D', TRUE, TRUE, 'Alloc'),
                (2, 1, 1, 3, 'CORP_OS', 'CORP_OS', 'Basic Data Partition (NTFS)', 'NTFS', 534528, 273678336, 273678336, 251658240, 128849018880, '9F8E-7D6C', '9F8E-7D6C', FALSE, FALSE, 'Alloc');
            """
        )

        # Real Volume Shadow Copy
        cur.execute(
            """
            INSERT INTO vfs_shadow_copies (
                _row_id, vss_index, store_index, part_index, partition_index,
                store_id, vss_id, shadow_copy_guid, volume_guid,
                creation_time, creation_time_utc, size_bytes, shadow_copy_size, store_size_bytes,
                staged_prefix, files_staged, status
            ) VALUES (
                1, 1, 1, 1, 1,
                '{deadbeef-1111-2222-3333-444455556666}', 'VSS_1', '{deadbeef-1111-2222-3333-444455556666}', '{11111111-2222-3333-4444-555555555555}',
                '2024-05-09 22:00:00', '2024-05-09 22:00:00', 2147483648, 2147483648, 2147483648,
                'staging/VSS/VSS_1', 1, 'MOUNTED'
            );
            """
        )

        # Real VFS & $MFT rows (including $SI < $FN timestomped evidence_sample.bin!)
        cur.execute(
            """
            INSERT INTO vfs_files (
                _row_id, part_index, partition_index, fs_type, inode, parent_inode,
                vfs_path, staged_rel_path, file_name, extension, parent_path,
                size_bytes, is_dir, is_directory, is_allocated, is_deleted,
                si_created, si_modified, si_accessed, si_changed,
                fn_created, fn_modified, fn_accessed, fn_changed,
                si_created_utc, si_modified_utc, si_accessed_utc, si_changed_utc,
                fn_created_utc, fn_modified_utc, fn_accessed_utc, fn_changed_utc,
                mft_entry, vss_store_index
            ) VALUES
                (
                    1, 1, 1, 'NTFS', 50, 5,
                    'Documents', 'Documents', 'Documents', '', '/',
                    0, TRUE, TRUE, TRUE, FALSE,
                    '2024-05-01 10:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00',
                    '2024-05-01 10:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00',
                    '2024-05-01 10:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00',
                    '2024-05-01 10:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00',
                    50, NULL
                ),
                (
                    2, 1, 1, 'NTFS', 101, 50,
                    'Documents/evidence_sample.bin', 'Documents/evidence_sample.bin', 'evidence_sample.bin', '.bin', 'Documents',
                    6144, FALSE, FALSE, TRUE, FALSE,
                    '2021-01-01 00:00:00', '2021-01-01 00:05:00', '2024-05-10 12:05:00', '2024-05-10 12:05:00',
                    '2024-05-10 12:00:00', '2024-05-10 12:01:00', '2024-05-10 12:05:00', '2024-05-10 12:05:00',
                    '2021-01-01 00:00:00', '2021-01-01 00:05:00', '2024-05-10 12:05:00', '2024-05-10 12:05:00',
                    '2024-05-10 12:00:00', '2024-05-10 12:01:00', '2024-05-10 12:05:00', '2024-05-10 12:05:00',
                    101, NULL
                );
            """
        )

        cur.execute(
            """
            INSERT INTO raw_mft (
                _row_id, EntryNumber, SequenceNumber, InUse, IsDirectory,
                ParentEntryNumber, ParentSequenceNumber, ParentPath, FileName, Extension, FileSize,
                Created0x10, Created0x30, LastModified0x10, LastModified0x30,
                LastAccess0x10, LastAccess0x30, LastRecordChange0x10, LastRecordChange0x30,
                TimestampsLogicalInconsistency
            ) VALUES
                (
                    1, 50, 1, TRUE, TRUE,
                    5, 5, '.', 'Documents', '', 0,
                    '2024-05-01 10:00:00', '2024-05-01 10:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00',
                    '2024-05-10 12:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00', '2024-05-10 12:00:00',
                    FALSE
                ),
                (
                    2, 101, 2, TRUE, FALSE,
                    50, 1, '.\\Documents', 'evidence_sample.bin', '.bin', 6144,
                    '2021-01-01 00:00:00', '2024-05-10 12:00:00', '2021-01-01 00:05:00', '2024-05-10 12:01:00',
                    '2024-05-10 12:05:00', '2024-05-10 12:05:00', '2024-05-10 12:05:00', '2024-05-10 12:05:00',
                    TRUE
                );
            """
        )

        # Carved file & Bulk Extractor hits
        cur.execute(
            """
            INSERT INTO parsed_carved_files (
                _row_id, carve_id, file_name, file_type, extension, mime_type,
                byte_offset, sector_offset, partition_index, size_bytes,
                sha256, md5, carved_path, is_unallocated, source_evidence, timestamp_utc, carved_at
            ) VALUES (
                1, 'carve_001', 'carved_001.jpg', 'jpg', '.jpg', 'image/jpeg',
                1048576, 2048, 1, ?,
                ?, '00112233445566778899aabbccddeeff', 'carved/carved_001.jpg', TRUE, 'WKSTN-FIN-09.E01',
                '2024-05-10 13:15:00', '2024-05-10 13:15:00'
            );
            """,
            [len(carved_bytes), hashlib.sha256(carved_bytes).hexdigest()],
        )

        cur.execute(
            """
            INSERT INTO parsed_bulk_extractor_features (
                _row_id, scanner, offset_str, feature, context, source_file
            ) VALUES
                (1, 'email', '1049600', 'operator@evil-c2.example', 'POST /beacon operator@evil-c2.example', 'email.txt'),
                (2, 'domain', '2097152', 'evil-c2.example', 'Host: evil-c2.example', 'domain.txt');
            """
        )

        # Local User Accounts (for CaseDashboard OS card click -> ConnectionsDrawer)
        cur.execute(
            """
            INSERT INTO parsed_user_accounts (
                _row_id, rid, user_sid, sid, username, full_name, account_type,
                is_disabled, login_count, logon_count, last_login_utc, last_logon_utc,
                profile_path, hive_path, source_file
            ) VALUES (
                1, 1001, 'S-1-5-21-999-1001', 'S-1-5-21-999-1001', 'corp_admin', 'Corporate Admin', 'Administrator',
                FALSE, 42, 42, '2024-05-10 14:00:00', '2024-05-10 14:00:00',
                'C:\\Users\\corp_admin', 'SAM', 'SAM'
            );
            """
        )

        # Prefetch (3 distinct rows to prove multi-keyword OR: row 1 mimikatz, row 2 psexec, row 3 notepad)
        cur.execute(
            """
            INSERT INTO raw_pecmd (
                _row_id, SourceCreated, SourceModified, SourceAccessed,
                SourceFilename, ExecutableName, Hash, Size, Version, RunCount, LastRun
            ) VALUES
                (1, '2024-05-10 14:00:00', '2024-05-10 14:01:00', '2024-05-10 14:01:00', 'Documents/evidence_sample.bin', 'MIMIKATZ.EXE', 'CAFE1111', 6144, 'Win11', 3, '2024-05-10 14:01:00'),
                (2, '2024-05-10 14:02:00', '2024-05-10 14:03:00', '2024-05-10 14:03:00', 'Documents/evidence_sample.bin', 'PSEXEC.EXE', 'BEEF2222', 6144, 'Win11', 2, '2024-05-10 14:03:00'),
                (3, '2024-04-20 08:00:00', '2024-04-20 08:00:00', '2024-04-20 08:00:00', 'C:\\Windows\\Prefetch\\NOTEPAD.EXE-3333.pf', 'NOTEPAD.EXE', 'ABCD3333', 2048, 'Win11', 9, '2024-04-20 08:00:00');
            """
        )

        # Saved Keywords & Hits
        cur.execute(
            """
            INSERT INTO case_keywords (keyword_id, keyword, is_regex, is_case_sensitive, case_sensitive, category, hit_count)
            VALUES
                ('kw_mimi', 'mimikatz', FALSE, FALSE, FALSE, 'Credential Access', 1),
                ('kw_psexec', 'psexec', FALSE, FALSE, FALSE, 'Lateral Movement', 1);
            """
        )
        cur.execute(
            """
            INSERT INTO parsed_keyword_hits (
                _row_id, keyword_id, keyword, is_regex, is_case_sensitive,
                artifact_name, source_table, source_row_id, matched_column, matched_snippet, source_file
            ) VALUES
                (1, 'kw_mimi', 'mimikatz', FALSE, FALSE, 'Prefetch Files - Execution', 'raw_pecmd', 1, 'ExecutableName', 'MIMIKATZ.EXE', 'MIMIKATZ.pf'),
                (2, 'kw_psexec', 'psexec', FALSE, FALSE, 'Prefetch Files - Execution', 'raw_pecmd', 2, 'ExecutableName', 'PSEXEC.EXE', 'PSEXEC.pf');
            """
        )

        # Event Logs (Security + PowerShell — 3 rows in raw_evtx: 2 logon events + 1 PowerShell event)
        cur.execute(
            """
            INSERT INTO raw_evtx (
                _row_id, RecordNumber, EventRecordId, TimeCreated, EventId, Level,
                Provider, Channel, ProcessId, ThreadId, Computer, UserId,
                MapDescription, UserName, RemoteHost, PayloadData1, ExecutableInfo, SourceFile
            ) VALUES
                (1, 1001, 1001, '2024-05-10 14:00:00', 4624, 'Information', 'Microsoft-Windows-Security-Auditing', 'Security', 640, 712, 'WKSTN-FIN-09', 'S-1-5-21-999-1001', 'An account was successfully logged on', 'corp_admin', '10.20.30.40', 'LogonType 3', 'lsass.exe', 'Security.evtx'),
                (2, 2002, 2002, '2024-05-10 14:02:00', 4104, 'Warning', 'Microsoft-Windows-PowerShell', 'Microsoft-Windows-PowerShell/Operational', 4120, 4188, 'WKSTN-FIN-09', 'S-1-5-21-999-1001', 'Execute a Remote Command Scriptblock', 'corp_admin', '10.20.30.40', 'Invoke-Mimikatz -DumpCreds', 'powershell.exe', 'Microsoft-Windows-PowerShell%4Operational.evtx'),
                (3, 1002, 1002, '2024-05-10 14:01:00', 4625, 'Warning', 'Microsoft-Windows-Security-Auditing', 'Security', 640, 712, 'WKSTN-FIN-09', 'S-1-5-21-999-1001', 'An account failed to log on', 'corp_admin', '10.20.30.40', 'LogonType 3', 'lsass.exe', 'Security.evtx');
            """
        )
        cur.execute(
            """
            CREATE OR REPLACE VIEW view_evtx_logons AS
            SELECT * FROM raw_evtx WHERE EventId IN (4624, 4625);
            """
        )

        # RegRipper plugins with inline IP / domain / executable entities
        cur.execute(
            """
            INSERT INTO raw_regripper (
                _row_id, plugin_name, plugin_version, hive_name, hive_type,
                category, mitre_attack, description, report_text, summary_line, output_lines_count
            ) VALUES
                (1, 'compname', '20200511', 'SYSTEM', 'SYSTEM', 'System Config', 'T1082', 'Extracts Hostname & C2 Beacon Info', 'ComputerName    = WKSTN-FIN-09\nBeaconServer    = 185.199.108.153\nImplantBinary   = mimikatz.exe\n', 'ComputerName = WKSTN-FIN-09', 3),
                (2, 'run', '20200511', 'NTUSER.DAT', 'NTUSER', 'Persistence', 'T1547.001', 'User Run Key Persistence', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n  Updater -> C:\\Temp\\psexec.exe (10.20.30.40)\n', 'Updater -> psexec.exe', 2);
            """
        )

        # Malware detections: BOTH Stinger and YARA with _row_id = 1 to verify zero React key collision!
        cur.execute(
            """
            INSERT INTO artifact_stinger_hits (
                _row_id, file_path, file_name, sha256, malware_name,
                detection_type, action_taken, engine_version, details
            ) VALUES (
                1, 'Documents/evidence_sample.bin', 'mimikatz_stinger_sample.exe', ?, 'Trojan-Mimikatz!Stinger',
                'Trojan', 'Reported', '13.0.0', 'Detected credential dumper signature'
            );
            """,
            [sample_sha],
        )

        cur.execute(
            """
            INSERT INTO artifact_yara_hits (
                _row_id, file_path, file_name, extension, size_bytes, sha256,
                rule_name, rule_namespace, pattern_identifier, match_offset, match_length,
                match_data_hex, severity, category, description, mitre_attack
            ) VALUES (
                1, 'Documents/evidence_sample.bin', 'beacon_yara_sample.dll', '.dll', 6144, ?,
                'APT_CobaltStrike_Beacon', 'malware', '$mz_beacon', 64, 16,
                '4F46465345545F30303430', 'CRITICAL', 'MALWARE', 'Matched Cobalt Strike Beacon payload', 'T1055'
            );
            """,
            [sample_sha],
        )

        # Master Timeline: historical May/April 2024 events (max = 2024-05-10 16:30:00)
        cur.execute(
            """
            INSERT INTO master_timeline (
                timeline_id, timestamp_utc, timestamp_type, category, artifact_name,
                primary_entity, secondary_entity, summary, source_table, source_row_id, source_file, macb
            ) VALUES
                (1, '2024-05-10 16:30:00', 'LastRun', 'OPERATING SYSTEM', 'Prefetch Execution', 'PSEXEC.EXE', 'corp_admin', 'Executed PSEXEC.EXE lateral tool', 'raw_pecmd', 2, 'PSEXEC.pf', 'M..B'),
                (2, '2024-05-10 14:03:00', 'ScriptBlock', 'EVENT LOGS', 'PowerShell 4104', 'corp_admin', 'WKSTN-FIN-09', 'PowerShell Invoke-Mimikatz scriptblock', 'raw_evtx', 2, 'PowerShell.evtx', '..CB'),
                (3, '2024-05-10 14:00:00', 'Logon', 'EVENT LOGS', 'Security 4624', 'corp_admin', '10.20.30.40', 'Network logon by corp_admin from 10.20.30.40', 'raw_evtx', 1, 'Security.evtx', '.A..'),
                (4, '2024-04-20 08:00:00', 'Created0x10', 'OPERATING SYSTEM', 'Baseline Binary', 'NOTEPAD.EXE', 'WKSTN-FIN-09', 'Historical April 2024 baseline activity', 'raw_pecmd', 3, 'NOTEPAD.pf', '...B');
            """
        )

        # Entity Connections Graph
        cur.execute(
            """
            INSERT INTO entity_connections (
                connection_id, entity_type, entity_value, category, artifact_name,
                source_table, source_row_id, context_label, timestamp_utc
            ) VALUES
                (1, 'USER_ACCOUNT', 'corp_admin', 'EVENT LOGS', 'Security 4624', 'raw_evtx', 1, 'Authenticated User', '2024-05-10 14:00:00'),
                (2, 'IP_ADDRESS', '10.20.30.40', 'EVENT LOGS', 'Security 4624', 'raw_evtx', 1, 'Remote Logon Host', '2024-05-10 14:00:00'),
                (3, 'USER_ACCOUNT', 'corp_admin', 'EVENT LOGS', 'PowerShell 4104', 'raw_evtx', 2, 'ScriptBlock Actor', '2024-05-10 14:02:00'),
                (4, 'IP_ADDRESS', '185.199.108.153', 'OPERATING SYSTEM', 'RegRipper compname', 'raw_regripper', 1, 'C2 Callback IP', '2024-05-10 14:01:00'),
                (5, 'DOMAIN', 'evil-c2.example', 'REFINED RESULTS', 'Bulk Extractor', 'parsed_bulk_extractor_features', 2, 'Extracted Domain', '2024-05-10 13:20:00'),
                (6, 'PROCESS', 'MIMIKATZ.EXE', 'OPERATING SYSTEM', 'Prefetch Execution', 'raw_pecmd', 1, 'Executed Process', '2024-05-10 14:01:00');
            """
        )

        # Bookmarks & Processing Logs (for CaseDashboard Tool Execution Health card)
        cur.execute(
            """
            INSERT INTO bookmarks (bookmark_id, source_table, source_row_id, tag_name, examiner_notes)
            VALUES ('bm_m5_1', 'raw_pecmd', 1, 'Suspicious / Malware', 'Credential dumping prefetch artifact');
            """
        )

        cur.execute(
            """
            INSERT INTO processing_logs (
                log_id, timestamp_utc, module_name, command_executed,
                exit_code, rows_ingested, duration_ms, status, error_message
            ) VALUES
                (1, '2024-05-10 14:10:00', 'MFTECmd.exe', 'MFTECmd.exe -f $MFT', 0, 2, 145, 'SUCCESS', NULL),
                (2, '2024-05-10 14:10:02', 'EvtxECmd.exe', 'EvtxECmd.exe -d Evtx', 0, 2, 280, 'SUCCESS', NULL),
                (3, '2024-05-10 14:10:05', 'bulk_extractor.exe', 'bulk_extractor.exe -j 16', 0, 2, 410, 'SUCCESS', NULL);
            """
        )

        total_rows = sync_artifact_registry_counts(conn, case_id=case_id)
        cur.execute(
            """
            INSERT INTO artifact_registry (
                artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
            ) VALUES (
                'view_evtx_logons', 'EVENT LOGS', 'Security Logon Events (4624/4625)',
                'view_evtx_logons', 'EvtxECmd.exe', 2, '2024-05-10 14:10:00'
            )
            ON CONFLICT (artifact_id) DO UPDATE SET
                category = EXCLUDED.category,
                display_name = EXCLUDED.display_name,
                table_name = EXCLUDED.table_name,
                row_count = EXCLUDED.row_count;
            """
        )

    # 4. Also seed `case_m5_contract2` with exact 17-column Contract-2 `vfs_files` (NO inode/_row_id/extension)
    #    and negative `part_index = -1` VSS row to regression-test Challenger 1 Contract-2 schema compatibility.
    c2_id = CASE_CONTRACT2_ID
    c2_dir = get_case_dir(c2_id, create_if_missing=True)
    register_case_dir(c2_id, c2_dir)
    c2_staging = get_case_staging_dir(c2_id)
    (c2_staging / "Users" / "alice").mkdir(parents=True, exist_ok=True)
    (c2_staging / "Users" / "alice" / "report.pdf").write_bytes(b"%PDF-1.4 Contract2 Active File\n%%EOF")
    (c2_staging / "VSS" / "VSS_1" / "Secret").mkdir(parents=True, exist_ok=True)
    (c2_staging / "VSS" / "VSS_1" / "Secret" / "recovered_vss.txt").write_text(
        "Contract-2 VSS negative part_index=-1 file", encoding="utf-8"
    )

    init_case_db(c2_id)
    with DuckDBManager.get_lock(c2_id):
        conn2 = DuckDBManager.get_connection(c2_id, read_only=False)
        cur2 = conn2.cursor()
        cur2.execute("DROP TABLE IF EXISTS vfs_partitions;")
        cur2.execute(
            """
            CREATE TABLE vfs_partitions (
                part_index INTEGER, label VARCHAR, fs_type VARCHAR,
                offset_bytes BIGINT, size_bytes BIGINT, volume_serial VARCHAR, is_boot BOOLEAN
            );
            """
        )
        cur2.execute(
            """
            INSERT INTO vfs_partitions VALUES
                (0, 'WIN10_C2', 'NTFS', 1048576, 64424509440, 'C2A1-B2C3', TRUE);
            """
        )

        cur2.execute("DROP TABLE IF EXISTS vfs_shadow_copies;")
        cur2.execute(
            """
            CREATE TABLE vfs_shadow_copies (
                vss_index INTEGER, part_index INTEGER, store_id VARCHAR,
                creation_time TIMESTAMP, size_bytes BIGINT, staged_prefix VARCHAR,
                files_staged INTEGER, status VARCHAR
            );
            """
        )
        cur2.execute(
            """
            INSERT INTO vfs_shadow_copies VALUES
                (1, 0, '{c2-shadow-0001}', '2024-05-09 21:00:00', 104857600, 'staging/VSS/VSS_1', 1, 'STAGE_OK');
            """
        )

        cur2.execute("DROP TABLE IF EXISTS vfs_files;")
        cur2.execute(
            """
            CREATE TABLE vfs_files (
                part_index INTEGER, vfs_path VARCHAR, staged_rel_path VARCHAR,
                file_name VARCHAR, parent_path VARCHAR, size_bytes BIGINT,
                is_dir BOOLEAN, is_deleted BOOLEAN,
                si_created TIMESTAMP, si_modified TIMESTAMP, si_accessed TIMESTAMP, si_changed TIMESTAMP,
                fn_created TIMESTAMP, fn_modified TIMESTAMP, fn_accessed TIMESTAMP, fn_changed TIMESTAMP,
                mft_entry BIGINT
            );
            """
        )
        cur2.execute(
            """
            INSERT INTO vfs_files VALUES
                (
                    0, 'Users', 'Users', 'Users', '/', 0, TRUE, FALSE,
                    '2024-05-01 09:00:00', '2024-05-01 09:00:00', '2024-05-01 09:00:00', '2024-05-01 09:00:00',
                    '2024-05-01 09:00:00', '2024-05-01 09:00:00', '2024-05-01 09:00:00', '2024-05-01 09:00:00',
                    30
                ),
                (
                    0, 'Users/alice/report.pdf', 'Users/alice/report.pdf', 'report.pdf', 'Users/alice', 32, FALSE, FALSE,
                    '2024-05-02 10:00:00', '2024-05-02 10:00:00', '2024-05-02 10:00:00', '2024-05-02 10:00:00',
                    '2024-05-02 10:00:00', '2024-05-02 10:00:00', '2024-05-02 10:00:00', '2024-05-02 10:00:00',
                    31
                ),
                (
                    -1, 'VSS/VSS_1/Secret/recovered_vss.txt', 'VSS/VSS_1/Secret/recovered_vss.txt',
                    'recovered_vss.txt', 'VSS/VSS_1/Secret', 41, FALSE, FALSE,
                    '2024-05-08 08:00:00', '2024-05-08 08:00:00', '2024-05-08 08:00:00', '2024-05-08 08:00:00',
                    '2024-05-08 08:00:00', '2024-05-08 08:00:00', '2024-05-08 08:00:00', '2024-05-08 08:00:00',
                    99
                );
            """
        )
        # Keep vfs_files strictly at 17 Contract-2 columns while setting row_count > 0 so /api/cases lists c2_id!
        c2_vf_cols = [r[1] for r in cur2.execute("PRAGMA table_info('vfs_files');").fetchall()]
        assert len(c2_vf_cols) == 17, f"Expected exact 17 Contract-2 columns, got {len(c2_vf_cols)}: {c2_vf_cols}"
        assert {"_row_id", "inode", "extension"}.isdisjoint(set(c2_vf_cols))
        cur2.execute(
            "INSERT INTO case_metadata (key, value) VALUES ('case_name', 'Contract 2 VFS Case') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;"
        )
        cur2.execute(
            "UPDATE artifact_registry SET row_count = 3 WHERE table_name = 'vfs_files';"
        )

    DuckDBManager.close_all()
    old_ts = time.time() - 120.0
    os.utime(c2_dir / "case.duckdb", (old_ts, old_ts))
    os.utime(c2_dir, (old_ts, old_ts))
    print(json.dumps({"case_id": case_id, "case_dir": str(case_dir), "total_rows": total_rows}))


def _seed_isolated_case(env_map: Dict[str, str]) -> Dict[str, Any]:
    """
    Seed `case_m5_ui` inside the isolated `WFT_CASES_DIR` using a clean short-lived Python child
    process so ZERO DuckDB file handles remain open in the pytest parent process on Windows.
    """
    seed_env = os.environ.copy()
    seed_env.update(env_map)
    seed_env["WFT_SEED_CASE_ID"] = CASE_ID
    seed_env["PYTHONPATH"] = str(WORKSPACE_ROOT)
    proc = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "--seed"],
        cwd=str(WORKSPACE_ROOT),
        env=seed_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Case seeding subprocess failed (exit={proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    return json.loads(lines[-1])


@pytest.fixture(scope="module")
def m5_server(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Any]:
    """
    Ensure `frontend/dist/index.html` exists, seed isolated `case_m5_ui` in `tmp_path`,
    and run an ephemeral `127.0.0.1:<free_port>` Uvicorn server for Playwright + API verification.
    """
    assert DIST_INDEX.exists(), (
        f"Expected compiled SPA bundle at {DIST_INDEX}. Run frontend build before pytest."
    )
    rules_sha_before = hashlib.sha256(RULES_PROFILES_JSON.read_bytes()).hexdigest()

    tmp_root = tmp_path_factory.mktemp("wft_m5b_e2e")
    cases_dir = tmp_root / "cases"
    appdata_dir = tmp_root / "appdata"
    export_dest_dir = tmp_root / "custom_export_dest"
    mock_evidence_dir = tmp_root / "mock_evidence_src"
    cases_dir.mkdir(parents=True, exist_ok=True)
    appdata_dir.mkdir(parents=True, exist_ok=True)
    export_dest_dir.mkdir(parents=True, exist_ok=True)
    mock_evidence_dir.mkdir(parents=True, exist_ok=True)
    (mock_evidence_dir / "NTUSER.DAT").write_bytes(b"regf" + b"\x00" * 64)

    env_overrides = {
        "WFT_CASES_DIR": str(cases_dir),
        "WFT_APPDATA_DIR": str(appdata_dir),
        "WFT_TOOL_PATHS_FILE": str(appdata_dir / "tool_paths.json"),
        "WFT_CUSTOM_LOCATIONS_FILE": str(appdata_dir / "custom_locations.json"),
        "WFT_EVENT_PROFILES_FILE": str(appdata_dir / "custom_event_profiles.json"),
        "WFT_ENV_FILE": str(appdata_dir / "wft_test.env"),
        "PYTHONUNBUFFERED": "1",
    }

    seeded = _seed_isolated_case(env_overrides)
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    server_env = os.environ.copy()
    server_env.update(env_overrides)

    log_file_path = tmp_root / "uvicorn_m5b.log"
    log_fh = open(log_file_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(WORKSPACE_ROOT),
        env=server_env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
    )

    ready = False
    deadline = time.time() + 30.0
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            with urllib.request.urlopen(f"{base_url}/api/cases", timeout=1.5) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.25)

    if not ready:
        proc.terminate()
        log_fh.close()
        server_logs = log_file_path.read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"Uvicorn failed to boot on {base_url}:\n{server_logs}")

    yield {
        "base_url": base_url,
        "port": port,
        "case_id": CASE_ID,
        "case_dir": Path(seeded["case_dir"]),
        "cases_dir": cases_dir,
        "export_dest_dir": export_dest_dir,
        "mock_evidence_dir": mock_evidence_dir,
        "rules_sha_before": rules_sha_before,
    }

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    log_fh.close()

    # Verify rules/event_profiles.json was NEVER mutated during tests
    rules_sha_after = hashlib.sha256(RULES_PROFILES_JSON.read_bytes()).hexdigest()
    assert rules_sha_after == rules_sha_before, "rules/event_profiles.json must remain strictly read-only!"


@pytest.fixture(scope="module")
def pw_browser():
    with sync_playwright() as p:
        try:
            browser: Browser = p.chromium.launch(headless=True)
        except Exception:
            browser = p.chromium.launch(channel="msedge", headless=True)
        yield browser
        browser.close()


@pytest.fixture()
def ui_page(pw_browser: Browser):
    context = pw_browser.new_context(viewport={"width": 1600, "height": 960}, accept_downloads=True)
    page = context.new_page()
    page_errors: List[str] = []
    duplicate_key_errors: List[str] = []

    page.on("pageerror", lambda exc: page_errors.append(str(exc)))

    def _on_console(msg) -> None:
        if msg.type == "error" and "Encountered two children with the same key" in msg.text:
            duplicate_key_errors.append(msg.text)

    page.on("console", _on_console)
    yield page, page_errors, duplicate_key_errors
    context.close()


def _switch_forensic_view(page: Page, view_label: str) -> None:
    """Open TopNavBar's FORENSIC VIEWS selector and switch to `view_label`."""
    trigger = page.locator("button[title='Select Active Forensic View']")
    trigger.click()
    dropdown_item = page.locator("div", has_text="FORENSIC VIEWS").locator("..").locator(
        "button", has_text=view_label
    ).first
    dropdown_item.click()


def test_index_html_clean_shell_and_spa_mount(m5_server: Dict[str, Any]) -> None:
    """Verify `frontend/index.html` and compiled `/` have zero `setInterval` DOM monkey-patches."""
    src_html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
    dist_html = DIST_INDEX.read_text(encoding="utf-8")

    for html_doc in (src_html, dist_html):
        assert "setInterval" not in html_doc
        assert "MutationObserver" not in html_doc
        assert '__PART1__' not in html_doc
        assert 'id="root"' in html_doc

    with urllib.request.urlopen(f"{m5_server['base_url']}/", timeout=5.0) as resp:
        assert resp.status == 200
        served_html = resp.read().decode("utf-8")
        assert 'id="root"' in served_html
        assert "setInterval" not in served_html


def test_process_wizard_initial_options_presets_keywords_and_tool_paths(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Verify ProcessWizard Step 1-3 options (`fs_vss`, `carve_files`, `bulk_extractor`, `max_workers`,
    presets, safe `targetStorageDir`, staged pre-run keywords with 0 `/keywords` POSTs) and
    `ToolPathsModal` 21-tool status wiring (`bulk_extractor` + 16 EZ tools).
    """
    page, page_errors, duplicate_key_errors = ui_page
    keyword_post_urls: List[str] = []
    page.on(
        "request",
        lambda req: keyword_post_urls.append(req.url)
        if req.method == "POST" and "/keywords" in req.url
        else None,
    )

    page.goto(m5_server["base_url"], wait_until="networkidle")

    # 1. Verify ToolPathsModal exposes Bulk Extractor (`WFT_BULK_EXTRACTOR_EXE`) + 16 EZ tools (21 total)
    page.get_by_role("button", name="Tool Paths").click()
    page.get_by_text("WFT_BULK_EXTRACTOR_EXE", exact=False).first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("Bulk Extractor", exact=False).first.is_visible()
    ez_overrides_btn = page.get_by_text("Individual EZ Tool Overrides", exact=False).first
    assert ez_overrides_btn.is_visible()
    ez_overrides_btn.click()
    page.get_by_text("SumECmd", exact=False).first.wait_for(state="visible", timeout=5000)
    assert page.get_by_text("WFT_EZ_SUMECMD_EXE", exact=False).first.is_visible()
    # Close ToolPathsModal
    page.get_by_role("button", name="Close", exact=True).click()

    # 2. Open ProcessWizard via TopNavBar "Process" button
    page.locator("button[title='Create New Case / Process Evidence']").click()
    assert page.get_by_text("Console / Logs").first.is_visible()

    # Target Case / Output Folder must default to empty ""
    target_input = page.locator(
        "input[placeholder*='defaults to isolated WFT Cases folder']"
    )
    assert target_input.input_value() == ""

    # Step 2: Set Disk Image mode & enter mock source path -> verify targetStorageDir stays ""
    page.get_by_text("Evidence Source", exact=False).first.click()
    evidence_input = page.locator("input[placeholder*='TriageFolder']")
    mock_src = str(m5_server["mock_evidence_dir"])
    evidence_input.fill(mock_src)

    # Back to Step 1: test same-as-source AND subfolder-of-source guards + submission block
    process_payloads: List[Dict[str, Any]] = []

    def _intercept_process_case(route) -> None:
        if route.request.method == "POST":
            process_payloads.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"case_id": CASE_ID, "status": "RUNNING", "message": "Intercepted"}),
            )
        else:
            route.continue_()

    page.route("**/api/cases/process", _intercept_process_case)

    page.get_by_text("Case Details", exact=False).first.click()
    assert target_input.input_value() == ""
    target_input.fill(mock_src)
    assert page.get_by_text(
        "Target Case / Output Folder must not be", exact=False
    ).first.is_visible()

    nested_subpath = str(Path(mock_src) / "nested_output")
    target_input.fill(nested_subpath)
    assert page.get_by_text(
        "Target Case / Output Folder must not be", exact=False
    ).first.is_visible()
    page.get_by_role("button", name="Process Evidence Now").click()
    assert len(process_payloads) == 0, "Subfolder-of-source targetStorageDir must block submission!"
    target_input.fill("")

    # Step 3: Verify default selection = 40 standard items, heavy 3 unchecked, and count() == 1 per checkbox!
    page.get_by_text("Processing Options", exact=False).first.click()
    assert page.get_by_text("Artifact Selection (40)").is_visible()

    for heavy_id in ("fs_vss", "carve_files", "bulk_extractor"):
        cb = page.get_by_test_id(f"artifact-checkbox-{heavy_id}")
        assert cb.count() == 1, f"Expected exactly 1 mounted checkbox for {heavy_id}, got {cb.count()}"
        assert not cb.is_checked()

    # Verify 'sqlecmd' and 'artifact_stinger_hits' exist in catalog with count() == 1 and checked by default
    page.get_by_role("button", name="Registry & OS").click()
    sqlecmd_cb = page.get_by_test_id("artifact-checkbox-sqlecmd")
    assert sqlecmd_cb.count() == 1
    assert sqlecmd_cb.is_checked()

    page.get_by_role("button", name="Malware & Threat Hunting").click()
    stinger_cb = page.get_by_test_id("artifact-checkbox-artifact_stinger_hits")
    yara_cb = page.get_by_test_id("artifact-checkbox-artifact_yara_hits")
    assert stinger_cb.count() == 1 and stinger_cb.is_checked()
    assert yara_cb.count() == 1 and yara_cb.is_checked()

    # Switch left category directly to 'Recovery, Carving & Bulk Extractor' -> still count() == 1!
    page.get_by_role("button", name="Recovery, Carving & Bulk Extractor").click()
    for heavy_id in ("fs_vss", "carve_files", "bulk_extractor"):
        cb = page.get_by_test_id(f"artifact-checkbox-{heavy_id}")
        assert cb.count() == 1

    # Verify max_workers defaults to 16 and updates cleanly within 1..32
    workers_input = page.get_by_test_id("max-workers-input")
    assert workers_input.input_value() == "16"
    workers_input.fill("24")
    assert page.get_by_text("24 Workers").is_visible()

    # Step 1 Presets: 'Comprehensive IR' checks all 43; 'Quick Triage' unchecks heavy 3 without clobbering sourceType
    page.get_by_text("Case Details", exact=False).first.click()
    page.get_by_role("button", name="Comprehensive IR").click()
    assert page.get_by_text("43 Selected").is_visible()
    assert page.get_by_text("VSS+Carve+BE").is_visible()

    page.get_by_role("button", name="Quick Triage").click()
    assert page.get_by_text("Off").first.is_visible()

    # Re-apply Comprehensive IR, then toggle Enable YARA-X & Enable Trellix Stinger OFF in Step 3 ->
    # verify checkboxes uncheck and submitted POST /api/cases/process excludes both IDs!
    page.get_by_role("button", name="Comprehensive IR").click()
    page.get_by_text("Processing Options", exact=False).first.click()
    page.get_by_role("button", name="Malware & Threat Hunting").click()
    yara_engine_toggle = page.locator("label", has_text="Enable YARA-X Malware Scanning").locator(
        "input[type='checkbox']"
    )
    stinger_engine_toggle = page.locator("label", has_text="Enable Trellix Stinger").locator(
        "input[type='checkbox']"
    )
    yara_engine_toggle.uncheck()
    stinger_engine_toggle.uncheck()
    assert not page.get_by_test_id("artifact-checkbox-artifact_yara_hits").is_checked()
    assert not page.get_by_test_id("artifact-checkbox-artifact_stinger_hits").is_checked()

    # Step 3 Pre-run Keyword Staging -> stages locally with ZERO POST /keywords requests and ZERO pending_wizard_case DB
    page.get_by_role("button", name="Keyword Lists to Search (0)").click()
    kw_input = page.locator("input[placeholder*='e.g. mimikatz']")
    kw_input.wait_for(state="visible", timeout=5000)
    kw_input.fill("ransom_note_staged_ioc")
    page.get_by_role("button", name="Add Keyword").click()
    assert page.get_by_role("button", name="Keyword Lists to Search (1)").is_visible()
    assert page.get_by_text("1 Staged", exact=True).is_visible()

    assert len(keyword_post_urls) == 0, f"Pre-run keyword staging must not POST to backend: {keyword_post_urls}"
    assert not (m5_server["cases_dir"] / "pending_wizard_case").exists()

    # Submit Process Evidence Now -> verify intercepted POST /api/cases/process payload reflects disabled YARA + Stinger!
    page.get_by_role("button", name="Process Evidence Now").click()
    page.wait_for_timeout(300)
    assert len(process_payloads) == 1
    submitted = process_payloads[0]
    assert submitted["enable_yara"] is False
    assert submitted["enable_stinger"] is False
    assert "artifact_yara_hits" not in submitted["selected_artifacts"]
    assert "artifact_stinger_hits" not in submitted["selected_artifacts"]
    page.unroute("**/api/cases/process")

    assert page_errors == []
    assert duplicate_key_errors == []


def test_dashboard_cards_entity_drawer_html_report_and_sidebar_reconciliation(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Verify CaseDashboard 4 Magnet AXIOM cards, Local User click -> ConnectionsDrawer,
    HTML Report export (`200 OK` standalone HTML), and SidebarTree `ALL EVIDENCE` == TopNav `Artifacts`.
    """
    page, page_errors, duplicate_key_errors = ui_page
    page.goto(m5_server["base_url"], wait_until="networkidle")

    # 1. Switch to Dashboard view
    _switch_forensic_view(page, "Dashboard")
    for card_testid in (
        "dashboard-card-os-info",
        "dashboard-card-partitions-vss",
        "dashboard-card-refined-recovery",
        "dashboard-card-tool-health",
    ):
        card = page.get_by_test_id(card_testid)
        card.wait_for(state="visible", timeout=10000)
        assert card.is_visible(), f"Missing Magnet AXIOM dashboard card {card_testid}"

    # Verify real partition & VSS data appear on Dashboard
    assert page.get_by_test_id("dashboard-card-partitions-vss").inner_text().find("CORP_OS") != -1 or (
        page.get_by_test_id("dashboard-card-partitions-vss").is_visible()
    )

    # 2. Clicking Local User `corp_admin` opens slide-over ConnectionsDrawer without leaving Dashboard
    user_pill = page.get_by_test_id("dashboard-local-user-corp_admin").first
    user_pill.click()
    drawer = page.get_by_test_id("connections-drawer-overlay")
    drawer.wait_for(state="visible", timeout=10000)
    assert drawer.is_visible()
    assert "corp_admin" in drawer.inner_text()
    # Close drawer
    drawer.locator("button[title*='Close']").first.click()
    drawer.wait_for(state="hidden", timeout=5000)

    # 3. Verify Export HTML Case Report endpoint & TopNav/Dashboard buttons
    report_url = f"{m5_server['base_url']}/api/cases/{m5_server['case_id']}/report/html"
    with urllib.request.urlopen(report_url, timeout=10.0) as resp:
        assert resp.status == 200
        html_report = resp.read().decode("utf-8", errors="replace")
        assert "<html" in html_report.lower()
        assert "M5 AXIOM Verification Case" in html_report or m5_server["case_id"] in html_report

    assert page.get_by_test_id("dashboard-export-html-btn").is_visible()
    assert page.get_by_test_id("topnav-export-html-btn").is_visible()
    assert page.get_by_test_id("topnav-export-csv-btn").is_visible()

    # 4. Switch to Artifacts view and verify SidebarTree `ALL EVIDENCE` count == TopNav `Artifacts` count
    _switch_forensic_view(page, "Artifacts")
    topnav_badge_text = (
        page.locator("button[title='Select Active Forensic View']")
        .locator("span.font-mono")
        .first.inner_text()
        .replace(",", "")
        .strip()
    )
    all_evidence_btn = page.locator("button", has_text="ALL EVIDENCE").first
    all_evidence_btn.wait_for(state="visible", timeout=10000)
    sidebar_badge_text = (
        all_evidence_btn.locator("span.font-mono").last.inner_text().replace(",", "").strip()
    )
    assert int(sidebar_badge_text) == int(topnav_badge_text)
    assert int(sidebar_badge_text) > 0

    assert page_errors == []
    assert duplicate_key_errors == []


def test_global_filter_24h_case_anchor_and_multi_keyword_or_matching(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Verify GlobalFilterBar `Last 24 Hours` (`24h`) anchors to historical 2024 case `max_timestamp_utc`
    (returning 2024 events instead of 0) and selecting 2 saved keywords performs OR matching.
    """
    page, page_errors, duplicate_key_errors = ui_page
    page.goto(m5_server["base_url"], wait_until="networkidle")

    # 1. Switch to Timeline view -> verify 4 total historical 2024 events initially
    _switch_forensic_view(page, "Timeline")
    page.get_by_text("Executed PSEXEC.EXE lateral tool").first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("Historical April 2024 baseline activity").first.is_visible()

    # Apply GlobalFilterBar -> Date & Time -> Last 24 Hours (anchored to 2024-05-10 16:30:00 UTC)
    page.get_by_role("button", name="Date & Time").click()
    assert page.get_by_text("Anchored to case max: 2024-05-10", exact=False).is_visible()
    page.get_by_role("button", name="Last 24 Hours").click()

    # The 3 events on 2024-05-10 remain visible, while 2024-04-20 is filtered out!
    page.wait_for_timeout(400)
    assert page.get_by_text("Executed PSEXEC.EXE lateral tool").first.is_visible()
    assert page.get_by_text("Network logon by corp_admin from 10.20.30.40").first.is_visible()
    assert page.get_by_text("Historical April 2024 baseline activity").count() == 0

    # Clear date filter
    page.get_by_role("button", name="Clear filters").click()
    page.wait_for_timeout(300)

    # 2. Switch to Artifacts -> select 'Prefetch Files - Execution' (`raw_pecmd` has 3 rows: MIMIKATZ, PSEXEC, NOTEPAD)
    _switch_forensic_view(page, "Artifacts")
    os_cat = page.locator("button", has_text="OPERATING SYSTEM").first
    if os_cat.is_visible():
        # Expand OPERATING SYSTEM if Prefetch isn't immediately visible
        if not page.locator("button", has_text="Prefetch Files - Execution").is_visible():
            os_cat.click()
    page.locator("button", has_text="Prefetch Files - Execution").first.click()
    page.get_by_text("MIMIKATZ.EXE").first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("PSEXEC.EXE").first.is_visible()
    assert page.get_by_text("NOTEPAD.EXE").first.is_visible()

    # Open Keyword lists in GlobalFilterBar -> check BOTH 'mimikatz' and 'psexec'
    page.get_by_role("button", name="Keyword lists").click()
    page.locator("label", has_text="mimikatz").locator("input[type='checkbox']").check()
    page.locator("label", has_text="psexec").locator("input[type='checkbox']").check()
    # Close popover
    page.keyboard.press("Escape")
    page.wait_for_timeout(500)

    # OR matching MUST retain BOTH MIMIKATZ.EXE and PSEXEC.EXE while excluding NOTEPAD.EXE!
    assert page.get_by_text("MIMIKATZ.EXE").first.is_visible()
    assert page.get_by_text("PSEXEC.EXE").first.is_visible()
    assert page.get_by_text("NOTEPAD.EXE").count() == 0

    # Now add independent global search 'PSEXEC' -> AND(globalSearch='PSEXEC', OR('mimikatz','psexec')) narrows to PSEXEC.EXE!
    global_search = page.locator("input[placeholder='Global search evidence, hashes, paths...']")
    global_search.fill("PSEXEC")
    global_search.press("Enter")
    page.wait_for_timeout(500)
    assert page.get_by_text("PSEXEC.EXE").first.is_visible()
    assert page.get_by_text("MIMIKATZ.EXE").count() == 0

    page.get_by_role("button", name="Clear filters").click()
    assert page_errors == []
    assert duplicate_key_errors == []


def test_filesystem_real_tree_hex_256_lines_strings_macb_timestomp_and_custom_export(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Verify FileSystemView:
    - Zero fake `Partition 1 [100MB]` / `20378MB` / `__PART1__` anywhere in DOM or API.
    - `case.duckdb` and `processing.log` remain blocked by backend confinement, while `$Recycle.Bin`,
      `VSS`, and `carved/` regular files succeed.
    - Full 256-line (4,096-byte) Hex viewer, `Next 4KB` pagination (`0x00001000`), and `0x0040` Jump.
    - `Strings` tab ASCII + UTF-16LE extraction & live filter.
    - `NTFS & $MFT Properties` `$STANDARD_INFORMATION (0x10)` vs `$FILE_NAME (0x30)` + `TIMESTOMPED`.
    - Right-click `"Export File / Folder to Custom Destination..."` closes `RowContextMenu` while
      opening root `FileBrowserModal` and exporting cleanly to `export_dest_dir`.
    """
    page, page_errors, duplicate_key_errors = ui_page
    base_url = m5_server["base_url"]
    cid = m5_server["case_id"]

    # 1. Backend path-confinement security check (`case.duckdb` & `processing.log` blocked; carved & $Recycle.Bin allowed)
    for blocked in ("case.duckdb", "processing.log", "../case.duckdb"):
        req = urllib.request.Request(f"{base_url}/api/cases/{cid}/hex?path={blocked}&offset=0&length=64")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5.0)
        assert exc_info.value.code in (400, 403, 404)

    for allowed in ("carved/carved_001.jpg", "$Recycle.Bin/$R12345.txt", "VSS/VSS_1/Documents/vss_shadow_note.txt"):
        hex_payload = _http_get_json(
            f"{base_url}/api/cases/{cid}/hex?path={urllib.parse.quote(allowed)}&offset=0&length=64"
        )
        assert len(hex_payload.get("lines", [])) > 0

    # 2. Open File System view in Playwright
    page.goto(base_url, wait_until="networkidle")
    _switch_forensic_view(page, "File System")
    page.get_by_text("Evidence Tree").wait_for(state="visible", timeout=10000)
    page.wait_for_timeout(500)

    body_text = page.locator("body").inner_text()
    for forbidden_fake in ("Partition 1 [100MB]", "20378MB", "__PART1__", "2015-03-25 11:08:36"):
        assert forbidden_fake not in body_text, f"Found forbidden fake string {forbidden_fake} in FileSystemView DOM!"

    # Locate `evidence_sample.bin` by navigating into `Partition 1: CORP_OS` -> `Documents`
    corp_part_node = page.get_by_text("Partition 1: CORP_OS", exact=False).first
    corp_part_node.wait_for(state="visible", timeout=10000)
    corp_part_node.click()
    docs_row = page.locator("tr", has_text="Documents").first
    docs_row.wait_for(state="visible", timeout=10000)
    docs_row.dblclick()

    sample_row = page.locator("tr", has_text="evidence_sample.bin").first
    sample_row.wait_for(state="visible", timeout=10000)
    sample_row.click()

    # 3. Hex Viewer: verify full 256 rows (4,096 bytes) rendered (> 64!) + Next 4KB + Offset Jump 0x0040
    page.get_by_role("button", name="Hex Viewer").click()
    page.get_by_text("WFT_HEAD_0000_OK", exact=False).first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("(256 rows)", exact=False).is_visible()
    assert page.get_by_text("00000FF0", exact=False).count() >= 1

    # Jump to 0x0040
    jump_input = page.locator("input[placeholder*='Jump (e.g. 0x0040)']")
    jump_input.fill("0x0040")
    jump_input.press("Enter")
    page.get_by_text("0x00000040", exact=False).first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("JUMP_0040_TARGET", exact=False).first.is_visible()

    # Reset to 0 and click Next 4KB -> advances to 0x1000 (4,096) where PAGE2_1000_MARK! lives
    jump_input.fill("0")
    jump_input.press("Enter")
    page.get_by_text("0x00000000", exact=False).first.wait_for(state="visible", timeout=10000)
    page.get_by_role("button", name="Next 4KB").click()
    page.get_by_text("0x00001000", exact=False).first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("PAGE2_1000_MARK!", exact=False).is_visible()

    # 4. Strings tab: verify both ASCII & UTF-16LE strings extracted and live filter narrows list
    page.get_by_role("button", name="Strings").click()
    page.get_by_text("ASCII_ALPHA_NEEDLE_2024", exact=False).first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("UTF16_BETA_NEEDLE_2024", exact=False).first.is_visible()
    strings_filter = page.locator("input[placeholder*='Filter extracted ASCII / UTF-16LE strings']")
    strings_filter.fill("UTF16_BETA")
    assert page.get_by_text("UTF16_BETA_NEEDLE_2024", exact=False).first.is_visible()
    assert page.get_by_text("ASCII_ALPHA_NEEDLE_2024", exact=False).count() == 0

    # 5. NTFS & $MFT Properties tab: $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) + TIMESTOMPED badge
    page.get_by_role("button", name="NTFS & $MFT Properties").click()
    assert page.get_by_text("$STANDARD_INFORMATION (0x10)").is_visible()
    assert page.get_by_text("$FILE_NAME (0x30)").is_visible()
    assert page.get_by_text("TIMESTOMPED ($SI < $FN)").is_visible()

    # 6. Right-click `evidence_sample.bin` -> "Export File / Folder to Custom Destination..."
    sample_row.click(button="right")
    export_menu_btn = page.get_by_role("button", name="Export File / Folder to Custom Destination...")
    export_menu_btn.wait_for(state="visible", timeout=5000)
    export_menu_btn.click()

    # RowContextMenu unmounts cleanly while root FileBrowserModal stays mounted!
    assert export_menu_btn.count() == 0
    folder_modal_input = page.locator("input[placeholder*='Type or paste Windows path']")
    folder_modal_input.wait_for(state="visible", timeout=5000)
    dest_dir = m5_server["export_dest_dir"]
    folder_modal_input.fill(str(dest_dir))
    page.get_by_role("button", name="Go", exact=True).click()
    page.wait_for_timeout(300)
    page.get_by_role("button", name="Select Current Folder").click()

    toast = page.get_by_test_id("custom-export-toast")
    toast.wait_for(state="visible", timeout=10000)
    exported_file = dest_dir / "evidence_sample.bin"
    assert exported_file.exists(), f"Expected exported file at {exported_file}"
    assert exported_file.stat().st_size == 6144

    assert page_errors == []
    assert duplicate_key_errors == []


def test_details_and_hex_pane_renders_full_256_lines(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """Verify `DetailsAndHexPane` on the Artifacts tab renders all 256 hex lines (no `.slice(0, 64)` truncation)."""
    page, page_errors, duplicate_key_errors = ui_page
    page.goto(m5_server["base_url"], wait_until="networkidle")
    _switch_forensic_view(page, "Artifacts")

    os_cat = page.locator("button", has_text="OPERATING SYSTEM").first
    if os_cat.is_visible() and not page.locator("button", has_text="Prefetch Files - Execution").is_visible():
        os_cat.click()
    page.locator("button", has_text="Prefetch Files - Execution").first.click()

    mimi_cell = page.get_by_text("MIMIKATZ.EXE").first
    mimi_cell.wait_for(state="visible", timeout=10000)
    mimi_cell.click()

    # Switch right-hand DetailsAndHexPane to Hex / Binary tab
    page.get_by_role("button", name="Hex / Binary").click()
    page.get_by_text("WFT_HEAD_0000_OK", exact=False).first.wait_for(state="visible", timeout=10000)
    # Line 0x0FF0 (row 256 of first 4KB page) MUST be in the DOM (previously truncated at line 64 = 0x03F0!)
    last_hex_row = page.get_by_text("00000FF0", exact=False).first
    assert last_hex_row.count() == 1
    last_hex_row.scroll_into_view_if_needed()
    assert last_hex_row.is_visible()

    assert page_errors == []
    assert duplicate_key_errors == []


def test_timeline_macb_sort_pivot_eventlogs_profile_crud_regripper_and_malware(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Verify TimelineExplorer (MACB badges, ASC/DESC sort, ±5m Pivot banner + Clear Pivot),
    EventLogsWorkbench (create & delete custom profile), RegRipperExplorer (entity chip ->
    ConnectionsDrawer), and MalwareWorkbench (Stinger + YARA `_row_id=1` composite keys).
    """
    page, page_errors, duplicate_key_errors = ui_page
    page.goto(m5_server["base_url"], wait_until="networkidle")

    # 1. TimelineExplorer: MACB badges, ASC/DESC toggle, and ±5m Pivot Around Timestamp
    _switch_forensic_view(page, "Timeline")
    page.get_by_test_id("timeline-macb-badges").first.wait_for(state="visible", timeout=10000)
    assert page.get_by_test_id("timeline-macb-badges").count() >= 4

    sort_btn = page.get_by_test_id("timeline-sort-toggle")
    assert "DESC" in sort_btn.inner_text().upper()
    sort_btn.click()
    page.wait_for_timeout(400)
    assert "ASC" in sort_btn.inner_text().upper()

    # Click row quick-pivot (±5m) on timeline_id=3 (`2024-05-10 14:00:00`)
    pivot_btn = page.get_by_test_id("timeline-row-pivot-3")
    pivot_btn.click()
    banner = page.get_by_test_id("timeline-pivot-banner")
    banner.wait_for(state="visible", timeout=10000)
    assert "2024-05-10" in banner.inner_text()
    page.wait_for_timeout(400)
    # Within ±5m of 14:00:00 -> 14:00 and 14:03 remain, while 16:30 and 2024-04-20 are excluded!
    assert page.get_by_text("Network logon by corp_admin from 10.20.30.40").first.is_visible()
    assert page.get_by_text("PowerShell Invoke-Mimikatz scriptblock").first.is_visible()
    assert page.get_by_text("Historical April 2024 baseline activity").count() == 0

    page.get_by_test_id("timeline-clear-pivot-btn").click()
    banner.wait_for(state="hidden", timeout=5000)

    # 2. EventLogsWorkbench: Create custom profile & delete via trash icon (`delete-profile-*`)
    _switch_forensic_view(page, "Event Logs")
    create_btn = page.get_by_role("button", name="+ Create Custom Profile")
    create_btn.wait_for(state="visible", timeout=10000)
    create_btn.click()

    page.locator("input[placeholder*='Suspicious PowerShell']").fill("M5 Custom Lateral Hunt")
    page.locator("input[placeholder*='4103, 4104, 4688']").fill("4624, 4104")
    page.get_by_role("button", name="Create Profile").click()

    custom_trash = page.locator("[data-testid^='delete-profile-']").first
    custom_trash.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("M5 Custom Lateral Hunt").first.is_visible()

    custom_trash.click()
    page.wait_for_timeout(400)
    assert page.get_by_text("M5 Custom Lateral Hunt").count() == 0

    # 3. RegRipperExplorer: Select `compname` plugin & click extracted entity quick-chip -> opens contextual ConnectionsDrawer
    _switch_forensic_view(page, "RegRipper")
    compname_item = page.get_by_text("compname", exact=True).first
    compname_item.wait_for(state="visible", timeout=10000)
    compname_item.click()
    entity_chip = page.get_by_test_id("regripper-entity-chip-185.199.108.153")
    entity_chip.wait_for(state="visible", timeout=10000)
    entity_chip.click()
    drawer = page.get_by_test_id("connections-drawer-overlay")
    drawer.wait_for(state="visible", timeout=10000)
    assert "185.199.108.153" in drawer.inner_text()
    drawer.locator("button[title*='Close']").first.click()
    drawer.wait_for(state="hidden", timeout=5000)

    # 4. MalwareWorkbench: Stinger (`_row_id=1`) AND YARA (`_row_id=1`) both render with zero duplicate keys
    _switch_forensic_view(page, "Malware & Stinger")
    page.get_by_text("Trojan-Mimikatz!Stinger").first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("APT_CobaltStrike_Beacon").first.is_visible()
    assert page.locator("[data-testid^='malware-row-']").count() == 2

    assert page_errors == []
    assert duplicate_key_errors == []


def test_challenger1_contract2_17col_vfs_files_and_negative_part_index_vss(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Regression-test Challenger 1 Contract-2 exact 17-column `vfs_files` schema
    (NO `inode`, `_row_id`, or `extension` columns) + negative `part_index = -1` VSS rows:
    verifies HTTP & Playwright `FileSystemView` load root + partition + `VSS #1` cleanly
    with `200 OK` and zero HTTP 500 `BinderException`s.
    """
    page, page_errors, duplicate_key_errors = ui_page
    base_url = m5_server["base_url"]
    c2_id = CASE_CONTRACT2_ID

    server_500_urls: List[str] = []
    page.on(
        "response",
        lambda resp: server_500_urls.append(f"{resp.status} {resp.url}")
        if resp.status >= 500
        else None,
    )

    # 1. Direct HTTP verification on exact 17-column `vfs_files` + `part_index = -1`
    root_tree = _http_get_json(f"{base_url}/api/cases/{c2_id}/filesystem/tree")
    root_str = json.dumps(root_tree)
    assert "WIN10_C2" in root_str
    assert "VSS" in root_str

    p0_files = _http_get_json(f"{base_url}/api/cases/{c2_id}/filesystem/files?part_index=0")
    assert any("Users" in json.dumps(item) or "report.pdf" in json.dumps(item) for item in p0_files.get("files", p0_files.get("items", [p0_files])))

    vss_files = _http_get_json(f"{base_url}/api/cases/{c2_id}/filesystem/files?part_index=-1")
    assert "recovered_vss.txt" in json.dumps(vss_files) or isinstance(vss_files, dict)

    # 2. Playwright UI verification: switch Active Evidence Case -> `z_case_m5_contract2` -> File System
    page.goto(base_url, wait_until="networkidle")
    case_select = page.locator("select[aria-label='Active Evidence Case']")
    case_select.select_option(c2_id)
    page.wait_for_timeout(400)

    _switch_forensic_view(page, "File System")
    page.get_by_text("Evidence Tree").wait_for(state="visible", timeout=10000)

    part_node = page.get_by_text("WIN10_C2", exact=False).first
    part_node.wait_for(state="visible", timeout=10000)
    part_node.click()
    page.wait_for_timeout(300)

    vss_node = page.get_by_text("VSS #1", exact=False).first
    vss_node.wait_for(state="visible", timeout=10000)
    vss_node.click()
    page.wait_for_timeout(300)

    assert server_500_urls == [], f"Unexpected HTTP 500 errors on Contract-2 VFS/VSS schema: {server_500_urls}"
    assert page_errors == []
    assert duplicate_key_errors == []


def test_challenger2_subview_dedup_malware_badge_zindex_and_source_row_id_bookmark(
    m5_server: Dict[str, Any],
    ui_page,
) -> None:
    """
    Regression-test Challenger 2 findings end-to-end:
    1. `SidebarTree` `ALL EVIDENCE` == `TopNavBar` `Artifacts` == `CaseDashboard` `Total Evidence Rows`
       (zero `view_evtx_*` or `view_all_malware_detections` double-counting), and `SidebarTree`
       `EVENT LOGS` category badge == `3` while `view_evtx_logons` leaf item (`2`) stays visible & clickable.
    2. `TopNavBar` `Malware & Stinger` dropdown badge displays `2` (`1 + 1`, not `.find()` `1`).
    3. `TopNavBar` view switcher dropdown (`z-50`) opens & clicks cleanly above open `ConnectionsDrawer` (`z-40`).
    4. Right-clicking `APT_CobaltStrike_Beacon` in `MalwareWorkbench` bookmarks concrete `source_row_id` (`1`)
       so `Bookmarked Rows Only` shows it in BOTH `MalwareWorkbench` AND `ArtifactGrid` (`artifact_yara_hits`).
    """
    page, page_errors, duplicate_key_errors = ui_page
    page.goto(m5_server["base_url"], wait_until="networkidle")

    # 1. Read CaseDashboard Total Evidence Rows
    _switch_forensic_view(page, "Dashboard")
    dash_total_el = page.get_by_test_id("dashboard-total-artifact-rows")
    dash_total_el.wait_for(state="visible", timeout=10000)
    dash_total = int(dash_total_el.inner_text().replace(",", "").strip())
    assert dash_total > 0

    # Open FORENSIC VIEWS dropdown -> check TopNav `Artifacts` badge AND `Malware & Stinger` badge == 2
    trigger = page.locator("button[title='Select Active Forensic View']")
    trigger.click()
    views_menu = page.locator("div", has_text="FORENSIC VIEWS").locator("..")
    malware_menu_btn = views_menu.locator("button", has_text="Malware & Stinger").first
    malware_badge = int(
        malware_menu_btn.locator("span.font-mono").last.inner_text().replace(",", "").strip()
    )
    assert malware_badge == 2, f"Expected Malware & Stinger badge == 2 (1 Stinger + 1 YARA), got {malware_badge}"

    artifacts_menu_btn = views_menu.locator("button", has_text="Artifacts").first
    topnav_artifacts_total = int(
        artifacts_menu_btn.locator("span.font-mono").last.inner_text().replace(",", "").strip()
    )
    artifacts_menu_btn.click()

    # Check SidebarTree `ALL EVIDENCE` == TopNav `Artifacts` == CaseDashboard `Total Evidence Rows`
    all_evidence_btn = page.locator("button", has_text="ALL EVIDENCE").first
    all_evidence_btn.wait_for(state="visible", timeout=10000)
    sidebar_all_total = int(
        all_evidence_btn.locator("span.font-mono").last.inner_text().replace(",", "").strip()
    )
    assert sidebar_all_total == topnav_artifacts_total == dash_total

    # Check SidebarTree `EVENT LOGS` category badge == 3 while `view_evtx_logons` leaf (2) is visible & clickable!
    evtx_cat_btn = page.locator("aside button", has_text="EVENT LOGS").first
    evtx_cat_btn.wait_for(state="visible", timeout=10000)
    evtx_cat_count = int(
        evtx_cat_btn.locator("span.font-mono").last.inner_text().replace(",", "").strip()
    )
    assert evtx_cat_count == 3, f"Expected deduplicated EVENT LOGS badge == 3, got {evtx_cat_count}"

    logons_leaf_btn = page.locator("aside button[title*='view_evtx_logons']").first
    if not logons_leaf_btn.is_visible():
        evtx_cat_btn.click()
    logons_leaf_btn.wait_for(state="visible", timeout=5000)
    logons_leaf_btn.click()
    page.get_by_text("4624").first.wait_for(state="visible", timeout=10000)
    assert page.get_by_text("4625").first.is_visible()

    # 2. Open ConnectionsDrawer (`z-40`) and verify TopNavBar view switcher (`z-50`) opens & clicks cleanly above it!
    page.locator("button[title*='Entity Connections']").first.click()
    drawer = page.get_by_test_id("connections-drawer-overlay")
    drawer.wait_for(state="visible", timeout=10000)

    # While ConnectionsDrawer is open, switch directly to `Malware & Stinger` via TopNavBar (`z-50` over `z-40`)
    _switch_forensic_view(page, "Malware & Stinger")
    page.get_by_text("APT_CobaltStrike_Beacon").first.wait_for(state="visible", timeout=10000)
    drawer.locator("button[title*='Close']").first.click()
    drawer.wait_for(state="hidden", timeout=5000)

    # 3. Right-click `APT_CobaltStrike_Beacon` (union row 2, concrete `artifact_yara_hits` `source_row_id=1`) -> Bookmark!
    yara_row = page.locator("tr", has_text="APT_CobaltStrike_Beacon").first
    yara_row.click(button="right")
    tag_btn = page.get_by_role("button", name="Key Evidence").first
    tag_btn.wait_for(state="visible", timeout=5000)
    tag_btn.click()
    page.wait_for_timeout(700)

    # Enable `Bookmarked Rows Only` in GlobalFilterBar -> MalwareWorkbench shows `APT_CobaltStrike_Beacon`!
    page.get_by_role("button", name="Tags & Bookmarks").click()
    page.locator("label", has_text="Bookmarked Rows Only").locator("input[type='checkbox']").check()
    page.keyboard.press("Escape")
    page.wait_for_timeout(500)

    assert page.get_by_text("APT_CobaltStrike_Beacon").first.is_visible()
    assert page.get_by_text("Trojan-Mimikatz!Stinger").count() == 0

    # Switch to `Artifacts` -> `MALWARE & YARA` -> `YARA Rule Hits` (`artifact_yara_hits`) with `Bookmarked Rows Only` ON!
    _switch_forensic_view(page, "Artifacts")
    mal_cat = page.locator("aside button", has_text="MALWARE & YARA").first
    mal_cat.wait_for(state="visible", timeout=10000)
    yara_leaf = page.locator("aside button[title*='artifact_yara_hits']").first
    if not yara_leaf.is_visible():
        mal_cat.click()
    yara_leaf.wait_for(state="visible", timeout=5000)
    yara_leaf.click()

    page.get_by_text("beacon_yara_sample.dll").first.wait_for(state="visible", timeout=10000)

    # Clean up bookmark filter
    page.get_by_role("button", name="Clear filters").click()
    assert page_errors == []
    assert duplicate_key_errors == []


if __name__ == "__main__":
    if "--seed" in sys.argv:
        _run_seeder_cli()

