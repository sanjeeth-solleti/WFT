"""
Unified M3-C 7-Parser Concurrency, Deterministic Worker Equivalence & Hygiene Suite (F28.M3).
Exercises ChromiumParser, FirefoxParser, EmailParser, ChatParser, CloudParser,
DocumentParser, MediaParser, and BaseParser concurrently against shared case.duckdb instances.
"""
from __future__ import annotations
import ast, concurrent.futures, io, os, sqlite3, struct, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Tuple
import pytest
import backend.config as cfg
from backend.db.engine import DuckDBManager, init_case_db
from backend.parsers.base_parser import WEBKIT_EPOCH_OFFSET_SECONDS, BaseParser
from backend.parsers.chat_parser import ChatParser
from backend.parsers.chromium_parser import ChromiumParser
from backend.parsers.cloud_parser import GDRIVE_FILES_DDL, CloudParser
from backend.parsers.document_parser import DocumentParser
from backend.parsers.email_parser import EmailParser
from backend.parsers.firefox_parser import FirefoxParser
from backend.parsers.media_parser import MediaParser
import backend.parsers.media_parser as media_mod

HIST_EPOCH = 1700040000  # 2023-11-15 09:20:00 UTC
VFS_FILES_DDL = (
    "CREATE TABLE IF NOT EXISTS vfs_files (part_index INTEGER, vfs_path VARCHAR, staged_rel_path VARCHAR, "
    "file_name VARCHAR, parent_path VARCHAR, size_bytes BIGINT, is_dir BOOLEAN, is_deleted BOOLEAN, "
    "si_created TIMESTAMP, si_modified TIMESTAMP, si_accessed TIMESTAMP, si_changed TIMESTAMP, "
    "fn_created TIMESTAMP, fn_modified TIMESTAMP, fn_accessed TIMESTAMP, fn_changed TIMESTAMP, "
    "si_created_utc TIMESTAMP, si_modified_utc TIMESTAMP, mft_entry BIGINT);"
)


def _build_exif_jpeg(dt_orig: str, offset_orig: str, width: int = 12, height: int = 10) -> bytes:
    """Build a valid JPEG with little-endian TIFF EXIF IFD0 + ExifIFD (0x9003 + 0x9011)."""
    def _asc(val: str) -> bytes:
        return val.encode("ascii") + b"\x00"

    make_b, model_b, dt0_b = _asc("Canon"), _asc("EOS R5"), _asc(dt_orig)
    dto_b, off_b = _asc(dt_orig), _asc(offset_orig)
    ifd0_cnt = 4
    ifd0_data_off = 8 + 2 + ifd0_cnt * 12 + 4

    def _pack_ifd(items: List[Tuple[int, int, int, bytes]], data_off: int) -> Tuple[bytes, bytes]:
        tbl = bytearray(struct.pack("<H", len(items)))
        ext = bytearray()
        for tag, ftype, cnt, raw in sorted(items, key=lambda x: x[0]):
            if len(raw) <= 4:
                tbl.extend(struct.pack("<HHI", tag, ftype, cnt) + raw.ljust(4, b"\x00"))
            else:
                off = data_off + len(ext)
                ext.extend(raw + (b"\x00" if len(raw) % 2 else b""))
                tbl.extend(struct.pack("<HHII", tag, ftype, cnt, off))
        tbl.extend(struct.pack("<I", 0))
        return bytes(tbl), bytes(ext)

    _, tmp_ext = _pack_ifd([(0x010F, 2, len(make_b), make_b), (0x0110, 2, len(model_b), model_b), (0x0132, 2, len(dt0_b), dt0_b), (0x8769, 4, 1, b"\x00" * 4)], ifd0_data_off)
    exif_off = ifd0_data_off + len(tmp_ext)
    exif_tbl, exif_ext = _pack_ifd([(0x9003, 2, len(dto_b), dto_b), (0x9011, 2, len(off_b), off_b)], exif_off + 2 + 2 * 12 + 4)
    ifd0_tbl, ifd0_ext = _pack_ifd(
        [(0x010F, 2, len(make_b), make_b), (0x0110, 2, len(model_b), model_b), (0x0132, 2, len(dt0_b), dt0_b), (0x8769, 4, 1, struct.pack("<I", exif_off))],
        ifd0_data_off,
    )
    tiff = b"II" + struct.pack("<HI", 42, 8) + ifd0_tbl + ifd0_ext + exif_tbl + exif_ext
    if media_mod.Image is not None:
        buf = io.BytesIO()
        media_mod.Image.new("RGB", (width, height), color=(30, 90, 150)).save(buf, format="JPEG")
        base_jpg = buf.getvalue()
    else:
        sof0_p = struct.pack(">BHHBBBB", 8, height, width, 1, 1, 0x11, 0)
        sos_p = struct.pack(">BBBBBB", 1, 1, 0, 0, 63, 0)
        base_jpg = (
            b"\xff\xd8\xff\xc0" + struct.pack(">H", len(sof0_p) + 2) + sof0_p
            + b"\xff\xda" + struct.pack(">H", len(sos_p) + 2) + sos_p + b"\x7f\xff\xd9"
        )
    app1 = b"Exif\x00\x00" + tiff
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + base_jpg[2:]


@pytest.fixture()
def m3c_case_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[str], Tuple[str, Path, Path]]]:
    appdata = tmp_path / "wft_appdata"
    cases_root = tmp_path / "cases_root"
    custom_loc = appdata / "custom_locations.json"
    tool_paths = appdata / "tool_paths.json"
    appdata.mkdir(parents=True, exist_ok=True)
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata))
    monkeypatch.setenv("WFT_CASES_DIR", str(cases_root))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(custom_loc))
    monkeypatch.setenv("WFT_TOOL_PATHS_FILE", str(tool_paths))
    monkeypatch.setattr(cfg, "APP_DATA_DIR", appdata)
    monkeypatch.setattr(cfg, "CASES_DIR", cases_root)
    monkeypatch.setattr(cfg, "CUSTOM_LOCATIONS_FILE", custom_loc)
    opened: List[str] = []

    def _create(case_id: str) -> Tuple[str, Path, Path]:
        case_dir = cases_root / case_id
        staging_dir = case_dir / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        cfg.register_case_dir(case_id, case_dir)
        init_case_db(case_id)
        with DuckDBManager.get_lock(case_id):
            cur = DuckDBManager.get_connection(case_id, read_only=False).cursor()
            cur.execute(VFS_FILES_DDL)
            cur.execute("CREATE TABLE IF NOT EXISTS case_metadata (key VARCHAR PRIMARY KEY, value VARCHAR);")
            cur.execute("INSERT OR REPLACE INTO case_metadata (key, value) VALUES ('source_type', 'image');")
        opened.append(case_id)
        return case_id, case_dir, staging_dir

    try:
        yield _create
    finally:
        for cid in opened:
            DuckDBManager.close_connection(cid)
            cfg.unregister_case_dir(cid)


def _seed_vfs(case_id: str, vfs_path: str, staged_rel_path: str, size_bytes: int, si_modified: str, si_created: str) -> None:
    with DuckDBManager.get_lock(case_id):
        cur = DuckDBManager.get_connection(case_id, read_only=False).cursor()
        cur.execute(
            "INSERT INTO vfs_files (part_index, vfs_path, staged_rel_path, file_name, parent_path, "
            "size_bytes, is_dir, is_deleted, si_created, si_modified, si_created_utc, si_modified_utc) "
            "VALUES (0, ?, ?, ?, ?, ?, FALSE, FALSE, ?, ?, ?, ?);",
            [vfs_path, staged_rel_path, Path(vfs_path).name, str(Path(vfs_path).parent).replace("\\", "/"), size_bytes, si_created, si_modified, si_created, si_modified],
        )


def _populate_m3c_staging(case_id: str, staging_dir: Path) -> None:
    """Create genuine 7-parser forensic fixtures stamped to 2023-11-15 with poisoned 2026 si_created."""
    # 1. Chrome History (2023-11-15 10:00:00 UTC)
    chrome_db = staging_dir / "Browsers" / "Chrome" / "Alice" / "Default" / "History"
    chrome_db.parent.mkdir(parents=True, exist_ok=True)
    wk_us = int(round((datetime(2023, 11, 15, 10, 0, 0, tzinfo=timezone.utc).timestamp() + WEBKIT_EPOCH_OFFSET_SECONDS) * 1_000_000))
    with sqlite3.connect(str(chrome_db)) as c:
        c.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);")
        c.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);")
        c.execute("INSERT INTO urls VALUES (1, 'https://portal.example.org/login', 'Portal Login', 2, 1, ?);", (wk_us,))
        c.execute("INSERT INTO visits VALUES (1, 1, ?, 0, 1, 5000000);", (wk_us,))

    # 2. Firefox places.sqlite (2023-11-15 10:01:00 UTC)
    ff_db = staging_dir / "Browsers" / "Firefox" / "Alice" / "abc.default-release" / "places.sqlite"
    ff_db.parent.mkdir(parents=True, exist_ok=True)
    pr_us = int(round(datetime(2023, 11, 15, 10, 1, 0, tzinfo=timezone.utc).timestamp() * 1_000_000))
    with sqlite3.connect(str(ff_db)) as c:
        c.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed INTEGER, last_visit_date INTEGER);")
        c.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);")
        c.execute("INSERT INTO moz_places VALUES (1, 'https://intranet.example.org/docs', 'Intranet Docs', 1, 1, ?);", (pr_us,))
        c.execute("INSERT INTO moz_historyvisits VALUES (1, 0, 1, ?, 1);", (pr_us,))

    # 3. RFC 5322 Email (2023-11-15 10:02:00 UTC)
    eml_p = staging_dir / "Mail" / "Alice" / "evidence.eml"
    eml_p.parent.mkdir(parents=True, exist_ok=True)
    eml_p.write_bytes(
        b"From: alice@example.org\r\nTo: bob@example.org\r\nSubject: Q4 Audit Packet\r\n"
        b"Date: Wed, 15 Nov 2023 10:02:00 +0000\r\nMessage-ID: <m3c-msg-01@example.org>\r\n\r\n"
        b"Verified audit packet attached for review.\r\n"
    )

    # 4. Slack SQLite Chat (2023-11-15 10:05:00 UTC)
    chat_db = staging_dir / "Chat" / "Slack" / "Alice" / "msgs.sqlite"
    chat_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(chat_db)) as c:
        c.execute("CREATE TABLE messages (sender TEXT, content TEXT, timestamp TEXT, channel TEXT);")
        c.execute("INSERT INTO messages VALUES ('alice', 'Audit timeline confirmed', '2023-11-15T10:05:00Z', 'ir-room');")

    # 5. Cloud OneDrive SyncEngineDatabase.db + GoogleDrive metadata_sqlite_db
    od_db = staging_dir / "Cloud" / "OneDrive" / "Alice" / "SyncEngineDatabase.db"
    gd_db = staging_dir / "Cloud" / "GoogleDrive" / "Alice" / "metadata_sqlite_db"
    od_db.parent.mkdir(parents=True, exist_ok=True)
    gd_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(od_db)) as c:
        c.execute("CREATE TABLE items (localPath TEXT, resourceId TEXT, size INTEGER, lastChange INTEGER, fileStatus TEXT);")
        c.execute("INSERT INTO items VALUES ('C:\\Users\\Alice\\OneDrive\\ledger.xlsx', 'od-res-1', 8192, 1700042760, 'SYNCED');")
    with sqlite3.connect(str(gd_db)) as c:
        c.execute("CREATE TABLE items (local_title TEXT, cloud_id TEXT, file_size INTEGER, modified_date INTEGER, trashed INTEGER);")
        c.execute("INSERT INTO items VALUES ('roadmap_2023.pdf', 'gd-doc-1', 4096, 1700042820, 0);")

    # 6. Documents: PDF (+05:30 -> 10:00:00 UTC) + Zone.Identifier + notes.txt (poisoned 2026 si_created)
    doc_dir = staging_dir / "Enrichment" / "Part_0" / "Users" / "Alice" / "Documents"
    doc_dir.mkdir(parents=True, exist_ok=True)
    pdf_p = doc_dir / "brief.pdf"
    pdf_p.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /Pages /Count 2 >>\nendobj\n"
        b"2 0 obj\n<< /Title (IR Brief) /Author (Alice) /CreationDate (D:20231115153000+05'30') >>\nendobj\n"
        b"trailer\n<< /Info 2 0 R >>\n%%EOF\n"
    )
    (doc_dir / "brief.pdf.Zone.Identifier").write_text(
        "[ZoneTransfer]\nZoneId=3\nHostUrl=https://dl.example.org/brief.pdf\n", encoding="utf-8"
    )
    notes_p = doc_dir / "notes.txt"
    notes_p.write_text("Timeline correlation note for case verification.\n", encoding="utf-8")

    # 7. Media: EXIF JPEG (+05:30 -> 10:15:00 UTC)
    pic_dir = staging_dir / "Enrichment" / "Part_0" / "Users" / "Alice" / "Pictures"
    pic_dir.mkdir(parents=True, exist_ok=True)
    jpg_p = pic_dir / "photo.jpg"
    jpg_p.write_bytes(_build_exif_jpeg("2023:11:15 15:45:00", "+05:30"))

    for f in staging_dir.rglob("*"):
        if f.is_file():
            os.utime(f, (HIST_EPOCH, HIST_EPOCH))

    poison_created = "2026-11-17 12:00:00"
    _seed_vfs(case_id, "/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History", "Browsers/Chrome/Alice/Default/History", chrome_db.stat().st_size, "2023-11-15 10:00:00", poison_created)
    _seed_vfs(case_id, "/Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release/places.sqlite", "Browsers/Firefox/Alice/abc.default-release/places.sqlite", ff_db.stat().st_size, "2023-11-15 10:01:00", poison_created)
    _seed_vfs(case_id, "/Users/Alice/Documents/brief.pdf", "Enrichment/Part_0/Users/Alice/Documents/brief.pdf", pdf_p.stat().st_size, "2023-11-15 09:00:00", poison_created)
    _seed_vfs(case_id, "/Users/Alice/Documents/notes.txt", "Enrichment/Part_0/Users/Alice/Documents/notes.txt", notes_p.stat().st_size, "2023-11-15 09:30:00", poison_created)
    _seed_vfs(case_id, "/Users/Alice/Pictures/photo.jpg", "Enrichment/Part_0/Users/Alice/Pictures/photo.jpg", jpg_p.stat().st_size, "2023-11-15 09:00:00", poison_created)


PARSER_CLASSES = (
    ChromiumParser, FirefoxParser, EmailParser, ChatParser, CloudParser, DocumentParser, MediaParser,
)


def test_m3c_unified_7_parser_barrier_concurrency_and_zero_wallclock(
    m3c_case_factory: Callable[[str], Tuple[str, Path, Path]]
) -> None:
    case_id, _, staging_dir = m3c_case_factory("m3c_barrier_case")
    _populate_m3c_staging(case_id, staging_dir)
    barrier = threading.Barrier(8)

    def _run_parser(cls: Any) -> Dict[str, int]:
        barrier.wait(timeout=15)
        return cls(case_id=case_id, staging_dir=staging_dir, source_type="image").parse()

    def _run_reader() -> int:
        barrier.wait(timeout=15)
        checks = 0
        for _ in range(16):
            with DuckDBManager.get_lock(case_id):
                cur = DuckDBManager.get_connection(case_id).cursor()
                cur.execute("SELECT COUNT(*) FROM artifact_registry;").fetchone()
                checks += 1
        return checks

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_run_parser, cls) for cls in PARSER_CLASSES] + [pool.submit(_run_reader)]
        results = [f.result(timeout=30) for f in futs]
    assert results[-1] == 16

    with DuckDBManager.get_lock(case_id):
        cur = DuckDBManager.get_connection(case_id).cursor()
        assert cur.execute("SELECT url FROM parsed_chrome_history;").fetchall() == [("https://portal.example.org/login",)]
        assert cur.execute("SELECT url FROM parsed_firefox_history;").fetchall() == [("https://intranet.example.org/docs",)]
        assert cur.execute("SELECT sender, subject FROM parsed_emails;").fetchall() == [("alice@example.org", "Q4 Audit Packet")]
        assert cur.execute("SELECT sender, recipient_channel FROM parsed_chat_messages;").fetchall() == [("alice", "ir-room")]
        assert cur.execute("SELECT COUNT(*) FROM parsed_cloud_files;").fetchone()[0] == 2
        assert cur.execute("SELECT cloud_provider, local_path FROM parsed_gdrive_files;").fetchall() == [("GoogleDrive", "roadmap_2023.pdf")]
        pdf_row = cur.execute(
            "SELECT CAST(created_time AS VARCHAR), zone_id, host_url FROM parsed_documents_metadata WHERE file_name = 'brief.pdf';"
        ).fetchone()
        assert pdf_row is not None and pdf_row[0].startswith("2023-11-15 10:00:00") and pdf_row[1] == 3
        assert pdf_row[2] == "https://dl.example.org/brief.pdf"
        assert cur.execute("SELECT COUNT(*) FROM parsed_text_documents;").fetchone()[0] == 1
        pic_dt = cur.execute("SELECT CAST(datetime_original AS VARCHAR) FROM parsed_media_pictures WHERE file_name = 'photo.jpg';").fetchone()
        assert pic_dt is not None and pic_dt[0].startswith("2023-11-15 10:15:00")
        assert cur.execute("SELECT COUNT(*) FROM artifact_registry WHERE category = 'EMAIL & CALENDAR';").fetchone()[0] >= 1
        assert cur.execute("SELECT COUNT(*) FROM artifact_registry WHERE category = 'EMAIL';").fetchone()[0] == 0

        parsed_tables = [
            r[0] for r in cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_name LIKE 'parsed_%';"
            ).fetchall()
        ]
        assert len(parsed_tables) >= 9
        current_yr = str(datetime.now(timezone.utc).year)
        for tbl in parsed_tables:
            cols = [r[0] for r in cur.execute(f'DESCRIBE "{tbl}";').fetchall() if r[0] != "_row_id"]
            for row in cur.execute(f'SELECT {", ".join(chr(34) + c + chr(34) for c in cols)} FROM "{tbl}";').fetchall():
                for cell in row:
                    if cell is not None:
                        s = str(cell)
                        assert "2026-" not in s and f"{current_yr}-" not in s, f"Wall-clock/poisoned timestamp leaked in {tbl}: {s}"


def _snapshot_case_tables(case_id: str, staging_dir: Path) -> Dict[str, List[Tuple[Any, ...]]]:
    snap: Dict[str, List[Tuple[Any, ...]]] = {}
    s_win, s_pos = str(staging_dir), staging_dir.as_posix()
    with DuckDBManager.get_lock(case_id):
        cur = DuckDBManager.get_connection(case_id).cursor()
        tables = sorted(r[0] for r in cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_name LIKE 'parsed_%';").fetchall())
        for tbl in tables:
            desc = [r[0] for r in cur.execute(f'DESCRIBE "{tbl}";').fetchall()]
            if "_row_id" in desc:
                rids = [r[0] for r in cur.execute(f'SELECT "_row_id" FROM "{tbl}";').fetchall()]
                assert len(rids) == len(set(rids)), f"Duplicate _row_id in {tbl}"
            data_cols = [c for c in desc if c != "_row_id"]
            rows = cur.execute(f'SELECT {", ".join(chr(34) + c + chr(34) for c in data_cols)} FROM "{tbl}";').fetchall()
            if rows:
                snap[tbl] = sorted(tuple("" if v is None else str(v).replace(s_win, "<STG>").replace(s_pos, "<STG>") for v in r) for r in rows)
        snap["artifact_registry"] = sorted(cur.execute("SELECT artifact_id, category, table_name, row_count FROM artifact_registry WHERE row_count > 0;").fetchall())
    return snap


def test_m3c_worker_count_deterministic_equivalence_and_gdrive_interleaving(m3c_case_factory: Callable[[str], Tuple[str, Path, Path]]) -> None:
    snapshots: Dict[int, Dict[str, List[Tuple[Any, ...]]]] = {}
    for workers in (1, 8, 16):
        cid, _, sdir = m3c_case_factory(f"m3c_eq_w{workers}")
        _populate_m3c_staging(cid, sdir)

        def _gdrive_fallback(target_cid: str = cid, target_sdir: Path = sdir) -> int:
            bp = BaseParser(case_id=target_cid, staging_dir=target_sdir, source_type="image")
            fb_rec = [{"cloud_provider": "Google Drive", "account": "alice@example.org", "local_path": "C:\\Users\\Alice\\Google Drive\\sync_log_item.docx", "cloud_path_or_id": "glog-99", "file_size": 2048, "modified_time": datetime(2023, 11, 15, 10, 20, 0), "status": "SYNCED", "source_file": "/Users/Alice/AppData/Local/Google/Drive/sync_log.log"}]
            with DuckDBManager.get_lock(target_cid):
                cnt = bp.insert_records("parsed_gdrive_files", fb_rec, schema_ddl=GDRIVE_FILES_DDL, artifact_id="gdrive_files", category="CLOUD", display_name="Google Drive Synced Files", source_tool="CloudParser", append=True)
                bp.register_artifact("parsed_gdrive_files", "gdrive_files", "CLOUD", "Google Drive Synced Files", "CloudParser", cnt)
                return cnt

        jobs = [lambda cls=c, tc=cid, ts=sdir: cls(case_id=tc, staging_dir=ts, source_type="image").parse() for c in PARSER_CLASSES]
        jobs.append(_gdrive_fallback)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for fut in [pool.submit(fn) for fn in jobs]:
                fut.result(timeout=30)

        if workers == 16:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                for fut in [pool.submit(lambda cls=c, tc=cid, ts=sdir: cls(case_id=tc, staging_dir=ts, source_type="image").parse()) for c in PARSER_CLASSES]:
                    fut.result(timeout=30)

        with DuckDBManager.get_lock(cid):
            cur = DuckDBManager.get_connection(cid).cursor()
            providers = {r[0] for r in cur.execute("SELECT cloud_provider FROM parsed_gdrive_files;").fetchall()}
            assert providers == {"GoogleDrive", "Google Drive"}
            gd_cnt = cur.execute("SELECT COUNT(*) FROM parsed_gdrive_files;").fetchone()[0]
            reg_cnt = cur.execute("SELECT row_count FROM artifact_registry WHERE artifact_id = 'gdrive_files';").fetchone()[0]
            assert gd_cnt == 2 and reg_cnt == 2
        snapshots[workers] = _snapshot_case_tables(cid, sdir)

    assert snapshots[1] == snapshots[8] == snapshots[16]


def test_m3c_11_file_hygiene_ast_compile_and_anticheat_invariants() -> None:
    root = Path(__file__).resolve().parents[2]
    parser_files = [
        root / "backend" / "parsers" / f"{stem}_parser.py"
        for stem in ("base", "chromium", "firefox", "chat", "cloud", "document", "email", "media")
    ]
    test_files = [
        root / "backend" / "tests" / name
        for name in ("test_m3_app_parsers.py", "test_m3a_browsers.py", "test_m3b_content_parsers.py")
    ]
    for p in parser_files + test_files:
        assert p.is_file(), f"Missing M3 owned file: {p}"
        raw = p.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), f"UTF-8 BOM forbidden in {p}"
        src = raw.decode("utf-8")
        tree = ast.parse(src, filename=str(p))
        compile(raw, str(p), "exec")
        if p in parser_files and p.name != "base_parser.py":
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    assert node.attr != "st_ctime", f"Forbidden .st_ctime access in {p}:{getattr(node, 'lineno', '?')}"
        elif p.name == "base_parser.py":
            for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "get_original_ctime"):
                assert all(not (isinstance(sub, ast.Attribute) and sub.attr == "st_ctime") for sub in ast.walk(fn))

    banned_token = "informant" + "@secret.com"
    for py_file in sorted((root / "backend" / "parsers").glob("*.py")):
        assert banned_token not in py_file.read_text(encoding="utf-8"), f"Hardcoded cheat token in {py_file}"
