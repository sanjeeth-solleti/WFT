"""
Milestone M1 Automated Test Suite:
Toolchain Bootstrap (Setup-WFTTools.ps1 Branches 1 & 2), WFT.exe / wft_launcher.py / build_standalone.py
Lifecycle Guarantees, backend.config Resolution & Precedence, backend.security Hardening,
and Live Workspace Toolchain Verification.
"""
from __future__ import annotations

import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import pefile
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
SETUP_PS1 = WORKSPACE_ROOT / "Setup-WFTTools.ps1"
CSC_EXE = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe")
POWERSHELL_EXE = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def _compile_cs_stub(out_exe: Path, cs_source: str) -> Path:
    cs_file = out_exe.with_suffix(".cs")
    cs_file.write_text(cs_source, encoding="utf-8")
    cp = subprocess.run(
        [str(CSC_EXE), "/nologo", "/optimize+", "/target:exe", f"/out:{out_exe}", str(cs_file)],
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert cp.returncode == 0, f"csc.exe failed compiling {out_exe}: {cp.stdout}\n{cp.stderr}"
    assert out_exe.is_file() and out_exe.read_bytes()[:2] == b"MZ"
    return out_exe


WFT_EXE = WORKSPACE_ROOT / "WFT.exe"
_LAUNCHER_CS = WORKSPACE_ROOT / "scripts" / "WFTLauncher.cs"
if _LAUNCHER_CS.is_file() and CSC_EXE.is_file():
    try:
        _tmp_wft = Path(tempfile.gettempdir()) / "WFT_launcher_compiled.exe"
        _compile_cs_stub(_tmp_wft, _LAUNCHER_CS.read_text(encoding="utf-8"))
        WFT_EXE = _tmp_wft
    except Exception:
        _NEW_WFT = WORKSPACE_ROOT / "scripts" / "WFT_new.exe"
        if _NEW_WFT.is_file():
            WFT_EXE = _NEW_WFT
PICKER_CS = WORKSPACE_ROOT / "scripts" / "WFTPicker.cs"
WFT_LAUNCHER_PY = WORKSPACE_ROOT / "scripts" / "wft_launcher.py"

EZ_16_MAP: Dict[str, str] = {
    "WFT_EZ_RLA_EXE": "rla.exe",
    "WFT_EZ_PECMD_EXE": "PECmd.exe",
    "WFT_EZ_MFTECMD_EXE": "MFTECmd.exe",
    "WFT_EZ_EVTXECMD_EXE": "EvtxECmd.exe",
    "WFT_EZ_RECMD_EXE": "RECmd.exe",
    "WFT_EZ_LECMD_EXE": "LECmd.exe",
    "WFT_EZ_JLECMD_EXE": "JLECmd.exe",
    "WFT_EZ_AMCACHE_EXE": "AmcacheParser.exe",
    "WFT_EZ_SHIMCACHE_EXE": "AppCompatCacheParser.exe",
    "WFT_EZ_SBECMD_EXE": "SBECmd.exe",
    "WFT_EZ_SRUMECMD_EXE": "SrumECmd.exe",
    "WFT_EZ_WXTCMD_EXE": "WxTCmd.exe",
    "WFT_EZ_SQLECMD_EXE": "SQLECmd.exe",
    "WFT_EZ_RBCMD_EXE": "RBCmd.exe",
    "WFT_EZ_RECENTFILECACHE_EXE": "RecentFileCacheParser.exe",
    "WFT_EZ_SUMECMD_EXE": "SumECmd.exe",
}

CANONICAL_25_ENV_KEYS = set(EZ_16_MAP.keys()) | {
    "WFT_EZTOOLS_DIR",
    "WFT_REGRIPPER_DIR",
    "WFT_REGRIPPER_EXE",
    "WFT_HINDSIGHT_EXE",
    "WFT_STINGER_EXE",
    "WFT_BULK_EXTRACTOR_EXE",
    "WFT_RULES_DIR",
    "WFT_CASES_DIR",
    "WFT_HOST",
    "WFT_PORT",
}


def _parse_dotenv_bytes(env_path: Path) -> Dict[str, str]:
    raw = env_path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), f"Unexpected UTF-8 BOM in {env_path}"
    parsed: Dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            parsed[k.strip()] = v.strip().strip('"').strip("'")
    return parsed



@pytest.fixture(scope="module")
def compiled_pe_stubs(tmp_path_factory) -> Dict[str, Path]:
    """Compiles genuine 64-bit Windows PE executables once for isolated bootstrap/config tests."""
    stub_dir = tmp_path_factory.mktemp("m1_pe_stubs")

    generic_exe = _compile_cs_stub(
        stub_dir / "generic_cli.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                Console.WriteLine("Forensic CLI Tool --help OK");
                return 0;
            }
        }
        """,
    )

    rip_v28_exe = _compile_cs_stub(
        stub_dir / "rip_v28.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                Console.WriteLine("Rip v.2.8_20200220 - CLI RegRipper tool");
                Console.WriteLine("Syntax: rip [-r Reg hive file] [-f profile] [-p plugin]");
                return 0;
            }
        }
        """,
    )

    rip_v40_exe = _compile_cs_stub(
        stub_dir / "rip_v40.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                Console.WriteLine("Rip v.4.0 - CLI RegRipper tool");
                Console.WriteLine("  -r <hive> .........Registry hive file to parse");
                Console.WriteLine("  -a ................Automatically run hive-specific plugins");
                Console.WriteLine("  -aT ...............Automatically run hive-specific TLN plugins");
                Console.WriteLine("  -l -c .............List plugins in CSV format");
                return 0;
            }
        }
        """,
    )

    stinger_exe = _compile_cs_stub(
        stub_dir / "stinger_stub.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                return 0;
            }
        }
        """,
    )
    with open(stinger_exe, "ab") as f:
        f.write(b"\x00" * 160_000)

    bad_python_exe = _compile_cs_stub(
        stub_dir / "bad_python.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                Console.Error.WriteLine("Simulated broken python shim");
                return 9009;
            }
        }
        """,
    )

    bulk_extractor_exe = _compile_cs_stub(
        stub_dir / "bulk_extractor64.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                Console.WriteLine("bulk_extractor 2.2.0");
                return 0;
            }
        }
        """,
    )

    bulk_extractor_bad_exe = _compile_cs_stub(
        stub_dir / "bulk_extractor_bad.exe",
        """
        using System;
        class P {
            static int Main(string[] args) {
                Console.Error.WriteLine("Corrupt bulk_extractor stub");
                return 2;
            }
        }
        """,
    )

    return {
        "generic": generic_exe,
        "rip_v28": rip_v28_exe,
        "rip_v40": rip_v40_exe,
        "stinger": stinger_exe,
        "bad_python": bad_python_exe,
        "bulk_extractor": bulk_extractor_exe,
        "bulk_extractor_bad": bulk_extractor_bad_exe,
    }


@pytest.fixture()
def isolated_config_env(monkeypatch, tmp_path):
    """Isolates backend.config from live workspace .env and %LOCALAPPDATA%\\WFT state."""
    import backend.config as cfg

    appdata = tmp_path / "appdata"
    appdata.mkdir(parents=True, exist_ok=True)
    tp_file = appdata / "tool_paths.json"
    env_file = tmp_path / ".env"
    loc_file = appdata / "custom_locations.json"

    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata))
    monkeypatch.setenv("WFT_TOOL_PATHS_FILE", str(tp_file))
    monkeypatch.setenv("WFT_ENV_FILE", str(env_file))
    monkeypatch.setenv("WFT_CUSTOM_LOCATIONS_FILE", str(loc_file))

    for k in list(os.environ.keys()):
        if k.startswith("WFT_EZ") or k in (
            "WFT_REGRIPPER_DIR",
            "WFT_REGRIPPER_EXE",
            "WFT_HINDSIGHT_EXE",
            "WFT_STINGER_EXE",
            "WFT_BULK_EXTRACTOR_EXE",
        ):
            monkeypatch.delenv(k, raising=False)

    cfg._REGRIPPER_VALIDATION_CACHE.clear()
    cfg.reload_dotenv(env_file=env_file, override=True)
    yield {
        "cfg": cfg,
        "appdata": appdata,
        "tp_file": tp_file,
        "env_file": env_file,
    }
    cfg._REGRIPPER_VALIDATION_CACHE.clear()


def _populate_ez_suite_dir(ez_dir: Path, generic_stub: Path, omit_exes: set[str] | None = None) -> None:
    omit_low = {x.lower() for x in (omit_exes or set())}
    ez_dir.mkdir(parents=True, exist_ok=True)
    for exe_name in EZ_16_MAP.values():
        if exe_name.lower() in omit_low:
            continue
        base = Path(exe_name).stem
        sub = ez_dir / "net" / base
        sub.mkdir(parents=True, exist_ok=True)
        shutil.copy2(generic_stub, sub / exe_name)
        if base.lower() == "recmd":
            batch_dir = sub / "BatchExamples"
            batch_dir.mkdir(parents=True, exist_ok=True)
            (batch_dir / "Kroll_Batch.reb").write_text("Description: Test Batch\n", encoding="utf-8")
        elif base.lower() == "sqlecmd":
            maps_dir = sub / "Maps"
            maps_dir.mkdir(parents=True, exist_ok=True)
            (maps_dir / "Windows_Sample.smap").write_text("Description: Test Map\n", encoding="utf-8")
        elif base.lower() == "evtxecmd":
            maps_dir = sub / "Maps"
            maps_dir.mkdir(parents=True, exist_ok=True)
            (maps_dir / "0000_Sample.map").write_text("Description: Event Map\n", encoding="utf-8")


def _run_powershell_inline(ps_command: str, env: Dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(POWERSHELL_EXE), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


# ==============================================================================
# 1. Manifests & Encoding Hygiene
# ==============================================================================
def test_env_example_and_m1_files_utf8_no_bom():
    env_example = WORKSPACE_ROOT / ".env.example"
    assert env_example.is_file()
    parsed = _parse_dotenv_bytes(env_example)
    assert CANONICAL_25_ENV_KEYS.issubset(set(parsed.keys())), (
        f"Missing keys in .env.example: {CANONICAL_25_ENV_KEYS - set(parsed.keys())}"
    )

    m1_text_files = [
        WORKSPACE_ROOT / ".env.example",
        WORKSPACE_ROOT / ".gitignore",
        WORKSPACE_ROOT / "requirements.txt",
        WORKSPACE_ROOT / "Setup-WFTTools.ps1",
        WORKSPACE_ROOT / "backend" / "__init__.py",
        WORKSPACE_ROOT / "backend" / "config.py",
        WORKSPACE_ROOT / "backend" / "security.py",
        WORKSPACE_ROOT / "scripts" / "setup_tools.py",
        WORKSPACE_ROOT / "scripts" / "wft_launcher.py",
        WORKSPACE_ROOT / "scripts" / "build_standalone.py",
        WORKSPACE_ROOT / "scripts" / "WFTLauncher.cs",
        WORKSPACE_ROOT / "scripts" / "WFTPicker.cs",
    ]
    for fp in m1_text_files:
        raw = fp.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), f"File {fp} must not contain a UTF-8 BOM"


# ==============================================================================
# 2. Setup-WFTTools.ps1 Two-Branch Automated Tests
# ==============================================================================
def test_ps1_branch1_detects_preexisting_tools_and_rejects_rip_v28(tmp_path, compiled_pe_stubs):
    proj_root = tmp_path / "proj_b1"
    (proj_root / "EZTools").mkdir(parents=True, exist_ok=True)  # Empty EZTools folder must NOT clobber WFT_EZTOOLS_DIR!
    (proj_root / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(PICKER_CS, proj_root / "scripts" / "WFTPicker.cs")

    # Decoy root comes FIRST in SearchRoots with Autopsy Rip v2.8 + 20 .pl files + hindsight_gui.exe
    decoy_root = tmp_path / "decoy_root"
    decoy_rr = decoy_root / "Autopsy" / "rr-full"
    (decoy_rr / "plugins").mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["rip_v28"], decoy_rr / "rip.exe")
    for i in range(5):
        (decoy_rr / "plugins" / f"decoy_{i}.pl").write_text("# perl plugin\n", encoding="utf-8")
    shutil.copy2(compiled_pe_stubs["generic"], decoy_root / "hindsight_gui.exe")
    shutil.copy2(compiled_pe_stubs["bulk_extractor_bad"], decoy_root / "bulk_extractor64.exe")
    (decoy_root / "bulk_extractor.exe").write_bytes(b"")

    # Pre-existing valid tool root comes SECOND in SearchRoots
    pre_root = tmp_path / "preexisting_tools"
    pre_ez = pre_root / "EZTools"
    _populate_ez_suite_dir(pre_ez, compiled_pe_stubs["generic"])

    pre_rr = pre_root / "RegRipper4.0-main"
    (pre_rr / "plugins").mkdir(parents=True, exist_ok=True)
    valid_rip = pre_rr / "rip.exe"
    shutil.copy2(compiled_pe_stubs["rip_v40"], valid_rip)
    (pre_rr / "plugins" / "samparse.pl").write_text("# valid samparse\n", encoding="utf-8")

    pre_hs = pre_root / "hindsight" / "hindsight.exe"
    pre_hs.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["generic"], pre_hs)

    pre_stinger = pre_root / "stinger" / "stinger64.exe"
    pre_stinger.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["stinger"], pre_stinger)

    pre_bulk = pre_root / "bulk_extractor" / "bulk_extractor64.exe"
    pre_bulk.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["bulk_extractor"], pre_bulk)

    # Dead URL overrides ensure any accidental Branch 2 network call would fail
    ps_cmd = f"""
    & '{SETUP_PS1}' `
      -ProjectRoot '{proj_root}' `
      -SearchRoots @('{decoy_root}', '{pre_root}') `
      -SkipFullDiskScan `
      -ToolUrlOverrides @{{
          EZBaseUrl      = 'http://127.0.0.1:1/unreachable';
          RegRipper      = 'http://127.0.0.1:1/unreachable.zip';
          Hindsight      = 'http://127.0.0.1:1/unreachable.exe';
          Stinger        = 'http://127.0.0.1:1/unreachable.exe';
          bulk_extractor = 'http://127.0.0.1:1/unreachable.exe'
      }}
    exit $LASTEXITCODE
    """
    cp = _run_powershell_inline(ps_cmd)
    assert cp.returncode == 0, f"Branch 1 failed:\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}"

    env_map = _parse_dotenv_bytes(proj_root / ".env")
    for env_key, exe_name in EZ_16_MAP.items():
        assert env_key in env_map, f"Missing {env_key} in .env"
        resolved = Path(env_map[env_key]).resolve()
        assert resolved.is_file() and resolved.name.lower() == exe_name.lower()
        assert str(resolved).lower().startswith(str(pre_ez.resolve()).lower())

    # Empty proj_root\EZTools must NOT clobber WFT_EZTOOLS_DIR
    assert Path(env_map["WFT_EZTOOLS_DIR"]).resolve() == pre_ez.resolve()

    # Decoy Autopsy Rip v2.8 & bad bulk_extractor must be rejected in favor of valid tools
    assert Path(env_map["WFT_REGRIPPER_EXE"]).resolve() == valid_rip.resolve()
    assert Path(env_map["WFT_REGRIPPER_DIR"]).resolve() == pre_rr.resolve()
    assert Path(env_map["WFT_HINDSIGHT_EXE"]).resolve() == pre_hs.resolve()
    assert Path(env_map["WFT_STINGER_EXE"]).resolve() == pre_stinger.resolve()
    assert Path(env_map["WFT_BULK_EXTRACTOR_EXE"]).resolve() == pre_bulk.resolve()

    picker_exe = proj_root / "tools" / "wft_picker.exe"
    assert picker_exe.is_file()
    p_res = subprocess.run(
        [str(picker_exe), "--test"],
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert p_res.returncode == 0 and "WFT_PICKER_OK" in p_res.stdout


class _LocalArtifactServer:
    """Serves synthetic tool zips/executables over 127.0.0.1 and records all HTTP GET paths."""

    def __init__(self, serve_dir: Path):
        self.serve_dir = serve_dir
        self.requested_paths: List[str] = []
        outer = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(outer.serve_dir), **kwargs)

            def do_GET(self):
                outer.requested_paths.append(self.path)
                return super().do_GET()

            def log_message(self, format, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.httpd.shutdown()
        self.httpd.server_close()


def _build_branch2_http_mirror(mirror_dir: Path, compiled_pe_stubs: Dict[str, Path]) -> None:
    ez_mirror = mirror_dir / "ez"
    ez_mirror.mkdir(parents=True, exist_ok=True)
    for exe_name in EZ_16_MAP.values():
        base = Path(exe_name).stem
        zip_path = ez_mirror / f"{base}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if base.lower() == "recmd":
                zf.write(compiled_pe_stubs["generic"], arcname=f"RECmd/{exe_name}")
                zf.writestr("RECmd/BatchExamples/Kroll_Batch.reb", "Description: Mirror Batch\n")
            elif base.lower() == "sqlecmd":
                zf.write(compiled_pe_stubs["generic"], arcname=f"SQLECmd/{exe_name}")
                zf.writestr("SQLECmd/Maps/Mirror_Map.smap", "Description: Mirror Map\n")
            elif base.lower() == "evtxecmd":
                zf.write(compiled_pe_stubs["generic"], arcname=f"EvtxeCmd/{exe_name}")
                zf.writestr("EvtxeCmd/Maps/0001_Mirror.map", "Description: Mirror Evtx Map\n")
            else:
                # Flat zip layout matching rla.zip, PECmd.zip, SumECmd.zip, etc.
                zf.write(compiled_pe_stubs["generic"], arcname=exe_name)

    rr_zip = mirror_dir / "regripper.zip"
    with zipfile.ZipFile(rr_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(compiled_pe_stubs["rip_v40"], arcname="RegRipper4.0-main/rip.exe")
        zf.writestr("RegRipper4.0-main/plugins/ntuser.pl", "# mirror plugin\n")

    shutil.copy2(compiled_pe_stubs["generic"], mirror_dir / "hindsight.exe")
    shutil.copy2(compiled_pe_stubs["stinger"], mirror_dir / "stinger64.exe")
    shutil.copy2(compiled_pe_stubs["bulk_extractor"], mirror_dir / "bulk_extractor64.exe")


def test_ps1_branch2_downloads_missing_tools_via_url_overrides(tmp_path, compiled_pe_stubs):
    mirror_dir = tmp_path / "mirror"
    _build_branch2_http_mirror(mirror_dir, compiled_pe_stubs)

    proj_root = tmp_path / "proj_b2"
    empty_search = tmp_path / "empty_search"
    empty_search.mkdir(parents=True, exist_ok=True)

    with _LocalArtifactServer(mirror_dir) as srv:
        ps_cmd = f"""
        & '{SETUP_PS1}' `
          -ProjectRoot '{proj_root}' `
          -SearchRoots @('{empty_search}') `
          -SkipFullDiskScan `
          -ToolUrlOverrides @{{
              EZBaseUrl      = '{srv.base_url}/ez';
              RegRipper      = '{srv.base_url}/regripper.zip';
              Hindsight      = '{srv.base_url}/hindsight.exe';
              Stinger        = '{srv.base_url}/stinger64.exe';
              bulk_extractor = '{srv.base_url}/bulk_extractor64.exe'
          }}
        exit $LASTEXITCODE
        """
        cp = _run_powershell_inline(ps_cmd)
        assert cp.returncode == 0, f"Branch 2 failed:\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}"
        fetched = set(srv.requested_paths)

    for exe_name in EZ_16_MAP.values():
        assert f"/ez/{Path(exe_name).stem}.zip" in fetched
    assert "/regripper.zip" in fetched
    assert "/hindsight.exe" in fetched
    assert "/stinger64.exe" in fetched
    assert "/bulk_extractor64.exe" in fetched

    tools_dir = (proj_root / "tools").resolve()
    env_map = _parse_dotenv_bytes(proj_root / ".env")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    for env_key, exe_name in EZ_16_MAP.items():
        p = Path(env_map[env_key]).resolve()
        assert p.is_file() and p.name.lower() == exe_name.lower()
        assert p.is_relative_to(tools_dir)
        assert subprocess.run([str(p), "--help"], capture_output=True, timeout=10, creationflags=creationflags).returncode == 0

    assert any(tools_dir.rglob("Kroll_Batch.reb"))
    assert any(tools_dir.rglob("*.smap"))
    rr_p = Path(env_map["WFT_REGRIPPER_EXE"]).resolve()
    hs_p = Path(env_map["WFT_HINDSIGHT_EXE"]).resolve()
    st_p = Path(env_map["WFT_STINGER_EXE"]).resolve()
    be_p = Path(env_map["WFT_BULK_EXTRACTOR_EXE"]).resolve()
    assert rr_p.is_relative_to(tools_dir)
    assert hs_p.is_relative_to(tools_dir)
    assert st_p.is_relative_to(tools_dir) and st_p.read_bytes()[:2] == b"MZ"
    assert be_p.is_relative_to(tools_dir) and be_p.read_bytes()[:2] == b"MZ"
    rr_run = subprocess.run([str(rr_p), "-h"], cwd=str(rr_p.parent), capture_output=True, text=True, timeout=10, creationflags=creationflags)
    assert rr_run.returncode == 0 and "-a" in rr_run.stdout
    assert subprocess.run([str(hs_p), "--help"], capture_output=True, timeout=10, creationflags=creationflags).returncode == 0
    assert subprocess.run([str(be_p), "-V"], capture_output=True, timeout=10, creationflags=creationflags).returncode == 0
    assert (tools_dir / "wft_picker.exe").is_file()


def test_ps1_branch2_partial_missing_ez_tool_rla_only(tmp_path, compiled_pe_stubs):
    mirror_dir = tmp_path / "mirror_partial"
    _build_branch2_http_mirror(mirror_dir, compiled_pe_stubs)

    pre_root = tmp_path / "partial_preexisting"
    _populate_ez_suite_dir(pre_root / "EZTools", compiled_pe_stubs["generic"], omit_exes={"rla.exe"})
    (pre_root / "RegRipper4.0" / "plugins").mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["rip_v40"], pre_root / "RegRipper4.0" / "rip.exe")
    (pre_root / "RegRipper4.0" / "plugins" / "sam.pl").write_text("# sam\n", encoding="utf-8")
    shutil.copy2(compiled_pe_stubs["generic"], pre_root / "hindsight.exe")
    shutil.copy2(compiled_pe_stubs["stinger"], pre_root / "stinger64.exe")
    shutil.copy2(compiled_pe_stubs["bulk_extractor"], pre_root / "bulk_extractor64.exe")

    proj_root = tmp_path / "proj_partial"
    with _LocalArtifactServer(mirror_dir) as srv:
        ps_cmd = f"""
        & '{SETUP_PS1}' `
          -ProjectRoot '{proj_root}' `
          -SearchRoots @('{pre_root}') `
          -SkipFullDiskScan `
          -ToolUrlOverrides @{{
              EZBaseUrl      = '{srv.base_url}/ez';
              RegRipper      = '{srv.base_url}/regripper.zip';
              Hindsight      = '{srv.base_url}/hindsight.exe';
              Stinger        = '{srv.base_url}/stinger64.exe';
              bulk_extractor = '{srv.base_url}/bulk_extractor64.exe'
          }}
        exit $LASTEXITCODE
        """
        cp = _run_powershell_inline(ps_cmd)
        assert cp.returncode == 0
        fetched = list(srv.requested_paths)

    assert fetched == ["/ez/rla.zip"], f"Expected ONLY /ez/rla.zip to be downloaded, got {fetched}"
    env_map = _parse_dotenv_bytes(proj_root / ".env")
    assert Path(env_map["WFT_EZ_RLA_EXE"]).resolve().is_relative_to((proj_root / "tools").resolve())
    assert Path(env_map["WFT_EZ_PECMD_EXE"]).resolve().is_relative_to(pre_root.resolve())
    assert Path(env_map["WFT_EZ_SUMECMD_EXE"]).resolve().is_relative_to(pre_root.resolve())


# ==============================================================================
# 3. Compiled WFT.exe & wft_launcher.py & build_standalone.py Lifecycle Tests
# ==============================================================================
def _run_wft_exe(work_dir: Path, args: List[str], extra_env: Dict[str, str]) -> subprocess.CompletedProcess:
    exe_copy = work_dir / "WFT.exe"
    if not exe_copy.exists():
        shutil.copy2(WFT_EXE, exe_copy)
    env = os.environ.copy()
    env.update(extra_env)
    return subprocess.run(
        [str(exe_copy)] + args,
        cwd=str(work_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def test_wft_exe_pip_failure_does_not_create_marker(tmp_path):
    work_dir = tmp_path / "wft_pip_fail"
    appdata_dir = tmp_path / "appdata"
    work_dir.mkdir()
    (work_dir / "requirements.txt").write_text("--no-such-pip-flag-xyz-999\n", encoding="utf-8")
    (work_dir / "Setup-WFTTools.ps1").write_text("exit 0\n", encoding="utf-8")

    cp = _run_wft_exe(
        work_dir,
        ["--setup-only"],
        {"WFT_APPDATA_DIR": str(appdata_dir), "WFT_PYTHON_EXE": sys.executable},
    )
    assert cp.returncode != 0
    assert not (work_dir / ".wft_setup_done").exists()
    assert not (appdata_dir / ".wft_setup_done").exists()


def test_wft_exe_ps1_failure_does_not_create_marker(tmp_path):
    work_dir = tmp_path / "wft_ps1_fail"
    appdata_dir = tmp_path / "appdata"
    work_dir.mkdir()
    (work_dir / "requirements.txt").write_text("# empty\n", encoding="utf-8")
    (work_dir / "Setup-WFTTools.ps1").write_text("Write-Error 'Simulated bootstrap failure'; exit 7\n", encoding="utf-8")

    cp = _run_wft_exe(
        work_dir,
        ["--setup-only"],
        {"WFT_APPDATA_DIR": str(appdata_dir), "WFT_PYTHON_EXE": sys.executable},
    )
    assert cp.returncode != 0
    assert not (work_dir / ".wft_setup_done").exists()
    assert not (appdata_dir / ".wft_setup_done").exists()


def test_wft_exe_success_creates_marker_and_skips_second_run(tmp_path):
    work_dir = tmp_path / "wft_ok"
    appdata_dir = tmp_path / "appdata"
    work_dir.mkdir()
    (work_dir / "requirements.txt").write_text("# empty\n", encoding="utf-8")
    (work_dir / "Setup-WFTTools.ps1").write_text(
        "param([string]$ProjectRoot = $PSScriptRoot)\n"
        "Add-Content -Path (Join-Path $ProjectRoot 'runs.log') -Value 'RUN'\n"
        "Set-Content -Path (Join-Path $ProjectRoot '.env') -Value 'WFT_PORT=8765'\n"
        "exit 0\n",
        encoding="utf-8",
    )

    env = {"WFT_APPDATA_DIR": str(appdata_dir), "WFT_PYTHON_EXE": sys.executable}
    cp1 = _run_wft_exe(work_dir, ["--setup-only"], env)
    assert cp1.returncode == 0, f"STDERR: {cp1.stderr}"
    assert (work_dir / ".wft_setup_done").is_file()
    assert len((work_dir / "runs.log").read_text(encoding="utf-8").splitlines()) == 1

    # Second launch without --setup must skip bootstrap
    cp2 = _run_wft_exe(work_dir, ["--setup-only"], env)
    assert cp2.returncode == 0
    assert len((work_dir / "runs.log").read_text(encoding="utf-8").splitlines()) == 1

    # Third launch with --setup must force re-execution
    cp3 = _run_wft_exe(work_dir, ["--setup", "--setup-only"], env)
    assert cp3.returncode == 0
    assert len((work_dir / "runs.log").read_text(encoding="utf-8").splitlines()) == 2


def test_wft_exe_skips_zero_byte_windowsapps_stub_and_broken_python(tmp_path, compiled_pe_stubs):
    work_dir = tmp_path / "wft_py_probe"
    appdata_dir = tmp_path / "appdata"
    work_dir.mkdir()
    (work_dir / "requirements.txt").write_text("# empty\n", encoding="utf-8")
    (work_dir / "Setup-WFTTools.ps1").write_text("param([string]$ProjectRoot) exit 0\n", encoding="utf-8")

    # 1. Zero-byte Microsoft\WindowsApps\python.exe stub
    winapps_dir = tmp_path / "Microsoft" / "WindowsApps"
    winapps_dir.mkdir(parents=True, exist_ok=True)
    (winapps_dir / "python.exe").write_bytes(b"")

    # 2. Non-zero PE python.exe that exits 9009
    bad_py_dir = tmp_path / "bad_py"
    bad_py_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["bad_python"], bad_py_dir / "python.exe")

    real_py_dir = str(Path(sys.executable).resolve().parent)
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    ps_dir = str(POWERSHELL_EXE.parent)
    custom_path = ";".join([str(winapps_dir), str(bad_py_dir), real_py_dir, ps_dir, rf"{sys_root}\System32"])

    exe_copy = work_dir / "WFT.exe"
    shutil.copy2(WFT_EXE, exe_copy)
    env = os.environ.copy()
    env.pop("WFT_PYTHON_EXE", None)
    env.pop("WFT_PYTHON_STRICT", None)
    env["WFT_APPDATA_DIR"] = str(appdata_dir)
    env["PATH"] = custom_path

    cp = subprocess.run(
        [str(exe_copy), "--setup-only"],
        cwd=str(work_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert cp.returncode == 0, f"STDOUT: {cp.stdout}\nSTDERR: {cp.stderr}"
    assert (work_dir / ".wft_setup_done").is_file()


def test_wft_exe_readonly_basedir_falls_back_to_localappdata_marker(tmp_path):
    ro_dir = tmp_path / "readonly_install"
    appdata_dir = tmp_path / "appdata_fallback"
    ro_dir.mkdir()
    shutil.copy2(WFT_EXE, ro_dir / "WFT.exe")
    (ro_dir / "requirements.txt").write_text("# empty\n", encoding="utf-8")
    (ro_dir / "Setup-WFTTools.ps1").write_text(
        "param([string]$ProjectRoot, [string]$EnvFilePath = '', [string]$ToolsRootDir = '')\n"
        "if (-not $EnvFilePath) { exit 5 }\n"
        "New-Item -ItemType Directory -Path $ToolsRootDir -Force | Out-Null\n"
        "Add-Content -Path $EnvFilePath -Value 'WFT_PORT=8765'\n"
        "exit 0\n",
        encoding="utf-8",
    )

    username = os.environ.get("USERNAME", "")
    userdomain = os.environ.get("USERDOMAIN", "")
    trustee = f"{userdomain}\\{username}" if userdomain else username

    icacls_exe = r"C:\Windows\System32\icacls.exe"
    deny_cp = subprocess.run(
        [icacls_exe, str(ro_dir), "/deny", f"{trustee}:(WD,AD)"],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert deny_cp.returncode == 0, f"icacls deny failed: {deny_cp.stdout} {deny_cp.stderr}"

    try:
        env = os.environ.copy()
        env["WFT_APPDATA_DIR"] = str(appdata_dir)
        env["WFT_PYTHON_EXE"] = sys.executable

        cp1 = subprocess.run(
            [str(ro_dir / "WFT.exe"), "--setup-only"],
            cwd=str(ro_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert cp1.returncode == 0, f"Read-only fallback failed: {cp1.stdout}\n{cp1.stderr}"
        assert not (ro_dir / ".wft_setup_done").exists()
        assert (appdata_dir / ".wft_setup_done").is_file()
        assert (appdata_dir / ".env").is_file()
        assert len((appdata_dir / ".env").read_text(encoding="utf-8").splitlines()) == 1

        # Second run must detect fallback marker and skip re-running Setup-WFTTools.ps1
        cp2 = subprocess.run(
            [str(ro_dir / "WFT.exe"), "--setup-only"],
            cwd=str(ro_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert cp2.returncode == 0
        assert len((appdata_dir / ".env").read_text(encoding="utf-8").splitlines()) == 1
    finally:
        subprocess.run(
            [icacls_exe, str(ro_dir), "/remove:d", trustee],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def test_wft_launcher_py_first_run_bootstrap_and_meipass_resolution(tmp_path, monkeypatch):
    import scripts.wft_launcher as launcher

    # 1. Verify simulated PyInstaller _MEIPASS script resolution
    empty_base = tmp_path / "frozen_base"
    meipass_dir = tmp_path / "meipass_bundle"
    empty_base.mkdir()
    meipass_dir.mkdir()
    bundled_ps1 = meipass_dir / "Setup-WFTTools.ps1"
    bundled_ps1.write_text("exit 0\n", encoding="utf-8")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass_dir), raising=False)
    assert launcher.resolve_setup_script(empty_base) == bundled_ps1.resolve()
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)

    # 2. Subprocess test of wft_launcher.py --setup-only (failure vs success)
    sub_base = tmp_path / "launcher_base"
    sub_app = tmp_path / "launcher_appdata"
    sub_base.mkdir()
    (sub_base / "Setup-WFTTools.ps1").write_text("exit 3\n", encoding="utf-8")

    env = os.environ.copy()
    env["WFT_BASE_DIR"] = str(sub_base)
    env["WFT_APPDATA_DIR"] = str(sub_app)
    env["WFT_HEADLESS"] = "1"

    fail_cp = subprocess.run(
        [sys.executable, str(WFT_LAUNCHER_PY), "--setup-only"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert fail_cp.returncode == 3
    assert not (sub_base / ".wft_setup_done").exists()

    (sub_base / "Setup-WFTTools.ps1").write_text(
        "param([string]$ProjectRoot, [string]$EnvFilePath, [string]$ToolsRootDir)\n"
        "Set-Content -Path $EnvFilePath -Value 'WFT_PORT=8765'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    ok_cp = subprocess.run(
        [sys.executable, str(WFT_LAUNCHER_PY), "--setup-only"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert ok_cp.returncode == 0
    assert (sub_base / ".wft_setup_done").is_file()
    assert (sub_base / ".env").is_file()


def test_wft_launcher_py_import_preserves_cwd_and_browser_profile_isolation_flags(tmp_path, monkeypatch):
    # 1. Verify importing scripts.wft_launcher does NOT mutate os.getcwd()
    outside_cwd = tmp_path / "outside_cwd"
    outside_cwd.mkdir()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(WORKSPACE_ROOT)
    env["WFT_APPDATA_DIR"] = str(tmp_path / "appdata")
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os, pathlib; before = pathlib.Path.cwd().resolve(); "
            "import scripts.wft_launcher; after = pathlib.Path.cwd().resolve(); "
            "assert before == after, f'{before} != {after}'; print('CWD_OK')",
        ],
        cwd=str(outside_cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert probe.returncode == 0 and "CWD_OK" in probe.stdout, f"{probe.stdout}\n{probe.stderr}"

    # 2. Verify isolated --user-data-dir and anti-delegation browser flags
    import scripts.wft_launcher as launcher

    custom_profile = tmp_path / "custom_browser_profile"
    monkeypatch.setenv("WFT_BROWSER_PROFILE_DIR", str(custom_profile))
    flags = launcher.build_browser_app_args("http://127.0.0.1:8765")
    assert "--app=http://127.0.0.1:8765" in flags
    assert f"--user-data-dir={str(custom_profile.resolve())}" in flags
    assert "--no-first-run" in flags
    assert "--no-default-browser-check" in flags
    assert "--disable-background-mode" in flags
    assert "--no-service-autorun" in flags
    assert any("msEdgeStartupBoost" in f for f in flags)


def test_build_standalone_pyinstaller_command_completeness():
    from scripts.build_standalone import build_pyinstaller_cmd

    cmd = build_pyinstaller_cmd(WORKSPACE_ROOT)
    joined = "\n".join(cmd)

    assert "Setup-WFTTools.ps1" in joined
    assert "WFTPicker.cs" in joined
    assert ".env.example" in joined
    assert "frontend/dist" in joined
    assert "rules" in joined
    assert "assets" in joined

    required_hidden = [
        "dotenv",
        "multipart",
        "yara_x",
        "rapidocr_onnxruntime",
        "onnxruntime",
        "pefile",
        "PIL",
        "pyhindsight",
        "regipy",
        "Evtx",
        "Registry",
        "dissect.target",
        "dissect.thumbcache",
        "dissect.esedb",
        "pandas",
        "fitz",
        "docx",
        "openpyxl",
        "pptx",
        "olefile",
        "extract_msg",
        "pypff",
        "py7zr",
        "rarfile",
        "win32com.client",
        "pyvshadow",
    ]
    for mod in required_hidden:
        assert f"--hidden-import={mod}" in cmd, f"Missing --hidden-import={mod} in build_standalone.py"


# ==============================================================================
# 4. backend.config & backend.security Unit Tests
# ==============================================================================
def test_config_sumecmd_and_get_tool_paths_alias(isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs):
    cfg = isolated_config_env["cfg"]

    assert "SumECmd.exe" in cfg.ALL_18_FORENSIC_TOOLS
    assert "bulk_extractor64.exe" in cfg.ALL_18_FORENSIC_TOOLS
    assert len(cfg.ALL_18_FORENSIC_TOOLS) == 20
    assert cfg.TOOL_EXE_TO_ENV_VAR.get("sumecmd.exe") == "WFT_EZ_SUMECMD_EXE"
    assert cfg.TOOL_EXE_TO_ENV_VAR.get("bulk_extractor64.exe") == "WFT_BULK_EXTRACTOR_EXE"
    assert cfg.TOOL_EXE_TO_ENV_VAR.get("bulk_extractor.exe") == "WFT_BULK_EXTRACTOR_EXE"
    assert cfg.get_tool_paths is cfg.get_tool_paths_status

    # Verify nested net/<Tool>/PECmd.exe marks ez_tools FOUND
    nested_ez = tmp_path / "ez_root"
    (nested_ez / "net" / "PECmd").mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["generic"], nested_ez / "net" / "PECmd" / "PECmd.exe")
    monkeypatch.setenv("WFT_EZTOOLS_DIR", str(nested_ez))

    status_a = cfg.get_tool_paths()
    status_b = cfg.get_tool_paths_status()
    assert status_a == status_b
    assert status_a["ez_tools"]["status"] == "FOUND"
    assert status_a["ez_pecmd"]["status"] == "FOUND"


def test_config_tool_paths_file_isolation_and_env_precedence(
    isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs
):
    cfg = isolated_config_env["cfg"]
    tp_file = isolated_config_env["tp_file"]
    env_file = isolated_config_env["env_file"]

    real_appdata_tp = Path(os.environ.get("LOCALAPPDATA", "")) / "WFT" / "tool_paths.json"
    real_before = real_appdata_tp.read_bytes() if real_appdata_tp.is_file() else None

    valid_pecmd = tmp_path / "valid_ez" / "PECmd.exe"
    valid_pecmd.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled_pe_stubs["generic"], valid_pecmd)

    stale_pecmd = tmp_path / "deleted_folder" / "PECmd.exe"
    tp_file.write_text(json.dumps({"WFT_EZ_PECMD_EXE": str(stale_pecmd)}), encoding="utf-8")

    # 1. Explicit os.environ / .env must win over stale tool_paths.json
    env_file.write_text(f"WFT_EZ_PECMD_EXE={valid_pecmd}\n", encoding="utf-8")
    cfg.reload_dotenv(env_file=env_file, override=True)

    assert cfg.find_ez_binary("PECmd.exe") == valid_pecmd.resolve()
    persisted = json.loads(tp_file.read_text(encoding="utf-8"))
    assert Path(persisted["WFT_EZ_PECMD_EXE"]).resolve() == valid_pecmd.resolve()

    # 2. Verify real %LOCALAPPDATA%\WFT\tool_paths.json was completely untouched
    real_after = real_appdata_tp.read_bytes() if real_appdata_tp.is_file() else None
    assert real_before == real_after


def test_config_find_ez_file_resolves_adjacent_to_individual_binaries(
    isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs
):
    cfg = isolated_config_env["cfg"]

    empty_ez_dir = tmp_path / "empty_ez"
    empty_ez_dir.mkdir()
    monkeypatch.setenv("WFT_EZTOOLS_DIR", str(empty_ez_dir))

    recmd_dir = tmp_path / "standalone_recmd"
    (recmd_dir / "BatchExamples").mkdir(parents=True)
    shutil.copy2(compiled_pe_stubs["generic"], recmd_dir / "RECmd.exe")
    reb_file = recmd_dir / "BatchExamples" / "Kroll_Batch.reb"
    reb_file.write_text("Description: Kroll\n", encoding="utf-8")
    monkeypatch.setenv("WFT_EZ_RECMD_EXE", str(recmd_dir / "RECmd.exe"))

    sqle_dir = tmp_path / "standalone_sqle"
    (sqle_dir / "Maps").mkdir(parents=True)
    shutil.copy2(compiled_pe_stubs["generic"], sqle_dir / "SQLECmd.exe")
    smap_file = sqle_dir / "Maps" / "Custom_Target.smap"
    smap_file.write_text("Description: SQLite Map\n", encoding="utf-8")
    monkeypatch.setenv("WFT_EZ_SQLECMD_EXE", str(sqle_dir / "SQLECmd.exe"))

    assert cfg.find_ez_file("Kroll_Batch.reb") == reb_file.resolve()
    assert cfg.find_ez_file("Custom_Target.smap") == smap_file.resolve()
    assert cfg.find_ez_file("*.smap") == smap_file.resolve()
    assert cfg.find_ez_file("Maps") == (sqle_dir / "Maps").resolve()
    assert cfg.find_ez_file("missing_file_xyz.reb", raise_if_missing=False) is None
    with pytest.raises(FileNotFoundError):
        cfg.find_ez_file("missing_file_xyz.reb", raise_if_missing=True)


def test_config_rejects_legacy_autopsy_regripper_v28(
    isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs
):
    cfg = isolated_config_env["cfg"]

    decoy_dir = tmp_path / "autopsy_rr"
    (decoy_dir / "plugins").mkdir(parents=True)
    decoy_rip = decoy_dir / "rip.exe"
    shutil.copy2(compiled_pe_stubs["rip_v28"], decoy_rip)
    (decoy_dir / "plugins" / "ntuser.pl").write_text("# v2.8 plugin\n", encoding="utf-8")

    valid_dir = tmp_path / "regripper_v4"
    (valid_dir / "plugins").mkdir(parents=True)
    valid_rip = valid_dir / "rip.exe"
    shutil.copy2(compiled_pe_stubs["rip_v40"], valid_rip)
    (valid_dir / "plugins" / "ntuser.pl").write_text("# v4.0 plugin\n", encoding="utf-8")

    assert cfg.validate_regripper_binary(decoy_rip) is False
    assert cfg.validate_regripper_binary(valid_rip) is True

    # Even if WFT_REGRIPPER_EXE points to decoy v2.8 while WFT_REGRIPPER_DIR points to v4.0, v2.8 is rejected
    monkeypatch.setenv("WFT_REGRIPPER_EXE", str(decoy_rip))
    monkeypatch.setenv("WFT_REGRIPPER_DIR", str(valid_dir))
    assert cfg.find_regripper_binary() == valid_rip.resolve()

    found = cfg.find_all_forensic_tools_fast(
        project_root=tmp_path / "empty_proj",
        target_exes=["rip.exe"],
        search_roots=[decoy_dir, valid_dir],
        skip_full_disk_scan=True,
    )
    assert Path(found["rip.exe"]).resolve() == valid_rip.resolve()


def test_security_quote_stripping_bracket_globs_zipbomb_xxe_and_origin(tmp_path):
    from backend.security import (
        ForensicSecurityHeadersMiddleware,
        resolve_sandboxed_case_file,
        safe_extract_zip,
        sanitize_sql_identifier,
        strip_unsafe_xml_entities,
        validate_tool_binary_path,
    )

    # 1. Quote-stripping & UNC/metacharacter blocks
    tool_p = tmp_path / "PECmd.exe"
    tool_p.write_bytes(b"MZ" + b"\x00" * 64)
    assert validate_tool_binary_path(f'  "{tool_p}"  ') == tool_p.resolve()
    with pytest.raises(ValueError):
        validate_tool_binary_path(r"\\evil-server\share\PECmd.exe")
    with pytest.raises(ValueError):
        validate_tool_binary_path(r"\\?\UNC\evil-server\share\PECmd.exe")
    with pytest.raises(ValueError):
        validate_tool_binary_path("C:\\Tools\\PECmd.exe & calc.exe")

    # 2. Sandbox file resolution with [1] glob chars & guest drive paths
    case_dir = tmp_path / "case_sec"
    staging = case_dir / "staging"
    bracket_file = staging / "Cache" / "invoice[1].pdf"
    bracket_file.parent.mkdir(parents=True, exist_ok=True)
    bracket_file.write_bytes(b"%PDF-1.4")

    guest_file = staging / "Users" / "Admin" / "Documents" / "secret.docx"
    guest_file.parent.mkdir(parents=True, exist_ok=True)
    guest_file.write_bytes(b"PK\x03\x04")

    assert resolve_sandboxed_case_file(case_dir, "NonExistentSubdir/invoice[1].pdf") == bracket_file.resolve()
    assert resolve_sandboxed_case_file(case_dir, r"C:\Users\Admin\Documents\secret.docx") == guest_file.resolve()
    with pytest.raises(HTTPException) as exc_info:
        resolve_sandboxed_case_file(case_dir, "../../outside.txt")
    assert exc_info.value.status_code == 403

    # 3. Stream-counted safe_extract_zip & Zip-Slip defense
    slip_buf = io.BytesIO()
    with zipfile.ZipFile(slip_buf, "w") as zf:
        zf.writestr("../escape.txt", "bad")
    slip_buf.seek(0)
    with zipfile.ZipFile(slip_buf, "r") as zf:
        with pytest.raises(PermissionError):
            safe_extract_zip(zf, tmp_path / "zip_out")

    big_buf = io.BytesIO()
    with zipfile.ZipFile(big_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ok.txt", b"A" * 100)
        zf.writestr("too_big.bin", b"B" * 5000)
    big_buf.seek(0)
    with zipfile.ZipFile(big_buf, "r") as zf:
        count = safe_extract_zip(zf, tmp_path / "zip_quota", max_total_bytes=1024)
    assert count == 1
    assert (tmp_path / "zip_quota" / "ok.txt").is_file()
    assert not (tmp_path / "zip_quota" / "too_big.bin").exists()

    # 4. External SYSTEM DTD + internal entity stripping & SQL identifier sanitization
    malicious_xml = '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.example/xxe.dtd"><Task>ok</Task>'
    cleaned_xml = strip_unsafe_xml_entities(malicious_xml)
    assert "DOCTYPE" not in cleaned_xml and "<Task>ok</Task>" in cleaned_xml
    assert sanitize_sql_identifier("123-bad;drop", prefix="9bad") == "tbl_123_bad_drop"

    # 5. Middleware origin validation (testserver allowed; quoted untrusted origin returns valid JSON 403)
    mini_app = FastAPI()
    mini_app.add_middleware(ForensicSecurityHeadersMiddleware)

    @mini_app.post("/ping")
    def _ping():
        return {"ok": True}

    tc = TestClient(mini_app)
    r_ok = tc.post("/ping", headers={"Origin": "http://testserver"})
    assert r_ok.status_code == 200
    assert r_ok.headers["X-Content-Type-Options"] == "nosniff"

    r_bad = tc.post("/ping", headers={"Origin": 'https://attacker.example/path"quote'})
    assert r_bad.status_code == 403
    parsed_err = r_bad.json()
    assert "attacker.example" in parsed_err["detail"]


# ==============================================================================
# 5. Live Workspace .env End-to-End Tool Execution Verification
# ==============================================================================
def test_live_workspace_dotenv_all_integrated_tools_executable(monkeypatch):
    import backend.config as cfg

    live_env_file = WORKSPACE_ROOT / ".env"
    live_marker = WORKSPACE_ROOT / ".wft_setup_done"
    assert live_env_file.is_file(), "Workspace .env must be generated by Setup-WFTTools.ps1 / WFT.exe"
    assert live_marker.is_file(), "Workspace .wft_setup_done must exist after WFT.exe --setup --setup-only"

    env_map = _parse_dotenv_bytes(live_env_file)
    monkeypatch.setenv("WFT_ENV_FILE", str(live_env_file))
    cfg._REGRIPPER_VALIDATION_CACHE.clear()
    cfg.reload_dotenv(env_file=live_env_file, override=True)

    run_env = os.environ.copy()
    run_env["DOTNET_ROLL_FORWARD"] = "Major"
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    # 1. All 16 Eric Zimmerman binaries execute --help cleanly + auxiliary files resolve
    for env_key, exe_name in EZ_16_MAP.items():
        assert env_key in env_map, f"Live workspace .env missing {env_key}"
        resolved_ez = cfg.find_ez_binary(exe_name)
        assert resolved_ez.is_file() and resolved_ez.read_bytes()[:2] == b"MZ"
        cp = subprocess.run(
            [str(resolved_ez), "--help"],
            env=run_env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
            creationflags=creationflags,
        )
        assert cp.returncode == 0, f"{exe_name} --help failed (rc={cp.returncode}): {cp.stdout}\n{cp.stderr}"

    kroll_reb = cfg.find_ez_file("Kroll_Batch.reb")
    assert kroll_reb is not None and kroll_reb.is_file()
    sample_smap = cfg.find_ez_file("*.smap")
    assert sample_smap is not None and sample_smap.is_file()
    maps_dir = cfg.find_ez_file("Maps")
    assert maps_dir is not None and maps_dir.is_dir()
    assert any(maps_dir.rglob("*.smap")), f"Expected SQLECmd *.smap files inside {maps_dir}"

    # 2. RegRipper v4.0 (-a supported + adjacent plugins/*.pl, NOT Autopsy v2.8)
    rip_exe = cfg.find_regripper_binary()
    assert rip_exe.is_file()
    assert any((rip_exe.parent / "plugins").glob("*.pl"))
    rip_cp = subprocess.run(
        [str(rip_exe), "-h"],
        cwd=str(rip_exe.parent),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=15,
        creationflags=creationflags,
    )
    assert rip_cp.returncode == 0
    assert re.search(r"(?m)^\s*-a\b", f"{rip_cp.stdout}\n{rip_cp.stderr}")

    # 3. Hindsight CLI executes --help cleanly
    hs_bin = cfg.find_hindsight_binary()
    assert hs_bin is not None and hs_bin.is_file()
    hs_cmd = [sys.executable, str(hs_bin), "--help"] if hs_bin.suffix.lower() == ".py" else [str(hs_bin), "--help"]
    hs_cp = subprocess.run(
        hs_cmd,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=30,
        creationflags=creationflags,
    )
    assert hs_cp.returncode == 0, f"Hindsight --help failed: {hs_cp.stdout}\n{hs_cp.stderr}"

    # 4. Trellix Stinger PE validation (NEVER invoke --help which opens modal GUI!)
    stinger_bin = cfg.find_stinger_binary()
    assert stinger_bin is not None and stinger_bin.is_file()
    assert stinger_bin.stat().st_size > 1_000_000
    pe = pefile.PE(str(stinger_bin), fast_load=True)
    try:
        assert pe.DOS_HEADER.e_magic == 0x5A4D
    finally:
        pe.close()

    # 5. Open-Source bulk_extractor binary validation (-V exits 0)
    assert "WFT_BULK_EXTRACTOR_EXE" in env_map, "Live workspace .env missing WFT_BULK_EXTRACTOR_EXE"
    bulk_bin = cfg.find_bulk_extractor_binary()
    assert bulk_bin is not None and bulk_bin.is_file()
    assert bulk_bin.stat().st_size > 1_000_000
    assert bulk_bin.read_bytes()[:2] == b"MZ"
    bulk_cp = subprocess.run(
        [str(bulk_bin), "-V"],
        cwd=str(bulk_bin.parent),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=15,
        creationflags=creationflags,
    )
    assert bulk_cp.returncode == 0, f"bulk_extractor -V failed: {bulk_cp.stdout}\n{bulk_cp.stderr}"

    # 6. Compiled native file/folder dialog helper (tools\wft_picker.exe --test)
    picker_exe = WORKSPACE_ROOT / "tools" / "wft_picker.exe"
    assert picker_exe.is_file()
    picker_cp = subprocess.run(
        [str(picker_exe), "--test"],
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=creationflags,
    )
    assert picker_cp.returncode == 0 and "WFT_PICKER_OK" in picker_cp.stdout


def test_setup_tools_py_cli_json_and_readonly_inspection():
    setup_py = WORKSPACE_ROOT / "scripts" / "setup_tools.py"
    cp = subprocess.run(
        [sys.executable, str(setup_py), "--json", "--no-write"],
        cwd=str(WORKSPACE_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert cp.returncode == 0, f"{cp.stdout}\n{cp.stderr}"
    payload = json.loads(cp.stdout)
    assert payload["yara_rule_files"] >= 1
    tools = payload["tools"]
    assert tools["ez_tools"]["status"] == "FOUND"
    assert tools["regripper"]["status"] == "FOUND"
    assert tools["hindsight"]["status"] == "FOUND"
    assert tools["stinger"]["status"] == "FOUND"
    assert tools["bulk_extractor"]["status"] == "FOUND"
    for ez_key in (
        "ez_rla", "ez_pecmd", "ez_mftecmd", "ez_evtxecmd", "ez_recmd", "ez_lecmd",
        "ez_jlecmd", "ez_amcache", "ez_shimcache", "ez_sbecmd", "ez_srumecmd",
        "ez_wxtcmd", "ez_sqlecmd", "ez_rbcmd", "ez_recentfilecache", "ez_sumecmd",
    ):
        assert tools[ez_key]["status"] == "FOUND", f"Expected {ez_key} FOUND in setup_tools.py --json"


# ==============================================================================
# 6. Iteration 2 Remediation & Scope Delta Regression Tests
# ==============================================================================
def test_config_find_ez_file_maps_sibling_collision_and_bounded_grandparent(
    isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs
):
    cfg = isolated_config_env["cfg"]

    # Simulate KAPE Modules\bin layout where EvtxECmd\Maps has .map and SQLECmd\Maps has .smap
    kape_bin = tmp_path / "Downloads" / "kape" / "KAPE" / "Modules" / "bin"
    evtx_dir = kape_bin / "EvtxECmd"
    recmd_dir = kape_bin / "RECmd"
    sqle_dir = kape_bin / "SQLECmd"
    (evtx_dir / "Maps").mkdir(parents=True)
    (recmd_dir / "BatchExamples").mkdir(parents=True)
    (sqle_dir / "Maps").mkdir(parents=True)

    shutil.copy2(compiled_pe_stubs["generic"], evtx_dir / "EvtxECmd.exe")
    shutil.copy2(compiled_pe_stubs["generic"], recmd_dir / "RECmd.exe")
    shutil.copy2(compiled_pe_stubs["generic"], sqle_dir / "SQLECmd.exe")

    (evtx_dir / "Maps" / "0001_Evtx.map").write_text("Description: Evtx Map\n", encoding="utf-8")
    (recmd_dir / "BatchExamples" / "Kroll_Batch.reb").write_text("Description: Batch\n", encoding="utf-8")
    (sqle_dir / "Maps" / "Windows_History.smap").write_text("Description: SQLite Map\n", encoding="utf-8")

    # Place an unrelated decoy file in unbounded grandparent Downloads\unrelated\decoy.reb
    unrelated_dir = tmp_path / "Downloads" / "unrelated_archive"
    unrelated_dir.mkdir(parents=True)
    (unrelated_dir / "unbounded_decoy.reb").write_text("Decoy\n", encoding="utf-8")

    standalone_mft = tmp_path / "Downloads" / "MFTECmd_Standalone"
    standalone_mft.mkdir(parents=True)
    shutil.copy2(compiled_pe_stubs["generic"], standalone_mft / "MFTECmd.exe")

    monkeypatch.setenv("WFT_EZ_EVTXECMD_EXE", str(evtx_dir / "EvtxECmd.exe"))
    monkeypatch.setenv("WFT_EZ_RECMD_EXE", str(recmd_dir / "RECmd.exe"))
    monkeypatch.setenv("WFT_EZ_SQLECMD_EXE", str(sqle_dir / "SQLECmd.exe"))
    monkeypatch.setenv("WFT_EZ_MFTECMD_EXE", str(standalone_mft / "MFTECmd.exe"))

    resolved_maps = cfg.find_ez_file("Maps")
    assert resolved_maps == (sqle_dir / "Maps").resolve()
    assert any(resolved_maps.rglob("*.smap"))

    # Unbounded grandparent Downloads/ must NOT be walked when parent.parent is not EZTools/ez_tools/net
    assert cfg.find_ez_file("unbounded_decoy.reb", raise_if_missing=False) is None


def test_config_rejects_non_pe_ez_binaries_and_prunes_stale_rip_v28_in_tool_paths_json(
    isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs
):
    cfg = isolated_config_env["cfg"]
    tp_file = isolated_config_env["tp_file"]
    env_file = isolated_config_env["env_file"]
    isolated_base = tmp_path / "isolated_base"
    isolated_base.mkdir(parents=True)
    monkeypatch.setattr(cfg, "BASE_DIR", isolated_base)

    # 1. HTML error page masquerading as PECmd.exe must be rejected by find_ez_binary & get_tool_paths_status
    html_ez_dir = tmp_path / "html_ez"
    html_pecmd = html_ez_dir / "PECmd.exe"
    html_pecmd.parent.mkdir(parents=True)
    html_pecmd.write_bytes(b"<html><body>404 Not Found - Error Page Padding Exceeding 64 Bytes</body></html>")

    monkeypatch.setenv("WFT_EZ_PECMD_EXE", str(html_pecmd))
    monkeypatch.setenv("WFT_EZTOOLS_DIR", str(html_ez_dir))
    with pytest.raises(FileNotFoundError):
        cfg.find_ez_binary("PECmd.exe")

    status_bad = cfg.get_tool_paths_status()
    assert status_bad["ez_pecmd"]["status"] == "MISSING"
    assert status_bad["ez_pecmd"]["resolved_path"] is None
    assert status_bad["ez_pecmd"]["path"] == ""
    assert status_bad["ez_tools"]["status"] == "MISSING"

    # Also verify 0-byte PECmd.exe in WFT_EZTOOLS_DIR marks ez_tools MISSING
    zero_ez_dir = tmp_path / "zero_ez"
    zero_ez_dir.mkdir(parents=True)
    (zero_ez_dir / "PECmd.exe").write_bytes(b"")
    monkeypatch.delenv("WFT_EZ_PECMD_EXE", raising=False)
    monkeypatch.setenv("WFT_EZTOOLS_DIR", str(zero_ez_dir))
    assert cfg.get_tool_paths_status()["ez_tools"]["status"] == "MISSING"

    # 2. Stale Autopsy rip.exe v2.8 in tool_paths.json must be pruned when .env sets WFT_REGRIPPER_DIR to v4.0
    decoy_rr = tmp_path / "autopsy_v28"
    (decoy_rr / "plugins").mkdir(parents=True)
    decoy_rip = decoy_rr / "rip.exe"
    shutil.copy2(compiled_pe_stubs["rip_v28"], decoy_rip)
    (decoy_rr / "plugins" / "sam.pl").write_text("# v2.8\n", encoding="utf-8")

    valid_rr = tmp_path / "regripper_v40"
    (valid_rr / "plugins").mkdir(parents=True)
    valid_rip = valid_rr / "rip.exe"
    shutil.copy2(compiled_pe_stubs["rip_v40"], valid_rip)
    (valid_rr / "plugins" / "sam.pl").write_text("# v4.0\n", encoding="utf-8")

    tp_file.write_text(
        json.dumps(
            {
                "WFT_REGRIPPER_EXE": str(decoy_rip),
                "WFT_EZ_PECMD_EXE": str(html_pecmd),
            }
        ),
        encoding="utf-8",
    )
    env_file.write_text(f"WFT_REGRIPPER_DIR={valid_rr}\n", encoding="utf-8")
    cfg._REGRIPPER_VALIDATION_CACHE.clear()
    cfg.reload_dotenv(env_file=env_file, override=True)

    assert "WFT_REGRIPPER_EXE" not in cfg._CUSTOM_TOOL_PATHS
    assert "WFT_EZ_PECMD_EXE" not in cfg._CUSTOM_TOOL_PATHS
    persisted_after = json.loads(tp_file.read_text(encoding="utf-8"))
    assert "WFT_REGRIPPER_EXE" not in persisted_after
    assert "WFT_EZ_PECMD_EXE" not in persisted_after

    st_rr = cfg.get_tool_paths_status()["regripper"]
    assert st_rr["status"] == "FOUND"
    assert Path(st_rr["path"]).resolve() == valid_rip.resolve()
    assert Path(st_rr["configured_path"]).resolve() == valid_rip.resolve()


def test_ps1_purges_corrupt_html_downloads_prunes_stale_env_keys_and_ignores_decoy_eztools(
    tmp_path, compiled_pe_stubs
):
    # 1. Verify 0-byte/HTML decoy in proj_root\EZTools does NOT clobber WFT_EZTOOLS_DIR in Branch 1
    proj_decoy = tmp_path / "proj_decoy_ez"
    (proj_decoy / "EZTools").mkdir(parents=True)
    (proj_decoy / "EZTools" / "PECmd.exe").write_bytes(b"")
    (proj_decoy / "EZTools" / "LECmd.exe").write_bytes(b"<html>404 Not Found Decoy Over Sixty Four Bytes Long........</html>")

    pre_root = tmp_path / "valid_pre"
    pre_ez = pre_root / "EZTools"
    _populate_ez_suite_dir(pre_ez, compiled_pe_stubs["generic"])
    (pre_root / "RegRipper4.0" / "plugins").mkdir(parents=True)
    shutil.copy2(compiled_pe_stubs["rip_v40"], pre_root / "RegRipper4.0" / "rip.exe")
    (pre_root / "RegRipper4.0" / "plugins" / "sam.pl").write_text("# sam\n", encoding="utf-8")
    shutil.copy2(compiled_pe_stubs["generic"], pre_root / "hindsight.exe")
    shutil.copy2(compiled_pe_stubs["stinger"], pre_root / "stinger64.exe")
    shutil.copy2(compiled_pe_stubs["bulk_extractor"], pre_root / "bulk_extractor64.exe")

    cp1 = _run_powershell_inline(
        f"""
        & '{SETUP_PS1}' `
          -ProjectRoot '{proj_decoy}' `
          -SearchRoots @('{pre_root}') `
          -SkipFullDiskScan `
          -ToolUrlOverrides @{{
              EZBaseUrl      = 'http://127.0.0.1:1/dead';
              RegRipper      = 'http://127.0.0.1:1/dead.zip';
              Hindsight      = 'http://127.0.0.1:1/dead.exe';
              Stinger        = 'http://127.0.0.1:1/dead.exe';
              bulk_extractor = 'http://127.0.0.1:1/dead.exe'
          }}
        exit $LASTEXITCODE
        """
    )
    assert cp1.returncode == 0
    env1 = _parse_dotenv_bytes(proj_decoy / ".env")
    assert Path(env1["WFT_EZTOOLS_DIR"]).resolve() == pre_ez.resolve()

    # 2. Verify corrupt HTML .zip / .exe downloads are purged from tools\ and stale .env keys are pruned
    corrupt_mirror = tmp_path / "corrupt_mirror"
    (corrupt_mirror / "ez").mkdir(parents=True)
    html_payload = b"<html><body>502 Bad Gateway Captive Portal Error Page Exceeding 128 Bytes.................</body></html>"
    for exe_name in EZ_16_MAP.values():
        base = Path(exe_name).stem
        with zipfile.ZipFile(corrupt_mirror / "ez" / f"{base}.zip", "w") as zf:
            zf.writestr(exe_name, html_payload)
    with zipfile.ZipFile(corrupt_mirror / "stinger.zip", "w") as zf:
        zf.writestr("stinger64.exe", html_payload)
    with zipfile.ZipFile(corrupt_mirror / "regripper.zip", "w") as zf:
        zf.writestr("rip.exe", html_payload)
    (corrupt_mirror / "hindsight.exe").write_bytes(html_payload)
    (corrupt_mirror / "bulk_extractor64.exe").write_bytes(html_payload)

    proj_corrupt = tmp_path / "proj_corrupt"
    proj_corrupt.mkdir(parents=True)
    # Pre-seed stale/invalid keys in .env to prove Remove-WFTEnvVar prunes them
    (proj_corrupt / ".env").write_text(
        "WFT_PORT=8765\n"
        f"WFT_EZ_PECMD_EXE={proj_corrupt / 'stale_pecmd.exe'}\n"
        f"WFT_STINGER_EXE={proj_corrupt / 'stale_stinger.exe'}\n"
        f"WFT_REGRIPPER_EXE={proj_corrupt / 'stale_rip.exe'}\n"
        f"WFT_HINDSIGHT_EXE={proj_corrupt / 'stale_hs.exe'}\n"
        f"WFT_BULK_EXTRACTOR_EXE={proj_corrupt / 'stale_be.exe'}\n",
        encoding="utf-8",
    )
    empty_search = tmp_path / "empty_s"
    empty_search.mkdir()

    with _LocalArtifactServer(corrupt_mirror) as srv:
        cp2 = _run_powershell_inline(
            f"""
            & '{SETUP_PS1}' `
              -ProjectRoot '{proj_corrupt}' `
              -SearchRoots @('{empty_search}') `
              -SkipFullDiskScan `
              -ForceUpdate `
              -ToolUrlOverrides @{{
                  EZBaseUrl      = '{srv.base_url}/ez';
                  RegRipper      = '{srv.base_url}/regripper.zip';
                  Hindsight      = '{srv.base_url}/hindsight.exe';
                  Stinger        = '{srv.base_url}/stinger.zip';
                  bulk_extractor = '{srv.base_url}/bulk_extractor64.exe'
              }}
            exit $LASTEXITCODE
            """
        )
    assert cp2.returncode == 0

    tools_sub = proj_corrupt / "tools"
    leftover_exes = [
        p for p in tools_sub.rglob("*.exe") if p.name.lower() != "wft_picker.exe"
    ]
    assert leftover_exes == [], f"Expected all corrupt non-PE .exe files purged, found: {leftover_exes}"

    env2 = _parse_dotenv_bytes(proj_corrupt / ".env")
    assert env2.get("WFT_PORT") == "8765"
    for pruned_key in (
        "WFT_EZ_PECMD_EXE",
        "WFT_EZTOOLS_DIR",
        "WFT_STINGER_EXE",
        "WFT_REGRIPPER_EXE",
        "WFT_REGRIPPER_DIR",
        "WFT_HINDSIGHT_EXE",
        "WFT_BULK_EXTRACTOR_EXE",
    ):
        assert pruned_key not in env2, f"Expected stale {pruned_key} to be pruned from .env"


def test_security_mixed_slash_unc_staging_escape_and_dtd_whitespace(tmp_path, monkeypatch):
    import xml.etree.ElementTree as ET
    from backend.security import (
        resolve_sandboxed_case_file,
        strip_unsafe_xml_entities,
        validate_tool_binary_path,
    )

    # 1. Mixed-slash UNC paths must be blocked by validate_tool_binary_path
    for mixed_unc in (
        r"\/127.0.0.1\share\PECmd.exe",
        r"/\127.0.0.1/share/PECmd.exe",
        r"//127.0.0.1/share/PECmd.exe",
        r"\\.\GLOBALROOT\Device\HarddiskVolume1\PECmd.exe",
    ):
        with pytest.raises(ValueError):
            validate_tool_binary_path(mixed_unc)

    # 2. resolve_sandboxed_case_file: block '../case.duckdb', '../processing.log', direct case.duckdb, and UNC without calling Path.resolve()
    case_dir = tmp_path / "case_alpha"
    staging = case_dir / "staging"
    reports = case_dir / "reports"
    staging.mkdir(parents=True)
    reports.mkdir(parents=True)

    (case_dir / "case.duckdb").write_bytes(b"DUCKDB_SECRET")
    (case_dir / "case.duckdb.wal").write_bytes(b"DUCKDB_WAL")
    (case_dir / "processing.log").write_text("internal log", encoding="utf-8")
    recycle_doc = staging / "$Recycle.Bin" / "S-1-5-21-1000" / "$R12345.docx"
    recycle_doc.parent.mkdir(parents=True)
    recycle_doc.write_bytes(b"PK\x03\x04")
    report_pdf = reports / "summary.pdf"
    report_pdf.write_bytes(b"%PDF-1.4")

    for forbidden_rel in (
        "../case.duckdb",
        r"..\case.duckdb",
        "../processing.log",
        "sub/../../case.duckdb",
        str(case_dir / "case.duckdb"),
        str(case_dir / "case.duckdb.wal"),
        str(case_dir / "processing.log"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            resolve_sandboxed_case_file(case_dir, forbidden_rel)
        assert exc_info.value.status_code == 403, f"Expected 403 for {forbidden_rel}"

    # Verify UNC paths are rejected BEFORE Path.resolve() touches SMB/WebDAV
    orig_resolve = Path.resolve

    def _guarded_resolve(self, *args, **kwargs):
        s = str(self)
        if "198.51.100.99" in s:
            raise AssertionError(f"Path.resolve() must NEVER be called on UNC path: {s}")
        return orig_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _guarded_resolve)
    for unc_input in (
        r"\\198.51.100.99\share\secret.txt",
        r"//198.51.100.99/share/secret.txt",
        r"\/198.51.100.99\share\secret.txt",
    ):
        with pytest.raises(HTTPException) as unc_exc:
            resolve_sandboxed_case_file(case_dir, unc_input)
        assert unc_exc.value.status_code == 403

    # Legitimate $Recycle.Bin evidence and reports/ file still resolve cleanly; bare "$Recycle.Bin" dir returns 404, empty/null returns 400
    assert resolve_sandboxed_case_file(case_dir, r"$Recycle.Bin\S-1-5-21-1000\$R12345.docx") == recycle_doc.resolve()
    assert resolve_sandboxed_case_file(case_dir, str(report_pdf)) == report_pdf.resolve()
    with pytest.raises(HTTPException) as bare_exc:
        resolve_sandboxed_case_file(case_dir, "$Recycle.Bin")
    assert bare_exc.value.status_code == 404
    with pytest.raises(HTTPException) as empty_exc:
        resolve_sandboxed_case_file(case_dir, "   ")
    assert empty_exc.value.status_code == 400

    # 3. strip_unsafe_xml_entities handles whitespace between ']' and '>' in internal DTD subset
    xml_with_ws = '<?xml version="1.0"?>\n<!DOCTYPE Task [\n  <!ENTITY xxe "secret">\n]   >\n<Task><Command>cmd.exe</Command></Task>'
    cleaned = strip_unsafe_xml_entities(xml_with_ws)
    assert "DOCTYPE" not in cleaned and "ENTITY" not in cleaned
    root = ET.fromstring(cleaned)
    assert root.tag == "Task" and root.findtext("Command") == "cmd.exe"


def test_wft_launcher_rejects_zero_byte_dotenv_on_exit_zero(tmp_path, monkeypatch):
    import scripts.wft_launcher as launcher

    base_dir = tmp_path / "zero_env_base"
    appdata_dir = tmp_path / "zero_env_appdata"
    base_dir.mkdir()
    appdata_dir.mkdir()
    monkeypatch.setenv("WFT_APPDATA_DIR", str(appdata_dir))

    # Bootstrap script creates a 0-byte .env and exits 0 (simulating completely offline/failed tool setup)
    (base_dir / "Setup-WFTTools.ps1").write_text(
        "param([string]$ProjectRoot, [string]$EnvFilePath, [string]$ToolsRootDir)\n"
        "[System.IO.File]::WriteAllText($EnvFilePath, '')\n"
        "exit 0\n",
        encoding="utf-8",
    )

    ok, rc = launcher.ensure_first_run_bootstrap(base_dir=base_dir, force=False)
    assert ok is False and rc == 1
    assert not (base_dir / ".wft_setup_done").exists()
    assert not (appdata_dir / ".wft_setup_done").exists()


def test_pyvshadow_import_and_bulk_extractor_config_and_zip_override(
    isolated_config_env, tmp_path, monkeypatch, compiled_pe_stubs
):
    import pyvshadow  # Must import cleanly from host Python 3.11

    assert hasattr(pyvshadow, "volume") or hasattr(pyvshadow, "get_version")

    cfg = isolated_config_env["cfg"]
    tp_file = isolated_config_env["tp_file"]
    env_file = isolated_config_env["env_file"]

    # 1. Verify non-PE decoy is rejected and .env wins over stale tool_paths.json for WFT_BULK_EXTRACTOR_EXE
    bad_be = tmp_path / "bad_be" / "bulk_extractor64.exe"
    bad_be.parent.mkdir(parents=True)
    bad_be.write_bytes(b"<html>404 Not Found</html>")

    valid_be = tmp_path / "good_be" / "bulk_extractor64.exe"
    valid_be.parent.mkdir(parents=True)
    shutil.copy2(compiled_pe_stubs["bulk_extractor"], valid_be)

    tp_file.write_text(json.dumps({"WFT_BULK_EXTRACTOR_EXE": str(bad_be)}), encoding="utf-8")
    env_file.write_text(f"WFT_BULK_EXTRACTOR_EXE={valid_be}\n", encoding="utf-8")
    cfg.reload_dotenv(env_file=env_file, override=True)

    assert cfg.find_bulk_extractor_binary() == valid_be.resolve()
    be_status = cfg.get_tool_paths_status()["bulk_extractor"]
    assert be_status["status"] == "FOUND"
    assert Path(be_status["path"]).resolve() == valid_be.resolve()

    # 2. Verify Setup-WFTTools.ps1 also supports .zip archive overrides for bulk_extractor
    zip_mirror = tmp_path / "be_zip_mirror"
    zip_mirror.mkdir()
    with zipfile.ZipFile(zip_mirror / "bulk_extractor.zip", "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(compiled_pe_stubs["bulk_extractor"], arcname="win64/bulk_extractor64.exe")

    proj_be_zip = tmp_path / "proj_be_zip"
    empty_s = tmp_path / "empty_be_s"
    empty_s.mkdir()
    with _LocalArtifactServer(zip_mirror) as srv:
        cp = _run_powershell_inline(
            f"""
            & '{SETUP_PS1}' `
              -ProjectRoot '{proj_be_zip}' `
              -SearchRoots @('{empty_s}') `
              -SkipFullDiskScan `
              -ToolUrlOverrides @{{
                  EZBaseUrl      = 'http://127.0.0.1:1/dead';
                  RegRipper      = 'http://127.0.0.1:1/dead.zip';
                  Hindsight      = 'http://127.0.0.1:1/dead.exe';
                  Stinger        = 'http://127.0.0.1:1/dead.exe';
                  bulk_extractor = '{srv.base_url}/bulk_extractor.zip'
              }}
            exit $LASTEXITCODE
            """
        )
    assert cp.returncode == 0
    be_env = _parse_dotenv_bytes(proj_be_zip / ".env")
    assert Path(be_env["WFT_BULK_EXTRACTOR_EXE"]).is_file()

