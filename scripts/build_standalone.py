"""
WFT - Automated Standalone Executable Builder
Compiles the complete WFT workstation (Python runtime, DuckDB, FastAPI backend,
pre-compiled React frontend SPA, and detection rules) into a single standalone WFT.exe.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def build():
    os.chdir(ROOT_DIR)
    print(f"[Build] Starting standalone WFT.exe packaging from: {ROOT_DIR}")

    # 1. Verify frontend dist exists
    dist_dir = ROOT_DIR / "frontend" / "dist"
    if not dist_dir.exists() or not (dist_dir / "index.html").exists():
        print("[Build] Warning: frontend/dist not found. Building frontend...")
        npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
        if npm_bin:
            subprocess.run([npm_bin, "run", "build"], cwd=str(ROOT_DIR / "frontend"), check=True)
        else:
            raise FileNotFoundError("frontend/dist is missing and npm was not found to build it.")

    # 2. Prepare PyInstaller command
    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--noconsole",
        f"--distpath={ROOT_DIR / 'dist'}",
        "--name=WFT",
        f"--icon={ROOT_DIR / 'assets' / 'wft.ico'}",
        f"--add-data={ROOT_DIR / 'frontend' / 'dist'};frontend/dist",
        f"--add-data={ROOT_DIR / 'rules'};rules",
        f"--add-data={ROOT_DIR / 'assets'};assets",
        "--collect-all=fastapi",
        "--collect-all=uvicorn",
        "--collect-all=starlette",
        "--collect-all=duckdb",
        "--collect-all=pydantic",
        "--collect-all=pydantic_core",
        "--collect-all=anyio",
        "--collect-all=dissect",
        "--collect-submodules=backend",
        "--hidden-import=uvicorn.logging",
        "--hidden-import=uvicorn.loops",
        "--hidden-import=uvicorn.loops.auto",
        "--hidden-import=uvicorn.protocols",
        "--hidden-import=uvicorn.protocols.http",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.protocols.websockets",
        "--hidden-import=uvicorn.protocols.websockets.auto",
        "--hidden-import=uvicorn.lifespan",
        "--hidden-import=uvicorn.lifespan.on",
        str(ROOT_DIR / "scripts" / "wft_launcher.py"),
    ]

    print("[Build] Running PyInstaller...")
    subprocess.run(pyinstaller_cmd, check=True)

    out_exe = ROOT_DIR / "dist" / "WFT.exe"
    if out_exe.exists():
        size_mb = round(out_exe.stat().st_size / (1024 * 1024), 2)
        print(f"\n[Build] SUCCESS! Standalone executable created: {out_exe} ({size_mb} MB)")
        return out_exe
    else:
        raise FileNotFoundError("PyInstaller completed but dist/WFT.exe was not found.")

if __name__ == "__main__":
    build()
