"""
WFT - Automated Standalone Executable Builder
Compiles the complete WFT workstation (Python runtime, DuckDB, FastAPI backend,
pre-compiled React frontend SPA, detection rules, and first-run PowerShell bootstrap)
into a single standalone WFT.exe.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List

ROOT_DIR = Path(__file__).resolve().parent.parent


def _has_spec(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False


def build_pyinstaller_cmd(root_dir: Path = ROOT_DIR) -> List[str]:
    sep = os.pathsep
    cmd: List[str] = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--noconsole",
        f"--distpath={root_dir / 'dist'}",
        "--name=WFT",
        f"--icon={root_dir / 'assets' / 'wft.ico'}",
        f"--add-data={root_dir / 'frontend' / 'dist'}{sep}frontend/dist",
        f"--add-data={root_dir / 'rules'}{sep}rules",
        f"--add-data={root_dir / 'assets'}{sep}assets",
        f"--add-data={root_dir / 'Setup-WFTTools.ps1'}{sep}.",
        f"--add-data={root_dir / 'scripts' / 'WFTPicker.cs'}{sep}scripts",
        f"--add-data={root_dir / '.env.example'}{sep}.",
        "--collect-all=fastapi",
        "--collect-all=uvicorn",
        "--collect-all=starlette",
        "--collect-all=duckdb",
        "--collect-all=pydantic",
        "--collect-all=pydantic_core",
        "--collect-all=anyio",
        "--collect-all=dissect",
        "--collect-submodules=backend",
    ]

    for pkg in ("rapidocr_onnxruntime", "pyhindsight", "pyvshadow"):
        if _has_spec(pkg):
            cmd.append(f"--collect-all={pkg}")

    for submod_pkg in ("regipy", "dissect.target", "dissect.thumbcache", "dissect.esedb", "dissect.util"):
        if _has_spec(submod_pkg):
            cmd.append(f"--collect-submodules={submod_pkg}")

    for bin_pkg in ("yara_x", "onnxruntime"):
        if _has_spec(bin_pkg):
            cmd.append(f"--collect-binaries={bin_pkg}")

    for data_pkg in ("docx", "pptx"):
        if _has_spec(data_pkg):
            cmd.append(f"--collect-data={data_pkg}")

    hidden_imports = [
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "dotenv",
        "multipart",
        "python_multipart",
        "yara_x",
        "rapidocr_onnxruntime",
        "onnxruntime",
        "cv2",
        "pefile",
        "PIL",
        "PIL.Image",
        "PIL.ExifTags",
        "pyhindsight",
        "regipy",
        "Evtx",
        "Evtx.Evtx",
        "Evtx.Views",
        "Registry",
        "dissect.target",
        "dissect.ntfs",
        "dissect.thumbcache",
        "dissect.esedb",
        "dissect.util",
        "pytsk3",
        "pandas",
        "fitz",
        "pymupdf",
        "docx",
        "openpyxl",
        "pptx",
        "olefile",
        "extract_msg",
        "pypff",
        "pyvshadow",
        "cramjam",
        "py7zr",
        "rarfile",
        "win32com.client",
        "pythoncom",
        "pywintypes",
    ]
    for hi in hidden_imports:
        cmd.append(f"--hidden-import={hi}")

    cmd.append(str(root_dir / "scripts" / "wft_launcher.py"))
    return cmd


def build() -> Path:
    os.chdir(ROOT_DIR)
    print(f"[Build] Starting standalone WFT.exe packaging from: {ROOT_DIR}")

    dist_dir = ROOT_DIR / "frontend" / "dist"
    if not dist_dir.exists() or not (dist_dir / "index.html").exists():
        print("[Build] Warning: frontend/dist not found. Building frontend...")
        npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
        if npm_bin:
            subprocess.run([npm_bin, "run", "build"], cwd=str(ROOT_DIR / "frontend"), check=True)
        else:
            raise FileNotFoundError("frontend/dist is missing and npm was not found to build it.")

    pyinstaller_cmd = build_pyinstaller_cmd(ROOT_DIR)
    print("[Build] Running PyInstaller...")
    subprocess.run(pyinstaller_cmd, check=True)

    out_exe = ROOT_DIR / "dist" / "WFT.exe"
    if out_exe.exists():
        size_mb = round(out_exe.stat().st_size / (1024 * 1024), 2)
        print(f"\n[Build] SUCCESS! Standalone executable created: {out_exe} ({size_mb} MB)")
        return out_exe
    raise FileNotFoundError("PyInstaller completed but dist/WFT.exe was not found.")


if __name__ == "__main__":
    build()
