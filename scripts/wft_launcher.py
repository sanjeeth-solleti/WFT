"""
Windows Forensic Toolkit (WFT) - Enterprise Desktop App Launcher & Crash Watchdog
Spawns the FastAPI backend (default 8765) and Vite/dist frontend (5173) with zero console windows,
ensures first-run external forensic tool bootstrap (Setup-WFTTools.ps1),
monitors process health, streams runtime logs to logs/wft_runtime.log,
and presents a native Windows diagnostic error dialog if any service crashes.
"""
import faulthandler
import multiprocessing
import sys

faulthandler.enable(file=sys.stderr, all_threads=True)
multiprocessing.freeze_support()

import atexit
import collections
import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# Fallback stdout/stderr for windowed PyInstaller mode
if sys.stdout is None:
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr is None:
    try:
        sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dynamic Base & Writable AppData Directory Resolution (NO import-time chdir!)
# ---------------------------------------------------------------------------
def get_base_dir() -> Path:
    """
    Resolves the project root directory whether running as a raw python script
    or compiled into a standalone PyInstaller executable (WFT.exe).
    """
    override = os.environ.get("WFT_BASE_DIR", "").strip()
    if override:
        return Path(override).resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_appdata_dir() -> Path:
    """Resolves writable per-user WFT directory (honoring WFT_APPDATA_DIR override)."""
    override = os.environ.get("WFT_APPDATA_DIR", "").strip()
    if override:
        app_dir = Path(override).resolve()
    else:
        local_app = os.environ.get("LOCALAPPDATA", "").strip()
        app_dir = (Path(local_app) / "WFT").resolve() if local_app else (Path.home() / ".wft").resolve()
    try:
        app_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return app_dir


def is_dir_writable(dir_path: Path) -> bool:
    try:
        if not dir_path.is_dir():
            return False
        probe = dir_path / f".wft_probe_{os.getpid()}_{time.time_ns()}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


BASE_DIR = get_base_dir()


_CACHED_LOG_DIR: Optional[Path] = None
_CACHED_LOG_KEY: Optional[Tuple[str, str]] = None


def get_runtime_log_dir() -> Path:
    """
    Standardized enterprise log directory (prefers writable BASE_DIR / logs when WFT_BASE_DIR is set
    or WFT_APPDATA_DIR is unset, falling back cleanly to get_appdata_dir() / logs when read-only).
    """
    global _CACHED_LOG_DIR, _CACHED_LOG_KEY
    active_base = get_base_dir()
    base_override = os.environ.get("WFT_BASE_DIR", "").strip()
    appdata_override = os.environ.get("WFT_APPDATA_DIR", "").strip()
    cache_key = (str(active_base), f"{base_override}|{appdata_override}")
    if _CACHED_LOG_DIR is not None and _CACHED_LOG_KEY == cache_key and _CACHED_LOG_DIR.is_dir():
        return _CACHED_LOG_DIR

    chosen: Optional[Path] = None
    if appdata_override and not base_override:
        appdata_logs = get_appdata_dir() / "logs"
        try:
            appdata_logs.mkdir(parents=True, exist_ok=True)
            if is_dir_writable(appdata_logs):
                chosen = appdata_logs
        except OSError:
            chosen = None

    if chosen is None:
        logs_dir = active_base / "logs"
        try:
            logs_dir.mkdir(parents=True, exist_ok=True)
            if is_dir_writable(logs_dir):
                chosen = logs_dir
        except OSError:
            chosen = None

    if chosen is None:
        fallback = get_appdata_dir() / "logs"
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            chosen = fallback
        except OSError:
            chosen = active_base / "logs"

    _CACHED_LOG_DIR = chosen
    _CACHED_LOG_KEY = cache_key
    return chosen


LOGS_DIR = get_runtime_log_dir()
LOG_FILE = LOGS_DIR / "wft_runtime.log"
LAUNCHER_PID_FILE = LOGS_DIR / "wft_launcher.pid"

# Circular in-memory buffer of recent logs for error reporting
LOG_BUFFER = collections.deque(maxlen=200)
_log_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Runtime Logging System
# ---------------------------------------------------------------------------
def write_log(msg: str, tag: str = "LAUNCHER") -> None:
    """
    Thread-safe logger writing timestamped lines to wft_runtime.log
    and appending to the in-memory circular buffer.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] [{tag}] {msg}\n"
    with _log_lock:
        LOG_BUFFER.append(formatted.strip())
        try:
            log_dir = get_runtime_log_dir()
            log_fp = log_dir / "wft_runtime.log"
            with open(log_fp, "a", encoding="utf-8", errors="replace") as f:
                f.write(formatted)
                f.flush()
        except Exception:
            pass


def stream_process_output(proc: subprocess.Popen, tag: str) -> None:
    """
    Background worker thread reading proc.stdout continuously and piping to log file.
    """
    try:
        if proc.stdout:
            for line in iter(proc.stdout.readline, ""):
                line_str = line.strip()
                if line_str:
                    write_log(line_str, tag=tag)
    except Exception as ex:
        write_log(f"Process stream error: {ex}", tag=tag)


def get_recent_log_lines(n: int = 35) -> str:
    """
    Retrieves the last n lines from logs/wft_runtime.log or the memory buffer.
    """
    try:
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                if lines:
                    return "".join(lines[-n:])
    except Exception:
        pass
    with _log_lock:
        return "\n".join(list(LOG_BUFFER)[-n:])


# ---------------------------------------------------------------------------
# Native Windows Error Dialog (Tkinter with Win32 MessageBoxW Fallback)
# ---------------------------------------------------------------------------
def show_native_error_dialog(
    title: str,
    headline: str,
    details: str,
    log_snippet: Optional[str] = None,
    non_blocking: bool = False,
) -> None:
    """
    Displays a native Windows dialog featuring error diagnostics, a scrollable
    traceback/log viewer, and buttons to copy the error or open wft_runtime.log.
    Suppressed automatically when headless mode is enabled.
    """
    if log_snippet is None:
        log_snippet = get_recent_log_lines(35)

    write_log(f"DISPLAYING ERROR DIALOG: {headline} | {details}", tag="ERROR")

    if (
        os.environ.get("WFT_HEADLESS", "").strip().lower() in ("1", "true", "yes")
        or os.environ.get("WFT_NONINTERACTIVE", "").strip().lower() in ("1", "true", "yes")
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    ):
        try:
            sys.stderr.write(f"[{title}] {headline}: {details}\n")
            sys.stderr.flush()
        except Exception:
            pass
        return

    full_report = (
        f"=== WINDOWS FORENSIC TOOLKIT (WFT) RUNTIME ERROR REPORT ===\n"
        f"Timestamp: {datetime.now().isoformat()}\n"
        f"Headline:  {headline}\n"
        f"Details:   {details}\n"
        f"BaseDir:   {BASE_DIR}\n\n"
        f"--- RECENT RUNTIME LOGS (logs/wft_runtime.log) ---\n"
        f"{log_snippet}\n"
    )

    try:
        import tkinter as tk
        from tkinter import scrolledtext

        root = tk.Tk()
        root.title(title)
        root.geometry("820x600")
        root.minsize(650, 450)
        root.configure(bg="#0f172a")

        root.update_idletasks()
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = max(0, (screen_w // 2) - 410)
        y = max(0, (screen_h // 2) - 300)
        root.geometry(f"+{x}+{y}")
        root.attributes("-topmost", True)

        hdr = tk.Frame(root, bg="#1e293b", padx=24, pady=18)
        hdr.pack(fill="x", side="top")

        icon_lbl = tk.Label(hdr, text="✖", font=("Segoe UI", 28, "bold"), fg="#ef4444", bg="#1e293b")
        icon_lbl.pack(side="left", padx=(0, 18))

        txt_container = tk.Frame(hdr, bg="#1e293b")
        txt_container.pack(side="left", fill="both", expand=True)

        head_lbl = tk.Label(
            txt_container,
            text=headline,
            font=("Segoe UI", 12, "bold"),
            fg="#f8fafc",
            bg="#1e293b",
            anchor="w",
            justify="left",
        )
        head_lbl.pack(fill="x")

        det_lbl = tk.Label(
            txt_container,
            text=details,
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#1e293b",
            anchor="w",
            justify="left",
            wraplength=660,
        )
        det_lbl.pack(fill="x", pady=(5, 0))

        body = tk.Frame(root, bg="#0f172a", padx=20, pady=12)
        body.pack(fill="both", expand=True)

        log_hdr = tk.Label(
            body,
            text="Diagnostic Logs (logs/wft_runtime.log):",
            font=("Segoe UI", 9, "bold"),
            fg="#cbd5e1",
            bg="#0f172a",
            anchor="w",
        )
        log_hdr.pack(fill="x", pady=(0, 6))

        txt_box = scrolledtext.ScrolledText(
            body,
            wrap="none",
            bg="#020617",
            fg="#38bdf8",
            insertbackground="#ffffff",
            font=("Consolas", 9),
            padx=10,
            pady=10,
            borderwidth=1,
            relief="solid",
        )
        txt_box.pack(fill="both", expand=True)
        txt_box.insert("1.0", log_snippet if log_snippet.strip() else "(No logs recorded yet)")
        txt_box.configure(state="disabled")

        footer = tk.Frame(root, bg="#0f172a", padx=20, pady=16)
        footer.pack(fill="x", side="bottom")

        def copy_to_clipboard():
            root.clipboard_clear()
            root.clipboard_append(full_report)
            copy_btn.configure(text="✓ Copied to Clipboard!", fg="#22c55e")
            root.after(2500, lambda: copy_btn.configure(text="Copy Error Log", fg="#f8fafc"))

        def open_runtime_log():
            try:
                if LOG_FILE.exists():
                    os.startfile(str(LOG_FILE))
            except Exception as ex:
                write_log(f"Failed to open log file: {ex}")

        copy_btn = tk.Button(
            footer,
            text="Copy Error Log",
            font=("Segoe UI", 9, "bold"),
            bg="#2563eb",
            fg="#f8fafc",
            activebackground="#1d4ed8",
            activeforeground="#ffffff",
            padx=14,
            pady=7,
            relief="flat",
            cursor="hand2",
            command=copy_to_clipboard,
        )
        copy_btn.pack(side="left", padx=(0, 10))

        log_btn = tk.Button(
            footer,
            text="Open wft_runtime.log",
            font=("Segoe UI", 9),
            bg="#334155",
            fg="#f8fafc",
            activebackground="#475569",
            activeforeground="#ffffff",
            padx=14,
            pady=7,
            relief="flat",
            cursor="hand2",
            command=open_runtime_log,
        )
        log_btn.pack(side="left")

        exit_btn = tk.Button(
            footer,
            text="Close & Exit",
            font=("Segoe UI", 9, "bold"),
            bg="#dc2626",
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            padx=18,
            pady=7,
            relief="flat",
            cursor="hand2",
            command=root.destroy,
        )
        exit_btn.pack(side="right")

        if not non_blocking:
            root.mainloop()
        return
    except Exception as tk_err:
        write_log(f"Tkinter dialog failed ({tk_err}); falling back to Win32 MessageBoxW", tag="ERROR")

    try:
        import ctypes
        flags = 0x10 | 0x40000 | 0x10000
        msg = f"{headline}\n\n{details}\n\nLogs:\n" + ("\n".join(log_snippet.splitlines()[-15:]))
        ctypes.windll.user32.MessageBoxW(0, msg, title, flags)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Prerequisite Resolvers & First-Run Bootstrap (Setup-WFTTools.ps1)
# ---------------------------------------------------------------------------
def _get_python_tier(cand: Path, allow_windows_apps: bool = False) -> int:
    try:
        full_str = str(cand.resolve())
        is_winapps = "\\microsoft\\windowsapps\\" in (full_str.lower() + "\\")
        if is_winapps and not allow_windows_apps:
            return 0
        if not cand.is_file():
            return 0
        if not is_winapps and cand.stat().st_size <= 0:
            return 0
        creationflags = 0x08000000 if sys.platform == "win32" else 0
        cp = subprocess.run(
            [
                full_str,
                "-c",
                "import sys; sys.exit(2 if (3, 10) <= sys.version_info < (3, 13) else (1 if sys.version_info >= (3, 13) else 0))",
            ],
            capture_output=True,
            timeout=5,
            creationflags=creationflags,
        )
        if cp.returncode == 2:
            return 2  # Preferred compatible Python (3.10 - 3.12)
        if cp.returncode == 1:
            return 1  # Fallback Python (3.13+)
        return 0
    except Exception:
        return 0


def _is_usable_python(cand: Path, allow_windows_apps: bool = False) -> bool:
    return _get_python_tier(cand, allow_windows_apps) > 0


def resolve_python_executable() -> Optional[str]:
    """
    Discovers a verified working Python executable (skipping 0-byte WindowsApps stubs,
    prioritizing fully compatible Python 3.10-3.12 over 3.13+).
    """
    fallback_py: Optional[str] = None

    explicit_py = os.environ.get("WFT_PYTHON_EXE", "").strip()
    if explicit_py:
        p = Path(explicit_py.strip('"'))
        tier = _get_python_tier(p, allow_windows_apps=True)
        if tier == 2:
            return str(p.resolve())
        if tier == 1 and fallback_py is None:
            fallback_py = str(p.resolve())
        if os.environ.get("WFT_PYTHON_STRICT") == "1":
            return fallback_py

    if not getattr(sys, "frozen", False):
        sys_tier = _get_python_tier(Path(sys.executable), allow_windows_apps=True)
        if sys_tier == 2:
            return sys.executable
        if sys_tier == 1 and fallback_py is None:
            fallback_py = sys.executable

    path_env = os.environ.get("PATH", "")
    windows_apps_dirs: List[Path] = []
    for raw_dir in path_env.split(os.pathsep):
        d = raw_dir.strip().strip('"')
        if not d:
            continue
        if r"\microsoft\windowsapps" in d.lower():
            windows_apps_dirs.append(Path(d))
            continue
        for name in ("python.exe", "python3.exe"):
            cand = Path(d) / name
            tier = _get_python_tier(cand, allow_windows_apps=False)
            if tier == 2:
                return str(cand.resolve())
            if tier == 1 and fallback_py is None:
                fallback_py = str(cand.resolve())

    # Check WindowsApps PATH entries
    for wa_dir in windows_apps_dirs:
        for name in ("python.exe", "python3.exe"):
            cand = wa_dir / name
            tier = _get_python_tier(cand, allow_windows_apps=True)
            if tier == 2:
                return str(cand.resolve())
            if tier == 1 and fallback_py is None:
                fallback_py = str(cand.resolve())

    # Try official PEP 397 Windows py launcher (-3.12, -3.11, -3.10 first, then -3)
    py_launchers = [
        "py.exe",
        "py",
        r"C:\Windows\py.exe",
        r"C:\Windows\System32\py.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Launcher\py.exe"),
        os.path.expandvars(r"%ProgramFiles%\Python Launcher\py.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Python Launcher\py.exe"),
    ]
    for py_ver in ["-3.12", "-3.11", "-3.10", "-3"]:
        for py_cmd in py_launchers:
            try:
                creationflags = 0x08000000 if sys.platform == "win32" else 0
                cp = subprocess.run(
                    [py_cmd, py_ver, "-c", "import sys; print(sys.executable)"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=creationflags,
                )
                if cp.returncode == 0 and cp.stdout.strip():
                    cand = Path(cp.stdout.strip())
                    tier = _get_python_tier(cand, allow_windows_apps=True)
                    if tier == 2:
                        return str(cand.resolve())
                    if tier == 1 and fallback_py is None:
                        fallback_py = str(cand.resolve())
            except Exception:
                pass

    # Check Windows Registry for registered PythonCore installations
    try:
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            reg_views = [winreg.KEY_READ]
            if hasattr(winreg, "KEY_WOW64_64KEY"):
                reg_views.append(winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            if hasattr(winreg, "KEY_WOW64_32KEY"):
                reg_views.append(winreg.KEY_READ | winreg.KEY_WOW64_32KEY)
            for flags in reg_views:
                try:
                    with winreg.OpenKey(hive, r"Software\Python\PythonCore", 0, flags) as root:
                        for i in range(winreg.QueryInfoKey(root)[0]):
                            ver = winreg.EnumKey(root, i)
                            try:
                                with winreg.OpenKey(root, rf"{ver}\InstallPath") as ik:
                                    try:
                                        p_val, _ = winreg.QueryValueEx(ik, "ExecutablePath")
                                        if p_val:
                                            cand = Path(p_val)
                                            tier = _get_python_tier(cand, allow_windows_apps=False)
                                            if tier == 2:
                                                return str(cand.resolve())
                                            if tier == 1 and fallback_py is None:
                                                fallback_py = str(cand.resolve())
                                    except Exception:
                                        pass
                                    try:
                                        p_val, _ = winreg.QueryValueEx(ik, "")
                                        if p_val:
                                            cand = Path(p_val) / "python.exe"
                                            tier = _get_python_tier(cand, allow_windows_apps=False)
                                            if tier == 2:
                                                return str(cand.resolve())
                                            if tier == 1 and fallback_py is None:
                                                fallback_py = str(cand.resolve())
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                except Exception:
                    pass
    except Exception:
        pass

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    prog_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    user_profile = os.environ.get("USERPROFILE", "")
    candidates = [
        BASE_DIR / ".venv" / "Scripts" / "python.exe",
        BASE_DIR / "venv" / "Scripts" / "python.exe",
        Path(local_app_data) / "Programs" / "Python" / "Python312" / "python.exe",
        Path(local_app_data) / "Programs" / "Python" / "Python311" / "python.exe",
        Path(local_app_data) / "Programs" / "Python" / "Python310" / "python.exe",
        Path(prog_files) / "Python312" / "python.exe",
        Path(prog_files) / "Python311" / "python.exe",
        Path(prog_files) / "Python310" / "python.exe",
        Path(prog_files_x86) / "Python312" / "python.exe",
        Path(prog_files_x86) / "Python311" / "python.exe",
        Path(prog_files_x86) / "Python310" / "python.exe",
        Path("C:/Python312/python.exe"),
        Path("C:/Python311/python.exe"),
        Path("C:/Python310/python.exe"),
        Path("C:/tools/python312/python.exe"),
        Path("C:/tools/python311/python.exe"),
        Path("C:/ProgramData/chocolatey/bin/python3.12.exe"),
        Path("C:/ProgramData/chocolatey/bin/python3.11.exe"),
        Path(local_app_data) / "Programs" / "Python" / "Python313" / "python.exe",
        Path(local_app_data) / "Programs" / "Python" / "Python314" / "python.exe",
        Path(prog_files) / "Python313" / "python.exe",
        Path(prog_files) / "Python314" / "python.exe",
        Path(prog_files_x86) / "Python313" / "python.exe",
        Path(prog_files_x86) / "Python314" / "python.exe",
        Path("C:/Python313/python.exe"),
        Path("C:/Python314/python.exe"),
        Path("C:/python/python.exe"),
        Path("C:/python3/python.exe"),
        Path("C:/tools/python313/python.exe"),
        Path("C:/tools/python314/python.exe"),
        Path("C:/tools/python3/python.exe"),
        Path("C:/ProgramData/chocolatey/bin/python.exe"),
        Path("C:/ProgramData/chocolatey/bin/python3.exe"),
        Path("C:/ProgramData/chocolatey/bin/python3.13.exe"),
        Path(user_profile) / "anaconda3" / "python.exe",
        Path(user_profile) / "miniconda3" / "python.exe",
        Path(user_profile) / "miniforge3" / "python.exe",
        Path("C:/ProgramData/anaconda3/python.exe"),
        Path("C:/ProgramData/miniconda3/python.exe"),
        Path("C:/ProgramData/miniforge3/python.exe"),
    ]
    for cand in candidates:
        tier = _get_python_tier(cand, allow_windows_apps=False)
        if tier == 2:
            return str(cand.resolve())
        if tier == 1 and fallback_py is None:
            fallback_py = str(cand.resolve())

    # Fallback: check default WindowsApps path if no other Python exists
    default_wa = Path(local_app_data) / "Microsoft" / "WindowsApps" / "python.exe"
    wa_tier = _get_python_tier(default_wa, allow_windows_apps=True)
    if wa_tier == 2:
        return str(default_wa.resolve())
    if wa_tier == 1 and fallback_py is None:
        fallback_py = str(default_wa.resolve())

    return fallback_py


def resolve_setup_script(base_dir: Path = BASE_DIR) -> Optional[Path]:
    """
    Resolves Setup-WFTTools.ps1 across source checkouts, sidecar installs, and PyInstaller _MEIPASS bundles.
    """
    candidates: List[Path] = [base_dir / "Setup-WFTTools.ps1"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "Setup-WFTTools.ps1")
    candidates.append(Path(__file__).resolve().parent.parent / "Setup-WFTTools.ps1")

    for c in candidates:
        try:
            if c.is_file():
                return c.resolve()
        except OSError:
            continue
    return None


def _load_env_file_into_environ(env_file: Path) -> None:
    if not env_file.is_file():
        return
    try:
        with open(env_file, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#") and "=" in s:
                    k, v = s.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k:
                        os.environ[k] = v
    except Exception as ex:
        write_log(f"Warning loading {env_file}: {ex}", tag="BOOTSTRAP")


def ensure_first_run_bootstrap(base_dir: Optional[Path] = None, force: bool = False) -> Tuple[bool, int]:
    """
    Ensures Setup-WFTTools.ps1 has executed at least once and populated .env + .wft_setup_done.
    Strictly writes .wft_setup_done ONLY when Setup-WFTTools.ps1 exits with code 0.
    """
    target_base = (base_dir or get_base_dir()).resolve()
    writable = is_dir_writable(target_base)
    state_dir = target_base if writable else get_appdata_dir()
    env_file = state_dir / ".env"
    marker_file = state_dir / ".wft_setup_done"
    tools_dir = state_dir / "tools"

    try:
        has_env = env_file.is_file() and env_file.stat().st_size > 0
    except OSError:
        has_env = False

    needs_setup = force or (not marker_file.is_file()) or (not has_env)
    if not needs_setup:
        _load_env_file_into_environ(env_file)
        return True, 0

    setup_script = resolve_setup_script(target_base)
    if setup_script is None:
        write_log(f"Setup-WFTTools.ps1 not found under {target_base} or _MEIPASS.", tag="BOOTSTRAP")
        return False, 2

    ps_exe = shutil.which("powershell.exe") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    cmd: List[str] = [
        ps_exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(setup_script),
        "-ProjectRoot",
        str(target_base),
        "-EnvFilePath",
        str(env_file),
        "-ToolsRootDir",
        str(tools_dir),
    ]
    extra_ps = os.environ.get("WFT_SETUP_PS_ARGS", "").strip()
    if extra_ps:
        cmd.extend(shlex.split(extra_ps, posix=False))

    write_log(f"Running first-run toolchain bootstrap: {' '.join(cmd)}", tag="BOOTSTRAP")
    creationflags = 0x08000000 if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(target_base),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
    except Exception as ex:
        write_log(f"Failed invoking Setup-WFTTools.ps1: {ex}", tag="BOOTSTRAP")
        return False, 1

    batch_lines: List[str] = []
    ts_boot = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if proc.stdout:
        for ln in proc.stdout.splitlines():
            s_ln = ln.strip()
            if s_ln:
                batch_lines.append(f"[{ts_boot}] [BOOTSTRAP] {s_ln}\n")
    if proc.stderr:
        for ln in proc.stderr.splitlines():
            s_ln = ln.strip()
            if s_ln:
                batch_lines.append(f"[{ts_boot}] [BOOTSTRAP] STDERR: {s_ln}\n")
    if batch_lines:
        with _log_lock:
            for bl in batch_lines:
                LOG_BUFFER.append(bl.strip())
            try:
                log_fp = get_runtime_log_dir() / "wft_runtime.log"
                with open(log_fp, "a", encoding="utf-8", errors="replace") as f:
                    f.writelines(batch_lines)
                    f.flush()
            except Exception:
                pass

    try:
        post_has_env = env_file.is_file() and env_file.stat().st_size > 0
    except OSError:
        post_has_env = False

    if proc.returncode == 0 and post_has_env:
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            marker_file.write_text(
                f"Setup completed at: {datetime.utcnow().isoformat()}Z\n",
                encoding="utf-8",
            )
        except OSError as ex:
            write_log(f"Failed writing marker {marker_file}: {ex}", tag="BOOTSTRAP")
            return False, 1
        _load_env_file_into_environ(env_file)
        if not writable:
            os.environ["WFT_ENV_FILE"] = str(env_file)
        return True, 0

    try:
        if marker_file.exists():
            marker_file.unlink(missing_ok=True)
    except OSError:
        pass
    return False, (proc.returncode if proc.returncode != 0 else 1)


def resolve_frontend_command(base_dir: Path) -> Tuple[Optional[List[str]], Path]:
    """
    Resolves the frontend runner (Vite CLI or npm run dev).
    If frontend/dist/index.html is already built, FastAPI serves it directly on the backend port,
    so we avoid launching Vite unless --dev is explicitly passed on the command line.
    """
    frontend_dir = base_dir / "frontend"
    dist_index = frontend_dir / "dist" / "index.html"

    dev_mode = any(arg.lower() in ("--dev", "-dev") for arg in sys.argv)
    if dist_index.exists() and not dev_mode:
        return None, frontend_dir

    local_vite = frontend_dir / "node_modules" / ".bin" / "vite.cmd"
    if local_vite.exists():
        return [str(local_vite), "--host", "127.0.0.1", "--port", "5173"], frontend_dir

    if (frontend_dir / "node_modules").exists():
        npx_bin = shutil.which("npx.cmd") or shutil.which("npx")
        if npx_bin:
            return [npx_bin, "vite", "--host", "127.0.0.1", "--port", "5173"], frontend_dir

        npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
        if npm_bin:
            return [npm_bin, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"], frontend_dir

    return None, frontend_dir


# ---------------------------------------------------------------------------
# Windows Job Object Management & Isolated Browser App Launcher
# ---------------------------------------------------------------------------
def setup_windows_job_object() -> Optional[int]:
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        hJob = kernel32.CreateJobObjectW(None, None)
        if not hJob:
            return None

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", wintypes.ULARGE_INTEGER),
                ("WriteOperationCount", wintypes.ULARGE_INTEGER),
                ("OtherOperationCount", wintypes.ULARGE_INTEGER),
                ("ReadTransferCount", wintypes.ULARGE_INTEGER),
                ("WriteTransferCount", wintypes.ULARGE_INTEGER),
                ("OtherTransferCount", wintypes.ULARGE_INTEGER),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryLimit", ctypes.c_size_t),
                ("PeakJobMemoryLimit", ctypes.c_size_t),
            ]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        JobObjectExtendedLimitInformation = 9
        success = kernel32.SetInformationJobObject(
            hJob,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if success:
            return hJob
    except Exception as ex:
        write_log(f"Notice setting up Windows Job Object: {ex}", tag="WARN")
    return None


def assign_proc_to_job(hJob: Optional[int], proc: Optional[subprocess.Popen]) -> None:
    if hJob and proc and sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.AssignProcessToJobObject(hJob, int(proc._handle))
        except Exception:
            pass


def get_browser_profile_dir() -> Path:
    override = os.environ.get("WFT_BROWSER_PROFILE_DIR", "").strip()
    profile_dir = Path(override).resolve() if override else (get_appdata_dir() / "browser_profile").resolve()
    profile_dir.mkdir(parents=True, exist_ok=True)
    return profile_dir


def build_browser_app_args(url: str, profile_dir: Optional[Path] = None) -> List[str]:
    use_isolated = os.environ.get("WFT_ISOLATED_BROWSER_PROFILE") == "1"
    if not use_isolated:
        return [f"--app={url}", "--new-window"]

    resolved_profile = (profile_dir or get_browser_profile_dir()).resolve()
    resolved_profile.mkdir(parents=True, exist_ok=True)
    # Clean up stale lockfile if left behind from previous run
    lock_file = resolved_profile / "lockfile"
    try:
        if lock_file.exists():
            lock_file.unlink(missing_ok=True)
    except Exception:
        pass
    return [
        f"--app={url}",
        f"--user-data-dir={str(resolved_profile)}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-mode",
        "--new-window",
    ]


def launch_desktop_window(url: str) -> Optional[subprocess.Popen]:
    """
    Opens the UI inside a standalone application frame
    (Google Chrome App mode, Microsoft Edge App mode, or system default browser).
    """
    if os.environ.get("WFT_NO_BROWSER") == "1" or any(a.lower() == "--no-browser" for a in sys.argv[1:]):
        write_log("Skipping desktop browser window (--no-browser / WFT_NO_BROWSER=1).", tag="LAUNCHER")
        return None

    if os.environ.get("WFT_LAUNCHED_FROM_EXE") == "1":
        write_log("Desktop browser window opening handled by WFT.exe parent launcher.", tag="LAUNCHER")
        return None

    write_log(f"Launching desktop application window for {url}...", tag="LAUNCHER")

    # 1. Try Google Chrome App Mode first (most reliable chromeless app frame on Windows)
    chrome_candidates = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ]
    which_chrome = shutil.which("chrome.exe") or shutil.which("chrome")
    if which_chrome:
        chrome_candidates.insert(0, Path(which_chrome))

    for cp in chrome_candidates:
        if cp.exists():
            try:
                write_log(f"Attempting Google Chrome App Mode: {cp}", tag="LAUNCHER")
                proc = subprocess.Popen([str(cp), f"--app={url}", "--new-window"])
                time.sleep(0.6)
                if proc.poll() is None or proc.returncode == 0:
                    write_log("Google Chrome App window successfully launched.", tag="LAUNCHER")
                    return proc
                write_log(f"Chrome exited immediately with code {proc.returncode}; trying Edge fallback.", tag="WARN")
            except Exception as ex:
                write_log(f"Failed to launch Chrome: {ex}", tag="LAUNCHER")

    # 2. Try Microsoft Edge App Mode
    edge_candidates = [
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    ]
    which_edge = shutil.which("msedge.exe") or shutil.which("msedge")
    if which_edge:
        edge_candidates.insert(0, Path(which_edge))

    for ep in edge_candidates:
        if ep.exists():
            try:
                write_log(f"Attempting Microsoft Edge App Mode: {ep}", tag="LAUNCHER")
                proc = subprocess.Popen([str(ep), f"--app={url}", "--new-window"])
                time.sleep(0.6)
                if proc.poll() is None or proc.returncode == 0:
                    write_log("Microsoft Edge App window successfully launched.", tag="LAUNCHER")
                    return proc
                write_log(f"Edge exited immediately with code {proc.returncode}; trying ShellExecute fallback.", tag="WARN")
            except Exception as ex:
                write_log(f"Failed to launch Edge: {ex}", tag="LAUNCHER")

    # 3. System Default Web Browser Fallback (ShellExecute / webbrowser)
    write_log("Opening system default web browser via Windows Shell...", tag="LAUNCHER")
    try:
        if hasattr(os, "startfile"):
            os.startfile(url)
        else:
            webbrowser.open(url)
    except Exception as ex:
        write_log(f"Browser launch fallback error: {ex}", tag="LAUNCHER")
        webbrowser.open(url)
    return None


# ---------------------------------------------------------------------------
# Network & Process Health Diagnostics
# ---------------------------------------------------------------------------
def is_endpoint_healthy(url: str, timeout: float = 1.5) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "WFT-Launcher/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def get_port_pids(port: int, listening_only: bool = False) -> List[int]:
    pids = set()
    try:
        flags = 0x08000000 if sys.platform == "win32" else 0
        res = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if f":{port}" in line:
                if listening_only and "LISTENING" not in line:
                    continue
                parts = line.split()
                if len(parts) >= 5 and f":{port}" in parts[1]:
                    try:
                        pid = int(parts[-1])
                        if pid > 4:
                            pids.add(pid)
                    except ValueError:
                        pass
    except Exception as ex:
        write_log(f"netstat check failed for port {port}: {ex}", tag="LAUNCHER")
    return list(pids)


def get_listening_pids(port: int) -> List[int]:
    return get_port_pids(port, listening_only=True)


def kill_process_tree(pid: int) -> None:
    try:
        flags = 0x08000000 if sys.platform == "win32" else 0
        subprocess.run(["taskkill", "/F", "/PID", str(pid), "/T"], capture_output=True, creationflags=flags)
    except Exception:
        pass


def wait_for_port_release(port: int, timeout: float = 4.0) -> bool:
    import socket
    start = time.time()
    while time.time() - start < timeout:
        pids = get_port_pids(port, listening_only=False)
        if pids:
            for pid in pids:
                write_log(f"Terminating lingering PID {pid} on port {port}...", tag="CLEANUP")
                kill_process_tree(pid)
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("127.0.0.1", port))
                    return True
            except OSError:
                pass
        time.sleep(0.3)
    return False


def stop_all_services(api_port: int = 8765) -> None:
    write_log(f"Cleaning up services on ports {api_port} and 5173...", tag="CLEANUP")
    if LAUNCHER_PID_FILE.exists():
        try:
            old_pid = int(LAUNCHER_PID_FILE.read_text(encoding="utf-8").strip())
            if old_pid != os.getpid() and old_pid > 4:
                write_log(f"Terminating previous launcher PID {old_pid}...", tag="CLEANUP")
                kill_process_tree(old_pid)
        except Exception:
            pass

    for port in [api_port, 5173]:
        wait_for_port_release(port, timeout=3.0)


def _resolve_api_port(argv: List[str]) -> int:
    for idx, arg in enumerate(argv):
        if arg.lower() == "--port" and idx + 1 < len(argv):
            try:
                return int(argv[idx + 1])
            except ValueError:
                pass
        elif arg.lower().startswith("--port="):
            try:
                return int(arg.split("=", 1)[1])
            except ValueError:
                pass
    try:
        return int(os.environ.get("WFT_PORT", "8765"))
    except ValueError:
        return 8765


# ---------------------------------------------------------------------------
# Main Launcher Workflow & Crash Watchdog
# ---------------------------------------------------------------------------
def main() -> None:
    active_base = get_base_dir()
    try:
        os.chdir(active_base)
    except OSError:
        pass

    argv = sys.argv[1:]
    lower_args = {a.lower() for a in argv}
    api_port = _resolve_api_port(argv)
    os.environ["WFT_PORT"] = str(api_port)

    write_log("=" * 70, tag="LAUNCHER")
    write_log("Windows Forensic Toolkit (WFT) Launcher Initializing", tag="LAUNCHER")
    write_log(f"Working Directory: {active_base}", tag="LAUNCHER")
    write_log(f"Executable:        {sys.executable}", tag="LAUNCHER")
    write_log(f"Frozen:            {getattr(sys, 'frozen', False)}", tag="LAUNCHER")

    if argv:
        first_arg = argv[0].lower()
        if first_arg in ["--backend-only", "-backend-only"]:
            try:
                faulthandler.enable(file=sys.stderr, all_threads=True)
                repo_root = Path(__file__).resolve().parent.parent
                for cand_root in (str(repo_root), str(active_base)):
                    if cand_root and cand_root not in sys.path:
                        sys.path.insert(0, cand_root)
                import uvicorn
                from backend.main import app
                uvicorn.run(
                    app,
                    host="127.0.0.1",
                    port=api_port,
                    log_config=None,
                    log_level="warning",
                    timeout_keep_alive=600,
                )
            except Exception as e:
                import traceback
                sys.stderr.write(f"FATAL: Backend server execution failed: {e}\n{traceback.format_exc()}\n")
                sys.stderr.flush()
                sys.exit(1)
            sys.exit(0)
        elif first_arg in ["--stop", "-stop", "/stop"]:
            stop_all_services(api_port=api_port)
            print(f"WFT services on ports {api_port} and 5173 stopped.")
            sys.exit(0)
        elif first_arg in ["--test-error", "-test-error"]:
            write_log("Simulated error requested via --test-error flag", tag="TEST")
            show_native_error_dialog(
                title="Windows Forensic Toolkit (WFT) - Simulated Crash Test",
                headline="Simulated Backend Crash Test (Exit Code 42)",
                details="This is an intentional verification test of the WFT native Windows Error Dialog and log viewer.",
            )
            sys.exit(0)
        elif first_arg in ["-c", "/c"]:
            sys.exit(0)

    force_setup = bool(lower_args.intersection({"--setup", "/setup", "--reinstall"}))
    setup_only = bool(lower_args.intersection({"--setup-only", "/setup-only"})) or (
        os.environ.get("WFT_SETUP_ONLY", "").strip().lower() in ("1", "true", "yes")
    )
    skip_setup = bool(lower_args.intersection({"--skip-setup", "/skip-setup"})) or (
        os.environ.get("WFT_SKIP_SETUP", "").strip().lower() in ("1", "true", "yes")
    )

    if setup_only:
        ok, rc = ensure_first_run_bootstrap(active_base, force=force_setup)
        sys.exit(0 if ok else (rc if rc != 0 else 1))

    if not skip_setup:
        ok, rc = ensure_first_run_bootstrap(active_base, force=force_setup)
        if not ok:
            write_log(f"First-run bootstrap reported non-zero status ({rc}); continuing startup with available tools.", tag="WARN")

    # 1. Check if WFT is already running and healthy
    backend_live = (
        is_endpoint_healthy(f"http://127.0.0.1:{api_port}/api/health", timeout=1.5)
        or is_endpoint_healthy(f"http://127.0.0.1:{api_port}/api/system/tool-paths", timeout=1.5)
    )
    frontend_live = is_endpoint_healthy("http://127.0.0.1:5173/", timeout=1.0)

    if backend_live and frontend_live:
        write_log(f"Existing healthy WFT instance detected on ports {api_port} and 5173. Opening desktop window...", tag="LAUNCHER")
        launch_desktop_window("http://127.0.0.1:5173")
        time.sleep(1.0)
        sys.exit(0)
    elif backend_live:
        if is_endpoint_healthy(f"http://127.0.0.1:{api_port}/", timeout=1.0) or is_endpoint_healthy(f"http://127.0.0.1:{api_port}/api/health", timeout=1.0):
            write_log(f"Existing healthy WFT backend detected serving UI on port {api_port}. Opening desktop window...", tag="LAUNCHER")
            launch_desktop_window(f"http://127.0.0.1:{api_port}")
            time.sleep(1.0)
            sys.exit(0)

    write_log(f"Ensuring ports {api_port} and 5173 are free before launching...", tag="LAUNCHER")
    log_dir = get_runtime_log_dir()
    pid_file = log_dir / "wft_launcher.pid"
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text(encoding="utf-8").strip())
            if old_pid != os.getpid() and old_pid > 4:
                write_log(f"Terminating previous launcher PID {old_pid}...", tag="CLEANUP")
                kill_process_tree(old_pid)
        except Exception:
            pass
    try:
        pid_file.write_text(str(os.getpid()), encoding="utf-8")
    except Exception:
        pass
    if not wait_for_port_release(api_port, timeout=4.0):
        lingering = get_port_pids(api_port, listening_only=True)
        err_msg = (
            f"Port {api_port} is already in use by another process (PID: {lingering or 'unknown'}) "
            f"and could not be released.\n\n"
            f"Please terminate the lingering process or start WFT with '--port <free_port>'."
        )
        write_log(err_msg, tag="FATAL")
        show_native_error_dialog(
            title="Windows Forensic Toolkit (WFT) - Port Conflict",
            headline=f"Port {api_port} In Use",
            details=err_msg,
        )
        sys.exit(1)
    wait_for_port_release(5173, timeout=2.0)

    hJob = setup_windows_job_object()
    is_frozen = getattr(sys, "frozen", False)
    backend_proc: Optional[subprocess.Popen] = None
    frontend_proc: Optional[subprocess.Popen] = None
    ui_proc: Optional[subprocess.Popen] = None
    runtime_log_fh = open(log_dir / "wft_runtime.log", "a", encoding="utf-8", buffering=1, errors="replace")

    def cleanup_children():
        try:
            if pid_file.exists():
                pid_file.unlink(missing_ok=True)
        except Exception:
            pass
        if backend_proc and backend_proc.poll() is None:
            write_log(f"Terminating Backend PID {backend_proc.pid}...", tag="SHUTDOWN")
            kill_process_tree(backend_proc.pid)
        if frontend_proc and frontend_proc.poll() is None:
            write_log(f"Terminating Frontend PID {frontend_proc.pid}...", tag="SHUTDOWN")
            kill_process_tree(frontend_proc.pid)
        if ui_proc and ui_proc.poll() is None:
            write_log(f"Terminating UI Process PID {ui_proc.pid}...", tag="SHUTDOWN")
            kill_process_tree(ui_proc.pid)
        for port in [api_port, 5173]:
            for pid in get_port_pids(port, listening_only=False):
                if pid != os.getpid():
                    kill_process_tree(pid)
        try:
            if runtime_log_fh and not runtime_log_fh.closed:
                runtime_log_fh.close()
        except Exception:
            pass

    atexit.register(cleanup_children)

    if sys.platform == "win32":
        try:
            import ctypes

            def win_ctrl_handler(dwCtrlType):
                write_log(f"Windows control event ({dwCtrlType}) received. Stopping all WFT processes...", tag="SHUTDOWN")
                cleanup_children()
                return True

            WINTYPE_HANDLER = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
            _global_handler = WINTYPE_HANDLER(win_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_global_handler, True)
        except Exception:
            pass

    signal.signal(signal.SIGINT, lambda s, f: (cleanup_children(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (cleanup_children(), sys.exit(0)))

    # 2. Resolve Python (required in non-frozen dev mode; frozen dist/WFT.exe uses self-contained --backend-only)
    python_exe = resolve_python_executable()
    if not is_frozen and not python_exe:
        msg = (
            "Python 3.10+ was not found on your system PATH or standard installation directories.\n\n"
            "Please ensure Python 3.10+ (3.10, 3.11, 3.12, or 3.13+) is installed and 'Add Python to PATH' is enabled."
        )
        write_log(msg, tag="FATAL")
        show_native_error_dialog(
            title="Windows Forensic Toolkit (WFT) - Missing Python Prerequisite",
            headline="Python 3.10+ Executable Not Found",
            details=msg,
        )
        sys.exit(1)

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    creationflags = 0x08000000  # CREATE_NO_WINDOW

    backend_env = os.environ.copy()
    backend_env["PYTHONUNBUFFERED"] = "1"
    backend_env["WFT_PORT"] = str(api_port)
    backend_env.pop("_MEIPASS2", None)

    if python_exe:
        write_log(f"Resolved Python executable: {python_exe}", tag="LAUNCHER")
        py_dir = str(Path(python_exe).parent)
        py_scripts = str(Path(python_exe).parent / "Scripts")
        cur_path = backend_env.get("PATH", "")
        backend_env["PATH"] = f"{py_dir}{os.pathsep}{py_scripts}{os.pathsep}{cur_path}"
        backend_env["WFT_PYTHON_EXE"] = python_exe

    def spawn_backend() -> subprocess.Popen:
        if is_frozen and os.environ.get("WFT_USE_SYSTEM_PYTHON") != "1":
            cmd = [sys.executable, "--backend-only", "--port", str(api_port)]
        else:
            cmd = [
                python_exe or sys.executable,
                "-m",
                "uvicorn",
                "backend.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
                "--timeout-keep-alive",
                "600",
            ]
        write_log(f"Starting Backend: {' '.join(cmd)}", tag="BACKEND")
        proc = subprocess.Popen(
            cmd,
            cwd=str(active_base),
            stdout=runtime_log_fh,
            stderr=runtime_log_fh,
            env=backend_env,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        assign_proc_to_job(hJob, proc)
        return proc

    try:
        backend_proc = spawn_backend()
    except Exception as ex:
        err_msg = f"Failed to spawn backend process: {ex}"
        write_log(err_msg, tag="FATAL")
        show_native_error_dialog(
            title="Windows Forensic Toolkit (WFT) - Backend Launch Failed",
            headline="Could Not Start FastAPI Backend",
            details=err_msg,
        )
        sys.exit(1)

    dist_dir = active_base / "frontend" / "dist"
    has_dist = dist_dir.exists() and (dist_dir / "index.html").exists()
    use_vite = False

    if not is_frozen:
        frontend_cmd, frontend_cwd = resolve_frontend_command(active_base)
        if frontend_cmd:
            write_log(f"Starting Frontend: {' '.join(frontend_cmd)} (cwd={frontend_cwd})", tag="FRONTEND")
            try:
                frontend_proc = subprocess.Popen(
                    frontend_cmd,
                    cwd=str(frontend_cwd),
                    stdout=runtime_log_fh,
                    stderr=runtime_log_fh,
                    env=backend_env,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                assign_proc_to_job(hJob, frontend_proc)
                use_vite = True
            except Exception as ex:
                write_log(f"Failed to spawn frontend dev server: {ex}", tag="FRONTEND")
                if not has_dist:
                    show_native_error_dialog(
                        title="Windows Forensic Toolkit (WFT) - Frontend Launch Failed",
                        headline="Could Not Start Frontend Vite Server",
                        details=f"Command '{' '.join(frontend_cmd)}' failed: {ex}",
                    )
                    cleanup_children()
                    sys.exit(1)
        else:
            write_log("Serving built frontend/dist assets via FastAPI.", tag="FRONTEND")
    else:
        write_log("Standalone frozen mode: FastAPI will serve built frontend/dist assets.", tag="FRONTEND")

    target_ui_url = "http://127.0.0.1:5173" if use_vite else f"http://127.0.0.1:{api_port}"

    write_log(f"Polling WFT services for startup readiness (target UI: {target_ui_url})...", tag="LAUNCHER")
    max_wait_seconds = 45.0
    start_time = time.time()
    ready = False
    backend_ready = False
    frontend_ready = False

    while (time.time() - start_time) < max_wait_seconds:
        if backend_proc:
            b_code = backend_proc.poll()
            if b_code is not None:
                cleanup_children()
                show_native_error_dialog(
                    title="Windows Forensic Toolkit (WFT) - Backend Startup Crash",
                    headline=f"Backend Service Terminated During Initialization (Exit Code: {b_code})",
                    details="The FastAPI backend process exited prematurely during startup. Review the runtime log below.",
                )
                sys.exit(b_code if b_code != 0 else 1)

        if frontend_proc:
            f_code = frontend_proc.poll()
            if f_code is not None:
                if has_dist:
                    write_log(f"Vite server exited (code {f_code}); falling back to FastAPI static dist on {api_port}", tag="WARN")
                    use_vite = False
                    target_ui_url = f"http://127.0.0.1:{api_port}"
                    frontend_proc = None
                else:
                    cleanup_children()
                    show_native_error_dialog(
                        title="Windows Forensic Toolkit (WFT) - Frontend Startup Crash",
                        headline=f"Frontend Service Terminated During Initialization (Exit Code: {f_code})",
                        details="The Vite frontend process exited prematurely during startup. Review the runtime log below.",
                    )
                    sys.exit(f_code)

        backend_ready = (
            is_endpoint_healthy(f"http://127.0.0.1:{api_port}/api/health", timeout=1.2)
            or is_endpoint_healthy(f"http://127.0.0.1:{api_port}/api/system/tool-paths", timeout=1.2)
        )
        if use_vite:
            frontend_ready = is_endpoint_healthy("http://127.0.0.1:5173/", timeout=0.8)
        else:
            frontend_ready = backend_ready

        if backend_ready and frontend_ready:
            ready = True
            break

        time.sleep(0.5)

    if not ready:
        elapsed = round(time.time() - start_time, 1)
        err_detail = f"Services did not respond within {elapsed}s timeout (backend_ready={backend_ready}, frontend_ready={frontend_ready})."
        write_log(f"TIMEOUT: {err_detail}", tag="FATAL")
        cleanup_children()
        show_native_error_dialog(
            title="Windows Forensic Toolkit (WFT) - Startup Timeout",
            headline=f"WFT Services Failed to Initialize ({elapsed}s Timeout)",
            details=err_detail,
        )
        sys.exit(1)

    write_log(f"All WFT services operational after {round(time.time() - start_time, 2)}s!", tag="LAUNCHER")

    ui_launch_ts = time.time()
    ui_proc = launch_desktop_window(target_ui_url)

    write_log("Entering background crash watchdog loop...", tag="WATCHDOG")
    backend_restart_count = 0
    backend_crash_timestamps = collections.deque(maxlen=10)

    try:
        while True:
            time.sleep(0.5)

            if ui_proc:
                ui_code = ui_proc.poll()
                if ui_code is not None:
                    elapsed_ui = time.time() - ui_launch_ts
                    if ui_code == 0:
                        write_log(
                            f"Browser launcher process completed/delegated ({elapsed_ui:.2f}s); keeping FastAPI backend alive.",
                            tag="WATCHDOG",
                        )
                        ui_proc = None
                    elif ui_code != 0 and elapsed_ui < 10.0:
                        write_log(
                            f"Browser launcher process exited prematurely with code {ui_code} ({elapsed_ui:.2f}s). "
                            f"Falling back to system default web browser...",
                            tag="WARN",
                        )
                        try:
                            if hasattr(os, "startfile"):
                                os.startfile(target_ui_url)
                            else:
                                webbrowser.open(target_ui_url)
                        except Exception as wb_err:
                            write_log(f"webbrowser fallback error: {wb_err}", tag="WARN")
                        ui_proc = None
                    elif os.environ.get("WFT_EXIT_ON_UI_CLOSE") == "1":
                        write_log(
                            f"Desktop application window closed by user (exit code: {ui_code}). "
                            f"Terminating all WFT background services...",
                            tag="SHUTDOWN",
                        )
                        cleanup_children()
                        sys.exit(0)
                    else:
                        write_log(
                            f"Browser process closed/detached (exit code: {ui_code}); keeping FastAPI backend alive.",
                            tag="WATCHDOG",
                        )
                        ui_proc = None

            if backend_proc:
                b_code = backend_proc.poll()
                if b_code is not None:
                    if b_code == 0:
                        write_log("Backend service exited cleanly. Shutting down WFT session...", tag="SHUTDOWN")
                        cleanup_children()
                        sys.exit(0)

                    now = time.time()
                    backend_crash_timestamps.append(now)
                    write_log(f"CRASH: Backend exited unexpectedly with code {b_code}", tag="WATCHDOG")

                    recent_crashes = [t for t in backend_crash_timestamps if (now - t) <= 15.0]
                    if len(recent_crashes) >= 3:
                        err_msg = (
                            f"Backend process crashed {len(recent_crashes)} times within 15 seconds "
                            f"(last exit code: {b_code}). Halting automatic restarts."
                        )
                        write_log(err_msg, tag="FATAL")
                        cleanup_children()
                        show_native_error_dialog(
                            title="Windows Forensic Toolkit (WFT) - Backend Crash Loop",
                            headline=f"Backend Crashed Repeatedly (Exit Code: {b_code})",
                            details=err_msg,
                        )
                        sys.exit(b_code if b_code != 0 else 1)

                    if backend_restart_count >= 5:
                        err_msg = (
                            f"Backend process reached maximum automatic restart limit of 5 "
                            f"(last exit code: {b_code}). Session terminated."
                        )
                        write_log(err_msg, tag="FATAL")
                        cleanup_children()
                        show_native_error_dialog(
                            title="Windows Forensic Toolkit (WFT) - Backend Restart Limit Reached",
                            headline=f"Backend Service Failed (Exit Code: {b_code})",
                            details=err_msg,
                        )
                        sys.exit(b_code if b_code != 0 else 1)

                    backend_restart_count += 1
                    write_log(
                        f"[WATCHDOG] Auto-restarted backend (Attempt {backend_restart_count}/5, exit code: {b_code})",
                        tag="WATCHDOG",
                    )
                    wait_for_port_release(api_port, timeout=2.0)
                    try:
                        if runtime_log_fh.closed:
                            runtime_log_fh = open(log_dir / "wft_runtime.log", "a", encoding="utf-8", buffering=1, errors="replace")
                        backend_proc = spawn_backend()
                    except Exception as ex:
                        err_msg = f"Failed to auto-restart backend process: {ex}"
                        write_log(err_msg, tag="FATAL")
                        cleanup_children()
                        show_native_error_dialog(
                            title="Windows Forensic Toolkit (WFT) - Backend Auto-Restart Failed",
                            headline="Could Not Restart FastAPI Backend",
                            details=err_msg,
                        )
                        sys.exit(1)

                    restarted_ok = False
                    for _ in range(20):
                        if backend_proc.poll() is not None:
                            break
                        if is_endpoint_healthy(f"http://127.0.0.1:{api_port}/api/health", timeout=0.8):
                            restarted_ok = True
                            break
                        time.sleep(0.5)

                    if restarted_ok:
                        write_log(
                            f"[WATCHDOG] Auto-restarted backend is healthy and responding on port {api_port}",
                            tag="WATCHDOG",
                        )
                    else:
                        write_log(
                            f"[WATCHDOG] Backend auto-restart initiated (PID {backend_proc.pid}), awaiting health confirmation",
                            tag="WATCHDOG",
                        )

            if frontend_proc:
                f_code = frontend_proc.poll()
                if f_code is not None:
                    write_log(f"CRASH: Frontend exited with code {f_code}", tag="WATCHDOG")
                    cleanup_children()
                    show_native_error_dialog(
                        title="Windows Forensic Toolkit (WFT) - Frontend Crashed",
                        headline=f"Frontend Process Exited Unexpectedly (Exit Code: {f_code})",
                        details="The Vite frontend dev server crashed or stopped during execution.",
                    )
                    sys.exit(f_code)
    except KeyboardInterrupt:
        write_log("KeyboardInterrupt received; exiting cleanly.", tag="LAUNCHER")
        cleanup_children()
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        try:
            write_log(f"Unhandled fatal exception in launcher: {exc}\n{tb}", tag="FATAL")
        except Exception:
            pass
        show_native_error_dialog(
            title="Windows Forensic Toolkit (WFT) - Fatal Error",
            headline="Application Startup Exception",
            details=f"An unexpected error occurred while launching WFT:\n\n{exc}",
            log_snippet=tb,
        )
        sys.exit(1)
