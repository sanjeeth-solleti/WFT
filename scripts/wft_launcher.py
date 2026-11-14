"""
Windows Forensic Toolkit (WFT) - Enterprise Desktop App Launcher & Crash Watchdog
Spawns the FastAPI backend (8765) and Vite/dist frontend (5173) with zero console windows,
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
# Dynamic Base Directory Resolution
# ---------------------------------------------------------------------------
def get_base_dir() -> Path:
    """
    Resolves the project root directory whether running as a raw python script
    or compiled into a standalone PyInstaller executable (WFT.exe).
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent

BASE_DIR = get_base_dir()
os.chdir(BASE_DIR)

def get_runtime_log_dir() -> Path:
    """
    Standardized enterprise log directory where WFT.exe presents (BASE_DIR / logs)
    with automatic directory creation.
    """
    logs_dir = BASE_DIR / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir
    except Exception:
        fallback = Path.cwd() / "logs"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

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
    Thread-safe logger writing timestamped lines to logs/wft_runtime.log
    and appending to the in-memory circular buffer.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] [{tag}] {msg}\n"
    with _log_lock:
        LOG_BUFFER.append(formatted.strip())
        try:
            with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
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
    """
    if log_snippet is None:
        log_snippet = get_recent_log_lines(35)

    full_report = (
        f"=== WINDOWS FORENSIC TOOLKIT (WFT) RUNTIME ERROR REPORT ===\n"
        f"Timestamp: {datetime.now().isoformat()}\n"
        f"Headline:  {headline}\n"
        f"Details:   {details}\n"
        f"BaseDir:   {BASE_DIR}\n\n"
        f"--- RECENT RUNTIME LOGS (logs/wft_runtime.log) ---\n"
        f"{log_snippet}\n"
    )

    write_log(f"DISPLAYING ERROR DIALOG: {headline} | {details}", tag="ERROR")

    # 1. Attempt Modern Dark-Themed Tkinter Dialog
    try:
        import tkinter as tk
        from tkinter import scrolledtext

        root = tk.Tk()
        root.title(title)
        root.geometry("820x600")
        root.minsize(650, 450)
        root.configure(bg="#0f172a")

        # Center on active display
        root.update_idletasks()
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = max(0, (screen_w // 2) - 410)
        y = max(0, (screen_h // 2) - 300)
        root.geometry(f"+{x}+{y}")
        root.attributes("-topmost", True)

        # Header Frame
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

        # Main Log Viewer Frame
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

        # Bottom Button Action Bar
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

    # 2. Pure Win32 Fallback
    try:
        import ctypes
        # MB_ICONERROR (0x10) | MB_TOPMOST (0x40000) | MB_SETFOREGROUND (0x10000)
        flags = 0x10 | 0x40000 | 0x10000
        msg = f"{headline}\n\n{details}\n\nLogs:\n" + ("\n".join(log_snippet.splitlines()[-15:]))
        ctypes.windll.user32.MessageBoxW(0, msg, title, flags)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Prerequisite Resolvers (Python, Node/Vite, Browsers)
# ---------------------------------------------------------------------------
def resolve_python_executable() -> Optional[str]:
    """
    Discovers the real Python executable even when running inside a frozen WFT.exe.
    """
    if not getattr(sys, "frozen", False):
        return sys.executable

    # Check PATH first
    which_py = shutil.which("python.exe") or shutil.which("python") or shutil.which("python3.exe")
    if which_py and os.path.exists(which_py):
        return which_py

    # Common Windows installation directories
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        Path(local_app_data) / "Programs" / "Python" / "Python312" / "python.exe",
        Path(local_app_data) / "Programs" / "Python" / "Python311" / "python.exe",
        Path(local_app_data) / "Programs" / "Python" / "Python310" / "python.exe",
        Path(local_app_data) / "Microsoft" / "WindowsApps" / "python.exe",
        Path("C:/Python312/python.exe"),
        Path("C:/Python311/python.exe"),
        Path("C:/Python310/python.exe"),
    ]
    for cand in candidates:
        if cand.exists():
            return str(cand.resolve())

    return None

def resolve_frontend_command(base_dir: Path) -> Tuple[Optional[List[str]], Path]:
    """
    Resolves the frontend runner (Vite CLI or npm run dev).
    If frontend/dist/index.html is already built, FastAPI serves it directly on port 8765,
    so we avoid launching Vite unless --dev is explicitly passed on the command line.
    """
    frontend_dir = base_dir / "frontend"
    dist_index = frontend_dir / "dist" / "index.html"

    # If pre-built static bundle exists and user did not explicitly request --dev, serve via FastAPI
    dev_mode = any(arg.lower() in ("--dev", "-dev") for arg in sys.argv)
    if dist_index.exists() and not dev_mode:
        return None, frontend_dir

    # Local node_modules/.bin/vite.cmd
    local_vite = frontend_dir / "node_modules" / ".bin" / "vite.cmd"
    if local_vite.exists():
        return [str(local_vite), "--host", "127.0.0.1", "--port", "5173"], frontend_dir

    # Only invoke npm / npx if node_modules exists in frontend directory
    if (frontend_dir / "node_modules").exists():
        npx_bin = shutil.which("npx.cmd") or shutil.which("npx")
        if npx_bin:
            return [npx_bin, "vite", "--host", "127.0.0.1", "--port", "5173"], frontend_dir

        npm_bin = shutil.which("npm.cmd") or shutil.which("npm")
        if npm_bin:
            return [npm_bin, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"], frontend_dir

    return None, frontend_dir

# ---------------------------------------------------------------------------
# Windows Job Object Management (Automatic Child Termination)
# ---------------------------------------------------------------------------
def setup_windows_job_object() -> Optional[int]:
    """
    Creates a Windows Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000).
    When the parent WFT.exe process terminates for ANY reason (normal close, Task Manager kill,
    crash), Windows kernel automatically terminates all child processes assigned to this job.
    """
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
    """Assigns child subprocess handle to Windows Job Object for automatic termination."""
    if hJob and proc and sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.AssignProcessToJobObject(hJob, int(proc._handle))
        except Exception:
            pass


def launch_desktop_window(url: str) -> Optional[subprocess.Popen]:
    """
    Opens the UI inside a clean, windowless standalone application frame
    (Microsoft Edge App mode, Google Chrome App mode, or default browser).
    Returns the Popen process handle if a dedicated browser app was spawned.
    """
    write_log(f"Launching desktop application window for {url}...", tag="LAUNCHER")

    browser_profile = BASE_DIR / "logs" / "wft_browser_profile"
    browser_profile.mkdir(parents=True, exist_ok=True)

    app_args = [
        f"--app={url}",
        f"--user-data-dir={str(browser_profile.resolve())}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=Translate",
        "--disable-background-networking",
        "--disable-sync",
    ]

    # 1. Edge App Mode
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
                write_log(f"Using Microsoft Edge App Mode: {ep}", tag="LAUNCHER")
                proc = subprocess.Popen(
                    [str(ep)] + app_args,
                    creationflags=0x08000000 if sys.platform == "win32" else 0,
                )
                return proc
            except Exception as ex:
                write_log(f"Failed to launch Edge: {ex}", tag="LAUNCHER")

    # 2. Chrome App Mode
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
                write_log(f"Using Google Chrome App Mode: {cp}", tag="LAUNCHER")
                proc = subprocess.Popen(
                    [str(cp)] + app_args,
                    creationflags=0x08000000 if sys.platform == "win32" else 0,
                )
                return proc
            except Exception as ex:
                write_log(f"Failed to launch Chrome: {ex}", tag="LAUNCHER")

    # 3. Fallback to default browser
    write_log("Using system default web browser fallback", tag="LAUNCHER")
    webbrowser.open(url)
    return None

# ---------------------------------------------------------------------------
# Network & Process Health Diagnostics
# ---------------------------------------------------------------------------
def is_endpoint_healthy(url: str, timeout: float = 1.5) -> bool:
    """
    Tests if an HTTP endpoint returns a successful status code.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "WFT-Launcher/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False

def get_port_pids(port: int, listening_only: bool = False) -> List[int]:
    """
    Returns process IDs with TCP sockets bound to the specified local port.
    """
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
    """
    Returns process IDs actively listening on the specified TCP port.
    """
    return get_port_pids(port, listening_only=True)

def kill_process_tree(pid: int) -> None:
    """
    Kills a process and all its children silently.
    """
    try:
        flags = 0x08000000 if sys.platform == "win32" else 0
        subprocess.run(["taskkill", "/F", "/PID", str(pid), "/T"], capture_output=True, creationflags=flags)
    except Exception:
        pass

def wait_for_port_release(port: int, timeout: float = 4.0) -> bool:
    """
    Ensures that any listening processes on the port are terminated
    and the TCP socket can be bound without [Errno 10048].
    """
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

def stop_all_services() -> None:
    """
    Stops all orphaned or running WFT services on ports 8765 and 5173,
    and terminates any existing launcher watchdog processes.
    """
    write_log("Cleaning up services on ports 8765 and 5173...", tag="CLEANUP")
    if LAUNCHER_PID_FILE.exists():
        try:
            old_pid = int(LAUNCHER_PID_FILE.read_text(encoding="utf-8").strip())
            if old_pid != os.getpid() and old_pid > 4:
                write_log(f"Terminating previous launcher PID {old_pid}...", tag="CLEANUP")
                kill_process_tree(old_pid)
        except Exception:
            pass

    for port in [8765, 5173]:
        wait_for_port_release(port, timeout=3.0)

# ---------------------------------------------------------------------------
# Main Launcher Workflow & Crash Watchdog
# ---------------------------------------------------------------------------
def main() -> None:
    write_log("=" * 70, tag="LAUNCHER")
    write_log("Windows Forensic Toolkit (WFT) Launcher Initializing", tag="LAUNCHER")
    write_log(f"Working Directory: {BASE_DIR}", tag="LAUNCHER")
    write_log(f"Executable:        {sys.executable}", tag="LAUNCHER")
    write_log(f"Frozen:            {getattr(sys, 'frozen', False)}", tag="LAUNCHER")

    # Command line flag handling
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["--backend-only", "-backend-only"]:
            try:
                import faulthandler
                faulthandler.enable(file=sys.stderr, all_threads=True)
                import uvicorn
                from backend.main import app
                uvicorn.run(app, host="127.0.0.1", port=8765, log_config=None, log_level="warning")
            except Exception as e:
                import traceback
                sys.stderr.write(f"FATAL: Backend server execution failed: {e}\n{traceback.format_exc()}\n")
                sys.stderr.flush()
                sys.exit(1)
            sys.exit(0)
        elif arg in ["--stop", "-stop", "/stop"]:
            stop_all_services()
            print("WFT services on ports 8765 and 5173 stopped.")
            sys.exit(0)
        elif arg in ["--test-error", "-test-error"]:
            write_log("Simulated error requested via --test-error flag", tag="TEST")
            show_native_error_dialog(
                title="Windows Forensic Toolkit (WFT) - Simulated Crash Test",
                headline="Simulated Backend Crash Test (Exit Code 42)",
                details="This is an intentional verification test of the WFT native Windows Error Dialog and log viewer.",
            )
            sys.exit(0)
        elif arg in ["-c", "/c"]:
            sys.exit(0)

    # 1. Check if WFT is already running and healthy
    backend_live = (
        is_endpoint_healthy("http://127.0.0.1:8765/api/health", timeout=1.5)
        or is_endpoint_healthy("http://127.0.0.1:8765/api/system/tool-paths", timeout=1.5)
    )
    frontend_live = is_endpoint_healthy("http://127.0.0.1:5173/", timeout=1.0)

    if backend_live and frontend_live:
        write_log("Existing healthy WFT instance detected on ports 8765 and 5173. Opening desktop window...", tag="LAUNCHER")
        launch_desktop_window("http://127.0.0.1:5173")
        sys.exit(0)
    elif backend_live:
        # Check if backend is serving frontend/dist or healthy
        if is_endpoint_healthy("http://127.0.0.1:8765/", timeout=1.0) or is_endpoint_healthy("http://127.0.0.1:8765/api/health", timeout=1.0):
            write_log("Existing healthy WFT backend detected serving UI on port 8765. Opening desktop window...", tag="LAUNCHER")
            launch_desktop_window("http://127.0.0.1:8765")
            sys.exit(0)

    # Clean any orphaned non-healthy processes on our target ports and verify socket availability
    write_log("Ensuring ports 8765 and 5173 are free before launching...", tag="LAUNCHER")
    if LAUNCHER_PID_FILE.exists():
        try:
            old_pid = int(LAUNCHER_PID_FILE.read_text(encoding="utf-8").strip())
            if old_pid != os.getpid() and old_pid > 4:
                write_log(f"Terminating previous launcher PID {old_pid}...", tag="CLEANUP")
                kill_process_tree(old_pid)
        except Exception:
            pass
    try:
        LAUNCHER_PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except Exception:
        pass
    wait_for_port_release(8765, timeout=4.0)
    wait_for_port_release(5173, timeout=2.0)

    hJob = setup_windows_job_object()
    is_frozen = getattr(sys, "frozen", False)
    backend_proc: Optional[subprocess.Popen] = None
    frontend_proc: Optional[subprocess.Popen] = None
    ui_proc: Optional[subprocess.Popen] = None
    runtime_log_fh = open(LOG_FILE, "a", encoding="utf-8", buffering=1, errors="replace")

    def cleanup_children():
        try:
            if LAUNCHER_PID_FILE.exists():
                LAUNCHER_PID_FILE.unlink(missing_ok=True)
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
        for port in [8765, 5173]:
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

    # 2. Resolve Python (used in dev mode or as priority runner in frozen mode)
    python_exe = resolve_python_executable()
    if not is_frozen and not python_exe:
        msg = (
            "Python 3.10+ was not found on your system PATH or standard installation directories.\n\n"
            "Please ensure Python 3.10+ is installed and 'Add Python to PATH' is enabled."
        )
        write_log(msg, tag="FATAL")
        show_native_error_dialog(
            title="Windows Forensic Toolkit (WFT) - Missing Python Prerequisite",
            headline="Python 3.10+ Executable Not Found",
            details=msg,
        )
        sys.exit(1)

    if python_exe:
        write_log(f"Resolved Python executable: {python_exe}", tag="LAUNCHER")

    # 3. Setup windowless flags and environment
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    creationflags = 0x08000000  # CREATE_NO_WINDOW

    backend_env = os.environ.copy()
    backend_env["PYTHONUNBUFFERED"] = "1"
    backend_env.pop("_MEIPASS2", None)

    # 4. Helper to spawn FastAPI backend with direct file logging (no pipe deadlocks)
    def spawn_backend() -> subprocess.Popen:
        if is_frozen and not python_exe:
            cmd = [sys.executable, "--backend-only"]
        else:
            cmd = [
                python_exe or sys.executable,
                "-m",
                "uvicorn",
                "backend.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8765",
            ]
        write_log(f"Starting Backend: {' '.join(cmd)}", tag="BACKEND")
        proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
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

    # 5. Start Frontend
    dist_dir = BASE_DIR / "frontend" / "dist"
    has_dist = dist_dir.exists() and (dist_dir / "index.html").exists()
    use_vite = False

    if not is_frozen:
        frontend_cmd, frontend_cwd = resolve_frontend_command(BASE_DIR)
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
            write_log("No Node/Vite environment found. FastAPI will serve built frontend/dist assets.", tag="FRONTEND")
    else:
        write_log("Standalone frozen mode: FastAPI will serve built frontend/dist assets.", tag="FRONTEND")

    target_ui_url = "http://127.0.0.1:5173" if use_vite else "http://127.0.0.1:8765"

    # 6. Poll Services Until Ready (Timeout 45 Seconds)
    write_log(f"Polling WFT services for startup readiness (target UI: {target_ui_url})...", tag="LAUNCHER")
    max_wait_seconds = 45.0
    start_time = time.time()
    ready = False

    while (time.time() - start_time) < max_wait_seconds:
        # Check backend crash
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

        # Check frontend crash if vite used
        if frontend_proc:
            f_code = frontend_proc.poll()
            if f_code is not None:
                # If dist exists, we can fall back to serving dist on 8765
                if has_dist:
                    write_log(f"Vite server exited (code {f_code}); falling back to FastAPI static dist on 8765", tag="WARN")
                    use_vite = False
                    target_ui_url = "http://127.0.0.1:8765"
                    frontend_proc = None
                else:
                    cleanup_children()
                    show_native_error_dialog(
                        title="Windows Forensic Toolkit (WFT) - Frontend Startup Crash",
                        headline=f"Frontend Service Terminated During Initialization (Exit Code: {f_code})",
                        details="The Vite frontend process exited prematurely during startup. Review the runtime log below.",
                    )
                    sys.exit(f_code)

        # Test HTTP health
        backend_ready = (
            is_endpoint_healthy("http://127.0.0.1:8765/api/health", timeout=1.2)
            or is_endpoint_healthy("http://127.0.0.1:8765/api/system/tool-paths", timeout=1.2)
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

    # 7. Launch Native Desktop Window
    ui_proc = launch_desktop_window(target_ui_url)

    # 8. Watchdog Monitoring Loop with Automatic Self-Healing
    write_log("Entering background crash watchdog loop...", tag="WATCHDOG")
    backend_restart_count = 0
    backend_crash_timestamps = collections.deque(maxlen=10)

    try:
        while True:
            time.sleep(0.5)

            # Monitor Desktop UI window: if closed by examiner, terminate all background processes cleanly
            if ui_proc:
                ui_code = ui_proc.poll()
                if ui_code is not None:
                    write_log(
                        f"Desktop application window closed by user (exit code: {ui_code}). "
                        f"Terminating all WFT background services...",
                        tag="SHUTDOWN",
                    )
                    cleanup_children()
                    sys.exit(0)

            # Monitor Backend
            if backend_proc:
                b_code = backend_proc.poll()
                if b_code is not None:
                    # Clean intentional exit (e.g. via /api/system/shutdown)
                    if b_code == 0:
                        write_log("Backend service exited cleanly. Shutting down WFT session...", tag="SHUTDOWN")
                        cleanup_children()
                        sys.exit(0)

                    now = time.time()
                    backend_crash_timestamps.append(now)
                    write_log(f"CRASH: Backend exited unexpectedly with code {b_code}", tag="WATCHDOG")

                    # Check rapid consecutive crashes: 3 crashes within 15 seconds
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

                    # Automatic self-healing restart
                    backend_restart_count += 1
                    write_log(
                        f"[WATCHDOG] Auto-restarted backend (Attempt {backend_restart_count}/5, exit code: {b_code})",
                        tag="WATCHDOG",
                    )
                    wait_for_port_release(8765, timeout=2.0)
                    try:
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

                    # Poll for health after restart (giving it up to 10 seconds)
                    restarted_ok = False
                    for _ in range(20):
                        if backend_proc.poll() is not None:
                            break
                        if is_endpoint_healthy("http://127.0.0.1:8765/api/health", timeout=0.8):
                            restarted_ok = True
                            break
                        time.sleep(0.5)

                    if restarted_ok:
                        write_log(
                            f"[WATCHDOG] Auto-restarted backend is healthy and responding on port 8765",
                            tag="WATCHDOG",
                        )
                    else:
                        write_log(
                            f"[WATCHDOG] Backend auto-restart initiated (PID {backend_proc.pid}), awaiting health confirmation",
                            tag="WATCHDOG",
                        )

            # Monitor Frontend (if running via Vite)
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
    main()
