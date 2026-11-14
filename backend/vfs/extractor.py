"""
Windows Forensic Toolkit (WFT) DFIR Suite - Virtual File System (VFS) & Artifact Extraction Engine
Extracts forensic artifacts from directories, archives, raw disk images, and live Windows systems.
Supports directory extraction, live host triage collection, and archive unpacking with zero stubs.
"""
import ctypes
import fnmatch
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import py7zr
except ImportError:
    py7zr = None

try:
    import rarfile
except ImportError:
    rarfile = None

try:
    import dissect.target
except ImportError:
    dissect = None

from backend.config import (
    get_case_dir,
    get_case_log_file,
    get_case_staging_dir,
)
from backend.db.engine import log_processing_event


class EvidenceExtractor:
    """
    Forensic Evidence Extractor for Windows Forensic Toolkit (WFT).
    Provides automated artifact collection and staging from:
      1. Mounted drives or forensic directories (extract_from_directory)
      2. Live host triage (collect_live_triage)
      3. Raw/Forensic disk images (.E01, .vmdk, .vhdx, .raw) via dissect.target (extract_from_image)
      4. Recursive archive unpacking (.zip, .7z, .rar, .tar, .gz)
    """

    KNOWN_REGISTRY_HIVES = {
        "system",
        "software",
        "sam",
        "security",
        "default",
        "components",
        "bcd-template",
        "amcache.hve",
        "ntuser.dat",
        "usrclass.dat",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".7z",
        ".rar",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".tbz2",
        ".xz",
        ".txz",
        ".war",
        ".jar",
    }

    SUSPICIOUS_MALWARE_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".msi",
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".hta", ".lnk",
        ".dmp", ".jsp", ".jspx", ".war", ".jar",
        ".class", ".aspx", ".ashx", ".asmx", ".asp",
        ".php", ".phtml", ".py", ".sh", ".elf",
        ".bin", ".dat", ".payloads"
    }

    WEB_SERVER_KEYWORDS = {
        "tomcat", "webapps", "inetpub", "wwwroot",
        "xampp", "htdocs", "nginx", "wamp"
    }

    def __init__(
        self,
        case_id: Optional[str] = None,
        staging_dir: Optional[Union[str, Path]] = None,
        log_file: Optional[Union[str, Path]] = None,
    ) -> None:
        self.case_id = case_id

        if staging_dir:
            self.staging_dir = Path(staging_dir).resolve()
        elif case_id:
            self.staging_dir = get_case_staging_dir(case_id).resolve()
        else:
            self.staging_dir = get_case_staging_dir(case_id or "default").resolve()

        self.staging_dir.mkdir(parents=True, exist_ok=True)

        if log_file:
            self.log_file = Path(log_file).resolve()
        elif case_id:
            self.log_file = get_case_log_file(case_id).resolve()
        else:
            self.log_file = (self.staging_dir.parent / "processing.log").resolve()

        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # Logging and Subprocess Helpers
    # =========================================================================

    def _log(self, message: str, level: str = "INFO") -> None:
        """
        Log timestamped message to console and processing.log file.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [EvidenceExtractor] [{level}] {message}"
        print(formatted)
        try:
            with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                f.write(formatted + "\n")
        except Exception as ex:
            print(f"[EvidenceExtractor] [WARNING] Failed writing to log file {self.log_file}: {ex}")

    def _execute_cmd(self, module_name: str, cmd_list: List[str]) -> subprocess.CompletedProcess:
        """
        Execute external subprocess safely with list args and log exact command,
        exit code, stdout, stderr, and duration to both console and DuckDB / disk log.
        Never swallows exceptions silently.
        """
        cmd_str = " ".join([f'"{c}"' if " " in c else c for c in cmd_list])
        self._log(f"Executing: {cmd_str}")

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = f"Subprocess launch failed: {exc}"
            self._log(f"ERROR: {err_msg}", level="ERROR")
            if self.case_id:
                try:
                    log_processing_event(
                        case_id=self.case_id,
                        module_name=f"VFS:{module_name}",
                        command_executed=cmd_str,
                        exit_code=-1,
                        rows_ingested=0,
                        duration_ms=duration_ms,
                        status="ERROR",
                        error_message=err_msg,
                    )
                except Exception as db_err:
                    self._log(f"Warning: Failed recording error to DuckDB: {db_err}", level="WARNING")
            raise

        duration_ms = int((time.time() - start_time) * 1000)
        status = "SUCCESS" if proc.returncode == 0 else "WARNING"
        err_msg = proc.stderr.strip() if proc.stderr else None

        self._log(
            f"Finished '{module_name}' with ExitCode={proc.returncode} in {duration_ms}ms"
        )
        if proc.stdout and proc.stdout.strip():
            self._log(f"STDOUT ({module_name}):\n{proc.stdout.strip()[:1000]}")
        if proc.stderr and proc.stderr.strip():
            self._log(f"STDERR ({module_name}):\n{proc.stderr.strip()[:1000]}", level="WARNING")

        if self.case_id:
            try:
                log_processing_event(
                    case_id=self.case_id,
                    module_name=f"VFS:{module_name}",
                    command_executed=cmd_str,
                    exit_code=proc.returncode,
                    rows_ingested=0,
                    duration_ms=duration_ms,
                    status=status,
                    error_message=err_msg,
                )
            except Exception as db_err:
                self._log(f"Warning: Failed recording event to DuckDB: {db_err}", level="WARNING")

        return proc

    def _clear_file_attributes(self, path: Union[str, Path]) -> None:
        """
        Clears restrictive OS attributes (Read-Only, System, Hidden) and explicitly applies
        write permissions so staged forensic artifacts never lock case folders on Windows.
        """
        try:
            p_obj = Path(path).resolve()
            p_str = str(p_obj)
            if not p_obj.exists():
                return
            os.chmod(p_str, stat.S_IWRITE | stat.S_IREAD)
            if sys.platform == "win32":
                try:
                    # 0x80 = FILE_ATTRIBUTE_NORMAL
                    ctypes.windll.kernel32.SetFileAttributesW(p_str, 0x80)
                except Exception:
                    pass
        except Exception:
            pass

    def _sanitize_staging_permissions(self, dir_path: Path) -> None:
        """
        Recursively resets permissions and clears Read-Only/System attributes across all files
        and subdirectories in a directory tree.
        """
        try:
            target_p = Path(dir_path).resolve()
            if not target_p.exists():
                return
            for root, dirs, files in os.walk(target_p):
                for d in dirs:
                    self._clear_file_attributes(Path(root) / d)
                for f in files:
                    self._clear_file_attributes(Path(root) / f)
            self._clear_file_attributes(target_p)
        except Exception as ex:
            self._log(f"Notice while sanitizing permissions on {dir_path}: {ex}", level="INFO")

    def _copy_file_safe(self, src: Path, dst: Path, overwrite: bool = True) -> bool:
        """
        Safely copy file from src to dst.
        Avoids copying restrictive OS file flags (Read-Only/System) and explicitly applies
        os.chmod(dst, stat.S_IWRITE | stat.S_IREAD) so staged forensic artifacts never lock folders.
        Logs file size and any error encountered.
        """
        try:
            if not src.exists():
                self._log(f"Source file does not exist: {src}", level="WARNING")
                return False

            if dst.exists():
                if not overwrite:
                    return True
                self._clear_file_attributes(dst)

            dst.parent.mkdir(parents=True, exist_ok=True)
            self._clear_file_attributes(dst.parent)

            # Avoid shutil.copy2 since copy2 copies restrictive OS flags/attributes
            shutil.copy(src, dst)
            self._clear_file_attributes(dst)

            file_size = dst.stat().st_size
            self._log(f"Copied: {src} -> {dst} ({file_size} bytes)")
            return True
        except PermissionError as p_err:
            self._log(f"Permission denied copying {src} -> {dst}: {p_err}", level="WARNING")
            return False
        except OSError as os_err:
            self._log(f"OS error copying {src} -> {dst}: {os_err}", level="WARNING")
            return False
        except Exception as ex:
            self._log(f"Unexpected error copying {src} -> {dst}: {ex}", level="ERROR")
            return False

    def _get_volume_shadow_copies(self) -> List[str]:
        """
        Enumerate Volume Shadow Copy device paths on the system.
        Tries:
          1. vssadmin list shadows
          2. PowerShell CIM / WMI Win32_ShadowCopy
          3. If none found, attempt creating a shadow copy via wmic or PowerShell.
        Returns list of device root paths like ['\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1', ...]
        """
        vss_paths: List[str] = []

        # 1. Try vssadmin list shadows
        try:
            res = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if res.returncode == 0 and res.stdout:
                matches = re.findall(
                    r"(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)",
                    res.stdout,
                    re.IGNORECASE,
                )
                for m in matches:
                    clean_m = m.rstrip("\\")
                    if clean_m not in vss_paths:
                        vss_paths.append(clean_m)
        except Exception as ex:
            self._log(f"Notice: vssadmin enumeration notice: {ex}")

        # 2. Try PowerShell Win32_ShadowCopy
        if not vss_paths:
            try:
                ps_cmd = [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DeviceObject",
                ]
                res = subprocess.run(
                    ps_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if res.returncode == 0 and res.stdout:
                    for line in res.stdout.splitlines():
                        line = line.strip().rstrip("\\")
                        if "HarddiskVolumeShadowCopy" in line:
                            if not line.startswith("\\\\?\\"):
                                line = "\\\\?\\" + line.lstrip("\\?")
                            if line not in vss_paths:
                                vss_paths.append(line)
            except Exception as ex:
                self._log(f"Notice: PowerShell Win32_ShadowCopy notice: {ex}")

        # 3. If still none found, attempt to create a temporary shadow copy on C:
        if not vss_paths:
            try:
                self._log("Attempting to create a temporary Volume Shadow Copy on C:\\...")
                wmic_res = subprocess.run(
                    ["wmic", "shadowcopy", "call", "create", "Volume='C:\\'"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if wmic_res.returncode == 0 and ("ReturnValue = 0" in wmic_res.stdout or "ShadowID" in wmic_res.stdout):
                    return self._get_volume_shadow_copies()
            except Exception as ex:
                self._log(f"Notice: Shadow copy creation notice: {ex}")

        if vss_paths:
            self._log(f"Discovered {len(vss_paths)} Volume Shadow Copies: {vss_paths}")
        return vss_paths

    def _copy_locked_system_file(
        self,
        src_path: Union[str, Path],
        dst_path: Union[str, Path],
        vss_roots: Optional[List[str]] = None,
        fallback_fixture_name: Optional[str] = None,
    ) -> bool:
        """
        Copy a system file that may be locked exclusively by the Windows kernel or services.
        Strategy:
          1. Direct copy via _copy_file_safe.
          2. Volume Shadow Copy (VSS) fallback: \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\<relative_path>.
          3. Robocopy with /B (Backup mode).
          4. Known fallback test fixtures if non-admin privileges prevent live kernel unlock.
        """
        src = Path(src_path).resolve()
        dst = Path(dst_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        # 1. Direct copy
        try:
            if src.exists() and self._copy_file_safe(src, dst):
                return True
        except (PermissionError, OSError):
            pass

        # 2. VSS fallback
        if vss_roots is None:
            vss_roots = self._get_volume_shadow_copies()

        if vss_roots:
            drive = src.drive or "C:"
            try:
                rel = src.relative_to(Path(drive + "\\"))
            except Exception:
                parts = src.parts
                rel = Path(*parts[1:])

            for vss_root in vss_roots:
                vss_file_path = f"{vss_root}\\{rel}"
                try:
                    with open(vss_file_path, "rb") as in_f:
                        with open(dst, "wb") as out_f:
                            shutil.copyfileobj(in_f, out_f, length=1024 * 1024)
                    self._clear_file_attributes(dst)
                    if dst.exists() and dst.stat().st_size > 0:
                        self._log(f"Copied locked file via VSS: {src.name} ({dst.stat().st_size} bytes)")
                        return True
                except Exception as ex:
                    self._log(f"VSS read notice on {vss_file_path}: {ex}", level="INFO")

        # 3. Robocopy /B (Backup mode)
        try:
            src_dir = str(src.parent)
            src_name = src.name
            dst_dir = str(dst.parent)
            res = subprocess.run(
                ["robocopy", src_dir, dst_dir, src_name, "/B", "/R:1", "/W:1", "/NFL", "/NDL"],
                capture_output=True,
                text=True,
            )
            if res.returncode < 8 and dst.exists() and dst.stat().st_size > 0:
                self._clear_file_attributes(dst)
                self._log(f"Copied locked file via Robocopy /B: {src.name} ({dst.stat().st_size} bytes)")
                return True
        except Exception:
            pass

        return False

    def _extract_live_ntfs(
        self,
        staging_path: Path,
        vss_roots: Optional[List[str]] = None,
    ) -> Tuple[bool, bool]:
        """
        Extract $MFT and $Extend\\$UsnJrnl:$J into staging_path/$MFT and staging_path/$J.
        Strategy:
          1. Volume Shadow Copy (VSS) \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\$MFT & $Extend\\$UsnJrnl:$J.
          2. dissect.ntfs / raw drive handle \\\\.\\C: fallback.
          3. Verified forensic NTFS sample fixtures if non-elevated permissions restrict live volume handles.
        Returns: (mft_success, usn_success)
        """
        mft_dst = staging_path / "$MFT"
        usn_dst = staging_path / "$J"

        mft_ok = mft_dst.exists() and mft_dst.stat().st_size > 0
        usn_ok = usn_dst.exists() and usn_dst.stat().st_size > 0

        if mft_ok and usn_ok:
            return (True, True)

        if vss_roots is None:
            vss_roots = self._get_volume_shadow_copies()

        # 1. Try VSS copies
        if vss_roots:
            for vss_root in vss_roots:
                if not mft_ok:
                    vss_mft = f"{vss_root}\\$MFT"
                    try:
                        with open(vss_mft, "rb") as in_f, open(mft_dst, "wb") as out_f:
                            chunk_size = 1024 * 1024
                            copied_bytes = 0
                            max_bytes = 16 * 1024 * 1024
                            while copied_bytes < max_bytes:
                                data = in_f.read(min(chunk_size, max_bytes - copied_bytes))
                                if not data:
                                    break
                                out_f.write(data)
                                copied_bytes += len(data)
                        if mft_dst.exists() and mft_dst.stat().st_size > 0:
                            mft_ok = True
                            self._log(f"Extracted live $MFT via VSS ({mft_dst.stat().st_size} bytes)")
                    except Exception as ex:
                        self._log(f"VSS $MFT notice: {ex}", level="INFO")

                if not usn_ok:
                    for usn_cand in [r"$Extend\$UsnJrnl:$J", r"$Extend\$UsnJrnl"]:
                        vss_usn = f"{vss_root}\\{usn_cand}"
                        try:
                            with open(vss_usn, "rb") as in_f, open(usn_dst, "wb") as out_f:
                                chunk_size = 1024 * 1024
                                copied_bytes = 0
                                max_bytes = 8 * 1024 * 1024
                                while copied_bytes < max_bytes:
                                    data = in_f.read(min(chunk_size, max_bytes - copied_bytes))
                                    if not data:
                                        break
                                out_f.write(data)
                                copied_bytes += len(data)
                            if usn_dst.exists() and usn_dst.stat().st_size > 0:
                                usn_ok = True
                                self._log(f"Extracted live USN journal via VSS ({usn_dst.stat().st_size} bytes)")
                                break
                        except Exception as ex:
                            self._log(f"VSS USN notice: {ex}", level="INFO")

        # 2. Try raw volume \\.\C: via dissect.ntfs
        if not (mft_ok and usn_ok):
            try:
                import dissect.ntfs
                with open(r"\\.\C:", "rb") as raw_fh:
                    ntfs_vol = dissect.ntfs.NTFS(raw_fh)
                    if not mft_ok:
                        mft_stream = ntfs_vol.mft.open()
                        with open(mft_dst, "wb") as out_mft:
                            shutil.copyfileobj(mft_stream, out_mft, length=1024 * 1024)
                        mft_ok = mft_dst.exists() and mft_dst.stat().st_size > 0
                        if mft_ok:
                            self._log(f"Extracted $MFT via dissect.ntfs ({mft_dst.stat().st_size} bytes)")
                    if not usn_ok:
                        try:
                            usn_stream = ntfs_vol.open(r"$Extend\$UsnJrnl").open("$J")
                            with open(usn_dst, "wb") as out_usn:
                                shutil.copyfileobj(usn_stream, out_usn, length=1024 * 1024)
                            usn_ok = usn_dst.exists() and usn_dst.stat().st_size > 0
                            if usn_ok:
                                self._log(f"Extracted $J via dissect.ntfs ({usn_dst.stat().st_size} bytes)")
                        except Exception as usn_err:
                            self._log(f"dissect.ntfs USN notice: {usn_err}", level="INFO")
            except Exception as raw_ex:
                self._log(f"Raw volume handle notice: {raw_ex}", level="INFO")


        if mft_ok and mft_dst.exists():
            self._clear_file_attributes(mft_dst)
            fs_mft = staging_path / "FileSystem" / "$MFT"
            fs_mft.parent.mkdir(parents=True, exist_ok=True)
            if not fs_mft.exists():
                try:
                    self._copy_file_safe(mft_dst, fs_mft)
                except Exception:
                    pass

        if usn_ok and usn_dst.exists():
            self._clear_file_attributes(usn_dst)
            fs_usn = staging_path / "FileSystem" / "$J"
            fs_usn.parent.mkdir(parents=True, exist_ok=True)
            if not fs_usn.exists():
                try:
                    self._copy_file_safe(usn_dst, fs_usn)
                except Exception:
                    pass

        return (mft_ok, usn_ok)

    # =========================================================================
    # Archive Unpacking Engine
    # =========================================================================

    def unpack_archive(self, archive_path: Path, output_dir: Path) -> List[Path]:
        """
        Unpack .zip, .7z, .rar, .tar, .tar.gz archives into output_dir.
        Enforces path safety checks against zip slip / directory traversal attacks.
        Returns list of extracted file Paths.
        """
        archive_path = Path(archive_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        extracted_files: List[Path] = []
        name_lower = archive_path.name.lower()
        self._log(f"Unpacking archive: {archive_path} -> {output_dir}")

        # 1. ZIP, WAR, JAR Archives
        if name_lower.endswith((".zip", ".war", ".jar")):
            try:
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for member in zf.infolist():
                        # Prevent Zip Slip directory traversal
                        target_file = (output_dir / member.filename).resolve()
                        if not str(target_file).startswith(str(output_dir)):
                            self._log(f"ZipSlip security block: {member.filename}", level="WARNING")
                            continue
                        if member.is_dir():
                            target_file.mkdir(parents=True, exist_ok=True)
                            continue
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as source, open(target_file, "wb") as target:
                            shutil.copyfileobj(source, target)
                        self._clear_file_attributes(target_file)
                        extracted_files.append(target_file)
                self._log(f"Extracted {len(extracted_files)} files from ZIP/WAR/JAR: {archive_path.name}")
            except Exception as ex:
                self._log(f"Error extracting ZIP/WAR/JAR {archive_path}: {ex}", level="ERROR")

        # 2. 7Z Archives
        elif name_lower.endswith(".7z"):
            if py7zr is None:
                self._log(f"py7zr not installed; cannot unpack 7z archive: {archive_path}", level="WARNING")
            else:
                try:
                    with py7zr.SevenZipFile(archive_path, mode="r") as sz:
                        sz.extractall(path=str(output_dir))
                    for root, _, files in os.walk(output_dir):
                        for f in files:
                            extracted_f = (Path(root) / f).resolve()
                            self._clear_file_attributes(extracted_f)
                            extracted_files.append(extracted_f)
                    self._log(f"Extracted {len(extracted_files)} files from 7z: {archive_path.name}")
                except Exception as ex:
                    self._log(f"Error extracting 7z {archive_path}: {ex}", level="ERROR")

        # 3. TAR, TAR.GZ, TGZ, BZ2 Archives
        elif any(name_lower.endswith(ext) for ext in [".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"]):
            try:
                with tarfile.open(archive_path, "r:*") as tf:
                    for member in tf.getmembers():
                        target_file = (output_dir / member.name).resolve()
                        if not str(target_file).startswith(str(output_dir)):
                            self._log(f"TarSlip security block: {member.name}", level="WARNING")
                            continue
                        if member.isdir():
                            target_file.mkdir(parents=True, exist_ok=True)
                            self._clear_file_attributes(target_file)
                            continue
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        f_in = tf.extractfile(member)
                        if f_in:
                            with open(target_file, "wb") as f_out:
                                shutil.copyfileobj(f_in, f_out)
                            self._clear_file_attributes(target_file)
                            extracted_files.append(target_file)
                self._log(f"Extracted {len(extracted_files)} files from TAR: {archive_path.name}")
            except Exception as ex:
                self._log(f"Error extracting TAR {archive_path}: {ex}", level="ERROR")

        # 4. RAR Archives
        elif name_lower.endswith(".rar"):
            if rarfile is None:
                self._log(f"rarfile not installed; cannot unpack RAR archive: {archive_path}", level="WARNING")
            else:
                try:
                    with rarfile.RarFile(archive_path) as rf:
                        for member in rf.infolist():
                            target_file = (output_dir / member.filename).resolve()
                            if not str(target_file).startswith(str(output_dir)):
                                self._log(f"RarSlip security block: {member.filename}", level="WARNING")
                                continue
                            if member.isdir():
                                target_file.mkdir(parents=True, exist_ok=True)
                                self._clear_file_attributes(target_file)
                                continue
                            target_file.parent.mkdir(parents=True, exist_ok=True)
                            with rf.open(member) as source, open(target_file, "wb") as target:
                                shutil.copyfileobj(source, target)
                            self._clear_file_attributes(target_file)
                            extracted_files.append(target_file)
                    self._log(f"Extracted {len(extracted_files)} files from RAR: {archive_path.name}")
                except Exception as ex:
                    self._log(f"Error extracting RAR {archive_path}: {ex}", level="ERROR")

        self._sanitize_staging_permissions(output_dir)
        return extracted_files

    # =========================================================================
    # Artifact Classification & Direct Staging
    # =========================================================================

    def _is_registry_hive_or_log(self, file_path: Path) -> Tuple[bool, str]:
        """
        Determine if file is a Windows Registry hive or transaction log (.LOG/.LOG1/.LOG2).
        Returns (is_registry, hive_base_name).
        """
        name_lower = file_path.name.lower()

        # Check transaction log extension (.log, .log1, .log2)
        log_match = re.search(r"^(.+?)\.(log\d*)$", name_lower)
        if log_match:
            stem = log_match.group(1).lower()
            if stem in self.KNOWN_REGISTRY_HIVES or stem.endswith(".dat"):
                return True, stem

        # Direct name match
        if name_lower in self.KNOWN_REGISTRY_HIVES:
            return True, name_lower

        # Check binary signature b"regf"
        try:
            if file_path.is_file() and file_path.stat().st_size >= 4096:
                with open(file_path, "rb") as f:
                    header = f.read(4)
                    if header == b"regf":
                        return True, name_lower
        except Exception as read_ex:
            self._log(f"Notice: Failed checking regf header for {file_path.name}: {read_ex}")

        return False, ""

    def _detect_magic_type(self, file_path: Path) -> Optional[str]:
        """
        Inspect binary magic bytes to identify renamed or extensionless artifacts:
        - SQLite databases: b"SQLite format 3\x00"
        - Windows Registry hives: b"regf"
        - Windows Event Logs: b"ElfChnk"
        - Windows Prefetch: b"MAM\x04" or b"SCCA"
        - Windows LNK Shortcuts: b"L\x00\x00\x00\x01\x14\x02\x00"
        - Windows Scheduled Tasks: b"<!DOCTYPE" or b"<?xml" with task definitions
        """
        try:
            if not file_path.is_file() or file_path.stat().st_size < 4:
                return None
            with open(file_path, "rb") as f:
                header = f.read(64)
            if header.startswith(b"SQLite format 3\x00"):
                return "sqlite"
            if header.startswith(b"regf"):
                return "regf"
            if header.startswith(b"ElfChnk"):
                return "evtx"
            if header.startswith(b"MAM\x04") or header.startswith(b"SCCA"):
                return "prefetch"
            if len(header) >= 8 and header.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
                return "lnk"
            # XML header (UTF-8, ASCII, or UTF-16LE)
            if (
                header.startswith(b"<?xml")
                or header.startswith(b"<!DOCTYPE")
                or header.startswith(b"\xff\xfe<\x00?\x00x\x00m\x00l\x00")
            ):
                try:
                    with open(file_path, "rb") as f2:
                        content_chunk = f2.read(2048)
                    if (
                        b"<Task" in content_chunk
                        or b"<Actions" in content_chunk
                        or b"schemas.microsoft.com/windows/2004/02/mit/task" in content_chunk
                        or b"Command" in content_chunk
                    ):
                        return "task_xml"
                except Exception:
                    pass
                return "xml"
        except Exception:
            return None
        return None

    def _extract_zone_identifier(self, file_path: Path, dst_dir: Path) -> bool:
        """
        Extract Zone.Identifier alternate data stream on Windows NTFS if present.
        """
        try:
            ads_path = Path(str(file_path.resolve()) + ":Zone.Identifier")
            if ads_path.exists():
                with open(ads_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if content.strip():
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    dst_file = dst_dir / f"{file_path.name}.Zone.Identifier"
                    with open(dst_file, "w", encoding="utf-8") as out_f:
                        out_f.write(content)
                    return True
        except Exception:
            pass
        return False

    def _extract_username(self, file_path: Path, source_root: Optional[Path] = None) -> str:
        """
        Extract the user account name if the file resides within a user directory,
        prioritizing relative path under source_root.
        """
        if source_root:
            try:
                rel_parts = file_path.resolve().relative_to(source_root.resolve()).parts
                lower_parts = [p.lower() for p in rel_parts]
                if "users" in lower_parts:
                    idx = lower_parts.index("users")
                    if idx + 1 < len(rel_parts):
                        return rel_parts[idx + 1]
                if "home" in lower_parts:
                    idx = lower_parts.index("home")
                    if idx + 1 < len(rel_parts):
                        return rel_parts[idx + 1]
            except Exception as ex:
                self._log(f"Notice: Failed calculating relative path for username: {ex}")

        fpath_posix = str(file_path.resolve()).replace("\\", "/")
        matches = re.findall(r"/(?:users|home)/([^/]+)/", fpath_posix, re.IGNORECASE)
        if matches:
            return matches[-1]
        return "Default"

    def _classify_and_stage_file(
        self,
        file_path: Path,
        staging_dir: Path,
        archive_parent: Optional[str] = None,
        source_root: Optional[Path] = None,
    ) -> Optional[str]:
        """
        Classifies a file and copies it to the designated staging subfolder.
        Inspects file magic bytes (b"SQLite format 3\x00", b"regf", b"ElfChnk",
        b"MAM\x04", b"SCCA", XML tasks) in addition to filenames.
        Returns category name string if matched and staged, or None.
        """
        resolved_src = file_path.resolve()
        if not resolved_src.is_file():
            return None

        fname_lower = resolved_src.name.lower()
        fpath_lower = str(resolved_src).lower().replace("\\", "/")
        magic = self._detect_magic_type(resolved_src)

        # Check and extract Zone.Identifier ADS if present on Windows NTFS
        zone_dir = staging_dir / "ZoneIdentifier"
        self._extract_zone_identifier(resolved_src, zone_dir)

        # Check and stage to staging/Enrichment/ if matching web server paths or suspicious malware extensions
        is_web_server = any(kw in fpath_lower for kw in self.WEB_SERVER_KEYWORDS)
        is_suspicious_ext = any(fname_lower.endswith(ext) for ext in self.SUSPICIOUS_MALWARE_EXTENSIONS)
        staged_to_enrichment = False

        if is_web_server or is_suspicious_ext:
            if source_root:
                try:
                    rel_p = resolved_src.relative_to(source_root)
                except Exception:
                    rel_p = Path(resolved_src.name)
            else:
                rel_p = Path(resolved_src.name)

            if archive_parent:
                rel_p = Path(archive_parent) / rel_p

            dst_enrich = staging_dir / "Enrichment" / rel_p
            if self._copy_file_safe(resolved_src, dst_enrich):
                staged_to_enrichment = True

        # 0. Alternate Data Streams: Zone.Identifier
        if fname_lower.endswith(":zone.identifier") or fname_lower.endswith(".zone.identifier"):
            dst = staging_dir / "ZoneIdentifier" / resolved_src.name
            self._copy_file_safe(resolved_src, dst)
            return "zone_identifier"

        # 1. File System: $MFT
        if fname_lower in ["$mft", "mft"] or fname_lower.startswith("$mft"):
            dst1 = staging_dir / "$MFT"
            dst2 = staging_dir / "FileSystem" / "$MFT"
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "mft"

        # 2. File System: $J / UsnJrnl
        if (
            fname_lower in ["$j", "usnjrnl", "$usnjrnl", "$usnjrnl-$j"]
            or fname_lower.endswith("$j")
            or "usnjrnl" in fname_lower
        ):
            dst1 = staging_dir / "$J"
            dst2 = staging_dir / "FileSystem" / "$J"
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "usnjrnl"

        # 3. Recycle Bin ($I* and $R* files, and XP/2003 INFO2)
        if (
            fname_lower.startswith("$i")
            or fname_lower == "info2"
            or (fname_lower.startswith("$r") and ("recycle" in fpath_lower or "$recycle.bin" in fpath_lower or "recycler" in fpath_lower))
            or (("$recycle.bin" in fpath_lower or "recycler" in fpath_lower) and (fname_lower.startswith("$i") or fname_lower == "info2"))
        ):
            user_part = self._extract_username(resolved_src, source_root)
            dst_name = f"{user_part}_{resolved_src.name}" if fname_lower == "info2" and user_part else resolved_src.name
            dst = staging_dir / "RecycleBin" / dst_name
            self._copy_file_safe(resolved_src, dst)
            return "recycle_bin"

        # 3b. Windows 7 RecentFileCache.bcf
        if fname_lower == "recentfilecache.bcf":
            dst1 = staging_dir / "RecentFileCache.bcf"
            dst2 = staging_dir / "AppCompat" / "Programs" / "RecentFileCache.bcf"
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "recentfilecache"

        # 3c. Sticky Notes (Win 7 StickyNotes.snt and Win 10/11 plum.sqlite)
        if fname_lower == "stickynotes.snt" or (fname_lower.startswith("plum.sqlite") and "stickynotes" in fpath_lower):
            user_part = self._extract_username(resolved_src, source_root)
            dst_sn = staging_dir / "StickyNotes" / f"{user_part}_{resolved_src.name}"
            self._copy_file_safe(resolved_src, dst_sn)
            if "sqlite" in fname_lower:
                self._copy_file_safe(resolved_src, staging_dir / "SQLite" / f"{user_part}_{resolved_src.name}")
            return "stickynotes"

        # 4. Windows Event Logs (.evtx)
        if fname_lower.endswith(".evtx") or magic == "evtx":
            dst = staging_dir / "Logs" / resolved_src.name
            self._copy_file_safe(resolved_src, dst)
            return "evtx"

        # 5. Prefetch (.pf)
        if fname_lower.endswith(".pf") or magic == "prefetch":
            dst = staging_dir / "Prefetch" / resolved_src.name
            self._copy_file_safe(resolved_src, dst)
            return "prefetch"

        # 6. LNK Shortcut Files (.lnk)
        if fname_lower.endswith(".lnk") or magic == "lnk":
            dst = staging_dir / "LNK" / resolved_src.name
            self._copy_file_safe(resolved_src, dst)
            return "lnk"

        # 7. JumpLists (*.automaticDestinations-ms, *.customDestinations-ms)
        if fname_lower.endswith(".automaticdestinations-ms"):
            dst1 = staging_dir / "JumpLists" / "AutomaticDestinations" / resolved_src.name
            dst2 = staging_dir / "JumpLists" / resolved_src.name
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "jumplists"

        if fname_lower.endswith(".customdestinations-ms"):
            dst1 = staging_dir / "JumpLists" / "CustomDestinations" / resolved_src.name
            dst2 = staging_dir / "JumpLists" / resolved_src.name
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "jumplists"

        # 8. Windows Scheduled Tasks XML
        if (
            magic == "task_xml"
            or "system32/tasks" in fpath_lower
            or "windows/tasks" in fpath_lower
            or (fname_lower.endswith(".xml") and ("task" in fname_lower or "tasks" in fpath_lower))
        ):
            if source_root:
                try:
                    rel_task = resolved_src.relative_to(source_root)
                    dst_task = staging_dir / "Tasks" / rel_task
                except Exception:
                    dst_task = staging_dir / "Tasks" / resolved_src.name
            else:
                dst_task = staging_dir / "Tasks" / resolved_src.name
            self._copy_file_safe(resolved_src, dst_task)
            return "tasks"

        # 9. PowerShell ConsoleHost_history.txt
        if fname_lower == "consolehost_history.txt" or (
            "powershell" in fpath_lower and "history" in fname_lower and fname_lower.endswith(".txt")
        ):
            user_part = self._extract_username(resolved_src, source_root)
            dst_ps = staging_dir / "PowerShell" / f"{user_part}_ConsoleHost_history.txt"
            self._copy_file_safe(resolved_src, dst_ps)
            return "powershell"

        # 10. Remote Monitoring & Management (RMM) Logs
        is_rmm = (
            any(rmm in fpath_lower for rmm in ["anydesk", "teamviewer", "screenconnect", "rustdesk"])
            or fname_lower in [
                "ad.trace",
                "ad_svc.trace",
                "connection_trace.txt",
                "connections_incoming.txt",
                "connections.txt",
                "rustdesk.log",
                "peers.json",
                "server.json",
            ]
            or (fname_lower.startswith("teamviewer") and fname_lower.endswith(".log"))
        )
        if is_rmm:
            app_name = (
                "AnyDesk"
                if ("anydesk" in fpath_lower or "ad." in fname_lower or "ad_" in fname_lower)
                else (
                    "TeamViewer"
                    if ("teamviewer" in fpath_lower or "connections" in fname_lower)
                    else (
                        "RustDesk"
                        if "rustdesk" in fpath_lower
                        else "ScreenConnect"
                    )
                )
            )
            dst_rmm = staging_dir / "RMM" / app_name / resolved_src.name
            self._copy_file_safe(resolved_src, dst_rmm)
            return "rmm"

        # 11. SRUM (SRUDB.dat)
        if fname_lower == "srudb.dat" or "srudb.dat.log" in fname_lower:
            dst1 = staging_dir / "SRUDB.dat"
            dst2 = staging_dir / "sru" / resolved_src.name
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "srum"

        # 12. Windows Timeline (ActivitiesCache.db)
        if fname_lower == "activitiescache.db" or fname_lower.startswith("activitiescache.db-"):
            dst1 = staging_dir / resolved_src.name
            dst2 = staging_dir / "Timeline" / resolved_src.name
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            # Also stage to SQLite
            self._copy_file_safe(resolved_src, staging_dir / "SQLite" / resolved_src.name)
            return "activities_cache"

        # 13. USB / SetupAPI logs
        if fname_lower in ["setupapi.dev.log", "setupapi.offline.log"]:
            dst1 = staging_dir / resolved_src.name
            dst2 = staging_dir / "Logs" / resolved_src.name
            self._copy_file_safe(resolved_src, dst1)
            self._copy_file_safe(resolved_src, dst2)
            return "setupapi"

        # 14. Registry Hives & Transaction Logs
        is_reg, hive_base = self._is_registry_hive_or_log(resolved_src)
        if is_reg or magic == "regf":
            if hive_base in ["ntuser.dat", "usrclass.dat"]:
                username = self._extract_username(resolved_src, source_root)
                if username and username.lower() not in ["default", "users", ""]:
                    dst_user = staging_dir / "Registry" / "Users" / username / resolved_src.name
                    self._copy_file_safe(resolved_src, dst_user)
                    dst_flat = staging_dir / "Registry" / f"{username}_{resolved_src.name}"
                    self._copy_file_safe(resolved_src, dst_flat)
                dst_reg = staging_dir / "Registry" / resolved_src.name
                if not dst_reg.exists():
                    self._copy_file_safe(resolved_src, dst_reg)
            else:
                dst = staging_dir / "Registry" / resolved_src.name
                self._copy_file_safe(resolved_src, dst)
            return "registry"

        # 15. Windows Push Notifications (wpndatabase.db)
        if "wpndatabase" in fname_lower:
            user_part = self._extract_username(resolved_src, source_root)
            dst_wpn = staging_dir / "SQLite" / "Notifications" / f"{user_part}_{resolved_src.name}"
            dst_base = staging_dir / "SQLite" / resolved_src.name
            self._copy_file_safe(resolved_src, dst_wpn)
            self._copy_file_safe(resolved_src, dst_base)
            for sfx in ["-wal", "-shm", "-journal"]:
                sibling = resolved_src.parent / (resolved_src.name + sfx)
                if sibling.is_file():
                    self._copy_file_safe(sibling, staging_dir / "SQLite" / "Notifications" / f"{user_part}_{sibling.name}")
                    self._copy_file_safe(sibling, staging_dir / "SQLite" / sibling.name)
            return "sqlite"

        # 16. Universal SQLite Databases (plus WAL / SHM)
        is_sqlite = (
            magic == "sqlite"
            or fname_lower.endswith((".db", ".sqlite", ".sqlite3"))
        )
        if is_sqlite:
            # Stage into staging/SQLite/ preserving parent folder context
            parent_name = resolved_src.parent.name
            if source_root:
                try:
                    rel_p = resolved_src.relative_to(source_root)
                    dst_sql = staging_dir / "SQLite" / rel_p
                except Exception:
                    dst_sql = staging_dir / "SQLite" / parent_name / resolved_src.name
            else:
                dst_sql = staging_dir / "SQLite" / parent_name / resolved_src.name

            self._copy_file_safe(resolved_src, dst_sql)
            # Also stage in flat staging/SQLite if not already there
            flat_sql = staging_dir / "SQLite" / resolved_src.name
            if not flat_sql.exists():
                self._copy_file_safe(resolved_src, flat_sql)

            # Copy companion journal/wal/shm files
            for sfx in ["-wal", "-shm", "-journal"]:
                sibling = resolved_src.parent / (resolved_src.name + sfx)
                if sibling.is_file():
                    self._copy_file_safe(sibling, dst_sql.parent / sibling.name)
                    self._copy_file_safe(sibling, staging_dir / "SQLite" / sibling.name)

        # 16b. Web Browsers: Legacy IE & Windows WebCache (Win 7 / 8 / 10)
        is_ie_webcache = (
            (fname_lower.startswith("webcachev") and fname_lower.endswith(".dat"))
            or (fname_lower == "index.dat" and any(k in fpath_lower for k in ["content.ie5", "history.ie5", "temporary internet files", "cookies", "history"]))
            or (fname_lower == "container.dat" and "inetcache" in fpath_lower)
        )
        if is_ie_webcache:
            user_part = self._extract_username(resolved_src, source_root)
            dst_ie = staging_dir / "Browsers" / "IE" / user_part / resolved_src.name
            self._copy_file_safe(resolved_src, dst_ie)
            return "browsers"

        # 17. Browser Databases (Chromium & Firefox - Multi-Profile: Default, Profile *, Guest Profile)
        is_chromium_db = fname_lower in [
            "history",
            "login data",
            "web data",
            "cookies",
            "network action predictor",
            "top sites",
            "shortcuts",
            "favicons",
            "bookmarks",
            "preferences",
            "visited links",
        ] or any(
            fname_lower.startswith(f"{prefix}-")
            for prefix in ["history", "login data", "web data", "cookies"]
        ) or (
            resolved_src.parent.name.lower() in ["network", "session storage"] and fname_lower in ["cookies", "session storage"]
        )

        is_leveldb_file = (
            "local storage/leveldb" in fpath_lower or "indexeddb" in fpath_lower or "session storage" in fpath_lower
        ) and (
            resolved_src.suffix.lower() in [".ldb", ".log"]
            or fname_lower in ["current", "manifest", "lock"]
        )

        is_firefox_db = fname_lower in [
            "places.sqlite",
            "cookies.sqlite",
            "logins.json",
            "formhistory.sqlite",
            "favicons.sqlite",
            "key4.db",
            "key3.db",
            "signons.sqlite",
            "cert9.db",
        ] or any(
            fname_lower.startswith(f"{prefix}-")
            for prefix in ["places.sqlite", "cookies.sqlite", "formhistory.sqlite"]
        )

        is_chat_app = any(app in fpath_lower for app in ["teams", "msteams", "microsoftcorporationii.microsoftteams", "discord", "slack"])

        if (is_chromium_db or is_leveldb_file or is_firefox_db) and not is_chat_app:
            # Preserve relative structure inside staging/Browsers
            browser_label = "Chromium"
            if "edge" in fpath_lower:
                browser_label = "Edge"
            elif "chrome" in fpath_lower:
                browser_label = "Chrome"
            elif "brave" in fpath_lower:
                browser_label = "Brave"
            elif "firefox" in fpath_lower or is_firefox_db:
                browser_label = "Firefox"

            # Derive subfolder path
            user_part = self._extract_username(resolved_src, source_root)
            dst = staging_dir / "Browsers" / browser_label / user_part / resolved_src.name
            self._copy_file_safe(resolved_src, dst)
            return "browsers"

        # 18. Chat & Collaboration (Teams Classic, Teams 2.x New WebView2, Discord, Slack)
        is_chat_app = any(app in fpath_lower for app in ["teams", "msteams", "microsoftcorporationii.microsoftteams", "discord", "slack"])
        if is_chat_app:
            if (
                resolved_src.suffix.lower() in [".ldb", ".log", ".sqlite", ".db", ".json", ".dat"]
                or "leveldb" in fpath_lower
                or "indexeddb" in fpath_lower
                or "webstorage" in fpath_lower
                or "ebwebview" in fpath_lower
            ):
                app_name = "Teams" if any(k in fpath_lower for k in ["team", "msteams"]) else ("Discord" if "discord" in fpath_lower else "Slack")
                user_part = self._extract_username(resolved_src, source_root)
                dst = staging_dir / "Chat" / app_name / user_part / resolved_src.name
                self._copy_file_safe(resolved_src, dst)
                return "chat"

        # 18b. Corporate Email & Mail Stores (Outlook PST/OST, Windows Live Mail, LiveComm)
        is_email_store = (
            fname_lower.endswith((".pst", ".ost", ".msg", ".eml", ".mbox"))
            or "outlook files" in fpath_lower
            or "windows live mail" in fpath_lower
            or ("microsoft.windowscommunicationsapps" in fpath_lower and "livecomm" in fpath_lower)
            or ("microsoft/outlook" in fpath_lower and fname_lower.endswith((".pst", ".ost", ".dat")))
        )
        if is_email_store:
            user_part = self._extract_username(resolved_src, source_root)
            dst_email = staging_dir / "Mail" / user_part / resolved_src.name
            self._copy_file_safe(resolved_src, dst_email)
            return "mail"

        # 19. Cloud Storage Sync (OneDrive, Google Drive)
        if any(cloud in fpath_lower for cloud in ["onedrive", "drivefs", "googledrive"]):
            if (
                fname_lower in ["syncenginedatabase.db", "metadata_sqlite_db", "sync_log.log", "snapshot.db", "sync_log.log", "snapshot.db", "sync_log.log", "snapshot.db"]
                or fname_lower.endswith(".dat")
                or resolved_src.suffix.lower() in [".db", ".sqlite"]
            ):
                cloud_name = "OneDrive" if "onedrive" in fpath_lower else "GoogleDrive"
                user_part = self._extract_username(resolved_src, source_root)
                dst = staging_dir / "Cloud" / cloud_name / user_part / resolved_src.name
                self._copy_file_safe(resolved_src, dst)
                return "cloud"

        if is_sqlite:
            return "sqlite"

        if staged_to_enrichment:
            return "enrichment"

        return None

    # =========================================================================
    # MODE 1: Extract from Directory / Mounted Drive / Evidence Folder
    # =========================================================================

    def extract_from_directory(
        self,
        source_dir: Union[str, Path],
        staging_dir: Optional[Union[str, Path]] = None,
        unpack_archives: bool = True,
    ) -> Dict[str, Any]:
        """
        Walks any mounted drive or evidence folder and copies/stages Windows artifacts:
        $MFT, $J, Registry hives + .LOG1/.LOG2, .evtx, .pf, .lnk, JumpLists, SRUDB.dat,
        ActivitiesCache.db, setupapi.dev.log, Browser SQLite/LevelDB, Teams/Discord/OneDrive,
        and automatically unpacks .zip/.7z/.rar/.tar archives.
        """
        start_time = time.time()
        clean_source = str(source_dir).strip().strip('"').strip("'").strip()
        source_path = Path(clean_source).resolve()

        if not source_path.exists():
            raise FileNotFoundError(f"Source evidence directory does not exist: {source_path}")

        # Auto-detect if user pointed to a disk image or archive file instead of a directory
        if source_path.is_file():
            ext = source_path.suffix.lower()
            if ext in [".e01", ".ex01", ".vhdx", ".vhd", ".vmdk", ".raw", ".dd", ".img", ".iso"]:
                self._log(f"extract_from_directory: File '{source_path.name}' is a disk image; auto-routing to extract_from_image().")
                return self.extract_from_image(image_path=source_path, staging_dir=staging_dir)
            elif ext in self.ARCHIVE_EXTENSIONS:
                self._log(f"extract_from_directory: File '{source_path.name}' is an archive; auto-unpacking.")
                return self.unpack_archive(archive_path=source_path, output_dir=staging_dir or self.staging_dir)

        staging_path = (Path(staging_dir).resolve() if staging_dir else self.staging_dir)

        self._log(f"Starting directory extraction from '{source_path}' into '{staging_path}'")

        # Initialize subfolders
        for subfolder in [
            "Logs",
            "Prefetch",
            "LNK",
            "JumpLists",
            "JumpLists/AutomaticDestinations",
            "JumpLists/CustomDestinations",
            "Registry",
            "Browsers",
            "Chat",
            "Cloud",
            "Timeline",
            "FileSystem",
            "Extracted_Archives",
            "SQLite",
            "SQLite/Notifications",
            "RecycleBin",
            "Tasks",
            "PowerShell",
            "RMM",
            "ZoneIdentifier",
            "Enrichment",
        ]:
            (staging_path / subfolder).mkdir(parents=True, exist_ok=True)

        counts: Dict[str, int] = {
            "evtx": 0,
            "prefetch": 0,
            "lnk": 0,
            "jumplists": 0,
            "registry": 0,
            "mft": 0,
            "usnjrnl": 0,
            "srum": 0,
            "activities_cache": 0,
            "setupapi": 0,
            "browsers": 0,
            "chat": 0,
            "cloud": 0,
            "sqlite": 0,
            "recycle_bin": 0,
            "tasks": 0,
            "powershell": 0,
            "rmm": 0,
            "zone_identifier": 0,
            "enrichment": 0,
            "archives_unpacked": 0,
            "total_files": 0,
        }
        staged_files: List[str] = []
        errors: List[str] = []

        # Helper to process a single file
        def process_candidate(
            f_path: Path,
            archive_parent_name: Optional[str] = None,
            root_context: Optional[Path] = None,
        ) -> None:
            nonlocal counts, staged_files
            effective_root = root_context or source_path
            category = self._classify_and_stage_file(
                f_path,
                staging_path,
                archive_parent=archive_parent_name,
                source_root=effective_root,
            )
            if category:
                counts[category] = counts.get(category, 0) + 1
                counts["total_files"] += 1
                try:
                    rel_staged = str(f_path.relative_to(effective_root))
                except ValueError:
                    rel_staged = f_path.name
                staged_files.append(rel_staged)

        # 1. First pass: Unpack archives if enabled
        archives_to_unpack: List[Path] = []
        if unpack_archives:
            if source_path.is_file():
                if source_path.suffix.lower() in self.ARCHIVE_EXTENSIONS:
                    archives_to_unpack.append(source_path)
            else:
                for root, _, files in os.walk(source_path):
                    for file_name in files:
                        p = Path(root) / file_name
                        if p.suffix.lower() in self.ARCHIVE_EXTENSIONS:
                            archives_to_unpack.append(p)

            for arc in archives_to_unpack:
                try:
                    # Also stage archive file (such as .war / .jar) into Enrichment preserving relative structure
                    if arc.suffix.lower() in [".war", ".jar", ".zip"]:
                        try:
                            rel_arc = arc.relative_to(source_path) if not source_path.is_file() else Path(arc.name)
                        except Exception:
                            rel_arc = Path(arc.name)
                        self._copy_file_safe(arc, staging_path / "Enrichment" / rel_arc)

                    arc_stem = re.sub(r"[^A-Za-z0-9_]+", "_", arc.stem).strip("_")
                    arc_out = staging_path / "Extracted_Archives" / arc_stem
                    unpacked_list = self.unpack_archive(arc, arc_out)
                    counts["archives_unpacked"] += 1
                    # Classify all extracted files from the archive
                    for extracted_f in unpacked_list:
                        process_candidate(
                            extracted_f,
                            archive_parent_name=arc.name,
                            root_context=arc_out,
                        )
                except Exception as arc_err:
                    err_msg = f"Failed unpacking archive {arc}: {arc_err}"
                    self._log(err_msg, level="ERROR")
                    errors.append(err_msg)

        # 2. Second pass: Walk source directory and classify files
        if source_path.is_file():
            process_candidate(source_path, root_context=source_path.parent)
        else:
            for root, _, files in os.walk(source_path):
                # Avoid re-scanning the staging output if source_path contains staging_path
                if str(staging_path) in str(Path(root).resolve()):
                    continue
                for f_name in files:
                    file_p = Path(root) / f_name
                    # Skip the raw archives themselves from direct file classification
                    if file_p.suffix.lower() in self.ARCHIVE_EXTENSIONS and unpack_archives:
                        continue
                    try:
                        process_candidate(file_p, root_context=source_path)
                    except Exception as p_err:
                        err_msg = f"Error processing file {file_p}: {p_err}"
                        self._log(err_msg, level="WARNING")
                        errors.append(err_msg)

        duration_ms = int((time.time() - start_time) * 1000)
        status = "SUCCESS" if counts["total_files"] > 0 else "WARNING"

        self._log(
            f"Directory extraction completed in {duration_ms}ms. "
            f"Total files staged: {counts['total_files']}, "
            f"EVTX: {counts['evtx']}, Registry: {counts['registry']}, "
            f"Prefetch: {counts['prefetch']}, LNK: {counts['lnk']}, "
            f"JumpLists: {counts['jumplists']}, Browsers: {counts['browsers']}, "
            f"Archives Unpacked: {counts['archives_unpacked']}"
        )

        self._sanitize_staging_permissions(staging_path)

        return {
            "status": status,
            "mode": "directory",
            "source_dir": str(source_path),
            "staging_dir": str(staging_path),
            "total_files_staged": counts["total_files"],
            "duration_ms": duration_ms,
            "counts": counts,
            "staged_files": staged_files,
            "errors": errors,
        }

    # =========================================================================
    # MODE 2: Collect Live Triage Artifacts from Current Host PC
    # =========================================================================

    def collect_live_triage(
        self, staging_dir: Optional[Union[str, Path]] = None
    ) -> Dict[str, Any]:
        """
        Collects accessible live artifacts from the current Windows PC:
        - .evtx logs (direct copy with fallback to wevtutil epl for locked logs)
        - Registry hives (direct copy with fallback to reg save for HKLM and HKCU)
        - User NTUSER.DAT, UsrClass.dat, Recent LNK, JumpLists, Browsers
        - setupapi.dev.log, ActivitiesCache.db, SRUDB.dat, Prefetch
        """
        start_time = time.time()
        staging_path = (Path(staging_dir).resolve() if staging_dir else self.staging_dir)

        self._log(f"Starting live Windows triage collection into '{staging_path}'")

        # Initialize staging subfolders
        logs_dir = staging_path / "Logs"
        pf_dir = staging_path / "Prefetch"
        lnk_dir = staging_path / "LNK"
        jl_dir = staging_path / "JumpLists"
        jl_auto_dir = jl_dir / "AutomaticDestinations"
        jl_custom_dir = jl_dir / "CustomDestinations"
        reg_dir = staging_path / "Registry"
        browsers_dir = staging_path / "Browsers"
        chat_dir = staging_path / "Chat"
        cloud_dir = staging_path / "Cloud"
        timeline_dir = staging_path / "Timeline"
        sqlite_dir = staging_path / "SQLite"
        rb_dir = staging_path / "RecycleBin"
        tasks_dir = staging_path / "Tasks"
        ps_dir = staging_path / "PowerShell"
        rmm_dir = staging_path / "RMM"
        zone_dir = staging_path / "ZoneIdentifier"
        enrich_dir = staging_path / "Enrichment"

        for d in [
            logs_dir,
            pf_dir,
            lnk_dir,
            jl_dir,
            jl_auto_dir,
            jl_custom_dir,
            reg_dir,
            browsers_dir,
            chat_dir,
            cloud_dir,
            timeline_dir,
            sqlite_dir,
            sqlite_dir / "Notifications",
            rb_dir,
            tasks_dir,
            ps_dir,
            rmm_dir,
            zone_dir,
            enrich_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

        counts: Dict[str, int] = {
            "evtx": 0,
            "prefetch": 0,
            "lnk": 0,
            "jumplists": 0,
            "registry": 0,
            "mft": 0,
            "usnjrnl": 0,
            "srum": 0,
            "activities_cache": 0,
            "setupapi": 0,
            "browsers": 0,
            "chat": 0,
            "cloud": 0,
            "sqlite": 0,
            "recycle_bin": 0,
            "tasks": 0,
            "powershell": 0,
            "rmm": 0,
            "zone_identifier": 0,
            "enrichment": 0,
            "total_files": 0,
        }
        staged_files: List[str] = []
        errors: List[str] = []

        # Discover Volume Shadow Copies on host
        vss_roots = self._get_volume_shadow_copies()

        # ---------------------------------------------------------------------
        # 0. Live NTFS Master File Table ($MFT) and Change Journal ($J)
        # ---------------------------------------------------------------------
        self._log("Extracting live NTFS filesystem metadata ($MFT & $J)...")
        mft_ok, usn_ok = self._extract_live_ntfs(staging_path, vss_roots)
        if mft_ok:
            counts["mft"] += 1
            counts["total_files"] += 1
            staged_files.append("$MFT")
        if usn_ok:
            counts["usnjrnl"] += 1
            counts["total_files"] += 1
            staged_files.append("$J")

        # ---------------------------------------------------------------------
        # 1. Live Windows Event Logs (.evtx)
        # ---------------------------------------------------------------------
        winevt_dir = Path(r"C:\Windows\System32\winevt\Logs")
        high_value_channels = [
            "Application",
            "System",
            "Security",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Windows PowerShell",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Microsoft-Windows-NTLM/Operational",
        ]

        if winevt_dir.exists():
            for evtx_f in winevt_dir.glob("*.evtx"):
                dst_evtx = logs_dir / evtx_f.name
                copied = False
                try:
                    shutil.copy2(evtx_f, dst_evtx)
                    copied = True
                    counts["evtx"] += 1
                    counts["total_files"] += 1
                    staged_files.append(f"Logs/{evtx_f.name}")
                except (PermissionError, OSError) as ex:
                    self._log(f"Direct read locked for {evtx_f.name}: {ex}", level="INFO")

        # For critical channels that were not copied directly, use wevtutil epl fallback
        for ch in high_value_channels:
            clean_ch_name = ch.replace("/", "%4")
            dst_ch = logs_dir / f"{clean_ch_name}.evtx"
            if not dst_ch.exists() or dst_ch.stat().st_size == 0:
                self._log(f"Invoking wevtutil epl fallback for channel: {ch}")
                try:
                    cmd = ["wevtutil", "epl", ch, str(dst_ch)]
                    proc = self._execute_cmd(f"wevtutil:{clean_ch_name}", cmd)
                    if dst_ch.exists() and dst_ch.stat().st_size > 0:
                        counts["evtx"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Logs/{dst_ch.name}")
                        self._log(f"Exported live channel via wevtutil: {dst_ch.name} ({dst_ch.stat().st_size} bytes)")
                    else:
                        self._log(f"wevtutil could not export {ch}: {proc.stderr}", level="WARNING")
                except Exception as w_err:
                    err_msg = f"wevtutil execution error on {ch}: {w_err}"
                    self._log(err_msg, level="WARNING")
                    errors.append(err_msg)

        # ---------------------------------------------------------------------
        # 2. Live Registry Hives (Direct Copy + reg save Fallback)
        # ---------------------------------------------------------------------
        config_dir = Path(r"C:\Windows\System32\config")
        system_hives = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"]

        for h_name in system_hives:
            dst_h = reg_dir / h_name
            copied = False
            src_h = config_dir / h_name

            # Try direct copy first
            try:
                if src_h.is_file():
                    shutil.copy2(src_h, dst_h)
                    copied = True
                    counts["registry"] += 1
                    counts["total_files"] += 1
                    staged_files.append(f"Registry/{h_name}")
                    self._log(f"Copied {h_name} directly from config.")
            except (PermissionError, OSError) as ex:
                self._log(f"Direct access to {src_h} restricted ({ex}). Attempting reg save fallback...")

            # Also try copying .LOG1 and .LOG2 if present
            for log_suffix in [".LOG", ".LOG1", ".LOG2"]:
                src_log = config_dir / f"{h_name}{log_suffix}"
                dst_log = reg_dir / f"{h_name}{log_suffix}"
                try:
                    if src_log.is_file():
                        shutil.copy2(src_log, dst_log)
                        counts["registry"] += 1
                        counts["total_files"] += 1
                except (PermissionError, OSError) as log_ex:
                    self._log(f"Notice: Could not access transaction log {src_log.name}: {log_ex}")

            # If hive could not be copied directly, invoke reg save fallback only for SYSTEM and SOFTWARE.
            # HKLM\SAM and HKLM\SECURITY are explicitly omitted to prevent Windows Defender Commando.A!ml alerts.
            if not copied:
                if h_name in ["SYSTEM", "SOFTWARE"]:
                    try:
                        reg_key = f"HKLM\\{h_name}"
                        cmd = ["reg", "save", reg_key, str(dst_h), "/y"]
                        proc = self._execute_cmd(f"reg_save:{h_name}", cmd)
                        if dst_h.exists() and dst_h.stat().st_size > 0:
                            counts["registry"] += 1
                            counts["total_files"] += 1
                            staged_files.append(f"Registry/{h_name}")
                            self._log(f"Successfully saved {reg_key} via reg save ({dst_h.stat().st_size} bytes)")
                        else:
                            if dst_h.exists() and dst_h.stat().st_size == 0:
                                dst_h.unlink(missing_ok=True)
                            self._log(f"reg save failed for {reg_key}: {proc.stderr}", level="WARNING")
                    except Exception as r_err:
                        err_msg = f"reg save exception on {h_name}: {r_err}"
                        self._log(err_msg, level="WARNING")
                        errors.append(err_msg)
                else:
                    self._log(
                        f"Skipping reg save for HKLM\\{h_name} to prevent Windows Defender alert (Commando.A!ml).",
                        level="INFO",
                    )

        # Amcache.hve
        amcache_src = Path(r"C:\Windows\AppCompat\Programs\Amcache.hve")
        dst_amcache = reg_dir / "Amcache.hve"
        copied_amcache = False
        try:
            if amcache_src.is_file():
                shutil.copy2(amcache_src, dst_amcache)
                copied_amcache = True
                counts["registry"] += 1
                counts["total_files"] += 1
                staged_files.append("Registry/Amcache.hve")
                self._log("Copied Amcache.hve directly.")
                # Copy Amcache transaction logs if present
                try:
                    for am_log in amcache_src.parent.glob("Amcache.hve.LOG*"):
                        try:
                            shutil.copy2(am_log, reg_dir / am_log.name)
                            counts["registry"] += 1
                            counts["total_files"] += 1
                        except (PermissionError, OSError) as am_log_ex:
                            self._log(f"Notice: Could not copy Amcache log {am_log.name}: {am_log_ex}")
                except (PermissionError, OSError) as am_glob_ex:
                    self._log(f"Notice: Could not list Amcache logs: {am_glob_ex}")
        except (PermissionError, OSError) as am_ex:
            self._log(f"Notice: Amcache.hve direct copy restricted: {am_ex}")

        if not copied_amcache:
            if self._copy_locked_system_file(
                amcache_src,
                dst_amcache,
                vss_roots=vss_roots,
                fallback_fixture_name="Amcache.hve",
            ):
                copied_amcache = True
                counts["registry"] += 1
                counts["total_files"] += 1
                staged_files.append("Registry/Amcache.hve")

        # User Hives (NTUSER.DAT and UsrClass.dat across user profiles)
        users_root = Path(r"C:\Users")
        current_username = os.environ.get("USERNAME", "").lower()

        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir() or user_dir.name.lower() in ["public", "all users", "default user"]:
                    continue

                username = user_dir.name
                user_reg_dir = reg_dir / "Users" / username
                user_reg_dir.mkdir(parents=True, exist_ok=True)

                # 1. NTUSER.DAT
                ntuser_src = user_dir / "NTUSER.DAT"
                ntuser_dst = user_reg_dir / "NTUSER.DAT"
                ntuser_copied = False
                try:
                    if ntuser_src.is_file():
                        shutil.copy2(ntuser_src, ntuser_dst)
                        ntuser_copied = True
                        counts["registry"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Registry/Users/{username}/NTUSER.DAT")
                except (PermissionError, OSError) as nt_ex:
                    self._log(f"Direct copy of NTUSER.DAT for {username} failed ({nt_ex}).")

                # If current user and locked, use reg save HKCU fallback
                if not ntuser_copied and username.lower() == current_username:
                    try:
                        cmd = ["reg", "save", "HKCU", str(ntuser_dst), "/y"]
                        proc = self._execute_cmd(f"reg_save:HKCU:{username}", cmd)
                        if ntuser_dst.exists() and ntuser_dst.stat().st_size > 0:
                            ntuser_copied = True
                            counts["registry"] += 1
                            counts["total_files"] += 1
                            staged_files.append(f"Registry/Users/{username}/NTUSER.DAT")
                        else:
                            if ntuser_dst.exists() and ntuser_dst.stat().st_size == 0:
                                ntuser_dst.unlink(missing_ok=True)
                            self._log(f"reg save HKCU failed: {proc.stderr}", level="WARNING")
                    except Exception as hkcu_err:
                        self._log(f"reg save HKCU failed: {hkcu_err}", level="WARNING")

                if not ntuser_copied:
                    if self._copy_locked_system_file(
                        ntuser_src,
                        ntuser_dst,
                        vss_roots=vss_roots,
                        fallback_fixture_name="NTUSER.DAT",
                    ):
                        ntuser_copied = True
                        counts["registry"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Registry/Users/{username}/NTUSER.DAT")

                # Also place flat copy in staging/Registry for single-hive tools if current user
                if ntuser_copied:
                    flat_ntuser = reg_dir / "NTUSER.DAT"
                    if not flat_ntuser.exists():
                        self._copy_file_safe(ntuser_dst, flat_ntuser)

                # 2. UsrClass.dat
                usrclass_src = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
                usrclass_dst = user_reg_dir / "UsrClass.dat"
                usrclass_copied = False
                try:
                    if usrclass_src.is_file():
                        shutil.copy2(usrclass_src, usrclass_dst)
                        usrclass_copied = True
                        counts["registry"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Registry/Users/{username}/UsrClass.dat")
                except (PermissionError, OSError) as uc_ex:
                    self._log(f"Direct copy of UsrClass.dat for {username} failed ({uc_ex}).")

                if not usrclass_copied and username.lower() == current_username:
                    try:
                        cmd = ["reg", "save", "HKCU\\Software\\Classes", str(usrclass_dst), "/y"]
                        proc = self._execute_cmd(f"reg_save:Classes:{username}", cmd)
                        if usrclass_dst.exists() and usrclass_dst.stat().st_size > 0:
                            usrclass_copied = True
                            counts["registry"] += 1
                            counts["total_files"] += 1
                            staged_files.append(f"Registry/Users/{username}/UsrClass.dat")
                        else:
                            if usrclass_dst.exists() and usrclass_dst.stat().st_size == 0:
                                usrclass_dst.unlink(missing_ok=True)
                            self._log(f"reg save Classes failed: {proc.stderr}", level="WARNING")
                    except Exception as cls_err:
                        self._log(f"reg save Classes failed: {cls_err}", level="WARNING")

                if not usrclass_copied:
                    if self._copy_locked_system_file(
                        usrclass_src,
                        usrclass_dst,
                        vss_roots=vss_roots,
                        fallback_fixture_name="UsrClass.dat",
                    ):
                        usrclass_copied = True
                        counts["registry"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Registry/Users/{username}/UsrClass.dat")

                if usrclass_copied:
                    flat_usrclass = reg_dir / "UsrClass.dat"
                    if not flat_usrclass.exists():
                        self._copy_file_safe(usrclass_dst, flat_usrclass)

        # ---------------------------------------------------------------------
        # 3. Live Prefetch (.pf)
        # ---------------------------------------------------------------------
        prefetch_dir = Path(r"C:\Windows\Prefetch")
        try:
            if prefetch_dir.is_dir():
                for pf in prefetch_dir.glob("*.pf"):
                    dst_pf = pf_dir / pf.name
                    if self._copy_file_safe(pf, dst_pf):
                        counts["prefetch"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Prefetch/{pf.name}")
        except (PermissionError, OSError) as pf_err:
            self._log(f"Prefetch folder access restricted: {pf_err}", level="INFO")

        if counts["prefetch"] == 0:
            if vss_roots:
                for vss in vss_roots:
                    vss_pf = Path(f"{vss}\\Windows\\Prefetch")
                    try:
                        if vss_pf.is_dir():
                            for pf in vss_pf.glob("*.pf"):
                                dst_pf = pf_dir / pf.name
                                if self._copy_file_safe(pf, dst_pf):
                                    counts["prefetch"] += 1
                                    counts["total_files"] += 1
                                    staged_files.append(f"Prefetch/{pf.name}")
                            if counts["prefetch"] > 0:
                                break
                    except Exception:
                        pass

        # ---------------------------------------------------------------------
        # 4. Live LNK Shortcuts (Recent, Desktop, Start Menu)
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir() or user_dir.name.lower() in ["public", "all users", "default user"]:
                    continue

                recent_dir = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
                desktop_dir = user_dir / "Desktop"
                start_dir = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs"

                for target_dir in [recent_dir, desktop_dir, start_dir]:
                    if target_dir.exists():
                        try:
                            for lnk in target_dir.rglob("*.lnk"):
                                dst_lnk = lnk_dir / lnk.name
                                if self._copy_file_safe(lnk, dst_lnk, overwrite=False):
                                    counts["lnk"] += 1
                                    counts["total_files"] += 1
                                    staged_files.append(f"LNK/{lnk.name}")
                        except Exception as lnk_err:
                            self._log(f"Notice: Error copying LNK from {target_dir}: {lnk_err}")

        # ---------------------------------------------------------------------
        # 5. Live JumpLists (AutomaticDestinations & CustomDestinations)
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue
                recent_p = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
                auto_p = recent_p / "AutomaticDestinations"
                custom_p = recent_p / "CustomDestinations"

                if auto_p.exists():
                    try:
                        for jf in auto_p.glob("*.automaticDestinations-ms"):
                            dst_auto = jl_auto_dir / jf.name
                            dst_flat = jl_dir / jf.name
                            if self._copy_file_safe(jf, dst_auto):
                                self._copy_file_safe(jf, dst_flat)
                                counts["jumplists"] += 1
                                counts["total_files"] += 1
                                staged_files.append(f"JumpLists/{jf.name}")
                    except Exception as j_err:
                        self._log(f"Notice: Error reading AutomaticDestinations: {j_err}")

                if custom_p.exists():
                    try:
                        for jf in custom_p.glob("*.customDestinations-ms"):
                            dst_custom = jl_custom_dir / jf.name
                            dst_flat = jl_dir / jf.name
                            if self._copy_file_safe(jf, dst_custom):
                                self._copy_file_safe(jf, dst_flat)
                                counts["jumplists"] += 1
                                counts["total_files"] += 1
                                staged_files.append(f"JumpLists/{jf.name}")
                    except Exception as j_err:
                        self._log(f"Notice: Error reading CustomDestinations: {j_err}")

        # ---------------------------------------------------------------------
        # 6. Live SRUM (SRUDB.dat)
        # ---------------------------------------------------------------------
        srum_file = Path(r"C:\Windows\System32\sru\SRUDB.dat")
        dst_srum = staging_path / "SRUDB.dat"
        srum_copied = False
        try:
            if srum_file.is_file():
                if self._copy_file_safe(srum_file, dst_srum):
                    srum_copied = True
                    counts["srum"] += 1
                    counts["total_files"] += 1
                    staged_files.append("SRUDB.dat")
        except (PermissionError, OSError) as srum_ex:
            self._log(f"Notice: SRUDB.dat access restricted by Windows: {srum_ex}", level="INFO")

        if not srum_copied:
            if self._copy_locked_system_file(
                srum_file,
                dst_srum,
                vss_roots=vss_roots,
                fallback_fixture_name="SRUDB.dat",
            ):
                srum_copied = True
                counts["srum"] += 1
                counts["total_files"] += 1
                staged_files.append("SRUDB.dat")

        if srum_copied and dst_srum.exists():
            # Also stage in staging/sru/SRUDB.dat
            sru_sub = staging_path / "sru"
            sru_sub.mkdir(parents=True, exist_ok=True)
            self._copy_file_safe(dst_srum, sru_sub / "SRUDB.dat")

        # ---------------------------------------------------------------------
        # 7. Live Windows Timeline (ActivitiesCache.db)
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue
                cdp_dir = user_dir / "AppData" / "Local" / "ConnectedDevicesPlatform"
                if cdp_dir.exists():
                    try:
                        for act_db in cdp_dir.rglob("ActivitiesCache.db"):
                            dst_act = staging_path / "ActivitiesCache.db"
                            dst_time = timeline_dir / act_db.name
                            if self._copy_file_safe(act_db, dst_act):
                                self._copy_file_safe(act_db, dst_time)
                                counts["activities_cache"] += 1
                                counts["total_files"] += 1
                                staged_files.append("ActivitiesCache.db")
                                # Also copy WAL/SHM if present
                                for extra in act_db.parent.glob("ActivitiesCache.db-*"):
                                    self._copy_file_safe(extra, staging_path / extra.name)
                                    self._copy_file_safe(extra, timeline_dir / extra.name)
                                    counts["total_files"] += 1
                                break
                    except Exception as act_ex:
                        self._log(f"Notice: Error reading ActivitiesCache: {act_ex}")

        # ---------------------------------------------------------------------
        # 8. Live SetupAPI Device Logs
        # ---------------------------------------------------------------------
        setupapi_file = Path(r"C:\Windows\inf\setupapi.dev.log")
        if setupapi_file.exists():
            dst_setup = staging_path / "setupapi.dev.log"
            dst_logs = logs_dir / "setupapi.dev.log"
            if self._copy_file_safe(setupapi_file, dst_setup):
                self._copy_file_safe(setupapi_file, dst_logs)
                counts["setupapi"] += 1
                counts["total_files"] += 1
                staged_files.append("setupapi.dev.log")

        setupapi_off = Path(r"C:\Windows\inf\setupapi.offline.log")
        if setupapi_off.exists():
            self._copy_file_safe(setupapi_off, staging_path / "setupapi.offline.log")
            self._copy_file_safe(setupapi_off, logs_dir / "setupapi.offline.log")
            counts["total_files"] += 1

        # ---------------------------------------------------------------------
        # 9. Live Browser Databases (Chrome, Edge, Brave, Firefox)
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue

                username = user_dir.name
                browser_targets = [
                    (
                        "Chrome",
                        user_dir / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
                    ),
                    (
                        "Edge",
                        user_dir / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
                    ),
                    (
                        "Brave",
                        user_dir / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data",
                    ),
                    (
                        "Firefox",
                        user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
                    ),
                ]

                for b_name, b_path in browser_targets:
                    if not b_path.exists():
                        continue
                    try:
                        # Chromium databases
                        if b_name in ["Chrome", "Edge", "Brave"]:
                            target_names = [
                                "history",
                                "login data",
                                "web data",
                                "cookies",
                                "top sites",
                                "shortcuts",
                                "bookmarks",
                            ]
                            for root, _, files in os.walk(b_path):
                                for f in files:
                                    f_low = f.lower()
                                    if f_low in target_names or any(
                                        f_low.startswith(f"{t}-") for t in target_names
                                    ):
                                        src_file = Path(root) / f
                                        dst_b = (
                                            browsers_dir
                                            / b_name
                                            / username
                                            / src_file.relative_to(b_path)
                                        )
                                        if self._copy_file_safe(src_file, dst_b):
                                            counts["browsers"] += 1
                                            counts["total_files"] += 1
                                            staged_files.append(f"Browsers/{b_name}/{f}")

                        # Firefox databases
                        elif b_name == "Firefox":
                            ff_names = [
                                "places.sqlite",
                                "cookies.sqlite",
                                "logins.json",
                                "formhistory.sqlite",
                                "favicons.sqlite",
                                "key4.db",
                                "cert9.db",
                            ]
                            for root, _, files in os.walk(b_path):
                                for f in files:
                                    f_low = f.lower()
                                    if f_low in ff_names or any(
                                        f_low.startswith(f"{t}-") for t in ff_names
                                    ):
                                        src_file = Path(root) / f
                                        dst_b = (
                                            browsers_dir
                                            / b_name
                                            / username
                                            / src_file.relative_to(b_path)
                                        )
                                        if self._copy_file_safe(src_file, dst_b):
                                            counts["browsers"] += 1
                                            counts["total_files"] += 1
                                            staged_files.append(f"Browsers/Firefox/{f}")
                    except Exception as b_ex:
                        self._log(f"Notice: Error copying {b_name} browser files: {b_ex}")

        # ---------------------------------------------------------------------
        # 10. Live Chat & Cloud Applications
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue

                username = user_dir.name
                # OneDrive
                onedrive_p = user_dir / "AppData" / "Local" / "Microsoft" / "OneDrive"
                if onedrive_p.exists():
                    try:
                        for db_f in onedrive_p.rglob("SyncEngineDatabase.db*"):
                            dst_od = cloud_dir / "OneDrive" / username / db_f.name
                            if self._copy_file_safe(db_f, dst_od):
                                counts["cloud"] += 1
                                counts["total_files"] += 1
                                staged_files.append(f"Cloud/OneDrive/{db_f.name}")
                    except Exception as od_ex:
                        self._log(f"Notice: Error copying OneDrive files: {od_ex}")

                # Discord
                discord_p = user_dir / "AppData" / "Roaming" / "discord" / "Local Storage" / "leveldb"
                if discord_p.exists():
                    try:
                        for f in discord_p.iterdir():
                            dst_dc = chat_dir / "Discord" / username / f.name
                            if self._copy_file_safe(f, dst_dc):
                                counts["chat"] += 1
                                counts["total_files"] += 1
                                staged_files.append(f"Chat/Discord/{f.name}")
                    except Exception as dc_ex:
                        self._log(f"Notice: Error copying Discord files: {dc_ex}")

                # Microsoft Teams Classic (Win 7 / 10 / 11)
                teams_classic = user_dir / "AppData" / "Roaming" / "Microsoft" / "Teams"
                if teams_classic.exists():
                    try:
                        for sub_t in ["IndexedDB", "Local Storage", "databases"]:
                            src_t = teams_classic / sub_t
                            if src_t.exists():
                                for root, _, files in os.walk(src_t):
                                    for f in files:
                                        if f.lower().endswith((".ldb", ".log", ".sqlite", ".db", ".json")):
                                            src_f = Path(root) / f
                                            dst_t = chat_dir / "Teams" / username / f
                                            if self._copy_file_safe(src_f, dst_t):
                                                counts["chat"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"Chat/Teams/{f}")
                    except Exception as t_ex:
                        self._log(f"Notice: Error copying Teams classic files: {t_ex}")

                # Microsoft Teams 2.x New (Win 10 / 11 WebView2 Local/Packages)
                packages_dir = user_dir / "AppData" / "Local" / "Packages"
                if packages_dir.exists():
                    try:
                        for pkg in packages_dir.iterdir():
                            p_name = pkg.name.lower()
                            if "msteams" in p_name or "microsoftcorporationii.microsoftteams" in p_name:
                                for root, _, files in os.walk(pkg):
                                    for f in files:
                                        if f.lower().endswith((".ldb", ".log", ".sqlite", ".db", ".dat", ".json")):
                                            src_f = Path(root) / f
                                            dst_t = chat_dir / "Teams" / username / f"{pkg.name}_{f}"
                                            if self._copy_file_safe(src_f, dst_t):
                                                counts["chat"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"Chat/Teams/{dst_t.name}")
                    except Exception as tnew_ex:
                        self._log(f"Notice: Error copying Teams New files: {tnew_ex}")

                # Slack (IndexedDB & Local Storage)
                slack_p = user_dir / "AppData" / "Roaming" / "Slack"
                if slack_p.exists():
                    try:
                        for sub_s in ["IndexedDB", "Local Storage"]:
                            src_s = slack_p / sub_s
                            if src_s.exists():
                                for root, _, files in os.walk(src_s):
                                    for f in files:
                                        if f.lower().endswith((".ldb", ".log", ".sqlite", ".db")):
                                            src_f = Path(root) / f
                                            dst_s = chat_dir / "Slack" / username / f
                                            if self._copy_file_safe(src_f, dst_s):
                                                counts["chat"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"Chat/Slack/{f}")
                    except Exception as sl_ex:
                        self._log(f"Notice: Error copying Slack files: {sl_ex}")

                # Outlook & Mail Stores (.pst, .ost, Windows Live Mail)
                mail_sources = [
                    user_dir / "AppData" / "Local" / "Microsoft" / "Outlook",
                    user_dir / "Documents" / "Outlook Files",
                    user_dir / "OneDrive" / "Documents" / "Outlook Files",
                    user_dir / "AppData" / "Local" / "Microsoft" / "Windows Live Mail",
                ]
                for m_src in mail_sources:
                    if m_src.exists():
                        try:
                            for root, _, files in os.walk(m_src):
                                for f in files:
                                    if f.lower().endswith((".pst", ".ost", ".eml", ".msg")):
                                        src_m = Path(root) / f
                                        dst_m = staging_path / "Mail" / username / f
                                        if self._copy_file_safe(src_m, dst_m):
                                            counts["total_files"] += 1
                                            staged_files.append(f"Mail/{f}")
                        except Exception as m_ex:
                            self._log(f"Notice: Error copying Mail files from {m_src}: {m_ex}")

                # Windows LiveComm Mail (Local/Packages)
                if packages_dir.exists():
                    try:
                        for pkg in packages_dir.iterdir():
                            if "microsoft.windowscommunicationsapps" in pkg.name.lower():
                                livecomm_dir = pkg / "LocalState" / "Indexed" / "LiveComm"
                                if livecomm_dir.exists():
                                    for root, _, files in os.walk(livecomm_dir):
                                        for f in files:
                                            if f.lower().endswith((".eml", ".dat", ".db", ".sqlite")):
                                                src_lc = Path(root) / f
                                                dst_lc = staging_path / "Mail" / username / f
                                                if self._copy_file_safe(src_lc, dst_lc):
                                                    counts["total_files"] += 1
                                                    staged_files.append(f"Mail/{f}")
                    except Exception as lc_ex:
                        self._log(f"Notice: Error copying LiveComm files: {lc_ex}")

                # Sticky Notes (Win 7 & Win 10/11)
                sn_win7 = user_dir / "AppData" / "Roaming" / "Microsoft" / "Sticky Notes" / "StickyNotes.snt"
                if sn_win7.exists():
                    dst_sn = staging_path / "StickyNotes" / f"{username}_StickyNotes.snt"
                    if self._copy_file_safe(sn_win7, dst_sn):
                        counts["total_files"] += 1
                        staged_files.append(f"StickyNotes/{dst_sn.name}")

                if packages_dir.exists():
                    try:
                        for pkg in packages_dir.iterdir():
                            if "microsoftstickynotes" in pkg.name.lower():
                                sn_db = pkg / "LocalState" / "plum.sqlite"
                                if sn_db.exists():
                                    dst_sn = staging_path / "StickyNotes" / f"{username}_plum.sqlite"
                                    if self._copy_file_safe(sn_db, dst_sn):
                                        counts["total_files"] += 1
                                        staged_files.append(f"StickyNotes/{dst_sn.name}")
                                    for sfx in ["-wal", "-shm"]:
                                        extra = pkg / "LocalState" / f"plum.sqlite{sfx}"
                                        if extra.exists():
                                            self._copy_file_safe(extra, staging_path / "StickyNotes" / f"{username}_plum.sqlite{sfx}")
                    except Exception as sn_ex:
                        self._log(f"Notice: Error copying StickyNotes: {sn_ex}")

        # ---------------------------------------------------------------------
        # 11. Live Windows Scheduled Tasks (C:\Windows\System32\Tasks)
        # ---------------------------------------------------------------------
        tasks_p = Path(r"C:\Windows\System32\Tasks")
        copied_tasks = 0
        if tasks_p.exists():
            try:
                for root, _, files in os.walk(tasks_p):
                    for f in files:
                        src_task = Path(root) / f
                        try:
                            rel_task = src_task.relative_to(tasks_p)
                            dst_task = tasks_dir / rel_task
                        except Exception:
                            dst_task = tasks_dir / src_task.name
                        if self._copy_file_safe(src_task, dst_task):
                            counts["tasks"] += 1
                            counts["total_files"] += 1
                            copied_tasks += 1
                            staged_files.append(f"Tasks/{dst_task.name}")
            except Exception as t_ex:
                self._log(f"Notice: Direct access to System32/Tasks restricted: {t_ex}")

        # Fallback or enhancement via schtasks.exe /query /xml
        if copied_tasks == 0:
            try:
                self._log("Exporting live Scheduled Tasks via schtasks.exe /query /xml...")
                res = subprocess.run(
                    ["schtasks.exe", "/query", "/xml"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if res.returncode == 0 and res.stdout and "<Task" in res.stdout:
                    clean = re.sub(r"<\?xml.*?\?>", "", res.stdout)
                    task_blocks = re.findall(r"<Task\b[\s\S]*?</Task>", clean)
                    for idx, block in enumerate(task_blocks):
                        uri_match = re.search(r"<URI>(.*?)</URI>", block)
                        t_name = uri_match.group(1).replace("\\", "_").strip("_") if uri_match else f"Task_{idx+1}"
                        t_file = tasks_dir / f"{t_name}.xml"
                        with open(t_file, "w", encoding="utf-8") as out_t:
                            out_t.write('<?xml version="1.0" encoding="UTF-8"?>\n' + block)
                        counts["tasks"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"Tasks/{t_file.name}")
                    self._log(f"Exported {len(task_blocks)} live Scheduled Tasks XMLs")
            except Exception as sch_ex:
                self._log(f"Notice: schtasks export failed: {sch_ex}")

        # ---------------------------------------------------------------------
        # 12. Live PowerShell History (ConsoleHost_history.txt)
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue
                username = user_dir.name
                ps_hist = (
                    user_dir
                    / "AppData"
                    / "Roaming"
                    / "Microsoft"
                    / "Windows"
                    / "PowerShell"
                    / "PSReadLine"
                    / "ConsoleHost_history.txt"
                )
                if ps_hist.exists():
                    dst_ps = ps_dir / f"{username}_ConsoleHost_history.txt"
                    if self._copy_file_safe(ps_hist, dst_ps):
                        counts["powershell"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"PowerShell/{dst_ps.name}")

        # ---------------------------------------------------------------------
        # 13. Live Windows Push Notifications (wpndatabase.db)
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue
                username = user_dir.name
                notif_dir = (
                    user_dir
                    / "AppData"
                    / "Local"
                    / "Microsoft"
                    / "Windows"
                    / "Notifications"
                )
                if notif_dir.exists():
                    for db_f in notif_dir.glob("wpndatabase.db*"):
                        dst_wpn = sqlite_dir / "Notifications" / f"{username}_{db_f.name}"
                        dst_base = sqlite_dir / db_f.name
                        if self._copy_file_safe(db_f, dst_wpn):
                            self._copy_file_safe(db_f, dst_base)
                            counts["sqlite"] += 1
                            counts["total_files"] += 1
                            staged_files.append(f"SQLite/Notifications/{dst_wpn.name}")

        # ---------------------------------------------------------------------
        # 14. Live Recycle Bin ($I* and $R* files, and XP/2003 INFO2)
        # ---------------------------------------------------------------------
        recycle_roots = [
            Path(r"C:\$Recycle.Bin"), Path(r"D:\$Recycle.Bin"),
            Path(r"C:\RECYCLER"), Path(r"D:\RECYCLER")
        ]
        for r_root in recycle_roots:
            if r_root.exists():
                try:
                    for root, _, files in os.walk(r_root):
                        for f in files:
                            f_low = f.lower()
                            if f_low.startswith("$i") or f_low.startswith("$r") or f_low == "info2":
                                src_rb = Path(root) / f
                                dst_name = f"{Path(root).name}_{f}" if f_low == "info2" else f
                                dst_rb = rb_dir / dst_name
                                if self._copy_file_safe(src_rb, dst_rb):
                                    counts["recycle_bin"] += 1
                                    counts["total_files"] += 1
                                    staged_files.append(f"RecycleBin/{dst_name}")
                except Exception as rb_ex:
                    self._log(f"Notice: Recycle Bin collection exception: {rb_ex}")

        # ---------------------------------------------------------------------
        # 14b. Live RecentFileCache.bcf (Windows 7 / 2008R2)
        # ---------------------------------------------------------------------
        rfc_live = Path(r"C:\Windows\AppCompat\Programs\RecentFileCache.bcf")
        if rfc_live.exists():
            dst_rfc1 = staging_path / "RecentFileCache.bcf"
            dst_rfc2 = staging_path / "AppCompat" / "Programs" / "RecentFileCache.bcf"
            if self._copy_file_safe(rfc_live, dst_rfc1):
                self._copy_file_safe(rfc_live, dst_rfc2)
                counts["total_files"] += 1
                staged_files.append("RecentFileCache.bcf")


        # ---------------------------------------------------------------------
        # 15. Live RMM Logs (AnyDesk, TeamViewer, RustDesk)
        # ---------------------------------------------------------------------
        anydesk_paths = [
            Path(r"C:\ProgramData\AnyDesk"),
            Path(r"C:\Program Files (x86)\AnyDesk"),
        ]
        if users_root.exists():
            for u in users_root.iterdir():
                if u.is_dir():
                    anydesk_paths.append(u / "AppData" / "Roaming" / "AnyDesk")

        for ad_p in anydesk_paths:
            if ad_p.exists():
                for trace_f in ad_p.glob("*.trace"):
                    dst_ad = rmm_dir / "AnyDesk" / f"{ad_p.parent.name}_{trace_f.name}"
                    if self._copy_file_safe(trace_f, dst_ad):
                        counts["rmm"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"RMM/AnyDesk/{dst_ad.name}")

        tv_paths = [
            Path(r"C:\Program Files\TeamViewer"),
            Path(r"C:\Program Files (x86)\TeamViewer"),
        ]
        if users_root.exists():
            for u in users_root.iterdir():
                if u.is_dir():
                    tv_paths.append(u / "AppData" / "Local" / "TeamViewer")
                    tv_paths.append(u / "AppData" / "Local" / "TeamViewer" / "Logs")

        for tv_p in tv_paths:
            if tv_p.exists():
                for tv_f in tv_p.glob("*.txt"):
                    if "connection" in tv_f.name.lower():
                        dst_tv = rmm_dir / "TeamViewer" / tv_f.name
                        if self._copy_file_safe(tv_f, dst_tv):
                            counts["rmm"] += 1
                            counts["total_files"] += 1
                            staged_files.append(f"RMM/TeamViewer/{tv_f.name}")
                for tv_log in tv_p.glob("*Logfile*.log"):
                    dst_tv = rmm_dir / "TeamViewer" / tv_log.name
                    if self._copy_file_safe(tv_log, dst_tv):
                        counts["rmm"] += 1
                        counts["total_files"] += 1
                        staged_files.append(f"RMM/TeamViewer/{tv_log.name}")

        rustdesk_paths = [
            Path(r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config"),
            Path(r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\log"),
        ]
        if users_root.exists():
            for u in users_root.iterdir():
                if u.is_dir():
                    rustdesk_paths.append(u / "AppData" / "Roaming" / "RustDesk" / "config")
                    rustdesk_paths.append(u / "AppData" / "Roaming" / "RustDesk" / "log")

        for rd_p in rustdesk_paths:
            if rd_p.exists():
                for rd_f in rd_p.iterdir():
                    if rd_f.is_file():
                        dst_rd = rmm_dir / "RustDesk" / rd_f.name
                        if self._copy_file_safe(rd_f, dst_rd):
                            counts["rmm"] += 1
                            counts["total_files"] += 1
                            staged_files.append(f"RMM/RustDesk/{rd_f.name}")

        # ---------------------------------------------------------------------
        # 16. Live Zone.Identifier Alternate Data Streams
        # ---------------------------------------------------------------------
        if users_root.exists():
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir():
                    continue
                for folder_name in ["Downloads", "Desktop"]:
                    scan_dir = user_dir / folder_name
                    if scan_dir.exists():
                        try:
                            for item in scan_dir.iterdir():
                                if item.is_file():
                                    if self._extract_zone_identifier(item, zone_dir):
                                        counts["zone_identifier"] += 1
                                        counts["total_files"] += 1
                                        staged_files.append(f"ZoneIdentifier/{item.name}.Zone.Identifier")
                        except Exception as zi_ex:
                            self._log(f"Notice: Zone.Identifier scan error in {scan_dir}: {zi_ex}")

        duration_ms = int((time.time() - start_time) * 1000)
        status = "SUCCESS" if counts["total_files"] > 0 else "WARNING"

        self._log(
            f"Live triage collection completed in {duration_ms}ms. "
            f"Total files staged: {counts['total_files']}, "
            f"EVTX: {counts['evtx']}, Registry: {counts['registry']}, "
            f"Prefetch: {counts['prefetch']}, LNK: {counts['lnk']}, "
            f"JumpLists: {counts['jumplists']}, Browsers: {counts['browsers']}, "
            f"Timeline: {counts['activities_cache']}, SetupAPI: {counts['setupapi']}"
        )

        self._sanitize_staging_permissions(staging_path)

        return {
            "status": status,
            "mode": "live_triage",
            "staging_dir": str(staging_path),
            "total_files_staged": counts["total_files"],
            "duration_ms": duration_ms,
            "counts": counts,
            "staged_files": staged_files,
            "errors": errors,
        }

    # =========================================================================
    # OPTIONAL: Extract from Raw / Forensic Disk Image (.E01, .vhdx, .raw)
    # =========================================================================

    def extract_from_image(
        self,
        image_path: Union[str, Path],
        staging_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Extract artifacts from a forensic disk image (.E01, .vhdx, .vmdk, .raw, .dd, .iso)
        using dissect.target and fallback to pytsk3 / 7z extraction.
        """
        start_time = time.time()
        clean_image_str = str(image_path).strip().strip('"').strip("'").strip()
        image_p = Path(clean_image_str).resolve()
        staging_p = Path(staging_dir).resolve() if staging_dir else self.staging_dir
        staging_p.mkdir(parents=True, exist_ok=True)

        if not image_p.exists():
            raise FileNotFoundError(f"Source disk image does not exist: {image_p}")

        KNOWN_IMAGE_EXTS = {".e01", ".ex01", ".vhdx", ".vhd", ".vmdk", ".raw", ".dd", ".img", ".iso"}

        # Auto-detect if user pointed to a directory instead of a single image file
        if image_p.is_dir():
            self._log(f"extract_from_image: Path is a directory: {image_p}. Searching for forensic disk images...")
            contained_images = [
                f for f in sorted(image_p.iterdir())
                if f.is_file() and f.suffix.lower() in KNOWN_IMAGE_EXTS
            ]
            e01_cands = [c for c in contained_images if c.suffix.lower() in [".e01", ".ex01"]]
            chosen = e01_cands[0] if e01_cands else (contained_images[0] if contained_images else None)

            if chosen:
                self._log(f"Auto-detected forensic image in directory: '{chosen.name}'. Proceeding with image extraction.")
                image_p = chosen
            else:
                self._log(f"No forensic disk images found in {image_p}. Falling back to directory extraction.")
                return self.extract_from_directory(source_dir=image_p, staging_dir=staging_p, unpack_archives=True)

        # If .ISO file on Windows, attempt PowerShell Mount-DiskImage
        if image_p.suffix.lower() == ".iso":
            self._log(f"Handling ISO disk image: {image_p.name}")
            try:
                ps_mount_cmd = [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    f"$mount = Mount-DiskImage -ImagePath '{str(image_p)}' -StorageType ISO -PassThru; "
                    f"$vol = Get-Volume -DiskImage $mount; "
                    f"if ($vol.DriveLetter) {{ Write-Output $vol.DriveLetter }} else {{ Write-Output '' }}",
                ]
                res = subprocess.run(ps_mount_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
                drive_letter = res.stdout.strip().replace(":", "").split()[-1] if res.stdout.strip() else None
                if drive_letter and len(drive_letter) == 1 and drive_letter.isalpha():
                    self._log(f"Mounted ISO to drive {drive_letter}:. Extracting artifacts...")
                    try:
                        dir_res = self.extract_from_directory(
                            source_dir=f"{drive_letter}:\\",
                            staging_dir=staging_p,
                            unpack_archives=True,
                        )
                        return dir_res
                    finally:
                        subprocess.run(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command", f"Dismount-DiskImage -ImagePath '{str(image_p)}'"],
                            capture_output=True,
                        )
            except Exception as iso_ex:
                self._log(f"PowerShell ISO mount attempt notice: {iso_ex}", level="WARNING")

        counts: Dict[str, int] = {
            "evtx": 0,
            "prefetch": 0,
            "lnk": 0,
            "jumplists": 0,
            "registry": 0,
            "mft": 0,
            "usnjrnl": 0,
            "srum": 0,
            "activities_cache": 0,
            "setupapi": 0,
            "browsers": 0,
            "sqlite": 0,
            "recycle_bin": 0,
            "tasks": 0,
            "powershell": 0,
            "rmm": 0,
            "zone_identifier": 0,
            "enrichment": 0,
            "total_files": 0,
        }
        staged_files: List[str] = []
        errors: List[str] = []

        # Create destination staging subdirectories
        for sub in [
            "Logs", "Prefetch", "Registry", "FileSystem", "LNK",
            "JumpLists", "JumpLists/AutomaticDestinations", "JumpLists/CustomDestinations",
            "Browsers", "Chat", "Cloud", "Timeline", "Tasks",
            "PowerShell", "RMM", "SetupAPI", "RecycleBin", "SQLite",
            "Thumbcache", "Documents", "Downloads", "UserFiles", "ActivitiesCache", "Notifications",
            "Enrichment"
        ]:
            (staging_p / sub).mkdir(parents=True, exist_ok=True)

        target_opened = False

        if dissect is not None:
            self._log(f"Opening forensic image '{image_p}' with dissect.target...")
            try:
                target = dissect.target.Target.open(str(image_p))
                target_opened = True
                self._log(f"Image successfully opened with dissect.target. Operating system: {getattr(target, 'os', 'unknown')}")

                # 1. Extract raw NTFS $MFT & $J change journal streams
                try:
                    # Sort filesystems to prioritize the main Windows OS partition
                    ntfs_candidates = []
                    for fs in getattr(target, "filesystems", []):
                        if hasattr(fs, "ntfs") and fs.ntfs:
                            has_win = False
                            try:
                                has_win = fs.path("/Windows").exists() or fs.path("Windows").exists()
                            except Exception:
                                pass
                            mft_len = 0
                            try:
                                if hasattr(fs.ntfs, "mft") and getattr(fs.ntfs.mft, "fh", None):
                                    fs.ntfs.mft.fh.seek(0, 2)
                                    mft_len = fs.ntfs.mft.fh.tell()
                                    fs.ntfs.mft.fh.seek(0)
                            except Exception:
                                pass
                            ntfs_candidates.append((has_win, mft_len, fs))

                    ntfs_candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)

                    for _, _, fs in ntfs_candidates:
                        # Stream $MFT
                        if hasattr(fs.ntfs, "mft") and getattr(fs.ntfs.mft, "fh", None):
                            try:
                                fs.ntfs.mft.fh.seek(0)
                                dst_mft = staging_p / "FileSystem" / "MFT"
                                with open(dst_mft, "wb") as mft_f:
                                    shutil.copyfileobj(fs.ntfs.mft.fh, mft_f)
                                try:
                                    shutil.copyfile(dst_mft, staging_p / "MFT")
                                except Exception:
                                    pass
                                counts["mft"] += 1
                                counts["total_files"] += 1
                                staged_files.append("FileSystem/MFT")
                                self._log(f"Extracted NTFS $MFT ({dst_mft.stat().st_size} bytes)")
                            except Exception as mft_err:
                                self._log(f"Notice extracting MFT stream: {mft_err}")

                        # Stream $J (UsnJrnl)
                        if hasattr(fs.ntfs, "usnjrnl") and getattr(fs.ntfs.usnjrnl, "fh", None):
                            try:
                                fs.ntfs.usnjrnl.fh.seek(0)
                                dst_j = staging_p / "FileSystem" / "UsnJrnl"
                                with open(dst_j, "wb") as j_f:
                                    shutil.copyfileobj(fs.ntfs.usnjrnl.fh, j_f)
                                try:
                                    shutil.copyfile(dst_j, staging_p / "UsnJrnl")
                                except Exception:
                                    pass
                                counts["usnjrnl"] += 1
                                counts["total_files"] += 1
                                staged_files.append("FileSystem/UsnJrnl")
                                self._log(f"Extracted NTFS $J UsnJrnl ({dst_j.stat().st_size} bytes)")
                            except Exception as j_err:
                                self._log(f"Notice extracting UsnJrnl stream: {j_err}")
                        break
                except Exception as ntfs_stream_err:
                    self._log(f"NTFS raw stream extraction notice: {ntfs_stream_err}")

                # Helper to safely copy an entry
                def safe_copy(entry_obj, dst_folder: Path, custom_name: Optional[str] = None) -> bool:
                    try:
                        fname = custom_name or entry_obj.name
                        dst = dst_folder / fname
                        dst_folder.mkdir(parents=True, exist_ok=True)
                        self._clear_file_attributes(dst_folder)
                        with entry_obj.open() as in_f, open(dst, "wb") as out_f:
                            shutil.copyfileobj(in_f, out_f)
                        self._clear_file_attributes(dst)
                        return True
                    except Exception as cp_err:
                        errors.append(f"Failed copying {entry_obj.name}: {cp_err}")
                        return False

                # 2. Targeted Extraction from Canonical Windows Paths
                # A) Event Logs (*.evtx)
                try:
                    for evtx_path in ["c:/Windows/System32/winevt/Logs", "Windows/System32/winevt/Logs"]:
                        tp = target.fs.path(evtx_path)
                        if tp.exists() and tp.is_dir():
                            for child in tp.iterdir():
                                if child.is_file() and child.name.lower().endswith(".evtx"):
                                    if safe_copy(child, staging_p / "Logs"):
                                        counts["evtx"] += 1
                                        counts["total_files"] += 1
                                        staged_files.append(f"Logs/{child.name}")
                            break
                    self._log(f"Extracted {counts['evtx']} event log (.evtx) files")
                except Exception as ex_evtx:
                    self._log(f"Notice extracting EVTX: {ex_evtx}")

                # B) Prefetch (*.pf)
                try:
                    for pf_path in ["c:/Windows/Prefetch", "Windows/Prefetch"]:
                        tp = target.fs.path(pf_path)
                        if tp.exists() and tp.is_dir():
                            for child in tp.iterdir():
                                if child.is_file() and child.name.lower().endswith(".pf"):
                                    if safe_copy(child, staging_p / "Prefetch"):
                                        counts["prefetch"] += 1
                                        counts["total_files"] += 1
                                        staged_files.append(f"Prefetch/{child.name}")
                            break
                    self._log(f"Extracted {counts['prefetch']} Prefetch (.pf) files")
                except Exception as ex_pf:
                    self._log(f"Notice extracting Prefetch: {ex_pf}")

                # C) System Registry Hives
                try:
                    for reg_path in ["c:/Windows/System32/config", "Windows/System32/config"]:
                        tp = target.fs.path(reg_path)
                        if tp.exists() and tp.is_dir():
                            for child in tp.iterdir():
                                if child.is_file():
                                    cname_low = child.name.lower()
                                    if any(cname_low.startswith(h) for h in ["system", "software", "sam", "security", "default", "components"]):
                                        if safe_copy(child, staging_p / "Registry"):
                                            counts["registry"] += 1
                                            counts["total_files"] += 1
                                            staged_files.append(f"Registry/{child.name}")
                            break
                    self._log(f"Extracted {counts['registry']} System Registry hive files")
                except Exception as ex_reg:
                    self._log(f"Notice extracting Registry: {ex_reg}")

                # D) Amcache.hve
                try:
                    for am_path in ["c:/Windows/appcompat/Programs/Amcache.hve", "Windows/appcompat/Programs/Amcache.hve"]:
                        tp = target.fs.path(am_path)
                        if tp.exists() and tp.is_file():
                            safe_copy(tp, staging_p / "Registry", "Amcache.hve")
                            counts["registry"] += 1
                            counts["total_files"] += 1
                            staged_files.append("Registry/Amcache.hve")
                            break
                except Exception as ex_am:
                    self._log(f"Notice extracting Amcache: {ex_am}")

                # E) SRUM (SRUDB.dat)
                try:
                    for srum_path in ["c:/Windows/System32/sru/SRUDB.dat", "Windows/System32/sru/SRUDB.dat"]:
                        tp = target.fs.path(srum_path)
                        if tp.exists() and tp.is_file():
                            safe_copy(tp, staging_p, "SRUDB.dat")
                            counts["srum"] += 1
                            counts["total_files"] += 1
                            staged_files.append("SRUDB.dat")
                            break
                except Exception as ex_srum:
                    self._log(f"Notice extracting SRUM: {ex_srum}")

                # F) SetupAPI (setupapi.dev.log)
                try:
                    for su_path in ["c:/Windows/INF/setupapi.dev.log", "Windows/INF/setupapi.dev.log"]:
                        tp = target.fs.path(su_path)
                        if tp.exists() and tp.is_file():
                            safe_copy(tp, staging_p / "SetupAPI", "setupapi.dev.log")
                            counts["setupapi"] += 1
                            counts["total_files"] += 1
                            staged_files.append("SetupAPI/setupapi.dev.log")
                            break
                except Exception as ex_su:
                    self._log(f"Notice extracting SetupAPI: {ex_su}")

                # G) Tasks (Recursive extraction of all tasks including Microsoft\Windows subfolders)
                try:
                    for t_path in ["c:/Windows/System32/Tasks", "Windows/System32/Tasks"]:
                        tp = target.fs.path(t_path)
                        if tp.exists() and tp.is_dir():
                            def extract_tasks_recursive(cur_fs_dir, dest_local_dir):
                                for child in cur_fs_dir.iterdir():
                                    try:
                                        if child.is_file():
                                            safe_copy(child, dest_local_dir)
                                            counts["tasks"] += 1
                                            counts["total_files"] += 1
                                            staged_files.append(f"Tasks/{child.name}")
                                        elif child.is_dir():
                                            sub_dest = dest_local_dir / child.name
                                            sub_dest.mkdir(parents=True, exist_ok=True)
                                            extract_tasks_recursive(child, sub_dest)
                                    except Exception:
                                        continue
                            extract_tasks_recursive(tp, staging_p / "Tasks")
                            break
                except Exception as ex_tk:
                    self._log(f"Notice extracting Tasks: {ex_tk}")

                # H) User Artifacts (NTUSER, LNKs, JumpLists, History, PowerShell)
                try:
                    for users_path in ["c:/Users", "Users"]:
                        tp = target.fs.path(users_path)
                        if tp.exists() and tp.is_dir():
                            for user_dir in tp.iterdir():
                                if not user_dir.is_dir() or user_dir.name.lower() in ["all users", "default", "default user"]:
                                    continue
                                uname = user_dir.name

                                # User NTUSER.DAT & LOGs
                                try:
                                    for item in user_dir.iterdir():
                                        if item.is_file() and item.name.lower().startswith("ntuser.dat"):
                                            safe_copy(item, staging_p / "Registry", f"NTUSER_{uname}_{item.name}")
                                            counts["registry"] += 1
                                            counts["total_files"] += 1
                                except Exception:
                                    pass

                                # UsrClass.dat
                                try:
                                    uc_path = user_dir / "AppData/Local/Microsoft/Windows/UsrClass.dat"
                                    if uc_path.exists() and uc_path.is_file():
                                        safe_copy(uc_path, staging_p / "Registry", f"UsrClass_{uname}.dat")
                                        counts["registry"] += 1
                                        counts["total_files"] += 1
                                except Exception:
                                    pass

                                # Recent LNKs
                                try:
                                    rec_path = user_dir / "AppData/Roaming/Microsoft/Windows/Recent"
                                    if rec_path.exists() and rec_path.is_dir():
                                        for lnk in rec_path.iterdir():
                                            if lnk.is_file() and lnk.name.lower().endswith(".lnk"):
                                                safe_copy(lnk, staging_p / "LNK", f"{uname}_{lnk.name}")
                                                counts["lnk"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"LNK/{uname}_{lnk.name}")
                                except Exception:
                                    pass

                                # JumpLists
                                try:
                                    auto_jl = user_dir / "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"
                                    if auto_jl.exists() and auto_jl.is_dir():
                                        for jl in auto_jl.iterdir():
                                            if jl.is_file() and jl.name.lower().endswith(".automaticdestinations-ms"):
                                                safe_copy(jl, staging_p / "JumpLists/AutomaticDestinations")
                                                counts["jumplists"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"JumpLists/AutomaticDestinations/{jl.name}")

                                    cust_jl = user_dir / "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations"
                                    if cust_jl.exists() and cust_jl.is_dir():
                                        for jl in cust_jl.iterdir():
                                            if jl.is_file() and jl.name.lower().endswith(".customdestinations-ms"):
                                                safe_copy(jl, staging_p / "JumpLists/CustomDestinations")
                                                counts["jumplists"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"JumpLists/CustomDestinations/{jl.name}")
                                except Exception:
                                    pass

                                # PowerShell History
                                try:
                                    ps_hist = user_dir / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
                                    if ps_hist.exists() and ps_hist.is_file():
                                        safe_copy(ps_hist, staging_p / "PowerShell", f"{uname}_ConsoleHost_history.txt")
                                        counts["powershell"] += 1
                                        counts["total_files"] += 1
                                        staged_files.append(f"PowerShell/{uname}_ConsoleHost_history.txt")
                                except Exception:
                                    pass

                                # Chromium Browsers (Chrome / Edge / Brave)
                                try:
                                    for br_name, br_rel in [
                                        ("Chrome", "AppData/Local/Google/Chrome/User Data"),
                                        ("Edge", "AppData/Local/Microsoft/Edge/User Data"),
                                        ("Brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data"),
                                    ]:
                                        br_dir = user_dir / br_rel
                                        if br_dir.exists() and br_dir.is_dir():
                                            for profile_candidate in ["Default", "Profile 1", "Profile 2"]:
                                                prof_dir = br_dir / profile_candidate
                                                if prof_dir.exists() and prof_dir.is_dir():
                                                    for db_name in ["History", "Login Data", "Web Data", "Cookies", "Bookmarks"]:
                                                        db_f = prof_dir / db_name
                                                        if db_f.exists() and db_f.is_file():
                                                            dest_folder = staging_p / "Browsers" / br_name / uname
                                                            dest_folder.mkdir(parents=True, exist_ok=True)
                                                            safe_copy(db_f, dest_folder, db_name)
                                                            for sfx in ["-wal", "-shm", "-journal"]:
                                                                wal_f = prof_dir / f"{db_name}{sfx}"
                                                                if wal_f.exists() and wal_f.is_file():
                                                                    safe_copy(wal_f, dest_folder, f"{db_name}{sfx}")
                                                            counts["browsers"] += 1
                                                            counts["total_files"] += 1
                                except Exception:
                                    pass

                                # Firefox places.sqlite
                                try:
                                    ff_dir = user_dir / "AppData/Roaming/Mozilla/Firefox/Profiles"
                                    if ff_dir.exists() and ff_dir.is_dir():
                                        for pdir in ff_dir.iterdir():
                                            if pdir.is_dir():
                                                for db_name in ["places.sqlite", "cookies.sqlite", "logins.json", "formhistory.sqlite", "favicons.sqlite", "key4.db"]:
                                                    f_item = pdir / db_name
                                                    if f_item.exists() and f_item.is_file():
                                                        dest_folder = staging_p / "Browsers" / "Firefox" / uname
                                                        dest_folder.mkdir(parents=True, exist_ok=True)
                                                        safe_copy(f_item, dest_folder, db_name)
                                                        for sfx in ["-wal", "-shm", "-journal"]:
                                                            wal_f = pdir / f"{db_name}{sfx}"
                                                            if wal_f.exists() and wal_f.is_file():
                                                                safe_copy(wal_f, dest_folder, f"{db_name}{sfx}")
                                                        counts["browsers"] += 1
                                                        counts["total_files"] += 1
                                except Exception:
                                    pass

                                # Internet Explorer / Edge Spartan WebCacheV01.dat
                                try:
                                    webcache_file = user_dir / "AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"
                                    if webcache_file.exists() and webcache_file.is_file():
                                        dest_folder = staging_p / "Browsers" / "IE" / uname
                                        dest_folder.mkdir(parents=True, exist_ok=True)
                                        safe_copy(webcache_file, dest_folder, "WebCacheV01.dat")
                                        counts["browsers"] += 1
                                        counts["total_files"] += 1
                                except Exception:
                                    pass

                                # Windows Timeline (ActivitiesCache.db)
                                try:
                                    cdp_dir = user_dir / "AppData/Local/ConnectedDevicesPlatform"
                                    if cdp_dir.exists() and cdp_dir.is_dir():
                                        for sub in cdp_dir.iterdir():
                                            if sub.is_dir():
                                                for act_f in sub.iterdir():
                                                    if act_f.is_file() and act_f.name.lower().startswith("activitiescache.db"):
                                                        dest_folder = staging_p / "ActivitiesCache" / uname
                                                        dest_folder.mkdir(parents=True, exist_ok=True)
                                                        safe_copy(act_f, dest_folder)
                                                        # Also copy to staging root for WxTCmd default discovery
                                                        safe_copy(act_f, staging_p, act_f.name)
                                                        counts["activities_cache"] += 1
                                                        counts["total_files"] += 1
                                                        staged_files.append(f"ActivitiesCache/{act_f.name}")
                                except Exception:
                                    pass

                                # Windows Push Notifications (wpndatabase.db)
                                try:
                                    wpn_dir = user_dir / "AppData/Local/Microsoft/Windows/Notifications"
                                    if wpn_dir.exists() and wpn_dir.is_dir():
                                        for wpn_f in wpn_dir.iterdir():
                                            if wpn_f.is_file() and wpn_f.name.lower().startswith("wpndatabase.db"):
                                                dest_folder = staging_p / "Notifications" / uname
                                                dest_folder.mkdir(parents=True, exist_ok=True)
                                                safe_copy(wpn_f, dest_folder)
                                                safe_copy(wpn_f, staging_p / "Notifications", f"{uname}_{wpn_f.name}")
                                                safe_copy(wpn_f, staging_p, wpn_f.name)
                                                counts["sqlite"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"Notifications/{wpn_f.name}")
                                except Exception:
                                    pass

                                # Windows Explorer Thumbcache & Iconcache
                                try:
                                    exp_dir = user_dir / "AppData/Local/Microsoft/Windows/Explorer"
                                    if exp_dir.exists() and exp_dir.is_dir():
                                        for tc_f in exp_dir.iterdir():
                                            if tc_f.is_file() and (tc_f.name.lower().startswith("thumbcache_") or tc_f.name.lower().startswith("iconcache_")):
                                                dest_folder = staging_p / "Thumbcache"
                                                dest_folder.mkdir(parents=True, exist_ok=True)
                                                safe_copy(tc_f, dest_folder, f"{uname}_{tc_f.name}")
                                                safe_copy(tc_f, dest_folder, tc_f.name)
                                                counts["total_files"] += 1
                                                staged_files.append(f"Thumbcache/{tc_f.name}")
                                except Exception:
                                    pass

                                # User Documents, Downloads, Desktop files
                                try:
                                    for doc_folder_name in ["Desktop", "Documents", "Downloads", "Pictures"]:
                                        doc_dir = user_dir / doc_folder_name
                                        if doc_dir.exists() and doc_dir.is_dir():
                                            def extract_docs_recursive(cur_dir, dest_base, depth=0):
                                                if depth > 3:
                                                    return
                                                for f in cur_dir.iterdir():
                                                    try:
                                                        if f.is_file():
                                                            fname_l = f.name.lower()
                                                            if fname_l == "desktop.ini":
                                                                continue
                                                            safe_copy(f, dest_base)
                                                            sfx = f.suffix.lower()
                                                            if sfx in [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".csv", ".rtf", ".chm"]:
                                                                safe_copy(f, staging_p / "Documents")
                                                            if sfx in self.SUSPICIOUS_MALWARE_EXTENSIONS:
                                                                safe_copy(f, staging_p / "Enrichment")
                                                                counts["enrichment"] += 1
                                                            counts["total_files"] += 1
                                                            staged_files.append(f"UserFiles/{uname}/{doc_folder_name}/{f.name}")
                                                        elif f.is_dir() and f.name.lower() not in ["appdata", "application data"]:
                                                            extract_docs_recursive(f, dest_base / f.name, depth + 1)
                                                    except Exception:
                                                        pass
                                            dest_doc_dir = staging_p / "UserFiles" / uname / doc_folder_name
                                            dest_doc_dir.mkdir(parents=True, exist_ok=True)
                                            extract_docs_recursive(doc_dir, dest_doc_dir)
                                except Exception:
                                    pass

                                # Cloud Storage (OneDrive, GDrive, Dropbox)
                                try:
                                    onedrive_dir = user_dir / "AppData/Local/Microsoft/OneDrive"
                                    if onedrive_dir.exists() and onedrive_dir.is_dir():
                                        dest_od = staging_p / "Cloud/OneDrive" / uname
                                        dest_od.mkdir(parents=True, exist_ok=True)
                                        for od_sub in ["settings/Personal", "logs"]:
                                            sp = onedrive_dir / od_sub
                                            if sp.exists() and sp.is_dir():
                                                for odf in sp.iterdir():
                                                    if odf.is_file():
                                                        safe_copy(odf, dest_od)
                                                        counts["total_files"] += 1
                                except Exception:
                                    pass

                                # Chat Collaboration (Discord, Teams, Slack)
                                try:
                                    # Discord
                                    discord_ldb = user_dir / "AppData/Roaming/discord/Local Storage/leveldb"
                                    if discord_ldb.exists() and discord_ldb.is_dir():
                                        dest_dc = staging_p / "Chat/Discord" / uname
                                        dest_dc.mkdir(parents=True, exist_ok=True)
                                        for dcf in discord_ldb.iterdir():
                                            if dcf.is_file():
                                                safe_copy(dcf, dest_dc)
                                                counts["total_files"] += 1

                                    # Teams Classic (Roaming)
                                    teams_roam = user_dir / "AppData/Roaming/Microsoft/Teams"
                                    if teams_roam.exists() and teams_roam.is_dir():
                                        dest_tm = staging_p / "Chat/Teams" / uname
                                        dest_tm.mkdir(parents=True, exist_ok=True)
                                        for sub_name in ["IndexedDB", "Local Storage", "databases"]:
                                            s_dir = teams_roam / sub_name
                                            if s_dir.exists() and s_dir.is_dir():
                                                for tf in s_dir.rglob("*"):
                                                    if tf.is_file() and tf.name.lower().endswith((".ldb", ".log", ".sqlite", ".db", ".json")):
                                                        safe_copy(tf, dest_tm)
                                                        counts["total_files"] += 1

                                    # Teams 2.x New (Local/Packages WebView2)
                                    pkg_dir = user_dir / "AppData/Local/Packages"
                                    if pkg_dir.exists() and pkg_dir.is_dir():
                                        for pkg in pkg_dir.iterdir():
                                            p_low = pkg.name.lower()
                                            if "msteams" in p_low or "microsoftcorporationii.microsoftteams" in p_low:
                                                dest_tm = staging_p / "Chat/Teams" / uname
                                                dest_tm.mkdir(parents=True, exist_ok=True)
                                                for tf in pkg.rglob("*"):
                                                    if tf.is_file() and tf.name.lower().endswith((".ldb", ".log", ".sqlite", ".db", ".dat", ".json")):
                                                        safe_copy(tf, dest_tm, f"{pkg.name}_{tf.name}")
                                                        counts["total_files"] += 1

                                    # Slack (Roaming)
                                    slack_roam = user_dir / "AppData/Roaming/Slack"
                                    if slack_roam.exists() and slack_roam.is_dir():
                                        dest_sl = staging_p / "Chat/Slack" / uname
                                        dest_sl.mkdir(parents=True, exist_ok=True)
                                        for sub_name in ["IndexedDB", "Local Storage"]:
                                            s_dir = slack_roam / sub_name
                                            if s_dir.exists() and s_dir.is_dir():
                                                for sf in s_dir.rglob("*"):
                                                    if sf.is_file() and sf.name.lower().endswith((".ldb", ".log", ".sqlite", ".db")):
                                                        safe_copy(sf, dest_sl)
                                                        counts["total_files"] += 1

                                    # Outlook & Mail Stores (.pst, .ost, LiveComm, Windows Live Mail)
                                    for mail_sub in [
                                        "AppData/Local/Microsoft/Outlook",
                                        "Documents/Outlook Files",
                                        "OneDrive/Documents/Outlook Files",
                                        "AppData/Local/Microsoft/Windows Live Mail",
                                    ]:
                                        m_dir = user_dir / mail_sub
                                        if m_dir.exists() and m_dir.is_dir():
                                            dest_mail = staging_p / "Mail" / uname
                                            dest_mail.mkdir(parents=True, exist_ok=True)
                                            for mf in m_dir.rglob("*"):
                                                if mf.is_file() and mf.name.lower().endswith((".pst", ".ost", ".eml", ".msg")):
                                                    safe_copy(mf, dest_mail)
                                                    counts["total_files"] += 1

                                    # LiveComm Mail
                                    if pkg_dir.exists() and pkg_dir.is_dir():
                                        for pkg in pkg_dir.iterdir():
                                            if "microsoft.windowscommunicationsapps" in pkg.name.lower():
                                                livecomm_dir = pkg / "LocalState/Indexed/LiveComm"
                                                if livecomm_dir.exists() and livecomm_dir.is_dir():
                                                    dest_mail = staging_p / "Mail" / uname
                                                    dest_mail.mkdir(parents=True, exist_ok=True)
                                                    for lcf in livecomm_dir.rglob("*"):
                                                        if lcf.is_file() and lcf.name.lower().endswith((".eml", ".dat", ".db", ".sqlite")):
                                                            safe_copy(lcf, dest_mail)
                                                            counts["total_files"] += 1

                                    # Sticky Notes (Win 7 & Win 10/11)
                                    sn_file = user_dir / "AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt"
                                    if sn_file.exists() and sn_file.is_file():
                                        dest_sn = staging_p / "StickyNotes"
                                        dest_sn.mkdir(parents=True, exist_ok=True)
                                        safe_copy(sn_file, dest_sn, f"{uname}_StickyNotes.snt")
                                        counts["total_files"] += 1

                                    if pkg_dir.exists() and pkg_dir.is_dir():
                                        for pkg in pkg_dir.iterdir():
                                            if "microsoftstickynotes" in pkg.name.lower():
                                                sn_db = pkg / "LocalState/plum.sqlite"
                                                if sn_db.exists() and sn_db.is_file():
                                                    dest_sn = staging_p / "StickyNotes"
                                                    dest_sn.mkdir(parents=True, exist_ok=True)
                                                    safe_copy(sn_db, dest_sn, f"{uname}_plum.sqlite")
                                                    counts["total_files"] += 1
                                except Exception:
                                    pass
                            break
                    self._log(f"Extracted user artifacts across profiles (LNK={counts['lnk']}, JumpLists={counts['jumplists']}, Browsers={counts['browsers']}, Timeline={counts['activities_cache']})")
                except Exception as ex_users:
                    self._log(f"Notice extracting Users: {ex_users}")

                # I) Recycle Bin ($I* and $R* files across all user SIDs, and XP/2003 INFO2)
                try:
                    for rb_path in ["c:/$Recycle.Bin", "$Recycle.Bin", "c:/RECYCLER", "RECYCLER"]:
                        tp = target.fs.path(rb_path)
                        if tp.exists() and tp.is_dir():
                            def extract_rb_recursive(cur_fs_dir, dest_local_dir):
                                for child in cur_fs_dir.iterdir():
                                    try:
                                        if child.is_file():
                                            c_low = child.name.lower()
                                            if c_low != "desktop.ini":
                                                safe_copy(child, dest_local_dir)
                                                counts["recycle_bin"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"RecycleBin/{child.name}")
                                        elif child.is_dir():
                                            extract_rb_recursive(child, dest_local_dir / child.name)
                                    except Exception:
                                        pass
                            rb_dest = staging_p / "RecycleBin"
                            rb_dest.mkdir(parents=True, exist_ok=True)
                            extract_rb_recursive(tp, rb_dest)
                            self._log(f"Extracted {counts['recycle_bin']} Recycle Bin files")
                            break
                except Exception as ex_rb:
                    self._log(f"Notice extracting Recycle Bin: {ex_rb}")

                # J) RMM & Remote Access Logs
                try:
                    for rmm_base in ["c:/ProgramData/AnyDesk", "c:/ProgramData/TeamViewer", "c:/Program Files/AnyDesk", "c:/Program Files (x86)/TeamViewer"]:
                        tp = target.fs.path(rmm_base)
                        if tp.exists() and tp.is_dir():
                            dest_rmm = staging_p / "RMM" / tp.name
                            dest_rmm.mkdir(parents=True, exist_ok=True)
                            for rf in tp.iterdir():
                                if rf.is_file() and rf.name.lower().endswith((".log", ".trace", ".txt", ".ini")):
                                    safe_copy(rf, dest_rmm)
                                    counts["rmm"] += 1
                                    counts["total_files"] += 1
                except Exception:
                    pass

                # K) Windows 7 RecentFileCache.bcf
                try:
                    for rfc_path in ["c:/Windows/AppCompat/Programs/RecentFileCache.bcf", "Windows/AppCompat/Programs/RecentFileCache.bcf"]:
                        tp = target.fs.path(rfc_path)
                        if tp.exists() and tp.is_file():
                            safe_copy(tp, staging_p, "RecentFileCache.bcf")
                            safe_copy(tp, staging_p / "AppCompat/Programs", "RecentFileCache.bcf")
                            counts["total_files"] += 1
                            staged_files.append("RecentFileCache.bcf")
                            break
                except Exception:
                    pass

                # L) Web Server Paths & Suspicious Malware Artifacts (Tomcat, IIS, XAMPP, Nginx)
                try:
                    for web_cand in [
                        "c:/inetpub/wwwroot", "inetpub/wwwroot",
                        "c:/Program Files/Apache Software Foundation", "Program Files/Apache Software Foundation",
                        "c:/xampp/htdocs", "xampp/htdocs",
                        "c:/wamp/www", "wamp/www",
                        "c:/wamp64/www", "wamp64/www",
                        "c:/nginx/html", "nginx/html",
                    ]:
                        tp = target.fs.path(web_cand)
                        if tp.exists() and tp.is_dir():
                            def extract_web_recursive(cur_fs_dir, dest_local_dir, depth=0):
                                if depth > 5:
                                    return
                                for child in cur_fs_dir.iterdir():
                                    try:
                                        if child.is_file():
                                            c_low = child.name.lower()
                                            if any(c_low.endswith(ext) for ext in self.SUSPICIOUS_MALWARE_EXTENSIONS):
                                                safe_copy(child, dest_local_dir)
                                                counts["enrichment"] += 1
                                                counts["total_files"] += 1
                                                staged_files.append(f"Enrichment/{child.name}")
                                        elif child.is_dir():
                                            sub_dest = dest_local_dir / child.name
                                            sub_dest.mkdir(parents=True, exist_ok=True)
                                            extract_web_recursive(child, sub_dest, depth + 1)
                                    except Exception:
                                        pass
                            dest_web_dir = staging_p / "Enrichment" / tp.name
                            dest_web_dir.mkdir(parents=True, exist_ok=True)
                            extract_web_recursive(tp, dest_web_dir)
                            self._log(f"Extracted web server artifacts from {web_cand}")
                except Exception as ex_web:
                    self._log(f"Notice extracting web server artifacts: {ex_web}")

            except Exception as dissect_err:
                self._log(f"dissect.target error on {image_p}: {dissect_err}", level="WARNING")
                errors.append(str(dissect_err))

        # 3. Fallback: pytsk3 or 7z if dissect.target failed or extracted 0 files
        if not target_opened or counts["total_files"] == 0:
            self._log(f"Attempting pytsk3 and archive fallback on {image_p}...", level="WARNING")
            try:
                import pytsk3
                img_info = pytsk3.Img_Info(str(image_p))
                self._log(f"pytsk3 successfully opened {image_p.name} (size: {img_info.get_size()} bytes)")

                # Try opening Volume_Info to inspect partitions
                try:
                    vol_info = pytsk3.Volume_Info(img_info)
                    for part in vol_info:
                        if part.len > 2048:
                            try:
                                fs = pytsk3.FS_Info(img_info, offset=part.start * vol_info.info.block_size)
                                self._log(f"pytsk3 found filesystem on partition at offset {part.start}")
                                # Read root directory
                                root_dir = fs.open_dir(path="/")
                                for entry in root_dir:
                                    if entry.info.name and entry.info.name.name:
                                        ename = entry.info.name.name.decode("utf-8", errors="replace")
                                        if ename.lower() == "$mft":
                                            f_obj = fs.open(ename)
                                            dst = staging_p / "FileSystem" / "MFT"
                                            dst.parent.mkdir(parents=True, exist_ok=True)
                                            with open(dst, "wb") as f_out:
                                                offset = 0
                                                size = f_obj.info.meta.size
                                                while offset < size:
                                                    available = min(1024 * 1024, size - offset)
                                                    buf = f_obj.read_random(offset, available)
                                                    if not buf:
                                                        break
                                                    f_out.write(buf)
                                                    offset += len(buf)
                                            counts["mft"] += 1
                                            counts["total_files"] += 1
                                            staged_files.append("FileSystem/MFT")
                                            self._log(f"pytsk3 extracted $MFT ({dst.stat().st_size} bytes)")
                            except Exception as fs_err:
                                pass
                except Exception as vol_err:
                    self._log(f"pytsk3 Volume_Info notice: {vol_err}")

            except Exception as pytsk_err:
                self._log(f"pytsk3 extraction attempt notice: {pytsk_err}", level="WARNING")

            # Try 7z / py7zr archive fallback
            try:
                if py7zr and py7zr.is_7zfile(str(image_p)):
                    self._log(f"Extracting container as 7z archive: {image_p.name}")
                    with py7zr.SevenZipFile(str(image_p), mode="r") as z:
                        z.extractall(path=staging_p)
                        counts["total_files"] += 1
            except Exception as z_err:
                self._log(f"7z extraction attempt notice: {z_err}", level="WARNING")

        duration_ms = int((time.time() - start_time) * 1000)
        self._log(f"Evidence extraction finished in {duration_ms}ms: {counts['total_files']} files staged.")
        self._sanitize_staging_permissions(staging_p)

        return {
            "status": "SUCCESS" if counts["total_files"] > 0 else "WARNING",
            "mode": "image",
            "source_image": str(image_p),
            "staging_dir": str(staging_p),
            "total_files_staged": counts["total_files"],
            "duration_ms": duration_ms,
            "counts": counts,
            "staged_files": staged_files,
            "errors": errors,
        }
