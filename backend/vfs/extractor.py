"""
Windows Forensic Toolkit (WFT) DFIR Suite - Virtual File System (VFS) & Artifact Extraction Engine
Multi-Volume VFS Ingestion (NTFS, FAT12/16/32, exFAT, ISO9660, ECMA-167 UDF + Type 2 VAT),
Forensic 8-Timestamp MACB Preservation, Contract 2 Staging Layout Hygiene,
and Offline/Live Volume Shadow Copy (VSS) Differential Extraction.
"""
from __future__ import annotations

import bz2
import ctypes
import gzip
import hashlib
import io
import logging
import lzma
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import types
import uuid
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union

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
    from dissect.target.filesystems.ntfs import NtfsFilesystem
except ImportError:
    dissect = None
    NtfsFilesystem = None

try:
    import dissect.ntfs as _dissect_ntfs
except ImportError:
    _dissect_ntfs = None

try:
    import dissect.volume.vss as _dvss_mod
    # Silence module-level WIP debug prints inside dissect.volume.vss thread-safely
    _dvss_mod.__dict__["print"] = lambda *args, **kwargs: None
except ImportError:
    _dvss_mod = None

try:
    import pytsk3
except ImportError:
    pytsk3 = None

try:
    import pyewf
except ImportError:
    pyewf = None

try:
    import pyvshadow
except ImportError:
    pyvshadow = None

try:
    import pyarrow as pa
except ImportError:
    pa = None

from backend.config import (
    get_case_dir,
    get_case_log_file,
    get_case_staging_dir,
    register_case_dir,
)
from backend.db.engine import DuckDBManager, log_processing_event

# =============================================================================
# Forensic Timestamp Constants, Data Models & Windows-Safe Helpers (F8)
# =============================================================================

EPOCH_1970_NAIVE = datetime(1970, 1, 1)
FILETIME_EPOCH_NAIVE = datetime(1601, 1, 1)

# Win32 SetFileTime treats FILETIME == 0 (-11644473600.0 == 1601-01-01T00:00:00Z)
# as "leave existing timestamp unchanged", which would leak host wall-clock now()!
# Values < -11644473599.0 or > 910692730085.0 raise OSError [WinError 87].
MIN_WIN_UTIME_EPOCH: float = -11644473599.0  # 1601-01-01T00:00:01Z
MAX_WIN_UTIME_EPOCH: float = 253402300799.0  # 9999-12-31T23:59:59Z

NORM_VSS_ALWAYS_HASH_NAMES: Set[str] = {
    "system",
    "software",
    "sam",
    "security",
    "default",
    "components",
    "amcache.hve",
    "ntuser.dat",
    "usrclass.dat",
    "srudb.dat",
    "webcachev01.dat",
}

MAX_ARCHIVE_MEMBER_BYTES: int = 512 * 1024 * 1024  # 512 MiB per archive member
MAX_ARCHIVE_TOTAL_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GiB cumulative per archive

_VSS_ARTIFACT_TOKENS: FrozenSet[str] = frozenset(
    {"vss", "fs_vss", "shadow_copies", "volume_shadow_copies"}
)

_WIN32_ILLEGAL_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WIN32_RESERVED_STEMS: FrozenSet[str] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)


def _sanitize_win32_segment(seg: str) -> str:
    """
    Sanitize a single path segment for safe staging onto Windows NTFS:
      - Replaces '..' with '_dotdot_' and skips '' / '.'.
      - Replaces Win32 illegal & NTFS ADS characters (< > : " / \\ | ? * and \\x00-\\x1f) with '_'.
      - Rewrites trailing dots and spaces deterministically so Win32 never strips them.
      - Prefixes Win32 reserved device names (CON, PRN, AUX, NUL, COM1..9, LPT1..9) with '_'.
    """
    if seg in ("", "."):
        return ""
    if seg == "..":
        return "_dotdot_"
    cleaned = _WIN32_ILLEGAL_CHARS_RE.sub("_", seg)
    if cleaned in ("", "."):
        return "_" if seg else ""
    if cleaned == "..":
        return "_dotdot_"
    if cleaned.endswith((".", " ")):
        stripped = cleaned.rstrip(". ")
        pad = "_" * (len(cleaned) - len(stripped))
        cleaned = (stripped + pad) if stripped else pad
    stem = cleaned.split(".", 1)[0].strip().lower()
    if stem in _WIN32_RESERVED_STEMS:
        cleaned = f"_{cleaned}"
    return cleaned


def _sanitize_rel_path(rel_path: str) -> str:
    """Sanitize every segment of a staging-relative path while preserving '/' hierarchy."""
    if not rel_path:
        return ""
    out_segs: List[str] = []
    for raw_seg in rel_path.replace("\\", "/").split("/"):
        if raw_seg in ("", "."):
            continue
        safe_seg = _sanitize_win32_segment(raw_seg)
        if safe_seg:
            out_segs.append(safe_seg)
    return "/".join(out_segs)


def _artifacts_request_vss(selected_artifacts: Optional[Iterable[str]]) -> bool:
    """Return True when selected_artifacts includes a VSS option identifier."""
    if selected_artifacts is None:
        return False
    items: Iterable[Any] = (
        [selected_artifacts]
        if isinstance(selected_artifacts, (str, bytes))
        else selected_artifacts
    )
    try:
        return any(
            str(item).strip().lower() in _VSS_ARTIFACT_TOKENS
            for item in items
            if item is not None
        )
    except Exception:
        return False


def _close_dissect_target(root_obj: Any) -> None:
    """
    Deterministically release all Windows file handles held inside dissect.target.Target,
    containers (Raw/EWF/VMDK/QCOW2/VHD), BufferedStream._fh wrappers, and VolumeSystem caches
    without triggering Target.__getattr__ plugin lookups, touching stdio/loggers, or relying on GC.
    """
    if root_obj is None:
        return
    seen: Set[int] = set()
    protected_streams = {
        id(s)
        for s in (
            sys.stdin,
            sys.stdout,
            sys.stderr,
            getattr(sys, "__stdin__", None),
            getattr(sys, "__stdout__", None),
            getattr(sys, "__stderr__", None),
        )
        if s is not None
    }
    skip_dict_keys = {"log", "logger", "_log", "_logger", "plugins", "_plugins", "_functions"}
    slotted_attrs = (
        "_fh", "fh", "stream", "_stream", "f", "fp", "_fp",
        "raw", "handle", "_handle", "base_fh",
        "fhs", "_fhs", "handles", "_handles",
        "streams", "_streams", "substreams", "extents", "_extents",
        "disks", "_disks", "volumes", "_volumes", "filesystems", "_filesystems",
        "_loader", "loader", "vs", "_vs", "container", "_container", "containers",
    )

    def _walk_close(obj: Any, depth: int) -> None:
        if obj is None or depth > 12:
            return
        oid = id(obj)
        if oid in seen or oid in protected_streams:
            return
        if isinstance(
            obj,
            (
                str,
                bytes,
                bytearray,
                memoryview,
                int,
                float,
                bool,
                type,
                PurePath,
                logging.Logger,
                logging.Handler,
                logging.Manager,
                types.ModuleType,
                types.FunctionType,
                types.MethodType,
                types.BuiltinFunctionType,
            ),
        ):
            return
        seen.add(oid)

        if isinstance(obj, dict):
            for k, val in list(obj.items()):
                if isinstance(k, str) and k in skip_dict_keys:
                    continue
                _walk_close(val, depth + 1)
            return
        if isinstance(obj, (list, tuple, set, frozenset)):
            for val in list(obj):
                _walk_close(val, depth + 1)
            return

        mod_name = getattr(type(obj), "__module__", "") or ""
        obj_dict = None
        if not mod_name.startswith(("logging", "_pytest", "pytest", "pluggy", "unittest")):
            try:
                obj_dict = object.__getattribute__(obj, "__dict__")
            except Exception:
                obj_dict = None
            if isinstance(obj_dict, dict):
                for k, val in list(obj_dict.items()):
                    if isinstance(k, str) and k in skip_dict_keys:
                        continue
                    _walk_close(val, depth + 1)

        if mod_name.startswith("dissect."):
            for cls in type(obj).__mro__:
                cls_slots = getattr(cls, "__slots__", ())
                if isinstance(cls_slots, str):
                    cls_slots = (cls_slots,)
                elif not isinstance(cls_slots, (tuple, list)):
                    continue
                for slot_k in cls_slots:
                    if not isinstance(slot_k, str) or slot_k in ("__dict__", "__weakref__") or slot_k in skip_dict_keys:
                        continue
                    try:
                        s_val = object.__getattribute__(obj, slot_k)
                    except Exception:
                        s_val = None
                    if s_val is not None:
                        _walk_close(s_val, depth + 1)

        for attr_k in slotted_attrs:
            if isinstance(obj_dict, dict) and attr_k in obj_dict:
                continue
            try:
                child = object.__getattribute__(obj, attr_k)
            except Exception:
                child = None
            if child is not None:
                _walk_close(child, depth + 1)

        try:
            close_fn = object.__getattribute__(obj, "close")
        except Exception:
            close_fn = None
        if callable(close_fn):
            try:
                fileno_fn = getattr(obj, "fileno", None)
                if callable(fileno_fn):
                    try:
                        if fileno_fn() in (0, 1, 2):
                            return
                    except Exception:
                        pass
                close_fn()
            except Exception:
                pass

    _walk_close(root_obj, 0)


def _normalize_utc_naive(dt: Optional[datetime]) -> Optional[datetime]:
    """Convert any datetime to UTC naive datetime (for DuckDB TIMESTAMP storage)."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _utc_dt_to_epoch(dt: datetime) -> float:
    """Convert UTC naive or timezone-aware datetime to POSIX epoch seconds cleanly on Windows."""
    naive_utc = _normalize_utc_naive(dt)
    assert naive_utc is not None
    return (naive_utc - EPOCH_1970_NAIVE).total_seconds()


def _filetime_to_utc(ft: Optional[int]) -> Optional[datetime]:
    """
    Convert raw 64-bit Windows FILETIME (100ns ticks since 1601-01-01 UTC) to UTC naive datetime.
    Returns None when ft is None, <= 0 (unset), or outside year 1..9999.
    """
    if not ft or ft <= 0:
        return None
    try:
        return FILETIME_EPOCH_NAIVE + timedelta(microseconds=int(ft) // 10)
    except (OverflowError, ValueError, TypeError):
        return None


def _epoch_to_utc(ts: Optional[Union[int, float]], nano: int = 0) -> Optional[datetime]:
    """
    Convert POSIX epoch seconds (including negative pre-1970 epochs) to UTC naive datetime.
    Returns None when ts is None or 0 (FAT/exFAT/ISO/TSK unset sentinel) — never host now().
    """
    if ts is None or ts == 0:
        return None
    try:
        extra_us = int(nano) // 1000 if nano and nano > 0 else 0
        return EPOCH_1970_NAIVE + timedelta(seconds=float(ts), microseconds=extra_us)
    except (OverflowError, ValueError, OSError, TypeError):
        return None


@dataclass(slots=True)
class ForensicMeta:
    """Canonical forensic file metadata carrying 8 NTFS $SI/$FN or FS MACB timestamps."""
    vfs_path: str
    part_index: int = 0
    fs_type: str = "UNKNOWN"
    vss_id: int = 0
    is_dir: bool = False
    is_deleted: bool = False
    size_bytes: int = 0
    mft_entry: Optional[int] = None
    si_created: Optional[datetime] = None
    si_modified: Optional[datetime] = None
    si_accessed: Optional[datetime] = None
    si_changed: Optional[datetime] = None
    fn_created: Optional[datetime] = None
    fn_modified: Optional[datetime] = None
    fn_accessed: Optional[datetime] = None
    fn_changed: Optional[datetime] = None


@dataclass(slots=True)
class _ActiveFileMeta:
    """Baseline metadata for an allocated active-partition file used for O(1) VSS dedup."""
    size_bytes: int
    si_modified_us: Optional[int]
    staged_path: Optional[Path]
    sha256: Optional[str] = None
    mft_entry: Optional[int] = None
    forensic_meta: Optional[ForensicMeta] = None


def _dt_to_us(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    naive = _normalize_utc_naive(dt)
    assert naive is not None
    delta = naive - EPOCH_1970_NAIVE
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def apply_forensic_utime(dst_path: Union[str, Path], meta: Optional[ForensicMeta]) -> None:
    """
    Apply forensic (atime, mtime) to a staged file on Windows after file close & attribute clear.
    Clamps disk epochs to [MIN_WIN_UTIME_EPOCH, MAX_WIN_UTIME_EPOCH] so FILETIME==0
    (1601-01-01T00:00:00Z) never triggers Win32 SetFileTime's silent no-op and out-of-range
    timestamps never raise WinError 87. When meta is None or carries no timestamps, clamps
    disk (atime, mtime) to (0.0, 0.0) (1970-01-01T00:00:00Z) so staged files never retain
    host wall-clock now() while vfs_files SQL columns remain NULL.
    """
    if meta is None:
        try:
            os.utime(str(dst_path), (0.0, 0.0))
        except (OSError, OverflowError, ValueError):
            pass
        return
    mtime_dt = meta.si_modified or meta.fn_modified or meta.si_created or meta.fn_created
    atime_dt = meta.si_accessed or meta.fn_accessed or mtime_dt
    if mtime_dt is None and atime_dt is None:
        try:
            os.utime(str(dst_path), (0.0, 0.0))
        except (OSError, OverflowError, ValueError):
            pass
        return
    if mtime_dt is None:
        mtime_dt = atime_dt
    if atime_dt is None:
        atime_dt = mtime_dt
    assert mtime_dt is not None and atime_dt is not None
    try:
        a_ts = max(MIN_WIN_UTIME_EPOCH, min(MAX_WIN_UTIME_EPOCH, _utc_dt_to_epoch(atime_dt)))
        m_ts = max(MIN_WIN_UTIME_EPOCH, min(MAX_WIN_UTIME_EPOCH, _utc_dt_to_epoch(mtime_dt)))
        os.utime(str(dst_path), (a_ts, m_ts))
    except (OSError, OverflowError, ValueError):
        pass


def _extract_parent_seg_num(pdir: Any) -> Optional[int]:
    """Decode parent MFT segment ID from either int or dissect _MFT_SEGMENT_REFERENCE."""
    if pdir is None:
        return None
    if isinstance(pdir, int):
        return pdir & 0xFFFFFFFFFFFF
    low = getattr(pdir, "SegmentNumberLowPart", None)
    if low is not None:
        high = int(getattr(pdir, "SegmentNumberHighPart", 0) or 0)
        return ((high << 32) | int(low)) & 0xFFFFFFFFFFFF
    try:
        return int(pdir) & 0xFFFFFFFFFFFF
    except Exception:
        return None


def _extract_ntfs_fn_links(
    fn_list: List[Any],
) -> Tuple[List[Tuple[Optional[int], str, List[Optional[datetime]]]], int, int]:
    """
    Extract all distinct NTFS $FILE_NAME (0x30) hardlink (parent_seg, file_name, fn_timestamps)
    tuples on an MFT segment:
      - Collapses DOS 8.3 aliases (flags == 2) ONLY against Win32/POSIX names in the SAME parent_seg.
      - Preserves multiple distinct hardlinks across different parent_segs AND within the same parent_seg.
    Returns (links, combined_file_attributes, max_fn_file_size).
    """
    grouped: Dict[Optional[int], List[Tuple[int, str, List[Optional[datetime]]]]] = {}
    combined_attrs = 0
    max_fn_sz = 0
    for f in fn_list:
        raw_fn = getattr(f, "attr", None)
        fname = str(getattr(f, "file_name", "") or "")
        if not fname:
            continue
        p_seg = _extract_parent_seg_num(getattr(raw_fn, "ParentDirectory", None)) if raw_fn is not None else None
        ns_flags = int(
            getattr(f, "flags", None)
            if getattr(f, "flags", None) is not None
            else (getattr(raw_fn, "Flags", 0) if raw_fn is not None else 0)
        )
        if raw_fn is not None:
            combined_attrs |= int(getattr(raw_fn, "FileAttributes", 0) or 0)
            max_fn_sz = max(max_fn_sz, int(getattr(raw_fn, "FileSize", 0) or 0))
            fn_t: List[Optional[datetime]] = [
                _filetime_to_utc(getattr(raw_fn, "CreationTime", 0)),
                _filetime_to_utc(getattr(raw_fn, "LastModificationTime", 0)),
                _filetime_to_utc(getattr(raw_fn, "LastAccessTime", 0)),
                _filetime_to_utc(getattr(raw_fn, "LastChangeTime", 0)),
            ]
        else:
            fn_t = [None, None, None, None]
        grouped.setdefault(p_seg, []).append((ns_flags, fname, fn_t))

    links: List[Tuple[Optional[int], str, List[Optional[datetime]]]] = []
    for p_seg, entries in grouped.items():
        non_dos = [e for e in entries if e[0] != 2]
        chosen_pool = non_dos if non_dos else entries
        seen_names_in_dir: Set[str] = set()
        for _, fname, fn_t in chosen_pool:
            low_nm = fname.lower()
            if low_nm in seen_names_in_dir:
                continue
            seen_names_in_dir.add(low_nm)
            links.append((p_seg, fname, fn_t))
    return links, combined_attrs, max_fn_sz


def extract_meta_dissect(
    entry_obj: Any,
    vfs_path: str,
    part_index: int,
    fs_type: str,
    vss_id: int = 0,
) -> ForensicMeta:
    """Extract all 8 $SI + $FN timestamps (unwrapping up to 4 hops to MftRecord) from a dissect entry."""
    meta = ForensicMeta(
        vfs_path=vfs_path,
        part_index=part_index,
        fs_type=fs_type,
        vss_id=vss_id,
    )
    rec = entry_obj
    for _ in range(4):
        if rec is None or (hasattr(rec, "attributes") and hasattr(rec, "segment")):
            break
        nxt = None
        for attr_k in ("_entry", "entry", "record"):
            try:
                cand = object.__getattribute__(rec, attr_k)
            except Exception:
                cand = getattr(rec, attr_k, None)
            if cand is not None and cand is not rec:
                nxt = cand
                break
        if nxt is None:
            break
        rec = nxt

    if rec is not None and hasattr(rec, "attributes") and hasattr(rec, "segment"):
        try:
            meta.mft_entry = int(rec.segment) if rec.segment is not None else None
            hdr = getattr(rec, "header", None)
            if hdr is not None and hasattr(hdr, "Flags"):
                meta.is_deleted = not bool(hdr.Flags & 0x0001)
                meta.is_dir = bool(hdr.Flags & 0x0002)
            if not meta.is_dir:
                try:
                    meta.size_bytes = int(rec.size())
                except Exception:
                    meta.size_bytes = 0
            attrs = rec.attributes
            si_coll = attrs.get(16, []) if hasattr(attrs, "get") else getattr(attrs, "STANDARD_INFORMATION", [])
            if si_coll:
                si_inner = getattr(si_coll[0], "attribute", si_coll[0])
                raw_si = getattr(si_inner, "attr", None)
                if raw_si is not None:
                    meta.si_created = _filetime_to_utc(getattr(raw_si, "CreationTime", 0))
                    meta.si_modified = _filetime_to_utc(getattr(raw_si, "LastModificationTime", 0))
                    meta.si_accessed = _filetime_to_utc(getattr(raw_si, "LastAccessTime", 0))
                    meta.si_changed = _filetime_to_utc(getattr(raw_si, "LastChangeTime", 0))
            fn_coll = attrs.get(48, []) if hasattr(attrs, "get") else getattr(attrs, "FILE_NAME", [])
            if fn_coll:
                fn_unwrapped = [getattr(f, "attribute", f) for f in fn_coll]
                target_leaf_low = PurePosixPath(vfs_path).name.lower() if vfs_path and vfs_path != "/" else ""
                chosen_fn = next(
                    (
                        f
                        for f in fn_unwrapped
                        if getattr(f, "flags", 0) != 2
                        and target_leaf_low
                        and str(getattr(f, "file_name", "") or "").lower() == target_leaf_low
                    ),
                    None,
                )
                if chosen_fn is None:
                    chosen_fn = next((f for f in fn_unwrapped if getattr(f, "flags", 0) != 2), fn_unwrapped[0])
                raw_fn = getattr(chosen_fn, "attr", None)
                if raw_fn is not None:
                    meta.fn_created = _filetime_to_utc(getattr(raw_fn, "CreationTime", 0))
                    meta.fn_modified = _filetime_to_utc(getattr(raw_fn, "LastModificationTime", 0))
                    meta.fn_accessed = _filetime_to_utc(getattr(raw_fn, "LastAccessTime", 0))
                    meta.fn_changed = _filetime_to_utc(getattr(raw_fn, "LastChangeTime", 0))
                    if meta.size_bytes == 0 and not meta.is_dir:
                        meta.size_bytes = int(getattr(raw_fn, "FileSize", 0) or 0)
            return meta
        except Exception:
            pass

    try:
        st = entry_obj.lstat() if hasattr(entry_obj, "lstat") else entry_obj.stat()
        meta.size_bytes = int(getattr(st, "st_size", 0) or 0)
        meta.is_dir = stat.S_ISDIR(getattr(st, "st_mode", 0))
        birthtime = getattr(st, "st_birthtime", None)
        meta.si_created = _epoch_to_utc(birthtime)
        meta.si_modified = _epoch_to_utc(getattr(st, "st_mtime", None))
        meta.si_accessed = _epoch_to_utc(getattr(st, "st_atime", None))
        ctime = getattr(st, "st_ctime", None)
        if ctime != birthtime:
            meta.si_changed = _epoch_to_utc(ctime)
    except Exception:
        pass
    return meta


def extract_meta_pytsk3(
    tsk_file: Any,
    vfs_path: str,
    part_index: int,
    fs_type: str,
    is_ntfs: bool,
    vss_id: int = 0,
    force_deleted: bool = False,
) -> ForensicMeta:
    """Extract 8 $SI/$FN timestamps on pytsk3 NTFS or 4 MACB timestamps on FAT/exFAT/ISO9660."""
    m = getattr(tsk_file.info, "meta", None)
    nm = getattr(tsk_file.info, "name", None)
    is_del = bool(force_deleted)
    if pytsk3 is not None:
        if m is not None and bool(m.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC):
            is_del = True
        if nm is not None and bool(nm.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC):
            is_del = True
    is_dir = False
    if pytsk3 is not None and m is not None:
        is_dir = m.type in (pytsk3.TSK_FS_META_TYPE_DIR, pytsk3.TSK_FS_META_TYPE_VIRT_DIR)
    meta = ForensicMeta(
        vfs_path=vfs_path,
        part_index=part_index,
        fs_type=fs_type,
        vss_id=vss_id,
        is_dir=is_dir,
        is_deleted=is_del,
        size_bytes=int(m.size) if (m is not None and getattr(m, "size", 0)) else 0,
        mft_entry=int(m.addr) if (is_ntfs and m is not None and getattr(m, "addr", None) is not None) else None,
    )
    if m is None:
        return meta

    if is_ntfs and pytsk3 is not None:
        try:
            best_fn_ns: Optional[int] = None
            for attr in tsk_file:
                atype = attr.info.type
                if atype == pytsk3.TSK_FS_ATTR_TYPE_NTFS_SI and attr.info.size >= 32:
                    raw = tsk_file.read_random(0, 32, atype, attr.info.id)
                    cr, mod, chg, acc = struct.unpack("<4Q", raw[:32])
                    meta.si_created = _filetime_to_utc(cr)
                    meta.si_modified = _filetime_to_utc(mod)
                    meta.si_changed = _filetime_to_utc(chg)
                    meta.si_accessed = _filetime_to_utc(acc)
                elif atype == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME and attr.info.size >= 66:
                    raw = tsk_file.read_random(0, 66, atype, attr.info.id)
                    ns = raw[65]
                    if best_fn_ns is None or (best_fn_ns == 2 and ns != 2):
                        cr, mod, chg, acc = struct.unpack("<4Q", raw[8:40])
                        meta.fn_created = _filetime_to_utc(cr)
                        meta.fn_modified = _filetime_to_utc(mod)
                        meta.fn_changed = _filetime_to_utc(chg)
                        meta.fn_accessed = _filetime_to_utc(acc)
                        best_fn_ns = ns
        except Exception:
            pass

    if meta.si_created is None:
        meta.si_created = _epoch_to_utc(getattr(m, "crtime", 0), getattr(m, "crtime_nano", 0))
    if meta.si_modified is None:
        meta.si_modified = _epoch_to_utc(getattr(m, "mtime", 0), getattr(m, "mtime_nano", 0))
    if meta.si_accessed is None:
        meta.si_accessed = _epoch_to_utc(getattr(m, "atime", 0), getattr(m, "atime_nano", 0))
    if meta.si_changed is None:
        meta.si_changed = _epoch_to_utc(getattr(m, "ctime", 0), getattr(m, "ctime_nano", 0))
    return meta


# =============================================================================
# Stream Wrappers: PartitionSubStream & Thread-Safe StreamImgInfo (F7, F27, F28)
# =============================================================================

class PartitionSubStream(io.RawIOBase):
    """Wraps a disk-level stream (raw file, pyewf.handle, or hypervisor disk) into a partition-bounded stream."""

    def __init__(
        self,
        base_fh: Any,
        offset: int,
        size: int,
        read_lock: Optional[threading.Lock] = None,
    ) -> None:
        super().__init__()
        self._fh = base_fh
        self._offset = int(offset)
        self._size = int(size)
        self._pos = 0
        self._lock = read_lock

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = max(0, int(offset))
        elif whence == io.SEEK_CUR:
            self._pos = max(0, self._pos + int(offset))
        elif whence == io.SEEK_END:
            self._pos = max(0, self._size + int(offset))
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if self._pos >= self._size:
            return b""
        to_read = (
            (self._size - self._pos)
            if (size is None or size < 0)
            else min(int(size), self._size - self._pos)
        )
        if to_read <= 0:
            return b""
        if self._lock is not None:
            with self._lock:
                self._fh.seek(self._offset + self._pos)
                data = self._fh.read(to_read)
        else:
            self._fh.seek(self._offset + self._pos)
            data = self._fh.read(to_read)
        self._pos += len(data)
        return data


if pytsk3 is not None:
    class StreamImgInfo(pytsk3.Img_Info):
        """Thread-safe pytsk3.Img_Info adapter over pyewf, dissect hypervisor streams, or raw files."""

        def __init__(self, stream: Any, size: int, read_lock: Optional[Union[threading.Lock, threading.RLock]] = None) -> None:
            self._stream = stream
            self._size = int(size)
            self._lock = read_lock or threading.RLock()
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self) -> None:
            pass

        def read(self, offset: int, size: int) -> bytes:
            if offset < 0 or offset >= self._size or size <= 0:
                return b""
            clamped = min(int(size), self._size - int(offset))
            with self._lock:
                self._stream.seek(int(offset))
                return self._stream.read(clamped)

        def get_size(self) -> int:
            return self._size
else:
    StreamImgInfo = None  # type: ignore[assignment,misc]


# =============================================================================
# Tier C: Pure-Python ECMA-167 / OSTA UDF 1.02–2.60 + Type 2 VAT Reader (F7)
# =============================================================================

def _decode_osta_cs0(raw: bytes) -> str:
    """Decode variable-length OSTACompressedUnicode byte array (FID file identifiers)."""
    if not raw:
        return ""
    comp_id = raw[0]
    payload = raw[1:]
    if comp_id == 8:
        return payload.decode("latin-1", errors="replace").rstrip("\x00")
    if comp_id == 16:
        if len(payload) % 2 == 1:
            payload = payload[:-1]
        return payload.decode("utf-16-be", errors="replace").rstrip("\x00")
    return raw.decode("latin-1", errors="replace").rstrip("\x00")


def _decode_osta_dstring(field: bytes) -> str:
    """Decode fixed-length ECMA-167 dstring where the final byte holds byte count."""
    if not field:
        return ""
    n_bytes = field[-1]
    if n_bytes == 0 or n_bytes > len(field) - 1:
        return _decode_osta_cs0(field[:-1]).strip()
    return _decode_osta_cs0(field[:n_bytes]).strip()


def _parse_udf_timestamp(b12: bytes) -> Optional[datetime]:
    """Parse 12-byte ECMA-167 1/7.3 timestamp into UTC naive datetime (or None if unset)."""
    if len(b12) < 12 or b12 == b"\x00" * 12:
        return None
    tz_type, yr = struct.unpack("<Hh", b12[:4])
    mo, da, hr, mi, sc, cs, hms, us = b12[4:12]
    if yr <= 0 or not (1 <= mo <= 12) or not (1 <= da <= 31):
        return None
    tz_raw = tz_type & 0x0FFF
    tz_min = (tz_raw - 0x1000) if (tz_raw & 0x0800) else tz_raw
    if (tz_type >> 12) == 1 and -1440 <= tz_min <= 1440 and tz_raw != 2047:
        tz = timezone(timedelta(minutes=tz_min))
    else:
        tz = timezone.utc
    try:
        usec = min(999999, int(cs) * 10000 + int(hms) * 100 + int(us))
        dt = datetime(yr, mo, da, min(hr, 23), min(mi, 59), min(sc, 59), usec, tzinfo=tz)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


@dataclass(slots=True)
class _UdfEntryRecord:
    vfs_path: str
    file_name: str
    parent_path: str
    is_dir: bool
    is_deleted: bool
    size_bytes: int
    si_created: Optional[datetime]
    si_modified: Optional[datetime]
    si_accessed: Optional[datetime]
    si_changed: Optional[datetime]
    fe_sector: int
    inline_data: Optional[bytes]
    extents: List[Tuple[int, int]]  # list of (phys_sector, byte_len)


MAX_ISO_VD_SECTORS = 256


def _validate_iso9660_pvd_before_pytsk3(
    stream: Any,
    part_offset: int,
    part_size: int,
    read_lock: threading.Lock,
) -> Tuple[bool, Optional[str]]:
    """
    Pre-validate ECMA-119 / ISO9660 Volume Descriptors starting at part_offset + 0x8000 across
    up to MAX_ISO_VD_SECTORS (512 KiB) until Volume Descriptor Set Terminator (vd_type == 255)
    BEFORE invoking pytsk3.FS_Info so malformed CD001 PVDs/SVDs (including at sec_i >= 16)
    never trigger libtsk's native C stack overflow (0xC00000FD) on Windows.
    """
    if stream is None or part_size < 0x8800:
        return True, None

    avail_bytes = int(part_size) - 0x8000
    max_scan_bytes = min(MAX_ISO_VD_SECTORS * 2048, avail_bytes)
    chunk_bytes = 32 * 2048

    found_pvd_or_svd = False
    found_terminator = False
    sec_i = 0
    cur_rel = 0

    while cur_rel < max_scan_bytes:
        to_read = min(chunk_bytes, max_scan_bytes - cur_rel)
        try:
            with read_lock:
                stream.seek(int(part_offset) + 0x8000 + cur_rel)
                buf = stream.read(to_read)
        except Exception as read_err:
            if sec_i == 0:
                return True, None
            return (
                False,
                f"Malformed ISO9660 volume descriptor sequence at offset {part_offset}: stream read error ({read_err})",
            )

        if sec_i == 0 and (len(buf) < 2048 or buf[1:6] != b"CD001"):
            return True, None

        if len(buf) < 2048:
            return (
                False,
                f"Malformed ISO9660 volume descriptor sequence at offset {part_offset}: "
                f"truncated descriptor at sector +{16 + sec_i} before terminator",
            )

        n_whole = len(buf) // 2048
        for idx in range(n_whole):
            vd = buf[idx * 2048 : (idx + 1) * 2048]
            if vd[1:6] != b"CD001":
                return (
                    False,
                    f"Malformed ISO9660 volume descriptor sequence at offset {part_offset}: "
                    f"missing CD001 magic at sector +{16 + sec_i} before terminator",
                )
            vd_type = vd[0]
            if vd_type == 255:
                found_terminator = True
                break
            if vd_type in (1, 2):
                found_pvd_or_svd = True
                logical_block_size = struct.unpack_from("<H", vd, 0x80)[0]
                path_table_size = struct.unpack_from("<I", vd, 0x84)[0]
                type_l_path_table = struct.unpack_from("<I", vd, 0x8C)[0]
                if logical_block_size not in (512, 1024, 2048):
                    return (
                        False,
                        f"Malformed ISO9660 volume descriptor (type={vd_type}) at offset {part_offset} "
                        f"(sector +{16 + sec_i}): invalid logical_block_size={logical_block_size}",
                    )
                total_blocks = max(1, int(part_size) // logical_block_size)
                min_lba = 0x8000 // logical_block_size
                if not (
                    0 < path_table_size <= part_size
                    and min_lba < type_l_path_table < total_blocks
                    and (type_l_path_table * logical_block_size + path_table_size <= part_size)
                ):
                    return (
                        False,
                        f"Malformed ISO9660 volume descriptor (type={vd_type}) at offset {part_offset} "
                        f"(sector +{16 + sec_i}): block_size={logical_block_size}, "
                        f"path_table_size={path_table_size}, type_l_path_table={type_l_path_table}, "
                        f"total_blocks={total_blocks}",
                    )
            sec_i += 1

        if found_terminator:
            break
        cur_rel += n_whole * 2048
        if len(buf) < to_read and not found_terminator:
            break

    if not found_terminator:
        return (
            False,
            f"Malformed ISO9660 volume descriptor sequence at offset {part_offset}: "
            f"missing Volume Descriptor Set Terminator within {MAX_ISO_VD_SECTORS} sectors",
        )
    if not found_pvd_or_svd:
        return (
            False,
            f"Malformed ISO9660 volume descriptor sequence at offset {part_offset}: "
            "missing Primary Volume Descriptor",
        )
    return True, None


def _has_udf_bea_nsr(stream: Any, part_offset: int, part_size: int, read_lock: threading.Lock) -> bool:
    """Check 2048-byte Volume Recognition Sequence @ +0x8000..+0x10000 for BEA01 / NSR02 / NSR03."""
    if part_size < 0x9800:
        return False
    with read_lock:
        stream.seek(part_offset + 0x8000)
        vrs = stream.read(min(0x8000, part_size - 0x8000))
    return (b"NSR02" in vrs or b"NSR03" in vrs) and b"BEA01" in vrs


def _parse_udf_volume(
    stream: Any,
    part_offset: int,
    part_size: int,
    read_lock: threading.Lock,
) -> Optional[Tuple[str, str, List[_UdfEntryRecord]]]:
    """
    Parse ECMA-167 / OSTA UDF 1.02–2.60 volume (including Type 2 Virtual Partition multi-session VAT).
    Returns (volume_label, volume_serial, entries) or None if not a valid UDF volume.
    """
    sec_size = 2048
    total_secs = part_size // sec_size
    if total_secs < 300:
        return None

    def read_sec(s: int, count: int = 1) -> bytes:
        if s < 0 or s >= total_secs:
            return b""
        clamped_cnt = min(count, total_secs - s)
        with read_lock:
            stream.seek(part_offset + s * sec_size)
            return stream.read(clamped_cnt * sec_size)

    # 1. Locate Anchor Volume Descriptor Pointer (AVDP, tag_id == 2)
    avdp_buf = b""
    for cand_sec in (256, total_secs - 256, total_secs - 1, 512):
        if 0 <= cand_sec < total_secs:
            b = read_sec(cand_sec)
            if len(b) >= 24 and struct.unpack("<H", b[:2])[0] == 2:
                avdp_buf = b
                break
    if not avdp_buf:
        return None

    mvds_len, mvds_loc = struct.unpack("<II", avdp_buf[16:24])
    rvds_len, rvds_loc = struct.unpack("<II", avdp_buf[24:32])

    label = ""
    vol_serial = ""
    part_starts: Dict[int, int] = {}
    fsd_lb = 0
    fsd_pr = 0
    has_type2_vat = False
    phys_part_start = 0

    for vds_loc, vds_len in ((mvds_loc, mvds_len), (rvds_loc, rvds_len)):
        if vds_loc == 0 or vds_len == 0:
            continue
        n_vds = max(1, min(64, vds_len // sec_size))
        vds_raw = read_sec(vds_loc, n_vds)
        for i in range(n_vds):
            d = vds_raw[i * sec_size : (i + 1) * sec_size]
            if len(d) < 512:
                break
            tid = struct.unpack("<H", d[:2])[0]
            if tid == 8:  # Terminating Descriptor
                break
            if tid == 1:  # Primary Volume Descriptor
                pvd_label = _decode_osta_dstring(d[24:56])
                if pvd_label and not label:
                    label = pvd_label
                vset = _decode_osta_dstring(d[72:200])
                if vset and not vol_serial:
                    m_ser = re.match(r"^([0-9A-Fa-f]{8,16})", vset)
                    vol_serial = m_ser.group(1).upper() if m_ser else vset[:16]
            elif tid == 5:  # Partition Descriptor
                p_num = struct.unpack("<H", d[22:24])[0]
                p_start = struct.unpack("<I", d[188:192])[0]
                part_starts[p_num] = p_start
                phys_part_start = p_start
            elif tid == 6:  # Logical Volume Descriptor
                sec_sz_lvd = struct.unpack("<I", d[212:216])[0]
                if sec_sz_lvd in (512, 1024, 2048, 4096):
                    sec_size = sec_sz_lvd
                    total_secs = part_size // sec_size
                lvd_label = _decode_osta_dstring(d[84:212])
                if lvd_label:
                    label = lvd_label
                _, fsd_lb, fsd_pr = struct.unpack("<IIH", d[248:258])
                mt_len, n_pm = struct.unpack("<II", d[264:272])
                pm_buf = d[440 : 440 + mt_len]
                pm_off = 0
                for _ in range(n_pm):
                    if pm_off + 2 > len(pm_buf):
                        break
                    pm_type, pm_len = pm_buf[pm_off], pm_buf[pm_off + 1]
                    if pm_len == 0:
                        break
                    pm_entry = pm_buf[pm_off : pm_off + pm_len]
                    if pm_type == 2 and b"*UDF Virtual Partition" in pm_entry:
                        has_type2_vat = True
                    pm_off += pm_len
        if part_starts:
            break

    if not part_starts:
        return None
    if phys_part_start == 0:
        phys_part_start = next(iter(part_starts.values()))

    def parse_fe_extents_and_meta(
        fe_buf: bytes,
        fe_sec: int,
        vat_table: Optional[Tuple[int, ...]],
        default_part_ref: int,
    ) -> Optional[
        Tuple[
            int,  # file_type (4=dir, 5=file, 248=VAT)
            int,  # info_len
            Optional[datetime],  # crtime
            Optional[datetime],  # mtime
            Optional[datetime],  # atime
            Optional[datetime],  # ctime
            Optional[bytes],  # inline_data
            List[Tuple[int, int]],  # extents (phys_sec, byte_len)
        ]
    ]:
        if len(fe_buf) < 176:
            return None
        tid = struct.unpack("<H", fe_buf[:2])[0]
        if tid not in (261, 266):
            return None
        icb_file_type = fe_buf[27]
        icb_flags = struct.unpack("<H", fe_buf[34:36])[0]
        ad_type = icb_flags & 0x0007
        info_len = struct.unpack("<Q", fe_buf[56:64])[0]

        if tid == 266:  # Extended File Entry
            if len(fe_buf) < 216:
                return None
            atime = _parse_udf_timestamp(fe_buf[80:92])
            mtime = _parse_udf_timestamp(fe_buf[92:104])
            crtime = _parse_udf_timestamp(fe_buf[104:116])
            ctime = _parse_udf_timestamp(fe_buf[116:128])
            l_ea, l_ad = struct.unpack("<II", fe_buf[208:216])
            hdr_end = 216
        else:  # Standard File Entry (261)
            atime = _parse_udf_timestamp(fe_buf[72:84])
            mtime = _parse_udf_timestamp(fe_buf[84:96])
            ctime = _parse_udf_timestamp(fe_buf[96:108])
            crtime = mtime
            l_ea, l_ad = struct.unpack("<II", fe_buf[168:176])
            hdr_end = 176

        ad_start = hdr_end + l_ea
        ad_raw = fe_buf[ad_start : ad_start + l_ad]

        def resolve_lba(lb: int, pr: int) -> int:
            if vat_table is not None and pr != 0:
                if 0 <= lb < len(vat_table) and vat_table[lb] != 0xFFFFFFFF:
                    return phys_part_start + vat_table[lb]
            base_p = part_starts.get(pr, phys_part_start)
            return base_p + lb

        if ad_type == 3:
            return (icb_file_type, min(info_len, len(ad_raw)), crtime, mtime, atime, ctime, ad_raw[:info_len], [])

        extents: List[Tuple[int, int]] = []

        def decode_ad_buffer(buf: bytes, cur_pr: int) -> None:
            pos = 0
            step = 8 if ad_type == 0 else (16 if ad_type == 1 else 20)
            if ad_type not in (0, 1, 2):
                return
            while pos + step <= len(buf):
                raw_len = struct.unpack("<I", buf[pos : pos + 4])[0]
                ext_type = (raw_len >> 30) & 0x03
                byte_len = raw_len & 0x3FFFFFFF
                if byte_len == 0:
                    break
                if ad_type == 0:
                    lb = struct.unpack("<I", buf[pos + 4 : pos + 8])[0]
                    pr = cur_pr
                elif ad_type == 1:
                    lb, pr = struct.unpack("<IH", buf[pos + 4 : pos + 10])
                else:
                    lb, pr = struct.unpack("<IH", buf[pos + 12 : pos + 18])
                if ext_type == 3:  # Continuation of Allocation Descriptors
                    cont_sec = resolve_lba(lb, pr)
                    cont_buf = read_sec(cont_sec, max(1, (byte_len + sec_size - 1) // sec_size))
                    if len(cont_buf) >= 24 and struct.unpack("<H", cont_buf[:2])[0] == 258:
                        aed_len = struct.unpack("<I", cont_buf[20:24])[0]
                        decode_ad_buffer(cont_buf[24 : 24 + aed_len], pr)
                elif ext_type == 0:  # Recorded and allocated
                    extents.append((resolve_lba(lb, pr), byte_len))
                pos += step

        decode_ad_buffer(ad_raw, default_part_ref)
        return (icb_file_type, info_len, crtime, mtime, atime, ctime, None, extents)

    def read_udf_entry_bytes(inline_data: Optional[bytes], extents: List[Tuple[int, int]], max_bytes: int) -> bytes:
        if inline_data is not None:
            return inline_data[:max_bytes]
        chunks: List[bytes] = []
        rem = max_bytes
        for psec, blen in extents:
            if rem <= 0:
                break
            take = min(blen, rem)
            n_s = (take + sec_size - 1) // sec_size
            data = read_sec(psec, n_s)[:take]
            chunks.append(data)
            rem -= len(data)
        return b"".join(chunks)

    def load_vat_from_sector(s: int) -> Optional[Tuple[int, ...]]:
        fe = read_sec(s)
        parsed = parse_fe_extents_and_meta(fe, s, None, 0)
        if parsed is None:
            return None
        ft, info_len, _, _, _, _, inl, exts = parsed
        if info_len == 0 or info_len > 16 * 1024 * 1024:
            return None
        if ft == 248:  # UDF 2.00+ VAT
            raw = read_udf_entry_bytes(inl, exts, info_len)
            if len(raw) < 8:
                return None
            hdr_len = struct.unpack("<H", raw[:2])[0]
            if hdr_len > len(raw) or (len(raw) - hdr_len) < 4:
                return None
            n_ent = (len(raw) - hdr_len) // 4
            return struct.unpack(f"<{n_ent}I", raw[hdr_len : hdr_len + n_ent * 4])
        if ft == 0:  # UDF 1.50 VAT (ends with 36-byte *UDF Virtual Alloc Tbl trailer)
            raw = read_udf_entry_bytes(inl, exts, info_len)
            if len(raw) >= 40 and b"*UDF Virtual Alloc Tbl" in raw[-36:]:
                body = raw[:-36]
                n_ent = len(body) // 4
                return struct.unpack(f"<{n_ent}I", body[: n_ent * 4])
        return None

    vat_sessions: List[Optional[Tuple[int, ...]]] = []
    if has_type2_vat:
        # Fast buffered scan across physical partition sectors to discover all VAT ICBs across sessions
        vat_secs: List[int] = []
        batch_secs = 512  # 1 MiB per read
        cur_s = phys_part_start
        while cur_s < total_secs:
            cnt = min(batch_secs, total_secs - cur_s)
            chunk = read_sec(cur_s, cnt)
            actual_cnt = len(chunk) // sec_size
            for idx_in_chunk in range(actual_cnt):
                off = idx_in_chunk * sec_size
                tid = chunk[off] | (chunk[off + 1] << 8)
                if tid in (261, 266):
                    ft = chunk[off + 27]
                    if ft == 248 or (ft == 0 and b"*UDF Virtual Alloc Tbl" in chunk[off : off + sec_size]):
                        vat_secs.append(cur_s + idx_in_chunk)
            cur_s += max(1, actual_cnt)

        for vs in vat_secs:
            vt = load_vat_from_sector(vs)
            if vt:
                vat_sessions.append(vt)

    if not vat_sessions:
        vat_sessions = [None]

    collected: List[_UdfEntryRecord] = []
    seen_paths_lower: Set[str] = set()

    def walk_session(vat_tbl: Optional[Tuple[int, ...]], session_is_historical: bool) -> None:
        # Resolve File Set Descriptor (tag_id == 256)
        if vat_tbl is not None and fsd_pr != 0:
            if fsd_lb >= len(vat_tbl) or vat_tbl[fsd_lb] == 0xFFFFFFFF:
                return
            fsd_phys = phys_part_start + vat_tbl[fsd_lb]
        else:
            fsd_phys = part_starts.get(fsd_pr, phys_part_start) + fsd_lb

        fsd_buf = read_sec(fsd_phys)
        if len(fsd_buf) < 416 or struct.unpack("<H", fsd_buf[:2])[0] != 256:
            return
        _, root_lb, root_pr = struct.unpack("<IIH", fsd_buf[400:410])

        visited_fe_secs: Set[int] = set()

        def resolve_icb_sec(lb: int, pr: int) -> Optional[int]:
            if vat_tbl is not None and pr != 0:
                if lb < 0 or lb >= len(vat_tbl) or vat_tbl[lb] == 0xFFFFFFFF:
                    return None
                return phys_part_start + vat_tbl[lb]
            return part_starts.get(pr, phys_part_start) + lb

        def walk_dir(dir_lb: int, dir_pr: int, cur_vfs_dir: str, force_del: bool, depth: int) -> None:
            if depth > 32:
                return
            fe_sec = resolve_icb_sec(dir_lb, dir_pr)
            if fe_sec is None or fe_sec in visited_fe_secs:
                return
            visited_fe_secs.add(fe_sec)

            fe_buf = read_sec(fe_sec)
            parsed = parse_fe_extents_and_meta(fe_buf, fe_sec, vat_tbl, dir_pr)
            if parsed is None:
                return
            ft, info_len, crtime, mtime, atime, ctime, inl, exts = parsed
            if ft != 4:  # Not a directory
                return

            if cur_vfs_dir == "/" and "/" not in seen_paths_lower:
                seen_paths_lower.add("/")
                collected.append(
                    _UdfEntryRecord(
                        vfs_path="/",
                        file_name="",
                        parent_path="",
                        is_dir=True,
                        is_deleted=False,
                        size_bytes=0,
                        si_created=crtime,
                        si_modified=mtime,
                        si_accessed=atime,
                        si_changed=ctime,
                        fe_sector=fe_sec,
                        inline_data=None,
                        extents=[],
                    )
                )

            dir_bytes = read_udf_entry_bytes(inl, exts, min(info_len, 8 * 1024 * 1024))
            off = 0
            while off + 38 <= len(dir_bytes):
                ftid = struct.unpack("<H", dir_bytes[off : off + 2])[0]
                if ftid != 257:  # File Identifier Descriptor
                    break
                f_char = dir_bytes[off + 18]
                l_fi = dir_bytes[off + 19]
                _, child_lb, child_pr = struct.unpack("<IIH", dir_bytes[off + 20 : off + 30])
                l_iu = struct.unpack("<H", dir_bytes[off + 36 : off + 38])[0]
                rec_len = (38 + l_iu + l_fi + 3) & ~3
                if rec_len <= 0 or off + rec_len > len(dir_bytes):
                    break

                is_parent_ptr = bool(f_char & 0x08)
                if not is_parent_ptr and l_fi > 0:
                    raw_name = dir_bytes[off + 38 + l_iu : off + 38 + l_iu + l_fi]
                    decoded_raw = _decode_osta_cs0(raw_name).strip("\x00")
                    fid_deleted = bool(f_char & 0x04) or force_del or session_is_historical
                    if fid_deleted and decoded_raw.startswith("\xfe") and len(decoded_raw) > 1:
                        decoded_raw = decoded_raw[1:]
                    if decoded_raw.strip() in ("", ".", ".."):
                        off += rec_len
                        continue
                    # Normalize embedded slashes or '..' inside hostile UDF FID entry names safely
                    norm_segs: List[str] = []
                    for seg_part in decoded_raw.replace("\\", "/").split("/"):
                        if seg_part in ("", "."):
                            continue
                        norm_segs.append("_dotdot_" if seg_part == ".." else seg_part)
                    fname = "/".join(norm_segs)

                    # Skip zeroed-ICB deleted FID tombstones in newer VATs so earlier VAT sessions
                    # recover the uncorrupted directory/file ICBs and contents cleanly.
                    if not (bool(f_char & 0x04) and child_lb == 0 and child_pr == 0) and fname:
                        child_vfs = f"/{fname}" if cur_vfs_dir == "/" else f"{cur_vfs_dir}/{fname}"
                        leaf_fname = PurePosixPath(child_vfs).name
                        par_vfs = str(PurePosixPath(child_vfs).parent) if str(PurePosixPath(child_vfs).parent) != "." else "/"
                        child_sec = resolve_icb_sec(child_lb, child_pr)
                        if child_sec is not None:
                            cfe_buf = read_sec(child_sec)
                            cparsed = parse_fe_extents_and_meta(cfe_buf, child_sec, vat_tbl, child_pr)
                            if cparsed is not None:
                                c_ft, c_sz, c_cr, c_mo, c_ac, c_ct, c_inl, c_exts = cparsed
                                c_is_dir = bool(f_char & 0x02) or (c_ft == 4)
                                key_low = child_vfs.lower()
                                if key_low not in seen_paths_lower:
                                    seen_paths_lower.add(key_low)
                                    collected.append(
                                        _UdfEntryRecord(
                                            vfs_path=child_vfs,
                                            file_name=leaf_fname,
                                            parent_path=par_vfs,
                                            is_dir=c_is_dir,
                                            is_deleted=fid_deleted,
                                            size_bytes=0 if c_is_dir else int(c_sz),
                                            si_created=c_cr,
                                            si_modified=c_mo,
                                            si_accessed=c_ac,
                                            si_changed=c_ct,
                                            fe_sector=child_sec,
                                            inline_data=c_inl,
                                            extents=c_exts,
                                        )
                                    )
                                if c_is_dir:
                                    walk_dir(child_lb, child_pr, child_vfs, fid_deleted, depth + 1)

                off += rec_len

        walk_dir(root_lb, root_pr, "/", session_is_historical, 0)

    # Walk latest VAT session first (active state), then earlier VAT sessions in reverse (historical deleted)
    walk_session(vat_sessions[-1], session_is_historical=False)
    for earlier_vat in reversed(vat_sessions[:-1]):
        walk_session(earlier_vat, session_is_historical=True)

    return (label or "UDF_Volume", vol_serial, collected)


# =============================================================================
# EvidenceExtractor Class — Multi-Volume VFS, Contract 2 Router & VSS Engine
# =============================================================================

_CHROMIUM_NON_PROFILE_DIRS: Set[str] = {
    "crashpad",
    "shadercache",
    "grshadercache",
    "graphitedawncache",
    "widevinecdm",
    "meipreload",
    "safetytips",
    "sslerrorassistant",
    "subresource filter",
    "zxcvbndata",
    "certificaterevocation",
    "crowd deny",
    "filetypepolicies",
    "firstpartysetspreload",
    "firstpartysetspeloaded",
    "origintrials",
    "pkimetadata",
    "pnacltranslationcache",
    "recoveryimproved",
    "safe browsing",
    "swreporter",
    "systemmetrics",
    "snapshots",
    "avatars",
    "autofillstates",
    "browsermetrics",
    "component crx cache",
    "native messaging hosts",
    "pepper flash",
    "evwhitelist",
    "pnacl",
}

_CHROMIUM_PROFILE_TOP_EXACT: Set[str] = {
    "history",
    "archived history",
    "media history",
    "cookies",
    "extension cookies",
    "web data",
    "login data",
    "login data for account",
    "bookmarks",
    "bookmarks.bak",
    "top sites",
    "shortcuts",
    "visited links",
    "preferences",
    "secure preferences",
    "favicons",
    "network action predictor",
    "dips",
    "current session",
    "current tabs",
    "last session",
    "last tabs",
    "local state",
}

_CHROMIUM_PROFILE_TOP_PREFIXES: Tuple[str, ...] = (
    "history-",
    "archived history-",
    "media history-",
    "cookies-",
    "extension cookies-",
    "web data-",
    "login data-",
    "top sites-",
    "shortcuts-",
    "favicons-",
    "network action predictor-",
    "dips-",
)

_CHROMIUM_PROFILE_SUBTREES: Set[str] = {
    "network",
    "sessions",
    "local storage",
    "session storage",
    "indexeddb",
    "extensions",
    "extension state",
    "local extension settings",
    "sync data",
    "cache",
}

_FIREFOX_PROFILE_EXACT: Set[str] = {
    "places.sqlite",
    "cookies.sqlite",
    "formhistory.sqlite",
    "favicons.sqlite",
    "permissions.sqlite",
    "content-prefs.sqlite",
    "protections.sqlite",
    "webappsstore.sqlite",
    "signons.sqlite",
    "logins.json",
    "key3.db",
    "key4.db",
    "cert9.db",
    "prefs.js",
    "addons.json",
    "extensions.json",
    "handlers.json",
    "sessionstore.jsonlz4",
}

_FIREFOX_PROFILE_PREFIXES: Tuple[str, ...] = (
    "places.sqlite-",
    "cookies.sqlite-",
    "formhistory.sqlite-",
    "favicons.sqlite-",
    "permissions.sqlite-",
    "content-prefs.sqlite-",
    "protections.sqlite-",
    "webappsstore.sqlite-",
    "signons.sqlite-",
    "key4.db-",
    "cert9.db-",
)

_OS_STANDARD_ROOT_DIRS: Set[str] = {
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "users",
    "documents and settings",
    "$recycle.bin",
    "recycler",
    "recycled",
    "system volume information",
    "recovery",
    "boot",
    "efi",
    "msocache",
    "$winreagent",
    "$windows.~bt",
    "$windows.~ws",
    "$extend",
    "config.msi",
    "found.000",
}

_NTFS_META_ROOT_NAMES: Set[str] = {
    "$mft",
    "$mftmirr",
    "$logfile",
    "$volume",
    "$attrdef",
    "$bitmap",
    "$boot",
    "$badclus",
    "$secure",
    "$upcase",
    "$extend",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
}


def _is_reg_hive_suffix_valid(fname_low: str, stem_low: str) -> bool:
    """Return True for <stem>, <stem>.log*, <stem>.blf, or <stem>.regtrans-ms (excluding .ini/.pol)."""
    if fname_low == stem_low:
        return True
    if not fname_low.startswith(stem_low + "."):
        return False
    rem = fname_low[len(stem_low) + 1 :]
    if rem.startswith("log") and (len(rem) == 3 or rem[3:].isdigit()):
        return True
    if rem.endswith(".blf") or rem.endswith(".regtrans-ms") or rem in ("blf", "regtrans-ms"):
        return True
    return False


class EvidenceExtractor:
    """
    Forensic Evidence Extractor for Windows Forensic Toolkit (WFT).
    Provides multi-threaded, MACB-preserving artifact collection and staging from:
      1. Complete forensic disk images (.E01, split .E01+.E02, .vmdk, .vhd, .vhdx, .qcow2, .dd, .raw, .img, .iso)
      2. Mounted drives, evidence folders, and single/nested archives (.zip, .7z, .rar, .tar*)
      3. Live Windows host triage + live/offline Volume Shadow Copies (VSS)
    """

    KNOWN_REGISTRY_HIVES: Set[str] = {
        "system",
        "software",
        "sam",
        "security",
        "default",
        "components",
        "bcd-template",
        "bcd",
        "amcache.hve",
        "ntuser.dat",
        "usrclass.dat",
    }

    ARCHIVE_EXTENSIONS: Set[str] = {
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

    KNOWN_IMAGE_EXTS: Set[str] = {
        ".e01",
        ".ex01",
        ".vhdx",
        ".vhd",
        ".vmdk",
        ".qcow2",
        ".raw",
        ".dd",
        ".img",
        ".iso",
    }

    SUSPICIOUS_MALWARE_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".sys", ".scr", ".msi",
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".hta", ".lnk",
        ".dmp", ".jsp", ".jspx", ".war", ".jar",
        ".class", ".aspx", ".ashx", ".asmx", ".asp",
        ".php", ".phtml", ".py", ".sh", ".elf",
        ".bin", ".dat", ".payloads",
    }

    WEB_SERVER_KEYWORDS: Set[str] = {
        "tomcat", "webapps", "inetpub", "wwwroot",
        "xampp", "htdocs", "nginx", "wamp",
    }

    def __init__(
        self,
        case_id: Optional[str] = None,
        staging_dir: Optional[Union[str, Path]] = None,
        log_file: Optional[Union[str, Path]] = None,
        enable_vss: bool = False,
        max_workers: int = 16,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> None:
        self.case_id = str(case_id).strip() if case_id else None
        if selected_artifacts is None:
            self.selected_artifacts: Tuple[str, ...] = ()
        elif isinstance(selected_artifacts, (str, bytes)):
            self.selected_artifacts = (str(selected_artifacts).strip(),)
        else:
            self.selected_artifacts = tuple(str(x).strip() for x in selected_artifacts if x is not None)
        self.enable_vss = bool(enable_vss) or _artifacts_request_vss(self.selected_artifacts)
        self.max_workers = max(1, min(32, int(max_workers or 16)))
        self._log_lock = threading.Lock()

        if staging_dir:
            self.staging_dir = Path(staging_dir).resolve()
            self._ensure_case_registered_for_staging(self.staging_dir)
        elif self.case_id:
            self.staging_dir = get_case_staging_dir(self.case_id).resolve()
        else:
            # Standalone invocation with neither case_id nor staging_dir: use OS temp dir,
            # NEVER polluting Desktop\cases\default\staging!
            self.staging_dir = Path(tempfile.mkdtemp(prefix="wft_staging_")).resolve()

        self.staging_dir.mkdir(parents=True, exist_ok=True)

        if log_file:
            self.log_file = Path(log_file).resolve()
        elif self.case_id and not staging_dir:
            self.log_file = get_case_log_file(self.case_id).resolve()
        else:
            self.log_file = (self.staging_dir.parent / "processing.log").resolve()

        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _ensure_case_registered_for_staging(self, staging_p: Path) -> None:
        """Auto-register cand_case_dir when standalone tests pass both case_id and staging_dir."""
        if not self.case_id:
            return
        try:
            cand_case_dir = (
                staging_p.parent
                if staging_p.name.lower() == "staging"
                else staging_p
            ).resolve()
            cur_case_dir = get_case_dir(self.case_id)
            if not (cur_case_dir / "case.duckdb").exists() and cur_case_dir.resolve() != cand_case_dir:
                register_case_dir(self.case_id, cand_case_dir)
        except Exception:
            pass

    def _resolve_workers(self, max_workers: Optional[int]) -> int:
        val = max_workers if max_workers is not None else self.max_workers
        try:
            return max(1, min(32, int(val)))
        except (TypeError, ValueError):
            return self.max_workers

    def _resolve_vss(
        self,
        enable_vss: bool = False,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> bool:
        return bool(enable_vss) or self.enable_vss or _artifacts_request_vss(selected_artifacts)

    # =========================================================================
    # Logging, Subprocess & Safe File-Attribute / Copy Helpers
    # =========================================================================

    def _log(self, message: str, level: str = "INFO") -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [EvidenceExtractor] [{level}] {message}"
        with self._log_lock:
            try:
                with open(self.log_file, "a", encoding="utf-8", errors="replace") as f:
                    f.write(formatted + "\n")
            except Exception:
                pass

    def _execute_cmd(
        self,
        module_name: str,
        cmd_list: List[str],
        timeout: int = 60,
    ) -> subprocess.CompletedProcess:
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
                timeout=timeout,
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
                except Exception:
                    pass
            raise

        duration_ms = int((time.time() - start_time) * 1000)
        status = "SUCCESS" if proc.returncode == 0 else "WARNING"
        err_msg = proc.stderr.strip() if proc.stderr else None
        self._log(f"Finished '{module_name}' with ExitCode={proc.returncode} in {duration_ms}ms")
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
            except Exception:
                pass
        return proc

    def _clear_file_attributes(self, path: Union[str, Path]) -> None:
        """
        Clear restrictive OS attributes (Read-Only, System, Hidden) so staged artifacts never lock
        case folders on Windows. Caller MUST invoke apply_forensic_utime() AFTER this call.
        """
        try:
            p_obj = Path(path)
            if not p_obj.exists():
                return
            p_str = str(p_obj)
            os.chmod(p_str, 0o700 if p_obj.is_dir() else 0o600)
            if sys.platform == "win32":
                try:
                    if not p_obj.is_dir():
                        ctypes.windll.kernel32.SetFileAttributesW(p_str, 0x80)
                except Exception:
                    pass
        except Exception:
            pass

    def _sanitize_staging_permissions(self, dir_path: Path) -> None:
        """
        Clear restrictive flags across dir_path while strictly preserving existing (atime, mtime)
        so restored forensic timestamps are never clobbered.
        """
        try:
            target_p = Path(dir_path).resolve()
            if not target_p.exists():
                return
            for root, dirs, files in os.walk(target_p):
                for d in dirs:
                    self._clear_file_attributes(Path(root) / d)
                for f in files:
                    fp = Path(root) / f
                    try:
                        st = fp.stat()
                        saved_times = (st.st_atime, st.st_mtime)
                    except OSError:
                        saved_times = None
                    self._clear_file_attributes(fp)
                    if saved_times is not None:
                        try:
                            os.utime(str(fp), saved_times)
                        except OSError:
                            pass
            self._clear_file_attributes(target_p)
        except Exception as ex:
            self._log(f"Notice while sanitizing permissions on {dir_path}: {ex}", level="INFO")

    @staticmethod
    def _stat_to_forensic_meta(
        src_path: Path,
        vfs_path: str = "",
        part_index: int = 0,
        fs_type: str = "FOLDER",
        st_override: Optional[os.stat_result] = None,
    ) -> ForensicMeta:
        meta = ForensicMeta(
            vfs_path=vfs_path or f"/{src_path.name}",
            part_index=part_index,
            fs_type=fs_type,
        )
        try:
            st = st_override if st_override is not None else src_path.stat()
            meta.size_bytes = int(st.st_size)
            meta.is_dir = stat.S_ISDIR(st.st_mode)
            btime = getattr(st, "st_birthtime", None)
            raw_btime = btime if btime is not None else st.st_ctime
            meta.si_modified = _epoch_to_utc(st.st_mtime)
            meta.si_accessed = _epoch_to_utc(st.st_atime)
            # On Windows NTFS (or copied/extracted triage folders), st_birthtime/st_ctime reflects
            # host file-creation/copy time while st_mtime preserves the historical forensic timestamp.
            if raw_btime is not None and st.st_mtime and st.st_mtime > 0 and raw_btime > st.st_mtime + 60:
                meta.si_created = meta.si_modified
            else:
                meta.si_created = _epoch_to_utc(raw_btime)
            if (
                sys.platform != "win32"
                and btime is not None
                and st.st_ctime != btime
                and (not st.st_mtime or st.st_ctime <= st.st_mtime + 60)
            ):
                meta.si_changed = _epoch_to_utc(st.st_ctime)
        except OSError:
            pass
        return meta

    @staticmethod
    def _strip_win_extended_prefix(p: Path) -> Path:
        s = str(p)
        if s.startswith("\\\\?\\UNC\\"):
            return Path("\\\\" + s[8:])
        if s.startswith("\\\\?\\"):
            return Path(s[4:])
        return p

    @staticmethod
    def _resolve_contained_dst(staging_root: Path, rel_or_dst: Union[str, Path]) -> Path:
        """
        Hard containment guard for every file-writing sink.
        Ensures the resolved destination path stays strictly inside staging_root,
        normalizing Windows '\\\\?\\' extended-path prefixes returned under concurrent mkdir.
        """
        try:
            root_res = EvidenceExtractor._strip_win_extended_prefix(Path(staging_root).resolve())
        except OSError:
            root_res = EvidenceExtractor._strip_win_extended_prefix(Path(os.path.abspath(str(staging_root))))
        cand = Path(rel_or_dst)
        raw_dst = cand if cand.is_absolute() else (root_res / cand)
        try:
            dst_res = EvidenceExtractor._strip_win_extended_prefix(raw_dst.resolve())
        except OSError:
            dst_res = EvidenceExtractor._strip_win_extended_prefix(Path(os.path.abspath(str(raw_dst))))
        dst_res.relative_to(root_res)
        if dst_res == root_res:
            raise ValueError(f"Refusing to overwrite staging root directory: {dst_res}")
        return dst_res

    @staticmethod
    def _claim_staged_rels(
        rels: List[str],
        claimed_map: Dict[str, Tuple[str, Any]],
        claim_lock: threading.Lock,
        source_key: Any,
        is_deleted: bool = False,
        hint_id: Optional[Union[int, str]] = None,
    ) -> Tuple[List[str], List[str]]:
        """
        Deterministically claim case-insensitive staging relative paths under claim_lock:
          - Returns (assigned_rels, rels_to_write).
          - If an identical source_key (e.g., multi-$FILE_NAME hardlink on the same MFT entry)
            already claimed the exact same destination, shares the path without duplicate writes.
          - If a distinct file collides on the same staging path (e.g., active + deleted non-OS file,
            case-insensitive collision, or multi-folder loose EVTX/Registry), disambiguates with
            __del_<id> or __dup_<seq> so neither file overwrites or races with the other.
        """
        assigned_rels: List[str] = []
        rels_to_write: List[str] = []
        with claim_lock:
            for raw_rel in rels:
                clean_rel = _sanitize_rel_path(raw_rel)
                if not clean_rel:
                    continue
                low_k = clean_rel.lower()
                existing = claimed_map.get(low_k)
                if existing is None:
                    claimed_map[low_k] = (clean_rel, source_key)
                    assigned_rels.append(clean_rel)
                    rels_to_write.append(clean_rel)
                    continue

                existing_rel, existing_key = existing
                if source_key is not None and existing_key == source_key:
                    assigned_rels.append(existing_rel)
                    continue

                if "/" in clean_rel:
                    dir_part, leaf_name = clean_rel.rsplit("/", 1)
                else:
                    dir_part, leaf_name = "", clean_rel
                p_leaf = PurePosixPath(leaf_name)
                stem = p_leaf.stem or leaf_name
                sfx = p_leaf.suffix if p_leaf.stem else ""

                seq = 1
                while True:
                    if is_deleted:
                        if hint_id is not None and seq == 1:
                            tag = f"__del_{hint_id}"
                        elif hint_id is not None:
                            tag = f"__del_{hint_id}_{seq}"
                        else:
                            tag = f"__del_{seq}"
                    else:
                        if hint_id is not None and seq == 1:
                            tag = f"__dup_{hint_id}"
                        else:
                            tag = f"__dup_{seq}"
                    cand_leaf = _sanitize_win32_segment(f"{stem}{tag}{sfx}")
                    cand_rel = f"{dir_part}/{cand_leaf}" if dir_part else cand_leaf
                    cand_low = cand_rel.lower()
                    if cand_low not in claimed_map:
                        claimed_map[cand_low] = (cand_rel, source_key)
                        assigned_rels.append(cand_rel)
                        rels_to_write.append(cand_rel)
                        break
                    seq += 1
        return assigned_rels, rels_to_write

    def _copy_file_safe(
        self,
        src: Path,
        dst: Path,
        overwrite: bool = True,
        meta: Optional[ForensicMeta] = None,
        root_guard: Optional[Path] = None,
    ) -> bool:
        """
        Copy src to dst without copying restrictive Read-Only/System flags, clear attributes,
        and apply original forensic (atime, mtime) strictly AFTER file close and _clear_file_attributes.
        """
        try:
            if not src.exists():
                return False
            dst_p = self._resolve_contained_dst(root_guard, dst) if root_guard is not None else Path(dst)
            eff_meta = meta if meta is not None else self._stat_to_forensic_meta(src)
            if dst_p.exists():
                if not overwrite:
                    return True
                self._clear_file_attributes(dst_p)
            dst_p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst_p)
            self._clear_file_attributes(dst_p)
            apply_forensic_utime(dst_p, eff_meta)
            return True
        except ValueError as sec_err:
            self._log(f"Blocked out-of-bounds copy {src} -> {dst}: {sec_err}", level="ERROR")
            return False
        except (PermissionError, OSError) as err:
            self._log(f"Copy notice {src} -> {dst}: {err}", level="WARNING")
            return False
        except Exception as ex:
            self._log(f"Unexpected error copying {src} -> {dst}: {ex}", level="ERROR")
            return False

    # =========================================================================
    # DuckDB Frozen Interface Contract 2 Persistence (F7, F8, F27, F28)
    # =========================================================================

    def _ensure_ancestor_dir_rows(
        self,
        vfs_files_rows: List[Tuple[Any, ...]],
    ) -> List[Tuple[Any, ...]]:
        """
        Ensure 100% closed parent_path tree connectivity across all partitions and VSS stores:
        every non-root row's parent_path (up to '/') has a matching (part_index, anc_path, is_dir=True) row.
        Synthesized intermediate directories carry None timestamps so wall-clock times never leak.
        """
        if not vfs_files_rows:
            return vfs_files_rows

        existing_dirs: Set[Tuple[int, str]] = set()
        for row in vfs_files_rows:
            if bool(row[6]):
                existing_dirs.add((int(row[0]), str(row[1] or "/")))

        extra_dirs: List[Tuple[Any, ...]] = []
        for row in vfs_files_rows:
            p_idx = int(row[0])
            v_path = str(row[1] or "/")
            if v_path == "/":
                continue
            cur_par = str(row[4] or "/")
            while cur_par:
                key = (p_idx, cur_par)
                if key not in existing_dirs:
                    existing_dirs.add(key)
                    anc_meta = ForensicMeta(
                        vfs_path=cur_par,
                        part_index=p_idx,
                        is_dir=True,
                        is_deleted=False,
                        size_bytes=0,
                    )
                    extra_dirs.append(self._build_vfs_row(p_idx, cur_par, None, anc_meta))
                if cur_par == "/":
                    break
                p_obj = PurePosixPath(cur_par)
                cur_par = str(p_obj.parent) if str(p_obj.parent) != "." else "/"

        if extra_dirs:
            return vfs_files_rows + extra_dirs
        return vfs_files_rows

    def _persist_vfs_tables(
        self,
        partitions_rows: List[Tuple[Any, ...]],
        vfs_files_rows: List[Tuple[Any, ...]],
        vss_rows: List[Tuple[Any, ...]],
    ) -> None:
        """
        Create and populate Frozen Interface Contract 2 DuckDB tables while preserving any
        superset columns pre-created by init_case_db() (schema.py / M5 / view_docs_txt):
          - vfs_partitions (7 Contract 2 columns; preserves superset columns if present)
          - vfs_files (17 Contract 2 columns; zero-copy PyArrow insert on `conn` directly)
          - vfs_shadow_copies (8 Contract 2 columns; preserves superset columns if present)
        Always serialized under DuckDBManager.get_lock(self.case_id).
        """
        if not self.case_id:
            return

        vfs_files_rows = self._ensure_ancestor_dir_rows(vfs_files_rows)

        expected_vfs_cols = [
            "part_index", "vfs_path", "staged_rel_path", "file_name", "parent_path",
            "size_bytes", "is_dir", "is_deleted",
            "si_created", "si_modified", "si_accessed", "si_changed",
            "fn_created", "fn_modified", "fn_accessed", "fn_changed",
            "mft_entry",
        ]
        expected_part_cols = [
            "part_index", "label", "fs_type", "offset_bytes", "size_bytes", "volume_serial", "is_boot",
        ]
        expected_vss_cols = [
            "vss_index", "part_index", "store_id", "creation_time",
            "size_bytes", "staged_prefix", "files_staged", "status",
        ]

        part_cols_csv = ", ".join(expected_part_cols)
        vfs_cols_csv = ", ".join(expected_vfs_cols)
        vss_cols_csv = ", ".join(expected_vss_cols)

        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)

            for tbl_name, exp_cols in (
                ("vfs_partitions", expected_part_cols),
                ("vfs_files", expected_vfs_cols),
                ("vfs_shadow_copies", expected_vss_cols),
            ):
                try:
                    existing = [r[0].lower() for r in conn.execute(f"DESCRIBE {tbl_name}").fetchall()]
                    if existing and not set(exp_cols).issubset(set(existing)):
                        conn.execute(f"DROP TABLE IF EXISTS {tbl_name}")
                except Exception:
                    pass

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vfs_partitions (
                    part_index INTEGER,
                    label VARCHAR,
                    fs_type VARCHAR,
                    offset_bytes BIGINT,
                    size_bytes BIGINT,
                    volume_serial VARCHAR,
                    is_boot BOOLEAN
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vfs_files (
                    part_index INTEGER,
                    vfs_path VARCHAR,
                    staged_rel_path VARCHAR,
                    file_name VARCHAR,
                    parent_path VARCHAR,
                    size_bytes BIGINT,
                    is_dir BOOLEAN,
                    is_deleted BOOLEAN,
                    si_created TIMESTAMP,
                    si_modified TIMESTAMP,
                    si_accessed TIMESTAMP,
                    si_changed TIMESTAMP,
                    fn_created TIMESTAMP,
                    fn_modified TIMESTAMP,
                    fn_accessed TIMESTAMP,
                    fn_changed TIMESTAMP,
                    mft_entry BIGINT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vfs_shadow_copies (
                    vss_index INTEGER,
                    part_index INTEGER,
                    store_id VARCHAR,
                    creation_time TIMESTAMP,
                    size_bytes BIGINT,
                    staged_prefix VARCHAR,
                    files_staged INTEGER,
                    status VARCHAR
                );
                """
            )

            conn.execute("DELETE FROM vfs_partitions;")
            conn.execute("DELETE FROM vfs_files;")
            conn.execute("DELETE FROM vfs_shadow_copies;")

            if partitions_rows:
                conn.executemany(
                    f"INSERT INTO vfs_partitions ({part_cols_csv}) VALUES (?, ?, ?, ?, ?, ?, ?);",
                    partitions_rows,
                )
                part_types = {
                    r[0].lower(): str(r[1]).upper()
                    for r in conn.execute("DESCRIBE vfs_partitions").fetchall()
                }
                if len(part_types) > len(expected_part_cols):
                    p_sets: List[str] = []
                    if "_row_id" in part_types:
                        p_sets.append("_row_id = rowid + 1")
                    if "partition_index" in part_types:
                        p_sets.append("partition_index = part_index")
                    if "addr" in part_types:
                        p_sets.append("addr = part_index")
                    if "volume_label" in part_types:
                        p_sets.append("volume_label = label")
                    if "description" in part_types:
                        p_sets.append("description = fs_type")
                    if "start_offset_bytes" in part_types:
                        p_sets.append("start_offset_bytes = offset_bytes")
                    if "start_sector" in part_types:
                        p_sets.append("start_sector = offset_bytes // 512")
                    if "length_sectors" in part_types:
                        p_sets.append("length_sectors = size_bytes // 512")
                    if "serial_number" in part_types:
                        p_sets.append("serial_number = volume_serial")
                    if "is_bootable" in part_types:
                        p_sets.append("is_bootable = is_boot")
                    if p_sets:
                        conn.execute(f"UPDATE vfs_partitions SET {', '.join(p_sets)};")

            if vss_rows:
                norm_vss = [
                    (
                        int(r[0]),
                        int(r[1]),
                        str(r[2]) if r[2] is not None else "",
                        _normalize_utc_naive(r[3]),
                        int(r[4] or 0),
                        str(r[5]) if r[5] is not None else "",
                        int(r[6] or 0),
                        str(r[7]) if r[7] is not None else "",
                    )
                    for r in vss_rows
                ]
                conn.executemany(
                    f"INSERT INTO vfs_shadow_copies ({vss_cols_csv}) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                    norm_vss,
                )
                vss_types = {
                    r[0].lower(): str(r[1]).upper()
                    for r in conn.execute("DESCRIBE vfs_shadow_copies").fetchall()
                }
                if len(vss_types) > len(expected_vss_cols):
                    s_sets: List[str] = []
                    if "_row_id" in vss_types:
                        s_sets.append("_row_id = rowid + 1")
                    if "store_index" in vss_types:
                        s_sets.append("store_index = vss_index")
                    if "partition_index" in vss_types:
                        s_sets.append("partition_index = part_index")
                    if "vss_id" in vss_types:
                        s_sets.append("vss_id = store_id")
                    if "shadow_copy_guid" in vss_types:
                        s_sets.append("shadow_copy_guid = store_id")
                    if "creation_time_utc" in vss_types:
                        if "CHAR" in vss_types["creation_time_utc"] or "TEXT" in vss_types["creation_time_utc"]:
                            s_sets.append("creation_time_utc = CAST(creation_time AS VARCHAR)")
                        else:
                            s_sets.append("creation_time_utc = creation_time")
                    if "shadow_copy_size" in vss_types:
                        s_sets.append("shadow_copy_size = size_bytes")
                    if "store_size_bytes" in vss_types:
                        s_sets.append("store_size_bytes = size_bytes")
                    if s_sets:
                        conn.execute(f"UPDATE vfs_shadow_copies SET {', '.join(s_sets)};")

            if vfs_files_rows:
                inserted_arrow = False
                if pa is not None:
                    try:
                        cols: List[List[Any]] = [[] for _ in range(17)]
                        for row in vfs_files_rows:
                            cols[0].append(int(row[0]))
                            cols[1].append(row[1])
                            cols[2].append(row[2])
                            cols[3].append(row[3])
                            cols[4].append(row[4])
                            cols[5].append(int(row[5] or 0))
                            cols[6].append(bool(row[6]))
                            cols[7].append(bool(row[7]))
                            cols[8].append(_normalize_utc_naive(row[8]))
                            cols[9].append(_normalize_utc_naive(row[9]))
                            cols[10].append(_normalize_utc_naive(row[10]))
                            cols[11].append(_normalize_utc_naive(row[11]))
                            cols[12].append(_normalize_utc_naive(row[12]))
                            cols[13].append(_normalize_utc_naive(row[13]))
                            cols[14].append(_normalize_utc_naive(row[14]))
                            cols[15].append(_normalize_utc_naive(row[15]))
                            cols[16].append(int(row[16]) if row[16] is not None else None)

                        schema = pa.schema(
                            [
                                ("part_index", pa.int32()),
                                ("vfs_path", pa.string()),
                                ("staged_rel_path", pa.string()),
                                ("file_name", pa.string()),
                                ("parent_path", pa.string()),
                                ("size_bytes", pa.int64()),
                                ("is_dir", pa.bool_()),
                                ("is_deleted", pa.bool_()),
                                ("si_created", pa.timestamp("us")),
                                ("si_modified", pa.timestamp("us")),
                                ("si_accessed", pa.timestamp("us")),
                                ("si_changed", pa.timestamp("us")),
                                ("fn_created", pa.timestamp("us")),
                                ("fn_modified", pa.timestamp("us")),
                                ("fn_accessed", pa.timestamp("us")),
                                ("fn_changed", pa.timestamp("us")),
                                ("mft_entry", pa.int64()),
                            ]
                        )
                        pa_tbl = pa.Table.from_pydict(
                            dict(zip(expected_vfs_cols, cols)),
                            schema=schema,
                        )
                        view_name = f"_tmp_vfs_files_{uuid.uuid4().hex[:8]}"
                        conn.register(view_name, pa_tbl)
                        try:
                            conn.execute(
                                f"INSERT INTO vfs_files ({vfs_cols_csv}) SELECT {vfs_cols_csv} FROM {view_name};"
                            )
                        finally:
                            try:
                                conn.unregister(view_name)
                            except Exception:
                                pass
                        inserted_arrow = True
                    except Exception as arrow_err:
                        self._log(f"PyArrow bulk insert notice, falling back to executemany: {arrow_err}", level="WARNING")

                if not inserted_arrow:
                    try:
                        import pandas as _pd
                        cols_data: Dict[str, List[Any]] = {c: [] for c in expected_vfs_cols}
                        for r in vfs_files_rows:
                            cols_data["part_index"].append(int(r[0]))
                            cols_data["vfs_path"].append(r[1])
                            cols_data["staged_rel_path"].append(r[2])
                            cols_data["file_name"].append(r[3])
                            cols_data["parent_path"].append(r[4])
                            cols_data["size_bytes"].append(int(r[5] or 0))
                            cols_data["is_dir"].append(bool(r[6]))
                            cols_data["is_deleted"].append(bool(r[7]))
                            cols_data["si_created"].append(_normalize_utc_naive(r[8]))
                            cols_data["si_modified"].append(_normalize_utc_naive(r[9]))
                            cols_data["si_accessed"].append(_normalize_utc_naive(r[10]))
                            cols_data["si_changed"].append(_normalize_utc_naive(r[11]))
                            cols_data["fn_created"].append(_normalize_utc_naive(r[12]))
                            cols_data["fn_modified"].append(_normalize_utc_naive(r[13]))
                            cols_data["fn_accessed"].append(_normalize_utc_naive(r[14]))
                            cols_data["fn_changed"].append(_normalize_utc_naive(r[15]))
                            cols_data["mft_entry"].append(int(r[16]) if r[16] is not None else None)
                        df = _pd.DataFrame(cols_data)
                        conn.execute(
                            f"INSERT INTO vfs_files ({vfs_cols_csv}) SELECT {vfs_cols_csv} FROM df;"
                        )
                        inserted_arrow = True
                    except Exception:
                        pass

                if not inserted_arrow:
                    chunk_sz = 2000
                    for start_i in range(0, len(vfs_files_rows), chunk_sz):
                        batch = [
                            (
                                int(r[0]), r[1], r[2], r[3], r[4],
                                int(r[5] or 0), bool(r[6]), bool(r[7]),
                                _normalize_utc_naive(r[8]), _normalize_utc_naive(r[9]),
                                _normalize_utc_naive(r[10]), _normalize_utc_naive(r[11]),
                                _normalize_utc_naive(r[12]), _normalize_utc_naive(r[13]),
                                _normalize_utc_naive(r[14]), _normalize_utc_naive(r[15]),
                                int(r[16]) if r[16] is not None else None,
                            )
                            for r in vfs_files_rows[start_i : start_i + chunk_sz]
                        ]
                        conn.executemany(
                            f"INSERT INTO vfs_files ({vfs_cols_csv}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            batch,
                        )

                existing_types = {
                    r[0].lower(): str(r[1]).upper()
                    for r in conn.execute("DESCRIBE vfs_files").fetchall()
                }
                if len(existing_types) > len(expected_vfs_cols):
                    f_sets: List[str] = []
                    if "_row_id" in existing_types:
                        f_sets.append("_row_id = rowid + 1")
                    if "partition_index" in existing_types:
                        f_sets.append("partition_index = part_index")
                    if "inode" in existing_types:
                        f_sets.append("inode = mft_entry")
                    if "extension" in existing_types:
                        f_sets.append(
                            "extension = CASE WHEN NOT is_dir AND instr(file_name, '.') > 0 "
                            "THEN lower(regexp_extract(file_name, '\\.[^.]+$')) ELSE '' END"
                        )
                    if "is_directory" in existing_types:
                        f_sets.append("is_directory = is_dir")
                    if "is_allocated" in existing_types:
                        f_sets.append("is_allocated = NOT COALESCE(is_deleted, FALSE)")
                    if "vss_store_index" in existing_types:
                        f_sets.append("vss_store_index = CASE WHEN part_index < 0 THEN -part_index ELSE NULL END")
                    for ts_base in (
                        "si_created", "si_modified", "si_accessed", "si_changed",
                        "fn_created", "fn_modified", "fn_accessed", "fn_changed",
                    ):
                        utc_col = f"{ts_base}_utc"
                        if utc_col in existing_types:
                            if "CHAR" in existing_types[utc_col] or "TEXT" in existing_types[utc_col]:
                                f_sets.append(f"{utc_col} = CAST({ts_base} AS VARCHAR)")
                            else:
                                f_sets.append(f"{utc_col} = {ts_base}")
                    if f_sets:
                        conn.execute(f"UPDATE vfs_files SET {', '.join(f_sets)};")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_vfs_files_parent ON vfs_files(part_index, parent_path);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vfs_files_staged ON vfs_files(staged_rel_path);")

    # =========================================================================
    # Safe Live Windows VSS Discovery (F27 — Zero wmic, 5s Timeouts)
    # =========================================================================

    def _discover_live_vss_snapshots(self) -> Tuple[List[Dict[str, Any]], str]:
        """
        Enumerate existing live Windows Volume Shadow Copies safely without creating new snapshots.
        Never invokes wmic shadowcopy call create. Enforces timeout=5 on vssadmin & PowerShell.
        Returns (snapshots, status) where each snapshot dict has:
          {"store_id": str, "creation_time": Optional[datetime], "device_path": str}
        and status is one of {"ok", "permission_denied", "none"}.
        """
        snapshots: List[Dict[str, Any]] = []
        seen_devs: Set[str] = set()
        perm_denied = False

        # 1. vssadmin list shadows (timeout=5)
        try:
            res = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            combined_low = ((res.stdout or "") + "\n" + (res.stderr or "")).lower()
            if any(
                phrase in combined_low
                for phrase in (
                    "don't have the correct permissions",
                    "administrator privileges",
                    "access is denied",
                )
            ):
                perm_denied = True
            if res.stdout:
                blocks = re.split(r"(?=Contents of shadow copy set ID:|Shadow Copy ID:)", res.stdout)
                for blk in blocks:
                    m_dev = re.search(
                        r"(\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)",
                        blk,
                        re.IGNORECASE,
                    )
                    if not m_dev:
                        continue
                    dev = m_dev.group(1).rstrip("\\")
                    if dev.lower() in seen_devs:
                        continue
                    seen_devs.add(dev.lower())
                    m_id = re.search(r"Shadow Copy ID:\s*(\{[0-9a-fA-F\-]+\})", blk)
                    store_id = m_id.group(1) if m_id else f"live_vss_{len(snapshots) + 1}"
                    ctime: Optional[datetime] = None
                    m_ct = re.search(r"creation time:\s*([^\r\n]+)", blk, re.IGNORECASE)
                    if m_ct:
                        raw_ct = m_ct.group(1).strip()
                        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
                            try:
                                ctime = datetime.strptime(raw_ct, fmt)
                                break
                            except ValueError:
                                continue
                    snapshots.append({"store_id": store_id, "creation_time": ctime, "device_path": dev})
        except subprocess.TimeoutExpired:
            self._log("vssadmin list shadows timed out after 5s.", level="INFO")
        except Exception as ex:
            self._log(f"vssadmin enumeration notice: {ex}", level="INFO")

        # 2. PowerShell Win32_ShadowCopy fallback (timeout=5)
        if not snapshots and not perm_denied:
            try:
                ps_cmd = [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object -Property ID,InstallDate,DeviceObject | ConvertTo-Json -Compress",
                ]
                res = subprocess.run(
                    ps_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                combined_low = ((res.stdout or "") + "\n" + (res.stderr or "")).lower()
                if any(
                    phrase in combined_low
                    for phrase in ("access is denied", "access denied", "permissiondenied", "administrator")
                ):
                    perm_denied = True
                elif res.returncode == 0 and res.stdout and res.stdout.strip():
                    import json as _json
                    raw_out = res.stdout.strip()
                    if raw_out.startswith(("{", "[")):
                        parsed = _json.loads(raw_out)
                        items = parsed if isinstance(parsed, list) else [parsed]
                        for item in items:
                            if not isinstance(item, dict):
                                continue
                            dev_raw = str(item.get("DeviceObject") or "").strip().rstrip("\\")
                            if "HarddiskVolumeShadowCopy" not in dev_raw:
                                continue
                            if not dev_raw.startswith("\\\\?\\"):
                                dev_raw = "\\\\?\\" + dev_raw.lstrip("\\?")
                            if dev_raw.lower() not in seen_devs:
                                seen_devs.add(dev_raw.lower())
                                snapshots.append(
                                    {
                                        "store_id": str(item.get("ID") or f"live_vss_{len(snapshots) + 1}"),
                                        "creation_time": None,
                                        "device_path": dev_raw,
                                    }
                                )
                    else:
                        for line in raw_out.splitlines():
                            line = line.strip().rstrip("\\")
                            if "HarddiskVolumeShadowCopy" in line:
                                if not line.startswith("\\\\?\\"):
                                    line = "\\\\?\\" + line.lstrip("\\?")
                                if line.lower() not in seen_devs:
                                    seen_devs.add(line.lower())
                                    snapshots.append(
                                        {
                                            "store_id": f"live_vss_{len(snapshots) + 1}",
                                            "creation_time": None,
                                            "device_path": line,
                                        }
                                    )
            except subprocess.TimeoutExpired:
                self._log("PowerShell Win32_ShadowCopy timed out after 5s.", level="INFO")
            except Exception as ex:
                self._log(f"PowerShell Win32_ShadowCopy notice: {ex}", level="INFO")

        if snapshots:
            return snapshots, "ok"
        if perm_denied:
            return [], "permission_denied"
        return [], "none"

    def _get_volume_shadow_copies(self) -> List[str]:
        """Backward-compatible helper returning live VSS device paths (never invokes wmic create)."""
        snaps, _ = self._discover_live_vss_snapshots()
        return [s["device_path"] for s in snaps]

    def _copy_locked_system_file(
        self,
        src_path: Union[str, Path],
        dst_path: Union[str, Path],
        vss_roots: Optional[List[str]] = None,
        fallback_fixture_name: Optional[str] = None,
    ) -> bool:
        src = Path(src_path).resolve()
        dst = Path(dst_path).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)

        try:
            if src.exists() and self._copy_file_safe(src, dst):
                return True
        except (PermissionError, OSError):
            pass

        if vss_roots is None:
            vss_roots = self._get_volume_shadow_copies()

        if vss_roots:
            drive = src.drive or "C:"
            try:
                rel = src.relative_to(Path(drive + "\\"))
            except Exception:
                parts = src.parts
                rel = Path(*parts[1:]) if len(parts) > 1 else Path(src.name)

            for vss_root in vss_roots:
                vss_file_path = Path(f"{vss_root}\\{rel}")
                try:
                    vss_meta = self._stat_to_forensic_meta(vss_file_path, fs_type="LIVE")
                    with open(vss_file_path, "rb") as in_f, open(dst, "wb") as out_f:
                        shutil.copyfileobj(in_f, out_f, length=1024 * 1024)
                    self._clear_file_attributes(dst)
                    apply_forensic_utime(dst, vss_meta)
                    if dst.exists() and dst.stat().st_size > 0:
                        return True
                except Exception:
                    continue

        try:
            res = subprocess.run(
                ["robocopy", str(src.parent), str(dst.parent), src.name, "/B", "/R:1", "/W:1", "/NFL", "/NDL"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if res.returncode < 8 and dst.exists() and dst.stat().st_size > 0:
                src_meta = self._stat_to_forensic_meta(src, fs_type="LIVE") if src.exists() else None
                self._clear_file_attributes(dst)
                apply_forensic_utime(dst, src_meta)
                return True
        except Exception:
            pass
        return False

    def _extract_live_ntfs(
        self,
        staging_path: Path,
        vss_roots: Optional[List[str]] = None,
    ) -> Tuple[bool, bool]:
        fs_dir = staging_path / "FileSystem"
        fs_dir.mkdir(parents=True, exist_ok=True)
        mft_dst = fs_dir / "$MFT"
        usn_dst = fs_dir / "$J"

        mft_ok = mft_dst.exists() and mft_dst.stat().st_size > 0
        usn_ok = usn_dst.exists() and usn_dst.stat().st_size > 0
        if mft_ok and usn_ok:
            return (True, True)

        if vss_roots is None:
            vss_roots = self._get_volume_shadow_copies()

        if vss_roots:
            for vss_root in vss_roots:
                if not mft_ok:
                    vss_mft = Path(f"{vss_root}\\$MFT")
                    try:
                        vss_meta = self._stat_to_forensic_meta(vss_mft, vfs_path="/$MFT", fs_type="LIVE")
                        with open(vss_mft, "rb") as in_f, open(mft_dst, "wb") as out_f:
                            shutil.copyfileobj(in_f, out_f, length=1024 * 1024)
                        self._clear_file_attributes(mft_dst)
                        apply_forensic_utime(mft_dst, vss_meta)
                        mft_ok = mft_dst.exists() and mft_dst.stat().st_size > 0
                    except Exception:
                        pass
                if not usn_ok:
                    for usn_cand in (r"$Extend\$UsnJrnl:$J", r"$Extend\$UsnJrnl"):
                        vss_usn = Path(f"{vss_root}\\{usn_cand}")
                        try:
                            vss_meta = self._stat_to_forensic_meta(vss_usn, vfs_path="/$Extend/$UsnJrnl:$J", fs_type="LIVE")
                            with open(vss_usn, "rb") as in_f, open(usn_dst, "wb") as out_f:
                                shutil.copyfileobj(in_f, out_f, length=1024 * 1024)
                            self._clear_file_attributes(usn_dst)
                            apply_forensic_utime(usn_dst, vss_meta)
                            if usn_dst.exists() and usn_dst.stat().st_size > 0:
                                usn_ok = True
                                break
                        except Exception:
                            pass

        if not (mft_ok and usn_ok) and _dissect_ntfs is not None:
            try:
                with open(r"\\.\C:", "rb") as raw_fh:
                    ntfs_vol = _dissect_ntfs.NTFS(raw_fh)
                    if not mft_ok:
                        mft_rec = ntfs_vol.mft.get(0)
                        mft_meta = extract_meta_dissect(mft_rec, "/$MFT", 0, "LIVE")
                        with open(mft_dst, "wb") as out_mft:
                            shutil.copyfileobj(mft_rec.open(), out_mft, length=1024 * 1024)
                        self._clear_file_attributes(mft_dst)
                        apply_forensic_utime(mft_dst, mft_meta)
                        mft_ok = mft_dst.exists() and mft_dst.stat().st_size > 0
                    if not usn_ok:
                        try:
                            usn_rec = ntfs_vol.mft.get(r"$Extend\$UsnJrnl")
                            usn_meta = extract_meta_dissect(usn_rec, "/$Extend/$UsnJrnl:$J", 0, "LIVE")
                            with open(usn_dst, "wb") as out_usn:
                                shutil.copyfileobj(usn_rec.open("$J"), out_usn, length=1024 * 1024)
                            self._clear_file_attributes(usn_dst)
                            apply_forensic_utime(usn_dst, usn_meta)
                            usn_ok = usn_dst.exists() and usn_dst.stat().st_size > 0
                        except Exception:
                            pass
            except Exception:
                pass

        return (mft_ok, usn_ok)

    # =========================================================================
    # Archive Unpacking Engine with Member Timestamp Preservation (F8)
    # =========================================================================

    @staticmethod
    def _extract_zipinfo_meta(member: zipfile.ZipInfo) -> ForensicMeta:
        mtime: Optional[datetime] = None
        atime: Optional[datetime] = None
        crtime: Optional[datetime] = None

        # Parse ZIP extra fields (0x000a NTFS FILETIME or 0x5455 Extended Timestamp)
        extra = member.extra or b""
        idx = 0
        while idx + 4 <= len(extra):
            hdr_id, data_sz = struct.unpack("<HH", extra[idx : idx + 4])
            body = extra[idx + 4 : idx + 4 + data_sz]
            idx += 4 + data_sz
            if hdr_id == 0x000A and len(body) >= 32:
                # NTFS extra field: 4B reserved, then tag 0x0001 (24B: Mtime, Atime, Ctime)
                tag, tsz = struct.unpack("<HH", body[4:8])
                if tag == 0x0001 and tsz >= 24:
                    ft_m, ft_a, ft_c = struct.unpack("<3Q", body[8:32])
                    mtime = _filetime_to_utc(ft_m) or mtime
                    atime = _filetime_to_utc(ft_a) or atime
                    crtime = _filetime_to_utc(ft_c) or crtime
            elif hdr_id == 0x5455 and len(body) >= 5:
                flags = body[0]
                pos = 1
                if (flags & 0x01) and pos + 4 <= len(body):
                    mtime = mtime or _epoch_to_utc(struct.unpack("<I", body[pos : pos + 4])[0])
                    pos += 4
                if (flags & 0x02) and pos + 4 <= len(body):
                    atime = atime or _epoch_to_utc(struct.unpack("<I", body[pos : pos + 4])[0])
                    pos += 4
                if (flags & 0x04) and pos + 4 <= len(body):
                    crtime = crtime or _epoch_to_utc(struct.unpack("<I", body[pos : pos + 4])[0])

        if mtime is None:
            dt_tup = getattr(member, "date_time", None)
            if dt_tup and len(dt_tup) == 6 and dt_tup != (1980, 1, 1, 0, 0, 0) and dt_tup[0] >= 1980:
                try:
                    mtime = datetime(*dt_tup)
                except ValueError:
                    mtime = None

        return ForensicMeta(
            vfs_path=f"/{member.filename.lstrip('/')}",
            fs_type="ARCHIVE",
            size_bytes=int(getattr(member, "file_size", 0) or 0),
            si_created=crtime,
            si_modified=mtime,
            si_accessed=atime or mtime,
        )

    def unpack_archive_with_meta(
        self,
        archive_path: Path,
        output_dir: Path,
        fallback_mtime: Optional[datetime] = None,
    ) -> List[Tuple[Path, ForensicMeta]]:
        """
        Unpack .zip/.war/.jar, .7z, .tar*, single-stream .gz/.bz2/.xz, and .rar archives into output_dir safely:
          - Rejects traversal ('..'), root/UNC prefixes, and Windows drive letters BEFORE writing.
          - Sanitizes Win32 illegal/ADS/trailing-dot/reserved segment names on relative member paths.
          - Enforces MAX_ARCHIVE_MEMBER_BYTES (512 MiB) and MAX_ARCHIVE_TOTAL_BYTES (2 GiB) caps.
          - Preserves archive member timestamps (falling back to parent archive fallback_mtime when unset,
            NEVER fabricating host wall-clock 2026 timestamps) and returns (Path, ForensicMeta) pairs.
        """
        archive_path = Path(archive_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        norm_fallback = _normalize_utc_naive(fallback_mtime)

        extracted_items: List[Tuple[Path, ForensicMeta]] = []
        name_lower = archive_path.name.lower()
        total_written = 0

        def _resolve_member_target(raw_member: str) -> Optional[Tuple[str, Path]]:
            if not raw_member:
                return None
            raw_s = str(raw_member)
            norm_s = raw_s.replace("\\", "/")
            if norm_s.startswith("/") or raw_s.startswith("\\"):
                return None
            if re.match(r"^[A-Za-z]:", norm_s):
                return None
            segs = norm_s.split("/")
            if any(seg == ".." for seg in segs):
                return None
            safe_segs: List[str] = []
            for seg in segs:
                if seg in ("", "."):
                    continue
                s_clean = _sanitize_win32_segment(seg)
                if not s_clean or s_clean == "_dotdot_":
                    return None
                safe_segs.append(s_clean)
            if not safe_segs:
                return None
            rel_clean = "/".join(safe_segs)
            try:
                target_p = self._resolve_contained_dst(output_dir, rel_clean)
            except ValueError:
                return None
            return rel_clean, target_p

        def _stream_to_target(src_stream: Any, dst_file: Path) -> Optional[int]:
            nonlocal total_written
            written_here = 0
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            if dst_file.exists():
                self._clear_file_attributes(dst_file)
            exceeded = False
            try:
                with open(dst_file, "wb") as out_f:
                    while True:
                        chunk = src_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        written_here += len(chunk)
                        if (
                            written_here > MAX_ARCHIVE_MEMBER_BYTES
                            or (total_written + written_here) > MAX_ARCHIVE_TOTAL_BYTES
                        ):
                            exceeded = True
                            break
                        out_f.write(chunk)
            except Exception:
                try:
                    dst_file.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
            if exceeded:
                try:
                    dst_file.unlink(missing_ok=True)
                except OSError:
                    pass
                self._log(
                    f"Archive decompression cap exceeded on {archive_path.name} -> {dst_file.name} "
                    f"(written={written_here}, total={total_written}); skipping member.",
                    level="WARNING",
                )
                return None
            total_written += written_here
            return written_here

        def _finalize_member(target_file: Path, m_meta: ForensicMeta, written_sz: int) -> None:
            m_meta.size_bytes = int(written_sz)
            if m_meta.si_modified is None and m_meta.si_created is None and norm_fallback is not None:
                m_meta.si_modified = norm_fallback
                if m_meta.si_accessed is None:
                    m_meta.si_accessed = norm_fallback
            self._clear_file_attributes(target_file)
            apply_forensic_utime(target_file, m_meta)
            extracted_items.append((target_file, m_meta))

        def _extract_tar_archive(tar_p: Path) -> None:
            nonlocal total_written
            with tarfile.open(tar_p, "r:*") as tf:
                for member in tf.getmembers():
                    if total_written >= MAX_ARCHIVE_TOTAL_BYTES:
                        break
                    resolved = _resolve_member_target(member.name)
                    if resolved is None:
                        continue
                    rel_clean, target_file = resolved
                    if member.isdir():
                        target_file.mkdir(parents=True, exist_ok=True)
                        self._clear_file_attributes(target_file)
                        continue
                    if not member.isfile():
                        continue
                    decl_sz = int(getattr(member, "size", 0) or 0)
                    if decl_sz > MAX_ARCHIVE_MEMBER_BYTES or (total_written + decl_sz) > MAX_ARCHIVE_TOTAL_BYTES:
                        self._log(
                            f"Skipping oversized TAR member {member.name} ({decl_sz} bytes) in {tar_p.name}",
                            level="WARNING",
                        )
                        continue
                    f_in = tf.extractfile(member)
                    if f_in is None:
                        continue
                    with f_in:
                        written_sz = _stream_to_target(f_in, target_file)
                    if written_sz is None:
                        continue
                    m_dt = _epoch_to_utc(getattr(member, "mtime", 0))
                    t_meta = ForensicMeta(
                        vfs_path=f"/{rel_clean}",
                        fs_type="ARCHIVE",
                        size_bytes=written_sz,
                        si_modified=m_dt,
                        si_accessed=m_dt,
                    )
                    _finalize_member(target_file, t_meta, written_sz)

        is_tar_compound = any(
            name_lower.endswith(ext)
            for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
        )

        if name_lower.endswith((".zip", ".war", ".jar")):
            try:
                with zipfile.ZipFile(archive_path, "r") as zf:
                    for member in zf.infolist():
                        if total_written >= MAX_ARCHIVE_TOTAL_BYTES:
                            break
                        resolved = _resolve_member_target(member.filename)
                        if resolved is None:
                            continue
                        rel_clean, target_file = resolved
                        if member.is_dir():
                            target_file.mkdir(parents=True, exist_ok=True)
                            continue
                        decl_sz = int(getattr(member, "file_size", 0) or 0)
                        if decl_sz > MAX_ARCHIVE_MEMBER_BYTES or (total_written + decl_sz) > MAX_ARCHIVE_TOTAL_BYTES:
                            self._log(
                                f"Skipping oversized ZIP member {member.filename} ({decl_sz} bytes) in {archive_path.name}",
                                level="WARNING",
                            )
                            continue
                        m_meta = self._extract_zipinfo_meta(member)
                        m_meta.vfs_path = f"/{rel_clean}"
                        with zf.open(member) as source:
                            written_sz = _stream_to_target(source, target_file)
                        if written_sz is None:
                            continue
                        _finalize_member(target_file, m_meta, written_sz)
            except Exception as ex:
                self._log(f"Error extracting ZIP/WAR/JAR {archive_path}: {ex}", level="ERROR")

        elif name_lower.endswith(".7z"):
            if py7zr is not None:
                try:
                    with py7zr.SevenZipFile(archive_path, mode="r") as sz:
                        info_by_name: Dict[str, Any] = {}
                        try:
                            for info in sz.list():
                                info_by_name[str(info.filename)] = info
                        except Exception:
                            pass
                        all_names = list(info_by_name.keys()) if info_by_name else list(sz.getnames())
                        valid_members: List[Tuple[str, str, Path, Optional[datetime], Optional[datetime]]] = []
                        planned_bytes = 0
                        needs_rename = False

                        for orig_name in all_names:
                            info_obj = info_by_name.get(orig_name)
                            if info_obj is not None and bool(getattr(info_obj, "is_directory", False)):
                                resolved_dir = _resolve_member_target(orig_name)
                                if resolved_dir is not None:
                                    resolved_dir[1].mkdir(parents=True, exist_ok=True)
                                continue
                            resolved = _resolve_member_target(orig_name)
                            if resolved is None:
                                self._log(
                                    f"Rejected unsafe 7z member path '{orig_name}' in {archive_path.name}",
                                    level="WARNING",
                                )
                                continue
                            rel_clean, target_file = resolved
                            uncomp_sz = int(getattr(info_obj, "uncompressed", 0) or 0) if info_obj is not None else 0
                            if uncomp_sz > MAX_ARCHIVE_MEMBER_BYTES or (planned_bytes + uncomp_sz) > MAX_ARCHIVE_TOTAL_BYTES:
                                self._log(
                                    f"Skipping oversized 7z member '{orig_name}' ({uncomp_sz} bytes) in {archive_path.name}",
                                    level="WARNING",
                                )
                                continue
                            planned_bytes += uncomp_sz
                            orig_norm = orig_name.replace("\\", "/").strip("/")
                            if orig_norm != rel_clean:
                                needs_rename = True
                            cr_dt = _normalize_utc_naive(getattr(info_obj, "creationtime", None)) if info_obj is not None else None
                            lw_dt = _normalize_utc_naive(getattr(info_obj, "lastwritetime", None)) if info_obj is not None else None
                            valid_members.append((orig_name, rel_clean, target_file, lw_dt, cr_dt))

                        if valid_members:
                            target_names = [m[0] for m in valid_members]
                            bio_factory_cls = getattr(getattr(py7zr, "io", None), "BytesIOFactory", None)
                            if needs_rename and bio_factory_cls is not None:
                                factory = bio_factory_cls(limit=MAX_ARCHIVE_MEMBER_BYTES + 1024)
                                sz.extract(targets=target_names, factory=factory)
                                products = getattr(factory, "products", {})
                                for orig_name, rel_clean, target_file, lw_dt, cr_dt in valid_members:
                                    bio = products.get(orig_name)
                                    if bio is None:
                                        continue
                                    bio.seek(0)
                                    written_sz = _stream_to_target(bio, target_file)
                                    if written_sz is None:
                                        continue
                                    eff_m = lw_dt or cr_dt
                                    m_meta = ForensicMeta(
                                        vfs_path=f"/{rel_clean}",
                                        fs_type="ARCHIVE",
                                        size_bytes=written_sz,
                                        si_created=cr_dt,
                                        si_modified=eff_m,
                                        si_accessed=eff_m,
                                    )
                                    _finalize_member(target_file, m_meta, written_sz)
                            else:
                                safe_direct = [m for m in valid_members if m[0].replace("\\", "/").strip("/") == m[1]]
                                if safe_direct:
                                    sz.extract(path=str(output_dir), targets=[m[0] for m in safe_direct])
                                    for orig_name, rel_clean, target_file, lw_dt, cr_dt in safe_direct:
                                        if not target_file.is_file():
                                            continue
                                        actual_sz = int(target_file.stat().st_size)
                                        if (
                                            actual_sz > MAX_ARCHIVE_MEMBER_BYTES
                                            or (total_written + actual_sz) > MAX_ARCHIVE_TOTAL_BYTES
                                        ):
                                            target_file.unlink(missing_ok=True)
                                            continue
                                        total_written += actual_sz
                                        eff_m = lw_dt or cr_dt
                                        m_meta = ForensicMeta(
                                            vfs_path=f"/{rel_clean}",
                                            fs_type="ARCHIVE",
                                            size_bytes=actual_sz,
                                            si_created=cr_dt,
                                            si_modified=eff_m,
                                            si_accessed=eff_m,
                                        )
                                        _finalize_member(target_file, m_meta, actual_sz)
                except Exception as ex:
                    self._log(f"Error extracting 7z {archive_path}: {ex}", level="ERROR")

        elif is_tar_compound:
            try:
                _extract_tar_archive(archive_path)
            except Exception as ex:
                self._log(f"Error extracting TAR {archive_path}: {ex}", level="ERROR")

        elif name_lower.endswith((".gz", ".bz2", ".xz")):
            try:
                opener: Callable[..., Any]
                strip_len: int
                gz_mtime: Optional[datetime] = None
                if name_lower.endswith(".gz"):
                    opener = gzip.open
                    strip_len = 3
                    try:
                        with open(archive_path, "rb") as raw_gz:
                            hdr10 = raw_gz.read(10)
                        if len(hdr10) == 10 and hdr10[:2] == b"\x1f\x8b":
                            raw_ts = struct.unpack("<I", hdr10[4:8])[0]
                            if raw_ts > 0:
                                gz_mtime = _epoch_to_utc(raw_ts)
                    except OSError:
                        gz_mtime = None
                elif name_lower.endswith(".bz2"):
                    opener = bz2.open
                    strip_len = 4
                else:
                    opener = lzma.open
                    strip_len = 3

                is_wrapped_tar = False
                try:
                    with opener(archive_path, "rb") as probe_s:
                        head512 = probe_s.read(512)
                    if len(head512) >= 262 and head512[257:262] == b"ustar":
                        is_wrapped_tar = True
                except Exception:
                    is_wrapped_tar = False

                if is_wrapped_tar:
                    _extract_tar_archive(archive_path)
                else:
                    base_stem = archive_path.name[:-strip_len] if len(archive_path.name) > strip_len else ""
                    if not base_stem:
                        base_stem = f"{archive_path.stem or 'stream'}_decompressed"
                    resolved = _resolve_member_target(base_stem)
                    if resolved is not None:
                        rel_clean, target_file = resolved
                        with opener(archive_path, "rb") as comp_in:
                            written_sz = _stream_to_target(comp_in, target_file)
                        if written_sz is not None:
                            s_meta = ForensicMeta(
                                vfs_path=f"/{rel_clean}",
                                fs_type="ARCHIVE",
                                size_bytes=written_sz,
                                si_modified=gz_mtime,
                                si_accessed=gz_mtime,
                            )
                            _finalize_member(target_file, s_meta, written_sz)
            except Exception as ex:
                self._log(f"Error decompressing stream {archive_path}: {ex}", level="WARNING")

        elif name_lower.endswith(".rar") and rarfile is not None:
            try:
                with rarfile.RarFile(archive_path) as rf:
                    for member in rf.infolist():
                        if total_written >= MAX_ARCHIVE_TOTAL_BYTES:
                            break
                        resolved = _resolve_member_target(member.filename)
                        if resolved is None:
                            continue
                        rel_clean, target_file = resolved
                        if member.isdir():
                            target_file.mkdir(parents=True, exist_ok=True)
                            self._clear_file_attributes(target_file)
                            continue
                        decl_sz = int(getattr(member, "file_size", 0) or 0)
                        if decl_sz > MAX_ARCHIVE_MEMBER_BYTES or (total_written + decl_sz) > MAX_ARCHIVE_TOTAL_BYTES:
                            continue
                        with rf.open(member) as source:
                            written_sz = _stream_to_target(source, target_file)
                        if written_sz is None:
                            continue
                        r_dt: Optional[datetime] = None
                        raw_mt = getattr(member, "mtime", None)
                        if isinstance(raw_mt, datetime):
                            r_dt = _normalize_utc_naive(raw_mt)
                        else:
                            dt_tup = getattr(member, "date_time", None)
                            if dt_tup and len(dt_tup) == 6 and dt_tup != (1980, 1, 1, 0, 0, 0):
                                try:
                                    r_dt = datetime(*dt_tup)
                                except ValueError:
                                    r_dt = None
                        r_meta = ForensicMeta(
                            vfs_path=f"/{rel_clean}",
                            fs_type="ARCHIVE",
                            size_bytes=written_sz,
                            si_modified=r_dt,
                            si_accessed=r_dt,
                        )
                        _finalize_member(target_file, r_meta, written_sz)
            except Exception as ex:
                self._log(f"Error extracting RAR {archive_path}: {ex}", level="ERROR")

        return extracted_items

    def unpack_archive(
        self,
        archive_path: Path,
        output_dir: Path,
        fallback_mtime: Optional[datetime] = None,
    ) -> List[Path]:
        """Backward-compatible wrapper returning unpacked Paths while preserving forensic member timestamps."""
        return [
            p
            for p, _ in self.unpack_archive_with_meta(
                archive_path=archive_path,
                output_dir=output_dir,
                fallback_mtime=fallback_mtime,
            )
        ]

    # =========================================================================
    # Magic Detection, Username Extraction & Unified Contract 2 Router (F8)
    # =========================================================================

    def _is_registry_hive_or_log(self, file_path: Path) -> Tuple[bool, str]:
        name_lower = file_path.name.lower()
        for h in self.KNOWN_REGISTRY_HIVES:
            if _is_reg_hive_suffix_valid(name_lower, h):
                return True, h
        try:
            if file_path.is_file() and file_path.stat().st_size >= 4096:
                with open(file_path, "rb") as f:
                    if f.read(4) == b"regf":
                        return True, name_lower
        except Exception:
            pass
        return False, ""

    def _detect_magic_bytes(self, header: bytes, ext_xml_chunk: bytes = b"") -> Optional[str]:
        if len(header) < 4:
            return None
        if header.startswith(b"SQLite format 3\x00"):
            return "sqlite"
        if header.startswith(b"regf"):
            return "regf"
        if header.startswith(b"ElfFile\x00") or header.startswith(b"ElfChnk"):
            return "evtx"
        if header.startswith(b"MAM\x04") or (len(header) >= 8 and header[4:8] == b"SCCA") or header.startswith(b"SCCA"):
            return "prefetch"
        if len(header) >= 8 and header.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
            return "lnk"
        if (
            header.startswith(b"<?xml")
            or header.startswith(b"<!DOCTYPE")
            or header.startswith(b"\xff\xfe<\x00?\x00x\x00m\x00l\x00")
        ):
            probe = ext_xml_chunk or header
            if (
                b"<Task" in probe
                or b"<Actions" in probe
                or b"schemas.microsoft.com/windows/2004/02/mit/task" in probe
                or b"<WLANProfile" in probe
            ):
                return "wlan_xml" if b"<WLANProfile" in probe else "task_xml"
            return "xml"
        return None

    def _detect_magic_type(self, file_path: Path) -> Optional[str]:
        try:
            if not file_path.is_file() or file_path.stat().st_size < 4:
                return None
            with open(file_path, "rb") as f:
                chunk = f.read(2048)
            return self._detect_magic_bytes(chunk[:64], chunk)
        except Exception:
            return None

    def _extract_zone_identifier(
        self,
        file_path: Path,
        dst_dir: Path,
        rel_subpath: Optional[str] = None,
    ) -> Optional[Path]:
        try:
            ads_path = Path(str(file_path.resolve()) + ":Zone.Identifier")
            if ads_path.exists():
                parent_meta = self._stat_to_forensic_meta(file_path)
                with open(ads_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if content.strip():
                    rel_target = f"{rel_subpath}.Zone.Identifier" if rel_subpath else f"{file_path.name}.Zone.Identifier"
                    safe_rel = _sanitize_rel_path(rel_target)
                    if not safe_rel:
                        return None
                    dst_file = self._resolve_contained_dst(dst_dir, safe_rel)
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(dst_file, "w", encoding="utf-8") as out_f:
                        out_f.write(content)
                    self._clear_file_attributes(dst_file)
                    apply_forensic_utime(dst_file, parent_meta)
                    return dst_file
        except Exception:
            pass
        return None

    def _extract_username(self, file_path: Union[str, Path], source_root: Optional[Path] = None) -> str:
        """Extract username from /Users/<U>, /Documents and Settings/<U>, or /home/<U>."""
        if source_root is not None:
            try:
                rel_parts = Path(file_path).resolve().relative_to(source_root.resolve()).parts
                low_parts = [p.lower() for p in rel_parts]
                for marker in ("users", "documents and settings", "home"):
                    if marker in low_parts:
                        idx = low_parts.index(marker)
                        if idx + 1 < len(rel_parts):
                            cand_u = _sanitize_win32_segment(rel_parts[idx + 1])
                            if cand_u and cand_u != "_dotdot_":
                                return cand_u
            except Exception:
                pass

        posix_str = str(file_path).replace("\\", "/")
        m = re.search(r"/(?:Users|Documents and Settings|home)/([^/]+)/", posix_str, re.IGNORECASE)
        if m:
            cand_u = _sanitize_win32_segment(m.group(1))
            if cand_u and cand_u != "_dotdot_":
                return cand_u
        return "Default"

    @staticmethod
    def _extract_user_and_subpath(parts: Tuple[str, ...], low_parts: Tuple[str, ...]) -> Tuple[Optional[str], Tuple[str, ...], Tuple[str, ...]]:
        """
        Given POSIX path segments (without leading ''), find ('Users' | 'Documents and Settings', <U>)
        and return (username, user_rel_parts, user_rel_low_parts).
        Rejects empty, '.', and '..' segments so 'Users/../../evil' never yields uname='..'.
        """
        for idx, seg in enumerate(low_parts):
            if seg in ("users", "documents and settings") and idx + 1 < len(parts):
                uname = parts[idx + 1]
                if uname not in ("", ".", "..") and uname.lower() not in ("all users",):
                    return uname, parts[idx + 2 :], low_parts[idx + 2 :]
        return None, (), ()

    def _route_vfs_artifact(
        self,
        vfs_path: str,
        size_bytes: int,
        part_index: int,
        has_windows_os: bool,
        is_deleted: bool = False,
        magic_hint: Optional[str] = None,
        allow_loose_folder_rules: bool = False,
        archive_parent: Optional[str] = None,
    ) -> Tuple[Optional[str], List[str]]:
        """
        Unified Frozen Interface Contract 2 Artifact Router.
        Sanitizes every staging relative path segment (blocking '..', Win32 ':' ADS, '<>|?*',
        trailing dots/spaces, and CON/NUL device stems) while keeping vfs_path faithful in vfs_files.
        """
        cat, raw_rels = self._route_vfs_artifact_raw(
            vfs_path=vfs_path,
            size_bytes=size_bytes,
            part_index=part_index,
            has_windows_os=has_windows_os,
            is_deleted=is_deleted,
            magic_hint=magic_hint,
            allow_loose_folder_rules=allow_loose_folder_rules,
            archive_parent=archive_parent,
        )
        if not cat or not raw_rels:
            return None, []
        safe_rels: List[str] = []
        for r in raw_rels:
            sr = _sanitize_rel_path(r)
            if sr and sr not in safe_rels:
                safe_rels.append(sr)
        return (cat, safe_rels) if safe_rels else (None, [])

    def _route_vfs_artifact_raw(
        self,
        vfs_path: str,
        size_bytes: int,
        part_index: int,
        has_windows_os: bool,
        is_deleted: bool = False,
        magic_hint: Optional[str] = None,
        allow_loose_folder_rules: bool = False,
        archive_parent: Optional[str] = None,
    ) -> Tuple[Optional[str], List[str]]:
        """
        Internal Contract 2 route classifier before segment-level Win32 sanitization.
        """
        norm_p = "/" + vfs_path.replace("\\", "/").lstrip("/")
        raw_parts = tuple(p for p in norm_p.split("/") if p and p != ".")
        if not raw_parts:
            return None, []

        low_parts = tuple(p.lower() for p in raw_parts)
        fname = raw_parts[-1]
        fname_low = low_parts[-1]
        fpath_low = "/".join(low_parts)
        part_label = f"Part_{part_index}" if part_index >= 0 else f"Part_0"
        rel_full = "/".join(raw_parts)
        if archive_parent:
            rel_full = f"{archive_parent}/{rel_full}"

        if fname_low in ("pagefile.sys", "hiberfil.sys", "swapfile.sys"):
            return None, []
        if low_parts[0] in ("$extend", "system volume information"):
            return None, []

        # 0. Zone.Identifier ADS files
        if fname_low.endswith(":zone.identifier") or fname_low.endswith(".zone.identifier"):
            return "zone_identifier", [f"ZoneIdentifier/{part_label}/{rel_full}"]

        # 1. Raw $MFT / $J when encountered as loose files in directory/archive mode
        if allow_loose_folder_rules:
            if fname_low in ("$mft", "mft") or fname_low.startswith("$mft"):
                return "mft", ["FileSystem/$MFT", "$MFT"]
            if fname_low in ("$j", "usnjrnl", "$usnjrnl", "$usnjrnl:$j", "$usnjrnl-$j") or fname_low.endswith(":$j"):
                return "usnjrnl", ["FileSystem/$J", "$J"]
        elif len(low_parts) == 1 and fname_low in _NTFS_META_ROOT_NAMES:
            return None, []

        uname, u_parts, u_low = self._extract_user_and_subpath(raw_parts, low_parts)

        # 2. Registry Hives & Transaction Logs (.LOG*, .BLF, .REGTRANS-MS) — ZERO flat duplicates!
        # 2a. System Registry: /Windows/System32/config/* and /Boot/BCD*
        if len(low_parts) >= 4 and low_parts[:3] == ("windows", "system32", "config") and len(low_parts) == 4:
            for sys_h in ("system", "software", "sam", "security", "default", "components", "bcd-template"):
                if _is_reg_hive_suffix_valid(fname_low, sys_h):
                    return "registry", [f"Registry/System/{fname}"]
        if len(low_parts) == 2 and low_parts[0] == "boot" and _is_reg_hive_suffix_valid(fname_low, "bcd"):
            return "registry", [f"Registry/System/{fname}"]

        # 2b. Amcache.hve & RecentFileCache.bcf
        if (
            len(low_parts) == 4
            and low_parts[0] == "windows"
            and low_parts[1] in ("appcompat", "apppatch")
            and low_parts[2] == "programs"
        ):
            if _is_reg_hive_suffix_valid(fname_low, "amcache.hve"):
                return "registry", [f"Registry/Amcache/{fname}"]
            if fname_low == "recentfilecache.bcf":
                return "recentfilecache", ["Registry/Amcache/RecentFileCache.bcf"]

        # 2c. User Registry (Vista+ /Users/<U> AND XP/2003 /Documents and Settings/<U>)
        if uname and u_low:
            if len(u_low) == 1 and _is_reg_hive_suffix_valid(fname_low, "ntuser.dat"):
                return "registry", [f"Registry/Users/{uname}/{fname}"]
            if (
                (len(u_low) == 5 and u_low[:4] == ("appdata", "local", "microsoft", "windows"))
                or (len(u_low) == 5 and u_low[:4] == ("local settings", "application data", "microsoft", "windows"))
            ) and _is_reg_hive_suffix_valid(fname_low, "usrclass.dat"):
                return "registry", [f"Registry/Users/{uname}/{fname}"]

        # Loose folder registry fallback (when source folder is an already-flattened triage dump)
        if allow_loose_folder_rules:
            if _is_reg_hive_suffix_valid(fname_low, "amcache.hve"):
                return "registry", [f"Registry/Amcache/{fname}"]
            if fname_low == "recentfilecache.bcf":
                return "recentfilecache", ["Registry/Amcache/RecentFileCache.bcf"]
            if _is_reg_hive_suffix_valid(fname_low, "ntuser.dat") or _is_reg_hive_suffix_valid(fname_low, "usrclass.dat"):
                eff_u = uname or "Default"
                return "registry", [f"Registry/Users/{eff_u}/{fname}"]
            for sys_h in ("system", "software", "sam", "security", "default", "components", "bcd-template"):
                if _is_reg_hive_suffix_valid(fname_low, sys_h):
                    return "registry", [f"Registry/System/{fname}"]
            if magic_hint == "regf":
                return "registry", [f"Registry/System/{fname}"]

        # 3. Browsers — Multi-Profile Dynamic Discovery + Local State + Subtrees
        if uname and u_low:
            # Determine Local AppData vs Roaming AppData prefix across Vista+ and XP/2003
            local_rest: Tuple[str, ...] = ()
            local_rest_low: Tuple[str, ...] = ()
            roam_rest: Tuple[str, ...] = ()
            roam_rest_low: Tuple[str, ...] = ()
            if len(u_low) >= 3 and u_low[:2] == ("appdata", "local"):
                local_rest, local_rest_low = u_parts[2:], u_low[2:]
            elif len(u_low) >= 3 and u_low[:2] == ("local settings", "application data"):
                local_rest, local_rest_low = u_parts[2:], u_low[2:]
            if len(u_low) >= 3 and u_low[:2] == ("appdata", "roaming"):
                roam_rest, roam_rest_low = u_parts[2:], u_low[2:]
            elif len(u_low) >= 2 and u_low[:1] == ("application data",):
                roam_rest, roam_rest_low = u_parts[1:], u_low[1:]

            # 3a. Chromium Browsers under Local AppData
            chromium_roots: Tuple[Tuple[Tuple[str, ...], str], ...] = (
                (("google", "chrome", "user data"), "Chrome"),
                (("microsoft", "edge", "user data"), "Edge"),
                (("bravesoftware", "brave-browser", "user data"), "Brave"),
                (("vivaldi", "user data"), "Vivaldi"),
                (("chromium", "user data"), "Chromium"),
            )
            for prefix_segs, br_name in chromium_roots:
                plen = len(prefix_segs)
                if len(local_rest_low) > plen and local_rest_low[:plen] == prefix_segs:
                    ud_parts = local_rest[plen:]
                    ud_low = local_rest_low[plen:]
                    # <User Data>/Local State -> staging/Browsers/<BrowserName>/<Username>/Local State
                    if len(ud_low) == 1 and ud_low[0] == "local state":
                        return "browsers", [f"Browsers/{br_name}/{uname}/Local State"]
                    if len(ud_low) >= 2:
                        prof_dir = ud_parts[0]
                        prof_low = ud_low[0]
                        if prof_low not in _CHROMIUM_NON_PROFILE_DIRS:
                            in_prof_parts = ud_parts[1:]
                            in_prof_low = ud_low[1:]
                            in_prof_rel = "/".join(in_prof_parts)
                            if len(in_prof_low) == 1:
                                f0 = in_prof_low[0]
                                if f0 in _CHROMIUM_PROFILE_TOP_EXACT or f0.startswith(_CHROMIUM_PROFILE_TOP_PREFIXES):
                                    return "browsers", [f"Browsers/{br_name}/{uname}/{prof_dir}/{in_prof_rel}"]
                            else:
                                top_sub = in_prof_low[0]
                                if top_sub in _CHROMIUM_PROFILE_SUBTREES:
                                    if top_sub == "cache" and size_bytes > 25 * 1024 * 1024:
                                        return None, []
                                    return "browsers", [f"Browsers/{br_name}/{uname}/{prof_dir}/{in_prof_rel}"]

            # 3b. Opera / Opera GX under Roaming AppData
            if (
                len(roam_rest_low) >= 3
                and roam_rest_low[0] == "opera software"
                and roam_rest_low[1] in ("opera stable", "opera gx stable")
            ):
                op_prof = roam_rest[1]
                op_in = roam_rest[2:]
                op_in_low = roam_rest_low[2:]
                op_rel = "/".join(op_in)
                if len(op_in_low) == 1:
                    f0 = op_in_low[0]
                    if f0 in _CHROMIUM_PROFILE_TOP_EXACT or f0.startswith(_CHROMIUM_PROFILE_TOP_PREFIXES):
                        return "browsers", [f"Browsers/Opera/{uname}/{op_prof}/{op_rel}"]
                elif op_in_low[0] in _CHROMIUM_PROFILE_SUBTREES:
                    if op_in_low[0] == "cache" and size_bytes > 25 * 1024 * 1024:
                        return None, []
                    return "browsers", [f"Browsers/Opera/{uname}/{op_prof}/{op_rel}"]

            # 3c. Firefox Profiles under Roaming AppData
            if len(roam_rest_low) >= 5 and roam_rest_low[:3] == ("mozilla", "firefox", "profiles"):
                ff_prof = roam_rest[3]
                ff_in = roam_rest[4:]
                ff_in_low = roam_rest_low[4:]
                ff_rel = "/".join(ff_in)
                if len(ff_in_low) == 1:
                    f0 = ff_in_low[0]
                    if f0 in _FIREFOX_PROFILE_EXACT or f0.startswith(_FIREFOX_PROFILE_PREFIXES):
                        return "browsers", [f"Browsers/Firefox/{uname}/{ff_prof}/{ff_rel}"]
                elif ff_in_low[0] in ("sessionstore-backups", "storage"):
                    return "browsers", [f"Browsers/Firefox/{uname}/{ff_prof}/{ff_rel}"]

            # 3d. Legacy IE / Edge WebCacheV01.dat & index.dat
            if (
                len(local_rest_low) == 4
                and local_rest_low[:3] == ("microsoft", "windows", "webcache")
                and (fname_low.startswith("webcachev") or fname_low.startswith("v01"))
            ):
                return "browsers", [f"WebCache/{uname}/{fname}"]
            if fname_low in ("index.dat", "container.dat") and any(
                k in fpath_low
                for k in ("history", "cookies", "temporary internet files", "content.ie5", "inetcache")
            ):
                u_rel = "/".join(u_parts)
                return "browsers", [f"Browsers/IE/{uname}/{u_rel}"]

            # 4. Windows Timeline: ActivitiesCache/<U>/<Subdir>/ActivitiesCache.db*
            if (
                len(local_rest_low) >= 3
                and local_rest_low[0] == "connecteddevicesplatform"
                and fname_low.startswith("activitiescache.db")
            ):
                cdp_sub = "/".join(local_rest[1:-1]) or "Default"
                return "activities_cache", [f"ActivitiesCache/{uname}/{cdp_sub}/{fname}"]

            # 5a. Per-User WER: WER/Users/<U>/<ReportFolder>/...
            if (
                len(local_rest_low) >= 5
                and local_rest_low[:3] == ("microsoft", "windows", "wer")
                and local_rest_low[3] in ("reportarchive", "reportqueue")
            ):
                wer_rel = "/".join(local_rest[4:])
                return "wer", [f"WER/Users/{uname}/{wer_rel}"]

            # 6. Windows Push Notifications: Notifications/<U>/wpndatabase.db*
            if (
                len(local_rest_low) == 4
                and local_rest_low[:3] == ("microsoft", "windows", "notifications")
                and fname_low.startswith("wpndatabase.db")
            ):
                return "sqlite", [f"Notifications/{uname}/{fname}"]

            # 7. PowerShell History: PowerShell/<U>/<Filename>
            if (
                len(roam_rest_low) >= 5
                and roam_rest_low[:4] == ("microsoft", "windows", "powershell", "psreadline")
            ):
                return "powershell", [f"PowerShell/{uname}/{fname}"]

            # 8. JumpLists & Recent / Desktop / Start Menu LNKs & Startup
            if len(roam_rest_low) >= 4 and roam_rest_low[:3] == ("microsoft", "windows", "recent"):
                rec_sub_low = roam_rest_low[3:]
                rec_sub = roam_rest[3:]
                if len(rec_sub_low) == 2 and rec_sub_low[0] == "automaticdestinations" and fname_low.endswith(".automaticdestinations-ms"):
                    return "jumplists", [f"JumpLists/{uname}/AutomaticDestinations/{fname}"]
                if len(rec_sub_low) == 2 and rec_sub_low[0] == "customdestinations" and fname_low.endswith(".customdestinations-ms"):
                    return "jumplists", [f"JumpLists/{uname}/CustomDestinations/{fname}"]
                if fname_low.endswith(".lnk"):
                    return "lnk", [f"Recent/{uname}/{'/'.join(rec_sub)}"]

            if len(u_low) >= 2 and u_low[0] == "recent" and fname_low.endswith(".lnk"):
                return "lnk", [f"Recent/{uname}/{'/'.join(u_parts[1:])}"]

            if "startup" in fpath_low and "start menu" in fpath_low:
                return "startup", [f"Startup/{uname}/{fname}"]

            if fname_low.endswith(".lnk") and any(seg in u_low for seg in ("desktop", "start menu")):
                return "lnk", [f"LNK/{uname}/{'/'.join(u_parts)}"]

            # 9. Thumbcache & StickyNotes
            if (
                len(local_rest_low) == 4
                and local_rest_low[:3] == ("microsoft", "windows", "explorer")
                and (fname_low.startswith("thumbcache_") or fname_low.startswith("iconcache_"))
            ):
                return "thumbcache", [f"Thumbcache/{uname}/{fname}"]

            if fname_low == "stickynotes.snt" or ("microsoftstickynotes" in fpath_low and fname_low.startswith("plum.sqlite")):
                return "stickynotes", [f"StickyNotes/{uname}/{fname}"]

            # 10. Cloud Storage (OneDrive, GoogleDrive, Dropbox)
            if len(local_rest_low) >= 3 and local_rest_low[:2] == ("microsoft", "onedrive"):
                if fname_low.endswith((".db", ".db-wal", ".db-shm", ".dat", ".ini", ".log", ".sqlite")):
                    od_rel = "/".join(local_rest[2:])
                    return "cloud", [f"Cloud/OneDrive/{uname}/{od_rel}"]
            if len(local_rest_low) >= 3 and local_rest_low[0] == "google" and local_rest_low[1] in ("drive", "drivefs"):
                if (
                    fname_low in ("sync_log.log", "snapshot.db", "metadata_sqlite_db")
                    or fname_low.startswith(("metadata_sqlite_db-", "snapshot.db-"))
                    or fname_low.endswith((".db", ".sqlite", ".log"))
                ):
                    gd_rel = "/".join(local_rest[2:])
                    return "cloud", [f"Cloud/GoogleDrive/{uname}/{gd_rel}"]
            for dbx_rest, dbx_low in ((local_rest, local_rest_low), (roam_rest, roam_rest_low)):
                if len(dbx_low) >= 2 and dbx_low[0] == "dropbox":
                    if fname_low.endswith((".dbx", ".json", ".sqlite3", ".db")) or "nucleus.sqlite3" in fname_low:
                        return "cloud", [f"Cloud/Dropbox/{uname}/{'/'.join(dbx_rest[1:])}"]

            # 11. Chat Applications (Teams, Discord, Slack, Skype, Telegram, Signal)
            if (
                any(k in fpath_low for k in ("/microsoft/teams/", "msteams", "microsoftcorporationii.microsoftteams", "/discord/", "/slack/", "/skype/"))
                and (
                    fname_low.endswith((".ldb", ".log", ".sqlite", ".db", ".json", ".dat"))
                    or fname_low in ("current", "lock")
                    or fname_low.startswith("manifest-")
                )
            ):
                app_lbl = (
                    "Teams"
                    if any(k in fpath_low for k in ("teams", "msteams"))
                    else ("Discord" if "/discord/" in fpath_low else ("Slack" if "/slack/" in fpath_low else "Skype"))
                )
                return "chat", [f"Chat/{app_lbl}/{uname}/{'/'.join(u_parts)}"]

            # 12. Email Stores (.pst, .ost, .eml, .msg, .mbox)
            if fname_low.endswith((".pst", ".ost", ".eml", ".msg", ".mbox")) and size_bytes <= 2 * 1024 * 1024 * 1024:
                return "email", [f"Email/{uname}/{'/'.join(u_parts)}"]

        # 5b. System WER: /ProgramData/Microsoft/Windows/WER/{ReportArchive,ReportQueue}/<ReportFolder>/...
        if (
            len(low_parts) >= 6
            and low_parts[:4] == ("programdata", "microsoft", "windows", "wer")
            and low_parts[4] in ("reportarchive", "reportqueue")
        ):
            return "wer", [f"WER/System/{'/'.join(raw_parts[5:])}"]
        if (
            len(low_parts) >= 8
            and low_parts[:6] == ("documents and settings", "all users", "application data", "microsoft", "windows", "wer")
            and low_parts[6] in ("reportarchive", "reportqueue")
        ):
            return "wer", [f"WER/System/{'/'.join(raw_parts[7:])}"]

        # 13. WLAN Profiles: /ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/<GUID>/*.xml
        if (
            len(low_parts) >= 7
            and low_parts[:5] == ("programdata", "microsoft", "wlansvc", "profiles", "interfaces")
            and fname_low.endswith(".xml")
        ):
            guid_dir = raw_parts[5]
            return "wlan", [f"WLAN/Interfaces/{guid_dir}/{fname}"]

        # 14. System Event Logs (.evtx / XP .evt), SetupAPI, SUM, WebLogs, Prefetch, SRUM, WBEM, Tasks
        if len(low_parts) >= 5 and low_parts[:4] == ("windows", "system32", "winevt", "logs") and fname_low.endswith(".evtx"):
            return "evtx", [f"Logs/{fname}"]
        if len(low_parts) == 4 and low_parts[:3] == ("windows", "system32", "config") and fname_low.endswith(".evt"):
            return "evtx", [f"Logs/{fname}"]
        if (
            (len(low_parts) == 3 and low_parts[:2] == ("windows", "inf") and fname_low.startswith("setupapi") and fname_low.endswith(".log"))
            or (len(low_parts) == 2 and low_parts[0] == "windows" and fname_low == "setupapi.log")
        ):
            return "setupapi", [f"USB/{fname}"]
        if len(low_parts) >= 5 and low_parts[:4] == ("windows", "system32", "logfiles", "sum"):
            return "sum", [f"SUM/{'/'.join(raw_parts[4:])}"]
        if (
            len(low_parts) >= 5
            and low_parts[:3] == ("windows", "system32", "logfiles")
            and (low_parts[3].startswith("w3svc") or low_parts[3] in ("firewall", "httperr"))
        ):
            return "weblogs", [f"WebLogs/{'/'.join(raw_parts[3:])}"]
        if len(low_parts) == 3 and low_parts[:2] == ("windows", "prefetch") and fname_low.endswith(".pf"):
            return "prefetch", [f"Prefetch/{fname}"]
        if len(low_parts) >= 4 and low_parts[:3] == ("windows", "system32", "sru"):
            return "srum", [f"SRUM/{'/'.join(raw_parts[3:])}"]
        if len(low_parts) >= 5 and low_parts[:4] == ("windows", "system32", "wbem", "repository"):
            return "wbem", [f"WBEM/{'/'.join(raw_parts[4:])}"]
        if (
            (len(low_parts) >= 4 and low_parts[:3] == ("windows", "system32", "tasks"))
            or (len(low_parts) >= 3 and low_parts[:2] == ("windows", "tasks"))
        ):
            t_start = 3 if low_parts[1] == "system32" else 2
            return "tasks", [f"Tasks/{'/'.join(raw_parts[t_start:])}"]

        # 15. Recycle Bin ($Recycle.Bin, RECYCLER, Recycled)
        if low_parts[0] in ("$recycle.bin", "recycler", "recycled") and len(low_parts) >= 2 and fname_low != "desktop.ini":
            return "recycle_bin", [f"RecycleBin/{'/'.join(raw_parts[1:])}"]

        # 16. RMM Logs (AnyDesk, TeamViewer, ScreenConnect, Splashtop, RustDesk)
        if any(rmm in fpath_low for rmm in ("anydesk", "teamviewer", "screenconnect", "splashtop", "rustdesk")) and (
            fname_low.endswith((".trace", ".log", ".txt", ".json", ".ini"))
        ):
            tool = (
                "AnyDesk"
                if "anydesk" in fpath_low
                else (
                    "TeamViewer"
                    if "teamviewer" in fpath_low
                    else ("RustDesk" if "rustdesk" in fpath_low else ("Splashtop" if "splashtop" in fpath_low else "ScreenConnect"))
                )
            )
            owner = uname or "System"
            return "rmm", [f"RMM/{tool}/{owner}/{fname}"]

        # 17. Loose Folder / Unstructured Triage Fallbacks (when source folder doesn't have full OS root)
        if allow_loose_folder_rules:
            if fname_low.endswith(".evtx") or magic_hint == "evtx":
                return "evtx", [f"Logs/{fname}"]
            if fname_low.endswith(".pf") or magic_hint == "prefetch":
                return "prefetch", [f"Prefetch/{fname}"]
            if fname_low.endswith(".automaticdestinations-ms"):
                return "jumplists", [f"JumpLists/{uname or 'Default'}/AutomaticDestinations/{fname}"]
            if fname_low.endswith(".customdestinations-ms"):
                return "jumplists", [f"JumpLists/{uname or 'Default'}/CustomDestinations/{fname}"]
            if fname_low.endswith(".lnk") or magic_hint == "lnk":
                return "lnk", [f"LNK/{uname or 'Default'}/{rel_full}"]
            if fname_low == "srudb.dat" or fname_low.startswith("srudb.dat"):
                return "srum", [f"SRUM/{fname}"]
            if fname_low.startswith("activitiescache.db"):
                sub_p = raw_parts[-2] if len(raw_parts) >= 2 else "Default"
                return "activities_cache", [f"ActivitiesCache/{uname or 'Default'}/{sub_p}/{fname}"]
            if fname_low.startswith("wpndatabase.db"):
                return "sqlite", [f"Notifications/{uname or 'Default'}/{fname}"]
            if fname_low.startswith("setupapi") and fname_low.endswith(".log"):
                return "setupapi", [f"USB/{fname}"]
            if fname_low == "consolehost_history.txt":
                return "powershell", [f"PowerShell/{uname or 'Default'}/{fname}"]
            if magic_hint == "task_xml":
                return "tasks", [f"Tasks/{rel_full}"]
            if magic_hint == "wlan_xml":
                guid_p = raw_parts[-2] if len(raw_parts) >= 2 else "Default"
                return "wlan", [f"WLAN/Interfaces/{guid_p}/{fname}"]
            if fname_low.endswith(".wer"):
                rep_folder = raw_parts[-2] if len(raw_parts) >= 2 else "Report"
                if uname:
                    return "wer", [f"WER/Users/{uname}/{rep_folder}/{fname}"]
                return "wer", [f"WER/System/{rep_folder}/{fname}"]
            if fname_low in _FIREFOX_PROFILE_EXACT or fname_low.startswith(_FIREFOX_PROFILE_PREFIXES):
                prof_p = raw_parts[-2] if len(raw_parts) >= 2 else "default"
                return "browsers", [f"Browsers/Firefox/{uname or 'Default'}/{prof_p}/{fname}"]
            if fname_low in _CHROMIUM_PROFILE_TOP_EXACT or fname_low.startswith(_CHROMIUM_PROFILE_TOP_PREFIXES):
                br = "Edge" if "edge" in fpath_low else ("Brave" if "brave" in fpath_low else "Chrome")
                if fname_low == "local state":
                    return "browsers", [f"Browsers/{br}/{uname or 'Default'}/Local State"]
                prof_p = raw_parts[-2] if len(raw_parts) >= 2 else "Default"
                if prof_p.lower() == "network" and len(raw_parts) >= 3:
                    prof_p = raw_parts[-3]
                    return "browsers", [f"Browsers/{br}/{uname or 'Default'}/{prof_p}/Network/{fname}"]
                return "browsers", [f"Browsers/{br}/{uname or 'Default'}/{prof_p}/{fname}"]
            if fname_low.endswith((".pst", ".ost", ".eml", ".msg", ".mbox")):
                return "email", [f"Email/{uname or 'Default'}/{rel_full}"]
            if magic_hint == "sqlite" or fname_low.endswith((".sqlite", ".sqlite3", ".db")):
                return "sqlite", [f"SQLite/{rel_full}"]

        # 18. Structure-Preserving Enrichment (staging/Enrichment/Part_<idx>/<full_rel_path>)
        is_archive_or_mail = fname_low.endswith(tuple(self.ARCHIVE_EXTENSIONS)) or fname_low.endswith((".pst", ".ost", ".mbox"))
        max_cap = (2 * 1024 * 1024 * 1024) if is_archive_or_mail else (256 * 1024 * 1024)
        if size_bytes > max_cap:
            return None, []

        if low_parts[0] == "windows":
            if len(low_parts) >= 2 and low_parts[1] in ("winsxs", "servicing", "installer"):
                return None, []
            if len(low_parts) >= 3 and low_parts[:3] == ("windows", "system32", "driverstore"):
                return None, []
            if fname_low.endswith((".nls", ".mui", ".mum", ".manifest", ".cat")):
                return None, []

        if not has_windows_os:
            # Non-OS / Removable / Data volume: stage 100% of regular files (allocated + non-empty deleted/orphan/VAT)
            if is_deleted and size_bytes <= 0:
                return None, []
            return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        # OS volume: stage user trees, web roots, Windows/Temp, PerfLogs, non-noisy ProgramData, and custom root folders
        if is_deleted:
            return None, []
        if fname_low == "desktop.ini":
            return None, []

        top_root_low = low_parts[0]
        if uname and u_low:
            # Skip noisy OS/app/browser binary cache trees under user profiles (index.dat & WebCacheV01.dat are already routed earlier)
            if any(
                noisy in fpath_low
                for noisy in (
                    "/appdata/local/packages/",
                    "/appdata/local/microsoft/clr",
                    "/appdata/local/microsoft/windows/temporary internet files/",
                    "/appdata/local/microsoft/windows/inetcache/",
                    "/appdata/local/microsoft/windows/webcache/",
                    "/appdata/local/google/chrome/application/",
                    "/appdata/local/google/chrome/user data/default/cache/",
                    "/appdata/local/google/chrome/user data/default/media cache/",
                    "/appdata/local/microsoft/edge/application/",
                    "/appdata/local/microsoft/edge/user data/default/cache/",
                    "/appdata/local/temp/low/",
                    "/local settings/temporary internet files/",
                )
            ):
                return None, []
            return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        if top_root_low in ("inetpub", "xampp", "wamp", "wamp64", "nginx", "perflogs"):
            return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        if len(low_parts) >= 3 and low_parts[:2] == ("windows", "temp"):
            return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        if top_root_low == "programdata":
            if any(
                skip_pd in fpath_low
                for skip_pd in (
                    "programdata/microsoft/windows defender",
                    "programdata/package cache",
                    "programdata/microsoft/windows/containers",
                    "programdata/usoprivate",
                    "programdata/microsoft/diagnosis",
                    "programdata/microsoft/search/data",
                    "programdata/apple/installer cache",
                )
            ):
                return None, []
            return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        if top_root_low not in _OS_STANDARD_ROOT_DIRS:
            return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        if any(kw in fpath_low for kw in self.WEB_SERVER_KEYWORDS):
            if top_root_low not in ("windows",):
                return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        if fname_low.endswith(tuple(self.SUSPICIOUS_MALWARE_EXTENSIONS)):
            if top_root_low not in (_OS_STANDARD_ROOT_DIRS - {"users", "documents and settings"}):
                return "enrichment", [f"Enrichment/{part_label}/{rel_full}"]

        return None, []

    def _stage_host_file_with_rels(
        self,
        file_path: Path,
        staging_dir: Path,
        archive_parent: Optional[str] = None,
        source_root: Optional[Path] = None,
        has_windows_os: bool = False,
        meta_override: Optional[ForensicMeta] = None,
        claimed_map: Optional[Dict[str, Tuple[str, Any]]] = None,
        claim_lock: Optional[threading.Lock] = None,
        source_key: Any = None,
        copy_sqlite_siblings: bool = True,
    ) -> Tuple[Optional[str], List[str]]:
        """
        Classify a host file on disk and copy it to its canonical Contract 2 staging path(s)
        while preserving original MACB timestamps via apply_forensic_utime().
        Returns (category, staged_rel_paths).
        """
        resolved_src = Path(file_path).resolve()
        staging_root = Path(staging_dir).resolve()
        if not resolved_src.is_file():
            return None, []

        if source_root is not None:
            try:
                rel_posix = resolved_src.relative_to(source_root.resolve()).as_posix()
            except ValueError:
                rel_posix = resolved_src.name
        else:
            rel_posix = resolved_src.name

        vfs_path = f"/{rel_posix.lstrip('/')}"
        meta = meta_override or self._stat_to_forensic_meta(resolved_src, vfs_path=vfs_path, fs_type="FOLDER")
        magic = self._detect_magic_type(resolved_src)

        staged_rels: List[str] = []
        # Extract NTFS :Zone.Identifier ADS if present on Windows
        zi_dst = self._extract_zone_identifier(resolved_src, staging_root / "ZoneIdentifier" / "Part_0", rel_subpath=rel_posix)
        if zi_dst is not None:
            try:
                staged_rels.append(zi_dst.relative_to(staging_root).as_posix())
            except ValueError:
                pass

        category, route_rels = self._route_vfs_artifact(
            vfs_path=vfs_path,
            size_bytes=meta.size_bytes,
            part_index=0,
            has_windows_os=has_windows_os,
            is_deleted=False,
            magic_hint=magic,
            allow_loose_folder_rules=not has_windows_os,
            archive_parent=archive_parent,
        )

        if not route_rels:
            return ("zone_identifier", staged_rels) if staged_rels else (None, [])

        if claimed_map is not None and claim_lock is not None:
            eff_key = source_key if source_key is not None else ("host", str(resolved_src))
            assigned_rels, rels_to_write = self._claim_staged_rels(
                rels=route_rels,
                claimed_map=claimed_map,
                claim_lock=claim_lock,
                source_key=eff_key,
                is_deleted=False,
            )
        else:
            assigned_rels = route_rels
            rels_to_write = route_rels

        write_set = set(rels_to_write)
        copied_any = False
        for rel_dst in assigned_rels:
            dst = self._resolve_contained_dst(staging_root, rel_dst)
            if rel_dst not in write_set:
                copied_any = True
                staged_rels.append(rel_dst)
                continue
            if self._copy_file_safe(resolved_src, dst, overwrite=True, meta=meta, root_guard=staging_root):
                copied_any = True
                staged_rels.append(rel_dst)
                if (
                    copy_sqlite_siblings
                    and category == "sqlite"
                    and not resolved_src.name.lower().endswith(("-wal", "-shm", "-journal"))
                ):
                    for sfx in ("-wal", "-shm", "-journal"):
                        sib = resolved_src.parent / (resolved_src.name + sfx)
                        if sib.is_file():
                            sib_meta = self._stat_to_forensic_meta(sib, vfs_path=f"{vfs_path}{sfx}", fs_type="FOLDER")
                            sib_dst = dst.parent / _sanitize_win32_segment(sib.name)
                            self._copy_file_safe(sib, sib_dst, overwrite=True, meta=sib_meta, root_guard=staging_root)

        return (category if copied_any else None), staged_rels

    def _classify_and_stage_file(
        self,
        file_path: Path,
        staging_dir: Path,
        archive_parent: Optional[str] = None,
        source_root: Optional[Path] = None,
    ) -> Optional[str]:
        cat, _ = self._stage_host_file_with_rels(
            file_path=file_path,
            staging_dir=staging_dir,
            archive_parent=archive_parent,
            source_root=source_root,
            has_windows_os=False,
        )
        return cat


    # =========================================================================
    # MODE 1: Extract from Directory / Evidence Folder / Archive
    # =========================================================================

    @staticmethod
    def _build_vfs_row(
        part_index: int,
        vfs_path: str,
        staged_rel_path: Optional[str],
        meta: ForensicMeta,
    ) -> Tuple[Any, ...]:
        norm_vfs = "/" + vfs_path.replace("\\", "/").lstrip("/")
        if norm_vfs == "/":
            fname = ""
            parent_p = ""
        else:
            p_obj = PurePosixPath(norm_vfs)
            fname = p_obj.name
            parent_p = str(p_obj.parent) if str(p_obj.parent) != "." else "/"
        return (
            int(part_index),
            norm_vfs,
            staged_rel_path,
            fname,
            parent_p,
            int(meta.size_bytes or 0),
            bool(meta.is_dir),
            bool(meta.is_deleted),
            meta.si_created,
            meta.si_modified,
            meta.si_accessed,
            meta.si_changed,
            meta.fn_created,
            meta.fn_modified,
            meta.fn_accessed,
            meta.fn_changed,
            meta.mft_entry,
        )

    def extract_from_directory(
        self,
        source_dir: Union[str, Path],
        staging_dir: Optional[Union[str, Path]] = None,
        unpack_archives: bool = True,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Walk an evidence directory or single archive, stage artifacts according to Contract 2,
        preserve original MACB timestamps via apply_forensic_utime(), unpack nested archives,
        and populate vfs_partitions, vfs_files, and vfs_shadow_copies in DuckDB.
        """
        start_time = time.time()
        eff_workers = self._resolve_workers(max_workers)
        eff_vss = self._resolve_vss(enable_vss, selected_artifacts)

        clean_source = str(source_dir).strip().strip('"').strip("'").strip()
        raw_source_abs = os.path.abspath(clean_source)
        try:
            root_initial_st = os.stat(raw_source_abs)
        except OSError:
            raise FileNotFoundError(f"Source evidence directory does not exist: {raw_source_abs}")

        staging_raw_abs = os.path.abspath(str(staging_dir)) if staging_dir else os.path.abspath(str(self.staging_dir))
        staging_norm = os.path.normcase(staging_raw_abs)

        # Snapshot initial stat() (st_atime, st_mtime, st_ctime, st_size) BEFORE Path.resolve(),
        # os.walk, or opening/unpacking files so Windows NTFS directory/file st_atime is never clobbered.
        initial_stat_map: Dict[str, os.stat_result] = {
            os.path.normcase(raw_source_abs): root_initial_st
        }
        if stat.S_ISDIR(root_initial_st.st_mode):
            def _capture_prewalk_stats(cur_dir_str: str) -> None:
                sub_dirs: List[str] = []
                try:
                    with os.scandir(cur_dir_str) as it:
                        for entry in it:
                            ep_abs = os.path.abspath(entry.path)
                            ep_key = os.path.normcase(ep_abs)
                            if ep_key == staging_norm or ep_key.startswith(staging_norm + os.sep):
                                continue
                            try:
                                st_e = entry.stat(follow_symlinks=True)
                                initial_stat_map[ep_key] = st_e
                                if entry.is_dir(follow_symlinks=False):
                                    sub_dirs.append(entry.path)
                            except OSError:
                                continue
                except OSError:
                    return
                for sd in sub_dirs:
                    _capture_prewalk_stats(sd)

            _capture_prewalk_stats(raw_source_abs)

        def _lookup_initial_stat(p: Path) -> Optional[os.stat_result]:
            st_hit = initial_stat_map.get(os.path.normcase(os.path.abspath(str(p))))
            if st_hit is not None:
                return st_hit
            try:
                return initial_stat_map.get(os.path.normcase(str(p.resolve())))
            except OSError:
                return None

        source_path = Path(raw_source_abs).resolve()
        initial_stat_map.setdefault(os.path.normcase(str(source_path)), root_initial_st)

        staging_path = Path(staging_dir).resolve() if staging_dir else self.staging_dir
        staging_path.mkdir(parents=True, exist_ok=True)
        self._ensure_case_registered_for_staging(staging_path)

        # Auto-route disk images passed to extract_from_directory
        if source_path.is_file() and source_path.suffix.lower() in self.KNOWN_IMAGE_EXTS:
            return self.extract_from_image(
                image_path=source_path,
                staging_dir=staging_path,
                enable_vss=eff_vss,
                max_workers=eff_workers,
                progress_callback=progress_callback,
                selected_artifacts=selected_artifacts,
            )

        is_single_archive = source_path.is_file() and (
            source_path.suffix.lower() in self.ARCHIVE_EXTENSIONS
            or any(source_path.name.lower().endswith(ext) for ext in (".tar.gz", ".tar.bz2", ".tar.xz"))
        )

        if progress_callback:
            progress_callback(5, f"Scanning {'archive' if is_single_archive else 'directory'} {source_path.name}...")

        has_win_os = (not source_path.is_file()) and (source_path / "Windows" / "System32" / "config").is_dir()

        counts: Dict[str, int] = {
            "evtx": 0, "prefetch": 0, "lnk": 0, "jumplists": 0, "registry": 0,
            "mft": 0, "usnjrnl": 0, "srum": 0, "activities_cache": 0, "setupapi": 0,
            "browsers": 0, "chat": 0, "cloud": 0, "email": 0, "sqlite": 0,
            "recycle_bin": 0, "tasks": 0, "powershell": 0, "rmm": 0, "wer": 0,
            "wlan": 0, "sum": 0, "zone_identifier": 0, "enrichment": 0,
            "archives_unpacked": 0, "total_files": 0,
        }
        staged_files: List[str] = []
        errors: List[str] = []
        vfs_rows: List[Tuple[Any, ...]] = []
        state_lock = threading.Lock()
        claimed_staged_rels: Dict[str, Tuple[str, Any]] = {}
        total_source_bytes = 0

        # Add synthetic root directory row (never stat() host temp archive file on single-archive mode)
        if is_single_archive:
            root_meta = ForensicMeta(vfs_path="/", part_index=0, fs_type="ARCHIVE", is_dir=True, size_bytes=0)
        else:
            root_meta = self._stat_to_forensic_meta(
                source_path,
                vfs_path="/",
                fs_type="FOLDER",
                st_override=_lookup_initial_stat(source_path),
            )
            root_meta.is_dir = True
            root_meta.size_bytes = 0
        vfs_rows.append(self._build_vfs_row(0, "/", None, root_meta))

        # (f_path, archive_parent, root_ctx, vfs_path, precomputed_meta)
        candidate_tasks: List[Tuple[Path, Optional[str], Path, str, Optional[ForensicMeta]]] = []

        # 1. Unpack single/nested archives up to MAX_NESTED_ARCHIVE_DEPTH=3 (preserving archive member timestamps)
        if unpack_archives:
            def _is_arc_name(fn_low: str) -> bool:
                return any(fn_low.endswith(ext) for ext in self.ARCHIVE_EXTENSIONS) or fn_low.endswith(
                    (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")
                )

            # Queue items: (arc_path, nested_vfs_container_or_none, depth, inherited_meta)
            arc_queue: List[Tuple[Path, Optional[str], int, Optional[ForensicMeta]]] = []
            if is_single_archive:
                arc_queue.append((source_path, None, 1, None))
            elif source_path.is_dir():
                for root, dirs, files in os.walk(source_path):
                    root_res = Path(root).resolve()
                    if root_res == staging_path or str(root_res).startswith(str(staging_path) + os.sep):
                        dirs[:] = []
                        continue
                    for fn in files:
                        fp = Path(root) / fn
                        if _is_arc_name(fn.lower()):
                            arc_queue.append((fp, None, 1, None))

            arc_seq = 0
            while arc_queue:
                arc, nested_vfs_cont, arc_depth, inherited_meta = arc_queue.pop(0)
                arc_idx = arc_seq
                arc_seq += 1
                try:
                    if inherited_meta is not None:
                        arc_meta = inherited_meta
                    else:
                        arc_meta = self._stat_to_forensic_meta(
                            arc,
                            fs_type="ARCHIVE" if is_single_archive else "FOLDER",
                            st_override=_lookup_initial_stat(arc),
                        )
                        total_source_bytes += arc_meta.size_bytes
                    arc_fallback = arc_meta.si_modified or arc_meta.si_created
                    if nested_vfs_cont is None and not is_single_archive:
                        try:
                            rel_arc = arc.resolve().relative_to(source_path).as_posix()
                        except ValueError:
                            rel_arc = arc.name
                        safe_arc_rel = _sanitize_rel_path(f"Enrichment/Part_0/{rel_arc}")
                        assigned_arc, _ = self._claim_staged_rels(
                            rels=[safe_arc_rel],
                            claimed_map=claimed_staged_rels,
                            claim_lock=state_lock,
                            source_key=("dir_arc", rel_arc),
                        )
                        if assigned_arc:
                            arc_dst = self._resolve_contained_dst(staging_path, assigned_arc[0])
                            if self._copy_file_safe(arc, arc_dst, overwrite=True, meta=arc_meta, root_guard=staging_path):
                                vfs_rows.append(self._build_vfs_row(0, f"/{rel_arc}", assigned_arc[0], arc_meta))
                                counts["enrichment"] += 1
                                counts["total_files"] += 1
                                staged_files.append(assigned_arc[0])
                        cont_vfs: Optional[str] = f"/{rel_arc}_extracted"
                    elif nested_vfs_cont is not None:
                        cont_vfs = nested_vfs_cont
                    else:
                        cont_vfs = None

                    arc_stem = re.sub(r"[^A-Za-z0-9_]+", "_", arc.stem).strip("_") or f"arc_{arc_idx}"
                    arc_out = staging_path / "Extracted_Archives" / f"{arc_stem}_{arc_idx}"
                    unpacked_items = self.unpack_archive_with_meta(
                        arc,
                        arc_out,
                        fallback_mtime=None if (is_single_archive and arc_depth == 1) else arc_fallback,
                    )
                    if inherited_meta is not None:
                        apply_forensic_utime(arc, inherited_meta)
                    if unpacked_items:
                        counts["archives_unpacked"] += 1
                        if cont_vfs is not None:
                            vfs_rows.append(
                                self._build_vfs_row(
                                    0,
                                    cont_vfs,
                                    None,
                                    ForensicMeta(
                                        vfs_path=cont_vfs,
                                        part_index=0,
                                        fs_type="ARCHIVE" if is_single_archive else "FOLDER",
                                        is_dir=True,
                                        si_modified=arc_fallback,
                                    ),
                                )
                            )
                    for extracted_f, m_meta in unpacked_items:
                        try:
                            rel_mem = extracted_f.resolve().relative_to(arc_out.resolve()).as_posix()
                        except ValueError:
                            rel_mem = extracted_f.name
                        mem_vfs = f"/{rel_mem}" if cont_vfs is None else f"{cont_vfs.rstrip('/')}/{rel_mem}"
                        arc_parent = None if cont_vfs is None else cont_vfs.lstrip("/")
                        m_meta.vfs_path = mem_vfs
                        m_meta.part_index = 0
                        m_meta.fs_type = "ARCHIVE" if is_single_archive else "FOLDER"
                        candidate_tasks.append((extracted_f, arc_parent, arc_out, mem_vfs, m_meta))
                        if arc_depth < 3 and _is_arc_name(extracted_f.name.lower()):
                            arc_queue.append((extracted_f, f"{mem_vfs}_extracted", arc_depth + 1, m_meta))
                except Exception as arc_err:
                    err_msg = f"Failed unpacking archive {arc}: {arc_err}"
                    self._log(err_msg, level="ERROR")
                    errors.append(err_msg)

        # 2. Walk regular files & directories in source_path
        if source_path.is_file() and not is_single_archive:
            candidate_tasks.append((source_path, None, source_path.parent, f"/{source_path.name}", None))
        elif source_path.is_dir():
            for root, dirs, files in os.walk(source_path):
                root_p = Path(root).resolve()
                if root_p == staging_path or str(root_p).startswith(str(staging_path) + os.sep):
                    dirs[:] = []
                    continue
                for d_name in dirs:
                    dp = root_p / d_name
                    if str(dp) == str(staging_path):
                        continue
                    try:
                        d_rel = dp.relative_to(source_path).as_posix()
                    except ValueError:
                        continue
                    d_meta = self._stat_to_forensic_meta(
                        dp,
                        vfs_path=f"/{d_rel}",
                        fs_type="FOLDER",
                        st_override=_lookup_initial_stat(dp),
                    )
                    d_meta.is_dir = True
                    d_meta.size_bytes = 0
                    vfs_rows.append(self._build_vfs_row(0, f"/{d_rel}", None, d_meta))

                for f_name in files:
                    fp = root_p / f_name
                    fn_low = f_name.lower()
                    if unpack_archives and (fp.suffix.lower() in self.ARCHIVE_EXTENSIONS or fn_low.endswith((".tar.gz", ".tar.bz2", ".tar.xz"))):
                        continue
                    try:
                        f_rel = fp.relative_to(source_path).as_posix()
                    except ValueError:
                        f_rel = f_name
                    candidate_tasks.append((fp, None, source_path, f"/{f_rel}", None))

        def _worker_stage_host(item: Tuple[Path, Optional[str], Path, str, Optional[ForensicMeta]]) -> None:
            fp, arc_parent, r_ctx, v_path, pre_meta = item
            f_meta: Optional[ForensicMeta] = pre_meta
            try:
                f_meta = pre_meta if pre_meta is not None else self._stat_to_forensic_meta(
                    fp,
                    vfs_path=v_path,
                    part_index=0,
                    fs_type="ARCHIVE" if is_single_archive else "FOLDER",
                    st_override=_lookup_initial_stat(fp),
                )
                cat, rels = self._stage_host_file_with_rels(
                    file_path=fp,
                    staging_dir=staging_path,
                    archive_parent=arc_parent,
                    source_root=r_ctx,
                    has_windows_os=has_win_os,
                    meta_override=f_meta,
                    claimed_map=claimed_staged_rels,
                    claim_lock=state_lock,
                    source_key=("dir_file", v_path, str(fp)),
                    copy_sqlite_siblings=False,
                )
                primary_rel = rels[0] if rels else None
                row = self._build_vfs_row(0, v_path, primary_rel, f_meta)
                with state_lock:
                    nonlocal total_source_bytes
                    total_source_bytes += f_meta.size_bytes
                    vfs_rows.append(row)
                    if cat and rels:
                        counts[cat] = counts.get(cat, 0) + 1
                        counts["total_files"] += 1
                        staged_files.extend(rels)
            except Exception as p_err:
                self._log(f"Error processing file {fp}: {p_err}", level="WARNING")
                with state_lock:
                    errors.append(f"Error processing file {fp}: {p_err}")
            finally:
                if pre_meta is not None and fp.is_file():
                    apply_forensic_utime(fp, f_meta)

        if eff_workers <= 1 or len(candidate_tasks) <= 2:
            for t_item in candidate_tasks:
                _worker_stage_host(t_item)
        else:
            with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                futs = [pool.submit(_worker_stage_host, t_item) for t_item in candidate_tasks]
                for fut in as_completed(futs):
                    fut.result()

        part_fs_type = "ARCHIVE" if is_single_archive else "FOLDER"
        part_rows = [
            (0, source_path.name or "Folder_0", part_fs_type, 0, int(total_source_bytes), "", False)
        ]
        self._persist_vfs_tables(part_rows, vfs_rows, [])

        if progress_callback:
            progress_callback(100, f"Staged {counts['total_files']} files from {source_path.name}")

        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "SUCCESS" if counts["total_files"] > 0 else "WARNING",
            "mode": "archive" if is_single_archive else "directory",
            "source_dir": str(source_path),
            "staging_dir": str(staging_path),
            "total_files_staged": counts["total_files"],
            "duration_ms": duration_ms,
            "counts": counts,
            "staged_files": staged_files,
            "errors": errors,
        }

    def extract_from_folder(
        self,
        source_dir: Union[str, Path],
        staging_dir: Optional[Union[str, Path]] = None,
        unpack_archives: bool = True,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Contract 2 alias delegating to extract_from_directory."""
        return self.extract_from_directory(
            source_dir=source_dir,
            staging_dir=staging_dir,
            unpack_archives=unpack_archives,
            enable_vss=enable_vss,
            max_workers=max_workers,
            progress_callback=progress_callback,
            selected_artifacts=selected_artifacts,
        )

    # =========================================================================
    # MODE 2: Live Host Triage + Safe Differential Live VSS (F8, F27, F28)
    # =========================================================================

    @staticmethod
    def _compute_file_sha256(path_obj: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path_obj, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _collect_live_vss_differential(
        self,
        staging_path: Path,
        snapshots: List[Dict[str, Any]],
        active_index: Dict[Tuple[int, str], _ActiveFileMeta],
        vfs_rows: List[Tuple[Any, ...]],
        vss_rows: List[Tuple[Any, ...]],
        eff_workers: int,
    ) -> int:
        """
        Differentially stage accessible live Windows shadow copy paths (\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*)
        into staging/VSS/VSS_<idx>/..., skipping files unchanged from active_index.
        """
        total_vss_staged = 0
        seen_vss_hashes: Set[Tuple[int, str, str]] = set()
        vss_claimed_rels: Dict[str, Tuple[str, Any]] = {}
        state_lock = threading.Lock()

        for idx0, snap in enumerate(snapshots):
            vss_idx = idx0 + 1
            dev_root = str(snap["device_path"]).rstrip("\\")
            store_id = str(snap.get("store_id") or f"live_vss_{vss_idx}")
            ctime = snap.get("creation_time")
            staged_prefix = f"VSS/VSS_{vss_idx}"

            # Check accessibility of shadow root
            win_probe = Path(f"{dev_root}\\Windows")
            root_probe = Path(f"{dev_root}\\")
            try:
                if not root_probe.exists() and not win_probe.exists():
                    vss_rows.append((vss_idx, 0, store_id, ctime, 0, staged_prefix, 0, "permission_denied"))
                    continue
                _ = list(os.scandir(str(root_probe)))
            except PermissionError:
                vss_rows.append((vss_idx, 0, store_id, ctime, 0, staged_prefix, 0, "permission_denied"))
                continue
            except OSError:
                vss_rows.append((vss_idx, 0, store_id, ctime, 0, staged_prefix, 0, "unavailable"))
                continue

            has_win = (root_probe / "Windows" / "System32" / "config").exists()
            scan_subtrees = (
                [
                    "Windows/System32/config",
                    "Windows/System32/winevt/Logs",
                    "Windows/System32/sru",
                    "Windows/System32/Tasks",
                    "Windows/AppCompat/Programs",
                    "Windows/Prefetch",
                    "ProgramData/Microsoft/Windows/WER",
                    "ProgramData/Microsoft/Wlansvc/Profiles/Interfaces",
                    "Users",
                    "$Recycle.Bin",
                ]
                if has_win
                else [""]
            )

            cand_files: List[Tuple[Path, str]] = []
            for sub in scan_subtrees:
                sub_p = (root_probe / Path(sub)) if sub else root_probe
                try:
                    if not sub_p.exists():
                        continue
                except OSError:
                    continue
                for r_str, d_names, f_names in os.walk(str(sub_p)):
                    low_r = r_str.lower().replace("\\", "/")
                    if any(
                        skip_d in low_r
                        for skip_d in ("/windows/winsxs", "/appdata/local/packages/", "/appdata/local/google/chrome/application")
                    ):
                        d_names[:] = []
                        continue
                    for fn in f_names:
                        fp = Path(r_str) / fn
                        rel_from_dev = str(fp)[len(str(root_probe).rstrip("\\")) :].replace("\\", "/").lstrip("/")
                        cand_files.append((fp, f"/{rel_from_dev}"))

            files_staged_this_vss = 0
            bytes_this_vss = 0

            # Synthetic VSS root row
            vfs_rows.append(
                self._build_vfs_row(
                    -vss_idx,
                    f"/VSS_{vss_idx}",
                    None,
                    ForensicMeta(vfs_path=f"/VSS_{vss_idx}", part_index=-vss_idx, fs_type="LIVE_VSS", is_dir=True, si_created=ctime),
                )
            )

            def _stage_live_vss_item(pair: Tuple[Path, str]) -> None:
                nonlocal files_staged_this_vss, bytes_this_vss, total_vss_staged
                fp, norm_vfs = pair
                try:
                    v_meta = self._stat_to_forensic_meta(fp, vfs_path=norm_vfs, part_index=-vss_idx, fs_type="LIVE_VSS")
                    v_meta.vss_id = vss_idx
                except OSError:
                    return

                cat, route_rels = self._route_vfs_artifact(
                    vfs_path=norm_vfs,
                    size_bytes=v_meta.size_bytes,
                    part_index=0,
                    has_windows_os=has_win,
                    is_deleted=False,
                )
                if not route_rels:
                    return

                norm_key = (0, norm_vfs.lower())
                act_meta = active_index.get(norm_key)
                fname_low = fp.name.lower()
                v_mtime_us = _dt_to_us(v_meta.si_modified)
                v_sha: Optional[str] = None

                if act_meta is None:
                    v_meta.is_deleted = True
                elif v_meta.size_bytes != act_meta.size_bytes:
                    v_meta.is_deleted = False
                else:
                    if (
                        fname_low not in NORM_VSS_ALWAYS_HASH_NAMES
                        and v_mtime_us is not None
                        and act_meta.si_modified_us == v_mtime_us
                    ):
                        return
                    v_sha = self._compute_file_sha256(fp)
                    if v_sha is not None:
                        if act_meta.sha256 is None and act_meta.staged_path and act_meta.staged_path.exists():
                            act_meta.sha256 = self._compute_file_sha256(act_meta.staged_path)
                            if act_meta.forensic_meta is not None:
                                apply_forensic_utime(act_meta.staged_path, act_meta.forensic_meta)
                            elif act_meta.si_modified_us is not None:
                                dt_act = EPOCH_1970_NAIVE + timedelta(microseconds=act_meta.si_modified_us)
                                apply_forensic_utime(
                                    act_meta.staged_path,
                                    ForensicMeta(vfs_path="", si_modified=dt_act, si_accessed=dt_act),
                                )
                            else:
                                apply_forensic_utime(act_meta.staged_path, None)
                        if act_meta.sha256 and v_sha == act_meta.sha256:
                            return
                    v_meta.is_deleted = False

                if v_sha is None:
                    v_sha = self._compute_file_sha256(fp)
                if v_sha is not None:
                    with state_lock:
                        h_key = (0, norm_vfs.lower(), v_sha)
                        if h_key in seen_vss_hashes:
                            return
                        seen_vss_hashes.add(h_key)

                vss_rel_raw = f"{staged_prefix}/{route_rels[0]}"
                assigned_vss_rels, _ = self._claim_staged_rels(
                    rels=[vss_rel_raw],
                    claimed_map=vss_claimed_rels,
                    claim_lock=state_lock,
                    source_key=("live_vss", vss_idx, norm_vfs.lower()),
                    is_deleted=v_meta.is_deleted,
                )
                if not assigned_vss_rels:
                    return
                vss_rel_dst = assigned_vss_rels[0]
                dst_p = self._resolve_contained_dst(staging_path, vss_rel_dst)
                if self._copy_file_safe(fp, dst_p, overwrite=True, meta=v_meta, root_guard=staging_path):
                    vss_vfs_path = f"/VSS_{vss_idx}{norm_vfs}"
                    row = self._build_vfs_row(-vss_idx, vss_vfs_path, vss_rel_dst, v_meta)
                    with state_lock:
                        vfs_rows.append(row)
                        files_staged_this_vss += 1
                        total_vss_staged += 1
                        bytes_this_vss += v_meta.size_bytes

            if eff_workers <= 1 or len(cand_files) <= 2:
                for item in cand_files:
                    _stage_live_vss_item(item)
            else:
                with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                    futs = [pool.submit(_stage_live_vss_item, item) for item in cand_files]
                    for fut in as_completed(futs):
                        fut.result()

            status_str = "staged" if files_staged_this_vss > 0 else "no_changes"
            vss_rows.append((vss_idx, 0, store_id, ctime, bytes_this_vss, staged_prefix, files_staged_this_vss, status_str))

        return total_vss_staged

    def collect_live_triage(
        self,
        staging_dir: Optional[Union[str, Path]] = None,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Collect accessible live Windows host forensic artifacts preserving MACB timestamps
        and Contract 2 layout, optionally staging differential live Volume Shadow Copies when enable_vss=True.
        Never executes 'wmic shadowcopy call create'.
        """
        start_time = time.time()
        eff_workers = self._resolve_workers(max_workers)
        eff_vss = self._resolve_vss(enable_vss, selected_artifacts)

        staging_path = Path(staging_dir).resolve() if staging_dir else self.staging_dir
        staging_path.mkdir(parents=True, exist_ok=True)
        self._ensure_case_registered_for_staging(staging_path)

        counts: Dict[str, int] = {
            "evtx": 0, "prefetch": 0, "lnk": 0, "jumplists": 0, "registry": 0,
            "mft": 0, "usnjrnl": 0, "srum": 0, "activities_cache": 0, "setupapi": 0,
            "browsers": 0, "chat": 0, "cloud": 0, "email": 0, "sqlite": 0,
            "recycle_bin": 0, "tasks": 0, "powershell": 0, "rmm": 0, "wer": 0,
            "wlan": 0, "sum": 0, "zone_identifier": 0, "enrichment": 0,
            "vss_files": 0, "total_files": 0,
        }
        staged_files: List[str] = []
        errors: List[str] = []
        vfs_rows: List[Tuple[Any, ...]] = []
        vss_rows: List[Tuple[Any, ...]] = []
        active_index: Dict[Tuple[int, str], _ActiveFileMeta] = {}
        live_claimed_rels: Dict[str, Tuple[str, Any]] = {}
        total_live_bytes = 0

        # Safe non-mutating VSS snapshot discovery (timeout=5)
        live_snapshots, vss_disc_status = self._discover_live_vss_snapshots()
        vss_roots = [s["device_path"] for s in live_snapshots]

        vfs_rows.append(
            self._build_vfs_row(0, "/", None, ForensicMeta(vfs_path="/", part_index=0, fs_type="LIVE", is_dir=True))
        )

        def _record_live_staged(
            src_p: Path,
            dst_p: Path,
            cat_key: str,
            vfs_rel: Optional[str] = None,
            src_meta: Optional[ForensicMeta] = None,
        ) -> None:
            nonlocal total_live_bytes
            if not dst_p.exists():
                return
            eff_vfs = vfs_rel or ("/" + str(src_p).split(":", 1)[-1].replace("\\", "/").lstrip("/"))
            if src_meta is not None:
                meta = src_meta
            elif src_p.exists():
                meta = self._stat_to_forensic_meta(src_p, vfs_path=eff_vfs, part_index=0, fs_type="LIVE")
            else:
                meta = ForensicMeta(
                    vfs_path=eff_vfs,
                    part_index=0,
                    fs_type="LIVE",
                    size_bytes=int(dst_p.stat().st_size),
                )
            rel_st = dst_p.relative_to(staging_path).as_posix()
            live_claimed_rels[rel_st.lower()] = (rel_st, ("live_sys", eff_vfs.lower()))
            vfs_rows.append(self._build_vfs_row(0, eff_vfs, rel_st, meta))
            active_index[(0, eff_vfs.lower())] = _ActiveFileMeta(
                size_bytes=meta.size_bytes,
                si_modified_us=_dt_to_us(meta.si_modified),
                staged_path=dst_p,
                forensic_meta=meta,
            )
            counts[cat_key] = counts.get(cat_key, 0) + 1
            counts["total_files"] += 1
            total_live_bytes += meta.size_bytes
            staged_files.append(rel_st)

        # 0. Live $MFT and $J
        mft_ok, usn_ok = self._extract_live_ntfs(staging_path, vss_roots)
        if mft_ok:
            _record_live_staged(Path(r"C:\$MFT"), staging_path / "FileSystem" / "$MFT", "mft", "/$MFT")
        if usn_ok:
            _record_live_staged(Path(r"C:\$Extend\$UsnJrnl:$J"), staging_path / "FileSystem" / "$J", "usnjrnl", "/$Extend/$UsnJrnl:$J")

        # 1. Event Logs
        winevt_dir = Path(r"C:\Windows\System32\winevt\Logs")
        logs_dir = staging_path / "Logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        if winevt_dir.is_dir():
            for evtx_f in winevt_dir.glob("*.evtx"):
                dst_ev = logs_dir / evtx_f.name
                if self._copy_file_safe(evtx_f, dst_ev):
                    _record_live_staged(evtx_f, dst_ev, "evtx")

        # 2. System Registry Hives & Amcache (Contract 2 layout: Registry/System/* and Registry/Amcache/*)
        sys_reg_dir = staging_path / "Registry" / "System"
        sys_reg_dir.mkdir(parents=True, exist_ok=True)
        config_dir = Path(r"C:\Windows\System32\config")
        for h_name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
            src_h = config_dir / h_name
            dst_h = sys_reg_dir / h_name
            copied = self._copy_file_safe(src_h, dst_h) if src_h.exists() else False
            if not copied and h_name in ("SYSTEM", "SOFTWARE"):
                try:
                    proc = self._execute_cmd(f"reg_save:{h_name}", ["reg", "save", f"HKLM\\{h_name}", str(dst_h), "/y"], timeout=20)
                    if dst_h.exists() and dst_h.stat().st_size > 0:
                        self._clear_file_attributes(dst_h)
                        if src_h.exists():
                            apply_forensic_utime(dst_h, self._stat_to_forensic_meta(src_h, fs_type="LIVE"))
                        copied = True
                    elif dst_h.exists():
                        dst_h.unlink(missing_ok=True)
                except Exception:
                    pass
            if copied:
                _record_live_staged(src_h, dst_h, "registry")
            for log_sfx in (".LOG", ".LOG1", ".LOG2"):
                src_l = config_dir / f"{h_name}{log_sfx}"
                dst_l = sys_reg_dir / src_l.name
                if src_l.exists() and self._copy_file_safe(src_l, dst_l):
                    _record_live_staged(src_l, dst_l, "registry")

        amcache_src = Path(r"C:\Windows\AppCompat\Programs\Amcache.hve")
        amcache_dir = staging_path / "Registry" / "Amcache"
        amcache_dir.mkdir(parents=True, exist_ok=True)
        dst_am = amcache_dir / "Amcache.hve"
        if (amcache_src.exists() and self._copy_file_safe(amcache_src, dst_am)) or self._copy_locked_system_file(amcache_src, dst_am, vss_roots=vss_roots):
            _record_live_staged(amcache_src, dst_am, "registry")
            try:
                for am_log in amcache_src.parent.glob("Amcache.hve.LOG*"):
                    dst_aml = amcache_dir / am_log.name
                    if self._copy_file_safe(am_log, dst_aml):
                        _record_live_staged(am_log, dst_aml, "registry")
            except OSError:
                pass

        # 3. Walk targeted OS + User forensic paths via Contract 2 router in parallel
        c_root = Path("C:\\")
        live_candidates: List[Path] = []
        for sys_sub in (
            r"C:\Windows\Prefetch",
            r"C:\Windows\inf",
            r"C:\Windows\System32\sru",
            r"C:\Windows\System32\Tasks",
            r"C:\Windows\System32\LogFiles\SUM",
            r"C:\ProgramData\Microsoft\Windows\WER",
            r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces",
        ):
            sp = Path(sys_sub)
            try:
                if sp.exists():
                    for r_s, _, f_ns in os.walk(sp):
                        for fn in f_ns:
                            live_candidates.append(Path(r_s) / fn)
            except OSError:
                pass

        users_root = Path(r"C:\Users")
        current_username = os.environ.get("USERNAME", "").lower()
        if users_root.exists():
            for user_dir in users_root.iterdir():
                try:
                    if not user_dir.is_dir() or user_dir.name.lower() in ("public", "all users", "default user"):
                        continue
                except OSError:
                    continue
                uname_safe = _sanitize_win32_segment(user_dir.name) or "Default"
                u_reg_dir = self._resolve_contained_dst(staging_path, f"Registry/Users/{uname_safe}")
                u_reg_dir.mkdir(parents=True, exist_ok=True)
                # NTUSER.DAT & UsrClass.dat + .LOG/.LOG1/.LOG2 transaction logs (ZERO flat copies!)
                nt_src = user_dir / "NTUSER.DAT"
                nt_dst = u_reg_dir / "NTUSER.DAT"
                nt_ok = self._copy_file_safe(nt_src, nt_dst, root_guard=staging_path)
                if not nt_ok and user_dir.name.lower() == current_username:
                    try:
                        self._execute_cmd(f"reg_save:HKCU:{uname_safe}", ["reg", "save", "HKCU", str(nt_dst), "/y"], timeout=20)
                        if nt_dst.exists() and nt_dst.stat().st_size > 0:
                            self._clear_file_attributes(nt_dst)
                            if nt_src.exists():
                                apply_forensic_utime(nt_dst, self._stat_to_forensic_meta(nt_src, fs_type="LIVE"))
                            nt_ok = True
                    except Exception:
                        pass
                if not nt_ok:
                    nt_ok = self._copy_locked_system_file(nt_src, nt_dst, vss_roots=vss_roots)
                if nt_ok:
                    _record_live_staged(nt_src, nt_dst, "registry")
                try:
                    for nt_sib in user_dir.glob("NTUSER.DAT*"):
                        sib_low = nt_sib.name.lower()
                        if sib_low != "ntuser.dat" and _is_reg_hive_suffix_valid(sib_low, "ntuser.dat"):
                            dst_ntl = u_reg_dir / _sanitize_win32_segment(nt_sib.name)
                            if self._copy_file_safe(nt_sib, dst_ntl, root_guard=staging_path) or self._copy_locked_system_file(
                                nt_sib, dst_ntl, vss_roots=vss_roots
                            ):
                                _record_live_staged(nt_sib, dst_ntl, "registry")
                except OSError:
                    pass

                uc_src = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
                uc_dst = u_reg_dir / "UsrClass.dat"
                uc_ok = self._copy_file_safe(uc_src, uc_dst, root_guard=staging_path)
                if not uc_ok and user_dir.name.lower() == current_username:
                    try:
                        self._execute_cmd(f"reg_save:Classes:{uname_safe}", ["reg", "save", "HKCU\\Software\\Classes", str(uc_dst), "/y"], timeout=20)
                        if uc_dst.exists() and uc_dst.stat().st_size > 0:
                            self._clear_file_attributes(uc_dst)
                            if uc_src.exists():
                                apply_forensic_utime(uc_dst, self._stat_to_forensic_meta(uc_src, fs_type="LIVE"))
                            uc_ok = True
                    except Exception:
                        pass
                if not uc_ok:
                    uc_ok = self._copy_locked_system_file(uc_src, uc_dst, vss_roots=vss_roots)
                if uc_ok:
                    _record_live_staged(uc_src, uc_dst, "registry")
                try:
                    if uc_src.parent.exists():
                        for uc_sib in uc_src.parent.glob("UsrClass.dat*"):
                            sib_low = uc_sib.name.lower()
                            if sib_low != "usrclass.dat" and _is_reg_hive_suffix_valid(sib_low, "usrclass.dat"):
                                dst_ucl = u_reg_dir / _sanitize_win32_segment(uc_sib.name)
                                if self._copy_file_safe(uc_sib, dst_ucl, root_guard=staging_path) or self._copy_locked_system_file(
                                    uc_sib, dst_ucl, vss_roots=vss_roots
                                ):
                                    _record_live_staged(uc_sib, dst_ucl, "registry")
                except OSError:
                    pass

                for u_sub in (
                    "AppData/Local/Google/Chrome/User Data",
                    "AppData/Local/Microsoft/Edge/User Data",
                    "AppData/Local/BraveSoftware/Brave-Browser/User Data",
                    "AppData/Roaming/Mozilla/Firefox/Profiles",
                    "AppData/Local/ConnectedDevicesPlatform",
                    "AppData/Local/Microsoft/Windows/WER",
                    "AppData/Local/Microsoft/Windows/Notifications",
                    "AppData/Roaming/Microsoft/Windows/Recent",
                    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine",
                ):
                    up = user_dir / Path(u_sub)
                    try:
                        if up.exists():
                            for r_s, d_ns, f_ns in os.walk(up):
                                if "cache" in Path(r_s).name.lower():
                                    d_ns[:] = []
                                    continue
                                for fn in f_ns:
                                    live_candidates.append(Path(r_s) / fn)
                    except OSError:
                        pass

        state_lock = threading.Lock()

        def _stage_live_cand(fp: Path) -> None:
            nonlocal total_live_bytes
            try:
                rel_p = fp.resolve().relative_to(c_root).as_posix()
            except Exception:
                rel_p = str(fp).split(":", 1)[-1].replace("\\", "/").lstrip("/")
            v_path = f"/{rel_p}"
            f_meta = self._stat_to_forensic_meta(fp, vfs_path=v_path, part_index=0, fs_type="LIVE")
            cat, route_rels = self._route_vfs_artifact(
                vfs_path=v_path,
                size_bytes=f_meta.size_bytes,
                part_index=0,
                has_windows_os=True,
                is_deleted=False,
            )
            if not cat or not route_rels or cat == "enrichment":
                return
            assigned_live, _ = self._claim_staged_rels(
                rels=[route_rels[0]],
                claimed_map=live_claimed_rels,
                claim_lock=state_lock,
                source_key=("live_cand", v_path.lower()),
            )
            if not assigned_live:
                return
            rel_live_dst = assigned_live[0]
            dst_p = self._resolve_contained_dst(staging_path, rel_live_dst)
            if self._copy_file_safe(fp, dst_p, overwrite=True, meta=f_meta, root_guard=staging_path):
                row = self._build_vfs_row(0, v_path, rel_live_dst, f_meta)
                with state_lock:
                    vfs_rows.append(row)
                    active_index[(0, v_path.lower())] = _ActiveFileMeta(
                        size_bytes=f_meta.size_bytes,
                        si_modified_us=_dt_to_us(f_meta.si_modified),
                        staged_path=dst_p,
                        forensic_meta=f_meta,
                    )
                    counts[cat] = counts.get(cat, 0) + 1
                    counts["total_files"] += 1
                    total_live_bytes += f_meta.size_bytes
                    staged_files.append(rel_live_dst)

        if eff_workers <= 1 or len(live_candidates) <= 2:
            for lc in live_candidates:
                _stage_live_cand(lc)
        else:
            with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                futs = [pool.submit(_stage_live_cand, lc) for lc in live_candidates]
                for fut in as_completed(futs):
                    fut.result()

        # 4. Optional Differential Live VSS Collection
        vss_status_out = "disabled"
        if eff_vss:
            if live_snapshots:
                staged_vss_cnt = self._collect_live_vss_differential(
                    staging_path=staging_path,
                    snapshots=live_snapshots,
                    active_index=active_index,
                    vfs_rows=vfs_rows,
                    vss_rows=vss_rows,
                    eff_workers=eff_workers,
                )
                counts["vss_files"] = staged_vss_cnt
                counts["total_files"] += staged_vss_cnt
                vss_status_out = "staged" if staged_vss_cnt > 0 else "no_changes"
            else:
                vss_status_out = vss_disc_status  # "permission_denied" or "none" (0 fabricated rows!)

        part_rows = [(0, "C:", "LIVE", 0, int(total_live_bytes), "", True)]
        self._persist_vfs_tables(part_rows, vfs_rows, vss_rows)

        if progress_callback:
            progress_callback(100, f"Live triage completed ({counts['total_files']} files staged)")

        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "SUCCESS" if counts["total_files"] > 0 else "WARNING",
            "mode": "live_triage",
            "staging_dir": str(staging_path),
            "total_files_staged": counts["total_files"],
            "vss_status": vss_status_out,
            "shadow_copies": len(vss_rows),
            "duration_ms": duration_ms,
            "counts": counts,
            "staged_files": staged_files,
            "errors": errors,
        }


    # =========================================================================
    # MODE 3: 3-Tier Multi-Partition / Multi-FS Image Engine + Offline VSS (F7, F8, F27, F28)
    # =========================================================================

    def _open_offline_vss_stores(
        self,
        part_index: int,
        part_fh: Any,
        source_read_lock: threading.Lock,
    ) -> Tuple[List[Tuple[str, Optional[datetime], int, Any]], Callable[[], None]]:
        """
        Enumerate offline NTFS Volume Shadow Copies on a partition stream using:
          1. Primary: pyvshadow (check_volume_signature_file_object + open_file_object + has_in_volume_data)
          2. Fallback: dissect.volume.vss.VSS (dvss.catalog.stores)
        Treats non-VSS OSError, 'Not a valid VSS identifier', 'Catalog offset is 0', and 0-store
        volumes cleanly as 0 snapshots without failing extraction.
        Returns (list of (store_id, creation_time, size_bytes, store_stream), cleanup_fn).
        """
        stores_out: List[Tuple[str, Optional[datetime], int, Any]] = []

        # 1. Primary: pyvshadow
        if pyvshadow is not None:
            vss_vol = None
            try:
                with source_read_lock:
                    part_fh.seek(0)
                    has_sig = bool(pyvshadow.check_volume_signature_file_object(part_fh))
                if not has_sig:
                    return [], lambda: None
                vss_vol = pyvshadow.volume()
                with source_read_lock:
                    part_fh.seek(0)
                    vss_vol.open_file_object(part_fh)
                raw_n = getattr(vss_vol, "number_of_stores", None)
                if raw_n is None and hasattr(vss_vol, "get_number_of_stores"):
                    raw_n = vss_vol.get_number_of_stores()
                n_stores = int(raw_n or 0)
                if n_stores == 0:
                    vss_vol.close()
                    return [], lambda: None
                for s_i in range(n_stores):
                    with source_read_lock:
                        st = vss_vol.get_store(s_i)
                        if not st.has_in_volume_data():
                            continue
                        raw_ct = st.get_creation_time()
                        ct_utc = _normalize_utc_naive(raw_ct)
                        s_id = str(
                            getattr(st, "identifier", None)
                            or getattr(st, "copy_identifier", None)
                            or f"part{part_index}_store{s_i}"
                        )
                        s_sz = int(getattr(st, "size", 0) or getattr(st, "volume_size", 0) or 0)
                    stores_out.append((s_id, ct_utc, s_sz, st))

                if not stores_out:
                    vss_vol.close()
                    return [], lambda: None

                def _close_pyvshadow() -> None:
                    if vss_vol is not None:
                        try:
                            vss_vol.close()
                        except Exception:
                            pass

                return stores_out, _close_pyvshadow
            except (OSError, IOError, Exception) as exc:
                self._log(f"Notice: Partition {part_index} pyvshadow open failed, trying DissectVSS fallback ({exc})", level="INFO")
                if vss_vol is not None:
                    try:
                        vss_vol.close()
                    except Exception:
                        pass

        # 2. Secondary Fallback: dissect.volume.vss.VSS (when pyvshadow is unavailable)
        if _dvss_mod is not None:
            try:
                with source_read_lock:
                    part_fh.seek(0)
                    dvss = _dvss_mod.VSS(part_fh)
                    cat_stores = list(getattr(getattr(dvss, "catalog", None), "stores", []) or [])
                for s_i, dst in enumerate(cat_stores):
                    try:
                        desc2 = getattr(dst, "desc2", None)
                        if desc2 is not None and getattr(desc2, "store_identifier", None):
                            s_id = str(uuid.UUID(bytes_le=desc2.store_identifier))
                        else:
                            raw_uuid = getattr(dst, "identifier", None) or getattr(dst, "copy_identifier", None)
                            s_id = str(raw_uuid) if raw_uuid else f"part{part_index}_store{s_i}"
                        ct_utc = _filetime_to_utc(getattr(dst, "creation_time", 0))
                        desc3 = getattr(dst, "desc3", None)
                        s_sz = int(
                            (getattr(desc3, "allocated_size", 0) if desc3 is not None else 0)
                            or getattr(dst, "volume_size", 0)
                            or getattr(dst, "size", 0)
                            or 0
                        )
                        with source_read_lock:
                            st_stream = dst.open()
                        stores_out.append((s_id, ct_utc, s_sz, st_stream))
                    except Exception:
                        continue
            except Exception as dvss_exc:
                msg = str(dvss_exc)
                if "Not a valid VSS identifier" not in msg and "Catalog offset is 0" not in msg:
                    self._log(f"Notice: DissectVSS skip on partition {part_index}: {dvss_exc}", level="INFO")
                return [], lambda: None

        return stores_out, lambda: None

    def _extract_offline_vss_for_partition(
        self,
        part_index: int,
        part_fh: Any,
        staging_p: Path,
        active_index: Dict[Tuple[int, str], _ActiveFileMeta],
        seen_vss_hashes: Set[Tuple[int, str, str]],
        next_vss_index: int,
        vfs_rows: List[Tuple[Any, ...]],
        vss_rows: List[Tuple[Any, ...]],
        source_read_lock: threading.Lock,
        eff_workers: int,
    ) -> Tuple[int, int]:
        """
        Mount each offline VSS store on partition `part_index` via NtfsFilesystem(store),
        walk strictly with entry.lstat() and skipping entry.is_symlink() (preventing FileNotFoundError: /C),
        differentially stage deleted/changed historical artifacts into staging/VSS/VSS_<idx>/...,
        and populate vfs_shadow_copies + negative-part_index vfs_files rows.
        Returns (updated_next_vss_index, total_vss_files_staged).
        """
        if NtfsFilesystem is None:
            return next_vss_index, 0

        stores, cleanup_fn = self._open_offline_vss_stores(part_index, part_fh, source_read_lock)
        total_staged = 0
        state_lock = threading.Lock()
        vss_claimed_rels: Dict[str, Tuple[str, Any]] = {}

        try:
            if not stores:
                return next_vss_index, 0
            for store_id, ctime, store_size, store_stream in stores:
                vss_idx = next_vss_index
                next_vss_index += 1
                staged_prefix = f"VSS/VSS_{vss_idx}"

                try:
                    with source_read_lock:
                        vss_fs = NtfsFilesystem(store_stream)
                except Exception as mnt_err:
                    self._log(f"Notice: Could not mount NTFS on VSS_{vss_idx} ({store_id}): {mnt_err}", level="WARNING")
                    vss_rows.append((vss_idx, part_index, store_id, ctime, store_size, staged_prefix, 0, "mount_error"))
                    continue

                has_win_vss = False
                try:
                    with source_read_lock:
                        cfg_e = vss_fs.path("/Windows/System32/config")
                        if cfg_e.exists() and not cfg_e.is_symlink():
                            has_win_vss = stat.S_ISDIR(cfg_e.lstat().st_mode)
                except Exception:
                    has_win_vss = False

                # Synthetic root row for /VSS_<vss_idx>
                vfs_rows.append(
                    self._build_vfs_row(
                        -vss_idx,
                        f"/VSS_{vss_idx}",
                        None,
                        ForensicMeta(
                            vfs_path=f"/VSS_{vss_idx}",
                            part_index=-vss_idx,
                            fs_type="NTFS_VSS",
                            vss_id=vss_idx,
                            is_dir=True,
                            si_created=ctime,
                        ),
                    )
                )

                vss_candidates: List[Tuple[Any, str, ForensicMeta, List[str]]] = []
                visited_mft: Set[int] = set()

                def _walk_vss_dir(dir_entry: Any, cur_vfs: str, depth: int) -> None:
                    if depth > 24:
                        return
                    try:
                        with source_read_lock:
                            children = list(dir_entry.iterdir())
                    except Exception:
                        return

                    for child in children:
                        try:
                            cname = child.name
                        except Exception:
                            continue
                        if not cname or cname in (".", ".."):
                            continue
                        cname_low = cname.lower()
                        if cur_vfs == "/" and cname_low in _NTFS_META_ROOT_NAMES:
                            continue

                        child_vfs = f"/{cname}" if cur_vfs == "/" else f"{cur_vfs}/{cname}"
                        child_low = child_vfs.lower()
                        # Always skip internal VSS store metadata under /System Volume Information
                        if child_low == "/system volume information":
                            continue
                        # Prune unroutable OS binary subtrees during VSS walk
                        if has_win_vss:
                            if child_low in ("/msocache", "/recovery", "/efi", "/$extend", "/windows.old", "/config.msi"):
                                continue
                            if cur_vfs.lower() == "/programdata" and cname_low in (
                                "package cache", "uso", "usoshared", "windowsholographicdevices"
                            ):
                                continue
                            if child_low in (
                                "/programdata/microsoft/search",
                                "/programdata/microsoft/diagnosis",
                                "/programdata/microsoft/windows defender",
                                "/programdata/microsoft/netframework",
                            ):
                                continue
                            if cname_low in (
                                "code cache", "gpucache", "shadercache", "grshadercache",
                                "dawnwebgpucache", "cryptneturlcache",
                                "jumplisticons", "jumplisticonsold", "jumplisticonsmostvisited",
                            ):
                                continue
                            if child_low.startswith("/windows/"):
                                if depth == 1 and child_low not in (
                                    "/windows/system32",
                                    "/windows/inf",
                                    "/windows/prefetch",
                                    "/windows/tasks",
                                    "/windows/appcompat",
                                    "/windows/apppatch",
                                    "/windows/panther",
                                    "/windows/temp",
                                ) and cname_low != "setupapi.log":
                                    continue
                                if depth == 2 and cur_vfs.lower() == "/windows/system32" and child_low not in (
                                    "/windows/system32/config",
                                    "/windows/system32/winevt",
                                    "/windows/system32/sru",
                                    "/windows/system32/wbem",
                                    "/windows/system32/tasks",
                                    "/windows/system32/logfiles",
                                ):
                                    continue
                            elif depth == 1 and cur_vfs.lower() in ("/program files", "/program files (x86)"):
                                if not any(
                                    kw in cname_low
                                    for kw in (
                                        "anydesk", "teamviewer", "screenconnect", "connectwise",
                                        "splashtop", "rustdesk", "tomcat", "apache", "nginx",
                                        "xampp", "wamp", "inetpub",
                                    )
                                ):
                                    continue

                        try:
                            with source_read_lock:
                                if child.is_symlink():
                                    continue
                                st = child.lstat()
                                c_meta = extract_meta_dissect(child, child_vfs, -vss_idx, "NTFS", vss_id=vss_idx)
                        except Exception:
                            continue

                        c_is_dir = stat.S_ISDIR(st.st_mode)
                        c_is_reg = stat.S_ISREG(st.st_mode)
                        c_meta.is_dir = c_is_dir
                        if c_is_reg and c_meta.size_bytes == 0:
                            c_meta.size_bytes = int(getattr(st, "st_size", 0) or 0)

                        if c_meta.mft_entry is not None:
                            if c_is_dir and c_meta.mft_entry in visited_mft:
                                continue
                            if c_is_dir:
                                visited_mft.add(c_meta.mft_entry)

                        if c_is_dir:
                            _walk_vss_dir(child, child_vfs, depth + 1)
                        elif c_is_reg:
                            cat, route_rels = self._route_vfs_artifact(
                                vfs_path=child_vfs,
                                size_bytes=c_meta.size_bytes,
                                part_index=part_index,
                                has_windows_os=has_win_vss,
                                is_deleted=False,
                            )
                            if cat and route_rels:
                                vss_candidates.append((child, child_vfs, c_meta, route_rels))

                try:
                    with source_read_lock:
                        root_e = vss_fs.path("/")
                    _walk_vss_dir(root_e, "/", 0)
                except Exception as walk_err:
                    self._log(f"Notice walking VSS_{vss_idx}: {walk_err}", level="WARNING")

                files_staged_here = 0

                def _process_vss_candidate(cand: Tuple[Any, str, ForensicMeta, List[str]]) -> None:
                    nonlocal files_staged_here, total_staged
                    entry_obj, norm_vfs, v_meta, route_rels = cand
                    act_meta = active_index.get((part_index, norm_vfs.lower()))
                    fname_low = norm_vfs.rsplit("/", 1)[-1].lower()
                    v_mtime_us = _dt_to_us(v_meta.si_modified)

                    need_hash_check = False
                    if act_meta is None:
                        v_meta.is_deleted = True
                    elif v_meta.size_bytes != act_meta.size_bytes:
                        v_meta.is_deleted = False
                    else:
                        if (
                            fname_low not in NORM_VSS_ALWAYS_HASH_NAMES
                            and v_mtime_us is not None
                            and act_meta.si_modified_us == v_mtime_us
                        ):
                            return
                        need_hash_check = True
                        v_meta.is_deleted = False

                    if v_meta.size_bytes > 256 * 1024 * 1024:
                        return

                    # Read bytes safely under source_read_lock
                    try:
                        with source_read_lock:
                            with entry_obj.open() as in_f:
                                data = in_f.read(v_meta.size_bytes) if v_meta.size_bytes > 0 else b""
                    except Exception:
                        return

                    v_sha = hashlib.sha256(data).hexdigest()
                    if need_hash_check and act_meta is not None:
                        if act_meta.sha256 is None and act_meta.staged_path and act_meta.staged_path.exists():
                            act_meta.sha256 = self._compute_file_sha256(act_meta.staged_path)
                            if act_meta.forensic_meta is not None:
                                apply_forensic_utime(act_meta.staged_path, act_meta.forensic_meta)
                            elif act_meta.si_modified_us is not None:
                                dt_act = EPOCH_1970_NAIVE + timedelta(microseconds=act_meta.si_modified_us)
                                apply_forensic_utime(
                                    act_meta.staged_path,
                                    ForensicMeta(vfs_path="", si_modified=dt_act, si_accessed=dt_act),
                                )
                            else:
                                apply_forensic_utime(act_meta.staged_path, None)
                        if act_meta.sha256 and v_sha == act_meta.sha256:
                            return

                    with state_lock:
                        cross_key = (part_index, norm_vfs.lower(), v_sha)
                        if cross_key in seen_vss_hashes:
                            return
                        seen_vss_hashes.add(cross_key)

                    vss_rel_raw = f"{staged_prefix}/{route_rels[0]}"
                    assigned_vss_rels, _ = self._claim_staged_rels(
                        rels=[vss_rel_raw],
                        claimed_map=vss_claimed_rels,
                        claim_lock=state_lock,
                        source_key=("offline_vss", vss_idx, v_meta.mft_entry, norm_vfs.lower()),
                        is_deleted=v_meta.is_deleted,
                        hint_id=v_meta.mft_entry,
                    )
                    if not assigned_vss_rels:
                        return
                    vss_rel_dst = assigned_vss_rels[0]
                    try:
                        dst_p = self._resolve_contained_dst(staging_p, vss_rel_dst)
                        if dst_p.exists():
                            self._clear_file_attributes(dst_p)
                        dst_p.parent.mkdir(parents=True, exist_ok=True)
                        with open(dst_p, "wb") as out_f:
                            out_f.write(data)
                        self._clear_file_attributes(dst_p)
                        apply_forensic_utime(dst_p, v_meta)
                    except Exception as vss_w_err:
                        self._log(f"VSS write notice on {norm_vfs} -> {vss_rel_dst}: {vss_w_err}", level="WARNING")
                        return

                    # Ancestor directory rows for /VSS_<vss_idx>/... are synthesized deterministically
                    # by _ensure_ancestor_dir_rows() prior to DuckDB persistence.
                    vss_vfs_path = f"/VSS_{vss_idx}{norm_vfs}"
                    row = self._build_vfs_row(-vss_idx, vss_vfs_path, vss_rel_dst, v_meta)
                    with state_lock:
                        vfs_rows.append(row)
                        files_staged_here += 1
                        total_staged += 1

                if eff_workers <= 1 or len(vss_candidates) <= 2:
                    for c_item in vss_candidates:
                        _process_vss_candidate(c_item)
                else:
                    with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                        futs = [pool.submit(_process_vss_candidate, c_item) for c_item in vss_candidates]
                        for fut in as_completed(futs):
                            fut.result()

                st_label = "staged" if files_staged_here > 0 else "no_changes"
                vss_rows.append((vss_idx, part_index, store_id, ctime, store_size, staged_prefix, files_staged_here, st_label))
        finally:
            cleanup_fn()

        return next_vss_index, total_staged

    def _unpack_staged_nested_archives(
        self,
        staging_p: Path,
        part_index: int,
        fs_type: str,
        staged_arc_records: List[Union[Tuple[Path, str], Tuple[Path, str, Optional[ForensicMeta]]]],
        vfs_rows: List[Tuple[Any, ...]],
        counts: Dict[str, int],
        staged_files: List[str],
    ) -> None:
        """
        Unpack nested archives (.zip/.7z/.tar*/.gz/.bz2/.xz/.rar) staged onto disk while
        preserving forensic member timestamps (falling back to parent archive mtime, NEVER
        re-reading host NTFS 2026 creation/copy timestamps via stat()).
        """
        def _is_nested_arc_name(fn_low: str) -> bool:
            return any(fn_low.endswith(ext) for ext in self.ARCHIVE_EXTENSIONS) or fn_low.endswith(
                (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")
            )

        current_batch: List[Union[Tuple[Path, str], Tuple[Path, str, Optional[ForensicMeta]]]] = list(staged_arc_records)
        for arc_depth in range(3):
            if not current_batch:
                break
            next_batch: List[Tuple[Path, str, Optional[ForensicMeta]]] = []
            for rec in current_batch:
                if len(rec) == 3:
                    arc_dst, arc_vfs_path, arc_meta = rec[0], rec[1], rec[2]
                else:
                    arc_dst, arc_vfs_path, arc_meta = rec[0], rec[1], None
                try:
                    if not arc_dst.is_file():
                        continue
                    sz = arc_dst.stat().st_size
                    if sz <= 0 or sz > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    fb_mtime = (
                        (arc_meta.si_modified or arc_meta.fn_modified or arc_meta.si_created or arc_meta.fn_created)
                        if arc_meta is not None
                        else None
                    )
                    extract_dir = self._resolve_contained_dst(
                        staging_p,
                        arc_dst.parent / _sanitize_win32_segment(f"{arc_dst.name}_extracted"),
                    )
                    unpacked_items = self.unpack_archive_with_meta(arc_dst, extract_dir, fallback_mtime=fb_mtime)
                    apply_forensic_utime(arc_dst, arc_meta)
                    if not unpacked_items:
                        continue
                    counts["archives_unpacked"] = counts.get("archives_unpacked", 0) + 1
                    container_vfs = f"{arc_vfs_path.rstrip('/')}_extracted"
                    vfs_rows.append(
                        self._build_vfs_row(
                            part_index,
                            container_vfs,
                            None,
                            ForensicMeta(
                                vfs_path=container_vfs,
                                part_index=part_index,
                                fs_type=fs_type,
                                is_dir=True,
                                si_modified=fb_mtime,
                            ),
                        )
                    )
                    for uf, m_meta in unpacked_items:
                        try:
                            rel_mem = uf.resolve().relative_to(extract_dir.resolve()).as_posix()
                            rel_staged = uf.resolve().relative_to(staging_p.resolve()).as_posix()
                        except ValueError:
                            continue
                        mem_vfs = f"{container_vfs}/{rel_mem}"
                        m_meta.vfs_path = mem_vfs
                        m_meta.part_index = part_index
                        m_meta.fs_type = fs_type
                        vfs_rows.append(self._build_vfs_row(part_index, mem_vfs, rel_staged, m_meta))
                        counts["enrichment"] = counts.get("enrichment", 0) + 1
                        counts["total_files"] += 1
                        staged_files.append(rel_staged)
                        if arc_depth < 2 and _is_nested_arc_name(uf.name.lower()):
                            next_batch.append((uf, mem_vfs, m_meta))
                except Exception as ex:
                    self._log(f"Nested archive unpack notice on {arc_dst}: {ex}", level="INFO")
            current_batch = next_batch

    def extract_from_image(
        self,
        image_path: Union[str, Path],
        staging_dir: Optional[Union[str, Path]] = None,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        3-Tier Multi-Partition & Multi-Filesystem Forensic Disk Image Extractor:
          - Tier A: dissect NTFS across ALL NTFS partitions ($MFT/$J streaming + mft.segments() 8-timestamp index)
          - Tier B: pytsk3 + StreamImgInfo across FAT12/16/32, exFAT, ISO9660, EXT, NTFS (incl. /$OrphanFiles)
          - Tier C: Pure-Python ECMA-167 / OSTA UDF 1.02–2.60 + Type 2 VAT multi-session reader
          - Optional Offline VSS (pyvshadow primary + DissectVSS fallback) differential staging
          - Race-free source_read_lock + ThreadPoolExecutor(max_workers=eff_workers) sink
        Never invokes PowerShell Mount-DiskImage.
        """
        start_time = time.time()
        eff_workers = self._resolve_workers(max_workers)
        eff_vss = self._resolve_vss(enable_vss, selected_artifacts)

        clean_image_str = str(image_path).strip().strip('"').strip("'").strip()
        image_p = Path(clean_image_str).resolve()
        staging_p = Path(staging_dir).resolve() if staging_dir else self.staging_dir
        staging_p.mkdir(parents=True, exist_ok=True)
        self._ensure_case_registered_for_staging(staging_p)

        if not image_p.exists():
            raise FileNotFoundError(f"Source disk image does not exist: {image_p}")

        # Auto-detect directory containing forensic disk image(s)
        if image_p.is_dir():
            contained_images = [
                f for f in sorted(image_p.iterdir())
                if f.is_file() and f.suffix.lower() in self.KNOWN_IMAGE_EXTS
            ]
            e01_cands = [c for c in contained_images if c.suffix.lower() in (".e01", ".ex01")]
            chosen = e01_cands[0] if e01_cands else (contained_images[0] if contained_images else None)
            if chosen is not None:
                image_p = chosen
            else:
                return self.extract_from_directory(
                    source_dir=image_p,
                    staging_dir=staging_p,
                    unpack_archives=True,
                    enable_vss=eff_vss,
                    max_workers=eff_workers,
                    progress_callback=progress_callback,
                    selected_artifacts=selected_artifacts,
                )

        self._log(
            f"Starting forensic image extraction on {image_p.name} (enable_vss={eff_vss}, workers={eff_workers})"
        )
        if progress_callback:
            progress_callback(5, f"Opening forensic image {image_p.name}...")

        counts: Dict[str, int] = {
            "evtx": 0, "prefetch": 0, "lnk": 0, "jumplists": 0, "registry": 0,
            "mft": 0, "usnjrnl": 0, "srum": 0, "activities_cache": 0, "setupapi": 0,
            "browsers": 0, "chat": 0, "cloud": 0, "email": 0, "sqlite": 0,
            "recycle_bin": 0, "tasks": 0, "powershell": 0, "rmm": 0, "wer": 0,
            "wlan": 0, "sum": 0, "zone_identifier": 0, "enrichment": 0,
            "archives_unpacked": 0, "vss_files": 0, "total_files": 0,
        }
        staged_files: List[str] = []
        errors: List[str] = []
        partitions_rows: List[Tuple[Any, ...]] = []
        vfs_rows: List[Tuple[Any, ...]] = []
        vss_rows: List[Tuple[Any, ...]] = []
        active_index: Dict[Tuple[int, str], _ActiveFileMeta] = {}
        seen_vss_hashes: Set[Tuple[int, str, str]] = set()
        claimed_staged_rels: Dict[str, Tuple[str, Any]] = {}
        next_vss_idx = 1

        source_read_lock = threading.RLock()
        state_lock = threading.Lock()

        target = None
        disk_stream: Optional[Any] = None
        tsk_img: Optional[Any] = None
        owned_raw_fh: Optional[Any] = None
        owned_ewf_h: Optional[Any] = None
        part_map: Dict[int, Tuple[int, bool, Any]] = {}
        dissect_ntfs_by_off: Dict[int, Any] = {}

        try:
            # 1. Open container via dissect.target (supports .dd, .E01, .vmdk, .vhd, .vhdx, .qcow2, .iso)
            if dissect is not None:
                try:
                    target = dissect.target.Target.open(str(image_p))
                except Exception as dt_err:
                    self._log(f"dissect.target open notice on {image_p.name}: {dt_err}", level="INFO")

            # 2. Establish logical disk stream + total disk size for PartitionSubStream / StreamImgInfo / UDF
            disk_size: int = 0
            if target is not None and getattr(target, "disks", None):
                try:
                    d0 = target.disks[0]
                    if callable(getattr(d0, "read", None)) and callable(getattr(d0, "seek", None)):
                        disk_stream = d0
                    else:
                        cand_fh = getattr(d0, "fh", None)
                        if callable(getattr(cand_fh, "read", None)) and callable(getattr(cand_fh, "seek", None)):
                            disk_stream = cand_fh
                    disk_size = int(getattr(d0, "size", 0) or 0)
                    if disk_size == 0 and disk_stream is not None:
                        disk_stream.seek(0, io.SEEK_END)
                        disk_size = int(disk_stream.tell())
                        disk_stream.seek(0)
                except Exception:
                    disk_stream = None

            if disk_stream is None:
                try:
                    if image_p.suffix.lower() in (".e01", ".ex01") and pyewf is not None:
                        ewf_files = pyewf.glob(str(image_p))
                        owned_ewf_h = pyewf.handle()
                        owned_ewf_h.open(ewf_files)
                        disk_stream = owned_ewf_h
                        disk_size = int(owned_ewf_h.get_media_size())
                    else:
                        owned_raw_fh = open(image_p, "rb")
                        disk_stream = owned_raw_fh
                        disk_size = int(image_p.stat().st_size)
                except Exception as open_err:
                    err_msg = f"Failed opening forensic image {image_p.name}: {open_err}"
                    self._log(err_msg, level="ERROR")
                    errors.append(err_msg)
                    self._persist_vfs_tables([], [], [])
                    duration_ms = int((time.time() - start_time) * 1000)
                    return {
                        "status": "ERROR",
                        "mode": "image",
                        "source_image": str(image_p),
                        "staging_dir": str(staging_p),
                        "partitions_found": 0,
                        "shadow_copies": 0,
                        "total_files_staged": 0,
                        "duration_ms": duration_ms,
                        "counts": counts,
                        "staged_files": [],
                        "errors": errors,
                    }

            # Always wrap disk_stream via StreamImgInfo rather than opening a second native C
            # pytsk3.Img_Info(str(image_p)) HANDLE that C-level FS_Info/File cycles could hold open.
            tsk_img = (
                StreamImgInfo(disk_stream, disk_size, read_lock=source_read_lock)
                if (StreamImgInfo is not None and disk_stream is not None and disk_size > 0)
                else None
            )

            # 3. Parse MBR bootable flags at LBA 0 if present
            mbr_boot_offsets: Set[int] = set()
            if disk_stream is not None and disk_size >= 512:
                try:
                    with source_read_lock:
                        disk_stream.seek(0)
                        mbr = disk_stream.read(512)
                    if len(mbr) == 512 and mbr[510:512] == b"\x55\xaa":
                        for p_slot in range(4):
                            ent = mbr[446 + p_slot * 16 : 462 + p_slot * 16]
                            status_b, p_type = ent[0], ent[4]
                            lba_start, lba_len = struct.unpack("<II", ent[8:16])
                            if status_b == 0x80 and p_type != 0 and p_type != 0xEE and lba_len > 0:
                                mbr_boot_offsets.add(lba_start * 512)
                except Exception:
                    pass

            # 4. Discover ALL partitions across pytsk3.Volume_Info + dissect target.volumes (NO >2048 sector cutoff!)
            # Map offset_bytes -> (size_bytes, is_boot, dissect_vol_or_none)
            part_map: Dict[int, Tuple[int, bool, Any]] = {}

            if tsk_img is not None and pytsk3 is not None:
                try:
                    with source_read_lock:
                        vol_info = pytsk3.Volume_Info(tsk_img)
                        blk_sz = int(getattr(vol_info.info, "block_size", 512) or 512)
                        parts_iter = list(vol_info)
                    for p in parts_iter:
                        if bool(p.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC) and int(p.len) > 0:
                            off_b = int(p.start) * blk_sz
                            sz_b = int(p.len) * blk_sz
                            part_map[off_b] = (sz_b, off_b in mbr_boot_offsets, None)
                except Exception:
                    pass

            if target is not None:
                t_vols = list(getattr(target, "volumes", []) or [])
                has_real_subparts = any(int(getattr(v, "offset", 0) or 0) > 0 for v in t_vols) or any(k > 0 for k in part_map)
                for v in t_vols:
                    v_off = int(getattr(v, "offset", 0) or 0)
                    v_sz = int(getattr(v, "size", 0) or disk_size)
                    if v_off == 0 and has_real_subparts:
                        continue
                    v_boot = v_off in mbr_boot_offsets
                    raw_v = getattr(v, "raw", None)
                    if raw_v is not None and bool(getattr(raw_v, "flags", 0) & 0x80):
                        v_boot = True
                    if v_off in part_map:
                        prev_sz, prev_b, _ = part_map[v_off]
                        part_map[v_off] = (v_sz or prev_sz, prev_b or v_boot, v)
                    else:
                        part_map[v_off] = (v_sz, v_boot, v)

            if not part_map and disk_size > 0:
                part_map[0] = (disk_size, False, None)

            # Map offset_bytes -> dissect NtfsFilesystem if already mounted by dissect.target
            dissect_ntfs_by_off: Dict[int, Any] = {}
            if target is not None:
                for dfs in list(getattr(target, "filesystems", []) or []):
                    if hasattr(dfs, "ntfs") and dfs.ntfs is not None:
                        fs_off = int(getattr(getattr(dfs, "volume", None), "offset", 0) or 0)
                        dissect_ntfs_by_off[fs_off] = dfs

            sorted_parts = sorted(part_map.items(), key=lambda kv: kv[0])
            primary_mft_written = False

            # Helper: write bytes or stream chunks to staging destinations in worker pool
            def _write_bytes_and_utime(
                data: bytes,
                assigned_rels: List[str],
                rels_to_write: List[str],
                meta: ForensicMeta,
            ) -> List[Path]:
                write_set = set(rels_to_write)
                written: List[Path] = []
                for rel_d in assigned_rels:
                    dst = self._resolve_contained_dst(staging_p, rel_d)
                    if rel_d in write_set:
                        if dst.exists():
                            self._clear_file_attributes(dst)
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        with open(dst, "wb") as out_f:
                            out_f.write(data)
                        self._clear_file_attributes(dst)
                        apply_forensic_utime(dst, meta)
                    written.append(dst)
                return written

            # 5. Iterate EVERY Partition (NO single-partition break!)
            for part_idx, (off_bytes, (sz_bytes, is_boot, d_vol)) in enumerate(sorted_parts):
                if progress_callback:
                    pct = 10 + int((part_idx / max(1, len(sorted_parts))) * 75)
                    progress_callback(pct, f"Extracting partition {part_idx} (@ {off_bytes})...")

                if d_vol is not None and callable(getattr(d_vol, "read", None)) and callable(getattr(d_vol, "seek", None)):
                    part_fh = d_vol
                elif (
                    d_vol is not None
                    and callable(getattr(getattr(d_vol, "fh", None), "read", None))
                    and callable(getattr(getattr(d_vol, "fh", None), "seek", None))
                ):
                    part_fh = d_vol.fh
                else:
                    part_fh = PartitionSubStream(disk_stream, off_bytes, sz_bytes, read_lock=None)

                # Check if NTFS via dissect
                ntfs_fs = dissect_ntfs_by_off.get(off_bytes)
                if ntfs_fs is None and NtfsFilesystem is not None and disk_stream is not None and sz_bytes >= 4096:
                    try:
                        with source_read_lock:
                            disk_stream.seek(off_bytes + 3)
                            oem_sig = disk_stream.read(8)
                        if oem_sig == b"NTFS    ":
                            sub_s = PartitionSubStream(disk_stream, off_bytes, sz_bytes, read_lock=None)
                            with source_read_lock:
                                ntfs_fs = NtfsFilesystem(sub_s)
                    except Exception:
                        ntfs_fs = None

                # =============================================================
                # TIER A: dissect NTFS Partition Engine
                # =============================================================
                if ntfs_fs is not None and getattr(ntfs_fs, "ntfs", None) is not None:
                    vol_name = ""
                    vol_serial = ""
                    try:
                        with source_read_lock:
                            vol_name = str(getattr(ntfs_fs.ntfs, "volume_name", "") or "").strip()
                            raw_ser = getattr(ntfs_fs.ntfs, "serial", None)
                            if raw_ser is not None:
                                vol_serial = f"{int(raw_ser):016X}"
                    except Exception:
                        pass
                    p_label = vol_name or f"Partition_{part_idx}"
                    partitions_rows.append((part_idx, p_label, "NTFS", int(off_bytes), int(sz_bytes), vol_serial, bool(is_boot)))

                    # Scan all MFT records linearly via mft.segments()
                    # Pass 1: collect segment metadata & ALL distinct $FILE_NAME (0x30) hardlink entries
                    raw_recs: List[
                        Tuple[
                            int,
                            bool,
                            bool,
                            bool,
                            int,
                            List[Optional[datetime]],
                            List[Tuple[Optional[int], str, List[Optional[datetime]]]],
                            Any,
                        ]
                    ] = []
                    parent_lookup: Dict[int, Tuple[Optional[int], str]] = {5: (None, "")}

                    try:
                        with source_read_lock:
                            for seg in ntfs_fs.ntfs.mft.segments():
                                try:
                                    s_num = int(seg.segment)
                                    hdr_flags = int(seg.header.Flags)
                                    in_use = bool(hdr_flags & 0x0001)
                                    is_d = bool(hdr_flags & 0x0002)
                                    attrs = seg.attributes
                                    fn_list = [getattr(f, "attribute", f) for f in attrs.get(48, [])]
                                    if not fn_list and s_num != 5:
                                        continue
                                    links, f_attrs_bits, max_fn_sz = _extract_ntfs_fn_links(fn_list)
                                    if s_num == 5 and not links:
                                        links = [(None, "", [None, None, None, None])]
                                    elif not links:
                                        continue

                                    si_list = [getattr(s, "attribute", s) for s in attrs.get(16, [])]
                                    raw_si = getattr(si_list[0], "attr", None) if si_list else None
                                    if raw_si is not None:
                                        f_attrs_bits |= int(getattr(raw_si, "FileAttributes", 0) or 0)
                                        si_t = [
                                            _filetime_to_utc(getattr(raw_si, "CreationTime", 0)),
                                            _filetime_to_utc(getattr(raw_si, "LastModificationTime", 0)),
                                            _filetime_to_utc(getattr(raw_si, "LastAccessTime", 0)),
                                            _filetime_to_utc(getattr(raw_si, "LastChangeTime", 0)),
                                        ]
                                    else:
                                        si_t = [None, None, None, None]

                                    is_reparse = bool(f_attrs_bits & 0x0400)
                                    f_sz = 0
                                    if not is_d:
                                        try:
                                            f_sz = int(seg.size())
                                        except Exception:
                                            f_sz = max_fn_sz

                                    if s_num != 5 and links:
                                        first_p_seg, first_name, _ = links[0]
                                        if first_name and (s_num not in parent_lookup or in_use):
                                            parent_lookup[s_num] = (first_p_seg, first_name)
                                    raw_recs.append((s_num, in_use, is_d, is_reparse, f_sz, si_t, links, seg))
                                except Exception:
                                    continue
                    except Exception as mft_scan_err:
                        self._log(f"MFT segment scan notice on partition {part_idx}: {mft_scan_err}", level="WARNING")

                    path_memo: Dict[int, str] = {5: "/"}

                    def _resolve_seg_path(seg_id: Optional[int]) -> str:
                        if seg_id is None or seg_id == 5:
                            return "/"
                        if seg_id in path_memo:
                            return path_memo[seg_id]
                        chain: List[str] = []
                        cur: Optional[int] = seg_id
                        seen_c: Set[int] = set()
                        while cur is not None and cur != 5 and cur not in seen_c and len(chain) < 64:
                            seen_c.add(cur)
                            if cur in path_memo:
                                prefix = path_memo[cur].rstrip("/")
                                full_p = f"{prefix}/{'/'.join(reversed(chain))}" if chain else path_memo[cur]
                                path_memo[seg_id] = full_p
                                return full_p
                            info = parent_lookup.get(cur)
                            if info is None:
                                chain.append(f"$Orphan_{cur}")
                                cur = None
                                break
                            p_seg, nm = info
                            if nm:
                                chain.append(nm)
                            cur = p_seg
                        full_p = "/" + "/".join(reversed(chain))
                        path_memo[seg_id] = full_p
                        return full_p

                    # Detect if this NTFS partition hosts a Windows OS installation
                    has_win_os = False
                    for s_num, in_use, is_d, _, _, _, links, _ in raw_recs:
                        if in_use and is_d:
                            for p_seg, b_name, _ in links:
                                if b_name.lower() == "config" and _resolve_seg_path(p_seg).lower() == "/windows/system32":
                                    has_win_os = True
                                    break
                            if has_win_os:
                                break

                    # Stream $MFT and $J per partition (preserving Part_<part_idx>_$MFT per partition!)
                    fs_stage_dir = staging_p / "FileSystem"
                    fs_stage_dir.mkdir(parents=True, exist_ok=True)
                    mft_part_rel: Optional[str] = None
                    mft_meta: Optional[ForensicMeta] = None
                    try:
                        with source_read_lock:
                            mft_fh = getattr(getattr(ntfs_fs.ntfs, "mft", None), "fh", None)
                            mft_rec0 = ntfs_fs.ntfs.mft.get(0)
                            mft_meta = extract_meta_dissect(mft_rec0, "/$MFT", part_idx, "NTFS")
                            if mft_fh is not None:
                                mft_fh.seek(0)
                                mft_part_rel = f"FileSystem/Part_{part_idx}_$MFT"
                                part_mft_dst = self._resolve_contained_dst(staging_p, mft_part_rel)
                                part_mft_dst.parent.mkdir(parents=True, exist_ok=True)
                                with open(part_mft_dst, "wb") as out_mft:
                                    shutil.copyfileobj(mft_fh, out_mft, length=4 * 1024 * 1024)
                                self._clear_file_attributes(part_mft_dst)
                                apply_forensic_utime(part_mft_dst, mft_meta)
                                claimed_staged_rels[mft_part_rel.lower()] = (mft_part_rel, ("mft", part_idx))
                                counts["mft"] += 1
                                counts["total_files"] += 1
                                staged_files.append(mft_part_rel)
                                if has_win_os or not primary_mft_written:
                                    for alias_rel in ("FileSystem/$MFT", "$MFT"):
                                        alias_dst = self._resolve_contained_dst(staging_p, alias_rel)
                                        self._copy_file_safe(part_mft_dst, alias_dst, overwrite=True, meta=mft_meta, root_guard=staging_p)
                                    apply_forensic_utime(part_mft_dst, mft_meta)
                                    primary_mft_written = True
                    except Exception as mft_err:
                        self._log(f"Notice streaming $MFT on partition {part_idx}: {mft_err}", level="INFO")

                    try:
                        with source_read_lock:
                            usn_obj = getattr(ntfs_fs.ntfs, "usnjrnl", None)
                            usn_fh = getattr(usn_obj, "fh", None)
                            if usn_fh is not None:
                                usn_meta: Optional[ForensicMeta] = None
                                try:
                                    usn_rec = getattr(usn_obj, "record", None) or ntfs_fs.ntfs.mft.get(r"$Extend\$UsnJrnl")
                                    if usn_rec is not None:
                                        usn_meta = extract_meta_dissect(usn_rec, "/$Extend/$UsnJrnl:$J", part_idx, "NTFS")
                                except Exception:
                                    usn_meta = None
                                if usn_meta is None or (
                                    usn_meta.si_modified is None
                                    and usn_meta.fn_modified is None
                                    and usn_meta.si_created is None
                                    and usn_meta.fn_created is None
                                ):
                                    usn_meta = mft_meta
                                usn_fh.seek(0)
                                j_part_rel = f"FileSystem/Part_{part_idx}_$J"
                                part_j_dst = self._resolve_contained_dst(staging_p, j_part_rel)
                                with open(part_j_dst, "wb") as out_j:
                                    shutil.copyfileobj(usn_fh, out_j, length=4 * 1024 * 1024)
                                self._clear_file_attributes(part_j_dst)
                                apply_forensic_utime(part_j_dst, usn_meta)
                                if part_j_dst.stat().st_size > 0:
                                    claimed_staged_rels[j_part_rel.lower()] = (j_part_rel, ("usnjrnl", part_idx))
                                    counts["usnjrnl"] += 1
                                    counts["total_files"] += 1
                                    staged_files.append(j_part_rel)
                                    if has_win_os or not (fs_stage_dir / "$J").exists():
                                        for alias_j in ("FileSystem/$J", "$J"):
                                            self._copy_file_safe(
                                                part_j_dst,
                                                self._resolve_contained_dst(staging_p, alias_j),
                                                overwrite=True,
                                                meta=usn_meta,
                                                root_guard=staging_p,
                                            )
                                        apply_forensic_utime(part_j_dst, usn_meta)
                                else:
                                    part_j_dst.unlink(missing_ok=True)
                    except Exception:
                        pass

                    # Pass 2: Build vfs_files rows & queue artifact staging jobs
                    # Sort allocated records before deleted records so active paths claim canonical routes first.
                    raw_recs.sort(key=lambda r: (0 if r[1] else 1, r[0]))
                    ntfs_jobs: List[Tuple[Any, str, List[str], List[str], ForensicMeta, int]] = []
                    nested_arcs_ntfs: List[Tuple[Path, str, Optional[ForensicMeta]]] = []
                    seen_zi_segs: Set[int] = set()

                    for s_num, in_use, is_d, is_reparse, f_sz, si_t, links, seg in raw_recs:
                        iter_links = [(None, "", [None, None, None, None])] if s_num == 5 else links
                        for p_seg, b_name, fn_t in iter_links:
                            if s_num == 5:
                                v_path = "/"
                            elif not b_name:
                                continue
                            else:
                                par_p = _resolve_seg_path(p_seg).rstrip("/")
                                v_path = f"{par_p}/{b_name}" if par_p else f"/{b_name}"

                            rec_meta = ForensicMeta(
                                vfs_path=v_path,
                                part_index=part_idx,
                                fs_type="NTFS",
                                is_dir=is_d,
                                is_deleted=not in_use,
                                size_bytes=0 if is_d else f_sz,
                                mft_entry=s_num,
                                si_created=si_t[0],
                                si_modified=si_t[1],
                                si_accessed=si_t[2],
                                si_changed=si_t[3],
                                fn_created=fn_t[0],
                                fn_modified=fn_t[1],
                                fn_accessed=fn_t[2],
                                fn_changed=fn_t[3],
                            )

                            init_staged_rel = mft_part_rel if s_num == 0 else None
                            row_idx = len(vfs_rows)
                            vfs_rows.append(self._build_vfs_row(part_idx, v_path, init_staged_rel, rec_meta))

                            if in_use and not is_d and not is_reparse:
                                active_index[(part_idx, v_path.lower())] = _ActiveFileMeta(
                                    size_bytes=f_sz,
                                    si_modified_us=_dt_to_us(rec_meta.si_modified),
                                    staged_path=None,
                                    mft_entry=s_num,
                                    forensic_meta=rec_meta,
                                )

                            if is_d or is_reparse or s_num == 0:
                                continue

                            cat, route_rels = self._route_vfs_artifact(
                                vfs_path=v_path,
                                size_bytes=f_sz,
                                part_index=part_idx,
                                has_windows_os=has_win_os,
                                is_deleted=not in_use,
                            )
                            if cat and route_rels:
                                src_k = (
                                    ("ntfs_alloc", part_idx, s_num)
                                    if in_use
                                    else ("ntfs_del", part_idx, s_num, v_path.lower())
                                )
                                assigned_rels, rels_to_write = self._claim_staged_rels(
                                    rels=route_rels,
                                    claimed_map=claimed_staged_rels,
                                    claim_lock=state_lock,
                                    source_key=src_k,
                                    is_deleted=not in_use,
                                    hint_id=s_num,
                                )
                                if assigned_rels:
                                    ntfs_jobs.append((seg, cat, assigned_rels, rels_to_write, rec_meta, row_idx))

                            # Check NTFS :Zone.Identifier ADS on allocated files (once per MFT segment/link)
                            if in_use and s_num not in seen_zi_segs:
                                seen_zi_segs.add(s_num)
                                try:
                                    data_attrs = seg.attributes.get(0x80, [])
                                    for d_attr in data_attrs:
                                        if str(getattr(d_attr, "name", "") or "").lower() == "zone.identifier":
                                            with source_read_lock:
                                                zi_bytes = d_attr.open().read(65536)
                                            if zi_bytes:
                                                zi_raw = _sanitize_rel_path(
                                                    f"ZoneIdentifier/Part_{part_idx}/{v_path.lstrip('/')}.Zone.Identifier"
                                                )
                                                zi_assigned, zi_write = self._claim_staged_rels(
                                                    rels=[zi_raw],
                                                    claimed_map=claimed_staged_rels,
                                                    claim_lock=state_lock,
                                                    source_key=("ntfs_zi", part_idx, s_num),
                                                )
                                                if zi_assigned:
                                                    _write_bytes_and_utime(zi_bytes, zi_assigned, zi_write, rec_meta)
                                                    zi_meta = ForensicMeta(
                                                        vfs_path=f"{v_path}:Zone.Identifier",
                                                        part_index=part_idx,
                                                        fs_type="NTFS",
                                                        size_bytes=len(zi_bytes),
                                                        mft_entry=s_num,
                                                        si_created=rec_meta.si_created,
                                                        si_modified=rec_meta.si_modified,
                                                        si_accessed=rec_meta.si_accessed,
                                                        si_changed=rec_meta.si_changed,
                                                    )
                                                    vfs_rows.append(
                                                        self._build_vfs_row(
                                                            part_idx,
                                                            f"{v_path}:Zone.Identifier",
                                                            zi_assigned[0],
                                                            zi_meta,
                                                        )
                                                    )
                                                    counts["zone_identifier"] += 1
                                                    counts["total_files"] += 1
                                                    staged_files.append(zi_assigned[0])
                                except Exception:
                                    pass

                    def _run_ntfs_job(
                        job: Tuple[Any, str, List[str], List[str], ForensicMeta, int],
                    ) -> None:
                        seg_obj, cat_k, assigned_rels, rels_to_write, r_meta, r_idx = job
                        try:
                            if not rels_to_write:
                                written_paths = [
                                    self._resolve_contained_dst(staging_p, r) for r in assigned_rels
                                ]
                            elif r_meta.size_bytes <= 32 * 1024 * 1024:
                                with source_read_lock:
                                    stream_f = seg_obj.open()
                                    raw_b = stream_f.read(r_meta.size_bytes) if r_meta.size_bytes > 0 else b""
                                written_paths = _write_bytes_and_utime(raw_b, assigned_rels, rels_to_write, r_meta)
                            else:
                                first_write_rel = rels_to_write[0]
                                primary_dst = self._resolve_contained_dst(staging_p, first_write_rel)
                                if primary_dst.exists():
                                    self._clear_file_attributes(primary_dst)
                                primary_dst.parent.mkdir(parents=True, exist_ok=True)
                                rem = r_meta.size_bytes
                                with source_read_lock:
                                    stream_f = seg_obj.open()
                                with open(primary_dst, "wb") as out_f:
                                    while rem > 0:
                                        with source_read_lock:
                                            chunk = stream_f.read(min(4 * 1024 * 1024, rem))
                                        if not chunk:
                                            break
                                        out_f.write(chunk)
                                        rem -= len(chunk)
                                self._clear_file_attributes(primary_dst)
                                apply_forensic_utime(primary_dst, r_meta)
                                for extra_rel in rels_to_write[1:]:
                                    extra_dst = self._resolve_contained_dst(staging_p, extra_rel)
                                    self._copy_file_safe(primary_dst, extra_dst, overwrite=True, meta=r_meta, root_guard=staging_p)
                                if len(rels_to_write) > 1:
                                    apply_forensic_utime(primary_dst, r_meta)
                                written_paths = [
                                    self._resolve_contained_dst(staging_p, r) for r in assigned_rels
                                ]
                        except Exception as ntfs_w_err:
                            self._log(
                                f"NTFS stage notice on part {part_idx} {r_meta.vfs_path} -> {assigned_rels}: {ntfs_w_err}",
                                level="WARNING",
                            )
                            return

                        if not written_paths:
                            return
                        first_dst = written_paths[0]
                        with state_lock:
                            old = vfs_rows[r_idx]
                            vfs_rows[r_idx] = (old[0], old[1], assigned_rels[0], *old[3:])
                            act_entry = active_index.get((part_idx, r_meta.vfs_path.lower()))
                            if act_entry is not None:
                                act_entry.staged_path = first_dst
                            if rels_to_write:
                                counts[cat_k] = counts.get(cat_k, 0) + 1
                                counts["total_files"] += 1
                                staged_files.extend(rels_to_write)
                                if first_dst.suffix.lower() in self.ARCHIVE_EXTENSIONS:
                                    nested_arcs_ntfs.append((first_dst, r_meta.vfs_path, r_meta))

                    if eff_workers <= 1 or len(ntfs_jobs) <= 2:
                        for jb in ntfs_jobs:
                            _run_ntfs_job(jb)
                    else:
                        with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                            futs = [pool.submit(_run_ntfs_job, jb) for jb in ntfs_jobs]
                            for fut in as_completed(futs):
                                fut.result()

                    self._unpack_staged_nested_archives(
                        staging_p=staging_p,
                        part_index=part_idx,
                        fs_type="NTFS",
                        staged_arc_records=nested_arcs_ntfs,
                        vfs_rows=vfs_rows,
                        counts=counts,
                        staged_files=staged_files,
                    )

                    if eff_vss and part_fh is not None:
                        next_vss_idx, vss_cnt = self._extract_offline_vss_for_partition(
                            part_index=part_idx,
                            part_fh=part_fh,
                            staging_p=staging_p,
                            active_index=active_index,
                            seen_vss_hashes=seen_vss_hashes,
                            next_vss_index=next_vss_idx,
                            vfs_rows=vfs_rows,
                            vss_rows=vss_rows,
                            source_read_lock=source_read_lock,
                            eff_workers=eff_workers,
                        )
                        counts["vss_files"] += vss_cnt
                        counts["total_files"] += vss_cnt
                    continue

                # =============================================================
                # TIER B: pytsk3 Engine (FAT12/16/32 + $OrphanFiles, exFAT, ISO9660, NTFS fallback)
                # =============================================================
                tsk_fs = None
                if tsk_img is not None and pytsk3 is not None:
                    iso_ok, iso_err = _validate_iso9660_pvd_before_pytsk3(
                        disk_stream, off_bytes, sz_bytes, source_read_lock
                    )
                    if not iso_ok:
                        self._log(f"Skipping pytsk3.FS_Info on partition {part_idx}: {iso_err}", level="WARNING")
                        errors.append(str(iso_err))
                    else:
                        try:
                            with source_read_lock:
                                tsk_fs = pytsk3.FS_Info(tsk_img, offset=off_bytes)
                        except Exception:
                            tsk_fs = None

                if tsk_fs is not None and pytsk3 is not None:
                    ftype = tsk_fs.info.ftype
                    is_tsk_ntfs = bool(ftype & pytsk3.TSK_FS_TYPE_NTFS_DETECT)
                    if ftype == pytsk3.TSK_FS_TYPE_FAT12:
                        fs_name = "FAT12"
                    elif ftype == pytsk3.TSK_FS_TYPE_FAT16:
                        fs_name = "FAT16"
                    elif ftype == pytsk3.TSK_FS_TYPE_FAT32:
                        fs_name = "FAT32"
                    elif ftype == getattr(pytsk3, "TSK_FS_TYPE_EXFAT", 0x00000080):
                        fs_name = "exFAT"
                    elif bool(ftype & pytsk3.TSK_FS_TYPE_FAT_DETECT):
                        fs_name = "FAT32"
                    elif bool(ftype & pytsk3.TSK_FS_TYPE_ISO9660_DETECT):
                        fs_name = "ISO9660"
                    elif is_tsk_ntfs:
                        fs_name = "NTFS"
                    elif bool(ftype & pytsk3.TSK_FS_TYPE_EXT_DETECT):
                        fs_name = "EXT4"
                    else:
                        fs_name = "RAW_FS"

                    vol_serial = ""
                    try:
                        id_used = int(getattr(tsk_fs.info, "fs_id_used", 0) or 0)
                        if id_used > 0:
                            raw_id = bytes(list(tsk_fs.info.fs_id)[:id_used])[::-1]
                            vol_serial = raw_id.hex().upper()
                    except Exception:
                        pass

                    vol_label = ""
                    has_win_tsk = False
                    try:
                        with source_read_lock:
                            _ = tsk_fs.open_dir(path="/Windows/System32/config")
                        has_win_tsk = True
                    except Exception:
                        has_win_tsk = False

                    visited_dirs: Set[Tuple[int, str]] = set()
                    tsk_raw_jobs: List[Tuple[Any, str, List[str], ForensicMeta, int]] = []
                    nested_arcs_tsk: List[Tuple[Path, str, Optional[ForensicMeta]]] = []

                    # Synthetic root row
                    vfs_rows.append(
                        self._build_vfs_row(part_idx, "/", None, ForensicMeta(vfs_path="/", part_index=part_idx, fs_type=fs_name, is_dir=True))
                    )

                    def _walk_tsk_dir(dir_obj: Any, cur_vfs: str, in_orphan: bool, depth: int) -> None:
                        nonlocal vol_label
                        if depth > 32:
                            return
                        try:
                            with source_read_lock:
                                entries = list(dir_obj)
                        except Exception:
                            return

                        # Walk allocated entries before unallocated/deleted entries so moved FAT/exFAT
                        # folders share their cluster chain with the active path first (is_deleted=False).
                        entries.sort(
                            key=lambda e: 1
                            if (
                                getattr(e.info, "name", None) is not None
                                and bool(e.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                            )
                            else 0
                        )

                        for entry in entries:
                            nm_info = getattr(entry.info, "name", None)
                            if nm_info is None or not getattr(nm_info, "name", None):
                                continue
                            ename = nm_info.name.decode("utf-8", errors="replace").strip("\x00")
                            if not ename or ename in (".", ".."):
                                continue

                            # Detect volume label entry on FAT/exFAT (NEVER compare ntype == 5, which is TSK_FS_NAME_TYPE_REG!)
                            if ename.endswith("(Volume Label Entry)"):
                                cand_lbl = ename.replace("(Volume Label Entry)", "").strip()
                                if cand_lbl and not vol_label:
                                    vol_label = cand_lbl
                                continue

                            if cur_vfs == "/" and ename in ("$MBR", "$FAT1", "$FAT2", "$ALLOC_BITMAP", "$UPCASE_TABLE", "$BadClus", "$Bitmap"):
                                continue

                            f_obj = entry
                            m_info = getattr(f_obj.info, "meta", None)
                            meta_addr = int(getattr(nm_info, "meta_addr", 0) or 0)

                            # CRITICAL for FAT32 /$OrphanFiles (rm#2.dd): resolve inode when meta is None!
                            if m_info is None and meta_addr > 0:
                                try:
                                    with source_read_lock:
                                        f_obj = tsk_fs.open_meta(inode=meta_addr)
                                        m_info = getattr(f_obj.info, "meta", None)
                                except Exception:
                                    m_info = None

                            if m_info is not None and m_info.type == pytsk3.TSK_FS_META_TYPE_VIRT:
                                continue

                            is_virt_orphan_root = (
                                cur_vfs == "/"
                                and ename == "$OrphanFiles"
                                and m_info is not None
                                and m_info.type == pytsk3.TSK_FS_META_TYPE_VIRT_DIR
                            )
                            if is_virt_orphan_root:
                                vfs_rows.append(
                                    self._build_vfs_row(
                                        part_idx,
                                        "/$OrphanFiles",
                                        None,
                                        ForensicMeta(
                                            vfs_path="/$OrphanFiles",
                                            part_index=part_idx,
                                            fs_type=fs_name,
                                            is_dir=True,
                                            is_deleted=True,
                                        ),
                                    )
                                )
                                try:
                                    with source_read_lock:
                                        sub_d = f_obj.as_directory()
                                    _walk_tsk_dir(sub_d, "/$OrphanFiles", True, depth + 1)
                                except Exception:
                                    pass
                                continue

                            child_vfs = f"/{ename}" if cur_vfs == "/" else f"{cur_vfs}/{ename}"
                            with source_read_lock:
                                t_meta = extract_meta_pytsk3(
                                    f_obj,
                                    vfs_path=child_vfs,
                                    part_index=part_idx,
                                    fs_type=fs_name,
                                    is_ntfs=is_tsk_ntfs,
                                    force_deleted=in_orphan,
                                )

                            row_idx = len(vfs_rows)
                            vfs_rows.append(self._build_vfs_row(part_idx, child_vfs, None, t_meta))

                            if t_meta.is_dir:
                                inode_id = int(getattr(m_info, "addr", 0) or meta_addr)
                                is_del_branch = bool(in_orphan or t_meta.is_deleted)
                                mode_tag = "del" if is_del_branch else "alloc"
                                visit_k = (inode_id, f"{mode_tag}:{cur_vfs}" if inode_id == 0 else mode_tag)
                                if visit_k in visited_dirs:
                                    continue
                                visited_dirs.add(visit_k)
                                try:
                                    with source_read_lock:
                                        sub_dir = f_obj.as_directory()
                                    _walk_tsk_dir(sub_dir, child_vfs, is_del_branch, depth + 1)
                                except Exception:
                                    pass
                            else:
                                cat, route_rels = self._route_vfs_artifact(
                                    vfs_path=child_vfs,
                                    size_bytes=t_meta.size_bytes,
                                    part_index=part_idx,
                                    has_windows_os=has_win_tsk,
                                    is_deleted=t_meta.is_deleted,
                                )
                                if cat and route_rels:
                                    tsk_raw_jobs.append((f_obj, cat, route_rels, t_meta, row_idx))

                    try:
                        with source_read_lock:
                            root_dir = tsk_fs.open_dir(path="/")
                        _walk_tsk_dir(root_dir, "/", False, 0)
                    except Exception as walk_e:
                        errors.append(f"pytsk3 walk notice on partition {part_idx}: {walk_e}")

                    partitions_rows.append(
                        (part_idx, vol_label or f"Partition_{part_idx}", fs_name, int(off_bytes), int(sz_bytes), vol_serial, bool(is_boot))
                    )

                    # Sort allocated entries before deleted/orphan entries so active paths claim canonical routes first
                    tsk_raw_jobs.sort(key=lambda j: (1 if j[3].is_deleted else 0, j[4]))
                    tsk_jobs: List[Tuple[Any, str, List[str], List[str], ForensicMeta, int]] = []
                    for f_obj_j, cat_j, r_rels_j, t_meta_j, r_idx_j in tsk_raw_jobs:
                        tsk_inode = int(
                            t_meta_j.mft_entry
                            or getattr(getattr(f_obj_j.info, "meta", None), "addr", 0)
                            or getattr(getattr(f_obj_j.info, "name", None), "meta_addr", 0)
                            or r_idx_j
                        )
                        src_k_tsk = (
                            ("tsk_alloc", part_idx, tsk_inode, t_meta_j.vfs_path)
                            if not t_meta_j.is_deleted
                            else ("tsk_del", part_idx, tsk_inode, r_idx_j)
                        )
                        assigned_t, write_t = self._claim_staged_rels(
                            rels=r_rels_j,
                            claimed_map=claimed_staged_rels,
                            claim_lock=state_lock,
                            source_key=src_k_tsk,
                            is_deleted=t_meta_j.is_deleted,
                            hint_id=tsk_inode,
                        )
                        if assigned_t:
                            tsk_jobs.append((f_obj_j, cat_j, assigned_t, write_t, t_meta_j, r_idx_j))

                    def _check_fat_orphan_magic(ext_s: str, head_b: bytes, f_sz: int) -> Optional[bool]:
                        if len(head_b) < 4:
                            return None
                        if ext_s == ".bmp":
                            return len(head_b) >= 6 and head_b[:2] == b"BM" and struct.unpack_from("<I", head_b, 2)[0] == f_sz
                        if ext_s == ".png":
                            return len(head_b) >= 8 and head_b[:8] == b"\x89PNG\r\n\x1a\n"
                        if ext_s == ".gif":
                            return len(head_b) >= 6 and head_b[:6] in (b"GIF87a", b"GIF89a")
                        if ext_s in (".jpg", ".jpeg"):
                            return head_b[:3] == b"\xff\xd8\xff"
                        if ext_s in (".tif", ".tiff"):
                            return head_b[:4] in (b"II*\x00", b"MM\x00*")
                        if ext_s == ".pdf":
                            return head_b[:5] == b"%PDF-"
                        if ext_s in (".zip", ".docx", ".xlsx", ".pptx"):
                            return head_b[:4] == b"PK\x03\x04"
                        if ext_s == ".7z":
                            return len(head_b) >= 6 and head_b[:6] == b"7z\xbc\xaf\x27\x1c"
                        if ext_s in (".sqlite", ".sqlite3", ".db"):
                            return len(head_b) >= 16 and head_b[:16] == b"SQLite format 3\x00"
                        return None

                    preformat_fat_geom: Optional[Tuple[int, int, int, int, Set[int]]] = None
                    if (
                        fs_name in ("FAT16", "FAT32")
                        and tsk_img is not None
                        and any(j[4].is_deleted for j in tsk_jobs)
                    ):
                        try:
                            with source_read_lock:
                                bpb = tsk_img.read(int(off_bytes), 512)
                            if len(bpb) >= 64:
                                bps = struct.unpack_from("<H", bpb, 11)[0]
                                spc_cur = bpb[13]
                                rsvd = struct.unpack_from("<H", bpb, 14)[0]
                                nfats = bpb[16]
                                fatsz16 = struct.unpack_from("<H", bpb, 22)[0]
                                fatsz32 = struct.unpack_from("<I", bpb, 36)[0]
                                fatsz = fatsz16 if fatsz16 != 0 else fatsz32
                                if bps in (512, 1024, 2048, 4096) and spc_cur > 0 and fatsz > 0:
                                    data_sec_cur = rsvd + nfats * fatsz
                                    total_secs = int(sz_bytes) // bps
                                    mismatched_orphans: List[Tuple[int, int, str, int]] = []
                                    for f_o, _, _, _, tm_o, _ in tsk_jobs:
                                        if not tm_o.is_deleted or tm_o.size_bytes < 16:
                                            continue
                                        ext_o = PurePosixPath(tm_o.vfs_path).suffix.lower()
                                        try:
                                            with source_read_lock:
                                                hd_o = f_o.read_random(0, min(16, tm_o.size_bytes))
                                                r0_addr: Optional[int] = None
                                                for attr_o in f_o:
                                                    for run_o in attr_o:
                                                        r0_addr = int(run_o.addr)
                                                        break
                                                    if r0_addr is not None:
                                                        break
                                        except Exception:
                                            continue
                                        chk_o = _check_fat_orphan_magic(ext_o, hd_o, tm_o.size_bytes)
                                        if (
                                            chk_o is False
                                            and r0_addr is not None
                                            and r0_addr >= data_sec_cur
                                            and (r0_addr - data_sec_cur) % spc_cur == 0
                                        ):
                                            fc_o = (r0_addr - data_sec_cur) // spc_cur + 2
                                            ma_o = int(
                                                tm_o.mft_entry
                                                or getattr(getattr(f_o.info, "meta", None), "addr", 0)
                                                or 0
                                            )
                                            dir_sec_o = data_sec_cur + max(0, (ma_o - 3) // (bps // 32)) if ma_o >= 3 else -1
                                            mismatched_orphans.append((fc_o, tm_o.size_bytes, ext_o, dir_sec_o))

                                    if mismatched_orphans:
                                        mismatched_orphans.sort(key=lambda x: x[0])
                                        cand_spcs = [s for s in (1, 2, 4, 8, 16, 32, 64, 128) if s != spc_cur]
                                        spc_votes: Dict[int, int] = {s: 0 for s in cand_spcs}
                                        spc_anchors: Dict[int, List[Tuple[int, int, str, int]]] = {
                                            s: [] for s in cand_spcs
                                        }
                                        for idx_m in range(len(mismatched_orphans) - 1):
                                            c_i, sz_i, _, _ = mismatched_orphans[idx_m]
                                            c_n, _, _, _ = mismatched_orphans[idx_m + 1]
                                            dc = c_n - c_i
                                            if dc > 0:
                                                for s_c in cand_spcs:
                                                    cb_c = s_c * bps
                                                    if (sz_i + cb_c - 1) // cb_c == dc:
                                                        spc_votes[s_c] += 1
                                                        spc_anchors[s_c].append(mismatched_orphans[idx_m])
                                        ordered_spcs = sorted(
                                            cand_spcs, key=lambda s: (-spc_votes[s], abs(s - 32))
                                        )
                                        min_matches = min(2, len(mismatched_orphans))
                                        for spc_p in ordered_spcs:
                                            anchors_p = (
                                                spc_anchors[spc_p][:2]
                                                if spc_anchors[spc_p]
                                                else mismatched_orphans[:3]
                                            )
                                            found_ds: Optional[int] = None
                                            for fc0, sz0, ext0, _ in anchors_p:
                                                min_ds = 32
                                                max_ds = min(total_secs - (fc0 - 2) * spc_p - 1, 65536)
                                                if max_ds < min_ds:
                                                    continue
                                                chunk_secs = 2048
                                                sec0_off = (fc0 - 2) * spc_p
                                                min_sec0 = min_ds + sec0_off
                                                max_sec0 = min(total_secs - 1, max_ds + sec0_off)
                                                for s_base in range(min_sec0, max_sec0 + 1, chunk_secs):
                                                    cnt_s = min(chunk_secs, max_sec0 - s_base + 1)
                                                    with source_read_lock:
                                                        s_buf = tsk_img.read(
                                                            int(off_bytes) + s_base * bps, cnt_s * bps
                                                        )
                                                    for rel_s in range(cnt_s):
                                                        sl = s_buf[rel_s * bps : rel_s * bps + 16]
                                                        if _check_fat_orphan_magic(ext0, sl, sz0) is True:
                                                            ds_cand = s_base + rel_s - sec0_off
                                                            if ds_cand < 32:
                                                                continue
                                                            hits_m = 0
                                                            for fc_v, sz_v, ext_v, _ in mismatched_orphans:
                                                                sec_v = ds_cand + (fc_v - 2) * spc_p
                                                                if sec_v < 32 or sec_v >= total_secs:
                                                                    continue
                                                                with source_read_lock:
                                                                    hv = tsk_img.read(
                                                                        int(off_bytes) + sec_v * bps, 16
                                                                    )
                                                                if _check_fat_orphan_magic(ext_v, hv, sz_v) is True:
                                                                    hits_m += 1
                                                                    if hits_m >= min_matches:
                                                                        break
                                                            if hits_m >= min_matches:
                                                                found_ds = ds_cand
                                                                break
                                                    if found_ds is not None:
                                                        break
                                                if found_ds is not None:
                                                    break
                                            if found_ds is not None:
                                                preformat_dir_secs = {
                                                    d_s for _, _, _, d_s in mismatched_orphans if d_s >= 0
                                                }
                                                preformat_fat_geom = (
                                                    bps,
                                                    spc_cur,
                                                    data_sec_cur,
                                                    spc_p,
                                                    found_ds,
                                                )
                                                preformat_orphan_dirs = preformat_dir_secs
                                                break
                        except Exception:
                            preformat_fat_geom = None

                    def _try_read_preformat_fat_orphan(f_obj: Any, t_meta: ForensicMeta) -> Optional[bytes]:
                        if preformat_fat_geom is None or not t_meta.is_deleted or tsk_img is None:
                            return None
                        bps_g, spc_c, ds_c, spc_p, ds_p = preformat_fat_geom
                        sz = t_meta.size_bytes
                        if sz <= 0 or sz > 32 * 1024 * 1024:
                            return None
                        ext_g = PurePosixPath(t_meta.vfs_path).suffix.lower()
                        try:
                            with source_read_lock:
                                cur_hd = f_obj.read_random(0, min(16, sz))
                                r0_a: Optional[int] = None
                                for attr_g in f_obj:
                                    for run_g in attr_g:
                                        r0_a = int(run_g.addr)
                                        break
                                    if r0_a is not None:
                                        break
                        except Exception:
                            return None
                        if r0_a is None or r0_a < ds_c or (r0_a - ds_c) % spc_c != 0:
                            return None
                        chk_cur = _check_fat_orphan_magic(ext_g, cur_hd, sz)
                        if chk_cur is True:
                            return None
                        if chk_cur is None:
                            ma_g = int(
                                t_meta.mft_entry
                                or getattr(getattr(f_obj.info, "meta", None), "addr", 0)
                                or 0
                            )
                            dsec_g = ds_c + max(0, (ma_g - 3) // (bps_g // 32)) if ma_g >= 3 else -1
                            if dsec_g not in preformat_orphan_dirs or cur_hd[:2] != b"\x00\x00":
                                return None
                        fc_g = (r0_a - ds_c) // spc_c + 2
                        prev_byte_off = int(off_bytes) + (ds_p + (fc_g - 2) * spc_p) * bps_g
                        if prev_byte_off < int(off_bytes) or prev_byte_off + sz > int(off_bytes) + int(sz_bytes):
                            return None
                        with source_read_lock:
                            prev_hd = tsk_img.read(prev_byte_off, min(16, sz))
                        chk_prev = _check_fat_orphan_magic(ext_g, prev_hd, sz)
                        if chk_prev is False:
                            return None
                        if chk_prev is None and not any(prev_hd):
                            return None
                        out_chunks: List[bytes] = []
                        rem = sz
                        pos_b = prev_byte_off
                        while rem > 0:
                            step_b = min(1024 * 1024, rem)
                            with source_read_lock:
                                blk = tsk_img.read(pos_b, step_b)
                            if not blk:
                                break
                            out_chunks.append(blk)
                            pos_b += len(blk)
                            rem -= len(blk)
                        recovered = b"".join(out_chunks)
                        return recovered if len(recovered) == sz else None

                    preformat_orphan_dirs: Set[int] = set()
                    if preformat_fat_geom is not None:
                        # Re-collect directory sectors of verified pre-format orphans
                        bps_g, spc_c, ds_c, spc_p, ds_p = preformat_fat_geom
                        for f_o, _, _, _, tm_o, _ in tsk_jobs:
                            if not tm_o.is_deleted or tm_o.size_bytes < 16:
                                continue
                            ext_o = PurePosixPath(tm_o.vfs_path).suffix.lower()
                            try:
                                with source_read_lock:
                                    r0_o: Optional[int] = None
                                    for a_o in f_o:
                                        for rn_o in a_o:
                                            r0_o = int(rn_o.addr)
                                            break
                                        if r0_o is not None:
                                            break
                                if r0_o is not None and r0_o >= ds_c and (r0_o - ds_c) % spc_c == 0:
                                    fc_o = (r0_o - ds_c) // spc_c + 2
                                    p_off = int(off_bytes) + (ds_p + (fc_o - 2) * spc_p) * bps_g
                                    if p_off + 16 <= int(off_bytes) + int(sz_bytes):
                                        with source_read_lock:
                                            phd = tsk_img.read(p_off, 16)
                                        if _check_fat_orphan_magic(ext_o, phd, tm_o.size_bytes) is True:
                                            ma_o = int(
                                                tm_o.mft_entry
                                                or getattr(getattr(f_o.info, "meta", None), "addr", 0)
                                                or 0
                                            )
                                            if ma_o >= 3:
                                                preformat_orphan_dirs.add(ds_c + max(0, (ma_o - 3) // (bps_g // 32)))
                            except Exception:
                                continue

                    def _run_tsk_job(
                        job: Tuple[Any, str, List[str], List[str], ForensicMeta, int],
                    ) -> None:
                        f_obj, cat_k, assigned_rels, rels_to_write, t_meta, r_idx = job
                        sz = t_meta.size_bytes
                        if t_meta.is_deleted and (sz <= 0 or sz > min(int(sz_bytes), 64 * 1024 * 1024)):
                            return
                        try:
                            if not rels_to_write:
                                written_paths = [
                                    self._resolve_contained_dst(staging_p, r) for r in assigned_rels
                                ]
                            elif sz <= 32 * 1024 * 1024:
                                preformat_bytes = _try_read_preformat_fat_orphan(f_obj, t_meta)
                                if preformat_bytes is not None:
                                    payload_bytes = preformat_bytes
                                else:
                                    chunks: List[bytes] = []
                                    off_r = 0
                                    while off_r < sz:
                                        take = min(1024 * 1024, sz - off_r)
                                        with source_read_lock:
                                            buf = f_obj.read_random(off_r, take)
                                        if not buf:
                                            break
                                        chunks.append(buf)
                                        off_r += len(buf)
                                    payload_bytes = b"".join(chunks)
                                written_paths = _write_bytes_and_utime(
                                    payload_bytes,
                                    assigned_rels,
                                    rels_to_write,
                                    t_meta,
                                )
                            else:
                                first_write_rel = rels_to_write[0]
                                primary_dst = self._resolve_contained_dst(staging_p, first_write_rel)
                                if primary_dst.exists():
                                    self._clear_file_attributes(primary_dst)
                                primary_dst.parent.mkdir(parents=True, exist_ok=True)
                                off_r = 0
                                with open(primary_dst, "wb") as out_f:
                                    while off_r < sz:
                                        take = min(4 * 1024 * 1024, sz - off_r)
                                        with source_read_lock:
                                            buf = f_obj.read_random(off_r, take)
                                        if not buf:
                                            break
                                        out_f.write(buf)
                                        off_r += len(buf)
                                self._clear_file_attributes(primary_dst)
                                apply_forensic_utime(primary_dst, t_meta)
                                for extra_rel in rels_to_write[1:]:
                                    extra_dst = self._resolve_contained_dst(staging_p, extra_rel)
                                    self._copy_file_safe(primary_dst, extra_dst, overwrite=True, meta=t_meta, root_guard=staging_p)
                                if len(rels_to_write) > 1:
                                    apply_forensic_utime(primary_dst, t_meta)
                                written_paths = [
                                    self._resolve_contained_dst(staging_p, r) for r in assigned_rels
                                ]
                        except Exception as tsk_w_err:
                            self._log(
                                f"pytsk3 stage notice on part {part_idx} {t_meta.vfs_path} -> {assigned_rels}: {tsk_w_err}",
                                level="WARNING",
                            )
                            return

                        if not written_paths:
                            return
                        first_dst = written_paths[0]
                        with state_lock:
                            old = vfs_rows[r_idx]
                            vfs_rows[r_idx] = (old[0], old[1], assigned_rels[0], *old[3:])
                            if rels_to_write:
                                counts[cat_k] = counts.get(cat_k, 0) + 1
                                counts["total_files"] += 1
                                staged_files.extend(rels_to_write)
                                if first_dst.suffix.lower() in self.ARCHIVE_EXTENSIONS:
                                    nested_arcs_tsk.append((first_dst, t_meta.vfs_path, t_meta))

                    if eff_workers <= 1 or len(tsk_jobs) <= 2:
                        for jb in tsk_jobs:
                            _run_tsk_job(jb)
                    else:
                        with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                            futs = [pool.submit(_run_tsk_job, jb) for jb in tsk_jobs]
                            for fut in as_completed(futs):
                                fut.result()

                    self._unpack_staged_nested_archives(
                        staging_p=staging_p,
                        part_index=part_idx,
                        fs_type=fs_name,
                        staged_arc_records=nested_arcs_tsk,
                        vfs_rows=vfs_rows,
                        counts=counts,
                        staged_files=staged_files,
                    )
                    continue

                # =============================================================
                # TIER C: Pure-Python ECMA-167 / OSTA UDF 1.02–2.60 + VAT Engine
                # =============================================================
                if disk_stream is not None and _has_udf_bea_nsr(disk_stream, off_bytes, sz_bytes, source_read_lock):
                    udf_res = _parse_udf_volume(disk_stream, off_bytes, sz_bytes, source_read_lock)
                    if udf_res is not None:
                        u_label, u_serial, u_entries = udf_res
                        partitions_rows.append(
                            (part_idx, u_label, "UDF", int(off_bytes), int(sz_bytes), u_serial, bool(is_boot))
                        )
                        udf_raw_jobs: List[Tuple[_UdfEntryRecord, str, List[str], ForensicMeta, int]] = []
                        nested_arcs_udf: List[Tuple[Path, str, Optional[ForensicMeta]]] = []

                        for u_ent in u_entries:
                            u_meta = ForensicMeta(
                                vfs_path=u_ent.vfs_path,
                                part_index=part_idx,
                                fs_type="UDF",
                                is_dir=u_ent.is_dir,
                                is_deleted=u_ent.is_deleted,
                                size_bytes=u_ent.size_bytes,
                                mft_entry=u_ent.fe_sector,
                                si_created=u_ent.si_created,
                                si_modified=u_ent.si_modified,
                                si_accessed=u_ent.si_accessed,
                                si_changed=u_ent.si_changed,
                            )
                            row_idx = len(vfs_rows)
                            vfs_rows.append(self._build_vfs_row(part_idx, u_ent.vfs_path, None, u_meta))
                            if not u_ent.is_dir:
                                cat, route_rels = self._route_vfs_artifact(
                                    vfs_path=u_ent.vfs_path,
                                    size_bytes=u_ent.size_bytes,
                                    part_index=part_idx,
                                    has_windows_os=False,
                                    is_deleted=u_ent.is_deleted,
                                )
                                if cat and route_rels:
                                    udf_raw_jobs.append((u_ent, cat, route_rels, u_meta, row_idx))

                        udf_raw_jobs.sort(key=lambda j: (1 if j[3].is_deleted else 0, j[4]))
                        udf_jobs: List[Tuple[_UdfEntryRecord, str, List[str], List[str], ForensicMeta, int]] = []
                        for u_ent_j, cat_j, u_rels_j, u_meta_j, r_idx_j in udf_raw_jobs:
                            src_k_udf = (
                                ("udf_alloc", part_idx, u_ent_j.fe_sector, u_meta_j.vfs_path.lower())
                                if not u_meta_j.is_deleted
                                else ("udf_del", part_idx, u_ent_j.fe_sector, r_idx_j)
                            )
                            assigned_u, write_u = self._claim_staged_rels(
                                rels=u_rels_j,
                                claimed_map=claimed_staged_rels,
                                claim_lock=state_lock,
                                source_key=src_k_udf,
                                is_deleted=u_meta_j.is_deleted,
                                hint_id=u_ent_j.fe_sector if u_ent_j.fe_sector else r_idx_j,
                            )
                            if assigned_u:
                                udf_jobs.append((u_ent_j, cat_j, assigned_u, write_u, u_meta_j, r_idx_j))

                        def _run_udf_job(
                            job: Tuple[_UdfEntryRecord, str, List[str], List[str], ForensicMeta, int],
                        ) -> None:
                            u_ent, cat_k, assigned_rels, rels_to_write, u_meta, r_idx = job
                            try:
                                if not rels_to_write:
                                    written_paths = [
                                        self._resolve_contained_dst(staging_p, r) for r in assigned_rels
                                    ]
                                else:
                                    if u_ent.inline_data is not None:
                                        payload = u_ent.inline_data[: u_ent.size_bytes]
                                    else:
                                        parts_b: List[bytes] = []
                                        rem = u_ent.size_bytes
                                        for psec, blen in u_ent.extents:
                                            if rem <= 0:
                                                break
                                            take = min(blen, rem)
                                            with source_read_lock:
                                                disk_stream.seek(off_bytes + psec * 2048)
                                                chunk = disk_stream.read(take)
                                            parts_b.append(chunk)
                                            rem -= len(chunk)
                                        payload = b"".join(parts_b)
                                    written_paths = _write_bytes_and_utime(
                                        payload,
                                        assigned_rels,
                                        rels_to_write,
                                        u_meta,
                                    )
                            except Exception as udf_w_err:
                                self._log(
                                    f"UDF stage notice on part {part_idx} {u_meta.vfs_path} -> {assigned_rels}: {udf_w_err}",
                                    level="WARNING",
                                )
                                return

                            if not written_paths:
                                return
                            first_dst = written_paths[0]
                            with state_lock:
                                old = vfs_rows[r_idx]
                                vfs_rows[r_idx] = (old[0], old[1], assigned_rels[0], *old[3:])
                                if rels_to_write:
                                    counts[cat_k] = counts.get(cat_k, 0) + 1
                                    counts["total_files"] += 1
                                    staged_files.extend(rels_to_write)
                                    if first_dst.suffix.lower() in self.ARCHIVE_EXTENSIONS:
                                        nested_arcs_udf.append((first_dst, u_meta.vfs_path, u_meta))

                        if eff_workers <= 1 or len(udf_jobs) <= 2:
                            for jb in udf_jobs:
                                _run_udf_job(jb)
                        else:
                            with ThreadPoolExecutor(max_workers=eff_workers) as pool:
                                futs = [pool.submit(_run_udf_job, jb) for jb in udf_jobs]
                                for fut in as_completed(futs):
                                    fut.result()

                        self._unpack_staged_nested_archives(
                            staging_p=staging_p,
                            part_index=part_idx,
                            fs_type="UDF",
                            staged_arc_records=nested_arcs_udf,
                            vfs_rows=vfs_rows,
                            counts=counts,
                            staged_files=staged_files,
                        )
                        continue

                # Unrecognized / raw unformatted partition record
                partitions_rows.append(
                    (part_idx, f"Partition_{part_idx}", "UNALLOCATED", int(off_bytes), int(sz_bytes), "", bool(is_boot))
                )

            # 6. Persist vfs_partitions, vfs_files, and vfs_shadow_copies to DuckDB
            self._persist_vfs_tables(partitions_rows, vfs_rows, vss_rows)

        finally:
            dissect_ntfs_by_off.clear()
            part_map.clear()
            if tsk_img is not None:
                try:
                    tsk_img.close()
                except Exception:
                    pass
                tsk_img = None
            if owned_ewf_h is not None:
                try:
                    owned_ewf_h.close()
                except Exception:
                    pass
                owned_ewf_h = None
            if owned_raw_fh is not None:
                try:
                    owned_raw_fh.close()
                except Exception:
                    pass
                owned_raw_fh = None
            if disk_stream is not None:
                _close_dissect_target(disk_stream)
                disk_stream = None
            if target is not None:
                _close_dissect_target(target)
                target = None

        if progress_callback:
            progress_callback(100, f"Image extraction finished ({counts['total_files']} files staged)")

        has_recognized_fs = any(str(pr[2]).upper() != "UNALLOCATED" for pr in partitions_rows)
        if counts["total_files"] > 0 or has_recognized_fs:
            final_status = "SUCCESS"
        elif errors:
            final_status = "ERROR"
        else:
            final_status = "WARNING"

        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": final_status,
            "mode": "image",
            "source_image": str(image_p),
            "staging_dir": str(staging_p),
            "partitions_found": len(partitions_rows),
            "shadow_copies": len(vss_rows),
            "total_files_staged": counts["total_files"],
            "duration_ms": duration_ms,
            "counts": counts,
            "staged_files": staged_files,
            "errors": errors,
        }

    # =========================================================================
    # Unified Contract 2 Dispatcher Aliases: extract(...) & extract_all(...)
    # =========================================================================

    def extract(
        self,
        source_path: Optional[Union[str, Path]] = None,
        source_type: Optional[str] = None,
        staging_dir: Optional[Union[str, Path]] = None,
        unpack_archives: bool = True,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Unified extraction entrypoint dispatching to collect_live_triage, extract_from_directory,
        or extract_from_image based on source_type / source_path.
        """
        stype = (source_type or "").strip().lower()
        if stype in ("live", "live_triage") or source_path is None:
            return self.collect_live_triage(
                staging_dir=staging_dir,
                enable_vss=enable_vss,
                max_workers=max_workers,
                progress_callback=progress_callback,
                selected_artifacts=selected_artifacts,
            )

        sp = Path(str(source_path).strip().strip('"').strip("'")).resolve()
        if stype in ("directory", "folder", "archive") or sp.is_dir():
            return self.extract_from_directory(
                source_dir=sp,
                staging_dir=staging_dir,
                unpack_archives=unpack_archives,
                enable_vss=enable_vss,
                max_workers=max_workers,
                progress_callback=progress_callback,
                selected_artifacts=selected_artifacts,
            )

        if sp.is_file() and (
            sp.suffix.lower() in self.ARCHIVE_EXTENSIONS
            or sp.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz"))
        ):
            return self.extract_from_directory(
                source_dir=sp,
                staging_dir=staging_dir,
                unpack_archives=unpack_archives,
                enable_vss=enable_vss,
                max_workers=max_workers,
                progress_callback=progress_callback,
                selected_artifacts=selected_artifacts,
            )

        return self.extract_from_image(
            image_path=sp,
            staging_dir=staging_dir,
            enable_vss=enable_vss,
            max_workers=max_workers,
            progress_callback=progress_callback,
            selected_artifacts=selected_artifacts,
        )

    def extract_all(
        self,
        source_path: Optional[Union[str, Path]] = None,
        source_type: Optional[str] = None,
        staging_dir: Optional[Union[str, Path]] = None,
        unpack_archives: bool = True,
        enable_vss: bool = False,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        selected_artifacts: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Contract 2 alias delegating to extract(...)."""
        return self.extract(
            source_path=source_path,
            source_type=source_type,
            staging_dir=staging_dir,
            unpack_archives=unpack_archives,
            enable_vss=enable_vss,
            max_workers=max_workers,
            progress_callback=progress_callback,
            selected_artifacts=selected_artifacts,
        )
