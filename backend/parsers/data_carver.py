"""
Windows Forensic Toolkit (WFT) DFIR Suite - Multi-Threaded Forensic Data Carver
Pure-Python, high-speed, zero-false-positive multi-threaded file carver supporting:
  - NTFS unallocated cluster runs ($Bitmap MFT entry 6)
  - Raw / UDF / FAT / ISO / E01 / VMDK / VHD / VHDX byte streams
  - Directory file carving
  - 10 structurally validated formats: JPEG, PNG, GIF, PDF, ZIP/DOCX/XLSX/PPTX,
    SQLite3, EVTX, Registry regf, PE EXE/DLL, and Windows Shell LNK.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import struct
import threading
import time
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from backend.config import get_case_dir, register_case_dir
from backend.db.engine import DuckDBManager, log_processing_event

try:
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    HAS_PIL = True
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[assignment]
    HAS_PIL = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore[assignment]
    HAS_PEFILE = False

try:
    import pyewf
    HAS_PYEWF = True
except ImportError:  # pragma: no cover
    pyewf = None  # type: ignore[assignment]
    HAS_PYEWF = False

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:  # pragma: no cover
    pytsk3 = None  # type: ignore[assignment]
    HAS_PYTSK3 = False

try:
    from dissect.target import Target as DissectTarget
    HAS_DISSECT_TARGET = True
except ImportError:  # pragma: no cover
    DissectTarget = None  # type: ignore[assignment]
    HAS_DISSECT_TARGET = False

try:
    import pymupdf as _pymupdf
    _pymupdf.TOOLS.mupdf_display_errors(False)
    _pymupdf.TOOLS.mupdf_display_warnings(False)
    HAS_PYMUPDF = True
except ImportError:  # pragma: no cover
    try:
        import fitz as _pymupdf  # type: ignore[no-redef]
        HAS_PYMUPDF = True
    except ImportError:  # pragma: no cover
        _pymupdf = None  # type: ignore[assignment]
        HAS_PYMUPDF = False


CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB primary anchor window
HEADER_OVERLAP = 64           # Max header lookahead (covers 64-byte DOS MZ + e_lfanew header)

MAX_JPG_SIZE = 25 * 1024 * 1024
MAX_PNG_SIZE = 25 * 1024 * 1024
MAX_GIF_SIZE = 10 * 1024 * 1024
MAX_PDF_SIZE = 32 * 1024 * 1024
MAX_ZIP_SIZE = 32 * 1024 * 1024
MAX_SQLITE_SIZE = 32 * 1024 * 1024
MAX_EVTX_SIZE = 32 * 1024 * 1024
MAX_REGF_SIZE = 16 * 1024 * 1024
MAX_PE_SIZE = 32 * 1024 * 1024
MAX_LNK_SIZE = 1 * 1024 * 1024
MAX_CARVE_SIZE = max(
    MAX_JPG_SIZE,
    MAX_PNG_SIZE,
    MAX_GIF_SIZE,
    MAX_PDF_SIZE,
    MAX_ZIP_SIZE,
    MAX_SQLITE_SIZE,
    MAX_EVTX_SIZE,
    MAX_REGF_SIZE,
    MAX_PE_SIZE,
    MAX_LNK_SIZE,
)

SIG_JPG = b"\xff\xd8\xff"
SIG_PNG = b"\x89PNG\r\n\x1a\n"
SIG_GIF87 = b"GIF87a"
SIG_GIF89 = b"GIF89a"
SIG_PDF = b"%PDF-"
SIG_EOCD = b"PK\x05\x06"
SIG_ZIP_LOCAL = b"PK\x03\x04"
SIG_SQLITE = b"SQLite format 3\x00"
SIG_EVTX = b"ElfFile\x00"
SIG_EVTX_CHUNK = b"ElfChnk\x00"
SIG_REGF = b"regf"
SIG_HBIN = b"hbin"
SIG_MZ = b"MZ"
SIG_LNK = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

VALID_SQLITE_PAGE_SIZES = frozenset({512, 1024, 2048, 4096, 8192, 16384, 32768, 65536})
VALID_PE_MACHINES = frozenset({0x014C, 0x8664, 0xAA64})
ZIP_FAMILY_TYPES = frozenset({"zip", "docx", "xlsx", "pptx"})


@dataclass
class _CarveCandidate:
    file_type: str
    extension: str
    offset_bytes: int
    size_bytes: int
    header_sig: str
    source_region: str
    stream_key: str
    sha256: str = ""
    blob: Optional[bytes] = None


@dataclass
class _ScanWindow:
    stream_key: str
    c_start: int
    c_end: int
    region_min_offset: int
    hard_limit: int
    source_region: str


_STREAM_GRAPH_ATTRS = (
    "filesystems",
    "volumes",
    "disks",
    "fs",
    "entries",
    "layers",
    "mounts",
    "loader",
    "_loader",
    "ntfs",
    "fh",
    "_fh",
    "stream",
    "_stream",
    "subfile",
    "_subfile",
    "parent",
    "_parent",
    "raw",
    "disk",
    "vs",
    "volume",
    "fp",
    "_fp",
    "handle",
    "_handle",
)


def _close_stream_chain(obj: Any, visited: Optional[Set[int]] = None) -> None:
    """Recursively close nested Dissect stream/container wrappers (including BufferedStream._fh) without invoking Target.__getattr__."""
    if obj is None:
        return
    if visited is None:
        visited = set()
    obj_id = id(obj)
    if obj_id in visited:
        return
    visited.add(obj_id)

    try:
        d_attr = object.__getattribute__(obj, "__dict__")
    except Exception:
        d_attr = None

    if isinstance(d_attr, dict):
        for attr_name in _STREAM_GRAPH_ATTRS:
            if attr_name not in d_attr:
                continue
            child = d_attr.get(attr_name)
            if child is None:
                continue
            if isinstance(child, (list, tuple, set)):
                for item in list(child):
                    _close_stream_chain(item, visited)
            elif isinstance(child, dict):
                for item in list(child.values()):
                    _close_stream_chain(item, visited)
            else:
                _close_stream_chain(child, visited)

    if isinstance(obj, io.IOBase):
        try:
            obj.close()
        except Exception:
            pass
    elif not (DissectTarget is not None and isinstance(obj, DissectTarget)):
        try:
            close_fn = object.__getattribute__(obj, "close")
        except Exception:
            close_fn = None
        if callable(close_fn):
            try:
                close_fn()
            except Exception:
                pass


def _close_dissect_target(target: Any) -> None:
    """Safely release underlying container/loader file handles on a DissectTarget without triggering PluginNotFoundError."""
    if target is None:
        return
    _close_stream_chain(target, set())


class _ThreadSafeStream:
    """Thread-safe random-access reader for raw files, E01 segments, and VMDK/VHD/VHDX disks."""

    def __init__(self, source_path: Path) -> None:
        self.source_path = Path(source_path).resolve()
        self.suffix = self.source_path.suffix.lower()
        self._local = threading.local()
        self._handles_lock = threading.Lock()
        self._open_handles: List[Any] = []
        self._shared_fh: Any = None
        self._shared_target: Any = None
        self._shared_lock = threading.Lock()
        self._ewf_segments: Optional[List[str]] = None
        self.size: int = 0
        self._init_stream()

    def _init_stream(self) -> None:
        if self.suffix in {".e01", ".ex01", ".s01"} and HAS_PYEWF:
            try:
                segs = pyewf.glob(str(self.source_path))
                if not segs:
                    segs = [str(self.source_path)]
                self._ewf_segments = segs
                h = pyewf.handle()
                h.open(segs)
                try:
                    self.size = int(h.get_media_size())
                finally:
                    h.close()
                return
            except (OSError, PermissionError, Exception):
                self._ewf_segments = None

        if self.suffix in {".vmdk", ".vhd", ".vhdx"} and HAS_DISSECT_TARGET:
            try:
                target = DissectTarget.open(str(self.source_path))
                self._shared_target = target
                disks = list(getattr(target, "disks", []) or [])
                vols = list(getattr(target, "volumes", []) or [])
                container = disks[0] if disks else (vols[0] if vols else None)
                if container is not None:
                    fh = container.open()
                    self._shared_fh = fh
                    fh.seek(0, io.SEEK_END)
                    self.size = int(fh.tell())
                    fh.seek(0, io.SEEK_SET)
                    return
            except Exception:
                self._close_shared()

        try:
            self.size = int(self.source_path.stat().st_size)
        except (OSError, PermissionError):
            self.size = 0

    def _get_thread_handle(self) -> Any:
        h = getattr(self._local, "handle", None)
        if h is not None:
            return h
        try:
            if self._ewf_segments is not None and HAS_PYEWF:
                eh = pyewf.handle()
                eh.open(self._ewf_segments)
                self._local.handle = eh
                with self._handles_lock:
                    self._open_handles.append(eh)
                return eh

            fh = open(self.source_path, "rb")
            self._local.handle = fh
            with self._handles_lock:
                self._open_handles.append(fh)
            return fh
        except (OSError, PermissionError):
            return None

    def read_at(self, offset: int, length: int) -> bytes:
        if length <= 0 or offset < 0 or offset >= self.size:
            return b""
        to_read = min(length, self.size - offset)
        if to_read <= 0:
            return b""

        try:
            if self._shared_fh is not None:
                with self._shared_lock:
                    self._shared_fh.seek(offset, io.SEEK_SET)
                    return self._shared_fh.read(to_read)

            h = self._get_thread_handle()
            if h is None:
                return b""
            if self._ewf_segments is not None:
                return h.read_buffer_at_offset(to_read, offset)

            h.seek(offset, io.SEEK_SET)
            return h.read(to_read)
        except (OSError, PermissionError, ValueError):
            return b""

    def _close_shared(self) -> None:
        if self._shared_fh is not None:
            _close_stream_chain(self._shared_fh, set())
            self._shared_fh = None
        if self._shared_target is not None:
            _close_dissect_target(self._shared_target)
            self._shared_target = None

    def close(self) -> None:
        with self._handles_lock:
            handles = list(self._open_handles)
            self._open_handles.clear()
        for h in handles:
            try:
                h.close()
            except Exception:
                pass
        self._close_shared()


def _extract_unallocated_bitmap_runs(
    bm_bytes: bytes,
    cluster_size: int,
    vol_offset: int,
    vol_size: int,
    media_size: int,
) -> List[Tuple[int, int]]:
    """Fast O(N) byte-skipping extraction of unallocated cluster runs from NTFS $Bitmap."""
    runs: List[Tuple[int, int]] = []
    max_clusters = vol_size // cluster_size if cluster_size > 0 else 0
    if max_clusters <= 0 or not bm_bytes:
        return runs

    total_bm = len(bm_bytes)
    run_start_cluster: Optional[int] = None
    byte_idx = 0

    while byte_idx < total_bm:
        base_cluster = byte_idx * 8
        if base_cluster >= max_clusters:
            break
        b = bm_bytes[byte_idx]
        if b == 0xFF:
            if run_start_cluster is not None:
                s_off = vol_offset + run_start_cluster * cluster_size
                e_off = min(media_size, vol_offset + base_cluster * cluster_size)
                if e_off - s_off >= 512:
                    runs.append((s_off, e_off))
                run_start_cluster = None
            byte_idx += 1
            while byte_idx < total_bm and bm_bytes[byte_idx] == 0xFF:
                byte_idx += 1
            continue

        if b == 0x00 and base_cluster + 8 <= max_clusters:
            if run_start_cluster is None:
                run_start_cluster = base_cluster
            byte_idx += 1
            while byte_idx < total_bm and bm_bytes[byte_idx] == 0x00 and (byte_idx * 8 + 8) <= max_clusters:
                byte_idx += 1
            continue

        for bit in range(8):
            c_idx = base_cluster + bit
            if c_idx >= max_clusters:
                break
            allocated = bool(b & (1 << bit))
            if not allocated:
                if run_start_cluster is None:
                    run_start_cluster = c_idx
            else:
                if run_start_cluster is not None:
                    s_off = vol_offset + run_start_cluster * cluster_size
                    e_off = min(media_size, vol_offset + c_idx * cluster_size)
                    if e_off - s_off >= 512:
                        runs.append((s_off, e_off))
                    run_start_cluster = None
        byte_idx += 1

    if run_start_cluster is not None:
        s_off = vol_offset + run_start_cluster * cluster_size
        e_off = min(media_size, vol_offset + max_clusters * cluster_size)
        if e_off - s_off >= 512:
            runs.append((s_off, e_off))

    return runs


def _verify_baseline_jpeg_huffman(blob: bytes) -> bool:
    """Verify ITU-T T.81 baseline/sequential JPEG MCU Huffman stream completeness before EOI.

    Pillow's libjpeg wrapper silently treats premature EOI (JWRN_PREMATURE_EOF) or mid-scan
    Huffman errors before FFD9 as non-fatal warnings without raising in Image.load().
    """
    n = len(blob)
    i = 2
    dht: Dict[Tuple[int, int], Tuple[List[Optional[Tuple[int, int]]], Dict[Tuple[int, int], int]]] = {}
    sof_info: Optional[Tuple[int, int, Dict[int, Tuple[int, int]]]] = None
    dri = 0

    while i < n:
        if blob[i] != 0xFF:
            return False
        while i < n and blob[i] == 0xFF:
            i += 1
        if i >= n:
            return False
        m = blob[i]
        i += 1
        if m == 0xD9:
            return True
        if m == 0x01 or (0xD0 <= m <= 0xD7):
            continue
        if i + 2 > n:
            return False
        slen = struct.unpack_from(">H", blob, i)[0]
        if slen < 2 or i + slen > n:
            return False
        seg = blob[i + 2 : i + slen]
        i += slen

        if m == 0xC4:
            p = 0
            while p + 17 <= len(seg):
                tc_th = seg[p]
                counts = seg[p + 1 : p + 17]
                p += 17
                total_syms = sum(counts)
                if p + total_syms > len(seg):
                    return False
                syms = seg[p : p + total_syms]
                p += total_syms
                lut: List[Optional[Tuple[int, int]]] = [None] * 256
                slow: Dict[Tuple[int, int], int] = {}
                code = 0
                idx = 0
                for bits_m1, cnt in enumerate(counts):
                    blen = bits_m1 + 1
                    for _ in range(cnt):
                        if code >= (1 << blen):
                            return False
                        sym = syms[idx]
                        idx += 1
                        if blen <= 8:
                            shift = 8 - blen
                            base = code << shift
                            for fill in range(1 << shift):
                                lut[base | fill] = (sym, blen)
                        else:
                            slow[(blen, code)] = sym
                        code += 1
                    code <<= 1
                dht[(tc_th >> 4, tc_th & 0x0F)] = (lut, slow)
        elif m == 0xDD and len(seg) >= 2:
            dri = struct.unpack_from(">H", seg, 0)[0]
        elif m in (0xC0, 0xC1):
            if len(seg) < 6:
                return False
            prec, h, w, nf = struct.unpack_from(">BHHB", seg, 0)
            if prec != 8 or nf < 1 or len(seg) < 6 + 3 * nf:
                return True
            comps: Dict[int, Tuple[int, int]] = {}
            for c in range(nf):
                cid, hv, _tq = seg[6 + 3 * c : 9 + 3 * c]
                hc, vc = hv >> 4, hv & 0x0F
                if hc < 1 or vc < 1:
                    return False
                comps[cid] = (hc, vc)
            sof_info = (w, h, comps)
        elif m in (0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            return True
        elif m == 0xDA:
            if sof_info is None or len(seg) < 1:
                return True
            ns = seg[0]
            if ns < 1 or len(seg) < 1 + 2 * ns + 3:
                return False
            ss, se, ahal = seg[1 + 2 * ns : 4 + 2 * ns]
            if ss != 0 or se != 63 or ahal != 0:
                return True
            w, h, comps = sof_info
            max_h = max(v[0] for v in comps.values())
            max_v = max(v[1] for v in comps.values())
            scan_blocks = []
            for c in range(ns):
                cs, tdta = seg[1 + 2 * c : 3 + 2 * c]
                if cs not in comps:
                    return False
                td, ta = tdta >> 4, tdta & 0x0F
                if (0, td) not in dht or (1, ta) not in dht:
                    return True
                hc, vc = comps[cs]
                reps = (hc * vc) if ns > 1 else 1
                for _ in range(reps):
                    scan_blocks.append((dht[(0, td)], dht[(1, ta)]))
            if ns > 1:
                mcu_cols = (w + 8 * max_h - 1) // (8 * max_h)
                mcu_rows = (h + 8 * max_v - 1) // (8 * max_v)
            else:
                hc0, vc0 = comps[seg[1]]
                cw = (w * hc0 + max_h - 1) // max_h
                ch = (h * vc0 + max_v - 1) // max_v
                mcu_cols = (cw + 7) // 8
                mcu_rows = (ch + 7) // 8
            total_mcus = mcu_cols * mcu_rows
            if total_mcus > 16384:
                return (n - i) * 8 >= total_mcus * len(scan_blocks) * 2

            pos = i
            bitbuf = 0
            nbits = 0
            for mcu_idx in range(total_mcus):
                if dri and mcu_idx > 0 and (mcu_idx % dri) == 0:
                    bitbuf = 0
                    nbits = 0
                    while pos < n and blob[pos] == 0xFF:
                        pos += 1
                    if pos < n and (0xD0 <= blob[pos] <= 0xD7):
                        pos += 1
                for (dc_lut, dc_slow), (ac_lut, ac_slow) in scan_blocks:
                    while nbits < 16 and pos < n:
                        b = blob[pos]
                        if b == 0xFF:
                            if pos + 1 < n and blob[pos + 1] == 0x00:
                                pos += 2
                            else:
                                break
                        else:
                            pos += 1
                        bitbuf = (bitbuf << 8) | b
                        nbits += 8
                    if nbits == 0:
                        return False
                    peek8 = ((bitbuf << (8 - nbits)) & 0xFF) if nbits < 8 else ((bitbuf >> (nbits - 8)) & 0xFF)
                    hit = dc_lut[peek8]
                    if hit is not None:
                        ssss, blen = hit
                        if nbits < blen:
                            return False
                        nbits -= blen
                        bitbuf &= (1 << nbits) - 1
                    else:
                        if nbits < 9:
                            return False
                        found = False
                        ssss = 0
                        for blen in range(9, 17):
                            while nbits < blen and pos < n:
                                b = blob[pos]
                                if b == 0xFF:
                                    if pos + 1 < n and blob[pos + 1] == 0x00:
                                        pos += 2
                                    else:
                                        break
                                else:
                                    pos += 1
                                bitbuf = (bitbuf << 8) | b
                                nbits += 8
                            if nbits < blen:
                                return False
                            code = (bitbuf >> (nbits - blen)) & ((1 << blen) - 1)
                            if (blen, code) in dc_slow:
                                ssss = dc_slow[(blen, code)]
                                nbits -= blen
                                bitbuf &= (1 << nbits) - 1
                                found = True
                                break
                        if not found:
                            return False
                    if ssss > 12:
                        return False
                    while nbits < ssss and pos < n:
                        b = blob[pos]
                        if b == 0xFF:
                            if pos + 1 < n and blob[pos + 1] == 0x00:
                                pos += 2
                            else:
                                break
                        else:
                            pos += 1
                        bitbuf = (bitbuf << 8) | b
                        nbits += 8
                    if nbits < ssss:
                        return False
                    nbits -= ssss
                    bitbuf &= (1 << nbits) - 1

                    k = 1
                    while k <= 63:
                        while nbits < 16 and pos < n:
                            b = blob[pos]
                            if b == 0xFF:
                                if pos + 1 < n and blob[pos + 1] == 0x00:
                                    pos += 2
                                else:
                                    break
                            else:
                                pos += 1
                            bitbuf = (bitbuf << 8) | b
                            nbits += 8
                        if nbits == 0:
                            return False
                        peek8 = ((bitbuf << (8 - nbits)) & 0xFF) if nbits < 8 else ((bitbuf >> (nbits - 8)) & 0xFF)
                        hit = ac_lut[peek8]
                        if hit is not None:
                            rs, blen = hit
                            if nbits < blen:
                                return False
                            nbits -= blen
                            bitbuf &= (1 << nbits) - 1
                        else:
                            if nbits < 9:
                                return False
                            found = False
                            rs = 0
                            for blen in range(9, 17):
                                while nbits < blen and pos < n:
                                    b = blob[pos]
                                    if b == 0xFF:
                                        if pos + 1 < n and blob[pos + 1] == 0x00:
                                            pos += 2
                                        else:
                                            break
                                    else:
                                        pos += 1
                                    bitbuf = (bitbuf << 8) | b
                                    nbits += 8
                                if nbits < blen:
                                    return False
                                code = (bitbuf >> (nbits - blen)) & ((1 << blen) - 1)
                                if (blen, code) in ac_slow:
                                    rs = ac_slow[(blen, code)]
                                    nbits -= blen
                                    bitbuf &= (1 << nbits) - 1
                                    found = True
                                    break
                            if not found:
                                return False
                        if rs == 0x00:
                            break
                        if rs == 0xF0:
                            k += 16
                            if k > 64:
                                return False
                            continue
                        r = rs >> 4
                        s = rs & 0x0F
                        if s == 0 or s > 11:
                            return False
                        k += r + 1
                        if k > 64:
                            return False
                        while nbits < s and pos < n:
                            b = blob[pos]
                            if b == 0xFF:
                                if pos + 1 < n and blob[pos + 1] == 0x00:
                                    pos += 2
                                else:
                                    break
                            else:
                                pos += 1
                            bitbuf = (bitbuf << 8) | b
                            nbits += 8
                        if nbits < s:
                            return False
                        nbits -= s
                        bitbuf &= (1 << nbits) - 1
            return True
    return True


def _validate_jpeg(sub: bytes) -> Optional[bytes]:
    if not HAS_PIL or len(sub) < 64 or sub[:3] != SIG_JPG:
        return None
    b3 = sub[3]
    if b3 < 0xC0 or b3 > 0xFE or b3 in (0xD8, 0xD9, 0xFF):
        return None

    n = len(sub)
    i = 2
    saw_sos = False
    end_pos = -1

    while i < n:
        if sub[i] != 0xFF:
            return None
        while i < n and sub[i] == 0xFF:
            i += 1
        if i >= n:
            return None
        marker = sub[i]
        i += 1

        if marker == 0x00:
            return None
        if marker == 0xD9:
            if not saw_sos:
                return None
            end_pos = i
            break
        if marker == 0x01 or (0xD0 <= marker <= 0xD7):
            continue
        if i + 2 > n:
            return None
        seg_len = struct.unpack_from(">H", sub, i)[0]
        if seg_len < 2 or i + seg_len > n:
            return None
        i += seg_len

        if marker == 0xDA:
            saw_sos = True
            while True:
                ff_pos = sub.find(b"\xff", i)
                if ff_pos < 0 or ff_pos + 1 >= n:
                    return None
                k = ff_pos + 1
                while k < n and sub[k] == 0xFF:
                    k += 1
                if k >= n:
                    return None
                nxt = sub[k]
                if nxt == 0x00 or (0xD0 <= nxt <= 0xD7):
                    i = k + 1
                    continue
                if nxt == 0xD9:
                    end_pos = k + 1
                    break
                # Progressive JPEG multi-scan marker (DHT, DQT, DRI, next SOS, APP, COM)
                i = k - 1
                break
            if end_pos > 0:
                break

    if end_pos < 64:
        return None

    blob = sub[:end_pos]
    try:
        with Image.open(io.BytesIO(blob)) as im:
            w, h = im.size
            if w < 1 or h < 1:
                return None
            im.verify()
        with Image.open(io.BytesIO(blob)) as im2:
            im2.load()
            if getattr(im2, "defects", 0) > 0:
                return None
        if not _verify_baseline_jpeg_huffman(blob):
            return None
        return blob
    except Exception:
        return None


def _validate_png(sub: bytes) -> Optional[bytes]:
    if not HAS_PIL or len(sub) < 45 or sub[:8] != SIG_PNG:
        return None
    if sub[12:16] != b"IHDR" or struct.unpack_from(">I", sub, 8)[0] != 13:
        return None

    n = len(sub)
    pos = 8
    end_pos = -1
    chunk_count = 0

    while pos + 12 <= n:
        clen = struct.unpack_from(">I", sub, pos)[0]
        if clen > MAX_PNG_SIZE or pos + 12 + clen > n:
            return None
        ctype = sub[pos + 4 : pos + 8]
        for b in ctype:
            if not ((65 <= b <= 90) or (97 <= b <= 122)):
                return None
        expected_crc = struct.unpack_from(">I", sub, pos + 8 + clen)[0]
        calc_crc = zlib.crc32(sub[pos + 4 : pos + 8 + clen]) & 0xFFFFFFFF
        if expected_crc != calc_crc:
            return None

        pos += 12 + clen
        chunk_count += 1
        if ctype == b"IEND":
            if clen != 0:
                return None
            end_pos = pos
            break
        if chunk_count > 65536:
            return None

    if end_pos < 45:
        return None

    blob = sub[:end_pos]
    try:
        with Image.open(io.BytesIO(blob)) as im:
            if im.size[0] < 1 or im.size[1] < 1:
                return None
            im.verify()
        with Image.open(io.BytesIO(blob)) as im2:
            im2.load()
        return blob
    except Exception:
        return None


def _skip_gif_subblocks(sub: bytes, pos: int) -> int:
    n = len(sub)
    while pos < n:
        bsz = sub[pos]
        pos += 1
        if bsz == 0:
            return pos
        pos += bsz
        if pos > n:
            return -1
    return -1


def _validate_gif(sub: bytes) -> Optional[bytes]:
    if not HAS_PIL or len(sub) < 26 or sub[:6] not in (SIG_GIF87, SIG_GIF89):
        return None
    w, h, packed = struct.unpack_from("<HHB", sub, 6)
    if not (1 <= w <= 16384 and 1 <= h <= 16384):
        return None

    n = len(sub)
    pos = 13
    if packed & 0x80:
        gct_size = 3 * (1 << ((packed & 0x07) + 1))
        pos += gct_size
    if pos >= n:
        return None

    saw_image = False
    end_pos = -1
    steps = 0
    while pos < n and steps < 100000:
        steps += 1
        intro = sub[pos]
        pos += 1
        if intro == 0x3B:  # Trailer
            end_pos = pos
            break
        if intro == 0x21:  # Extension
            if pos >= n:
                end_pos = -1
                break
            pos += 1  # label
            pos = _skip_gif_subblocks(sub, pos)
            if pos < 0:
                end_pos = -1
                break
        elif intro == 0x2C:  # Image Descriptor
            if pos + 9 > n:
                end_pos = -1
                break
            iw, ih, ipacked = struct.unpack_from("<HHB", sub, pos + 4)
            if iw == 0 or ih == 0:
                end_pos = -1
                break
            pos += 9
            if ipacked & 0x80:
                lct_size = 3 * (1 << ((ipacked & 0x07) + 1))
                pos += lct_size
            if pos >= n:
                end_pos = -1
                break
            lzw_min = sub[pos]
            if lzw_min < 2 or lzw_min > 12:
                end_pos = -1
                break
            pos += 1
            pos = _skip_gif_subblocks(sub, pos)
            if pos < 0:
                end_pos = -1
                break
            saw_image = True
        elif intro == 0x00:
            continue
        else:
            end_pos = -1
            break

    candidates: List[int] = []
    if saw_image and end_pos > 20:
        candidates.append(end_pos)
    else:
        search_from = 20
        for _ in range(8):
            idx = sub.find(b"\x3b", search_from)
            if idx < 0:
                break
            candidates.append(idx + 1)
            search_from = idx + 1

    for cand_end in candidates:
        blob = sub[:cand_end]
        try:
            with Image.open(io.BytesIO(blob)) as im:
                if im.size[0] < 1 or im.size[1] < 1:
                    continue
                im.verify()
            with Image.open(io.BytesIO(blob)) as im2:
                im2.load()
            return blob
        except Exception:
            continue
    return None


_PDF_STARTXREF_EOF_RE = re.compile(rb"startxref\s+(\d+)\s*(?:\r?\n|\r|\s)*%%EOF")
_PDF_XREF_TABLE_RE = re.compile(rb"(?:^|[\r\n])\s*xref\b")
_PDF_XREF_STREAM_RE = re.compile(rb"/Type\s*/XRef\b")
_PDF_INCR_FOLLOW_RE = re.compile(rb"\A(?:[ \t\r\n]|%[^\r\n]*[\r\n]){0,256}(?:\d+\s+\d+\s+obj\b|xref\b)")


def _validate_pdf(sub: bytes) -> Optional[bytes]:
    if len(sub) < 64 or sub[:5] != SIG_PDF:
        return None
    if sub[5:7] not in (b"1.", b"2.") or not (48 <= sub[7] <= 57):
        return None

    # Search for valid %%EOF markers without crossing a subsequent %PDF- header or orphan unallocated tails
    best_end = -1
    search_pos = 32
    while search_pos < len(sub):
        eof_pos = sub.find(b"%%EOF", search_pos)
        if eof_pos < 0:
            break
        check_from = best_end if best_end > 0 else 8
        nxt_pdf = sub.find(b"%PDF-", check_from, eof_pos)
        if nxt_pdf >= 0 and sub[nxt_pdf + 5 : nxt_pdf + 7] in (b"1.", b"2."):
            break

        tail_win = sub[max(0, eof_pos - 2048) : eof_pos + 5]
        m_sx = _PDF_STARTXREF_EOF_RE.search(tail_win)
        if m_sx is not None:
            try:
                xref_off = int(m_sx.group(1))
            except ValueError:
                xref_off = -1

            if 0 < xref_off < eof_pos:
                body_probe = sub[:eof_pos]
                has_catalog_xref = (
                    b"/Root" in body_probe and _PDF_XREF_TABLE_RE.search(body_probe) is not None
                ) or (_PDF_XREF_STREAM_RE.search(body_probe) is not None)
                if b"obj" in body_probe and b"endobj" in body_probe and has_catalog_xref:
                    cand_end = eof_pos + 5
                    if sub[cand_end : cand_end + 2] == b"\r\n":
                        cand_end += 2
                    elif sub[cand_end : cand_end + 1] in (b"\n", b"\r"):
                        cand_end += 1

                    cand_blob = sub[:cand_end]
                    pdf_ok = True
                    if HAS_PYMUPDF and _pymupdf is not None:
                        doc = None
                        try:
                            doc = _pymupdf.open(stream=cand_blob, filetype="pdf")
                            if int(getattr(doc, "page_count", 0) or 0) < 1:
                                pdf_ok = False
                        except Exception:
                            pdf_ok = False
                        finally:
                            if doc is not None:
                                try:
                                    doc.close()
                                except Exception:
                                    pass

                    if pdf_ok:
                        best_end = cand_end
                        after_eof = sub[cand_end : cand_end + 320]
                        if not after_eof or _PDF_INCR_FOLLOW_RE.match(after_eof) is None:
                            break
        search_pos = eof_pos + 5

    if best_end < 64:
        return None
    return sub[:best_end]


def _validate_zip_ooxml(blob: bytes) -> Optional[Tuple[str, str]]:
    if len(blob) < 30 or blob[:4] != SIG_ZIP_LOCAL:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
            infos = zf.infolist()
            if not infos:
                return None
            total_uncomp = sum(max(0, int(inf.file_size)) for inf in infos)
            if total_uncomp > 512 * 1024 * 1024:
                return None
            if zf.testzip() is not None:
                return None

            names_low = {inf.filename.replace("\\", "/").lower() for inf in infos}
            if "[content_types].xml" in names_low:
                if any(n.startswith("word/") for n in names_low):
                    return ("docx", "docx")
                if any(n.startswith("xl/") for n in names_low):
                    return ("xlsx", "xlsx")
                if any(n.startswith("ppt/") for n in names_low):
                    return ("pptx", "pptx")
                non_meta = {
                    n
                    for n in names_low
                    if n not in ("[content_types].xml", "_rels/.rels") and not n.endswith("/")
                }
                if non_meta and all(
                    n == "tablestyles.xml"
                    or n.startswith(("theme/", "drs/", "diagrams/", "_rels/"))
                    for n in non_meta
                ):
                    return None
            return ("zip", "zip")
    except Exception:
        return None


def _validate_sqlite(read_fn: Callable[[int], bytes]) -> Optional[bytes]:
    hdr = read_fn(128)
    if len(hdr) < 108 or hdr[:16] != SIG_SQLITE:
        return None

    ps_raw = struct.unpack_from(">H", hdr, 16)[0]
    page_size = 65536 if ps_raw == 1 else ps_raw
    if page_size not in VALID_SQLITE_PAGE_SIZES:
        return None
    if hdr[18] not in (1, 2) or hdr[19] not in (1, 2) or hdr[21:24] != b"\x40\x20\x20":
        return None

    schema_format = struct.unpack_from(">I", hdr, 44)[0]
    if schema_format not in (0, 1, 2, 3, 4):
        return None
    text_enc = struct.unpack_from(">I", hdr, 56)[0]
    if text_enc not in (0, 1, 2, 3):
        return None

    # Validate page 1 B-tree header at offset 100
    btree_flag = hdr[100]
    if btree_flag not in (0x02, 0x05, 0x0A, 0x0D):
        return None
    cell_count = struct.unpack_from(">H", hdr, 103)[0]
    hdr_end = 112 if btree_flag in (0x02, 0x05) else 108
    if hdr_end + cell_count * 2 > page_size:
        return None

    db_pages = struct.unpack_from(">I", hdr, 28)[0]
    if db_pages >= 1:
        total_size = page_size * db_pages
        if total_size > MAX_SQLITE_SIZE:
            return None
        blob = read_fn(total_size)
        if len(blob) != total_size:
            return None
        return blob

    # Fallback when header[28:32] == 0 (older SQLite < 3.7.0): walk valid pages
    probe = read_fn(min(MAX_SQLITE_SIZE, page_size * 256))
    if len(probe) < page_size:
        return None
    valid_pages = 1
    max_p = len(probe) // page_size
    for p_idx in range(1, max_p):
        p_off = p_idx * page_size
        flag = probe[p_off]
        if flag in (0x00, 0x02, 0x05, 0x0A, 0x0D):
            if flag in (0x02, 0x05, 0x0A, 0x0D):
                cc = struct.unpack_from(">H", probe, p_off + 3)[0]
                if (12 if flag in (0x02, 0x05) else 8) + cc * 2 > page_size:
                    break
            valid_pages += 1
        else:
            break
    return probe[: valid_pages * page_size]


def _validate_evtx(read_fn: Callable[[int], bytes]) -> Optional[bytes]:
    hdr = read_fn(4112)
    if len(hdr) < 4104 or hdr[:8] != SIG_EVTX:
        return None

    # Standard EVTX_HEADER: header_size @ 32 (== 128), minor @ 36, major @ 38 (== 3), header_block_size @ 40 (== 4096), num_chunks @ 42
    hdr_block_sz = struct.unpack_from("<H", hdr, 40)[0]
    num_chunks = struct.unpack_from("<H", hdr, 42)[0]
    if hdr_block_sz != 4096:
        # Check alternate synthetic header placement at +36
        alt_block_sz = struct.unpack_from("<H", hdr, 36)[0]
        if alt_block_sz == 4096:
            hdr_block_sz = 4096
            if num_chunks == 0:
                num_chunks = max(1, struct.unpack_from("<H", hdr, 38)[0])
        else:
            return None

    if hdr[4096:4104] != SIG_EVTX_CHUNK:
        return None

    if num_chunks == 0:
        num_chunks = 1
    if num_chunks > 512:
        return None

    total_size = 4096 + num_chunks * 65536
    if total_size > MAX_EVTX_SIZE:
        return None

    blob = read_fn(total_size)
    if len(blob) != total_size:
        return None
    for c in range(num_chunks):
        c_magic = blob[4096 + c * 65536 : 4104 + c * 65536]
        if c == 0 and c_magic != SIG_EVTX_CHUNK:
            return None
        if c > 0 and c_magic not in (SIG_EVTX_CHUNK, b"\x00" * 8):
            return None

    return blob


def _validate_regf(read_fn: Callable[[int], bytes]) -> Optional[bytes]:
    hdr = read_fn(4112)
    if len(hdr) < 4104 or hdr[:4] != SIG_REGF:
        return None

    seq1, seq2 = struct.unpack_from("<II", hdr, 4)
    major_ver = struct.unpack_from("<I", hdr, 20)[0]
    minor_ver = struct.unpack_from("<I", hdr, 24)[0]
    file_type_val = struct.unpack_from("<I", hdr, 28)[0]
    root_cell_offset = struct.unpack_from("<I", hdr, 36)[0]
    bins_size = struct.unpack_from("<I", hdr, 40)[0]

    if seq1 == 0 or seq2 == 0:
        return None
    if major_ver != 1 or minor_ver not in (3, 4, 5, 6) or file_type_val != 0:
        return None
    if bins_size < 4096 or bins_size % 4096 != 0:
        return None
    if root_cell_offset < 0x20 or root_cell_offset >= bins_size:
        return None

    calc_csum = 0
    for word in struct.unpack_from("<127I", hdr, 0):
        calc_csum ^= word
    if calc_csum == 0xFFFFFFFF:
        calc_csum = 0xFFFFFFFE
    elif calc_csum == 0:
        calc_csum = 1
    stored_csum = struct.unpack_from("<I", hdr, 0x1FC)[0]
    if calc_csum != stored_csum:
        return None

    total_size = 4096 + bins_size
    if total_size > MAX_REGF_SIZE:
        return None
    if hdr[4096:4100] != SIG_HBIN:
        return None

    blob = read_fn(total_size)
    if len(blob) != total_size:
        return None

    root_nk_pos = 4096 + root_cell_offset + 4
    if root_nk_pos + 2 > total_size or blob[root_nk_pos : root_nk_pos + 2] != b"nk":
        return None

    cur = 4096
    walked = 0
    while cur < total_size:
        if cur + 0x20 > total_size:
            return None
        if blob[cur : cur + 4] != SIG_HBIN:
            return None
        rel_off, hbin_sz = struct.unpack_from("<II", blob, cur + 4)
        if rel_off != (cur - 4096):
            return None
        if hbin_sz < 4096 or (hbin_sz % 4096) != 0:
            return None
        if cur + hbin_sz > total_size:
            return None
        cur += hbin_sz
        walked += hbin_sz

    if walked != bins_size:
        return None
    return blob


def _validate_pe(read_fn: Callable[[int], bytes], quick_hdr: bytes) -> Optional[Tuple[str, bytes]]:
    if not HAS_PEFILE or len(quick_hdr) < 0x40 or quick_hdr[:2] != SIG_MZ:
        return None
    e_lfanew = struct.unpack_from("<I", quick_hdr, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > 0x1000:
        return None

    pe_probe = quick_hdr if len(quick_hdr) >= e_lfanew + 24 else read_fn(e_lfanew + 24)
    if len(pe_probe) < e_lfanew + 24:
        return None
    if pe_probe[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", pe_probe, e_lfanew + 4)[0]
    if machine not in VALID_PE_MACHINES:
        return None
    num_sec = struct.unpack_from("<H", pe_probe, e_lfanew + 6)[0]
    if num_sec < 1 or num_sec > 96:
        return None

    hdr_window = read_fn(min(MAX_PE_SIZE, e_lfanew + 512 + num_sec * 40))
    pe = None
    try:
        pe = pefile.PE(data=hdr_window, fast_load=True)
        opt_magic = getattr(pe.OPTIONAL_HEADER, "Magic", 0)
        if opt_magic not in (0x10B, 0x20B) or not pe.sections:
            return None

        opt_hdr_sz = int(getattr(pe.FILE_HEADER, "SizeOfOptionalHeader", 0) or 0)
        min_opt_sz = 0x60 if opt_magic == 0x10B else 0x70
        if opt_hdr_sz < min_opt_sz:
            return None

        fa = int(getattr(pe.OPTIONAL_HEADER, "FileAlignment", 0) or 0)
        sa = int(getattr(pe.OPTIONAL_HEADER, "SectionAlignment", 0) or 0)
        if not (512 <= fa <= 65536) or (fa & (fa - 1)) != 0:
            return None
        if sa < fa or sa > 0x10000000 or (sa & (sa - 1)) != 0:
            return None

        hdr_min_end = e_lfanew + 24 + opt_hdr_sz + len(pe.sections) * 40
        size_of_headers = int(getattr(pe.OPTIONAL_HEADER, "SizeOfHeaders", 0) or 0)
        size_of_image = int(getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0) or 0)
        if size_of_headers < hdr_min_end or size_of_image < size_of_headers or size_of_image > 0x80000000:
            return None

        end_off = size_of_headers
        has_raw_section = False
        for s in pe.sections:
            va = int(getattr(s, "VirtualAddress", 0) or 0)
            raw_ptr = int(getattr(s, "PointerToRawData", 0) or 0)
            raw_sz = int(getattr(s, "SizeOfRawData", 0) or 0)
            if va >= size_of_image:
                return None
            if raw_sz > 0:
                has_raw_section = True
                if raw_ptr < size_of_headers or (raw_ptr + raw_sz) > MAX_PE_SIZE:
                    return None
                end_off = max(end_off, raw_ptr + raw_sz)

        if not has_raw_section:
            return None

        data_dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
        if len(data_dirs) > 4:
            sec_dir = data_dirs[4]
            cert_va = int(getattr(sec_dir, "VirtualAddress", 0) or 0)
            cert_sz = int(getattr(sec_dir, "Size", 0) or 0)
            if cert_va >= end_off and cert_sz > 0 and (cert_va + cert_sz) <= MAX_PE_SIZE:
                end_off = max(end_off, cert_va + cert_sz)

        if end_off < 512 or end_off > MAX_PE_SIZE:
            return None

        blob = read_fn(end_off)
        if len(blob) != end_off:
            return None

        is_dll = bool(int(pe.FILE_HEADER.Characteristics) & 0x2000)
        ext = "dll" if is_dll else "exe"
        return (ext, blob)
    except Exception:
        return None
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def _validate_lnk(sub: bytes) -> Optional[bytes]:
    if len(sub) < 80 or sub[:20] != SIG_LNK:
        return None
    link_flags = struct.unpack_from("<I", sub, 20)[0]
    if link_flags == 0 or (link_flags & 0xF8000000) != 0:
        return None
    show_cmd = struct.unpack_from("<I", sub, 60)[0]
    if show_cmd > 16:
        return None
    if sub[68:76] != b"\x00" * 8:
        return None

    n = len(sub)
    pos = 76

    # 1. LinkTargetIDList
    if link_flags & 0x01:
        if pos + 2 > n:
            return None
        id_len = struct.unpack_from("<H", sub, pos)[0]
        if id_len < 2 or pos + 2 + id_len > n:
            return None
        if struct.unpack_from("<H", sub, pos + 2 + id_len - 2)[0] != 0:
            return None
        pos += 2 + id_len

    # 2. LinkInfo
    if link_flags & 0x02:
        if pos + 8 > n:
            return None
        li_len, li_hdr_sz = struct.unpack_from("<II", sub, pos)
        if li_len < 0x1C or (li_hdr_sz != 0x1C and li_hdr_sz < 0x24) or li_hdr_sz > li_len or pos + li_len > n:
            return None
        pos += li_len

    # 3. StringData (NAME, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION)
    is_unicode = bool(link_flags & 0x80)
    for bit in (0x04, 0x08, 0x10, 0x20, 0x40):
        if link_flags & bit:
            if pos + 2 > n:
                return None
            cch = struct.unpack_from("<H", sub, pos)[0]
            if cch > 4096:
                return None
            byte_cnt = cch * 2 if is_unicode else cch
            if pos + 2 + byte_cnt > n:
                return None
            pos += 2 + byte_cnt

    # 4. ExtraData blocks terminated by < 4 byte terminal block (0x00000000)
    saw_terminal = False
    blocks = 0
    while pos + 4 <= n and blocks < 64:
        blk_sz = struct.unpack_from("<I", sub, pos)[0]
        if blk_sz < 4:
            if blk_sz != 0:
                return None
            pos += 4
            saw_terminal = True
            break
        if blk_sz > 8192 or pos + blk_sz > n:
            return None
        sig = struct.unpack_from("<I", sub, pos + 4)[0]
        if (sig & 0xFFFF0000) != 0xA0000000:
            return None
        pos += blk_sz
        blocks += 1

    if not saw_terminal and pos < n:
        return None
    if pos < 76 or pos > MAX_LNK_SIZE:
        return None
    return sub[:pos]


class DataCarver:
    """
    High-speed multi-threaded forensic data carver with strict structural verification.
    Recovers JPEG, PNG, GIF, PDF, ZIP/DOCX/XLSX/PPTX, SQLite3, EVTX, Registry regf,
    PE EXE/DLL, and Windows LNK artifacts with zero garbage false positives.
    """

    def __init__(self, case_id: str, case_dir: Path, db_manager: Any = None) -> None:
        self.case_id = str(case_id)
        self.case_dir = Path(case_dir).resolve()
        self.carved_dir = self.case_dir / "carved"
        self.db_manager = db_manager if db_manager is not None else DuckDBManager
        self._fallback_lock = threading.RLock()

        if self.db_manager is DuckDBManager:
            try:
                if get_case_dir(self.case_id).resolve() != self.case_dir:
                    register_case_dir(self.case_id, self.case_dir)
            except Exception:
                pass

    def _acquire_lock(self) -> Any:
        get_lock = getattr(self.db_manager, "get_lock", None)
        if callable(get_lock):
            return get_lock(self.case_id)
        return self._fallback_lock

    def _get_connection(self) -> Any:
        get_conn = getattr(self.db_manager, "get_connection", None)
        if callable(get_conn):
            return get_conn(self.case_id, read_only=False)
        return DuckDBManager.get_connection(self.case_id, read_only=False)

    def _discover_ntfs_unallocated_runs(
        self, source_path: Path, media_size: int
    ) -> List[Tuple[int, int]]:
        runs: List[Tuple[int, int]] = []
        if source_path.suffix.lower() in {".dd", ".raw", ".img", ".bin", ".e01", ".ex01", ".vmdk", ".vhd", ".vhdx"} or source_path.is_file():
            if HAS_DISSECT_TARGET:
                target = None
                try:
                    target = DissectTarget.open(str(source_path))
                    for fs in getattr(target, "filesystems", []) or []:
                        nt = getattr(fs, "ntfs", None)
                        if nt is None:
                            continue
                        cluster_size = int(getattr(nt, "cluster_size", 0) or 0)
                        fh = getattr(nt, "fh", None)
                        vol_offset = getattr(fh, "offset", 0)
                        vol_size = getattr(fh, "size", 0)
                        if vol_offset is None or cluster_size <= 0:
                            continue
                        bm_entry = nt.mft.get(6)
                        bm_fh = bm_entry.open()
                        try:
                            bm_bytes = bm_fh.read()
                        finally:
                            try:
                                bm_fh.close()
                            except Exception:
                                pass
                        part_runs = _extract_unallocated_bitmap_runs(
                            bm_bytes=bm_bytes,
                            cluster_size=cluster_size,
                            vol_offset=int(vol_offset),
                            vol_size=int(vol_size or media_size),
                            media_size=media_size,
                        )
                        runs.extend(part_runs)
                except Exception:
                    runs = []
                finally:
                    _close_dissect_target(target)

            if not runs and HAS_PYTSK3 and source_path.suffix.lower() not in {".e01", ".ex01", ".vmdk", ".vhd", ".vhdx"}:
                img = None
                vol = None
                fs_info = None
                bm_file = None
                try:
                    img = pytsk3.Img_Info(str(source_path))
                    offsets_to_try: List[int] = []
                    try:
                        vol = pytsk3.Volume_Info(img)
                        block_sz = int(getattr(vol.info, "block_size", 512) or 512)
                        for part in vol:
                            if part.len > 0 and not (part.flags & pytsk3.TSK_VS_PART_FLAG_META):
                                offsets_to_try.append(int(part.start) * block_sz)
                    except Exception:
                        offsets_to_try = [0]

                    for v_off in offsets_to_try:
                        try:
                            fs_info = pytsk3.FS_Info(img, offset=v_off)
                            if fs_info.info.ftype not in (pytsk3.TSK_FS_TYPE_NTFS, pytsk3.TSK_FS_TYPE_NTFS_DETECT):
                                continue
                            cluster_sz = int(fs_info.info.block_size)
                            total_blocks = int(fs_info.info.block_count)
                            bm_file = fs_info.open_meta(inode=6)
                            bm_size = int(bm_file.info.meta.size)
                            if bm_size > 0:
                                bm_bytes = bm_file.read_random(0, bm_size)
                                runs.extend(
                                    _extract_unallocated_bitmap_runs(
                                        bm_bytes=bm_bytes,
                                        cluster_size=cluster_sz,
                                        vol_offset=v_off,
                                        vol_size=total_blocks * cluster_sz,
                                        media_size=media_size,
                                    )
                                )
                        except Exception:
                            continue
                except Exception:
                    pass
                finally:
                    bm_file = None
                    fs_info = None
                    vol = None
                    if img is not None:
                        try:
                            img.close()
                        except Exception:
                            pass
                        img = None

        return runs

    def _compute_allocated_hashes(self, staging_dir: Optional[Path], workers: int) -> Set[str]:
        if staging_dir is None or not staging_dir.is_dir():
            return set()

        cand_files: List[Path] = []
        for root, dirs, files in os.walk(staging_dir):
            dirs[:] = [d for d in dirs if d.lower() not in ("vss", "recyclebin", "$recycle.bin", "carved")]
            for fn in files:
                fn_low = fn.lower()
                if fn_low.endswith((".duckdb", ".duckdb.wal", ".duckdb.tmp")) or ".duckdb." in fn_low:
                    continue
                fp = Path(root) / fn
                try:
                    st = fp.stat()
                    if 0 < st.st_size <= MAX_CARVE_SIZE:
                        cand_files.append(fp)
                except OSError:
                    continue

        if not cand_files:
            return set()

        def _hash_one(p: Path) -> Optional[str]:
            try:
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    while True:
                        blk = f.read(262144)
                        if not blk:
                            break
                        h.update(blk)
                return h.hexdigest()
            except OSError:
                return None

        hashes: Set[str] = set()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for digest in ex.map(_hash_one, cand_files):
                if digest:
                    hashes.add(digest)
        return hashes

    def _scan_window(
        self,
        win: _ScanWindow,
        streams: Dict[str, _ThreadSafeStream],
    ) -> List[_CarveCandidate]:
        stream = streams[win.stream_key]
        primary_len = win.c_end - win.c_start
        if primary_len <= 0:
            return []

        buf = stream.read_at(win.c_start, min(win.hard_limit - win.c_start, primary_len + HEADER_OVERLAP))
        if not buf:
            return []

        hits: List[_CarveCandidate] = []

        def _make_reader(abs_offset: int, max_len: int) -> Callable[[int], bytes]:
            avail = max(0, min(max_len, win.hard_limit - abs_offset))

            def _reader(req_len: int) -> bytes:
                take = min(req_len, avail)
                if take <= 0:
                    return b""
                rel = abs_offset - win.c_start
                if 0 <= rel and rel + take <= len(buf):
                    return buf[rel : rel + take]
                return stream.read_at(abs_offset, take)

            return _reader

        # 1. JPEG (FFD8FF)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_JPG, pos)
            if idx < 0 or idx >= primary_len:
                break
            if idx + 4 <= len(buf):
                b3 = buf[idx + 3]
                if 0xC0 <= b3 <= 0xFE and b3 not in (0xD8, 0xD9, 0xFF):
                    abs_off = win.c_start + idx
                    reader = _make_reader(abs_off, MAX_JPG_SIZE)
                    # Read adaptive initial window before full 25 MiB read
                    sub = reader(2 * 1024 * 1024)
                    blob = _validate_jpeg(sub)
                    if blob is None and len(sub) == 2 * 1024 * 1024:
                        blob = _validate_jpeg(reader(MAX_JPG_SIZE))
                    if blob is not None:
                        hits.append(
                            _CarveCandidate(
                                file_type="jpg",
                                extension="jpg",
                                offset_bytes=abs_off,
                                size_bytes=len(blob),
                                header_sig="FFD8FF",
                                source_region=win.source_region,
                                stream_key=win.stream_key,
                                sha256=hashlib.sha256(blob).hexdigest(),
                                blob=blob if len(blob) <= 524288 else None,
                            )
                        )
                        pos = idx + len(blob)
                        continue
                    # If outer JPEG failed (e.g. truncated photo missing FFD9) and starts with EXIF APP1
                    # (or JFIF APP0 followed by EXIF APP1), skip past the APP1 segment so embedded EXIF
                    # thumbnails inside truncated photos are never carved as standalone false positives.
                    if len(sub) >= 12 and sub[:4] == b"\xff\xd8\xff\xe1" and sub[6:12] == b"Exif\x00\x00":
                        app1_len = struct.unpack_from(">H", sub, 4)[0]
                        if app1_len >= 8:
                            pos = idx + 4 + app1_len
                            continue
                    elif len(sub) >= 20 and sub[:4] == b"\xff\xd8\xff\xe0":
                        app0_len = struct.unpack_from(">H", sub, 4)[0]
                        nxt_m = 4 + app0_len
                        if app0_len >= 2 and nxt_m + 10 <= len(sub) and sub[nxt_m : nxt_m + 2] == b"\xff\xe1" and sub[nxt_m + 4 : nxt_m + 10] == b"Exif\x00\x00":
                            app1_len = struct.unpack_from(">H", sub, nxt_m + 2)[0]
                            if app1_len >= 8:
                                pos = idx + nxt_m + 2 + app1_len
                                continue
            pos = idx + 1

        # 2. PNG (89504E470D0A1A0A)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_PNG, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_off = win.c_start + idx
            reader = _make_reader(abs_off, MAX_PNG_SIZE)
            sub = reader(4 * 1024 * 1024)
            blob = _validate_png(sub)
            if blob is None and len(sub) == 4 * 1024 * 1024:
                blob = _validate_png(reader(MAX_PNG_SIZE))
            if blob is not None:
                hits.append(
                    _CarveCandidate(
                        file_type="png",
                        extension="png",
                        offset_bytes=abs_off,
                        size_bytes=len(blob),
                        header_sig="89504E470D0A1A0A",
                        source_region=win.source_region,
                        stream_key=win.stream_key,
                        sha256=hashlib.sha256(blob).hexdigest(),
                        blob=blob if len(blob) <= 524288 else None,
                    )
                )
            pos = idx + 1

        # 3. GIF (GIF87a / GIF89a)
        for gif_sig in (SIG_GIF87, SIG_GIF89):
            pos = 0
            while pos < primary_len:
                idx = buf.find(gif_sig, pos)
                if idx < 0 or idx >= primary_len:
                    break
                abs_off = win.c_start + idx
                reader = _make_reader(abs_off, MAX_GIF_SIZE)
                sub = reader(2 * 1024 * 1024)
                blob = _validate_gif(sub)
                if blob is None and len(sub) == 2 * 1024 * 1024:
                    blob = _validate_gif(reader(MAX_GIF_SIZE))
                if blob is not None:
                    hits.append(
                        _CarveCandidate(
                            file_type="gif",
                            extension="gif",
                            offset_bytes=abs_off,
                            size_bytes=len(blob),
                            header_sig="47494638",
                            source_region=win.source_region,
                            stream_key=win.stream_key,
                            sha256=hashlib.sha256(blob).hexdigest(),
                            blob=blob if len(blob) <= 524288 else None,
                        )
                    )
                pos = idx + 1

        # 4. PDF (%PDF-1. / %PDF-2.)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_PDF, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_off = win.c_start + idx
            reader = _make_reader(abs_off, MAX_PDF_SIZE)
            hdr8 = reader(16)
            if len(hdr8) >= 8 and hdr8[5:7] in (b"1.", b"2.") and (48 <= hdr8[7] <= 57):
                sub = reader(4 * 1024 * 1024)
                blob = _validate_pdf(sub)
                if blob is None and len(sub) == 4 * 1024 * 1024:
                    blob = _validate_pdf(reader(MAX_PDF_SIZE))
                if blob is not None:
                    hits.append(
                        _CarveCandidate(
                            file_type="pdf",
                            extension="pdf",
                            offset_bytes=abs_off,
                            size_bytes=len(blob),
                            header_sig="255044462D",
                            source_region=win.source_region,
                            stream_key=win.stream_key,
                            sha256=hashlib.sha256(blob).hexdigest(),
                            blob=blob if len(blob) <= 524288 else None,
                        )
                    )
            pos = idx + 1

        # 5. ZIP / DOCX / XLSX / PPTX via EOCD (PK\x05\x06)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_EOCD, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_eocd = win.c_start + idx
            eocd = buf[idx : idx + 22] if idx + 22 <= len(buf) else stream.read_at(abs_eocd, 22)
            if len(eocd) == 22:
                disk_no, cd_disk, _ent_d, ent_tot, cd_size, cd_off, cmt_len = struct.unpack_from(
                    "<HHHHIIH", eocd, 4
                )
                if disk_no == 0 and cd_disk == 0 and ent_tot >= 1 and cd_size >= 46:
                    z_start = abs_eocd - (cd_size + cd_off)
                    z_end = abs_eocd + 22 + cmt_len
                    z_len = z_end - z_start
                    if (
                        win.region_min_offset <= z_start < abs_eocd
                        and z_end <= win.hard_limit
                        and 30 <= z_len <= MAX_ZIP_SIZE
                    ):
                        local_hdr = (
                            buf[z_start - win.c_start : z_start - win.c_start + 4]
                            if (win.c_start <= z_start and (z_start - win.c_start + 4) <= len(buf))
                            else stream.read_at(z_start, 4)
                        )
                        if local_hdr == SIG_ZIP_LOCAL:
                            rel_s = z_start - win.c_start
                            blob = (
                                buf[rel_s : rel_s + z_len]
                                if (0 <= rel_s and rel_s + z_len <= len(buf))
                                else stream.read_at(z_start, z_len)
                            )
                            if len(blob) == z_len:
                                cls_res = _validate_zip_ooxml(blob)
                                if cls_res is not None:
                                    ftype, ext = cls_res
                                    hits.append(
                                        _CarveCandidate(
                                            file_type=ftype,
                                            extension=ext,
                                            offset_bytes=z_start,
                                            size_bytes=z_len,
                                            header_sig="504B0304",
                                            source_region=win.source_region,
                                            stream_key=win.stream_key,
                                            sha256=hashlib.sha256(blob).hexdigest(),
                                            blob=blob if z_len <= 524288 else None,
                                        )
                                    )
            pos = idx + 1

        # 6. SQLite 3 (SQLite format 3\x00)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_SQLITE, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_off = win.c_start + idx
            blob = _validate_sqlite(_make_reader(abs_off, MAX_SQLITE_SIZE))
            if blob is not None:
                hits.append(
                    _CarveCandidate(
                        file_type="sqlite",
                        extension="sqlite",
                        offset_bytes=abs_off,
                        size_bytes=len(blob),
                        header_sig="53514C69746520666F726D6174203300",
                        source_region=win.source_region,
                        stream_key=win.stream_key,
                        sha256=hashlib.sha256(blob).hexdigest(),
                        blob=blob if len(blob) <= 524288 else None,
                    )
                )
            pos = idx + 1

        # 7. EVTX (ElfFile\x00)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_EVTX, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_off = win.c_start + idx
            blob = _validate_evtx(_make_reader(abs_off, MAX_EVTX_SIZE))
            if blob is not None:
                hits.append(
                    _CarveCandidate(
                        file_type="evtx",
                        extension="evtx",
                        offset_bytes=abs_off,
                        size_bytes=len(blob),
                        header_sig="456C6646696C6500",
                        source_region=win.source_region,
                        stream_key=win.stream_key,
                        sha256=hashlib.sha256(blob).hexdigest(),
                        blob=blob if len(blob) <= 524288 else None,
                    )
                )
            pos = idx + 1

        # 8. Registry Hive (regf)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_REGF, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_off = win.c_start + idx
            blob = _validate_regf(_make_reader(abs_off, MAX_REGF_SIZE))
            if blob is not None:
                hits.append(
                    _CarveCandidate(
                        file_type="regf",
                        extension="regf",
                        offset_bytes=abs_off,
                        size_bytes=len(blob),
                        header_sig="72656766",
                        source_region=win.source_region,
                        stream_key=win.stream_key,
                        sha256=hashlib.sha256(blob).hexdigest(),
                        blob=blob if len(blob) <= 524288 else None,
                    )
                )
            pos = idx + 1

        # 9. PE Executable / DLL (MZ + fast O(1) e_lfanew/PE\0\0/Machine pre-filter)
        if HAS_PEFILE:
            pos = 0
            while pos < primary_len:
                idx = buf.find(SIG_MZ, pos)
                if idx < 0 or idx >= primary_len:
                    break
                abs_off = win.c_start + idx
                e_lfanew = -1
                reader_pe: Optional[Callable[[int], bytes]] = None
                if idx + 0x40 <= len(buf):
                    e_lfanew = struct.unpack_from("<I", buf, idx + 0x3C)[0]
                else:
                    reader_pe = _make_reader(abs_off, MAX_PE_SIZE)
                    mz_hdr = reader_pe(0x40)
                    if len(mz_hdr) >= 0x40:
                        e_lfanew = struct.unpack_from("<I", mz_hdr, 0x3C)[0]
                if 0x40 <= e_lfanew <= 0x1000:
                    reader = reader_pe if reader_pe is not None else _make_reader(abs_off, MAX_PE_SIZE)
                    quick_hdr = (
                        buf[idx : idx + e_lfanew + 24]
                        if (idx + e_lfanew + 24) <= len(buf)
                        else reader(e_lfanew + 24)
                    )
                    pe_res = _validate_pe(reader, quick_hdr)
                    if pe_res is not None:
                        ext, blob = pe_res
                        hits.append(
                            _CarveCandidate(
                                file_type=ext,
                                extension=ext,
                                offset_bytes=abs_off,
                                size_bytes=len(blob),
                                header_sig="4D5A",
                                source_region=win.source_region,
                                stream_key=win.stream_key,
                                sha256=hashlib.sha256(blob).hexdigest(),
                                blob=blob if len(blob) <= 524288 else None,
                            )
                        )
                pos = idx + 1

        # 10. Windows Shell Link LNK (4C000000 + CLSID)
        pos = 0
        while pos < primary_len:
            idx = buf.find(SIG_LNK, pos)
            if idx < 0 or idx >= primary_len:
                break
            abs_off = win.c_start + idx
            reader = _make_reader(abs_off, MAX_LNK_SIZE)
            sub = reader(65536)
            blob = _validate_lnk(sub)
            if blob is None and len(sub) == 65536:
                blob = _validate_lnk(reader(MAX_LNK_SIZE))
            if blob is not None:
                hits.append(
                    _CarveCandidate(
                        file_type="lnk",
                        extension="lnk",
                        offset_bytes=abs_off,
                        size_bytes=len(blob),
                        header_sig="4C000000",
                        source_region=win.source_region,
                        stream_key=win.stream_key,
                        sha256=hashlib.sha256(blob).hexdigest(),
                        blob=blob,
                    )
                )
            pos = idx + 1

        return hits

    def _suppress_nested_zips(self, candidates: List[_CarveCandidate]) -> List[_CarveCandidate]:
        """Suppress sub-ZIP fragments inside outer ZIP/OOXML archives and EXIF thumbnails inside outer JPEGs."""
        intervals_by_group: Dict[Tuple[str, str], List[Tuple[int, int]]] = {}
        for c in candidates:
            grp = "zip" if c.file_type in ZIP_FAMILY_TYPES else ("jpg" if c.file_type == "jpg" else "")
            if grp:
                intervals_by_group.setdefault((c.stream_key, grp), []).append(
                    (c.offset_bytes, c.offset_bytes + c.size_bytes)
                )

        if not intervals_by_group:
            return candidates

        for k in intervals_by_group:
            intervals_by_group[k].sort(key=lambda iv: (iv[0], -iv[1]))

        filtered: List[_CarveCandidate] = []
        for c in candidates:
            grp = "zip" if c.file_type in ZIP_FAMILY_TYPES else ("jpg" if c.file_type == "jpg" else "")
            if not grp:
                filtered.append(c)
                continue
            z_s = c.offset_bytes
            z_e = c.offset_bytes + c.size_bytes
            nested = False
            for o_s, o_e in intervals_by_group.get((c.stream_key, grp), []):
                if o_s > z_s:
                    break
                if o_s <= z_s and z_e <= o_e and (z_s > o_s or z_e < o_e):
                    nested = True
                    break
            if not nested:
                filtered.append(c)
        return filtered

    def _persist_records(self, records: List[Dict[str, Any]], duration_ms: int) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS parsed_carved_files (
            _row_id BIGINT,
            carve_id VARCHAR,
            file_name VARCHAR,
            file_type VARCHAR,
            extension VARCHAR,
            mime_type VARCHAR,
            offset_bytes BIGINT,
            byte_offset BIGINT,
            sector_offset BIGINT,
            partition_index INTEGER,
            size_bytes BIGINT,
            sha256 VARCHAR,
            md5 VARCHAR,
            carved_rel_path VARCHAR,
            carved_path VARCHAR,
            source_region VARCHAR,
            source_evidence VARCHAR,
            is_unallocated BOOLEAN,
            header_sig VARCHAR,
            validated BOOLEAN,
            timestamp_utc TIMESTAMP,
            carved_at TIMESTAMP
        );
        """
        required_col_defs = [
            ("carve_id", "VARCHAR"),
            ("file_type", "VARCHAR"),
            ("extension", "VARCHAR"),
            ("offset_bytes", "BIGINT"),
            ("size_bytes", "BIGINT"),
            ("sha256", "VARCHAR"),
            ("carved_rel_path", "VARCHAR"),
            ("source_region", "VARCHAR"),
            ("header_sig", "VARCHAR"),
            ("validated", "BOOLEAN"),
            ("file_name", "VARCHAR"),
            ("mime_type", "VARCHAR"),
            ("byte_offset", "BIGINT"),
            ("sector_offset", "BIGINT"),
            ("carved_path", "VARCHAR"),
            ("is_unallocated", "BOOLEAN"),
            ("source_evidence", "VARCHAR"),
        ]
        all_supported_cols = [c for c, _ in required_col_defs]

        with self._acquire_lock():
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(ddl)

            desc_rows = cur.execute("DESCRIBE parsed_carved_files;").fetchall()
            existing_cols_lower = {str(r[0]).lower(): str(r[0]) for r in desc_rows}
            for col_name, col_type in required_col_defs:
                if col_name.lower() not in existing_cols_lower:
                    try:
                        cur.execute(
                            f'ALTER TABLE parsed_carved_files ADD COLUMN "{col_name}" {col_type};'
                        )
                    except Exception:
                        pass

            cur.execute("DELETE FROM parsed_carved_files;")

            desc_rows = cur.execute("DESCRIBE parsed_carved_files;").fetchall()
            existing_cols = [str(r[0]) for r in desc_rows]
            has_row_id = "_row_id" in existing_cols

            if records:
                data_cols = [c for c in all_supported_cols if c in existing_cols and c in records[0]]
                if has_row_id:
                    ins_cols = ["_row_id"] + data_cols
                    placeholders = ", ".join(["?"] * len(ins_cols))
                    col_sql = ", ".join(f'"{c}"' for c in ins_cols)
                    rows_data = [
                        tuple([idx] + [rec.get(c) for c in data_cols])
                        for idx, rec in enumerate(records, start=1)
                    ]
                else:
                    ins_cols = data_cols
                    placeholders = ", ".join(["?"] * len(ins_cols))
                    col_sql = ", ".join(f'"{c}"' for c in ins_cols)
                    rows_data = [tuple(rec.get(c) for c in ins_cols) for rec in records]

                cur.executemany(
                    f"INSERT INTO parsed_carved_files ({col_sql}) VALUES ({placeholders});",
                    rows_data,
                )

            tables = {
                r[0]
                for r in cur.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                ).fetchall()
            }
            if "artifact_registry" in tables:
                try:
                    existing_art = cur.execute(
                        "SELECT artifact_id FROM artifact_registry WHERE table_name = 'parsed_carved_files' LIMIT 1;"
                    ).fetchone()
                    art_id = existing_art[0] if existing_art else "carve_files"
                    cur.execute(
                        """
                        INSERT INTO artifact_registry (
                            artifact_id, category, display_name, table_name, source_tool, row_count, last_updated
                        ) VALUES (?, 'OPERATING SYSTEM', 'Carved Files (Unallocated & Raw)', 'parsed_carved_files', 'DataCarver', ?, CURRENT_TIMESTAMP)
                        ON CONFLICT (artifact_id) DO UPDATE SET
                            category = EXCLUDED.category,
                            display_name = EXCLUDED.display_name,
                            table_name = EXCLUDED.table_name,
                            source_tool = EXCLUDED.source_tool,
                            row_count = EXCLUDED.row_count,
                            last_updated = now();
                        """,
                        [art_id, len(records)],
                    )
                except Exception:
                    pass

            if "processing_logs" in tables and self.db_manager is DuckDBManager:
                try:
                    log_processing_event(
                        case_id=self.case_id,
                        module_name="Parser:DataCarver",
                        command_executed=f"DataCarver.run(carved={len(records)})",
                        exit_code=0,
                        rows_ingested=len(records),
                        duration_ms=duration_ms,
                        status="SUCCESS",
                    )
                except Exception:
                    pass

    def run(
        self,
        source_path: Path,
        staging_dir: Optional[Path] = None,
        max_workers: int = 16,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        workers = max(1, min(int(max_workers or 16), 32))
        src = Path(source_path).resolve()

        shutil.rmtree(self.carved_dir, ignore_errors=True)
        self.carved_dir.mkdir(parents=True, exist_ok=True)

        if not src.exists():
            duration_ms = int((time.perf_counter() - t0) * 1000)
            self._persist_records([], duration_ms)
            return {
                "status": "SKIPPED",
                "carved_count": 0,
                "by_type": {},
                "source_regions": [],
                "duration_ms": duration_ms,
                "carved_dir": str(self.carved_dir),
            }

        streams: Dict[str, _ThreadSafeStream] = {}
        windows: List[_ScanWindow] = []
        allocated_hashes: Set[str] = set()
        regions_seen: Set[str] = set()

        try:
            if src.is_dir():
                for root, dirs, files in os.walk(src):
                    root_p = Path(root).resolve()
                    if root_p == self.carved_dir or self.carved_dir in root_p.parents:
                        dirs[:] = []
                        continue
                    dirs[:] = [
                        d
                        for d in dirs
                        if (root_p / d).resolve() != self.carved_dir
                    ]
                    for fn in sorted(files):
                        fn_low = fn.lower()
                        if fn_low.endswith((".duckdb", ".duckdb.wal", ".duckdb.tmp", ".duckdb-wal", ".duckdb-shm")) or ".duckdb." in fn_low:
                            continue
                        fp = (root_p / fn).resolve()
                        try:
                            fsize = fp.stat().st_size
                        except OSError:
                            continue
                        if fsize < 30:
                            continue
                        rel_posix = fp.relative_to(src).as_posix()
                        region_tag = f"directory_file:{rel_posix}"
                        s_key = str(fp)
                        st_inst = _ThreadSafeStream(fp)
                        if st_inst.size < 30:
                            st_inst.close()
                            continue
                        streams[s_key] = st_inst
                        regions_seen.add(region_tag)
                        for off in range(0, st_inst.size, CHUNK_SIZE):
                            windows.append(
                                _ScanWindow(
                                    stream_key=s_key,
                                    c_start=off,
                                    c_end=min(st_inst.size, off + CHUNK_SIZE),
                                    region_min_offset=0,
                                    hard_limit=st_inst.size,
                                    source_region=region_tag,
                                )
                            )
            else:
                s_key = str(src)
                main_stream = _ThreadSafeStream(src)
                streams[s_key] = main_stream
                media_size = main_stream.size

                ntfs_runs = self._discover_ntfs_unallocated_runs(src, media_size)
                total_unalloc = sum(r_e - r_s for r_s, r_e in ntfs_runs)
                allocated_hashes = self._compute_allocated_hashes(staging_dir, workers)

                # Adaptive chunk size: For large disk images (> 16 GB), scale chunk size up from 8 MiB to 16/32 MiB
                # to optimize I/O block size, reduce seek penalties, and accelerate multi-threaded scanning
                eff_chunk = 32 * 1024 * 1024 if media_size > 64 * 1024 * 1024 * 1024 else (16 * 1024 * 1024 if media_size > 16 * 1024 * 1024 * 1024 else CHUNK_SIZE)

                if ntfs_runs and total_unalloc >= 512:
                    region_tag = "unallocated_ntfs"
                    regions_seen.add(region_tag)
                    for r_start, r_end in ntfs_runs:
                        for off in range(r_start, r_end, eff_chunk):
                            windows.append(
                                _ScanWindow(
                                    stream_key=s_key,
                                    c_start=off,
                                    c_end=min(r_end, off + eff_chunk),
                                    region_min_offset=r_start,
                                    hard_limit=r_end,
                                    source_region=region_tag,
                                )
                            )
                else:
                    region_tag = "raw_stream"
                    regions_seen.add(region_tag)
                    for off in range(0, media_size, eff_chunk):
                        windows.append(
                            _ScanWindow(
                                stream_key=s_key,
                                c_start=off,
                                c_end=min(media_size, off + eff_chunk),
                                region_min_offset=0,
                                hard_limit=media_size,
                                source_region=region_tag,
                            )
                        )

            all_candidates: List[_CarveCandidate] = []
            if windows:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(self._scan_window, w, streams) for w in windows]
                    for fut in as_completed(futures):
                        batch = fut.result()
                        if batch:
                            all_candidates.extend(batch)

            all_candidates.sort(
                key=lambda c: (c.source_region, c.offset_bytes, -c.size_bytes, c.file_type)
            )
            all_candidates = self._suppress_nested_zips(all_candidates)

            seen_hashes: Set[str] = set(allocated_hashes)
            seen_spans: Set[Tuple[str, int, int]] = set()
            records: List[Dict[str, Any]] = []
            counts_by_type: Dict[str, int] = {}
            carve_idx = 0

            for cand in all_candidates:
                span_key = (cand.stream_key, cand.offset_bytes, cand.size_bytes)
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)

                if cand.sha256 in seen_hashes:
                    continue
                seen_hashes.add(cand.sha256)

                carve_idx += 1
                carve_id = f"carve_{carve_idx:06d}"
                ext = cand.extension
                ext_dir = self.carved_dir / ext
                ext_dir.mkdir(parents=True, exist_ok=True)
                out_file = ext_dir / f"{carve_id}.{ext}"

                data_bytes = (
                    cand.blob
                    if cand.blob is not None
                    else streams[cand.stream_key].read_at(cand.offset_bytes, cand.size_bytes)
                )
                out_file.write_bytes(data_bytes)

                carved_rel_path = f"carved/{ext}/{carve_id}.{ext}"
                counts_by_type[cand.file_type] = counts_by_type.get(cand.file_type, 0) + 1
                mime_map = {
                    "jpg": "image/jpeg",
                    "png": "image/png",
                    "gif": "image/gif",
                    "pdf": "application/pdf",
                    "zip": "application/zip",
                    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "sqlite": "application/vnd.sqlite3",
                    "evtx": "application/x-ms-evtx",
                    "regf": "application/x-ms-regf",
                    "exe": "application/x-dosexec",
                    "dll": "application/x-dosexec",
                    "lnk": "application/x-ms-shortcut",
                }
                records.append(
                    {
                        "carve_id": carved_id_str(carve_id),
                        "file_name": f"{carve_id}.{ext}",
                        "file_type": cand.file_type,
                        "extension": ext,
                        "mime_type": mime_map.get(ext, "application/octet-stream"),
                        "offset_bytes": int(cand.offset_bytes),
                        "byte_offset": int(cand.offset_bytes),
                        "sector_offset": int(cand.offset_bytes) // 512,
                        "size_bytes": int(cand.size_bytes),
                        "sha256": cand.sha256,
                        "carved_rel_path": carved_rel_path,
                        "carved_path": carved_rel_path,
                        "source_region": cand.source_region,
                        "source_evidence": cand.source_region,
                        "is_unallocated": cand.source_region == "unallocated_ntfs",
                        "header_sig": cand.header_sig,
                        "validated": True,
                    }
                )

            for st_obj in list(streams.values()):
                st_obj.close()
            streams.clear()

            duration_ms = int((time.perf_counter() - t0) * 1000)
            self._persist_records(records, duration_ms)

            return {
                "status": "SUCCESS",
                "carved_count": len(records),
                "by_type": counts_by_type,
                "source_regions": sorted(regions_seen),
                "duration_ms": duration_ms,
                "carved_dir": str(self.carved_dir),
            }
        finally:
            for st_obj in list(streams.values()):
                st_obj.close()
            streams.clear()


def carved_id_str(val: str) -> str:
    return str(val)
