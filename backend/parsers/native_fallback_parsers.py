"""
WFT v4.0 - Native Fallback & Magnet AXIOM OS/Registry Parsers
Provides pure-Python forensic fallbacks when external CLI tools are absent or return 0 rows,
plus offline Registry/OS parsers (`regipy` + `dissect.regf` + `dissect.esedb`) populating all
8 Magnet AXIOM OS/Registry artifact tables with thread-safe DuckDB serialization.
"""
from __future__ import annotations

import codecs
import hashlib
import math
import os
import re
import struct
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import (
    BaseParser,
    _parse_str_to_utc_naive,
    windows_filetime_to_datetime,
)

try:
    from dissect.util.compression import lzxpress_huffman
except ImportError:  # pragma: no cover
    lzxpress_huffman = None  # type: ignore[assignment]

try:
    from dissect.eventlog.evtx import Evtx as DissectEvtx
except ImportError:  # pragma: no cover
    DissectEvtx = None  # type: ignore[assignment]

try:
    import Evtx.Evtx as PyEvtxMod
except ImportError:  # pragma: no cover
    PyEvtxMod = None  # type: ignore[assignment]

try:
    from dissect.esedb import EseDB
except ImportError:  # pragma: no cover
    EseDB = None  # type: ignore[assignment]

try:
    from regipy.registry import RegistryHive as RegipyHive
except ImportError:  # pragma: no cover
    RegipyHive = None  # type: ignore[assignment]

try:
    from dissect.regf import RegistryHive as DissectRegfHive
except ImportError:  # pragma: no cover
    DissectRegfHive = None  # type: ignore[assignment]


_SIDE_CAR_SUFFIXES = (
    ".log",
    ".log1",
    ".log2",
    ".blf",
    ".regtrans-ms",
    ".sav",
    ".bak",
    ".csv",
    ".txt",
    ".json",
    ".xml",
)

_KNOWN_FOLDER_GUIDS: Dict[str, str] = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": r"%SystemRoot%\System32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": r"%SystemRoot%\SysWOW64",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": r"%SystemRoot%",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": r"%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": r"%ProgramFiles(x86)%",
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": r"%ProgramFiles%",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": r"%ProgramData%\Microsoft\Windows\Start Menu\Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": r"%APPDATA%\Microsoft\Windows\Start Menu\Programs",
}

_ACB_FLAG_LABELS: Tuple[Tuple[int, str], ...] = (
    (0x0001, "AccountDisabled"),
    (0x0002, "HomeDirRequired"),
    (0x0004, "PasswordNotRequired"),
    (0x0008, "TempDuplicateAccount"),
    (0x0010, "NormalUserAccount"),
    (0x0020, "MnsLogonAccount"),
    (0x0040, "InterdomainTrustAccount"),
    (0x0080, "WorkstationTrustAccount"),
    (0x0100, "ServerTrustAccount"),
    (0x0200, "PasswordNeverExpires"),
    (0x0400, "AutoLocked"),
)

_SERVICE_START_TYPES: Dict[int, str] = {
    0: "Boot",
    1: "System",
    2: "Auto",
    3: "Manual",
    4: "Disabled",
}

_SERVICE_TYPES: Dict[int, str] = {
    0x001: "Kernel Driver",
    0x002: "File System Driver",
    0x004: "Adapter",
    0x008: "Recognizer Driver",
    0x010: "Win32 Own Process",
    0x020: "Win32 Share Process",
    0x110: "Win32 Own Process (Interactive)",
    0x120: "Win32 Share Process (Interactive)",
}


@dataclass(frozen=True)
class HiveTarget:
    path: Path
    hive_type: str
    username: Optional[str]
    provenance: str
    display_source: str


@dataclass
class RegValueItem:
    name: str
    value: Any
    raw_bytes: Optional[bytes]
    value_type: str


class _RegKeyAdapter:
    """Normalized read-only wrapper over a `regipy` NKRecord or `dissect.regf` key."""

    def __init__(self, backend: str, raw_key: Any, path_str: str) -> None:
        self._backend = backend
        self._key = raw_key
        self.path = path_str

    @property
    def name(self) -> str:
        try:
            return str(self._key.name)
        except Exception:
            return ""

    @property
    def last_modified(self) -> Optional[datetime]:
        try:
            if self._backend == "regipy":
                ft = getattr(self._key.header, "last_modified", None)
                if isinstance(ft, int):
                    return windows_filetime_to_datetime(ft)
                if isinstance(ft, datetime):
                    return ft if ft.tzinfo else ft.replace(tzinfo=timezone.utc)
            else:
                ts = getattr(self._key, "timestamp", None)
                if isinstance(ts, datetime):
                    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
                if isinstance(ts, int):
                    return windows_filetime_to_datetime(ts)
        except Exception:
            pass
        return None

    def iter_subkeys(self) -> List["_RegKeyAdapter"]:
        out: List[_RegKeyAdapter] = []
        try:
            if self._backend == "regipy":
                subs = self._key.iter_subkeys() or []
                for sk in subs:
                    sk_name = str(getattr(sk, "name", ""))
                    child_p = f"{self.path}\\{sk_name}".strip("\\")
                    out.append(_RegKeyAdapter("regipy", sk, child_p))
            else:
                for sk in self._key.subkeys():
                    sk_name = str(getattr(sk, "name", ""))
                    child_p = f"{self.path}\\{sk_name}".strip("\\")
                    out.append(_RegKeyAdapter("dissect", sk, child_p))
        except Exception:
            pass
        return out

    def get_subkey(self, child_name: str) -> Optional["_RegKeyAdapter"]:
        target_low = child_name.lower()
        for sk in self.iter_subkeys():
            if sk.name.lower() == target_low:
                return sk
        return None

    def iter_values(self) -> List[RegValueItem]:
        items: List[RegValueItem] = []
        try:
            if self._backend == "regipy":
                # CRITICAL: trim_values=False preserves full REG_BINARY bytes instead of 256-char hex!
                for v in (self._key.iter_values(trim_values=False) or []):
                    vname = str(getattr(v, "name", "") or "")
                    vtype = str(getattr(v, "value_type", "") or "")
                    val = getattr(v, "value", None)
                    raw_b: Optional[bytes] = None
                    if isinstance(val, (bytes, bytearray, memoryview)):
                        raw_b = bytes(val)
                    items.append(RegValueItem(name=vname, value=val, raw_bytes=raw_b, value_type=vtype))
            else:
                for v in self._key.values():
                    vname = str(getattr(v, "name", "") or "(default)")
                    raw_d = getattr(v, "data", None)
                    raw_b = bytes(raw_d) if isinstance(raw_d, (bytes, bytearray, memoryview)) else None
                    try:
                        val = v.value
                    except Exception:
                        val = raw_b
                    vtype = str(getattr(v, "type", "") or "")
                    items.append(RegValueItem(name=vname, value=val, raw_bytes=raw_b, value_type=vtype))
        except Exception:
            pass
        return items

    def value_map(self) -> Dict[str, RegValueItem]:
        return {it.name.lower(): it for it in self.iter_values()}


class _HiveReader:
    """Context-managed offline Registry hive reader (`regipy` primary, `dissect.regf` fallback)."""

    def __init__(self, hive_path: Path) -> None:
        self.hive_path = hive_path
        self._fh: Any = None
        self._backend: Optional[str] = None
        self._hive: Any = None

    def _close_hive_streams(self) -> None:
        if self._hive is not None:
            for attr_name in ("_stream", "stream", "fh", "_fh"):
                st = getattr(self._hive, attr_name, None)
                if st is not None and hasattr(st, "close") and callable(st.close):
                    try:
                        st.close()
                    except Exception:
                        pass
            self._hive = None
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None
        self._backend = None

    def __enter__(self) -> "_HiveReader":
        if RegipyHive is not None:
            try:
                self._hive = RegipyHive(str(self.hive_path))
                _ = self._hive.root
                self._backend = "regipy"
                return self
            except Exception:
                self._close_hive_streams()

        if DissectRegfHive is not None:
            self._fh = open(self.hive_path, "rb")
            try:
                self._hive = DissectRegfHive(self._fh)
                self._backend = "dissect"
                return self
            except Exception:
                self._close_hive_streams()
                raise

        raise RuntimeError(f"Unable to open registry hive: {self.hive_path}")

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._close_hive_streams()

    @property
    def root(self) -> Optional[_RegKeyAdapter]:
        if self._hive is None or self._backend is None:
            return None
        try:
            if self._backend == "regipy":
                return _RegKeyAdapter("regipy", self._hive.root, "")
            return _RegKeyAdapter("dissect", self._hive.root(), "")
        except Exception:
            return None

    def get_key(self, key_path: str) -> Optional[_RegKeyAdapter]:
        if self._hive is None or self._backend is None:
            return None
        clean = key_path.strip("\\")
        if not clean:
            return self.root

        if self._backend == "regipy":
            # CRITICAL: regipy requires leading backslash whenever '\' is in key_path!
            prefixed = "\\" + clean
            try:
                nk = self._hive.get_key(prefixed)
                if nk is not None:
                    return _RegKeyAdapter("regipy", nk, clean)
            except Exception:
                pass
            # Case-insensitive walk fallback for mixed-case keys
            cur = self.root
            for part in clean.split("\\"):
                if cur is None:
                    return None
                cur = cur.get_subkey(part)
            return cur

        try:
            dk = self._hive.open(clean)
            if dk is not None:
                return _RegKeyAdapter("dissect", dk, clean)
        except Exception:
            pass
        cur = self.root
        for part in clean.split("\\"):
            if cur is None:
                return None
            cur = cur.get_subkey(part)
        return cur


def _val_as_str(item: Optional[RegValueItem]) -> Optional[str]:
    if item is None or item.value is None:
        return None
    v = item.value
    if isinstance(v, str):
        s = v.rstrip("\x00").strip()
        return s if s else None
    if isinstance(v, list):
        joined = ", ".join(str(x).rstrip("\x00").strip() for x in v if str(x).strip("\x00").strip())
        return joined if joined else None
    if isinstance(v, (bytes, bytearray)):
        raw = bytes(v)
        if len(raw) >= 2 and len(raw) % 2 == 0:
            s = raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
            if s:
                return s
        s = raw.decode("utf-8", errors="ignore").split("\x00", 1)[0].strip()
        return s if s else None
    s = str(v).strip()
    return s if s else None


def _val_as_int(item: Optional[RegValueItem]) -> Optional[int]:
    if item is None or item.value is None:
        return None
    v = item.value
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if item.raw_bytes and len(item.raw_bytes) >= 4:
        return int(struct.unpack_from("<I", item.raw_bytes, 0)[0])
    try:
        return int(str(v).strip(), 0)
    except Exception:
        return None


def _val_as_bytes(item: Optional[RegValueItem]) -> Optional[bytes]:
    if item is None:
        return None
    if item.raw_bytes is not None:
        return item.raw_bytes
    if isinstance(item.value, (bytes, bytearray, memoryview)):
        return bytes(item.value)
    return None


def _decode_systemtime_16(raw: Optional[bytes], bias_minutes: int = 0) -> Optional[datetime]:
    if not raw or len(raw) < 16:
        return None
    try:
        year, month, _dow, day, hour, minute, second, ms = struct.unpack_from("<8H", raw, 0)
        if year < 1970 or year > 2100 or not (1 <= month <= 12) or not (1 <= day <= 31):
            return None
        dt = datetime(
            year,
            month,
            day,
            min(hour, 23),
            min(minute, 59),
            min(second, 59),
            min(ms, 999) * 1000,
            tzinfo=timezone.utc,
        )
        if bias_minutes:
            dt = dt + timedelta(minutes=bias_minutes)
        return dt
    except Exception:
        return None


def _decode_binary_sid(blob: bytes) -> Optional[str]:
    if not blob or len(blob) < 8:
        return None
    try:
        rev = blob[0]
        sub_cnt = blob[1]
        if rev != 1 or sub_cnt > 15 or len(blob) < 8 + sub_cnt * 4:
            return None
        ident_auth = int.from_bytes(blob[2:8], "big")
        subs = struct.unpack_from(f"<{sub_cnt}I", blob, 8)
        return f"S-{rev}-{ident_auth}-" + "-".join(str(x) for x in subs)
    except Exception:
        return None


def _ole_days_to_datetime(val: Any) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (bytes, bytearray, memoryview)):
        raw_b = bytes(val)
        if len(raw_b) == 8:
            try:
                fval = struct.unpack("<d", raw_b)[0]
                if math.isfinite(fval) and 25569.0 < fval <= 80000.0:
                    return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=fval)
                uval = struct.unpack("<Q", raw_b)[0]
                if 116444736000000000 <= uval <= 210000000000000000:
                    return windows_filetime_to_datetime(uval)
            except Exception:
                return None
        return None
    if isinstance(val, int) and not isinstance(val, bool):
        if abs(val) > 80000:
            # dissect.esedb decodes JET_coltyp.DateTime via c_esedb.int64 (raw IEEE-754 double bits)
            if -(1 << 63) <= val < (1 << 64):
                try:
                    fval = struct.unpack("<d", struct.pack("<q" if val < 0 else "<Q", val))[0]
                    if math.isfinite(fval) and 25569.0 < fval <= 80000.0:
                        return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=fval)
                except Exception:
                    pass
            if 116444736000000000 <= val <= 210000000000000000:
                return windows_filetime_to_datetime(val)
            return None
        fval = float(val)
        if 25569.0 < fval <= 80000.0:
            try:
                return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=fval)
            except Exception:
                return None
        return None
    if isinstance(val, float):
        if not math.isfinite(val) or val <= 25569.0 or val > 80000.0:
            return None
        try:
            return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=val)
        except Exception:
            return None
    return None


def _ese_get(rec: Any, col: str, default: Any = None, raw: bool = False) -> Any:
    """Safely reads an ESE record column without raising KeyError when `col` is absent."""
    if rec is None:
        return default
    getter = getattr(rec, "get", None)
    if not callable(getter):
        return default
    try:
        val = getter(col, raw=raw) if raw else getter(col)
    except TypeError:
        try:
            val = getter(col)
        except (KeyError, IndexError, AttributeError, TypeError, ValueError):
            return default
    except (KeyError, IndexError, AttributeError, ValueError):
        return default
    return default if val is None else val


def _ese_int(rec: Any, *cols: str, default: int = 0) -> int:
    """Safely extracts the first non-None integer column from `rec` without falsy `0` clobbering."""
    for col_name in cols:
        v = _ese_get(rec, col_name)
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                continue
    return default


def _map_evtx_level(level_raw: Any, keywords_raw: Any) -> str:
    lvl: Optional[int] = None
    if level_raw is not None and str(level_raw).strip() != "":
        try:
            lvl = int(str(level_raw).strip(), 0)
        except Exception:
            lvl = None

    kw: int = 0
    if keywords_raw is not None and str(keywords_raw).strip() != "":
        try:
            kw = int(str(keywords_raw).strip(), 0)
        except Exception:
            kw = 0

    if lvl == 1:
        return "Critical"
    if lvl == 2:
        return "Error"
    if lvl == 3:
        return "Warning"
    if lvl == 5:
        return "Verbose"

    if kw & 0x0010000000000000:
        return "Audit Failure"
    if kw & 0x0020000000000000:
        return "Audit Success"
    return "Information"


def _decode_userassist_path(rot13_name: str) -> str:
    decoded = codecs.decode(rot13_name, "rot_13")
    for guid_key, env_prefix in _KNOWN_FOLDER_GUIDS.items():
        if decoded.upper().startswith(guid_key.upper()):
            decoded = env_prefix + decoded[len(guid_key) :]
            break
    return decoded


def _format_acb_flags(acb: int) -> str:
    names = [label for bit, label in _ACB_FLAG_LABELS if (acb & bit)]
    if not names:
        return f"0x{acb:04X}"
    return f"{', '.join(names)} (0x{acb:04X})"


def _extract_pidl_strings(buf: bytes) -> List[str]:
    """Extracts human-readable path segments from a Windows Shell Item ID List (PIDL)."""
    segments: List[str] = []
    pos = 0
    n = len(buf)
    while pos + 2 <= n:
        cb = struct.unpack_from("<H", buf, pos)[0]
        if cb < 2 or pos + cb > n:
            break
        item = buf[pos : pos + cb]
        pos += cb

        # Check drive letter shell item (type 0x2F, e.g. "C:\")
        if len(item) >= 6 and item[2] in (0x23, 0x25, 0x29, 0x2A, 0x2E, 0x2F):
            drv = item[3:6].decode("ascii", errors="ignore").rstrip("\x00").strip()
            if re.match(r"^[A-Za-z]:\\?$", drv):
                segments.append(drv.rstrip("\\"))
                continue

        # Search 0xBEEF0004 extension block for long UTF-16LE filename
        beef_idx = item.find(b"\x04\x00\xef\xbe")
        if beef_idx != -1 and beef_idx >= 4:
            ext_ver = struct.unpack_from("<H", item, beef_idx - 2)[0]
            str_off = beef_idx + 4
            if ext_ver >= 9:
                str_off = beef_idx + 42
            elif ext_ver >= 8:
                str_off = beef_idx + 38
            elif ext_ver >= 7:
                str_off = beef_idx + 34
            elif ext_ver >= 3:
                str_off = beef_idx + 16
            if str_off < len(item):
                long_name = item[str_off:].decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
                if long_name and all(ord(c) >= 32 for c in long_name):
                    segments.append(long_name)
                    continue

        # Fallback: scan ASCII short name at offset 14 for file/folder items (0x31/0x32)
        if len(item) > 14 and (item[2] & 0x70) == 0x30:
            short_s = item[14:].split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
            if short_s and all(32 <= ord(c) < 127 for c in short_s):
                segments.append(short_s)
    return segments


def _extract_recentdocs_names(raw: bytes) -> Tuple[str, str]:
    """Extracts `(primary_name, lnk_name)` from a `RecentDocs` binary value."""
    if not raw:
        return "", ""
    # Null-terminated UTF-16LE target filename starts at offset 0
    end_u16 = 0
    while end_u16 + 2 <= len(raw):
        if raw[end_u16 : end_u16 + 2] == b"\x00\x00":
            break
        end_u16 += 2
    primary = raw[:end_u16].decode("utf-16le", errors="ignore").strip()
    rest = raw[end_u16 + 2 :]
    lnk_name = ""
    pidl_parts = _extract_pidl_strings(rest)
    if pidl_parts:
        lnk_name = "\\".join(pidl_parts)
    return primary, lnk_name


class NativeFallbackParser(BaseParser):
    """
    Pure-Python forensic fallback & Magnet AXIOM OS/Registry artifact parser:
      - Non-destructive pure-Python fallbacks (`raw_pecmd`, `raw_mft`, `raw_evtx`,
        `raw_rbcmd`, `raw_recmd`, `raw_srum_app`, `raw_srum_net`, `raw_srum_conn`)
      - ESE `WebCacheV01.dat` (`parsed_ie_history`) & Google Drive `sync_log.log` (`parsed_gdrive_files`)
      - 8 Magnet AXIOM Registry/OS tables:
        `parsed_user_accounts`, `parsed_windows_services`, `parsed_autoruns`,
        `parsed_userassist`, `parsed_bam_dam`, `parsed_registry_mru`,
        `parsed_network_profiles`, `parsed_wer_reports`
    """

    def _existing_table_count(self, table_name: str) -> int:
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cur = conn.cursor()
            exists = (
                cur.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = ? LIMIT 1;",
                    [table_name],
                ).fetchone()
                is not None
            )
            if not exists:
                return 0
            row = cur.execute(f'SELECT COUNT(*) FROM "{table_name}";').fetchone()
            return int(row[0] or 0) if row else 0

    def _ensure_table_columns(self, table_name: str, create_ddl: str, required_cols: List[Tuple[str, str]]) -> str:
        alter_stmts = [
            f'ALTER TABLE "{table_name}" ADD COLUMN IF NOT EXISTS "{col}" {ctype};'
            for col, ctype in required_cols
        ]
        return create_ddl.strip() + "\n" + "\n".join(alter_stmts)

    def _get_source_timestamps(
        self, file_path: Path
    ) -> Tuple[Optional[datetime], Optional[datetime], Optional[datetime]]:
        """
        Looks up `(created_utc, modified_utc, accessed_utc)` from `vfs_files` first
        (with strict VSS candidate isolation), falling back to `get_original_ctime` /
        `get_original_mtime` (never fabricating wall-clock time or copying mtime into ctime).
        """
        raw_rel = self._raw_staging_rel_posix(file_path)
        inner_rel, vss_idx = self._compute_staging_rel_parts(file_path)
        rel_candidates: List[str] = []
        if vss_idx is not None:
            if raw_rel:
                r_low = raw_rel.strip("/").lower()
                if r_low and r_low not in rel_candidates:
                    rel_candidates.append(r_low)
                with_stg = f"staging/{r_low}"
                if with_stg not in rel_candidates:
                    rel_candidates.append(with_stg)
            if inner_rel:
                in_low = inner_rel.strip("/").lower()
                if in_low:
                    for vc in (
                        f"vss/vss_{vss_idx}/{in_low}",
                        f"staging/vss/vss_{vss_idx}/{in_low}",
                        f"vss_{vss_idx}/{in_low}",
                        f"staging/vss_{vss_idx}/{in_low}",
                    ):
                        if vc not in rel_candidates:
                            rel_candidates.append(vc)
        else:
            for c in (raw_rel, inner_rel):
                if c:
                    c_low = c.strip("/").lower()
                    if c_low and c_low not in rel_candidates:
                        rel_candidates.append(c_low)
                    with_stg = f"staging/{c_low}"
                    if with_stg not in rel_candidates:
                        rel_candidates.append(with_stg)

        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cur = conn.cursor()
                has_vfs = (
                    cur.execute(
                        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = 'vfs_files' LIMIT 1;"
                    ).fetchone()
                    is not None
                )
                if has_vfs and rel_candidates:
                    vfs_cols = {
                        str(r[0]).lower(): str(r[0])
                        for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                    }
                    if "staged_rel_path" in vfs_cols:
                        def _col_or_null(*names: str) -> str:
                            found = [f'"{vfs_cols[n]}"' for n in names if n in vfs_cols]
                            return f"COALESCE({', '.join(found)})" if found else "NULL"

                        cr_expr = _col_or_null("si_created", "si_created_utc", "fn_created", "fn_created_utc")
                        mod_expr = _col_or_null("si_modified", "si_modified_utc", "fn_modified", "fn_modified_utc")
                        acc_expr = _col_or_null("si_accessed", "si_accessed_utc", "fn_accessed", "fn_accessed_utc")
                        q_srp = f'"{vfs_cols["staged_rel_path"]}"'
                        ph = ", ".join(["?"] * len(rel_candidates))
                        row = cur.execute(
                            f"""
                            SELECT {cr_expr}, {mod_expr}, {acc_expr}
                            FROM "vfs_files"
                            WHERE {q_srp} IS NOT NULL
                              AND LOWER(TRIM(BOTH '/' FROM REPLACE({q_srp}, chr(92), '/'))) IN ({ph})
                            LIMIT 1;
                            """,
                            rel_candidates,
                        ).fetchone()
                        if row is not None:
                            def _to_dt(v: Any) -> Optional[datetime]:
                                if isinstance(v, datetime):
                                    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
                                if isinstance(v, str):
                                    dt = _parse_str_to_utc_naive(v)
                                    return dt.replace(tzinfo=timezone.utc) if dt else None
                                return None

                            return _to_dt(row[0]), _to_dt(row[1]), _to_dt(row[2])
        except Exception:
            pass

        def _str_to_utc(ts_str: Optional[str]) -> Optional[datetime]:
            if not ts_str:
                return None
            dt = _parse_str_to_utc_naive(ts_str)
            return dt.replace(tzinfo=timezone.utc) if dt is not None else None

        cr_fallback = _str_to_utc(self.get_original_ctime(file_path))
        mod_fallback = _str_to_utc(self.get_original_mtime(file_path))
        return cr_fallback, mod_fallback, None

    # -------------------------------------------------------------------------
    # Canonical Offline Registry Hive Discovery (clean_hives > staging/Registry + VSS)
    # -------------------------------------------------------------------------
    def _canonicalize_hive_display_source(
        self,
        raw_disp: str,
        hive_type: str,
        username: Optional[str],
        prov: str,
    ) -> str:
        vss_prefix = ""
        if prov != "active":
            m_vn = re.search(r"(\d+)", prov)
            vss_prefix = f"[VSS#{m_vn.group(1)}] " if m_vn else f"[{prov}] "

        cleaned = re.sub(r"^\s*\[VSS[^\]]*\]\s*", "", str(raw_disp or ""), flags=re.IGNORECASE).strip()
        cleaned_norm = cleaned.replace("/", "\\").lower()
        case_norm = str(self.case_dir.resolve()).replace("/", "\\").lower()
        stg_norm = str(self.staging_dir.resolve()).replace("/", "\\").lower()

        needs_canonical = (
            not cleaned
            or cleaned.lower().startswith("[staged]")
            or "clean_hives" in cleaned_norm
            or (case_norm and case_norm in cleaned_norm)
            or (stg_norm and stg_norm in cleaned_norm)
        )
        if needs_canonical:
            ht_up = hive_type.upper()
            uname = username or "Default"
            if ht_up == "NTUSER":
                cleaned = f"C:\\Users\\{uname}\\NTUSER.DAT"
            elif ht_up == "USRCLASS":
                cleaned = f"C:\\Users\\{uname}\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
            elif ht_up == "AMCACHE":
                cleaned = r"C:\Windows\appcompat\Programs\Amcache.hve"
            else:
                cleaned = f"C:\\Windows\\System32\\config\\{ht_up}"

        return f"{vss_prefix}{cleaned}" if vss_prefix else cleaned

    def _discover_hives(self) -> List[HiveTarget]:
        roots: List[Tuple[str, Path]] = []
        clean_dir = self.case_dir / "clean_hives"
        if clean_dir.is_dir():
            roots.append(("clean", clean_dir))
        reg_dir = self.staging_dir / "Registry"
        if reg_dir.is_dir():
            roots.append(("staged", reg_dir))
        vss_dir = self.staging_dir / "VSS"
        if vss_dir.is_dir():
            roots.append(("vss", vss_dir))

        seen_slots: Set[Tuple[str, str, str]] = set()
        seen_paths: Set[Path] = set()
        targets: List[HiveTarget] = []
        staging_resolved = self.staging_dir.resolve()

        for _tier, base in roots:
            if not base.exists():
                continue
            base_resolved = base.resolve()
            for p in sorted(base.rglob("*")):
                if not p.is_file():
                    continue
                rp = p.resolve()
                if rp in seen_paths:
                    continue
                name_low = p.name.lower()
                if any(name_low.endswith(sfx) for sfx in _SIDE_CAR_SUFFIXES):
                    continue
                try:
                    if p.stat().st_size < 4096:
                        continue
                    with open(p, "rb") as fh:
                        if fh.read(4) != b"regf":
                            continue
                except Exception:
                    continue

                try:
                    rel_path_obj = rp.relative_to(base_resolved)
                    rel_str = rel_path_obj.as_posix()
                except ValueError:
                    rel_path_obj = Path(p.name)
                    rel_str = self._raw_staging_rel_posix(p)
                m_vss = re.search(r"(?i)(?:^|/)(vss[_\-#]?\d+)(?:/|$)", rel_str)
                prov = m_vss.group(1).upper().replace("-", "_").replace("#", "_") if m_vss else "active"
                if prov.startswith("VSS") and not prov.startswith("VSS_"):
                    prov = "VSS_" + prov[3:]

                hive_type: Optional[str] = None
                username: Optional[str] = None

                # Extract username from Users/<User>/... or Documents and Settings/<User>/...
                m_usr = re.search(
                    r"(?i)(?:^|/)(?:Users|Documents and Settings)/([^/]+)/(?:.*)?(?:ntuser\.dat|usrclass\.dat)",
                    rel_str,
                )
                if m_usr:
                    username = m_usr.group(1)

                if "usrclass" in name_low:
                    hive_type = "USRCLASS"
                    if not username:
                        m_u2 = re.match(r"(?i)^usrclass[_.\-](.+?)(?:\.dat)?$", p.name)
                        if m_u2:
                            username = m_u2.group(1)
                elif "ntuser" in name_low:
                    hive_type = "NTUSER"
                    if not username:
                        m_n2 = re.match(r"(?i)^ntuser[_.\-](.+?)(?:\.dat)?$", p.name)
                        if m_n2 and m_n2.group(1).lower() != "dat":
                            username = m_n2.group(1)
                elif "amcache" in name_low:
                    hive_type = "AMCACHE"
                elif name_low in ("sam", "sam.hive") or re.search(r"(?i)(?:^|[_.\-])sam$", p.stem):
                    hive_type = "SAM"
                elif name_low in ("system", "system.hive") or re.search(r"(?i)(?:^|[_.\-])system$", p.stem):
                    hive_type = "SYSTEM"
                elif name_low in ("software", "software.hive") or re.search(r"(?i)(?:^|[_.\-])software$", p.stem):
                    hive_type = "SOFTWARE"
                elif name_low in ("security", "security.hive") or re.search(r"(?i)(?:^|[_.\-])security$", p.stem):
                    hive_type = "SECURITY"

                if not hive_type:
                    continue

                slot = (prov, hive_type, (username or "").lower())
                if slot in seen_slots:
                    continue
                seen_slots.add(slot)
                seen_paths.add(rp)

                try:
                    _ = rp.relative_to(staging_resolved)
                    in_staging = True
                except ValueError:
                    in_staging = False

                if not in_staging or _tier == "clean":
                    # Rebase clean_hives / outside-staging path under staging_dir/Registry/... so
                    # BaseParser.resolve_evidence_path NEVER falls through to host Users\<Examiner> regex!
                    rel_parts = [seg for seg in rel_path_obj.parts if seg]
                    if prov != "active":
                        # Strip leading VSS/<VSS_N> segments if present before rebasing under VSS/<prov>/Registry
                        while rel_parts and re.match(r"(?i)^vss(?:[_\-#]?\d+)?$", rel_parts[0]):
                            rel_parts.pop(0)
                        if rel_parts and rel_parts[0].lower() == "registry":
                            rel_parts.pop(0)
                        lookup_path = self.staging_dir / "VSS" / prov / "Registry" / Path(*rel_parts)
                    else:
                        if rel_parts and rel_parts[0].lower() == "registry":
                            rel_parts.pop(0)
                        lookup_path = self.staging_dir / "Registry" / Path(*rel_parts)
                    raw_disp = self.resolve_evidence_path(lookup_path)
                else:
                    raw_disp = self.resolve_evidence_path(rp)

                disp_src = self._canonicalize_hive_display_source(raw_disp, hive_type, username, prov)

                targets.append(
                    HiveTarget(
                        path=rp,
                        hive_type=hive_type,
                        username=username,
                        provenance=prov,
                        display_source=disp_src,
                    )
                )

        return targets

    @staticmethod
    def _get_control_set_names(reader: _HiveReader) -> List[str]:
        current_num = 1
        sel = reader.get_key("Select")
        if sel is not None:
            cur_val = _val_as_int(sel.value_map().get("current"))
            if cur_val and 1 <= cur_val <= 999:
                current_num = cur_val
        preferred = f"ControlSet{current_num:03d}"
        found: List[str] = []
        if reader.get_key(preferred) is not None:
            found.append(preferred)
        root = reader.root
        if root is not None:
            for sk in root.iter_subkeys():
                if sk.name.lower().startswith("controlset") and sk.name not in found:
                    found.append(sk.name)
        if not found and reader.get_key("CurrentControlSet") is not None:
            found.append("CurrentControlSet")
        return found

    @staticmethod
    def _get_active_time_bias_minutes(reader: _HiveReader) -> int:
        for cs in NativeFallbackParser._get_control_set_names(reader):
            tzi = reader.get_key(f"{cs}\\Control\\TimeZoneInformation")
            if tzi is None:
                continue
            vmap = tzi.value_map()
            raw_val = _val_as_int(vmap.get("activetimebias"))
            if raw_val is None:
                raw_val = _val_as_int(vmap.get("bias"))
            if raw_val is not None:
                signed = (raw_val - 0x100000000) if raw_val >= 0x80000000 else int(raw_val)
                if -900 <= signed <= 900:
                    return signed
        return 0

    def _build_sid_user_map(self, hives: Optional[List[HiveTarget]] = None) -> Dict[str, Tuple[str, Optional[str]]]:
        """Maps `SID -> (username, profile_path)` from `SOFTWARE\\...\\ProfileList` and `SAM`."""
        targets = hives if hives is not None else self._discover_hives()
        sid_map: Dict[str, Tuple[str, Optional[str]]] = {}

        for ht in targets:
            if ht.hive_type != "SOFTWARE":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    pl_key = reader.get_key(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
                    if pl_key is None:
                        continue
                    for sk in pl_key.iter_subkeys():
                        sid_str = sk.name.strip()
                        if not sid_str.upper().startswith("S-1-"):
                            continue
                        p_img = _val_as_str(sk.value_map().get("profileimagepath"))
                        uname = Path(p_img.replace("\\", "/")).name if p_img else ""
                        if uname:
                            sid_map[sid_str] = (uname, p_img)
            except Exception:
                continue
        return sid_map

    # -------------------------------------------------------------------------
    # A9: Native Windows Prefetch (.pf) Parser (MAM\x04 + SCCA v17/v23/v26/v30)
    # -------------------------------------------------------------------------
    def _parse_single_prefetch(
        self, pf_path: Path
    ) -> Optional[Tuple[str, Dict[str, Any], List[Dict[str, Any]]]]:
        try:
            raw_on_disk = pf_path.read_bytes()
            if len(raw_on_disk) < 8:
                return None
            h = hashlib.sha256(raw_on_disk).hexdigest()

            raw = raw_on_disk
            if raw[:3] == b"MAM":
                if lzxpress_huffman is None or len(raw) < 8:
                    return None
                uncompressed_size = struct.unpack_from("<I", raw, 4)[0]
                hdr_len = 12 if (raw[3] & 0x80) else 8
                if len(raw) <= hdr_len or uncompressed_size <= 0 or uncompressed_size > 64 * 1024 * 1024:
                    return None
                try:
                    decomp = lzxpress_huffman.decompress(raw[hdr_len:])
                except TypeError:
                    decomp = lzxpress_huffman.decompress(raw[hdr_len:], size=uncompressed_size)  # type: ignore[call-arg]
                except Exception:
                    return None
                if uncompressed_size > 0:
                    raw = decomp[:uncompressed_size]
                else:
                    raw = decomp

            if len(raw) < 0x94 or raw[4:8] != b"SCCA":
                return None

            version = struct.unpack_from("<I", raw, 0)[0]
            file_size = struct.unpack_from("<I", raw, 12)[0]
            raw_exe = raw[16:76].decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()
            pf_hash = f"{struct.unpack_from('<I', raw, 76)[0]:08X}"
            metrics_off = struct.unpack_from("<I", raw, 0x54)[0]

            run_count = 0
            last_runs: List[Optional[datetime]] = [None] * 8

            if version == 17 and len(raw) >= 0x94:
                last_runs[0] = windows_filetime_to_datetime(struct.unpack_from("<Q", raw, 0x78)[0])
                run_count = struct.unpack_from("<I", raw, 0x90)[0]
            elif version == 23 and len(raw) >= 0x9C:
                last_runs[0] = windows_filetime_to_datetime(struct.unpack_from("<Q", raw, 0x80)[0])
                run_count = struct.unpack_from("<I", raw, 0x98)[0]
            elif version == 26 and len(raw) >= 0xD4:
                for i in range(8):
                    last_runs[i] = windows_filetime_to_datetime(struct.unpack_from("<Q", raw, 0x80 + i * 8)[0])
                run_count = struct.unpack_from("<I", raw, 0xD0)[0]
            elif version >= 30 and len(raw) >= 0xCC:
                for i in range(8):
                    last_runs[i] = windows_filetime_to_datetime(struct.unpack_from("<Q", raw, 0x80 + i * 8)[0])
                rc_off = 0xC8 if metrics_off == 0xE8 else 0xD0
                if rc_off + 4 <= len(raw):
                    run_count = struct.unpack_from("<I", raw, rc_off)[0]

            fn_off, fn_len = struct.unpack_from("<II", raw, 0x64)
            files_loaded = ""
            if 0 < fn_off < len(raw) and fn_off + fn_len <= len(raw):
                blob = raw[fn_off : fn_off + fn_len].decode("utf-16le", errors="ignore")
                loaded_list = [s.strip() for s in blob.split("\x00") if s.strip()]
                files_loaded = ", ".join(loaded_list)

            vol_off, vol_cnt, _vol_sz = struct.unpack_from("<III", raw, 0x6C)
            vol0_name = ""
            vol0_serial = ""
            vol0_created: Optional[datetime] = None
            directories_str = ""
            if vol_cnt >= 1 and 0 < vol_off and vol_off + 20 <= len(raw):
                v_path_off, v_path_chars = struct.unpack_from("<II", raw, vol_off)
                v_created_ft = struct.unpack_from("<Q", raw, vol_off + 8)[0]
                v_serial = struct.unpack_from("<I", raw, vol_off + 16)[0]
                vol0_serial = f"{v_serial:08X}" if v_serial else ""
                vol0_created = windows_filetime_to_datetime(v_created_ft)
                vp_start = vol_off + v_path_off
                vp_end = vp_start + v_path_chars * 2
                if 0 < vp_start < len(raw) and vp_end <= len(raw):
                    vol0_name = raw[vp_start:vp_end].decode("utf-16le", errors="ignore").rstrip("\x00").strip()
                if vol_off + 36 <= len(raw):
                    dir_off, dir_cnt = struct.unpack_from("<II", raw, vol_off + 28)
                    d_pos = vol_off + dir_off
                    dirs: List[str] = []
                    for _ in range(min(dir_cnt, 512)):
                        if d_pos + 2 > len(raw):
                            break
                        d_len = struct.unpack_from("<H", raw, d_pos)[0]
                        d_start = d_pos + 2
                        d_end = d_start + d_len * 2
                        if d_end > len(raw):
                            break
                        d_str = raw[d_start:d_end].decode("utf-16le", errors="ignore").rstrip("\x00").strip()
                        if d_str:
                            dirs.append(d_str)
                        d_pos = d_end + 2
                    if dirs:
                        directories_str = ", ".join(dirs)

            src_cr, src_mod, src_acc = self._get_source_timestamps(pf_path)
            src_disp = self.resolve_evidence_path(pf_path)
            exe_name = raw_exe or pf_path.stem.rsplit("-", 1)[0]

            ver_map = {17: "WinXP (v17)", 23: "Win7 (v23)", 26: "Win8.1 (v26)", 30: "Win10/11 (v30)"}
            rec = {
                "SourceCreated": src_cr,
                "SourceModified": src_mod,
                "SourceAccessed": src_acc,
                "SourceFilename": src_disp,
                "ExecutableName": exe_name,
                "Hash": pf_hash,
                "Size": int(file_size or len(raw)),
                "Version": ver_map.get(version, f"v{version}"),
                "RunCount": int(run_count),
                "LastRun": last_runs[0],
                "PreviousRun0": last_runs[1],
                "PreviousRun1": last_runs[2],
                "PreviousRun2": last_runs[3],
                "PreviousRun3": last_runs[4],
                "PreviousRun4": last_runs[5],
                "PreviousRun5": last_runs[6],
                "PreviousRun6": last_runs[7],
                "PreviousRun7": None,
                "Volume0Name": vol0_name,
                "Volume0Serial": vol0_serial,
                "Volume0Created": vol0_created,
                "Directories": directories_str,
                "FilesLoaded": files_loaded,
            }
            tl_rows = [
                {
                    "RunTime": rt,
                    "ExecutableName": exe_name,
                    "Hash": pf_hash,
                    "SourceCreated": src_cr,
                    "SourceFilename": src_disp,
                }
                for rt in last_runs
                if rt is not None
            ]
            return h, rec, tl_rows
        except Exception as ex:
            self._log(f"Prefetch parse notice on {pf_path.name}: {ex}", "WARNING")
            return None

    def parse_prefetch_natively(self, max_workers: int = 16) -> int:
        existing = self._existing_table_count("raw_pecmd")
        if existing > 0:
            return existing

        pf_files = [
            p for p in self.staging_dir.rglob("*.pf")
            if p.is_file() and p.stat().st_size >= 8
        ]
        if not pf_files:
            return 0

        workers = max(1, min(32, int(max_workers or 16), len(pf_files)))
        seen_hashes: Set[str] = set()
        records: List[Dict[str, Any]] = []
        timeline_records: List[Dict[str, Any]] = []

        if workers > 1 and len(pf_files) > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for res in pool.map(self._parse_single_prefetch, pf_files):
                    if res is None:
                        continue
                    h, rec, tl_rows = res
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    records.append(rec)
                    timeline_records.extend(tl_rows)
        else:
            for pf_path in pf_files:
                res = self._parse_single_prefetch(pf_path)
                if res is None:
                    continue
                h, rec, tl_rows = res
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                records.append(rec)
                timeline_records.extend(tl_rows)

        if not records:
            return 0

        cnt = self.insert_records(
            table_name="raw_pecmd",
            records=records,
            artifact_id="os_prefetch",
            category="OPERATING SYSTEM",
            display_name="Prefetch Files - Execution",
            source_tool="NativePrefetchParser",
        )
        if timeline_records and self._existing_table_count("raw_pecmd_timeline") == 0:
            self.insert_records(
                table_name="raw_pecmd_timeline",
                records=timeline_records,
                artifact_id="raw_pecmd_timeline",
                category="OPERATING SYSTEM",
                display_name="Prefetch Timeline",
                source_tool="NativePrefetchParser",
            )
        return cnt

    # -------------------------------------------------------------------------
    # A8: Uncapped Native NTFS $MFT / MFT Parser (USA fixups, $DATA size, $SI<$FN)
    # -------------------------------------------------------------------------
    def parse_mft_natively(self, max_records: Optional[int] = None) -> int:
        existing = self._existing_table_count("raw_mft")
        if existing > 0:
            return existing

        seen_mft_paths: Set[Path] = set()
        seen_mft_digests: Set[Tuple[int, str]] = set()
        mft_files: List[Path] = []

        priority_paths = [
            self.staging_dir / "$MFT",
            self.staging_dir / "MFT",
            self.staging_dir / "FileSystem" / "$MFT",
            self.staging_dir / "FileSystem" / "MFT",
            self.staging_dir / "MFT" / "$MFT",
            self.staging_dir / "MFT" / "MFT",
        ]
        all_candidates = list(priority_paths)
        if self.staging_dir.exists():
            all_candidates.extend(
                p for p in sorted(self.staging_dir.rglob("*"))
                if p.is_file() and p.name.upper() in ("$MFT", "MFT")
            )

        for cand in all_candidates:
            try:
                if not cand.is_file():
                    continue
                rp = cand.resolve()
                if rp in seen_mft_paths:
                    continue
                sz = rp.stat().st_size
                if sz < 1024:
                    continue
                with open(rp, "rb") as fh:
                    head = fh.read(4096)
                if head[:4] != b"FILE":
                    continue
                sig = (sz, hashlib.sha256(head).hexdigest())
                if sig in seen_mft_digests:
                    continue
                seen_mft_paths.add(rp)
                seen_mft_digests.add(sig)
                mft_files.append(rp)
            except Exception:
                continue

        if not mft_files:
            return 0

        all_records: List[Dict[str, Any]] = []

        for mft_file in mft_files:
            file_records: List[Dict[str, Any]] = []
            parent_map: Dict[int, Tuple[int, str]] = {5: (5, ".")}
            try:
                with open(mft_file, "rb") as f:
                    seq_idx = 0
                    while True:
                        if max_records is not None and len(all_records) + len(file_records) >= max_records:
                            break
                        raw_buf = f.read(1024)
                        if not raw_buf or len(raw_buf) < 1024:
                            break
                        if raw_buf[:4] != b"FILE":
                            seq_idx += 1
                            continue

                        buf = bytearray(raw_buf)
                        usa_off = struct.unpack_from("<H", buf, 4)[0]
                        usa_cnt = struct.unpack_from("<H", buf, 6)[0]
                        if usa_cnt >= 2 and 0 < usa_off and usa_off + usa_cnt * 2 <= 1024:
                            usn = bytes(buf[usa_off : usa_off + 2])
                            for s_idx in range(1, usa_cnt):
                                sec_end = s_idx * 512 - 2
                                if sec_end + 2 <= 1024 and bytes(buf[sec_end : sec_end + 2]) == usn:
                                    fix = buf[usa_off + s_idx * 2 : usa_off + (s_idx + 1) * 2]
                                    buf[sec_end : sec_end + 2] = fix

                        seq_num = struct.unpack_from("<H", buf, 16)[0]
                        attr_off = struct.unpack_from("<H", buf, 20)[0]
                        flags = struct.unpack_from("<H", buf, 22)[0]
                        in_use = bool(flags & 0x0001)
                        is_dir = bool(flags & 0x0002)

                        hdr_rec_num = struct.unpack_from("<I", buf, 44)[0] if attr_off >= 48 else 0
                        entry_num = int(hdr_rec_num) if (hdr_rec_num > 0 or seq_idx == 0) else seq_idx

                        si_cr = si_mod = si_mft = si_acc = None
                        fn_cr = fn_mod = fn_mft = fn_acc = None
                        file_name = ""
                        parent_entry = 5
                        parent_seq = 1
                        fn_real_size = 0
                        data_size: Optional[int] = None

                        pos = attr_off
                        while 0 < pos <= 1000:
                            attr_type = struct.unpack_from("<I", buf, pos)[0]
                            if attr_type in (0xFFFFFFFF, 0):
                                break
                            attr_len = struct.unpack_from("<I", buf, pos + 4)[0]
                            if attr_len <= 0 or pos + attr_len > 1024:
                                break
                            non_res = buf[pos + 8]
                            name_len = buf[pos + 9]

                            if non_res == 0 and pos + 22 <= 1024:
                                val_len = struct.unpack_from("<I", buf, pos + 16)[0]
                                val_off = struct.unpack_from("<H", buf, pos + 20)[0]
                                vpos = pos + val_off
                                if attr_type == 0x10 and vpos + 32 <= 1024:
                                    si_cr = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos)[0])
                                    si_mod = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 8)[0])
                                    si_mft = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 16)[0])
                                    si_acc = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 24)[0])
                                elif attr_type == 0x30 and vpos + 66 <= 1024:
                                    p_ref = struct.unpack_from("<Q", buf, vpos)[0]
                                    p_ent = p_ref & 0x0000FFFFFFFFFFFF
                                    p_seq = (p_ref >> 48) & 0xFFFF
                                    fn_chars = buf[vpos + 64]
                                    fn_ns = buf[vpos + 65]
                                    if vpos + 66 + fn_chars * 2 <= 1024:
                                        cand_name = bytes(buf[vpos + 66 : vpos + 66 + fn_chars * 2]).decode(
                                            "utf-16le", errors="ignore"
                                        )
                                        if not file_name or fn_ns != 2:
                                            file_name = cand_name
                                            parent_entry = p_ent
                                            parent_seq = p_seq
                                            fn_cr = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 8)[0])
                                            fn_mod = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 16)[0])
                                            fn_mft = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 24)[0])
                                            fn_acc = windows_filetime_to_datetime(struct.unpack_from("<Q", buf, vpos + 32)[0])
                                            real_sz = struct.unpack_from("<Q", buf, vpos + 56)[0]
                                            if real_sz > fn_real_size:
                                                fn_real_size = real_sz
                                elif attr_type == 0x80 and name_len == 0:
                                    data_size = int(val_len)
                            elif non_res != 0 and attr_type == 0x80 and name_len == 0 and pos + 56 <= 1024:
                                start_vcn = struct.unpack_from("<Q", buf, pos + 16)[0]
                                if start_vcn == 0:
                                    data_size = int(struct.unpack_from("<Q", buf, pos + 48)[0])

                            pos += attr_len

                        if file_name:
                            if is_dir:
                                parent_map[entry_num] = (parent_entry, file_name)
                            ext = Path(file_name).suffix.lower() if (not is_dir and "." in file_name) else ""
                            actual_size = 0 if is_dir else int(data_size if data_size is not None else fn_real_size)
                            timestomp = bool(
                                (si_cr is not None and fn_cr is not None and si_cr < fn_cr)
                                or (si_mod is not None and fn_cr is not None and si_mod < fn_cr)
                            )
                            file_records.append({
                                "EntryNumber": entry_num,
                                "SequenceNumber": seq_num,
                                "InUse": in_use,
                                "IsDirectory": is_dir,
                                "ParentEntryNumber": parent_entry,
                                "ParentSequenceNumber": parent_seq,
                                "ParentPath": ".",
                                "FileName": file_name,
                                "Extension": ext,
                                "FileSize": actual_size,
                                "Created0x10": si_cr,
                                "Created0x30": fn_cr,
                                "LastModified0x10": si_mod,
                                "LastModified0x30": fn_mod,
                                "LastAccess0x10": si_acc,
                                "LastAccess0x30": fn_acc,
                                "LastRecordChange0x10": si_mft,
                                "LastRecordChange0x30": fn_mft,
                                "TimestampsLogicalInconsistency": timestomp,
                            })
                        seq_idx += 1

                def _resolve_dir_path(ent: int) -> str:
                    parts: List[str] = []
                    cur_e = ent
                    visited: Set[int] = set()
                    while cur_e in parent_map and cur_e != 5 and cur_e not in visited and len(parts) < 128:
                        visited.add(cur_e)
                        p_e, dname = parent_map[cur_e]
                        if dname and dname != ".":
                            parts.append(dname)
                        cur_e = p_e
                    return "." if not parts else (".\\" + "\\".join(reversed(parts)))

                for rec in file_records:
                    rec["ParentPath"] = _resolve_dir_path(rec["ParentEntryNumber"])

                all_records.extend(file_records)
            except Exception as ex:
                self._log(f"Native MFT parse warning on {mft_file.name}: {ex}", "WARNING")

        if not all_records:
            return 0

        return self.insert_records(
            table_name="raw_mft",
            records=all_records,
            artifact_id="fs_mft",
            category="OPERATING SYSTEM",
            display_name="NTFS Master File Table ($MFT)",
            source_tool="NativeMFTParser",
        )

    # -------------------------------------------------------------------------
    # A2: Uncapped Native EVTX Parser (`dissect.eventlog.evtx` + `Evtx.Evtx`)
    # -------------------------------------------------------------------------
    def _parse_single_evtx_file(
        self,
        ev_path: Path,
        max_events_per_file: Optional[int] = None,
        display_source: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        file_rows: List[Dict[str, Any]] = []
        raw_fs_path = str(ev_path)
        disp_src = display_source if display_source is not None else self.resolve_evidence_path(ev_path)

        def _unwrap_bxml(v: Any) -> Any:
            if hasattr(v, "get") and callable(v.get):
                try:
                    return v.get()
                except Exception:
                    return None
            return v

        def _parse_iso_dt(val: Any) -> Optional[datetime]:
            val = _unwrap_bxml(val)
            if isinstance(val, datetime):
                return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
            if isinstance(val, (int, float)) and val > 100_000_000_000_000:
                return windows_filetime_to_datetime(int(val))
            if isinstance(val, str) and val.strip():
                try:
                    return datetime.fromisoformat(val.strip().replace("Z", "+00:00"))
                except Exception:
                    dt = _parse_str_to_utc_naive(val)
                    return dt.replace(tzinfo=timezone.utc) if dt else None
            return None

        # 1. Primary: dissect.eventlog.evtx.Evtx
        parsed_with_dissect = False
        if DissectEvtx is not None:
            try:
                sys_keys = {
                    "Provider_Name",
                    "Provider_Guid",
                    "EventSourceName",
                    "EventID",
                    "Version",
                    "Level",
                    "Task",
                    "Opcode",
                    "Keywords",
                    "TimeCreated_SystemTime",
                    "EventRecordID",
                    "Correlation_ActivityID",
                    "Correlation_RelatedActivityID",
                    "Execution_ProcessID",
                    "Execution_ThreadID",
                    "Channel",
                    "Computer",
                    "Security_UserID",
                }
                with open(ev_path, "rb") as fh:
                    for rec in DissectEvtx(fh, path=disp_src):
                        if max_events_per_file is not None and len(file_rows) >= max_events_per_file:
                            break
                        ev_id_raw = _unwrap_bxml(rec.get("EventID"))
                        try:
                            ev_id = int(ev_id_raw) if ev_id_raw is not None else 0
                        except Exception:
                            ev_id = 0
                        rec_id_raw = _unwrap_bxml(rec.get("EventRecordID"))
                        try:
                            rec_id = int(rec_id_raw) if rec_id_raw is not None else (len(file_rows) + 1)
                        except Exception:
                            rec_id = len(file_rows) + 1

                        ts_dt = _parse_iso_dt(rec.get("TimeCreated_SystemTime"))
                        level_str = _map_evtx_level(
                            _unwrap_bxml(rec.get("Level")),
                            _unwrap_bxml(rec.get("Keywords")),
                        )
                        provider = str(_unwrap_bxml(rec.get("Provider_Name")) or _unwrap_bxml(rec.get("EventSourceName")) or "")
                        channel = str(_unwrap_bxml(rec.get("Channel")) or ev_path.stem)
                        computer = str(_unwrap_bxml(rec.get("Computer")) or "")
                        user_id = str(_unwrap_bxml(rec.get("Security_UserID")) or "")

                        pid_raw = _unwrap_bxml(rec.get("Execution_ProcessID"))
                        tid_raw = _unwrap_bxml(rec.get("Execution_ThreadID"))
                        pid = int(pid_raw) if isinstance(pid_raw, int) else (int(str(pid_raw), 0) if str(pid_raw or "").isdigit() else 0)
                        tid = int(tid_raw) if isinstance(tid_raw, int) else (int(str(tid_raw), 0) if str(tid_raw or "").isdigit() else 0)

                        payload_parts: List[str] = []
                        user_name = ""
                        remote_host = ""
                        exe_info = ""
                        for k, raw_v in rec.items():
                            if k in sys_keys:
                                continue
                            uv = _unwrap_bxml(raw_v)
                            if uv is None:
                                continue
                            sval = str(uv).strip()
                            if not sval:
                                continue
                            payload_parts.append(f"{k}: {sval}")
                            if k in ("TargetUserName", "SubjectUserName", "User") and sval not in (
                                "-",
                                "SYSTEM",
                                "LOCAL SERVICE",
                                "NETWORK SERVICE",
                            ) and not sval.endswith("$"):
                                user_name = sval
                            elif k in ("IpAddress", "WorkstationName", "SourceNetworkAddress", "ClientAddress") and sval not in (
                                "-",
                                "127.0.0.1",
                                "::1",
                            ):
                                remote_host = sval
                            elif k in ("NewProcessName", "ProcessName", "Image", "CommandLine", "ParentProcessName") and not exe_info:
                                exe_info = sval

                        file_rows.append({
                            "RecordNumber": 0,
                            "EventRecordId": rec_id,
                            "TimeCreated": ts_dt,
                            "EventId": ev_id,
                            "Level": level_str,
                            "Provider": provider,
                            "Channel": channel,
                            "ProcessId": pid,
                            "ThreadId": tid,
                            "Computer": computer,
                            "UserId": user_id,
                            "MapDescription": f"Event {ev_id} ({provider})" if provider else f"Event {ev_id}",
                            "UserName": user_name or None,
                            "RemoteHost": remote_host or None,
                            "PayloadData1": " | ".join(payload_parts)[:2000] if payload_parts else "",
                            "ExecutableInfo": exe_info,
                            "SourceFile": disp_src,
                        })
                if file_rows:
                    parsed_with_dissect = True
            except Exception:
                file_rows.clear()
                parsed_with_dissect = False

        # 2. Fallback: python-evtx (`Evtx.Evtx`) XML parser
        if not parsed_with_dissect and PyEvtxMod is not None:
            try:
                with PyEvtxMod.Evtx(raw_fs_path) as log:
                    for record in log.records():
                        if max_events_per_file is not None and len(file_rows) >= max_events_per_file:
                            break
                        try:
                            xml_str = record.xml()
                            clean_xml = re.sub(r'\sxmlns(?::\w+)?=(?:"[^"]*"|\'[^\']*\')', "", xml_str)
                            root = ET.fromstring(clean_xml)
                            sys_node = root.find("System")
                            if sys_node is None:
                                continue

                            ev_id_node = sys_node.find("EventID")
                            ev_id = (
                                int(ev_id_node.text.strip())
                                if (ev_id_node is not None and ev_id_node.text and ev_id_node.text.strip().isdigit())
                                else 0
                            )
                            rec_id_node = sys_node.find("EventRecordID")
                            rec_id_val: Optional[int] = None
                            if rec_id_node is not None and rec_id_node.text and rec_id_node.text.strip():
                                try:
                                    rec_id_val = int(rec_id_node.text.strip(), 0)
                                except Exception:
                                    rec_id_val = None
                            if rec_id_val is None:
                                rec_id_val = int(record.record_num())

                            lvl_node = sys_node.find("Level")
                            kw_node = sys_node.find("Keywords")
                            level_str = _map_evtx_level(
                                lvl_node.text if lvl_node is not None else None,
                                kw_node.text if kw_node is not None else None,
                            )

                            tc_node = sys_node.find("TimeCreated")
                            ts_dt = _parse_iso_dt(tc_node.attrib.get("SystemTime", "") if tc_node is not None else "")

                            prov_node = sys_node.find("Provider")
                            provider = (
                                prov_node.attrib.get("Name")
                                or prov_node.attrib.get("EventSourceName")
                                or ""
                            ) if prov_node is not None else ""

                            chan_node = sys_node.find("Channel")
                            channel = (chan_node.text or ev_path.stem) if chan_node is not None else ev_path.stem
                            comp_node = sys_node.find("Computer")
                            computer = (comp_node.text or "") if comp_node is not None else ""
                            sec_node = sys_node.find("Security")
                            user_id = sec_node.attrib.get("UserID", "") if sec_node is not None else ""

                            exec_node = sys_node.find("Execution")
                            pid = 0
                            tid = 0
                            if exec_node is not None:
                                p_attr = exec_node.attrib.get("ProcessID", "0")
                                t_attr = exec_node.attrib.get("ThreadID", "0")
                                try:
                                    pid = int(p_attr, 0)
                                except Exception:
                                    pid = 0
                                try:
                                    tid = int(t_attr, 0)
                                except Exception:
                                    tid = 0

                            payload_parts = []
                            user_name = ""
                            remote_host = ""
                            exe_info = ""

                            ev_data = root.find("EventData")
                            if ev_data is not None:
                                for d_elem in ev_data.iter():
                                    if d_elem is ev_data:
                                        continue
                                    d_name = d_elem.attrib.get("Name", "") or d_elem.tag
                                    d_val = (d_elem.text or "").strip()
                                    if d_val:
                                        payload_parts.append(f"{d_name}: {d_val}" if d_name else d_val)
                                        if d_name in ("TargetUserName", "SubjectUserName") and d_val not in (
                                            "-",
                                            "SYSTEM",
                                            "LOCAL SERVICE",
                                            "NETWORK SERVICE",
                                        ) and not d_val.endswith("$"):
                                            user_name = d_val
                                        elif d_name in ("IpAddress", "WorkstationName", "SourceNetworkAddress") and d_val not in (
                                            "-",
                                            "127.0.0.1",
                                            "::1",
                                        ):
                                            remote_host = d_val
                                        elif d_name in ("NewProcessName", "ProcessName", "Image", "CommandLine") and not exe_info:
                                            exe_info = d_val

                            usr_data = root.find("UserData")
                            if usr_data is not None:
                                for u_elem in usr_data.iter():
                                    if u_elem is usr_data or list(u_elem):
                                        continue
                                    u_val = (u_elem.text or "").strip()
                                    if u_val:
                                        u_name = u_elem.tag.split("}")[-1]
                                        payload_parts.append(f"{u_name}: {u_val}")

                            file_rows.append({
                                "RecordNumber": 0,
                                "EventRecordId": rec_id_val,
                                "TimeCreated": ts_dt,
                                "EventId": ev_id,
                                "Level": level_str,
                                "Provider": provider,
                                "Channel": channel,
                                "ProcessId": pid,
                                "ThreadId": tid,
                                "Computer": computer,
                                "UserId": user_id,
                                "MapDescription": f"Event {ev_id} ({provider})" if provider else f"Event {ev_id}",
                                "UserName": user_name or None,
                                "RemoteHost": remote_host or None,
                                "PayloadData1": " | ".join(payload_parts)[:2000] if payload_parts else "",
                                "ExecutableInfo": exe_info,
                                "SourceFile": disp_src,
                            })
                        except Exception:
                            continue
            except Exception as ex:
                self._log(f"Native EVTX notice on {ev_path.name}: {ex}", "WARNING")

        return file_rows

    def parse_evtx_natively(
        self, max_events_per_file: Optional[int] = None, max_workers: int = 16
    ) -> int:
        existing = self._existing_table_count("raw_evtx")
        if existing > 0:
            return existing

        if DissectEvtx is None and PyEvtxMod is None:
            self._log("Neither dissect.eventlog.evtx nor python-evtx installed; skipping EVTX fallback", "WARNING")
            return 0

        evtx_files = sorted(
            [p for p in self.staging_dir.rglob("*.evtx") if p.is_file() and p.stat().st_size >= 4096],
            key=lambda p: (
                0 if p.name.lower() in ("security.evtx", "system.evtx", "application.evtx") else 1,
                p.name.lower(),
            ),
        )
        if not evtx_files:
            return 0

        # Pre-resolve canonical forensic evidence paths once before parallel worker dispatch
        # so worker threads remain 100% lock-free while preventing host staging path leakage!
        evtx_jobs: List[Tuple[Path, str]] = [
            (ev_path, self.resolve_evidence_path(ev_path)) for ev_path in evtx_files
        ]

        workers = max(1, min(32, int(max_workers or 16), len(evtx_jobs)))
        records: List[Dict[str, Any]] = []

        if workers > 1 and len(evtx_jobs) > 1:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for batch in pool.map(
                    lambda job: self._parse_single_evtx_file(job[0], max_events_per_file, display_source=job[1]),
                    evtx_jobs,
                ):
                    records.extend(batch)
        else:
            for ev_path, disp_src in evtx_jobs:
                records.extend(self._parse_single_evtx_file(ev_path, max_events_per_file, display_source=disp_src))

        if not records:
            return 0

        for idx, rec in enumerate(records, start=1):
            rec["RecordNumber"] = idx

        cnt = self.insert_records(
            table_name="raw_evtx",
            records=records,
            artifact_id="os_evtx",
            category="EVENT LOGS",
            display_name="All Event Logs (Combined)",
            source_tool="NativeEvtxParser",
        )
        try:
            from backend.db.schema import register_evtx_granular_views

            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                register_evtx_granular_views(conn, case_id=self.case_id)
        except Exception:
            pass
        return cnt

    # -------------------------------------------------------------------------
    # A4: IE10/11 & Edge Legacy WebCacheV01.dat ESE History Parser (`EseDB`)
    # -------------------------------------------------------------------------
    @staticmethod
    def _derive_user_from_path_str(path_str: str) -> str:
        s = path_str.replace("\\", "/")
        m = re.search(r"(?i)(?:^|/)(?:Users|Documents and Settings)/([^/]+)(?:/|$)", s)
        if m:
            return m.group(1)
        m_b = re.search(r"(?i)(?:^|/)Browsers/[^/]+/([^/]+)(?:/|$)", s)
        if m_b:
            return m_b.group(1)
        return "Unknown"

    def parse_ie_webcache(self) -> int:
        webcache_files = [
            p for p in self.staging_dir.rglob("WebCacheV*.dat")
            if p.is_file() and p.stat().st_size >= 256
        ]
        if not webcache_files:
            return 0

        records: List[Dict[str, Any]] = []
        seen_urls: Set[Tuple[str, str, Optional[str]]] = set()

        for wc_file in webcache_files:
            src_disp = self.resolve_evidence_path(wc_file)
            rel_wc = self._raw_staging_rel_posix(wc_file)
            default_user = self._derive_user_from_path_str(f"{rel_wc} | {src_disp}")
            parsed_ese = False

            if EseDB is not None:
                try:
                    with open(wc_file, "rb") as fh:
                        db = EseDB(fh)
                        try:
                            table_names = {t.name for t in db.tables()}
                            containers: List[Tuple[int, str, str]] = []
                            if "Containers" in table_names:
                                for crec in db.table("Containers").records():
                                    cid = _ese_get(crec, "ContainerId")
                                    cname_val = _ese_get(crec, "Name", "")
                                    cdir_val = _ese_get(crec, "Directory", "")
                                    cname = str(cname_val or "").strip("\x00").strip()
                                    cdir = str(cdir_val or "").strip("\x00").strip()
                                    if cid is not None:
                                        try:
                                            containers.append((int(cid), cname, cdir))
                                        except (TypeError, ValueError):
                                            continue

                            for cid, cname, cdir in containers:
                                ctbl_name = f"Container_{cid}"
                                if ctbl_name not in table_names:
                                    continue
                                cname_low = cname.lower()
                                if not any(k in cname_low for k in ("history", "mshist", "content", "iedownload", "domstore")):
                                    continue
                                prof_user = self._derive_user_from_path_str(cdir) if cdir else default_user
                                if prof_user == "Unknown":
                                    prof_user = default_user
                                for row in db.table(ctbl_name).records():
                                    raw_u_val = _ese_get(row, "Url")
                                    if raw_u_val is None:
                                        continue
                                    if isinstance(raw_u_val, (bytes, bytearray, memoryview)):
                                        ub = bytes(raw_u_val)
                                        raw_url = ub.decode("utf-16le" if b"\x00" in ub else "utf-8", errors="ignore").strip("\x00").strip()
                                    else:
                                        raw_url = str(raw_u_val).strip("\x00").strip()
                                    if not raw_url:
                                        continue
                                    m_vis = re.match(r"(?i)^Visited:\s*([^@]+)@(.+)$", raw_url)
                                    if m_vis:
                                        row_user = m_vis.group(1).strip() or prof_user
                                        clean_url = m_vis.group(2).strip()
                                    else:
                                        row_user = prof_user
                                        clean_url = raw_url
                                    if not re.match(r"(?i)^(?:https?|ftp|file)://", clean_url):
                                        continue

                                    acc_dt = windows_filetime_to_datetime(_ese_get(row, "AccessedTime"))
                                    mod_dt = windows_filetime_to_datetime(_ese_get(row, "ModifiedTime"))
                                    cr_dt = windows_filetime_to_datetime(_ese_get(row, "CreationTime"))
                                    visit_dt = acc_dt or mod_dt or cr_dt
                                    acc_cnt = _ese_int(row, "AccessCount", default=1)
                                    key = (row_user.lower(), clean_url, str(visit_dt))
                                    if key in seen_urls:
                                        continue
                                    seen_urls.add(key)
                                    title_s = clean_url.rstrip("/").split("/")[-1][:120] or clean_url[:120]
                                    records.append({
                                        "browser": "Internet Explorer",
                                        "profile": row_user,
                                        "container_name": cname or ctbl_name,
                                        "url": clean_url,
                                        "title": title_s,
                                        "visit_count": acc_cnt,
                                        "typed_count": 0,
                                        "visit_time": visit_dt,
                                        "accessed_time": acc_dt or visit_dt,
                                        "modified_time": mod_dt,
                                        "from_visit": 0,
                                        "transition": "LINK",
                                        "source_file": src_disp,
                                    })
                            parsed_ese = True
                        finally:
                            db = None
                except Exception:
                    parsed_ese = False

            if not parsed_ese:
                try:
                    raw = wc_file.read_bytes()
                    _cr_ts, mod_ts, acc_ts = self._get_source_timestamps(wc_file)
                    fallback_ts = acc_ts or mod_ts
                    text_u16 = raw.decode("utf-16le", errors="ignore")
                    url_pat = re.compile(
                        r"(?:Visited:\s*([^@\x00\r\n]{1,40})@)?((?:https?|ftp|file)://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{6,350})"
                    )
                    for m in url_pat.finditer(text_u16):
                        row_user = (m.group(1) or default_user).strip() or "Unknown"
                        clean_url = m.group(2).strip()
                        if any(noise in clean_url.lower() for noise in ("microsoft.com/pki", "ocsp.", "crl.", "schemas.microsoft.com")):
                            continue
                        key = (row_user.lower(), clean_url, str(fallback_ts))
                        if key in seen_urls:
                            continue
                        seen_urls.add(key)
                        records.append({
                            "browser": "Internet Explorer",
                            "profile": row_user,
                            "container_name": "History",
                            "url": clean_url,
                            "title": clean_url.rstrip("/").split("/")[-1][:120] or clean_url[:120],
                            "visit_count": 1,
                            "typed_count": 0,
                            "visit_time": fallback_ts,
                            "accessed_time": fallback_ts,
                            "modified_time": mod_ts,
                            "from_visit": 0,
                            "transition": "LINK",
                            "source_file": src_disp,
                        })
                except Exception as ex:
                    self._log(f"IE WebCache parse notice on {wc_file.name}: {ex}", "WARNING")

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_ie_history",
            """
            CREATE TABLE IF NOT EXISTS parsed_ie_history (
                _row_id BIGINT, browser VARCHAR, profile VARCHAR, container_name VARCHAR,
                url VARCHAR, title VARCHAR, visit_count INTEGER, typed_count INTEGER,
                visit_time TIMESTAMP, accessed_time TIMESTAMP, modified_time TIMESTAMP,
                from_visit BIGINT, transition VARCHAR, source_file VARCHAR
            );
            """,
            [
                ("browser", "VARCHAR"),
                ("profile", "VARCHAR"),
                ("container_name", "VARCHAR"),
                ("url", "VARCHAR"),
                ("title", "VARCHAR"),
                ("visit_count", "INTEGER"),
                ("typed_count", "INTEGER"),
                ("visit_time", "TIMESTAMP"),
                ("accessed_time", "TIMESTAMP"),
                ("modified_time", "TIMESTAMP"),
                ("from_visit", "BIGINT"),
                ("transition", "VARCHAR"),
                ("source_file", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_ie_history",
            records=records,
            schema_ddl=ddl,
            artifact_id="ie_history",
            category="WEB RELATED",
            display_name="Internet Explorer / WebCache History",
            source_tool="WebCacheESEParser",
        )

    # -------------------------------------------------------------------------
    # SRUDB.dat ESE Parser (`EseDB` -> `raw_srum_app`, `raw_srum_net`, `raw_srum_conn`)
    # -------------------------------------------------------------------------
    def parse_srum_natively(self) -> int:
        if EseDB is None:
            return 0

        need_app = self._existing_table_count("raw_srum_app") == 0
        need_net = self._existing_table_count("raw_srum_net") == 0
        need_conn = self._existing_table_count("raw_srum_conn") == 0
        if not (need_app or need_net or need_conn):
            return (
                self._existing_table_count("raw_srum_app")
                + self._existing_table_count("raw_srum_net")
                + self._existing_table_count("raw_srum_conn")
            )

        srudb_files = [
            p for p in self.staging_dir.rglob("*")
            if p.is_file() and p.name.lower() == "srudb.dat" and p.stat().st_size >= 4096
        ]
        if not srudb_files:
            return 0

        sid_user_map = self._build_sid_user_map()
        app_rows: List[Dict[str, Any]] = []
        net_rows: List[Dict[str, Any]] = []
        conn_rows: List[Dict[str, Any]] = []

        for sru_path in srudb_files:
            try:
                with open(sru_path, "rb") as fh:
                    db = EseDB(fh)
                    try:
                        tbl_names = {t.name for t in db.tables()}
                        id_map: Dict[int, str] = {}

                        if "SruDbIdMapTable" in tbl_names:
                            for irec in db.table("SruDbIdMapTable").records():
                                idx = _ese_get(irec, "IdIndex")
                                itype = _ese_get(irec, "IdType")
                                blob = _ese_get(irec, "IdBlob", raw=True)
                                if idx is None or not blob:
                                    continue
                                raw_b = bytes(blob) if isinstance(blob, (bytes, bytearray, memoryview)) else str(blob).encode("utf-16le", "ignore")
                                if itype == 3:
                                    sid_str = _decode_binary_sid(raw_b)
                                    if sid_str:
                                        uname = sid_user_map.get(sid_str, (sid_str, None))[0]
                                        id_map[int(idx)] = uname
                                else:
                                    app_s = raw_b.decode("utf-16le", errors="ignore").rstrip("\x00").strip()
                                    if app_s:
                                        id_map[int(idx)] = app_s

                        def _resolve_id(raw_id: Any) -> str:
                            if raw_id is None:
                                return ""
                            try:
                                return id_map.get(int(raw_id), str(raw_id))
                            except Exception:
                                return str(raw_id)

                        def _srum_ts(rec: Any) -> Optional[datetime]:
                            ts_raw = _ese_get(rec, "TimeStamp")
                            if ts_raw is None:
                                ts_raw = _ese_get(rec, "Timestamp")
                            return _ole_days_to_datetime(ts_raw)

                        if need_app and "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}" in tbl_names:
                            for r in db.table("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}").records():
                                app_id_val = _ese_get(r, "AppId")
                                exe_s = _resolve_id(app_id_val)
                                app_rows.append({
                                    "Timestamp": _srum_ts(r),
                                    "AppId": "" if app_id_val is None else str(app_id_val),
                                    "ExeInfo": exe_s,
                                    "UserId": _resolve_id(_ese_get(r, "UserId")),
                                    "ForegroundCycleTime": _ese_int(r, "ForegroundCycleTime", default=0),
                                    "BackgroundCycleTime": _ese_int(r, "BackgroundCycleTime", default=0),
                                    "FaceTime": _ese_int(r, "FaceTime", default=0),
                                })

                        if need_net and "{973F5D5C-1D90-4944-BE8E-24B94231A174}" in tbl_names:
                            for r in db.table("{973F5D5C-1D90-4944-BE8E-24B94231A174}").records():
                                app_id_val = _ese_get(r, "AppId")
                                exe_s = _resolve_id(app_id_val)
                                net_rows.append({
                                    "Timestamp": _srum_ts(r),
                                    "AppId": "" if app_id_val is None else str(app_id_val),
                                    "ExeInfo": exe_s,
                                    "UserId": _resolve_id(_ese_get(r, "UserId")),
                                    "BytesSent": _ese_int(r, "BytesSent", default=0),
                                    "BytesReceived": _ese_int(r, "BytesRecvd", "BytesReceived", default=0),
                                    "InterfaceLuid": _ese_int(r, "InterfaceLuid", default=0),
                                })

                        if need_conn and "{DD6636C4-8929-4683-974E-22C046A43763}" in tbl_names:
                            for r in db.table("{DD6636C4-8929-4683-974E-22C046A43763}").records():
                                app_id_val = _ese_get(r, "AppId")
                                exe_s = _resolve_id(app_id_val)
                                conn_rows.append({
                                    "Timestamp": _srum_ts(r),
                                    "AppId": "" if app_id_val is None else str(app_id_val),
                                    "ExeInfo": exe_s,
                                    "UserId": _resolve_id(_ese_get(r, "UserId")),
                                    "ConnectedTime": windows_filetime_to_datetime(_ese_get(r, "ConnectStartTime")),
                                    "ConnectDurationSeconds": _ese_int(r, "ConnectTime", default=0),
                                    "InterfaceLuid": _ese_int(r, "InterfaceLuid", default=0),
                                })
                    finally:
                        db = None
            except Exception as ex:
                self._log(f"SRUM EseDB parse notice on {sru_path.name}: {ex}", "WARNING")

        total = 0
        if need_app and app_rows:
            total += self.insert_records(
                table_name="raw_srum_app",
                records=app_rows,
                artifact_id="network_srum_app",
                category="OPERATING SYSTEM",
                display_name="SRUM Application Resource Usage",
                source_tool="NativeSRUMParser",
            )
        if need_net and net_rows:
            total += self.insert_records(
                table_name="raw_srum_net",
                records=net_rows,
                artifact_id="network_srum_net",
                category="OPERATING SYSTEM",
                display_name="SRUM Network Data Usage",
                source_tool="NativeSRUMParser",
            )
        if need_conn and conn_rows:
            total += self.insert_records(
                table_name="raw_srum_conn",
                records=conn_rows,
                artifact_id="network_srum_conn",
                category="OPERATING SYSTEM",
                display_name="SRUM Network Connections",
                source_tool="NativeSRUMParser",
            )
        return total

    # -------------------------------------------------------------------------
    # A12: Google Drive sync_log.log Parser (Zero Hardcoded Dataset Filters)
    # -------------------------------------------------------------------------
    def parse_gdrive_logs(self) -> int:
        if not self.staging_dir.exists():
            return 0
        sync_logs = sorted(
            (p for p in self.staging_dir.rglob("sync_log.log*") if p.is_file()),
            key=lambda p: (0 if p.name.lower() == "sync_log.log" else 1, str(p).lower()),
        )
        if not sync_logs:
            return 0

        def _norm_gdrive_path(v: Any) -> str:
            return re.sub(
                r"\\+",
                r"\\",
                str(v or "").replace("\\\\\\\\?\\\\", "").replace("\\\\?\\", "").replace("/", "\\"),
            ).strip().lower()

        records: List[Dict[str, Any]] = []
        seen_paths: Set[str] = set()
        line_re = re.compile(
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:,(\d+))?\s+([+-]\d{4})\s+(?:INFO|DEBUG|WARNING)\s+\S+\s+(.*)$"
        )
        path_re = re.compile(r"(?:u'|')([A-Za-z]:\\\\[^'\r\n]+|\\\\\?\\[A-Za-z]:\\[^'\r\n]+)(?:')")
        email_re = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

        for slog in sync_logs:
            try:
                text = slog.read_text(encoding="utf-8-sig", errors="replace")
                m_em = email_re.search(text)
                src_disp = self.resolve_evidence_path(slog)
                discovered_account = m_em.group(1) if m_em else self._derive_user_from_path_str(src_disp)

                for line in text.splitlines():
                    m_line = line_re.match(line)
                    if not m_line:
                        continue
                    ts_str, ms_str, tz_str, msg = m_line.groups()
                    m_path = path_re.search(msg)
                    if not m_path:
                        continue
                    raw_p = re.sub(
                        r"\\+",
                        r"\\",
                        m_path.group(1).replace("\\\\\\\\?\\\\", "").replace("\\\\?\\", ""),
                    ).strip()
                    fname = Path(raw_p.replace("\\", "/")).name
                    if not fname or fname.lower() in ("google drive", "my drive", "desktop.ini"):
                        continue

                    msg_low = msg.lower()
                    status = "SYNCED"
                    if "delete" in msg_low or "remove" in msg_low or "trash" in msg_low:
                        status = "DELETED"
                    elif "create" in msg_low or "upload" in msg_low:
                        status = "UPLOADED"
                    elif "download" in msg_low:
                        status = "DOWNLOADED"

                    norm_p = _norm_gdrive_path(raw_p)
                    if not norm_p or norm_p in seen_paths:
                        continue
                    seen_paths.add(norm_p)

                    dt: Optional[datetime] = None
                    try:
                        ts_norm = " ".join(ts_str.split())
                        dt_aware = datetime.strptime(f"{ts_norm} {tz_str}", "%Y-%m-%d %H:%M:%S %z")
                        if ms_str:
                            dt_aware = dt_aware.replace(microsecond=int((ms_str + "000000")[:6]))
                        dt = dt_aware.astimezone(timezone.utc).replace(tzinfo=None)
                    except Exception:
                        dt = _parse_str_to_utc_naive(ts_str)

                    records.append({
                        "cloud_provider": "GoogleDrive",
                        "account": discovered_account,
                        "local_path": raw_p,
                        "cloud_path_or_id": fname,
                        "file_size": 0,
                        "modified_time": dt,
                        "status": status,
                        "source_file": src_disp,
                    })
            except Exception as ex:
                self._log(f"Google Drive sync_log notice on {slog.name}: {ex}", "WARNING")

        if not records:
            return 0

        GDRIVE_FILES_DDL = (
            'CREATE TABLE IF NOT EXISTS "parsed_gdrive_files" ('
            "_row_id BIGINT, cloud_provider VARCHAR, account VARCHAR, "
            "local_path VARCHAR, cloud_path_or_id VARCHAR, file_size BIGINT, "
            "modified_time TIMESTAMP, status VARCHAR, source_file VARCHAR);"
        )

        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cur = conn.cursor()

            has_gd_tbl = (
                cur.execute(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'main' AND table_name = 'parsed_gdrive_files' LIMIT 1;"
                ).fetchone()
                is not None
            )
            existing_norm_paths: Set[str] = set()
            existing_bare_names: Set[str] = set()
            existing_cnt = 0
            if has_gd_tbl:
                gd_cols = {
                    str(r[0]).lower(): str(r[0])
                    for r in cur.execute('DESCRIBE "parsed_gdrive_files";').fetchall()
                }
                if "local_path" in gd_cols:
                    q_lp = f'"{gd_cols["local_path"]}"'
                    for (lp_val,) in cur.execute(f'SELECT {q_lp} FROM "parsed_gdrive_files";').fetchall():
                        existing_cnt += 1
                        norm_lp = _norm_gdrive_path(lp_val)
                        if norm_lp:
                            existing_norm_paths.add(norm_lp)
                            if "\\" not in norm_lp:
                                existing_bare_names.add(norm_lp)
                else:
                    cnt_row = cur.execute('SELECT COUNT(*) FROM "parsed_gdrive_files";').fetchone()
                    existing_cnt = int(cnt_row[0] or 0) if cnt_row else 0

                if existing_cnt > 0:
                    cloud_parser_ran = (
                        cur.execute(
                            "SELECT 1 FROM processing_logs WHERE module_name = 'Parser:Cloud' AND status = 'SUCCESS' LIMIT 1;"
                        ).fetchone()
                        is not None
                        or cur.execute(
                            "SELECT 1 FROM artifact_registry "
                            "WHERE (artifact_id IN ('gdrive_files', 'cloud_gdrive') OR table_name = 'parsed_gdrive_files') "
                            "AND source_tool = 'CloudParser' AND row_count > 0 LIMIT 1;"
                        ).fetchone()
                        is not None
                    )
                    if cloud_parser_ran:
                        return existing_cnt

            filtered_records: List[Dict[str, Any]] = []
            for rec in records:
                norm_lp = _norm_gdrive_path(rec.get("local_path"))
                bare_name = str(rec.get("cloud_path_or_id") or "").strip().lower()
                if norm_lp and norm_lp in existing_norm_paths:
                    continue
                if bare_name and bare_name in existing_bare_names:
                    continue
                if norm_lp:
                    existing_norm_paths.add(norm_lp)
                filtered_records.append(rec)

            if not filtered_records:
                return existing_cnt

            inserted = self.insert_records(
                table_name="parsed_gdrive_files",
                records=filtered_records,
                schema_ddl=GDRIVE_FILES_DDL,
                artifact_id="gdrive_files",
                category="CLOUD",
                display_name="Google Drive Synced Files",
                source_tool="NativeGDriveFallback",
                append=True,
            )
            try:
                total_after = int(cur.execute('SELECT COUNT(*) FROM "parsed_gdrive_files";').fetchone()[0] or 0)
                cur.execute(
                    "UPDATE artifact_registry SET row_count = ? WHERE artifact_id = 'gdrive_files' OR table_name = 'parsed_gdrive_files';",
                    [total_after],
                )
            except Exception:
                total_after = existing_cnt + int(inserted or 0)
            return total_after

    # -------------------------------------------------------------------------
    # A17: Non-Destructive Native $Recycle.Bin $I Metadata Parser (`raw_rbcmd`)
    # -------------------------------------------------------------------------
    def parse_recycle_bin_natively(self) -> int:
        existing = self._existing_table_count("raw_rbcmd")
        if existing > 0:
            return existing

        i_files = [
            p for p in self.staging_dir.rglob("$I*")
            if p.is_file() and 28 <= p.stat().st_size <= 8192 and p.name.upper() != "$I30"
        ]
        if not i_files:
            return 0

        records: List[Dict[str, Any]] = []
        for ipath in i_files:
            try:
                raw = ipath.read_bytes()
                if len(raw) < 28:
                    continue
                ver = struct.unpack_from("<Q", raw, 0)[0]
                if ver not in (1, 2):
                    continue
                fsize = struct.unpack_from("<Q", raw, 8)[0]
                del_ft = struct.unpack_from("<Q", raw, 16)[0]
                del_dt = windows_filetime_to_datetime(del_ft)
                if ver == 2:
                    name_len = struct.unpack_from("<I", raw, 24)[0]
                    orig_path = raw[28 : 28 + name_len * 2].decode("utf-16le", errors="ignore").rstrip("\x00")
                else:
                    orig_path = raw[24:544].decode("utf-16le", errors="ignore").split("\x00", 1)[0]
                if orig_path:
                    records.append({
                        "SourceName": self.resolve_evidence_path(ipath),
                        "FileName": Path(orig_path.replace("\\", "/")).name,
                        "FileSize": int(fsize),
                        "DeletedOn": del_dt,
                        "OriginalPath": orig_path,
                    })
            except Exception:
                continue

        if not records:
            return 0

        return self.insert_records(
            table_name="raw_rbcmd",
            records=records,
            artifact_id="fs_recyclebin",
            category="OPERATING SYSTEM",
            display_name="Recycle Bin ($I / $R)",
            source_tool="NativeRecycleBinParser",
        )

    # -------------------------------------------------------------------------
    # A10: Non-Destructive Registry OS Summary Fallback (`raw_recmd`)
    # -------------------------------------------------------------------------
    def parse_registry_os_summary_natively(self) -> int:
        existing = self._existing_table_count("raw_recmd")
        if existing > 0:
            return existing

        hives = self._discover_hives()
        if not hives:
            return 0

        records: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str, str]] = set()

        def add_fact(
            cat: str,
            desc: str,
            vname: str,
            vtype: str,
            val: str,
            hive_src: str,
            hive_type: str,
            key_path: str,
            last_write: Optional[datetime],
        ) -> None:
            v_clean = str(val or "").strip("\x00").strip()
            if not v_clean or (hive_src, key_path, vname) in seen_keys:
                return
            seen_keys.add((hive_src, key_path, vname))
            records.append({
                "HivePath": hive_src,
                "HiveType": hive_type,
                "Category": cat,
                "Description": desc,
                "KeyPath": key_path,
                "ValueName": vname,
                "ValueType": vtype,
                "ValueData": v_clean,
                "ValueData2": None,
                "ValueData3": None,
                "Comment": None,
                "LastWriteTimestamp": last_write,
            })

        for ht in hives:
            if ht.hive_type not in ("SOFTWARE", "SYSTEM", "SAM"):
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    if ht.hive_type == "SOFTWARE":
                        kp = r"Microsoft\Windows NT\CurrentVersion"
                        cv = reader.get_key(kp)
                        if cv is not None:
                            vmap = cv.value_map()
                            lw = cv.last_modified
                            for vname, label in (
                                ("ProductName", "OS Product Name"),
                                ("BuildLabEx", "OS Build Lab"),
                                ("CurrentBuild", "OS Build Number"),
                                ("DisplayVersion", "OS Display Version"),
                                ("RegisteredOwner", "Registered Owner"),
                                ("RegisteredOrganization", "Registered Organization"),
                                ("ProductId", "Windows Product ID"),
                                ("PathName", "System Root Path"),
                            ):
                                item = vmap.get(vname.lower())
                                sval = _val_as_str(item)
                                if sval:
                                    add_fact("OS Information", label, vname, item.value_type if item else "REG_SZ", sval, ht.display_source, "SOFTWARE", kp, lw)
                            inst_ts = _val_as_int(vmap.get("installdate"))
                            if inst_ts and inst_ts > 0:
                                inst_dt = datetime.fromtimestamp(inst_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                                add_fact("OS Information", "OS Install Date (UTC)", "InstallDate", "REG_DWORD", inst_dt, ht.display_source, "SOFTWARE", kp, lw)

                    elif ht.hive_type == "SYSTEM":
                        for cs in self._get_control_set_names(reader):
                            cn_kp = f"{cs}\\Control\\ComputerName\\ComputerName"
                            cn_k = reader.get_key(cn_kp)
                            if cn_k is not None:
                                cn_val = _val_as_str(cn_k.value_map().get("computername"))
                                if cn_val:
                                    add_fact("System Identity", "Computer Name (Hostname)", "ComputerName", "REG_SZ", cn_val, ht.display_source, "SYSTEM", cn_kp, cn_k.last_modified)

                            tz_kp = f"{cs}\\Control\\TimeZoneInformation"
                            tz_k = reader.get_key(tz_kp)
                            if tz_k is not None:
                                tz_map = tz_k.value_map()
                                for tzw in ("TimeZoneKeyName", "StandardName"):
                                    tz_s = _val_as_str(tz_map.get(tzw.lower()))
                                    if tz_s:
                                        add_fact("Time Zone", "System Time Zone", tzw, "REG_SZ", tz_s, ht.display_source, "SYSTEM", tz_kp, tz_k.last_modified)
                                        break

                            win_kp = f"{cs}\\Control\\Windows"
                            win_k = reader.get_key(win_kp)
                            if win_k is not None:
                                sd_b = _val_as_bytes(win_k.value_map().get("shutdowntime"))
                                if sd_b and len(sd_b) >= 8:
                                    sd_dt = windows_filetime_to_datetime(struct.unpack_from("<Q", sd_b, 0)[0])
                                    if sd_dt:
                                        add_fact("System State", "Last Recorded Shutdown (UTC)", "ShutdownTime", "REG_BINARY", sd_dt.strftime("%Y-%m-%d %H:%M:%S UTC"), ht.display_source, "SYSTEM", win_kp, win_k.last_modified)

                    elif ht.hive_type == "SAM":
                        for sam_kp in (r"SAM\Domains\Account\Users\Names", r"Domains\Account\Users\Names"):
                            names_k = reader.get_key(sam_kp)
                            if names_k is not None:
                                u_list = [sk.name for sk in names_k.iter_subkeys() if sk.name]
                                if u_list:
                                    add_fact("Local Accounts", "SAM Local User Accounts", "Names", "REG_NONE", ", ".join(u_list), ht.display_source, "SAM", sam_kp, names_k.last_modified)
                                break
            except Exception as ex:
                self._log(f"Registry summary fallback notice on {ht.path.name}: {ex}", "WARNING")

        if not records:
            return 0

        return self.insert_records(
            table_name="raw_recmd",
            records=records,
            artifact_id="registry_recmd",
            category="OPERATING SYSTEM",
            display_name="Registry Hive Batch Analysis (OS & System Facts)",
            source_tool="NativeRegistryParser",
        )


    # =========================================================================
    # 8 Magnet AXIOM Registry & Operating System Parsers
    # =========================================================================

    # 1. parsed_user_accounts (SAM + SOFTWARE ProfileList)
    def parse_user_accounts(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        sid_profile_map = self._build_sid_user_map(targets)
        records: List[Dict[str, Any]] = []
        seen_rids_per_prov: Set[Tuple[str, int]] = set()
        seen_sids: Set[Tuple[str, str]] = set()

        for ht in targets:
            if ht.hive_type != "SAM":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    domain_sid_prefix: Optional[str] = None
                    for acct_kp in (r"SAM\Domains\Account", r"Domains\Account"):
                        acct_k = reader.get_key(acct_kp)
                        if acct_k is not None:
                            v_blob = _val_as_bytes(acct_k.value_map().get("v"))
                            if v_blob and len(v_blob) >= 24:
                                for cand_off in (len(v_blob) - 24, len(v_blob) - 28):
                                    if cand_off >= 0:
                                        cand_sid = _decode_binary_sid(v_blob[cand_off : cand_off + 24])
                                        if cand_sid and cand_sid.startswith("S-1-5-21-"):
                                            domain_sid_prefix = cand_sid
                                            break
                            break

                    if not domain_sid_prefix:
                        for s_key in sid_profile_map:
                            if s_key.startswith("S-1-5-21-") and s_key.count("-") >= 7:
                                domain_sid_prefix = s_key.rsplit("-", 1)[0]
                                break

                    users_k: Optional[_RegKeyAdapter] = None
                    for users_kp in (r"SAM\Domains\Account\Users", r"Domains\Account\Users"):
                        users_k = reader.get_key(users_kp)
                        if users_k is not None:
                            break
                    if users_k is None:
                        continue

                    names_rid_map: Dict[int, Tuple[str, Optional[datetime]]] = {}
                    names_sub = users_k.get_subkey("Names")
                    if names_sub is not None:
                        for n_sk in names_sub.iter_subkeys():
                            # In SAM\...\Users\Names\<Username>, default value's data_type holds the RID!
                            for v_item in n_sk.iter_values():
                                m_hex = re.search(r"0x([0-9a-fA-F]+)", v_item.value_type)
                                if m_hex:
                                    try:
                                        names_rid_map[int(m_hex.group(1), 16)] = (n_sk.name, n_sk.last_modified)
                                    except Exception:
                                        pass

                    for sub in users_k.iter_subkeys():
                        if not re.match(r"^[0-9A-Fa-f]{8}$", sub.name):
                            continue
                        rid_from_key = int(sub.name, 16)
                        vmap = sub.value_map()
                        f_bytes = _val_as_bytes(vmap.get("f"))
                        v_bytes = _val_as_bytes(vmap.get("v"))

                        last_logon: Optional[datetime] = None
                        pwd_last_set: Optional[datetime] = None
                        last_failed: Optional[datetime] = None
                        rid = rid_from_key
                        acb_flags_int = 0
                        failed_cnt = 0
                        logon_cnt = 0

                        if f_bytes and len(f_bytes) >= 0x44:
                            last_logon = windows_filetime_to_datetime(struct.unpack_from("<Q", f_bytes, 0x08)[0])
                            pwd_last_set = windows_filetime_to_datetime(struct.unpack_from("<Q", f_bytes, 0x18)[0])
                            last_failed = windows_filetime_to_datetime(struct.unpack_from("<Q", f_bytes, 0x28)[0])
                            f_rid = struct.unpack_from("<I", f_bytes, 0x30)[0]
                            if f_rid > 0:
                                rid = int(f_rid)
                            acb_flags_int = struct.unpack_from("<H", f_bytes, 0x38)[0]
                            failed_cnt = int(struct.unpack_from("<H", f_bytes, 0x40)[0])
                            logon_cnt = int(struct.unpack_from("<H", f_bytes, 0x42)[0])

                        def _read_v_str(desc_offset: int) -> str:
                            if not v_bytes or len(v_bytes) < 0xCC or desc_offset + 8 > 0xCC:
                                return ""
                            s_off, s_len = struct.unpack_from("<II", v_bytes, desc_offset)
                            start = 0xCC + s_off
                            end = start + s_len
                            if s_len == 0 or start < 0xCC or end > len(v_bytes):
                                return ""
                            return v_bytes[start:end].decode("utf-16le", errors="ignore").rstrip("\x00").strip()

                        uname = _read_v_str(0x0C)
                        full_name = _read_v_str(0x18)
                        comment = _read_v_str(0x24)
                        if not uname and rid in names_rid_map:
                            uname = names_rid_map[rid][0]
                        if not uname:
                            continue

                        if (ht.provenance, rid) in seen_rids_per_prov:
                            continue
                        seen_rids_per_prov.add((ht.provenance, rid))

                        full_sid = f"{domain_sid_prefix}-{rid}" if domain_sid_prefix else f"RID-{rid}"
                        seen_sids.add((ht.provenance, full_sid))
                        prof_path = sid_profile_map.get(full_sid, ("", None))[1]
                        created_dt = names_rid_map.get(rid, ("", None))[1] or sub.last_modified

                        is_disabled = bool(acb_flags_int & 0x0001)
                        is_locked = bool(acb_flags_int & 0x0400)
                        pwd_not_req = bool(acb_flags_int & 0x0004)
                        flags_str = _format_acb_flags(acb_flags_int)

                        records.append({
                            "rid": int(rid),
                            "username": uname,
                            "full_name": full_name or None,
                            "comment": comment or None,
                            "account_flags": flags_str,
                            "last_logon_utc": last_logon,
                            "pwd_last_set_utc": pwd_last_set,
                            "last_failed_logon_utc": last_failed,
                            "logon_count": int(logon_cnt),
                            "source_hive": ht.display_source,
                            # schema.py / normalizer.py compatibility aliases
                            "user_sid": full_sid,
                            "sid": full_sid,
                            "account_type": "Local SAM User",
                            "is_disabled": is_disabled,
                            "is_locked": is_locked,
                            "password_not_required": pwd_not_req,
                            "login_count": int(logon_cnt),
                            "invalid_login_count": int(failed_cnt),
                            "last_login_utc": last_logon,
                            "last_password_change_utc": pwd_last_set,
                            "password_reset_utc": pwd_last_set,
                            "last_failed_login_utc": last_failed,
                            "account_created_utc": created_dt,
                            "created_utc": created_dt,
                            "profile_path": prof_path,
                            "hive_path": ht.display_source,
                            "source_file": ht.display_source,
                        })
            except Exception as ex:
                self._log(f"SAM user accounts parse notice on {ht.path.name}: {ex}", "WARNING")

        # Include domain / Microsoft accounts present in SOFTWARE ProfileList but not in local SAM
        for ht in targets:
            if ht.hive_type != "SOFTWARE":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    pl_key = reader.get_key(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
                    if pl_key is None:
                        continue
                    for sk in pl_key.iter_subkeys():
                        sid_str = sk.name.strip()
                        if not sid_str.startswith("S-1-5-21-"):
                            continue
                        if (ht.provenance, sid_str) in seen_sids:
                            continue
                        try:
                            rid_val = int(sid_str.rsplit("-", 1)[-1])
                        except Exception:
                            continue
                        if (ht.provenance, rid_val) in seen_rids_per_prov:
                            continue
                        p_img = _val_as_str(sk.value_map().get("profileimagepath"))
                        if not p_img:
                            continue
                        uname = Path(p_img.replace("\\", "/")).name
                        if not uname:
                            continue
                        seen_sids.add((ht.provenance, sid_str))
                        records.append({
                            "rid": rid_val,
                            "username": uname,
                            "full_name": None,
                            "comment": None,
                            "account_flags": "ProfileList Account",
                            "last_logon_utc": None,
                            "pwd_last_set_utc": None,
                            "last_failed_logon_utc": None,
                            "logon_count": 0,
                            "source_hive": ht.display_source,
                            "user_sid": sid_str,
                            "sid": sid_str,
                            "account_type": "Domain / Microsoft Profile",
                            "is_disabled": False,
                            "is_locked": False,
                            "password_not_required": False,
                            "login_count": 0,
                            "invalid_login_count": 0,
                            "last_login_utc": None,
                            "last_password_change_utc": None,
                            "password_reset_utc": None,
                            "last_failed_login_utc": None,
                            "account_created_utc": sk.last_modified,
                            "created_utc": sk.last_modified,
                            "profile_path": p_img,
                            "hive_path": ht.display_source,
                            "source_file": ht.display_source,
                        })
            except Exception:
                continue

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_user_accounts",
            """
            CREATE TABLE IF NOT EXISTS parsed_user_accounts (
                _row_id BIGINT, rid INTEGER, username VARCHAR, full_name VARCHAR,
                comment VARCHAR, account_flags VARCHAR, last_logon_utc TIMESTAMP,
                pwd_last_set_utc TIMESTAMP, last_failed_logon_utc TIMESTAMP,
                logon_count INTEGER, source_hive VARCHAR, user_sid VARCHAR, sid VARCHAR,
                account_type VARCHAR, is_disabled BOOLEAN, is_locked BOOLEAN,
                password_not_required BOOLEAN, login_count INTEGER,
                invalid_login_count INTEGER, last_login_utc TIMESTAMP,
                last_password_change_utc TIMESTAMP, password_reset_utc TIMESTAMP,
                last_failed_login_utc TIMESTAMP, account_created_utc TIMESTAMP,
                created_utc TIMESTAMP, profile_path VARCHAR, hive_path VARCHAR,
                source_file VARCHAR
            );
            """,
            [
                ("rid", "INTEGER"),
                ("username", "VARCHAR"),
                ("full_name", "VARCHAR"),
                ("comment", "VARCHAR"),
                ("account_flags", "VARCHAR"),
                ("last_logon_utc", "TIMESTAMP"),
                ("pwd_last_set_utc", "TIMESTAMP"),
                ("last_failed_logon_utc", "TIMESTAMP"),
                ("logon_count", "INTEGER"),
                ("source_hive", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_user_accounts",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_user_accounts",
            category="OPERATING SYSTEM",
            display_name="Windows User Accounts (SAM / Registry)",
            source_tool="NativeRegistryParser",
        )

    # 2. parsed_windows_services (SYSTEM Services)
    def parse_windows_services(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        records: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()

        for ht in targets:
            if ht.hive_type != "SYSTEM":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    csets = self._get_control_set_names(reader)
                    if not csets:
                        continue
                    cs = csets[0]
                    svc_root = reader.get_key(f"{cs}\\Services")
                    if svc_root is None:
                        continue

                    for sk in svc_root.iter_subkeys():
                        sname = sk.name.strip()
                        if not sname or (ht.provenance, sname.lower()) in seen:
                            continue
                        vmap = sk.value_map()
                        start_int = _val_as_int(vmap.get("start"))
                        type_int = _val_as_int(vmap.get("type"))
                        img_path = _val_as_str(vmap.get("imagepath"))
                        disp_name = _val_as_str(vmap.get("displayname"))
                        obj_name = _val_as_str(vmap.get("objectname"))
                        desc_s = _val_as_str(vmap.get("description"))
                        err_int = _val_as_int(vmap.get("errorcontrol"))
                        fail_cmd = _val_as_str(vmap.get("failurecommand"))
                        delayed = _val_as_int(vmap.get("delayedautostart"))

                        svc_dll: Optional[str] = None
                        params_sk = sk.get_subkey("Parameters")
                        if params_sk is not None:
                            svc_dll = _val_as_str(params_sk.value_map().get("servicedll"))

                        if img_path is None and svc_dll is None and start_int is None and type_int is None:
                            continue

                        seen.add((ht.provenance, sname.lower()))
                        start_label = _SERVICE_START_TYPES.get(start_int, str(start_int) if start_int is not None else "Unknown")
                        if start_int == 2 and delayed == 1:
                            start_label = "Auto (Delayed)"
                        type_label = _SERVICE_TYPES.get(type_int, f"0x{type_int:X}" if type_int is not None else "Unknown")
                        lw = sk.last_modified
                        kp = f"{cs}\\Services\\{sname}"

                        records.append({
                            "service_name": sname,
                            "display_name": disp_name or sname,
                            "image_path": img_path or svc_dll,
                            "start_type": start_label,
                            "service_type": type_label,
                            "object_name": obj_name,
                            "description": desc_s,
                            "last_write_utc": lw,
                            "source_hive": ht.display_source,
                            # schema.py / normalizer.py compatibility aliases
                            "service_dll": svc_dll,
                            "account_name": obj_name,
                            "error_control": str(err_int) if err_int is not None else None,
                            "failure_command": fail_cmd,
                            "last_modified_utc": lw,
                            "key_path": kp,
                            "hive_path": ht.display_source,
                            "source_file": ht.display_source,
                        })
            except Exception as ex:
                self._log(f"Windows services parse notice on {ht.path.name}: {ex}", "WARNING")

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_windows_services",
            """
            CREATE TABLE IF NOT EXISTS parsed_windows_services (
                _row_id BIGINT, service_name VARCHAR, display_name VARCHAR,
                image_path VARCHAR, start_type VARCHAR, service_type VARCHAR,
                object_name VARCHAR, description VARCHAR, last_write_utc TIMESTAMP,
                source_hive VARCHAR, service_dll VARCHAR, account_name VARCHAR,
                error_control VARCHAR, failure_command VARCHAR,
                last_modified_utc TIMESTAMP, key_path VARCHAR, hive_path VARCHAR,
                source_file VARCHAR
            );
            """,
            [
                ("service_name", "VARCHAR"),
                ("display_name", "VARCHAR"),
                ("image_path", "VARCHAR"),
                ("start_type", "VARCHAR"),
                ("service_type", "VARCHAR"),
                ("object_name", "VARCHAR"),
                ("description", "VARCHAR"),
                ("last_write_utc", "TIMESTAMP"),
                ("source_hive", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_windows_services",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_windows_services",
            category="OPERATING SYSTEM",
            display_name="Windows Services Configuration",
            source_tool="NativeRegistryParser",
        )

    # 3. parsed_autoruns (SOFTWARE, NTUSER.DAT + Startup folder files)
    def parse_autoruns(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        records: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        def _emit(
            entry_name: str,
            cmd_path: str,
            loc_key: str,
            user: Optional[str],
            lw: Optional[datetime],
            src_hive: str,
            ar_type: str = "Run Key",
        ) -> None:
            e_clean = entry_name.strip()
            c_clean = cmd_path.strip("\x00").strip()
            if not e_clean or not c_clean:
                return
            dedup = (src_hive, loc_key.lower(), e_clean.lower(), c_clean.lower())
            if dedup in seen:
                return
            seen.add(dedup)
            records.append({
                "entry_name": e_clean,
                "command_or_path": c_clean,
                "location_key": loc_key,
                "username": user,
                "last_write_utc": lw,
                "source_hive": src_hive,
                # schema.py / view_autoruns / normalizer.py compatibility aliases
                "autorun_type": ar_type,
                "category": ar_type,
                "location": loc_key,
                "key_path": loc_key,
                "value_name": e_clean,
                "command": c_clean,
                "image_path": c_clean,
                "launch_string": c_clean,
                "enabled": True,
                "publisher": None,
                "last_modified_utc": lw,
                "hive_path": src_hive,
                "source_file": src_hive,
            })

        software_run_keys = (
            r"Microsoft\Windows\CurrentVersion\Run",
            r"Microsoft\Windows\CurrentVersion\RunOnce",
            r"Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"Microsoft\Windows\CurrentVersion\RunServices",
            r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        )
        ntuser_run_keys = (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        )

        for ht in targets:
            if ht.hive_type == "SOFTWARE":
                try:
                    with _HiveReader(ht.path) as reader:
                        for rk in software_run_keys:
                            k = reader.get_key(rk)
                            if k is None:
                                continue
                            for v in k.iter_values():
                                if v.name == "(default)":
                                    continue
                                sval = _val_as_str(v)
                                if sval:
                                    _emit(v.name, sval, k.path, None, k.last_modified, ht.display_source, "Run Key")

                        # Winlogon Shell / Userinit / Taskman
                        for wl_kp in (
                            r"Microsoft\Windows NT\CurrentVersion\Winlogon",
                            r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        ):
                            wl_k = reader.get_key(wl_kp)
                            if wl_k is not None:
                                wl_map = wl_k.value_map()
                                for wv in ("Userinit", "Shell", "Taskman"):
                                    sval = _val_as_str(wl_map.get(wv.lower()))
                                    if sval:
                                        _emit(wv, sval, wl_k.path, None, wl_k.last_modified, ht.display_source, "Winlogon")

                        # Windows AppInit_DLLs / Load
                        win_k = reader.get_key(r"Microsoft\Windows NT\CurrentVersion\Windows")
                        if win_k is not None:
                            w_map = win_k.value_map()
                            for wv in ("AppInit_DLLs", "Load"):
                                sval = _val_as_str(w_map.get(wv.lower()))
                                if sval:
                                    _emit(wv, sval, win_k.path, None, win_k.last_modified, ht.display_source, "AppInit")

                        # Image File Execution Options Debugger persistence
                        ifeo_k = reader.get_key(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
                        if ifeo_k is not None:
                            for sk in ifeo_k.iter_subkeys():
                                dbg = _val_as_str(sk.value_map().get("debugger"))
                                if dbg:
                                    _emit(sk.name, dbg, sk.path, None, sk.last_modified, ht.display_source, "IFEO Debugger")

                        # Active Setup StubPath
                        as_k = reader.get_key(r"Microsoft\Active Setup\Installed Components")
                        if as_k is not None:
                            for sk in as_k.iter_subkeys():
                                stub = _val_as_str(sk.value_map().get("stubpath"))
                                if stub:
                                    lbl = _val_as_str(sk.value_map().get("(default)")) or sk.name
                                    _emit(lbl, stub, sk.path, None, sk.last_modified, ht.display_source, "Active Setup")
                except Exception as ex:
                    self._log(f"Autoruns SOFTWARE parse notice on {ht.path.name}: {ex}", "WARNING")

            elif ht.hive_type == "NTUSER":
                try:
                    with _HiveReader(ht.path) as reader:
                        for rk in ntuser_run_keys:
                            k = reader.get_key(rk)
                            if k is None:
                                continue
                            for v in k.iter_values():
                                if v.name == "(default)":
                                    continue
                                sval = _val_as_str(v)
                                if sval:
                                    _emit(v.name, sval, k.path, ht.username, k.last_modified, ht.display_source, "User Run Key")

                        wl_u = reader.get_key(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
                        if wl_u is not None:
                            sh_val = _val_as_str(wl_u.value_map().get("shell"))
                            if sh_val:
                                _emit("Shell", sh_val, wl_u.path, ht.username, wl_u.last_modified, ht.display_source, "User Winlogon")

                        win_u = reader.get_key(r"Software\Microsoft\Windows NT\CurrentVersion\Windows")
                        if win_u is not None:
                            wu_map = win_u.value_map()
                            for wv in ("Load", "Run"):
                                sval = _val_as_str(wu_map.get(wv.lower()))
                                if sval:
                                    _emit(wv, sval, win_u.path, ht.username, win_u.last_modified, ht.display_source, "User Windows")
                except Exception as ex:
                    self._log(f"Autoruns NTUSER parse notice on {ht.path.name}: {ex}", "WARNING")

        # Also check staged Startup folder files if present
        if self.staging_dir.exists():
            for p in self.staging_dir.rglob("*"):
                if not p.is_file():
                    continue
                p_posix = p.as_posix().lower()
                if "/start menu/programs/startup/" in p_posix and p.name.lower() != "desktop.ini":
                    _cr, mod_dt, _acc = self._get_source_timestamps(p)
                    disp = self.resolve_evidence_path(p)
                    u_name = self._derive_user_from_path_str(disp)
                    _emit(
                        p.name,
                        disp,
                        "Startup Folder",
                        None if u_name == "Unknown" else u_name,
                        mod_dt,
                        disp,
                        "Startup Folder",
                    )

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_autoruns",
            """
            CREATE TABLE IF NOT EXISTS parsed_autoruns (
                _row_id BIGINT, entry_name VARCHAR, command_or_path VARCHAR,
                location_key VARCHAR, username VARCHAR, last_write_utc TIMESTAMP,
                source_hive VARCHAR, autorun_type VARCHAR, category VARCHAR,
                location VARCHAR, key_path VARCHAR, value_name VARCHAR,
                command VARCHAR, image_path VARCHAR, launch_string VARCHAR,
                enabled BOOLEAN, publisher VARCHAR, last_modified_utc TIMESTAMP,
                hive_path VARCHAR, source_file VARCHAR
            );
            """,
            [
                ("entry_name", "VARCHAR"),
                ("command_or_path", "VARCHAR"),
                ("location_key", "VARCHAR"),
                ("username", "VARCHAR"),
                ("last_write_utc", "TIMESTAMP"),
                ("source_hive", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_autoruns",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_autoruns",
            category="OPERATING SYSTEM",
            display_name="Parsed Autoruns (Registry & Startup)",
            source_tool="NativeRegistryParser",
        )

    # 4. parsed_userassist (NTUSER.DAT ROT13 v5 72B + XP v3 16B)
    def parse_userassist(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        records: List[Dict[str, Any]] = []

        for ht in targets:
            if ht.hive_type != "NTUSER":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    ua_root = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
                    if ua_root is None:
                        continue
                    for guid_sk in ua_root.iter_subkeys():
                        guid_name = guid_sk.name.strip()
                        cnt_sk = guid_sk.get_subkey("Count")
                        if cnt_sk is None:
                            continue
                        for v in cnt_sk.iter_values():
                            if not v.name or v.name in ("(default)", "UEME_CTLSESSION"):
                                continue
                            decoded_name = _decode_userassist_path(v.name)
                            if decoded_name.upper().startswith("UEME_CTLSESSION"):
                                continue
                            raw_b = _val_as_bytes(v)
                            if not raw_b:
                                continue

                            run_cnt: int = 0
                            focus_cnt: Optional[int] = None
                            focus_ms: Optional[int] = None
                            last_exec: Optional[datetime] = None

                            if len(raw_b) >= 72:
                                run_cnt = int(struct.unpack_from("<I", raw_b, 4)[0])
                                focus_cnt = int(struct.unpack_from("<I", raw_b, 8)[0])
                                focus_ms = int(struct.unpack_from("<I", raw_b, 12)[0])
                                last_exec = windows_filetime_to_datetime(struct.unpack_from("<Q", raw_b, 60)[0])
                            elif len(raw_b) == 16:
                                raw_c = int(struct.unpack_from("<I", raw_b, 4)[0])
                                run_cnt = (raw_c - 5) if raw_c >= 5 else raw_c
                                last_exec = windows_filetime_to_datetime(struct.unpack_from("<Q", raw_b, 8)[0])
                            else:
                                continue

                            records.append({
                                "program_path": decoded_name,
                                "guid": guid_name,
                                "run_count": run_cnt,
                                "focus_count": focus_cnt,
                                "focus_time_ms": focus_ms,
                                "last_executed_utc": last_exec,
                                "username": ht.username,
                                "source_hive": ht.display_source,
                                # schema.py / view_userassist / normalizer.py compatibility aliases
                                "user_sid": None,
                                "rot13_name": v.name,
                                "last_run_utc": last_exec,
                                "key_path": cnt_sk.path,
                                "hive_path": ht.display_source,
                                "source_file": ht.display_source,
                            })
            except Exception as ex:
                self._log(f"UserAssist parse notice on {ht.path.name}: {ex}", "WARNING")

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_userassist",
            """
            CREATE TABLE IF NOT EXISTS parsed_userassist (
                _row_id BIGINT, program_path VARCHAR, guid VARCHAR,
                run_count INTEGER, focus_count INTEGER, focus_time_ms BIGINT,
                last_executed_utc TIMESTAMP, username VARCHAR, source_hive VARCHAR,
                user_sid VARCHAR, rot13_name VARCHAR, last_run_utc TIMESTAMP,
                key_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
            );
            """,
            [
                ("program_path", "VARCHAR"),
                ("guid", "VARCHAR"),
                ("run_count", "INTEGER"),
                ("focus_count", "INTEGER"),
                ("focus_time_ms", "BIGINT"),
                ("last_executed_utc", "TIMESTAMP"),
                ("username", "VARCHAR"),
                ("source_hive", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_userassist",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_userassist",
            category="OPERATING SYSTEM",
            display_name="Parsed UserAssist Execution",
            source_tool="NativeRegistryParser",
        )

    # 5. parsed_bam_dam (SYSTEM BAM & DAM UserSettings)
    def parse_bam_dam(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        sid_map = self._build_sid_user_map(targets)
        records: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        bam_dam_families = (
            ("BAM", r"Services\bam\State\UserSettings"),
            ("BAM", r"Services\bam\UserSettings"),
            ("DAM", r"Services\dam\State\UserSettings"),
            ("DAM", r"Services\dam\UserSettings"),
        )

        for ht in targets:
            if ht.hive_type != "SYSTEM":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    csets = self._get_control_set_names(reader)
                    if not csets:
                        continue
                    cs = csets[0]
                    for mod_type, rel_kp in bam_dam_families:
                        fam_key = reader.get_key(f"{cs}\\{rel_kp}")
                        if fam_key is None:
                            continue
                        for sid_sk in fam_key.iter_subkeys():
                            sid_str = sid_sk.name.strip()
                            vmap = sid_sk.value_map()
                            seq_no = _val_as_int(vmap.get("sequencenumber"))
                            uname = sid_map.get(sid_str, (None, None))[0]
                            for v in sid_sk.iter_values():
                                if v.name.lower() in ("version", "sequencenumber", "(default)"):
                                    continue
                                raw_b = _val_as_bytes(v)
                                if not raw_b or len(raw_b) < 8:
                                    continue
                                exec_dt = windows_filetime_to_datetime(struct.unpack_from("<Q", raw_b, 0)[0])
                                exe_path = v.name.strip()
                                dedup = (ht.provenance, mod_type, sid_str, exe_path.lower())
                                if dedup in seen:
                                    continue
                                seen.add(dedup)
                                app_n = Path(exe_path.replace("\\", "/")).name
                                records.append({
                                    "sid": sid_str,
                                    "executable_path": exe_path,
                                    "last_execution_utc": exec_dt,
                                    "type": mod_type,
                                    "source_hive": ht.display_source,
                                    # schema.py / view_bam_dam / normalizer.py compatibility aliases
                                    "service_type": mod_type,
                                    "user_sid": sid_str,
                                    "username": uname,
                                    "app_name": app_n,
                                    "sequence_number": seq_no,
                                    "execution_time_utc": exec_dt,
                                    "key_path": sid_sk.path,
                                    "hive_path": ht.display_source,
                                    "source_file": ht.display_source,
                                })
            except Exception as ex:
                self._log(f"BAM/DAM parse notice on {ht.path.name}: {ex}", "WARNING")

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_bam_dam",
            """
            CREATE TABLE IF NOT EXISTS parsed_bam_dam (
                _row_id BIGINT, sid VARCHAR, executable_path VARCHAR,
                last_execution_utc TIMESTAMP, type VARCHAR, source_hive VARCHAR,
                service_type VARCHAR, user_sid VARCHAR, username VARCHAR,
                app_name VARCHAR, sequence_number INTEGER,
                execution_time_utc TIMESTAMP, key_path VARCHAR,
                hive_path VARCHAR, source_file VARCHAR
            );
            """,
            [
                ("sid", "VARCHAR"),
                ("executable_path", "VARCHAR"),
                ("last_execution_utc", "TIMESTAMP"),
                ("type", "VARCHAR"),
                ("source_hive", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_bam_dam",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_bam_dam",
            category="OPERATING SYSTEM",
            display_name="Parsed BAM/DAM Execution",
            source_tool="NativeRegistryParser",
        )

    # 6. parsed_registry_mru (NTUSER.DAT & UsrClass.dat)
    def parse_registry_mru(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        records: List[Dict[str, Any]] = []

        def _parse_mrulistex(vmap: Dict[str, RegValueItem]) -> Dict[str, int]:
            order: Dict[str, int] = {}
            b = _val_as_bytes(vmap.get("mrulistex"))
            if not b:
                return order
            for pos_idx in range(0, len(b) - 3, 4):
                entry_id = struct.unpack_from("<I", b, pos_idx)[0]
                if entry_id == 0xFFFFFFFF:
                    break
                order[str(entry_id)] = pos_idx // 4
            return order

        def _parse_mrulist_ascii(vmap: Dict[str, RegValueItem]) -> Dict[str, int]:
            order: Dict[str, int] = {}
            s = _val_as_str(vmap.get("mrulist"))
            if not s:
                return order
            for idx, ch in enumerate(s):
                order[ch.lower()] = idx
            return order

        def _emit_mru(
            mru_type: str,
            kp: str,
            entry_name: str,
            val_text: str,
            pos: Optional[int],
            lw: Optional[datetime],
            user: Optional[str],
            src_hive: str,
            ext: Optional[str] = None,
        ) -> None:
            clean_val = val_text.strip("\x00").strip()
            if not clean_val:
                return
            records.append({
                "mru_type": mru_type,
                "key_path": kp,
                "entry_name": entry_name,
                "value_text": clean_val,
                "mru_position": pos,
                "last_write_utc": lw,
                "username": user,
                "source_hive": src_hive,
                # schema.py / normalizer.py compatibility aliases
                "category": mru_type,
                "value_name": entry_name,
                "target_path": clean_val,
                "target_name": Path(clean_val.replace("\\", "/")).name or clean_val,
                "entry_value": clean_val,
                "extension": ext,
                "last_modified_utc": lw,
                "hive_path": src_hive,
                "source_file": src_hive,
            })

        for ht in targets:
            if ht.hive_type == "NTUSER":
                try:
                    with _HiveReader(ht.path) as reader:
                        # 1. RecentDocs (+ .ext subkeys)
                        rd_root = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
                        if rd_root is not None:
                            for rd_k, ext_lbl in [(rd_root, None)] + [(sk, sk.name) for sk in rd_root.iter_subkeys()]:
                                vmap = rd_k.value_map()
                                order = _parse_mrulistex(vmap)
                                for v in rd_k.iter_values():
                                    if v.name.lower() in ("mrulistex", "mrulist", "(default)"):
                                        continue
                                    raw_b = _val_as_bytes(v)
                                    if not raw_b:
                                        continue
                                    prim, lnk_n = _extract_recentdocs_names(raw_b)
                                    text_out = f"{prim} ({lnk_n})" if (prim and lnk_n and lnk_n != prim) else (prim or lnk_n)
                                    _emit_mru(
                                        "RecentDocs",
                                        rd_k.path,
                                        v.name,
                                        text_out,
                                        order.get(v.name),
                                        rd_k.last_modified,
                                        ht.username,
                                        ht.display_source,
                                        ext=ext_lbl,
                                    )

                        # 2. ComDlg32\OpenSavePidlMRU
                        os_root = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU")
                        if os_root is not None:
                            for sk in [os_root] + os_root.iter_subkeys():
                                vmap = sk.value_map()
                                order = _parse_mrulistex(vmap)
                                ext_lbl = None if sk is os_root else sk.name
                                for v in sk.iter_values():
                                    if v.name.lower() in ("mrulistex", "mrulist", "(default)"):
                                        continue
                                    raw_b = _val_as_bytes(v)
                                    if not raw_b:
                                        continue
                                    segs = _extract_pidl_strings(raw_b)
                                    val_s = "\\".join(segs) if segs else raw_b.decode("utf-16le", errors="ignore").split("\x00", 1)[0]
                                    _emit_mru(
                                        "OpenSavePidlMRU",
                                        sk.path,
                                        v.name,
                                        val_s,
                                        order.get(v.name),
                                        sk.last_modified,
                                        ht.username,
                                        ht.display_source,
                                        ext=ext_lbl,
                                    )

                        # 3. ComDlg32\LastVisitedPidlMRU
                        lv_k = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU")
                        if lv_k is not None:
                            vmap = lv_k.value_map()
                            order = _parse_mrulistex(vmap)
                            for v in lv_k.iter_values():
                                if v.name.lower() in ("mrulistex", "mrulist", "(default)"):
                                    continue
                                raw_b = _val_as_bytes(v)
                                if not raw_b:
                                    continue
                                end_u16 = 0
                                while end_u16 + 2 <= len(raw_b):
                                    if raw_b[end_u16 : end_u16 + 2] == b"\x00\x00":
                                        break
                                    end_u16 += 2
                                exe_s = raw_b[:end_u16].decode("utf-16le", errors="ignore").strip()
                                pidl_segs = _extract_pidl_strings(raw_b[end_u16 + 2 :])
                                dir_s = "\\".join(pidl_segs)
                                val_s = f"{exe_s} -> {dir_s}" if (exe_s and dir_s) else (exe_s or dir_s)
                                _emit_mru(
                                    "LastVisitedPidlMRU",
                                    lv_k.path,
                                    v.name,
                                    val_s,
                                    order.get(v.name),
                                    lv_k.last_modified,
                                    ht.username,
                                    ht.display_source,
                                )

                        # 4. Explorer\WordWheelQuery
                        ww_k = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery")
                        if ww_k is not None:
                            vmap = ww_k.value_map()
                            order = _parse_mrulistex(vmap)
                            for v in ww_k.iter_values():
                                if v.name.lower() in ("mrulistex", "mrulist", "(default)"):
                                    continue
                                raw_b = _val_as_bytes(v)
                                q_str = (
                                    raw_b.decode("utf-16le", errors="ignore").rstrip("\x00").strip()
                                    if raw_b
                                    else (_val_as_str(v) or "")
                                )
                                _emit_mru(
                                    "WordWheelQuery",
                                    ww_k.path,
                                    v.name,
                                    q_str,
                                    order.get(v.name),
                                    ww_k.last_modified,
                                    ht.username,
                                    ht.display_source,
                                )

                        # 5. Explorer\TypedPaths
                        tp_k = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
                        if tp_k is not None:
                            for v in tp_k.iter_values():
                                if v.name == "(default)":
                                    continue
                                sval = _val_as_str(v)
                                if sval:
                                    m_num = re.search(r"(\d+)$", v.name)
                                    pos_i = int(m_num.group(1)) if m_num else None
                                    _emit_mru(
                                        "TypedPaths",
                                        tp_k.path,
                                        v.name,
                                        sval,
                                        pos_i,
                                        tp_k.last_modified,
                                        ht.username,
                                        ht.display_source,
                                    )

                        # 6. Internet Explorer\TypedURLs (+ TypedURLsTime when present)
                        tu_k = reader.get_key(r"Software\Microsoft\Internet Explorer\TypedURLs")
                        if tu_k is not None:
                            tu_time_k = reader.get_key(r"Software\Microsoft\Internet Explorer\TypedURLsTime")
                            tu_times = tu_time_k.value_map() if tu_time_k is not None else {}
                            for v in tu_k.iter_values():
                                if v.name == "(default)":
                                    continue
                                sval = _val_as_str(v)
                                if sval:
                                    m_num = re.search(r"(\d+)$", v.name)
                                    pos_i = int(m_num.group(1)) if m_num else None
                                    url_ts = tu_k.last_modified
                                    tb = _val_as_bytes(tu_times.get(v.name.lower()))
                                    if tb and len(tb) >= 8:
                                        ft_dt = windows_filetime_to_datetime(struct.unpack_from("<Q", tb, 0)[0])
                                        if ft_dt:
                                            url_ts = ft_dt
                                    _emit_mru(
                                        "TypedURLs",
                                        tu_k.path,
                                        v.name,
                                        sval,
                                        pos_i,
                                        url_ts,
                                        ht.username,
                                        ht.display_source,
                                    )

                        # 7. Explorer\RunMRU
                        run_mru_k = reader.get_key(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
                        if run_mru_k is not None:
                            vmap = run_mru_k.value_map()
                            order_a = _parse_mrulist_ascii(vmap)
                            for v in run_mru_k.iter_values():
                                if v.name.lower() in ("mrulist", "mrulistex", "(default)"):
                                    continue
                                sval = _val_as_str(v)
                                if sval:
                                    if sval.endswith("\\1"):
                                        sval = sval[:-2]
                                    _emit_mru(
                                        "RunMRU",
                                        run_mru_k.path,
                                        v.name,
                                        sval,
                                        order_a.get(v.name.lower()),
                                        run_mru_k.last_modified,
                                        ht.username,
                                        ht.display_source,
                                    )
                except Exception as ex:
                    self._log(f"Registry MRU NTUSER parse notice on {ht.path.name}: {ex}", "WARNING")

            elif ht.hive_type == "USRCLASS":
                try:
                    with _HiveReader(ht.path) as reader:
                        # UsrClass.dat MuiCache & VirtualStore / Shell MRU entries
                        for mc_kp in (
                            r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                            r"Local Settings\ImmutableMuiCache",
                        ):
                            mc_k = reader.get_key(mc_kp)
                            if mc_k is None:
                                continue
                            for idx, v in enumerate(mc_k.iter_values()):
                                if v.name.lower() in ("langid", "(default)"):
                                    continue
                                sval = _val_as_str(v)
                                text_out = f"{v.name} ({sval})" if sval else v.name
                                _emit_mru(
                                    "MuiCache",
                                    mc_k.path,
                                    v.name,
                                    text_out,
                                    idx,
                                    mc_k.last_modified,
                                    ht.username,
                                    ht.display_source,
                                )
                        # Also check if RecentDocs / ComDlg32 keys exist in UsrClass
                        for sub_rel, mtype in (
                            (r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "RecentDocs"),
                            (r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", "OpenSavePidlMRU"),
                        ):
                            uk = reader.get_key(sub_rel)
                            if uk is not None:
                                vmap = uk.value_map()
                                order = _parse_mrulistex(vmap)
                                for v in uk.iter_values():
                                    if v.name.lower() in ("mrulistex", "mrulist", "(default)"):
                                        continue
                                    raw_b = _val_as_bytes(v)
                                    val_s = (
                                        _extract_recentdocs_names(raw_b)[0]
                                        if raw_b
                                        else (_val_as_str(v) or "")
                                    )
                                    _emit_mru(
                                        mtype,
                                        uk.path,
                                        v.name,
                                        val_s,
                                        order.get(v.name),
                                        uk.last_modified,
                                        ht.username,
                                        ht.display_source,
                                    )
                except Exception as ex:
                    self._log(f"Registry MRU UsrClass parse notice on {ht.path.name}: {ex}", "WARNING")

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_registry_mru",
            """
            CREATE TABLE IF NOT EXISTS parsed_registry_mru (
                _row_id BIGINT, mru_type VARCHAR, key_path VARCHAR,
                entry_name VARCHAR, value_text VARCHAR, mru_position INTEGER,
                last_write_utc TIMESTAMP, username VARCHAR, source_hive VARCHAR,
                category VARCHAR, value_name VARCHAR, target_path VARCHAR,
                target_name VARCHAR, entry_value VARCHAR, extension VARCHAR,
                last_modified_utc TIMESTAMP, hive_path VARCHAR, source_file VARCHAR
            );
            """,
            [
                ("mru_type", "VARCHAR"),
                ("key_path", "VARCHAR"),
                ("entry_name", "VARCHAR"),
                ("value_text", "VARCHAR"),
                ("mru_position", "INTEGER"),
                ("last_write_utc", "TIMESTAMP"),
                ("username", "VARCHAR"),
                ("source_hive", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_registry_mru",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_registry_mru",
            category="OPERATING SYSTEM",
            display_name="Registry MRU (RecentDocs / OpenSavePidl / RunMRU)",
            source_tool="NativeRegistryParser",
        )

    # 7. parsed_network_profiles (SOFTWARE NetworkList + Staged WLAN XML)
    def parse_network_profiles(self, hives: Optional[List[HiveTarget]] = None) -> int:
        targets = hives if hives is not None else self._discover_hives()
        records: List[Dict[str, Any]] = []

        # Lookup ActiveTimeBias from active SYSTEM hive if present
        bias_mins = 0
        for ht in targets:
            if ht.hive_type == "SYSTEM" and ht.provenance == "active":
                try:
                    with _HiveReader(ht.path) as sys_reader:
                        bias_mins = self._get_active_time_bias_minutes(sys_reader)
                        break
                except Exception:
                    pass

        cat_map = {0: "Public", 1: "Private", 2: "Domain"}
        ntype_map = {6: "Wired", 23: "VPN", 71: "Wireless", 243: "Mobile Broadband"}

        for ht in targets:
            if ht.hive_type != "SOFTWARE":
                continue
            try:
                with _HiveReader(ht.path) as reader:
                    sig_by_guid: Dict[str, Dict[str, Any]] = {}
                    for sig_kind in ("Unmanaged", "Managed"):
                        sig_root = reader.get_key(
                            f"Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\{sig_kind}"
                        )
                        if sig_root is None:
                            continue
                        for sk in sig_root.iter_subkeys():
                            smap = sk.value_map()
                            pguid = (_val_as_str(smap.get("profileguid")) or "").upper()
                            if not pguid:
                                continue
                            mac_b = _val_as_bytes(smap.get("defaultgatewaymac"))
                            mac_str = (
                                ":".join(f"{b:02X}" for b in mac_b[:6])
                                if (mac_b and len(mac_b) >= 6 and any(b != 0 for b in mac_b[:6]))
                                else None
                            )
                            sig_by_guid[pguid] = {
                                "dns_suffix": _val_as_str(smap.get("dnssuffix")),
                                "first_network": _val_as_str(smap.get("firstnetwork")),
                                "default_gateway_mac": mac_str,
                                "managed": (sig_kind == "Managed"),
                            }

                    prof_root = reader.get_key(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
                    if prof_root is None:
                        continue
                    for p_sk in prof_root.iter_subkeys():
                        pguid = p_sk.name.strip()
                        vmap = p_sk.value_map()
                        pname = _val_as_str(vmap.get("profilename")) or pguid
                        pdesc = _val_as_str(vmap.get("description"))
                        cat_code = _val_as_int(vmap.get("category"))
                        ntype_code = _val_as_int(vmap.get("nametype"))
                        managed_flag = bool(_val_as_int(vmap.get("managed")) or 0)

                        dt_created = _decode_systemtime_16(_val_as_bytes(vmap.get("datecreated")), bias_minutes=bias_mins)
                        dt_last = _decode_systemtime_16(_val_as_bytes(vmap.get("datelastconnected")), bias_minutes=bias_mins)

                        sig_info = sig_by_guid.get(pguid.upper(), {})
                        dns_sfx = sig_info.get("dns_suffix")
                        first_net = sig_info.get("first_network")
                        gw_mac = sig_info.get("default_gateway_mac")
                        is_managed = managed_flag or bool(sig_info.get("managed"))

                        cat_label = cat_map.get(cat_code, str(cat_code) if cat_code is not None else "Unknown")
                        ntype_label = ntype_map.get(ntype_code, str(ntype_code) if ntype_code is not None else "Network")
                        ssid_or_dns = first_net or dns_sfx or pname

                        records.append({
                            "profile_name": pname,
                            "ssid_or_dns": ssid_or_dns,
                            "description": pdesc,
                            "category": cat_label,
                            "date_created_utc": dt_created,
                            "date_last_connected_utc": dt_last,
                            "default_gateway_mac": gw_mac,
                            "auth_type": "Domain/Managed" if is_managed else ntype_label,
                            "source": ht.display_source,
                            # schema.py / normalizer.py compatibility aliases
                            "profile_guid": pguid,
                            "network_type": ntype_label,
                            "managed": is_managed,
                            "dns_suffix": dns_sfx,
                            "ssid": first_net if ntype_code == 71 else None,
                            "ip_address": None,
                            "dhcp_server": None,
                            "first_connected_utc": dt_created,
                            "last_connected_utc": dt_last,
                            "key_path": p_sk.path,
                            "hive_path": ht.display_source,
                            "source_file": ht.display_source,
                        })
            except Exception as ex:
                self._log(f"NetworkList parse notice on {ht.path.name}: {ex}", "WARNING")

        # Scan staged WLAN XML profiles (`Wlansvc/Profiles/Interfaces/.../*.xml` or `WLAN/*.xml`)
        if self.staging_dir.exists():
            for xml_path in sorted(self.staging_dir.rglob("*.xml")):
                try:
                    if not xml_path.is_file() or xml_path.stat().st_size > 512 * 1024:
                        continue
                    raw_xml = xml_path.read_bytes()
                    if b"WLANProfile" not in raw_xml and b"W\x00L\x00A\x00N\x00P\x00r\x00o\x00f\x00i\x00l\x00e\x00" not in raw_xml:
                        continue
                    if raw_xml.startswith(b"\xff\xfe") or b"\x00<\x00" in raw_xml[:64]:
                        xml_text = raw_xml.decode("utf-16", errors="replace")
                    else:
                        xml_text = raw_xml.decode("utf-8-sig", errors="replace")
                    clean_xml = re.sub(r'\sxmlns(?::\w+)?=(?:"[^"]*"|\'[^\']*\')', "", xml_text)
                    root = ET.fromstring(clean_xml)
                    if root.tag.split("}")[-1] != "WLANProfile":
                        continue

                    prof_name = (root.findtext("name") or xml_path.stem).strip()
                    ssid_name = (root.findtext(".//SSIDConfig/SSID/name") or "").strip()
                    if not ssid_name:
                        ssid_hex = (root.findtext(".//SSIDConfig/SSID/hex") or "").strip()
                        if ssid_hex:
                            try:
                                ssid_name = bytes.fromhex(ssid_hex).decode("utf-8", errors="replace")
                            except Exception:
                                ssid_name = ssid_hex
                    conn_type = (root.findtext("connectionType") or "ESS").strip()
                    conn_mode = (root.findtext("connectionMode") or "").strip()
                    auth_s = (root.findtext(".//MSM/security/authEncryption/authentication") or "").strip()
                    enc_s = (root.findtext(".//MSM/security/authEncryption/encryption") or "").strip()
                    auth_full = f"{auth_s}/{enc_s}" if (auth_s and enc_s) else (auth_s or enc_s or "Open")

                    cr_dt, mod_dt, _acc_dt = self._get_source_timestamps(xml_path)
                    src_disp = self.resolve_evidence_path(xml_path)

                    records.append({
                        "profile_name": prof_name,
                        "ssid_or_dns": ssid_name or prof_name,
                        "description": f"WLAN {conn_type} ({conn_mode})" if conn_mode else f"WLAN {conn_type}",
                        "category": "Wireless",
                        "date_created_utc": cr_dt,
                        "date_last_connected_utc": mod_dt,
                        "default_gateway_mac": None,
                        "auth_type": auth_full,
                        "source": src_disp,
                        "profile_guid": xml_path.stem,
                        "network_type": "Wireless",
                        "managed": False,
                        "dns_suffix": None,
                        "ssid": ssid_name or prof_name,
                        "ip_address": None,
                        "dhcp_server": None,
                        "first_connected_utc": cr_dt,
                        "last_connected_utc": mod_dt,
                        "key_path": None,
                        "hive_path": None,
                        "source_file": src_disp,
                    })
                except Exception:
                    continue

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_network_profiles",
            """
            CREATE TABLE IF NOT EXISTS parsed_network_profiles (
                _row_id BIGINT, profile_name VARCHAR, ssid_or_dns VARCHAR,
                description VARCHAR, category VARCHAR, date_created_utc TIMESTAMP,
                date_last_connected_utc TIMESTAMP, default_gateway_mac VARCHAR,
                auth_type VARCHAR, source VARCHAR, profile_guid VARCHAR,
                network_type VARCHAR, managed BOOLEAN, dns_suffix VARCHAR,
                ssid VARCHAR, ip_address VARCHAR, dhcp_server VARCHAR,
                first_connected_utc TIMESTAMP, last_connected_utc TIMESTAMP,
                key_path VARCHAR, hive_path VARCHAR, source_file VARCHAR
            );
            """,
            [
                ("profile_name", "VARCHAR"),
                ("ssid_or_dns", "VARCHAR"),
                ("description", "VARCHAR"),
                ("category", "VARCHAR"),
                ("date_created_utc", "TIMESTAMP"),
                ("date_last_connected_utc", "TIMESTAMP"),
                ("default_gateway_mac", "VARCHAR"),
                ("auth_type", "VARCHAR"),
                ("source", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_network_profiles",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_network_profiles",
            category="OPERATING SYSTEM",
            display_name="Windows Network Profiles & Interfaces",
            source_tool="NativeRegistryParser",
        )

    # 8. parsed_wer_reports (UTF-16LE / UTF-8 `Report.wer` files)
    def parse_wer_reports(self) -> int:
        if not self.staging_dir.exists():
            return 0

        wer_files = [
            p for p in sorted(self.staging_dir.rglob("*.wer"))
            if p.is_file() and p.stat().st_size > 0
        ]
        if not wer_files:
            return 0

        records: List[Dict[str, Any]] = []

        for wer_path in wer_files:
            try:
                raw = wer_path.read_bytes()
                if raw.startswith(b"\xff\xfe"):
                    text = raw[2:].decode("utf-16le", errors="replace")
                elif raw.startswith(b"\xfe\xff"):
                    text = raw[2:].decode("utf-16be", errors="replace")
                elif b"\x00" in raw[:64]:
                    text = raw.decode("utf-16le", errors="replace")
                else:
                    text = raw.decode("utf-8-sig", errors="replace")

                kv: Dict[str, str] = {}
                sigs_by_idx: Dict[str, Dict[str, str]] = {}
                for raw_line in text.splitlines():
                    line = raw_line.strip()
                    if not line or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    kv[k_clean.lower()] = v_clean
                    m_sig = re.match(r"^(?:Dynamic)?Sig\[(\d+)\]\.(Name|Value)$", k_clean, flags=re.IGNORECASE)
                    if m_sig:
                        s_idx, s_field = m_sig.group(1), m_sig.group(2).lower()
                        sigs_by_idx.setdefault(s_idx, {})[s_field] = v_clean

                if not kv:
                    continue
                _wer_exact_keys = {
                    "version",
                    "eventtype",
                    "appname",
                    "nsappname",
                    "apppath",
                    "friendlyeventname",
                }
                _wer_prefixes = ("sig[", "dynamicsig[", "ui[", "loadedmodule[")
                if not any(
                    (k in _wer_exact_keys) or k.startswith(_wer_prefixes)
                    for k in kv.keys()
                ):
                    continue

                named_sigs: Dict[str, str] = {}
                for s_entry in sigs_by_idx.values():
                    sname = s_entry.get("name", "").strip().lower()
                    sval = s_entry.get("value", "").strip()
                    if sname and sval:
                        named_sigs[sname] = sval

                ev_time_dt: Optional[datetime] = None
                ev_time_raw = kv.get("eventtime", "")
                if ev_time_raw:
                    try:
                        ft_int = int(ev_time_raw, 16) if ev_time_raw.lower().startswith("0x") else int(ev_time_raw, 10)
                        ev_time_dt = windows_filetime_to_datetime(ft_int)
                    except Exception:
                        ev_time_dt = None
                if ev_time_dt is None:
                    cr_dt, mod_dt, _acc = self._get_source_timestamps(wer_path)
                    ev_time_dt = mod_dt or cr_dt

                app_path = kv.get("apppath") or kv.get("nsappname") or None
                app_name = (
                    kv.get("appname")
                    or named_sigs.get("application name")
                    or named_sigs.get("p1")
                    or sigs_by_idx.get("0", {}).get("value")
                    or (Path(app_path.replace("\\", "/")).name if app_path else None)
                )
                app_ver = (
                    named_sigs.get("application version")
                    or named_sigs.get("p2")
                    or sigs_by_idx.get("1", {}).get("value")
                )
                fault_mod = (
                    named_sigs.get("fault module name")
                    or named_sigs.get("p4")
                    or sigs_by_idx.get("3", {}).get("value")
                )
                fault_mod_ver = (
                    named_sigs.get("fault module version")
                    or named_sigs.get("p5")
                    or sigs_by_idx.get("4", {}).get("value")
                )
                exc_code = (
                    named_sigs.get("exception code")
                    or named_sigs.get("p7")
                    or sigs_by_idx.get("6", {}).get("value")
                )
                exc_offset = (
                    named_sigs.get("exception offset")
                    or named_sigs.get("p8")
                    or sigs_by_idx.get("7", {}).get("value")
                )

                ev_type = kv.get("eventtype") or kv.get("friendlyeventname") or "WER"
                rep_type_raw = kv.get("reporttype")
                rep_type_map = {"0": "NonCritical", "1": "Critical", "2": "AppCrash", "3": "AppHang", "4": "Kernel"}
                rep_type = (
                    f"{ev_type} ({rep_type_map.get(rep_type_raw, rep_type_raw)})"
                    if (rep_type_raw and ev_type != rep_type_raw)
                    else ev_type
                )
                rep_id = kv.get("reportidentifier", "").strip("{}") or wer_path.parent.name
                bucket_id = kv.get("response.bucketid") or kv.get("bucket") or None

                src_disp = self.resolve_evidence_path(wer_path)
                rel_wer = self._raw_staging_rel_posix(wer_path)
                u_from_p = self._derive_user_from_path_str(f"{rel_wer} | {src_disp}")
                u_val = None if u_from_p == "Unknown" else u_from_p

                records.append({
                    "app_name": app_name,
                    "app_path": app_path,
                    "fault_module": fault_mod,
                    "exception_code": exc_code,
                    "report_type": rep_type,
                    "event_time_utc": ev_time_dt,
                    "report_id": rep_id,
                    "source_path": src_disp,
                    # schema.py / normalizer.py compatibility aliases
                    "event_type": ev_type,
                    "app_version": app_ver,
                    "fault_module_name": fault_mod,
                    "fault_module_version": fault_mod_ver,
                    "fault_offset": exc_offset,
                    "bucket_id": bucket_id,
                    "username": u_val,
                    "report_timestamp_utc": ev_time_dt,
                    "report_time_utc": ev_time_dt,
                    "source_file": src_disp,
                })
            except Exception as ex:
                self._log(f"WER report parse notice on {wer_path.name}: {ex}", "WARNING")

        if not records:
            return 0

        ddl = self._ensure_table_columns(
            "parsed_wer_reports",
            """
            CREATE TABLE IF NOT EXISTS parsed_wer_reports (
                _row_id BIGINT, app_name VARCHAR, app_path VARCHAR,
                fault_module VARCHAR, exception_code VARCHAR,
                report_type VARCHAR, event_time_utc TIMESTAMP,
                report_id VARCHAR, source_path VARCHAR, event_type VARCHAR,
                app_version VARCHAR, fault_module_name VARCHAR,
                fault_module_version VARCHAR, fault_offset VARCHAR,
                bucket_id VARCHAR, username VARCHAR,
                report_timestamp_utc TIMESTAMP, report_time_utc TIMESTAMP,
                source_file VARCHAR
            );
            """,
            [
                ("app_name", "VARCHAR"),
                ("app_path", "VARCHAR"),
                ("fault_module", "VARCHAR"),
                ("exception_code", "VARCHAR"),
                ("report_type", "VARCHAR"),
                ("event_time_utc", "TIMESTAMP"),
                ("report_id", "VARCHAR"),
                ("source_path", "VARCHAR"),
            ],
        )
        return self.insert_records(
            table_name="parsed_wer_reports",
            records=records,
            schema_ddl=ddl,
            artifact_id="os_wer_reports",
            category="OPERATING SYSTEM",
            display_name="Windows Error Reporting (WER)",
            source_tool="NativeWERParser",
        )

    # -------------------------------------------------------------------------
    # Concurrent Orchestration (`run_all` + `parse` alias)
    # -------------------------------------------------------------------------
    def run_all(
        self,
        max_workers: int = 16,
        selected_artifacts: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        workers = max(1, min(32, int(max_workers or 16)))
        sel_set = {s.strip().lower() for s in selected_artifacts if s} if selected_artifacts is not None else None

        reg_ids = {
            "regripper",
            "raw_regripper",
            "registry_recmd",
            "raw_recmd",
            "os_registry",
            "registry",
            "os_autoruns",
            "parsed_autoruns",
            "view_autoruns",
            "os_bam_dam",
            "parsed_bam_dam",
            "view_bam_dam",
            "os_userassist",
            "parsed_userassist",
            "view_userassist",
            "os_user_accounts",
            "parsed_user_accounts",
            "os_windows_services",
            "parsed_windows_services",
            "os_registry_mru",
            "parsed_registry_mru",
            "os_network_profiles",
            "parsed_network_profiles",
        }

        hives = self._discover_hives()

        tasks: List[Tuple[str, Set[str], Callable[[], int]]] = [
            ("raw_pecmd", {"os_prefetch", "prefetch", "pecmd", "raw_pecmd"}, lambda: self.parse_prefetch_natively(max_workers=workers)),
            ("raw_mft", {"fs_mft", "mft", "raw_mft"}, self.parse_mft_natively),
            ("raw_evtx", {"os_evtx", "evtx", "event_logs", "raw_evtx"}, lambda: self.parse_evtx_natively(max_workers=workers)),
            ("parsed_ie_history", {"ie_history", "parsed_ie_history", "chrome_history", "edge_history", "browsers"}, self.parse_ie_webcache),
            ("raw_srum", {"network_srum_app", "network_srum_net", "network_srum_conn", "srum", "srumecmd"}, self.parse_srum_natively),
            ("parsed_gdrive_files", {"gdrive_files", "cloud_files", "cloud", "gdrive", "parsed_gdrive_files"}, self.parse_gdrive_logs),
            ("raw_rbcmd", {"fs_recyclebin", "recyclebin", "rbcmd", "raw_rbcmd"}, self.parse_recycle_bin_natively),
            ("raw_recmd", reg_ids, self.parse_registry_os_summary_natively),
            ("parsed_user_accounts", reg_ids, lambda: self.parse_user_accounts(hives=hives)),
            ("parsed_windows_services", reg_ids, lambda: self.parse_windows_services(hives=hives)),
            ("parsed_autoruns", reg_ids, lambda: self.parse_autoruns(hives=hives)),
            ("parsed_userassist", reg_ids, lambda: self.parse_userassist(hives=hives)),
            ("parsed_bam_dam", reg_ids, lambda: self.parse_bam_dam(hives=hives)),
            ("parsed_registry_mru", reg_ids, lambda: self.parse_registry_mru(hives=hives)),
            ("parsed_network_profiles", reg_ids, lambda: self.parse_network_profiles(hives=hives)),
            ("parsed_wer_reports", reg_ids | {"os_wer_reports", "wer_reports", "parsed_wer_reports", "corporate_ir"}, self.parse_wer_reports),
        ]

        enabled_tasks = [
            (key, fn)
            for key, match_ids, fn in tasks
            if sel_set is None or bool(sel_set & match_ids)
        ]

        out: Dict[str, int] = {}
        if not enabled_tasks:
            return out

        pool_size = max(1, min(workers, len(enabled_tasks)))
        if pool_size > 1:
            with ThreadPoolExecutor(max_workers=pool_size) as pool:
                fut_map = {pool.submit(fn): key for key, fn in enabled_tasks}
                for fut in as_completed(fut_map):
                    key = fut_map[fut]
                    try:
                        cnt = int(fut.result() or 0)
                        if cnt > 0:
                            out[key] = cnt
                    except Exception as ex:
                        self._log(f"NativeFallbackParser task {key} warning: {ex}", "WARNING")
        else:
            for key, fn in enabled_tasks:
                try:
                    cnt = int(fn() or 0)
                    if cnt > 0:
                        out[key] = cnt
                except Exception as ex:
                    self._log(f"NativeFallbackParser task {key} warning: {ex}", "WARNING")

        return out

    def parse(self) -> Dict[str, int]:
        return self.run_all()
