"""
Windows Forensic Toolkit (WFT) DFIR Suite - USB Device Correlator
Cross-correlates offline USB artifacts from Windows SYSTEM hive
(Select, TimeZoneInformation ActiveTimeBias, Enum/USBSTOR, Enum/USB, MountedDevices),
SOFTWARE hive (Windows Portable Devices, EMDMgmt), per-user NTUSER.DAT (MountPoints2),
setupapi.dev.log / setupapi.offline.log, and raw_recmd.
Live host registry (winreg) is strictly gated to explicit live triage cases only.
"""
from __future__ import annotations

import os
import re
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser, windows_filetime_to_datetime

try:
    from regipy.registry import RegistryHive as RegipyHive
    HAS_REGIPY = True
except ImportError:  # pragma: no cover
    RegipyHive = None  # type: ignore[assignment]
    HAS_REGIPY = False

try:
    from dissect.regf import RegistryHive as DissectRegfHive
    HAS_DISSECT_REGF = True
except ImportError:  # pragma: no cover
    DissectRegfHive = None  # type: ignore[assignment]
    HAS_DISSECT_REGF = False


USB_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_usb_devices (
    _row_id BIGINT,
    vendor_id VARCHAR,
    product_id VARCHAR,
    revision VARCHAR,
    serial_number VARCHAR,
    friendly_name VARCHAR,
    drive_letter VARCHAR,
    volume_guid VARCHAR,
    first_connected_utc TIMESTAMP,
    last_connected_utc TIMESTAMP,
    source_evidence VARCHAR
);
"""

_SIDE_CAR_SUFFIXES = (
    ".log",
    ".log1",
    ".log2",
    ".blf",
    ".regtrans-ms",
    ".sav",
    ".bak",
    ".txt",
    ".csv",
    ".json",
    ".db",
    ".sqlite",
    ".duckdb",
)

_USB_PROPS_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"


@dataclass
class _HiveCandidate:
    path: Path
    role: str  # "SYSTEM", "SOFTWARE", "NTUSER"
    username: Optional[str]
    provenance: str  # "active" or "VSS_<N>"


def _coerce_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _decode_filetime_any(val: Any) -> Optional[datetime]:
    """Decode Windows FILETIME from datetime, ISO string, 8-byte REG_BINARY/REG_FILETIME, or int."""
    if val is None:
        return None
    if isinstance(val, datetime):
        dt = _coerce_utc(val)
        return dt if (dt and dt.year >= 1971) else None
    if isinstance(val, (bytes, bytearray)):
        if len(val) >= 8:
            ft = struct.unpack_from("<Q", val, 0)[0]
            return windows_filetime_to_datetime(ft)
        return None
    if isinstance(val, int) and not isinstance(val, bool):
        return windows_filetime_to_datetime(val)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        try:
            norm = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(norm)
            dt_utc = _coerce_utc(dt)
            return dt_utc if (dt_utc and dt_utc.year >= 1971) else None
        except ValueError:
            return None
    return None


def _clean_device_label(raw: Any) -> str:
    if raw is None:
        return ""
    s = str(raw).strip("\x00 ").strip()
    if ";" in s and s.startswith("@"):
        s = s.rsplit(";", 1)[-1].strip()
    return s


def _normalize_serial(raw_instance: str) -> str:
    s = raw_instance.strip().strip("\\#")
    if not s:
        return ""
    # Synthetic Windows instance ID when USB descriptor lacks serial (e.g. 7&1a2b3c4d&0)
    if len(s) > 2 and s[1] == "&" and s[0].isalnum():
        cleaned = re.sub(r"&\d+$", "", s)
        return cleaned.upper().strip()
    return s.split("&")[0].upper().strip()


class _OfflineKeyWrapper:
    """Unified read-only Registry key wrapper over regipy NKRecord or dissect.regf RegistryKey."""

    def __init__(self, backend: str, raw_key: Any) -> None:
        self._backend = backend
        self._key = raw_key

    @property
    def name(self) -> str:
        if self._backend == "regipy":
            return str(getattr(self._key, "name", "") or "")
        return str(self._key.name)

    @property
    def last_modified(self) -> Optional[datetime]:
        try:
            if self._backend == "regipy":
                ft = getattr(self._key.header, "last_modified", None)
                return windows_filetime_to_datetime(ft)
            ts = getattr(self._key, "timestamp", None)
            return _coerce_utc(ts) if isinstance(ts, datetime) else None
        except Exception:
            return None

    def subkeys(self) -> Iterator["_OfflineKeyWrapper"]:
        try:
            if self._backend == "regipy":
                for sk in self._key.iter_subkeys():
                    yield _OfflineKeyWrapper("regipy", sk)
            else:
                for sk in self._key.subkeys():
                    yield _OfflineKeyWrapper("dissect", sk)
        except Exception:
            return

    def subkey(self, name: str) -> Optional["_OfflineKeyWrapper"]:
        target_low = name.lower()
        for sk in self.subkeys():
            if sk.name.lower() == target_low:
                return sk
        return None

    def iter_values(self) -> Iterator[Tuple[str, Any, Optional[bytes]]]:
        """Yields (value_name, parsed_value, raw_bytes_if_available)."""
        if self._backend == "regipy":
            try:
                for v in self._key.iter_values(trim_values=False):
                    v_name = str(getattr(v, "name", "") or "")
                    v_val = getattr(v, "value", None)
                    raw_b = bytes(v_val) if isinstance(v_val, (bytes, bytearray)) else None
                    yield (v_name, v_val, raw_b)
            except Exception:
                return
        else:
            try:
                for v in self._key.values():
                    v_name = str(getattr(v, "name", "") or "") or "(default)"
                    try:
                        raw_b = bytes(v.data)
                    except Exception:
                        raw_b = None
                    try:
                        v_val = v.value
                    except Exception:
                        v_val = raw_b
                    yield (v_name, v_val, raw_b)
            except Exception:
                return

    def get_value_map(self) -> Dict[str, Tuple[Any, Optional[bytes]]]:
        out: Dict[str, Tuple[Any, Optional[bytes]]] = {}
        for v_name, v_val, raw_b in self.iter_values():
            out[v_name.lower()] = (v_val, raw_b)
        return out


class _OfflineHiveWrapper:
    """Context-managed offline Registry hive reader using regipy primary and dissect.regf fallback."""

    def __init__(self, hive_path: Path) -> None:
        self.hive_path = hive_path
        self._backend = ""
        self._hive: Any = None
        self._fh: Any = None

    def __enter__(self) -> Optional["_OfflineHiveWrapper"]:
        if HAS_REGIPY:
            try:
                self._hive = RegipyHive(str(self.hive_path))
                self._backend = "regipy"
                return self
            except Exception:
                self._close_regipy()

        if HAS_DISSECT_REGF:
            try:
                self._fh = open(self.hive_path, "rb")
                self._hive = DissectRegfHive(self._fh)
                self._backend = "dissect"
                return self
            except Exception:
                self._close_dissect()

        return None

    def _close_regipy(self) -> None:
        if self._hive is not None:
            stream = getattr(self._hive, "_stream", None)
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
            self._hive = None

    def _close_dissect(self) -> None:
        self._hive = None
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._backend == "regipy":
            self._close_regipy()
        else:
            self._close_dissect()

    def get_key(self, rel_path: str) -> Optional[_OfflineKeyWrapper]:
        cleaned = rel_path.strip("\\/")
        if self._backend == "regipy":
            try:
                if not cleaned:
                    return _OfflineKeyWrapper("regipy", self._hive.root)
                nk = self._hive.get_key("\\" + cleaned)
                return _OfflineKeyWrapper("regipy", nk)
            except Exception:
                # Case-insensitive walk fallback on regipy root
                cur = _OfflineKeyWrapper("regipy", self._hive.root)
                for part in cleaned.split("\\"):
                    if not part:
                        continue
                    nxt = cur.subkey(part)
                    if nxt is None:
                        return None
                    cur = nxt
                return cur
        elif self._backend == "dissect":
            try:
                dk = self._hive.open(cleaned) if cleaned else self._hive.root()
                return _OfflineKeyWrapper("dissect", dk)
            except Exception:
                try:
                    cur = _OfflineKeyWrapper("dissect", self._hive.root())
                    for part in cleaned.split("\\"):
                        if not part:
                            continue
                        nxt = cur.subkey(part)
                        if nxt is None:
                            return None
                        cur = nxt
                    return cur
                except Exception:
                    return None
        return None


class USBDeviceCorrelator(BaseParser):
    """
    Forensic engine correlating USB connection history across:
      1. Offline SYSTEM hive (Select, ActiveTimeBias, Enum\\USBSTOR, Enum\\USB, MountedDevices)
      2. Offline SOFTWARE hive (Windows Portable Devices\\Devices, EMDMgmt)
      3. Offline per-user NTUSER.DAT hives (MountPoints2)
      4. setupapi.dev.log & setupapi.offline.log (converted to UTC via ActiveTimeBias)
      5. RECmd output raw_recmd (if already parsed into DuckDB)
      6. Live host Registry (ONLY when case source_type is explicitly live / live_triage)
    """

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Path] = None,
        source_type: Optional[str] = None,
    ) -> None:
        super().__init__(case_id, staging_dir)
        self.source_type = source_type
        self.usbstor_re = re.compile(
            r"USBSTOR[#\\]DISK&VEN_([^&#\\]+)&PROD_([^&#\\]+)&REV_([^&#\\]*)[#\\]([^&#\\\s\]]+)",
            re.IGNORECASE,
        )
        self.devclass_re = re.compile(
            r"DISK&VEN_([^&]+)&PROD_([^&]+)(?:&REV_([^&]*))?",
            re.IGNORECASE,
        )
        self.scsi_usb_re = re.compile(
            r"SCSI[#\\]DISK&VEN_([^&#\\]+)&PROD_([^&#\\]+)[#\\]([^&#\\\s\]]+)",
            re.IGNORECASE,
        )
        self.usb_vid_re = re.compile(
            r"USB[#\\]VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})(?:&MI_\d+)?[#\\]([^&#\\\s\]]+)",
            re.IGNORECASE,
        )
        self.vid_pid_key_re = re.compile(
            r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})",
            re.IGNORECASE,
        )
        self.section_start_re = re.compile(r"^>>>\s+\[(.*?)\]")
        self.start_time_re = re.compile(
            r"^>>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"
        )
        self.guid_re = re.compile(
            r"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}"
        )
        self.drive_letter_re = re.compile(r"^([A-Za-z]):\\?$")
        self._guid_to_drive: Dict[str, str] = {}
        self._drive_to_guid: Dict[str, str] = {}

    def _resolve_is_live_triage(self, explicit_source_type: Optional[str] = None) -> bool:
        """Return True ONLY when case is explicitly live / live_triage; False for all offline cases."""
        cand = explicit_source_type if explicit_source_type is not None else self.source_type
        if cand is not None:
            return str(cand).strip().lower() in ("live", "live_triage")

        try:
            with self.db_manager.get_lock(self.case_id):
                conn = self.db_manager.get_connection(self.case_id, read_only=False)
                self.conn = conn
                cursor = conn.cursor()
                tables = {
                    r[0]
                    for r in cursor.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if "case_metadata" in tables:
                    row = cursor.execute(
                        "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                    ).fetchone()
                    if row and row[0]:
                        return str(row[0]).strip().lower() in ("live", "live_triage")

                if "processing_logs" in tables:
                    row = cursor.execute(
                        """
                        SELECT command_executed FROM processing_logs
                        WHERE module_name = 'Pipeline:Extractor'
                        ORDER BY log_id DESC LIMIT 1;
                        """
                    ).fetchone()
                    if row and row[0]:
                        cmd_low = str(row[0]).strip().lower()
                        if cmd_low.startswith("extractor (live"):
                            return True
                        if cmd_low.startswith("extractor ("):
                            return False
        except Exception:
            return False

        return False

    @staticmethod
    def _append_evidence(dev: Dict[str, Any], tag: str) -> None:
        cur = dev.get("source_evidence") or ""
        if not cur:
            dev["source_evidence"] = tag
        elif tag not in cur:
            dev["source_evidence"] = f"{cur} + {tag}"

    @staticmethod
    def _update_timestamps(
        dev: Dict[str, Any],
        first_cand: Optional[datetime] = None,
        last_cand: Optional[datetime] = None,
    ) -> None:
        fc = _coerce_utc(first_cand)
        lc = _coerce_utc(last_cand)
        if fc is not None:
            cur_f = _coerce_utc(dev.get("first_connected_utc"))
            if cur_f is None or fc < cur_f:
                dev["first_connected_utc"] = fc
            cur_l = _coerce_utc(dev.get("last_connected_utc"))
            if cur_l is None or fc > cur_l:
                dev["last_connected_utc"] = fc
        if lc is not None:
            cur_l = _coerce_utc(dev.get("last_connected_utc"))
            if cur_l is None or lc > cur_l:
                dev["last_connected_utc"] = lc
            cur_f = _coerce_utc(dev.get("first_connected_utc"))
            if cur_f is None:
                dev["first_connected_utc"] = lc

    def _ensure_device(
        self,
        correlated_map: Dict[str, Dict[str, Any]],
        clean_serial: str,
        vendor_id: str = "",
        product_id: str = "",
        revision: str = "",
        friendly_name: str = "",
        source_evidence: str = "",
    ) -> Dict[str, Any]:
        dev = correlated_map.get(clean_serial)
        if dev is None:
            dev = {
                "vendor_id": vendor_id,
                "product_id": product_id,
                "revision": revision,
                "serial_number": clean_serial,
                "friendly_name": friendly_name or f"{vendor_id} {product_id}".strip(),
                "drive_letter": None,
                "volume_guid": None,
                "first_connected_utc": None,
                "last_connected_utc": None,
                "source_evidence": source_evidence,
                "_parent_id_prefix": None,
                "_container_id": None,
            }
            correlated_map[clean_serial] = dev
        else:
            if vendor_id and (not dev["vendor_id"] or dev["vendor_id"].upper().startswith("VID_") and not vendor_id.upper().startswith("VID_")):
                dev["vendor_id"] = vendor_id
            if product_id and (not dev["product_id"] or dev["product_id"].upper().startswith("PID_") and not product_id.upper().startswith("PID_")):
                dev["product_id"] = product_id
            if revision and not dev["revision"]:
                dev["revision"] = revision
            if friendly_name and (
                not dev["friendly_name"]
                or dev["friendly_name"].upper().startswith("USB VID_")
                or dev["friendly_name"] == f"{dev['vendor_id']} {dev['product_id']}".strip()
            ):
                dev["friendly_name"] = friendly_name
            if source_evidence:
                self._append_evidence(dev, source_evidence)
        return dev

    def _parse_ts(self, ts_str: Optional[str], bias_minutes: int = 0) -> Optional[datetime]:
        """Parse setupapi local timestamp (YYYY/MM/DD HH:MM:SS.mmm) and convert to UTC using ActiveTimeBias."""
        if not ts_str:
            return None
        try:
            clean = ts_str.strip().replace("/", "-")
            naive_local = datetime.fromisoformat(clean)
            utc_dt = naive_local + timedelta(minutes=int(bias_minutes))
            return utc_dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def _parse_setupapi_logs(
        self,
        log_path: Path,
        correlated_map: Dict[str, Dict[str, Any]],
        bias_minutes: int = 0,
    ) -> None:
        """Parse setupapi.dev.log or setupapi.offline.log lines and update correlated_map."""
        try:
            raw = log_path.read_bytes()
            if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                content = raw.decode("utf-16", errors="replace")
            else:
                content = raw.decode("utf-8-sig", errors="replace")
        except Exception as ex:
            self._log(f"Error reading setupapi log {log_path}: {ex}", "WARNING")
            return

        lines = content.splitlines()
        current_section = ""
        current_time: Optional[datetime] = None

        for line in lines:
            m_sec = self.section_start_re.match(line)
            if m_sec:
                current_section = m_sec.group(1)
                current_time = None
                continue

            m_st = self.start_time_re.match(line)
            if m_st:
                current_time = self._parse_ts(m_st.group(1), bias_minutes=bias_minutes)
                # Once section start timestamp is read, also evaluate current_section header with this timestamp
                if current_section:
                    self._extract_setupapi_line(current_section, current_time, correlated_map, log_path.name)
                continue

            self._extract_setupapi_line(line, current_time, correlated_map, log_path.name)

    def _extract_setupapi_line(
        self,
        txt: str,
        current_time: Optional[datetime],
        correlated_map: Dict[str, Dict[str, Any]],
        log_name: str,
    ) -> None:
        m_usbstor = self.usbstor_re.search(txt)
        if m_usbstor:
            ven, prod, rev, serial = m_usbstor.groups()
            clean_serial = _normalize_serial(serial)
            if clean_serial:
                ven_c = ven.strip("_ ").strip()
                prod_c = prod.strip("_ ").strip()
                rev_c = rev.strip("_ ").strip()
                dev = self._ensure_device(
                    correlated_map,
                    clean_serial,
                    vendor_id=ven_c,
                    product_id=prod_c,
                    revision=rev_c,
                    friendly_name=f"{ven_c} {prod_c}".strip(),
                    source_evidence=log_name,
                )
                m_guid = self.guid_re.search(txt)
                if m_guid and not dev["volume_guid"]:
                    g = m_guid.group(1)
                    # Ignore the generic Disk/Partition/Volume device interface class GUIDs
                    if g.lower() not in (
                        "53f56307-b6bf-11d0-94f2-00a0c91efb8b",
                        "53f5630d-b6bf-11d0-94f2-00a0c91efb8b",
                        "7f108a28-9833-4b3b-b780-2c6b5fa5c062",
                    ):
                        dev["volume_guid"] = f"{{{g}}}"
                if current_time is not None:
                    self._update_timestamps(dev, first_cand=current_time, last_cand=current_time)

        m_vid = self.usb_vid_re.search(txt)
        if m_vid:
            vid, pid, serial = m_vid.groups()
            clean_serial = _normalize_serial(serial)
            if clean_serial:
                dev = self._ensure_device(
                    correlated_map,
                    clean_serial,
                    vendor_id=f"VID_{vid.upper()}",
                    product_id=f"PID_{pid.upper()}",
                    revision="",
                    friendly_name=f"USB VID_{vid.upper()} PID_{pid.upper()}",
                    source_evidence=log_name,
                )
                if current_time is not None:
                    self._update_timestamps(dev, first_cand=current_time, last_cand=current_time)

    def _discover_offline_hives(self) -> List[_HiveCandidate]:
        """Discover deduplicated SYSTEM, SOFTWARE, and per-user NTUSER.DAT hives (clean_hives > staging)."""
        search_roots: List[Tuple[Path, int]] = [
            (self.case_dir / "clean_hives", 0),
            (self.staging_dir / "Registry", 1),
            (self.staging_dir / "VSS", 2),
            (self.staging_dir, 3),
        ]
        seen_paths: Set[Path] = set()
        seen_slots: Set[Tuple[str, str, str]] = set()
        discovered: List[_HiveCandidate] = []

        _SKIP_HIVE_ROOTS = {
            "logs", "prefetch", "filesystem", "mft", "srum", "jumplists",
            "tasks", "powershell", "rmm", "carved_thumbnails", "zoneidentifier",
            "recyclebin", "wbem", "wer", "wlan", "usb", "browsers", "chat",
            "cloud", "mail", "media", "documents", "notifications", "activitiescache",
        }
        for root_dir, _prio in search_roots:
            if not root_dir.is_dir():
                continue
            if root_dir == self.staging_dir and discovered:
                break
            for dirpath, dirnames, filenames in os.walk(root_dir):
                dp = Path(dirpath)
                if root_dir == self.staging_dir and dp.resolve() == self.staging_dir.resolve():
                    dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_HIVE_ROOTS]
                for fn in sorted(filenames):
                    fn_low = fn.lower()
                    if fn_low.endswith(_SIDE_CAR_SUFFIXES):
                        continue
                    fp = (dp / fn).resolve()
                    if fp in seen_paths:
                        continue
                    seen_paths.add(fp)

                    role = ""
                    username: Optional[str] = None
                    try:
                        rel_parts = fp.relative_to(root_dir.resolve()).parts
                    except ValueError:
                        rel_parts = (fp.parent.name, fp.name)
                    parts_low = [p.lower() for p in rel_parts]

                    if fn_low in ("system", "system.hive", "system.dat") or re.search(r"(?:^|_)system$", fn_low):
                        role = "SYSTEM"
                    elif fn_low in ("software", "software.hive", "software.dat") or re.search(r"(?:^|_)software$", fn_low):
                        role = "SOFTWARE"
                    elif "ntuser" in fn_low and (fn_low.endswith(".dat") or fn_low == "ntuser"):
                        role = "NTUSER"
                        for idx_p, seg in enumerate(parts_low):
                            if seg in ("users", "documents and settings", "userfiles") and idx_p + 1 < len(rel_parts):
                                cand_u = rel_parts[idx_p + 1]
                                if cand_u.lower() not in ("ntuser.dat", "registry"):
                                    username = cand_u
                                    break
                        if not username:
                            m_u = re.match(r"^ntuser[_\-](.+?)(?:\.dat)?$", fn, re.IGNORECASE)
                            if m_u:
                                username = m_u.group(1)
                            elif fp.parent.name.lower() not in ("users", "registry", "clean_hives", "system", "staging"):
                                username = fp.parent.name
                            else:
                                username = "Default"
                    else:
                        continue

                    try:
                        if fp.stat().st_size < 4096:
                            continue
                        with open(fp, "rb") as chk:
                            if chk.read(4) != b"regf":
                                continue
                    except OSError:
                        continue

                    provenance = "active"
                    m_vss = re.search(r"(?i)(?:^|[\\/])(vss[_\-]?\d+)(?:[\\/]|$)", str(fp))
                    if m_vss:
                        provenance = m_vss.group(1).upper().replace("-", "_")

                    slot = (provenance, role, (username or "").lower())
                    if slot in seen_slots:
                        continue
                    seen_slots.add(slot)
                    discovered.append(
                        _HiveCandidate(
                            path=fp,
                            role=role,
                            username=username,
                            provenance=provenance,
                        )
                    )

        return discovered

    @staticmethod
    def _read_active_control_set_names(hive: _OfflineHiveWrapper) -> List[str]:
        ordered: List[str] = []
        sel = hive.get_key("Select")
        if sel is not None:
            vmap = sel.get_value_map()
            cur_entry = vmap.get("current")
            if cur_entry is not None and isinstance(cur_entry[0], int):
                ordered.append(f"ControlSet{int(cur_entry[0]):03d}")

        root_k = hive.get_key("")
        if root_k is not None:
            for sk in root_k.subkeys():
                if sk.name.lower().startswith("controlset") or sk.name.lower() == "currentcontrolset":
                    if sk.name not in ordered:
                        ordered.append(sk.name)

        for fallback_cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
            if fallback_cs not in ordered and hive.get_key(fallback_cs) is not None:
                ordered.append(fallback_cs)

        return ordered

    @staticmethod
    def _read_time_bias_minutes(hive: _OfflineHiveWrapper, cs_names: List[str]) -> Optional[int]:
        """Read signed 32-bit ActiveTimeBias (fallback Bias) from TimeZoneInformation."""
        for cs in cs_names:
            tz_key = hive.get_key(f"{cs}\\Control\\TimeZoneInformation")
            if tz_key is None:
                continue
            vmap = tz_key.get_value_map()
            for v_key in ("activetimebias", "bias"):
                entry = vmap.get(v_key)
                if entry is None:
                    continue
                val, raw_b = entry
                raw_u32: Optional[int] = None
                if isinstance(val, int) and not isinstance(val, bool):
                    raw_u32 = val & 0xFFFFFFFF
                elif raw_b is not None and len(raw_b) >= 4:
                    raw_u32 = struct.unpack_from("<I", raw_b, 0)[0]
                if raw_u32 is not None:
                    return (raw_u32 - 0x100000000) if raw_u32 >= 0x80000000 else int(raw_u32)
        return None

    @staticmethod
    def _read_usb_prop_filetime(prop_parent: _OfflineKeyWrapper, prop_code: str) -> Optional[datetime]:
        """Read 0064/0065/0066/0067 FILETIME from either direct default value or 0000/00000000 subkey."""
        code_key = prop_parent.subkey(prop_code)
        if code_key is None:
            return None

        # 1. Direct values on 0064 / 0066 / 0067 (Windows 10/11)
        for _vname, vval, raw_b in code_key.iter_values():
            dt = _decode_filetime_any(vval) or _decode_filetime_any(raw_b)
            if dt is not None:
                return dt

        # 2. Subkey 0000 or 00000000 default value (Windows 7/8)
        for sub_name in ("0000", "00000000"):
            sk = code_key.subkey(sub_name)
            if sk is not None:
                for _vname, vval, raw_b in sk.iter_values():
                    dt = _decode_filetime_any(vval) or _decode_filetime_any(raw_b)
                    if dt is not None:
                        return dt

        # 3. Any child subkey fallback
        for sk in code_key.subkeys():
            for _vname, vval, raw_b in sk.iter_values():
                dt = _decode_filetime_any(vval) or _decode_filetime_any(raw_b)
                if dt is not None:
                    return dt

        return None

    def _extract_props_timestamps(
        self, inst_key: _OfflineKeyWrapper
    ) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Extract (first_install_utc, last_activity_utc) from Properties\\{83da6326-...}."""
        props_key = inst_key.subkey("Properties")
        if props_key is None:
            return (None, None)
        guid_key = props_key.subkey(_USB_PROPS_GUID)
        if guid_key is None:
            return (None, None)

        t_0064 = self._read_usb_prop_filetime(guid_key, "0064")
        t_0065 = self._read_usb_prop_filetime(guid_key, "0065")
        t_0066 = self._read_usb_prop_filetime(guid_key, "0066")
        t_0067 = self._read_usb_prop_filetime(guid_key, "0067")

        first_dt = t_0064 or t_0065
        last_candidates = [t for t in (t_0066, t_0067, t_0064, t_0065) if t is not None]
        last_dt = max(last_candidates) if last_candidates else None
        return (first_dt, last_dt)

    def _correlate_system_hive(
        self,
        hive: _OfflineHiveWrapper,
        hive_label: str,
        correlated_map: Dict[str, Dict[str, Any]],
    ) -> Optional[int]:
        cs_names = self._read_active_control_set_names(hive)
        bias_min = self._read_time_bias_minutes(hive, cs_names)

        # 1. Enum\USBSTOR
        for cs in cs_names:
            usbstor_key = hive.get_key(f"{cs}\\Enum\\USBSTOR")
            if usbstor_key is None:
                continue
            for dev_class_key in usbstor_key.subkeys():
                dc_name = dev_class_key.name
                m_dc = self.devclass_re.search(dc_name)
                if m_dc:
                    ven = (m_dc.group(1) or "").strip("_ ").strip()
                    prod = (m_dc.group(2) or "").strip("_ ").strip()
                    rev = (m_dc.group(3) or "").strip("_ ").strip()
                else:
                    parts = dc_name.split("&")
                    ven = parts[0] if parts else "USB"
                    prod = parts[1] if len(parts) > 1 else dc_name
                    rev = parts[2] if len(parts) > 2 else ""

                for inst_key in dev_class_key.subkeys():
                    clean_serial = _normalize_serial(inst_key.name)
                    if not clean_serial:
                        continue
                    vmap = inst_key.get_value_map()
                    friendly = ""
                    if "friendlyname" in vmap:
                        friendly = _clean_device_label(vmap["friendlyname"][0])
                    if not friendly and "devicedesc" in vmap:
                        friendly = _clean_device_label(vmap["devicedesc"][0])
                    if not friendly:
                        friendly = f"{ven} {prod}".strip() or dc_name

                    dev = self._ensure_device(
                        correlated_map,
                        clean_serial,
                        vendor_id=ven,
                        product_id=prod,
                        revision=rev,
                        friendly_name=friendly,
                        source_evidence=f"SYSTEM\\{cs}\\Enum\\USBSTOR ({hive_label})",
                    )

                    if "parentidprefix" in vmap and vmap["parentidprefix"][0]:
                        pip = _clean_device_label(vmap["parentidprefix"][0])
                        if pip:
                            dev["_parent_id_prefix"] = pip
                    if "containerid" in vmap and vmap["containerid"][0]:
                        cid = _clean_device_label(vmap["containerid"][0]).lower()
                        if cid:
                            dev["_container_id"] = cid

                    prop_first, prop_last = self._extract_props_timestamps(inst_key)
                    nk_ts = inst_key.last_modified
                    if prop_first is not None or prop_last is not None:
                        if prop_first is not None:
                            dev["_has_authoritative_first"] = True
                        if prop_last is not None:
                            dev["_has_authoritative_pnp_last"] = True
                        self._update_timestamps(dev, first_cand=prop_first, last_cand=prop_last)
                        if prop_last is None and nk_ts is not None:
                            self._update_timestamps(dev, last_cand=nk_ts)
                    elif nk_ts is not None:
                        self._update_timestamps(dev, first_cand=nk_ts, last_cand=nk_ts)

        # 2. Enum\USB (enrich VID/PID & timestamps for USBSTOR devices or USBSTOR-service devices)
        for cs in cs_names:
            usb_key = hive.get_key(f"{cs}\\Enum\\USB")
            if usb_key is None:
                continue
            for vid_pid_key in usb_key.subkeys():
                m_vp = self.vid_pid_key_re.search(vid_pid_key.name)
                vid_str = m_vp.group(1).upper() if m_vp else ""
                pid_str = m_vp.group(2).upper() if m_vp else ""

                for inst_key in vid_pid_key.subkeys():
                    clean_serial = _normalize_serial(inst_key.name)
                    if not clean_serial:
                        continue
                    vmap = inst_key.get_value_map()
                    cid = _clean_device_label(vmap.get("containerid", ("", None))[0]).lower()
                    pip = _clean_device_label(vmap.get("parentidprefix", ("", None))[0])
                    svc = _clean_device_label(vmap.get("service", ("", None))[0]).lower()

                    matched_dev = correlated_map.get(clean_serial)
                    if matched_dev is None and (cid or pip):
                        for cand_dev in correlated_map.values():
                            if cid and cand_dev.get("_container_id") == cid:
                                matched_dev = cand_dev
                                break
                            if pip and cand_dev.get("_parent_id_prefix") and cand_dev["_parent_id_prefix"].lower() == pip.lower():
                                matched_dev = cand_dev
                                break

                    if matched_dev is None and svc in ("usbstor", "uaspstor"):
                        friendly = _clean_device_label(vmap.get("friendlyname", ("", None))[0]) or _clean_device_label(
                            vmap.get("devicedesc", ("", None))[0]
                        )
                        matched_dev = self._ensure_device(
                            correlated_map,
                            clean_serial,
                            vendor_id=f"VID_{vid_str}" if vid_str else "USB",
                            product_id=f"PID_{pid_str}" if pid_str else vid_pid_key.name,
                            revision="",
                            friendly_name=friendly or f"USB VID_{vid_str} PID_{pid_str}".strip(),
                            source_evidence=f"SYSTEM\\{cs}\\Enum\\USB",
                        )

                    if matched_dev is not None:
                        if vid_str and not matched_dev["vendor_id"]:
                            matched_dev["vendor_id"] = f"VID_{vid_str}"
                        if pid_str and not matched_dev["product_id"]:
                            matched_dev["product_id"] = f"PID_{pid_str}"
                        if vid_str and pid_str:
                            self._append_evidence(matched_dev, f"Enum\\USB(VID_{vid_str}&PID_{pid_str})")
                        if pip and not matched_dev.get("_parent_id_prefix"):
                            matched_dev["_parent_id_prefix"] = pip
                        if cid and not matched_dev.get("_container_id"):
                            matched_dev["_container_id"] = cid

                        prop_first, prop_last = self._extract_props_timestamps(inst_key)
                        nk_ts = inst_key.last_modified
                        if prop_first is not None or prop_last is not None:
                            if prop_first is not None:
                                matched_dev["_has_authoritative_first"] = True
                            if prop_last is not None:
                                matched_dev["_has_authoritative_pnp_last"] = True
                            self._update_timestamps(matched_dev, first_cand=prop_first, last_cand=prop_last)
                        elif nk_ts is not None:
                            fallback_first = None if matched_dev.get("_has_authoritative_first") else nk_ts
                            fallback_last = None if matched_dev.get("_has_authoritative_pnp_last") else nk_ts
                            self._update_timestamps(matched_dev, first_cand=fallback_first, last_cand=fallback_last)

        # 3. MountedDevices (raw bytes pairing + UTF-16LE serial & ParentIdPrefix matching)
        md_key = hive.get_key("MountedDevices")
        if md_key is not None:
            raw_entries: List[Tuple[str, bytes, str]] = []
            bytes_to_drive: Dict[bytes, str] = {}
            bytes_to_guid: Dict[bytes, str] = {}

            for val_name, val_obj, raw_b in md_key.iter_values():
                b_data: Optional[bytes] = raw_b
                if b_data is None and isinstance(val_obj, (bytes, bytearray)):
                    b_data = bytes(val_obj)
                elif b_data is None and isinstance(val_obj, str):
                    # Fallback if hex-encoded string
                    try:
                        b_data = bytes.fromhex(val_obj)
                    except ValueError:
                        b_data = val_obj.encode("utf-16le", errors="ignore")
                if not b_data:
                    continue

                u16 = b_data.decode("utf-16le", errors="ignore") if len(b_data) >= 16 else ""
                u16_low = u16.lower()
                if "cdrom" in u16_low or "floppy" in u16_low:
                    continue

                raw_entries.append((val_name, b_data, u16))

                m_dl = re.search(r"\\DosDevices\\([A-Za-z]:)", val_name, re.IGNORECASE)
                if m_dl:
                    bytes_to_drive[b_data] = m_dl.group(1).upper()

                m_guid = self.guid_re.search(val_name)
                if m_guid:
                    bytes_to_guid[b_data] = f"{{{m_guid.group(1)}}}"

            for shared_b, dl_val in bytes_to_drive.items():
                vg_val = bytes_to_guid.get(shared_b)
                if vg_val:
                    self._drive_to_guid[dl_val.upper()] = vg_val
                    self._guid_to_drive[vg_val.lower()] = dl_val.upper()

            for val_name, b_data, u16 in raw_entries:
                if not u16:
                    continue
                u16_low = u16.lower()
                dl = bytes_to_drive.get(b_data)
                vguid = bytes_to_guid.get(b_data)

                matched_devs: List[Dict[str, Any]] = []

                m_usbstor = self.usbstor_re.search(u16)
                if m_usbstor:
                    ven, prod, rev, serial = m_usbstor.groups()
                    clean_serial = _normalize_serial(serial)
                    if clean_serial:
                        ven_c = ven.strip("_ ").strip()
                        prod_c = prod.strip("_ ").strip()
                        rev_c = rev.strip("_ ").strip()
                        dev = self._ensure_device(
                            correlated_map,
                            clean_serial,
                            vendor_id=ven_c,
                            product_id=prod_c,
                            revision=rev_c,
                            friendly_name=f"{ven_c} {prod_c}".strip(),
                            source_evidence=f"MountedDevices ({hive_label})",
                        )
                        matched_devs.append(dev)

                for c_serial, cand_dev in correlated_map.items():
                    if cand_dev in matched_devs:
                        continue
                    cs_low = c_serial.lower()
                    pip = (cand_dev.get("_parent_id_prefix") or "").lower()
                    serial_hit = bool(
                        cs_low
                        and len(cs_low) >= 3
                        and (
                            f"#{cs_low}#" in u16_low
                            or f"#{cs_low}&" in u16_low
                            or f"\\{cs_low}\\" in u16_low
                            or f"\\{cs_low}&" in u16_low
                        )
                    )
                    pip_hit = bool(
                        pip
                        and (
                            f"#{pip}&" in u16_low
                            or f"#{pip}#" in u16_low
                        )
                    )
                    if serial_hit or pip_hit:
                        matched_devs.append(cand_dev)

                for mdev in matched_devs:
                    if dl and not mdev["drive_letter"]:
                        mdev["drive_letter"] = dl
                        self._append_evidence(mdev, f"MountedDevices({dl})")
                    if vguid and not mdev["volume_guid"]:
                        mdev["volume_guid"] = vguid
                        self._append_evidence(mdev, "MountedDevices(VolumeGUID)")

        return bias_min

    def _correlate_software_hive(
        self,
        hive: _OfflineHiveWrapper,
        correlated_map: Dict[str, Dict[str, Any]],
    ) -> None:
        # 1. Microsoft\Windows Portable Devices\Devices
        wpd_key = hive.get_key("Microsoft\\Windows Portable Devices\\Devices")
        if wpd_key is not None:
            for dev_sk in wpd_key.subkeys():
                sk_name = dev_sk.name
                sk_low = sk_name.lower()
                vmap = dev_sk.get_value_map()
                wpd_friendly = _clean_device_label(vmap.get("friendlyname", ("", None))[0])

                target_dev: Optional[Dict[str, Any]] = None
                m_usbstor = self.usbstor_re.search(sk_name.replace("##", "#"))
                if m_usbstor:
                    _ven, _prod, _rev, serial = m_usbstor.groups()
                    c_ser = _normalize_serial(serial)
                    target_dev = correlated_map.get(c_ser)

                if target_dev is None:
                    for c_ser, cand_dev in correlated_map.items():
                        pip = (cand_dev.get("_parent_id_prefix") or "").lower()
                        if (len(c_ser) >= 3 and f"#{c_ser.lower()}" in sk_low) or (pip and f"#{pip}" in sk_low):
                            target_dev = cand_dev
                            break

                if target_dev is not None and wpd_friendly:
                    m_dl = self.drive_letter_re.match(wpd_friendly)
                    if m_dl:
                        if not target_dev["drive_letter"]:
                            target_dev["drive_letter"] = f"{m_dl.group(1).upper()}:"
                        self._append_evidence(target_dev, "WPD")
                    else:
                        if wpd_friendly.lower() not in (target_dev["friendly_name"] or "").lower():
                            target_dev["friendly_name"] = f"{target_dev['friendly_name']} [{wpd_friendly}]".strip()
                        self._append_evidence(target_dev, "WPD")

        # 2. Microsoft\Windows NT\CurrentVersion\EMDMgmt
        emd_key = hive.get_key("Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt")
        if emd_key is not None:
            for sk in emd_key.subkeys():
                sk_name = sk.name
                m_usbstor = self.usbstor_re.search(sk_name)
                if not m_usbstor:
                    continue
                ven, prod, rev, serial = m_usbstor.groups()
                clean_serial = _normalize_serial(serial)
                if not clean_serial:
                    continue
                ven_c = ven.strip("_ ").strip()
                prod_c = prod.strip("_ ").strip()
                rev_c = rev.strip("_ ").strip()
                dev = self._ensure_device(
                    correlated_map,
                    clean_serial,
                    vendor_id=ven_c,
                    product_id=prod_c,
                    revision=rev_c,
                    friendly_name=f"{ven_c} {prod_c}".strip(),
                    source_evidence="SOFTWARE\\EMDMgmt",
                )
                m_guid = self.guid_re.search(sk_name)
                if m_guid:
                    if not dev["volume_guid"]:
                        dev["volume_guid"] = f"{{{m_guid.group(1)}}}"
                    tail = sk_name[m_guid.end() :].lstrip("_")
                    if "_" in tail:
                        vol_label, _vol_serial_dec = tail.rsplit("_", 1)
                        vol_label = vol_label.strip()
                        if vol_label and vol_label.lower() not in (dev["friendly_name"] or "").lower():
                            dev["friendly_name"] = f"{dev['friendly_name']} [{vol_label}]".strip()
                if sk.last_modified is not None:
                    self._update_timestamps(dev, last_cand=sk.last_modified)

    def _correlate_ntuser_hive(
        self,
        hive: _OfflineHiveWrapper,
        username: str,
        correlated_map: Dict[str, Dict[str, Any]],
    ) -> None:
        mp2_key = hive.get_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
        if mp2_key is None:
            return
        guid_to_devs: Dict[str, List[Dict[str, Any]]] = {}
        for dev in correlated_map.values():
            vg = dev.get("volume_guid")
            if vg:
                guid_to_devs.setdefault(vg.lower(), []).append(dev)
        if not guid_to_devs:
            return

        for sk in mp2_key.subkeys():
            sk_low = sk.name.strip().lower()
            matched_list = guid_to_devs.get(sk_low)
            if not matched_list:
                continue
            sk_ts = sk.last_modified
            for dev in matched_list:
                self._append_evidence(dev, f"MountPoints2({username})")
                if sk_ts is not None:
                    self._update_timestamps(dev, last_cand=sk_ts)

    def _correlate_from_offline_registry(
        self, correlated_map: Dict[str, Dict[str, Any]]
    ) -> int:
        """Correlate offline SYSTEM, SOFTWARE, and NTUSER.DAT hives; return ActiveTimeBias minutes."""
        hives = self._discover_offline_hives()
        detected_bias_min: Optional[int] = None

        system_hives = [h for h in hives if h.role == "SYSTEM"]
        software_hives = [h for h in hives if h.role == "SOFTWARE"]
        ntuser_hives = [h for h in hives if h.role == "NTUSER"]

        for sh in system_hives:
            label = sh.path.name if sh.provenance == "active" else f"{sh.provenance}:{sh.path.name}"
            with _OfflineHiveWrapper(sh.path) as h_wrap:
                if h_wrap is None:
                    continue
                bias = self._correlate_system_hive(h_wrap, label, correlated_map)
                if bias is not None and detected_bias_min is None:
                    detected_bias_min = bias

        for swh in software_hives:
            with _OfflineHiveWrapper(swh.path) as h_wrap:
                if h_wrap is None:
                    continue
                self._correlate_software_hive(h_wrap, correlated_map)

        # Cross-fill paired drive_letter <-> volume_guid before MountPoints2 lookup
        for dev in correlated_map.values():
            dl = dev.get("drive_letter")
            vg = dev.get("volume_guid")
            if dl and not vg:
                paired_vg = self._drive_to_guid.get(dl.upper())
                if paired_vg:
                    dev["volume_guid"] = paired_vg
            elif vg and not dl:
                paired_dl = self._guid_to_drive.get(vg.lower())
                if paired_dl:
                    dev["drive_letter"] = paired_dl

        for nth in ntuser_hives:
            with _OfflineHiveWrapper(nth.path) as h_wrap:
                if h_wrap is None:
                    continue
                self._correlate_ntuser_hive(h_wrap, nth.username or "User", correlated_map)

        return int(detected_bias_min) if detected_bias_min is not None else 0

    def _correlate_from_raw_recmd(self, correlated_map: Dict[str, Dict[str, Any]]) -> None:
        """Check if raw_recmd table exists in case.duckdb and extract MountedDevices / USBSTOR info."""
        recmd_rows: List[Tuple[Any, ...]] = []
        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cursor = conn.cursor()
            has_recmd = (
                cursor.execute(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'raw_recmd';"
                ).fetchone()[0]
                > 0
            )
            if not has_recmd:
                return

            desc = cursor.execute("DESCRIBE raw_recmd;").fetchall()
            col_map = {str(r[0]).lower(): str(r[0]) for r in desc}
            key_col = col_map.get("keypath")
            val_name_col = col_map.get("valuename")
            val_data_col = col_map.get("valuedata")
            ts_col = col_map.get("lastwritetimestamp")

            if not (key_col and val_data_col):
                return

            try:
                q = f"""
                SELECT "{key_col}", "{val_name_col or key_col}", "{val_data_col}", "{ts_col or key_col}"
                FROM raw_recmd
                WHERE "{key_col}" ILIKE '%USBSTOR%' OR "{key_col}" ILIKE '%MountedDevices%' OR "{key_col}" ILIKE '%EMDMgmt%';
                """
                recmd_rows = cursor.execute(q).fetchall()
            except Exception as ex:
                self._log(f"Warning: Could not extract from raw_recmd: {ex}", "WARNING")
                return

        for row in recmd_rows:
            keypath, val_name, val_data, _ts = row
            val_data_str = str(val_data or "")
            kp_str = str(keypath or "")

            if "mounteddevices" in kp_str.lower():
                m_dl = re.search(r"\\DosDevices\\([A-Za-z]:)", str(val_name or ""), re.IGNORECASE)
                drive_letter = m_dl.group(1).upper() if m_dl else None
                m_guid = self.guid_re.search(str(val_name or ""))
                vol_guid = f"{{{m_guid.group(1)}}}" if m_guid else None

                m_usbstor = self.usbstor_re.search(val_data_str)
                if m_usbstor:
                    ven, prod, rev, serial = m_usbstor.groups()
                    clean_serial = _normalize_serial(serial)
                    if clean_serial:
                        dev = self._ensure_device(
                            correlated_map,
                            clean_serial,
                            vendor_id=ven.strip("_ ").strip(),
                            product_id=prod.strip("_ ").strip(),
                            revision=rev.strip("_ ").strip(),
                            source_evidence="raw_recmd(MountedDevices)",
                        )
                        if drive_letter and not dev["drive_letter"]:
                            dev["drive_letter"] = drive_letter
                        if vol_guid and not dev["volume_guid"]:
                            dev["volume_guid"] = vol_guid

            if "usbstor" in kp_str.lower():
                m_usbstor = self.usbstor_re.search(kp_str)
                if m_usbstor:
                    _ven, _prod, _rev, serial = m_usbstor.groups()
                    clean_serial = _normalize_serial(serial)
                    if clean_serial in correlated_map:
                        self._append_evidence(correlated_map[clean_serial], "raw_recmd(USBSTOR)")

    def _correlate_from_live_registry(self, correlated_map: Dict[str, Dict[str, Any]]) -> None:
        """Query live host Windows Registry ONLY during explicit live / live_triage runs."""
        if os.name != "nt":
            return

        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as key:
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    val_name, val_data, _ = winreg.EnumValue(key, i)
                    val_str = (
                        val_data.decode("utf-16le", errors="ignore")
                        if isinstance(val_data, bytes)
                        else str(val_data)
                    )
                    m_usbstor = self.usbstor_re.search(val_str)
                    if m_usbstor:
                        ven, prod, rev, serial = m_usbstor.groups()
                        clean_serial = _normalize_serial(serial)
                        if not clean_serial:
                            continue
                        ven_c = ven.strip("_ ").strip()
                        prod_c = prod.strip("_ ").strip()
                        rev_c = rev.strip("_ ").strip()
                        dev = self._ensure_device(
                            correlated_map,
                            clean_serial,
                            vendor_id=ven_c,
                            product_id=prod_c,
                            revision=rev_c,
                            friendly_name=f"{ven_c} {prod_c}".strip(),
                            source_evidence="LiveHKLM\\MountedDevices",
                        )
                        if "\\DosDevices\\" in val_name:
                            dl = val_name.replace("\\DosDevices\\", "").strip()
                            if dl and not dev["drive_letter"]:
                                dev["drive_letter"] = dl
                        m_guid = self.guid_re.search(val_name)
                        if m_guid and not dev["volume_guid"]:
                            dev["volume_guid"] = f"{{{m_guid.group(1)}}}"

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                ) as usbstor_key:
                    num_sub = winreg.QueryInfoKey(usbstor_key)[0]
                    for i in range(num_sub):
                        dev_key_name = winreg.EnumKey(usbstor_key, i)
                        with winreg.OpenKey(usbstor_key, dev_key_name) as dev_key:
                            num_instances = winreg.QueryInfoKey(dev_key)[0]
                            for j in range(num_instances):
                                serial_key_name = winreg.EnumKey(dev_key, j)
                                clean_serial = _normalize_serial(serial_key_name)
                                if not clean_serial:
                                    continue
                                with winreg.OpenKey(dev_key, serial_key_name) as inst_key:
                                    try:
                                        friendly_name = winreg.QueryValueEx(inst_key, "FriendlyName")[0]
                                    except OSError:
                                        try:
                                            friendly_name = winreg.QueryValueEx(inst_key, "DeviceDesc")[0]
                                        except OSError:
                                            friendly_name = dev_key_name
                                    self._ensure_device(
                                        correlated_map,
                                        clean_serial,
                                        vendor_id=dev_key_name.split("&")[0] if "&" in dev_key_name else "USB",
                                        product_id=dev_key_name.split("&")[1] if "&" in dev_key_name else dev_key_name,
                                        friendly_name=_clean_device_label(friendly_name),
                                        source_evidence="LiveHKLM\\Enum\\USBSTOR",
                                    )
            except OSError as reg_err:
                self._log(f"Live Enum/USBSTOR lookup info: {reg_err}", "DEBUG")
        except Exception as ex:
            self._log(f"Live registry lookup warning: {ex}", "WARNING")

    def parse(self, source_type: Optional[str] = None) -> Dict[str, int]:
        """Cross-correlate all USB evidence sources and populate parsed_usb_devices."""
        start_time = time.time()
        self._log(f"Starting USB Device Correlator across staging directory: {self.staging_dir}")

        self._guid_to_drive.clear()
        self._drive_to_guid.clear()
        correlated_map: Dict[str, Dict[str, Any]] = {}

        # 1. Offline Registry hives FIRST (establishes ActiveTimeBias, USBSTOR, MountedDevices, WPD/EMDMgmt, MountPoints2)
        bias_minutes = self._correlate_from_offline_registry(correlated_map)

        # 2. Parse setupapi.dev.log and setupapi.offline.log (adjusted to UTC via ActiveTimeBias)
        setupapi_files: List[Path] = []
        seen_logs: Set[Path] = set()
        if self.staging_dir.exists():
            staging_res = self.staging_dir.resolve()
            _SKIP_USB_ROOTS = {
                "registry", "logs", "prefetch", "filesystem", "mft", "srum",
                "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails",
                "zoneidentifier", "recyclebin", "wbem", "wer", "wlan", "browsers",
                "chat", "cloud", "mail", "media", "documents", "notifications",
                "activitiescache", "sqlite",
            }
            for walk_root, dirs, files in os.walk(staging_res):
                root_p = Path(walk_root)
                if root_p == staging_res:
                    dirs[:] = [d for d in dirs if d.lower() not in _SKIP_USB_ROOTS]
                for fname in sorted(files):
                    fn_low = fname.lower()
                    if fn_low.startswith("setupapi") and fn_low.endswith(".log"):
                        rp = (root_p / fname).resolve()
                        if rp not in seen_logs:
                            seen_logs.add(rp)
                            setupapi_files.append(rp)

        self._log(
            f"Found {len(setupapi_files)} setupapi log files (ActiveTimeBias={bias_minutes} min): "
            f"{[f.name for f in setupapi_files]}"
        )
        for sapif in setupapi_files:
            self._parse_setupapi_logs(sapif, correlated_map, bias_minutes=bias_minutes)

        # 3. Correlate from raw_recmd in DuckDB (if populated)
        self._correlate_from_raw_recmd(correlated_map)

        # 4. Live host registry correlation ONLY on explicit live / live_triage cases
        if self._resolve_is_live_triage(explicit_source_type=source_type):
            self._correlate_from_live_registry(correlated_map)

        records: List[Dict[str, Any]] = []
        for _serial, dev in sorted(correlated_map.items(), key=lambda kv: kv[0]):
            records.append(
                {
                    "vendor_id": dev["vendor_id"],
                    "product_id": dev["product_id"],
                    "revision": dev["revision"],
                    "serial_number": dev["serial_number"],
                    "friendly_name": dev["friendly_name"],
                    "drive_letter": dev["drive_letter"],
                    "volume_guid": dev["volume_guid"],
                    "first_connected_utc": dev["first_connected_utc"],
                    "last_connected_utc": dev["last_connected_utc"],
                    "source_evidence": dev["source_evidence"],
                }
            )

        with self.db_manager.get_lock(self.case_id):
            conn = self.db_manager.get_connection(self.case_id, read_only=False)
            self.conn = conn
            cursor = conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS parsed_usb_devices;")

        row_count = self.insert_records(
            table_name="parsed_usb_devices",
            records=records,
            schema_ddl=USB_SCHEMA_DDL,
            artifact_id="usb_devices",
            category="OPERATING SYSTEM",
            display_name="USB & External Storage Devices",
            source_tool="USBDeviceCorrelator",
        )

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:USBCorrelator",
            command_executed=(
                f"USBDeviceCorrelator.parse({len(setupapi_files)} logs, "
                f"{len(records)} correlated devices, bias={bias_minutes}m)"
            ),
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"USB Device Correlator completed in {duration_ms}ms with {row_count} devices registered."
        )
        return {"parsed_usb_devices": row_count}
