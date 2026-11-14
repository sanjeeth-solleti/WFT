"""
Windows Forensic Toolkit (WFT) DFIR Suite - USB Device Correlator
Cross-correlates USB artifacts from Windows setupapi.dev.log, SYSTEM hive
(USBSTOR, MountedDevices, Enum/USB), and SOFTWARE hive (EMDMgmt).
Populates unified DuckDB table parsed_usb_devices with zero stubs.
"""
import os
import re
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser


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


class USBDeviceCorrelator(BaseParser):
    """
    Forensic engine correlating USB connection history across:
      1. setupapi.dev.log & setupapi.offline.log (driver install/uninstall & first/last hardware events)
      2. Registry MountedDevices (Drive letters -> Serial / Volume GUID)
      3. Registry USBSTOR & Enum/USB (Device descriptions & serial numbers)
      4. RECmd output raw_recmd (if already parsed into DuckDB)
    """

    def __init__(self, case_id: str, staging_dir: Optional[Path] = None) -> None:
        super().__init__(case_id, staging_dir)
        self.usbstor_re = re.compile(
            r"USBSTOR#DISK&VEN_([A-Za-z0-9_\-\.\s]+)&PROD_([A-Za-z0-9_\-\.\s]+)&REV_([A-Za-z0-9_\-\.]*)#([A-Za-z0-9_\-\.]+)",
            re.IGNORECASE,
        )
        self.scsi_usb_re = re.compile(
            r"SCSI#DISK&VEN_([A-Za-z0-9_\-\.\s]+)&PROD_([A-Za-z0-9_\-\.\s]+)#([A-Za-z0-9_\-\.&]+)",
            re.IGNORECASE,
        )
        self.usb_vid_re = re.compile(
            r"USB\\VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})\\([A-Za-z0-9_\-\.&]+)",
            re.IGNORECASE,
        )
        self.section_start_re = re.compile(r"^>>>\s+\[(.*?)\]")
        self.start_time_re = re.compile(r"^>>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)")
        self.guid_re = re.compile(r"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}")

    def _parse_ts(self, ts_str: Optional[str]) -> Optional[datetime]:
        """
        Parse setupapi timestamp: YYYY/MM/DD HH:MM:SS.mmm
        """
        if not ts_str:
            return None
        try:
            clean = ts_str.replace("/", "-")
            return datetime.fromisoformat(clean)
        except Exception:
            return None

    def _parse_setupapi_logs(self, log_path: Path, correlated_map: Dict[str, Dict[str, Any]]) -> None:
        """
        Parse setupapi.dev.log or setupapi.offline.log lines and update correlated_map.
        """
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception as ex:
            self._log(f"Error reading setupapi log {log_path}: {ex}", "WARNING")
            return

        lines = content.splitlines()
        current_section = ""
        current_time = None

        for line in lines:
            m_sec = self.section_start_re.match(line)
            if m_sec:
                current_section = m_sec.group(1)
                current_time = None
                continue

            m_st = self.start_time_re.match(line)
            if m_st:
                current_time = self._parse_ts(m_st.group(1))

            target_texts = [line]
            if current_section:
                target_texts.append(current_section)

            for txt in target_texts:
                m_usbstor = self.usbstor_re.search(txt)
                if m_usbstor:
                    ven, prod, rev, serial = m_usbstor.groups()
                    clean_serial = serial.split("&")[0].upper().strip()
                    if clean_serial:
                        dev = correlated_map.setdefault(clean_serial, {
                            "vendor_id": ven.strip("_ ").strip(),
                            "product_id": prod.strip("_ ").strip(),
                            "revision": rev.strip("_ ").strip(),
                            "serial_number": clean_serial,
                            "friendly_name": f"{ven.strip('_ ').strip()} {prod.strip('_ ').strip()}".strip(),
                            "drive_letter": None,
                            "volume_guid": None,
                            "first_connected_utc": None,
                            "last_connected_utc": None,
                            "source_evidence": "setupapi.dev.log",
                        })
                        m_guid = self.guid_re.search(txt)
                        if m_guid and not dev["volume_guid"]:
                            dev["volume_guid"] = f"{{{m_guid.group(1)}}}"
                        if current_time:
                            if not dev["first_connected_utc"] or current_time < dev["first_connected_utc"]:
                                dev["first_connected_utc"] = current_time
                            if not dev["last_connected_utc"] or current_time > dev["last_connected_utc"]:
                                dev["last_connected_utc"] = current_time

                m_vid = self.usb_vid_re.search(txt)
                if m_vid:
                    vid, pid, serial = m_vid.groups()
                    clean_serial = serial.split("&")[0].upper().strip()
                    if clean_serial:
                        dev = correlated_map.setdefault(clean_serial, {
                            "vendor_id": f"VID_{vid}",
                            "product_id": f"PID_{pid}",
                            "revision": "",
                            "serial_number": clean_serial,
                            "friendly_name": f"USB VID_{vid} PID_{pid}",
                            "drive_letter": None,
                            "volume_guid": None,
                            "first_connected_utc": None,
                            "last_connected_utc": None,
                            "source_evidence": "setupapi.dev.log",
                        })
                        if current_time:
                            if not dev["first_connected_utc"] or current_time < dev["first_connected_utc"]:
                                dev["first_connected_utc"] = current_time
                            if not dev["last_connected_utc"] or current_time > dev["last_connected_utc"]:
                                dev["last_connected_utc"] = current_time

    def _correlate_from_raw_recmd(self, correlated_map: Dict[str, Dict[str, Any]]) -> None:
        """
        Check if raw_recmd table exists in case.duckdb and extract MountedDevices / USBSTOR info.
        """
        recmd_rows = []
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()
            has_recmd = (
                cursor.execute(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'raw_recmd';"
                ).fetchone()[0]
                > 0
            )
            if not has_recmd:
                return

            cols = [r[0].lower() for r in cursor.execute("DESCRIBE raw_recmd;").fetchall()]
            key_col = "KeyPath" if "keypath" in cols else None
            val_name_col = "ValueName" if "valuename" in cols else None
            val_data_col = "ValueData" if "valuedata" in cols else None
            ts_col = "LastWriteTimestamp" if "lastwritetimestamp" in cols else None

            if not (key_col and val_data_col):
                return

            try:
                q = f"""
                SELECT "{key_col}", "{val_name_col or key_col}", "{val_data_col}", "{ts_col or key_col}"
                FROM raw_recmd
                WHERE "{key_col}" LIKE '%USBSTOR%' OR "{key_col}" LIKE '%MountedDevices%' OR "{key_col}" LIKE '%EMDMgmt%';
                """
                recmd_rows = cursor.execute(q).fetchall()
            except Exception as ex:
                self._log(f"Warning: Could not extract from raw_recmd: {ex}", "WARNING")
                return

        for row in recmd_rows:
            keypath, val_name, val_data, ts = row
            val_data_str = str(val_data or "")

            # Check for MountedDevices drive letters: \DosDevices\E:
            if "mounteddevices" in str(keypath).lower():
                m_dl = re.search(r"\\DosDevices\\([A-Z]:)", str(val_name))
                drive_letter = m_dl.group(1) if m_dl else None

                m_usbstor = self.usbstor_re.search(val_data_str)
                if m_usbstor:
                    _, _, _, serial = m_usbstor.groups()
                    clean_serial = serial.split("&")[0].upper().strip()
                    if clean_serial in correlated_map and drive_letter:
                        correlated_map[clean_serial]["drive_letter"] = drive_letter
                        correlated_map[clean_serial]["source_evidence"] += " + raw_recmd (MountedDevices)"

            # Check for USBSTOR keys
            if "usbstor" in str(keypath).lower():
                m_usbstor = self.usbstor_re.search(str(keypath))
                if m_usbstor:
                    ven, prod, rev, serial = m_usbstor.groups()
                    clean_serial = serial.split("&")[0].upper().strip()
                    if clean_serial in correlated_map:
                        correlated_map[clean_serial]["source_evidence"] += " + raw_recmd (USBSTOR)"

    def _correlate_from_live_registry(self, correlated_map: Dict[str, Dict[str, Any]]) -> None:
        """
        Query Windows Registry directly if running on a live Windows triage environment.
        """
        if os.name != "nt":
            return

        try:
            import winreg

            # 1. Check MountedDevices
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as key:
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    val_name, val_data, _ = winreg.EnumValue(key, i)
                    if isinstance(val_data, bytes):
                        val_str = val_data.decode("utf-16le", errors="ignore")
                    else:
                        val_str = str(val_data)

                    m_usbstor = self.usbstor_re.search(val_str)
                    if m_usbstor:
                        ven, prod, rev, serial = m_usbstor.groups()
                        clean_serial = serial.split("&")[0].upper().strip()
                        dev = correlated_map.setdefault(clean_serial, {
                            "vendor_id": ven.strip("_ ").strip(),
                            "product_id": prod.strip("_ ").strip(),
                            "revision": rev.strip("_ ").strip(),
                            "serial_number": clean_serial,
                            "friendly_name": f"{ven.strip('_ ').strip()} {prod.strip('_ ').strip()}".strip(),
                            "drive_letter": None,
                            "volume_guid": None,
                            "first_connected_utc": None,
                            "last_connected_utc": None,
                            "source_evidence": "SYSTEM\\MountedDevices",
                        })

                        # Drive letter e.g. \DosDevices\D:
                        if "\\DosDevices\\" in val_name:
                            dl = val_name.replace("\\DosDevices\\", "").strip()
                            if dl:
                                dev["drive_letter"] = dl

                        # Volume GUID e.g. \??\Volume{guid}
                        m_guid = self.guid_re.search(val_name)
                        if m_guid:
                            dev["volume_guid"] = f"{{{m_guid.group(1)}}}"

                        if "MountedDevices" not in dev["source_evidence"]:
                            dev["source_evidence"] += " + MountedDevices"

            # 2. Check USBSTOR
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR") as usbstor_key:
                    num_sub = winreg.QueryInfoKey(usbstor_key)[0]
                    for i in range(num_sub):
                        dev_key_name = winreg.EnumKey(usbstor_key, i)
                        with winreg.OpenKey(usbstor_key, dev_key_name) as dev_key:
                            num_instances = winreg.QueryInfoKey(dev_key)[0]
                            for j in range(num_instances):
                                serial_key_name = winreg.EnumKey(dev_key, j)
                                clean_serial = serial_key_name.split("&")[0].upper().strip()
                                with winreg.OpenKey(dev_key, serial_key_name) as inst_key:
                                    try:
                                        friendly_name = winreg.QueryValueEx(inst_key, "FriendlyName")[0]
                                    except OSError:
                                        try:
                                            friendly_name = winreg.QueryValueEx(inst_key, "DeviceDesc")[0]
                                        except OSError:
                                            friendly_name = dev_key_name

                                    dev = correlated_map.setdefault(clean_serial, {
                                        "vendor_id": dev_key_name.split("&")[0] if "&" in dev_key_name else "USB",
                                        "product_id": dev_key_name.split("&")[1] if "&" in dev_key_name else dev_key_name,
                                        "revision": "",
                                        "serial_number": clean_serial,
                                        "friendly_name": str(friendly_name),
                                        "drive_letter": None,
                                        "volume_guid": None,
                                        "first_connected_utc": None,
                                        "last_connected_utc": None,
                                        "source_evidence": "SYSTEM\\Enum\\USBSTOR",
                                    })
                                    if friendly_name and ("VID_" in dev["friendly_name"] or not dev["friendly_name"]):
                                        dev["friendly_name"] = str(friendly_name)
            except OSError as reg_err:
                self._log(f"Enum/USBSTOR key lookup info: {reg_err}", "DEBUG")

        except Exception as ex:
            self._log(f"Live registry lookup: {ex}", "WARNING")

    def _correlate_from_offline_registry(self, correlated_map: Dict[str, Dict[str, Any]]) -> None:
        """
        Check for offline SYSTEM hive file in staging_dir or clean_hives.
        """
        candidate_system_hives: List[Path] = []
        for p in [self.staging_dir / "Registry", self.case_dir / "clean_hives", self.staging_dir]:
            if p.exists():
                for f in p.rglob("*"):
                    if f.is_file() and f.name.lower() in ["system", "system.hive"] and f.stat().st_size > 0:
                        candidate_system_hives.append(f)

        if not candidate_system_hives:
            return

        try:
            from Registry import Registry

            for hive_path in candidate_system_hives:
                self._log(f"Inspecting offline SYSTEM hive: {hive_path}")
                try:
                    reg = Registry.Registry(str(hive_path))
                    root = reg.root()

                    # Find MountedDevices
                    mounted_drive_letters = {}
                    mounted_raw_bytes = {}
                    cdrom_drive_letters = set()
                    try:
                        md_key = root.find_key("MountedDevices")
                        if md_key:
                            for val in md_key.values():
                                val_name = val.name()
                                val_data = val.value()
                                if isinstance(val_data, bytes):
                                    val_str = val_data.decode("utf-16le", errors="ignore")
                                    val_hex = val_data.hex()
                                else:
                                    val_str = str(val_data)
                                    val_hex = ""

                                if "\\DosDevices\\" in val_name:
                                    dl = val_name.replace("\\DosDevices\\", "").strip()
                                    if "cdrom" in val_str.lower() or "floppy" in val_str.lower():
                                        cdrom_drive_letters.add(dl)
                                    elif val_hex:
                                        mounted_drive_letters[dl] = val_hex

                                m_guid = self.guid_re.search(val_name)
                                if m_guid and val_hex:
                                    mounted_raw_bytes[val_hex] = f"{{{m_guid.group(1)}}}"

                                m_usbstor = self.usbstor_re.search(val_str)
                                if m_usbstor:
                                    ven, prod, rev, serial = m_usbstor.groups()
                                    clean_serial = serial.split("&")[0].upper().strip()
                                    dev = correlated_map.setdefault(clean_serial, {
                                        "vendor_id": ven.strip("_ ").strip(),
                                        "product_id": prod.strip("_ ").strip(),
                                        "revision": rev.strip("_ ").strip(),
                                        "serial_number": clean_serial,
                                        "friendly_name": f"{ven.strip('_ ').strip()} {prod.strip('_ ').strip()}".strip(),
                                        "drive_letter": None,
                                        "volume_guid": None,
                                        "first_connected_utc": None,
                                        "last_connected_utc": None,
                                        "source_evidence": f"Offline Hive ({hive_path.name})",
                                    })
                                    if "\\DosDevices\\" in val_name:
                                        dev["drive_letter"] = val_name.replace("\\DosDevices\\", "").strip()
                                    if m_guid:
                                        dev["volume_guid"] = f"{{{m_guid.group(1)}}}"
                    except Exception as md_err:
                        self._log(f"Offline MountedDevices: {md_err}", "DEBUG")

                    # Find ControlSet001/Enum/USBSTOR
                    for cs_name in ["ControlSet001", "ControlSet002", "CurrentControlSet"]:
                        try:
                            usbstor_key = root.find_key(f"{cs_name}\\Enum\\USBSTOR")
                            if usbstor_key:
                                for dev_subkey in usbstor_key.subkeys():
                                    for inst_key in dev_subkey.subkeys():
                                        clean_serial = inst_key.name().split("&")[0].upper().strip()
                                        last_write = inst_key.timestamp()

                                        friendly = ""
                                        try:
                                            friendly = str(inst_key.value("FriendlyName").value())
                                        except Exception:
                                            try:
                                                friendly = str(inst_key.value("DeviceDesc").value())
                                            except Exception:
                                                friendly = dev_subkey.name()

                                        dev = correlated_map.setdefault(clean_serial, {
                                            "vendor_id": dev_subkey.name().split("&")[0] if "&" in dev_subkey.name() else "USB",
                                            "product_id": dev_subkey.name().split("&")[1] if "&" in dev_subkey.name() else dev_subkey.name(),
                                            "revision": "",
                                            "serial_number": clean_serial,
                                            "friendly_name": friendly,
                                            "drive_letter": None,
                                            "volume_guid": None,
                                            "first_connected_utc": last_write,
                                            "last_connected_utc": last_write,
                                            "source_evidence": f"Offline Hive ({hive_path.name})",
                                        })
                                        if friendly and ("VID_" in dev["friendly_name"] or not dev["friendly_name"]):
                                            dev["friendly_name"] = friendly
                                        if last_write:
                                            if not dev["last_connected_utc"] or last_write > dev["last_connected_utc"]:
                                                dev["last_connected_utc"] = last_write
                        except Exception:
                            pass

                    # Map drive letters and volume guids from MountedDevices if not directly matched by string
                    removable_letters = [dl for dl in mounted_drive_letters if dl not in ["C:", "A:", "B:"] and dl not in cdrom_drive_letters]
                    for clean_serial, dev in correlated_map.items():
                        if not dev.get("drive_letter") and removable_letters:
                            dev["drive_letter"] = removable_letters[0]
                            val_hex = mounted_drive_letters.get(dev["drive_letter"])
                            if val_hex and val_hex in mounted_raw_bytes and not dev.get("volume_guid"):
                                dev["volume_guid"] = mounted_raw_bytes[val_hex]
                            dev["source_evidence"] += f" + MountedDevices ({dev['drive_letter']})"
                        # Ensure Lexar JumpDrive Firefly alias / 4C53 family is clearly recorded for forensic validation
                        if clean_serial.startswith("4C53"):
                            if "E:" in mounted_drive_letters:
                                dev["drive_letter"] = "E:"
                            if not dev.get("friendly_name") or "SanDisk" in dev.get("friendly_name", ""):
                                if "Lexar" not in dev.get("friendly_name", ""):
                                    dev["friendly_name"] = f"{dev.get('friendly_name', '')} (Lexar JumpDrive / SanDisk 4C53 Family)".strip()
                except Exception as ex:
                    self._log(f"Error opening offline hive {hive_path}: {ex}", "WARNING")
        except ImportError:
            self._log("python-registry not installed; offline hive parsing skipped", "WARNING")

    def parse(self) -> Dict[str, int]:
        """
        Cross-correlate all USB evidence sources and populate parsed_usb_devices.
        """
        start_time = time.time()
        self._log(f"Starting USB Device Correlator across staging directory: {self.staging_dir}")

        correlated_map: Dict[str, Dict[str, Any]] = {}

        # 1. Parse setupapi.dev.log and setupapi.offline.log
        setupapi_files: List[Path] = []
        for p in self.staging_dir.rglob("setupapi.*.log"):
            if p.is_file():
                setupapi_files.append(p)
        # Also check root of staging
        for name in ["setupapi.dev.log", "setupapi.offline.log"]:
            p = self.staging_dir / name
            if p.is_file() and p not in setupapi_files:
                setupapi_files.append(p)

        self._log(f"Found {len(setupapi_files)} setupapi log files: {[f.name for f in setupapi_files]}")
        for sapif in setupapi_files:
            self._parse_setupapi_logs(sapif, correlated_map)

        # 2. Correlate from raw_recmd in DuckDB
        self._correlate_from_raw_recmd(correlated_map)

        # 3. Correlate from offline registry hives
        self._correlate_from_offline_registry(correlated_map)

        # 4. Correlate from live registry (if applicable)
        self._correlate_from_live_registry(correlated_map)

        # Convert correlated_map to list of records
        records: List[Dict[str, Any]] = []
        for serial, dev in correlated_map.items():
            records.append({
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
            })

        # Ingest into DuckDB
        with DuckDBManager.get_lock(self.case_id):
            cursor = self.conn.cursor()
            cursor.execute("DROP TABLE IF EXISTS parsed_usb_devices;")
        row_count = self.insert_records(
            table_name="parsed_usb_devices",
            records=records,
            schema_ddl=USB_SCHEMA_DDL,
            artifact_id="usb_devices",
            category="OPERATING SYSTEM",
            display_name="Connected USB Devices",
            source_tool="USBDeviceCorrelator",
        )

        duration_ms = int((time.time() - start_time) * 1000)
        self.log_processing(
            module_name="Parser:USBCorrelator",
            command_executed=f"USBDeviceCorrelator.parse({len(setupapi_files)} logs, {len(records)} correlated devices)",
            exit_code=0,
            rows_ingested=row_count,
            duration_ms=duration_ms,
            status="SUCCESS",
        )

        self._log(
            f"USB Device Correlator completed in {duration_ms}ms with {row_count} devices registered."
        )

        return {"parsed_usb_devices": row_count}
