"""
Windows Forensic Toolkit (WFT) RegRipper 4.0 Orchestrator & Parser Runner
Executes rip.exe across Windows Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER, USRCLASS, AMCACHE),
parses and structures plugin reports, and ingests into DuckDB raw_regripper table.
"""
import csv
import io
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from backend.config import find_regripper_binary
from backend.db.engine import DuckDBManager


class RegRipperRunner:
    """
    Executes RegRipper 4.0 against staged and cleaned Windows registry hives,
    splitting individual plugin reports into structured, queryable database records.
    """

    def __init__(
        self,
        case_id: str,
        case_dir: Path,
        log_fn: Optional[Callable[[str, str], None]] = None,
    ):
        self.case_id = case_id
        self.case_dir = Path(case_dir).resolve()
        self.log_fn = log_fn or self._default_log
        self.regripper_out_dir = self.case_dir / "regripper"
        self.regripper_out_dir.mkdir(parents=True, exist_ok=True)
        self._plugin_catalog: Optional[Dict[str, Dict[str, str]]] = None

    def _default_log(self, msg: str, level: str = "INFO") -> None:
        print(f"[{level}] [RegRipperRunner] {msg}")

    def get_plugin_catalog(self) -> Dict[str, Dict[str, str]]:
        """
        Loads and caches the RegRipper plugin catalog by querying `rip.exe -l -c`.
        Returns dict keyed by lowercase plugin name.
        """
        if self._plugin_catalog is not None:
            return self._plugin_catalog

        catalog: Dict[str, Dict[str, str]] = {}
        try:
            rip_exe = find_regripper_binary()
            cmd = [str(rip_exe), "-l", "-c"]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            if res.returncode == 0 and res.stdout:
                reader = csv.reader(io.StringIO(res.stdout))
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 6:
                        pname = row[0].strip().lower()
                        catalog[pname] = {
                            "plugin_name": row[0].strip(),
                            "version": row[1].strip(),
                            "hive": row[2].strip(),
                            "mitre": row[3].strip(),
                            "category": row[4].strip(),
                            "description": row[5].strip(),
                        }
        except Exception as ex:
            self.log_fn(f"Notice loading RegRipper plugin catalog: {ex}", "WARNING")

        self._plugin_catalog = catalog
        return self._plugin_catalog

    def find_registry_hives(self) -> List[Tuple[str, str, Path]]:
        """
        Finds candidate registry hives in clean_hives (first priority) or staging.
        Returns list of tuples: (hive_type, hive_display_name, hive_path)
        """
        hives: List[Tuple[str, str, Path]] = []
        seen_types: Set[str] = set()

        search_dirs = [
            self.case_dir / "clean_hives",
            self.case_dir / "staging" / "Registry",
            self.case_dir / "staging",
        ]

        # Prioritized hive matchers: (hive_type, regex_pattern)
        hive_specs = [
            ("SYSTEM", r"^SYSTEM$"),
            ("SOFTWARE", r"^SOFTWARE$"),
            ("SAM", r"^SAM$"),
            ("SECURITY", r"^SECURITY$"),
            ("AMCACHE", r"^Amcache\.hve$"),
            ("NTUSER", r"NTUSER.*\.DAT$"),
            ("USRCLASS", r"UsrClass.*\.dat$"),
        ]

        for s_dir in search_dirs:
            if not s_dir.is_dir():
                continue
            for fpath in s_dir.rglob("*"):
                if not fpath.is_file() or fpath.stat().st_size == 0:
                    continue
                # Skip transaction logs and tmcontainers
                fname_lower = fpath.name.lower()
                if (
                    fname_lower.endswith(".log")
                    or fname_lower.endswith(".log1")
                    or fname_lower.endswith(".log2")
                    or fname_lower.endswith(".tm")
                    or fname_lower.endswith(".blf")
                    or "regtrans-ms" in fname_lower
                ):
                    continue

                for h_type, pattern in hive_specs:
                    if re.search(pattern, fpath.name, re.IGNORECASE):
                        key = f"{h_type}_{fpath.stem.lower()}"
                        if key not in seen_types:
                            seen_types.add(key)
                            hives.append((h_type, fpath.name, fpath))
                        break

        self.log_fn(f"Discovered {len(hives)} candidate registry hives: {[h[1] for h in hives]}")
        return hives

    def parse_plugin_blocks(
        self,
        raw_text: str,
        hive_name: str,
        hive_type: str,
    ) -> List[Dict[str, Any]]:
        """
        Parses rip.exe output stream into structured per-plugin report records.
        """
        catalog = self.get_plugin_catalog()
        records: List[Dict[str, Any]] = []

        # RegRipper separates plugins by '----------------------------------------'
        sections = re.split(r"-{30,}\s*\n", raw_text)

        for sec in sections:
            sec_clean = sec.strip()
            if not sec_clean:
                continue

            lines = sec_clean.splitlines()
            first_line = lines[0].strip() if lines else ""

            # Match: '<plugin> v.<version>' or 'Launching <plugin> v.<version>'
            m = re.search(r"(?:Launching\s+)?([a-zA-Z0-9_\-]+)\s+v\.([\w\.]+)", first_line)
            if not m:
                # Try finding header anywhere in the first 3 lines
                for l in lines[:3]:
                    m = re.search(r"^([a-zA-Z0-9_\-]+)\s+v\.([\w\.]+)", l.strip())
                    if m:
                        break

            if m:
                pname = m.group(1).strip()
                pver = m.group(2).strip()
            else:
                # Fallback to single word plugin name if valid
                words = first_line.split()
                if words and re.match(r"^[a-zA-Z0-9_\-]+$", words[0]):
                    pname = words[0]
                    pver = ""
                else:
                    continue

            # Lookup catalog metadata
            cat_info = catalog.get(pname.lower(), {})
            category = cat_info.get("category", "")
            mitre_attack = cat_info.get("mitre", "")
            description = cat_info.get("description", "")

            # If description or category not in catalog, check sec header lines
            for l in lines[:6]:
                l_s = l.strip()
                if not mitre_attack and "MITRE:" in l_s:
                    mitre_attack = l_s.replace("MITRE:", "").strip()
                if not description and (l_s.startswith("(") or "Parse" in l_s or "Check" in l_s or "Get" in l_s):
                    description = l_s.strip("()")

            # Find a meaningful summary line (first non-header, non-empty finding)
            summary_line = ""
            for l in lines[1:]:
                l_s = l.strip()
                if (
                    l_s
                    and not l_s.startswith("(")
                    and not l_s.startswith("MITRE:")
                    and not l_s.startswith("Launching")
                    and not l_s.startswith("Ref:")
                    and not l_s.startswith("Analysis Tip:")
                ):
                    summary_line = l_s[:200]
                    break

            records.append({
                "plugin_name": pname,
                "plugin_version": pver,
                "hive_name": hive_name,
                "hive_type": hive_type,
                "category": category or "Registry & OS",
                "mitre_attack": mitre_attack,
                "description": description or f"RegRipper {pname} plugin analysis",
                "report_text": sec_clean,
                "summary_line": summary_line or f"Analysis for {pname}",
                "output_lines_count": len(lines),
            })

        return records

    def run(self) -> Dict[str, Any]:
        """
        Executes RegRipper across all detected hives, ingests into DuckDB,
        and removes raw RECmd batch dump from artifact registry.
        """
        t0 = time.time()
        self.log_fn("Starting RegRipper 4.0 analysis pipeline...")

        try:
            rip_exe = find_regripper_binary()
        except FileNotFoundError as fnf:
            self.log_fn(f"RegRipper binary rip.exe not available: {fnf}", "ERROR")
            return {"status": "ERROR", "message": str(fnf), "plugins_parsed": 0}

        hives = self.find_registry_hives()
        if not hives:
            self.log_fn("No registry hives found for RegRipper analysis.", "WARNING")
            return {"status": "SKIPPED", "message": "No registry hives found", "plugins_parsed": 0}

        all_records: List[Dict[str, Any]] = []

        for h_type, h_name, h_path in hives:
            self.log_fn(f"Executing RegRipper plugins on hive: {h_name} ({h_type})...")
            out_txt_file = self.regripper_out_dir / f"{Path(h_name).stem}_rip.txt"

            try:
                cmd = [str(rip_exe), "-r", str(h_path), "-a"]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=180,  # 3 minute timeout per hive
                )

                stdout_text = proc.stdout or ""
                # Persist raw text report to case directory
                out_txt_file.write_text(stdout_text, encoding="utf-8", errors="replace")

                records = self.parse_plugin_blocks(stdout_text, h_name, h_type)
                self.log_fn(f"Hive {h_name}: parsed {len(records)} plugin reports.")
                all_records.extend(records)

            except Exception as ex:
                self.log_fn(f"Error executing RegRipper on hive {h_name}: {ex}", "WARNING")

        # Ingest into DuckDB
        total_ingested = 0
        with DuckDBManager.get_lock(self.case_id):
            conn = DuckDBManager.get_connection(self.case_id, read_only=False)
            cursor = conn.cursor()

            # Create table if not exists
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_regripper (
                _row_id BIGINT,
                plugin_name VARCHAR NOT NULL,
                plugin_version VARCHAR,
                hive_name VARCHAR NOT NULL,
                hive_type VARCHAR NOT NULL,
                category VARCHAR,
                mitre_attack VARCHAR,
                description VARCHAR,
                report_text VARCHAR NOT NULL,
                summary_line VARCHAR,
                output_lines_count INTEGER,
                parsed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

            # Clear existing records for this case before re-inserting
            cursor.execute("DELETE FROM raw_regripper;")

            if all_records:
                insert_stmt = """
                INSERT INTO raw_regripper (
                    _row_id, plugin_name, plugin_version, hive_name, hive_type,
                    category, mitre_attack, description, report_text,
                    summary_line, output_lines_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """
                rows_to_insert = [
                    (
                        idx + 1,
                        r["plugin_name"],
                        r["plugin_version"],
                        r["hive_name"],
                        r["hive_type"],
                        r["category"],
                        r["mitre_attack"],
                        r["description"],
                        r["report_text"],
                        r["summary_line"],
                        r["output_lines_count"],
                    )
                    for idx, r in enumerate(all_records)
                ]
                cursor.executemany(insert_stmt, rows_to_insert)
                total_ingested = len(rows_to_insert)

            # Register raw_regripper in artifact_registry
            cursor.execute("""
            INSERT OR REPLACE INTO artifact_registry
            (artifact_id, category, display_name, table_name, source_tool, row_count, last_updated)
            VALUES ('regripper_plugins', 'OPERATING SYSTEM', 'RegRipper Plugins Analysis', 'raw_regripper', 'RegRipper 4.0', ?, CURRENT_TIMESTAMP);
            """, [total_ingested])

            # Remove 'Registry Hive Batch Analysis' (raw_recmd) from artifact_registry as requested by user
            cursor.execute("""
            DELETE FROM artifact_registry
            WHERE artifact_id = 'os_recmd'
               OR display_name ILIKE '%Registry%Batch%'
               OR table_name = 'raw_recmd';
            """)

        duration_sec = round(time.time() - t0, 2)
        self.log_fn(f"RegRipper 4.0 analysis completed in {duration_sec}s: {total_ingested} plugin reports ingested.")

        return {
            "status": "SUCCESS",
            "plugins_parsed": total_ingested,
            "duration_seconds": duration_sec,
            "output_directory": str(self.regripper_out_dir),
        }
