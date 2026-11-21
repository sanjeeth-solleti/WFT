"""
Windows Forensic Toolkit (WFT) DFIR Suite - External Tool Paths & Environment Setup Helper
Verifies presence, configuration, and health of external forensic engines:
  1. Eric Zimmerman 16-Tool CLI Suite (.NET 6/9/10)
  2. RegRipper 4.0 (rip.exe -a & plugins/)
  3. Hindsight (hindsight.exe / pyhindsight)
  4. Trellix Stinger (stinger64.exe / stinger32.exe) & PE Heuristics
  5. Open-Source Bulk Extractor (bulk_extractor64.exe / bulk_extractor.exe)
  6. YARA-X Rules Engine
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.config import (
    BASE_DIR,
    RULES_DIR,
    get_env_file,
    get_tool_paths_status,
    reload_dotenv,
    save_tool_paths,
    scan_and_sync_tool_paths,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="WFT External Tool Paths & Health Verification")
    parser.add_argument("--sync", action="store_true", help="Scan host for forensic tools and update .env")
    parser.add_argument("--bootstrap", action="store_true", help="Run Setup-WFTTools.ps1 and reload .env")
    parser.add_argument("--json", action="store_true", help="Emit JSON status report")
    parser.add_argument("--no-write", action="store_true", help="Read-only inspection; do not modify .env")
    args = parser.parse_args(argv)

    if args.bootstrap and not args.no_write:
        ps_script = BASE_DIR / "Setup-WFTTools.ps1"
        ps_exe = shutil.which("powershell.exe") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        if ps_script.is_file():
            subprocess.run(
                [ps_exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)],
                cwd=str(BASE_DIR),
                check=False,
            )

    reload_dotenv()
    env_file = get_env_file()
    if (args.sync or not env_file.exists()) and not args.no_write:
        scan_and_sync_tool_paths(apply_to_env=True)
        reload_dotenv()

    status_dict = get_tool_paths_status()
    yara_files = sorted(RULES_DIR.glob("*.yar*")) if RULES_DIR.is_dir() else []

    if args.json:
        print(
            json.dumps(
                {
                    "env_file": str(env_file),
                    "yara_rule_files": len(yara_files),
                    "tools": status_dict,
                },
                indent=2,
            )
        )
        return 0

    print("=" * 126)
    print("  Windows Forensic Toolkit (WFT) DFIR Suite - TOOL PATHS & HEALTH VERIFICATION")
    print("=" * 126)

    col_w = [44, 18, 58]
    header = f"{'TOOL NAME':<{col_w[0]}} | {'STATUS':<{col_w[1]}} | {'RESOLVED PATH':<{col_w[2]}}"
    print("-" * len(header))
    print(header)
    print("-" * len(header))

    main_items = [(k, v) for k, v in status_dict.items() if v.get("category") == "main"]
    ez_items = [(k, v) for k, v in status_dict.items() if v.get("category") == "individual_ez"]

    for _, info in main_items + ez_items:
        name = info.get("name", "")[: col_w[0]]
        status = f"[{info.get('status', 'UNKNOWN')}]"
        path = info.get("resolved_path") or "(not configured)"
        print(f"{name:<{col_w[0]}} | {status:<{col_w[1]}} | {path}")

    print("-" * len(header))
    found_count = sum(1 for v in status_dict.values() if v.get("status") == "FOUND")
    total_count = len(status_dict)
    print(f"\nSummary: {found_count}/{total_count} forensic tool entries FOUND | YARA rule files: {len(yara_files)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
