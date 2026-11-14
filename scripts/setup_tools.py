"""
Windows Forensic Toolkit (WFT) DFIR Suite - External Tool Paths & Environment Setup Helper
Verifies presence, configuration, and health of external forensic engines:
  1. Eric Zimmerman CLI Tools (.NET 6/9)
  2. RegRipper 4.0 (rip.exe & plugins)
  3. Hindsight (pyhindsight & hindsight.exe)
  4. Trellix Stinger (stinger64.exe / stinger32.exe) & PE Heuristics
  5. YARA-X Rules Engine
"""
import os
import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.config import (
    BASE_DIR,
    get_tool_paths_status,
    save_tool_paths,
)


def main():
    print("=" * 80)
    print("  Windows Forensic Toolkit (WFT) DFIR Suite - TOOL PATHS & HEALTH VERIFICATION")
    print("=" * 80)

    # Check or create default .env if missing
    env_file = ROOT_DIR / ".env"
    env_example = ROOT_DIR / ".env.example"
    if not env_file.exists() and env_example.exists():
        print(f"[setup] Creating .env from .env.example...")
        env_file.write_text(env_example.read_text(encoding="utf-8"), encoding="utf-8")

    status_dict = get_tool_paths_status()

    col_w = [18, 10, 48]
    header = f"{'TOOL NAME':<{col_w[0]}} | {'STATUS':<{col_w[1]}} | {'RESOLVED PATH':<{col_w[2]}}"
    print("-" * len(header))
    print(header)
    print("-" * len(header))

    for key, info in status_dict.items():
        name = info.get("name", key)
        status = info.get("status", "UNKNOWN")
        path = info.get("resolved_path") or "(not configured)"
        status_str = f"[{status}]"
        print(f"{name:<{col_w[0]}} | {status_str:<{col_w[1]}} | {path:<{col_w[2]}}")

    print("-" * len(header))
    print("\nSummary:")
    found_count = sum(1 for v in status_dict.values() if v.get("status") == "FOUND")
    total_count = len(status_dict)
    print(f"  {found_count}/{total_count} forensic tool components successfully located and verified.\n")


if __name__ == "__main__":
    main()
