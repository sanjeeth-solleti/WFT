"""
Windows Forensic Toolkit (WFT) DFIR Suite - Parsers Package
Exports all custom OS, carving, and application parsers with concurrent-safe lazy fallback resolution.
"""
from __future__ import annotations

import importlib
from typing import Any, Dict, Tuple

from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    filetime_to_datetime,
    prtime_to_datetime,
    webkit_to_datetime,
    windows_filetime_to_datetime,
)

_LAZY_EXPORTS: Dict[str, Tuple[str, str]] = {
    "NativeFallbackParser": (".native_fallback_parsers", "NativeFallbackParser"),
    "DataCarver": (".data_carver", "DataCarver"),
    "USBDeviceCorrelator": (".usb_correlator", "USBDeviceCorrelator"),
    "CorporateIRParser": (".corporate_ir_parser", "CorporateIRParser"),
    "ChatParser": (".chat_parser", "ChatParser"),
    "ChromiumParser": (".chromium_parser", "ChromiumParser"),
    "CloudParser": (".cloud_parser", "CloudParser"),
    "DocumentParser": (".document_parser", "DocumentParser"),
    "EmailParser": (".email_parser", "EmailParser"),
    "FirefoxParser": (".firefox_parser", "FirefoxParser"),
    "MediaParser": (".media_parser", "MediaParser"),
}

for _export_name, (_rel_mod, _attr_name) in _LAZY_EXPORTS.items():
    try:
        _mod = importlib.import_module(_rel_mod, __name__)
        _cls = getattr(_mod, _attr_name, None)
        if _cls is not None:
            globals()[_export_name] = _cls
    except Exception:
        # Leave unbound so __getattr__ dynamically resolves once sibling module is ready.
        pass


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is not None:
        rel_mod, attr_name = target
        try:
            mod = importlib.import_module(rel_mod, __name__)
            val = getattr(mod, attr_name)
            if val is not None:
                globals()[name] = val
                return val
        except Exception as exc:
            raise AttributeError(f"module {__name__!r} could not resolve {name!r}: {exc}") from exc
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseParser",
    "webkit_to_datetime",
    "prtime_to_datetime",
    "windows_filetime_to_datetime",
    "filetime_to_datetime",
    "copy_sqlite_with_wal",
    "DataCarver",
    "NativeFallbackParser",
    "USBDeviceCorrelator",
    "CorporateIRParser",
    "ChromiumParser",
    "FirefoxParser",
    "ChatParser",
    "CloudParser",
    "DocumentParser",
    "EmailParser",
    "MediaParser",
]
