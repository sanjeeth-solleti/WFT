"""
Windows Forensic Toolkit (WFT) DFIR Suite - Parsers Package
Exports all custom application parsers and correlators.
"""
from backend.parsers.base_parser import (
    BaseParser,
    copy_sqlite_with_wal,
    prtime_to_datetime,
    webkit_to_datetime,
    windows_filetime_to_datetime,
)
from backend.parsers.chat_parser import ChatParser
from backend.parsers.chromium_parser import ChromiumParser
from backend.parsers.cloud_parser import CloudParser
from backend.parsers.corporate_ir_parser import CorporateIRParser
from backend.parsers.document_parser import DocumentParser
from backend.parsers.email_parser import EmailParser
from backend.parsers.firefox_parser import FirefoxParser
from backend.parsers.media_parser import MediaParser
from backend.parsers.usb_correlator import USBDeviceCorrelator

__all__ = [
    "BaseParser",
    "webkit_to_datetime",
    "prtime_to_datetime",
    "windows_filetime_to_datetime",
    "copy_sqlite_with_wal",
    "ChromiumParser",
    "FirefoxParser",
    "ChatParser",
    "CloudParser",
    "CorporateIRParser",
    "DocumentParser",
    "EmailParser",
    "MediaParser",
    "USBDeviceCorrelator",
]
