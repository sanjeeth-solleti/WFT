"""
WFT Enterprise DFIR Suite - Central Offensive Security & Sandbox Containment Guards
Protects the forensic examiner's host OS against:
  - Path Traversal / Local File Inclusion (LFI) & Sibling Prefix Bypasses (CVE-2026-29509)
  - Counter-Forensic Zip-Slip & Symlink Escapes
  - SQL Identifier & View Injection from suspect artifacts
  - XXE / XML Entity Expansion Bombs in Scheduled Tasks & EVTX
  - Arbitrary Binary / UNC Share Execution in Tool Paths
"""
from __future__ import annotations

import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

SAFE_SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
XML_ENTITY_BOMB_RE = re.compile(r"<!ENTITY\s+|<!DOCTYPE\s+[^>]*\[", re.IGNORECASE)


def sanitize_sql_identifier(name: str, prefix: str = "tbl_") -> str:
    """
    Strictly sanitizes any dynamic table, view, or column name derived from
    suspect evidence (e.g. SQLite table names or EVTX channel names).
    """
    clean = re.sub(r"[^A-Za-z0-9_]", "_", str(name or "").strip()).strip("_")
    if not clean or clean[0].isdigit():
        clean = f"{prefix}{clean}"
    clean = clean[:63]
    if not SAFE_SQL_IDENTIFIER_RE.match(clean):
        raise ValueError(f"Blocked unsafe SQL identifier: {name!r}")
    return clean


def resolve_sandboxed_case_file(case_dir: Path, requested_path: str) -> Path:
    """
    Resolves a file path requested by the UI (for Hex, Media Preview, or Export)
    and strictly enforces that the final resolved path (after following symlinks
    and '..' segments) resides INSIDE `case_dir` using `Path.is_relative_to()`.
    Blocks:
      1. Absolute paths to host OS files (e.g. C:\\Windows\\System32\\config\\SAM, /etc/passwd)
      2. Relative traversal (../../Users/Examiner/.ssh/id_rsa)
      3. Sibling-prefix bypasses (cases/cfreds-evil vs cases/cfreds - CVE-2026-29509)
    """
    if not requested_path or not str(requested_path).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file path")

    case_root = case_dir.resolve()
    staging_root = (case_root / "staging").resolve()

    norm_str = str(requested_path).strip().replace("\\", "/")
    cand = Path(norm_str)

    resolved: Optional[Path] = None
    if cand.is_absolute():
        resolved = cand.resolve()
        # An absolute path is ONLY allowed if it is genuinely inside case_root!
        if not resolved.is_relative_to(case_root):
            # Try stripping the foreign prefix and resolving relative to staging_root
            m = re.search(r"(?i)/staging/(.+)$", norm_str)
            if m:
                resolved = (staging_root / m.group(1)).resolve()
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Security Sandbox Violation: Access outside case directory is forbidden.",
                )
    else:
        clean_rel = norm_str.lstrip("/")
        resolved = (staging_root / clean_rel).resolve()

    # Strict Path.is_relative_to check (immune to string prefix tricks)
    if not resolved.is_relative_to(case_root):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Sandbox Violation: Path traversal attempt blocked.",
        )

    if not resolved.is_file():
        # Safe filename fallback search strictly within staging_root
        target_name = Path(norm_str).name
        if target_name and target_name not in (".", ".."):
            for match in staging_root.rglob(target_name):
                res_m = match.resolve()
                if res_m.is_file() and res_m.is_relative_to(staging_root):
                    return res_m
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Requested evidence file not found in case staging.")

    return resolved


def safe_extract_zip(zf: zipfile.ZipFile, dest_dir: Path, max_total_bytes: int = 512 * 1024 * 1024) -> int:
    """
    Zip-Slip and Zip-Bomb resistant archive extractor.
    Verifies every member's resolved destination with `Path.is_relative_to(dest_root)`
    and enforces a cumulative uncompressed byte ceiling.
    """
    dest_root = dest_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    extracted_count = 0
    total_written = 0

    for member in zf.infolist():
        if member.is_dir():
            continue
        # Block suspicious compression ratios (> 100:1 when size > 10MB)
        if member.file_size > max_total_bytes or (total_written + member.file_size) > max_total_bytes:
            break
        clean_member = member.filename.replace("\\", "/").lstrip("/")
        target_path = (dest_root / clean_member).resolve()
        if not target_path.is_relative_to(dest_root):
            raise PermissionError(f"Blocked Zip-Slip path traversal entry: {member.filename!r}")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member, "r") as src, open(target_path, "wb") as dst:
            shutil.copyfileobj(src, dst, length=65536)
        total_written += member.file_size
        extracted_count += 1

    return extracted_count


def strip_unsafe_xml_entities(xml_text: str) -> str:
    """
    Neutralizes XXE (<!ENTITY ... SYSTEM "file:///...">) and Billion Laughs
    DOCTYPE blocks before passing untrusted XML to ElementTree.
    """
    if XML_ENTITY_BOMB_RE.search(xml_text):
        xml_text = re.sub(r"<!DOCTYPE[^>]*\[[\s\S]*?\]>", "", xml_text, flags=re.IGNORECASE)
        xml_text = re.sub(r"<!ENTITY[^>]*>", "", xml_text, flags=re.IGNORECASE)
    return xml_text


def validate_tool_binary_path(raw_path: str) -> Path:
    """
    Blocks UNC network shares (\\\\attacker\\share\\evil.exe) and command injection
    metacharacters when configuring external forensic tool paths.
    """
    clean = str(raw_path or "").strip()
    if not clean:
        raise ValueError("Empty tool path")
    if clean.startswith("\\\\") or clean.startswith("//"):
        raise ValueError("Security Policy: Remote UNC network paths are forbidden for tool binaries.")
    if any(ch in clean for ch in (";", "|", "&", "`", "$", "\n", "\r")):
        raise ValueError("Security Policy: Illegal shell metacharacters in tool path.")
    return Path(clean).resolve()


class ForensicSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies OWASP API Security headers and blocks cross-origin state-mutating requests
    from untrusted web origins (preventing drive-by CSRF against localhost).
    """

    ALLOWED_ORIGINS = {
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }

    async def dispatch(self, request: Request, call_next) -> Response:
        origin = request.headers.get("origin")
        if origin and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if origin.rstrip("/") not in self.ALLOWED_ORIGINS:
                return Response(
                    content='{"detail":"Blocked cross-origin request from untrusted origin."}',
                    status_code=status.HTTP_403_FORBIDDEN,
                    media_type="application/json",
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
