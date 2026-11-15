"""
WFT Enterprise DFIR Suite - Central Offensive Security & Sandbox Containment Guards
"""
from __future__ import annotations

import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

SAFE_SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
XML_ENTITY_BOMB_RE = re.compile(r"<!ENTITY\s+|<!DOCTYPE\s+[^>]*\[", re.IGNORECASE)


def sanitize_sql_identifier(name: str, prefix: str = "tbl_") -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", str(name or "").strip()).strip("_")
    if not clean or clean[0].isdigit():
        clean = f"{prefix}{clean}"
    clean = clean[:63]
    if not SAFE_SQL_IDENTIFIER_RE.match(clean):
        raise ValueError(f"Blocked unsafe SQL identifier: {name!r}")
    return clean


def resolve_sandboxed_case_file(case_dir: Path, requested_path: str) -> Path:
    if not requested_path or not str(requested_path).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file path")

    case_root = case_dir.resolve()
    staging_root = (case_root / "staging").resolve()

    norm_str = str(requested_path).strip().replace("\\", "/")
    cand = Path(norm_str)

    resolved: Optional[Path] = None
    if cand.is_absolute():
        resolved = cand.resolve()
        if not resolved.is_relative_to(case_root):
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

    if not resolved.is_relative_to(case_root):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Sandbox Violation: Path traversal attempt blocked.",
        )

    if not resolved.is_file():
        target_name = Path(norm_str).name
        if target_name and target_name not in (".", ".."):
            for match in staging_root.rglob(target_name):
                res_m = match.resolve()
                if res_m.is_file() and res_m.is_relative_to(staging_root):
                    return res_m
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Requested evidence file not found in case staging.")

    return resolved


def safe_extract_zip(zf: zipfile.ZipFile, dest_dir: Path, max_total_bytes: int = 512 * 1024 * 1024) -> int:
    dest_root = dest_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    extracted_count = 0
    total_written = 0

    for member in zf.infolist():
        if member.is_dir():
            continue
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
    if XML_ENTITY_BOMB_RE.search(xml_text):
        xml_text = re.sub(r"<!DOCTYPE[^>]*\[[\s\S]*?\]>", "", xml_text, flags=re.IGNORECASE)
        xml_text = re.sub(r"<!ENTITY[^>]*>", "", xml_text, flags=re.IGNORECASE)
    return xml_text


def validate_tool_binary_path(raw_path: str) -> Path:
    clean = str(raw_path or "").strip()
    if not clean:
        raise ValueError("Empty tool path")
    if clean.startswith("\\\\") or clean.startswith("//"):
        raise ValueError("Security Policy: Remote UNC network paths are forbidden for tool binaries.")
    if any(ch in clean for ch in (";", "|", "&", "`", "$", "\n", "\r")):
        raise ValueError("Security Policy: Illegal shell metacharacters in tool path.")
    return Path(clean).resolve()


def is_trusted_local_origin(origin: str) -> bool:
    """
    Allows port 8765 (http://127.0.0.1:8765, http://localhost:8765), any other
    localhost/127.0.0.1 port, and desktop app schemes, while blocking external websites.
    """
    if not origin:
        return True
    raw = origin.strip().lower().rstrip("/")
    if raw in ("null", "file://") or raw.startswith(("file://", "tauri://", "app://", "wft://", "webview://", "chrome-extension://", "edge://")):
        return True
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        return host in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")
    except Exception:
        return False


class ForensicSecurityHeadersMiddleware(BaseHTTPMiddleware):
    ALLOWED_ORIGINS = {
        "http://127.0.0.1:8765",
        "http://localhost:8765",
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
            if origin.rstrip("/") not in self.ALLOWED_ORIGINS and not is_trusted_local_origin(origin):
                return Response(
                    content=f'{{"detail":"Blocked cross-origin request from untrusted origin: {origin}"}}',
                    status_code=status.HTTP_403_FORBIDDEN,
                    media_type="application/json",
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
