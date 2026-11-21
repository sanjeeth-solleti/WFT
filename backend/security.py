"""
WFT Enterprise DFIR Suite - Central Offensive Security & Sandbox Containment Guards
"""
from __future__ import annotations

import glob
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

SAFE_SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
XML_ENTITY_BOMB_RE = re.compile(r"<!ENTITY\s+|<!DOCTYPE\s+", re.IGNORECASE)


def sanitize_sql_identifier(name: str, prefix: str = "tbl_") -> str:
    safe_prefix = re.sub(r"[^A-Za-z0-9_]", "_", str(prefix or "tbl_"))
    if not safe_prefix or not (safe_prefix[0].isalpha() or safe_prefix[0] == "_"):
        safe_prefix = "tbl_"
    clean = re.sub(r"[^A-Za-z0-9_]", "_", str(name or "").strip()).strip("_")
    if not clean or clean[0].isdigit():
        clean = f"{safe_prefix}{clean}"
    clean = clean[:63]
    if not SAFE_SQL_IDENTIFIER_RE.match(clean):
        raise ValueError(f"Blocked unsafe SQL identifier: {name!r}")
    return clean


def resolve_sandboxed_case_file(case_dir: Path, requested_path: str) -> Path:
    if not requested_path or "\x00" in str(requested_path) or not str(requested_path).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty or invalid file path")

    raw_clean = str(requested_path).strip()
    raw_norm = raw_clean.replace("/", "\\")
    raw_norm_low = raw_norm.lower()
    if (
        raw_norm.startswith("\\\\")
        or raw_norm_low.startswith("\\\\?\\unc\\")
        or raw_norm_low.startswith("\\\\.\\")
        or Path(raw_norm).drive.startswith("\\\\")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Sandbox Violation: Remote UNC network paths are forbidden.",
        )

    case_root = case_dir.resolve()
    staging_root = (case_root / "staging").resolve()
    reports_root = (case_root / "reports").resolve()

    norm_str = raw_clean.replace("\\", "/")
    segments = [seg for seg in norm_str.split("/") if seg]
    if ".." in segments:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Sandbox Violation: Path traversal attempt blocked.",
        )

    def _is_forbidden_case_internal(target: Path) -> bool:
        if target.parent == case_root:
            low_name = target.name.lower()
            if low_name.startswith("case.duckdb") or low_name == "processing.log":
                return True
        return False

    cand = Path(norm_str)
    resolved: Optional[Path] = None

    if cand.is_absolute():
        resolved = cand.resolve()
        if str(resolved).startswith("\\\\"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Sandbox Violation: Remote UNC network paths are forbidden.",
            )
        if _is_forbidden_case_internal(resolved):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Sandbox Violation: Access to internal case database or logs is forbidden.",
            )
        if not (resolved.is_relative_to(staging_root) or resolved.is_relative_to(reports_root)):
            m = re.search(r"(?i)/staging/(.+)$", norm_str)
            if m:
                rel_after = m.group(1).lstrip("/")
                if ".." in [s for s in rel_after.split("/") if s]:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Security Sandbox Violation: Path traversal attempt blocked.",
                    )
                resolved = (staging_root / rel_after).resolve()
            else:
                guest_rel = re.sub(r"^[A-Za-z]:/+", "", norm_str).lstrip("/")
                if guest_rel and guest_rel != norm_str:
                    guest_cand = (staging_root / guest_rel).resolve()
                    if (
                        not str(guest_cand).startswith("\\\\")
                        and guest_cand.is_relative_to(staging_root)
                        and guest_cand.is_file()
                    ):
                        return guest_cand
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Security Sandbox Violation: Access outside case staging directory is forbidden.",
                )
    else:
        clean_rel = norm_str.lstrip("/")
        if clean_rel.lower().startswith("staging/"):
            clean_rel = clean_rel[len("staging/") :].lstrip("/")
        cand_rel = (staging_root / clean_rel).resolve()
        if str(cand_rel).startswith("\\\\") or not cand_rel.is_relative_to(staging_root):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Sandbox Violation: Path traversal attempt blocked.",
            )
        resolved = cand_rel

    if (
        str(resolved).startswith("\\\\")
        or _is_forbidden_case_internal(resolved)
        or not (resolved.is_relative_to(staging_root) or resolved.is_relative_to(reports_root))
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security Sandbox Violation: Path traversal attempt blocked.",
        )

    if not resolved.is_file():
        target_name = Path(norm_str).name
        if target_name and target_name not in (".", "..") and staging_root.is_dir():
            escaped_name = glob.escape(target_name)
            for match in staging_root.rglob(escaped_name):
                res_m = match.resolve()
                if not str(res_m).startswith("\\\\") and res_m.is_file() and res_m.is_relative_to(staging_root):
                    return res_m
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requested evidence file not found in case staging.",
        )

    return resolved


def safe_extract_zip(zf: zipfile.ZipFile, dest_dir: Path, max_total_bytes: int = 512 * 1024 * 1024) -> int:
    dest_root = dest_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    extracted_count = 0
    total_written = 0

    for member in zf.infolist():
        if member.is_dir():
            continue
        raw_member = member.filename.replace("\\", "/")
        first_seg = raw_member.lstrip("/").split("/", 1)[0]
        clean_member = raw_member.lstrip("/")
        if not clean_member or ":" in first_seg or ".." in Path(clean_member).parts:
            raise PermissionError(f"Blocked Zip-Slip path traversal entry: {member.filename!r}")

        target_path = (dest_root / clean_member).resolve()
        if not target_path.is_relative_to(dest_root):
            raise PermissionError(f"Blocked Zip-Slip path traversal entry: {member.filename!r}")

        if member.file_size > max_total_bytes or (total_written + member.file_size) > max_total_bytes:
            break

        target_path.parent.mkdir(parents=True, exist_ok=True)
        aborted_for_limit = False
        try:
            with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if total_written > max_total_bytes:
                        aborted_for_limit = True
                        break
                    dst.write(chunk)
        except Exception:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise

        if aborted_for_limit:
            target_path.unlink(missing_ok=True)
            break

        extracted_count += 1

    return extracted_count


def strip_unsafe_xml_entities(xml_text: str) -> str:
    if XML_ENTITY_BOMB_RE.search(xml_text):
        xml_text = re.sub(r"<!DOCTYPE[^>\[]*\[[\s\S]*?\]\s*>", "", xml_text, flags=re.IGNORECASE)
        xml_text = re.sub(r"<!DOCTYPE[^>]*>", "", xml_text, flags=re.IGNORECASE)
        xml_text = re.sub(r"<!ENTITY[^>]*>", "", xml_text, flags=re.IGNORECASE)
    return xml_text


def validate_tool_binary_path(raw_path: str) -> Path:
    raw_str = str(raw_path or "")
    if "\x00" in raw_str:
        raise ValueError("Security Policy: Null byte in tool path.")
    clean = raw_str.strip().strip('"').strip("'").strip()
    if not clean:
        raise ValueError("Empty tool path")
    norm = clean.replace("/", "\\")
    norm_low = norm.lower()
    if (
        norm.startswith("\\\\")
        or norm_low.startswith("\\\\?\\unc\\")
        or norm_low.startswith("\\\\.\\")
        or Path(norm).drive.startswith("\\\\")
    ):
        raise ValueError("Security Policy: Remote UNC network paths are forbidden for tool binaries.")
    if any(ch in clean for ch in (";", "|", "&", "`", "$", "\n", "\r")):
        raise ValueError("Security Policy: Illegal shell metacharacters in tool path.")
    resolved = Path(clean).resolve()
    if str(resolved).startswith("\\\\"):
        raise ValueError("Security Policy: Remote UNC network paths are forbidden for tool binaries.")
    return resolved


def is_trusted_local_origin(origin: str) -> bool:
    """
    Allows port 8765 (http://127.0.0.1:8765, http://localhost:8765), any other
    localhost/127.0.0.1 port, testserver, and desktop app schemes, while blocking external websites.
    """
    if not origin:
        return True
    raw = origin.strip().lower().rstrip("/")
    if raw in ("null", "file://") or raw.startswith(
        ("file://", "tauri://", "app://", "wft://", "webview://", "chrome-extension://", "edge://")
    ):
        return True
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        return host in ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "testserver")
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
        "http://testserver",
    }

    async def dispatch(self, request: Request, call_next) -> Response:
        origin = request.headers.get("origin")
        if origin and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if origin.rstrip("/") not in self.ALLOWED_ORIGINS and not is_trusted_local_origin(origin):
                payload = json.dumps({"detail": f"Blocked cross-origin request from untrusted origin: {origin}"})
                return Response(
                    content=payload,
                    status_code=status.HTTP_403_FORBIDDEN,
                    media_type="application/json",
                )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
