"""
Windows Forensic Toolkit (WFT) DFIR Suite - Media, EXIF & Windows Thumbcache Parser
Extracts:
1. Detailed EXIF & video metadata into parsed_media_exif, parsed_media_pictures, and parsed_media_videos.
2. Windows Explorer thumbcache_*.db databases & Snipping Tool / ScreenSketch screenshots,
   strictly validating BMP/JPEG/PNG headers & structure before carving into staging/Carved_Thumbnails/ -> parsed_thumbcache.
"""
import hashlib
import json
import math
import os
import re
import struct
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union

try:
    from PIL import ExifTags, Image
    HAS_PIL = True
except ImportError:
    ExifTags = None  # type: ignore[assignment]
    Image = None  # type: ignore[assignment]
    HAS_PIL = False

try:
    from dissect.thumbcache import ThumbcacheFile
    HAS_THUMBCACHE = True
except ImportError:
    ThumbcacheFile = None  # type: ignore[assignment]
    HAS_THUMBCACHE = False

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    cv2 = None  # type: ignore[assignment]
    HAS_CV2 = False

from backend.db.engine import DuckDBManager
from backend.parsers.base_parser import BaseParser


MEDIA_EXIF_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_media_exif (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    file_type VARCHAR,
    file_size_bytes BIGINT,
    sha256 VARCHAR,
    camera_make VARCHAR,
    camera_model VARCHAR,
    datetime_original TIMESTAMP,
    software VARCHAR,
    image_width INTEGER,
    image_height INTEGER,
    duration_seconds DOUBLE,
    latitude DOUBLE,
    longitude DOUBLE,
    gps_position VARCHAR,
    gps_coordinates VARCHAR,
    raw_metadata VARCHAR,
    source_file VARCHAR
);
"""

MEDIA_PICTURES_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_media_pictures (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    file_type VARCHAR,
    file_size_bytes BIGINT,
    sha256 VARCHAR,
    camera_make VARCHAR,
    camera_model VARCHAR,
    datetime_original TIMESTAMP,
    software VARCHAR,
    image_width INTEGER,
    image_height INTEGER,
    latitude DOUBLE,
    longitude DOUBLE,
    gps_position VARCHAR,
    gps_coordinates VARCHAR,
    raw_metadata VARCHAR,
    source_file VARCHAR
);
"""

MEDIA_VIDEOS_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_media_videos (
    _row_id BIGINT,
    file_path VARCHAR,
    file_name VARCHAR,
    file_type VARCHAR,
    file_size_bytes BIGINT,
    sha256 VARCHAR,
    datetime_original TIMESTAMP,
    duration_seconds DOUBLE,
    width INTEGER,
    height INTEGER,
    raw_metadata VARCHAR,
    source_file VARCHAR
);
"""

THUMBCACHE_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS parsed_thumbcache (
    _row_id BIGINT,
    cache_name VARCHAR,
    cache_file VARCHAR,
    entry_id BIGINT,
    entry_hash VARCHAR,
    cache_type VARCHAR,
    source_type VARCHAR,
    file_extension VARCHAR,
    extension VARCHAR,
    image_dimensions VARCHAR,
    image_size_bytes BIGINT,
    carved_path VARCHAR,
    carved_file_path VARCHAR,
    sha256 VARCHAR,
    carved_at TIMESTAMP,
    timestamp_utc TIMESTAMP,
    source_file VARCHAR
);
"""

# Standard EXIF / TIFF Tag IDs (for pure-Python fallback & deterministic tag ID resolution)
_FALLBACK_EXIF_TAGS: Dict[int, str] = {
    0x0100: "ImageWidth",
    0x0101: "ImageLength",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x8769: "ExifOffset",
    0x8825: "GPSInfo",
    0x882A: "TimeZoneOffset",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized",
    0x9290: "SubsecTime",
    0x9291: "SubsecTimeOriginal",
    0x9292: "SubsecTimeDigitized",
    0xA002: "ExifImageWidth",
    0xA003: "ExifImageHeight",
}

_FALLBACK_GPS_TAGS: Dict[int, str] = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x001D: "GPSDateStamp",
}

_TIFF_FIELD_SIZES: Dict[int, int] = {
    1: 1,   # BYTE
    2: 1,   # ASCII
    3: 2,   # SHORT
    4: 4,   # LONG
    5: 8,   # RATIONAL
    6: 1,   # SBYTE
    7: 1,   # UNDEFINED
    8: 2,   # SSHORT
    9: 4,   # SLONG
    10: 8,  # SRATIONAL
    11: 4,  # FLOAT
    12: 8,  # DOUBLE
}

_EXIF_OFFSET_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})$")
_EXIF_DT_RE = re.compile(
    r"^(\d{4})[:\-](\d{2})[:\-](\d{2})[T\s]+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?\s*(Z|[+-]\d{1,2}:?\d{2})?$"
)
_MAC_EPOCH_DELTA = 2082844800


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize any datetime to naive UTC so DuckDB TIMESTAMP never shifts by host timezone."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def compute_sha256(data_or_path: Union[bytes, Path]) -> str:
    hasher = hashlib.sha256()
    if isinstance(data_or_path, (bytes, bytearray)):
        hasher.update(data_or_path)
    else:
        with open(data_or_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    return hasher.hexdigest().lower()


def _clean_exif_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="ignore").replace("\x00", "").strip()
    return str(val).replace("\x00", "").strip()


def _rational_to_float(x: Any) -> Optional[float]:
    if x is None:
        return None
    if hasattr(x, "numerator") and hasattr(x, "denominator"):
        try:
            den = int(x.denominator)
            return (float(x.numerator) / float(den)) if den != 0 else None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    if isinstance(x, (tuple, list)) and len(x) == 2:
        try:
            den_f = float(x[1])
            return (float(x[0]) / den_f) if den_f != 0.0 else None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    if isinstance(x, (bool, bytes, bytearray)):
        if isinstance(x, (bytes, bytearray)):
            s = _clean_exif_str(x)
            if not s:
                return None
            try:
                v = float(s)
                return v if math.isfinite(v) else None
            except ValueError:
                return None
        return None
    try:
        val = float(x)
        return val if math.isfinite(val) else None
    except (ValueError, TypeError, ZeroDivisionError):
        return None


def dms_to_decimal(dms: Any, ref: Any, is_lon: bool = False) -> Optional[float]:
    """
    Convert EXIF GPS DMS coordinates and hemisphere ref to signed decimal degrees.
    Safely handles bytes/str refs, IFDRational, (num, den) tuples, and 0/0 uninitialized tags.
    """
    ref_clean = _clean_exif_str(ref).upper()
    is_negative = ref_clean.startswith(("S", "W"))
    dec: Optional[float] = None

    if isinstance(dms, (list, tuple)) and len(dms) >= 3:
        deg = _rational_to_float(dms[0])
        mins = _rational_to_float(dms[1])
        secs = _rational_to_float(dms[2])
        if deg is None:
            return None
        # If deg == 0 and both mins/secs failed due to 0/0, reject as uninitialized
        if deg == 0.0 and mins is None and secs is None:
            return None
        mins_v = mins if mins is not None else 0.0
        secs_v = secs if secs is not None else 0.0
        if deg < 0:
            is_negative = True
        dec = abs(deg) + (abs(mins_v) / 60.0) + (abs(secs_v) / 3600.0)
    elif isinstance(dms, (int, float, str, bytes, bytearray)) or hasattr(dms, "numerator"):
        val = _rational_to_float(dms)
        if val is None:
            return None
        if val < 0:
            is_negative = True
        dec = abs(val)

    if dec is None or not math.isfinite(dec):
        return None
    if dec == 0.0 and not ref_clean:
        return None
    if is_negative and dec != 0.0:
        dec = -dec
    limit = 180.0 if is_lon else 90.0
    if abs(dec) > limit:
        return None
    return round(dec, 6)


def _parse_tz_offset(offset_val: Any) -> Optional[timezone]:
    if offset_val is None:
        return None
    if isinstance(offset_val, (int, float)) and not isinstance(offset_val, bool):
        hrs = int(offset_val)
        if -14 <= hrs <= 14:
            return timezone(timedelta(hours=hrs))
        return None
    if isinstance(offset_val, (tuple, list)) and len(offset_val) >= 1:
        return _parse_tz_offset(offset_val[0])
    s = _clean_exif_str(offset_val).upper()
    if not s:
        return None
    if s == "Z":
        return timezone.utc
    m = _EXIF_OFFSET_RE.match(s)
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    hh, mm = int(m.group(2)), int(m.group(3))
    if hh > 14 or mm >= 60 or (hh == 14 and mm > 0):
        return None
    return timezone(sign * timedelta(hours=hh, minutes=mm))


def parse_exif_timestamp(
    val: Any,
    offset_val: Any = None,
    subsec_val: Any = None,
) -> Optional[datetime]:
    """
    Parse EXIF timestamp string with optional EXIF OffsetTime* / TimeZoneOffset
    and return naive UTC datetime suitable for DuckDB TIMESTAMP columns.
    """
    val_str = _clean_exif_str(val)
    if not val_str or val_str.startswith("0000"):
        return None

    m = _EXIF_DT_RE.match(val_str)
    if m:
        year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
        if not (1970 <= year <= 2100):
            return None
        frac_s = m.group(7) or _clean_exif_str(subsec_val)
        digits = "".join(ch for ch in frac_s if ch.isdigit()) if frac_s else ""
        micro = int((digits[:6]).ljust(6, "0")) if digits else 0
        inline_off = m.group(8)
        try:
            dt = datetime(year, month, day, hour, minute, second, micro)
        except ValueError:
            return None
        tz = _parse_tz_offset(offset_val) or _parse_tz_offset(inline_off)
        if tz is not None:
            return dt.replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    try:
        dt_iso = datetime.fromisoformat(val_str.replace("Z", "+00:00"))
        if not (1970 <= dt_iso.year <= 2100):
            return None
        tz_override = _parse_tz_offset(offset_val)
        if dt_iso.tzinfo is not None:
            return dt_iso.astimezone(timezone.utc).replace(tzinfo=None)
        if tz_override is not None:
            return dt_iso.replace(tzinfo=tz_override).astimezone(timezone.utc).replace(tzinfo=None)
        return dt_iso
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Pure-Python EXIF TIFF / Image Header Fallback & Strict Payload Validator
# ---------------------------------------------------------------------------

def _decode_tiff_ifd(tiff_data: bytes, endian: str, ifd_offset: int) -> Dict[int, Any]:
    tags: Dict[int, Any] = {}
    t_len = len(tiff_data)
    if ifd_offset < 8 or ifd_offset + 2 > t_len:
        return tags

    num_entries = struct.unpack_from(endian + "H", tiff_data, ifd_offset)[0]
    if num_entries > 512:
        return tags

    pos = ifd_offset + 2
    for _ in range(num_entries):
        if pos + 12 > t_len:
            break
        tag_id, field_type, count = struct.unpack_from(endian + "HHI", tiff_data, pos)
        raw_val_field = tiff_data[pos + 8 : pos + 12]
        pos += 12

        unit_sz = _TIFF_FIELD_SIZES.get(field_type)
        if unit_sz is None or count == 0 or count > 65536:
            continue
        total_bytes = unit_sz * count
        if total_bytes <= 4:
            v_bytes = raw_val_field[:total_bytes]
        else:
            val_off = struct.unpack_from(endian + "I", raw_val_field, 0)[0]
            if val_off + total_bytes > t_len:
                continue
            v_bytes = tiff_data[val_off : val_off + total_bytes]

        try:
            if field_type == 2:  # ASCII
                tags[tag_id] = v_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
            elif field_type == 7:  # UNDEFINED
                tags[tag_id] = bytes(v_bytes)
            elif field_type in (1, 6, 3, 8, 4, 9, 11, 12):
                fmt_ch = {1: "B", 6: "b", 3: "H", 8: "h", 4: "I", 9: "i", 11: "f", 12: "d"}[field_type]
                vals = struct.unpack(f"{endian}{count}{fmt_ch}", v_bytes)
                tags[tag_id] = vals[0] if count == 1 else vals
            elif field_type in (5, 10):  # RATIONAL / SRATIONAL
                fmt_pair = "II" if field_type == 5 else "ii"
                pairs = []
                for idx in range(count):
                    n_val, d_val = struct.unpack_from(endian + fmt_pair, v_bytes, idx * 8)
                    pairs.append((n_val, d_val))
                tags[tag_id] = pairs[0] if count == 1 else tuple(pairs)
        except struct.error:
            continue

    return tags


def _parse_exif_tiff_bytes(tiff_data: bytes) -> Tuple[Dict[int, Any], Dict[int, Any], Dict[int, Any]]:
    if len(tiff_data) < 8:
        return {}, {}, {}
    bo = tiff_data[:2]
    if bo == b"II":
        endian = "<"
    elif bo == b"MM":
        endian = ">"
    else:
        return {}, {}, {}

    magic, ifd0_off = struct.unpack_from(endian + "HI", tiff_data, 2)
    if magic != 42:
        return {}, {}, {}

    ifd0 = _decode_tiff_ifd(tiff_data, endian, ifd0_off)
    exif_ifd: Dict[int, Any] = {}
    gps_ifd: Dict[int, Any] = {}

    exif_ptr = ifd0.get(0x8769)
    if isinstance(exif_ptr, int) and exif_ptr > 0:
        exif_ifd = _decode_tiff_ifd(tiff_data, endian, exif_ptr)

    gps_ptr = ifd0.get(0x8825)
    if isinstance(gps_ptr, int) and gps_ptr > 0:
        gps_ifd = _decode_tiff_ifd(tiff_data, endian, gps_ptr)

    return ifd0, exif_ifd, gps_ifd


def _extract_exif_tiff_from_image_bytes(raw_bytes: bytes) -> Optional[bytes]:
    """Extract raw TIFF header bytes from TIFF or JPEG APP1 (Exif\\x00\\x00) or PNG eXIf."""
    if len(raw_bytes) < 8:
        return None
    if raw_bytes[:4] in (b"II*\x00", b"MM\x00*"):
        return raw_bytes
    # JPEG APP1 walk
    if raw_bytes[:3] == b"\xff\xd8\xff":
        pos = 2
        b_len = len(raw_bytes)
        while pos < b_len - 4:
            if raw_bytes[pos] != 0xFF:
                break
            while pos < b_len and raw_bytes[pos] == 0xFF:
                pos += 1
            if pos >= b_len:
                break
            marker = raw_bytes[pos]
            pos += 1
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                continue
            if marker in (0xD9, 0xDA):
                break
            if pos + 2 > b_len:
                break
            seg_len = struct.unpack_from(">H", raw_bytes, pos)[0]
            if seg_len < 2 or pos + seg_len > b_len:
                break
            if marker == 0xE1 and seg_len >= 14:
                payload = raw_bytes[pos + 2 : pos + seg_len]
                if payload[:6] == b"Exif\x00\x00":
                    return payload[6:]
            pos += seg_len
    # PNG eXIf chunk walk
    if raw_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        pos = 8
        b_len = len(raw_bytes)
        while pos + 12 <= b_len:
            c_len, c_type = struct.unpack_from(">I4s", raw_bytes, pos)
            if pos + 12 + c_len > b_len:
                break
            if c_type == b"eXIf" and c_len >= 8:
                return raw_bytes[pos + 8 : pos + 8 + c_len]
            if c_type == b"IEND":
                break
            pos += 12 + c_len
    return None


def _probe_image_dimensions_pure(buf: bytes) -> Tuple[int, int]:
    """Pure-Python width/height reader for PNG, BMP, GIF, JPEG, WebP, and TIFF."""
    b_len = len(buf)
    if b_len < 10:
        return 0, 0
    # PNG
    if b_len >= 24 and buf[:8] == b"\x89PNG\r\n\x1a\n" and buf[12:16] == b"IHDR":
        w, h = struct.unpack_from(">II", buf, 16)
        if 0 < w <= 65536 and 0 < h <= 65536:
            return int(w), int(h)
    # GIF
    if b_len >= 10 and buf[:6] in (b"GIF87a", b"GIF89a"):
        w, h = struct.unpack_from("<HH", buf, 6)
        return int(w), int(h)
    # BMP
    if b_len >= 26 and buf[:2] == b"BM":
        bi_size = struct.unpack_from("<I", buf, 14)[0]
        if bi_size == 12:
            w, h = struct.unpack_from("<HH", buf, 18)
            return int(w), int(h)
        if bi_size in (40, 52, 56, 108, 124) and b_len >= 26:
            w, h_s = struct.unpack_from("<ii", buf, 18)
            if 0 < w <= 65536 and 0 < abs(h_s) <= 65536:
                return int(w), int(abs(h_s))
    # JPEG SOF walk
    if buf[:3] == b"\xff\xd8\xff":
        pos = 2
        while pos < b_len - 4:
            if buf[pos] != 0xFF:
                break
            while pos < b_len and buf[pos] == 0xFF:
                pos += 1
            if pos >= b_len:
                break
            marker = buf[pos]
            pos += 1
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                continue
            if marker in (0xD9, 0xDA):
                break
            if pos + 2 > b_len:
                break
            seg_len = struct.unpack_from(">H", buf, pos)[0]
            if seg_len < 2 or pos + seg_len > b_len:
                break
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                if seg_len >= 7:
                    h, w = struct.unpack_from(">HH", buf, pos + 3)
                    if 0 < w <= 65536 and 0 < h <= 65536:
                        return int(w), int(h)
            pos += seg_len
    # TIFF
    if buf[:4] in (b"II*\x00", b"MM\x00*"):
        ifd0, exif_ifd, _ = _parse_exif_tiff_bytes(buf)
        w = ifd0.get(0x0100) or exif_ifd.get(0xA002) or 0
        h = ifd0.get(0x0101) or exif_ifd.get(0xA003) or 0
        if isinstance(w, int) and isinstance(h, int) and w > 0 and h > 0:
            return w, h
    # WebP
    if b_len >= 30 and buf[:4] == b"RIFF" and buf[8:12] == b"WEBP":
        chunk_hdr = buf[12:16]
        if chunk_hdr == b"VP8X" and b_len >= 30:
            w = 1 + int.from_bytes(buf[24:27], "little")
            h = 1 + int.from_bytes(buf[27:30], "little")
            return w, h
        if chunk_hdr == b"VP8 " and b_len >= 30 and buf[23:26] == b"\x9d\x01\x2a":
            w, h = struct.unpack_from("<HH", buf, 26)
            return w & 0x3FFF, h & 0x3FFF
        if chunk_hdr == b"VP8L" and b_len >= 25 and buf[20] == 0x2F:
            bits = struct.unpack_from("<I", buf, 21)[0]
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    return 0, 0


def _validate_bmp_payload(buf: bytes) -> Optional[Tuple[bytes, str, int, int]]:
    b_len = len(buf)
    if b_len < 26 or buf[:2] != b"BM":
        return None

    bf_size, bf_res1, bf_res2, bf_off_bits = struct.unpack_from("<IHHI", buf, 2)
    bi_size = struct.unpack_from("<I", buf, 14)[0]

    if bf_res1 != 0 or bf_res2 != 0:
        return None
    if bi_size not in (12, 40, 52, 56, 108, 124):
        return None

    min_hdr = 14 + bi_size
    if b_len < min_hdr:
        return None
    if bf_size < min_hdr or bf_size > b_len:
        return None
    if bf_off_bits < min_hdr or bf_off_bits >= bf_size:
        return None

    if bi_size == 12:
        w, h, planes, bpp = struct.unpack_from("<HHHH", buf, 18)
        comp = 0
    else:
        w, h_signed, planes, bpp, comp = struct.unpack_from("<iiHHI", buf, 18)
        if h_signed == -2147483648:
            return None
        h = abs(h_signed)

    if not (1 <= w <= 16384 and 1 <= h <= 16384):
        return None
    if planes != 1 or bpp not in (1, 4, 8, 16, 24, 32):
        return None
    if comp not in (0, 1, 2, 3, 4, 5, 6):
        return None

    if comp in (0, 3, 6):
        row_stride = ((w * bpp + 31) // 32) * 4
        expected_end = bf_off_bits + row_stride * h
        if expected_end > b_len + 4 or bf_size < bf_off_bits + h:
            return None

    return (buf[:bf_size], "bmp", int(w), int(h))


def _validate_jpeg_payload(buf: bytes) -> Optional[Tuple[bytes, str, int, int]]:
    b_len = len(buf)
    if b_len < 32 or buf[:3] != b"\xff\xd8\xff":
        return None
    first_marker = buf[3]
    if not (0xC0 <= first_marker <= 0xFE) or first_marker in (0xD8, 0xD9):
        return None

    pos = 2
    width = 0
    height = 0
    sos_end = -1

    while pos < b_len - 2:
        if buf[pos] != 0xFF:
            return None
        while pos < b_len and buf[pos] == 0xFF:
            pos += 1
        if pos >= b_len:
            return None
        marker = buf[pos]
        pos += 1

        if marker == 0xD9:
            # EOI before SOS -> invalid JPEG
            return None
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            continue
        if pos + 2 > b_len:
            return None
        seg_len = struct.unpack_from(">H", buf, pos)[0]
        if seg_len < 2 or pos + seg_len > b_len:
            return None

        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if seg_len < 7:
                return None
            h_val, w_val = struct.unpack_from(">HH", buf, pos + 3)
            if not (1 <= w_val <= 32768 and 1 <= h_val <= 32768):
                return None
            width, height = int(w_val), int(h_val)

        if marker == 0xDA:  # SOS (Start of Scan)
            sos_end = pos + seg_len
            break

        pos += seg_len

    if sos_end == -1 or width <= 0 or height <= 0:
        return None

    # Walk JPEG entropy-coded scan data skipping 0xFF00 stuffed bytes and RST0..RST7 markers
    scan_pos = sos_end
    eoi_end = -1
    while scan_pos < b_len - 1:
        ff_idx = buf.find(b"\xff", scan_pos)
        if ff_idx == -1 or ff_idx + 1 >= b_len:
            break
        m_pos = ff_idx + 1
        while m_pos < b_len and buf[m_pos] == 0xFF:
            m_pos += 1
        if m_pos >= b_len:
            break
        m_byte = buf[m_pos]
        if m_byte == 0x00 or 0xD0 <= m_byte <= 0xD7:
            scan_pos = m_pos + 1
            continue
        if m_byte == 0xD9:
            eoi_end = m_pos + 1
            break
        # Progressive JPEG may have multiple SOS/DHT/DQT segments before final EOI
        if 0xC0 <= m_byte <= 0xFE:
            if m_pos + 3 <= b_len:
                next_seg_len = struct.unpack_from(">H", buf, m_pos + 1)[0]
                if next_seg_len >= 2 and m_pos + 1 + next_seg_len <= b_len:
                    scan_pos = m_pos + 1 + next_seg_len
                    continue
        scan_pos = m_pos + 1

    if eoi_end == -1:
        return None

    return (buf[:eoi_end], "jpg", width, height)


def _validate_png_payload(buf: bytes) -> Optional[Tuple[bytes, str, int, int]]:
    b_len = len(buf)
    if b_len < 45 or buf[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    if buf[8:16] != b"\x00\x00\x00\rIHDR":
        return None

    w, h, bit_depth, color_type, comp, filt, interlace = struct.unpack_from(">IIBBBBB", buf, 16)
    if not (1 <= w <= 32768 and 1 <= h <= 32768):
        return None
    if bit_depth not in (1, 2, 4, 8, 16) or color_type not in (0, 2, 3, 4, 6):
        return None
    if comp != 0 or filt != 0 or interlace not in (0, 1):
        return None

    expected_crc = struct.unpack_from(">I", buf, 29)[0]
    actual_crc = zlib.crc32(buf[12:29]) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        return None

    pos = 33
    saw_idat = False
    while pos + 12 <= b_len:
        c_len, c_type = struct.unpack_from(">I4s", buf, pos)
        if c_len > 64 * 1024 * 1024 or pos + 12 + c_len > b_len:
            return None
        if not all((65 <= b <= 90) or (97 <= b <= 122) for b in c_type):
            return None
        if c_type == b"IDAT" and c_len > 0:
            saw_idat = True
        elif c_type == b"IEND":
            if c_len != 0 or not saw_idat:
                return None
            if buf[pos + 8 : pos + 12] != b"\xaeB`\x82":
                return None
            return (buf[: pos + 12], "png", int(w), int(h))
        pos += 12 + c_len

    return None


def validate_and_slice_image_payload(buf: bytes) -> Optional[Tuple[bytes, str, int, int]]:
    """
    Strictly validate candidate BMP, JPEG, or PNG image payload.
    Returns (exact_image_bytes, extension, width, height) or None.
    """
    if not buf or len(buf) < 26:
        return None
    if buf[:3] == b"\xff\xd8\xff":
        return _validate_jpeg_payload(buf)
    if buf[:8] == b"\x89PNG\r\n\x1a\n":
        return _validate_png_payload(buf)
    if buf[:2] == b"BM":
        return _validate_bmp_payload(buf)
    return None


def _extract_validated_entry_image(payload: bytes) -> Optional[Tuple[bytes, str, int, int]]:
    """Check payload start or small wrapper prefix (< 64 bytes) for a strictly valid image."""
    direct = validate_and_slice_image_payload(payload)
    if direct is not None:
        return direct
    limit = min(64, len(payload))
    for sig in (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"BM"):
        search_from = 1
        while search_from < limit:
            idx = payload.find(sig, search_from, limit + len(sig))
            if idx == -1 or idx >= limit:
                break
            res = validate_and_slice_image_payload(payload[idx:])
            if res is not None:
                return res
            search_from = idx + 1
    return None


# ---------------------------------------------------------------------------
# Recursive ISO BMFF (MP4 / MOV / M4V / 3GP) Metadata Walker
# ---------------------------------------------------------------------------

_BMFF_CONTAINER_BOXES = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta"}


def _walk_bmff_boxes(fh: BinaryIO, start: int, end: int, meta: Dict[str, Any], depth: int = 0) -> None:
    if depth > 8 or start >= end:
        return
    pos = start
    while pos + 8 <= end:
        fh.seek(pos)
        hdr = fh.read(8)
        if len(hdr) < 8:
            break
        box_size, box_type = struct.unpack(">I4s", hdr)
        header_len = 8
        if box_size == 1:
            ext_hdr = fh.read(8)
            if len(ext_hdr) < 8:
                break
            box_size = struct.unpack(">Q", ext_hdr)[0]
            header_len = 16
        elif box_size == 0:
            box_size = end - pos

        if box_size < header_len or pos + box_size > end:
            break

        payload_start = pos + header_len
        box_end = pos + box_size
        payload_len = box_end - payload_start

        if box_type in _BMFF_CONTAINER_BOXES:
            _walk_bmff_boxes(fh, payload_start, box_end, meta, depth + 1)
        elif box_type == b"mvhd" and payload_len >= 20:
            fh.seek(payload_start)
            buf = fh.read(min(payload_len, 64))
            version = buf[0]
            c_time = 0
            m_time = 0
            timescale = 0
            duration = 0
            if version == 0 and len(buf) >= 20:
                c_time, m_time, timescale, duration = struct.unpack_from(">IIII", buf, 4)
                max_dur = 0xFFFFFFFF
            elif version == 1 and len(buf) >= 32:
                c_time, m_time, timescale, duration = struct.unpack_from(">QQIQ", buf, 4)
                max_dur = 0xFFFFFFFFFFFFFFFF
            else:
                max_dur = 0

            # Only convert 1904-epoch timestamps when genuinely set (> 1970); NEVER fabricate 1904-01-01 when 0!
            if c_time > _MAC_EPOCH_DELTA:
                epoch_sec = c_time - _MAC_EPOCH_DELTA
                if 315532800 <= epoch_sec <= 4102444800:
                    meta["creation_time"] = datetime.fromtimestamp(
                        epoch_sec, tz=timezone.utc
                    ).replace(tzinfo=None)
            if m_time > _MAC_EPOCH_DELTA:
                m_epoch = m_time - _MAC_EPOCH_DELTA
                if 315532800 <= m_epoch <= 4102444800:
                    meta["modification_time"] = datetime.fromtimestamp(
                        m_epoch, tz=timezone.utc
                    ).replace(tzinfo=None)

            if timescale > 0 and 0 < duration < max_dur:
                meta["duration_seconds"] = round(float(duration) / float(timescale), 3)

        elif box_type == b"tkhd" and payload_len >= 84:
            fh.seek(payload_start)
            buf = fh.read(min(payload_len, 104))
            version = buf[0]
            w_fixed = 0
            h_fixed = 0
            if version == 0 and len(buf) >= 84:
                w_fixed, h_fixed = struct.unpack_from(">II", buf, 76)
            elif version == 1 and len(buf) >= 96:
                w_fixed, h_fixed = struct.unpack_from(">II", buf, 88)
            w_px = int(w_fixed >> 16)
            h_px = int(h_fixed >> 16)
            if 0 < w_px <= 32768 and 0 < h_px <= 32768:
                if (w_px * h_px) > (meta["width"] * meta["height"]):
                    meta["width"] = w_px
                    meta["height"] = h_px

        pos = box_end


def parse_mp4_mov_metadata(file_path: Path) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "width": 0,
        "height": 0,
        "duration_seconds": None,
        "creation_time": None,
        "modification_time": None,
        "camera_make": None,
        "camera_model": None,
        "software": None,
    }

    try:
        file_size = os.path.getsize(file_path)
        if file_size >= 8:
            with open(file_path, "rb") as fh:
                _walk_bmff_boxes(fh, 0, file_size, meta, depth=0)
    except Exception:
        pass

    # Optional cv2 fallback ONLY when ISO BMFF did not yield dimensions or duration
    if cv2 is not None and (meta["width"] == 0 or meta["duration_seconds"] is None):
        try:
            cap = cv2.VideoCapture(str(file_path))
            if cap.isOpened():
                if meta["width"] == 0:
                    w_cv = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
                    h_cv = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
                    if 0 < w_cv <= 32768 and 0 < h_cv <= 32768:
                        meta["width"] = w_cv
                        meta["height"] = h_cv
                if meta["duration_seconds"] is None:
                    fps = float(cap.get(cv2.CAP_PROP_FPS) or 0.0)
                    frame_count = float(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0.0)
                    if fps > 0.0 and frame_count > 0.0:
                        meta["duration_seconds"] = round(frame_count / fps, 3)
            cap.release()
        except Exception:
            pass

    return meta


class MediaParser(BaseParser):
    """
    Forensic parser for multimedia files (Images, Videos, Windows Thumbcache).
    Populates:
      - parsed_media_exif
      - parsed_media_pictures
      - parsed_media_videos
      - parsed_thumbcache
    """

    IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".heic"}
    VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".3gp", ".3g2", ".avi", ".mkv", ".wmv"}

    def __init__(
        self,
        case_id: str,
        staging_dir: Optional[Path] = None,
        source_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(case_id, staging_dir, source_type=source_type, **kwargs)  # type: ignore[call-arg]
        except TypeError:
            super().__init__(case_id, staging_dir)
        if not getattr(self, "source_type", None) and source_type:
            self.source_type = source_type
        self.carved_thumbnails_dir = self.staging_dir / "Carved_Thumbnails"
        self.carved_thumbnails_dir.mkdir(parents=True, exist_ok=True)
        self._parse_init_ts = time.time()
        self._vfs_rel_cache: Optional[Dict[str, Optional[datetime]]] = None
        self._vfs_path_cache: Optional[Dict[str, Optional[datetime]]] = None
        self._cached_eff_source_type: Optional[str] = None

    def _preload_vfs_time_cache(self) -> None:
        rel_map: Dict[str, Optional[datetime]] = {}
        vp_map: Dict[str, Optional[datetime]] = {}
        eff_src = (getattr(self, "source_type", None) or "").strip().lower()
        try:
            with DuckDBManager.get_lock(self.case_id):
                cur = self._get_conn().cursor()
                tables = {
                    str(r[0])
                    for r in cur.execute(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                    ).fetchall()
                }
                if not eff_src and "case_metadata" in tables:
                    m_row = cur.execute(
                        "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                    ).fetchone()
                    if m_row and m_row[0]:
                        eff_src = str(m_row[0]).strip().lower()
                if "vfs_files" in tables:
                    vfs_cols = {
                        str(r[0]).lower(): str(r[0])
                        for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                    }
                    mod_exprs = [
                        self._quote_ident(vfs_cols[c])
                        for c in ("si_modified", "si_modified_utc", "fn_modified", "fn_modified_utc")
                        if c in vfs_cols
                    ]
                    srp_sql = (
                        f"LOWER(TRIM(BOTH '/' FROM REPLACE(COALESCE({self._quote_ident(vfs_cols['staged_rel_path'])}, ''), chr(92), '/')))"
                        if "staged_rel_path" in vfs_cols
                        else "''"
                    )
                    vp_sql = (
                        f"LOWER(REPLACE(COALESCE({self._quote_ident(vfs_cols['vfs_path'])}, ''), '/', chr(92)))"
                        if "vfs_path" in vfs_cols
                        else "''"
                    )
                    mod_sql = f"COALESCE({', '.join(mod_exprs)})" if mod_exprs else "NULL"
                    for srp_k, vp_k, m_raw in cur.execute(
                        f'SELECT {srp_sql}, {vp_sql}, {mod_sql} FROM "vfs_files";'
                    ).fetchall():
                        m_dt: Optional[datetime] = None
                        if isinstance(m_raw, datetime):
                            m_dt = _to_naive_utc(m_raw)
                        elif m_raw is not None:
                            try:
                                m_dt = _to_naive_utc(
                                    datetime.fromisoformat(str(m_raw).strip().replace("Z", "+00:00"))
                                )
                            except ValueError:
                                m_dt = None
                        if srp_k and srp_k not in rel_map:
                            rel_map[srp_k] = m_dt
                        if vp_k and vp_k not in vp_map:
                            vp_map[vp_k] = m_dt
        except Exception:
            return
        self._vfs_rel_cache = rel_map
        self._vfs_path_cache = vp_map
        self._cached_eff_source_type = eff_src

    @staticmethod
    def _quote_ident(ident: str) -> str:
        escaped = ident.replace('"', '""')
        return f'"{escaped}"'

    def _local_vfs_lookup_candidates(self, p: Path) -> Tuple[List[str], List[str]]:
        base_builder = getattr(self, "_build_vfs_lookup_candidates", None)
        if callable(base_builder):
            try:
                rel_c, vfs_c = base_builder(p)
                if rel_c or vfs_c:
                    return list(rel_c), list(vfs_c)
            except Exception:
                pass
        rel_cands: List[str] = []
        try:
            rel_posix = p.resolve().relative_to(self.staging_dir.resolve()).as_posix().strip("/").lower()
            if rel_posix:
                rel_cands.append(rel_posix)
                rel_cands.append(f"staging/{rel_posix}")
        except Exception:
            pass
        return rel_cands, []

    def _get_original_mtime_dt(self, file_path: Union[str, Path]) -> Optional[datetime]:
        """
        Resolve original forensic file modification time as naive UTC datetime querying
        vfs_files modification columns ONLY (NEVER si_created, fn_created, or host file creation metadata).
        """
        p = Path(file_path)
        rel_candidates, vfs_cands = self._local_vfs_lookup_candidates(p)
        effective_source_type = (getattr(self, "source_type", None) or "").strip().lower()

        if self._vfs_rel_cache is not None and self._vfs_path_cache is not None:
            if not effective_source_type and self._cached_eff_source_type:
                effective_source_type = self._cached_eff_source_type
            for rc in rel_candidates:
                if rc in self._vfs_rel_cache:
                    return self._vfs_rel_cache[rc]
            for vc in vfs_cands:
                if vc in self._vfs_path_cache:
                    return self._vfs_path_cache[vc]
        else:
            try:
                with DuckDBManager.get_lock(self.case_id):
                    cur = self._get_conn().cursor()
                    tables = {
                        str(r[0])
                        for r in cur.execute(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main';"
                        ).fetchall()
                    }
                    if not effective_source_type and "case_metadata" in tables:
                        m_row = cur.execute(
                            "SELECT value FROM case_metadata WHERE LOWER(key) = 'source_type' LIMIT 1;"
                        ).fetchone()
                        if m_row and m_row[0]:
                            effective_source_type = str(m_row[0]).strip().lower()

                    if "vfs_files" in tables:
                        vfs_cols = {
                            str(r[0]).lower(): str(r[0])
                            for r in cur.execute('DESCRIBE "vfs_files";').fetchall()
                        }
                        mod_exprs = [
                            self._quote_ident(vfs_cols[c])
                            for c in ("si_modified", "si_modified_utc", "fn_modified", "fn_modified_utc")
                            if c in vfs_cols
                        ]
                        where_clauses: List[str] = []
                        params: List[Any] = []
                        if rel_candidates and "staged_rel_path" in vfs_cols:
                            q_srp = self._quote_ident(vfs_cols["staged_rel_path"])
                            ph = ", ".join(["?"] * len(rel_candidates))
                            where_clauses.append(
                                f"LOWER(TRIM(BOTH '/' FROM REPLACE(COALESCE({q_srp}, ''), chr(92), '/'))) IN ({ph})"
                            )
                            params.extend(rel_candidates)
                        if vfs_cands and "vfs_path" in vfs_cols:
                            q_vp = self._quote_ident(vfs_cols["vfs_path"])
                            ph_v = ", ".join(["?"] * len(vfs_cands))
                            where_clauses.append(
                                f"LOWER(REPLACE(COALESCE({q_vp}, ''), '/', chr(92))) IN ({ph_v})"
                            )
                            params.extend(vfs_cands)

                        if where_clauses:
                            mod_sql = f"COALESCE({', '.join(mod_exprs)})" if mod_exprs else "NULL"
                            where_sql = " OR ".join(where_clauses)
                            row = cur.execute(
                                f'SELECT 1, {mod_sql} FROM "vfs_files" WHERE {where_sql} LIMIT 1;',
                                params,
                            ).fetchone()
                            if row is not None:
                                val = row[1]
                                if val is None:
                                    return None
                                if isinstance(val, datetime):
                                    return _to_naive_utc(val)
                                try:
                                    dt_v = datetime.fromisoformat(str(val).strip().replace("Z", "+00:00"))
                                    return _to_naive_utc(dt_v)
                                except ValueError:
                                    return None
            except Exception:
                pass

        if effective_source_type in ("image", "disk_image", "e01", "raw", "vhd", "vhdx", "vmdk"):
            return None

        try:
            st_mtime = float(p.stat().st_mtime)
            if st_mtime <= 0 or st_mtime >= (self._parse_init_ts - 120.0):
                return None
            return datetime.fromtimestamp(st_mtime, tz=timezone.utc).replace(tzinfo=None)
        except OSError:
            return None

    @staticmethod
    def _write_carved_bytes(out_path: Path, data: bytes) -> Path:
        """Write carved image bytes ensuring `out_path` on disk 100% matches `data` (zero hash collision)."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        target = out_path
        if target.exists():
            try:
                if target.read_bytes() == data:
                    return target
            except OSError:
                pass
            digest = compute_sha256(data)
            target = out_path.parent / f"{out_path.stem}_{digest[:16]}{out_path.suffix}"
            if target.exists():
                try:
                    if target.read_bytes() == data:
                        return target
                except OSError:
                    pass
        target.write_bytes(data)
        return target

    def _parse_image_exif(self, file_path: Path) -> Dict[str, Any]:
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = file_path.suffix.lstrip(".").upper()
        evidence_path = self.resolve_evidence_path(file_path, file_size)

        rec: Dict[str, Any] = {
            "file_path": evidence_path,
            "file_name": file_path.name,
            "file_type": ext,
            "file_size_bytes": file_size,
            "sha256": sha256,
            "camera_make": None,
            "camera_model": None,
            "datetime_original": None,
            "software": None,
            "gps_coordinates": None,
            "gps_position": None,
            "latitude": None,
            "longitude": None,
            "image_width": 0,
            "image_height": 0,
            "width": 0,
            "height": 0,
            "duration_seconds": None,
            "raw_metadata": "{}",
            "source_file": evidence_path,
        }

        ifd0_tags: Dict[int, Any] = {}
        exif_ifd_tags: Dict[int, Any] = {}
        gps_ifd_tags: Dict[int, Any] = {}
        raw_tags: Dict[str, Any] = {}

        # Stage 1: Pillow Image & EXIF extraction when Pillow is available
        if Image is not None:
            try:
                with Image.open(file_path) as img:
                    rec["width"] = int(img.width)
                    rec["image_width"] = int(img.width)
                    rec["height"] = int(img.height)
                    rec["image_height"] = int(img.height)

                    exif = img.getexif()
                    if exif:
                        for tag_id, val in exif.items():
                            if isinstance(tag_id, int):
                                ifd0_tags[tag_id] = val
                        try:
                            exif_ifd_id = ExifTags.IFD.Exif if (ExifTags is not None and hasattr(ExifTags, "IFD")) else 0x8769
                            sub_exif = exif.get_ifd(exif_ifd_id)
                            if sub_exif:
                                for tag_id, val in sub_exif.items():
                                    if isinstance(tag_id, int):
                                        exif_ifd_tags[tag_id] = val
                        except Exception:
                            pass

                        try:
                            gps_ifd_id = ExifTags.IFD.GPSInfo if (ExifTags is not None and hasattr(ExifTags, "IFD")) else 0x8825
                            sub_gps = exif.get_ifd(gps_ifd_id)
                            if sub_gps:
                                for tag_id, val in sub_gps.items():
                                    if isinstance(tag_id, int):
                                        gps_ifd_tags[tag_id] = val
                        except Exception:
                            pass
            except Exception as ex:
                raw_tags["pil_warning"] = str(ex)[:200]

        # Stage 2: Pure-Python TIFF/JPEG-APP1/PNG-eXIf & header dimension fallback
        if rec["image_width"] == 0 or (not ifd0_tags and not exif_ifd_tags and not gps_ifd_tags):
            try:
                with open(file_path, "rb") as fh:
                    head_bytes = fh.read(min(file_size, 2 * 1024 * 1024))
                if rec["image_width"] == 0 or rec["image_height"] == 0:
                    w_p, h_p = _probe_image_dimensions_pure(head_bytes)
                    if w_p > 0 and h_p > 0:
                        rec["width"] = w_p
                        rec["image_width"] = w_p
                        rec["height"] = h_p
                        rec["image_height"] = h_p
                tiff_blob = _extract_exif_tiff_from_image_bytes(head_bytes)
                if tiff_blob is not None:
                    fb_ifd0, fb_exif, fb_gps = _parse_exif_tiff_bytes(tiff_blob)
                    for k, v in fb_ifd0.items():
                        ifd0_tags.setdefault(k, v)
                    for k, v in fb_exif.items():
                        exif_ifd_tags.setdefault(k, v)
                    for k, v in fb_gps.items():
                        gps_ifd_tags.setdefault(k, v)
            except Exception as ex:
                raw_tags.setdefault("fallback_warning", str(ex)[:200])

        tag_map = ExifTags.TAGS if ExifTags is not None else _FALLBACK_EXIF_TAGS
        gps_tag_map = ExifTags.GPSTAGS if ExifTags is not None else _FALLBACK_GPS_TAGS

        for tag_id, val in ifd0_tags.items():
            t_name = tag_map.get(tag_id, _FALLBACK_EXIF_TAGS.get(tag_id, str(tag_id)))
            raw_tags[t_name] = _clean_exif_str(val)[:200] if isinstance(val, (str, bytes, bytearray)) else str(val)[:200]

        for tag_id, val in exif_ifd_tags.items():
            t_name = tag_map.get(tag_id, _FALLBACK_EXIF_TAGS.get(tag_id, str(tag_id)))
            raw_tags[t_name] = _clean_exif_str(val)[:200] if isinstance(val, (str, bytes, bytearray)) else str(val)[:200]

        make_val = _clean_exif_str(ifd0_tags.get(0x010F) or exif_ifd_tags.get(0x010F))
        model_val = _clean_exif_str(ifd0_tags.get(0x0110) or exif_ifd_tags.get(0x0110))
        soft_val = _clean_exif_str(ifd0_tags.get(0x0131) or exif_ifd_tags.get(0x0131))

        rec["camera_make"] = make_val or None
        rec["camera_model"] = model_val or None
        rec["software"] = soft_val or None

        # Strict EXIF Timestamp Resolution (DateTimeOriginal -> DateTimeDigitized -> IFD0 DateTime)
        dt_orig_raw = exif_ifd_tags.get(0x9003) or ifd0_tags.get(0x9003)
        dt_digi_raw = exif_ifd_tags.get(0x9004) or ifd0_tags.get(0x9004)
        dt_mod_raw = ifd0_tags.get(0x0132) or exif_ifd_tags.get(0x0132)

        off_orig = (
            exif_ifd_tags.get(0x9011)
            or ifd0_tags.get(0x9011)
            or exif_ifd_tags.get(0x9010)
            or ifd0_tags.get(0x9010)
            or exif_ifd_tags.get(0x882A)
            or ifd0_tags.get(0x882A)
        )
        off_digi = (
            exif_ifd_tags.get(0x9012)
            or ifd0_tags.get(0x9012)
            or exif_ifd_tags.get(0x9010)
            or ifd0_tags.get(0x9010)
            or exif_ifd_tags.get(0x882A)
            or ifd0_tags.get(0x882A)
        )
        off_mod = (
            exif_ifd_tags.get(0x9010)
            or ifd0_tags.get(0x9010)
            or exif_ifd_tags.get(0x882A)
            or ifd0_tags.get(0x882A)
        )

        resolved_dt: Optional[datetime] = None
        if dt_orig_raw is not None:
            resolved_dt = parse_exif_timestamp(dt_orig_raw, off_orig, exif_ifd_tags.get(0x9291))
        if resolved_dt is None and dt_digi_raw is not None:
            resolved_dt = parse_exif_timestamp(dt_digi_raw, off_digi, exif_ifd_tags.get(0x9292))
        if resolved_dt is None and dt_mod_raw is not None:
            resolved_dt = parse_exif_timestamp(
                dt_mod_raw,
                off_mod,
                exif_ifd_tags.get(0x9290) or ifd0_tags.get(0x9290),
            )
        rec["datetime_original"] = resolved_dt

        # GPS Extraction
        if gps_ifd_tags:
            gps_named: Dict[str, Any] = {}
            for g_id, g_val in gps_ifd_tags.items():
                g_name = gps_tag_map.get(g_id, _FALLBACK_GPS_TAGS.get(g_id, str(g_id)))
                gps_named[g_name] = g_val
                raw_tags[f"GPS_{g_name}"] = (
                    _clean_exif_str(g_val)[:200]
                    if isinstance(g_val, (str, bytes, bytearray))
                    else str(g_val)[:200]
                )

            lat_ref = gps_named.get("GPSLatitudeRef")
            lon_ref = gps_named.get("GPSLongitudeRef")
            lat_dec = dms_to_decimal(gps_named.get("GPSLatitude"), lat_ref, is_lon=False)
            lon_dec = dms_to_decimal(gps_named.get("GPSLongitude"), lon_ref, is_lon=True)

            if (
                lat_dec == 0.0
                and lon_dec == 0.0
                and not _clean_exif_str(lat_ref)
                and not _clean_exif_str(lon_ref)
            ):
                lat_dec = None
                lon_dec = None

            if lat_dec is not None and lon_dec is not None:
                coord_str = f"{lat_dec:.6f}, {lon_dec:.6f}"
                rec["gps_coordinates"] = coord_str
                rec["gps_position"] = coord_str
                rec["latitude"] = lat_dec
                rec["longitude"] = lon_dec

        rec["raw_metadata"] = json.dumps(raw_tags, ensure_ascii=False)
        return rec

    def _parse_video_file(self, file_path: Path) -> Dict[str, Any]:
        file_size = os.path.getsize(file_path)
        sha256 = compute_sha256(file_path)
        ext = file_path.suffix.lstrip(".").upper()
        evidence_path = self.resolve_evidence_path(file_path, file_size)
        meta = parse_mp4_mov_metadata(file_path)

        creation_dt = _to_naive_utc(meta.get("creation_time"))
        width = int(meta.get("width") or 0)
        height = int(meta.get("height") or 0)
        duration_sec = meta.get("duration_seconds")

        return {
            "file_path": evidence_path,
            "file_name": file_path.name,
            "file_type": ext,
            "file_size_bytes": file_size,
            "sha256": sha256,
            "camera_make": meta.get("camera_make"),
            "camera_model": meta.get("camera_model"),
            "datetime_original": creation_dt,
            "software": meta.get("software"),
            "gps_coordinates": None,
            "gps_position": None,
            "latitude": None,
            "longitude": None,
            "image_width": width,
            "image_height": height,
            "width": width,
            "height": height,
            "duration_seconds": duration_sec,
            "raw_metadata": json.dumps(
                {
                    "width": width,
                    "height": height,
                    "duration_seconds": duration_sec,
                    "creation_time": creation_dt.strftime("%Y-%m-%d %H:%M:%S") if creation_dt else None,
                },
                ensure_ascii=False,
            ),
            "source_file": evidence_path,
        }

    def _carve_headers_from_bytes(
        self,
        raw_bytes: bytes,
        cache_name: str,
        source_file: Path,
    ) -> List[Dict[str, Any]]:
        """Strict header + structural carving fallback for non-CMMM cache containers."""
        results: List[Dict[str, Any]] = []
        buf_len = len(raw_bytes)
        evidence_source = self.resolve_evidence_path(source_file)
        seen_hashes = set()

        for sig in (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"BM"):
            idx = 0
            while idx < buf_len - 26:
                start = raw_bytes.find(sig, idx)
                if start == -1:
                    break
                max_slice = raw_bytes[start : min(buf_len, start + 10 * 1024 * 1024)]
                validated = validate_and_slice_image_payload(max_slice)
                if validated is None:
                    idx = start + 2
                    continue

                img_data, ext, w, h = validated
                img_hash = compute_sha256(img_data)
                if img_hash not in seen_hashes:
                    seen_hashes.add(img_hash)
                    carved_name = f"{cache_name}_carved_{ext}_{start}_{img_hash[:8]}.{ext}"
                    out_path = self.carved_thumbnails_dir / carved_name
                    self._write_carved_bytes(out_path, img_data)

                    results.append({
                        "cache_name": cache_name,
                        "cache_file": cache_name,
                        "entry_id": start,
                        "entry_hash": f"offset_0x{start:x}",
                        "file_extension": ext,
                        "extension": ext,
                        "image_dimensions": f"{w}x{h}",
                        "image_size_bytes": len(img_data),
                        "sha256": img_hash,
                        "carved_path": str(out_path),
                        "carved_file_path": str(out_path),
                        "cache_type": "THUMBCACHE_CARVED",
                        "source_type": "THUMBCACHE_CARVED",
                        "carved_at": None,
                        "timestamp_utc": None,
                        "source_file": evidence_source,
                    })
                idx = start + max(len(img_data), 2)

        return results

    def _parse_cmmm_entries_pure(
        self,
        raw_bytes: bytes,
        db_path: Path,
        evidence_source: str,
    ) -> List[Dict[str, Any]]:
        """
        Pure-Python Windows CMMM thumbcache walker supporting Vista (0x14), Win7 (0x15),
        Win8 (0x1A..0x1E), Win8.1 (0x1F), Win10 (0x20), and Win11 (0x26+), handling header
        offsets and empty/zeroed cache slots without aborting.
        """
        records: List[Dict[str, Any]] = []
        b_len = len(raw_bytes)
        if b_len < 24 or raw_bytes[:4] != b"CMMM":
            return records

        version, _cache_type, f3, f4, _entry_count = struct.unpack_from("<5I", raw_bytes, 4)
        first_offset = f3 if version <= 0x15 else f4
        if first_offset < 24 or first_offset >= b_len or raw_bytes[first_offset : first_offset + 4] != b"CMMM":
            found = raw_bytes.find(b"CMMM", 24)
            if found == -1:
                return records
            first_offset = found

        cache_name = db_path.name
        pos = first_offset
        entry_seq = 0

        while 24 <= pos <= b_len - 48:
            if raw_bytes[pos : pos + 4] != b"CMMM":
                nxt = raw_bytes.find(b"CMMM", pos + 1)
                if nxt == -1:
                    break
                pos = nxt
                continue

            if version == 0x14:
                if pos + 56 > b_len:
                    break
                entry_size, entry_hash, _ext_w, id_len, pad_len, data_len, _unk = struct.unpack_from(
                    "<IQ8sIIII", raw_bytes, pos + 4
                )
                hdr_len = 56
            elif version == 0x15:
                if pos + 48 > b_len:
                    break
                entry_size, entry_hash, id_len, pad_len, data_len, _unk = struct.unpack_from(
                    "<IQIIII", raw_bytes, pos + 4
                )
                hdr_len = 48
            else:
                if pos + 56 > b_len:
                    break
                entry_size, entry_hash, id_len, pad_len, data_len, _w_h, _h_h, _unk = struct.unpack_from(
                    "<IQIIIIII", raw_bytes, pos + 4
                )
                hdr_len = 56

            if entry_size < hdr_len or pos + entry_size > b_len:
                pos += 4
                continue
            if hdr_len + id_len + pad_len + data_len > entry_size:
                pos += 4
                continue

            entry_seq += 1
            if data_len > 0:
                data_start = pos + hdr_len + id_len + pad_len
                payload = raw_bytes[data_start : data_start + data_len]
                validated = _extract_validated_entry_image(payload)
                if validated is not None:
                    img_bytes, ext, w, h = validated
                    entry_hash_hex = f"{entry_hash:016x}"
                    img_hash = compute_sha256(img_bytes)
                    carved_name = f"{db_path.stem}_{entry_hash_hex}_{entry_seq}_{img_hash[:12]}.{ext}"
                    out_path = self._write_carved_bytes(self.carved_thumbnails_dir / carved_name, img_bytes)

                    records.append({
                        "cache_name": cache_name,
                        "cache_file": cache_name,
                        "entry_id": entry_seq,
                        "entry_hash": entry_hash_hex,
                        "file_extension": ext,
                        "extension": ext,
                        "image_dimensions": f"{w}x{h}",
                        "image_size_bytes": len(img_bytes),
                        "sha256": img_hash,
                        "carved_path": str(out_path),
                        "carved_file_path": str(out_path),
                        "cache_type": "THUMBCACHE",
                        "source_type": "THUMBCACHE",
                        "carved_at": None,
                        "timestamp_utc": None,
                        "source_file": evidence_source,
                    })

            pos += entry_size

        return records

    def _parse_thumbcache_db(self, db_path: Path) -> List[Dict[str, Any]]:
        raw_bytes = db_path.read_bytes()
        if not raw_bytes:
            return []

        cache_name = db_path.name
        evidence_source = self.resolve_evidence_path(db_path, len(raw_bytes))
        is_cmmm = len(raw_bytes) >= 24 and raw_bytes[:4] == b"CMMM"

        records: List[Dict[str, Any]] = []
        seen_keys = set()

        # Stage 1: Pure-Python CMMM structural walker
        if is_cmmm:
            cmmm_recs = self._parse_cmmm_entries_pure(raw_bytes, db_path, evidence_source)
            for rec in cmmm_recs:
                seen_keys.add((rec["entry_hash"], rec["sha256"]))
                records.append(rec)

        # Stage 2: Optional dissect.thumbcache fallback when Stage 1 yields 0 entries (strictly validated)
        if ThumbcacheFile is not None and is_cmmm and not records:
            try:
                with open(db_path, "rb") as fh:
                    tc = ThumbcacheFile(fh)
                    it = iter(tc.entries())
                    dissect_seq = len(records)
                    while True:
                        try:
                            entry = next(it)
                        except StopIteration:
                            break
                        except Exception:
                            break

                        try:
                            data = entry.data
                            if not data:
                                continue
                            validated = _extract_validated_entry_image(data)
                            if validated is None:
                                continue
                            img_bytes, ext, w, h = validated
                            entry_hash_raw = (
                                getattr(entry, "cache_entry_hash", None)
                                or getattr(entry, "hash", 0)
                            )
                            entry_hash_hex = (
                                f"{entry_hash_raw:016x}"
                                if isinstance(entry_hash_raw, int)
                                else str(entry_hash_raw)
                            )
                            img_hash = compute_sha256(img_bytes)
                            if (entry_hash_hex, img_hash) in seen_keys:
                                continue
                            seen_keys.add((entry_hash_hex, img_hash))
                            dissect_seq += 1
                            carved_name = f"{db_path.stem}_{entry_hash_hex}_{dissect_seq}_{img_hash[:12]}.{ext}"
                            out_path = self._write_carved_bytes(self.carved_thumbnails_dir / carved_name, img_bytes)

                            records.append({
                                "cache_name": cache_name,
                                "cache_file": cache_name,
                                "entry_id": dissect_seq,
                                "entry_hash": entry_hash_hex,
                                "file_extension": ext,
                                "extension": ext,
                                "image_dimensions": f"{w}x{h}",
                                "image_size_bytes": len(img_bytes),
                                "sha256": img_hash,
                                "carved_path": str(out_path),
                                "carved_file_path": str(out_path),
                                "cache_type": "THUMBCACHE",
                                "source_type": "THUMBCACHE",
                                "carved_at": None,
                                "timestamp_utc": None,
                                "source_file": evidence_source,
                            })
                        except Exception:
                            continue
            except Exception:
                pass

        # Stage 3: Strict raw header carving ONLY when file is not a CMMM container
        if not is_cmmm:
            try:
                records.extend(self._carve_headers_from_bytes(raw_bytes, cache_name, db_path))
            except Exception as carve_ex:
                self._log(f"Carving failed on {db_path.name}: {carve_ex}", "WARNING")

        return records

    def _parse_snipping_tool_screenshots(self, candidate_media: Optional[List[Path]] = None) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        seen_hashes = set()
        seq = 0

        staging_resolved = self.staging_dir.resolve()
        iter_paths = (
            candidate_media
            if candidate_media is not None
            else sorted(self.staging_dir.rglob("*"), key=lambda item: str(item))
        )
        for p in iter_paths:
            if candidate_media is None and not p.is_file():
                continue
            try:
                path_lower = p.relative_to(staging_resolved).as_posix().lower()
            except Exception:
                try:
                    path_lower = p.resolve().relative_to(staging_resolved).as_posix().lower()
                except Exception:
                    path_lower = p.name.lower()
            if "carved_thumbnails" in path_lower:
                continue
            if not any(k in path_lower for k in ("screensketch", "snippingtool", "screenshots")):
                continue
            if p.suffix.lower() not in self.IMAGE_EXTS:
                continue

            try:
                raw_bytes = p.read_bytes()
                if not raw_bytes:
                    continue
                file_size = len(raw_bytes)
                sha256 = compute_sha256(raw_bytes)
                if sha256 in seen_hashes:
                    continue
                seen_hashes.add(sha256)

                ext = p.suffix.lstrip(".").lower()
                mtime = self._get_original_mtime_dt(p)
                evidence_source = self.resolve_evidence_path(p, file_size)

                w, h = 0, 0
                if Image is not None:
                    try:
                        with Image.open(p) as img:
                            w, h = int(img.width), int(img.height)
                    except Exception:
                        w, h = 0, 0
                if w == 0 or h == 0:
                    w, h = _probe_image_dimensions_pure(raw_bytes)
                dims_str = f"{w}x{h}" if (w > 0 and h > 0) else ""

                src_label = "SCREENSKETCH" if "screensketch" in path_lower else "SNIPPING_TOOL"
                dest_name = f"{src_label.lower()}_{p.stem}_{sha256[:8]}.{ext}"
                out_path = self.carved_thumbnails_dir / dest_name
                self._write_carved_bytes(out_path, raw_bytes)

                seq += 1
                records.append({
                    "cache_name": p.parent.name,
                    "cache_file": p.parent.name,
                    "entry_id": seq,
                    "entry_hash": sha256[:16],
                    "file_extension": ext,
                    "extension": ext,
                    "image_dimensions": dims_str,
                    "image_size_bytes": file_size,
                    "sha256": sha256,
                    "carved_path": str(out_path),
                    "carved_file_path": str(out_path),
                    "cache_type": src_label,
                    "source_type": src_label,
                    "carved_at": mtime,
                    "timestamp_utc": mtime,
                    "source_file": evidence_source,
                })
            except Exception:
                continue

        return records

    def parse(self, max_workers: int = 16) -> Dict[str, int]:
        start_time = time.time()
        workers = max(1, min(32, int(max_workers or 16)))
        self._log(f"Starting MediaParser across staging directory: {self.staging_dir} (workers={workers})")

        self._preload_vfs_time_cache()
        self._get_vfs_staged_cache()
        self._get_mft_index_cache()

        exif_records: List[Dict[str, Any]] = []
        picture_records: List[Dict[str, Any]] = []
        video_records: List[Dict[str, Any]] = []
        thumb_records: List[Dict[str, Any]] = []

        candidate_media: List[Path] = []
        candidate_thumbcache: List[Path] = []

        _SKIP_MEDIA_ROOTS = {
            "registry", "logs", "prefetch", "filesystem", "mft", "srum",
            "jumplists", "tasks", "powershell", "rmm", "carved_thumbnails", "zoneidentifier",
        }
        if self.staging_dir.exists():
            staging_res = self.staging_dir.resolve()
            for walk_root, dirs, files in os.walk(staging_res):
                root_p = Path(walk_root)
                if root_p == staging_res:
                    dirs[:] = [d for d in dirs if d.lower() not in _SKIP_MEDIA_ROOTS]
                else:
                    dirs[:] = [d for d in dirs if d.lower() != "carved_thumbnails"]
                for fname in files:
                    p = root_p / fname
                    name_lower = fname.lower()
                    sfx = p.suffix.lower()
                    if sfx in self.IMAGE_EXTS or sfx in self.VIDEO_EXTS:
                        candidate_media.append(p)
                    elif ("thumbcache_" in name_lower or "iconcache_" in name_lower) and sfx in (".db", ".db2", ""):
                        candidate_thumbcache.append(p)

        candidate_media = sorted(
            candidate_media,
            key=lambda item: (1 if "enrichment" in item.as_posix().lower() else 0, str(item)),
        )
        candidate_thumbcache = sorted(candidate_thumbcache, key=lambda item: str(item))

        def _parse_single_media(mf: Path) -> Optional[Tuple[str, str, str, Dict[str, Any]]]:
            try:
                if "carved_thumbnails" in mf.as_posix().lower() or mf.stat().st_size == 0:
                    return None
                mf_hash = compute_sha256(mf)
                if mf.suffix.lower() in self.IMAGE_EXTS:
                    rec = self._parse_image_exif(mf)
                    return ("image", mf.name.lower(), mf_hash, rec)
                rec = self._parse_video_file(mf)
                return ("video", mf.name.lower(), mf_hash, rec)
            except Exception as ex:
                self._log(f"Failed parsing media {mf}: {ex}", "WARNING")
                return None

        if workers > 1 and len(candidate_media) > 2:
            with ThreadPoolExecutor(max_workers=min(workers, len(candidate_media))) as pool:
                media_results = list(pool.map(_parse_single_media, candidate_media))
        else:
            media_results = [_parse_single_media(mf) for mf in candidate_media]

        seen_media_hashes = set()
        for res_item in media_results:
            if res_item is None:
                continue
            kind, name_low, mf_hash, rec = res_item
            dedup_key = (name_low, mf_hash)
            if dedup_key in seen_media_hashes:
                continue
            seen_media_hashes.add(dedup_key)

            exif_rec = {k: v for k, v in rec.items() if k not in ("width", "height")}
            exif_records.append(exif_rec)
            if kind == "image":
                picture_records.append(
                    {k: v for k, v in rec.items() if k not in ("width", "height", "duration_seconds")}
                )
            else:
                video_records.append({
                    "file_path": rec["file_path"],
                    "file_name": rec["file_name"],
                    "file_type": rec["file_type"],
                    "file_size_bytes": rec["file_size_bytes"],
                    "sha256": rec["sha256"],
                    "datetime_original": rec["datetime_original"],
                    "duration_seconds": rec["duration_seconds"],
                    "width": rec["width"],
                    "height": rec["height"],
                    "raw_metadata": rec["raw_metadata"],
                    "source_file": rec["source_file"],
                })

        seen_thumbcache_dbs = set()
        for tcf in candidate_thumbcache:
            try:
                tcf_hash = compute_sha256(tcf)
                if (tcf.name.lower(), tcf_hash) in seen_thumbcache_dbs:
                    continue
                seen_thumbcache_dbs.add((tcf.name.lower(), tcf_hash))
                thumb_records.extend(self._parse_thumbcache_db(tcf))
            except Exception as ex:
                self._log(f"Failed parsing thumbcache {tcf}: {ex}", "WARNING")

        thumb_records.extend(self._parse_snipping_tool_screenshots(candidate_media=candidate_media))

        with DuckDBManager.get_lock(self.case_id):
            exif_count = self.insert_records(
                table_name="parsed_media_exif",
                records=exif_records,
                schema_ddl=MEDIA_EXIF_SCHEMA_DDL,
            )

            pic_count = self.insert_records(
                table_name="parsed_media_pictures",
                records=picture_records,
                schema_ddl=MEDIA_PICTURES_SCHEMA_DDL,
                artifact_id="media_pictures",
                category="MEDIA",
                display_name="Pictures & EXIF Metadata",
                source_tool="MediaParser",
            )

            vid_count = self.insert_records(
                table_name="parsed_media_videos",
                records=video_records,
                schema_ddl=MEDIA_VIDEOS_SCHEMA_DDL,
                artifact_id="media_videos",
                category="MEDIA",
                display_name="Videos & Audio Files",
                source_tool="MediaParser",
            )

            thumb_count = self.insert_records(
                table_name="parsed_thumbcache",
                records=thumb_records,
                schema_ddl=THUMBCACHE_SCHEMA_DDL,
                artifact_id="windows_thumbcache",
                category="MEDIA",
                display_name="Windows Thumbcache",
                source_tool="MediaParser",
            )

            duration_ms = int((time.time() - start_time) * 1000)
            self.log_processing(
                module_name="Parser:Media",
                command_executed=f"MediaParser.parse({len(candidate_media)} media, {len(candidate_thumbcache)} thumbcache)",
                exit_code=0,
                rows_ingested=pic_count + vid_count + thumb_count,
                duration_ms=duration_ms,
                status="SUCCESS",
            )

        return {
            "parsed_media_exif": exif_count,
            "parsed_media_pictures": pic_count,
            "parsed_media_videos": vid_count,
            "parsed_thumbcache": thumb_count,
        }
