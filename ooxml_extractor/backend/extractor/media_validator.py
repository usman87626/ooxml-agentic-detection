"""
media_validator.py — Structural validation of font, image, and metafile entries.

Detects malformed EMF/WMF metafiles, suspicious font tables, and
TIFF integer overflow indicators without full rendering.
"""
from __future__ import annotations
import struct
import logging

logger = logging.getLogger(__name__)

# EMF header constants
_EMF_MAGIC = 0x00000001  # EMR_HEADER record type
_WMF_MAGIC_PLACEABLE = b'\xD7\xCD\xC6\x9A'  # Placeable WMF
_WMF_MAGIC_STANDARD = b'\x01\x00\x09\x00'    # Standard WMF

# Suspicious EMF record types that have been exploited
_SUSPICIOUS_EMF_RECORDS = {
    0x00000046: "EMR_EXTTEXTOUTW",    # CVE-2021-31199
    0x00000024: "EMR_ESCAPE",         # Shellcode injection vector
    0x00000059: "EMR_GLSBOUNDEDRECORD", # Buffer overflow
    0x0000005A: "EMR_PIXELFORMAT",    # Heap corruption
}

# TTF/OTF table names that are exploitation targets
_SUSPICIOUS_FONT_TABLES = {b'glyf', b'CFF ', b'hmtx', b'kern', b'name'}


def _validate_emf(path: str, data: bytes) -> dict | None:
    """Validate EMF metafile structure."""
    if len(data) < 88:
        return {"path": path, "type": "emf", "issue": "EMF too small", "severity": "LOW"}

    try:
        record_type = struct.unpack_from('<I', data, 0)[0]
        record_size = struct.unpack_from('<I', data, 4)[0]

        if record_type != _EMF_MAGIC:
            return {"path": path, "type": "emf", "issue": "Invalid EMF header record type", "severity": "MEDIUM"}

        # Check bounds
        bounds = struct.unpack_from('<4i', data, 8)
        if any(abs(b) > 100000 for b in bounds):
            return {"path": path, "type": "emf", "issue": f"Suspicious EMF bounds: {bounds}", "severity": "HIGH"}

        # Scan for suspicious record types in first 4KB
        offset = record_size
        suspicious_found = []
        while offset + 8 <= min(len(data), 4096):
            try:
                rtype = struct.unpack_from('<I', data, offset)[0]
                rsize = struct.unpack_from('<I', data, offset + 4)[0]
                if rtype in _SUSPICIOUS_EMF_RECORDS:
                    suspicious_found.append(_SUSPICIOUS_EMF_RECORDS[rtype])
                if rsize == 0 or rsize > len(data):
                    break
                offset += rsize
            except struct.error:
                break

        if suspicious_found:
            return {
                "path": path, "type": "emf",
                "issue": f"Suspicious EMF records: {', '.join(suspicious_found)}",
                "severity": "HIGH",
            }
    except Exception as e:
        return {"path": path, "type": "emf", "issue": f"EMF parse error: {e}", "severity": "MEDIUM"}

    return None


def _validate_wmf(path: str, data: bytes) -> dict | None:
    """Validate WMF metafile structure."""
    if len(data) < 18:
        return {"path": path, "type": "wmf", "issue": "WMF too small", "severity": "LOW"}

    try:
        if data[:4] == _WMF_MAGIC_PLACEABLE:
            # Placeable WMF: check bbox
            left = struct.unpack_from('<h', data, 6)[0]
            top = struct.unpack_from('<h', data, 8)[0]
            right = struct.unpack_from('<h', data, 10)[0]
            bottom = struct.unpack_from('<h', data, 12)[0]
            if (right - left) > 50000 or (bottom - top) > 50000:
                return {
                    "path": path, "type": "wmf",
                    "issue": f"Suspiciously large WMF dimensions: {right-left}x{bottom-top}",
                    "severity": "HIGH",
                }
    except Exception as e:
        return {"path": path, "type": "wmf", "issue": f"WMF parse error: {e}", "severity": "MEDIUM"}

    return None


def _validate_font(path: str, data: bytes) -> dict | None:
    """Validate font file (TTF/OTF) table directory."""
    if len(data) < 12:
        return {"path": path, "type": "font", "issue": "Font too small", "severity": "LOW"}

    try:
        # TTF/OTF header
        num_tables = struct.unpack_from('>H', data, 4)[0]
        if num_tables > 100:
            return {
                "path": path, "type": "font",
                "issue": f"Excessive table count: {num_tables}",
                "severity": "HIGH",
            }

        # Check table entries
        offset = 12
        for _ in range(min(num_tables, 50)):
            if offset + 16 > len(data):
                break
            tag = data[offset:offset + 4]
            table_offset = struct.unpack_from('>I', data, offset + 8)[0]
            table_size = struct.unpack_from('>I', data, offset + 12)[0]

            # Check for oversized tables
            if table_size > 10 * 1024 * 1024:  # 10MB
                return {
                    "path": path, "type": "font",
                    "issue": f"Oversized font table '{tag.decode('ascii', errors='replace')}': {table_size} bytes",
                    "severity": "HIGH",
                }

            # Check for table pointing outside file
            if table_offset + table_size > len(data) + 1024:
                return {
                    "path": path, "type": "font",
                    "issue": f"Font table '{tag.decode('ascii', errors='replace')}' exceeds file bounds",
                    "severity": "HIGH",
                }

            offset += 16
    except Exception as e:
        return {"path": path, "type": "font", "issue": f"Font parse error: {e}", "severity": "MEDIUM"}

    return None


def _validate_tiff(path: str, data: bytes) -> dict | None:
    """Check TIFF for integer overflow indicators."""
    if len(data) < 8:
        return None

    try:
        # TIFF byte order
        if data[:2] == b'II':
            fmt = '<'
        elif data[:2] == b'MM':
            fmt = '>'
        else:
            return None

        magic = struct.unpack_from(f'{fmt}H', data, 2)[0]
        if magic != 42:
            return {"path": path, "type": "tiff", "issue": "Invalid TIFF magic", "severity": "MEDIUM"}

        ifd_offset = struct.unpack_from(f'{fmt}I', data, 4)[0]
        if ifd_offset > len(data):
            return {
                "path": path, "type": "tiff",
                "issue": f"IFD offset {ifd_offset} exceeds file size {len(data)}",
                "severity": "HIGH",
            }
    except Exception:
        pass

    return None


def validate_media_entries(entries: dict[str, bytes]) -> list[dict]:
    """
    Validate all media/font/metafile entries for structural anomalies.
    Returns list of issue dicts for manifest.
    """
    issues: list[dict] = []

    for path, data in entries.items():
        if not data or len(data) < 8:
            continue

        lower = path.lower()
        result = None

        # EMF
        if lower.endswith('.emf') or (len(data) >= 4 and struct.unpack_from('<I', data, 0)[0] == _EMF_MAGIC):
            result = _validate_emf(path, data)
        # WMF
        elif lower.endswith('.wmf') or data[:4] in (_WMF_MAGIC_PLACEABLE, _WMF_MAGIC_STANDARD):
            result = _validate_wmf(path, data)
        # Font files
        elif lower.endswith(('.ttf', '.otf', '.eot', '.woff', '.woff2')):
            result = _validate_font(path, data)
        # TIFF
        elif lower.endswith(('.tiff', '.tif')) or data[:2] in (b'II', b'MM'):
            if data[:2] in (b'II', b'MM') and len(data) > 4:
                result = _validate_tiff(path, data)

        if result:
            issues.append(result)

    return issues
