"""
content_type_detector.py — detect content types for OOXML ZIP entries.

Strategy (layered, no dropping):
  1. Parse [Content_Types].xml if present (Default + Override elements)
  2. Path-extension heuristics (OOXML-aware)
  3. Magic-byte sniff (first few bytes of raw content)
  4. xml root namespace hints (for XML entries)
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Known OOXML extension → content-type mapping
# ---------------------------------------------------------------------------

EXTENSION_CT_MAP: dict[str, str] = {
    "rels": "application/vnd.openxmlformats-package.relationships+xml",
    "xml": "application/xml",
    "bin": "application/vnd.ms-office.activeX+bin",
    "vml": "application/vnd.openxmlformats-officedocument.vmlDrawing",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tiff": "image/tiff",
    "svg": "image/svg+xml",
    "emf": "image/x-emf",
    "wmf": "image/x-wmf",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    "docm": "application/vnd.ms-word.document.macroEnabled.12",
    "pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "xltx": "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "xltm": "application/vnd.ms-excel.template.macroEnabled.12",
    "dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "dotm": "application/vnd.ms-word.template.macroEnabled.12",
    "potx": "application/vnd.openxmlformats-officedocument.presentationml.template",
    "potm": "application/vnd.ms-powerpoint.template.macroEnabled.12",
    "xlsb": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    "ppsx": "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "ppsm": "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
}

# path-prefix → content-type overrides (OOXML structure conventions)
PATH_PREFIX_CT: list[tuple[str, str]] = [
    ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
    ("word/styles.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"),
    ("word/settings.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"),
    ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
    ("xl/sharedStrings.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"),
    ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
    ("docProps/app.xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml"),
    ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
    ("xl/macrosheets/", "application/vnd.ms-excel.macrosheet+xml"),
    ("vbaProject.bin", "application/vnd.ms-office.vbaProject"),
]

# Magic bytes → content type (just the type string, detection by binary_peeker)
MAGIC_CT_MAP: list[tuple[bytes, str]] = [
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/x-ole-storage"),
    (b"PK\x03\x04", "application/zip"),
    (b"MZ", "application/x-dosexec"),
    (b"\x7fELF", "application/x-elf"),
    (b"%PDF", "application/pdf"),
    (b"{\\rtf", "application/rtf"),
    (b"\xFF\xD8\xFF", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF", "image/gif"),
    (b"<?xml", "application/xml"),
    (b"<html", "text/html"),
    (b"<HTML", "text/html"),
]

CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"


@dataclass
class ContentTypeMap:
    """Detected content types for all entries in the archive."""

    # path → detected content type
    entries: dict[str, str] = field(default_factory=dict)

    # Defaults from [Content_Types].xml (extension → ct)
    defaults: dict[str, str] = field(default_factory=dict)

    # Errors encountered while parsing [Content_Types].xml
    parse_errors: list[str] = field(default_factory=list)

    def get(self, path: str, raw_bytes: bytes = b"") -> str:
        """Return the best known content type for *path*."""
        return self.entries.get(path, "application/octet-stream")


def parse_content_types_xml(xml_bytes: bytes) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """
    Parse [Content_Types].xml.

    Returns:
        defaults: extension (lower, no dot) → content-type
        overrides: absolute part-name → content-type
        errors: list of error strings
    """
    defaults: dict[str, str] = {}
    overrides: dict[str, str] = {}
    errors: list[str] = []

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        errors.append(f"[Content_Types].xml parse error: {exc}")
        return defaults, overrides, errors

    ns = CT_NS
    for child in root:
        tag = child.tag.replace(f"{{{ns}}}", "")
        if tag == "Default":
            ext = (child.get("Extension") or "").lower().lstrip(".")
            ct = child.get("ContentType") or ""
            if ext and ct:
                defaults[ext] = ct
        elif tag == "Override":
            part = (child.get("PartName") or "").lstrip("/")
            ct = child.get("ContentType") or ""
            if part and ct:
                overrides[part] = ct

    return defaults, overrides, errors


def detect_by_magic(raw_bytes: bytes) -> Optional[str]:
    """Return a content type based on magic bytes, or None."""
    if not raw_bytes:
        return None
    for magic, ct in MAGIC_CT_MAP:
        if raw_bytes[: len(magic)] == magic:
            return ct
    return None


def detect_by_path(path: str) -> Optional[str]:
    """Return a content type based on path prefix/extension heuristics."""
    path_lower = path.lower().lstrip("/")

    for prefix, ct in PATH_PREFIX_CT:
        if path_lower == prefix.lower() or path_lower.startswith(prefix.lower()):
            return ct

    ext = path_lower.rsplit(".", 1)[-1] if "." in path_lower else ""
    return EXTENSION_CT_MAP.get(ext)


def build_content_type_map(
    entries: list[tuple[str, bytes]],  # (path, raw_bytes)
    content_types_xml: Optional[bytes] = None,
) -> ContentTypeMap:
    """
    Build a complete :class:`ContentTypeMap` for the archive.

    *content_types_xml* is the raw bytes of ``[Content_Types].xml`` if present.
    *entries* is a list of ``(path, raw_bytes)`` for all entries.
    """
    ctmap = ContentTypeMap()

    # Layer 1: parse [Content_Types].xml
    if content_types_xml:
        defaults, overrides, errors = parse_content_types_xml(content_types_xml)
        ctmap.defaults = defaults
        ctmap.parse_errors.extend(errors)
    else:
        defaults = {}
        overrides = {}

    for path, raw_bytes in entries:
        clean_path = path.lstrip("/")

        # Priority 1: explicit override from [Content_Types].xml
        if clean_path in overrides:
            ctmap.entries[path] = overrides[clean_path]
            continue

        # Priority 2: path-prefix heuristics (OOXML structure)
        path_ct = detect_by_path(path)
        if path_ct:
            ctmap.entries[path] = path_ct
            continue

        # Priority 3: extension from [Content_Types].xml defaults
        ext = clean_path.rsplit(".", 1)[-1].lower() if "." in clean_path else ""
        if ext in defaults:
            ctmap.entries[path] = defaults[ext]
            continue

        # Priority 4: Magic bytes
        magic_ct = detect_by_magic(raw_bytes)
        if magic_ct:
            ctmap.entries[path] = magic_ct
            continue

        # Fallback
        ctmap.entries[path] = "application/octet-stream"

    return ctmap
