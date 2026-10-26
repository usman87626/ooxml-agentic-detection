"""
xml_decoder.py — UTF-8 / UTF-16LE decoding + lightweight XML summary.

Decoding is additive — this module never replaces raw bytes.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from .utils import extract_namespaces, extract_root_tag

_XML_DECLARATION_ENC = re.compile(
    r"""<\?xml[^>]*encoding\s*=\s*['"]([^'"]+)['"][^>]*\?>""",
    re.IGNORECASE,
)


@dataclass
class XmlSummary:
    """Lightweight, non-truncating summary of an XML document."""

    root_tag: str = ""
    namespaces: list[str] = field(default_factory=list)
    # top-level child tag → count
    child_element_counts: dict[str, int] = field(default_factory=dict)
    total_elements: int = 0


@dataclass
class XmlDecodeResult:
    """Result of attempting to decode an XML / text part."""

    # Decoded as UTF-8 (best effort)
    decoded_text_utf8: str = ""

    # Decoded as UTF-16LE (best effort; may be empty if not applicable)
    decoded_text_utf16le: str = ""

    # Error message if XML could not be structurally parsed
    parse_error: str = ""

    # Lightweight XML summary (populated only if parse succeeds)
    xml_summary: Optional[XmlSummary] = None


def _sniff_encoding(raw: bytes) -> str:
    """Return the declared encoding from an XML declaration, or 'utf-8'."""
    m = _XML_DECLARATION_ENC.search(raw[:200].decode("ascii", errors="ignore"))
    return m.group(1).lower() if m else "utf-8"


def _build_xml_summary(text: str) -> tuple[XmlSummary, str]:
    """
    Parse *text* as XML and return a lightweight XmlSummary.

    Returns (summary, error_string).
    """
    summary = XmlSummary()
    # Quick heuristic path counts from regex (fast, avoids full parse for huge docs)
    summary.root_tag = extract_root_tag(text)
    summary.namespaces = extract_namespaces(text)

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return summary, str(exc)

    # Count child elements at depth-1
    counts: dict[str, int] = {}
    for child in root:
        tag = child.tag
        # Strip namespace from tag for readability
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        counts[tag] = counts.get(tag, 0) + 1

    # Total elements (cheap iter)
    total = sum(1 for _ in root.iter())
    summary.child_element_counts = counts
    summary.total_elements = total

    return summary, ""


def decode_part(raw_bytes: bytes, *, force_xml_parse: bool = True) -> XmlDecodeResult:
    """
    Attempt to decode *raw_bytes* as text/XML.

    UTF-8 decode is always attempted.
    UTF-16LE decode is attempted if a BOM (FF FE) is found or if the
    UTF-8 decode produces mostly null-bytes / replacement chars.
    XML summary is built only when *force_xml_parse* is True.
    """
    result = XmlDecodeResult()

    if not raw_bytes:
        return result

    # --- UTF-8 decode ---
    try:
        result.decoded_text_utf8 = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        result.decoded_text_utf8 = ""
        result.parse_error = f"UTF-8 decode failed: {exc}"

    # --- UTF-16LE decode (if BOM present or UTF-8 looks garbled) ---
    has_bom_le = raw_bytes[:2] == b"\xff\xfe"
    has_bom_be = raw_bytes[:2] == b"\xfe\xff"
    null_ratio = (
        raw_bytes.count(0) / max(len(raw_bytes), 1)
    )  # high ratio = likely UTF-16
    if has_bom_le or null_ratio > 0.3:
        try:
            encoding = "utf-16-le" if has_bom_le else "utf-16"
            result.decoded_text_utf16le = raw_bytes.decode(encoding, errors="replace")
        except Exception as exc:  # noqa: BLE001
            result.decoded_text_utf16le = f"[UTF-16LE decode error: {exc}]"
    elif has_bom_be:
        try:
            result.decoded_text_utf16le = raw_bytes.decode("utf-16-be", errors="replace")
        except Exception as exc:  # noqa: BLE001
            result.decoded_text_utf16le = f"[UTF-16BE decode error: {exc}]"

    # --- XML parse for summary ---
    if force_xml_parse:
        text_for_parse = result.decoded_text_utf16le or result.decoded_text_utf8
        if text_for_parse:
            summary, parse_error = _build_xml_summary(text_for_parse)
            result.xml_summary = summary
            if parse_error and not result.parse_error:
                result.parse_error = parse_error

    return result


def is_xml_like(path: str, raw_bytes: bytes) -> bool:
    """Return True if the path or bytes suggests XML content."""
    path_lower = path.lower()
    if path_lower.endswith(".xml") or path_lower.endswith(".rels"):
        return True
    if raw_bytes[:5] in (b"<?xml", b"\xef\xbb\xbf<"):  # UTF-8 BOM + <
        return True
    if raw_bytes[:6] in (b"\xff\xfe<\x00?", b"\xfe\xff\x00<"):  # UTF-16 BOM + <
        return True
    return False
