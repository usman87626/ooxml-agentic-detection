"""
rtf_extractor.py — Parse RTF blobs embedded in OOXML for nested payloads.

Extracts OLE objects inside RTF (objdata, objemb), detects Equation Editor
objects (CVE-2017-11882), and extracts nested embedded content.
"""
from __future__ import annotations
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# RTF control word patterns
_OBJDATA_RE = re.compile(r'\\objdata\s+([0-9a-fA-F\s]+)', re.DOTALL)
_OBJEMB_RE = re.compile(r'\\objemb\b', re.IGNORECASE)
# Revision: obfuscated RTF often breaks the "\objdata <hex>" layout, so also
# accept the bare control word; \objupdate forces the OLE object to refresh
# (and its server to run) when the document opens — an exploit-delivery pattern.
_OBJDATA_ANY_RE = re.compile(r'\\objdata(?![a-z])', re.IGNORECASE)
_OBJUPDATE_RE = re.compile(r'\\objupdate(?![a-z])', re.IGNORECASE)
_OBJCLASS_RE = re.compile(r'\\objclass\s+(\w+)', re.IGNORECASE)
_EQUATION_RE = re.compile(r'Equation\.3|Equation\.DSMT|MathType', re.IGNORECASE)

# Equation Editor CLSID (CVE-2017-11882)
_EQUATION_CLSID = b'\x02\xce\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'


@dataclass
class RtfFinding:
    source_path: str
    has_ole_objects: bool = False
    has_equation_editor: bool = False
    has_autoupdate: bool = False
    obj_classes: list[str] = field(default_factory=list)
    nested_types: list[str] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)


def _hex_to_bytes(hex_str: str) -> bytes:
    """Convert RTF hex string (with whitespace) to bytes."""
    cleaned = re.sub(r'\s+', '', hex_str)
    try:
        return bytes.fromhex(cleaned[:2048])  # Cap to avoid huge allocations
    except ValueError:
        return b""


def scan_rtf_blob(path: str, data: bytes) -> RtfFinding:
    """Scan an RTF blob for embedded objects and exploit indicators."""
    finding = RtfFinding(source_path=path)

    try:
        text = data.decode('ascii', errors='ignore')
    except Exception:
        return finding

    # Check for embedded OLE objects
    objdata_matches = _OBJDATA_RE.findall(text)
    if objdata_matches:
        finding.has_ole_objects = True
        finding.risk_indicators.append(f"Contains {len(objdata_matches)} OLE \\objdata stream(s)")

        for hex_data in objdata_matches[:5]:  # Cap at 5
            raw = _hex_to_bytes(hex_data)
            if _EQUATION_CLSID in raw:
                finding.has_equation_editor = True
                finding.risk_indicators.append("Equation Editor CLSID detected (CVE-2017-11882)")

            # Check for PE header in OLE data
            if b'MZ' in raw[:256]:
                finding.nested_types.append("PE_in_RTF_OLE")
                finding.risk_indicators.append("PE executable embedded in RTF OLE object")

    if not objdata_matches and _OBJDATA_ANY_RE.search(text):
        finding.has_ole_objects = True
        finding.risk_indicators.append("Contains OLE \\objdata stream (non-standard layout)")
    if _OBJUPDATE_RE.search(text):
        finding.has_autoupdate = True
        finding.risk_indicators.append("OLE object set to auto-update on open (\\objupdate)")

    # Check for \objemb
    if _OBJEMB_RE.search(text):
        finding.has_ole_objects = True
        finding.risk_indicators.append("Contains \\objemb (embedded object)")

    # Extract object classes
    for cls_match in _OBJCLASS_RE.finditer(text):
        cls_name = cls_match.group(1)
        finding.obj_classes.append(cls_name)
        if _EQUATION_RE.match(cls_name):
            finding.has_equation_editor = True
            finding.risk_indicators.append(f"Equation Editor class: {cls_name}")

    return finding


def extract_rtf_findings(entries: dict[str, bytes]) -> list[dict]:
    """
    Scan all RTF-typed entries for embedded objects.
    Returns list of finding dicts for manifest inclusion.
    """
    findings: list[dict] = []

    for path, raw_bytes in entries.items():
        if not raw_bytes or len(raw_bytes) < 10:
            continue
        # Only scan entries that look like RTF
        if not raw_bytes[:5] == b'{\\rtf':
            continue

        finding = scan_rtf_blob(path, raw_bytes)
        if finding.has_ole_objects or finding.has_equation_editor:
            findings.append({
                "source_path": finding.source_path,
                "has_ole_objects": finding.has_ole_objects,
                "has_equation_editor": finding.has_equation_editor,
                "has_autoupdate": finding.has_autoupdate,
                "obj_classes": finding.obj_classes,
                "nested_types": finding.nested_types,
                "risk_indicators": finding.risk_indicators,
            })

    return findings
