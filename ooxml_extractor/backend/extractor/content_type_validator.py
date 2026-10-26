"""
content_type_validator.py — Validate [Content_Types].xml for poisoning attacks.

Detects duplicate overrides, suspicious MIME mappings, external schema refs,
and non-standard content types that could enable extension remapping attacks.
"""
from __future__ import annotations
import re
import logging
from collections import Counter

logger = logging.getLogger(__name__)

# Standard OOXML content types (known-safe)
_STANDARD_TYPES: frozenset[str] = frozenset({
    "application/xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.openxmlformats-officedocument.theme+xml",
    "application/vnd.openxmlformats-package.relationships+xml",
    "application/vnd.openxmlformats-package.core-properties+xml",
    "application/vnd.openxmlformats-officedocument.extended-properties+xml",
    "image/png", "image/jpeg", "image/gif", "image/bmp", "image/tiff",
    "image/x-emf", "image/x-wmf",
    "application/vnd.ms-office.activeX+xml",
    "application/vnd.ms-office.activeX",
})

# Dangerous content type → extension mappings
_DANGEROUS_MAPPINGS: dict[str, str] = {
    "application/vnd.ms-office.vbaProject": "VBA project — can execute macros",
    "application/x-oleobject": "OLE object — can contain arbitrary payloads",
    "application/x-msdownload": "Executable download",
    "application/x-dosexec": "DOS executable",
    "text/html": "HTML — can contain scripts",
    "application/javascript": "JavaScript — active content",
    "application/x-javascript": "JavaScript — active content",
}

# Regex for [Content_Types].xml parsing
_DEFAULT_RE = re.compile(
    r'<Default\s+Extension="([^"]+)"\s+ContentType="([^"]+)"',
    re.IGNORECASE,
)
_OVERRIDE_RE = re.compile(
    r'<Override\s+PartName="([^"]+)"\s+ContentType="([^"]+)"',
    re.IGNORECASE,
)


def validate(decoded_text_map: dict[str, str]) -> list[dict]:
    """
    Validate [Content_Types].xml for poisoning indicators.
    Returns list of issue dicts.
    """
    issues: list[dict] = []

    ct_text = decoded_text_map.get("[Content_Types].xml", "")
    if not ct_text:
        return issues

    # Parse Default entries
    defaults = _DEFAULT_RE.findall(ct_text)
    default_ext_counter = Counter(ext.lower() for ext, _ in defaults)

    # Parse Override entries
    overrides = _OVERRIDE_RE.findall(ct_text)
    override_part_counter = Counter(part.lower() for part, _ in overrides)

    # --- Check 1: Duplicate Default entries (priority confusion) ---
    for ext, count in default_ext_counter.items():
        if count > 1:
            issues.append({
                "type": "duplicate_default",
                "detail": f"Extension '.{ext}' has {count} Default entries (priority confusion)",
                "severity": "HIGH",
            })

    # --- Check 2: Duplicate Override entries ---
    for part, count in override_part_counter.items():
        if count > 1:
            issues.append({
                "type": "duplicate_override",
                "detail": f"PartName '{part}' has {count} Override entries",
                "severity": "HIGH",
            })

    # --- Check 3: Dangerous content type mappings ---
    for ext, ct in defaults:
        for dangerous_ct, desc in _DANGEROUS_MAPPINGS.items():
            if ct.lower().startswith(dangerous_ct.lower()):
                issues.append({
                    "type": "dangerous_mapping",
                    "detail": f"Extension '.{ext}' mapped to '{ct}' ({desc})",
                    "severity": "HIGH",
                })

    for part, ct in overrides:
        for dangerous_ct, desc in _DANGEROUS_MAPPINGS.items():
            if ct.lower().startswith(dangerous_ct.lower()):
                # VBA project in standard location is normal
                if "vbaproject" in part.lower() and "vbaProject" in ct:
                    continue
                issues.append({
                    "type": "dangerous_override",
                    "detail": f"'{part}' mapped to '{ct}' ({desc})",
                    "severity": "HIGH",
                })

    # --- Check 4: Uncommon extensions with executable types ---
    executable_exts = {'.bin', '.dat', '.tmp', '.ole'}
    for ext, ct in defaults:
        if f'.{ext.lower()}' in executable_exts:
            if any(d in ct.lower() for d in ['vba', 'activex', 'oleobject', 'executable']):
                issues.append({
                    "type": "suspicious_extension_mapping",
                    "detail": f"Binary extension '.{ext}' mapped to executable type '{ct}'",
                    "severity": "MEDIUM",
                })

    # --- Check 5: External schema references ---
    if re.search(r'xmlns[^=]*=\s*["\']http[s]?://', ct_text, re.IGNORECASE):
        # Standard OOXML namespaces are OK, check for non-standard
        non_std = re.findall(r'xmlns[^=]*=\s*["\'](http[s]?://[^"\']+)["\']', ct_text)
        for ns in non_std:
            if 'schemas.openxmlformats.org' not in ns and 'schemas.microsoft.com' not in ns:
                issues.append({
                    "type": "external_schema",
                    "detail": f"Non-standard namespace: {ns}",
                    "severity": "MEDIUM",
                })

    return issues
