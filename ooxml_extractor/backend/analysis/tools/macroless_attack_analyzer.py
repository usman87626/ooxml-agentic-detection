"""
macroless_attack_analyzer.py — Detect macro-less attack vectors in OOXML.

Covers:
- QAT (Quick Access Toolbar) poisoning via customUI
- webSettings.xml external resource loading
- oleLink relationships (auto-fetch remote content)
- Excel externalData connections
- Custom document properties with encoded payloads
"""
from __future__ import annotations
import re
import logging

logger = logging.getLogger(__name__)

# webSettings.xml dangerous elements
# Revision note (R6 round): the earlier pattern also matched pixelsPerInch,
# targetScreenSz, divs, doNotSaveAsSingleFile, etc. Word writes these into the
# webSettings part of ordinary documents (ECMA-376 Part 1, w:webSettings), so the
# rule fired on virtually every .docx. Only frame/frameset structures relate to
# the frame-injection technique; external frame sources are flagged separately
# (web_settings_frame, HIGH).
_WEB_SETTINGS_DANGEROUS = re.compile(
    r'<w:(?:frameset|frame)\b',
    re.IGNORECASE,
)
_FRAME_SRC_RE = re.compile(r'<w:sourceFileName[^>]*>([^<]+)</w:sourceFileName>', re.IGNORECASE)

# Custom UI / QAT patterns
_CUSTOM_UI_RE = re.compile(r'<customUI\b[^>]*>', re.IGNORECASE)
_QAT_RE = re.compile(r'<mso:cmd\b.*?idMso="([^"]+)"', re.IGNORECASE)
_QAT_MACRO_RE = re.compile(r'onAction="([^"]+)"', re.IGNORECASE)

# External data connections (Excel)
_CONN_RE = re.compile(r'<connection\b[^>]*>', re.IGNORECASE)
_DB_COMMAND_RE = re.compile(r'<dbPr\b[^>]*command="([^"]*)"', re.IGNORECASE)

# oleLink relationship type
_OLE_LINK_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleLink"
# altChunk: imports a part in another format (RTF/MHT/HTML) into the document body.
_ALTCHUNK_TYPE_SUFFIX = "/afchunk"
_ALTCHUNK_RISKY_EXT = (".rtf", ".mht", ".mhtml", ".htm", ".html")


def analyze(manifest: dict) -> dict:
    """
    Detect macro-less structural attack vectors.
    """
    findings: list[dict] = []
    detected = False

    entries = manifest.get("entries", [])
    decoded_map: dict[str, str] = {}
    for entry in entries:
        decoded = entry.get("decoded") or {}
        text = decoded.get("decoded_text_utf8", "")
        if text:
            decoded_map[entry.get("path", "")] = text

    # --- 1. webSettings.xml analysis ---
    for path, text in decoded_map.items():
        if "websettings" not in path.lower():
            continue

        # Check for frames pointing to external resources
        for m in _FRAME_SRC_RE.finditer(text):
            src = m.group(1).strip()
            if src.startswith(("http://", "https://", "ftp://", "\\\\")):
                detected = True
                findings.append({
                    "type": "web_settings_frame",
                    "source": path,
                    "detail": f"External frame source: {src}",
                    "severity": "HIGH",
                })

        if _WEB_SETTINGS_DANGEROUS.search(text):
            findings.append({
                "type": "web_settings_suspicious",
                "source": path,
                "detail": "Contains suspicious webSettings elements",
                "severity": "MEDIUM",
            })

    # --- 2. Custom UI / QAT poisoning ---
    for path, text in decoded_map.items():
        if "customui" not in path.lower() and "ribbon" not in path.lower():
            continue

        if _CUSTOM_UI_RE.search(text):
            # Check for macro-bound actions
            for m in _QAT_MACRO_RE.finditer(text):
                action = m.group(1)
                detected = True
                findings.append({
                    "type": "qat_macro_binding",
                    "source": path,
                    "detail": f"Custom UI button bound to: {action}",
                    "severity": "HIGH",
                })

    # --- 3. oleLink relationships ---
    for rf in manifest.get("rels_files", []):
        for rel in rf.get("relationships", []):
            if rel.get("type") == _OLE_LINK_TYPE:
                target = rel.get("target", "")
                if target:
                    detected = True
                    findings.append({
                        "type": "ole_link",
                        "source": rf.get("path", ""),
                        "detail": f"oleLink auto-fetch: {target}",
                        "severity": "HIGH",
                    })

    # --- 3b. altChunk imports (revision: hidden RTF/MHT content imported on open) ---
    for rf in manifest.get("rels_files", []):
        for rel in rf.get("relationships", []):
            if str(rel.get("type", "")).lower().endswith(_ALTCHUNK_TYPE_SUFFIX):
                target = rel.get("resolved_target") or rel.get("target", "")
                risky = target.lower().endswith(_ALTCHUNK_RISKY_EXT)
                if risky:
                    detected = True
                findings.append({
                    "type": "altchunk_import",
                    "source": rf.get("path", ""),
                    "target": target,
                    "detail": f"altChunk imports {target}",
                    "severity": "HIGH" if risky else "MEDIUM",
                })

    # --- 4. External data connections (Excel) ---
    for path, text in decoded_map.items():
        if "connections" not in path.lower() and "connection" not in path.lower():
            continue

        for m in _DB_COMMAND_RE.finditer(text):
            cmd = m.group(1)
            if any(kw in cmd.lower() for kw in ('cmd', 'exec', 'shell', 'powershell', 'http')):
                detected = True
                findings.append({
                    "type": "external_data_connection",
                    "source": path,
                    "detail": f"Suspicious DB command: {cmd[:200]}",
                    "severity": "HIGH",
                })

    # --- 5. Custom document properties with encoded payloads ---
    for path, text in decoded_map.items():
        if "custom" not in path.lower() or "properties" not in path.lower():
            continue

        # Look for base64-like property values
        props = re.findall(r'<vt:lpwstr>([^<]{50,})</vt:lpwstr>', text, re.IGNORECASE)
        for prop_val in props:
            # Check if it looks like encoded data
            if re.match(r'^[A-Za-z0-9+/=]{50,}$', prop_val.strip()):
                detected = True
                findings.append({
                    "type": "encoded_property",
                    "source": path,
                    "detail": f"Base64-like custom property value ({len(prop_val)} chars)",
                    "severity": "MEDIUM",
                })

    return {
        "detected": detected,
        "findings": findings,
        "finding_count": len(findings),
    }
