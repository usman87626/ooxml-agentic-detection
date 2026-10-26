"""
html_svg_analyzer.py — Deterministic analysis of extracted HTML/SVG payloads.

Extracts payloads from embedded HTML/SVG (using extractor data in manifest)
and also performs deterministic pattern matching for common attack signatures.
Code can be passed to LLM via the analysis pipeline if needed.
"""
from __future__ import annotations
import re
import logging

logger = logging.getLogger(__name__)

# Suspicious JavaScript patterns
_JS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("eval_call", re.compile(r'\beval\s*\(', re.IGNORECASE)),
    ("document_write", re.compile(r'document\.write\s*\(', re.IGNORECASE)),
    ("atob_decode", re.compile(r'\batob\s*\(', re.IGNORECASE)),
    ("fromCharCode", re.compile(r'String\.fromCharCode', re.IGNORECASE)),
    ("createElement_script", re.compile(r'createElement\s*\(\s*["\']script', re.IGNORECASE)),
    ("xmlhttp_open", re.compile(r'XMLHttpRequest|\.open\s*\(\s*["\'](?:GET|POST)', re.IGNORECASE)),
    ("fetch_call", re.compile(r'\bfetch\s*\(', re.IGNORECASE)),
    ("window_location", re.compile(r'window\.location\s*=', re.IGNORECASE)),
    ("innerhtml_set", re.compile(r'\.innerHTML\s*=', re.IGNORECASE)),
    ("powershell_ref", re.compile(r'powershell|cmd\.exe|wscript', re.IGNORECASE)),
    ("base64_block", re.compile(r'[A-Za-z0-9+/]{40,}={0,2}', re.IGNORECASE)),
    ("obfuscated_hex", re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}', re.IGNORECASE)),
]


def extract_payloads(manifest: dict) -> dict:
    """
    Analyze HTML/SVG entries from the manifest for active script content.
    Uses extraction data + deterministic pattern matching.
    """
    entries = manifest.get("entries", [])
    html_svg_findings: list[dict] = []
    has_payloads = False
    has_rtf_exploits = False

    for entry in entries:
        path = entry.get("path", "")
        decoded = entry.get("decoded") or {}
        text = decoded.get("decoded_text_utf8", "")
        classification = entry.get("classification") or {}
        mime = classification.get("mime_guess", "")

        lower_path = path.lower()

        # Check for HTML content
        is_html = (
            lower_path.endswith(('.html', '.htm', '.mht', '.mhtml')) or
            'text/html' in mime.lower() or
            (text and '<html' in text[:200].lower())
        )

        # Check for SVG content
        is_svg = (
            lower_path.endswith('.svg') or
            'image/svg' in mime.lower() or
            (text and '<svg' in text[:200].lower())
        )

        if not (is_html or is_svg) or not text:
            continue

        # Run pattern matching on the content
        detected_patterns: list[dict] = []
        for pattern_name, pattern in _JS_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                detected_patterns.append({
                    "pattern": pattern_name,
                    "count": len(matches),
                })

        # Check for dangerous tags
        dangerous_tags = []
        for tag in ('script', 'iframe', 'object', 'embed', 'applet', 'form'):
            tag_re = re.compile(f'<{tag}[\\s>]', re.IGNORECASE)
            if tag_re.search(text):
                dangerous_tags.append(tag)

        # SVG event handlers
        svg_events = []
        if is_svg:
            event_re = re.compile(
                r'\b(onload|onclick|onerror|onmouseover)\s*=\s*["\']([^"\']{1,200})["\']',
                re.IGNORECASE
            )
            for m in event_re.finditer(text):
                svg_events.append({"event": m.group(1), "code": m.group(2)[:100]})

        if detected_patterns or dangerous_tags or svg_events:
            has_payloads = True
            html_svg_findings.append({
                "path": path,
                "type": "svg" if is_svg else "html",
                "dangerous_tags": dangerous_tags,
                "js_patterns": detected_patterns,
                "svg_events": svg_events,
                "content_preview": text[:300],
            })

    # Check for RTF exploit indicators from manifest
    rtf_findings = manifest.get("rtf_findings", [])
    rtf_objects: list[dict] = []
    for rf in rtf_findings:
        if rf.get("has_equation_editor"):
            has_rtf_exploits = True
        if rf.get("has_ole_objects"):
            rtf_objects.append({
                "source": rf.get("source_path", ""),
                "autoupdate": bool(rf.get("has_autoupdate")),
                "equation_editor": bool(rf.get("has_equation_editor")),
                "classes": rf.get("obj_classes", [])[:5],
            })

    return {
        "has_payloads": has_payloads,
        "has_rtf_exploits": has_rtf_exploits,
        "rtf_objects": rtf_objects,
        "findings": html_svg_findings,
        "finding_count": len(html_svg_findings),
    }
