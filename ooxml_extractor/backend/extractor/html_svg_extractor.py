"""
html_svg_extractor.py — Extract active content from HTML/SVG entries in OOXML.

Finds <script>, <iframe>, <object>, <embed> in HTML, and event handlers
+ <script> in SVG. Extracts code content for downstream LLM analysis.
"""
from __future__ import annotations
import re
import logging
from html.parser import HTMLParser

logger = logging.getLogger(__name__)

# Script tag extraction
_SCRIPT_RE = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)

# Dangerous HTML elements
_DANGEROUS_TAGS = {'script', 'iframe', 'object', 'embed', 'applet', 'form', 'input'}

# SVG event handlers
_SVG_EVENT_RE = re.compile(
    r'\b(onload|onclick|onerror|onmouseover|onfocus|onblur|onanimationend|onbegin)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Data URI detection
_DATA_URI_RE = re.compile(r'data:\s*\w+/\w+[^"\'>\s]+', re.IGNORECASE)


class _PayloadExtractor(HTMLParser):
    """Extract dangerous elements from HTML."""

    def __init__(self):
        super().__init__()
        self.dangerous_elements: list[dict] = []
        self._in_script = False
        self._script_content = ""

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        if tag_lower in _DANGEROUS_TAGS:
            attr_dict = {k.lower(): v for k, v in attrs}
            self.dangerous_elements.append({
                "tag": tag_lower,
                "attributes": attr_dict,
            })
        if tag_lower == "script":
            self._in_script = True
            self._script_content = ""

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            if self._script_content.strip():
                self.dangerous_elements.append({
                    "tag": "script_content",
                    "code": self._script_content.strip()[:2000],
                })

    def handle_data(self, data):
        if self._in_script:
            self._script_content += data


def extract_html_payloads(path: str, content: str) -> dict | None:
    """Extract dangerous payloads from an HTML document."""
    parser = _PayloadExtractor()
    try:
        parser.feed(content)
    except Exception as e:
        logger.warning("HTML parse error in %s: %s", path, e)

    # Also extract script tags via regex (backup)
    script_blocks = _SCRIPT_RE.findall(content)
    data_uris = _DATA_URI_RE.findall(content)

    if not parser.dangerous_elements and not script_blocks and not data_uris:
        return None

    return {
        "source_path": path,
        "type": "html",
        "dangerous_elements": parser.dangerous_elements[:20],
        "script_count": len(script_blocks),
        "script_code": [s.strip()[:2000] for s in script_blocks[:5]],
        "data_uris": data_uris[:10],
    }


def extract_svg_payloads(path: str, content: str) -> dict | None:
    """Extract dangerous payloads from an SVG document."""
    event_handlers = []
    for m in _SVG_EVENT_RE.finditer(content):
        event_handlers.append({
            "event": m.group(1),
            "code": m.group(2)[:500],
        })

    script_blocks = _SCRIPT_RE.findall(content)
    data_uris = _DATA_URI_RE.findall(content)

    if not event_handlers and not script_blocks and not data_uris:
        return None

    return {
        "source_path": path,
        "type": "svg",
        "event_handlers": event_handlers[:20],
        "script_count": len(script_blocks),
        "script_code": [s.strip()[:2000] for s in script_blocks[:5]],
        "data_uris": data_uris[:10],
    }


def extract_all(entries: dict[str, bytes], decoded_map: dict[str, str]) -> list[dict]:
    """
    Scan all entries for HTML/SVG with active content.
    Returns list of payload dicts for manifest.
    """
    findings: list[dict] = []

    for path, raw_bytes in entries.items():
        lower_path = path.lower()
        text = decoded_map.get(path, "")

        if not text and raw_bytes:
            try:
                text = raw_bytes.decode('utf-8', errors='ignore')
            except Exception:
                continue

        if not text or len(text) < 20:
            continue

        # Detect HTML
        is_html = (lower_path.endswith(('.html', '.htm')) or
                   raw_bytes[:6].lower().startswith((b'<html', b'<!doct')) or
                   b'<script' in raw_bytes[:1024].lower())

        # Detect SVG
        is_svg = (lower_path.endswith('.svg') or
                  b'<svg' in raw_bytes[:512].lower())

        if is_html:
            result = extract_html_payloads(path, text)
            if result:
                findings.append(result)
        elif is_svg:
            result = extract_svg_payloads(path, text)
            if result:
                findings.append(result)

    return findings
