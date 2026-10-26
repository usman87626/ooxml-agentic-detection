"""
url_validator.py — Validate URL content patterns in OOXML documents.

Flags suspicious URL structures: dangerous extensions, IP targets,
data: URIs, URL shorteners, and suspicious query parameters.
"""
from __future__ import annotations
import re
import logging
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# Dangerous file extensions in URLs
_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp',
    '.sct', '.hta', '.cpl', '.pif', '.inf',
    '.dll', '.ocx', '.sys',
    '.jar', '.class',
    '.application', '.appref-ms',
    '.lnk', '.url',
    '.reg', '.rgs',
    '.chm', '.hlp',
})

# URL shortener domains
_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'lc.chat',
    'rebrand.ly', 'bl.ink', 'short.io', 'cutt.ly',
    'v.gd', 'qr.ae', 'shorturl.at', 'rb.gy',
})

# IP address pattern (IPv4)
_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# Base64-like query parameter values
_B64_PARAM_RE = re.compile(r'^[A-Za-z0-9+/=]{20,}$')


def _analyze_url(url: str) -> dict | None:
    """Analyze a single URL for suspicious patterns."""
    issues: list[str] = []
    severity = "LOW"

    try:
        parsed = urlparse(url)
    except Exception:
        return {"url": url, "issues": ["Unparseable URL"], "severity": "MEDIUM"}

    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query

    # --- data: protocol ---
    if scheme == "data":
        issues.append("data: URI scheme (inline payload)")
        severity = "HIGH"
        return {"url": url[:200], "issues": issues, "severity": severity}

    # --- Dangerous file extension ---
    for ext in _DANGEROUS_EXTENSIONS:
        if path.endswith(ext):
            issues.append(f"Downloads dangerous file type: {ext}")
            severity = "HIGH"
            break

    # --- IP-based target ---
    if hostname and _IP_RE.match(hostname):
        issues.append(f"IP-based target: {hostname}")
        severity = max(severity, "MEDIUM") if severity != "HIGH" else severity

    # --- URL shortener ---
    if hostname in _SHORTENER_DOMAINS:
        issues.append(f"URL shortener domain: {hostname}")
        severity = max(severity, "MEDIUM") if severity != "HIGH" else severity

    # --- Suspicious query parameters ---
    if query:
        try:
            params = parse_qs(query)
            for key, values in params.items():
                for val in values:
                    if _B64_PARAM_RE.match(val):
                        issues.append(f"Base64-encoded query param: {key}")
                        severity = "MEDIUM"
                        break
        except Exception:
            pass

    # --- Non-standard ports ---
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        issues.append(f"Non-standard port: {parsed.port}")
        if severity == "LOW":
            severity = "MEDIUM"

    # --- UNC / SMB path ---
    if url.startswith("\\\\") or url.startswith("//"):
        issues.append("UNC/SMB path (credential theft risk)")
        severity = "HIGH"

    if not issues:
        return None

    return {"url": url[:300], "issues": issues, "severity": severity}


def analyze(manifest: dict) -> dict:
    """
    Validate all URLs found in the manifest.
    Returns suspicious_urls list and issue details.
    """
    all_urls = manifest.get("urls", [])
    # Also collect URLs from rels external targets
    for rf in manifest.get("rels_files", []):
        for rel in rf.get("relationships", []):
            target = rel.get("target", "")
            if rel.get("target_mode") == "External" and target:
                if target not in all_urls:
                    all_urls.append(target)

    suspicious: list[dict] = []
    suspicious_urls: list[str] = []

    for url in all_urls:
        result = _analyze_url(url)
        if result:
            suspicious.append(result)
            suspicious_urls.append(url)

    return {
        "total_urls_checked": len(all_urls),
        "suspicious_count": len(suspicious),
        "suspicious_urls": suspicious_urls,
        "url_issues": suspicious,
    }
