"""
url_whitelist.py — Known-clean OOXML/W3C/Microsoft namespace URL filter.

URLs matching any prefix or exact domain in this list are structural
(schema declarations, namespace identifiers, etc.) and are never
external network threats. Filter them from the "urls" list in the manifest
to reduce noise for analysts.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Whitelist — prefix-based (starts_with) matching  (all lower-case)
# ---------------------------------------------------------------------------

WHITELIST_PREFIXES: tuple[str, ...] = (
    # W3C standards
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://www.w3schools.com/",

    # XML / XSD / XSL namespaces
    "http://www.w3.org/2001/xmlschema",
    "http://www.w3.org/1999/xsl/",
    "http://www.w3.org/2001/xmlschema-instance",
    "http://www.w3.org/tr/",

    # Dublin Core (purl.org)
    "http://purl.org/dc/",
    "https://purl.org/dc/",

    # OOXML / ECMA-376 schemas
    "http://schemas.openxmlformats.org/",
    "https://schemas.openxmlformats.org/",

    # Microsoft Office schemas
    "http://schemas.microsoft.com/office/",
    "https://schemas.microsoft.com/office/",
    "http://schemas.microsoft.com/",
    "https://schemas.microsoft.com/",

    # VML / OLE legacy URNs
    "urn:schemas-microsoft-com:",
    "urn:mpeg:",
    "urn:oasis:",
    "urn:ietf:",

    # OASIS
    "http://docs.oasis-open.org/",
    "https://docs.oasis-open.org/",

    # ECMA International
    "http://www.ecma-international.org/",
    "https://www.ecma-international.org/",

    # LibreOffice
    "http://schemas.libreoffice.org/",
    "https://schemas.libreoffice.org/",

    # Adobe / PDF
    "http://ns.adobe.com/",
    "https://ns.adobe.com/",
    "http://purl.org/rss/",

    # Dublin Core / Creative Commons (purl.org variants)
    "http://purl.org/",
    "https://purl.org/",
    "http://dublincore.org/",
    "https://dublincore.org/",

    # OpenDocument
    "urn:oasis:names:tc:opendocument:",

    # XML
    "http://www.w3.org/xml/",

    # Well-known benign CDNs / font URLs embedded in Office themes
    "http://fonts.googleapis.com/",
    "https://fonts.googleapis.com/",
    "http://fonts.gstatic.com/",
    "https://fonts.gstatic.com/",

    # RDF
    "http://www.w3.org/1999/02/22-rdf-syntax-ns",
    "http://www.w3.org/2000/01/rdf-schema",

    # Python / pip metadata sometimes embedded
    "http://creativecommons.org/",
    "https://creativecommons.org/",

    # Wikipedia (often linked in benign document templates)
    "http://wikipedia.org/",
    "https://wikipedia.org/",
    "http://en.wikipedia.org/",
    "https://en.wikipedia.org/",

    # GML / OGC
    "http://www.opengis.net/",
    "https://www.opengis.net/",
)

# Exact hosts (scheme-stripped, lower-case) that are always clean
WHITELIST_HOSTS: frozenset[str] = frozenset({
    "www.w3.org",
    "www.ecma-international.org",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "docs.oasis-open.org",
    "ns.adobe.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "creativecommons.org",
    "www.opengis.net",
    "dublincore.org",
    "wikipedia.org",
    "en.wikipedia.org",
    "www.wikipedia.org",
    "schemas.libreoffice.org",
})


def is_whitelisted(url: str) -> bool:
    """Return True if *url* matches a known-clean namespace / schema prefix."""
    u = url.strip().lower()
    # Prefix check
    for prefix in WHITELIST_PREFIXES:
        if u.startswith(prefix):
            return True
    # Host check
    try:
        # Strip scheme
        rest = u.split("://", 1)[-1].lstrip("/")
        host = rest.split("/")[0].split("?")[0].split("#")[0]
        if host in WHITELIST_HOSTS:
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def filter_urls(urls: list[str]) -> tuple[list[str], list[str]]:
    """
    Split URLs into (external_urls, whitelisted_urls).

    external_urls   — URLs not on the whitelist (need analyst attention)
    whitelisted_urls — matched whitelist entries (structural / known-clean)
    """
    external: list[str] = []
    whitelisted: list[str] = []
    for url in urls:
        if is_whitelisted(url):
            whitelisted.append(url)
        else:
            external.append(url)
    return external, whitelisted
