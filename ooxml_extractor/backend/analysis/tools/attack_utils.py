"""
attack_utils.py — Shared utility module for specialized OOXML attack detection.
Includes entropy estimation, best-effort decompression, and magic sniffing.
"""
from __future__ import annotations
import re
import math
import zlib
import gzip
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Regexes
# ---------------------------------------------------------------------------

EMBEDDED_HTML_RE = re.compile(
    r'embeddedHtml\s*=\s*(?P<quote>["\'])(?P<html>.*?)(?P=quote)',
    re.IGNORECASE | re.DOTALL,
)

TEMPLATE_REL_RE = re.compile(
    r'<Relationship[^>]+Type="[^"]*attachedTemplate[^"]*"[^>]+Target="(?P<target>[^"]+)"',
    re.IGNORECASE,
)

MAX_DECOMPRESSED_BYTES = 1024 * 1024  # 1 MB cap

# ---------------------------------------------------------------------------
# Entropy & Classification
# ---------------------------------------------------------------------------

def estimate_entropy(data: bytes, sample_size: int = 512) -> float:
    """
    Shannon entropy estimate (bits per byte) on a sample.
    High entropy (~7.5-8.0) usually = encrypted/compressed blob.
    """
    if not data:
        return 0.0

    sample = data[:sample_size]
    length = len(sample)
    freq: Dict[int, int] = {}
    for b in sample:
        freq[b] = freq.get(b, 0) + 1

    ent = 0.0
    for c in freq.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def guess_mime_from_magic(data: bytes) -> Tuple[str | None, str | None]:
    """
    Magic-sniffer. Returns (mime, extension).
    """
    if not data:
        return None, None

    head = data[:64]
    strip_head = head.lstrip()

    # PE
    if head.startswith(b"MZ"):
        return "application/x-dosexec", "exe"

    # OLE
    if head.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "application/x-ole-storage", "ole"

    # ZIP
    if head.startswith(b"PK\x03\x04"):
        return "application/zip", "zip"

    # PDF
    if b"%PDF-" in head[:16]:
        return "application/pdf", "pdf"

    # RTF
    if strip_head.startswith(b"{\\rtf1"):
        return "application/rtf", "rtf"

    # HTML
    lower = strip_head.lower()
    if lower.startswith((b"<html", b"<!doctype html", b"<body", b"<script")):
        return "text/html", "html"

    # SVG
    if b"<svg" in lower:
        return "image/svg+xml", "svg"

    # Plain text
    try:
        txt = head.decode("utf-8")
        if txt.isprintable():
            return "text/plain", "txt"
    except Exception:
        pass

    return "application/octet-stream", None

# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------

def _looks_like_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    if cmf & 0x0F != 8:
        return False
    return ((cmf << 8) + flg) % 31 == 0


def _looks_like_gzip(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B


def try_decompress(data: bytes) -> bytes | None:
    """Best-effort decompression of unknown blobs."""
    if not data or len(data) < 8:
        return None

    # 1) zlib
    if _looks_like_zlib(data):
        try:
            decomp = zlib.decompressobj()
            return decomp.decompress(data, MAX_DECOMPRESSED_BYTES)
        except Exception:
            pass

    # 2) gzip
    if _looks_like_gzip(data):
        try:
            return gzip.decompress(data)[:MAX_DECOMPRESSED_BYTES]
        except Exception:
            pass

    # 3) raw DEFLATE
    try:
        decomp = zlib.decompressobj(wbits=-15)
        return decomp.decompress(data, MAX_DECOMPRESSED_BYTES)
    except Exception:
        pass

    return None


# ---------- Embedded object filtering ----------
INTERESTING_EXTS = {
    # Executables / scripts
    "exe", "dll", "scr", "ocx", "cpl",
    "sys", "drv", "pif",
    "js", "jse", "vbs", "vbe", "hta",
    "ps1", "psm1", "psc1",
    "bat", "cmd",
    "wsf", "wsc", "sct", "wsh", "ws",

    # Office macro containers
    "doc", "docx", "docm", "dotm",
    "xls", "xlsx", "xlsm", "xltm",
    "ppt", "pptx", "pptm",
    "dot", "pot", "xlt",
    "mhtml", "mht",

    # Archive containers / packing formats
    "zip", "rar", "7z", "cab", "gz", "bz2", "xz", "arj", "ace",

    # Installers / packages
    "msi", "msp", "mst", "appx", "msix",

    # PDF & structured payloads
    "pdf", "ole",

    # Virtualized payloads
    "vhd", "vhdx",

    # URL artifacts
    "url", "lnk",
}

INTERESTING_MIME_PREFIXES = {
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
    "application/x-executable",
    "application/zip",
    "application/pdf",
    "application/x-ole-storage",
    "application/vnd.ms-package.3dmanufacturing",
    "application/vnd.ms-office.activeX",
}


def classify_embedded_blob(data: bytes) -> Tuple[bool, str | None, str | None]:
    # 1) classification on raw bytes
    mime_hint, ext_hint = guess_mime_from_magic(data)
    
    is_interesting = False

    # Known dangerous extensions
    if ext_hint and ext_hint.lower() in INTERESTING_EXTS:
        is_interesting = True

    # Known dangerous mime prefixes
    elif mime_hint:
        for pref in INTERESTING_MIME_PREFIXES:
            if mime_hint.startswith(pref):
                is_interesting = True
                break

    # 2) Try to see inside compression if not already clearly interesting
    if not is_interesting:
        decompressed = try_decompress(data)
        if decompressed:
            d_mime, d_ext = guess_mime_from_magic(decompressed)
            
            # Prefer decompressed type if we got something meaningful
            if d_mime or d_ext:
                mime_hint = d_mime or mime_hint
                ext_hint = d_ext or ext_hint

            # Re-apply rules on decompressed view
            if d_ext and d_ext.lower() in INTERESTING_EXTS:
                is_interesting = True
            elif d_mime:
                for pref in INTERESTING_MIME_PREFIXES:
                    if d_mime.startswith(pref):
                        is_interesting = True
                        break

    # 3) High-entropy unknown binary (e.g., encrypted or heavily compressed)
    if not is_interesting:
        ent = estimate_entropy(data)
        if len(data) >= 64 and ent >= 7.5:
            is_interesting = True
            if mime_hint is None:
                mime_hint = "application/octet-stream"
            if ext_hint is None:
                ext_hint = "bin"

    return is_interesting, mime_hint, ext_hint


def filter_embedded_objects(raw_objects: List[Dict[str, Any]]) -> Dict[str, Any]:
    interesting: List[Dict[str, Any]] = []

    for obj in raw_objects:
        data = obj.get("data", b"")
        try:
            is_interesting, mime_hint, ext_hint = classify_embedded_blob(data)
        except Exception as e:
            logger.error(f"classify error for {obj.get('container_name')}: {e}")
            continue

        if not is_interesting:
            continue

        interesting.append(
            {
                "container_name": obj.get("container_name"),
                "size": len(data),
                "mime_hint": mime_hint,
                "extension_hint": ext_hint,
                "source": obj.get("source"),
                "data": data,
                "context": obj.get("context"),
            }
        )

    return {
        "has_embedded": len(interesting) > 0,
        "embedded_objects": interesting,
    }
