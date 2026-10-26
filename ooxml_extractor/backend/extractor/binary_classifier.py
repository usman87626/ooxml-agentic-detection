"""
binary_classifier.py — Static binary classification with dual identification engines (v2.1).

Two engines run in parallel for every file:
  1. Magic-byte / heuristic engine (zero-dependency, always available)
  2. Google Magika ML engine (graceful fallback if not installed)

Both results are preserved in ClassificationResult.
The primary BinaryKind is derived from the magic-byte engine (deterministic);
Magika provides a secondary ML-based label and MIME guess.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Optional
from analysis.tools.attack_utils import classify_embedded_blob


# ---------------------------------------------------------------------------
# Stable Taxonomy Enum (DO NOT REORDER — downstream code depends on values)
# ---------------------------------------------------------------------------

class BinaryKind(str, Enum):
    """Stable taxonomy of binary kinds for OOXML parts and embedded blobs."""
    xml_document          = "xml_document"
    rels_relationship     = "rels_relationship"
    vba_macro_container   = "vba_macro_container"
    ole_compound_document = "ole_compound_document"
    pe_executable         = "pe_executable"
    pdf_document          = "pdf_document"
    rtf_document          = "rtf_document"
    html_document         = "html_document"
    javascript_code       = "javascript_code"
    powershell_script     = "powershell_script"
    text_plain            = "text_plain"
    zip_archive           = "zip_archive"
    image_png             = "image_png"
    image_jpeg            = "image_jpeg"
    image_gif             = "image_gif"
    image_bmp             = "image_bmp"
    image_tiff            = "image_tiff"
    excel_binary_workbook = "excel_binary_workbook"
    office_embedded_object = "office_embedded_object"
    office_media          = "office_media"
    office_theme          = "office_theme"
    office_custom_xml     = "office_custom_xml"
    office_settings       = "office_settings"
    office_metadata       = "office_metadata"
    archive_7z            = "archive_7z"
    archive_tar           = "archive_tar"
    binary_unknown        = "binary_unknown"
    data_unknown          = "data_unknown"


# ---------------------------------------------------------------------------
# Magika lazy loader — graceful if not installed
# ---------------------------------------------------------------------------

_magika_instance = None
_magika_available: Optional[bool] = None


def _get_magika():
    """Return a shared Magika instance, or None if magika is not installed."""
    global _magika_instance, _magika_available
    if _magika_available is False:
        return None
    if _magika_instance is not None:
        return _magika_instance
    try:
        from magika import Magika  # type: ignore[import]
        _magika_instance = Magika()
        _magika_available = True
    except Exception:  # pragma: no cover
        _magika_available = False
        _magika_instance = None
    return _magika_instance


@dataclass
class MagikaResult:
    """Structured result from Google Magika ML engine."""
    label: str = ""          # e.g. "docx", "xml", "ole"
    group: str = ""          # e.g. "document", "code"
    mime_type: str = ""      # e.g. "application/msword"
    description: str = ""   # human-readable description
    score: float = 0.0       # confidence 0.0–1.0
    is_text: bool = False

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "group": self.group,
            "mime_type": self.mime_type,
            "description": self.description,
            "score": round(self.score, 4),
            "is_text": self.is_text,
        }


@dataclass
class MagicByteResult:
    """Result from the first-byte / heuristic engine."""
    mime_type: str = ""      # e.g. "application/zip"
    magic_label: str = ""    # e.g. "PK (ZIP)"
    confidence: float = 0.0
    embedded_mz: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mime_type": self.mime_type,
            "magic_label": self.magic_label,
            "confidence": round(self.confidence, 4),
            "embedded_mz": self.embedded_mz,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """Output of classify() for one file — dual-engine identification."""
    # Primary (from magic-byte engine)
    kind: BinaryKind = BinaryKind.data_unknown
    mime_guess: str = "application/octet-stream"
    magic: str = ""
    confidence: float = 1.0
    notes: list[str] = field(default_factory=list)
    embedded_signatures: list[dict] = field(default_factory=list)

    # Dual-engine breakdown
    magic_byte: Optional[MagicByteResult] = None
    magika: Optional[MagikaResult] = None

    def to_dict(self) -> dict:
        d = {
            "kind": self.kind.value,
            "mime_guess": self.mime_guess,
            "magic": self.magic,
            "confidence": self.confidence,
            "notes": self.notes,
            "embedded_signatures": self.embedded_signatures,
            "magic_byte": self.magic_byte.to_dict() if self.magic_byte else None,
            "magika": self.magika.to_dict() if self.magika else None,
        }
        return d


# ---------------------------------------------------------------------------
# Magic byte constants
# ---------------------------------------------------------------------------

_OLE_MAGIC      = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
_ZIP_MAGIC      = b"PK\x03\x04"
_ZIP_EMPTY      = b"PK\x05\x06"
_ZIP_SPAN       = b"PK\x07\x08"
_MZ_MAGIC       = b"MZ"
_PDF_MAGIC      = b"%PDF"
_RTF_MAGIC      = b"{\\rtf"
_PNG_MAGIC      = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC     = b"\xff\xd8\xff"
_GIF87_MAGIC    = b"GIF87a"
_GIF89_MAGIC    = b"GIF89a"
_BMP_MAGIC      = b"BM"
_TIFF_LE_MAGIC  = b"II*\x00"
_TIFF_BE_MAGIC  = b"MM\x00*"
_7Z_MAGIC       = b"7z\xbc\xaf\x27\x1c"
_TAR_OFFSET     = 257
_TAR_MAGIC      = b"ustar"

_PS_KEYWORDS    = frozenset([b"invoke-expression", b"iex", b"start-process",
                              b"invoke-webrequest", b"downloadstring", b"bypass",
                              b"encodedcommand", b"-enc ", b"powershell"])
_JS_PATTERNS    = frozenset([b"function(", b"var ", b"=>", b"document.write",
                              b"eval(", b"require(", b"module.exports"])


# ---------------------------------------------------------------------------
# Embedded MZ signature scanner
# ---------------------------------------------------------------------------

def _scan_embedded_mz(raw: bytes, max_scan: int = 65536) -> list[dict]:
    """Scan for MZ headers at every 2-byte offset within raw[0:max_scan]."""
    results: list[dict] = []
    scan = raw[:max_scan]
    offset = 0
    while offset < len(scan) - 2:
        if scan[offset:offset+2] == b"MZ":
            try:
                e_lfanew = struct.unpack_from("<I", scan, offset + 0x3C)[0]
                pe_offset = offset + e_lfanew
                if pe_offset + 4 <= len(scan) and scan[pe_offset:pe_offset+4] == b"PE\x00\x00":
                    results.append({"type": "PE_executable", "offset": offset, "confirmed": True})
                else:
                    results.append({"type": "MZ_header", "offset": offset, "confirmed": False})
            except struct.error:
                results.append({"type": "MZ_header", "offset": offset, "confirmed": False})
        offset += 2
    return results[:16]


# ---------------------------------------------------------------------------
# Path-based classification heuristics
# ---------------------------------------------------------------------------

def _classify_by_path(path: str) -> Optional[tuple[BinaryKind, str, float, str]]:
    """Return (kind, mime, confidence, label) from path, or None."""
    p = path.lower().lstrip("/")
    ext = PurePosixPath(p).suffix.lstrip(".")

    if p.endswith(".rels"):
        return BinaryKind.rels_relationship, "application/vnd.openxmlformats-package.relationships+xml", 0.99, ".rels"
    if "vbaproject.bin" in p:
        return BinaryKind.vba_macro_container, "application/vnd.ms-office.vbaProject", 0.99, "vbaProject.bin"
    if p.startswith("xl/macrosheets/") and ext == "xml":
        return BinaryKind.xml_document, "application/vnd.ms-excel.macrosheet+xml", 0.95, "xl macrosheet"
    if ext == "xlsb":
        return BinaryKind.excel_binary_workbook, "application/vnd.ms-excel.sheet.binary.macroEnabled.12", 0.99, ".xlsb"
    if "/theme/" in p and ext == "xml":
        return BinaryKind.office_theme, "application/xml", 0.9, "theme"
    if "/customxml/" in p or p.startswith("customxml/"):
        return BinaryKind.office_custom_xml, "application/xml", 0.9, "customXml"
    if "settings.xml" in p or "options.xml" in p:
        return BinaryKind.office_settings, "application/xml", 0.9, "settings"
    if p.startswith("docprops/"):
        return BinaryKind.office_metadata, "application/xml", 0.9, "docProps"
    if ("/media/" in p or "/images/" in p) and ext in ("png", "jpg", "jpeg", "gif", "bmp", "tiff", "emf", "wmf", "svg"):
        kind_map = {"png": BinaryKind.image_png, "jpg": BinaryKind.image_jpeg, "jpeg": BinaryKind.image_jpeg,
                    "gif": BinaryKind.image_gif, "bmp": BinaryKind.image_bmp, "tiff": BinaryKind.image_tiff}
        return kind_map.get(ext, BinaryKind.office_media), f"image/{ext}", 0.85, f".{ext} media"
    if "/embeddings/" in p:
        return BinaryKind.office_embedded_object, "application/octet-stream", 0.7, "embeddings dir"
    if ext == "xml":
        return BinaryKind.xml_document, "application/xml", 0.9, ".xml"
    return None


# ---------------------------------------------------------------------------
# Magika engine
# ---------------------------------------------------------------------------

def _run_magika(raw_bytes: bytes) -> Optional[MagikaResult]:
    """Run Google Magika on raw_bytes. Returns None if unavailable or on error."""
    m = _get_magika()
    if m is None:
        return None
    try:
        result = m.identify_bytes(raw_bytes)
        output = result.output
        return MagikaResult(
            label=output.ct_label,
            group=getattr(output, "group", ""),
            mime_type=output.mime_type,
            description=getattr(output, "description", ""),
            score=float(result.score),
            is_text=getattr(output, "is_text", False),
        )
    except Exception:  # noqa: BLE001  # pragma: no cover
        return None


# ---------------------------------------------------------------------------
# Magic-byte engine
# ---------------------------------------------------------------------------

def _run_magic_bytes(path: str, raw_bytes: bytes) -> tuple[Optional[BinaryKind], MagicByteResult]:
    """
    Run the first-byte / heuristic engine.

    Returns (magic_kind_or_None, MagicByteResult).
    """
    notes: list[str] = []
    head = raw_bytes[:16] if raw_bytes else b""
    head256 = raw_bytes[:256] if raw_bytes else b""
    head4k = raw_bytes[:4096] if raw_bytes else b""

    magic_kind: Optional[BinaryKind] = None
    magic_label = ""
    mime = "application/octet-stream"

    if head[:8] == _OLE_MAGIC:
        magic_kind = BinaryKind.ole_compound_document
        magic_label = "D0CF (OLE)"
        mime = "application/x-ole-storage"
        if "vbaproject.bin" in path.lower():
            magic_kind = BinaryKind.vba_macro_container
            magic_label = "D0CF (OLE/VBA)"
            mime = "application/vnd.ms-office.vbaProject"
    elif head[:4] in (_ZIP_MAGIC, _ZIP_EMPTY, _ZIP_SPAN) or head[:2] == b"PK":
        magic_kind = BinaryKind.zip_archive
        magic_label = "PK (ZIP)"
        mime = "application/zip"
    elif head[:2] == _MZ_MAGIC:
        magic_kind = BinaryKind.pe_executable
        magic_label = "MZ (PE)"
        mime = "application/x-dosexec"
    elif head[:4] == _PDF_MAGIC:
        magic_kind = BinaryKind.pdf_document
        magic_label = "%PDF"
        mime = "application/pdf"
    elif head[:5] == _RTF_MAGIC:
        magic_kind = BinaryKind.rtf_document
        magic_label = "{\\rtf"
        mime = "application/rtf"
    elif head[:8] == _PNG_MAGIC:
        magic_kind = BinaryKind.image_png
        magic_label = "PNG"
        mime = "image/png"
    elif head[:3] == _JPEG_MAGIC:
        magic_kind = BinaryKind.image_jpeg
        magic_label = "JPEG"
        mime = "image/jpeg"
    elif head[:6] in (_GIF87_MAGIC, _GIF89_MAGIC):
        magic_kind = BinaryKind.image_gif
        magic_label = "GIF"
        mime = "image/gif"
    elif head[:2] == _BMP_MAGIC:
        magic_kind = BinaryKind.image_bmp
        magic_label = "BM (BMP)"
        mime = "image/bmp"
    elif head[:4] in (_TIFF_LE_MAGIC, _TIFF_BE_MAGIC):
        magic_kind = BinaryKind.image_tiff
        magic_label = "TIFF"
        mime = "image/tiff"
    elif head[:6] == _7Z_MAGIC:
        magic_kind = BinaryKind.archive_7z
        magic_label = "7z"
        mime = "application/x-7z-compressed"
    elif len(raw_bytes) > _TAR_OFFSET + 5 and raw_bytes[_TAR_OFFSET:_TAR_OFFSET+5] == _TAR_MAGIC:
        magic_kind = BinaryKind.archive_tar
        magic_label = "ustar (TAR)"
        mime = "application/x-tar"
    elif head256[:5].lower() == b"<?xml" or (head256[:3] == b"\xef\xbb\xbf" and head256[3:8].lower() == b"<?xml"):
        magic_kind = BinaryKind.xml_document
        magic_label = "<?xml"
        mime = "application/xml"
    elif (head256[:6].lower() in (b"<html ", b"<html>") or
          head256[:15].lower().startswith(b"<!doctype html")):
        magic_kind = BinaryKind.html_document
        magic_label = "<html"
        mime = "text/html"

    # Content sniffing fallback for text-like / script blobs
    if magic_kind is None and raw_bytes:
        lower_head = head4k.lower()
        if any(kw in lower_head for kw in _PS_KEYWORDS):
            magic_kind = BinaryKind.powershell_script
            magic_label = "PS keywords"
            mime = "text/plain"
        elif any(kw in lower_head for kw in _JS_PATTERNS):
            magic_kind = BinaryKind.javascript_code
            magic_label = "JS patterns"
            mime = "application/javascript"
        else:
            printable = sum(1 for b in raw_bytes[:512] if 0x20 <= b <= 0x7E or b in (9, 10, 13))
            if printable / max(len(raw_bytes[:512]), 1) > 0.85:
                magic_kind = BinaryKind.text_plain
                magic_label = "text-heuristic"
                mime = "text/plain"
            else:
                # Advanced fallback using attack_utils (entropy, decompression)
                is_risky, a_mime, a_ext = classify_embedded_blob(raw_bytes)
                if is_risky:
                    magic_kind = BinaryKind.binary_unknown
                    magic_label = f"Advanced: {a_ext or 'blob'}"
                    mime = a_mime or mime
                    notes.append(f"Advanced classifier identified risky {a_ext} blob (MIME: {a_mime})")

    # Embedded MZ scan
    embedded = []
    if raw_bytes and magic_kind not in (BinaryKind.pe_executable,):
        embedded = _scan_embedded_mz(raw_bytes)
        if embedded:
            notes.append(f"Found {len(embedded)} embedded MZ signature(s)")

    confidence = 0.95 if magic_kind is not None else 0.3
    return magic_kind, MagicByteResult(
        mime_type=mime,
        magic_label=magic_label,
        confidence=confidence,
        embedded_mz=embedded,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Path priority sets for merge logic
# ---------------------------------------------------------------------------

_BINARY_IDENTITY_KINDS = {
    BinaryKind.ole_compound_document, BinaryKind.vba_macro_container,
    BinaryKind.pe_executable, BinaryKind.pdf_document, BinaryKind.rtf_document,
    BinaryKind.image_png, BinaryKind.image_jpeg, BinaryKind.image_gif,
    BinaryKind.image_bmp, BinaryKind.image_tiff,
    BinaryKind.zip_archive, BinaryKind.archive_7z, BinaryKind.archive_tar,
    BinaryKind.html_document,
}
_PATH_PRIORITY_KINDS = {
    BinaryKind.vba_macro_container, BinaryKind.rels_relationship,
    BinaryKind.excel_binary_workbook, BinaryKind.office_theme,
    BinaryKind.office_custom_xml, BinaryKind.office_settings,
    BinaryKind.office_metadata, BinaryKind.office_embedded_object,
    BinaryKind.office_media,
}


# ---------------------------------------------------------------------------
# Main classification function
# ---------------------------------------------------------------------------

def classify(path: str, raw_bytes: bytes) -> ClassificationResult:
    """
    Classify *raw_bytes* at *path* using two independent engines:

    1. Magic-byte / heuristic engine  → deterministic, always available
    2. Google Magika ML engine        → probabilistic, graceful fallback

    Both results are preserved. The primary BinaryKind is derived from
    the magic-byte engine with path-heuristic refinement.
    """
    # Run both engines
    magic_kind, magic_byte_result = _run_magic_bytes(path, raw_bytes)
    magika_result = _run_magika(raw_bytes)

    # Resolve path heuristics
    path_result = _classify_by_path(path)

    # Merge: derive final kind
    notes = list(magic_byte_result.notes)
    if magic_kind is not None:
        final_kind = magic_kind
        mime = magic_byte_result.mime_type
        confidence = magic_byte_result.confidence
        # Path overrides generic xml_document for known OOXML structural kinds
        if magic_kind == BinaryKind.xml_document and path_result and path_result[0] in _PATH_PRIORITY_KINDS:
            final_kind = path_result[0]
            mime = path_result[1]
            confidence = path_result[2]
            notes.append(f"Path override xml_document → {final_kind.value}: {path_result[3]}")
        elif path_result and path_result[0] in _PATH_PRIORITY_KINDS and magic_kind not in _BINARY_IDENTITY_KINDS:
            final_kind = path_result[0]
            confidence = 0.99
            notes.append(f"Path override: {path_result[3]}")
    elif path_result:
        final_kind, mime, confidence, _ = path_result
    else:
        final_kind = BinaryKind.data_unknown if not raw_bytes else BinaryKind.binary_unknown
        mime = "application/octet-stream"
        confidence = 0.3

    return ClassificationResult(
        kind=final_kind,
        mime_guess=mime,
        magic=magic_byte_result.magic_label,
        confidence=confidence,
        notes=notes,
        embedded_signatures=magic_byte_result.embedded_mz,
        magic_byte=magic_byte_result,
        magika=magika_result,
    )
