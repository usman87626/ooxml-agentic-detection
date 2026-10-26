"""
utils.py — shared helpers: hashing, path safety, snippets.
"""

import hashlib
import os
import re
from pathlib import Path, PurePosixPath


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    """Return hex-encoded SHA-256 of *data*."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return hex-encoded SHA-256 by streaming *path* from disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# ZipSlip prevention
# ---------------------------------------------------------------------------

def safe_extract_path(base_dir: Path, entry_name: str) -> Path:
    """
    Resolve the absolute output path for a ZIP entry.

    Raises ValueError if the path contains '..' components or if the
    resolved absolute path escapes *base_dir* (ZipSlip prevention).
    """
    # 1. Reject any path that contains '..' components BEFORE any stripping.
    #    This catches: "../etc/passwd", "word/../../evil", "a/b/../../../tmp"
    raw_posix = PurePosixPath(entry_name)
    if ".." in raw_posix.parts:
        raise ValueError(
            f"ZipSlip blocked: entry '{entry_name}' contains '..' path component"
        )

    # 2. Strip leading slashes / drive letters and collapse '.' segments.
    safe_parts = [p for p in raw_posix.parts if p not in ("", ".", "/")]
    safe_relative = Path(*safe_parts) if safe_parts else Path("_empty_")
    full_path = (base_dir / safe_relative).resolve()

    # 3. Final resolved-path check — must still be inside base_dir.
    try:
        full_path.relative_to(base_dir.resolve())
    except ValueError:
        raise ValueError(
            f"ZipSlip blocked: entry '{entry_name}' resolves outside workspace "
            f"root '{base_dir}'"
        )

    return full_path


def is_safe_path(base_dir: Path, candidate: Path) -> bool:
    """Return True iff *candidate* is inside *base_dir*."""
    try:
        candidate.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def bounded_snippet(text: str, offset: int = 0, window: int = 200) -> str:
    """Return up to *window* chars of *text* centred around *offset*."""
    start = max(0, offset - window // 2)
    end = min(len(text), offset + window // 2)
    return text[start:end]


def safe_str(data: bytes, encoding: str = "utf-8", errors: str = "replace") -> str:
    """Decode *data* to str, replacing bad chars."""
    return data.decode(encoding, errors=errors)


# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE Compound Document"),
    (b"PK\x03\x04", "ZIP Archive"),
    (b"PK\x05\x06", "ZIP Archive (empty)"),
    (b"MZ", "PE Executable"),
    (b"\x7fELF", "ELF Executable"),
    (b"%PDF", "PDF Document"),
    (b"{\\rtf", "RTF Document"),
    (b"\xFF\xFE", "UTF-16LE BOM"),
    (b"\xFE\xFF", "UTF-16BE BOM"),
    (b"\xEF\xBB\xBF", "UTF-8 BOM"),
    (b"GIF87a", "GIF Image"),
    (b"GIF89a", "GIF Image"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image"),
    (b"\xFF\xD8\xFF", "JPEG Image"),
    (b"RIFF", "RIFF Media"),
    (b"\x1f\x8b", "GZIP Archive"),
    (b"BZh", "BZ2 Archive"),
]


def detect_magic(data: bytes) -> str:
    """Return a human-readable type string based on first magic bytes."""
    if not data:
        return "Empty"
    for magic, label in MAGIC_SIGNATURES:
        if data[: len(magic)] == magic:
            return label
    # Heuristic: high printable-ratio → plain text
    printable = sum(1 for b in data[:512] if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    if len(data[:512]) > 0 and printable / len(data[:512]) > 0.85:
        return "Text/ASCII"
    return "Unknown Binary"


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

_NS_RE = re.compile(r'\bxmlns(?::[\w\-]+)?\s*=\s*"([^"]+)"')
_ROOT_TAG_RE = re.compile(r"<([A-Za-z_][\w:\-]*)")


def extract_namespaces(xml_text: str) -> list[str]:
    return list(dict.fromkeys(_NS_RE.findall(xml_text)))  # deduplicated


def extract_root_tag(xml_text: str) -> str:
    m = _ROOT_TAG_RE.search(xml_text)
    return m.group(1) if m else ""
