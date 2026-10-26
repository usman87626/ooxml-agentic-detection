"""
binary_peeker.py — magic-byte based type detection for embedded/binary parts.
"""

from __future__ import annotations

from .utils import detect_magic, MAGIC_SIGNATURES


# Extended signatures for embedded object identification
_EXTENDED_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE Compound Document"),
    (b"PK\x03\x04", "ZIP / OOXML Archive"),
    (b"PK\x05\x06", "ZIP Archive (empty)"),
    (b"PK\x07\x08", "ZIP Archive (spanned)"),
    (b"MZ", "PE Executable"),
    (b"\x7fELF", "ELF Executable"),
    (b"%PDF", "PDF Document"),
    (b"{\\rtf", "RTF Document"),
    (b"\xCA\xFE\xBA\xBE", "Java Class"),
    (b"\xCE\xFA\xED\xFE", "Mach-O Binary (LE 32-bit)"),
    (b"\xCF\xFA\xED\xFE", "Mach-O Binary (LE 64-bit)"),
    (b"GIF87a", "GIF Image"),
    (b"GIF89a", "GIF Image"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image"),
    (b"\xFF\xD8\xFF", "JPEG Image"),
    (b"RIFF", "RIFF Media (AVI/WAV)"),
    (b"\x1f\x8b", "GZIP Archive"),
    (b"BZh", "BZ2 Archive"),
    (b"7z\xBC\xAF'\x1C", "7z Archive"),
    (b"Rar!", "RAR Archive"),
    (b"\x52\x61\x72\x21\x1A\x07", "RAR5 Archive"),
    (b"<?xml", "XML Document"),
    (b"<html", "HTML Document"),
    (b"<HTML", "HTML Document"),
]


def peek_type(data: bytes) -> str:
    """
    Return the best-guess content type for *data* based on magic bytes.

    Uses the extended signature table for more precise identification
    of embedded binaries commonly found in OOXML containers.
    """
    if not data:
        return "Empty"

    for magic, label in _EXTENDED_SIGNATURES:
        if data[: len(magic)] == magic:
            return label

    # If nothing matched, fall back to the shared detect_magic helper
    return detect_magic(data)


def is_ole(data: bytes) -> bool:
    """Return True if *data* starts with the OLE compound-document magic."""
    return data[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def is_pe(data: bytes) -> bool:
    """Return True if *data* has a PE (MZ) header."""
    return data[:2] == b"MZ"


def is_zip(data: bytes) -> bool:
    """Return True if *data* starts with a ZIP local-file header."""
    return data[:2] == b"PK"


def is_pdf(data: bytes) -> bool:
    return data[:4] == b"%PDF"


def is_rtf(data: bytes) -> bool:
    return data[:5] == b"{\\rtf"


def hex_preview(data: bytes, max_bytes: int = 256) -> str:
    """Return a formatted hex dump of the first *max_bytes* bytes."""
    chunk = data[:max_bytes]
    lines: list[str] = []
    for i in range(0, len(chunk), 16):
        row = chunk[i : i + 16]
        hex_part = " ".join(f"{b:02X}" for b in row)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        lines.append(f"{i:04X}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)
