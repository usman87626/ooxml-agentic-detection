"""
zip_reader.py — safe ZIP reading with ZipSlip prevention.

Yields ZipEntry objects for every entry in the archive.
Handles malformed ZIPs via best-effort extraction.
"""

from __future__ import annotations

import hashlib
import logging
import zlib
import zipfile
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from .utils import safe_extract_path, sha256_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zip bomb protection limits
# ---------------------------------------------------------------------------
MAX_TOTAL_BYTES = 200 * 1024 * 1024    # 200 MB cumulative decompressed
MAX_ENTRY_SIZE  = 100 * 1024 * 1024    # 100 MB per single entry
MAX_ENTRY_COUNT = 10_000               # Max entries in a ZIP


@dataclass
class ZipEntry:
    """All metadata + raw bytes for a single ZIP archive entry."""

    # Original path string as stored in the ZIP directory
    path: str

    # Numeric ZIP compression method (0=stored, 8=deflate, etc.)
    compression_method: int

    # Compressed / uncompressed sizes from ZIP directory
    compress_size: int
    file_size: int

    # CRC32 from ZIP directory header (may be 0 for streaming entries)
    crc32: int

    # Whether the entry is encrypted (general-purpose-bit-flag bit 0)
    is_encrypted: bool

    # SHA-256 of the raw (decompressed) bytes
    sha256: str

    # Raw decompressed bytes — never discarded
    raw_bytes: bytes

    # Absolute path where raw bytes were written to disk (set after save)
    extracted_path: str = ""

    # Human-readable extraction error (empty string = success)
    error: str = ""


def _read_entry_safe(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[bytes, str]:
    """
    Read a single entry from the open *ZipFile*.

    Returns (raw_bytes, error_message).  On any error, returns
    (b"", error_message) so the caller can record the failure
    without crashing the overall extraction.
    """
    try:
        data = zf.read(info.filename)
        return data, ""
    except zipfile.BadZipFile as exc:
        return b"", f"BadZipFile: {exc}"
    except zlib.error as exc:
        return b"", f"Decompression error: {exc}"
    except RuntimeError as exc:
        # Raised for encrypted entries when no password is provided
        return b"", f"Encrypted entry (no password): {exc}"
    except Exception as exc:  # noqa: BLE001
        return b"", f"Unexpected read error: {exc}"


def iter_zip_entries(
    archive_data: bytes,
    *,
    allow_encrypted: bool = True,
) -> Generator[ZipEntry, None, None]:
    """
    Iterate over **every** entry in the ZIP archive provided as *archive_data*.

    Yields a :class:`ZipEntry` for each entry, including:
    - entries that cannot be decompressed (error recorded in `.error`)
    - encrypted entries (raw bytes will be empty, is_encrypted=True)
    - zero-byte / directory entries

    Includes zip bomb protection: entries exceeding size limits or
    cumulative byte limits are skipped with an error recorded.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(archive_data), "r")
    except zipfile.BadZipFile as exc:
        logger.error("Cannot open ZIP: %s", exc)
        # Yield a single sentinel entry so the caller knows what happened
        yield ZipEntry(
            path="<archive>",
            compression_method=0,
            compress_size=len(archive_data),
            file_size=0,
            crc32=0,
            is_encrypted=False,
            sha256=sha256_bytes(archive_data),
            raw_bytes=archive_data,
            error=f"Cannot open ZIP: {exc}",
        )
        return

    with zf:
        total_decompressed = 0
        entry_count = 0

        for info in zf.infolist():
            entry_count += 1

            # Zip bomb: too many entries
            if entry_count > MAX_ENTRY_COUNT:
                logger.warning("Zip bomb protection: entry count %d exceeds limit %d", entry_count, MAX_ENTRY_COUNT)
                yield ZipEntry(
                    path=info.filename, compression_method=info.compress_type,
                    compress_size=info.compress_size, file_size=info.file_size,
                    crc32=info.CRC, is_encrypted=bool(info.flag_bits & 0x1),
                    sha256="", raw_bytes=b"",
                    error=f"Zip bomb protection: entry count exceeds {MAX_ENTRY_COUNT}",
                )
                continue

            # Zip bomb: single entry too large (check declared size)
            if info.file_size > MAX_ENTRY_SIZE:
                logger.warning("Zip bomb protection: %s declares %d bytes (limit %d)",
                               info.filename, info.file_size, MAX_ENTRY_SIZE)
                yield ZipEntry(
                    path=info.filename, compression_method=info.compress_type,
                    compress_size=info.compress_size, file_size=info.file_size,
                    crc32=info.CRC, is_encrypted=bool(info.flag_bits & 0x1),
                    sha256="", raw_bytes=b"",
                    error=f"Zip bomb protection: declared size {info.file_size} exceeds {MAX_ENTRY_SIZE}",
                )
                continue

            is_encrypted = bool(info.flag_bits & 0x1)
            raw_bytes, error = _read_entry_safe(zf, info)

            # Zip bomb: check actual decompressed size
            if len(raw_bytes) > MAX_ENTRY_SIZE:
                logger.warning("Zip bomb protection: %s actual size %d exceeds limit",
                               info.filename, len(raw_bytes))
                raw_bytes = b""
                error = f"Zip bomb protection: actual size exceeds {MAX_ENTRY_SIZE}"

            # Zip bomb: cumulative size check
            total_decompressed += len(raw_bytes)
            if total_decompressed > MAX_TOTAL_BYTES:
                logger.warning("Zip bomb protection: cumulative size %d exceeds %d",
                               total_decompressed, MAX_TOTAL_BYTES)
                yield ZipEntry(
                    path=info.filename, compression_method=info.compress_type,
                    compress_size=info.compress_size, file_size=info.file_size,
                    crc32=info.CRC, is_encrypted=is_encrypted,
                    sha256="", raw_bytes=b"",
                    error=f"Zip bomb protection: cumulative decompressed bytes exceed {MAX_TOTAL_BYTES}",
                )
                continue

            digest = sha256_bytes(raw_bytes) if raw_bytes else sha256_bytes(b"")

            yield ZipEntry(
                path=info.filename,
                compression_method=info.compress_type,
                compress_size=info.compress_size,
                file_size=info.file_size,
                crc32=info.CRC,
                is_encrypted=is_encrypted,
                sha256=digest,
                raw_bytes=raw_bytes,
                error=error,
            )


def open_zip_from_path(file_path: Path) -> bytes:
    """Read a file from disk into bytes for use with :func:`iter_zip_entries`."""
    with open(file_path, "rb") as f:
        return f.read()


COMPRESSION_METHOD_NAMES: dict[int, str] = {
    0: "stored",
    8: "deflated",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
    98: "ppmd",
}


def compression_name(method: int) -> str:
    return COMPRESSION_METHOD_NAMES.get(method, f"unknown({method})")
