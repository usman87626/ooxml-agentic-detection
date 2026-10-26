"""
ole_embedded_extractor.py — enumerate and identify embedded OLE objects.

Handles:
  - word/embeddings/, xl/embeddings/, ppt/embeddings/ (OOXML standard paths)
  - Any *.bin file detected as OLE compound document
  - Embedded PEs, RTFs, ZIPs, PDFs inside OLE streams

Uses olefile when available for OLE stream enumeration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .binary_peeker import peek_type, is_ole, is_pe, is_zip, is_pdf, is_rtf
from .utils import sha256_bytes

logger = logging.getLogger(__name__)

# Standard OOXML embedding directories (any of these → treat as probable OLE)
_EMBEDDING_PREFIXES: tuple[str, ...] = (
    "word/embeddings/",
    "xl/embeddings/",
    "ppt/embeddings/",
    "word/media/",      # media can contain OLE objects
    "xl/media/",
    "ppt/media/",
)


@dataclass
class OleStreamInfo:
    """A single stream/storage within an OLE compound document."""

    name: str
    size: int
    is_storage: bool  # True = storage (directory), False = stream (data)


@dataclass
class EmbeddedObject:
    """Metadata for a single embedded binary object."""

    archive_path: str
    sha256: str
    size: int

    # Type string from binary_peeker (e.g. "OLE Compound Document", "PE Executable")
    detected_type: str

    # OLE-specific: list of internal streams (populated if is_ole=True)
    ole_streams: list[OleStreamInfo] = field(default_factory=list)
    ole_error: str = ""

    # Whether a child payload was extracted to a sub-path
    child_payload_path: str = ""


def _enumerate_ole_streams(raw_bytes: bytes) -> tuple[list[OleStreamInfo], str]:
    """
    Use olefile to list storages and streams in an OLE compound document.

    Returns (streams, error_string).
    """
    streams: list[OleStreamInfo] = []
    try:
        import olefile  # type: ignore
    except ImportError:
        return [], "olefile not installed; pip install olefile"

    try:
        ole = olefile.OleFileIO(raw_bytes)
    except Exception as exc:  # noqa: BLE001
        return [], f"olefile open error: {exc}"

    try:
        for entry in ole.listdir(streams=True, storages=True):
            path_str = "/".join(entry)
            try:
                size = ole.get_size(entry)
                is_storage = ole.exists(entry) and ole.get_type(entry) == olefile.STGTY_STORAGE
            except Exception:  # noqa: BLE001
                size = 0
                is_storage = False
            streams.append(OleStreamInfo(name=path_str, size=size, is_storage=is_storage))
    except Exception as exc:  # noqa: BLE001
        return streams, f"olefile listdir error: {exc}"
    finally:
        ole.close()

    return streams, ""


def _is_embedding_path(path: str) -> bool:
    path_lower = path.lstrip("/").lower()
    return any(path_lower.startswith(p) for p in _EMBEDDING_PREFIXES)


def extract_embedded_objects(entries: dict[str, bytes]) -> list[EmbeddedObject]:
    """
    Enumerate and identify embedded objects in *entries*.

    Strategy:
    1. Check standard OOXML embedding directories
    2. Also check any .bin file with OLE magic anywhere in the archive
    3. For OLE blobs: enumerate internal streams via olefile
    4. For non-OLE blobs: detect type from magic bytes
    """
    results: list[EmbeddedObject] = []
    processed: set[str] = set()

    for path, raw_bytes in entries.items():
        is_embed = _is_embedding_path(path)
        is_bin = path.lower().endswith(".bin")
        is_ole_magic = bool(raw_bytes) and is_ole(raw_bytes)

        if not (is_embed or is_bin or is_ole_magic):
            continue

        # Skip very small or empty entries
        if len(raw_bytes) < 8:
            continue

        if path in processed:
            continue
        processed.add(path)

        detected_type = peek_type(raw_bytes)
        digest = sha256_bytes(raw_bytes)

        obj = EmbeddedObject(
            archive_path=path,
            sha256=digest,
            size=len(raw_bytes),
            detected_type=detected_type,
        )

        # Enumerate OLE streams
        if is_ole(raw_bytes):
            ole_streams, ole_error = _enumerate_ole_streams(raw_bytes)
            obj.ole_streams = ole_streams
            obj.ole_error = ole_error

        results.append(obj)

    return results
