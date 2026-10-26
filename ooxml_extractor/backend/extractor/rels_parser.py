"""
rels_parser.py — parse all .rels files in an OOXML archive.

Extracts every relationship (Id, Type, Target, TargetMode) and resolves
internal targets to their full archive paths.  External URLs are collected
in a flat list for easy consumption.

Nothing is dropped: raw .rels bytes are preserved alongside parsed records.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional

RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"

# URL patterns we want to surface even when TargetMode != "External"
_URL_RE = re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE)


@dataclass
class RelationshipRecord:
    """A single <Relationship> element from a .rels file."""

    rel_id: str          # Id attribute
    type: str            # Type (URI)
    target: str          # Raw Target attribute
    target_mode: str     # "External" | "Internal" | "" (default = Internal)
    is_external: bool    # True when TargetMode == "External"

    # For internal relationships: the resolved archive path (relative to root)
    resolved_target: str = ""

    # For external: the URL or UNC path
    external_url: str = ""


@dataclass
class RelsFileRecord:
    """All relationships from a single .rels file."""

    path: str                              # Archive path of the .rels file
    source_part: str                       # The part this .rels file belongs to
    relationships: list[RelationshipRecord] = field(default_factory=list)
    raw_bytes: bytes = field(default=b"", repr=False)
    parse_error: str = ""


def _resolve_internal_target(rels_path: str, target: str) -> str:
    """
    Resolve an internal relationship target to its absolute archive path.

    OOXML .rels files live at  <dir>/_rels/<source_basename>.rels
    The Target is relative to *<dir>* (not to the .rels file itself).

    Example:
      rels_path  = "word/_rels/document.xml.rels"
      target     = "styles.xml"
      → resolved = "word/styles.xml"

    Absolute targets (starting with /) are returned as-is (strip leading /).
    """
    if target.startswith("/"):
        return target.lstrip("/")

    # Parent directory of the .rels file is <dir>/_rels/
    # The base directory for resolution is <dir>/
    rels_posix = PurePosixPath(rels_path)
    base_dir = rels_posix.parent.parent  # go up from _rels/ to <dir>/

    resolved = (base_dir / target).as_posix()
    # Collapse any .. that snuck through
    parts = []
    for p in resolved.split("/"):
        if p == "..":
            if parts:
                parts.pop()
        elif p and p != ".":
            parts.append(p)
    return "/".join(parts)


def _extract_urls_from_text(text: str) -> list[str]:
    """Return all HTTP/HTTPS URLs found anywhere in *text*."""
    return _URL_RE.findall(text)


def parse_rels_bytes(rels_path: str, raw_bytes: bytes) -> RelsFileRecord:
    """
    Parse the .rels XML in *raw_bytes* and return a :class:`RelsFileRecord`.

    Robust: on any parse error the record is returned with `.parse_error` set
    and an empty relationships list (raw bytes still preserved).
    """
    # Derive which source part this .rels file belongs to:
    #   "word/_rels/document.xml.rels" → source="word/document.xml"
    #   "_rels/.rels"                  → source="<root>"
    rels_posix = PurePosixPath(rels_path)
    parent_dir = rels_posix.parent.parent  # up from _rels/
    stem = rels_posix.stem  # filename without last suffix, e.g. "document.xml"
    if stem == ".rels" or stem == "":
        source_part = str(parent_dir) if str(parent_dir) != "." else "<root>"
    else:
        if str(parent_dir) in (".", ""):
            source_part = stem
        else:
            source_part = f"{parent_dir}/{stem}"

    record = RelsFileRecord(
        path=rels_path,
        source_part=source_part,
        raw_bytes=raw_bytes,
    )

    if not raw_bytes:
        record.parse_error = "Empty .rels file"
        return record

    # Try to decode
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        record.parse_error = f"Decode error: {exc}"
        return record

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        record.parse_error = f"XML parse error: {exc}"
        return record

    for child in root:
        tag = child.tag.replace(f"{{{RELS_NS}}}", "")
        if tag != "Relationship":
            continue

        rel_id = child.get("Id", "")
        rel_type = child.get("Type", "")
        target = child.get("Target", "")
        target_mode = child.get("TargetMode", "Internal")  # default = Internal
        is_external = target_mode.strip().lower() == "external"

        rel = RelationshipRecord(
            rel_id=rel_id,
            type=rel_type,
            target=target,
            target_mode=target_mode,
            is_external=is_external,
        )

        if is_external:
            rel.external_url = target
        else:
            rel.resolved_target = _resolve_internal_target(rels_path, target)

        record.relationships.append(rel)

    return record


def collect_all_rels(
    entries: dict[str, bytes],  # {archive_path: raw_bytes}
) -> tuple[list[RelsFileRecord], list[str]]:
    """
    Parse every .rels file in *entries*.

    Returns:
        rels_records: list of :class:`RelsFileRecord`
        all_urls: deduplicated list of every external URL found
    """
    rels_records: list[RelsFileRecord] = []
    url_set: set[str] = set()

    for path, raw_bytes in entries.items():
        if not path.lower().endswith(".rels"):
            continue

        record = parse_rels_bytes(path, raw_bytes)
        rels_records.append(record)

        for rel in record.relationships:
            if rel.is_external and rel.external_url:
                url_set.add(rel.external_url)

        # Also scan decoded text for embedded URLs (belt + suspenders)
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            for url in _extract_urls_from_text(text):
                url_set.add(url)
        except Exception:  # noqa: BLE001
            pass

    return rels_records, sorted(url_set)
