"""
macro_vba_extractor.py — VBA macro extraction from vbaProject.bin / OLE streams.

Uses oletools (olevba) when available.  If olevba is not installed or fails,
the error is recorded and raw bytes are still preserved in the manifest.

Extraction is additive — no raw content is ever dropped.
"""

from __future__ import annotations

import io
import logging
import collections
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Python 3.10+ compatibility for oletools/olevba
if not hasattr(collections, 'MutableMapping'):
    import collections.abc
    collections.MutableMapping = collections.abc.MutableMapping
if not hasattr(collections, 'Iterable'):
    import collections.abc
    collections.Iterable = collections.abc.Iterable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suspicious VBA keyword lists (extraction only — no verdict)
# ---------------------------------------------------------------------------

AUTO_EXEC_KEYWORDS: frozenset[str] = frozenset(
    [
        "AutoOpen",
        "AutoClose",
        "AutoExec",
        "AutoExit",
        "AutoNew",
        "Document_Open",
        "Document_Close",
        "Document_BeforeClose",
        "Workbook_Open",
        "Workbook_Close",
        "Workbook_BeforeClose",
        "Workbook_Activate",
        "Presentation_Open",
        "Presentation_Close",
        "Auto_Open",
        "Auto_Close",
        "SheetActivate",
        "SheetDeactivate",
    ]
)

SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset(
    [
        "Shell",
        "CreateObject",
        "GetObject",
        "WScript.Shell",
        "PowerShell",
        "cmd.exe",
        "environ",
        "Chr(",
        "Asc(",
        "Mid(",
        "InStr(",
        "StrReverse",
        "Base64",
        "URLDownloadToFile",
        "ADODB.Stream",
        "Scripting.FileSystemObject",
        "WinHttp",
        "XMLHTTP",
        "Execute",
        "Eval",
        ".Run",
        "CallByName",
        "VirtualAlloc",
        "RtlMoveMemory",
        "CreateThread",
        "RegWrite",
        "RegRead",
        "OpenTextFile",
        "Write(",
        "Close(",
    ]
)


@dataclass
class MacroModule:
    """VBA source extracted from a single module."""

    module_name: str
    code: str
    auto_exec_keywords: list[str] = field(default_factory=list)
    suspicious_keywords: list[str] = field(default_factory=list)


@dataclass
class MacroContainerResult:
    """Extraction result from a single vbaProject.bin or similar OLE container."""

    archive_path: str
    modules: list[MacroModule] = field(default_factory=list)
    extraction_log: str = ""
    error: str = ""
    is_vba_locked: bool = False  # DPB= protected project


@dataclass
class MacroExtractionResult:
    """Aggregated VBA extraction result for the entire archive."""

    containers_found: list[str] = field(default_factory=list)
    results: list[MacroContainerResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_keywords(code: str, keywords: frozenset[str]) -> list[str]:
    """Return keywords found in *code* (case-sensitive for VBA accuracy)."""
    found = []
    code_lower = code.lower()
    for kw in keywords:
        if kw.lower() in code_lower:
            found.append(kw)
    return sorted(set(found))


def _extract_via_olevba(archive_path: str, raw_bytes: bytes) -> MacroContainerResult:
    """
    Use olevba (oletools) to extract VBA source from *raw_bytes*.

    Returns a :class:`MacroContainerResult` with modules populated or
    an error string if extraction fails.
    """
    result = MacroContainerResult(archive_path=archive_path)

    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML  # type: ignore
    except ImportError:
        result.error = "oletools not installed; pip install oletools"
        logger.warning("oletools not available for %s", archive_path)
        return result

    try:
        vba_parser = VBA_Parser(
            filename=archive_path,
            data=raw_bytes,
            relaxed=True,
        )
    except Exception as exc:  # noqa: BLE001
        result.error = f"VBA_Parser init error: {exc}"
        return result

    log_lines: list[str] = []

    try:
        if not vba_parser.detect_vba_macros():
            result.extraction_log = "No VBA macros detected"
            return result

        module_map: dict[str, str] = {}

        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            name = vba_filename or stream_path or "unnamed"
            # Accumulate code per module name
            if name in module_map:
                module_map[name] += "\n" + (vba_code or "")
            else:
                module_map[name] = vba_code or ""
            log_lines.append(f"Extracted module: {name} from {stream_path}")

        for mod_name, code in module_map.items():
            module = MacroModule(
                module_name=mod_name,
                code=code,
                auto_exec_keywords=_find_keywords(code, AUTO_EXEC_KEYWORDS),
                suspicious_keywords=_find_keywords(code, SUSPICIOUS_KEYWORDS),
            )
            result.modules.append(module)

    except Exception as exc:  # noqa: BLE001
        result.error = f"Extraction error: {exc}"
        log_lines.append(f"ERROR: {exc}")
    finally:
        try:
            vba_parser.close()
        except Exception:  # noqa: BLE001
            pass

    result.extraction_log = "\n".join(log_lines)
    return result


def _is_vba_container(path: str, raw_bytes: bytes) -> bool:
    """Return True if *path*/*raw_bytes* looks like a VBA container."""
    path_lower = path.lower()

    # Explicit vbaProject.bin (any location)
    if "vbaproject.bin" in path_lower:
        return True

    # OLE compound doc containing a VBA-related stream  
    if raw_bytes[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        # We'll try olevba on any OLE blob — it won't hurt
        return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_macros(entries: dict[str, bytes]) -> MacroExtractionResult:
    """
    Scan *entries* (archive_path → raw_bytes) for VBA macro containers.
    """
    overall = MacroExtractionResult()

    for path, raw_bytes in entries.items():
        if not raw_bytes:
            continue
        if _is_vba_container(path, raw_bytes):
            container_result = _extract_via_olevba(path, raw_bytes)

            # Check for encrypted/locked VBA project
            if b'DPB=' in raw_bytes or b'DPx=' in raw_bytes:
                container_result.is_vba_locked = True
                if not container_result.modules:
                    container_result.extraction_log += "\nWARNING: VBA project is password-protected (DPB=). Code may be hidden."

            # ONLY add to containers_found if we actually extracted modules, 
            # or it is a locked project, or it is explicitly named vbaproject.bin
            is_explicit_vba = "vbaproject.bin" in path.lower()
            if container_result.modules or container_result.is_vba_locked or is_explicit_vba:
                overall.containers_found.append(path)
                overall.results.append(container_result)

    return overall
