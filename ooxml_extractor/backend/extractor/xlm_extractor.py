"""
xlm_extractor.py — detect and extract XLM / Excel 4.0 macro sheets.

Looks for:
  - xl/macrosheets/*.xml  (explicit macrosheet parts)
  - workbook.xml sheet entries with sheetType="macrosheet"
  - cell formulas containing XLM functions
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

# Namespaces used in workbook/sheet XML
_NS_SS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

# XLM functions that are commonly abused (extraction only — no verdict)
SUSPICIOUS_XLM_FUNCTIONS: frozenset[str] = frozenset(
    [
        "EXEC",
        "REGISTER",
        "CALL",
        "HALT",
        "GET.CELL",
        "GET.WORKSPACE",
        "GET.WINDOW",
        "GET.DOCUMENT",
        "ACTIVATE",
        "APP.ACTIVATE",
        "FORMULA.FILL",
        "FORMULA",
        "SET.VALUE",
        "RUN",
        "RETURN",
        "GOTO",
        "ON.TIME",
        "ALERT",
        "FILE.DELETE",
        "FOPEN",
        "FREAD",
        "FWRITE",
        "FCLOSE",
        "DIRECTORY",
        "ENVIRONX",
        "ENVIRONMENT",
        "OPEN",
        "CLOSE",
    ]
)

_XLM_FUNC_RE = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in sorted(SUSPICIOUS_XLM_FUNCTIONS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


@dataclass
class XlmCell:
    """A single cell in an XLM macro sheet."""

    ref: str       # Cell reference, e.g. "A1"
    formula: str   # Raw formula string (starts with '=' or is a value)
    value: str     # Evaluated value if available
    suspicious_functions: list[str] = field(default_factory=list)


@dataclass
class XlmSheetResult:
    """Results extracted from one XLM macro sheet."""

    sheet_name: str
    archive_path: str
    cells: list[XlmCell] = field(default_factory=list)
    # Unique suspicious functions found across all cells
    all_suspicious_functions: list[str] = field(default_factory=list)
    parse_error: str = ""


@dataclass
class XlmFindings:
    """Aggregated XLM extraction results for the entire archive."""

    macro_sheet_paths: list[str] = field(default_factory=list)
    sheets: list[XlmSheetResult] = field(default_factory=list)
    workbook_macro_sheet_names: list[str] = field(default_factory=list)


def _detect_suspicious(formula: str) -> list[str]:
    """Return XLM function names found in *formula*."""
    return list(dict.fromkeys(m.upper() for m in _XLM_FUNC_RE.findall(formula)))


def _parse_macrosheet_xml(path: str, raw_bytes: bytes, sheet_name: str = "") -> XlmSheetResult:
    """
    Parse an xl/macrosheets/*.xml file and extract cell data.
    """
    result = XlmSheetResult(
        sheet_name=sheet_name or path.split("/")[-1].replace(".xml", ""),
        archive_path=path,
    )

    if not raw_bytes:
        result.parse_error = "Empty file"
        return result

    try:
        text = raw_bytes.decode("utf-8", errors="replace")
        root = ET.fromstring(text)
    except Exception as exc:  # noqa: BLE001
        result.parse_error = f"XML parse error: {exc}"
        return result

    ns = _NS_SS
    suspicious_set: set[str] = set()

    # Iterate <row> → <c> elements
    for row_el in root.iter(f"{{{ns}}}row"):
        for cell_el in row_el.iter(f"{{{ns}}}c"):
            ref = cell_el.get("r", "??")
            formula_el = cell_el.find(f"{{{ns}}}f")
            value_el = cell_el.find(f"{{{ns}}}v")

            formula = formula_el.text or "" if formula_el is not None else ""
            value = value_el.text or "" if value_el is not None else ""

            suspicious = _detect_suspicious(formula)
            for fn in suspicious:
                suspicious_set.add(fn)

            if formula or value:  # skip empty cells
                result.cells.append(
                    XlmCell(
                        ref=ref,
                        formula=f"={formula}" if formula else "",
                        value=value,
                        suspicious_functions=suspicious,
                    )
                )

    result.all_suspicious_functions = sorted(suspicious_set)
    return result


def _parse_workbook_for_macro_sheets(
    workbook_bytes: bytes,
) -> list[tuple[str, str]]:
    """
    Parse workbook.xml to find sheets with sheetType="macrosheet".

    Returns list of (name, r:id) tuples.
    """
    results: list[tuple[str, str]] = []
    if not workbook_bytes:
        return results
    try:
        root = ET.fromstring(workbook_bytes.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return results

    ns = _NS_SS
    r_ns = _NS_R

    for sheet_el in root.iter(f"{{{ns}}}sheet"):
        sheet_type = sheet_el.get(f"{{{ns}}}sheetType") or sheet_el.get("sheetType", "")
        if sheet_type.lower() == "macrosheet":
            name = sheet_el.get("name", "")
            r_id = sheet_el.get(f"{{{r_ns}}}id") or sheet_el.get("r:id", "")
            results.append((name, r_id))

    return results


def extract_xlm(entries: dict[str, bytes]) -> XlmFindings:
    """
    Scan *entries* (archive_path → raw_bytes) for XLM macro indicators.

    Strategy:
    1. Identify xl/macrosheets/*.xml directly
    2. Scan workbook.xml for macrosheet references
    3. Parse each detected sheet
    """
    findings = XlmFindings()

    # Step 1: direct path detection
    macro_paths = [
        p for p in entries
        if p.lower().startswith("xl/macrosheets/") and p.lower().endswith(".xml")
    ]
    findings.macro_sheet_paths = macro_paths

    # Step 2: workbook.xml macrosheet type detection
    workbook_path = next(
        (p for p in entries if p.lower() in ("xl/workbook.xml", "xl/workbook.xml")),
        None,
    )
    if workbook_path:
        wb_macro_sheets = _parse_workbook_for_macro_sheets(entries[workbook_path])
        findings.workbook_macro_sheet_names = [name for name, _ in wb_macro_sheets]

    # Step 3: parse all macro sheets found
    parsed_paths: set[str] = set()
    for path in macro_paths:
        result = _parse_macrosheet_xml(path, entries[path])
        findings.sheets.append(result)
        parsed_paths.add(path)

    # Step 4: also scan ALL xl/worksheets/*.xml for embedded XLM (belt + suspenders)
    for path, raw_bytes in entries.items():
        if path in parsed_paths:
            continue
        path_lower = path.lower()
        if not (path_lower.startswith("xl/worksheets/") and path_lower.endswith(".xml")):
            continue
        # Quick scan — only create a result if suspicious functions are found
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if _XLM_FUNC_RE.search(text):
            result = _parse_macrosheet_xml(path, raw_bytes)
            if result.all_suspicious_functions:
                if path not in findings.macro_sheet_paths:
                    findings.macro_sheet_paths.append(path)
                findings.sheets.append(result)

    return findings
