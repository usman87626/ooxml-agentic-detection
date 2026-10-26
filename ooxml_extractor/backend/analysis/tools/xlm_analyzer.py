"""
xlm_analyzer.py — Deterministic XLM (Excel 4.0 macro) signal extraction.

Includes a dangerous-function watchlist with argument extraction and
CHAR() concatenation obfuscation detection.
No LLM logic allowed here.
"""
from __future__ import annotations
import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dangerous XLM function watchlist
# ---------------------------------------------------------------------------
_DANGEROUS_FUNCTIONS: frozenset[str] = frozenset({
    "EXEC", "CALL", "RUN", "HALT", "REGISTER",
    "FOPEN", "FWRITE", "FREAD", "FCLOSE", "FSIZE",
    "ALERT", "APP.MAXIMIZE", "FORMULA", "FORMULA.FILL",
    "SET.VALUE", "SET.NAME", "DEFINE.NAME",
    "WAIT", "ON.TIME", "ERROR",
    "DIRECTORY", "FILES", "SAVE.AS",
    "WORKBOOK.HIDE", "WINDOW.HIDE",
})

# Functions used to build obfuscated strings
_OBFUSCATION_FUNCTIONS: frozenset[str] = frozenset({
    "CHAR", "CODE", "T", "MID", "CONCATENATE", "SUBSTITUTE",
})

# Regex to extract function name and arguments from an XLM formula
_FUNC_RE = re.compile(r'=?\s*([A-Za-z_.]+)\s*\((.*)\)', re.DOTALL)

# CHAR(N) pattern for detecting char-by-char string reconstruction
_CHAR_RE = re.compile(r'CHAR\s*\(\s*(\d+)\s*\)', re.IGNORECASE)

# Anti-sandbox detection patterns
_ANTI_SANDBOX_RE = re.compile(
    r'(?:GET\.WORKSPACE|GET\.WINDOW|GET\.DOCUMENT|GET\.CELL|INFO|NOW|FILES)\s*\(',
    re.IGNORECASE,
)


def _extract_functions(formula: str) -> list[dict]:
    """Extract all function calls and their arguments from an XLM formula."""
    results = []
    # Simple tokenizer: find FUNC_NAME( patterns
    i = 0
    while i < len(formula):
        m = re.search(r'([A-Za-z_.]+)\s*\(', formula[i:])
        if not m:
            break
        func_name = m.group(1).upper()
        start = i + m.end()

        # Simple argument extraction (find matching paren)
        depth = 1
        j = start
        while j < len(formula) and depth > 0:
            if formula[j] == '(':
                depth += 1
            elif formula[j] == ')':
                depth -= 1
            j += 1
        args = formula[start:j - 1] if j <= len(formula) else formula[start:]

        results.append({"function": func_name, "args": args.strip()[:200]})
        i = start
    return results


def _decode_char_concat(formula: str) -> str:
    """Attempt to decode CHAR(N)&CHAR(N)&... concatenation into a string."""
    chars = _CHAR_RE.findall(formula)
    if len(chars) < 3:
        return ""
    try:
        return "".join(chr(int(c)) for c in chars if 0 < int(c) < 256)
    except (ValueError, OverflowError):
        return ""


def extract_xlm(manifest: dict) -> dict:
    """
    Extract XLM macro signals from the document manifest.

    Output:
        xlm_detected: bool
        xlm_functions: list[str]
        xlm_sheets: list[str]
        dangerous_functions: list[dict]  — {function, args, source, risk}
        decoded_strings: list[str]       — decoded CHAR() concatenation
        anti_sandbox_detected: bool
        xlm_risk_score: int              — 0-100 based on function severity
    """
    xlm = manifest.get("xlm_macros", {})
    results = xlm.get("results", [])

    xlm_detected = xlm.get("macros_found", False)
    xlm_functions: set[str] = set()
    xlm_sheets: list[str] = []
    dangerous: list[dict] = []
    decoded_strings: list[str] = []
    anti_sandbox = False
    risk_score = 0

    for r in results:
        sheet_name = r.get("sheet_name", "unknown")
        xlm_sheets.append(sheet_name)

        for cell in r.get("formulas", []):
            formula = cell.get("formula", "")
            cell_ref = cell.get("ref", "?")

            # Extract all functions from formula
            funcs = _extract_functions(formula)
            for f in funcs:
                fname = f["function"]
                xlm_functions.add(fname)

                if fname in _DANGEROUS_FUNCTIONS:
                    dangerous.append({
                        "function": fname,
                        "args": f["args"],
                        "source": f"{sheet_name}!{cell_ref}",
                        "risk": "HIGH",
                    })
                    risk_score += 30

                elif fname in _OBFUSCATION_FUNCTIONS:
                    dangerous.append({
                        "function": fname,
                        "args": f["args"],
                        "source": f"{sheet_name}!{cell_ref}",
                        "risk": "MEDIUM",
                    })
                    risk_score += 5

            # Detect CHAR() concatenation obfuscation
            decoded = _decode_char_concat(formula)
            if decoded and len(decoded) >= 3:
                decoded_strings.append(decoded)
                dangerous.append({
                    "function": "CHAR_CONCAT",
                    "args": decoded,
                    "source": f"{sheet_name}!{cell_ref}",
                    "risk": "HIGH",
                })
                risk_score += 20

            # Anti-sandbox detection
            if _ANTI_SANDBOX_RE.search(formula):
                anti_sandbox = True
                risk_score += 10

    # Also check formulas reported by extractor
    xlm_findings = manifest.get("xlm_findings", {})
    for sheet in xlm_findings.get("sheets", []):
        sheet_name = sheet.get("sheet_name", "unknown")
        if sheet_name not in xlm_sheets:
            xlm_sheets.append(sheet_name)
        for cell in sheet.get("cells", []):
            formula = cell.get("formula", "")
            for sf in cell.get("suspicious_functions", []):
                if sf.upper() in _DANGEROUS_FUNCTIONS:
                    xlm_detected = True
                    dangerous.append({
                        "function": sf.upper(),
                        "args": formula[:200],
                        "source": f"{sheet_name}!{cell.get('ref', '?')}",
                        "risk": "HIGH",
                    })
                    risk_score += 30

    return {
        "xlm_detected": xlm_detected,
        "xlm_functions": list(xlm_functions),
        "xlm_sheets": xlm_sheets,
        "dangerous_functions": dangerous,
        "decoded_strings": decoded_strings,
        "anti_sandbox_detected": anti_sandbox,
        "xlm_risk_score": min(risk_score, 100),
    }
