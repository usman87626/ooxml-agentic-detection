"""
dde_analyzer.py — Deep DDE signal extraction from OOXML manifest.

Scans both raw XML (field codes in <w:instrText>, <w:fldSimple>) and
visible text for DDE/DDEAUTO patterns. Extracts the actual command payload.
No LLM logic allowed here.
"""
from __future__ import annotations
import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# DDE / DDEAUTO keyword in any text context
_DDE_RE = re.compile(r"(DDEAUTO|DDE)\s+", re.IGNORECASE)

# XML field instruction patterns — catches DDE inside Word field codes
_INSTR_TEXT_RE = re.compile(
    r'<w:instrText[^>]*>(.*?)</w:instrText>',
    re.IGNORECASE | re.DOTALL,
)
_FLD_SIMPLE_RE = re.compile(
    r'<w:fldSimple\s+w:instr="([^"]*)"',
    re.IGNORECASE | re.DOTALL,
)

# Excel DDE formulas in shared strings or cell values
_EXCEL_DDE_RE = re.compile(
    r'(?:=\s*)?(?:CMD|MSEXCEL)\|[^\'"!]+!\w+',
    re.IGNORECASE,
)
_EXCEL_CELL_DDE_RE = re.compile(
    r'<[a-z]:?v>([^<]*DDE(?:AUTO)?[^<]*)</[a-z]:?v>',
    re.IGNORECASE,
)

# DDE command payload extraction (after DDE/DDEAUTO keyword)
_DDE_COMMAND_RE = re.compile(
    r'(?:DDEAUTO|DDE)\s+(\S+)\s+"?([^"]*)"?',
    re.IGNORECASE,
)


def extract_dde(manifest: dict) -> dict:
    """
    Extract DDE signals from the document manifest using deep XML parsing.

    Output:
        dde_detected: bool
        dde_locations: list[str]
        dde_commands: list[dict]  — extracted command payloads
        dde_field_codes: list[str] — raw field instruction text
    """
    dde_detected = False
    dde_locations: list[str] = []
    dde_commands: list[dict] = []
    dde_field_codes: list[str] = []

    # --- 1. Check entry paths for DDE indicators ---
    for entry in manifest.get("entries", []):
        path = entry.get("path", "")
        if "dde" in path.lower():
            dde_detected = True
            dde_locations.append(f"path: {path}")

    # --- 2. Deep scan raw decoded XML text for field codes ---
    for entry in manifest.get("entries", []):
        path = entry.get("path", "")
        decoded = entry.get("decoded") or {}
        text = decoded.get("decoded_text_utf8", "")
        if not text:
            continue

        # 2a. <w:instrText> elements (Word field instruction fragments)
        instr_fragments = _INSTR_TEXT_RE.findall(text)
        # Reconstruct fragmented instrText (attackers split across multiple tags)
        combined_instr = " ".join(instr_fragments).strip()
        if combined_instr and _DDE_RE.search(combined_instr):
            dde_detected = True
            dde_locations.append(f"instrText: {path}")
            dde_field_codes.append(combined_instr[:500])
            # Extract command
            cmd_match = _DDE_COMMAND_RE.search(combined_instr)
            if cmd_match:
                dde_commands.append({
                    "source": path,
                    "application": cmd_match.group(1),
                    "command": cmd_match.group(2),
                    "raw": combined_instr[:500],
                })

        # 2b. <w:fldSimple> with instr attribute
        for instr in _FLD_SIMPLE_RE.findall(text):
            if _DDE_RE.search(instr):
                dde_detected = True
                dde_locations.append(f"fldSimple: {path}")
                dde_field_codes.append(instr[:500])
                cmd_match = _DDE_COMMAND_RE.search(instr)
                if cmd_match:
                    dde_commands.append({
                        "source": path,
                        "application": cmd_match.group(1),
                        "command": cmd_match.group(2),
                        "raw": instr[:500],
                    })

        # 2c. Excel cell values with DDE
        for cell_match in _EXCEL_CELL_DDE_RE.finditer(text):
            dde_detected = True
            dde_locations.append(f"excel_cell: {path}")
            dde_field_codes.append(cell_match.group(1)[:500])

        # 2d. Excel DDE channel references (CMD|'...'!...)
        for m in _EXCEL_DDE_RE.finditer(text):
            dde_detected = True
            dde_locations.append(f"excel_dde_channel: {path}")
            dde_commands.append({
                "source": path,
                "application": "EXCEL_DDE",
                "command": m.group()[:500],
                "raw": m.group()[:500],
            })

    # --- 3. Scan visible text as fallback ---
    visible_ext = manifest.get("visible_text_extract", {})
    for part, text in visible_ext.items():
        if _DDE_RE.search(text):
            dde_detected = True
            dde_locations.append(f"text_part: {part}")
            cmd_match = _DDE_COMMAND_RE.search(text)
            if cmd_match:
                dde_commands.append({
                    "source": f"text:{part}",
                    "application": cmd_match.group(1),
                    "command": cmd_match.group(2),
                    "raw": text[:500],
                })

    # --- 4. Use extractor-level DDE findings if available ---
    for finding in manifest.get("dde_findings", []):
        snippet = finding.get("snippet", "")
        if snippet:
            dde_detected = True
            dde_locations.append(f"extractor: {finding.get('file_path', 'unknown')}")
            cmd_match = _DDE_COMMAND_RE.search(snippet)
            if cmd_match:
                dde_commands.append({
                    "source": finding.get("file_path", "unknown"),
                    "application": cmd_match.group(1),
                    "command": cmd_match.group(2),
                    "raw": snippet[:500],
                })

    return {
        "dde_detected": dde_detected,
        "dde_locations": list(set(dde_locations)),
        "dde_commands": dde_commands,
        "dde_field_codes": dde_field_codes,
    }
