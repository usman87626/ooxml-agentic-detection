"""
dde_detector.py — DDE / DDEAUTO pattern scanning across OOXML XML parts.

Scans decoded text for DDE field instructions.
All findings are pure metadata — no verdict is assigned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Core DDE/DDEAUTO keyword patterns (case-insensitive)
_DDE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bDDEAUTO\b", re.IGNORECASE),
    re.compile(r"\bDDE\b(?!\s*AUTO)", re.IGNORECASE),  # DDE but not DDEAUTO (already caught above)
    # Word field instructions containing DDE
    re.compile(r"\{[^}]*DDE(?:AUTO)?\b[^}]*\}", re.IGNORECASE | re.DOTALL),
    # XML field instruction tags common in Word
    re.compile(r'<w:instrText[^>]*>[^<]*DDE(?:AUTO)?\b[^<]*</w:instrText>', re.IGNORECASE | re.DOTALL),
    # Excel shared strings / cell values with DDE
    re.compile(r'<v>[^<]*DDE(?:AUTO)?[^<]*</v>', re.IGNORECASE),
    # Excel formula-like DDE references
    re.compile(r'=\s*DDE(?:AUTO)?\s*\(', re.IGNORECASE),
    # PowerPoint / generic XML field code
    re.compile(r'<a:fld[^>]*>[^<]*DDE[^<]*</a:fld>', re.IGNORECASE | re.DOTALL),
]

# Contextual snippets to also capture (Excel cell/CONCAT patterns)
_CONTEXT_PATTERNS: list[re.Pattern] = [
    re.compile(r'DDEAUTO\s+\S+\s+"[^"]*"', re.IGNORECASE),
    re.compile(r'DDE\s+\S+\s+\S+\s+"[^"]*"', re.IGNORECASE),
]

_SNIPPET_WINDOW = 150  # chars each side of match


@dataclass
class DdeFinding:
    """A single DDE / DDEAUTO occurrence in an OOXML part."""

    # Archive path where the finding was made
    file_path: str

    # The matched text (bounded)
    snippet: str

    # Byte offset in the decoded text where the match starts
    offset: int

    # Which pattern matched (for triage)
    pattern_label: str = ""


def scan_for_dde(
    file_path: str,
    decoded_text: str,
) -> list[DdeFinding]:
    """
    Scan *decoded_text* from *file_path* for DDE/DDEAUTO patterns.

    Returns a list of :class:`DdeFinding`.  An empty list means no patterns
    were found; this is not a verdict (the caller must not infer safety).
    """
    findings: list[DdeFinding] = []
    seen_offsets: set[int] = set()

    for pattern in _DDE_PATTERNS:
        for m in pattern.finditer(decoded_text):
            start = m.start()
            if start in seen_offsets:
                continue
            seen_offsets.add(start)

            # Extract bounded context snippet
            snippet_start = max(0, start - _SNIPPET_WINDOW)
            snippet_end = min(len(decoded_text), m.end() + _SNIPPET_WINDOW)
            snippet = decoded_text[snippet_start:snippet_end].strip()

            findings.append(
                DdeFinding(
                    file_path=file_path,
                    snippet=snippet[:500],  # hard cap
                    offset=start,
                    pattern_label=pattern.pattern[:60],
                )
            )

    return findings


def scan_entries(
    entries: dict[str, str],  # {archive_path: decoded_text}
    *,
    xml_only: bool = True,
) -> list[DdeFinding]:
    """
    Scan all entries in *entries* for DDE patterns.

    *xml_only* (default True) limits scanning to .xml / .rels files,
    which covers all known DDE injection surfaces in OOXML.
    Set to False to also scan plain-text entries.
    """
    all_findings: list[DdeFinding] = []

    for path, text in entries.items():
        if not text:
            continue
        if xml_only and not (path.lower().endswith(".xml") or path.lower().endswith(".rels")):
            continue
        findings = scan_for_dde(path, text)
        all_findings.extend(findings)

    return all_findings
