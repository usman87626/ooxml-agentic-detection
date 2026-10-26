"""
obfuscation_analyzer.py — Deterministic obfuscation signal extraction.

Detects both basic encoding patterns (base64, hex, chr) AND semantic VBA
obfuscation techniques (StrReverse, CallByName, Replace chains, Environ, WMI).
No LLM logic allowed here.
"""
from __future__ import annotations
import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Basic encoding patterns
# ---------------------------------------------------------------------------
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_CHR_RE = re.compile(r"(?:chr\W?\d+\W?[\\&\+]\W?){3,}", re.IGNORECASE)
_HEX_RE = re.compile(r"(?:0x[0-9a-fA-F]{2,},?\s*){5,}")

# ---------------------------------------------------------------------------
# VBA semantic obfuscation patterns
# ---------------------------------------------------------------------------
# StrReverse usage
_STRREVERSE_RE = re.compile(r"\bStrReverse\s*\(", re.IGNORECASE)

# CallByName invocations (indirect function calls to evade keyword detection)
_CALLBYNAME_RE = re.compile(r"\bCallByName\s*\(", re.IGNORECASE)

# Replace() chains — 3+ sequential Replace calls (string reconstruction)
_REPLACE_RE = re.compile(r"(?:Replace\s*\([^)]+\)\s*,?\s*){2,}", re.IGNORECASE)
_REPLACE_SINGLE_RE = re.compile(r"\bReplace\s*\(", re.IGNORECASE)

# Environ() calls — indirect command resolution
_ENVIRON_RE = re.compile(r"\bEnviron\s*\(", re.IGNORECASE)

# Mid/Left/Right string construction — 5+ uses suggest string building
_STRING_FUNC_RE = re.compile(r"\b(?:Mid|Left|Right)\s*\(", re.IGNORECASE)

# Chr() with arithmetic (e.g., Chr(Asc("A") + 3))
_CHR_ARITH_RE = re.compile(r"\bChr\w?\s*\(\s*(?:Asc|CLng|CInt|\d+\s*[\+\-\*])", re.IGNORECASE)

# Shell via WMI (winmgmts dispatch for process creation)
_WMI_RE = re.compile(r'(?:GetObject|CreateObject)\s*\(\s*["\']winmgmts:', re.IGNORECASE)

# CreateObject with shell-like progIDs
_CREATEOBJECT_SHELL_RE = re.compile(
    r'CreateObject\s*\(\s*["\'](?:WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject'
    r'|MSXML2\.XMLHTTP|Microsoft\.XMLHTTP|ADODB\.Stream|Schedule\.Service)["\']',
    re.IGNORECASE,
)

# PowerShell encoded command patterns
_PS_ENCODED_RE = re.compile(
    r'(?:-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{20,})',
    re.IGNORECASE,
)

# String concatenation abuse — many short string concat operators
_CONCAT_ABUSE_RE = re.compile(r'(?:["\'][^"\']{0,3}["\'][\s]*&[\s]*){5,}')


def _count_matches(pattern: re.Pattern, text: str) -> int:
    """Count all non-overlapping matches of pattern in text."""
    return len(pattern.findall(text))


def extract_obfuscation(manifest: dict) -> dict:
    """
    Extract obfuscation signals from the document manifest.

    Output:
        obfuscation_detected: bool
        obfuscation_types: list[str]
        obfuscation_locations: list[str]
        obfuscation_details: list[dict]  — per-technique breakdown
    """
    obf_detected = False
    obf_types: set[str] = set()
    obf_locations: list[str] = []
    obf_details: list[dict] = []

    def _check(pattern: re.Pattern, label: str, text: str, source: str, threshold: int = 1):
        nonlocal obf_detected
        count = _count_matches(pattern, text)
        if count >= threshold:
            obf_detected = True
            obf_types.add(label)
            obf_locations.append(source)
            obf_details.append({"technique": label, "count": count, "source": source})

    # --- Scan macro code ---
    macros = manifest.get("macros", {})
    for r in macros.get("results", []):
        for m in r.get("modules", []):
            code = m.get("code", "")
            src = f"macro:{m.get('module_name', 'unknown')}"

            # Basic encoding
            _check(_B64_RE, "base64", code, src)
            _check(_CHR_RE, "chr_chain", code, src)
            _check(_HEX_RE, "hex_array", code, src)

            # Semantic VBA obfuscation
            _check(_STRREVERSE_RE, "str_reverse", code, src)
            _check(_CALLBYNAME_RE, "call_by_name", code, src)
            _check(_REPLACE_SINGLE_RE, "replace_chains", code, src, threshold=3)
            _check(_ENVIRON_RE, "environ_call", code, src)
            _check(_STRING_FUNC_RE, "string_func_construction", code, src, threshold=15)
            _check(_CHR_ARITH_RE, "chr_arithmetic", code, src)
            _check(_WMI_RE, "wmi_shell", code, src)
            _check(_CREATEOBJECT_SHELL_RE, "createobject_shell", code, src)
            _check(_PS_ENCODED_RE, "powershell_encoded", code, src)
            _check(_CONCAT_ABUSE_RE, "string_concat_abuse", code, src, threshold=2)

    # --- Scan visible text ---
    visible_ext = manifest.get("visible_text_extract", {})
    for part, text in visible_ext.items():
        src = f"text_part:{part}"
        _check(_B64_RE, "base64", text, src)
        _check(_PS_ENCODED_RE, "powershell_encoded", text, src)

    # --- Scan decoded XML/text entries for hidden obfuscation ---
    for entry in manifest.get("entries", []):
        decoded = entry.get("decoded") or {}
        text = decoded.get("decoded_text_utf8", "")
        if not text or len(text) < 50:
            continue
        path = entry.get("path", "")
        # Only scan non-standard content parts for obfuscation
        if any(x in path.lower() for x in ("/customxml/", "/embeddings/", "/activex/")):
            _check(_B64_RE, "base64_in_xml", text, f"entry:{path}")
            _check(_HEX_RE, "hex_in_xml", text, f"entry:{path}")

    return {
        "obfuscation_detected": obf_detected,
        "obfuscation_types": list(obf_types),
        "obfuscation_locations": obf_locations,
        "obfuscation_details": obf_details,
    }
