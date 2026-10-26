"""
prompt_injection_scanner.py — Scan document text for prompt injection patterns.
"""
from __future__ import annotations

from agents.guardrails import contains_prompt_injection, _INJECTION_PATTERNS, strip_xml_tags_and_normalize


def _collect_all_text(manifest: dict) -> str:
    """Pull decoded text from entries + macro code into one string."""
    parts: list[str] = []
    for entry in manifest.get("entries", []):
        decoded = entry.get("decoded") or {}
        raw_text = decoded.get("decoded_text_utf8", "")
        if raw_text:
            parts.append(strip_xml_tags_and_normalize(raw_text))
    for r in manifest.get("macros", {}).get("results", []):
        for m in r.get("modules", []):
            parts.append(m.get("code", ""))
    return "\n".join(p for p in parts if p)


def scan(manifest: dict) -> dict:
    """
    Scan all document text for prompt injection attempt patterns.

    Input:  manifest dict
    Output: structured result
    """
    text = _collect_all_text(manifest)

    if not text.strip():
        return {
            "prompt_injection_score": 0,
            "prompt_injection_detected": False,
            "evidence_snippets": [],
        }

    detected, snippets = contains_prompt_injection(text)

    # Score proportional to number of unique pattern matches (cap 100)
    score = min(len(snippets) * 25, 100)

    return {
        "prompt_injection_score": score,
        "prompt_injection_detected": detected,
        "evidence_snippets": snippets[:10],
    }
