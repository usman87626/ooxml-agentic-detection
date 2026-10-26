"""
template_injection_analyzer.py — Detect OOXML template/remote-content injection.

Covers: CVE-2017-0199, CVE-2022-30190 (Follina), frame injection, subdocument
injection, external links, and dangerous protocol schemes (mhtml:, ms-msdt:).
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Relationship types to check for external injection
# ---------------------------------------------------------------------------
_INJECTION_REL_TYPES: dict[str, str] = {
    # Original — attachedTemplate
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate":
        "attachedTemplate",
    # OLE object external
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject":
        "oleObject",
    # Frame — external frame injection (downloads remote content)
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame":
        "frame",
    # SubDocument — remote sub-document inclusion
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/subDocument":
        "subDocument",
    # External link (Excel)
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink":
        "externalLink",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath":
        "externalLinkPath",
    # aFChunk — alternate frame chunk (remote document inclusion)
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk":
        "aFChunk",
    # Package (remote package fetch)
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/package":
        "package",
    # OLE package
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/olePackage":
        "olePackage",
}

# Dangerous URL protocol schemes
_DANGEROUS_PROTOCOLS: tuple[str, ...] = (
    "mhtml:",         # CVE-2021-40444 variants
    "ms-msdt:",       # Follina (CVE-2022-30190)
    "ms-excel:",      # Excel protocol handler
    "ms-word:",       # Word protocol handler
    "ms-powerpoint:", # PowerPoint protocol handler
    "cid:",           # Content-ID (used in mhtml attacks)
    "\\\\",           # UNC path (SMB relay / credential theft)
)


def analyze(manifest: dict) -> dict:
    """
    Detect remote template/content injection in the OOXML manifest.

    Input:  manifest dict
    Output: structured result with injection URLs, flags, and risk score
    """
    rels_files = manifest.get("rels_files", [])

    injection_urls: list[str] = []
    flags: list[str] = []
    injection_details: list[dict] = []

    for rf in rels_files:
        rels_path = rf.get("path", "")
        for rel in rf.get("relationships", []):
            rel_type = rel.get("type", "")
            target_mode = rel.get("target_mode", "")
            target = rel.get("target", "")

            # Check if this relationship type is one we care about
            rel_label = _INJECTION_REL_TYPES.get(rel_type)

            if rel_label and target_mode == "External" and target:
                injection_urls.append(target)
                flags.append(f"malicious_{rel_label}: {target}")
                injection_details.append({
                    "type": rel_label,
                    "target": target,
                    "rels_file": rels_path,
                    "rel_id": rel.get("rel_id", ""),
                })

            # Also check for OLE objects with external targets (any rel type)
            elif target_mode == "External" and target:
                target_lower = target.lower()
                # Check for dangerous protocol schemes
                for protocol in _DANGEROUS_PROTOCOLS:
                    if target_lower.startswith(protocol):
                        injection_urls.append(target)
                        flags.append(f"dangerous_protocol_{protocol.rstrip(':')}: {target}")
                        injection_details.append({
                            "type": f"dangerous_protocol",
                            "protocol": protocol,
                            "target": target,
                            "rels_file": rels_path,
                            "rel_id": rel.get("rel_id", ""),
                        })
                        break

                # Check for HTTP(S)/FTP external targets in any relationship
                if target_lower.startswith(("http://", "https://", "ftp://")):
                    # Already handled by specific rel types above; only flag
                    # if it wasn't caught by _INJECTION_REL_TYPES
                    if not rel_label:
                        # Generic external relationship — lower severity but noteworthy
                        injection_details.append({
                            "type": "generic_external",
                            "rel_type": rel_type,
                            "target": target,
                            "rels_file": rels_path,
                        })

    detected = len(injection_urls) > 0
    # Score based on severity: each injection is high risk
    score = min(len(injection_urls) * 50, 100) if detected else 0

    return {
        "template_injection_detected": detected,
        "template_injection_score": score,
        "injection_urls": injection_urls,
        "injection_details": injection_details,
        "flags": flags,
    }
