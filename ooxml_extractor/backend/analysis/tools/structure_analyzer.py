"""
structure_analyzer.py — OOXML structural anomaly detection (deterministic).
"""
from __future__ import annotations

_HYPERLINK_TYPE         = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
_EXTERNAL_LINK_TYPE     = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink"
_OLE_OBJECT_TYPE        = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
_IMAGE_TYPE             = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"

# Suspicious entry path patterns
_SUSPICIOUS_PATH_PATTERNS = [
    ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js",
    ".hta", ".cmd", ".pif", ".com",
]


def analyze(manifest: dict) -> dict:
    """
    Detect structural anomalies in the OOXML manifest.

    Input:  manifest dict
    Output: structured result
    """
    flags: list[str] = []
    score = 0

    entries   = manifest.get("entries", [])
    rels_files = manifest.get("rels_files", [])
    summary   = manifest.get("summary", {})

    # ── Suspicious entry paths ──────────────────────────────────────────────
    for entry in entries:
        path = entry.get("path", "").lower()
        for pattern in _SUSPICIOUS_PATH_PATTERNS:
            if path.endswith(pattern):
                flags.append(f"suspicious_path: {entry['path']}")
                score += 30

    # ── Excessive external hyperlinks ───────────────────────────────────────
    external_links: list[str] = []
    for rf in rels_files:
        for rel in rf.get("relationships", []):
            if rel.get("type") == _HYPERLINK_TYPE and rel.get("is_external"):
                external_links.append(rel.get("external_url", rel.get("target", "")))
    if len(external_links) > 10:
        flags.append(f"excessive_external_links: {len(external_links)}")
        score += 15

    # ── External OLE objects ────────────────────────────────────────────────
    ole_external: list[str] = []
    for rf in rels_files:
        for rel in rf.get("relationships", []):
            if rel.get("type") == _OLE_OBJECT_TYPE and rel.get("target_mode") == "External":
                ole_external.append(rel.get("target", ""))
                flags.append(f"external_ole_object: {rel.get('target', '')}")
                score += 40

    # ── Deeply nested ZIP entries (may indicate zip-in-zip) ─────────────────
    deep_entries = [e["path"] for e in entries if e.get("path", "").count("/") > 6]
    if deep_entries:
        flags.append(f"deep_nesting: {len(deep_entries)} entries")
        score += 10

    # ── Encrypted entries ───────────────────────────────────────────────────
    encrypted = [e["path"] for e in entries if e.get("is_encrypted")]
    if encrypted:
        flags.append(f"encrypted_entries: {len(encrypted)}")
        score += 20 * len(encrypted)

    # ── Duplicate SHA256 across entries (same content, different names) ─────
    sha_map: dict[str, list[str]] = {}
    for e in entries:
        sha = e.get("sha256", "")
        if sha:
            sha_map.setdefault(sha, []).append(e.get("path", ""))
    duplicates = {sha: paths for sha, paths in sha_map.items() if len(paths) > 1 and sha}
    if len(duplicates) > 3:
        flags.append(f"many_duplicate_entries: {len(duplicates)} groups")
        score += 10

    return {
        "anomaly_score": min(score, 100),
        "flags": flags,
        "ole_external": ole_external,
        "external_links_count": len(external_links),
        "encrypted_entries": encrypted,
        "suspicious_paths": [f for f in flags if f.startswith("suspicious_path:")],
    }
