"""
ole_analyzer.py — Analyze embedded objects with raw byte verification.

Re-classifies OLE objects from raw bytes at analysis time using
attack_utils.classify_embedded_blob() for independent verification,
in addition to trusting manifest metadata.
"""
from __future__ import annotations
import base64
import logging

from analysis.tools.attack_utils import estimate_entropy, classify_embedded_blob, guess_mime_from_magic

logger = logging.getLogger(__name__)

_HIGH_RISK_TYPES: frozenset[str] = frozenset({
    "pe_executable", "pe_dll", "binary_executable",
    "ole_package", "ole_embedded",
    "javascript_code", "powershell_script",
    "rtf_document", "hta_document",
    "PE Executable", "ELF Executable",
})

_MED_RISK_TYPES: frozenset[str] = frozenset({
    "pdf_document", "vba_macro_container",
    "excel_binary_workbook", "zip_archive",
    "archive_7z", "archive_tar",
    "OLE Compound Document", "PDF Document",
    "RTF Document", "HTML Document",
    "ZIP / OOXML Archive",
})


def _verify_from_raw_bytes(base64_data: str) -> dict | None:
    """
    Decode base64 raw bytes from manifest and re-classify using attack_utils.

    Returns classification dict or None if data not available.
    """
    if not base64_data:
        return None
    try:
        raw = base64.b64decode(base64_data)
    except Exception:
        return None

    if len(raw) < 8:
        return None

    is_risky, mime_hint, ext_hint = classify_embedded_blob(raw)
    entropy = estimate_entropy(raw)
    mime_from_magic, _ = guess_mime_from_magic(raw)

    return {
        "is_risky": is_risky,
        "mime_hint": mime_hint,
        "ext_hint": ext_hint,
        "entropy": round(entropy, 2),
        "magic_mime": mime_from_magic,
        "raw_size": len(raw),
    }


def analyze(manifest: dict) -> dict:
    """
    Analyze embedded objects using advanced heuristics (entropy, recursive classification).

    Re-classifies from raw bytes when available for independent verification,
    not just trusting manifest metadata.
    """
    objects: list[dict] = manifest.get("embedded_objects", [])

    if not objects:
        return {
            "embedded_object_count": 0,
            "embedded_payload_detected": False,
            "object_types": [],
            "risk_score": 0,
            "high_risk_objects": [],
        }

    results: list[dict] = []
    high_risk: list[dict] = []
    med_risk: list[dict] = []
    total_risk_score = 0
    verified_objects: list[dict] = []

    # Build a lookup from entry path → raw_bytes_base64 for re-classification
    entry_bytes_map: dict[str, str] = {}
    for entry in manifest.get("entries", []):
        b64 = entry.get("raw_bytes_base64", "")
        if b64:
            entry_bytes_map[entry.get("path", "")] = b64

    for obj in objects:
        path = obj.get("archive_path", "unknown")
        dtype = (obj.get("detected_type") or "unknown").lower()
        size = obj.get("size", 0)

        is_risky = False
        risk_level = "LOW"

        # --- 1. Manifest-based classification ---
        if dtype in _HIGH_RISK_TYPES or dtype.lower() in {t.lower() for t in _HIGH_RISK_TYPES}:
            is_risky = True
            risk_level = "HIGH"
            total_risk_score += 40
        elif dtype in _MED_RISK_TYPES or dtype.lower() in {t.lower() for t in _MED_RISK_TYPES}:
            is_risky = True
            risk_level = "MED"
            total_risk_score += 15

        # --- 2. Raw byte re-verification ---
        raw_b64 = entry_bytes_map.get(path, "")
        byte_verification = _verify_from_raw_bytes(raw_b64)

        if byte_verification:
            verified_objects.append({
                "path": path,
                "manifest_type": dtype,
                "raw_byte_analysis": byte_verification,
            })

            # If raw bytes say it's risky but manifest didn't catch it → escalate
            if byte_verification["is_risky"] and not is_risky:
                is_risky = True
                risk_level = "HIGH (raw-byte-escalated)"
                total_risk_score += 40

            # High entropy on an already-risky object → extra concern
            if byte_verification.get("entropy", 0) >= 7.5 and is_risky:
                total_risk_score += 10
                risk_level += "+HIGH_ENTROPY"

            # Flag discrepancy between manifest type and raw classification
            if byte_verification.get("mime_hint") and byte_verification["mime_hint"] != "application/octet-stream":
                raw_mime = byte_verification["mime_hint"]
                if raw_mime and "dosexec" in raw_mime and "executable" not in dtype:
                    is_risky = True
                    risk_level = "HIGH (PE-mismatch)"
                    total_risk_score += 50

        if is_risky:
            risk_entry = {
                "archive_path": path,
                "detected_type": dtype,
                "risk_level": risk_level,
                "size": size,
                "sha256": obj.get("sha256", ""),
                "byte_verification": byte_verification,
            }
            # Only truly dangerous objects go to high_risk (PE, scripts, etc.)
            # Generic OLE/PDF/ZIP go to medium_risk — they shouldn't trigger the verdict floor
            if "HIGH" in risk_level:
                high_risk.append(risk_entry)
            else:
                med_risk.append(risk_entry)

        results.append({
            "path": path,
            "type": dtype,
            "risk": risk_level,
        })

    return {
        "embedded_object_count": len(objects),
        "embedded_payload_detected": len(high_risk) > 0,
        "high_risk_objects": high_risk,
        "medium_risk_objects": med_risk,
        "object_summary": results,
        "risk_score": min(total_risk_score, 100),
        "verified_objects": verified_objects,
    }
