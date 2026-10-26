"""
pcode_analyzer.py — VBA P-code stomping detection.

Detects discrepancies between VBA source code (readable text) and the compiled
P-code stream. If source is empty/minimal but a substantial P-code binary exists,
or if the source hash diverges from what the P-code represents, it indicates stomping.
"""
from __future__ import annotations
import logging
import hashlib

logger = logging.getLogger(__name__)

# VBA compiled stream markers
_PCODE_STREAM_NAMES = frozenset({
    '__SRP_0', '__SRP_1', '__SRP_2', '__SRP_3',
    '_VBA_PROJECT',
})

# Typical compiled module stream prefix
_MODULE_STREAM_MAGIC = b'\x01\x16'


def analyze(manifest: dict) -> dict:
    """
    Detect VBA P-code stomping by comparing source code vs compiled state.

    Stomping indicators:
    1. VBA containers exist with modules that have empty/trivial code
       but the OLE container has substantial binary streams
    2. Source is minimal but OLE streams are large (compiled P-code)
    3. DPB= encrypted project with no extractable source
    """
    macros = manifest.get("macros", {})
    results = macros.get("results", [])

    stomping_detected = False
    stomping_evidence: list[str] = []
    module_analysis: list[dict] = []

    for r in results:
        archive_path = r.get("archive_path", "")
        modules = r.get("modules", [])
        is_locked = r.get("is_vba_locked", False)
        error = r.get("error", "")

        # Get OLE stream info for this container from embedded objects
        ole_streams = []
        for obj in manifest.get("embedded_objects", []):
            if obj.get("archive_path") == archive_path:
                ole_streams = obj.get("ole_streams", [])
                break

        # Calculate total source code size
        total_source_chars = sum(len(m.get("code", "")) for m in modules)

        # Calculate vba binary stream sizes
        binary_stream_size = 0
        has_srp_streams = False
        for stream in ole_streams:
            name = stream.get("name", "")
            size = stream.get("size", 0)
            if any(srp in name.upper() for srp in _PCODE_STREAM_NAMES):
                has_srp_streams = True
                binary_stream_size += size

        # --- Stomping indicator 1: VBA container detected, code is empty/trivial ---
        if modules and total_source_chars < 50 and binary_stream_size > 500:
            stomping_detected = True
            stomping_evidence.append(
                f"{archive_path}: Source is trivial ({total_source_chars} chars) "
                f"but compiled P-code streams total {binary_stream_size} bytes"
            )

        # --- Stomping indicator 2: No modules extracted but container has VBA/SRP streams ---
        if not modules and not is_locked and not error:
            # Container found but olevba couldn't extract — possible stomping ONLY IF there's binary P-code
            if binary_stream_size > 0 or has_srp_streams:
                stomping_detected = True
                stomping_evidence.append(
                    f"{archive_path}: VBA container exists but no source modules extracted (possible stomping)"
                )

        # --- Stomping indicator 3: Modules present with SRP streams ---
        if modules and has_srp_streams:
            # SRP streams contain pre-compiled P-code cache
            for m in modules:
                code = m.get("code", "")
                code_hash = hashlib.md5(code.encode()).hexdigest()[:8]
                module_analysis.append({
                    "module": m.get("module_name", "unknown"),
                    "source_chars": len(code),
                    "source_hash": code_hash,
                    "container": archive_path,
                })

            # If source is suspiciously small relative to SRP cache
            if total_source_chars < 200 and binary_stream_size > 2000:
                stomping_detected = True
                stomping_evidence.append(
                    f"{archive_path}: Disproportionate P-code cache ({binary_stream_size} bytes) "
                    f"vs source ({total_source_chars} chars)"
                )

        # --- Stomping indicator 4: Encrypted project with no code ---
        if is_locked and total_source_chars == 0:
            stomping_evidence.append(
                f"{archive_path}: Encrypted VBA project with no extractable source"
            )

    return {
        "stomping_detected": stomping_detected,
        "stomping_evidence": stomping_evidence,
        "module_analysis": module_analysis,
    }
