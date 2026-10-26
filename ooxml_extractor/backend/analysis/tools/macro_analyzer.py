"""
macro_analyzer.py — Deterministic macro (VBA) signal extraction.
No LLM logic allowed here.
"""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

def extract_vba(manifest: dict) -> dict:
    """
    Extract VBA macro signals from the document manifest.
    
    Output:
        has_macros: bool
        macro_paths: list[str]
        autoexec_keywords: list[str]
        macro_modules: list[dict]
        macro_code: str (concatenated for LLM)
        macro_module_count: int
        suspicious_keywords: list[str]
    """
    macros = manifest.get("macros", {})
    containers = macros.get("containers_found", [])
    results = macros.get("results", [])

    if not containers:
        return {
            "has_macros": False,
            "macro_paths": [],
            "autoexec_keywords": [],
            "macro_modules": [],
            "macro_code": "",
            "macro_module_count": 0,
            "suspicious_keywords": [],
            "ioc_keywords": [],
        }

    all_modules: list[dict] = []
    all_code_chunks: list[str] = []
    auto_exec_keywords = set()
    suspicious_keywords = set()
    ioc_keywords = set()

    for r in results:
        for m in r.get("modules", []):
            module_name = m.get("module_name", "unknown")
            module_type = m.get("module_type", "unknown")
            code = m.get("code", "")
            
            all_code_chunks.append(code)
            all_modules.append({
                "name": module_name,
                "type": module_type,
                "code": code
            })
            
            for kw in m.get("auto_exec_keywords", []):
                auto_exec_keywords.add(kw)
            for kw in m.get("suspicious_keywords", []):
                suspicious_keywords.add(kw)
            for kw in m.get("ioc_keywords", []):
                ioc_keywords.add(kw)

    all_code = "\n\n".join(all_code_chunks)

    # Check for encrypted/locked VBA projects
    encrypted_vba = any(r.get("is_vba_locked", False) for r in results)

    return {
        "has_macros": True,
        "macro_paths": containers,
        "autoexec_keywords": list(auto_exec_keywords),
        "macro_modules": all_modules,
        "macro_code": all_code,
        "macro_module_count": len(all_modules),
        "suspicious_keywords": list(suspicious_keywords),
        "ioc_keywords": list(ioc_keywords),
        "encrypted_vba_detected": encrypted_vba,
    }
