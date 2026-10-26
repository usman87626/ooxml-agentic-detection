"""
deterministic_engine.py — Orchestrate deterministic signal extraction from OOXML manifest.
No LLM calls allowed here. Produces the SignalGraph.
Uses parallel execution via ThreadPoolExecutor for independent tools.
"""
from __future__ import annotations
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from analysis.schema import SignalGraph
from analysis.tools import (
    macro_analyzer,
    ole_analyzer,
    dde_analyzer,
    xlm_analyzer,
    structure_analyzer,
    obfuscation_analyzer,
    template_injection_analyzer,
    prompt_injection_scanner,
    intent_analyzer,
    ooxml_attack_analyzer,
    pcode_analyzer,
    macroless_attack_analyzer,
    url_validator,
    html_svg_analyzer,
)

logger = logging.getLogger(__name__)

# Tool registry: name → (function, manifest_arg)
_TOOLS: dict[str, Any] = {
    "macros":       macro_analyzer.extract_vba,
    "ole":          ole_analyzer.analyze,
    "dde":          dde_analyzer.extract_dde,
    "xlm":          xlm_analyzer.extract_xlm,
    "structure":    structure_analyzer.analyze,
    "obfuscation":  obfuscation_analyzer.extract_obfuscation,
    "t_injection":  template_injection_analyzer.analyze,
    "ooxml_attack": ooxml_attack_analyzer.analyze,
    "p_injection":  prompt_injection_scanner.scan,
    "text_stats":   intent_analyzer.get_text_stats,
    "pcode":        pcode_analyzer.analyze,
    "macroless":    macroless_attack_analyzer.analyze,
    "url_val":      url_validator.analyze,
    "html_svg":     html_svg_analyzer.extract_payloads,
}


def build_signal_graph(manifest: dict) -> SignalGraph:
    """
    Run all deterministic tools in parallel and compile a signal graph.
    Uses ThreadPoolExecutor directly (no asyncio) to avoid nested event loop issues.
    """
    logger.info("Building deterministic signal graph (parallel)")

    results: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="det_tool") as executor:
        # Submit all tools
        future_to_name = {
            executor.submit(fn, manifest): name
            for name, fn in _TOOLS.items()
        }

        # Collect results as they complete
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as e:
                logger.error("Tool %s failed: %s", name, e)
                results[name] = {}

    macros       = results.get("macros", {})
    ole          = results.get("ole", {})
    dde          = results.get("dde", {})
    xlm          = results.get("xlm", {})
    structure    = results.get("structure", {})
    obfuscation  = results.get("obfuscation", {})
    t_injection  = results.get("t_injection", {})
    ooxml_attack = results.get("ooxml_attack", {})
    p_injection  = results.get("p_injection", {})
    text_stats   = results.get("text_stats", {})
    pcode        = results.get("pcode", {})
    macroless    = results.get("macroless", {})
    url_val      = results.get("url_val", {})
    html_svg     = results.get("html_svg", {})

    # Consolidate URLs
    raw_urls = manifest.get("urls", [])
    all_urls = list(set(raw_urls))
    for item in ooxml_attack.get("online_video_details", []):
        for link in item.get("links", []):
            if link not in all_urls:
                all_urls.append(link)
    all_urls = sorted(set(all_urls))
    url_count = len(all_urls)

    # Extract document metadata for LLM context
    file_meta = manifest.get("file_metadata", {})
    doc_metadata = {
        "page_count": file_meta.get("page_count"),
        "slide_count": file_meta.get("slide_count"),
        "word_count": file_meta.get("word_count"),
        "file_size": file_meta.get("size"),
        "filename": file_meta.get("filename"),
        "doc_type": file_meta.get("detected_doc_type"),
    }
    doc_metadata = {k: v for k, v in doc_metadata.items() if v is not None}

    signals = SignalGraph(
        visible_text_length=text_stats.get("visible_text_length", 0),
        intent_candidates=text_stats.get("intent_candidates"),
        has_macros=macros.get("has_macros", False),
        autoexec_keywords=macros.get("autoexec_keywords", []),
        macro_module_count=macros.get("macro_module_count", 0),
        url_count=url_count,
        all_urls=all_urls,
        embedded_objects=ole.get("embedded_object_count", 0),
        binary_types=ole.get("object_types", []),
        dde_detected=dde.get("dde_detected", False),
        xlm_detected=xlm.get("xlm_detected", False),
        obfuscation_detected=obfuscation.get("obfuscation_detected", False),
        template_injection_detected=t_injection.get("template_injection_detected", False),
        prompt_injection_detected=p_injection.get("prompt_injection_detected", False),
        has_online_video=ooxml_attack.get("has_online_video", False),
        has_activex=ooxml_attack.get("has_activex", False),
        has_dangerous_activex=ooxml_attack.get("has_dangerous_activex", False),
        has_rtf_exploits=html_svg.get("has_rtf_exploits", False),
        has_html_svg_payloads=html_svg.get("has_payloads", False),
        has_media_anomalies=structure.get("has_media_anomalies", False),
        content_type_poisoning=structure.get("content_type_poisoning", False),
        encrypted_vba_detected=macros.get("encrypted_vba_detected", False),
        macroless_attacks_detected=macroless.get("detected", False),
        suspicious_urls=url_val.get("suspicious_urls", []),
        pcode_stomping_detected=pcode.get("stomping_detected", False),
        doc_metadata=doc_metadata,
        raw_signals={
            "macros": macros,
            "ole": ole,
            "dde": dde,
            "xlm": xlm,
            "structure": structure,
            "obfuscation": obfuscation,
            "template_injection": t_injection,
            "ooxml_attack": ooxml_attack,
            "prompt_injection": p_injection,
            "text_stats": text_stats,
            "pcode": pcode,
            "macroless": macroless,
            "url_validation": url_val,
            "html_svg": html_svg,
        }
    )
    return signals
