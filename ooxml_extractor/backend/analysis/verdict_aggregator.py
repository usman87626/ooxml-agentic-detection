"""
verdict_aggregator.py — LLM Task 3: Correlate all signals and produce the final verdict.
Includes retry logic and deterministic verdict floor.
"""
from __future__ import annotations
import asyncio
import logging
import json
import time
import config
from analysis.instructions.loader import load_instruction
from analysis.schema import AnalysisVerdict, SignalGraph, Verdict
from analysis.tools.intent_analyzer import IntentResponse
from analysis.macro_behavior_analyzer import MacroBehaviorResponse

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = load_instruction("aggregator")
_SYSTEM_PROMPT_DECISIVE = load_instruction("aggregator_decisive")

# ---------------------------------------------------------------------------
# Deterministic verdict floor — signals that CANNOT be overridden to CLEAN
# ---------------------------------------------------------------------------
def _apply_verdict_floor(verdict: Verdict, signal_graph: SignalGraph) -> tuple[Verdict, list[str]]:
    """
    Enforce minimum verdict based on deterministic signals.
    Returns (adjusted_verdict, floor_reasons).
    Template injection is NOT enforced (can be legit).
    """
    floor_reasons: list[str] = []

    # --- MALICIOUS floor (these should never be CLEAN) ---
    malicious_floor = False

    # DDE with actual extracted commands = confirmed weaponized
    dde_commands = signal_graph.raw_signals.get("dde", {}).get("dde_commands", [])
    if signal_graph.dde_detected and len(dde_commands) > 0:
        malicious_floor = True
        floor_reasons.append("Deterministic floor: DDE with extracted command payload detected")

    # Known-dangerous ActiveX CLSIDs
    if signal_graph.has_dangerous_activex:
        malicious_floor = True
        floor_reasons.append("Deterministic floor: Dangerous ActiveX CLSID detected")

    # P-code stomping = confirmed evasion technique
    if signal_graph.pcode_stomping_detected:
        malicious_floor = True
        floor_reasons.append("Deterministic floor: VBA P-code stomping detected (compiled code differs from source)")

    if malicious_floor and verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS):
        return Verdict.MALICIOUS, floor_reasons

    # --- SUSPICIOUS floor ---
    suspicious_floor = False

    # XLM macros with dangerous functions
    xlm_dangerous = signal_graph.raw_signals.get("xlm", {}).get("dangerous_functions", [])
    if signal_graph.xlm_detected and len(xlm_dangerous) > 0:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: XLM macros with dangerous functions")

    # Obfuscated macros
    if signal_graph.obfuscation_detected and signal_graph.has_macros:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: Obfuscated VBA macro code")

    # Encrypted VBA project (can't inspect)
    if signal_graph.encrypted_vba_detected:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: Encrypted/locked VBA project cannot be inspected")

    # Embedded high-risk payloads (PE, scripts)
    ole_high_risk = signal_graph.raw_signals.get("ole", {}).get("high_risk_objects", [])
    if len(ole_high_risk) > 0:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: High-risk embedded objects detected")

    # Prompt injection in document
    if signal_graph.prompt_injection_detected:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: Prompt injection attempt detected in document")

    # Macro-less structural attacks
    if signal_graph.macroless_attacks_detected:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: Macro-less structural attack vector detected")

    # HTML/SVG payloads with script content
    if signal_graph.has_html_svg_payloads:
        suspicious_floor = True
        floor_reasons.append("Deterministic floor: Active script content in embedded HTML/SVG")

    if suspicious_floor and verdict == Verdict.CLEAN:
        return Verdict.SUSPICIOUS, floor_reasons

    return verdict, floor_reasons


_GRAPH_PROMPT_ADDENDUM = """SIGNAL GRAPH:
The input includes `signal_graph`, built deterministically from the analyzer outputs. Each node is one signal with a type, a severity (LOW/MEDIUM/HIGH/CRITICAL), a confidence and the artifact it was found in. When present, `edges` link signals by fixed rules (containment, exec_dependency, behavioral, network) and `correlated_chains` lists groups of linked signals. `deterministic_risk_score` (0-100) summarises the evidence.
- Treat linked signals as one coordinated technique and weigh them together.
- Treat isolated low-severity signals as weak evidence on their own.
- The graph and the score are evidence; they do not override the rules above."""


async def aggregate(
    signal_graph: SignalGraph,
    intent_result: IntentResponse,
    macro_result: MacroBehaviorResponse,
    manifest: dict,
    force_decisive_verdict: bool = False,
) -> AnalysisVerdict:
    """
    LLM Task 3: Correlate all signals and produce the final verdict.
    Includes retry logic (config.MAX_LLM_RETRIES) and deterministic verdict floor.

    force_decisive_verdict:
        False (default, app behavior): the aggregator may return
            REQUIRE_NETWORK_ANALYSIS, and a deterministic rule additionally forces
            CLEAN+URLs -> REQUIRE_NETWORK_ANALYSIS.
        True: the aggregator MUST commit to CLEAN / SUSPICIOUS / MALICIOUS. RNA is
            removed from the verdict space (constrained schema + decisive prompt)
            and the deterministic URL->RNA forcing is disabled. Network follow-up is
            still surfaced via the supplementary `needs_web_analysis` flag.
    """
    doc_type = manifest.get("file_metadata", {}).get("detected_doc_type", "Unknown OOXML Document")
    
    signal_summary = signal_graph.model_dump(exclude={"raw_signals"})
    
    aggregator_input = {
        "document_type": doc_type,
        "doc_metadata": signal_graph.doc_metadata,
        "signals": signal_summary,
        "intent_classification": intent_result.model_dump(),
        "macro_behavior_analysis": macro_result.model_dump(),
    }

    # Decisive mode constrains the verdict space to CLEAN/SUSPICIOUS/MALICIOUS so
    # the aggregator must commit; otherwise the app's 4-class schema (incl. RNA) is used.
    from analysis.schema import AggregatorResponse, AggregatorResponseDecisive
    response_schema = AggregatorResponseDecisive if force_decisive_verdict else AggregatorResponse
    system_prompt = _SYSTEM_PROMPT_DECISIVE if force_decisive_verdict else _SYSTEM_PROMPT

    # Signal Graph (Algorithms 2-3): deterministic nodes, edges and risk score.
    graph_mode = getattr(config, "SIGNAL_GRAPH_MODE", "off")
    graph_meta: dict = {"graph_mode": graph_mode}
    det_risk = None
    if graph_mode in ("full", "nodes"):
        from analysis.signal_graph import build_graph
        g = build_graph(signal_graph.model_dump())
        scores = g.scores()
        det_risk = int(round(100 * (scores["graph"] if graph_mode == "full" else scores["nodes"])))
        aggregator_input["signal_graph"] = g.to_prompt(include_edges=(graph_mode == "full"))
        aggregator_input["deterministic_risk_score"] = det_risk
        graph_meta.update({"risk_scores": scores, "graph_stats": g.stats()})
        system_prompt = system_prompt + "\n\n" + _GRAPH_PROMPT_ADDENDUM

    last_error = ""
    for attempt in range(config.MAX_LLM_RETRIES):
        try:
            client = config.get_openai_client()
            response = client.beta.chat.completions.parse(
                model=config.OPENAI_MODEL_AGGREGATOR,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(aggregator_input, indent=2)}
                ],
                response_format=response_schema,
                max_completion_tokens=config.LLM_MAX_COMPLETION_TOKENS_AGGREGATOR,
                temperature=config.LLM_TEMPERATURE,
            )
            llm_data = response.choices[0].message.parsed

            # LLM verdict (normalise to the Verdict enum; decisive schema uses a
            # 3-class enum with identical string values)
            final_verdict = Verdict(llm_data.verdict.value)
            final_reasoning = list(llm_data.reasoning)

            # URL fallback: CLEAN + external URLs → REQUIRE_NETWORK_ANALYSIS
            # (deterministic forcing — disabled in decisive mode so the aggregator's
            #  own decision stands and RNA never replaces the verdict)
            if not force_decisive_verdict and final_verdict == Verdict.CLEAN and signal_graph.all_urls:
                final_verdict = Verdict.REQUIRE_NETWORK_ANALYSIS
                final_reasoning.append("Fallback: Non-whitelisted URLs present. Requiring network analysis.")

            # Apply deterministic verdict floor
            floored_verdict, floor_reasons = _apply_verdict_floor(final_verdict, signal_graph)
            if floored_verdict != final_verdict:
                final_verdict = floored_verdict
                final_reasoning.extend(floor_reasons)

            # Ensure MITRE techniques are populated even if LLM missed them
            mitre_techs = llm_data.mitre_techniques
            if not mitre_techs:
                from analysis.schema import MitreTechnique
                if signal_graph.has_macros or signal_graph.encrypted_vba_detected:
                    mitre_techs.append(MitreTechnique(id="T1059.005", name="Visual Basic", tactic="Execution", description="Document contains VBA macros."))
                if signal_graph.dde_detected or signal_graph.xlm_detected:
                    mitre_techs.append(MitreTechnique(id="T1059", name="Command and Scripting Interpreter", tactic="Execution", description="Legacy execution mechanisms (DDE/XLM) detected."))
                if signal_graph.template_injection_detected or signal_graph.all_urls:
                    mitre_techs.append(MitreTechnique(id="T1221", name="Template Injection", tactic="Defense Evasion", description="External remote references detected."))
                if final_verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) and not mitre_techs:
                    mitre_techs.append(MitreTechnique(id="T1204.002", name="Malicious File", tactic="User Execution", description="User must open the file to trigger any potential action."))

            verdict = AnalysisVerdict(
                verdict=final_verdict,
                confidence=llm_data.confidence,
                risk_score=det_risk if det_risk is not None else llm_data.risk_score,
                intent=llm_data.intent,
                intent_confidence=llm_data.intent_confidence,
                deception=llm_data.deception,
                harm=llm_data.harm,
                reasoning=final_reasoning,
                indicators=llm_data.indicators,
                behavior_profile=llm_data.behavior_profile,
                mitre_techniques=mitre_techs,
                needs_web_analysis=llm_data.needs_web_analysis,
                prompt_injection_detected=llm_data.prompt_injection_detected,
                extracted_iocs=list(set(llm_data.extracted_iocs + signal_graph.all_urls)),
                signal_graph=signal_graph,
                input_data=aggregator_input,
                analysis_metadata={**graph_meta, "llm_risk_estimate": llm_data.risk_score},
            )
            return verdict

        except Exception as e:
            last_error = str(e)
            logger.warning("Verdict aggregation attempt %d/%d failed: %s",
                           attempt + 1, config.MAX_LLM_RETRIES, e)
            if attempt < config.MAX_LLM_RETRIES - 1:
                delay = config.LLM_RETRY_BASE_DELAY * (2 ** attempt)
                logger.info("Retrying in %.1fs...", delay)
                await asyncio.sleep(delay)

    # All retries exhausted — use fallback
    logger.error("All %d LLM retries exhausted. Using deterministic fallback.", config.MAX_LLM_RETRIES)
    fb = _fallback_verdict(signal_graph, intent_result, macro_result,
                           error=last_error, force_decisive_verdict=force_decisive_verdict)
    fb.analysis_metadata.update(graph_meta)
    if det_risk is not None:
        fb.risk_score = det_risk
    return fb


def _fallback_verdict(
    signal: SignalGraph,
    intent: IntentResponse,
    macro: MacroBehaviorResponse,
    error: str = "",
    force_decisive_verdict: bool = False,
) -> AnalysisVerdict:
    """Deterministic fallback for verdict when LLM is unavailable."""
    score = macro.macro_risk_score
    if signal.dde_detected or signal.xlm_detected:
        score = max(score, 80)
    if signal.has_dangerous_activex:
        score = max(score, 90)
    if signal.pcode_stomping_detected:
        score = max(score, 85)
    if signal.encrypted_vba_detected:
        score = max(score, 40)
    if signal.macroless_attacks_detected:
        score = max(score, 35)
    if signal.has_html_svg_payloads:
        score = max(score, 30)
    
    if score >= 60:
        verdict = Verdict.MALICIOUS
    elif score >= 20:
        verdict = Verdict.SUSPICIOUS
    elif not force_decisive_verdict and signal.all_urls:
        verdict = Verdict.REQUIRE_NETWORK_ANALYSIS
    else:
        verdict = Verdict.CLEAN

    # Apply floor even on fallback
    floored_verdict, floor_reasons = _apply_verdict_floor(verdict, signal)
    if floored_verdict != verdict:
        verdict = floored_verdict

    reasoning = [f"Fallback triggered after {config.MAX_LLM_RETRIES} retries. Error: {error}",
                 f"Deterministic risk score: {score}"]
    reasoning.extend(floor_reasons)

    # Deterministic MITRE mapping for fallback
    from analysis.schema import MitreTechnique
    mitre = []
    if signal.has_macros or signal.encrypted_vba_detected:
        mitre.append(MitreTechnique(id="T1059.005", name="Visual Basic", tactic="Execution", description="Document contains VBA macros."))
    if signal.dde_detected or signal.xlm_detected:
        mitre.append(MitreTechnique(id="T1059", name="Command and Scripting Interpreter", tactic="Execution", description="Legacy execution mechanisms (DDE/XLM) detected."))
    if signal.template_injection_detected or signal.all_urls:
        mitre.append(MitreTechnique(id="T1221", name="Template Injection", tactic="Defense Evasion", description="External remote references detected."))
    if not mitre:
        mitre.append(MitreTechnique(id="T1204.002", name="Malicious File", tactic="User Execution", description="User must open the file to trigger any potential action."))

    return AnalysisVerdict(
        verdict=verdict,
        confidence=0.5,
        risk_score=score,
        intent=intent.intent,
        intent_confidence=intent.intent_confidence,
        reasoning=reasoning,
        indicators=macro.macro_indicators,
        mitre_techniques=mitre,
        signal_graph=signal,
        analysis_metadata={"fallback": True, "error": error, "retries_exhausted": True}
    )
