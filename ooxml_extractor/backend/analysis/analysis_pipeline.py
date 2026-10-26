"""
analysis_pipeline.py — Orchestrate the full agentic analysis pipeline.

Pipeline:
  Manifest → Planner → Executor → Correlation → Aggregator → AnalysisVerdict

Saves results to workspace:
  analysis/verdict.json
  analysis/analysis_status.json
"""
from __future__ import annotations
import asyncio
import json
import logging
import time

from analysis.schema import AnalysisStatus, AnalysisVerdict, SignalGraph
from analysis import deterministic_engine, macro_behavior_analyzer, verdict_aggregator
from analysis.tools import intent_analyzer
from storage import workspace as ws

logger = logging.getLogger("analysis.pipeline")


def _save_status(workspace_id: str, status: AnalysisStatus, extra: dict | None = None) -> None:
    data: dict = {"analysis_status": status.value}
    if extra:
        data.update(extra)
    path = ws.get_workspace_path(workspace_id) / "analysis" / "analysis_status.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _save_verdict(workspace_id: str, verdict: AnalysisVerdict) -> None:
    path = ws.get_workspace_path(workspace_id) / "analysis" / "verdict.json"
    path.write_text(verdict.model_dump_json(indent=2), encoding="utf-8")


def load_analysis_status(workspace_id: str) -> dict:
    try:
        path = ws.get_workspace_path(workspace_id) / "analysis" / "analysis_status.json"
        if not path.exists():
            return {"analysis_status": "idle"}
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"analysis_status": "idle"}


def load_verdict(workspace_id: str) -> dict:
    try:
        path = ws.get_workspace_path(workspace_id) / "analysis" / "verdict.json"
        if not path.exists():
            raise FileNotFoundError("No verdict.json found")
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to load verdict: {e}") from e


async def run_pipeline(workspace_id: str) -> AnalysisVerdict:
    """
    Execute the simplified, direct analysis pipeline:
    Manifest -> Deterministic Engine -> Signal Graph -> LLM Analysis -> Final Verdict.
    """
    t_pipeline_start = time.perf_counter()
    logger.info("[%s] Simplified analysis pipeline starting", workspace_id)

    # 1. Load manifest
    try:
        raw = ws.load_manifest(workspace_id)
        manifest = json.loads(raw)
    except Exception as e:
        _save_status(workspace_id, AnalysisStatus.error, {"error": str(e)})
        raise

    _save_status(workspace_id, AnalysisStatus.running, {"stage": "deterministic_tools"})

    # 2. Stage A: Deterministic Tool Engine -> Signal Graph
    t0 = time.perf_counter()
    signal_graph = deterministic_engine.build_signal_graph(manifest)
    deterministic_ms = round((time.perf_counter() - t0) * 1000, 1)
    
    _save_status(workspace_id, AnalysisStatus.running, {
        "stage": "intent_analysis",
        "has_macros": signal_graph.has_macros,
        "deterministic_ms": deterministic_ms,
    })

    # 3. Stage B: LLM Task 1 — Intent Classification (any visible text)
    t0 = time.perf_counter()
    intent_result = None
    if signal_graph.visible_text_length > 0:
        doc_type = manifest.get("file_metadata", {}).get("detected_doc_type", "Unknown")
        intent_result = await intent_analyzer.classify_intent(
            signal_graph.raw_signals["text_stats"]["visible_text"],
            doc_type=doc_type
        )
    intent_ms = round((time.perf_counter() - t0) * 1000, 1)

    _save_status(workspace_id, AnalysisStatus.running, {
        "stage": "macro_behavior_analysis",
        "intent_ms": intent_ms,
    })

    # 4. Stage C: LLM Task 2 — Macro Behavior Analysis (always when macros present)
    t0 = time.perf_counter()
    macro_result = None
    if signal_graph.has_macros:
        doc_type = manifest.get("file_metadata", {}).get("detected_doc_type", "Unknown")
        macro_result = await macro_behavior_analyzer.analyze_behavior(
            signal_graph.raw_signals["macros"]["macro_code"],
            signal_graph.raw_signals["macros"].get("ioc_keywords", []),
            doc_type=doc_type
        )
    macro_ms = round((time.perf_counter() - t0) * 1000, 1)

    _save_status(workspace_id, AnalysisStatus.running, {
        "stage": "verdict_aggregation",
        "macro_ms": macro_ms,
    })

    # 5. Stage D: LLM Task 3 — Correlation + Verdict
    t0 = time.perf_counter()
    # Provide dummy objects if tasks were skipped to satisfy aggregator interface
    intent_final = intent_result or intent_analyzer.IntentResponse(
        intent="skipped_low_density", 
        intent_confidence=0.0, 
        risk_keywords=[],
        explanation="Text too short for reliable intent classification."
    )
    macro_final = macro_result or macro_behavior_analyzer.MacroBehaviorResponse(macro_behavior="skipped_no_autoexec", macro_risk_score=0, macro_indicators=[])
    
    verdict = await verdict_aggregator.aggregate(
        signal_graph,
        intent_final,
        macro_final,
        manifest
    )
    aggregator_ms = round((time.perf_counter() - t0) * 1000, 1)

    # 6. Final Enrichment & Save
    total_ms = round((time.perf_counter() - t_pipeline_start) * 1000, 1)
    verdict.analysis_metadata.update({
        "total_pipeline_ms": total_ms,
        "deterministic_ms": deterministic_ms,
        "intent_ms": intent_ms,
        "macro_ms": macro_ms,
        "aggregator_ms": aggregator_ms,
        "workspace_id": workspace_id,
        "pipeline_version": "2.0-deterministic-first"
    })
    
    # Save the agent trace files for UI transparency
    ws_dir = ws.get_workspace_path(workspace_id)
    analysis_dir = ws_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    with open(analysis_dir / "signal_graph.json", "w", encoding="utf-8") as f:
        f.write(signal_graph.model_dump_json(indent=2))

    with open(analysis_dir / "agent_intent.json", "w", encoding="utf-8") as f:
        f.write(intent_final.model_dump_json(indent=2))

    with open(analysis_dir / "agent_macro_behavior.json", "w", encoding="utf-8") as f:
        f.write(macro_final.model_dump_json(indent=2))

    with open(analysis_dir / "agent_aggregator.json", "w", encoding="utf-8") as f:
        f.write(verdict.model_dump_json(indent=2))

    _save_verdict(workspace_id, verdict)
    _save_status(workspace_id, AnalysisStatus.done, {
        "verdict": verdict.verdict.value,
        "risk_score": verdict.risk_score,
        "total_ms": total_ms,
    })

    return verdict
