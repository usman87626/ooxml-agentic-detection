#!/usr/bin/env python3
"""
02_run_reasoning.py — Stage 2: agentic LLM reasoning over the labelled dataset.

Replays each record from 01_build_dataset.py through the EXACT production
reasoning path used by analysis_pipeline.run_pipeline():

    Intent classifier  (analysis.tools.intent_analyzer.classify_intent)
    Macro analyzer     (analysis.macro_behavior_analyzer.analyze_behavior)
    Verdict aggregator (analysis.verdict_aggregator.aggregate)  + deterministic floor

Same YAML system prompts, same Pydantic schemas, same retry/backoff, same floor.
The only addition is instrumentation: per-sample wall time, prompt/completion
tokens, and USD cost (via _common.UsageRecorder + pricing table).

NO INFO LEAKAGE: only the signal graph (which never contains the label) is fed
to the model. The `label` field is used solely to tag the output row for the
evaluator — it is never placed in a prompt.

Output: results/<run_id>/predictions.jsonl + results/<run_id>/run_meta.json

Usage:
  python 02_run_reasoning.py --dataset data/labelled_dataset.jsonl
  python 02_run_reasoning.py --dataset data/labelled_dataset.jsonl --run-id baseline_4omini
  python 02_run_reasoning.py ... --model-analysis gpt-4o-mini --model-aggregator gpt-4o-mini
  python 02_run_reasoning.py ... --limit 10 --resume
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import _common
_common.bootstrap_backend()

log = logging.getLogger("experiments.reason")

import config  # noqa: E402
from analysis.schema import SignalGraph  # noqa: E402
from analysis.tools import intent_analyzer  # noqa: E402
from analysis import macro_behavior_analyzer, verdict_aggregator  # noqa: E402


def _floor_applied(reasoning: list[str]) -> bool:
    return any(isinstance(r, str) and r.startswith("Deterministic floor:") for r in reasoning)


MASKED_DOC_TYPE = "Unknown OOXML Document"


async def reason_over_sample(rec: dict, recorder: "_common.UsageRecorder",
                             neutralize_filename: bool = True, mask_doc_type: bool = False) -> dict:
    """Run the 3 agents over one dataset record, mirroring run_pipeline()."""
    sg_dump = rec.get("signal_graph")
    out: dict = {
        "filename": rec["filename"],
        "sha256": rec.get("sha256", ""),
        "label": rec["label"],
        "doc_type": rec.get("doc_type", "Unknown"),
        "file_size": rec.get("file_size", 0),
        "signals": rec.get("signal_summary"),
    }
    if sg_dump is None:
        out.update({"predicted_verdict": "ERROR", "error": rec.get("error") or "no signal_graph in dataset"})
        return out

    signal_graph = SignalGraph(**sg_dump)

    # Leak guard: the aggregator receives signal_graph.doc_metadata, which carries
    # the original filename. This dataset names malicious files by SHA-256 hash and
    # clean files with human names, so the filename is an implicit label signal.
    # Drop it so the model decides on content/structure only, not the filename.
    if neutralize_filename and isinstance(signal_graph.doc_metadata, dict):
        signal_graph.doc_metadata.pop("filename", None)

    raw = signal_graph.raw_signals or {}
    doc_type = rec.get("doc_type", "Unknown")
    # R6-1 format ablation: hide the declared file type from every agent.
    if mask_doc_type:
        doc_type = MASKED_DOC_TYPE
        if isinstance(signal_graph.doc_metadata, dict):
            signal_graph.doc_metadata.pop("doc_type", None)
    manifest_stub = {"file_metadata": {"detected_doc_type": doc_type}}

    timing: dict[str, float] = {}
    tokens: dict[str, dict] = {}

    # --- Stage B: intent (only if visible text present) ---
    intent_result = None
    recorder.reset()
    t0 = time.perf_counter()
    if signal_graph.visible_text_length > 0:
        visible_text = raw.get("text_stats", {}).get("visible_text", "")
        intent_result = await intent_analyzer.classify_intent(visible_text, doc_type=doc_type)
    timing["intent_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    tokens["intent"] = _common.summarise_calls(recorder.drain())

    # --- Stage C: macro behavior (only if macros present) ---
    macro_result = None
    recorder.reset()
    t0 = time.perf_counter()
    if signal_graph.has_macros:
        macro_code = raw.get("macros", {}).get("macro_code", "")
        ioc = raw.get("macros", {}).get("ioc_keywords", [])
        macro_result = await macro_behavior_analyzer.analyze_behavior(macro_code, ioc, doc_type=doc_type)
    timing["macro_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    tokens["macro"] = _common.summarise_calls(recorder.drain())

    # Dummies for skipped stages — identical to run_pipeline()
    intent_final = intent_result or intent_analyzer.IntentResponse(
        intent="skipped_low_density", intent_confidence=0.0, risk_keywords=[],
        explanation="Text too short for reliable intent classification.")
    macro_final = macro_result or macro_behavior_analyzer.MacroBehaviorResponse(
        macro_behavior="skipped_no_autoexec", macro_risk_score=0, macro_indicators=[])

    # --- Stage D: aggregation + deterministic floor ---
    recorder.reset()
    t0 = time.perf_counter()
    # force_decisive_verdict=True: the aggregator MUST commit to CLEAN/SUSPICIOUS/
    # MALICIOUS (constrained schema + decisive prompt). REQUIRE_NETWORK_ANALYSIS is
    # not a verdict here — network follow-up survives only as the supplementary
    # `needs_web_analysis` flag, captured below.
    verdict = await verdict_aggregator.aggregate(
        signal_graph, intent_final, macro_final, manifest_stub, force_decisive_verdict=True)
    timing["aggregator_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    tokens["aggregator"] = _common.summarise_calls(recorder.drain())

    # Roll-ups
    reasoning_ms = round(timing["intent_ms"] + timing["macro_ms"] + timing["aggregator_ms"], 2)
    ext_ms = float(rec.get("extraction_ms") or 0.0)
    det_ms = float(rec.get("deterministic_ms") or 0.0)
    total_prompt = sum(t["prompt_tokens"] for t in tokens.values())
    total_completion = sum(t["completion_tokens"] for t in tokens.values())
    total_tokens = sum(t["total_tokens"] for t in tokens.values())
    total_cost = round(sum(t["cost_usd"] for t in tokens.values()), 8)
    total_calls = sum(t["calls"] for t in tokens.values())
    failed_calls = sum(t.get("failed_calls", 0) for t in tokens.values())
    if failed_calls:
        log.warning("%s: %d LLM call(s) failed; verdict may rely on fallback/defaults",
                    rec["filename"], failed_calls)

    out.update({
        "predicted_verdict": verdict.verdict.value,
        "risk_score": verdict.risk_score,
        "confidence": verdict.confidence,
        "intent": verdict.intent,
        "needs_web_analysis": bool(verdict.needs_web_analysis),
        "mitre_techniques": [f"{m.id}: {m.name}" for m in verdict.mitre_techniques],
        "reasoning": list(verdict.reasoning),
        "floor_applied": _floor_applied(verdict.reasoning),
        "graph_mode": verdict.analysis_metadata.get("graph_mode"),
        "risk_scores": verdict.analysis_metadata.get("risk_scores"),
        "graph_stats": verdict.analysis_metadata.get("graph_stats"),
        "llm_risk_estimate": verdict.analysis_metadata.get("llm_risk_estimate"),
        "is_fallback": bool(verdict.analysis_metadata.get("fallback", False)),
        "llm_calls": total_calls,
        "llm_calls_failed": failed_calls,
        "tokens": {
            "by_stage": tokens,
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_tokens,
        },
        "cost_usd": total_cost,
        "timing_ms": {
            "extraction": ext_ms,
            "deterministic": det_ms,
            "intent": timing["intent_ms"],
            "macro": timing["macro_ms"],
            "aggregator": timing["aggregator_ms"],
            "reasoning_total": reasoning_ms,
            "end_to_end": round(ext_ms + det_ms + reasoning_ms, 2),
        },
        "error": None,
    })
    return out


async def main_async(args) -> None:
    # Optional model overrides (agents read these at call time)
    if args.model_analysis:
        config.OPENAI_MODEL_ANALYSIS = args.model_analysis
    if args.model_aggregator:
        config.OPENAI_MODEL_AGGREGATOR = args.model_aggregator
    config.SIGNAL_GRAPH_MODE = args.graph_mode

    dataset = _common.read_jsonl(args.dataset)
    if not dataset:
        raise SystemExit(f"No records in dataset: {args.dataset}")
    if args.limit:
        dataset = dataset[: args.limit]

    run_id = args.run_id or datetime.now().strftime("run_%Y%m%d_%H%M%S")
    run_dir = _common.RESULTS_DIR / run_id
    pred_path = run_dir / "predictions.jsonl"
    _common.setup_logging(run_dir / "run.log", verbose=args.verbose)

    done_keys: set[str] = set()
    if pred_path.exists() and args.resume:
        done_keys = {f"{r['label']}/{r['filename']}" for r in _common.read_jsonl(pred_path)}
        print(f"[reason] resuming run '{run_id}' — {len(done_keys)} predictions already present")
    elif pred_path.exists() and not args.resume:
        raise SystemExit(f"{pred_path} exists. Use --resume to continue or pick a new --run-id.")

    try:
        recorder = _common.UsageRecorder.install()
    except RuntimeError as e:
        raise SystemExit(f"[reason] cannot start: {e}\nSet OPENAI_API_KEY in the environment.")

    print(f"[reason] run '{run_id}' | analysis={config.OPENAI_MODEL_ANALYSIS} "
          f"aggregator={config.OPENAI_MODEL_AGGREGATOR} | {len(dataset)} samples")

    t0 = time.perf_counter()
    n = errors = with_llm_failures = 0
    for i, rec in enumerate(dataset, 1):
        key = f"{rec['label']}/{rec['filename']}"
        if key in done_keys:
            continue
        try:
            row = await reason_over_sample(rec, recorder, neutralize_filename=not args.keep_filename,
                                           mask_doc_type=args.mask_doc_type)
        except Exception as exc:  # noqa: BLE001
            log.exception("Reasoning failed for %s/%s", rec["label"], rec.get("filename"))
            row = {"filename": rec["filename"], "label": rec["label"],
                   "predicted_verdict": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        _common.append_jsonl(pred_path, row)
        n += 1
        if row.get("predicted_verdict") == "ERROR":
            errors += 1
        if row.get("llm_calls_failed"):
            with_llm_failures += 1
        v = row.get("predicted_verdict")
        cost = row.get("cost_usd", 0.0)
        tt = row.get("tokens", {}).get("total_tokens", 0)
        e2e = row.get("timing_ms", {}).get("end_to_end", 0)
        flag = " ⚠LLM-fail" if row.get("llm_calls_failed") else (" ⚠fallback" if row.get("is_fallback") else "")
        print(f"  [{i}/{len(dataset)}] {rec['label']:9s} {rec['filename'][:42]:42s} "
              f"-> {v:24s} {tt:6d} tok  ${cost:.5f}  {e2e:.0f}ms{flag}")

    wall = time.perf_counter() - t0
    meta = {
        "run_id": run_id,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(Path(args.dataset).resolve()),
        "model_analysis": config.OPENAI_MODEL_ANALYSIS,
        "model_aggregator": config.OPENAI_MODEL_AGGREGATOR,
        "pricing_usd_per_million": {
            config.OPENAI_MODEL_ANALYSIS: _common.price_for(config.OPENAI_MODEL_ANALYSIS),
            config.OPENAI_MODEL_AGGREGATOR: _common.price_for(config.OPENAI_MODEL_AGGREGATOR),
        },
        "samples_this_run": n,
        "error_predictions_this_run": errors,
        "samples_with_llm_call_failures": with_llm_failures,
        "filename_neutralized": not args.keep_filename,
        "decisive_verdict": True,
        "graph_mode": args.graph_mode,
        "served_models": dict(recorder.served),
        "doc_type_masked": bool(args.mask_doc_type),
        "wall_seconds_this_run": round(wall, 2),
        "max_completion_tokens": {
            "analysis": config.LLM_MAX_COMPLETION_TOKENS_ANALYSIS,
            "aggregator": config.LLM_MAX_COMPLETION_TOKENS_AGGREGATOR,
        },
        "note": "Labels never entered any prompt. Tokens captured from response.usage. "
                "Costs use the pricing snapshot in _common.PRICING_USD_PER_M.",
    }
    _common.write_json(run_dir / "run_meta.json", meta)
    print(f"[reason] done — {n} predictions in {wall:.1f}s "
          f"({errors} ERROR, {with_llm_failures} with LLM-call failures)")
    if errors or with_llm_failures:
        log.warning("%d error prediction(s), %d sample(s) had failed LLM calls — see %s",
                    errors, with_llm_failures, run_dir / "run.log")
    print(f"[reason] -> {pred_path}")
    print(f"[reason] next: python 03_evaluate.py --run-dir {run_dir}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Replay labelled dataset through the real LLM agents.")
    ap.add_argument("--dataset", type=Path, default=_common.DATA_DIR / "labelled_dataset.jsonl")
    ap.add_argument("--run-id", type=str, default="")
    ap.add_argument("--model-analysis", type=str, default="", help="Override intent/macro model")
    ap.add_argument("--model-aggregator", type=str, default="", help="Override aggregator model")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--keep-filename", action="store_true",
                    help="Do NOT strip filename from aggregator input (default strips it to avoid label leakage)")
    ap.add_argument("--graph-mode", choices=["full", "nodes", "off"], default="full",
                    help="Signal Graph given to the aggregator: full (edges), nodes (edge ablation), off (run v3 behaviour)")
    ap.add_argument("--mask-doc-type", action="store_true",
                    help="Hide the declared file type from all agents (R6-1 format ablation)")
    ap.add_argument("--verbose", action="store_true", help="Show backend INFO logs too")
    args = ap.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
