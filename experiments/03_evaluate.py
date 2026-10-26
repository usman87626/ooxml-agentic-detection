#!/usr/bin/env python3
"""
03_evaluate.py — Stage 3: score predictions + aggregate time/tokens/cost.

Reads results/<run_id>/predictions.jsonl (from 02_run_reasoning.py) and writes:
  report.json  — machine-readable metrics
  report.md    — paper-ready markdown tables

Scoring rules (binary: positive = malicious detection):
  malicious sample: MALICIOUS or SUSPICIOUS -> TP ; CLEAN -> FN
  clean sample    : CLEAN -> TN ; MALICIOUS or SUSPICIOUS -> FP
  ERROR           : excluded from the matrix, counted separately
  REQUIRE_NETWORK_ANALYSIS -> resolved by --rna policy:
     positive (default): treat as a positive detection (malicious->TP, clean->FP)
                         => label-independent, NO ground-truth leakage
     clean             : treat as CLEAN (malicious->FN, clean->TN)
     exclude           : drop from the matrix (counted separately)
     leaky             : reproduce the app's current behavior (malicious->TP, clean->TN)
                         => uses the true label; shown only for comparison

Also reports: accuracy, precision, recall, specificity, F1, FPR, balanced acc,
ROC-AUC (risk_score vs label), latency stats (end-to-end + per stage), token
stats, cost stats + projection, verdict distribution, deterministic-floor
influence, per-doc-type breakdown, and a baseline-comparison table.

Usage:
  python 03_evaluate.py --run-dir results/run_20260618_120000
  python 03_evaluate.py --predictions results/x/predictions.jsonl --rna positive
"""
from __future__ import annotations

import argparse
import json
import logging
import statistics as stats
from collections import Counter, defaultdict
from pathlib import Path

import _common

log = logging.getLogger("experiments.eval")

POSITIVE = {"MALICIOUS", "SUSPICIOUS"}


def classify_cell(label: str, pred: str, rna: str) -> str | None:
    """Return 'TP'|'TN'|'FP'|'FN'|None (None => excluded)."""
    is_mal = label == "malicious"
    if pred == "ERROR":
        return None
    if pred == "REQUIRE_NETWORK_ANALYSIS":
        if rna == "exclude":
            return None
        if rna == "clean":
            pred = "CLEAN"
        elif rna == "leaky":
            return "TP" if is_mal else "TN"
        else:  # positive
            pred = "SUSPICIOUS"
    positive = pred in POSITIVE
    if is_mal:
        return "TP" if positive else "FN"
    return "FP" if positive else "TN"


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def roc_auc(rows: list[dict]) -> float | None:
    """Mann-Whitney U AUC using risk_score; positive class = malicious."""
    pos = [r["risk_score"] for r in rows
           if r["label"] == "malicious" and isinstance(r.get("risk_score"), (int, float))]
    neg = [r["risk_score"] for r in rows
           if r["label"] == "clean" and isinstance(r.get("risk_score"), (int, float))]
    if not pos or not neg:
        return None
    ranks = 0.0
    for p in pos:
        for n in neg:
            ranks += 1.0 if p > n else (0.5 if p == n else 0.0)
    return round(ranks / (len(pos) * len(neg)), 4)


def stat_block(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    s = sorted(values)
    return {
        "n": len(s),
        "min": round(min(s), 4),
        "max": round(max(s), 4),
        "mean": round(stats.fmean(s), 4),
        "median": round(stats.median(s), 4),
        "p90": round(s[min(len(s) - 1, int(len(s) * 0.9))], 4),
        "p95": round(s[min(len(s) - 1, int(len(s) * 0.95))], 4),
        "total": round(sum(s), 4),
    }


def _llm_incomplete(r: dict) -> bool:
    """LLM reasoning did not fully complete (API failure → deterministic fallback).
    Such a sample still has a system-produced verdict (so it IS counted in the
    confusion matrix), but its latency/tokens/cost reflect retry/backoff overhead,
    so it is excluded from the economics figures only."""
    return bool(r.get("is_fallback")) or bool(r.get("llm_calls_failed"))


def build_report(rows: list[dict], rna: str, meta: dict) -> dict:
    all_preds = [r for r in rows if r.get("predicted_verdict")]
    # Classification set: every sample that produced a verdict (only true ERRORs,
    # i.e. no verdict at all, are dropped). Fallback verdicts ARE counted.
    scored = [r for r in all_preds if r["predicted_verdict"] != "ERROR"]
    errored = len(all_preds) - len(scored)
    # Economics set: of the scored samples, those whose LLM calls all completed
    # normally (fallback/failed-call samples excluded so retry time/0-token calls
    # don't distort latency & cost).
    econ = [r for r in scored if not _llm_incomplete(r)]
    excluded_economics = len(scored) - len(econ)

    cm = Counter()
    excluded = 0
    for r in scored:
        cell = classify_cell(r["label"], r["predicted_verdict"], rna)
        if cell is None:
            excluded += 1
        else:
            cm[cell] += 1
    tp, tn, fp, fn = cm["TP"], cm["TN"], cm["FP"], cm["FN"]
    total = tp + tn + fp + fn

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    f1 = safe_div(2 * precision * recall, precision + recall)
    metrics = {
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "scored": total,
        "excluded_from_matrix": excluded,
        "accuracy": round(safe_div(tp + tn, total), 4),
        "precision": round(precision, 4),
        "recall_tpr": round(recall, 4),
        "specificity_tnr": round(specificity, 4),
        "fpr": round(safe_div(fp, fp + tn), 4),
        "f1": round(f1, 4),
        "balanced_accuracy": round((recall + specificity) / 2, 4),
        "roc_auc_riskscore": roc_auc(scored),
    }

    ok = scored  # classification set (used for floor/by-type/signals/FN below)

    def _tm(r, key):
        return (r.get("timing_ms") or {}).get(key)

    # Timing/economics use the `econ` set (completed LLM calls only).
    e2e = [v for r in econ if (v := _tm(r, "end_to_end")) is not None]
    reasoning_t = [v for r in econ if (v := _tm(r, "reasoning_total")) is not None]
    ext_t = [v for r in econ if (v := _tm(r, "extraction")) is not None]
    det_t = [v for r in econ if (v := _tm(r, "deterministic")) is not None]
    # Per-stage LLM latency, computed only over samples where the stage executed
    # (intent skips no-text docs; macro skips no-macro docs), so zeros don't skew it.
    def _stage_lat(stage):
        return [v for r in econ if (v := _tm(r, stage)) is not None and v > 0]
    timing = {
        "end_to_end_ms": stat_block(e2e),
        "reasoning_ms": stat_block(reasoning_t),
        "extraction_ms": stat_block(ext_t),
        "deterministic_ms": stat_block(det_t),
        "intent_ms": stat_block(_stage_lat("intent")),
        "macro_ms": stat_block(_stage_lat("macro")),
        "aggregator_ms": stat_block(_stage_lat("aggregator")),
        "end_to_end_seconds_mean": round(safe_div(sum(e2e), len(e2e)) / 1000, 3) if e2e else 0,
    }

    def _tok(r, key):
        return (r.get("tokens") or {}).get(key)

    prompt_tok = [v for r in econ if (v := _tok(r, "prompt_tokens")) is not None]
    compl_tok = [v for r in econ if (v := _tok(r, "completion_tokens")) is not None]
    total_tok = [v for r in econ if (v := _tok(r, "total_tokens")) is not None]
    costs = [r["cost_usd"] for r in econ if isinstance(r.get("cost_usd"), (int, float))]
    calls = [r["llm_calls"] for r in econ if isinstance(r.get("llm_calls"), int)]
    mean_total_tok = safe_div(sum(total_tok), len(total_tok)) if total_tok else 0
    mean_cost = safe_div(sum(costs), len(costs)) if costs else 0
    economics = {
        "prompt_tokens": stat_block(prompt_tok),
        "completion_tokens": stat_block(compl_tok),
        "total_tokens": stat_block(total_tok),
        "llm_calls_per_sample": stat_block([float(c) for c in calls]),
        "cost_usd": stat_block(costs),
        "avg_tokens_per_sample": round(mean_total_tok, 1),
        "avg_cost_per_sample_usd": round(mean_cost, 6),
        "total_cost_usd": round(sum(costs), 6),
        "projected_cost_per_1000_usd": round(mean_cost * 1000, 4),
    }

    # --- Per-run totals (headline numbers for the paper / baseline comparison) ---
    wall = meta.get("wall_seconds_this_run")
    e2e_total_s = round(sum(e2e) / 1000, 2) if e2e else 0.0
    reasoning_total_s = round(sum(reasoning_t) / 1000, 2) if reasoning_t else 0.0
    denom_s = wall or e2e_total_s
    run_totals = {
        "samples_scored": len(econ),
        "total_llm_tokens": sum(total_tok),
        "total_prompt_tokens": sum(prompt_tok),
        "total_completion_tokens": sum(compl_tok),
        "total_cost_usd": round(sum(costs), 6),
        "avg_cost_per_sample_usd": round(mean_cost, 6),
        "avg_tokens_per_sample": round(mean_total_tok, 1),
        "wall_clock_seconds": wall,
        "summed_end_to_end_seconds": e2e_total_s,
        "summed_reasoning_seconds": reasoning_total_s,
        "avg_end_to_end_seconds": round(safe_div(sum(e2e), len(e2e)) / 1000, 3) if e2e else 0,
        "throughput_docs_per_min": round(safe_div(len(econ), denom_s) * 60, 2) if denom_s else 0,
        "projected_cost_per_1000_usd": round(mean_cost * 1000, 4),
        "projected_cost_per_million_usd": round(mean_cost * 1_000_000, 2),
    }

    # --- Per-stage token/cost (intent vs macro vs aggregator) across the run ---
    stages = ["intent", "macro", "aggregator"]
    per_stage = {s: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
                     "cost_usd": 0.0, "calls": 0} for s in stages}
    for r in econ:
        bs = (r.get("tokens") or {}).get("by_stage") or {}
        for s in stages:
            d = bs.get(s) or {}
            per_stage[s]["prompt_tokens"] += d.get("prompt_tokens", 0)
            per_stage[s]["completion_tokens"] += d.get("completion_tokens", 0)
            per_stage[s]["total_tokens"] += d.get("total_tokens", 0)
            per_stage[s]["cost_usd"] += d.get("cost_usd", 0.0)
            per_stage[s]["calls"] += d.get("calls", 0)
    for s in stages:
        per_stage[s]["cost_usd"] = round(per_stage[s]["cost_usd"], 6)

    verdict_dist = Counter(r["predicted_verdict"] for r in scored)
    floor_used = sum(1 for r in ok if r.get("floor_applied"))

    by_type: dict[str, Counter] = defaultdict(Counter)
    for r in ok:
        cell = classify_cell(r["label"], r["predicted_verdict"], rna)
        if cell:
            by_type[r.get("doc_type", "Unknown")][cell] += 1

    # Which deterministic signals fired on true positives vs false positives
    sig_flags = ["has_macros", "dde_detected", "xlm_detected", "obfuscation_detected",
                 "template_injection_detected", "prompt_injection_detected",
                 "has_dangerous_activex", "macroless_attacks_detected",
                 "has_html_svg_payloads", "encrypted_vba_detected", "pcode_stomping_detected"]
    signal_on_tp, signal_on_fp = Counter(), Counter()
    for r in ok:
        cell = classify_cell(r["label"], r["predicted_verdict"], rna)
        sig = r.get("signals") or {}
        for fl in sig_flags:
            if sig.get(fl):
                if cell == "TP":
                    signal_on_tp[fl] += 1
                elif cell == "FP":
                    signal_on_fp[fl] += 1

    false_negatives = [{"filename": r["filename"], "doc_type": r.get("doc_type"),
                        "risk_score": r.get("risk_score"), "signals_present":
                        [f for f in sig_flags if (r.get("signals") or {}).get(f)]}
                       for r in ok
                       if r["label"] == "malicious" and r["predicted_verdict"] == "CLEAN"]

    return {
        "run_id": meta.get("run_id"),
        "model_analysis": meta.get("model_analysis"),
        "model_aggregator": meta.get("model_aggregator"),
        "rna_policy": rna,
        "counts": {
            "total_predictions": len(scored),
            "clean": sum(1 for r in scored if r["label"] == "clean"),
            "malicious": sum(1 for r in scored if r["label"] == "malicious"),
            "errored_no_verdict": errored,
            "economics_n": len(econ),
            "excluded_from_economics": excluded_economics,
            "needs_web_analysis_flagged": sum(1 for r in scored if r.get("needs_web_analysis")),
        },
        "metrics": metrics,
        "timing": timing,
        "economics": economics,
        "run_totals": run_totals,
        "per_stage": per_stage,
        "verdict_distribution": dict(verdict_dist),
        "deterministic_floor": {
            "verdicts_influenced_by_floor": floor_used,
            "share_of_scored": round(safe_div(floor_used, len(ok)), 4),
        },
        "by_doc_type": {k: dict(v) for k, v in by_type.items()},
        "signal_firing_on_true_positives": dict(signal_on_tp.most_common()),
        "signal_firing_on_false_positives": dict(signal_on_fp.most_common()),
        "false_negatives": false_negatives,
    }


def render_md(rep: dict) -> str:
    m, e, t = rep["metrics"], rep["economics"], rep["timing"]
    cm = m["confusion_matrix"]
    L = []
    L.append(f"# Evaluation report — `{rep['run_id']}`\n")
    L.append(f"- Models: analysis=`{rep['model_analysis']}`, aggregator=`{rep['model_aggregator']}`")
    L.append(f"- RNA policy: **{rep['rna_policy']}** (REQUIRE_NETWORK_ANALYSIS handling)")
    c = rep["counts"]
    L.append(f"- Samples scored (classification): {c['total_predictions']} ({c['clean']} clean / {c['malicious']} malicious)")
    L.append(f"- Economics (latency/tokens/cost) computed over {c['economics_n']} samples "
             f"({c['excluded_from_economics']} excluded: LLM calls did not complete → retry/backoff would distort timing)\n")

    L.append("## Confusion matrix\n")
    L.append("| | Pred + (mal) | Pred − (clean) |")
    L.append("|---|---|---|")
    L.append(f"| **Actual malicious** | TP = {cm['TP']} | FN = {cm['FN']} |")
    L.append(f"| **Actual clean** | FP = {cm['FP']} | TN = {cm['TN']} |")
    if m['excluded_from_matrix']:
        L.append(f"\n_Excluded from matrix (RNA): {m['excluded_from_matrix']}_\n")

    L.append("## Classification metrics\n")
    L.append("| Metric | Value |")
    L.append("|---|---|")
    for k in ["accuracy", "precision", "recall_tpr", "specificity_tnr", "fpr", "f1",
              "balanced_accuracy", "roc_auc_riskscore"]:
        L.append(f"| {k} | {m[k]} |")

    L.append("\n## Latency, tokens & cost (paper Results material)\n")
    L.append("| Quantity | Mean | Median | Min | Max | Total |")
    L.append("|---|---|---|---|---|---|")
    e2e = t["end_to_end_ms"]
    L.append(f"| End-to-end (ms) | {e2e.get('mean')} | {e2e.get('median')} | {e2e.get('min')} | {e2e.get('max')} | — |")
    rt = t["reasoning_ms"]
    L.append(f"| LLM reasoning (ms) | {rt.get('mean')} | {rt.get('median')} | {rt.get('min')} | {rt.get('max')} | — |")
    tt = e["total_tokens"]
    L.append(f"| Total tokens | {tt.get('mean')} | {tt.get('median')} | {tt.get('min')} | {tt.get('max')} | {tt.get('total')} |")
    cu = e["cost_usd"]
    L.append(f"| Cost (USD) | {round(e['avg_cost_per_sample_usd'],6)} | {cu.get('median')} | {cu.get('min')} | {cu.get('max')} | {round(e['total_cost_usd'],4)} |")
    L.append(f"\n- **Avg tokens/sample:** {e['avg_tokens_per_sample']}  ·  **Avg $/sample:** {e['avg_cost_per_sample_usd']}  "
             f"·  **$/1000 samples:** {e['projected_cost_per_1000_usd']}")
    L.append(f"- **Avg end-to-end:** {t['end_to_end_seconds_mean']} s  ·  LLM calls/sample: {e['llm_calls_per_sample'].get('mean')}")

    rt = rep["run_totals"]
    L.append("\n## Per-run totals (headline for the paper)\n")
    L.append("| Quantity | Value |")
    L.append("|---|---|")
    L.append(f"| Samples scored | {rt['samples_scored']} |")
    L.append(f"| **Total cost (USD)** | **${rt['total_cost_usd']}** |")
    L.append(f"| Avg cost / sample (USD) | ${rt['avg_cost_per_sample_usd']} |")
    L.append(f"| Total LLM tokens | {rt['total_llm_tokens']:,} (prompt {rt['total_prompt_tokens']:,} / completion {rt['total_completion_tokens']:,}) |")
    L.append(f"| Avg tokens / sample | {rt['avg_tokens_per_sample']} |")
    L.append(f"| Wall-clock for run (s) | {rt['wall_clock_seconds']} |")
    L.append(f"| Avg end-to-end / sample (s) | {rt['avg_end_to_end_seconds']} |")
    L.append(f"| Throughput (docs/min) | {rt['throughput_docs_per_min']} |")
    L.append(f"| Projected cost / 1,000 docs (USD) | ${rt['projected_cost_per_1000_usd']} |")
    L.append(f"| Projected cost / 1,000,000 docs (USD) | ${rt['projected_cost_per_million_usd']} |")

    ps = rep["per_stage"]
    L.append("\n## Per-stage token & cost (whole run)\n")
    L.append("| Stage | Calls | Prompt tok | Completion tok | Total tok | Cost (USD) |")
    L.append("|---|---|---|---|---|---|")
    for s in ["intent", "macro", "aggregator"]:
        d = ps[s]
        L.append(f"| {s} | {d['calls']} | {d['prompt_tokens']:,} | {d['completion_tokens']:,} | {d['total_tokens']:,} | ${d['cost_usd']} |")

    L.append("\n## Baseline comparison (fill base-paper column from Heß & Graffi 2025)\n")
    L.append("| Metric | This run | Base paper (single-LLM) |")
    L.append("|---|---|---|")
    L.append(f"| Samples | {c['total_predictions']} | 25 |")
    L.append(f"| F1 | {m['f1']} | 0.929 |")
    L.append(f"| Precision | {m['precision']} | ~0.93 |")
    L.append(f"| Recall | {m['recall_tpr']} | ~0.93 |")
    L.append(f"| Avg latency / doc (s) | {rt['avg_end_to_end_seconds']} | 5–9 |")
    L.append(f"| Avg cost / doc (USD) | {rt['avg_cost_per_sample_usd']} | 0.19 |")
    L.append(f"| Total run cost (USD) | {rt['total_cost_usd']} | ~{round(0.19 * c['total_predictions'], 2)} (est. @ $0.19/doc) |")

    L.append("\n## Verdict distribution\n")
    for k, v in sorted(rep["verdict_distribution"].items(), key=lambda x: -x[1]):
        L.append(f"- {k}: {v}")

    fl = rep["deterministic_floor"]
    L.append(f"\n## Deterministic floor influence\n- Verdicts changed/justified by floor: "
             f"{fl['verdicts_influenced_by_floor']} ({fl['share_of_scored']*100:.1f}% of scored)")

    L.append("\n## Signal firing on true positives\n")
    for k, v in rep["signal_firing_on_true_positives"].items():
        L.append(f"- {k}: {v}")
    if rep["signal_firing_on_false_positives"]:
        L.append("\n## Signal firing on false positives\n")
        for k, v in rep["signal_firing_on_false_positives"].items():
            L.append(f"- {k}: {v}")

    if rep["false_negatives"]:
        L.append(f"\n## Missed malicious (false negatives): {len(rep['false_negatives'])}\n")
        for fnr in rep["false_negatives"][:40]:
            L.append(f"- {fnr['filename']} (risk {fnr['risk_score']}, signals: "
                     f"{', '.join(fnr['signals_present']) or 'none'})")

    L.append("\n## Per doc-type\n")
    L.append("| Doc type | TP | FN | FP | TN |")
    L.append("|---|---|---|---|---|")
    for dt, cells in sorted(rep["by_doc_type"].items()):
        L.append(f"| {dt} | {cells.get('TP',0)} | {cells.get('FN',0)} | {cells.get('FP',0)} | {cells.get('TN',0)} |")

    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate predictions + time/token/cost.")
    ap.add_argument("--run-dir", type=Path, help="results/<run_id> directory")
    ap.add_argument("--predictions", type=Path, help="Explicit predictions.jsonl path")
    ap.add_argument("--rna", choices=["positive", "clean", "exclude", "leaky"], default="positive")
    ap.add_argument("--split", choices=["dev", "test", "all"], default="all",
                    help="score only the dev or test half of data/split_r2.json")
    ap.add_argument("--split-file", type=Path, default=_common.DATA_DIR / "split_r2.json")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.run_dir:
        pred_path = args.run_dir / "predictions.jsonl"
        meta_path = args.run_dir / "run_meta.json"
        out_dir = args.run_dir
    elif args.predictions:
        pred_path = args.predictions
        meta_path = args.predictions.parent / "run_meta.json"
        out_dir = args.predictions.parent
    else:
        raise SystemExit("Provide --run-dir or --predictions")

    _common.setup_logging(out_dir / "eval.log", verbose=args.verbose)

    rows = _common.read_jsonl(pred_path)
    if not rows:
        raise SystemExit(f"No predictions in {pred_path}")
    if args.split != "all":
        split = {s["sha256"]: s["split"] for s in json.loads(args.split_file.read_text())["samples"]}
        missing = [r["filename"] for r in rows if r.get("sha256") not in split]
        if missing:
            raise SystemExit(f"{len(missing)} predictions are not in {args.split_file}, e.g. {missing[:3]}")
        rows = [r for r in rows if split[r["sha256"]] == args.split]
        print(f"[eval] split={args.split}: {len(rows)} samples")
    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not read %s: %s", meta_path, exc)

    try:
        rep = build_report(rows, args.rna, meta)
    except Exception:
        log.exception("Failed to build report from %s", pred_path)
        raise

    exc = rep["counts"].get("excluded_from_economics", 0)
    if exc:
        log.info("%d sample(s) counted in classification but excluded from economics "
                 "(LLM calls incomplete → retry/backoff).", exc)
    tag = args.rna if args.split == "all" else f"{args.rna}_{args.split}"
    rep["split"] = args.split
    _common.write_json(out_dir / f"report_{tag}.json", rep)
    md = render_md(rep)
    (out_dir / f"report_{tag}.md").write_text(md, encoding="utf-8")

    print(md)
    print(f"[eval] wrote {out_dir / f'report_{tag}.json'}")
    print(f"[eval] wrote {out_dir / f'report_{tag}.md'}")


if __name__ == "__main__":
    main()
