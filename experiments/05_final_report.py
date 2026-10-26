#!/usr/bin/env python3
"""
05_final_report.py — Final evaluation tables for the revision (Reviewer 6 / 2 / 7).

Pre-registered before the test half was scored (2026-10-26):
  PRIMARY      : run r4_full, the agents' own verdict (system as designed);
                 MALICIOUS or SUSPICIOUS = positive (analyst-triage convention).
  SECONDARY    : same run, MALICIOUS-only view (strongest label; blocking context).
  ABLATIONS    : r4_nodes (no edges, RQ2/R6-4), r4_masked (file type hidden, R6-1),
                 r4_off (pre-revision configuration on the revision corpus).
  RISK SCORE   : ROC-AUC of the deterministic scores (additive = Alg. 3 as first
                 submitted, nodes = no edges, graph = revised Alg. 3).
Nothing here changes a verdict. Standard library only.

Usage (from experiments/):
  python 05_final_report.py --split test      # the numbers for the paper (run once)
  python 05_final_report.py --split dev       # development half, for reference
Output: results/final_r4/report_<split>.md and .json
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics as st
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
RUNS = {"r4_full": "Full graph (primary)", "r4_nodes": "Nodes only, no edges",
        "r4_masked": "Full graph, file type hidden", "r4_off": "Pre-revision config (no graph)"}
PRIMARY = "r4_full"
FORMATS = ["docx", "xlsm", "xlsx", "pptx", "pptm"]
BOOT = 2000
SEED = 20261026


# ----------------------------------------------------------------------------- io
def load_jsonl(p: Path) -> list[dict]:
    with p.open() as f:
        return [json.loads(l) for l in f if l.strip()]


# ------------------------------------------------------------------------ metrics
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def confusion(rows: list[dict], positive) -> dict:
    tp = sum(1 for r in rows if r["label"] == "malicious" and positive(r))
    fn = sum(1 for r in rows if r["label"] == "malicious" and not positive(r))
    fp = sum(1 for r in rows if r["label"] == "clean" and positive(r))
    tn = sum(1 for r in rows if r["label"] == "clean" and not positive(r))
    return {"TP": tp, "FN": fn, "FP": fp, "TN": tn}


def metrics(c: dict) -> dict:
    tp, fn, fp, tn = c["TP"], c["FN"], c["FP"], c["TN"]
    n = tp + fn + fp + tn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    spec = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / den if den else 0.0
    return {**c, "n": n, "precision": prec, "recall": rec, "f1": f1,
            "accuracy": (tp + tn) / n if n else 0.0, "specificity": spec, "fpr": 1 - spec,
            "balanced_accuracy": (rec + spec) / 2, "mcc": mcc,
            "precision_ci": wilson(tp, tp + fp), "recall_ci": wilson(tp, tp + fn),
            "fpr_ci": wilson(fp, fp + tn)}


def f1_boot_ci(rows: list[dict], positive) -> tuple[float, float]:
    rnd = random.Random(SEED)
    vals = []
    for _ in range(BOOT):
        s = [rows[rnd.randrange(len(rows))] for _ in rows]
        vals.append(metrics(confusion(s, positive))["f1"])
    vals.sort()
    return vals[int(0.025 * BOOT)], vals[int(0.975 * BOOT) - 1]


def auc(rows: list[dict], score) -> float:
    pos = [score(r) for r in rows if r["label"] == "malicious" and score(r) is not None]
    neg = [score(r) for r in rows if r["label"] == "clean" and score(r) is not None]
    if not pos or not neg:
        return float("nan")
    s = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in pos for b in neg)
    return s / (len(pos) * len(neg))


def auc_boot_ci(rows: list[dict], score) -> tuple[float, float]:
    rnd = random.Random(SEED)
    vals = []
    for _ in range(BOOT):
        s = [rows[rnd.randrange(len(rows))] for _ in rows]
        v = auc(s, score)
        if not math.isnan(v):
            vals.append(v)
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals)) - 1]


def mcnemar(a: dict, b: dict, rows_a: list[dict], rows_b: list[dict], positive) -> dict:
    """Exact McNemar test on correctness of two runs over the same samples."""
    ok_a = {r["sha256"]: positive(r) == (r["label"] == "malicious") for r in rows_a}
    ok_b = {r["sha256"]: positive(r) == (r["label"] == "malicious") for r in rows_b}
    common = ok_a.keys() & ok_b.keys()
    b01 = sum(1 for s in common if ok_a[s] and not ok_b[s])
    b10 = sum(1 for s in common if not ok_a[s] and ok_b[s])
    n, k = b01 + b10, min(b01, b10)
    p = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n) if n else 1.0
    return {"only_first_correct": b01, "only_second_correct": b10, "p_value": p}


# ------------------------------------------------------------------------- helpers
POS = lambda r: r.get("predicted_verdict") in ("MALICIOUS", "SUSPICIOUS")  # noqa: E731
STRICT = lambda r: r.get("predicted_verdict") == "MALICIOUS"  # noqa: E731
fmt = lambda r: r["filename"].rsplit(".", 1)[-1].lower()  # noqa: E731


def pct(x: float) -> str:
    return "n/a" if x != x else f"{100 * x:.1f}%"


def ci(t: tuple) -> str:
    return f"[{100 * t[0]:.1f}, {100 * t[1]:.1f}]"


def mrow(name: str, m: dict, f1ci=None) -> str:
    f1 = f"{m['f1']:.3f}" + (f" [{f1ci[0]:.3f}, {f1ci[1]:.3f}]" if f1ci else "")
    return (f"| {name} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | {pct(m['precision'])} {ci(m['precision_ci'])} "
            f"| {pct(m['recall'])} {ci(m['recall_ci'])} | {f1} | {pct(m['fpr'])} {ci(m['fpr_ci'])} | {m['mcc']:.3f} |")


HDR = ("| Configuration | TP | FN | FP | TN | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] | FPR [95% CI] | MCC |\n"
       "|---|---|---|---|---|---|---|---|---|---|")


# ---------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", choices=["dev", "test", "all"], required=True)
    ap.add_argument("--split-file", type=Path, default=HERE / "data" / "split_r2.json")
    ap.add_argument("--manifest", type=Path, default=HERE.parent / "dataset" / "metadata" / "dataset_manifest.csv")
    ap.add_argument("--docs-per-day", type=int, default=10000)
    a = ap.parse_args()

    split = {s["sha256"]: s for s in json.loads(a.split_file.read_text())["samples"]}
    basis = {r["sha256"]: r["label_basis"] for r in csv.DictReader(a.manifest.open())} if a.manifest.exists() else {}
    keep = lambda r: a.split == "all" or split[r["sha256"]]["split"] == a.split  # noqa: E731

    runs = {}
    for rid in RUNS:
        p = RES / rid / "predictions.jsonl"
        if not p.exists():
            raise SystemExit(f"missing {p}")
        rows = [r for r in load_jsonl(p) if keep(r)]
        runs[rid] = rows
    P = runs[PRIMARY]
    nm = sum(r["label"] == "malicious" for r in P)
    nc = len(P) - nm
    out: dict = {"split": a.split, "n": len(P), "n_malicious": nm, "n_clean": nc}
    L: list[str] = [f"# Final evaluation — split: **{a.split}** ({len(P)} samples: {nm} malicious / {nc} clean)\n",
                    "Pre-registered before scoring the test half. Primary = agents' own verdict of the full system "
                    "(MALICIOUS or SUSPICIOUS = positive). No verdict is altered by this script.\n"]

    # 1. primary + secondary
    mP, mS = metrics(confusion(P, POS)), metrics(confusion(P, STRICT))
    out["primary"], out["malicious_only"] = mP, mS
    L += ["## 1. Detection performance (primary run)\n", HDR,
          mrow("Agents' verdict (MAL or SUSP = positive)", mP, f1_boot_ci(P, POS)),
          mrow("MALICIOUS-only view", mS, f1_boot_ci(P, STRICT)), "",
          f"Accuracy {pct(mP['accuracy'])}, balanced accuracy {pct(mP['balanced_accuracy'])}, specificity {pct(mP['specificity'])}.\n"]
    v3 = Counter((r["label"], r.get("predicted_verdict")) for r in P)
    L += ["**3-class breakdown**\n", "| True label | → MALICIOUS | → SUSPICIOUS | → CLEAN |", "|---|---|---|---|"]
    for lab in ("malicious", "clean"):
        L.append(f"| {lab} | {v3[(lab, 'MALICIOUS')]} | {v3[(lab, 'SUSPICIOUS')]} | {v3[(lab, 'CLEAN')]} |")
    L.append("")

    # 2. ablations
    L += ["## 2. Ablations (same samples, same model)\n", HDR]
    out["ablations"] = {}
    for rid, name in RUNS.items():
        m = metrics(confusion(runs[rid], POS))
        ms = metrics(confusion(runs[rid], STRICT))
        out["ablations"][rid] = {"triage": m, "malicious_only": ms}
        L.append(mrow(name, m))
    L += ["", "| Configuration | MALICIOUS-only precision | MALICIOUS-only recall | MALICIOUS-only F1 |", "|---|---|---|---|"]
    for rid, name in RUNS.items():
        ms = out["ablations"][rid]["malicious_only"]
        L.append(f"| {name} | {pct(ms['precision'])} | {pct(ms['recall'])} | {ms['f1']:.3f} |")
    L += ["", "**Paired McNemar tests (correctness, triage convention)**\n", "| Comparison | only primary correct | only other correct | exact p |", "|---|---|---|---|"]
    out["mcnemar"] = {}
    for rid in ("r4_nodes", "r4_masked", "r4_off"):
        t = mcnemar({}, {}, P, runs[rid], POS)
        out["mcnemar"][rid] = t
        L.append(f"| full vs {RUNS[rid]} | {t['only_first_correct']} | {t['only_second_correct']} | {t['p_value']:.3f} |")
    L.append("")

    # 3. risk score (RQ2 / R6-4)
    L += ["## 3. Deterministic risk score — ROC-AUC (RQ2, R6-4)\n", "| Score | ROC-AUC [95% bootstrap CI] |", "|---|---|"]
    out["auc"] = {}
    for k, name in (("additive", "Alg. 3 as first submitted (mean of node evidence)"),
                    ("nodes", "Nodes only (max node evidence, no edges)"),
                    ("graph", "Signal Graph (revised Alg. 3, correlation edges)")):
        f = lambda r, k=k: (r.get("risk_scores") or {}).get(k)  # noqa: E731
        v, c = auc(P, f), auc_boot_ci(P, f)
        out["auc"][k] = (v, c)
        L.append(f"| {name} | {v:.3f} [{c[0]:.3f}, {c[1]:.3f}] |")
    f = lambda r: r.get("llm_risk_estimate")  # noqa: E731
    v = auc(P, f)
    out["auc"]["llm_estimate"] = v
    L += [f"| LLM's own risk estimate (for comparison) | {v:.3f} |", ""]

    # 4. per format (R6-1)
    L += ["## 4. Per-format results (R6-1)\n",
          "| Format | Mal / Clean | Recall (full) | FPR (full) | Recall (type hidden) | FPR (type hidden) | Majority-format baseline acc. |",
          "|---|---|---|---|---|---|---|"]
    out["per_format"] = {}
    for fm in FORMATS:
        a_ = [r for r in P if fmt(r) == fm]
        b_ = [r for r in runs["r4_masked"] if fmt(r) == fm]
        if not a_:
            continue
        ma, mb = metrics(confusion(a_, POS)), metrics(confusion(b_, POS))
        nmal = sum(r["label"] == "malicious" for r in a_)
        maj = max(nmal, len(a_) - nmal) / len(a_)
        out["per_format"][fm] = {"full": ma, "masked": mb, "n_mal": nmal, "n_clean": len(a_) - nmal}
        L.append(f"| {fm} | {nmal} / {len(a_) - nmal} | {pct(ma['recall'])} | {pct(ma['fpr'])} | "
                 f"{pct(mb['recall'])} | {pct(mb['fpr'])} | {pct(maj)} |")
    by_fmt = Counter((fmt(r), r["label"]) for r in P)
    base_ok = sum(max(by_fmt[(f_, "malicious")], by_fmt[(f_, "clean")]) for f_ in FORMATS)
    out["format_only_baseline_accuracy"] = base_ok / len(P)
    L += ["", f"Format-only baseline (predict each format's majority class): accuracy {pct(base_ok / len(P))} "
          f"(≈50% means the corpus is balanced within formats). Primary accuracy: {pct(mP['accuracy'])}.\n"]

    # 5. campaign-weighted recall (R6-3)
    mal = [r for r in P if r["label"] == "malicious"]
    groups = defaultdict(list)
    for r in mal:
        groups[split[r["sha256"]]["group"]].append(POS(r))
    gw = st.mean(sum(v) / len(v) for v in groups.values())
    big = max(groups.values(), key=len)
    out["campaign"] = {"groups": len(groups), "group_weighted_recall": gw, "largest_group": len(big)}
    L += ["## 5. Campaign / family duplication (R6-3)\n",
          f"Malicious samples: {len(mal)} in {len(groups)} similarity groups (ssdeep ≥ 50); largest group {len(big)} samples. "
          f"Sample-level recall {pct(mP['recall'])}; group-weighted recall (each group counts once) {pct(gw)}.\n"]

    # 6. label-basis sensitivity (R6-2)
    if basis:
        strong = [r for r in P if basis.get(r["sha256"], "").endswith(("VT>=5", "VT=0"))]
        ms_ = metrics(confusion(strong, POS))
        out["label_sensitivity"] = ms_
        L += ["## 6. Label-basis sensitivity (R6-2)\n",
              f"Restricting to samples whose label is confirmed by VirusTotal (malicious ≥ 5 engines, clean 0 engines; "
              f"{ms_['n']} samples): precision {pct(ms_['precision'])}, recall {pct(ms_['recall'])}, F1 {ms_['f1']:.3f}, "
              f"FPR {pct(ms_['fpr'])}.\n"]

    # 7. operational false alerts (R6-6, R7-1, R2-3b)
    L += ["## 7. Expected alert load at realistic base rates (R6-6, R7-1)\n",
          f"Assumes {a.docs_per_day:,} documents/day; FPR and recall from section 1 (95% Wilson CI for FPR).\n",
          "| View | Malicious base rate | True detections/day | False alerts/day [95% CI] | Alert precision |", "|---|---|---|---|---|"]
    out["operational"] = []
    for vname, m in (("Triage (MAL or SUSP)", mP), ("MALICIOUS-only", mS)):
        for br in (0.01, 0.001):
            mald = a.docs_per_day * br
            ben = a.docs_per_day - mald
            tp = m["recall"] * mald
            fa = m["fpr"] * ben
            lo, hi = m["fpr_ci"][0] * ben, m["fpr_ci"][1] * ben
            prec = tp / (tp + fa) if tp + fa else float("nan")
            out["operational"].append({"view": vname, "base_rate": br, "tp_day": tp, "fa_day": fa, "fa_ci": (lo, hi), "precision": prec})
            L.append(f"| {vname} | {br:.1%} | {tp:.1f} | {fa:.1f} [{lo:.1f}, {hi:.1f}] | {pct(prec)} |")
    L.append("")

    # 8. economics
    ok = [r for r in P if not r.get("llm_calls_failed")]
    e2e = sorted(r["timing_ms"]["end_to_end"] / 1000 for r in ok)
    cost = [r["cost_usd"] for r in ok]
    tok = [r["tokens"]["total_tokens"] for r in ok]
    q = lambda xs, p: xs[min(len(xs) - 1, int(p * len(xs)))]  # noqa: E731
    out["economics"] = {"n": len(ok), "median_s": st.median(e2e), "p90_s": q(e2e, 0.9), "mean_cost": st.mean(cost),
                        "mean_tokens": st.mean(tok)}
    L += ["## 8. Cost and latency (primary run)\n",
          f"n = {len(ok)} (samples with a failed LLM call excluded). End-to-end median {st.median(e2e):.2f} s, "
          f"p90 {q(e2e, 0.9):.2f} s; mean tokens {st.mean(tok):.0f}; mean cost ${st.mean(cost):.5f}/document "
          f"(${1000 * st.mean(cost):.2f} per 1,000).\n"]

    # 9. run provenance
    L.append("## 9. Run provenance\n")
    for rid in RUNS:
        mpath = RES / rid / "run_meta.json"
        if mpath.exists():
            m = json.loads(mpath.read_text())
            L.append(f"- `{rid}`: graph_mode={m.get('graph_mode')}, doc_type_masked={m.get('doc_type_masked')}, "
                     f"served={', '.join(sorted({k.split('|')[0] for k in (m.get('served_models') or {})}))}, ran_at={m.get('ran_at')}")
    od = RES / "final_r4"
    od.mkdir(parents=True, exist_ok=True)
    (od / f"report_{a.split}.md").write_text("\n".join(L) + "\n")
    (od / f"report_{a.split}.json").write_text(json.dumps(out, indent=2, default=list))
    print("\n".join(L))
    print(f"\n-> {od / f'report_{a.split}.md'}")


if __name__ == "__main__":
    main()
