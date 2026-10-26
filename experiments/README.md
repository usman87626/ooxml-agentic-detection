# Experiments harness

Reproducible, 3-stage experimental pipeline for the paper. It **reuses the real
backend** (extractor, deterministic engine, prompts, schemas, agents, verdict
floor) — nothing is reimplemented — and adds **per-run time, token, and cost**
measurement that the production app does not record.

```
01_build_dataset.py   clean/ + malicious/  ->  labelled dataset (deterministic only, no LLM)
02_run_reasoning.py   labelled dataset      ->  predictions + time/tokens/cost (real agents)
03_evaluate.py        predictions           ->  metrics + economics report (json + md)
_common.py            shared: path bootstrap, pricing, usage capture, IO
```

Why 3 stages: extraction/deterministic signals are deterministic and slow-ish,
so we compute them **once** (Stage 1). Reasoning is the variable, paid, LLM part
(Stage 2) and can be re-run across models from the cached dataset. Scoring
(Stage 3) is pure post-processing and can be re-run with different policies for
free.

## Prerequisites
- Use the backend venv: `../ooxml_extractor/backend/.venv/bin/python` (already
  has fastapi/oletools/magika/openai/etc.). Or `pip install -r
  ../ooxml_extractor/backend/requirements.txt`.
- `export OPENAI_API_KEY="sk-..."` — required for **Stage 2 only**. Stage 1 and
  Stage 3 need no key.

> Run scripts from inside `experiments/` so `import _common` resolves.

## Stage 1 — build the labelled dataset (no LLM)
```bash
PY=../ooxml_extractor/backend/.venv/bin/python
$PY 01_build_dataset.py --clean ../dataset/clean --malicious ../dataset/malicious
# -> data/labelled_dataset.jsonl  (+ .meta.json)
```
Each record = `filename, source_path, label, sha256, file_size, doc_type,
extraction_ms, deterministic_ms, signal_summary (compact, LLM-ready),
signal_graph (full incl. raw_signals: macro code, visible text, all tool
outputs)`. Re-running resumes (skips files already present); `--overwrite`
restarts; `--limit N` caps per label; `--keep-workspaces` keeps extracted trees.
The label is **never** embedded inside `signal_graph` → leakage-safe to feed an LLM.

## Stage 2 — run the agentic reasoning (uses LLM)
```bash
$PY 02_run_reasoning.py --dataset data/labelled_dataset.jsonl --run-id main
# -> results/main/predictions.jsonl  (+ run_meta.json)
```
Runs the exact production path (`classify_intent` → `analyze_behavior` →
`aggregate` + deterministic floor) with the same YAML prompts/schemas/retries.
Captures per-sample, per-stage **wall time, prompt/completion tokens, USD cost,
LLM call count**. Only the signal graph is sent to the model; the label is used
solely to tag the output row. `--model-analysis` / `--model-aggregator` override
models (to compare gpt-4o-mini vs gpt-4o etc.); `--resume` continues a run;
`--limit N` for a quick subset.

## Stage 3 — evaluate (no LLM)
```bash
$PY 03_evaluate.py --run-dir results/main --rna positive
# -> results/main/report_positive.json + report_positive.md
```
Produces confusion matrix, precision/recall/specificity/F1/FPR/balanced-acc,
ROC-AUC (risk_score), latency stats (end-to-end + per stage), token stats, cost
stats + $/1000 projection, verdict distribution, deterministic-floor influence,
per-doc-type breakdown, signal-firing on TP/FP, and a false-negative list.

**The aggregator decides — no REQUIRE_NETWORK_ANALYSIS verdict.** Stage 2 calls
the aggregator with `force_decisive_verdict=True`, so it MUST commit to exactly one
of `CLEAN` / `SUSPICIOUS` / `MALICIOUS`. This is enforced two ways: a constrained
response schema (`AggregatorResponseDecisive`, RNA removed from the verdict enum)
plus a decisive system prompt (`aggregator_decisive.yaml`), and the hardcoded
`CLEAN + URLs → RNA` forcing is disabled. Network follow-up is **not lost** — it
survives as the supplementary boolean `needs_web_analysis` on each prediction, but
it never replaces the verdict. (The app keeps its original 4-class behavior by
default; only this experiment sets the flag.)

Because predictions are pure 3-class, scoring is unambiguous and leak-free by
construction; the `03_evaluate.py --rna` flag is a no-op here (kept only as a safety
net in case a prediction ever contains RNA). The report also counts how many
samples the aggregator flagged with `needs_web_analysis`.

## Cost note
Pricing lives in `_common.PRICING_USD_PER_M` (USD per 1M tokens, snapshot
2026-06). Update it if rates change or you switch models. `run_meta.json` records
the exact rates used for each run.

---

## Suggested additions to the paper's Results section
The harness already emits most of these; a few need an extra run.

1. **Cost & token economics** (now measurable): avg tokens/sample, avg $/sample,
   $/1000 docs, and a direct row vs the base paper's $0.19/request. This is a
   concrete, defensible advantage (bounded input + cheaper model). *(emitted)*
2. **Latency decomposition**: extraction vs deterministic vs LLM-reasoning, not
   just one end-to-end number — shows where the 7.4 s goes and that the
   deterministic layer is cheap. *(emitted)*
3. **Leak-free metrics**: report `positive`-policy numbers as primary so the
   "0 false positives" claim survives review. *(emitted; see `--rna`)*
4. **Deterministic-floor ablation**: how many verdicts the floor changed/justified,
   and metrics with floor on vs off — isolates the contribution of your key
   safety mechanism. *(floor influence emitted; on/off needs a flagged re-run)*
5. **Run-to-run stability**: LLM output is non-deterministic. Run Stage 2 ~3×
   (same dataset) and report verdict-flip rate / metric variance (mean ± sd).
   Reviewers love a stability number for an LLM system.
6. **ROC-AUC + operating points**: AUC on `risk_score` plus the precision/recall
   at a couple of thresholds. *(AUC emitted)*
7. **Per-attack-vector recall**: recall broken down by signal (macro vs DDE vs
   XLM vs template-injection vs macroless), to substantiate the "complete attack
   surface" and "macro-less" claims. *(TP signal-firing emitted; group as needed)*
8. **Error/FN analysis**: enumerate missed malicious files and why (encrypted,
   obfuscated, no static signal) — turns the lower recall into an honest,
   informative limitation. *(FN list emitted)*
9. **Per-doc-type breakdown** (docx/xlsm/pptx): detection isn't uniform across
   formats; show it. *(emitted)*
10. **Model comparison**: same dataset through gpt-4o-mini vs a stronger model —
    accuracy vs cost trade-off table. Strong "operational extendability" evidence.
    *(just re-run Stage 2 with `--model-*` and re-evaluate)*
11. **Statistical comparison to baseline**: if you reproduce the baseline on the
    same 285 set, a McNemar test makes the comparison rigorous rather than
    cross-dataset hand-waving.
12. **Dataset card**: counts by type/label, sources, dedup-by-hash confirmation,
    date — reconcile the 143+143 vs the paper's "285/142" discrepancy.
