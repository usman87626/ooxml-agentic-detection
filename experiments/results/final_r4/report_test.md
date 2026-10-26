# Final evaluation — split: **test** (160 samples: 81 malicious / 79 clean)

Pre-registered before scoring the test half. Primary = agents' own verdict of the full system (MALICIOUS or SUSPICIOUS = positive). No verdict is altered by this script.

## 1. Detection performance (primary run)

| Configuration | TP | FN | FP | TN | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] | FPR [95% CI] | MCC |
|---|---|---|---|---|---|---|---|---|---|
| Agents' verdict (MAL or SUSP = positive) | 68 | 13 | 19 | 60 | 78.2% [68.4, 85.5] | 84.0% [74.5, 90.4] | 0.810 [0.742, 0.869] | 24.1% [16.0, 34.5] | 0.601 |
| MALICIOUS-only view | 45 | 36 | 2 | 77 | 95.7% [85.8, 98.8] | 55.6% [44.7, 65.9] | 0.703 [0.607, 0.787] | 2.5% [0.7, 8.8] | 0.582 |

Accuracy 80.0%, balanced accuracy 79.9%, specificity 75.9%.

**3-class breakdown**

| True label | → MALICIOUS | → SUSPICIOUS | → CLEAN |
|---|---|---|---|
| malicious | 45 | 23 | 13 |
| clean | 2 | 17 | 60 |

## 2. Ablations (same samples, same model)

| Configuration | TP | FN | FP | TN | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] | FPR [95% CI] | MCC |
|---|---|---|---|---|---|---|---|---|---|
| Full graph (primary) | 68 | 13 | 19 | 60 | 78.2% [68.4, 85.5] | 84.0% [74.5, 90.4] | 0.810 | 24.1% [16.0, 34.5] | 0.601 |
| Nodes only, no edges | 69 | 12 | 21 | 58 | 76.7% [66.9, 84.2] | 85.2% [75.9, 91.3] | 0.807 | 26.6% [18.1, 37.2] | 0.591 |
| Full graph, file type hidden | 68 | 13 | 27 | 52 | 71.6% [61.8, 79.7] | 84.0% [74.5, 90.4] | 0.773 | 34.2% [24.7, 45.2] | 0.507 |
| Pre-revision config (no graph) | 67 | 14 | 22 | 57 | 75.3% [65.4, 83.1] | 82.7% [73.1, 89.4] | 0.788 | 27.8% [19.2, 38.6] | 0.552 |

| Configuration | MALICIOUS-only precision | MALICIOUS-only recall | MALICIOUS-only F1 |
|---|---|---|---|
| Full graph (primary) | 95.7% | 55.6% | 0.703 |
| Nodes only, no edges | 90.9% | 24.7% | 0.388 |
| Full graph, file type hidden | 95.6% | 53.1% | 0.683 |
| Pre-revision config (no graph) | 91.7% | 27.2% | 0.419 |

**Paired McNemar tests (correctness, triage convention)**

| Comparison | only primary correct | only other correct | exact p |
|---|---|---|---|
| full vs Nodes only, no edges | 3 | 2 | 1.000 |
| full vs Full graph, file type hidden | 9 | 1 | 0.021 |
| full vs Pre-revision config (no graph) | 5 | 1 | 0.219 |

## 3. Deterministic risk score — ROC-AUC (RQ2, R6-4)

| Score | ROC-AUC [95% bootstrap CI] |
|---|---|
| Alg. 3 as first submitted (mean of node evidence) | 0.774 [0.700, 0.843] |
| Nodes only (max node evidence, no edges) | 0.867 [0.805, 0.920] |
| Signal Graph (revised Alg. 3, correlation edges) | 0.870 [0.808, 0.922] |
| LLM's own risk estimate (for comparison) | 0.872 |

## 4. Per-format results (R6-1)

| Format | Mal / Clean | Recall (full) | FPR (full) | Recall (type hidden) | FPR (type hidden) | Majority-format baseline acc. |
|---|---|---|---|---|---|---|
| docx | 28 / 28 | 100.0% | 14.3% | 100.0% | 17.9% | 50.0% |
| xlsm | 27 / 28 | 100.0% | 46.4% | 100.0% | 71.4% | 50.9% |
| xlsx | 13 / 13 | 61.5% | 7.7% | 61.5% | 7.7% | 50.0% |
| pptx | 9 / 9 | 44.4% | 0.0% | 44.4% | 0.0% | 50.0% |
| pptm | 4 / 1 | 25.0% | 100.0% | 25.0% | 100.0% | 80.0% |

Format-only baseline (predict each format's majority class): accuracy 51.2% (≈50% means the corpus is balanced within formats). Primary accuracy: 80.0%.

## 5. Campaign / family duplication (R6-3)

Malicious samples: 81 in 48 similarity groups (ssdeep ≥ 50); largest group 24 samples. Sample-level recall 84.0%; group-weighted recall (each group counts once) 74.0%.

## 6. Label-basis sensitivity (R6-2)

Restricting to samples whose label is confirmed by VirusTotal (malicious ≥ 5 engines, clean 0 engines; 126 samples): precision 79.0%, recall 85.3%, F1 0.821, FPR 33.3%.

## 7. Expected alert load at realistic base rates (R6-6, R7-1)

Assumes 10,000 documents/day; FPR and recall from section 1 (95% Wilson CI for FPR).

| View | Malicious base rate | True detections/day | False alerts/day [95% CI] | Alert precision |
|---|---|---|---|---|
| Triage (MAL or SUSP) | 1.0% | 84.0 | 2381.0 [1581.2, 3419.1] | 3.4% |
| Triage (MAL or SUSP) | 0.1% | 8.4 | 2402.7 [1595.6, 3450.1] | 0.3% |
| MALICIOUS-only | 1.0% | 55.6 | 250.6 [69.0, 868.1] | 18.1% |
| MALICIOUS-only | 0.1% | 5.6 | 252.9 [69.6, 876.0] | 2.1% |

## 8. Cost and latency (primary run)

n = 160 (samples with a failed LLM call excluded). End-to-end median 5.15 s, p90 7.21 s; mean tokens 5682; mean cost $0.00102/document ($1.02 per 1,000).

## 9. Run provenance

- `r4_full`: graph_mode=full, doc_type_masked=False, served=gpt-4o-mini-2024-07-18, ran_at=2026-10-25T18:26:43.442539+00:00
- `r4_nodes`: graph_mode=nodes, doc_type_masked=False, served=gpt-4o-mini-2024-07-18, ran_at=2026-10-25T18:26:09.242816+00:00
- `r4_masked`: graph_mode=full, doc_type_masked=True, served=gpt-4o-mini-2024-07-18, ran_at=2026-10-25T18:26:41.418385+00:00
- `r4_off`: graph_mode=off, doc_type_masked=False, served=gpt-4o-mini-2024-07-18, ran_at=2026-10-25T18:25:41.981823+00:00
