# Evaluation report — `r4_nodes`

- Models: analysis=`gpt-4o-mini`, aggregator=`gpt-4o-mini`
- RNA policy: **positive** (REQUIRE_NETWORK_ANALYSIS handling)
- Samples scored (classification): 164 (83 clean / 81 malicious)
- Economics (latency/tokens/cost) computed over 163 samples (1 excluded: LLM calls did not complete → retry/backoff would distort timing)

## Confusion matrix

| | Pred + (mal) | Pred − (clean) |
|---|---|---|
| **Actual malicious** | TP = 68 | FN = 13 |
| **Actual clean** | FP = 24 | TN = 59 |
## Classification metrics

| Metric | Value |
|---|---|
| accuracy | 0.7744 |
| precision | 0.7391 |
| recall_tpr | 0.8395 |
| specificity_tnr | 0.7108 |
| fpr | 0.2892 |
| f1 | 0.7861 |
| balanced_accuracy | 0.7752 |
| roc_auc_riskscore | 0.8449 |

## Latency, tokens & cost (paper Results material)

| Quantity | Mean | Median | Min | Max | Total |
|---|---|---|---|---|---|
| End-to-end (ms) | 5442.2393 | 4635.66 | 2745.52 | 64719.57 | — |
| LLM reasoning (ms) | 5310.8391 | 4329.96 | 2689.82 | 64514.71 | — |
| Total tokens | 5507.0429 | 4611 | 2952 | 32404 | 897648 |
| Cost (USD) | 0.00101 | 0.0008 | 0.0006 | 0.0084 | 0.1647 |

- **Avg tokens/sample:** 5507.0  ·  **Avg $/sample:** 0.00101  ·  **$/1000 samples:** 1.0104
- **Avg end-to-end:** 5.442 s  ·  LLM calls/sample: 2.2577

## Per-run totals (headline for the paper)

| Quantity | Value |
|---|---|
| Samples scored | 163 |
| **Total cost (USD)** | **$0.164693** |
| Avg cost / sample (USD) | $0.00101 |
| Total LLM tokens | 897,648 (prompt 830,880 / completion 66,768) |
| Avg tokens / sample | 5507.0 |
| Wall-clock for run (s) | 1888.09 |
| Avg end-to-end / sample (s) | 5.442 |
| Throughput (docs/min) | 5.18 |
| Projected cost / 1,000 docs (USD) | $1.0104 |
| Projected cost / 1,000,000 docs (USD) | $1010.39 |

## Per-stage token & cost (whole run)

| Stage | Calls | Prompt tok | Completion tok | Total tok | Cost (USD) |
|---|---|---|---|---|---|
| intent | 140 | 162,149 | 6,869 | 169,018 | $0.028444 |
| macro | 65 | 180,739 | 4,042 | 184,781 | $0.029536 |
| aggregator | 163 | 487,992 | 55,857 | 543,849 | $0.106713 |

## Baseline comparison (fill base-paper column from Heß & Graffi 2025)

| Metric | This run | Base paper (single-LLM) |
|---|---|---|
| Samples | 164 | 25 |
| F1 | 0.7861 | 0.929 |
| Precision | 0.7391 | ~0.93 |
| Recall | 0.8395 | ~0.93 |
| Avg latency / doc (s) | 5.442 | 5–9 |
| Avg cost / doc (USD) | 0.00101 | 0.19 |
| Total run cost (USD) | 0.164693 | ~31.16 (est. @ $0.19/doc) |

## Verdict distribution

- CLEAN: 72
- SUSPICIOUS: 70
- MALICIOUS: 22

## Deterministic floor influence
- Verdicts changed/justified by floor: 1 (0.6% of scored)

## Signal firing on true positives

- has_macros: 32
- macroless_attacks_detected: 28
- obfuscation_detected: 28
- template_injection_detected: 9
- has_dangerous_activex: 2
- xlm_detected: 1

## Signal firing on false positives

- has_macros: 21
- obfuscation_detected: 9
- macroless_attacks_detected: 7
- template_injection_detected: 2

## Missed malicious (false negatives): 13

- 4dd75e9c997abbb78aff675a28039b49ed7ebbfc2d97a4e378f7fd0d03d7e2fd.pptx (risk 3, signals: none)
- 59e868574332d2aae75eef795596950f4c27d5b782b1a83853e66663077050ea.xlsx (risk 24, signals: none)
- 7e6aaa62831f2c2d26fbd3af7a7650fced824eb60c8dcbb85bb61c25a9614674.pptx (risk 0, signals: none)
- 82a6bc0c91753e50d86d70e628559aa98d59ce8d18a54c0096dc4d61570c7313.xlsx (risk 24, signals: none)
- 92779228416f0dce42fd4e3d1ead5cfaecf563694391c01f421c53edd773b72e.pptx (risk 3, signals: none)
- 9dd04a0478f0544a405b6eaf7ac69d12b09d47e6bcb1d9c7381a337fbd2c1cba.pptm (risk 0, signals: none)
- b291f17e5402645975b43f5c77bccfe4086521a8692a03416155b67d6c681c2d.xlsx (risk 24, signals: none)
- d719137d0897400221a3aef32bcdd01d537113efd80ccc63b1cfaf9c2905b979.pptm (risk 0, signals: none)
- d7f87f322803a94fe4e9e14cd5d01204ad361b4e5466217194650620fc506cc2.pptx (risk 24, signals: none)
- dd5084a5b4c7e9853eff014ba9fd15ed00493372ec41181a3e5a169be080597a.xlsx (risk 0, signals: none)
- ef626ed9781a41cf289c34127932aa17eaa4026d3907269a36f614f8512d0f57.pptm (risk 0, signals: none)
- f7824521fa09069c426fb84f0a96ec7f070defa691c5699e2f265e5151d5a458.xlsx (risk 24, signals: none)
- f816fa23310189511527310951896f19f9b4496994b5e7e40df9f9f8e661bc0e.xlsx (risk 24, signals: none)

## Per doc-type

| Doc type | TP | FN | FP | TN |
|---|---|---|---|---|
| Excel Macro-Enabled Workbook (OOXML) | 28 | 0 | 14 | 13 |
| Excel Workbook (OOXML) | 6 | 6 | 2 | 10 |
| PowerPoint Macro-Enabled Presentation (OOXML) | 1 | 3 | 7 | 0 |
| PowerPoint Presentation (OOXML) | 5 | 4 | 0 | 9 |
| Word Document (OOXML) | 28 | 0 | 1 | 27 |
