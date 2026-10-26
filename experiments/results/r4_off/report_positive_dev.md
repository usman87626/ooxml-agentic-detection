# Evaluation report — `r4_off`

- Models: analysis=`gpt-4o-mini`, aggregator=`gpt-4o-mini`
- RNA policy: **positive** (REQUIRE_NETWORK_ANALYSIS handling)
- Samples scored (classification): 164 (83 clean / 81 malicious)
- Economics (latency/tokens/cost) computed over 163 samples (1 excluded: LLM calls did not complete → retry/backoff would distort timing)

## Confusion matrix

| | Pred + (mal) | Pred − (clean) |
|---|---|---|
| **Actual malicious** | TP = 68 | FN = 13 |
| **Actual clean** | FP = 19 | TN = 64 |
## Classification metrics

| Metric | Value |
|---|---|
| accuracy | 0.8049 |
| precision | 0.7816 |
| recall_tpr | 0.8395 |
| specificity_tnr | 0.7711 |
| fpr | 0.2289 |
| f1 | 0.8095 |
| balanced_accuracy | 0.8053 |
| roc_auc_riskscore | 0.709 |

## Latency, tokens & cost (paper Results material)

| Quantity | Mean | Median | Min | Max | Total |
|---|---|---|---|---|---|
| End-to-end (ms) | 5281.5659 | 4423.19 | 2288.65 | 55356.94 | — |
| LLM reasoning (ms) | 5150.1658 | 4202.92 | 2234.43 | 55152.08 | — |
| Total tokens | 4936.1227 | 4240 | 2517 | 25100 | 804588 |
| Cost (USD) | 0.000914 | 0.0008 | 0.0005 | 0.0068 | 0.149 |

- **Avg tokens/sample:** 4936.1  ·  **Avg $/sample:** 0.000914  ·  **$/1000 samples:** 0.914
- **Avg end-to-end:** 5.282 s  ·  LLM calls/sample: 2.2577

## Per-run totals (headline for the paper)

| Quantity | Value |
|---|---|
| Samples scored | 163 |
| **Total cost (USD)** | **$0.148986** |
| Avg cost / sample (USD) | $0.000914 |
| Total LLM tokens | 804,588 (prompt 741,705 / completion 62,883) |
| Avg tokens / sample | 4936.1 |
| Wall-clock for run (s) | 1846.03 |
| Avg end-to-end / sample (s) | 5.282 |
| Throughput (docs/min) | 5.3 |
| Projected cost / 1,000 docs (USD) | $0.914 |
| Projected cost / 1,000,000 docs (USD) | $914.02 |

## Per-stage token & cost (whole run)

| Stage | Calls | Prompt tok | Completion tok | Total tok | Cost (USD) |
|---|---|---|---|---|---|
| intent | 140 | 162,149 | 6,821 | 168,970 | $0.028415 |
| macro | 65 | 180,739 | 4,163 | 184,902 | $0.029609 |
| aggregator | 163 | 398,817 | 51,899 | 450,716 | $0.090962 |

## Baseline comparison (fill base-paper column from Heß & Graffi 2025)

| Metric | This run | Base paper (single-LLM) |
|---|---|---|
| Samples | 164 | 25 |
| F1 | 0.8095 | 0.929 |
| Precision | 0.7816 | ~0.93 |
| Recall | 0.8395 | ~0.93 |
| Avg latency / doc (s) | 5.282 | 5–9 |
| Avg cost / doc (USD) | 0.000914 | 0.19 |
| Total run cost (USD) | 0.148986 | ~31.16 (est. @ $0.19/doc) |

## Verdict distribution

- CLEAN: 77
- SUSPICIOUS: 65
- MALICIOUS: 22

## Deterministic floor influence
- Verdicts changed/justified by floor: 3 (1.8% of scored)

## Signal firing on true positives

- has_macros: 32
- macroless_attacks_detected: 28
- obfuscation_detected: 28
- template_injection_detected: 9
- has_dangerous_activex: 2
- xlm_detected: 1

## Signal firing on false positives

- has_macros: 15
- obfuscation_detected: 9
- macroless_attacks_detected: 7
- template_injection_detected: 2

## Missed malicious (false negatives): 13

- 59e868574332d2aae75eef795596950f4c27d5b782b1a83853e66663077050ea.xlsx (risk 5, signals: none)
- 7e6aaa62831f2c2d26fbd3af7a7650fced824eb60c8dcbb85bb61c25a9614674.pptx (risk 0, signals: none)
- 82a6bc0c91753e50d86d70e628559aa98d59ce8d18a54c0096dc4d61570c7313.xlsx (risk 5, signals: none)
- 9dd04a0478f0544a405b6eaf7ac69d12b09d47e6bcb1d9c7381a337fbd2c1cba.pptm (risk 5, signals: none)
- b291f17e5402645975b43f5c77bccfe4086521a8692a03416155b67d6c681c2d.xlsx (risk 5, signals: none)
- d053d5f0d7f4913f4c4e950ba9d19c0bed200add50a1e82f18e86e7c1a4bf925.pptx (risk 0, signals: none)
- d719137d0897400221a3aef32bcdd01d537113efd80ccc63b1cfaf9c2905b979.pptm (risk 0, signals: none)
- d7f87f322803a94fe4e9e14cd5d01204ad361b4e5466217194650620fc506cc2.pptx (risk 10, signals: none)
- dd5084a5b4c7e9853eff014ba9fd15ed00493372ec41181a3e5a169be080597a.xlsx (risk 0, signals: none)
- ef626ed9781a41cf289c34127932aa17eaa4026d3907269a36f614f8512d0f57.pptm (risk 5, signals: none)
- f1f6c2f589e7fefc7efb70dfda615f6560e5a237d544ae83755fa1e9c81264e1.pptx (risk 5, signals: none)
- f7824521fa09069c426fb84f0a96ec7f070defa691c5699e2f265e5151d5a458.xlsx (risk 5, signals: none)
- f816fa23310189511527310951896f19f9b4496994b5e7e40df9f9f8e661bc0e.xlsx (risk 5, signals: none)

## Per doc-type

| Doc type | TP | FN | FP | TN |
|---|---|---|---|---|
| Excel Macro-Enabled Workbook (OOXML) | 28 | 0 | 8 | 19 |
| Excel Workbook (OOXML) | 6 | 6 | 2 | 10 |
| PowerPoint Macro-Enabled Presentation (OOXML) | 1 | 3 | 7 | 0 |
| PowerPoint Presentation (OOXML) | 5 | 4 | 0 | 9 |
| Word Document (OOXML) | 28 | 0 | 2 | 26 |
