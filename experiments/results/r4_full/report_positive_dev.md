# Evaluation report — `r4_full`

- Models: analysis=`gpt-4o-mini`, aggregator=`gpt-4o-mini`
- RNA policy: **positive** (REQUIRE_NETWORK_ANALYSIS handling)
- Samples scored (classification): 164 (83 clean / 81 malicious)
- Economics (latency/tokens/cost) computed over 163 samples (1 excluded: LLM calls did not complete → retry/backoff would distort timing)

## Confusion matrix

| | Pred + (mal) | Pred − (clean) |
|---|---|---|
| **Actual malicious** | TP = 68 | FN = 13 |
| **Actual clean** | FP = 21 | TN = 62 |
## Classification metrics

| Metric | Value |
|---|---|
| accuracy | 0.7927 |
| precision | 0.764 |
| recall_tpr | 0.8395 |
| specificity_tnr | 0.747 |
| fpr | 0.253 |
| f1 | 0.8 |
| balanced_accuracy | 0.7932 |
| roc_auc_riskscore | 0.8606 |

## Latency, tokens & cost (paper Results material)

| Quantity | Mean | Median | Min | Max | Total |
|---|---|---|---|---|---|
| End-to-end (ms) | 5547.8262 | 4519.91 | 2931.0 | 76737.44 | — |
| LLM reasoning (ms) | 5416.4261 | 4423.63 | 2873.53 | 76532.58 | — |
| Total tokens | 5753.7301 | 4639 | 3027 | 30864 | 937858 |
| Cost (USD) | 0.001042 | 0.0008 | 0.0006 | 0.0075 | 0.1699 |

- **Avg tokens/sample:** 5753.7  ·  **Avg $/sample:** 0.001042  ·  **$/1000 samples:** 1.0423
- **Avg end-to-end:** 5.548 s  ·  LLM calls/sample: 2.2577

## Per-run totals (headline for the paper)

| Quantity | Value |
|---|---|
| Samples scored | 163 |
| **Total cost (USD)** | **$0.169889** |
| Avg cost / sample (USD) | $0.001042 |
| Total LLM tokens | 937,858 (prompt 872,947 / completion 64,911) |
| Avg tokens / sample | 5753.7 |
| Wall-clock for run (s) | 1930.6 |
| Avg end-to-end / sample (s) | 5.548 |
| Throughput (docs/min) | 5.07 |
| Projected cost / 1,000 docs (USD) | $1.0423 |
| Projected cost / 1,000,000 docs (USD) | $1042.26 |

## Per-stage token & cost (whole run)

| Stage | Calls | Prompt tok | Completion tok | Total tok | Cost (USD) |
|---|---|---|---|---|---|
| intent | 140 | 162,149 | 6,877 | 169,026 | $0.028449 |
| macro | 65 | 180,739 | 4,100 | 184,839 | $0.029571 |
| aggregator | 163 | 530,059 | 53,934 | 583,993 | $0.111869 |

## Baseline comparison (fill base-paper column from Heß & Graffi 2025)

| Metric | This run | Base paper (single-LLM) |
|---|---|---|
| Samples | 164 | 25 |
| F1 | 0.8 | 0.929 |
| Precision | 0.764 | ~0.93 |
| Recall | 0.8395 | ~0.93 |
| Avg latency / doc (s) | 5.548 | 5–9 |
| Avg cost / doc (USD) | 0.001042 | 0.19 |
| Total run cost (USD) | 0.169889 | ~31.16 (est. @ $0.19/doc) |

## Verdict distribution

- CLEAN: 75
- SUSPICIOUS: 52
- MALICIOUS: 37

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

- has_macros: 17
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
| Excel Macro-Enabled Workbook (OOXML) | 28 | 0 | 10 | 17 |
| Excel Workbook (OOXML) | 6 | 6 | 2 | 10 |
| PowerPoint Macro-Enabled Presentation (OOXML) | 1 | 3 | 7 | 0 |
| PowerPoint Presentation (OOXML) | 5 | 4 | 0 | 9 |
| Word Document (OOXML) | 28 | 0 | 2 | 26 |
