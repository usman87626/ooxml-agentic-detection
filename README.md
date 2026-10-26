# Deterministic-First Agentic Detection of Malicious OOXML Documents

Code, evaluation data and results for the paper *"Towards Reliable Detection of Malicious Office Documents: A Deterministic-First Agentic Approach"* (Information Processing & Management, under revision).

## Contents

| Path | What it contains |
|---|---|
| `ooxml_extractor/backend/` | Framework: 14-stage extractor, 14 deterministic analyzers, Signal Graph (`analysis/signal_graph.py`), LLM agents, deterministic verdict floor |
| `ooxml_extractor/frontend/` | React/Vite user interface (optional) |
| `experiments/` | Reproducible evaluation pipeline (build dataset → run agents → evaluate → final report) |
| `experiments/data/split_r2.json` | Group-aware development/test split (164 / 160 documents) |
| `experiments/results/r4_*/` | Per-document predictions and run metadata for the four reported configurations |
| `experiments/results/final_r4/` | Final reports (`report_test.*` = numbers reported in the paper) |
| `experiments/results/environment.json` | Hardware and software used |
| `dataset/metadata/dataset_manifest.csv` | All 324 documents: SHA-256, label, format, source, malware family, VirusTotal verdict, label basis |
| `dataset/metadata/` (other files) | MalwareBazaar metadata, VirusTotal results, benign xlsm selection log, excluded samples |
| `dataset/mb_downloader.py`, `dataset/vt_check.py` | Download malicious samples by hash; verify labels on VirusTotal |

## Dataset

324 OOXML documents, balanced within every format:

| Format | Malicious | Benign |
|---|---|---|
| docx | 56 | 56 |
| xlsm | 55 | 55 |
| xlsx | 25 | 25 |
| pptx | 18 | 18 |
| pptm | 8 | 8 |
| **Total** | **162** | **162** |

- **Malicious samples are not redistributed.** Retrieve them from MalwareBazaar by SHA-256 (requires a free MalwareBazaar API key):
  ```bash
  cd dataset && pip install pyzipper && export MB_API_KEY="..."
  python mb_downloader.py manifest   # downloads exactly the hashes in metadata/dataset_manifest.csv
  ```
  The manifest lists the exact hashes used. One sample (`MAD_Sessional_Papers_Leaked.docx`) is not on MalwareBazaar and is available on request.
- **Benign samples** are listed with SHA-256 and source (GitHub repositories or public web pages found with Google search operators). The complete corpus is available from the corresponding author on reasonable request for research purposes.

## Reproducing the results

Requirements: Python 3.12, an OpenAI API key (only for step 2).

```bash
cd ooxml_extractor/backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd ../../experiments
export OPENAI_API_KEY="..."

python 01_build_dataset.py --clean ../dataset/clean --malicious ../dataset/malicious --out data/labelled_dataset_r4.jsonl
python 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_full   --graph-mode full
python 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_nodes  --graph-mode nodes
python 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_masked --graph-mode full --mask-doc-type
python 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_off    --graph-mode off
python 05_final_report.py --split test
```

The final report can be regenerated from the included predictions without any API key: `python 05_final_report.py --split test`.

LLM outputs are not perfectly deterministic even at temperature 0, so re-runs may differ slightly from the included predictions. Reported runs used `gpt-4o-mini-2024-07-18`.

## Main results (test half, 160 documents)

| View | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Agents' verdict (MALICIOUS or SUSPICIOUS = positive) | 78.2% | 84.0% | 0.810 | 24.1% |
| MALICIOUS-only | 95.7% | 55.6% | 0.703 | 2.5% |

Full tables, ablations and confidence intervals: `experiments/results/final_r4/report_test.md`.

## Safety

The framework performs static analysis only and never executes documents. Handle malicious samples in an isolated environment. Predictions contain indicators (URLs, paths) extracted from malware samples; treat them as untrusted.

## Citation

[Add citation after publication]
