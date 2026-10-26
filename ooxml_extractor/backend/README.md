# OOXML Extractor — Backend

FastAPI backend for full-fidelity OOXML extraction + agentic security analysis.

> [!TIP]
> **For a deep dive into our detection psychology and architecture, see [TECHNICAL.md](TECHNICAL.md).**

## Setup

```bash
cd ooxml-extractor/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY="sk-..."
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | *(required)* | OpenAI API key |
| `WORKSPACE_ROOT` | `./ooxml_workspaces` | Extraction workspace root |
| `MAX_LLM_RETRIES` | `3` | Max retry attempts for LLM calls |
| `LLM_RETRY_BASE_DELAY` | `1.0` | Base delay (seconds) for exponential backoff |
| `OPENAI_MODEL_AGGREGATOR` | `gpt-4o-mini` | Model for verdict aggregation |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload Office document → `{workspace_id}` |
| `GET` | `/api/workspaces/{id}/manifest` | Full extraction manifest JSON |
| `GET` | `/api/workspaces/{id}/file?path=...` | Stream raw bytes |
| `GET` | `/api/workspaces/{id}/preview?path=...` | Decoded text or hex dump |
| `GET` | `/api/workspaces/{id}/search?q=...` | Full-text search |
| `POST` | `/api/workspaces/{id}/analyze` | Trigger agentic analysis |
| `GET` | `/api/workspaces/{id}/analysis/status` | Analysis status |
| `GET` | `/api/workspaces/{id}/analysis/verdict` | Final verdict JSON |
| `GET` | `/health` | Health check |

## Architecture

```
backend/
├── app.py                          # FastAPI application
├── config.py                       # Centralized config (env vars)
│
├── extractor/                      # 14-stage extraction pipeline
│   ├── manifest_builder.py         # Pipeline orchestrator
│   ├── zip_reader.py               # ZIP reader + bomb protection
│   ├── content_type_detector.py    # [Content_Types].xml + magic
│   ├── xml_decoder.py              # UTF-8/UTF-16LE decoder
│   ├── binary_classifier.py        # Magic Byte + Magika ML
│   ├── structure_enumerator.py     # OOXML role mapping
│   ├── rels_parser.py              # .rels relationship parser
│   ├── macro_vba_extractor.py      # olevba + encrypted VBA detection
│   ├── xlm_extractor.py            # XLM macro sheet detection
│   ├── dde_detector.py             # DDE/DDEAUTO patterns
│   ├── ole_embedded_extractor.py   # OLE stream enumeration
│   ├── rtf_extractor.py            # RTF OLE + CVE-2017-11882
│   ├── html_svg_extractor.py       # HTML/SVG payload extraction
│   ├── media_validator.py          # EMF/WMF/font/TIFF validation
│   ├── content_type_validator.py   # Content_Types.xml poisoning detection
│   ├── binary_peeker.py            # Magic-byte + hex preview
│   ├── url_whitelist.py            # URL filtering
│   └── utils.py                    # SHA-256, ZipSlip safety
│
├── analysis/                       # Agentic analysis layer
│   ├── analysis_pipeline.py        # Pipeline orchestrator
│   ├── deterministic_engine.py     # 14 parallel deterministic tools
│   ├── verdict_aggregator.py       # LLM verdict + floor + retry
│   ├── macro_behavior_analyzer.py  # LLM macro analysis
│   ├── schema.py                   # SignalGraph, AnalysisVerdict
│   ├── instructions/               # LLM prompt templates (YAML)
│   │   ├── loader.py
│   │   └── *.yaml
│   └── tools/                      # Deterministic analysis tools
│       ├── macro_analyzer.py
│       ├── ole_analyzer.py
│       ├── dde_analyzer.py
│       ├── xlm_analyzer.py
│       ├── obfuscation_analyzer.py
│       ├── template_injection_analyzer.py
│       ├── structure_analyzer.py
│       ├── prompt_injection_scanner.py
│       ├── ooxml_attack_analyzer.py
│       ├── pcode_analyzer.py
│       ├── macroless_attack_analyzer.py
│       ├── url_validator.py
│       ├── html_svg_analyzer.py
│       ├── intent_analyzer.py
│       └── attack_utils.py
│
├── agents/
│   └── guardrails.py               # LLM guardrails + Unicode normalization
│
├── models/
│   └── schema.py                   # Pydantic manifest models (v3)
│
├── storage/
│   └── workspace.py                # UUID workspace folder management
│
└── tests/
    ├── conftest.py
    ├── test_zip_slip.py
    ├── test_rels_parser.py
    ├── test_macro_extractor.py
    ├── test_dde_detector.py
    ├── test_xlm_extractor.py
    ├── test_binary_classifier.py
    ├── test_analysis_tools.py
    ├── test_structure_enumerator.py
    └── test_timing.py
```

## Running Tests

```bash
pytest tests/ -v
# 132 tests pass (4 pre-existing pyparsing/olevba Python 3.12 failures)
```

## Security

- **No execution**: purely static analysis
- **ZipSlip prevention**: all paths validated
- **Zip bomb protection**: 200MB cumulative, 100MB/entry, 10K entry cap
- **Office decryption**: `msoffcrypto-tool` for encrypted documents
- **Encrypted VBA detection**: `DPB=`/`DPx=` projects flagged
- **Unicode normalization**: NFKC + zero-width character stripping
- **Deterministic verdict floor**: LLM cannot override confirmed threats
- **LLM retry**: exponential backoff, configurable via env vars
- **Parallel tooling**: all 14 deterministic tools run concurrently
- **Guardrails**: applied at all 3 LLM call sites
