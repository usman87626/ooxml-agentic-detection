"""
config.py — centralised configuration for OOXML Extractor + Agentic Analysis Layer.

All settings read from environment variables with safe defaults.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


# ---------------------------------------------------------------------------
# Workspace storage
# ---------------------------------------------------------------------------
WORKSPACE_ROOT: Path = Path(os.environ.get("WORKSPACE_ROOT", "./ooxml_workspaces"))


# ---------------------------------------------------------------------------
# OpenAI — agentic analysis
# ---------------------------------------------------------------------------
# Read from environment only — never commit a key. Set OPENAI_API_KEY in the env.
OPENAI_API_KEY:           str = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL_ANALYSIS:    str = os.environ.get("OPENAI_MODEL_ANALYSIS",    "gpt-4o-mini")
OPENAI_MODEL_AGGREGATOR:  str = os.environ.get("OPENAI_MODEL_AGGREGATOR",  "gpt-4o-mini")

# Maximum chars of document text fed to any prompt
MAX_SAFE_TEXT_CHARS:   int = 4_000

# LLM retry configuration
MAX_LLM_RETRIES:      int = int(os.environ.get("MAX_LLM_RETRIES", "3"))
LLM_RETRY_BASE_DELAY: float = float(os.environ.get("LLM_RETRY_BASE_DELAY", "3.0"))

# LLM sampling temperature (0 = deterministic / reproducible). Overridable via env.
LLM_TEMPERATURE: float = float(os.environ.get("LLM_TEMPERATURE", "0"))

# Signal Graph given to the verdict aggregator (analysis/signal_graph.py):
#   full  = nodes + rule-based edges + graph risk score (default)
#   nodes = nodes only, no edges, max-node risk score (edge ablation)
#   off   = no graph; risk score from the LLM (pre-revision behaviour, run v3)
SIGNAL_GRAPH_MODE: str = os.environ.get("SIGNAL_GRAPH_MODE", "full").lower()

# LLM Token Limits
LLM_MAX_COMPLETION_TOKENS_AGGREGATOR: int = 8192
LLM_MAX_COMPLETION_TOKENS_ANALYSIS:   int = 1500

ALLOWED_EXTENSIONS = {
    ".docx", ".docm", ".dotx", ".dotm",
    ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
    ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
    ".zip",
}


# ---------------------------------------------------------------------------
# OpenAI client (lazy singleton)
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_openai_client():
    """Return a cached OpenAI client. Raises if OPENAI_API_KEY is missing."""
    try:
        from openai import OpenAI  # type: ignore
    except ImportError as exc:
        raise RuntimeError("openai package not installed. Run: pip install openai>=1.70.0") from exc

    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OPENAI_API_KEY environment variable is not set. "
            "Analysis requires a valid OpenAI API key."
        )
    return OpenAI(api_key=OPENAI_API_KEY)
