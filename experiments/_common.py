"""
_common.py — shared utilities for the experiments harness.

Responsibilities:
  * Bootstrap sys.path so the real backend package (extractor/, analysis/, etc.)
    is importable from these scripts WITHOUT copying any code.
  * Centralise LLM pricing and cost computation.
  * Provide a usage-capturing wrapper around the OpenAI client so we can record
    prompt/completion tokens (and therefore $) per call — the production code
    never reads response.usage, so we capture it here as a side channel without
    modifying production code.
  * Small JSONL / IO helpers.

Nothing here makes detection decisions; it only instruments the real pipeline.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
EXPERIMENTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENTS_DIR.parent


def _find_backend_dir() -> Path:
    """Locate the backend, tolerating either project-folder name spelling."""
    for name in ("ooxml_extractor", "ooxml-extractor"):
        cand = REPO_ROOT / name / "backend"
        if cand.exists():
            return cand
    # Fall back to the new canonical name for a clear error message.
    return REPO_ROOT / "ooxml_extractor" / "backend"


BACKEND_DIR = _find_backend_dir()
DATA_DIR = EXPERIMENTS_DIR / "data"
RESULTS_DIR = EXPERIMENTS_DIR / "results"
CACHE_WORKSPACES = EXPERIMENTS_DIR / ".cache" / "workspaces"

_BOOTSTRAPPED = False
LOGS_DIR = EXPERIMENTS_DIR / "logs"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging(logfile: Path | None = None, *, verbose: bool = False,
                  quiet_backend: bool = True) -> logging.Logger:
    """
    Configure root logging for an experiment script.

    - Console (stderr) shows INFO+ (DEBUG+ if verbose).
    - If logfile is given, a file handler captures DEBUG+ (full forensic trail,
      including tracebacks logged via logger.exception / exc_info).
    - Backend's own chatty INFO loggers (extractor.*, analysis.*) are pinned to
      WARNING by default so their per-stage INFO spam doesn't drown real errors,
      while their WARNING/ERROR (the "why it failed" lines) still surface.

    Backend modules use logging.getLogger(__name__) and propagate to root, so this
    makes their warnings/errors visible without touching production code.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if logfile is not None:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)

    if quiet_backend and not verbose:
        for noisy in ("extractor", "analysis", "storage"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    log = logging.getLogger("experiments")
    if logfile is not None:
        log.info("Logging to %s", logfile)
    return log


def bootstrap_backend() -> None:
    """
    Make the backend importable and point extraction workspaces at a local
    cache dir so we don't pollute the app's ooxml_workspaces/.

    Must be called BEFORE importing any backend module (config, analysis, ...).
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    if not BACKEND_DIR.exists():
        raise RuntimeError(f"Backend not found at {BACKEND_DIR}")
    # Default the extraction workspace root into experiments/.cache unless the
    # caller already set one explicitly.
    os.environ.setdefault("WORKSPACE_ROOT", str(CACHE_WORKSPACES))
    CACHE_WORKSPACES.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(BACKEND_DIR))
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Pricing — USD per 1,000,000 tokens.
# Source: public OpenAI pricing. Prices change; override via CLI/env or edit here.
# Snapshot taken 2026-06. Keys are matched as a prefix of the model id.
# ---------------------------------------------------------------------------
PRICING_USD_PER_M: dict[str, dict[str, float]] = {
    "gpt-4o-mini":  {"input": 0.150, "output": 0.600},
    "gpt-4o":       {"input": 2.500, "output": 10.000},
    "gpt-4.1-mini": {"input": 0.400, "output": 1.600},
    "gpt-4.1-nano": {"input": 0.100, "output": 0.400},
    "gpt-4.1":      {"input": 2.000, "output": 8.000},
    "o4-mini":      {"input": 1.100, "output": 4.400},
}
_DEFAULT_PRICE_KEY = "gpt-4o-mini"
_unknown_models_seen: set[str] = set()


def price_for(model: str) -> dict[str, float]:
    """Return {input, output} USD/1M for a model id (longest matching prefix)."""
    if not model:
        return PRICING_USD_PER_M[_DEFAULT_PRICE_KEY]
    best = None
    for key in PRICING_USD_PER_M:
        if model.startswith(key) and (best is None or len(key) > len(best)):
            best = key
    if best is None:
        if model not in _unknown_models_seen:
            _unknown_models_seen.add(model)
            print(f"[pricing] WARNING: no price for model '{model}', "
                  f"falling back to '{_DEFAULT_PRICE_KEY}' rates.", file=sys.stderr)
        best = _DEFAULT_PRICE_KEY
    return PRICING_USD_PER_M[best]


def compute_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    p = price_for(model)
    return (prompt_tokens / 1_000_000.0) * p["input"] + \
           (completion_tokens / 1_000_000.0) * p["output"]


# ---------------------------------------------------------------------------
# Usage-capturing OpenAI client wrapper
# ---------------------------------------------------------------------------
class UsageRecorder:
    """
    Wraps the real OpenAI client so every `.beta.chat.completions.parse(...)`
    call is transparently observed and its token usage appended to a sink.

    Usage:
        rec = UsageRecorder.install()         # patches config.get_openai_client
        rec.reset()
        ... call real agent (which calls config.get_openai_client().beta...parse) ...
        calls = rec.drain()                   # list of {model, prompt_tokens, ...}
    """

    def __init__(self, real_client: Any):
        self._real = real_client
        self.calls: list[dict] = []
        self.served: dict[str, int] = {}   # "snapshot|fingerprint" -> call count
        parse = self._make_parse()
        completions = SimpleNamespace(parse=parse)
        chat = SimpleNamespace(completions=completions)
        beta = SimpleNamespace(chat=chat)
        # The proxy object handed to production code in place of the real client.
        self.client = SimpleNamespace(beta=beta, _real=real_client)

    def _make_parse(self):
        log = logging.getLogger("experiments.llm")

        def parse(**kwargs):
            model = kwargs.get("model", "")
            try:
                resp = self._real.beta.chat.completions.parse(**kwargs)
            except Exception as exc:  # noqa: BLE001
                # Record the failure (zero tokens) and log WITH traceback, then
                # re-raise so the production agent's own try/except handles it as
                # usual. This makes otherwise-silent LLM failures visible.
                self.calls.append({
                    "model": model, "prompt_tokens": 0, "completion_tokens": 0,
                    "total_tokens": 0, "error": f"{type(exc).__name__}: {exc}",
                })
                log.error("LLM parse failed (model=%s): %s", model, exc, exc_info=True)
                raise
            u = getattr(resp, "usage", None)
            # R6-7: record the exact model snapshot the API served (e.g.
            # gpt-4o-mini-2024-07-18) and its system fingerprint, not just the alias.
            served = str(getattr(resp, "model", "") or "")
            fp = str(getattr(resp, "system_fingerprint", "") or "")
            key = f"{served}|{fp}"
            self.served[key] = self.served.get(key, 0) + 1
            self.calls.append({
                "model": model,
                "served_model": served,
                "prompt_tokens": int(getattr(u, "prompt_tokens", 0) or 0) if u else 0,
                "completion_tokens": int(getattr(u, "completion_tokens", 0) or 0) if u else 0,
                "total_tokens": int(getattr(u, "total_tokens", 0) or 0) if u else 0,
            })
            return resp
        return parse

    def reset(self) -> None:
        self.calls = []

    def drain(self) -> list[dict]:
        out = self.calls
        self.calls = []
        return out

    @classmethod
    def install(cls) -> "UsageRecorder":
        """Patch config.get_openai_client to return the recording proxy."""
        import config
        real = config.get_openai_client()  # raises RuntimeError if no key
        rec = cls(real)
        config.get_openai_client = lambda: rec.client  # type: ignore[assignment]
        return rec


def summarise_calls(calls: list[dict]) -> dict:
    """Aggregate a list of call usage records into prompt/completion/total + cost."""
    prompt = sum(c["prompt_tokens"] for c in calls)
    completion = sum(c["completion_tokens"] for c in calls)
    total = sum(c["total_tokens"] for c in calls) or (prompt + completion)
    cost = sum(compute_cost(c["model"], c["prompt_tokens"], c["completion_tokens"]) for c in calls)
    failed = sum(1 for c in calls if c.get("error"))
    return {
        "calls": len(calls),
        "failed_calls": failed,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "cost_usd": round(cost, 8),
    }


# ---------------------------------------------------------------------------
# JSONL helpers
# ---------------------------------------------------------------------------
def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
