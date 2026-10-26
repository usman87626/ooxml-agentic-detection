"""
logging_setup.py — structured JSON logging for the OOXML extractor.

Produces log lines like:
  {"ts": "2026-03-06T01:35:20Z", "level": "INFO", "ws": "uuid", "module": "zip_reader", "msg": "..."}

Usage::

    from extractor.logging_setup import get_logger, setup_logging

    setup_logging()  # call once at app startup
    logger = get_logger(__name__, workspace_id="abc-123")
    logger.info("Starting extraction")
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A002
        doc = {
            "ts": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }
        # Attach workspace_id if present on the record
        ws = getattr(record, "workspace_id", None)
        if ws:
            doc["ws"] = ws

        # Attach exception info if present
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)

        return json.dumps(doc, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Workspace-bound logger adapter
# ---------------------------------------------------------------------------

class WorkspaceLogger(logging.LoggerAdapter):
    """
    Logger adapter that automatically injects workspace_id into every record.

    Usage::

        logger = get_logger("extractor.zip_reader", workspace_id=ws_id)
        logger.info("Extracted 42 entries")
        # → {"ts":..., "level":"INFO", "ws":"uuid", "module":"extractor.zip_reader", "msg":"Extracted 42 entries"}
    """

    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})
        kwargs["extra"]["workspace_id"] = self.extra.get("workspace_id", "")
        return msg, kwargs


def get_logger(name: str, workspace_id: str = "") -> WorkspaceLogger:
    """
    Return a :class:`WorkspaceLogger` for *name* bound to *workspace_id*.

    If *workspace_id* is empty, logs will omit the "ws" field.
    """
    base = logging.getLogger(name)
    return WorkspaceLogger(base, {"workspace_id": workspace_id})


# ---------------------------------------------------------------------------
# Root setup
# ---------------------------------------------------------------------------

_logging_configured = False


def setup_logging(
    level: int = logging.INFO,
    stream=None,
) -> None:
    """
    Configure root logger with JSON formatting.

    Call once at application startup (idempotent).
    """
    global _logging_configured
    if _logging_configured:
        return

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(level)
    # Remove any pre-existing handlers (e.g., basicConfig defaults)
    root.handlers.clear()
    root.addHandler(handler)

    _logging_configured = True


def reset_logging() -> None:
    """Reset logging configuration (useful for tests)."""
    global _logging_configured
    _logging_configured = False
    logging.getLogger().handlers.clear()
