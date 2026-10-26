"""
timing.py — pipeline timing utilities.

Uses time.perf_counter() for high-resolution sub-millisecond accuracy.
Provides a context-manager based API for easy stage timing.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class StageTimingRecord:
    """Timing result for one pipeline stage."""
    name: str
    time_ms: float

    def to_dict(self) -> dict:
        return {"name": self.name, "time_ms": round(self.time_ms, 3)}


class PipelineTimings:
    """
    Accumulates per-stage timing records for one extraction run.

    Usage::

        timings = PipelineTimings()

        with timings.stage("zip_enumeration"):
            ...code...

        with timings.stage("macro_extraction"):
            ...code...

        timings.finish()
        print(timings.total_ms)
        print(timings.to_list())
    """

    def __init__(self) -> None:
        self._records: list[StageTimingRecord] = []
        self._start: float = time.perf_counter()
        self._end: float = 0.0

    @contextmanager
    def stage(self, name: str) -> Generator[None, None, None]:
        """Context manager that records elapsed time for *name*."""
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self._records.append(StageTimingRecord(name=name, time_ms=elapsed_ms))

    def finish(self) -> None:
        """Mark the end of the pipeline run."""
        self._end = time.perf_counter()

    @property
    def total_ms(self) -> float:
        """Total elapsed time from construction to finish() in milliseconds."""
        end = self._end if self._end else time.perf_counter()
        return (end - self._start) * 1000.0

    def to_list(self) -> list[dict]:
        """Return all stage records as a list of dicts."""
        return [r.to_dict() for r in self._records]

    def to_dict(self) -> dict:
        """Return a summary dict with total and per-stage timings."""
        return {
            "total_ms": round(self.total_ms, 3),
            "stages": self.to_list(),
        }

    def get(self, name: str) -> float:
        """Return the time_ms for a named stage, or 0.0 if not found."""
        for r in self._records:
            if r.name == name:
                return r.time_ms
        return 0.0


def measure_ms(fn, *args, **kwargs) -> tuple:
    """
    Call *fn(*args, **kwargs)* and return (result, elapsed_ms).

    Convenience helper for timing a single callable without a context manager.
    """
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return result, elapsed_ms
