#!/usr/bin/env python3
"""
01_build_dataset.py — Stage 1: deterministic, label-aware dataset builder.

Takes a clean/ folder and a malicious/ folder, runs the REAL extraction
pipeline (manifest_builder) + REAL deterministic engine (build_signal_graph)
on every supported document, and emits one self-contained labelled record per
file. No LLM is called here.

Each output record contains everything an LLM reasoning stage needs, so the
dataset can be replayed against any model without re-extracting:

  filename, source_path, label, sha256, file_size, doc_type
  extraction_ms, deterministic_ms
  signal_summary   -> SignalGraph minus raw_signals  (the compact, LLM-ready view)
  signal_graph     -> full SignalGraph incl. raw_signals (macro code, visible text, ...)
  error            -> set if extraction failed

Output: JSONL (default experiments/data/labelled_dataset.jsonl) + a .meta.json
sidecar describing the build.

Usage:
  python 01_build_dataset.py --clean ../dataset/clean --malicious ../dataset/malicious
  python 01_build_dataset.py --clean C/ --malicious M/ --out data/run1.jsonl --limit 20
  python 01_build_dataset.py ... --keep-workspaces      # keep extracted/ trees for inspection
  python 01_build_dataset.py ... --overwrite            # ignore/replace existing output
"""
from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import _common
_common.bootstrap_backend()

log = logging.getLogger("experiments.build")

# Backend imports (after bootstrap)
import config  # noqa: E402
from extractor.manifest_builder import build_manifest  # noqa: E402
from analysis import deterministic_engine  # noqa: E402
import storage.workspace as ws  # noqa: E402


def gather_files(folder: Path, label: str, allowed: set[str]) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    if not folder.exists() or not folder.is_dir():
        print(f"[warn] {label} folder missing or not a dir: {folder}")
        return out
    for f in sorted(folder.rglob("*")):
        if f.is_file() and f.suffix.lower() in allowed and not f.name.startswith("~$"):
            out.append((f, label))
    return out


def process_one(path: Path, label: str, keep_ws: bool) -> dict:
    t_ext0 = time.perf_counter()
    workspace_id, _ = ws.create_workspace()
    rec: dict = {
        "filename": path.name,
        "source_path": str(path.resolve()),
        "label": label,
    }
    try:
        archive_bytes = path.read_bytes()
        ws.save_uploaded_file(workspace_id, path.name, archive_bytes)
        manifest = build_manifest(workspace_id, path.name, archive_bytes)
        extraction_ms = round((time.perf_counter() - t_ext0) * 1000, 2)

        manifest_dict = manifest.model_dump()

        t_det0 = time.perf_counter()
        signal_graph = deterministic_engine.build_signal_graph(manifest_dict)
        deterministic_ms = round((time.perf_counter() - t_det0) * 1000, 2)

        fm = manifest_dict.get("file_metadata", {})
        rec.update({
            "sha256": fm.get("sha256", ""),
            "file_size": fm.get("size", len(archive_bytes)),
            "doc_type": fm.get("detected_doc_type", "Unknown"),
            "extraction_ms": extraction_ms,
            "deterministic_ms": deterministic_ms,
            "signal_summary": signal_graph.model_dump(exclude={"raw_signals"}),
            "signal_graph": signal_graph.model_dump(),
            "error": None,
        })
    except Exception as exc:  # noqa: BLE001
        # Full traceback to the log (file + console); concise message in the record.
        log.exception("Extraction failed for %s/%s (workspace=%s)", label, path.name, workspace_id)
        rec.update({
            "sha256": "",
            "file_size": path.stat().st_size if path.exists() else 0,
            "doc_type": "ERROR",
            "extraction_ms": round((time.perf_counter() - t_ext0) * 1000, 2),
            "deterministic_ms": 0.0,
            "signal_summary": None,
            "signal_graph": None,
            "error": f"{type(exc).__name__}: {exc}",
        })
    finally:
        if not keep_ws:
            try:
                ws.delete_workspace(workspace_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("Could not delete workspace %s: %s", workspace_id, exc)
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a labelled deterministic dataset (no LLM).")
    ap.add_argument("--clean", required=True, type=Path, help="Folder of clean documents")
    ap.add_argument("--malicious", required=True, type=Path, help="Folder of malicious documents")
    ap.add_argument("--out", type=Path, default=_common.DATA_DIR / "labelled_dataset.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="Process at most N files per label (0 = all)")
    ap.add_argument("--keep-workspaces", action="store_true", help="Do not delete extracted workspaces")
    ap.add_argument("--overwrite", action="store_true", help="Replace any existing output instead of resuming")
    ap.add_argument("--verbose", action="store_true", help="Show backend INFO logs too")
    args = ap.parse_args()

    out_path: Path = args.out
    _common.setup_logging(out_path.with_suffix(".build.log"), verbose=args.verbose)

    allowed = set(config.ALLOWED_EXTENSIONS)

    clean = gather_files(args.clean, "clean", allowed)
    mal = gather_files(args.malicious, "malicious", allowed)
    if args.limit:
        clean, mal = clean[: args.limit], mal[: args.limit]
    files = clean + mal
    print(f"[build] {len(clean)} clean + {len(mal)} malicious = {len(files)} files")

    done_keys: set[tuple[str, str]] = set()
    if out_path.exists() and not args.overwrite:
        existing = _common.read_jsonl(out_path)
        done_keys = {(r["label"], r["filename"]) for r in existing}
        print(f"[build] resuming — {len(done_keys)} records already present in {out_path.name}")
    elif args.overwrite and out_path.exists():
        out_path.unlink()

    t0 = time.perf_counter()
    processed = errors = 0
    for i, (path, label) in enumerate(files, 1):
        if (label, path.name) in done_keys:
            continue
        rec = process_one(path, label, args.keep_workspaces)
        _common.append_jsonl(out_path, rec)
        processed += 1
        if rec["error"]:
            errors += 1
            print(f"  [{i}/{len(files)}] ERROR {label}/{path.name}: {rec['error']}")
        else:
            print(f"  [{i}/{len(files)}] ok {label}/{path.name} "
                  f"(ext {rec['extraction_ms']}ms, det {rec['deterministic_ms']}ms)")

    total_s = time.perf_counter() - t0
    meta = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "clean_dir": str(args.clean.resolve()),
        "malicious_dir": str(args.malicious.resolve()),
        "total_in_scope": len(files),
        "processed_this_run": processed,
        "extraction_errors_this_run": errors,
        "wall_seconds_this_run": round(total_s, 2),
        "allowed_extensions": sorted(allowed),
        "output": str(out_path.resolve()),
        "note": "Records carry full signal_graph incl. raw_signals (macro code, visible text). "
                "No labels are embedded inside signal_graph, so it is leakage-safe to feed to an LLM.",
    }
    _common.write_json(out_path.with_suffix(".meta.json"), meta)
    print(f"[build] done — wrote/updated {out_path} ({processed} new, {errors} errors) in {total_s:.1f}s")
    print(f"[build] meta -> {out_path.with_suffix('.meta.json')}")


if __name__ == "__main__":
    main()


"""
python3 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_full   --graph-mode full
python3 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_nodes  --graph-mode nodes
python3 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_masked --graph-mode full --mask-doc-type
python3 02_run_reasoning.py --dataset data/labelled_dataset_r4.jsonl --run-id r4_off    --graph-mode off

for r in r4_full r4_nodes r4_masked r4_off; do python 03_evaluate.py --run-dir results/$r --split dev; done
"""