"""
workspace.py — workspace folder management for OOXML extraction sessions (v3).

Layout per workspace:
  {workspace_id}/
    uploads/         original uploaded file(s)
    extracted/       raw ZIP entry tree (lossless)
    images/          extracted image files (copies for fast serving)
    analysis/
      summary.json
      entries_index.json
      macros.json
      rels.json
      urls.json
      dde.json
      xlm.json
      embedded_objects.json
    manifest.json    full combined manifest
    status.json      job status
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from extractor.utils import safe_extract_path

DEFAULT_WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "./ooxml_workspaces"))

_IMAGE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".webp", ".svg", ".emf", ".wmf",
})


def get_workspace_root() -> Path:
    root = Path(os.environ.get("WORKSPACE_ROOT", str(DEFAULT_WORKSPACE_ROOT)))
    root.mkdir(parents=True, exist_ok=True)
    return root


def create_workspace() -> tuple[str, Path]:
    """Create a new workspace directory. Returns (workspace_id, workspace_path)."""
    workspace_id = str(uuid.uuid4())
    workspace_path = get_workspace_root() / workspace_id
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "extracted").mkdir(exist_ok=True)
    (workspace_path / "uploads").mkdir(exist_ok=True)
    (workspace_path / "images").mkdir(exist_ok=True)
    (workspace_path / "analysis").mkdir(exist_ok=True)
    return workspace_id, workspace_path


def get_workspace_path(workspace_id: str) -> Path:
    path = get_workspace_root() / workspace_id
    if not path.exists():
        raise FileNotFoundError(f"Workspace not found: {workspace_id}")
    return path


def delete_workspace(workspace_id: str) -> None:
    """Permanently delete a workspace directory and all its contents."""
    ws = get_workspace_path(workspace_id)
    shutil.rmtree(ws)


def save_uploaded_file(workspace_id: str, filename: str, data: bytes) -> Path:
    ws = get_workspace_path(workspace_id)
    upload_path = ws / "uploads" / filename
    upload_path.write_bytes(data)
    return upload_path


def save_entry(workspace_id: str, entry_path: str, raw_bytes: bytes) -> Path:
    """Write a ZIP entry's raw bytes to the extracted/ tree (ZipSlip-safe).
    Also copies image files into images/ for quick serving.
    """
    ws = get_workspace_path(workspace_id)
    extracted_root = ws / "extracted"
    dest = safe_extract_path(extracted_root, entry_path)
    
    if entry_path.endswith("/") or entry_path.endswith("\\"):
        dest.mkdir(parents=True, exist_ok=True)
        return dest
        
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw_bytes)

    # Mirror images into images/ flat folder for quick serving
    if dest.suffix.lower() in _IMAGE_EXTENSIONS and raw_bytes:
        images_dir = ws / "images"
        images_dir.mkdir(exist_ok=True)
        # Preserve dirname in name to avoid clashes: word_media_image1.png
        safe_name = entry_path.replace("/", "_").replace("\\", "_").lstrip("_")
        img_dest = images_dir / safe_name
        try:
            img_dest.write_bytes(raw_bytes)
        except OSError:
            pass  # non-critical

    return dest


def get_extracted_file(workspace_id: str, entry_path: str) -> Path:
    ws = get_workspace_path(workspace_id)
    extracted_root = ws / "extracted"
    return safe_extract_path(extracted_root, entry_path)


def save_manifest(workspace_id: str, manifest_json: str) -> Path:
    ws = get_workspace_path(workspace_id)
    manifest_path = ws / "manifest.json"
    manifest_path.write_text(manifest_json, encoding="utf-8")
    return manifest_path


def load_manifest(workspace_id: str) -> str:
    ws = get_workspace_path(workspace_id)
    manifest_path = ws / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found in workspace {workspace_id}")
    return manifest_path.read_text(encoding="utf-8")


def save_analysis_components(workspace_id: str, manifest_dict: dict) -> None:
    """
    Write per-component JSON files into analysis/ subdirectory.

    Each file contains only its relevant section from the manifest,
    making it easy to inspect individual results without loading the full manifest.
    """
    ws = get_workspace_path(workspace_id)
    analysis_dir = ws / "analysis"
    analysis_dir.mkdir(exist_ok=True)

    def _write(name: str, data) -> None:
        (analysis_dir / name).write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # summary.json — timing, counts, metadata
    _write("summary.json", {
        "workspace_id": manifest_dict.get("workspace_id"),
        "status": manifest_dict.get("status"),
        "file_metadata": manifest_dict.get("file_metadata", {}),
        "summary": manifest_dict.get("summary", {}),
        "timings": manifest_dict.get("timings", []),
    })

    # entries_index.json — per-entry metadata (no raw bytes / decoded text)
    entries_index = []
    for e in manifest_dict.get("entries", []):
        entries_index.append({
            "path": e.get("path"),
            "file_size": e.get("file_size"),
            "sha256": e.get("sha256"),
            "content_type": e.get("content_type"),
            "structural_role": e.get("structural_role"),
            "classify_time_ms": e.get("classify_time_ms"),
            "classification": e.get("classification"),
            "error": e.get("error"),
        })
    _write("entries_index.json", entries_index)

    # Individual analysis sections
    _write("macros.json",           manifest_dict.get("macros", {}))
    _write("rels.json",             manifest_dict.get("rels_files", []))
    _write("urls.json",             {
        "external": manifest_dict.get("urls", []),
        "whitelisted": manifest_dict.get("whitelisted_urls", []),
    })
    _write("dde.json",              manifest_dict.get("dde_findings", []))
    _write("xlm.json",              manifest_dict.get("xlm_findings", {}))
    _write("embedded_objects.json", manifest_dict.get("embedded_objects", []))


def list_images(workspace_id: str) -> list[dict]:
    """Return list of image files in images/ with metadata."""
    ws = get_workspace_path(workspace_id)
    images_dir = ws / "images"
    if not images_dir.exists():
        return []
    result = []
    for f in sorted(images_dir.iterdir()):
        if f.is_file():
            result.append({
                "name": f.name,
                "size": f.stat().st_size,
                "ext": f.suffix.lower().lstrip("."),
            })
    return result


def load_analysis_component(workspace_id: str, component: str) -> str:
    """Load a specific analysis component JSON file."""
    allowed = {
        "summary", "entries_index", "macros", "rels", "urls",
        "dde", "xlm", "embedded_objects",
        "signal_graph", "agent_intent", "agent_macro_behavior", "agent_aggregator",
    }
    if component not in allowed:
        raise ValueError(f"Unknown component '{component}'. Valid: {sorted(allowed)}")
    ws = get_workspace_path(workspace_id)
    path = ws / "analysis" / f"{component}.json"
    if not path.exists():
        raise FileNotFoundError(f"analysis/{component}.json not found")
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Status management
# ---------------------------------------------------------------------------

def save_status(workspace_id: str, status_dict: dict) -> None:
    """Persist status.json to workspace root."""
    ws_root = get_workspace_root() / workspace_id
    ws_root.mkdir(parents=True, exist_ok=True)
    (ws_root / "status.json").write_text(
        json.dumps(status_dict, ensure_ascii=False), encoding="utf-8"
    )


def load_status(workspace_id: str) -> dict:
    """Load status.json. Returns {status: queued} if file not found."""
    try:
        ws = get_workspace_path(workspace_id)
    except FileNotFoundError:
        return {"status": "queued"}
    status_path = ws / "status.json"
    if not status_path.exists():
        return {"status": "queued"}
    try:
        return json.loads(status_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"status": "error", "error": "corrupt status.json"}


def list_workspaces() -> list[str]:
    root = get_workspace_root()
    return [d.name for d in root.iterdir() if d.is_dir()]
