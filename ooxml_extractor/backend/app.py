"""
app.py — FastAPI application for the OOXML extractor (v2).

v2 changes:
  - POST /api/upload  → returns immediately with {workspace_id, status: "queued"}
  - Background asyncio worker runs extraction (bounded concurrency via semaphore)
  - GET /api/workspaces/{id}/status  → queued | running | done | error
  - GET /api/workspaces/{id}/entries → filterable by classification.kind
  - JSON structured logging via logging_setup
  - setup_logging() called at startup
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import mimetypes
import re
import time
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

import config
import uvicorn
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from extractor.manifest_builder import build_manifest
from extractor.binary_peeker import hex_preview
from extractor.xml_decoder import decode_part, is_xml_like
from extractor.logging_setup import setup_logging, get_logger
from storage.workspace import (
    create_workspace,
    get_workspace_path,
    get_extracted_file,
    load_manifest,
    save_manifest,
    save_uploaded_file,
    save_status,
    load_status,
    delete_workspace,
    list_images,
    load_analysis_component,
    save_analysis_components,
)

# ---------------------------------------------------------------------------
# Logging setup (call once at module load in production)
# ---------------------------------------------------------------------------
setup_logging()
logger = get_logger("app")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="OOXML Extractor",
    description="Research-grade, full-fidelity Microsoft Office OOXML extractor & analysis API v2",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Async job queue
# ---------------------------------------------------------------------------
_JOB_QUEUE: asyncio.Queue = asyncio.Queue()
_SEMAPHORE: asyncio.Semaphore = asyncio.Semaphore(4)   # max 4 parallel extractions

def _ext_ok(filename: str) -> bool:
    return Path(filename).suffix.lower() in config.ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def _extraction_worker() -> None:
    """Continuously drain _JOB_QUEUE, running one extraction at a time (bounded)."""
    while True:
        job = await _JOB_QUEUE.get()
        workspace_id, filename, archive_bytes, auto_analyze = job if len(job) == 4 else (*job, False)
        
        async with _SEMAPHORE:
            ws_logger = get_logger("app.worker", workspace_id=workspace_id)
            ws_logger.info("Extraction starting")
            save_status(workspace_id, {"status": "running", "started_at": time.time()})
            t0 = time.perf_counter()
            success = False
            try:
                loop = asyncio.get_event_loop()
                manifest = await loop.run_in_executor(
                    None, build_manifest, workspace_id, filename, archive_bytes
                )
                manifest_json = manifest.model_dump_json(indent=2)
                save_manifest(workspace_id, manifest_json)
                import json as _json
                save_analysis_components(workspace_id, _json.loads(manifest_json))
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                save_status(workspace_id, {
                    "status": "done",
                    "time_ms": elapsed_ms,
                    "entry_count": len(manifest.entries),
                    "macro_containers": manifest.summary.macro_containers,
                    "dde_hits": manifest.summary.dde_hits,
                    "xlm_hits": manifest.summary.xlm_hits,
                })
                ws_logger.info("Extraction done in %.1f ms", elapsed_ms)
                success = True
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                save_status(workspace_id, {
                    "status": "error",
                    "error": str(exc),
                    "time_ms": elapsed_ms,
                })
                ws_logger.error("Extraction failed: %s", exc)
                
        # Trigger analysis OUTSIDE the semaphore so we don't block other extractions
        if success and auto_analyze:
            from analysis.analysis_pipeline import run_pipeline
            asyncio.create_task(run_pipeline(workspace_id))
            
        _JOB_QUEUE.task_done()


@app.on_event("startup")
async def startup_event() -> None:
    """Launch the background extraction worker."""
    asyncio.create_task(_extraction_worker())
    logger.info("OOXML Extractor v2 started — worker running")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _load_manifest_dict(workspace_id: str) -> dict:
    try:
        raw = load_manifest(workspace_id)
        return json.loads(raw)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workspace '{workspace_id}' not found or extraction not yet complete")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Corrupt manifest: {exc}")


# ---------------------------------------------------------------------------
# POST /api/upload  — returns immediately (queued)
# ---------------------------------------------------------------------------
@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    auto_analyze: bool = Form(False)
):
    """
    Accept an Office document, create a workspace, queue extraction.

    Returns immediately with {workspace_id, status: "queued"}.
    Poll GET /api/workspaces/{id}/status to track progress.
    """
    filename = file.filename or "upload.bin"
    if not _ext_ok(filename):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported extension '{Path(filename).suffix}'. "
                   f"Supported: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    archive_bytes = await file.read()
    if not archive_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    workspace_id, _ = create_workspace()
    save_uploaded_file(workspace_id, filename, archive_bytes)
    save_status(workspace_id, {"status": "queued", "queued_at": time.time()})

    await _JOB_QUEUE.put((workspace_id, filename, archive_bytes, auto_analyze))
    logger.info("Queued workspace %s for file %s (%d bytes)", workspace_id, filename, len(archive_bytes))

    return {
        "workspace_id": workspace_id,
        "filename": filename,
        "file_size": len(archive_bytes),
        "status": "queued",
    }


# ---------------------------------------------------------------------------
# POST /api/upload-bulk  — returns list of queued items
# ---------------------------------------------------------------------------
@app.post("/api/upload-bulk")
async def upload_files_bulk(
    files: list[UploadFile] = File(...),
    auto_analyze: bool = Form(False)
):
    """
    Accept multiple Office documents, queue extractions.
    Returns list of {workspace_id, filename, status: "queued"}.
    """
    results = []
    for f in files:
        filename = f.filename or "upload.bin"
        if not _ext_ok(filename):
            continue
            
        archive_bytes = await f.read()
        if not archive_bytes:
            continue
            
        workspace_id, _ = create_workspace()
        save_uploaded_file(workspace_id, filename, archive_bytes)
        save_status(workspace_id, {"status": "queued", "queued_at": time.time()})
        await _JOB_QUEUE.put((workspace_id, filename, archive_bytes, auto_analyze))
        
        results.append({
            "workspace_id": workspace_id,
            "filename": filename,
            "status": "queued"
        })
        
    return {"uploaded": results}


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/status
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/status")
async def get_status(workspace_id: str):
    """
    Return current extraction status.

    Possible values: queued | running | done | error
    """
    try:
        get_workspace_path(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workspace '{workspace_id}' not found")
    return load_status(workspace_id)


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/manifest
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/manifest")
async def get_manifest(workspace_id: str):
    """Return the full extraction manifest as JSON."""
    data = _load_manifest_dict(workspace_id)
    return JSONResponse(content=data)


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/entries  (v2) — filterable by kind
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/entries")
async def get_entries(
    workspace_id: str,
    kind: Optional[str] = Query(None, description="Filter by classification.kind"),
    role: Optional[str] = Query(None, description="Filter by structural_role"),
    limit: int = Query(500, le=2000),
    offset: int = Query(0, ge=0),
):
    """
    Return manifest entries, optionally filtered by binary_kind or structural_role.

    Examples:
      ?kind=pe_executable
      ?kind=vba_macro_container
      ?role=macrosheet
    """
    manifest_dict = _load_manifest_dict(workspace_id)
    entries = manifest_dict.get("entries", [])

    if kind:
        entries = [e for e in entries if e.get("classification", {}).get("kind") == kind]

    if role:
        entries = [e for e in entries if e.get("structural_role") == role]

    total = len(entries)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": entries[offset: offset + limit],
    }


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/file
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/file")
async def get_file(workspace_id: str, path: str = Query(...)):
    """Stream raw bytes for an extracted file."""
    try:
        file_path = get_extracted_file(workspace_id, path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Workspace not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    media_type, _ = mimetypes.guess_type(path)
    media_type = media_type or "application/octet-stream"

    def _iter():
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

    return StreamingResponse(
        _iter(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{Path(path).name}"'},
    )


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/preview
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/preview")
async def get_preview(workspace_id: str, path: str = Query(...)):
    """
    Decoded text preview (XML parts) or hex dump + base64 (binary blobs).
    """
    try:
        file_path = get_extracted_file(workspace_id, path)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    raw = file_path.read_bytes()

    if is_xml_like(path, raw):
        result = decode_part(raw, force_xml_parse=True)
        text = result.decoded_text_utf8 or result.decoded_text_utf16le or "[decode failed]"
        return {
            "path": path,
            "type": "text",
            "content": text,
            "parse_error": result.parse_error,
            "xml_summary": result.xml_summary.__dict__ if result.xml_summary else None,
        }

    hex_dump = hex_preview(raw, max_bytes=1024)
    b64_preview = base64.b64encode(raw[:4096]).decode("ascii")
    return {
        "path": path,
        "type": "binary",
        "hex_dump": hex_dump,
        "base64_preview": b64_preview,
        "size": len(raw),
    }


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/search
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/search")
async def search(workspace_id: str, q: str = Query(..., min_length=1)):
    """Full-text search across decoded content, macros, URLs, and relationships."""
    manifest_dict = _load_manifest_dict(workspace_id)
    pattern = re.compile(re.escape(q), re.IGNORECASE)
    SNIPPET_WINDOW = 100
    results: list[dict] = []

    def _snippet(text: str, match) -> str:
        s = max(0, match.start() - SNIPPET_WINDOW)
        e = min(len(text), match.end() + SNIPPET_WINDOW)
        return text[s:e]

    for entry in manifest_dict.get("entries", []):
        decoded = entry.get("decoded")
        if not decoded:
            continue
        text = decoded.get("decoded_text_utf8", "")
        for m in pattern.finditer(text):
            results.append({
                "source": "entry",
                "path": entry["path"],
                "kind": entry.get("classification", {}).get("kind", ""),
                "snippet": _snippet(text, m),
                "offset": m.start(),
            })
            if len(results) >= 500:
                break
        if len(results) >= 500:
            break

    for container in manifest_dict.get("macros", {}).get("results", []):
        for module in container.get("modules", []):
            text = module.get("code", "")
            for m in pattern.finditer(text):
                results.append({
                    "source": "macro",
                    "path": container["archive_path"],
                    "module": module["module_name"],
                    "snippet": _snippet(text, m),
                    "offset": m.start(),
                })
                if len(results) >= 500:
                    break

    for url in manifest_dict.get("urls", []):
        if pattern.search(url):
            results.append({"source": "url", "path": "urls", "snippet": url, "offset": 0})

    for rels_file in manifest_dict.get("rels_files", []):
        for rel in rels_file.get("relationships", []):
            target = rel.get("target", "")
            if pattern.search(target):
                results.append({
                    "source": "relationship",
                    "path": rels_file["path"],
                    "snippet": target,
                    "offset": 0,
                })

    return {"query": q, "total": len(results), "results": results[:500]}


# ---------------------------------------------------------------------------
# GET /api/workspaces  — list all past extractions
# ---------------------------------------------------------------------------
@app.get("/api/workspaces")
async def list_all_workspaces():
    """
    Return a summary list of all past workspaces (for history panel).

    Each item includes workspace_id, status, and whatever metadata is
    available from status.json and manifest.json.
    """
    from storage.workspace import list_workspaces, load_status, get_workspace_path
    import json as _json

    items = []
    for ws_id in list_workspaces():
        status_data = load_status(ws_id)
        # Try to enrich from manifest if done
        filename = ""
        file_size = 0
        detected_doc_type = ""
        entry_count = status_data.get("entry_count", 0)
        try:
            ws_path = get_workspace_path(ws_id)
            manifest_path = ws_path / "manifest.json"
            if manifest_path.exists():
                # Only read the metadata section to keep it fast
                raw = manifest_path.read_text(encoding="utf-8")
                m = _json.loads(raw)
                fm = m.get("file_metadata", {})
                filename = fm.get("filename", "")
                file_size = fm.get("size", 0)
                detected_doc_type = fm.get("detected_doc_type", "")
                entry_count = m.get("summary", {}).get("entry_count", entry_count)
            else:
                # Try uploads/ dir for filename
                uploads = ws_path / "uploads"
                if uploads.exists():
                    files = list(uploads.iterdir())
                    if files:
                        filename = files[0].name
                        file_size = files[0].stat().st_size
        except Exception:  # noqa: BLE001
            pass

        items.append({
            "workspace_id": ws_id,
            "status": status_data.get("status", "unknown"),
            "filename": filename,
            "file_size": file_size,
            "detected_doc_type": detected_doc_type,
            "entry_count": entry_count,
            "time_ms": status_data.get("time_ms"),
            "error": status_data.get("error"),
        })

    # Sort: done workspaces first, then by workspace_id (UUID has time component)
    items.sort(key=lambda x: (x["status"] != "done", x["workspace_id"]), reverse=False)
    items.reverse()   # newest first

    return {"total": len(items), "workspaces": items}


# ---------------------------------------------------------------------------
# DELETE /api/workspaces/{id}  — remove a workspace permanently
# ---------------------------------------------------------------------------
@app.delete("/api/workspaces/{workspace_id}")
async def remove_workspace(workspace_id: str):
    """Permanently delete a workspace and all extracted files."""
    try:
        delete_workspace(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workspace '{workspace_id}' not found")
    logger.info("Deleted workspace %s", workspace_id)
    return {"deleted": workspace_id}


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/analysis/{component}  — per-component JSON
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/analysis/{component}")
async def get_analysis_component(workspace_id: str, component: str):
    """
    Serve a specific analysis component JSON.

    Valid components: summary | entries_index | macros | rels | urls | dde | xlm | embedded_objects
    """
    try:
        raw = load_analysis_component(workspace_id, component)
        import json as _json
        return JSONResponse(content=_json.loads(raw))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/images  — list extracted images
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/images")
async def get_images(workspace_id: str):
    """Return list of image files extracted into images/ subdirectory."""
    try:
        imgs = list_images(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workspace '{workspace_id}' not found")
    return {"workspace_id": workspace_id, "count": len(imgs), "images": imgs}


# ---------------------------------------------------------------------------
# GET /api/workspaces/{id}/images/{filename}  — serve an image file
# ---------------------------------------------------------------------------
@app.get("/api/workspaces/{workspace_id}/images/{filename}")
async def serve_image(workspace_id: str, filename: str):
    """Serve an image file from the images/ subdirectory."""
    import mimetypes as _mt
    try:
        ws = get_workspace_path(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Workspace not found")
    # Basic sanitisation — no path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    img_path = ws / "images" / filename
    if not img_path.exists():
        raise HTTPException(status_code=404, detail=f"Image '{filename}' not found")
    media_type, _ = _mt.guess_type(filename)
    media_type = media_type or "application/octet-stream"

    def _iter():
        with open(img_path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

    return StreamingResponse(_iter(), media_type=media_type)




# ---------------------------------------------------------------------------
# Agentic Analysis Pipeline
# ---------------------------------------------------------------------------
@app.post("/api/workspaces/{workspace_id}/analyze")
async def start_analysis(workspace_id: str, background_tasks: BackgroundTasks, force_rerun: bool = False):
    """
    Queue the agentic analysis pipeline for a completed extraction workspace.

    Pipeline: Planner → Executor → Correlation → Aggregator
    """
    from analysis.analysis_pipeline import run_pipeline, load_analysis_status
    from analysis.schema import AnalysisStatus

    # Check workspace exists
    try:
        get_workspace_path(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workspace '{workspace_id}' not found")

    # Check extraction is done
    status = load_status(workspace_id)
    if status.get("status") != "done":
        raise HTTPException(status_code=409, detail="Extraction must be complete before analysis can run")

    # Check already running / done (unless force_rerun)
    if not force_rerun:
        ana_status = load_analysis_status(workspace_id)
        if ana_status.get("analysis_status") in ("running", "done"):
            return {
                "workspace_id": workspace_id,
                "analysis_status": ana_status.get("analysis_status"),
                "message": "Analysis already complete. Pass force_rerun=true to re-run.",
            }

    async def _run():
        try:
            await run_pipeline(workspace_id)
        except Exception as exc:
            from analysis.schema import AnalysisStatus as AS
            from analysis.analysis_pipeline import _save_status
            logger.exception("[%s] Analysis pipeline error: %s", workspace_id, exc)
            _save_status(workspace_id, AS.error, {"error": str(exc)})

    background_tasks.add_task(_run)
    return {"workspace_id": workspace_id, "analysis_status": "queued", "message": "Analysis pipeline started"}


@app.get("/api/workspaces/{workspace_id}/analysis/status")
async def get_analysis_status(workspace_id: str):
    """Poll analysis pipeline status."""
    from analysis.analysis_pipeline import load_analysis_status
    try:
        get_workspace_path(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return load_analysis_status(workspace_id)


@app.get("/api/workspaces/{workspace_id}/verdict")
async def get_verdict(workspace_id: str):
    """Return the final analysis verdict."""
    from analysis.analysis_pipeline import load_verdict
    try:
        return load_verdict(workspace_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No verdict found. Run /analyze first.")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Health

# ---------------------------------------------------------------------------
@app.get("/api/url-whitelist")
async def get_url_whitelist():
    """Return the full URL whitelist (prefixes + exact hosts) used to filter structural namespace URLs."""
    from extractor.url_whitelist import WHITELIST_PREFIXES, WHITELIST_HOSTS, is_whitelisted
    return {
        "description": "Known-clean structural/namespace URLs filtered from extraction results",
        "prefix_count": len(WHITELIST_PREFIXES),
        "host_count": len(WHITELIST_HOSTS),
        "prefixes": list(WHITELIST_PREFIXES),
        "hosts": sorted(WHITELIST_HOSTS),
    }


@app.post("/api/url-whitelist/check")
async def check_url(url: str):
    """Check whether a specific URL would be whitelisted."""
    from extractor.url_whitelist import is_whitelisted
    matched = is_whitelisted(url)
    return {"url": url, "whitelisted": matched}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "ooxml-extractor",
        "version": "2.0.0",
        "queue_size": _JOB_QUEUE.qsize(),
    }


# ---------------------------------------------------------------------------
# Evaluation Loop
# ---------------------------------------------------------------------------
class EvalRequest(BaseModel):
    clean_path: str
    malicious_path: str
    report_name: Optional[str] = None

@app.get("/api/eval/ls")
async def eval_ls(path: Optional[str] = None):
    """List directories for the Evaluation folder picker."""
    import os
    from pathlib import Path
    
    # Default to user's home or workspace root if no path given
    if not path:
        path = str(Path.home())
        
    p = Path(path)
    if not p.exists() or not p.is_dir():
        raise HTTPException(status_code=404, detail="Directory not found")
        
    try:
        dirs = []
        for item in p.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                dirs.append({
                    "name": item.name,
                    "path": str(item.absolute())
                })
        # Sort alphabetically
        dirs.sort(key=lambda x: x["name"].lower())
        
        return {
            "current_path": str(p.absolute()),
            "parent_path": str(p.parent.absolute()) if p.parent != p else None,
            "directories": dirs
        }
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied to read this directory")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/eval/start")
async def start_eval(req: EvalRequest, background_tasks: BackgroundTasks):
    import uuid
    from services.evaluation_service import run_evaluation
    eval_id = str(uuid.uuid4())
    background_tasks.add_task(run_evaluation, eval_id, req.clean_path, req.malicious_path, req.report_name)
    return {"eval_id": eval_id}

@app.get("/api/eval/status/{eval_id}")
async def eval_status(eval_id: str):
    from services.evaluation_service import get_evaluation_status
    status = get_evaluation_status(eval_id)
    if not status:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    return status

@app.post("/api/eval/resume/{eval_id}")
async def resume_eval(eval_id: str, req: EvalRequest, background_tasks: BackgroundTasks):
    from services.evaluation_service import resume_evaluation
    background_tasks.add_task(resume_evaluation, eval_id, req.clean_path, req.malicious_path)
    return {"eval_id": eval_id, "status": "resumed"}

@app.get("/api/eval/reports")
async def list_eval_reports():
    from services.evaluation_service import list_reports
    return list_reports()

@app.get("/api/eval/reports/{report_id}")
async def get_eval_report(report_id: str):
    from services.evaluation_service import load_report
    report = load_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@app.delete("/api/eval/reports/{report_id}")
async def delete_eval_report(report_id: str):
    from services.evaluation_service import delete_report
    success = delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "deleted"}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
