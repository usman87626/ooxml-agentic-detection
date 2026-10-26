import asyncio
import json
import logging
import os
import time
import uuid
import shutil
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

import config
from extractor.manifest_builder import build_manifest
from storage.workspace import create_workspace, save_uploaded_file, save_manifest, save_status
from analysis.analysis_pipeline import run_pipeline
from analysis.instructions.loader import load_instruction

logger = logging.getLogger("evaluation_service")

class JudgeResponse(BaseModel):
    score: int
    feedback: str

# In-memory store for evaluation progress
_EVALUATIONS = {}

REPORTS_DIR = Path(__file__).parent.parent / "evaluations"

def _ensure_reports_dir():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def _sanitize_metrics(data: dict) -> dict:
    """Recursively replace non-JSON-compliant floats (inf, -inf, nan) with 0."""
    if isinstance(data, dict):
        return {k: _sanitize_metrics(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_sanitize_metrics(v) for v in data]
    elif isinstance(data, float):
        if data == float('inf') or data == float('-inf') or data != data: # nan
            return 0
    return data

def get_evaluation_status(eval_id: str) -> dict | None:
    # First check memory
    if eval_id in _EVALUATIONS:
        return _sanitize_metrics(_EVALUATIONS[eval_id])
    
    # Check disk
    _ensure_reports_dir()
    p = REPORTS_DIR / f"{eval_id}.json"
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        return _sanitize_metrics(data)
    
    return None

def list_reports() -> list[dict]:
    _ensure_reports_dir()
    reports = []
    for f in REPORTS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            reports.append({
                "eval_id": f.stem,
                "report_name": data.get("report_name", "Unnamed Report"),
                "clean_path": data.get("clean_path", ""),
                "malicious_path": data.get("malicious_path", ""),
                "created_at": data.get("created_at", datetime.fromtimestamp(f.stat().st_mtime).isoformat()),
                "total_files": data.get("progress", {}).get("total", 0),
                "current_files": data.get("progress", {}).get("current", 0),
                "status": data.get("status") or ("done" if data.get("progress", {}).get("current", 0) >= data.get("progress", {}).get("total", 1) else "interrupted"),
                "accuracy": _calc_accuracy(data.get("metrics", {}).get("confusion_matrix", {}))
            })
        except Exception as e:
            logger.error(f"Error reading report {f.name}: {e}")
            
    reports.sort(key=lambda x: x["created_at"], reverse=True)
    return reports

def _calc_accuracy(matrix: dict) -> str:
    if not matrix: return "0%"
    tp = matrix.get("TP", 0)
    tn = matrix.get("TN", 0)
    fp = matrix.get("FP", 0)
    fn = matrix.get("FN", 0)
    total = tp + tn + fp + fn
    if total == 0: return "0%"
    return f"{((tp + tn) / total * 100):.1f}%"

def load_report(report_id: str) -> dict | None:
    _ensure_reports_dir()
    p = REPORTS_DIR / f"{report_id}.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return None

def delete_report(report_id: str) -> bool:
    _ensure_reports_dir()
    p = REPORTS_DIR / f"{report_id}.json"
    if p.exists():
        # Clean up associated workspaces to save disk space
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            from storage.workspace import delete_workspace
            for r in data.get("results", []):
                ws_id = r.get("workspace_id")
                if ws_id:
                    try:
                        delete_workspace(ws_id)
                    except Exception as e:
                        logger.error("Failed to delete workspace %s: %s", ws_id, e)
        except Exception as e:
            logger.error("Failed to read report %s for workspace cleanup: %s", report_id, e)

        p.unlink()
        if report_id in _EVALUATIONS:
            del _EVALUATIONS[report_id]
        return True
    return False

async def _analyze_file(file_path: Path, true_label: str) -> dict:
    t_start = time.perf_counter()
    workspace_id, ws_path = create_workspace()
    
    archive_bytes = file_path.read_bytes()
    filename = file_path.name
    save_uploaded_file(workspace_id, filename, archive_bytes)
    
    # Run extractor
    manifest_obj = await asyncio.to_thread(build_manifest, workspace_id, filename, archive_bytes)
    if hasattr(manifest_obj, 'model_dump'):
        manifest_dict = manifest_obj.model_dump()
    else:
        manifest_dict = manifest_obj # fallback just in case
    save_manifest(workspace_id, json.dumps(manifest_dict))
    
    # Run analyzer
    save_status(workspace_id, {"status": "running"})
    try:
        verdict = await run_pipeline(workspace_id)
        save_status(workspace_id, {"status": "done"})
        pred_verdict = verdict.verdict
        reasoning = verdict.reasoning
        risk_score = verdict.risk_score
        mitre_techniques = [f"{m.id}: {m.name}" for m in verdict.mitre_techniques]
        from storage.workspace import load_analysis_component
        features = []
        try:
            sg_raw = load_analysis_component(workspace_id, "signal_graph")
            sg = json.loads(sg_raw)
            if sg.get("has_macros"): features.append("Macros")
            if sg.get("embedded_objects", 0) > 0: features.append("Embedded Objects")
            if sg.get("dde_detected"): features.append("DDE")
            if sg.get("xlm_detected"): features.append("XLM")
            if sg.get("obfuscation_detected"): features.append("Obfuscation")
            if sg.get("template_injection_detected"): features.append("Template Injection")
            if sg.get("prompt_injection_detected"): features.append("Prompt Injection")
            if sg.get("has_html_svg_payloads"): features.append("HTML/SVG")
            if sg.get("intent_candidates") and len(sg.get("intent_candidates")) > 0: features.append("Suspicious Intent")
        except Exception as e:
            logger.warning("Failed to load signal graph for feature counting: %s", e)
    except Exception as e:
        save_status(workspace_id, {"status": "error", "error": str(e)})
        logger.error(f"Pipeline failed for {filename}: {e}")
        pred_verdict = "ERROR"
        reasoning = [str(e)]
        risk_score = 0
        mitre_techniques = []
        features = []
    
    duration = time.perf_counter() - t_start
    
    # If it was a fallback DUE TO ERROR, we count it as an ERROR
    final_verdict = pred_verdict
    
    # Extract fallback info from metadata if available
    is_fallback = False
    if 'verdict' in locals() and hasattr(verdict, 'analysis_metadata'):
        analysis_metadata = verdict.analysis_metadata
        is_fallback = analysis_metadata.get("fallback", False)
        if is_fallback and analysis_metadata.get("error"):
            final_verdict = "ERROR"

    return {
        "filename": filename,
        "true_label": true_label,
        "predicted_verdict": final_verdict,
        "duration": duration,
        "risk_score": risk_score,
        "mitre_techniques": mitre_techniques,
        "features": features,
        "workspace_id": workspace_id,
        "is_fallback": is_fallback
    }

async def run_evaluation(eval_id: str, clean_dir: str, malicious_dir: str, report_name: str | None = None):
    # Set default name if empty
    actual_name = report_name if report_name and report_name.strip() else f"Eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    _EVALUATIONS[eval_id] = {
        "report_name": actual_name,
        "clean_path": clean_dir,
        "malicious_path": malicious_dir,
        "created_at": datetime.now().isoformat(),
        "status": "running",
        "progress": {"current": 0, "total": 0},
        "metrics": {
             "min_time": float("inf"),
             "max_time": 0,
             "avg_time": 0,
             "all_times": [],
             "confusion_matrix": {
                  "TP": 0, "TN": 0, "FP": 0, "FN": 0
             },
             "require_network_clean": 0,
             "require_network_malicious": 0,
             "roc_points": [],
             "mitre_counts_clean": {},
             "mitre_counts_malicious": {},
             "feature_counts_clean": {},
             "feature_counts_malicious": {},
             "error_count": 0,
             "total_samples": 0,
             "total_clean": 0,
             "total_malicious": 0
        },
        "results": []
    }
    
    
    files_to_process = []
    
    clean_path = Path(clean_dir)
    mal_path = Path(malicious_dir)
    
    if clean_path.exists() and clean_path.is_dir():
        for f in clean_path.rglob("*"):
            if f.is_file() and f.suffix.lower() in config.ALLOWED_EXTENSIONS:
                files_to_process.append((f, "clean"))
                
    if mal_path.exists() and mal_path.is_dir():
        for f in mal_path.rglob("*"):
            if f.is_file() and f.suffix.lower() in config.ALLOWED_EXTENSIONS:
                files_to_process.append((f, "malicious"))
                
    _EVALUATIONS[eval_id]["progress"]["total"] = len(files_to_process)
    
    # Save initial state to disk so it's visible in list
    _ensure_reports_dir()
    dump_path = REPORTS_DIR / f"{eval_id}.json"
    dump_path.write_text(json.dumps(_sanitize_metrics(_EVALUATIONS[eval_id]), indent=2), encoding="utf-8")

    if not files_to_process:
        _EVALUATIONS[eval_id]["status"] = "done"
        dump_path.write_text(json.dumps(_EVALUATIONS[eval_id], indent=2), encoding="utf-8")
        return
        
    total_time = 0
    total_judge_score = 0
    valid_judge_count = 0
    
    for idx, (fpath, label) in enumerate(files_to_process):
        try:
            res = await _analyze_file(fpath, label)
            
            # Update metrics
            metrics = _EVALUATIONS[eval_id]["metrics"]
            metrics["total_samples"] += 1
            if label == "clean": metrics["total_clean"] += 1
            else: metrics["total_malicious"] += 1

            t = res["duration"]
            metrics["min_time"] = min(metrics["min_time"] if metrics["min_time"] != float("inf") else t, t)
            metrics["max_time"] = max(metrics["max_time"], t)
            metrics["all_times"].append(t)
            # Re-calc average
            metrics["avg_time"] = sum(metrics["all_times"]) / len(metrics["all_times"])
            
            # ROC points extraction
            # 1 for malicious, 0 for clean
            true_binary = 1 if label.lower() == "malicious" else 0
            
            metrics["roc_points"].append({
                "true_label": true_binary,
                "risk_score": res["risk_score"]
            })
            
            # Frequent MITRE tracking
            m_key = f"mitre_counts_{label.lower()}"
            for mitre in res.get("mitre_techniques", []):
                metrics[m_key][mitre] = metrics[m_key].get(mitre, 0) + 1
                
            # Frequent Features tracking
            f_key = f"feature_counts_{label.lower()}"
            for feat in res.get("features", []):
                metrics[f_key][feat] = metrics[f_key].get(feat, 0) + 1
                
            pred = res["predicted_verdict"]
            
            if pred == "REQUIRE_NETWORK_ANALYSIS":
                if label == "clean":
                    metrics["require_network_clean"] += 1
                    metrics["confusion_matrix"]["TN"] += 1
                    res["predicted_verdict"] = "CLEAN" 
                else:
                    metrics["require_network_malicious"] += 1
                    metrics["confusion_matrix"]["TP"] += 1
                    res["predicted_verdict"] = "MALICIOUS"
            elif pred != "ERROR":
                if label == "malicious":
                    if pred in ["MALICIOUS", "SUSPICIOUS"]:
                        metrics["confusion_matrix"]["TP"] += 1
                    elif pred == "CLEAN":
                        metrics["confusion_matrix"]["FN"] += 1
                else: # clean
                    if pred == "CLEAN":
                        metrics["confusion_matrix"]["TN"] += 1
                    else:
                        metrics["confusion_matrix"]["FP"] += 1
            else:
                metrics["error_count"] += 1
                        
            _EVALUATIONS[eval_id]["results"].append(res)
            
        except Exception as e:
            logger.error("Failed to evaluate %s: %s", fpath, e)
            metrics["error_count"] += 1
            _EVALUATIONS[eval_id]["results"].append({
                "filename": fpath.name,
                "true_label": label,
                "error": str(e),
                "predicted_verdict": "ERROR"
            })
            
            
        _EVALUATIONS[eval_id]["progress"]["current"] = idx + 1
        
        # Save progress after EVERY file for maximum robustness
        dump_path.write_text(json.dumps(_sanitize_metrics(_EVALUATIONS[eval_id]), indent=2), encoding="utf-8")
        
    # fix infinite min_time
    if _EVALUATIONS[eval_id]["metrics"]["min_time"] == float("inf"):
         _EVALUATIONS[eval_id]["metrics"]["min_time"] = 0
         
    # Calculate outlier-free average
    all_times = _EVALUATIONS[eval_id]["metrics"].get("all_times", [])
    if all_times:
        all_times.sort()
        # Remove top 10% outliers if there are more than 10 files
        if len(all_times) > 10:
            cutoff = int(len(all_times) * 0.9)
            filtered_times = all_times[:cutoff]
            _EVALUATIONS[eval_id]["metrics"]["avg_time"] = sum(filtered_times) / len(filtered_times)
        else:
            _EVALUATIONS[eval_id]["metrics"]["avg_time"] = sum(all_times) / len(all_times)
         
    _EVALUATIONS[eval_id]["status"] = "done"

    # Save final report to disk
    _ensure_reports_dir()
    dump_path = REPORTS_DIR / f"{eval_id}.json"
    dump_path.write_text(json.dumps(_sanitize_metrics(_EVALUATIONS[eval_id]), indent=2), encoding="utf-8")

async def resume_evaluation(eval_id: str, clean_dir: str, malicious_dir: str):
    """Resume an evaluation that stopped mid-way."""
    report = load_report(eval_id)
    if not report:
        raise ValueError("Report not found")
        
    finished_files = {r["filename"] for r in report.get("results", [])}
    
    # Reload files to process
    all_files = []
    clean_path = Path(clean_dir)
    mal_path = Path(malicious_dir)
    
    if clean_path.exists() and clean_path.is_dir():
        for f in clean_path.rglob("*"):
            if f.is_file() and f.suffix.lower() in config.ALLOWED_EXTENSIONS:
                all_files.append((f, "clean"))
                
    if mal_path.exists() and mal_path.is_dir():
        for f in mal_path.rglob("*"):
            if f.is_file() and f.suffix.lower() in config.ALLOWED_EXTENSIONS:
                all_files.append((f, "malicious"))
                
    remaining_files = [(f, l) for f, l in all_files if f.name not in finished_files]
    
    # Sync progress total in case files changed
    report["progress"]["total"] = len(all_files)
    report["status"] = "running"
    
    # Migration for older reports
    if "total_samples" not in report["metrics"]:
        report["metrics"]["total_samples"] = len(report.get("results", []))
        report["metrics"]["total_clean"] = sum(1 for r in report.get("results", []) if r.get("true_label") == "clean")
        report["metrics"]["total_malicious"] = sum(1 for r in report.get("results", []) if r.get("true_label") == "malicious")
        report["metrics"]["error_count"] = report["metrics"].get("error_count", sum(1 for r in report.get("results", []) if r.get("predicted_verdict") == "ERROR"))

    _EVALUATIONS[eval_id] = report
    
    # Start the loop with remaining files
    _ensure_reports_dir()
    dump_path = REPORTS_DIR / f"{eval_id}.json"
    
    for idx, (fpath, label) in enumerate(remaining_files):
        try:
            res = await _analyze_file(fpath, label)
            
            # Update metrics
            metrics = _EVALUATIONS[eval_id]["metrics"]
            metrics["total_samples"] += 1
            if label == "clean": metrics["total_clean"] += 1
            else: metrics["total_malicious"] += 1

            t = res["duration"]
            metrics["min_time"] = min(metrics["min_time"] if metrics["min_time"] != float("inf") else t, t)
            metrics["max_time"] = max(metrics["max_time"], t)
            metrics["all_times"].append(t)
            metrics["avg_time"] = sum(metrics["all_times"]) / len(metrics["all_times"])
            
            true_binary = 1 if label.lower() == "malicious" else 0
            metrics["roc_points"].append({"true_label": true_binary, "risk_score": res["risk_score"]})
            
            m_key = f"mitre_counts_{label.lower()}"
            for mitre in res.get("mitre_techniques", []):
                metrics[m_key][mitre] = metrics[m_key].get(mitre, 0) + 1
                
            f_key = f"feature_counts_{label.lower()}"
            for feat in res.get("features", []):
                metrics[f_key][feat] = metrics[f_key].get(feat, 0) + 1
                
            pred = res["predicted_verdict"]
            if pred == "REQUIRE_NETWORK_ANALYSIS":
                if label == "clean":
                    metrics["require_network_clean"] += 1
                    metrics["confusion_matrix"]["TN"] += 1
                    res["predicted_verdict"] = "CLEAN"
                else:
                    metrics["require_network_malicious"] += 1
                    metrics["confusion_matrix"]["TP"] += 1
                    res["predicted_verdict"] = "MALICIOUS"
            elif pred != "ERROR":
                if label == "malicious":
                    if pred in ["MALICIOUS", "SUSPICIOUS"]: metrics["confusion_matrix"]["TP"] += 1
                    elif pred == "CLEAN": metrics["confusion_matrix"]["FN"] += 1
                else:
                    if pred == "CLEAN": metrics["confusion_matrix"]["TN"] += 1
                    else: metrics["confusion_matrix"]["FP"] += 1
            else:
                metrics["error_count"] += 1
                        
            _EVALUATIONS[eval_id]["results"].append(res)
            
        except Exception as e:
            logger.error("Failed to evaluate %s: %s", fpath, e)
            metrics["error_count"] += 1
            _EVALUATIONS[eval_id]["results"].append({
                "filename": fpath.name,
                "true_label": label,
                "error": str(e),
                "predicted_verdict": "ERROR"
            })
            
        _EVALUATIONS[eval_id]["progress"]["current"] = len(_EVALUATIONS[eval_id]["results"])
        # Save progress after EVERY file
        dump_path.write_text(json.dumps(_sanitize_metrics(_EVALUATIONS[eval_id]), indent=2), encoding="utf-8")
            
    _EVALUATIONS[eval_id]["status"] = "done"
    dump_path.write_text(json.dumps(_sanitize_metrics(_EVALUATIONS[eval_id]), indent=2), encoding="utf-8")
