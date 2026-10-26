#!/usr/bin/env python3
"""
env_report.py — record the hardware/software environment for the paper (R6-7).
Run with the backend venv active:  python env_report.py
Writes results/environment.json and prints it.
"""
import json, os, platform, subprocess, sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def ver(pkg):
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return None


env = {
    "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "os": f"macOS {platform.mac_ver()[0]}" if platform.system() == "Darwin" else platform.platform(),
    "machine": platform.machine(),
    "cpu": sh(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor(),
    "cores_physical": sh(["sysctl", "-n", "hw.physicalcpu"]) or None,
    "cores_logical": os.cpu_count(),
    "ram_gb": round(int(sh(["sysctl", "-n", "hw.memsize"]) or 0) / 2**30, 1) or None,
    "model_name": sh(["sysctl", "-n", "hw.model"]) or None,
    "python": sys.version.split()[0],
    "libraries": {p: ver(p) for p in ["openai", "pydantic", "oletools", "olefile", "magika",
                                       "msoffcrypto-tool", "fastapi", "uvicorn", "pyyaml", "lxml"]},
    "llm_snapshots_note": "exact served model snapshots are recorded per run in results/<run>/run_meta.json -> served_models",
}
out = Path(__file__).resolve().parent / "results" / "environment.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(env, indent=2))
print(json.dumps(env, indent=2))
print(f"\n-> {out}")
