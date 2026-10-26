#!/usr/bin/env python3
"""
vt_check.py — VirusTotal label verification for the evaluation corpus (R6-2).

Looks up every file in dataset/clean and dataset/malicious on VirusTotal by
SHA-256 and records the engine verdicts. Read-only by default: files are NOT
uploaded unless you pass --upload-unknown (an upload is shared with VirusTotal's
partners, so only use it for files from public sources).

Output: dataset/metadata/vt_results.csv (one row per file). The run is resumable:
files already in the CSV are skipped, so you can stop and restart at any time.

Usage (from the dataset/ folder):
  export VT_API_KEY="..."
  python vt_check.py                       # free tier: 4 requests/min (~80 min for 324 files)
  python vt_check.py --rpm 30              # premium key
  python vt_check.py --upload-unknown      # also submit files VirusTotal has never seen
  python vt_check.py --summary             # print the summary only, no API calls
  python vt_check.py --min-malicious 5     # threshold used in the summary (default 5)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "metadata" / "vt_results.csv"
API = "https://www.virustotal.com/api/v3"
OFFICE_EXT = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
              ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"}
FIELDS = ["sha256", "label", "filename", "status", "malicious", "suspicious", "undetected",
          "harmless", "engines_total", "threat_label", "type_tag", "first_submission",
          "last_analysis", "checked_at"]


class RateLimiter:
    def __init__(self, rpm: int):
        self.gap = 60.0 / rpm + 0.5
        self.last = 0.0

    def wait(self) -> None:
        d = self.last + self.gap - time.monotonic()
        if d > 0:
            time.sleep(d)
        self.last = time.monotonic()


def _key() -> str:
    k = os.environ.get("VT_API_KEY", "").strip()
    if not k:
        sys.exit('VT_API_KEY is not set. Run: export VT_API_KEY="<your key>"')
    return k


def _request(req: urllib.request.Request, rl: RateLimiter) -> tuple[int, dict]:
    """Send one request; on HTTP 429 (quota) wait and retry."""
    for attempt in range(5):
        rl.wait()
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print("  quota hit (429) — waiting 60 s")
                time.sleep(60)
                continue
            body = e.read()
            try:
                return e.code, json.loads(body or b"{}")
            except json.JSONDecodeError:
                return e.code, {}
        except urllib.error.URLError as e:
            print(f"  network error ({e}); retrying in 20 s")
            time.sleep(20)
    return 0, {}


def lookup(sha: str, rl: RateLimiter) -> tuple[int, dict]:
    req = urllib.request.Request(f"{API}/files/{sha}", headers={"x-apikey": _key()})
    return _request(req, rl)


def upload(path: Path, rl: RateLimiter) -> str | None:
    """Submit a file; return the analysis id."""
    boundary = uuid.uuid4().hex
    data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
        + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{API}/files", data=data, method="POST", headers={
        "x-apikey": _key(), "Content-Type": f"multipart/form-data; boundary={boundary}"})
    code, j = _request(req, rl)
    return (j.get("data") or {}).get("id") if code == 200 else None


def wait_analysis(aid: str, rl: RateLimiter, tries: int = 12) -> bool:
    req = urllib.request.Request(f"{API}/analyses/{aid}", headers={"x-apikey": _key()})
    for _ in range(tries):
        code, j = _request(req, rl)
        if code == 200 and ((j.get("data") or {}).get("attributes") or {}).get("status") == "completed":
            return True
        time.sleep(20)
    return False


def row_from(sha: str, label: str, name: str, code: int, j: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if code == 404:
        return {"sha256": sha, "label": label, "filename": name, "status": "not_found", "checked_at": now}
    if code != 200:
        return {"sha256": sha, "label": label, "filename": name, "status": f"error_{code}", "checked_at": now}
    a = (j.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    ts = lambda t: datetime.fromtimestamp(t, timezone.utc).date().isoformat() if t else ""  # noqa: E731
    return {
        "sha256": sha, "label": label, "filename": name, "status": "found",
        "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
        "undetected": st.get("undetected", 0), "harmless": st.get("harmless", 0),
        "engines_total": sum(v for k, v in st.items() if k in ("malicious", "suspicious", "undetected", "harmless")),
        "threat_label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
        "type_tag": a.get("type_tag", ""),
        "first_submission": ts(a.get("first_submission_date")),
        "last_analysis": ts(a.get("last_analysis_date")),
        "checked_at": now,
    }


def load() -> dict[tuple[str, str], dict]:
    if not OUT.exists():
        return {}
    with OUT.open(newline="") as f:
        return {(r["label"], r["filename"]): r for r in csv.DictReader(f)}


def save(rows: dict) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    with tmp.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows.values(), key=lambda r: (r["label"], r["filename"])):
            w.writerow({k: r.get(k, "") for k in FIELDS})
    tmp.replace(OUT)


def corpus() -> list[tuple[str, Path]]:
    out = []
    for label in ("clean", "malicious"):
        for p in sorted((HERE / label).iterdir()):
            if p.is_file() and not p.name.startswith((".", "~$")) and p.suffix.lower() in OFFICE_EXT:
                out.append((label, p))
    return out


def summary(rows: dict, min_mal: int) -> None:
    files = corpus()
    present = {(l, p.name) for l, p in files}
    R = [r for k, r in rows.items() if k in present]
    print(f"\n=== VirusTotal summary ({len(R)}/{len(files)} files checked) ===")
    for label in ("clean", "malicious"):
        L = [r for r in R if r["label"] == label]
        found = [r for r in L if r["status"] == "found"]
        nf = [r for r in L if r["status"] == "not_found"]
        err = [r for r in L if r["status"].startswith("error")]
        print(f"\n{label}: {len(L)} checked | found {len(found)} | not on VT {len(nf)} | errors {len(err)}")
        if label == "clean":
            bad = [r for r in found if int(r["malicious"] or 0) > 0]
            print(f"  clean files with >=1 malicious detection: {len(bad)}")
            for r in sorted(bad, key=lambda r: -int(r["malicious"])):
                print(f"    {r['malicious']:>3}/{r['engines_total']}  {r['filename']}  {r['threat_label']}")
        else:
            det = sorted(int(r["malicious"] or 0) for r in found)
            weak = [r for r in found if int(r["malicious"] or 0) < min_mal]
            if det:
                print(f"  detections: min {det[0]}, median {det[len(det) // 2]}, max {det[-1]}")
            print(f"  malicious files below the {min_mal}-engine threshold: {len(weak)}")
            for r in sorted(weak, key=lambda r: int(r["malicious"] or 0)):
                print(f"    {r['malicious']:>3}/{r['engines_total']}  {r['filename']}")
        for r in nf:
            print(f"    not on VT: {r['filename']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpm", type=int, default=4, help="requests per minute (free tier = 4)")
    ap.add_argument("--upload-unknown", action="store_true", help="submit files VirusTotal has not seen")
    ap.add_argument("--recheck", action="store_true", help="re-query files already in the CSV")
    ap.add_argument("--min-malicious", type=int, default=5, help="detection threshold for the summary")
    ap.add_argument("--summary", action="store_true", help="print the summary from the CSV only")
    ap.add_argument("--label", choices=["clean", "malicious"], help="only check files with this label")
    a = ap.parse_args()

    rows = load()
    if a.summary:
        summary(rows, a.min_malicious)
        return

    rl = RateLimiter(a.rpm)
    files = corpus()
    todo = [(l, p) for l, p in files if a.recheck or (l, p.name) not in rows
            or rows[(l, p.name)]["status"].startswith("error")
            or (a.upload_unknown and rows[(l, p.name)]["status"] == "not_found")]
    if a.label:
        todo = [(l, p) for l, p in todo if l == a.label]
    eta = len(todo) * 60 / a.rpm / 60
    print(f"{len(files)} files in corpus, {len(todo)} to check (~{eta:.0f} min at {a.rpm}/min)")

    for i, (label, p) in enumerate(todo, 1):
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        code, j = lookup(sha, rl)
        if code == 404 and a.upload_unknown:
            print(f"  [{i}/{len(todo)}] {p.name}: not on VT, uploading")
            aid = upload(p, rl)
            if aid and wait_analysis(aid, rl):
                code, j = lookup(sha, rl)
        r = row_from(sha, label, p.name, code, j)
        rows[(label, p.name)] = r
        save(rows)
        det = f"{r.get('malicious', '?')}/{r.get('engines_total', '?')}" if r["status"] == "found" else r["status"]
        print(f"  [{i}/{len(todo)}] {label:9s} {det:>9s}  {p.name[:60]}")

    summary(rows, a.min_malicious)
    print(f"\nResults: {OUT}")


if __name__ == "__main__":
    main()
