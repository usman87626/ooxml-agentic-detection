#!/usr/bin/env python3
"""
mb_downloader.py — MalwareBazaar collector for the OOXML evaluation corpus.

Replaces the old tag-based downloader.py. Changes (revision round 2, R6-1/R6-3/R6-5):
  * Queries by MalwareBazaar's detected file type (get_file_type), not by user tags.
  * API key read from the MB_API_KEY environment variable (never hard-coded).
  * Skips hashes already in the corpus; verifies SHA-256 after extraction;
    keeps only OOXML (ZIP) containers, so .gz / OLE .doc samples are rejected.
  * Optional --max-per-family cap to limit campaign/family duplication.
  * Writes per-sample metadata (family, tags, first_seen, TLSH, ssdeep, ...)
    to dataset/metadata/malicious_metadata.csv for the dataset manifest.

Usage (from the dataset/ folder, with the backend venv active):
  pip install pyzipper
  export MB_API_KEY="..."
  python mb_downloader.py fetch --type pptx --count 50 --max-per-family 5
  python mb_downloader.py fetch --type pptx --count 50 --dry-run   # list only
  python mb_downloader.py backfill        # metadata for files already in malicious/
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

API_URL = "https://mb-api.abuse.ch/api/v1/"
HERE = Path(__file__).resolve().parent
MAL_DIR = HERE / "malicious"
EXCLUDED_DIR = HERE / "_excluded"
META_CSV = HERE / "metadata" / "malicious_metadata.csv"
OOXML_TYPES = {"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm",
               "xlsb", "pptx", "pptm", "potx", "potm", "ppsx", "ppsm"}
META_FIELDS = ["sha256", "filename", "file_type", "signature", "tags", "first_seen",
               "file_size", "tlsh", "ssdeep", "reporter", "delivery_method", "source"]
SLEEP_QUERY = 1.5
SLEEP_DOWNLOAD = 2.0


# --------------------------------------------------------------------------- API
def _api_key() -> str:
    key = os.environ.get("MB_API_KEY", "").strip()
    if not key:
        sys.exit("MB_API_KEY is not set. Run: export MB_API_KEY=\"<your key>\"")
    return key


def _post(data: dict, raw: bool = False):
    req = urllib.request.Request(
        API_URL,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Auth-Key": _api_key(), "User-Agent": "ooxml-research/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        body = r.read()
    if raw:
        return body
    return json.loads(body)


def query_file_type(file_type: str, limit: int = 1000) -> list[dict]:
    j = _post({"query": "get_file_type", "file_type": file_type, "limit": str(limit)})
    if j.get("query_status") != "ok":
        print(f"[query] {file_type}: {j.get('query_status')}")
        return []
    return j.get("data") or []


def get_info(sha256: str) -> dict | None:
    j = _post({"query": "get_info", "hash": sha256})
    if j.get("query_status") != "ok" or not j.get("data"):
        return None
    return j["data"][0]


def download(sha256: str) -> bytes | None:
    """Return the sample's raw bytes (MB serves an AES zip, password 'infected')."""
    import pyzipper  # imported lazily so --dry-run / backfill work without it
    body = _post({"query": "get_file", "sha256_hash": sha256}, raw=True)
    if body[:2] != b"PK":  # error responses come back as JSON
        print(f"  ! download refused: {body[:120]!r}")
        return None
    with pyzipper.AESZipFile(io.BytesIO(body)) as z:
        z.pwd = b"infected"
        names = z.namelist()
        if len(names) != 1:
            print(f"  ! unexpected archive content: {names}")
            return None
        return z.read(names[0])


# --------------------------------------------------------------------- helpers
def existing_hashes() -> set[str]:
    hashes = set()
    for d in (MAL_DIR, EXCLUDED_DIR):
        if d.exists():
            for p in d.rglob("*"):  # includes _excluded/ subfolders
                if p.is_file() and not p.name.startswith("."):
                    hashes.add(hashlib.sha256(p.read_bytes()).hexdigest())
    return hashes


def is_ooxml_zip(data: bytes) -> bool:
    if data[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return "[Content_Types].xml" in z.namelist()
    except zipfile.BadZipFile:
        return False


def load_meta() -> dict[str, dict]:
    if not META_CSV.exists():
        return {}
    with META_CSV.open(newline="") as f:
        return {r["sha256"]: r for r in csv.DictReader(f)}


def save_meta(rows: dict[str, dict]) -> None:
    META_CSV.parent.mkdir(parents=True, exist_ok=True)
    with META_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=META_FIELDS)
        w.writeheader()
        for r in sorted(rows.values(), key=lambda r: r["sha256"]):
            w.writerow({k: r.get(k, "") for k in META_FIELDS})


def meta_row(info: dict, filename: str, source: str) -> dict:
    return {
        "sha256": info.get("sha256_hash", ""),
        "filename": filename,
        "file_type": info.get("file_type", ""),
        "signature": info.get("signature") or "",
        "tags": ";".join(info.get("tags") or []),
        "first_seen": info.get("first_seen", ""),
        "file_size": info.get("file_size", ""),
        "tlsh": info.get("tlsh") or "",
        "ssdeep": info.get("ssdeep") or "",
        "reporter": info.get("reporter", ""),
        "delivery_method": info.get("delivery_method") or "",
        "source": source,
    }


# -------------------------------------------------------------------- commands
def cmd_fetch(a) -> None:
    ftype = a.type.lower()
    if ftype not in OOXML_TYPES:
        sys.exit(f"--type must be one of {sorted(OOXML_TYPES)}")
    MAL_DIR.mkdir(exist_ok=True)
    have = existing_hashes()
    meta = load_meta()
    fam = Counter(r["signature"] or "unknown" for r in meta.values())

    candidates = query_file_type(ftype)
    print(f"[query] {ftype}: {len(candidates)} candidates from MalwareBazaar, "
          f"{len(have)} hashes already in corpus")
    time.sleep(SLEEP_QUERY)

    got = 0
    for s in candidates:
        if got >= a.count:
            break
        sha = s["sha256_hash"]
        family = s.get("signature") or "unknown"
        if sha in have:
            continue
        # The cap applies to named families only. "unknown" means no signature,
        # not one family; near-duplicates there are handled by TLSH clustering.
        if a.max_per_family and family != "unknown" and fam[family] >= a.max_per_family:
            continue
        if a.dry_run:
            print(f"  would fetch {sha}  family={family}  first_seen={s.get('first_seen')}")
            fam[family] += 1
            got += 1
            continue
        try:
            data = download(sha)
        except Exception as e:  # network / archive errors: log and move on
            print(f"  ! {sha}: {e}")
            continue
        time.sleep(SLEEP_DOWNLOAD)
        if data is None:
            continue
        if hashlib.sha256(data).hexdigest() != sha:
            print(f"  ! {sha}: hash mismatch after extraction, skipped")
            continue
        if not is_ooxml_zip(data):
            print(f"  ! {sha}: not an OOXML container, skipped")
            continue
        name = f"{sha}.{ftype}"
        (MAL_DIR / name).write_bytes(data)
        meta[sha] = meta_row(s, name, "MalwareBazaar:get_file_type")
        save_meta(meta)  # save after each file so an interrupted run loses nothing
        have.add(sha)
        fam[family] += 1
        got += 1
        print(f"  + {name}  family={family}  ({got}/{a.count})")

    print(f"\nDone: {got} {'listed' if a.dry_run else 'downloaded'} ({ftype}).")
    if got < a.count:
        print(f"Only {got} of {a.count} were available under the current filters.")


def cmd_backfill(a) -> None:
    meta = load_meta()
    files = sorted(p for p in MAL_DIR.iterdir() if p.is_file() and not p.name.startswith("."))
    print(f"[backfill] {len(files)} files in {MAL_DIR}")
    for p in files:
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if sha in meta and not a.refresh:
            continue
        try:
            info = get_info(sha)
        except urllib.error.URLError as e:
            print(f"  ! {p.name}: {e}")
            continue
        time.sleep(SLEEP_QUERY)
        if info is None:
            print(f"  ? {p.name}: not found on MalwareBazaar")
            meta[sha] = {"sha256": sha, "filename": p.name, "source": "not_found_on_MB"}
        else:
            meta[sha] = meta_row(info, p.name, "MalwareBazaar:get_info")
            print(f"  = {p.name}  family={meta[sha]['signature'] or 'unknown'}")
        save_meta(meta)
    fam = Counter(r.get("signature") or "unknown" for r in meta.values())
    print(f"\nMetadata for {len(meta)} samples -> {META_CSV}")
    print("Top families:", fam.most_common(10))


def cmd_manifest(a) -> None:
    """Download exactly the malicious samples listed in metadata/dataset_manifest.csv."""
    path = HERE / "metadata" / "dataset_manifest.csv"
    rows = [r for r in csv.DictReader(path.open()) if r["label"] == "malicious"]
    _api_key()  # exits with a clear message if MB_API_KEY is missing
    try:
        import pyzipper  # noqa: F401
    except ImportError:
        sys.exit("pyzipper is required: pip install pyzipper")
    MAL_DIR.mkdir(exist_ok=True)
    have = existing_hashes()
    got = missing = 0
    for r in rows:
        sha, name = r["sha256"], r["filename"]
        if sha in have:
            continue
        try:
            data = download(sha)
        except Exception as e:  # network / archive errors: log and move on
            print(f"  ! {name}: {e}")
            data = None
        time.sleep(SLEEP_DOWNLOAD)
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            print(f"  - not retrievable from MalwareBazaar: {name}")
            missing += 1
            continue
        (MAL_DIR / name).write_bytes(data)
        got += 1
        print(f"  + {name}")
    print(f"\nDownloaded {got}; already present {len(rows) - got - missing}; not retrievable {missing}.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="download new malicious samples of one OOXML type")
    f.add_argument("--type", required=True)
    f.add_argument("--count", type=int, required=True)
    f.add_argument("--max-per-family", type=int, default=0,
                   help="cap samples per MalwareBazaar signature (0 = no cap)")
    f.add_argument("--dry-run", action="store_true", help="list what would be fetched")
    f.set_defaults(func=cmd_fetch)
    b = sub.add_parser("backfill", help="fetch metadata for files already in malicious/")
    b.add_argument("--refresh", action="store_true", help="re-query samples already in the CSV")
    b.set_defaults(func=cmd_backfill)
    m = sub.add_parser("manifest", help="download exactly the malicious hashes in metadata/dataset_manifest.csv")
    m.set_defaults(func=cmd_manifest)
    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
