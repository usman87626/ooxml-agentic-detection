"""
ooxml_attack_analyzer.py — Analyzer for Online Video, ActiveX, and embedded HTML attacks.

Includes ActiveX CLSID extraction and checking against a known-dangerous list.
"""
from __future__ import annotations
import html as py_html
import re
import struct
import logging
from html.parser import HTMLParser
from typing import List, Dict, Any

from analysis.tools.attack_utils import EMBEDDED_HTML_RE, TEMPLATE_REL_RE

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-dangerous ActiveX CLSIDs
# ---------------------------------------------------------------------------
DANGEROUS_CLSIDS: Dict[str, str] = {
    # ShockwaveFlash — used in Flash-based exploits
    "d27cdb6e-ae6d-11cf-96b8-444553540000": "ShockwaveFlash.ShockwaveFlash (Flash exploit vector)",
    # MSXML2.XMLHTTP — remote data fetching
    "f6d90f16-9c73-11d3-b32e-00c04f990bb4": "MSXML2.XMLHTTP (Remote data fetch)",
    "88d96a0a-f192-11d4-a65f-0040963251e5": "MSXML2.XMLHTTP.6.0 (Remote data fetch)",
    # InkEdit — used for arbitrary code execution
    "233c1507-6a77-46a4-9443-f871f945d258": "InkEdit Control (Code execution vector)",
    # InkPicture
    "04a1e553-fe36-4fde-865e-344194e69424": "InkPicture Control (Code execution vector)",
    # Microsoft Forms controls (common in phishing)
    "d7053240-ce69-11cd-a777-00dd01143c57": "Microsoft Forms 2.0 CommandButton",
    # Shell.Explorer
    "8856f961-340a-11d0-a96b-00c04fd705a2": "Shell.Explorer (WebBrowser Control)",
    # Microsoft Web Browser
    "eab22ac3-30c1-11cf-a7eb-0000c05bae0b": "WebBrowser Control (Remote content load)",
    # ADODB.Recordset — data exfiltration
    "00000535-0000-0010-8000-00aa006d2ea4": "ADODB.Recordset (Data access)",
    # ScriptControl — execute scripts
    "0e59f1d5-1fbe-11d0-8ff2-00a0d10038bc": "MSScriptControl.ScriptControl (Script execution)",
    # WScript.Shell
    "72c24dd5-d70a-438b-8a42-98424b88afb8": "WScript.Shell (Shell command execution)",
    # Shell.Application
    "13709620-c279-11ce-a49e-444553540000": "Shell.Application (Shell access)",
    # Schedule.Service — task scheduler
    "0f87369f-a4e5-4cfc-bd3e-73e6154572dd": "Schedule.Service (Task scheduler access)",
    # PowerPoint.Show — CVE exploitation
    "91493441-5a91-11cf-8700-00aa0060263b": "PowerPoint.Show.12 (Embedded presentation)",
    # MMC / SnapIn — admin tool abuse
    "49b2791a-b1ae-4c90-9b8e-e860ba07f889": "MMC.SnapIn (Administrative tool abuse)",
}

# CLSID regex (standard format with/without braces)
_CLSID_RE = re.compile(
    r'\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?',
    re.IGNORECASE,
)

# OLE CLSID offset in ActiveX .bin files (first 16 bytes after OLE header)
_OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


class _VideoLinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag, attrs):
        for attr, value in attrs:
            if attr.lower() in ("href", "src", "data-src") and value:
                self.links.append(value)

def extract_html_links(html_str: str) -> List[str]:
    parser = _VideoLinkExtractor()
    try:
        parser.feed(html_str)
    except Exception as e:
        logger.warning(f"HTML parse error: {e}")

    seen = set()
    unique = []
    for link in parser.links:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return unique


def _extract_clsid_from_bin(data: bytes) -> str | None:
    """
    Attempt to extract CLSID from an ActiveX .bin file.

    Strategy:
    1. If it's an OLE compound doc, try to read CLSID from standard position
    2. Scan first 512 bytes for CLSID-like patterns in text representation
    3. Try to extract from raw UUID bytes at common offsets
    """
    if not data or len(data) < 20:
        return None

    # Strategy 1: If OLE, try known offset (sector 0, bytes 48-63 contain root CLSID)
    if data[:8] == _OLE_MAGIC and len(data) >= 64:
        try:
            # Root entry CLSID is at offset 48 in the header (for OLE files)
            # Actually, CLSIDs in ActiveX bins are often in the first few hundred bytes
            # Try olefile if available
            try:
                import olefile
                ole = olefile.OleFileIO(data)
                clsid = ole.root.clsid
                ole.close()
                if clsid and clsid != "00000000-0000-0000-0000-000000000000":
                    return clsid.lower()
            except Exception:
                pass
        except Exception:
            pass

    # Strategy 2: Search text representation in first 1KB
    text_view = ""
    try:
        text_view = data[:1024].decode("utf-8", errors="ignore")
    except Exception:
        pass

    for m in _CLSID_RE.finditer(text_view):
        clsid = m.group(1).lower()
        if clsid != "00000000-0000-0000-0000-000000000000":
            return clsid

    # Strategy 3: Try common binary UUID offsets
    for offset in (0, 4, 8, 16, 20, 48, 64, 80):
        if offset + 16 <= len(data):
            try:
                # Read as little-endian UUID structure
                d1 = struct.unpack_from('<I', data, offset)[0]
                d2 = struct.unpack_from('<H', data, offset + 4)[0]
                d3 = struct.unpack_from('<H', data, offset + 6)[0]
                d4 = data[offset + 8:offset + 16]
                clsid = f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-" + \
                         "".join(f"{b:02x}" for b in d4[2:])
                if clsid in DANGEROUS_CLSIDS:
                    return clsid
            except (struct.error, IndexError):
                continue

    return None


def analyze(manifest: dict) -> dict:
    """
    Analyze manifest for Online Video (embeddedHtml), ActiveX streams,
    and ActiveX CLSID risk assessment.
    """
    entries = manifest.get("entries", [])
    decoded_text_map = {}  # path -> text

    # Build a path -> raw_bytes_base64 lookup for ActiveX binary inspection
    entry_bytes_map: Dict[str, str] = {}
    for entry in entries:
        decoded = entry.get("decoded") or {}
        text = decoded.get("decoded_text_utf8", "")
        if text:
            decoded_text_map[entry["path"]] = text
        b64 = entry.get("raw_bytes_base64", "")
        if b64:
            entry_bytes_map[entry["path"]] = b64

    online_video = []
    activex_found = []
    activex_clsids: List[Dict[str, Any]] = []
    template_injections = []

    for path, text in decoded_text_map.items():
        lower_path = path.lower()

        # 1. Online Video
        if "embeddedhtml" in text.lower():
            for m in EMBEDDED_HTML_RE.finditer(text):
                raw_html = m.group("html")
                try:
                    decoded_html = py_html.unescape(raw_html)
                    links = extract_html_links(decoded_html)
                    online_video.append({
                        "path": path,
                        "links": links
                    })
                except Exception:
                    pass

        # 2. ActiveX detection and CLSID extraction
        if "/activex/" in lower_path and lower_path.endswith((".bin", ".xml")):
            activex_found.append(path)

            # Try to extract CLSID from binary data
            import base64
            raw_b64 = entry_bytes_map.get(path, "")
            if raw_b64:
                try:
                    raw_data = base64.b64decode(raw_b64)
                    clsid = _extract_clsid_from_bin(raw_data)
                    if clsid:
                        risk_desc = DANGEROUS_CLSIDS.get(clsid)
                        activex_clsids.append({
                            "path": path,
                            "clsid": clsid,
                            "is_dangerous": risk_desc is not None,
                            "description": risk_desc or "Unknown CLSID",
                        })
                except Exception as e:
                    logger.warning(f"ActiveX CLSID extraction failed for {path}: {e}")

            # Also scan XML-based ActiveX definitions for classid attributes
            if lower_path.endswith(".xml") and "classid" in text.lower():
                for clsid_match in _CLSID_RE.finditer(text):
                    clsid = clsid_match.group(1).lower()
                    risk_desc = DANGEROUS_CLSIDS.get(clsid)
                    activex_clsids.append({
                        "path": path,
                        "clsid": clsid,
                        "is_dangerous": risk_desc is not None,
                        "description": risk_desc or "Unknown CLSID",
                    })

    has_dangerous_activex = any(c.get("is_dangerous") for c in activex_clsids)

    return {
        "has_online_video": len(online_video) > 0,
        "online_video_details": online_video,
        "has_activex": len(activex_found) > 0,
        "activex_paths": activex_found,
        "activex_clsids": activex_clsids,
        "has_dangerous_activex": has_dangerous_activex,
    }
