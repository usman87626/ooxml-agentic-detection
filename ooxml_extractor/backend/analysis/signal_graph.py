"""
signal_graph.py — Deterministic Signal Graph construction and risk scoring.

Implements Algorithm 2 (graph construction) and Algorithm 3 (risk scoring) of the
paper. No LLM calls. Input is the flat SignalGraph produced by
deterministic_engine.build_signal_graph() (as a dict, i.e. `model_dump()`), so the
module also runs offline on cached experiment records.

Nodes  : one per emitted signal: (id, type, severity, confidence, artifact, attrs)
Edges  : labelled, produced only by fixed predicates (rules), never learned:
         containment | exec_dependency | behavioral | network
Scores : additive  — Algorithm 3 as printed in the first submission (node mean)
         nodes     — max node evidence; the graph with E = {} (edge ablation)
         graph     — max over connected components of noisy-OR(node evidence):
                     linked evidence corroborates, unlinked evidence does not add up
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any

# --------------------------------------------------------------------------- scales
SEVERITY_WEIGHT = {"LOW": 1.0, "MEDIUM": 3.0, "HIGH": 6.0, "CRITICAL": 10.0}
W_MAX = SEVERITY_WEIGHT["CRITICAL"]

# VBA keyword families (keywords come from extractor/macro_vba_extractor.py).
# severity, confidence per family; confidence < 1 because matching is lexical.
MACRO_CAPABILITIES: dict[str, tuple[tuple[str, ...], str, float]] = {
    "memory_injection": (("VirtualAlloc", "RtlMoveMemory", "CreateThread"), "CRITICAL", 0.8),
    "process_execution": (("Shell", "WScript.Shell", "PowerShell", "cmd.exe", ".Run",
                           "Execute", "Eval", "CallByName", "CreateObject", "GetObject"), "HIGH", 0.6),
    "network_download": (("URLDownloadToFile", "WinHttp", "XMLHTTP", "ADODB.Stream"), "HIGH", 0.7),
    "file_registry_write": (("RegWrite", "Scripting.FileSystemObject", "OpenTextFile", "Write("), "MEDIUM", 0.6),
    "string_manipulation": (("Chr(", "Asc(", "Mid(", "InStr(", "StrReverse", "Base64", "environ"), "LOW", 0.5),
}
EXEC_CAPABILITIES = {"memory_injection", "process_execution", "network_download"}

# Excel/Word object-model calls that share names with execution keywords but run
# no external process: stripped before capability matching (revision, R6 round).
BENIGN_HOST_CALLS = re.compile(
    r"Application\.Run\b|\.Evaluate\b|\bEvaluate\s*\(|\.Find\.Execute\b|Dialogs\([^)]*\)\.Execute\b"
    r"|\.Execute(?:Mso|Excel4Macro)?\b(?=\s*(?:\(|$|'))",
    re.I | re.M)
WORD_KEYWORDS = {"Eval", "Execute"}  # must match as whole words (not "Evaluate", "Executed")

URL_RE = re.compile(r"""(?:https?|ftp|file|mhtml)://[^\s"'<>()]+""", re.I)


@dataclass
class Node:
    id: str
    type: str
    severity: str
    confidence: float
    artifact: str = ""                 # archive part, macro module or sheet
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def evidence(self) -> float:       # p_i in [0,1]
        return SEVERITY_WEIGHT[self.severity] / W_MAX * self.confidence


@dataclass
class Edge:
    src: str
    dst: str
    type: str                          # containment | exec_dependency | behavioral | network
    rule: str                          # name of the predicate that fired


@dataclass
class SignalGraphModel:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    # ---------------------------------------------------------------- scoring
    def risk_additive(self) -> float:
        """Algorithm 3 as printed in the first submission: sum(w*c) / (|V| * w_max)."""
        if not self.nodes:
            return 0.0
        return sum(SEVERITY_WEIGHT[n.severity] * n.confidence for n in self.nodes) / (len(self.nodes) * W_MAX)

    def risk_nodes(self) -> float:
        """Edge ablation: every node is its own component, so R = max_i p_i."""
        return max((n.evidence for n in self.nodes), default=0.0)

    def scoring_edges(self) -> list[Edge]:
        """Edges that merge evidence in the risk score.
        Correlation edges (exec_dependency, behavioral, network) always do. A
        containment edge only records where a signal lives, so it counts only when
        the container is itself a HIGH/CRITICAL signal (e.g. a risky altChunk import),
        not for structural containers such as the VBA project."""
        sev = {n.id: n.severity for n in self.nodes}
        return [e for e in self.edges
                if e.type != "containment" or sev.get(e.src) in ("HIGH", "CRITICAL")]

    def components(self, edges: list[Edge] | None = None) -> list[list[Node]]:
        parent = {n.id: n.id for n in self.nodes}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for e in (self.edges if edges is None else edges):
            parent[find(e.src)] = find(e.dst)
        groups: dict[str, list[Node]] = {}
        for n in self.nodes:
            groups.setdefault(find(n.id), []).append(n)
        return sorted(groups.values(), key=len, reverse=True)

    def risk_graph(self) -> float:
        """Full graph: R = max over components C of 1 - prod_{i in C} (1 - p_i)."""
        best = 0.0
        for comp in self.components(self.scoring_edges()):
            q = 1.0
            for n in comp:
                q *= 1.0 - n.evidence
            best = max(best, 1.0 - q)
        return best

    def scores(self) -> dict[str, float]:
        return {"additive": round(self.risk_additive(), 4),
                "nodes": round(self.risk_nodes(), 4),
                "graph": round(self.risk_graph(), 4)}

    # ------------------------------------------------------------ serialisation
    def to_prompt(self, include_edges: bool = True, max_nodes: int = 60) -> dict:
        """Compact form for the aggregator prompt (edge ablation: include_edges=False)."""
        nodes = sorted(self.nodes, key=lambda n: -n.evidence)[:max_nodes]
        keep = {n.id for n in nodes}
        out = {
            "nodes": [{"id": n.id, "type": n.type, "severity": n.severity,
                       "confidence": n.confidence, "artifact": n.artifact,
                       **({"detail": n.attrs.get("detail")} if n.attrs.get("detail") else {})}
                      for n in nodes],
            "omitted_nodes": max(0, len(self.nodes) - len(nodes)),
        }
        if include_edges:
            out["edges"] = [asdict(e) for e in self.edges if e.src in keep and e.dst in keep]
            out["correlated_chains"] = [
                [n.id for n in c] for c in self.components() if len(c) > 1 and all(n.id in keep for n in c)
            ]
        return out

    def stats(self) -> dict:
        et: dict[str, int] = {}
        for e in self.edges:
            et[e.type] = et.get(e.type, 0) + 1
        comps = self.components()
        return {"n_nodes": len(self.nodes), "n_edges": len(self.edges), "edge_types": et,
                "largest_component": len(comps[0]) if comps else 0}


# --------------------------------------------------------------------------- build
def _mod(name: str) -> str:
    """Normalise a macro module reference: 'macro:ThisWorkbook.cls' -> 'thisworkbook'."""
    name = name.split(":", 1)[-1].strip()
    name = re.sub(r"\.(cls|bas|frm)$", "", name, flags=re.I)
    return name.lower()


def _norm_url(u: str) -> str:
    return u.strip().rstrip("/").lower()


def build_graph(sg: dict) -> SignalGraphModel:
    """Algorithm 2. `sg` is a SignalGraph as a dict (model_dump()), incl. raw_signals."""
    raw = sg.get("raw_signals") or {}
    g = SignalGraphModel()
    seen: set[tuple] = set()

    def add(ntype: str, sev: str, conf: float, artifact: str = "", key: Any = None, **attrs) -> Node | None:
        k = (ntype, artifact, key if key is not None else attrs.get("detail", ""))
        if k in seen:
            return None
        seen.add(k)
        n = Node(id=f"n{len(g.nodes)}", type=ntype, severity=sev, confidence=conf,
                 artifact=artifact, attrs=attrs)
        g.nodes.append(n)
        return n

    # ---------------------------------------------------------------- pass 1: nodes
    macros = raw.get("macros", {}) or {}
    macro_paths = list(macros.get("macro_paths") or [])
    project = macro_paths[0] if macro_paths else "vbaProject"
    if macros.get("has_macros"):
        for p in macro_paths or [project]:
            add("VBA_PROJECT", "MEDIUM", 1.0, p, detail=f"VBA project ({macros.get('macro_module_count', 0)} modules)")

    modules = macros.get("macro_modules") or []
    for m in modules:
        code = (m.get("code") or "")
        low = BENIGN_HOST_CALLS.sub(" ", code).lower()
        mname = _mod(m.get("name", ""))
        for cap, (kws, sev, conf) in MACRO_CAPABILITIES.items():
            hits = sorted({k for k in kws if (re.search(r"\b" + k.lower() + r"\b", low) if k in WORD_KEYWORDS
                                               else k.lower() in low)})
            if hits:
                add("MACRO_CAPABILITY", sev, conf, f"macro:{mname}", key=cap,
                    capability=cap, detail=f"{cap}: {', '.join(hits)}", module=mname)
        for kw in macros.get("autoexec_keywords") or []:
            if kw.lower() in code.lower():
                # MEDIUM: a trigger alone is not malicious; risk comes from what it runs (edges)
                add("AUTOEXEC", "MEDIUM", 0.9, f"macro:{mname}", key=kw, module=mname, detail=kw)
        for u in URL_RE.findall(code):
            add("MACRO_URL", "MEDIUM", 0.7, f"macro:{mname}", key=_norm_url(u), url=u, module=mname,
                detail=u[:120])
    # autoexec keywords that could not be located in a module
    for kw in macros.get("autoexec_keywords") or []:
        if not any(n.type == "AUTOEXEC" and n.attrs.get("detail") == kw for n in g.nodes):
            add("AUTOEXEC", "MEDIUM", 0.9, project, key=kw, detail=kw, module="")
    if macros.get("encrypted_vba_detected"):
        add("ENCRYPTED_VBA", "HIGH", 0.9, project, detail="password-protected VBA project")

    for d in (raw.get("obfuscation", {}) or {}).get("obfuscation_details") or []:
        src = d.get("source", "")
        art = f"macro:{_mod(src)}" if src.startswith("macro:") else src
        add("OBFUSCATION", "MEDIUM", 0.7, art, key=d.get("technique"),
            detail=f"{d.get('technique')} x{d.get('count')}", module=_mod(src) if src.startswith("macro:") else "")

    pcode = raw.get("pcode", {}) or {}
    if pcode.get("stomping_detected"):
        add("PCODE_STOMPING", "CRITICAL", 0.95, project, detail="VBA source/p-code mismatch")

    xlm = raw.get("xlm", {}) or {}
    for f in xlm.get("dangerous_functions") or []:
        sheet = (f.get("source") or "").split("!")[0]
        sev = "CRITICAL" if str(f.get("risk", "")).upper() == "CRITICAL" else "HIGH"
        add("XLM_EXEC", sev, 0.9, f"sheet:{sheet}", key=f.get("function"), detail=f"XLM {f.get('function')}")
    if xlm.get("anti_sandbox_detected"):
        add("XLM_ANTI_SANDBOX", "HIGH", 0.85, "xlm", detail="anti-sandbox checks")
    if xlm.get("xlm_detected") and not xlm.get("dangerous_functions"):
        add("XLM_MACROSHEET", "MEDIUM", 0.8, "xlm", detail="Excel 4.0 macro sheet")

    dde = raw.get("dde", {}) or {}
    for c in dde.get("dde_commands") or []:
        cmd = c.get("command") if isinstance(c, dict) else str(c)
        loc = c.get("location", "") if isinstance(c, dict) else ""
        add("DDE_COMMAND", "CRITICAL", 0.95, loc, key=str(cmd)[:80], detail=str(cmd)[:120],
            urls=[_norm_url(u) for u in URL_RE.findall(str(cmd))])
    for loc in dde.get("dde_locations") or []:
        add("DDE_FIELD", "HIGH", 0.8, loc.split(": ", 1)[-1], detail=loc)

    ole = raw.get("ole", {}) or {}
    for o, sev, conf in ([(x, "HIGH", 0.9) for x in ole.get("high_risk_objects") or []] +
                         [(x, "MEDIUM", 0.8) for x in ole.get("medium_risk_objects") or []]):
        path = o.get("archive_path", "")
        if path in macro_paths:          # the VBA container itself is already a node
            continue
        add("EMBEDDED_OBJECT", sev, conf, path, detail=f"{o.get('detected_type')} ({o.get('risk_level')})")

    ox = raw.get("ooxml_attack", {}) or {}
    for c in ox.get("activex_clsids") or []:
        dangerous = bool(c.get("is_dangerous"))
        add("ACTIVEX", "CRITICAL" if dangerous else "MEDIUM", 0.95 if dangerous else 0.6,
            c.get("path", ""), key=c.get("clsid"), detail=f"CLSID {c.get('clsid')} {c.get('description', '')}".strip())
    for v in ox.get("online_video_details") or []:
        for link in v.get("links", []) or []:
            add("ONLINE_VIDEO", "MEDIUM", 0.7, v.get("path", ""), key=_norm_url(link), url=link, detail=link[:120])

    ti = raw.get("template_injection", {}) or {}
    inj = {_norm_url(u) for u in ti.get("injection_urls") or []}
    for d in ti.get("injection_details") or []:
        tgt = d.get("target", "")
        if _norm_url(tgt) in inj:
            add("TEMPLATE_INJECTION", "HIGH", 0.85, d.get("rels_file", ""), key=_norm_url(tgt), url=tgt,
                detail=f"{d.get('type')} -> {tgt[:100]}")
        else:
            add("EXTERNAL_REFERENCE", "LOW", 0.5, d.get("rels_file", ""), key=_norm_url(tgt), url=tgt,
                detail=f"{d.get('type')} -> {tgt[:100]}")

    st = raw.get("structure", {}) or {}
    for f in st.get("flags") or []:
        add("STRUCTURE_ANOMALY", "MEDIUM", 0.6, "package", key=f, detail=str(f)[:120])
    for u in st.get("ole_external") or []:
        add("EXTERNAL_OLE_LINK", "HIGH", 0.85, "package", key=_norm_url(u), url=u, detail=u[:120],
            urls=[_norm_url(x) for x in URL_RE.findall(u)])
    if sg.get("content_type_poisoning"):
        add("CONTENT_TYPE_POISONING", "HIGH", 0.8, "[Content_Types].xml", detail="content-type override anomaly")
    if sg.get("has_media_anomalies"):
        add("MEDIA_ANOMALY", "MEDIUM", 0.6, "media", detail="malformed media record")

    for f in (raw.get("macroless", {}) or {}).get("findings") or []:
        sev = str(f.get("severity", "MEDIUM")).upper()
        sev = sev if sev in SEVERITY_WEIGHT else "MEDIUM"
        if f.get("type") == "qat_macro_binding":
            sev = "MEDIUM"   # ribbon callbacks are standard in macro add-ins; the edge to VBA carries the risk
        conf = 0.85 if f.get("type") == "altchunk_import" else 0.7
        add("MACROLESS", sev, conf, f.get("source", ""), key=(f.get("type"), f.get("target", "")),
            detail=f"{f.get('type')}: {str(f.get('detail', ''))[:90]}", finding=f.get("type"),
            target=f.get("target", ""))

    hs = raw.get("html_svg", {}) or {}
    for f in hs.get("findings") or []:
        add("ACTIVE_CONTENT", "HIGH", 0.85, f.get("path", f.get("source", "")), key=str(f)[:80],
            detail=f"{f.get('type', 'html')} active content")
    for o in hs.get("rtf_objects") or []:
        src = o.get("source", "")
        add("RTF_OLE_OBJECT", "HIGH", 0.85, src, detail="OLE object embedded in RTF" +
            (" (Equation Editor)" if o.get("equation_editor") else ""))
        if o.get("autoupdate"):
            add("RTF_OLE_AUTOUPDATE", "HIGH", 0.9, src, detail="RTF OLE object auto-updates on open (\\objupdate)")
    if hs.get("has_rtf_exploits"):
        add("RTF_EXPLOIT", "CRITICAL", 0.95, "rtf", detail="RTF exploit (e.g. Equation Editor)")

    if (raw.get("prompt_injection", {}) or {}).get("prompt_injection_detected"):
        add("PROMPT_INJECTION", "MEDIUM", 0.8, "visible_text", detail="instructions aimed at an AI analyst")

    url_issue = {_norm_url(i.get("url", "")): i for i in (raw.get("url_validation", {}) or {}).get("url_issues") or []}
    for u in sg.get("all_urls") or []:
        nu = _norm_url(u)
        if nu in url_issue:
            sev = str(url_issue[nu].get("severity", "MEDIUM")).upper()
            add("SUSPICIOUS_URL", sev if sev in SEVERITY_WEIGHT else "MEDIUM", 0.7, "url", key=nu, url=u,
                detail=f"{u[:90]} ({'; '.join(url_issue[nu].get('issues', []))[:60]})")
        else:
            add("URL", "LOW", 0.3, "url", key=nu, url=u, detail=u[:120])

    # ---------------------------------------------------------------- pass 2: edges
    _add_edges(g)
    return g


def _add_edges(g: SignalGraphModel) -> None:
    by_type: dict[str, list[Node]] = {}
    for n in g.nodes:
        by_type.setdefault(n.type, []).append(n)
    T = lambda *ts: [n for t in ts for n in by_type.get(t, [])]  # noqa: E731
    have: set[tuple[str, str, str]] = set()

    def link(a: Node, b: Node, etype: str, rule: str) -> None:
        if a.id == b.id or (a.id, b.id, etype) in have:
            return
        have.add((a.id, b.id, etype))
        g.edges.append(Edge(a.id, b.id, etype, rule))

    macro_signals = T("MACRO_CAPABILITY", "AUTOEXEC", "OBFUSCATION", "MACRO_URL", "ENCRYPTED_VBA", "PCODE_STOMPING")
    macro_signals = [n for n in macro_signals if n.artifact.startswith("macro:") or n.type in ("ENCRYPTED_VBA", "PCODE_STOMPING")
                     or n.artifact in [p.artifact for p in T("VBA_PROJECT")]]

    # R1 containment: a VBA project contains every signal raised inside its modules
    for proj in T("VBA_PROJECT"):
        for s in macro_signals:
            link(proj, s, "containment", "vba_project_contains_module_signal")
    # R2 containment: an embedded part contains signals located inside it
    for parent in T("EMBEDDED_OBJECT", "ACTIVEX"):
        for s in g.nodes:
            if s is not parent and s.artifact and parent.artifact and s.artifact != parent.artifact \
                    and s.artifact.startswith(parent.artifact.rsplit(".", 1)[0]):
                link(parent, s, "containment", "part_contains_signal")

    # R3 exec dependency: an auto-execution trigger runs execution-capable code
    # in the same module, or anywhere in the same project when not module-resolved
    for a in T("AUTOEXEC"):
        for s in T("MACRO_CAPABILITY", "OBFUSCATION", "MACRO_URL"):
            same_mod = a.attrs.get("module") and a.attrs.get("module") == s.attrs.get("module")
            if s.type == "MACRO_CAPABILITY" and s.attrs.get("capability") not in EXEC_CAPABILITIES and not same_mod:
                continue
            if same_mod or not a.attrs.get("module"):
                link(a, s, "exec_dependency", "autoexec_triggers_code")
            elif s.type == "MACRO_CAPABILITY":
                link(a, s, "exec_dependency", "autoexec_triggers_project_code")
    # R4 exec dependency: macro-less triggers that fire VBA (UI callbacks, ActiveX events)
    for t in [n for n in T("MACROLESS") if n.attrs.get("finding") == "qat_macro_binding"] + T("ACTIVEX"):
        for proj in T("VBA_PROJECT"):
            link(t, proj, "exec_dependency", "ui_or_activex_triggers_vba")
    # R5 exec dependency: DDE field executes its command; XLM macro sheet executes functions
    for f in T("DDE_FIELD"):
        for c in T("DDE_COMMAND"):
            link(f, c, "exec_dependency", "dde_field_runs_command")
    for s in T("XLM_MACROSHEET", "XLM_ANTI_SANDBOX"):
        for x in T("XLM_EXEC"):
            link(s, x, "exec_dependency", "xlm_sheet_runs_function")

    # R6 behavioral linkage: concealment + capability in the same module
    for o in T("OBFUSCATION"):
        for c in T("MACRO_CAPABILITY"):
            if o.attrs.get("module") and o.attrs.get("module") == c.attrs.get("module") \
                    and c.attrs.get("capability") in EXEC_CAPABILITIES:
                link(o, c, "behavioral", "obfuscated_execution")
    for h in T("ENCRYPTED_VBA", "PCODE_STOMPING"):
        for c in T("MACRO_CAPABILITY"):
            if c.attrs.get("capability") in EXEC_CAPABILITIES:
                link(h, c, "behavioral", "concealed_execution")
    # R7 behavioral linkage: remote template + macro-less web/frame settings (same technique)
    for t in T("TEMPLATE_INJECTION", "EXTERNAL_OLE_LINK"):
        for m in T("MACROLESS", "STRUCTURE_ANOMALY", "CONTENT_TYPE_POISONING"):
            if m.attrs.get("finding") != "qat_macro_binding":
                link(t, m, "behavioral", "remote_load_with_structural_tampering")

    # R7b containment: an altChunk import contains the signals of the part it imports;
    #     exec dependency: an auto-updating RTF object activates its embedded OLE object
    for a in [n for n in T("MACROLESS") if n.attrs.get("finding") == "altchunk_import"]:
        for r in T("RTF_OLE_OBJECT", "RTF_OLE_AUTOUPDATE", "RTF_EXPLOIT"):
            if a.attrs.get("target") and r.artifact == a.attrs.get("target"):
                link(a, r, "containment", "altchunk_imports_part")
    for u in T("RTF_OLE_AUTOUPDATE"):
        for o in T("RTF_OLE_OBJECT"):
            if o.artifact == u.artifact:
                link(u, o, "exec_dependency", "autoupdate_activates_ole")

    # R8 network retrieval: a signal that names a URL resolves to that URL node
    url_nodes: dict[str, Node] = {}
    for u in T("URL", "SUSPICIOUS_URL"):
        url_nodes[_norm_url(u.attrs.get("url", ""))] = u
    for s in g.nodes:
        if s.type in ("URL", "SUSPICIOUS_URL"):
            continue
        targets = set(s.attrs.get("urls") or [])
        if s.attrs.get("url"):
            targets.add(_norm_url(s.attrs["url"]))
        for t in targets:
            if t in url_nodes:
                link(s, url_nodes[t], "network", "signal_resolves_to_url")
    # R9 network retrieval: downloader capability in a module that embeds a URL
    for c in T("MACRO_CAPABILITY"):
        if c.attrs.get("capability") in ("network_download", "process_execution"):
            for mu in T("MACRO_URL"):
                if mu.attrs.get("module") == c.attrs.get("module"):
                    link(c, mu, "network", "download_capability_with_url")
