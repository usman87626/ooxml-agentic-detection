"""
schema.py — Pydantic models for the Agentic Analysis Layer.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Analysis status
# ---------------------------------------------------------------------------

class AnalysisStatus(str, Enum):
    idle    = "idle"
    queued  = "queued"
    running = "running"
    done    = "done"
    error   = "error"


# ---------------------------------------------------------------------------
# Per-tool result
# ---------------------------------------------------------------------------

class ToolResult(BaseModel):
    tool_name:    str
    duration_ms:  float = 0.0
    input_data:   Any = None
    output:       dict[str, Any] = Field(default_factory=dict)
    error:        str = ""
    skipped:      bool = False
    skip_reason:  str = ""


# ---------------------------------------------------------------------------
# Signal Graph (Deterministic Outputs)
# ---------------------------------------------------------------------------

class SignalGraph(BaseModel):
    visible_text_length:        int = 0
    intent_candidates:          Optional[list[str]] = None
    has_macros:                 bool = False
    autoexec_keywords:          list[str] = Field(default_factory=list)
    macro_module_count:         int = 0
    url_count:                  int = 0
    all_urls:                   list[str] = Field(default_factory=list)
    embedded_objects:           int = 0
    binary_types:               list[str] = Field(default_factory=list)
    dde_detected:               bool = False
    xlm_detected:               bool = False
    obfuscation_detected:       bool = False
    template_injection_detected: bool = False
    prompt_injection_detected:  bool = False
    has_online_video:           bool = False
    has_activex:                bool = False
    has_dangerous_activex:      bool = False
    has_rtf_exploits:           bool = False
    has_html_svg_payloads:      bool = False
    has_media_anomalies:        bool = False
    content_type_poisoning:     bool = False
    encrypted_vba_detected:     bool = False
    macroless_attacks_detected: bool = False
    suspicious_urls:            list[str] = Field(default_factory=list)
    pcode_stomping_detected:    bool = False
    doc_metadata:               dict[str, Any] = Field(default_factory=dict)
    raw_signals:                dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    CLEAN                    = "CLEAN"
    SUSPICIOUS               = "SUSPICIOUS"
    MALICIOUS                = "MALICIOUS"
    REQUIRE_NETWORK_ANALYSIS = "REQUIRE_NETWORK_ANALYSIS"


class MitreTechnique(BaseModel):
    id:          str   # e.g. T1204.002
    name:        str
    tactic:      str
    description: str = ""


class AnalysisVerdict(BaseModel):
    verdict:                    Verdict = Verdict.CLEAN
    confidence:                 float = 0.0         # 0.0-1.0
    risk_score:                 int = 0             # 0-100
    intent:                     str = ""
    intent_confidence:          float = 0.0
    deception:                  str = ""
    harm:                       str = ""
    reasoning:                  list[str] = Field(default_factory=list)
    indicators:                 list[str] = Field(default_factory=list)
    behavior_profile:           list[str] = Field(default_factory=list)
    mitre_techniques:           list[MitreTechnique] = Field(default_factory=list)
    needs_web_analysis:         bool = False
    prompt_injection_detected:  bool = False
    extracted_iocs:             list[str] = Field(default_factory=list)
    artifact_summary:           dict[str, Any] = Field(default_factory=dict)
    analysis_metadata:          dict[str, Any] = Field(default_factory=dict)

    # Internal tracking
    signal_graph:               Optional[SignalGraph] = None
    input_data:                 Any = None

    @field_validator("confidence")
    def normalize_confidence(cls, v: float) -> float:
        """If the LLM outputs 95.0 instead of 0.95, normalize it."""
        if v > 1.0:
            return v / 100.0
        return v


class AggregatorResponse(BaseModel):
    """
    OpenAI-safe version of AnalysisVerdict for Structured Outputs.
    Excludes dict[str, Any] and Any types which break Structured Output constraints.
    """
    verdict:                    Verdict
    confidence:                 float
    risk_score:                 int
    intent:                     str
    intent_confidence:          float
    deception:                  str
    harm:                       str
    reasoning:                  list[str]
    indicators:                 list[str]
    behavior_profile:           list[str]
    mitre_techniques:           list[MitreTechnique]
    needs_web_analysis:         bool
    prompt_injection_detected:  bool
    extracted_iocs:             list[str]


class DecisiveVerdict(str, Enum):
    """Verdict space when the aggregator MUST commit to a decision (no RNA)."""
    CLEAN      = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS  = "MALICIOUS"


class AggregatorResponseDecisive(BaseModel):
    """
    Same as AggregatorResponse but the verdict is constrained to the three
    decisive classes — the aggregator cannot defer with REQUIRE_NETWORK_ANALYSIS.
    Network follow-up is still expressible via the supplementary `needs_web_analysis`
    flag, but it does not replace the verdict decision.
    """
    verdict:                    DecisiveVerdict
    confidence:                 float
    risk_score:                 int
    intent:                     str
    intent_confidence:          float
    deception:                  str
    harm:                       str
    reasoning:                  list[str]
    indicators:                 list[str]
    behavior_profile:           list[str]
    mitre_techniques:           list[MitreTechnique]
    needs_web_analysis:         bool
    prompt_injection_detected:  bool
    extracted_iocs:             list[str]


# ---------------------------------------------------------------------------
# API request / response
# ---------------------------------------------------------------------------

class AnalysisRequest(BaseModel):
    workspace_id: str
    force_rerun:  bool = False


class AnalysisStatusResponse(BaseModel):
    workspace_id:     str
    analysis_status:  AnalysisStatus = AnalysisStatus.idle
    verdict:          Optional[str] = None
    risk_score:       Optional[int] = None
    error:            str = ""
    elapsed_ms:       Optional[float] = None
