"""
schema.py — Pydantic models for the OOXML extraction manifest v2.

v2 additions:
  - ClassificationResult (28-kind BinaryKind taxonomy)
  - StageTimingRecord + ManifestSummary
  - ManifestStatus enum
  - ZipEntryRecord: classification, structural_role, extract_time_ms, classify_time_ms
  - Manifest: status, summary, timings
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class ManifestStatus(str, Enum):
    queued  = "queued"
    running = "running"
    done    = "done"
    error   = "error"


# ---------------------------------------------------------------------------
# Binary classification (v2)
# ---------------------------------------------------------------------------

class BinaryKindModel(str, Enum):
    """Mirror of extractor.binary_classifier.BinaryKind — kept in sync."""
    xml_document          = "xml_document"
    rels_relationship     = "rels_relationship"
    vba_macro_container   = "vba_macro_container"
    ole_compound_document = "ole_compound_document"
    pe_executable         = "pe_executable"
    pdf_document          = "pdf_document"
    rtf_document          = "rtf_document"
    html_document         = "html_document"
    javascript_code       = "javascript_code"
    powershell_script     = "powershell_script"
    text_plain            = "text_plain"
    zip_archive           = "zip_archive"
    image_png             = "image_png"
    image_jpeg            = "image_jpeg"
    image_gif             = "image_gif"
    image_bmp             = "image_bmp"
    image_tiff            = "image_tiff"
    excel_binary_workbook = "excel_binary_workbook"
    office_embedded_object = "office_embedded_object"
    office_media          = "office_media"
    office_theme          = "office_theme"
    office_custom_xml     = "office_custom_xml"
    office_settings       = "office_settings"
    office_metadata       = "office_metadata"
    archive_7z            = "archive_7z"
    archive_tar           = "archive_tar"
    binary_unknown        = "binary_unknown"
    data_unknown          = "data_unknown"


class MagikaResult(BaseModel):
    """Result from Google Magika ML engine."""
    label: str = ""
    group: str = ""
    mime_type: str = ""
    description: str = ""
    score: float = 0.0
    is_text: bool = False


class MagicByteResult(BaseModel):
    """Result from first-byte / heuristic engine."""
    mime_type: str = ""
    magic_label: str = ""
    confidence: float = 0.0
    embedded_mz: list[dict] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    kind: str = "data_unknown"
    mime_guess: str = "application/octet-stream"
    magic: str = ""
    confidence: float = 0.0
    notes: list[str] = Field(default_factory=list)
    embedded_signatures: list[dict] = Field(default_factory=list)
    # Dual-engine breakdown
    magic_byte: Optional[MagicByteResult] = None
    magika: Optional[MagikaResult] = None


# ---------------------------------------------------------------------------
# Timing (v2)
# ---------------------------------------------------------------------------

class StageTimingRecord(BaseModel):
    name: str
    time_ms: float


class ManifestSummary(BaseModel):
    time_total_ms: float = 0.0
    entry_count: int = 0
    macro_containers: int = 0
    dde_hits: int = 0
    xlm_hits: int = 0
    xlm_sheets: int = 0
    external_url_count: int = 0      # URLs NOT on the whitelist
    whitelisted_url_count: int = 0   # Structural/namespace URLs filtered out
    embedded_object_count: int = 0
    error_count: int = 0


# ---------------------------------------------------------------------------
# Per-entry (ZIP member) model
# ---------------------------------------------------------------------------

class XmlSummaryModel(BaseModel):
    root_tag: str = ""
    namespaces: list[str] = Field(default_factory=list)
    child_element_counts: dict[str, int] = Field(default_factory=dict)
    total_elements: int = 0


class DecodedView(BaseModel):
    decoded_text_utf8: str = ""
    decoded_text_utf16le: str = ""
    parse_error: str = ""
    xml_summary: Optional[XmlSummaryModel] = None


class ZipEntryRecord(BaseModel):
    path: str
    compression_method: str = "stored"
    compress_size: int = 0
    file_size: int = 0
    crc32: int = 0
    is_encrypted: bool = False
    sha256: str = ""
    extracted_path: str = ""
    raw_bytes_base64: str = ""
    content_type: str = "application/octet-stream"
    error: str = ""
    decoded: Optional[DecodedView] = None
    # v2 fields
    classification: Optional[ClassificationResult] = None
    structural_role: str = "unknown"
    extract_time_ms: float = 0.0
    classify_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Relationship models
# ---------------------------------------------------------------------------

class RelationshipRecord(BaseModel):
    rel_id: str = ""
    type: str = ""
    target: str = ""
    target_mode: str = "Internal"
    is_external: bool = False
    resolved_target: str = ""
    external_url: str = ""


class RelsFileRecord(BaseModel):
    path: str
    source_part: str = ""
    relationships: list[RelationshipRecord] = Field(default_factory=list)
    parse_error: str = ""


# ---------------------------------------------------------------------------
# VBA Macro models
# ---------------------------------------------------------------------------

class MacroModule(BaseModel):
    module_name: str
    code: str = ""
    auto_exec_keywords: list[str] = Field(default_factory=list)
    suspicious_keywords: list[str] = Field(default_factory=list)


class MacroContainerResult(BaseModel):
    archive_path: str
    modules: list[MacroModule] = Field(default_factory=list)
    extraction_log: str = ""
    error: str = ""


class MacroExtractionResult(BaseModel):
    containers_found: list[str] = Field(default_factory=list)
    results: list[MacroContainerResult] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# DDE models
# ---------------------------------------------------------------------------

class DdeFinding(BaseModel):
    file_path: str
    snippet: str
    offset: int
    pattern_label: str = ""


# ---------------------------------------------------------------------------
# XLM models
# ---------------------------------------------------------------------------

class XlmCell(BaseModel):
    ref: str
    formula: str = ""
    value: str = ""
    suspicious_functions: list[str] = Field(default_factory=list)


class XlmSheetResult(BaseModel):
    sheet_name: str
    archive_path: str
    cells: list[XlmCell] = Field(default_factory=list)
    all_suspicious_functions: list[str] = Field(default_factory=list)
    parse_error: str = ""


class XlmFindings(BaseModel):
    macro_sheet_paths: list[str] = Field(default_factory=list)
    sheets: list[XlmSheetResult] = Field(default_factory=list)
    workbook_macro_sheet_names: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Embedded object models
# ---------------------------------------------------------------------------

class OleStreamInfo(BaseModel):
    name: str
    size: int
    is_storage: bool


class EmbeddedObject(BaseModel):
    archive_path: str
    sha256: str
    size: int
    detected_type: str
    ole_streams: list[OleStreamInfo] = Field(default_factory=list)
    ole_error: str = ""
    child_payload_path: str = ""


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------

class FileMetadata(BaseModel):
    filename: str
    size: int
    sha256: str
    detected_doc_type: str = ""
    page_count: Optional[int] = None
    slide_count: Optional[int] = None
    word_count: Optional[int] = None


# ---------------------------------------------------------------------------
# Root Manifest (v2)
# ---------------------------------------------------------------------------

class Manifest(BaseModel):
    """Root manifest — v2 adds status, summary, timings, per-entry classification."""

    workspace_id: str
    status: ManifestStatus = ManifestStatus.done
    file_metadata: FileMetadata

    # v2: summary block
    summary: ManifestSummary = Field(default_factory=ManifestSummary)

    # v2: per-stage timing list
    timings: list[StageTimingRecord] = Field(default_factory=list)

    # Complete entry list — every ZIP member, no omissions
    entries: list[ZipEntryRecord] = Field(default_factory=list)

    rels_files: list[RelsFileRecord] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)                    # External / unknown URLs
    whitelisted_urls: list[str] = Field(default_factory=list)        # Known-clean namespace URLs
    macros: MacroExtractionResult = Field(default_factory=MacroExtractionResult)
    dde_findings: list[DdeFinding] = Field(default_factory=list)
    xlm_findings: XlmFindings = Field(default_factory=XlmFindings)
    embedded_objects: list[EmbeddedObject] = Field(default_factory=list)

    # v3: Extended extraction findings
    rtf_findings: list[dict] = Field(default_factory=list)
    html_svg_findings: list[dict] = Field(default_factory=list)
    media_issues: list[dict] = Field(default_factory=list)
    content_type_issues: list[dict] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
