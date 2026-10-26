"""
manifest_builder.py — orchestrate all extractors and assemble Manifest (v2).

v2 additions:
  - PipelineTimings wired through all stages
  - binary_classifier called per entry
  - structure_enumerator annotates structural roles
  - JSON structured logging via logging_setup
  - ManifestSummary populated at the end
"""

from __future__ import annotations

import base64
import re
import logging
from pathlib import Path
from typing import Optional

from extractor.zip_reader import iter_zip_entries, compression_name
from extractor.content_type_detector import build_content_type_map
from extractor.rels_parser import collect_all_rels
from extractor.xml_decoder import decode_part, is_xml_like
from extractor.macro_vba_extractor import extract_macros
from extractor.xlm_extractor import extract_xlm
from extractor.dde_detector import scan_entries
from extractor.ole_embedded_extractor import extract_embedded_objects
from extractor.utils import sha256_bytes
from extractor.binary_classifier import classify as classify_binary
from extractor.structure_enumerator import enumerate_structure
from extractor.timing import PipelineTimings, measure_ms
from extractor.logging_setup import get_logger
from extractor.url_whitelist import filter_urls
from extractor.rtf_extractor import extract_rtf_findings
from extractor.html_svg_extractor import extract_all as extract_html_svg
from extractor.media_validator import validate_media_entries
from extractor.content_type_validator import validate as validate_content_types

# Decryption support (optional)
try:
    import msoffcrypto
    _HAS_MSOFFCRYPTO = True
except ImportError:
    _HAS_MSOFFCRYPTO = False

from models.schema import (
    Manifest, ManifestStatus, ManifestSummary, FileMetadata,
    ZipEntryRecord, DecodedView, XmlSummaryModel,
    ClassificationResult, MagikaResult, MagicByteResult, StageTimingRecord,
    RelsFileRecord, RelationshipRecord,
    MacroModule, MacroContainerResult, MacroExtractionResult,
    DdeFinding, XlmCell, XlmSheetResult, XlmFindings,
    OleStreamInfo, EmbeddedObject,
)
import storage.workspace as ws_store

BASE64_INLINE_THRESHOLD_BYTES = 256 * 1024  # 256 KB


def _detect_doc_type(filename: str, entries_paths: list[str]) -> str:
    fname_lower = filename.lower()
    ext_map = {
        ".docx": "Word Document (OOXML)",    ".docm": "Word Macro-Enabled Document (OOXML)",
        ".dotx": "Word Template (OOXML)",    ".dotm": "Word Macro-Enabled Template (OOXML)",
        ".xlsx": "Excel Workbook (OOXML)",   ".xlsm": "Excel Macro-Enabled Workbook (OOXML)",
        ".xltx": "Excel Template (OOXML)",   ".xltm": "Excel Macro-Enabled Template (OOXML)",
        ".xlsb": "Excel Binary Workbook",
        ".pptx": "PowerPoint Presentation (OOXML)",  ".pptm": "PowerPoint Macro-Enabled Presentation (OOXML)",
        ".potx": "PowerPoint Template (OOXML)",      ".potm": "PowerPoint Macro-Enabled Template (OOXML)",
        ".ppsx": "PowerPoint Show (OOXML)",          ".ppsm": "PowerPoint Macro-Enabled Show (OOXML)",
    }
    for ext, label in ext_map.items():
        if fname_lower.endswith(ext):
            return label
    path_set = {p.lower() for p in entries_paths}
    if "word/document.xml" in path_set:
        return "Word Document (OOXML)"
    if "xl/workbook.xml" in path_set:
        return "Excel Workbook (OOXML)"
    if "ppt/presentation.xml" in path_set:
        return "PowerPoint Presentation (OOXML)"
    return "Unknown OOXML / ZIP"


# ---------------------------------------------------------------------------
# Decryption helper
# ---------------------------------------------------------------------------
_COMMON_PASSWORDS = ["", "VelvetSweatshop", "1234", "password", "123456"]

def _try_decrypt(archive_bytes: bytes, log) -> tuple[bytes, bool]:
    """
    Attempt to decrypt an encrypted Office document using common passwords.
    Returns (decrypted_bytes, was_decrypted). If decryption fails or not needed,
    returns (original_bytes, False).
    """
    if not _HAS_MSOFFCRYPTO:
        return archive_bytes, False

    import io
    try:
        file_obj = io.BytesIO(archive_bytes)
        ms_file = msoffcrypto.OfficeFile(file_obj)
        if not ms_file.is_encrypted():
            return archive_bytes, False

        log.info("Encrypted document detected — attempting decryption")
        for pwd in _COMMON_PASSWORDS:
            try:
                ms_file.load_key(password=pwd)
                output = io.BytesIO()
                ms_file.decrypt(output)
                decrypted = output.getvalue()
                log.info("Decryption succeeded with password: %s",
                         repr(pwd) if pwd else '(empty)')
                return decrypted, True
            except Exception:
                continue

        log.warning("Decryption failed — no common password worked")
        return archive_bytes, False
    except Exception as e:
        log.warning("Decryption check error: %s", e)
        return archive_bytes, False


# ---------------------------------------------------------------------------
# Metadata extraction (page/slide/word count from docProps/app.xml)
# ---------------------------------------------------------------------------
def _extract_doc_metadata(decoded_text_map: dict[str, str]) -> dict:
    """
    Extract document metadata (page count, slide count, word count)
    from docProps/app.xml.
    """
    metadata: dict = {}
    app_text = decoded_text_map.get("docProps/app.xml", "")
    if not app_text:
        return metadata

    # Page count
    m = re.search(r'<Pages>(\d+)</Pages>', app_text, re.IGNORECASE)
    if m:
        metadata["page_count"] = int(m.group(1))

    # Slide count
    m = re.search(r'<Slides>(\d+)</Slides>', app_text, re.IGNORECASE)
    if m:
        metadata["slide_count"] = int(m.group(1))

    # Word count
    m = re.search(r'<Words>(\d+)</Words>', app_text, re.IGNORECASE)
    if m:
        metadata["word_count"] = int(m.group(1))

    # Paragraph count
    m = re.search(r'<Paragraphs>(\d+)</Paragraphs>', app_text, re.IGNORECASE)
    if m:
        metadata["paragraph_count"] = int(m.group(1))

    # Character count
    m = re.search(r'<Characters>(\d+)</Characters>', app_text, re.IGNORECASE)
    if m:
        metadata["character_count"] = int(m.group(1))

    # Application
    m = re.search(r'<Application>([^<]+)</Application>', app_text, re.IGNORECASE)
    if m:
        metadata["application"] = m.group(1).strip()

    # Company
    m = re.search(r'<Company>([^<]+)</Company>', app_text, re.IGNORECASE)
    if m:
        metadata["company"] = m.group(1).strip()

    return metadata


def build_manifest(
    workspace_id: str,
    filename: str,
    archive_bytes: bytes,
) -> Manifest:
    """
    Run the full 10-stage extraction pipeline and return a Manifest (v2).

    Stages:
      1.  ZIP enumeration + raw byte extraction
      2.  Content-type detection
      3.  XML/text decoding (additive)
      4.  Binary classification (per entry)
      5.  Structural role assignment
      6.  Relationship parsing
      7.  VBA macro extraction
      8.  XLM detection
      9.  DDE detection
      10. Embedded object enumeration
    """
    log = get_logger("extractor.manifest_builder", workspace_id=workspace_id)
    timings = PipelineTimings()
    errors: list[str] = []
    warnings: list[str] = []
    was_decrypted = False

    # -----------------------------------------------------------------------
    # Stage 0.5: Decryption attempt (if encrypted)
    # -----------------------------------------------------------------------
    archive_bytes, was_decrypted = _try_decrypt(archive_bytes, log)
    if was_decrypted:
        warnings.append("[decryption] Document was encrypted — decrypted with common password")

    # -----------------------------------------------------------------------
    # Stage 1: ZIP enumeration + disk write
    # -----------------------------------------------------------------------
    log.info("Stage 1: ZIP enumeration")
    raw_entry_map: dict[str, bytes] = {}
    zip_entry_records: list[ZipEntryRecord] = []

    with timings.stage("zip_enumeration"):
        for ze in iter_zip_entries(archive_bytes):
            if ze.error:
                errors.append(f"[zip] {ze.path}: {ze.error}")
                log.warning("ZIP read error: %s — %s", ze.path, ze.error)

            extracted_path = ""
            try:
                dest = ws_store.save_entry(workspace_id, ze.path, ze.raw_bytes)
                extracted_path = str(dest)
            except ValueError as exc:
                errors.append(f"[zipslip-blocked] {ze.path}: {exc}")
                log.warning("ZipSlip blocked: %s", ze.path)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"[save-error] {ze.path}: {exc}")
                log.error("Failed to save: %s — %s", ze.path, exc)

            raw_b64 = ""
            if len(ze.raw_bytes) <= BASE64_INLINE_THRESHOLD_BYTES:
                raw_b64 = base64.b64encode(ze.raw_bytes).decode("ascii")

            record = ZipEntryRecord(
                path=ze.path,
                compression_method=compression_name(ze.compression_method),
                compress_size=ze.compress_size,
                file_size=ze.file_size,
                crc32=ze.crc32,
                is_encrypted=ze.is_encrypted,
                sha256=ze.sha256,
                extracted_path=extracted_path,
                raw_bytes_base64=raw_b64,
                error=ze.error,
                extract_time_ms=0.0,  # individual timing is stage-level for now
            )
            zip_entry_records.append(record)
            raw_entry_map[ze.path] = ze.raw_bytes

    log.info("Stage 1 done: %d entries", len(zip_entry_records))

    # -----------------------------------------------------------------------
    # Stage 2: Content-type detection
    # -----------------------------------------------------------------------
    log.info("Stage 2: Content-type detection")
    with timings.stage("content_type_detection"):
        ct_raw = raw_entry_map.get("[Content_Types].xml", b"")
        ct_map = build_content_type_map(
            entries=[(p, b) for p, b in raw_entry_map.items()],
            content_types_xml=ct_raw or None,
        )
        errors.extend(ct_map.parse_errors)
        for record in zip_entry_records:
            record.content_type = ct_map.get(record.path, raw_entry_map.get(record.path, b""))

    # -----------------------------------------------------------------------
    # Stage 3: XML/text decoding (additive)
    # -----------------------------------------------------------------------
    log.info("Stage 3: XML decoding")
    decoded_text_map: dict[str, str] = {}

    with timings.stage("xml_parsing"):
        for record in zip_entry_records:
            raw = raw_entry_map.get(record.path, b"")
            if not raw:
                continue
            is_xml = is_xml_like(record.path, raw) or record.content_type in (
                "application/xml",
                "application/vnd.openxmlformats-package.relationships+xml",
                "text/xml", "text/plain",
            )
            if is_xml:
                try:
                    decode_result = decode_part(raw, force_xml_parse=True)
                    decoded_view = DecodedView(
                        decoded_text_utf8=decode_result.decoded_text_utf8,
                        decoded_text_utf16le=decode_result.decoded_text_utf16le,
                        parse_error=decode_result.parse_error,
                    )
                    if decode_result.xml_summary:
                        s = decode_result.xml_summary
                        decoded_view.xml_summary = XmlSummaryModel(
                            root_tag=s.root_tag,
                            namespaces=s.namespaces,
                            child_element_counts=s.child_element_counts,
                            total_elements=s.total_elements,
                        )
                    record.decoded = decoded_view
                    decoded_text_map[record.path] = decode_result.decoded_text_utf8
                    if decode_result.parse_error:
                        warnings.append(f"[xml-parse] {record.path}: {decode_result.parse_error}")
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"[xml-decode] {record.path}: {exc}")
                    log.error("XML decode failed: %s — %s", record.path, exc)

    # -----------------------------------------------------------------------
    # Stage 4: Binary classification (per entry)
    # -----------------------------------------------------------------------
    log.info("Stage 4: Binary classification")
    with timings.stage("binary_classification"):
        for record in zip_entry_records:
            raw = raw_entry_map.get(record.path, b"")
            try:
                cls_result, cls_ms = measure_ms(classify_binary, record.path, raw)
                # Build optional sub-objects
                mb = cls_result.magic_byte
                mg = cls_result.magika
                record.classification = ClassificationResult(
                    kind=cls_result.kind.value,
                    mime_guess=cls_result.mime_guess,
                    magic=cls_result.magic,
                    confidence=cls_result.confidence,
                    notes=cls_result.notes,
                    embedded_signatures=cls_result.embedded_signatures,
                    magic_byte=MagicByteResult(
                        mime_type=mb.mime_type,
                        magic_label=mb.magic_label,
                        confidence=mb.confidence,
                        embedded_mz=mb.embedded_mz,
                        notes=mb.notes,
                    ) if mb else None,
                    magika=MagikaResult(
                        label=mg.label,
                        group=mg.group,
                        mime_type=mg.mime_type,
                        description=mg.description,
                        score=mg.score,
                        is_text=mg.is_text,
                    ) if mg else None,
                )
                record.classify_time_ms = round(cls_ms, 3)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"[classify] {record.path}: {exc}")
                log.error("Classification failed: %s — %s", record.path, exc)

    # -----------------------------------------------------------------------
    # Stage 5: Structural role assignment
    # -----------------------------------------------------------------------
    log.info("Stage 5: Structural role assignment")
    with timings.stage("structure_enumeration"):
        role_map = enumerate_structure([r.path for r in zip_entry_records])
        for record in zip_entry_records:
            record.structural_role = role_map.get(record.path, "unknown").value

    # -----------------------------------------------------------------------
    # Stage 6: Relationship parsing
    # -----------------------------------------------------------------------
    log.info("Stage 6: Relationship parsing")
    rels_records_model: list[RelsFileRecord] = []
    all_urls: list[str] = []

    with timings.stage("relationship_parsing"):
        rels_raw_map = {p: b for p, b in raw_entry_map.items() if p.lower().endswith(".rels")}
        rels_extractor_results, all_urls = collect_all_rels(rels_raw_map)

        # Also extract URLs from decoded XML text
        _url_re = re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE)
        for text in decoded_text_map.values():
            for url in _url_re.findall(text):
                if url not in all_urls:
                    all_urls.append(url)
        all_urls = sorted(set(all_urls))

        # Split into external (analyst-relevant) and whitelisted (structural)
        external_urls, whitelisted_urls = filter_urls(all_urls)

        for rf in rels_extractor_results:
            rels_records_model.append(
                RelsFileRecord(
                    path=rf.path,
                    source_part=rf.source_part,
                    relationships=[
                        RelationshipRecord(
                            rel_id=r.rel_id, type=r.type, target=r.target,
                            target_mode=r.target_mode, is_external=r.is_external,
                            resolved_target=r.resolved_target, external_url=r.external_url,
                        ) for r in rf.relationships
                    ],
                    parse_error=rf.parse_error,
                )
            )

    # -----------------------------------------------------------------------
    # Stage 7: VBA macro extraction
    # -----------------------------------------------------------------------
    log.info("Stage 7: VBA macro extraction")
    macro_model = MacroExtractionResult()

    with timings.stage("macro_extraction"):
        try:
            macro_raw = extract_macros(raw_entry_map)
            macro_model = MacroExtractionResult(
                containers_found=macro_raw.containers_found,
                results=[
                    MacroContainerResult(
                        archive_path=r.archive_path,
                        modules=[
                            MacroModule(
                                module_name=m.module_name, code=m.code,
                                auto_exec_keywords=m.auto_exec_keywords,
                                suspicious_keywords=m.suspicious_keywords,
                            ) for m in r.modules
                        ],
                        extraction_log=r.extraction_log,
                        error=r.error,
                    ) for r in macro_raw.results
                ],
            )
            for r in macro_raw.results:
                if r.error:
                    warnings.append(f"[vba] {r.archive_path}: {r.error}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[macro-extraction]: {exc}")
            log.error("VBA extraction failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 8: XLM detection
    # -----------------------------------------------------------------------
    log.info("Stage 8: XLM detection")
    xlm_model = XlmFindings()

    with timings.stage("xlm_detection"):
        try:
            xlm_raw = extract_xlm(raw_entry_map)
            xlm_model = XlmFindings(
                macro_sheet_paths=xlm_raw.macro_sheet_paths,
                workbook_macro_sheet_names=xlm_raw.workbook_macro_sheet_names,
                sheets=[
                    XlmSheetResult(
                        sheet_name=s.sheet_name, archive_path=s.archive_path,
                        cells=[
                            XlmCell(ref=c.ref, formula=c.formula, value=c.value,
                                    suspicious_functions=c.suspicious_functions)
                            for c in s.cells
                        ],
                        all_suspicious_functions=s.all_suspicious_functions,
                        parse_error=s.parse_error,
                    ) for s in xlm_raw.sheets
                ],
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[xlm-detection]: {exc}")
            log.error("XLM detection failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 9: DDE detection
    # -----------------------------------------------------------------------
    log.info("Stage 9: DDE detection")
    dde_model: list[DdeFinding] = []

    with timings.stage("dde_detection"):
        try:
            dde_raw = scan_entries(decoded_text_map, xml_only=True)
            dde_model = [
                DdeFinding(file_path=f.file_path, snippet=f.snippet,
                           offset=f.offset, pattern_label=f.pattern_label)
                for f in dde_raw
            ]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[dde-detection]: {exc}")
            log.error("DDE detection failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 10: Embedded object enumeration
    # -----------------------------------------------------------------------
    log.info("Stage 10: Embedded object enumeration")
    embedded_model: list[EmbeddedObject] = []

    with timings.stage("embedded_object_extraction"):
        try:
            embedded_raw = extract_embedded_objects(raw_entry_map)
            embedded_model = [
                EmbeddedObject(
                    archive_path=o.archive_path, sha256=o.sha256, size=o.size,
                    detected_type=o.detected_type,
                    ole_streams=[
                        OleStreamInfo(name=s.name, size=s.size, is_storage=s.is_storage)
                        for s in o.ole_streams
                    ],
                    ole_error=o.ole_error, child_payload_path=o.child_payload_path,
                ) for o in embedded_raw
            ]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"[embedded-extraction]: {exc}")
            log.error("Embedded extraction failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 11: RTF content parsing
    # -----------------------------------------------------------------------
    log.info("Stage 11: RTF content parsing")
    rtf_findings_list: list[dict] = []

    with timings.stage("rtf_extraction"):
        try:
            rtf_findings_list = extract_rtf_findings(raw_entry_map)
        except Exception as exc:
            errors.append(f"[rtf-extraction]: {exc}")
            log.error("RTF extraction failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 12: HTML/SVG payload extraction
    # -----------------------------------------------------------------------
    log.info("Stage 12: HTML/SVG payload extraction")
    html_svg_findings: list[dict] = []

    with timings.stage("html_svg_extraction"):
        try:
            html_svg_findings = extract_html_svg(raw_entry_map, decoded_text_map)
        except Exception as exc:
            errors.append(f"[html-svg-extraction]: {exc}")
            log.error("HTML/SVG extraction failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 13: Media/font/metafile validation
    # -----------------------------------------------------------------------
    log.info("Stage 13: Media validation")
    media_issues: list[dict] = []

    with timings.stage("media_validation"):
        try:
            media_issues = validate_media_entries(raw_entry_map)
        except Exception as exc:
            errors.append(f"[media-validation]: {exc}")
            log.error("Media validation failed: %s", exc)

    # -----------------------------------------------------------------------
    # Stage 14: Content_Types.xml validation
    # -----------------------------------------------------------------------
    log.info("Stage 14: Content_Types validation")
    content_type_issues: list[dict] = []

    with timings.stage("content_type_validation"):
        try:
            content_type_issues = validate_content_types(decoded_text_map)
        except Exception as exc:
            errors.append(f"[content-type-validation]: {exc}")
            log.error("Content_Types validation failed: %s", exc)

    # -----------------------------------------------------------------------
    # Assemble manifest
    # -----------------------------------------------------------------------
    timings.finish()

    doc_type = _detect_doc_type(filename, list(raw_entry_map.keys()))

    # Extract document metadata (pages, slides, word count)
    doc_metadata = _extract_doc_metadata(decoded_text_map)

    file_meta = FileMetadata(
        filename=filename,
        size=len(archive_bytes),
        sha256=sha256_bytes(archive_bytes),
        detected_doc_type=doc_type,
        page_count=doc_metadata.get("page_count"),
        slide_count=doc_metadata.get("slide_count"),
        word_count=doc_metadata.get("word_count"),
    )

    summary = ManifestSummary(
        time_total_ms=round(timings.total_ms, 3),
        entry_count=len(zip_entry_records),
        macro_containers=len(macro_model.containers_found),
        dde_hits=len(dde_model),
        xlm_hits=len(xlm_model.sheets),
        xlm_sheets=len(xlm_model.macro_sheet_paths),
        external_url_count=len(external_urls),
        whitelisted_url_count=len(whitelisted_urls),
        embedded_object_count=len(embedded_model),
        error_count=len(errors),
    )

    timing_records = [
        StageTimingRecord(name=s["name"], time_ms=s["time_ms"])
        for s in timings.to_list()
    ]

    log.info(
        "Extraction complete: %d entries, %.1f ms",
        len(zip_entry_records), timings.total_ms,
    )

    return Manifest(
        workspace_id=workspace_id,
        status=ManifestStatus.done,
        file_metadata=file_meta,
        summary=summary,
        timings=timing_records,
        entries=zip_entry_records,
        rels_files=rels_records_model,
        urls=external_urls,
        whitelisted_urls=whitelisted_urls,
        macros=macro_model,
        dde_findings=dde_model,
        xlm_findings=xlm_model,
        embedded_objects=embedded_model,
        rtf_findings=rtf_findings_list,
        html_svg_findings=html_svg_findings,
        media_issues=media_issues,
        content_type_issues=content_type_issues,
        errors=errors,
        warnings=warnings,
    )
