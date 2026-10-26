"""
structure_enumerator.py — OOXML structural role assignment.

Maps every archive entry path to a human-readable structural role.
Used by the manifest builder to annotate entries with their place in
the OOXML document model.
"""

from __future__ import annotations

from enum import Enum
from pathlib import PurePosixPath
from typing import Optional


class OoxmlRole(str, Enum):
    """Structural role of an OOXML archive entry."""
    content_types     = "content_types"      # [Content_Types].xml
    relationships     = "relationships"      # _rels/*.rels
    document_part     = "document_part"      # primary document body
    stylesheet        = "stylesheet"         # styles, numbering, fonts
    theme             = "theme"              # Office themes
    settings          = "settings"           # document/workbook settings
    shared_strings    = "shared_strings"     # xl/sharedStrings.xml
    worksheet         = "worksheet"          # xl/worksheets/*
    macrosheet        = "macrosheet"         # xl/macrosheets/*
    chartsheet        = "chartsheet"         # xl/chartsheets/*
    slide             = "slide"              # ppt/slides/*
    slide_layout      = "slide_layout"       # ppt/slideLayouts/*
    slide_master      = "slide_master"       # ppt/slideMasters/*
    media             = "media"              # images/audio/video
    embedded_object   = "embedded_object"    # OLE/embedded binaries
    macro_container   = "macro_container"    # vbaProject.bin
    custom_xml        = "custom_xml"         # customXml/*
    metadata          = "metadata"           # docProps/core.xml app.xml
    drawing           = "drawing"            # xl/drawings/, word/drawings/
    chart             = "chart"              # xl/charts/
    external_link     = "external_link"      # xl/externalLinks/
    footer_header     = "footer_header"      # word/headers/ word/footers/
    comment           = "comment"            # word/comments.xml
    revision          = "revision"           # word/revisions
    diagram           = "diagram"            # diagrams
    vml               = "vml"               # VML drawings
    unknown           = "unknown"


# ---------------------------------------------------------------------------
# Path-to-role mapping rules (checked in order; first match wins)
# ---------------------------------------------------------------------------

_RULES: list[tuple] = [
    # (match_fn: path_str → bool, role)
    (lambda p: p == "[content_types].xml",        OoxmlRole.content_types),
    (lambda p: p.endswith(".rels"),               OoxmlRole.relationships),
    (lambda p: "vbaproject.bin" in p,             OoxmlRole.macro_container),
    (lambda p: p.startswith("docprops/"),         OoxmlRole.metadata),
    (lambda p: "/customxml/" in p or p.startswith("customxml/"), OoxmlRole.custom_xml),
    (lambda p: "/theme/" in p,                    OoxmlRole.theme),
    (lambda p: p in ("word/styles.xml", "word/styleswithtypes.xml",
                     "word/numbering.xml", "word/fonts.xml"),   OoxmlRole.stylesheet),
    (lambda p: p in ("word/settings.xml", "word/websettings.xml",
                     "xl/workbook.xml", "xl/settings.xml",
                     "ppt/presProps.xml", "ppt/presentation.xml"),  OoxmlRole.settings),
    (lambda p: "xl/sharedstrings.xml" in p,       OoxmlRole.shared_strings),
    (lambda p: p.startswith("xl/macrosheets/"),   OoxmlRole.macrosheet),
    (lambda p: p.startswith("xl/worksheets/"),    OoxmlRole.worksheet),
    (lambda p: p.startswith("xl/chartsheets/"),   OoxmlRole.chartsheet),
    (lambda p: p.startswith("xl/charts/"),        OoxmlRole.chart),
    (lambda p: p.startswith("xl/externall"),      OoxmlRole.external_link),
    (lambda p: p.startswith("xl/drawings/") or
               p.startswith("word/drawings/") or
               p.startswith("ppt/drawings/"),     OoxmlRole.drawing),
    (lambda p: p.startswith("ppt/slides/") and "layout" not in p and "master" not in p, OoxmlRole.slide),
    (lambda p: p.startswith("ppt/slidelayouts/"), OoxmlRole.slide_layout),
    (lambda p: p.startswith("ppt/slidemasters/"), OoxmlRole.slide_master),
    (lambda p: "word/document.xml" in p or
               "word/document2.xml" in p,         OoxmlRole.document_part),
    (lambda p: p.startswith("word/headers/") or
               p.startswith("word/footers/"),     OoxmlRole.footer_header),
    (lambda p: "word/comments" in p,              OoxmlRole.comment),
    (lambda p: "word/revisions" in p or "word/tracked" in p, OoxmlRole.revision),
    (lambda p: "/media/" in p or "/images/" in p, OoxmlRole.media),
    (lambda p: "/embeddings/" in p,               OoxmlRole.embedded_object),
    (lambda p: p.endswith(".vml") or "/vml/" in p, OoxmlRole.vml),
    (lambda p: "diagram" in p,                    OoxmlRole.diagram),
]


def assign_role(path: str) -> OoxmlRole:
    """Return the OOXML structural role for a single archive entry *path*."""
    p = path.lower().lstrip("/")
    for match_fn, role in _RULES:
        try:
            if match_fn(p):
                return role
        except Exception:  # noqa: BLE001
            continue
    return OoxmlRole.unknown


def enumerate_structure(paths: list[str]) -> dict[str, OoxmlRole]:
    """
    Assign a structural role to every path in *paths*.

    Returns a dict mapping archive path → OoxmlRole.
    """
    return {path: assign_role(path) for path in paths}


def role_display_name(role: OoxmlRole) -> str:
    """Return a user-friendly display name for a role."""
    return role.value.replace("_", " ").title()
