/**
 * ClassificationBadge.jsx — colour-coded badge for BinaryKind taxonomy.
 *
 * Semantic colours:
 *   🔴 Red     — PE, VBA/OLE, macros, embedded objects
 *   🟡 Yellow  — scripts (JS, PS), RTF, XLM-adjacent
 *   🟢 Green   — images, media
 *   🔵 Blue    — XML, rels, settings, metadata, themes
 *   ⬜ Grey    — plain text, unknown, archives
 */

import { Chip, Tooltip } from '@mui/material';

const KIND_CONFIG = {
    // Red — high-risk
    pe_executable: { label: 'PE', color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
    vba_macro_container: { label: 'VBA', color: '#ef4444', bg: 'rgba(239,68,68,0.12)' },
    ole_compound_document: { label: 'OLE', color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
    office_embedded_object: { label: 'EMBEDDED', color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
    // Yellow — scripts / documents with macro risk
    rtf_document: { label: 'RTF', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    html_document: { label: 'HTML', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    javascript_code: { label: 'JS', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    powershell_script: { label: 'PS1', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    excel_binary_workbook: { label: 'XLSB', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    // Blue — document structure
    xml_document: { label: 'XML', color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' },
    rels_relationship: { label: 'RELS', color: '#a78bfa', bg: 'rgba(167,139,250,0.12)' },
    office_theme: { label: 'THEME', color: '#60a5fa', bg: 'rgba(96,165,250,0.08)' },
    office_custom_xml: { label: 'CX', color: '#60a5fa', bg: 'rgba(96,165,250,0.08)' },
    office_settings: { label: 'SETTINGS', color: '#60a5fa', bg: 'rgba(96,165,250,0.08)' },
    office_metadata: { label: 'META', color: '#60a5fa', bg: 'rgba(96,165,250,0.08)' },
    // Green — media
    image_png: { label: 'PNG', color: '#34d399', bg: 'rgba(52,211,153,0.1)' },
    image_jpeg: { label: 'JPEG', color: '#34d399', bg: 'rgba(52,211,153,0.1)' },
    image_gif: { label: 'GIF', color: '#34d399', bg: 'rgba(52,211,153,0.1)' },
    image_bmp: { label: 'BMP', color: '#34d399', bg: 'rgba(52,211,153,0.1)' },
    image_tiff: { label: 'TIFF', color: '#34d399', bg: 'rgba(52,211,153,0.1)' },
    office_media: { label: 'MEDIA', color: '#34d399', bg: 'rgba(52,211,153,0.1)' },
    // Archives
    zip_archive: { label: 'ZIP', color: '#00d4ff', bg: 'rgba(0,212,255,0.1)' },
    archive_7z: { label: '7Z', color: '#00d4ff', bg: 'rgba(0,212,255,0.1)' },
    archive_tar: { label: 'TAR', color: '#00d4ff', bg: 'rgba(0,212,255,0.1)' },
    // Security documents
    pdf_document: { label: 'PDF', color: '#fb923c', bg: 'rgba(251,146,60,0.12)' },
    // Gray — unknown / text
    text_plain: { label: 'TXT', color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' },
    binary_unknown: { label: 'BIN', color: '#64748b', bg: 'rgba(100,116,139,0.1)' },
    data_unknown: { label: '???', color: '#64748b', bg: 'rgba(100,116,139,0.1)' },
};

export default function ClassificationBadge({ kind, size = 'small', tooltip = true }) {
    if (!kind) return null;
    const cfg = KIND_CONFIG[kind] || { label: kind.toUpperCase().slice(0, 8), color: '#64748b', bg: 'rgba(100,116,139,0.1)' };

    const chip = (
        <Chip
            label={cfg.label}
            size={size}
            sx={{
                height: size === 'small' ? 18 : 22,
                fontSize: size === 'small' ? 10 : 12,
                fontWeight: 700,
                letterSpacing: '0.04em',
                background: cfg.bg,
                color: cfg.color,
                border: `1px solid ${cfg.color}30`,
                borderRadius: '4px',
                '& .MuiChip-label': { px: 0.75 },
                flexShrink: 0,
            }}
        />
    );

    return tooltip ? (
        <Tooltip title={kind} placement="right" enterDelay={400}>
            {chip}
        </Tooltip>
    ) : chip;
}
