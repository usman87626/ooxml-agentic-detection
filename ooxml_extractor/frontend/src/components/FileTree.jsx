import { useState, useMemo } from 'react';
import { Box, Typography, InputBase, Tooltip, Chip, IconButton, Select, MenuItem } from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import ClassificationBadge from './ClassificationBadge';

const KIND_ICONS = {
    xml_document: '📄', rels_relationship: '🔗', vba_macro_container: '⚠️',
    ole_compound_document: '📦', pe_executable: '💀', pdf_document: '📕',
    rtf_document: '📝', html_document: '🌐', javascript_code: '⚡',
    powershell_script: '⚡', text_plain: '📝', zip_archive: '🗜️',
    image_png: '🖼️', image_jpeg: '🖼️', image_gif: '🖼️', image_bmp: '🖼️',
    image_tiff: '🖼️', office_media: '🖼️', office_theme: '🎨',
    excel_binary_workbook: '📊', office_embedded_object: '📎',
    office_custom_xml: '📄', office_settings: '⚙️', office_metadata: 'ℹ️',
    archive_7z: '🗜️', archive_tar: '🗜️', binary_unknown: '❓', data_unknown: '❓',
};

const ROLE_COLOR = {
    document_part: '#60a5fa', relationship_file: '#a78bfa', macrosheet: '#f87171',
    vba_container: '#f87171', worksheet: '#34d399', slide: '#fb923c',
    theme: '#c084fc', settings: '#94a3b8', metadata: '#94a3b8',
    content_types: '#94a3b8', unknown: '#475569',
};

function basename(p) { return p.split('/').pop() || p; }
function dirname(p) { const parts = p.split('/'); parts.pop(); return parts.join('/'); }

function formatBytes(n) {
    if (!n) return '';
    if (n < 1024) return `${n}B`;
    if (n < 1048576) return `${(n / 1024).toFixed(0)}KB`;
    return `${(n / 1048576).toFixed(1)}MB`;
}

export default function FileTree({ entries = [], selected, onSelect, kindFilter, onKindFilterChange }) {
    const [query, setQuery] = useState('');

    // Build kind options with counts
    const kindCounts = useMemo(() => {
        const counts = {};
        entries.forEach(e => {
            const k = e.classification?.kind || 'data_unknown';
            counts[k] = (counts[k] || 0) + 1;
        });
        return counts;
    }, [entries]);

    // Filter entries
    const filtered = useMemo(() => {
        let out = entries;
        if (kindFilter) out = out.filter(e => (e.classification?.kind || 'data_unknown') === kindFilter);
        if (query) {
            const q = query.toLowerCase();
            out = out.filter(e => e.path.toLowerCase().includes(q));
        }
        return out;
    }, [entries, kindFilter, query]);

    // Group by directory for tree display
    const grouped = useMemo(() => {
        const dirs = {};
        filtered.forEach(e => {
            const dir = dirname(e.path) || '.';
            if (!dirs[dir]) dirs[dir] = [];
            dirs[dir].push(e);
        });
        return Object.entries(dirs).sort(([a], [b]) => a.localeCompare(b));
    }, [filtered]);

    const [collapsedDirs, setCollapsedDirs] = useState(new Set());
    const toggleDir = (dir) => setCollapsedDirs(prev => {
        const next = new Set(prev);
        next.has(dir) ? next.delete(dir) : next.add(dir);
        return next;
    });

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Search + Kind filter bar */}
            <Box sx={{ p: 1, borderBottom: '1px solid var(--border)', display: 'flex', gap: 0.75, flexDirection: 'column', flexShrink: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 1, px: 1, py: 0.4 }}>
                    <SearchIcon sx={{ fontSize: 13, color: 'var(--text-muted)', mr: 0.5 }} />
                    <InputBase
                        placeholder="Filter by path…"
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                        sx={{ flex: 1, fontSize: 12, color: 'text.primary', '& input::placeholder': { color: 'var(--text-muted)' } }}
                    />
                    {query && <IconButton size="small" sx={{ p: 0 }} onClick={() => setQuery('')}><ClearIcon sx={{ fontSize: 12 }} /></IconButton>}
                </Box>
                <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                    <Select value={kindFilter} onChange={e => onKindFilterChange(e.target.value)} displayEmpty size="small"
                        sx={{ fontSize: 11, height: 24, flex: 1, '.MuiSelect-select': { py: '2px', px: 1 }, background: 'var(--bg-primary)', border: '1px solid var(--border)' }}>
                        <MenuItem value="" sx={{ fontSize: 11 }}>All kinds ({entries.length})</MenuItem>
                        {Object.entries(kindCounts).sort(([, a], [, b]) => b - a).map(([kind, count]) => (
                            <MenuItem key={kind} value={kind} sx={{ fontSize: 11 }}>
                                {KIND_ICONS[kind] || '•'} {kind} ({count})
                            </MenuItem>
                        ))}
                    </Select>
                    {kindFilter && <IconButton size="small" sx={{ p: 0.2 }} onClick={() => onKindFilterChange('')}><ClearIcon sx={{ fontSize: 12 }} /></IconButton>}
                </Box>
                <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', px: 0.5 }}>
                    {filtered.length} of {entries.length} entries
                </Typography>
            </Box>

            {/* Tree */}
            <Box sx={{ flex: 1, overflow: 'auto' }}>
                {grouped.map(([dir, dirEntries]) => (
                    <Box key={dir}>
                        {/* Directory header */}
                        {dir !== '.' && (
                            <Box onClick={() => toggleDir(dir)} sx={{
                                display: 'flex', alignItems: 'center', gap: 0.5, px: 1, py: '3px',
                                cursor: 'pointer', userSelect: 'none',
                                '&:hover': { background: 'var(--bg-tertiary)' },
                            }}>
                                <Typography sx={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', mr: 0.25 }}>
                                    {collapsedDirs.has(dir) ? '▶' : '▼'}
                                </Typography>
                                <Typography sx={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {dir}/
                                </Typography>
                                <Typography sx={{ fontSize: 10, color: 'var(--text-muted)' }}>{dirEntries.length}</Typography>
                            </Box>
                        )}
                        {/* File rows */}
                        {!collapsedDirs.has(dir) && dirEntries.map(entry => {
                            const isSelected = entry.path === selected;
                            const kind = entry.classification?.kind || 'data_unknown';
                            const role = entry.structural_role || 'unknown';
                            const magika = entry.classification?.magika;

                            return (
                                <Tooltip key={entry.path}
                                    title={
                                        <Box sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', lineHeight: 1.7 }}>
                                            <div style={{ color: '#60a5fa', marginBottom: 4 }}>{entry.path}</div>
                                            <div>Kind: <b>{kind}</b></div>
                                            <div>Role: {role}</div>
                                            <div>Size: {entry.file_size?.toLocaleString()} bytes</div>
                                            <div>SHA256: {entry.sha256?.slice(0, 16)}…</div>
                                            {magika && <div>Magika: {magika.label} ({(magika.score * 100).toFixed(0)}%)</div>}
                                            {entry.is_encrypted && <div style={{ color: '#f87171' }}>⚠ Encrypted</div>}
                                            {entry.classification?.embedded_signatures?.length > 0 && (
                                                <div style={{ color: '#f87171' }}>⚠ {entry.classification.embedded_signatures.length} embedded sig(s)</div>
                                            )}
                                        </Box>
                                    }
                                    placement="right" enterDelay={400} arrow>
                                    <Box onClick={() => onSelect(entry.path)} sx={{
                                        display: 'flex', alignItems: 'center', gap: 0.75,
                                        px: dir === '.' ? 1 : 2, py: '3px', cursor: 'pointer',
                                        background: isSelected ? 'var(--accent-dim)' : 'transparent',
                                        borderLeft: isSelected ? '2px solid var(--accent)' : '2px solid transparent',
                                        '&:hover': { background: isSelected ? 'var(--accent-dim)' : 'var(--bg-tertiary)' },
                                        minHeight: 24,
                                    }}>
                                        {/* Kind icon */}
                                        <Typography sx={{ fontSize: 12, flexShrink: 0, lineHeight: 1 }}>{KIND_ICONS[kind] || '•'}</Typography>

                                        {/* Filename */}
                                        <Typography sx={{
                                            fontSize: 12, fontFamily: 'var(--font-mono)', flex: 1,
                                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                            color: isSelected ? 'var(--accent)' : kind === 'pe_executable' || kind === 'vba_macro_container' ? 'var(--danger)' : 'var(--text-primary)',
                                            fontWeight: (kind === 'pe_executable' || kind === 'vba_macro_container') ? 700 : 400,
                                        }}>
                                            {basename(entry.path)}
                                        </Typography>

                                        {/* Right side metadata */}
                                        <Box sx={{ display: 'flex', gap: 0.4, alignItems: 'center', flexShrink: 0 }}>
                                            {/* Structural role pill */}
                                            {role && role !== 'unknown' && (
                                                <Typography sx={{ fontSize: 9, color: ROLE_COLOR[role] || '#475569', fontFamily: 'var(--font-mono)', letterSpacing: '-0.01em' }}>
                                                    {role.replace(/_/g, '·')}
                                                </Typography>
                                            )}
                                            {/* File size */}
                                            {entry.file_size > 0 && (
                                                <Typography sx={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
                                                    {formatBytes(entry.file_size)}
                                                </Typography>
                                            )}
                                            {/* Threat indicators */}
                                            {entry.is_encrypted && <Typography sx={{ fontSize: 9, color: 'var(--danger)' }}>🔒</Typography>}
                                            {(entry.classification?.embedded_signatures?.length > 0 || entry.classification?.magic_byte?.embedded_mz?.length > 0) && (
                                                <Typography sx={{ fontSize: 9, color: 'var(--danger)' }} title="Embedded PE signature">⚠</Typography>
                                            )}
                                        </Box>
                                    </Box>
                                </Tooltip>
                            );
                        })}
                    </Box>
                ))}
                {filtered.length === 0 && (
                    <Box sx={{ p: 2, textAlign: 'center' }}>
                        <Typography variant="caption" color="text.secondary">No entries match</Typography>
                    </Box>
                )}
            </Box>
        </Box>
    );
}
