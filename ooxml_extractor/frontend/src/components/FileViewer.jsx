import { useState, useEffect } from 'react';
import { Box, Typography, Tabs, Tab, CircularProgress, Alert, Button, Tooltip, IconButton, Chip, LinearProgress } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import { getPreview, getFileDownloadUrl } from '../api/client';
import ClassificationBadge from './ClassificationBadge';

const PREVIEW_LIMIT = 200_000;

// ── Dual classification panel ─────────────────────────────────────────────
function ClassificationPanel({ cls }) {
    if (!cls) return null;

    const mb = cls.magic_byte;
    const mg = cls.magika;

    return (
        <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {/* Summary row */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                <ClassificationBadge kind={cls.kind} size="medium" tooltip={false} />
                <Typography sx={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {cls.mime_guess}
                </Typography>
                <Chip label={`${(cls.confidence * 100).toFixed(0)}% conf.`} size="small"
                    sx={{ fontSize: 10, height: 18, background: 'var(--bg-tertiary)', color: 'var(--text-muted)' }} />
            </Box>

            {/* Engine comparison table */}
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
                {/* Magic byte engine */}
                <Box sx={{ p: 1.5, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 1 }}>
                        <FingerprintIcon sx={{ fontSize: 14, color: '#60a5fa' }} />
                        <Typography sx={{ fontSize: 11, fontWeight: 700, color: '#60a5fa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            Magic Byte
                        </Typography>
                    </Box>
                    {mb ? (
                        <Box sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                            <div><span style={{ color: 'var(--text-muted)' }}>MIME: </span>{mb.mime_type || '—'}</div>
                            <div><span style={{ color: 'var(--text-muted)' }}>Magic: </span><span style={{ color: 'var(--accent)' }}>{mb.magic_label || '—'}</span></div>
                            <div><span style={{ color: 'var(--text-muted)' }}>Conf: </span>{(mb.confidence * 100).toFixed(0)}%</div>
                            {mb.embedded_mz?.length > 0 && (
                                <Box sx={{ mt: 0.5, p: 0.75, background: 'var(--danger-dim)', borderRadius: 0.5 }}>
                                    <span style={{ color: 'var(--danger)' }}>⚠ {mb.embedded_mz.length} embedded MZ</span>
                                    {mb.embedded_mz.slice(0, 3).map((sig, i) => (
                                        <div key={i} style={{ color: 'var(--text-muted)', paddingLeft: 8 }}>
                                            @ 0x{sig.offset?.toString(16)} — {sig.type} {sig.confirmed ? '✓' : '?'}
                                        </div>
                                    ))}
                                </Box>
                            )}
                            {mb.notes?.map((n, i) => (
                                <div key={i} style={{ color: 'var(--text-muted)', fontSize: 10 }}>{n}</div>
                            ))}
                        </Box>
                    ) : (
                        <Typography sx={{ fontSize: 11, color: 'var(--text-muted)' }}>No data</Typography>
                    )}
                </Box>

                {/* Magika engine */}
                <Box sx={{ p: 1.5, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1, position: 'relative' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 1 }}>
                        <AutoAwesomeIcon sx={{ fontSize: 14, color: '#a78bfa' }} />
                        <Typography sx={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            Magika ML
                        </Typography>
                    </Box>
                    {mg ? (
                        <Box sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                            <div><span style={{ color: 'var(--text-muted)' }}>Label: </span><span style={{ color: '#a78bfa', fontWeight: 600 }}>{mg.label || '—'}</span></div>
                            <div><span style={{ color: 'var(--text-muted)' }}>MIME: </span>{mg.mime_type || '—'}</div>
                            <div><span style={{ color: 'var(--text-muted)' }}>Group: </span>{mg.group || '—'}</div>
                            <div><span style={{ color: 'var(--text-muted)' }}>Desc: </span>{mg.description || '—'}</div>
                            <div><span style={{ color: 'var(--text-muted)' }}>Score: </span>
                                <span style={{ color: mg.score > 0.9 ? 'var(--success)' : mg.score > 0.6 ? 'var(--warning)' : 'var(--danger)' }}>
                                    {(mg.score * 100).toFixed(1)}%
                                </span>
                            </div>
                            {/* Score bar */}
                            <LinearProgress
                                variant="determinate"
                                value={mg.score * 100}
                                sx={{
                                    mt: 0.5, height: 3, borderRadius: 1,
                                    backgroundColor: 'var(--bg-primary)',
                                    '& .MuiLinearProgress-bar': {
                                        background: mg.score > 0.9 ? 'var(--success)' : mg.score > 0.6 ? 'var(--warning)' : 'var(--danger)',
                                    }
                                }}
                            />
                            {mg.is_text && <Chip label="text" size="small" sx={{ width: 'fit-content', fontSize: 9, height: 16 }} />}
                        </Box>
                    ) : (
                        <Typography sx={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            Not available{' '}
                            <Typography component="span" sx={{ fontSize: 10, color: 'var(--text-muted)' }}>
                                (pip install magika)
                            </Typography>
                        </Typography>
                    )}
                </Box>
            </Box>

            {/* Notes / embedded sigs */}
            {cls.notes?.length > 0 && (
                <Box sx={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {cls.notes.map((n, i) => <div key={i}>ℹ {n}</div>)}
                </Box>
            )}
        </Box>
    );
}

// ── Metadata panel ────────────────────────────────────────────────────────
function MetadataPanel({ entry }) {
    if (!entry) return null;
    const rows = [
        ['Path', entry.path],
        ['Size', `${entry.file_size?.toLocaleString()} bytes (compressed: ${entry.compress_size?.toLocaleString()})`],
        ['SHA-256', entry.sha256],
        ['CRC32', entry.crc32],
        ['Content Type', entry.content_type],
        ['Structural Role', entry.structural_role],
        ['Compression', entry.compression_method],
        ['Encrypted', entry.is_encrypted ? '⚠ Yes' : 'No'],
        ['Classify Time', entry.classify_time_ms ? `${entry.classify_time_ms} ms` : '—'],
        ['Error', entry.error || 'None'],
    ];
    return (
        <Box sx={{ p: 2, overflow: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <tbody>
                    {rows.map(([label, val]) => (
                        <tr key={label} style={{ borderBottom: '1px solid var(--border)' }}>
                            <td style={{ padding: '6px 12px 6px 0', color: 'var(--text-secondary)', fontSize: 12, whiteSpace: 'nowrap', width: 140, verticalAlign: 'top' }}>
                                {label}
                            </td>
                            <td style={{
                                padding: '6px 0', fontSize: 12, fontFamily: 'var(--font-mono)', wordBreak: 'break-all',
                                color: String(val).startsWith('⚠') ? 'var(--danger)' : 'var(--text-primary)'
                            }}>
                                {String(val)}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>

            {/* Dual Classification Panel */}
            <Box sx={{ mt: 2, borderTop: '1px solid var(--border)', pt: 2 }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: 'primary.main', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Binary Classification
                </Typography>
                <ClassificationPanel cls={entry.classification} />
            </Box>

            {/* XML Summary */}
            {entry.decoded?.xml_summary && (
                <Box sx={{ mt: 2, p: 1.5, background: 'var(--bg-tertiary)', borderRadius: 1, border: '1px solid var(--border)' }}>
                    <Typography variant="caption" sx={{ fontWeight: 700, color: 'primary.main', textTransform: 'uppercase', letterSpacing: '0.05em' }}>XML Summary</Typography>
                    <Box sx={{ mt: 0.5, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                        <div>Root: <span style={{ color: 'var(--accent)' }}>{entry.decoded.xml_summary.root_tag || 'unknown'}</span></div>
                        <div>Elements: {entry.decoded.xml_summary.total_elements?.toLocaleString()}</div>
                        {entry.decoded.xml_summary.namespaces?.length > 0 && (
                            <Box sx={{ mt: 0.5 }}>
                                <div style={{ color: 'var(--text-secondary)' }}>Namespaces:</div>
                                {entry.decoded.xml_summary.namespaces.slice(0, 8).map(ns => (
                                    <div key={ns} style={{ paddingLeft: 12, color: 'var(--text-muted)', fontSize: 11 }}>{ns}</div>
                                ))}
                            </Box>
                        )}
                    </Box>
                </Box>
            )}
        </Box>
    );
}

// ── Main FileViewer ───────────────────────────────────────────────────────
export default function FileViewer({ workspaceId, path, manifest }) {
    const [tab, setTab] = useState(0);
    const [preview, setPreview] = useState(null);
    const [previewLoading, setPreviewLoading] = useState(false);
    const [previewError, setPreviewError] = useState('');
    const [copied, setCopied] = useState(false);

    const entry = manifest?.entries?.find(e => e.path === path);

    useEffect(() => {
        let mounted = true;
        if (!path || !workspaceId) return;

        const loadPreview = async () => {
            if (tab === 0) {
                setPreviewLoading(true);
                setPreviewError('');
                setPreview(null);
                try {
                    const data = await getPreview(workspaceId, path);
                    if (mounted) setPreview(data);
                } catch (e) {
                    if (mounted) setPreviewError(e.response?.data?.detail || e.message);
                } finally {
                    if (mounted) setPreviewLoading(false);
                }
            } else {
                setPreview(null);
                setPreviewError('');
            }
        };

        loadPreview();
        return () => { mounted = false; };
    }, [path, workspaceId, tab]);

    const handleCopy = () => {
        const text = preview?.content || preview?.hex_dump || '';
        navigator.clipboard.writeText(text).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        });
    };

    if (!path) return (
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, flexDirection: 'column', gap: 1, color: 'var(--text-muted)' }}>
            <Typography variant="body2">Select a file from the tree to preview</Typography>
        </Box>
    );

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
            {/* Header */}
            <Box sx={{ display: 'flex', alignItems: 'center', px: 2, py: 1, borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0, gap: 1 }}>
                {entry?.classification?.kind && <ClassificationBadge kind={entry.classification.kind} size="small" />}
                <Typography sx={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {path}
                </Typography>
                {entry?.classification?.magika && (
                    <Tooltip title={`Magika: ${entry.classification.magika.label} (${(entry.classification.magika.score * 100).toFixed(0)}%)`}>
                        <Chip
                            icon={<AutoAwesomeIcon sx={{ fontSize: 11 }} />}
                            label={`${entry.classification.magika.label} · ${(entry.classification.magika.score * 100).toFixed(0)}%`}
                            size="small"
                            sx={{ fontSize: 10, height: 20, background: 'rgba(167,139,250,0.12)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.2)', cursor: 'default' }}
                        />
                    </Tooltip>
                )}
                <Tooltip title={copied ? 'Copied!' : 'Copy content'}>
                    <IconButton size="small" onClick={handleCopy} sx={{ color: 'text.secondary' }}>
                        <ContentCopyIcon fontSize="small" />
                    </IconButton>
                </Tooltip>
                <Tooltip title="Download raw file">
                    <IconButton size="small" component="a" href={getFileDownloadUrl(workspaceId, path)} download sx={{ color: 'text.secondary' }}>
                        <DownloadIcon fontSize="small" />
                    </IconButton>
                </Tooltip>
            </Box>

            {/* Tabs */}
            <Tabs value={tab} onChange={(_, v) => setTab(v)}
                sx={{ borderBottom: '1px solid var(--border)', minHeight: 36, flexShrink: 0, background: 'var(--bg-secondary)', px: 1 }}
                TabIndicatorProps={{ style: { background: 'var(--accent)' } }}
            >
                <Tab label="Preview" sx={{ minHeight: 36, fontSize: 12, py: 0 }} />
                <Tab label="Raw / Hex" sx={{ minHeight: 36, fontSize: 12, py: 0 }} />
                <Tab label="Metadata + Classification" sx={{ minHeight: 36, fontSize: 12, py: 0 }} />
            </Tabs>

            {/* Content */}
            <Box sx={{ flex: 1, overflow: 'auto', background: 'var(--bg-primary)' }}>
                {tab === 0 && (() => {
                    // --- Image detection ---
                    const IMAGE_KINDS = new Set(['image_png', 'image_jpeg', 'image_gif', 'image_bmp', 'image_tiff', 'office_media']);
                    const IMAGE_EXTS = new Set(['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'tif', 'webp', 'svg']);
                    const ext = path?.split('.').pop()?.toLowerCase() || '';
                    const kind = entry?.classification?.kind || '';
                    const isImage = IMAGE_KINDS.has(kind) || IMAGE_EXTS.has(ext);
                    const imgUrl = getFileDownloadUrl(workspaceId, path);

                    if (isImage) {
                        return (
                            <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                                <Box sx={{
                                    background: 'repeating-conic-gradient(#1a2332 0% 25%, #151e2d 0% 50%) 0 0 / 20px 20px',
                                    border: '1px solid var(--border)', borderRadius: 2, overflow: 'hidden',
                                    maxWidth: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    p: 1, minHeight: 120,
                                }}>
                                    <img
                                        src={imgUrl}
                                        alt={path}
                                        onError={(e) => {
                                            e.target.style.display = 'none';
                                            e.target.nextElementSibling.style.display = 'block';
                                        }}
                                        style={{ maxWidth: '100%', maxHeight: '60vh', objectFit: 'contain', display: 'block', borderRadius: 4 }}
                                    />
                                    <Typography sx={{ display: 'none', color: 'var(--text-muted)', fontSize: 13, p: 2 }}>
                                        Cannot render (binary/unsupported format) — use Download below
                                    </Typography>
                                </Box>
                                <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
                                    <Chip label={ext.toUpperCase() || 'IMG'} size="small"
                                        sx={{ fontSize: 11, background: 'rgba(52,211,153,0.1)', color: 'var(--success)', border: '1px solid rgba(52,211,153,0.2)' }} />
                                    {entry?.file_size > 0 && (
                                        <Typography variant="caption" color="text.secondary">
                                            {(entry.file_size / 1024).toFixed(1)} KB
                                        </Typography>
                                    )}
                                    <Button size="small" component="a" href={imgUrl} download
                                        startIcon={<DownloadIcon sx={{ fontSize: 14 }} />} sx={{ fontSize: 12 }}>
                                        Download
                                    </Button>
                                </Box>
                            </Box>
                        );
                    }

                    return (
                        <Box>
                            {previewLoading && <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress size={24} /></Box>}
                            {previewError && <Alert severity="error" sx={{ m: 2 }}>{previewError}</Alert>}
                            {preview?.type === 'text' && (
                                <>
                                    {preview.parse_error && <Alert severity="warning" sx={{ mx: 2, mt: 2, fontSize: 12 }}>{preview.parse_error}</Alert>}
                                    <pre style={{ margin: 0, padding: '16px', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6 }}>
                                        {(preview.content || '').slice(0, PREVIEW_LIMIT)}
                                        {preview.content?.length > PREVIEW_LIMIT && <span style={{ color: 'var(--text-muted)' }}>\n\n[Truncated — {preview.content.length.toLocaleString()} chars. Download for full.]</span>}
                                    </pre>
                                </>
                            )}
                            {preview?.type === 'binary' && (
                                <Box sx={{ p: 2 }}>
                                    <Alert severity="info" sx={{ mb: 2, fontSize: 12 }}>Binary ({preview.size?.toLocaleString()} bytes). Showing hex dump of first 1 KB.</Alert>
                                    <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, border: '1px solid var(--border)', overflowX: 'auto' }}>
                                        {preview.hex_dump}
                                    </pre>
                                </Box>
                            )}
                        </Box>
                    );
                })()}


                {tab === 1 && (
                    <Box sx={{ p: 2 }}>
                        {entry?.raw_bytes_base64 ? (
                            <>
                                <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>Base64 encoded raw bytes</Typography>
                                <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, border: '1px solid var(--border)', overflowX: 'auto', marginTop: 8, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                    {entry.raw_bytes_base64}
                                </pre>
                            </>
                        ) : (
                            <Alert severity="info">File exceeds inline limit. <Button size="small" component="a" href={getFileDownloadUrl(workspaceId, path)} download>Download raw bytes</Button></Alert>
                        )}
                    </Box>
                )}

                {tab === 2 && <MetadataPanel entry={entry} />}
            </Box>
        </Box>
    );
}
