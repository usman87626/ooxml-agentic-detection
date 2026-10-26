import { useState } from 'react';
import {
    Box, Typography, Tabs, Tab, Chip, Divider,
    Table, TableBody, TableCell, TableHead, TableRow,
    Switch, FormControlLabel, Tooltip, IconButton, Alert
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import DownloadIcon from '@mui/icons-material/Download';
import { getFileDownloadUrl } from '../api/client';

// ─── Relationships table ────────────────────────────────────────────────
function RelationshipsTab({ manifest }) {
    const [externalOnly, setExternalOnly] = useState(false);
    const allRels = (manifest?.rels_files || []).flatMap(rf =>
        rf.relationships.map(r => ({ ...r, from: rf.path }))
    );
    const visible = externalOnly ? allRels.filter(r => r.is_external) : allRels;

    return (
        <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5, px: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary', flex: 1 }}>
                    {visible.length} / {allRels.length} relationships
                </Typography>
                <FormControlLabel
                    label={<Typography variant="caption">External only</Typography>}
                    control={<Switch size="small" checked={externalOnly} onChange={e => setExternalOnly(e.target.checked)} />}
                    sx={{ m: 0 }}
                />
            </Box>
            {visible.length === 0
                ? <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>None</Typography>
                : (
                    <Box sx={{ overflow: 'auto', maxHeight: 'calc(100vh - 250px)' }}>
                        {visible.map((r, i) => (
                            <Box key={i} sx={{ px: 1, py: 0.75, borderBottom: '1px solid var(--border)', '&:hover': { background: 'rgba(255,255,255,0.02)' } }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.25 }}>
                                    {r.is_external && <Chip label="EXT" size="small" sx={{ height: 16, fontSize: 10, background: 'var(--danger-dim)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }} />}
                                    <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {r.rel_id}
                                    </Typography>
                                </Box>
                                <Typography sx={{ fontSize: 11, color: 'var(--text-secondary)', mb: 0.25 }}>
                                    {r.type?.split('/').pop()}
                                </Typography>
                                <CopyableText text={r.target} />
                            </Box>
                        ))}
                    </Box>
                )
            }
        </Box>
    );
}

// ─── URLs list ──────────────────────────────────────────────────────────
function UrlsTab({ manifest }) {
    const urls = manifest?.urls || [];
    if (!urls.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No external URLs found</Typography>;
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary', px: 1, display: 'block', mb: 1 }}>
                {urls.length} URLs
            </Typography>
            {urls.map((url, i) => (
                <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 0.5, px: 1, py: 0.5, borderBottom: '1px solid var(--border)', '&:hover': { background: 'rgba(255,255,255,0.02)' } }}>
                    <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {url}
                    </Typography>
                    <Tooltip title="Copy URL"><IconButton size="small" onClick={() => navigator.clipboard.writeText(url)} sx={{ p: 0.25 }}><ContentCopyIcon sx={{ fontSize: 13 }} /></IconButton></Tooltip>
                    <Tooltip title="Open (use caution)"><IconButton size="small" component="a" href={url} target="_blank" rel="noopener noreferrer" sx={{ p: 0.25, color: 'text.secondary' }}><OpenInNewIcon sx={{ fontSize: 13 }} /></IconButton></Tooltip>
                </Box>
            ))}
        </Box>
    );
}

// ─── VBA Macros ─────────────────────────────────────────────────────────
function MacrosTab({ manifest }) {
    const [selectedContainer, setSelectedContainer] = useState(0);
    const containers = manifest?.macros?.results || [];
    if (!containers.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No VBA macros found</Typography>;

    const container = containers[selectedContainer];

    return (
        <Box>
            {containers.length > 1 && (
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', px: 1, mb: 1 }}>
                    {containers.map((c, i) => (
                        <Chip key={i} label={c.archive_path.split('/').pop()} size="small" clickable
                            sx={{ fontSize: 11, height: 20, background: i === selectedContainer ? 'var(--accent-dim)' : 'var(--bg-tertiary)', color: i === selectedContainer ? 'var(--accent)' : 'var(--text-secondary)', border: `1px solid ${i === selectedContainer ? 'var(--accent)' : 'var(--border)'}` }}
                            onClick={() => setSelectedContainer(i)}
                        />
                    ))}
                </Box>
            )}
            {container?.is_vba_locked && (
                <Alert severity="warning" sx={{ mx: 1, mb: 1, fontSize: 11, py: 0.25 }}>
                    🔒 VBA project is password-protected (encrypted). Code may be hidden.
                </Alert>
            )}
            {container?.error && <Alert severity="warning" sx={{ mx: 1, mb: 1, fontSize: 11 }}>{container.error}</Alert>}
            {(container?.modules || []).map((mod, i) => (
                <Box key={i} sx={{ mb: 1.5, border: '1px solid var(--border)', borderRadius: 1, overflow: 'hidden' }}>
                    <Box sx={{ px: 1.5, py: 0.75, background: 'var(--bg-tertiary)', display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography sx={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{mod.module_name}</Typography>
                        {mod.auto_exec_keywords?.map(k => <Chip key={k} label={k} size="small" sx={{ height: 16, fontSize: 10, background: 'var(--danger-dim)', color: 'var(--danger)' }} />)}
                        {mod.suspicious_keywords?.slice(0, 3).map(k => <Chip key={k} label={k} size="small" sx={{ height: 16, fontSize: 10, background: 'rgba(245,158,11,0.12)', color: 'var(--warning)' }} />)}
                    </Box>
                    <pre style={{ margin: 0, padding: '8px 12px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', background: 'var(--bg-primary)', overflowX: 'auto', maxHeight: 200 }}>
                        {mod.code || '(empty)'}
                    </pre>
                </Box>
            ))}
        </Box>
    );
}

// ─── DDE Findings ──────────────────────────────────────────────────────
function DdeTab({ manifest }) {
    const findings = manifest?.dde_findings || [];
    if (!findings.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No DDE patterns detected</Typography>;
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'var(--danger)', px: 1, display: 'block', mb: 1 }}>{findings.length} DDE finding{findings.length !== 1 ? 's' : ''}</Typography>
            {findings.map((f, i) => (
                <Box key={i} sx={{ px: 1, py: 1, mb: 1, background: 'var(--danger-dim)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 1 }}>
                    <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', mb: 0.5 }}>{f.file_path}</Typography>
                    <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--danger)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{f.snippet}</Typography>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', mt: 0.5 }}>offset: {f.offset}</Typography>
                </Box>
            ))}
        </Box>
    );
}

// ─── XLM Findings ──────────────────────────────────────────────────────
function XlmTab({ manifest }) {
    const xlm = manifest?.xlm_findings;
    const sheets = xlm?.sheets || [];
    if (!sheets.length && !xlm?.macro_sheet_paths?.length) {
        return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No XLM macro sheets detected</Typography>;
    }
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'var(--warning)', px: 1, display: 'block', mb: 1 }}>{xlm?.macro_sheet_paths?.length} macro sheet path(s)</Typography>
            {sheets.map((sheet, i) => (
                <Box key={i} sx={{ mb: 1.5, border: '1px solid var(--border)', borderRadius: 1, overflow: 'hidden' }}>
                    <Box sx={{ px: 1.5, py: 0.75, background: 'var(--bg-tertiary)', display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                        <Typography sx={{ fontSize: 12, fontWeight: 700, color: 'var(--warning)' }}>{sheet.sheet_name}</Typography>
                        {sheet.all_suspicious_functions?.map(fn => (
                            <Chip key={fn} label={fn} size="small" sx={{ height: 16, fontSize: 10, background: 'rgba(245,158,11,0.12)', color: 'var(--warning)', border: '1px solid rgba(245,158,11,0.25)' }} />
                        ))}
                    </Box>
                    <Box sx={{ maxHeight: 150, overflow: 'auto' }}>
                        {sheet.cells?.slice(0, 50).map((cell, j) => (
                            <Box key={j} sx={{ display: 'flex', gap: 1, px: 1.5, py: 0.4, borderBottom: '1px solid var(--border)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                                <span style={{ color: 'var(--accent)', width: 40, flexShrink: 0 }}>{cell.ref}</span>
                                <span style={{ color: cell.suspicious_functions?.length ? 'var(--warning)' : 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {cell.formula || cell.value}
                                </span>
                            </Box>
                        ))}
                    </Box>
                </Box>
            ))}
        </Box>
    );
}

// ─── Embedded Objects ───────────────────────────────────────────────────
function EmbeddedObjectCard({ obj, workspaceId }) {
    const [expanded, setExpanded] = useState(false);
    const [preview, setPreview] = useState(null);
    const [loadingPreview, setLoadingPreview] = useState(false);

    const dtype = obj.detected_type || 'unknown';
    const isDangerous = /PE|executable|script|powershell|hta|rtf/i.test(dtype);
    const isOLE = /OLE|Compound/i.test(dtype);
    const riskColor = isDangerous ? 'var(--danger)' : isOLE ? 'var(--warning)' : 'var(--text-secondary)';
    const riskBg = isDangerous ? 'var(--danger-dim)' : isOLE ? 'rgba(245,158,11,0.12)' : 'rgba(148,163,184,0.1)';

    const handleExpand = async () => {
        setExpanded(e => !e);
        if (!preview && !loadingPreview) {
            setLoadingPreview(true);
            try {
                const { getPreview } = await import('../api/client');
                const data = await getPreview(workspaceId, obj.archive_path);
                setPreview(data);
            } catch {
                setPreview({ error: 'Preview not available' });
            } finally {
                setLoadingPreview(false);
            }
        }
    };

    return (
        <Box sx={{
            mb: 1, border: `1px solid ${isDangerous ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
            borderRadius: 1, overflow: 'hidden',
            background: isDangerous ? 'rgba(239,68,68,0.03)' : 'var(--bg-tertiary)',
        }}>
            {/* Header — always visible */}
            <Box onClick={handleExpand} sx={{
                display: 'flex', alignItems: 'center', gap: 0.75, px: 1, py: 0.75,
                cursor: 'pointer', '&:hover': { background: 'rgba(255,255,255,0.02)' },
            }}>
                <Typography sx={{ fontSize: 13, color: 'var(--text-muted)', flexShrink: 0 }}>
                    {expanded ? '▾' : '▸'}
                </Typography>
                <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {obj.archive_path?.split('/').pop() || obj.archive_path}
                </Typography>
                <Chip label={dtype} size="small" sx={{
                    height: 18, fontSize: 9, background: riskBg, color: riskColor,
                    border: `1px solid ${isDangerous ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`, maxWidth: 140,
                    flexShrink: 0,
                }} />
                <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
                    {obj.size ? (obj.size < 1024 ? `${obj.size} B` : `${(obj.size / 1024).toFixed(1)} KB`) : ''}
                </Typography>
                <Tooltip title="Download">
                    <IconButton size="small" component="a" href={getFileDownloadUrl(workspaceId, obj.archive_path)}
                        download onClick={e => e.stopPropagation()}
                        sx={{ p: 0.25, color: 'text.secondary' }}>
                        <DownloadIcon sx={{ fontSize: 13 }} />
                    </IconButton>
                </Tooltip>
            </Box>

            {/* Expanded details */}
            {expanded && (
                <Box sx={{ px: 1, pb: 1, borderTop: '1px solid var(--border)' }}>
                    {/* Path + SHA */}
                    <Typography sx={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', mt: 0.75, mb: 0.25 }}>
                        Path: {obj.archive_path}
                    </Typography>
                    {obj.sha256 && (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                            <Typography sx={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                                SHA-256: {obj.sha256}
                            </Typography>
                            <IconButton size="small" onClick={() => navigator.clipboard.writeText(obj.sha256)} sx={{ p: 0.15, opacity: 0.5, '&:hover': { opacity: 1 } }}>
                                <ContentCopyIcon sx={{ fontSize: 10 }} />
                            </IconButton>
                        </Box>
                    )}

                    {/* CLSIDs if present */}
                    {obj.clsids?.length > 0 && (
                        <Box sx={{ mb: 0.5 }}>
                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 700 }}>CLSIDs:</Typography>
                            {obj.clsids.map((c, j) => (
                                <Chip key={j} label={c} size="small" sx={{ height: 16, fontSize: 9, mr: 0.5, mb: 0.25, fontFamily: 'var(--font-mono)', background: 'rgba(148,163,184,0.08)', color: 'var(--text-muted)' }} />
                            ))}
                        </Box>
                    )}

                    {/* OLE Streams — visual tree */}
                    {obj.ole_streams?.length > 0 && (
                        <Box sx={{ mb: 0.75, p: 0.75, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 1 }}>
                            <Typography sx={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', mb: 0.5 }}>
                                OLE Streams ({obj.ole_streams.length})
                            </Typography>
                            {obj.ole_streams.map((s, j) => {
                                const streamDanger = /Macros|VBA|PowerShell|_VBA_PROJECT/i.test(s.name);
                                return (
                                    <Box key={j} sx={{ display: 'flex', alignItems: 'center', gap: 0.5, py: 0.2, pl: s.is_storage ? 0 : 1.5 }}>
                                        <Typography sx={{ fontSize: 11 }}>{s.is_storage ? '📁' : '📄'}</Typography>
                                        <Typography sx={{
                                            fontSize: 10, fontFamily: 'var(--font-mono)', flex: 1,
                                            color: streamDanger ? 'var(--warning)' : 'var(--text-muted)',
                                            fontWeight: streamDanger ? 700 : 400,
                                        }}>
                                            {s.name}
                                        </Typography>
                                        <Typography sx={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', flexShrink: 0 }}>
                                            {s.size < 1024 ? `${s.size} B` : `${(s.size / 1024).toFixed(1)} KB`}
                                        </Typography>
                                    </Box>
                                );
                            })}
                        </Box>
                    )}

                    {/* Hex preview */}
                    {loadingPreview && (
                        <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center', py: 1 }}>Loading preview…</Typography>
                    )}
                    {preview && !preview.error && preview.type === 'binary' && (
                        <Box sx={{ mt: 0.5 }}>
                            <Typography sx={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', mb: 0.5 }}>
                                Hex Preview (first {Math.min(preview.size || 0, 1024)} bytes of {preview.size?.toLocaleString()})
                            </Typography>
                            <pre style={{
                                margin: 0, padding: '8px 10px', fontSize: 10, fontFamily: 'var(--font-mono)',
                                color: 'var(--accent)', background: 'var(--bg-primary)',
                                border: '1px solid var(--border)', borderRadius: 4,
                                maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                lineHeight: 1.6,
                            }}>
                                {preview.hex_dump}
                            </pre>
                        </Box>
                    )}
                    {preview && !preview.error && preview.type === 'text' && (
                        <Box sx={{ mt: 0.5 }}>
                            <Typography sx={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', mb: 0.5 }}>Content Preview</Typography>
                            <pre style={{
                                margin: 0, padding: '8px 10px', fontSize: 10, fontFamily: 'var(--font-mono)',
                                color: 'var(--text-secondary)', background: 'var(--bg-primary)',
                                border: '1px solid var(--border)', borderRadius: 4,
                                maxHeight: 200, overflow: 'auto', whiteSpace: 'pre-wrap',
                            }}>
                                {preview.content?.slice(0, 2000)}
                            </pre>
                        </Box>
                    )}
                    {preview?.error && (
                        <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic', mt: 0.5 }}>{preview.error}</Typography>
                    )}
                </Box>
            )}
        </Box>
    );
}

function EmbeddedTab({ manifest, workspaceId }) {
    const objects = manifest?.embedded_objects || [];
    if (!objects.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No embedded objects found</Typography>;

    const dangerCount = objects.filter(o => /PE|executable|script|powershell|hta|rtf/i.test(o.detected_type || '')).length;

    return (
        <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, px: 1, mb: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: 'text.secondary' }}>
                    {objects.length} embedded object{objects.length !== 1 ? 's' : ''}
                </Typography>
                {dangerCount > 0 && (
                    <Chip label={`${dangerCount} high-risk`} size="small" sx={{ height: 16, fontSize: 9, background: 'var(--danger-dim)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }} />
                )}
                <Typography variant="caption" sx={{ fontSize: 10, color: 'var(--text-muted)', ml: 'auto' }}>Click to expand</Typography>
            </Box>
            {objects.map((obj, i) => (
                <EmbeddedObjectCard key={i} obj={obj} workspaceId={workspaceId} />
            ))}
        </Box>
    );
}

// ─── RTF Findings ───────────────────────────────────────────────────────
function RtfTab({ manifest }) {
    const findings = manifest?.rtf_findings || [];
    if (!findings.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No RTF content detected</Typography>;
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'var(--danger)', px: 1, display: 'block', mb: 1 }}>
                {findings.length} RTF finding{findings.length !== 1 ? 's' : ''}
            </Typography>
            {findings.map((f, i) => (
                <Box key={i} sx={{ px: 1, py: 1, mb: 1, background: f.has_equation_editor ? 'var(--danger-dim)' : 'var(--bg-tertiary)', border: `1px solid ${f.has_equation_editor ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`, borderRadius: 1 }}>
                    <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', mb: 0.5 }}>{f.path || f.archive_path}</Typography>
                    {f.has_equation_editor && (
                        <Chip label="⚠ Equation Editor (CVE-2017-11882)" size="small" sx={{ height: 18, fontSize: 10, mb: 0.5, background: 'var(--danger-dim)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }} />
                    )}
                    {f.ole_objects_count > 0 && (
                        <Typography sx={{ fontSize: 10, color: 'var(--text-muted)' }}>OLE objects: {f.ole_objects_count}</Typography>
                    )}
                    {f.has_pe_payload && (
                        <Chip label="PE Payload Detected" size="small" sx={{ height: 16, fontSize: 10, mt: 0.5, background: 'var(--danger-dim)', color: 'var(--danger)' }} />
                    )}
                    {f.object_classes?.length > 0 && (
                        <Box sx={{ mt: 0.5 }}>
                            {f.object_classes.map((cls, j) => (
                                <Chip key={j} label={cls} size="small" sx={{ height: 16, fontSize: 9, mr: 0.5, mb: 0.25, background: 'rgba(148,163,184,0.1)', color: 'var(--text-secondary)' }} />
                            ))}
                        </Box>
                    )}
                </Box>
            ))}
        </Box>
    );
}

// ─── HTML/SVG Findings ──────────────────────────────────────────────────
function HtmlSvgTab({ manifest }) {
    const findings = manifest?.html_svg_findings || [];
    if (!findings.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No HTML/SVG payloads detected</Typography>;
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'var(--warning)', px: 1, display: 'block', mb: 1 }}>
                {findings.length} HTML/SVG finding{findings.length !== 1 ? 's' : ''}
            </Typography>
            {findings.map((f, i) => (
                <Box key={i} sx={{ px: 1, py: 1, mb: 1, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                        <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', flex: 1 }}>{f.path}</Typography>
                        <Chip label={f.type?.toUpperCase() || 'HTML'} size="small" sx={{ height: 16, fontSize: 9, background: 'var(--accent-dim)', color: 'var(--accent)' }} />
                    </Box>
                    {f.dangerous_elements?.length > 0 && (
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 0.5 }}>
                            {f.dangerous_elements.map((el, j) => (
                                <Chip key={j} label={`<${el.tag}>`} size="small" sx={{ height: 16, fontSize: 10, background: 'var(--danger-dim)', color: 'var(--danger)' }} />
                            ))}
                        </Box>
                    )}
                    {f.svg_events?.length > 0 && (
                        <Box sx={{ mb: 0.5 }}>
                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)' }}>SVG Event Handlers:</Typography>
                            {f.svg_events.map((ev, j) => (
                                <Typography key={j} sx={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--warning)', pl: 1 }}>
                                    {ev.event}= "{ev.handler?.slice(0, 80)}"
                                </Typography>
                            ))}
                        </Box>
                    )}
                    {f.extracted_code && (
                        <pre style={{ margin: 0, padding: '6px 8px', fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 4, maxHeight: 120, overflow: 'auto' }}>
                            {f.extracted_code.slice(0, 500)}
                        </pre>
                    )}
                </Box>
            ))}
        </Box>
    );
}

// ─── Media Issues ───────────────────────────────────────────────────────
function MediaTab({ manifest }) {
    const issues = manifest?.media_issues || [];
    if (!issues.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>No media anomalies detected</Typography>;
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'var(--warning)', px: 1, display: 'block', mb: 1 }}>
                {issues.length} media issue{issues.length !== 1 ? 's' : ''}
            </Typography>
            {issues.map((iss, i) => (
                <Box key={i} sx={{ px: 1, py: 1, mb: 1, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.25 }}>
                        <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', flex: 1 }}>{iss.path}</Typography>
                        <Chip label={iss.type || iss.media_type || 'binary'} size="small" sx={{ height: 16, fontSize: 9, background: 'rgba(148,163,184,0.1)', color: 'var(--text-secondary)' }} />
                    </Box>
                    {(iss.issues || iss.anomalies || []).map((a, j) => (
                        <Typography key={j} sx={{ fontSize: 10, color: 'var(--warning)', pl: 1 }}>• {typeof a === 'string' ? a : a.detail || a.description || JSON.stringify(a)}</Typography>
                    ))}
                </Box>
            ))}
        </Box>
    );
}

// ─── Content_Types Issues ───────────────────────────────────────────────
function ContentTypesTab({ manifest }) {
    const issues = manifest?.content_type_issues || [];
    if (!issues.length) return <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>Content_Types.xml is clean</Typography>;
    return (
        <Box>
            <Typography variant="caption" sx={{ fontWeight: 700, color: 'var(--warning)', px: 1, display: 'block', mb: 1 }}>
                {issues.length} Content_Types issue{issues.length !== 1 ? 's' : ''}
            </Typography>
            {issues.map((iss, i) => (
                <Box key={i} sx={{ px: 1, py: 0.75, mb: 0.75, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.25 }}>
                        <Chip label={iss.severity || iss.type || 'WARN'} size="small" sx={{ height: 16, fontSize: 9, background: (iss.severity === 'HIGH' || iss.type === 'dangerous_mime') ? 'var(--danger-dim)' : 'rgba(245,158,11,0.12)', color: (iss.severity === 'HIGH' || iss.type === 'dangerous_mime') ? 'var(--danger)' : 'var(--warning)' }} />
                        <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>{iss.type || iss.category}</Typography>
                    </Box>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', pl: 0.5 }}>{iss.detail || iss.description || iss.message}</Typography>
                </Box>
            ))}
        </Box>
    );
}

// ─── Utility: copyable text ─────────────────────────────────────────────
function CopyableText({ text }) {
    return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }}>
            <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                {text}
            </Typography>
            <IconButton size="small" onClick={() => navigator.clipboard.writeText(text)} sx={{ p: 0.25, opacity: 0.5, '&:hover': { opacity: 1 } }}>
                <ContentCopyIcon sx={{ fontSize: 11 }} />
            </IconButton>
        </Box>
    );
}

// ─── Main SecurityPanel ─────────────────────────────────────────────────
const SEC_TABS = ['Rels', 'URLs', 'Macros', 'DDE', 'XLM', 'Embedded', 'RTF', 'HTML/SVG', 'Media', 'Types'];

export default function SecurityPanel({ manifest, workspaceId }) {
    const [tab, setTab] = useState(0);

    const counts = [
        (manifest?.rels_files || []).flatMap(r => r.relationships).length,
        (manifest?.urls || []).length,
        (manifest?.macros?.results || []).flatMap(r => r.modules).length,
        (manifest?.dde_findings || []).length,
        (manifest?.xlm_findings?.sheets || []).length,
        (manifest?.embedded_objects || []).length,
        (manifest?.rtf_findings || []).length,
        (manifest?.html_svg_findings || []).length,
        (manifest?.media_issues || []).length,
        (manifest?.content_type_issues || []).length,
    ];

    const getCountColor = (i) => {
        if (i === 3 && counts[3] > 0) return 'var(--danger)';  // DDE
        if (i === 4 && counts[4] > 0) return 'var(--warning)';  // XLM
        if (i === 6 && counts[6] > 0) return 'var(--danger)';  // RTF
        if (i === 7 && counts[7] > 0) return 'var(--warning)';  // HTML/SVG
        if (i === 8 && counts[8] > 0) return 'var(--warning)';  // Media
        if (i === 9 && counts[9] > 0) return 'var(--warning)';  // Types
        return 'var(--accent)';
    };

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            <Tabs
                value={tab}
                onChange={(_, v) => setTab(v)}
                variant="scrollable"
                scrollButtons="auto"
                sx={{ borderBottom: '1px solid var(--border)', minHeight: 32, flexShrink: 0 }}
                TabIndicatorProps={{ style: { background: 'var(--accent)', height: 2 } }}
            >
                {SEC_TABS.map((label, i) => (
                    <Tab
                        key={label}
                        label={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                <span>{label}</span>
                                {counts[i] > 0 && (
                                    <Box sx={{
                                        minWidth: 16, height: 16, borderRadius: '8px', fontSize: 10, fontWeight: 700,
                                        display: 'flex', alignItems: 'center', justifyContent: 'center', px: 0.5,
                                        background: getCountColor(i),
                                        color: '#000',
                                    }}>
                                        {counts[i]}
                                    </Box>
                                )}
                            </Box>
                        }
                        sx={{ minHeight: 32, fontSize: 11, py: 0, px: 1, minWidth: 0 }}
                    />
                ))}
            </Tabs>

            <Box sx={{ flex: 1, overflow: 'auto', pt: 1 }}>
                {tab === 0 && <RelationshipsTab manifest={manifest} />}
                {tab === 1 && <UrlsTab manifest={manifest} />}
                {tab === 2 && <MacrosTab manifest={manifest} />}
                {tab === 3 && <DdeTab manifest={manifest} />}
                {tab === 4 && <XlmTab manifest={manifest} />}
                {tab === 5 && <EmbeddedTab manifest={manifest} workspaceId={workspaceId} />}
                {tab === 6 && <RtfTab manifest={manifest} />}
                {tab === 7 && <HtmlSvgTab manifest={manifest} />}
                {tab === 8 && <MediaTab manifest={manifest} />}
                {tab === 9 && <ContentTypesTab manifest={manifest} />}
            </Box>
        </Box>
    );
}
