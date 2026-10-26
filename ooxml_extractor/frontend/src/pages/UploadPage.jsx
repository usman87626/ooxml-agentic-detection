import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadDocument, uploadBulkDocuments, listWorkspaces, deleteWorkspace } from '../api/client';
import {
    Box, Button, Typography, LinearProgress, Alert, Paper, Chip,
    Divider, Tooltip, IconButton, CircularProgress, Dialog,
    DialogTitle, DialogContent, DialogActions
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import SecurityIcon from '@mui/icons-material/Security';
import HistoryIcon from '@mui/icons-material/History';
import OpenInBrowserIcon from '@mui/icons-material/OpenInBrowser';
import RefreshIcon from '@mui/icons-material/Refresh';
import AssessmentIcon from '@mui/icons-material/Assessment';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassTopIcon from '@mui/icons-material/HourglassTop';

const ACCEPTED = ['.docx', '.docm', '.dotx', '.dotm', '.xlsx', '.xlsm', '.xltx', '.xltm', '.xlsb', '.pptx', '.pptm', '.potx', '.potm', '.zip'];

function StatusIcon({ status }) {
    if (status === 'done') return <CheckCircleIcon sx={{ fontSize: 13, color: 'var(--success)', flexShrink: 0 }} />;
    if (status === 'error') return <ErrorIcon sx={{ fontSize: 13, color: 'var(--danger)', flexShrink: 0 }} />;
    if (status === 'running') return <CircularProgress size={11} sx={{ color: '#60a5fa', flexShrink: 0 }} />;
    return <HourglassTopIcon sx={{ fontSize: 13, color: 'var(--text-muted)', flexShrink: 0 }} />;
}

function formatBytes(n) {
    if (!n) return '';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function HistoryPanel({ onOpen }) {
    const [workspaces, setWorkspaces] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [confirmDelete, setConfirmDelete] = useState(null);
    const [deleting, setDeleting] = useState('');

    const load = useCallback(async () => {
        setLoading(true);
        try { const data = await listWorkspaces(); setWorkspaces(data.workspaces || []); setError(''); }
        catch (e) { setError(e.message); }
        finally { setLoading(false); }
    }, []);

    useEffect(() => { load(); }, [load]);

    const handleDelete = async (ws) => {
        setDeleting(ws.workspace_id);
        try {
            await deleteWorkspace(ws.workspace_id);
            setWorkspaces(prev => prev.filter(w => w.workspace_id !== ws.workspace_id));
        } catch (e) { setError(e.message); }
        finally { setDeleting(''); setConfirmDelete(null); }
    };

    if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}><CircularProgress size={18} /></Box>;
    if (error) return <Alert severity="error" sx={{ mt: 1, fontSize: 12 }}>{error}</Alert>;
    if (workspaces.length === 0) return (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', textAlign: 'center', py: 2 }}>
            No previous extractions found.
        </Typography>
    );

    return (
        <>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, maxHeight: 340, overflow: 'auto', pr: 0.25 }}>
                {workspaces.map(ws => (
                    <Box key={ws.workspace_id} sx={{
                        display: 'flex', alignItems: 'center', gap: 1, p: '8px 10px',
                        background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1.5,
                        transition: 'all 0.12s',
                        '&:hover': ws.status === 'done' ? { borderColor: 'var(--accent)', background: 'var(--accent-dim)' } : {},
                    }}>
                        <Box sx={{ cursor: ws.status === 'done' ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 1, flex: 1, minWidth: 0 }}
                            onClick={() => ws.status === 'done' && onOpen(ws.workspace_id)}>
                            <StatusIcon status={ws.status} />
                            <Box sx={{ flex: 1, minWidth: 0 }}>
                                <Typography sx={{ fontSize: 12, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: ws.status === 'done' ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                                    {ws.filename || ws.workspace_id.slice(0, 20) + '…'}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
                                    {ws.detected_doc_type && <Typography variant="caption" sx={{ fontSize: 10, color: 'var(--text-muted)' }}>{ws.detected_doc_type}</Typography>}
                                    {ws.file_size > 0 && <Typography variant="caption" sx={{ fontSize: 10, color: 'var(--text-muted)' }}>· {formatBytes(ws.file_size)}</Typography>}
                                    {ws.entry_count > 0 && <Typography variant="caption" sx={{ fontSize: 10, color: 'var(--text-muted)' }}>· {ws.entry_count} parts</Typography>}
                                    {ws.time_ms && <Typography variant="caption" sx={{ fontSize: 10, color: 'var(--text-muted)' }}>· {Math.round(ws.time_ms)}ms</Typography>}
                                    {ws.status === 'error' && ws.error && <Typography variant="caption" sx={{ fontSize: 10, color: 'var(--danger)' }}>{ws.error.slice(0, 60)}</Typography>}
                                </Box>
                            </Box>
                        </Box>
                        {ws.status !== 'done' && (
                            <Chip label={ws.status} size="small" sx={{ fontSize: 9, height: 16, textTransform: 'uppercase', background: ws.status === 'error' ? 'var(--danger-dim)' : 'rgba(96,165,250,0.12)', color: ws.status === 'error' ? 'var(--danger)' : '#60a5fa' }} />
                        )}
                        {ws.status === 'done' && (
                            <Tooltip title="Open"><OpenInBrowserIcon sx={{ fontSize: 14, color: 'var(--accent)', cursor: 'pointer' }} onClick={() => onOpen(ws.workspace_id)} /></Tooltip>
                        )}
                        <Tooltip title="Delete workspace">
                            <IconButton size="small" onClick={() => setConfirmDelete(ws)}
                                disabled={deleting === ws.workspace_id}
                                sx={{ color: 'var(--text-muted)', p: 0.3, '&:hover': { color: 'var(--danger)' } }}>
                                {deleting === ws.workspace_id ? <CircularProgress size={12} /> : <DeleteOutlineIcon sx={{ fontSize: 14 }} />}
                            </IconButton>
                        </Tooltip>
                    </Box>
                ))}
            </Box>

            {/* Delete confirmation dialog */}
            <Dialog open={!!confirmDelete} onClose={() => setConfirmDelete(null)} maxWidth="xs" fullWidth
                PaperProps={{ sx: { background: 'var(--bg-secondary)', border: '1px solid var(--border)' } }}>
                <DialogTitle sx={{ fontSize: 15, fontWeight: 700 }}>Delete workspace?</DialogTitle>
                <DialogContent>
                    <Typography sx={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                        This will permanently remove all extracted files for <strong>{confirmDelete?.filename || confirmDelete?.workspace_id?.slice(0, 20)}</strong>. This cannot be undone.
                    </Typography>
                </DialogContent>
                <DialogActions>
                    <Button size="small" onClick={() => setConfirmDelete(null)}>Cancel</Button>
                    <Button size="small" color="error" variant="contained" onClick={() => handleDelete(confirmDelete)}>Delete</Button>
                </DialogActions>
            </Dialog>
        </>
    );
}

export default function UploadPage() {
    const navigate = useNavigate();
    const [dragging, setDragging] = useState(false);
    const [files, setFiles] = useState([]);
    const [progress, setProgress] = useState(0);
    const [uploading, setUploading] = useState(false);
    const [error, setError] = useState('');
    const [historyKey, setHistoryKey] = useState(0);

    const handleDrop = useCallback((e) => {
        e.preventDefault(); setDragging(false);
        const dropped = Array.from(e.dataTransfer.files);
        if (dropped.length) setFiles(dropped);
    }, []);

    const handleUpload = async (autoAnalyze = false) => {
        if (!files.length) return;
        setUploading(true); setError(''); setProgress(0);
        try {
            if (files.length === 1) {
                // We do not have a progress callback for uploadDocument in the basic implementation, but we can pass setProgress if added
                const result = await uploadDocument(files[0], autoAnalyze);
                navigate(`/workspace/${result.workspace_id}`, { state: { status: result.status } });
            } else {
                await uploadBulkDocuments(files, autoAnalyze);
                setFiles([]);
                setHistoryKey(k => k + 1);
            }
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Upload failed');
        } finally { setUploading(false); }
    };

    return (
        <Box sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', px: 2, py: 4, gap: 3 }}>
            <Box sx={{ width: '100%', maxWidth: 540, display: 'flex', justifyContent: 'flex-end', mb: -2 }}>
                <Button size="small" variant="text" startIcon={<AssessmentIcon />} onClick={() => navigate('/eval')} sx={{ color: 'var(--text-secondary)' }}>
                    Batch Evaluation
                </Button>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1.5, mb: 1 }}>
                    <SecurityIcon sx={{ fontSize: 36, color: 'primary.main' }} />
                    <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: '-0.02em' }}>OOXML Extractor</Typography>
                </Box>
                <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 480 }}>
                    Research-grade, full-fidelity Microsoft Office document extractor with dual binary classification.
                </Typography>
            </Box>

            <Paper
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={handleDrop}
                onClick={() => document.getElementById('file-input').click()}
                sx={{
                    width: '100%', maxWidth: 540, p: 4,
                    border: `2px dashed ${dragging ? '#00d4ff' : '#1e2d45'}`,
                    borderRadius: 3, background: dragging ? 'rgba(0,212,255,0.04)' : 'var(--bg-card)',
                    cursor: 'pointer', transition: 'all 0.2s', textAlign: 'center',
                    '&:hover': { borderColor: '#00d4ff', background: 'rgba(0,212,255,0.03)' },
                }}>
                <input id="file-input" type="file" multiple hidden accept={ACCEPTED.join(',')} onChange={(e) => setFiles(Array.from(e.target.files))} />
                <CloudUploadIcon sx={{ fontSize: 44, color: 'primary.main', mb: 1, opacity: 0.85 }} />
                {files.length > 0 ? (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                        <InsertDriveFileIcon sx={{ color: 'primary.main', fontSize: 16 }} />
                        <Typography sx={{ fontWeight: 600, color: 'primary.main', fontSize: 14 }}>
                            {files.length === 1 ? files[0].name : `${files.length} files selected`}
                        </Typography>
                        {files.length === 1 && <Typography variant="caption" color="text.secondary">({(files[0].size / 1024).toFixed(1)} KB)</Typography>}
                    </Box>
                ) : (
                    <>
                        <Typography sx={{ fontWeight: 600, mb: 0.5, fontSize: 14 }}>Drop Office documents here</Typography>
                        <Typography variant="caption" color="text.secondary">or click to browse</Typography>
                    </>
                )}
            </Paper>

            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, justifyContent: 'center', maxWidth: 540 }}>
                {ACCEPTED.map(ext => <Chip key={ext} label={ext} size="small" sx={{ fontSize: 10, height: 20, background: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }} />)}
            </Box>

            {
                uploading && (
                    <Box sx={{ width: '100%', maxWidth: 540 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                            <Typography variant="caption" color="text.secondary">Uploading…</Typography>
                            <Typography variant="caption" color="primary.main">{progress}%</Typography>
                        </Box>
                        <LinearProgress variant="determinate" value={progress} sx={{ borderRadius: 1 }} />
                    </Box>
                )
            }
            {error && <Alert severity="error" sx={{ width: '100%', maxWidth: 540, fontSize: 13 }}>{error}</Alert>}

            <Box sx={{ display: 'flex', gap: 2, width: '100%', maxWidth: 540 }}>
                <Button variant="outlined" size="large" onClick={() => handleUpload(false)} disabled={files.length === 0 || uploading}
                    sx={{ flex: 1, py: 1.2, fontWeight: 700, fontSize: 14, borderRadius: 2 }}>
                    Extract Only
                </Button>
                <Button variant="contained" size="large" onClick={() => handleUpload(true)} disabled={files.length === 0 || uploading}
                    sx={{ flex: 1, py: 1.2, fontWeight: 700, fontSize: 14, borderRadius: 2 }}>
                    {uploading ? 'Processing...' : 'Extract & Analyze (Agents)'}
                </Button>
            </Box>

            {/* History */}
            <Box sx={{ width: '100%', maxWidth: 540 }}>
                <Divider sx={{ mb: 1.5 }} />
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                        <HistoryIcon sx={{ fontSize: 15, color: 'var(--text-secondary)' }} />
                        <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>Previous Extractions</Typography>
                    </Box>
                    <Tooltip title="Refresh">
                        <IconButton size="small" onClick={() => setHistoryKey(k => k + 1)} sx={{ color: 'var(--text-muted)', p: 0.3 }}>
                            <RefreshIcon sx={{ fontSize: 14 }} />
                        </IconButton>
                    </Tooltip>
                </Box>
                <HistoryPanel key={historyKey} onOpen={(id) => navigate(`/workspace/${id}`)} onRefresh={() => setHistoryKey(k => k + 1)} />
            </Box>
        </Box>
    );
}
