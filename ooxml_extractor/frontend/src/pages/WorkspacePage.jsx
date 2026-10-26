import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { getManifest, getStatus, search, getImages, getImageUrl } from '../api/client';
import {
    Box, Typography, CircularProgress, Alert, IconButton,
    InputBase, Paper, Tooltip, Divider, Chip, LinearProgress
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import SearchIcon from '@mui/icons-material/Search';
import SecurityIcon from '@mui/icons-material/Security';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import TimerIcon from '@mui/icons-material/Timer';
import FileTree from '../components/FileTree';
import FileViewer from '../components/FileViewer';
import SecurityPanel from '../components/SecurityPanel';
import SearchResults from '../components/SearchResults';
import AnalysisPanel from '../components/AnalysisPanel';

const POLL_INTERVAL_MS = 1200;

export default function WorkspacePage() {
    const { workspaceId } = useParams();
    const navigate = useNavigate();
    const location = useLocation();

    const [status, setStatus] = useState(location.state?.status || 'queued');
    const [statusData, setStatusData] = useState({});
    const [manifest, setManifest] = useState(null);
    const [loadErr, setLoadErr] = useState('');
    const [selectedPath, setSelectedPath] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState(null);
    const [searching, setSearching] = useState(false);
    const [activeTab, setActiveTab] = useState('tree');
    const [kindFilter, setKindFilter] = useState('');
    const [images, setImages] = useState([]);
    const [imagesLoaded, setImagesLoaded] = useState(false);

    const pollRef = useRef(null);
    const doneRef = useRef(false);

    // ── Status polling ──────────────────────────────────────────────────────
    const pollStatus = useCallback(async () => {
        try {
            const s = await getStatus(workspaceId);
            setStatusData(s);
            setStatus(s.status);
            if (s.status === 'done' || s.status === 'error') {
                clearInterval(pollRef.current);
                doneRef.current = true;
                if (s.status === 'done') {
                    const m = await getManifest(workspaceId);
                    setManifest(m);
                    try { const imgs = await getImages(workspaceId); setImages(imgs.images || []); setImagesLoaded(true); } catch { /* swallow error */ }
                }
            }
        } catch (e) {
            setLoadErr(e.response?.data?.detail || e.message);
            clearInterval(pollRef.current);
        }
    }, [workspaceId]);

    useEffect(() => {
        // Start polling immediately
        pollStatus();
        pollRef.current = setInterval(pollStatus, POLL_INTERVAL_MS);
        return () => clearInterval(pollRef.current);
    }, [pollStatus]);

    const handleSearch = async (e) => {
        e.preventDefault();
        if (!searchQuery.trim()) return;
        setSearching(true);
        setActiveTab('search');
        try {
            const results = await search(workspaceId, searchQuery);
            setSearchResults(results);
        } catch (e) {
            setSearchResults({ query: searchQuery, total: 0, results: [], error: e.message });
        } finally {
            setSearching(false);
        }
    };

    // ── Loading / Error states ──────────────────────────────────────────────
    if (loadErr) return (
        <Box sx={{ p: 4 }}><Alert severity="error">{loadErr}</Alert></Box>
    );

    const totalEntries = manifest?.entries?.length || 0;
    const summary = manifest?.summary || statusData;

    // ── Pending states ──────────────────────────────────────────────────────
    const isPending = status === 'queued' || status === 'running';

    // ── Render ──────────────────────────────────────────────────────────────
    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
            {/* Top Bar */}
            <Box sx={{
                display: 'flex', alignItems: 'center', gap: 1.5, px: 2, py: 1,
                background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', flexShrink: 0,
            }}>
                <Tooltip title="New extraction">
                    <IconButton size="small" onClick={() => navigate('/')} sx={{ color: 'text.secondary' }}>
                        <ArrowBackIcon fontSize="small" />
                    </IconButton>
                </Tooltip>
                <SecurityIcon sx={{ color: 'primary.main', fontSize: 20 }} />
                <Typography sx={{ fontWeight: 700, fontSize: 15 }}>OOXML Extractor</Typography>
                <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />
                <Typography variant="caption" sx={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {manifest?.file_metadata?.filename || workspaceId}
                </Typography>

                {/* Status badge */}
                <Chip
                    label={status}
                    size="small"
                    sx={{
                        fontSize: 10, height: 20, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
                        background: status === 'done' ? 'rgba(16,185,129,0.12)' : status === 'error' ? 'var(--danger-dim)' : 'rgba(96,165,250,0.12)',
                        color: status === 'done' ? 'var(--success)' : status === 'error' ? 'var(--danger)' : '#60a5fa',
                        border: `1px solid ${status === 'done' ? 'rgba(16,185,129,0.25)' : status === 'error' ? 'rgba(239,68,68,0.25)' : 'rgba(96,165,250,0.25)'}`,
                    }}
                />

                {/* Timing badge */}
                {statusData.time_ms && (
                    <Tooltip title="Total extraction time">
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.4 }}>
                            <TimerIcon sx={{ fontSize: 13, color: 'var(--text-muted)' }} />
                            <Typography variant="caption" sx={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                                {statusData.time_ms?.toFixed(0)}ms
                            </Typography>
                        </Box>
                    </Tooltip>
                )}

                {/* Stats */}
                <Box sx={{ display: 'flex', gap: 0.75, ml: 0.5 }}>
                    {totalEntries > 0 && <Chip label={`${totalEntries} parts`} size="small" sx={{ fontSize: 11, height: 20, background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid rgba(0,212,255,0.2)' }} />}
                    {summary?.macro_containers > 0 && <Chip label={`${summary.macro_containers} macro`} size="small" sx={{ fontSize: 11, height: 20, background: 'var(--danger-dim)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.25)' }} />}
                    {summary?.dde_hits > 0 && <Chip label={`${summary.dde_hits} DDE`} size="small" sx={{ fontSize: 11, height: 20, background: 'rgba(245,158,11,0.12)', color: 'var(--warning)', border: '1px solid rgba(245,158,11,0.25)' }} />}
                    {summary?.xlm_hits > 0 && <Chip label={`${summary.xlm_hits} XLM`} size="small" sx={{ fontSize: 11, height: 20, background: 'rgba(245,158,11,0.12)', color: 'var(--warning)', border: '1px solid rgba(245,158,11,0.25)' }} />}
                </Box>

                <Box sx={{ flex: 1 }} />

                {/* Search */}
                {!isPending && (
                    <Paper component="form" onSubmit={handleSearch} sx={{
                        display: 'flex', alignItems: 'center', px: 1.5, py: 0.5,
                        background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1.5, width: 280,
                    }}>
                        <SearchIcon sx={{ fontSize: 16, color: 'text.secondary', mr: 1 }} />
                        <InputBase placeholder="Search extracted content…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
                            sx={{ flex: 1, fontSize: 13, color: 'text.primary', '& input::placeholder': { color: 'var(--text-muted)' } }} />
                        {searching && <CircularProgress size={14} sx={{ ml: 1 }} />}
                    </Paper>
                )}
            </Box>

            {/* Progress bar while running */}
            {isPending && (
                <Box sx={{ flexShrink: 0 }}>
                    <LinearProgress sx={{ height: 2 }} />
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1.5, py: 6, flexDirection: 'column' }}>
                        <CircularProgress size={36} />
                        <Typography color="text.secondary" sx={{ fontWeight: 500 }}>
                            {status === 'queued' ? 'Queued — waiting for worker…' : 'Extracting document…'}
                        </Typography>
                        <Typography variant="caption" sx={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            {workspaceId}
                        </Typography>
                    </Box>
                </Box>
            )}

            {/* Main 3-panel layout */}
            {!isPending && (
                <Box sx={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
                    {/* Left panel — 360px Strelka-style tree */}
                    <Box sx={{
                        width: 360, flexShrink: 0,
                        background: 'var(--bg-secondary)', borderRight: '1px solid var(--border)',
                        display: 'flex', flexDirection: 'column', overflow: 'hidden',
                    }}>
                        {/* Left tab bar */}
                        <Box sx={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
                            {['tree', 'security', 'images', 'analysis'].map(tab => (
                                <Box key={tab} onClick={() => setActiveTab(tab)} sx={{
                                    flex: 1, textAlign: 'center', py: '7px', cursor: 'pointer', fontSize: 11, fontWeight: 600,
                                    color: activeTab === tab ? 'primary.main' : 'text.secondary',
                                    background: activeTab === tab ? 'var(--accent-dim)' : 'transparent',
                                    borderBottom: activeTab === tab ? '2px solid var(--accent)' : '2px solid transparent',
                                    transition: 'all 0.12s', textTransform: 'uppercase', letterSpacing: '0.06em',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0.5
                                }}>
                                    {tab === 'tree' ? `Parts (${manifest?.entries?.length ?? 0})` : tab === 'images' ? `Images (${images.length})` : tab === 'analysis' ? <><AccountTreeIcon sx={{ fontSize: 14 }} /> Trace</> : 'Security'}
                                </Box>
                            ))}
                        </Box>
                        <Box sx={{ flex: 1, overflow: 'auto' }}>
                            {activeTab === 'tree' && <FileTree entries={manifest?.entries || []} selected={selectedPath} onSelect={setSelectedPath} kindFilter={kindFilter} onKindFilterChange={setKindFilter} />}
                            {activeTab === 'security' && <SecurityPanel manifest={manifest} workspaceId={workspaceId} />}
                            {activeTab === 'analysis' && <AnalysisPanel workspaceId={workspaceId} />}
                            {activeTab === 'images' && (
                                <Box sx={{ p: 1 }}>
                                    {!imagesLoaded && <Typography variant="caption" color="text.secondary" sx={{ display: 'block', textAlign: 'center', mt: 2 }}>Loading…</Typography>}
                                    {imagesLoaded && images.length === 0 && <Typography variant="caption" color="text.secondary" sx={{ display: 'block', textAlign: 'center', mt: 2 }}>No images extracted</Typography>}
                                    <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0.75 }}>
                                        {images.map(img => (
                                            <Box key={img.name} onClick={() => {
                                                // Find the entry path for this image and select it
                                                const matchEntry = manifest?.entries?.find(e => e.path.endsWith(img.name.replace(/_/g, '/')) || e.path.split('/').pop() === img.name.split('_').pop());
                                                if (matchEntry) { setSelectedPath(matchEntry.path); setActiveTab('tree'); }
                                            }} sx={{
                                                background: 'repeating-conic-gradient(#1a2332 0% 25%, #151e2d 0% 50%) 0 0 / 12px 12px',
                                                border: '1px solid var(--border)', borderRadius: 1, overflow: 'hidden', cursor: 'pointer', aspectRatio: '1',
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                '&:hover': { borderColor: 'var(--accent)' },
                                            }}>
                                                <img src={getImageUrl(workspaceId, img.name)} alt={img.name}
                                                    style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain', display: 'block' }} />
                                            </Box>
                                        ))}
                                    </Box>
                                </Box>
                            )}
                        </Box>
                    </Box>

                    {/* Center */}
                    <Box sx={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                        {activeTab === 'search' && searchResults ? (
                            <SearchResults results={searchResults} onSelect={(path) => { setSelectedPath(path); setActiveTab('tree'); }} />
                        ) : !manifest ? (
                            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1 }}>
                                <Alert severity="error">Extraction failed: {statusData.error}</Alert>
                            </Box>
                        ) : (
                            <FileViewer workspaceId={workspaceId} path={selectedPath} manifest={manifest} />
                        )}
                    </Box>
                </Box>
            )}

            {/* Error state */}
            {status === 'error' && (
                <Box sx={{ p: 4 }}>
                    <Alert severity="error">Extraction failed: {statusData.error || 'Unknown error'}</Alert>
                </Box>
            )}
        </Box>
    );
}
