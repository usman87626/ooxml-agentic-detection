import { useState, useEffect, useCallback, useRef } from 'react';
import {
    Box, Typography, Chip, LinearProgress, Button, Alert, CircularProgress,
    Accordion, AccordionSummary, AccordionDetails, Tooltip, Divider
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import LinkIcon from '@mui/icons-material/Link';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import PsychologyIcon from '@mui/icons-material/Psychology';
import ViewListIcon from '@mui/icons-material/ViewList';
import DataObjectIcon from '@mui/icons-material/DataObject';
import { ToggleButton, ToggleButtonGroup } from '@mui/material';
import { startAnalysis, getAnalysisStatus, getVerdict } from '../api/client';

const POLL_MS = 2000;

const VERDICT_META = {
    CLEAN: { color: '#10b981', bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.3)', icon: <CheckCircleIcon /> },
    SUSPICIOUS: { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)', icon: <WarningAmberIcon /> },
    MALICIOUS: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)', icon: <CancelIcon /> },
    CAUTION: { color: '#60a5fa', bg: 'rgba(96,165,250,0.12)', border: 'rgba(96,165,250,0.3)', icon: <HelpOutlineIcon /> },
};

function ScoreBar({ value, max = 100, color }) {
    const pct = Math.min(100, Math.round((value / max) * 100));
    return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <LinearProgress variant="determinate" value={pct}
                sx={{ flex: 1, height: 6, borderRadius: 3, bgcolor: 'var(--bg-tertiary)', '& .MuiLinearProgress-bar': { bgcolor: color || '#60a5fa', borderRadius: 3 } }} />
            <Typography sx={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: color || 'var(--text-secondary)', minWidth: 32, textAlign: 'right' }}>
                {value}
            </Typography>
        </Box>
    );
}

function ToolCard({ result }) {
    const hasError = !!result.error;
    const isSkipped = result.skipped;
    const kindIcon = {
        macro_analyzer: '⚠️',
        ole_analyzer: '📦',
        dde_analyzer: '📝',
        xlm_analyzer: '📊',
        obfuscation_analyzer: '🔍',
        structure_analyzer: '🏗',
        prompt_injection_scanner: '🚨',
        intent_analyzer: '🧠',
        phishing_analyzer: '🎣',
        template_injection_analyzer: '🎯',
        ooxml_attack_analyzer: '🛡',
        pcode_analyzer: '🔬',
        macroless_attack_analyzer: '🕳',
        url_validator: '🔗',
        html_svg_analyzer: '🌐',
    };

    return (
        <Accordion disableGutters sx={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: '6px !important', mb: 0.75, '&::before': { display: 'none' } }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ fontSize: 14 }} />} sx={{ minHeight: '38px !important', px: 1.5, py: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
                    <Typography sx={{ fontSize: 13 }}>{kindIcon[result.tool_name] || '🔧'}</Typography>
                    <Typography sx={{ fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 600, flex: 1 }}>
                        {result.tool_name}
                    </Typography>
                    {hasError && <Chip label="error" size="small" sx={{ fontSize: 9, height: 16, bgcolor: 'var(--danger-dim)', color: 'var(--danger)' }} />}
                    {isSkipped && <Chip label="skipped" size="small" sx={{ fontSize: 9, height: 16, bgcolor: 'var(--bg-primary)', color: 'var(--text-muted)' }} />}
                    {result.duration_ms > 0 && <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{Math.round(result.duration_ms)}ms</Typography>}
                </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ px: 1.5, pt: 0, pb: 1.5 }}>
                {hasError && <Alert severity="error" sx={{ fontSize: 11, mb: 1, py: 0 }}>{result.error}</Alert>}
                {result.skip_reason && <Typography sx={{ fontSize: 11, color: 'var(--text-muted)' }}>Skipped: {result.skip_reason}</Typography>}

                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {result.input_data && (
                        <Box mt={1}>
                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', mb: 0.5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Input Payload</Typography>
                            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto', maxHeight: 200, margin: 0, background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6 }}>
                                {JSON.stringify(result.input_data, null, 2)}
                            </pre>
                        </Box>
                    )}
                    {result.output && Object.keys(result.output).length > 0 && (
                        <Box mt={1}>
                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', mb: 0.5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Output Payload</Typography>
                            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto', maxHeight: 300, margin: 0, background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6 }}>
                                {JSON.stringify(result.output, null, 2)}
                            </pre>
                        </Box>
                    )}
                </Box>
            </AccordionDetails>
        </Accordion>
    );
}

function MitreBadge({ technique }) {
    return (
        <Box sx={{ p: 1.25, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', borderRadius: 1.5, mb: 0.75 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Chip label={technique.id} size="small" sx={{ fontSize: 10, height: 18, fontFamily: 'var(--font-mono)', bgcolor: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }} />
                <Typography sx={{ fontSize: 12, fontWeight: 600 }}>{technique.name}</Typography>
                <Chip label={technique.tactic} size="small" sx={{ fontSize: 10, height: 18, bgcolor: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid rgba(0,212,255,0.2)' }} />
            </Box>
            {technique.description && <Typography sx={{ fontSize: 11, color: 'var(--text-secondary)' }}>{technique.description}</Typography>}
        </Box>
    );
}

function VerdictPanel({ verdict }) {
    const meta = VERDICT_META[verdict.verdict] || VERDICT_META.SUSPICIOUS;
    const riskColor = verdict.risk_score >= 60 ? '#ef4444' : verdict.risk_score >= 20 ? '#f59e0b' : '#10b981';

    return (
        <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ p: 2, background: meta.bg, border: `1px solid ${meta.border}`, borderRadius: 2, display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <Box sx={{ color: meta.color, display: 'flex' }}>{meta.icon}</Box>
                <Box sx={{ flex: 1 }}>
                    <Typography sx={{ fontSize: 18, fontWeight: 800, color: meta.color, letterSpacing: '-0.02em' }}>{verdict.verdict}</Typography>
                    <Typography sx={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        Confidence: {Math.round((verdict.confidence || 0) * 100)}%
                    </Typography>
                </Box>
                <Box sx={{ textAlign: 'right' }}>
                    <Typography sx={{ fontSize: 28, fontWeight: 800, color: riskColor, fontFamily: 'var(--font-mono)' }}>{verdict.risk_score}</Typography>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)' }}>/ 100 risk</Typography>
                </Box>
            </Box>

            <Box>
                <Typography sx={{ fontSize: 11, color: 'var(--text-muted)', mb: 0.5 }}>Risk Score</Typography>
                <ScoreBar value={verdict.risk_score} color={riskColor} />
            </Box>

            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                {[
                    { label: 'Intent', value: verdict.intent },
                    { label: 'Deception', value: verdict.deception },
                    { label: 'Harm', value: verdict.harm },
                    { label: 'Intent Confidence', value: verdict.intent_confidence ? `${Math.round(verdict.intent_confidence * 100)}%` : null },
                ].filter(f => f.value).map(f => (
                    <Box key={f.label}>
                        <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.25 }}>{f.label}</Typography>
                        <Typography sx={{ fontSize: 12, color: 'var(--text-primary)' }}>{f.value}</Typography>
                    </Box>
                ))}
            </Box>

            {verdict.indicators?.length > 0 && (
                <Box>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>Indicators</Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {verdict.indicators.map(ind => (
                            <Chip key={ind} label={ind} size="small" sx={{ fontSize: 10, height: 20, bgcolor: 'rgba(239,68,68,0.08)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.15)' }} />
                        ))}
                    </Box>
                </Box>
            )}

            {verdict.extracted_iocs?.length > 0 && (
                <Box>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>Extracted IOCs</Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {verdict.extracted_iocs.map(ioc => (
                            <Chip key={ioc} label={ioc} size="small" sx={{ fontSize: 10, height: 20, bgcolor: 'rgba(96,165,250,0.08)', color: '#60a5fa', border: '1px solid rgba(96,165,250,0.15)', fontFamily: 'var(--font-mono)' }} />
                        ))}
                    </Box>
                </Box>
            )}

            {verdict.prompt_injection_detected && <Alert severity="error" sx={{ fontSize: 11, py: 0 }}>Prompt injection detected</Alert>}
            {verdict.needs_web_analysis && <Alert severity="warning" sx={{ fontSize: 11, py: 0 }}>Requires Web Analysis</Alert>}

            {verdict.reasoning?.length > 0 && (
                <Box>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>Reasoning</Typography>
                    {verdict.reasoning.map((r, i) => (
                        <Box key={i} sx={{ display: 'flex', gap: 1, mb: 0.5 }}>
                            <Typography sx={{ fontSize: 11, color: 'var(--text-muted)' }}>•</Typography>
                            <Typography sx={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r}</Typography>
                        </Box>
                    ))}
                </Box>
            )}
        </Box>
    );
}

function MacrosSection({ verdict }) {
    const macros = verdict.signal_graph?.raw_signals?.macros;
    if (!macros || (!macros.has_macros && macros.macro_module_count === 0)) {
        return <Box sx={{ p: 2 }}><Typography sx={{ fontSize: 12, color: 'var(--text-muted)' }}>No VBA macros found in this document.</Typography></Box>;
    }

    return (
        <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {macros.encrypted_vba_detected && (
                <Alert severity="warning" sx={{ fontSize: 11, py: 0.5 }}>
                    VBA Project is password-protected or locked (DPB=). Some code may be hidden from static extraction.
                </Alert>
            )}

            {macros.macro_modules?.length > 0 ? (
                macros.macro_modules.map((mod, i) => (
                    <Box key={i} sx={{ border: '1px solid var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                        <Box sx={{ px: 1.5, py: 1, background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <Typography sx={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{mod.name}</Typography>
                            <Chip label={mod.type || 'Module'} size="small" sx={{ fontSize: 9, height: 16 }} />
                        </Box>
                        <pre style={{ margin: 0, padding: '12px', fontSize: 11, fontFamily: 'var(--font-mono)', overflow: 'auto', maxHeight: 400, background: 'var(--bg-primary)', color: 'var(--text-secondary)' }}>
                            {mod.code || "' No code extracted for this module"}
                        </pre>
                    </Box>
                ))
            ) : (
                <Box sx={{ p: 2, background: 'var(--bg-tertiary)', borderRadius: 2, border: '1px dashed var(--border)' }}>
                    <Typography sx={{ fontSize: 12, color: 'var(--text-secondary)', textAlign: 'center' }}>
                        Macro container detected but no modules were extracted.
                    </Typography>
                </Box>
            )}

            {macros.macro_paths?.length > 0 && (
                <Box>
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', mb: 0.5, textTransform: 'uppercase' }}>Source Containers</Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {macros.macro_paths.map(p => <Chip key={p} label={p} size="small" sx={{ fontSize: 10, height: 18, fontFamily: 'var(--font-mono)' }} />)}
                    </Box>
                </Box>
            )}
        </Box>
    );
}

function SignalsSection({ verdict }) {
    const signals = verdict.signal_graph;
    if (!signals) return <Typography sx={{ p: 2, fontSize: 12, color: 'var(--text-muted)' }}>No signal graph data</Typography>;

    return (
        <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {/* Text length and density removed per user request */}

            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {signals.has_macros && <Chip label="VBA Macros" color="error" variant="outlined" size="small" />}
                {signals.dde_detected && <Chip label="DDE Detected" color="error" variant="outlined" size="small" />}
                {signals.xlm_detected && <Chip label="XLM Detected" color="error" variant="outlined" size="small" />}
                {signals.obfuscation_detected && <Chip label="Obfuscation" color="error" variant="outlined" size="small" />}
                {signals.template_injection_detected && <Chip label="Template Injection" color="error" variant="outlined" size="small" />}
                {signals.prompt_injection_detected && <Chip label="Prompt Injection" color="error" variant="outlined" size="small" />}
                {signals.pcode_stomping_detected && <Chip label="P-Code Stomping" color="error" variant="outlined" size="small" />}
                {signals.encrypted_vba_detected && <Chip label="Encrypted VBA" color="warning" variant="outlined" size="small" />}
                {signals.macroless_attacks_detected && <Chip label="Macro-less Attack" color="error" variant="outlined" size="small" />}
                {signals.has_online_video && <Chip label="Online Video" color="warning" variant="outlined" size="small" />}
                {signals.has_dangerous_activex && <Chip label="Dangerous ActiveX" color="error" variant="outlined" size="small" />}
                {signals.has_activex && !signals.has_dangerous_activex && <Chip label="ActiveX" color="warning" variant="outlined" size="small" />}
                {signals.has_rtf_exploits && <Chip label="RTF Exploits" color="error" variant="outlined" size="small" />}
                {signals.has_html_svg_payloads && <Chip label="HTML/SVG Payloads" color="warning" variant="outlined" size="small" />}
                {signals.has_media_anomalies && <Chip label="Media Anomalies" color="warning" variant="outlined" size="small" />}
                {signals.content_type_poisoning && <Chip label="Content-Type Poisoning" color="warning" variant="outlined" size="small" />}
                {signals.autoexec_keywords?.length > 0 && <Chip label="AutoExec" color="warning" variant="outlined" size="small" />}
                {signals.suspicious_urls?.length > 0 && <Chip label={`${signals.suspicious_urls.length} Suspicious URLs`} color="warning" variant="outlined" size="small" />}
            </Box>

            <Box>
                <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', mb: 1, textTransform: 'uppercase' }}>Raw Signal Dump</Typography>
                <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6, overflow: 'auto', maxHeight: 300 }}>
                    {JSON.stringify(signals.raw_signals || {}, null, 2)}
                </pre>
            </Box>
        </Box>
    );
}

function ReasoningSection({ verdict }) {
    const stages = [
        { name: 'Intent Classification (Task 1)', icon: '🎯', desc: "Analyzes document narrative and lure patterns." },
        { name: 'Macro Behavior Analysis (Task 2)', icon: '🧠', desc: "Deobfuscates and reasons about code execution flow." },
        { name: 'Verdict Aggregation (Task 3)', icon: '⚖️', desc: "Correlates technical signals with classified intent." }
    ];

    return (
        <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {stages.map((s, i) => (
                <Box key={i} sx={{ borderLeft: '2px solid var(--accent)', pl: 2, mb: 1 }}>
                    <Typography sx={{ fontSize: 12, fontWeight: 700, mb: 0.5 }}>{s.icon} {s.name}</Typography>
                    <Typography sx={{ fontSize: 11, color: 'var(--text-secondary)' }}>{s.desc}</Typography>
                </Box>
            ))}
            <Box mt={1}>
                <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', mb: 0.5, textTransform: 'uppercase' }}>Full Verdict Reasoning</Typography>
                <Box sx={{ p: 2, background: 'var(--bg-tertiary)', borderRadius: 2, border: '1px solid var(--border)' }}>
                    {verdict.reasoning?.map((r, i) => (
                        <Typography key={i} sx={{ fontSize: 12, mb: 1, color: 'var(--text-primary)' }}>
                            <span style={{ color: 'var(--accent)', marginRight: '8px' }}>[{i + 1}]</span>
                            {r}
                        </Typography>
                    ))}
                </Box>
            </Box>
        </Box>
    );
}

function MitreSection({ verdict }) {
    const techs = verdict.mitre_techniques || [];
    if (techs.length === 0) return <Typography sx={{ p: 2, fontSize: 12, color: 'var(--text-muted)' }}>No MITRE techniques mapped</Typography>;
    return (
        <Box sx={{ p: 2 }}>
            <Typography sx={{ fontSize: 11, color: 'var(--text-muted)', mb: 1, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                ATT&CK Techniques ({techs.length})
            </Typography>
            {techs.map(t => <MitreBadge key={t.id} technique={t} />)}
        </Box>
    );
}

// ── Main Analysis Panel ──────────────────────────────────────────────────────

const TABS = [
    { id: 'verdict', label: '🎯 Verdict' },
    { id: 'signals', label: '📊 Signals' },
    { id: 'macros', label: '📜 Macros' },
    { id: 'reasoning', label: '🧠 Reasoning' },
    { id: 'mitre', label: '🗡 MITRE' },
];

export default function AnalysisPanel({ workspaceId }) {
    const [tab, setTab] = useState('verdict');
    const [viewMode, setViewMode] = useState('visual'); // 'visual' | 'json'
    const [status, setStatus] = useState('idle');
    const [stage, setStage] = useState('');
    const [verdict, setVerdict] = useState(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const pollRef = useRef(null);

    const stopPolling = () => { clearInterval(pollRef.current); };

    const pollStatus = useCallback(async () => {
        try {
            const s = await getAnalysisStatus(workspaceId);
            setStatus(s.analysis_status || 'idle');
            setStage(s.stage || '');
            if (s.analysis_status === 'done') {
                stopPolling();
                const v = await getVerdict(workspaceId);
                setVerdict(v);
            } else if (s.analysis_status === 'error') {
                stopPolling();
                setError(s.error || 'Analysis failed');
            }
        } catch {
            // 404 = not started yet
        }
    }, [workspaceId]);

    // Boot: check if already done or running
    useEffect(() => {
        let mounted = true;
        let retryCount = 0;
        let retryTimer = null;

        const init = async () => {
            try {
                const s = await getAnalysisStatus(workspaceId);
                if (!mounted) return;

                setStatus(s.analysis_status || 'idle');
                setStage(s.stage || '');

                if (s.analysis_status === 'done') {
                    const v = await getVerdict(workspaceId);
                    setVerdict(v);
                } else if (s.analysis_status === 'queued' || s.analysis_status === 'running') {
                    // Auto-analyze was triggered upstream, start polling automatically
                    pollRef.current = setInterval(pollStatus, POLL_MS);
                } else if (s.analysis_status === 'error') {
                    setError(s.error || 'Analysis failed');
                }
            } catch {
                // 404 = not started yet — but auto_analyze may be about to start
                // Retry a few times to catch the transition
                if (mounted && retryCount < 5) {
                    retryCount++;
                    retryTimer = setTimeout(init, 2000);
                }
            }
        };
        init();
        return () => { mounted = false; stopPolling(); if (retryTimer) clearTimeout(retryTimer); };
    }, [workspaceId, pollStatus]);

    const handleAnalyze = async () => {
        setLoading(true); setError(''); setVerdict(null);
        try {
            const res = await startAnalysis(workspaceId);
            setStatus(res.analysis_status);
            if (res.analysis_status === 'done') {
                const v = await getVerdict(workspaceId);
                setVerdict(v);
            } else {
                pollRef.current = setInterval(pollStatus, POLL_MS);
            }
        } catch (e) {
            setError(e.response?.data?.detail || e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => () => stopPolling(), []);

    const isRunning = status === 'queued' || status === 'running';

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Header */}
            <Box sx={{ px: 2, pt: 1.5, pb: 1, borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <AccountTreeIcon sx={{ fontSize: 17, color: 'var(--accent)' }} />
                    <Typography sx={{ fontWeight: 700, fontSize: 13, flex: 1 }}>Analysis Pipeline</Typography>
                    {status !== 'idle' && (
                        <Chip label={status} size="small" sx={{
                            fontSize: 9, height: 16, textTransform: 'uppercase',
                            bgcolor: status === 'done' ? 'rgba(16,185,129,0.1)' : status === 'error' ? 'var(--danger-dim)' : 'rgba(96,165,250,0.1)',
                            color: status === 'done' ? '#10b981' : status === 'error' ? 'var(--danger)' : '#60a5fa',
                        }} />
                    )}
                </Box>

                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                    <Button
                        variant="contained" fullWidth size="small"
                        startIcon={loading || isRunning ? <CircularProgress size={12} color="inherit" /> : <SecurityIcon sx={{ fontSize: 14 }} />}
                        onClick={handleAnalyze}
                        disabled={loading || isRunning || status === 'done'}
                        sx={{ fontSize: 12, py: 0.75, fontWeight: 700 }}>
                        {status === 'done' ? 'Analysis Complete' : isRunning ? `Running — ${stage || 'working…'}` : 'Run Analysis'}
                    </Button>

                    {verdict && (
                        <ToggleButtonGroup
                            value={viewMode}
                            exclusive
                            onChange={(e, v) => v && setViewMode(v)}
                            size="small"
                            sx={{ height: 32, flexShrink: 0 }}
                        >
                            <ToggleButton value="visual" sx={{ px: 1, py: 0 }}>
                                <Tooltip title="Visual Rendering"><ViewListIcon sx={{ fontSize: 16 }} /></Tooltip>
                            </ToggleButton>
                            <ToggleButton value="json" sx={{ px: 1, py: 0 }}>
                                <Tooltip title="Raw JSON Trace"><DataObjectIcon sx={{ fontSize: 16 }} /></Tooltip>
                            </ToggleButton>
                        </ToggleButtonGroup>
                    )}
                </Box>
                {status === 'done' && (
                    <Button size="small" fullWidth onClick={handleAnalyze} sx={{ fontSize: 11, mt: 0.5, color: 'var(--text-muted)' }}>
                        Re-run Pipeline
                    </Button>
                )}
            </Box>

            {/* Progress */}
            {isRunning && (
                <Box sx={{ flexShrink: 0 }}>
                    <LinearProgress sx={{ height: 2 }} />
                    <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center', py: 0.5 }}>
                        Agent Trace: {stage || 'initializing'}
                    </Typography>
                </Box>
            )}

            {/* Error */}
            {error && <Alert severity="error" sx={{ m: 1, fontSize: 11, py: 0.25 }}>{error}</Alert>}

            {/* Tabs */}
            {
                verdict && (
                    <>
                        <Box sx={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0, overflow: 'auto' }}>
                            {TABS.map(t => (
                                <Box key={t.id} onClick={() => setTab(t.id)} sx={{
                                    px: 1.25, py: '6px', cursor: 'pointer', fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap',
                                    color: tab === t.id ? 'var(--accent)' : 'var(--text-secondary)',
                                    borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
                                    '&:hover': { color: 'var(--text-primary)' },
                                }}>{t.label}</Box>
                            ))}
                        </Box>
                        <Box sx={{ flex: 1, overflow: 'auto' }}>
                            {viewMode === 'json' ? (
                                <Box sx={{ p: 2 }}>
                                    {tab === 'verdict' && (
                                        <Box>
                                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', mb: 0.5 }}>Aggregator Output (Verdict)</Typography>
                                            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto', background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6 }}>
                                                {JSON.stringify(verdict, null, 2)}
                                            </pre>
                                        </Box>
                                    )}
                                    {tab === 'signals' && (
                                        <Box>
                                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', mb: 0.5 }}>Signal Graph</Typography>
                                            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto', background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6 }}>
                                                {JSON.stringify(verdict.signal_graph, null, 2)}
                                            </pre>
                                        </Box>
                                    )}
                                    {tab === 'reasoning' && (
                                        <Box>
                                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', mb: 0.5 }}>Reasoning Data</Typography>
                                            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto', background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6 }}>
                                                {JSON.stringify({ intent: verdict.intent, reasoning: verdict.reasoning }, null, 2)}
                                            </pre>
                                        </Box>
                                    )}
                                    {tab === 'mitre' && (
                                        <Box>
                                            <Typography sx={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', mb: 0.5 }}>MITRE Mappings</Typography>
                                            <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto', background: 'var(--bg-primary)', padding: '12px', border: '1px solid var(--border)', borderRadius: 6 }}>
                                                {JSON.stringify(verdict.mitre_techniques, null, 2)}
                                            </pre>
                                        </Box>
                                    )}
                                </Box>
                            ) : (
                                <>
                                    {tab === 'verdict' && <VerdictPanel verdict={verdict} />}
                                    {tab === 'signals' && <SignalsSection verdict={verdict} />}
                                    {tab === 'macros' && <MacrosSection verdict={verdict} />}
                                    {tab === 'reasoning' && <ReasoningSection verdict={verdict} />}
                                    {tab === 'mitre' && <MitreSection verdict={verdict} />}
                                </>
                            )}
                        </Box>
                    </>
                )
            }

            {
                status === 'idle' && !verdict && (
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1, flexDirection: 'column', gap: 1 }}>
                        <PsychologyIcon sx={{ fontSize: 36, color: 'var(--text-muted)', opacity: 0.4 }} />
                        <Typography sx={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            Click Run Analysis to start the agentic pipeline
                        </Typography>
                    </Box>
                )
            }
        </Box >
    );
}
