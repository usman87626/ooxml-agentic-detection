import { useState, useEffect, useRef } from 'react';
import { Box, Typography, TextField, Button, CircularProgress, Paper, Grid, Table, TableBody, TableCell, TableHead, TableRow, IconButton, Link as MuiLink, Tooltip } from '@mui/material';
import { Link } from 'react-router-dom';
import { XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, CartesianGrid, AreaChart, Area, Line } from 'recharts';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import DeleteIcon from '@mui/icons-material/Delete';
import StorageIcon from '@mui/icons-material/Storage';
import { startEvaluation, getEvaluationStatus, listEvaluations, getEvaluationReport, deleteEvaluationReport, resumeEvaluation } from '../api/client';

import FileBrowserDialog from './FileBrowserDialog';

export default function EvaluationPanel() {
    const [cleanPath, setCleanPath] = useState('');
    const [maliciousPath, setMaliciousPath] = useState('');
    const [evalId, setEvalId] = useState(null);
    const [status, setStatus] = useState(null);
    const [polling, setPolling] = useState(false);
    const [error, setError] = useState('');

    const [pickerOpen, setPickerOpen] = useState(false);
    const [activeField, setActiveField] = useState(null); // 'clean' or 'malicious'

    const [reportName, setReportName] = useState('');
    const [reports, setReports] = useState([]);

    const fetchReports = async () => {
        try {
            const data = await listEvaluations();
            setReports(data || []);
        } catch (e) {
            console.error("Failed to load reports", e);
        }
    };

    useEffect(() => {
        let mounted = true;
        const init = async () => {
            const data = await listEvaluations();
            if (mounted) setReports(data || []);
        };
        init();
        return () => { mounted = false; };
    }, []);

    const handleLoadReport = async (id) => {
        try {
            const data = await getEvaluationReport(id);
            setStatus(data);
            setEvalId(id);
            setPolling(false);
        } catch (e) {
            console.error(e);
        }
    };

    const handleDeleteReport = async (id) => {
        try {
            await deleteEvaluationReport(id);
            fetchReports();
            if (id === evalId) {
                setStatus(null);
                setEvalId(null);
            }
        } catch (e) {
            console.error(e);
        }
    };

    const handleStart = async () => {
        if (!cleanPath || !maliciousPath) {
            setError('Please provide both paths');
            return;
        }
        setError('');
        try {
            const res = await startEvaluation(cleanPath, maliciousPath, reportName);
            setEvalId(res.eval_id);
            setPolling(true);
        } catch (err) {
            setError(err.response?.data?.detail || err.message);
        }
    };

    const handleResume = async (id, cPath, mPath) => {
        setError('');
        try {
            await resumeEvaluation(id, cPath, mPath || cleanPath, mPath || maliciousPath);
            setEvalId(id);
            setPolling(true);
        } catch (err) {
            setError(err.response?.data?.detail || err.message);
        }
    };

    const openPicker = (field) => {
        setActiveField(field);
        setPickerOpen(true);
    };

    const handleFolderSelect = (path) => {
        if (activeField === 'clean') setCleanPath(path);
        else if (activeField === 'malicious') setMaliciousPath(path);
    };

    const pollErrors = useRef(0);

    useEffect(() => {
        let interval;
        if (polling && evalId) {
            pollErrors.current = 0;
            interval = setInterval(async () => {
                try {
                    const res = await getEvaluationStatus(evalId);
                    pollErrors.current = 0; // reset on success
                    setStatus(res);
                    if (res.status === 'done' || res.status === 'error') {
                        setPolling(false);
                        clearInterval(interval);
                        fetchReports();
                    }
                } catch (err) {
                    pollErrors.current += 1;
                    if (pollErrors.current >= 5) {
                        setError('Error polling status: ' + (err.response?.data?.detail || err.message));
                        setPolling(false);
                        clearInterval(interval);
                    }
                }
            }, 2000);
        }
        return () => clearInterval(interval);
    }, [polling, evalId]);

    const renderChartPanels = () => {
        if (!status || !status.metrics) return null;

        const m = status.metrics;



        const { TP, TN, FP, FN } = m.confusion_matrix;
        const total = TP + TN + FP + FN;

        // Calculate derived metrics
        const precision = TP + FP > 0 ? (TP / (TP + FP)) : 0;
        const recall = TP + FN > 0 ? (TP / (TP + FN)) : 0;
        const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
        const fpr = FP + TN > 0 ? (FP / (FP + TN)) : 0;
        const fnr = FN + TP > 0 ? (FN / (FN + TP)) : 0;
        const accuracy = total > 0 ? ((TP + TN) / total) : 0;

        // --- Calculate ROC & AUC ---
        let auc = 0;
        let rocData = [];
        if (m.roc_points && m.roc_points.length > 0) {
            const sortedPoints = [...m.roc_points].sort((a, b) => b.risk_score - a.risk_score);
            let totalPos = sortedPoints.filter(p => p.true_label === 1).length;
            let totalNeg = sortedPoints.filter(p => p.true_label === 0).length;

            if (totalPos > 0 && totalNeg > 0) {
                let tp = 0;
                let fp = 0;
                let prevFpr = 0;
                let prevTpr = 0;

                rocData.push({ fpr: 0, tpr: 0, baseline: 0 }); // Origin

                for (let i = 0; i < sortedPoints.length; i++) {
                    if (sortedPoints[i].true_label === 1) tp++;
                    else fp++;

                    // Standard ROC: Only push point when score changes or list ends
                    if (i === sortedPoints.length - 1 || sortedPoints[i].risk_score !== sortedPoints[i + 1].risk_score) {
                        let curFpr = fp / totalNeg;
                        let curTpr = tp / totalPos;

                        // Trapezoidal rule for AUC
                        auc += ((curFpr - prevFpr) * (curTpr + prevTpr)) / 2;

                        rocData.push({
                            fpr: Number(curFpr.toFixed(3)),
                            tpr: Number(curTpr.toFixed(3)),
                            threshold: sortedPoints[i].risk_score,
                            baseline: Number(curFpr.toFixed(3))
                        });
                        prevFpr = curFpr;
                        prevTpr = curTpr;
                    }
                }
                rocData.push({ fpr: 1, tpr: 1, baseline: 1 }); // Endpoint
            }
        }

        let aucInterpretation = "Random";
        if (auc >= 0.9) aucInterpretation = "Excellent";
        else if (auc >= 0.8) aucInterpretation = "Strong";
        else if (auc >= 0.7) aucInterpretation = "Acceptable";

        // --- Calculate Top 5 MITRE & Features (Separated) ---
        const getTop = (counts) => Object.entries(counts || {})
            .map(([name, value]) => ({ name: name.split(':')[0], fullName: name, value }))
            .sort((a, b) => b.value - a.value).slice(0, 5);

        const mitreMalicious = getTop(m.mitre_counts_malicious);
        const mitreClean = getTop(m.mitre_counts_clean);
        const featureMalicious = getTop(m.feature_counts_malicious);
        const featureClean = getTop(m.feature_counts_clean);

        const maxMaliMitre = mitreMalicious.length > 0 ? mitreMalicious[0].value : 1;
        const maxMaliFeat = featureMalicious.length > 0 ? featureMalicious[0].value : 1;
        const maxCleanMitre = mitreClean.length > 0 ? mitreClean[0].value : 1;
        const maxCleanFeat = featureClean.length > 0 ? featureClean[0].value : 1;
        return (
            <Grid container spacing={3} sx={{ mt: 2 }}>
                <Grid size={{ xs: 12, md: 6 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', height: '100%', display: 'flex', flexDirection: 'column' }}>
                        <Typography variant="subtitle2" sx={{ mb: 2 }}>Confusion Matrix</Typography>
                        <Box sx={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', p: 1 }}>
                            <Table size="small" sx={{
                                '& td, & th': { border: '1px solid var(--border)' },
                                '& th': { background: 'rgba(255,255,255,0.02)' }
                            }}>
                                <TableHead>
                                    <TableRow>
                                        <TableCell sx={{ border: 'none !important', background: 'transparent !important' }}></TableCell>
                                        <TableCell align="center" sx={{ color: 'var(--text-muted)' }}>
                                            <Typography variant="caption" sx={{ fontWeight: 'bold' }}>Predicted<br />Malicious</Typography>
                                        </TableCell>
                                        <TableCell align="center" sx={{ color: 'var(--text-muted)' }}>
                                            <Typography variant="caption" sx={{ fontWeight: 'bold' }}>Predicted<br />Clean</Typography>
                                        </TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    <TableRow>
                                        <TableCell align="center" sx={{ background: 'rgba(255,255,255,0.02)' }}>
                                            <Typography variant="caption" sx={{ color: 'var(--text-muted)', fontWeight: 'bold' }}>Actual<br />Malicious</Typography>
                                        </TableCell>
                                        <TableCell align="center" sx={{ background: 'rgba(16, 185, 129, 0.05)', border: '2px solid #10b981 !important' }}>
                                            <Typography variant="h5" sx={{ color: '#10b981', fontWeight: 'bold' }}>{m.confusion_matrix.TP}</Typography>
                                            <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>True Positive</Typography>
                                        </TableCell>
                                        <TableCell align="center" sx={{ background: 'rgba(239, 68, 68, 0.05)' }}>
                                            <Typography variant="h5" sx={{ color: '#ef4444', fontWeight: 'bold' }}>{m.confusion_matrix.FN}</Typography>
                                            <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>False Negative</Typography>
                                        </TableCell>
                                    </TableRow>
                                    <TableRow>
                                        <TableCell align="center" sx={{ background: 'rgba(255,255,255,0.02)' }}>
                                            <Typography variant="caption" sx={{ color: 'var(--text-muted)', fontWeight: 'bold' }}>Actual<br />Clean</Typography>
                                        </TableCell>
                                        <TableCell align="center" sx={{ background: 'rgba(245, 158, 11, 0.05)' }}>
                                            <Typography variant="h5" sx={{ color: '#f59e0b', fontWeight: 'bold' }}>{m.confusion_matrix.FP}</Typography>
                                            <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>False Positive</Typography>
                                        </TableCell>
                                        <TableCell align="center" sx={{ background: 'rgba(59, 130, 246, 0.05)', border: '2px solid #3b82f6 !important' }}>
                                            <Typography variant="h5" sx={{ color: '#3b82f6', fontWeight: 'bold' }}>{m.confusion_matrix.TN}</Typography>
                                            <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>True Negative</Typography>
                                        </TableCell>
                                    </TableRow>
                                </TableBody>
                            </Table>
                        </Box>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                            <Typography variant="subtitle2">ROC Curve</Typography>
                            <Box sx={{ textAlign: 'right' }}>
                                <Typography variant="h6" sx={{ color: auc >= 0.8 ? '#10b981' : (auc >= 0.7 ? '#f59e0b' : '#ef4444'), lineHeight: 1 }}>{auc.toFixed(3)}</Typography>
                                <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>AUC ({aucInterpretation})</Typography>
                            </Box>
                        </Box>
                        <Box sx={{ height: 215, flex: 1 }}>
                            {rocData.length > 0 ? (
                                <ResponsiveContainer width="100%" height="100%">
                                    <AreaChart data={rocData} margin={{ top: 5, right: 20, left: -20, bottom: 5 }}>
                                        <defs>
                                            <linearGradient id="colorTpr" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                            </linearGradient>
                                        </defs>
                                        <XAxis dataKey="fpr" type="number" domain={[0, 1]} tickCount={5} stroke="#94a3b8" fontSize={12} label={{ value: 'False Positive Rate', position: 'insideBottom', offset: -5, fill: '#94a3b8', fontSize: 11 }} />
                                        <YAxis dataKey="tpr" type="number" domain={[0, 1]} tickCount={5} stroke="#94a3b8" fontSize={12} label={{ value: 'True Positive Rate', angle: -90, position: 'insideLeft', fill: '#94a3b8', fontSize: 11 }} />
                                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                        <RechartsTooltip
                                            contentStyle={{ background: '#1e293b', border: 'none', color: '#fff' }}
                                            labelFormatter={(v) => `FPR: ${v}`}
                                            formatter={(val, name, props) => {
                                                if (name === 'tpr') return [val, 'True Positive Rate'];
                                                if (props.payload.threshold !== undefined) return [props.payload.threshold, 'Risk Threshold'];
                                                return [val, name];
                                            }}
                                        />
                                        <Area type="monotone" dataKey="tpr" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorTpr)" isAnimationActive={false} />
                                        <Line type="linear" dataKey="baseline" stroke="rgba(255,255,255,0.2)" strokeDasharray="5 5" dot={false} isAnimationActive={false} strokeWidth={1} />
                                    </AreaChart>
                                </ResponsiveContainer>
                            ) : (
                                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Not enough data for ROC</Typography>
                                </Box>
                            )}
                        </Box>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12 }}>
                    <Typography variant="overline" sx={{ color: 'var(--danger)', fontWeight: 'bold', display: 'block', mb: -1, ml: 1 }}>Malicious Dataset Insights</Typography>
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
                        <Typography variant="subtitle2" sx={{ mb: 2 }}>Top MITRE Tags (Malicious)</Typography>
                        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1.5, justifyContent: 'center' }}>
                            {mitreMalicious.length > 0 ? mitreMalicious.map((d, i) => (
                                <Box key={i} sx={{ width: '100%', position: 'relative' }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                        <Typography variant="caption" sx={{ color: '#e2e8f0', zIndex: 1, fontSize: 11 }}>{d.fullName}</Typography>
                                        <Typography variant="caption" sx={{ color: 'var(--text-muted)', zIndex: 1 }}>{d.value}</Typography>
                                    </Box>
                                    <Box sx={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 1, overflow: 'hidden' }}>
                                        <Box sx={{ width: `${(d.value / maxMaliMitre) * 100}%`, height: '100%', background: '#f43f5e', borderRadius: 1 }} />
                                    </Box>
                                </Box>
                            )) : (
                                <Typography variant="caption" sx={{ color: 'var(--text-muted)', textAlign: 'center' }}>No MITRE tags observed.</Typography>
                            )}
                        </Box>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
                        <Typography variant="subtitle2" sx={{ mb: 2 }}>Top Feature Occurrences (Malicious)</Typography>
                        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1.5, justifyContent: 'center' }}>
                            {featureMalicious.length > 0 ? featureMalicious.map((d, i) => (
                                <Box key={i} sx={{ width: '100%', position: 'relative' }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                        <Typography variant="caption" sx={{ color: '#e2e8f0', zIndex: 1 }}>{d.fullName}</Typography>
                                        <Typography variant="caption" sx={{ color: 'var(--text-muted)', zIndex: 1 }}>{d.value}</Typography>
                                    </Box>
                                    <Box sx={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 1, overflow: 'hidden' }}>
                                        <Box sx={{ width: `${(d.value / maxMaliFeat) * 100}%`, height: '100%', background: '#8b5cf6', borderRadius: 1 }} />
                                    </Box>
                                </Box>
                            )) : (
                                <Typography variant="caption" sx={{ color: 'var(--text-muted)', textAlign: 'center' }}>No features observed.</Typography>
                            )}
                        </Box>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12 }}>
                    <Typography variant="overline" sx={{ color: 'var(--success)', fontWeight: 'bold', display: 'block', mb: -1, ml: 1 }}>Clean Dataset Insights</Typography>
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
                        <Typography variant="subtitle2" sx={{ mb: 2 }}>Top MITRE Tags (Clean)</Typography>
                        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1.5, justifyContent: 'center' }}>
                            {mitreClean.length > 0 ? mitreClean.map((d, i) => (
                                <Box key={i} sx={{ width: '100%', position: 'relative' }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                        <Typography variant="caption" sx={{ color: '#e2e8f0', zIndex: 1, fontSize: 11 }}>{d.fullName}</Typography>
                                        <Typography variant="caption" sx={{ color: 'var(--text-muted)', zIndex: 1 }}>{d.value}</Typography>
                                    </Box>
                                    <Box sx={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 1, overflow: 'hidden' }}>
                                        <Box sx={{ width: `${(d.value / maxCleanMitre) * 100}%`, height: '100%', background: '#10b981', borderRadius: 1 }} />
                                    </Box>
                                </Box>
                            )) : (
                                <Typography variant="caption" sx={{ color: 'var(--text-muted)', textAlign: 'center' }}>No MITRE tags observed.</Typography>
                            )}
                        </Box>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
                        <Typography variant="subtitle2" sx={{ mb: 2 }}>Top Feature Occurrences (Clean)</Typography>
                        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 1.5, justifyContent: 'center' }}>
                            {featureClean.length > 0 ? featureClean.map((d, i) => (
                                <Box key={i} sx={{ width: '100%', position: 'relative' }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                                        <Typography variant="caption" sx={{ color: '#e2e8f0', zIndex: 1 }}>{d.fullName}</Typography>
                                        <Typography variant="caption" sx={{ color: 'var(--text-muted)', zIndex: 1 }}>{d.value}</Typography>
                                    </Box>
                                    <Box sx={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 1, overflow: 'hidden' }}>
                                        <Box sx={{ width: `${(d.value / maxCleanFeat) * 100}%`, height: '100%', background: '#3b82f6', borderRadius: 1 }} />
                                    </Box>
                                </Box>
                            )) : (
                                <Typography variant="caption" sx={{ color: 'var(--text-muted)', textAlign: 'center' }}>No features observed.</Typography>
                            )}
                        </Box>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12, md: 2 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', textAlign: 'center' }}>
                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Total Samples</Typography>
                        <Typography variant="h4" sx={{ color: 'var(--text-primary)', mt: 1 }}>{m.total_samples || 0}</Typography>
                    </Paper>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', textAlign: 'center' }}>
                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Actual Clean</Typography>
                        <Typography variant="h4" sx={{ color: '#3b82f6', mt: 1 }}>{m.total_clean || 0}</Typography>
                    </Paper>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', textAlign: 'center' }}>
                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Actual Malicious</Typography>
                        <Typography variant="h4" sx={{ color: '#ef4444', mt: 1 }}>{m.total_malicious || 0}</Typography>
                    </Paper>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', textAlign: 'center' }}>
                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Require Net (Mal)</Typography>
                        <Typography variant="h4" sx={{ color: '#10b981', mt: 1 }}>{m.require_network_malicious}</Typography>
                    </Paper>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', textAlign: 'center' }}>
                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Require Net (Clean)</Typography>
                        <Typography variant="h4" sx={{ color: '#f59e0b', mt: 1 }}>{m.require_network_clean}</Typography>
                    </Paper>
                </Grid>
                <Grid size={{ xs: 12, md: 2 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)', textAlign: 'center' }}>
                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Errored Files</Typography>
                        <Typography variant="h4" sx={{ color: '#71717a', mt: 1 }}>{m.error_count || 0}</Typography>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12 }}>
                    <Paper sx={{ p: 2, background: 'var(--bg-tertiary)', border: '1px solid var(--border)' }}>
                        <Typography variant="subtitle2" sx={{ mb: 2 }}>Classification Metrics</Typography>
                        <Grid container spacing={2}>
                            <Grid size={{ xs: 6, sm: 4, md: 2 }}>
                                <Box sx={{ textAlign: 'center' }}>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Avg Latency</Typography>
                                    <Typography variant="h6" sx={{ color: 'var(--text-primary)' }}>{m.avg_time.toFixed(2)}s</Typography>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)', fontSize: 10, display: 'block', mt: -0.5 }}>Min: {m.min_time === Infinity ? 0 : m.min_time.toFixed(2)}s | Max: {m.max_time.toFixed(2)}s</Typography>
                                </Box>
                            </Grid>
                            <Grid size={{ xs: 6, sm: 4, md: 2 }}>
                                <Box sx={{ textAlign: 'center' }}>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Accuracy</Typography>
                                    <Typography variant="h6" sx={{ color: 'var(--text-primary)' }}>{(accuracy * 100).toFixed(1)}%</Typography>
                                </Box>
                            </Grid>
                            <Grid size={{ xs: 6, sm: 4, md: 1.6 }}>
                                <Box sx={{ textAlign: 'center' }}>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Precision</Typography>
                                    <Typography variant="h6" sx={{ color: '#10b981' }}>{(precision * 100).toFixed(1)}%</Typography>
                                </Box>
                            </Grid>
                            <Grid size={{ xs: 6, sm: 4, md: 1.6 }}>
                                <Box sx={{ textAlign: 'center' }}>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Recall (TPR)</Typography>
                                    <Typography variant="h6" sx={{ color: '#3b82f6' }}>{(recall * 100).toFixed(1)}%</Typography>
                                </Box>
                            </Grid>
                            <Grid size={{ xs: 6, sm: 4, md: 1.6 }}>
                                <Box sx={{ textAlign: 'center' }}>
                                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>F1-Score</Typography>
                                    <Typography variant="h6" sx={{ color: '#8b5cf6' }}>{(f1 * 100).toFixed(1)}%</Typography>
                                </Box>
                            </Grid>
                            <Grid size={{ xs: 6, sm: 4, md: 1.6 }}>
                                <Tooltip title="False Positive Rate = FP / (FP + TN)" arrow>
                                    <Box sx={{ textAlign: 'center', cursor: 'help' }}>
                                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>FPR ⓘ</Typography>
                                        <Typography variant="h6" sx={{ color: '#f59e0b' }}>{(fpr * 100).toFixed(1)}%</Typography>
                                    </Box>
                                </Tooltip>
                            </Grid>
                            <Grid size={{ xs: 6, sm: 4, md: 1.6 }}>
                                <Tooltip title="False Negative Rate = FN / (FN + TP)" arrow>
                                    <Box sx={{ textAlign: 'center', cursor: 'help' }}>
                                        <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>FNR ⓘ</Typography>
                                        <Typography variant="h6" sx={{ color: '#ef4444' }}>{(fnr * 100).toFixed(1)}%</Typography>
                                    </Box>
                                </Tooltip>
                            </Grid>
                        </Grid>
                    </Paper>
                </Grid>

                <Grid size={{ xs: 12 }}>
                    <Paper sx={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', overflow: 'hidden' }}>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>File</TableCell>
                                    <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>True Label</TableCell>
                                    <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>Predicted</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {status.results?.map((r, i) => (
                                    <TableRow key={i} sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                                        <TableCell>
                                            {r.workspace_id ? (
                                                <MuiLink component={Link} to={`/workspace/${r.workspace_id}`} target="_blank" sx={{ fontSize: 12, wordBreak: 'break-all', textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}>
                                                    {r.filename}
                                                </MuiLink>
                                            ) : (
                                                <Typography sx={{ fontSize: 12, wordBreak: 'break-all' }}>{r.filename}</Typography>
                                            )}
                                        </TableCell>
                                        <TableCell><Typography sx={{ fontSize: 12, textTransform: 'uppercase' }}>{r.true_label}</Typography></TableCell>
                                        <TableCell>
                                            <Typography sx={{
                                                fontSize: 12,
                                                color: r.predicted_verdict === (r.true_label.toUpperCase() === 'MALICIOUS' ? 'MALICIOUS' : 'CLEAN') ? 'var(--success)' : 'var(--danger)'
                                            }}>
                                                {r.predicted_verdict}
                                            </Typography>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </Paper>
                </Grid>
            </Grid>
        );
    };

    return (
        <Box sx={{ maxWidth: 1000, margin: '0 auto' }}>
            <Paper sx={{ p: 3, mb: 4, background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>1. Provide Dataset Paths</Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid size={{ xs: 12, md: 5 }}>
                        <TextField
                            label="Clean OOXML Directory Path"
                            variant="outlined"
                            size="small"
                            fullWidth
                            value={cleanPath}
                            onChange={(e) => setCleanPath(e.target.value)}
                            disabled={polling}
                            InputProps={{
                                readOnly: true,
                                endAdornment: (
                                    <Button size="small" variant="contained" disabled={polling} onClick={() => openPicker('clean')} sx={{ minWidth: 'auto', whiteSpace: 'nowrap' }}>
                                        Browse...
                                    </Button>
                                )
                            }}
                        />
                    </Grid>
                    <Grid size={{ xs: 12, md: 5 }}>
                        <TextField
                            label="Malicious OOXML Directory Path"
                            variant="outlined"
                            size="small"
                            fullWidth
                            value={maliciousPath}
                            onChange={(e) => setMaliciousPath(e.target.value)}
                            disabled={polling}
                            InputProps={{
                                readOnly: true,
                                endAdornment: (
                                    <Button size="small" variant="contained" disabled={polling} onClick={() => openPicker('malicious')} sx={{ minWidth: 'auto', whiteSpace: 'nowrap' }}>
                                        Browse...
                                    </Button>
                                )
                            }}
                        />
                    </Grid>
                    <Grid size={{ xs: 12, md: 2 }}>
                        <TextField
                            label="Report Name"
                            variant="outlined"
                            size="small"
                            fullWidth
                            value={reportName}
                            onChange={(e) => setReportName(e.target.value)}
                            disabled={polling}
                            placeholder="Optional"
                        />
                    </Grid>
                </Grid>
                <Button
                    variant="contained"
                    startIcon={<PlayArrowIcon />}
                    disabled={polling || !cleanPath || !maliciousPath}
                    onClick={handleStart}
                    sx={{ mt: 1 }}
                >
                    Start Loop
                </Button>
                {error && <Typography sx={{ color: 'var(--danger)', mt: 2, fontSize: 13 }}>{error}</Typography>}
            </Paper>

            {(polling || status) && (
                <Paper sx={{ p: 3, mb: 4, background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                            2. Execution Progress {polling && <CircularProgress size={14} sx={{ ml: 1, verticalAlign: 'middle' }} />}
                        </Typography>
                        {status && <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>
                            Processed: {status.progress.current} / {status.progress.total}
                        </Typography>}
                    </Box>

                    {renderChartPanels()}
                </Paper>
            )}

            <Paper sx={{ p: 3, background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>3. Saved Evaluation Reports</Typography>
                {reports.length === 0 ? (
                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>No reports saved yet.</Typography>
                ) : (
                    <Table size="small" sx={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)' }}>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>Name</TableCell>
                                <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>Created At</TableCell>
                                <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>Total Files</TableCell>
                                <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }}>Accuracy</TableCell>
                                <TableCell sx={{ color: 'var(--text-muted)', fontSize: 12 }} align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {reports.map((r) => (
                                <TableRow key={r.eval_id} sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                                    <TableCell><Typography sx={{ fontSize: 13, fontWeight: 'bold' }}>{r.report_name}</Typography></TableCell>
                                    <TableCell><Typography sx={{ fontSize: 12 }}>{new Date(r.created_at).toLocaleString()}</Typography></TableCell>
                                    <TableCell><Typography sx={{ fontSize: 12 }}>{r.total_files}</Typography></TableCell>
                                    <TableCell>
                                        <Typography sx={{ fontSize: 12, color: r.status === 'done' ? 'var(--success)' : 'var(--warning)' }}>
                                            {r.status === 'done' ? (r.accuracy || '0%') : `${r.status} (${r.current_files}/${r.total_files})`}
                                        </Typography>
                                    </TableCell>
                                    <TableCell align="right">
                                        {r.status !== 'done' ? (
                                            <Button
                                                size="small"
                                                variant="contained"
                                                color="success"
                                                startIcon={<PlayArrowIcon />}
                                                onClick={() => handleResume(r.eval_id, r.clean_path || cleanPath, r.malicious_path || maliciousPath)}
                                                sx={{ mr: 1, fontSize: 10, py: 0 }}
                                            >
                                                RESUME
                                            </Button>
                                        ) : (
                                            <IconButton size="small" onClick={() => handleLoadReport(r.eval_id)} sx={{ color: '#3b82f6', mr: 1 }} title="Load Report">
                                                <StorageIcon fontSize="small" />
                                            </IconButton>
                                        )}
                                        <IconButton size="small" onClick={() => handleDeleteReport(r.eval_id)} sx={{ color: '#ef4444' }} title="Delete Report">
                                            <DeleteIcon fontSize="small" />
                                        </IconButton>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                )}
            </Paper>

            <FileBrowserDialog
                open={pickerOpen}
                onClose={() => setPickerOpen(false)}
                onSelect={handleFolderSelect}
                title={activeField === 'clean' ? 'Select Clean Dataset Folder' : 'Select Malicious Dataset Folder'}
            />
        </Box>
    );
}
