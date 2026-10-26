import { Box, Typography, Chip, Alert } from '@mui/material';

const SOURCE_COLORS = {
    entry: { bg: 'var(--accent-dim)', color: 'var(--accent)' },
    macro: { bg: 'rgba(245,158,11,0.12)', color: 'var(--warning)' },
    url: { bg: 'rgba(16,185,129,0.1)', color: 'var(--success)' },
    relationship: { bg: 'rgba(167,139,250,0.12)', color: '#a78bfa' },
};

export default function SearchResults({ results, onSelect }) {
    if (!results) return null;

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
            <Box sx={{ px: 2, py: 1.5, borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 }}>
                <Typography sx={{ fontSize: 13, fontWeight: 600 }}>
                    Search: <span style={{ color: 'var(--accent)' }}>"{results.query}"</span>
                    <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
                        {results.total} result{results.total !== 1 ? 's' : ''}
                    </span>
                </Typography>
            </Box>

            <Box sx={{ flex: 1, overflow: 'auto', p: 1.5 }}>
                {results.error && <Alert severity="error" sx={{ mb: 1.5 }}>{results.error}</Alert>}
                {results.total === 0 && (
                    <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', mt: 4 }}>No results found</Typography>
                )}
                {(results.results || []).map((r, i) => {
                    const colors = SOURCE_COLORS[r.source] || SOURCE_COLORS.entry;
                    return (
                        <Box
                            key={i}
                            onClick={() => r.path !== 'urls' && onSelect(r.path)}
                            sx={{
                                p: 1.5, mb: 1, borderRadius: 1, border: '1px solid var(--border)',
                                background: 'var(--bg-card)',
                                cursor: r.path !== 'urls' ? 'pointer' : 'default',
                                '&:hover': r.path !== 'urls' ? { borderColor: 'var(--accent)', background: 'var(--accent-dim)' } : {},
                                transition: 'all 0.15s',
                            }}
                        >
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.5 }}>
                                <Chip label={r.source} size="small"
                                    sx={{ height: 18, fontSize: 10, fontWeight: 700, background: colors.bg, color: colors.color, border: `1px solid ${colors.color}30` }}
                                />
                                <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                                    {r.path}
                                </Typography>
                                {r.module && <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>Module: {r.module}</Typography>}
                            </Box>
                            <Box sx={{ p: 1, borderRadius: 0.5, background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                                <Typography sx={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 80, overflow: 'hidden' }}>
                                    {r.snippet}
                                </Typography>
                            </Box>
                        </Box>
                    );
                })}
            </Box>
        </Box>
    );
}
