import { Box, Typography, IconButton } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { useNavigate } from 'react-router-dom';
import EvaluationPanel from '../components/EvaluationPanel';

export default function EvaluationPage() {
    const navigate = useNavigate();

    return (
        <Box sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
            <Box sx={{
                px: 3, py: 2, display: 'flex', alignItems: 'center', gap: 2,
                borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)',
                position: 'sticky', top: 0, zIndex: 10
            }}>
                <IconButton onClick={() => navigate('/')} size="small" sx={{ color: 'var(--text-secondary)' }}>
                    <ArrowBackIcon />
                </IconButton>
                <Box>
                    <Typography variant="h6" sx={{ fontSize: 16, fontWeight: 600 }}>
                        Batch Evaluation Dashboard
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'var(--text-muted)' }}>
                        Evaluate Agentic Engine performance on Clean vs Malicious datasets
                    </Typography>
                </Box>
            </Box>

            <Box sx={{ flex: 1, p: 4, overflow: 'auto' }}>
                <EvaluationPanel />
            </Box>
        </Box>
    );
}
