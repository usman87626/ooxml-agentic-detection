import { useState, useEffect } from 'react';
import { Dialog, DialogTitle, DialogContent, DialogActions, Button, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography, CircularProgress, IconButton, Box } from '@mui/material';
import FolderIcon from '@mui/icons-material/Folder';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import { getEvaluationLs } from '../api/client';

export default function FileBrowserDialog({ open, onClose, onSelect, title }) {
    const [currentPath, setCurrentPath] = useState('');
    const [parentPath, setParentPath] = useState(null);
    const [directories, setDirectories] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const loadDirs = async (path = null) => {
        setLoading(true);
        setError('');
        try {
            const data = await getEvaluationLs(path);
            setCurrentPath(data.current_path);
            setParentPath(data.parent_path);
            setDirectories(data.directories);
        } catch (err) {
            setError(err.response?.data?.detail || err.message);
        } finally {
            setLoading(false);
        }
    };

    // Load initial on open
    useEffect(() => {
        if (open) {
            loadDirs();
        }
    }, [open]);

    const handleSelect = () => {
        onSelect(currentPath);
        onClose();
    };

    return (
        <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth PaperProps={{ sx: { background: 'var(--bg-secondary)', backgroundImage: 'none', border: '1px solid var(--border)' } }}>
            <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, borderBottom: '1px solid var(--border)', pb: 1.5 }}>
                <FolderIcon sx={{ color: 'primary.main' }} /> {title || 'Select Directory'}
            </DialogTitle>
            <DialogContent sx={{ p: 0, minHeight: 300, display: 'flex', flexDirection: 'column' }}>
                <Box sx={{ p: 1.5, background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 1 }}>
                    <IconButton size="small" disabled={!parentPath || loading} onClick={() => loadDirs(parentPath)}>
                        <ArrowUpwardIcon fontSize="small" />
                    </IconButton>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 13, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={currentPath}>
                        {currentPath}
                    </Typography>
                </Box>

                {loading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flex: 1 }}>
                        <CircularProgress size={24} />
                    </Box>
                ) : error ? (
                    <Box sx={{ p: 3, textAlign: 'center' }}>
                        <Typography color="error" variant="body2">{error}</Typography>
                    </Box>
                ) : (
                    <List sx={{ flex: 1, overflowY: 'auto', p: 0 }}>
                        {directories.length === 0 ? (
                            <ListItem>
                                <ListItemText primary={<Typography variant="body2" color="text.secondary">No subdirectories</Typography>} />
                            </ListItem>
                        ) : (
                            directories.map(dir => (
                                <ListItem
                                    key={dir.path}
                                    disablePadding
                                    sx={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                                >
                                    <ListItemButton
                                        onClick={() => loadDirs(dir.path)}
                                        sx={{ '&:hover': { background: 'rgba(255,255,255,0.05)' } }}
                                    >
                                        <ListItemIcon sx={{ minWidth: 36 }}>
                                            <FolderIcon sx={{ color: '#fbbf24', fontSize: 20 }} />
                                        </ListItemIcon>
                                        <ListItemText primary={<Typography variant="body2">{dir.name}</Typography>} />
                                        <ChevronRightIcon fontSize="small" sx={{ color: 'var(--text-muted)' }} />
                                    </ListItemButton>
                                </ListItem>
                            ))
                        )}
                    </List>
                )}
            </DialogContent>
            <DialogActions sx={{ borderTop: '1px solid var(--border)', p: 2 }}>
                <Button onClick={onClose} sx={{ color: 'var(--text-secondary)' }}>Cancel</Button>
                <Button variant="contained" onClick={handleSelect} disabled={loading || !!error}>Select Current Folder</Button>
            </DialogActions>
        </Dialog>
    );
}
