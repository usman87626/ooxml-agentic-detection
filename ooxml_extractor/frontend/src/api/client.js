// src/api/client.js — axios wrappers for all backend endpoints (v3)

import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: BASE_URL, timeout: 120000 });

export async function uploadDocument(file, autoAnalyze = false, onProgress) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('auto_analyze', autoAnalyze);
    const response = await api.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (e) => { if (onProgress && e.total) onProgress(Math.round((e.loaded * 100) / e.total)); },
    });
    return response.data;
}

export async function uploadBulkDocuments(files, autoAnalyze = false) {
    const formData = new FormData();
    for (const file of files) {
        formData.append('files', file);
    }
    formData.append('auto_analyze', autoAnalyze);
    const response = await api.post('/api/upload-bulk', formData, {
        headers: {
            'Content-Type': 'multipart/form-data'
        }
    });
    return response.data;
}

export async function listWorkspaces() {
    const response = await api.get('/api/workspaces');
    return response.data;
}

export async function deleteWorkspace(workspaceId) {
    const response = await api.delete(`/api/workspaces/${workspaceId}`);
    return response.data;
}

export async function getStatus(workspaceId) {
    const response = await api.get(`/api/workspaces/${workspaceId}/status`);
    return response.data;
}

export async function getManifest(workspaceId) {
    const response = await api.get(`/api/workspaces/${workspaceId}/manifest`);
    return response.data;
}

export async function getAnalysisComponent(workspaceId, component) {
    const response = await api.get(`/api/workspaces/${workspaceId}/analysis/${component}`);
    return response.data;
}

export async function getImages(workspaceId) {
    const response = await api.get(`/api/workspaces/${workspaceId}/images`);
    return response.data;
}

export function getImageUrl(workspaceId, filename) {
    return `${BASE_URL}/api/workspaces/${workspaceId}/images/${encodeURIComponent(filename)}`;
}

export async function getEntries(workspaceId, { kind, role, limit = 500, offset = 0 } = {}) {
    const params = { limit, offset };
    if (kind) params.kind = kind;
    if (role) params.role = role;
    const response = await api.get(`/api/workspaces/${workspaceId}/entries`, { params });
    return response.data;
}

export function getFileDownloadUrl(workspaceId, path) {
    return `${BASE_URL}/api/workspaces/${workspaceId}/file?path=${encodeURIComponent(path)}`;
}

export async function getPreview(workspaceId, path) {
    const response = await api.get(`/api/workspaces/${workspaceId}/preview`, { params: { path } });
    return response.data;
}

export async function search(workspaceId, query) {
    const response = await api.get(`/api/workspaces/${workspaceId}/search`, { params: { q: query } });
    return response.data;
}

export async function startAnalysis(workspaceId, forceRerun = false) {
    const response = await api.post(`/api/workspaces/${workspaceId}/analyze?force_rerun=${forceRerun}`);
    return response.data;
}

export async function getAnalysisStatus(workspaceId) {
    const response = await api.get(`/api/workspaces/${workspaceId}/analysis/status`);
    return response.data;
}

export async function getVerdict(workspaceId) {
    const response = await api.get(`/api/workspaces/${workspaceId}/verdict`);
    return response.data;
}

export const startEvaluation = async (cleanPath, maliciousPath, reportName) => {
    const res = await api.post('/api/eval/start', {
        clean_path: cleanPath,
        malicious_path: maliciousPath,
        report_name: reportName
    });
    return res.data;
};

export const resumeEvaluation = async (evalId, cleanPath, maliciousPath) => {
    const res = await api.post(`/api/eval/resume/${evalId}`, {
        clean_path: cleanPath,
        malicious_path: maliciousPath
    });
    return res.data;
};

export async function getEvaluationStatus(evalId) {
    const response = await api.get(`/api/eval/status/${evalId}`);
    return response.data;
}

export const getEvaluationLs = async (path = null) => {
    let url = '/api/eval/ls';
    if (path) {
        url += `?path=${encodeURIComponent(path)}`;
    }
    const res = await api.get(url);
    return res.data;
};

export const listEvaluations = async () => {
    const res = await api.get('/api/eval/reports');
    return res.data;
};

export const getEvaluationReport = async (reportId) => {
    const res = await api.get(`/api/eval/reports/${reportId}`);
    return res.data;
};

export const deleteEvaluationReport = async (reportId) => {
    const res = await api.delete(`/api/eval/reports/${reportId}`);
    return res.data;
};

export default api;
