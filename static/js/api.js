/**
 * Chronos-DFIR API Client Module
 * Centralizes all backend communications.
 */

export const API = {
    async uploadFile(formData) {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        return await response.json();
    },

    async processArtifact(artifactType, filePath) {
        const formData = new FormData();
        formData.append('artifact_type', artifactType);
        formData.append('file_path', filePath);

        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        return await response.json();
    },

    async fetchData(filename, params = {}) {
        const urlParams = new URLSearchParams(params);
        const response = await fetch(`/api/data/${filename}?${urlParams.toString()}`);
        return await response.json();
    },

    async getEmptyColumns(filename, params = {}) {
        const urlParams = new URLSearchParams(params);
        const response = await fetch(`/api/empty_columns/${filename}?${urlParams.toString()}`);
        return await response.json();
    },

    async exportData(filename, params) {
        const response = await fetch('/api/export_filtered', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename, ...params })
        });
        return await response.json();
    },

    async getForensicReport(params) {
        const response = await fetch('/api/forensic_report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        });
        return await response.json();
    },

    async resetSession() {
        const response = await fetch('/api/reset', { method: 'POST' });
        return await response.json();
    }
};
