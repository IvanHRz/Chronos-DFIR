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
    },

    async getEnrichmentConfig() {
        const response = await fetch('/api/enrichment/config');
        return await response.json();
    },

    async lookupIOC(iocValue, iocType) {
        const response = await fetch('/api/enrichment/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc_value: iocValue, ioc_type: iocType })
        });
        return await response.json();
    },

    // ── Settings & API Key Management ──

    async getSettingsConfig() {
        const response = await fetch('/api/settings/config');
        return await response.json();
    },

    async saveApiKey(provider, key) {
        const response = await fetch('/api/settings/api-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider, key })
        });
        return await response.json();
    },

    async testApiKey(provider) {
        const response = await fetch('/api/settings/test-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider })
        });
        return await response.json();
    },

    async clearEnrichmentCache() {
        const response = await fetch('/api/settings/clear-cache', { method: 'POST' });
        return await response.json();
    },

    // ── Grid-Integrated Enrichment ──

    async getEnrichableColumns(filename) {
        const response = await fetch(`/api/enrichment/columns/${filename}`);
        return await response.json();
    },

    async extractIOCs(filename, params) {
        const response = await fetch('/api/enrichment/extract', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename, ...params })
        });
        return await response.json();
    },

    async bulkEnrich(filename, params) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 180000);
        try {
            const response = await fetch('/api/enrichment/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename, ...params }),
                signal: controller.signal
            });
            return await response.json();
        } finally {
            clearTimeout(timeoutId);
        }
    },

    async saveEnrichmentToCase(caseId, results, filename, columnsUsed) {
        const response = await fetch('/api/enrichment/save-to-case', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                case_id: caseId,
                results,
                filename: filename || '',
                columns_used: columnsUsed || []
            })
        });
        return await response.json();
    }
};
