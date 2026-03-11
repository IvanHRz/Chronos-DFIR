/**
 * Chronos-DFIR Settings Manager
 * Slide-out panel for API key configuration, IOC lookup, and cache management.
 */

import { API } from './api.js?v=202';

export class SettingsManager {
    constructor() {
        this._panel = document.getElementById('settings-panel');
        this._isOpen = false;
        this._config = null;
    }

    toggle() {
        this._isOpen ? this.close() : this.open();
    }

    async open() {
        this._isOpen = true;
        this._panel.classList.add('open');
        await this._loadConfig();
    }

    close() {
        this._isOpen = false;
        this._panel.classList.remove('open');
    }

    async _loadConfig() {
        try {
            this._config = await API.getSettingsConfig();
            this._render();
        } catch (e) {
            console.error('[SETTINGS] Failed to load config:', e);
            this._panel.querySelector('.settings-body').innerHTML =
                '<p style="color:#ef4444;padding:20px;">Failed to load settings. Is the server running?</p>';
        }
    }

    _render() {
        const { providers, cache } = this._config;
        const body = this._panel.querySelector('.settings-body');

        let html = '<div class="settings-section"><h3><i class="fas fa-shield-halved"></i> Threat Intelligence Providers</h3>';

        // Group: no-key providers first, then key-required
        const noKey = providers.filter(p => !p.key_required);
        const withKey = providers.filter(p => p.key_required);

        // No-key providers (always active)
        for (const p of noKey) {
            html += this._renderFreeProvider(p);
        }

        // Key-required providers
        for (const p of withKey) {
            html += this._renderKeyProvider(p);
        }
        html += '</div>';

        // IOC Lookup section
        html += `
        <div class="settings-section">
            <h3><i class="fas fa-search"></i> IOC Lookup</h3>
            <div class="ioc-lookup-form">
                <select id="ioc-type-select" class="settings-select">
                    <option value="ip">IP Address</option>
                    <option value="hash">File Hash</option>
                    <option value="domain">Domain</option>
                    <option value="email">Email</option>
                </select>
                <div style="display:flex;gap:6px;flex:1;">
                    <input type="text" id="ioc-value-input" class="settings-input" placeholder="Enter IOC value..." style="flex:1;">
                    <button id="ioc-lookup-btn" class="btn-primary btn-sm">Search</button>
                </div>
            </div>
            <div id="ioc-lookup-results"></div>
        </div>`;

        // Cache section
        const cacheInfo = cache || { total_entries: 0, active_entries: 0, expired_entries: 0 };
        html += `
        <div class="settings-section">
            <h3><i class="fas fa-database"></i> Enrichment Cache</h3>
            <div class="cache-stats">
                <span>${cacheInfo.active_entries} active</span>
                <span style="color:var(--text-muted);">${cacheInfo.expired_entries} expired</span>
                <span style="color:var(--text-muted);">${cacheInfo.total_entries} total</span>
            </div>
            <button id="clear-cache-btn" class="btn-danger btn-sm" style="margin-top:8px;">Clear Cache</button>
        </div>`;

        body.innerHTML = html;
        this._bindEvents();
    }

    _renderFreeProvider(p) {
        return `
        <div class="provider-card">
            <div class="provider-header">
                <span class="provider-status active"></span>
                <i class="fas ${p.icon} provider-icon"></i>
                <span class="provider-name">${p.name}</span>
                <span class="provider-rate">${p.rate_limit}</span>
            </div>
            <p class="provider-desc">${p.description}</p>
            <span class="provider-badge free">No API key needed</span>
        </div>`;
    }

    _renderKeyProvider(p) {
        const isActive = p.active;
        const statusClass = isActive ? 'active' : 'inactive';
        const maskedKey = p.masked_key || '';

        return `
        <div class="provider-card" data-provider="${p.id}">
            <div class="provider-header">
                <span class="provider-status ${statusClass}"></span>
                <i class="fas ${p.icon} provider-icon"></i>
                <span class="provider-name">${p.name}</span>
                <span class="provider-rate">${p.rate_limit}</span>
            </div>
            <p class="provider-desc">${p.description}</p>
            <div class="provider-key-row">
                <input type="password" class="settings-input provider-key-input"
                       placeholder="${maskedKey || 'Enter API key...'}"
                       data-provider="${p.id}" autocomplete="off">
                <button class="btn-sm btn-primary provider-save-btn" data-provider="${p.id}">Save</button>
                <button class="btn-sm btn-secondary provider-test-btn" data-provider="${p.id}"
                        ${!isActive ? 'disabled' : ''}>Test</button>
            </div>
            <div class="provider-test-result" id="test-result-${p.id}"></div>
            ${p.signup_url ? `<a href="${p.signup_url}" target="_blank" class="provider-signup">Get free API key &rarr;</a>` : ''}
        </div>`;
    }

    _bindEvents() {
        // Save buttons
        this._panel.querySelectorAll('.provider-save-btn').forEach(btn => {
            btn.addEventListener('click', () => this._saveKey(btn.dataset.provider));
        });

        // Test buttons
        this._panel.querySelectorAll('.provider-test-btn').forEach(btn => {
            btn.addEventListener('click', () => this._testKey(btn.dataset.provider));
        });

        // Enter key on inputs
        this._panel.querySelectorAll('.provider-key-input').forEach(input => {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this._saveKey(input.dataset.provider);
            });
        });

        // IOC Lookup
        const lookupBtn = document.getElementById('ioc-lookup-btn');
        const lookupInput = document.getElementById('ioc-value-input');
        if (lookupBtn) lookupBtn.addEventListener('click', () => this._lookupIOC());
        if (lookupInput) lookupInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this._lookupIOC();
        });

        // Clear cache
        const clearBtn = document.getElementById('clear-cache-btn');
        if (clearBtn) clearBtn.addEventListener('click', () => this._clearCache());
    }

    async _saveKey(providerId) {
        const input = this._panel.querySelector(`.provider-key-input[data-provider="${providerId}"]`);
        const key = input?.value?.trim();
        if (!key) return;

        const btn = this._panel.querySelector(`.provider-save-btn[data-provider="${providerId}"]`);
        btn.textContent = '...';
        btn.disabled = true;

        try {
            const result = await API.saveApiKey(providerId, key);
            if (result.status === 'saved') {
                input.value = '';
                input.placeholder = result.masked;
                // Update status dot
                const card = this._panel.querySelector(`.provider-card[data-provider="${providerId}"]`);
                const dot = card?.querySelector('.provider-status');
                if (dot) { dot.classList.remove('inactive'); dot.classList.add('active'); }
                // Enable test button
                const testBtn = card?.querySelector('.provider-test-btn');
                if (testBtn) testBtn.disabled = false;
            }
        } catch (e) {
            console.error(`[SETTINGS] Save key failed for ${providerId}:`, e);
        } finally {
            btn.textContent = 'Save';
            btn.disabled = false;
        }
    }

    async _testKey(providerId) {
        const resultDiv = document.getElementById(`test-result-${providerId}`);
        if (!resultDiv) return;
        resultDiv.innerHTML = '<span style="color:var(--text-muted);">Testing...</span>';

        try {
            const result = await API.testApiKey(providerId);
            if (result.valid) {
                resultDiv.innerHTML = `<span style="color:#22c55e;">&#10003; Valid (${result.latency_ms}ms)</span>`;
            } else {
                resultDiv.innerHTML = `<span style="color:#ef4444;">&#10007; ${result.error || 'Invalid key'}</span>`;
            }
        } catch (e) {
            resultDiv.innerHTML = `<span style="color:#ef4444;">&#10007; Connection error</span>`;
        }
    }

    async _lookupIOC() {
        const typeSelect = document.getElementById('ioc-type-select');
        const valueInput = document.getElementById('ioc-value-input');
        const resultsDiv = document.getElementById('ioc-lookup-results');
        if (!typeSelect || !valueInput || !resultsDiv) return;

        const iocType = typeSelect.value;
        const iocValue = valueInput.value.trim();
        if (!iocValue) return;

        resultsDiv.innerHTML = '<div class="ioc-loading">Querying providers...</div>';

        try {
            const result = await API.lookupIOC(iocValue, iocType);
            resultsDiv.innerHTML = this._renderLookupResult(result, iocValue, iocType);
        } catch (e) {
            resultsDiv.innerHTML = '<div class="ioc-error">Lookup failed. Check server connection.</div>';
        }
    }

    _renderLookupResult(data, iocValue, iocType) {
        if (data.status === 'no_results') {
            return `<div class="ioc-result-card"><p style="color:var(--text-muted);">No results for ${iocValue}</p></div>`;
        }

        let html = `<div class="ioc-result-card"><div class="ioc-result-header">${iocType.toUpperCase()}: ${iocValue}</div>`;

        // Render each provider's results
        const providerRenderers = {
            geo: (d) => d.country ? `<b>GEO:</b> ${d.country}${d.city ? ', ' + d.city : ''} | ${d.isp || ''} | ${d.asname || ''}` : '',
            abuse: (d) => d.abuse_confidence !== undefined ? `<b>AbuseIPDB:</b> ${d.abuse_confidence}% confidence (${d.total_reports} reports)` : '',
            vt: (d) => d.malicious !== undefined ? `<b>VirusTotal:</b> ${d.malicious}/${(d.malicious||0)+(d.harmless||0)+(d.suspicious||0)+(d.undetected||0)} malicious` : '',
            greynoise: (d) => d.classification ? `<b>GreyNoise:</b> ${d.classification.toUpperCase()}${d.noise ? ' (internet noise)' : ''}${d.name ? ' — ' + d.name : ''}` : '',
            threatfox: (d) => d.found ? `<b>ThreatFox:</b> ${d.malware || 'Unknown malware'}${d.threat_type ? ' (' + d.threat_type + ')' : ''}` : (d.found === false ? '<b>ThreatFox:</b> Clean' : ''),
            otx: (d) => d.pulse_count !== undefined ? `<b>OTX:</b> ${d.pulse_count} pulses${d.pulses && d.pulses.length ? ' — ' + d.pulses[0] : ''}` : '',
            urlhaus: (d) => d.query_status ? `<b>URLhaus:</b> ${d.urls_total || 0} URLs${d.threat_type ? ' (' + d.threat_type + ')' : ''}` : '',
            urlscan: (d) => d.total_results !== undefined ? `<b>URLScan:</b> ${d.total_results} results` : '',
            hibp: (d) => d.breach_count !== undefined ? `<b>HIBP:</b> ${d.breach_count} breaches${d.breaches && d.breaches.length ? ' (' + d.breaches.slice(0,3).join(', ') + ')' : ''}` : '',
            circl: (d) => d.known !== undefined ? `<b>CIRCL:</b> ${d.known ? 'Known file — ' + (d.product_name || d.file_name || 'NSRL') : 'Not in known-file DB'}` : '',
            malwarebazaar: (d) => d.found ? `<b>MalwareBazaar:</b> ${d.signature || 'Malware'} (${d.file_type || ''})${d.tags && d.tags.length ? ' [' + d.tags.join(', ') + ']' : ''}` : (d.found === false ? '<b>MalwareBazaar:</b> Not found in malware DB' : ''),
        };

        for (const [key, renderer] of Object.entries(providerRenderers)) {
            if (data[key] && typeof data[key] === 'object' && Object.keys(data[key]).length > 0) {
                const line = renderer(data[key]);
                if (line) html += `<div class="ioc-result-line">${line}</div>`;
            }
        }

        html += '</div>';
        return html;
    }

    async _clearCache() {
        const btn = document.getElementById('clear-cache-btn');
        if (btn) { btn.textContent = '...'; btn.disabled = true; }

        try {
            await API.clearEnrichmentCache();
            await this._loadConfig(); // Refresh stats
        } catch (e) {
            console.error('[SETTINGS] Clear cache failed:', e);
        } finally {
            if (btn) { btn.textContent = 'Clear Cache'; btn.disabled = false; }
        }
    }
}
