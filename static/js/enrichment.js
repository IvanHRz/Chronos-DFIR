/**
 * Chronos-DFIR Enrichment Manager v2
 *
 * Redesigned flow:
 * 1. Provider selector popover — shows ONLY auto-detected columns per IOC type
 * 2. Extract & Preview modal — dedup stats, time estimation, API call count
 * 3. Bulk enrichment — progress bar, results with risk badges
 * 4. Dedicated enrichment modal (not reusing summary-modal)
 */

import { API } from './api.js?v=202';
import ChronosState from './state.js?v=202';

// Provider → IOC types
const PROVIDER_IOC_TYPES = {
    ip_api: ["ip"], abuseipdb: ["ip"], virustotal: ["ip", "domain", "hash"],
    greynoise: ["ip"], internetdb: ["ip"],
    urlhaus: ["domain"], urlscan: ["domain"],
    threatfox: ["ip", "domain", "hash"], threatfox_free: ["ip", "domain", "hash"],
    otx: ["ip", "domain", "hash"],
    circl: ["hash"], malwarebazaar: ["hash"], hibp: ["email"]
};

export class EnrichmentManager {
    constructor(gridManager) {
        this.grid = gridManager;
        this._selectedProviders = [];
        this._highlightedColumns = new Map();
        this._extractedIOCs = null;
        this._enrichmentResults = null;
        this._isEnriching = false;
        this._popoverVisible = false;
        this._providerConfig = null;
        this._outsideClickHandler = null;
        this._ensureModalExists();
    }

    // ── Dedicated Modal ────────────────────────────────────────────

    _ensureModalExists() {
        if (document.getElementById('enrichment-modal')) return;

        const html = `<div id="enrichment-modal" class="enrich-modal hidden">
            <div class="enrich-modal-content">
                <div class="enrich-modal-header">
                    <h2 id="enrich-modal-title">Enrichment</h2>
                    <span class="enrich-modal-close" id="enrich-modal-close">&times;</span>
                </div>
                <div id="enrich-modal-body" class="enrich-modal-body"></div>
                <div class="enrich-modal-footer">
                    <button id="enrich-modal-close-btn" class="btn-secondary btn-sm">Close</button>
                </div>
            </div>
        </div>`;
        document.body.insertAdjacentHTML('beforeend', html);

        // Always-active close handlers
        document.getElementById('enrich-modal-close')?.addEventListener('click', () => this._closeModal());
        document.getElementById('enrich-modal-close-btn')?.addEventListener('click', () => this._closeModal());

        // Click backdrop to close
        document.getElementById('enrichment-modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'enrichment-modal') this._closeModal();
        });
    }

    _openModal(title) {
        this._ensureModalExists();
        const modal = document.getElementById('enrichment-modal');
        const titleEl = document.getElementById('enrich-modal-title');
        if (titleEl) titleEl.textContent = title || 'Enrichment';
        if (modal) modal.classList.remove('hidden');
    }

    _closeModal() {
        const modal = document.getElementById('enrichment-modal');
        if (modal) modal.classList.add('hidden');
    }

    _setModalContent(html) {
        const body = document.getElementById('enrich-modal-body');
        if (body) body.innerHTML = html;
    }

    // ── Step 1: Provider Selector ──────────────────────────────────

    async showProviderSelector() {
        if (!ChronosState.currentFilename) {
            alert("Load a file first before enriching.");
            return;
        }

        // Load provider config if not cached
        if (!this._providerConfig) {
            try {
                this._providerConfig = await API.getSettingsConfig();
            } catch (e) {
                console.error("[ENRICH] Failed to load provider config:", e);
            }
        }

        // Auto-detect columns from backend
        let detectedColumns = {}, allColumns = [], activeProviders = [];
        try {
            const colData = await API.getEnrichableColumns(ChronosState.currentFilename);
            detectedColumns = colData.detected || {};
            allColumns = colData.columns || [];
            activeProviders = colData.active_providers || [];
        } catch (e) {
            console.error("[ENRICH] Column detection failed:", e);
        }

        this._detectedColumns = detectedColumns;
        this._allColumns = allColumns;
        this._activeProviders = new Set(activeProviders);

        if (this._popoverVisible) {
            this._closePopover();
            return;
        }

        this._showPopover(detectedColumns);
    }

    _showPopover(detectedColumns) {
        this._closePopover();
        this._popoverVisible = true;
        this._selectedColumns = {};  // iocType → [colNames] - what user selected

        // Initialize selected columns from detection
        for (const [iocType, cols] of Object.entries(detectedColumns)) {
            this._selectedColumns[iocType] = [...cols];
        }

        // Build provider list from config + active status
        const providers = this._providerConfig?.providers || [];
        const byType = { ip: [], domain: [], hash: [], email: [] };
        for (const p of providers) {
            const types = PROVIDER_IOC_TYPES[p.id] || [];
            const isActive = this._activeProviders.has(p.id);
            for (const t of types) {
                if (byType[t] && !byType[t].find(x => x.id === p.id)) {
                    byType[t].push({ ...p, isActive });
                }
            }
        }

        // Determine free providers
        const FREE_PROVIDERS = new Set(['ip_api', 'circl', 'urlhaus', 'internetdb', 'threatfox_free']);

        let html = `<div class="enrich-popover" id="enrich-popover">
            <div class="enrich-popover-header">
                <h3><i class="fas fa-search-plus"></i> Enrichment</h3>
                <span class="enrich-popover-close" id="enrich-popover-close">&times;</span>
            </div>
            <div class="enrich-popover-body">
            <div class="enrich-quick-select">
                <button id="enrich-free-only" class="btn-sm btn-primary enrich-qs-btn active">
                    <i class="fas fa-unlock"></i> Free
                </button>
                <button id="enrich-all-available" class="btn-sm btn-secondary enrich-qs-btn">
                    <i class="fas fa-layer-group"></i> All
                </button>
                <button id="enrich-custom" class="btn-sm btn-secondary enrich-qs-btn">
                    <i class="fas fa-sliders-h"></i> Custom
                </button>
            </div>`;

        const typeLabels = { ip: "IP Address", domain: "Domain", hash: "File Hash", email: "Email" };
        const typeIcons = { ip: "fa-network-wired", domain: "fa-globe", hash: "fa-fingerprint", email: "fa-envelope" };

        let hasAnyColumns = false;

        for (const [iocType, provs] of Object.entries(byType)) {
            if (provs.length === 0) continue;

            const cols = detectedColumns[iocType] || [];
            const hasDetected = cols.length > 0;
            if (hasDetected) hasAnyColumns = true;

            html += `<div class="enrich-type-group" data-ioc-type="${iocType}">
                <div class="enrich-type-header">
                    <span class="enrich-type-label">
                        <i class="fas ${typeIcons[iocType]}"></i> ${typeLabels[iocType]}
                    </span>`;

            if (hasDetected) {
                html += `<span class="enrich-col-badge detected">${cols.length} col${cols.length > 1 ? 's' : ''} detected</span>`;
            } else {
                html += `<span class="enrich-col-badge none">no columns found</span>`;
            }

            html += `</div>`;

            // --- Detected Artifacts section ---
            if (hasDetected) {
                const autoCheck = cols.length <= 3; // Auto-select when few columns detected
                html += `<div class="enrich-artifacts-section">
                    <span class="enrich-section-label">Detected Artifacts
                        <label class="enrich-toggle-switch" title="Select All / Deselect All">
                            <input type="checkbox" class="enrich-select-all" data-ioc-type="${iocType}" ${autoCheck ? 'checked' : ''}>
                            <span class="enrich-toggle-slider"></span>
                            <span class="enrich-toggle-label">${autoCheck ? 'Deselect All' : 'Select All'}</span>
                        </label>
                    </span>
                    <div class="enrich-detected-cols">`;
                for (const col of cols) {
                    html += `<label class="enrich-col-item">
                        <input type="checkbox" class="enrich-col-cb" data-col="${col}" data-ioc-type="${iocType}" ${autoCheck ? 'checked' : ''}>
                        <span>${col}</span>
                    </label>`;
                }
                html += `</div></div>`;
            }

            // --- Available Analyzers section (ALWAYS shown) ---
            html += `<div class="enrich-analyzers-section">
                <span class="enrich-section-label">Available Analyzers</span>`;

            if (!hasDetected) {
                html += `<div class="enrich-no-artifacts-hint">
                    <i class="fas fa-info-circle"></i> No ${typeLabels[iocType].toLowerCase()} columns detected — analyzers shown for reference.
                </div>`;
            }

            html += `<div class="enrich-providers">`;
            for (const p of provs) {
                const canUse = p.isActive && hasDetected;
                const disabled = !canUse ? 'disabled' : '';
                const statusClass = p.isActive ? 'active' : 'inactive';
                const tooltip = !p.isActive ? 'title="API key not configured"' : (!hasDetected ? 'title="No columns detected for this type"' : '');
                html += `<label class="enrich-provider-item ${!canUse ? 'disabled' : ''}" ${tooltip}>
                    <input type="checkbox" class="enrich-provider-cb" data-provider="${p.id}" data-ioc-type="${iocType}" ${disabled} ${canUse ? 'checked' : ''}>
                    <span class="provider-status ${statusClass}"></span>
                    ${p.name}
                    <span class="enrich-rate">${p.rate_limit}</span>
                </label>`;
            }
            html += `</div></div>`;

            html += `</div>`;
        }

        if (!hasAnyColumns) {
            html += `<div class="enrich-no-columns">
                <i class="fas fa-info-circle"></i>
                <p>No IOC columns detected in this artifact.</p>
                <p class="enrich-hint">This file may not contain IP addresses, hashes, domains, or emails in a recognizable format.</p>
            </div>`;
        }

        html += `</div>
            <div class="enrich-popover-footer">
                <button id="enrich-start-btn" class="btn-primary btn-sm" ${!hasAnyColumns ? 'disabled' : ''}>
                    <i class="fas fa-bolt"></i> Extract & Preview
                </button>
                <button id="enrich-cancel-btn" class="btn-secondary btn-sm">Cancel</button>
            </div>
        </div>`;

        document.body.insertAdjacentHTML('beforeend', html);

        // Bind events
        document.getElementById('enrich-popover-close')?.addEventListener('click', () => this._closePopover());
        document.getElementById('enrich-cancel-btn')?.addEventListener('click', () => this._closePopover());
        document.getElementById('enrich-start-btn')?.addEventListener('click', () => this._onExtractClick());

        // Quick-select buttons
        const qsBtns = ['enrich-free-only', 'enrich-all-available', 'enrich-custom'];
        const setQsActive = (activeId) => {
            for (const id of qsBtns) {
                const el = document.getElementById(id);
                if (!el) continue;
                if (id === activeId) {
                    el.classList.add('active');
                    el.classList.replace('btn-secondary', 'btn-primary');
                } else {
                    el.classList.remove('active');
                    el.classList.replace('btn-primary', 'btn-secondary');
                }
            }
        };
        document.getElementById('enrich-free-only')?.addEventListener('click', () => {
            this._applyProviderFilter('free');
            setQsActive('enrich-free-only');
        });
        document.getElementById('enrich-all-available')?.addEventListener('click', () => {
            this._applyProviderFilter('all');
            setQsActive('enrich-all-available');
        });
        document.getElementById('enrich-custom')?.addEventListener('click', () => {
            this._applyProviderFilter('custom');
            setQsActive('enrich-custom');
        });

        // Apply "Free only" by default
        this._applyProviderFilter('free');

        // Column checkboxes update state
        document.querySelectorAll('.enrich-col-cb').forEach(cb => {
            cb.addEventListener('change', () => this._updateSelectedColumns());
        });

        // "Select All" toggle switches per IOC type
        document.querySelectorAll('.enrich-select-all').forEach(toggle => {
            toggle.addEventListener('change', () => {
                const iocType = toggle.dataset.iocType;
                const cbs = document.querySelectorAll(`.enrich-col-cb[data-ioc-type="${iocType}"]`);
                cbs.forEach(cb => { cb.checked = toggle.checked; });
                const label = toggle.closest('.enrich-toggle-switch')?.querySelector('.enrich-toggle-label');
                if (label) label.textContent = toggle.checked ? 'Deselect All' : 'Select All';
                this._updateSelectedColumns();
            });
        });

        // Provider checkboxes
        document.querySelectorAll('.enrich-provider-cb').forEach(cb => {
            cb.addEventListener('change', () => this._updateButtonState());
        });

        // Highlight detected columns in grid
        this._highlightDetectedColumns(detectedColumns);

        // Click outside to close (with cleanup)
        if (this._outsideClickHandler) {
            document.removeEventListener('click', this._outsideClickHandler);
        }
        setTimeout(() => {
            this._outsideClickHandler = (e) => {
                const popover = document.getElementById('enrich-popover');
                const btn = document.getElementById('enrich-btn');
                if (popover && !popover.contains(e.target) && btn && !btn.contains(e.target)) {
                    this._closePopover();
                }
            };
            document.addEventListener('click', this._outsideClickHandler);
        }, 150);
    }

    _closePopover() {
        const popover = document.getElementById('enrich-popover');
        if (popover) popover.remove();
        this._popoverVisible = false;
        if (this._outsideClickHandler) {
            document.removeEventListener('click', this._outsideClickHandler);
            this._outsideClickHandler = null;
        }
        this._clearHighlights();
    }

    _applyProviderFilter(mode) {
        const FREE_PROVIDERS = new Set(['ip_api', 'circl', 'urlhaus', 'internetdb', 'threatfox_free']);
        document.querySelectorAll('.enrich-provider-cb').forEach(cb => {
            if (cb.disabled) return; // Skip providers without API key / no columns
            if (mode === 'free') {
                cb.checked = FREE_PROVIDERS.has(cb.dataset.provider);
            } else if (mode === 'custom') {
                cb.checked = false; // User selects manually
            } else {
                cb.checked = true; // All available (active) providers
            }
        });
        this._updateButtonState();
    }

    _updateSelectedColumns() {
        this._selectedColumns = {};
        document.querySelectorAll('.enrich-col-cb:checked').forEach(cb => {
            const type = cb.dataset.iocType;
            const col = cb.dataset.col;
            if (!this._selectedColumns[type]) this._selectedColumns[type] = [];
            if (!this._selectedColumns[type].includes(col)) this._selectedColumns[type].push(col);
        });
        this._updateButtonState();
    }

    _updateButtonState() {
        const checkedProviders = document.querySelectorAll('.enrich-provider-cb:checked');
        this._selectedProviders = [...new Set([...checkedProviders].map(cb => cb.dataset.provider))];

        // Check if any selected providers have columns
        const neededTypes = new Set();
        for (const p of this._selectedProviders) {
            (PROVIDER_IOC_TYPES[p] || []).forEach(t => neededTypes.add(t));
        }

        let hasColumns = false;
        for (const t of neededTypes) {
            if ((this._selectedColumns[t] || []).length > 0) {
                hasColumns = true;
                break;
            }
        }

        const btn = document.getElementById('enrich-start-btn');
        if (btn) btn.disabled = this._selectedProviders.length === 0 || !hasColumns;
    }

    // ── Column Highlighting ────────────────────────────────────────

    _highlightDetectedColumns(detectedColumns) {
        this._clearHighlights();
        if (!this.grid.table) return;

        const allDetected = new Set();
        for (const cols of Object.values(detectedColumns)) {
            cols.forEach(c => allDetected.add(c));
        }

        this.grid.table.getColumns().forEach(col => {
            const field = col.getField();
            if (field && allDetected.has(field)) {
                const el = col.getElement();
                if (el) el.classList.add('enrichment-highlight');
            }
        });
    }

    _clearHighlights() {
        document.querySelectorAll('.enrichment-highlight').forEach(el => {
            el.classList.remove('enrichment-highlight');
        });
        this._highlightedColumns.clear();
    }

    // ── Step 2: IOC Extraction & Preview ───────────────────────────

    async _onExtractClick() {
        if (this._selectedProviders.length === 0) return;

        // Build columns map from selected columns
        const columns = {};
        const neededTypes = new Set();
        for (const p of this._selectedProviders) {
            (PROVIDER_IOC_TYPES[p] || []).forEach(t => neededTypes.add(t));
        }

        for (const [iocType, cols] of Object.entries(this._selectedColumns)) {
            if (neededTypes.has(iocType) && cols.length > 0) {
                columns[iocType] = [...cols];
            }
        }

        if (Object.keys(columns).length === 0) {
            alert("No compatible columns selected for the chosen providers.");
            return;
        }

        this._closePopover();
        this._openModal('Enrichment — Extracting IOCs...');
        this._setModalContent(`<div class="enrich-loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>Scanning filtered data for IOCs...</p>
        </div>`);

        try {
            const result = await API.extractIOCs(ChronosState.currentFilename, {
                columns,
                providers: this._selectedProviders,
                query: ChronosState.currentQuery || '',
                col_filters: JSON.stringify(ChronosState.currentColumnFilters || []),
                selected_ids: ChronosState.selectedIds || [],
                start_time: ChronosState.startTime || '',
                end_time: ChronosState.endTime || '',
            });

            if (result.total_iocs === 0) {
                this._setModalContent(`<div class="enrich-empty">
                    <i class="fas fa-search"></i>
                    <p>No enrichable IOCs found in the filtered data.</p>
                    <p class="enrich-hint">Possible reasons:</p>
                    <ul class="enrich-hint-list">
                        <li>Private/internal IPs are excluded from enrichment (they can't be looked up externally)</li>
                        <li>Column values don't match expected IOC formats</li>
                        <li>Try adjusting your filters to include more rows</li>
                    </ul>
                    ${this._renderPrivateIpInfo(result.summary)}
                </div>`);
                return;
            }

            this._extractedIOCs = result;
            this._renderExtractionPreview(result, columns);

        } catch (e) {
            console.error("[ENRICH] Extraction failed:", e);
            this._setModalContent(`<div class="enrich-error">Extraction failed: ${this._escapeHtml(e.message)}</div>`);
        }
    }

    _renderPrivateIpInfo(summary) {
        const ipInfo = summary?.ip;
        if (!ipInfo || ipInfo.private_ips_excluded === 0) return '';

        const sample = (ipInfo.private_ips_sample || []).join(', ');
        return `<div class="enrich-private-ip-info">
            <i class="fas fa-lock"></i>
            <strong>${ipInfo.private_ips_excluded} private IPs detected</strong> (excluded from enrichment):
            <span class="enrich-hint">${sample}</span>
        </div>`;
    }

    _renderExtractionPreview(data, columns) {
        const titleEl = document.getElementById('enrich-modal-title');
        if (titleEl) titleEl.textContent = 'Enrichment — Preview';

        const typeLabels = { ip: "IP Addresses", domain: "Domains", hash: "File Hashes", email: "Emails" };
        const typeIcons = { ip: "fa-network-wired", domain: "fa-globe", hash: "fa-fingerprint", email: "fa-envelope" };

        const estimate = data.estimate || {};

        let html = `<div class="enrich-preview">
            <div class="enrich-preview-stats">
                <div class="enrich-stat">
                    <span class="enrich-stat-value">${(data.total_rows || 0).toLocaleString()}</span>
                    <span class="enrich-stat-label">Rows Scanned</span>
                </div>
                <div class="enrich-stat highlight">
                    <span class="enrich-stat-value">${data.total_iocs}</span>
                    <span class="enrich-stat-label">Unique IOCs</span>
                </div>
                <div class="enrich-stat">
                    <span class="enrich-stat-value">${estimate.total_api_calls || '?'}</span>
                    <span class="enrich-stat-label">API Calls</span>
                </div>
                <div class="enrich-stat">
                    <span class="enrich-stat-value">${estimate.estimated_display || '?'}</span>
                    <span class="enrich-stat-label">Est. Time</span>
                </div>
            </div>`;

        // IOC type breakdown
        for (const [iocType, info] of Object.entries(data.summary || {})) {
            const hasExclusions = (info.private_ips_excluded || 0) > 0 || (info.excluded_filenames || 0) > 0 || (info.excluded_invalid || 0) > 0;
            if (info.count === 0 && !hasExclusions) continue;

            const colsUsed = (columns[iocType] || []).join(', ');

            html += `<div class="enrich-preview-section">
                <h4><i class="fas ${typeIcons[iocType] || 'fa-tag'}"></i> ${typeLabels[iocType] || iocType}
                    <span class="enrich-count-badge">${info.count}</span>
                </h4>
                <div class="enrich-preview-meta">
                    <span>Source: <strong>${colsUsed}</strong></span>
                    <span>Raw values: ${info.total_raw?.toLocaleString() || '?'}</span>
                    <span>Duplicates removed: ${info.duplicates_removed || 0}</span>
                    ${info.private_ips_excluded > 0 ? `<span class="enrich-private-ip-info">Private IPs excluded: ${info.private_ips_excluded}</span>` : ''}
                    ${info.excluded_filenames > 0 ? `<span class="enrich-private-ip-info">Filenames excluded (.exe/.dll): ${info.excluded_filenames}</span>` : ''}
                    ${info.excluded_invalid > 0 ? `<span class="enrich-private-ip-info">Invalid format excluded: ${info.excluded_invalid}</span>` : ''}
                </div>`;

            if (info.count > 0) {
                html += `<div class="enrich-sample-list">
                    ${info.sample.map(v => `<span class="enrich-sample-item">${this._escapeHtml(v)}</span>`).join('')}
                    ${info.count > 10 ? `<span class="enrich-sample-more">+${info.count - 10} more</span>` : ''}
                </div>`;
            }

            html += `</div>`;
        }

        // Time warning for slow providers
        if (estimate.estimated_seconds > 30) {
            html += `<div class="enrich-warning"><i class="fas fa-clock"></i> Estimated time: ${estimate.estimated_display}. Enrichment runs in background — results will appear when ready.</div>`;
        }

        html += `<div class="enrich-preview-actions">
            <button id="enrich-run-btn" class="btn-primary"><i class="fas fa-bolt"></i> Enrich Now (${data.total_iocs} IOCs)</button>
            <button id="enrich-back-btn" class="btn-secondary">Back</button>
        </div></div>`;

        this._setModalContent(html);

        document.getElementById('enrich-run-btn')?.addEventListener('click', () => this._runBulkEnrichment(columns));
        document.getElementById('enrich-back-btn')?.addEventListener('click', () => this._closeModal());
    }

    // ── Step 3: Bulk Enrichment ────────────────────────────────────

    async _runBulkEnrichment(columns) {
        const titleEl = document.getElementById('enrich-modal-title');
        if (titleEl) titleEl.textContent = 'Enrichment — Processing...';

        this._isEnriching = true;
        const totalIOCs = this._extractedIOCs?.total_iocs || 0;

        this._setModalContent(`<div class="enrich-loading">
            <i class="fas fa-cog fa-spin" style="font-size:2.5rem;"></i>
            <p>Enriching ${totalIOCs} IOCs via ${this._selectedProviders.length} provider${this._selectedProviders.length > 1 ? 's' : ''}...</p>
            <div class="enrich-progress-bar">
                <div class="enrich-progress-fill" id="enrich-progress-fill"></div>
            </div>
            <p class="enrich-hint" id="enrich-progress-text">Starting enrichment pipeline...</p>
        </div>`);

        try {
            const result = await API.bulkEnrich(ChronosState.currentFilename, {
                columns,
                providers: this._selectedProviders,
                query: ChronosState.currentQuery || '',
                col_filters: JSON.stringify(ChronosState.currentColumnFilters || []),
                selected_ids: ChronosState.selectedIds || [],
                start_time: ChronosState.startTime || '',
                end_time: ChronosState.endTime || '',
            });

            this._enrichmentResults = result;
            this._isEnriching = false;

            if (result.status === 'no_iocs') {
                this._setModalContent(`<div class="enrich-empty">
                    <i class="fas fa-search"></i>
                    <p>No IOCs found to enrich.</p>
                </div>`);
                return;
            }

            this._renderEnrichmentResults(result);

        } catch (e) {
            this._isEnriching = false;
            console.error("[ENRICH] Bulk enrichment failed:", e);
            if (e.name === 'AbortError') {
                this._setModalContent(`<div class="enrich-error">
                    <i class="fas fa-clock" style="font-size:2rem; margin-bottom:0.5rem;"></i>
                    <p>Enrichment timed out after 3 minutes.</p>
                    <p class="enrich-hint">Try with fewer IOCs or fewer providers. Free APIs (ip-api, CIRCL, URLhaus) are fastest.</p>
                </div>`);
            } else {
                this._setModalContent(`<div class="enrich-error">Enrichment failed: ${this._escapeHtml(e.message)}</div>`);
            }
        }
    }

    // ── Step 4: Results ────────────────────────────────────────────

    _renderEnrichmentResults(results) {
        const titleEl = document.getElementById('enrich-modal-title');
        const meta = results.metadata || {};
        const totalEnriched = results.total_enriched || 0;
        const elapsed = meta.elapsed_seconds || 0;

        if (titleEl) titleEl.textContent = `Enrichment Results — ${totalEnriched} IOCs`;

        let html = `<div class="enrich-results">`;

        // Stats bar
        html += `<div class="enrich-results-stats">
            <span><i class="fas fa-check-circle" style="color:#22c55e;"></i> ${totalEnriched} enriched</span>
            <span><i class="fas fa-clock"></i> ${elapsed}s</span>
            <span><i class="fas fa-shield-halved"></i> ${(results.providers_used || []).length} providers</span>
        </div>`;

        // Export bar
        html += `<div class="enrich-export-bar">
            <button class="btn-sm btn-secondary" id="enrich-export-csv"><i class="fas fa-file-csv"></i> CSV</button>
            <button class="btn-sm btn-secondary" id="enrich-export-xlsx"><i class="fas fa-file-excel"></i> Excel</button>
            <button class="btn-sm btn-secondary" id="enrich-export-json"><i class="fas fa-code"></i> JSON</button>
        </div>`;

        // Render each IOC type
        const sections = [
            { key: "ip_enrichment", label: "IP Addresses", icon: "fa-network-wired", valKey: "ip" },
            { key: "domain_enrichment", label: "Domains", icon: "fa-globe", valKey: "domain" },
            { key: "hash_enrichment", label: "File Hashes", icon: "fa-fingerprint", valKey: "hash" },
            { key: "email_enrichment", label: "Emails", icon: "fa-envelope", valKey: "email" },
        ];

        for (const sec of sections) {
            const items = results[sec.key] || [];
            if (items.length === 0) continue;

            html += `<div class="enrich-section">
                <h3><i class="fas ${sec.icon}"></i> ${sec.label} <span class="enrich-count-badge">${items.length}</span></h3>`;

            for (const item of items) {
                const iocVal = item[sec.valKey] || '';
                const summaryLine = this._buildSummaryLine(item);
                const riskBadge = this._calculateRiskBadge(item);

                html += `<details class="enrich-ioc-details">
                    <summary>
                        <span class="enrich-ioc-value">${this._escapeHtml(iocVal)}</span>
                        ${summaryLine}
                        <span class="enrich-risk-badge ${riskBadge.class}">${riskBadge.label}</span>
                    </summary>
                    <div class="enrich-ioc-table">
                        ${this._renderProviderTable(item, sec.valKey)}
                    </div>
                </details>`;
            }

            html += `</div>`;
        }

        html += `</div>`;
        this._setModalContent(html);

        // Bind export buttons
        document.getElementById('enrich-export-csv')?.addEventListener('click', () => this._exportResults('csv'));
        document.getElementById('enrich-export-xlsx')?.addEventListener('click', () => this._exportResults('xlsx'));
        document.getElementById('enrich-export-json')?.addEventListener('click', () => this._exportResults('json'));
    }

    _buildSummaryLine(item) {
        const parts = [];
        if (item.geo?.country) parts.push(item.geo.country_code || item.geo.country);
        if (item.abuse?.abuse_confidence !== undefined) parts.push(`Abuse: ${item.abuse.abuse_confidence}%`);
        if (item.vt?.malicious !== undefined) {
            const total = (item.vt.malicious || 0) + (item.vt.harmless || 0) + (item.vt.suspicious || 0) + (item.vt.undetected || 0);
            parts.push(`VT: ${item.vt.malicious}/${total}`);
        }
        if (item.greynoise?.classification) parts.push(`GN: ${item.greynoise.classification}`);
        if (item.circl?.known === true) parts.push(`NSRL: known`);
        if (item.threatfox?.found === true) parts.push(`TF: ${item.threatfox.malware || 'hit'}`);
        if (item.hibp?.breach_count !== undefined) parts.push(`Breaches: ${item.hibp.breach_count}`);

        return parts.length > 0
            ? `<span class="enrich-summary-text">${parts.join(' | ')}</span>`
            : '';
    }

    _calculateRiskBadge(item) {
        const vtMalicious = item.vt?.malicious || 0;
        const abuseConf = item.abuse?.abuse_confidence || 0;
        const gnClass = item.greynoise?.classification || '';
        const tfFound = item.threatfox?.found || false;
        const hibpBreaches = item.hibp?.breach_count || 0;

        if (vtMalicious > 5 || abuseConf > 75 || gnClass === 'malicious' || tfFound) {
            return { class: 'risk-critical', label: 'MALICIOUS' };
        }
        if (vtMalicious > 0 || abuseConf > 25 || hibpBreaches > 3) {
            return { class: 'risk-suspicious', label: 'SUSPICIOUS' };
        }
        return { class: 'risk-clean', label: 'CLEAN' };
    }

    _renderProviderTable(item, valKey) {
        let html = '<table class="enrich-detail-table"><thead><tr><th>Provider</th><th>Field</th><th>Value</th></tr></thead><tbody>';

        for (const [key, data] of Object.entries(item)) {
            if (key === valKey || !data || typeof data !== 'object' || Object.keys(data).length === 0) continue;
            const providerName = data.provider || key;

            for (const [field, val] of Object.entries(data)) {
                if (field === 'provider') continue;
                let displayVal = val;
                if (Array.isArray(val)) displayVal = val.join(', ');
                else if (typeof val === 'object' && val !== null) displayVal = JSON.stringify(val);
                else if (typeof val === 'boolean') displayVal = val ? 'Yes' : 'No';

                html += `<tr><td>${this._escapeHtml(providerName)}</td><td>${this._escapeHtml(field)}</td><td>${this._escapeHtml(String(displayVal))}</td></tr>`;
            }
        }

        html += '</tbody></table>';
        return html;
    }

    // ── Export ──────────────────────────────────────────────────────

    async _exportResults(format) {
        if (!this._enrichmentResults) return;

        try {
            const response = await fetch('/api/enrichment/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ results: this._enrichmentResults, format }),
            });

            if (!response.ok) throw new Error(`Export failed: ${response.statusText}`);

            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const ext = format === 'xlsx' ? 'xlsx' : format === 'json' ? 'json' : 'csv';

            window.isDownloading = true;
            const a = document.createElement('a');
            a.href = url;
            a.download = `enrichment_results.${ext}`;
            a.style.position = 'fixed';
            a.style.left = '-9999px';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                window.isDownloading = false;
            }, 3000);
        } catch (e) {
            console.error("[ENRICH] Export failed:", e);
            alert("Export failed: " + e.message);
        }
    }

    // ── Utilities ──────────────────────────────────────────────────

    _escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
}
