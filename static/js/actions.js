import { API } from './api.js?v=179';
import ChronosState from './state.js?v=179';
import events from './events.js?v=179';

export class ActionManager {
    constructor(gridManager, chartManager) {
        this.grid = gridManager;
        this.charts = chartManager;
    }

    /**
     * Robust file download: sets isDownloading flag to bypass beforeunload guard,
     * uses an offscreen <a> element with the download attribute.
     */
    _triggerDownload(url, filename) {
        window.isDownloading = true;
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || '';
        a.style.position = 'fixed';
        a.style.left = '-9999px';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            window.isDownloading = false;
        }, 3000);
    }

    // Called automatically after file loads to populate the forensic dashboard bar
    async loadDashboardCards() {
        const fileToExport = ChronosState.processedFiles?.csv || ChronosState.currentFilename;
        if (!fileToExport) return;
        try {
            const data = await API.getForensicReport({
                filename: fileToExport,
                query: "",
                col_filters: [],
                selected_ids: [],
                start_time: "",
                end_time: ""
            });
            this.renderForensicReport(data, null); // null = don't update modal content
        } catch (e) {
            // Silent fail — dashboard cards stay empty until user opens Context
        }
    }

    softReset() {
        // Clear all UI state without wiping session
        ChronosState.resetFilters();

        const interp = document.getElementById('chart-interpretation');
        if (interp) {
            interp.innerText = "Loading data...";
            interp.style.color = '#ccc';
        }
    }

    async hardReset() {
        if (!confirm("WARNING: This will wipe ALL current session data, uploaded files, and processed reports. This action is IRREVERSIBLE. Are you sure?")) return;

        try {
            const resp = await API.resetSession();
            // Backend returns {"message": ...} on success, not status: 'success'
            if (resp.status === 'success' || resp.message) {
                ChronosState.reset();
                alert("Hard Reset Successful. The application will now reload.");
                window.location.reload();
            } else {
                throw new Error(resp.error || "Reset failed");
            }
        } catch (e) {
            alert("Hard Reset Error: " + e.message);
        }
    }

    async downloadSplitZip() {
        if (!ChronosState.currentFilename) {
            alert("Please load a file first.");
            return;
        }

        const zipBtn = document.getElementById('download-split');
        const originalText = zipBtn ? zipBtn.innerHTML : "";
        if (zipBtn) {
            zipBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Splitting...';
            zipBtn.disabled = true;
        }

        const chunkSelect = document.getElementById('zip-chunk-size');
        const chunkSize = chunkSelect ? chunkSelect.value : "99";
        const formatSelect = document.getElementById('zip-format');
        const zipFormat = formatSelect ? formatSelect.value : "csv";

        try {
            const sorters = window.grid?.getSorters();
            let sort_col = null, sort_dir = null;
            if (sorters && sorters.length > 0) {
                sort_col = sorters[0].field;
                sort_dir = sorters[0].dir;
            }

            const resp = await fetch('/api/export/split-zip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: ChronosState.currentFilename,
                    chunk_size_mb: parseInt(chunkSize),
                    zip_format: zipFormat,
                    query: ChronosState.currentQuery,
                    col_filters: ChronosState.currentColumnFilters,
                    selected_ids: ChronosState.selectedIds,
                    start_time: ChronosState.startTime || "",
                    end_time: ChronosState.endTime || "",
                    sort_col: sort_col,
                    sort_dir: sort_dir,
                    visible_columns: window.grid?.getColumns().filter(c => c.isVisible()).map(c => c.getField()) || []
                })
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.error || "Split failed");
            }

            const data = await resp.json();
            if (data.download_url) {
                this._triggerDownload(data.download_url, data.filename || '');
            }

        } catch (e) {
            alert("Split Error: " + e.message);
        } finally {
            if (zipBtn) {
                zipBtn.innerHTML = originalText;
                zipBtn.disabled = false;
            }
        }
    }

    async generateReport() {
        const fileToExport = ChronosState.processedFiles.csv || ChronosState.currentFilename;
        if (!fileToExport) {
            alert("Please load and process a file first.");
            return;
        }

        const reportBtn = document.getElementById('download-report');
        const originalText = reportBtn ? reportBtn.innerHTML : "";
        if (reportBtn) {
            reportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
            reportBtn.disabled = true;
        }

        try {
            const resp = await fetch('/api/export/html', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: fileToExport,
                    original_filename: ChronosState.currentFilename,
                    query: ChronosState.currentQuery,
                    col_filters: ChronosState.currentColumnFilters,
                    start_time: ChronosState.startTime,
                    end_time: ChronosState.endTime
                })
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.error || "Report generation failed");
            }

            const data = await resp.json();
            if (data.download_url) {
                this._triggerDownload(data.download_url, data.filename || '');
            }

        } catch (e) {
            alert("Report Error: " + e.message);
        } finally {
            if (reportBtn) {
                reportBtn.innerHTML = originalText;
                reportBtn.disabled = false;
            }
        }
    }

    async showForensicSummary() {
        const fileToExport = ChronosState.processedFiles.csv || ChronosState.currentFilename;
        if (!fileToExport) {
            alert("Please load a file first.");
            return;
        }

        const modal = document.getElementById("summary-modal");
        const content = document.getElementById("summary-content");
        if (!modal || !content) return;

        modal.classList.remove("hidden");
        modal.classList.add("show");
        content.innerHTML = `
            <div style="text-align:center; padding: 40px;">
                <p style="color:var(--accent-primary); font-weight:600;">Orchestrating Forensic Analysis...</p>
                <p style="font-size:0.8rem; color:var(--text-secondary);">Parallel Processing Enabled.</p>
            </div>
        `;

        try {
            let sort_col = null;
            let sort_dir = null;
            if (this.grid.table) {
                const sorters = this.grid.table.getSorters();
                if (sorters.length > 0) {
                    sort_col = sorters[0].field;
                    sort_dir = sorters[0].dir;
                }
            }

            const data = await API.getForensicReport({
                filename: fileToExport,
                query: ChronosState.currentQuery,
                col_filters: ChronosState.currentColumnFilters,
                selected_ids: ChronosState.selectedIds,
                start_time: ChronosState.startTime || "",
                end_time: ChronosState.endTime || "",
                sort_col: sort_col,
                sort_dir: sort_dir
            });

            this.renderForensicReport(data, content);

            // ── Export dropdown toggle ────────────────────────────────────
            const expToggle = document.getElementById("modal-export-toggle");
            const expMenu   = document.getElementById("modal-export-menu");
            if (expToggle && expMenu) {
                expToggle.onclick = (e) => {
                    e.stopPropagation();
                    const isOpen = expMenu.classList.toggle('open');
                    expToggle.setAttribute('aria-expanded', isOpen);
                };
                expMenu.addEventListener('click', e => e.stopPropagation());
                document.addEventListener('click', () => expMenu.classList.remove('open'), { once: false });
            }

            // JSON download (clean summary list)
            const dlJson = document.getElementById("modal-dl-json");
            if (dlJson) {
                dlJson.onclick = (e) => {
                    e.preventDefault();
                    const summary = {
                        filename: fileToExport,
                        risk_level: data.risk_level,
                        risk_score: data.risk_score,
                        primary_identity: data.primary_identity,
                        top_tactic: data.top_tactic,
                        total_records: data.total_records,
                        risk_justify: data.risk_justify,
                        sigma_hits: (data.sigma_hits || []).map(h => ({
                            title: h.title, level: h.level,
                            technique: h.mitre_technique, events: h.matched_rows
                        })),
                        results: data.results
                    };
                    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const fname = `Forensic_${fileToExport.replace(/\.[^.]+$/, '')}.json`;
                    window.isDownloading = true;
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = fname;
                    a.style.position = 'fixed';
                    a.style.left = '-9999px';
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); window.isDownloading = false; }, 3000);
                    expMenu.classList.remove('open');
                };
            }

            // HTML Report download
            const dlHtml = document.getElementById("modal-dl-html");
            if (dlHtml) {
                dlHtml.onclick = (e) => {
                    e.preventDefault();
                    expMenu.classList.remove('open');
                    // Trigger via existing generateReport action
                    this.generateReport();
                };
            }

            // PDF: server-side generation — 4-method fallback chain
            const dlPdf = document.getElementById("modal-dl-pdf");
            if (dlPdf) {
                dlPdf.onclick = async (e) => {
                    e.preventDefault();
                    expMenu.classList.remove('open');
                    expToggle.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generando PDF...';
                    try {
                        const resp = await fetch('/api/export/pdf', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                filename: fileToExport,
                                original_filename: ChronosState.currentFilename,
                                query: ChronosState.currentQuery,
                                col_filters: ChronosState.currentColumnFilters,
                                start_time: ChronosState.startTime || "",
                                end_time: ChronosState.endTime || ""
                            })
                        });
                        const result = await resp.json();
                        if (result.download_url) {
                            this._triggerDownload(result.download_url, result.filename || 'ChronosReport.pdf');

                            // Inform user which method was used
                            const methodLabels = {
                                'weasyprint':    '✅ PDF generado con WeasyPrint.',
                                'playwright':    '✅ PDF generado con Playwright (Chromium headless).',
                                'xhtml2pdf':     '✅ PDF generado con xhtml2pdf.',
                                'wkhtmltopdf':   '✅ PDF generado con wkhtmltopdf.',
                                'browser-print': null  // handled below
                            };
                            if (result.fallback || result.method === 'browser-print') {
                                // Open HTML in new tab so print dialog fires automatically
                                window.open(result.download_url, '_blank');
                                this._showPdfToast(
                                    '📄 El diálogo de impresión se abrirá en la nueva pestaña. ' +
                                    'Selecciona <strong>Guardar como PDF</strong> en la impresora.',
                                    'info', 8000
                                );
                            } else if (methodLabels[result.method]) {
                                this._showPdfToast(methodLabels[result.method], 'success', 3000);
                            }
                        } else {
                            this._showPdfToast('❌ Error al generar PDF: ' + (result.error || 'Error desconocido'), 'error', 5000);
                        }
                    } catch(err) {
                        this._showPdfToast('❌ Error de conexión: ' + err.message, 'error', 5000);
                    } finally {
                        expToggle.innerHTML = '<i class="fas fa-download"></i> Export Report <i class="fas fa-caret-down" style="font-size:0.75rem;"></i>';
                    }
                };
            }

            const closeBtn = document.getElementById("close-modal");
            const closeBtnAlt = document.getElementById("close-modal-btn");
            const doClose = () => {
                modal.classList.remove("show");
                modal.classList.add("hidden");
                if (expMenu) expMenu.classList.remove('open');
            };
            if (closeBtn) closeBtn.onclick = doClose;
            if (closeBtnAlt) closeBtnAlt.onclick = doClose;

        } catch (e) {
            content.innerHTML = `<div class="error-box" style="color:red; padding:20px;">Analysis Error: ${e.message}</div>`;
        }
    }

    renderForensicReport(data, container) {
        // Update Dashboard Cards if elements exist
        const tacticEl = document.getElementById('dash-tactic');
        const identityEl = document.getElementById('dash-identity');
        const riskEl = document.getElementById('dash-risk');
        const epsEl = document.getElementById('dash-eps');

        const _badVals = new Set(['null', 'none', 'nan', 'n/a', 'undefined', '-', '']);
        const tacticVal = data.top_tactic && !_badVals.has(String(data.top_tactic).trim().toLowerCase()) ? data.top_tactic : 'N/A';
        if (tacticEl) tacticEl.innerText = tacticVal;
        if (identityEl) identityEl.innerText = data.primary_identity || "N/A";
        if (riskEl) {
            riskEl.innerText = data.risk_level || "Low";
            if (data.risk_level === 'High' || data.risk_level === 'Critical') {
                riskEl.style.color = '#ff4d4d';
            } else if (data.risk_level === 'Medium') {
                riskEl.style.color = '#f59e0b';
            } else {
                riskEl.style.color = '#00e676';
            }

            // Show Justification_Log always (tooltip-style below risk card)
            const riskCard = riskEl.closest('.dash-card');
            if (riskCard) {
                const existingJustify = riskCard.querySelector('.risk-justify-log');
                if (existingJustify) existingJustify.remove();
                const score = data.risk_score !== undefined ? ` (Score: ${data.risk_score})` : '';
                const justify = Array.isArray(data.risk_justify) && data.risk_justify.length > 0
                    ? data.risk_justify.map(j => `<div style="margin-bottom:2px;">• ${j}</div>`).join('')
                    : '<div style="color:#4ade80;">No anomalies detected.</div>';
                const jDiv = document.createElement('div');
                jDiv.className = 'risk-justify-log';
                jDiv.style.cssText = 'font-size:0.65rem; color:#94a3b8; margin-top:4px; max-height:120px; overflow-y:auto;';
                jDiv.innerHTML = `<strong style="color:#64748b;">Justification${score}:</strong>${justify}`;
                riskCard.appendChild(jDiv);
            }
        }
        if (epsEl) epsEl.innerText = data.eps || "0";

        // Show dashboard if it was hidden
        document.getElementById('forensic-dash')?.classList.remove('hidden');

        const riskColors = { Critical: '#ff4d4d', High: '#f59e0b', Medium: '#facc15', Low: '#4ade80' };
        const riskColor = riskColors[data.risk_level] || '#94a3b8';
        const riskScore = data.risk_score !== undefined ? ` (Score: ${data.risk_score})` : '';
        const justifyHtml = Array.isArray(data.risk_justify) && data.risk_justify.length
            ? data.risk_justify.map(j => `<li style="margin-bottom:3px;">${j}</li>`).join('')
            : '<li style="color:#4ade80;">No anomalies detected.</li>';

        let html = "";
        html += `
            <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid var(--border-color);">
                <h3 style="margin-top:0; color:var(--accent-primary);">Forensic Insight Summary</h3>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; font-size:0.9rem; margin-bottom:12px;">
                    <div><strong>Records Seen:</strong> ${data.total_records || 'N/A'}</div>
                    <div><strong>Analysis Timestamp:</strong> ${new Date().toLocaleString()}</div>
                    <div><strong>Top Tactic:</strong> ${data.top_tactic || 'N/A'}</div>
                    <div><strong>Primary Identity:</strong> ${data.primary_identity || 'N/A'}</div>
                    <div><strong>Events/Sec:</strong> ${data.eps || '0'}</div>
                    <div><strong style="color:${riskColor};">Risk Level: ${data.risk_level || 'Low'}${riskScore}</strong></div>
                </div>
                ${data.risk_justify && data.risk_justify.length ? `
                <div style="background:rgba(0,0,0,0.2); border-radius:6px; padding:10px 14px; border-left:3px solid ${riskColor};">
                    <div style="font-size:0.75rem; color:#64748b; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px;">Risk Justification</div>
                    <ul style="margin:0; padding-left:18px; font-size:0.82rem; color:#94a3b8; list-style:disc;">${justifyHtml}</ul>
                </div>` : ''}
            </div>
        `;

        if (data.results && Array.isArray(data.results)) {
            data.results.forEach(section => {
                if (typeof section === 'string') {
                    const lines = section.split('\n');
                    const title = lines[0].replace(/#/g, '').trim();
                    const body = lines.slice(1).join('\n');
                    html += `
                        <div class="report-section">
                            <h4 style="color:var(--accent-secondary); border-bottom:1px solid #333; padding-bottom:5px;">${title}</h4>
                            <div style="white-space:pre-wrap; font-size:0.85rem; padding:10px; background:rgba(0,0,0,0.2); border-radius:4px;">${body}</div>
                        </div>
                    `;
                } else if (typeof section === 'object' && section !== null) {
                    let title = "Section";
                    let body = "";

                    if (section.type === "timeline") {
                        title = "TIMELINE ANALYSIS";
                        if (section.peaks && section.peaks.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-bottom:12px;">Activity Peaks (Top 3 Buckets):</strong>`;
                            body += `<div style="display:flex; flex-wrap:wrap; gap:12px;">`;
                            section.peaks.forEach((p, i) => {
                                const colors = ['#e53e3e','#f59e0b','#4299e1'];
                                body += `<div style="flex:1; min-width:200px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.1); border-left:3px solid ${colors[i]||'#4299e1'}; border-radius:6px; padding:10px 14px;">
                                    <div style="font-size:0.7rem; color:#94a3b8; text-transform:uppercase; margin-bottom:4px;">Peak #${i+1}</div>
                                    <div style="font-family:monospace; color:var(--accent-primary); font-size:0.9rem; margin-bottom:4px;">${p.hour}</div>
                                    <div style="font-size:1.1rem; font-weight:700; color:${colors[i]||'#4299e1'};">${p.count.toLocaleString()} <span style="font-size:0.7rem; font-weight:400; color:#94a3b8;">events</span></div>
                                </div>`;
                            });
                            body += `</div>`;
                        } else {
                            body += `<strong>Time Range (Approx):</strong> ${section.time_range}<br>`;
                        }
                    } else if (section.type === "context") {
                        title = "SANITIZED FORENSIC SUMMARY";

                        // Actionable Fields: IPs, Users, Hosts, Paths, Methods, Violations
                        const hasGridItems = (section.ips && section.ips.length > 0) ||
                            (section.users && section.users.length > 0) ||
                            (section.hosts && section.hosts.length > 0) ||
                            (section.paths && section.paths.length > 0) ||
                            (section.methods && section.methods.length > 0) ||
                            (section.violations && section.violations.length > 0);

                        if (hasGridItems) {
                            body += `<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap:15px; margin-bottom:20px;">`;

                            if (section.ips && section.ips.length > 0) {
                                body += `<div><strong style="color:var(--text-secondary);">Top IPs:</strong><br>
                                    ${section.ips.map(ip => `<span class="tactic-badge" style="background:rgba(59,130,246,0.1); color:#60a5fa; border:1px solid rgba(59,130,246,0.2);">${ip.id} (${ip.count})</span>`).join(' ')}
                                </div>`;
                            }

                            if (section.users && section.users.length > 0) {
                                body += `<div><strong style="color:var(--text-secondary);">Top Users:</strong><br>
                                    ${section.users.map(u => `<span class="tactic-badge" style="background:rgba(16,185,129,0.1); color:#34d399; border:1px solid rgba(16,185,129,0.2);">${u.id} (${u.count})</span>`).join(' ')}
                                </div>`;
                            }

                            if (section.hosts && section.hosts.length > 0) {
                                body += `<div><strong style="color:var(--text-secondary);">Top Assets (Hosts):</strong><br>
                                    ${section.hosts.map(h => `<span class="tactic-badge" style="background:rgba(139,92,246,0.1); color:#a78bfa; border:1px solid rgba(139,92,246,0.2);">${h.id} (${h.count})</span>`).join(' ')}
                                </div>`;
                            }

                            if (section.paths && section.paths.length > 0) {
                                body += `<div><strong style="color:var(--text-secondary);">Top Directories:</strong><br>
                                    ${section.paths.map(p => {
                                    let displayUrl = p.id.length > 32 ? p.id.substring(0, 32) + '...' : p.id;
                                    return `<span class="tactic-badge" title="${p.id}" style="background:rgba(236,72,153,0.1); color:#f472b6; border:1px solid rgba(236,72,153,0.2);">${displayUrl} (${p.count})</span>`
                                }).join(' ')}
                                </div>`;
                            }

                            if (section.methods && section.methods.length > 0) {
                                body += `<div><strong style="color:var(--text-secondary);">HTTP Methods:</strong><br>
                                    ${section.methods.map(m => `<span class="tactic-badge" style="background:rgba(245,158,11,0.1); color:#fbbf24; border:1px solid rgba(245,158,11,0.2);">${m.id} (${m.count})</span>`).join(' ')}
                                </div>`;
                            }

                            if (section.violations && section.violations.length > 0) {
                                body += `<div><strong style="color:var(--text-secondary);">Violation Categories:</strong><br>
                                    ${section.violations.map(v => {
                                    let displayCat = v.id.length > 32 ? v.id.substring(0, 32) + '...' : v.id;
                                    return `<span class="tactic-badge" title="${v.id}" style="background:rgba(239,68,68,0.1); color:#f87171; border:1px solid rgba(239,68,68,0.2);">${displayCat} (${v.count})</span>`
                                }).join(' ')}
                                </div>`;
                            }

                            body += `</div>`;
                        }

                        if (section.event_ids && section.event_ids.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-bottom:8px;">TOP EVENT IDs</strong>`;
                            body += `<table class="context-table"><thead><tr><th>Event ID</th><th>Count</th></tr></thead><tbody>`;
                            section.event_ids.forEach(e => {
                                body += `<tr><td style="font-weight:bold; color:var(--accent-primary);">${e.id}</td><td>${e.count}</td></tr>`;
                            });
                            body += `</tbody></table><br>`;
                        }
                        if (section.tactics && section.tactics.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-bottom:8px;">TACTIC DISTRIBUTION</strong>`;
                            body += `<table class="context-table"><thead><tr><th>Tactic</th><th>Count</th></tr></thead><tbody>`;
                            section.tactics.forEach(t => {
                                body += `<tr><td><span class="tactic-badge">${t.category}</span></td><td>${t.count}</td></tr>`;
                            });
                            body += `</tbody></table>`;
                        }
                    } else if (section.type === "hunting") {
                        title = "CHRONOS HUNTER SUMMARY";
                        if (section.patterns && section.patterns.length > 0) {
                            body += `<div class="warning-banner"><i class="fas fa-exclamation-triangle"></i> SUSPICIOUS PATTERNS DETECTED</div>`;
                            body += `<div style="overflow-x:auto;"><table class="context-table" style="table-layout:fixed; width:100%;"><thead><tr><th style="width:140px; white-space:nowrap;">Time</th><th style="width:120px;">User</th><th>Command</th></tr></thead><tbody>`;
                            section.patterns.forEach(p => {
                                body += `<tr><td style="white-space:nowrap; font-size:0.78rem;">${p.timestamp}</td><td style="font-size:0.78rem;">${p.user}</td><td style="word-break: break-all; font-family:var(--font-mono); font-size:0.75rem; color:#ffb74d; line-height:1.4;">${p.command}</td></tr>`;
                            });
                            body += `</tbody></table></div><br>`;
                        } else {
                            body += `<div style="color:#00e676; padding:10px; border:1px solid #00e676; border-radius:4px; margin-bottom:15px;"><i class="fas fa-check-circle"></i> No common suspicious command-line patterns detected.</div>`;
                        }

                        if (section.network && section.network.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-bottom:8px;">TOP NETWORK DESTINATIONS</strong>`;
                            body += `<table class="context-table"><thead><tr><th>Destination</th><th>Count</th></tr></thead><tbody>`;
                            section.network.forEach(n => {
                                body += `<tr><td style="font-family:monospace;">${n.destination}</td><td>${n.count}</td></tr>`;
                            });
                            body += `</tbody></table><br>`;
                        }

                        if (section.logons && section.logons.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-bottom:8px;">AUTHENTICATION / LOGON SUMMARY</strong>`;
                            body += `<table class="context-table"><thead><tr><th>Event / Category</th><th>Count</th></tr></thead><tbody>`;
                            section.logons.forEach(l => {
                                let key = Object.keys(l).find(k => k !== 'count');
                                body += `<tr><td style="color:#cbd5e1;">${l[key]}</td><td>${l.count}</td></tr>`;
                            });
                            body += `</tbody></table>`;
                        }
                    } else if (section.type === "identity") {
                        title = "IDENTITY & ASSETS";
                        if (section.users && section.users.length > 0) {
                            body += `<div style="margin-bottom:10px;"><strong style="color:var(--text-secondary);">Top Users:</strong><br> ${section.users.map(u => `<span style="display:inline-block; background:rgba(255,255,255,0.05); padding:2px 6px; border-radius:3px; margin:2px 4px 2px 0;">${u.name} <strong style="color:var(--accent-primary)">(${u.count})</strong></span>`).join('')}</div>`;
                        }
                        if (section.hosts && section.hosts.length > 0) {
                            body += `<div style="margin-bottom:15px;"><strong style="color:var(--text-secondary);">Top Hosts:</strong><br> ${section.hosts.map(h => `<span style="display:inline-block; background:rgba(255,255,255,0.05); padding:2px 6px; border-radius:3px; margin:2px 4px 2px 0;">${h.name} <strong style="color:var(--accent-primary)">(${h.count})</strong></span>`).join('')}</div>`;
                        }
                        if (section.processes && section.processes.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-bottom:8px;">TOP PROCESSES</strong>`;
                            body += `<table class="context-table"><thead><tr><th>Process</th><th>Count</th></tr></thead><tbody>`;
                            section.processes.forEach(p => {
                                body += `<tr><td style="font-family:monospace;">${p.name}</td><td>${p.count}</td></tr>`;
                            });
                            body += `</tbody></table>`;
                        }
                        if (section.rare_processes && section.rare_processes.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-top:15px; margin-bottom:8px;">RARE PROCESSES <span style="font-size:0.7rem; font-weight:normal; color:#ffb74d;">(Potential Anomalies)</span></strong>`;
                            body += `<table class="context-table"><thead><tr><th>Process</th><th>Count</th></tr></thead><tbody>`;
                            section.rare_processes.forEach(p => {
                                body += `<tr><td style="font-family:monospace; color:#ffd54f;">${p.name}</td><td>${p.count}</td></tr>`;
                            });
                            body += `</tbody></table>`;
                        }
                        if (section.rare_paths && section.rare_paths.length > 0) {
                            body += `<strong style="color:var(--text-secondary); display:block; margin-top:15px; margin-bottom:8px;">RARE EXECUTION PATHS</strong>`;
                            body += `<table class="context-table"><thead><tr><th>Path</th><th>Count</th></tr></thead><tbody>`;
                            section.rare_paths.forEach(p => {
                                body += `<tr><td style="font-family:monospace; color:#ffd54f; font-size:0.75rem; word-break: break-all;">${p.name}</td><td>${p.count}</td></tr>`;
                            });
                            body += `</tbody></table>`;
                        }
                    }

                    html += `
                        <div class="report-section" style="margin-bottom: 25px;">
                            <h4 style="color:var(--accent-secondary); border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">${title}</h4>
                            <div style="font-size:0.85rem; padding:15px; background:rgba(0,0,0,0.25); border-radius:6px; border: 1px solid rgba(255,255,255,0.05);">${body}</div>
                        </div>
                    `;
                }
            });
        }

        // --- SIGMA DETECTIONS SECTION ---
        if (data.sigma_hits && data.sigma_hits.length > 0) {
            const levelColor = { critical: '#ff4d4d', high: '#f59e0b', medium: '#facc15', low: '#4ade80' };
            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#f97316; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        SIGMA RULE DETECTIONS (${data.sigma_hits.length} rules fired)
                    </h4>
                    <div style="font-size:0.85rem; padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(249,115,22,0.25);">
                        <table style="width:100%; border-collapse:collapse;">
                            <thead>
                                <tr style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase;">
                                    <th style="text-align:left; padding:4px 8px;">Level</th>
                                    <th style="text-align:left; padding:4px 8px;">Rule</th>
                                    <th style="text-align:left; padding:4px 8px;">Technique</th>
                                    <th style="text-align:right; padding:4px 8px;">Events</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.sigma_hits.map(h => `
                                    <tr style="border-top:1px solid rgba(255,255,255,0.05);">
                                        <td style="padding:5px 8px;">
                                            <span style="color:${levelColor[h.level] || '#94a3b8'}; font-weight:700; font-size:0.75rem; text-transform:uppercase;">${h.level}</span>
                                        </td>
                                        <td style="padding:5px 8px; color:var(--text-primary);">${h.title}</td>
                                        <td style="padding:5px 8px; color:var(--text-secondary); font-size:0.78rem; font-family:monospace;">${h.mitre_technique || '—'}</td>
                                        <td style="padding:5px 8px; text-align:right; color:var(--accent-primary); font-weight:600;">${h.matched_rows}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        if (container) container.innerHTML = html;
    }

    // Toast notification for PDF export status
    _showPdfToast(html, type = 'info', duration = 4000) {
        const existing = document.getElementById('chronos-pdf-toast');
        if (existing) existing.remove();

        const colors = {
            success: { bg: 'rgba(16,185,129,0.15)', border: '#10b981', icon: '✅' },
            info:    { bg: 'rgba(59,130,246,0.15)',  border: '#3b82f6', icon: '📄' },
            error:   { bg: 'rgba(239,68,68,0.15)',   border: '#ef4444', icon: '❌' }
        };
        const c = colors[type] || colors.info;

        const toast = document.createElement('div');
        toast.id = 'chronos-pdf-toast';
        toast.style.cssText = `
            position:fixed; bottom:24px; right:24px; z-index:99999;
            background:${c.bg}; border:1px solid ${c.border}; border-radius:8px;
            padding:14px 18px; max-width:360px; font-size:0.85rem;
            color:var(--text-primary,#e2e8f0); backdrop-filter:blur(8px);
            box-shadow:0 4px 20px rgba(0,0,0,0.4);
            animation: fadeInUp 0.3s ease;
        `;
        toast.innerHTML = html;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.transition = 'opacity 0.4s';
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 400);
        }, duration);
    }
}
