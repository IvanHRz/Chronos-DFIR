import { API } from './api.js?v=189';
import ChronosState from './state.js?v=189';
import events from './events.js?v=189';

export class ActionManager {
    constructor(gridManager, chartManager) {
        this.grid = gridManager;
        this.charts = chartManager;
    }

    /**
     * Robust file download: sets isDownloading flag to bypass beforeunload guard,
     * uses an offscreen <a> element with the download attribute.
     */
    _closeExportDropdown() {
        const menu = document.querySelector('.dropdown-content');
        if (menu) menu.classList.remove('open');
    }

    /**
     * Export forensic summary as CSV from the context modal data
     */
    _buildForensicSummaryRows(data, filename) {
        // Build structured rows with consistent 5-column layout — ALL modal sections
        const MAX_COLS = 5;
        const pad = (arr) => { while (arr.length < MAX_COLS) arr.push(""); return arr; };
        const section = (title) => { rows.push(pad([])); rows.push(pad([`═══ ${title} ═══`])); };
        const headers = (...cols) => { rows.push(pad(cols)); rows.push(pad(cols.map(() => "────────"))); };
        const rows = [];

        // ── 1. HEADER METADATA ──
        rows.push(pad(["═══ CHRONOS-DFIR FORENSIC SUMMARY ═══"]));
        headers("Field", "Value");
        rows.push(pad(["File", filename]));
        rows.push(pad(["Risk Level", `${data.risk_level || 'N/A'} (Score: ${data.risk_score ?? 'N/A'})`]));
        rows.push(pad(["Primary Identity", data.primary_identity || "N/A"]));
        rows.push(pad(["Top Tactic", data.top_tactic || "N/A"]));
        rows.push(pad(["Total Records", String(data.total_records || "N/A")]));
        rows.push(pad(["Events/Sec", String(data.eps || "0")]));

        // ── 2. RESULTS SECTIONS (timeline, context, hunting, identity) ──
        if (data.results && Array.isArray(data.results)) {
            data.results.forEach(s => {
                if (!s || typeof s !== 'object') return;

                if (s.type === "timeline") {
                    section("TIMELINE ANALYSIS");
                    if (s.peaks?.length) {
                        headers("Peak #", "Hour", "Events");
                        s.peaks.forEach((p, i) => rows.push(pad([String(i + 1), p.hour || "", String(p.count || 0)])));
                    }
                    if (s.time_range) rows.push(pad(["Time Range", s.time_range]));
                }

                else if (s.type === "context") {
                    section("SANITIZED FORENSIC SUMMARY");
                    const lists = [
                        ["Top IPs", s.ips, "id"],
                        ["Top Users", s.users, "id"],
                        ["Top Hosts", s.hosts, "id"],
                        ["Top Directories", s.paths, "id"],
                        ["HTTP Methods", s.methods, "id"],
                        ["Violations", s.violations, "id"],
                    ];
                    for (const [label, items, key] of lists) {
                        if (items?.length) {
                            rows.push(pad([label]));
                            headers("Name", "Count");
                            items.forEach(it => rows.push(pad([String(it[key] || it.name || ""), String(it.count || 0)])));
                        }
                    }
                    if (s.event_ids?.length) {
                        rows.push(pad(["Top Event IDs"]));
                        headers("Event ID", "Count");
                        s.event_ids.forEach(e => rows.push(pad([String(e.id || ""), String(e.count || 0)])));
                    }
                    if (s.tactics?.length) {
                        rows.push(pad(["Tactic Distribution"]));
                        headers("Tactic", "Count");
                        s.tactics.forEach(t => rows.push(pad([t.category || "", String(t.count || 0)])));
                    }
                }

                else if (s.type === "hunting") {
                    section("CHRONOS HUNTER SUMMARY");
                    if (s.patterns?.length) {
                        rows.push(pad(["SUSPICIOUS PATTERNS DETECTED"]));
                        headers("Timestamp", "User", "Command");
                        s.patterns.forEach(p => rows.push(pad([p.timestamp || "", p.user || "", p.command || ""])));
                    } else {
                        rows.push(pad(["No suspicious command-line patterns detected."]));
                    }
                    if (s.network?.length) {
                        rows.push(pad(["Top Network Destinations"]));
                        headers("Destination", "Count");
                        s.network.forEach(n => rows.push(pad([n.destination || "", String(n.count || 0)])));
                    }
                    if (s.logons?.length) {
                        rows.push(pad(["Authentication / Logon Summary"]));
                        headers("Event / Category", "Count");
                        s.logons.forEach(l => {
                            const key = Object.keys(l).find(k => k !== 'count');
                            rows.push(pad([key ? String(l[key]) : "", String(l.count || 0)]));
                        });
                    }
                }

                else if (s.type === "identity") {
                    section("IDENTITY & ASSETS");
                    const idLists = [
                        ["Top Users", s.users],
                        ["Top Hosts", s.hosts],
                        ["Top Processes", s.processes],
                        ["Rare Processes (Anomalies)", s.rare_processes],
                        ["Rare Execution Paths", s.rare_paths],
                    ];
                    for (const [label, items] of idLists) {
                        if (items?.length) {
                            rows.push(pad([label]));
                            headers("Name", "Count");
                            items.forEach(it => rows.push(pad([it.name || "", String(it.count || 0)])));
                        }
                    }
                }
            });
        }

        // ── 3. SIGMA DETECTIONS (with evidence rows) ──
        if (data.sigma_hits?.length) {
            section("SIGMA RULE DETECTIONS");
            headers("Level", "Rule", "MITRE Technique", "Matched Events", "Description");
            for (const h of data.sigma_hits) {
                rows.push([
                    h.level?.toUpperCase() || "", h.title || "",
                    h.mitre_technique || "", String(h.matched_rows || 0), h.description || ""
                ]);
                // Include sample evidence rows if available
                if (h.sample_evidence?.length) {
                    const evCols = Object.keys(h.sample_evidence[0]).filter(k => k !== '_id').slice(0, 5);
                    rows.push(pad([`  Evidence (${h.sample_evidence.length} samples):`]));
                    rows.push(pad(evCols));
                    for (const ev of h.sample_evidence.slice(0, 10)) {
                        rows.push(pad(evCols.map(c => String(ev[c] ?? "").substring(0, 200))));
                    }
                }
            }
            rows.push(pad([]));
        }

        // ── 4. YARA DETECTIONS ──
        if (data.yara_hits?.length) {
            section("YARA DETECTIONS");
            headers("Rule", "Category", "Tags", "Strings Matched");
            for (const y of data.yara_hits) {
                rows.push(pad([y.rule || "", y.namespace || "", (y.tags || []).join(", "), String(y.strings_matched || 0)]));
            }
        }

        // ── 5. MITRE KILL CHAIN ──
        if (data.mitre_kill_chain?.length) {
            section("MITRE ATT&CK KILL CHAIN");
            headers("Tactic", "Threat Level", "Count", "Description");
            for (const m of data.mitre_kill_chain) {
                rows.push(pad([m.tactic || "", m.threat_level || "", String(m.count || 0), m.description || ""]));
            }
        }

        // ── 6. CROSS-SOURCE CORRELATION (new structure) ──
        const corr = data.cross_source_correlation;
        if (corr?.chains?.length) {
            section("CROSS-SOURCE CORRELATION");
            headers("Pivot Type", "Entity", "Events", "First Seen", "Last Seen");
            for (const c of corr.chains) {
                rows.push(pad([c.pivot_type || "", c.entity || "", String(c.total_events || 0), c.first_seen || "", c.last_seen || ""]));
            }
        }
        // Fallback: old results array format
        if (Array.isArray(data.results) && !corr?.chains?.length) {
            const oldCorr = data.results.find?.(r => r?.cross_source_correlation);
            if (oldCorr?.cross_source_correlation?.length) {
                section("CROSS-SOURCE CORRELATION");
                headers("Entity", "Type", "Sources", "Events");
                for (const c of oldCorr.cross_source_correlation) {
                    rows.push(pad([c.entity || "", c.type || "", (c.sources || []).join(", "), String(c.count || 0)]));
                }
            }
        }

        // ── 7. SESSION PROFILES ──
        if (data.session_profiles?.length) {
            section("SESSION PROFILES");
            headers("IP / Identity", "Requests", "Dwell Time", "Unique Paths", "User Agent");
            for (const sp of data.session_profiles) {
                rows.push([sp.ip || sp.identity || "", String(sp.requests || 0), sp.dwell || "",
                    String(sp.unique_paths || 0), (sp.user_agent || "").substring(0, 100)]);
            }
        }

        // ── 8. RISK JUSTIFICATION ──
        if (data.risk_justify) {
            section("RISK JUSTIFICATION");
            const justifyList = Array.isArray(data.risk_justify) ? data.risk_justify : [data.risk_justify];
            for (const j of justifyList) {
                rows.push(pad([`• ${j}`]));
            }
        }

        return rows;
    }

    _exportForensicSummaryCSV(data, filename) {
        const rows = this._buildForensicSummaryRows(data, filename);
        const csvContent = rows.map(r =>
            r.map(v => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")
        ).join("\n");

        const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const fname = `Forensic_Summary_${filename.replace(/\.[^.]+$/, '')}.csv`;
        window.isDownloading = true;
        const a = document.createElement('a');
        a.href = url; a.download = fname;
        a.style.position = 'fixed'; a.style.left = '-9999px';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); window.isDownloading = false; }, 3000);
    }

    async _exportForensicSummaryXLSX(data, filename) {
        // Send forensic summary data to backend for proper XLSX generation with xlsxwriter
        try {
            window.isDownloading = true;
            const resp = await fetch('/api/export/forensic-summary', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename, summary: data })
            });
            if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
            const result = await resp.json();
            if (result.download_url) {
                await this._triggerDownload(result.download_url, result.filename || 'ForensicSummary.xlsx');
            }
        } catch (e) {
            console.error('XLSX export failed, falling back to CSV:', e);
            this._exportForensicSummaryCSV(data, filename);
            window.isDownloading = false;
        }
    }

    /**
     * Export filtered data (CSV/Excel/JSON) via /api/export_filtered
     */
    async _exportFiltered(filename, format) {
        try {
            console.log(`[EXPORT] _exportFiltered('${format}') for ${filename}`);
            const tbl = this.grid?.table || window.grid?.table;

            // Prioritize ChronosState.selectedIds (source of truth) over grid method
            let selectedIds = ChronosState.selectedIds || [];
            if (selectedIds.length === 0) {
                try { selectedIds = this.grid?.getSelectedIds ? this.grid.getSelectedIds() : []; } catch (e) { /* ignore */ }
            }

            let visibleCols = [];
            try {
                if (tbl) visibleCols = tbl.getColumns().filter(c => c.isVisible() && c.getField() && c.getField() !== '_id').map(c => c.getField());
            } catch (e) { /* ignore */ }

            let sort_col = null, sort_dir = null;
            try {
                if (tbl) {
                    const sorters = tbl.getSorters();
                    if (sorters.length > 0) { sort_col = sorters[0].field; sort_dir = sorters[0].dir; }
                }
            } catch (e) { /* ignore */ }

            console.log('[EXPORT] Sending:', {
                query: ChronosState.currentQuery,
                col_filters: ChronosState.currentColumnFilters,
                selected_ids: selectedIds.length + ' IDs',
                start_time: ChronosState.startTime,
                end_time: ChronosState.endTime
            });
            window.isDownloading = true;
            const result = await API.exportData(filename, {
                format,
                query: ChronosState.currentQuery || "",
                start_time: ChronosState.startTime || "",
                end_time: ChronosState.endTime || "",
                col_filters: JSON.stringify(ChronosState.currentColumnFilters || []),
                selected_ids: selectedIds,
                visible_columns: visibleCols,
                sort_col,
                sort_dir
            });
            console.log(`[EXPORT] Response:`, result);

            if (result.download_url) {
                await this._triggerDownload(result.download_url, result.filename || `Export.${format}`);
            } else {
                alert("Export failed: " + (result.error || result.detail || JSON.stringify(result)));
            }
        } catch (e) {
            console.error("[EXPORT] Error:", e);
            alert("Export error: " + e.message);
        }
    }

    async _triggerDownload(url, filename) {
        window.isDownloading = true;
        console.log(`[DOWNLOAD] Triggering: ${url} (${filename})`);
        this._closeExportDropdown();
        // Use direct server URL — backend sends Content-Disposition: attachment
        // Blob URLs strip HTTP headers and Arc/Chromium shows internal UUIDs
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || 'download';
        a.style.position = 'fixed';
        a.style.left = '-9999px';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            window.isDownloading = false;
        }, 4000);
    }

    // Called automatically after file loads to populate the forensic dashboard bar
    _dashRequestId = 0;
    async loadDashboardCards() {
        const fileToExport = ChronosState.processedFiles?.csv || ChronosState.currentFilename;
        if (!fileToExport) return;
        const requestId = ++this._dashRequestId;
        console.log('[DASHBOARD] Refreshing with:', {
            query: ChronosState.currentQuery,
            col_filters: ChronosState.currentColumnFilters,
            selected_ids: (ChronosState.selectedIds || []).length + ' IDs',
            start_time: ChronosState.startTime,
            end_time: ChronosState.endTime
        });
        try {
            const data = await API.getForensicReport({
                filename: fileToExport,
                query: ChronosState.currentQuery || "",
                col_filters: JSON.stringify(ChronosState.currentColumnFilters || []),
                selected_ids: ChronosState.selectedIds || [],
                start_time: ChronosState.startTime || "",
                end_time: ChronosState.endTime || ""
            });
            // Ignore stale responses from previous requests (race condition guard)
            if (requestId !== this._dashRequestId) return;
            this.renderForensicReport(data, null); // null = don't update modal content
        } catch (e) {
            console.error('[DASHBOARD] Failed to refresh cards:', e.message);
        }
    }

    softReset() {
        // Clear all UI state without wiping session
        ChronosState.resetFilters();
        if (this.grid) this.grid.clearFilters();

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
            const tbl = window.grid?.table;
            const sorters = tbl?.getSorters() || [];
            let sort_col = null, sort_dir = null;
            if (sorters.length > 0) {
                sort_col = sorters[0].field;
                sort_dir = sorters[0].dir;
            }

            let visibleCols = [];
            if (tbl) {
                visibleCols = tbl.getColumns()
                    .filter(c => c.isVisible() && c.getField() && c.getField() !== '_id')
                    .map(c => c.getField());
            }

            const resp = await fetch('/api/export/split-zip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: ChronosState.currentFilename,
                    chunk_size_mb: parseInt(chunkSize),
                    zip_format: zipFormat,
                    query: ChronosState.currentQuery,
                    col_filters: JSON.stringify(ChronosState.currentColumnFilters),
                    selected_ids: ChronosState.selectedIds,
                    start_time: ChronosState.startTime || "",
                    end_time: ChronosState.endTime || "",
                    sort_col: sort_col,
                    sort_dir: sort_dir,
                    visible_columns: visibleCols
                })
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.error || "Split failed");
            }

            const data = await resp.json();
            if (data.download_url) {
                await this._triggerDownload(data.download_url, data.filename || 'Split.zip');
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
            const tbl = this.grid?.table || window.grid?.table;
            let sort_col = null, sort_dir = null;
            try {
                if (tbl) {
                    const sorters = tbl.getSorters();
                    if (sorters.length > 0) { sort_col = sorters[0].field; sort_dir = sorters[0].dir; }
                }
            } catch (_) { /* ignore */ }

            const resp = await fetch('/api/export/html', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: fileToExport,
                    original_filename: ChronosState.currentFilename,
                    query: ChronosState.currentQuery,
                    col_filters: JSON.stringify(ChronosState.currentColumnFilters),
                    selected_ids: ChronosState.selectedIds || [],
                    start_time: ChronosState.startTime,
                    end_time: ChronosState.endTime,
                    sort_col: sort_col,
                    sort_dir: sort_dir
                })
            });

            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.error || "Report generation failed");
            }

            const data = await resp.json();
            if (data.download_url) {
                await this._triggerDownload(data.download_url, data.filename || 'Report.html');
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
                col_filters: JSON.stringify(ChronosState.currentColumnFilters || []),
                selected_ids: ChronosState.selectedIds || [],
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

            // CSV / Excel forensic summary export from modal
            const dlCsv = document.getElementById("modal-dl-csv");
            if (dlCsv) {
                dlCsv.onclick = (e) => {
                    e.preventDefault();
                    expMenu.classList.remove('open');
                    this._exportForensicSummaryCSV(data, fileToExport);
                };
            }
            const dlXlsx = document.getElementById("modal-dl-xlsx");
            if (dlXlsx) {
                dlXlsx.onclick = (e) => {
                    e.preventDefault();
                    expMenu.classList.remove('open');
                    this._exportForensicSummaryXLSX(data, fileToExport);
                };
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
                                col_filters: JSON.stringify(ChronosState.currentColumnFilters || []),
                                selected_ids: ChronosState.selectedIds || [],
                                start_time: ChronosState.startTime || "",
                                end_time: ChronosState.endTime || ""
                            })
                        });
                        const result = await resp.json();
                        if (result.download_url) {
                            await this._triggerDownload(result.download_url, result.filename || 'ChronosReport.pdf');

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
        if (tacticEl) {
            tacticEl.innerText = tacticVal;
            // Show sigma hit count as subtitle if available
            const tacticCard = tacticEl.closest('.dash-card');
            if (tacticCard) {
                const existingSub = tacticCard.querySelector('.dash-sigma-count');
                if (existingSub) existingSub.remove();
                if (data.sigma_hits?.length > 0) {
                    const sub = document.createElement('span');
                    sub.className = 'dash-sigma-count';
                    sub.style.cssText = 'display:block; font-size:0.6rem; color:#f97316; margin-top:2px;';
                    sub.innerText = `${data.sigma_hits.length} Sigma detection${data.sigma_hits.length > 1 ? 's' : ''}`;
                    tacticCard.appendChild(sub);
                }
            }
        }
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

        // Flash animation to indicate data refreshed
        const dashEl = document.getElementById('forensic-dash');
        if (dashEl) {
            dashEl.classList.remove('hidden');
            dashEl.querySelectorAll('.dash-card').forEach(card => {
                card.style.transition = 'background-color 0.3s';
                card.style.backgroundColor = 'rgba(59,130,246,0.15)';
                setTimeout(() => { card.style.backgroundColor = ''; }, 600);
            });
        }

        // TTP Summary Strip — severity badges + top MITRE techniques
        const ttpStrip = document.getElementById('ttp-summary-strip');
        if (ttpStrip) {
            if (data.sigma_hits?.length > 0) {
                ttpStrip.classList.remove('hidden');
                const levelCounts = {};
                const techMap = new Map();
                const levelColors = { critical: '#ff4d4d', high: '#f59e0b', medium: '#facc15', low: '#4ade80' };
                data.sigma_hits.forEach(h => {
                    const lvl = (h.level || 'low').toLowerCase();
                    levelCounts[lvl] = (levelCounts[lvl] || 0) + (h.matched_rows || 1);
                    if (h.mitre_technique) {
                        const tech = h.mitre_technique.split(' ')[0]; // e.g. "T1003.001"
                        techMap.set(tech, (techMap.get(tech) || 0) + (h.matched_rows || 1));
                    }
                });
                let stripHtml = '<span style="color:#94a3b8;text-transform:uppercase;margin-right:4px;font-weight:600;">TTPs:</span>';
                for (const [lvl, count] of Object.entries(levelCounts)) {
                    const col = levelColors[lvl] || '#94a3b8';
                    stripHtml += `<span class="ttp-badge" style="border-color:${col};color:${col};">${lvl.toUpperCase()}: ${count}</span>`;
                }
                const sortedTechs = [...techMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
                sortedTechs.forEach(([tech, cnt]) => {
                    stripHtml += `<span class="ttp-tech">${tech} (${cnt})</span>`;
                });
                ttpStrip.innerHTML = stripHtml;
            } else {
                ttpStrip.classList.add('hidden');
                ttpStrip.innerHTML = '';
            }
        }

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

        // --- SIGMA DETECTIONS SECTION (Expandable with Evidence) ---
        if (data.sigma_hits && data.sigma_hits.length > 0) {
            const levelColor = { critical: '#ff4d4d', high: '#f59e0b', medium: '#facc15', low: '#4ade80' };
            const sigmaId = `sigma-${Date.now()}`;
            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#f97316; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        SIGMA RULE DETECTIONS (${data.sigma_hits.length} rules fired)
                    </h4>
                    <div style="font-size:0.85rem; padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(249,115,22,0.25);">
                        ${data.sigma_hits.map((h, idx) => {
                            const color = levelColor[h.level] || '#94a3b8';
                            const hasEvidence = h.sample_evidence && h.sample_evidence.length > 0;
                            const evidenceId = `${sigmaId}-ev-${idx}`;
                            const displayRows = hasEvidence ? h.sample_evidence.slice(0, 10) : [];
                            const evidenceCols = hasEvidence ? Object.keys(displayRows[0]).filter(k => k !== '_id') : [];
                            const remaining = h.matched_rows - displayRows.length;

                            let rowHtml = `
                            <div style="border-top:1px solid rgba(255,255,255,0.05); padding:6px 0;">
                                <div style="display:flex; align-items:center; gap:8px; cursor:${hasEvidence ? 'pointer' : 'default'}; padding:4px 8px;"
                                     ${hasEvidence ? `onclick="document.getElementById('${evidenceId}').classList.toggle('hidden')"` : ''}>
                                    ${hasEvidence ? `<span style="color:#64748b; font-size:0.7rem; width:14px; text-align:center;" id="${evidenceId}-arrow">&#9654;</span>` : '<span style="width:14px;"></span>'}
                                    <span style="color:${color}; font-weight:700; font-size:0.75rem; text-transform:uppercase; min-width:60px;">${h.level}</span>
                                    <span style="color:var(--text-primary); flex:1;">${h.title}</span>
                                    <span style="color:var(--text-secondary); font-size:0.78rem; font-family:monospace; min-width:90px;">${h.mitre_technique || '\u2014'}</span>
                                    <span style="color:var(--accent-primary); font-weight:600; min-width:50px; text-align:right;">${h.matched_rows}</span>
                                </div>`;

                            if (hasEvidence) {
                                rowHtml += `
                                <div id="${evidenceId}" class="hidden" style="padding:6px 8px 8px 30px;">
                                    <div style="overflow-x:auto; max-height:280px; overflow-y:auto;">
                                        <table style="width:100%; border-collapse:collapse; font-size:0.75rem;">
                                            <thead>
                                                <tr style="color:var(--text-secondary); font-size:0.68rem; text-transform:uppercase;">
                                                    <th style="text-align:left; padding:3px 6px; border-bottom:1px solid rgba(255,255,255,0.1);">Row#</th>
                                                    ${evidenceCols.map(c => `<th style="text-align:left; padding:3px 6px; border-bottom:1px solid rgba(255,255,255,0.1);">${c}</th>`).join('')}
                                                </tr>
                                            </thead>
                                            <tbody>
                                                ${displayRows.map(row => `
                                                    <tr style="border-top:1px solid rgba(255,255,255,0.03);">
                                                        <td style="padding:3px 6px; color:var(--accent-primary); font-family:monospace;">${row._id || ''}</td>
                                                        ${evidenceCols.map(c => {
                                                            let val = row[c] != null ? String(row[c]) : '';
                                                            if (val.length > 120) val = val.substring(0, 120) + '\u2026';
                                                            return `<td style="padding:3px 6px; color:var(--text-primary); font-family:monospace; font-size:0.72rem; word-break:break-all; max-width:300px;">${val}</td>`;
                                                        }).join('')}
                                                    </tr>
                                                `).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:12px; margin-top:6px;">
                                        ${remaining > 0 ? `<span style="font-size:0.72rem; color:var(--text-secondary);">+ ${remaining} more rows</span>` : ''}
                                        ${h.all_row_ids && h.all_row_ids.length > 0 ? `
                                            <button onclick="window._chronosViewSigmaInGrid && window._chronosViewSigmaInGrid(${JSON.stringify(h.all_row_ids)})"
                                                style="font-size:0.72rem; padding:3px 10px; background:rgba(249,115,22,0.15); border:1px solid rgba(249,115,22,0.4); border-radius:4px; color:#f97316; cursor:pointer;">
                                                View all in Grid
                                            </button>` : ''}
                                    </div>
                                </div>`;
                            }
                            rowHtml += `</div>`;
                            return rowHtml;
                        }).join('')}
                    </div>
                </div>
            `;
        }

        // --- YARA DETECTIONS SECTION ---
        if (data.yara_hits && data.yara_hits.length > 0) {
            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#ef4444; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        YARA DETECTIONS (${data.yara_hits.length} rules matched)
                    </h4>
                    <div style="font-size:0.85rem; padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(239,68,68,0.25);">
                        <table style="width:100%; border-collapse:collapse;">
                            <thead>
                                <tr style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase;">
                                    <th style="text-align:left; padding:4px 8px;">Rule</th>
                                    <th style="text-align:left; padding:4px 8px;">Category</th>
                                    <th style="text-align:left; padding:4px 8px;">Tags</th>
                                    <th style="text-align:right; padding:4px 8px;">Strings</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.yara_hits.map(y => `
                                    <tr style="border-top:1px solid rgba(255,255,255,0.05);">
                                        <td style="padding:5px 8px; color:#ef4444; font-weight:600;">${y.rule}</td>
                                        <td style="padding:5px 8px; color:var(--text-secondary); font-size:0.78rem;">${y.namespace || '\u2014'}</td>
                                        <td style="padding:5px 8px; font-size:0.75rem;">
                                            ${(y.tags || []).map(t => `<span style="display:inline-block; background:rgba(239,68,68,0.1); color:#f87171; border:1px solid rgba(239,68,68,0.2); padding:1px 6px; border-radius:3px; margin:1px 2px; font-size:0.7rem;">${t}</span>`).join('')}
                                        </td>
                                        <td style="padding:5px 8px; text-align:right; color:var(--accent-primary); font-weight:600;">${y.strings_matched}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // --- MITRE ATT&CK KILL CHAIN SECTION ---
        if (data.mitre_kill_chain && data.mitre_kill_chain.length > 0) {
            const tacticColors = {
                initial_access: '#ef4444', execution: '#f97316', persistence: '#eab308',
                privilege_escalation: '#84cc16', defense_evasion: '#22c55e',
                credential_access: '#14b8a6', discovery: '#06b6d4', lateral_movement: '#3b82f6',
                collection: '#6366f1', command_and_control: '#8b5cf6', exfiltration: '#a855f7',
                impact: '#ec4899', reconnaissance: '#f43f5e', resource_development: '#fb923c', unknown: '#64748b'
            };
            const sevBadge = { critical: '#ff4d4d', high: '#f59e0b', medium: '#facc15', low: '#4ade80' };
            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#a855f7; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        MITRE ATT&CK KILL CHAIN (${data.mitre_kill_chain.length} tactics observed)
                    </h4>
                    <div style="display:flex; flex-wrap:wrap; gap:10px; padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(168,85,247,0.25);">
                        ${data.mitre_kill_chain.map(t => `
                            <div style="flex:1; min-width:160px; background:rgba(0,0,0,0.3); border-radius:6px; padding:10px; border-left:3px solid ${tacticColors[t.tactic] || '#64748b'};">
                                <div style="font-size:0.7rem; text-transform:uppercase; color:${tacticColors[t.tactic] || '#64748b'}; font-weight:700; margin-bottom:2px;">
                                    ${t.tactic_id || ''} ${t.tactic.replace(/_/g, ' ')}
                                </div>
                                ${t.tactic_description ? `<div style="font-size:0.65rem; color:var(--text-secondary); margin-bottom:6px; font-style:italic;">${t.tactic_description}</div>` : ''}
                                ${t.techniques.map(tech => `
                                    <div style="font-size:0.78rem; color:var(--text-primary); margin-bottom:3px;">
                                        <span style="font-family:monospace; color:var(--text-secondary); font-size:0.72rem;">${tech.technique || '—'}</span>
                                        ${tech.title}
                                        <span style="float:right; color:${sevBadge[tech.level] || '#94a3b8'}; font-size:0.7rem; font-weight:700;">${tech.matched_rows}</span>
                                    </div>
                                `).join('')}
                                <div style="margin-top:6px; font-size:0.68rem; color:var(--text-secondary);">
                                    Severity: <span style="color:${sevBadge[t.max_severity] || '#94a3b8'}; font-weight:700; text-transform:uppercase;">${t.max_severity}</span>
                                    &middot; ${t.total_hits} hits
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // --- CROSS-SOURCE CORRELATION SECTION ---
        if (data.cross_source_correlation && data.cross_source_correlation.chains && data.cross_source_correlation.chains.length > 0) {
            const corr = data.cross_source_correlation;
            const pivotIcon = { ip: '🌐', user: '👤', host: '🖥' };
            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#06b6d4; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        CROSS-SOURCE CORRELATION (${corr.total_correlated} events linked)
                    </h4>
                    <div style="font-size:0.85rem; padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(6,182,212,0.25);">
                        <table style="width:100%; border-collapse:collapse;">
                            <thead>
                                <tr style="color:var(--text-secondary); font-size:0.75rem; text-transform:uppercase;">
                                    <th style="text-align:left; padding:4px 8px;">Pivot</th>
                                    <th style="text-align:left; padding:4px 8px;">Entity</th>
                                    <th style="text-align:right; padding:4px 8px;">Events</th>
                                    <th style="text-align:left; padding:4px 8px;">First Seen</th>
                                    <th style="text-align:left; padding:4px 8px;">Last Seen</th>
                                    <th style="text-align:right; padding:4px 8px;">Dwell</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${corr.chains.map(c => {
                                    const dwell = c.dwell_time_seconds != null
                                        ? (c.dwell_time_seconds > 3600 ? (c.dwell_time_seconds/3600).toFixed(1) + 'h' : (c.dwell_time_seconds/60).toFixed(0) + 'm')
                                        : '\u2014';
                                    const hasRowIds = c.row_ids && c.row_ids.length > 0;
                                    return `
                                    <tr style="border-top:1px solid rgba(255,255,255,0.05);">
                                        <td style="padding:5px 8px;">${pivotIcon[c.pivot_type] || '\uD83D\uDD17'} ${c.pivot_type}</td>
                                        <td style="padding:5px 8px; font-family:monospace; color:var(--accent-primary); font-size:0.8rem;">
                                            ${c.pivot_value}
                                            ${c.sources && c.sources.length > 1 ? `<span style="font-size:0.65rem; color:#a855f7; margin-left:4px;">[${c.sources.length} sources]</span>` : ''}
                                            ${hasRowIds ? `<button onclick="window._chronosViewSigmaInGrid && window._chronosViewSigmaInGrid(${JSON.stringify(c.row_ids)})"
                                                style="font-size:0.65rem; padding:1px 6px; margin-left:6px; background:rgba(6,182,212,0.15); border:1px solid rgba(6,182,212,0.4); border-radius:3px; color:#06b6d4; cursor:pointer; vertical-align:middle;">
                                                View</button>` : ''}
                                        </td>
                                        <td style="padding:5px 8px; text-align:right; font-weight:600; color:var(--text-primary);">${c.event_count}</td>
                                        <td style="padding:5px 8px; font-size:0.75rem; color:var(--text-secondary);">${c.first_seen || '\u2014'}</td>
                                        <td style="padding:5px 8px; font-size:0.75rem; color:var(--text-secondary);">${c.last_seen || '\u2014'}</td>
                                        <td style="padding:5px 8px; text-align:right; color:#f59e0b; font-weight:600;">${dwell}</td>
                                    </tr>`;
                                }).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // --- SESSION PROFILES SECTION ---
        if (data.session_profiles && data.session_profiles.length > 0) {
            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#f43f5e; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        ATTACKER SESSION PROFILES (${data.session_profiles.length} sources)
                    </h4>
                    <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:10px; padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(244,63,94,0.25);">
                        ${data.session_profiles.map(s => {
                            const dwell = s.dwell_time_seconds != null
                                ? (s.dwell_time_seconds > 3600 ? (s.dwell_time_seconds/3600).toFixed(1) + 'h' : (s.dwell_time_seconds/60).toFixed(0) + 'm')
                                : '—';
                            const threat = s.request_count > 500 ? 'HIGH' : s.request_count > 100 ? 'MEDIUM' : 'LOW';
                            const threatColor = { HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#4ade80' };
                            return `
                            <div style="background:rgba(0,0,0,0.3); border-radius:6px; padding:12px; border-left:3px solid ${threatColor[threat]};">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                    <span style="font-family:monospace; color:var(--accent-primary); font-size:0.9rem;">${s.attacker_ip}</span>
                                    <span style="font-size:0.65rem; font-weight:700; color:${threatColor[threat]}; text-transform:uppercase; padding:2px 6px; border:1px solid ${threatColor[threat]}; border-radius:3px;">${threat}</span>
                                </div>
                                <div style="font-size:0.78rem; color:var(--text-secondary); line-height:1.6;">
                                    <div>Requests: <span style="color:var(--text-primary); font-weight:600;">${s.request_count}</span></div>
                                    <div>Dwell: <span style="color:#f59e0b; font-weight:600;">${dwell}</span></div>
                                    ${s.unique_paths ? `<div>Unique paths: <span style="color:var(--text-primary);">${s.unique_paths}</span></div>` : ''}
                                    ${s.user_agent && s.user_agent !== 'N/A' ? `<div style="font-size:0.7rem; margin-top:4px; color:var(--text-secondary); word-break:break-all;">UA: ${s.user_agent}</div>` : ''}
                                </div>
                            </div>`;
                        }).join('')}
                    </div>
                </div>
            `;
        }

        // --- EXECUTION ARTIFACTS SECTION (only if real data exists) ---
        if (data.execution_artifacts && data.execution_artifacts.artifact_types_detected && data.execution_artifacts.artifact_types_detected.length > 0) {
            const arts = data.execution_artifacts;
            const artifactIcons = { shimcache: '🗃', amcache: '📦', prefetch: '⚡', srum: '📊', generic_execution_refs: '🔍' };
            // Filter to types that actually have items
            const typesWithData = arts.artifact_types_detected.filter(type => {
                const items = type === 'generic_execution_refs' ? (arts.generic_refs || []) : (arts[type] || []);
                return items.length > 0;
            });
            if (typesWithData.length > 0) {
                html += `
                    <div class="report-section" style="margin-bottom:25px;">
                        <h4 style="color:#22c55e; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                            EXECUTION ARTIFACTS (${typesWithData.join(', ')})
                        </h4>
                        <div style="padding:10px; background:rgba(0,0,0,0.25); border-radius:6px; border:1px solid rgba(34,197,94,0.25);">
                            ${typesWithData.map(type => {
                                const items = type === 'generic_execution_refs' ? (arts.generic_refs || []) : (arts[type] || []);
                                return `
                                <div style="margin-bottom:12px;">
                                    <div style="font-size:0.8rem; font-weight:700; color:#22c55e; text-transform:uppercase; margin-bottom:6px;">
                                        ${artifactIcons[type] || '📄'} ${type.replace(/_/g, ' ')} (${items.length} entries)
                                    </div>
                                    <div style="font-size:0.75rem; font-family:monospace; max-height:200px; overflow-y:auto;">
                                        ${items.map(item => `
                                            <div style="padding:3px 8px; border-bottom:1px solid rgba(255,255,255,0.03); color:var(--text-secondary);">
                                                ${Object.entries(item).map(([k,v]) => `<span style="color:var(--text-secondary)">${k}:</span> <span style="color:var(--text-primary)">${String(v).substring(0,120)}</span>`).join(' &middot; ')}
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>`;
                            }).join('')}
                        </div>
                    </div>
                `;
            }
        }

        // --- THREAT INTELLIGENCE ENRICHMENT SECTION ---
        if (data.threat_intelligence && data.threat_intelligence.total_enriched > 0) {
            const ti = data.threat_intelligence;
            const countryFlags = {
                US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',FR:'🇫🇷',CN:'🇨🇳',RU:'🇷🇺',JP:'🇯🇵',KR:'🇰🇷',
                BR:'🇧🇷',IN:'🇮🇳',AU:'🇦🇺',CA:'🇨🇦',NL:'🇳🇱',IT:'🇮🇹',ES:'🇪🇸',SE:'🇸🇪',
                UA:'🇺🇦',IR:'🇮🇷',KP:'🇰🇵',RO:'🇷🇴',PL:'🇵🇱',MX:'🇲🇽',AR:'🇦🇷',CL:'🇨🇱',
            };
            const getFlag = (cc) => countryFlags[cc] || '🏴';
            const abuseColor = (score) => score > 75 ? '#ef4444' : score > 25 ? '#f59e0b' : '#4ade80';
            const vtColor = (m) => m > 5 ? '#ef4444' : m > 0 ? '#f59e0b' : '#4ade80';

            html += `
                <div class="report-section" style="margin-bottom:25px;">
                    <h4 style="color:#8b5cf6; border-bottom:1px solid #333; padding-bottom:8px; margin-bottom:12px; font-size:1.1rem; text-transform:uppercase; letter-spacing:0.5px;">
                        THREAT INTELLIGENCE ENRICHMENT (${ti.total_enriched} IOCs enriched)
                    </h4>
                    <div style="font-size:0.7rem; color:var(--text-secondary); margin-bottom:10px;">
                        Providers: ${(ti.providers_used || []).join(', ')}
                    </div>`;

            // IP enrichment
            if (ti.ip_enrichment && ti.ip_enrichment.length > 0) {
                html += `
                    <div style="margin-bottom:15px;">
                        <div style="font-size:0.8rem; font-weight:700; color:#8b5cf6; margin-bottom:8px;">IP ADDRESSES</div>
                        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(300px, 1fr)); gap:8px;">
                            ${ti.ip_enrichment.map(ip => {
                                const geo = ip.geo || {};
                                const abuse = ip.abuse || {};
                                const vt = ip.vt || {};
                                const abuseScore = abuse.abuse_confidence || 0;
                                return `
                                <div style="background:rgba(0,0,0,0.3); border-radius:6px; padding:10px; border-left:3px solid ${abuseColor(abuseScore)}; cursor:pointer;"
                                     onclick="window._chronosLookupIOC && window._chronosLookupIOC('${ip.ip}', 'ip')">
                                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                                        <span style="font-family:monospace; color:var(--accent-primary); font-size:0.9rem;">${ip.ip}</span>
                                        ${geo.country_code ? `<span style="font-size:0.85rem;">${getFlag(geo.country_code)} ${geo.country_code}</span>` : ''}
                                    </div>
                                    <div style="font-size:0.75rem; color:var(--text-secondary); line-height:1.6;">
                                        ${geo.isp ? `<div>ISP: <span style="color:var(--text-primary);">${geo.isp}</span></div>` : ''}
                                        ${geo.asn ? `<div>ASN: <span style="color:var(--text-primary);">${geo.asn}</span></div>` : ''}
                                        ${geo.city ? `<div>Location: <span style="color:var(--text-primary);">${geo.city}, ${geo.region || ''}</span></div>` : ''}
                                        ${abuse.abuse_confidence !== undefined ? `<div>Abuse Score: <span style="font-weight:700; color:${abuseColor(abuseScore)};">${abuseScore}%</span> (${abuse.total_reports || 0} reports)</div>` : ''}
                                        ${vt.malicious !== undefined ? `<div>VirusTotal: <span style="font-weight:700; color:${vtColor(vt.malicious)};">${vt.malicious} malicious</span> / ${vt.harmless || 0} clean</div>` : ''}
                                    </div>
                                </div>`;
                            }).join('')}
                        </div>
                    </div>`;
            }

            // Domain enrichment
            if (ti.domain_enrichment && ti.domain_enrichment.length > 0) {
                html += `
                    <div style="margin-bottom:15px;">
                        <div style="font-size:0.8rem; font-weight:700; color:#8b5cf6; margin-bottom:8px;">DOMAINS</div>
                        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:8px;">
                            ${ti.domain_enrichment.map(d => {
                                const uh = d.urlhaus || {};
                                const vt = d.vt || {};
                                const isMalicious = (vt.malicious || 0) > 0 || uh.query_status === 'is_host';
                                return `
                                <div style="background:rgba(0,0,0,0.3); border-radius:6px; padding:10px; border-left:3px solid ${isMalicious ? '#ef4444' : '#4ade80'};">
                                    <div style="font-family:monospace; color:var(--accent-primary); font-size:0.85rem; margin-bottom:6px;">${d.domain}</div>
                                    <div style="font-size:0.75rem; color:var(--text-secondary); line-height:1.6;">
                                        ${uh.query_status ? `<div>URLhaus: <span style="color:${uh.query_status === 'is_host' ? '#ef4444' : 'var(--text-primary)'}; font-weight:600;">${uh.query_status}</span> ${uh.urls_total ? `(${uh.urls_total} URLs)` : ''}</div>` : ''}
                                        ${uh.threat_type ? `<div>Threat: <span style="color:#f59e0b;">${uh.threat_type}</span></div>` : ''}
                                        ${vt.malicious !== undefined ? `<div>VirusTotal: <span style="font-weight:700; color:${vtColor(vt.malicious)};">${vt.malicious} malicious</span></div>` : ''}
                                    </div>
                                </div>`;
                            }).join('')}
                        </div>
                    </div>`;
            }

            // Hash enrichment
            if (ti.hash_enrichment && ti.hash_enrichment.length > 0) {
                html += `
                    <div style="margin-bottom:15px;">
                        <div style="font-size:0.8rem; font-weight:700; color:#8b5cf6; margin-bottom:8px;">FILE HASHES</div>
                        ${ti.hash_enrichment.map(h => {
                            const vt = h.vt || {};
                            return `
                            <div style="background:rgba(0,0,0,0.3); border-radius:6px; padding:8px 12px; margin-bottom:4px; border-left:3px solid ${vtColor(vt.malicious || 0)};">
                                <span style="font-family:monospace; font-size:0.75rem; color:var(--accent-primary);">${h.hash}</span>
                                ${vt.malicious !== undefined ? `<span style="float:right; font-size:0.75rem; font-weight:700; color:${vtColor(vt.malicious)};">${vt.malicious}/${(vt.malicious||0)+(vt.harmless||0)+(vt.undetected||0)} detections</span>` : ''}
                                ${vt.popular_threat_name ? `<div style="font-size:0.7rem; color:#f59e0b; margin-top:2px;">${vt.popular_threat_name}</div>` : ''}
                            </div>`;
                        }).join('')}
                    </div>`;
            }

            // Email enrichment (HIBP)
            if (ti.email_enrichment && ti.email_enrichment.length > 0) {
                html += `
                    <div style="margin-bottom:15px;">
                        <div style="font-size:0.8rem; font-weight:700; color:#8b5cf6; margin-bottom:8px;">CREDENTIAL BREACHES</div>
                        ${ti.email_enrichment.map(e => {
                            const hibp = e.hibp || {};
                            const breached = (hibp.breach_count || 0) > 0;
                            return `
                            <div style="background:rgba(0,0,0,0.3); border-radius:6px; padding:8px 12px; margin-bottom:4px; border-left:3px solid ${breached ? '#ef4444' : '#4ade80'};">
                                <span style="font-family:monospace; font-size:0.8rem; color:var(--accent-primary);">${e.email}</span>
                                <span style="float:right; font-size:0.75rem; font-weight:700; color:${breached ? '#ef4444' : '#4ade80'};">${hibp.breach_count || 0} breaches</span>
                                ${breached && hibp.breaches ? `<div style="font-size:0.7rem; color:var(--text-secondary); margin-top:4px;">${hibp.breaches.join(', ')}</div>` : ''}
                            </div>`;
                        }).join('')}
                    </div>`;
            }

            html += `</div>`;
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
