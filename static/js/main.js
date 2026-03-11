console.log("CHRONOS-CORE: Loading v202...");
import { API } from './api.js?v=202';
import { GridManager } from './grid.js?v=202';
import { ChartManager } from './charts.js?v=202';
import { ActionManager } from './actions.js?v=202';
import { SettingsManager } from './settings.js?v=202';
import { EnrichmentManager } from './enrichment.js?v=202';
import ChronosState from './state.js?v=202';
import events from './events.js?v=202';

// Initialize Managers
let grid, charts, actions, settings, enrichment;
try {
    grid = new GridManager('timeline-table');
    charts = new ChartManager();
    actions = new ActionManager(grid, charts);
    settings = new SettingsManager();
    enrichment = new EnrichmentManager(grid);
    console.log("CHRONOS-CORE: All managers initialized OK");
} catch (e) {
    console.error("CHRONOS-CORE: Manager init FAILED:", e);
}

// Expose grid globally for actions to read columns and sorters
window.grid = grid;

// Global IOC lookup handler for enrichment section clicks
window._chronosLookupIOC = async (iocValue, iocType) => {
    try {
        const result = await API.lookupIOC(iocValue, iocType);
        console.log(`[ENRICHMENT] Lookup ${iocType}:${iocValue}`, result);
        alert(`IOC: ${iocValue}\n\n${JSON.stringify(result, null, 2)}`);
    } catch (e) {
        console.warn(`[ENRICHMENT] Lookup failed: ${e}`);
    }
};

// View Sigma/Correlation detection rows in the main grid
window._chronosViewSigmaInGrid = (rowIds) => {
    if (!rowIds || !rowIds.length || !grid.table) return;
    // Close forensic modal
    const modal = document.getElementById("summary-modal");
    if (modal) { modal.classList.remove("show"); modal.classList.add("hidden"); }
    // Apply client-side filter to show only detection rows
    const idSet = new Set(rowIds.map(id => typeof id === 'number' ? id : parseInt(id, 10)));
    grid.isSelectionView = true;
    grid.table.setFilter(data => idSet.has(data._id));
    // Update Row Filter button to reflect active state
    const filterBtn = document.getElementById('filter-selection-btn');
    if (filterBtn) {
        filterBtn.innerText = "Show All Events";
        filterBtn.classList.add("active-filter");
    }
};

document.addEventListener('DOMContentLoaded', () => {
    console.log("CHRONOS-CORE: DOMContentLoaded fired — wiring UI");

    // Initialize Plugins
    if (typeof flatpickr !== 'undefined') {
        flatpickr(".date-picker", { enableTime: true, enableSeconds: true, dateFormat: "Y-m-d H:i:S" });
    }

    charts.init('log-scale-toggle');
    setupEventListeners();
    setupStateObservers();
    window.__chronosReady = true;
    console.log("CHRONOS-CORE: UI ready ✓");
});

function setupStateObservers() {
    // Reveal results area when a file is loaded
    events.on('SESSION_UPDATED', () => {
        // Auto-populate forensic dashboard bar in the background
        actions.loadDashboardCards();

        const resArea = document.getElementById('results-area');
        if (resArea) resArea.classList.remove('hidden');

        // ── Navigation Guard ──────────────────────────────────────────────
        // Activate beforeunload after session is set (file loaded)
        window.addEventListener('beforeunload', handleBeforeUnload);

        // Android/iOS back-button and browser back via pushState
        history.pushState(null, '', window.location.href);
        window.addEventListener('popstate', handlePopState);
    });

    // Refresh dashboard cards when filters change (debounced to avoid flooding)
    let _dashDebounce = null;
    const debouncedDashRefresh = () => {
        clearTimeout(_dashDebounce);
        _dashDebounce = setTimeout(() => {
            if (ChronosState.currentFilename) actions.loadDashboardCards();
        }, 500);
    };
    events.on('FILTERS_CHANGED', debouncedDashRefresh);
    events.on('TIME_RANGE_CHANGED', debouncedDashRefresh);
    events.on('SELECTION_CHANGED', debouncedDashRefresh);

    // Global stats update
    events.on('COUNTS_UPDATED', ({ total, filtered }) => {
        const countEl = document.getElementById('record-count');
        if (countEl) countEl.innerText = `${filtered.toLocaleString()} / ${total.toLocaleString()} Records`;
    });
}

// ── Navigation Guard Handlers ────────────────────────────────────────────
function handleBeforeUnload(e) {
    if (window.isDownloading) return; // Allow export redirects
    const msg = '¿Seguro que quieres salir? Perderás el análisis actual en Chronos-DFIR.';
    e.preventDefault();
    e.returnValue = msg; // Required for Chrome/Edge
    return msg;
}

function handlePopState() {
    // Re-push state to prevent actual navigation
    history.pushState(null, '', window.location.href);
    const confirmed = confirm(
        '⚠️ Chronos-DFIR\n\n¿Regresar? Esto descartará el análisis actual y los filtros aplicados.\n\nPresiona «Cancelar» para quedarte en la app.'
    );
    if (confirmed) {
        // User confirmed — remove guards and let them leave
        window.removeEventListener('beforeunload', handleBeforeUnload);
        window.removeEventListener('popstate', handlePopState);
        history.back();
    }
    // If cancelled: do nothing — pushState already keeps them here
}


function closeExportMenu() {
    const menu = document.querySelector('.dropdown-content');
    if (menu) menu.classList.remove('open');
}

function setupEventListeners() {
    // ── File Upload ──────────────────────────────────────────────────────────
    const fileElem = document.getElementById('fileElem');
    const dropArea = document.getElementById('drop-area');

    function handleFileSelected(file) {
        if (!file) return;
        // Assign the file to the hidden input via DataTransfer so the rest of
        // the upload logic can read it from fileElem.files
        const dt = new DataTransfer();
        dt.items.add(file);
        if (fileElem) fileElem.files = dt.files;

        // Update the visible label
        const label = document.querySelector(`label[for='fileElem']`);
        if (label) label.textContent = file.name;
    }

    if (fileElem) {
        fileElem.addEventListener('change', (e) => {
            if (e.target.files?.length) handleFileSelected(e.target.files[0]);
        });
    }

    // Drag & Drop on the upload section
    if (dropArea) {
        ['dragenter', 'dragover'].forEach(evt =>
            dropArea.addEventListener(evt, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropArea.classList.add('drag-over');
            })
        );
        ['dragleave', 'dragend'].forEach(evt =>
            dropArea.addEventListener(evt, () => dropArea.classList.remove('drag-over'))
        );
        dropArea.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropArea.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files?.length) handleFileSelected(files[0]);
        });
    }


    // Process Button
    const processBtn = document.getElementById('process-btn');
    if (processBtn) {
        processBtn.addEventListener('click', () => processArtifact());
    }

    // Column Manager
    document.getElementById('col-manager-btn')?.addEventListener('click', () => {
        grid.toggleColumnManager();
    });

    document.getElementById('move-top-btn')?.addEventListener('click', () => {
        grid.moveSelectedColumns();
    });

    document.getElementById('filter-cols-btn')?.addEventListener('click', () => {
        grid.toggleColumnSelection(true);
    });

    document.getElementById('reset-col-manager-btn')?.addEventListener('click', () => {
        grid.removeColumnManagerUI();
    });

    document.getElementById('toggle-empty-cols')?.addEventListener('click', () => {
        if (!ChronosState.currentFilename) return;
        grid.toggleEmptyColumns(ChronosState.currentFilename);
    });

    // Hard Reset
    document.getElementById('hard-reset-btn')?.addEventListener('click', () => actions.hardReset());

    // Settings Panel
    document.getElementById('settings-btn')?.addEventListener('click', () => settings.toggle());

    // Enrichment
    document.getElementById('enrich-btn')?.addEventListener('click', () => enrichment.showProviderSelector());

    // ── Export Buttons (Direct — no dropdown) ──────────────────────────
    document.getElementById('download-csv')?.addEventListener('click', () => {
        console.log('[CLICK] CSV export button clicked');
        if (!ChronosState.currentFilename) { alert("Load a file first."); return; }
        actions._exportFiltered(ChronosState.currentFilename, 'csv');
    });
    document.getElementById('download-xlsx')?.addEventListener('click', () => {
        console.log('[CLICK] XLSX export button clicked');
        if (!ChronosState.currentFilename) { alert("Load a file first."); return; }
        actions._exportFiltered(ChronosState.currentFilename, 'xlsx');
    });
    document.getElementById('download-json')?.addEventListener('click', () => {
        console.log('[CLICK] JSON export button clicked');
        if (!ChronosState.currentFilename) { alert("Load a file first."); return; }
        actions._exportFiltered(ChronosState.currentFilename, 'json');
    });
    document.getElementById('download-ai')?.addEventListener('click', () => {
        actions.showForensicSummary();
    });
    document.getElementById('download-report')?.addEventListener('click', () => {
        actions.generateReport();
    });

    // Row Selection Filter (Selection View)
    document.getElementById('filter-selection-btn')?.addEventListener('click', function () {
        const isNowViewingSelection = grid.applyRowSelectionFilter(ChronosState.currentFilename);

        if (isNowViewingSelection) {
            const ids = ChronosState.selectedIds.length > 0
                ? ChronosState.selectedIds
                : grid.getSelectedIds();
            charts.loadHistogramSubset(ChronosState.currentFilename, ids);
        } else {
            // Re-trigger global view
            events.emit('FILTERS_CHANGED', { query: ChronosState.currentQuery, colFilters: ChronosState.currentColumnFilters });
        }

        this.innerText = isNowViewingSelection ? "Show All Events" : "Row Filter";
        this.classList.toggle("active-filter", isNowViewingSelection);
    });

    // Time Filter
    document.getElementById('filter-time-btn')?.addEventListener('click', () => {
        const start = document.getElementById('time-start')?.value;
        const end = document.getElementById('time-end')?.value;
        if (start && end) {
            ChronosState.setTimeRange(start, end);
            const clearBtn = document.getElementById('clear-time-btn');
            if (clearBtn) clearBtn.style.display = 'inline-block';
        }
    });

    // Reset All Filters
    document.getElementById('reset-view-btn-toolbar')?.addEventListener('click', () => {
        const searchInput = document.getElementById('global-search');
        if (searchInput) searchInput.value = "";

        const start = document.getElementById('time-start');
        const end = document.getElementById('time-end');
        if (start) start.value = "";
        if (end) end.value = "";

        const clearBtn = document.getElementById('clear-time-btn');
        if (clearBtn) clearBtn.style.display = 'none';

        ChronosState.resetFilters();
        grid.clearFilters();

        // Reset Row Filter button state
        const selBtn = document.getElementById('filter-selection-btn');
        if (selBtn) {
            selBtn.innerText = "Row Filter";
            selBtn.classList.remove("active-filter");
        }
    });

    // Clear Time Filter
    document.getElementById('clear-time-btn')?.addEventListener('click', () => {
        ChronosState.setTimeRange("", "");
        const start = document.getElementById('time-start');
        const end = document.getElementById('time-end');
        if (start) start.value = "";
        if (end) end.value = "";
        const clearBtn = document.getElementById('clear-time-btn');
        if (clearBtn) clearBtn.style.display = 'none';
    });

    // Global Search with Debounce
    const searchInput = document.getElementById('global-search');
    if (searchInput) {
        let debounceTimer;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                ChronosState.updateFilters(e.target.value.trim(), ChronosState.currentColumnFilters);
            }, 850);
        });
    }

    // Chart Controls
    document.getElementById('download-chart-png')?.addEventListener('click', () => {
        if (!ChronosState.currentFilename) {
            alert("No data available to download.");
            return;
        }
        charts.downloadAsPNG('timeline-chart', `timeline-${ChronosState.currentFilename}.png`);
    });

    document.getElementById('download-chart-excel')?.addEventListener('click', () => {
        exportData('xlsx'); // Standard export doubles as chart logic export for now
    });
}

async function exportData(format) {
    try {
        console.log(`[EXPORT] exportData('${format}') called`);

        if (!ChronosState.currentFilename) {
            alert("Please load a file first before exporting.");
            return;
        }

        console.log(`[EXPORT] Starting ${format} export for ${ChronosState.currentFilename}`);

        // Read filters safely
        let filters = [];
        try {
            filters = grid.table ? grid.table.getHeaderFilters() : [];
        } catch (e) {
            console.warn("[EXPORT] getHeaderFilters failed:", e);
        }

        let selectedIds = [];
        try {
            selectedIds = grid.getSelectedIds ? grid.getSelectedIds() : [];
        } catch (e) {
            console.warn("[EXPORT] getSelectedIds failed:", e);
        }

        let visibleCols = [];
        try {
            if (grid.table) {
                visibleCols = grid.table.getColumns()
                    .filter(c => c.isVisible() && c.getField() && c.getField() !== '_id')
                    .map(c => c.getField());
            }
        } catch (e) {
            console.warn("[EXPORT] getColumns failed:", e);
        }

        const params = {
            format: format,
            query: ChronosState.currentQuery || "",
            start_time: ChronosState.startTime || "",
            end_time: ChronosState.endTime || "",
            col_filters: JSON.stringify(filters),
            selected_ids: selectedIds,
            visible_columns: visibleCols
        };

        try {
            if (grid.table) {
                const sorters = grid.table.getSorters();
                if (sorters.length > 0) {
                    params.sort_col = sorters[0].field;
                    params.sort_dir = sorters[0].dir;
                }
            }
        } catch (e) {
            console.warn("[EXPORT] getSorters failed:", e);
        }

        // Close export dropdown
        closeExportMenu();

        window.isDownloading = true;
        console.log(`[EXPORT] Sending request...`, params);
        const result = await API.exportData(ChronosState.currentFilename, params);
        console.log(`[EXPORT] Response:`, result);

        if (result.download_url) {
            // Direct server URL — backend sends Content-Disposition: attachment
            window.isDownloading = true;
            const a = document.createElement('a');
            a.href = result.download_url;
            a.download = result.filename || 'Export.csv';
            a.style.position = 'fixed';
            a.style.left = '-9999px';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); window.isDownloading = false; }, 4000);
            console.log(`[EXPORT] Download triggered: ${result.download_url}`);
        } else if (result.error || result.detail) {
            alert("Export failed: " + (result.error || result.detail || JSON.stringify(result)));
        } else {
            alert("Export failed: Unexpected response format.");
        }
    } catch (e) {
        console.error("[EXPORT] CRITICAL Error:", e);
        alert("Export error: " + e.message);
    } finally {
        setTimeout(() => { window.isDownloading = false; }, 4000);
    }
}

async function processArtifact() {
    if (window._uploadInProgress) return;

    const fileInput = document.getElementById('fileElem');
    if (!fileInput.files[0]) {
        alert("Please select a file first clicking on 'Select File' or by Drag & Drop.");
        return;
    }

    window._uploadInProgress = true;
    const file = fileInput.files[0];
    let artifactType = 'generic';
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext === 'evtx') artifactType = 'EVTX';
    else if (ext === 'mft') artifactType = 'MFT';

    const processBtn = document.getElementById('process-btn');
    const originalText = processBtn.innerHTML;
    processBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    processBtn.disabled = true;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('artifact_type', artifactType);

    try {
        const result = await API.uploadFile(formData);
        if (result.status === 'success') {
            ChronosState.setSession(result.csv_filename, { csv: result.csv_filename, excel: null });
        } else {
            alert("Error processing file: " + (result.message || JSON.stringify(result)));
        }
    } catch (err) {
        alert("Processing failed: " + err.message);
        console.error("Processing failed:", err);
    } finally {
        processBtn.innerHTML = originalText;
        processBtn.disabled = false;
        window._uploadInProgress = false;
    }
}

// Expose processArtifact globally as fallback
window.processArtifact = processArtifact;
