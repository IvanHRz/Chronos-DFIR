console.log("CHRONOS-CORE: Loading v179...");
import { API } from './api.js?v=179';
import { GridManager } from './grid.js?v=179';
import { ChartManager } from './charts.js?v=179';
import { ActionManager } from './actions.js?v=179';
import ChronosState from './state.js?v=179';
import events from './events.js?v=179';

// Initialize Managers
const grid = new GridManager('timeline-table');
const charts = new ChartManager();
const actions = new ActionManager(grid, charts);

// Expose grid globally for actions to read columns and sorters
window.grid = grid;

document.addEventListener('DOMContentLoaded', () => {
    console.log("Chronos-DFIR Modular Engine Initialized with State Management");

    // Initialize Plugins
    if (typeof flatpickr !== 'undefined') {
        flatpickr(".date-picker", { enableTime: true, enableSeconds: true, dateFormat: "Y-m-d H:i:S" });
    }

    charts.init('log-scale-toggle');
    setupEventListeners();
    setupStateObservers();
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

    // ── Export Dropdown: click-based (not hover) ──────────────────────────
    const exportDropdown = document.querySelector('.dropdown');
    const exportToggleBtn = exportDropdown?.querySelector('.dropdown-toggle');
    const exportMenu = exportDropdown?.querySelector('.dropdown-content');

    if (exportToggleBtn && exportMenu) {
        // Toggle on button click
        exportToggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = exportMenu.classList.toggle('open');
            exportToggleBtn.setAttribute('aria-expanded', isOpen);
        });
        // Items inside: stop propagation (don't close on click-through)
        exportMenu.addEventListener('click', (e) => e.stopPropagation());
        // Close when clicking outside
        document.addEventListener('click', () => {
            exportMenu.classList.remove('open');
            exportToggleBtn.setAttribute('aria-expanded', 'false');
        });
    }

    // Export Buttons
    document.getElementById('download-csv')?.addEventListener('click', () => exportData('csv'));
    document.getElementById('download-xlsx')?.addEventListener('click', () => exportData('xlsx'));

    document.getElementById('download-json')?.addEventListener('click', () => exportData('json'));

    document.getElementById('download-ai')?.addEventListener('click', () => {
        actions.showForensicSummary();
    });

    document.getElementById('download-report')?.addEventListener('click', () => {
        actions.generateReport();
    });

    document.getElementById('download-split')?.addEventListener('click', () => {
        actions.downloadSplitZip();
    });

    // Row Selection Filter (Selection View)
    document.getElementById('filter-selection-btn')?.addEventListener('click', function () {
        const isNowViewingSelection = grid.applyRowSelectionFilter(ChronosState.currentFilename);

        if (isNowViewingSelection) {
            const ids = grid.getSelectedIds();
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
    if (!ChronosState.currentFilename) {
        alert("Please load a file first before exporting.");
        return;
    }

    // Always read directly from the grid to guarantee current header filters are included
    const filters = grid.table ? grid.table.getHeaderFilters() : (ChronosState.currentColumnFilters || []);
    const selectedIds = grid.getSelectedIds ? grid.getSelectedIds() : [];

    let visibleCols = [];
    if (grid.table) {
        visibleCols = grid.table.getColumns()
            .filter(c => c.isVisible() && c.getField() && c.getField() !== '_id')
            .map(c => c.getField());
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

    if (grid.table) {
        const sorters = grid.table.getSorters();
        if (sorters.length > 0) {
            params.sort_col = sorters[0].field;
            params.sort_dir = sorters[0].dir;
        }
    }

    try {
        window.isDownloading = true;
        const result = await API.exportData(ChronosState.currentFilename, params);
        if (result.download_url) {
            // Use offscreen anchor for reliable cross-browser download
            const a = document.createElement('a');
            a.href = result.download_url;
            a.download = result.filename || '';
            a.style.position = 'fixed';
            a.style.left = '-9999px';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => document.body.removeChild(a), 3000);
        } else if (result.error || result.detail) {
            alert("Export failed: " + (result.error || result.detail || JSON.stringify(result)));
        } else {
            alert("Export failed: Unexpected response format.");
        }
    } catch (e) {
        alert("Export network error: " + e.message);
    } finally {
        setTimeout(() => { window.isDownloading = false; }, 4000);
    }
}

async function processArtifact() {
    const fileInput = document.getElementById('fileElem');
    if (!fileInput.files[0]) {
        alert("Please select a file first clicking on 'Select File' or by Drag & Drop.");
        return;
    }

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
    }
}
