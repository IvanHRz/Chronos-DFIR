// 1. Globals
console.log("VERSION 116 LOADED");
let selectedFile = null;
let table = null;
let processedFiles = {};
let currentDataUrl = null;
let currentIsRemote = false;
let currentCategory = 'generic';
let currentQuery = "";
let chartInstance = null;
let currentExcludeId = null;
let currentFilename = null;
let isSelectionView = false;
let currentChartData = null; 
let currentStartTime = null;
let currentEndTime = null;
let currentColumnFilters = {}; 
let histogramAbortController = null; 
let filterDebounceTimer = null; 

// --- Column Manager State ---
let isColumnManagerMode = false;
let selectedColumns = []; 
let originalColumns = []; 

// --- NAVIGATION GUARD ---
window.addEventListener('beforeunload', function (e) {
    if (table) {
        e.preventDefault();
        e.returnValue = '';
        return '';
    }
});

function resetAppState() {
    console.log("Resetting app state...");
    if (chartInstance) {
        chartInstance.destroy();
        chartInstance = null;
    }
    if (table) {
        table.destroy();
        table = null;
    }
    processedFiles = {};
    currentDataUrl = null;
    currentIsRemote = false;
    currentCategory = 'generic';
    currentQuery = "";
    currentExcludeId = null;
    currentFilename = null;
    isSelectionView = false;
    currentChartData = null;
    currentStartTime = null;
    currentEndTime = null;
    currentColumnFilters = {};
    filterDebounceTimer = null;
    isColumnManagerMode = false;
    selectedColumns = [];
    originalColumns = [];

    const infoEl = document.getElementById('time-range-info');
    if (infoEl) infoEl.innerText = "Time Range: N/A";

    const recordCountEl = document.getElementById('record-count');
    if (recordCountEl) recordCountEl.innerText = "0 Records Loaded";

    const startIn = document.getElementById('time-start');
    if (startIn) {
        if (startIn._flatpickr) startIn._flatpickr.clear();
        startIn.value = "";
    }

    const endIn = document.getElementById('time-end');
    if (endIn) {
        if (endIn._flatpickr) endIn._flatpickr.clear();
        endIn.value = "";
    }

    const interp = document.getElementById('chart-interpretation');
    if (interp) {
        interp.innerText = "Loading data...";
        interp.style.color = '#ccc';
    }

    const noiseBtn = document.getElementById('noise-filter-btn');
    if (noiseBtn) noiseBtn.style.display = 'none';

    const colManagerBtn = document.getElementById('col-manager-btn');
    if (colManagerBtn) {
        colManagerBtn.classList.remove('active-manager');
        colManagerBtn.classList.add('btn-info');
        colManagerBtn.innerHTML = 'Manage Columns <i class="fas fa-columns"></i>';
    }
    const colManagerActions = document.getElementById('col-manager-actions');
    if (colManagerActions) colManagerActions.style.display = 'none';

    const wrapper = document.getElementById('chart-wrapper');
    if (wrapper) wrapper.style.display = 'none';
}

const searchInput = document.getElementById('global-search');
if (searchInput) {
    let debounceTimer;
    searchInput.addEventListener('input', (e) => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            currentQuery = e.target.value.trim();
            if (currentDataUrl) {
                loadGrid(currentDataUrl, currentCategory);
                if (currentFilename) {
                    loadHistogram(currentFilename, currentExcludeId, currentStartTime, currentEndTime);
                }
            }
        }, 850);
    });
}

const dlCsv = document.getElementById('download-csv');
if (dlCsv) dlCsv.addEventListener('click', () => downloadData('csv'));

const dlXlsx = document.getElementById('download-excel');
if (dlXlsx) dlXlsx.addEventListener('click', () => downloadData('xlsx'));

const dlSplit = document.getElementById('download-split');
if (dlSplit) dlSplit.addEventListener('click', () => downloadData('zip'));

const dlAi = document.getElementById('download-ai');
if (dlAi) dlAi.addEventListener('click', () => downloadData('csv', true));

const hideEmptyBtn = document.getElementById('toggle-empty-cols');
if (hideEmptyBtn) {
    hideEmptyBtn.addEventListener('click', toggleEmptyColumns);
}

document.addEventListener('DOMContentLoaded', () => {
    const timeBtn = document.getElementById('filter-time-btn');
    if (timeBtn) {
        timeBtn.addEventListener('click', () => {
            const startIn = document.getElementById('time-start');
            const endIn = document.getElementById('time-end');
            if (!startIn.value || !endIn.value) {
                alert("Please select both Start and End times.");
                return;
            }
            currentStartTime = startIn.value;
            currentEndTime = endIn.value;
            if (currentFilename) {
                loadHistogram(currentFilename, currentExcludeId, currentStartTime, currentEndTime);
                loadGrid(currentDataUrl, currentCategory);
            }
        });
    }

    const clearBtn = document.getElementById('clear-time-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            document.getElementById('time-start').value = "";
            document.getElementById('time-end').value = "";
            currentStartTime = null;
            currentEndTime = null;
            if (currentFilename) {
                loadHistogram(currentFilename, currentExcludeId);
                loadGrid(currentDataUrl, currentCategory);
            }
        });
    }

    const logToggle = document.getElementById('log-scale-toggle');
    if (logToggle) {
        logToggle.addEventListener('change', () => {
            if (currentChartData) {
                renderChart(currentChartData); 
            }
        });
    }
});

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files);
}

function highlightFormatter(cell, formatterParams, onRendered) {
    let val = cell.getValue();
    if (val === null || val === undefined) return "";
    const fieldName = cell.getColumn().getField().toLowerCase();
    if (fieldName.includes("time") || fieldName.includes("date") || fieldName.includes("created") || fieldName.includes("modified")) {
        const num = parseFloat(val);
        if (!isNaN(num) && num > 946684800) {
            let date = new Date(num > 946684800000 ? num : num * 1000);
            if (!isNaN(date.getTime())) {
                val = date.toISOString().replace('T', ' ').split('.')[0];
            }
        }
    }
    val = String(val).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    if (currentQuery && currentQuery.trim().length > 0) {
        const regex = new RegExp(`(${currentQuery.trim()})`, 'gi');
        val = val.replace(regex, '<span class="highlight-term">$1</span>');
    }
    return val;
}

let hidingEmpty = false;
function toggleEmptyColumns() {
    if (!table) return;
    const btn = document.getElementById('toggle-empty-cols');
    if (hidingEmpty) {
        table.getColumns().forEach(col => col.show());
        hidingEmpty = false;
        btn.innerText = "Hide Empty";
        btn.classList.remove("active-success");
    } else {
        const data = table.getData("active");
        if (!data || data.length === 0) return;
        const columns = table.getColumns();
        table.blockRedraw();
        columns.forEach(col => {
            const field = col.getField();
            if (['Tag', '_id', 'No.'].includes(field)) return;
            let hasValue = data.some(d => d[field] !== null && d[field] !== undefined && String(d[field]).trim() !== "");
            if (!hasValue) col.hide();
        });
        table.restoreRedraw();
        hidingEmpty = true;
        btn.innerText = "Show All";
        btn.classList.add("active-success");
    }
}

function handleFiles(files) {
    if (files.length > 0) {
        selectedFile = files[0];
        document.getElementById('upload-status').innerText = `Selected: ${selectedFile.name}`;
        document.getElementById('controls').classList.remove('hidden');
        resetAppState();
    }
}

async function loadGrid(dataUrl, category) {
    if (!dataUrl) return;
    currentDataUrl = dataUrl;
    currentCategory = category;
    const isRemote = true;
    currentIsRemote = isRemote;
    const statusEl = document.getElementById('record-count');
    try {
        statusEl.innerText = "Fetching Data...";
        let previewUrl = `${dataUrl}?page=1&size=50`;
        if (currentQuery) previewUrl += `&query=${encodeURIComponent(currentQuery)}`;
        const response = await fetch(previewUrl);
        const jsonResp = await response.json();
        const data = jsonResp.data || [];
        if (table) table.destroy();
        let columns = [
            { title: "Tag", formatter: "rowSelection", titleFormatter: "rowSelection", align: "center", headerSort: false, width: 50, frozen: true },
            { title: "No.", field: "_id", width: 70, frozen: true }
        ];
        if (data.length > 0) {
            Object.keys(data[0]).filter(k => !['_id', 'No.'].includes(k)).forEach(key => {
                columns.push({ title: key, field: key, headerFilter: "input", width: 150, formatter: highlightFormatter });
            });
        }
        table = new Tabulator("#timeline-table", {
            height: "600px",
            pagination: "remote",
            paginationSize: 500,
            ajaxURL: dataUrl,
            ajaxURLGenerator: (url, config, params) => {
                let finalUrl = `${url}?page=${params.page}&size=${params.size}`;
                if (currentQuery) finalUrl += `&query=${encodeURIComponent(currentQuery)}`;
                if (currentStartTime) finalUrl += `&start_time=${currentStartTime}`;
                if (currentEndTime) finalUrl += `&end_time=${currentEndTime}`;
                return finalUrl;
            },
            columns: columns,
            selectable: true
        });
        statusEl.innerText = `Total Records: ${jsonResp.total}`;
    } catch (e) { console.error(e); }
}

async function loadHistogram(filename, excludeId, start, end) {
    const wrapper = document.getElementById('chart-wrapper');
    wrapper.style.display = 'block';
    let url = `/api/histogram/${filename}?_t=${Date.now()}`;
    if (currentQuery) url += `&query=${encodeURIComponent(currentQuery)}`;
    if (start) url += `&start_time=${start}`;
    if (end) url += `&end_time=${end}`;
    const response = await fetch(url);
    const data = await response.json();
    currentChartData = data;
    renderChart(data);
}

function renderChart(data) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    if (chartInstance) chartInstance.destroy();
    
    // Modify "Actividad" (standard bars) to be dotted/transparent with outline
    if (data.datasets) {
        data.datasets.forEach(ds => {
            if (ds.label === "Actividad") {
                ds.backgroundColor = 'rgba(56, 189, 248, 0.1)';
                ds.borderColor = '#38bdf8';
                ds.borderWidth = 1;
                ds.borderDash = [2, 2];
            }
        });
    }

    chartInstance = new Chart(ctx, {
        type: 'bar',
        data: data,
        options: {
            scales: {
                y: { beginAtZero: true, type: document.getElementById('log-scale-toggle')?.checked ? 'logarithmic' : 'linear' }
            }
        }
    });
    document.getElementById('chart-interpretation').innerText = data.interpretation;
}

async function downloadData(format, ai = false) {
    if (!currentFilename) return;
    const body = {
        filename: currentFilename,
        format: format,
        query: currentQuery,
        start_time: currentStartTime,
        end_time: currentEndTime,
        ai_optimized: ai
    };
    const response = await fetch(ai ? '/api/export_filtered' : (format === 'zip' ? '/api/export_split' : '/api/export_filtered'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Chronos_Export.${format}`;
    a.click();
}
