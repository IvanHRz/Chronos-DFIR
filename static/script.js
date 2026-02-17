// 1. Globals (Moved to Top)
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
let currentChartData = null; // Cache for re-rendering
let currentStartTime = null;
let currentEndTime = null;
let currentColumnFilters = {}; // Track active column header filters
let histogramAbortController = null; // Prevent race conditions in charting
let filterDebounceTimer = null; // Debounce chart reload on filter changes

// New Reset Function to ensure no state persistence
function resetAppState() {
    console.log("Resetting app state...");

    // 1. Destroy and nullify instances
    if (chartInstance) {
        chartInstance.destroy();
        chartInstance = null;
    }
    if (table) {
        table.destroy();
        table = null;
    }

    // 2. Reset globals
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

    // 3. Clear DOM Elements
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
}

// ... (Rest of globals/bindings) ...

// ... (In renderChart and loadHistogram) ...
// (I will apply specific replaces below)

// Search Binding
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('global-search');
    if (searchInput) {
        let debounceTimer;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                currentQuery = e.target.value.trim();
                // Only reload if we have a file loaded
                if (currentDataUrl) {
                    loadGrid(currentDataUrl, currentCategory);
                    // Also update chart to reflect search filter
                    if (currentFilename) {
                        loadHistogram(currentFilename, currentExcludeId, currentStartTime, currentEndTime);
                    }
                }
            }, 850); // 850ms debounce for smoother universal search on large files
        });
    }

    // Bind Controls if they exist
    const dlCsv = document.getElementById('download-csv');
    if (dlCsv) dlCsv.addEventListener('click', () => downloadData('csv'));

    const dlXlsx = document.getElementById('download-xlsx');
    if (dlXlsx) dlXlsx.addEventListener('click', () => downloadData('xlsx'));

    // AI Context Download
    document.getElementById('download-ai').addEventListener('click', () => downloadData('csv', true));

    // Hide Empty Columns Toggle
    const hideEmptyBtn = document.getElementById('toggle-empty-cols');
    if (hideEmptyBtn) {
        hideEmptyBtn.addEventListener('click', toggleEmptyColumns);
    }

    // Filter Button Logic
    bindFilterButton();

    // Bind Time Controls
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
                // 1. Update Chart
                loadHistogram(currentFilename, currentExcludeId, currentStartTime, currentEndTime);
                // 2. Update Grid
                loadGrid(currentDataUrl, currentCategory);
            }
        });
    }

    // Bind Clear Button
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

    // Bind Log Scale
    const logToggle = document.getElementById('log-scale-toggle');
    if (logToggle) {
        logToggle.addEventListener('change', () => {
            if (currentChartData) {
                renderChart(currentChartData); // Re-render with cached data
            }
        });
    }
});

// Expose handleFiles for inline HTML
window.handleFiles = handleFiles;


// Drag & Drop Logic
const dropArea = document.getElementById('drop-area');

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropArea.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, unhighlight, false);
});

function highlight(e) {
    dropArea.classList.add('highlight');
}

function unhighlight(e) {
    dropArea.classList.remove('highlight');
}

dropArea.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files);
}

// Custom Formatter for Search Highlighting
// Helper to track columns with search hits
let columnsWithHits = new Set();

function highlightFormatter(cell, formatterParams, onRendered) {
    let val = cell.getValue();
    if (val === null || val === undefined) return "";

    // EPOCH DATE FORMATTING
    if (formatterParams && formatterParams.isEpoch) {
        let num = parseFloat(val);
        if (!isNaN(num)) {
            // Heuristic: If > 1 trillion, assume milliseconds. Else seconds.
            // Year 2000 in ms = ~9.4e11. Year 2000 in sec = ~9.4e8.
            let date = new Date(num > 946684800000 ? num : num * 1000);

            // Format to YYYY-MM-DD HH:MM:SS
            // Using localized ISO-like format
            let yyyy = date.getFullYear();
            let mm = String(date.getMonth() + 1).padStart(2, '0');
            let dd = String(date.getDate()).padStart(2, '0');
            let hh = String(date.getHours()).padStart(2, '0');
            let min = String(date.getMinutes()).padStart(2, '0');
            let ss = String(date.getSeconds()).padStart(2, '0');
            val = `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
        }
    }

    val = String(val);

    // HTML Escape first
    val = val.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#039;");

    if (currentQuery && currentQuery.trim().length > 0) {
        // Case insensitive replacement
        const regex = new RegExp(`(${currentQuery.trim()})`, 'gi');
        if (regex.test(val)) {
            // Mark this column as having a hit
            columnsWithHits.add(cell.getColumn().getField());
            val = val.replace(regex, '<span class="highlight-term">$1</span>');
        }
    }

    // Preserve newlines for textarea behavior
    val = val.replace(/\n/g, "<br>");

    return val;
}

let hidingEmpty = false;
function toggleEmptyColumns() {
    if (!table) return;
    const btn = document.getElementById('toggle-empty-cols');

    if (hidingEmpty) {
        // Show All
        table.getColumns().forEach(col => col.show());
        hidingEmpty = false;
        btn.innerText = "Hide Empty";
        btn.style.background = "#607d8b"; // Blue-grey
    } else {
        // Hide Empty
        const visibleRows = table.getRows("active"); // Get rows in current filter/page view
        // Note: For remote pagination, this only checks current page. Good for performance.

        let colsToHide = [];
        const columns = table.getColumns();

        columns.forEach(col => {
            let field = col.getField();
            if (field === "_id" || field === "Timestamp" || field === "EventID") return; // Always show key columns

            let isEmpty = true;
            for (let row of visibleRows) {
                let val = row.getData()[field];
                if (val !== null && val !== undefined && val !== "" && String(val).trim() !== "") {
                    isEmpty = false;
                    break;
                }
            }
            if (isEmpty) colsToHide.push(col);
        });

        colsToHide.forEach(col => col.hide());
        hidingEmpty = true;
        btn.innerText = "Show All";
        btn.style.background = "#4caf50"; // Green
    }
}


function handleFiles(files) {
    // Initialize Flatpickr for 24h Time Selection
    if (window.flatpickr) {
        flatpickr(".date-picker", {
            enableTime: true,
            dateFormat: "Y-m-d H:i",
            time_24hr: true,
            allowInput: true
        });
    }

    if (files.length > 0) {
        selectedFile = files[0];
        document.getElementById('upload-status').innerText = `Selected: ${selectedFile.name}`;

        const controls = document.getElementById('controls');
        controls.classList.remove('hidden');

        // Auto-detect type
        const ext = selectedFile.name.split('.').pop().toLowerCase();
        const select = document.getElementById('artifact-type');
        const processBtn = document.getElementById('process-btn');

        // Reset state
        select.parentElement.classList.remove('hidden');
        processBtn.innerText = "Process Artifact";

        if (ext === 'evtx') select.value = 'EVTX';
        else if (ext === 'mft') select.value = 'MFT';
        else {
            // Generic CSV/XLSX: Hide artifact selector
            select.style.display = 'none';
            processBtn.innerText = "Load View";
            select.value = 'EVTX';
        }

        if (ext === 'evtx' || ext === 'mft') {
            select.style.display = 'inline-block';
        }

        // Total Reset Logic
        resetAppState();
    }
}

// Process Logic
document.getElementById('process-btn').addEventListener('click', async () => {
    if (!selectedFile) return;

    const artifactType = document.getElementById('artifact-type').value;
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('artifact_type', artifactType);

    // Total Reset Logic before new processing
    resetAppState();

    const btn = document.getElementById('process-btn');
    const originalText = btn.innerText;
    btn.innerText = "Processing... (This may take a moment)";
    btn.disabled = true;

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.status === 'success') {
            document.getElementById('results-area').classList.remove('hidden');
            const recordCountText = result.processed_records === "N/A"
                ? "Report Loaded"
                : `${result.processed_records} Records Processed`;
            document.getElementById('record-count').innerText = recordCountText;

            // Store filenames for download
            processedFiles = {
                csv: result.csv_filename,
                xlsx: result.xlsx_filename
            };

            // Load Data into Grid with Category
            const category = result.file_category || (result.processed_records !== "N/A" ? "generic" : "forensic");
            loadGrid(result.data_url, category);

            // Load Histogram (Timeline)
            if (result.csv_filename) {
                currentFilename = result.csv_filename;
                loadHistogram(result.csv_filename);
            }
        } else {
            alert('Error: ' + result.error);
        }

    } catch (e) {
        alert('Upload failed: ' + e);
        console.error(e);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
});



// Chart Export Functions
window.downloadChartPNG = function () {
    if (chartInstance) {
        const a = document.createElement('a');
        a.href = chartInstance.toBase64Image();
        a.download = 'chronos_chart.png';
        a.click();
    } else {
        alert("No chart available to download.");
    }
};

window.downloadChartExcel = function () {
    if (!chartInstance || !chartInstance.data.labels) {
        alert("No chart data available.");
        return;
    }

    const labels = chartInstance.data.labels;
    const datasets = chartInstance.data.datasets;

    // Construct CSV
    // Format: Time, Category1, Category2, ...
    let header = ["Time"];
    datasets.forEach(ds => header.push(ds.label));

    let rows = [header.join(",")];

    for (let i = 0; i < labels.length; i++) {
        let row = [labels[i]];
        datasets.forEach(ds => {
            row.push(ds.data[i] || 0);
        });
        rows.push(row.join(","));
    }

    const csvContent = "data:text/csv;charset=utf-8," + rows.join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "chronos_chart_data.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
};

async function loadGrid(dataUrl, category) {
    if (!dataUrl) return;
    currentDataUrl = dataUrl;
    currentCategory = category;
    // currentStartTime and currentEndTime are globals now used below

    // Reset Filter View state
    // isSelectionView = false; // Assuming this is defined elsewhere if needed
    const btn = document.getElementById('filter-selection-btn');
    if (btn) {
        btn.innerText = "Filter Selection";
        btn.classList.remove("btn-warning");
    }

    // NOTE: loadHistogram is called from process-btn handler, NOT here.
    // Calling it here caused duplicate/race condition.

    const isRemote = true; // Large files always remote pagination
    currentIsRemote = isRemote; // Store global state

    const statusEl = document.getElementById('record-count');
    try {
        statusEl.innerText = "Fetching Data...";

        // 1. Fetch First Page (Preview) to detect columns
        let previewUrl = `${dataUrl}?page=1&size=50&_t=${Date.now()}`;
        if (currentQuery) previewUrl += `&query=${encodeURIComponent(currentQuery)}`;
        if (currentStartTime) previewUrl += `&start_time=${currentStartTime}`;
        if (currentEndTime) previewUrl += `&end_time=${currentEndTime}`;
        if (currentColumnFilters && Object.keys(currentColumnFilters).length > 0) {
            previewUrl += `&col_filters=${encodeURIComponent(JSON.stringify(currentColumnFilters))}`;
        }

        const response = await fetch(previewUrl);
        if (!response.ok) throw new Error(response.statusText);
        const jsonResp = await response.json();

        // Backend now returns { last_page: X, data: [...], total: Y } for paginated results
        // Or pure array if old backend (backward compatibility safe check)
        const data = Array.isArray(jsonResp) ? jsonResp : (jsonResp.data || []);
        const totalRows = jsonResp.total || data.length;
        // const isRemote = !Array.isArray(jsonResp); // If it's the new format, use Remote // This line is now redundant

        // Update Globals for Filter Button
        currentDataUrl = dataUrl;
        currentIsRemote = isRemote;
        currentCategory = category;

        if (data.length === 0) {
            statusEl.innerText = "No Data Found";
            if (table) table.clearData();
            return;
        }

        if (table) {
            table.destroy();
        }

        // 2. Define Columns from Preview Data
        let columns = [];
        let isGeneric = (category === 'generic');

        // Infer Generic if not Forensic format
        if (!isGeneric && data.length > 0 && !data[0].hasOwnProperty('EventID')) {
            isGeneric = true;
        }

        if (isGeneric) {
            // Auto-Columns
            // Check for existing "No." column
            const hasNoColumn = data.length > 0 && Object.keys(data[0]).some(k => k.toLowerCase() === 'no.');

            // Filter out redundant ID columns and Tag column (since we have a checkbox Tag)
            const keys = Object.keys(data[0]).filter(k => !['LineNumber', 'Line', 'line', 'id', 'Tag', 'tag', '_tag', 'Original_Id', 'No.', 'no.', '_id'].includes(k));

            // 1. TAG Column (Checkbox)
            columns.push({
                title: "Tag",
                formatter: "rowSelection",
                titleFormatter: "rowSelection",
                align: "center",
                headerSort: false,
                width: 50,
                frozen: true
            });

            // 2. ID Column (Only if not present in source)
            if (!hasNoColumn) {
                columns.push({
                    title: "No.",
                    field: "_id",
                    formatter: function (cell) {
                        const page = cell.getTable().getPage();
                        const size = cell.getTable().getPageSize();
                        // Fallback to _id if available (from backend), else Calc
                        const rowData = cell.getRow().getData();
                        if (rowData._id !== undefined) return rowData._id;
                        return ((page - 1) * size) + cell.getRow().getPosition(true);
                    },
                    width: 70,
                    frozen: true
                });
            } else {
                // If source has "No.", add it back to keys or handle explicitly?
                // keys filtered it out. Let's add it explicitly if it exists.
                // But wait, if it exists, we want to use THAT one.
                // So we should find the key that matched 'no.' and add it.
                const noKey = Object.keys(data[0]).find(k => k.toLowerCase() === 'no.');
                if (noKey) {
                    columns.push({ title: "No.", field: noKey, width: 70, frozen: true });
                }
            }

            keys.forEach(key => {
                let colDef = {
                    title: key,
                    field: key,
                    headerFilter: "input",
                    width: 150,
                    formatter: highlightFormatter,
                    formatterParams: {}
                };

                // Auto-detect Epoch Timestamp
                // Heuristic: Check first row value + Column Name keywords
                let sampleVal = data.length > 0 ? data[0][key] : null;
                let isEpoch = false;

                // 1. Check numeric range (Year 2000 - 2100 approx)
                if (sampleVal !== null && !isNaN(sampleVal)) {
                    let num = parseFloat(sampleVal);
                    // Sec: > 9e8, MS: > 9e11
                    if (num > 900000000) {
                        // 2. Strong signal: Keywords in column name
                        const timeKeywords = /time|date|seen|created|modified|timestamp|last|start|end/i;
                        if (timeKeywords.test(key)) {
                            isEpoch = true;
                        }
                        // 3. Strong signal: Very large number (ms timestamp)
                        else if (num > 900000000000) {
                            isEpoch = true;
                        }
                    }
                }

                if (isEpoch) {
                    colDef.formatterParams.isEpoch = true;
                    colDef.width = 180; // Widen for date string
                }

                columns.push(colDef);
            });
        } else {
            // Forensic Columns
            columns.push(
                {
                    title: "Tag",
                    formatter: "rowSelection",
                    titleFormatter: "rowSelection",
                    align: "center",
                    headerSort: false,
                    width: 50,
                    frozen: true
                },
                {
                    title: "No.",
                    field: "_id",
                    formatter: function (cell) {
                        const rowData = cell.getRow().getData();
                        if (rowData._id !== undefined) return rowData._id;
                        const page = cell.getTable().getPage();
                        const size = cell.getTable().getPageSize();
                        return ((page - 1) * size) + cell.getRow().getPosition(true);
                    },
                    width: 70,
                    frozen: true
                },
                { title: "Timestamp", field: "Timestamp", frozen: true, width: 180, sorter: "string", headerFilter: "input", formatter: highlightFormatter },
                // removed "Line" (Record ID) as requested ("literally the same")
                { title: "EventID", field: "EventID", headerFilter: "input", width: 90, formatter: highlightFormatter },
                { title: "Level", field: "Level", headerFilter: "input", width: 90, formatter: highlightFormatter },
                { title: "Provider", field: "Provider", headerFilter: "input", formatter: highlightFormatter },
                { title: "Computer", field: "Computer", headerFilter: "input", formatter: highlightFormatter },
                { title: "Description", field: "Description", formatter: highlightFormatter },
            );
        }

        // 3. Initialize Tabulator
        let tableConfig = {
            layout: "fitData", // Performance optimization: faster than fitDataFill
            // height: "100%", // CSS "100%" can fail in some flex layouts
            height: "600px",  // Forced height to ensure rendering
            theme: "midnight",
            movableColumns: true,
            layoutColumnsOnNewData: false, // Prevent re-layout on data load for speed
            // UX OPTIMIZATION: Virtual rendering DISABLED to prevent drag issues
            renderHorizontal: "virtual", // Reverting to virtual as "basic" caused blank table
            // renderHorizontalBuffer: 15000, // Not needed if virtual is false
            columns: columns,

            // ROW SELECTION
            selectable: true,
            selectablePersistence: true // Maintain selection across pages
        };

        if (isRemote) {
            // REMOTE PAGINATION (Large Files)
            tableConfig.pagination = true;
            tableConfig.paginationMode = "remote";

            // Server-side column header filtering
            tableConfig.headerFilterMode = "remote";
            tableConfig.headerFilterLiveFilterDelay = 800; // Debounce keystroke

            tableConfig.paginationSize = 500;
            tableConfig.ajaxURL = dataUrl;

            // Dynamic URL builder: includes time filters, query, AND column header filters
            tableConfig.ajaxURLGenerator = function (url, config, params) {
                let finalUrl = `${url}?page=${params.page || 1}&size=${params.size || 500}&_t=${Date.now()}`;
                if (currentQuery) finalUrl += `&query=${encodeURIComponent(currentQuery)}`;
                if (currentStartTime) finalUrl += `&start_time=${currentStartTime}`;
                if (currentEndTime) finalUrl += `&end_time=${currentEndTime}`;

                // Extract header filters from Tabulator's filter params
                const colFilters = {};
                if (params.filter && params.filter.length > 0) {
                    params.filter.forEach(f => {
                        if (f.value && f.value.toString().trim()) {
                            colFilters[f.field] = f.value.toString().trim();
                        }
                    });
                }
                if (Object.keys(colFilters).length > 0) {
                    finalUrl += `&col_filters=${encodeURIComponent(JSON.stringify(colFilters))}`;
                }
                return finalUrl;
            };

            // Response format mapping
            tableConfig.paginationDataReceived = {
                "last_page": "last_page",
                "data": "data"
            };

            tableConfig.paginationDataSent = {
                "page": "page",
                "size": "size"
            };

            statusEl.innerText = `Total Records: ${totalRows} (Paged)`;
        } else {
            // LOCAL PAGINATION (Legacy/Small Files)
            tableConfig.data = data;
            tableConfig.pagination = true;
            tableConfig.paginationMode = "local";
            tableConfig.paginationSize = 500; // Increased to 500
            statusEl.innerText = `${data.length} Records Loaded`;
        }

        table = new Tabulator("#timeline-table", tableConfig);

        // UX: Auto-expand columns with search hits
        table.on("dataFiltered", function (filters, rows) {
            if (currentQuery && columnsWithHits.size > 0) {
                // Determine appropriate width (e.g., 300px or auto)
                columnsWithHits.forEach(field => {
                    const col = table.getColumn(field);
                    if (col) {
                        col.setWidth(300); // Expand to show context
                        // col.scrollTo(); // Optional: scroll to first hit? might be annoying
                    }
                });
                // Reset for next search
                columnsWithHits.clear();
            }
        });

        // Restore Event Handlers
        table.on("cellClick", function (e, cell) {
            // Important: Don't trigger modal if clicking the selection checkbox
            const field = cell.getColumn().getField();
            const colDef = cell.getColumn().getDefinition();
            if (!field && colDef.formatter === "rowSelection") return;

            const val = cell.getValue();
            const colTitle = colDef.title || colDef.field;
            if (val) showModal(colTitle, val);
        });

        // Sync chart when column header filters change (e.g., EventID=2050)
        table.on("dataFiltered", function (filters, rows) {
            // Build filter map from active header filters
            let headerFilters;
            try { headerFilters = table.getHeaderFilters(); } catch (e) { return; }
            const newFilters = {};
            headerFilters.forEach(f => {
                if (f.value && f.value.toString().trim()) {
                    newFilters[f.field] = f.value.toString().trim();
                }
            });

            // Only reload if filters actually changed
            const filtersChanged = JSON.stringify(newFilters) !== JSON.stringify(currentColumnFilters);
            if (!filtersChanged) return;

            currentColumnFilters = newFilters;

            // Debounce: wait 800ms after last filter keystroke
            if (filterDebounceTimer) clearTimeout(filterDebounceTimer);
            filterDebounceTimer = setTimeout(() => {
                if (currentFilename) {
                    console.log("Column filters changed, syncing chart:", currentColumnFilters);
                    loadHistogram(currentFilename, currentExcludeId, currentStartTime, currentEndTime);
                }
            }, 800);
        });

        statusEl.innerText = `${data.length} Records Loaded`;

    } catch (e) {
        alert("Failed to load grid data: " + e.message);
        console.error(e);
        statusEl.innerText = "Error loading data";
    }
}

// Modal Logic
const modal = document.getElementById("detail-modal");
const span = document.getElementsByClassName("close-btn")[0];
const modalText = document.getElementById("modal-text");
const modalTitle = document.getElementById("modal-title");

function showModal(title, text) {
    modalTitle.innerText = title;
    // Pretty print JSON if detected
    try {
        if (typeof text === 'string' && (text.startsWith('{') || text.startsWith('['))) {
            text = JSON.stringify(JSON.parse(text), null, 2);
        }
    } catch (e) { }
    modalText.innerText = text;
    modal.classList.add("show");
}

if (span) {
    span.onclick = function () {
        if (modal) modal.classList.remove("show");
    }
}

window.onclick = function (event) {
    if (modal && event.target == modal) {
        modal.classList.remove("show");
    }
}

// Downloads utilizing Backend for FULL file access or Filtered Export
async function downloadData(format, aiOptimized = false) {
    if (!processedFiles || !processedFiles.csv) {
        // Fallback for purely local data (rare)
        if (table) table.download(format, `Chronos_Export.${format}`, { source: "active" });
        return;
    }

    const filters = table.getHeaderFilters();
    const selectedRows = table.getSelectedRows();

    // 1. Selection Export (Client Side) - when rows are checked OR in filter selection view
    if (selectedRows.length > 0) {
        table.download(format, `Chronos_Selected.${format}`, { source: "selection" });
        return;
    }

    // 2. If in Selection View (Filter Selection mode), export ALL visible table data
    if (isSelectionView) {
        const data = table.getData();
        if (!data || data.length === 0) {
            alert("No data to export.");
            return;
        }

        // Build CSV manually from table data
        const columns = table.getColumnDefinitions()
            .filter(c => c.field && c.field !== '_checkbox')
            .map(c => c.field);

        const csvRows = [columns.join(",")];
        data.forEach(row => {
            const values = columns.map(col => {
                let val = row[col] !== undefined && row[col] !== null ? String(row[col]) : "";
                // Escape commas and quotes
                if (val.includes(",") || val.includes('"') || val.includes("\n")) {
                    val = '"' + val.replace(/"/g, '""') + '"';
                }
                return val;
            });
            csvRows.push(values.join(","));
        });

        const csvContent = csvRows.join("\n");
        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `Chronos_Filtered.${format === "xlsx" ? "csv" : format}`;
        a.click();
        URL.revokeObjectURL(url);
        return;
    }

    // 2. Export via Backend (Filtered or Full) -> Ensures "No." column and Timestamp Formatting
    if (processedFiles && processedFiles.csv) {
        let btn;
        if (aiOptimized) {
            btn = document.getElementById('download-ai');
        } else {
            btn = document.getElementById(`download-${format}`);
        }

        const originalText = btn.innerText;
        btn.innerText = aiOptimized ? "Exporting AI View..." : "Exporting...";
        btn.disabled = true;

        try {
            const resp = await fetch('/api/export_filtered', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: processedFiles.csv,
                    start_time: currentStartTime,
                    end_time: currentEndTime,
                    query: currentQuery,
                    col_filters: currentColumnFilters, // Correctly pass column header filters
                    ai_optimized: aiOptimized // NEW: Flag to remove empty columns
                })
            });

            if (!resp.ok) throw new Error("Export failed");

            // Trigger Download
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;

            // Smart Extension Handling
            let extension = format;
            const contentType = resp.headers.get("content-type");
            if (contentType && contentType.includes("zip")) {
                extension = "zip";
            }
            a.download = `Chronos_Export.${extension}`;

            document.body.appendChild(a);
            a.click();
            a.remove();
        } catch (e) {
            alert("Export error: " + e.message);
        } finally {
            if (btn) {
                btn.innerText = originalText;
                btn.disabled = false;
            }
        }
        return;
    }
    // Fallback
    table.download(format, `Chronos_Export.${format}`, { source: "active" });
}


// Event listeners for downloads moved to DOMContentLoaded
// New: Split Zip Download
async function downloadSplitZip() {
    if (!processedFiles || !processedFiles.csv) {
        alert("No file loaded to split.");
        return;
    }

    const filters = table ? table.getHeaderFilters() : [];

    // If in Selection View, export the visible table data as CSV (no split needed for small subsets)
    if (isSelectionView && table) {
        table.download("csv", `Chronos_Filtered_Split.csv`);
        return;
    }

    const btn = document.getElementById('download-split');
    const originalText = btn.innerText;
    btn.innerText = "Zipping...";
    btn.disabled = true;

    try {
        const resp = await fetch('/api/export_split', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: processedFiles.csv,
                filters: filters,
                selected_ids: [],
                format: 'csv',
                query: currentQuery || "",
                start_time: currentStartTime || "",
                end_time: currentEndTime || ""
            })
        });

        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.error || "Export failed");
        }

        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Chronos_Split_Export.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

    } catch (e) {
        alert("Split Export Failed: " + e.message);
        console.error(e);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

// Bind it
document.addEventListener('DOMContentLoaded', () => {
    // ... existing bindings ...
    const dlSplit = document.getElementById('download-split');
    if (dlSplit) dlSplit.addEventListener('click', downloadSplitZip);
});


function bindFilterButton() {
    const btn = document.getElementById('filter-selection-btn');
    if (!btn) return;

    // Remove existing listeners (not easily possible without named function, but we rely on single bind on load)
    // We assume this is called once on DOMContentLoaded

    btn.addEventListener('click', function () {
        console.log("Filter button clicked");

        if (!table) return;
        const btn = this;

        if (!isSelectionView) {
            // Enter Selection View
            const selectedRows = table.getSelectedRows();

            // Sort by _id to maintain timeline/row order (not selection order)
            const selectedData = selectedRows
                .map(row => row.getData())
                .sort((a, b) => (a._id || 0) - (b._id || 0));

            // Get Indices for Backend using the global '_id' provided by get_data
            const selectedIndices = selectedData.map(d => d._id !== undefined ? d._id : 0);

            if (selectedData.length === 0) {
                alert("No rows selected. Please check the boxes on the left to filter.");
                return;
            }

            // 1. Grid Visual Update (Client Side)
            table.replaceData(selectedData)
                .then(() => {
                    isSelectionView = true;
                    btn.innerText = "Show All Events";
                    btn.classList.add("active-filter");
                    btn.style.backgroundColor = "#ff9800";
                    btn.style.color = "#000";

                    const interp = document.getElementById('chart-interpretation');
                    if (interp) interp.innerText = `Viewing ${selectedData.length} selected events in grid. Updating chart...`;
                });

            // 2. Chat Update (Backend Subset Analysis)
            updateChartWithSubset(currentFilename, selectedIndices);

        } else {
            // Exit Selection View
            isSelectionView = false;
            btn.innerText = "Filter Selection";
            btn.classList.remove("active-filter");
            btn.style.backgroundColor = "";
            btn.style.color = "";

            // Reload original data
            if (currentDataUrl) {
                loadGrid(currentDataUrl, currentCategory);
                // currentFilename is global now
                loadHistogram(currentFilename, currentExcludeId);
            }
        }
    });
}

// Chart Subset Helper
async function updateChartWithSubset(filename, indices) {
    if (!filename || !indices.length) return;

    console.log("Updating chart with subset:", filename, indices.length, "rows");
    try {
        const resp = await fetch('/api/histogram_subset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: filename, selected_ids: indices })
        });
        const data = await resp.json();
        console.log("Subset Chart Data:", data);

        if (data.error) {
            console.error("Subset chart error:", data.error);
            const interp = document.getElementById('chart-interpretation');
            if (interp) {
                interp.style.color = 'orange';
                interp.innerText = `Chart update failed: ${data.error}`;
            }
            return;
        }

        // Cache data for log scale toggle
        currentChartData = data;

        renderChart(data);

        // Update Time Range and Events info (same as loadHistogram)
        if (data.stats) {
            const infoEl = document.getElementById('time-range-info');
            if (infoEl) {
                const formatDateToISO = (isoStr) => {
                    if (!isoStr) return "N/A";
                    const d = new Date(isoStr);
                    if (isNaN(d.getTime())) return isoStr;
                    const pad = (n) => n.toString().padStart(2, '0');
                    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
                };
                const start = formatDateToISO(data.stats.start_time);
                const end = formatDateToISO(data.stats.end_time);
                infoEl.innerHTML = `Time Range: <span style="color:#fff">${start}</span> to <span style="color:#fff">${end}</span> | Events: <span style="color:#fff">${data.stats.total_events}</span> <span style="color:#ff9800">(Filtered)</span>`;
            }

            const recordCountEl = document.getElementById('record-count');
            if (recordCountEl) recordCountEl.innerText = `${data.stats.total_events} Records (Filtered)`;
        }

        // Update interpretation
        if (data.interpretation) {
            const interp = document.getElementById('chart-interpretation');
            if (interp) {
                interp.style.color = '#ccc';
                interp.innerText = data.interpretation;
            }
        }
    } catch (e) {
        console.error("Subset Chart Error:", e);
        const interp = document.getElementById('chart-interpretation');
        if (interp) {
            interp.style.color = 'orange';
            interp.innerText = `Chart update error: ${e.message}`;
        }
    }
}

async function loadHistogram(filename, excludeId = null, startTime = null, endTime = null) {
    currentFilename = filename;
    currentExcludeId = excludeId;

    const wrapper = document.getElementById('chart-wrapper');
    const interp = document.getElementById('chart-interpretation');
    const noiseBtn = document.getElementById('noise-filter-btn') || createNoiseButton();

    let url = `/api/histogram/${filename}?`;
    if (excludeId) url += `exclude_id=${excludeId}&`;
    if (startTime) url += `start_time=${startTime}&`;
    if (endTime) url += `end_time=${endTime}&`;
    if (currentQuery) url += `query=${encodeURIComponent(currentQuery)}&`;
    // Pass active column header filters
    if (currentColumnFilters && Object.keys(currentColumnFilters).length > 0) {
        url += `col_filters=${encodeURIComponent(JSON.stringify(currentColumnFilters))}&`;
    }
    // Prevent caching
    url += `_t=${Date.now()}&`;

    // Visual Feedback
    if (interp) {
        interp.style.color = '#888';
        interp.innerText = "Filtering data and updating chart...";
    }

    // Cancel any pending histogram request to prevent race conditions
    if (histogramAbortController) histogramAbortController.abort();
    histogramAbortController = new AbortController();

    try {
        const response = await fetch(url, { signal: histogramAbortController.signal });
        const data = await response.json();

        // Handle Backend Error
        if (data.error) {
            console.error("Backend Error:", data.error);
            if (interp) {
                interp.style.color = 'red';
                interp.innerText = `Error loading chart: ${data.error}`;
            }
            if (chartInstance) chartInstance.destroy();
            return;
        }

        // Update Info Bar
        if (data.stats) {
            const infoEl = document.getElementById('time-range-info');
            if (infoEl) {
                // Helper to format date
                const formatDateToISO = (isoStr) => {
                    if (!isoStr) return "N/A";
                    const d = new Date(isoStr);
                    if (isNaN(d.getTime())) return isoStr;
                    // YYYY-MM-DD HH:mm:ss
                    const pad = (n) => n.toString().padStart(2, '0');
                    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
                };

                const start = formatDateToISO(data.stats.start_time);
                const end = formatDateToISO(data.stats.end_time);

                infoEl.innerHTML = `Time Range: <span style="color:#fff">${start}</span> to <span style="color:#fff">${end}</span> | Events: <span style="color:#fff">${data.stats.total_events}</span>`;

                // Set inputs (ALWAYS overwrite on initial load of a new file)
                const startIn = document.getElementById('time-start');
                const endIn = document.getElementById('time-end');
                if (startIn && data.stats.start_time) {
                    startIn.value = data.stats.start_time.slice(0, 16);
                }
                if (endIn && data.stats.end_time) {
                    endIn.value = data.stats.end_time.slice(0, 16);
                }
            }
        }

        // Cache data for log scale toggle
        currentChartData = data;

        renderChart(data);

        // Handle Interpretation
        if (data.interpretation && interp) {
            interp.style.color = '#ccc';
            let interpText = data.interpretation;
            // Append global stats summary when available
            if (data.global_stats && data.global_stats.max_bucket > 0) {
                const gs = data.global_stats;
                interpText += ` | 📊 Prom: ${Math.round(gs.mean_bucket).toLocaleString()} | Máx: ${gs.max_bucket.toLocaleString()}`;
            }
            interp.innerText = interpText;
        }

        // Handle Noise Filter Button
        if (data.noise_info && data.noise_info.percent > 40) { // Threshold 40%
            noiseBtn.style.display = 'inline-block';
            noiseBtn.innerText = `Hide Noise (ID: ${data.noise_info.top_talker_id} - ${data.noise_info.percent}%)`;
            noiseBtn.onclick = () => {
                // Toggle
                if (currentExcludeId) {
                    loadHistogram(filename, null); // Reset
                    noiseBtn.classList.remove('active-noise');
                } else {
                    loadHistogram(filename, data.noise_info.top_talker_id); // Filter
                    noiseBtn.classList.add('active-noise');
                }
            };
            if (currentExcludeId) {
                noiseBtn.innerText = "Show All Events (Reset Noise)";
                noiseBtn.classList.add('active-noise');
            }
        } else {
            noiseBtn.style.display = 'none';
        }

    } catch (e) {
        console.error("Histogram loading failed", e);
        if (currentExcludeId === null) { const interp = document.getElementById('chart-interpretation'); if (interp) { interp.style.color = 'red'; interp.innerText = "Error: " + e.message; } }
    }
}

function createNoiseButton() {
    // Target the new .chart-controls div
    const controls = document.querySelector('.chart-controls');
    const wrapper = document.getElementById('chart-wrapper');

    const btn = document.createElement('button');
    btn.id = 'noise-filter-btn';
    btn.className = 'btn-sm btn-outline-danger';
    btn.style.marginLeft = '10px';
    btn.style.display = 'none';

    // Append to controls if exists, else prepend to wrapper
    if (controls) {
        controls.appendChild(btn);
    } else if (wrapper) {
        wrapper.insertBefore(btn, wrapper.firstChild);
    }
    return btn;
}

// Render Logic extracted for reuse
function renderChart(data) {
    const ctx = document.getElementById('timelineChart').getContext('2d');

    // Destroy previous instance
    if (chartInstance) {
        chartInstance.destroy();
    }

    // Check Log Scale
    const logToggle = document.getElementById('log-scale-toggle');
    const isLog = logToggle ? logToggle.checked : false;

    // Determine if we have global context (filtered view)
    const gs = data.global_stats || null;

    // Build chart datasets 
    // Modify styles for "Activity" vars to be "dotted" (border only, dashed)
    // Modify "Trend" to be smooth
    // Add "Peaks" dataset

    const chartDatasets = [];

    // 1. Process existing datasets (Activity & Trend)
    (data.datasets || []).forEach(ds => {
        if (ds.type === 'line' && (ds.label === 'Trend' || ds.label === 'Tendencia')) {
            // Improve Trend Visuals
            ds.tension = 0.4; // Smooth
            ds.cubicInterpolationMode = 'monotone'; // More organic
            ds.borderColor = '#FFFF00'; // Bright Yellow for high visibility
            ds.backgroundColor = 'rgba(255, 255, 0, 0.1)';
            ds.borderWidth = 3; // Thicker line
            ds.fill = true;
            chartDatasets.push(ds);
        } else if (ds.label === 'Anomaly (> 2σ)') {
            chartDatasets.push(ds);
        } else {
            // Activity Bars -> "Dotted" style
            // We simulate "dotted bars" by making them transparent with a dashed border
            // If user wants them "filled but dotted", we'd need a pattern. 
            // "Las barras eran lineas punteadas" -> Dotted outlines?
            // Let's try: Transparent fill, strong colored border, dashed.

            const baseColor = ds.backgroundColor || '#3399ff';

            // Clone to avoid mutating original ref if needed
            const newDs = { ...ds };
            newDs.backgroundColor = baseColor; // Keep fill for visibility, maybe reduce opacity?
            newDs.backgroundColor = 'transparent'; // As requested "dotted lines" implies outline
            newDs.borderColor = baseColor;
            newDs.borderWidth = 2;
            newDs.borderSkipped = false; // Border on all sides
            newDs.borderDash = [3, 3]; // Dotted effect

            // Make them pop a bit more if they are transparent
            if (ds.label.includes('Alta')) {
                newDs.borderColor = '#ff6600';
            }

            chartDatasets.push(newDs);
        }
    });

    // 2. Add "Peaks" dataset (Red Arrows)
    // Identify local maxima or just high values? User said "picos... flecha roja"
    // Let's mark topmost peaks (e.g. > 80% of global max)

    // We need to reconstruct the total volume array to find peaks
    // Assuming data.datasets has the volume data. 
    // But data.datasets is stacked... finding "peaks" of the STACK is hard without summing.
    // data.global_stats has max_bucket, but we don't have the per-bucket totals easily here unless we sum.
    // Let's extract the "Trend" dataset or sum the bars if possible.
    // Actually, "Trend" (SMA) is a good proxy, or we can just iterate the labels and sum segments.

    // Simple approach: Use data.datasets to sum volumes per index
    if (data.datasets) {
        const totals = new Array(data.labels.length).fill(0);
        data.datasets.forEach(ds => {
            if (ds.type !== 'line' && ds.type !== 'scatter' && !ds.hidden) {
                ds.data.forEach((val, i) => {
                    totals[i] += (val || 0);
                });
            }
        });

        const maxVal = Math.max(...totals);
        const peakThreshold = maxVal * 0.8; // Mark peaks > 80% max

        const peakData = totals.map(v => (v >= peakThreshold && v > 0) ? v + (maxVal * 0.05) : null); // Lift arrow slightly above bar

        chartDatasets.push({
            label: 'Peaks',
            data: peakData,
            type: 'scatter',
            backgroundColor: 'red',
            borderColor: 'red',
            pointStyle: 'triangle',
            rotation: 180, // Point down
            pointRadius: 6,
            order: 0,
            tooltip: {
                callbacks: {
                    label: (context) => `Peak: ${Math.round(totals[context.dataIndex])}`
                }
            }
        });
    }

    // Config
    chartInstance = new Chart(ctx, {
        type: 'bar',
        data: { labels: data.labels, datasets: chartDatasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            },
            scales: {
                x: {
                    stacked: data.stacked !== false,
                    grid: { color: '#333' },
                    ticks: { color: '#aaa', maxRotation: 45, font: { size: 10 } }
                },
                y: {
                    type: isLog ? 'logarithmic' : 'linear',
                    stacked: data.stacked !== false,
                    grid: { color: '#333', drawBorder: true },
                    ticks: { color: '#aaa' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#ccc', font: { size: 11 } },
                    onClick: function (e, legendItem, legend) {
                        const index = legendItem.datasetIndex;
                        const ci = legend.chart;

                        // Additive Isolation Logic
                        let isIsolationMode = false;
                        for (let i = 0; i < ci.data.datasets.length; i++) {
                            if (!ci.isDatasetVisible(i)) {
                                isIsolationMode = true;
                                break;
                            }
                        }

                        const evt = e.native || e;

                        if (evt.shiftKey || evt.ctrlKey || evt.metaKey) {
                            if (ci.isDatasetVisible(index)) ci.hide(index);
                            else ci.show(index);
                        } else {
                            if (!isIsolationMode) {
                                ci.data.datasets.forEach((ds, i) => {
                                    if (i === index) ci.show(i);
                                    else ci.hide(i);
                                });
                            } else {
                                if (ci.isDatasetVisible(index)) {
                                    ci.hide(index);
                                    let anyVisible = false;
                                    for (let i = 0; i < ci.data.datasets.length; i++) {
                                        if (ci.isDatasetVisible(i)) {
                                            anyVisible = true;
                                            break;
                                        }
                                    }
                                    if (!anyVisible) {
                                        ci.data.datasets.forEach((ds, i) => {
                                            ci.show(i);
                                        });
                                    }
                                } else {
                                    ci.show(index);
                                }
                            }
                        }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(0,0,0,0.85)',
                    titleColor: '#fff',
                    bodyColor: '#ccc',
                    callbacks: {
                        title: function (context) {
                            const isoStr = context[0].label;
                            const d = new Date(isoStr);
                            if (!isNaN(d.getTime())) {
                                const pad = (n) => n.toString().padStart(2, '0');
                                return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
                            }
                            return isoStr;
                        },
                        afterBody: function (context) {
                            const lines = [];
                            if (gs) {
                                const val = context[0]?.parsed?.y || 0;
                                const pctOfTotal = ((val / gs.total_events) * 100).toFixed(3);
                                const ratioToMean = gs.mean_bucket > 0 ? (val / gs.mean_bucket).toFixed(1) : 'N/A';
                                lines.push(`${pctOfTotal}% of ${gs.total_events.toLocaleString()} total events`);
                                lines.push(`${ratioToMean}x global average`);
                                if (val > gs.max_bucket * 0.85 && val > gs.mean_bucket) lines.push('⚠️ Near global peak');
                            }
                            lines.push('');
                            lines.push('Legend: Click=Isolate | Shift+Click=Toggle');
                            return lines;
                        }
                    }
                }
            },
            onClick: (evt, activeElements) => {
                if (activeElements.length > 0) {
                    const idx = activeElements[0].index;
                    const label = data.labels[idx];
                    console.log("Clicked bucket:", label);
                }
            }
        }
    });
}
