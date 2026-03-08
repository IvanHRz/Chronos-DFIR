import { API } from './api.js?v=179';
import ChronosState from './state.js?v=179';
import events from './events.js?v=179';

export class GridManager {
    constructor(elementId) {
        this.elementId = elementId;
        this.table = null;
        this.isSelectionView = false;
        this.columnManagerActive = false;
        this.selectedColumns = [];
        this.columnsWithHits = new Set();
        this.setupEventListeners();
    }

    setupEventListeners() {
        events.on('SESSION_UPDATED', async ({ filename }) => {
            if (!filename) return;
            try {
                // Fetch 1 row to get dynamic columns
                window.isDownloading = true;
                const res = await fetch(`/api/data/${filename}?page=1&size=1`);
                const jsonData = await res.json();
                const cols = this.generateColumns(jsonData.data || [], 'generic');

                this.init({
                    ajaxURL: `/api/data/${filename}`,
                    ajaxParams: {
                        query: ChronosState.currentQuery,
                        start_time: ChronosState.startTime,
                        end_time: ChronosState.endTime,
                        col_filters: JSON.stringify(ChronosState.currentColumnFilters)
                    },
                    columns: cols
                });
            } catch (e) {
                console.error("Failed to load schema:", e);
                alert("Could not load grid schema: " + e.message);
            } finally {
                window.isDownloading = false;
            }
        });

        events.on('FILTERS_CHANGED', () => this.reload());
        events.on('TIME_RANGE_CHANGED', () => this.reload());
        events.on('STATE_RESET', () => {
            if (this.table) {
                this.table.clearData();
                this.isSelectionView = false;
            }
        });
    }

    reload() {
        if (!this.table || !ChronosState.currentFilename) return;
        this.table.setData(`/api/data/${ChronosState.currentFilename}`, {
            query: ChronosState.currentQuery,
            start_time: ChronosState.startTime,
            end_time: ChronosState.endTime,
            col_filters: JSON.stringify(ChronosState.currentColumnFilters)
        });
    }


    getSearchRegex(query) {
        if (!query || query.length < 2) return null;
        try {
            return new RegExp(`(${query.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')})`, 'gi');
        } catch (e) { return null; }
    }

    highlightFormatter(cell) {
        let val = cell.getValue();
        if (val === null || val === undefined) return "";

        const fieldName = cell.getColumn().getField()?.toLowerCase() || "";
        if (fieldName.includes("time") || fieldName.includes("date") || fieldName.includes("created") || fieldName.includes("modified")) {
            const num = parseFloat(val);
            if (!isNaN(num) && num > 946684800) {
                let date = new Date(num > 946684800000 ? num : num * 1000);
                if (!isNaN(date.getTime())) {
                    const pad = (n) => n.toString().padStart(2, '0');
                    val = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
                }
            }
        }

        val = String(val);
        val = val.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");

        const currentQuery = ChronosState.currentQuery;
        if (currentQuery && currentQuery.trim().length > 0) {
            const regex = this.getSearchRegex(currentQuery);
            if (regex && regex.test(val)) {
                this.columnsWithHits.add(cell.getColumn().getField());
                val = val.replace(regex, '<span class="highlight-term">$1</span>');
            }
        }
        return val;
    }

    init(options = {}) {
        const defaultConfig = {
            layout: "fitData",
            height: "600px",
            theme: "midnight",
            index: "_id",
            movableColumns: true,
            pagination: true,
            paginationMode: "remote",
            paginationSize: 500,
            // headerFilterMode is NOT "remote" — we handle server-side filtering via
            // our own col_filters param in reload(). This ensures exports always
            // receive the same filter payload that the grid uses.
            sortMode: "remote",
            selectable: true,
            selectablePersistence: true,
            initialSort: [{ column: "_id", dir: "asc" }],
            nestedFieldSeparator: false
        };


        this.table = new Tabulator(`#${this.elementId}`, {
            ...defaultConfig,
            ...options,
            ajaxResponse: (url, params, response) => {
                if (response.total !== undefined) {
                    const unfiltered = response.total_unfiltered ?? response.total;
                    ChronosState.setCounts(unfiltered, response.total);
                }

                if (response.start_time && response.end_time) {
                    const timeEl = document.getElementById('time-range-info');
                    if (timeEl) {
                        timeEl.innerText = `Time Range: ${response.start_time} - ${response.end_time}`;
                    }
                }
                return response;
            }
        });

        // Row Selection Updates state
        this.table.on("rowSelectionChanged", (data, rows) => {
            ChronosState.selectedIds = data.map(r => r._id);
        });

        // Sync header filters → ChronosState via updateFilters (emits FILTERS_CHANGED).
        // This ensures grid, chart, and exports all use the exact same filter state.
        this._headerFilterTimer = null;
        this.table.on("headerFilterChanged", () => {
            clearTimeout(this._headerFilterTimer);
            this._headerFilterTimer = setTimeout(() => {
                const filters = this.table.getHeaderFilters();
                ChronosState.updateFilters(ChronosState.currentQuery, filters);
            }, 400); // 400ms debounce — avoids one request per keystroke
        });

        // Cell Click for Details — only show modal for long/complex values
        this.table.on("cellClick", (e, cell) => {
            const field = cell.getColumn().getField();
            const colDef = cell.getColumn().getDefinition();
            if (!field || colDef.formatter === "rowSelection" || field === "_id") return;

            const val = cell.getValue();
            if (!val) return;
            const str = String(val);
            // Show modal only for: JSON strings, or content longer than 60 chars
            const isJson = str.startsWith('{') || str.startsWith('[');
            const isLong = str.length > 60;
            if (isJson || isLong) {
                const colTitle = colDef.title || field;
                this.showDetailModal(colTitle, str);
            }
        });

        return this.table;
    }

    showDetailModal(title, text) {
        const modal = document.getElementById("detail-modal");
        const modalTitle = document.getElementById("modal-title");
        const modalText = document.getElementById("modal-text");

        if (!modal || !modalText) return;

        if (modalTitle) modalTitle.innerText = title;

        // Pretty print JSON
        try {
            if (typeof text === 'string' && (text.startsWith('{') || text.startsWith('['))) {
                text = JSON.stringify(JSON.parse(text), null, 2);
            }
        } catch (e) { }

        modalText.innerText = text;
        modal.classList.add("show");
        modal.classList.remove("hidden");

        // Close on X button
        const closeBtn = modal.querySelector('.close-btn');
        if (closeBtn) {
            closeBtn.onclick = () => {
                modal.classList.remove("show");
                modal.classList.add("hidden");
            };
        }
        // Close on backdrop click
        modal.onclick = (ev) => {
            if (ev.target === modal) {
                modal.classList.remove("show");
                modal.classList.add("hidden");
            }
        };
    }

    handleHeaderClick(e, column) {
        if (!this.columnManagerActive) return;
        if (e) {
            e.stopPropagation();
            e.preventDefault();
        }
        this.toggleColumnSelection(column);
    }

    generateColumns(sampleData, category) {
        // No. column: pure client-side row counter (1..N always, independent of backend _id)
        const noCol = {
            title: "No.",
            field: "_id",
            width: 75,
            frozen: true,
            headerSort: false,
            headerClick: this.handleHeaderClick.bind(this),
            formatter: (cell) => {
                const table = cell.getTable();
                const page = (table.getPage && table.getPage()) || 1;
                const pageSize = (table.getPageSize && table.getPageSize()) || 500;
                const rows = table.rowManager?.activeRows || [];
                const row = cell.getRow()._row;
                const idx = rows.indexOf(row);
                return idx !== -1 ? (page - 1) * pageSize + idx + 1 : (cell.getValue() ?? '');
            }
        };
        const columns = [
            { formatter: "rowSelection", titleFormatter: "rowSelection", hozAlign: "center", headerSort: false, width: 40, frozen: true },
            noCol
        ];

        // Artifact specific logic
        if (category === 'EVTX') {
            columns.push({ title: "Timestamp", field: "timestamp", sorter: "datetime", width: 180, formatter: this.highlightFormatter.bind(this), headerClick: this.handleHeaderClick.bind(this) });
            columns.push({ title: "Event ID", field: "event_id", sorter: "number", width: 80, formatter: this.highlightFormatter.bind(this), headerClick: this.handleHeaderClick.bind(this) });
            columns.push({ title: "Task", field: "task", width: 150, formatter: this.highlightFormatter.bind(this), headerClick: this.handleHeaderClick.bind(this) });
        } else if (category === 'MFT') {
            columns.push({ title: "File Path", field: "file_path", width: 300, formatter: this.highlightFormatter.bind(this), headerClick: this.handleHeaderClick.bind(this) });
            columns.push({ title: "Created", field: "created", sorter: "datetime", width: 180, formatter: this.highlightFormatter.bind(this), headerClick: this.handleHeaderClick.bind(this) });
        }

        // Auto-generate remaining from sample
        // Skip internal/reserved column names to prevent duplicates from old exports
        const RESERVED = new Set(['_id', 'No.', 'no.', 'NO.', 'Original_No.', 'original_no.']);
        if (sampleData && sampleData.length > 0) {
            const existingFields = new Set(columns.map(c => c.field));
            Object.keys(sampleData[0]).forEach(key => {
                if (!existingFields.has(key) && !RESERVED.has(key)) {
                    columns.push({ title: key, field: key, headerFilter: "input", formatter: this.highlightFormatter.bind(this), headerClick: this.handleHeaderClick.bind(this) });
                }
            });
        }

        return columns;
    }



    getSelectedIds() {
        if (!this.table) return [];
        if (this.isSelectionView) {
            return this.table.getData().map(r => r._id);
        }
        return this.table.getSelectedRows().map(r => r.getData()._id);
    }

    applyRowSelectionFilter(filename, onUpdateChart) {
        if (!this.table) return;

        if (!this.isSelectionView) {
            const selectedRows = this.table.getSelectedRows();
            if (selectedRows.length === 0) {
                alert("No rows selected. Please check the boxes on the left to filter.");
                return false;
            }

            const selectedIndices = selectedRows.map(r => r.getData()._id || 0);
            const idSet = new Set(selectedIndices);

            this.isSelectionView = true;
            this.table.setFilter(data => idSet.has(data._id));
            // Deselect all rows after filtering — the filter IS the selection now
            this.table.deselectRow();

            if (onUpdateChart) onUpdateChart(filename, selectedIndices);
            return true;
        } else {
            this.isSelectionView = false;
            this.table.clearFilter();
            return false;
        }
    }

    async toggleEmptyColumns(filename) {
        if (!this.table || !filename) return;

        const btn = document.getElementById('toggle-empty-cols');

        // TOGGLE OFF: instantly show hidden cols from cache (batched redraw)
        if (this._hiddenEmptyCols?.length > 0) {
            this.table.blockRedraw();
            this._hiddenEmptyCols.forEach(col => { try { col.show(); } catch (_) { } });
            this.table.restoreRedraw();
            this._hiddenEmptyCols = [];
            if (btn) btn.innerHTML = `Hide Empty`;
            return;
        }

        // TOGGLE ON: fetch empty cols once, cache, hide
        const originalText = btn?.innerHTML || 'Hide Empty';
        if (btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ...';

        try {
            const params = {
                query: window.ChronosState?.currentQuery || '',
                start_time: window.ChronosState?.startTime || '',
                end_time: window.ChronosState?.endTime || '',
                col_filters: JSON.stringify(window.ChronosState?.currentColumnFilters || this.table.getHeaderFilters() || [])
            };
            const data = await API.getEmptyColumns(filename, params);
            const emptySet = new Set((data.empty_columns || []).map(c => c.toLowerCase()));

            const toHide = [];
            this.table.getColumns().forEach(col => {
                const def = col.getDefinition();
                const field = (col.getField() || '').toLowerCase();
                const title = (def.title || '').toLowerCase();
                // Never hide frozen/internal columns
                if (def.formatter === 'rowSelection' || field === '_id') return;
                if (emptySet.has(field) || emptySet.has(title)) toHide.push(col);
            });

            if (toHide.length === 0) {
                if (btn) btn.innerHTML = originalText;
                btn && alert('No hay columnas completamente vacías.');
                return;
            }

            this.table.blockRedraw();
            toHide.forEach(col => { try { col.hide(); } catch (_) { } });
            this.table.restoreRedraw();
            this._hiddenEmptyCols = toHide;
            if (btn) btn.innerHTML = `Show All (${toHide.length})`;
        } catch (e) {
            console.error('toggleEmptyColumns error:', e);
            if (btn) btn.innerHTML = originalText;
        }
    }



    clearFilters() {
        if (!this.table) return;
        this.table.blockRedraw();
        this.table.clearFilter();
        this.table.clearHeaderFilter();
        this.table.setSort([]);
        this.table.deselectRow();

        const cols = this.table.getColumns();
        cols.forEach(col => { if (!col.isVisible()) col.show(); });

        this.isSelectionView = false;
        this.table.restoreRedraw();
    }

    // ─────────────────────────────────────────────────────────────
    // Column Manager — Numbered ordering, multi-select, filter
    // ─────────────────────────────────────────────────────────────

    toggleColumnManager() {
        this.columnManagerActive = !this.columnManagerActive;
        const btn = document.getElementById('col-manager-btn');
        const actions = document.getElementById('col-manager-actions');

        if (this.columnManagerActive) {
            btn?.classList.add('active-manager');
            if (btn) btn.innerHTML = `Done <i class="fas fa-check"></i>`;
            if (actions) actions.style.display = 'inline-flex';
            this.injectColumnManagerUI();
            // Add renderComplete listener to persist UI elements
            if (this.table) {
                this._renderCompleteHandler = () => {
                    if (this.columnManagerActive) {
                        this.injectColumnManagerUI();
                        this._refreshOrderBadges();
                    }
                };
                this.table.on("renderComplete", this._renderCompleteHandler);
            }
        } else {
            btn?.classList.remove('active-manager');
            if (btn) btn.innerHTML = `Manage Cols <i class="fas fa-columns"></i>`;
            if (actions) actions.style.display = 'none';
            this._removeColumnManagerUI();
            // Remove renderComplete listener
            if (this.table && this._renderCompleteHandler) {
                this.table.off("renderComplete", this._renderCompleteHandler);
                this._renderCompleteHandler = null;
            }
        }
    }

    injectColumnManagerUI() {
        if (!this.table) return;
        this._removeColumnManagerUI(); // clean slate

        this.table.getColumns().forEach(col => {
            const def = col.getDefinition();
            const field = col.getField();

            if (def.formatter === 'rowSelection' || field === '_id' || !field) return;

            const el = col.getElement();
            const titleHolder = el?.querySelector('.tabulator-col-title-holder');
            if (!titleHolder || titleHolder.querySelector('.col-mgr-wrap')) return;

            const wrap = document.createElement('div');
            wrap.className = 'col-mgr-wrap';
            wrap.style.cssText = 'display:flex;align-items:center;gap:3px;margin-right:4px;cursor:pointer;';

            const badge = document.createElement('span');
            badge.className = 'col-order-badge';
            badge.style.cssText = 'display:inline-block;border:1px solid #718096;color:#718096;border-radius:4px;width:18px;height:18px;font-size:11px;line-height:16px;text-align:center;flex-shrink:0;transition:all 0.2s;';
            badge.textContent = '+';

            wrap.onclick = (e) => {
                e.stopPropagation();
                this._onColToggle(field);
            };

            wrap.appendChild(badge);
            titleHolder.insertBefore(wrap, titleHolder.firstChild);
        });

        this._refreshOrderBadges();
    }

    _onColToggle(field) {
        const idx = this.selectedColumns.indexOf(field);
        if (idx === -1) {
            this.selectedColumns.push(field);
        } else {
            this.selectedColumns.splice(idx, 1);
        }
        this._refreshOrderBadges();
    }

    _refreshOrderBadges() {
        if (!this.table) return;
        this.table.getColumns().forEach(col => {
            const field = col.getField();
            const el = col.getElement();
            const badge = el?.querySelector('.col-order-badge');
            if (!badge) return;
            const rank = this.selectedColumns.indexOf(field);
            if (rank === -1) {
                badge.style.background = 'transparent';
                badge.style.color = '#718096';
                badge.style.borderColor = '#718096';
                badge.textContent = '+';
            } else {
                badge.style.background = '#4299e1';
                badge.style.color = '#fff';
                badge.style.borderColor = '#4299e1';
                badge.textContent = rank + 1;
            }
        });
    }

    _removeColumnManagerUI() {
        document.querySelectorAll('.col-mgr-wrap').forEach(el => el.remove());
    }

    clearSelectedColumns() {
        this.selectedColumns = [];
        this._refreshOrderBadges();
    }

    removeColumnManagerUI() {
        this._removeColumnManagerUI();
        this.selectedColumns = [];
        this.columnManagerActive = false;

        // Remove renderComplete listener to stop badge re-injection
        if (this.table && this._renderCompleteHandler) {
            this.table.off("renderComplete", this._renderCompleteHandler);
            this._renderCompleteHandler = null;
        }

        // Reset UI buttons
        const btn = document.getElementById('col-manager-btn');
        const actions = document.getElementById('col-manager-actions');
        if (btn) {
            btn.classList.remove('active-manager');
            btn.innerHTML = `Manage Cols <i class="fas fa-columns"></i>`;
        }
        if (actions) actions.style.display = 'none';

        // Show all hidden columns in a single redraw
        if (this.table) {
            this.table.blockRedraw();
            this.table.getColumns().forEach(col => {
                try { if (!col.isVisible()) col.show(); } catch (_) { }
            });
            this.table.restoreRedraw();
        }
    }

    toggleColumnSelection(colOrFilterFlag) {
        if (colOrFilterFlag === true) {
            this._filterToSelected();
        } else if (colOrFilterFlag) {
            const field = colOrFilterFlag.getField?.();
            if (!field) return;
            const idx = this.selectedColumns.indexOf(field);
            if (idx === -1) this.selectedColumns.push(field);
            else this.selectedColumns.splice(idx, 1);
            this._refreshOrderBadges();
        }
    }

    _filterToSelected() {
        if (!this.table || this.selectedColumns.length === 0) {
            alert('Selecciona columnas primero (usa los números en los encabezados).');
            return;
        }

        // Reorder: frozen cols first, then selected in badge order, then hide the rest
        const selected = this.selectedColumns;
        const allDefs = this.table.getColumnDefinitions();

        const frozenDefs = allDefs.filter(c =>
            c.formatter === 'rowSelection' || c.field === '_id'
        );
        const selectedDefs = selected
            .map(f => allDefs.find(c => c.field === f))
            .filter(Boolean);
        const otherDefs = allDefs.filter(c =>
            c.formatter !== 'rowSelection' &&
            c.field !== '_id' &&
            !selected.includes(c.field)
        );

        // Rebuild columns: frozen + selected + hidden rest
        const rebuiltDefs = [
            ...frozenDefs,
            ...selectedDefs,
            ...otherDefs.map(c => ({ ...c, visible: false }))
        ];
        this.table.setColumns(rebuiltDefs);

        setTimeout(() => {
            if (this.columnManagerActive) this.injectColumnManagerUI();
            this._refreshOrderBadges();
        }, 150);
    }

    moveSelectedColumns() {
        if (!this.table || this.selectedColumns.length === 0) {
            alert('Selecciona columnas primero (usa los checkboxes en los encabezados).');
            return;
        }

        const selected = this.selectedColumns;
        const allDefs = this.table.getColumnDefinitions();

        const frozenDefs = allDefs.filter(c =>
            c.formatter === 'rowSelection' || c.field === '_id'
        );
        const selectedDefs = selected
            .map(f => allDefs.find(c => c.field === f))
            .filter(Boolean);
        const otherDefs = allDefs.filter(c =>
            c.formatter !== 'rowSelection' &&
            c.field !== '_id' &&
            !selected.includes(c.field)
        );

        this.table.setColumns([...frozenDefs, ...selectedDefs, ...otherDefs]);

        setTimeout(() => {
            if (this.columnManagerActive) this.injectColumnManagerUI();
            this._refreshOrderBadges();
        }, 150);
    }
}
