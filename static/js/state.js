import events from './events.js?v=191';

/**
 * ChronosState - The Single Source of Truth for the application.
 * All state modifications should go through this object.
 */
const ChronosState = {
    // Session Data
    currentFilename: null,
    processedFiles: { csv: null, excel: null },

    // Data State
    rawData: [], // Reserved for local data mode if implemented
    currentQuery: "",
    currentColumnFilters: {},
    selectedIds: [],

    // UI Configuration
    startTime: "",
    endTime: "",
    visibleColumns: [],

    // Stats
    totalRecords: 0,
    filteredRecords: 0,

    /**
     * Update the current file session
     */
    setSession: function (filename, processed = { csv: null, excel: null }) {
        this.currentFilename = filename;
        this.processedFiles = processed;
        // Reset filters for new session context
        this.currentQuery = "";
        this.currentColumnFilters = {};
        this.startTime = "";
        this.endTime = "";
        events.emit('SESSION_UPDATED', { filename, processed });
    },

    /**
     * Update query and filters
     */
    updateFilters: function (query, colFilters) {
        this.currentQuery = query;
        this.currentColumnFilters = colFilters;
        events.emit('FILTERS_CHANGED', { query, colFilters });
    },

    /**
     * Update time range
     */
    setTimeRange: function (start, end) {
        this.startTime = start;
        this.endTime = end;
        events.emit('TIME_RANGE_CHANGED', { start, end });
    },

    /**
     * Update record counts
     */
    setCounts: function (total, filtered) {
        this.totalRecords = total;
        this.filteredRecords = filtered;
        events.emit('COUNTS_UPDATED', { total, filtered });
    },

    /**
     * Clear all active filters and time ranges
     */
    resetFilters: function () {
        this.currentQuery = "";
        this.currentColumnFilters = {};
        this.selectedIds = [];
        this.startTime = "";
        this.endTime = "";
        events.emit('FILTERS_CHANGED', { query: "", colFilters: {} });
        events.emit('TIME_RANGE_CHANGED', { start: "", end: "" });
    },

    /**
     * Reset the state to initial values
     */
    reset: function () {
        this.currentFilename = null;
        this.processedFiles = { csv: null, excel: null };
        this.currentQuery = "";
        this.currentColumnFilters = {};
        this.selectedIds = [];
        this.startTime = "";
        this.endTime = "";
        this.totalRecords = 0;
        this.filteredRecords = 0;
        events.emit('STATE_RESET');
    }
};

export default ChronosState;
