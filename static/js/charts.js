import ChronosState from './state.js?v=185';
import events from './events.js?v=185';

export class ChartManager {
    constructor() {
        this.charts = {
            timeline: null,
            tactic: null,
            severity: null
        };
        this.isLogScale = false;
        this.setupEventListeners();
    }

    setupEventListeners() {
        events.on('SESSION_UPDATED', ({ filename }) => {
            if (!filename) return;
            this.loadHistogram(filename, null, ChronosState.startTime, ChronosState.endTime, ChronosState.currentColumnFilters);
        });

        events.on('FILTERS_CHANGED', () => {
            if (ChronosState.currentFilename) {
                this.loadHistogram(ChronosState.currentFilename, null, ChronosState.startTime, ChronosState.endTime, ChronosState.currentColumnFilters);
            }
        });

        events.on('TIME_RANGE_CHANGED', () => {
            if (ChronosState.currentFilename) {
                this.loadHistogram(ChronosState.currentFilename, null, ChronosState.startTime, ChronosState.endTime, ChronosState.currentColumnFilters);
            }
        });

        // Debounced: selecting multiple rows fires per-row, avoid API flooding
        let _selDebounce = null;
        events.on('SELECTION_CHANGED', () => {
            clearTimeout(_selDebounce);
            _selDebounce = setTimeout(() => {
                if (ChronosState.currentFilename) {
                    this.loadHistogram(ChronosState.currentFilename, null, ChronosState.startTime, ChronosState.endTime, ChronosState.currentColumnFilters);
                }
            }, 400);
        });

        events.on('STATE_RESET', () => {
            Object.values(this.charts).forEach(c => { if (c) c.destroy(); });
            this.charts = { timeline: null, tactic: null, severity: null };
        });
    }

    init(logScaleToggleId) {
        const toggle = document.getElementById(logScaleToggleId);
        if (toggle) {
            toggle.addEventListener('change', (e) => {
                this.isLogScale = e.target.checked;
                // Re-render logic would go here or be triggered by main
            });
        }
    }

    renderTimeline(ctxId, data, interpretationId) {
        if (this.charts.timeline) this.charts.timeline.destroy();

        const ctx = document.getElementById(ctxId).getContext('2d');

        // --- Stats: prefer backend-computed values, fallback to local calc ---
        const rawData = data.datasets?.[0]?.data || [];
        const stats = data.stats || {};
        const mean = stats.mean ?? (rawData.length ? rawData.reduce((a, b) => a + b, 0) / rawData.length : 0);
        const peakVal = stats.peak ?? (rawData.length ? Math.max(...rawData) : 0);
        const peakIdx = rawData.indexOf(peakVal);
        const meanValue = Math.round(mean);

        // Build datasets: main bars
        const mainDs = data.datasets.map(ds => {
            const isBar = (ds.type !== 'line');
            return {
                ...ds,
                borderWidth: isBar ? 1 : 2,
                backgroundColor: rawData.map((v, i) => {
                    if (i === peakIdx) return 'rgba(229,62,62,0.85)'; // peak = red
                    if (v > mean * 1.5) return 'rgba(237,137,54,0.75)';   // above 1.5x mean = orange
                    return 'rgba(99,179,237,0.70)';                        // normal = blue
                }),
                borderColor: rawData.map((_, i) => i === peakIdx ? '#e53e3e' : '#4299e1'),
                pointRadius: 0,
                tension: 0.3
            };
        });

        // Mean reference line (dashed orange)
        const meanLineDs = {
            label: `Media: ${meanValue} ev`,
            data: new Array(rawData.length).fill(meanValue),
            type: 'line',
            borderColor: '#f6ad55',
            borderWidth: 2,
            // segment.borderDash is the Chart.js v3/v4 way to get dashed lines
            segment: { borderDash: [6, 4] },
            pointRadius: 0,
            tension: 0,
            fill: false,
            order: 0,
            yAxisID: 'y'
        };

        const datasets = rawData.length ? [...mainDs, meanLineDs] : mainDs;

        // Only use log scale when user explicitly toggles checkbox
        const useLogScale = this.isLogScale;
        // Detect when log scale would help (for suggestion in interpretation bar)
        const logSuggested = peakVal > 0 && mean > 0 && (peakVal / mean) > 4;

        this.charts.timeline = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                transitions: { active: { animation: { duration: 200 } } },
                scales: {
                    y: {
                        type: useLogScale ? 'logarithmic' : 'linear',
                        beginAtZero: !useLogScale,
                        min: useLogScale ? 1 : undefined,
                        grid: { color: 'rgba(255,255,255,0.08)' },
                        ticks: {
                            color: '#aaa',
                            callback: useLogScale
                                ? (v) => Number.isInteger(Math.log10(v)) ? v.toLocaleString() : null
                                : undefined
                        }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#aaa', maxRotation: 45, minRotation: 45 }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#eee', boxWidth: 12 }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            afterBody: (items) => {
                                const i = items?.[0]?.dataIndex;
                                if (i === peakIdx && peakVal > 0)
                                    return [`⚠ PICO: ${peakVal} eventos (${((peakVal / mean) * 100 - 100).toFixed(0)}% sobre media)`];
                                return [];
                            }
                        }
                    }
                }
            }
        });

        if (interpretationId) {
            const el = document.getElementById(interpretationId);
            if (el) {
                const peakLabel = data.labels?.[peakIdx] ?? 'N/A';
                const logNote = logSuggested ? ` &nbsp;|&nbsp; <span style="color:#a78bfa">💡 Pico ${Math.round(peakVal/mean)}x media — considera activar Log Scale</span>` : '';
                el.innerHTML =
                    `<b>Tendencia:</b> ${data.interpretation || '—'} &nbsp;|&nbsp; ` +
                    `<span style="color:#e53e3e"><b>⚠ Pico:</b> ${peakVal} ev @ ${peakLabel}</span> &nbsp;|&nbsp; ` +
                    `<span style="color:#f6ad55"><b>Media:</b> ${meanValue} ev/bucket</span>${logNote}`;
                el.style.display = 'block';
            }
        }
    }




    renderDistribution(ctxId, data, title) {
        if (this.charts[ctxId]) this.charts[ctxId].destroy();

        const canvas = document.getElementById(ctxId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        this.charts[ctxId] = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.labels,
                datasets: [{
                    data: data.values,
                    backgroundColor: [
                        '#00d4ff', '#0055ff', '#ff0055', '#ffaa00', '#00ffaa'
                    ]
                }]
            },
            options: {
                responsive: true,
                animation: { duration: 300 },
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#ccc' } }
                }
            }
        });
    }

    async loadHistogram(filename, excludeId = null, startTime = null, endTime = null, colFilters = {}) {
        const params = new URLSearchParams();
        if (excludeId) params.append('exclude_id', excludeId);
        if (startTime) params.append('start_time', startTime);
        if (endTime) params.append('end_time', endTime);
        // Send global search query so chart reflects the same filter as the grid
        const query = ChronosState.currentQuery;
        if (query) params.append('query', query);
        // col_filters can be an array (Tabulator headerFilters) or object
        if (colFilters) {
            const hasFilters = Array.isArray(colFilters) ? colFilters.length > 0 : Object.keys(colFilters).length > 0;
            if (hasFilters) params.append('col_filters', JSON.stringify(colFilters));
        }
        // Send selected_ids so chart reflects row selection
        const selectedIds = ChronosState.selectedIds || [];
        if (selectedIds.length > 0) {
            params.append('selected_ids', JSON.stringify(selectedIds));
        }

        try {
            const response = await fetch(`/api/histogram/${encodeURIComponent(filename)}?${params.toString()}`);
            if (!response.ok) throw new Error("Chart data fetch failed");
            const data = await response.json();

            this.updateWithData(data);
        } catch (err) {
            console.error("Error loading histogram:", err);
        }
    }

    async loadHistogramSubset(filename, selectedIds) {
        if (!filename || !selectedIds.length) return;

        try {
            const response = await fetch('/api/histogram_subset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename,
                    selected_ids: selectedIds,
                    query: ChronosState.currentQuery || "",
                    start_time: ChronosState.startTime || "",
                    end_time: ChronosState.endTime || "",
                    col_filters: JSON.stringify(ChronosState.currentColumnFilters || {})
                })
            });

            if (!response.ok) throw new Error("Subset data fetch failed");
            const data = await response.json();

            this.updateWithData(data);
        } catch (err) {
            console.error("Error loading subset histogram:", err);
            const interp = document.getElementById('chart-interpretation');
            if (interp) {
                interp.style.color = 'orange';
                interp.innerText = `Chart update failed: ${err.message}`;
            }
        }
    }

    updateWithData(data) {
        // --- Timeline Chart ---
        if (data.labels && data.datasets) {
            // Show the chart wrapper (hidden by default in CSS)
            const chartWrapper = document.getElementById('chart-wrapper');
            if (chartWrapper) chartWrapper.style.display = 'block';

            this.renderTimeline('timeline-chart', data, 'chart-interpretation');
        }

        // --- Distribution Charts ---
        if (data.distributions) {
            const hasDistributions = data.distributions.tactics || data.distributions.severity;
            if (hasDistributions) {
                const distRow = document.getElementById('distribution-row');
                if (distRow) distRow.style.display = 'flex';
            }
            if (data.distributions.tactics) {
                this.renderDistribution('tactic-chart', data.distributions.tactics, 'Tactic Distribution');
            }
            if (data.distributions.severity) {
                this.renderDistribution('severity-chart', data.distributions.severity, 'Severity Distribution');
            }
        }

        // --- Dashboard Stats ---
        const stats = data.stats || {};
        const fmt = (iso) => {
            if (!iso) return 'N/A';
            try { return new Date(iso).toLocaleString(); } catch { return iso; }
        };

        const timeRangeEl = document.getElementById('time-range-info');
        if (timeRangeEl) {
            const start = fmt(stats.start_time || stats.file_start);
            const end = fmt(stats.end_time || stats.file_end);
            timeRangeEl.textContent = `Time Range: ${start} → ${end}`;
        }

        const epsEl = document.getElementById('dash-eps');
        if (epsEl) {
            let epsVal = stats.eps != null ? stats.eps : 0;
            // Fallback: compute from timestamps if eps is 0 and we have time bounds
            if (!epsVal && stats.start_time && stats.end_time && stats.total_events > 0) {
                const durSec = (new Date(stats.end_time) - new Date(stats.start_time)) / 1000;
                if (durSec > 0) epsVal = (stats.total_events / durSec).toFixed(4);
            }
            epsEl.textContent = epsVal || '0';
        }


        // Top tactic from distributions
        const tacticEl = document.getElementById('dash-tactic');
        if (tacticEl && data.distributions?.tactics) {
            const sorted = Object.entries(data.distributions.tactics)
                .sort((a, b) => b[1] - a[1]);
            tacticEl.textContent = sorted.length ? sorted[0][0] : 'N/A';
        }

        // Risk level from smart risk engine or fallback to severity
        const riskEl = document.getElementById('dash-risk');
        if (riskEl) {
            if (data.distributions?.smart_risk) {
                const info = data.distributions.smart_risk;
                riskEl.textContent = info.Risk_Level;
                riskEl.style.color = info.UI_Color;
            } else if (data.distributions?.severity) {
                const entries = Object.entries(data.distributions.severity);
                const high = entries.filter(([k]) => /high|crit/i.test(k)).reduce((s, [, v]) => s + v, 0);
                const medium = entries.filter(([k]) => /med/i.test(k)).reduce((s, [, v]) => s + v, 0);

                if (high > 0) {
                    riskEl.textContent = 'High';
                    riskEl.style.color = '#ff4d4d';
                } else if (medium > 0) {
                    riskEl.textContent = 'Medium';
                    riskEl.style.color = '#f59e0b';
                } else {
                    riskEl.textContent = 'Low';
                    riskEl.style.color = '#00e676';
                }
            }
        }
    }


    downloadAsPNG(canvasId, filename) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const link = document.createElement('a');
        link.download = filename;
        link.href = canvas.toDataURL('image/png');
        link.click();
    }
}
