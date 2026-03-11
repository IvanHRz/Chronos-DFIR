import ChronosState from './state.js?v=202';
import events from './events.js?v=202';

export class ChartManager {
    constructor() {
        this.charts = {
            timeline: null,
            categories: null,
            sources: null,
            severity: null,
            topEvents: null,
            topProcesses: null,
            topGeneric: null,
            severityTime: null
        };
        this.isLogScale = false;
        // Read chart colors from CSS vars for consistency
        const _css = (v, fb) => getComputedStyle(document.documentElement).getPropertyValue(v).trim() || fb;
        this.C = {
            peak:      _css('--chart-peak', '#e53e3e'),
            aboveMean: _css('--chart-above-mean', '#f6ad55'),
            normal:    _css('--chart-normal', '#63b3ed'),
            meanLine:  _css('--chart-mean-line', 'rgba(246,173,85,0.7)'),
            sevCrit:   _css('--sev-critical', '#ef4444'),
            sevHigh:   _css('--sev-high', '#f97316'),
            sevMed:    _css('--sev-medium', '#eab308'),
            sevLow:    _css('--sev-low', '#22c55e'),
            sevInfo:   _css('--sev-info', '#3b82f6'),
            // UI colors for axes, labels, grids — pure white for readability
            grid:     'rgba(255,255,255,0.1)',
            tick:     '#ffffff',
            legend:   '#ffffff',
            title:    '#ffffff',
            subtitle: '#ffffff',
            surface:  _css('--bg-surface', '#1e293b'),
        };
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
            this.charts = { timeline: null, categories: null, sources: null, severity: null, topEvents: null, topProcesses: null, topGeneric: null, severityTime: null };
            for (const id of ['chart-wrapper', 'distribution-row', 'analytics-row', 'severity-time-wrapper']) {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            }
        });
    }

    init(logScaleToggleId) {
        const toggle = document.getElementById(logScaleToggleId);
        if (toggle) {
            toggle.addEventListener('change', (e) => {
                this.isLogScale = e.target.checked;
            });
        }
    }

    // -----------------------------------------------------------------------
    // Timeline — DO NOT MODIFY (user confirmed this chart is good)
    // -----------------------------------------------------------------------
    renderTimeline(ctxId, data, interpretationId) {
        if (this.charts.timeline) this.charts.timeline.destroy();

        const ctx = document.getElementById(ctxId).getContext('2d');

        const rawData = data.datasets?.[0]?.data || [];
        const stats = data.stats || {};
        const mean = stats.mean ?? (rawData.length ? rawData.reduce((a, b) => a + b, 0) / rawData.length : 0);
        const peakVal = stats.peak ?? (rawData.length ? Math.max(...rawData) : 0);
        const peakIdx = rawData.indexOf(peakVal);
        const meanValue = Math.round(mean);

        const mainDs = data.datasets.map(ds => {
            const isBar = (ds.type !== 'line');
            if (!isBar) return { ...ds, borderWidth: 2, pointRadius: 0, tension: 0.3 };
            return {
                ...ds,
                borderWidth: 1,
                backgroundColor: rawData.map((val, idx) => {
                    if (idx === peakIdx && peakVal > 0) return this.C.peak + 'dd';
                    if (val > mean && mean > 0) return this.C.aboveMean + 'cc';
                    return this.C.normal + 'b3';
                }),
                borderColor: rawData.map((val, idx) => {
                    if (idx === peakIdx && peakVal > 0) return this.C.peak;
                    if (val > mean && mean > 0) return this.C.aboveMean;
                    return this.C.normal;
                }),
                pointRadius: 0,
                tension: 0.3
            };
        });

        const meanLineDs = {
            label: `Mean: ${meanValue} events`,
            data: new Array(rawData.length).fill(meanValue),
            type: 'line',
            borderColor: this.C.meanLine,
            borderWidth: 2,
            segment: { borderDash: [6, 4] },
            pointRadius: 0,
            tension: 0,
            fill: false,
            order: 0,
            yAxisID: 'y'
        };

        const datasets = rawData.length ? [...mainDs, meanLineDs] : mainDs;
        const useLogScale = this.isLogScale;
        const logSuggested = peakVal > 0 && mean > 0 && (peakVal / mean) > 4;

        this.charts.timeline = new Chart(ctx, {
            type: 'bar',
            data: { labels: data.labels, datasets },
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
                        grid: { color: this.C.grid },
                        ticks: {
                            color: this.C.tick,
                            callback: useLogScale
                                ? (v) => Number.isInteger(Math.log10(v)) ? v.toLocaleString() : null
                                : undefined
                        }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: this.C.tick, maxRotation: 45, minRotation: 45 }
                    }
                },
                plugins: {
                    legend: { labels: { color: this.C.legend, boxWidth: 12 } },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            afterBody: (items) => {
                                const i = items?.[0]?.dataIndex;
                                if (i === peakIdx && peakVal > 0)
                                    return [`⚠ PEAK: ${peakVal} events (${((peakVal / mean) * 100 - 100).toFixed(0)}% above mean)`];
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
                const logNote = logSuggested ? ` &nbsp;|&nbsp; <span style="color:${this.C.sevInfo}">💡 Peak ${Math.round(peakVal/mean)}x mean — consider enabling Log Scale</span>` : '';
                el.innerHTML =
                    `<b>Trend:</b> ${data.interpretation || '—'} &nbsp;|&nbsp; ` +
                    `<span style="color:${this.C.peak}"><b>⚠ Peak:</b> ${peakVal} events @ ${peakLabel}</span> &nbsp;|&nbsp; ` +
                    `<span style="color:${this.C.aboveMean}"><b>Mean:</b> ${meanValue} events/bucket</span>${logNote}`;
                el.style.display = 'block';
            }
        }
    }

    // -----------------------------------------------------------------------
    // Doughnut Distribution — with title, center text, stats subtitle
    // -----------------------------------------------------------------------
    renderDistribution(chartKey, ctxId, data, title) {
        if (this.charts[chartKey]) this.charts[chartKey].destroy();
        const canvas = document.getElementById(ctxId);
        if (!canvas) return;

        // Unified format: always {labels, values, stats}
        let labels, values, uniqueCount = 0, coveragePct = 0;
        if (Array.isArray(data.labels)) {
            labels = data.labels;
            values = data.values;
            uniqueCount = data.unique_count || labels.length;
            coveragePct = data.coverage_pct || 0;
        } else {
            // Legacy dict format fallback
            const sorted = Object.entries(data)
                .filter(([k]) => !['total', 'unique_count', 'coverage_pct', 'labels', 'values'].includes(k))
                .sort((a, b) => b[1] - a[1]).slice(0, 10);
            labels = sorted.map(([k]) => k.length > 30 ? k.slice(0, 27) + '...' : k);
            values = sorted.map(([, v]) => v);
            uniqueCount = labels.length;
        }
        if (!labels.length) return;

        const total = values.reduce((a, b) => a + b, 0);
        const palette = [
            this.C.sevInfo, '#06b6d4', '#60a5fa', this.C.sevHigh, this.C.sevLow,
            '#14b8a6', this.C.sevMed, '#38bdf8', this.C.sevCrit, '#64748b'
        ];

        // Subtitle with stats
        const subtitle = uniqueCount > 0
            ? `${uniqueCount} unique values${coveragePct > 0 ? ` · ${coveragePct}% coverage` : ''}`
            : '';

        // Center text plugin (shows total in doughnut hole)
        const centerTextPlugin = {
            id: 'centerText',
            afterDraw(chart) {
                const { ctx: c, chartArea: { top, bottom, left, right } } = chart;
                const centerX = (left + right) / 2;
                const centerY = (top + bottom) / 2;
                c.save();
                c.font = 'bold 18px system-ui, sans-serif';
                c.fillStyle = chart.options._titleColor || '#e2e8f0';
                c.textAlign = 'center';
                c.textBaseline = 'middle';
                c.fillText(total.toLocaleString(), centerX, centerY - 8);
                c.font = '11px system-ui, sans-serif';
                c.fillStyle = chart.options._subtitleColor || '#94a3b8';
                c.fillText('events', centerX, centerY + 12);
                c.restore();
            }
        };

        this.charts[chartKey] = new Chart(canvas.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data: values,
                    backgroundColor: palette.slice(0, labels.length),
                    borderColor: this.C.surface,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                _titleColor: this.C.title,
                _subtitleColor: this.C.subtitle,
                cutout: '55%',
                plugins: {
                    title: {
                        display: true,
                        text: title,
                        color: this.C.title,
                        font: { size: 14, weight: 'bold' },
                        padding: { bottom: 2 }
                    },
                    subtitle: {
                        display: !!subtitle,
                        text: subtitle,
                        color: this.C.subtitle,
                        font: { size: 11, style: 'italic' },
                        padding: { bottom: 6 }
                    },
                    legend: {
                        position: 'right',
                        labels: {
                            color: this.C.legend, boxWidth: 10, padding: 5,
                            font: { size: 11 },
                            generateLabels: (chart) => {
                                const ds = chart.data.datasets[0];
                                return chart.data.labels.map((lbl, i) => {
                                    const val = ds.data[i];
                                    const pct = total > 0 ? ((val / total) * 100).toFixed(0) : 0;
                                    return {
                                        text: `${lbl} (${pct}%)`,
                                        fillStyle: ds.backgroundColor[i],
                                        strokeStyle: ds.borderColor,
                                        lineWidth: ds.borderWidth,
                                        index: i
                                    };
                                });
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => {
                                const pct = total > 0 ? ((ctx.raw / total) * 100).toFixed(1) : 0;
                                return ` ${ctx.label}: ${ctx.raw.toLocaleString()} (${pct}%)`;
                            }
                        }
                    }
                }
            },
            plugins: [centerTextPlugin]
        });
    }

    // -----------------------------------------------------------------------
    // Horizontal Bar — with title, stats subtitle, color-coded dominant bar
    // -----------------------------------------------------------------------
    renderHorizontalBar(chartKey, ctxId, data, title) {
        if (this.charts[chartKey]) this.charts[chartKey].destroy();
        const canvas = document.getElementById(ctxId);
        if (!canvas || !data?.labels?.length) return;

        const total = data.values.reduce((a, b) => a + b, 0);
        const maxVal = Math.max(...data.values);
        const uniqueCount = data.unique_count || data.labels.length;
        const coveragePct = data.coverage_pct || 0;

        // Color coding: dominant bar (>50% of shown) gets warm color
        const colors = data.values.map((v) => {
            const ratio = total > 0 ? v / total : 0;
            if (ratio > 0.5) return this.C.sevCrit + 'cc';
            if (ratio > 0.25) return this.C.sevHigh + 'cc';
            return this.C.sevInfo + 'bf';
        });
        const borderColors = data.values.map((v) => {
            const ratio = total > 0 ? v / total : 0;
            if (ratio > 0.5) return this.C.sevCrit;
            if (ratio > 0.25) return this.C.sevHigh;
            return this.C.sevInfo;
        });

        const subtitle = uniqueCount > 0
            ? `Top ${data.labels.length} of ${uniqueCount} unique${coveragePct > 0 ? ` · ${coveragePct}% coverage` : ''}`
            : '';

        // Custom plugin: draw value labels on bars (GoAccess style)
        const barValueLabels = {
            id: 'barValueLabels',
            afterDatasetsDraw(chart) {
                const { ctx } = chart;
                chart.data.datasets.forEach((ds, dsIdx) => {
                    const meta = chart.getDatasetMeta(dsIdx);
                    meta.data.forEach((bar, i) => {
                        const val = ds.data[i];
                        const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0';
                        const label = val >= 1000 ? `${(val/1000).toFixed(1)}k (${pct}%)` : `${val.toLocaleString()} (${pct}%)`;
                        ctx.save();
                        ctx.fillStyle = chart.options._labelColor || '#e2e8f0';
                        ctx.font = '10px Inter, sans-serif';
                        ctx.textAlign = 'left';
                        ctx.textBaseline = 'middle';
                        const x = bar.x + 6;
                        const y = bar.y;
                        // Only draw if bar is wide enough to show label outside
                        if (x < chart.chartArea.right - 10) {
                            ctx.fillText(label, x, y);
                        }
                        ctx.restore();
                    });
                });
            }
        };

        this.charts[chartKey] = new Chart(canvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [{
                    label: title || 'Count',
                    data: data.values,
                    backgroundColor: colors,
                    borderColor: borderColors,
                    borderWidth: 1,
                    borderRadius: 4,
                    barPercentage: 0.8
                }]
            },
            plugins: [barValueLabels],
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: this.C.grid },
                        ticks: {
                            color: this.C.tick,
                            callback: (v) => v >= 1000 ? (v/1000).toFixed(0) + 'k' : v
                        }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: this.C.legend, font: { size: 11 } }
                    }
                },
                _labelColor: this.C.title,
                plugins: {
                    title: {
                        display: true,
                        text: title,
                        color: this.C.title,
                        font: { size: 14, weight: 'bold' },
                        padding: { bottom: 2 }
                    },
                    subtitle: {
                        display: !!subtitle,
                        text: subtitle,
                        color: this.C.subtitle,
                        font: { size: 11, style: 'italic' },
                        padding: { bottom: 6 }
                    },
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => {
                                const pct = total > 0 ? ((ctx.raw / total) * 100).toFixed(1) : 0;
                                return `${ctx.raw.toLocaleString()} events (${pct}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Stacked Severity Over Time
    // -----------------------------------------------------------------------
    renderStackedTimeline(ctxId, data) {
        if (this.charts.severityTime) this.charts.severityTime.destroy();
        const canvas = document.getElementById(ctxId);
        if (!canvas || !data?.labels?.length || !data?.series) return;

        const sevColors = {
            'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308',
            'low': '#22c55e', 'informational': '#64748b', 'info': '#64748b'
        };
        const defaultColors = ['#60a5fa', '#06b6d4', '#14b8a6', '#84cc16', '#f43f5e'];
        let colorIdx = 0;

        const datasets = Object.entries(data.series).map(([level, counts]) => {
            const key = level.toLowerCase();
            const color = sevColors[key] || defaultColors[colorIdx++ % defaultColors.length];
            return {
                label: level,
                data: counts,
                backgroundColor: color + 'cc',
                borderColor: color,
                borderWidth: 1
            };
        });

        this.charts.severityTime = new Chart(canvas.getContext('2d'), {
            type: 'bar',
            data: { labels: data.labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                scales: {
                    x: {
                        stacked: true,
                        grid: { display: false },
                        ticks: { color: this.C.tick, maxRotation: 45, minRotation: 45 }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        grid: { color: this.C.grid },
                        ticks: { color: this.C.tick }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Severity Over Time',
                        color: this.C.title,
                        font: { size: 14, weight: 'bold' }
                    },
                    legend: {
                        position: 'top',
                        labels: { color: this.C.legend, boxWidth: 12, padding: 8 }
                    },
                    tooltip: { mode: 'index', intersect: false }
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Data Loading
    // -----------------------------------------------------------------------
    async loadHistogram(filename, excludeId = null, startTime = null, endTime = null, colFilters = {}) {
        const params = new URLSearchParams();
        if (excludeId) params.append('exclude_id', excludeId);
        if (startTime) params.append('start_time', startTime);
        if (endTime) params.append('end_time', endTime);
        const query = ChronosState.currentQuery;
        if (query) params.append('query', query);
        if (colFilters) {
            const hasFilters = Array.isArray(colFilters) ? colFilters.length > 0 : Object.keys(colFilters).length > 0;
            if (hasFilters) params.append('col_filters', JSON.stringify(colFilters));
        }
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

    // -----------------------------------------------------------------------
    // Main orchestrator
    // -----------------------------------------------------------------------
    updateWithData(data) {
        const isNoTimeline = data.no_timeline === true;

        // --- Timeline Chart ---
        if (!isNoTimeline && data.labels?.length && data.datasets) {
            const chartWrapper = document.getElementById('chart-wrapper');
            if (chartWrapper) chartWrapper.style.display = 'block';
            this.renderTimeline('timeline-chart', data, 'chart-interpretation');
        } else {
            const chartWrapper = document.getElementById('chart-wrapper');
            if (chartWrapper) chartWrapper.style.display = 'none';
            if (isNoTimeline) {
                const interp = document.getElementById('chart-interpretation');
                if (interp) {
                    interp.innerHTML = '<b>No timeline available</b> — showing frequency analysis charts.';
                    interp.style.display = 'block';
                }
            }
        }

        // --- Distribution Charts (Doughnuts) ---
        if (data.distributions) {
            const dist = data.distributions;
            const hasDoughnuts = dist.categories || dist.sources || dist.severity;
            if (hasDoughnuts) {
                const distRow = document.getElementById('distribution-row');
                if (distRow) distRow.style.display = 'flex';
            }

            const catTitle = dist.category_column || 'Event Categories';
            if (dist.categories) {
                this.renderDistribution('categories', 'category-chart', dist.categories, catTitle);
            }

            const srcTitle = dist.source_column || 'Sources';
            if (dist.sources) {
                this.renderDistribution('sources', 'source-chart', dist.sources, srcTitle);
            }

            if (dist.severity && !dist.categories && !dist.sources) {
                this.renderDistribution('severity', 'category-chart', dist.severity, 'Severity');
            }

            // --- Top EventIDs (horizontal bar) ---
            if (dist.top_events) {
                const row = document.getElementById('analytics-row');
                if (row) row.style.display = 'flex';
                const evTitle = dist.top_events.chart_title || 'Top Event IDs';
                this.renderHorizontalBar('topEvents', 'top-events-chart',
                    dist.top_events, evTitle);
            }

            // --- Top Processes (horizontal bar) ---
            if (dist.top_processes) {
                const row = document.getElementById('analytics-row');
                if (row) row.style.display = 'flex';
                const procTitle = dist.top_processes.chart_title || 'Top Processes';
                this.renderHorizontalBar('topProcesses', 'top-processes-chart',
                    dist.top_processes, procTitle);
            }

            // --- Top Generic (fallback) ---
            if (dist.top_generic && !dist.top_events && !dist.top_processes) {
                const row = document.getElementById('analytics-row');
                if (row) row.style.display = 'flex';
                const genTitle = dist.top_generic_column || 'Top Values';
                this.renderHorizontalBar('topGeneric', 'top-events-chart',
                    dist.top_generic, genTitle);
            }

            // --- Severity Over Time (stacked bar) ---
            if (!isNoTimeline && dist.severity_over_time) {
                const wrapper = document.getElementById('severity-time-wrapper');
                if (wrapper) wrapper.style.display = 'block';
                this.renderStackedTimeline('severity-time-chart', dist.severity_over_time);
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
            if (!epsVal && stats.start_time && stats.end_time && stats.total_events > 0) {
                const durSec = (new Date(stats.end_time) - new Date(stats.start_time)) / 1000;
                if (durSec > 0) epsVal = (stats.total_events / durSec).toFixed(4);
            }
            epsEl.textContent = epsVal || '0';
        }

        // Top category from distributions — show with count
        const tacticEl = document.getElementById('dash-tactic');
        if (tacticEl) {
            const catData = data.distributions?.categories || data.distributions?.severity;
            if (catData) {
                const labs = catData.labels || Object.keys(catData);
                const vals = catData.values || Object.values(catData);
                if (labs.length) {
                    // Find max
                    let maxIdx = 0;
                    for (let i = 1; i < vals.length; i++) {
                        if (vals[i] > vals[maxIdx]) maxIdx = i;
                    }
                    const topName = labs[maxIdx];
                    const topCount = vals[maxIdx];
                    tacticEl.textContent = `${topName} (${topCount.toLocaleString()})`;
                } else {
                    tacticEl.textContent = 'N/A';
                }
            }
        }

        // Risk level from smart risk engine or fallback to severity
        const riskEl = document.getElementById('dash-risk');
        if (riskEl) {
            if (data.distributions?.smart_risk) {
                const info = data.distributions.smart_risk;
                riskEl.textContent = info.Risk_Level;
                riskEl.style.color = info.UI_Color;
            } else if (data.distributions?.severity) {
                const sev = data.distributions.severity;
                const sevVals = sev.labels ? Object.fromEntries(sev.labels.map((l, i) => [l, sev.values[i]])) : sev;
                const entries = Object.entries(sevVals);
                const high = entries.filter(([k]) => /high|crit/i.test(k)).reduce((s, [, v]) => s + v, 0);
                const medium = entries.filter(([k]) => /med/i.test(k)).reduce((s, [, v]) => s + v, 0);
                if (high > 0) {
                    riskEl.textContent = 'High';
                    riskEl.style.color = this.C.sevCrit;
                } else if (medium > 0) {
                    riskEl.textContent = 'Medium';
                    riskEl.style.color = this.C.sevHigh;
                } else {
                    riskEl.textContent = 'Low';
                    riskEl.style.color = this.C.sevLow;
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
