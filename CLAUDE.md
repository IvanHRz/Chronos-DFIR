# CLAUDE.md — Chronos-DFIR Operational Rules

## 1. Project Context

Chronos-DFIR is a forensic timeline explorer and DFIR analysis platform.
It ingests multi-format evidence (EVTX, CSV, MFT, Plist, XLSX), applies Sigma/YARA detection, and renders interactive timelines with risk-scored intelligence.

## 2. Tech Stack & Hardware Rules

| Layer | Technology | Constraint |
|-------|-----------|------------|
| Backend | Python 3.12+, FastAPI, uvicorn | Async-first, streaming I/O |
| Data Engine | Polars (vectorized), PyArrow | NEVER use Pandas. All transforms must be vectorized Polars expressions. |
| Frontend | Tabulator.js (virtual DOM), Chart.js | Minimize main-thread computation; push aggregations to backend |
| Detection | Sigma YAML, YARA rules | `rules/sigma/`, `rules/yara/` — standard format only |
| Target HW | Apple Silicon M4 | Use `scan_csv`/`sink_csv` for streaming. Optimize for ARM NEON/unified memory. |
| Exports | WeasyPrint, Playwright, xhtml2pdf | Multi-format: PDF, HTML standalone, CSV, XLSX, JSON |

**Hard rules:**
- All file I/O must use streaming (Polars `scan_*`/`sink_*`) for datasets > 50MB.
- Never block the event loop — use `asyncio.to_thread()` for CPU-bound Polars work.
- JS cache-bust: append `?v=XXX` to all static imports. Increment on every release.

## 3. Coding Standards (DFIR & Zimmerman Logic)

### Evidence Integrity (NON-NEGOTIABLE)
- **Never mutate original evidence metadata.** Timestamps, hex values (0x...), SIDs, and hashes must pass through unaltered.
- **Never fabricate timestamps.** If a parser lacks real FILETIME data, emit `null` — never `datetime.now()`.
- **Column `No.` is cosmetic** — renumbered on display, never used as a foreign key.

### Output Format Rules
- **CSV/XLSX exports** → flat tabular format, one row per event. No nesting.
- **JSON exports** → nested structure compatible with SOAR ingestion (Splunk SOAR, Cortex XSOAR).
- **Context/AI exports** → use `generate_export_payloads()` via `/api/forensic_report`.
- **CSV/Excel buttons** → always route to `/api/export_filtered` with `ai_optimized=False`.

### Code Quality
- No Pandas. No `iterrows()`. No Python-level loops over dataframes.
- Prefer `pl.Expr` chains over `apply()`/`map_elements()`.
- Sigma rules: standard YAML. No custom DSL.
- Backend functions in `app.py` are core — do NOT rewrite without explicit approval.
- Keep `app.py` under 2000 lines. Extract new parsers into `engine/`.

## 4. Multi-Agent Protocol

### Gemini CLI Coordination
Before writing new code or refactoring existing modules, **always read `GEMINI_CLI_CHANNEL.md`** to:
1. Check for pending Gemini audit findings or strategic recommendations.
2. Verify no conflicting implementation is in progress.
3. Align on architectural decisions flagged by Antigravity counter-audits.

### Agent Hierarchy
- **Claude (Architect)**: Design decisions, code implementation, rule authoring.
- **Gemini CLI (Engineer)**: QA audits, performance profiling, dependency review.
- **Antigravity (Auditor)**: Counter-audits, reality checks against reported state.

### Conflict Resolution
If Gemini reports "COMPLETE" but Antigravity flags issues → **Antigravity takes precedence**.
Always verify claims against actual source code, not skill heuristics or documentation.

### Session Continuity
- Consult `memory/MEMORY.md` at session start for project state.
- After major changes, update memory files to reflect new architecture decisions.

---

## 5. Engineering Retro — Claude (Architect)

### v177 Fixes Applied (2026-03-08)

**Bugs Fixed:**
1. **RARE EXECUTION PATHS: "None"** — `sub_analyze_identity_and_procs()` in `engine/forensic.py` was not filtering null/blank values before `group_by()`. Fixed: added `is_not_null()` + blank/sentinel filtering before aggregation.
2. **Column Manager state leak** — `removeColumnManagerUI()` did NOT reset `columnManagerActive`, did NOT remove `renderComplete` listener, did NOT hide action buttons. Result: after "Clear Selection", checkbox selection stopped working and badge injection persisted. Fixed: full state reset including flag, listener cleanup, and UI reset.
3. **toggleEmptyColumns() slow** — Each `col.hide()`/`col.show()` call triggered a full Tabulator re-render. For 50 empty columns = 50 re-renders. Fixed: wrapped with `blockRedraw()`/`restoreRedraw()` for single batch redraw.
4. **Chart ignoring filters** — `loadHistogram()` did not send global search `query` param. Also, `headerFilterChanged` event called `reload()` directly without emitting `FILTERS_CHANGED`, so chart never knew about column filter changes. Fixed both.
5. **Record counter showing total/total** — Backend only returned filtered count. Frontend showed "38,464 / 38,464" even with active filters. Fixed: backend now returns `total_unfiltered` alongside `total`.
6. **Tabulator sort params ignored** — Backend expected `sort_col`/`sort_dir` but Tabulator sends `sort[0][field]`/`sort[0][dir]`. Remote sort was silently broken. Fixed: data endpoint now parses Tabulator's format.
7. **Download file race condition** — `delete_file` ran immediately after response, risking deletion before browser download completed. Fixed: added 10s delay.

### Evaluation of Gemini/Antigravity Reports

**Gemini CLI** reports "COMPLETE" status — this is overly optimistic. The report describes what SHOULD be, not what IS. Example: claims GPU acceleration via CSS `will-change`/`content-visibility` but neither is implemented in actual stylesheets.

**Antigravity** correctly identifies:
1. **MFT `datetime.now()` timestamps** — VALID. This is a forensic integrity violation. Priority: HIGH for next sprint.
2. **CSS performance heuristics not implemented** — VALID. Will add `content-visibility: auto` to grid containers and `will-change: transform` to chart canvas.
3. **app.py monolith (2000+ lines)** — VALID but low-priority. Extracting parsers to engine modules is worthwhile but not blocking.
4. **Sigma engine partial** — VALID. `timeframe` and `count` conditions are not supported. This limits brute-force and beaconing detection.
5. **Frontend recalculating stats** — PARTIALLY VALID. Chart.js needs label arrays client-side, but peak/mean calculations should move to backend responses (already done in v177 for histogram).

**My priority ranking (next sprint):**
1. Fix remaining export bugs (PDF content rendering, filter propagation verification)
2. MFT timestamp integrity fix (forensic non-negotiable)
3. CSS performance hints (`content-visibility`, `will-change`)
4. Sigma temporal conditions (`timeframe`, `count`)
5. app.py decomposition (extract macOS parser, chart aggregation to engine/)

### v177 Critical Fix: `_id` Column (2026-03-08, post-retro)

**Root Cause of ALL Export Failures for EVTX files**: The `_id` column (required by Tabulator remote sort and `_apply_standard_processing()`) was only added in the `/api/data/{filename}` endpoint. Three other endpoints — `forensic_report`, `histogram`, and `split-zip` — called `_apply_standard_processing()` WITHOUT adding `_id` first. Since Tabulator sends `sort_col="_id"` as default, every processing call crashed with `ColumnNotFoundError`.

**Fixed in:** `app.py` — added `with_row_index(name="_id", offset=1)` to all three endpoints + defensive checks in `_apply_standard_processing()` for sort and selected_ids operations.

**Sigma Rules Expansion**: 15 new detection rules created (46 total). Coverage now includes: T1204, T1033, T1083, T1057, T1070.003, T1218, T1547.012, T1560, T1048, T1071, T1490, T1548.002, T1021.002, T1552, T1049.

### Evaluation of Gemini/Antigravity V3 Reports (2026-03-08)

**Gemini CLI v168 "Consolidation Report"** — Claims "The Great Decoupling" is done and the system is "Production-Ready". This is false:
- `app.py` remains at 2,108 lines — no meaningful extraction occurred.
- Claims "Vectorización Total" to Polars backend — but `app.py` still has pandas-style branching in main endpoints.
- Claims Sigma "v2" with complex conditions — but `sigma_engine.py` Line 12 explicitly defers temporal aggregation to v1.2.
- **Verdict**: Gemini continues to report the roadmap as if it were shipped code. Its reports are aspirational documentation, not engineering status.

**Antigravity V3 Audit** — Correct on all counts:
1. **app.py monolith (2,108 lines)** — VALID. `process_file` is ~400 lines of if/elif branching. Needs extraction.
2. **MFT `datetime.now()` fraud** — VALID. Still present. Blocks any forensic integrity certification.
3. **CSS GPU hints nonexistent** — VALID. Zero instances of `will-change` or `content-visibility` in any stylesheet.
4. **Sigma v2 is partial** — VALID. No `timeframe`, no `count > N`. Brute-force and beaconing detection impossible.

**Architectural Decision**: Antigravity's "Staging-Fragile" assessment is accurate. The system is functional for analyst workflow but NOT production-certified for forensic evidence submission. MFT fix is the gating item.

**Action Items (priority order):**
1. **[BLOCKED → RESOLVED]** Export failures — `_id` fix applied. Needs user verification.
2. **[NEXT]** MFT FILETIME struct parsing — replace `datetime.now()` with real `$STANDARD_INFORMATION` parsing or explicit `null`.
3. **[DONE v178]** CSS `content-visibility: auto` on `.tabulator`, `will-change: transform` on `#chart-wrapper`.
4. **[BACKLOG]** Sigma temporal conditions (`timeframe`, `count`).
5. **[BACKLOG]** app.py decomposition — extract `process_file` branching into `engine/ingestor.py`.

### v178 Fixes (2026-03-08)

**Bugs Fixed:**
1. **"0" appearing as TOP/RARE PROCESS** — `sub_analyze_identity_and_procs()` picked "Task" column (EVTX task category IDs) as proc_col. Fixed: removed "task" from primary proc_col candidates; added smart fallback that only uses "Task" if values contain paths/executables. Added regex filter to exclude pure numeric values (1-5 digits) from process statistics.
2. **TOP PROCESSES unfiltered** — Only RARE had null/sentinel filtering. Fixed: both TOP and RARE now use shared `_filter_meaningful()` function.

**Performance:**
3. **CSS GPU hints** — Added `content-visibility: auto` + `contain-intrinsic-size` to `.tabulator`, `will-change: transform` to `#chart-wrapper`.

**Sigma Rules:**
4. **Comprehensive rule expansion** — Creating 30+ new rules covering all forensic artifact categories (Prefetch, ShimCache, AmCache, UserAssist, SRUM, LNK, JumpLists, ShellBags, Browser, Linux, macOS).

### Evaluation of Antigravity V4 Report (2026-03-08)

**Antigravity V4** — "El Ingestor Fantasma" — Correct on all counts:
1. **`universal_ingestor.py` is orphaned** — VERIFIED. Zero imports in `app.py` or `app_logic.py`. Gemini created the file but never connected it. Dead code.
2. **MFT `datetime.now()` persists** — VERIFIED. Still unfixed.
3. **CSS GPU hints absent** — **NOW FIXED in v178**. Added `content-visibility: auto` and `will-change: transform`.
4. **Sigma v2 still partial** — VERIFIED. No `timeframe` support.
5. **`calculate_smart_risk_m4` is real** — CONFIRMED. Only genuine new functionality that Gemini-era actually shipped.

**Architectural Decision on `universal_ingestor.py`**: Do NOT integrate it yet. The current `process_file` in `app.py` works and has been field-tested. Integrating untested orphan code risks introducing regressions. When we do app.py decomposition, we'll evaluate whether to adopt, rewrite, or delete it.

### v179 Fixes (2026-03-08)

**Critical Fixes:**
1. **MFT `datetime.now()` fraud RESOLVED** — `mft_engine.py` completely rewritten. `_read_si_timestamps()` now parses real `$STANDARD_INFORMATION` attribute (type 0x10) FILETIME values from MFT binary records using `struct.unpack`. `win64_to_datetime()` was already implemented but never called — now it IS called. Verified with unit test producing correct datetime from FILETIME values. **This resolves Antigravity V3/V4/V5 Critical Finding #1.**

2. **Export download reliability** — Created `_triggerDownload()` helper in `actions.js` replacing all inline download code. All downloads (PDF, HTML, JSON blob, split-zip) now:
   - Set `window.isDownloading = true` (bypasses `beforeunload` guard)
   - Use offscreen `<a>` (`position: fixed; left: -9999px`) instead of `display: none`
   - Clean up with 3s timeout

3. **`exportData()` in main.js** — Same offscreen anchor pattern, extended `isDownloading` timeout from 2s to 4s.

4. **state.js duplicate `resetFilters`** — Two definitions existed (lines 62-65 overridden by 80-87). Removed the first (less complete) one that didn't emit `STATE_RESET`.

**Performance:**
5. **CSS `will-change` corrected** — Was on `#chart-wrapper` (has `display: none` by default = no-op). Moved to `#chart-wrapper canvas` (the actual Chart.js rendering element).
6. **charts.js backend stats preference** — `renderTimeline()` now uses `data.stats.mean` and `data.stats.peak` from backend instead of recalculating with `reduce()`/`Math.max()` client-side.

**Detection:**
7. **86 Sigma rules total** (46 pre-existing + 40 new). New coverage:
   - Windows artifacts: Prefetch, ShimCache, AmCache, UserAssist, SRUM, LNK/JumpLists, ShellBags, MRU, Recycle Bin
   - Linux: reverse shells, SSH brute force, sudo abuse, systemd persistence, cron, auditd, container escape
   - macOS: TCC bypass, Gatekeeper, XProtect, Authorization plugins
   - Browser: history manipulation, cookie theft, cache forensics
   - Network: DNS tunneling, proxy evasion, firewall manipulation

### Evaluation of Antigravity V5 Report (2026-03-08)

**Antigravity V5** — Line-by-line audit in `GEMINI_CLI_CHANNEL.md` (lines 191-337).

| Finding | Status | Notes |
|---------|--------|-------|
| MFT `datetime.now()` fraud | **FIXED v179** | Real FILETIME parsing from $STANDARD_INFORMATION |
| CSS `will-change` on wrong element | **FIXED v179** | Moved to canvas element |
| charts.js redundant calculations | **FIXED v179** | Uses backend stats |
| state.js duplicate resetFilters | **FIXED v179** | Removed first definition |
| Download reliability (isDownloading) | **FIXED v179** | `_triggerDownload()` helper |
| Pandas fallback in app.py process_file | **NOT FIXED** | 5 occurrences remain — needs extraction |
| Test suite is fake | **NOT FIXED** | No pytest, no asserts — needs rewrite |
| Sigma temporal conditions | **NOT FIXED** | `timeframe`/`count` still unsupported |
| app.py monolith (2118 lines) | **NOT FIXED** | Low priority — works but hard to maintain |
| `universal_ingestor.py` orphaned | **BY DESIGN** | Will evaluate during decomposition |

**Remaining priority (next sprint):**
1. User verification of v179 (Cmd+Shift+R to clear cache)
2. ~~Pandas fallback elimination in `process_file`~~ → DONE v180
3. Sigma temporal conditions (`timeframe`, `count`)
4. Test suite with pytest + httpx
5. ~~app.py decomposition~~ → DONE v180

### v180 Fixes (2026-03-08)

**Architectural Overhaul:**
1. **Pandas ELIMINATED from app.py** — 9 occurrences removed:
   - SQLite: `pd.read_sql_query()` → `cursor.fetchall()` + `pl.DataFrame()`
   - Plist: `pd.DataFrame()` → `_sanitize_plist_val()` + `pl.DataFrame(strict=False)`
   - Whitespace CSV (pslist/txt/log): `pd.read_csv(sep=r'\s+')` → `_read_whitespace_csv()` with `re.split()`
   - 4 dead `import pandas as pd` removed

2. **app.py decomposition: 2,160 → 1,528 lines (-29%)**:
   - `process_file` parsing logic (400 lines) → `engine/ingestor.py` (290 lines)
   - `analyze_dataframe` (268 lines) → `engine/analyzer.py` (220 lines)
   - `_read_whitespace_csv` helper → `engine/ingestor.py`
   - app.py now contains ONLY: FastAPI endpoints, middleware, routing

3. **New modules created**:
   - `engine/ingestor.py` — Multi-format file parser (CSV, XLSX, JSON, SQLite, Plist, PSList, TXT/LOG, ZIP, TSV, Parquet)
   - `engine/analyzer.py` — Histogram analysis, time-series bucketing, distribution calculations

**CLAUDE.md compliance post-v180:**
- "NEVER use Pandas" → ✅ 0 pandas in app.py (only `timeline_skill.py` legacy)
- "Keep `app.py` under 2000 lines" → ✅ 1,528 lines
- "Never fabricate timestamps" → ✅ Resolved v179
