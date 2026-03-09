"""
Chronos-DFIR Analyzer — Histogram and time-series analysis engine.
Generates chart data, trend analysis, and distribution breakdowns.
"""
import logging
import traceback
import re
import polars as pl
from engine.forensic import TIME_HIERARCHY, get_primary_time_column

logger = logging.getLogger("Chronos-DFIR")

# Shared: sentinel values to filter out of Top-N charts
_MEANINGLESS = {"null", "none", "n/a", "-", "", "nan", "undefined", "unknown", "0",
                "system", "(null)", "<null>", "not available"}
_PURE_NUMERIC = re.compile(r"^\d{1,5}$")

# Windows Event ID descriptions for enriched chart labels
_KNOWN_EVENT_IDS = {
    "1": "Process Create (Sysmon)",
    "2": "File Creation Time (Sysmon)",
    "3": "Network Connection (Sysmon)",
    "4": "Sysmon Service State",
    "5": "Process Terminated (Sysmon)",
    "6": "Driver Loaded (Sysmon)",
    "7": "Image Loaded (Sysmon)",
    "8": "CreateRemoteThread (Sysmon)",
    "10": "Process Access (Sysmon)",
    "11": "File Created (Sysmon)",
    "12": "Registry Event (Sysmon)",
    "13": "Registry Value Set (Sysmon)",
    "15": "FileCreateStreamHash (Sysmon)",
    "17": "Pipe Created (Sysmon)",
    "22": "DNS Query (Sysmon)",
    "23": "File Delete (Sysmon)",
    "25": "Process Tampering (Sysmon)",
    "26": "File Delete Logged (Sysmon)",
    "104": "System Log Cleared",
    "1024": "RDP Connection Attempt",
    "1025": "RDP Connection Success",
    "1026": "RDP Disconnection",
    "1102": "Security Log Cleared",
    "4104": "PowerShell ScriptBlock",
    "4624": "Logon Success",
    "4625": "Logon Failure",
    "4634": "Logoff",
    "4648": "Explicit Logon",
    "4656": "Object Handle Requested",
    "4662": "Directory Service Access",
    "4663": "Object Access Attempt",
    "4672": "Admin Privileges Assigned",
    "4673": "Privileged Service Called",
    "4688": "Process Created",
    "4689": "Process Terminated",
    "4697": "Service Installed",
    "4698": "Scheduled Task Created",
    "4699": "Scheduled Task Deleted",
    "4700": "Scheduled Task Enabled",
    "4702": "Scheduled Task Updated",
    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4724": "Password Reset Attempt",
    "4728": "Member Added to Global Group",
    "4732": "Member Added to Local Group",
    "4738": "User Account Changed",
    "4740": "Account Locked Out",
    "4756": "Member Added to Universal Group",
    "4768": "Kerberos TGT Requested",
    "4769": "Kerberos Service Ticket",
    "4771": "Kerberos Pre-Auth Failed",
    "4776": "NTLM Authentication",
    "4798": "User Local Group Enumerated",
    "4799": "Security Group Enumerated",
    "5136": "Directory Object Modified",
    "5140": "Network Share Accessed",
    "5145": "Network Share Check",
    "5156": "Firewall Connection Allowed",
    "5157": "Firewall Connection Blocked",
    "7036": "Service State Changed",
    "7040": "Service Start Type Changed",
    "7045": "New Service Installed",
    "8004": "NTLM Authentication (DC)",
    "11707": "Software Install Success",
    "11724": "Software Uninstall Success",
}

# Source column candidates for source distribution chart
_SOURCE_CANDIDATES = [
    "SourceName", "Provider", "Provider_Name", "ProviderName",
    "Computer", "ComputerName", "MachineName", "Hostname",
    "Channel", "LogName",
    "SubjectUserName", "TargetUserName", "User",
]

# Category column candidates (replaces "tactic" for non-MITRE data)
_CATEGORY_CANDIDATES = [
    "Chronos_Tactic", "MITRE_Tactic", "Tactic", "ViolationCategory",
    "ViolationType", "Protection", "EventName", "TaskCategory",
    "Category", "Title",
]


def _compute_top_distribution(lf, col_name, top_n=10, filter_numeric=False, enrich_event_ids=False):
    """Compute top-N distribution for a column. Returns {labels, values} or None."""
    try:
        schema_names = lf.collect_schema().names()
        if col_name not in schema_names:
            return None
        df = (lf
              .select(pl.col(col_name).cast(pl.Utf8, strict=False).alias("_val"))
              .filter(pl.col("_val").is_not_null() & (pl.col("_val").str.strip_chars() != ""))
              .group_by("_val").agg(pl.len().alias("count"))
              .sort("count", descending=True)
              .head(top_n * 2)
              .collect())
        if df.is_empty():
            return None
        labels, values = [], []
        for row in df.to_dicts():
            val = str(row["_val"]).strip()
            if val.lower() in _MEANINGLESS:
                continue
            if filter_numeric and _PURE_NUMERIC.match(val):
                continue
            # Enrich Event IDs with human-readable descriptions
            if enrich_event_ids:
                desc = _KNOWN_EVENT_IDS.get(val)
                label = f"{val} — {desc}" if desc else val
            else:
                label = val if len(val) <= 50 else val[:47] + "..."
            labels.append(label)
            values.append(row["count"])
            if len(labels) >= top_n:
                break
        return {"labels": labels, "values": values} if labels else None
    except Exception as e:
        logger.warning(f"Top distribution for {col_name} failed: {e}")
        return None


def _detect_columns(cols):
    """Detect standard forensic columns. Returns dict of detected column names."""
    detected = {}
    detected["level"] = next((c for c in cols if c.lower() in [
        'level', 'severity', 'riskscore', 'risk']), None)
    detected["eventid"] = next((c for c in cols if c.lower() in [
        'eventid', 'event_id', 'wineventid']), None)
    detected["process"] = next((c for c in cols if c.lower() in [
        'processname', 'image', 'process', 'newprocessname', 'parentimage',
        'sourceimage', 'targetimage', 'application']), None)
    detected["category"] = next((c for c in cols if c in _CATEGORY_CANDIDATES), None)
    detected["source"] = next((c for c in cols if c in _SOURCE_CANDIDATES), None)
    return detected


def _compute_non_temporal(df_source, cols, detected):
    """Generate chart data for files without timestamps (Top-N charts only)."""
    is_lazy = isinstance(df_source, pl.LazyFrame)
    lf = df_source if is_lazy else df_source.lazy()
    try:
        total = lf.select(pl.len()).collect().item()
    except Exception:
        total = 0

    distributions = _compute_distributions(lf, cols, detected, labels=None, bucketed_df=None, bucket=None)

    return {
        "labels": [], "datasets": [],
        "no_timeline": True,
        "interpretation": "No timeline available — showing frequency analysis.",
        "distributions": distributions,
        "stats": {"total_events": total, "eps": 0}
    }


def _compute_distributions(lf, cols, detected, labels=None, bucketed_df=None, bucket=None):
    """Compute all distribution charts from a LazyFrame."""
    distributions = {}
    eventid_col = detected.get("eventid")
    proc_col = detected.get("process")
    level_col = detected.get("level")
    category_col = detected.get("category")
    source_col = detected.get("source")

    schema_names = lf.collect_schema().names()

    # Category distribution (formerly "tactics" — now shows actual column data)
    if category_col and category_col in schema_names:
        try:
            cat_counts = lf.group_by(category_col).agg(pl.len().alias("count")).collect()
            raw = dict(zip(
                cat_counts[category_col].cast(pl.Utf8, strict=False).fill_null("N/A").to_list(),
                cat_counts["count"].to_list()
            ))
            # Filter meaningless entries
            filtered = {k: v for k, v in raw.items() if k.lower().strip() not in _MEANINGLESS}
            if filtered:
                distributions["categories"] = filtered
                distributions["category_column"] = category_col
        except Exception as _ce:
            logger.warning(f"Category distribution failed: {_ce}")

    # Source distribution (Computer, Provider, User, etc.)
    if source_col and source_col in schema_names:
        try:
            src_counts = lf.group_by(source_col).agg(pl.len().alias("count")).collect()
            raw = dict(zip(
                src_counts[source_col].cast(pl.Utf8, strict=False).fill_null("N/A").to_list(),
                src_counts["count"].to_list()
            ))
            filtered = {k: v for k, v in raw.items() if k.lower().strip() not in _MEANINGLESS}
            if filtered:
                distributions["sources"] = filtered
                distributions["source_column"] = source_col
        except Exception as _se:
            logger.warning(f"Source distribution failed: {_se}")

    # Severity distribution
    if level_col and level_col in schema_names:
        try:
            sev_counts = lf.group_by(level_col).agg(pl.len().alias("count")).collect()
            raw = dict(zip(
                sev_counts[level_col].cast(pl.Utf8, strict=False).fill_null("N/A").to_list(),
                sev_counts["count"].to_list()
            ))
            filtered = {k: v for k, v in raw.items() if k.lower().strip() not in _MEANINGLESS}
            if filtered:
                distributions["severity"] = filtered
        except Exception:
            pass

    # Top EventIDs with enriched labels
    if eventid_col:
        top_ev = _compute_top_distribution(lf, eventid_col, top_n=10, enrich_event_ids=True)
        if top_ev:
            distributions["top_events"] = top_ev

    # Top Processes
    if proc_col:
        top_proc = _compute_top_distribution(lf, proc_col, top_n=8, filter_numeric=True)
        if top_proc:
            distributions["top_processes"] = top_proc

    # Severity Over Time (stacked bar data) — only when timeline exists
    if level_col and level_col in schema_names and labels and bucketed_df is not None and bucket:
        try:
            sot_df = (lf
                      .with_columns(pl.col("ts").dt.truncate(bucket).alias("_bucket"))
                      .group_by(["_bucket", level_col])
                      .agg(pl.len().alias("cnt"))
                      .sort("_bucket")
                      .collect())
            bucket_labels = bucketed_df["_bucket"].to_list()
            sev_levels = sot_df[level_col].cast(pl.Utf8, strict=False).fill_null("N/A").unique().to_list()
            series = {}
            for lvl in sev_levels:
                lvl_data = sot_df.filter(pl.col(level_col).cast(pl.Utf8, strict=False).fill_null("N/A") == lvl)
                lvl_buckets = lvl_data["_bucket"].to_list()
                lvl_counts = lvl_data["cnt"].to_list()
                bucket_map = dict(zip(lvl_buckets, lvl_counts))
                series[lvl] = [bucket_map.get(b, 0) for b in bucket_labels]
            distributions["severity_over_time"] = {"labels": labels, "series": series}
        except Exception as _sot_e:
            logger.warning(f"Severity over time failed: {_sot_e}")

    # Auto-detect top column for files with few known columns
    if not distributions.get("top_events") and not distributions.get("top_processes"):
        # Find the most interesting column (highest cardinality but < total rows)
        for c in cols:
            if c.startswith("_") or c.lower() in {"no.", "no", "row_number"}:
                continue
            if c in schema_names:
                top = _compute_top_distribution(lf, c, top_n=10, filter_numeric=True)
                if top and len(top["labels"]) >= 3:
                    distributions["top_generic"] = top
                    distributions["top_generic_column"] = c
                    break

    # Smart Risk Engine
    try:
        from engine.forensic import calculate_smart_risk_m4
        smart_risk = calculate_smart_risk_m4(lf)
        distributions["smart_risk"] = smart_risk
    except Exception as sre_e:
        logger.warning(f"Smart Risk Engine failed: {sre_e}")

    return distributions


def analyze_dataframe(df_source, target_bars=50, start_time: str = None, end_time: str = None):
    """
    Optimized core function to generate advanced histogram data from a Polars LazyFrame or DataFrame.
    Returns dict with labels, datasets, trend, anomalies, top_talker, and stats.
    Executes aggregations lazily to minimize memory footprint.
    """
    try:
        is_lazy = isinstance(df_source, pl.LazyFrame)
        cols = df_source.collect_schema().names() if is_lazy else df_source.columns

        # Detect standard forensic columns
        detected = _detect_columns(cols)

        # 1. Parsing Time - Prioritized Search using Global Hierarchy
        existing_cols = set(cols)
        found_hierarchy = [c for c in TIME_HIERARCHY if c in existing_cols]
        if not found_hierarchy:
            found_hierarchy = [c for c in cols if any(h.lower() == c.lower() for h in TIME_HIERARCHY)]

        time_col = get_primary_time_column(cols)

        if not found_hierarchy and not time_col:
            logger.warning("No time column found. Computing non-temporal distributions.")
            return _compute_non_temporal(df_source, cols, detected)

        logger.info(f"Analyzing time context. Hierarchy found: {found_hierarchy}")

        # Optimization: Only select necessary columns
        keep_cols = list(set(found_hierarchy + ([time_col] if time_col else [])))
        for key in ["level", "eventid", "process", "category", "source"]:
            col = detected.get(key)
            if col:
                keep_cols.append(col)

        q_base = df_source.lazy().select(list(set(keep_cols)))

        # Prepare each potential time column for parsing and coalesce them
        parse_exprs = []
        for col_to_parse in keep_cols:
            c = pl.col(col_to_parse)
            c_str = c.cast(pl.Utf8)
            c_float = c.cast(pl.Float64, strict=False)
            c_int = c_float.cast(pl.Int64, strict=False)

            parse_exprs.append(
                pl.coalesce([
                    c_str.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                    c_str.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                    c_str.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                    c_str.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                    c_str.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                    c_str.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                    c_str.str.to_datetime("%Y-%m-%d", strict=False),
                    pl.when(c_int.is_not_null() & (c_int > 0) & (c_int < 30000000000))
                      .then(pl.from_epoch(c_int * 1000, time_unit="ms"))
                      .otherwise(None).cast(pl.Datetime, strict=False),
                    pl.when(c_int.is_not_null() & (c_int >= 30000000000) & (c_int < 30000000000000))
                      .then(pl.from_epoch(c_int, time_unit="ms"))
                      .otherwise(None).cast(pl.Datetime, strict=False),
                    pl.when(c_int.is_not_null() & (c_int >= 30000000000000))
                      .then(pl.from_epoch(c_int, time_unit="us"))
                      .otherwise(None).cast(pl.Datetime, strict=False),
                ])
            )

        q_parsed = q_base.with_columns(
            pl.coalesce(parse_exprs).alias("ts")
        ).filter(pl.col("ts").is_not_null())

        try:
            global_stats_df = q_parsed.select([
                pl.col("ts").min().alias("min_ts"),
                pl.col("ts").max().alias("max_ts"),
                pl.len().alias("count")
            ]).collect()

            file_min = global_stats_df[0, "min_ts"]
            file_max = global_stats_df[0, "max_ts"]
            file_total = global_stats_df[0, "count"]

        except Exception as e:
            logger.error(f"Date parsing aggregation failed: {e}")
            return {
                "labels": [], "datasets": [], "error": f"Failed to parse dates: {str(e)}",
                "stats": {"total_events": 0, "eps": 0}
            }

        if file_total == 0:
            return {
                "labels": [], "datasets": [], "error": "No parseable dates found in primary time column.",
                "stats": {"total_events": 0, "eps": 0}
            }

        # Apply Filtering
        q_filtered = q_parsed
        try:
            if start_time and start_time != "null":
                q_filtered = q_filtered.filter(pl.col("ts") >= pl.lit(start_time).str.to_datetime(strict=False))
            if end_time and end_time != "null":
                q_filtered = q_filtered.filter(pl.col("ts") <= pl.lit(end_time).str.to_datetime(strict=False))
        except Exception as e:
            logger.warning(f"Chart filter failed: {e}. Returning unfiltered.")
            q_filtered = q_parsed

        view_stats_df = q_filtered.select([
            pl.col("ts").min().alias("min_ts"),
            pl.col("ts").max().alias("max_ts"),
            pl.len().alias("count")
        ]).collect()

        view_min = view_stats_df[0, "min_ts"]
        view_max = view_stats_df[0, "max_ts"]
        view_total = view_stats_df[0, "count"]

        if view_total == 0:
            return {
                "labels": [], "datasets": [],
                "interpretation": "No data in selected time range (Try resetting zoom).",
                "stats": {
                    "total_events": 0,
                    "file_total": file_total,
                    "start_time": str(file_min), "end_time": str(file_max),
                    "file_start": file_min.isoformat() if file_min else None,
                    "file_end": file_max.isoformat() if file_max else None,
                    "eps": 0
                }
            }

        labels = []
        datasets = []
        interpretation = "Timeline chart generated."
        global_stats = {}
        top_talker_id = None
        top_talker_pct = 0.0
        duration = (view_max - view_min).total_seconds() if (view_min and view_max) else 0
        bucketed_df = None
        bucket = "1h"

        # Timeline Chart — Adaptive bucketing (DO NOT MODIFY — user confirmed this chart is good)
        try:
            if duration <= 0:
                bucket = "1h"
            elif duration < 3 * 3600:
                bucket = "5m"
            elif duration < 6 * 3600:
                bucket = "15m"
            elif duration < 12 * 3600:
                bucket = "30m"
            elif duration < 48 * 3600:
                bucket = "1h"
            elif duration < 7 * 86400:
                bucket = "6h"
            else:
                bucket = "1d"

            bucketed_df = q_filtered.with_columns(
                pl.col("ts").dt.truncate(bucket).alias("_bucket")
            ).group_by("_bucket").agg(
                pl.len().cast(pl.Int32).alias("cnt")
            ).sort("_bucket").collect()

            labels = bucketed_df["_bucket"].dt.to_string("%Y-%m-%d %H:%M").to_list()
            y_vals = bucketed_df["cnt"].to_list()
            datasets = [{"label": "Events", "data": y_vals}]

            if len(y_vals) > 1:
                mid = max(1, len(y_vals) // 2)
                avg_first = sum(y_vals[:mid]) / mid
                avg_second = sum(y_vals[mid:]) / max(1, len(y_vals) - mid)
                if avg_second > avg_first * 1.2:
                    interpretation = "Alza (Posible Ataque/Spike)"
                elif avg_second < avg_first * 0.8:
                    interpretation = "Baja (Mitigación/Inactividad)"
                else:
                    interpretation = "Estable"
        except Exception as e:
            logger.error(f"Timeline bucketing failed: {e}")
            traceback.print_exc()

        # All distributions via shared function
        distributions = _compute_distributions(
            q_filtered, cols, detected,
            labels=labels, bucketed_df=bucketed_df, bucket=bucket
        )

        return {
            "labels": labels,
            "datasets": datasets,
            "interpretation": interpretation,
            "stacked": True,
            "global_stats": global_stats,
            "noise_info": {
                "top_talker_id": top_talker_id,
                "percent": round(top_talker_pct * 100, 1)
            },
            "distributions": distributions,
            "stats": {
                "total_events": view_total,
                "file_total": file_total,
                "start_time": view_min.isoformat() if view_min else None,
                "end_time": view_max.isoformat() if view_max else None,
                "file_start": file_min.isoformat() if file_min else None,
                "file_end": file_max.isoformat() if file_max else None,
                "eps": round(view_total / duration, 2) if duration > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Analysis Error: {e}")
        traceback.print_exc()
        return {"error": str(e)}
