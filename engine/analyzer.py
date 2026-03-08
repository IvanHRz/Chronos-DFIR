"""
Chronos-DFIR Analyzer — Histogram and time-series analysis engine.
Generates chart data, trend analysis, and distribution breakdowns.
"""
import logging
import traceback
import polars as pl
from engine.forensic import TIME_HIERARCHY, get_primary_time_column

logger = logging.getLogger("Chronos-DFIR")


def analyze_dataframe(df_source, target_bars=50, start_time: str = None, end_time: str = None):
    """
    Optimized core function to generate advanced histogram data from a Polars LazyFrame or DataFrame.
    Returns dict with labels, datasets, trend, anomalies, top_talker, and stats.
    Executes aggregations lazily to minimize memory footprint.
    """
    try:
        is_lazy = isinstance(df_source, pl.LazyFrame)
        cols = df_source.collect_schema().names() if is_lazy else df_source.columns

        # 1. Parsing Time - Prioritized Search using Global Hierarchy
        existing_cols = set(cols)
        found_hierarchy = [c for c in TIME_HIERARCHY if c in existing_cols]
        if not found_hierarchy:
            found_hierarchy = [c for c in cols if any(h.lower() == c.lower() for h in TIME_HIERARCHY)]

        time_col = get_primary_time_column(cols)

        if not found_hierarchy and not time_col:
            logger.error(f"No time column found. Available columns: {cols}")
            return {
                "labels": [], "datasets": [], "error": f"No valid time column found. Available: {cols[:5]}...",
                "stats": {"total_events": 0, "eps": 0}
            }

        logger.info(f"Analyzing time context. Hierarchy found: {found_hierarchy}")

        # Optimization: Only select necessary columns
        keep_cols = list(set(found_hierarchy + ([time_col] if time_col else [])))
        level_col = next((c for c in cols if c.lower() in ['level', 'severity', 'riskscore', 'risk']), None)
        if level_col:
            keep_cols.append(level_col)
        eventid_col = next((c for c in cols if c.lower() in ['eventid', 'event_id', 'wineventid']), None)
        if eventid_col:
            keep_cols.append(eventid_col)

        tactic_candidates = ["Chronos_Tactic", "MITRE_Tactic", "Tactic", "ViolationCategory",
                             "ViolationType", "Protection", "Title", "EventName", "TaskCategory", "Category"]
        _tactic_col_source = next((c for c in cols if c in tactic_candidates), None)
        if _tactic_col_source:
            keep_cols.append(_tactic_col_source)

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
            ]).collect(streaming=True)

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
        ]).collect(streaming=True)

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

        # Timeline Chart — Adaptive bucketing
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
            ).sort("_bucket").collect(streaming=True)

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

        # Tactic & Severity Distribution
        distributions = {}
        _tactic_col = next((c for c in q_filtered.collect_schema().names() if c in tactic_candidates), None)

        if _tactic_col:
            try:
                tactic_counts = q_filtered.group_by(_tactic_col).agg(pl.len().alias("count")).collect(streaming=True)
                distributions["tactics"] = dict(zip(
                    tactic_counts[_tactic_col].cast(pl.Utf8, strict=False).to_list(),
                    tactic_counts["count"].to_list()
                ))
            except Exception as _te:
                logger.warning(f"Tactics distribution failed: {_te}")

        if level_col and level_col in q_filtered.collect_schema().names():
            sev_counts = q_filtered.group_by(level_col).agg(pl.len().alias("count")).collect(streaming=True)
            distributions["severity"] = dict(zip(
                sev_counts[level_col].cast(pl.Utf8, strict=False).fill_null("N/A").to_list(),
                sev_counts["count"].to_list()
            ))

        # Smart Risk Engine
        try:
            from engine.forensic import calculate_smart_risk_m4
            smart_risk = calculate_smart_risk_m4(q_filtered)
            distributions["smart_risk"] = smart_risk
        except Exception as sre_e:
            logger.warning(f"Smart Risk Engine failed: {sre_e}")

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
