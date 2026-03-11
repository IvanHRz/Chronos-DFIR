"""
Chronos-DFIR Sigma Engine — Dynamic YAML-to-Polars Rule Evaluator
==================================================================
Translates Sigma YAML detection rules into Polars LazyFrame expressions
and evaluates them against forensic DataFrames at analysis time.

SCOPE (v1.2):
  IN:  field|contains, |endswith, |startswith, |any, |all, |not
       EventID list matching (is_in)
       Boolean conditions: and / or between named detection blocks
       Metadata extraction: title, level, tags, custom fields
       Temporal correlation: timeframe + correlation (event_count, group-by, gte)
       Custom aggregation: aggregation block (group_by, time_window, threshold)
  OUT: near queries, base64offset, cidr modifiers

Author: Chronos-DFIR / Ivan Huerta
"""
import os
import re
import glob
import logging
import functools
import operator
from typing import Optional

import polars as pl

logger = logging.getLogger("chronos.sigma_engine")

# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------
_RULES_CACHE: Optional[list] = None

def _get_rules_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", "rules", "sigma")


def load_sigma_rules(rules_dir: Optional[str] = None, force_reload: bool = False) -> list:
    """
    Walk the rules/sigma directory and return all parsed YAML rules.
    Results are cached in-process after first load.
    """
    global _RULES_CACHE
    if _RULES_CACHE is not None and not force_reload:
        return _RULES_CACHE

    try:
        import yaml  # PyYAML
    except ImportError:
        logger.warning("PyYAML not installed — Sigma engine disabled. Run: pip install pyyaml")
        _RULES_CACHE = []
        return []

    base = rules_dir or _get_rules_dir()
    patterns = [
        os.path.join(base, "**", "*.yml"),
        os.path.join(base, "**", "*.yaml"),
    ]

    rules = []
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    doc = yaml.safe_load(fh)
                if not isinstance(doc, dict):
                    continue
                doc["_path"] = path
                rules.append(doc)
            except Exception as exc:
                logger.debug(f"Could not load sigma rule {path}: {exc}")

    logger.info(f"Sigma Engine: loaded {len(rules)} rules from {base}")
    _RULES_CACHE = rules
    return rules


# ---------------------------------------------------------------------------
# Expression builders
# ---------------------------------------------------------------------------

def _field_expr(col_name: str, columns: list[str]) -> Optional[pl.Expr]:
    """
    Case-insensitive column lookup.  Returns None if not found.
    Also handles dot-notation (e.g. 'EventData.CommandLine') by trying the
    last segment as a fallback.
    """
    # Exact match first
    for c in columns:
        if c.lower() == col_name.lower():
            return pl.col(c).cast(pl.Utf8, strict=False)

    # Dot-notation fallback: "EventData.CommandLine" → "CommandLine"
    last_part = col_name.rsplit(".", 1)[-1]
    for c in columns:
        if c.lower() == last_part.lower():
            return pl.col(c).cast(pl.Utf8, strict=False)

    return None


def _apply_modifier(expr: pl.Expr, modifier: str, values) -> pl.Expr:
    """
    Apply a single Sigma modifier to a Polars string expression.
    values: str | list[str]
    """
    if isinstance(values, str):
        values = [values]
    values = [str(v) for v in values if v is not None]

    if not values:
        return pl.lit(False)

    mod = modifier.lower()

    if mod == "contains":
        return functools.reduce(operator.or_, [expr.str.contains(v, literal=True) for v in values])
    if mod == "contains|any":
        return functools.reduce(operator.or_, [expr.str.contains(v, literal=True) for v in values])
    if mod == "contains|all":
        return functools.reduce(operator.and_, [expr.str.contains(v, literal=True) for v in values])
    if mod in ("endswith", "endswith|any"):
        return functools.reduce(operator.or_, [expr.str.ends_with(v) for v in values])
    if mod == "endswith|all":
        return functools.reduce(operator.and_, [expr.str.ends_with(v) for v in values])
    if mod in ("startswith", "startswith|any"):
        return functools.reduce(operator.or_, [expr.str.starts_with(v) for v in values])
    if mod == "startswith|all":
        return functools.reduce(operator.and_, [expr.str.starts_with(v) for v in values])
    if mod == "re":
        return functools.reduce(operator.or_, [expr.str.contains(v, literal=False) for v in values])

    # Plain equality / list match
    return expr.is_in(values)


def _build_field_condition(field_raw: str, values, columns: list[str]) -> Optional[pl.Expr]:
    """
    Parse a Sigma field spec like 'Image|endswith|any' into a Polars expression.
    Handles:
      - plain field  (exact match / list)
      - field|modifier
      - field|not|modifier  (negation)
    """
    parts = field_raw.split("|")
    field_name = parts[0]
    modifiers = [p.lower() for p in parts[1:]]

    negate = "not" in modifiers
    mods_clean = [m for m in modifiers if m != "not"]
    modifier = "|".join(mods_clean) if mods_clean else ""

    col_expr = _field_expr(field_name, columns)
    if col_expr is None:
        return None  # Column not present in this dataset — skip silently

    if isinstance(values, list):
        vals = [str(v) for v in values if v is not None]
    else:
        vals = [str(values)] if values is not None else []

    if not vals:
        return None

    if modifier == "":
        # Plain value(s) — treat as is_in or equality
        expr = col_expr.is_in(vals)
    else:
        expr = _apply_modifier(col_expr, modifier, vals)

    return (~expr) if negate else expr


def _build_named_condition(named_block: dict, columns: list[str]) -> Optional[pl.Expr]:
    """
    Convert a named detection block (dict of field: value pairs) into a Polars AND expression.
    All field conditions within a named block are implicitly AND-ed.
    """
    sub_exprs = []
    for field_raw, values in named_block.items():
        if field_raw.startswith("EventID") or field_raw.lower() in ("eventid", "wineventid", "event_id"):
            # Special handling: EventID as integer-string list
            col_expr = _field_expr(field_raw, columns)
            if col_expr is None:
                # Try common aliases
                for alias in ["EventID", "WinEventId", "EventId", "event_id", "Id", "id"]:
                    col_expr = _field_expr(alias, columns)
                    if col_expr is not None:
                        break
            if col_expr is not None:
                vals = [str(v) for v in (values if isinstance(values, list) else [values]) if v is not None]
                # Strip trailing .0 from float-parsed IDs
                clean_col = col_expr.str.replace(r"\.0$", "", literal=False)
                sub_exprs.append(clean_col.is_in(vals))
            continue

        cond = _build_field_condition(field_raw, values, columns)
        if cond is not None:
            sub_exprs.append(cond)

    if not sub_exprs:
        return None
    return functools.reduce(operator.and_, sub_exprs)


def _parse_condition_string(condition_str: str, named_exprs: dict[str, Optional[pl.Expr]]) -> Optional[pl.Expr]:
    """
    Parse Sigma condition string: "a or b", "a and b", "all of them",
    "1 of named_*", etc. into a single Polars expression.
    Only handles AND / OR chains for MVP scope.
    """
    cond = condition_str.strip()

    # "all of them" — OR of all named conditions
    if re.fullmatch(r"all\s+of\s+them", cond, re.IGNORECASE):
        exprs = [e for e in named_exprs.values() if e is not None]
        return functools.reduce(operator.and_, exprs) if exprs else None

    # "1 of them" or "any of them"
    if re.fullmatch(r"(?:1|any)\s+of\s+them", cond, re.IGNORECASE):
        exprs = [e for e in named_exprs.values() if e is not None]
        return functools.reduce(operator.or_, exprs) if exprs else None

    # "1 of name_*" wildcard
    m = re.fullmatch(r"(?:\d+|any|all)\s+of\s+([\w\*]+)", cond, re.IGNORECASE)
    if m:
        pattern = m.group(1).replace("*", ".*")
        matched = [e for k, e in named_exprs.items() if re.fullmatch(pattern, k) and e is not None]
        if not matched:
            return None
        op = operator.and_ if cond.lower().startswith("all") else operator.or_
        return functools.reduce(op, matched)

    # Tokenize AND / OR — split on ' or ' and ' and '
    # We do OR first (lowest precedence), then AND
    def _resolve_token(tok: str) -> Optional[pl.Expr]:
        tok = tok.strip()
        neg = tok.startswith("not ")
        if neg:
            tok = tok[4:].strip()
        e = named_exprs.get(tok)
        if e is None:
            return None
        return (~e) if neg else e

    # Split on ' or ' first
    or_parts = re.split(r'\bor\b', cond, flags=re.IGNORECASE)
    or_exprs = []
    for or_part in or_parts:
        # Within each OR segment, split on ' and '
        and_parts = re.split(r'\band\b', or_part, flags=re.IGNORECASE)
        and_exprs = [_resolve_token(p) for p in and_parts]
        and_exprs = [e for e in and_exprs if e is not None]
        if and_exprs:
            or_exprs.append(functools.reduce(operator.and_, and_exprs))

    if not or_exprs:
        return None
    return functools.reduce(operator.or_, or_exprs)


# ---------------------------------------------------------------------------
# Temporal correlation helpers
# ---------------------------------------------------------------------------

def _parse_timeframe(tf_str: str) -> Optional[str]:
    """Parse Sigma timeframe string (e.g. '5m', '1h', '60s') into Polars duration string."""
    if not tf_str or not isinstance(tf_str, str):
        return None
    tf = tf_str.strip().lower()
    m = re.fullmatch(r"(\d+)\s*(s|m|h|d)", tf)
    if not m:
        return None
    val, unit = m.group(1), m.group(2)
    return f"{val}{unit}"


def _find_time_column(columns: list[str]) -> Optional[str]:
    """Find the best time column in the DataFrame for temporal correlation."""
    time_candidates = ["Time", "Timestamp", "EventTime", "TimeCreated",
                       "UtcTime", "CreationUtcTime", "_time", "date", "Date"]
    for cand in time_candidates:
        for col in columns:
            if col.lower() == cand.lower():
                return col
    return None


def _evaluate_temporal_correlation(
    df_matched: pl.DataFrame,
    detection: dict,
    rule: dict,
) -> Optional[int]:
    """
    Apply temporal correlation (timeframe + correlation block or aggregation block)
    to already-matched rows. Returns adjusted match count, or None if no temporal
    correlation is needed.

    Supports two patterns:
    1. Sigma standard: detection.timeframe + detection.correlation
       correlation: {type: event_count, group-by: [field], timespan: "5m", condition: {gte: 10}}
    2. Custom Chronos: rule.aggregation
       aggregation: {group_by: [field], time_window: "5m", threshold: 10}
    """
    timeframe = detection.get("timeframe")
    correlation = detection.get("correlation")
    aggregation = rule.get("aggregation")

    if not timeframe and not correlation and not aggregation:
        return None  # No temporal correlation needed

    if df_matched.is_empty():
        return 0

    time_col = _find_time_column(df_matched.columns)
    if not time_col:
        logger.debug(f"Temporal correlation skipped: no time column found in {df_matched.columns[:5]}")
        return None  # Can't do temporal without a time column

    # Parse time column to datetime
    try:
        ts_col = pl.col(time_col).cast(pl.Utf8)
        df_ts = df_matched.with_columns(
            pl.coalesce([
                ts_col.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                ts_col.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                ts_col.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                ts_col.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                ts_col.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
            ]).alias("_sigma_ts")
        ).filter(pl.col("_sigma_ts").is_not_null()).sort("_sigma_ts")
    except Exception as e:
        logger.debug(f"Temporal correlation: time parse failed: {e}")
        return None

    if df_ts.is_empty():
        return 0

    # Determine parameters from either correlation or aggregation block
    if correlation and isinstance(correlation, dict):
        group_by_fields = correlation.get("group-by", [])
        timespan_str = correlation.get("timespan") or str(timeframe or "5m")
        threshold_cond = correlation.get("condition", {})
        threshold = threshold_cond.get("gte", 5) if isinstance(threshold_cond, dict) else 5
    elif aggregation and isinstance(aggregation, dict):
        group_by_fields = aggregation.get("group_by", [])
        timespan_str = aggregation.get("time_window", str(timeframe or "5m"))
        threshold = aggregation.get("threshold", 5)
    else:
        # Has timeframe but no correlation/aggregation details — just use timeframe as info
        return None

    if isinstance(group_by_fields, str):
        group_by_fields = [group_by_fields]

    duration = _parse_timeframe(timespan_str)
    if not duration:
        duration = "5m"

    # Resolve group-by columns (case-insensitive)
    resolved_groups = []
    for gf in group_by_fields:
        for col in df_ts.columns:
            if col.lower() == gf.lower():
                resolved_groups.append(col)
                break

    try:
        if resolved_groups:
            # Group by time window + group fields, count events per group per window
            windowed = (
                df_ts.sort("_sigma_ts")
                .group_by_dynamic("_sigma_ts", every=duration, group_by=resolved_groups)
                .agg(pl.len().alias("_event_count"))
            )
            # Count groups that exceed threshold
            hot_groups = windowed.filter(pl.col("_event_count") >= threshold)
            if hot_groups.is_empty():
                return 0
            # Return total events in hot windows
            return hot_groups["_event_count"].sum()
        else:
            # No group-by — just count events per time window
            windowed = (
                df_ts.sort("_sigma_ts")
                .group_by_dynamic("_sigma_ts", every=duration)
                .agg(pl.len().alias("_event_count"))
            )
            hot_windows = windowed.filter(pl.col("_event_count") >= threshold)
            if hot_windows.is_empty():
                return 0
            return hot_windows["_event_count"].sum()
    except Exception as e:
        logger.debug(f"Temporal correlation eval failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Forensic context columns — always include in evidence if present in data
# ---------------------------------------------------------------------------
FORENSIC_CONTEXT_COLUMNS = [
    "UserName", "User", "AccountName", "SubjectUserName", "TargetUserName",
    "EventDataTargetUserName", "EventDataSubjectUserName",
    "ProcessName", "Image", "NewProcessName", "ParentImage", "ParentProcessName",
    "SourceIP", "IpAddress", "SourceAddress", "ClientIP", "EndpointIp",
    "CommandLine", "ParentCommandLine",
    "Status", "Result", "LogonType",
    "DestinationHostname", "DestinationIp", "DestPort",
    "ServiceName", "TaskName", "ObjectName",
]

# ---------------------------------------------------------------------------
# Main evaluation entry point
# ---------------------------------------------------------------------------

def match_sigma_rules(df: pl.DataFrame, rules: Optional[list] = None) -> list[dict]:
    """
    Evaluate all loaded Sigma rules against a DataFrame.
    Returns a list of hit dicts, one per (rule, row) match:
      {title, level, mitre_technique, mitre_tactic, tags, matched_rows}
    """
    if df.is_empty():
        return []

    if rules is None:
        rules = load_sigma_rules()

    if not rules:
        return []

    columns = df.columns
    columns_lower = {c.lower(): c for c in columns}
    hits = []

    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            continue

        condition_str = detection.get("condition", "")
        if not condition_str:
            continue

        # Pre-check: extract all field names referenced by this rule
        # If NONE of them exist in the DataFrame, skip the rule entirely
        _meta_keys = {"condition", "timeframe", "correlation"}
        rule_fields = set()
        for block_name, block_value in detection.items():
            if block_name in _meta_keys:
                continue
            if isinstance(block_value, dict):
                for field_raw in block_value.keys():
                    rule_fields.add(field_raw.split("|")[0])
            elif isinstance(block_value, list):
                for b in block_value:
                    if isinstance(b, dict):
                        for field_raw in b.keys():
                            rule_fields.add(field_raw.split("|")[0])

        if rule_fields:
            has_any_field = any(
                f in columns or f.lower() in columns_lower
                for f in rule_fields
            )
            if not has_any_field:
                continue  # Skip rule — none of its fields exist in data

        # Collect field names referenced in detection blocks for evidence columns
        detection_fields: set[str] = set()

        # Build named expression blocks (skip meta keys)
        named_exprs: dict[str, Optional[pl.Expr]] = {}
        for block_name, block_value in detection.items():
            if block_name in _meta_keys:
                continue
            if isinstance(block_value, dict):
                named_exprs[block_name] = _build_named_condition(block_value, columns)
                # Track which fields this block references
                for field_raw in block_value.keys():
                    base_field = field_raw.split("|")[0]
                    detection_fields.add(base_field)
            elif isinstance(block_value, list):
                # List of dicts — OR them
                sub = [_build_named_condition(b, columns) for b in block_value if isinstance(b, dict)]
                sub = [e for e in sub if e is not None]
                named_exprs[block_name] = functools.reduce(operator.or_, sub) if sub else None
                for b in block_value:
                    if isinstance(b, dict):
                        for field_raw in b.keys():
                            detection_fields.add(field_raw.split("|")[0])
            else:
                named_exprs[block_name] = None

        # Resolve the condition string
        final_expr = _parse_condition_string(str(condition_str), named_exprs)
        if final_expr is None:
            continue

        # Evaluate — count matching rows
        try:
            df_matched = df.filter(final_expr)
            match_count = df_matched.height
        except Exception as exc:
            logger.debug(f"Sigma rule '{rule.get('title', '?')}' eval error: {exc}")
            continue

        if match_count == 0:
            continue

        # Apply temporal correlation if rule has timeframe/correlation/aggregation
        temporal_count = _evaluate_temporal_correlation(df_matched, detection, rule)
        if temporal_count is not None:
            match_count = temporal_count
            if match_count == 0:
                continue

        # --- Extract evidence: resolve detection_fields to actual column names ---
        matched_columns = []
        for df_name in detection_fields:
            # Case-insensitive match + dot-notation fallback
            for c in columns:
                if c.lower() == df_name.lower() or c.lower() == df_name.rsplit(".", 1)[-1].lower():
                    if c not in matched_columns and c != "_id":
                        matched_columns.append(c)
                    break

        # Build sample evidence: first 150 rows with _id + detection columns
        sample_evidence = []
        all_row_ids = []
        try:
            # Select _id + matched columns (+ time column if available)
            evidence_cols = []
            if "_id" in df_matched.columns:
                evidence_cols.append("_id")
                all_row_ids = df_matched["_id"].to_list()[:500]
            # Add time column first for context
            time_col = _find_time_column(df_matched.columns)
            if time_col and time_col not in matched_columns:
                evidence_cols.append(time_col)
            evidence_cols.extend(matched_columns)
            # Add forensic context columns that exist in data (max 12 total cols)
            for fc in FORENSIC_CONTEXT_COLUMNS:
                if len(evidence_cols) >= 12:
                    break
                # Case-insensitive match against actual columns
                for c in df_matched.columns:
                    if c.lower() == fc.lower() and c not in evidence_cols:
                        evidence_cols.append(c)
                        break
            # Deduplicate while preserving order
            seen = set()
            deduped = []
            for c in evidence_cols:
                if c not in seen and c in df_matched.columns:
                    seen.add(c)
                    deduped.append(c)
            if deduped:
                sample_df = df_matched.head(150).select(deduped)
                sample_evidence = sample_df.to_dicts()
        except Exception as exc:
            logger.debug(f"Sigma evidence extraction for '{rule.get('title', '?')}': {exc}")

        custom = rule.get("custom", {}) or {}
        raw_tags = rule.get("tags", []) or []
        # Normalize tags: ensure consistent "attack.tXXXX" format
        tags = []
        for t in raw_tags:
            t_lower = str(t).lower().strip()
            # Normalize "mitre.tXXXX" → "attack.tXXXX"
            if t_lower.startswith("mitre.t"):
                t_lower = "attack." + t_lower[6:]
            tags.append(t_lower)

        hits.append({
            "title": rule.get("title", "Unknown Rule"),
            "level": rule.get("level", "unknown"),
            "mitre_technique": custom.get("mitre_technique", next(
                (t for t in tags if t.startswith("attack.t")), ""
            )),
            "mitre_tactic": custom.get("mitre_tactic", next(
                (t for t in tags if t.startswith("attack.") and not t.startswith("attack.t")), ""
            )),
            "tags": tags,
            "matched_rows": match_count,
            "matched_columns": matched_columns,
            "sample_evidence": sample_evidence,
            "all_row_ids": all_row_ids,
            "rule_path": os.path.relpath(rule["_path"], _get_rules_dir()) if rule.get("_path") else "inline",
        })

    hits.sort(key=lambda h: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(h["level"].lower(), 4),
        -h["matched_rows"]
    ))

    return hits
