"""
Chronos-DFIR Sigma Engine — Dynamic YAML-to-Polars Rule Evaluator
==================================================================
Translates Sigma YAML detection rules into Polars LazyFrame expressions
and evaluates them against forensic DataFrames at analysis time.

SCOPE (v1.1):
  IN:  field|contains, |endswith, |startswith, |any, |all, |not
       EventID list matching (is_in)
       Boolean conditions: and / or between named detection blocks
       Metadata extraction: title, level, tags, custom fields
  OUT: Temporal aggregation (timeframe + count > N) — deferred to v1.2
       near queries, base64offset, cidr modifiers

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

    # Unsupported temporal/count conditions — skip gracefully
    if re.search(r"\|count\b|timeframe", cond, re.IGNORECASE):
        return None

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
    hits = []

    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            continue

        condition_str = detection.get("condition", "")
        if not condition_str:
            continue

        # Build named expression blocks (everything except 'condition' key)
        named_exprs: dict[str, Optional[pl.Expr]] = {}
        for block_name, block_value in detection.items():
            if block_name == "condition":
                continue
            if isinstance(block_value, dict):
                named_exprs[block_name] = _build_named_condition(block_value, columns)
            elif isinstance(block_value, list):
                # List of dicts — OR them
                sub = [_build_named_condition(b, columns) for b in block_value if isinstance(b, dict)]
                sub = [e for e in sub if e is not None]
                named_exprs[block_name] = functools.reduce(operator.or_, sub) if sub else None
            else:
                named_exprs[block_name] = None

        # Resolve the condition string
        final_expr = _parse_condition_string(str(condition_str), named_exprs)
        if final_expr is None:
            continue

        # Evaluate — count matching rows
        try:
            match_count = df.filter(final_expr).height
        except Exception as exc:
            logger.debug(f"Sigma rule '{rule.get('title', '?')}' eval error: {exc}")
            continue

        if match_count == 0:
            continue

        custom = rule.get("custom", {}) or {}
        tags = rule.get("tags", []) or []

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
            "rule_path": os.path.relpath(rule.get("_path", ""), _get_rules_dir()),
        })

    hits.sort(key=lambda h: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(h["level"].lower(), 4),
        -h["matched_rows"]
    ))

    return hits
