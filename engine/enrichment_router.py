"""
Chronos-DFIR Enrichment Router.

Grid-integrated IOC extraction, bulk enrichment, export, and case persistence.
"""

import asyncio
import csv
import io
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

import polars as pl
from fastapi import APIRouter
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger("chronos.enrichment.router")

enrichment_router = APIRouter(prefix="/api/enrichment", tags=["enrichment"])

OUTPUT_DIR = os.environ.get("CHRONOS_DATA_DIR", "chronos_output")

# ---------------------------------------------------------------------------
# IOC Column Detection Patterns (mirrors frontend IOC_COLUMN_MAP)
# ---------------------------------------------------------------------------

IOC_COLUMN_PATTERNS = {
    "ip": [
        "clientip", "srcip", "sourceip", "destip", "destinationip",
        "ipaddress", "endpointip", "remoteip", "sourceaddress",
        "destinationaddress", "ip", "ip_address", "src_ip", "dst_ip",
        "x-forwarded-for", "ipport", "sourceipaddress", "destipaddress",
        "remoteaddress", "localaddress", "dstaddr", "srcaddr",
        "hostip", "serverip",
    ],
    "domain": [
        "domain", "domainname", "targetdomainname", "hostname",
        "destinationhostname", "querieddomainname", "url",
        "computer", "computername",
        "remotehost", "targethost", "servername",
    ],
    "hash": [
        "md5", "sha1", "sha256", "hashes", "filehash", "hash",
        "imphash", "sha256hash", "md5hash",
        # Sysmon-specific hash columns
        "processfilehashmd5", "processfilehashsha1", "processfilehashsha256",
        "parentfilehashmd5", "parentfilehashsha1", "parentfilehashsha256",
    ],
    "email": [
        "targetusername", "subjectusername", "email",
        "userprincipalname",
    ],
}

# Provider → IOC type mapping
PROVIDER_IOC_TYPES = {
    "ip_api": ["ip"],
    "abuseipdb": ["ip"],
    "virustotal": ["ip", "domain", "hash"],
    "greynoise": ["ip"],
    "internetdb": ["ip"],
    "urlhaus": ["domain"],
    "urlscan": ["domain"],
    "threatfox": ["ip", "domain", "hash"],
    "threatfox_free": ["ip", "domain", "hash"],
    "otx": ["ip", "domain", "hash"],
    "circl": ["hash"],
    "malwarebazaar": ["hash"],
    "hibp": ["email"],
}

# Provider rate limits (requests per minute) for time estimation
PROVIDER_RATE_LIMITS = {
    "ip_api": 45,
    "abuseipdb": 60,
    "virustotal": 4,
    "greynoise": 30,
    "internetdb": 60,
    "urlhaus": 60,
    "urlscan": 5,
    "threatfox": 30,
    "threatfox_free": 30,
    "otx": 30,
    "circl": 60,
    "malwarebazaar": 30,
    "hibp": 10,
}

# Regex for splitting multi-value cells
_LIST_PATTERN = re.compile(r"^\s*\[.*\]\s*$", re.DOTALL)
_HASH_KEY_VALUE_PATTERN = re.compile(r"(?:MD5|SHA1|SHA256|SHA384|SHA512|IMPHASH)=([a-fA-F0-9]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ExtractRequest(BaseModel):
    filename: str
    columns: Dict[str, List[str]]  # {"ip": ["SourceIP", "DestIP"], ...}
    providers: List[str] = []
    query: str = ""
    col_filters: str = "{}"
    selected_ids: List[int] = []
    start_time: str = ""
    end_time: str = ""


class BulkEnrichRequest(BaseModel):
    filename: str
    columns: Dict[str, List[str]]
    providers: List[str] = []
    query: str = ""
    col_filters: str = "{}"
    selected_ids: List[int] = []
    start_time: str = ""
    end_time: str = ""


class SaveToCaseRequest(BaseModel):
    case_id: str
    results: Dict[str, Any]
    filename: str = ""
    columns_used: List[str] = []


class ExportEnrichmentRequest(BaseModel):
    results: Dict[str, Any]
    format: str = "csv"  # csv, xlsx, json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_filtered_dataframe(filename: str, params: dict) -> pl.DataFrame:
    """Load a processed file and apply standard filters."""
    from engine.forensic import apply_standard_processing

    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filename}")

    if filename.endswith(".parquet"):
        lf = pl.scan_parquet(filepath)
    else:
        lf = pl.scan_csv(filepath, infer_schema_length=0, try_parse_dates=False, truncate_ragged_lines=True)

    # Apply filters
    filter_params = {
        "query": params.get("query", ""),
        "col_filters": params.get("col_filters", "{}"),
        "start_time": params.get("start_time", ""),
        "end_time": params.get("end_time", ""),
        "sort_col": "",
        "sort_dir": "",
        "selected_ids": params.get("selected_ids", []),
    }
    lf = apply_standard_processing(lf, filter_params)
    return lf.collect()


def _split_multi_value(val: str) -> list:
    """Split cell values that contain multiple IOCs.

    Handles:
    - Python-style lists: "['172.28.126.2', '10.1.1.78']"
    - Hash key-value pairs: "MD5=abc123,SHA256=def456"
    - Comma-separated: "8.8.8.8, 1.1.1.1"
    - Pipe-separated: "8.8.8.8|1.1.1.1"
    """
    val = val.strip()

    # Python list-like: ['val1', 'val2'] or ["val1", "val2"]
    if _LIST_PATTERN.match(val):
        # Extract quoted items
        items = re.findall(r"['\"]([^'\"]+)['\"]", val)
        if items:
            return [item.strip() for item in items if item.strip()]
        # Fallback: strip brackets and split by comma
        inner = val.strip()[1:-1]
        return [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]

    # Hash key-value pairs: MD5=abc123,SHA256=def456 or SHA256=abc123
    hash_matches = _HASH_KEY_VALUE_PATTERN.findall(val)
    if hash_matches:
        return hash_matches

    # Pipe-separated
    if "|" in val and "," not in val:
        parts = [p.strip() for p in val.split("|") if p.strip()]
        if len(parts) > 1:
            return parts

    # Comma-separated (only if it looks like IOC values, not prose)
    if "," in val:
        parts = [p.strip() for p in val.split(",") if p.strip()]
        if len(parts) > 1 and all(len(p) < 100 for p in parts):
            return parts

    return [val]


def _extract_iocs_from_df(
    df: pl.DataFrame,
    columns: Dict[str, List[str]],
) -> Dict[str, Any]:
    """Extract unique IOC values from specified columns, handling multi-value cells.

    Returns dict with structure per ioc_type:
      { "values": [...], "total_raw": N, "private_ips_excluded": N }
    """
    from engine.enrichment import _is_public_ip, _IP_PATTERN, _HASH_PATTERN, _DOMAIN_PATTERN, _EMAIL_PATTERN, _is_valid_domain

    limits = {"ip": 200, "domain": 100, "hash": 100, "email": 50}
    result = {}

    for ioc_type, col_names in columns.items():
        values = set()
        private_ips = set()
        excluded_filenames = 0
        excluded_invalid = 0
        total_raw = 0

        for col in col_names:
            if col not in df.columns:
                continue
            series = df[col].cast(pl.Utf8).drop_nulls().unique()
            for raw_val in series.to_list():
                raw_val = str(raw_val).strip()
                if len(raw_val) < 3 or raw_val in ("", "N/A", "n/a", "-", "None", "null", "nan"):
                    continue

                # Split multi-value cells
                split_vals = _split_multi_value(raw_val)

                for val in split_vals:
                    val = val.strip()
                    if len(val) < 2:
                        continue
                    total_raw += 1

                    if ioc_type == "ip":
                        # Strip IPv6-mapped IPv4 prefix (Sysmon uses ::ffff:x.x.x.x)
                        clean_val = re.sub(r'^::ffff:', '', val)
                        if _IP_PATTERN.match(clean_val):
                            if _is_public_ip(clean_val):
                                values.add(clean_val)
                            else:
                                private_ips.add(clean_val)
                        else:
                            excluded_invalid += 1
                    elif ioc_type == "hash":
                        if _HASH_PATTERN.match(val):
                            values.add(val.lower())
                        else:
                            excluded_invalid += 1
                    elif ioc_type == "domain":
                        if _is_valid_domain(val) and not _IP_PATTERN.match(val):
                            values.add(val.lower())
                        elif _DOMAIN_PATTERN.match(val) and not _IP_PATTERN.match(val):
                            excluded_filenames += 1  # .exe/.dll matched old regex
                        else:
                            excluded_invalid += 1
                    elif ioc_type == "email":
                        if _EMAIL_PATTERN.match(val):
                            values.add(val.lower())
                        else:
                            excluded_invalid += 1

        max_count = limits.get(ioc_type, 50)
        sorted_vals = sorted(list(values))[:max_count]
        result[ioc_type] = {
            "values": sorted_vals,
            "total_raw": total_raw,
            "unique_count": len(values),
            "private_ips_excluded": len(private_ips),
            "private_ips_sample": sorted(list(private_ips))[:5],
            "excluded_filenames": excluded_filenames,
            "excluded_invalid": excluded_invalid,
        }

    return result


def _detect_columns_by_content(df_sample: pl.DataFrame, already_detected: set) -> Dict[str, List[str]]:
    """Scan sample data to detect IOC columns by content value patterns.

    Checks if >=3% of non-null values in a column match IP/hash/domain/email patterns.
    Handles multi-value cells by splitting before matching.
    """
    from engine.enrichment import _IP_PATTERN, _HASH_PATTERN, _DOMAIN_PATTERN, _EMAIL_PATTERN, _is_valid_domain

    content_detected: Dict[str, List[str]] = {}
    MIN_MATCH_RATIO = 0.03  # 3% threshold (lowered from 5% for sparse columns)

    skip_cols = already_detected | {"_id", "No.", "no.", "timestamp", "Timestamp", "datetime"}

    for col in df_sample.columns:
        if col in skip_cols or col.startswith("_"):
            continue

        try:
            series = df_sample[col].cast(pl.Utf8).drop_nulls()
        except Exception:
            continue

        if len(series) == 0:
            continue

        sample_vals = series.head(300).to_list()
        non_empty = [v.strip() for v in sample_vals if v and len(v.strip()) >= 3]
        if len(non_empty) < 2:  # Lowered from 3 to catch sparse columns
            continue

        # Flatten multi-value cells before matching
        flat_vals = []
        for v in non_empty:
            split = _split_multi_value(v)
            flat_vals.extend(s.strip() for s in split if s.strip())

        if not flat_vals:
            continue

        total = len(flat_vals)

        # Count pattern matches (strip ::ffff: IPv6 prefix for IP detection)
        ip_count = sum(1 for v in flat_vals if _IP_PATTERN.match(re.sub(r'^::ffff:', '', v)))
        hash_count = sum(1 for v in flat_vals if _HASH_PATTERN.match(v))
        domain_count = sum(1 for v in flat_vals if _is_valid_domain(v) and not _IP_PATTERN.match(v))
        email_count = sum(1 for v in flat_vals if _EMAIL_PATTERN.match(v))

        if ip_count / total >= MIN_MATCH_RATIO:
            content_detected.setdefault("ip", []).append(col)
        elif hash_count / total >= MIN_MATCH_RATIO:
            content_detected.setdefault("hash", []).append(col)
        elif domain_count / total >= MIN_MATCH_RATIO:
            content_detected.setdefault("domain", []).append(col)
        elif email_count / total >= MIN_MATCH_RATIO:
            content_detected.setdefault("email", []).append(col)

    return content_detected


def _flatten_enrichment_results(results: Dict[str, Any]) -> List[dict]:
    """Flatten enrichment results into tabular rows for CSV/XLSX export."""
    rows = []

    for enrichment_key in ["ip_enrichment", "domain_enrichment", "hash_enrichment", "email_enrichment"]:
        items = results.get(enrichment_key, [])
        for item in items:
            ioc_val = item.get("ip") or item.get("domain") or item.get("hash") or item.get("email", "")
            ioc_type = enrichment_key.replace("_enrichment", "")

            for provider_key, provider_data in item.items():
                if provider_key in ("ip", "domain", "hash", "email") or not isinstance(provider_data, dict) or not provider_data:
                    continue
                provider_name = provider_data.get("provider", provider_key)
                for field_key, field_val in provider_data.items():
                    if field_key == "provider":
                        continue
                    rows.append({
                        "IOC": ioc_val,
                        "Type": ioc_type,
                        "Provider": provider_name,
                        "Field": field_key,
                        "Value": str(field_val) if not isinstance(field_val, (list, dict)) else json.dumps(field_val),
                    })

    return rows


def _estimate_enrichment_time(iocs_by_type: dict, providers: list) -> dict:
    """Estimate enrichment time and API calls based on provider rate limits."""
    total_calls = 0
    slowest_seconds = 0

    for provider in providers:
        supported_types = PROVIDER_IOC_TYPES.get(provider, [])
        rate = PROVIDER_RATE_LIMITS.get(provider, 30)
        provider_calls = 0

        for ioc_type in supported_types:
            count = iocs_by_type.get(ioc_type, 0)
            provider_calls += count

        total_calls += provider_calls
        if rate > 0 and provider_calls > 0:
            seconds = (provider_calls / rate) * 60
            if seconds > slowest_seconds:
                slowest_seconds = seconds

    return {
        "total_api_calls": total_calls,
        "estimated_seconds": round(slowest_seconds),
        "estimated_display": _format_time(round(slowest_seconds)),
    }


def _format_time(seconds: int) -> str:
    if seconds < 60:
        return f"~{seconds}s"
    minutes = seconds // 60
    secs = seconds % 60
    if secs:
        return f"~{minutes}m {secs}s"
    return f"~{minutes}m"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@enrichment_router.get("/columns/{filename}")
async def get_enrichable_columns(filename: str):
    """Return auto-detected IOC columns for a loaded file.

    Uses two-phase detection:
    1. Name-based: match column names against known IOC patterns
    2. Content-based: sample first 500 rows and check if values match IOC patterns
    """
    try:
        filepath = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(filepath):
            return JSONResponse(status_code=404, content={"error": "File not found"})

        if filename.endswith(".parquet"):
            lf = pl.scan_parquet(filepath)
        else:
            lf = pl.scan_csv(filepath, infer_schema_length=0, try_parse_dates=False, truncate_ragged_lines=True)

        # Sample first 500 rows (also gives us column names without extra call)
        df_sample = lf.head(500).collect()
        all_cols = df_sample.columns
        cols_lower = {c.lower(): c for c in all_cols}

        # Phase 1: Name-based detection
        detected = {}
        for ioc_type, patterns in IOC_COLUMN_PATTERNS.items():
            matched = []
            for pattern in patterns:
                if pattern in cols_lower and cols_lower[pattern] not in matched:
                    matched.append(cols_lower[pattern])
            if matched:
                detected[ioc_type] = matched

        # Phase 2: Content-based detection
        already_detected = set()
        for cols in detected.values():
            already_detected.update(cols)

        try:
            content_detected = await asyncio.to_thread(
                _detect_columns_by_content, df_sample, already_detected
            )
            for ioc_type, cols in content_detected.items():
                if ioc_type not in detected:
                    detected[ioc_type] = cols
                else:
                    for c in cols:
                        if c not in detected[ioc_type]:
                            detected[ioc_type].append(c)
        except Exception as e:
            logger.warning(f"Content-based detection failed: {e}")

        # Build provider availability info
        from engine.enrichment import load_api_keys, get_active_providers
        keys = load_api_keys()
        active_providers = get_active_providers(keys)

        return {
            "columns": all_cols,
            "detected": detected,
            "provider_ioc_types": PROVIDER_IOC_TYPES,
            "active_providers": active_providers,
        }
    except Exception as e:
        logger.error(f"Column detection error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@enrichment_router.post("/extract")
async def extract_iocs(req: ExtractRequest):
    """Extract and deduplicate IOCs from the filtered grid data."""
    try:
        df = await asyncio.to_thread(
            _load_filtered_dataframe,
            req.filename,
            {
                "query": req.query,
                "col_filters": req.col_filters,
                "selected_ids": req.selected_ids,
                "start_time": req.start_time,
                "end_time": req.end_time,
            },
        )

        total_rows = len(df)
        iocs_data = await asyncio.to_thread(_extract_iocs_from_df, df, req.columns)

        # Build summary
        summary = {}
        total_iocs = 0
        iocs_by_type = {}
        for ioc_type, data in iocs_data.items():
            values = data["values"]
            count = len(values)
            summary[ioc_type] = {
                "count": count,
                "total_raw": data["total_raw"],
                "duplicates_removed": data["total_raw"] - data["unique_count"],
                "private_ips_excluded": data.get("private_ips_excluded", 0),
                "private_ips_sample": data.get("private_ips_sample", []),
                "excluded_filenames": data.get("excluded_filenames", 0),
                "excluded_invalid": data.get("excluded_invalid", 0),
                "sample": values[:10],
            }
            total_iocs += count
            iocs_by_type[ioc_type] = count

        # Estimate time based on providers
        estimate = _estimate_enrichment_time(iocs_by_type, req.providers)

        # Flatten values for backward compat
        iocs_flat = {t: d["values"] for t, d in iocs_data.items()}

        return {
            "status": "ok",
            "total_rows": total_rows,
            "total_iocs": total_iocs,
            "iocs": iocs_flat,
            "summary": summary,
            "estimate": estimate,
        }
    except FileNotFoundError as e:
        return JSONResponse(status_code=404, content={"error": str(e)})
    except Exception as e:
        logger.error(f"IOC extraction error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@enrichment_router.post("/bulk")
async def bulk_enrich(req: BulkEnrichRequest):
    """Execute bulk enrichment on extracted IOCs."""
    try:
        from engine.enrichment import enrich_all_iocs, load_api_keys, get_active_providers
        from engine.enrichment_cache import EnrichmentCache

        start_time = time.monotonic()

        # Step 1: Extract IOCs from filtered data
        df = await asyncio.to_thread(
            _load_filtered_dataframe,
            req.filename,
            {
                "query": req.query,
                "col_filters": req.col_filters,
                "selected_ids": req.selected_ids,
                "start_time": req.start_time,
                "end_time": req.end_time,
            },
        )

        iocs_data = await asyncio.to_thread(_extract_iocs_from_df, df, req.columns)

        # Step 2: Build IOC set for enrichment pipeline
        iocs = {
            "ips": set(iocs_data.get("ip", {}).get("values", [])),
            "domains": set(iocs_data.get("domain", {}).get("values", [])),
            "hashes": set(iocs_data.get("hash", {}).get("values", [])),
            "emails": set(iocs_data.get("email", {}).get("values", [])),
        }

        total_iocs = sum(len(v) for v in iocs.values())
        if total_iocs == 0:
            return {"status": "no_iocs", "message": "No enrichable IOCs found in the selected data."}

        # Step 3: Filter providers if specified
        keys = load_api_keys()
        active = get_active_providers(keys)

        if req.providers:
            requested_active = [p for p in req.providers if p in active]
            allowed_types = set()
            for p in requested_active:
                allowed_types.update(PROVIDER_IOC_TYPES.get(p, []))

            if "ip" not in allowed_types:
                iocs["ips"] = set()
            if "domain" not in allowed_types:
                iocs["domains"] = set()
            if "hash" not in allowed_types:
                iocs["hashes"] = set()
            if "email" not in allowed_types:
                iocs["emails"] = set()

        # Step 4: Run enrichment
        cache = EnrichmentCache()
        cache.clear_expired()

        results = await enrich_all_iocs(iocs, keys, cache)

        elapsed = round(time.monotonic() - start_time, 1)

        # Add metadata
        results["metadata"] = {
            "elapsed_seconds": elapsed,
            "total_iocs_submitted": total_iocs,
            "iocs_by_type": {
                "ip": len(iocs["ips"]),
                "domain": len(iocs["domains"]),
                "hash": len(iocs["hashes"]),
                "email": len(iocs["emails"]),
            },
            "filename": req.filename,
        }

        return results

    except FileNotFoundError as e:
        return JSONResponse(status_code=404, content={"error": str(e)})
    except Exception as e:
        logger.error(f"Bulk enrichment error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@enrichment_router.post("/export")
async def export_enrichment(req: ExportEnrichmentRequest):
    """Export enrichment results as CSV, XLSX, or JSON."""
    try:
        if req.format == "json":
            json_bytes = json.dumps(req.results, indent=2, default=str).encode("utf-8")
            return StreamingResponse(
                io.BytesIO(json_bytes),
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=enrichment_results.json"},
            )

        rows = _flatten_enrichment_results(req.results)
        if not rows:
            return JSONResponse(status_code=400, content={"error": "No enrichment data to export"})

        if req.format == "csv":
            output = io.StringIO()
            output.write("\ufeff")  # UTF-8 BOM for Excel
            writer = csv.DictWriter(output, fieldnames=["IOC", "Type", "Provider", "Field", "Value"])
            writer.writeheader()
            writer.writerows(rows)
            csv_bytes = output.getvalue().encode("utf-8")

            return StreamingResponse(
                io.BytesIO(csv_bytes),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=enrichment_results.csv"},
            )

        elif req.format == "xlsx":
            import xlsxwriter

            xlsx_buffer = io.BytesIO()
            wb = xlsxwriter.Workbook(xlsx_buffer, {"in_memory": True, "strings_to_numbers": False})
            ws = wb.add_worksheet("Enrichment")

            header_fmt = wb.add_format({"bold": True, "bg_color": "#f1f5f9", "font_color": "#1e293b"})
            text_fmt = wb.add_format({"num_format": "@"})

            headers = ["IOC", "Type", "Provider", "Field", "Value"]
            for i, h in enumerate(headers):
                ws.write_string(0, i, h, header_fmt)

            for r_idx, row in enumerate(rows, start=1):
                for c_idx, key in enumerate(headers):
                    ws.write_string(r_idx, c_idx, str(row.get(key, "")), text_fmt)

            ws.set_column(0, 0, 40)
            ws.set_column(1, 1, 10)
            ws.set_column(2, 2, 18)
            ws.set_column(3, 3, 22)
            ws.set_column(4, 4, 50)
            wb.close()

            xlsx_buffer.seek(0)
            return StreamingResponse(
                xlsx_buffer,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": "attachment; filename=enrichment_results.xlsx"},
            )

        return JSONResponse(status_code=400, content={"error": f"Unsupported format: {req.format}"})

    except Exception as e:
        logger.error(f"Enrichment export error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@enrichment_router.post("/save-to-case")
async def save_enrichment_to_case(req: SaveToCaseRequest):
    """Persist enrichment results to DuckDB case_iocs table."""
    try:
        from engine.case_db import upsert_ioc

        saved_count = 0
        context = f"Bulk enrichment from {req.filename}" if req.filename else "Manual enrichment"
        if req.columns_used:
            context += f", columns: {', '.join(req.columns_used)}"

        for enrichment_key in ["ip_enrichment", "domain_enrichment", "hash_enrichment", "email_enrichment"]:
            items = req.results.get(enrichment_key, [])
            ioc_type = enrichment_key.replace("_enrichment", "")

            for item in items:
                ioc_val = item.get("ip") or item.get("domain") or item.get("hash") or item.get("email", "")
                if not ioc_val:
                    continue

                enrichment_json = {}
                for key, val in item.items():
                    if key not in ("ip", "domain", "hash", "email") and isinstance(val, dict):
                        enrichment_json[key] = val

                upsert_ioc(
                    case_id=req.case_id,
                    ioc_type=ioc_type,
                    ioc_value=ioc_val,
                    context=context,
                    enrichment_json=json.dumps(enrichment_json, default=str),
                )
                saved_count += 1

        return {"status": "saved", "count": saved_count}

    except Exception as e:
        logger.error(f"Save to case error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
