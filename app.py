import os
import io
import time
import json
import shutil
import logging
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from engine.forensic import (
    TIME_HIERARCHY, EVENT_ID_HIERARCHY, get_primary_time_column,
    normalize_time_columns_in_df, parse_time_boundary, sanitize_context_data,
    apply_standard_processing as _apply_standard_processing,
    sub_analyze_timeline, sub_analyze_context, sub_analyze_hunting,
    sub_analyze_identity_and_procs, ingest_json_file
)
from timeline_skill import generate_unified_timeline
import polars as pl
import csv
import sys
import zipfile
import math
import traceback
import re
from typing import List, Optional, Any
from pydantic import BaseModel
import asyncio

# Load .env for API keys (if present)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("Chronos-DFIR")

# NOTE: chronos_timeseries_builder (builder.py) is available in .agents/skills/
# but not wired into any endpoint yet. See engine/skill_router.py for status.
# To activate: import and call build_chronos_timeseries() in chart/histogram endpoint.

# Helper to sanitize filenames
def sanitize_filename(filename: str) -> str:
    # Remove path traversal attempts
    base = os.path.basename(filename)
    # Remove any non-alphanumeric characters except dots, dashes and underscores
    sanitized = re.sub(r"[^a-zA-Z0-9\._\-]", "_", base)
    return sanitized


# Increase CSV field size limit to handle large JSON blobs in cells (e.g. SharpHound)
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2147483647) # Fallback for 32-bit systems


app = FastAPI(title="Chronos-DFIR Web")

@app.post("/api/reset")
async def hard_reset():
    """
    Hard reset endpoint to clear all session caches, uploads, and outputs.
    """
    try:
        # 1. Clear processed_files cache
        processed_files.clear()

        # 2. Cleanup directories
        for folder in ["chronos_uploads", "chronos_output"]:
            if os.path.exists(folder):
                for filename in os.listdir(folder):
                    file_path = os.path.join(folder, filename)
                    try:
                        if os.path.isfile(file_path) or os.path.islink(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        logger.error(f"Failed to delete {file_path} during reset: {e}")

        logger.info("Hard Reset completed: Cache and folders cleared.")
        return JSONResponse(content={"message": "Hard reset successful. Data cleared."}, status_code=200)
    except Exception as e:
        logger.error(f"Hard Reset failed: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)

# Mount Case Management Router
from engine.case_router import case_router
app.include_router(case_router)

@app.on_event("startup")
async def startup_event():
    # Initialize Case Database
    try:
        from engine.case_db import init_db
        init_db()
    except Exception as e:
        logger.warning(f"Case DB init skipped: {e}")
    logger.info("Startup cleanup complete: /chronos_uploads and /chronos_output cleared.")

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "chronos_output")
UPLOAD_DIR = os.path.join(BASE_DIR, "chronos_uploads")
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Global Cache
processed_files = {}

# Ensure directories exist
for d in [OUTPUT_DIR, UPLOAD_DIR, STATIC_DIR, TEMPLATES_DIR]:
    os.makedirs(d, exist_ok=True)

# Mount statics and templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Auto-cachebust: compute hash of key static assets at startup
import hashlib

def _compute_asset_hash():
    """MD5 hash of main JS + CSS files for automatic cache-busting."""
    files_to_hash = [
        os.path.join(STATIC_DIR, "js", "main.js"),
        os.path.join(STATIC_DIR, "chronos_v110.css"),
    ]
    h = hashlib.md5()
    for fp in files_to_hash:
        if os.path.exists(fp):
            h.update(open(fp, "rb").read())
    return h.hexdigest()[:8]

ASSET_VERSION = _compute_asset_hash()
logger.info(f"Asset version hash: {ASSET_VERSION}")

# Disable Caching Middleware
@app.middleware("http")
async def add_no_cache_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    response = templates.TemplateResponse("index.html", {"request": request, "v": ASSET_VERSION})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.post("/upload")
async def process_file(
    file: UploadFile = File(...),
    artifact_type: str = Form(...),
    case_id: Optional[str] = Form(None),
    phase_id: Optional[str] = Form(None),
):
    from engine.ingestor import ingest_file, normalize_and_save
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)

        # STREAMING UPLOAD: Stream directly to disk to handle 6GB+ files
        # Chain of Custody: compute SHA256 hash during upload (zero extra I/O)
        sha256 = hashlib.sha256()
        with open(file_path, "wb") as buffer:
            while chunk := file.file.read(8192):
                sha256.update(chunk)
                buffer.write(chunk)
        file_hash = sha256.hexdigest()
        file_size = os.path.getsize(file_path)
        logger.info(f"Chain of Custody — {file.filename}: SHA256={file_hash}, Size={file_size}")

        ext = os.path.splitext(file.filename)[1].lower()

        # LOGIC BRANCH: Generic Report vs Forensic Artifact
        generic_exts = ['.csv', '.xlsx', '.tsv', '.parquet', '.json', '.jsonl', '.ndjson',
                        '.db', '.sqlite', '.sqlite3', '.pslist', '.txt', '.log', '.plist', '.zip']
        if ext in generic_exts:
            csv_filename = f"import_{file.filename.split('.')[0]}_{int(time.time())}.csv"
            dest_path = os.path.join(OUTPUT_DIR, csv_filename)

            row_count = "Unknown (Lazy)"
            file_cat = "generic"

            try:
                lf, df_eager, file_cat = ingest_file(file_path, ext)
                rc = normalize_and_save(lf, df_eager, dest_path)
                row_count = rc if rc >= 0 else "Unknown (Lazy)"
                processed_files[file.filename] = csv_filename

            except MemoryError:
                logger.warning("OOM during normalization. Using raw file.")
                shutil.copy(file_path, dest_path)
            except Exception as e:
                logger.error(f"Parsing error, saving raw: {e}")
                try:
                    shutil.copy(file_path, dest_path)
                except Exception as copy_e:
                    logger.error(f"Raw copy FAILED: {copy_e}")
                row_count = "Unknown"

            # Register file in case database if case context provided
            _file_id = None
            if case_id:
                try:
                    from engine.case_db import register_file as _reg_file
                    _rc = int(row_count) if isinstance(row_count, (int, float)) else 0
                    _file_id = _reg_file(
                        case_id=case_id, phase_id=phase_id,
                        original_filename=file.filename,
                        processed_filename=csv_filename,
                        sha256=file_hash, file_size=file_size,
                        file_category=file_cat, row_count=_rc,
                    )
                except Exception as reg_e:
                    logger.warning(f"Case file registration failed: {reg_e}")

            return {
                "status": "success",
                "message": "File uploaded successfully",
                "data_url": f"/api/data/{csv_filename}",
                "csv_filename": csv_filename,
                "xlsx_filename": None,
                "processed_records": row_count,
                "file_category": file_cat,
                "original_filename": file.filename,
                "file_id": _file_id,
                "chain_of_custody": {
                    "sha256": file_hash,
                    "file_size_bytes": file_size,
                    "original_filename": file.filename,
                }
            }

        # Forensic Processing (MFT/EVTX)
        result_json = generate_unified_timeline(file_path, artifact_type, OUTPUT_DIR)
        result = json.loads(result_json)

        if result.get("status") != "success":
            return JSONResponse(content={"error": result.get("error", "Unknown error")}, status_code=500)

        result['file_category'] = 'forensic'
        csv_path = result['files']['csv']
        filename = os.path.basename(csv_path)
        processed_files[file.filename] = filename

        # Register forensic file in case database
        _file_id = None
        if case_id:
            try:
                from engine.case_db import register_file as _reg_file
                _file_id = _reg_file(
                    case_id=case_id, phase_id=phase_id,
                    original_filename=file.filename,
                    processed_filename=filename,
                    sha256=file_hash, file_size=file_size,
                    file_category='forensic',
                    row_count=result.get("processed_records", 0) or 0,
                )
            except Exception as reg_e:
                logger.warning(f"Case file registration failed: {reg_e}")

        return {
            "status": "success",
            "message": "File processed successfully",
            "data_url": f"/api/data/{filename}",
            "processed_records": result.get("processed_records"),
            "csv_filename": filename,
            "xlsx_filename": os.path.basename(result['files']['excel']),
            "original_filename": file.filename,
            "file_id": _file_id,
            "chain_of_custody": {
                "sha256": file_hash,
                "file_size_bytes": file_size,
                "original_filename": file.filename,
            }
        }

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/data/{filename}")
async def get_data(request: Request, filename: str, page: int = 1, size: int = 50, query: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None, col_filters: Optional[str] = None, sort_col: Optional[str] = None, sort_dir: Optional[str] = None):
    import polars as pl
    import numpy as np
    import traceback
    import math

    # Tabulator sends sort as sort[0][field] / sort[0][dir] — map to our params
    _sort_col = request.query_params.get("sort[0][field]") or sort_col
    _sort_dir = request.query_params.get("sort[0][dir]") or sort_dir

    try:
        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        try:
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            try:
                lf.collect().head(1)
            except:
                lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)
        except Exception as scan_err:
             logger.error(f"Error scanning csv {csv_path}: {scan_err}")
             return JSONResponse(content={"error": str(scan_err)}, status_code=500)

        try:
            # 1. Assign stable row IDs BEFORE any filtering if they don't exist
            # This ensures that frontend row selection (which keys on _id) is stable across filters
            schema_names = lf.collect_schema().names()
            if "_id" not in schema_names:
                lf = lf.with_row_index(name="_id", offset=1)

            # Count unfiltered total BEFORE applying filters
            total_unfiltered = lf.select(pl.len()).collect(engine="streaming").item()

            # Apply Unified Processing (query, filters, time range, sort)
            params = {
                "query": query,
                "col_filters": col_filters,
                "start_time": start_time,
                "end_time": end_time,
                "sort_col": _sort_col,
                "sort_dir": _sort_dir
            }
            lf = _apply_standard_processing(lf, params)

            # Calculate total rows BEFORE slicing (filtered count)
            total_rows = lf.select(pl.len()).collect(engine="streaming").item()
            last_page = math.ceil(total_rows / size) if size > 0 else 1
            offset = (page - 1) * size

            if total_rows == 0:
                 return {
                     "current_page": page,
                     "last_page": last_page,
                     "data": [],
                     "total": 0,
                     "total_unfiltered": total_unfiltered,
                     "start_time": None,
                     "end_time": None
                 }

            # Try to determine max/min time overall for the view
            view_start = None
            view_end = None
            try:
                schema = lf.collect_schema()
                if "Time" in schema.names():
                    time_stats = lf.select([
                        pl.col("Time").min().alias("min_time"),
                        pl.col("Time").max().alias("max_time")
                    ]).collect()
                    if len(time_stats) > 0:
                        view_start = time_stats[0, "min_time"]
                        view_end = time_stats[0, "max_time"]
                        if view_start: view_start = str(view_start)
                        if view_end: view_end = str(view_end)
            except Exception as e:
                logger.warning(f"Could not calculate global time bounds: {e}")

            # Final Pagination
            q = lf.slice(offset, size)

            # Final normalization for display
            q = normalize_time_columns_in_df(q)
            df_page = q.collect(engine="streaming")

            return {
                "current_page": page,
                "last_page": last_page,
                "data": df_page.to_dicts(),
                "total": total_rows,
                "total_unfiltered": total_unfiltered,
                "start_time": view_start,
                "end_time": view_end
            }


        except Exception as p_err:
            logger.error(f"Polars error in get_data: {p_err}")
            # traceback.print_exc() # Reduce noise
            traceback.print_exc()
            return JSONResponse(content={"error": str(p_err)}, status_code=500)

    except Exception as e:
        logger.error(f"General error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


from engine.analyzer import analyze_dataframe


@app.get("/api/empty_columns/{filename}")
async def get_empty_columns(filename: str, query: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None, col_filters: Optional[str] = None, selected_ids: Optional[str] = None):
    """
    Identifies completely empty columns (all nulls or empty strings).
    Calculated via Polars lazy evaluation for out-of-core extremely large files.
    Applies current ui filters to ensure accuracy against the active view.
    """
    import polars as pl
    import json
    import functools, operator
    try:
        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        # Scan to get lazy frame
        try:
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            lf.collect().head(1)
        except:
            lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)

        schema = lf.collect_schema()
        all_cols = schema.names()

        # Parse selected_ids from JSON string if provided
        parsed_selected_ids = []
        if selected_ids:
            try:
                parsed_selected_ids = json.loads(selected_ids)
            except (json.JSONDecodeError, TypeError):
                pass

        # Apply Unified Processing
        params = {
            "query": query,
            "col_filters": col_filters,
            "start_time": start_time,
            "end_time": end_time,
            "selected_ids": parsed_selected_ids
        }
        lf = _apply_standard_processing(lf, params)

        # Build lazy expressions to check if every row in a column is null, empty string, or common null indicators
        exprs = []
        # Common string representations of null/empty in forensics
        null_regex = r"^(?i)(-+|n/?a|null|none|nan|undefined|unknown|\s*)$"

        for c in all_cols:
            exprs.append(
                (
                    pl.col(c).is_null() |
                    (pl.col(c).cast(pl.Utf8, strict=False).str.contains(null_regex).fill_null(False))
                ).all().alias(c)
            )

        # Collect this single row result
        res = lf.select(exprs).collect(engine="streaming")

        # Exclude internal/index columns that always contain data
        INTERNAL_COLS = {"_id", "No.", "Original_No."}
        empty_cols = [c for c in all_cols if res[c][0] and c not in INTERNAL_COLS]

        return {"empty_columns": empty_cols}

    except Exception as e:
        logger.error(f"Error checking empty columns: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/api/histogram/{filename}")
async def get_histogram(filename: str, exclude_id: str = None, start_time: str = None, end_time: str = None, query: str = None, col_filters: str = None, selected_ids: str = None):
    """
    Get Histogram for FULL file (standard view).
    Supports ?exclude_id=4624 to hide specific EventID.
    Supports time filtering ?start_time=..&end_time=..
    Supports column filters ?col_filters={"EventID":"2050"}
    """
    try:
        import datetime
        def log_step(msg):
            with open("/tmp/chronos_histogram_error.log", "a") as f:
                f.write(f"{datetime.datetime.now()} - {msg}\n")

        log_step(f"get_histogram called with filename: '{filename}'")

        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            log_step(f"File not found: {csv_path}")
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        # Lazy Load Logic
        log_step("Starting Lazy Load Logic")
        try:
            df = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            df.collect().head(1)  # Test if it works
            log_step("scan_csv (strict) succeeded")
        except:
            df = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)
            log_step("scan_csv (lossy) succeeded")

        log_step("collecting schema")
        schema_names = df.collect_schema().names()
        if "_id" not in schema_names:
            df = df.with_row_index(name="_id", offset=1)

        # Apply Unified Processing
        log_step("Applying _apply_standard_processing")
        params = {
            "query": query,
            "col_filters": col_filters,
            "start_time": start_time,
            "end_time": end_time,
            "selected_ids": selected_ids
        }
        df = _apply_standard_processing(df, params)

        # Apply Forensic Discernment (Sanitization & Hunting)
        log_step("Applying sanitize_context_data")
        try:
            df = sanitize_context_data(df)
        except Exception as e:
            log_step(f"Forensic discernment failed for histogram: {e}")

        log_step("Calling analyze_dataframe")
        result = analyze_dataframe(df, start_time=start_time, end_time=end_time)
        log_step("analyze_dataframe finished")
        return result

    except Exception as e:
        import traceback
        import datetime
        with open("/tmp/chronos_histogram_error.log", "a") as f:
            f.write(f"{datetime.datetime.now()} - Error in get_histogram: {e}\n")
            f.write(f"Traceback: {traceback.format_exc()}\n")
        logger.error(f"Error in histogram: {e}")
        return {"error": str(e)}

class SubsetRequest(BaseModel):
    filename: str
    selected_ids: List[Any]
    query: Optional[str] = ""
    col_filters: Any = {}
    start_time: Optional[str] = ""
    end_time: Optional[str] = ""

@app.get("/api/timeseries/{filename}")
async def get_timeseries(filename: str):
    """
    Timeseries analysis endpoint — uses chronos_timeseries_builder skill.
    Returns structured chart data with trend analysis and peak detection.
    """
    try:
        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=10000)
        time_col = get_primary_time_column(lf.collect_schema().names())

        # Import and run the timeseries builder skill
        import sys as _sys
        _skill_path = os.path.join(BASE_DIR, ".agents", "skills", "chronos_timeseries_builder")
        if _skill_path not in _sys.path:
            _sys.path.append(_skill_path)
        from builder import build_chronos_timeseries

        result = await asyncio.to_thread(build_chronos_timeseries, lf, time_col)
        return result
    except Exception as e:
        logger.error(f"Timeseries error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/api/histogram_subset")
async def get_histogram_subset(req: SubsetRequest):
    """
    Generate histogram for ONLY the selected rows.
    Loads and sorts data the same way as get_data to ensure _id alignment.
    """
    try:
        csv_path = os.path.join(OUTPUT_DIR, req.filename)
        if not os.path.exists(csv_path):
            return {"error": "File not found"}

        # Load CSV
        try:
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
        except:
            lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)

        schema = lf.collect_schema()

        # Apply Unified Processing (all active filters + selected rows)
        params = {
            "query": req.query,
            "col_filters": req.col_filters,
            "start_time": req.start_time,
            "end_time": req.end_time,
            "selected_ids": req.selected_ids
        }
        lf = _apply_standard_processing(lf, params)
        df_subset = lf.drop("_id").collect()

        if df_subset.height == 0:
            return {"error": "No matching rows found"}

        result = analyze_dataframe(df_subset, target_bars=30)
        if "error" in result:
            return result

        # Override global_stats with REAL stats from the FULL dataset
        # (analyze_dataframe computed them from the subset which is wrong)
        full_df = lf.drop("_id").collect()
        full_result = analyze_dataframe(full_df, target_bars=50)
        if "global_stats" in full_result:
            result["global_stats"] = full_result["global_stats"]
        elif "datasets" in full_result:
            # Fallback: compute from full result's datasets
            all_vals = []
            for ds in full_result.get("datasets", []):
                if ds.get("type") not in ("line", "scatter"):
                    all_vals.extend([v for v in ds.get("data", []) if v is not None])
            if all_vals:
                result["global_stats"] = {
                    "max_bucket": int(max(all_vals)),
                    "mean_bucket": round(sum(all_vals) / len(all_vals), 1),
                    "min_bucket": int(min(all_vals)),
                    "total_events": full_df.height,
                    "total_buckets": len(all_vals)
                }

        result['interpretation'] = "Filtered View: " + result.get('interpretation', '')
        return result

    except Exception as e:
        import traceback
        logger.error(f"Error in subset histogram: {e}")
        traceback.print_exc()
        return {"error": str(e)}
        return {"error": str(e)}


@app.get("/download/{filename}")
async def download_file(filename: str, background_tasks: BackgroundTasks):
    file_path = os.path.join(OUTPUT_DIR, filename)
    if os.path.exists(file_path):
        background_tasks.add_task(delete_file, file_path)
        return FileResponse(file_path, filename=filename, media_type='application/octet-stream')
    return JSONResponse(content={"error": "File not found"}, status_code=404)

class FilterModel(BaseModel):
    field: str
    type: str
    value: Any

class ExportRequest(BaseModel):
    filename: str
    col_filters: Any = {}
    selected_ids: list = []
    format: str = "csv"
    query: Optional[str] = ""
    start_time: Optional[str] = ""
    end_time: Optional[str] = ""
    ai_optimized: bool = False
    visible_columns: list[str] = []
    original_filename: str = ""
    sort_col: Optional[str] = None
    sort_dir: Optional[str] = None
    chunk_size_mb: Optional[int] = 99
    zip_format: Optional[str] = "csv"  # "csv" or "json"

class ReportRequest(BaseModel):
    filename: str
    query: Optional[str] = ""
    col_filters: Any = {}
    selected_ids: list = []
    start_time: Optional[str] = ""
    end_time: Optional[str] = ""
    sort_col: Optional[str] = None
    sort_dir: Optional[str] = None

# Helper to delete file (used in background tasks)
def delete_file(path: str):
    import time as _t
    try:
        # Delay deletion to ensure the browser finishes downloading the file
        _t.sleep(10)
        if os.path.exists(path):
            os.remove(path)
            logger.info(f"Background cleanup: Deleted {path}")
    except Exception as e:
        logger.error(f"Error in background cleanup of {path}: {e}")

@app.post("/api/forensic_report")
async def forensic_report(request: ReportRequest):
    import polars as pl
    import os
    import time
    from fastapi.responses import JSONResponse

    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)

        # Assign stable row IDs if they don't exist (needed by _apply_standard_processing)
        schema_names = lf.collect_schema().names()
        if "_id" not in schema_names:
            lf = lf.with_row_index(name="_id", offset=1)

        # Apply Unified Processing
        params = {
            "query": request.query,
            "col_filters": request.col_filters,
            "start_time": request.start_time,
            "end_time": request.end_time,
            "sort_col": request.sort_col,
            "sort_dir": request.sort_dir,
            "selected_ids": request.selected_ids
        }
        lf = _apply_standard_processing(lf, params)

        df = lf.collect()

        # --- CHRONOS MASTER ANALYZER (Parallel Execution) ---
        from engine.forensic import (sub_analyze_timeline, sub_analyze_context,
            sub_analyze_hunting, sub_analyze_identity_and_procs,
            correlate_cross_source, group_sessions, detect_execution_artifacts)

        import asyncio
        start_p = time.perf_counter()

        # Pre-process time columns
        df_p = df.clone()
        for col in TIME_HIERARCHY:
            if col in df_p.columns:
                try:
                    df_p = df_p.with_columns(pl.col(col).str.to_datetime(strict=False))
                except: pass

        from engine.sigma_engine import match_sigma_rules, load_sigma_rules

        # YARA scan helper — best-effort, first 5MB of CSV text
        def _yara_scan_for_report(file_path):
            yara_rules = _load_yara_rules()
            if yara_rules is None:
                return []
            try:
                with open(file_path, "r", errors="replace") as f:
                    text = f.read(5 * 1024 * 1024)
                matches = yara_rules.match(data=text)
                return [{
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "strings_matched": len(m.strings),
                    "meta": {k: str(v) for k, v in (m.meta or {}).items()} if hasattr(m, 'meta') and m.meta else {},
                } for m in matches]
            except Exception as e:
                logger.debug(f"YARA scan in forensic report: {e}")
                return []

        tasks = [
            asyncio.to_thread(sub_analyze_timeline, df_p),       # 0
            asyncio.to_thread(sub_analyze_context, df_p),         # 1
            asyncio.to_thread(sub_analyze_hunting, df_p),         # 2
            asyncio.to_thread(sub_analyze_identity_and_procs, df_p),  # 3
            asyncio.to_thread(match_sigma_rules, df_p, load_sigma_rules()),  # 4
            asyncio.to_thread(correlate_cross_source, df_p),      # 5
            asyncio.to_thread(group_sessions, df_p),              # 6
            asyncio.to_thread(detect_execution_artifacts, df_p),  # 7
            asyncio.to_thread(_yara_scan_for_report, csv_path),   # 8
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        formatted_results = []
        sigma_hits_result = []
        correlation_result = {}
        session_result = []
        exec_artifacts_result = {}
        yara_hits_result = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                if i == 4:
                    logger.debug(f"Sigma engine error: {r}")
                elif i == 8:
                    logger.debug(f"YARA scan error: {r}")
                elif i >= 5:
                    logger.debug(f"Skill task {i} error: {r}")
                else:
                    formatted_results.append(f"### Error in Analysis ###\n{str(r)}")
            elif i == 4:
                sigma_hits_result = r if isinstance(r, list) else []
            elif i == 5:
                correlation_result = r if isinstance(r, dict) else {}
            elif i == 6:
                session_result = r if isinstance(r, list) else []
            elif i == 7:
                exec_artifacts_result = r if isinstance(r, dict) else {}
            elif i == 8:
                yara_hits_result = r if isinstance(r, list) else []
            else:
                formatted_results.append(r)

        # MITRE kill chain mapping (fast, runs on sigma_hits — no separate thread needed)
        from engine.forensic import map_mitre_from_sigma
        mitre_kill_chain = map_mitre_from_sigma(sigma_hits_result)

        # --- THREAT INTELLIGENCE ENRICHMENT (non-blocking, post-pipeline) ---
        enrichment_result = {}
        try:
            from engine.enrichment import deduplicate_iocs, enrich_all_iocs, load_api_keys
            api_keys = load_api_keys()
            if any(api_keys.values()):
                # Extract context_data from Task 1 results
                context_data = {}
                for r in formatted_results:
                    if isinstance(r, dict) and r.get("type") == "context":
                        context_data = r
                        break
                iocs = deduplicate_iocs(context_data, session_result, correlation_result)
                if any(iocs.values()):
                    enrichment_result = await asyncio.wait_for(
                        enrich_all_iocs(iocs, api_keys),
                        timeout=30.0
                    )
                    logger.info(f"Enrichment: {enrichment_result.get('total_enriched', 0)} IOCs enriched via {len(enrichment_result.get('providers_used', []))} providers")
        except asyncio.TimeoutError:
            logger.warning("Enrichment timed out after 30s, returning partial results")
        except Exception as e:
            logger.debug(f"Enrichment phase skipped: {e}")

        end_p = time.perf_counter()
        logger.info(f"Forensic Report generated in {end_p - start_p:.2f}s for {df.height} records | Sigma hits: {len(sigma_hits_result)} | YARA hits: {len(yara_hits_result)} | Correlations: {correlation_result.get('total_correlated', 0)} | Sessions: {len(session_result)} | Artifacts: {len(exec_artifacts_result.get('artifact_types_detected', []))}")

        # --- Derive dashboard card values from data ---
        cols = df.columns

        # Top Tactic: use Tactic col, else CommandLine most common, else first text col
        top_tactic = "N/A"
        # WAF columns first, then Windows event columns
        _bad_values = {
            "-", "null", "none", "n/a", "", "nan", "undefined",
            "macos_unified_log", "macos_persistence_info", "macos_bulk_plist",
            "volatility_ram_process", "macos_plist_item", "unknown"
        }
        for tac_col in ["ViolationCategory", "ViolationType", "Protection", "Title", "Tactic", "EventID", "Provider", "Channel"]:
            if tac_col in cols:
                try:
                    vc = (df.select(pl.col(tac_col).cast(pl.Utf8, strict=False))
                          .to_series()
                          .drop_nulls()
                          .filter(~pl.Series(
                              [str(v).strip().lower() in _bad_values
                               for v in df.select(pl.col(tac_col).cast(pl.Utf8, strict=False)).to_series().drop_nulls().to_list()]
                          ))
                          .value_counts(sort=True))
                    if len(vc) > 0:
                        val = str(vc[0, tac_col]).strip()
                        if val.lower() not in _bad_values:
                            # If value is numeric, label it as Windows EventID
                            if val.isdigit():
                                try:
                                    from engine.forensic import SYSMON_EVENT_LABELS
                                    _elabel = SYSMON_EVENT_LABELS.get(val, "Windows Event")
                                    top_tactic = f"Win EventID {val}: {_elabel}"
                                except:
                                    top_tactic = f"Win EventID {val}"
                            else:
                                top_tactic = val
                except: pass
                if top_tactic != "N/A":
                    break

        # Primary Identity: Check Context Data explicitly to unify mappings
        primary_identity = "N/A"
        try:
            # results[1] is the sub_analyze_context dictionary
            context_data = results[1] if isinstance(results[1], dict) else {}
            if context_data.get("users"):
                primary_identity = context_data["users"][0].get("id", "N/A")
            elif context_data.get("ips"):
                primary_identity = context_data["ips"][0].get("id", "N/A")
        except:
             pass

        if primary_identity == "N/A":
             for id_col in ["User", "ProcessUser", "SubjectUserName", "AccountName", "UserName", "primary_user"]:
                 if id_col in cols:
                     try:
                         vc = df.select(pl.col(id_col).drop_nulls().filter(pl.col(id_col) != "-")).to_series().value_counts(sort=True)
                         if len(vc) > 0:
                             primary_identity = str(vc[0, id_col])
                     except: pass
                     break

        # Risk Level: compute using Smart Risk Engine M4 (with Sigma hits from parallel run)
        risk_score = 0
        risk_justify = []
        try:
            from engine.forensic import calculate_smart_risk_m4
            risk_assessment = calculate_smart_risk_m4(df_parsed=df, sigma_hits=sigma_hits_result)
            risk_level = risk_assessment.get("Risk_Level", "Low")
            risk_score = risk_assessment.get("Risk_Score", 0)
            risk_justify = risk_assessment.get("Justification_Log", [])
        except Exception as e:
            logger.warning(f"Error calculating smart risk level: {e}")
            risk_level = "Low"

        # EPS: events per second
        eps = 0
        try:
            from engine.forensic import get_primary_time_column
            time_col = get_primary_time_column(cols)
            if time_col:
                _ts = (df[time_col]
                       .cast(pl.Utf8, strict=False)
                       .str.to_datetime(strict=False)
                       .drop_nulls())
                if len(_ts) > 1:
                    span = (_ts.max() - _ts.min()).total_seconds()
                    if span > 0:
                        eps = round(df.height / span, 4)
        except: pass

        return {
            "total_records": df.height,
            "results": formatted_results,
            "filename": request.filename,
            "top_tactic": top_tactic,
            "primary_identity": primary_identity,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_justify": risk_justify,
            "eps": eps,
            "sigma_hits": sigma_hits_result,
            "mitre_kill_chain": mitre_kill_chain,
            "cross_source_correlation": correlation_result,
            "session_profiles": session_result,
            "execution_artifacts": exec_artifacts_result,
            "yara_hits": yara_hits_result,
            "threat_intelligence": enrichment_result,
        }


    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

# --- Threat Intelligence Enrichment Endpoints ---

@app.get("/api/enrichment/config")
async def enrichment_config():
    """Return which enrichment providers are configured and cache stats."""
    try:
        from engine.enrichment import load_api_keys, get_active_providers
        from engine.enrichment_cache import EnrichmentCache
        keys = load_api_keys()
        cache = EnrichmentCache()
        return {
            "providers": get_active_providers(keys),
            "configured_keys": [k for k, v in keys.items() if v],
            "cache_stats": cache.stats(),
        }
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


class IOCLookupRequest(BaseModel):
    ioc_value: str
    ioc_type: str  # "ip", "domain", "hash", "email"


@app.post("/api/enrichment/lookup")
async def enrichment_lookup(request: IOCLookupRequest):
    """On-demand enrichment for a single IOC."""
    try:
        from engine.enrichment import enrich_single_ioc
        result = await asyncio.wait_for(
            enrich_single_ioc(request.ioc_value, request.ioc_type),
            timeout=15.0,
        )
        return result
    except asyncio.TimeoutError:
        return JSONResponse(content={"error": "Enrichment timed out"}, status_code=504)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/api/export_filtered")
async def export_filtered(request: ExportRequest, background_tasks: BackgroundTasks):
    import polars as pl
    import os
    import time
    from fastapi.responses import FileResponse, JSONResponse
    logger.info(f"[EXPORT_FILTERED] query={request.query!r}, col_filters={request.col_filters!r}, "
                f"start={request.start_time!r}, end={request.end_time!r}, format={request.format!r}, "
                f"selected_ids={request.selected_ids!r} (len={len(request.selected_ids) if request.selected_ids else 0})")

    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        try:
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            lf.collect().head(1)
        except:
            lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)

        # Assign stable row IDs BEFORE filtering if they don't exist
        schema = lf.collect_schema()
        if "_id" not in schema.names():
            lf = lf.with_row_index(name="_id", offset=1)

        # Apply Unified Processing
        params = {
            "query": request.query,
            "col_filters": request.col_filters,
            "start_time": request.start_time,
            "end_time": request.end_time,
            "sort_col": request.sort_col,
            "sort_dir": request.sort_dir,
            "selected_ids": request.selected_ids
        }
        lf = _apply_standard_processing(lf, params)

        # For specific selection exports, we want to maintain sequential 1,2,3... in the final file
        # rather than the global absolute row numbers from the main view (which might be 5, 20, 100...)
        if request.selected_ids:
             lf = lf.drop("_id").with_row_index(name="_id", offset=1)

        # --- 5. FORMAT AND SELECT COLUMNS ---
        lf = normalize_time_columns_in_df(lf)

        # Prepare schemas
        schema_final = lf.collect_schema()
        all_cols_final = schema_final.names()

        # Handle ID Column Rename safely
        id_col_name = "No."
        # If "No." already exists in data and it's NOT our ID column, rename it to avoid conflict
        if id_col_name in all_cols_final:
             lf = lf.rename({id_col_name: "Original_No."})

        # Rename _id to No.
        lf = lf.rename({"_id": id_col_name})

        # Re-fetch schema after rename
        schema_final = lf.collect_schema()
        all_cols_final = schema_final.names()

        # Filter Columns based on visible_columns
        if request.visible_columns:
            target_cols = []
            for c in request.visible_columns:
                # Front-end sends field names.
                # "No." column field is usually "_id" in frontend definitions,
                # but we just renamed "_id" to "No." in backend.
                if c == "_id" or c == "No.":
                    if "No." in all_cols_final:
                        target_cols.append(pl.col("No."))
                elif c in all_cols_final:
                        target_cols.append(pl.col(c))

            if target_cols:
                lf = lf.select(target_cols)
        else:
             # Default: Put "No." first
             if "No." in all_cols_final:
                 other_cols = [c for c in all_cols_final if c != "No."]
                 lf = lf.select(["No."] + other_cols)

        # Export Format
        fmt = request.format.lower()
        if fmt not in ["csv", "xlsx", "json"]:
            fmt = "csv"
        ext = fmt

        # AI Optimization: Limit rows to save LLM tokens and force CSV layout
        if request.ai_optimized:
            ext = "txt" # Summary report

        # Safety for filename
        base_name = request.original_filename or request.filename
        if not base_name: base_name = "data"
        if request.ai_optimized:
            base_name += "_Context"

        # Sanitize base_name
        base_name = sanitize_filename(base_name)

        out_filename = f"Export_{os.path.splitext(base_name)[0]}_{int(time.time())}.{ext}"
        out_path = os.path.join(OUTPUT_DIR, out_filename)

        if request.ai_optimized:
            # For Context, we collect the full filtered dataset to calculate statistics
            # Note: For extremely large datasets, we might want to do this lazily,
            # but for IR artifacts it's generally manageable.
            df = lf.collect()
            try:
                from engine.forensic import generate_export_payloads
                import json

                # Run YARA scan on the source CSV for the context export
                yara_context_hits = []
                try:
                    yara_rules = _load_yara_rules()
                    if yara_rules:
                        with open(csv_path, "r", errors="replace") as yf:
                            yara_text = yf.read(5 * 1024 * 1024)
                        yara_matches = yara_rules.match(data=yara_text)
                        yara_context_hits = [{
                            "rule": m.rule, "namespace": m.namespace,
                            "tags": list(m.tags), "strings_matched": len(m.strings),
                            "meta": {k: str(v) for k, v in (m.meta or {}).items()} if hasattr(m, 'meta') and m.meta else {},
                        } for m in yara_matches]
                except Exception as ye:
                    logger.debug(f"YARA in context export: {ye}")

                intel_payloads = generate_export_payloads(df, yara_hits=yara_context_hits)
                context_json_str = intel_payloads.get("context_json", "{}")

                out_filename = out_filename.replace(".txt", ".json")
                out_path = os.path.join(OUTPUT_DIR, out_filename)

                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(context_json_str)

            except Exception as ai_err:
                logger.error(f"Context Report generation failed: {ai_err}")
                stats_header = f"Error generating Context report: {ai_err}\n"
                stats_header += f"Total Filtered Events: {len(df)}\n"
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(stats_header)

            return JSONResponse(content={"download_url": f"/download/{out_filename}", "filename": out_filename})

        if ext == "csv":
            # Remove internal analysis columns (Validated_EventID) before export
            _exp_schema = lf.collect_schema()
            _internal_cols = {"Validated_EventID", "_epoch_tmp_", "_ts_sort_", "_bucket"}
            _drop_internal = [c for c in _exp_schema.names() if c in _internal_cols]
            if _drop_internal:
                lf = lf.drop(_drop_internal)
                _exp_schema = lf.collect_schema()
            # Cast ALL non-string columns to Utf8 to preserve hex, hashes, GUIDs
            _csv_cast = [
                pl.col(c).cast(pl.Utf8)
                for c, dtype in _exp_schema.items()
                if dtype not in [pl.Utf8, pl.String]
            ]
            if _csv_cast:
                lf = lf.with_columns(_csv_cast)
            # Wrap hex-like values (0x...) in Excel formula ="..." to prevent
            # Excel/Numbers auto-conversion of hex strings to decimal numbers.
            _hex_prone_kw = {"hash", "hex", "guid", "address", "ostype", "sid"}
            _hex_col_names = [c for c in _exp_schema.names()
                              if any(k in c.lower() for k in _hex_prone_kw)
                              or c in {"OsType", "SrcFileHashId", "Hash", "TargetFileHashId"}]
            if _hex_col_names:
                _hex_wrap = [
                    pl.when(pl.col(c).str.contains(r"^0[xX]"))
                      .then(pl.concat_str([pl.lit('="'), pl.col(c), pl.lit('"')]))
                      .otherwise(pl.col(c))
                      .alias(c)
                    for c in _hex_col_names
                    if c in _exp_schema.names()
                ]
                if _hex_wrap:
                    lf = lf.with_columns(_hex_wrap)
            # Write CSV with UTF-8 BOM so Excel recognizes encoding and preserves text.
            # quote_style='always' quotes EVERY field unconditionally.
            import tempfile
            _tmp_csv = out_path + ".tmp"
            lf.sink_csv(_tmp_csv, quote_style="always")
            # Prepend BOM to force Excel to treat file as UTF-8 text
            with open(_tmp_csv, "rb") as _src, open(out_path, "wb") as _dst:
                _dst.write(b"\xef\xbb\xbf")  # UTF-8 BOM
                _dst.write(_src.read())
            os.remove(_tmp_csv)
        elif ext == "json":
            # Export as standard JSON array [{...}, {...}] — readable by any tool
            cast_exprs = []
            for col, dtype in lf.collect_schema().items():
                if dtype in [pl.Object, pl.Null] or isinstance(dtype, (pl.List, pl.Struct)):
                    cast_exprs.append(pl.col(col).cast(pl.Utf8))
            if cast_exprs:
                lf = lf.with_columns(cast_exprs)
            df = lf.collect(engine="streaming")
            # Use Python json.dump for proper array format (Polars removed row_oriented kwarg)
            import json as _json_mod
            with open(out_path, "w", encoding="utf-8") as _jf:
                _json_mod.dump(df.to_dicts(), _jf, ensure_ascii=False, default=str)
        else:
            # XLSX Memory Leak Protection: Limit row count for Excel exports
            row_count = lf.select(pl.len()).collect().item()
            XLSX_ROW_LIMIT = 100000
            if row_count > XLSX_ROW_LIMIT:
                return JSONResponse(
                    content={"error": f"Dataset too large for Excel export ({row_count} rows). Please filter your data below {XLSX_ROW_LIMIT} rows or use CSV/JSON export."},
                    status_code=400
                )

            df = lf.collect()

            # Remove internal analysis columns
            _internal_xlsx = {"Validated_EventID", "_epoch_tmp_", "_ts_sort_", "_bucket"}
            df = df.drop([c for c in df.columns if c in _internal_xlsx])

            # Preserve Hexadecimal formatting and other strings by casting to Utf8
            problematic_cols = ["OsType", "SrcFileHashId", "Hash", "TargetFileHashId", "EventID", "EventId", "No.", "Original_No."]
            cast_exprs = []
            for col in df.columns:
                dtype = df.schema[col]
                # Cast hex/id/hash columns and any non-string column to Utf8 to preserve values
                if col in problematic_cols or any(k in col.lower() for k in ["hash", "id", "guid", "address", "hex"]):
                   cast_exprs.append(pl.col(col).cast(pl.Utf8))
                elif dtype == pl.Null or dtype == pl.Object:
                   cast_exprs.append(pl.col(col).cast(pl.Utf8))

            if cast_exprs:
                df = df.with_columns(cast_exprs)

            # Write XLSX with explicit text formatting for hex/hash/guid columns
            # to prevent Excel from auto-converting values like 0x00000030 to numbers
            import xlsxwriter
            workbook = xlsxwriter.Workbook(out_path, {'strings_to_numbers': False})
            worksheet = workbook.add_worksheet("Data")
            header_fmt = workbook.add_format({'bold': True, 'bg_color': '#1e3a5f', 'font_color': '#ffffff'})
            text_fmt = workbook.add_format({'num_format': '@'})  # Force text format

            # Identify columns that need text-force (hex, hash, guid, id patterns)
            _hex_keywords = {"hash", "hex", "guid", "address", "ostype", "sid", "id"}
            _text_force_cols = set()
            for idx, col in enumerate(df.columns):
                cl = col.lower()
                if col in problematic_cols or any(k in cl for k in _hex_keywords):
                    _text_force_cols.add(idx)

            # Force TEXT format at COLUMN level for hex/hash/guid columns
            # This prevents Numbers.app/Excel from auto-converting "0x00000030" to 30
            for idx in _text_force_cols:
                worksheet.set_column(idx, idx, None, text_fmt)

            # Write headers
            for col_idx, col_name in enumerate(df.columns):
                worksheet.write(0, col_idx, col_name, header_fmt)

            # Write data rows — use write_string for ALL cells to prevent
            # Excel auto-conversion of hex (0x...), large numbers, GUIDs, etc.
            for row_idx, row in enumerate(df.iter_rows()):
                for col_idx, val in enumerate(row):
                    if val is None:
                        worksheet.write_blank(row_idx + 1, col_idx, None)
                    elif col_idx in _text_force_cols:
                        worksheet.write_string(row_idx + 1, col_idx, str(val), text_fmt)
                    else:
                        # Use write_string for everything to prevent auto-conversion
                        worksheet.write_string(row_idx + 1, col_idx, str(val))

            worksheet.autofit()
            workbook.close()

        # Do NOT delete the file here. The frontend expects a JSON with download_url,
        # and the `/download/{filename}` route handles deleting the file after serving it.
        return JSONResponse(content={"download_url": f"/download/{out_filename}", "filename": out_filename})


    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/api/export/html")
async def export_html(request: ExportRequest, background_tasks: BackgroundTasks):
    """
    Generate a standalone HTML forensic report.
    """
    import polars as pl
    import os
    import time
    from fastapi.responses import JSONResponse
    from datetime import datetime

    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        try:
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            lf.collect().head(1)
        except:
            lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)

        # Apply Filters (Same as export_filtered)
        schema = lf.collect_schema()

        # Assign stable row IDs BEFORE filtering if they don't exist
        if "_id" not in schema.names():
            lf = lf.with_row_index(name="_id", offset=1)

        params = {
            "query": request.query,
            "col_filters": request.col_filters,
            "start_time": request.start_time,
            "end_time": request.end_time,
            "selected_ids": request.selected_ids
        }
        lf = _apply_standard_processing(lf, params)

        if request.selected_ids:
             lf = lf.drop("_id").with_row_index(name="_id", offset=1)

        # Get Chart Data
        chart_data = analyze_dataframe(lf, target_bars=50)

        # Get Full Count (Filtered)
        df_full = lf.collect()
        total_filtered = df_full.height
        all_cols = df_full.columns

        # Generate Smart Actionable Intel
        try:
            from engine.forensic import generate_export_payloads
            intel_payloads = generate_export_payloads(df_full)
            html_intel = intel_payloads.get("html_data", {})
            try:
                from engine.forensic import sub_analyze_context, sub_analyze_hunting
                context_data = sub_analyze_context(df_full)
                hunting_data = sub_analyze_hunting(df_full)
            except Exception:
                context_data = {"type": "context", "event_ids": [], "tactics": [], "threat_actors": []}
                hunting_data = {"type": "hunting", "patterns": [], "network": []}

            context_data["actionable_iocs"] = html_intel.get("Critical_Findings_Table", [])
            context_data["system_anomalies"] = html_intel.get("Anomalous_Processes_Table", [])
        except Exception as e:
            logger.error(f"Error in export analysis actionable intel: {e}")
            context_data = {"type": "context", "event_ids": [], "tactics": [], "threat_actors": []}
            hunting_data = {"type": "hunting", "patterns": [], "network": []}

        threat_actors = context_data.get("threat_actors", [])

        # Get Stats for summary banner
        stats = chart_data.get("stats", {})
        time_range_str = f"{stats.get('start_time', 'N/A')} to {stats.get('end_time', 'N/A')}"

        # === EPS — compute directly from df_full timestamps ===
        eps = stats.get("eps", 0)
        try:
            _time_col_eps = get_primary_time_column(all_cols)
            if _time_col_eps and df_full.height > 1:
                _ts_series = df_full[_time_col_eps].cast(pl.Utf8).str.to_datetime(strict=False)
                _ts_min = _ts_series.drop_nulls().min()
                _ts_max = _ts_series.drop_nulls().max()
                if _ts_min and _ts_max:
                    _dur = (_ts_max - _ts_min).total_seconds()
                    if _dur > 0:
                        eps = round(df_full.height / _dur, 4)
        except Exception as _e_eps:
            logger.warning(f"Direct EPS calculation failed: {_e_eps}")

        # Identity Logic (Top Source/User)
        top_id = "N/A"
        if context_data.get("users"):
             top_id = context_data["users"][0].get("id", "N/A")
        elif context_data.get("ips"):
             top_id = context_data["ips"][0].get("id", "N/A")

        if top_id == "N/A" and not df_full.is_empty():
             # Try to find common identity columns
             id_cols = [c for c in all_cols if any(k in c.lower() for k in ["user", "subject", "account", "source_name"])]
             if id_cols:
                  try:
                       top_id_df = df_full.group_by(id_cols[0]).count().sort("count", descending=True).limit(1)
                       if not top_id_df.is_empty():
                            top_id = str(top_id_df[0, 0])
                  except:
                       pass

        # Additional aggregations for GoAccess / ELK style report
        top_events = []
        _synthetic_eid_bad = {
            "macos_unified_log", "macos_persistence_info", "macos_bulk_plist",
            "volatility_ram_process", "macos_plist_item", "unknown", "null", "none", "n/a", "-", ""
        }
        if "EventID" in all_cols:
             try:
                  lf_clean = lf.with_columns(pl.col("EventID").cast(pl.Utf8, strict=False).str.replace(r"\.0$", "").alias("_clean_event_id"))
                  vc = (lf_clean
                        .filter(pl.col("_clean_event_id").is_not_null() &
                                (~pl.col("_clean_event_id").str.to_lowercase().is_in(list(_synthetic_eid_bad))))
                        .group_by("_clean_event_id").count().sort("count", descending=True).limit(5).collect())
                  top_events = [{"name": str(row["_clean_event_id"]), "count": row["count"]} for row in vc.to_dicts()]
             except: pass

        top_providers = []
        provider_cols = ["providername", "source", "logname", "provider_name"]
        p_col_match = next((c for c in all_cols if c.lower() in provider_cols), None)
        if p_col_match:
             try:
                  vc = lf.drop_nulls(p_col_match).group_by(p_col_match).count().sort("count", descending=True).limit(5).collect()
                  top_providers = [{"name": str(row[p_col_match]), "count": row["count"]} for row in vc.to_dicts()]
             except: pass

        df_len = total_filtered
        _sigma_hits_html = []  # Initialize BEFORE try block to ensure it's always defined
        try:
            from engine.forensic import calculate_smart_risk_m4
            from engine.sigma_engine import match_sigma_rules, load_sigma_rules
            _sigma_rules_html = load_sigma_rules()
            _sigma_hits_html = match_sigma_rules(df_full, _sigma_rules_html)
            logger.info(f"[HTML_REPORT] Sigma matched: {len(_sigma_hits_html)} rules")
            _risk_html = calculate_smart_risk_m4(df_parsed=df_full, sigma_hits=_sigma_hits_html)
            risk_level = _risk_html.get("Risk_Level", "Low")
            risk_score = _risk_html.get("Risk_Score", 0)
            risk_justify = _risk_html.get("Justification_Log", [])
        except Exception as _re:
            logger.warning(f"HTML report risk calculation failed: {_re}")
            risk_level = "Low"
            risk_score = 0
            risk_justify = []

        # NOTE: eps was already calculated directly from df_full timestamps above (line ~1407).
        # Do NOT re-assign from stats here — that was overwriting the correct value with 0.

        # === Top Tactic for HTML Report (WAF-aware + Windows EVTX) ===
        top_tactic_report = "N/A"
        _tac_bad = {
            "-", "null", "none", "n/a", "", "nan", "undefined", "unknown",
            "macos_unified_log", "macos_persistence_info", "macos_bulk_plist",
            "volatility_ram_process", "macos_plist_item"
        }
        if not df_full.is_empty():
            _tac_cols = ["ViolationCategory", "ViolationType", "Protection", "Tactic",
                         "TaskCategory", "Subcategory", "Channel", "Title", "EventID"]
            for tac_col in _tac_cols:
                if tac_col in df_full.columns:
                    try:
                        _ser = (df_full[tac_col]
                                .cast(pl.Utf8, strict=False)
                                .drop_nulls()
                                .filter(pl.Series([str(v).strip().lower() not in _tac_bad
                                                   for v in df_full[tac_col]
                                                   .cast(pl.Utf8, strict=False)
                                                   .fill_null("")])))
                        _counts = _ser.value_counts(sort=True)
                        if len(_counts) > 0:
                            val = str(_counts[0, tac_col]).strip()
                            if val.lower() not in _tac_bad:
                                top_tactic_report = val
                    except:
                        try:
                            _ser2 = df_full[tac_col].cast(pl.Utf8, strict=False).drop_nulls()
                            _counts2 = _ser2.value_counts(sort=True)
                            if len(_counts2) > 0:
                                val2 = str(_counts2[0, tac_col]).strip()
                                if val2.lower() not in _tac_bad:
                                    top_tactic_report = val2
                        except:
                            pass
                    if top_tactic_report != "N/A":
                        break

        # If top_tactic_report is a numeric Event ID, add human-readable label
        if top_tactic_report != "N/A" and top_tactic_report.isdigit():
            try:
                from engine.forensic import SYSMON_EVENT_LABELS
                _elabel = SYSMON_EVENT_LABELS.get(top_tactic_report, "Windows Event")
                top_tactic_report = f"Win EventID {top_tactic_report}: {_elabel}"
            except:
                top_tactic_report = f"Win EventID {top_tactic_report}"

        import json
        # Render Template
        rendered_html = templates.get_template("static_report.html").render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            filename=request.original_filename or request.filename,
            total_events=total_filtered,
            time_range=time_range_str,
            top_identity=top_id,
            top_tactic=top_tactic_report,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_justify=risk_justify,
            eps=eps,
            top_events_json=json.dumps(top_events),
            top_providers_json=json.dumps(top_providers),
            chart_data_json=json.dumps(chart_data),
            context_data_json=json.dumps(context_data),
            hunting_data_json=json.dumps(hunting_data),
            threat_actors_json=json.dumps(threat_actors),
            sigma_hits_json=json.dumps(_sigma_hits_html),
        )

        # Save to temp file
        report_filename = f"Report_{int(time.time())}.html"
        report_path = os.path.join(OUTPUT_DIR, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return JSONResponse(content={"download_url": f"/download/{report_filename}", "filename": report_filename})

    except Exception as e:
        logger.error(f"HTML Export error: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/api/export/forensic-summary")
async def export_forensic_summary(request: Request):
    """Generate a formatted XLSX forensic summary report from context modal data — ALL sections."""
    import xlsxwriter
    try:
        body = await request.json()
        filename = body.get("filename", "unknown")
        summary = body.get("summary", {})

        out_filename = f"Forensic_Summary_{filename.replace('.', '_')}_{int(time.time())}.xlsx"
        out_path = os.path.join(OUTPUT_DIR, out_filename)

        workbook = xlsxwriter.Workbook(out_path, {'strings_to_numbers': False})

        # Formats
        title_fmt = workbook.add_format({'bold': True, 'font_size': 14, 'font_color': '#1e3a8a', 'bottom': 2})
        section_fmt = workbook.add_format({'bold': True, 'font_size': 11, 'font_color': '#ffffff', 'bg_color': '#1e3a5f', 'bottom': 1})
        subsection_fmt = workbook.add_format({'bold': True, 'font_size': 10, 'font_color': '#1e3a8a', 'bottom': 1, 'italic': True})
        header_fmt = workbook.add_format({'bold': True, 'bg_color': '#e2e8f0', 'font_color': '#334155', 'bottom': 1})
        kv_key_fmt = workbook.add_format({'bold': True, 'font_color': '#475569'})
        kv_val_fmt = workbook.add_format({'font_color': '#1e293b'})
        text_fmt = workbook.add_format({'num_format': '@', 'text_wrap': True})
        warn_fmt = workbook.add_format({'font_color': '#dc2626', 'bold': True, 'num_format': '@'})
        critical_fmt = workbook.add_format({'font_color': '#dc2626', 'bold': True})
        high_fmt = workbook.add_format({'font_color': '#ea580c', 'bold': True})
        medium_fmt = workbook.add_format({'font_color': '#d97706', 'bold': True})
        low_fmt = workbook.add_format({'font_color': '#16a34a', 'bold': True})
        level_fmts = {'critical': critical_fmt, 'high': high_fmt, 'medium': medium_fmt, 'low': low_fmt}

        ws = workbook.add_worksheet("Forensic Summary")
        ws.set_column(0, 0, 22)
        ws.set_column(1, 1, 42)
        ws.set_column(2, 2, 28)
        ws.set_column(3, 3, 16)
        ws.set_column(4, 4, 55)

        # Helper functions
        def write_section(r, title):
            ws.merge_range(r, 0, r, 4, title, section_fmt)
            return r + 1

        def write_subsection(r, title):
            ws.write_string(r, 0, title, subsection_fmt)
            return r + 1

        def write_headers(r, cols):
            for ci, c in enumerate(cols):
                ws.write_string(r, ci, c, header_fmt)
            return r + 1

        def write_list_table(r, title, items, key="id"):
            """Write a named list of {key: str, count: int} items."""
            if not items:
                return r
            r = write_subsection(r, title)
            r = write_headers(r, ["Name", "Count"])
            for it in items:
                name = str(it.get(key) or it.get("name") or "")
                ws.write_string(r, 0, name, text_fmt)
                ws.write_string(r, 1, str(it.get("count", 0)), text_fmt)
                r += 1
            return r

        row = 0
        ws.write(row, 0, "CHRONOS-DFIR FORENSIC SUMMARY", title_fmt)
        row += 2

        # ── 1. HEADER METADATA ──
        kv_data = [
            ("File", filename),
            ("Risk Level", f"{summary.get('risk_level', 'N/A')} (Score: {summary.get('risk_score', 'N/A')})"),
            ("Primary Identity", summary.get("primary_identity", "N/A")),
            ("Top Tactic", summary.get("top_tactic", "N/A")),
            ("Total Records", str(summary.get("total_records", "N/A"))),
            ("Events/Sec", str(summary.get("eps", "0"))),
        ]
        for key, val in kv_data:
            ws.write_string(row, 0, key, kv_key_fmt)
            ws.write_string(row, 1, str(val), kv_val_fmt)
            row += 1
        row += 1

        # ── 2. RESULTS SECTIONS (timeline, context, hunting, identity) ──
        results = summary.get("results") or []
        if isinstance(results, list):
            for s in results:
                if not isinstance(s, dict):
                    continue

                if s.get("type") == "timeline":
                    row = write_section(row, "TIMELINE ANALYSIS")
                    peaks = s.get("peaks") or []
                    if peaks:
                        row = write_headers(row, ["Peak #", "Hour", "Events"])
                        for i, p in enumerate(peaks):
                            ws.write_string(row, 0, str(i + 1), text_fmt)
                            ws.write_string(row, 1, str(p.get("hour", "")), text_fmt)
                            ws.write_string(row, 2, str(p.get("count", 0)), text_fmt)
                            row += 1
                    if s.get("time_range"):
                        ws.write_string(row, 0, "Time Range", kv_key_fmt)
                        ws.write_string(row, 1, str(s["time_range"]), kv_val_fmt)
                        row += 1
                    row += 1

                elif s.get("type") == "context":
                    row = write_section(row, "SANITIZED FORENSIC SUMMARY")
                    for label, key in [("Top IPs", "ips"), ("Top Users", "users"), ("Top Hosts", "hosts"),
                                       ("Top Directories", "paths"), ("HTTP Methods", "methods"), ("Violations", "violations")]:
                        row = write_list_table(row, label, s.get(key), "id")
                    if s.get("event_ids"):
                        row = write_list_table(row, "Top Event IDs", s["event_ids"], "id")
                    if s.get("tactics"):
                        row = write_subsection(row, "Tactic Distribution")
                        row = write_headers(row, ["Tactic", "Count"])
                        for t in s["tactics"]:
                            ws.write_string(row, 0, str(t.get("category", "")), text_fmt)
                            ws.write_string(row, 1, str(t.get("count", 0)), text_fmt)
                            row += 1
                    row += 1

                elif s.get("type") == "hunting":
                    row = write_section(row, "CHRONOS HUNTER SUMMARY")
                    patterns = s.get("patterns") or []
                    if patterns:
                        ws.write_string(row, 0, "SUSPICIOUS PATTERNS DETECTED", warn_fmt)
                        row += 1
                        row = write_headers(row, ["Timestamp", "User", "Command"])
                        for p in patterns:
                            ws.write_string(row, 0, str(p.get("timestamp", "")), text_fmt)
                            ws.write_string(row, 1, str(p.get("user", "")), text_fmt)
                            ws.write_string(row, 2, str(p.get("command", "")), text_fmt)
                            row += 1
                    if s.get("network"):
                        row = write_list_table(row, "Top Network Destinations", s["network"], "destination")
                    if s.get("logons"):
                        row = write_subsection(row, "Authentication / Logon Summary")
                        row = write_headers(row, ["Event / Category", "Count"])
                        for l in s["logons"]:
                            key = next((k for k in l if k != "count"), "")
                            ws.write_string(row, 0, str(l.get(key, "")), text_fmt)
                            ws.write_string(row, 1, str(l.get("count", 0)), text_fmt)
                            row += 1
                    row += 1

                elif s.get("type") == "identity":
                    row = write_section(row, "IDENTITY & ASSETS")
                    for label, key in [("Top Users", "users"), ("Top Hosts", "hosts"), ("Top Processes", "processes"),
                                       ("Rare Processes", "rare_processes"), ("Rare Execution Paths", "rare_paths")]:
                        row = write_list_table(row, label, s.get(key), "name")
                    row += 1

        # ── 3. SIGMA DETECTIONS (with evidence) ──
        sigma_hits = summary.get("sigma_hits") or []
        if sigma_hits:
            row = write_section(row, "SIGMA RULE DETECTIONS")
            row = write_headers(row, ["Level", "Rule", "MITRE Technique", "Events", "Description"])
            for h in sigma_hits:
                lvl = (h.get("level") or "low").lower()
                ws.write_string(row, 0, lvl.upper(), level_fmts.get(lvl, text_fmt))
                ws.write_string(row, 1, h.get("title", ""), text_fmt)
                ws.write_string(row, 2, h.get("mitre_technique", ""), text_fmt)
                ws.write_string(row, 3, str(h.get("matched_rows", 0)), text_fmt)
                ws.write_string(row, 4, h.get("description", ""), text_fmt)
                row += 1
                # Evidence rows
                evidence = h.get("sample_evidence") or []
                if evidence:
                    ev_cols = [c for c in evidence[0].keys() if c != "_id"][:5]
                    ws.write_string(row, 0, f"  Evidence ({len(evidence)} samples):", subsection_fmt)
                    row += 1
                    row = write_headers(row, ev_cols)
                    for ev in evidence[:10]:
                        for ci, c in enumerate(ev_cols):
                            ws.write_string(row, ci, str(ev.get(c, ""))[:200], text_fmt)
                        row += 1
            row += 1

        # ── 4. YARA DETECTIONS ──
        yara_hits = summary.get("yara_hits") or []
        if yara_hits:
            row = write_section(row, "YARA DETECTIONS")
            row = write_headers(row, ["Rule", "Category", "Tags", "Strings Matched"])
            for y in yara_hits:
                ws.write_string(row, 0, y.get("rule", ""), text_fmt)
                ws.write_string(row, 1, y.get("namespace", ""), text_fmt)
                ws.write_string(row, 2, ", ".join(y.get("tags", [])), text_fmt)
                ws.write_string(row, 3, str(y.get("strings_matched", 0)), text_fmt)
                row += 1
            row += 1

        # ── 5. MITRE KILL CHAIN ──
        mitre = summary.get("mitre_kill_chain") or []
        if mitre:
            row = write_section(row, "MITRE ATT&CK KILL CHAIN")
            row = write_headers(row, ["Tactic", "Threat Level", "Count", "Description"])
            for m in mitre:
                ws.write_string(row, 0, m.get("tactic", ""), text_fmt)
                ws.write_string(row, 1, m.get("threat_level", ""), text_fmt)
                ws.write_string(row, 2, str(m.get("count", 0)), text_fmt)
                ws.write_string(row, 3, m.get("description", ""), text_fmt)
                row += 1
            row += 1

        # ── 6. CROSS-SOURCE CORRELATION ──
        corr = summary.get("cross_source_correlation") or {}
        chains = corr.get("chains") if isinstance(corr, dict) else []
        if chains:
            row = write_section(row, "CROSS-SOURCE CORRELATION")
            row = write_headers(row, ["Pivot Type", "Entity", "Events", "First Seen", "Last Seen"])
            for c in chains:
                ws.write_string(row, 0, c.get("pivot_type", ""), text_fmt)
                ws.write_string(row, 1, c.get("entity", ""), text_fmt)
                ws.write_string(row, 2, str(c.get("total_events", 0)), text_fmt)
                ws.write_string(row, 3, c.get("first_seen", ""), text_fmt)
                ws.write_string(row, 4, c.get("last_seen", ""), text_fmt)
                row += 1
            row += 1

        # ── 7. SESSION PROFILES ──
        sessions = summary.get("session_profiles") or []
        if sessions:
            row = write_section(row, "SESSION PROFILES")
            row = write_headers(row, ["IP / Identity", "Requests", "Dwell Time", "Unique Paths", "User Agent"])
            for sp in sessions:
                ws.write_string(row, 0, sp.get("ip") or sp.get("identity", ""), text_fmt)
                ws.write_string(row, 1, str(sp.get("requests", 0)), text_fmt)
                ws.write_string(row, 2, sp.get("dwell", ""), text_fmt)
                ws.write_string(row, 3, str(sp.get("unique_paths", 0)), text_fmt)
                ws.write_string(row, 4, str(sp.get("user_agent", ""))[:100], text_fmt)
                row += 1
            row += 1

        # ── 8. RISK JUSTIFICATION ──
        risk_justify = summary.get("risk_justify")
        if risk_justify:
            row = write_section(row, "RISK JUSTIFICATION")
            justify_list = risk_justify if isinstance(risk_justify, list) else [risk_justify]
            for j in justify_list:
                ws.write_string(row, 0, f"• {j}", text_fmt)
                row += 1

        workbook.close()
        return JSONResponse(content={"download_url": f"/download/{out_filename}", "filename": out_filename})

    except Exception as e:
        logger.error(f"Forensic summary XLSX error: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/api/export/pdf")
async def export_pdf(request: ExportRequest, background_tasks: BackgroundTasks):
    """
    Generate a PDF forensic report using a 4-method fallback chain (cross-platform):
      1. WeasyPrint  — best quality, works on Linux with GTK/GLib
      2. Playwright  — headless Chromium, best on macOS/Windows/Linux without system libs
      3. xhtml2pdf   — pure Python, no system dependencies, moderate quality
      4. wkhtmltopdf — subprocess, if installed on the host
      5. HTML+print  — universal fallback: HTML with window.print() auto-triggered
    """
    import time, json as _json
    from fastapi.responses import JSONResponse

    try:
        # ── Common step: generate HTML report ──────────────────────────────────
        html_response = await export_html(request, background_tasks)
        html_info = _json.loads(html_response.body)
        if "error" in html_info:
            return JSONResponse(content=html_info, status_code=500)

        html_path = os.path.join(OUTPUT_DIR, html_info["filename"])
        pdf_filename = f"ChronosReport_{int(time.time())}.pdf"
        pdf_path = os.path.join(OUTPUT_DIR, pdf_filename)

        def _cleanup_html():
            try: os.remove(html_path)
            except: pass

        def _pdf_response():
            return JSONResponse(content={
                "download_url": f"/download/{pdf_filename}",
                "filename": pdf_filename,
                "method": _method_used
            })

        _method_used = "unknown"

        # ── Method 1: WeasyPrint ───────────────────────────────────────────────
        # Works on Linux (production) when GTK/Pango/GLib are installed.
        try:
            from weasyprint import HTML as WP_HTML
            with open(html_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            pdf_bytes = WP_HTML(string=html_content, base_url=OUTPUT_DIR).write_pdf()
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)
            _cleanup_html()
            _method_used = "weasyprint"
            return _pdf_response()
        except Exception as _wp_err:
            logger.warning(f"[PDF] WeasyPrint failed: {_wp_err}")

        # ── Method 2: Playwright (headless Chromium) ───────────────────────────
        # Best cross-platform option. Requires: pip install playwright && playwright install chromium
        try:
            from playwright.async_api import async_playwright
            abs_html = os.path.abspath(html_path)
            logger.info(f"[PDF] Playwright: opening file://{abs_html}")
            async with async_playwright() as _pw:
                browser = await _pw.chromium.launch(
                    headless=True,
                    args=["--disable-web-security", "--no-sandbox", "--allow-file-access-from-files"]
                )
                ctx = await browser.new_context(ignore_https_errors=True)
                page = await ctx.new_page()
                # Log any console errors from the page
                page.on("console", lambda msg: logger.info(f"[PDF][Browser] {msg.type}: {msg.text}") if msg.type in ("error", "warning") else None)
                page.on("pageerror", lambda err: logger.warning(f"[PDF][Browser] Page error: {err}"))
                # goto file:// — Chromium will load CDN scripts (Chart.js, Tabulator)
                await page.goto(f"file://{abs_html}", wait_until="networkidle", timeout=45000)
                # Extra wait for Chart.js to finish rendering its animations
                await page.wait_for_timeout(4000)
                # Log page dimensions for debugging
                _body_h = await page.evaluate("document.body.scrollHeight")
                logger.info(f"[PDF] Playwright: page body height = {_body_h}px")
                await page.pdf(
                    path=pdf_path,
                    format="A4",
                    print_background=True,
                    margin={"top": "15mm", "bottom": "15mm", "left": "12mm", "right": "12mm"}
                )
                await browser.close()
            _pdf_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0
            logger.info(f"[PDF] Playwright: generated {_pdf_size} bytes")
            if _pdf_size > 1024:  # Reject suspiciously small PDFs (< 1KB)
                _cleanup_html()
                _method_used = "playwright"
                return _pdf_response()
            logger.warning(f"[PDF] Playwright produced tiny file ({_pdf_size} bytes), trying next method")
        except Exception as _pl_err:
            logger.warning(f"[PDF] Playwright failed: {_pl_err}")
            import traceback
            traceback.print_exc()

        # ── Method 3: xhtml2pdf (pure Python) ─────────────────────────────────
        # No system libraries needed. CSS support is limited (no flexbox/grid).
        try:
            from xhtml2pdf import pisa
            with open(html_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            # xhtml2pdf needs a simplified stylesheet — inject print-safe overrides
            _print_css = """
            <style>
            body { background: white !important; color: black !important; font-family: Arial, sans-serif; font-size: 10pt; }
            .card, .section, .report-section { background: #f5f5f5 !important; border: 1px solid #ccc !important; page-break-inside: avoid; }
            table { width: 100%; border-collapse: collapse; font-size: 9pt; }
            th, td { border: 1px solid #aaa; padding: 4px 6px; text-align: left; }
            th { background: #ddd !important; font-weight: bold; }
            canvas { display: none !important; }
            .no-print { display: none !important; }
            * { color: black !important; background-color: white !important; }
            </style>
            """
            html_for_pisa = html_content.replace("</head>", _print_css + "</head>")
            with open(pdf_path, "wb") as out_f:
                status = pisa.CreatePDF(html_for_pisa, dest=out_f, encoding="utf-8")
            if not status.err and os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                _cleanup_html()
                _method_used = "xhtml2pdf"
                return _pdf_response()
            logger.warning(f"[PDF] xhtml2pdf error flag: {status.err}")
        except Exception as _xp_err:
            logger.warning(f"[PDF] xhtml2pdf failed: {_xp_err}")

        # ── Method 4: wkhtmltopdf (subprocess) ────────────────────────────────
        # Works if the binary is installed on the host (any OS).
        try:
            import subprocess, shutil as _shutil
            wk = _shutil.which("wkhtmltopdf")
            if wk:
                result = subprocess.run(
                    [wk, "--quiet", "--enable-local-file-access",
                     "--page-size", "A4", "--margin-top", "15mm",
                     "--margin-bottom", "15mm", "--margin-left", "12mm", "--margin-right", "12mm",
                     html_path, pdf_path],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0 and os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                    _cleanup_html()
                    _method_used = "wkhtmltopdf"
                    return _pdf_response()
                logger.warning(f"[PDF] wkhtmltopdf exit {result.returncode}: {result.stderr.decode(errors='replace')}")
        except Exception as _wk_err:
            logger.warning(f"[PDF] wkhtmltopdf failed: {_wk_err}")

        # ── Fallback 5: HTML with auto-print dialog ────────────────────────────
        # Universal: user opens the file, browser shows Print → Save as PDF dialog.
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        auto_print_js = (
            '<script>'
            'window.addEventListener("load",function(){'
            'document.title="Chronos Forensic Report";'
            'setTimeout(function(){window.print();},800);'
            '});'
            '</script>'
        )
        print_html = html_content.replace("</body>", auto_print_js + "</body>")
        print_filename = html_info["filename"].replace(".html", "_print.html")
        print_path = os.path.join(OUTPUT_DIR, print_filename)
        with open(print_path, "w", encoding="utf-8") as f:
            f.write(print_html)
        _cleanup_html()
        return JSONResponse(content={
            "download_url": f"/download/{print_filename}",
            "filename": print_filename,
            "fallback": True,
            "method": "browser-print",
            "message": (
                "Abre el archivo descargado en tu navegador. "
                "El diálogo de impresión se abrirá automáticamente — "
                "selecciona 'Guardar como PDF' para obtener el PDF."
            )
        })

    except Exception as e:
        logger.error(f"PDF Export error: {e}", exc_info=True)
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/api/export/split-zip")
async def export_split_zip(request: ExportRequest, background_tasks: BackgroundTasks):
    import polars as pl
    import zipfile
    import time
    import os
    import io

    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        try:
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            lf.collect().head(1)
        except:
            lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True, infer_schema_length=0)

        # Assign stable row IDs BEFORE filtering if they don't exist
        if "_id" not in lf.collect_schema().names():
            lf = lf.with_row_index(name="_id", offset=1)

        # Apply Unified Processing
        params = {
            "query": request.query,
            "col_filters": request.col_filters,
            "start_time": request.start_time,
            "end_time": request.end_time,
            "sort_col": request.sort_col,
            "sort_dir": request.sort_dir,
            "selected_ids": request.selected_ids
        }
        lf = _apply_standard_processing(lf, params)

        # For specific selection exports, we want to maintain sequential 1,2,3... in the final file
        if request.selected_ids:
             lf = lf.drop("_id").with_row_index(name="_id", offset=1)

        # Final Formatting
        lf = normalize_time_columns_in_df(lf)

        # Prepare schemas and column renaming
        all_cols_split = lf.collect_schema().names()
        id_col_name = "No."
        if id_col_name in all_cols_split:
             lf = lf.rename({id_col_name: "Original_No."})

        # Rename _id to No.
        lf = lf.rename({"_id": id_col_name})
        all_cols_split = lf.collect_schema().names()

        # Filter Columns based on visible_columns
        if request.visible_columns:
            target_cols = []
            for c in request.visible_columns:
                if c == "_id" or c == "No.":
                    if "No." in all_cols_split:
                        target_cols.append(pl.col("No."))
                elif c in all_cols_split:
                    target_cols.append(pl.col(c))
            if target_cols:
                lf = lf.select(target_cols)
        else:
             if "No." in all_cols_split:
                  other_cols = [c for c in all_cols_split if c != "No."]
                  lf = lf.select(["No."] + other_cols)

        # Stream directly to ZIP
        base_name = request.original_filename or request.filename
        if not base_name: base_name = "data"
        base_name = sanitize_filename(base_name)

        zip_base = f"Split_{os.path.splitext(base_name)[0]}"
        zip_filename = f"{zip_base}_{int(time.time())}.zip"
        zip_path = os.path.join(OUTPUT_DIR, zip_filename)

        # Determine chunk size (Bytes)
        user_chunk_mb = request.chunk_size_mb or 99
        user_chunk_mb = max(10, min(500, user_chunk_mb))
        CHUNK_SIZE_BYTES = user_chunk_mb * 1024 * 1024

        # Row-based streaming loop
        batch_size = 10000
        offset = 0
        total_rows = lf.select(pl.len()).collect().item()

        use_json = (getattr(request, 'zip_format', 'csv') or 'csv').lower() == 'json'
        ext = "json" if use_json else "csv"

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            part_num = 1
            current_p_path = os.path.join(OUTPUT_DIR, f"temp_p_{int(time.time())}_{part_num}.{ext}")
            current_p_size = 0
            header_written = False

            while offset < total_rows:
                df_batch = lf.slice(offset, batch_size).collect(engine="streaming")

                temp_buf = io.BytesIO()
                if use_json:
                    import json as _json
                    rows = df_batch.to_dicts()
                    chunk_bytes = _json.dumps(rows, ensure_ascii=False, default=str).encode('utf-8')
                else:
                    df_batch.write_csv(temp_buf, include_header=(not header_written))
                    chunk_bytes = temp_buf.getvalue()
                batch_len = len(chunk_bytes)

                if current_p_size > 0 and (current_p_size + batch_len > CHUNK_SIZE_BYTES):
                    zipf.write(current_p_path, arcname=f"Part_{part_num}.{ext}")
                    os.remove(current_p_path)
                    part_num += 1
                    current_p_path = os.path.join(OUTPUT_DIR, f"temp_p_{int(time.time())}_{part_num}.{ext}")
                    current_p_size = 0
                    if not use_json:
                        temp_buf = io.BytesIO()
                        df_batch.write_csv(temp_buf, include_header=True)
                        chunk_bytes = temp_buf.getvalue()
                        batch_len = len(chunk_bytes)

                with open(current_p_path, 'ab') as f_out:
                    f_out.write(chunk_bytes)
                current_p_size += batch_len
                offset += batch_size
                header_written = True

            if os.path.exists(current_p_path):
                zipf.write(current_p_path, arcname=f"Part_{part_num}.{ext}")
                os.remove(current_p_path)

        return JSONResponse(content={"download_url": f"/download/{zip_filename}", "filename": zip_filename})

    except Exception as e:
        logger.error(f"Split ZIP Export failed: {e}")
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

# =============================================================================
# YARA SCANNING — On-demand scan of ingested data against YARA rules
# =============================================================================
_yara_rules_compiled = None

def _load_yara_rules():
    """Compile all YARA rules from rules/yara/ at first use."""
    global _yara_rules_compiled
    if _yara_rules_compiled is not None:
        return _yara_rules_compiled
    try:
        import yara
        rules_dir = os.path.join(os.path.dirname(__file__), "rules", "yara")
        if not os.path.isdir(rules_dir):
            return None
        rule_files = {}
        for root, _, files in os.walk(rules_dir):
            for f in files:
                if f.endswith(".yar"):
                    ns = os.path.splitext(f)[0]
                    rule_files[ns] = os.path.join(root, f)
        if rule_files:
            _yara_rules_compiled = yara.compile(filepaths=rule_files)
            logger.info(f"YARA: compiled {len(rule_files)} rule files")
        return _yara_rules_compiled
    except ImportError:
        logger.debug("yara-python not installed — YARA scanning disabled")
        return None
    except Exception as e:
        logger.warning(f"YARA compilation error: {e}")
        return None

@app.post("/api/yara_scan/{filename}")
async def yara_scan(filename: str):
    """Scan ingested CSV text content against compiled YARA rules."""
    import asyncio
    rules = _load_yara_rules()
    if rules is None:
        return JSONResponse(content={"error": "YARA rules not available"}, status_code=501)
    csv_path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(csv_path):
        return JSONResponse(content={"error": "File not found"}, status_code=404)
    try:
        def _scan():
            with open(csv_path, "r", errors="replace") as f:
                text = f.read(5 * 1024 * 1024)  # Scan first 5MB
            matches = rules.match(data=text)
            return [{
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "strings_matched": len(m.strings),
            } for m in matches]
        results = await asyncio.to_thread(_scan)
        return {"filename": filename, "yara_matches": results, "total_matches": len(results)}
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# =============================================================================
# FORENSIC DOC PROCESSOR — PDF IOC extraction & XLSX integrity check
# =============================================================================
@app.post("/api/document/extract_iocs")
async def extract_iocs_from_document(file: UploadFile = File(...)):
    """Upload a PDF and extract IOCs (IPs, hashes, domains, URLs)."""
    import asyncio
    _skills_dir = os.path.join(os.path.dirname(__file__), ".agents", "skills", "chronos_forensic_doc_processor")
    if _skills_dir not in sys.path:
        sys.path.insert(0, _skills_dir)
    from forensic_doc_processor import extract_pdf_text, extract_iocs_from_pdf_text

    ext = os.path.splitext(file.filename)[1].lower()
    if ext != ".pdf":
        return JSONResponse(content={"error": "Only PDF files supported"}, status_code=400)
    tmp_path = os.path.join(UPLOAD_DIR, f"ioc_scan_{file.filename}")
    try:
        with open(tmp_path, "wb") as f:
            f.write(await file.read())
        def _extract():
            result = extract_pdf_text(tmp_path)
            if result["status"] != "ok":
                return result
            full_text = " ".join(p["text"] for p in result["pages"])
            iocs = extract_iocs_from_pdf_text(full_text)
            return {
                "status": "ok",
                "filename": file.filename,
                "total_pages": result["total_pages"],
                "total_chars": result["total_chars"],
                "iocs": iocs,
                "ioc_count": sum(len(v) for v in iocs.values()),
            }
        return await asyncio.to_thread(_extract)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.post("/api/document/check_xlsx")
async def check_xlsx_endpoint(file: UploadFile = File(...)):
    """Upload an XLSX and verify forensic integrity (empty cols, hex truncation)."""
    import asyncio
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".agents", "skills", "chronos_forensic_doc_processor"))
    from forensic_doc_processor import check_xlsx_integrity

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".xlsx", ".xls"):
        return JSONResponse(content={"error": "Only XLSX/XLS files supported"}, status_code=400)
    tmp_path = os.path.join(UPLOAD_DIR, f"check_{file.filename}")
    try:
        with open(tmp_path, "wb") as f:
            f.write(await file.read())
        result = await asyncio.to_thread(check_xlsx_integrity, tmp_path)
        result["filename"] = file.filename
        return result
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["static", "templates", "engine", ".agents/skills"]
    )
