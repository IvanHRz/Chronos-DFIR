import os
import io
import json
import shutil
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from timeline_skill import generate_unified_timeline
import polars as pl
import csv
import sys
import zipfile
import math
from typing import List, Optional, Any
from pydantic import BaseModel

# Increase CSV field size limit to handle large JSON blobs in cells (e.g. SharpHound)
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2147483647) # Fallback for 32-bit systems

app = FastAPI(title="Chronos-DFIR Web")

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
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

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def process_file(file: UploadFile = File(...), artifact_type: str = Form(...)):
    import shutil
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
    
        # STREAMING UPLOAD: Stream directly to disk to handle 6GB+ files
        # Replaces memory-heavy wait file.read()
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        ext = os.path.splitext(file.filename)[1].lower()

        # LOGIC BRANCH: Generic Report vs Forensic Artifact
        generic_exts = ['.csv', '.xlsx', '.tsv', '.parquet', '.json', '.jsonl', '.ndjson', '.db', '.sqlite', '.sqlite3']
        if ext in generic_exts:
            import time
            csv_filename = f"import_{file.filename.split('.')[0]}_{int(time.time())}.csv"
            dest_path = os.path.join(OUTPUT_DIR, csv_filename)
            
            row_count = "Unknown (Lazy)"
            file_cat = "generic"
            
            import pandas as pd
            import polars as pl # Ensure polars is imported here or at top
            
            try:
                # 1. Handle Modern Formats (Parquet, JSON, SQLite)
                if ext == '.parquet':
                    df = pl.read_parquet(file_path).to_pandas()
                elif ext in ['.json', '.jsonl', '.ndjson']:
                    try:
                        df = pl.read_ndjson(file_path).to_pandas()
                    except:
                        df = pl.read_json(file_path).to_pandas()
                elif ext in ['.db', '.sqlite', '.sqlite3']:
                    import sqlite3
                    conn = sqlite3.connect(file_path)
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        tables = [r[0] for r in cursor.fetchall() if not r[0].startswith('sqlite_')]
                        if not tables: raise Exception("No tables found")
                        target_table = tables[0]
                        for t in tables:
                            if t.lower() in ['events', 'logs', 'timeline', 'entries']:
                                target_table = t
                                break
                        df = pd.read_sql_query(f"SELECT * FROM \"{target_table}\"", conn)
                    finally:
                        conn.close()
                
                # 2. Handle Excel
                elif ext == '.xlsx':
                    df = pd.read_excel(file_path)
                
                # 3. Handle TSV
                elif ext == '.tsv':
                    try:
                        df = pd.read_csv(file_path, sep='\t', encoding='utf-8', engine='python')
                    except:
                        df = pd.read_csv(file_path, sep='\t', encoding='utf-16', engine='python')
                
                # 4. Handle CSV (Default Fallback)
                else:
                    # Robust CSV Read
                    try:
                        df = pd.read_csv(file_path, encoding='utf-8-sig', sep=None, engine='python')
                    except:
                        try:
                            df = pd.read_csv(file_path, encoding='utf-16', sep=None, engine='python')
                        except:
                            try:
                                df = pd.read_csv(file_path, encoding='cp1252', sep=None, engine='python')
                            except Exception as final_e:
                                raise final_e
                
                # CRITICAL: Normalize Headers (Strip whitespace) to ensure Frontend mapping works
                df.columns = df.columns.astype(str).str.strip()
                
                # User Request: Normalize Headers (Remove leading _, Capitalize)
                new_columns = []
                for col in df.columns:
                    col_lower = col.lower()
                    
                    if col_lower == '_time':
                        new_columns.append('Time')
                    elif col_lower == '_id':
                        new_columns.append('Original_Id') # Avoid collision with our "No." column
                    else:
                        # Remove leading underscores and capitalize first letter
                        clean_col = col.lstrip('_')
                        if clean_col:
                            clean_col = clean_col[0].upper() + clean_col[1:]
                        else:
                            clean_col = col # Fallback if empty
                        new_columns.append(clean_col)
                
                df.columns = new_columns
                
                # Save normalized CSV for frontend consumption (always save as standard UTF-8)
                df.to_csv(dest_path, index=False, encoding='utf-8')
                row_count = len(df)
                
                # Update global map
                processed_files[file.filename] = csv_filename
                
            except MemoryError:
                print("OOM during normalization (File too big). Using raw file.")
                shutil.copy(file_path, dest_path)
            except Exception as e:
                # If parsing fails, just save raw and hope for best (or frontend handles it)
                print(f"Parsing error, saving raw: {e}")
                shutil.copy(file_path, dest_path)
                row_count = "Unknown"

            return {
                "status": "success",
                "message": "File uploaded successfully",
                "data_url": f"/api/data/{csv_filename}",
                "csv_filename": csv_filename,
                "xlsx_filename": None, 
                "processed_records": row_count,
                "file_category": file_cat
            }

        # Forensic Processing (MFT/EVTX)
        # Note: output_dir is fixed to OUTPUT_DIR
        # We already saved 'file_path' above, so we just pass it to the engine.
        result_json = generate_unified_timeline(file_path, artifact_type, OUTPUT_DIR)
        result = json.loads(result_json)
        
        if result.get("status") != "success":
            return JSONResponse(content={"error": result.get("error", "Unknown error")}, status_code=500)
        
        # Add category for frontend switching
        result['file_category'] = 'forensic'
            
        # Extract filename from path to use in subsequent requests
        csv_path = result['files']['csv']
        filename = os.path.basename(csv_path)
        
        # Update global map
        processed_files[file.filename] = filename
        
        return {
            "status": "success",
            "message": "File processed successfully",
            "data_url": f"/api/data/{filename}",
            "processed_records": result.get("processed_records"),
            "csv_filename": filename,
            "xlsx_filename": os.path.basename(result['files']['excel'])
        }

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/api/data/{filename}")
async def get_data(filename: str, page: int = 1, size: int = 50, query: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None, col_filters: Optional[str] = None):
    import polars as pl
    import numpy as np
    import traceback
    import math

    try:
        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        # Polars is MUCH faster and memory efficient for large files
        try:
            # Simple approach: Try UTF-8 first (default).
            try:
                lf = pl.scan_csv(csv_path, ignore_errors=True)
                lf.fetch(1) 
            except:
                 lf = pl.scan_csv(csv_path, encoding='utf8-lossy', ignore_errors=True)

            # Row count will be assigned AFTER sorting to maintain timeline order

            # TIME FILTERING logic (Sync with Chart)
            # Try to find time column
            time_col = None
            schema = lf.collect_schema()
            candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
            for col in schema.keys():
                if col.lower() in candidates:
                    time_col = col
                    break
            
            if time_col and (start_time or end_time):
                # Robust Date Parsing (Same as analyze_dataframe)
                c_ts = pl.col(time_col).cast(pl.Utf8)
                lf = lf.with_columns(
                    pl.coalesce([
                        pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="ms"),
                        pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="s"),
                        c_ts.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                        c_ts.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%d/%m/%Y %H:%M", strict=False),
                        c_ts.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%b %d, %Y %I:%M %p", strict=False),
                        c_ts.str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y", strict=False),
                    ]).alias("_ts_filter_")
                )

                if start_time:
                    lf = lf.filter(pl.col("_ts_filter_") >= pl.lit(start_time).str.to_datetime(strict=False))
                if end_time:
                    lf = lf.filter(pl.col("_ts_filter_") <= pl.lit(end_time).str.to_datetime(strict=False))
                
                # Cleanup temp column
                lf = lf.drop("_ts_filter_")


            # GLOBAL SEARCH LOGIC (Apply before pagination)
            if query and query.strip():
                import functools, operator
                q_lower = query.strip().lower()
                # 1. Inspect schema to find string-like cols (Utf8/String)
                string_cols = [name for name, dtype in schema.items() if dtype in [pl.String, pl.Utf8]]
                
                if string_cols:
                    # Construct expression: (col1 contains Q) OR (col2 contains Q) ...
                    # literal=True avoids regex errors with chars like '.' or '-'
                    # fill_null(False) prevents a null in one column from 'poisoning' the whole row search
                    filters = [
                        pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(q_lower, literal=True).fill_null(False) 
                        for c in string_cols
                    ]
                    
                    if filters:
                        combined_filter = functools.reduce(operator.or_, filters)
                        lf = lf.filter(combined_filter)

            # --- COLUMN HEADER FILTERS (from Tabulator) ---
            if col_filters and col_filters.strip():
                try:
                    import json
                    cf = json.loads(col_filters)
                    for col_name, col_value in cf.items():
                        if col_name in schema and col_value:
                            lf = lf.filter(
                                pl.col(col_name).cast(pl.Utf8).str.to_lowercase().str.contains(
                                    col_value.lower(), literal=True
                                )
                            )
                except Exception as e:
                    print(f"Warning: Failed to parse col_filters in get_data: {e}")
            # --- SORT BY TIMESTAMP (Timeline Order) ---
            time_col_sort = None
            time_candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
            for col_name in schema.keys():
                if col_name.lower() in time_candidates:
                    time_col_sort = col_name
                    break

            if time_col_sort:
                c_sort = pl.col(time_col_sort).cast(pl.Utf8)
                lf = lf.with_columns(
                    pl.coalesce([
                        pl.from_epoch(pl.col(time_col_sort).cast(pl.Int64, strict=False), time_unit="ms"),
                        pl.from_epoch(pl.col(time_col_sort).cast(pl.Int64, strict=False), time_unit="s"),
                        c_sort.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                        c_sort.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                        c_sort.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                        c_sort.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                        c_sort.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                        c_sort.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                        c_sort.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                        c_sort.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                        c_sort.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                        c_sort.str.to_datetime("%Y-%m-%d", strict=False),
                        c_sort.str.to_datetime("%m/%d/%Y", strict=False),
                    ]).alias("_ts_sort_")
                ).sort("_ts_sort_", nulls_last=True).drop("_ts_sort_")

            # Assign _id AFTER sorting so row numbers follow timeline order
            lf = lf.with_row_index(name="_id", offset=1)

            # Pagination Logic
            # Just do the count (filtered or total)
            total_rows = lf.select(pl.len()).collect().item()
            last_page = math.ceil(total_rows / size) if size > 0 else 1

            # Slice it
            offset = (page - 1) * size
            q = lf.slice(offset, size)
            df_page = q.collect()
            
            records = df_page.to_dicts()
            
            return {
                "current_page": page,
                "last_page": last_page,
                "data": records,
                "total": total_rows
            }
            
        except Exception as p_err:
             print(f"Polars failed: {p_err}")
             return JSONResponse(content={"error": str(p_err)}, status_code=500)
    
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

def analyze_dataframe(df_source, target_bars=50, start_time: str = None, end_time: str = None):
    """
    Core function to generate advanced histogram data from a Polars DataFrame.
    Returns dict with labels, datasets, trend, anomalies, top_talker, and stats.
    """
    try:
        # 1. Parsing Time
        time_col = None
        candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
        for col in df_source.columns:
            if col.lower() in candidates:
                time_col = col
                break
        
        if not time_col:
            print(f"[ERROR] No time column found. Available columns: {df_source.columns}")
            return {"error": f"No time column found. Available: {df_source.columns}"}

        print(f"[DEBUG] analyzing time column: {time_col}, Type: {df_source.schema[time_col]}")

        # Ensure Time is Datetime (Robust Inference)
        # Convert to LazyFrame for consistent filtering
        q_base = df_source.lazy()
        
        c_time = pl.col(time_col)
        
        try:
            # Helper to cast to string if needed for parsing
            c_time_str = c_time.cast(pl.Utf8)

            # Pre-clean: Remove timezone offset if present (e.g. +00:00 or Z) to simplify parsing
            # Regex: Remove +HH:MM or -HH:MM at end of string
            c_time_clean = c_time_str.str.replace(r'[\+\-]\d{2}:\d{2}$', '', literal=False).str.replace('Z$', '', literal=False)

            # We construct a list of expressions to try
            # Note: strict=False returns null on failure
            q_base = q_base.with_columns(
                pl.coalesce([
                    # Strict numeric parsing first
                    pl.from_epoch(c_time.cast(pl.Int64, strict=False), time_unit="ms"), # Unix Timestamp (ms)
                    pl.from_epoch(c_time.cast(pl.Int64, strict=False), time_unit="s"), # Unix Timestamp (s)
                    pl.from_epoch(c_time.cast(pl.Int64, strict=False), time_unit="us"), # Unix Timestamp (us)
                    pl.from_epoch(c_time.cast(pl.Int64, strict=False), time_unit="ns"), # Unix Timestamp (ns)
                    # Strict string parsing next
                    c_time_str.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False), # ISO 8601 full
                    c_time_str.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False), # ISO 8601 no frac
                    c_time_str.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False), # ISO space with subsec
                    c_time_str.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False), # ISO space
                    c_time_str.str.to_datetime("%Y-%m-%d %H:%M", strict=False), # ISO no seconds
                    c_time_str.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False), # US AM/PM with sec
                    c_time_str.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False), # US AM/PM NO seconds
                    c_time_str.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False), # US 24hr
                    c_time_str.str.to_datetime("%m/%d/%Y %H:%M", strict=False), # US 24hr no sec
                    c_time_str.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False), # EU
                    c_time_str.str.to_datetime("%d/%m/%Y %H:%M", strict=False), # EU no sec
                    c_time_str.str.to_datetime("%Y/%m/%d %H:%M:%S", strict=False), # Slash YMD
                    c_time_str.str.to_datetime("%b %d %Y %H:%M:%S", strict=False), # "Feb 07 2026 10..."
                    c_time_str.str.to_datetime("%b %d, %Y %H:%M:%S", strict=False), # "Feb 07, 2026 10..."
                    c_time_str.str.to_datetime("%b %d, %Y %I:%M:%S %p", strict=False), # "Feb 07, 2026 1:02:00 PM"
                    c_time_str.str.to_datetime("%b %d, %Y %I:%M %p", strict=False), # "Feb 07, 2026 1:02 PM"
                    c_time_str.str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False), # Dash DMY
                    c_time_str.str.to_datetime("%Y-%m-%d", strict=False), # Date only
                    c_time_str.str.to_datetime("%m/%d/%Y", strict=False), # US date only
                    c_time_str.str.to_datetime("%d/%m/%Y", strict=False), # EU date only
                ]).alias("ts")
            ).filter(pl.col("ts").is_not_null())
            
            # Sort by Timestamp for correct timeline order
            q_base = q_base.sort("ts")
            
            # Use collect() here to force execution inside try block
            full_df = q_base.collect()

        except Exception as e:
            # Fallback diagnostics: Print first few rows of raw time column
            try:
                sample = df_source.select(time_col).head(5).to_pandas()[time_col].tolist()
                print(f"[ERROR] Date parsing failed. Sample values from '{time_col}': {sample}")
            except:
                pass
            print(f"[ERROR] Date parsing failed in analyze_dataframe: {e}")
            import traceback
            traceback.print_exc()
            return {"error": f"Failed to parse dates in column '{time_col}': {str(e)}"}
        if full_df.height == 0:
            return {"error": "No valid timestamps found"}
        
        # Ensure sorted for group_by_dynamic and proper range stats
        full_df = full_df.sort("ts")

        file_min = full_df["ts"].min()
        file_max = full_df["ts"].max()
        file_total = full_df.height

        # Apply Filtering
        q = full_df.lazy()
        if start_time:
            q = q.filter(pl.col("ts") >= pl.lit(start_time).str.to_datetime(strict=False))
        if end_time:
            q = q.filter(pl.col("ts") <= pl.lit(end_time).str.to_datetime(strict=False))
            
        df = q.collect()
        
        if df.height == 0:
             return {
                 "labels": [], "datasets": [], 
                 "interpretation": "No data in selected time range.",
                 "stats": {
                     "total_events": 0,
                     "file_total": file_total,
                     "start_time": None, "end_time": None,
                     "file_start": file_min.isoformat() if file_min else None,
                     "file_end": file_max.isoformat() if file_max else None
                 }
             }

        # Calculate View Stats
        view_min = df["ts"].min()
        view_max = df["ts"].max()
        view_total = df.height
        
        duration = (view_max - view_min).total_seconds()
        
        # Dynamic Interval (Target ~50 bars)
        possible_intervals = [
            ("1s", 1), ("10s", 10), ("30s", 30),
            ("1m", 60), ("5m", 300), ("10m", 600), ("30m", 1800),
            ("1h", 3600), ("4h", 14400), ("12h", 43200),
            ("1d", 86400), ("7d", 604800)
        ]
        
        interval = "1h" # Default
        best_diff = float('inf')
        
        for name, seconds in possible_intervals:
            num_bars = duration / seconds
            diff = abs(num_bars - target_bars)
            if diff < best_diff:
                best_diff = diff
                interval = name

        # Aggregation
        # Find Level Column
        level_col = next((c for c in df.columns if c.lower() == 'level'), None)
        
        agg_exprs = [pl.len().alias("total_volume")]
        
        if level_col:
            # Simplified categories for forensic analysis:
            # "Alta Actividad" = Critical(1) + Error(2) + Warning(3) — notable events
            # "Actividad" = Info(4) + Verbose(5) + anything else — routine events
            agg_exprs.extend([
                pl.col(level_col).cast(pl.Utf8).is_in(["1", "2", "3", "Critical", "CRITICAL", "Error", "ERROR", "Warning", "WARNING"]).sum().alias("Alta Actividad"),
                (~pl.col(level_col).cast(pl.Utf8).is_in(["1", "2", "3", "Critical", "CRITICAL", "Error", "ERROR", "Warning", "WARNING"])).sum().alias("Actividad")
            ])
        else:
            # If no level, everything is Actividad
             agg_exprs.append(pl.len().alias("Actividad"))

        pivoted = df.group_by_dynamic("ts", every=interval).agg(agg_exprs).sort("ts")

        # For small datasets (≤20 events), create a contextual chart with
        # individual bars grouped by timestamp, compared against global activity
        if view_total <= 20:
            # Group events by unique second (so multiple events at same second stack)
            df_individual = df.with_columns(
                pl.col("ts").dt.truncate("1s").alias("ts_sec")
            )
            grouped = df_individual.group_by("ts_sec").agg(pl.len().alias("count")).sort("ts_sec")
            
            individual_labels = [t.strftime("%H:%M:%S") for t in grouped["ts_sec"]]
            individual_values = grouped["count"].to_list()
            
            # Compute global context from the FULL bucketed histogram
            all_volumes = pivoted["total_volume"].to_list()
            global_max = max(all_volumes) if all_volumes else 1
            global_mean = sum(all_volumes) / len(all_volumes) if all_volumes else 1
            global_min = min(all_volumes) if all_volumes else 0
            
            # Color each bar based on where it sits relative to global mean
            bar_colors = []
            for v in individual_values:
                if v > global_mean * 1.5:
                    bar_colors.append("#ff8c42")  # High relative to global
                elif v > global_mean:
                    bar_colors.append("#ffb74d")  # Above average
                else:
                    bar_colors.append("#3399ff")  # Normal
            
            individual_datasets = [{
                "label": "Selected Events",
                "data": individual_values,
                "backgroundColor": bar_colors,
                "borderColor": "#1a6dcc",
                "borderWidth": 1,
                "borderRadius": 4,
                "order": 2
            }]

            # Compute noise info
            _top_id = "N/A"
            _top_pct = 0
            if "EventID" in df.columns:
                _top = df["EventID"].value_counts().sort("count", descending=True).head(1)
                if _top.height > 0:
                    _top_id = str(_top[0, "EventID"])
                    _top_pct = _top[0, "count"] / view_total

            interpretation = (
                f"Individual View: {view_total} events in {len(individual_labels)} time groups. "
                f"Global max: {int(global_max)} events/bucket, avg: {int(global_mean)}. "
                f"Time span: {individual_labels[0]} → {individual_labels[-1]}."
            )

            return {
                "labels": individual_labels,
                "datasets": individual_datasets,
                "interpretation": interpretation,
                "stacked": False,
                "global_stats": {
                    "max_bucket": int(global_max),
                    "mean_bucket": round(global_mean, 1),
                    "min_bucket": int(global_min),
                    "total_events": file_total,
                    "total_buckets": len(all_volumes)
                },
                "noise_info": {
                    "top_talker_id": _top_id,
                    "percent": round(_top_pct * 100, 1)
                },
                "stats": {
                    "total_events": view_total,
                    "file_total": file_total,
                    "start_time": view_min.isoformat() if view_min else None,
                    "end_time": view_max.isoformat() if view_max else None,
                    "file_start": file_min.isoformat() if file_min else None,
                    "file_end": file_max.isoformat() if file_max else None
                }
            }

        # Define Value Columns — simplified for forensic usefulness
        if level_col:
            value_cols = ["Alta Actividad", "Actividad"]
        else:
            value_cols = ["Actividad"]

        # 4. Moving Average (Trend)
        pivoted = pivoted.with_columns(
            pl.col("total_volume").rolling_mean(window_size=5).fill_null(0).alias("trend_sma")
        )
        
        # 5. Anomaly Detection
        mean_vol = pivoted["total_volume"].mean()
        std_vol = pivoted["total_volume"].std()
        if std_vol is None or std_vol == 0: std_vol = 1
        
        pivoted = pivoted.with_columns(
            (pl.col("total_volume") > (mean_vol + 2 * std_vol)).alias("is_anomaly")
        )

        # 6. Noise Filter Info
        top_talker_id = "N/A"
        top_talker_pct = 0
        if "EventID" in df.columns:
            top = df["EventID"].value_counts().sort("count", descending=True).head(1)
            if top.height > 0:
                top_talker_id = str(top[0, "EventID"])
                top_talker_pct = top[0, "count"] / view_total

        # Format Labels
        label_fmt = "%Y-%m-%d %H:%M"
        if interval.endswith("d"): label_fmt = "%Y-%m-%d"
        elif interval.endswith("s"): label_fmt = "%H:%M:%S"
        
        labels = [t.strftime(label_fmt) for t in pivoted["ts"]]
        
        datasets = []
        
        # Colors
        colors = {
            "Alta Actividad": "#ff6600",
            "Actividad": "#3399ff",
        }

        for cat in value_cols:
            if cat not in pivoted.columns: continue
            
            datasets.append({
                "label": cat,
                "data": pivoted[cat].to_list(),
                "backgroundColor": colors.get(cat, "#3399ff"),
                "stack": "Stack 0",
                "order": 2
            })

        # Trend Line (area fill)
        datasets.append({
            "label": "Tendencia",
            "data": pivoted["trend_sma"].to_list(),
            "type": "line",
            "borderColor": "rgba(0, 255, 255, 0.7)",
            "backgroundColor": "rgba(0, 255, 255, 0.08)",
            "borderWidth": 2,
            "pointRadius": 0,
            "tension": 0.4,
            "fill": True,
            "order": 1
        })
        
        # Anomalies
        anomalies = [totals if is_anom else None for totals, is_anom in zip(pivoted["total_volume"], pivoted["is_anomaly"])]
        
        # Only add anomaly dataset if any exist
        if any(anomalies):
            datasets.append({
                "label": "Anomaly (> 2σ)",
                "data": anomalies,
                "type": "scatter",
                "backgroundColor": "#ff0000",
                "pointRadius": 6,
                "pointStyle": "triangle",
                "order": 0 
            })

        # Interpretation
        peak_idx = pivoted["total_volume"].arg_max()
        peak_time = labels[peak_idx] if peak_idx is not None else "?"
        peak_val = pivoted[peak_idx, "total_volume"] if peak_idx is not None else 0
        
        interpretation = (
            f"Analysis: Peak activity at {peak_time} ({int(peak_val)} events). "
            f"Trend: {'Rising' if pivoted['trend_sma'][-1] > pivoted['trend_sma'][0] else 'Stable/Falling'}. "
            f"Anomalies found: {sum(pivoted['is_anomaly'])}."
        )

        # Compute global stats for context reference lines
        all_volumes = pivoted["total_volume"].to_list()
        global_max = max(all_volumes) if all_volumes else 1
        global_mean = sum(all_volumes) / len(all_volumes) if all_volumes else 1
        global_min = min(all_volumes) if all_volumes else 0

        return {
            "labels": labels,
            "datasets": datasets,
            "interpretation": interpretation,
            "stacked": True,
            "global_stats": {
                "max_bucket": int(global_max),
                "mean_bucket": round(global_mean, 1),
                "min_bucket": int(global_min),
                "total_events": file_total,
                "total_buckets": len(all_volumes)
            },
            "noise_info": {
                "top_talker_id": top_talker_id,
                "percent": round(top_talker_pct * 100, 1)
            },
            "stats": {
                "total_events": view_total,
                "file_total": file_total,
                "start_time": view_min.isoformat() if view_min else None,
                "end_time": view_max.isoformat() if view_max else None,
                "file_start": file_min.isoformat() if file_min else None,
                "file_end": file_max.isoformat() if file_max else None
            }
        }
    except Exception as e:
        print(f"Analysis Error: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

# Global DataFrame Cache (Simple in-memory for demo)
# Global DataFrame Cache (Simple in-memory for demo)
main_df = None
current_loaded_filename = None

# We need a way to load main_df. 
# Currently 'upload' endpoint saves file but doesn't load main_df globally.
# This logic needs to be robust. 
# get_histogram should load it if invalid.

@app.get("/api/histogram/{filename}")
async def get_histogram(filename: str, exclude_id: str = None, start_time: str = None, end_time: str = None, query: str = None, col_filters: str = None):
    """
    Get Histogram for FULL file (standard view).
    Supports ?exclude_id=4624 to hide specific EventID.
    Supports time filtering ?start_time=..&end_time=..
    Supports column filters ?col_filters={"EventID":"2050"}
    """
    global main_df, current_loaded_filename
    try:
        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        # Lazy Load Logic: If main_df is None or mismatch, reload
        if main_df is None or current_loaded_filename != filename:
             print(f"Loading new file into memory: {filename}")
             main_df = pl.read_csv(csv_path, ignore_errors=True, infer_schema_length=0)
             current_loaded_filename = filename
        
        df = main_df 
        if df is None: return {"error": "No data loaded"}

        # Filter Noise
        if exclude_id and exclude_id.strip():
            df = df.with_columns(pl.col("EventID").cast(pl.Utf8))
            df = df.filter(pl.col("EventID") != exclude_id)

        # Filter by Search Query
        if query and query.strip():
            import functools, operator
            q_lower = query.strip().lower()
            string_cols = [name for name, dtype in df.schema.items() if dtype in [pl.String, pl.Utf8]]
            if string_cols:
                # literal=True for robust matching, fill_null(False) to handle missing values
                search_filters = [
                    pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(q_lower, literal=True).fill_null(False) 
                    for c in string_cols
                ]
                combined_filter = functools.reduce(operator.or_, search_filters)
                df = df.filter(combined_filter)

        # Apply Column Header Filters (from Tabulator)
        if col_filters and col_filters.strip():
            try:
                import json
                filters = json.loads(col_filters)
                for col_name, col_value in filters.items():
                    if col_name in df.columns and col_value:
                        # Case-insensitive contains match (same as Tabulator headerFilter behavior)
                        df = df.filter(
                            pl.col(col_name).cast(pl.Utf8).str.to_lowercase().str.contains(
                                col_value.lower(), literal=True
                            )
                        )
            except Exception as e:
                print(f"Warning: Failed to parse col_filters: {e}")

        return analyze_dataframe(df, start_time=start_time, end_time=end_time)

    except Exception as e:
        return {"error": str(e)}

class SubsetRequest(BaseModel):
    filename: str
    selected_ids: List[Any]

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

        # Sort by timestamp (same logic as get_data) to align _id values
        time_col_sort = None
        time_candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
        for col_name in schema.names():
            if col_name.lower() in time_candidates:
                time_col_sort = col_name
                break

        if time_col_sort:
            c_sort = pl.col(time_col_sort).cast(pl.Utf8)
            lf = lf.with_columns(
                pl.coalesce([
                    pl.from_epoch(pl.col(time_col_sort).cast(pl.Int64, strict=False), time_unit="ms"),
                    pl.from_epoch(pl.col(time_col_sort).cast(pl.Int64, strict=False), time_unit="s"),
                    c_sort.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y", strict=False),
                ]).alias("_ts_sort_")
            ).sort("_ts_sort_", nulls_last=True).drop("_ts_sort_")

        # Assign _id AFTER sorting (same as get_data)
        lf = lf.with_row_index(name="_id", offset=1)

        # Parse the selected IDs
        valid_ids = []
        for i in req.selected_ids:
            try: valid_ids.append(int(i))
            except: pass
            
        if not valid_ids: return {"error": "No valid IDs provided"}
        
        # Filter by _id column (matches the _id sent from frontend)
        df_subset = lf.filter(pl.col("_id").is_in(valid_ids)).drop("_id").collect()

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
        traceback.print_exc()
        return {"error": str(e)}


@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(OUTPUT_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    return JSONResponse(content={"error": "File not found"}, status_code=404)

class FilterModel(BaseModel):
    field: str
    type: str
    value: Any

class ExportRequest(BaseModel):
    filename: str
    filters: list = []
    selected_ids: list = []
    format: str = "csv"
    query: str = ""
    start_time: str = ""
    end_time: str = ""

@app.post("/api/export_filtered")
async def export_filtered(request: ExportRequest):
    import polars as pl
    import zipfile # Added import
    import time # Already present, but ensuring it's here
    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        # Scan and add Row ID to match Frontend (1-based)
        lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
        lf = lf.with_row_count(name="_id", offset=1)

        # 1. Apply Filtering by Selected IDs (Tags)
        if request.selected_ids:
            lf = lf.filter(pl.col("_id").is_in(request.selected_ids))
        
        # 2. Apply Column Filters (if any)
        # Tabulator sends: {field, type, value}
        # Types: "like", "=", "!=", "<", ">", ">=", "<="
        if request.filters:
            for f in request.filters:
                # Basic Type Handling
                col = pl.col(f.field)
                val = f.value
                
                # Check if column is string to handle "like" case insensitive
                # Polars requires type awareness. We can try/except or force str for "like"
                
                if f.type == "like":
                    # Assume string search
                    lf = lf.filter(col.cast(pl.Utf8).str.to_lowercase().str.contains(str(val).lower(), literal=True))
                elif f.type == "=":
                    # String or Number match? 
                    # If val is numeric, polars might handle strict types.
                    # Ideally, frontend sends correct type.
                    lf = lf.filter(col.cast(pl.Utf8) == str(val))
                elif f.type == "!=":
                    lf = lf.filter(col.cast(pl.Utf8) != str(val))
                elif f.type == ">":
                    lf = lf.filter(col > val)
                elif f.type == "<":
                    lf = lf.filter(col < val)
                elif f.type == ">=":
                    lf = lf.filter(col >= val)
                elif f.type == "<=":
                    lf = lf.filter(col <= val)

        # 3. Apply Global Search (same logic as get_data)
        if request.query and request.query.strip():
            import functools, operator
            q_lower = request.query.strip().lower()
            schema = lf.collect_schema()
            string_cols = [name for name, dtype in schema.items() if dtype == pl.String or dtype == pl.Utf8]
            if string_cols:
                search_filters = [pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(q_lower, literal=True) for c in string_cols]
                combined_filter = functools.reduce(operator.or_, search_filters)
                lf = lf.filter(combined_filter)

        # 4. Apply Time Filtering (same logic as get_data)
        if request.start_time or request.end_time:
            time_col_export = None
            schema = lf.collect_schema()
            candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
            for col_name in schema.keys():
                if col_name.lower() in candidates:
                    time_col_export = col_name
                    break
            if time_col_export:
                c_ts = pl.col(time_col_export).cast(pl.Utf8)
                lf = lf.with_columns(
                    pl.coalesce([
                        pl.from_epoch(pl.col(time_col_export).cast(pl.Int64, strict=False), time_unit="ms"),
                        pl.from_epoch(pl.col(time_col_export).cast(pl.Int64, strict=False), time_unit="s"),
                        c_ts.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                        c_ts.str.to_datetime("%Y-%m-%d", strict=False),
                        c_ts.str.to_datetime("%m/%d/%Y", strict=False),
                    ]).alias("_ts_filter_")
                )
                if request.start_time:
                    lf = lf.filter(pl.col("_ts_filter_") >= pl.lit(request.start_time).str.to_datetime(strict=False))
                if request.end_time:
                    lf = lf.filter(pl.col("_ts_filter_") <= pl.lit(request.end_time).str.to_datetime(strict=False))
                lf = lf.drop("_ts_filter_")

        # Collect Result
        # Allow streaming? For simplicity, write to temp file then serve?
        # Or collect to memory if < 100MB? 
        # Large filtered export might be huge.
        # Safe bet: Write to a "temp_export_TIMESTAMP.csv" and serve it.
        
        import time
        temp_filename = f"export_{int(time.time())}.{request.format}"
        temp_path = os.path.join(OUTPUT_DIR, temp_filename)
        
        # Collect and Process DataFrame
        
        # Rename _id to match "No." column and ensure it's first
        lf = lf.rename({"_id": "No."})
        
        # Reorder columns to make "No." first
        all_cols = lf.collect_schema().names()
        if "No." in all_cols:
            # Move "No." to front
            other_cols = [c for c in all_cols if c != "No."]
            lf = lf.select(["No."] + other_cols)
            
        # User Request: Truncate Timestamp to Seconds (remove micro/nanoseconds)
        # Assuming Timestamp is in "YYYY-MM-DD HH:MM:SS.ssssss" format (Length 19 for seconds)
        if "Timestamp" in all_cols:
            # Strict slice to 19 chars: "2026-01-10 21:15:36" (19 chars)
            # If shorter, it keeps it. If longer, it cuts.
            # Convert to string first to be safe.
            lf = lf.with_columns(
                pl.col("Timestamp").cast(pl.String).str.slice(0, 19).alias("Timestamp")
            )

        # User Request: Remove redundant "Line" or "Original_Id" columns from Export
        cols_to_drop = [c for c in all_cols if c.lower() in ['line', 'linenumber', 'original_id']]
        if cols_to_drop:
            lf = lf.drop(cols_to_drop)
        
        df = lf.collect()
        
        # Write based on format
        if request.format == "xlsx":
            df.write_excel(temp_path)
        else:
            df.write_csv(temp_path)
        
        return FileResponse(temp_path, filename=f"Chronos_Export.{request.format}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)
@app.post("/api/export_split")
async def export_split(request: ExportRequest):
    import polars as pl
    import zipfile
    import time
    import glob
    import shutil

    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        # Temp file usage avoids loading everything into RAM
        temp_full_csv = os.path.join(OUTPUT_DIR, f"temp_full_{int(time.time())}.csv")
        zip_filename = f"Chronos_Split_{int(time.time())}.zip"
        zip_path = os.path.join(OUTPUT_DIR, zip_filename)

        # Determine if we need to apply filters
        has_filters = (
            request.selected_ids or 
            request.filters or 
            (request.query and request.query.strip()) or 
            request.start_time or 
            request.end_time
        )

        if not has_filters:
            # OPTIMIZATION: If no filters, just use the original file as source
            # But we must add "No." column if it's missing? The original file doesn't have it unless we added it.
            # The user expects "No." column usually.
            # Let's Scan and Sink to add Row Count cheaply
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            lf = lf.with_row_count(name="No.", offset=1)
            # Reorder if necessary? Usually fine.
            lf.sink_csv(temp_full_csv)
        else:
            # Apply Filters (Scan Mode)
            lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
            lf = lf.with_row_count(name="_id", offset=1)

            # 1. ID Filter
            if request.selected_ids:
                lf = lf.filter(pl.col("_id").is_in(request.selected_ids))
            
            # 2. Column Filters
            if request.filters:
                for f in request.filters:
                    col = pl.col(f.field)
                    val = f.value
                    if f.type == "like":
                        lf = lf.filter(col.cast(pl.Utf8).str.to_lowercase().str.contains(str(val).lower(), literal=True))
                    elif f.type == "=":
                        lf = lf.filter(col.cast(pl.Utf8) == str(val))
                    elif f.type == "!=":
                        lf = lf.filter(col.cast(pl.Utf8) != str(val))
                    elif f.type == ">":
                        lf = lf.filter(col > val)
                    elif f.type == "<":
                        lf = lf.filter(col < val)
                    elif f.type == ">=":
                        lf = lf.filter(col >= val)
                    elif f.type == "<=":
                        lf = lf.filter(col <= val)

            # 3. Global Search
            if request.query and request.query.strip():
                import functools, operator
                q_lower = request.query.strip().lower()
                schema = lf.collect_schema()
                string_cols = [name for name, dtype in schema.items() if dtype == pl.String or dtype == pl.Utf8]
                if string_cols:
                    search_filters = [pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(q_lower, literal=True) for c in string_cols]
                    combined_filter = functools.reduce(operator.or_, search_filters)
                    lf = lf.filter(combined_filter)

            # 4. Time Filtering (Only if requested - expensive!)
            if request.start_time or request.end_time:
                time_col_exp = None
                schema = lf.collect_schema()
                candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
                for col_name in schema.keys():
                    if col_name.lower() in candidates:
                        time_col_exp = col_name
                        break
                if time_col_exp:
                    # Heavy date parsing logic only when needed
                    c_ts = pl.col(time_col_exp).cast(pl.Utf8)
                    lf = lf.with_columns(
                         pl.coalesce([
                             pl.from_epoch(pl.col(time_col_exp).cast(pl.Int64, strict=False), time_unit="ms"),
                             pl.from_epoch(pl.col(time_col_exp).cast(pl.Int64, strict=False), time_unit="s"),
                             c_ts.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                             c_ts.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                             c_ts.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                             c_ts.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                             c_ts.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                             c_ts.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                             c_ts.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                             c_ts.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                             c_ts.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                             c_ts.str.to_datetime("%Y-%m-%d", strict=False),
                             c_ts.str.to_datetime("%m/%d/%Y", strict=False),
                        ]).alias("_ts_filter_")
                    )
                    if request.start_time:
                        lf = lf.filter(pl.col("_ts_filter_") >= pl.lit(request.start_time).str.to_datetime(strict=False))
                    if request.end_time:
                        lf = lf.filter(pl.col("_ts_filter_") <= pl.lit(request.end_time).str.to_datetime(strict=False))
                    lf = lf.drop("_ts_filter_")

            # Rename _id to No.
            lf = lf.rename({"_id": "No."})
            
            # SINK to Temp File (Streaming) - Avoids OOM
            lf.sink_csv(temp_full_csv)

        # Split Logic (Byte-based)
        CHUNK_SIZE_BYTES = 95 * 1024 * 1024 # ~95MB safe limit for 99MB max
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            part_num = 1
            current_bytes = 0
            current_lines = []
            header = None
            
            with open(temp_full_csv, 'r', encoding='utf-8', errors='replace') as infile:
                header = infile.readline()
                current_lines.append(header)
                current_bytes += len(header.encode('utf-8'))
                
                for line in infile:
                    line_bytes = len(line.encode('utf-8'))
                    
                    if current_bytes + line_bytes > CHUNK_SIZE_BYTES:
                         # Write chunk
                         part_filename = f"Part_{part_num}.csv"
                         temp_part_path = os.path.join(OUTPUT_DIR, f"temp_part_{part_num}_{int(time.time())}.csv")
                         with open(temp_part_path, 'w', encoding='utf-8') as outfile:
                             outfile.writelines(current_lines)
                         
                         zipf.write(temp_part_path, arcname=part_filename)
                         os.remove(temp_part_path)
                         
                         # Reset for next chunk
                         part_num += 1
                         current_lines = [header]
                         current_bytes = len(header.encode('utf-8'))
                    
                    current_lines.append(line)
                    current_bytes += line_bytes
                
                # Write final chunk
                if len(current_lines) > 1: # Header + Data
                    part_filename = f"Part_{part_num}.csv"
                    temp_part_path = os.path.join(OUTPUT_DIR, f"temp_part_{part_num}_{int(time.time())}.csv")
                    with open(temp_part_path, 'w', encoding='utf-8') as outfile:
                        outfile.writelines(current_lines)
                    zipf.write(temp_part_path, arcname=part_filename)
                    os.remove(temp_part_path)

        # Cleanup Full Temp
        if os.path.exists(temp_full_csv):
            os.remove(temp_full_csv)

        return FileResponse(zip_path, filename=zip_filename)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
