from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil
import uuid
import pandas as pd
import polars as pl
import json
import traceback
from datetime import datetime, timedelta
import numpy as np
import time
from typing import Optional, List, Any
from pydantic import BaseModel

# --- MOTORES PROPIOS ---
from mft_engine import process_mft_file
from evtx_engine import process_evtx_file

app = FastAPI(title="Chronos-DFIR Web API")

# --- MIDDLEWARE: No-Cache ---
@app.middleware("http")
async def add_no_cache_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de carpetas
UPLOAD_DIR = "/Users/ivanhuerta/Documents/chronos_antigravity/uploads"
OUTPUT_DIR = "/Users/ivanhuerta/Documents/chronos_antigravity/output"
STATIC_DIR = "/Users/ivanhuerta/Documents/chronos_antigravity/static"
TEMPLATES_DIR = "/Users/ivanhuerta/Documents/chronos_antigravity/templates"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Montar archivos estáticos y plantillas
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def upload_artifact(file: UploadFile = File(...), artifact_type: str = Form(...)):
    try:
        file_id = str(uuid.uuid4())
        ext = file.filename.split('.')[-1].lower()
        file_path = os.path.join(UPLOAD_DIR, f"{file_id}.{ext}")

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Determinar si es un reporte directo o requiere parsing
        report_extensions = ['csv', 'xlsx', 'tsv', 'json', 'parquet', 'sqlite']
        
        if ext in report_extensions:
            # Es un reporte genérico
            # Convertimos a CSV para el frontend (usando Polars para velocidad)
            csv_filename = f"Report_{file_id}.csv"
            csv_path = os.path.join(OUTPUT_DIR, csv_filename)
            
            if ext == 'csv':
                shutil.copy(file_path, csv_path)
            elif ext == 'xlsx':
                df = pl.read_excel(file_path)
                df.write_csv(csv_path)
            elif ext == 'parquet':
                df = pl.read_parquet(file_path)
                df.write_csv(csv_path)
            # Más formatos según necesidad...

            return {
                "status": "success",
                "processed_records": "N/A",
                "data_url": f"/api/data/{csv_filename}",
                "csv_filename": csv_filename,
                "file_category": "generic"
            }

        else:
            # Parsing Forense Real
            from timeline_skill import generate_unified_timeline
            result_json = generate_unified_timeline(file_path, artifact_type, OUTPUT_DIR)
            result = json.loads(result_json)

            if "error" in result:
                return JSONResponse(content={"error": result["error"]}, status_code=500)

            csv_filename = os.path.basename(result["files"]["csv"])
            xlsx_filename = os.path.basename(result["files"]["excel"])

            return {
                "status": "success",
                "processed_records": result["processed_records"],
                "data_url": f"/api/data/{csv_filename}",
                "csv_filename": csv_filename,
                "xlsx_filename": xlsx_filename,
                "file_category": "forensic"
            }

    except Exception as e:
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/api/data/{filename}")
async def get_data(filename: str, page: int = 1, size: int = 50, query: Optional[str] = None, start_time: Optional[str] = None, end_time: Optional[str] = None, col_filters: Optional[str] = None, sort_col: Optional[str] = None, sort_dir: Optional[str] = None):
    try:
        csv_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "File not found"}, status_code=404)

        # Usar LazyFrame para eficiencia extrema en archivos de GBs
        lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
        
        # --- STABLE SORT BY TIMESTAMP (BEFORE _id generation) ---
        # Identifying the time column candidate
        schema = lf.collect_schema()
        time_col = None
        time_candidates = [
            'time', 'timestamp', 'date', 'datetime', 'insert_timestamp', 
            '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 
            'date_time', 'start_time', 'end_time', 'testtime', 
            'object first seen', 'first seen', 'last seen', 'creation time'
        ]
        for col_name in schema.keys():
            if any(c in col_name.lower() for c in time_candidates):
                time_col = col_name
                break
        
        if time_col:
            # We must coalesce and convert to datetime for stable sorting
            # This is slow on first load but ensures ID consistency
            c = pl.col(time_col).cast(pl.Utf8)
            lf = lf.with_columns(
                pl.coalesce([
                    pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="ms"),
                    pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="s"),
                    c.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                    c.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                    c.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                    c.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                    c.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                    c.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                    c.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                    c.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                    c.str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                    c.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                    c.str.to_datetime("%d/%m/%Y %H:%M", strict=False),
                    c.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                    c.str.to_datetime("%b %d, %Y %I:%M %p", strict=False),
                    c.str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                    c.str.to_datetime("%Y-%m-%d", strict=False),
                    c.str.to_datetime("%m/%d/%Y", strict=False),
                ]).alias("_ts_sort_")
            ).sort("_ts_sort_", descending=False).drop("_ts_sort_")

        # GENERATE ID AFTER SORT
        lf = lf.with_row_index(name="_id", offset=1)

        # 1. Aplicar Filtro Global (Search)
        if query and query.strip():
            query_val = query.strip().lower()
            all_cols = lf.collect_schema().names()
            if all_cols:
                # Use horizontal search for speed across many columns
                lf = lf.filter(
                    pl.any_horizontal(
                        pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(query_val, literal=True).fill_null(False)
                        for c in all_cols
                    )
                )

        # 2. Aplicar Filtros de Tiempo
        if start_time or end_time:
            # Reuses detection logic from sorting if needed, but here we can just do a string comparison if format is fixed
            # or better re-parse if format varies. Since we sorted by converted TS already, we should parse.
            if time_col:
                c = pl.col(time_col).cast(pl.Utf8)
                lf = lf.with_columns(
                    pl.coalesce([
                        pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="ms"),
                        pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="s"),
                        c.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                        c.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                        c.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                        c.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                        c.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                        c.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                        c.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                        c.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                        c.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                        c.str.to_datetime("%Y-%m-%d", strict=False),
                        c.str.to_datetime("%m/%d/%Y", strict=False),
                    ]).alias("_ts_filter_")
                )
                if start_time:
                    lf = lf.filter(pl.col("_ts_filter_") >= pl.lit(start_time).str.to_datetime(strict=False))
                if end_time:
                    lf = lf.filter(pl.col("_ts_filter_") <= pl.lit(end_time).str.to_datetime(strict=False))
                lf = lf.drop("_ts_filter_")

        # 3. Aplicar Filtros de Columna (desde el header del grid)
        if col_filters and col_filters.strip():
            try:
                filters = json.loads(col_filters)
                for col_name, col_value in filters.items():
                    if col_name in lf.collect_schema().names() and col_value:
                        lf = lf.filter(
                            pl.col(col_name).cast(pl.Utf8).str.to_lowercase().str.contains(
                                col_value.lower(), literal=True
                            ).fill_null(False)
                        )
            except Exception as e:
                print(f"Warning: Failed to parse col_filters: {e}")

        # 4. User-Requested Sorting
        if sort_col and sort_dir:
            descending = (sort_dir.lower() == 'desc')
            actual_col = None
            
            # Case-insensitive column finding
            all_cols = lf.collect_schema().names()
            for c in all_cols:
                if c.lower() == sort_col.lower():
                    actual_col = c
                    break
            
            if not actual_col and sort_col.lower() == "no.":
                actual_col = "_id"

            if actual_col:
                # Try sorting as numbers if possible, fallback to string
                try:
                    # Test if column can be numeric? (Too expensive on scan)
                    # For now, stable string sort
                    lf = lf.sort(actual_col, descending=descending)
                except:
                    lf = lf.sort(actual_col, descending=descending)

        # Contar total filtrado
        total = lf.select(pl.len()).collect().item()

        # Paginación
        offset = (page - 1) * size
        df_page = lf.slice(offset, size).collect()

        return {
            "total": total,
            "page": page,
            "size": size,
            "last_page": (total // size) + (1 if total % size > 0 else 0),
            "data": df_page.to_dicts()
        }

    except Exception as e:
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

def analyze_dataframe(df: pl.DataFrame, target_bars: int = 50, start_time: str = None, end_time: str = None):
    """
    Motor estadístico para generar el histograma.
    Detecta automáticamente frecuencia (segundos, minutos, días).
    """
    try:
        # Detectar Columna de Tiempo
        time_col = None
        candidates = ['time', 'timestamp', 'date', 'datetime', 'insert_timestamp', '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 'date_time', 'start_time', 'end_time']
        for col in df.columns:
            if col.lower() in candidates:
                time_col = col
                break
        
        if not time_col:
            return {"error": "Time column not found"}

        # Convertir a Datetime
        c = pl.col(time_col).cast(pl.Utf8)
        df = df.with_columns(
            pl.coalesce([
                pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="ms"),
                pl.from_epoch(pl.col(time_col).cast(pl.Int64, strict=False), time_unit="s"),
                c.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                c.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                c.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                c.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                c.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                c.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                c.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                c.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                c.str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                c.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                c.str.to_datetime("%d/%m/%Y %H:%M", strict=False),
                c.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                c.str.to_datetime("%b %d, %Y %I:%M %p", strict=False),
                c.str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                c.str.to_datetime("%Y-%m-%d", strict=False),
                c.str.to_datetime("%m/%d/%Y", strict=False),
            ]).alias("ts")
        ).filter(pl.col("ts").is_not_null())

        if df.height == 0:
            return {"error": "No valid timestamps found"}

        # Global file stats (before any zooming)
        file_total = df.height
        file_min = df["ts"].min()
        file_max = df["ts"].max()

        # Update df if start/end zoom is applied from chart
        if start_time:
            df = df.filter(pl.col("ts") >= pl.lit(start_time).str.to_datetime(strict=False))
        if end_time:
            df = df.filter(pl.col("ts") <= pl.lit(end_time).str.to_datetime(strict=False))
        
        if df.height == 0:
             return {"error": "No events in this time range"}

        view_total = df.height
        view_min = df["ts"].min()
        view_max = df["ts"].max()

        duration = (view_max - view_min).total_seconds()
        
        # Determinar Intervalo (Bucket size)
        if duration < 60: interval = "1s"
        elif duration < 3600: interval = "1m"
        elif duration < 86400: interval = "5m"
        elif duration < 86400 * 7: interval = "1h"
        else: interval = "1d"

        # Pivotar por Categoría (Level) si existe
        cat_col = "Level" if "Level" in df.columns else None
        
        # Aggregation
        if cat_col:
            pivoted = df.group_by_dynamic("ts", every=interval).agg(
                pl.len().alias("total_volume"),
                pl.col(cat_col).value_counts().alias("counts")
            ).explode("counts").unnest("counts").pivot(
                index="ts", columns=cat_col, values="count"
            ).fill_null(0)
            
            # Re-calculamos total_volume si el pivot lo perdió o para exactitud
            value_cols = [c for c in pivoted.columns if c != "ts"]
            pivoted = pivoted.with_columns(
                total_volume = pl.sum_horizontal(value_cols)
            )
        else:
            pivoted = df.group_by_dynamic("ts", every=interval).agg(
                pl.len().alias("total_volume")
            ).fill_null(0)
            value_cols = ["total_volume"]

        # Estadísticas de Tendencia y Anomalías
        pivoted = pivoted.with_columns(
            trend_sma = pl.col("total_volume").rolling_mean(window_size=max(1, len(pivoted)//10), center=True).fill_null(strategy="forward").fill_null(strategy="backward"),
            std_dev = pl.col("total_volume").std()
        ).with_columns(
            is_anomaly = pl.col("total_volume") > (pl.col("trend_sma") + 2 * pl.col("std_dev").fill_null(0))
        )

        # AI Interpretation Snippets
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
main_df = None
current_loaded_filename = None

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
            q_lower = query.strip().lower()
            all_cols = df.columns
            if all_cols:
                try:
                    df = df.filter(
                        pl.any_horizontal(
                            pl.col(c).cast(pl.Utf8).str.to_lowercase().str.contains(q_lower, literal=True).fill_null(False)
                            for c in all_cols
                        )
                    )
                except Exception as e:
                    print(f"Chart search optimization failed: {e}. Falling back to iterative search.")
                    import functools, operator
                    filters = []
                    for c in all_cols:
                        try:
                            filters.append(
                                pl.col(c).cast(pl.Utf8, strict=False).str.to_lowercase().str.contains(q_lower, literal=True).fill_null(False)
                            )
                        except: pass
                    if filters:
                        df = df.filter(functools.reduce(operator.or_, filters))

        # Apply Column Header Filters
        if col_filters and col_filters.strip():
            try:
                import json
                filters = json.loads(col_filters)
                for col_name, col_value in filters.items():
                    if col_name in df.columns and col_value:
                        df = df.filter(
                            pl.col(col_name).cast(pl.Utf8).str.to_lowercase().str.contains(
                                col_value.lower(), literal=True
                            ).fill_null(False)
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

        # STABLE SORT BY TIMESTAMP
        time_col_sort = None
        time_candidates_sort = [
            'time', 'timestamp', 'date', 'datetime', 'insert_timestamp', 
            '_time', 'eventtime', 'creationtime', 'logtime', 'time_created', 
            'date_time', 'start_time', 'end_time', 'testtime', 
            'object first seen', 'first seen', 'last seen', 'creation time'
        ]
        for col_name in schema.keys():
            if any(c in col_name.lower() for c in time_candidates_sort):
                time_col_sort = col_name
                break

        if time_col_sort:
            c_sort = pl.col(time_col_sort).cast(pl.Utf8)
            lf = lf.with_columns(
                pl.coalesce([
                    pl.from_epoch(pl.col(time_col_sort).cast(pl.Int64, strict=False), time_unit="ms"),
                    pl.from_epoch(pl.col(time_col_sort).cast(pl.Int64, strict=False), time_unit="s"),
                    c_sort.str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%dT%H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d %H:%M", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %I:%M:%S %p", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %I:%M %p", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y %H:%M", strict=False),
                    c_sort.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%d/%m/%Y %H:%M", strict=False),
                    c_sort.str.to_datetime("%b %d %Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%b %d, %Y %I:%M %p", strict=False),
                    c_sort.str.to_datetime("%d-%m-%Y %H:%M:%S", strict=False),
                    c_sort.str.to_datetime("%Y-%m-%d", strict=False),
                    c_sort.str.to_datetime("%m/%d/%Y", strict=False),
                ]).alias("_ts_sort_")
            ).sort("_ts_sort_", descending=False).drop("_ts_sort_")

        # Assign _id AFTER sorting
        lf = lf.with_row_index(name="_id", offset=1)

        # Parse the selected IDs
        valid_ids = []
        for i in req.selected_ids:
            try: valid_ids.append(int(i))
            except: pass
            
        if not valid_ids: return {"error": "No valid IDs provided"}
        
        # Filter by _id column
        df_subset = lf.filter(pl.col("_id").is_in(valid_ids)).drop("_id").collect()

        if df_subset.height == 0:
            return {"error": "No matching rows found"}

        result = analyze_dataframe(df_subset, target_bars=30) 
        if "error" in result:
            return result

        # Override global_stats with REAL stats from the FULL dataset
        full_df = lf.drop("_id").collect()
        full_result = analyze_dataframe(full_df, target_bars=50)
        if "global_stats" in full_result:
            result["global_stats"] = full_result["global_stats"]

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

class ExportRequest(BaseModel):
    filename: str
    filters: list = []
    selected_ids: list = []
    format: str = "csv"
    query: str = ""
    start_time: str = ""
    end_time: str = ""
    ai_optimized: bool = False
    visible_columns: list[str] = []

@app.post("/api/export_filtered")
async def export_filtered(request: ExportRequest):
    import zipfile
    import time
    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
        lf = lf.with_row_count(name="_id", offset=1)

        # 1. Filtering by Selected IDs
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

        # 4. Time Filtering
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

        # 5. Format Timestamps and Cleanup
        schema_final = lf.collect_schema()
        all_cols = schema_final.names()
        
        # Rename _id to No.
        lf = lf.rename({"_id": "No."})
        
        # Reorder columns
        if "No." in all_cols:
            other_cols = [c for c in all_cols if c != "_id" and c != "No."]
            lf = lf.select(["No."] + other_cols)
            
        # Truncate Timestamp
        if "Timestamp" in all_cols:
            lf = lf.with_columns(
                pl.col("Timestamp").cast(pl.String).str.slice(0, 19).alias("Timestamp")
            )

        # Remove redundant columns
        cols_to_drop = [c for c in all_cols if c.lower() in ['line', 'linenumber', 'original_id']]
        if cols_to_drop:
            lf = lf.drop(cols_to_drop)
        
        df = lf.collect()

        # AI Optimization
        if request.ai_optimized:
            valid_cols = []
            for col_name in df.columns:
                c = df[col_name]
                if c.null_count() == df.height: continue
                if c.dtype == pl.Utf8:
                    n_empty = c.filter(c.str.contains(r"^\s*$")).len()
                    if n_empty == df.height: continue
                valid_cols.append(col_name)
            if valid_cols:
                df = df.select(valid_cols)
        
        temp_filename = f"export_{int(time.time())}.{request.format}"
        temp_path = os.path.join(OUTPUT_DIR, temp_filename)
        
        if request.format == "xlsx":
            df.write_excel(temp_path)
        else:
            df.write_csv(temp_path)
        
        return FileResponse(temp_path, filename=f"Chronos_Export.{request.format}")

    except Exception as e:
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/api/export_split")
async def export_split(request: ExportRequest):
    import zipfile
    import time
    try:
        csv_path = os.path.join(OUTPUT_DIR, request.filename)
        if not os.path.exists(csv_path):
            return JSONResponse(content={"error": "Source file not found"}, status_code=404)

        temp_full_csv = os.path.join(OUTPUT_DIR, f"temp_full_{int(time.time())}.csv")
        zip_filename = f"Chronos_Split_{int(time.time())}.zip"
        zip_path = os.path.join(OUTPUT_DIR, zip_filename)

        lf = pl.scan_csv(csv_path, ignore_errors=True, infer_schema_length=0)
        lf = lf.with_row_count(name="No.", offset=1)
        lf.sink_csv(temp_full_csv)

        CHUNK_SIZE_BYTES = 95 * 1024 * 1024
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            part_num = 1
            current_bytes = 0
            current_lines = []
            
            with open(temp_full_csv, 'r', encoding='utf-8', errors='replace') as infile:
                header = infile.readline()
                current_lines.append(header)
                current_bytes += len(header.encode('utf-8'))
                
                for line in infile:
                    line_bytes = len(line.encode('utf-8'))
                    if current_bytes + line_bytes > CHUNK_SIZE_BYTES:
                         part_filename = f"Part_{part_num}.csv"
                         temp_part_path = os.path.join(OUTPUT_DIR, f"temp_part_{part_num}.csv")
                         with open(temp_part_path, 'w', encoding='utf-8') as outfile:
                             outfile.writelines(current_lines)
                         zipf.write(temp_part_path, arcname=part_filename)
                         os.remove(temp_part_path)
                         part_num += 1
                         current_lines = [header]
                         current_bytes = len(header.encode('utf-8'))
                    current_lines.append(line)
                    current_bytes += line_bytes
                
                if len(current_lines) > 1:
                    part_filename = f"Part_{part_num}.csv"
                    temp_part_path = os.path.join(OUTPUT_DIR, f"temp_final_part_{part_num}.csv")
                    with open(temp_part_path, 'w', encoding='utf-8') as outfile:
                        outfile.writelines(current_lines)
                    zipf.write(temp_part_path, arcname=part_filename)
                    os.remove(temp_part_path)

        if os.path.exists(temp_full_csv): os.remove(temp_full_csv)
        return FileResponse(zip_path, filename=zip_filename)

    except Exception as e:
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
