"""
Chronos-DFIR Ingestor — Multi-format file parsing engine.
Extracts data from CSV, XLSX, JSON, SQLite, Plist, PSList, TXT/LOG, ZIP, TSV, Parquet.
All output is Polars DataFrame or LazyFrame. Zero pandas dependency.
"""
import os
import re
import logging
import polars as pl
from engine.forensic import ingest_json_file

logger = logging.getLogger("Chronos-DFIR")


def _read_whitespace_csv(file_path: str) -> pl.DataFrame:
    """Read whitespace-separated files (pslist, log) without pandas.
    Splits on consecutive whitespace, handles bad lines gracefully."""
    with open(file_path, 'r', errors='replace') as f:
        lines = f.readlines()
    if not lines:
        return pl.DataFrame()
    header_line = None
    data_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped:
            header_line = stripped
            data_start = i + 1
            break
    if not header_line:
        return pl.DataFrame()
    headers = re.split(r'\s+', header_line)
    n_cols = len(headers)
    rows = []
    for line in lines[data_start:]:
        stripped = line.strip()
        if not stripped:
            continue
        parts = re.split(r'\s+', stripped, maxsplit=n_cols - 1)
        if len(parts) == n_cols:
            rows.append(parts)
        elif len(parts) > n_cols:
            rows.append(parts[:n_cols])
        else:
            rows.append(parts + [''] * (n_cols - len(parts)))
    if not rows:
        return pl.DataFrame({h: [] for h in headers})
    return pl.DataFrame(
        {headers[i]: [row[i] for row in rows] for i in range(n_cols)}
    )


def _sanitize_plist_val(v):
    """Convert plist values (bytes, datetime, nested) to Polars-safe types."""
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, (dict, list)):
        return str(v)
    return v


def ingest_file(file_path: str, ext: str) -> tuple:
    """Parse a file into a Polars LazyFrame or DataFrame.

    Returns:
        tuple: (lf, df_eager, file_cat) where exactly one of lf/df_eager is set.
    """
    lf = None
    df_eager = None
    file_cat = "generic"

    if ext == '.parquet':
        lf = pl.scan_parquet(file_path)

    elif ext in ['.json', '.jsonl', '.ndjson']:
        lf = ingest_json_file(file_path)

    elif ext in ['.db', '.sqlite', '.sqlite3']:
        import sqlite3
        conn = sqlite3.connect(file_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall() if not r[0].startswith('sqlite_')]
            if not tables:
                raise Exception("No tables found")
            target_table = tables[0]
            for t in tables:
                if t.lower() in ['events', 'logs', 'timeline', 'entries']:
                    target_table = t
                    break
            cursor.execute(f'SELECT * FROM "{target_table}"')
            col_names = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            df_eager = pl.DataFrame(
                {col_names[i]: [row[i] for row in rows] for i in range(len(col_names))},
                strict=False
            ).cast({c: pl.Utf8 for c in col_names}, strict=False)
        finally:
            conn.close()

    elif ext == '.xlsx':
        df_eager = pl.read_excel(file_path)

    elif ext in ['.pslist', '.txt', '.log']:
        df_eager, file_cat = _parse_text_file(file_path, ext)

    elif ext == '.zip':
        df_eager, file_cat = _parse_zip_plist(file_path)

    elif ext == '.plist':
        df_eager = _parse_single_plist(file_path)

    elif ext == '.tsv':
        lf = pl.scan_csv(file_path, separator='\t', ignore_errors=True, infer_schema_length=0)

    else:
        lf, file_cat = _parse_csv_robust(file_path, file_cat)

    # Volatility PSList fingerprint
    if df_eager is not None:
        cols_eager = df_eager.columns
        if all(c in cols_eager for c in ["Offset(V)", "PPID", "Threads"]):
            file_cat = "Memory/Volatility_PSList"
            rename_map_vola = {}
            if "CreateTime" in cols_eager:
                rename_map_vola["CreateTime"] = "Time"
            if rename_map_vola:
                df_eager = df_eager.rename(rename_map_vola)
            exprs = [pl.lit("Volatility_RAM_Process").alias("EventID")]
            if "Name" in cols_eager and "PID" in cols_eager:
                exprs.append(
                    pl.concat_str([pl.col("Name"), pl.lit(" ["), pl.col("PID").cast(pl.Utf8), pl.lit("]")], separator="").alias("Destination_Entity")
                )
            if "PPID" in cols_eager:
                exprs.append(
                    pl.concat_str([pl.lit("PPID: "), pl.col("PPID").cast(pl.Utf8)], separator="").alias("Source_Entity")
                )
            df_eager = df_eager.with_columns(exprs)

    return lf, df_eager, file_cat


def normalize_and_save(lf, df_eager, dest_path: str) -> int:
    """Normalize column headers, add _id index, and write to CSV.
    Returns row count (or -1 for lazy/unknown)."""
    cols = lf.collect_schema().names() if lf is not None else df_eager.columns
    rename_mapping = {}

    for col in cols:
        col_str = str(col).strip()
        col_lower = col_str.lower()
        if col_lower == '_time':
            final_col = 'Time'
        elif col_lower == '_id':
            final_col = 'Original_Id'
        elif col_str.isdigit():
            final_col = f'Field_{col_str}'
        else:
            clean_col = col_str.lstrip('_')
            if clean_col:
                final_col = clean_col[0].upper() + clean_col[1:]
            else:
                final_col = col_str
        if final_col != col_str:
            rename_mapping[col_str] = final_col

    if lf is not None:
        if rename_mapping:
            lf = lf.rename(rename_mapping)
        lf = lf.with_row_index(name="_id", offset=1)
        lf.sink_csv(dest_path)
        return -1
    else:
        df_eager = df_eager.rename(rename_mapping)
        df_eager = df_eager.with_row_index(name="_id", offset=1)
        df_eager.write_csv(dest_path)
        return len(df_eager)


# ─── Private parsers ────────────────────────────────────────────────

def _parse_text_file(file_path: str, ext: str) -> tuple:
    """Parse .txt, .log, .pslist files. Returns (df_eager, file_cat)."""
    file_cat = "generic"
    try:
        if ext == '.txt':
            df_txt = pl.read_csv(file_path, separator="\x1f", has_header=False, new_columns=["raw_line"], ignore_errors=True)
            # Attempt 1: macOS Unified Log format
            regex_pattern = r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+-\d{4})\s+(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
            df_parsed = df_txt.select(
                pl.col("raw_line").str.extract_groups(regex_pattern).alias("parsed")
            ).unnest("parsed")
            df_clean = df_parsed.drop_nulls(subset=["timestamp"])

            if df_clean.height > 0:
                df_eager = df_clean.rename({"timestamp": "Time", "process": "Source_Entity", "message": "Destination_Entity", "host": "Computer"})
                df_eager = df_eager.with_columns(pl.lit("macOS_Unified_Log").alias("EventID"))
                return df_eager, "macOS/Unified_Logs"

            # Attempt 2: macOS persistence triage (ls -la output)
            ls_pattern = r"^(?P<perms>[-dlrwxst@+]{7,11}[+@]?)\s+(?P<links>\d+)\s+(?P<owner>\S+)\s+(?P<group>\S+)\s+(?P<size>\d+)\s+(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<timestr>[\d:]+)\s+(?P<name>.+)$"
            lines = df_txt["raw_line"].to_list()
            is_ls_triage = any(re.match(ls_pattern, l) for l in lines[:50] if l)

            if is_ls_triage:
                df_eager = _parse_ls_triage(lines, ls_pattern)
                if df_eager is not None:
                    return df_eager, "macOS/Persistence_Triage"

            # Fallback: whitespace-separated
            return _read_whitespace_csv(file_path), file_cat
        else:
            # .pslist / .log — try whitespace-separated
            return _read_whitespace_csv(file_path), file_cat
    except Exception as e:
        logger.error(f"Error reading pslist/txt: {e}")
        lf = pl.scan_csv(file_path, ignore_errors=True, infer_schema_length=0)
        # Return as eager for consistency
        return lf.collect(), file_cat


def _parse_ls_triage(lines: list, ls_pattern: str):
    """Parse ls -la output into a DataFrame."""
    from datetime import datetime as _dt
    records = []
    current_section = "Unknown"
    ls_re = re.compile(ls_pattern)
    current_year = _dt.now().year
    month_map = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                 "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

    for raw in lines:
        if not raw or not raw.strip():
            continue
        stripped = raw.strip()
        if stripped.endswith(":") and "/" in stripped:
            current_section = stripped.rstrip(":")
            continue
        if re.match(r"^total\s+\d+$", stripped):
            continue
        m = ls_re.match(stripped)
        if m:
            g = m.groupdict()
            mo = month_map.get(g["month"].capitalize(), 1)
            dy = int(g["day"])
            if ":" in g["timestr"]:
                hh, mm = g["timestr"].split(":")
                ts = f"{current_year}-{mo:02d}-{dy:02d} {int(hh):02d}:{int(mm):02d}:00"
            else:
                ts = f"{g['timestr']}-{mo:02d}-{dy:02d} 00:00:00"
            name = g["name"].strip()
            if name in (".", ".."):
                continue
            parent = current_section if current_section != "Unknown" else ""
            full_path = f"{parent}/{name}" if parent and not name.startswith("/") else name
            records.append({
                "Time": ts, "Permissions": g["perms"], "Links": g["links"],
                "Owner": g["owner"], "Group": g["group"], "Size": g["size"],
                "Month": g["month"], "Day": g["day"],
                "Source_Entity": g["owner"], "Destination_Entity": full_path,
                "EventID": "macOS_Persistence_Triage", "Section": current_section,
                "Computer": "triage-host",
            })
        else:
            records.append({
                "Time": "", "Permissions": "", "Links": "", "Owner": "", "Group": "",
                "Size": "", "Month": "", "Day": "", "Source_Entity": "",
                "Destination_Entity": stripped, "EventID": "macOS_Persistence_Info",
                "Section": current_section, "Computer": "triage-host",
            })

    if records:
        df = pl.DataFrame(records)
        return df.filter(pl.col("Time").str.len_chars() > 0)
    return None


def _parse_zip_plist(file_path: str) -> tuple:
    """Parse a ZIP containing .plist files (macOS bundle)."""
    import zipfile
    import tempfile
    import shutil
    from pathlib import Path
    import plistlib

    extract_dir = tempfile.mkdtemp()
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    records = []
    for plist_file in Path(extract_dir).rglob("*.plist"):
        try:
            with open(plist_file, 'rb') as f:
                data = plistlib.load(f)
            label = data.get('Label', 'UNKNOWN')
            if isinstance(data.get('ProgramArguments'), list):
                program_args = " ".join(str(x) for x in data.get('ProgramArguments'))
            else:
                program_args = str(data.get('ProgramArguments', data.get('Program', '')))
            records.append({
                "Source_File": str(plist_file.name),
                "full_path": str(plist_file),
                "EventID": label,
                "Destination_Entity": program_args,
                "run_at_load": str(data.get('RunAtLoad', False)),
                "keep_alive": str(data.get('KeepAlive', False)),
                "Time": "1970-01-01 00:00:00"
            })
        except Exception as e:
            logger.error(f"Error parsing plist in zip: {e}")

    shutil.rmtree(extract_dir, ignore_errors=True)

    if not records:
        raise Exception("No valid .plist files found in the ZIP archive.")

    return pl.DataFrame(records), "macOS/Bulk_Plist"


def _parse_single_plist(file_path: str) -> pl.DataFrame:
    """Parse a single .plist file into a Polars DataFrame."""
    import plistlib
    with open(file_path, 'rb') as fp:
        plist_data = plistlib.load(fp)

    if isinstance(plist_data, dict):
        list_keys = [k for k, v in plist_data.items() if isinstance(v, list)]
        if len(list_keys) == 1:
            plist_data = plist_data[list_keys[0]]
        else:
            plist_data = [plist_data]
    elif not isinstance(plist_data, list):
        plist_data = [{"Value": str(plist_data)}]

    sanitized = [{k: _sanitize_plist_val(v) for k, v in row.items()} for row in plist_data]
    if not sanitized:
        return pl.DataFrame()
    cols = list(sanitized[0].keys())
    return pl.DataFrame(sanitized, strict=False).cast({c: pl.Utf8 for c in cols}, strict=False)


def _parse_csv_robust(file_path: str, file_cat: str) -> tuple:
    """Robust CSV reading with encoding fallback and headerless detection."""
    try:
        lf = pl.scan_csv(file_path, ignore_errors=True, infer_schema_length=0)
        lf.head(1).collect()
    except Exception:
        try:
            lf = pl.scan_csv(file_path, ignore_errors=True, infer_schema_length=0, encoding='utf8-lossy')
        except Exception as final_e:
            raise final_e

    # Detect headerless CSV: first column name looks like Unix permissions
    try:
        _first_col = lf.collect_schema().names()[0]
        if re.match(r'^[-dlcbpst][-rwxst@+]{6,}', _first_col) or _first_col.startswith('/'):
            _n_cols = len(lf.collect_schema().names())
            _new_cols = [f'Field_{i}' for i in range(_n_cols)]
            try:
                lf = pl.scan_csv(file_path, has_header=False, new_columns=_new_cols, ignore_errors=True, infer_schema_length=0)
            except Exception:
                lf = pl.scan_csv(file_path, has_header=False, new_columns=_new_cols, ignore_errors=True, infer_schema_length=0, encoding='utf8-lossy')
            file_cat = "FileSystem/LS_Triage"
    except Exception:
        pass

    return lf, file_cat
