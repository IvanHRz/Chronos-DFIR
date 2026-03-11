import polars as pl
import xlsxwriter
import os
import json
from datetime import datetime

# Importamos nuestros motores
from mft_engine import process_mft_file
from evtx_engine import process_evtx_file

def generate_unified_timeline(source_path: str, artifact_type: str, output_dir: str) -> str:
    """
    Skill principal para Antigravity. Parsea MFT o EVTX y exporta a Excel/CSV.
    Zero pandas dependency — uses Polars write_excel natively.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. Ejecutar el motor correspondiente
    try:
        if artifact_type.upper() == "MFT":
            df = process_mft_file(source_path)
        elif artifact_type.upper() == "EVTX":
            df = process_evtx_file(source_path)
        else:
            return json.dumps({"error": "Tipo de artefacto no soportado (Usa MFT o EVTX)"})
    except Exception as e:
        return json.dumps({"error": f"Error en el motor: {str(e)}"})

    # 2. Preparar rutas de salida
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"Timeline_{artifact_type}_{ts}"
    csv_path = os.path.join(output_dir, f"{filename}.csv")
    xlsx_path = os.path.join(output_dir, f"{filename}.xlsx")

    # 3. Exportar CSV (Velocidad nativa Polars)
    df.write_csv(csv_path)

    # 4. Exportar Excel (xlsxwriter directo — Polars write_excel deprecated params)
    with xlsxwriter.Workbook(str(xlsx_path)) as wb:
        ws = wb.add_worksheet("Timeline")
        header_fmt = wb.add_format({"bold": True, "bg_color": "#1a1a2e", "font_color": "#ffffff"})
        text_fmt = wb.add_format({"num_format": "@"})

        columns = df.columns
        for col_idx, col_name in enumerate(columns):
            ws.write(0, col_idx, col_name, header_fmt)

        for row_idx, row in enumerate(df.iter_rows()):
            for col_idx, val in enumerate(row):
                ws.write_string(row_idx + 1, col_idx, str(val) if val is not None else "", text_fmt)

        ws.freeze_panes(1, 0)
        ws.autofilter(0, 0, len(df), len(columns) - 1)
        ws.autofit()

    return json.dumps({
        "status": "success",
        "processed_records": len(df),
        "files": {"excel": xlsx_path, "csv": csv_path}
    })
