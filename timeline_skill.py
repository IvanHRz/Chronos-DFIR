import polars as pl
import os
import json
import pandas as pd
from datetime import datetime

# Importamos nuestros motores
from mft_engine import process_mft_file
from evtx_engine import process_evtx_file

def generate_unified_timeline(source_path: str, artifact_type: str, output_dir: str) -> str:
    """
    Skill principal para Antigravity. Parsea MFT o EVTX y exporta a Excel/CSV.
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

    # 4. Exportar Excel (Estilo Zimmerman con XlsxWriter)
    with pd.ExcelWriter(xlsx_path, engine='xlsxwriter') as writer:
        df.to_pandas().to_excel(writer, sheet_name='Timeline', index=False)
        worksheet = writer.sheets['Timeline']
        
        # Formato profesional
        worksheet.freeze_panes(1, 0) # Inmovilizar cabecera
        worksheet.autofilter(0, 0, 0, len(df.columns) - 1) # Filtros
        worksheet.set_column('A:K', 18) # Ajustar ancho

    return json.dumps({
        "status": "success",
        "processed_records": len(df),
        "files": {"excel": xlsx_path, "csv": csv_path}
    })
