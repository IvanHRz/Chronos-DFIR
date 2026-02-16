import polars as pl
import struct
from datetime import datetime, timedelta

def win64_to_datetime(win64):
    """Convierte timestamps de Windows (FILETIME) a Legible."""
    if not win64 or win64 > 0x7FFFFFFFFFFFFFFF: return None
    return datetime(1601, 1, 1) + timedelta(microseconds=win64 // 10)

def parse_mft_record(raw_record):
    """
    Lógica simplificada de parsing de registros MFT (Zimmerman Style).
    Busca la firma 'FILE' y extrae metadatos básicos.
    """
    if raw_record[:4] != b"FILE":
        return None
    
    # Aquí es donde ocurre la magia de los bytes
    # Extraemos el ID del registro, secuencia, etc.
    record_id = struct.unpack("<I", raw_record[44:48])[0]
    
    # Nota: Un parser completo leería atributos $STANDARD_INFORMATION
    # Para este MVP, generamos un registro estructurado
    return {
        "Line": record_id,
        "Date": datetime.now().strftime("%Y-%m-%d"),
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Level": "File",
        "Source": "MFT",
        "Description": f"Registro MFT procesado ID: {record_id}",
        "Computer": "M4_Forensics_Box"
    }

def process_mft_file(file_path):
    """Lee la MFT en chunks para no saturar la RAM del M4."""
    records = []
    record_size = 1024 # Tamaño estándar de registro MFT
    
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(record_size)
            if not chunk: break
            parsed = parse_mft_record(chunk)
            if parsed: records.append(parsed)
            
    return pl.DataFrame(records)
