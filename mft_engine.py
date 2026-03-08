import polars as pl
import struct
from datetime import datetime, timedelta

def win64_to_datetime(win64):
    """Convierte timestamps de Windows FILETIME (100-ns intervals desde 1601-01-01) a datetime."""
    if not win64 or win64 == 0 or win64 > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=win64 // 10)
    except (OverflowError, OSError):
        return None

def _read_si_timestamps(raw_record, attr_offset):
    """
    Parse $STANDARD_INFORMATION attribute (type 0x10) timestamps.
    SI layout at attribute content offset:
      +0x00  Created (FILETIME, 8 bytes)
      +0x08  Modified (FILETIME, 8 bytes)
      +0x10  MFT Modified (FILETIME, 8 bytes)
      +0x18  Accessed (FILETIME, 8 bytes)
    """
    timestamps = {}
    try:
        pos = attr_offset
        while pos + 16 <= len(raw_record):
            attr_type = struct.unpack("<I", raw_record[pos:pos+4])[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack("<I", raw_record[pos+4:pos+8])[0]
            if attr_len < 16 or attr_len > 2048:
                break

            if attr_type == 0x10:  # $STANDARD_INFORMATION
                # Non-resident flag at offset +8 (1 byte)
                non_resident = raw_record[pos + 8] if pos + 9 <= len(raw_record) else 0
                if non_resident == 0:
                    # Content offset (2 bytes at pos+20), Content size (4 bytes at pos+16)
                    content_offset = struct.unpack("<H", raw_record[pos+20:pos+22])[0]
                    content_start = pos + content_offset
                    if content_start + 32 <= len(raw_record):
                        created  = struct.unpack("<Q", raw_record[content_start:content_start+8])[0]
                        modified = struct.unpack("<Q", raw_record[content_start+8:content_start+16])[0]
                        mft_mod  = struct.unpack("<Q", raw_record[content_start+16:content_start+24])[0]
                        accessed = struct.unpack("<Q", raw_record[content_start+24:content_start+32])[0]
                        timestamps["Created"]  = win64_to_datetime(created)
                        timestamps["Modified"] = win64_to_datetime(modified)
                        timestamps["MFT_Modified"] = win64_to_datetime(mft_mod)
                        timestamps["Accessed"] = win64_to_datetime(accessed)
                return timestamps

            pos += attr_len
    except (struct.error, IndexError):
        pass
    return timestamps

def parse_mft_record(raw_record):
    """
    Parse MFT record: extract record ID, sequence, flags, and $STANDARD_INFORMATION timestamps.
    Returns None for invalid records.
    """
    if len(raw_record) < 48 or raw_record[:4] != b"FILE":
        return None

    # Record ID from offset 44 (MFT Reference Number)
    record_id = struct.unpack("<I", raw_record[44:48])[0]

    # Sequence number at offset 16
    sequence = struct.unpack("<H", raw_record[16:18])[0]

    # Flags at offset 22: 0x01=In Use, 0x02=Directory
    flags = struct.unpack("<H", raw_record[22:24])[0]
    in_use = bool(flags & 0x01)
    is_dir = bool(flags & 0x02)

    # First attribute offset at offset 20
    attr_offset = struct.unpack("<H", raw_record[20:22])[0]

    # Parse $STANDARD_INFORMATION timestamps
    timestamps = _read_si_timestamps(raw_record, attr_offset)

    # Use Modified as primary timestamp; fall back to Created, then null
    primary_ts = timestamps.get("Modified") or timestamps.get("Created")

    result = {
        "Line": record_id,
        "Date": primary_ts.strftime("%Y-%m-%d") if primary_ts else None,
        "Time": primary_ts.strftime("%H:%M:%S") if primary_ts else None,
        "Timestamp": primary_ts.strftime("%Y-%m-%d %H:%M:%S") if primary_ts else None,
        "Created": timestamps.get("Created", "").strftime("%Y-%m-%d %H:%M:%S") if timestamps.get("Created") else None,
        "Modified": timestamps.get("Modified", "").strftime("%Y-%m-%d %H:%M:%S") if timestamps.get("Modified") else None,
        "Accessed": timestamps.get("Accessed", "").strftime("%Y-%m-%d %H:%M:%S") if timestamps.get("Accessed") else None,
        "MFT_Modified": timestamps.get("MFT_Modified", "").strftime("%Y-%m-%d %H:%M:%S") if timestamps.get("MFT_Modified") else None,
        "Sequence": sequence,
        "InUse": in_use,
        "IsDirectory": is_dir,
        "Level": "Directory" if is_dir else "File",
        "Source": "MFT",
        "Description": f"MFT Record {record_id} (Seq: {sequence})" + (" [Deleted]" if not in_use else ""),
    }
    return result

def process_mft_file(file_path):
    """Lee la MFT en chunks de 1024 bytes (tamaño estándar de registro)."""
    records = []
    record_size = 1024

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(record_size)
            if not chunk or len(chunk) < record_size:
                break
            parsed = parse_mft_record(chunk)
            if parsed:
                records.append(parsed)

    return pl.DataFrame(records)
