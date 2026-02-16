import polars as pl
from evtx import PyEvtxParser
import json

def process_evtx_file(file_path):
    """
    Motor optimizado para parsear Event Logs (.evtx) 
    y convertirlos a un DataFrame de Polars.
    """
    parser = PyEvtxParser(file_path)
    records = []

    for record in parser.records_json():
        # Cada record es un JSON con la estructura de Windows Event Log
        data = json.loads(record['data'])
        event_id = data['Event']['System'].get('EventID', '0')
        computer = data['Event']['System'].get('Computer', 'Unknown')
        timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
        
        # Merged Timestamp
        timestamp_str = timestamp.replace('T', ' ').replace('Z', '')
        # Only keep up to microseconds (first 26 chars usually: 2026-01-01 12:00:00.000000)
        timestamp_str = timestamp_str[:26]

        # Helper to handle potential dicts (e.g., fields with attributes)
        def get_value(v):
            if isinstance(v, dict):
                return v.get('#text', str(v))
            return v

        records.append({
            "Line": record['event_record_id'],
            "Timestamp": timestamp_str,
            "Level": get_value(data['Event']['System'].get('Level', 'Info')),
            "Provider": data['Event']['System'].get('Provider', {}).get('#attributes', {}).get('Name', 'Unknown'),
            "EventID": get_value(event_id),
            "Task": get_value(data['Event']['System'].get('Task', '0')),
            "User": "System", 
            "Computer": computer,
            "Description": f"Event {get_value(event_id)} from {computer}",
            "Source": "EVTX"
        })
            
    return pl.DataFrame(records)
