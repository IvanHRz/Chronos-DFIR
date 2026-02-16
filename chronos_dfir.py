import argparse
import os
import json
import sys
from timeline_skill import generate_unified_timeline

def main():
    parser = argparse.ArgumentParser(description="Chronos-DFIR: Forensic Artifact Processor")
    parser.add_argument("--source", required=True, help="Path to the source file (MFT or EVTX)")
    parser.add_argument("--type", required=True, choices=["MFT", "EVTX"], help="Type of artifact to process")
    parser.add_argument("--output", default="/Users/ivanhuerta/Documents/chronos_antigravity/output", help="Output directory")

    args = parser.parse_args()

    print(f"[*] Chronos-DFIR initialized.")
    print(f"[*] Processing: {args.source}")
    print(f"[*] Artifact Type: {args.type}")
    print(f"[*] Output Directory: {args.output}")

    try:
        result_json = generate_unified_timeline(args.source, args.type, args.output)
        result = json.loads(result_json)

        if "error" in result:
            print(f"[!] Error: {result['error']}")
            sys.exit(1)
        
        if result.get("status") == "success":
            print(f"[+] Success!")
            print(f"    Processed Records: {result.get('processed_records')}")
            print(f"    CSV Output: {result.get('files', {}).get('csv')}")
            print(f"    Excel Output: {result.get('files', {}).get('excel')}")
        else:
            print(f"[!] Unknown status returned: {result}")

    except Exception as e:
        print(f"[!] Critical Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
