"""
exporter.py

Handles writing captured packet data out to disk in either JSON or CSV
format, so captures can be reviewed later or shared (e.g. for a report).
"""

import json
import csv


def export_to_json(packet_list, filepath):
    """Write the list of parsed packet dicts to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(packet_list, f, indent=2)
    print(f"[+] Exported {len(packet_list)} packets to {filepath} (JSON)")


def export_to_csv(packet_list, filepath):
    """Write the list of parsed packet dicts to a CSV file."""
    if not packet_list:
        print("[!] No packets to export.")
        return

    fieldnames = packet_list[0].keys()
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_list)
    print(f"[+] Exported {len(packet_list)} packets to {filepath} (CSV)")


def export(packet_list, filepath):
    """Dispatch to the correct export function based on file extension."""
    if filepath.endswith(".json"):
        export_to_json(packet_list, filepath)
    elif filepath.endswith(".csv"):
        export_to_csv(packet_list, filepath)
    else:
        print("[!] Unsupported export format. Use a .json or .csv extension.")
