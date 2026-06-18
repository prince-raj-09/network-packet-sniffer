"""
sniffer.py

Main entry point for the Network Packet Sniffer.

Usage (CLI mode):
    sudo python3 sniffer.py --filter tcp --port 80 --count 100 --export capture.json

Usage (interactive mode):
    sudo python3 sniffer.py
    (then follow the on-screen prompts)

Note: Requires root/sudo privileges to capture raw packets.
"""

import argparse
import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

from packet_parser import parse_packet
from stats import TrafficStats
from exporter import export


def build_bpf_filter(protocol, port):
    """
    Build a BPF (Berkeley Packet Filter) string from user-friendly options.
    This is passed directly to Scapy's sniff() for efficient kernel-level
    filtering, rather than filtering in Python after the fact.
    """
    parts = []
    if protocol and protocol != "all":
        parts.append(protocol)
    if port:
        parts.append(f"port {port}")
    return " and ".join(parts) if parts else None


def run_capture(protocol, port, count, export_path, verbose):
    """Run the actual packet capture loop and return collected packet info."""
    stats = TrafficStats()
    captured = []

    bpf_filter = build_bpf_filter(protocol, port)

    print("[*] Starting capture...")
    if bpf_filter:
        print(f"[*] Filter applied: {bpf_filter}")
    print(f"[*] Capturing {'until ' + str(count) + ' packets' if count else 'indefinitely'} "
          f"(Ctrl+C to stop early)\n")

    def handle_packet(packet):
        info = parse_packet(packet)
        if info is None:
            return  # skip non-IP packets
        stats.update(info)
        captured.append(info)
        if verbose:
            print(info["summary"])

    try:
        sniff(
            filter=bpf_filter,
            prn=handle_packet,
            count=count if count else 0,  # 0 means infinite in Scapy
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print("[!] Permission denied. Try running with sudo.")
        sys.exit(1)

    print("\n" + stats.summary_report())

    if export_path:
        export(captured, export_path)

    return captured


def interactive_mode():
    """Prompt the user step by step for capture options."""
    print("=== Network Packet Sniffer (Interactive Mode) ===\n")

    protocol = input("Protocol to filter (tcp/udp/icmp/all) [all]: ").strip().lower() or "all"

    port_input = input("Port to filter (leave blank for any): ").strip()
    port = int(port_input) if port_input else None

    count_input = input("Number of packets to capture (leave blank for unlimited): ").strip()
    count = int(count_input) if count_input else None

    export_input = input("Export results to file (e.g. capture.json or capture.csv, leave blank to skip): ").strip()
    export_path = export_input if export_input else None

    verbose_input = input("Show each packet as it's captured? (y/n) [y]: ").strip().lower() or "y"
    verbose = verbose_input == "y"

    run_capture(protocol, port, count, export_path, verbose)


def main():
    parser = argparse.ArgumentParser(
        description="A Python network packet sniffer with filtering, live stats, and export support."
    )
    parser.add_argument("--filter", dest="protocol", choices=["tcp", "udp", "icmp", "all"],
                         help="Protocol to filter by")
    parser.add_argument("--port", type=int, help="Port number to filter by")
    parser.add_argument("--count", type=int, help="Number of packets to capture before stopping")
    parser.add_argument("--export", dest="export_path", help="File path to export results to (.json or .csv)")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-packet output, show only summary")

    args = parser.parse_args()

    # If no CLI args were given at all, fall back to interactive mode
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        run_capture(
            protocol=args.protocol or "all",
            port=args.port,
            count=args.count,
            export_path=args.export_path,
            verbose=not args.quiet,
        )


if __name__ == "__main__":
    main()
