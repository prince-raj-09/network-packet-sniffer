# Network Packet Sniffer

A Python-based network packet sniffer built with [Scapy](https://scapy.net/) that captures live network traffic, parses protocol-level details (IP, TCP, UDP, ICMP), tracks real-time statistics, and exports captured data to JSON or CSV for later analysis.

Built as part of a cybersecurity internship project, with a focus on demonstrating practical understanding of packet structure and network-layer protocols rather than just wrapping an existing tool.

## Features

- **Live packet capture** using raw sockets via Scapy
- **Protocol filtering** — capture only TCP, UDP, or ICMP traffic
- **Port filtering** — capture traffic to/from a specific port
- **Packet count limiting** — stop automatically after N packets
- **Live traffic summary** — protocol breakdown, top source IPs, top destination ports, total bytes captured
- **Export to JSON or CSV** — save captures for later review or reporting
- **Dual interface** — works as a CLI tool (for scripting) or an interactive menu (for quick manual use)

## How it works

The tool uses Scapy's `sniff()` function with a [BPF filter](https://biot.com/capstats/bpf.html) for efficient, kernel-level packet filtering rather than filtering after capture in Python. Each captured packet is parsed into a normalized dictionary (`packet_parser.py`), fed into a running statistics tracker (`stats.py`), and optionally written to disk (`exporter.py`) once capture stops.

## Project structure

```
network-packet-sniffer/
├── sniffer.py          # Main entry point (CLI + interactive mode)
├── packet_parser.py    # Extracts structured info from raw packets
├── stats.py            # Tracks live traffic statistics
├── exporter.py         # Handles JSON/CSV export
├── requirements.txt
├── sample_capture.json # Example output for reference
└── README.md
```

## Requirements

- Python 3.8+
- Linux (developed and tested on Kali Linux) — raw socket capture requires root privileges and works most reliably on Linux
- Root/sudo access (required for raw packet capture)

## Installation

```bash
git clone https://github.com/prince-raj-09/network-packet-sniffer.git
cd network-packet-sniffer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Interactive mode

Run with no arguments and follow the prompts:

```bash
sudo venv/bin/python3 sniffer.py
```

### CLI mode

```bash
# Capture all traffic indefinitely
sudo venv/bin/python3 sniffer.py

# Capture only TCP traffic
sudo venv/bin/python3 sniffer.py --filter tcp

# Capture UDP traffic on port 53 (DNS), stop after 10 packets, export to JSON
sudo venv/bin/python3 sniffer.py --filter udp --port 53 --count 10 --export dns_capture.json

# Capture quietly (summary only, no live packet-by-packet output)
sudo venv/bin/python3 sniffer.py --quiet --count 50 --export capture.csv
```

### CLI options

| Flag | Description |
|---|---|
| `--filter` | Protocol to filter by: `tcp`, `udp`, `icmp`, or `all` (default: `all`) |
| `--port` | Filter by a specific port number |
| `--count` | Stop automatically after capturing N packets |
| `--export` | File path to save results to (`.json` or `.csv`) |
| `--quiet` | Suppress per-packet output, show only the final summary |

## Example output

```
[*] Starting capture...
[*] Filter applied: udp and port 53
[*] Capturing until 10 packets (Ctrl+C to stop early)

192.168.1.5:55106 -> 192.168.1.1:53 [UDP] len=75
192.168.1.1:53 -> 192.168.1.5:55106 [UDP] len=127
...

==================================================
TRAFFIC SUMMARY
==================================================
Total packets captured : 10
Total bytes captured   : 1003

Protocol breakdown:
  UDP      10

Top source IPs:
  192.168.1.5          5 packets
  192.168.1.1          5 packets

Top destination ports:
  53         10 packets
==================================================

[+] Exported 10 packets to dns_capture.json (JSON)
```

A sample export is included in this repo as `sample_capture.json` to show the structure of exported data without needing to run a live capture.

## Why these design choices

- **BPF filtering at capture time** (rather than filtering in Python after capture) keeps the tool efficient even on busy networks, since the kernel discards non-matching packets before they're even handed to Python.
- **Separation of concerns** across four files (parsing, stats, export, main) makes the codebase easy to extend — for example, adding a new export format only requires changes to `exporter.py`.
- **Dual CLI/interactive support** makes the tool usable both for quick manual testing and for scripted/automated use cases.

## Limitations & possible extensions

- Currently only parses IP-layer traffic (Ethernet-only frames, like ARP, are skipped) — could be extended to support more link-layer protocols.
- No GUI — a future version could add a simple web dashboard for live visualization.
- Tested on Linux; raw socket capture on Windows requires Npcap and additional configuration not covered here.

## Disclaimer

This tool is intended for educational use and authorized network monitoring only (e.g. your own machine, your own lab/VM network, or networks you have explicit permission to monitor). Capturing traffic on networks you do not own or have authorization to monitor may be illegal in your jurisdiction.

## Author

Built by [prince-raj-09](https://github.com/prince-raj-09) as part of a cybersecurity internship project.
