"""
packet_parser.py

Responsible for taking a raw Scapy packet and turning it into a clean,
structured dictionary that the rest of the application (stats, exporter,
display) can use without needing to know anything about Scapy internals.
"""

from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Ether


def parse_packet(packet):
    """
    Extract relevant fields from a captured packet.

    Returns a dictionary with normalized fields, or None if the packet
    doesn't contain an IP layer (we only care about IP traffic for this tool).
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": _get_protocol_name(packet),
        "length": len(packet),
        "src_port": None,
        "dst_port": None,
        "ttl": ip_layer.ttl,
        "flags": None,
        "summary": None,
    }

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        info["src_port"] = tcp_layer.sport
        info["dst_port"] = tcp_layer.dport
        info["flags"] = str(tcp_layer.flags)

    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        info["src_port"] = udp_layer.sport
        info["dst_port"] = udp_layer.dport

    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        info["flags"] = f"type={icmp_layer.type}, code={icmp_layer.code}"

    info["summary"] = _build_summary(info)
    return info


def _get_protocol_name(packet):
    """Identify the transport-layer protocol in a human-readable way."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def _build_summary(info):
    """Build a one-line human-readable summary of the packet."""
    base = f"{info['src_ip']}"
    if info["src_port"]:
        base += f":{info['src_port']}"
    base += f" -> {info['dst_ip']}"
    if info["dst_port"]:
        base += f":{info['dst_port']}"
    base += f" [{info['protocol']}] len={info['length']}"
    return base
