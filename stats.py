"""
stats.py

Tracks running statistics about captured traffic: protocol breakdown,
top talkers (most active source IPs), and total packet/byte counts.

Kept as a class so the sniffer can hold one instance and update it
packet-by-packet as capture happens.
"""

from collections import defaultdict


class TrafficStats:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.src_ip_counts = defaultdict(int)
        self.dst_port_counts = defaultdict(int)

    def update(self, packet_info):
        """Update running stats with a newly parsed packet's info."""
        self.total_packets += 1
        self.total_bytes += packet_info["length"]
        self.protocol_counts[packet_info["protocol"]] += 1
        self.src_ip_counts[packet_info["src_ip"]] += 1

        if packet_info["dst_port"]:
            self.dst_port_counts[packet_info["dst_port"]] += 1

    def top_n(self, counter_dict, n=5):
        """Return the top N entries from a counter dict, sorted descending."""
        return sorted(counter_dict.items(), key=lambda x: x[1], reverse=True)[:n]

    def summary_report(self):
        """Build a human-readable summary of all stats collected so far."""
        lines = []
        lines.append("=" * 50)
        lines.append("TRAFFIC SUMMARY")
        lines.append("=" * 50)
        lines.append(f"Total packets captured : {self.total_packets}")
        lines.append(f"Total bytes captured   : {self.total_bytes}")
        lines.append("")
        lines.append("Protocol breakdown:")
        for proto, count in self.top_n(self.protocol_counts, n=10):
            lines.append(f"  {proto:<8} {count}")
        lines.append("")
        lines.append("Top source IPs:")
        for ip, count in self.top_n(self.src_ip_counts, n=5):
            lines.append(f"  {ip:<20} {count} packets")
        lines.append("")
        lines.append("Top destination ports:")
        for port, count in self.top_n(self.dst_port_counts, n=5):
            lines.append(f"  {port:<10} {count} packets")
        lines.append("=" * 50)
        return "\n".join(lines)
