"""
analyzer.py
-----------
Network Packet Analyzer — Live Capture & Anomaly Detection
Author: Raashid Shaik

Features:
  - Live packet capture using Scapy
  - Protocol breakdown (TCP, UDP, ICMP, ARP, DNS)
  - Anomaly detection (port scans, high-frequency IPs, suspicious ports)
  - Traffic statistics and summary reporting
  - Export findings to JSON and CSV reports
  - Demo mode (no root required) using simulated packets
"""

import json
import csv
import os
import time
import random
from datetime import datetime
from collections import defaultdict, Counter
from report import generate_report

# ── Try importing Scapy (requires root for live capture) ─────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠  Scapy not installed. Running in demo mode with simulated packets.")


# ── Configuration ─────────────────────────────────────────────────────────────
SUSPICIOUS_PORTS   = {22, 23, 3389, 4444, 5900, 6666, 31337}
PORT_SCAN_THRESHOLD = 15    # unique ports from one IP in capture window
HIGH_FREQ_THRESHOLD = 50    # packets from one IP = high frequency flag
OUTPUT_DIR          = "reports"


# =============================================================================
# PACKET STORE
# =============================================================================

class PacketStore:
    """Stores captured packets and computes traffic statistics."""

    def __init__(self):
        self.packets        = []
        self.ip_counter     = Counter()
        self.proto_counter  = Counter()
        self.port_tracker   = defaultdict(set)   # src_ip → set of dst_ports
        self.dns_queries    = []
        self.start_time     = datetime.now()

    def add(self, pkt_info: dict):
        self.packets.append(pkt_info)
        src = pkt_info.get("src_ip", "unknown")
        self.ip_counter[src] += 1
        self.proto_counter[pkt_info.get("protocol", "OTHER")] += 1

        dst_port = pkt_info.get("dst_port")
        if dst_port:
            self.port_tracker[src].add(dst_port)

        if pkt_info.get("dns_query"):
            self.dns_queries.append(pkt_info["dns_query"])

    def stats(self) -> dict:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return {
            "total_packets":  len(self.packets),
            "duration_sec":   round(elapsed, 2),
            "packets_per_sec": round(len(self.packets) / elapsed, 2) if elapsed > 0 else 0,
            "protocol_breakdown": dict(self.proto_counter),
            "top_talkers":    self.ip_counter.most_common(5),
            "unique_ips":     len(self.ip_counter),
            "dns_queries":    len(self.dns_queries),
        }


# =============================================================================
# PACKET PROCESSOR
# =============================================================================

def process_packet(pkt, store: PacketStore):
    """Extract fields from a Scapy packet and add to store."""
    info = {
        "timestamp": datetime.now().isoformat(),
        "protocol":  "OTHER",
        "src_ip":    None,
        "dst_ip":    None,
        "src_port":  None,
        "dst_port":  None,
        "length":    len(pkt),
        "dns_query": None,
        "flags":     None,
    }

    if pkt.haslayer(IP):
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst

    if pkt.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["flags"]    = str(pkt[TCP].flags)

    elif pkt.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport

    elif pkt.haslayer(ICMP):
        info["protocol"] = "ICMP"

    elif pkt.haslayer(ARP):
        info["protocol"] = "ARP"
        info["src_ip"]   = pkt[ARP].psrc
        info["dst_ip"]   = pkt[ARP].pdst

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        info["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        info["protocol"]  = "DNS"

    store.add(info)


# =============================================================================
# ANOMALY DETECTION
# =============================================================================

def detect_anomalies(store: PacketStore) -> list:
    """
    Analyze captured traffic and flag anomalies:
    1. Port scan — one IP hitting many distinct ports
    2. High-frequency source — flood/DoS indicator
    3. Suspicious port access — known malicious ports
    """
    anomalies = []

    # 1. Port scan detection
    for src_ip, ports in store.port_tracker.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            anomalies.append({
                "type":        "PORT_SCAN",
                "severity":    "HIGH",
                "src_ip":      src_ip,
                "detail":      f"Accessed {len(ports)} unique ports: {sorted(list(ports))[:10]}...",
                "detected_at": datetime.now().isoformat(),
            })

    # 2. High-frequency source
    for src_ip, count in store.ip_counter.items():
        if count >= HIGH_FREQ_THRESHOLD:
            anomalies.append({
                "type":        "HIGH_FREQUENCY",
                "severity":    "MEDIUM",
                "src_ip":      src_ip,
                "detail":      f"Sent {count} packets — possible flood or DoS activity.",
                "detected_at": datetime.now().isoformat(),
            })

    # 3. Suspicious port access
    suspicious_hits = defaultdict(list)
    for pkt in store.packets:
        dst_port = pkt.get("dst_port")
        if dst_port and dst_port in SUSPICIOUS_PORTS:
            suspicious_hits[pkt.get("src_ip", "unknown")].append(dst_port)

    for src_ip, ports in suspicious_hits.items():
        anomalies.append({
            "type":        "SUSPICIOUS_PORT",
            "severity":    "HIGH",
            "src_ip":      src_ip,
            "detail":      f"Accessed suspicious port(s): {list(set(ports))}",
            "detected_at": datetime.now().isoformat(),
        })

    return anomalies


# =============================================================================
# DEMO MODE — Simulated Packets
# =============================================================================

def generate_demo_packets(store: PacketStore, count: int = 200):
    """
    Simulate realistic network traffic for demo/testing purposes.
    Includes normal traffic + injected anomalies.
    """
    print(f"\n📦 Generating {count} simulated packets in demo mode...\n")

    protocols   = ["TCP", "UDP", "ICMP", "DNS", "ARP"]
    normal_ips  = [f"192.168.1.{i}" for i in range(2, 20)]
    common_ports = [80, 443, 53, 8080, 8443, 3306, 5432]

    for i in range(count):
        proto  = random.choices(protocols, weights=[50, 25, 10, 10, 5])[0]
        src_ip = random.choice(normal_ips)

        pkt = {
            "timestamp": datetime.now().isoformat(),
            "protocol":  proto,
            "src_ip":    src_ip,
            "dst_ip":    f"10.0.0.{random.randint(1, 50)}",
            "src_port":  random.randint(1024, 65535),
            "dst_port":  random.choice(common_ports),
            "length":    random.randint(64, 1500),
            "dns_query": f"example{random.randint(1,5)}.com" if proto == "DNS" else None,
            "flags":     random.choice(["S", "SA", "A", "FA", "PA"]) if proto == "TCP" else None,
        }
        store.add(pkt)

    # Inject port scan from attacker IP
    attacker_ip = "172.16.0.99"
    print(f"  ⚠  Injecting port scan from {attacker_ip}...")
    for port in range(20, 45):
        store.add({
            "timestamp": datetime.now().isoformat(),
            "protocol": "TCP", "src_ip": attacker_ip,
            "dst_ip": "192.168.1.1", "src_port": random.randint(1024, 65535),
            "dst_port": port, "length": 60, "dns_query": None, "flags": "S",
        })

    # Inject high-frequency flood
    flood_ip = "10.10.10.10"
    print(f"  ⚠  Injecting high-frequency flood from {flood_ip}...")
    for _ in range(60):
        store.add({
            "timestamp": datetime.now().isoformat(),
            "protocol": "UDP", "src_ip": flood_ip,
            "dst_ip": "192.168.1.1", "src_port": 5000,
            "dst_port": 80, "length": 1400, "dns_query": None, "flags": None,
        })

    # Inject suspicious port access
    sus_ip = "192.168.1.77"
    print(f"  ⚠  Injecting suspicious port access from {sus_ip}...")
    for port in [4444, 31337, 3389]:
        store.add({
            "timestamp": datetime.now().isoformat(),
            "protocol": "TCP", "src_ip": sus_ip,
            "dst_ip": "192.168.1.1", "src_port": random.randint(1024, 65535),
            "dst_port": port, "length": 80, "dns_query": None, "flags": "S",
        })

    print(f"  ✓ Demo packets generated: {len(store.packets)} total\n")


# =============================================================================
# MAIN
# =============================================================================

def main(live: bool = False, packet_count: int = 200, interface: str = None):
    print("=" * 60)
    print("  NETWORK PACKET ANALYZER")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    store = PacketStore()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if live and SCAPY_AVAILABLE:
        print(f"\n🔴 Live capture mode — capturing {packet_count} packets...")
        print("   (Requires root/administrator privileges)\n")
        try:
            sniff(
                iface=interface,
                count=packet_count,
                prn=lambda pkt: process_packet(pkt, store),
                store=False
            )
        except PermissionError:
            print("❌ Permission denied. Run with sudo for live capture.")
            print("   Falling back to demo mode...\n")
            generate_demo_packets(store, packet_count)
    else:
        generate_demo_packets(store, packet_count)

    # Analyze
    print("🔍 Running anomaly detection...")
    anomalies = detect_anomalies(store)
    stats     = store.stats()

    # Report
    generate_report(stats, anomalies, store.packets, OUTPUT_DIR)

    # Console summary
    print("\n" + "=" * 60)
    print("  ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"  Total Packets    : {stats['total_packets']:,}")
    print(f"  Unique IPs       : {stats['unique_ips']}")
    print(f"  Duration         : {stats['duration_sec']}s")
    print(f"  Packets/sec      : {stats['packets_per_sec']}")
    print(f"\n  Protocol Breakdown:")
    for proto, count in stats["protocol_breakdown"].items():
        print(f"    {proto:<8}: {count:>5} packets")
    print(f"\n  🚨 Anomalies Detected: {len(anomalies)}")
    for a in anomalies:
        print(f"    [{a['severity']}] {a['type']} — {a['src_ip']}")
    print(f"\n  📄 Reports saved to: {OUTPUT_DIR}/")
    print("=" * 60)


if __name__ == "__main__":
    main(live=False, packet_count=200)
