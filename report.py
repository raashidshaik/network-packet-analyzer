"""
report.py
---------
Generates JSON and CSV reports from packet analysis results.
Author: Raashid Shaik
"""

import json
import csv
import os
from datetime import datetime


def generate_report(stats: dict, anomalies: list, packets: list, output_dir: str):
    """Generate JSON summary report and CSV packet log."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    _write_json_report(stats, anomalies, output_dir, timestamp)
    _write_csv_report(packets, output_dir, timestamp)
    _write_anomaly_csv(anomalies, output_dir, timestamp)


def _write_json_report(stats: dict, anomalies: list, output_dir: str, timestamp: str):
    """Write full summary report as JSON."""
    report = {
        "report_generated": datetime.now().isoformat(),
        "summary":          stats,
        "anomalies":        anomalies,
        "anomaly_count":    len(anomalies),
        "severity_counts": {
            "HIGH":   len([a for a in anomalies if a["severity"] == "HIGH"]),
            "MEDIUM": len([a for a in anomalies if a["severity"] == "MEDIUM"]),
            "LOW":    len([a for a in anomalies if a["severity"] == "LOW"]),
        }
    }

    path = os.path.join(output_dir, f"report_{timestamp}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  ✓ JSON report   : {path}")


def _write_csv_report(packets: list, output_dir: str, timestamp: str):
    """Write packet log as CSV."""
    if not packets:
        return

    path = os.path.join(output_dir, f"packets_{timestamp}.csv")
    fieldnames = ["timestamp", "protocol", "src_ip", "dst_ip",
                  "src_port", "dst_port", "length", "flags", "dns_query"]

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(packets)
    print(f"  ✓ Packet log CSV: {path}")


def _write_anomaly_csv(anomalies: list, output_dir: str, timestamp: str):
    """Write anomaly report as CSV."""
    if not anomalies:
        print("  ✓ No anomalies detected — skipping anomaly CSV.")
        return

    path = os.path.join(output_dir, f"anomalies_{timestamp}.csv")
    fieldnames = ["type", "severity", "src_ip", "detail", "detected_at"]

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(anomalies)
    print(f"  ✓ Anomaly CSV   : {path}")
