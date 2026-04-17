#!/usr/bin/env python3
"""
Alert Processor — Demo 04
Simulates receiving SIEM alerts and enriching them with TI.
"""
import json
import random
import sys
import time
import os
sys.path.insert(0, "/app/scripts")
from enrich import enrich_ioc

SIMULATED_ALERTS = [
    {"id": "ALERT-001", "rule": "Suspicious Outbound Connection", "src_ip": "192.168.1.42",
     "dst_ip": "185.220.101.5", "dst_port": 443, "process": "powershell.exe"},
    {"id": "ALERT-002", "rule": "DNS Query to Suspicious Domain", "src_ip": "192.168.1.42",
     "domain": "update-services.ru", "process": "svchost.exe"},
    {"id": "ALERT-003", "rule": "Malware Hash Detected by EDR", "src_ip": "192.168.1.50",
     "file_hash": "b2d58de3f5a3e9f7c1a8d4b9e6c2f0a1234567890abcdef",
     "file_path": "C:\\Users\\mjones\\AppData\\Roaming\\Microsoft\\svchost32.exe"},
    {"id": "ALERT-004", "rule": "Port Scan Detected", "src_ip": "203.0.113.50",
     "dst_subnet": "192.168.1.0/24", "scan_type": "SYN"},
    {"id": "ALERT-005", "rule": "Benign Connection (False Positive Test)", "src_ip": "192.168.1.10",
     "dst_ip": "8.8.8.8", "dst_port": 53, "process": "svchost.exe"},
]


def process_alert(alert):
    print(f"\n{'='*70}")
    print(f"[*] Processing Alert: {alert['id']} — {alert['rule']}")
    print(f"{'='*70}")
    print(f"Raw Alert: {json.dumps(alert, indent=2)}")

    enrichments = []

    # Extract and enrich relevant IOCs from the alert
    if "dst_ip" in alert:
        print(f"\n[>] Enriching destination IP: {alert['dst_ip']}")
        enrichments.append(enrich_ioc(alert["dst_ip"], "ip"))

    if "domain" in alert:
        print(f"\n[>] Enriching domain: {alert['domain']}")
        enrichments.append(enrich_ioc(alert["domain"], "domain"))

    if "file_hash" in alert:
        print(f"\n[>] Enriching file hash: {alert['file_hash']}")
        enrichments.append(enrich_ioc(alert["file_hash"], "hash"))

    if "src_ip" in alert and alert["id"] == "ALERT-004":
        print(f"\n[>] Enriching scanning source IP: {alert['src_ip']}")
        enrichments.append(enrich_ioc(alert["src_ip"], "ip"))

    # Determine overall alert disposition
    max_level = "INFO"
    level_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for e in enrichments:
        if level_order.index(e.get("threat_level", "INFO")) > level_order.index(max_level):
            max_level = e["threat_level"]

    print(f"\n{'─'*70}")
    print(f"[DISPOSITION] Alert {alert['id']}: {max_level}")
    if max_level in ("HIGH", "CRITICAL"):
        print(f"[ACTION] *** Escalate to Incident Response Team ***")
    elif max_level == "MEDIUM":
        print(f"[ACTION] Assign to Tier 2 analyst for investigation")
    else:
        print(f"[ACTION] Log and move to false-positive review queue")
    print(f"{'─'*70}\n")

    return {"alert": alert, "enrichments": enrichments, "final_level": max_level}


if __name__ == "__main__":
    print("[*] Alert Processor started — Demo 04")
    print("[*] Processing simulated SIEM alerts with TI enrichment...\n")

    results = []
    for alert in SIMULATED_ALERTS:
        result = process_alert(alert)
        results.append(result)
        time.sleep(3)

    # Final summary
    print(f"\n{'='*70}")
    print(f"PROCESSING COMPLETE — {len(results)} alerts processed")
    print(f"{'='*70}")
    level_counts = {}
    for r in results:
        level = r["final_level"]
        level_counts[level] = level_counts.get(level, 0) + 1

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = level_counts.get(level, 0)
        if count:
            print(f"  {level}: {count} alert(s)")

    print("\n[*] Alert processor complete. Sleeping...")
    while True:
        time.sleep(60)
