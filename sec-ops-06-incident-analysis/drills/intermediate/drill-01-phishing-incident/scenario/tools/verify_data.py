#!/usr/bin/env python3
"""
verify_data.py - Verify phishing incident scenario data is loaded in Elasticsearch.

Usage: docker exec drill01-loader python3 /tools/verify_data.py
"""

import os
import sys
import requests
from datetime import datetime

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "changeme")
auth = (ES_USER, ES_PASS)

EXPECTED_INDICES = {
    "email":    {"min_docs": 2, "description": "Email/SMTP logs"},
    "proxy":    {"min_docs": 2, "description": "Web proxy logs"},
    "sysmon":   {"min_docs": 5, "description": "Sysmon endpoint telemetry"},
    "winlogs":  {"min_docs": 2, "description": "Windows Security Event Logs"},
    "firewall": {"min_docs": 1, "description": "Firewall connection logs"},
}


def check_index(index_name, min_docs):
    """Check if an index exists and has minimum document count."""
    try:
        r = requests.get(
            f"{ES_HOST}/{index_name}/_count",
            auth=auth, timeout=10
        )
        if r.status_code == 404:
            return False, 0, "Index not found"
        if r.status_code != 200:
            return False, 0, f"HTTP {r.status_code}"
        count = r.json().get("count", 0)
        if count < min_docs:
            return False, count, f"Only {count} docs (expected >={min_docs})"
        return True, count, "OK"
    except Exception as e:
        return False, 0, str(e)


def main():
    print("=" * 60)
    print("Drill 01 - Phishing Incident: Data Verification")
    print("=" * 60)
    print(f"Elasticsearch: {ES_HOST}")
    print(f"Checked at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()

    all_ok = True
    for index, cfg in EXPECTED_INDICES.items():
        ok, count, msg = check_index(index, cfg["min_docs"])
        status = "✓" if ok else "✗"
        desc = cfg["description"]
        print(f"  [{status}] {index:<12} {count:>5} docs  — {desc}  ({msg})")
        if not ok:
            all_ok = False

    print()
    if all_ok:
        print("All indices verified. You can start the investigation.")
        print()
        print("Access Kibana at: http://localhost:5601")
        print("Credentials:      elastic / changeme")
        print()
        print("Scenario context:")
        print("  - Phishing sender domain: medtech-benefits.net")
        print("  - Phishing email time:    2024-11-18 ~11:08 UTC")
        print("  - SIEM alert time:        2024-11-18 11:15 UTC")
        print("  - Primary victim host:    WS-KBAKER (10.10.1.45)")
    else:
        print("Some indices are missing or have insufficient data.")
        print("Re-run: docker compose down -v && docker compose up -d")
        sys.exit(1)


if __name__ == "__main__":
    main()
