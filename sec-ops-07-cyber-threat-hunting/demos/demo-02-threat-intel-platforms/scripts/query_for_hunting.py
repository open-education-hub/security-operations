#!/usr/bin/env python3
"""
Query MISP to extract IOCs for threat hunting.
Formats output for Splunk (CSV lookup) and Elasticsearch (NDJSON bulk import).

Usage:
    export MISP_URL="https://localhost"
    export MISP_KEY="your-api-key-here"
    python3 query_for_hunting.py

Prerequisites:
    pip install pymisp
"""

import os
import json
from pymisp import PyMISP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MISP_URL = os.environ.get("MISP_URL", "https://localhost")
MISP_KEY = os.environ.get("MISP_KEY", "your-api-key")
VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "false").lower() == "true"


# ---------------------------------------------------------------------------
# IOC collection
# ---------------------------------------------------------------------------

def get_hunting_iocs(misp: PyMISP, lookback_days: int = 30) -> dict:
    """
    Extract IDS-enabled IOCs from MISP events published in the last
    `lookback_days` days. Skip TLP:RED events.

    Returns a dict keyed by indicator type.
    """

    hunting_iocs: dict = {
        "ip": [],
        "domain": [],
        "hash_md5": [],
        "hash_sha256": [],
        "url": [],
        "yara": [],
    }

    results = misp.search(
        publish_timestamp=f"{lookback_days}d",
        to_ids=True,
        pythonify=True,
    )

    for event in results:
        # Determine TLP level
        event_tlp = "clear"
        for tag in event.tags:
            if "tlp:" in tag.name.lower():
                event_tlp = tag.name.lower().split("tlp:")[1].strip()

        # Skip TLP:RED — do not automate distribution of red intelligence
        if event_tlp == "red":
            continue

        for attr in event.attributes:
            if not attr.to_ids:
                continue

            ioc_data = {
                "value": str(attr.value),
                "comment": str(attr.comment),
                "event_id": event.id,
                "event_info": event.info[:50],
                "timestamp": str(attr.timestamp),
            }

            atype = attr.type
            if atype in ("ip-dst", "ip-src"):
                hunting_iocs["ip"].append(ioc_data)
            elif atype in ("domain", "hostname"):
                hunting_iocs["domain"].append(ioc_data)
            elif atype == "md5":
                hunting_iocs["hash_md5"].append(ioc_data)
            elif atype == "sha256":
                hunting_iocs["hash_sha256"].append(ioc_data)
            elif atype == "url":
                hunting_iocs["url"].append(ioc_data)
            elif atype == "yara":
                hunting_iocs["yara"].append(ioc_data)

    return hunting_iocs


# ---------------------------------------------------------------------------
# Export formatters
# ---------------------------------------------------------------------------

def format_for_splunk(iocs: dict) -> None:
    """Write a Splunk-compatible CSV lookup table."""

    csv_path = "splunk_ioc_lookup.csv"
    with open(csv_path, "w") as f:
        f.write("indicator_type,indicator_value,source,comment\n")

        for ip in iocs["ip"]:
            f.write(
                f"ip,{ip['value']},MISP-{ip['event_id']},"
                f"{ip['comment'].replace(',', ';')}\n"
            )
        for domain in iocs["domain"]:
            f.write(
                f"domain,{domain['value']},MISP-{domain['event_id']},"
                f"{domain['comment'].replace(',', ';')}\n"
            )
        for sha256 in iocs["hash_sha256"]:
            f.write(
                f"sha256,{sha256['value']},MISP-{sha256['event_id']},"
                f"{sha256['comment'].replace(',', ';')}\n"
            )

    print(f"[✓] Written {csv_path}")
    print(
        "    Splunk usage:  | lookup splunk_ioc_lookup "
        "indicator_value as dest_ip OUTPUT source, comment"
    )


def format_for_elastic(iocs: dict) -> None:
    """Write an Elasticsearch bulk-import NDJSON file."""

    ndjson_path = "elastic_iocs.ndjson"
    with open(ndjson_path, "w") as f:
        for ip in iocs["ip"]:
            doc = {
                "indicator": {
                    "type": "ipv4-addr",
                    "ip": ip["value"],
                    "provider": "MISP",
                    "confidence": 75,
                    "description": ip["comment"],
                    "marking": {"tlp": "AMBER"},
                }
            }
            f.write(
                json.dumps({"index": {"_index": "threat-indicators"}}) + "\n"
            )
            f.write(json.dumps(doc) + "\n")

        for domain in iocs["domain"]:
            doc = {
                "indicator": {
                    "type": "domain-name",
                    "domain": domain["value"],
                    "provider": "MISP",
                    "confidence": 75,
                    "description": domain["comment"],
                    "marking": {"tlp": "AMBER"},
                }
            }
            f.write(
                json.dumps({"index": {"_index": "threat-indicators"}}) + "\n"
            )
            f.write(json.dumps(doc) + "\n")

    print(f"[✓] Written {ndjson_path}")
    print(
        "    Elastic import: curl -X POST 'localhost:9200/_bulk' "
        "-H 'Content-Type: application/x-ndjson' "
        "--data-binary @elastic_iocs.ndjson"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    misp = PyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_SSL)

    print(f"[*] Fetching IOCs from MISP (last 30 days) ...")
    iocs = get_hunting_iocs(misp, lookback_days=30)

    print("\n[✓] Retrieved:")
    print(f"    IPs:       {len(iocs['ip'])}")
    print(f"    Domains:   {len(iocs['domain'])}")
    print(f"    SHA256:    {len(iocs['hash_sha256'])}")
    print(f"    MD5:       {len(iocs['hash_md5'])}")
    print(f"    URLs:      {len(iocs['url'])}")
    print(f"    YARA:      {len(iocs['yara'])}")

    format_for_splunk(iocs)
    format_for_elastic(iocs)

    # Full JSON dump
    with open("all_iocs.json", "w") as fh:
        json.dump(iocs, fh, indent=2, default=str)
    print("[✓] Written all_iocs.json")
