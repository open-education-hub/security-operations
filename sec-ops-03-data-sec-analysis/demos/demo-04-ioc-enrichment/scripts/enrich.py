#!/usr/bin/env python3
"""
IOC Enrichment Script — Demo 04
Queries MISP and VirusTotal to enrich security indicators.

Usage:
    python3 enrich.py --type ip --value 185.220.101.5
    python3 enrich.py --type domain --value malicious.example.com
    python3 enrich.py --type hash --value SHA256_HASH
    python3 enrich.py --batch sample_iocs.txt
    python3 enrich.py --type ip --value 8.8.8.8 --vt-key YOUR_KEY
"""
import argparse
import json
import os
import sys
import time
import requests

# ─── Configuration ──────────────────────────────────────────────────────────
MISP_URL = os.getenv("MISP_URL", "http://localhost")
MISP_KEY = os.getenv("MISP_KEY", "YOUR_MISP_API_KEY")
VT_KEY   = os.getenv("VT_API_KEY", "")

# Mock VT data for when no API key is provided (for demonstration)
MOCK_VT_DATA = {
    "185.220.101.5":  {"malicious": 32, "suspicious": 5,  "undetected": 53, "country": "DE", "as_owner": "Hetzner Online GmbH"},
    "203.0.113.10":   {"malicious": 0,  "suspicious": 2,  "undetected": 88, "country": "US", "as_owner": "IANA Reserved"},
    "update-services.ru": {"malicious": 28, "suspicious": 8, "undetected": 54, "country": "RU", "registrar": "reg.ru"},
    "44d88612fea8a8f36de82e1278abb02f3524ec74": {"malicious": 70, "suspicious": 0, "undetected": 20, "name": "EICAR-Test-File"},
    "b2d58de3f5a3e9f7c1a8d4b9e6c2f0a1234567890abcdef": {"malicious": 58, "suspicious": 4, "undetected": 28, "name": "Trojan:Win32/Emotet"},
}

# Mock MISP data for demo
MOCK_MISP_DATA = {
    "185.220.101.5": {
        "found": True, "events": 2,
        "threat_actor": "Emotet Distribution Network",
        "tags": ["tlp:green", "misp-galaxy:threat-actor=\"Emotet\"", "mitre-attack:command-and-control:T1071.001"],
        "first_seen": "2024-01-15", "last_seen": "2024-03-10",
        "event_ids": ["1001", "1002"],
    },
    "update-services.ru": {
        "found": True, "events": 1,
        "threat_actor": "Emotet",
        "tags": ["tlp:green", "type:c2", "mitre-attack:command-and-control"],
        "first_seen": "2024-03-08", "last_seen": "2024-03-15",
        "event_ids": ["1001"],
    },
    "44d88612fea8a8f36de82e1278abb02f3524ec74": {
        "found": True, "events": 1,
        "threat_actor": None,
        "tags": ["tlp:white", "type:test-file"],
        "first_seen": "1993-01-01", "last_seen": "2024-01-01",
        "event_ids": ["999"],
    },
    "b2d58de3f5a3e9f7c1a8d4b9e6c2f0a1234567890abcdef": {
        "found": True, "events": 3,
        "threat_actor": "Emotet",
        "malware_family": "Emotet/Heodo",
        "tags": ["tlp:green", "misp-galaxy:malpedia=\"Emotet\"", "mitre-attack:execution:T1059.001"],
        "first_seen": "2024-02-20", "last_seen": "2024-03-14",
        "event_ids": ["1002", "1003", "1004"],
    },
}


# ─── MISP Query ─────────────────────────────────────────────────────────────
def query_misp(value, ioc_type):
    """Query MISP for an IOC. Falls back to mock data if MISP is unavailable."""
    try:
        from pymisp import PyMISP
        misp = PyMISP(MISP_URL, MISP_KEY, False)
        results = misp.search(value=value, type_attribute=misp_type_map(ioc_type))

        if not results:
            return {"found": False, "events": 0}

        tags = []
        threat_actors = []
        first_seen = None
        last_seen  = None
        event_ids  = []

        for event in results:
            event_ids.append(event.uuid)
            for attr in event.attributes:
                for tag in attr.tags:
                    tags.append(tag.name)
            if hasattr(event, 'date') and event.date:
                date_str = str(event.date)
                if first_seen is None or date_str < first_seen:
                    first_seen = date_str
                if last_seen is None or date_str > last_seen:
                    last_seen = date_str

        return {
            "found": True,
            "events": len(results),
            "tags": list(set(tags)),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_ids": event_ids,
        }

    except Exception as e:
        print(f"[~] MISP unavailable ({e}), using mock data", file=sys.stderr)
        return MOCK_MISP_DATA.get(value, {"found": False, "events": 0})


def misp_type_map(ioc_type):
    """Map friendly IOC type names to MISP attribute types."""
    return {
        "ip":     "ip-dst",
        "domain": "domain",
        "hash":   "sha256",
        "url":    "url",
        "email":  "email-src",
    }.get(ioc_type, "text")


# ─── VirusTotal Query ────────────────────────────────────────────────────────
def query_virustotal(value, ioc_type, api_key=None):
    """Query VirusTotal API for an IOC."""
    key = api_key or VT_KEY
    if not key:
        # Return mock data
        return MOCK_VT_DATA.get(value, {"malicious": 0, "suspicious": 0, "undetected": 90})

    BASE = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": key}

    endpoint_map = {
        "ip":     f"{BASE}/ip_addresses/{value}",
        "domain": f"{BASE}/domains/{value}",
        "hash":   f"{BASE}/files/{value}",
        "url":    f"{BASE}/urls/{requests.utils.quote(value, safe='')}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            attrs = resp.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }
            # Add type-specific fields
            if ioc_type == "ip":
                result["country"]  = attrs.get("country", "Unknown")
                result["as_owner"] = attrs.get("as_owner", "Unknown")
            elif ioc_type == "domain":
                result["registrar"] = attrs.get("registrar", "Unknown")
                result["categories"] = attrs.get("categories", {})
            elif ioc_type == "hash":
                result["name"]    = attrs.get("meaningful_name", "Unknown")
                result["type_tag"] = attrs.get("type_tag", "")
            return result
        elif resp.status_code == 404:
            return {"malicious": 0, "found_in_vt": False}
        elif resp.status_code == 429:
            return {"error": "Rate limited — upgrade to VT Premium or wait"}
        else:
            return {"error": f"VT error {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─── Threat Score Calculation ────────────────────────────────────────────────
def calculate_threat_score(misp_result, vt_result):
    """Calculate a composite threat score from MISP + VT data."""
    score = 0.0

    # MISP contribution (max 50 points)
    if misp_result.get("found"):
        score += min(misp_result["events"] * 10, 30)
        # High-confidence tags add points
        tags = misp_result.get("tags", [])
        if any("tlp:red" in t.lower() for t in tags):
            score += 20
        elif any("tlp:amber" in t.lower() for t in tags):
            score += 10

    # VirusTotal contribution (max 50 points)
    vt_malicious  = vt_result.get("malicious", 0)
    vt_suspicious = vt_result.get("suspicious", 0)
    vt_total      = vt_malicious + vt_suspicious + vt_result.get("undetected", 90)
    if vt_total > 0:
        detection_rate = (vt_malicious + 0.5 * vt_suspicious) / vt_total
        score += detection_rate * 50

    if score >= 70:
        level = "CRITICAL"
        action = "Block immediately + open Priority 1 incident"
    elif score >= 50:
        level = "HIGH"
        action = "Block at firewall, open incident ticket, notify IR team"
    elif score >= 30:
        level = "MEDIUM"
        action = "Monitor closely, investigate within 2 hours"
    elif score >= 10:
        level = "LOW"
        action = "Log and monitor, review in next analyst cycle"
    else:
        level = "INFO"
        action = "No immediate action required"

    return {
        "score":   round(score, 1),
        "level":   level,
        "action":  action,
    }


# ─── Main Enrichment Function ────────────────────────────────────────────────
def enrich_ioc(value, ioc_type, vt_key=None):
    """Enrich a single IOC against MISP and VirusTotal."""
    print(f"\n[*] Enriching {ioc_type.upper()}: {value}")
    print("=" * 60)

    misp_result = query_misp(value, ioc_type)
    vt_result   = query_virustotal(value, ioc_type, vt_key)
    threat      = calculate_threat_score(misp_result, vt_result)

    result = {
        "ioc":            value,
        "type":           ioc_type,
        "misp":           misp_result,
        "virustotal":     vt_result,
        "threat_score":   threat["score"],
        "threat_level":   threat["level"],
        "recommended_action": threat["action"],
    }

    print(json.dumps(result, indent=2))
    return result


def process_batch(filepath, vt_key=None):
    """Process a file containing IOCs, one per line in format: type,value"""
    results = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 1)
            if len(parts) != 2:
                print(f"[!] Skipping invalid line: {line}", file=sys.stderr)
                continue
            ioc_type, value = parts[0].strip(), parts[1].strip()
            result = enrich_ioc(value, ioc_type, vt_key)
            results.append(result)
            time.sleep(0.5)  # Rate limiting

    print(f"\n[+] Processed {len(results)} IOCs")
    # Summary
    by_level = {}
    for r in results:
        level = r["threat_level"]
        by_level[level] = by_level.get(level, 0) + 1
    print("[*] Summary by threat level:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_level.get(level, 0)
        if count:
            print(f"    {level}: {count}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool — Demo 04")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--value",  help="IOC value to look up")
    group.add_argument("--batch",  help="File with IOCs (type,value per line)")
    parser.add_argument("--type",  choices=["ip", "domain", "hash", "url"],
                        help="IOC type (required with --value)")
    parser.add_argument("--vt-key", help="VirusTotal API key (overrides VT_API_KEY env var)")

    args = parser.parse_args()

    if args.value:
        if not args.type:
            print("[!] --type is required when using --value", file=sys.stderr)
            sys.exit(1)
        enrich_ioc(args.value, args.type, args.vt_key)
    elif args.batch:
        process_batch(args.batch, args.vt_key)
