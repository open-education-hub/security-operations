#!/usr/bin/env python3
"""
IOC Enrichment Script
Checks extracted IOCs against a local mock reputation database.
"""
import json
import re

BUNDLE_FILE = "/data/threat_bundle.json"

# Mock reputation database (simulates VirusTotal/OTX responses)
REPUTATION_DB = {
    "203.0.113.45":                    {"score": 95, "verdict": "MALICIOUS", "feeds": 12, "tags": ["C2", "APT42"]},
    "198.51.100.12":                   {"score": 78, "verdict": "SUSPICIOUS", "feeds": 3,  "tags": ["exfil", "data-theft"]},
    "update.cdn-secure.net":           {"score": 88, "verdict": "MALICIOUS", "feeds": 7,  "tags": ["typosquat", "malware-delivery"]},
    "d41d8cd98f00b204e9800998ecf8427e": {"score": 100, "verdict": "MALICIOUS", "feeds": 22, "tags": ["backdoor", "CloudLoader"]},
    "5f4dcc3b5aa765d61d8327deb882cf99": {"score": 72, "verdict": "SUSPICIOUS", "feeds": 4, "tags": ["persistence", "dropper"]},
}

with open(BUNDLE_FILE) as f:
    bundle = json.load(f)

iocs = []
for obj in bundle["objects"]:
    if obj["type"] != "indicator":
        continue
    pattern = obj.get("pattern", "")
    ip_match = re.search(r"ipv4-addr:value = '([^']+)'", pattern)
    domain_match = re.search(r"domain-name:value = '([^']+)'", pattern)
    hash_match = re.search(r"hashes\.'[^']+' = '([^']+)'", pattern)
    if ip_match:
        iocs.append(("IP", ip_match.group(1)))
    elif domain_match:
        iocs.append(("DOMAIN", domain_match.group(1)))
    elif hash_match:
        iocs.append(("HASH", hash_match.group(1)))

print("=" * 60)
print("IOC Enrichment Report")
print("=" * 60)

for ioc_type, ioc_value in iocs:
    rep = REPUTATION_DB.get(ioc_value)
    print(f"\n[{ioc_type}] {ioc_value}")
    if rep:
        verdict = rep["verdict"]
        score = rep["score"]
        feeds = rep["feeds"]
        tags = ", ".join(rep["tags"])
        color = "\033[91m" if verdict == "MALICIOUS" else "\033[93m"
        reset = "\033[0m"
        print(f"  Score:   {score}/100")
        print(f"  Verdict: {color}{verdict}{reset}")
        print(f"  Feeds:   seen in {feeds} threat intelligence feeds")
        print(f"  Tags:    {tags}")
        if verdict == "MALICIOUS":
            print("  ACTION:  Block immediately — add to firewall/SIEM blocklist")
        else:
            print("  ACTION:  Monitor — investigate further before blocking")
    else:
        print("  Score:   N/A")
        print("  Verdict: UNKNOWN — not in local DB")
        print("  ACTION:  Query VirusTotal/OTX for additional context")

print("\n" + "=" * 60)
print("Enrichment complete. Share STIX bundle to MISP for team visibility.")
