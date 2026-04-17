#!/usr/bin/env python3
"""
Parse STIX 2.1 bundle and extract IOCs and summary information.
"""
import json
import re

BUNDLE_FILE = "/data/threat_bundle.json"

with open(BUNDLE_FILE) as f:
    bundle = json.load(f)

objects = bundle["objects"]
by_type = {}
for obj in objects:
    t = obj["type"]
    by_type.setdefault(t, []).append(obj)

print("=" * 60)
print("STIX Bundle Summary")
print("=" * 60)

for actor in by_type.get("threat-actor", []):
    print(f"\nThreat Actor: {actor['name']}")
    print(f"  Motivation: {actor.get('primary_motivation', 'unknown')}")
    print(f"  Sophistication: {actor.get('sophistication', 'unknown')}")
    print(f"  Aliases: {', '.join(actor.get('aliases', []))}")

for campaign in by_type.get("campaign", []):
    print(f"\nCampaign: {campaign['name']}")
    print(f"  First seen: {campaign.get('first_seen', 'unknown')}")
    print(f"  Objective: {campaign.get('objective', 'unknown')}")

for malware in by_type.get("malware", []):
    print(f"\nMalware: {malware['name']}")
    print(f"  Types: {', '.join(malware.get('malware_types', []))}")
    print(f"  Capabilities: {', '.join(malware.get('capabilities', []))}")

print("\n" + "=" * 60)
print("Indicators (IOCs)")
print("=" * 60)

for indicator in by_type.get("indicator", []):
    pattern = indicator.get("pattern", "")
    name = indicator.get("name", "")
    desc = indicator.get("description", "")

    # Extract value from STIX pattern
    ip_match = re.search(r"ipv4-addr:value = '([^']+)'", pattern)
    domain_match = re.search(r"domain-name:value = '([^']+)'", pattern)
    hash_match = re.search(r"hashes\.'[^']+' = '([^']+)'", pattern)

    if ip_match:
        print(f"\n[IP]     {ip_match.group(1):<25} — {desc}")
    elif domain_match:
        print(f"\n[DOMAIN] {domain_match.group(1):<25} — {desc}")
    elif hash_match:
        print(f"\n[HASH]   {hash_match.group(1):<25} — {desc}")
    else:
        print(f"\n[OTHER]  {name} — {pattern}")

print("\n" + "=" * 60)
print(f"Relationships: {len(by_type.get('relationship', []))}")
for rel in by_type.get("relationship", []):
    print(f"  {rel['source_ref'].split('--')[0]} --[{rel['relationship_type']}]--> {rel['target_ref'].split('--')[0]}")
