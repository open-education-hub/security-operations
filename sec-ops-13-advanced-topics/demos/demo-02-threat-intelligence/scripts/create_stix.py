#!/usr/bin/env python3
"""
Create a new STIX 2.1 bundle from scratch — simulating analyst output.
"""
import json
import uuid
from datetime import datetime, timezone

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def new_id(type_name):
    return f"{type_name}--{uuid.uuid4()}"

# New C2 IP discovered during investigation
indicator = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": new_id("indicator"),
    "created": now(),
    "modified": now(),
    "name": "New CloudLoader C2 (analyst-discovered)",
    "indicator_types": ["malicious-activity"],
    "pattern": "[ipv4-addr:value = '192.0.2.99']",
    "pattern_type": "stix",
    "valid_from": now(),
    "description": "Newly discovered C2 IP for CloudLoader, found during log analysis of compromised host"
}

# ATT&CK technique: T1071 - Application Layer Protocol (C2 over HTTP)
attack_pattern = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": new_id("attack-pattern"),
    "created": now(),
    "modified": now(),
    "name": "Application Layer Protocol: Web Protocols",
    "description": "CloudLoader uses HTTP/HTTPS for C2 communication to blend with normal traffic",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1071/001/",
            "external_id": "T1071.001"
        }
    ]
}

# Reference to existing CloudLoader malware
existing_malware_id = "malware--deadbeef-1111-2222-3333-444455556666"

# Relationships
rel_indicator_malware = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": new_id("relationship"),
    "created": now(),
    "modified": now(),
    "relationship_type": "indicates",
    "source_ref": indicator["id"],
    "target_ref": existing_malware_id
}

rel_malware_technique = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": new_id("relationship"),
    "created": now(),
    "modified": now(),
    "relationship_type": "uses",
    "source_ref": existing_malware_id,
    "target_ref": attack_pattern["id"]
}

# Report packaging everything
report = {
    "type": "report",
    "spec_version": "2.1",
    "id": new_id("report"),
    "created": now(),
    "modified": now(),
    "name": "CloudLoader New C2 — Analyst Report",
    "description": "New C2 infrastructure discovered for CloudLoader backdoor during incident investigation",
    "report_types": ["threat-actor", "indicator"],
    "published": now(),
    "object_refs": [
        indicator["id"],
        attack_pattern["id"],
        rel_indicator_malware["id"],
        rel_malware_technique["id"]
    ]
}

bundle = {
    "type": "bundle",
    "id": new_id("bundle"),
    "spec_version": "2.1",
    "objects": [indicator, attack_pattern, rel_indicator_malware, rel_malware_technique, report]
}

output = json.dumps(bundle, indent=2)
print("=" * 60)
print("Generated STIX 2.1 Bundle")
print("=" * 60)
print(output)
print("\n" + "=" * 60)
print("This bundle can be submitted to MISP or a TAXII server:")
print("  POST /taxii/collections/{id}/objects/")
print("  Content-Type: application/taxii+json;version=2.1")
