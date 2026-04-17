#!/usr/bin/env python3
"""
VERIS Record Explorer - Interactive demo for Session 11
"""
import json
import os

SAMPLES_DIR = "/data/samples"

def load_record(filename):
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path) as f:
        return json.load(f)

def print_summary(record):
    print(f"\n{'='*60}")
    print(f"Incident ID : {record.get('incident_id', 'N/A')}")
    print(f"Summary     : {record.get('summary', 'N/A')}")
    print(f"Confidence  : {record.get('confidence', 'N/A')}")
    print(f"{'='*60}")

def print_4a(record):
    print("\n--- ACTOR ---")
    for actor_type, details in record.get('actor', {}).items():
        print(f"  Type   : {actor_type}")
        print(f"  Variety: {details.get('variety', [])}")
        print(f"  Motive : {details.get('motive', [])}")

    print("\n--- ACTION ---")
    for action_type, details in record.get('action', {}).items():
        print(f"  Type   : {action_type}")
        print(f"  Variety: {details.get('variety', [])}")
        print(f"  Vector : {details.get('vector', [])}")

    print("\n--- ASSET ---")
    for asset in record.get('asset', {}).get('assets', []):
        print(f"  {asset.get('variety', 'Unknown')}")

    print("\n--- ATTRIBUTE ---")
    for attr_type, details in record.get('attribute', {}).items():
        print(f"  Type: {attr_type}")
        if attr_type == 'confidentiality':
            print(f"  Disclosure: {details.get('data_disclosure', 'Unknown')}")
            for d in details.get('data', []):
                print(f"    Data: {d.get('variety')} - {d.get('amount', '?')} records")
        if attr_type == 'availability':
            print(f"  Variety: {details.get('variety', [])}")
            dur = details.get('duration', {})
            print(f"  Duration: {dur.get('value', '?')} {dur.get('unit', '?')}")

def print_timeline(record):
    print("\n--- TIMELINE ---")
    timeline = record.get('timeline', {})
    for key, val in timeline.items():
        if isinstance(val, dict):
            if 'year' in val:
                print(f"  {key}: {val.get('year')}-{val.get('month', '??')}")
            else:
                print(f"  {key}: {val.get('value', '?')} {val.get('unit', '?')}")

# Load the sample record on startup
print("VERIS Schema Explorer - Demo 01")
print("================================")
print("Available sample files:")
for f in os.listdir(SAMPLES_DIR):
    print(f"  - {f}")

print("\nLoading phishing_breach.json ...")
incident = load_record("phishing_breach.json")

print_summary(incident)
print_4a(incident)
print_timeline(incident)

print("\n\nExplore further:")
print("  print_summary(incident)")
print("  print_4a(incident)")
print("  print_timeline(incident)")
print("  incident['actor']  # raw access")
print("  incident.keys()    # all top-level fields")
