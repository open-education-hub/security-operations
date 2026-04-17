#!/usr/bin/env python3
"""Forensic analysis tools loader for advanced drill 02."""
import json, sys, os

EVIDENCE_DIR = "/forensics/evidence"

def load(name):
    path = os.path.join(EVIDENCE_DIR, name)
    with open(path) as f:
        return json.load(f)

print("Forensic analysis tools loaded.")
print("Available scripts:")
print("  python3 /forensics/scripts/timeline.py --help")
print("  python3 /forensics/scripts/memory.py --help")
print("  python3 /forensics/scripts/deleted.py --help")
print("  python3 /forensics/scripts/netflow.py --help")
print("  python3 /forensics/scripts/usb.py --list")
print("  python3 /forensics/scripts/generate-report.py --output /tmp/report.md")
