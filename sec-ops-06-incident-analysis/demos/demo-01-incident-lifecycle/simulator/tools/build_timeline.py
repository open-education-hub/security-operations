#!/usr/bin/env python3
"""
Tool: build_timeline.py
Generates the incident timeline for demo-01
"""

import json
import sys

TIMELINE = [
    {"time": "2024-11-15 09:42:11", "system": "MAIL01",    "event": "Phishing email delivered (SPF FAIL)",         "phase": "Delivery"},
    {"time": "2024-11-15 09:44:22", "system": "WS-JSMITH", "event": "HTTP GET to http://185.220.101.47/track",     "phase": "Delivery"},
    {"time": "2024-11-15 09:44:28", "system": "WS-JSMITH", "event": "Word document opened (Invoice...docm)",       "phase": "Delivery"},
    {"time": "2024-11-15 09:44:35", "system": "WS-JSMITH", "event": "WINWORD.EXE → CMD.EXE → POWERSHELL.EXE",     "phase": "Exploit"},
    {"time": "2024-11-15 09:45:02", "system": "WS-JSMITH", "event": "TCP 4444 outbound to 185.220.101.47",         "phase": "C2"},
    {"time": "2024-11-15 09:45:08", "system": "WS-JSMITH", "event": "C2 connected — shell active",                 "phase": "C2"},
    {"time": "2024-11-15 09:47:12", "system": "WS-JSMITH", "event": "whoami /all (discovery)",                     "phase": "Discovery"},
    {"time": "2024-11-15 09:47:45", "system": "WS-JSMITH", "event": "ipconfig /all (discovery)",                   "phase": "Discovery"},
    {"time": "2024-11-15 09:48:03", "system": "WS-JSMITH", "event": "net user /domain (discovery)",                "phase": "Discovery"},
    {"time": "2024-11-15 09:48:31", "system": "WS-JSMITH", "event": 'net group "Domain Admins" /domain',           "phase": "Discovery"},
    {"time": "2024-11-15 09:52:00", "system": "SIEM",      "event": "Alert triggered (macro execution rule)",      "phase": "Detection"},
]

print(f"\nINCIDENT TIMELINE: INC-2024-0847")
print("=" * 85)
print(f"{'Time (UTC)':<22} {'System':<12} {'Event':<50} {'Phase'}")
print("─" * 85)
for entry in TIMELINE:
    print(f"{entry['time']:<22} {entry['system']:<12} {entry['event']:<50} {entry['phase']}")
print()
