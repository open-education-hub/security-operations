#!/usr/bin/env python3
"""
parse_sysmon.py — Sysmon XML Event Parser (Demo 02)
Parses simulated Sysmon events and identifies suspicious patterns.
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

SUSPICIOUS_PATTERNS = [
    {
        "name": "Office App Spawns Script Engine (T1059.001)",
        "event_id": "1",
        "check": lambda e: any(
            office in (get_field(e, "ParentImage") or "")
            for office in ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"]
        ) and any(
            script in (get_field(e, "Image") or "")
            for script in ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "cscript.exe"]
        ),
        "severity": "CRITICAL",
    },
    {
        "name": "PowerShell with Encoded Command (T1059.001)",
        "event_id": "1",
        "check": lambda e: "powershell" in (get_field(e, "Image") or "").lower()
            and any(flag in (get_field(e, "CommandLine") or "").lower()
                    for flag in ["-enc", "-encodedcommand"]),
        "severity": "HIGH",
    },
    {
        "name": "Executable Dropped to Temp/AppData (T1105)",
        "event_id": "11",
        "check": lambda e: any(
            loc in (get_field(e, "TargetFilename") or "").lower()
            for loc in ["\\temp\\", "\\appdata\\"]
        ) and (get_field(e, "TargetFilename") or "").lower().endswith(".exe"),
        "severity": "HIGH",
    },
    {
        "name": "LSASS Memory Access — Credential Dump (T1003.001)",
        "event_id": "10",
        "check": lambda e: "lsass.exe" in (get_field(e, "TargetImage") or "").lower(),
        "severity": "CRITICAL",
    },
    {
        "name": "Registry Run Key Modification — Persistence (T1547.001)",
        "event_id": "13",
        "check": lambda e: "\\currentversion\\run" in (get_field(e, "TargetObject") or "").lower(),
        "severity": "HIGH",
    },
    {
        "name": "Remote Thread Injection (T1055.001)",
        "event_id": "8",
        "check": lambda e: any(
            target in (get_field(e, "TargetImage") or "").lower()
            for target in ["explorer.exe", "svchost.exe", "services.exe", "lsass.exe"]
        ),
        "severity": "CRITICAL",
    },
    {
        "name": "PowerShell Network Connection (T1071.001)",
        "event_id": "3",
        "check": lambda e: "powershell" in (get_field(e, "Image") or "").lower(),
        "severity": "HIGH",
    },
    {
        "name": "Suspicious DNS Query — Possible C2 (T1071.004)",
        "event_id": "22",
        "check": lambda e: get_field(e, "QueryName") is not None,
        "severity": "MEDIUM",
    },
]

EVENT_DESCRIPTIONS = {
    "1":  "Process Create",
    "2":  "File Creation Time Changed",
    "3":  "Network Connection",
    "6":  "Driver Loaded",
    "7":  "Image Loaded",
    "8":  "CreateRemoteThread",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "RegistryEvent (Object Create/Delete)",
    "13": "RegistryEvent (Value Set)",
    "14": "RegistryEvent (Key/Value Rename)",
    "15": "FileCreateStreamHash",
    "17": "PipeEvent (Created)",
    "18": "PipeEvent (Connected)",
    "22": "DNSEvent",
    "23": "FileDelete",
    "25": "ProcessTampering",
}


def get_field(event_element, field_name):
    """Extract a named data field from a Sysmon event element."""
    for data in event_element.findall(".//Data"):
        if data.get("Name") == field_name:
            return data.text
    return None


def get_event_id(event_element):
    eid = event_element.find(".//EventID")
    return eid.text if eid is not None else "?"


def get_timestamp(event_element):
    tc = event_element.find(".//TimeCreated")
    return tc.get("SystemTime", "N/A") if tc is not None else "N/A"


def parse_events(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        events = root.findall("Event")
        return events
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        sys.exit(1)


def display_all_events(events):
    print(f"\n{'='*72}")
    print(f"  SYSMON EVENT LOG — {len(events)} events found")
    print(f"{'='*72}\n")

    for event in events:
        eid = get_event_id(event)
        ts = get_timestamp(event)
        desc = EVENT_DESCRIPTIONS.get(eid, "Unknown")
        print(f"  [{ts}] Event ID {eid}: {desc}")

        if eid == "1":
            print(f"    Image  : {get_field(event, 'Image')}")
            cmdline = get_field(event, 'CommandLine') or ''
            print(f"    CmdLine: {cmdline[:80]}")
            print(f"    Parent : {get_field(event, 'ParentImage')}")
            print(f"    User   : {get_field(event, 'User')}")

        elif eid == "3":
            print(f"    Process: {get_field(event, 'Image')}")
            print(f"    Dst    : {get_field(event, 'DestinationIp')}:{get_field(event, 'DestinationPort')}")
            print(f"    Domain : {get_field(event, 'DestinationHostname')}")

        elif eid == "10":
            print(f"    Source : {get_field(event, 'SourceImage')}")
            print(f"    Target : {get_field(event, 'TargetImage')}")
            print(f"    Access : {get_field(event, 'GrantedAccess')}")

        elif eid == "11":
            print(f"    Process: {get_field(event, 'Image')}")
            print(f"    File   : {get_field(event, 'TargetFilename')}")

        elif eid == "13":
            print(f"    Process: {get_field(event, 'Image')}")
            print(f"    Key    : {get_field(event, 'TargetObject')}")
            print(f"    Value  : {get_field(event, 'Details')}")

        elif eid == "22":
            print(f"    Process: {get_field(event, 'Image')}")
            print(f"    Query  : {get_field(event, 'QueryName')}")
            print(f"    Result : {get_field(event, 'QueryResults')}")

        elif eid == "8":
            print(f"    Source : {get_field(event, 'SourceImage')}")
            print(f"    Target : {get_field(event, 'TargetImage')}")
        print()


def detect_suspicious(events):
    print(f"\n{'='*72}")
    print(f"  SUSPICIOUS ACTIVITY DETECTION RESULTS")
    print(f"{'='*72}\n")

    detections = []
    for event in events:
        eid = get_event_id(event)
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern["event_id"] == eid:
                try:
                    if pattern["check"](event):
                        detections.append({
                            "name": pattern["name"],
                            "severity": pattern["severity"],
                            "event_id": eid,
                            "timestamp": get_timestamp(event),
                            "event": event,
                        })
                except Exception:
                    pass

    if not detections:
        print("  No suspicious patterns detected.\n")
        return

    for det in detections:
        sev = det["severity"]
        prefix = {"CRITICAL": "!!! CRITICAL", "HIGH": " !! HIGH    ", "MEDIUM": "  ! MEDIUM  "}.get(sev, "    LOW     ")
        print(f"  {prefix} | Event {det['event_id']} @ {det['timestamp']}")
        print(f"            Detected: {det['name']}")

        eid = det["event_id"]
        event = det["event"]
        if eid == "1":
            print(f"            Process : {get_field(event, 'Image')}")
            print(f"            Parent  : {get_field(event, 'ParentImage')}")
            cmdline = get_field(event, 'CommandLine') or ''
            print(f"            CmdLine : {cmdline[:80]}")
        elif eid == "10":
            print(f"            Accessor: {get_field(event, 'SourceImage')}")
            print(f"            Target  : {get_field(event, 'TargetImage')}")
            print(f"            Access  : {get_field(event, 'GrantedAccess')}")
        elif eid == "13":
            print(f"            Process : {get_field(event, 'Image')}")
            print(f"            RegKey  : {get_field(event, 'TargetObject')}")
        elif eid == "8":
            print(f"            Injector: {get_field(event, 'SourceImage')}")
            print(f"            Victim  : {get_field(event, 'TargetImage')}")
        print()

    print(f"  Total detections: {len(detections)}")
    crit_count = sum(1 for d in detections if d["severity"] == "CRITICAL")
    high_count = sum(1 for d in detections if d["severity"] == "HIGH")
    print(f"  CRITICAL: {crit_count}  HIGH: {high_count}")


def main():
    parser = argparse.ArgumentParser(description="Sysmon Event Parser — Demo 02")
    parser.add_argument("--file", default="/var/log/sysmon_events.xml")
    parser.add_argument("--all", action="store_true", help="Show all events")
    parser.add_argument("--detect-suspicious", action="store_true", help="Run detection rules")
    args = parser.parse_args()

    events = parse_events(args.file)
    print(f"\n[+] Loaded {len(events)} Sysmon events from {args.file}")

    if args.all:
        display_all_events(events)

    if args.detect_suspicious or not args.all:
        detect_suspicious(events)


if __name__ == "__main__":
    main()
