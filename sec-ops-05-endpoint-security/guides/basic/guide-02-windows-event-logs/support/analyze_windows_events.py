#!/usr/bin/env python3
"""
analyze_windows_events.py
Analyzes the sample_security_events.jsonl file for security patterns.
Usage: python3 analyze_windows_events.py [--file <path>]

Guide 02 — Windows Event Log Analysis
"""

import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime

DEFAULT_FILE = "sample_security_events.jsonl"


def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def summarize(events):
    counts = defaultdict(int)
    for e in events:
        counts[e["EventID"]] += 1
    print("\n=== EVENT SUMMARY ===")
    for eid, cnt in sorted(counts.items()):
        label = {
            4624: "Successful Logon",
            4625: "Failed Logon",
            4688: "Process Created",
            4698: "Scheduled Task Created",
            7045: "New Service Installed",
        }.get(eid, "Other")
        print(f"  EventID {eid} ({label}): {cnt}")


def detect_brute_force(events):
    print("\n=== BRUTE FORCE DETECTION ===")
    failures = defaultdict(list)
    for e in events:
        if e["EventID"] == 4625:
            key = (e.get("IpAddress", "-"), e.get("TargetUserName", "-"))
            failures[key].append(e["TimeCreated"])

    found = False
    for (ip, user), times in failures.items():
        if len(times) >= 5:
            found = True
            print(f"  [ALERT] Brute force: {len(times)} failures for '{user}' from {ip}")
            print(f"          First: {times[0]}  Last: {times[-1]}")

    if not found:
        print("  No brute force patterns detected.")


def check_brute_force_success(events):
    print("\n=== BRUTE FORCE SUCCESS CHECK ===")
    failures_by_ip = defaultdict(int)
    success_after_failures = []

    for e in events:
        if e["EventID"] == 4625:
            failures_by_ip[e.get("IpAddress", "-")] += 1
        elif e["EventID"] == 4624:
            ip = e.get("IpAddress", "-")
            if failures_by_ip.get(ip, 0) >= 5:
                success_after_failures.append(e)

    if success_after_failures:
        for e in success_after_failures:
            print(f"  [CRITICAL] Brute force SUCCEEDED:")
            print(f"    User: {e.get('TargetUserName')} @ {e.get('Computer')}")
            print(f"    From: {e.get('IpAddress')} at {e.get('TimeCreated')}")
            print(f"    Auth: {e.get('AuthenticationPackageName')}")
    else:
        print("  No successful logon after brute force detected.")


def suspicious_processes(events):
    print("\n=== SUSPICIOUS PROCESS CREATION ===")
    suspicious_parents = {
        "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE",
        "mshta.exe", "wscript.exe", "cscript.exe",
    }
    suspicious_children = {
        "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe",
    }

    found = False
    for e in events:
        if e["EventID"] != 4688:
            continue
        parent = e.get("ParentProcessName", "").split("\\")[-1].lower()
        child = e.get("NewProcessName", "").split("\\")[-1].lower()
        cmdline = e.get("CommandLine", "")

        # Check parent-child relationship
        if parent.upper() in suspicious_parents and child in suspicious_children:
            found = True
            print(f"  [HIGH] Office/script parent spawning shell:")
            print(f"    {e.get('ParentProcessName')} → {e.get('NewProcessName')}")
            print(f"    CmdLine: {cmdline[:100]}")
            print(f"    Time: {e.get('TimeCreated')}  Host: {e.get('Computer')}")

        # Check for encoded PowerShell
        if child == "powershell.exe" and any(
            flag in cmdline.lower() for flag in ["-enc", "-encodedcommand", "-w hidden", "-nop"]
        ):
            found = True
            print(f"  [HIGH] Obfuscated PowerShell execution:")
            print(f"    User: {e.get('SubjectUserName')}  Host: {e.get('Computer')}")
            print(f"    CmdLine: {cmdline[:120]}")

    if not found:
        print("  No suspicious process creation found.")


def persistence_check(events):
    print("\n=== PERSISTENCE MECHANISMS ===")
    found = False
    for e in events:
        if e["EventID"] == 4698:
            found = True
            print(f"  [MEDIUM] Scheduled task created:")
            print(f"    Task: {e.get('TaskName')}")
            print(f"    User: {e.get('SubjectUserName')}  Host: {e.get('Computer')}")
            print(f"    Time: {e.get('TimeCreated')}")
    if not found:
        print("  No persistence via scheduled tasks found.")


def unique_source_ips(events):
    print("\n=== UNIQUE SOURCE IPs ===")
    ips = set()
    for e in events:
        ip = e.get("IpAddress", "-")
        if ip and ip not in ("-", "127.0.0.1", "::1"):
            ips.add(ip)
    for ip in sorted(ips):
        print(f"  {ip}")


def lateral_movement(events):
    print("\n=== LATERAL MOVEMENT INDICATORS ===")
    # Look for type 3 logons after brute force success IPs
    bf_ips = set()
    for e in events:
        if e["EventID"] == 4624:
            ip = e.get("IpAddress", "-")
            for e2 in events:
                if e2["EventID"] == 4625 and e2.get("IpAddress") == ip:
                    bf_ips.add(ip)

    seen_hosts = defaultdict(set)
    for e in events:
        if e["EventID"] == 4624 and e.get("LogonType") == 3:
            ip = e.get("IpAddress", "-")
            host = e.get("Computer", "-")
            if ip in bf_ips:
                seen_hosts[ip].add(host)

    if seen_hosts:
        for ip, hosts in seen_hosts.items():
            if len(hosts) > 1:
                print(f"  [HIGH] Lateral movement from {ip} to:")
                for h in sorted(hosts):
                    print(f"    → {h}")
    else:
        print("  No lateral movement patterns detected.")


def main():
    parser = argparse.ArgumentParser(description="Analyze Windows Security Events")
    parser.add_argument("--file", default=DEFAULT_FILE, help="Path to JSONL file")
    args = parser.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    print(f"Loaded {len(events)} events from {args.file}")

    summarize(events)
    unique_source_ips(events)
    detect_brute_force(events)
    check_brute_force_success(events)
    suspicious_processes(events)
    persistence_check(events)
    lateral_movement(events)

    print("\n=== ANALYSIS COMPLETE ===")


if __name__ == "__main__":
    main()
