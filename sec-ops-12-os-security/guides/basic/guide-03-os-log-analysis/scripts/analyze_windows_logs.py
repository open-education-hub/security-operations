#!/usr/bin/env python3
"""
analyze_windows_logs.py
Windows Security Event Log analyzer for the OS Log Analysis guide.
Reads JSON event samples from /var/log/samples/ and produces
formatted analysis output.

Usage:
  python3 /scripts/analyze_windows_logs.py --type logon
  python3 /scripts/analyze_windows_logs.py --type process
  python3 /scripts/analyze_windows_logs.py --type all
"""

import json
import sys
import os
import argparse
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────
WINDOWS_EVENTS_FILE  = "/var/log/samples/windows_process_events.json"
SAMPLES_DIR          = "/var/log/samples"

# Expected baseline: IPs that are considered "normal" for this environment
TRUSTED_IPS = {"192.168.1.5", "192.168.1.42", "192.168.1.1", "127.0.0.1"}

# Logon types
LOGON_TYPES = {
    2:  "Interactive (console)",
    3:  "Network (SMB/WMI)",
    4:  "Batch (scheduled tasks)",
    5:  "Service (service start)",
    7:  "Unlock (workstation unlock)",
    8:  "NetworkCleartext (plain-text creds!)",
    9:  "NewCredentials (runas)",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive (offline domain logon)",
}

# High-risk event IDs
HIGH_RISK_EVENTS = {7045, 4698, 4720, 4728, 1102}
CRITICAL_EVENTS  = {1102}
SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "nc.exe", "nc64.exe", "ncat.exe",
    "meterpreter", "cobalt strike", "psexec.exe", "wce.exe",
    "pwdump.exe", "gsecdump.exe", "procdump.exe",
}
SUSPICIOUS_PATHS = [
    r"\AppData\Local\Temp",
    r"\AppData\Roaming",
    r"\Downloads",
    r"C:\ProgramData\\",
    r"C:\Temp",
    r"\Users\Public",
]


def load_events(path: str) -> list:
    if not os.path.exists(path):
        print(f"[!] Sample file not found: {path}")
        print(f"    Make sure you are running inside the container with samples mounted.")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def flag(msg: str, level: str = "WARN") -> str:
    colors = {"CRIT": "\033[91m", "WARN": "\033[93m", "INFO": "\033[94m", "OK": "\033[92m"}
    reset  = "\033[0m"
    c = colors.get(level, "")
    return f"{c}[{level}]{reset} {msg}"


def analyze_logon_events(events: list) -> None:
    print("\n" + "="*70)
    print("  LOGON EVENT ANALYSIS (Event IDs 4624 / 4625 / 4648)")
    print("="*70)

    failures_by_ip: dict = defaultdict(list)
    successes_by_ip: dict = defaultdict(list)

    for ev in events:
        eid = ev.get("id")
        if eid not in (4624, 4625, 4648):
            continue
        ip   = ev.get("ip") or ev.get("IpAddress", "-")
        user = ev.get("user") or ev.get("TargetUserName", "?")
        time = ev.get("time") or ev.get("TimeGenerated", "?")
        ltype= ev.get("type") or ev.get("LogonType", 0)
        lname= LOGON_TYPES.get(ltype, f"Type {ltype}")

        if eid == 4625:
            failures_by_ip[ip].append({"time": time, "user": user})
        elif eid == 4624:
            successes_by_ip[ip].append({"time": time, "user": user, "type": lname})

        sus = ""
        if ip not in TRUSTED_IPS and ip not in ("-", "127.0.0.1"):
            sus = "  *** UNTRUSTED SOURCE IP ***"
        if ltype == 8:
            sus += "  *** CLEARTEXT CREDS ***"

        status = "FAIL" if eid == 4625 else "SUCC"
        print(f"  {time}  [{status}] {eid}  User:{user:<14} Type:{lname:<28} From:{ip}{sus}")

    # Brute force detection
    print("\n--- Brute Force Detection ---")
    bf_threshold = 5
    for ip, fails in failures_by_ip.items():
        if len(fails) >= bf_threshold:
            succs = successes_by_ip.get(ip, [])
            if succs:
                print(flag(
                    f"BRUTE FORCE SUCCESS: {ip} — {len(fails)} failures then "
                    f"{len(succs)} success(es). LIKELY COMPROMISED!", "CRIT"))
                for s in succs:
                    print(f"    Successful logon: {s['time']}  User:{s['user']}  Type:{s['type']}")
            else:
                print(flag(
                    f"Brute force attempt: {ip} — {len(fails)} failures. No success (blocked?).", "WARN"))
        elif len(fails) > 1:
            print(f"  INFO: {ip} had {len(fails)} failed logons (below brute-force threshold).")


def analyze_process_events(events: list) -> None:
    print("\n" + "="*70)
    print("  PROCESS CREATION ANALYSIS (Event ID 4688)")
    print("="*70)

    for ev in events:
        eid = ev.get("id")
        if eid != 4688:
            continue
        time    = ev.get("time", "?")
        proc    = ev.get("process", ev.get("ProcessName", "?"))
        parent  = ev.get("parent", ev.get("ParentProcessName", "?"))
        cmdline = ev.get("cmdline", ev.get("CommandLine", ""))
        path    = ev.get("path", proc)
        user    = ev.get("user", ev.get("SubjectUserName", "-"))

        flags = []

        # Check process name
        if proc.lower() in SUSPICIOUS_PROCESSES:
            flags.append(("CRIT", f"KNOWN MALICIOUS TOOL: {proc}"))

        # Check path
        for sp in SUSPICIOUS_PATHS:
            if sp.lower() in path.lower():
                flags.append(("WARN", f"Suspicious path: {path}"))
                break

        # Check command line
        cmdl = cmdline.lower()
        if "-encodedcommand" in cmdl or "-enc " in cmdl:
            flags.append(("WARN", "Encoded PowerShell command"))
        if "downloadstring" in cmdl or "downloadfile" in cmdl or "iex" in cmdl:
            flags.append(("WARN", "PowerShell web cradle / IEX pattern"))
        if "-e cmd.exe" in cmdl or "-e /bin/bash" in cmdl or "-e cmd" in cmdl:
            flags.append(("CRIT", "Netcat shell execution flag (-e)"))
        if "urlcache" in cmdl:
            flags.append(("WARN", "certutil LOLBin download attempt"))
        if "base64" in cmdl and "decode" in cmdl:
            flags.append(("WARN", "Base64 decode in command line"))

        level = "CRIT" if any(f[0] == "CRIT" for f in flags) else ("WARN" if flags else "INFO")
        color = {"CRIT": "\033[91m", "WARN": "\033[93m", "INFO": "\033[0m"}[level]
        reset = "\033[0m"

        print(f"\n  {time}  {color}[4688]{reset}  {proc} (parent: {parent})  User: {user}")
        if cmdline:
            print(f"    CMD: {cmdline[:100]}{'...' if len(cmdline) > 100 else ''}")
        for lvl, msg in flags:
            print(f"    {flag(msg, lvl)}")


def analyze_persistence_events(events: list) -> None:
    print("\n" + "="*70)
    print("  PERSISTENCE EVENT ANALYSIS (7045 / 4698 / 4720 / 4728)")
    print("="*70)

    for ev in events:
        eid  = ev.get("id")
        time = ev.get("time", "?")

        if eid == 7045:
            svc  = ev.get("service", "?")
            path = ev.get("path", "?")
            acct = ev.get("account", "?")
            print(f"\n  {time}  {flag('NEW SERVICE INSTALLED (7045)','CRIT')}")
            print(f"    Service: {svc}")
            print(f"    Path:    {path}")
            print(f"    Account: {acct}")
            if acct == "LocalSystem":
                print(f"    {flag('Service runs as SYSTEM — highest privilege', 'WARN')}")
            for sp in SUSPICIOUS_PATHS:
                if sp.lower() in path.lower():
                    print(f"    {flag(f'Service binary in suspicious path: {path}', 'CRIT')}")
                    break

        elif eid == 4698:
            task = ev.get("task", "?")
            act  = ev.get("action", "?")
            print(f"\n  {time}  {flag('SCHEDULED TASK CREATED (4698)','CRIT')}")
            print(f"    Task:   {task}")
            print(f"    Action: {act[:100]}{'...' if len(act) > 100 else ''}")
            if "-encodedcommand" in act.lower() or "-enc " in act.lower():
                print(f"    {flag('Encoded PowerShell in task action — decode and investigate!', 'CRIT')}")

        elif eid == 4720:
            sub  = ev.get("SubjectUserName", "?")
            tgt  = ev.get("TargetUserName", "?")
            print(f"\n  {time}  {flag('USER ACCOUNT CREATED (4720)','WARN')}")
            print(f"    Created by: {sub}  New account: {tgt}")

        elif eid == 4728:
            sub   = ev.get("SubjectUserName", "?")
            tgt   = ev.get("TargetUserName", "?")
            group = ev.get("GroupName", "?")
            print(f"\n  {time}  {flag('USER ADDED TO PRIVILEGED GROUP (4728)','CRIT')}")
            print(f"    Added by: {sub}  Member: {tgt}  Group: {group}")

        elif eid == 1102:
            user = ev.get("user", ev.get("SubjectUserName", "?"))
            print(f"\n  {time}  {flag('SECURITY LOG CLEARED (1102) — ANTI-FORENSICS!', 'CRIT')}")
            print(f"    Cleared by: {user}")


def main():
    parser = argparse.ArgumentParser(description="Windows Security Event Log Analyzer")
    parser.add_argument(
        "--type", choices=["logon", "process", "persistence", "all"],
        default="all", help="Analysis type to run"
    )
    parser.add_argument(
        "--file", default=WINDOWS_EVENTS_FILE,
        help="Path to JSON events file"
    )
    args = parser.parse_args()

    print(f"\nLoading events from: {args.file}")
    events = load_events(args.file)
    print(f"Loaded {len(events)} events.")

    if args.type in ("logon", "all"):
        analyze_logon_events(events)

    if args.type in ("process", "all"):
        analyze_process_events(events)

    if args.type in ("persistence", "all"):
        analyze_persistence_events(events)

    print("\n" + "="*70)
    print("  Analysis complete.")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
