#!/usr/bin/env python3
"""
EDR Event Analyzer — Demo 01: EDR Concepts
Parses sample_events.jsonl and displays attack timeline, IoCs, and hunting results.
"""

import json
import argparse
import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "white",
}

SEVERITY_ICONS = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]",
    "medium":   "[MEDIUM]",
    "low":      "[LOW]",
    "info":     "[INFO]",
}

def load_events(path="sample_events.jsonl"):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: skipped invalid JSON line: {e}")
    return sorted(events, key=lambda e: e.get("timestamp", ""))


def format_event(event, index):
    ts = event.get("timestamp", "")
    etype = event.get("event_type", "unknown")
    sev = event.get("severity", "info")
    mitre = event.get("mitre_technique", "")
    proc = event.get("process", {})

    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f"  Event #{index+1} | {ts} | Type: {etype.upper()} | {SEVERITY_ICONS.get(sev, f"[{sev.upper()}]")} | {mitre}")
    lines.append(f"{'='*70}")
    lines.append(f"  Host: {event.get('hostname', 'N/A')} | User: {event.get('user', 'N/A')}")

    if etype == "process_create":
        lines.append(f"  Process   : {proc.get('image', 'N/A')}")
        lines.append(f"  PID       : {proc.get('pid', 'N/A')}")
        lines.append(f"  CmdLine   : {proc.get('command_line', 'N/A')[:100]}")
        lines.append(f"  Parent    : {proc.get('parent_image', 'N/A')}")
        lines.append(f"  Workdir   : {proc.get('current_directory', 'N/A')}")

    elif etype == "network_connect":
        net = event.get("network", {})
        lines.append(f"  Process   : {proc.get('image', 'N/A')}")
        lines.append(f"  Dst IP    : {net.get('destination_ip')}:{net.get('destination_port')}")
        lines.append(f"  Protocol  : {net.get('protocol')} {net.get('direction')}")
        lines.append(f"  Bytes     : sent={net.get('bytes_sent')} recv={net.get('bytes_received')}")

    elif etype == "dns_query":
        dns = event.get("dns", {})
        lines.append(f"  Process   : {proc.get('image', 'N/A')}")
        lines.append(f"  Query     : {dns.get('query')} ({dns.get('query_type')})")
        lines.append(f"  Response  : {dns.get('response')}")

    elif etype == "file_create":
        f_info = event.get("file", {})
        lines.append(f"  Process   : {proc.get('image', 'N/A')}")
        lines.append(f"  File      : {f_info.get('path')}")
        lines.append(f"  Size      : {f_info.get('size_bytes')} bytes")
        lines.append(f"  SHA256    : {f_info.get('sha256', 'N/A')[:48]}...")
        lines.append(f"  Signed    : {f_info.get('signed')} | PE: {f_info.get('is_pe')}")
        if f_info.get("vt_detections"):
            lines.append(f"  VT Hits   : {f_info.get('vt_detections')}")

    elif etype == "registry_set":
        reg = event.get("registry", {})
        lines.append(f"  Process   : {proc.get('image', 'N/A')}")
        lines.append(f"  Key       : {reg.get('key')}")
        lines.append(f"  Value     : {reg.get('value_name')} = {reg.get('value_data')}")
        lines.append(f"  Operation : {reg.get('operation')}")

    elif etype == "process_access":
        tgt = event.get("target", {})
        lines.append(f"  Accessor  : {proc.get('image', 'N/A')} (PID {proc.get('pid')})")
        lines.append(f"  Target    : {tgt.get('image')} (PID {tgt.get('pid')})")
        lines.append(f"  AccessMask: {tgt.get('access_mask')} ({tgt.get('access_description')})")

    return "\n".join(lines)


def mode_timeline(events):
    print("\n" + "="*70)
    print("  EDR ATTACK TIMELINE — Demo 01")
    print("="*70)
    print(f"  Total events: {len(events)}")
    crit = sum(1 for e in events if e.get("severity") == "critical")
    high = sum(1 for e in events if e.get("severity") == "high")
    print(f"  CRITICAL: {crit}  HIGH: {high}")
    print("="*70)

    stages = {
        "T1566.001": "Stage 1: Initial Access",
        "T1059.001": "Stage 2: Execution",
        "T1071.004": "Stage 3: C2 Communication",
        "T1071.001": "Stage 3: C2 Communication",
        "T1105":     "Stage 4: Payload Delivery",
        "T1547.001": "Stage 5: Persistence",
        "T1036.005": "Stage 5: Masquerading",
        "T1003.001": "Stage 6: Credential Access",
    }

    for i, event in enumerate(events):
        mitre = event.get("mitre_technique", "")
        stage = stages.get(mitre, "")
        if stage:
            print(f"\n  >>> {stage} <<<")
        print(format_event(event, i))


def mode_ioc(events):
    print("\n" + "="*70)
    print("  EXTRACTED INDICATORS OF COMPROMISE (IoCs)")
    print("="*70)

    hashes = set()
    ips = set()
    domains = set()
    paths = set()
    reg_keys = set()
    parent_child = set()

    for event in events:
        proc = event.get("process", {})
        # Hashes
        if proc.get("md5") and "ABCDEF" not in proc.get("md5", ""):
            hashes.add(("MD5", proc["md5"]))
        if proc.get("sha256") and "ABCDEF" not in proc.get("sha256", ""):
            hashes.add(("SHA256", proc["sha256"][:32] + "..."))
        # File hashes
        file_info = event.get("file", {})
        if file_info.get("md5"):
            hashes.add(("MD5", file_info["md5"]))
        # IPs
        net = event.get("network", {})
        if net.get("destination_ip"):
            ips.add(net["destination_ip"])
        # DNS
        dns = event.get("dns", {})
        if dns.get("query"):
            domains.add(dns["query"])
        if dns.get("response"):
            ips.add(dns["response"])
        # File paths
        if file_info.get("path") and file_info.get("is_pe"):
            paths.add(file_info["path"])
        # Registry
        reg = event.get("registry", {})
        if reg.get("key"):
            reg_keys.add(f"{reg['key']}\\{reg['value_name']}")
        # Parent-child
        if proc.get("parent_image") and proc.get("image"):
            parent = proc["parent_image"].split("\\")[-1]
            child = proc["image"].split("\\")[-1]
            parent_child.add(f"{parent} → {child}")

    print("\n  [HASHES]")
    for t, h in hashes:
        print(f"    {t}: {h}")

    print("\n  [IP ADDRESSES]")
    for ip in ips:
        print(f"    {ip}")

    print("\n  [DOMAINS]")
    for d in domains:
        print(f"    {d}")

    print("\n  [SUSPICIOUS FILE PATHS]")
    for p in paths:
        print(f"    {p}")

    print("\n  [REGISTRY KEYS]")
    for r in reg_keys:
        print(f"    {r}")

    print("\n  [PARENT→CHILD PROCESS RELATIONSHIPS]")
    for pc in parent_child:
        print(f"    {pc}")


def mode_hunt(events, query):
    print(f"\n  HUNT QUERY: '{query}'")
    print("="*70)
    results = []
    query_lower = query.lower()
    for i, event in enumerate(events):
        event_str = json.dumps(event).lower()
        if query_lower in event_str:
            results.append((i, event))

    print(f"  Found {len(results)} matching events\n")
    for i, event in results:
        print(format_event(event, i))


def main():
    parser = argparse.ArgumentParser(description="EDR Event Analyzer — Demo 01")
    parser.add_argument("--mode", choices=["timeline", "ioc", "hunt"], default="timeline")
    parser.add_argument("--query", default="", help="Search term for hunt mode")
    parser.add_argument("--file", default="sample_events.jsonl")
    args = parser.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file} not found. Run from the demo directory.")
        sys.exit(1)

    if args.mode == "timeline":
        mode_timeline(events)
    elif args.mode == "ioc":
        mode_ioc(events)
    elif args.mode == "hunt":
        if not args.query:
            print("Error: --query required for hunt mode")
            sys.exit(1)
        mode_hunt(events, args.query)


if __name__ == "__main__":
    main()
