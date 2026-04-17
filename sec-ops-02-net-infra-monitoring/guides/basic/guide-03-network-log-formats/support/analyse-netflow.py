#!/usr/bin/env python3
"""
NetFlow Record Analyser
========================
This script parses the text-format NetFlow records in netflow-records.txt
and demonstrates common security analysis queries.

Usage:
    python3 analyse-netflow.py netflow-records.txt
    python3 analyse-netflow.py --beaconing netflow-records.txt
    python3 analyse-netflow.py --top-talkers netflow-records.txt
    python3 analyse-netflow.py --large-flows 1000000 netflow-records.txt
"""

import re
import sys
from collections import defaultdict, Counter


# ──────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────

FLOW_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"   # date_start
    r",\s+([\d.]+)"                                        # duration
    r",\s+(\w+)"                                           # protocol
    r",\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)"          # src_ip:port -> dst_ip:port
    r",\s+(\S+)"                                           # flags
    r",\s+(\d+)"                                           # tos
    r",\s+(\d+)"                                           # packets
    r",\s+(\d+)"                                           # bytes
    r",\s+(\d+)"                                           # flows
)

def parse_flows(filepath):
    flows = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = FLOW_LINE.match(line)
            if not m:
                continue
            flows.append({
                "start": m.group(1),
                "duration": float(m.group(2)),
                "proto": m.group(3),
                "src_ip": m.group(4),
                "src_port": int(m.group(5)),
                "dst_ip": m.group(6),
                "dst_port": int(m.group(7)),
                "flags": m.group(8),
                "tos": int(m.group(9)),
                "packets": int(m.group(10)),
                "bytes": int(m.group(11)),
                "flows_count": int(m.group(12)),
            })
    return flows


# ──────────────────────────────────────────────────────
# Analysis functions
# ──────────────────────────────────────────────────────

def show_all(flows):
    """Print all flows in a readable table."""
    print(f"{'Start':<24} {'Proto':<5} {'Src IP:Port':<25} {'Dst IP:Port':<25} "
          f"{'Flags':<8} {'Pkts':>6} {'Bytes':>12}")
    print("-" * 110)
    for f in flows:
        src = f"{f['src_ip']}:{f['src_port']}"
        dst = f"{f['dst_ip']}:{f['dst_port']}"
        print(f"{f['start']:<24} {f['proto']:<5} {src:<25} {dst:<25} "
              f"{f['flags']:<8} {f['packets']:>6} {f['bytes']:>12,}")


def top_talkers(flows, n=10):
    """Show top N source IPs by total bytes."""
    src_bytes = Counter()
    for f in flows:
        src_bytes[f["src_ip"]] += f["bytes"]
    print(f"\n=== TOP {n} SOURCE IPs BY BYTES ===")
    for ip, total in src_bytes.most_common(n):
        print(f"  {ip:>18s}: {total:>15,} bytes  ({total/1_048_576:.1f} MB)")


def detect_beaconing(flows, interval_tolerance=5.0, min_connections=3):
    """
    Detect beaconing: a source connecting to the same destination repeatedly
    at roughly equal time intervals with similar byte counts.
    """
    print(f"\n=== BEACONING DETECTION (tolerance={interval_tolerance}s, min_conn={min_connections}) ===")

    # Group flows by (src_ip, dst_ip, dst_port)
    groups = defaultdict(list)
    for f in flows:
        key = (f["src_ip"], f["dst_ip"], f["dst_port"])
        groups[key].append(f)

    found = False
    for (src, dst, dport), group in groups.items():
        if len(group) < min_connections:
            continue

        # Calculate byte variance
        bytes_list = [f["bytes"] for f in group]
        avg_bytes = sum(bytes_list) / len(bytes_list)
        byte_variance = max(bytes_list) - min(bytes_list)

        if byte_variance < avg_bytes * 0.20 and len(group) >= min_connections:
            found = True
            print(f"\n  POSSIBLE BEACON: {src} → {dst}:{dport}")
            print(f"  Connections : {len(group)}")
            print(f"  Bytes/conn  : avg={avg_bytes:.0f}, variance={byte_variance}")
            print(f"  First seen  : {group[0]['start']}")
            print(f"  Last seen   : {group[-1]['start']}")

    if not found:
        print("  No beaconing patterns detected with current thresholds.")


def large_flows(flows, min_bytes=1_000_000):
    """Show flows that transferred more than min_bytes."""
    print(f"\n=== LARGE FLOWS (> {min_bytes:,} bytes) ===")
    large = [f for f in flows if f["bytes"] >= min_bytes]
    if not large:
        print("  No flows exceeding threshold.")
        return
    for f in sorted(large, key=lambda x: x["bytes"], reverse=True):
        src = f"{f['src_ip']}:{f['src_port']}"
        dst = f"{f['dst_ip']}:{f['dst_port']}"
        print(f"  {f['start']}  {f['proto']}  {src} → {dst}")
        print(f"    bytes={f['bytes']:,}  ({f['bytes']/1_048_576:.1f} MB)  "
              f"duration={f['duration']:.1f}s  flags={f['flags']}")


def detect_syn_scan(flows, min_syns=5):
    """Detect port scanning: many SYN-only flows from one source."""
    print(f"\n=== PORT SCAN DETECTION (SYN-only flows, min={min_syns}) ===")
    syn_counts = Counter()
    syn_dports = defaultdict(set)
    for f in flows:
        # SYN-only: flags contain S but not A, and duration ~= 0
        if "S" in f["flags"] and "A" not in f["flags"] and f["duration"] < 0.1:
            syn_counts[f["src_ip"]] += 1
            syn_dports[f["src_ip"]].add(f["dst_port"])

    for ip, count in syn_counts.most_common():
        if count >= min_syns:
            ports = sorted(syn_dports[ip])
            print(f"  POSSIBLE SCAN from {ip}: {count} SYN-only flows")
            print(f"    Ports probed: {ports}")


# ──────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    args = set(sys.argv[1:])
    files = [a for a in sys.argv[1:] if not a.startswith("--") and not a.isdigit()]

    if not files:
        print("Error: provide a netflow records file path")
        sys.exit(1)

    flows = parse_flows(files[0])
    print(f"Loaded {len(flows)} flow records from {files[0]}\n")

    if "--top-talkers" in args:
        top_talkers(flows)
    elif "--beaconing" in args:
        detect_beaconing(flows)
    elif "--large-flows" in args:
        # Find the numeric argument for minimum bytes
        min_b = next((int(a) for a in sys.argv[1:] if a.isdigit()), 1_000_000)
        large_flows(flows, min_b)
    elif "--scan" in args:
        detect_syn_scan(flows)
    else:
        show_all(flows)
        top_talkers(flows)
        detect_beaconing(flows)
        large_flows(flows, 1_000_000)
        detect_syn_scan(flows)
