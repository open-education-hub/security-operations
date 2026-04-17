#!/usr/bin/env python3
"""Timeline analysis tool for forensic drill."""
import json, sys, argparse, os
from datetime import datetime

EVIDENCE = "/forensics/evidence/disk_timeline.json"

def load():
    with open(EVIDENCE) as f:
        return json.load(f)

def parse_args():
    p = argparse.ArgumentParser(description="Filesystem timeline analysis")
    p.add_argument("--summary", action="store_true", help="Show timeline summary")
    p.add_argument("--path", help="Filter by path prefix")
    p.add_argument("--user", help="Filter by username")
    p.add_argument("--window", help="Time window: START,END (ISO format)")
    p.add_argument("--size-gt", type=int, help="Show files larger than N bytes")
    p.add_argument("--action", help="Filter by action type")
    return p.parse_args()

def fmt_size(n):
    if n is None: return "-"
    if n > 1_000_000_000: return f"{n/1_000_000_000:.1f} GB"
    if n > 1_000_000: return f"{n/1_000_000:.1f} MB"
    if n > 1_000: return f"{n/1_000:.1f} KB"
    return f"{n} B"

def main():
    args = parse_args()
    events = load()

    if args.window:
        start_s, end_s = args.window.split(",")
        start = datetime.fromisoformat(start_s.replace("Z","+00:00"))
        end   = datetime.fromisoformat(end_s.replace("Z","+00:00"))
        events = [e for e in events if start <= datetime.fromisoformat(e['ts'].replace("Z","+00:00")) <= end]

    if args.path:
        events = [e for e in events if e.get('path') and e['path'].startswith(args.path)]

    if args.user:
        events = [e for e in events if e.get('user') == args.user]

    if args.action:
        events = [e for e in events if e.get('action') == args.action]

    if args.size_gt:
        events = [e for e in events if e.get('size') and e['size'] > args.size_gt]

    if args.summary:
        print(f"\n{'='*70}")
        print(f"DISK TIMELINE SUMMARY — {len(events)} events")
        print(f"{'='*70}")
        actions = {}
        for e in events:
            a = e.get('action','?')
            actions[a] = actions.get(a, 0) + 1
        for a, c in sorted(actions.items()):
            print(f"  {a:20s}: {c}")
        print(f"\nTime range: {events[0]['ts']} → {events[-1]['ts']}")
        print()

    print(f"\n{'Timestamp':<25} {'Action':<15} {'User':<10} {'Size':<10} Path/Detail")
    print("-" * 90)
    for e in events:
        path = e.get('path') or e.get('detail','')
        note = f" [{e['note']}]" if e.get('note') else ""
        print(f"{e['ts']:<25} {e['action']:<15} {e.get('user',''):<10} {fmt_size(e.get('size')):<10} {path}{note}")

if __name__ == "__main__":
    main()
