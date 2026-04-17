#!/usr/bin/env python3
"""Memory forensics analysis for forensic drill."""
import json, sys, argparse

SNAP = "/forensics/evidence/memory_snapshot.json"

def load():
    with open(SNAP) as f: return json.load(f)

def parse_args():
    p = argparse.ArgumentParser(description="Memory snapshot analysis")
    p.add_argument("--processes", action="store_true")
    p.add_argument("--network-connections", action="store_true")
    p.add_argument("--open-files", action="store_true")
    p.add_argument("--suspicious", action="store_true")
    p.add_argument("--cmdline", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    snap = load()
    procs = snap.get("processes", [])
    conns = snap.get("network_connections", [])
    files = snap.get("open_files", [])

    if args.processes or not any(vars(args).values()):
        print(f"\n{'='*60}")
        print(f"RUNNING PROCESSES at {snap['collection_time']}")
        print(f"{'='*60}")
        print(f"{'PID':<8} {'PPID':<8} {'User':<12} {'Command'}")
        print("-" * 60)
        for p in procs:
            deleted = " [DELETED EXE]" if p.get('deleted_exe') else ""
            note = f" ← {p['note']}" if p.get('note') else ""
            print(f"{p['pid']:<8} {p.get('ppid','-'):<8} {p.get('user','?'):<12} {p['cmd']}{deleted}{note}")

    if args.network_connections:
        print(f"\n{'='*60}")
        print(f"NETWORK CONNECTIONS")
        print(f"{'='*60}")
        for c in conns:
            note = f" ← {c['note']}" if c.get('note') else ""
            print(f"  PID {c['pid']}: {c['src']} → {c['dst']} [{c['state']}]{note}")

    if args.open_files:
        print(f"\n{'='*60}")
        print(f"OPEN FILES (selected)")
        print(f"{'='*60}")
        for f in files:
            note = f" ← {f['note']}" if f.get('note') else ""
            print(f"  PID {f['pid']} fd/{f['fd']}: {f['path']}{note}")

    if args.suspicious:
        print(f"\n{'='*60}")
        print(f"SUSPICIOUS INDICATORS")
        print(f"{'='*60}")
        for p in procs:
            if p.get('deleted_exe'):
                print(f"  [!] PID {p['pid']}: running from DELETED binary — {p['cmd']}")
        for c in conns:
            if c.get('note') and 'reverse' in c['note'].lower():
                print(f"  [!] Residual reverse shell connection: {c['src']} → {c['dst']}")
        print()

    if args.cmdline:
        print(f"\n{'='*60}")
        print(f"PROCESS COMMAND LINES")
        print(f"{'='*60}")
        for p in procs:
            print(f"  PID {p['pid']} [{p.get('user','?')}]: {p['cmd']}")

if __name__ == "__main__":
    main()
