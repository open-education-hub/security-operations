#!/usr/bin/env python3
"""Network flow analysis for forensic drill."""
import json, argparse
from datetime import datetime

FLOWS = "/forensics/evidence/netflow.json"

def load():
    with open(FLOWS) as f: return json.load(f)

def fmt_bytes(n):
    if n > 1_000_000_000: return f"{n/1_000_000_000:.2f} GB"
    if n > 1_000_000: return f"{n/1_000_000:.2f} MB"
    if n > 1_000: return f"{n/1_000:.2f} KB"
    return f"{n} B"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--summary", action="store_true")
    p.add_argument("--during", metavar="START,END")
    args = p.parse_args()
    flows = load()

    if args.during:
        s, e = args.during.split(",")
        start = datetime.fromisoformat(s.replace("Z","+00:00"))
        end   = datetime.fromisoformat(e.replace("Z","+00:00"))
        flows = [f for f in flows if start <= datetime.fromisoformat(f['ts'].replace("Z","+00:00")) <= end]

    print(f"\n{'='*70}")
    print(f"NETWORK FLOWS ({len(flows)} records)")
    print(f"{'='*70}")
    total_out = 0
    for f in flows:
        out = f.get('bytes_out',0)
        total_out += out
        note = f" ← {f['note']}" if f.get('note') else ""
        print(f"  {f['ts']}  {f['src']} → {f['dst']}")
        print(f"    Out: {fmt_bytes(out)}  In: {fmt_bytes(f.get('bytes_in',0))}  Proto: {f['proto']}{note}")
        print()

    if args.summary:
        print(f"\nTotal outbound: {fmt_bytes(total_out)}")
        dsts = {}
        for f in flows:
            dst = f['dst'].rsplit(':',1)[0]
            dsts[dst] = dsts.get(dst,0) + f.get('bytes_out',0)
        print("Top destinations:")
        for dst, sz in sorted(dsts.items(), key=lambda x: -x[1]):
            print(f"  {dst}: {fmt_bytes(sz)}")

if __name__ == "__main__":
    main()
