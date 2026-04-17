#!/usr/bin/env python3
"""Deleted file analysis for forensic drill."""
import json, argparse

DELETED = "/forensics/evidence/deleted_files.json"

def load():
    with open(DELETED) as f: return json.load(f)

def fmt_size(n):
    if n > 1_000_000_000: return f"{n/1_000_000_000:.2f} GB"
    if n > 1_000_000: return f"{n/1_000_000:.2f} MB"
    return f"{n} B"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--list", action="store_true")
    p.add_argument("--details", metavar="FILENAME")
    args = p.parse_args()
    items = load()

    if args.list:
        print(f"\n{'='*70}")
        print("DELETED FILES (inode metadata recovered from filesystem journal)")
        print(f"{'='*70}")
        print(f"{'Filename':<45} {'Size':<12} {'Deleted':<25} Method")
        print("-" * 70)
        for i in items:
            print(f"{i['filename']:<45} {fmt_size(i['size']):<12} {i['deleted']:<25} {i['method']}")

    if args.details:
        for i in items:
            if args.details in i['filename']:
                print(f"\n{'='*60}")
                print(f"DELETED FILE DETAILS: {i['filename']}")
                print(f"{'='*60}")
                print(f"  Full path:    {i['path']}")
                print(f"  Inode:        {i['inode']}")
                print(f"  Size:         {fmt_size(i['size'])} ({i['size']:,} bytes)")
                print(f"  Owner UID:    {i['uid']}")
                print(f"  Created:      {i['created']}")
                print(f"  Deleted:      {i['deleted']}")
                print(f"  Delete method:{i['method']}")
                print(f"  Note:         {i['note']}")
                if i.get('tar_contents'):
                    print(f"\n  Archive Contents (from audit log tar command args):")
                    for c in i['tar_contents']:
                        print(f"    - {c}")
                print()

if __name__ == "__main__":
    main()
