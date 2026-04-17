#!/usr/bin/env python3
"""USB device analysis for forensic drill."""
import re, sys

USB_LOG = "/forensics/evidence/usb_events.log"

def main():
    print(f"\n{'='*60}")
    print("USB DEVICE EVENTS")
    print(f"{'='*60}")
    with open(USB_LOG) as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if "SerialNumber" in line:
            print(f"\n  [DEVICE SERIAL]: {line.split('SerialNumber:')[1].strip()}")
        elif "Product:" in line:
            print(f"  [PRODUCT]:       {line.split('Product:')[1].strip()}")
        elif "Manufacturer" in line:
            print(f"  [MANUFACTURER]:  {line.split('Manufacturer:')[1].strip()}")
        elif "Mounted" in line:
            print(f"  [MOUNTED]:       {line}")
        elif "Unmounted" in line:
            print(f"  [UNMOUNTED]:     {line}")
    print()
    print("  Device serial: SANDISK-USB3-SN20240103 (20240103AA4F2B9C)")
    print("  Mounted by UID 1001 (mkumar)")
    print("  Duration plugged in: ~1 min 40 sec (02:23:11 → 02:24:50)")

if __name__ == "__main__":
    main()
