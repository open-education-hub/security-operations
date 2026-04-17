#!/usr/bin/env python3
"""
UNIX Timestamp Converter and Zeek Log Analyser
================================================
This script helps with the Advanced Drill 01 (Network Forensics).

It converts UNIX timestamps to human-readable UTC datetimes,
and processes the artefact logs provided in the drill scenario
to assist with timeline reconstruction.

Usage:
    python3 analyse-forensics.py                  # Process built-in drill artefacts
    python3 analyse-forensics.py --convert TS     # Convert a single timestamp
    python3 analyse-forensics.py --timeline       # Print full sorted timeline

Example:
    python3 analyse-forensics.py --convert 1705363200
    python3 analyse-forensics.py --timeline
"""

import sys
from datetime import datetime, timezone


# ──────────────────────────────────────────────────────
# Timestamp utilities
# ──────────────────────────────────────────────────────

def ts_to_utc(unix_ts: float) -> str:
    """Convert a UNIX timestamp to a human-readable UTC string."""
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def duration_fmt(seconds: float) -> str:
    """Format a duration in seconds to HH:MM:SS or minutes."""
    if seconds < 0:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}min ({seconds:.0f}s)"
    return f"{seconds/3600:.2f}hr ({seconds:.0f}s)"


def bytes_fmt(b: int) -> str:
    """Format byte counts to human-readable."""
    if b < 1024:
        return f"{b} B"
    if b < 1_048_576:
        return f"{b/1024:.1f} KB"
    if b < 1_073_741_824:
        return f"{b/1_048_576:.1f} MB"
    return f"{b/1_073_741_824:.2f} GB"


# ──────────────────────────────────────────────────────
# Drill 01 artefact data (from the drill README)
# ──────────────────────────────────────────────────────

# conn.log entries (ts, uid, src_ip, src_port, dst_ip, dst_port,
#                   proto, service, duration, orig_bytes, resp_bytes, state)
CONN_ENTRIES = [
    # Initial exploitation phase — attacker probing web server
    (1705363200.00, "CaA1B2C3D4E5", "185.220.101.35", 49234, "10.0.1.10", 443,
     "tcp", "ssl", 0.23, 1890, 512, "SF"),
    (1705363220.00, "CaF6G7H8I9J0", "185.220.101.35", 38291, "10.0.1.10", 443,
     "tcp", "ssl", 0.21, 1905, 509, "SF"),
    (1705363240.00, "CaK1L2M3N4O5", "185.220.101.35", 29384, "10.0.1.10", 443,
     "tcp", "ssl", 0.24, 1893, 511, "SF"),
    # ... pattern continues every 20s for 45 minutes (abbreviated)
    (1705365870.00, "CbZ9Y8X7W6V5", "185.220.101.35", 11234, "10.0.1.10", 443,
     "tcp", "ssl", 0.22, 1901, 510, "SF"),
    # [90-minute gap]
    # Reverse shell — victim calls attacker on port 4444
    (1705372200.00, "CcA1B2C3D4E5", "10.0.1.10", 56234, "185.220.101.35", 4444,
     "tcp", "-", 1843.22, 24891034, 512, "SF"),
    # DNS reconnaissance
    (1705372200.00, "CcB2C3D4E5F6", "10.0.1.10", 56235, "8.8.8.8", 53,
     "udp", "dns", 0.01, 78, 94, "SF"),
    # Lateral movement via SMB
    (1705372450.00, "CdA1B2C3D4E5", "10.0.1.10", 34521, "10.10.1.5", 445,
     "tcp", "smb", 12.44, 45234, 892345, "SF"),
    (1705372455.00, "CdB2C3D4E5F6", "10.0.1.10", 34522, "10.10.1.6", 445,
     "tcp", "smb", 9.23, 44123, 754321, "SF"),
    (1705372460.00, "CdC3D4E5F6G7", "10.0.1.10", 34523, "10.10.1.7", 445,
     "tcp", "smb", 11.01, 43891, 823455, "SF"),
    # SSH scanning (S0 = SYN sent, no response)
    (1705372465.00, "CdD4E5F6G7H8", "10.0.1.10", 34524, "10.10.1.20", 22,
     "tcp", "-", 0.00, 74, 0, "S0"),
    (1705372466.00, "CdE5F6G7H8I9", "10.0.1.10", 34525, "10.10.1.21", 22,
     "tcp", "-", 0.00, 74, 0, "S0"),
    # ... 22 more S0 connections to 10.10.1.x:22
    # RDP lateral movement to admin workstation
    (1705372890.00, "CeA1B2C3D4E5", "10.0.1.10", 38291, "10.10.5.100", 3389,
     "tcp", "rdp", 7234.01, 891234034, 234891034, "SF"),
    # Exfiltration — two simultaneous streams (from compromised workstation)
    (1705380124.00, "CfA1B2C3D4E5", "10.10.5.100", 45123, "52.1.2.100", 443,
     "tcp", "ssl", 3601.44, 4198305120, 512, "SF"),
    (1705380134.00, "CfB2C3D4E5F6", "10.10.5.100", 45124, "185.220.101.35", 443,
     "tcp", "ssl", 3599.12, 4201098432, 509, "SF"),
]

# dns.log entries (ts, uid, src_ip, dst_ip, query, qtype, rcode, answer)
DNS_ENTRIES = [
    (1705372201.00, "CcB2C3D4E5F6", "10.0.1.10", "8.8.8.8",
     "whoami.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372205.00, "CcC3D4E5F6G7", "10.0.1.10", "8.8.8.8",
     "dc01.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372210.00, "CcD4E5F6G7H8", "10.0.1.10", "8.8.8.8",
     "fileserver01.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372215.00, "CcE5F6G7H8I9", "10.0.1.10", "8.8.8.8",
     "mail.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372220.00, "CcF6G7H8I9J0", "10.0.1.10", "8.8.8.8",
     "backup.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372225.00, "CcG7H8I9J0K1", "10.0.1.10", "8.8.8.8",
     "payroll.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372230.00, "CcH8I9J0K1L2", "10.0.1.10", "8.8.8.8",
     "trading.internal.volta-finance.com", "A", "NXDOMAIN", None),
    (1705372235.00, "CcI9J0K1L2M3", "10.0.1.10", "8.8.8.8",
     "bRt7kXpY9mNq2wVs4uLe6iOa1dFh8jCg.relay.stealdata.pw", "TXT", "NOERROR",
     "STAGE2:download:http://185.220.101.35/implant.bin"),
]

# http.log entries (ts, uid, src_ip, dst_ip, method, host, uri, status, ua, resp_bytes)
HTTP_ENTRIES = [
    (1705372245.00, "CgA1B2C3D4E5", "10.0.1.10", "185.220.101.35",
     "GET", "185.220.101.35", "/implant.bin", 200, "-", 2408960),
    (1705372250.00, "CgB2C3D4E5F6", "10.0.1.10", "185.220.101.35",
     "GET", "185.220.101.35", "/stage3.ps1", 200, "-", 14336),
    (1705372920.00, "ChA1B2C3D4E5", "10.10.5.100", "52.1.2.100",
     "POST", "backup-q4.s3.amazonaws.com", "/uploads/vault.7z", 200,
     "python-requests/2.31", 156),
]


# ──────────────────────────────────────────────────────
# Analysis output functions
# ──────────────────────────────────────────────────────

def print_timestamp_reference():
    """Print all timestamps from the drill with UTC conversions."""
    print("=" * 70)
    print("TIMESTAMP REFERENCE — DRILL 01 (VOLTA FINANCIAL)")
    print("=" * 70)

    all_ts = set()
    for entry in CONN_ENTRIES:
        all_ts.add(entry[0])
        if entry[9] > 0:  # has duration
            all_ts.add(entry[0] + entry[8])
    for entry in DNS_ENTRIES:
        all_ts.add(entry[0])
    for entry in HTTP_ENTRIES:
        all_ts.add(entry[0])

    print(f"\n{'UNIX Timestamp':<18} {'UTC Datetime':<25} {'Note'}")
    print("-" * 70)
    for ts in sorted(all_ts):
        note = ""
        if ts == 1705363200.00:
            note = "← First attacker connection"
        elif ts == 1705365870.00:
            note = "← Last exploitation-phase connection"
        elif ts == 1705372200.00:
            note = "← Reverse shell + DNS recon begins"
        elif ts == 1705372450.00:
            note = "← SMB lateral movement begins"
        elif ts == 1705372890.00:
            note = "← RDP lateral movement to workstation"
        elif ts == 1705380124.00:
            note = "← Exfiltration begins"
        print(f"{ts:<18.2f} {ts_to_utc(ts):<25} {note}")

    # Key gaps
    print(f"\nKey time gaps:")
    print(f"  Exploitation phase:    {ts_to_utc(1705363200)} to {ts_to_utc(1705365870)}")
    print(f"  Gap duration:          {duration_fmt(1705372200 - 1705365870)}")
    print(f"  Active intrusion:      {ts_to_utc(1705372200)} to {ts_to_utc(1705380124 + 3601)}")
    print(f"  Intrusion duration:    {duration_fmt(1705380124 + 3601 - 1705372200)}")


def print_timeline():
    """Print a sorted timeline of all events."""
    print("\n" + "=" * 70)
    print("SORTED ATTACK TIMELINE")
    print("=" * 70)

    events = []

    for c in CONN_ENTRIES:
        ts, uid, src, sport, dst, dport, proto, svc, dur, ob, rb, state = c
        events.append((ts, f"CONN  {src}:{sport} → {dst}:{dport} "
                          f"proto={proto} service={svc} "
                          f"state={state} out={bytes_fmt(ob)} in={bytes_fmt(rb)} "
                          f"dur={duration_fmt(dur)}"))

    for d in DNS_ENTRIES:
        ts, uid, src, dst, query, qtype, rcode, answer = d
        ans = f" → '{answer}'" if answer else ""
        events.append((ts, f"DNS   {src} → {dst} query={query} type={qtype} "
                          f"rcode={rcode}{ans}"))

    for h in HTTP_ENTRIES:
        ts, uid, src, dst, method, host, uri, status, ua, resp_size = h
        events.append((ts, f"HTTP  {src} → {host} {method} {uri} "
                          f"status={status} size={bytes_fmt(resp_size)} "
                          f"ua={ua}"))

    print(f"\n{'UTC Time':<26} {'Event'}")
    print("-" * 70)
    for ts, event in sorted(events):
        print(f"{ts_to_utc(ts):<26} {event}")


def print_scope_summary():
    """Print a summary of affected hosts."""
    print("\n" + "=" * 70)
    print("AFFECTED HOSTS SUMMARY")
    print("=" * 70)

    affected = {
        "10.0.1.10": "COMPROMISED — DMZ web server (initial entry point, reverse shell, lateral movement source)",
        "10.10.1.5":  "ACCESSED — Internal file server (SMB read, ~892 KB files transferred)",
        "10.10.1.6":  "ACCESSED — Internal file server (SMB read, ~754 KB files transferred)",
        "10.10.1.7":  "ACCESSED — Internal file server (SMB read, ~823 KB files transferred)",
        "10.10.5.100": "COMPROMISED — Admin/finance workstation (RDP session 2hr, exfiltration source)",
    }
    scanned_range = "10.10.1.20–10.10.1.43"

    for ip, desc in affected.items():
        print(f"\n  {ip}")
        print(f"  {desc}")

    print(f"\n  {scanned_range}")
    print(f"  SCANNED — 24 hosts probed via SSH (S0 state — likely unreachable)")

    print(f"\nExfiltration destinations:")
    print(f"  52.1.2.100  (backup-q4.s3.amazonaws.com) — {bytes_fmt(4198305120)} sent")
    print(f"  185.220.101.35 (attacker Tor exit node)   — {bytes_fmt(4201098432)} sent")
    print(f"  Total exfiltrated: ~{bytes_fmt(4198305120 + 4201098432)}")


# ──────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────

if __name__ == "__main__":
    args = set(sys.argv[1:])

    if "--convert" in args:
        idx = sys.argv.index("--convert")
        if idx + 1 < len(sys.argv):
            try:
                ts = float(sys.argv[idx + 1])
                print(f"{ts} → {ts_to_utc(ts)}")
            except ValueError:
                print(f"Error: '{sys.argv[idx + 1]}' is not a valid timestamp")
        else:
            print("Error: --convert requires a timestamp argument")
        sys.exit(0)

    if "--timeline" in args:
        print_timestamp_reference()
        print_timeline()
        sys.exit(0)

    # Default: run full analysis
    print_timestamp_reference()
    print_timeline()
    print_scope_summary()

    print("\n" + "=" * 70)
    print("Use this data to answer drill questions A1, A2, A3, B1, B2, B3, C1-C3")
    print("Reference the drill README for the full questions.")
