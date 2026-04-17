#!/usr/bin/env python3
"""
Syslog Format Parser and Analyser
==================================
This script demonstrates how to parse and analyse syslog messages
in both RFC 3164 and RFC 5424 formats.

Usage:
    python3 parse-syslog.py firewall-syslog.log
    python3 parse-syslog.py --stats firewall-syslog.log
"""

import re
import sys
from collections import Counter
from datetime import datetime


# ──────────────────────────────────────────────────────
# Syslog priority decoder
# ──────────────────────────────────────────────────────

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SEVERITY_NAMES = {
    0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
    4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug",
}

def decode_priority(priority_val):
    """Decode a syslog priority value into facility and severity."""
    facility = priority_val >> 3       # Upper bits
    severity = priority_val & 0x07    # Lower 3 bits
    return (
        facility,
        FACILITY_NAMES.get(facility, f"facility_{facility}"),
        severity,
        SEVERITY_NAMES.get(severity, f"severity_{severity}"),
    )


# ──────────────────────────────────────────────────────
# RFC 3164 parser
# ──────────────────────────────────────────────────────

RFC3164_PATTERN = re.compile(
    r"^<(\d+)>"                        # Priority
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+" # Timestamp
    r"(\S+)\s+"                        # Hostname
    r"(\S+?)(?:\[(\d+)\])?:\s+"        # Program [PID]
    r"(.+)$"                           # Message
)

def parse_rfc3164(line):
    """Parse an RFC 3164 syslog message."""
    m = RFC3164_PATTERN.match(line.strip())
    if not m:
        return None
    priority_val = int(m.group(1))
    fac_num, fac_name, sev_num, sev_name = decode_priority(priority_val)
    return {
        "raw": line.strip(),
        "priority": priority_val,
        "facility": fac_name,
        "severity_num": sev_num,
        "severity": sev_name,
        "timestamp": m.group(2),
        "hostname": m.group(3),
        "program": m.group(4),
        "pid": m.group(5),
        "message": m.group(6),
    }


# ──────────────────────────────────────────────────────
# Firewall log field extractor
# ──────────────────────────────────────────────────────

FW_ACTION_PATTERN = re.compile(r"\[FW-(\w+)\]")
FW_FIELDS_PATTERN = re.compile(r"(\w+)=(\S+)")

def extract_fw_fields(message):
    """Extract structured fields from a Linux iptables firewall log message."""
    action_match = FW_ACTION_PATTERN.search(message)
    action = action_match.group(1) if action_match else "UNKNOWN"
    fields = dict(FW_FIELDS_PATTERN.findall(message))
    return {
        "action": action,
        "src_ip": fields.get("SRC", "-"),
        "dst_ip": fields.get("DST", "-"),
        "protocol": fields.get("PROTO", "-"),
        "src_port": fields.get("SPT", "-"),
        "dst_port": fields.get("DPT", "-"),
        "in_iface": fields.get("IN", "-"),
        "ttl": fields.get("TTL", "-"),
    }


# ──────────────────────────────────────────────────────
# Main analysis functions
# ──────────────────────────────────────────────────────

def analyse_log_file(filepath, show_stats=False):
    """Parse and analyse a syslog file."""
    parsed_entries = []
    parse_errors = 0

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            entry = parse_rfc3164(line)
            if entry:
                parsed_entries.append(entry)
            else:
                parse_errors += 1

    print(f"Parsed {len(parsed_entries)} entries ({parse_errors} parse errors)\n")

    if show_stats:
        print_statistics(parsed_entries)
    else:
        print_entries(parsed_entries)


def print_entries(entries):
    """Print each parsed log entry in a readable format."""
    for e in entries:
        fw = extract_fw_fields(e["message"]) if "[FW-" in e["message"] else None
        print(f"[{e['severity']:>13s}] {e['timestamp']}  {e['hostname']}  {e['program']}")
        if fw:
            print(f"  FW: {fw['action']:>5s}  {fw['src_ip']:>15s}:{fw['src_port']:<6s} → "
                  f"{fw['dst_ip']:>15s}:{fw['dst_port']:<6s}  proto={fw['protocol']}")
        else:
            print(f"  MSG: {e['message'][:100]}")
        print()


def print_statistics(entries):
    """Print statistical summary of the log file."""
    print("=== SEVERITY DISTRIBUTION ===")
    severity_counts = Counter(e["severity"] for e in entries)
    for sev, count in sorted(severity_counts.items(),
                              key=lambda x: ["Emergency","Alert","Critical","Error",
                                             "Warning","Notice","Informational","Debug"].index(x[0])
                              if x[0] in ["Emergency","Alert","Critical","Error",
                                          "Warning","Notice","Informational","Debug"] else 99):
        bar = "█" * min(count, 40)
        print(f"  {sev:>13s}: {count:>4d}  {bar}")

    print("\n=== TOP SOURCE IPs (BLOCKED) ===")
    blocked = [extract_fw_fields(e["message"])
               for e in entries if "[FW-BLOCK]" in e["message"]]
    src_counts = Counter(f["src_ip"] for f in blocked if f["src_ip"] != "-")
    for ip, count in src_counts.most_common(10):
        print(f"  {ip:>15s}: {count} blocked packets")

    print("\n=== TOP DESTINATION PORTS (BLOCKED) ===")
    dst_port_counts = Counter(f["dst_port"] for f in blocked if f["dst_port"] != "-")
    for port, count in dst_port_counts.most_common(10):
        print(f"  Port {port:>6s}: {count} blocked packets")

    print("\n=== AUTHENTICATION EVENTS ===")
    for e in entries:
        if "sshd" in e["program"] or "sudo" in e["program"]:
            print(f"  [{e['severity']}] {e['timestamp']} {e['hostname']}: {e['message'][:120]}")


# ──────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nExample: python3 parse-syslog.py firewall-syslog.log")
        print("         python3 parse-syslog.py --stats firewall-syslog.log")
        sys.exit(1)

    show_stats = "--stats" in sys.argv
    logfile = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not logfile:
        print("Error: provide a log file path")
        sys.exit(1)

    analyse_log_file(logfile[0], show_stats=show_stats)
