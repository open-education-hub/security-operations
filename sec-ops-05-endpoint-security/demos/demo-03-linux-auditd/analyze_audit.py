#!/usr/bin/env python3
"""
analyze_audit.py — Linux Audit Log Analyzer (Demo 03)
Parses audit.log format and detects suspicious patterns.
"""
import re
import sys
import argparse
from collections import defaultdict

AUDIT_RULES_KEYS = {
    "exec_64bit":    "Program execution (64-bit)",
    "exec_32bit":    "Program execution (32-bit)",
    "identity":      "Identity/account change",
    "sudoers":       "Sudoers modification",
    "privesc":       "Privilege escalation attempt",
    "privesc_syscall": "Privilege escalation (setuid/setgid)",
    "cron":          "Cron job modification",
    "ssh_keys":      "SSH key modification",
    "sshd_config":   "SSH config change",
    "network_connect": "Network connection",
    "shadow_read":   "Shadow password file read",
    "passwd_read":   "Passwd file read",
    "systemd_unit":  "Systemd unit file change",
}


def parse_audit_record(line):
    """Parse a single audit log line into a dict."""
    record = {}
    # Extract type
    m = re.match(r'type=(\S+)', line)
    if m:
        record['type'] = m.group(1)
    # Extract timestamp and sequence
    m = re.search(r'msg=audit\((\d+\.\d+):(\d+)\)', line)
    if m:
        record['timestamp'] = float(m.group(1))
        record['sequence'] = int(m.group(2))
    # Extract all key=value pairs (quoted and unquoted)
    pairs = re.findall(r'(\w+)=(?:"([^"]*)"|(\'[^\']*\')|(\S+))', line)
    for pair in pairs:
        key = pair[0]
        value = pair[1] or pair[2].strip("'") or pair[3]
        record[key] = value
    # Extract msg= field specially for USER_AUTH/USER_LOGIN
    m = re.search(r"msg='(.+)'", line)
    if m:
        record['msg_content'] = m.group(1)
    record['raw'] = line.strip()
    return record


def load_audit_log(filepath):
    """Load and group audit records by sequence number."""
    try:
        with open(filepath) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    records = []
    for line in lines:
        line = line.strip()
        if line:
            records.append(parse_audit_record(line))

    # Group by sequence number for correlated events
    groups = defaultdict(list)
    for r in records:
        seq = r.get('sequence', 0)
        groups[seq].append(r)

    return records, groups


def display_summary(records):
    print(f"\n{'='*72}")
    print(f"  AUDIT LOG SUMMARY")
    print(f"{'='*72}")
    print(f"  Total records: {len(records)}")

    type_counts = defaultdict(int)
    key_counts = defaultdict(int)
    for r in records:
        type_counts[r.get('type', 'UNKNOWN')] += 1
        key = r.get('key', '').strip('"')
        if key and key != '(null)':
            key_counts[key] += 1

    print(f"\n  Record Types:")
    for rtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {rtype:<30} {count}")

    print(f"\n  Triggered Rule Keys:")
    for key, count in sorted(key_counts.items(), key=lambda x: -x[1]):
        desc = AUDIT_RULES_KEYS.get(key, "")
        print(f"    {key:<30} {count:>3}  — {desc}")


def detect_suspicious(records, groups):
    print(f"\n{'='*72}")
    print(f"  SUSPICIOUS ACTIVITY DETECTION")
    print(f"{'='*72}\n")

    findings = []

    # Brute force: multiple failed auths from same host
    failed_auth_hosts = defaultdict(list)
    for r in records:
        if r.get('type') in ('USER_AUTH', 'USER_LOGIN'):
            content = r.get('msg_content', '')
            if 'res=failed' in content:
                m = re.search(r'hostname=(\S+)', content)
                if m:
                    host = m.group(1)
                    acct_m = re.search(r'acct="([^"]+)"', content)
                    acct = acct_m.group(1) if acct_m else '?'
                    failed_auth_hosts[host].append(acct)

    for host, accounts in failed_auth_hosts.items():
        if len(accounts) >= 3:
            findings.append({
                "severity": "HIGH",
                "title": f"SSH Brute Force / Password Spray from {host}",
                "detail": f"  {len(accounts)} failed auth attempts: accounts tried = {', '.join(set(accounts))}",
                "mitre": "T1110.001 / T1110.003",
            })

    # Detect sudo to bash (shell breakout)
    for seq, group in groups.items():
        execve = next((r for r in group if r.get('type') == 'EXECVE'), None)
        syscall = next((r for r in group if r.get('type') == 'SYSCALL'), None)
        if execve and syscall:
            args = [execve.get(f'a{i}', '') for i in range(int(execve.get('argc', 0)))]
            cmd = ' '.join(args)
            if 'sudo' in cmd and ('bash' in cmd or 'sh' in cmd):
                auid = syscall.get('auid', '?')
                findings.append({
                    "severity": "HIGH",
                    "title": "Sudo to Shell Detected (Potential Breakout)",
                    "detail": f"  auid={auid} ran: {cmd}\n  euid={syscall.get('euid','?')} (effective root)",
                    "mitre": "T1548.003",
                })

    # Detect curl|bash patterns
    for seq, group in groups.items():
        execve = next((r for r in group if r.get('type') == 'EXECVE'), None)
        syscall = next((r for r in group if r.get('type') == 'SYSCALL'), None)
        if execve:
            args = [execve.get(f'a{i}', '') for i in range(min(int(execve.get('argc', 0)), 5))]
            cmd = ' '.join(args)
            if ('curl' in cmd or 'wget' in cmd) and ('bash' in cmd or 'sh' in cmd or '|' in cmd):
                auid = syscall.get('auid', '?') if syscall else '?'
                findings.append({
                    "severity": "CRITICAL",
                    "title": "Remote Script Execution (curl|bash Pattern)",
                    "detail": f"  auid={auid} ran: {cmd}",
                    "mitre": "T1059.004",
                })

    # Detect user account creation
    for seq, group in groups.items():
        execve = next((r for r in group if r.get('type') == 'EXECVE'), None)
        syscall = next((r for r in group if r.get('type') == 'SYSCALL'), None)
        if execve:
            args = [execve.get(f'a{i}', '') for i in range(int(execve.get('argc', 0)))]
            cmd = ' '.join(args)
            if 'useradd' in cmd or 'adduser' in cmd:
                auid = syscall.get('auid', '?') if syscall else '?'
                findings.append({
                    "severity": "CRITICAL",
                    "title": "Backdoor User Account Created",
                    "detail": f"  auid={auid} ran: {cmd}",
                    "mitre": "T1136.001",
                })

    # Detect SSH key modification
    for seq, group in groups.items():
        paths = [r for r in group if r.get('type') == 'PATH']
        syscall = next((r for r in group if r.get('type') == 'SYSCALL'), None)
        for path_r in paths:
            pname = path_r.get('name', '')
            if 'authorized_keys' in pname:
                auid = syscall.get('auid', '?') if syscall else '?'
                findings.append({
                    "severity": "CRITICAL",
                    "title": "SSH Authorized Keys Modified",
                    "detail": f"  auid={auid} modified: {pname}",
                    "mitre": "T1098.004",
                })

    # Detect cron modification
    for seq, group in groups.items():
        key_vals = [r.get('key', '').strip('"') for r in group]
        syscall = next((r for r in group if r.get('type') == 'SYSCALL'), None)
        execve = next((r for r in group if r.get('type') == 'EXECVE'), None)
        if 'cron' in key_vals and syscall:
            auid = syscall.get('auid', '?')
            cmd = ''
            if execve:
                args = [execve.get(f'a{i}', '') for i in range(int(execve.get('argc', 0)))]
                cmd = ' '.join(args)
            findings.append({
                "severity": "HIGH",
                "title": "Cron Job Persistence Detected",
                "detail": f"  auid={auid} modified cron: {cmd}",
                "mitre": "T1053.003",
            })

    if not findings:
        print("  No suspicious activity detected.\n")
        return

    for f in findings:
        sev = f['severity']
        icon = {"CRITICAL": "!!! CRITICAL", "HIGH": " !! HIGH    ", "MEDIUM": "  ! MEDIUM  "}.get(sev, "    INFO    ")
        print(f"  {icon} | {f['title']}")
        print(f"{f['detail']}")
        print(f"           MITRE ATT&CK: {f['mitre']}")
        print()

    crit = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    print(f"  Total findings: {len(findings)} (CRITICAL: {crit}, HIGH: {high})")


def show_executions(records, groups):
    """Show all command executions."""
    print(f"\n{'='*72}")
    print(f"  COMMAND EXECUTION LOG")
    print(f"{'='*72}\n")
    for seq in sorted(groups.keys()):
        group = groups[seq]
        execve = next((r for r in group if r.get('type') == 'EXECVE'), None)
        syscall = next((r for r in group if r.get('type') == 'SYSCALL'), None)
        if execve and syscall:
            argc = int(execve.get('argc', 0))
            args = [execve.get(f'a{i}', '') for i in range(min(argc, 6))]
            cmd = ' '.join(args)
            auid = syscall.get('auid', '?')
            uid = syscall.get('uid', '?')
            euid = syscall.get('euid', '?')
            exe = syscall.get('exe', '?').strip('"')
            key = syscall.get('key', '').strip('"')
            print(f"  auid={auid} uid={uid} euid={euid} key={key}")
            print(f"  exe={exe}")
            print(f"  cmd: {cmd[:100]}")
            print()


def main():
    parser = argparse.ArgumentParser(description="Audit Log Analyzer — Demo 03")
    parser.add_argument("--file", default="audit.log.sample")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--detect", action="store_true")
    parser.add_argument("--executions", action="store_true")
    args = parser.parse_args()

    records, groups = load_audit_log(args.file)
    print(f"\n[+] Loaded {len(records)} audit records from {args.file}")
    print(f"[+] Grouped into {len(groups)} correlated event sets")

    if args.summary or not (args.detect or args.executions):
        display_summary(records)

    if args.executions:
        show_executions(records, groups)

    if args.detect or not (args.summary or args.executions):
        detect_suspicious(records, groups)


if __name__ == "__main__":
    main()
