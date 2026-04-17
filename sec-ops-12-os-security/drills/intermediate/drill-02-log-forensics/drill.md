# Drill 02 (Intermediate) — Log Forensics

**Level:** Intermediate

**Estimated time:** 45 minutes

---

## Objective

Reconstruct a security incident entirely from log evidence.
Using auth.log, auditd logs, and syslog, determine the full sequence of attacker actions and identify all compromised accounts.

---

## Setup

```console
cd drills/intermediate/drill-02-log-forensics
docker compose up --build
docker compose exec log-forensics bash
```

Pre-populated log files are at `/var/log/forensics/`.
Do not modify these files.

---

## Scenario

Your organization's internal HR portal server was flagged by network monitoring for sending unexpected outbound traffic to an external IP.
You have been given access to the system's log files from the past 72 hours.
No EDR agent was running — logs are your only evidence.

**Your mission:** Reconstruct exactly what happened.

---

## Task 1: Establish a Baseline

Before diving into the attack, understand what is "normal" for this server:

```console
# What services are logging?
ls /var/log/forensics/

# How many successful SSH logins occurred in the 72-hour window?
grep "Accepted" /var/log/forensics/auth.log | wc -l

# Who are the normal users logging in?
grep "Accepted" /var/log/forensics/auth.log | awk '{print $9}' | sort | uniq -c
```

---

## Task 2: Identify Anomalous Authentication

```bash
# Failed login attempts by source IP
grep "Failed password" /var/log/forensics/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn

# Any logins from unusual source IPs?
grep "Accepted" /var/log/forensics/auth.log | \
  awk '{print $9, $11}' | sort | uniq

# Any logins at unusual hours (e.g., 02:00-05:00)?
grep "Accepted" /var/log/forensics/auth.log | \
  awk '$3 >= "02:00" && $3 <= "05:00" {print}'
```

**Questions:**

1. Which IP was performing brute-force activity?
1. Which account was compromised?
1. At what time did the successful login occur?

---

## Task 3: Trace Post-Compromise Activity

After identifying the initial compromise timestamp, trace what happened next:

```console
# All activity from the compromised user after the suspicious login
# (replace TIME and USER with your findings from Task 2)
awk -v start="TIME" '$3 > start && /USER/' /var/log/forensics/auth.log

# Sudo commands executed
grep "sudo.*COMMAND" /var/log/forensics/auth.log | grep -v "^#"

# New accounts created
grep "useradd\|adduser\|new user" /var/log/forensics/auth.log
```

---

## Task 4: auditd Log Analysis

```bash
# File writes to sensitive locations
ausearch -f /etc/passwd --input-logs /var/log/forensics/audit.log 2>/dev/null

# Privilege escalation events
ausearch -k privileged-sudo --input-logs /var/log/forensics/audit.log 2>/dev/null

# Execution of unusual binaries
ausearch -k exec --input-logs /var/log/forensics/audit.log 2>/dev/null | \
  grep -E "/tmp|/dev/shm|/var/tmp"

# Generate a summary report
aureport --summary --input-logs /var/log/forensics/audit.log 2>/dev/null
```

---

## Task 5: Syslog Analysis

```console
# Check syslog for unusual activity
grep -E "cron|systemd|kernel|segfault" /var/log/forensics/syslog | \
  tail -50

# Cron job changes
grep -E "cron|CRON" /var/log/forensics/syslog | grep -v "CMD"

# Network-related system events
grep -E "iptables|nftables|firewall" /var/log/forensics/syslog
```

---

## Task 6: Build the Full Timeline

Using all three log sources, construct a complete timeline:

```text
[timestamp]  [source]  [event]  [significance]
```

Your timeline must cover:

1. Initial brute-force activity
1. First successful login
1. Every command or system change made by the attacker
1. Persistence mechanism installation
1. Outbound connection initiation

---

## Task 7: Produce an IOC Report

List all indicators of compromise in a structured format:

| IOC Type | Value | First Seen | Context |
|----------|-------|------------|---------|
| IP Address | ? | ? | Brute-force source |
| Username | ? | ? | Compromised account |
| File Path | ? | ? | Malware dropped |
| Process | ? | ? | Reverse shell |

---

## Deliverable

A complete incident log report:

1. Attack timeline (Task 6)
1. IOC table (Task 7)
1. Root cause analysis (1 paragraph)
1. Recommended detection improvements (2–3 specific SIEM rules that would have detected this earlier)

See the solution in: `solutions/drill-02-solution/solution.md`
