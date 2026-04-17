# Drill 02 (Intermediate): Log Forensics — Incident Reconstruction

**Level:** Intermediate

**Estimated time:** 50 minutes

---

## Objective

Reconstruct a security incident from log files, identify the attacker's actions, determine the impact, and produce an incident timeline.

---

## Setup

```console
cd drills/intermediate/drill-02-log-forensics
docker compose up --build
docker compose exec log-forensics bash
```

Log files are available at `/var/log/incident/`:

* `auth.log` — authentication events
* `audit.log` — auditd kernel events
* `syslog` — general system log
* `nginx_access.log` — web server access log

---

## Scenario

At 09:00 on March 16, 2024, the on-call engineer received an automated alert: "Unusual outbound traffic detected from web server (10.0.1.50) to IP 185.220.X.X:4444."

You have been given the log files from the preceding 48 hours.
Your task is to reconstruct what happened.

---

## Tasks

### Task 1: Web Application Attack Analysis (20 points)

Search the nginx access log for evidence of an initial attack vector.

```console
# Hint: Look for unusual HTTP status codes, unusual paths, or SQL injection patterns
grep -E "500|404" /var/log/incident/nginx_access.log | tail -50
grep -i "select\|union\|concat\|;--" /var/log/incident/nginx_access.log
```

Document:

1. What was the initial attack vector?
1. When did it start?
1. What IP was the attacker using?
1. Which endpoint was targeted?

### Task 2: System Compromise Timeline (25 points)

After identifying the initial attack time and source IP, trace what happened next.

```console
# Search auth log around the attack time
grep "10.0.5.X" /var/log/incident/auth.log  # Use attacker IP from Task 1

# Check for new processes or user accounts created
ausearch -f /etc/passwd --start "$(date -d 'Task1_attack_time' '+%H:%M:%S')" 2>/dev/null || \
  grep "useradd\|adduser" /var/log/incident/auth.log
```

Build a timeline:

```text
[TIME] Event 1: ...
[TIME] Event 2: ...
...
```

### Task 3: Persistence Mechanisms (20 points)

Find evidence of persistence established by the attacker.

```console
# Check for cron job additions
grep "cron" /var/log/incident/syslog
grep "cron" /var/log/incident/auth.log

# Check audit log for file modifications in persistence-relevant paths
ausearch -f /etc/cron.d --start ... 2>/dev/null || \
  grep "cron" /var/log/incident/audit.log
```

Document:

1. What persistence mechanism was used?
1. When was it established?
1. How would you detect this in the future (SIEM rule)?

### Task 4: Data Exfiltration Assessment (20 points)

Determine if any data was exfiltrated.

```console
# Look for large outbound transfers
grep "185.220" /var/log/incident/syslog

# Check audit log for large file reads
ausearch -sc read --start ... 2>/dev/null || \
  grep "READ" /var/log/incident/audit.log | head -50
```

Document:

1. Was data exfiltrated? What evidence supports your conclusion?
1. What data types were potentially accessed?
1. Does this constitute a GDPR-notifiable breach? Why or why not?

### Task 5: Root Cause Analysis (15 points)

Based on your findings:

1. What was the root cause of the compromise?
1. What security controls were missing or failed?
1. What is the VERIS classification of this incident?

---

## Deliverable

A structured incident report:

1. Executive Summary (3–4 sentences)
1. Incident Timeline (table format)
1. Root Cause Analysis
1. Impact Assessment
1. Recommendations (3 specific controls)

See `solutions/drill-02-solution/` for reference.
