# Drill 02 (Advanced): Incident Triage — First 30 Minutes

**Level:** Advanced

**Estimated time:** 60 minutes

---

## Objective

Perform a rapid incident triage on a potentially compromised system within 30 minutes, following a structured triage process, and produce a Go/No-Go containment recommendation.

---

## Background

When a SOC analyst receives a high-severity alert about a potentially compromised system, the first 30 minutes are critical.
The goals are:

1. **Confirm or deny** that a compromise occurred
1. **Assess scope** — is this one system or have they spread?
1. **Identify immediate actions** — isolate, remediate, or monitor?
1. **Preserve evidence** — collect volatile data before it's lost

This drill simulates an active triage scenario.

---

## Setup

```console
cd drills/advanced/drill-02-incident-triage
docker compose up --build
docker compose exec triage-system bash
```

**Alert that triggered this investigation:**
> SIEM Alert: Impossible travel detected for user `jsmith`. Login from Berlin at 09:15 and from Bucharest at 09:22 (same session). Additionally, unusual outbound traffic to 185.220.X.X on port 8443 detected from this workstation.

---

## 30-Minute Triage Protocol

### Minutes 0-5: Volatile Data Collection

```bash
# IMMEDIATELY collect volatile data (it changes every second)

# 1. Timestamp everything
date > /tmp/triage_start.txt

# 2. Running processes
ps auxf > /tmp/triage_processes.txt

# 3. Network connections
ss -tnp > /tmp/triage_connections.txt

# 4. Logged-in users
who > /tmp/triage_users.txt
last | head -20 > /tmp/triage_logins.txt

# 5. Recently created/modified files
find / -newer /tmp/triage_start.txt -type f \
  -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null > /tmp/triage_recent_files.txt
```

**Question (5 min):** Based on the initial data, is the attacker still active (current session), or did they disconnect?

### Minutes 5-15: Investigate the Alert IOCs

```bash
# 1. Is the suspicious IP still connected?
grep "185.220" /tmp/triage_connections.txt

# 2. What process owns that connection?
SUSPICIOUS_IP="185.220.X.X"
ss -tnp | grep $SUSPICIOUS_IP

# 3. Investigate that process
PID=$(ss -tnp | grep $SUSPICIOUS_IP | grep -oP "pid=\K[0-9]+")
cat /proc/$PID/cmdline | tr '\0' ' '
ls -la /proc/$PID/exe
cat /proc/$PID/maps

# 4. Check for deleted binaries
ls -la /proc/*/exe 2>/dev/null | grep deleted

# 5. Check jsmith's recent activity
grep "jsmith" /var/log/auth.log | tail -20
```

### Minutes 15-25: Scope Assessment

```bash
# Has the attacker moved to other systems?
# (Check network connections to internal IPs)
ss -tnp | grep -v "127.0.0\|:22 " | grep "ESTAB"

# Are there any new accounts?
grep "useradd\|adduser" /var/log/auth.log | tail -10

# Check for lateral movement artifacts
grep "SSH\|scp\|sftp\|rsync" /var/log/auth.log | tail -20

# Check authentication attempts from this machine to others
grep "$(hostname)" /var/log/auth.log 2>/dev/null | tail -20
```

### Minutes 25-30: Evidence Preservation and Decision

```console
# Preserve key evidence before any action
tar czf /tmp/triage_evidence_$(date +%s).tar.gz \
  /tmp/triage_*.txt /var/log/auth.log /var/log/syslog

# Calculate hashes for chain of custody
sha256sum /tmp/triage_evidence_*.tar.gz
```

**Decision matrix:**
| Finding | Action |
|---------|--------|
| Active attacker, active session | ISOLATE immediately |
| Backdoor but no active session | ISOLATE after evidence collection |
| No confirmed compromise, IOC only | MONITOR, escalate |
| False positive | DOCUMENT, close ticket |

---

## Deliverable

A 30-minute triage report:

1. Summary of findings (5 bullets maximum)
1. Confirmation: Was a compromise confirmed? (Yes/No/Suspected)
1. Scope: Is this isolated or does evidence suggest lateral movement?
1. Recommendation: Isolate / Monitor / False Positive
1. Evidence collected (list of files)
1. VERIS preliminary classification (Actor, Action, Asset)

See `solutions/drill-02-solution/` for reference.
