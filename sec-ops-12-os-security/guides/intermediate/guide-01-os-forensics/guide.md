# Guide 04 (Intermediate): OS Forensics Investigation Workflow

**Level:** Intermediate

**Estimated time:** 60 minutes

**Prerequisites:** Session 12 reading (Sections 12–14), Basic guides 01–03

---

## Objective

This guide teaches a systematic forensic investigation workflow applicable to both Windows and Linux incidents.
You will follow the PICERL (Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned) model and apply forensic principles to reconstruct a real incident from artifacts.

---

## Overview: The Forensic Investigation Workflow

```text
1. TRIAGE              — Quickly assess scope, determine what happened

2. PRESERVATION        — Capture volatile evidence (memory, network state)
3. COLLECTION          — Gather logs, disk artifacts, process snapshots
4. EXAMINATION         — Parse and analyze individual artifact types
5. ANALYSIS            — Correlate across artifacts, build timeline
6. REPORTING           — Document findings, IOCs, recommendations
```

**Principle: Order of Volatility**

```text
Most volatile  →  CPU registers, caches
                  Memory (RAM)
                  Network connections
                  Running processes
                  Open files
                  Login sessions
                  Filesystem metadata
Least volatile →  Disk contents, backup media
```

---

## Setup

```console
cd guides/intermediate/guide-01-os-forensics
docker compose up --build
docker compose exec forensics bash
```

---

## Phase 1: Triage — Rapid Assessment

The first 15 minutes of any incident are critical.
Run these commands to get situational awareness:

### Linux Triage

```console
# Run the triage script
/scripts/linux-triage.sh 2>&1 | tee /tmp/triage_$(date +%Y%m%d_%H%M%S).txt
```

```bash
# Manual triage steps:

echo "=== [1/6] System Identification ==="
hostname; date; id; uname -a

echo "=== [2/6] Active Network Connections ==="
ss -tnp   # Established TCP with process names
ss -tlnp  # Listening ports (backdoors?)

echo "=== [3/6] Running Processes (look for anomalies) ==="
ps auxef | grep -E "tmp|shm|nc |python|perl|ruby|bash.*-i" | grep -v grep

echo "=== [4/6] Logged-In Users ==="
w; who

echo "=== [5/6] Recent Logins ==="
last -i | head -20

echo "=== [6/6] Recent File Modifications ==="
find /etc /home /root /tmp /var/spool/cron -newer /var/log/dpkg.log -type f 2>/dev/null | head -20
```

### Windows Triage (PowerShell)

```powershell
# Run in PowerShell environment
Write-Host "=== System Identification ===" -ForegroundColor Cyan
hostname; date; whoami; [System.Environment]::OSVersion

Write-Host "=== Active Network Connections ===" -ForegroundColor Cyan
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
  Format-Table

Write-Host "=== Processes from Suspicious Paths ===" -ForegroundColor Cyan
Get-Process | Select-Object Name, Id, Path |
  Where-Object { $_.Path -match 'Temp|AppData\\Local\\Temp|ProgramData(?!\\Microsoft)' }

Write-Host "=== Logged-In Users ===" -ForegroundColor Cyan
query user 2>$null

Write-Host "=== Recent Security Events (last 1 hour) ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{
  LogName='Security'; StartTime=(Get-Date).AddHours(-1)
  Id=@(4624,4625,4688,7045,1102)
} -EA SilentlyContinue |
  Select-Object TimeCreated, Id, Message | Format-List
```

---

## Phase 2: Preservation — Capture Volatile Evidence

```bash
# CRITICAL: Capture volatile evidence BEFORE any remediation
# This data will be GONE after reboot or network disconnect

# Create evidence directory
mkdir -p /evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)
EVDIR="/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)"

echo "Evidence directory: $EVDIR"

# 1. Network connections (most volatile - C2 channels)
ss -tnp  > $EVDIR/network_connections.txt
ss -tlnp > $EVDIR/listening_ports.txt
ip addr  > $EVDIR/ip_addresses.txt
arp -n   > $EVDIR/arp_cache.txt

# 2. Process list (will change when malware detects investigation)
ps auxef > $EVDIR/process_list.txt
ls -la /proc/*/exe 2>/dev/null > $EVDIR/process_executables.txt

# 3. Open files (shows which processes have what files open)
lsof -n  > $EVDIR/open_files.txt 2>/dev/null

# 4. Login information
w        > $EVDIR/logged_in_users.txt
last -i  > $EVDIR/login_history.txt
lastb -i > $EVDIR/failed_logins.txt 2>/dev/null

# 5. Loaded kernel modules (rootkit detection)
lsmod    > $EVDIR/kernel_modules.txt

# Hash all evidence files for integrity
sha256sum $EVDIR/* > $EVDIR/evidence_hashes.sha256
echo "Preservation complete. Evidence in: $EVDIR"
```

---

## Phase 3: Collection — Artifacts Gathering

### Linux Artifact Collection

```bash
# Collect all relevant artifacts
EVDIR="/evidence/linux_artifacts"
mkdir -p $EVDIR

# System logs
cp /var/log/auth.log $EVDIR/ 2>/dev/null
cp /var/log/syslog $EVDIR/ 2>/dev/null
cp /var/log/audit/audit.log $EVDIR/ 2>/dev/null
journalctl --since "7 days ago" -o json > $EVDIR/journal_7days.json 2>/dev/null

# Cron and persistence
cat /etc/crontab > $EVDIR/crontab_etc.txt
ls -la /etc/cron.d/ >> $EVDIR/crontab_etc.txt
cat /etc/cron.d/* >> $EVDIR/crontab_etc.txt 2>/dev/null
ls -la /var/spool/cron/crontabs/ > $EVDIR/user_crontabs.txt 2>/dev/null
cat /var/spool/cron/crontabs/* >> $EVDIR/user_crontabs.txt 2>/dev/null

# User accounts and credentials
cp /etc/passwd $EVDIR/
cp /etc/group $EVDIR/
cp /etc/sudoers $EVDIR/ 2>/dev/null

# Bash histories
for user_home in /root /home/*; do
    user=$(basename $user_home)
    [ -f "$user_home/.bash_history" ] && cp "$user_home/.bash_history" "$EVDIR/bash_history_$user.txt"
done

# SSH keys (backdoors)
find /root /home -name "authorized_keys" -exec cp {} $EVDIR/authorized_keys_$(basename $(dirname {})).txt \; 2>/dev/null

# Hash collection
sha256sum $EVDIR/* > $EVDIR/HASHES.sha256
echo "Linux collection complete."
```

---

## Phase 4: Examination — Forensic Artifact Analysis

### 4.1 Timeline Analysis

```bash
# Build a unified timeline from multiple log sources
echo "=== UNIFIED TIMELINE CONSTRUCTION ==="

# Method 1: Use log timestamps to build a chronological view
{
  # auth.log entries
  grep -h "14:4[0-9]\|14:5[0-9]\|15:" /evidence/linux_artifacts/auth.log 2>/dev/null | \
    awk '{print $3, "[auth.log]", $0}' | sort

  # auditd entries (convert epoch to readable)
  ausearch -if /evidence/linux_artifacts/audit.log -i 2>/dev/null | \
    grep "time=" | sed 's/.*time="\([^"]*\)".*/\1 [auditd]/' | sort

} | sort > /tmp/timeline.txt

cat /tmp/timeline.txt | head -50
```

```console
# Look for temporal clustering of events (attacker's activity window)
echo "=== EVENT DENSITY BY HOUR ==="
grep -oE "[0-9]{2}:[0-9]{2}:[0-9]{2}" /evidence/linux_artifacts/auth.log 2>/dev/null | \
  cut -d: -f1 | sort | uniq -c | sort -rn | head -5
```

### 4.2 Process Execution Analysis

```bash
# Correlate process execution from multiple sources
echo "=== PROCESS EXECUTION EVIDENCE ==="

echo "1. Bash history (direct commands):"
cat /root/.bash_history 2>/dev/null | head -20

echo ""
echo "2. Auditd execve() calls:"
ausearch -m execve -i -if /evidence/linux_artifacts/audit.log 2>/dev/null | \
  grep "EXECVE\|SYSCALL" | head -20

echo ""
echo "3. Cron-executed commands:"
grep "CRON.*CMD\|CMD.*update\|CMD.*payload" /evidence/linux_artifacts/syslog 2>/dev/null | head -10
```

### 4.3 Network Forensics

```bash
# Identify C2 communication indicators
echo "=== NETWORK INDICATORS OF COMPROMISE ==="

# From preserved network connections
echo "Established connections at time of collection:"
cat /evidence/linux_artifacts/network_connections.txt 2>/dev/null || \
  echo "(Run preservation phase first)"

# From process list — processes with unexpected network
echo ""
echo "Processes with network connections (from preserved snapshot):"
grep -E "nc |python|bash" /evidence/linux_artifacts/open_files.txt 2>/dev/null | head -10
```

---

## Phase 5: Analysis — Building the Attack Narrative

```console
# Run the incident analysis script
python3 /scripts/incident_analysis.py

# This script correlates all evidence and produces:
# - Attack timeline with confidence levels
# - MITRE ATT&CK technique mapping
# - IOC list
# - Recommended containment actions
```

**Manual attack narrative construction:**

```text
ATTACK NARRATIVE TEMPLATE:

1. INITIAL ACCESS

   How: [brute force / phishing / exploit]
   When: [timestamp]
   Who: [user account compromised]
   From: [source IP]
   Evidence: [auth.log line, event ID, etc.]

2. EXECUTION
   Tools: [commands run, scripts downloaded]
   When: [timestamp]
   Evidence: [bash_history, auditd execve, prefetch]

3. PERSISTENCE
   Mechanism: [cron / service / SSH key / registry]
   Location: [specific file/key]
   Evidence: [audit log, file modification time]

4. PRIVILEGE ESCALATION (if any)
   Method: [sudo misconfiguration / SUID / kernel exploit]
   Evidence: [sudo log, auditd]

5. CREDENTIAL ACCESS
   What: [password hash / plaintext / SSH key]
   How: [shadow file read / LSASS dump / memory scraping]
   Evidence: [auditd, Sysmon Event 10]

6. DEFENSE EVASION
   Actions: [log cleared, file deleted, timestomping]
   Evidence: [Event 1102, prefetch of deleted binary]
```

---

## Phase 6: Reporting — Documenting Findings

```console
# Generate a forensic investigation report
python3 /scripts/generate_report.py \
  --incident-id "INC-2024-0114" \
  --analyst "Student" \
  --system "demo-forensics" \
  --output /evidence/incident_report.md

cat /evidence/incident_report.md
```

**Report structure (complete in your own investigation):**

```markdown
# Incident Report: INC-2024-XXXX

## Executive Summary
[2-3 sentences describing what happened, impact, and status]

## Incident Timeline
| Time | Source | Event | Significance |
|------|--------|-------|-------------|

## Attack Chain (MITRE ATT&CK)
- T1110 Brute Force → T1059 Command Execution → T1136 Account Creation → T1053 Scheduled Task

## Indicators of Compromise
### Network IOCs
- IP: 10.0.5.123 (attacker C2)

### Host IOCs
- File: /tmp/.update.sh
- User: backdoor_user (UID 1002)
- Cron: * * * * * root /tmp/.update.sh

## Root Causes
1. Password authentication enabled on SSH

2. alice had unrestricted sudo access
3. No account lockout policy

## Recommendations
1. IMMEDIATE: Disable password auth (PasswordAuthentication no)

2. SHORT-TERM: Restrict sudo to specific commands
3. LONG-TERM: Deploy PAM lockout, centralize logging to SIEM
```

---

## Summary

You have practiced the complete forensic investigation workflow:

| Phase | Key Activities | Tools |
|-------|---------------|-------|
| Triage | Network state, processes, recent logins | ss, ps, w, last |
| Preservation | Capture volatile evidence with hashes | dd, sha256sum |
| Collection | Logs, cron, bash history, SSH keys | cp, ausearch, journalctl |
| Examination | Timeline construction, process correlation | sort, awk, ausearch |
| Analysis | Attack narrative, MITRE mapping | Custom analysis |
| Reporting | IOC list, root causes, recommendations | Markdown report |

**Key forensic principles:**

1. **Don't modify evidence** — work on copies
1. **Document chain of custody** — hash everything
1. **Follow order of volatility** — memory before disk
1. **Multiple sources** — no single artifact tells the whole story
1. **Context matters** — a process in `/tmp` is always suspicious, never explain it away
