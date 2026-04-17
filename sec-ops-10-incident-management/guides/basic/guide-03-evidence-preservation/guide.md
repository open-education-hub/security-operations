# Guide 03 (Basic): Evidence Preservation and Chain of Custody

> **Estimated time:** 30–40 minutes
> **Level:** Basic
> **Goal:** Learn to preserve digital evidence in a legally defensible manner, establish proper chain of custody, and use standard forensic tools for evidence acquisition.

---

## Why Evidence Preservation Matters

Digital evidence is fragile.
Without proper preservation:

* **Legally**: Evidence may be inadmissible in court or regulatory proceedings. Opposing counsel will challenge evidence that lacks a documented chain of custody.
* **Technically**: Volatile evidence (RAM, running processes, network connections) disappears on shutdown or reboot. Even disk artifacts can be overwritten by normal OS activity.
* **Organizationally**: Without preserved evidence, root cause analysis is impossible, making it harder to prevent recurrence.

The goal is to collect and preserve evidence in a way that proves:

1. The evidence is **authentic** (it really came from the system in question)
1. The evidence is **unaltered** (it has not been modified since collection)
1. The evidence was **collected properly** (with documented procedures and chain of custody)

---

## The Order of Volatility

Always collect evidence from most volatile to least volatile:

```text
MOST VOLATILE (collect first)
     │
     ▼

1. CPU registers and cache contents

2. RAM (system memory)           ← highest investigative value, disappears on shutdown
3. Network connection state       ← netstat output, active TCP/UDP connections
4. Running processes              ← ps, tasklist — disappears on shutdown
5. Open file handles              ← lsof, handle.exe
6. Clipboard contents             ← volatile but rarely needed
     │
     ▼
7. Disk image (non-volatile but writable)
8. System logs (SIEM export, event logs)
9. Network flow data (NetFlow, proxy logs)
10. Remote storage and cloud logs ← varies by provider retention
     │
     ▼
LEAST VOLATILE (but still collect promptly)
```

**Practical rule:** Before you touch a system for containment, collect items 2–5 from the list above.

---

## Part 1: Windows Evidence Collection

### 1.1 Pre-Collection Setup

```powershell
# Create a timestamped evidence directory
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$INCIDENT = "INC-2025-0042"
$EVID = "D:\Evidence\${INCIDENT}\${TIMESTAMP}"
New-Item -ItemType Directory -Force -Path $EVID

# Record collection start time
"Collection started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" |
  Out-File "$EVID\collection_log.txt"
"Collector: $env:USERNAME on $env:COMPUTERNAME" |
  Out-File "$EVID\collection_log.txt" -Append
```

### 1.2 Memory Acquisition (Highest Priority)

```powershell
# Option A: WinPMEM (recommended, open source)
# Download from: https://github.com/Velocidex/WinPmem/releases
.\winpmem_mini_x64_rc2.exe "$EVID\memory.raw"

# Compute hash immediately after capture
$hash = (Get-FileHash "$EVID\memory.raw" -Algorithm SHA256).Hash
"memory.raw SHA256: $hash" | Out-File "$EVID\HASHES.sha256"
"Captured at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')" |
  Out-File "$EVID\HASHES.sha256" -Append
```

### 1.3 Volatile System State

```powershell
# Network connections
netstat -anob > "$EVID\network_connections.txt"
"[$(Get-Date -Format 'HH:mm:ss UTC')] Network connections captured" |
  Out-File "$EVID\collection_log.txt" -Append

# ARP cache (LAN-level connection map)
arp -a > "$EVID\arp_cache.txt"

# DNS cache
ipconfig /displaydns > "$EVID\dns_cache.txt"

# Running processes with detail
Get-Process | Select-Object Id, ProcessName, Path, CPU, StartTime, MainWindowTitle |
  Export-Csv "$EVID\processes.csv" -NoTypeInformation

# Detailed process info via WMI
wmic process get Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath /format:csv >
  "$EVID\processes_wmi.csv"

# Logged-in users
query user > "$EVID\logged_in_users.txt"
qwinsta > "$EVID\sessions.txt"

# Loaded drivers and services
sc query type= all state= all > "$EVID\services.txt"

# Scheduled tasks
schtasks /query /fo LIST /v > "$EVID\scheduled_tasks.txt"

# Autostart locations
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  "$EVID\run_hklm.reg"
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  "$EVID\run_hkcu.reg"
```

### 1.4 Disk Evidence

```powershell
# Export Windows Event Logs (critical sources)
# Do this before any system changes

$LogNames = @("Security", "System", "Application",
              "Microsoft-Windows-PowerShell/Operational",
              "Microsoft-Windows-Sysmon/Operational")

foreach ($log in $LogNames) {
    $safeName = $log.Replace("/", "_").Replace("\", "_")
    wevtutil epl $log "$EVID\${safeName}.evtx"
}

# Prefetch files (execution evidence)
Copy-Item "$env:WINDIR\Prefetch\*.pf" "$EVID\Prefetch\" -Force

# Recent files (LNK files)
Copy-Item "$env:APPDATA\Microsoft\Windows\Recent\*" "$EVID\Recent\" -Force
```

### 1.5 Full Disk Image (if required)

For a full forensic image, use FTK Imager from AccessData (free download):

```text
GUI-based disk imaging steps (FTK Imager):

1. File → Create Disk Image

2. Source: Physical Drive → Select target drive
3. Destination: E01 (EnCase format) — includes metadata + hash verification
4. Fragment image: [set fragment size or 0 for single file]
5. Image filename: FINANCE-WS-042_disk.E01
6. Enable: Verify images after they are created
7. Start
8. Record: MD5 and SHA1 hashes displayed on completion
```

Command-line disk imaging with dd:

```console
# On Linux forensic workstation with disk attached
# /dev/sda = source disk, /mnt/evidence/ = destination

sudo dcfldd if=/dev/sda of=/mnt/evidence/disk.img hash=sha256 \
  hashlog=/mnt/evidence/disk.sha256 hashwindow=256M

# Verify image
sha256sum /mnt/evidence/disk.img
```

---

## Part 2: Linux Evidence Collection

### 2.1 Quick Collection Script

```bash
#!/bin/bash
# Linux volatile evidence collection script
# Run as root

INCIDENT="INC-2025-0042"
EVID="/tmp/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVID"

echo "=== Collection started: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===" | tee "$EVID/collection_log.txt"
echo "=== Collector: $(whoami)@$(hostname) ===" | tee -a "$EVID/collection_log.txt"

# Network state
echo "[$(date +%H:%M:%S)] Collecting network state..." | tee -a "$EVID/collection_log.txt"
ss -antp > "$EVID/sockets.txt"
netstat -anp > "$EVID/netstat.txt" 2>/dev/null
ip route show > "$EVID/routes.txt"
arp -n > "$EVID/arp.txt"
cat /etc/resolv.conf > "$EVID/dns_config.txt"

# Running processes
echo "[$(date +%H:%M:%S)] Collecting processes..." | tee -a "$EVID/collection_log.txt"
ps auxf > "$EVID/processes.txt"
ps axo pid,ppid,user,cmd > "$EVID/processes_ppid.txt"
ls -la /proc/*/exe 2>/dev/null > "$EVID/proc_exe.txt"

# Open files
lsof -n > "$EVID/open_files.txt" 2>/dev/null

# Users and sessions
who > "$EVID/who.txt"
w > "$EVID/w.txt"
last -n 50 > "$EVID/last_logins.txt"

# Cron jobs (persistence)
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null | sed "s/^/$user: /"
done > "$EVID/crontabs.txt"
ls -la /etc/cron* >> "$EVID/crontabs.txt"

# Systemd services (persistence)
systemctl list-units --type=service --all > "$EVID/services.txt"
ls -la /etc/systemd/system/ > "$EVID/systemd_custom.txt"

# SSH authorized keys (persistence)
find /home /root -name "authorized_keys" -exec echo "=== {} ===" \; \
  -exec cat {} \; > "$EVID/ssh_authorized_keys.txt" 2>/dev/null

# SUID/SGID binaries (privilege escalation)
find / -perm /6000 -type f 2>/dev/null > "$EVID/suid_sgid.txt"

# Recently modified files (last 24 hours)
find /tmp /var/tmp /dev/shm /home -newer /proc/uptime -type f 2>/dev/null > "$EVID/recent_files.txt"

# Bash history
find /home /root -name ".bash_history" -exec echo "=== {} ===" \; \
  -exec cat {} \; > "$EVID/bash_history.txt" 2>/dev/null

# Installed packages
if command -v dpkg &>/dev/null; then
  dpkg -l > "$EVID/packages.txt"
elif command -v rpm &>/dev/null; then
  rpm -qa --last > "$EVID/packages.txt"
fi

# Hash all collected files
echo "[$(date +%H:%M:%S)] Hashing evidence files..." | tee -a "$EVID/collection_log.txt"
sha256sum "$EVID"/* > "$EVID/HASHES.sha256" 2>/dev/null

echo "=== Collection complete: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===" | tee -a "$EVID/collection_log.txt"
echo "=== Evidence directory: $EVID ===" | tee -a "$EVID/collection_log.txt"
```

---

## Part 3: Chain of Custody

### 3.1 Chain of Custody Form

Every piece of collected evidence must have a completed chain of custody form:

```text
╔══════════════════════════════════════════════════════════════════════╗
║               DIGITAL EVIDENCE — CHAIN OF CUSTODY                  ║
╠══════════════════════════════════════════════════════════════════════╣
║ Evidence ID:        EVID-MEM-001                                    ║
║ Incident ID:        INC-2025-0042                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║ EVIDENCE DESCRIPTION                                                ║
║   Type:             Memory dump (RAM image)                         ║
║   Source system:    FINANCE-WS-042                                  ║
║   IP Address:       192.168.10.55                                   ║
║   OS:               Windows 10 Pro 22H2 (Build 19045)              ║
║   RAM size:         16 GB                                           ║
║   File name:        memory.raw                                      ║
║   File size:        17,179,869,184 bytes                            ║
╠══════════════════════════════════════════════════════════════════════╣
║ HASH VALUES (compute at time of collection)                         ║
║   MD5:       [compute and record]                                   ║
║   SHA-256:   [compute and record — use this as primary]             ║
╠══════════════════════════════════════════════════════════════════════╣
║ COLLECTION DETAILS                                                  ║
║   Date/Time:        2025-04-10 09:15:23 UTC                         ║
║   Collection Tool:  WinPMEM v4.0.rc1                                ║
║   Tool Hash:        [tool executable SHA-256]                       ║
║   Collected By:     J. Garcia (Tier 2 Analyst, Employee #1042)      ║
║   Witnessed By:     M. Torres (Forensics Lead, Employee #1089)      ║
╠══════════════════════════════════════════════════════════════════════╣
║ STORAGE INFORMATION                                                 ║
║   Primary storage:  Encrypted NAS share (AES-256)                  ║
║   Path:             \\nas-ir\evidence\INC-2025-0042\                ║
║   Access controls:  IRT team only (RBAC enforced)                  ║
╠══════════════════════════════════════════════════════════════════════╣
║ CUSTODY TRANSFERS (add row for each transfer)                       ║
║                                                                     ║
║  Date/Time (UTC) | From          | To           | Purpose | Initials║
║  ──────────────────────────────────────────────────────────────     ║
║  2025-04-10 09:20| J. Garcia     | NAS /evidence| Storage | JG     ║
║  2025-04-10 11:00| NAS /evidence | M. Torres    | Analysis| MT     ║
║  2025-04-10 17:00| M. Torres     | NAS /evidence| Complete| MT     ║
╠══════════════════════════════════════════════════════════════════════╣
║ VERIFICATION LOG (hash verification on each access)                 ║
║                                                                     ║
║  2025-04-10 11:00 | M. Torres | SHA-256 verified ✓ | Analysis start║
║  2025-04-10 17:00 | M. Torres | SHA-256 verified ✓ | Analysis end  ║
╚══════════════════════════════════════════════════════════════════════╝
```

### 3.2 Evidence Hash Verification

```bash
# At collection — compute and record hash
sha256sum memory.raw > memory.raw.sha256
cat memory.raw.sha256
# Output: a3f4e5b6c7d8e9f0a1b2c3d4e5f6... memory.raw

# Before every analysis session — verify hash
sha256sum -c memory.raw.sha256
# Expected output: memory.raw: OK
# If output is: memory.raw: FAILED  → evidence has been altered — DO NOT analyze, report immediately

# Before and after every custody transfer
sha256sum disk.img
# Record this hash in the custody transfer log
```

### 3.3 Evidence Storage Requirements

```text
EVIDENCE STORAGE CHECKLIST:
□ Original media in tamper-evident packaging (for physical media)
□ Digital evidence on write-protected storage or evidence management system
□ Access log maintained for all evidence access
□ Evidence encrypted at rest (AES-256 minimum)
□ Backup copy on separate physical storage in different location
□ Access restricted to IRT members with need-to-know
□ Retention period defined (minimum 12 months; longer for criminal cases)
□ Chain of custody form stored with evidence
```

---

## Part 4: Evidence Integrity Failures — What Not to Do

Common evidence integrity mistakes and their consequences:

```text
MISTAKE                     │ CONSEQUENCE
────────────────────────────┼──────────────────────────────────────────────
Working on original disk    │ OS writes to disk, overwrites evidence
No hash on collection       │ Cannot prove evidence unaltered — inadmissible
Rebooting before RAM dump   │ Lose all volatile evidence (processes, connections)
Emailing evidence files     │ Evidence passed through insecure channel, log of access lost
Using corporate OneDrive    │ Third-party cloud access creates chain of custody issues
Powering off without imaging│ Encryption key (for encrypted disk) lost
No access log               │ Cannot prove who accessed evidence — chain broken
MD5 only (no SHA-256)       │ MD5 is deprecated for legal evidence; weak against collisions
```

---

## Practical Exercise

**Scenario:** You have been called to investigate a workstation (ACCT-WS-005) suspected of connecting to a malware C2 server.
The EDR alert fired 10 minutes ago.
The system is still running.

**Tasks:**

1. In what order will you collect evidence from this system? List the specific items you will collect and the tools you will use.

1. Draft a Chain of Custody form header for the first piece of evidence you collect. Include: Evidence ID, system details, and hash placeholder.

1. After collecting memory, you attempt to copy the file to a USB drive but the USB is not write-protected. What risks does this create, and what should you do instead?

1. Your IR Lead asks you to share the memory dump with an external forensics consultant via email attachment. What is the correct procedure?

**Answers:** See Guide 03 Solution section (or discuss with your instructor).

---

## Key Takeaways

1. **Collect volatile evidence before containment** — memory dumps before EDR isolation; network state before firewall blocks.

1. **Hash everything, immediately** — SHA-256 at the moment of collection is your evidence's birth certificate.

1. **Chain of custody is a process, not a form** — it is the continuous documentation of who touched evidence and when.

1. **Never work on originals** — create forensic copies and verify hash before each analysis session.

1. **Store securely from day one** — access-controlled, encrypted, with access logging.

1. **Document tool versions** — "collected with WinPMEM v4.0.rc1 (hash: abc123...)" is part of the evidence record.
