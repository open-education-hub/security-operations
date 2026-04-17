# Guide 02: Evidence Collection Procedures and Chain of Custody

**Level:** Basic

**Estimated time:** 20 minutes

**Prerequisites:** Reading — Section 6 (Evidence Types and Chain of Custody)

---

## Purpose

By the end of this guide, you will be able to:

* Identify volatile versus non-volatile evidence
* Apply the correct collection order (order of volatility)
* Complete a chain of custody form accurately
* Explain why chain of custody matters in legal proceedings
* Avoid the most common evidence collection mistakes

---

## Part 1: The Order of Volatility

Evidence collection must prioritize the most volatile data first. **Evidence that will disappear if the system is powered off must be collected before anything else.**

```text
MOST VOLATILE (collect first)
────────────────────────────────

1. CPU registers and cache        (nanoseconds — lost immediately)

2. Routing tables, ARP cache      (minutes — network state)
3. Process table, running services (minutes — killed on shutdown)
4. Memory (RAM)                   (seconds after power loss)
5. Temporary file system / swap   (cleared on shutdown)
6. Network connections (netstat)  (disconnected when isolated)
7. Clipboard contents             (cleared when process ends)
────────────────────────────────
LESS VOLATILE (can wait briefly)
────────────────────────────────
8. File system (disk) — metadata  (survives shutdown, may be overwritten)
9. Log files                      (rotation may delete old entries)
10. Application data              (survives shutdown)
────────────────────────────────
MOST PERSISTENT (can wait)
────────────────────────────────
11. Archived logs (SIEM)          (defined retention policy)
12. Backup data                   (defined retention policy)
13. Physical media                (indefinitely persistent)
```

### Decision point: To isolate or not?

Before collecting volatile evidence, decide whether to isolate the system.

**Isolate first if:**

* Active data exfiltration is occurring
* Ransomware encryption is spreading
* Risk of further spread outweighs intelligence value of observation

**Collect volatile evidence first if:**

* No active spread/exfiltration
* Litigation or forensic investigation likely
* You need to understand the full scope (what C2, what commands)

**If in doubt:** Collect volatile first, then isolate.

---

## Part 2: Volatile Evidence Collection Commands

### Windows

```powershell
# Create evidence directory on external USB/network share
$evidence_dir = "E:\Evidence\$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $evidence_dir

# Step 1: Record system time (reference timestamp)
Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" |
  Out-File "$evidence_dir\00-timestamp.txt"

# Step 2: Running processes (with paths and parent PIDs)
Get-Process | Select-Object Id, ProcessName, Path, StartTime, CPU,
  @{N='ParentPID'; E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}} |
  Export-Csv "$evidence_dir\01-processes.csv" -NoTypeInformation

# Step 3: Network connections
netstat -ano > "$evidence_dir\02-netstat.txt"
Get-NetTCPConnection | Export-Csv "$evidence_dir\02-tcpconnections.csv" -NoTypeInformation

# Step 4: Logged-in users
query user > "$evidence_dir\03-users.txt"
Get-WmiObject -Class Win32_LoggedOnUser |
  Select-Object Antecedent, Dependent |
  Out-File "$evidence_dir\03-loggedon.txt"

# Step 5: Open files and handles (requires Sysinternals handle.exe)
# handle.exe -a > "$evidence_dir\04-handles.txt"

# Step 6: DNS cache
ipconfig /displaydns > "$evidence_dir\05-dns-cache.txt"

# Step 7: ARP cache
arp -a > "$evidence_dir\06-arp-cache.txt"

# Step 8: Scheduled tasks
schtasks /query /fo CSV /v > "$evidence_dir\07-scheduled-tasks.csv"

# Step 9: Services
Get-Service | Export-Csv "$evidence_dir\08-services.csv" -NoTypeInformation

# Step 10: Memory dump (requires WinPmem)
# winpmem_mini_x64_rc2.exe "$evidence_dir\09-memory.raw"
```

### Linux

```bash
#!/bin/bash
# Evidence collection script for Linux
EVIDENCE_DIR="/mnt/usb/evidence/$(hostname)-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# Step 1: System time (critical reference)
date -u > "$EVIDENCE_DIR/00-timestamp.txt"
echo "Hardware clock: $(hwclock --show)" >> "$EVIDENCE_DIR/00-timestamp.txt"

# Step 2: Running processes
ps auxf > "$EVIDENCE_DIR/01-processes.txt"
ps -eo pid,ppid,user,args > "$EVIDENCE_DIR/01-processes-detail.txt"

# Step 3: Network connections
ss -antup > "$EVIDENCE_DIR/02-network-connections.txt"
ip addr show > "$EVIDENCE_DIR/02-ip-addresses.txt"
ip route show > "$EVIDENCE_DIR/02-routing-table.txt"
arp -a > "$EVIDENCE_DIR/02-arp-cache.txt"

# Step 4: Logged-in users
w > "$EVIDENCE_DIR/03-users.txt"
last -20 >> "$EVIDENCE_DIR/03-users.txt"

# Step 5: Open files
lsof > "$EVIDENCE_DIR/04-open-files.txt"
lsof -i > "$EVIDENCE_DIR/04-network-files.txt"

# Step 6: Kernel modules (rootkit check)
lsmod > "$EVIDENCE_DIR/05-kernel-modules.txt"

# Step 7: Cron jobs
crontab -l > "$EVIDENCE_DIR/06-cron-user.txt" 2>/dev/null
ls -la /etc/cron* /var/spool/cron/ >> "$EVIDENCE_DIR/06-cron-all.txt" 2>/dev/null

# Step 8: Memory acquisition (requires avml or LiME)
# avml "$EVIDENCE_DIR/memory.lime"

# Step 9: Hash everything collected
sha256sum "$EVIDENCE_DIR"/* > "$EVIDENCE_DIR/MANIFEST.sha256"

echo "Evidence collection complete: $EVIDENCE_DIR"
echo "Verify with: sha256sum -c $EVIDENCE_DIR/MANIFEST.sha256"
```

---

## Part 3: Non-Volatile Evidence Collection

Non-volatile evidence can be collected more deliberately.
Always use write-blocking when acquiring disk images.

### Disk Imaging (Linux — using dd)

```bash
# Identify the target disk
lsblk

# Acquire a full disk image (WRITE BLOCKER MUST BE IN PLACE)
sudo dd if=/dev/sda of=/mnt/evidence/disk-image.dd bs=64K conv=noerror,sync status=progress

# Compute hashes before and after
sha256sum /dev/sda > /mnt/evidence/disk-image-SOURCE.sha256
sha256sum /mnt/evidence/disk-image.dd > /mnt/evidence/disk-image-COPY.sha256

# Verify they match
diff /mnt/evidence/disk-image-SOURCE.sha256 /mnt/evidence/disk-image-COPY.sha256
```

### Windows Event Log Export

```powershell
# Export key event logs
$logs = @("Security", "System", "Application",
          "Microsoft-Windows-Sysmon/Operational",
          "Microsoft-Windows-PowerShell/Operational",
          "Microsoft-Windows-WMI-Activity/Operational")

foreach ($log in $logs) {
    $safe_name = $log -replace "[/\\]", "-"
    $output = "E:\Evidence\logs\$safe_name.evtx"
    wevtutil export-log "$log" "$output" /ow:true
    Write-Host "Exported: $log -> $output"
}
```

---

## Part 4: Chain of Custody — Completing the Form

### Why Chain of Custody Matters

Evidence that cannot be proven unmodified is:

* Inadmissible in criminal proceedings
* Challengeable in civil litigation
* Potentially excluded from disciplinary proceedings
* A liability risk for the organization

**Chain of custody documents:**

1. Who collected the evidence
1. When and where it was collected
1. The method used to collect it
1. A cryptographic hash proving integrity
1. Every person who has handled it since

### Chain of Custody Form — Template

```text
═══════════════════════════════════════════════════════════════
                    CHAIN OF CUSTODY RECORD
═══════════════════════════════════════════════════════════════

Case Number:        _______________
Incident Ticket:    _______________
Exhibit Number:     _______________

EVIDENCE DESCRIPTION
────────────────────────────────────────────────────────────────
Description:        _______________________________________________
Make/Model:         _______________________________________________
Serial Number:      _______________________________________________
Asset Tag:          _______________________________________________

COLLECTION DETAILS
────────────────────────────────────────────────────────────────
Collected by:       _______________________________________________
  Badge/ID:         _______________________________________________
Collection date:    _______________________________________________
Collection time:    _______________ (UTC)
Collection location:_______________________________________________
Collection method:  _______________________________________________

INTEGRITY VERIFICATION
────────────────────────────────────────────────────────────────
MD5 Hash:           _______________________________________________
SHA-256 Hash:       _______________________________________________
Hash computed at:   _______________ (UTC)
Hash computed by:   _______________________________________________

TRANSFER LOG
────────────────────────────────────────────────────────────────
Date/Time    │ Released By     │ Received By     │ Reason         │ Sig
─────────────┼─────────────────┼─────────────────┼────────────────┼────
             │                 │                 │                │
             │                 │                 │                │
             │                 │                 │                │
             │                 │                 │                │

NOTES
────────────────────────────────────────────────────────────────
___________________________________________________________________
___________________________________________________________________

═══════════════════════════════════════════════════════════════
```

### Completed Example

```text
═══════════════════════════════════════════════════════════════
                    CHAIN OF CUSTODY RECORD
═══════════════════════════════════════════════════════════════

Case Number:        CASE-2024-047
Incident Ticket:    INC-2024-0847
Exhibit Number:     E-001

EVIDENCE DESCRIPTION
────────────────────────────────────────────────────────────────
Description:        Dell Latitude 5540 laptop, IT asset
Make/Model:         Dell / Latitude 5540
Serial Number:      ABC123456
Asset Tag:          IT-ASSET-0892

COLLECTION DETAILS
────────────────────────────────────────────────────────────────
Collected by:       Jane Smith
  Badge/ID:         SOC-4521
Collection date:    2024-11-15
Collection time:    14:32 UTC
Collection location:3rd Floor, Open Plan Area, Desk 12B, Building A
Collection method:  Live forensic acquisition using FTK Imager v4.7.1
                    Disk image + memory dump, system left running
                    during acquisition (volatile evidence preserved)

INTEGRITY VERIFICATION
────────────────────────────────────────────────────────────────
MD5 Hash:           f1e2d3c4b5a69788c7d6e5f4a3b2c1d0
SHA-256 Hash:       a3f9b2c1e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2
Hash computed at:   2024-11-15 15:14 UTC
Hash computed by:   Jane Smith (SOC-4521)

TRANSFER LOG
────────────────────────────────────────────────────────────────
Date/Time          │ Released By  │ Received By  │ Reason            │ Sig
───────────────────┼──────────────┼──────────────┼───────────────────┼─────
2024-11-15 16:00   │ J. Smith     │ Evidence Rm  │ Initial storage   │ [sig]
2024-11-16 09:30   │ Evidence Rm  │ D. Jones     │ DFIR analysis     │ [sig]
2024-11-18 17:00   │ D. Jones     │ Evidence Rm  │ Analysis complete │ [sig]
2024-11-20 11:00   │ Evidence Rm  │ Legal - K.L. │ Litigation hold   │ [sig]
═══════════════════════════════════════════════════════════════
```

---

## Part 5: Common Chain of Custody Mistakes

| Mistake | Consequence | Prevention |
|---------|-------------|-----------|
| No hash computed | Cannot prove integrity | Always compute SHA-256 at collection |
| Hash computed after opening file | Integrity invalidated | Hash before any access |
| Evidence left unattended | Tampering allegation | Secure storage, transfer log |
| No timestamp on collection | Timeline disputes | Use UTC, document immediately |
| Collecting on live system without write protection | File system modified | Use write blockers |
| Allowing unauthorized access | Chain broken | Formal transfer log required |
| Using MD5 only | Collision attacks possible | Use SHA-256 minimum |
| Copy without verifying hash | May have a corrupted copy | Always verify hash post-copy |

---

## Summary Checklist

Before finishing any evidence collection:

```text
Evidence Collection Checklist
==============================
[ ] Time stamped (UTC) — system clock vs. reference clock difference noted
[ ] Volatile evidence collected BEFORE non-volatile
[ ] Write blocker in use for disk acquisition
[ ] SHA-256 hash computed immediately after collection
[ ] Chain of custody form completed with all fields
[ ] Evidence stored in secure, tamper-evident location
[ ] Transfer log initialized
[ ] Collection method documented (tool version, flags used)
[ ] Evidence directory hash manifest created
[ ] No modifications made to evidence after collection
```
