# Drill 01 (Intermediate) — Windows Incident Response

## Scenario

You are a SOC analyst at **Meridian Financial Services**.
At 14:32 UTC, the SIEM triggered an alert:

> **Alert**: Credential dumping tool detected on `WKS-FINANCE-07`
> **Source**: Windows Defender — Event ID 1116 (Malware Detected)
> **Host**: WKS-FINANCE-07 (Windows 10, Finance department)
> **User at time of alert**: `jdavis` (Finance Analyst)

A follow-up alert fired 8 minutes later:

> **Alert**: Lateral movement detected — new logon from `WKS-FINANCE-07` to `FS-CORP-01` (file server)
> **Event ID**: 4624 (Type 3 — Network Logon)
> **Account**: `svc_backup` (service account)

Your task is to perform a structured incident response investigation using the simulated evidence environment.
Determine:

1. How was `jdavis`'s session compromised?
1. What tools were used and what was accessed?
1. How did the attacker pivot to `svc_backup`?
1. What persistence was established?
1. What is the full attack timeline?

**Estimated time:** 45–60 minutes

**Difficulty:** Intermediate

**Prerequisites:** Completed basic drills; familiarity with Windows Event IDs, PowerShell, and lateral movement concepts.

---

## Environment Setup

```console
docker compose up -d
docker exec -it win-incident-01 pwsh
```

Once inside the container, load the drill scenario:

```powershell
. /drill/scripts/load-incident.ps1
Show-DrillIntro
```

---

## Evidence Sources Available

| Source | Location in Container | Description |
|--------|-----------------------|-------------|
| Security Event Log | `/drill/logs/Security.evtx.json` | 4624, 4625, 4648, 4688, 4697, 7045 events |
| Sysmon Log | `/drill/logs/Sysmon.evtx.json` | Process creation, network connections, file creates |
| PowerShell Log | `/drill/logs/PowerShell.evtx.json` | Script block logging (Event ID 4104) |
| Prefetch artifacts | `/drill/artifacts/prefetch/` | Simulated prefetch entries |
| Registry export | `/drill/artifacts/registry/` | Run keys, services, SAM-related keys |
| Network connections | `/drill/artifacts/netstat.txt` | Snapshot of connections at time of alert |
| Running processes | `/drill/artifacts/processes.txt` | `ps`-style snapshot at alert time |
| File system timeline | `/drill/artifacts/mft_timeline.csv` | MFT-based timeline (simulated) |

---

## Tasks

### Task 1: Initial Access — How Was `jdavis` Compromised?

Examine the Security and Sysmon logs around the time of the alert.

```powershell
# Load and search Security events
$events = Get-Content /drill/logs/Security.evtx.json | ConvertFrom-Json
$events | Where-Object { $_.EventID -eq 4688 } | Select-Object -First 20 | Format-Table TimeCreated, SubjectUserName, NewProcessName, CommandLine -Wrap

# Examine PowerShell script block logs
$ps = Get-Content /drill/logs/PowerShell.evtx.json | ConvertFrom-Json
$ps | Where-Object { $_.EventID -eq 4104 } | Select-Object TimeCreated, ScriptBlockText | Format-List
```

**Questions:**

1. What process executed just before the Defender alert at 14:32?
1. Was there a suspicious document or file opened by `jdavis` prior to credential dumping activity?
1. What was the parent process of the suspicious activity?

---

### Task 2: Credential Dumping — What Was Taken?

Investigate the credential dumping activity.

```powershell
# Look for LSASS access in Sysmon logs (Event ID 10 — Process Access)
$sysmon = Get-Content /drill/logs/Sysmon.evtx.json | ConvertFrom-Json
$sysmon | Where-Object { $_.EventID -eq 10 -and $_.TargetImage -like "*lsass*" } | Format-List

# Check for known credential dumping tools in process creation (Event ID 1)
$sysmon | Where-Object { $_.EventID -eq 1 } | Where-Object {
    $_.Image -match "procdump|mimikatz|wce|fgdump|pwdump|comsvcs" -or
    $_.CommandLine -match "sekurlsa|lsass|minidump"
} | Format-List TimeCreated, Image, CommandLine, ParentImage
```

**Questions:**

1. Which tool or technique was used to dump credentials from LSASS?
1. What was the full command line used?
1. Was the dump file written to disk? If so, where?
1. What MITRE ATT&CK technique ID covers this activity?

---

### Task 3: Lateral Movement — Pivoting to `svc_backup`

Trace how the attacker moved from `WKS-FINANCE-07` to `FS-CORP-01`.

```powershell
# Find all logon events for svc_backup
$events | Where-Object { $_.EventID -in @(4624, 4648) -and $_.TargetUserName -eq "svc_backup" } |
    Format-Table TimeCreated, EventID, LogonType, IpAddress, AuthenticationPackage -Wrap

# Look for network connections around the time of lateral movement
Get-Content /drill/artifacts/netstat.txt

# Examine MFT timeline for access to network shares
Import-Csv /drill/artifacts/mft_timeline.csv | Where-Object { $_.FileName -match "\\\\FS-CORP" } | Format-Table
```

**Questions:**

1. What logon type was used for the lateral movement to `FS-CORP-01`?
1. How did the attacker obtain `svc_backup` credentials? (Hint: look at the LSASS dump contents and the credential in use)
1. What authentication protocol was negotiated? (NTLM vs Kerberos — check the `AuthenticationPackage` field)
1. What was accessed on `FS-CORP-01`?

---

### Task 4: Persistence — Establishing a Foothold

Identify any persistence mechanisms the attacker put in place.

```powershell
# Check registry Run keys
$regRun = Get-Content /drill/artifacts/registry/run_keys.json | ConvertFrom-Json
$regRun | Format-List

# Check for new services (Event ID 7045)
$events | Where-Object { $_.EventID -eq 7045 } | Format-List TimeCreated, ServiceName, ImagePath, ServiceType, StartType

# Check for new scheduled tasks (Event ID 4698)
$events | Where-Object { $_.EventID -eq 4698 } | Format-List TimeCreated, SubjectUserName, TaskName, TaskContent

# Check Sysmon for dropped files
$sysmon | Where-Object { $_.EventID -eq 11 } | Where-Object {
    $_.TargetFilename -match "\\AppData\\|\\Temp\\|\\Windows\\Temp\\"
} | Format-Table TimeCreated, Image, TargetFilename
```

**Questions:**

1. Was a new Windows service installed? If so, what was its name and binary path?
1. Was a scheduled task created? What does it execute and when?
1. Was a registry Run key added? Under which key and for which user?
1. What payload/tool was planted for persistence?

---

### Task 5: Timeline Reconstruction

Build a complete attack timeline from initial access to persistence.

```powershell
# Use the built-in timeline helper
Invoke-DrillTimeline

# Or manually correlate:
$allEvents = @(
    ($events | Select-Object TimeCreated, EventID, @{N='Source';E={'Security'}}, @{N='Detail';E={"$($_.SubjectUserName) → $($_.NewProcessName)$($_.TargetUserName)"}}),
    ($sysmon | Select-Object TimeCreated, EventID, @{N='Source';E={'Sysmon'}}, @{N='Detail';E={"$($_.Image) → $($_.TargetFilename)$($_.DestinationIp)"}})
) | Sort-Object TimeCreated

$allEvents | Where-Object { $_.TimeCreated -gt "2024-01-15T14:20:00" } | Format-Table -Wrap
```

**Questions:**

1. What was the first malicious event in the timeline?
1. How long elapsed between initial compromise and credential dumping?
1. How long between credential dumping and lateral movement?
1. Map each stage to the MITRE ATT&CK Kill Chain phase.

---

### Task 6: Incident Report — IOCs and Remediation

Compile findings and recommend remediation.

```powershell
# Generate a summary using the drill helper
Invoke-DrillReport
```

**Questions:**

1. List all **Indicators of Compromise (IOCs)**: file hashes/names, IPs, registry keys, service names.
1. Which accounts were compromised or used by the attacker?
1. What immediate containment steps should be taken?
1. What long-term hardening recommendations would prevent recurrence?

---

## Scoring

| Task | Points | Description |
|------|--------|-------------|
| Task 1 | 15 | Correctly identifies initial access vector |
| Task 2 | 20 | Identifies credential dumping tool, command, and file |
| Task 3 | 20 | Traces lateral movement, auth protocol, accessed resources |
| Task 4 | 20 | Finds all three persistence mechanisms |
| Task 5 | 15 | Constructs accurate timeline with MITRE mapping |
| Task 6 | 10 | Complete IOC list and actionable remediation |
| **Total** | **100** | |

---

## Hints

* **Task 1**: Check Event ID 4688 (process creation) with CommandLine logging enabled. Look for Office or PDF processes spawning cmd/powershell.
* **Task 2**: `comsvcs.dll` with `MiniDump` is a LOLBin technique for LSASS dumping — no external tool needed.
* **Task 3**: Type 3 logon (network) using NTLM suggests pass-the-hash. Type 2 (interactive) using Kerberos suggests pass-the-ticket.
* **Task 4**: Attackers often install persistence in multiple locations simultaneously. Check all three vectors.
* **Task 5**: Sort by timestamp. The first malicious event predates the Defender alert by several minutes.
