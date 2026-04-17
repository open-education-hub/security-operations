# Demo 01: Developing a Threat Hunting Hypothesis from Threat Intelligence

**Duration:** ~30 minutes

**Difficulty:** Intermediate

**Prerequisites:** Reading material sections 1-6, basic familiarity with SIEM concepts

---

## Overview

In this demo, we walk through the complete process of converting a published threat intelligence report into a structured, testable hunting hypothesis, and then translating that hypothesis into concrete queries.

We will use a realistic scenario based on common threat actor activity: a financial sector organization receives a threat intelligence report about a financially-motivated APT group using PowerShell Empire and Living-off-the-Land techniques.

---

## Scenario: FIN-STORM Threat Actor Activity

You are a threat hunter at **SecureBank Corp**.
Your threat intelligence team has shared the following alert (TLP:AMBER):

> **FLASH REPORT - FIN-STORM Activity in Financial Sector**
> Date: March 2024
> TLP: AMBER
>
> The FIN-STORM group has been observed targeting financial institutions in Western Europe. Initial access is typically achieved via spear-phishing emails containing macro-enabled Office documents. Post-exploitation activity includes:
>
> - PowerShell-based staging (base64-encoded commands, AMSI bypass)
> - Credential harvesting via LSASS memory dump (Mimikatz variants)
> - Lateral movement using WMI and PsExec alternatives
> - Data staging in C:\ProgramData\Microsoft\Crypto\
> - Exfiltration over HTTPS to attacker-controlled infrastructure
>
> **Observed IOCs (as of report date):**
> - C2 IPs: 192.0.2.15, 198.51.100.22
> - Domains: update-secure-cdn[.]com, auth-verify-portal[.]net
> - File hashes (SHA256):
>   - `a3f5c2e1d9b4...` (macro dropper)
>   - `7c89d3a2f1e4...` (PowerShell loader)

---

## Step 1: Analyze the Threat Intelligence Report

Before forming hypotheses, extract the key information:

### Threat Actor Profile Summary

| Element | Details |
|---------|---------|
| Actor Name | FIN-STORM |
| Motivation | Financial |
| Target Sector | Financial institutions |
| Geography | Western Europe |

### TTP Extraction (Map to ATT&CK)

| Observed Behavior | ATT&CK Technique | Tactic |
|-------------------|-----------------|--------|
| Spear-phishing with macro documents | T1566.001 | Initial Access |
| PowerShell with base64 encoding | T1059.001 | Execution |
| AMSI bypass | T1562.001 | Defense Evasion |
| LSASS dump / Mimikatz | T1003.001 | Credential Access |
| WMI-based lateral movement | T1047 | Lateral Movement |
| PsExec alternative | T1021.002 | Lateral Movement |
| Staging in C:\ProgramData | T1074.001 | Collection |
| HTTPS exfiltration | T1048.002 | Exfiltration |

### Intelligence Assessment

* **Confidence:** High (multiple confirmed incidents)
* **Relevance to SecureBank:** High (same sector, same geography)
* **IOC Freshness:** Current (report dated today)
* **TTP Validity:** These TTPs have been consistent across 6 months of observations

---

## Step 2: Prioritize Hunting Targets

Not all TTPs are equally huntable.
Evaluate each:

| TTP | Huntability | Data Sources Available | Priority |
|-----|-------------|----------------------|----------|
| PS with base64 | High | Windows Event Logs, PS Logs | 1 |
| LSASS dump | High | Sysmon, EDR | 2 |
| WMI lateral movement | High | Sysmon, Security Logs | 3 |
| AMSI bypass | Medium | PS Script Block Logs | 4 |
| Data staging in ProgramData | Medium | Sysmon File Create | 5 |
| Spear-phishing delivery | Low (reactive) | Email logs | 6 |
| HTTPS exfiltration | Low (needs DLP) | Firewall/proxy logs | 7 |

**Decision:** We will hunt for TTPs 1, 2, and 3 as our primary targets.

---

## Step 3: Form Structured Hypotheses

### Hypothesis 1: PowerShell-Based Staging Activity

**Hypothesis Statement:**
> "If FIN-STORM actors have established a foothold in our environment and are using PowerShell for staging (T1059.001), I would expect to find PowerShell processes executing with encoded command parameters, possibly spawned by Office applications, present in Windows Security Event Logs (Event ID 4688) and PowerShell Operational Logs (Event ID 4104) on workstations in the past 7 days."

**Testable predictions:**

* PowerShell processes with `-EncodedCommand`, `-enc`, or `-ec` flags
* PowerShell spawned by `winword.exe`, `excel.exe`, or `outlook.exe`
* PowerShell with `-WindowStyle Hidden` or `-NonInteractive`
* PowerShell making outbound connections (unusual for most workstations)

**Data sources:**

* Windows Security Event Log: Event ID 4688 (Process Creation, with command line logging enabled)
* PowerShell Operational Log: Event ID 4103, 4104
* Sysmon Event ID 1 (ProcessCreate), Event ID 3 (NetworkConnect)

```text
# Splunk query for Hypothesis 1
index=wineventlog EventCode=4688
  (CommandLine="*powershell*" OR CommandLine="*pwsh*")
  (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-ec *")
| eval parent=ParentProcessName
| stats count by parent, CommandLine, ComputerName
| sort count asc

# Sysmon variant
index=sysmon EventID=1
  (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  (CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*hidden*")
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR
   ParentImage="*\\outlook.exe" OR ParentImage="*\\WINWORD.EXE")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

---

### Hypothesis 2: LSASS Memory Access (Credential Harvesting)

**Hypothesis Statement:**
> "If FIN-STORM actors are attempting credential harvesting via LSASS memory access (T1003.001), I would expect to find processes accessing LSASS memory with suspicious permissions in Sysmon Event ID 10 (ProcessAccess) logs on servers and privileged workstations in the past 7 days."

**Testable predictions:**

* Non-system processes accessing lsass.exe with read/all-access rights
* Access rights: 0x1fffff (full), 0x1410, 0x143a (common Mimikatz access masks)
* Unusual processes targeting LSASS (not known security tools)

**Data sources:**

* Sysmon Event ID 10 (ProcessAccess)
* Windows Security Event ID 4656 (Object access, if SACL configured)

```text
# Splunk - LSASS access hunt
index=sysmon EventID=10 TargetImage="*\\lsass.exe"
| where NOT (SourceImage IN (
    "*\\MsMpEng.exe",       -- Windows Defender
    "*\\SenseIR.exe",       -- Defender for Endpoint
    "*\\csrss.exe",         -- System
    "*\\wininit.exe"        -- System
  ))
| eval suspicious_access=if(match(GrantedAccess, "0x1fffff|0x1410|0x143a|0x40"), "YES", "REVIEW")
| stats count by SourceImage, GrantedAccess, suspicious_access, ComputerName
| sort - suspicious_access, count
```

---

### Hypothesis 3: WMI-Based Lateral Movement

**Hypothesis Statement:**
> "If FIN-STORM actors are using WMI for lateral movement (T1047), I would expect to find wmiprvse.exe spawning child processes (particularly cmd.exe or PowerShell) on servers or privileged workstations, which would appear in Sysmon Event ID 1 logs with wmiprvse.exe as the parent process."

**Testable predictions:**

* `wmiprvse.exe` spawning `cmd.exe`, `powershell.exe`, or other suspicious processes
* `wmic.exe` being executed with `/node:` parameter (remote execution)
* WMI activity outside of normal business hours

**Data sources:**

* Sysmon Event ID 1 (ProcessCreate)
* Windows Security Event ID 4688

```text
# WMI lateral movement hunt
index=sysmon EventID=1
  ParentImage="*\\wmiprvse.exe"
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage, ParentCommandLine
| sort _time desc

# WMIC remote execution hunt
index=sysmon EventID=1 Image="*\\wmic.exe"
  CommandLine="*/node:*"
| table _time, ComputerName, User, CommandLine
```

---

## Step 4: Define the Hunt Scope and Plan

| Parameter | Value |
|-----------|-------|
| Hunt ID | HUNT-2024-015 |
| Trigger | FIN-STORM threat intelligence report |
| Start Date | 2024-03-15 |
| Time Window | Last 30 days |
| Scope | All Windows workstations and servers |
| Priority | HIGH |
| Hunter | Primary analyst |
| Estimated Duration | 4-6 hours |

### Data Availability Check

Before executing the hunt, verify data sources are available:

```bash
# Splunk - check data source availability
| metadata type=sourcetypes
| where totalCount > 0
| table sourcetype, recentTime, totalCount

# Check Sysmon coverage
index=sysmon
| stats count by host
| where count < 100  # Identify hosts with low Sysmon data (possible gaps)
| sort count asc
```

**Expected data sources for this hunt:**

* [ ] Windows Security Event Logs (Event ID 4688 - requires audit process creation with command line)
* [ ] PowerShell Operational Logs (Event ID 4104 - requires PS script block logging)
* [ ] Sysmon (Event ID 1, 3, 10 - requires Sysmon deployment)

---

## Step 5: IOC Hunting (Parallel Track)

While TTP hunting runs in parallel, also hunt for the specific IOCs from the report:

```text
# Hunt for C2 IP connections
index=network_logs OR index=firewall
  (dest_ip="192.0.2.15" OR dest_ip="198.51.100.22")
| table _time, src_ip, src_host, dest_ip, dest_port, bytes_out, action
| sort _time desc

# Hunt for malicious domains (DNS logs)
index=dns
  (query="update-secure-cdn.com" OR query="auth-verify-portal.net")
| table _time, src_ip, src_host, query, answer
| sort _time desc

# Hunt for file hashes (if EDR data available)
index=edr event_type=file_creation
  (sha256="a3f5c2e1d9b4*" OR sha256="7c89d3a2f1e4*")
| table _time, hostname, user, file_path, sha256
```

---

## Step 6: Document the Hunt

### Hunt Log Entry

```markdown
# HUNT-2024-015

## Status: IN PROGRESS
## Hunter: [Your Name]
## Date Started: 2024-03-15

## Trigger
FIN-STORM flash report (TLP:AMBER) received from threat intelligence team.
Actor targeting financial institutions in Western Europe with PS-based TTPs.

## Hypotheses
1. PowerShell encoded command execution (T1059.001)

2. LSASS memory access for credential harvesting (T1003.001)
3. WMI-based lateral movement (T1047)

## Scope
- Time window: 2024-02-14 to 2024-03-15 (30 days)
- Systems: All Windows hosts (1,247 workstations, 89 servers)
- Data sources: Sysmon, Windows Security Events, PowerShell Operational

## Queries Executed
[Attached: hunt-2024-015-queries.txt]

## Preliminary Findings
- Hypothesis 1: 3 PowerShell encoded command instances found on FIN-WS-045
  - All 3 attributed to legitimate IT automation script (confirmed with IT)
  - No Office parent processes found
  - FINDING: Gap identified - PS command line logging not enabled on 23 servers

- Hypothesis 2: No suspicious LSASS access found
  - One alert from security tool (MsMpEng.exe) - expected

- Hypothesis 3: WMI spawning cmd.exe found on DB-SRV-02
  - PENDING: Investigating with DBA team - may be legitimate maintenance

## Outcome (In Progress)
- Likely negative hunt (no active compromise)
- Gap identified: PS command line audit not universal
- Pending: Verify WMI finding on DB-SRV-02

## Follow-up Actions
- [ ] Enable PowerShell command line logging on 23 servers (ticket: IT-4421)
- [ ] Create detection rule for encoded PS from Office parents
- [ ] Verify DB-SRV-02 WMI activity with DBA team
```

---

## Key Takeaways

1. **Threat intelligence drives hypothesis formation** — Don't hunt randomly; use threat intelligence to prioritize
1. **Map TTPs to ATT&CK** — This provides structure and links to hunting playbooks
1. **Prioritize by huntability** — Some TTPs are easier to hunt than others given your data sources
1. **Structure your hypotheses** — A good hypothesis specifies: actor, technique, expected evidence, data source
1. **Document everything** — Even negative hunts are valuable; document gaps and improvements
1. **Parallel track IOCs** — Quick wins from IOC hunting can confirm or deny active compromise while TTP hunting runs

---

## Practice Exercises

1. Using the FIN-STORM report, write a hypothesis for the data staging TTP (T1074.001). What data sources would you use? What queries?

1. The report mentions AMSI bypass (T1562.001). Research how AMSI bypass typically appears in PowerShell script block logs. Write a Splunk query to detect it.

1. Create a hunt plan for detecting the HTTPS exfiltration TTP. What challenges would you face? What data sources would you need?
