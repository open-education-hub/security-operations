# Guide 02: Analyzing Windows Event Logs for Security Events

**Level:** Basic

**Time required:** 40 minutes

**Prerequisites:** Guide 01, reading.md Sections 5.1–5.2

---

## Learning Objectives

By the end of this guide, you will be able to:

1. Identify the most security-relevant Windows Event IDs
1. Read and interpret raw Windows Security event XML
1. Write correlation logic for common attack patterns (brute force, lateral movement)
1. Use a Docker environment to practice analyzing sample event logs

---

## Overview

Windows Event Logs are the primary data source for endpoint security monitoring in Windows environments.
This guide covers hands-on analysis of the key events you will encounter as a SOC analyst.

---

## Step 1: Windows Event Log Structure

Every Windows event has this structure:

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="..."/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>             <!-- 0=Information, 2=Error, 3=Warning -->
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2024-03-15T14:20:01.123456789Z"/>
    <EventRecordID>12345678</EventRecordID>
    <Computer>WORKSTATION01.corp.local</Computer>
  </System>
  <EventData>
    <!-- Event-specific fields here -->
    <Data Name="FieldName">Value</Data>
    ...
  </EventData>
</Event>
```

**Key System fields:**

* `EventID` — the event type (most important for filtering)
* `TimeCreated` — when the event occurred (always in UTC)
* `Computer` — which system generated it

---

## Step 2: Event ID 4624 — Successful Logon

### Full Event Analysis

```xml
<EventData>
  <!-- Who was already logged in (the session doing the logon) -->
  <Data Name="SubjectUserSid">S-1-5-18</Data>
  <Data Name="SubjectUserName">WORKSTATION01$</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3e7</Data>

  <!-- The new logon being created -->
  <Data Name="TargetUserSid">S-1-5-21-...1001</Data>
  <Data Name="TargetUserName">jdoe</Data>
  <Data Name="TargetDomainName">CORP</Data>
  <Data Name="TargetLogonId">0x1a2b3c</Data>

  <!-- MOST IMPORTANT: Logon Type -->
  <Data Name="LogonType">3</Data>

  <!-- Network information (for Type 3, 10) -->
  <Data Name="IpAddress">10.10.5.22</Data>
  <Data Name="IpPort">54231</Data>
  <Data Name="WorkstationName">LAPTOP-HR01</Data>

  <Data Name="LogonProcessName">NtLmSsp</Data>
  <Data Name="AuthenticationPackageName">NTLM</Data>
  <Data Name="TransmittedServices">-</Data>
  <Data Name="LmPackageName">NTLM V2</Data>
  <Data Name="KeyLength">128</Data>
  <Data Name="ProcessId">0x0</Data>
  <Data Name="ProcessName">-</Data>
</EventData>
```

### Analysis Checklist for Event 4624

When you see a 4624, ask:

| Question | Where to Look | Red Flag |
|----------|---------------|----------|
| What logon type? | `LogonType` field | Type 3 from external IP, Type 8, Type 10 at unusual hours |
| Who logged in? | `TargetUserName` | Service accounts, disabled accounts, admin accounts |
| From where? | `IpAddress`, `WorkstationName` | External IPs, unusual workstations |
| How authenticated? | `AuthenticationPackageName` | NTLM on a Kerberos environment = possible pass-the-hash |
| At what time? | `TimeCreated` | Outside business hours |

### Exercise 2.1 — Analyze This Event

```text
EventID: 4624
TimeCreated: 2024-03-15T03:47:22Z (3:47 AM)
TargetUserName: administrator
LogonType: 10
IpAddress: 185.234.219.47
AuthenticationPackageName: NTLM
WorkstationName: KALI
```

**Your analysis:** What's suspicious here?
(Answer at bottom of guide)

---

## Step 3: Event ID 4625 — Failed Logon

### Key Fields for Brute Force Detection

```xml
<EventData>
  <Data Name="TargetUserName">administrator</Data>
  <Data Name="TargetDomainName">CORP</Data>
  <Data Name="FailureReason">%%2313</Data>  <!-- Wrong password -->
  <Data Name="Status">0xc000006d</Data>
  <Data Name="SubStatus">0xc000006a</Data>
  <Data Name="LogonType">3</Data>
  <Data Name="IpAddress">185.234.219.47</Data>
  <Data Name="IpPort">0</Data>
</EventData>
```

**Failure Reason Codes:**

| SubStatus | Meaning | Security Significance |
|-----------|---------|----------------------|
| 0xc000006a | Wrong password | Brute force / typo |
| 0xc0000064 | User does not exist | User enumeration |
| 0xc0000234 | Account locked out | Lockout policy in effect |
| 0xc0000072 | Account disabled | Testing disabled accounts |
| 0xc000006f | Logon outside hours | Policy violation or bypass attempt |

### Brute Force Detection Rules

**Rule 1: Standard Brute Force**

```text
Condition: 10+ Event 4625 from same IpAddress within 5 minutes
Action: Alert MEDIUM severity
Context: All failed against same user → targeted attack
```

**Rule 2: Password Spray**

```text
Condition: 3+ Event 4625 with different TargetUserName from same IpAddress within 10 minutes
Action: Alert HIGH severity
Context: Low-and-slow against many users → avoids lockout policy
```

**Rule 3: Brute Force Success**

```text
Condition: Event 4624 (success) immediately following 5+ Event 4625 (failures) from same IpAddress
Action: Alert CRITICAL severity
Context: Attack succeeded — immediate investigation required
```

---

## Step 4: Event ID 4688 — Process Creation

### Enabling Full Command Line

> By default on most Windows systems, the `CommandLine` field is blank. Enable it:
> `Group Policy → Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Detailed Tracking → Audit Process Creation`
> AND:
> `Group Policy → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`

### Anatomy of a Suspicious 4688

```xml
<EventData>
  <Data Name="SubjectUserName">jdoe</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="NewProcessId">0x11f0</Data>   <!-- 4592 decimal -->
  <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="TokenElevationType">%%1937</Data>  <!-- Full token = admin -->
  <Data Name="ProcessId">0xc30</Data>       <!-- 3120 decimal = parent -->
  <Data Name="CommandLine">powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA==</Data>
  <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
</EventData>
```

### Detection Rules for Event 4688

**Rule 1: Office Spawns Scripting Engine**

```sql
-- SIEM query (pseudo-SQL)
SELECT * FROM windows_events
WHERE EventID = 4688
AND ParentProcessName LIKE '%\WINWORD.EXE'
   OR ParentProcessName LIKE '%\EXCEL.EXE'
   OR ParentProcessName LIKE '%\POWERPNT.EXE'
AND (NewProcessName LIKE '%\powershell.exe'
  OR NewProcessName LIKE '%\cmd.exe'
  OR NewProcessName LIKE '%\wscript.exe'
  OR NewProcessName LIKE '%\mshta.exe')
```

**Rule 2: PowerShell with Encoding/Obfuscation Flags**

```sql
SELECT * FROM windows_events
WHERE EventID = 4688
AND NewProcessName LIKE '%\powershell.exe'
AND (CommandLine LIKE '%-enc%'
  OR CommandLine LIKE '%-EncodedCommand%'
  OR CommandLine LIKE '%-nop%'
  OR CommandLine LIKE '%-w hidden%')
```

**Rule 3: Execution from Temp/AppData**

```sql
SELECT * FROM windows_events
WHERE EventID = 4688
AND (NewProcessName LIKE '%\Temp\%'
  OR NewProcessName LIKE '%\AppData\%')
AND NewProcessName LIKE '%.exe'
```

---

## Step 5: Event ID 4698 — Scheduled Task Created

### Full Event Analysis

```xml
<EventData>
  <Data Name="SubjectUserName">jdoe</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="TaskName">\Microsoft\Windows\WindowsUpdate\Scheduled Start</Data>
  <Data Name="TaskContent">
    &lt;Task&gt;
      &lt;Actions&gt;
        &lt;Exec&gt;
          &lt;Command&gt;C:\Users\jdoe\AppData\Roaming\Microsoft\wuhelper.exe&lt;/Command&gt;
        &lt;/Exec&gt;
      &lt;/Actions&gt;
      &lt;Triggers&gt;
        &lt;LogonTrigger&gt;
          &lt;Enabled&gt;true&lt;/Enabled&gt;
        &lt;/LogonTrigger&gt;
      &lt;/Triggers&gt;
      &lt;Principals&gt;
        &lt;Principal&gt;
          &lt;UserId&gt;CORP\jdoe&lt;/UserId&gt;
          &lt;RunLevel&gt;HighestAvailable&lt;/RunLevel&gt;
        &lt;/Principal&gt;
      &lt;/Principals&gt;
    &lt;/Task&gt;
  </Data>
</EventData>
```

**Red flags in this task:**

1. Task name mimics a legitimate Microsoft task (`WindowsUpdate\Scheduled Start`)
1. Executable is in `AppData\Roaming\Microsoft\` — user-writable location
1. Trigger is `LogonTrigger` — fires every time this user logs in (persistence!)
1. Created by a regular user (`jdoe`), not IT/admin

### Detection Approach

```sql
SELECT * FROM windows_events
WHERE EventID = 4698
AND TaskContent LIKE '%AppData%'
   OR TaskContent LIKE '%Temp%'
   OR TaskContent LIKE '%ProgramData%'
```

---

## Step 6: Event ID 7045 — New Service Installed

```xml
<!-- This event is in the System log, not Security -->
<EventData>
  <Data Name="ServiceName">WindowsFontService</Data>
  <Data Name="ServiceFileName">C:\Windows\Temp\svch0st.exe</Data>
  <Data Name="ServiceType">user mode service</Data>
  <Data Name="ServiceStartType">auto start</Data>
  <Data Name="ServiceAccount">LocalSystem</Data>
</EventData>
```

**Red flags:**

1. Service name looks legitimate but is slightly different from real (`svchost` → `svch0st`)
1. Binary in `C:\Windows\Temp\` — not a normal Windows service location
1. Runs as `LocalSystem` — maximum privilege
1. `auto start` — runs every reboot

---

## Step 7: Hands-On Practice with Docker

### Run the Log Analysis Environment

```console
# From the guide directory
docker run --rm -it -v $(pwd)/sample_logs:/logs python:3.11-slim bash

# Install analysis tools
pip install python-evtx rich

# Analyze the sample Windows Security log
python3 /logs/analyze_windows_events.py
```

### Sample Event Log File

The file `sample_security_events.jsonl` in this directory contains 50 realistic Windows Security events including:

* Normal authentication (Type 2 and Type 3)
* A simulated brute force attack
* Malicious process creation
* Scheduled task persistence

### Analysis Questions

1. How many unique source IPs attempted authentication?
1. Which account was targeted in the brute force?
1. Did the brute force succeed?
1. What suspicious processes were created?
1. Was any persistence established?

---

## Exercise 2.1 Answer

**Event analyzed:**

```text
EventID: 4624, TimeCreated: 3:47 AM, TargetUserName: administrator
LogonType: 10, IpAddress: 185.234.219.47, AuthenticationPackageName: NTLM
WorkstationName: KALI
```

**Analysis:**

* **3:47 AM** — outside normal business hours (anomalous)
* **administrator account** — high-privilege, should be monitored closely
* **LogonType 10** — Remote Interactive (RDP login)
* **External IP (185.234.219.47)** — not a corporate IP range; public internet
* **NTLM authentication** — RDP typically uses Kerberos in a corporate environment; NTLM suggests possible pass-the-hash or direct credential use
* **Workstation name "KALI"** — Kali Linux is a penetration testing OS; legitimate users don't connect from Kali

**Verdict:** This is almost certainly malicious.
An attacker gained the administrator password (or hash) and is connecting via RDP from an external IP using a Kali Linux machine, at 3 AM.

**Response actions:**

1. Immediately isolate the target system
1. Disable the administrator account (or at minimum change the password)
1. Block the source IP at the firewall
1. Identify how the credentials were obtained
1. Check all systems for similar logons from this IP

---

## Summary

| Event ID | What It Detects | Key Fields |
|---------|----------------|------------|
| 4624 | Successful logon | LogonType, IpAddress, AuthenticationPackageName |
| 4625 | Failed logon | FailureReason, SubStatus, IpAddress |
| 4688 | Process created | NewProcessName, CommandLine, ParentProcessName |
| 4698 | Scheduled task created | TaskName, TaskContent |
| 7045 | New service | ServiceFileName, ServiceAccount |
| 4719 | Audit policy change | AuditPolicyChanges |

**Next Guide:** Guide 03 — Setting Up Linux Security Monitoring with auditd
