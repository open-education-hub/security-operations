# Guide 01 (Intermediate): EDR Investigation Workflow for a Compromised Endpoint

**Level:** Intermediate

**Time required:** 60 minutes

**Prerequisites:** Guides 01–03 (Basic), Demo 01, reading.md all sections

---

## Learning Objectives

By the end of this guide, you will be able to:

1. Follow a structured EDR investigation methodology from initial alert to conclusion
1. Reconstruct a complete attack timeline from endpoint telemetry
1. Identify the full scope of a compromise (patient zero, lateral movement, persistence)
1. Make evidence-based containment and remediation decisions
1. Document findings for handoff or incident report

---

## Overview: The EDR Investigation Framework

A structured approach to EDR investigations prevents missed steps and produces defensible conclusions.

```text
ALERT
  │
  ▼
TRIAGE         ← Is this real? (true/false positive)
  │
  ▼
SCOPE          ← What did the attacker do? What did they touch?
  │
  ▼
TIMELINE       ← When did each step happen? In what order?
  │
  ▼
IOC EXTRACTION ← What indicators can we hunt for fleet-wide?
  │
  ▼
CONTAINMENT    ← Stop the bleeding (isolate, kill, block)
  │
  ▼
REMEDIATION    ← Clean up, restore, harden
  │
  ▼
DOCUMENTATION  ← Write the incident report
```

---

## The Scenario

**Alert received at 14:35 UTC:**

```text
ALERT: EDR — CRITICAL
Host: WORKSTATION01.corp.local
User: corp\jdoe
Detection: "LSASS Memory Access by Unsigned Process"
Source: WinUpdate.exe (C:\Users\jdoe\AppData\Local\Temp\)
Time: 2024-03-15T14:22:01Z
Verdict: Malicious — Credential Dumping Attempt
```

This is your starting point.
You have an EDR alert.
Time to investigate.

---

## Phase 1: Triage — Is This Real?

**Time budget: 5 minutes**

### Step 1.1: Review the Alert Details

```text
Source Process: C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe
Target Process: C:\Windows\System32\lsass.exe
Access Mask: 0x1FFFFF (PROCESS_ALL_ACCESS)
Parent of Source: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Triage questions:**

* Is `WinUpdate.exe` a known application in our environment? → Check software inventory
* Is running from `%TEMP%` expected for any legitimate software? → No, never
* Does any legitimate tool request `PROCESS_ALL_ACCESS` on LSASS? → Only AV/EDR agents
* Is `powershell.exe` a normal parent for this type of process? → No

**Verdict: TRUE POSITIVE** — Confidence: 99%

**Why:** The combination of unsigned executable in `%TEMP%`, spawned from PowerShell, requesting full access to LSASS is definitively malicious.

### Step 1.2: Check the EDR Console

In a real EDR, you'd now:

1. Open the alert in the EDR console
1. Expand the incident timeline
1. Click "Show all events related to this process"
1. Check the process tree (parent → child → grandchild)

For our simulation, the events in `demos/demo-01-edr-concepts/sample_events.jsonl` represent what you'd see.

---

## Phase 2: Scope — Reconstruct the Full Attack Chain

**Time budget: 20 minutes**

### Step 2.1: Find Patient Zero Event

Work backwards from the LSASS access alert.
The question is: **How did WinUpdate.exe get onto this machine?**

```text
WinUpdate.exe (C:\...\Temp\) ← spawned by ← powershell.exe (PID 4592)
```

Where did `powershell.exe` (PID 4592) come from?

```text
powershell.exe (PID 4592) ← spawned by ← WINWORD.EXE (PID 3120)
WINWORD.EXE (PID 3120) ← opened ← invoice_march.docm
invoice_march.docm ← from ← C:\Users\jdoe\Downloads\
WINWORD.EXE ← launched by ← OUTLOOK.EXE
```

**Patient Zero:** An email with a malicious macro-enabled Word document (`invoice_march.docm`).

**MITRE Initial Access:** T1566.001 — Spearphishing Attachment

### Step 2.2: Map the Complete Kill Chain

Using all events from the sample log:

```text
T+00s  [14:20:01]  Outlook → WINWORD opens invoice_march.docm
T+14s  [14:20:15]  WINWORD → powershell.exe -enc (macro execution)
T+17s  [14:20:18]  PowerShell DNS: update.microsoft-cdn-delivery.com → 185.234.219.47
T+18s  [14:20:19]  PowerShell TCP → 185.234.219.47:443 (downloads 45KB)
T+21s  [14:20:22]  PowerShell creates WinUpdate.exe in Temp (payload dropped)
T+22s  [14:20:23]  WinUpdate.exe launches (from Temp, spawned by PowerShell)
T+24s  [14:20:25]  WinUpdate.exe → HKCU\Run\WindowsUpdateHelper (persistence)
T+27s  [14:20:28]  WinUpdate.exe copies itself to AppData\Roaming\Microsoft\
T+120s [14:22:01]  WinUpdate.exe → LSASS (PROCESS_ALL_ACCESS) — credential dump
T+154s [14:22:35]  wuhelper.exe → 185.234.219.47:443 (sends dumped credentials)
```

**Attack stages identified:**

1. Initial Access: T1566.001 (spearphishing attachment)
1. Execution: T1059.001 (malicious PowerShell macro)
1. C2 Established: T1071.001 (HTTPS C2)
1. Payload Delivered: T1105 (file downloaded to Temp)
1. Persistence: T1547.001 (Registry Run key)
1. Masquerading: T1036.005 (copy to MS-looking path)
1. Credential Access: T1003.001 (LSASS dump)
1. Exfiltration: T1041 (credentials sent to C2)

### Step 2.3: Determine the Blast Radius

Ask: **Did the attacker move laterally?**

```bash
# EDR fleet-wide query: Did any other host connect to this C2?
HUNT: network_events WHERE destination_ip = '185.234.219.47'

# Did the credential dump succeed? Were those credentials used elsewhere?
HUNT: auth_events WHERE
  source_user = 'corp\jdoe'
  AND timestamp > '2024-03-15T14:22:35Z'
  AND logon_type IN (3, 10)
  AND source_workstation != 'WORKSTATION01'

# Was the hash used for pass-the-hash?
HUNT: auth_events WHERE
  source_user = 'corp\jdoe'
  AND auth_package = 'NTLM'
  AND logon_type = 3
  AND timestamp > '2024-03-15T14:22:35Z'
```

### Step 2.4: Check for Other Affected Systems

If the attacker dumped credentials, they may use them for lateral movement within minutes.
Prioritize:

1. Any systems `jdoe` has admin rights on
1. Any high-value systems (domain controllers, file servers, databases)
1. Systems in the same network segment as WORKSTATION01

---

## Phase 3: IOC Extraction

Extract all indicators for fleet-wide hunting and blocking:

```text
NETWORK IOCs:
  IP: 185.234.219.47
  Domain: update.microsoft-cdn-delivery.com
  C2 Port: 443 (HTTPS)

FILE IOCs:
  MD5: DEADBEEFDEADBEEFDEADBEEFDEADBEEF
  SHA256: CAFEBABECAFEBABE...
  Filename: WinUpdate.exe
  Filename: wuhelper.exe

PATH IOCs:
  C:\Users\*\AppData\Local\Temp\WinUpdate.exe
  C:\Users\*\AppData\Roaming\Microsoft\wuhelper.exe

REGISTRY IOCs:
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper

BEHAVIORAL IOCs:
  WINWORD.EXE → powershell.exe -enc
  powershell.exe -nop -w hidden -enc
  Unsigned process accessing lsass.exe with 0x1FFFFF
```

---

## Phase 4: Containment

### Immediate Actions (First 10 minutes)

**1.
Isolate the Endpoint**

In an EDR console, click "Isolate Host." This:

* Cuts all network connectivity except to the EDR backend
* The endpoint can still receive investigation queries
* The attacker's C2 beacon is severed

If doing this manually:

```powershell
# Windows Firewall block all (emergency measure)
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

**2.
Kill the Malicious Process**

```powershell
# From EDR live response
taskkill /F /PID 5891  # WinUpdate.exe
taskkill /F /IM wuhelper.exe
```

**3.
Block the C2 at Network Level**

```text
Firewall rule: DENY outbound to 185.234.219.47
DNS sinkhole: update.microsoft-cdn-delivery.com → 0.0.0.0
```

**4.
Force Password Reset**

```text
jdoe's AD account: reset password immediately
Any credentials that may have been in LSASS when dumped: reset all
```

---

## Phase 5: Remediation

### Cleaning the Endpoint

```powershell
# 1. Remove malicious files (from EDR live response)
Remove-Item "C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe" -Force
Remove-Item "C:\Users\jdoe\AppData\Roaming\Microsoft\wuhelper.exe" -Force

# 2. Remove persistence (Registry Run key)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "WindowsUpdateHelper"

# 3. Verify no scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
  Select-Object TaskName, TaskPath, State

# 4. Verify no new services
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and
  $_.BinaryPathName -notlike "C:\Windows\*" -and
  $_.BinaryPathName -notlike "C:\Program Files*" }
```

### Determining Safe-to-Restore Status

Before returning the endpoint to service:

* [ ] Malicious files removed
* [ ] Persistence mechanisms removed
* [ ] No evidence of lateral movement from this host
* [ ] Credentials rotated
* [ ] OS and application patches up to date
* [ ] EDR agent health confirmed

If any lateral movement occurred: **extend investigation before restoring.**

---

## Phase 6: Documentation

### Incident Summary Template

```text
INCIDENT ID: IR-2024-0315-001
SEVERITY: Critical
STATUS: Contained / Under Remediation

TIMELINE:
  14:20:01 — Initial compromise via spearphishing email to jdoe
  14:20:15 — Malicious macro executed PowerShell payload
  14:22:01 — LSASS credential dump detected by EDR
  14:35:00 — EDR alert received by SOC
  14:41:00 — Endpoint isolated
  14:45:00 — C2 blocked at firewall

AFFECTED SYSTEMS:
  - WORKSTATION01.corp.local (confirmed compromised)
  - No lateral movement confirmed (investigation ongoing)

ROOT CAUSE:
  Spearphishing email with macro-enabled Word document

WHAT THE ATTACKER ACHIEVED:
  - Code execution on WORKSTATION01
  - Persistence via registry Run key
  - Credential dump of jdoe's LSASS (hash sent to C2)

WHAT WAS PREVENTED:
  - EDR detection before attacker used credentials
  - No confirmed lateral movement

REMEDIATION ACTIONS:
  - Endpoint isolated and cleaned
  - jdoe password reset
  - C2 IP/domain blocked
  - IOCs deployed to SIEM for fleet hunting

DETECTION GAPS:
  - Initial phishing email was not blocked by email gateway
  - Consider blocking macro-enabled documents from external email

RECOMMENDATIONS:
  - Disable macro execution from internet-sourced documents (GPO)
  - Enable Protected View enforcement
  - Add AMSI monitoring for PowerShell
```

---

## Summary: Investigation Checklist

```text
□ Alert triaged (true/false positive determination)
□ Parent process identified
□ Full process tree reconstructed
□ Initial access vector identified
□ All persistence mechanisms found
□ Network IOCs extracted (IPs, domains)
□ File IOCs extracted (hashes, paths)
□ Lateral movement checked (other hosts queried)
□ Endpoint isolated
□ Malicious processes killed
□ C2 blocked
□ Persistence cleaned
□ Credentials reset
□ Incident report drafted
□ Detection improvements identified
```
