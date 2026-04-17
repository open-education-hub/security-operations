# Drill 01 Intermediate Solution: Data-Driven Threat Hunt

---

## Task 1: Stack Count Analysis

### Suspicious Parent-Child Relationships

| Parent → Child | Count | Threat Level | Why Suspicious | ATT&CK | Legitimate Explanation |
|----------------|-------|-------------|----------------|--------|------------------------|
| WINWORD.EXE → powershell.exe | 1 | **CRITICAL** | Office spawning PowerShell is a primary macro/phishing indicator | T1566.001, T1059.001 | Extremely rare legitimate scenario (macro automation script - should be reviewed) |
| mshta.exe → powershell.exe | 4 | **HIGH** | mshta.exe is a LOLBin; spawning PS indicates code exec | T1218.005 | None legitimate in corporate environment |
| mshta.exe → cmd.exe | 1 | **HIGH** | Same as above | T1218.005 | None |
| WINWORD.EXE → cmd.exe | 3 | **HIGH** | Word spawning cmd.exe = macro execution | T1566.001, T1059.003 | Some mail merge automation, but unusual |
| regsvr32.exe → cmd.exe | 2 | **HIGH** | Regsvr32 spawning shells = possible Squiblydoo | T1218.010 | Extremely rare |
| wscript.exe → powershell.exe | 8 | **HIGH** | WSH script downloading/executing PS | T1059.001, T1059.005 | Rare legitimate scripting |
| wscript.exe → cmd.exe | 18 | **MEDIUM** | WSH scripts are sometimes legitimate | T1059.005 | Batch automation scripts |
| OUTLOOK.EXE → powershell.exe | 23 | **MEDIUM-HIGH** | Email attachment execution | T1566.001 | Macro-enabled email automation (unusual) |
| OUTLOOK.EXE → cmd.exe | 45 | **MEDIUM** | Higher count but still suspicious | T1566.001 | Some email-triggered scripts |
| svchost.exe → cmd.exe | 3 | **MEDIUM** | Service host spawning shell | T1055, T1569 | Some Windows services do this |

**Top 3 to investigate first:**

1. **WINWORD.EXE → powershell.exe (count=1)** - Critical because this is a very specific, high-fidelity indicator of macro execution with PowerShell. The count of 1 means it happened on exactly one machine - easy to investigate. This could be the initial compromise indicator.

1. **mshta.exe → powershell.exe (count=4)** - High confidence indicator of LOLBin execution. MSHTA rarely has any legitimate use in enterprise environments. 4 events across likely few hosts means manageable investigation scope.

1. **OUTLOOK.EXE → powershell.exe (count=23)** - High volume from Outlook is a significant concern as it suggests either a recurring malicious activity or a widespread misconfigured automation. Either way needs investigation.

---

## Task 2: PowerShell Investigation

### Event #1 Analysis
**Assessment: MALICIOUS (CRITICAL)**

* **Suspicious indicators:**
  * Parent: WINWORD.EXE — Office application spawning PowerShell = almost always malicious
  * `-WindowStyle hidden` — hides execution from user
  * `-exec bypass` — bypasses execution policy controls
  * `-enc` (base64 encoded command) — obfuscation
  * Network connection 5 seconds after launch to 198.51.100.88:443

* **Base64 decode of command:**

  ```text
  SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0
  ACAATQBJAFQAQQBDAE8ATQAuAFMAaABlAGwAbAAuAEEAcABwAGwAaQBjAGEAdABpAG8AbgApAC4A
  UQBVAFQATQ==
```

  Decoded (UTF-16LE): `Invoke-Expression (New-Object MITACOM.Shell.Application).QUTML`
  (This is a simplified example; real Base64 would decode to actual C2 download code)

* **ATT&CK:** T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1027 (Obfuscated Files), T1204.002 (User Execution: Malicious File)

* **Additional evidence needed:** Email logs for tjones on 2024-03-12 (what email triggered this?), file system for recently opened Word documents, EDR process tree.

### Event #2 Analysis
**Assessment: MALICIOUS (related to Event #1)**

* Discovery commands run by the compromised PowerShell session
* `whoami & net user & net localgroup administrators` = classic post-exploitation discovery
* ATT&CK: T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1033 (System Owner/User Discovery)

### Event #3 Analysis
**Assessment: MALICIOUS (related to Events #1 and #2)**

* Downloads and executes a second-stage payload
* `IEX (New-Object Net.WebClient).DownloadString(...)` = in-memory execution, avoids file on disk
* Downloads from same C2 as Event #1 (198.51.100.88)
* ATT&CK: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1086

### Event #4 Analysis
**Assessment: SUSPICIOUS (requires investigation)**

* Parent is OUTLOOK.EXE, which is unusual (spawning PowerShell from email client)
* However: script is on local disk, no network connection, ran for 3 minutes and exited normally
* Additional evidence needed: What is the content of `invoice_automation.ps1`? Is it in your IT change management system as an approved script? Who created it and when? What does the process tree look like?
* Likely: An employee received a legitimate email with an attached automation script, or this is a test. But it MUST be investigated.

### Event #5 Analysis
**Assessment: BENIGN (with documentation)**

* `Import-Module Az; Connect-AzAccount` is the standard Azure PowerShell login command
* Connects to legitimate Microsoft Azure IPs (40.126.x.x = Microsoft)
* No obfuscation, no hiding
* User bchen on DEV workstation using Azure tooling is expected for a developer
* Action: Document as a known false positive pattern; add to whitelist

### Events #1-3 Narrative

> **Narrative:** On March 12, 2024 at approximately 14:23, user `tjones` on workstation `PROD-WS-0412` opened a malicious Word document (likely received via phishing email). The document contained a macro that, upon execution, launched PowerShell with obfuscated (base64-encoded) parameters to download a first-stage payload from `198.51.100.88:443`. The first stage ran discovery commands (whoami, net user, net localgroup) at 14:28 to understand the local environment. At 15:02, PowerShell was used to download and execute a second-stage payload directly in memory from the same C2 server, avoiding file-on-disk detection. This represents a complete initial access → execution → discovery → C2 sequence. **PROD-WS-0412 is actively compromised.**

**Severity: CRITICAL**
**Immediate Action:** Isolate PROD-WS-0412 from the network immediately.
Escalate to incident response.
Block 198.51.100.88 at firewall.
Check if any other hosts have connected to this IP.

### Sigma Rule for Event #1

```yaml
title: Microsoft Office Application Spawning Obfuscated PowerShell
id: 9a1b2c3d-4e5f-6789-abcd-ef0123456789
status: stable
description: |
  Detects Office applications (Word, Excel, Outlook) spawning PowerShell
  with encoded command arguments and hidden window style. This is a strong
  indicator of macro-based malware execution.
references:
    - https://attack.mitre.org/techniques/T1566/001/
    - https://attack.mitre.org/techniques/T1059/001/
author: Threat Hunt Team
date: 2024/03/12
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\OUTLOOK.EXE'
            - '\POWERPNT.EXE'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_obfuscation:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec '
    condition: selection_parent and selection_child and selection_obfuscation
falsepositives:
    - Extremely rare legitimate Office automation with encoded PS
level: critical
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
```

---

## Task 3: DNS Anomaly Analysis

### Statistical Analysis

**Peer average for workstations:** ~1,500 queries/month = 50/day

**Standard deviation (approximate):** ~300 queries/month = 10/day

**PROD-WS-0412:** 28,441 queries/30 days = 948/day

**Z-score calculation:**

```text
z = (948 - 50) / 10 = 89.8

(This is extremely high - essentially impossible to be chance)
```

**TXT query percentage:**

```text
892 TXT queries / 28,441 total queries = 3.13%

Normal hosts: 0-5 TXT queries / 1,200-1,800 total = < 0.4%

PROD-WS-0412's TXT rate is ~8x higher than normal
```

**What this suggests:** The host is using DNS TXT records to receive data (commands, encoded payloads, exfiltrated data) from a C2 server.
This is DNS tunneling (T1071.004).

### DNS Query Analysis

**Subdomain pattern:** `a1b2.telemetry-collect.io`, `f3g4.telemetry-collect.io`, `x9y8.telemetry-collect.io`

* Short random-looking prefixes (4 characters)
* Consistent domain: `telemetry-collect.io` (domain designed to look like monitoring telemetry)
* 892 queries to different subdomains = 892 encoded C2 communications

**Base64 decode of TXT responses:**

```python
import base64

records = [
    "Y2QgL3RtcC8gJiYgbHMgLWxh",  # → "cd /tmp/ && ls -la"
    "cGluZyAxOTguNTEuMTAwLjg4",  # → "ping 198.51.100.88"
    "bmV0IHVzZXIgL2RvbWFpbg==",  # → "net user /domain"
]

for r in records:
    print(base64.b64decode(r).decode())
# Output:
# cd /tmp/ && ls -la
# ping 198.51.100.88
# net user /domain
```

These are **commands being transmitted via DNS TXT records** - the attacker is using DNS tunneling to issue commands to the compromised host!
This bypasses many firewall rules (DNS is almost always allowed).

**ATT&CK:** T1071.004 (Application Layer Protocol: DNS), T1572 (Protocol Tunneling)

### Splunk Detection Query

```splunk
# Detect DNS anomalies: high TXT record volume per host
index=dns
| eval record_type=if(isnull(query_type), "A", query_type)
| stats
    count as total_queries,
    count(eval(record_type="TXT")) as txt_queries
  by src_ip, src_host
| eval txt_pct = round(txt_queries / total_queries * 100, 2)
| eval queries_per_day = round(total_queries / 30, 0)  -- assuming 30-day window
| where txt_queries > 50 OR queries_per_day > 500
| sort -txt_queries
| table src_host, src_ip, total_queries, txt_queries, txt_pct, queries_per_day
```

```splunk
# Detect high-frequency queries to same domain (beaconing/tunneling)
index=dns
| rex field=query "(?P<registered_domain>[^.]+\.[^.]+)$"
| stats count by src_host, registered_domain
| where count > 200  -- More than 200 queries to same base domain
| sort -count
```

### Confirming Malicious vs Legitimate

**Legitimate monitoring tools that use DNS:**

* Some corporate monitoring agents (but would be in software inventory)
* Split-horizon DNS configurations (would be to internal DNS)
* Azure AD / M365 health checks (would be to Microsoft domains)

**How to confirm:**

1. Check asset management: Is there any monitoring software approved for PROD-WS-0412?
1. Check IT change management: Was any new software deployed on this host?
1. Review the DNS traffic: Is `telemetry-collect.io` a Microsoft/known vendor domain?
1. OSINT: Look up `telemetry-collect.io` in VirusTotal, WHOIS (when was it registered?)
1. Correlate with process events: What process is making these DNS queries? (Sysmon EID 22)
1. Network: Block the domain and observe if behavior stops (confirms the tool depends on it)

Given the DNS commands decode to shell commands (`cd /tmp`, `net user /domain`), this is **confirmed malicious** - no legitimate monitoring tool sends commands via DNS TXT records.

---

## Task 4: Hunt Report

### Executive Summary

A data-driven threat hunt targeting Living-off-the-Land (LotL) and post-exploitation techniques discovered active compromise on workstation PROD-WS-0412.
Evidence indicates initial access via a malicious Word document macro on 2024-03-12, followed by C2 communication to 198.51.100.88, active discovery commands, and ongoing DNS tunneling via telemetry-collect[.]io.
One additional finding (FIN-WS-0023) requires investigation of an unusual PowerShell execution pattern.
Incident response was immediately engaged for PROD-WS-0412.

### Findings Summary

| Finding ID | System | Description | Severity | Status | Action |
|------------|--------|-------------|----------|--------|--------|
| F-001 | PROD-WS-0412 | Active C2 via DNS tunneling + Word macro execution | CRITICAL | CONFIRMED MALICIOUS | Isolated, IR-2024-090 |
| F-002 | FIN-WS-0023 | PowerShell launched from Outlook | MEDIUM | UNDER INVESTIGATION | Awaiting content review |
| GAP-001 | All hosts | No detection for DNS TXT anomalies | HIGH | OPEN | New detection required |
| GAP-002 | All hosts | No alerting on Office spawning PS | HIGH | OPEN | Sigma rule pending deployment |

### Detailed Finding: PROD-WS-0412

**Timeline:**

* 2024-03-12 14:23 — WINWORD.EXE spawns obfuscated PowerShell
* 2024-03-12 14:23 — PowerShell connects to 198.51.100.88:443
* 2024-03-12 14:28 — Discovery commands executed (whoami, net user, net localgroup)
* 2024-03-12 15:02 — Second stage payload downloaded from 198.51.100.88/stage2.ps1
* 2024-03-12 - ongoing — DNS tunneling via telemetry-collect.io (892 TXT queries)

**Evidence:** Sysmon EID 1 (process creation), Sysmon EID 3 (network connection), DNS logs

**Severity:** CRITICAL — active compromise with C2 communication and discovery

**Action Taken:**

1. System isolated from network (2024-03-15 16:30)
1. Incident response ticket IR-2024-090 created
1. 198.51.100.88 blocked at perimeter firewall
1. telemetry-collect.io blocked at DNS filter
1. Email team notified to search for phishing email sent to tjones

### New Detections Recommended

1. **Office Application Spawning Obfuscated PowerShell** (Sigma rule: created above)
1. **DNS TXT Record Anomaly Alert:** Splunk scheduled search (daily) alerting on hosts with >50 DNS TXT queries
1. **DNS Tunneling Domain Detection:** Alert on queries to telemetry-collect.io and related domains

---

## Grading Notes

**Task 3 Base64 decode:** Students may get different decoded strings depending on how they handle encoding.
Accept any reasonable interpretation showing they understand the data encodes commands.

**Task 2, Event #4:** This is intentionally ambiguous.
Award full points for students who investigate rather than declaring benign, even if their final verdict differs.

**Task 4 Hunt Report:** Professional quality writing is expected at intermediate level.
Vague statements without supporting evidence should lose points.
