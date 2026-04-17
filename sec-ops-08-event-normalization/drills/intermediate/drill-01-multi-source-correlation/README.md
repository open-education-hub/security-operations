# Drill 01 (Intermediate): Multi-Source Correlation Rule Writing

**Level:** Intermediate

**Estimated time:** 45 minutes

**Deliverable:** Three complete correlation rules in Sigma YAML and one in SPL

---

## Context

Your SOC has just deployed a new normalized log pipeline.
Events from Windows Active Directory, Linux endpoints, network firewalls, and a proxy server are now all normalized to ECS and stored in Elasticsearch with index pattern `security-*`.

The CISO has asked your team to implement detection rules for three threat scenarios they're most concerned about:

1. **Account compromise via credential stuffing**
1. **Internal network enumeration after initial access**
1. **Staged data exfiltration via web proxy**

You also need to write an SPL rule for the existing Splunk deployment (which has not yet been migrated to Elasticsearch).

---

## Scenario 1: Credential Stuffing Detection

### Background

A credential stuffing attack tries a large number of username/password pairs (from breached credential dumps) across many accounts, typically hitting each account only 1–3 times (below account lockout thresholds).
Unlike brute force (many attempts on one account), credential stuffing:

* Targets many different accounts from one or few source IPs
* Uses low rates per account (1–3 failures) to avoid lockout
* Often succeeds for accounts reusing breached passwords

### Detection Logic

```text
IF the same source IP:
  - Attempts login for > 20 DISTINCT usernames
  - Within a 10-minute window
  - With a failure rate > 80% (most attempts fail)
THEN: credential stuffing alert
```

### Task 1A: Write Sigma Rule

Write a Sigma rule that detects this pattern.
The rule should:

* Work across Windows and Linux authentication logs (use normalized ECS fields)
* Tag with appropriate ATT&CK techniques
* Include realistic false positive documentation
* Set an appropriate severity level

```yaml
title: [YOUR TITLE]
id: [GENERATE A UUID]
status: [appropriate status]
description: |
  [YOUR DESCRIPTION]
tags:
  - [ATT&CK tags]
logsource:
  [YOUR LOGSOURCE]
detection:
  [YOUR DETECTION]
falsepositives:
  - [YOUR FALSE POSITIVES]
level: [YOUR LEVEL]
```

### Task 1B: Write Elasticsearch DSL Query

Write the Elasticsearch aggregation query that would detect this pattern in the normalized data:

```json
GET security-*/_search
{
  [YOUR QUERY]
}
```

---

## Scenario 2: Internal Network Enumeration

### Background

After gaining initial access, attackers perform **discovery** to understand the network layout before moving laterally.
Key network enumeration behaviors include:

* Scanning many hosts on internal subnets
* Probing common ports (445 SMB, 3389 RDP, 22 SSH, 5985 WinRM)
* Using standard Windows tools (ping, arp, nslookup)
* **Originating from internal workstations, not servers** (unusual for workstations to scan)

### Detection Logic

```text
IF an internal workstation (not a known scanner/server):
  - Connects to > 15 distinct internal IP addresses
  - On admin/lateral-movement ports (22, 445, 3389, 5985, 5986)
  - Within 5 minutes
THEN: network enumeration alert

Exclude:
  - Known vulnerability scanner IPs
  - IT management servers
  - Anything with `host.type = "server"` in asset database
```

### Task 2A: Write Sigma Rule

```yaml
# YOUR SIGMA RULE FOR SCENARIO 2
```

### Task 2B: Write SPL Correlation Search

Write the SPL search that would be saved as a Splunk correlation search:

```splunk
# YOUR SPL SEARCH
```

---

## Scenario 3: Staged Data Exfiltration via Web Proxy

### Background

Attackers exfiltrate data through web proxy traffic to blend in with normal web browsing.
Staged exfiltration involves:

1. **Archive creation** — creating ZIP/RAR archives on the endpoint
1. **Large upload** — uploading to external cloud storage (Dropbox, Mega, Google Drive, etc.)
1. **Suspicious timing** — often at night or on weekends when monitoring is reduced

### Detection Logic

```text
IF for the same host (within 30 minutes):
  Step 1: A compression tool runs (7zip.exe, WinRAR.exe, zip, tar)
  Step 2: A large HTTP/HTTPS upload occurs to a cloud storage domain
         (> 100 MB uploaded, based on proxy bytes_out field)
  Step 3: Either step occurs outside business hours OR the domain is
         a file-sharing service not approved in the company allowlist
THEN: staged exfiltration alert
```

### Task 3A: Write Sigma Rule (Multi-Step)

Note: Standard Sigma doesn't natively support multi-step sequence detection, but you can represent the intent.
Use the YARA-L equivalent as a bonus.

```yaml
# YOUR SIGMA RULE
# For multi-step, use Sigma's new correlation rules format
# OR write two individual rules that correlate in the SIEM
```

### Task 3B: Write YARA-L Rule (Bonus)

```yara-l
# YOUR YARA-L RULE
```

---

## Task 4: SPL Rule for Splunk

Write a complete Splunk SPL correlation search for **Scenario 1 (Credential Stuffing)**.
The search should:

* Run as a scheduled search every 10 minutes over the last 10 minutes of data
* Use `tstats` for performance efficiency
* Output a table with: timestamp, source IP, distinct usernames count, failure rate, severity
* Set severity based on number of accounts targeted

```splunk
# YOUR SPL SEARCH
```

---

## Submission Checklist

* [ ] Sigma rule for Scenario 1 (Credential Stuffing)
* [ ] Elasticsearch DSL for Scenario 1
* [ ] Sigma rule for Scenario 2 (Network Enumeration)
* [ ] SPL rule for Scenario 2
* [ ] Sigma rule for Scenario 3 (Data Exfiltration)
* [ ] YARA-L rule for Scenario 3 (bonus)
* [ ] SPL rule for Scenario 1

**Grading criteria:**

* Correct ATT&CK technique tagging (20%)
* Detection logic accuracy (40%)
* False positive awareness (20%)
* Query syntax correctness (20%)
