# Detection Rule Package: T1055.001 — DLL Injection
# Security Operations Course - Session 08: Event Normalization
# Drill 01 (Advanced): Full Detection Engineering Workflow
#
# =============================================================================
# STUDENT INSTRUCTIONS
# =============================================================================
# This scaffold provides the structure of a production-ready detection package.
# Your task is to complete each file in this package.
#
# Package structure:
#   detection-package-T1055.001/
#   ├── README.md                        ← THIS FILE (complete Part 6)
#   ├── rules/
#   │   ├── primary-detection.yml        ← Part 3.1: Primary Sigma rule
#   │   └── supporting-indicator.yml     ← Part 3.2: Supporting Sigma rule
#   ├── tests/
#   │   ├── true_positive_events.json    ← Part 4.2: Events that should fire
#   │   └── true_negative_events.json    ← Part 4.2: Events that should NOT fire
#   ├── queries/
#   │   ├── splunk.spl                   ← Sigma compiled to Splunk SPL
#   │   ├── elasticsearch.kql            ← Sigma compiled to EQL
#   │   └── sentinel.kql                 ← Sigma compiled to Sentinel KQL
#   ├── coverage/
#   │   └── navigator_layer.json         ← Part 5.1: ATT&CK Navigator layer
#   └── tuning/
#       └── whitelist.csv               ← Known-good process pairs to exclude
#
# =============================================================================

# [STUDENT TASK — Part 6]
# Replace this file with your completed README.md for the detection package.
# Requirements:
#   1. Overview: What technique does this package detect?
#   2. Deployment guide: How to use this in a SIEM
#   3. Expected false positives and how to tune
#   4. Testing procedure
#   5. Maintenance notes (when to update, what to watch for)

## Overview

**Technique:** T1055.001 — Process Injection: Dynamic-link Library Injection
**Tactic:** Defense Evasion, Privilege Escalation
**ATT&CK Reference:** https://attack.mitre.org/techniques/T1055/001/

[STUDENT TASK: Write a 2-3 sentence description of what DLL injection is and
why it is dangerous. Include: what it allows attackers to do, why it evades
detection, and which malware families use it.]

## Detection Coverage

| Rule File | Data Source | Event Type | Coverage |
|-----------|------------|------------|---------|
| primary-detection.yml | Sysmon EventID 8 | CreateRemoteThread | HIGH |
| supporting-indicator.yml | [STUDENT: choose your data source] | [Event type] | MEDIUM |

## Deployment Guide

### Prerequisites

[STUDENT TASK: List what must be configured before deploying these rules]

- [ ] Sysmon deployed and EventID 8 enabled in configuration
- [ ] Sysmon events forwarded to SIEM
- [ ] [Your supporting indicator's data source requirements]

### Importing to SIEM

**Splunk:**
```
# Import SPL rule from queries/splunk.spl
# Create saved search as alert
Settings → Searches, Reports, and Alerts → New Alert
```

**Elasticsearch/Kibana:**
```
# Import EQL rule from queries/elasticsearch.kql
Security → Rules → Create New Rule → Event Correlation (EQL)
```

**Microsoft Sentinel:**
```
# Import KQL rule from queries/sentinel.kql
Sentinel → Analytics → Create → Scheduled query rule
```

## Expected False Positives

[STUDENT TASK: List processes that legitimately use CreateRemoteThread
and would trigger false positives. Use the whitelist.csv file to document
exclusions.]

| Process | Reason for FP | Exclusion in whitelist.csv |
|---------|--------------|---------------------------|
| Visual Studio (devenv.exe) | Debugger attaches to processes | Yes |
| [STUDENT: add more] | | |

## Testing

Run the test cases from the `tests/` directory:

```bash
# Load true positive test events
# [STUDENT: describe how to load test events into your SIEM]

# Load true negative test events
# [STUDENT: describe how to verify the rule does NOT fire]
```

## Maintenance

**Review cadence:** Monthly  
**Review trigger:** New ATT&CK sub-technique added to T1055; new FP discovered

**When to update:**
- New legitimate software identified that uses CreateRemoteThread
- New DLL injection technique variant discovered
- False positive rate increases above 5%

---
*Package created as part of Detection Engineering course exercise.*
*This is a training artifact — review before production deployment.*
