# Drill 01 (Advanced): Full Detection Engineering Workflow

**Level:** Advanced

**Estimated time:** 90 minutes

**Deliverable:** A complete, production-ready detection rule package for a specific ATT&CK technique

---

## Overview

Detection engineering is more than writing a query.
A production-ready detection requires:

1. Threat modeling — understanding the attack technique deeply
1. Data source mapping — identifying what logs cover the technique
1. Rule development — writing, testing, and iterating
1. Validation — simulating the attack and confirming detection
1. Documentation — making the rule maintainable and explainable
1. ATT&CK coverage mapping — tracking your detection portfolio

This drill takes you through the full workflow for **T1055.001 — Process Injection: Dynamic-link Library Injection** (DLL Injection).

---

## Part 1: Threat Modeling

### Research the Technique

Read the ATT&CK page for T1055.001 (DLL Injection).
Answer these questions:

**Q1.1:** What are the three most common Windows API call sequences used to perform DLL injection?

**Q1.2:** List four real-world malware families or threat actor tools known to use DLL injection (from ATT&CK).

**Q1.3:** What is the key difference between:

* Classic DLL injection (OpenProcess + WriteProcessMemory + CreateRemoteThread)
* Reflective DLL injection
* Process Hollowing (T1055.012)

**Q1.4:** What legitimate Windows software also uses the DLL injection mechanism?
Why does this matter for detection?

---

## Part 2: Data Source Mapping

### Available Data Sources

Your environment has the following telemetry available:

| Source | Coverage | Collection Method |
|--------|---------|-------------------|
| Sysmon EventID 1 | Process creation | Sysmon config |
| Sysmon EventID 8 | CreateRemoteThread | Sysmon config |
| Sysmon EventID 10 | Process access (OpenProcess) | Sysmon config (high volume) |
| Sysmon EventID 11 | File created | Sysmon config |
| Sysmon EventID 7 | Image loaded (DLL load) | Sysmon config (very high volume) |
| Windows Security 4688 | Process creation (limited cmdline) | GPO |
| EDR telemetry | API-level hooks | CrowdStrike Falcon |
| Memory forensics | In-memory DLL detection | Not real-time |

### Tasks

**Q2.1:** Create a data source coverage matrix.
For each API call in DLL injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread), identify which data source(s) would capture it.

| API Call | Sysmon EID | Win Security | EDR | Notes |
|----------|-----------|--------------|-----|-------|
| OpenProcess | | | | |
| VirtualAllocEx | | | | |
| WriteProcessMemory | | | | |
| CreateRemoteThread | | | | |

**Q2.2:** Which single Sysmon event ID gives the highest-fidelity detection signal for DLL injection?
Justify your answer.

**Q2.3:** What is the tradeoff between using Sysmon EventID 7 (ImageLoaded) vs EventID 8 (CreateRemoteThread) for detection?

---

## Part 3: Rule Development

### Task 3.1: Write the Primary Detection Rule (Sysmon EventID 8)

Write a Sigma rule for **CreateRemoteThread to a non-child process** that detects DLL injection.

Requirements:

* Focus on the source and target process relationship
* Exclude known-legitimate sources of CreateRemoteThread (debuggers, AV, JIT compilers)
* Tag with ATT&CK T1055.001
* Set appropriate severity and false positive guidance

```yaml
title: [YOUR TITLE]
id: [UUID]
# COMPLETE THE RULE
```

### Task 3.2: Write a Supporting Indicator Rule

The CreateRemoteThread detection may miss reflective DLL injection.
Write a second Sigma rule using a different data source (your choice from the table in Part 2) as a complementary signal.

```yaml
title: [YOUR TITLE - Supporting Indicator]
id: [UUID]
# COMPLETE THE RULE
```

### Task 3.3: Write a YARA-L Correlation Rule

Correlate your two rules above: alert when both signals occur for the same process/host within 5 minutes.

```yara-l
rule dll_injection_correlated {
  # COMPLETE THE RULE
}
```

---

## Part 4: Validation with Atomic Red Team

### Task 4.1: Map Atomic Tests

Go to https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md

List the atomic tests available for T1055.001 and which of your detection rules (primary or supporting) each test would trigger.

| Atomic Test # | Test Name | Expected Rule to Fire |
|-------------|-----------|----------------------|
| | | |
| | | |

### Task 4.2: Design Test Cases

Design test cases that should both fire and NOT fire your detection:

**Should FIRE (True Positives):**

| Test | Expected Trigger |
|------|-----------------|
| Inject DLL into notepad.exe using cmd.exe parent | Primary rule (CreateRemoteThread) |
| Reflective DLL inject via PowerShell | Supporting rule |

**Should NOT FIRE (True Negatives — rule correctly does NOT alert):**

| Scenario | Why It Should Not Alert |
|----------|------------------------|
| Visual Studio debugger attaching to process | |
| Windows Defender real-time protection scanning a file | |
| JVM class loading | |

---

## Part 5: ATT&CK Coverage Documentation

### Task 5.1: Update Coverage Map

Create an ATT&CK Navigator JSON layer that shows:

* T1055.001 covered by your new rule (green, score=1)
* T1055 sub-techniques you do NOT yet cover (red, score=0)
* Related techniques partially covered by existing rules (yellow, score=0.5)

```json
{
  "name": "DLL Injection Coverage Layer",
  "versions": { "attack": "14" },
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1055.001",
      "score": 1,
      "color": "#52BE80",
      "comment": "Covered by rule: DLL-INJ-001"
    }
    // ADD MORE TECHNIQUES
  ]
}
```

### Task 5.2: Identify Detection Gaps

Based on your data source mapping:

* Which sub-techniques of T1055 are NOT covered by your new rules?
* What data sources would you need to add to cover those gaps?

---

## Part 6: Full Rule Package

Assemble the final deliverable — a "detection rule package" folder containing:

```text
detection-package-T1055.001/
├── README.md               ← Overview, context, deployment guide
├── rules/
│   ├── primary-detection.yml    ← Sigma rule (CreateRemoteThread)
│   └── supporting-indicator.yml ← Sigma rule (secondary signal)
├── tests/
│   ├── true_positive_events.json   ← Sample events that should fire
│   └── true_negative_events.json   ← Sample events that should NOT fire
├── queries/
│   ├── splunk.spl           ← Compiled Sigma for Splunk
│   ├── elasticsearch.kql    ← Compiled Sigma for Elastic
│   └── sentinel.kql         ← Compiled Sigma for Sentinel
├── coverage/
│   └── navigator_layer.json ← ATT&CK Navigator layer
└── tuning/
    └── whitelist.csv        ← Known-good process pairs to exclude
```

Write the README.md for this package.

---

## Submission Checklist

* [ ] Part 1: All four threat modeling questions answered
* [ ] Part 2: Data source coverage matrix completed
* [ ] Part 3: Primary detection rule (Sigma)
* [ ] Part 3: Supporting indicator rule (Sigma)
* [ ] Part 3: YARA-L correlation rule
* [ ] Part 4: Atomic test mapping table
* [ ] Part 4: True positive and true negative test cases defined
* [ ] Part 5: ATT&CK Navigator JSON layer
* [ ] Part 5: Coverage gap analysis
* [ ] Part 6: Detection package README.md
