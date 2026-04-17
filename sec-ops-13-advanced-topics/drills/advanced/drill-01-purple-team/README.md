# Drill 01: Purple Team Exercise Planning and Execution

## Difficulty: Advanced

## Estimated Time: 90 minutes

## Scenario

You are the SOC Lead at a European energy company.
The CISO has approved the organisation's first purple team exercise.
Your task is to plan and execute a tabletop purple team engagement focused on the threat actor **Sandstorm** (a fictional APT targeting European energy infrastructure).

## Objectives

1. Translate threat intelligence into a purple team test plan
1. Write detection hypotheses for each ATT&CK technique
1. Document blue team detection results and gaps
1. Produce a detection improvement plan from the findings

---

## Background: Sandstorm TTPs

Based on a threat intelligence report, Sandstorm uses the following ATT&CK techniques:

| # | Technique | ID | Phase |
|---|-----------|-----|-------|
| 1 | Spearphishing Attachment | T1566.001 | Initial Access |
| 2 | User Execution: Malicious File | T1204.002 | Execution |
| 3 | PowerShell | T1059.001 | Execution |
| 4 | Scheduled Task | T1053.005 | Persistence |
| 5 | OS Credential Dumping: LSASS | T1003.001 | Credential Access |
| 6 | Network Share Discovery | T1135 | Discovery |
| 7 | Lateral Tool Transfer | T1570 | Lateral Movement |
| 8 | Exfiltration Over C2 | T1041 | Exfiltration |
| 9 | Inhibit System Recovery | T1490 | Impact |

---

## Task 1: Scoping the Exercise

Before the exercise begins, you must scope it with the red team.

Answer these scoping questions:

1. Which systems are **in scope** for the exercise? Consider: endpoints, servers, domain controllers, OT/SCADA systems, cloud resources
1. Which systems should be **out of scope** and why?
1. What is the **assumed breach scenario**? (What initial access is the red team given to start from?)
1. What are the **rules of engagement**? (e.g., no actual data deletion, no production system disruption)
1. What is the **notification protocol**? (Who knows the exercise is happening? Does the L1 SOC know?)

---

## Task 2: Detection Hypotheses

For each of the 9 ATT&CK techniques above, write a detection hypothesis:

```text
Technique:   [name + ID]
Hypothesis:  There is evidence of [behaviour] if [observable] appears in [log source]
Log Source:  [which log]
Query Logic: [what to filter/search for]
Expected Indicator: [what a positive detection looks like]
```

Complete at least 5 of the 9.

---

## Task 3: Tabletop Simulation

The red team has simulated the following actions.
For each, determine whether your SOC would detect it:

**Action 1**: Red team sends a spearphishing email with a `.docm` attachment to 3 employees.
One opens it.
The macro runs `mshta.exe` to download a payload.

| Detection Question | Your Answer |
|-------------------|-------------|
| Does your email gateway scan `.docm` files for macros? | |
| Does your EDR alert on `mshta.exe` spawning from `winword.exe`? | |
| Do you have a SIEM rule for this process chain? | |
| **Detection outcome**: | Detected / Missed / Partial |

**Action 2**: The payload establishes persistence via a Scheduled Task named `MicrosoftUpdateTask`.

| Detection Question | Your Answer |
|-------------------|-------------|
| Do you collect Windows Security Event ID 4698 (scheduled task creation)? | |
| Do you have alerting for new scheduled tasks from non-standard user contexts? | |
| **Detection outcome**: | |

**Action 3**: The attacker runs Mimikatz to dump LSASS credentials.

| Detection Question | Your Answer |
|-------------------|-------------|
| Do you have EDR with credential theft protection? | |
| Do you alert on `lsass.exe` memory access from non-system processes? | |
| Do you have Windows Credential Guard enabled? | |
| **Detection outcome**: | |

**Action 4**: The attacker uses `net view` and `net share` to enumerate network shares.

| Detection Question | Your Answer |
|-------------------|-------------|
| Do you log and alert on network share enumeration? | |
| Is this likely a false positive in your environment? | |
| **Detection outcome**: | |

**Action 5**: The attacker exfiltrates data via HTTPS to `192.0.2.88` (known C2 IP from threat intel).

| Detection Question | Your Answer |
|-------------------|-------------|
| Is this IP in your SIEM IOC blocklist? | |
| Do you have proxy/firewall logging for HTTPS CONNECT? | |
| **Detection outcome**: | |

---

## Task 4: Gap Analysis and Improvement Plan

Based on your tabletop results, complete this gap analysis:

| Technique | Detected? | Gap | Priority | Remediation |
|-----------|-----------|-----|----------|-------------|
| Spearphishing Attachment | | | | |
| Malicious Macro Execution | | | | |
| PowerShell | | | | |
| Scheduled Task Persistence | | | | |
| LSASS Dump | | | | |
| Network Share Discovery | | | | |
| Lateral Tool Transfer | | | | |
| Exfil over C2 | | | | |
| Inhibit Recovery | | | | |

---

## Task 5: Purple Team Findings Report

Write an executive summary (max 300 words) for the CISO covering:

* How many techniques were detected vs. missed
* The top 3 most critical gaps
* Recommended remediation priorities
* Proposed timeline for next exercise
