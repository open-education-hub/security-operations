# Demo 04: Post-Incident Review Process

## Overview

This demo is a facilitated discussion and document review demonstrating how to conduct a post-incident review (PIR) for the ransomware incident from Demo 01.
No Docker required — this is a process and documentation demo.

## Learning Objectives

* Structure a post-incident review meeting
* Apply the 5 Whys root cause analysis technique
* Write effective action items from a PIR
* Update playbooks based on PIR findings

## Demo Materials

Review the pre-prepared PIR report for INC-2024-1147:

### PIR Report: INC-2024-1147 (Ransomware — LockBit 3.0)

**Incident Date:** 2024-11-14

**Containment:** 2024-11-14 (same day)

**Recovery:** 2024-11-16

**PIR Date:** 2024-11-21

**Presenter:** IR Manager

---

#### Timeline

| Time | Event |
|------|-------|
| 2024-11-13 17:00 | Attacker sends phishing email to m.chen |
| 2024-11-13 17:22 | m.chen clicks malicious link, downloads loader |
| 2024-11-13 17:25 | Loader installs LockBit dropper, establishes C2 |
| 2024-11-13 17:30 to 2024-11-14 09:00 | Attacker explores network (~16h undetected) |
| 2024-11-14 09:00 | Encryption begins (finance-ws-040, 041, 042) |
| 2024-11-14 09:18 | EDR behavioral alert fires |
| 2024-11-14 09:35 | First host isolated |
| 2024-11-14 10:30 | Incident declared P1, IR team engaged |
| 2024-11-14 11:30 | All 3 hosts isolated, C2 blocked |
| 2024-11-15 | Recovery from backups begins |
| 2024-11-16 14:00 | All systems operational |

**Total dwell time:** 16 hours (undetected)

**Total business impact:** 28 hours downtime for Finance team

---

#### Root Cause Analysis (5 Whys)

**Why were 3 workstations encrypted?**
→ LockBit ransomware executed successfully and encrypted files.

**Why was LockBit able to execute?**
→ It was dropped by a PowerShell stager that was not detected by AV (fileless).

**Why wasn't the fileless stager detected?**
→ The EDR behavioral rule for fileless execution was disabled (known FP issue — was meant to be re-enabled after tuning).

**Why was it not re-enabled?**
→ There was no tracking mechanism for disabled detection rules.
The analyst who disabled it left the company, and no one knew it was still off.

**Why is there no tracking mechanism for disabled rules?**
→ No formal process exists for rule state changes.
Rules are changed ad hoc with no approval or review workflow.

**ROOT CAUSE:** No rule lifecycle management process — rules are disabled without audit trail or automatic re-enable procedures.

---

#### Action Items

| # | Action | Owner | Due | Priority |
|---|--------|-------|-----|----------|
| 1 | Implement detection rule change management process | Detection Eng | Dec 1 | P1 |
| 2 | Audit all currently disabled detection rules | SOC Team Lead | Nov 22 | P1 |
| 3 | Add web proxy logs to SIEM (phishing link click was undetected) | SIEM Team | Dec 15 | P2 |
| 4 | Update phishing response playbook to include "check for fileless execution" step | IR Manager | Nov 25 | P2 |
| 5 | Conduct phishing simulation exercise in Q1 2025 | Security Awareness | Jan 15 | P3 |

---

## Demo Walkthrough

### Part 1: Walk Through Timeline (5 min)

Narrate the attack timeline.
Highlight: the 16-hour undetected dwell time.
Ask: "Why 16 hours?
What would have detected this earlier?"

### Part 2: Live 5 Whys (10 min)

Conduct the 5 Whys analysis interactively with the audience.
Ask them to volunteer "why?" at each step before revealing the next.

**Key reveal:** The root cause is NOT "the analyst disabled a rule" — it's "there is no process to track rule state changes." Individual fault vs. system fault.

### Part 3: Action Item Quality (5 min)

Show two versions of action item #1:

**Bad action item:**
> "Fix the rule management issue."

**Good action item:**
> "Implement detection rule change management process: all rule enable/disable changes require a JIRA ticket with approval, reason, and automatic re-enable date. Owner: Detection Engineering. Due: December 1, 2024."

### Part 4: Discussion (5 min)

* Should the incident have required GDPR notification? (Finance data, encrypted — analyze together)
* What would change if this incident had been caused by an insider?

## No Teardown Required

This demo uses only documents and discussion.
