# Drill 01 — Alert Prioritization

## Scenario

You are a Tier 1 SOC analyst at **EuroTech Solutions**, a mid-size IT services company with 500 employees.
It is 09:15 on a Monday morning and your shift just started.
Your SIEM queue contains the following 8 alerts waiting for triage.

Review each alert, apply the priority matrix, and document your triage decisions.

---

## Alert Queue

| # | Alert ID | Rule | Severity | Hostname | User | Key Details |
|---|----------|------|----------|----------|------|-------------|
| 1 | ALT-001 | Tor exit node connection | Medium | LAPTOP-DEV-07 | dev.alice | 1 outbound connection to known Tor exit node |
| 2 | ALT-002 | Admin account login outside business hours | Low | CORP-AD-01 | svc_backup | Domain controller, 03:00 local time |
| 3 | ALT-003 | USB mass storage connected | Low | DESKTOP-RECV-01 | warehouse.bob | USB connected in warehouse workstation |
| 4 | ALT-004 | Antivirus alert: HackTool | High | LAPTOP-CEO-01 | ceo.carol | AV blocked a file: Mimikatz |
| 5 | ALT-005 | Failed VPN logins | Medium | VPN-GW-01 | unknown | 52 failed login attempts in 10 min |
| 6 | ALT-006 | DNS query to newly-registered domain | Low | SERVER-PROD-02 | N/A | DNS query to: xkzq8j.freshdesk-cdn.tk |
| 7 | ALT-007 | Scheduled task created | Medium | WORKSTATION-IT-03 | it.dave | New scheduled task via schtasks.exe |
| 8 | ALT-008 | Large data transfer to cloud | High | FILE-SERVER-01 | N/A | 18 GB uploaded to Google Drive API |

---

## Asset Context

| Hostname | Type | Criticality | Department |
|----------|------|-------------|------------|
| LAPTOP-DEV-07 | Developer workstation | Medium | Engineering |
| CORP-AD-01 | Domain controller | Critical | IT |
| DESKTOP-RECV-01 | Desktop | Low | Warehouse |
| LAPTOP-CEO-01 | Executive laptop | Critical | Executive |
| VPN-GW-01 | VPN gateway | High | IT |
| SERVER-PROD-02 | Production server | High | IT |
| WORKSTATION-IT-03 | IT workstation | Medium | IT |
| FILE-SERVER-01 | File server | Critical | IT |

---

## Your Tasks

### Task 1: Apply the Priority Matrix (25 points)

For each of the 8 alerts:

1. Identify the asset criticality
1. Identify the alert severity
1. Determine the final priority (Critical / High / Medium / Low / Info)
1. Assign to: Tier 1 handles / Escalate to Tier 2 / Auto-close

Fill in this table:

| Alert | Asset Criticality | Alert Severity | Final Priority | Assignment |
|-------|------------------|----------------|----------------|------------|
| ALT-001 | ? | Medium | ? | ? |
| ALT-002 | ? | Low | ? | ? |
| ALT-003 | ? | Low | ? | ? |
| ALT-004 | ? | High | ? | ? |
| ALT-005 | ? | Medium | ? | ? |
| ALT-006 | ? | Low | ? | ? |
| ALT-007 | ? | Medium | ? | ? |
| ALT-008 | ? | High | ? | ? |

### Task 2: Identify the Top 3 Priorities (20 points)

Based on your analysis, which 3 alerts require the most urgent attention?
Justify your ranking.
Consider:

* Business risk
* Attack stage (initial access vs. post-exploitation)
* Evidence of active threat vs. policy violation

### Task 3: Write a Triage Note for ALT-004 (30 points)

ALT-004 is the most concerning alert.
Write a full triage note including:

* Your triage decision (TP/FP/Needs investigation)
* Evidence you would look for to confirm your decision
* What enrichment you would perform
* What immediate actions you would recommend
* Whether you would escalate, and to whom

### Task 4: Identify False Positive Candidates (15 points)

Which alerts do you suspect might be false positives without further investigation?
For each, explain:

* Why it might be a false positive
* What single piece of evidence would confirm it as FP
* What single piece of evidence would escalate it to a true positive

### Task 5: Workflow Question (10 points)

ALT-002 fired at 03:00.
You are reviewing it at 09:15.
The SLA for Low severity is "acknowledge within 8 hours."

1. Has the SLA been breached?
1. What should you do now?
1. What process improvement would prevent this situation?

---

## Hints

* A svc_backup account logging into a Domain Controller at 3 AM is unusual even if the severity is listed as Low — the SIEM rule severity doesn't always reflect business risk
* Mimikatz on an executive laptop is almost always highly significant
* DNS to a `.tk` (Tokelau ccTLD) domain that was recently registered from a production server is a strong C2 indicator
* A scheduled task created by an IT admin on an IT workstation might be entirely routine
* Consider whether the 18 GB upload could be legitimate (monthly backup, migration project)

---

## Submission Format

Write your answers in a Markdown document with sections matching each task.
Be specific and justify every decision.
