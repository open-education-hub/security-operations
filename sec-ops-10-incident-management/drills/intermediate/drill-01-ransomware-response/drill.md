# Drill 01 (Intermediate): Full Ransomware Response Scenario

> **Level:** Intermediate
> **Estimated time:** 60–90 minutes
> **Format:** Individual or small group exercise
> **Tools:** Reference materials permitted (IR Plan, reading material)

---

## Overview

You are the IR Lead at **FinServe S.A.**, a mid-sized asset management company based in Bucharest, Romania.
The company manages investments for approximately 12,000 retail clients.
All client data (personal details, portfolio data, transaction history) is stored in the company's data center and cloud (Azure).

It is Tuesday, 07:42 local time.
You receive the following escalation via the on-call SOC line.

---

## Initial Report

> **From:** SOC Tier 1 (overnight shift)
> **To:** IR Lead (on-call)
> **Time:** 07:42 EEST (04:42 UTC)
>
> "We're getting alerts from Defender for Endpoint on multiple machines. It looks like files are being renamed on several workstations. We also have a report from our cleaning staff that they found a note on the printer in the trading floor. Photo attached. Also seeing 'ransom-demand.txt' files appearing on shared drives. No response from our on-site IT admin — he went home at midnight."

**Ransom note (printer photo):**
> "Your network has been encrypted by LockBit 3.0. All your files are encrypted and cannot be decrypted without our key. To restore your data, visit: [.onion address]. You have 72 hours. Do not contact police or FBI. Silence is golden. DO NOT restart servers or you will lose everything. Your Company ID: F1N53RV3-2025."

---

## Background Information

| Item | Detail |
|------|--------|
| Organization | FinServe S.A., Bucharest, Romania |
| Sector | Financial services (asset management) |
| Employees | 180 staff |
| Clients | 12,000 retail investment clients |
| Client data | Name, address, national ID, portfolio data, bank account IBAN |
| Regulatory obligations | GDPR (DPA: ANSPDCP), DORA (ICT incident reporting), NIS2 (Important entity) |
| Active systems | 180 workstations, 12 servers, Azure cloud (M365, Azure VMs) |
| Backups | Daily to on-premises NAS, weekly to Azure Blob Storage (last backup: Monday 23:00) |
| IR Plan | Exists but was last tested 18 months ago |
| EDR | Microsoft Defender for Endpoint (all workstations) |
| SIEM | Microsoft Sentinel |

---

## Part 1: Initial Response (First 30 Minutes)

**Task 1.1 — Incident Declaration**

Based on the initial report, answer:

1. Is this a confirmed P1 incident? Provide your reasoning using the severity classification criteria from the IR Plan.

1. Who do you notify in the first 15 minutes? List roles and approximate contact sequence.

1. Write a 3-sentence initial executive notification message (BLUF format) that you would send to the CISO and CEO via out-of-band channel (Signal).

**Task 1.2 — Immediate Triage Questions**

List the 5 most important questions you need to answer in the next 30 minutes to understand the incident scope.
For each question, identify the data source that would answer it.

| Priority | Question | Data Source |
|----------|---------|-------------|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

**Task 1.3 — Volatile Evidence Consideration**

Before taking any containment action, what volatile evidence should you attempt to collect?
For each item, explain why it matters for this specific ransomware scenario.

---

## Part 2: Developing Intelligence (30–60 Minutes)

At 08:10, your SOC analyst provides the following SIEM analysis:

> **Scope so far:** 47 workstations showing encrypted files (out of 180). All 47 are in the Trading, Finance, and Operations departments. 6 servers have not been reached yet.
> **First evidence of infection:** Monday at 23:47 (about 8 hours before detection).
> **Attacker movement:** SIEM shows RDP sessions from `10.0.5.23` (a decommissioned server IP that should be offline) to 47 workstations between 23:47 Monday and 06:15 Tuesday.
> **Backups:** Monday 23:00 backup completed successfully. No encryption artifacts detected in the backup at this time.
> **Azure:** M365 services appear unaffected. Azure VMs have not been checked yet.

**Task 2.1 — Scope Assessment**

Based on this new information, update your assessment:

1. What is the likely patient-zero? What evidence supports this?
1. Is the Monday 23:00 backup safe to use for recovery? What additional validation is needed?
1. The attacker was present for approximately 8 hours before encryption began. What activities might they have been conducting during that time?

**Task 2.2 — Containment Decision**

Answer the following containment questions:

1. Should you isolate all 47 affected workstations immediately? What are the tradeoffs?
1. What should you do about the 6 unconfirmed servers? Prioritize them.
1. The decommissioned server at `10.0.5.23` appears to be the attacker's pivot point. What action do you take and why?
1. Should you contact the backup system administrator before or after containment? Why?

**Task 2.3 — GDPR Assessment**

At 08:30, a forensics analyst confirms: the attacker accessed the client database server before encryption.
Log analysis shows bulk SELECT queries executed between 00:15 and 01:30 Tuesday (during the dwell period).

The database contains: client name, national ID (CNP), investment portfolio data, and bank account IBANs for 12,000 clients.

Answer these questions:

1. Has a GDPR breach occurred? Which definition applies?
1. When did the 72-hour GDPR notification clock start?
1. To whom must FinServe S.A. notify in Romania? Provide the authority name.
1. Does DORA also apply? If so, what is the DORA notification timeline for major ICT incidents?
1. Does NIS2 apply? What timeline applies?
1. Draft the headline paragraph for the GDPR Art. 33 notification to the supervisory authority.

---

## Part 3: Eradication and Recovery Planning (60–90 Minutes)

At 10:00, all 47 workstations and the attacker's pivot server are isolated.
The forensics analyst has identified:

* **Initial access**: Phishing email sent to the IT admin on Friday afternoon. The IT admin clicked a malicious attachment, installing a remote access tool. The attacker then used stolen credentials to RDP to the decommissioned server and used it as a staging point.
* **Lateral movement**: SMB and WMI used from the decommissioned server
* **Data exfiltration**: 2.3 GB of data extracted to an external cloud service before encryption
* **Persistence**: A malicious scheduled task named "WindowsUpdate_v3" was found on 12 workstations
* **Ransomware**: LockBit 3.0, deployed via PsExec

**Task 3.1 — Eradication Checklist**

Create an eradication checklist specific to this incident.
Use the format:
`| Step | Action | Justification | Owner |`

Include at minimum:

* Malware removal
* Persistence removal
* Credential rotation (specify which credentials)
* Vulnerability remediation (what was the root vulnerability?)
* Domain security hardening

**Task 3.2 — Recovery Sequencing**

List the 10 systems that should be recovered first, in order.
Justify your prioritization logic.

**Task 3.3 — PIR Questions**

Identify the 5 most important "why" questions this incident raises.
For each, suggest the likely root cause and a potential systemic fix.

| Why question | Likely root cause | Systemic fix |
|-------------|-------------------|--------------|
| | | |

---

## Part 4: Communication Deliverables

**Task 4.1 — Executive Brief**

Write a 1-page executive brief to be delivered to the CEO and Board at 12:00.
Use the BLUF format.
Include: what happened, current status, regulatory obligations, business impact, and 3 key decisions needed from the Board.

**Task 4.2 — Customer Notification (Draft)**

Draft the customer notification email that will be sent to FinServe's 12,000 clients under GDPR Art. 34 (assuming high risk assessment requires individual notification).
Write in plain, non-technical language.

**Task 4.3 — Regulatory Timeline**

Create a timeline showing when each regulatory notification must be filed:

| Regulation | Filing deadline | Filing recipient | Status |
|-----------|----------------|-----------------|--------|
| GDPR Art. 33 | | | |
| DORA (initial) | | | |
| NIS2 (early warning) | | | |
| NIS2 (full notification) | | | |

---

## Evaluation Criteria

| Dimension | Excellent | Adequate | Needs Work |
|-----------|---------|---------|-----------|
| Initial response | Correct P1 declaration, appropriate notifications, proper executive message | One notification missed or slight delay | Wrong severity, missing notifications |
| GDPR assessment | Correctly identifies 72h clock start, correct authority, correct obligation | 72h calculated from wrong start time | Does not identify GDPR obligation |
| Containment logic | Evidence capture before isolation, correct isolation sequence, backup protection | Isolation correct but misses evidence capture | Immediate shutdown of all systems |
| Eradication completeness | All 5 areas covered with justification | 3-4 areas covered | Missing persistence or credential rotation |
| Communication quality | Executive brief is clear, concise, actionable | Brief is present but too technical or too vague | Not produced |

---

## Solution

See: `../../solutions/drill-01-solution/solution.md`
