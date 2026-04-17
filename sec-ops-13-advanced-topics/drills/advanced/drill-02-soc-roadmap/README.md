# Drill 02: SOC Improvement Roadmap

## Difficulty: Advanced

## Estimated Time: 90 minutes

## Scenario

You have been hired as a SOC consultant for a Romanian healthcare organisation.
After an initial assessment, you have gathered the following data about their current SOC state:

**Organisation facts:**

* 2,000 employees, 3 hospitals, 1 central IT team of 12
* Subject to NIS2 Directive (healthcare is an essential sector) and GDPR
* Had a ransomware incident 8 months ago (resolved in 5 days, cost €1.2M)
* No dedicated SOC; security is handled by 2 sysadmins part-time
* SIEM deployed 1 year ago (Splunk) but only 3 alert rules active
* No threat intelligence feed
* No incident response playbooks
* CloudTrail not enabled (Azure used, no Defender for Cloud)
* Patch management: monthly, often delayed
* Staff: 2 sysadmins (no dedicated security training), 1 CISO (mostly compliance-focused)

**NIS2 obligations applicable:**

* Incident notification within 24 hours to ENISA
* Risk management measures (patching, access control, encryption)
* Supply chain security
* Business continuity and crisis management

## Objectives

1. Perform a SOC maturity assessment for this organisation
1. Identify the critical gaps aligned with NIS2 requirements
1. Build a prioritised 18-month improvement roadmap
1. Define KPIs to measure progress
1. Identify quick wins that can be implemented in 30 days

---

## Task 1: Maturity Assessment

Score the organisation across each SOC-CMM domain (0–4):

| Domain | Score (0–4) | Justification |
|--------|------------|---------------|
| Business (governance, budget, strategy) | | |
| People (skills, staffing, training, retention) | | |
| Process (playbooks, SLAs, incident handling) | | |
| Technology (tools, integration, coverage) | | |
| Services (scope of SOC services provided) | | |
| **Overall Maturity** | | |

Provide brief justification for each score based on the scenario facts.

---

## Task 2: NIS2 Gap Analysis

Map the organisation's current state against NIS2 requirements:

| NIS2 Requirement | Current State | Gap Severity | Gap Description |
|-----------------|---------------|-------------|-----------------|
| Incident detection and response | | Critical/High/Medium | |
| 24h incident notification capability | | | |
| Risk management (patching, access control) | | | |
| Supply chain security oversight | | | |
| Business continuity planning | | | |
| Cryptography and encryption | | | |
| Network security | | | |
| Management body accountability | | | |

---

## Task 3: Prioritised Improvement Roadmap (18 months)

Design an 18-month roadmap.
Budget constraint: €150,000 total.

Structure your roadmap as:

**Immediate (30 days) — Quick Wins (Free or < €5,000)**

List 5–7 actions that cost nothing or very little and have immediate impact.
Format:

```text
Action: [description]
Why:    [impact / risk mitigated]
Owner:  [who does it]
Cost:   [estimate]
```

**Phase 1 (Months 1–6) — Foundation (~€60,000)**

* Focus: [theme, e.g., "Establish detection baseline"]
* List 5–8 specific initiatives

**Phase 2 (Months 7–12) — Capability Building (~€60,000)**

* Focus: [theme]
* List 5–8 initiatives

**Phase 3 (Months 13–18) — Optimisation (~€30,000)**

* Focus: [theme]
* List 3–5 initiatives

---

## Task 4: KPI Framework

Define 8 KPIs to track SOC maturity progress.
For each KPI:

```text
KPI Name:
Current Value:  [based on scenario]
6-month Target:
12-month Target:
18-month Target:
Data Source:    [where this metric comes from]
```

Include at least:

* MTTD
* MTTR
* Alert volume / false positive rate
* NIS2 notification compliance rate
* ATT&CK detection coverage %
* Staff training completion rate

---

## Task 5: NIS2 Incident Notification Process

The organisation had a ransomware incident 8 months ago and did NOT notify ENISA within 24 hours.
Design an incident notification process that meets NIS2 Article 23 requirements:

1. What triggers the 24-hour notification obligation?
1. What information must be included in the 24-hour notification?
1. Who in the organisation is responsible for sending the notification?
1. What internal escalation path ensures the CISO is informed in time?
1. Design a simple notification checklist (max 10 items) that the on-call analyst can follow

---

## Task 6: Presenting to the Board

Write a 200-word "board memo" recommending the SOC investment.
The board is concerned about costs, not security.
Address:

* Business risk language (not technical)
* Cost of inaction (use the €1.2M previous incident as a reference)
* ROI framing of the €150,000 investment
* Legal obligation under NIS2 (management liability)
