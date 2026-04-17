# Guide 01 (Intermediate): SOC Maturity Assessment and Improvement Roadmap

## Overview

This intermediate guide takes you through a structured process for assessing the maturity of a SOC and building an improvement roadmap.
You will learn established maturity models, how to measure the current state across people, process, and technology dimensions, and how to prioritise improvements for maximum security benefit.

## Learning Objectives

After completing this guide you will be able to:

* Apply the SOC-CMM or CISA maturity model to assess a SOC's current state
* Score a SOC across people, process, and technology dimensions
* Identify the most impactful improvement opportunities
* Write a structured SOC improvement roadmap with priorities and timelines

## Estimated Time

60 minutes

## Prerequisites

* Familiarity with basic SOC functions (triage, incident response, threat hunting)
* Completion of basic guides 01–03 is recommended

---

## 1. SOC Maturity Models

### 1.1 Five-Level Generic Model

Most SOC maturity frameworks use 5 levels:

| Level | Name | Characteristics |
|-------|------|----------------|
| 1 | Initial / Ad-hoc | No defined processes, reactive only, high staff turnover |
| 2 | Developing | Basic processes documented, SIEM deployed, triage exists |
| 3 | Defined | Standardised playbooks, SLAs, regular reporting, threat hunting begins |
| 4 | Managed | Metrics-driven, purple team exercises, threat intel integrated |
| 5 | Optimising | Continuous improvement, advanced automation, industry leadership |

### 1.2 The SOC-CMM Framework

The SOC Capability Maturity Model (SOC-CMM) assesses five domains:

1. **Business** — governance, strategy, budget alignment
1. **People** — staffing, skills, training, retention
1. **Process** — incident handling, SLAs, playbooks, change management
1. **Technology** — tools, integration, coverage, automation
1. **Services** — scope of services provided

Each domain is scored 0–4.
The overall maturity is the weighted average.

---

## 2. Assessing People Maturity

### 2.1 Staffing Model

| Indicator | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Analyst shifts | Business hours only | 24×7 with on-call | 24×7 with full staffing |
| Tier structure | No tiers | L1/L2 defined | L1/L2/L3 + specialists |
| Turnover | > 40% annually | 15-25% | < 10% |
| Training budget | Ad-hoc | Annual certification | 10%+ of salary budget |

### 2.2 Skills Assessment

Run a skills gap analysis against key competency areas:

* Malware analysis
* Network forensics
* Cloud security
* Threat intelligence
* Scripting/automation (Python, PowerShell)
* Incident response

**Assessment method**: Have each analyst self-rate 1–4 per competency; supplement with CTF/exercise results.

### 2.3 Knowledge Retention

Document your tribal knowledge:

* Create runbooks for all common incident types
* Record investigation walkthroughs
* Cross-train analysts across specialisations
* Conduct tabletop exercises quarterly

---

## 3. Assessing Process Maturity

### 3.1 Alert Triage Process

Score each characteristic:

| Characteristic | Score 0 | Score 2 | Score 4 |
|---------------|---------|---------|---------|
| Alert prioritisation | No priority | Manual priority | Automated severity scoring |
| Triage time SLA | None | Defined but not met | Defined and consistently met |
| Escalation path | Informal | Documented | Automated escalation |
| False positive tracking | None | Spreadsheet | Systematic with feedback loop |

### 3.2 Incident Response Process

Use the NIST IR lifecycle as the baseline:

* **Preparation**: Do you have playbooks for top 10 incident types?
* **Detection**: Do you have detection rules for all critical attack patterns?
* **Containment**: Do you have defined containment procedures for each scenario?
* **Eradication**: Is root cause analysis performed on all P1/P2 incidents?
* **Recovery**: Is recovery verified with testing, not just assumption?
* **Post-incident**: Are lessons learned systematically applied to improve detection?

### 3.3 Change Management for SIEM Rules

A mature SOC treats SIEM detection rules like software:

* Rules are version-controlled (Git)
* New rules go through a testing environment before production
* Rule changes require peer review
* Performance impact is measured before deployment
* Rules have owners responsible for tuning

---

## 4. Assessing Technology Maturity

### 4.1 Log Coverage Assessment

Map your log sources against the environment:

```text
Category           | Sources Available | % Coverage
-------------------+-------------------+------------
Network perimeter  | Firewall, IDS     | 90%
Endpoints          | EDR, Windows logs | 75%
Authentication     | AD, IdP           | 95%
Cloud              | CloudTrail        | 60%
Applications       | Web app logs      | 40%
Email              | Email gateway     | 80%
```

Gaps in cloud and application coverage are typical at maturity level 2.

### 4.2 Detection Coverage Assessment (ATT&CK)

Use the MITRE ATT&CK Navigator to map your detection rules:

1. Export your SIEM rule list
1. Tag each rule with ATT&CK technique(s) it detects
1. Import into ATT&CK Navigator
1. Identify red areas (no coverage)
1. Prioritise based on most-used techniques in your threat model

### 4.3 Automation Assessment

| Task | Level 2 (manual) | Level 4 (automated) |
|------|-----------------|---------------------|
| Alert enrichment | Analyst manually looks up IP | SOAR auto-enriches |
| Ticket creation | Analyst manually creates | SOAR creates with context |
| Containment | Analyst manually blocks | SOAR blocks and notifies |
| IOC ingestion | Weekly manual import | Hourly automated feed |
| Metrics reporting | Monthly manual spreadsheet | Real-time dashboard |

---

## 5. Building the Improvement Roadmap

### 5.1 Gap Prioritisation Matrix

After scoring all dimensions, plot gaps on a 2x2 matrix:

```text
      High Security Impact
             ↑
             │  Quick wins     │  Strategic projects
             │  (do first)     │  (plan carefully)
Low Effort ──┼─────────────────┼──────── High Effort
             │  Low priority   │  Deprioritise
             │                 │
             ↓
      Low Security Impact
```

### 5.2 Example Roadmap (Level 2 → Level 3)

**Quarter 1: Foundation**

* Enable CloudTrail in all regions (low effort, high impact)
* Create playbooks for top 5 incident types
* Implement alert severity scoring in SIEM

**Quarter 2: Process**

* Deploy SOAR for top 3 automation use cases (enrichment, ticketing, IOC blocking)
* Establish weekly alert triage review meeting
* Begin monthly MTTD/MTTR reporting

**Quarter 3: Technology**

* Expand ATT&CK coverage from 30% to 50%
* Onboard threat intelligence feed into SIEM
* Implement 24×7 on-call rotation

**Quarter 4: Validation**

* First purple team exercise
* Full SOC-CMM assessment (baseline for year 2 improvement)
* Annual training plan per analyst

### 5.3 OKRs for SOC Improvement

Frame improvements as Objectives and Key Results:

**Objective**: Reduce mean time to detect threats
**Key Results:**

* MTTD < 4 hours by Q4 (from 12 hours current)
* Alert-to-triage SLA met in > 95% of cases
* ATT&CK detection coverage > 50% (from 30%)

---

## 6. Presenting Maturity to Management

SOC maturity is a business conversation, not just a technical one.

**Avoid**: "We need more SIEM rules and a SOAR platform."

**Use instead**:

* **Risk language**: "Our current detection capability means an attacker has an average of 12 hours undetected. Our target is 4 hours."
* **Business impact**: "A 12-hour MTTD increases the potential impact of a ransomware event by approximately €X in recovery costs."
* **ROI**: "Automating alert triage (3 weeks of analyst time per month) frees capacity for threat hunting."

---

## Summary

SOC maturity improvement is a structured, multi-year programme.
Assess current state honestly across people, process, and technology.
Prioritise improvements by security impact versus effort.
Use metrics (MTTD, MTTR, FPR, ATT&CK coverage) to track progress and communicate value to leadership.
A Level 3 SOC with well-tuned processes beats a Level 5 tool set with no process around it.
