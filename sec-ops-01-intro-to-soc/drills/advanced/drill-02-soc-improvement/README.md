# Drill 02 (Advanced): SOC Maturity Assessment and Improvement Plan

## Description

Perform a SOC maturity assessment for a fictional organization and develop a 12-month improvement roadmap.
This exercise requires applying SOC best practices to identify gaps and propose measurable improvements.

## Objectives

* Apply SOC maturity frameworks (e.g., SOC-CMM) to assess current state.
* Identify critical gaps in detection, process, and people.
* Develop a realistic, prioritized improvement roadmap.
* Define measurable success criteria (KPIs).

## Background: NordLogistics AB

**Company:** NordLogistics AB

**Size:** 1,200 employees

**Industry:** Logistics and supply chain (operates in 8 EU countries)

**Current SOC state:**

| Area | Current State |
|------|--------------|
| SIEM | Deployed 2 years ago; 40% of systems sending logs; rarely tuned |
| Detection rules | 85 rules total; last reviewed 18 months ago; 60% false positive rate |
| Staffing | 4 Tier 1 analysts (2 shifts); no Tier 2/3 dedicated staff |
| Incident response | No formal IR plan; ad-hoc responses via email |
| Threat intelligence | No TI program; no external feeds |
| Playbooks | 2 documented playbooks (phishing and malware); never tested |
| MTTD | 14.5 hours average |
| MTTR | 28 hours average |
| Alert volume | 2,400 alerts/day; 72% false positives |

**Recent incident:** NordLogistics suffered a ransomware attack 8 months ago.

Systems were down for 4 days.
Recovery cost: €1.8M.
The attacker was inside the network for 23 days before deploying ransomware.
The SIEM generated 12 related alerts during that period — none were acted upon.

## Deliverables

### 1. Maturity Assessment (Table)

Rate each SOC domain on a 1-5 maturity scale:
1 = Non-existent, 2 = Ad-hoc, 3 = Defined, 4 = Managed, 5 = Optimized

Domains: Technology, Detection Engineering, Incident Response, Threat Intelligence, People & Training, Processes & Procedures.

For each domain: current score, target score (12 months), key gap.

### 2. Gap Analysis (Top 5 Critical Gaps)

Identify the 5 most critical gaps.
For each gap:

* Current state
* Risk impact if not addressed
* Effort to fix (Low/Medium/High)
* Priority (P1/P2/P3)

### 3. 12-Month Improvement Roadmap

Create a phased improvement plan:

* **Months 1-3**: Quick wins (low effort, high impact)
* **Months 4-6**: Foundation building
* **Months 7-12**: Advanced capabilities

For each item: what will be done, success metric, responsible role.

### 4. Target KPIs (12 months)

Define target values for:

* MTTD, MTTR, False Positive Rate, Alert volume reduction, Detection coverage %, Playbooks documented.

### 5. Business Case Summary (200 words)

Write a brief business case justifying the SOC improvement investment to the CFO.
Use the ransomware incident as context.
Quantify the expected risk reduction.

## Hints

* The ransomware was inside for 23 days = MTTD failure. Focus on detection improvement first.
* 72% false positive rate = alert fatigue caused the missed alerts. Rule tuning is a quick win.
* No Tier 2/3 = alerts are triaged but never deeply investigated. Consider hiring or upskilling.
* 40% log coverage = huge blind spots. Getting to 80%+ coverage should be a Year 1 target.
* Industry benchmarks: mature SOCs target MTTD < 1 hour, MTTR < 4 hours, FPR < 20%.

## Evaluation Criteria

* Accuracy of maturity ratings (aligned with described current state).
* Specificity of gap analysis (concrete, not generic).
* Feasibility of roadmap (realistic timeline and effort estimates).
* Quality of business case (quantified risk reduction).
