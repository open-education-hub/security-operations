# Drill 02 (Advanced): Correlation Architecture Design

**Level:** Advanced

**Estimated time:** 90 minutes

**Deliverable:** A correlation architecture design document for a mid-size enterprise SOC

---

## Scenario

You have been hired as a senior security architect to design the detection and correlation infrastructure for **CorpBank**, a mid-size financial institution with:

* **3,000 endpoints** (Windows workstations and servers)
* **5 data centers** across 3 geographic regions
* **Cloud presence**: 60% workloads in AWS, 20% in Azure
* **400 applications** including 3 critical banking platforms
* **12 SOC analysts** across two shifts (8h each), 24/7 coverage
* **Compliance requirements**: PCI-DSS, SOX, local banking regulation (7-year log retention)
* **Current state**: Splunk ES deployed, 200 GB/day ingest, 95% FP rate, analyst fatigue is a crisis

**Business goals:**

1. Reduce analyst alert fatigue (target: each analyst handles ≤15 actionable alerts/shift)
1. Detect account compromise within 15 minutes of first indicator
* Detect lateral movement before ransomware deployment (MTTD ≤ 30 min)
1. Achieve ATT&CK coverage ≥60% for top-10 ransomware techniques
1. Maintain 7-year log retention for compliance at reasonable cost

---

## Part 1: Architecture Design

### Task 1.1: Design the Log Ingestion and Normalization Pipeline

Design the end-to-end pipeline from log source to SIEM, considering:

* Volume: 200 GB/day current, projected 500 GB/day in 18 months
* Cloud and on-premise sources
* Normalization requirements (choose a schema)
* Cost optimization for the 7-year retention requirement

Draw a block diagram (ASCII or describe components) with:

* Data flow
* Key tool choices with justification
* Tiering strategy (hot/warm/cold storage)

**Your design should answer:**

1. What normalization schema do you choose and why?
1. Where does normalization happen (agent? collector? SIEM ingest)?
1. How do you handle the cost of 7-year retention at 500 GB/day?
1. What is your strategy for the 60% AWS workloads?

### Task 1.2: SIEM Tier Architecture

Given the analyst capacity (12 analysts, ≤15 alerts/shift = 180 actionable alerts/day total), design a tiered detection architecture:

**Tier 1 (SIEM):** High-fidelity, rule-based detection for known TTPs

**Tier 2 (UEBA):** Behavioral anomaly detection for account compromise

**Tier 3 (XDR/EDR):** Endpoint and cloud-native detection

For each tier, specify:

* Primary detection technology
* Types of rules/models deployed
* Alert routing (who handles what)
* Expected alert volume contribution

---

## Part 2: Detection Priority Planning

### Task 2.1: Ransomware Technique Coverage Plan

CorpBank's threat intelligence team has identified the following top-10 ransomware techniques for the banking sector (in order of frequency in recent campaigns):

| Rank | Technique | ID |
|------|-----------|-----|
| 1 | Valid Accounts | T1078 |
| 2 | Phishing: Spearphishing Attachment | T1566.001 |
| 3 | Command and Scripting: PowerShell | T1059.001 |
| 4 | Inhibit System Recovery (VSS deletion) | T1490 |
| 5 | Data Encrypted for Impact | T1486 |
| 6 | Remote Services: SMB/Admin Shares | T1021.002 |
| 7 | OS Credential Dumping | T1003 |
| 8 | Scheduled Task/Job | T1053.005 |
| 9 | Boot/Logon Autostart: Registry | T1547.001 |
| 10 | Exfiltration over Web | T1048 |

Create a detection coverage plan:

| Rank | Technique | Data Source | Rule Type | Priority | Existing? | Gap to Close |
|------|-----------|------------|-----------|----------|-----------|-------------|
| 1 | T1078 | | | High | | |
| ... | | | | | | |

### Task 2.2: MTTR/MTTD Target Achievement

The goal is MTTD ≤ 15 min for account compromise and ≤ 30 min for lateral movement.

For each scenario, design the detection rule chain that achieves this MTTD:

**Scenario A: Compromised credential used from external IP**

```text
T=0:    Attacker purchases credential from dark web marketplace
T=5m:   First login attempt from foreign IP using valid credentials
T=?:    SOC detects and contains

Design the detection rule(s) and response playbook to achieve ≤15 min MTTD.
```

**Scenario B: Ransomware staging (pre-deployment phase)**

```text
T=0:    Attacker lateral-moves to domain controller
T=5m:   Domain enumeration commands run
T=10m:  Shadow copies deleted (vssadmin delete shadows /all)
T=15m:  Ransomware deployed to share

Design detection to catch at T=5m to T=10m window (≤30 min MTTD from step 1).
```

---

## Part 3: Rule Governance Model

### Task 3.1: Design a Rule Lifecycle Governance Process

Design a governance process for the detection rule library.
Include:

1. **Rule intake**: How does a new rule get proposed? (threat intel, purple team, vendor, ISAC)
1. **Development phase**: Who writes the rule? What tooling?
1. **Testing phase**: What tests must pass before production deployment?
1. **Production deployment**: Change management, rollback plan
1. **Monitoring phase**: How is rule performance tracked (FP rate, TP rate)?
1. **Retirement phase**: When and how is a rule deprecated?

Draw the lifecycle as a state machine or flowchart (describe states and transitions).

### Task 3.2: Rule Repository Structure

Design the Git repository structure for CorpBank's detection-as-code implementation:

```text
corpbank-detections/
├── [YOUR STRUCTURE]
```

Include:

* Directory organization (by tactic? by data source? by platform?)
* Required files per rule (rule YAML, test cases, tuning notes)
* CI/CD pipeline configuration (testing, compilation, deployment)
* How ATT&CK coverage is tracked automatically

---

## Part 4: Capacity and Cost Planning

### Task 4.1: Alert Volume Budget

Calculate the required detection infrastructure to achieve the analyst capacity target:

```text
Given:
- 12 analysts, 2 shifts = 6 analysts/shift
- Target: ≤15 actionable alerts/analyst/shift
- Alert investigation time: average 20 min/alert
- Shift duration: 8 hours (480 min)
- Non-alert time: 30% (training, documentation, escalations)

Calculate:
- Maximum actionable alerts/shift (total across all analysts)
- Required alert-to-actionable ratio (target FP rate)
- If current volume is 2,000 alerts/day with 5% TP rate,
  what is the current workload gap?
```

### Task 4.2: Data Retention Cost Model

Design a tiered storage model for 7-year retention:

```text
Assumptions:
- Current ingest: 200 GB/day raw logs
- After normalization/compression: 50 GB/day
- Hot tier (0-30 days): Fast SSD, high cost — needed for active investigations
- Warm tier (31-90 days): SSD/HDD hybrid — incidents span up to 90 days
- Cold tier (91 days - 7 years): Object storage (S3/Azure Blob) — compliance only

Calculate:
- Storage required for each tier
- Estimated monthly cost (use: hot=$0.23/GB, warm=$0.07/GB, cold=$0.004/GB)
- Total annual TCO for data retention
```

---

## Part 5: Architecture Document

Write a 2-page architecture document (equivalent) covering:

1. **Executive Summary**: Key decisions and rationale
1. **Architecture Diagram**: Text description of the data flow
1. **Technology Choices**: What you chose and why (not chose and why not)
1. **Detection Strategy**: Tiered approach, priority techniques, coverage targets
1. **Risk and Limitations**: What this architecture does NOT protect against
1. **Roadmap**: 6-month, 12-month, 24-month milestones

---

## Submission Checklist

* [ ] Task 1.1: Ingestion/normalization pipeline design with 4 questions answered
* [ ] Task 1.2: Three-tier detection architecture (SIEM/UEBA/XDR)
* [ ] Task 2.1: Ransomware coverage plan table (all 10 techniques)
* [ ] Task 2.2: MTTD achievement design for both scenarios
* [ ] Task 3.1: Rule lifecycle governance process
* [ ] Task 3.2: Git repository structure
* [ ] Task 4.1: Alert volume calculations
* [ ] Task 4.2: Storage cost model
* [ ] Part 5: Architecture document
