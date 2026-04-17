# Drill 02 (Advanced): Data Lake Security Architecture Design

**Estimated time:** 90 minutes

**Difficulty:** Advanced

**Tools:** Architecture design tool (draw.io, Mermaid, or paper)

## Objective

Design a complete, production-grade security data lake architecture for a hypothetical organization.
This drill tests your understanding of log collection, normalization, storage tiers, and analysis pipeline design.

## Organization Profile

**ACME Financial Corp:**

* 5,000 employees across 3 offices (NYC, London, Singapore)
* AWS multi-region deployment (us-east-1, eu-west-1, ap-southeast-1)
* On-premises data center in NYC (primary) with DR site in Chicago
* Active Directory (2,000 managed Windows workstations)
* 200 Linux servers (on-prem + AWS EC2)
* Palo Alto NGFW at each office perimeter
* M365 (Office 365) for email and collaboration
* Regulatory requirements: SOX (7-year retention), PCI-DSS (1-year online, 3-month available), GDPR (data minimization)
* Budget: approximately $500K/year for security tooling (log storage + SIEM)
* Current state: No SIEM, no centralized logging

## Challenge Tasks

### Task 1: Log Source Inventory (20 min)

Create a comprehensive inventory of all log sources ACME should collect.

For each source, specify:

* Log type and format
* Volume estimate (events/day or GB/day)
* Collection method
* Security priority (Critical / High / Medium / Low)
* Retention requirement

**Table template:**

| Source | Format | Est. Volume | Collection Method | Priority | Retention |
|--------|--------|-------------|-------------------|----------|-----------|
| Windows Event Logs (2000 endpoints) | WinEventLog XML | ? | ? | ? | ? |
| ... | ... | ... | ... | ... | ... |

Include at least 15 log sources.

---

### Task 2: Architecture Design (30 min)

Design the data lake architecture.
Your design must address:

**Collection Layer:**

* How do logs get from source to central platform?
* How do you handle the three geographic regions differently?
* How do you handle cloud vs. on-premises differently?

**Normalization Layer:**

* What tool(s) perform normalization?
* What schema standard do you adopt (ECS, CIM, custom)?
* Where does normalization happen (at collection, at ingest, or at query)?

**Storage Layer:**

* What technology stores the data?
* How do you implement hot/warm/cold tiering?
* How do you handle the competing retention requirements (7 years for SOX vs. GDPR data minimization)?

**Analysis Layer:**

* What SIEM/analytics platform?
* How do you serve the three geographic SOC teams?
* How do you integrate threat intelligence?

**Draw (or describe in detail) the architecture.** If drawing is not possible, write a detailed description that includes data flow, components, and key design decisions.

---

### Task 3: Volume Calculation (15 min)

Estimate the storage requirements for your architecture.

Given:

* Windows endpoints generate approximately 500KB/endpoint/day of compressed, indexed logs
* Linux servers: 200KB/server/day
* Firewall: 2GB/firewall/day (raw), compresses to ~400MB
* AWS CloudTrail: ~50MB/day total across all regions
* Web proxy: ~1GB/day

Calculate:

1. Total raw volume per day
1. Total compressed volume per day (assume 5:1 compression on text logs)
1. Total storage for hot tier (90 days)
1. Total storage for warm tier (90 days to 12 months)
1. Total storage for cold archive (1 year to 7 years)
1. Estimated monthly cost for each tier (use AWS S3 pricing: $0.023/GB/month for standard, $0.004/GB/month for Glacier)

---

### Task 4: Compliance Mapping (15 min)

For ACME's regulatory requirements, create a compliance mapping:

**SOX Requirements:**

* Which log sources must be retained for 7 years?
* Which systems are "in scope" for SOX?
* How do you prove log integrity for audit purposes?

**PCI-DSS Requirements:**

* Define the Cardholder Data Environment (CDE) scope
* Which logs from CDE systems require 1-year retention with 3-month online availability?
* How do you separate PCI-in-scope logs from out-of-scope logs in the data lake?

**GDPR Requirements:**

* Which log sources contain personal data?
* How do you handle the right to erasure for logs?
* What is your data minimization strategy?

---

### Task 5: Threat Detection Priority List (10 min)

Given ACME is a financial services company with the above profile, prioritize 10 detection rules for the SIEM.
For each:

* Name the rule
* Identify the primary data source(s)
* Map to MITRE ATT&CK
* Justify the priority

---

See `../solutions/drill-02-solution/README.md` for a complete reference architecture.
