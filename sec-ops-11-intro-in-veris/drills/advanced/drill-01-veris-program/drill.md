# Drill 01 (Advanced): Design a VERIS-Based Incident Tracking Program

**Level:** Advanced

**Estimated time:** 90–120 minutes

**Directory:** `drills/advanced/drill-01-veris-program/`

**Prerequisites:** All basic and intermediate drills, Guide 01 (Intermediate)

---

## Overview

In this drill you will design and partially implement a VERIS-based incident tracking program for a mid-sized organization.
This is a realistic, systems-thinking exercise that requires you to apply VERIS knowledge to operational security program design.

---

## Scenario

You have been hired as the lead SOC analyst at **Meridian Financial Group**, a financial services company with:

* 2,400 employees across 6 offices
* NAICS: 522110 (Commercial Banking) + 523910 (Miscellaneous financial services)
* IT environment: hybrid cloud (AWS + on-premises)
* ~40 security incidents per year historically
* Current incident documentation: unstructured Word documents and email threads
* No metrics or trend reporting capability
* Compliance requirements: GLBA, SOX, state breach notification laws, PCI DSS

**Your mandate**: Design and implement a VERIS-based incident tracking program that will:

1. Standardize incident documentation
1. Enable quarterly metrics reporting
1. Support breach determination and regulatory notification decisions
1. Produce annual threat landscape analysis comparable to industry benchmarks

---

## Part 1: Program Design Document (30 minutes)

Write a program design document covering:

### 1.1 Scope and Objectives

Define:

* What constitutes a recordable incident (vs. security event)
* Minimum information required to open a VERIS record
* Who is responsible for creating and reviewing VERIS records
* How long records are retained

### 1.2 VERIS Record Lifecycle

Design the lifecycle from incident detection to closed VERIS record:

```text
[Detection] → [Triage] → [Investigation] → [VERIS Encoding] → [Review] → [Closed]
```

For each stage, specify:

* What VERIS fields are populated at that stage
* Who is responsible
* What the timeline requirement is

### 1.3 Field Requirements

Based on Meridian's requirements, specify:

* Which VERIS fields are **required** for every record
* Which fields are **required only for breaches** (Confidentiality disclosure = Yes)
* Which fields are **optional but recommended**

### 1.4 Integration Points

How will VERIS records integrate with:

* The ticketing system (ServiceNow or similar)
* The SIEM (for discovery method tracking)
* Legal/compliance team (for breach notification workflows)
* Management reporting

---

## Part 2: Classification Policy (20 minutes)

Write a **one-page classification policy** that provides clear guidance for common ambiguous situations.
Address each of the following:

2a.
When does an unencrypted lost laptop become a reportable data breach vs. a privacy incident?

2b.
How should cloud misconfigurations be classified when you are uncertain whether data was accessed?

2c.
When should a phishing email that was blocked by email security be recorded vs. not recorded?

2d.
How should ransomware be classified before and after a forensic investigation confirms/denies exfiltration?

2e.
Under what circumstances should an External actor be classified as Nation-state vs.
Unknown?

---

## Part 3: Metrics Framework (20 minutes)

Design a quarterly metrics dashboard with 8 key VERIS-derived metrics.
For each metric:

* Define it precisely using VERIS field(s)
* State what it measures
* Define a target/threshold
* Describe how you calculate it

**Start with these 4 and add 4 of your own:**

1. **Breach Rate**: `[Confidentiality.data_disclosure = "Yes" count] / [total incidents]`
1. **Mean Time to Discovery (MTTD)**: `mean(timeline.discovery.value)` where unit normalized to days
1. **Internal Detection Rate**: `[discovery_method.internal count] / [total incidents]`
1. **External Actor Rate**: `[incidents with actor.external] / [total incidents]`

Add 4 more metrics of your own design.

---

## Part 4: Implementation (40 minutes)

Implement the following components in Python:

### 4.1 VERIS Record Template Generator

Write a function `generate_template(incident_type: str) -> dict` that returns a pre-populated VERIS JSON template optimized for the most common incident types at a financial services firm:

```python
# Supported types:
# "phishing" - Social engineering initial access
# "ransomware" - Ransomware attack
# "misconfiguration" - Cloud/system misconfiguration
# "credential_theft" - Credential-based account compromise
# "insider_misuse" - Internal actor data misuse
# "lost_device" - Lost or stolen device
```

Each template should pre-populate:

* `schema_version`
* `source_id`
* `confidence` (initial value)
* Actor type, variety, and motive (best guesses for the type)
* Action category and common variety for that type
* Most common asset type for that incident type
* Relevant attribute (Confidentiality for data incidents, Availability for ransomware, etc.)

### 4.2 Breach Determination Engine

Write a function `determine_breach_status(record: dict) -> dict` that returns:

```python
{
  "is_confirmed_breach": bool,
  "is_potential_breach": bool,
  "regulatory_triggers": list,  # e.g. ["HIPAA", "GLBA", "State PII"]
  "notification_required": bool,
  "recommended_action": str
}
```

The function should check:

* Confidentiality.data_disclosure value
* Data types exposed (for regulatory mapping)
* Whether notification deadlines apply

### 4.3 Quarterly Metrics Calculator

Write a function `quarterly_metrics(records: list, year: int, quarter: int) -> dict` that:

* Filters records to the specified quarter
* Calculates all 8 metrics from Part 3
* Returns a structured metrics report

---

## Part 5: Sample Records

Create 5 VERIS JSON records representing realistic incidents Meridian Financial Group might experience:

1. A phishing attack targeting the CFO (BEC attempt, blocked before wire transfer)
1. A cloud S3 misconfiguration exposing customer statements
1. A ransomware attack that encrypted 30 workstations in branch office
1. An insider misuse incident (loan officer accessed competitor's customer data)
1. A third-party vendor suffering a breach that exposed Meridian customer data

---

## Deliverables

1. Part 1: Program design document (~500 words)
1. Part 2: Classification policy (one page)
1. Part 3: Metrics framework table (8 metrics)
1. Part 4: Three Python functions (template generator, breach engine, metrics calculator)
1. Part 5: Five VERIS JSON records

Compare with model answers in:
`drills/advanced/solutions/drill-01-solution/solution.md`

---

*Drill 01 (Advanced) | Session 11 | Security Operations Master Class | Digital4Security*
