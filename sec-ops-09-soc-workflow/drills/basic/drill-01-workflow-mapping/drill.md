# Drill 01 (Basic): SOC Workflow Mapping

**Level**: Basic

**Estimated time**: 30-45 minutes

**Type**: Documentation / Analysis exercise (no lab environment required)

---

## Learning Objectives

* Practice documenting a SOC workflow from a scenario description
* Build a severity classification matrix
* Identify workflow gaps and improvement opportunities
* Create a RACI matrix for a described team

---

## Scenario: MedCorp SOC

**Context**: You are a newly hired SOC consultant at MedCorp, a healthcare company with 800 employees, 600 Windows endpoints, and 40 servers.
The SOC has been running for 18 months but has never formally documented its workflows.

**Current state (from analyst interviews)**:

* Team: 3 L1 analysts (split across 2 shifts), 1 L2 analyst, 1 SOC manager
* SIEM: Splunk with ~1,200 alerts/day
* Average alert volume per analyst: 200/shift
* SLA target: P1 within 4 hours (never formally measured)
* Ticket system: Jira (used inconsistently — some analysts create tickets, some don't)
* Escalation: Informal — analysts call each other or send Slack messages
* False positive rate: Estimated 65% (unmeasured)
* Current alert types: Failed logins (40%), Malware detections (15%), USB usage (20%), Policy violations (25%)
* The company processes patient health records (PHI) — HIPAA applies

**Known problems** (from your interviews):

1. Tickets often missing key fields (no standard template)
1. Night shift has no L2 coverage — escalations go to voicemail
1. Malware alerts sometimes take 6+ hours to investigate (analyst wasn't sure what to do)
1. High-criticality servers are not distinguished from regular workstations in alerts
1. No documented handover procedure — incoming shift starts from scratch

---

## Tasks

### Task 1: Document the Current Alert Lifecycle (10 min)

Using the workflow documentation template from Guide 01, document how alerts CURRENTLY flow through MedCorp's SOC (based on the scenario description above).
Include all steps from alert generation to closure, noting where there are gaps or unclear ownership.

Your documentation should cover:

* Alert generation
* Triage
* Ticket creation
* Investigation
* Escalation
* Resolution

### Task 2: Build an Asset Criticality Model (10 min)

Define asset criticality tiers for MedCorp.
Consider:

* Servers running the Electronic Health Records (EHR) system
* Active Directory domain controllers
* Employee workstations
* Medical devices (heart monitors, etc.) connected to the network
* HIPAA compliance requirements (PHI data must be protected)
* Administrative workstations used by billing department

Create a 4-tier criticality table with:

* Tier definition
* Example assets from MedCorp
* Special HIPAA considerations

### Task 3: Design a Severity Matrix (5 min)

Using your asset criticality tiers from Task 2, create a severity classification matrix.
Map threat severity (Critical/High/Medium/Low) × asset criticality (Tier 1-4) to P1-P4 severity ratings.

Consider: Should a Low threat against a Tier 1 asset be P3 or P2 at a healthcare company?

### Task 4: Identify Workflow Gaps (10 min)

Based on the scenario, list at least 6 specific workflow gaps.
For each gap, describe:

* The gap (what's missing or broken)
* The risk it creates
* A recommended fix

Format:
| # | Gap | Risk | Recommended Fix |
|---|-----|------|-----------------|

### Task 5: Design a RACI Matrix (10 min)

Create a RACI matrix for MedCorp's SOC covering these activities:

* Alert monitoring
* Ticket creation
* L1 investigation
* Escalation decision
* L2 investigation
* HIPAA incident notification
* Shift handover
* Playbook maintenance
* Metrics reporting

Roles to include: L1 Analyst, L2 Analyst, SOC Manager, CISO, Legal/Compliance

---

## Deliverables

Submit the following in a structured document:

1. Alert lifecycle documentation (with gaps noted)
1. Asset criticality table (4 tiers)
1. Severity classification matrix (4×4)
1. Gap analysis table (minimum 6 gaps)
1. RACI matrix

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Lifecycle documentation captures all key steps | 20 |
| Asset criticality model is appropriate for healthcare | 20 |
| Severity matrix is logically consistent | 15 |
| Gap analysis identifies real risks | 30 |
| RACI matrix has no ambiguous role assignments | 15 |
| **Total** | **100** |
