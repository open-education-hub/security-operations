# Drill 02 — SOC Workflow Mapping

## Scenario

**MediCare IT GmbH** is a small healthcare IT company in Germany (80 employees).
They provide software to hospitals and clinics.
They have recently hired their first two dedicated security analysts and are building their SOC processes from scratch.

Currently, when a security alert fires:

* The on-call analyst gets an email
* The analyst investigates manually (no ticketing system)
* The analyst takes notes in a personal spreadsheet
* Resolution is communicated via email
* No formal documentation is kept

They have experienced two incidents in the last year where response was delayed or disorganized.

---

## Your Tasks

### Task 1: Identify Process Gaps (20 points)

Based on the current state described above, identify at least **5 specific process gaps**.
For each gap:

* Name the gap
* Explain the risk it creates
* Cite which best practice or framework addresses it

Consider the following dimensions: accountability, auditability, SLA management, knowledge transfer, regulatory compliance (especially GDPR for a healthcare company), and escalation.

### Task 2: Design the Ideal Alert Lifecycle (30 points)

Design a complete alert lifecycle for MediCare IT GmbH.
Draw (or describe using ASCII art) the workflow from alert detection to case closure.

Your workflow must include:

* All state transitions (minimum 5 states)
* Decision points (minimum 3)
* Escalation path
* Regulatory trigger (GDPR Article 33 for healthcare patient data breaches)
* Documentation points
* Estimated time targets for each transition

### Task 3: Write SLA Definitions (20 points)

Define SLAs appropriate for MediCare IT GmbH.
Given their size (80 employees, 2 analysts, no 24×7 coverage), you need to be realistic while maintaining appropriate security rigor.

Define SLAs for: Critical, High, Medium, Low severity.

For each severity level, specify:

* Acknowledgment time
* Investigation time
* Resolution time
* Who handles it (Tier 1 / Tier 2 / External MSSP / Escalate to management)
* Whether 24×7 on-call is required

Justify your choices based on the company size and regulatory context.

### Task 4: Design the Escalation Matrix (20 points)

Create an escalation matrix for MediCare IT GmbH.
Because they only have 2 analysts, the escalation structure is different from a large enterprise.

Your matrix must address:

* When to escalate from Analyst 1 → Analyst 2
* When to escalate to the company's IT Director (no dedicated SOC manager)
* When to escalate to the external MSSP (they have a contract)
* When to engage the DPO (they have a part-time DPO)
* When to notify the German DPA (Datenschutzbehörde) per GDPR

### Task 5: Identify Quick Wins (10 points)

MediCare IT GmbH has a budget of €5,000 for the first year to improve their SOC processes.
They cannot afford enterprise tools.

Recommend exactly **3 quick wins** that:

* Cost within budget (combined)
* Address the most critical gaps from Task 1
* Can be implemented within 1 month
* Include free/open-source tooling where possible

For each recommendation: tool/process name, cost, time to implement, gap addressed.

---

## Constraints

* MediCare IT GmbH has 2 analysts working 9-18 Mon–Fri
* No 24×7 coverage (on-call by personal phone only)
* Budget: €5,000 first year
* Regulatory obligation: GDPR (patient data of hospital clients), German healthcare data regulations (KHZG)
* They process patient-adjacent data (hospital scheduling, billing support)

---

## Hints

* When designing SLAs for a small team without 24×7 coverage, consider business-hours SLAs vs. calendar-time SLAs
* TheHive is free and provides case management — a major improvement over spreadsheets
* GDPR Article 33 requires 72-hour notification to the supervisory authority — this applies even to a 2-person SOC
* For a healthcare company, patient data breaches have regulatory AND reputational consequences
* Consider that the 2 analysts cannot be on call every night — a shared on-call rotation is not sustainable without support
