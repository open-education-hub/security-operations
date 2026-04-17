# Drill 02 (Advanced): IR Program Design for an Organization

> **Level:** Advanced
> **Estimated time:** 2–3 hours
> **Format:** Consulting project / written deliverables
> **Deliverable:** Complete IR program design document

---

## Overview

This drill simulates a real consulting engagement.
You have been hired as a security consultant to design an incident response program from scratch for a specific organization.
This means going beyond writing a single IR Plan — you must think about the entire IR *program*: team structure, tooling, metrics, governance, regulatory integration, and continuous improvement.

This is the kind of work done by consultants at major firms (Deloitte Cyber, PwC Cybersecurity, Mandiant Consulting) when helping organizations build IR capabilities.

---

## Client Brief

**Client:** TransLog d.o.o. — a Slovenian logistics company

**Business description:**
TransLog operates across 8 EU countries.
They manage freight forwarding, customs documentation, and last-mile delivery. 1,200 employees.
Annual revenue: EUR 85M.
They moved to a hybrid cloud environment (Azure + on-premises data center in Ljubljana) two years ago.

**What they handle:**

* Personal data of ~250,000 EU individuals (customers: shippers and receivers)
* Commercial shipping documents and customs declarations (some involve dual-use goods)
* Real-time tracking data integrated with carrier APIs
* Payment processing via Stripe (no card data stored internally)
* Data related to ~4,000 business customers (B2B clients)

**Regulatory obligations:**

* GDPR (controller for personal data of individuals)
* NIS2 (classified as Important Entity — transport sector, Article 3(2))
* Slovenia national authority: IP RS (Information Commissioner of the Republic of Slovenia)
* CERT contact: SI-CERT

**Current IR state:**

* No formal IR plan
* No CSIRT or dedicated security team
* 3 IT staff manage all security and IT operations
* EDR deployed to all Windows endpoints last year
* No SIEM (reviewing options)
* Cyber insurance purchased 6 months ago
* One tabletop exercise conducted: "we played it by ear"
* GDPR compliance: DPO appointed (part-time), breach register exists but has had no entries (suspicious, given 250,000 people's data is processed)

**Recent incident (not properly handled):**

* 3 months ago: A logistics coordinator's laptop was stolen from their car. The laptop had a local copy of a customer database segment (not supposed to be stored locally per policy). IT disabled the account and reported the laptop stolen to police. No GDPR notification was made. No PIR was conducted.

**Budget for IR program:** EUR 80,000 first year (including tooling, training, external retainer)

---

## Your Deliverables

### Deliverable 1: IR Program Maturity Assessment (Current State)

Rate TransLog's current IR maturity across 5 dimensions.
Use a 1–5 scale (1=None, 2=Initial, 3=Developing, 4=Defined, 5=Optimized).

For each dimension, provide:

* Current maturity score (1–5)
* Evidence from the brief supporting your score
* Target score for end of Year 1

| Dimension | Current (1–5) | Evidence | Target Y1 (1–5) |
|---------|--------------|---------|----------------|
| Preparation & Planning | | | |
| Detection & Analysis | | | |
| Containment & Response | | | |
| Regulatory Compliance | | | |
| Post-Incident Learning | | | |

Also: Was the stolen laptop incident handled correctly?
Identify all the failures and their consequences.

### Deliverable 2: IR Team Design

TransLog cannot afford a dedicated CSIRT.
Design a **virtual CSIRT model** using existing staff and external resources.

Your design must include:

1. **Team structure chart**: Show all roles, whether they are internal or external, and reporting lines
1. **Role descriptions** (one paragraph each) for the 5 most critical roles
1. **Escalation matrix**: Who to call for P1, P2, P3, P4
1. **External resources**: Which vendors/services to retain (IR retainer, forensics, legal — be specific about what each provides and estimated cost allocation)
1. **On-call coverage design**: TransLog operates 24/7 logistics. How do you ensure after-hours P1 response capability with only 3 IT staff?

Budget allocation guidance: assign the EUR 80,000 budget across team-related items (training, retainer, tools).

### Deliverable 3: Tooling Roadmap

Design a 12-month tooling roadmap.
Given the budget constraints, prioritize tools that give the most IR capability improvement.

**Format:**

```text
QUARTER 1 (Month 1–3): Foundation Tools
  Tool 1: [Name + purpose + estimated cost]
  Tool 2: ...
  Milestone: [what IR capability is enabled by end of Q1]

QUARTER 2 (Month 4–6): Detection Enhancement
  Tool 3: ...
  Milestone: ...

QUARTER 3 (Month 7–9): Response Enhancement
  ...

QUARTER 4 (Month 10–12): Consolidation & Automation
  ...
```

Include specific tools from the reading material (TheHive, Volatility, KAPE, MISP, etc.) and justify why each is appropriate for TransLog's environment.

### Deliverable 4: IR Plan Outline

Write a complete **outline** (not full content) for TransLog's IR Plan.
This means:

* Full table of contents with all sections and subsections
* One-paragraph description of what each major section covers
* Annotation of which sections need legal review before finalization

Your outline should be structured so that someone could use it to write the full IR Plan.

### Deliverable 5: Regulatory Integration Plan

TransLog has never filed a breach notification.
Based on the recent stolen laptop incident and their ongoing obligations, design a regulatory integration plan:

1. **Retrospective assessment**: Should TransLog have filed a GDPR notification for the stolen laptop? Build the legal argument both ways (yes and no). What should they do now?

1. **Breach assessment process**: Design a decision flowchart that TransLog staff can use within the first 2 hours of any incident to determine whether regulatory notification is required and to which authorities.

1. **Notification calendar template**: Create a template tracking sheet for monitoring notification deadlines during an active incident.

1. **Training requirement**: What regulatory knowledge must all members of the virtual CSIRT have? Design a 2-hour regulatory awareness module outline.

### Deliverable 6: 12-Month IR Metrics Dashboard

Design the IR program metrics dashboard that TransLog's CISO will review monthly.
Include:

1. **Operational metrics** (5 KPIs): Specific, measurable, with targets
1. **Compliance metrics** (3 KPIs): GDPR/NIS2 compliance indicators
1. **Program maturity metrics** (2 KPIs): Track improvement over time

For each metric, specify:

* Metric name and definition
* Measurement method (how will you get this data?)
* Month 1 baseline estimate
* Year-end target

### Deliverable 7: Quick-Win Recommendations

Identify the 5 actions TransLog should take in the first 30 days to reduce IR risk, before any tooling or formal program is complete.
Order them by impact-to-effort ratio.

For each quick win:

```text
Quick Win #[N]: [Title]
  Action: [Specific steps]
  Impact: [What risk is reduced]
  Effort: [Time/cost estimate]
  Owner: [Role]
  Deadline: Day [X] of Month 1
```

---

## Evaluation Criteria

| Deliverable | Max Points | Key Assessment Criteria |
|------------|-----------|------------------------|
| Maturity Assessment | 15 | Accurate scoring with evidence, realistic targets |
| IR Team Design | 20 | Realistic virtual model, budget awareness, on-call solution |
| Tooling Roadmap | 15 | Appropriate tool selection, logical prioritization |
| IR Plan Outline | 15 | Completeness, structure, legal annotation |
| Regulatory Integration | 20 | Correct retrospective analysis, usable flowchart, accurate notification rules |
| Metrics Dashboard | 10 | Measurable KPIs with targets and collection methods |
| Quick Wins | 5 | Practical, high-impact, realistic for small team |
| **Total** | **100** | |

---

## Professional Context

This type of work is the core output of a security consulting engagement.
The skills demonstrated in this drill translate directly to:

* **Security consulting**: GRC and incident response advisory at Big 4 and boutique firms
* **CISO roles**: Building IR programs at organizations with limited resources
* **IR program management**: Program management roles at mature security organizations
* **Certification exams**: CISM, CISSP, CRISC all test IR program design thinking

When reviewing your solution, ask yourself: would a sophisticated client like TransLog pay for this advice?
Does it reflect real-world constraints (budget, staffing, regulatory pressure)?

---

## Solution

See: `../../solutions/drill-02-solution/solution.md`
