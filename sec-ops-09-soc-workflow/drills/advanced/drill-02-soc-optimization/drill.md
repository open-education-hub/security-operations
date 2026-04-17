# Drill 02 (Advanced): SOC Workflow Optimization — FinServ Corp

**Level**: Advanced

**Estimated time**: 2-3 hours

**Type**: Analysis + design + partial implementation

**Prerequisites**: All session materials completed

---

## Learning Objectives

* Perform a complete SOC maturity assessment from a breach post-mortem
* Design a multi-phase optimization roadmap
* Identify root causes across people, process, and technology failures
* Redesign SOAR automation with appropriate safeguards
* Build a business case for SOC improvement investment

---

## Scenario: FinServ Corp SOC Optimization

**Context**: FinServ Corp is a financial services company under regulatory scrutiny after a breach exposed customer data.
The breach occurred because:

1. A phishing email was not investigated for 11 hours (SLA breach)
1. The compromised account was not disabled for 4 hours after confirmation
1. Post-breach analysis revealed the SOAR automation blocked a legitimate CDN IP, causing a 2-hour outage

**Current SOC state:**

| Metric | Current Value |
|--------|--------------|
| Team | 8 L1 analysts, 3 L2, 1 SOC Manager |
| Alert volume | 4,500/day |
| MTTD (phishing) | 6.2 hours average |
| MTTR (P1) | 8.5 hours (target: 4 hours) |
| False positive rate | 58% overall; 73% for phishing |
| Automation rate | 35% (XSOAR deployed 6 months ago) |
| P1 SLA compliance | 67% |
| Coverage | 3-shift rotation; night shift: 2 L1, no L2 |

**Breach timeline (known facts):**

* 23:14 — Phishing email arrives; Splunk alert fires
* 23:14 — Alert goes to night shift queue (2 L1 analysts, each with 180+ alerts)
* 23:45 — User clicks link; reports to helpdesk
* 06:20 — Helpdesk escalates to SOC (7.5 hours later)
* 06:25 — L1 escalates to on-call L2
* 10:15 — L2 disables account (4 hours after escalation)
* 10:22 — Data exfiltration confirmed (11 hours after email)

**SOAR automation issue (separate incident):**

* XSOAR playbook auto-blocked IPs with reputation score >40
* Blocked Cloudflare 104.16.0.0/12 range
* 12 applications went offline for 2 hours
* Alert from IT took 2 hours to be associated with the SOAR action

---

## Tasks

### Task 1: Breach Root Cause Analysis

**1.1** Build a detailed timeline with each event, decision point, and failure.

**1.2** For each failure, categorize as:

* Process failure (procedure wrong or missing)
* Tool failure (technology didn't perform)
* Human failure (wrong decision by individual)
* Coverage failure (nobody available)

**1.3** Analyze the Cloudflare IP block automation failure:

* Root cause
* Required safeguards that were missing
* Redesigned blocking playbook
* Monitoring that would have detected the issue faster

### Task 2: Redesign SOC Workflow

**2.1** Redesign the phishing workflow addressing:

* Young/newly registered domains (age <7 days = high risk even without VT history)
* Integration with helpdesk for user-reported phishing
* Target: MTTD <30 min for phishing
* Human-in-the-loop gate for containment on uncertain detections

**2.2** Redesign night shift coverage:

* Ensure P2+ phishing alerts get 15-min response at any hour
* No new headcount (budget constraint)
* Use automation to reduce night shift volume by 50%

**2.3** Fix the SOAR IP blocking:

* Multi-layer allowlist design
* Auto-block vs. approval logic
* Monitoring for SOAR-initiated network changes
* Rollback procedure

### Task 3: Metrics and Roadmap

**3.1** Define measurable targets for all key metrics.

**3.2** Design a 3-phase implementation roadmap:

* Phase 1 (Week 1-2): Quick wins
* Phase 2 (Month 1-3): Process improvements
* Phase 3 (Month 3-6): Technology improvements

**3.3** Create a 5-slide executive presentation outline.

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Root cause analysis identifies all failure types | 20 |
| Phishing workflow redesign addresses all gaps | 20 |
| Night shift coverage is realistic | 15 |
| SOAR automation fix is technically sound | 15 |
| Metrics targets are specific and measurable | 15 |
| Implementation roadmap is realistic and prioritized | 15 |
| **Total** | **100** |
