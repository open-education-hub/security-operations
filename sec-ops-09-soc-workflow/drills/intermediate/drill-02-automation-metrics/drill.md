# Drill 02 (Intermediate): Calculate Automation Metrics from SOC Data

**Level**: Intermediate

**Estimated time**: 45-60 minutes

**Type**: Data analysis exercise (no lab environment required)

---

## Learning Objectives

* Calculate MTTD, MTTR, MTTA from raw ticket data
* Calculate and interpret false positive rate
* Calculate automation rate before and after SOAR deployment
* Identify highest-ROI automation opportunities from metrics
* Build a business case for SOAR investment using calculated metrics

---

## Scenario: RetailCo SOC Metrics Analysis

**Context**: RetailCo is a retail chain with 200 stores.
Their SOC has been operational for 2 years.
Management is considering investing in a SOAR platform (Shuffle or XSOAR) and has asked you to:

1. Analyze current SOC performance data
1. Project the benefit of automation
1. Build a business case

---

## Part 1: Raw Data

### Dataset 1: Alert resolution data (30-day period)

| Ticket ID | Alert Type | Severity | Alert Time | Ack Time | Investigation Start | Resolution Time | Resolution Type |
|-----------|-----------|----------|-----------|---------|---------------------|-----------------|----------------|
| TKT-1001 | Phishing | P2 | 2026-03-01 08:15 | 2026-03-01 08:32 | 2026-03-01 08:45 | 2026-03-01 10:22 | True Positive |
| TKT-1002 | Phishing | P3 | 2026-03-01 09:42 | 2026-03-01 10:15 | 2026-03-01 10:30 | 2026-03-01 11:05 | False Positive |
| TKT-1003 | Brute Force | P2 | 2026-03-01 11:20 | 2026-03-01 11:28 | 2026-03-01 11:35 | 2026-03-01 13:50 | True Positive |
| TKT-1004 | Malware | P1 | 2026-03-01 14:00 | 2026-03-01 14:04 | 2026-03-01 14:10 | 2026-03-01 16:45 | True Positive |
| TKT-1005 | Phishing | P2 | 2026-03-01 15:30 | 2026-03-01 16:10 | 2026-03-01 16:25 | 2026-03-01 17:15 | False Positive |
| TKT-1006 | Phishing | P3 | 2026-03-01 17:00 | 2026-03-01 18:45 | 2026-03-01 19:00 | 2026-03-01 19:30 | False Positive |
| TKT-1007 | Brute Force | P3 | 2026-03-02 08:05 | 2026-03-02 09:00 | 2026-03-02 09:15 | 2026-03-02 10:00 | False Positive |
| TKT-1008 | Malware | P2 | 2026-03-02 11:15 | 2026-03-02 11:20 | 2026-03-02 11:30 | 2026-03-02 14:20 | True Positive |
| TKT-1009 | Policy Viol. | P4 | 2026-03-02 14:30 | 2026-03-02 17:00 | 2026-03-02 17:30 | 2026-03-03 09:00 | True Positive |
| TKT-1010 | Phishing | P2 | 2026-03-02 16:00 | 2026-03-02 16:18 | 2026-03-02 16:30 | 2026-03-02 17:45 | True Positive |

**Note**: This is a sample of 10 tickets.
For the full 30-day period:

* Total tickets created: 847
* Phishing tickets: 412 (of which 285 are FP)
* Brute Force tickets: 198 (of which 88 are FP)
* Malware tickets: 72 (of which 9 are FP)
* Policy Violation tickets: 165 (of which 41 are FP)

### Dataset 2: SLA Compliance (30-day period)

| Severity | Total Tickets | Resolved in SLA | SLA Breaches |
|----------|--------------|-----------------|--------------|
| P1 | 12 | 10 | 2 |
| P2 | 187 | 159 | 28 |
| P3 | 445 | 398 | 47 |
| P4 | 203 | 175 | 28 |

SLA targets: P1=4h, P2=8h, P3=24h, P4=72h

### Dataset 3: Analyst time tracking (sample, per ticket type)

| Alert Type | Average Analyst Time (Manual) | Tasks that are Automatable |
|-----------|------------------------------|---------------------------|
| Phishing | 14 min | IOC extraction (3 min), VT check (3 min), quarantine (2 min) = 8 min |
| Brute Force | 18 min | IP reputation check (3 min), AD lookup (2 min), block IP (2 min) = 7 min |
| Malware | 35 min | Hash VT check (3 min), process tree export (5 min) = 8 min |
| Policy Viol. | 8 min | Asset lookup (1 min), user lookup (1 min) = 2 min |

### Dataset 4: Staffing and cost

| Role | Count | Average annual salary | Hours/day |
|------|-------|----------------------|-----------|
| L1 Analyst | 4 FTE | $65,000 | 8h |
| L2 Analyst | 2 FTE | $85,000 | 8h |
| SOC Manager | 1 FTE | $105,000 | 8h |

---

## Part 2: Calculation Tasks

### Task 1: Calculate MTTD, MTTA, MTTR (using sample data)

Using the 10 tickets in Dataset 1:

1. Calculate MTTA for each ticket (Alert Time → Ack Time)
1. Calculate MTTR for each ticket (Alert Time → Resolution Time)
1. Calculate average MTTD (assume Detection Time = Alert Time for this exercise)
1. Identify which tickets breached SLA

Show your work for all calculations.

### Task 2: Calculate False Positive Rates

Using Dataset 1 (full 30-day totals):

1. Calculate FPR for each alert type
1. Calculate overall FPR
1. Rank alert types by FPR (highest FP rate first)
1. Calculate total analyst-hours wasted on FPs per month

Analyst-hours formula: `FP Count × Average Analysis Time / 60`

### Task 3: Calculate SLA Compliance Rates

Using Dataset 2:

1. Calculate SLA compliance rate for each severity
1. Identify which severity level has the worst compliance
1. Calculate what percentage improvement is needed to reach 95% for all levels

### Task 4: Calculate Automation ROI

Using Dataset 3 (automatable time per ticket type):

1. Calculate total analyst-hours/month currently spent on automatable tasks for each type
1. Assume 70% automation rate for phishing, 60% for brute force, 40% for malware, 80% for policy violations
1. Calculate monthly analyst-hours saved post-automation
1. Calculate annual cost savings (use L1 analyst salary, assume all automatable work is L1)
1. Shuffle SOAR setup cost: $0 (open source) + 40 hours engineer time ($50/hr) = $2,000

   Ongoing maintenance: 5 hours/month
   Calculate ROI over 12 months

### Task 5: Build a Metrics Dashboard Table

Create a summary table with all calculated metrics:
| Metric | Current Value | Target | Gap |
|--------|--------------|--------|-----|
| Overall MTTD | ? | <1h | ? |
| Average MTTA (P1/P2) | ? | <15min | ? |
| Average MTTR (P1) | ? | <4h | ? |
| Overall FPR | ? | <20% | ? |
| Phishing FPR | ? | <15% | ? |
| P1 SLA Compliance | ? | >95% | ? |
| P2 SLA Compliance | ? | >95% | ? |
| Automation Rate | 0% (current) | 60% | 60% |
| Analyst hrs/day on FPs | ? | <20% capacity | ? |

---

## Part 3: Business Case

Based on your calculations, write a 1-page business case (max 400 words) recommending whether to:

* Deploy Shuffle SOAR (free, moderate effort)
* Purchase XSOAR ($50K/year license, lower setup effort)
* Do nothing / invest in rule tuning instead

Include:

* Quantified current pain points (use your calculated metrics)
* Projected ROI for your recommended option
* Risk of not investing
* Three specific automation use cases ranked by ROI

---

## Deliverables

1. Calculations for Tasks 1-4 with shown work
1. Completed metrics dashboard table (Task 5)
1. Business case (Part 3)

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| MTTD/MTTA/MTTR calculations correct | 25 |
| FPR calculations correct with analyst-hour impact | 20 |
| SLA compliance calculations and improvement needed | 15 |
| Automation ROI calculation logical and well-supported | 25 |
| Business case is data-driven and actionable | 15 |
| **Total** | **100** |
