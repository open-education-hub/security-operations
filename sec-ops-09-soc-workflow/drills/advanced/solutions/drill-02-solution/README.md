# Solution: Drill 02 — SOC Workflow Optimization

## Part A: Current State Analysis

### Analyst Utilization Rate

```text
Productive hours per analyst per month:
  7 hours/shift × 22 business days = 154 hours/month

Team productive capacity (6 analysts):
  6 × 154 = 924 hours/month

Current workload:
  18,500 alerts × 7.8 min/alert = 144,300 min = 2,405 hours/month

But only L1 triage is included in 7.8 min. Let's account for case management too:
  P2+P3 case work: (52 × 4.6h) + (310 × 13.2h) = 239 + 4,092 = 4,331 hours/month

Wait — this can't be right. Let me recalculate:

Alert triage only: 18,500 × 7.8 min ÷ 60 = 2,405 hours of triage time
Team capacity: 924 hours
Triage utilization: 2,405 / 924 = 260% — clearly impossible

Resolution: Many alerts are queued/backlogged, causing the SLA breaches.
Analysts are triaging ~924 hours of work per month. ~1,481 hours of alerts
are either backlogged, auto-dismissed, or worked during overtime.
```

**Actual per-analyst triage load:** 924 ÷ 6 = 154 h/month capacity.
At 7.8 min/alert that's ~1,185 alerts/analyst/month = ~7,110 total.
But volume is 18,500 → **gap of ~11,390 alerts/month** not being properly triaged.

**This explains:** 89%+ false positive "close" rate is partially legitimate FPs AND partially analysts force-closing alerts they don't have time for.
This is a high-risk operational situation.

---

### SLA Breach Cost in Analyst Time

```text
P2 breaches: 18% of 52 cases = 9.4 cases/month
  Each breach = time after 4h SLA was spent = assume avg 2h overage
  Cost: 9.4 × 2h = 18.8 hours of "late" P2 work/month

P3 breaches: 24% of 310 cases = 74.4 cases/month
  Each breach = 1.2h overage (MTTR 13.2h vs 12h SLA)
  Cost: 74.4 × 1.2h = 89.3 hours of "late" P3 work/month
```

**SLA breach cost: ~108 analyst-hours/month** dedicated to work already past deadline.

---

## Part B: Capacity Modeling

### Scenario 1: Hire 1 Analyst

New team capacity: 7 × 154 = **1,078 hours/month**
New utilization: 2,405 / 1,078 = **223%** (still severely overloaded)

**Hiring does not solve the fundamental problem.** The team is triple-staffed below requirements.
Adding 1/6 more capacity barely moves the needle.

However: for **P2/P3 case work specifically**, 1 more analyst dedicated to case resolution could significantly reduce SLA breaches.

### Scenario 2: Implement SOAR

Top-3 alert types (71% of all alerts): 18,500 × 0.71 = 13,135 alerts/month
Current time: 13,135 × (weighted avg 12.4 min for top 3) = 2,714 hours on top-3 types
After SOAR (75% reduction): 2,714 × 0.25 = 679 hours

**New total triage time: 679 + (18,500 × 0.29 × 7.8 min / 60) = 679 + 696 = 1,375 hours/month**

**New utilization: 1,375 / 924 = 149%** — still overloaded but dramatically improved.

Remaining gap: 451 hours/month overloaded.
But now analysts aren't spending time on 99% FP alerts — they're spending it on real threats.

**Effect on SLA breaches:** With analysts freed from mechanical enrichment, they can focus on P2/P3 investigation.
Estimated SLA breach reduction: 40-60%.

---

## Part C: Recommendation

### Recommendation: Implement SOAR

**Quantitative Justification:**

* Hiring 1 analyst: reduces utilization from 260% to 223% (6% improvement) at €60k/year
* Implementing SOAR: reduces utilization from 260% to 149% (43% improvement) at €45k/year (cheaper AND more effective)
* SOAR also improves consistency (standardized enrichment), reduces human error, and scales as alert volume grows

**Risks of SOAR Implementation:**

1. 3-6 month implementation timeline — no immediate relief
1. Risk of incorrect playbook behavior (tested mitigation: staged rollout)
1. Staff resistance to workflow changes (mitigation: involve analysts in playbook design)
1. Initial SOAR maintenance overhead (mitigation: dedicated SOAR engineer or outsource)

**Timeline:**

* Month 1: SOAR deployment, integration setup, testing
* Month 2: Phishing enrichment playbook (highest volume alert type)
* Month 3: Account lockout + AV detection playbooks
* Month 4: Tuning and optimization
* Month 5: Advanced playbooks (ransomware P1 response)
* Month 6: Full operational review

---

## Part D: Workflow Changes (No Budget)

### Change 1: Implement a "Quick Triage" Queue for High-FP Rules

**Description:** Create a separate queue for alerts from rules with historical FP > 95%.
Analysts spend a maximum of 2 minutes on these before closing as likely FP.
They do not receive the same 12-minute allocation.

**Why it helps:** Frees analyst time for high-value alerts.
Forces explicit queue design rather than FIFO processing.

**Measure success:** Reduction in average handle time for known-noisy rules; no increase in missed TPs.

---

### Change 2: Implement Pre-Shift Brief and Watchlist Review

**Description:** Each shift starts with a 10-minute structured brief reviewing: open P1/P2 cases, watchlist hosts/users, known environment issues.
Currently shifts start cold.

**Why it helps:** Reduces "context re-acquisition" time when analysts switch tasks.
Prevents P2 cases from stalling because the incoming analyst didn't know what to do next.

**Measure success:** Reduction in P2 MTTR; reduction in cases that breach SLA during shift transitions.

---

### Change 3: Create a Weekly Top-10 FP Review Meeting

**Description:** 30-minute weekly meeting to review the 10 most common FP-generating events.
Analysts vote on which rules to disable or modify.
Changes go through a fast-track approval process.

**Why it helps:** Systematically reduces FP rate over time without technology investment.
Engages analysts in improving their own tooling.
Builds institutional knowledge.

**Measure success:** Monthly FP rate trend (should decrease ~5% per month if maintained consistently).
