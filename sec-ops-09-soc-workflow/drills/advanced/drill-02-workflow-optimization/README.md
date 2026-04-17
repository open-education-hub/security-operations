# Drill 02 (Advanced): SOC Workflow Optimization

## Scenario

You are the SOC Manager at MedCorp (a healthcare organization, 3,000 employees, 8 hospitals).
Your team of 6 analysts is struggling with burnout and missed SLAs.
You have budget to hire 1 more analyst OR invest in SOAR tooling — but not both.

You have been given 6 months of performance data and must make a data-driven recommendation.

## Data Provided

### Current State

**Shift Schedule:**

* 3 shifts: Day (08-16), Evening (16-00), Night (00-08)
* Day: 2 analysts. Evening: 2 analysts. Night: 2 analysts.
* Weekend: 1 analyst per shift.

**Monthly Metrics (average over last 6 months):**

* Total alerts: 18,500/month
* TP rate: 8.2%
* P1 incidents: 4/month (avg MTTR: 1.8h — within SLA)
* P2 incidents: 52/month (avg MTTR: 4.6h — **SLA is 4h**)
* P3 incidents: 310/month (avg MTTR: 13.2h — SLA is 12h)
* SLA breach rate: 18% P2, 24% P3
* Analyst sick days: avg 2.1/analyst/month (above industry average of 1.2)
* Analyst turnover last year: 2 of 6 left (33%)

**Automation Status:**

* Current SOAR: None
* Average triage time: 7.8 min/alert
* Automated enrichment: None (all manual)
* Time for standard phishing triage: 15 min
* Time for account lockout triage: 12 min
* Time for AV detection triage: 10 min
* These three alert types: 71% of all alerts

**Estimated cost of hiring 1 analyst:** €60,000/year fully loaded

**Estimated cost of SOAR implementation:** €45,000 (first year, including integration)

**Estimated SOAR ROI:** Reduces analyst time on top-3 alert types by 75%

## Objectives

### Part A: Current State Analysis

1. Calculate current analyst utilization rate (assume 7-hour productive shift × 22 business days/month)
1. Are analysts overloaded? By how much?
1. What is the SLA breach cost in analyst-time? (How many hours were spent on breached cases beyond their SLA window?)

### Part B: Capacity Modeling

Model two scenarios:

1. **Hire 1 analyst:** How does utilization change? Do SLA breaches decrease?
1. **Implement SOAR:** With 75% reduction in top-3 alert type time, what is the new utilization rate?

### Part C: Recommendation

Write a recommendation document (1 page) including:

* Your recommendation (hire OR SOAR — justify why)
* Quantitative justification
* Risks of your recommendation
* Implementation timeline for the chosen option

### Part D: Workflow Redesign

Regardless of your choice, identify 3 workflow changes (not technology) that could reduce SLA breaches without any additional budget.
For each:

* Describe the change
* Why it would help
* How to measure success

## Hints

* Analyst utilization above 85% leads to quality degradation and burnout
* SOAR doesn't just save time — it standardizes quality, which reduces rework
* Night shift SLA breaches are often caused by reduced staffing, not by tool gaps
* The 33% annual turnover means the team is in a constant state of training
* Healthcare sector has strict regulatory requirements (HIPAA); SLA breaches are not just operational issues
