# Drill 02 (Intermediate): SOC Metrics Analysis

## Scenario

You are the SOC Team Lead at AcmeCorp.
The CISO has asked for a monthly performance review and wants to understand: (1) how the team is performing, (2) where the biggest problems are, and (3) what should be improved next month.

You have been given the raw metrics data for October 2024.

## Data: October 2024 Metrics

### Alert Volume and Outcomes

| Week | Total Alerts | True Positive | False Positive | Benign TP |
|------|-------------|--------------|----------------|-----------|
| W1 (Oct 1-7) | 5,421 | 287 | 4,892 | 242 |
| W2 (Oct 8-14) | 4,988 | 261 | 4,452 | 275 |
| W3 (Oct 15-21) | 6,102 | 318 | 5,441 | 343 |
| W4 (Oct 22-31) | 5,771 | 295 | 5,188 | 288 |
| **Total** | **22,282** | **1,161** | **19,973** | **1,148** |

### MTTD and MTTR by Severity

| Severity | SLA (MTTR) | Avg MTTD | Avg MTTR | Cases | SLA Breaches |
|----------|-----------|---------|---------|-------|-------------|
| P1 | 2 hours | 0.3h | 1.4h | 5 | 0 |
| P2 | 4 hours | 1.2h | 3.8h | 64 | 8 |
| P3 | 12 hours | 4.1h | 9.2h | 287 | 23 |
| P4 | 48 hours | N/A | 14.1h | 805 | 12 |

### Top 5 Alert-Generating Rules

| Rule | Alerts Oct | FP Rate | Analyst Handle Time |
|------|-----------|---------|---------------------|
| OUTBOUND_LARGE_TRANSFER | 4,228 | 97.3% | 4.2 min avg |
| AFTER_HOURS_LOGIN | 3,112 | 94.8% | 3.1 min avg |
| USB_DEVICE_INSERTED | 2,881 | 99.1% | 2.4 min avg |
| CLEARTEXT_CREDS_NETWORK | 1,892 | 76.4% | 8.7 min avg |
| PS_ENCODED_COMMAND | 1,447 | 68.2% | 11.3 min avg |

### Analyst Performance

| Analyst | Alerts Handled | Avg Handle Time | Cases Opened | SLA Breaches Caused |
|---------|---------------|----------------|--------------|---------------------|
| A. Garcia (L2) | 82 cases | 48 min | 82 | 2 |
| B. Kim (L1) | 4,210 alerts | 6.1 min | 41 | 15 |
| C. Osei (L1) | 3,944 alerts | 7.8 min | 37 | 6 |
| D. Patel (L1) | 4,012 alerts | 5.9 min | 39 | 4 |
| E. Santos (L1) | 3,891 alerts | 6.4 min | 38 | 18 |

## Objectives

### Part A: Calculate Key Metrics

1. Calculate the **overall false positive rate** for October
1. Calculate **SLA compliance rate** for each severity level
1. Calculate **average analyst workload** (alerts/day assuming 22 business days, 4 L1 analysts)

### Part B: Identify Problems

Analyze the data and identify at least **5 specific problems** or anomalies.
For each problem, describe:

* What the data shows
* Why it is a problem
* What information you would want to investigate further

### Part C: Prioritized Improvement Plan

Create a prioritized improvement plan for November with at least 3 specific, actionable items.
For each item:

* Describe the action
* Expected impact (what metric will improve?)
* Effort level (low/medium/high)
* Owner

### Part D: CISO Briefing

Write a 1-page (max) briefing for the CISO summarizing:

* Performance against SLA targets
* Top 2 issues needing executive attention
* One recommendation for a quick win next month

## Hints

* A rule with 99%+ FP rate may need to be reconsidered entirely (disabled or heavily refined)
* P2 SLA compliance of 8/64 breaches = 87.5% — is that acceptable?
* Analyst B. Kim handled 4,210 alerts. Is 15 SLA breaches from B. Kim a training issue or a workload issue?
* Consider the relationship between high-volume low-FP rules (PS_ENCODED) and analyst time
