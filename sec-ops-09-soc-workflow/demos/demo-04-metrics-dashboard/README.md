# Demo 04: SOC Metrics Dashboard with Grafana + Prometheus

## Overview

This demo builds a simple SOC metrics dashboard that tracks key performance indicators: MTTD, MTTR, alert volume by severity, and SLA compliance rates.
Students see how operational data can be turned into actionable management insights.

## Learning Objectives

* Understand key SOC metrics (MTTD, MTTR, SLA compliance)
* Read and interpret a SOC operations dashboard
* Understand the difference between operational and management dashboards
* Connect metrics to process improvement decisions

## Setup

```console
docker compose up -d
# Wait ~30 seconds for Grafana to start
```

Access Grafana at http://localhost:3000 (admin / admin).

## Pre-built Dashboard

The docker-compose file loads a pre-built dashboard (`dashboards/soc-metrics.json`) that displays:

### Panel 1: Alert Volume Trend (7 days)
Shows total alerts per day broken down by severity (P1/P2/P3/P4).
A spike on day 5 represents a simulated incident wave.

### Panel 2: MTTD Gauge
Current week mean time to detect.
Green if < 4 hours, amber if 4-24 hours, red if > 24 hours.

### Panel 3: MTTR by Severity
Bar chart showing average resolution time per severity level vs SLA target lines.

### Panel 4: True Positive Rate
Pie chart showing TP / FP / Benign TP breakdown for the current week.

### Panel 5: SLA Compliance Table
Table showing SLA compliance per severity class:

```text
Severity  | SLA Target | Cases | Breached | Compliance
──────────┼────────────┼───────┼──────────┼───────────
P1        | 30 min     |   3   |    0     | 100%
P2        | 2 hours    |  18   |    1     | 94.4%
P3        | 8 hours    |  47   |    3     | 93.6%
P4        | 24 hours   | 112   |    7     | 93.8%
```

### Panel 6: Top Alert Sources
Which detection rules are generating the most alerts (useful for identifying noisy rules to tune).

## Demo Walkthrough

### Part 1: Operational View (analyst perspective, ~5 min)

Walk through current open alerts, queue depth, and SLA countdown timers.
Explain how analysts use this to prioritize their queue at the start of a shift.

### Part 2: Management View (CISO perspective, ~5 min)

Show the trend lines.
Point out:

* MTTR improved from 3h → 1.8h over the past month (positive trend after adding SOAR automation)
* False positive rate is still 78% (needs rule tuning)
* One P2 SLA breach last week (root cause: analyst was in mandatory training, no backup)

### Part 3: Connecting Metrics to Decisions (~5 min)

Ask students: "Based on this dashboard, what would you prioritize this week?"

Expected discussion:

* Reduce FP rate for top 3 noisy rules
* Review coverage for P2 SLA breach
* Check if MTTD spike on day 5 had a root cause

## Discussion Questions

1. Why is MTTD harder to measure than MTTR?
1. What's the danger of optimizing for MTTR without considering quality of resolution?
1. What additional panels would you add to this dashboard?

## Teardown

```console
docker compose down -v
```
