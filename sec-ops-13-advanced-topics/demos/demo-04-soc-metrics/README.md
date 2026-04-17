# Demo 04: SOC Metrics and KPI Dashboard

## Overview

In this demo, we generate and visualise SOC operational metrics using Python and a simple web dashboard.
A data generator simulates 30 days of SOC activity (alerts, incidents, response times), and a dashboard displays MTTD, MTTR, false positive rates, alert volume trends, and detection coverage.
Students learn how to interpret these metrics and identify areas for improvement.

## Learning Objectives

* Calculate MTTD (Mean Time to Detect), MTTR (Mean Time to Respond), and MTTC (Mean Time to Contain)
* Interpret false positive rates and understand their operational impact
* Read an alert volume trend and identify anomalies
* Map metrics to SOC maturity levels
* Understand what good and poor metric values indicate

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-04-soc-metrics
docker compose up --build
```

Access the dashboard at: **http://localhost:5050**

## Files

* `docker-compose.yml` — Flask dashboard container
* `Dockerfile` — Python with Flask and data libraries
* `app/app.py` — Flask web application with metrics dashboard
* `app/data_generator.py` — generates 30 days of simulated SOC data
* `app/templates/dashboard.html` — HTML dashboard template

## Walk-through

### Step 1: View the Main Dashboard

Open **http://localhost:5050** in your browser.

The dashboard shows:

* **Today's summary**: total alerts, confirmed incidents, false positives
* **MTTD trend**: how quickly alerts are detected over 30 days
* **MTTR trend**: how quickly incidents are resolved
* **False positive rate**: percentage of alerts that were not real incidents
* **Alert volume by source**: SIEM, EDR, Network, Cloud

### Step 2: Interpret MTTD

**Current MTTD: 4.2 hours**

Industry benchmarks:
| Level | MTTD | Meaning |
|-------|------|---------|
| Poor  | > 24h | Attackers have >1 day undetected |
| Average | 8-24h | Reactive SOC |
| Good  | 1-8h  | Active monitoring |
| Excellent | < 1h | Near-real-time detection |

At 4.2 hours, this SOC is in the "Good" range.
The trend shows improvement from 12h (30 days ago).

### Step 3: Interpret MTTR

**Current MTTR: 6.8 hours**

For a SOC handling mostly medium-severity incidents, this is acceptable.
High-severity incidents should be resolved in under 4 hours.

Compare MTTD + MTTR to the **attacker dwell time** — if MTTD is 4h and MTTR 6h, the total exposure window is ~10 hours.

### Step 4: Analyse False Positive Rate

**Current FPR: 34%**

This means 34% of alerts are not real incidents.
High FPR causes:

* Analyst fatigue (alert fatigue)
* Missed real incidents (buried in noise)
* Wasted investigation time

Target FPR: **< 20%** for a well-tuned SIEM.

Actions to reduce FPR:

1. Tune detection rules (raise thresholds for noisy rules)
1. Add whitelisting for known legitimate behaviour
1. Prioritise rule quality over rule quantity

### Step 5: Read Alert Volume Trends

The chart shows alert volumes by source over 30 days.
Look for:

* **Spikes**: sudden increase may indicate active attack or misconfigured rule
* **Gradual increase**: growing environment or degrading rule tuning
* **Drops to zero**: data source failure (sensor went offline)

### Step 6: Calculate Detection Coverage

```text
Coverage = (Monitored ATT&CK techniques / Total relevant techniques) × 100
```

The demo shows 47 out of 103 ATT&CK techniques covered — **45.6% coverage**.

Improvement plan:

1. Identify the most critical uncovered techniques for your threat model
1. Implement detection rules or log sources for each
1. Validate with purple team exercises

## Cleanup

```console
docker compose down
```

## Key Takeaways

* MTTD and MTTR are the primary health indicators of a SOC
* False positive rate directly impacts analyst efficiency and alert fatigue
* Metrics should drive continuous improvement, not just reporting
* Detection coverage mapped to ATT&CK shows where gaps exist
* All metrics should be trended over time — a single snapshot is not meaningful
