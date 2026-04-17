# Demo 04: SOC Metrics and KPI Dashboard

**Estimated time:** 30 minutes

---

## Overview

Generate and visualise SOC operational metrics using Python and a web dashboard.
A data generator simulates 30 days of SOC activity — alerts, incidents, and response times.
You will interpret MTTD, MTTR, false positive rates, and alert volume trends, and understand what these metrics reveal about SOC health.

---

## Learning Objectives

* Calculate MTTD, MTTR, and MTTC from sample data
* Interpret false positive rates and their operational impact
* Read an alert volume trend and identify anomalies
* Map metrics to SOC maturity levels
* Understand what good and poor metric values indicate

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-04-soc-metrics
docker compose up --build
```

Access the dashboard at: **http://localhost:5050**

---

## Step 1: Review the Main Dashboard

Open **http://localhost:5050** in your browser.

The dashboard displays:

* **Today's summary:** total alerts, confirmed incidents, false positives
* **MTTD trend:** detection speed over 30 days
* **MTTR trend:** resolution speed over 30 days
* **False positive rate:** % of alerts that were not real incidents
* **Alert volume by source:** SIEM, EDR, Network, Cloud

---

## Step 2: Interpret MTTD (Mean Time to Detect)

**Current MTTD: 4.2 hours**

| Level | MTTD | Meaning |
|-------|------|---------|
| Poor | > 24 hours | Attacker has >1 day undetected |
| Average | 8–24 hours | Reactive SOC |
| Good | 1–8 hours | Active monitoring |
| Excellent | < 1 hour | Near-real-time detection |

At 4.2 hours this SOC is in the "Good" range.
The trend shows improvement from 12 hours (30 days ago) — evidence that process or tooling improvements are working.

**Discussion:** What would reduce MTTD below 1 hour?

* Better detection rules (catch earlier in the attack chain)
* Automated triage (AI pre-classifies alerts before analyst review)
* 24×7 coverage (no overnight blind spots)

---

## Step 3: Interpret MTTR (Mean Time to Respond)

**Current MTTR: 6.8 hours**

For a SOC handling mostly medium-severity incidents, 6.8 hours is acceptable.
However:

* **High-severity incidents** should be resolved in < 4 hours
* **Critical incidents** (active ransomware, data exfiltration) should target < 1 hour

The combined exposure window = MTTD + MTTR = ~11 hours.
This is the window during which an attacker operates undetected and uncontained.

---

## Step 4: Analyse the False Positive Rate

**Current FPR: 34%**

This means 34% of alerts are not real incidents.
High FPR causes:

* **Alert fatigue**: analysts become desensitised to alerts
* **Missed real incidents**: buried in noise
* **Wasted investigation time**: reduced capacity for real threats

**Target FPR:** < 20% for a well-tuned SIEM

**Actions to reduce FPR:**

1. Tune noisy detection rules (raise thresholds, add exceptions for known-good behavior)
1. Add whitelisting for known-legitimate applications and IP ranges
1. Prioritise rule quality over quantity (10 well-tuned rules > 100 noisy rules)

---

## Step 5: Read Alert Volume Trends

The chart shows alert volumes by source over 30 days.
Patterns to look for:

* **Spikes:** Sudden increase may indicate an active attack, or a misconfigured rule generating noise
* **Gradual increase:** Growing environment (new endpoints/services) or degrading rule tuning
* **Drop to zero:** Data source failure — a sensor went offline and you are now blind

**Exercise:** In the demo chart, identify any anomalous days and hypothesize what caused them.

---

## Step 6: Calculate Detection Coverage

```text
Coverage = (Covered ATT&CK techniques / Total relevant techniques) × 100
```

The demo shows **47 of 103 ATT&CK techniques covered = 45.6%**.

**Improvement approach:**

1. Identify the highest-frequency uncovered techniques in your industry (use DBIR or ATT&CK Navigator)
1. Implement detection rules or log sources for each
1. Validate with purple team exercises
1. Re-measure coverage after each improvement

---

## Discussion Points

1. **MTTD and MTTR are the primary health indicators**: All other metrics (alerts, incidents, coverage) exist to improve these two numbers.

1. **Metrics drive improvement, not just reporting**: If your MTTD is not trending down, investigate why — tool coverage? staffing? tuning?

1. **Trend is more important than snapshot**: A single data point tells you where you are. The trend tells you whether you are improving.

1. **Coverage gaps define your risk**: The 54.4% of ATT&CK techniques without detection coverage represent your blind spots.

---

## Clean Up

```console
docker compose down
```
