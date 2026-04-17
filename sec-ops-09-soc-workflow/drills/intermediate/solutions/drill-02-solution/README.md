# Solution: Drill 02 — SOC Metrics Analysis

## Part A: Key Metric Calculations

### Overall False Positive Rate

```text
Total alerts: 22,282
False positives: 19,973
FP rate: 19,973 / 22,282 = 89.6%
```

### SLA Compliance Rate by Severity

```text
P1: 5 cases, 0 breaches → 100% compliance
P2: 64 cases, 8 breaches → (64-8)/64 = 87.5% compliance
P3: 287 cases, 23 breaches → (287-23)/287 = 92.0% compliance
P4: 805 cases, 12 breaches → (805-12)/805 = 98.5% compliance
```

### Average Analyst Workload

```text
L1 analysts: 4
Business days in October: 22 (approx)
Total L1 alerts: 4,210 + 3,944 + 4,012 + 3,891 = 16,057
Per analyst per day: 16,057 / (4 × 22) = ~182 alerts/analyst/day
```

---

## Part B: Problems Identified

### Problem 1: USB_DEVICE_INSERTED rule has 99.1% FP rate

**Data:** 2,881 alerts, only 26 are true positives.
Analysts spending 2.4 min average × 2,881 = **115 analyst-hours** processing this rule in October.

**Why it's a problem:** This rule is consuming enormous analyst time with almost no value. 99.1% FP means for every 100 alerts, only 1 matters.
Analysts may be developing alert fatigue specifically from this rule.

**Investigate further:** What does a TP USB insertion look like vs an FP?
Can we add context filters (e.g., only alert for USB insertions on systems in sensitive zones)?

---

### Problem 2: Analyst E. Santos has disproportionate SLA breaches

**Data:** E.
Santos handled 3,891 alerts (similar to peers) but caused 18 SLA breaches — vs 4 for D.
Patel with a similar workload.

**Why it's a problem:** Either E.
Santos has a performance issue, a training gap, or is regularly assigned to harder cases.
This disparity warrants investigation.

**Investigate further:** What case types did E.
Santos handle?
Were the SLA breaches on P2/P3 cases?
Was E.
Santos less experienced or working a night shift with less support?

---

### Problem 3: P2 SLA compliance at 87.5%

**Data:** 8 out of 64 P2 cases breached SLA.

**Why it's a problem:** P2 cases include significant confirmed incidents (C2 activity, malware, etc.).
An 87.5% compliance rate means ~1 in 8 serious incidents exceeded the 4-hour response window — significant risk.

**Investigate further:** Were the breaches clustered around specific days/shifts?
Were they all from the same analyst?
Did they coincide with high alert volume days?

---

### Problem 4: OUTBOUND_LARGE_TRANSFER is the highest-volume rule at 97.3% FP

**Data:** 4,228 alerts, 97.3% FP.
Average handle time 4.2 min × 4,228 = **296 analyst-hours** wasted in October.

**Why it's a problem:** This single rule consumed roughly 296 analyst-hours producing only ~114 true positives.
That's 2.6 hours per useful alert — extremely inefficient.

**Investigate further:** What threshold is triggering this?
Can we add context (known backup jobs, approved data transfer tools, specific source IPs whitelisted)?

---

### Problem 5: MTTD for P2 cases is 1.2 hours

**Data:** Average detection time for P2 is 1.2 hours.

**Why it's a problem:** For confirmed incidents (C2 beacons, lateral movement), 1.2 hours of undetected activity before even acknowledging the alert is significant dwell time.

**Investigate further:** What causes the 1.2h detection delay?
Is SIEM correlation running on delayed log ingestion?
Are some P2 rules using daily batch correlation instead of real-time?

---

## Part C: Prioritized Improvement Plan for November

### Item 1: Suppress or Refactor USB_DEVICE_INSERTED Rule

* **Action:** Analyze the 26 TPs. What distinguishes them from the 2,855 FPs? Add context conditions: only alert if device is inserted outside business hours OR on a machine in a high-security zone. Alternatively, disable the rule and re-evaluate after redesign.
* **Expected impact:** Reduce alert volume by ~2,881/month; free up ~115 analyst-hours; reduce alert fatigue.
* **Effort:** Medium (requires rule analysis and testing)
* **Owner:** SOC Team Lead + Detection Engineering

### Item 2: Investigate and Address E. Santos SLA Breaches

* **Action:** Review all 18 SLA breaches from E. Santos. Determine root cause: skill gap, workload imbalance, or shift coverage issue. Provide targeted coaching or redistribute caseload.
* **Expected impact:** Reduce L1 SLA breaches by up to 10/month.
* **Effort:** Low (management review + 1:1 coaching)
* **Owner:** SOC Manager

### Item 3: Add SOAR Enrichment for Top 3 Noisy Rules

* **Action:** Implement automatic enrichment playbooks for OUTBOUND_LARGE_TRANSFER, AFTER_HOURS_LOGIN, and USB_DEVICE_INSERTED. Each playbook should auto-resolve obvious FPs (known backup jobs, known after-hours workers) and only surface ambiguous cases to analysts.
* **Expected impact:** Reduce analyst handle time for these rules by 60-80%; expected ~400 analyst-hours saved/month.
* **Effort:** High (requires SOAR playbook development and testing)
* **Owner:** SOC Team Lead + SOAR Engineer

---

## Part D: CISO Briefing

```text
TO: CISO
FROM: SOC Team Lead
RE: Security Operations Performance — October 2024
DATE: November 1, 2024

SUMMARY

October alert volume: 22,282 total alerts, 5.2% true positive rate, 89.6% false
positive rate.

SLA PERFORMANCE
  P1 (Critical): 100% — 0 breaches
  P2 (High):     87.5% — 8 breaches out of 64 cases (TARGET: 95%)
  P3 (Medium):   92.0% — 23 breaches (TARGET: 95%)
  P4 (Low):      98.5% — 12 breaches (TARGET: 95%)

TOP ISSUES REQUIRING ATTENTION

1. P2 SLA compliance is below target (87.5% vs 95% target). 8 high-severity

   incidents exceeded the 4-hour response window. Root cause analysis underway.
   We estimate 3 of the 8 breaches were caused by a single analyst workload issue
   being addressed in November.

2. Alert fatigue risk is high. Two detection rules alone generated 7,109 alerts
   with combined FP rates above 97%. This is consuming ~411 analyst-hours/month
   and increasing the risk that analysts miss real alerts buried in noise.
   We are implementing SOAR automation to address this in November.

NOVEMBER QUICK WIN
Suppressing / refactoring the USB_DEVICE_INSERTED rule alone is estimated to
save 115 analyst-hours and eliminate ~13% of total alert volume.
This change is low-risk and can be implemented within 1 week.
```
