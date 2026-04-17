# Solution: SOC Maturity Assessment and Improvement Roadmap

**Drill:** Advanced Drill 02 — SOC Maturity

**Session:** 13 — Advanced Topics in Security Operations

---

## Overview

This is a primarily analytical drill.
The solution provides model answers for each task, including sample code for data processing, example maturity scores with justifications, and a complete executive report template.
Actual scores and findings will vary based on the dataset in the container.

---

## Task 1 — Maturity Assessment Model Answers

The questionnaire responses are designed to produce these scores:

```python
#!/usr/bin/env python3
import json

with open("/data/maturity_questionnaire.json") as f:
    questionnaire = json.load(f)

# Keywords indicating each maturity level
LEVEL_INDICATORS = {
    5: ["proactively", "continuous improvement", "feeds back", "optimis"],
    4: ["tracked", "we measure", "trend", "SLA met", "reviewed quarterly", "adjusted based on"],
    3: ["always", "runbook", "documented", "consistently", "we follow"],
    2: ["mostly", "partially", "we have a doc", "sometimes automated", "some coverage"],
    1: ["ad-hoc", "sometimes", "depends on who", "no formal", "informally"],
    0: ["no process", "we don't", "not in place", "never"]
}

def score_response(response_text):
    text_lower = response_text.lower()
    for level in range(5, -1, -1):
        if any(kw in text_lower for kw in LEVEL_INDICATORS[level]):
            return level
    return 1  # default to 1 if no clear indicators

scorecard = {}
for domain_data in questionnaire:
    domain = domain_data["domain"]
    responses = domain_data["responses"]

    scores = [score_response(r["response"]) for r in responses]
    avg_score = round(sum(scores) / len(scores), 1)

    # The lowest-scoring response indicates the critical gap
    lowest = min(responses, key=lambda r: score_response(r["response"]))

    scorecard[domain] = {
        "score": avg_score,
        "justification": f"Average of {len(scores)} responses. Responses ranged from {min(scores)} to {max(scores)}.",
        "gap": lowest["question"]
    }

with open("/tmp/maturity_scorecard.json", "w") as f:
    json.dump(scorecard, f, indent=2)

print("Domain Maturity Scorecard:")
print(f"{'Domain':45s} {'Score':6s} {'Gap'}")
print("-" * 100)
for domain, data in scorecard.items():
    print(f"  {domain:43s} {data['score']:6.1f}  {data['gap'][:60]}")
```

**Expected scorecard (model answers — adjust based on actual data):**

| Domain | Score | Key Gap |
|--------|-------|---------|
| Log Collection & Normalisation | 2.5 | Cloud workload coverage < 30% |
| Alert Triage & Enrichment | 1.5 | No automated enrichment; manual lookup for every alert |
| Incident Detection | 1.5 | 87% reactive detection; no proactive hunting programme |
| Incident Response | 2.0 | Playbooks exist for only 4 of 23 incident types |
| Threat Intelligence | 1.0 | Single commercial feed; no internal IOC management |
| Vulnerability Management | 2.5 | No SLA for critical patch application |
| SOC Tooling & Automation | 2.0 | SIEM has no SOAR integration; 14% automation rate |
| Metrics & Reporting | 2.0 | Metrics collected but not trended; no exec dashboard |

**Overall maturity: 1.9 / 5 — Early Developing**

---

## Task 2 — Metrics Analysis

```python
import json
from statistics import mean

with open("/data/soc_metrics_12months.json") as f:
    metrics = json.load(f)

# Calculate 12-month averages
fields = [
    "alerts_generated", "alerts_triaged", "alerts_escalated",
    "mean_time_to_detect_hours", "mean_time_to_respond_hours",
    "mean_time_to_contain_hours", "false_positive_rate_pct",
    "automation_rate_pct", "analyst_overtime_hours", "critical_sla_breach_count"
]

print("12-Month Averages:")
for field in fields:
    values = [m[field] for m in metrics if field in m]
    avg = mean(values)
    print(f"  {field:40s} {avg:8.2f}")

# Triage coverage
triage_coverage = [m["alerts_triaged"]/m["alerts_generated"]*100 for m in metrics]
print(f"\n  {'alert_triage_coverage_pct':40s} {mean(triage_coverage):8.2f}")

# Q1 vs Q4 comparison
q1 = metrics[:3]
q4 = metrics[9:]

print("\nQ1 vs Q4 comparison (concerning trends):")
for field in ["mean_time_to_detect_hours", "false_positive_rate_pct", "critical_sla_breach_count", "automation_rate_pct"]:
    q1_avg = mean(m[field] for m in q1)
    q4_avg = mean(m[field] for m in q4)
    delta = q4_avg - q1_avg
    direction = "↑ WORSE" if (delta > 0 and field != "automation_rate_pct") else ("↓ WORSE" if field == "automation_rate_pct" and delta < 0 else "→ stable")
    print(f"  {field:40s} Q1={q1_avg:6.1f}  Q4={q4_avg:6.1f}  Δ={delta:+6.1f}  {direction}")
```

**Expected findings:**

| Metric | 12-month avg | Industry target | Status |
|--------|-------------|-----------------|--------|
| MTTD (hours) | 29.1 | ≤ 4 hours | CRITICAL |
| False Positive Rate | 74.8% | ≤ 40% | CRITICAL |
| Alert Triage Coverage | 56% | ≥ 90% | CRITICAL |
| Automation Rate | 14% | ≥ 40% | POOR |
| MTTR (hours) | 7.1 | ≤ 1 hour | POOR |

**3 Most Concerning Trends (Q1 → Q4):**

1. MTTD increasing from 28h to 34h → Detection capability degrading (analyst overload, poor tuning)
1. False positive rate increasing from 74% to 79% → Detection rules drifting; tuning backlog growing
1. SLA breach count increasing from 12/month to 19/month → Response capacity insufficient for volume

---

## Task 3 — Incident History Analysis

```python
with open("/data/incident_history.json") as f:
    incidents = json.load(f)

total = len(incidents)

# Proactive vs reactive
proactive = [i for i in incidents if i.get("detection_method") in ("SOC_alert", "threat_hunt", "automated_detection")]
reactive  = [i for i in incidents if i.get("detection_method") in ("user_reported", "external_notification", "by_chance")]
print(f"Proactive detection: {len(proactive)/total*100:.1f}%")
print(f"Reactive detection:  {len(reactive)/total*100:.1f}%")

# Root causes
from collections import Counter
root_causes = Counter(i.get("root_cause_category") for i in incidents)
print("\nTop root cause categories:")
for cause, count in root_causes.most_common(5):
    print(f"  {cause:40s} {count}")

# Containment time by severity
from statistics import mean as avg
by_severity = {}
for inc in incidents:
    sev = inc.get("severity","unknown")
    days = inc.get("days_to_contain", 0)
    by_severity.setdefault(sev, []).append(days)

print("\nAverage days to contain by severity:")
for sev, times in sorted(by_severity.items()):
    print(f"  {sev:15s} {avg(times):.1f} days")

# Playbook vs no-playbook
with_pb   = [i for i in incidents if i.get("playbook_used")]
without_pb = [i for i in incidents if not i.get("playbook_used")]
if with_pb and without_pb:
    print(f"\nWith playbook:    {avg(i['days_to_contain'] for i in with_pb):.1f} days avg")
    print(f"Without playbook: {avg(i['days_to_contain'] for i in without_pb):.1f} days avg")
```

**Expected findings:**

* 87% of incidents were reactive (user-reported or discovered by chance)
* Top root causes: Phishing/credential theft (42%), Misconfiguration (28%), Unpatched vulnerability (19%)
* Average containment: Critical=4.2 days, High=2.1 days, Medium=0.8 days
* With playbook: 1.1 days avg; Without playbook: 3.4 days avg (3x faster with playbook)
* The near-miss ransomware incident was user-reported (reactive) with 6 days to contain

---

## Task 4 — Prioritised Roadmap

**Priority scoring:**

| Domain | Maturity Score | Gap (5-score) | Metric Impact | Incident Correlation | Total Priority Score |
|--------|---------------|---------------|---------------|---------------------|---------------------|
| Alert Triage & Enrichment | 1.5 | 3.5 | +2 (FP rate, triage coverage) | +1 | **6.5** |
| Incident Detection | 1.5 | 3.5 | +2 (MTTD) | +1 (87% reactive) | **6.5** |
| SOC Tooling & Automation | 2.0 | 3.0 | +2 (14% automation) | +1 | **6.0** |
| Incident Response | 2.0 | 3.0 | +2 (SLA breaches) | +1 (playbook gap) | **6.0** |
| Threat Intelligence | 1.0 | 4.0 | 0 | 0 | **4.0** |
| Log Collection | 2.5 | 2.5 | 0 | 0 | **2.5** |
| Vulnerability Management | 2.5 | 2.5 | 0 | +1 | **3.5** |
| Metrics & Reporting | 2.0 | 3.0 | 0 | 0 | **3.0** |

**Top 3 Initiatives:**

1. **Alert Triage Automation** (Alert Triage & Enrichment)
   * Deploy automated enrichment via SOAR: IP reputation, domain age, user risk score
   * Expected outcome: Reduce analyst alert handling time by 60%; FP rate from 75% to 45%

   * Effort: Medium | Timeline: 8 weeks

1. **Detection Rule Tuning Programme** (Incident Detection)
   * Weekly rule review cadence; retire or tune rules with FP rate > 80%; add detection coverage for top 3 root cause categories
   * Expected outcome: MTTD from 29h to 8h; triage coverage from 56% to 85%

   * Effort: Low (process change only) | Timeline: 4 weeks to launch, 12 weeks to full effect

1. **Playbook Expansion** (Incident Response)
   * Write and validate playbooks for top 10 incident types (covering ~90% of volume)
   * Expected outcome: Containment time reduction of 65% for incidents covered; SLA breach rate halved

   * Effort: Medium | Timeline: 12 weeks

---

## Task 5 — Executive Report Template

```markdown
# SOC Maturity Assessment Report — Vantage Energy Partners

**Date:** 2024-11-15
**Prepared by:** Senior Security Consultant
**Classification:** CONFIDENTIAL — Board and CISO Distribution Only

---

## 1. Executive Summary

Vantage Energy Partners' SOC currently operates at an **Early Developing** maturity level
(overall score: **1.9 out of 5**). The assessment reveals three critical deficiencies that
directly contributed to the near-miss ransomware incident in Q3 and continue to expose the
organisation to material risk.

**Top 3 Concerns:**
- Only 13% of incidents are detected proactively — the SOC is reactive by design
- Mean Time to Detect is 29 hours — 7× the industry target of 4 hours
- 44% of all security alerts are never reviewed due to analyst overload and poor automation

**Headline Recommendation:** Prioritise alert triage automation and detection rule tuning
before adding headcount. The current analyst team is spending 75% of their time on false
positives — fixing this will double effective capacity without additional hiring costs.

---

## 2. Maturity Scorecard

| Domain | Current Score | 12-Month Target | Gap |
|--------|--------------|-----------------|-----|
| Log Collection & Normalisation | 2.5 | 3.5 | +1.0 |
| Alert Triage & Enrichment | 1.5 | 3.0 | +1.5 |
| Incident Detection | 1.5 | 3.0 | +1.5 |
| Incident Response | 2.0 | 3.5 | +1.5 |
| Threat Intelligence | 1.0 | 2.5 | +1.5 |
| Vulnerability Management | 2.5 | 3.5 | +1.0 |
| SOC Tooling & Automation | 2.0 | 3.5 | +1.5 |
| Metrics & Reporting | 2.0 | 3.0 | +1.0 |
| **OVERALL** | **1.9** | **3.2** | **+1.3** |

---

## 3. Key Metric Findings

[3 concerning metrics with industry comparison — see Task 2 output]

---

## 4. Incident History Insights

[Proactive/reactive ratio; playbook impact — see Task 3 output]

---

## 5. Prioritised Improvement Roadmap

| Quarter | Domain | Initiative | Milestone | Success Metric |
|---------|--------|------------|-----------|----------------|
| Q1 2025 | Detection | Rule Tuning Programme | 50% of rules reviewed | MTTD ≤ 12h |
| Q1 2025 | IR | Playbook Gap Analysis | Top 10 playbooks drafted | Playbook coverage 70% |
| Q2 2025 | Triage | SOAR Enrichment Deployment | Automated enrichment live | FP rate ≤ 50% |
| Q2 2025 | IR | Playbook Testing & Activation | Tabletops complete | SLA breach count ≤ 8/month |
| Q3 2025 | Detection | Threat Hunt Programme | 2 hunts/month cadence | Proactive detection 30% |
| Q3 2025 | CTI | IOC Management Platform | Feed integration complete | Enrichment coverage 80% |
| Q4 2025 | Tooling | SIEM Optimisation | Dashboards deployed | Triage coverage ≥ 85% |
| Q4 2025 | Metrics | Executive KPI Dashboard | Board-ready reporting | Monthly exec report |

---

## 6. Resource Requirements

- **People:** No immediate headcount increase recommended; 0.5 FTE redirected to rule tuning
- **Tools:** SOAR platform licence (~$80K/year); IOC management platform (~$40K/year)
- **Training:** SANS SEC555 (SIEM with tactical analytics) for 2 senior analysts; detection engineering workshop
- **Total estimated investment:** ~$180K year 1, ~$120K year 2

---

## 7. Risk if No Action Taken

The near-miss ransomware incident in Q3 was contained by a user who reported unusual file
encryption on their workstation — not by the SOC. With MTTD averaging 29 hours, a fast-moving
ransomware operator (typical propagation < 4 hours) would have encrypted critical operational
systems before the SOC was even aware of the breach.

If current trends continue:
- MTTD will reach 40+ hours by Q4 2025 (based on Q1→Q4 trajectory)
- SLA breach rate will double, potentially triggering regulatory findings under NIS2
- Analyst burnout risk is high — overtime hours increased 34% in 12 months
- Probability of a successfully completed ransomware attack within 18 months: HIGH
```

---

## Scoring Guide

| Criterion | Full marks if... |
|-----------|-----------------|
| Task 1 (20 pts) | All 8 domains scored with justified rationale; each has a specific gap |
| Task 2 (20 pts) | Correct averages; 3 trends identified with capability linkage |
| Task 3 (15 pts) | Correct proactive/reactive ratio; top 3 root causes; containment time comparison |
| Task 4 (20 pts) | Priority scores logically derived; top-3 initiatives include specific metrics and timelines |
| Task 5 (25 pts) | Report is professional; all 7 sections present; data-driven; actionable |
