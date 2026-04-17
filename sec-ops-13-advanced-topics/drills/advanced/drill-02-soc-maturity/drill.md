# Drill: SOC Maturity Assessment and Improvement Roadmap

**Level:** Advanced

**Estimated time:** 90–120 minutes

**Session:** 13 — Advanced Topics in Security Operations

---

## Scenario

You have been brought in as a senior security consultant to assess the SOC maturity of **Vantage Energy Partners**, a mid-sized energy company.
Following a near-miss ransomware incident last quarter, the board has allocated budget for SOC improvements but wants data-driven justification for any proposed changes.

You will conduct a structured maturity assessment using a simplified SOC Capability Maturity Model (CMM), analyse current metrics data, identify the most critical capability gaps, and produce a prioritised improvement roadmap with a 12-month implementation plan.

This drill is primarily analytical and report-writing focused — it exercises your ability to synthesise data and produce executive-level recommendations.

---

## Learning Objectives

* Apply a structured maturity model to evaluate SOC capabilities
* Interpret SOC operational metrics and identify trends
* Prioritise improvement areas using risk-based reasoning
* Produce a professional maturity assessment report with a realistic roadmap

---

## Environment Setup

```console
cd demos/demo-04-soc-metrics
docker compose up -d
docker compose exec app bash
```

Datasets available:

* `/data/soc_metrics_12months.json` — 12 months of SOC operational metrics
* `/data/maturity_questionnaire.json` — self-assessment responses from SOC staff
* `/data/incident_history.json` — anonymised incident records from the past year

---

## SOC Capability Maturity Model

Use this simplified 5-level model across 8 capability domains:

| Level | Name | Description |
|-------|------|-------------|
| 0 | Non-existent | No formal process; ad-hoc responses only |
| 1 | Initial | Process exists but is undocumented and inconsistently applied |
| 2 | Developing | Process documented; partially implemented; some automation |
| 3 | Defined | Process fully documented; consistently implemented; measured |
| 4 | Managed | Process is measured, controlled, and continuously improved |
| 5 | Optimising | Process is proactively improved using threat intelligence |

**Capability Domains:**

1. **Log Collection & Normalisation** — Coverage, completeness, timeliness of log ingestion
1. **Alert Triage & Enrichment** — Speed and quality of alert investigation
1. **Incident Detection** — Proactive detection vs. reactive detection ratio
1. **Incident Response** — Documented playbooks, SLA adherence, escalation paths
1. **Threat Intelligence** — CTI feed integration, IOC management, threat hunting
1. **Vulnerability Management** — Coverage, remediation SLAs, patch cycle times
1. **SOC Tooling & Automation** — SIEM maturity, SOAR integration, playbook automation
1. **Metrics & Reporting** — KPI tracking, trend analysis, executive reporting

---

## Metrics Data Format

`/data/soc_metrics_12months.json`:

```json
[
  {
    "month": "2024-01",
    "alerts_generated": 4820,
    "alerts_triaged": 2100,
    "alerts_escalated": 187,
    "incidents_opened": 143,
    "incidents_closed": 138,
    "mean_time_to_detect_hours": 28.4,
    "mean_time_to_respond_hours": 6.2,
    "mean_time_to_contain_hours": 18.7,
    "false_positive_rate_pct": 76.2,
    "analyst_overtime_hours": 124,
    "critical_sla_breach_count": 12,
    "threat_hunts_initiated": 0,
    "playbooks_executed": 31,
    "automation_rate_pct": 14.2
  }
]
```

---

## Tasks

### Task 1 — Conduct the Maturity Assessment

Load `/data/maturity_questionnaire.json`.
This contains self-assessment answers from SOC staff across all 8 capability domains.
Each question has a `domain`, a `question`, the `response` (text), and an `evidence` list (what they can demonstrate).

For each domain:

1. Review the responses and evidence.
1. Assign a maturity level (0–5) based on the evidence.
1. Write a 2–3 sentence justification for your score.
1. Identify the single most critical gap within that domain.

Build a maturity scorecard: a dict of `{ domain: { score, justification, gap } }`.

**Hint:** Look for keywords in responses:

* Level 1: "we sometimes...", "it depends on who's on shift", "no formal..."
* Level 2: "we have a doc but...", "most of the time...", "partially automated"
* Level 3: "we always...", "it's in the runbook", "we measure..."
* Level 4: "we track trends...", "we review and adjust...", "SLAs are met 95%+"
* Level 5: "we feed CTI back into...", "we proactively...", "continuous improvement"

### Task 2 — Analyse the Metrics Data

Load `/data/soc_metrics_12months.json`.

1. Calculate the 12-month average for each metric.
1. Identify the **3 most concerning trends** — metrics that are worsening over time (compare Q1 vs Q4).
1. For each concerning trend, explain what SOC capability failure it indicates.
1. Calculate the analyst workload: total alerts triaged / total analysts (assume 6 full-time analysts).

Industry benchmarks to compare against:

* **Mean Time to Detect (MTTD):** Target ≤ 4 hours (>24 hours is critical)
* **Mean Time to Respond (MTTR):** Target ≤ 1 hour
* **False Positive Rate:** Target ≤ 40% (>70% indicates tuning problems)
* **Automation Rate:** Target ≥ 40%
* **Alert Triage Coverage:** Target ≥ 90% (alerts triaged / alerts generated)

### Task 3 — Analyse the Incident History

Load `/data/incident_history.json`.
Each record includes: incident ID, severity, detection method, days to contain, playbook used (boolean), root cause category.

1. What percentage of incidents were detected proactively (by the SOC) vs. reactively (reported by users or external parties)?
1. What are the top 3 root cause categories?
1. What is the average time to contain by severity level?
1. For incidents where no playbook was used, what was the average time to contain vs. when a playbook was used?
1. Identify any seasonal patterns (month-by-month incident counts).

### Task 4 — Prioritise Gaps and Build the Roadmap

Using your findings from Tasks 1–3:

1. Rank the 8 capability domains by priority for improvement (1 = most urgent). Use this scoring:
   * **Maturity gap** (5 minus current score) = base priority
   * **Metric impact** = +2 if metrics show direct evidence of degradation in this domain
   * **Incident correlation** = +1 if incidents reveal root causes traceable to this domain

1. For the top 3 priority domains, define one concrete improvement initiative each:
   * Initiative name
   * What specifically will change (process, tool, or people)
   * Expected metric improvement (e.g., "reduce MTTD by 40%")
   * Effort: Low / Medium / High
   * Estimated time to implement: weeks

1. Build a 12-month roadmap table:

| Quarter | Domain | Initiative | Milestone | Success Metric |
|---------|--------|------------|-----------|----------------|

### Task 5 — Write the Executive Assessment Report

Create `/tmp/vantage_soc_maturity_report.md` with:

1. **Executive Summary** (half page) — Overall maturity score (average), top 3 concerns, headline recommendation
1. **Maturity Scorecard** — Table of all 8 domains with current score, target score (12 months), and gap
1. **Key Metric Findings** — Highlight the 3 most concerning metrics with industry comparison
1. **Incident History Insights** — Key findings from incident data
1. **Prioritised Improvement Roadmap** — 12-month table from Task 4
1. **Resource Requirements** — Rough estimate: how many additional analysts, what tools, what training
1. **Risk if No Action Taken** — What happens if the current state continues? (Reference the near-miss incident)

---

## Deliverables

* `/tmp/maturity_scorecard.json` — JSON scorecard from Task 1
* `/tmp/vantage_soc_maturity_report.md` — Full executive report

---

## Hints

* A maturity score below 2 in any domain means that domain is a critical vulnerability, not just a gap. Treat it as a risk item, not just an improvement opportunity.
* The near-miss ransomware incident is key context: it will appear in the incident history as a "contained" critical incident. Note the detection method — if it was reactive (user reported), that's a strong indicator of detection maturity gaps.
* When building the roadmap, be realistic about organisational capacity. Trying to improve all 8 domains simultaneously will fail. Pick the top 3 and do them well.
* The SOC metrics show ~56% alert triage coverage (alerts triaged / alerts generated). This means ~44% of alerts are never reviewed — this is a critical data point for the executive report.

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Task 1: All 8 domains scored with justified scores and specific gaps | 20 |
| Task 2: Correct metric averages; 3 concerning trends with capability explanation | 20 |
| Task 3: Correct proactive/reactive ratio; top root causes; containment time analysis | 15 |
| Task 4: Priority ranking is logically justified; top-3 initiatives are concrete and measurable | 20 |
| Task 5: Executive report is professional, data-driven, and complete across all 7 sections | 25 |

**Total: 100 points**
