# Drill 02 (Intermediate) — Automation Gap Analysis

## Scenario

**LogiTrans BV** is a Dutch logistics company with 2,000 employees and a 4-person SOC.
They currently use:

* **Splunk** as their SIEM (240,000 events/day, 650 alerts/day)
* **Jira** as their ticketing system
* **No SOAR platform**
* **CrowdStrike Falcon** EDR on all endpoints
* **Proofpoint** email security
* **Palo Alto** perimeter firewall
* **Microsoft Azure AD** for identity

Their SOC processes 650 alerts per day manually.
Each analyst handles roughly 160 alerts per day, working 09:00–18:00.
The SOC manager reports:

* MTTD: 3.2 hours (too high)
* MTTR: 18.6 hours (way too high)
* FP rate: 67% (very high)
* SLA compliance: 48% (failed more than passed)
* Analyst turnover: 2 analysts left in the last 6 months (burnout)

The company has allocated €80,000 for SOC tooling improvements in the next fiscal year.

---

## Your Tasks

### Task 1: Alert Volume Analysis (20 points)

Given the following breakdown of the 650 daily alerts, analyze the alert landscape:

| Alert Type | Count/Day | Current FP Rate | Avg Manual Time |
|------------|-----------|----------------|----------------|
| Failed VPN logins | 85 | 88% | 8 min |
| Antivirus alerts | 120 | 45% | 15 min |
| USB storage connected | 40 | 92% | 5 min |
| DNS to unusual domains | 95 | 71% | 12 min |
| Large file transfers | 30 | 60% | 20 min |
| User account anomalies | 55 | 52% | 18 min |
| Network scans detected | 110 | 79% | 8 min |
| Email with attachment | 75 | 55% | 14 min |
| Privilege escalation | 20 | 35% | 25 min |
| Lateral movement indicators | 20 | 30% | 35 min |

1. Calculate total analyst-hours per day consumed by each alert type
1. Calculate total analyst-hours consumed across all alerts
1. Identify which alert types consume the most analyst time
1. Identify which alert types have the worst ROI (high volume + high FP rate + low risk)

### Task 2: Automation Opportunity Scoring (25 points)

For each alert type, score it on three dimensions (1–5 each):

* **Volume**: 5 = very high volume (>80/day), 1 = very low (<10/day)
* **Automation Complexity**: 5 = easy to automate (clear rules), 1 = very hard (requires judgment)
* **Risk of Wrong Auto-Decision**: 5 = very low risk (FP close is safe), 1 = very high risk (auto-close could hide breach)

Calculate an **Automation Priority Score** = Volume × Complexity / Risk

Rank the alert types by automation priority and identify your top 5 candidates for automation.

### Task 3: Design Automation for Top 3 Alert Types (35 points)

For your top 3 automation candidates:

1. Write the automation logic in pseudocode (not full Python — focus on decision structure)
1. Estimate:
   * Automation coverage (% of alerts that can be handled automatically)
   * Time savings per day (analyst-hours)
   * Risk of automation errors (low/medium/high)
1. Define what monitoring you would put in place to catch automation errors

### Task 4: Budget and Tool Selection (20 points)

Given the €80,000 budget, recommend:

1. Which SOAR platform to purchase/deploy (justify: open source vs. commercial)
1. How to allocate the budget across: SOAR, integrations, training, and other improvements
1. Expected ROI: how many analyst-hours per day will be saved after 6 months?
1. What metric improvements do you expect after 1 year of automation?

For SOAR platform comparison, consider:

* **Shuffle** (open source, free)
* **Cortex XSOAR** (commercial, ~€30,000–50,000/year)
* **Splunk SOAR** (commercial, part of Splunk licensing)
* **TheHive + Cortex** (open source, free)

---

## Constraints

* LogiTrans BV is subject to Dutch GDPR implementation (AVG)
* They handle personal data of customers and employees
* Four analysts, 09:00–18:00 Mon–Fri
* Existing Splunk investment must be leveraged
* Target metrics after 1 year: FP rate < 40%, MTTR < 8 hours, SLA compliance > 80%

---

## Hints

* "Automation Complexity" scores should reflect whether the decision can be expressed as clear rules (e.g., "internal IP + known device + business hours = FP") vs. requires contextual judgment
* USB alerts at 92% FP are prime candidates for better rule tuning, not just automation
* Lateral movement alerts at 30% FP deserve human attention even with automation support
* Consider that Splunk SOAR integrates natively with Splunk — reducing integration effort
* Analyst burnout is a factor: even if automation doesn't save direct analyst time, reducing noise (FP alerts) has significant quality-of-life benefits that reduce turnover
