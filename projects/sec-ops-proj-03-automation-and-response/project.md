# Project 03: SOC Automation and Response

**Covers:** Sessions 09–11

**Estimated time:** 6–8 hours

**Level:** Advanced

---

## Overview

This project challenges you to build a Security Orchestration, Automation, and Response (SOAR) pipeline that handles a realistic alert scenario end-to-end without analyst intervention.
You will then document a real or simulated incident using the VERIS (Vocabulary for Event Recording and Incident Sharing) schema, and finally produce an automated metric report that would be suitable for weekly SOC management review.

Sessions 09–11 covered SOAR concepts, playbook design, and VERIS.
This project is the synthesis: design, implement, and measure.

---

## Learning Outcomes

Upon completing this project, you will be able to:

* Design and implement an automated SOAR playbook for a high-volume alert type
* Enrich alerts automatically using threat intelligence and asset context
* Generate a structured VERIS incident record
* Produce a metrics report with trend analysis from raw SOC data

---

## Scenario

You are a senior SOC engineer at **Helios Maritime Logistics**.
The SOC handles approximately 200 alerts per day but only has 4 analysts. 73% of alerts are phishing-related and follow predictable patterns.
The CISO has approved a project to automate phishing response.

**Your three deliverables:**

1. **Automated Phishing Response Playbook** — A Python-based SOAR playbook that processes phishing alerts automatically
1. **VERIS Incident Record** — A VERIS-formatted JSON record for a sample incident from this scenario
1. **SOC Metrics Report** — Automated weekly metrics report with trend analysis

---

## Environment Setup

```console
cd demos/demo-04-soc-metrics
docker compose up -d
docker compose exec app bash
```

Available resources inside the container:

* `/data/alert_queue.json` — 50 simulated phishing alerts in SIEM format
* `/data/asset_inventory.json` — Asset inventory with host-to-owner mapping
* `/data/threat_intel.json` — IOC reputation data (mock threat intel API)
* `/data/soc_metrics_4weeks.json` — 4 weeks of SOC operational metrics
* `/data/veris_schema_excerpt.json` — VERIS 1.3.7 schema reference (key fields)
* Python libraries: `requests`, `jq`, `rich`, `pydantic`

---

## Part 1: Automated Phishing Response Playbook (Estimated: 3 hours)

### Context

When a phishing alert fires, the current manual process takes 45 minutes per alert:

1. Analyst reads the alert (5 min)
1. Analyst looks up the sender domain in VirusTotal (5 min)
1. Analyst looks up the recipient in the HR system (5 min)
1. Analyst checks if the email was opened or links clicked (10 min)
1. Analyst decides on response action (5 min)
1. Analyst sends notification email to recipient (5 min)
1. Analyst adds IOC to blocklist (5 min)
1. Analyst closes the ticket (5 min)

You will automate steps 2–7 entirely.

### Alert Format

Each alert in `/data/alert_queue.json` looks like:

```json
{
  "alert_id": "ALT-2024-8821",
  "timestamp": "2024-11-18T09:14:22Z",
  "rule_name": "PhishingEmailDetected",
  "severity": "high",
  "email": {
    "sender": "invoices@contoso-billing.ru",
    "sender_ip": "185.220.101.47",
    "recipient": "m.chen@helios-logistics.com",
    "subject": "URGENT: Overdue invoice INV-2024-9921",
    "attachment": "invoice_INV-2024-9921.pdf.exe",
    "attachment_md5": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "link_clicked": false,
    "attachment_opened": false
  }
}
```

### Playbook Requirements

Write a Python script (`/tmp/phishing_playbook.py`) that processes each alert in `/data/alert_queue.json` and performs these automated steps:

**Step 1 — Triage Scoring**

Calculate a `risk_score` (0–100) based on:

* Sender domain less than 30 days old: +30
* Sender IP in threat intel as malicious: +25
* Attachment has `.exe`, `.dll`, `.js`, `.vbs` extension: +20
* Attachment MD5 in threat intel: +20
* Attachment was opened by recipient: +40 (overrides other scores — automatic BLOCK)
* Link was clicked by recipient: +30
* Sender domain typosquatting known brand (contains "microsoft", "amazon", "google", "paypal", "helios"): +15

**Step 2 — Asset Enrichment**

Look up the recipient email in `/data/asset_inventory.json` to get:

* Employee name and department
* Manager's name and email
* Whether the employee has had security training in the past 12 months

**Step 3 — Threat Intel Enrichment**

Look up the sender IP and attachment MD5 in `/data/threat_intel.json`:

* Reputation score (0–100, higher = more malicious)
* Category (phishing, malware, c2, spam)
* Last seen date

**Step 4 — Decision Engine**

Based on `risk_score`:

* `>= 70`: **BLOCK** — Quarantine email, block sender domain in mail filter, add sender IP to blocklist, notify recipient and their manager
* `40–69`: **CONTAIN** — Quarantine email, notify recipient, flag for analyst review
* `< 40`: **MONITOR** — Log the alert, add to watchlist, no immediate action

**Step 5 — Action Execution (Simulated)**

Since you are in a sandbox, simulate actions by writing to action log files:

* `/tmp/blocklist.txt` — append blocked IPs/domains
* `/tmp/quarantine_log.json` — append quarantined alerts
* `/tmp/notifications.json` — append simulated email notifications
* `/tmp/analyst_queue.json` — append alerts requiring review

**Step 6 — Metrics Output**

After processing all 50 alerts, print a summary:

```text
=== Phishing Playbook Run Summary ===
Total alerts processed : 50
BLOCK actions          : X
CONTAIN actions        : Y
MONITOR actions        : Z
Mean processing time   : X.X ms per alert
Estimated analyst time saved : X hours
```

Assume each alert would have taken 45 minutes manually.

**Deliverable:** `/tmp/phishing_playbook.py` + `/tmp/blocklist.txt` + `/tmp/quarantine_log.json` + `/tmp/notifications.json` + summary output

---

## Part 2: VERIS Incident Record (Estimated: 1.5 hours)

### Context

The following incident occurred at Helios Maritime Logistics and must be documented in VERIS 1.3.7 format for sharing with the national CERT.

**Incident Brief:**

* Date: 2024-11-18
* Initial vector: Phishing email with malicious Word attachment
* Attacker obtained credentials of `m.chen` (finance department)
* Used credentials to log into the company's invoice portal
* Downloaded 3 months of supplier payment records (personal financial data — GDPR relevant)
* Incident detected 6 hours after breach began (MTTD = 6 hours)
* Data exfiltrated: ~50,000 supplier payment records (PII)
* Threat actor profile: financially motivated, Eastern European nexus

### Task

1. Review the VERIS schema at `/data/veris_schema_excerpt.json`
1. Create `/tmp/veris_incident.json` with a complete VERIS record covering:
   * `incident_id`, `summary`, `source_id`
   * `victim` section (industry, employee count, country)
   * `actor` section (motive, variety, country)
   * `action` section (Social + Hacking with sub-attributes)
   * `asset` section (what was affected)
   * `attribute` section (confidentiality, integrity, availability impact)
   * `discovery_method` and `discovery_notes`
   * `timeline` (compromise, exfiltration, discovery, containment dates/hours)

1. Write a brief (1 page) VERIS record justification at `/tmp/veris_justification.md` explaining:
   * Why you chose each `action.hacking.variety` value
   * Why you classified the data as `Personal` (explain GDPR relevance)
   * What ENUMERATIONS you used for `actor.external.motive`

**Hint:** VERIS uses controlled vocabularies (enumerations).
Key values you will need:

* `actor.external.variety`: `['Organized crime']`
* `action.social.variety`: `['Phishing']`
* `action.hacking.variety`: `['Use of stolen creds', 'Exploit vuln']`
* `attribute.confidentiality.data.variety`: `['Payment']`, `['Personal']`
* `discovery_method`: `['Log review']` or `['Security software (AV, IDS, FW, UTM, etc.)']`

**Deliverable:** `/tmp/veris_incident.json` + `/tmp/veris_justification.md`

---

## Part 3: SOC Metrics Report (Estimated: 1.5 hours)

### Context

Every Monday, the SOC Lead sends the CISO a weekly metrics report.
Currently this is produced manually by copying numbers from the SIEM into a Word document — it takes 2 hours every week.
You will automate this with a Python script that generates the report in Markdown format.

### Task

Write `/tmp/metrics_report_generator.py` that:

1. Loads `/data/soc_metrics_4weeks.json`
1. Calculates the following for the most recent week:
   * Total alerts generated
   * Alerts triaged (and triage coverage %)
   * False positive rate
   * MTTD, MTTR (averages)
   * Automation rate
   * SLA breach count
1. Calculates week-over-week trends (this week vs. last week) for each metric
1. Compares against industry benchmarks (hard-code these):
   * MTTD target: 4 hours
   * FP rate target: 40%
   * Automation rate target: 40%
   * Triage coverage target: 90%
1. Produces a Markdown report at `/tmp/soc_weekly_report.md` with:
   * Executive summary (3 bullet points: best performing metric, worst performing metric, key trend)
   * Metrics table with current value, previous week, trend indicator (↑/↓/→), and benchmark comparison (✓/✗)
   * Automated recommendations: for any metric below benchmark, generate a specific recommendation
   * Alert volume chart (ASCII bar chart of daily alert volume for the week)

**Example metrics table format:**

```text
| Metric | This Week | Last Week | Trend | vs Target |
|--------|-----------|-----------|-------|-----------|
| MTTD (hours) | 31.2 | 28.7 | ↑ WORSE | ✗ (target: 4h) |
| FP Rate (%) | 72.1 | 74.8 | ↓ BETTER | ✗ (target: 40%) |
```

**Deliverable:** `/tmp/metrics_report_generator.py` + `/tmp/soc_weekly_report.md`

---

## Deliverables Summary

| # | Deliverable | Description |
|---|------------|-------------|
| 1 | `/tmp/phishing_playbook.py` | Full SOAR playbook |
| 2 | `/tmp/blocklist.txt` | IPs/domains blocked by playbook |
| 3 | `/tmp/quarantine_log.json` | Quarantined alert records |
| 4 | `/tmp/notifications.json` | Simulated notifications |
| 5 | `/tmp/analyst_queue.json` | Alerts requiring human review |
| 6 | `/tmp/veris_incident.json` | VERIS record |
| 7 | `/tmp/veris_justification.md` | VERIS choices explained |
| 8 | `/tmp/metrics_report_generator.py` | Report generator script |
| 9 | `/tmp/soc_weekly_report.md` | Generated weekly report |

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Playbook: triage scoring logic correct; handles all 50 alerts | 15 |
| Playbook: enrichment steps implemented (asset + threat intel) | 15 |
| Playbook: decision engine produces correct BLOCK/CONTAIN/MONITOR | 15 |
| Playbook: action simulation (correct outputs in all 4 files) | 10 |
| Playbook: summary metrics are accurate | 5 |
| VERIS record: all required sections present and populated | 20 |
| VERIS justification: choices are correctly explained | 10 |
| Metrics report: all required metrics calculated with trends | 10 |

**Total: 100 points**

---

## Hints

* **Typosquatting detection:** Use simple substring checking: if any of `['microsoft', 'amazon', 'google', 'paypal', 'helios']` appears in the sender domain, flag it. (A real implementation would use edit distance, but substring is sufficient here.)
* **Domain age:** The `threat_intel.json` includes a `domain_age_days` field for known domains. For unknown domains, assume age is unknown and don't add the age score.
* **VERIS controlled vocabularies:** Always use exact string values from the VERIS enumeration lists. Common mistake: using `"Phishing email"` instead of `"Phishing"`. Refer to `/data/veris_schema_excerpt.json` for valid values.

* **ASCII bar chart:** Use `|` characters scaled to the maximum daily value. E.g., if max day = 120 alerts and bar width = 40 chars, each char = 3 alerts.

* **Week-over-week trend:** For metrics where a lower value is better (MTTD, FP rate, SLA breaches), "↑" means worse. Be explicit in your trend labels: `↑ WORSE` vs `↑ BETTER` depending on the metric direction.
* **Time saved calculation:** If each phishing alert takes 45 minutes manually and your playbook fully resolves it in < 1 second, the time saved is 45 minutes per BLOCK/CONTAIN action. MONITOR actions still require analyst review, so time saved is smaller.

---

## Extension Challenges (Optional, no additional marks)

* Add a second playbook for "impossible travel" alerts (user logs in from two geographically distant IPs within 1 hour)
* Add a `VERIS_validate()` function that checks your VERIS JSON against the schema for required fields
* Build a simple Flask dashboard that shows the playbook's action history
