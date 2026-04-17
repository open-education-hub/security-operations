# Project 02: Incident Analysis — From Detection to Root Cause

## Covers Sessions: 06–08 (Incident Analysis, Cyber Threat Hunting, Event Normalization)

## Estimated Time: 6–8 hours

---

## Overview

In this project, you will analyse a realistic multi-stage cyberattack that has already occurred at a fictional European logistics company.
You are given raw log data from multiple sources and must reconstruct the full attack timeline, determine the root cause, identify what data was compromised, and produce a comprehensive incident analysis report.

This project integrates concepts from Sessions 06–08:

* Incident analysis methodology: Diamond Model, Kill Chain (Session 06)
* Cyber threat hunting with hypotheses and ATT&CK mapping (Session 07)
* Event normalization, ECS/CEF, log correlation across sources (Session 08)

---

## Learning Objectives

By completing this project you will be able to:

1. Reconstruct an attack timeline from raw, multi-source log data
1. Map attacker actions to MITRE ATT&CK techniques
1. Apply the Diamond Model to characterise the threat actor
1. Perform threat hunting using structured hypotheses
1. Normalise disparate log formats into a common schema
1. Produce a structured post-incident analysis report

---

## Scenario

**Organisation:** TransLog SA, a logistics company based in Bucharest operating truck fleet management software and a customer portal.

**What you know (briefing):**

* On 2024-03-15 at approximately 16:00, an alert fired indicating unusual database activity
* IT isolated the affected database server
* Later investigation found an attacker had been in the environment for 3 days
* Your job: reconstruct the full 3-day attack using the provided logs

**Available log sources (all in `/data/logs/`):**

* `web_access.log` — Apache access log from the customer portal (JSON)
* `windows_security.evtx.json` — Windows Security Event Log exports from 3 servers
* `dns_queries.log` — DNS query log from the internal DNS server
* `firewall.log` — Next-gen firewall NetFlow records
* `db_audit.log` — Database audit log (MySQL slow query + general query log)
* `email_gateway.log` — Email gateway log (one day, around the time of initial access)

---

## Environment Setup

```console
cd projects/sec-ops-proj-02-incident-analysis
docker compose up --build -d
```

The environment provides:

* A Jupyter notebook server at http://localhost:8888 (password: `secops`) for log analysis
* Pre-loaded log files in `/data/logs/`
* A Kibana instance at http://localhost:5601 with all logs indexed
* Python 3.11 with pandas, matplotlib, and elasticsearch libraries

---

## Tasks

### Task 1: Timeline Reconstruction (30–40 minutes)

Using the provided logs, build a chronological attack timeline.
Identify each significant attacker action with timestamp, log source, and description.

Expected timeline length: 15–25 events spanning 3 days.

Start with these anchor questions:

1. What was the initial access vector? (Hint: check `email_gateway.log` and `web_access.log` for Day 1)
1. When did the attacker first authenticate to an internal system?
1. When did lateral movement begin?
1. What was the attacker's objective? (What did they access or exfiltrate?)
1. How long was the attacker in the environment before detection?

**Format your timeline as:**

```text
TIMESTAMP           | SOURCE      | EVENT DESCRIPTION                         | ATT&CK ID
--------------------+-------------+-------------------------------------------+-----------
2024-03-12 09:23:41 | email-gw    | Phishing email received by j.popescu@...  | T1566.001
...
```

**Deliverable**: `timeline.md`

---

### Task 2: ATT&CK Technique Mapping

From your timeline, identify all MITRE ATT&CK techniques used.
For each:

1. Technique ID and name
1. Evidence from logs (specific log entry or query)
1. Confidence level (High / Medium / Low) and justification

Minimum expected: 8 techniques across at least 4 different ATT&CK Tactics.

**Deliverable**: `attack_mapping.md`

---

### Task 3: Diamond Model Analysis

Apply the Diamond Model to characterise this incident:

```text
DIAMOND MODEL ANALYSIS
======================
Adversary:
  - What do we know about the threat actor? (motivation, sophistication, TTPs)
  - Nation-state, criminal, hacktivist, insider? Justify.

Infrastructure:
  - What IP addresses, domains, tools did the attacker use?
  - Is the infrastructure commodity (rented) or custom?

Capability:
  - What was the attacker's technical capability level?
  - What tools/malware were used (if any)?
  - Custom tools or commodity?

Victim:
  - What is the target profile?
  - Why was TransLog SA targeted? (opportunity, data value, sector?)
  - What assets were ultimately compromised?

Meta-features:
  - Timestamp (when was the activity)
  - Phase (which Kill Chain phase most activity falls in)
  - Result (success / failure)
  - Direction (internal → internet, external → internal, etc.)
```

**Deliverable**: `diamond_model.md`

---

### Task 4: Log Normalization Exercise

The logs you received are in different formats.
To correlate them, you need to normalise them to a common schema.

Using the provided Python notebook or script:

1. Parse `web_access.log` (Apache JSON) and `firewall.log` (custom CSV format)
1. Normalise both to Elastic Common Schema (ECS) fields:
   * `@timestamp`, `source.ip`, `destination.ip`, `destination.port`, `http.request.method`, `http.response.status_code`, `url.path`, `event.action`, `event.outcome`
1. Find events that appear in BOTH logs for the same source IP and time window (join by source IP ± 60 seconds)
1. Export the normalised, joined dataset as `normalised_events.csv`

**Deliverable**: Python script (`normalise_logs.py`) and output file (`normalised_events.csv`)

---

### Task 5: Threat Hunt

Based on your timeline analysis, write and execute 3 threat hunting queries:

**Hunt 1:** Identify if any other internal hosts communicated with the attacker's C2 infrastructure (not just the initially compromised system).

**Hunt 2:** Look for signs of credential reuse — did any new accounts log in successfully shortly after credential dumping was observed?

**Hunt 3:** Identify if any data exfiltration occurred before the known exfiltration event (was there earlier, smaller-scale exfiltration that went unnoticed?).

For each hunt, document:

* Hypothesis
* Query used
* Results (positive / negative / inconclusive)
* What you would do differently to improve coverage

**Deliverable**: `threat_hunt_report.md`

---

### Task 6: Post-Incident Analysis Report

Write a professional post-incident analysis (PIA) report.
This is the primary deliverable.

The report must include:

* **Executive Summary** (5–7 sentences, non-technical, suitable for board/management)
* **Incident Timeline** (from Task 1)
* **Impact Assessment**: What data was accessed/exfiltrated? How many records? What regulatory obligations apply (GDPR, NIS2)?
* **Root Cause Analysis**: What security controls failed or were absent?
* **ATT&CK Mapping Summary** (from Task 2)
* **Recommendations**: Minimum 5 specific, actionable recommendations
* **Lessons Learned**: What would have caught this attack earlier?

Minimum length: 1,500 words.

**Deliverable**: `post_incident_report.md`

---

## Hints

* Start with the email gateway log on Day 1 — phishing is the most common initial access vector
* The Windows Security Event Log is key for lateral movement: look for Event IDs 4624 (logon), 4625 (failed), 4648 (explicit credentials), 4698 (scheduled task)
* DNS queries will reveal C2 communication patterns — look for domains with high query frequency or unusual TLDs
* Database audit logs often contain the "smoking gun" — what was actually accessed
* For Task 4, pandas `pd.read_json()` and `pd.to_datetime()` are your primary tools
* The ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) is useful for visualising your technique map

---

## Grading Criteria

| Component | Points |
|-----------|--------|
| Timeline accuracy and completeness | 25 |
| ATT&CK mapping (≥8 techniques, evidence) | 20 |
| Diamond Model analysis | 15 |
| Log normalization (working script + output) | 15 |
| Threat hunt quality (3 hunts with results) | 10 |
| Post-incident report (professional quality) | 15 |
| **Total** | **100** |

---

## Submission

Submit a ZIP file containing:

* `timeline.md`
* `attack_mapping.md`
* `diamond_model.md`
* `normalise_logs.py` and `normalised_events.csv`
* `threat_hunt_report.md`
* `post_incident_report.md`
