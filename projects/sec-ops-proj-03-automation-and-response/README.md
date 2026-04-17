# Project 03: Automation and Response — Building a SOAR-Enabled SOC

## Covers Sessions: 09–11 (SOC Workflow, Incident Management, Introduction to VERIS)

## Estimated Time: 7–8 hours

---

## Overview

In this project, you will build a Security Orchestration, Automation, and Response (SOAR) system from scratch using Python and Docker.
You will automate common SOC workflows, implement an incident management lifecycle with VERIS classification, and build a simple dashboard showing SOC operational metrics.

This is a hands-on engineering project — you will write Python code and configure Docker services.

This project integrates concepts from Sessions 09–11:

* SOC workflow automation and playbook execution (Session 09)
* Incident lifecycle management: triage, escalation, closure (Session 10)
* VERIS incident classification and DBIR-style reporting (Session 11)

---

## Learning Objectives

By completing this project you will be able to:

1. Design and implement an automated incident triage playbook in Python
1. Build an alert enrichment pipeline that queries threat intelligence sources
1. Implement an incident management database with full lifecycle tracking
1. Classify incidents using the VERIS 4-A model
1. Generate a DBIR-style incident summary report
1. Expose SOC metrics via a simple REST API

---

## Scenario

You have been asked to build a lightweight SOAR system for a small SOC that currently manages everything via email and spreadsheets.
The system must:

1. **Ingest** alerts from a simulated SIEM (alerts arrive as JSON via HTTP POST)
1. **Triage** alerts automatically: enrich with IOC context, assign severity, create incident tickets
1. **Manage** incident lifecycle: open → investigating → contained → closed
1. **Classify** closed incidents with VERIS fields
1. **Report** weekly metrics: MTTD, MTTR, incident counts by classification

---

## Environment Setup

```console
cd projects/sec-ops-proj-03-automation-and-response
docker compose up --build -d
```

Services:
| Service | URL | Description |
|---------|-----|-------------|
| SOAR API | http://localhost:7000 | Your SOAR system (you build this) |
| Alert Generator | internal | Sends test alerts to your SOAR API |
| SQLite DB | /data/incidents.db | Persistent incident database |
| Dashboard | http://localhost:7001 | Metrics dashboard (you build part of this) |

---

## Tasks

### Task 1: Alert Ingestion Endpoint (20 points)

Implement a Flask API endpoint that receives alerts from the SIEM:

**Endpoint:** `POST /api/alerts`

**Input format:**

```json
{
  "alert_id": "SIEM-2024-003421",
  "timestamp": "2024-03-15T10:23:41Z",
  "rule_name": "HTTP Brute Force",
  "severity": "medium",
  "source_ip": "185.220.101.42",
  "destination_ip": "10.0.0.15",
  "destination_port": 443,
  "raw_log": "10:23:41 185.220.101.42 -> 10.0.0.15:443 [...]"
}
```

**Required behaviour:**

* Validate required fields (return 400 if missing)
* Deduplicate: if an alert with the same `alert_id` already exists, return 409 Conflict
* Store the alert in the SQLite database
* Trigger the triage playbook (Task 2)
* Return: `{"incident_id": "INC-2024-001", "status": "created"}`

**Deliverable:** `soar/api/alerts.py`

---

### Task 2: Automated Triage Playbook (25 points)

Implement the triage playbook that runs automatically when a new alert is created:

**Playbook steps:**

1. **IOC Enrichment**: Query the local mock reputation database (`/data/ioc_db.json`) for the source IP.
   * If found AND score > 70: set incident severity to `HIGH`
   * If found AND score 40–70: set severity to `MEDIUM`
   * If not found: keep original severity

1. **Asset Lookup**: Query the asset database (`/data/assets.json`) for the destination IP.
   * If destination is a critical asset (e.g., database server, payment system): upgrade severity by one level

1. **Deduplication**: Check if an open incident already exists for the same source IP within the last 2 hours. If yes, add this alert to the existing incident rather than creating a new one.

1. **Auto-ticket creation**: For HIGH severity incidents, automatically create a ticket with priority `P1`. For MEDIUM: `P2`. For LOW: `P3`.

1. **Notification**: For P1 incidents, write a notification to `soar/notifications/p1_alerts.log` with format:

   ```text
   [2024-03-15T10:23:41Z] P1 ALERT: INC-2024-001 — HTTP Brute Force from 185.220.101.42 targeting db-server-01
```

**Deliverable:** `soar/playbooks/triage.py`

---

### Task 3: Incident Lifecycle Management (20 points)

Implement the full incident lifecycle API:

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/incidents` | List all incidents (with filters: status, severity, date range) |
| GET | `/api/incidents/{id}` | Get incident details including all associated alerts |
| PATCH | `/api/incidents/{id}/status` | Update status: `open → investigating → contained → closed` |
| POST | `/api/incidents/{id}/notes` | Add analyst notes to an incident |
| POST | `/api/incidents/{id}/close` | Close incident with resolution details and VERIS classification |

**Close payload:**

```json
{
  "resolution": "Blocked source IP, no breach confirmed",
  "veris": {
    "actor": {"external": {"variety": ["Unknown"]}},
    "action": {"hacking": {"variety": ["Brute-force"], "vector": ["Web application"]}},
    "asset": {"assets": [{"variety": "S - Web application"}]},
    "attribute": {"confidentiality": {"data_disclosed": "No"}}
  }
}
```

**Deliverable:** `soar/api/incidents.py`

---

### Task 4: VERIS Classification and Reporting (15 points)

Once at least 10 incidents are closed in your system (the alert generator will create them), generate a VERIS summary report:

**Script:** `soar/reports/veris_report.py`

**Output:** `reports/weekly_summary.md`

The report must include:

* Total incidents in the reporting period
* Breakdown by actor category (External, Internal, Partner, Unknown)
* Breakdown by action category (Hacking, Malware, Social, Error, Misuse, Physical, Environmental)
* Top 3 asset types targeted
* Top 3 action varieties (e.g., "Brute-force", "Phishing", "DoS")
* DBIR-style percentage bars (ASCII)

Example output:

```text
WEEKLY SOC SUMMARY — Week of 2024-03-11
========================================
Total Incidents: 23

Actor Categories:
  External  ||||||||||||||||||||  87%  (20)
  Internal  ||                    8%  ( 2)
  Unknown                          4%  ( 1)

Top Action Varieties:

  1. Brute-force       ||||||||||||  52%  (12)

  2. Phishing          |||||         22%  ( 5)
  3. C2 Communication  |||           13%  ( 3)
```

**Deliverable:** `soar/reports/veris_report.py` + sample output

---

### Task 5: Metrics API and Dashboard (10 points)

Implement a metrics API and connect it to the provided dashboard template:

**Endpoint:** `GET /api/metrics`

Response:

```json
{
  "period": "last_30_days",
  "total_alerts": 342,
  "total_incidents": 47,
  "false_positive_rate": 0.31,
  "mttd_hours": 3.2,
  "mttr_hours": 14.7,
  "open_incidents": 5,
  "by_severity": {"critical": 2, "high": 12, "medium": 28, "low": 5},
  "by_status": {"open": 5, "investigating": 3, "contained": 1, "closed": 38}
}
```

The dashboard at http://localhost:7001 reads from this endpoint and displays charts.

**Deliverable:** `soar/api/metrics.py`

---

### Task 6: Testing and Documentation (10 points)

**Tests:** Write at least 5 unit tests for your playbook and API:

```console
cd soar && python -m pytest tests/ -v
```

Tests should cover:

* Alert deduplication (same alert ID returns 409)
* IOC enrichment: high-score IP → severity upgrade
* Critical asset: destination is DB server → severity upgrade
* VERIS classification stored correctly
* MTTD calculation is accurate

**Documentation:** Write `soar/README.md` covering:

* Architecture overview (which component does what)
* How to run the system
* How to add a new playbook
* API reference (all endpoints, parameters, responses)

---

## Starter Code

The repository contains:

* `soar/app.py` — Flask application skeleton (empty routes)
* `soar/database.py` — SQLite schema and helper functions
* `data/ioc_db.json` — Mock IOC reputation database (200 entries)
* `data/assets.json` — Mock asset inventory with criticality ratings
* `alert_generator/generate.py` — Sends test alerts to your API
* `docker-compose.yml` — All services pre-configured

---

## Hints

* Start with Task 1 (ingestion) before anything else — the alert generator will test it immediately
* SQLite is pre-initialised with the schema from `soar/database.py` — do not recreate tables
* The VERIS 4-A model: **Actor** (who), **Action** (what), **Asset** (where/what affected), **Attribute** (what was compromised: C-I-A)
* For MTTD: calculate `alert.timestamp - incident.detection_time` (they are different fields)
* The metrics endpoint can use SQL aggregations directly: `SELECT COUNT(*), AVG(mttd_hours) FROM incidents`

* For ASCII bar charts in the report: `'|' * int(pct * 20)` gives 0–20 bars for 0–100%

---

## Grading Criteria

| Component | Points |
|-----------|--------|
| Alert ingestion endpoint (Task 1) | 20 |
| Triage playbook automation (Task 2) | 25 |
| Incident lifecycle API (Task 3) | 20 |
| VERIS report generation (Task 4) | 15 |
| Metrics API and dashboard (Task 5) | 10 |
| Tests + documentation (Task 6) | 10 |
| **Total** | **100** |

---

## Submission

Submit a ZIP of the entire `soar/` directory including:

* All Python source files
* `reports/weekly_summary.md` (sample output)
* `tests/` directory
* `soar/README.md`
* `screenshots/` with at least 3 screenshots (dashboard, API response, P1 notification)
