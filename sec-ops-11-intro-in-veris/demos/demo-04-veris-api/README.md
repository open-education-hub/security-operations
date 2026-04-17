# Demo 04: VERIS Community API and Dataset Tools

## Overview

In this demo, we interact with the VERIS Community Database (VCDB) dataset using command-line tools and a local REST API that wraps the dataset.
Students will query, filter, and export incident data, simulating how a SOC analyst would leverage community incident intelligence for threat modeling and benchmarking.

## Learning Objectives

* Understand the structure and accessibility of the VCDB
* Query VERIS incident data by industry, actor type, and action
* Calculate basic threat metrics from the dataset
* Export filtered datasets for further analysis
* Understand how community data can inform SOC detection priorities

## Prerequisites

* Docker installed and running
* `curl` or any HTTP client (browser works too)

## Setup

```console
cd demos/demo-04-veris-api
docker compose up --build
```

Services started:

* **VERIS API**: http://localhost:8080 — REST API over the sample dataset
* **Data browser**: http://localhost:8080/docs — Swagger UI for API exploration

## Files

* `docker-compose.yml` — service definition
* `Dockerfile` — FastAPI + Python environment
* `app/main.py` — FastAPI application
* `app/data/` — sample VERIS dataset (100 records)
* `app/queries/` — example query scripts

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/incidents` | List all incidents (paginated) |
| GET | `/incidents/{id}` | Get a specific incident |
| GET | `/incidents/filter` | Filter by industry, actor, action, year |
| GET | `/stats/actors` | Actor type breakdown |
| GET | `/stats/actions` | Action type breakdown |
| GET | `/stats/industries` | Industry breakdown |
| GET | `/stats/timeline` | MTTD/MTTC statistics |
| GET | `/export/csv` | Export filtered results as CSV |

## Walk-through

### Step 1: Explore the Dataset

```console
# Get total count
curl http://localhost:8080/incidents | python3 -m json.tool | head -20

# Get actor statistics
curl http://localhost:8080/stats/actors | python3 -m json.tool
```

Expected response:

```json
{
  "total": 100,
  "breakdown": {
    "external": 67,
    "internal": 24,
    "partner": 9
  }
}
```

### Step 2: Filter by Industry

```console
# Healthcare incidents only
curl "http://localhost:8080/incidents/filter?industry=Healthcare" | python3 -m json.tool

# Finance + external actors
curl "http://localhost:8080/incidents/filter?industry=Finance&actor=external" | python3 -m json.tool
```

### Step 3: Filter by Attack Type

```console
# All incidents involving ransomware
curl "http://localhost:8080/incidents/filter?action=malware&variety=Ransomware" | python3 -m json.tool

# Phishing incidents in the last 2 years
curl "http://localhost:8080/incidents/filter?action=social&variety=Phishing&year_from=2022" | python3 -m json.tool
```

### Step 4: Get Timeline Statistics

```console
# MTTD and MTTC across all incidents
curl http://localhost:8080/stats/timeline | python3 -m json.tool
```

Expected response:

```json
{
  "mttd_hours_avg": 312.5,
  "mttd_hours_median": 168.0,
  "mttc_hours_avg": 48.3,
  "mttc_hours_median": 24.0,
  "sample_size": 45
}
```

### Step 5: Build a Threat Profile

Use the API to answer: *"What does the threat landscape look like for a European financial services company?"*

```console
# Step 1: Get Finance incidents
curl "http://localhost:8080/incidents/filter?industry=Finance" > finance_incidents.json

# Step 2: Analyze actors
curl "http://localhost:8080/stats/actors?industry=Finance" | python3 -m json.tool

# Step 3: Analyze actions
curl "http://localhost:8080/stats/actions?industry=Finance" | python3 -m json.tool

# Step 4: Look at data types disclosed
curl "http://localhost:8080/stats/data_types?industry=Finance" | python3 -m json.tool
```

Build a brief threat profile:

```text
THREAT PROFILE: Financial Services
===================================
Top Actor: External (organized crime) — XX%
Top Initial Action: Social engineering (phishing) — XX%
Top Follow-up Action: Hacking (stolen creds) — XX%
Most targeted assets: Databases, Mail servers
Most common data loss: Financial records, Credentials
MTTD: XX hours average
```

### Step 6: Export for Reporting

```console
# Export filtered Finance incidents as CSV for a report
curl "http://localhost:8080/export/csv?industry=Finance" -o finance_incidents.csv

# Open the CSV
cat finance_incidents.csv | head -5
```

### Step 7: API-driven Detection Tuning

Based on the threat profile, a SOC analyst would:

1. **Prioritize phishing detection** — email gateway, URL scanning
1. **Focus on credential monitoring** — impossible travel, unusual login times
1. **Alert on database access anomalies** — large exports, off-hours queries
1. **Review mail server logging** — exfiltration via email

In your SIEM, the top correlation rules for Finance should cover:

* Phishing click detection (proxy logs)
* Credential stuffing (failed login spikes)
* Large data downloads (DLP alerts)

## Clean Up

```console
docker compose down
```
