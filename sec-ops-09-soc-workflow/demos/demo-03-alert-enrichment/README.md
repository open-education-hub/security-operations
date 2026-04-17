# Demo 03: Automated Alert Enrichment with TheHive + Cortex

## Overview

This demo shows how an incoming alert is automatically enriched using TheHive (case management) and Cortex (analyzer engine) before an analyst reviews it.
Students will see how IP addresses, hashes, and domains are automatically checked against threat intelligence within seconds of case creation.

## Learning Objectives

* Understand TheHive case and observable structure
* See Cortex analyzers run in real-time
* Compare manual vs automated enrichment time
* Observe how enrichment context changes triage decisions

## Prerequisites

* Docker and Docker Compose installed
* 4 GB RAM available (Elasticsearch + TheHive + Cortex)
* VirusTotal free API key (optional, for live enrichment)

## Setup

### 1. Start the stack

```console
docker compose up -d
```

The `docker-compose.yml` starts:

* Elasticsearch 7.17 (TheHive backend)
* TheHive 5.2
* Cortex 3.1.7

### 2. Wait for startup (approx 90 seconds)

```console
docker compose logs -f thehive | grep "Started"
```

### 3. Configure Cortex

Open http://localhost:9001 in your browser.

1. Create admin account on first run
1. Navigate to **Organizations** → Create `demo-org`
1. Navigate to **Users** → Create API user, copy the API key
1. Enable analyzers: `AbuseIPDB_2_0`, `Shodan_Host_1_0`, `VirusTotal_GetReport_3_0`

### 4. Connect TheHive to Cortex

In TheHive (http://localhost:9000):

1. Login as admin (admin / secret)
1. **Platform Management** → **Cortex** → Add server
   * URL: `http://cortex:9001`
   * API Key: (from step 3)

### 5. Inject a test alert

```bash
# Create a case with suspicious observables via TheHive API
curl -u admin:secret -H "Content-Type: application/json" \
  -X POST http://localhost:9000/api/case \
  -d '{
    "title": "Suspicious Outbound Connection - DEMO-PC-01",
    "description": "EDR alert: process svchost.exe connected to 185.220.101.5:443",
    "severity": 2,
    "tags": ["demo", "c2-suspected"]
  }'
```

Then add observables to the case:

```console
# Replace CASE_ID with the returned _id
CASE_ID="..."

curl -u admin:secret -H "Content-Type: application/json" \
  -X POST http://localhost:9000/api/v1/case/$CASE_ID/observable \
  -d '{"dataType": "ip", "data": "185.220.101.5", "ioc": true, "tags": ["c2"]}'

curl -u admin:secret -H "Content-Type: application/json" \
  -X POST http://localhost:9000/api/v1/case/$CASE_ID/observable \
  -d '{"dataType": "hash", "data": "4abc5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c", "ioc": true}'
```

## Demo Walkthrough

### Step 1: Show the case without enrichment (2 min)

Open the case in TheHive.
Point out that the observables are just raw data — IP and hash — no context.

**Ask:** "If this is all you have, how long would it take to manually check these?"

### Step 2: Run Cortex analyzers (3 min)

1. Click on the IP observable `185.220.101.5`
1. Click **Run Analyzers**
1. Select `AbuseIPDB_2_0` and run
1. Watch the real-time result appear

**Expected result:** AbuseIPDB reports this is a Tor exit node with 2,000+ abuse reports.

### Step 3: Run hash analyzer (3 min)

1. Click on the hash observable
1. Run `VirusTotal_GetReport_3_0`
1. Show the JSON result: detection rate, malware family name

### Step 4: Compare timelines (2 min)

| Approach | Time to enrich both observables |
|----------|---------------------------------|
| Manual (browser tabs) | ~8 minutes |
| Cortex automated | ~45 seconds |
| **With auto-run on case create** | ~0 analyst minutes |

### Step 5: Show the enriched triage decision

With enrichment complete, walk through the triage:

* IP is a known Tor exit → attacker using anonymization
* Hash matches known malware → confirmed infection
* Decision: **P1 — Escalate immediately**

## Discussion Questions

1. What is the risk of fully automating the escalation decision (not just enrichment)?
1. What happens when a Cortex analyzer's API key expires?
1. How would you handle a situation where VirusTotal is unavailable?

## Teardown

```console
docker compose down -v
```

## Files

* `docker-compose.yml` — TheHive + Cortex + Elasticsearch stack
