# Demo 03: Setting Up Shuffle SOAR with Docker and Connecting to Splunk

**Duration**: ~45 minutes

**Level**: Intermediate

**Prerequisites**: Docker and Docker Compose installed; 8GB RAM minimum

---

## Overview

This demo walks through the complete setup of Shuffle SOAR using Docker Compose and establishes a live integration with Splunk SIEM.
By the end, Splunk alerts will automatically trigger Shuffle workflows.

**What you will accomplish:**

* Deploy Shuffle SOAR (full stack) in Docker
* Deploy Splunk Enterprise in Docker
* Configure Splunk HEC (HTTP Event Collector) to send alerts to Shuffle
* Configure Shuffle webhook to receive Splunk alerts
* Test end-to-end: Splunk rule fires → Shuffle playbook executes

---

## Part 1: Deploy Shuffle SOAR

### 1.1 Clone/prepare the demo directory

```console
cd /opt/soc-lab/demo-03-shuffle-automation

# Create required directories
mkdir -p shuffle-apps shuffle-files
mkdir -p splunk-config sample-logs
```

### 1.2 Create Splunk configuration files

**splunk-config/inputs.conf:**

```ini
[monitor:///opt/splunk/var/spool/upload]
index = main
sourcetype = syslog

[http]
disabled = 0
enableSSL = 0
port = 8088
useDeploymentServer = 0
token = soar-integration-token-2026

[http://soar_alerts]
disabled = 0
index = soc_alerts
sourcetype = soc:alert
token = soar-integration-token-2026
```

**splunk-config/savedsearches.conf:**

```ini
[Phishing Email Alert]
search = index=soc_alerts sourcetype="soc:alert" alert_type="phishing" | head 100
dispatch.earliest_time = -5m
dispatch.latest_time = now
enableSched = 1
cron_schedule = */5 * * * *
alert.track = 1
alert.severity = 3
alert.suppress = 0
actions = webhook
action.webhook.param.url = http://shuffle-backend:5001/api/v1/hooks/webhook_phishing
action.webhook.enable = 1

[Brute Force Alert]
search = index=soc_alerts sourcetype="soc:alert" alert_type="brute_force" | stats count by src_ip | where count > 50
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
cron_schedule = */10 * * * *
alert.track = 1
alert.severity = 4
actions = webhook
action.webhook.param.url = http://shuffle-backend:5001/api/v1/hooks/webhook_bruteforce
action.webhook.enable = 1
```

### 1.3 Start the stack

```console
cd /opt/soc-lab/demo-03-shuffle-automation
docker compose up -d

# Watch startup progress
docker compose logs -f --tail 20
```

**Expected startup sequence:**

```text
shuffle-opensearch  | cluster health: green
shuffle-backend     | Shuffle backend starting on port 5001
shuffle-frontend    | nginx: starting
shuffle-orborus     | Connected to backend
splunk              | Splunk web started on http://0.0.0.0:8000
```

**Wait times:**

* OpenSearch: ~60 seconds to become healthy
* Splunk: ~2-3 minutes for first start
* Shuffle backend: ~30 seconds after OpenSearch is healthy

### 1.4 Verify services

```bash
# Check all containers are running
docker compose ps

# Test Shuffle API
curl -s http://localhost:5001/api/v1/health | python3 -m json.tool

# Test Splunk Web (may take 2-3 min on first start)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000
# Expected: 303 (redirect to login)

# Test Splunk HEC
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Splunk soar-integration-token-2026" \
  http://localhost:8088/services/collector/health
# Expected: 200
```

---

## Part 2: Initial Shuffle Configuration

### 2.1 First login and organization setup

1. Open browser: `http://localhost:3001`
1. Login: admin / ShuffleSOAR2026!
1. Navigate to **Admin** → **Organization**
1. Set organization name: `SOC Lab`
1. Note the **Organization ID** (needed for Orborus)

### 2.2 Verify Orborus is connected

1. Navigate to **Admin** → **Environments**
1. You should see environment `default` with status **Active**
1. If not active: check Docker logs `docker logs shuffle-orborus`

### 2.3 Install required apps

Navigate to **Apps** → **Search Apps** (uses Shuffle app repository):

Apps to install/activate:

* `VirusTotal` (v3)
* `TheHive` (v5)
* `HTTP` (included by default)
* `Shuffle Tools` (included by default)

For each app:

1. Click app → **Activate**
1. Click **Authenticate** → enter credentials
1. Click **Test Authentication**

---

## Part 3: Configure Splunk Integration

### 3.1 Access Splunk Web

1. Open: `http://localhost:8000`
1. Login: admin / Splunk2026Admin!
1. Accept license (first time)

### 3.2 Enable HTTP Event Collector (HEC)

1. Navigate to **Settings** → **Data Inputs** → **HTTP Event Collector**
1. Click **Global Settings**:
   * Enable SSL: **No** (lab only)
   * HTTP Port Number: **8088**
1. Click **Save**
1. Click **New Token**:
   * Name: `soar-integration`
   * Token Value: `soar-integration-token-2026`
   * Default Index: `soc_alerts`
1. Click **Review** → **Submit**

### 3.3 Create SOC Alerts index

1. Navigate to **Settings** → **Indexes** → **New Index**
1. Index Name: `soc_alerts`
1. Click **Save**

### 3.4 Ingest sample phishing alert

```bash
# Send a sample phishing alert to Splunk via HEC
curl -s -X POST http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk soar-integration-token-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "index": "soc_alerts",
    "sourcetype": "soc:alert",
    "event": {
      "alert_type": "phishing",
      "alert_id": "SPL-2026-001",
      "sender": "malware-test@virus.test",
      "sender_ip": "185.220.101.50",
      "recipient": "alice@company.com",
      "subject": "Your account requires immediate action",
      "urls": ["http://virus.test/phish"],
      "attachment_hash": "",
      "timestamp": "2026-04-06T14:32:11Z",
      "siem_rule": "Phishing_Email_Detected"
    }
  }'
```

### 3.5 Create Splunk alert with webhook action

1. In Splunk, navigate to **Search & Reporting**
1. Run search:

   ```spl
   index=soc_alerts sourcetype="soc:alert" alert_type="phishing"
   | table _time, alert_id, sender, recipient, urls, alert_type
```

1. Click **Save As** → **Alert**
1. Configure:
   * **Title**: `Phishing Email Detected`
   * **Permissions**: Private
   * **Alert Type**: Scheduled
   * **Run every**: 5 minutes
   * **Trigger when**: Number of results > 0
1. Under **Add Actions** → select **Webhook**
1. **URL**: `http://shuffle-backend:5001/api/v1/hooks/webhook_<your-shuffle-webhook-id>`
1. Click **Save**

> Get your Shuffle webhook ID from: Shuffle → Workflows → Your Workflow → Triggers → Webhook URL

---

## Part 4: Create the Shuffle Webhook Workflow

### 4.1 Create webhook workflow in Shuffle

1. Navigate to **Workflows** → **New Workflow**
1. Name: `Splunk Phishing Alert Handler`

### 4.2 Add Webhook trigger

1. Add **Webhook** trigger
1. Name: `splunk_phishing_webhook`
1. Copy the webhook URL (needed for Splunk)

### 4.3 Add VirusTotal enrichment

```text
Action: vt_check_url
App: VirusTotal
Action: Get URL analysis report

Parameter mapping:
  url: $exec.result.0.event.urls[0]
  (Splunk wraps the event data in result[0].event)
```

> Note: Splunk webhook sends data in format: `{"result": [{"event": {...}}]}`

### 4.4 Add Python scoring action

```python
# Action: score_and_route
import json

# Parse trigger data (Splunk format)
try:
    data = $exec
    if isinstance(data, str):
        data = json.loads(data)

    # Splunk webhook wraps event data
    event = data.get("result", [{}])[0].get("event", {})
    if not event:
        event = data  # Fallback if direct format

    alert_id = event.get("alert_id", "UNKNOWN")
    sender = event.get("sender", "unknown@unknown.com")

except Exception as e:
    event = {}
    alert_id = "PARSE_ERROR"
    sender = "error"

# Get VT results
vt_score = 0
try:
    vt_data = $vt_check_url
    if isinstance(vt_data, str):
        vt_data = json.loads(vt_data)
    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    vt_score = int((malicious / max(total, 1)) * 100)
except:
    vt_score = 0

verdict = "MALICIOUS" if vt_score >= 50 else ("SUSPICIOUS" if vt_score >= 20 else "CLEAN")
severity = 3 if verdict == "MALICIOUS" else (2 if verdict == "SUSPICIOUS" else 1)

return json.dumps({
    "alert_id": alert_id,
    "sender": sender,
    "vt_score": vt_score,
    "verdict": verdict,
    "thehive_severity": severity,
    "timestamp": event.get("timestamp", "")
})
```

### 4.5 Add TheHive alert creation

```text
Action: create_thehive_alert
App: TheHive
Action: Create Alert

title: "Splunk Phishing Alert: $score_and_route.sender [$score_and_route.verdict]"
description: |
  Alert from Splunk SIEM.
  Alert ID: $score_and_route.alert_id
  Sender: $score_and_route.sender
  VT Score: $score_and_route.vt_score%
  Verdict: $score_and_route.verdict
  Timestamp: $score_and_route.timestamp
severity: $score_and_route.thehive_severity
tags: ["phishing", "splunk-alert", "soar-auto"]
type: external
source: splunk
sourceRef: $score_and_route.alert_id
```

---

## Part 5: Test End-to-End Integration

### 5.1 Trigger the full pipeline

```bash
# 1. Send alert to Splunk HEC
curl -s -X POST http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk soar-integration-token-2026" \
  -d '{"index":"soc_alerts","sourcetype":"soc:alert","event":{"alert_type":"phishing","alert_id":"E2E-TEST-001","sender":"test@malicious-domain.evil","sender_ip":"185.220.101.50","recipient":"bob@company.com","urls":["http://malicious-domain.evil/login"],"timestamp":"2026-04-06T15:00:00Z"}}'

# 2. Wait ~30 seconds for Splunk scheduled alert to fire
# OR manually trigger from Splunk UI:
# Alerts → Phishing Email Detected → Run Now

# 3. Check Shuffle executions
curl -s -u admin:ShuffleSOAR2026! \
  http://localhost:5001/api/v1/workflows/executions | python3 -m json.tool

# 4. Verify TheHive alert was created
curl -s -u admin:admin \
  http://localhost:9000/api/alert?range=0-5 | python3 -m json.tool
```

### 5.2 Monitor execution in Shuffle UI

1. Open `http://localhost:3001`
1. Navigate to **Workflows** → your workflow
1. Click **Executions** tab
1. Click on the latest execution
1. Verify each action: green = success, red = failure
1. Click on any action to see input/output data

### 5.3 Verify complete data flow

```text
Splunk HEC event → soc_alerts index
         ↓
Splunk saved search → fires → webhook to Shuffle
         ↓
Shuffle: webhook received → workflow starts
         ↓
Shuffle: VirusTotal API call → score calculated
         ↓
Shuffle: TheHive → alert created
         ↓
TheHive: alert appears in Alerts list
```

---

## Part 6: Python Automation Script (Alternative to SOAR for testing)

For testing or minimal environments, use this Python script to simulate SOAR behavior:

```python
#!/usr/bin/env python3
"""
minimal_soar.py - Minimal SOAR simulation using Python
Tests the same workflow logic without Shuffle
"""

import requests
import json
import time
import sys

VIRUSTOTAL_API_KEY = "your-vt-api-key"
THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "your-thehive-api-key"

def check_url_virustotal(url):
    """Check URL reputation in VirusTotal"""
    import urllib.parse
    url_id = urllib.parse.quote(url, safe="").rstrip("=")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        return {"score": int(malicious/max(total,1)*100), "malicious": malicious}
    else:
        # URL not in VT, submit for analysis
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        return {"score": 0, "malicious": 0, "status": "submitted"}

def create_thehive_alert(title, description, severity, tags):
    """Create alert in TheHive"""
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "title": title,
        "description": description,
        "severity": severity,
        "tags": tags,
        "type": "external",
        "source": "python-soar",
        "sourceRef": f"auto-{int(time.time())}"
    }
    response = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers=headers,
        json=payload
    )
    return response.json()

def process_phishing_alert(alert_data):
    """Process a phishing alert end-to-end"""
    print(f"Processing alert: {alert_data.get('alert_id', 'UNKNOWN')}")

    urls = alert_data.get("urls", [])
    if not urls:
        print("No URLs to check")
        return

    # Enrich first URL
    print(f"Checking URL: {urls[0]}")
    vt_result = check_url_virustotal(urls[0])
    print(f"VT Score: {vt_result['score']}%")

    # Determine verdict
    if vt_result["score"] >= 50:
        verdict = "MALICIOUS"
        severity = 3
    elif vt_result["score"] >= 20:
        verdict = "SUSPICIOUS"
        severity = 2
    else:
        verdict = "CLEAN"
        severity = 1

    print(f"Verdict: {verdict}")

    # Create TheHive alert
    if verdict in ["MALICIOUS", "SUSPICIOUS"]:
        alert = create_thehive_alert(
            title=f"Phishing Alert [{verdict}]: {alert_data.get('sender', 'unknown')}",
            description=f"""
Automated Phishing Detection

Sender: {alert_data.get('sender')}
Recipient: {alert_data.get('recipient')}
URL: {urls[0]}
VT Score: {vt_result['score']}%
Verdict: {verdict}
Alert ID: {alert_data.get('alert_id')}
            """,
            severity=severity,
            tags=["phishing", "python-soar", verdict.lower()]
        )
        print(f"TheHive alert created: {alert.get('_id', 'ERROR')}")

    return {"verdict": verdict, "vt_score": vt_result["score"]}

if __name__ == "__main__":
    # Example alert
    test_alert = {
        "alert_id": "TEST-001",
        "sender": "attacker@evil.test",
        "recipient": "user@company.com",
        "urls": ["http://evil.test/phish"],
        "timestamp": "2026-04-06T14:32:11Z"
    }
    result = process_phishing_alert(test_alert)
    print(f"Final result: {json.dumps(result, indent=2)}")
```

Run the script:

```console
python3 minimal_soar.py
```

---

## Cleanup

```bash
# Stop all containers (preserve data)
docker compose down

# Stop and remove all data (full reset)
docker compose down -v

# Remove images (free disk space)
docker rmi ghcr.io/shuffle/shuffle-frontend:latest \
           ghcr.io/shuffle/shuffle-backend:latest \
           ghcr.io/shuffle/shuffle-orborus:latest \
           splunk/splunk:9.2
```

---

## Troubleshooting Guide

| Problem | Diagnosis | Fix |
|---------|-----------|-----|
| OpenSearch won't start | Check `vm.max_map_count` | `sysctl -w vm.max_map_count=262144` |
| Shuffle backend crashes | Check OpenSearch health | Wait for OpenSearch healthy status |
| Splunk won't start | Port 8000 in use | `lsof -i :8000` and kill conflict |
| Webhook not triggered | Splunk alert not saving | Check savedsearches.conf syntax |
| Shuffle execution fails | App auth error | Re-authenticate app in Shuffle UI |
| TheHive not reachable | Network issue | Check soc-net Docker network |

**Resource requirements:**

* Shuffle stack: ~2GB RAM
* Splunk: ~2GB RAM
* Total recommended: 8GB RAM, 4 vCPUs, 20GB disk
