# Demo 01 — SOAR Introduction: Building Your First Playbook

## Overview

This demo introduces SOAR concepts using **Shuffle** — a free, open-source SOAR platform.
We build a working phishing email response playbook from scratch, demonstrating how automation connects tools and reduces analyst workload.

**Duration:** 45 minutes

**Difficulty:** Beginner

**Tools:** Docker, Shuffle, VirusTotal API (free tier)

---

## Setup

### Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    container_name: shuffle-backend
    hostname: shuffle-backend
    environment:
      - DATASTORE_EMULATOR_HOST=shuffle-database:8000
      - SHUFFLE_APP_HOTLOAD_FOLDER=/shuffle-apps
      - SHUFFLE_FILE_LOCATION=/shuffle-files
      - SHUFFLE_DEFAULT_USERNAME=admin
      - SHUFFLE_DEFAULT_PASSWORD=shuffleadmin
    ports:
      - "5001:5001"
    volumes:
      - ./shuffle-apps:/shuffle-apps
      - ./shuffle-files:/shuffle-files
    depends_on:
      - shuffle-database
    networks:
      - shuffle-net

  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    container_name: shuffle-frontend
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
    ports:
      - "3001:80"
    depends_on:
      - shuffle-backend
    networks:
      - shuffle-net

  shuffle-database:
    image: fjogelid/datastore-emulator:latest
    container_name: shuffle-database
    environment:
      - DATASTORE_PROJECT_ID=shuffle
    ports:
      - "8000:8000"
    networks:
      - shuffle-net

networks:
  shuffle-net:
    driver: bridge
```

### Start the environment

```console
docker compose up -d
# Wait ~30 seconds for services to initialize

# Access Shuffle UI at: http://localhost:3001
# Username: admin
# Password: shuffleadmin
```

---

## Part 1: Manual Triage Simulation (10 minutes)

Before automating, perform the task manually to understand what we're automating.

**Scenario:** A user forwards a suspicious email.
You need to:

1. Extract the sender domain and any URLs
1. Check them on VirusTotal
1. Decide whether to block them

**Sample phishing email:**

```text
From: invoice@microsoflts-billing.com
Subject: URGENT: Your Microsoft subscription payment failed

Dear Customer,

Please click the link below to update your payment details:
http://update-ms365-payment.tk/secure/billing/

Your service will be suspended in 24 hours.

Microsoft Billing Team
```

**Manual steps:**

1. Extract domain: `microsoflts-billing.com`
1. Extract URL: `http://update-ms365-payment.tk/secure/billing/`
1. Go to https://www.virustotal.com — submit the URL
1. Note the result (likely 10+ vendors flag this as malicious)
1. Decision: Block domain and URL at email gateway and web proxy

**Time taken manually:** ~5–8 minutes per phishing report

---

## Part 2: Build the Phishing Playbook in Shuffle (25 minutes)

### Step 1: Log in to Shuffle

Open http://localhost:3001 and log in with admin/shuffleadmin.

### Step 2: Create a new workflow

1. Click **Workflows** → **New Workflow**
1. Name: `Phishing Email Response`
1. Description: `Automated triage and containment for reported phishing emails`

### Step 3: Add a Webhook trigger

1. Click the **+** icon in the workflow editor
1. Select **Trigger** → **Webhook**
1. Click the trigger block, copy the webhook URL
1. Set the trigger name: `Phishing Report Received`

### Step 4: Add URL extraction

1. Add action: **Tools** → **Regex capture group**
1. Name: `Extract URL`
1. Input: `$exec.body.email_body`
1. Regex: `https?://[^\s<>"]+`

### Step 5: Add VirusTotal check

1. Add action: **VirusTotal** → **Get URL report**
1. Name: `VT URL Check`
1. API Key: (enter your free VirusTotal API key)
1. URL: `$Extract_URL.#1`

### Step 6: Add decision branch

1. Add action: **Tools** → **Condition**
1. Name: `Is URL Malicious?`
1. Condition: `$VT_URL_Check.data.attributes.last_analysis_stats.malicious > 5`

### Step 7: Add notification (malicious branch)

1. Add action: **Tools** → **HTTP**
1. Name: `Alert Analyst`
1. Method: POST
1. URL: `http://your-webhook-receiver/alert` (use https://webhook.site for testing)
1. Body:

```json
{
  "severity": "HIGH",
  "message": "Malicious URL detected in phishing email",
  "url": "$Extract_URL.#1",
  "vt_score": "$VT_URL_Check.data.attributes.last_analysis_stats.malicious"
}
```

### Step 8: Test the workflow

**Send a test webhook:**

```console
curl -X POST http://localhost:3001/api/v1/hooks/<YOUR-WEBHOOK-ID> \
  -H "Content-Type: application/json" \
  -d '{
    "reporter": "jane.doe@company.com",
    "email_subject": "URGENT: Your payment failed",
    "email_body": "Click here: http://update-ms365-payment.tk/secure/billing/"
  }'
```

Check the workflow execution history to verify each step ran.

---

## Part 3: Review and Discussion (10 minutes)

### Before automation vs. after

| Metric | Manual | Automated |
|--------|--------|-----------|
| Time per report | 5–8 min | < 30 sec |
| Consistent process | No | Yes |
| Audit trail | Depends | Always |
| Analyst required | Yes (start to finish) | Only for exceptions |

### Automation boundaries

Discuss with the class: What should **not** be automated?

* The decision to fire someone based on phishing
* Law enforcement notifications
* Actions affecting more than 50 systems simultaneously without review
* Novel/unknown attack patterns

### Key takeaway

SOAR doesn't replace analysts — it amplifies them.
A single analyst with SOAR can effectively handle the volume that would require 3 without it.

---

## Cleanup

```console
docker compose down -v
```
