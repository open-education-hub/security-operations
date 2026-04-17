# Drill 01 (Advanced): Full SOAR Deployment

**Level**: Advanced

**Estimated time**: 3-4 hours

**Type**: Hands-on implementation

**Prerequisites**: All demos completed; Shuffle + TheHive + Splunk running

---

## Learning Objectives

* Design and deploy a multi-playbook SOAR system
* Build integrations between Splunk, Shuffle, and TheHive
* Implement automated containment with human-in-the-loop approval
* Create automated metrics collection from the SOAR platform
* Handle edge cases and failures gracefully

---

## Scenario: MedCorp SOAR Deployment

MedCorp has approved a Shuffle SOAR deployment.
Your task is to deploy a production-ready SOAR solution covering the three highest-volume alert types:

1. **Phishing emails** (412/month, 69% FP rate)
1. **Brute force/credential stuffing** (198/month, 44% FP rate)
1. **Malware detections** (72/month, 12% FP rate)

Each workflow must:

* Receive alerts from Splunk via webhook
* Enrich IOCs using VirusTotal and/or AbuseIPDB
* Create structured cases in TheHive with observables
* For high-confidence detections: implement automated containment with approval gate
* Send SOC team notifications via Slack
* Collect execution metrics for weekly reporting

---

## Part 1: Infrastructure Setup (45 min)

### 1.1 Deploy the full stack

Use the following docker-compose which combines all components:

```yaml
# File: docker-compose.yml
# Full SOAR lab stack: Shuffle + TheHive + Cortex + Splunk

version: '3.8'
services:
  # --- Shuffle SOAR ---
  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    ports: ["3001:80"]
    environment: [BACKEND_HOSTNAME=shuffle-backend]
    networks: [soc-net]

  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    ports: ["5001:5001"]
    volumes:
      - ./shuffle-apps:/shuffle-apps
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - OPENSEARCH_URL=http://shuffle-opensearch:9200
      - SHUFFLE_DEFAULT_USERNAME=admin
      - SHUFFLE_DEFAULT_PASSWORD=ShuffleSOAR2026!
    networks: [soc-net]

  shuffle-opensearch:
    image: opensearchproject/opensearch:2.11.1
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
    ulimits:
      nofile: {soft: 65536, hard: 65536}
    networks: [soc-net]

  shuffle-orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    volumes: [/var/run/docker.sock:/var/run/docker.sock:ro]
    environment:
      - BASE_URL=http://shuffle-backend:5001
      - ORG_ID=default
      - ENVIRONMENT_NAME=default
    networks: [soc-net]

  # --- TheHive + Cortex ---
  thehive:
    image: strangebee/thehive:5.3
    ports: ["9000:9000"]
    depends_on: [cassandra, elasticsearch]
    networks: [soc-net]

  cortex:
    image: thehiveproject/cortex:3.1.8
    ports: ["9001:9001"]
    volumes: [/var/run/docker.sock:/var/run/docker.sock:ro]
    networks: [soc-net]

  cassandra:
    image: cassandra:4
    networks: [soc-net]

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.14
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    networks: [soc-net]

  # --- Splunk ---
  splunk:
    image: splunk/splunk:9.2
    ports: ["8000:8000", "8088:8088", "8089:8089"]
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=Splunk2026Admin!
    networks: [soc-net]

networks:
  soc-net:
    driver: bridge
```

### 1.2 Verification

```console
# Check all services
docker compose ps

# Test each service API
curl -sf http://localhost:5001/api/v1/health && echo "Shuffle OK"
curl -sf http://localhost:9000/api/v1/status && echo "TheHive OK"
curl -sf -o /dev/null -w "%{http_code}" http://localhost:8000 && echo " Splunk OK"
```

---

## Part 2: Build Three SOAR Workflows (90 min)

### Workflow 1: Phishing Email Response

**Trigger**: Webhook from Splunk `Phishing_Email_Detected` rule

**Required actions**:

1. Extract sender, URLs, attachment hashes from webhook payload
1. Check URL reputation (VirusTotal)
1. Check sender domain (AbuseIPDB)
1. Calculate composite risk score
1. If score ≥ 70: Create HIGH severity TheHive alert + request quarantine approval via Slack
1. If 30 ≤ score < 70: Create MEDIUM severity TheHive alert (analyst review)
1. If score < 30: Create LOW severity TheHive alert (auto-close candidate)

**Success criteria**:

* [ ] Webhook receives Splunk payload correctly
* [ ] VirusTotal check runs in <30 sec
* [ ] TheHive alert created with correct severity for each score range
* [ ] Slack notification sent for HIGH severity with approval button (or text asking for manual approval)
* [ ] Workflow execution completes without error for all 3 score scenarios

### Workflow 2: Brute Force / Account Compromise

**Trigger**: Webhook from Splunk `Credential_Stuffing_Detected` rule

**Required actions**:

1. Extract attacker IPs, target accounts, success/fail counts
1. Check all source IPs against AbuseIPDB (loop over IPs)
1. Calculate average abuse score
1. Query SIEM (Splunk API) for additional context: did same IPs hit other systems?
1. If successful logins detected: Create P1 TheHive case + send urgent Slack message
1. If no successful logins + all IPs have high abuse score: Create P2 TheHive case
1. Add all source IPs as observables in TheHive case

**Success criteria**:

* [ ] IP loop correctly processes all 3 IPs from scenario
* [ ] Splunk API query returns context data
* [ ] TheHive case created with severity based on login success/failure
* [ ] All source IPs added as observables

### Workflow 3: Malware Hash Enrichment

Build on Drill 01 (Intermediate).
Extend with:

* Add MalwareBazaar lookup in parallel with VirusTotal
* Auto-submit unknown hashes to VirusTotal for scanning
* Add file metadata lookup (magic bytes, file type)
* If MALICIOUS: trigger endpoint isolation approval workflow
  * Create Slack message: "⚠️ APPROVAL NEEDED: Isolate workstation-42? React ✅ for YES, ❌ for NO"
  * Note: In a full implementation, you'd use Slack interactive components; for lab, document the approval step as a manual action

---

## Part 3: Integration Testing (30 min)

### 3.1 Send test alerts to Splunk HEC

```bash
# Test phishing alert
curl -X POST http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk soar-integration-token-2026" \
  -d '{
    "index": "soc_alerts",
    "sourcetype": "soc:alert",
    "event": {
      "alert_type": "phishing",
      "alert_id": "ADV-TEST-001",
      "sender": "malware@evil-domain.xyz",
      "urls": ["http://evil-domain.xyz/steal"],
      "timestamp": "2026-04-06T15:00:00Z"
    }
  }'

# Trigger Splunk saved search manually (or wait for scheduler)
# Then watch Shuffle executions: http://localhost:3001
```

### 3.2 Verify end-to-end

For each workflow:

1. Trigger the webhook with test data
1. Monitor Shuffle execution
1. Verify TheHive case/alert created with correct fields
1. Verify Slack notification sent (check webhook endpoint)
1. Document execution time

---

## Part 4: Metrics Collection Workflow (30 min)

Build a 4th workflow: **Daily SOC Metrics Report**

**Trigger**: Schedule (daily at 08:00)

**Actions**:

1. Query Shuffle API: count executions by workflow for last 24h
1. Query TheHive API: count alerts by severity and status for last 24h
1. Calculate: automation rate = (auto-closed alerts / total alerts) × 100
1. Build metrics summary report
1. Send to SOC Slack channel

```python
# Action: calculate_daily_metrics

import json
from datetime import datetime, timedelta

# Data from previous actions
shuffle_executions = $get_shuffle_executions
thehive_alerts = $get_thehive_alerts

# Count metrics
total_alerts = len(thehive_alerts.get("data", []))

# Count by status
status_counts = {}
for alert in thehive_alerts.get("data", []):
    status = alert.get("status", "unknown")
    status_counts[status] = status_counts.get(status, 0) + 1

auto_closed = status_counts.get("Ignored", 0) + status_counts.get("Closed", 0)
automation_rate = round(auto_closed / max(total_alerts, 1) * 100, 1)

report = f"""
📊 *Daily SOC Metrics Report* — {datetime.now().strftime('%Y-%m-%d')}

*Alert Volume*: {total_alerts} alerts
*Auto-resolved*: {auto_closed} ({automation_rate}%)
*Requiring review*: {total_alerts - auto_closed}

*By Status*:
{chr(10).join(f'  • {k}: {v}' for k, v in status_counts.items())}

*Workflows executed*: {len(shuffle_executions.get("executions", []))}
"""

return report
```

---

## Part 5: Documentation (30 min)

Create documentation for your deployment:

1. **Architecture diagram** (hand-drawn or tool): Show all components and data flows
1. **Runbook**: How to restart the stack if something fails
1. **Operations guide**: How to add a new alert type to an existing workflow
1. **Known limitations**: What doesn't work perfectly in this lab setup

---

## Deliverables

1. All three Shuffle workflows (exported JSON files)
1. Screenshots: 3 test executions (one per workflow, showing complete execution)
1. Screenshots: 3 TheHive cases/alerts (one per workflow)
1. Daily metrics workflow (exported JSON)
1. Architecture diagram
1. Operations documentation (max 2 pages)

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| All 3 workflows deployed and functional | 30 |
| Conditional branching works correctly | 15 |
| TheHive integration creates correct artifacts | 20 |
| Metrics workflow functional | 15 |
| Documentation is clear and accurate | 10 |
| Error handling/edge cases addressed | 10 |
| **Total** | **100** |
