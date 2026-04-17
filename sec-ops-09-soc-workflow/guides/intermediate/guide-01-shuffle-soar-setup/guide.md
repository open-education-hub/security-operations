# Guide 01 (Intermediate): Setting Up and Configuring Shuffle SOAR

**Level**: Intermediate

**Estimated time**: 60 minutes

**Prerequisites**: Docker experience; Demo 03 reviewed; basic REST API knowledge

---

## Learning Objectives

After this guide, you will be able to:

* Deploy Shuffle SOAR in production-ready Docker configuration
* Configure app authentication for security tool integrations
* Build and test a complete automated workflow
* Handle workflow errors and implement retry logic
* Export/import workflows for version control

---

## Section 1: Production-Ready Shuffle Deployment

### 1.1 Security hardening considerations

The Demo 03 docker-compose uses default credentials.
For any non-lab deployment:

```console
# Generate secure random values
openssl rand -hex 32  # Use output as SHUFFLE_ENCRYPTION_MODIFIER
openssl rand -base64 24  # Use as admin password
```

### 1.2 Production docker-compose configuration

```yaml
version: '3.8'

secrets:
  shuffle_encryption_key:
    file: ./secrets/encryption.key
  shuffle_admin_password:
    file: ./secrets/admin.password

services:
  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:1.4.0  # Pin version in production
    container_name: shuffle-frontend
    restart: always
    ports:
      - "127.0.0.1:3001:80"  # Bind to localhost; use reverse proxy for HTTPS
    environment:
      - BACKEND_HOSTNAME=shuffle-backend
    depends_on:
      shuffle-backend:
        condition: service_healthy
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:1.4.0
    container_name: shuffle-backend
    restart: always
    ports:
      - "127.0.0.1:5001:5001"
    volumes:
      - ./shuffle-apps:/shuffle-apps
      - ./shuffle-files:/shuffle-files
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - SHUFFLE_APP_HOTLOAD_FOLDER=/shuffle-apps
      - SHUFFLE_FILE_LOCATION=/shuffle-files
      - OPENSEARCH_URL=http://shuffle-opensearch:9200
      - SHUFFLE_ENCRYPTION_MODIFIER_FILE=/run/secrets/shuffle_encryption_key
    secrets:
      - shuffle_encryption_key
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:5001/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 45s
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  shuffle-orborus:
    image: ghcr.io/shuffle/shuffle-orborus:1.4.0
    container_name: shuffle-orborus
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - SHUFFLE_APP_SDK_VERSION=1.1.0
      - SHUFFLE_WORKER_VERSION=1.4.0
      - ORG_ID=default
      - ENVIRONMENT_NAME=production
      - BASE_URL=http://shuffle-backend:5001
      - SHUFFLE_ORBORUS_EXECUTION_TIMEOUT=600
      - SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY=5
      - CLEANUP=true
      - HTTP_PROXY=${HTTP_PROXY:-}
      - HTTPS_PROXY=${HTTPS_PROXY:-}
      - NO_PROXY=shuffle-backend,shuffle-opensearch
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  shuffle-opensearch:
    image: opensearchproject/opensearch:2.11.1
    container_name: shuffle-opensearch
    restart: always
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx2g"
      - cluster.routing.allocation.disk.threshold_enabled=false
    volumes:
      - shuffle-opensearch-data:/usr/share/opensearch/data
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health | python3 -c \"import sys,json;d=json.load(sys.stdin);sys.exit(0 if d.get('status') in ['green','yellow'] else 1)\""]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  shuffle-opensearch-data:
    driver: local

networks:
  default:
    name: shuffle-net
```

### 1.3 Deploy and verify

```bash
# Create secrets directory
mkdir -p secrets
openssl rand -hex 32 > secrets/encryption.key
# Set admin password interactively:
echo -n "YourSecurePassword2026!" > secrets/admin.password

# Set file permissions (secrets should only be readable by root)
chmod 600 secrets/encryption.key secrets/admin.password

# Deploy
docker compose up -d

# Verify health
docker compose ps
curl -sf http://localhost:5001/api/v1/health | python3 -m json.tool
```

---

## Section 2: App Configuration Reference

### 2.1 VirusTotal App

```text
App: VirusTotal
Auth Type: API Key
Header: x-apikey

Configuration:
  Authentication label: virustotal-prod
  API Key: [Your VT API key]

Rate limits (free tier):
  - 4 requests/minute
  - 500 requests/day

Workaround for rate limits in Shuffle:
  Add "Shuffle Tools → Wait" action with 15000ms delay
  between consecutive VT calls in loops
```

### 2.2 TheHive App

```text
App: TheHive
Auth Type: Bearer Token

Configuration:
  URL: http://thehive:9000  (use container hostname in same Docker network)
  API Key: [TheHive API key from Profile → API Key]

To generate TheHive API key:

  1. Login to TheHive

  2. Click profile icon → Settings → API Keys
  3. Create → Copy key (shown only once)
```

### 2.3 HTTP App (Generic REST)

The HTTP app is Shuffle's Swiss Army knife.
Use it to call any tool not in the app catalog.

```text
App: HTTP
Auth: None (pass credentials per-action via headers)

Common authentication patterns:

# API Key in header:
Headers:
  Authorization: ApiKey <your-key>

# Bearer token:
Headers:
  Authorization: Bearer <your-token>

# Basic auth:
Headers:
  Authorization: Basic <base64(user:pass)>

# Custom header:
Headers:
  X-API-Key: <your-key>
```

### 2.4 Splunk App

```text
App: Splunk
Auth Type: Basic or Token

Configuration:
  URL: http://splunk:8089  (REST API, NOT port 8000)
  Username: admin
  Password: [Splunk admin password]

  OR for token auth:
  Token: [Splunk API token from Settings → Token Management]

Note: Port 8089 is Splunk REST API. Port 8000 is Web UI only.
```

### 2.5 Slack App

```text
App: HTTP (use generic HTTP for Slack webhooks)

Incoming Webhook setup:

  1. api.slack.com → Your Apps → Create App

  2. Incoming Webhooks → Activate
  3. Add to workspace → select channel
  4. Copy webhook URL

Shuffle action:
  App: HTTP
  Method: POST
  URL: https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
  Headers: Content-Type: application/json
  Body: {"text": "Your message here"}

For rich formatting:
  Body: {
    "blocks": [
      {
        "type": "header",
        "text": {"type": "plain_text", "text": "🚨 Security Alert"}
      },
      {
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*Sender*: $exec.sender\n*Score*: $score.vt_score%"}
      }
    ]
  }
```

---

## Section 3: Variable Reference and Data Manipulation

### 3.1 Variable syntax in Shuffle

```text
$exec                    → Root of trigger execution data
$exec.field              → Specific field from trigger
$exec.array[0]           → First element of an array
$action_name             → Root output of a previous action
$action_name.field       → Specific field from action output
$action_name.data[0]     → First element of data array
```

### 3.2 Common data extraction patterns

**Extracting from VirusTotal response:**

```text
VT Response structure:
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 12,
        "suspicious": 3,
        "undetected": 56,
        "harmless": 14,
        "timeout": 0
      }
    }
  }
}

Access malicious count:
$vt_check.data.attributes.last_analysis_stats.malicious

Calculate score in Python action:
import json
vt = $vt_check if isinstance($vt_check, dict) else json.loads($vt_check)
malicious = vt["data"]["attributes"]["last_analysis_stats"]["malicious"]
total = sum(vt["data"]["attributes"]["last_analysis_stats"].values())
score = int(malicious / max(total, 1) * 100)
```

**Extracting from TheHive Create response:**

```text
TheHive Create Alert returns:
{"_id": "~123456789", "_type": "alert", "title": "...", ...}

Access case ID:
$thehive_create._id
```

**Handling Splunk webhook format:**

```text
Splunk webhook wraps results in "result" key:
{
  "result": {
    "src_ip": "10.0.0.1",
    "dest_host": "dc01",
    ...
  },
  "search_name": "Brute Force Alert",
  ...
}

Access search name: $exec.search_name
Access src_ip: $exec.result.src_ip
```

### 3.3 Python transformation patterns

```python
# Pattern 1: Safe JSON parsing (handles string or dict)
import json
def safe_parse(data):
    if isinstance(data, str):
        return json.loads(data)
    return data

# Pattern 2: Extract field with default
data = safe_parse($action_name)
value = data.get("field", "default_value")

# Pattern 3: Nested extraction with error handling
try:
    score = data["data"]["attributes"]["stats"]["malicious"]
except (KeyError, TypeError):
    score = 0

# Pattern 4: Calculate percentage
numerator = 5
denominator = 87
percentage = round(numerator / max(denominator, 1) * 100, 1)

# Pattern 5: Build formatted string
lines = [
    f"Score: {score}%",
    f"Verdict: {'MALICIOUS' if score > 50 else 'CLEAN'}",
    f"Checked: {len(ips)} IPs"
]
return "\n".join(lines)
```

---

## Section 4: Error Handling in Workflows

### 4.1 Action failure modes

| Failure Type | Cause | Handling |
|-------------|-------|---------|
| API rate limit (429) | Too many requests | Add Wait action; retry with exponential backoff |
| Auth failure (401) | Invalid/expired credentials | Re-authenticate app; alert admin |
| Not found (404) | IOC not in database | Handle gracefully; score = 0 |
| Timeout | Slow API response | Increase timeout in action config |
| Parse error | Unexpected response format | Use try/except in Python; provide defaults |

### 4.2 Implementing retry logic in Python

```python
import json
import time

def with_retry(action_output, max_attempts=3):
    """
    Shuffle doesn't have native retry, but you can implement it
    in a Python action by checking for error indicators.
    """
    data = action_output if isinstance(action_output, dict) else {}

    # Check for rate limit indicator
    if isinstance(action_output, str) and "rate limit" in action_output.lower():
        time.sleep(60)  # Wait 1 minute for VT free tier reset
        return {"error": "rate_limited", "retry": True}

    # Check for auth error
    if isinstance(action_output, dict) and action_output.get("error") == "Wrong credentials":
        return {"error": "auth_failed", "retry": False, "alert_admin": True}

    return {"data": data, "error": None}

result = with_retry($vt_check)
return json.dumps(result)
```

### 4.3 Fallback workflow design

Build workflows with graceful degradation:

```text
[VirusTotal URL Check]
        │
   ┌────┴────┐
   │ Success │ Error/Timeout
   │         │
   ▼         ▼
[Use VT   [Use AbuseIPDB
 Score]    as fallback]
   │         │
   └────┬────┘
        │
   [Continue with available score]
```

---

## Section 5: Workflow Version Control

### 5.1 Export workflow for Git

```bash
# Export via Shuffle API
WORKFLOW_ID="your-workflow-uuid"
SHUFFLE_KEY="your-api-key"

curl -s -u admin:${SHUFFLE_KEY} \
  "http://localhost:5001/api/v1/workflows/${WORKFLOW_ID}/export" \
  -o "workflows/phishing-response-v1.json"

# Add to Git
git add workflows/
git commit -m "feat: add phishing response playbook v1.0"
git push
```

### 5.2 Workflow JSON structure for version tracking

```json
{
  "id": "uuid-here",
  "name": "Phishing Email Response",
  "description": "Automated phishing triage: enrich, score, quarantine",
  "created": "2026-04-01T10:00:00Z",
  "edited": "2026-04-06T14:00:00Z",
  "tags": ["phishing", "tier1", "production"],
  "triggers": [...],
  "actions": [...],
  "branches": [...]
}
```

### 5.3 Workflow changelog convention

Add to workflow description:

```text
## Changelog

v1.3 (2026-04-06): Added AbuseIPDB fallback when VT rate limited
v1.2 (2026-03-15): Fixed Splunk webhook parsing for new result format
v1.1 (2026-02-20): Added Slack notification for MALICIOUS verdicts
v1.0 (2026-02-01): Initial deployment
```

---

## Section 6: Monitoring Shuffle Health

### 6.1 Key metrics to monitor

```console
# Check execution queue depth (long queue = workers can't keep up)
curl -s http://localhost:5001/api/v1/workflows/executions/stats | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Queue: {d.get(\"queue_depth\", 0)}')"

# Check worker health
docker stats shuffle-orborus --no-stream --format "table {{.CPUPerc}}\t{{.MemUsage}}"

# Check OpenSearch cluster health
curl -s http://localhost:9201/_cluster/health | python3 -m json.tool
```

### 6.2 Log analysis

```console
# Watch for execution errors
docker logs shuffle-backend -f | grep -i "error\|fail\|exception"

# Count executions per minute
docker logs shuffle-backend --since 1h | grep "execution" | wc -l
```

---

## Troubleshooting Decision Tree

```text
Workflow not triggering?
    │
    ├── Check: Is the trigger active? (Shuffle UI → Triggers → enabled?)
    ├── Check: Is the webhook URL correct?
    └── Test: Send manual curl to webhook URL

Action failing?
    │
    ├── Check: App authentication valid? (Apps → Test Auth)
    ├── Check: Network connectivity? (Shuffle to tool)
    └── Check: Response format changed? (Update Python parsing)

Execution stuck?
    │
    ├── Check: Worker running? (docker ps → shuffle-orborus)
    ├── Check: OpenSearch healthy? (curl :9201/_cluster/health)
    └── Restart: docker compose restart shuffle-orborus
```

---

## Summary

You have learned to:

* Deploy Shuffle with production-ready configuration
* Authenticate all major security tool apps
* Extract and manipulate data between workflow actions using JSONPath and Python
* Implement error handling and graceful degradation
* Version-control workflows using Git
* Monitor Shuffle health and diagnose issues

**Next**: Intermediate Drill 01 challenges you to implement a complete SOAR automation for a new use case.
