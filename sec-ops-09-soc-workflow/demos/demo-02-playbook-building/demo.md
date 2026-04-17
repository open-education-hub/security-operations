# Demo 02: Building a Phishing Response Playbook in Shuffle

**Duration**: ~45 minutes

**Level**: Intermediate

**Prerequisites**: Demo 01 completed; Shuffle running (see Demo 03 for setup)

---

## Overview

In this demo you will build a complete phishing email response playbook in Shuffle SOAR from scratch.
The playbook will:

1. Receive a phishing alert via webhook
1. Extract and enrich IOCs (URL + domain)
1. Calculate a maliciousness score
1. Conditionally quarantine the email
1. Create a case in TheHive
1. Send a Slack notification to the SOC channel

**Tools used**: Shuffle SOAR, VirusTotal API (free tier), TheHive, Slack webhook

---

## Environment Setup

Ensure the following services are running (use Demo 03's `docker-compose.yml`):

```console
# Verify services are up
docker-compose ps

# Expected output:
# shuffle-frontend   Up   0.0.0.0:3001->80/tcp
# shuffle-backend    Up   0.0.0.0:5001->5001/tcp
# shuffle-opensearch Up   9200/tcp
# thehive            Up   0.0.0.0:9000->9000/tcp
```

Access Shuffle at: `http://localhost:3001`
Default credentials: admin / password (change on first login)

---

## Step 1: Configure App Integrations

Before building the workflow, configure the tools Shuffle will connect to.

### 1a. Configure VirusTotal App

1. In Shuffle, navigate to **Apps** → search "VirusTotal"
1. Click **VirusTotal** → **Authenticate**
1. Enter:
   * **Label**: `virustotal-prod`
   * **API Key**: `<your-VT-free-api-key>`
1. Click **Save**

> Free VirusTotal API: 4 requests/minute, 500/day. Sufficient for lab use.

### 1b. Configure TheHive App

1. Navigate to **Apps** → search "TheHive"
1. Click **TheHive** → **Authenticate**
1. Enter:
   * **Label**: `thehive-local`
   * **URL**: `http://thehive:9000`
   * **API Key**: `<your-thehive-api-key>`

> Get TheHive API key: Login → Profile → API Key → Create

### 1c. Configure HTTP App (for AbuseIPDB)

The HTTP App allows direct REST API calls to any tool.

1. Navigate to **Apps** → search "HTTP"
1. The HTTP app requires no authentication at the app level — credentials are passed per-action.

---

## Step 2: Create the Phishing Response Workflow

### 2a. Create New Workflow

1. Navigate to **Workflows** → **+ New Workflow**
1. Name: `Phishing Email Response v1`
1. Description: `Automated phishing triage: enrich, score, quarantine, ticket`
1. Click **Create**

### 2b. Add Webhook Trigger

1. In the workflow editor, click **+** to add a trigger
1. Select **Webhook**
1. Configure:
   * **Name**: `phishing_alert_trigger`
   * **Description**: Receives phishing alerts from SIEM
1. Note the webhook URL displayed: `http://shuffle-backend:5001/api/v1/hooks/webhook_<id>`
1. Click **Save Trigger**

**Test the trigger** (from terminal):

```bash
curl -X POST http://localhost:5001/api/v1/hooks/webhook_<your-id> \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-001",
    "sender": "attacker@evil-domain.xyz",
    "recipient": "alice@company.com",
    "subject": "Urgent: Account Suspended",
    "urls": ["http://evil-domain.xyz/login"],
    "timestamp": "2026-04-06T14:32:11Z"
  }'
```

### 2c. Add Action: VirusTotal URL Check

1. Click **+** to add action after the trigger
1. Select **App**: VirusTotal
1. Select **Action**: `Get URL report`
1. Configure:
   * **Name**: `vt_url_check`
   * **URL**: `$exec.urls[0]`

   (This reads the first URL from the trigger data)

1. Click **Save**

**Understanding variable syntax**:

* `$exec` = the trigger execution data
* `$exec.urls[0]` = first URL in the urls array
* `$exec.sender` = the sender field from trigger

### 2d. Add Action: AbuseIPDB Domain Check (HTTP)

1. Add action → **App**: HTTP
1. Select **Action**: `GET`
1. Configure:
   * **Name**: `abuseipdb_check`
   * **URL**: `https://api.abuseipdb.com/api/v2/check`
   * **Headers**:

     ```text
     Key: Key
     Value: <your-abuseipdb-api-key>
```

   * **Query Parameters**:

     ```text
     ipAddress: $exec.sender_ip
     maxAgeInDays: 90
```

1. Click **Save**

> Note: If you don't have AbuseIPDB key, skip this action and rely on VT only.

### 2e. Add Action: Calculate Risk Score (Python)

Shuffle supports inline Python scripts using the "Shuffle Tools" app.

1. Add action → **App**: Shuffle Tools
1. Select **Action**: `Run Python`
1. Configure:
   * **Name**: `calculate_score`
   * **Script**:

```python
import json

# Get VirusTotal results
vt_output = "$vt_url_check"
vt_data = json.loads(vt_output) if isinstance(vt_output, str) else vt_output

# Extract malicious count
malicious = 0
try:
    stats = vt_data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    vt_score = int((malicious / max(total, 1)) * 100)
except (KeyError, TypeError):
    vt_score = 0

# Score thresholds
if vt_score >= 50:
    verdict = "MALICIOUS"
    ticket_severity = "High"
    action = "quarantine_and_block"
elif vt_score >= 20:
    verdict = "SUSPICIOUS"
    ticket_severity = "Medium"
    action = "quarantine_and_review"
else:
    verdict = "CLEAN"
    ticket_severity = "Low"
    action = "log_and_close"

result = {
    "vt_score": vt_score,
    "malicious_detections": malicious,
    "verdict": verdict,
    "ticket_severity": ticket_severity,
    "action": action
}

return json.dumps(result)
```

### 2f. Add Condition: Branch on Verdict

1. Add **Condition** node after `calculate_score`
1. Configure condition:
   * **Value 1**: `$calculate_score.verdict`
   * **Operator**: `Equals`
   * **Value 2**: `MALICIOUS`
1. This creates two branches: `True` (malicious) and `False` (clean/suspicious)

### 2g. Add Action: TheHive Create Alert (both branches)

**For True branch (Malicious)**:

1. Add action → **App**: TheHive
1. Select **Action**: `Create Alert`
1. Configure:
   * **Name**: `thehive_create_alert_malicious`
   * **Title**: `Phishing: $exec.sender - MALICIOUS`
   * **Description**:

     ```text
     Automated phishing detection.
     Sender: $exec.sender
     Recipient: $exec.recipient
     URL: $exec.urls[0]
     VT Score: $calculate_score.vt_score%
     Verdict: MALICIOUS - Email quarantined automatically
```

   * **Severity**: `3` (High)
   * **Tags**: `["phishing", "auto-quarantine", "soar"]`
   * **Type**: `external`
   * **Source**: `shuffle-soar`

**For False branch (Suspicious/Clean)**:

* Same configuration but Severity: `2` (Medium) and adjust description

### 2h. Add Action: Slack Notification

1. Add action → **App**: HTTP
1. Configure Slack webhook notification:
   * **URL**: `https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK`
   * **Method**: POST
   * **Body**:

```json
{
  "text": "🚨 *Phishing Alert* - $calculate_score.verdict\n*Sender:* $exec.sender\n*Recipient:* $exec.recipient\n*VT Score:* $calculate_score.vt_score%\n*Action:* $calculate_score.action\n*TheHive Alert:* $thehive_create_alert_malicious.id"
}
```

---

## Step 3: Test the Complete Workflow

### 3a. Manual Test with Sample Data

1. In Shuffle workflow editor, click **Run** (▶ button)
1. Select **Run with test data**
1. Enter test payload:

```json
{
  "alert_id": "SPL-TEST-001",
  "sender": "phishing@evil-malware-test.com",
  "sender_ip": "185.220.101.50",
  "recipient": "alice@company.com",
  "subject": "URGENT: Your password has expired",
  "urls": ["http://evil-malware-test.com/steal-creds"],
  "attachment_hash": "",
  "timestamp": "2026-04-06T14:32:11Z"
}
```

1. Watch execution in real-time in the **Execution** panel
1. Verify each action completes successfully (green checkmark)

### 3b. Verify Results in TheHive

1. Open TheHive at `http://localhost:9000`
1. Navigate to **Alerts**
1. Verify new alert was created with:
   * Title containing "MALICIOUS"
   * Severity: High
   * Tags: phishing, auto-quarantine, soar
   * Description with enrichment data

### 3c. Check Execution Logs

```console
# View Shuffle backend logs
docker logs shuffle-backend --tail 50

# View worker logs
docker logs shuffle-worker --tail 50
```

---

## Step 4: Enrich the Playbook — Add Email Headers Check

**Challenge**: Extend the playbook to also check if the email passes SPF/DKIM/DMARC.

Add a Python action to parse the email authentication results:

```python
# Action: parse_email_auth
import json

# Simulated email header check (in production, parse actual email headers)
# These would come from your email security gateway API
sender = "$exec.sender"
sender_domain = sender.split("@")[-1] if "@" in sender else sender

# Simulate SPF/DKIM results (replace with real API calls in production)
auth_results = {
    "sender_domain": sender_domain,
    "spf": "fail",      # pass/fail/softfail/none
    "dkim": "none",     # pass/fail/none
    "dmarc": "fail",    # pass/fail/none
    "auth_score": 0     # 0 = all fail, 100 = all pass
}

# Calculate auth score
passing = sum([
    auth_results["spf"] == "pass",
    auth_results["dkim"] == "pass",
    auth_results["dmarc"] == "pass"
])
auth_results["auth_score"] = int(passing / 3 * 100)

# High risk if all 3 fail
auth_results["auth_risk"] = "HIGH" if auth_results["auth_score"] == 0 else "LOW"

return json.dumps(auth_results)
```

Then incorporate `auth_risk` into the final scoring:

```python
# In calculate_score, combine VT score with auth risk
combined_score = vt_score
if "$parse_email_auth.auth_risk" == "HIGH":
    combined_score = min(100, combined_score + 25)  # Boost score if auth fails
```

---

## Step 5: Export the Workflow

Export your completed workflow for sharing and version control:

1. In Shuffle, navigate to your workflow
1. Click **...** → **Export Workflow**
1. Save as `phishing-response-playbook-v1.json`

**Workflow JSON structure** (simplified):

```json
{
  "name": "Phishing Email Response v1",
  "description": "Automated phishing triage",
  "triggers": [
    {
      "type": "webhook",
      "name": "phishing_alert_trigger"
    }
  ],
  "actions": [
    {
      "name": "vt_url_check",
      "app_name": "VirusTotal",
      "action": "get_url_report",
      "parameters": {"url": "$exec.urls[0]"}
    },
    {
      "name": "calculate_score",
      "app_name": "Shuffle Tools",
      "action": "run_python",
      "parameters": {"code": "..."}
    }
  ],
  "conditions": [...]
}
```

---

## Workflow Diagram (Final State)

```text
[Webhook Trigger: phishing_alert_trigger]
                │
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
[VT URL    [AbuseIPDB  [Parse Email
 Check]     Check]      Auth Headers]
    │           │           │
    └───────────┴───────────┘
                │
                ▼
    [Calculate Risk Score (Python)]
                │
         ┌──────┴──────┐
      MALICIOUS     SUSPICIOUS/CLEAN
         │               │
         ▼               ▼
  [TheHive Alert  [TheHive Alert
   SEV: High]      SEV: Medium]
         │               │
         └───────┬────── ┘
                 │
                 ▼
         [Slack Notification]
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Webhook not receiving data | Check Shuffle backend is running; verify webhook URL is correct |
| VirusTotal 429 error | Rate limit hit (free tier). Add `wait` action with 15s delay |
| TheHive connection refused | Verify TheHive container is running: `docker ps` |
| Python action fails | Check Python syntax; use `return json.dumps(result)` not `print()` |
| No Slack notification | Verify Slack webhook URL is valid; test with `curl` |

---

## Summary

You have built a production-quality phishing response playbook that:

* Receives alerts via webhook from any SIEM
* Enriches IOCs using VirusTotal and AbuseIPDB APIs
* Calculates a risk score using inline Python
* Creates structured cases in TheHive
* Notifies the SOC team via Slack
* Runs in ~12 seconds vs. ~19 minutes manually

**Next steps**: Demo 03 covers the full Shuffle setup and connecting to Splunk as the SIEM source.
