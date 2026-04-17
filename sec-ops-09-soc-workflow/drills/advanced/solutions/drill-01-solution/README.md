# Solution: Drill 01 — Full SOAR Integration

## Part A: Architecture Design

### Integration Architecture

```text
Elasticsearch Watcher
  ├── Condition: ransomware indicators (shadow copy delete, mass rename)
  └── Action: HTTP POST to Shuffle webhook URL
              {host, process, files_affected, alert_id, timestamp}
                        │
                        ▼
              Shuffle SOAR (webhook listener)
                        │
            ┌───────────┼───────────┐
            │           │           │
            ▼           ▼           ▼
       TheHive       CrowdStrike   Cortex
      Create P1       Get Host     Enrich
        Case          by Name      hash/IP
            │           │           │
            └───────────┴───────────┘
                        │
                   Aggregate results
                        │
                   Slack notification
                        │
              If CrowdStrike failed → PagerDuty
```

### Authentication

* API keys stored in Shuffle's **credential vault** (never in playbook YAML)
* Each integration uses a dedicated service account (principle of least privilege)
* CrowdStrike: OAuth2 client credentials (client_id + client_secret → bearer token)
* TheHive: API key in Authorization header
* Slack: Webhook URL (secret) stored in Shuffle credentials

### Failure Handling

If CrowdStrike API is unavailable:

1. Log the failure in the case notes
1. Set case tag `isolation-failed`
1. Page on-call engineer via PagerDuty
1. Analyst must manually isolate within 10 minutes (escalation procedure)

---

## Part B: Playbook Implementation (Pseudocode)

```yaml
name: "Ransomware P1 Response"
version: "1.0"

trigger:
  type: webhook
  method: POST

step_1:
  name: "Parse Alert"
  action: parse_json
  input: $trigger.body
  output: hostname, process_name, affected_files, alert_timestamp

step_2_parallel_a:
  name: "Create TheHive Case"
  action: thehive.create_case
  input:
    title: "RANSOMWARE SUSPECTED — {hostname} — {alert_timestamp}"
    severity: critical
    description: |
      Source process: {process_name}
      Affected files (sample): {affected_files[0:10]}
      Alert generated: {alert_timestamp}
    tags: ["ransomware", "p1", "auto-created"]
    status: open
  output: case_id

step_2_parallel_b:
  name: "Get CrowdStrike Host ID"
  action: http_request
  method: GET
  url: "https://api.crowdstrike.com/devices/queries/devices/v1?filter=hostname:'{hostname}'"
  headers:
    Authorization: "Bearer {cs_token}"
  output: device_id

step_3:
  name: "Isolate Host"
  action: http_request
  method: POST
  url: "https://api.crowdstrike.com/devices/actions/v2?action_name=contain"
  headers:
    Authorization: "Bearer {cs_token}"
    Content-Type: "application/json"
  body: '{"ids": ["{device_id}"]}'
  on_failure: goto step_5_failure_notify
  output: isolation_status

step_4:
  name: "Add Isolation Note to TheHive"
  action: thehive.add_task_log
  input:
    case_id: case_id
    message: "Host {hostname} isolated in CrowdStrike at {current_time}. Device ID: {device_id}"

step_5:
  name: "Notify Slack"
  action: slack.send_message
  input:
    channel: "#soc-critical"
    message: |
      🚨 *RANSOMWARE ALERT — P1*
      Host: {hostname}
      Process: {process_name}
      TheHive Case: https://thehive/cases/{case_id}
      CrowdStrike Isolation: SUCCESS
      Time: {alert_timestamp}

step_5_failure_notify:
  name: "Notify Failure and Page On-Call"
  action: parallel
  actions:
    - slack.send_message:
        channel: "#soc-critical"
        message: "⚠️ ISOLATION FAILED for {hostname} — MANUAL ACTION REQUIRED. TheHive: {case_id}"
    - pagerduty.trigger_incident:
        title: "Host isolation failed: {hostname}"
        severity: critical
        details: "CrowdStrike API unavailable or device not found"
```

---

## Part C: Test Plan

### Test Input Data

```json
{
  "hostname": "test-vm-ransomware-01",
  "process_name": "vssadmin.exe",
  "affected_files": [
    "C:\\Users\\test\\Documents\\budget.xlsx",
    "C:\\Users\\test\\Documents\\budget.xlsx.ENCRYPTED"
  ],
  "alert_timestamp": "2024-11-14T10:00:00Z",
  "alert_id": "TEST-001"
}
```

### Expected Outputs at Each Step

| Step | Expected Output |
|------|----------------|
| Parse Alert | hostname="test-vm-ransomware-01", process="vssadmin.exe" |
| TheHive Case | Case created, ID returned (e.g., ~abc123) |
| CrowdStrike Host Lookup | Device ID returned from mock |
| Isolation | HTTP 200 from mock with `{"resources": ["success"]}` |
| Slack | Message visible in mock endpoint logs |

### Testing Isolation Without Real Host

Use the Docker mock environment:

* The CrowdStrike mock API returns "success" for hostname `test-vm-ransomware-01`
* It returns a 503 error for hostname `test-vm-fail-01` (to test failure path)
* Never test against production CrowdStrike — use dedicated test tenant or sandbox

### Testing Failure Handling

Send request with hostname `test-vm-fail-01`:

* Expect: TheHive case created, Slack failure message, PagerDuty incident created

---

## Part D: Operational Considerations

### 1. Blast Radius

**Risks:**

* Isolating the wrong host (typo in hostname, hostname collision)
* Isolating a critical server that happens to trigger ransomware indicators (e.g., backup software doing mass file operations)
* SOAR service outage silently drops alerts

**Mitigations:**

* Whitelist critical servers (domain controllers, backup servers) from automatic isolation
* Add a 30-second check after isolation to verify it was successful
* Add SOAR health monitoring (alert if no playbooks run in X hours during business hours)

### 2. Kill Switch

Add a global variable in Shuffle: `RANSOMWARE_PLAYBOOK_ENABLED = true`.
Wrap all destructive steps with: `if RANSOMWARE_PLAYBOOK_ENABLED != true: skip`.
Changing this variable disables isolation globally without modifying the playbook.

### 3. Silent Failure Monitoring

* Alert if no ransomware playbook has run in 24 hours (may indicate trigger issue)
* Alert if playbook takes > 120 seconds (indicates API timeout/slowness)
* Alert if TheHive case creation step consistently fails

### 4. Human Approval for Isolation?

**Recommendation: No approval required for ransomware P1.**

Ransomware encrypts files at a rate of thousands per minute.
A 2-minute delay waiting for analyst approval could mean thousands of additional files encrypted.
The blast radius of incorrect isolation (temporarily cutting off a host from the network) is far lower than the blast radius of uncontained ransomware spreading to other systems.
However, the whitelist of critical servers must be rigorously maintained to avoid catastrophic false positives.
