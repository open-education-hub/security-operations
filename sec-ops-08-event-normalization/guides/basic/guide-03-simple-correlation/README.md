# Guide 03: Writing a Simple Multi-Event Correlation Rule

**Level:** Basic

**Estimated time:** 30 minutes

**Goal:** Write and understand your first multi-event (threshold-based) correlation rules

---

## From Single Events to Correlation

A single failed login attempt is noise.
Ten failed login attempts from the same IP in 2 minutes is a brute force attack.
The difference is **correlation** — combining multiple events in time to detect a pattern.

```text
Event stream (raw):
10:00:01 - 203.0.113.42 → WORKSTATION01 - auth failure
10:00:03 - 203.0.113.42 → WORKSTATION01 - auth failure
10:00:05 - 203.0.113.42 → WORKSTATION01 - auth failure
...
10:01:45 - 203.0.113.42 → WORKSTATION01 - auth failure (12th)

Single-event view: "yet another failed login"
Correlated view:   "12 failures from same IP in 1m 45s → BRUTE FORCE ALERT"
```

---

## Anatomy of a Threshold Rule

A threshold (aggregation) rule has four key components:

```text
WHEN   [matching condition]      ← which events to count
GROUP  BY [grouping fields]      ← how to group them
COUNT  > [threshold]             ← how many triggers the alert
WITHIN [time window]             ← the time period to count over
```

---

## Example 1: Brute Force SSH Detection

### In Plain English
> "If the same source IP produces more than 10 failed SSH authentication events within 5 minutes, fire an alert."

### In SPL (Splunk)

```splunk
index=security sourcetype=linux_secure "Failed password"
| eval time_bucket = floor(_time/300)*300  /* 300s = 5 min buckets */
| stats count AS failure_count BY time_bucket, src_ip, host
| where failure_count > 10
| eval
    _time = time_bucket,
    alert_name = "SSH Brute Force Attempt",
    severity = if(failure_count > 50, "critical", "high")
| fields - time_bucket
| table _time, host, src_ip, failure_count, severity, alert_name
| sort -failure_count
```

### In Elasticsearch Query (Kibana Dev Tools)

```json
GET security-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term":  { "event.category": "authentication" } },
        { "term":  { "event.outcome": "failure" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "source.ip", "size": 20 },
      "aggs": {
        "per_5min_window": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "5m"
          },
          "aggs": {
            "failure_count": { "value_count": { "field": "@timestamp" } },
            "alert_filter": {
              "bucket_selector": {
                "buckets_path": { "count": "failure_count" },
                "script": "params.count > 10"
              }
            }
          }
        }
      }
    }
  }
}
```

### In Sigma YAML

```yaml
title: SSH Brute Force - Multiple Failed Login Attempts
id: a1a2a3a4-b5b6-c7c8-d9d0-e1e2e3e4e5e6
status: stable
description: Detects brute force SSH login attempts from a single source IP
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: auth
detection:
  selection:
    process.name: sshd
    event.outcome: failure
  timeframe: 5m
  condition: selection | count() by source.ip > 10
level: medium
falsepositives:
  - Automated deployment tools
  - Password managers with cached credentials
```

---

## Example 2: Account Lockout Storm Detection

### In Plain English
> "If more than 5 distinct user accounts are locked out within 10 minutes — likely a credential spray attack."

### In SPL

```splunk
index=security sourcetype=WinEventLog:Security EventCode=4740
| bucket _time span=10m
| stats dc(TargetUserName) AS locked_accounts, values(TargetUserName) AS accounts BY _time
| where locked_accounts > 5
| eval alert_name = "Account Lockout Storm - Possible Credential Spray"
| table _time, locked_accounts, accounts, alert_name
```

---

## Example 3: Detecting After-Hours Administrative Access

### In Plain English
> "Alert when any privileged user (domain admin) authenticates successfully outside business hours (before 7AM or after 8PM weekdays, or any time on weekends)."

### In SPL

```splunk
index=security sourcetype=WinEventLog:Security EventCode=4624
| lookup privileged_accounts username AS TargetUserName OUTPUT is_privileged
| where is_privileged = "true"
| eval
    hour_of_day = tonumber(strftime(_time, "%H")),
    day_of_week = strftime(_time, "%u")   /* 1=Mon...7=Sun */
| where hour_of_day < 7 OR hour_of_day >= 20 OR day_of_week IN ("6", "7")
| eval
    alert_name = "Privileged Login Outside Business Hours",
    severity = "high"
| table _time, TargetUserName, IpAddress, ComputerName, alert_name, severity
```

---

## Understanding Time Windows

### Tumbling Window

Fixed, non-overlapping intervals.
Events are counted per interval only.

```text
|---5min---|---5min---|---5min---|
 Events: 3   Events: 12  Events: 4
               ↑ ALERT (>10)
```

**Best for:** Regular interval reporting, compliance metrics.

### Sliding Window

The window moves forward with each new event.
More responsive but more computationally expensive.

```text
t=0:      [----5min----] count=3
t=0:30:   [  --5min--  ] count=8
t=1:00:         [5min  ] count=12  ← ALERT fires here
t=1:30:              [5m] count=9
```

**Best for:** Real-time detection where immediate response is needed.

### Session Window

The window extends as long as events keep arriving, closing after a "gap" timeout.

```text
Events: .  .  .  .      ...  .  .  .
        |---session---|  |-session-|
           gap timeout
```

**Best for:** Detecting attack campaigns that have pauses (attacker goes quiet for a while, then resumes).

---

## Adding Context to the Alert

A raw alert with just "12 auth failures from 203.0.113.42" isn't actionable.
Enrich the alert:

```splunk
index=security sourcetype=linux_secure "Failed password"
| eval time_bucket = floor(_time/300)*300
| stats
    count AS failure_count,
    dc(host) AS targeted_systems,
    values(host) AS target_hosts,
    values(user) AS targeted_users
    BY time_bucket, src_ip
| where failure_count > 10
/* Add GeoIP context via a lookup */
| lookup geoip_db ip AS src_ip OUTPUT country_name AS src_country, city_name AS src_city
/* Add threat intel context */
| lookup threat_intel ip AS src_ip OUTPUT malicious AS is_known_bad, threat_category
| eval
    severity = case(
        is_known_bad = "true", "critical",
        failure_count > 50, "high",
        true(), "medium"),
    alert_name = "SSH Brute Force from " + src_country
| table _time, src_ip, src_country, src_city, failure_count,
        targeted_systems, target_hosts, targeted_users,
        is_known_bad, threat_category, severity, alert_name
```

---

## Testing Your Rule

Before deploying, test with synthetic data:

### Test Case 1: Rule Should Fire

Create 11+ events with the same `src_ip` within 5 minutes:

```python
# generate_test_events.py
import datetime

base_time = datetime.datetime(2024, 12, 14, 7, 40, 0)
src_ip = "10.99.99.99"

for i in range(12):
    ts = base_time + datetime.timedelta(seconds=i*15)
    print(f'{ts.strftime("%b %d %H:%M:%S")} testhost sshd[9999]: Failed password for invalid user testuser from {src_ip} port 5000{i} ssh2')
```

### Test Case 2: Rule Should NOT Fire (below threshold)

Create 5 events from the same IP → verify no alert.

### Test Case 3: Different IPs Should Not Correlate

Create 10 events but from 10 different IPs → verify no alert for any single IP.

---

## Checkpoint Questions

1. What are the four key components of a threshold correlation rule?
1. What is the difference between a tumbling window and a sliding window? Which is more computationally expensive?
1. In the brute force rule, why do we `GROUP BY src_ip` rather than `GROUP BY username`?
1. Why might enriching an alert with GeoIP information be valuable for SOC analysts?
