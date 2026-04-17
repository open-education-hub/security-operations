# Guide 04 (Intermediate): Advanced Correlation with Time Windows and Sequences

**Level:** Intermediate

**Estimated time:** 45 minutes

**Goal:** Build multi-stage sequence correlation rules and implement behavioral baseline detection

---

## Beyond Threshold: Why Sequences Matter

Threshold rules detect volume anomalies.
But many attacks don't produce high volumes — they produce **specific sequences of actions**:

1. Attacker bruteforces credentials → enters the network quietly
1. Runs discovery commands (`whoami`, `net group`, `arp -a`)
1. Identifies a lateral movement target
1. Connects to target via SMB
1. Deploys payload

No single step triggers a threshold alert.
The attacker is moving slowly and carefully.
Only by **correlating across multiple events in sequence** can you detect the full picture.

---

## Sequence Rule Architecture

A sequence rule needs:

1. **Step definitions** — what events constitute each step
1. **Binding field** — what ties all steps together (e.g., `host.name`, `user.name`)
1. **Time constraint** — maximum time from step 1 to step N
1. **Optional ordering** — do steps have to happen in order?

---

## Example 1: Brute Force Leading to Success (2-step sequence)

### Plain English
> "If a source IP generates 5+ failed logins for a user, then that same IP successfully authenticates as that user within 10 minutes — alert on 'Brute Force Succeeded'."

### SPL Implementation (Splunk Transaction)

```splunk
index=security sourcetype=WinEventLog:Security EventCode IN (4625, 4624)
| eval event_stage = case(EventCode == 4625, "failure", EventCode == 4624, "success", true(), "unknown")
| transaction TargetUserName IpAddress
              startswith="event_stage=failure"
              endswith="event_stage=success"
              maxspan=10m
              maxpause=2m
| where eventcount >= 6
| eval
    fail_count = eventcount - 1,
    alert_name = "Brute Force Login Succeeded",
    severity = "critical",
    mitre = "T1110"
| table _time, TargetUserName, IpAddress, fail_count, duration, alert_name, severity
```

### Elasticsearch EQL (Event Query Language)

```json
GET security-*/_eql/search
{
  "query": """
    sequence by source.ip, user.name with maxspan=10m
      [authentication where event.outcome == "failure"] with runs=5
      [authentication where event.outcome == "success"]
  """,
  "filter": {
    "range": { "@timestamp": { "gte": "now-24h" } }
  }
}
```

EQL's `with runs=5` means "the first event must occur at least 5 times before the sequence continues".

---

## Example 2: Reconnaissance → Lateral Movement Sequence (3-step)

### Detection Logic

```text
Step 1: Discovery commands executed on host A
  (net.exe, whoami.exe, arp.exe, ipconfig.exe, nltest.exe)

Step 2: Outbound SMB connection from host A to host B
  (within 5 minutes of Step 1)

Step 3: Successful authentication on host B from host A's IP
  (within 5 minutes of Step 2)

BINDING: host A (source host for steps 1+2, source IP for step 3)
WINDOW: 15 minutes total
```

### SPL Implementation

```splunk
/* Step 1: Find discovery tool executions */
index=security sourcetype=WinEventLog:Sysmon EventCode=1
  [| search process_name IN ("net.exe","net1.exe","whoami.exe","arp.exe","ipconfig.exe","nltest.exe","dsquery.exe")]
| rename ComputerName AS pivot_host
| bucket _time span=15m
| stats
    values(process_name) AS discovery_tools
    count AS discovery_count
    BY _time, pivot_host, user
| where discovery_count >= 3

/* Join with Step 2: Outbound SMB from same host */
| join type=inner pivot_host [
    search index=security sourcetype=firewall_logs dest_port=445 action=allow
    | rename src_host AS pivot_host
    | stats
        values(dest_ip) AS smb_targets
        count AS smb_count
        BY pivot_host
    | where smb_count >= 1
  ]

/* Join with Step 3: Successful auth on SMB target */
| join type=inner smb_targets [
    search index=security sourcetype=WinEventLog:Security EventCode=4624 LogonType=3
    | eval combo = IpAddress + ":" + TargetComputerName
    | stats count BY combo, IpAddress, TargetComputerName
    | rename TargetComputerName AS smb_targets, IpAddress AS lateral_src
  ]

| eval
    alert_name = "Suspected Lateral Movement - Recon + SMB + Auth Chain",
    severity = "high",
    mitre_tactics = "Discovery → Lateral Movement"
| table _time, pivot_host, user, discovery_tools, smb_targets, lateral_src, alert_name, severity
```

### EQL Implementation

```json
GET security-*/_eql/search
{
  "query": """
    sequence by host.name with maxspan=15m
      [process where process.name in ("net.exe", "whoami.exe", "arp.exe", "ipconfig.exe", "nltest.exe")] with runs=3
      [network where network.transport == "tcp" and destination.port == 445 and network.direction == "outbound"]
      [authentication where event.outcome == "success" and network.type == "remote"]
  """
}
```

---

## Example 3: Impossible Travel Detection (Behavioral)

### Logic

If user X authenticates from Country A, then authenticates from Country B within N hours, and the physical distance cannot be covered in that time — this is suspicious.

```text
max_travel_time_hours = distance_km / 900   (assuming fastest commercial flight)
If (time_diff_hours < max_travel_time_hours) AND (locations are different) → ALERT
```

### SPL Implementation

```splunk
index=security sourcetype=WinEventLog:Security EventCode=4624
| eval country = lower(src_country)  /* GeoIP enriched field */
| sort user, _time
| streamstats
    last(_time) AS prev_time
    last(country) AS prev_country
    last(IpAddress) AS prev_ip
    by user
| eval
    time_diff_hours = round((_time - prev_time) / 3600, 1),
    location_changed = if(country != prev_country AND country != "" AND prev_country != "", 1, 0)
| where location_changed = 1 AND time_diff_hours < 6  /* Less than 6 hours between countries */
| where user != prev_ip  /* Sanity check */
| eval
    alert_name = "Impossible Travel Detected",
    details = user + " logged in from " + prev_country + " then " + country + " in " + time_diff_hours + " hours",
    severity = if(time_diff_hours < 1, "critical", "high")
| table _time, user, prev_country, country, prev_ip, IpAddress, time_diff_hours, alert_name, severity
```

---

## Example 4: Data Exfiltration Baseline Deviation

### Logic

Compare current day's outbound data transfer for a user/host to the 30-day rolling average.
Alert if current transfer is more than 3 standard deviations above normal.

### SPL Implementation

```splunk
/* Step 1: Compute 30-day baseline */
index=network sourcetype=netflow
  earliest=-31d latest=-1d
| eval transfer_mb = round(bytes_out / 1048576, 2)
| bucket _time span=1d
| stats sum(transfer_mb) AS daily_mb BY _time, src_ip
| stats
    avg(daily_mb) AS avg_daily_mb
    stdev(daily_mb) AS stdev_daily_mb
    BY src_ip

/* Step 2: Get today's transfer */
| join type=inner src_ip [
    search index=network sourcetype=netflow earliest=-24h
    | eval transfer_mb = round(bytes_out / 1048576, 2)
    | stats sum(transfer_mb) AS today_mb BY src_ip
  ]

/* Step 3: Compute z-score */
| eval
    z_score = if(stdev_daily_mb > 0, round((today_mb - avg_daily_mb) / stdev_daily_mb, 2), 0),
    threshold = avg_daily_mb + (3 * stdev_daily_mb)

/* Step 4: Alert on statistical anomalies */
| where today_mb > threshold AND z_score > 3
| eval
    alert_name = "Unusual Outbound Data Transfer Volume",
    severity = case(z_score > 10, "critical", z_score > 5, "high", true(), "medium"),
    details = "Today: " + today_mb + " MB vs avg: " + round(avg_daily_mb, 1) + " MB (z=" + z_score + ")"
| table src_ip, today_mb, avg_daily_mb, z_score, threshold, alert_name, severity, details
| sort -z_score
```

---

## YARA-L Sequence Rule (Google Chronicle)

YARA-L is particularly elegant for sequence detection:

```yara-l
rule lateral_movement_recon_to_auth {
  meta:
    author = "SOC Team"
    description = "Recon commands followed by successful remote authentication"
    severity = "HIGH"
    mitre_attack_technique = "T1021"

  events:
    $recon.metadata.event_type = "PROCESS_LAUNCH"
    $recon.principal.hostname = $pivot_host
    $recon.target.process.file.full_path = /(?i)(net\.exe|whoami\.exe|ipconfig\.exe|nltest\.exe)$/

    $auth.metadata.event_type = "USER_LOGIN"
    $auth.security_result.action = "ALLOW"
    $auth.principal.hostname != $pivot_host    /* Different host */
    $auth.principal.ip = $recon.principal.ip   /* Same IP */

  match:
    $pivot_host over 15m

  condition:
    #recon >= 3 and $auth
}
```

---

## Key Considerations for Sequence Rules

### State Management

Sequence rules require tracking partial sequences in memory or a database:

```text
Pending sequences cache:
{
  "key": "10.0.1.5:jdoe",           // binding field values
  "steps_completed": 1,             // how far along the sequence
  "step1_time": 1734161121,         // timestamp of step 1
  "step1_data": {...},              // data from step 1 for the alert
  "expires_at": 1734161121 + 900   // TTL: step1_time + max window
}
```

### Late-Arriving Events

Network delays and log buffering mean step 3 might arrive before step 2.
Your correlation engine must handle this:

* **Wait mode**: Buffer events and wait for out-of-order arrivals (increases latency)
* **Reorder mode**: Process in event time order (requires watermarks)
* **Replay mode**: Periodically re-run rules against historical data

### Binding Field Selection

Choose binding fields carefully:

* `host.name` — ties events on the same machine
* `user.name` — ties events from the same user account
* `source.ip` — ties events from the same IP (risk: NAT/proxy)
* `network.community_id` — ties events for the same network connection

---

## Checkpoint Questions

1. What is the "binding field" in a sequence rule and why is it critical?
1. In the EQL brute force example, what does `with runs=5` mean?
1. Why might using `source.ip` as a binding field be problematic in environments with NAT or shared proxies?
1. In the z-score exfiltration rule, why use a 30-day baseline rather than just yesterday's data?
1. What is the difference between a sliding window and a session window? Give a use case for each.
