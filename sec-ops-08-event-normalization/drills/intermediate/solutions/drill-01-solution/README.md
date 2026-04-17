# Drill 01 Solution (Intermediate): Multi-Source Correlation Rules

---

## Scenario 1 Solution: Credential Stuffing

### 1A: Sigma Rule

```yaml
title: Credential Stuffing Attack - Multiple Account Login Failures
id: f7a8b9c0-d1e2-f3a4-b5c6-d7e8f9a0b1c2
status: stable
description: |
  Detects a credential stuffing attack pattern where a single source IP
  attempts authentication against many different user accounts within a
  short time window. Unlike brute force (many attempts on one account),
  credential stuffing targets many accounts with few attempts each,
  typically using breached credential lists.

  Threshold: >20 distinct account targets, >80% failure rate, 10-minute window.
references:
  - https://attack.mitre.org/techniques/T1110/004/
  - https://owasp.org/www-community/attacks/Credential_stuffing
author: SOC Team
date: 2024/12/14
modified: 2024/12/14
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.004
  - attack.initial_access
logsource:
  category: authentication
detection:
  selection:
    event.category: authentication
    event.outcome: failure
  timeframe: 10m
  condition: selection | count(user.name) by source.ip > 20
fields:
  - source.ip
  - user.name
  - host.name
  - event.dataset
falsepositives:
  - LDAP/RADIUS proxy servers that aggregate authentication from many users
  - Password synchronization tools
  - Automated testing frameworks in dev environments
  - Mail servers checking credentials for many users
level: high
```

### 1B: Elasticsearch DSL Query

```json
GET security-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term":  { "event.category": "authentication" } },
        { "term":  { "event.outcome": "failure" } },
        { "range": { "@timestamp": { "gte": "now-10m" } } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": {
        "field": "source.ip",
        "size": 50,
        "min_doc_count": 5
      },
      "aggs": {
        "per_window": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "10m"
          },
          "aggs": {
            "unique_users": {
              "cardinality": { "field": "user.name" }
            },
            "total_failures": {
              "value_count": { "field": "event.outcome" }
            },
            "credential_stuffing_filter": {
              "bucket_selector": {
                "buckets_path": {
                  "users": "unique_users"
                },
                "script": "params.users > 20"
              }
            },
            "sample_users": {
              "terms": {
                "field": "user.name",
                "size": 10
              }
            }
          }
        }
      }
    }
  }
}
```

---

## Scenario 2 Solution: Internal Network Enumeration

### 2A: Sigma Rule

```yaml
title: Internal Network Enumeration from Workstation
id: a0b1c2d3-e4f5-a6b7-c8d9-e0f1a2b3c4d5
status: stable
description: |
  Detects internal network enumeration originating from a workstation (not a
  known server or scanner). Identifies connections to many distinct internal
  hosts on administrative and remote access ports within a 5-minute window.
  This pattern indicates an attacker performing pre-lateral-movement discovery.
references:
  - https://attack.mitre.org/techniques/T1046/
  - https://attack.mitre.org/techniques/T1018/
author: SOC Team
date: 2024/12/14
tags:
  - attack.discovery
  - attack.t1046
  - attack.t1018
  - attack.lateral_movement
logsource:
  category: firewall
  product: generic
detection:
  selection:
    network.direction: internal
    destination.port:
      - 22
      - 445
      - 135
      - 139
      - 3389
      - 5985
      - 5986
      - 4444
      - 9090
  filter_known_scanners:
    source.ip|cidr:
      - '10.0.0.100/32'   # Nessus scanner
      - '10.0.0.101/32'   # SCCM server
  timeframe: 5m
  condition: selection and not filter_known_scanners | count(destination.ip) by source.ip > 15
fields:
  - source.ip
  - destination.ip
  - destination.port
  - host.name
falsepositives:
  - Vulnerability scanners (Nessus, Qualys, OpenVAS) - exclude their IPs
  - Backup agents scanning for targets
  - Asset management tools (SCCM, KACE, Ivanti)
  - IT admins running manual network discovery
level: medium
```

### 2B: SPL Correlation Search

```splunk
/* Scheduled search: run every 5 minutes, last 5 minutes of data */
index=network sourcetype=firewall
  dest_port IN (22, 445, 135, 139, 3389, 5985, 5986)
  NOT src_ip IN ("10.0.0.100", "10.0.0.101")  /* Known scanners */
  /* Internal-to-internal only */
  src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16

| bucket _time span=5m

/* Check dest is also internal */
| where (match(dest_ip, "^10\.") OR match(dest_ip, "^172\.(1[6-9]|2[0-9]|3[01])\.") OR match(dest_ip, "^192\.168\."))

| stats
    dc(dest_ip)   AS unique_dest_hosts
    dc(dest_port) AS unique_dest_ports
    values(dest_port) AS scanned_ports
    count         AS total_connections
    BY _time, src_ip

| where unique_dest_hosts > 15

/* Join with asset DB to check if source is workstation */
| lookup asset_db ip AS src_ip OUTPUT host_type
| where host_type = "workstation" OR isnull(host_type)  /* Alert if unknown or known workstation */

| eval
    alert_name = "Internal Network Enumeration",
    severity = case(unique_dest_hosts > 50, "high", true(), "medium"),
    mitre_techniques = "T1046, T1018"

| table _time, src_ip, host_type, unique_dest_hosts, unique_dest_ports, scanned_ports, alert_name, severity
| sort -unique_dest_hosts
```

---

## Scenario 3 Solution: Staged Data Exfiltration

### 3A: Sigma Rules (Two-Part Approach)

**Rule Part 1: Archive Creation**

```yaml
title: Suspicious Archive Creation - Potential Data Staging
id: b2c3d4e5-f6a7-b8c9-d0e1-f2a3b4c5d6e7
status: stable
description: |
  Detects execution of compression tools that may indicate data staging
  before exfiltration. Should be correlated with subsequent large uploads.
tags:
  - attack.collection
  - attack.t1560
  - attack.t1560.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name|endswith:
      - '7z.exe'
      - '7za.exe'
      - 'WinRAR.exe'
      - 'WinZip32.exe'
      - 'zip.exe'
    process.command_line|contains:
      - ' a '    # archive mode
      - ' -a'    # archive flag
  filter_it_ops:
    user.name|endswith: '$'  # Computer accounts (backup agents)
  condition: selection and not filter_it_ops
falsepositives:
  - IT backup agents
  - Software deployment packages
  - Developers creating release packages
level: low
```

**Rule Part 2: Large Upload to Cloud Storage**

```yaml
title: Large Upload to Cloud Storage / File Sharing Service
id: c3d4e5f6-a7b8-c9d0-e1f2-a3b4c5d6e7f8
status: stable
description: |
  Detects large outbound uploads to known cloud storage or file sharing
  domains. May indicate exfiltration of archived data.
tags:
  - attack.exfiltration
  - attack.t1048
  - attack.t1048.002
logsource:
  category: proxy
  product: generic
detection:
  selection_domain:
    url.domain|endswith:
      - '.dropbox.com'
      - '.mega.nz'
      - '.onedrive.live.com'
      - '.wetransfer.com'
      - '.sendspace.com'
      - '.anonfiles.com'
      - 'gofile.io'
      - 'temp.sh'
  selection_large:
    http.request.bytes|gte: 104857600   # 100 MB
  condition: selection_domain and selection_large
falsepositives:
  - Authorized cloud backup solutions
  - Developers uploading release artifacts
  - Business users backing up work files to approved cloud storage
level: medium
```

### 3B: YARA-L Rule (Bonus)

```yara-l
rule staged_exfiltration_archive_then_upload {
  meta:
    author = "SOC Team"
    description = "Detects archive creation followed by large upload to cloud storage"
    severity = "HIGH"
    mitre_attack_tactic = "Exfiltration"
    mitre_attack_technique = "T1560, T1048"

  events:
    /* Step 1: Archive tool execution */
    $archive.metadata.event_type = "PROCESS_LAUNCH"
    $archive.principal.hostname = $pivot_host
    $archive.target.process.file.full_path = /(?i)(7z\.exe|7za\.exe|WinRAR\.exe|WinZip32\.exe)$/
    $archive.target.process.command_line = /(?i)\s(-a|a)\s/

    /* Step 2: Large upload to cloud storage domain */
    $upload.metadata.event_type = "NETWORK_HTTP"
    $upload.principal.hostname = $pivot_host
    $upload.network.sent_bytes > 104857600    /* 100 MB */
    $upload.target.url =
      /(?i)(dropbox\.com|mega\.nz|onedrive\.live\.com|wetransfer\.com|sendspace\.com)/
    $upload.network.http.method = "POST"

  match:
    $pivot_host over 30m

  condition:
    $archive and $upload

  outcome:
    $risk_score = 75
    $alert_msg = strings.concat(
      "Possible data staging and exfiltration on ",
      $pivot_host,
      ": archive created then ",
      strings.to_string($upload.network.sent_bytes / 1048576),
      " MB uploaded to cloud storage"
    )
}
```

---

## Task 4 Solution: SPL for Credential Stuffing

```splunk
/* Scheduled search: every 10 min, last 10 min */
| tstats
    dc(Authentication.user)      AS distinct_accounts
    count                        AS total_attempts
    count(eval(action="failure")) AS failures
    count(eval(action="success")) AS successes
    WHERE
      index=security
      (source=WinEventLog* EventCode=4625) OR
      (source=linux_secure ("Failed password" OR "Invalid user"))
    BY
      Authentication.src_ip
      span=10m

| eval
    failure_rate = round((failures / total_attempts) * 100, 1),
    success_rate = round((successes / total_attempts) * 100, 1)

/* Apply threshold conditions */
| where distinct_accounts > 20 AND failure_rate > 80

/* Enrich with GeoIP */
| iplocation Authentication.src_ip prefix=src_

/* Calculate severity */
| eval severity = case(
    distinct_accounts > 100, "critical",
    distinct_accounts > 50,  "high",
    true(),                  "medium")

/* Final output */
| rename Authentication.src_ip AS source_ip
| eval
    alert_name = "Credential Stuffing Attack",
    mitre_technique = "T1110.004"
| table
    _time,
    source_ip,
    src_Country,
    src_City,
    distinct_accounts,
    total_attempts,
    failures,
    failure_rate,
    severity,
    alert_name,
    mitre_technique
| sort -distinct_accounts
```

---

## Grading Notes

**Common mistakes to look for:**

1. Using `source.ip` vs `src_ip` — after normalization, always use ECS names (`source.ip`)
1. Forgetting `with runs=N` in EQL for minimum event count
1. Not excluding known-good IPs (scanners, load balancers)
1. ATT&CK tagging: credential stuffing is T1110.004, not just T1110
1. YARA-L: the `outcome` section allows computing alert context; missing it loses points for the bonus
