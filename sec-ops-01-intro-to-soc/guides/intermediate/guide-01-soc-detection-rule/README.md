# Guide 01 (Intermediate): Writing Custom SIEM Detection Rules

## Objective

Write custom Splunk detection rules that go beyond simple pattern matching.
Learn to correlate multiple events, use time-based analysis, and tune rules to reduce false positives.

## Prerequisites

* Completed all Basic guides.
* Comfortable writing basic SPL queries.
* Splunk running with sample data.

## Background

Effective SIEM detection rules require balancing sensitivity and specificity:

* **Too sensitive**: High false positive rate, alert fatigue.
* **Too specific**: Misses real threats (false negatives).

## Steps

### Step 1: Multi-Stage Attack Detection

A brute force attack that succeeds is more dangerous than one that doesn't.
Write a query that detects both stages:

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for (?<user>\w+) from (?<src_ip>[^\s]+)"
| bucket _time span=10m
| stats
    count(eval(status="Failed")) as fail_count,
    count(eval(status="Accepted")) as success_count,
    values(user) as targets
    by src_ip, _time
| where fail_count >= 3 AND success_count >= 1
| eval attack_type="Brute Force + Successful Login"
| table _time, src_ip, fail_count, success_count, targets, attack_type
```

This query:

1. Extracts status, user, and IP from each log line.
1. Groups events into 10-minute windows.
1. Counts failures and successes per IP per window.
1. Only alerts when an IP has both failures AND a success.

### Step 2: Threshold Tuning

The threshold of 3 failures may generate too many false positives for some environments.
Consider:

```spl
| where fail_count >= 10 AND success_count >= 1
```

Or add a time constraint — brute force usually happens fast:

```spl
| where fail_count >= 5 AND success_count >= 1 AND fail_count > success_count * 3
```

### Step 3: Create a Lookup Table for Whitelisting

Some IPs are known-good (e.g., monitoring systems, backup servers).
Create a whitelist:

1. Create a file `whitelist_ips.csv`:

```csv
ip,description
192.168.1.1,gateway
192.168.1.200,backup_server
10.0.0.1,monitoring
```

1. In Splunk: **Settings → Lookups → Lookup table files → Add new**. Upload the CSV.

1. Update your detection query to exclude whitelisted IPs:

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for (?<user>\w+) from (?<src_ip>[^\s]+)"
| lookup whitelist_ips ip as src_ip OUTPUT description as whitelist_reason
| where isnull(whitelist_reason)
| stats count(eval(status="Failed")) as fail_count, count(eval(status="Accepted")) as success_count by src_ip
| where fail_count >= 5 AND success_count >= 1
```

### Step 4: Add MITRE ATT&CK Tagging

Document your detection with ATT&CK metadata:

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for (?<user>\w+) from (?<src_ip>[^\s]+)"
| stats count(eval(status="Failed")) as fail_count, count(eval(status="Accepted")) as success_count by src_ip, user
| where fail_count >= 5 AND success_count >= 1
| eval mitre_technique="T1110.001"
| eval mitre_tactic="Credential Access"
| eval mitre_name="Brute Force: Password Guessing"
| table src_ip, user, fail_count, success_count, mitre_technique, mitre_tactic, mitre_name
```

### Step 5: Save as Correlation Search

Save the final detection query as an alert with:

* Title: `[T1110.001] SSH Brute Force with Successful Login`
* Severity: Critical
* Description: `Detects SSH brute force attacks where at least one login succeeded. MITRE T1110.001.`

## Verification

* [ ] Multi-stage query returns results for the sample data.
* [ ] Whitelist lookup created and working.
* [ ] MITRE ATT&CK fields added to alert output.
* [ ] Alert saved with proper naming convention.

## Summary

You have written a production-quality SIEM detection rule that correlates events, filters noise using whitelists, and is documented with MITRE ATT&CK metadata.
These are the skills needed for a Tier 2/3 analyst or a Security Engineer building and maintaining a detection library.
