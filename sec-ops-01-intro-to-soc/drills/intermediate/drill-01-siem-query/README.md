# Drill 01 (Intermediate): SIEM Query Writing for Threat Detection

## Description

You are given access to a Splunk instance with sample security logs.
Your task is to write SPL queries that detect specific threat scenarios.
Each scenario requires a different detection approach.

## Objectives

* Write effective SPL queries for real security use cases.
* Apply statistical analysis for anomaly detection.
* Create correlation queries that span multiple event types.

## Setup

Use the Splunk environment from Guide 01.
Additional sample data is available in `support/`.

```console
# Load the extended sample dataset
docker cp support/extended_logs.csv my-splunk:/tmp/extended_logs.csv
```

Import in Splunk via Settings → Add Data → Upload, with sourcetype `csv`.

## Scenarios

### Scenario 1: Password Spray Detection

Password spraying attacks try ONE common password against MANY accounts, rather than many passwords against one account (brute force).
Detection requires looking for:

* Many different usernames targeted from one IP.
* Low number of attempts per username (to avoid per-account lockouts).

Write a Splunk query to detect password spraying: an IP that attempted to log in against 5 or more different usernames, with fewer than 3 attempts per username.

**Hint:**

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "..."
| stats ... by src_ip, user
| stats count(user) as unique_users, avg(...) as avg_attempts_per_user by src_ip
| where unique_users >= 5 AND avg_attempts_per_user < 3
```

### Scenario 2: After-Hours Login Detection

Your organization's policy is that corporate systems should only be accessed between 07:00-20:00 local time.
Detect successful logins outside these hours.

**Hint:** Use `eval hour=strftime(_time, "%H")` to extract the hour.

### Scenario 3: Privilege Escalation Detection

Detect when a non-admin user runs a command with `sudo` and the command contains sensitive keywords: `passwd`, `adduser`, `visudo`, or `chmod 777`.

Sample log format:

```text
Jan 15 10:30:00 server sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/passwd alice
```

Write a query to detect such events and extract the user, command, and target user.

### Scenario 4: Data Exfiltration Baseline Anomaly

Using firewall logs with the fields `src_ip`, `dst_ip`, `bytes_out`, `timestamp`, create a query that:

1. Calculates the average daily outbound bytes per source IP over the sample period.
1. Flags any IP whose outbound traffic in the last day is more than 3 times the historical average.

This is an introduction to **behavioral anomaly detection** — the core of modern threat detection.

## Submission

Submit your four Splunk queries.
Include:

* The query itself.
* Sample output (copy/paste 3-5 rows from Splunk results).
* A brief explanation of what each query detects and why.

## Hints

* Use `stats`, `eventstats`, and `streamstats` for different aggregation patterns.
* `rex` is your friend for extracting fields from unstructured logs.
* Test queries on small time windows first, then expand.
* High false positive rates are expected at first; think about how to reduce them.
