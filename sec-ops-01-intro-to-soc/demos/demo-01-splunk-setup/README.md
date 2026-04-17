# Demo 01: Setting Up a Splunk Free Trial Environment

## Overview

This demo shows how to set up a Splunk Cloud trial environment and ingest your first logs for security analysis.
Students will observe the SIEM interface, understand data ingestion, and run basic search queries.

**Duration:** ~20 minutes

**Platform:** Docker (local) or Splunk Cloud free trial

**Difficulty:** Beginner

## Objectives

* Spin up a Splunk instance using Docker.
* Ingest sample security logs.
* Run basic SPL (Splunk Processing Language) queries.
* View the default security dashboards.

## Setup

### Option A: Docker (Recommended for offline/lab use)

```console
# Pull and run Splunk in a Docker container
docker run -d \
  --name splunk \
  -p 8000:8000 \
  -p 9997:9997 \
  -e SPLUNK_GENERAL_TERMS='--accept-sgt-current-at-splunk-com' \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='D4Sec-sec-ops!' \
  splunk/splunk:latest
```

Wait approximately 2-3 minutes for Splunk to initialize, then open:

```text
http://localhost:8000
```

Login with:

* Username: `admin`
* Password: `Admin1234!`

### Option B: Splunk Cloud Free Trial

1. Go to https://www.splunk.com/en_us/trials/splunk-cloud.html
1. Register with a valid email address.
1. Follow the activation email link.

## Walkthrough

### Step 1: Explore the Splunk Interface

After logging in, familiarize yourself with:

* **Search & Reporting**: The main search interface.
* **Dashboards**: Pre-built visual displays.
* **Settings**: Data input and index configuration.
* **Apps**: Extensions that add functionality.

### Step 2: Ingest Sample Data

In your Splunk container, we'll use the built-in `_internal` index which contains Splunk's own operational logs.
This is perfect for demonstration.

Navigate to **Search & Reporting** and run:

```spl
index=_internal | head 20
```

This shows the 20 most recent internal Splunk log entries.

### Step 3: Add Sample Security Log Data

Create a file named `sample_auth.log` with the following content:

```text
2024-01-15 08:23:11 Failed password for user admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:12 Failed password for user admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:13 Failed password for user admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:14 Failed password for user admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:15 Failed password for user admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:23:16 Accepted password for user admin from 192.168.1.100 port 22 ssh2
2024-01-15 08:25:02 Failed password for user root from 10.0.0.55 port 22 ssh2
2024-01-15 08:25:03 Failed password for user root from 10.0.0.55 port 22 ssh2
2024-01-15 08:30:00 Accepted password for user jdoe from 192.168.1.50 port 22 ssh2
2024-01-15 09:00:00 session opened for user admin by (uid=0)
```

Copy this file into the Splunk container:

```console
docker cp sample_auth.log splunk:/tmp/sample_auth.log
```

In Splunk, navigate to **Settings → Add Data → Upload** and upload the file.
Set the source type to `linux_secure`.

### Step 4: Run Security Queries

**Query 1: Count failed logins by IP**

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
```

**Query 2: Detect brute force (>3 failures from same IP)**

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 3
```

**Query 3: Find successful logins after multiple failures**

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for user (?<user>\w+) from (?<src_ip>[^\s]+)"
| stats count(eval(status="Failed")) as failures, count(eval(status="Accepted")) as successes by src_ip
| where failures > 3 AND successes > 0
```

### Step 5: Create a Simple Alert

1. Run Query 2 from above.
1. Click **Save As → Alert**.
1. Configure:
   * Title: `Brute Force Detection`
   * Schedule: Every 5 minutes
   * Trigger condition: Number of results > 0
   * Action: Add to Triggered Alerts

## Discussion Points

* What does each query tell us about the security event?
* Why is the third query (brute force + success) more concerning than just failures?
* What additional data sources would improve detection accuracy?
* How would this alert workflow look in a real SOC environment?

## Cleanup

```console
docker stop splunk && docker rm splunk
```
