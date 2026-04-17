# Demo 01: Setting Up Multiple Data Sources Feeding into Splunk

**Difficulty:** Beginner–Intermediate

**Time:** ~45 minutes

**Prerequisites:** Docker Desktop installed, 8GB RAM available

## Overview

In this demo you will spin up a complete multi-source log ingestion environment using Docker Compose.
The environment simulates:

* A Linux web server generating Apache access logs
* A simulated Windows event log generator (Python-based)
* A Zeek network sensor analyzing generated traffic
* A Splunk instance receiving all log streams via the Splunk Universal Forwarder (UF) and HEC (HTTP Event Collector)

By the end of this demo you will see all log sources appearing in Splunk and be able to run basic searches across them.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                   Docker Network                     │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ web-server   │    │   log-generator          │   │
│  │ (nginx)      │    │   (Python - simulates    │   │
│  │              │    │    auth/sysmon events)   │   │
│  └──────┬───────┘    └────────────┬─────────────┘   │
│         │ access.log              │ JSON events      │
│         │                         │                   │
│  ┌──────▼─────────────────────────▼─────────────┐   │
│  │           splunk-forwarder                    │   │
│  │   (tails log files, forwards via TCP 9997)   │   │
│  └──────────────────┬────────────────────────────┘   │
│                     │                                 │
│  ┌──────────────────▼────────────────────────────┐   │
│  │              splunk                            │   │
│  │   Web UI: http://localhost:8000               │   │
│  │   HEC: http://localhost:8088                  │   │
│  │   Receiver: port 9997                         │   │
│  └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

```console
# Verify Docker is running
docker --version
docker compose version

# Check available memory (need at least 6GB)
free -h
```

## Step-by-Step Instructions

### Step 1: Review the docker-compose.yml

Open `docker-compose.yml` in this directory and review the services defined.
Notice how:

* The `web-server` container writes logs to a shared volume `/logs`
* The `log-generator` writes simulated events to the same volume
* `splunk-forwarder` mounts that volume read-only and monitors the files
* `splunk` is the central indexer and search head

### Step 2: Start the Environment

```console
# From this directory
docker compose up -d

# Watch startup progress (Splunk takes ~2 minutes to initialize)
docker compose logs -f splunk
```

Wait until you see:

```text
Splunk has been started successfully. You can access it at http://localhost:8000
```

### Step 3: Access Splunk

1. Open http://localhost:8000 in your browser
1. Login: `admin` / `SecOpsDemo123!`
1. Dismiss any setup dialogs

### Step 4: Verify Data is Flowing

In the Splunk search bar, run:

```spl
index=* earliest=-5m | stats count by sourcetype
```

You should see entries for:

* `access_combined` (Apache-format web logs)
* `auth_events` (simulated authentication logs)
* `sysmon_json` (simulated endpoint events)

### Step 5: Explore Each Data Source

**Web server logs:**

```spl
index=main sourcetype=access_combined earliest=-15m
| table _time clientip request status bytes
```

**Simulated failed logons:**

```spl
index=main sourcetype=auth_events event_type=failed_login earliest=-15m
| table _time src_ip username failure_reason
```

**Simulated process creation (Sysmon-style):**

```spl
index=main sourcetype=sysmon_json EventID=1 earliest=-15m
| table _time Computer User Image CommandLine ParentImage
```

### Step 6: Create a Simple Dashboard

1. Navigate to **Search & Reporting** → New search

1. Run: `index=main | timechart span=1m count by sourcetype`

1. Click **Save As** → **Dashboard Panel**
1. Name it "Demo 01 - Data Sources Overview"

### Step 7: Tear Down

```console
docker compose down -v
```

## What You Learned

* How multiple data sources can feed a central SIEM simultaneously
* The role of the Splunk Universal Forwarder as a collection agent
* The difference between sourcetypes and how Splunk uses them for parsing
* Basic SPL queries to verify log ingestion

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Splunk takes too long to start | Wait up to 5 minutes; check with `docker compose logs splunk` |
| No data in search results | Check forwarder: `docker compose logs splunk-forwarder` |
| Port 8000 already in use | Change the port mapping in docker-compose.yml |
| Out of memory | Reduce `SPLUNK_RAM_MBs` in docker-compose.yml to 1024 |
