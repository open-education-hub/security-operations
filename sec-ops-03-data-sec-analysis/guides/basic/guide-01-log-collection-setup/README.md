# Guide 01: Setting Up Log Collection with Splunk Universal Forwarder

**Level:** Basic

**Time:** ~30 minutes

**Prerequisites:** Docker Desktop installed

## What You Will Learn

* What the Splunk Universal Forwarder (UF) is and how it fits in the architecture
* How to deploy the UF in Docker and connect it to a Splunk indexer
* How to configure the UF to monitor specific log files
* How to verify that logs are flowing into Splunk

## Background

### The Collection Problem

A Splunk indexer cannot directly reach into every server and pull log files.
Instead, a lightweight **collection agent** runs on each host, monitors log files, and ships new log entries to the indexer.
This agent is the **Universal Forwarder (UF)**.

The UF is:

* **Lightweight:** ~15MB binary, minimal CPU/memory overhead
* **Reliable:** Buffers events locally if the network or indexer is unavailable
* **Configurable:** Monitors files, Windows Event Logs, network ports, scripts
* **Secure:** Supports TLS encryption for the data channel

### Architecture Overview

```text
Each monitored host:
┌─────────────────────────────────────────────────────────────┐
│  /var/log/auth.log  ──┐                                     │
│  /var/log/syslog    ──┤  Splunk Universal Forwarder         │
│  /var/log/nginx/*.log ┤  - Monitors file changes (inotify)  │
│  Windows Event Log  ──┘  - Compresses + forwards to indexer │
└─────────────────────────────────────────────────────────────┘
                                    │ TCP 9997 (Splunk protocol)
                                    ▼
              ┌────────────────────────────────────┐
              │      Splunk Indexer                 │
              │  - Receives and parses events       │
              │  - Stores in compressed indexes     │
              │  - Makes searchable via SPL         │
              └────────────────────────────────────┘
```

## Step 1: Understand the inputs.conf File

The UF's primary configuration file is `inputs.conf`.
It defines **what** to monitor.

**File monitoring:**

```ini
[monitor:///var/log/auth.log]
sourcetype = linux_secure
index = main

[monitor:///var/log/nginx/access.log]
sourcetype = access_combined
index = main

# Monitor an entire directory
[monitor:///var/log/apache2/]
sourcetype = access_combined
index = web
whitelist = \.log$
```

**Windows Event Log monitoring** (on Windows UF only):

```ini
[WinEventLog://Security]
disabled = false
index = windows
start_from = oldest
current_only = false
renderXml = true

[WinEventLog://System]
disabled = false
index = windows

[WinEventLog://Application]
disabled = false
index = windows
```

**Key configuration options:**

| Option | Description | Example |
|--------|-------------|---------|
| `sourcetype` | Tells Splunk how to parse the data | `access_combined`, `syslog` |
| `index` | Which Splunk index to send data to | `main`, `windows`, `security` |
| `disabled` | Enable/disable this input | `false` |
| `start_from` | `oldest` (all history) or `newest` (only new data) | `newest` |
| `whitelist` | Regex — only forward matching filenames | `\.log$` |
| `blacklist` | Regex — skip matching filenames | `\.gz$` |

## Step 2: Understand the outputs.conf File

The `outputs.conf` file tells the UF **where** to forward data.

```ini
[tcpout]
defaultGroup = primary_indexers

[tcpout:primary_indexers]
server = splunk-indexer.company.com:9997

# For TLS encryption (production recommended):
# sslCertPath = $SPLUNK_HOME/etc/certs/client.pem
# sslRootCAPath = $SPLUNK_HOME/etc/certs/ca.pem
# useSSL = true
```

**Load-balanced configuration (multiple indexers):**

```ini
[tcpout:primary_indexers]
server = indexer1:9997, indexer2:9997, indexer3:9997
autoLBFrequency = 30
```

## Step 3: Deploy with Docker

For this guide, we will deploy both a Splunk indexer and a UF using Docker Compose.

### Create the docker-compose.yml

Create a new directory and save this file:

```yaml
version: "3.8"
services:
  splunk:
    image: splunk/splunk:9.2
    container_name: guide01-splunk
    environment:
      SPLUNK_START_ARGS: "--accept-license"
      SPLUNK_PASSWORD: "SecOpsDemo123!"
    ports:
      - "8000:8000"
      - "9997:9997"
    volumes:
      - splunk-data:/opt/splunk/var
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000"]
      interval: 30s
      retries: 10
      start_period: 120s

  log-source:
    image: ubuntu:22.04
    container_name: guide01-log-source
    volumes:
      - app-logs:/var/log/app
    command: >
      bash -c "
        apt-get update -q && apt-get install -y -q rsyslog &&
        while true; do
          echo \"{\\\"ts\\\":\\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\",\\\"event\\\":\\\"user_login\\\",\\\"user\\\":\\\"testuser\\\",\\\"src_ip\\\":\\\"10.0.0.1\\\"}\" >> /var/log/app/events.log;
          sleep 5;
        done"

  splunk-forwarder:
    image: splunk/universalforwarder:9.2
    container_name: guide01-forwarder
    environment:
      SPLUNK_START_ARGS: "--accept-license"
      SPLUNK_PASSWORD: "SecOpsDemo123!"
      SPLUNK_FORWARD_SERVER: "splunk:9997"
    volumes:
      - app-logs:/var/log/app:ro
      - ./inputs.conf:/opt/splunkforwarder/etc/system/local/inputs.conf:ro
    depends_on:
      splunk:
        condition: service_healthy

volumes:
  splunk-data:
  app-logs:
```

### Create inputs.conf

```ini
[monitor:///var/log/app/events.log]
sourcetype = app_events
index = main
```

### Start the stack

```console
docker compose up -d
docker compose logs -f splunk-forwarder
```

## Step 4: Verify Log Collection

After 2 minutes, open http://localhost:8000 and run:

```spl
index=main sourcetype=app_events | head 10
```

You should see JSON events from the log-source container.

## Step 5: Troubleshoot Common Issues

### No data in Splunk

**Check forwarder connectivity:**

```console
docker exec guide01-forwarder /opt/splunkforwarder/bin/splunk list forward-server
```

Expected output should show `splunk:9997` as `Active`.

**Check the monitored file exists:**

```console
docker exec guide01-forwarder ls -la /var/log/app/
```

**Check forwarder logs:**

```console
docker exec guide01-forwarder cat /opt/splunkforwarder/var/log/splunk/splunkd.log | tail -50
```

Look for:

* `Connected to idx=splunk:9997` — successful connection
* `File not found: /var/log/app/events.log` — volume mount issue
* `Error opening receiver` — firewall or port issue

### Data appears but is in wrong sourcetype

Check `props.conf` on the indexer to ensure the sourcetype is configured correctly for parsing.

## Step 6: Production Considerations

**Security:**

* Enable TLS between UF and indexer (see `outputs.conf` TLS options)
* Run the UF as a non-root user
* Restrict `inputs.conf` to only the logs needed (least-privilege principle)

**Performance:**

* The UF uses ~20-50MB RAM and negligible CPU
* It buffers up to 500MB locally if the indexer is unreachable
* Log rotation (logrotate) can cause the UF to lose its file position; configure `crcSalt` to handle rotated files:

```ini
[monitor:///var/log/app/events.log]
sourcetype = app_events
crcSalt = <SOURCE>
```

**Scale:**

* A single Splunk indexer can receive from hundreds of UF instances
* Use a **deployment server** to push `inputs.conf` updates to all UFs centrally

## Summary

| Concept | Key Point |
|---------|-----------|
| Universal Forwarder | Lightweight agent that monitors files and ships logs |
| inputs.conf | Defines what to monitor and the sourcetype |
| outputs.conf | Defines where to send data (indexer address) |
| Port 9997 | Default Splunk-to-Splunk forwarding port |
| sourcetype | Label that determines parsing rules in Splunk |
