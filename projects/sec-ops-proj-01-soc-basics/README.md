# Project 01: SOC Basics — Building and Operating a Security Operations Centre

## Covers Sessions: 01–05 (Intro to SOC, Network/Infrastructure Monitoring, Data Security and Analysis, Crypto Essentials, Endpoint Security)

## Estimated Time: 6–8 hours

---

## Overview

In this project, you will build a minimal but functional Security Operations Centre (SOC) environment using Docker.
You will configure log collection, set up basic detection rules, monitor a simulated network environment, and respond to a set of pre-scripted security events.
By the end, you will have hands-on experience with the full detect-investigate-respond loop.

This project integrates concepts from Sessions 01–05:

* SOC architecture and analyst roles (Session 01)
* Network traffic monitoring and analysis (Session 02)
* Log parsing and SIEM correlation (Session 03)
* TLS/encryption basics and certificate monitoring (Session 04)
* Endpoint telemetry and EDR concepts (Session 05)

---

## Learning Objectives

By completing this project you will be able to:

1. Deploy a multi-service monitoring environment using Docker Compose
1. Configure log collection from multiple sources into a centralised system
1. Write and test detection rules that trigger on suspicious activity
1. Investigate an alert end-to-end: from detection to root cause analysis
1. Document findings in a professional incident report
1. Apply basic network forensics (Wireshark/tcpdump) to identify suspicious traffic

---

## Scenario

You are the first SOC analyst hired at **SecureMed**, a small Romanian healthcare startup with 50 employees.
They have:

* A small web application (`patient-portal`) exposed on the internet
* An internal employee network with Windows workstations
* A MySQL database containing patient appointment data
* A file server accessible by all employees

The CISO has asked you to set up monitoring and respond to any incidents over the next "operational week" (simulated via the environment).

The environment contains **5 pre-scripted security events** that you must detect, investigate, and document.

---

## Environment Setup

### Prerequisites

* Docker and Docker Compose installed
* At least 4 GB RAM available for Docker
* Ports 5601, 9200, 9514, 8080 must be free

### Launch the Environment

```console
git clone <this-repo>
cd projects/sec-ops-proj-01-soc-basics
docker compose up --build -d
```

Wait 2–3 minutes for all services to start, then verify:

```console
docker compose ps
```

All services should be `running`.

### Access Points

| Service | URL / Connection |
|---------|----------------|
| Kibana (SIEM/log viewer) | http://localhost:5601 |
| Patient Portal (target web app) | http://localhost:8080 |
| Log generator (simulates events) | runs automatically in background |

### Simulated Attack Events

The environment automatically generates 5 security events over the first 30 minutes of operation.
You must detect and investigate each one.

---

## Tasks

### Task 1: Verify Log Collection

Before investigating events, confirm your monitoring is working.

1. Log into Kibana at http://localhost:5601
1. Navigate to **Discover** and verify you can see logs from:
   * `patient-portal` (web access logs)
   * `syslog` (system events)
   * `network-monitor` (simulated network flow data)
1. Create an index pattern for each log source
1. Verify at least 100 log events are present

**Deliverable**: Screenshot of Kibana Discover showing all 3 log sources with recent events.

---

### Task 2: Configure Detection Rules

Before the events fire, configure at least 3 detection rules in Kibana/ElastAlert:

**Required rules:**

1. More than 10 failed HTTP 401 responses in 1 minute from the same source IP
1. Any connection to or from a known malicious IP (provide a small IOC list in `data/malicious_ips.txt`)
1. Successful login from a source IP that has previously generated failed login attempts

**Stretch rules (optional):**

1. SQL injection pattern detected in web request URI
1. Sensitive file download (file path contains `patient` or `medical`)

**Deliverable**: Export your rule definitions to a file `detection_rules.json`.

---

### Task 3: Investigate Security Events

Five events will be generated.
For each event you detect, complete an investigation:

| Event | Clue |
|-------|------|
| Event 1 | Brute force attempt against patient-portal login |
| Event 2 | Successful login after brute force from same IP |
| Event 3 | SQL injection attempt in search parameter |
| Event 4 | Large file download of patient records export |
| Event 5 | Connection to a known malicious IP from internal host |

For each event, answer:

1. What triggered the alert?
1. What is the source and target?
1. What happened before and after the alert event (context)?
1. Is this a true positive or false positive? Why?
1. What is the recommended response action?

**Deliverable**: Investigation notes for all 5 events.

---

### Task 4: Network Traffic Analysis

The environment captures network traffic.
Use the provided PCAP file (`data/capture.pcap`) or analyse live traffic with:

```console
docker compose exec network-monitor tcpdump -i eth0 -w /data/capture.pcap
```

Using Wireshark or `tcpdump` filters:

1. Identify the brute force source IP and count of attempts
1. Find the SQL injection payload in HTTP traffic
1. Identify any unencrypted sensitive data (HTTP, not HTTPS)
1. Calculate the total bytes transferred in the large file download

**Deliverable**: `network_analysis.md` with findings and screenshots.

---

### Task 5: Incident Report

Write a formal incident report for the most severe event you detected (the SQL injection or the compromised account).
The report should follow this structure:

```text
INCIDENT REPORT
===============
Report ID:        IR-2024-001
Date/Time:
Analyst:
Severity:

Executive Summary (3-5 sentences):
  [Non-technical summary for management]

Timeline of Events:
  [Chronological list of key events with timestamps]

Technical Findings:
  [Detailed technical analysis]

Impact Assessment:
  [What was affected? Was any data exposed?]

Root Cause:
  [Why did this happen?]

Containment Actions Taken:
  [What was done to stop the attack?]

Recommendations:
  [How to prevent recurrence]
```

**Deliverable**: Completed `incident_report.md`.

---

### Task 6: Reflection Questions

Answer these questions in `reflection.md`:

1. Which event was hardest to detect and why?
1. What log sources were missing that would have improved your investigation?
1. If you had to prioritise one improvement to this SOC setup, what would it be?
1. How would SIEM rule 3 (login from IP with previous failures) generate false positives? How would you tune it?
1. What is the difference between a SOC analyst's job in this project versus a real production SOC?

---

## Grading Criteria

| Component | Points |
|-----------|--------|
| Log collection verified (Task 1) | 10 |
| Detection rules configured (Task 2) | 20 |
| All 5 events investigated (Task 3) | 30 |
| Network analysis complete (Task 4) | 20 |
| Incident report quality (Task 5) | 15 |
| Reflection questions (Task 6) | 5 |
| **Total** | **100** |

---

## Hints

* Start with Task 1 before anything else — if logs are not flowing, no investigation is possible
* The Kibana **Discover** tab with a 30-minute time window will show all events
* Use `docker compose logs -f log-generator` to see what events are being simulated
* SQL injection patterns often include `'`, `OR 1=1`, `UNION SELECT`, `--`
* For the network analysis, Wireshark filter `http.request.method == "POST"` will find login attempts
* The IOC list in `data/malicious_ips.txt` is intentionally small — add it as a lookup table in Kibana

## Submission

Submit a ZIP file containing:

* `detection_rules.json`
* `investigation_notes.md` (all 5 events)
* `network_analysis.md`
* `incident_report.md`
* `reflection.md`
* Screenshots folder with at least 5 screenshots
