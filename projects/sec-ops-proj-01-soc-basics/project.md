# Project 01: Build a Basic SOC Monitoring Setup

**Covers:** Sessions 01–05

**Estimated time:** 6–8 hours

**Level:** Foundational

---

## Overview

This project brings together the foundational skills from Sessions 01–05 to build a functional, containerised SOC monitoring environment from scratch.
You will configure log collection, deploy a basic SIEM, write your first detection rules, and demonstrate that your setup can detect a simulated attack.

By the end of this project, you will have a working monitoring stack that you could adapt for a small organisation or use as a personal lab environment.

---

## Learning Outcomes

Upon completing this project, you will be able to:

* Stand up a complete log collection pipeline from endpoint to SIEM
* Write and test detection rules for common attacker techniques
* Generate an alert when a simulated attack occurs
* Produce a basic SOC operations report summarising the environment's alert posture

---

## Scenario

You have been hired as a junior security engineer at **Orion Retail Group**, a small e-commerce company with 50 employees.
Orion has no existing security monitoring infrastructure.
The CISO has asked you to stand up a proof-of-concept SOC monitoring environment using open-source tools, prove it can detect basic attacks, and document what you built.

Your environment will be entirely Docker-based so it can run on any laptop.

---

## Environment

All components run in Docker.
You may use images from Docker Hub.

**Required components:**

| Component | Suggested Image | Purpose |
|-----------|----------------|---------|
| Log collector | `fluent/fluent-bit` | Collect logs from application containers |
| SIEM / log store | `opensearchproject/opensearch` + `opensearch-dashboards` | Store and search logs |
| Simulated application | `nginx:latest` or `httpd:latest` | Generate access logs |
| Attack simulator | Custom Python script or `kalilinux/kali-rolling` | Generate attack traffic |

You are free to use alternative open-source tools (Elasticsearch + Kibana, Wazuh, Graylog, etc.) if you prefer, provided the same deliverables can be demonstrated.

---

## Project Tasks

### Part 1 — Environment Setup (Estimated: 1.5 hours)

**1.1** Create a `docker-compose.yml` that brings up:

* A web application container (nginx or similar) with access logging enabled
* A Fluent Bit container configured to tail the web application's access logs and forward them to OpenSearch
* An OpenSearch container
* An OpenSearch Dashboards container

**1.2** Verify the pipeline works:

* Browse to the web application to generate access log entries
* Confirm the log entries appear in OpenSearch (use the Dashboards UI or `curl` the API)
* Document the log schema: what fields are present in each log record?

**1.3** Create an index pattern in OpenSearch Dashboards to query your logs.

**Deliverable:** `docker-compose.yml` + screenshot or `curl` output showing logs in OpenSearch.

---

### Part 2 — Detection Rules (Estimated: 2 hours)

**2.1** Write a detection rule (using OpenSearch alerting, or a Python polling script, or equivalent) that fires when:

* More than 20 HTTP 404 responses occur within a 60-second window from the same source IP (directory brute-force indicator)

**2.2** Write a second detection rule that fires when:

* An HTTP request contains any of these strings in the URL path: `../`, `%2e%2e`, `/etc/passwd`, `/etc/shadow`, `<script>` (web attack indicator)

**2.3** Write a third detection rule for:

* An HTTP response code of 200 on a URL path containing `/admin` or `/wp-admin` (successful admin page access)

Document each rule:

* What does it detect?
* What is the expected false positive rate and why?
* What ATT&CK technique does it map to?

**Deliverable:** Rule definitions in your chosen format (JSON query, Python script, or YAML) + ATT&CK mapping table.

---

### Part 3 — Attack Simulation (Estimated: 1.5 hours)

**3.1** Using a Python script or `curl` commands, simulate the following attacks against your web application:

**Attack A — Directory Brute Force:**

```bash
# Simulate a tool like dirb/gobuster by sending many 404 requests rapidly
for path in /admin /backup /config /.git /wp-login.php /phpmyadmin /robots.txt /test /debug /api; do
  curl -s "http://localhost:8080/$path" > /dev/null
done
# Repeat 30 times
```

**Attack B — Path Traversal Attempt:**

```console
curl "http://localhost:8080/../../../etc/passwd"
curl "http://localhost:8080/%2e%2e%2fetc%2fpasswd"
```

**Attack C — Admin Page Probe:**

```console
curl "http://localhost:8080/admin"
curl "http://localhost:8080/wp-admin/"
```

**3.2** After running the attacks, verify that your detection rules fired.
Capture:

* The alert output (or log query showing the detected events)
* The timestamp of the first attack event and the first alert

**3.3** Calculate detection latency: time from first attack event to first alert.

**Deliverable:** Attack scripts + screenshots/output showing alerts fired.

---

### Part 4 — SOC Operations Report (Estimated: 1 hour)

Write a `soc_operations_report.md` (1–2 pages) covering:

1. **Environment Description** — What you built, what components are running, their purpose
1. **Log Sources** — What log sources are ingested, sample log record with field descriptions
1. **Detection Rules** — Summary table of all 3 rules with ATT&CK mapping
1. **Attack Simulation Results** — Did the rules fire? What was the alert latency?
1. **Gaps and Limitations** — What attacks would your current setup NOT detect? (List at least 3)
1. **Recommended Next Steps** — What would you add in a production deployment? (List at least 4)

**Deliverable:** `soc_operations_report.md`

---

## Deliverables Summary

| # | Deliverable | Description |
|---|------------|-------------|
| 1 | `docker-compose.yml` | Full stack definition |
| 2 | `fluent-bit.conf` | Fluent Bit pipeline config |
| 3 | `detection_rules/` | Directory with all 3 rule definitions |
| 4 | `attack_simulation.sh` or `.py` | Attack simulation scripts |
| 5 | `soc_operations_report.md` | Operations report |
| 6 | Evidence screenshots or `evidence/` | Proof rules fired |

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Environment is fully functional (logs flow from app → SIEM) | 20 |
| All 3 detection rules are implemented and syntactically correct | 20 |
| All 3 attacks are simulated and evidence shows alerts fired | 25 |
| ATT&CK mapping is correct for all rules | 10 |
| SOC report addresses all 6 required sections with depth | 25 |

**Total: 100 points**

---

## Hints

* Start with a simple `nginx` container and test that its access logs are being written before adding Fluent Bit. Debugging a broken pipeline is much harder when all components are running simultaneously.
* OpenSearch has a built-in Alerting plugin. Alternatively, you can use a Python script with `requests` to poll OpenSearch on a schedule and trigger an alert when a threshold is crossed.
* For the directory brute force rule, use a time-window aggregation. If you are using raw Python, you can scan logs every 60 seconds and count 404s per source IP in that window.
* The "gaps and limitations" section is important — a SOC report that claims to detect everything is not credible. Be honest about what your setup misses.
* For the ATT&CK mapping: T1190 (Exploit Public-Facing Application) covers web attacks; T1595.003 (Active Scanning: Wordlist Scanning) covers directory brute force.

---

## Extension Challenges (Optional, no additional marks)

* Add a fourth log source (e.g., SSH authentication logs from a second container) and write a detection rule for brute-force login attempts
* Build a simple dashboard in OpenSearch Dashboards showing alert counts by rule over time
* Add TLS to the nginx container and demonstrate that logs still flow correctly
