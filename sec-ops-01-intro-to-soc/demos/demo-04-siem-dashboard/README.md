# Demo 04: Building a SIEM Dashboard

## Overview

This demo shows how to build a security monitoring dashboard in Splunk (or Wazuh) that gives a SOC analyst an at-a-glance view of the security posture.
Students will create panels for failed logins, geographic login anomalies, and top alert categories.

**Duration:** ~25 minutes

**Platform:** Docker (Splunk)

**Difficulty:** Beginner

## Objectives

* Create a Splunk dashboard with multiple panels.
* Write SPL queries for common SOC use cases.
* Understand the difference between operational and executive dashboards.

## Prerequisites

* Splunk running from Demo 01.
* Sample log data ingested.

## Dashboard Panels to Build

### Panel 1: Failed Login Attempts (Last 24 Hours)

**SPL Query:**

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| timechart count span=1h
```

**Visualization:** Line chart

**Purpose:** Shows login failure trends over time — spikes indicate brute force attempts.

---

### Panel 2: Top Source IPs for Failed Logins

**SPL Query:**

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| top limit=10 src_ip
```

**Visualization:** Bar chart

**Purpose:** Identifies the most active attack sources.

---

### Panel 3: Successful Logins After Failures (Possible Brute Force Success)

**SPL Query:**

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for user (?<user>\w+) from (?<src_ip>[^\s]+)"
| stats count(eval(status="Failed")) as failures, count(eval(status="Accepted")) as successes by src_ip
| where failures > 3 AND successes >= 1
```

**Visualization:** Table

**Purpose:** Critical alert panel — successful login after multiple failures.

---

### Panel 4: Alert Severity Summary

**SPL Query (using simulated alert data):**

```spl
index=main sourcetype=alerts
| stats count by severity
| eval severity_order=case(severity="critical",1, severity="high",2, severity="medium",3, severity="low",4)
| sort severity_order
```

**Visualization:** Pie chart

**Purpose:** Executive view of alert distribution by severity.

---

## Creating the Dashboard

1. In Splunk, navigate to **Search & Reporting → Dashboards → Create New Dashboard**.
1. Name it: `SOC Overview - Session 01`
1. For each panel:
   a. Click **Add Panel → New from Search**.
   b. Enter the SPL query.
   c. Choose the appropriate visualization type.
   d. Set the time range to **Last 24 hours**.
   e. Save the panel.

## Dashboard Best Practices

| Principle | Explanation |
|-----------|-------------|
| **Less is more** | Show only critical information; avoid clutter |
| **Time context** | Always show time range on dashboards |
| **Actionable panels** | Every panel should lead to an action |
| **Color coding** | Red = critical, Orange = high, Yellow = medium, Green = low |
| **Refresh rate** | Operational dashboards: every 1-5 minutes |

## Dashboard Types

| Type | Audience | Purpose |
|------|----------|---------|
| **Operational** | L1/L2 Analysts | Real-time alert triage |
| **Tactical** | L2/L3, Team Lead | Investigation support |
| **Strategic/Executive** | SOC Manager, CISO | KPI trends, risk posture |

## Exporting for Offline Review

```console
# Export dashboard as PNG (requires Splunk Enterprise)
curl -k -u admin:Admin1234! \
  "http://localhost:8000/en-US/app/search/export" \
  --output dashboard_export.png
```

## Discussion

* What data is most important to show on an operational dashboard?
* How does this dashboard help reduce MTTD (Mean Time to Detect)?
* What additional data sources would make this dashboard more powerful?
