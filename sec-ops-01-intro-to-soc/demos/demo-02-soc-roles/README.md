# Demo 02: SOC Roles Simulation

## Overview

In this demo, students experience a simulated SOC environment by playing different analyst roles and responding to a staged security incident.
The demo uses a simple Docker-based log generator and a web dashboard to simulate the SOC workflow.

**Duration:** ~25 minutes

**Platform:** Docker

**Difficulty:** Beginner

## Objectives

* Understand the difference between Tier 1, Tier 2, and Tier 3 analyst tasks.
* Practice the escalation workflow.
* Document a basic incident from alert to closure.

## Scenario

A company's monitoring system has detected unusual network activity.
Students will role-play as SOC analysts and work through the incident.

**Simulated incident:** A user account `bob.smith` has been used to:

1. Log in from an unusual country (Romania) at 3 AM.
1. Access 500+ files in 10 minutes.
1. Attempt to connect to an external IP known for data exfiltration.

## Setup

```console
docker run -d \
  --name soc-sim \
  -p 8080:80 \
  nginx:alpine

# Copy the simulation HTML dashboard
docker cp soc_dashboard.html soc-sim:/usr/share/nginx/html/index.html
```

Or simply open `soc_dashboard.html` directly in a browser.

## Role Cards

### Tier 1 Analyst Card

You have received the following alerts in your queue:

```text
[HIGH]   2024-01-15 03:12:44  Geo-anomaly login: bob.smith from RO (normally US)
[MEDIUM] 2024-01-15 03:15:00  Mass file access: bob.smith accessed 500 files
[HIGH]   2024-01-15 03:18:33  Outbound to known-bad IP: 185.220.101.45 from bob.smith's machine
```

**Your tasks:**

1. Review each alert. Are any of these false positives?
1. Check if `bob.smith` has any business travel listed in HR system (assume: No).
1. Determine the combined severity of the incident.
1. Fill in the initial triage form below.
1. Escalate to Tier 2 with your findings.

**Triage Form (fill in):**

```text
Analyst: _______________
Date/Time: _______________
Alert IDs: _______________
Initial Assessment: [ ] False Positive  [X] True Positive
Severity: [ ] Low  [ ] Medium  [X] High  [ ] Critical
Systems Affected: _______________
Recommended Action: _______________
```

### Tier 2 Analyst Card

You receive an escalation from Tier 1 about user `bob.smith`.

**Your tasks:**

1. Examine the timeline of events — do the three alerts correlate?
1. Check threat intelligence: is `185.220.101.45` known malicious? (Assume: Yes, it's a Tor exit node.)
1. Determine if bob.smith's credentials were likely compromised.
1. Recommend immediate containment actions.
1. Decide if Tier 3 / incident response is needed.

**Investigation Notes Template:**

```text
Investigator: _______________
Ticket #: INC-2024-001

Timeline:
- 03:12:44 : Login from Romania (anomalous)
- 03:15:00 : Bulk file access (500 files in 10 min)
- 03:18:33 : Outbound to 185.220.101.45 (Tor exit node)

Hypothesis: Account compromise + data exfiltration
Confidence: [ ] Low  [ ] Medium  [X] High

Containment Actions Recommended:

1. Disable bob.smith account immediately

2. Block outbound to 185.220.101.45 at firewall
3. Isolate bob.smith's workstation from network
4. Preserve logs for forensic analysis

Escalate to IR Team: [X] Yes  [ ] No
```

### Tier 3 / Incident Responder Card

You receive the incident package from Tier 2.

**Your tasks:**

1. Identify the attack technique using MITRE ATT&CK.
1. Determine the full scope of the compromise.
1. Identify what data may have been exfiltrated.
1. Draft the incident report summary.

**MITRE ATT&CK Mapping:**

```text
T1078    - Valid Accounts (credential theft/reuse)
T1083    - File and Directory Discovery
T1041    - Exfiltration Over C2 Channel
T1090.003 - Proxy: Multi-hop Proxy (Tor)
```

## Debrief Discussion

After completing the simulation, discuss:

1. How long did each tier take to reach their conclusions?
1. What information was missing that would have helped?
1. What automation could reduce manual work at Tier 1?
1. What detection rules should be created to catch this earlier next time?

## Key Takeaways

* **Correlation** of multiple alerts tells a much richer story than each alert in isolation.
* **Speed matters**: The attacker was done in under 10 minutes.
* **Geo-anomaly alerts** are high-value but require context (business travel, VPN use).
* **MITRE ATT&CK** helps classify and communicate attacker behavior consistently.
