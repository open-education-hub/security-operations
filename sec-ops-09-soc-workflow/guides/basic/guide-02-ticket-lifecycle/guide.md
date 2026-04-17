# Guide 02 — Ticket Lifecycle Management

## Objective

By the end of this guide you will be able to:

* Create well-structured incident tickets with all required fields
* Transition tickets through their lifecycle states correctly
* Write clear work log entries
* Close tickets with appropriate resolution documentation

**Estimated time:** 25 minutes

**Level:** Basic

**Prerequisites:** Guide 01 (Alert Triage Workflow)

---

## Background

A ticket is the primary unit of work in a SOC.
Every investigation, every action taken, every decision made must be recorded in a ticket.
The ticket becomes the definitive record of "what happened and what we did."

This guide walks through the complete lifecycle of a ticket using **TheHive** as the case management system.

---

## Setup

Run TheHive (from Demo 02 docker-compose.yml):

```console
docker compose up -d
# Wait ~3 minutes
# Open http://localhost:9000
# Login: admin@thehive.local / secret
```

---

## Ticket Lifecycle

```text
┌──────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────────┐    ┌────────┐
│ New  │───▶│ Acknowledged │───▶│ In Progress │───▶│ Pending External │───▶│ Closed │
└──────┘    └──────────────┘    └─────────────┘    └──────────────────┘    └────────┘
                                       │                    │
                                       ▼                    │
                               ┌──────────────┐            │
                               │  Escalated   │────────────┘
                               └──────────────┘
```

---

## Step 1: Create a New Ticket

We'll create a ticket for a brute force attack scenario.

**Alert details:**

```text
Alert: BF-2025-004891
Time: 2025-04-10 14:15 UTC
Source: SIEM (Splunk)
Rule: Multiple failed SSH logins — production server
Details:
  Source: 203.0.113.67
  Target: prod-web-01.globalbank.internal (port 22)
  Failed attempts: 127 in 8 minutes
  Valid usernames tried: root, admin, ubuntu, ec2-user
```

### In TheHive:

1. Click **Cases** → **New Case**

1. Fill in fields:

| Field | Value |
|-------|-------|
| Title | SSH brute force — prod-web-01 — 203.0.113.67 |
| Severity | Medium |
| TLP | Amber |
| PAP | Amber |
| Tags | `ssh`, `brute-force`, `production-server` |
| Assignee | Your user |

1. Description:

```text
## Summary
SSH brute force attack detected against production web server.

## Detection
- SIEM Rule: BF-SSH-001 threshold trigger
- Attempts: 127 failed SSH logins in 8 minutes
- Source: 203.0.113.67 (single IP)
- Target: prod-web-01.globalbank.internal

## Initial Assessment
Standard brute force pattern. Source is a single IP — likely automated tool.
No successful logins detected. SSH key authentication is enforced (password disabled).
Low risk of actual compromise but should be blocked.
```

1. Click **Create Case** — status is now **New**

---

## Step 2: Acknowledge the Ticket

1. Click on the case you just created
1. Change status to **In Progress** (this is the "acknowledge" action in TheHive)
1. **Add a work log entry:**

```text
Acknowledged at 14:18 UTC.
Initial review: source 203.0.113.67 is a single IP.
Password auth is disabled on prod-web-01 — minimal actual risk.
Will enrich IP and check for other targets.
```

---

## Step 3: Add Observables

Observables are the IOCs associated with this case.

1. Navigate to **Observables** tab
1. Click **Add observable** for each:

| Type | Value | Tags | Is IOC? |
|------|-------|------|---------|
| ip | 203.0.113.67 | brute-force, source | Yes |
| hostname | prod-web-01.globalbank.internal | production, target | No |
| other | SSH brute force | attack-type | No |

---

## Step 4: Create and Work Tasks

### Add investigation tasks

Navigate to **Tasks** tab, add:

**Task 1:** Enrich source IP 203.0.113.67

**Task 2:** Check for other targets of this IP in last 24h

**Task 3:** Block IP at firewall

### Start Task 1

1. Click Task 1 → **Start**
1. Work through the enrichment, then log your findings:

```text
IP Enrichment Results for 203.0.113.67:
- WHOIS: DigitalOcean, NY datacenter
- ASN: AS14061 (DigitalOcean LLC)
- AbuseIPDB: 47 reports in last 30 days
- VirusTotal: 5/92 engines flagged
- No PTR record

Assessment: Likely a rented VPS used for brute force scanning.
Not a sophisticated attacker — automated scanner.
Risk level: LOW (SSH keys enforced, no successful logins)
```

1. Click **Close Task**

### Start Task 2

```text
SIEM query: index=network dst_ip=203.0.113.67 OR src_ip=203.0.113.67 earliest=-24h
Results:
- Only SSH attempts to prod-web-01.globalbank.internal
- No other internal hosts targeted
- No outbound connections (not a C2)

Conclusion: Targeted at this single host. No lateral movement or wider campaign.
```

1. Click **Close Task**

### Start Task 3

In a real environment, you would submit a firewall change request.
For this guide, log the action:

```text
Firewall block request submitted:
- Ticket: FW-CHG-2025-0847
- Action: Block 203.0.113.67/32 inbound all ports
- Target: perimeter firewall + cloud security group
- Duration: 30 days, then review
- Submitted to: network-team@globalbank.com
```

1. Click **Close Task**

---

## Step 5: Move to "Pending External"

When waiting for another team (network team, HR, IT), move the ticket to **Pending** state:

1. Change status to **Waiting** (Pending External in TheHive)
1. Add a log entry:

```text
Waiting for firewall team to confirm block of 203.0.113.67.
Expected response: within 2 hours (per SLA for security requests).
Following up at 16:18 UTC if no confirmation.
```

---

## Step 6: Receive Confirmation and Close

**Simulated response from network team:**

```text
"Block applied at 15:47 UTC. Rule ID: FW-RULE-20250410-001.
Confirmed no traffic from 203.0.113.67 in last 5 minutes."
```

### Update the ticket

1. Change status back to **In Progress**
1. Log the confirmation:

```text
15:51 UTC: Received confirmation from network team.
Block rule FW-RULE-20250410-001 applied at 15:47 UTC.
Verified no further SSH attempts from source IP.
```

1. All tasks are closed — proceed to close the case.

---

## Step 7: Close the Ticket

1. Change status to **Resolved**
1. Add the closing summary:

```text
## Resolution Summary

**Verdict:** True Positive — Brute Force Attack

**Impact:** None — SSH password authentication was disabled.
No successful logins were recorded.

**Actions Taken:**

1. Enriched source IP — confirmed as brute force scanner (AbuseIPDB: 47 reports)

2. Verified no other internal hosts targeted
3. Requested and confirmed firewall block of 203.0.113.67/32

**Duration:**
- Alert time: 14:15 UTC
- Acknowledged: 14:18 UTC (3 min — within SLA)
- Resolved: 15:51 UTC (96 min — within 2-hour Medium SLA)

**Lessons Learned:** None — standard automated scanner, no unusual TTPs.

**Follow-up Actions:**
- None required. Block will auto-expire in 30 days.
```

1. Close the case with **TruePositive** resolution

---

## Step 8: Review the Closed Ticket

Look at the full case history — it should show:

* Every status change with timestamp
* Every work log entry
* All observables with enrichment
* All tasks with completion notes
* Clear opening and closing summaries

This is the audit trail that regulators, legal teams, and future analysts can rely on.

---

## Knowledge Check

1. Why should you acknowledge a ticket immediately upon receiving it?
1. What information belongs in the ticket description vs. work log entries?
1. When should you move a ticket to "Pending External"?
1. What makes a good resolution summary?
1. Why should observables be added even for low-risk incidents?
