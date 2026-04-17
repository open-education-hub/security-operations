# Drill 01 (Basic): Incident Classification Exercise

**Level:** Basic

**Time:** 30 minutes
**No lab environment required**

---

## Instructions

Below are 8 alert descriptions from a SOC ticketing system.
For each alert:

1. Determine if this is a **real incident** or a likely **false positive**
1. Assign an **NIST incident category**
1. Assign a **severity level (P1–P5)** using the severity matrix
1. State the **most important immediate action**
1. Identify any **escalation triggers** that apply

Record your answers in the answer sheet at the bottom of this file.
Solutions are in `solutions/drill-01-solution/README.md`.

---

## Alert 1: The Blocked Port Scan

```text
SIEM Alert: Inbound Port Scan Detected
────────────────────────────────────────────────────────────────
Time:           2024-11-15 11:24:33 UTC
Source IP:      45.89.67.123 (External — Geolocation: Romania)
Target:         192.168.0.0/24 (Internal network range)
Ports scanned:  22, 23, 80, 443, 3389, 8080, 8443
Duration:       47 seconds
Firewall action: BLOCKED (all probes dropped)
Previous alerts from this IP: 0
```

---

## Alert 2: The Helpdesk Ticket

```text
Source: User report via helpdesk ticket
────────────────────────────────────────────────────────────────
Time:           2024-11-15 13:08:00 UTC
Reporter:       Sarah Nguyen (Marketing Manager)
Report:         "I received an email from what looks like our CFO
                asking me to urgently transfer $47,000 to a new
                vendor. The email says it's confidential and I
                shouldn't discuss it with anyone. The sender email
                is: cfo.urgent@acme-finance.net
                Our real CFO email is: j.parker@acme.com"
Action taken:   User has NOT made any transfer yet.
```

---

## Alert 3: The Crypto Miner

```text
EDR Alert: Suspicious CPU Usage + Network Connection
────────────────────────────────────────────────────────────────
Time:           2024-11-15 14:55:01 UTC
Host:           DEV-WORKSTATION-07 (192.168.20.87)
User:           developer1 (non-privileged developer account)
Alert detail:   Process 'xmrig.exe' consuming 95% CPU
                Network connection to stratum+tcp://pool.minexmr.com:4444
                Process created by developer1 (not system process)
Asset role:     Developer workstation, not connected to production
Classification: Non-production, LOW criticality asset
Note:           Developer acknowledged they installed mining software
                "as an experiment" on their own workstation.
```

---

## Alert 4: The Suspicious Login

```text
SIEM Alert: Impossible Travel Detected
────────────────────────────────────────────────────────────────
Time:           2024-11-15 16:02:44 UTC
Account:        m.johnson@acme.com (Finance Director)
Event 1:        Successful login from New York, USA
                IP: 71.123.45.67 — 2024-11-15 09:15:22 UTC
Event 2:        Successful login from Lagos, Nigeria
                IP: 196.44.123.89 — 2024-11-15 15:58:44 UTC
Distance:       ~8,500 km in ~6 hours 43 minutes
Physical travel time needed: ~14+ hours
Service accessed: Sharepoint (company intranet + HR data)
MFA status:    NOT enrolled (Finance Director in MFA rollout backlog)
```

---

## Alert 5: The Malware Alert with Context

```text
AV Alert: Malware Detected and Quarantined
────────────────────────────────────────────────────────────────
Time:           2024-11-15 10:22:18 UTC
Host:           RECEPTION-PC (192.168.5.12)
User:           receptionist (non-privileged)
Malware:        Adware.BrowserModifier.SearchProtect
Action:         QUARANTINED successfully
Network activity: None suspicious
Process chain:  User launched installer → adware dropped and blocked
Asset role:     Reception desktop, no access to internal systems
File origin:    Download from "free screensaver" website
Follow-up scan: Clean — no additional detections
```

---

## Alert 6: The Ransomware Indicator

```text
EDR Alert: Mass File Modification Detected
────────────────────────────────────────────────────────────────
Time:           2024-11-15 15:44:01 UTC
Host:           FINANCE-WS-03 (192.168.15.22)
User:           a.chen (Finance Analyst)
Alert detail:   1,847 files modified in last 2 minutes
                File extensions changed to: .locked_by_mafia
                vssadmin.exe executed: "vssadmin delete shadows /all /quiet"
                New file created: "HOW_TO_DECRYPT_README.txt"
                Network connection from host: 172.16.1.0/24 (internal)
Asset role:     Finance workstation — has access to financial systems
                and shared network drives
```

---

## Alert 7: The After-Hours Access

```text
SIEM Alert: Privileged Account Access Outside Business Hours
────────────────────────────────────────────────────────────────
Time:           2024-11-15 02:14:33 UTC (Saturday night)
Account:        DBA_prod (Production Database Administrator account)
Activity:       Logged into PROD-DB-01 (192.168.50.10)
                Ran queries on CustomerData.Customers table (47,000 records)
                Exported data: SELECT * output to local CSV file
                Session duration: 23 minutes
Baseline:       DBA_prod normally active Mon-Fri 08:00-18:00 UTC
                No prior weekend access in 90 days
MFA:           Enrolled and passed
Note:           No change control ticket for weekend maintenance
```

---

## Alert 8: The VPN Brute Force

```text
SIEM Alert: VPN Authentication Failures — Threshold Exceeded
────────────────────────────────────────────────────────────────
Time:           2024-11-15 08:32:11 UTC
Target service: VPN gateway (vpn.acme.com)
Source IP:      103.224.182.47 (External — Geolocation: Netherlands)
Failures:       847 authentication attempts in 4 hours
Accounts targeted: 23 different usernames (from public breach list matching
                   acme.com email format: firstname.lastname@acme.com)
Successes:      0 (no successful authentications)
Lockouts:       3 accounts locked out
MFA:            Deployed on VPN for all users
```

---

## Answer Sheet

Complete this before checking the solutions.

```text
Alert | False Positive? | NIST Category | Severity | Immediate Action | Escalation Trigger?
──────┼─────────────────┼───────────────┼──────────┼──────────────────┼────────────────────
  1   |                 |               |          |                  |
  2   |                 |               |          |                  |
  3   |                 |               |          |                  |
  4   |                 |               |          |                  |
  5   |                 |               |          |                  |
  6   |                 |               |          |                  |
  7   |                 |               |          |                  |
  8   |                 |               |          |                  |
```

---

## Scoring Guide

* **8 correct on all fields:** Excellent — ready for Tier 2 classification work
* **6–7 correct:** Good — review the cases you missed against the solution
* **4–5 correct:** Review Guide 01 and the severity matrix before proceeding
* **<4 correct:** Revisit the full classification framework section in the reading
