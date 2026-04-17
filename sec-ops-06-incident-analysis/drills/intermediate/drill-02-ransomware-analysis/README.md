# Drill 02 (Intermediate): Ransomware Scenario Analysis

**Level:** Intermediate

**Time:** 60 minutes

**Environment:** Docker (log analysis environment)

---

## Overview

You are a SOC analyst called in at 03:15 UTC (weekend, on-call).
Multiple automated alerts have fired simultaneously.
This is a ransomware incident.
Your job is to:

1. Confirm the ransomware infection scope
1. Determine if data was exfiltrated before encryption (double extortion)
1. Identify the initial access vector
1. Preserve evidence and initiate the incident response
1. Prepare the executive briefing

---

## Lab Setup

```console
cd drills/intermediate/drill-02-ransomware-analysis
docker compose up -d
```

Access:

* Kibana: http://localhost:5602 (elastic / changeme)

---

## Scenario

**Organization:** RetailCo Ltd — a mid-size retail company

**Environment:** Windows domain `retailco.local`

**Date:** 2024-11-23 (Saturday, 03:15 UTC — all staff asleep)

```text
SYSTEMS:
  WS-01 through WS-20  — Staff workstations (192.168.10.x)
  POS-01 through POS-5 — Point-of-Sale terminals (192.168.20.x)
  FILE-SRV01          — Central file server (192.168.50.10) — ~500K customer records
  BACKUP-SRV01        — Backup server (192.168.50.20)
  DC01                — Domain Controller (192.168.50.5)
```

**Alerts firing simultaneously at 03:15 UTC:**

```text
Alert 1: Mass file modification on FILE-SRV01 — 50,000 files in 3 minutes
Alert 2: New file extensions: .retailco_enc
Alert 3: vssadmin.exe delete shadows on DC01
Alert 4: Scheduled task created on DC01 with encoded PowerShell
Alert 5: Authentication from 185.234.219.44 to VPN — succeeded at 01:02 UTC
Alert 6: Beacon traffic to 94.130.88.15 from FILE-SRV01 (started 02:18 UTC)
Alert 7: Ransom note: HOW_TO_RECOVER.html found in 847 directories
```

---

## Investigation Questions

### Section 1: Immediate Response (15 minutes)

**Q1.** List the first 5 containment actions you take in priority order.
For each, explain why it takes that priority position.

**Q2.** Alert 5 shows a successful VPN authentication from an external IP at 01:02 UTC.
What is the significance of this timestamp relative to the ransomware deployment at 03:15 UTC?
What does this tell you about the attacker's access?

**Q3.** Alert 6 shows beacon traffic starting at 02:18 UTC.
The ransomware deployed at ~03:15 UTC.
What activity likely occurred in the 57-minute window between 02:18 and 03:15?

Query beacon traffic timeline:

```text
index=firewall dest_ip="94.130.88.15" earliest="2024-11-22"
| timechart span=5m count
| where count > 0
```

**Q4.** The backup server (BACKUP-SRV01) is on the same network segment as the file server.
What is your highest priority concern about the backup server?

---

### Section 2: Scoping the Incident (15 minutes)

**Q5.** Determine which systems have the `.retailco_enc` extension on files:

```text
index=sysmon EventID=11
| where like(TargetFilename, "%.retailco_enc")
| stats count by Computer
| sort -count
```

**Q6.** Determine if all domain-joined systems were hit by checking for the scheduled task:

```text
index=sysmon EventID=1
| where like(CommandLine, "%schtasks%") AND Computer="DC01"
| table _time, CommandLine, User
```

What does a scheduled task created on the Domain Controller suggest about the attacker's privilege level?

**Q7.** The POS terminals (192.168.20.x) process payment card data.
Determine if any POS terminals were encrypted:

```text
index=sysmon EventID=11 Computer="POS-*"
| where like(TargetFilename, "%.retailco_enc")
| stats count by Computer
```

If POS terminals are encrypted, what additional regulatory notifications are required?

---

### Section 3: Initial Access Investigation (15 minutes)

**Q8.** Alert 5 shows VPN authentication from `185.234.219.44` succeeding at 01:02 UTC.
Investigate which account was used:

```text
index=vpn_logs src_ip="185.234.219.44"
| table _time, username, src_ip, auth_result, mfa_used
| sort _time
```

**Q9.** Once you know the account used for VPN access, check its recent authentication history:

```text
index=winlogs EventCode=4624 Account_Name="[VPN USER]"
| where Source_Network_Address != "192.168.0.0/16"
| table _time, Source_Network_Address, ComputerName, Logon_Type
| sort _time
```

Was this VPN login the first external authentication for this account?
If not, when did external access begin?

**Q10.** Determine the initial infection vector.
Hint: Look at email logs for the VPN user's account in the 7 days before the incident:

```text
index=email to_address="*[vpn user]@retailco.com*" earliest="2024-11-16"
| table _time, from_address, subject, attachment_name, spf_result
| sort -_time
```

---

### Section 4: Double Extortion Assessment (10 minutes)

**Q11.** Before deploying ransomware, attackers that use double extortion exfiltrate data.
Check for large outbound transfers from FILE-SRV01 in the 24 hours before encryption:

```text
index=firewall src_ip="192.168.50.10"
| where NOT cidrmatch("192.168.0.0/16", dest_ip)
| eval size_gb = round(bytes_out / 1073741824, 2)
| where size_gb > 0.1
| table _time, dest_ip, dest_port, size_gb
| sort _time
```

**Q12.** If data was exfiltrated, what is the scope of the data breach in addition to the ransomware?

* FILE-SRV01 contains ~500,000 customer records (name, email, purchase history, some payment tokens)
* What regulatory frameworks apply?
* What is the notification timeline?

---

### Section 5: Executive Briefing (5 minutes)

**Q13.** Write a 5-bullet executive briefing for the CEO.
Cover:

1. What happened (non-technical)
1. Business impact
1. Current status
1. What you're doing about it
1. Decision needed from leadership

---

## Answer Template

```text
RANSOMWARE INCIDENT ANALYSIS — RetailCo Ltd
============================================
Analyst: [Name]
Date: 2024-11-23

Q1 - Top 5 containment actions:

1. [Action] — Reason:

2. [Action] — Reason:
3. [Action] — Reason:
4. [Action] — Reason:
5. [Action] — Reason:

Q2 - VPN access significance:
[Your analysis]

Q3 - 02:18-03:15 attacker activity:
[Your analysis]

Q4 - Backup server concern:
[Your analysis]

Q5 - Encrypted systems:
[List]

Q6 - Scheduled task significance:
[Your analysis]

Q7 - POS terminal status + regulatory:
[Your analysis]

Q8-Q10 - Initial access chain:
[Your analysis]

Q11-Q12 - Exfiltration findings:
[Your analysis]

Q13 - Executive briefing:
•
•
•
•
•
```
