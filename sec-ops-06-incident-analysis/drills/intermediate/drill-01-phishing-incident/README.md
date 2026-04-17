# Drill 01 (Intermediate): Full Phishing Incident Investigation

**Level:** Intermediate

**Time:** 60–90 minutes

**Environment:** Docker (log analysis environment)

---

## Overview

You are a Tier 2 SOC analyst.
A P3 alert has been escalated to you after a Tier 1 analyst confirmed initial malicious activity.
Your job is to conduct a complete investigation: scope the incident, build the timeline, identify all affected assets, and produce an investigation report.

---

## Lab Setup

```console
cd drills/intermediate/drill-01-phishing-incident
docker compose up -d
```

Access the log analysis environment:

```text
Kibana: http://localhost:5601  (elastic / changeme)
```

Verify data is loaded:

```console
docker exec drill01-loader python3 /tools/verify_data.py
```

---

## Scenario Background

**Organization:** MedTech Solutions — a healthcare technology company

**Environment:** Windows Active Directory, `medtech.local`

**Date:** 2024-11-18

**Alert time:** 11:15 UTC

**Available systems:**

```text
WS-KBAKER      10.10.1.45    Karen Baker — Senior HR Manager
WS-DPATEL      10.10.1.67    Dev Patel — IT Helpdesk
WS-ADMIN       10.10.1.88    IT Admin workstation (shared)
HR-SRV01       10.10.2.10    HR Server (employee PII: 2,800 records)
AD-SRV01       10.10.2.5     Active Directory Domain Controller
MAIL01         10.10.2.20    Mail Server
```

**Initial alert:**

```text
SIEM Alert: Office Process Spawning Shell
Time:      2024-11-18 11:08:42 UTC
Host:      WS-KBAKER (10.10.1.45)
User:      MEDTECH\kbaker
Process:   WINWORD.EXE → POWERSHELL.EXE -W Hidden -Enc [base64]
Rule:      Office macro execution detection
Severity:  P3 (Medium) — initial classification by Tier 1
Tier 1 note: "Appears to be real. Macro execution confirmed. Escalating."
```

---

## Your Investigation Tasks

### Task 1: Validate and Upgrade Severity (10 minutes)

Using the logs available, answer:

**1a.** What was the phishing email subject and sender domain?
Query the email logs:

```text
index=email to_address="*kbaker*" earliest="2024-11-17" latest="2024-11-19"
```

**1b.** What did the macro execute?
Decode the Base64 PowerShell command:

```console
docker exec drill01-loader python3 /tools/decode_ps.py
```

**1c.** Based on what you find, what should the severity be upgraded to?
Justify.

---

### Task 2: Scope — Find All Victims (15 minutes)

**2a.** Check if the same phishing campaign targeted other users:

```text
index=email
| where like(subject, "%") AND (spf_result="FAIL" OR dkim_result="FAIL")
| stats count by to_address, subject, sender_ip
| sort -count
```

**2b.** For each user who received the phishing email, check proxy logs for link clicks:

```text
index=proxy
| where like(uri, "%[phishing domain from email]%")
| stats count by user, dest_ip
```

**2c.** Check which hosts have an active C2 connection to the attacker IP you found:

```text
index=firewall dest_ip="[C2 IP from decoded PowerShell]"
| stats count, values(src_ip) as infected_hosts
```

---

### Task 3: Build the Attack Timeline (20 minutes)

Collect evidence from all log sources and construct a timeline:

```text
index=* host IN ("WS-KBAKER", "WS-DPATEL", "HR-SRV01", "AD-SRV01")
earliest="2024-11-18T11:00:00" latest="2024-11-18T14:00:00"
| table _time, host, sourcetype, EventID, User, CommandLine, dest_ip
| sort _time
```

Organize your findings into this timeline structure:

```text
DateTime (UTC)  | System    | Source  | Event              | Phase      | ATT&CK
────────────────┼───────────┼─────────┼────────────────────┼────────────┼────────
                |           |         |                    |            |
                |           |         |                    |            |
```

---

### Task 4: Check for Lateral Movement (15 minutes)

**4a.** Has the attacker pivoted from WS-KBAKER to any server?

```text
index=winlogs EventCode=4624 Logon_Type=3 Source_Network_Address="10.10.1.45"
| table _time, Account_Name, ComputerName, Logon_Type
| sort _time
```

**4b.** Check for authentication attempts to HR-SRV01 and AD-SRV01 from any compromised host during the incident window.

**4c.** If lateral movement is confirmed, map to ATT&CK and update your severity assessment.

---

### Task 5: Assess Data Exposure (10 minutes)

**5a.** Check HR-SRV01 file access logs:

```text
index=winlogs EventCode=4663 ComputerName="HR-SRV01"
| where like(Object_Name, "%\\HR\\%") OR like(Object_Name, "%employee%") OR like(Object_Name, "%PII%")
| table _time, Account_Name, Object_Name, Access_Mask
| sort _time
```

**5b.** Check for large outbound transfers from HR-SRV01:

```text
index=firewall src_ip="10.10.2.10"
| where NOT (cidrmatch("10.10.0.0/16", dest_ip))
| eval size_mb = round(bytes_out / 1048576, 2)
| where size_mb > 1
| table _time, dest_ip, dest_port, size_mb
| sort -size_mb
```

**5c.** HR-SRV01 holds 2,800 employee PII records.
Based on your findings, what is the data breach notification status?

---

### Task 6: Document Your Findings (10 minutes)

Complete the incident report below with your findings:

```markdown
INCIDENT INVESTIGATION REPORT
==============================
Incident ID:        INC-2024-[assign one]
Analyst:            [Your name]
Date of report:     2024-11-18

INCIDENT SUMMARY
─────────────────────────────────────────────────────────────
[2-3 sentence summary of what happened]

CONFIRMED AFFECTED SYSTEMS
─────────────────────────────────────────────────────────────
System | IP | Status | Evidence
       |    |        |

CONFIRMED AFFECTED ACCOUNTS
─────────────────────────────────────────────────────────────
Account | Type | Status | Actions Required
        |      |        |

ATTACK TIMELINE
─────────────────────────────────────────────────────────────
[Insert your timeline here]

INDICATORS OF COMPROMISE
─────────────────────────────────────────────────────────────
Type | Value | Context
     |       |

ATT&CK TECHNIQUES OBSERVED
─────────────────────────────────────────────────────────────
ID | Technique | Tactic | Evidence
   |           |        |

DATA EXPOSURE ASSESSMENT
─────────────────────────────────────────────────────────────
Data type:      [Employee PII — 2,800 records]
Accessed:       [YES / NO / UNKNOWN]
Exfiltrated:    [YES / NO / UNKNOWN]
Breach notification required: [YES / NO / INVESTIGATE FURTHER]

IMMEDIATE ACTIONS TAKEN
─────────────────────────────────────────────────────────────
[ ] [List containment actions]

RECOMMENDED NEXT STEPS
─────────────────────────────────────────────────────────────

1. [List remediation items]
```

---

## Docker Compose File

```yaml
# docker-compose.yml generated for this drill
# See solutions/drill-01-solution/ for expected findings
```

---

## Cleanup

```console
docker compose down -v
```
