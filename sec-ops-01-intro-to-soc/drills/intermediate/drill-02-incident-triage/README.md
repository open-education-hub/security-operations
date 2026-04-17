# Drill 02 (Intermediate): Incident Triage and Escalation Report

## Description

You receive a complex, multi-step security incident.
Using the provided logs and context, perform a complete triage and write a formal escalation report for the incident response team.

## Objectives

* Correlate multiple alerts into a single incident narrative.
* Write a professional-quality incident escalation report.
* Map the attack chain to MITRE ATT&CK techniques.
* Identify containment priorities.

## Background

Your SOC has received three related alerts within 20 minutes.
Your job is to determine if they are related, assess the severity of the combined incident, and escalate with a complete picture.

## Alert 1

```text
Time:     2024-03-15 22:05:00
Rule:     Geo-anomaly Login
User:     finance_tom
Host:     WKSTN-FIN-003
Details:  Successful login from 45.142.212.100 (geolocation: Russia)
          User's normal login location: Netherlands
Severity: High
```

## Alert 2

```text
Time:     2024-03-15 22:09:00
Rule:     Mass File Access
User:     finance_tom
Host:     FILESERVER-FIN
Details:  User accessed 847 files in the /Finance/Q1-Reports/ directory
          Normal baseline: 12 file accesses per hour
Severity: High
```

## Alert 3

```text
Time:     2024-03-15 22:18:00
Rule:     Large Outbound Transfer
Host:     WKSTN-FIN-003
Details:  2.3GB transferred to 185.220.101.34 (Tor exit node) over port 443
Severity: Critical
```

## Context Information

* `finance_tom` is an accountant who works Monday-Friday, 08:00-17:00.
* The /Finance/Q1-Reports/ directory contains sensitive financial data for the upcoming quarterly report.
* WKSTN-FIN-003 is finance_tom's primary workstation.
* 185.220.101.34 is flagged in multiple threat intelligence feeds as a Tor exit node used for data exfiltration.

## Your Tasks

1. **Correlate the alerts**: Are all three related? What is the attack narrative?
1. **Assess severity**: What is the combined incident severity?
1. **Map to MITRE ATT&CK**: Identify at least 3 applicable techniques.
1. **Identify what data may have been compromised**.
1. **Write a formal escalation report** (see template below).

## Escalation Report Template

```text
INCIDENT ESCALATION REPORT
===========================
Incident ID:          INC-[DATE]-[NUMBER]
Analyst:              [Your Name]
Date/Time:            [Current]
Classification:       [True Positive / False Positive / Needs Investigation]
Severity:             [Critical / High / Medium / Low]

SUMMARY:
[2-3 sentence executive summary of the incident]

TIMELINE OF EVENTS:
[Chronological list of events with timestamps]

AFFECTED ASSETS:
[List of affected systems, users, data]

ATTACK NARRATIVE:
[Explanation of what likely happened, in plain language]

MITRE ATT&CK MAPPING:
[List of applicable techniques with IDs]

POTENTIAL IMPACT:
[What data/systems may have been compromised]

RECOMMENDED IMMEDIATE ACTIONS:
[Numbered list of containment actions]

ESCALATION TO:
[Who should receive this report]
```

## Hints

* Think about the timeline: 22:05 → 22:09 → 22:18 (13 minutes total).
* The 22:00 timeframe is outside business hours.
* 847 files / 12 normal = ~70x the normal rate.
* 2.3GB in ~10 minutes over Tor = deliberate exfiltration.
* Consider whether `finance_tom`'s credentials were stolen or if they are the insider threat.
