# Drill 01 (Basic): SOC Roles Identification

## Description

You are given a set of security tasks.
For each task, identify which SOC role (Tier 1, Tier 2, Tier 3, or SOC Manager) is primarily responsible for performing it.

## Objectives

* Identify the correct SOC analyst tier for different tasks.
* Understand the scope of responsibilities at each level.

## Tasks

For each of the following tasks, identify the **primary responsible role**:

1. A new alert appears in the SIEM queue showing failed login attempts. Review the alert to determine if it is a true or false positive.

1. An active malware infection has been confirmed. Analyze the malware binary to understand its capabilities and communication patterns.

1. No specific alert has fired, but you proactively search through logs for signs of attacker persistence mechanisms that might have been installed 3 weeks ago.

1. Write the monthly SOC performance report including MTTD, MTTR, and false positive rates for presentation to the CISO.

1. An L1 analyst has escalated an incident involving a compromised admin account. Investigate the full extent of the account's activity and determine what systems were accessed.

1. Configure new Splunk data inputs to start receiving logs from the newly deployed web application firewall (WAF).

1. A user calls the SOC hotline saying their computer is acting strange. Log the report and create an initial ticket.

## Hints

* Tier 1 focuses on **volume work**: reviewing the alert queue, initial classification, first response.
* Tier 2 focuses on **depth**: investigating individual incidents in detail.
* Tier 3 focuses on **expertise and proactivity**: hunting, advanced analysis.
* The SOC Manager focuses on **operations and reporting**: metrics, people management, strategy.

## Submission

Write your answers in the format:

```text
Task 1: [Role] — [Brief reason]
Task 2: [Role] — [Brief reason]
...
```
