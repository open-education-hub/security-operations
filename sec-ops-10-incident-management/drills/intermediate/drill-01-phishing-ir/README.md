# Drill 01 (Intermediate): Full Phishing Incident Response

## Scenario

You are the Tier 2 analyst at AcmeCorp.
At 10:30 UTC, three users report they received an email from "IT Support" asking them to click a link to update their Microsoft 365 password.
Two users clicked the link.
One entered their credentials on a fake M365 login page.

You have confirmed: user K.
Martinez (Finance Manager) entered her credentials.
K.
Martinez has access to the company's financial reporting system and can view payroll data.

## Available Evidence

### Email Details

```text
From: it-support@acmecorp-helpdesk.biz
Subject: Urgent: Your M365 account requires verification
Received: 2024-11-14 10:15 UTC
Recipients: 3 users (2 clicked, 1 did not)
Phishing URL: https://login.microsoftonline-secure.biz/sso/auth
User-agent on click: Chrome/Windows (K. Martinez workstation)
```

### EDR Alerts

```text
finance-ws-033 (K. Martinez):
  10:28 - Credential entered on external site (browser history)
  10:44 - New email inbox rule created via MAPI: delete all emails containing
          "password", "account", "security alert"
  10:51 - M365 audit log: new device registered for MFA
  11:02 - SharePoint: 47 files downloaded from "Finance Reports" folder
```

### Threat Intel

```text
Domain: login.microsoftonline-secure.biz
  Registered: 2024-11-10 (4 days ago)
  VirusTotal: 22/80 vendors flag as phishing
  WHOIS: Privacy protected, Russian registrar
```

## Objectives

### Part A: Initial Assessment (20 min)

1. Classify the incident (type, severity, scope)
1. Identify all affected systems and users
1. Map to MITRE ATT&CK (minimum 3 techniques)
1. Assess GDPR notification requirement (payroll data accessed)

### Part B: Containment Plan (20 min)

1. Write a prioritized containment action list (with sequence and timing)
1. Identify which actions require IT support vs. IR analyst alone
1. Address: K. Martinez's sessions, the inbox rule, the new MFA device, the SharePoint access

### Part C: Eradication Plan (10 min)

1. What must be removed/reset?
1. How do you verify the eradication is complete?

### Part D: Evidence Documentation (10 min)

1. List all evidence to preserve (with evidence type for each)
1. Create one complete chain of custody record for the most critical piece of evidence

### Part E: Communication (15 min)

1. Write the SBAR brief for the CISO
1. Write the first paragraph of the GDPR notification to the DPA

## Hints

* The inbox rule created at 10:44 is a red flag — why would the attacker create this?
* The new MFA device registered at 10:51 means the attacker has persistent access even after a password reset
* SharePoint downloading 47 files at 11:02 is likely data exfiltration
* K. Martinez's account may be actively used by the attacker right now
