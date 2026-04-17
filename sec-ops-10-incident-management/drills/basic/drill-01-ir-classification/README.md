# Drill 01 (Basic): Incident Classification

## Scenario

You are an IR analyst at HealthCorp (hospital network, 5,000 employees, processes patient data).
You receive 6 incident reports in one day.
For each, apply the NIST 800-61 classification methodology.

## Incidents to Classify

### Incident 1
A nurse called the help desk saying her workstation is "acting weird" — it's very slow and showing pop-ups she doesn't recognize.
A quick remote look shows several unknown processes running and `cmd.exe` with an encoded command visible.

### Incident 2
An external penetration tester (engaged under a signed contract) reports they successfully extracted credentials from the HR database using a SQL injection vulnerability.
No patient data was accessed.

### Incident 3
The mail gateway blocked 847 emails from `billing@acmecorp-invoice.fake` containing a macro-enabled Excel file.
No emails were delivered to users.

### Incident 4
A sysadmin reports that `backup-srv-01` (which backs up all patient records) has no network connectivity and shows disk encryption activity.
A ransom note is visible on the screen.

### Incident 5
User D.
Kovacs in billing (who was terminated yesterday) successfully authenticated to the patient billing portal from an IP in a foreign country 2 hours ago.
IT forgot to disable his account.

### Incident 6
The IDS flagged 3,000 failed SSH login attempts targeting the external-facing jump server over 4 hours.
All attempts failed.
The source IP has been blocked automatically.

## Deliverables

For each incident, document:

1. **Incident Type** (malware, unauthorized access, data breach, DDoS, social engineering, insider threat, other)
1. **Severity** (P1/P2/P3/P4) with justification
1. **Scope** assessment (single system, department, enterprise-wide)
1. **Does this require GDPR notification?** (Yes / Possibly / No) — justify
1. **Immediate action** (what's the first thing you do?)

## Hints

* Incident 4 involves patient data on a backup server — this is healthcare data (special category under GDPR)
* Incident 5: "authorized" access to terminated employee — is this a breach? Is the data at risk?
* The hospital is an essential entity under NIS2 — stricter notification requirements
* Incident 2 is a Benign TP (pentest under contract) — but still needs documentation
