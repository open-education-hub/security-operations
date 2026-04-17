# Guide 03 (Basic): Understanding the Alert Workflow

## Objective

Create a complete alert workflow in Splunk: from writing a detection query to triggering an alert and documenting a triage decision.

## Prerequisites

* Completed Guides 01 and 02.
* Sample auth logs ingested in Splunk.

## Background

An alert workflow has three phases:

1. **Detection**: A SIEM rule fires when suspicious conditions are met.
1. **Triage**: An analyst reviews the alert and determines its validity.
1. **Action**: The analyst closes, escalates, or responds to the alert.

## Steps

### Step 1: Write a Brute Force Detection Rule

We want to detect when an IP address has 5 or more failed login attempts.

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 5
| sort -failed_attempts
```

Run this query and verify it returns `192.168.1.100` with 5 failed attempts.

### Step 2: Save as Alert

1. With the query from Step 1 running, click **Save As → Alert**.
1. Configure the alert:
   * **Title**: `Brute Force - SSH Login Failures`
   * **Description**: `Detects when a single IP has 5+ failed SSH login attempts`
   * **Alert Type**: Scheduled
   * **Schedule**: Run Every 5 Minutes
   * **Expires**: 24 hours
1. Under **Trigger Conditions**:
   * Trigger when: Number of Results is greater than 0
1. Under **Trigger Actions**:
   * Click **Add Actions → Add to Triggered Alerts**
   * Severity: High
1. Click **Save**.

### Step 3: Simulate the Alert Firing

To see the alert in action, navigate to **Activity → Triggered Alerts**.

If your sample data matches the trigger condition, you'll see the alert listed there.

Alternatively, you can manually verify by re-running the search and confirming the results.

### Step 4: Practice Triage

Using the alert you created, work through this triage checklist:

**Alert:** `Brute Force - SSH Login Failures`

**Source IP:** `192.168.1.100`

**Failed attempts:** 5

Triage checklist:

```text
[ ] 1. Is the source IP internal or external?
        192.168.1.x = internal (RFC 1918 private range)

[ ] 2. Is the source IP known? (Check asset inventory)
        Unknown in this exercise — treat as suspicious

[ ] 3. Was the login ultimately successful?
        Query: index=main sourcetype=linux_secure "Accepted password" src_ip=192.168.1.100
        Result: YES — login succeeded after 5 failures

[ ] 4. What account was targeted?
        Account: admin (high-value target!)

[ ] 5. Determine classification:
        [ ] False Positive
        [X] True Positive

[ ] 6. Determine severity:
        [ ] Low
        [ ] Medium
        [X] High (admin account compromised)
        [ ] Critical
```

### Step 5: Document the Triage Decision

Create a triage note (this would normally go into a ticketing system):

```text
=== TRIAGE NOTE ===
Alert ID:        ALT-SSH-001
Alert Name:      Brute Force - SSH Login Failures
Analyst:         [Your Name]
Date/Time:       [Current Date/Time]

Finding:
- IP 192.168.1.100 made 5 failed SSH login attempts against user 'admin'
- One subsequent SUCCESSFUL login was observed
- This indicates a possible successful brute force attack

Classification:  TRUE POSITIVE
Severity:        HIGH

Recommended Actions:

1. Investigate what actions were taken after the successful login

2. Rotate the 'admin' SSH password immediately
3. Block 192.168.1.100 if it cannot be identified as a legitimate asset
4. Review SSH access logs for post-login activity

Escalate to:     Tier 2 Analyst
```

### Step 6: Write a Follow-up Query

After escalation, a Tier 2 analyst would investigate post-login activity:

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for (?<user>\w+) from (?<src_ip>[^\s]+)"
| where src_ip="192.168.1.100"
| table _time, status, user, src_ip
| sort _time
```

## Verification

* [ ] Alert created successfully in Splunk.
* [ ] Alert appears in Triggered Alerts.
* [ ] You completed the triage checklist.
* [ ] You wrote a triage note with classification, severity, and actions.

## Summary

You have created a complete alert workflow: detection rule → alert → triage → documentation.
This is the core day-to-day workflow for a Tier 1 SOC analyst.
Mastering this cycle — and doing it quickly and accurately — is the foundation of effective SOC operations.
