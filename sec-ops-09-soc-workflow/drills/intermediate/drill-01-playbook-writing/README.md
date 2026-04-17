# Drill 01 (Intermediate): Playbook Writing

## Scenario

Your SOC manager has asked you to design a SOAR playbook for **account lockout investigation**.
This alert type currently takes L1 analysts an average of 12 minutes to triage.
You need to reduce it to under 2 minutes through automation.

## Background

Account lockout alerts fire when a user account is locked out due to too many failed authentication attempts.
Currently, the L1 workflow is:

1. Read alert (2 min)
1. Look up user in Active Directory (3 min)
1. Check if user is currently logged in somewhere (2 min)
1. Check SIEM for source IPs of the failed attempts (3 min)
1. Look up those IPs in VirusTotal (2 min)
1. Make triage decision (manual)

**Total manual time: ~12 minutes**

## Objectives

1. Design the full playbook (inputs, steps, decision gates, outputs)
1. Write the playbook in a structured YAML-like format
1. Identify which steps can be automated and which require human approval
1. Estimate time savings

## Alert Data Available

When this playbook is triggered, the following data is available:

```json
{
  "alert_type": "ACCOUNT_LOCKOUT",
  "username": "m.rodriguez",
  "lockout_time": "2024-11-14T10:22:14Z",
  "source_workstation": "acct-ws-022",
  "failed_attempt_count": 8,
  "failed_attempt_ips": ["192.168.10.42", "10.0.0.5"],
  "domain": "ACMECORP"
}
```

## Deliverables

### Part A: Playbook Design Document

Write a complete playbook design document including:

* Trigger definition
* All automated steps with descriptions
* Decision gates with criteria
* Branch paths (high risk vs. benign user error)
* Human approval points
* Output/closure conditions

### Part B: Playbook Pseudocode

Write the playbook in YAML-like pseudocode following this template:

```yaml
name: "Account Lockout Investigation"
version: "1.0"
trigger:
  type: ...
  condition: ...

inputs:
  - field: ...
    description: ...

steps:
  step_1:
    name: ...
    action: ...
    input: ...
    output: ...

  step_2:
    name: ...
    type: condition
    condition: ...
    true_path: ...
    false_path: ...

outputs:
  - ...
```

### Part C: Time Analysis

Fill in this table:

| Step | Manual Time | Automated? | Automated Time | Human Gate? |
|------|------------|------------|----------------|-------------|
| Read alert | 2 min | | | |
| AD lookup | 3 min | | | |
| Check active sessions | 2 min | | | |
| Enrich source IPs | 5 min | | | |
| Triage decision | 2 min | | | |
| **Total** | **12 min** | | | |

## Hints

* Account lockout from external IPs is much more suspicious than from internal workstations
* A single known workstation = user probably just forgot their password
* Multiple different source IPs = more likely a password spray attack
* Consider: what if the user's own workstation has malware doing the lockout?
* Active Directory can be queried via LDAP or SOAR AD integration
* Some SOAR platforms have built-in AD actions (Get-ADUser equivalent)

## Success Criteria

Your playbook should:

* Reduce analyst time from 12 min to < 2 min for benign cases
* Automatically escalate high-risk cases (external IPs, multiple sources) to Tier 2
* Document all enrichment data in the case automatically
* Never automatically unlock accounts (requires human approval)
