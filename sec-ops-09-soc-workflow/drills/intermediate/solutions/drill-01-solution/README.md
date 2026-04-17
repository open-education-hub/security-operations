# Solution: Drill 01 — Playbook Writing (Account Lockout Investigation)

## Part A: Playbook Design Document

### Trigger
**Alert type:** ACCOUNT_LOCKOUT

**Trigger condition:** Any account lockout event from the SIEM

### Automated Steps

1. **Query Active Directory** for username: Get display name, department, manager, last login, account status, group memberships (especially privileged groups)
1. **Retrieve lockout source IPs** from SIEM (failed authentication events in the 30 min before lockout)
1. **Categorize source IPs**: Internal (RFC1918) vs External
1. **Enrich external IPs** with VirusTotal + AbuseIPDB
1. **Check internal IP host** against CMDB — is it the user's assigned workstation?
1. **Calculate risk score** based on enrichment
1. **Branch on risk score:**
   * Low risk (known workstation, no external IPs, single source) → Create low-priority case, suggest "user forgot password", prompt analyst for quick confirm-or-escalate
   * High risk (external IPs, multiple sources, malicious IPs, privileged account) → Create P1/P2 case, assign to Tier 2, notify SOC manager

### Human Approval Required For

* Unlocking the account
* Forcing password reset
* Blocking source IPs (for external attacks)

---

## Part B: Playbook Pseudocode

```yaml
name: "Account Lockout Investigation"
version: "1.0"
author: "SOC Team"
last_reviewed: "2024-11-14"

trigger:
  type: siem_alert
  condition: alert_type == "ACCOUNT_LOCKOUT"

inputs:
  - field: username
    description: Locked-out account username
  - field: lockout_time
    description: Timestamp of lockout
  - field: source_workstation
    description: Reported workstation from AD lockout event
  - field: failed_attempt_count
    description: Number of failed attempts before lockout
  - field: failed_attempt_ips
    description: List of source IPs from failed auth events
  - field: domain
    description: AD domain

steps:
  step_1:
    name: "Query Active Directory"
    action: ad_get_user
    input: username, domain
    output:
      - display_name
      - department
      - manager_email
      - last_successful_login
      - is_privileged (bool: member of Domain Admins, Administrators, etc.)
      - account_enabled

  step_2:
    name: "Categorize Source IPs"
    action: python_script
    input: failed_attempt_ips
    logic: |
      external_ips = [ip for ip in failed_attempt_ips if not is_rfc1918(ip)]
      internal_ips = [ip for ip in failed_attempt_ips if is_rfc1918(ip)]
    output:
      - external_ips: list
      - internal_ips: list
      - has_external: bool

  step_3:
    name: "Enrich External IPs"
    action: conditional
    condition: has_external == true
    if_true:
      action: virustotal_and_abuseipdb_bulk
      input: external_ips
      output: ip_scores (dict: ip -> score)
    if_false:
      output: ip_scores = {}

  step_4:
    name: "Check Internal IP Against CMDB"
    action: cmdb_lookup
    input: internal_ips[0] (primary internal source)
    output:
      - assigned_to_user
      - is_users_own_machine (bool)

  step_5:
    name: "Calculate Risk Score"
    action: python_script
    logic: |
      score = 0
      if has_external: score += 5
      if max(ip_scores.values(), default=0) > 10: score += 3
      if is_privileged: score += 3
      if not is_users_own_machine: score += 2
      if failed_attempt_count > 20: score += 1
    output: risk_score (0-14)

  step_6:
    name: "Risk Branch"
    type: condition
    condition: risk_score >= 5 OR is_privileged == true

    high_risk_path:
      step_6a:
        name: "Create High-Priority Case"
        action: thehive_create_case
        input:
          title: "Account Lockout — POSSIBLE ATTACK — {username}"
          severity: HIGH (P2) or CRITICAL (P1 if privileged)
          description: |
            Automated enrichment summary:
            User: {display_name} ({department})
            Failed attempts: {failed_attempt_count}
            External IPs: {external_ips}
            VT scores: {ip_scores}
            Risk score: {risk_score}/14
          tags: [account-lockout, external-brute-force, automated]
          assign_to: Tier2
      step_6b:
        name: "Notify Tier 2 and Manager"
        action: send_notification
        recipients: [soc-team-channel, users_manager_email]

    low_risk_path:
      step_6c:
        name: "Create Low-Priority Case with Quick-Triage prompt"
        action: thehive_create_case
        input:
          title: "Account Lockout — Likely User Error — {username}"
          severity: LOW (P4)
          description: |
            Source: {source_workstation} (user's own machine: {is_users_own_machine})
            Risk score: {risk_score}/14 — Low risk
            Suggested action: Contact user to confirm, reset password if needed
          tags: [account-lockout, low-risk, automated]
          assign_to: Tier1

outputs:
  - risk_score
  - case_id
  - action_taken ("escalated_p1" | "escalated_p2" | "low_risk_triage")
  - enrichment_report
```

---

## Part C: Time Analysis

| Step | Manual Time | Automated? | Automated Time | Human Gate? |
|------|------------|------------|----------------|-------------|
| Read alert | 2 min | Yes (auto-enrichment pre-populates) | 0 min | No |
| AD lookup | 3 min | Yes (step 1) | ~3 sec | No |
| Check active sessions | 2 min | Yes (step 4 via CMDB) | ~5 sec | No |
| Enrich source IPs | 5 min | Yes (steps 2-3) | ~15 sec | No |
| Triage decision | 2 min | Semi (risk score presented) | < 30 sec analyst review | Yes (confirm/escalate) |
| **Total** | **12 min** | | **~1 min** | **Analyst quick review** |

**Time savings: ~91% reduction for standard lockout alerts**

---

## Key Design Decisions

1. **Why not auto-unlock accounts?** Automatic unlocking during an active brute force would let the attacker try again immediately. Always require human approval.

1. **Why is the low-risk path still P4 and not auto-closed?** Even with low risk scores, a human must confirm. User error today could be credential theft next time.

1. **Privileged account override:** Even a "single source, own machine" lockout of a Domain Admin is escalated. The privilege level overrides the risk score.
