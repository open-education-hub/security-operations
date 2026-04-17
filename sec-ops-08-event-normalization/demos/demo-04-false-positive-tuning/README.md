# Demo 04: Tuning Detection Rules to Reduce False Positives

**Duration:** ~40 minutes

**Difficulty:** Intermediate–Advanced

**Prerequisites:** Demos 01–03 completed, Splunk or Elasticsearch running

---

## Overview

Every detection rule starts noisy.
This demo walks through a systematic process for reducing false positives without sacrificing true positive detection.
You will:

1. Start with an intentionally noisy detection rule
1. Analyze the false positive distribution using aggregation queries
1. Apply three tuning techniques: threshold adjustment, scope narrowing, and contextual enrichment
1. Validate that the tuned rule still fires on real attack simulations
1. Document the tuning decision for future reference

---

## Scenario Setup

### The Problem

Your SOC deployed a rule to detect `net.exe` and `net1.exe` execution (potential reconnaissance and lateral movement preparation).
Within 24 hours it fired **847 times** — far more than the team can investigate.

### Noisy Rule (Pre-Tuning)

```splunk
# Rule: net.exe Execution Detected
# FP Rate: ~95% (very noisy)
# Alert count: 847/day

index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| table _time, host, user, process_name, command_line, parent_process
```

---

## Step 1: FP Analysis — Understand the Noise

Before tuning, understand *why* the rule is noisy.

### Analysis Query 1: Command Line Frequency

```splunk
index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| stats count BY command_line
| sort -count
| head 20
```

**Expected output reveals legitimate use cases:**

```text
count  command_line
412    net use \\server\share
198    net time /domain
87     net start "Print Spooler"
62     net view
43     net localgroup administrators
22     net group "Domain Admins" /domain   ← suspicious
14     net user administrator /active:no    ← suspicious
9      net share C$ /unlimited             ← suspicious
```

### Analysis Query 2: Parent Process Distribution

```splunk
index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| stats count BY parent_process
| sort -count
```

**Expected output:**

```text
count  parent_process
389    services.exe       ← legitimate Windows services
201    mmc.exe            ← Microsoft Management Console
107    explorer.exe       ← manual user execution
52     cmd.exe            ← could be legitimate or malicious
31     powershell.exe     ← higher risk parent
18     wscript.exe        ← higher risk parent (script execution)
```

### Analysis Query 3: User Context Distribution

```splunk
index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| stats count BY user
| sort -count
| eval user_type = case(
    match(user, "(?i)svc-|service|backup|nessus|sccm"), "service_account",
    match(user, "(?i)SYSTEM|LOCAL SERVICE|NETWORK SERVICE"), "system_account",
    true(), "regular_user")
| stats sum(count) AS total BY user_type
```

### Analysis Query 4: Time-of-Day Distribution

```splunk
index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| eval hour_of_day = strftime(_time, "%H")
| stats count BY hour_of_day
| sort hour_of_day
```

---

## Step 2: Tuning Iteration 1 — Exclude Known-Good Parent Processes

**Hypothesis**: Most FPs come from legitimate parents (`services.exe`, `mmc.exe`).

```splunk
# Rule v1.1 — Added parent process exclusions
# FP Rate estimate: ~60% (still noisy)

index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| where NOT parent_process IN (
    "services.exe",
    "mmc.exe",
    "wmiprvse.exe",
    "svchost.exe"
  )
| table _time, host, user, process_name, command_line, parent_process
```

---

## Step 3: Tuning Iteration 2 — Focus on High-Risk Commands

**Hypothesis**: Only certain `net.exe` command patterns are truly suspicious — specifically those relating to domain enumeration and account manipulation.

```splunk
# Rule v1.2 — Focused on suspicious command patterns
# FP Rate estimate: ~20% (getting better)

index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| where NOT parent_process IN ("services.exe", "mmc.exe", "wmiprvse.exe", "svchost.exe")
| where match(command_line, "(?i)(?:/domain|group|localgroup|user.*\/add|share.*\$|accounts)")
| where NOT match(command_line, "(?i)net\s+time|net\s+use\s+[A-Z]:|net\s+start")
| table _time, host, user, process_name, command_line, parent_process
```

---

## Step 4: Tuning Iteration 3 — Contextual Risk Scoring

Instead of binary allow/deny, assign a risk score and only alert on high-risk combinations.

```splunk
# Rule v1.3 — Risk score model
# FP Rate estimate: ~5% (production-ready)

index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| eval risk_score = 0

  /*=== Parent Process Risk ===*/
| eval risk_score = case(
    parent_process IN ("wscript.exe", "cscript.exe", "mshta.exe"), risk_score + 40,
    parent_process IN ("powershell.exe", "cmd.exe"),               risk_score + 20,
    parent_process IN ("explorer.exe"),                            risk_score + 5,
    true(),                                                        risk_score + 0)

  /*=== Command Pattern Risk ===*/
| eval risk_score = case(
    match(command_line, "(?i)(group.*domain|user.*\/add|localgroup.*admin)"), risk_score + 40,
    match(command_line, "(?i)(accounts|share.*\$|session|computer)"),         risk_score + 20,
    match(command_line, "(?i)(view|time|use)"),                               risk_score + 0,
    true(),                                                                   risk_score + 10)

  /*=== User Context Risk ===*/
| eval risk_score = case(
    match(user, "(?i)SYSTEM|NETWORK SERVICE"),                risk_score + 0,
    match(user, "(?i)svc-|service|backup"),                   risk_score + 0,
    match(user, "(?i)administrator|admin"),                   risk_score + 15,
    true(),                                                    risk_score + 10)

  /*=== Time Context Risk ===*/
| eval hour = tonumber(strftime(_time, "%H"))
| eval day_of_week = strftime(_time, "%u")  /* 1=Mon, 7=Sun */
| eval is_business_hours = if(
    (day_of_week >= 1 AND day_of_week <= 5) AND (hour >= 8 AND hour <= 18),
    1, 0)
| eval risk_score = if(is_business_hours = 0, risk_score + 20, risk_score)

  /*=== Alert on high risk ===*/
| where risk_score >= 50

| eval severity = case(
    risk_score >= 80, "critical",
    risk_score >= 60, "high",
    true(), "medium")
| table _time, host, user, process_name, command_line, parent_process, risk_score, severity
| sort -risk_score
```

---

## Step 5: Validate Tuned Rule Against Attack Simulation

Verify the tuned rule still fires on real attacks.

### Simulated Attack Scenario

```console
# sample-data/attack_simulation.csv — mimics a real lateral movement scenario
# Add to Splunk: docker cp sample-data/attack_simulation.csv demo03-splunk:/tmp/
```

```csv
_time,host,user,process_name,parent_process,command_line,pid,ppid
2024-12-14T02:15:00Z,WORKSTATION01,administrator,net.exe,powershell.exe,"net group ""Domain Admins"" /domain",5000,4999
2024-12-14T02:15:05Z,WORKSTATION01,administrator,net.exe,powershell.exe,"net user administrator /active:no",5001,4999
2024-12-14T02:15:10Z,WORKSTATION01,administrator,net.exe,powershell.exe,"net localgroup administrators attacker_user /add",5002,4999
2024-12-14T02:15:15Z,WORKSTATION01,administrator,net1.exe,powershell.exe,"net1 accounts /domain",5003,4999
```

**Run validation:**

```splunk
# Run the tuned rule against attack simulation data
index=security sourcetype=csv_attack_sim process_name IN ("net.exe", "net1.exe")
| eval risk_score = 0
| eval risk_score = case(
    parent_process IN ("wscript.exe", "cscript.exe", "mshta.exe"), risk_score + 40,
    parent_process IN ("powershell.exe", "cmd.exe"),               risk_score + 20,
    parent_process IN ("explorer.exe"),                            risk_score + 5,
    true(),                                                        risk_score + 0)
| eval risk_score = case(
    match(command_line, "(?i)(group.*domain|user.*\/add|localgroup.*admin)"), risk_score + 40,
    match(command_line, "(?i)(accounts|share.*\$|session|computer)"),         risk_score + 20,
    true(),                                                                   risk_score + 10)
| eval risk_score = if(tonumber(strftime(_time, "%H")) < 8 OR tonumber(strftime(_time, "%H")) > 18, risk_score + 20, risk_score)
| where risk_score >= 50
| table _time, host, user, command_line, risk_score
```

**Expected: All 4 attack simulation events fire (risk scores 60–100).**

---

## Step 6: Using Lookup Tables for Dynamic Whitelisting

Instead of hardcoding exclusions, use a lookup table that can be updated without modifying the rule.

### lookups/authorized_admin_hosts.csv

```csv
host,authorized_admin_account,reason
JUMPBOX01,admin_ops,"Authorized jump host for IT operations"
MGMT-SRV01,svc-backup,"Backup server uses net.exe for network shares"
SCCM-SRV01,svc-sccm,"SCCM deployment server"
```

```splunk
# Load the lookup table
| inputlookup authorized_admin_hosts.csv

# Use it in the rule
index=security sourcetype=csv_process process_name IN ("net.exe", "net1.exe")
| lookup authorized_admin_hosts host OUTPUT authorized_admin_account, reason AS whitelist_reason
| where isnull(whitelist_reason)  /* Exclude whitelisted hosts */
| [... rest of the risk scoring ...]
```

---

## Step 7: Documenting the Tuning Decision

Always document tuning changes in the rule metadata:

```yaml
# Updated Sigma rule with tuning documentation
title: Net.exe Domain Reconnaissance
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: stable
description: |
  Detects use of net.exe/net1.exe for domain reconnaissance commands.
  Focuses on high-risk command patterns and parent processes.
author: SOC Team
date: 2024/12/14
modified: 2024/12/14
version: "1.3"
tuning_history:
  - version: "1.0"
    date: "2024-12-01"
    fp_rate: "95%"
    alert_volume: "847/day"
    description: "Initial rule — all net.exe execution"
  - version: "1.1"
    date: "2024-12-07"
    fp_rate: "60%"
    alert_volume: "350/day"
    description: "Excluded services.exe, mmc.exe, wmiprvse.exe parents"
  - version: "1.2"
    date: "2024-12-10"
    fp_rate: "20%"
    alert_volume: "85/day"
    description: "Focused on domain enum and account manipulation commands"
  - version: "1.3"
    date: "2024-12-14"
    fp_rate: "5%"
    alert_volume: "8/day"
    description: "Added risk scoring model with time-of-day and user context"
```

---

## Tuning Results Summary

| Version | Alert Volume | FP Rate | True Positives/Day | Change |
|---------|-------------|---------|-------------------|--------|
| v1.0 | 847 | ~95% | ~42 | Baseline (too noisy) |
| v1.1 | 350 | ~60% | ~40 | Exclude safe parents |
| v1.2 | 85 | ~20% | ~38 | Focus suspicious commands |
| v1.3 | 8 | ~5% | ~7–8 | Risk scoring + time/user context |

The final tuned rule reduced alert volume by **99%** while retaining **~80% of true positive detections** that require investigation.

---

## Key Takeaways

1. Always analyze the false positive distribution before tuning — understand *why* it's noisy.
1. Use aggregation queries to find the most common FP patterns (parent process, command, time).
1. Risk scoring (additive model) is more nuanced than binary filtering — it preserves marginal cases.
1. Validate tuned rules against known-attack data before deploying to production.
1. Document every tuning decision with before/after metrics — this builds institutional knowledge.
1. Use lookup tables for dynamic whitelists that IT operations can update without rule changes.
1. The goal is a manageable alert volume with acceptable true positive rate, not zero alerts.
