# Demo 03: Writing Correlation Rules in Splunk to Detect Multi-Step Attacks

**Difficulty:** Intermediate–Advanced

**Time:** ~50 minutes

**Prerequisites:** Demo 01 completed or Splunk instance available

## Overview

This demo focuses on **correlation rule writing** — the art of detecting multi-step attacks by combining events from multiple sources and time windows.
Single-event alerts are easy to write but generate excessive false positives.
Multi-step correlation detects entire attack sequences with much higher confidence.

We will detect a classic **office macro → PowerShell → C2 beacon** attack chain using Splunk SPL correlation searches.

## Attack Scenario Detected

```text
Step 1: User receives phishing email and opens Word document
Step 2: Word document runs a macro that spawns PowerShell
Step 3: PowerShell downloads and executes a payload
Step 4: Malware establishes HTTPS C2 connection to suspicious domain
Step 5: Malware creates scheduled task for persistence
```

Each step leaves log evidence.
Our correlation rules detect the sequence.

## Step-by-Step Instructions

### Step 1: Start the Environment

```console
docker compose up -d

# Wait for Splunk to be ready
docker compose logs -f splunk | grep "successfully"
```

Access Splunk: http://localhost:8000 (admin / SecOpsDemo123!)

### Step 2: Load Sample Attack Data

The `attack-simulator` container will load pre-crafted attack event data into Splunk via HEC.
Wait 2-3 minutes after startup, then verify:

```spl
index=main sourcetype=attack_sim | stats count by attack_step
```

You should see 5 attack steps with event counts.

### Step 3: Write Rule 1 — Office Process Spawning Scripting Engine

This detects when an Office application (Word, Excel) spawns a scripting interpreter — a hallmark of macro-based malware.

```spl
index=main sourcetype=sysmon_json EventID=1
| where (
    match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE") AND
    match(Image, "(?i)(powershell|cmd|wscript|cscript|mshta|regsvr32)\.exe")
  )
| eval attack_stage = "Execution"
| eval mitre_technique = "T1566.001 - Spearphishing Attachment"
| table _time, Computer, User, ParentImage, Image, CommandLine, attack_stage, mitre_technique
```

Save this as: **Alert: Office Application Spawned Scripting Engine**

### Step 4: Write Rule 2 — Encoded PowerShell Command

PowerShell with `-EncodedCommand` is used to obfuscate malicious scripts.
While occasionally legitimate, it is heavily abused.

```spl
index=main sourcetype=sysmon_json EventID=1 Image="*powershell*"
| where match(CommandLine, "(?i)-enc(odedcommand)?\\s+[A-Za-z0-9+/]{50,}")
| eval encoding_suspicion = if(len(CommandLine) > 300, "HIGH", "MEDIUM")
| eval mitre_technique = "T1059.001 - PowerShell"
| table _time, Computer, User, CommandLine, encoding_suspicion, mitre_technique
```

### Step 5: Write Rule 3 — Multi-Step Correlation (The Key Rule)

This rule detects the **full attack chain**: Office spawn → PowerShell connection, all within 10 minutes on the same host.

```spl
| tstats summariesonly=false count
    FROM datamodel=Endpoint.Processes
    WHERE Processes.parent_process_name IN ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE")
      AND Processes.process_name IN ("powershell.exe", "cmd.exe", "wscript.exe")
    BY Processes.dest, Processes.user, Processes.process_name,
       Processes.parent_process_name, _time span=1m

| rename Processes.* AS *
| eval phase="office_spawn"

| appendcols
    [| tstats summariesonly=false count
         FROM datamodel=Network_Traffic.All_Traffic
         WHERE All_Traffic.dest_port=443 All_Traffic.direction="outbound"
         BY All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, _time span=1m
     | rename All_Traffic.* AS *
     | eval phase="c2_connection"]

| transaction dest maxspan=10m
| where mvcount(phase) >= 2
| eval confidence = "HIGH - Multi-step pattern detected"
| eval mitre_technique = "T1566.001 → T1059.001 → T1071.001"
| table _time, dest, user, confidence, mitre_technique
```

### Step 6: Write Rule 4 — Brute Force Detection with Lockout

This detects accounts being brute-forced AND the subsequent successful logon.

```spl
index=main sourcetype=auth_events
| eval event_type=coalesce(event_type, "unknown")
| bin _time span=5m
| stats
    count(eval(event_type="failed_login"))  AS fail_count
    count(eval(event_type="successful_login")) AS success_count
    values(src_ip) AS src_ips
    BY _time, username
| where fail_count >= 10 AND success_count >= 1
| eval alert_type = "Brute Force Followed by Success"
| eval severity = "CRITICAL"
| eval mitre_technique = "T1110.001 - Password Guessing"
| table _time, username, fail_count, success_count, src_ips, alert_type, severity
```

Save as: **Alert: Brute Force Succeeded**

### Step 7: Build a Correlation Dashboard

1. In Splunk, go to **Dashboards** → **Create New Dashboard**
1. Name: "Demo 03 - Attack Correlation"
1. Add panels using the searches from Steps 3–6
1. Add a timeline panel:

```spl
index=main (sourcetype=sysmon_json OR sourcetype=auth_events)
| eval event_category=case(
    sourcetype="sysmon_json" AND EventID=1, "Process Creation",
    sourcetype="sysmon_json" AND EventID=3, "Network Connection",
    sourcetype="auth_events" AND event_type="failed_login", "Auth Failure",
    sourcetype="auth_events" AND event_type="successful_login", "Auth Success",
    true(), "Other"
  )
| timechart span=1m count by event_category
```

### Step 8: Review Alert Results

After loading the attack simulation data, run:

```spl
index=main sourcetype=attack_sim
| sort _time
| table _time, attack_step, description, host, user, details
```

This shows all the simulated attack events in chronological order.
Verify your correlation rules fired for the appropriate steps.

### Step 9: Tear Down

```console
docker compose down -v
```

## Key SPL Concepts Used

| SPL Command | Purpose |
|-------------|---------|
| `stats count BY` | Aggregation with grouping |
| `where match()` | Regex matching |
| `eval` | Field calculation and conditional logic |
| `transaction` | Group related events within a time window |
| `appendcols` | Add columns from a sub-search |
| `tstats` | Fast statistics over data models |
| `bin _time span=` | Time bucketing for threshold rules |

## Discussion Questions

1. Why does the multi-step rule (Step 5) produce fewer false positives than individual rules?
1. What is the trade-off between using `tstats` (fast) vs. raw search (flexible)?
1. How would you tune Rule 4 to reduce false positives from shared NAT IP addresses?
1. For each rule, what MITRE ATT&CK technique does it detect?
