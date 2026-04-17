# Drill 02 Solution (Intermediate): Alert Tuning

---

## Rule 1 Solution: cmd.exe Execution (Tuned)

### Analysis

The attack events all come from **unusual parent processes** — Office documents (winword.exe), downloaded executables (from Temp directory), script hosts (wscript.exe, mshta.exe).
These are the "living off the land" (LoLBin) patterns that matter.

The FPs come from `svchost.exe` and `userinit.exe` (Windows internals) and `Git\git.exe` (developer tool).
Critically, **explorer.exe** should NOT be excluded because a user could be tricked into running a malicious file from their desktop, which spawns via explorer.exe.

### Tuned Sigma Rule

```yaml
title: cmd.exe Spawned by Suspicious Parent Process
id: d8e9f0a1-b2c3-d4e5-f6a7-b8c9d0e1f2a3
status: stable
description: |
  Detects cmd.exe execution from parent processes that are not typical system
  or application launchers. Focuses on office applications, script interpreters,
  and downloaded executables — common vectors for malicious cmd.exe spawning.

  NOT excluding explorer.exe: attackers can deliver payloads that execute via
  explorer.exe when users open malicious files.
references:
  - https://attack.mitre.org/techniques/T1059/003/
author: SOC Team
date: 2024/12/14
modified: 2024/12/14
tags:
  - attack.execution
  - attack.t1059.003
  - attack.defense_evasion
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
  filter_windows_internals:
    ParentImage|endswith:
      - '\svchost.exe'
      - '\userinit.exe'
      - '\services.exe'
      - '\smss.exe'
      - '\csrss.exe'
  filter_known_apps:
    ParentImage|contains:
      - '\Git\git.exe'
      - '\Git\git-cmd.exe'
      - '\Git\usr\bin\'
      - '\SourceTree\'
      - '\TortoiseGit\'
  condition: selection and not 1 of filter_*
fields:
  - ParentImage
  - CommandLine
  - User
  - ComputerName
falsepositives:
  - DevOps tools not covered by filter_known_apps
  - Package managers (chocolatey, winget) if not excluded
  - Terminal emulators (ConEmu, Windows Terminal) launching cmd
level: medium
```

**Estimated metrics:**

* From 847 → ~70 alerts/day (~92% reduction)
* FP rate: from ~95% to ~25%
* True positive retention: ~100% (all 4 attack events still fire)

**Why NOT exclude explorer.exe:**

* `winword.exe` spawns cmd.exe via `explorer.exe`? No — Office spawns cmd.exe directly.
* If an attacker places `malware.exe` on the desktop and the user double-clicks it, explorer.exe spawns the malware → cmd.exe. Excluding explorer.exe would miss this.

---

## Rule 2 Solution: .xyz DNS (Tuned)

### Analysis

Three categories: (1) known-good internal/business tools, (2) random/DGA-looking subdomains, (3) known-bad.
The approach:

* Whitelist specific domains confirmed as legitimate by business
* Detect high-entropy subdomain patterns (DGA indicator)
* Reference threat intel lookup for known-bad domains

### Tuned Sigma Rule

```yaml
title: Suspicious .xyz TLD DNS Query - Potential DGA or C2
id: e9f0a1b2-c3d4-e5f6-a7b8-c9d0e1f2a3b4
status: stable
description: |
  Detects DNS queries for .xyz domains that are either:
  (1) Not in the approved business domain whitelist, or
  (2) Match DGA-like patterns (high-entropy subdomain labels)

  The .xyz TLD is heavily abused by attackers for DGA C2 and phishing.
  After excluding known-legitimate business uses, remaining queries warrant
  investigation, especially those with random-looking subdomain labels.
references:
  - https://attack.mitre.org/techniques/T1568/002/
  - https://attack.mitre.org/techniques/T1071/004/
author: SOC Team
date: 2024/12/14
tags:
  - attack.command_and_control
  - attack.t1568.002
  - attack.t1071.004
logsource:
  category: dns
  product: generic
detection:
  selection_xyz:
    dns.question.name|endswith: '.xyz'
  filter_approved_domains:
    dns.question.name:
      - 'cdn.example.xyz'
      - 'assets.shopify.xyz'
      - 'login.okta.xyz'
      - 'tracking.analytics.xyz'
  condition: selection_xyz and not filter_approved_domains
fields:
  - dns.question.name
  - source.ip
  - host.name
falsepositives:
  - Newly registered legitimate business tools using .xyz TLD
  - Browser preloading/prefetch of .xyz links in email
level: low
```

**SPL version with DGA entropy detection:**

```splunk
index=security sourcetype=dns dns_query="*.xyz"
/* Exclude approved domains */
| where NOT dns_query IN (
    "cdn.example.xyz", "assets.shopify.xyz",
    "login.okta.xyz", "tracking.analytics.xyz"
  )
/* Check threat intel */
| lookup threat_intel domain AS dns_query OUTPUT malicious, threat_category, threat_confidence
/* Compute subdomain entropy as DGA indicator */
| rex field=dns_query "^(?P<subdomain>[^.]+)\."
| eval subdomain_length = len(subdomain)
/* High-entropy indicators: length > 12 chars, or contains hex-like patterns */
| eval dga_score = case(
    malicious = "true",                          100,
    match(subdomain, "^[0-9a-f]{16,}$"),         80,  /* pure hex */
    match(subdomain, "^[a-z0-9]{20,}$"),         60,  /* random alphanum */
    subdomain_length > 15,                       40,  /* very long */
    true(),                                       10)
| where dga_score >= 40 OR malicious = "true"
| eval
    alert_name = "Suspicious .xyz Domain - Possible DGA/C2",
    severity = case(dga_score >= 80, "high", dga_score >= 40, "medium", true(), "low")
| table _time, source_ip, dns_query, subdomain, dga_score, threat_category, severity
```

**Additional enrichment to reduce FPs further:**

* **Alexa/Umbrella top-1M rank**: Domains that appear in top-1M global rankings are unlikely to be C2
* **Domain age**: Newly registered domains (< 30 days) are more suspicious
* **SSL certificate transparency logs**: Known legitimate sites will have valid, CA-signed certificates

**Estimated metrics:**

* From 1,243 → ~120 alerts/day (~90% reduction)
* High-confidence DGA/C2 alerts: ~15/day
* FP rate: from ~98% to ~30%

---

## Rule 3 Solution: PowerShell Risk Model

### Risk Model Definition

| Feature | Risk Points | Rationale |
|---------|------------|-----------|
| `-encodedCommand` + base64 > 200 chars | +40 | Long encoded commands hide complex payloads |
| `-encodedCommand` + base64 < 50 chars | +5 | Short encoded cmds often legitimate |
| `DownloadString`, `DownloadFile`, `WebClient` | +50 | Download cradles are strong indicators |
| `IEX`, `Invoke-Expression` | +30 | Code execution of downloaded content |
| `Invoke-WebRequest`, `wget`, `curl` + output | +30 | Downloading files |
| `-WindowsStyle Hidden` | +20 | Hides execution from user |
| `-ExecutionPolicy Bypass` | +10 | Overrides security policy |
| `-NonInteractive -NoProfile` | +5 | Non-interactive script, not management |
| Script from `C:\Windows\Temp` or `%TEMP%` | +40 | Scripts in temp dirs are highly suspicious |
| Script from `C:\scripts\` | -20 | Known admin script path (deduct points) |
| Parent: Office apps (winword, excel, etc.) | +50 | Classic macro delivery |
| Parent: Script host (wscript, mshta) | +40 | Script chain execution |
| Outside business hours (before 7AM / after 8PM) | +15 | Unusual timing |

**Alert threshold: ≥ 50 points**

### Tuned SPL Rule

```splunk
index=security sourcetype=WinEventLog:Sysmon EventCode=1
  (process_name="powershell.exe" OR process_name="pwsh.exe")

/* Initialize risk score */
| eval risk_score = 0

/* Encoded command length */
| rex field=command_line "(?i)-(?:enc|encodedCommand)\s+(?P<b64_str>[A-Za-z0-9+/=]+)"
| eval b64_length = len(b64_str)
| eval risk_score = case(
    b64_length > 200, risk_score + 40,
    b64_length > 0 AND b64_length <= 50, risk_score + 5,
    b64_length > 50, risk_score + 20,
    true(), risk_score)

/* Download cradles */
| eval risk_score = case(
    match(command_line, "(?i)(DownloadString|DownloadFile|WebClient)"), risk_score + 50,
    true(), risk_score)
| eval risk_score = case(
    match(command_line, "(?i)(IEX|Invoke-Expression)\s"), risk_score + 30,
    true(), risk_score)
| eval risk_score = case(
    match(command_line, "(?i)(Invoke-WebRequest|wget|curl).+(-OutFile|-o\s)"), risk_score + 30,
    true(), risk_score)

/* Execution flags */
| eval risk_score = case(
    match(command_line, "(?i)-WindowsStyle\s+Hidden"), risk_score + 20,
    true(), risk_score)
| eval risk_score = case(
    match(command_line, "(?i)-ExecutionPolicy\s+Bypass"), risk_score + 10,
    true(), risk_score)

/* Script path */
| eval risk_score = case(
    match(command_line, "(?i)(\\Temp\\|\\tmp\\|\\AppData\\|%temp%)"), risk_score + 40,
    match(command_line, "(?i)C:\\scripts\\"), risk_score - 20,
    true(), risk_score)

/* Parent process */
| eval risk_score = case(
    match(parent_process, "(?i)(winword|excel|powerpnt|outlook)\.exe"), risk_score + 50,
    match(parent_process, "(?i)(wscript|mshta|cscript)\.exe"),          risk_score + 40,
    match(parent_process, "(?i)(regsvr32|rundll32|msiexec)\.exe"),       risk_score + 30,
    true(), risk_score)

/* Time context */
| eval hour = tonumber(strftime(_time, "%H"))
| eval risk_score = if(hour < 7 OR hour > 20, risk_score + 15, risk_score)

/* Filter: alert only high risk */
| where risk_score >= 50

| eval severity = case(
    risk_score >= 100, "critical",
    risk_score >= 70, "high",
    true(), "medium")
| table _time, host, user, process_name, parent_process, command_line, risk_score, severity
| sort -risk_score
```

**Estimated metrics:**

* From 2,105 → ~40 alerts/day (~98% reduction)
* FP rate: from ~98% to ~10%
* True positive retention: all malicious download cradle events still fire (risk ≥ 80)

---

## Task 4: Sample Completed Tuning Record

```markdown
## Alert Tuning Record

**Rule ID:** d8e9f0a1-b2c3-d4e5-f6a7-b8c9d0e1f2a3
**Rule Name:** cmd.exe Spawned by Suspicious Parent Process
**Analyst:** SOC Team
**Date:** 2024-12-14

### Pre-Tuning Metrics
- Alert volume: 847 alerts/day
- Estimated FP rate: ~95%
- True positives/day: ~42
- Analyst investigation time/day: ~28 hours (20 min/alert × 847 × 0.1 investigated)

### FP Root Cause Analysis
1. Windows internals (svchost.exe, userinit.exe): 344 alerts/day (41%)

   - svchost spawns cmd.exe during system tasks, entirely benign
2. Developer Git tools (Git\git.exe): 143 alerts/day (17%)
   - Git for Windows extensively uses cmd.exe for git operations
3. Application launchers (explorer.exe, AppLaunch.exe): 89 alerts/day (10%)
   - Normal user activity opening command prompt from Start menu

### Tuning Changes Applied
1. Excluded Windows system parents (svchost.exe, userinit.exe, services.exe, smss.exe, csrss.exe)

   - Rationale: These processes are never compromised to spawn malicious cmd.exe
   - Impact: -344 FPs/day
2. Excluded Git/version-control tool parents
   - Rationale: Confirmed with development team; Git routinely uses cmd.exe
   - Impact: -143 FPs/day
   - Note: Added to whitelist lookup table for dynamic management
3. Did NOT exclude explorer.exe
   - Rationale: Attackers can deliver payloads that execute via explorer.exe
     (e.g., user double-clicking malicious attachment saved to desktop)
   - This preserves detection of the most common delivery vector

### Post-Tuning Metrics (Estimated)
- Alert volume: ~70 alerts/day (91.7% reduction)
- Estimated FP rate: ~25%
- True positives/day: ~42 (100% retention of attack detections)

### Validation
- [x] Rule tested against known-good attack simulation events (all 4 fire)
- [x] All required attack events still trigger the rule
- [x] Whitelist/exclusion list documented and reviewed by team lead

### Risks Introduced
1. If an attacker compromises a svchost.exe instance and spawns cmd.exe from it,

   we would miss the detection. Mitigated by: Sysmon process injection detection
   (EventID 8 - CreateRemoteThread) would still fire.
2. Git tool exclusion: If an attacker renames their binary to git.exe, they'd evade
   this filter. Mitigated by: hash-based exclusion (not path-based) in production.

### Review Date
2025-01-14 (30 days post-deployment)
```
