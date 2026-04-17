# Hypothesis Development Worksheet
# Security Operations Course - Session 07: Cyber Threat Hunting
# Guide 01: Step-by-Step Threat Hunting Methodology
#
# Instructions: Complete one worksheet per hypothesis before hunting.
#               A well-formed hypothesis makes the difference between
#               purposeful hunting and random log searching.
# =============================================================================

Hunt ID:   HUNT-[YYYY]-[NNN]
Date:      [YYYY-MM-DD]
Hunter:    [Your name]


## Step 1 — Identify the Threat

What threat, technique, or behavior am I investigating?

ATT&CK Technique ID:     [e.g., T1059.001]
ATT&CK Technique Name:   [e.g., Command and Scripting Interpreter: PowerShell]
ATT&CK Tactic:           [e.g., Execution]

Threat Description:
  [In 2-3 sentences: What does this technique do? How does an attacker use it?
   What makes it dangerous or hard to detect?]

Real-world examples of this technique:
  - [Threat actor or malware family]
  - [Threat actor or malware family]

Why is this relevant to MY environment now?
  [Why hunt for this technique at this time? Link to trigger from scope doc.]


## Step 2 — Define the Scope

Environment where this technique could occur:
  [e.g., "corporate Windows workstations running Office 365"]

Realistic attack scenario in my environment:
  [Describe the specific way an attacker would use this technique in your
   environment. Be concrete. "A phishing email delivers a macro-enabled
   document, the macro spawns PowerShell..." etc.]


## Step 3 — Identify Observable Evidence

What specific evidence would exist in logs IF this technique is active?

### Process-level evidence (Sysmon EventID 1 / Windows EventID 4688):
  - Parent process:     [What process spawns the malicious process?]
  - Child process:      [What process is created?]
  - Command-line flags: [What flags/arguments are suspicious?]
  - Example:            [Paste a realistic example log entry]

### Network evidence (Sysmon EventID 3 / firewall logs / proxy logs):
  - Connection pattern: [What destination? What port? What protocol?]
  - Volume/frequency:   [Beaconing? Large transfer? Unusual timing?]
  - Example:            [Paste a realistic example log entry]

### File system evidence (Sysmon EventID 11):
  - File created:       [What file, where, by what process?]
  - Example:            [Paste a realistic example log entry]

### Registry evidence (Sysmon EventID 13):
  - Key modified:       [What registry key indicates this technique?]
  - Example:            [Paste a realistic example log entry]

### Other evidence:
  - [Describe any other observable artifacts]


## Step 4 — Establish the Baseline

What does LEGITIMATE activity look like for the same log fields?

Known legitimate uses of [process/technique]:
  1. [Legitimate use case 1 — what spawns it, why, what arguments]
  2. [Legitimate use case 2]
  3. [Legitimate use case 3]

How do I distinguish malicious from legitimate?
  Key differentiators:
  - [Field/value that distinguishes malicious: e.g., "-EncodedCommand"]
  - [Field/value that distinguishes malicious: e.g., parent = WINWORD.EXE]
  - [What is NEVER seen in legitimate usage: e.g., parent = svchost.exe]

Known-good exclusions (processes to filter OUT of results):
  - [Process/pattern to exclude and why]
  - [Process/pattern to exclude and why]


## Step 5 — Define the Time Window

Lookback period:     [e.g., 30 days]
Justification:
  [Why this window? Long enough to catch persistent threats?
   Short enough to be practical? Does data retention support it?]

Available data retention: [X days per SIEM configuration]

Time-of-day restrictions:
  [ ] No restriction — check all hours
  [ ] Focus on off-hours (attackers often work outside business hours)
  [ ] Focus on business hours (user-interactive technique)
  [ ] Other: _______________________________________________


## Step 6 — Write the Formal Hypothesis

Using your answers above, write the complete hypothesis:

"If [THREAT from Step 1] is active in [SCOPE from Step 2],
 I would observe [EVIDENCE from Step 3]
 in [DATA SOURCE],
 distinguishable from legitimate [BASELINE from Step 4],
 over [TIME WINDOW from Step 5]."

Your hypothesis:
  "If ____________________________________________________
   is active in _________________________________________,
   I would observe _______________________________________
   in ___________________________________________________,
   distinguishable from legitimate _______________________,
   over _________________________________________________."


## Step 7 — Success Criteria

### Hunt SUCCESS (evidence found):
  - What findings would constitute confirmation of the hypothesis?
  - What is the minimum evidence threshold for escalation?
    [ ] Single matching event
    [ ] Two or more corroborating events
    [ ] Corroboration across multiple data sources
    [ ] Other: ___________________________________________

### Hunt NEGATIVE (no evidence found):
  - Is a negative result meaningful, or could it reflect data gaps?
  - What data coverage is required to declare a confident negative?
    Required coverage: ______% of [endpoint/user/system type]
  - At what coverage % should the hunt be declared inconclusive?


## Step 8 — Queries

Write your initial queries before starting (refine during hunt):

### Query 1 — Broad scan (start wide)
Tool:    [Splunk/Kibana/Sigma]
Purpose: [What does this find?]

```
[Paste query here]
```

### Query 2 — Narrow (filter known-good)
Tool:    [Splunk/Kibana/Sigma]
Purpose: [What does this find after filtering?]

```
[Paste query here]
```

### Query 3 — Anomaly focus
Tool:    [Splunk/Kibana/Sigma]
Purpose: [Stack counting / outlier detection]

```
[Paste query here]
```


## Completed Example (Reference)

Hypothesis:
  "If a threat actor is using PowerShell-based lateral movement (T1059.001)
   in our corporate Windows environment, I would observe PowerShell processes
   with encoded command-line arguments (-EncodedCommand or -enc) in Sysmon
   EventID 1 logs from corporate workstations, where the parent process is
   NOT Windows Task Scheduler (taskeng.exe) or SCCM (ccmexec.exe) — our known
   legitimate automated uses — over the past 14 days."

Why this is a good hypothesis:
  ✓ Specific technique: T1059.001
  ✓ Specific scope: corporate Windows workstations
  ✓ Specific indicator: encoded commands with unusual parents
  ✓ Excludes known-legitimate: Task Scheduler, SCCM
  ✓ Specific data source: Sysmon EventID 1
  ✓ Specific time window: 14 days
  ✓ Testable: yes — run the query, count results
