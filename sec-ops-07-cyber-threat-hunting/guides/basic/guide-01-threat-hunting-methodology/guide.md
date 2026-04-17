# Guide 01: Step-by-Step Threat Hunting Methodology

**Level:** Basic  
**Estimated Time:** 30 minutes  
**Goal:** Understand and apply a repeatable, structured threat hunting methodology

---

## Introduction

Effective threat hunting is not random searching through logs. It is a structured, repeatable process that produces consistent results and improves your organization's security over time. This guide walks you through the complete methodology from receiving threat intelligence to closing a hunt with actionable outputs.

---

## The Five-Phase Threat Hunting Methodology

```
Phase 1: Trigger & Scoping
         ↓
Phase 2: Hypothesis Formation
         ↓
Phase 3: Data Collection & Validation
         ↓
Phase 4: Investigation & Analysis
         ↓
Phase 5: Documentation & Follow-up
         ↑_____________|
         (Continuous loop)
```

---

## Phase 1: Trigger and Scoping

Every hunt must start with a clear trigger and defined scope. Without these, hunts become unfocused and produce poor results.

### Identifying Your Hunt Trigger

Triggers fall into four categories:

**1. Intelligence-Driven Triggers**
- New threat intelligence report about your sector
- ISAC advisory about active campaigns
- Government cybersecurity advisory (CISA, NCSC)
- Vendor threat report relevant to your environment

**2. Environment-Driven Triggers**
- New technology deployment (new cloud service, new software)
- Recent vulnerability disclosure affecting your stack
- Upcoming high-risk event (M&A, product launch)
- Security control gap identified

**3. Anomaly-Driven Triggers**
- Statistical anomaly noticed during routine analysis
- Unusual pattern in dashboards
- Staff report of suspicious behavior

**4. Compliance/Audit Triggers**
- Regulatory requirement to prove no compromise
- Post-audit hunting to validate controls
- Tabletop exercise follow-up

### Defining the Hunt Scope

Scope defines what you will and will not include in the hunt. Be explicit:

```
Hunt Scope Template:
─────────────────────────────────────────────
Hunt ID:          HUNT-YYYY-NNN
Trigger:          [Describe the trigger clearly]
Hypothesis:       [One sentence - see Phase 2]
Time Window:      [Start date] to [End date]
Systems in Scope: [All workstations / Specific subnet / Specific servers]
Systems Excluded: [OT/ICS / Development / Lab systems]
Data Sources:     [List required data sources]
Priority:         [Critical / High / Medium / Low]
Estimated Effort: [X hours / X days]
Assigned Hunter:  [Name]
─────────────────────────────────────────────
```

**Scope considerations:**
- Start narrow and expand if needed (narrow scope = faster results)
- Consider data retention limits (do you have 30 days of logs?)
- Identify data source gaps before starting (missing logs = incomplete results)

---

## Phase 2: Hypothesis Formation

A hypothesis is a specific, testable statement about what you expect to find if an adversary is active in your environment.

### The Hypothesis Formula

```
"If [threat actor/technique] is present in [environment scope],
 then I would observe [specific indicator/behavior]
 in [specific data source] during [time window]."
```

### Good vs. Poor Hypotheses

**Poor hypothesis:**
> "There might be malware on our network."

Problems: Too vague, not testable, no specific indicator, no data source.

**Better hypothesis:**
> "If a threat actor is using PowerShell for lateral movement, there would be unusual PowerShell executions in our environment."

Better but still vague—what is "unusual"?

**Good hypothesis:**
> "If a threat actor is using PowerShell-based lateral movement (T1059.001) in our corporate network, I would expect to observe PowerShell processes with encoded command-line arguments spawned by parent processes other than the Windows Task Scheduler and SCCM (our known legitimate uses), in Windows Event ID 4688 logs from corporate workstations over the past 14 days."

This is good because:
- Specific technique (T1059.001)
- Specific scope (corporate workstations)
- Specific indicator (encoded commands, unusual parents)
- Excludes known legitimate activity
- Specific data source (Event ID 4688)
- Specific time window (14 days)

### Writing Your First Hypothesis

Use this worksheet:

```
1. THREAT: What threat or technique am I investigating?
   ___________________________________________________

2. SCOPE: Where in the environment could this occur?
   ___________________________________________________

3. INDICATOR: What specific observable evidence would exist?
   ___________________________________________________

4. DATA SOURCE: Where would this evidence appear in my logs?
   ___________________________________________________

5. BASELINE: What does legitimate activity look like here?
   ___________________________________________________

6. TIME WINDOW: What is my lookback period?
   ___________________________________________________

7. HYPOTHESIS (combine above):
   "If [1] is active in [2], I would observe [3] in [4],
   distinguishable from legitimate [5], over [6]."
```

---

## Phase 3: Data Collection and Validation

Before hunting, verify your data is available and complete.

### Data Source Validation Checklist

For each required data source:

```
Data Source: Windows Security Event Logs
─────────────────────────────────────────
□ Are events flowing? (Check last event timestamp)
□ Is coverage complete? (What % of endpoints are logging?)
□ Is the relevant event type enabled?
  □ Event ID 4688 (Process Creation) - requires audit policy
  □ Command-line audit enabled? (Required for hunting!)
□ What is the retention period?
□ Are there time gaps in coverage?
□ Is the data indexed/searchable?

Data Source: PowerShell Operational Logs
─────────────────────────────────────────
□ Is script block logging enabled? (Event ID 4104)
□ Is module logging enabled? (Event ID 4103)
□ Are logs being forwarded to SIEM?
□ Coverage: ___% of workstations
□ Coverage: ___% of servers

Data Source: Sysmon
─────────────────────────────────────────
□ Is Sysmon deployed? Coverage: ___%
□ What Sysmon version?
□ Which events are enabled? (Check config)
  □ Event ID 1: ProcessCreate
  □ Event ID 3: NetworkConnect
  □ Event ID 7: ImageLoad
  □ Event ID 8: CreateRemoteThread
  □ Event ID 10: ProcessAccess
□ Are logs forwarded to SIEM?
```

### Documenting Data Gaps

If data is missing:
1. Document the gap in your hunt log
2. Estimate the impact on hunt completeness
3. Note it as a finding (gaps in coverage ARE findings)
4. Create a follow-up action to remediate the gap

---

## Phase 4: Investigation and Analysis

This is the core hunting phase. Follow these practices:

### 4.1 Start Broad, Narrow Down

Begin with wide queries to understand the landscape, then narrow:

```
Step 1: Count everything
  → How many PowerShell processes ran in the last 14 days?
  
Step 2: Filter known-good
  → Remove processes spawned by Task Scheduler and SCCM
  
Step 3: Focus on anomalies
  → Which remaining instances have encoded commands?
  
Step 4: Investigate anomalies
  → For each flagged instance: who, what, when, where, why?
```

### 4.2 Use Stack Counting

Count everything, sort ascending. Rare items (small stacks) are your hunting targets:

```sql
-- Stack count: Parent processes of PowerShell
SELECT ParentProcessName, COUNT(*) as count
FROM process_logs
WHERE Image LIKE '%powershell%'
GROUP BY ParentProcessName
ORDER BY count ASC

-- Investigate rows with count = 1 first
```

### 4.3 Pivot on Findings

When you find something suspicious, pivot to related data:

```
Suspicious finding: Encoded PowerShell on WORKSTATION-042

Pivot 1: What other processes ran on WORKSTATION-042 that day?
Pivot 2: What network connections did WORKSTATION-042 make?
Pivot 3: What user was logged in? Did they log into other hosts?
Pivot 4: Were any files created/modified on WORKSTATION-042?
Pivot 5: Did the PowerShell process spawn any child processes?
```

### 4.4 The "3Ws" for Each Finding

For every suspicious item, document the 3Ws:

- **What?** What exactly was observed? (Specific log entry, timestamp, system)
- **Why suspicious?** Why does this deviate from expected behavior?
- **What next?** What further investigation is needed? Escalate? Close?

### 4.5 Evaluating Findings

Not every anomaly is malicious. Apply this evaluation process:

```
Is this anomalous?
  YES ─→ Can it be explained by legitimate activity?
           YES ─→ Document and close (note the baseline exception)
           NO ─→ Is there corroborating evidence?
                   YES ─→ ESCALATE TO INCIDENT RESPONSE
                   NO ─→ Flag as SUSPICIOUS, gather more evidence
  NO ──→ Close and move on
```

---

## Phase 5: Documentation and Follow-up

The hunt is not complete until everything is documented and follow-up actions are captured.

### The Hunt Report

Every hunt, positive or negative, produces a report:

```markdown
# Hunt Report: HUNT-2024-NNN

## Executive Summary
[2-3 sentences: What was hunted, what was found, key actions taken]

## Hunt Details
- Hypothesis: [Full hypothesis statement]
- Trigger: [What triggered this hunt]
- Scope: [Time window, systems, data sources]
- Hunter: [Name]
- Duration: [How long the hunt took]

## Methodology
[Brief description of approach taken]

## Findings

### Finding 1: [Finding Title]
- Severity: [Critical / High / Medium / Low / Informational]
- Status: [Confirmed Malicious / Suspicious / Benign / Under Investigation]
- Description: [What was found]
- Evidence: [Log entries, screenshots, hash values]
- Action Taken: [Incident ticket, blocked, investigated, etc.]

### Finding 2: [If applicable]
...

## Negative Findings
[Describe what was NOT found - this is also valuable]

## Coverage Gaps Identified
1. [Gap 1]: PowerShell command-line logging not enabled on 23 servers
   Action: IT ticket TICKET-4421 created

## New Detection Rules Created
1. [Rule name + link]: Detects [behavior]

## Recommendations
1. [Short-term action]
2. [Medium-term improvement]

## Metrics
- Data sources reviewed: X
- Total events analyzed: X
- Hypotheses tested: X
- True positives found: X
- False positives encountered: X
- Time spent: X hours
```

### Converting Hunt Findings to Detections

Every confirmed TTP finding should become an automated detection:

```
Hunt Finding → Sigma Rule → SIEM Alert → Detection Coverage

Process:
1. Identify the specific behavior pattern
2. Write a Sigma rule capturing that pattern
3. Convert to your SIEM's query language
4. Test the rule (verify TP, tune FP)
5. Deploy to production
6. Document the rule and link it to the hunt
```

### The Continuous Improvement Loop

After each hunt:
1. Update your hunting playbooks with new queries
2. Add new data sources discovered
3. Update your ATT&CK coverage map
4. Assess maturity level improvements
5. Share learnings with the team

---

## Quick Reference: Hunt Quality Checklist

Before declaring a hunt complete:

**Hypothesis Quality:**
- [ ] Hypothesis was specific and testable
- [ ] ATT&CK technique(s) identified
- [ ] Expected evidence clearly defined

**Data Quality:**
- [ ] Data source availability confirmed before hunting
- [ ] Coverage gaps documented
- [ ] Data retention sufficient for time window

**Analysis Quality:**
- [ ] All anomalies investigated (not just flagged)
- [ ] Each finding has 3Ws documented
- [ ] Known-legitimate activity baseline established

**Output Quality:**
- [ ] Hunt report written
- [ ] All findings actioned (escalated, closed, or tracked)
- [ ] Coverage gaps have follow-up tickets
- [ ] New detection rules created where applicable

---

## Common Beginner Mistakes

1. **Hunting without a hypothesis** → Random log searching produces random results
2. **Not validating data first** → "Hunting" in incomplete data gives false confidence
3. **Stopping at IOC hits** → An IOC match is the start of investigation, not the end
4. **Declaring negative without checking gaps** → "Nothing found" means nothing if your data coverage is 40%
5. **Not documenting** → Undocumented hunts cannot be reproduced, improved, or shared
6. **Acting on single indicators** → Require corroboration before escalating
7. **Not creating detections from findings** → Repeating the same hunt manually is waste

---

*Next: Guide 02 - Setting Up and Using MISP for Threat Intelligence*
