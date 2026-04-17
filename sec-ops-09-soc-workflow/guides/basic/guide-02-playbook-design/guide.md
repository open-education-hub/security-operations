# Guide 02: Designing Effective Playbooks

**Level**: Basic

**Estimated time**: 45 minutes

**Prerequisites**: Guide 01 completed

---

## Learning Objectives

After this guide, you will be able to:

* Distinguish playbooks from runbooks
* Apply the standard playbook structure to a new scenario
* Design decision trees for common alert types
* Use provided templates to create a complete playbook
* Identify the three types of playbooks and when each applies

---

## Section 1: Playbook Design Principles

### Principle 1: Decision logic before procedure

A playbook's value is in capturing the **decision logic** — the if/then/else reasoning an experienced analyst uses.
Procedure (the "how") belongs in runbooks.

**Bad playbook step**:
> "Check if the email is malicious."

**Good playbook step**:
> "3. Query VirusTotal for each URL in the email. If ANY URL has a malicious score >50, proceed to Step 4a (quarantine). If all URLs score <20, proceed to Step 5 (close as clean). If any URL scores 20-50, proceed to Step 4b (analyst review)."

### Principle 2: Explicit escalation criteria

Ambiguous escalation is the #1 cause of "alert limbo." Every playbook must have explicit, measurable criteria for escalation.

**Vague** (do not use):
> "Escalate to L2 if the incident seems serious."

**Explicit** (correct):
> "Escalate to L2 immediately if ANY of the following are true:
> - Ransomware IOCs detected on endpoint (YARA match or file extension mass-rename)
> - C2 communication detected from Tier 1 or Tier 2 asset
> - Data exfiltration indicators (>100MB outbound to unknown IP)
> - More than 5 accounts compromised in same incident"

### Principle 3: Time-boxed decisions

Include time limits at key decision points to prevent analyst paralysis:

> "If investigation is not complete within 30 minutes of ticket creation, and severity is P2 or higher, immediately escalate to L2 regardless of current state."

### Principle 4: Reversibility awareness

Flag actions that are difficult or impossible to reverse:

> "⚠️ IRREVERSIBLE ACTION: Disabling this account will lock out the user immediately. Confirm severity is P1 or P2 and obtain L2 verbal approval before proceeding."

### Principle 5: Version control

Every playbook should have a version number and change log.
Analysts following an outdated playbook is worse than having no playbook at all.

---

## Section 2: Standard Playbook Template

```markdown
# Playbook: [INCIDENT TYPE]

**ID**: PB-[NNN]
**Version**: [X.Y]
**Last Updated**: [YYYY-MM-DD]
**Owner**: [Name / Team]
**Review Cycle**: Quarterly
**Trigger Rules**: [SIEM rule names that activate this playbook]

---

## 1. Purpose

[1-2 sentences: what security event this playbook addresses]

---

## 2. Scope

**Applies to**: [Affected systems, environments, alert types]
**Does NOT apply to**: [Exclusions, edge cases handled elsewhere]

---

## 3. Prerequisites

**Access required**:
- [ ] [System] with [permission level]
- [ ] [Tool] with [role]

**Knowledge required**:
- [ ] [Skill/knowledge]

---

## 4. Trigger Conditions

This playbook activates when:
- SIEM rule `[RULE_NAME]` fires AND
- [Additional condition, e.g., asset criticality ≥ Tier 2]

Manual activation: Analyst determines this event type during investigation of a different alert.

---

## 5. Procedure

### Step 1: [Action Name] (Target: X minutes)

**Who**: [Role]
**Tool**: [Tool name]
**Action**: [What to do]
**Reference**: Runbook [RB-NNN]

**Decision**:
- If [condition A] → Go to Step 2
- If [condition B] → Go to Step 4
- If [condition C] → **ESCALATE** (see Section 6)
- If unable to determine → **ESCALATE**

---

### Step 2: [Action Name] (Target: X minutes)

[Continue pattern...]

---

## 6. Escalation Criteria

**Escalate to L2 immediately if**:
- [ ] [Condition 1]
- [ ] [Condition 2]

**Declare incident if**:
- [ ] [Condition 1 — usually data confirmed exfiltrated or ongoing attack]

**Executive notification if**:
- [ ] [Condition — regulatory or reputational impact]

---

## 7. Containment Actions

| Action | Who | Approval Required | Runbook |
|--------|-----|-------------------|---------|
| [Action 1] | L1 | No | RB-[NNN] |
| [Action 2] | L2 | L2 verbal | RB-[NNN] |
| [Action 3] | L2 | SOC Manager written | RB-[NNN] |

---

## 8. Evidence Collection

Collect and preserve:
- [ ] [Evidence type 1] — Method: [how to collect]
- [ ] [Evidence type 2] — Method: [how to collect]

Store at: [Location / path]
Chain of custody: Document in ticket (who collected, when, hash)

---

## 9. Closure Criteria

Ticket can be closed when ALL of the following are true:
- [ ] Root cause identified
- [ ] Containment actions complete and verified
- [ ] Evidence preserved (if applicable)
- [ ] Affected users notified (if applicable)
- [ ] IOCs blocked (if applicable)
- [ ] Tuning recommendation filed (if FP or FP-adjacent)

---

## 10. Communication

| Stakeholder | When | How | Template |
|-------------|------|-----|---------|
| Affected user | [Condition] | Email | [Template ID] |
| L2 team | On escalation | Slack + ticket | [Standard] |
| Management | [Condition] | Email + phone | [Template ID] |

---

## 11. Time Targets

| Phase | Target | SLA |
|-------|--------|-----|
| Triage complete | [X] min from alert | P[1-4] |
| Investigation complete | [X] min from triage | P[1-4] |
| Containment | [X] min from decision | P[1-4] |
| Closure | [X] hr from alert | P[1-4] |

---

## 12. Metrics

Track for this playbook:
- Average triage time
- Average investigation time
- Escalation rate
- FP rate
- Closure time vs. SLA

---

## 13. Appendix

### Quick Reference Commands
[Tool-specific commands for analysts]

### Contact List
| Name | Role | Contact | Hours |
|------|------|---------|-------|
| | | | |

### Related Documents
- Runbook: [RB-NNN] — [Title]
- Policy: [Policy reference]
```

---

## Section 3: Completed Playbook Example — Malware Detected on Endpoint

```markdown
# Playbook: Malware Detected on Endpoint

**ID**: PB-007
**Version**: 3.2
**Last Updated**: 2026-04-01
**Owner**: SOC Team
**Review Cycle**: Quarterly
**Trigger Rules**:
- `Malware_Detected_CrowdStrike`
- `AV_Alert_Defender`
- `Suspicious_Process_Execution`

---

## 1. Purpose

Guide the response when EDR or AV detects malware on an endpoint, from initial
triage through containment and evidence collection.

---

## 2. Scope

**Applies to**: All Windows/Linux/Mac endpoints managed by CrowdStrike or
Windows Defender.
**Does NOT apply to**: Sandbox/honeypot systems (different procedure).

---

## 4. Trigger Conditions

This playbook activates when:
- CrowdStrike alert "Prevention" or "Detection" fires on any endpoint
- OR Windows Defender alert severity = High/Severe

---

## 5. Procedure

### Step 1: Verify the Alert (Target: 5 minutes)

**Who**: L1 Analyst
**Tool**: CrowdStrike Falcon Console / Defender Security Center

1. Open alert in EDR console

2. Check detection type: Prevention (blocked) vs. Detection (executed)
3. Note: hostname, user, process name, parent process, file hash
4. Check if hash is on internal allowlist (benign software list)

**Decision**:
- If allowlisted hash → Close as FP, submit tuning request → END
- If Detection type = "Prevention" AND hash in VT >80% malicious → Step 2
- If Detection type = "Detection" (malware ran) → **IMMEDIATE Step 2**
- If unable to assess in 5 min → Escalate to L2

---

### Step 2: Assess Execution Scope (Target: 10 minutes)

**Who**: L1 Analyst
**Tool**: SIEM, CrowdStrike

1. Check SIEM: Has this endpoint made outbound connections to unknown IPs in last 2 hours?

2. Check SIEM: Have any files been mass-modified/renamed in last 2 hours?
3. Check EDR: What processes has this malware spawned?
4. Check EDR: Did malware attempt persistence (registry run keys, scheduled tasks)?

**Decision**:
- Signs of active C2, data staging, or persistence → **ESCALATE to L2** NOW
- Isolated/blocked malware with no execution → Step 3 (L1 can handle)
- Ransomware indicators (mass file rename, ransom note) → **P1 ESCALATE**

---

### Step 3: Contain the Endpoint (Target: 5 minutes)

**Who**: L1 Analyst
⚠️ **Semi-reversible action**: Isolation cuts network access. Verify ticket ID before proceeding.

**Tool**: CrowdStrike / Defender
**Reference**: Runbook RB-020 (CrowdStrike Endpoint Isolation)

1. Isolate endpoint from network via EDR console

2. Document in ticket: "Endpoint [hostname] isolated at [time] by [analyst]"
3. Notify user's manager (see Communication template MSG-001)

---

### Step 4: Collect Evidence (Target: 15 minutes)

**Who**: L1 (basic), L2 (full forensic)

Minimum evidence (L1):
- [ ] Screenshot of EDR alert details
- [ ] Export process tree from EDR
- [ ] Note all IOCs: file hash, process names, registry keys, C2 IPs

Full forensic (L2 if escalated):
- [ ] Memory acquisition (Runbook RB-040)
- [ ] KAPE triage collection (Runbook RB-022)

---

## 6. Escalation Criteria

**Escalate to L2 immediately if**:
- [ ] Malware executed (not just detected/blocked)
- [ ] C2 communication observed
- [ ] Multiple endpoints affected (>2)
- [ ] Ransomware indicators (file encryption, ransom note)
- [ ] Admin/privileged account involved
- [ ] Malware touched Tier 1 or Tier 2 asset

---

## 9. Closure Criteria

- [ ] Malware sample preserved and hash documented
- [ ] Endpoint reimaged or verified clean (L2 sign-off)
- [ ] All IOCs blocked (firewall + DNS)
- [ ] Source of infection identified (if possible)
- [ ] Affected user notified and educated
```

---

## Section 4: Decision Tree Design

Decision trees make the branching logic visual and easier to validate.

### Building a decision tree

1. **Start with the trigger** — what event initiates the workflow?
1. **List the key questions** — what are the critical decision points?
1. **Map the branches** — what happens for each answer?
1. **Identify terminal states** — close, escalate, or follow different playbook
1. **Validate with scenarios** — walk 3-5 real past incidents through the tree

**Decision tree template (ASCII):**

```text
[TRIGGER]
    │
    ▼
[Question 1?]
    │
   ┌┴──┐
  Yes  No
   │    │
  [A]  [B]
   │    │
   ▼    ▼
[Question 2?] [Question 3?]
```

---

## Section 5: Playbook Testing

A playbook that has never been tested is just a hypothesis.
Testing methods:

### Tabletop exercise
Gather the SOC team, present a scenario, walk through the playbook step by step.
Identify:

* Steps that are unclear or ambiguous
* Missing decision branches
* Unrealistic time targets
* Tool access or permission issues

### Historical replay
Take a real past incident (resolved) and walk it through the new playbook.
Does the playbook correctly handle it?
Would the outcome have been better or worse?

### Synthetic alert injection
Inject a simulated alert (in a test environment or using test IOCs) and have an analyst respond following the playbook literally.
Note where they get stuck.

---

## Key Takeaways

1. Decision logic is the most valuable part of a playbook. Procedure belongs in runbooks.
1. Explicit escalation criteria prevent alert limbo — the most common SOC failure mode.
1. Every containment action must be flagged with its reversibility.
1. Playbooks should be tested before deployment, not just after an incident exposes a gap.
1. A 20-step playbook that analysts skip is worse than a 5-step playbook they follow consistently.

---

## Templates Provided

Use these templates to create your own playbooks:

* Full playbook template (Section 2)
* Decision tree template (Section 4)
* Complete example: Malware on Endpoint (Section 3)

Practice: Create a complete playbook for one of these scenarios:

* Account Compromise Response
* Data Exfiltration Alert
* Ransomware Detected
