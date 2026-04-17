# Guide 01: Understanding and Documenting SOC Workflows

**Level**: Basic

**Estimated time**: 45 minutes

**Prerequisites**: Reading (Section 2-3) completed

---

## Learning Objectives

After completing this guide, you will be able to:

* Map the alert lifecycle from detection to closure
* Document a SOC workflow using standard notation
* Create a severity classification matrix for your environment
* Design a RACI matrix for a SOC team
* Identify gaps in an existing workflow

---

## Section 1: What is a SOC Workflow?

A **SOC workflow** is the defined sequence of steps that transforms a raw security alert into a resolved ticket.
It specifies:

* **Who** performs each step (roles, tiers)
* **What** they do at each step (actions, decisions)
* **When** they must do it (SLAs, time targets)
* **How** they do it (tools, procedures)
* **Why** — the security objective each step achieves

Without a documented workflow, each analyst creates their own process.
This leads to:

* Inconsistent response quality
* Coverage gaps between shifts
* Difficulty training new analysts
* No basis for measuring performance

---

## Section 2: The Three-Layer Model

SOC workflows operate on three layers:

```text
Layer 3: Strategic (Management)
  ↑ Reports metrics, tracks SLAs, drives improvements
  ↓ Sets policy, approves resources, defines escalation authority

Layer 2: Tactical (L2/L3 Analysts)
  ↑ Escalates unresolved alerts, complex investigations
  ↓ Receives escalations, guides response decisions

Layer 1: Operational (L1 Analysts)
  → Receives alerts, triages, creates tickets, executes playbooks
```

Each layer must have clearly defined handoff points.
The most common failure mode is when Layer 1 doesn't know when to escalate to Layer 2.

---

## Section 3: Documenting the Alert Lifecycle

### Step-by-step documentation method

Use this template to document your SOC's alert lifecycle:

```text
ALERT LIFECYCLE DOCUMENTATION
Organization: ________________
Documented by: _______________
Date: _______________________
Review date: _________________

STEP 1: ALERT GENERATION
  Source: _________________ (SIEM rule name, tool)
  Trigger condition: _______________________
  Data included in alert: __________________
  Where alert appears: _____________________ (queue name)

STEP 2: ALERT ACKNOWLEDGMENT
  Who: _________________ (role)
  How (interface): _________________________
  Time target: ____ minutes
  Action: Create ticket? [Y/N]

STEP 3: INITIAL TRIAGE
  Who: _________________
  Information gathered: ____________________
  Decision point: __________________________
  If [condition]: → Step X
  If [condition]: → Escalate (who?)

STEP 4: INVESTIGATION
  Who: _________________
  Tools used: _____________________________
  Evidence collected: _____________________
  Decision point: __________________________

STEP 5: CONTAINMENT (if applicable)
  Who: _________________
  Actions: ________________________________
  Approval required from: __________________

STEP 6: RESOLUTION & CLOSURE
  Who: _________________
  Closure criteria: _______________________
  Documentation requirements: ______________
  Notification required: ___________________

METRICS CAPTURED AT EACH STEP:
  Alert generation → acknowledgment: MTTA
  Alert generation → resolution: MTTR
```

---

## Section 4: Flow Diagram Notation

Use standard flowchart notation to visualize workflows:

| Symbol | Meaning | When to use |
|--------|---------|-------------|
| Rectangle | Process/Action | An action an analyst takes |
| Diamond | Decision | A yes/no or conditional branch |
| Rounded rectangle | Terminal | Start or end of workflow |
| Parallelogram | Data | Information input or output |
| Double-headed arrow | Bidirectional flow | Communication or data exchange |

**Example minimal notation:**

```text
(START: SIEM Alert)
       │
       ▼
[Check alert type]
       │
   ┌───┴───┐
   │       │
  FP?     TP?
   │       │
   ▼       ▼
[Close]  [Triage]
           │
      ┌────┴────┐
      │         │
   Low/Med    High/Crit
      │         │
      ▼         ▼
   [L1 work]  [Escalate L2]
      │
   ┌──┴──┐
   │     │
 Resolved?
   │     │
  Yes    No (→ Loop back)
   │
(END: Close Ticket)
```

---

## Section 5: Building a Severity Matrix

### 5.1 Define asset criticality tiers

First, classify your assets:

| Criticality | Definition | Examples |
|-------------|------------|---------|
| **Tier 1 (Critical)** | Business stops if compromised | Payment systems, AD domain controllers, CEO laptop |
| **Tier 2 (High)** | Major disruption if compromised | Core servers, executive systems, customer databases |
| **Tier 3 (Medium)** | Operational impact | Business workstations, shared servers, dev systems |
| **Tier 4 (Low)** | Minimal business impact | Lab systems, test environments, printers |

### 5.2 Define threat severity levels

| Severity | Definition | Examples |
|----------|------------|---------|
| **Critical** | Active exploitation, data exfiltration | Ransomware executing, known APT TTPs |
| **High** | Strong indicators of compromise | Successful brute force, C2 beacon |
| **Medium** | Suspicious activity | Policy violation, anomalous behavior |
| **Low** | Informational / policy | Software install, unusual login time |

### 5.3 Build the matrix

Fill in your organization's severity assignments:

```text
SEVERITY MATRIX TEMPLATE:

               │  Threat: Critical  │  Threat: High  │  Threat: Medium  │  Threat: Low
───────────────┼────────────────────┼────────────────┼──────────────────┼─────────────
Tier 1 Asset   │      P1 / SEV-1   │   P1 / SEV-1   │   P2 / SEV-2     │  P3 / SEV-3
Tier 2 Asset   │      P1 / SEV-1   │   P2 / SEV-2   │   P2 / SEV-2     │  P3 / SEV-3
Tier 3 Asset   │      P2 / SEV-2   │   P2 / SEV-2   │   P3 / SEV-3     │  P4 / SEV-4
Tier 4 Asset   │      P2 / SEV-2   │   P3 / SEV-3   │   P4 / SEV-4     │  P4 / SEV-4
```

---

## Section 6: RACI Matrix Design

A RACI matrix prevents role confusion and coverage gaps.

### Building a SOC RACI matrix

```text
RACI MATRIX: SOC Alert Workflow

Activity                        │ L1 Analyst │ L2 Analyst │ L3/Hunter │ SOC Mgr │ CISO
───────────────────────────────── ────────────────────────────────────────────────────
Alert monitoring & triage       │     R      │     C      │     -     │    I    │  -
Ticket creation                 │     R      │     -      │     -     │    I    │  -
IOC enrichment (manual)         │     R      │     C      │     -     │    -    │  -
Playbook execution (L1)         │     R      │     -      │     -     │    -    │  -
L1 → L2 escalation decision     │     R      │     A      │     -     │    I    │  -
Deep investigation               │     C      │     R      │     C     │    I    │  -
Malware analysis                │     -      │     R      │     C     │    I    │  -
Incident declaration            │     -      │     R      │     C     │    A    │  I
Containment actions (auto)      │     R      │     C      │     -     │    I    │  -
Containment actions (manual)    │     C      │     R      │     C     │    A    │  -
Executive notification          │     -      │     -      │     -     │    R    │  A
Playbook maintenance            │     C      │     R      │     C     │    A    │  -
Threat hunting                  │     -      │     C      │     R     │    I    │  -
Metrics reporting               │     -      │     C      │     -     │    R    │  A
Post-incident review            │     C      │     R      │     C     │    A    │  I

R=Responsible, A=Accountable, C=Consulted, I=Informed
```

---

## Section 7: Workflow Gap Analysis

A gap analysis compares your current workflow against a target state.

### Gap analysis template

```text
SOC WORKFLOW GAP ANALYSIS

Current state assessment:
□ Is each alert type covered by a documented workflow?
  Covered: ___/total alert types

□ Does each workflow have defined SLAs?
  With SLAs: ___/total workflows

□ Is there a severity classification matrix?
  Exists: [Y/N]  Last updated: ________

□ Are roles and responsibilities documented (RACI)?
  Exists: [Y/N]  Last updated: ________

□ Is there a documented escalation path?
  Exists: [Y/N]  Clear criteria: [Y/N]

□ Is there a shift handover procedure?
  Exists: [Y/N]  Consistently followed: [Y/N]

□ Are SLA breaches tracked and reviewed?
  Tracked: [Y/N]  Regular review: [Y/N]

Identified gaps:

1. _________________________________

2. _________________________________
3. _________________________________

Priority improvements (next 30 days):

1. _________________________________

2. _________________________________
```

---

## Section 8: Practical Exercise

### Exercise: Document your (hypothetical) SOC workflow

Given this scenario: You are the SOC manager for a 10-person team handling security for a financial services company with ~500 endpoints and 50 servers.

**Task 1**: Define asset criticality tiers for:

* Core banking application servers
* Employee workstations
* External web servers
* Development systems
* Executive laptops

**Task 2**: Build a severity matrix for your organization using the tiers from Task 1.

**Task 3**: Document the alert lifecycle for a "Failed Login Attempt" alert from the SIEM.

**Task 4**: Create a RACI matrix for your 10-person SOC:

* 6 L1 analysts
* 3 L2 analysts
* 1 SOC manager

---

## Key Takeaways

1. A documented workflow is the foundation of every other SOC improvement — you cannot automate what you haven't defined.

1. The RACI matrix prevents the two most common failures: multiple people doing the same thing (duplication) and nobody doing something (gap).

1. Severity matrices must be calibrated to **your** organization — a developer workstation at a hospital is lower criticality than the same device at a nuclear facility.

1. Gap analysis should be repeated quarterly — workflows drift as the environment changes.

1. Document the workflow as it **actually works**, not as you think it should work. If analysts regularly skip a step, that's a signal the step needs redesign.

---

## Next Steps

* Complete Drill 01 (Workflow Mapping) to practice these skills
* Review Guide 02 to learn how playbooks extend workflow documentation
* Review the reading material Section 3 for SLA reference values
