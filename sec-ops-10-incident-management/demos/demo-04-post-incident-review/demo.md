# Demo 04 — Post-Incident Review: Conducting an Effective AAR

## Overview

This demo models a Post-Incident Review (PIR / After-Action Review) for the MedSupply ransomware precursor case.
We practice structured review format, root cause analysis, and creating actionable improvement items.

**Duration:** 35 minutes

**Format:** Guided facilitation demo (role-play with discussion)

**Scenario:** Review of the Cobalt Strike incident from Demo 01

---

## The Post-Incident Review Purpose

A PIR is NOT a blame session.
It is a structured improvement activity.

**Goals:**

1. Establish shared understanding of what happened
1. Identify what worked well (to reinforce)
1. Identify what could be improved (to fix)
1. Produce specific, owned action items

**Who attends:**

* IR team members who worked the incident
* System owners (IT, DBA, network)
* Legal/DPO if regulatory implications
* SOC Manager
* Optionally: CISO for P1 incidents

---

## The Incident Timeline (Recap)

```text
2025-04-10 Timeline: MedSupply GmbH — Cobalt Strike Incident

14:29 UTC  anna.schmidt opens "Supplier_Invoice_April.docx"
14:30 UTC  Word macro executes → PS download cradle
14:30 UTC  PowerShell downloads Cobalt Strike stager from 185.220.101.73
14:32 UTC  EDR fires alert: Cobalt Strike beacon
14:37 UTC  Tier 1 escalates to Tier 2 (5 min triage)
14:42 UTC  Tier 2 begins investigation
14:53 UTC  Isolation decision made (11 min for scope assessment)
14:55 UTC  WORKSTATION-FINANCE-03 isolated
14:56 UTC  C2 IP 185.220.101.73 blocked at perimeter firewall
15:10 UTC  Credential reset for anna.schmidt completed
15:30 UTC  Disk image collection begins
16:30 UTC  Management briefed
17:30 UTC  anna.schmidt back on clean workstation
```

**MTTD:** 2 minutes (excellent)

**MTTI (to Isolation):** 23 minutes (good)

**MTTR (to restored operation):** 3 hours (acceptable for this severity)

---

## Structured Review: The "4-Box" Method

### Box 1: What Happened? (5 minutes)

Agree on the facts — no blame, no "should have."

**Facilitator asks:** "Let's go through the timeline.
Is everyone aligned on what happened?"

Walk through the timeline.
Note any disagreements on facts — these indicate documentation gaps.

**Key facts for this incident:**

* Attack vector: Macro-enabled Word document from email
* Initial access: User anna.schmidt (standard user, Finance)
* Attacker tool: Cobalt Strike beacon
* C2: 185.220.101.73 (known malicious)
* Detection: EDR (CrowdStrike) within 2 minutes of beacon establishment
* Dwell time before containment: 23 minutes
* Data at risk: None confirmed
* Business impact: Single workstation offline for 3 hours

### Box 2: What Went Well? (7 minutes)

**Facilitator asks:** "What went right in our response?
What should we keep doing?"

**Expected answers from participants:**

From Tier 1 analyst:

* "The EDR alert was clear and actionable — it included the hash and C2 IP directly"
* "TheHive was ready to use — case creation was fast"

From Tier 2 analyst:

* "The scope determination queries we ran in Splunk were quick — we had the scope in 7 minutes"
* "Containment decision framework was clear — we knew exactly when to isolate"

From IT team:

* "Firewall team responded to the block request in under 10 minutes"

From IR Manager:

* "Communication to management was clear and on time"
* "New workstation was ready in under 2 hours — IT preparation paid off"

**Record all items — these are practices to codify and protect.**

### Box 3: What Could Be Improved? (10 minutes)

**Facilitator asks:** "What were the friction points?
What would you do differently?"

**Expected answers:**

From Tier 2 analyst:

* "We didn't capture memory before isolation. By the time we decided to isolate, we were focused on containment, not evidence."
* "There was no playbook for Cobalt Strike specifically — we were working from general principles"

From Email admin:

* "This macro got through our email filter. We need to look at why."

From Legal:

* "We identified this could have been a GDPR case if finance data was accessed. We don't have a quick-reference guide for when GDPR applies."

From IT:

* "The certificate for the macro-blocked Proofpoint policy expired 3 weeks ago. That's why it passed."

**These are honest process failures — not individual failures.**

### Box 4: What Will We Change? (8 minutes)

Convert "what went wrong" into specific action items.

**Action items from this review:**

| # | Problem | Action Item | Owner | Deadline | Priority |
|---|---------|-------------|-------|----------|---------|
| 1 | No memory capture procedure | Add memory capture to containment SOP (before isolation if time allows) | IR Lead | 2025-04-17 | High |
| 2 | No Cobalt Strike playbook | Write Cobalt Strike specific response playbook | SOC Lead | 2025-04-24 | High |
| 3 | Email filter policy expired | Renew Proofpoint macro-blocking policy certificate + add renewal reminders | Email Admin | 2025-04-14 | Critical |
| 4 | GDPR trigger reference | Create one-page GDPR trigger reference card for IR team | DPO | 2025-04-30 | Medium |
| 5 | Finance credential review | Review what systems anna.schmidt had access to; confirm no unauthorized use | IT + Finance | 2025-04-11 | High |

**Facilitator notes:**

* Each item has ONE owner (not "IT team" — a specific person)
* Each item has a specific deadline
* Action items are reviewed at the next monthly IR meeting

---

## The 5-Why Root Cause Analysis

For the most important failure (email filter bypass), apply 5-Why:

**Problem:** Macro-enabled document bypassed email security filter.

* **Why 1:** Why did it bypass? → Policy expired 3 weeks ago.
* **Why 2:** Why did the policy expire? → No automated renewal reminder configured.
* **Why 3:** Why no renewal reminder? → When the system was configured, no one set up the renewal alert.
* **Why 4:** Why wasn't this part of the setup procedure? → The setup procedure didn't include "configure renewal alerts" as a step.
* **Why 5:** Why not? → Email security was configured by a contractor who didn't follow the company's security hardening standard.

**Root cause:** Policy renewal was not included in the standard operating procedure for email security configuration.

**Fix:** Update the email security SOP to include: "Configure renewal alerts for all security policies, set to 30/14/7 days before expiry."

---

## PIR Report Template

```markdown
# Post-Incident Review Report
## Incident: INC-2025-04712 — Cobalt Strike Beacon at MedSupply GmbH

**Date of Review:** 2025-04-15
**Incident Dates:** 2025-04-10
**Severity:** P2 — High
**Review Facilitator:** [IR Manager]

### Incident Summary
[2-3 sentence summary]

### Timeline
[Key events with timestamps]

### What Went Well
- [List]

### What Could Be Improved
- [List]

### Root Cause Analysis
**Primary root cause:** [Description]
**Contributing factors:** [List]

### Action Items
| # | Item | Owner | Deadline |
|---|------|-------|----------|
| 1 | ... | ... | ... |

### Metrics
- MTTD: X minutes
- MTTI: Y minutes
- MTTR: Z hours
- Data at risk: [None confirmed / Description]
- Business impact: [Description]

### Lessons Learned Summary
[1-2 sentences on key takeaways]

**Report approved by:** [IR Manager, Date]
**Distribution:** IR Team, SOC Manager, CISO
**Classification:** CONFIDENTIAL — INTERNAL ONLY
```

---

## Key Facilitation Rules

1. **No blame** — "The system failed" not "Alice failed"
1. **Facts over feelings** — stick to documented timeline
1. **Action items have owners** — "we" as the owner means no one is accountable
1. **Close the loop** — action items must be reviewed at the next meeting
1. **Write it up** — a verbal PIR that isn't documented will be repeated
