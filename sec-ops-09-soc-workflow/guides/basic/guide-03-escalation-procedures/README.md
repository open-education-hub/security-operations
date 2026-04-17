# Guide 03 (Basic): Escalation Procedures

## Objective

Understand when and how to escalate a security case, what information to hand off, and how to receive an escalation.
Learn shift handover procedures.

## Estimated Time

20–30 minutes

## Prerequisites

* Guides 01 and 02 completed

---

## When to Escalate

### Escalation Triggers for Tier 1 → Tier 2

Escalate when ANY of the following is true:

| Trigger | Reason |
|---------|--------|
| Confirmed true positive of any severity | All TPs need deeper investigation |
| Cannot determine TP/FP within 30 minutes | Don't waste time on ambiguity |
| Multiple hosts affected | Possible lateral movement |
| Privileged account involved (admin, service account) | Elevated impact |
| Data exfiltration suspected | Legal/compliance implications |
| Matches known APT TTP | Specialized analysis required |
| SLA is approaching and investigation incomplete | Time risk |

### Common L1 Mistake: Holding Too Long

A frequent error is L1 analysts holding cases too long because they want to "figure it out" before escalating.
This causes:

* SLA breaches
* Delayed containment (attacker has more time)
* L2 receiving stale evidence

**Rule of thumb:** If you're spending more than 20 minutes on a single alert without clear progress, escalate.

---

## How to Escalate

### Escalation Notification

When escalating:

1. **Update the ticket** with all findings to date
1. **Change status** to ESCALATED
1. **Notify** the receiving analyst (Slack, Teams, phone for P1/P2)
1. **Verbally brief** for P1/P2 (never just drop a ticket and walk away)

### Escalation Brief Format (for verbal handoff)

Use the SBAR format:

```text
SITUATION: "I have a confirmed Cobalt Strike beacon on finance-ws-042."

BACKGROUND: "It appeared at 09:18 UTC. The host belongs to M. Chen in finance.
The parent process was msiexec.exe spawning PowerShell, which then connected
to a known C2 IP. VT score 47/80, AbuseIPDB 100% confidence."

ASSESSMENT: "I assess this as P1. The user has access to financial reporting
systems. The C2 is active and the beacon may have been running for several hours."

RECOMMENDATION: "I recommend immediate host isolation, memory acquisition,
and notification to the IR team. The case is ready for Tier 2 takeover."
```

---

## Shift Handover Procedure

### 30 Minutes Before End of Shift

1. Review all open cases assigned to you
1. Ensure status and notes are current
1. Flag any cases that need action by incoming shift
1. Identify any hosts/users on watch list

### The Handover Document

Complete this template before leaving:

```markdown
# Shift Handover — [Date] [Time] UTC
## Outgoing Analyst: [Name]
## Incoming Analyst: [Name]

### Critical Open Cases
| Case ID | Title | Status | Next Required Action | Deadline |
|---------|-------|--------|---------------------|----------|
| ...     | ...   | ...    | ...                 | ...      |

### Watch List (Monitoring without active case)
| Asset/User | Reason for Monitoring | Since |
|-----------|----------------------|-------|
| ...       | ...                   | ...   |

### Environmental Notes
(Planned changes, known issues, suppressed rules, active pentests)

### Shift Summary
- Events processed: X
- Alerts triaged: X
- Cases opened: X
- Escalations: X
```

### Verbal Handover

For P1/P2 cases, always do a verbal (not just written) handover.
Walk the incoming analyst through:

1. What happened
1. What's been done
1. What still needs to be done
1. Any traps or gotchas (e.g., "don't block that IP yet, IT confirmed they need it for a patch process")

---

## Receiving an Escalation

When receiving an escalated case:

1. **Acknowledge receipt** — update ticket status and add your name
1. **Read the entire case** before taking any action
1. **Ask questions** if the escalating analyst is still available
1. **Do not redo completed work** — trust the enrichment already done; verify only if suspicious

---

## Practice Exercise

Scenario: You are an L1 analyst at the end of a 6-hour shift.
You have the following open cases:

| Case ID | Title | Severity | Status | Time Open |
|---------|-------|----------|--------|-----------|
| INC-201 | Suspicious DNS — eng-ws-022 | P3 | In Progress (you) | 2 hours |
| INC-202 | PowerShell – svc-backup | P2 | In Progress (you) | 45 min |
| INC-203 | Failed logins – jumphost | P4 | In Progress (you) | 3 hours |
| INC-204 | New admin account created | P2 | New (unreviewed) | 10 min |

**Task 1:** Prioritize which case needs immediate attention before handover.

**Task 2:** Draft the shift handover document for these 4 cases.
For INC-202 (P2), include a verbal brief using the SBAR format.

**Task 3:** Decide which case(s) should be escalated before the end of your shift and justify why.

---

## Key Takeaways

1. Escalate early rather than late — containment delay is the biggest risk
1. The SBAR format ensures key information is communicated clearly
1. Written handover is mandatory; verbal handover is required for P1/P2
1. Incoming analysts own the case once they acknowledge receipt
