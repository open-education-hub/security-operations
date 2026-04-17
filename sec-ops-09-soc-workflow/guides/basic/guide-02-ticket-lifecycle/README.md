# Guide 02 (Basic): Ticket Lifecycle Management

## Objective

Learn how to create, update, and close security cases in a ticketing system following SOC standards.
Understand case states, SLA tracking, and documentation requirements.

## Estimated Time

25–35 minutes

## Prerequisites

* Guide 01 completed
* Session 09 sections 3 and 5

---

## Case Lifecycle States

```text
NEW → ASSIGNED → IN PROGRESS → [ESCALATED] → RESOLVED → CLOSED
                       ↑                            ↓
                   PENDING ←────────────────────────┘
                  (awaiting info)
```

### State Definitions

| State | When to use | SLA clock |
|-------|------------|-----------|
| **NEW** | Alert just arrived, unreviewed | Paused |
| **ASSIGNED** | Analyst has ownership | Running |
| **IN PROGRESS** | Actively investigating | Running |
| **PENDING** | Waiting for user/team response | Paused (typically) |
| **ESCALATED** | Moved to higher tier | Transfer timer starts |
| **RESOLVED** | Containment/response complete | Stopped |
| **CLOSED** | Fully documented, no further action | Stopped |

---

## Creating a Case

### Required Fields

Every security case must capture:

```text
Title:          [Short, descriptive — include asset and behavior]
                Example: "Suspicious PowerShell — acct-ws-017"
                NOT: "Alert #4412" or "Something weird"

Severity:       P1 / P2 / P3 / P4

Status:         (initial: ASSIGNED)

Assigned To:    Your name / team

Description:    Plain-language summary of what happened,
                based on raw alert and initial enrichment

Source Alert:   Alert ID / SIEM link

SLA Deadline:   Calculated from creation time + severity SLA
                P1: +30 min, P2: +2 hours, P3: +8 hours, P4: +24 hours

Observables:    List all IOCs: IPs, hashes, domains, users, hosts
```

### Good Title Examples

| Bad | Good |
|-----|------|
| "Network alert" | "Outbound C2 connection via Tor — finance-ws-042" |
| "User issue" | "Brute force against admin account — m.smith" |
| "Malware?" | "Suspected Cobalt Strike beacon — svchost.exe — prod-srv-01" |

---

## Updating a Case

Every significant action taken must be logged as a case note:

```text
[14:22 UTC] Initial triage complete.
  - VirusTotal: IP 198.98.56.149 — 41/80 vendors, Tor exit node
  - AbuseIPDB: 100% abuse confidence, 1,847 reports
  - Host acct-ws-017 owner: M. Chen, Finance
  - No prior incidents on this host in 90 days
  - No pentest scheduled
  Severity upgraded to P2. Escalating to Tier 2.

[14:35 UTC] Escalated to J. Garcia (Tier 2).
  Reason: Confirmed C2 pattern to known Tor exit node from high-value asset

[15:10 UTC] J. Garcia: Host isolated in CrowdStrike.
  Memory image acquired. Submitted to malware analysis team.
```

### Update Frequency

* P1: Update every 15–30 minutes
* P2: Update every 1–2 hours
* P3/P4: Update at each significant step

---

## Closing a Case

Before closing, verify:

* [ ] Root cause identified
* [ ] All affected systems documented
* [ ] Response actions documented
* [ ] Containment confirmed
* [ ] IOCs added and tagged
* [ ] Classification correct (TP / FP / Benign TP)
* [ ] Post-incident review needed? (yes/no, with justification)

### Closure Classifications

| Classification | Meaning |
|---------------|---------|
| **True Positive** | Real attack, handled |
| **False Positive** | Alert was incorrect, no threat |
| **Benign True Positive** | Alert correct, activity was legitimate (authorized pentest, etc.) |
| **Duplicate** | Already captured in another case |
| **Informational** | No response needed, tracking only |

---

## Practical Exercise

Using TheHive (from Demo 01 or Demo 03), create and manage a case:

### Task 1: Create the Case

Use this alert:

```text
Alert: Suspicious DNS Query
Time: 2024-11-14 16:05 UTC
Host: eng-ws-022 (192.168.20.33)
User: t.kovacs (Engineering)
Query: aabbcc112233.c2-domain-evil.com (TXT record)
DNS answer: 4.4.4.4 (does not resolve to attacker-controlled IP)
```

Create the case with proper title, severity, and description.

### Task 2: Add Observables

Add these observables to the case:

* Domain: `aabbcc112233.c2-domain-evil.com`
* Host: `eng-ws-022`
* User: `t.kovacs`

### Task 3: Enrich and Update

Manually check the domain at VirusTotal and note your findings in a case update.

### Task 4: Make a Triage Decision

Based on your enrichment, decide: TP or FP?
What severity?
Document your decision.

### Task 5: Close the Case

Close with the appropriate classification and a complete closure note.

---

## Key Takeaways

1. Tickets are legal and operational records — write them for someone who wasn't there
1. SLA deadlines are tracked from assignment time
1. Every action must be logged; "I investigated it" is not sufficient
1. Good closure documentation prevents re-triaging the same alert type next week
