# Drill 02 (Basic): Ticket Management and SLA Tracking

## Scenario

You are responsible for managing the case lifecycle for 6 security incidents.
Your task is to apply correct ticket states, calculate SLA deadlines, identify which cases are at risk of SLA breach, and write proper closure notes.

## SLA Policy Reference

| Severity | Acknowledge By | Resolve By |
|----------|---------------|-----------|
| P1 | 15 minutes | 2 hours |
| P2 | 30 minutes | 4 hours |
| P3 | 2 hours | 12 hours |
| P4 | 4 hours | 48 hours |

## The Cases

### Case INC-501

```text
Title: Ransomware suspected — warehouse-pc-01
Severity: P1
Created: 2024-11-14 09:00 UTC
Current time: 2024-11-14 09:18 UTC
Status: NEW (unassigned)
Notes: None
```

**Question:** Is there an SLA risk?
What should be done immediately?

---

### Case INC-502

```text
Title: Phishing email — 3 recipients — CFO targeted
Severity: P2
Created: 2024-11-14 08:30 UTC
Current time: 2024-11-14 11:45 UTC
Status: IN PROGRESS (assigned to you at 08:45)
Notes: "Looking at it" (added at 08:45)
```

**Question:** Is there an SLA risk?
What is missing from this case?

---

### Case INC-503

```text
Title: Failed VPN logins — s.jones (x8 in 1 hour)
Severity: P3
Created: 2024-11-14 07:00 UTC
Current time: 2024-11-14 10:30 UTC
Status: IN PROGRESS
Notes: "Checked, s.jones says she forgot her password and used the wrong
        one multiple times. She reset it at 09:15 and logged in successfully."
```

**Question:** What is the correct closure classification?
Write a proper closure note.

---

### Case INC-504

```text
Title: Suspicious outbound traffic — dev-ws-044 (1.2 GB in 20 min)
Severity: P2
Created: 2024-11-14 06:00 UTC
Current time: 2024-11-14 10:15 UTC
Status: PENDING (waiting for dev team to respond)
Note: "Asked dev team what this traffic is — no response yet"
```

**Question:** Is the SLA clock running?
Is there anything wrong with the approach?

---

### Case INC-505

```text
Title: Admin login at 02:30 UTC — prod-db-01
Severity: P3
Created: 2024-11-14 03:00 UTC
Current time: 2024-11-14 10:00 UTC
Status: IN PROGRESS
Notes: "Need to check with DBA team to confirm if this was them"
       (Note added at 03:05 UTC, nothing since)
```

**Question:** What SLA breach risk exists?
What should have happened by now?

---

### Case INC-506

```text
Title: AV detection — Trojan.GenericKD.47234 — mkt-ws-012
Severity: P2
Observables: C:\Users\k.wilson\Downloads\invoice_nov14.exe
             SHA256: aabb1122...
Created: 2024-11-14 09:45 UTC
Current time: 2024-11-14 11:00 UTC
Status: RESOLVED
Notes from resolution: "Quarantined file. Closed."
```

**Question:** Is this case ready to close?
What is missing from the resolution note?

---

## Objectives

1. For each case, identify SLA status (on track / at risk / breached)
1. Identify what's missing or wrong in each case's documentation
1. Write corrected closure notes for INC-503 and INC-506
1. Calculate exact SLA deadlines for all 6 cases

## Deliverables

* SLA status table
* Issues identified per case
* Two rewritten closure notes (INC-503 and INC-506)

## Hints

* PENDING typically pauses the SLA clock — but only if properly documented with a reason
* "Looking at it" is not a sufficient case note
* A closure note must answer: What happened? How was it confirmed? What was done?
