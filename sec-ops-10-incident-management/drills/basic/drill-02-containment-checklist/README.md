# Drill 02 (Basic): Containment Checklist Development

## Objective

Create a containment checklist for three specific incident types: ransomware, compromised credentials, and data exfiltration.
Justify each step.

## Background

Your SOC currently has no formal containment checklists.
Analysts are improvising each time, leading to:

* Inconsistent evidence collection
* Missed containment steps
* Varying response quality between analysts

Your task is to create 3 checklists that any Tier 2 analyst can follow.

## Deliverables

Create containment checklists (in table format) for each of the following incident types:

### Checklist 1: Ransomware Containment

Requirements for the checklist:

* Must preserve volatile evidence before any containment action
* Must address spread prevention (lateral movement)
* Must address backup protection
* Must address communication requirements
* All steps must be in correct sequence

Format:

```markdown
| Step | Action | Rationale | Owner |
|------|--------|-----------|-------|
| 1 | ... | ... | L2 Analyst |
```

### Checklist 2: Compromised Credential Containment

Requirements:

* Must address all access vectors (VPN, web apps, M365, on-prem AD)
* Must preserve authentication logs before account changes
* Must address session revocation (not just password reset)
* Must include notification of affected user's manager

### Checklist 3: Data Exfiltration Containment

Requirements:

* Must preserve the evidence of what was exfiltrated
* Must block the exfiltration channel without alerting the attacker (initial phase)
* Must address regulatory notification timeline
* Must include scope assessment (how much data, what type)

## Evaluation Criteria

Each checklist should have:

* Minimum 8 steps
* Steps in correct logical sequence
* Rationale for each step
* Owner assignment (Tier 1 / Tier 2 / IR Manager / IT)
* At least one "human approval" gate for irreversible actions

## Hints

* For ransomware: "Isolate immediately" is step 2, not step 1. What is step 1?
* For credentials: Disabling an account is different from revoking active sessions
* For exfiltration: You may want to monitor for 30 minutes before blocking to understand scope
* Each checklist should reference the evidence handling guide
