# Drill 02: Zero Trust Architecture Design

## Difficulty: Intermediate

## Estimated Time: 50 minutes

## Scenario

You are a senior SOC analyst at a European financial institution with 500 employees.
The CISO has asked you to design a Zero Trust architecture for the following situation:

**Current state:**

* All employees connect via a traditional VPN to a flat internal network
* Once on VPN, they can reach all internal systems (no segmentation)
* Applications run on on-premises servers and in Azure (PaaS)
* A breach last year occurred via a phishing attack that compromised a VPN credential (no MFA)
* Authentication is Active Directory; no Azure AD / Entra ID deployed
* No device management (BYOD allowed)

**Target state:**

* Eliminate implicit trust from network location
* Enforce MFA on all access
* Apply least-privilege access to each application
* Enable continuous device health monitoring
* Improve SOC visibility into access patterns

## Objectives

1. Design the Zero Trust architecture components
1. Define the access policy for a specific use case
1. Identify what new SOC monitoring capabilities are gained
1. Address GDPR/privacy considerations
1. Create a phased implementation plan

---

## Task 1: Architecture Design

Draw (or describe in structured text) a Zero Trust architecture that replaces the current VPN setup.
Your design must include:

1. **Identity Provider (IdP)** — which technology, what features
1. **Device management** — how to handle BYOD and corporate devices
1. **Zero Trust Network Access (ZTNA)** — what it replaces, how it works
1. **Application protection** — how each application is protected
1. **SOC integration** — where logs flow and what is monitored

Use the following format:

```text
COMPONENT: [name]
PURPOSE:   [what it does]
TECHNOLOGY: [product/standard]
CONNECTS TO: [other components]
LOGS TO:   [SIEM/audit]
```

---

## Task 2: Access Policy Definition

Define a Zero Trust access policy for the following scenario:

**User**: Alice, Finance Department analyst

**Resource**: Finance ERP application (Azure PaaS, sensitive data)

**Normal access**: 09:00–18:00 CET from company laptop

Write access policy rules covering:

| Scenario | Access Decision | Reason |
|----------|----------------|--------|
| Alice, company laptop, MFA passed, 10:00 CET | | |
| Alice, personal phone, MFA passed, 10:00 CET | | |
| Alice, company laptop, NO MFA, 10:00 CET | | |
| Alice, company laptop, MFA passed, 02:00 CET | | |
| Bob (IT admin), company laptop, MFA passed, 10:00 CET | | |
| Alice, company laptop flagged by EDR as compromised, MFA passed | | |
| Alice, login from Romania (unusual) + MFA passed, 10:00 CET | | |

For each row, state whether access should be: **Allow / Allow with step-up auth / Deny** and why.

---

## Task 3: SOC Monitoring Improvements

Complete the following comparison table for the current VPN model vs. your Zero Trust design:

| Monitoring Capability | VPN Model | Zero Trust Model |
|----------------------|-----------|-----------------|
| Can you see who accessed which application? | | |
| Can you see failed access attempts? | | |
| Can you detect access from a compromised device? | | |
| Can you detect impossible travel? | | |
| Can you detect lateral movement to unauthorised system? | | |
| Can you detect off-hours access to sensitive data? | | |

---

## Task 4: GDPR Considerations

The Zero Trust system logs every access request: user identity, device ID, requested resource, timestamp, location (IP), and access decision.

Answer the following:

1. Is this personal data under GDPR? Why?
1. What is the lawful basis for processing this data for security purposes?
1. How long should access logs be retained? (Consider both security needs and data minimisation)
1. Who within the organisation should have access to these logs?
1. What measures prevent insider abuse of access to the logs?

---

## Task 5: Implementation Roadmap

Design a 12-month phased implementation plan.
The organisation has a limited budget and cannot deploy everything at once.
Prioritise phases by security impact.

**Constraint**: The single VPN breach caused €800,000 in damages.
The CISO has approved a €200,000 budget for ZT implementation.

**Phase structure:**

```text
Phase 1 (Months 1-3): [What to implement first and why]
Phase 2 (Months 4-6): [What comes next]
Phase 3 (Months 7-9): [...]
Phase 4 (Months 10-12): [...]
```

For each phase, state:

* What is implemented
* What security risk is mitigated
* Estimated cost (from the €200K budget)
* Success metrics
