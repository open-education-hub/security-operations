# Solution: Drill 01 — SOC Workflow Mapping (MedCorp)

---

## Task 1: Alert Lifecycle Documentation

```text
ALERT LIFECYCLE: MedCorp SOC (Current State)

STEP 1: ALERT GENERATION
  Source: Splunk SIEM (~1,200 alerts/day from multiple rules)
  Trigger condition: Various detection rules
  Data in alert: Alert name, IP, user, timestamp
  Where alert appears: Splunk alert dashboard

  GAP: Alerts not categorized by type/priority automatically;
       analyst must manually assess each.

STEP 2: ALERT ACKNOWLEDGMENT
  Who: L1 Analyst (on shift)
  How: Splunk dashboard — manual check
  Time target: UNDEFINED (no SLA set)
  Action: Analyst reviews alert in Splunk

  GAP: No acknowledgment tracking; if analyst is busy,
       alert can sit for hours.

STEP 3: TRIAGE
  Who: L1 Analyst
  Action: Check alert details, assess manually
  Time target: UNDEFINED

  GAP: No triage checklist; no asset criticality data;
       analyst making decisions without context.
  GAP: 65% FP rate means ~780/day alerts are false positives.

STEP 4: TICKET CREATION
  Who: L1 Analyst (sometimes)
  Tool: Jira

  CRITICAL GAP: Inconsistent — some analysts create tickets,
       some don't. No standard field requirements.

STEP 5: INVESTIGATION
  Who: L1 Analyst
  Tool: Splunk

  GAP: No investigation checklist; no playbooks.
  GAP: Malware alerts take 6+ hours — analyst unsure what to do.

STEP 6: ESCALATION
  Who: L1 → L2 (informal Slack/phone)
  Time target: UNDEFINED

  CRITICAL GAP: Night shift — no L2 coverage.
       Escalations go to voicemail.

STEP 7: RESOLUTION & CLOSURE
  GAP: No closure criteria; no documentation requirements.
  GAP: No post-incident review process.

HANDOVER:
  CRITICAL GAP: No handover procedure.
```

---

## Task 2: Asset Criticality Model for MedCorp

| Tier | Definition | MedCorp Examples | HIPAA Note |
|------|-----------|-----------------|------------|
| **Tier 1 (Critical)** | Loss or compromise immediately halts operations or causes regulatory violation | EHR servers, AD domain controllers, backup systems, HL7 interfaces, medical device gateways | Any breach triggers immediate HIPAA assessment |
| **Tier 2 (High)** | Significant disruption; PHI directly accessible | Billing workstations, database servers, PACS imaging servers, core network infrastructure | PHI accessible — breach affects patient data |
| **Tier 3 (Medium)** | Operational impact; no direct PHI access | Standard employee workstations, HR/Finance servers, scheduling systems | Lateral movement risk to Tier 1/2 |
| **Tier 4 (Low)** | Minimal impact | Lab VMs, test environments, printers, guest WiFi | PHI not accessible |

---

## Task 3: Severity Classification Matrix

| Asset Criticality | Threat: Critical | Threat: High | Threat: Medium | Threat: Low |
|-------------------|-----------------|--------------|----------------|-------------|
| Tier 1 (Critical) | **P1** (4h SLA)  | **P1** (4h)  | **P2** (8h)    | **P2** (8h) |
| Tier 2 (High)     | **P1** (4h)      | **P2** (8h)  | **P2** (8h)    | **P3** (24h) |
| Tier 3 (Medium)   | **P2** (8h)      | **P2** (8h)  | **P3** (24h)   | **P4** (72h) |
| Tier 4 (Low)      | **P2** (8h)      | **P3** (24h) | **P4** (72h)   | **P4** (72h) |

**Justification for Tier 1 Low = P2**: In healthcare, even low-threat events on critical assets must be investigated within 8 hours because HIPAA breach assessment requirements start at the moment of suspected unauthorized access.

---

## Task 4: Workflow Gap Analysis

| # | Gap | Risk | Recommended Fix |
|---|-----|------|-----------------|
| 1 | No SLA targets defined or measured | P1 incidents can take hours to acknowledge; HIPAA breach notification clock may start | Define SLA per severity; implement Jira SLA schemes |
| 2 | Inconsistent ticket creation | No audit trail; impossible to measure MTTR; HIPAA audit requirements unmet | Mandatory tickets for all non-FP alerts; Jira template with required fields |
| 3 | No L2 night coverage | P1 incidents unresponded for 8+ hours; malware spreads; HIPAA violation window extends | On-call L2 rotation; PagerDuty with 30-min SLA; defined escalation path |
| 4 | No asset criticality in SIEM | All alerts treated equally; cannot prioritize; severity miscalculated | Asset criticality lookup table in Splunk; tag all alerts with asset tier |
| 5 | No playbooks | Inconsistent response; 6+ hour malware investigations; analyst uncertainty | Playbooks for top 5 alert types; start with malware and credential attacks |
| 6 | No shift handover procedure | In-progress investigations abandoned; SLA timers not maintained; incidents missed | Standard handover report; 15-min shift overlap; documented in shift log |
| 7 | 65% false positive rate | Alert fatigue; ~780 wasted analyst actions/day; real threats may be missed | Monthly FP review; tune top 3 noisy rules; target <30% within 6 months |
| 8 | No HIPAA incident response procedure | Breach notification deadlines (60 days) may be missed; HHS fines up to $1.9M | HIPAA breach playbook; defined breach determination checklist |

---

## Task 5: RACI Matrix

| Activity | L1 Analyst | L2 Analyst | SOC Manager | CISO | Legal/Compliance |
|----------|-----------|-----------|------------|------|-----------------|
| Alert monitoring | R | C | I | - | - |
| Ticket creation | R | - | I | - | - |
| L1 investigation | R | C | I | - | - |
| Escalation decision (L1→L2) | R | A | I | - | - |
| L2 investigation | C | R | I | I | - |
| HIPAA breach determination | C | R | A | C | C |
| HIPAA incident notification | - | C | R | A | R |
| Night shift escalation | I | R | A | - | - |
| Shift handover | R | C | A | - | - |
| Playbook maintenance | C | R | A | I | C |
| Metrics reporting | - | C | R | A | - |
| Rule tuning | C | R | A | I | - |

*R=Responsible, A=Accountable, C=Consulted, I=Informed*

---

## Examiner Notes

**Common mistakes:**

* Not assigning exactly ONE A per activity
* Missing HIPAA-specific considerations in severity matrix
* Gap analysis that doesn't include measurable risk or specific fixes
* RACI with multiple Accountable roles for same activity
