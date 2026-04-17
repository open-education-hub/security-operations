# Drill 01 (Advanced): Full SOAR Integration

## Scenario

AcmeCorp's SOC currently uses Elasticsearch (SIEM), TheHive (case management), and CrowdStrike Falcon (EDR).
You have been tasked with implementing an end-to-end SOAR integration for the **ransomware triage playbook** using Shuffle SOAR.

When the SIEM detects ransomware indicators (file encryption activity, shadow copy deletion, mass file renaming), it must:

1. Automatically collect enrichment data
1. Create a P1 case in TheHive
1. Automatically isolate the affected host in CrowdStrike Falcon
1. Notify the SOC team and IT manager on call
1. Initiate a memory dump collection request

## Technical Environment

```text
┌─────────────────────────────────────────────────────┐
│                    AcmeCorp SOC Stack                │
├─────────────────────────────────────────────────────┤
│  Elasticsearch 8.x (SIEM)     → Watcher alerts       │
│  TheHive 5.x                  → Case management      │
│  Cortex 3.x                   → Auto-enrichment      │
│  Shuffle SOAR                 → Orchestration        │
│  CrowdStrike Falcon API       → EDR isolation        │
│  Slack                        → Team notifications   │
└─────────────────────────────────────────────────────┘
```

## Objectives

### Part A: Architecture Design (No Coding Required)

Draw or describe the integration architecture:

1. How does Elasticsearch send alerts to Shuffle?
1. How does Shuffle authenticate to TheHive, Cortex, and CrowdStrike?
1. Where are API keys stored securely?
1. What happens if CrowdStrike API is unavailable?

### Part B: Playbook Implementation

Implement the ransomware triage playbook in Shuffle with the following requirements:

**Requirement 1:** Alert trigger via Elasticsearch Watcher webhook to Shuffle

**Requirement 2:** Auto-create TheHive P1 case with:

* Title including hostname and timestamp
* All affected files (up to 10 sample filenames)
* Source process that triggered the alert
* Automated tag `ransomware`

**Requirement 3:** Query CrowdStrike for host ID by hostname, then isolate the host

**Requirement 4:** Notify `#soc-critical` Slack channel with:

* Alert summary
* TheHive case link
* CrowdStrike isolation status

**Requirement 5:** Failure handling — if CrowdStrike isolation fails, page the on-call engineer via PagerDuty

### Part C: Testing

Write a complete test plan:

1. Test input data (what JSON payload will you send to the webhook?)
1. Expected output at each step
1. How will you verify isolation was successful without isolating a real host?
1. How will you test the failure handling path?

### Part D: Operational Considerations

Answer:

1. What is the blast radius if this playbook has a bug? (What could go wrong?)
1. How would you implement a kill switch to disable the playbook temporarily?
1. What monitoring would you add to detect if the playbook itself fails silently?
1. Should this playbook require human approval before isolation? Justify your answer.

## Docker Environment

A test environment is provided for local testing without real cloud services:

```console
docker compose up -d
```

This starts:

* Shuffle SOAR
* TheHive mock (simplified)
* CrowdStrike API mock (returns success/failure based on hostname)
* Slack webhook mock (logs messages to container stdout)

## Hints

* Shuffle has native TheHive and Slack integrations; CrowdStrike requires custom HTTP actions
* API authentication should use Shuffle's credential vault, not hardcoded values
* Consider the race condition: TheHive case creation and CrowdStrike isolation should run in parallel
* The playbook must complete within 60 seconds for P1 SLA compliance
* CrowdStrike host isolation requires: `POST /devices/actions/v2?action_name=contain`
