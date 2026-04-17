# Session 09: SOC Workflow and Automation

**Estimated reading time: ~2 hours**

---

## Table of Contents

1. [Introduction](#1-introduction)
1. [SOC Workflow Fundamentals: People, Process, Technology](#2-soc-workflow-fundamentals-people-process-technology)
1. [The Alert-to-Ticket Workflow](#3-the-alert-to-ticket-workflow)
1. [SOC Playbooks](#4-soc-playbooks)
1. [SOAR: Security Orchestration, Automation, and Response](#5-soar-security-orchestration-automation-and-response)
1. [SOAR Platforms](#6-soar-platforms)
1. [Key Automation Use Cases](#7-key-automation-use-cases)
1. [Metrics and KPIs for Workflow Optimization](#8-metrics-and-kpis-for-workflow-optimization)
1. [Shift Management and 24/7 Coverage](#9-shift-management-and-247-coverage)
1. [Case Management and Ticketing Systems](#10-case-management-and-ticketing-systems)
1. [SOC Automation Pitfalls](#11-soc-automation-pitfalls)
1. [Building a SOC Runbook](#12-building-a-soc-runbook)
1. [Summary](#13-summary)
1. [References](#14-references)

---

## 1. Introduction

Modern Security Operations Centers (SOCs) face an ever-growing deluge of security alerts.
Industry research consistently shows that mature SOCs receive hundreds of thousands of alerts per day, with analysts able to investigate only a fraction.
The gap between alerts generated and alerts investigated is the "SOC efficiency gap" — and bridging it is the central challenge of SOC workflow engineering.

This session covers the end-to-end workflow inside a SOC: how alerts are triaged, escalated, investigated, and resolved; how playbooks standardize responses; how SOAR platforms automate repetitive tasks; and how metrics drive continuous improvement.
By the end, you will understand not just the tools, but the operational philosophy that makes a SOC function at scale.

**Learning objectives:**

* Describe the full alert-to-closure lifecycle
* Design and document SOC playbooks
* Understand SOAR architecture and its integration points
* Configure basic Shuffle SOAR workflows
* Measure SOC performance using industry-standard KPIs
* Identify and avoid common automation pitfalls

---

## 2. SOC Workflow Fundamentals: People, Process, Technology

### 2.1 The SOC Triad

Every effective SOC rests on three pillars:

**People** — Analysts, engineers, and managers organized into tiers with defined roles and responsibilities.
Without skilled people, neither processes nor technology deliver value.

**Process** — Documented, repeatable procedures that ensure consistency.
Processes convert individual knowledge into organizational capability.

**Technology** — Tools that amplify analyst capacity: SIEM, EDR, SOAR, ticketing, threat intelligence, and more.
Technology without process creates noise; process without technology creates bottlenecks.

The SOC triad is often visualized as a Venn diagram where the intersection — where all three overlap — is "effective security operations."

### 2.2 SOC Tier Structure

Most SOCs use a tiered analyst model:

| Tier | Role | Responsibilities |
|------|------|-----------------|
| Tier 1 | Security Analyst (L1) | Alert triage, initial classification, ticket creation, routine playbook execution |
| Tier 2 | Senior Analyst (L2) | Deep investigation, malware analysis, hunting, escalated incident response |
| Tier 3 | Expert / Threat Hunter (L3) | Advanced threat hunting, zero-day analysis, red team collaboration, tooling development |
| Management | SOC Manager / CISO | Metrics review, stakeholder reporting, resource planning, policy oversight |

**Escalation paths** must be clearly defined.
Ambiguity in escalation leads to "alert limbo" — tickets that bounce between tiers without resolution.

### 2.3 RACI Matrix in the SOC

The RACI (Responsible, Accountable, Consulted, Informed) matrix defines who does what for every process:

| Activity | Tier 1 | Tier 2 | Tier 3 | SOC Manager |
|----------|--------|--------|--------|-------------|
| Alert triage | R | C | - | I |
| Ticket creation | R | - | - | I |
| Incident investigation | C | R | C | I |
| Malware analysis | - | R | C | I |
| Threat hunting | I | C | R | I |
| Metrics reporting | - | C | C | R/A |
| Playbook maintenance | C | R | C | A |

*R = Responsible, A = Accountable, C = Consulted, I = Informed*

### 2.4 The Process Layer: Standard Operating Procedures

Standard Operating Procedures (SOPs) are the backbone of SOC process.
An SOP for alert triage might specify:

1. Analyst receives alert from SIEM queue
1. Analyst checks alert against known false positive list
1. If not on FP list, analyst queries threat intelligence platform
1. Analyst assigns severity (Critical/High/Medium/Low)
1. Analyst creates ticket with required fields populated
1. Analyst follows playbook for the alert type
1. If playbook leads to "escalate," analyst notifies Tier 2

Without this documented process, different analysts make different decisions about the same alert type — creating inconsistency and coverage gaps.

### 2.5 Technology Stack Overview

A typical SOC technology stack includes:

```text
[Data Sources]
├── Firewalls, IDS/IPS
├── Endpoints (EDR: CrowdStrike, Defender, Carbon Black)
├── Cloud (AWS CloudTrail, Azure Monitor)
├── Applications (web servers, databases)
└── Identity (Active Directory, Azure AD)

[Collection & Normalization]
└── Log Shipper (Splunk UF, Filebeat, NXLog)

[Detection & Correlation]
└── SIEM (Splunk, Microsoft Sentinel, QRadar, Elastic)

[Enrichment & Intelligence]
└── Threat Intel Platform (MISP, OpenCTI, Recorded Future)

[Orchestration & Automation]
└── SOAR (Shuffle, Palo Alto XSOAR, Splunk SOAR)

[Case Management]
└── Ticketing (TheHive, Jira, ServiceNow)

[Response]
├── EDR response actions
├── Firewall rule automation
└── Identity (account disable, password reset)
```

---

## 3. The Alert-to-Ticket Workflow

### 3.1 Lifecycle Overview

The alert-to-ticket workflow is the operational heartbeat of a SOC.
Understanding it in detail is essential before attempting to automate any part of it.

```text
SIEM Alert Generated
        │
        ▼
Alert Queue (L1 Analyst)
        │
   ┌────┴────┐
   │  Triage │
   └────┬────┘
        │
   Known FP? ──Yes──> Close / Tune Rule
        │
        No
        │
   Enrich with TI
        │
   Assign Severity
        │
   ┌────┴────┐
   │  Create │
   │  Ticket │
   └────┬────┘
        │
   Execute Playbook
        │
   ┌────┴──────────────┐
   │ Resolved by L1?   │
   └────┬──────────────┘
  Yes   │   No
   │    │    └──> Escalate to L2
   │    │              │
   │    │         L2 Investigation
   │    │              │
   │    │    ┌─────────┴──────────┐
   │    │    │ Incident Declared? │
   │    │    └─────────┬──────────┘
   │    │         Yes  │  No
   │    │          │   │  └──> Resolve / Close
   │    │          │
   │    │    Full IR Process
   │    │    (PICERL)
   │    │
   ▼    ▼
 Ticket Closure
        │
  Post-Incident Review (if applicable)
```

### 3.2 Alert Triage: The First 5 Minutes

Effective triage is the most time-critical phase.
Analysts must quickly determine:

1. **Is this alert valid?** Has the detection rule fired correctly, or is this a known false positive?
1. **What is the context?** Who is the affected user/host? What is their role? What time of day?
1. **What is the severity?** Does this require immediate action or can it wait?
1. **What type of event is this?** Malware? Phishing? Insider threat? Policy violation?

**Triage checklist (per alert):**

* [ ] Check alert source and rule name
* [ ] Verify affected asset (IP, hostname, user account)
* [ ] Check asset criticality in CMDB/asset inventory
* [ ] Query threat intelligence for IOCs in alert
* [ ] Check historical context (has this alert fired before for this asset?)
* [ ] Correlate with other recent alerts (is this part of a pattern?)
* [ ] Assign severity based on asset criticality × threat severity matrix

### 3.3 Severity Classification Matrix

| Asset Criticality | Threat Severity: Critical | Threat Severity: High | Threat Severity: Medium | Threat Severity: Low |
|-------------------|--------------------------|----------------------|------------------------|---------------------|
| Critical Asset    | SEV-1 (P1)               | SEV-1 (P1)           | SEV-2 (P2)             | SEV-3 (P3)          |
| High Asset        | SEV-1 (P1)               | SEV-2 (P2)           | SEV-2 (P2)             | SEV-3 (P3)          |
| Medium Asset      | SEV-2 (P2)               | SEV-2 (P2)           | SEV-3 (P3)             | SEV-4 (P4)          |
| Low Asset         | SEV-2 (P2)               | SEV-3 (P3)           | SEV-4 (P4)             | SEV-4 (P4)          |

### 3.4 Ticket Fields: What to Capture

A well-structured security ticket captures everything needed for investigation and post-incident analysis:

**Mandatory fields:**

* Ticket ID (auto-generated)
* Created timestamp
* Alert source (SIEM rule name / alert ID)
* Severity (P1-P4)
* Status (New / In Progress / Pending / Resolved / Closed)
* Assigned analyst
* Affected assets (IP, hostname, user)
* Alert type (malware, phishing, brute force, etc.)
* Initial description

**Investigation fields (populated during analysis):**

* IOCs extracted (IPs, hashes, domains, URLs)
* MITRE ATT&CK technique(s)
* Evidence artifacts collected
* Timeline of events
* Analysis notes
* Escalation history

**Closure fields:**

* Resolution type (True Positive / False Positive / Benign True Positive)
* Root cause
* Remediation actions taken
* Lessons learned
* Rule tuning recommendations (if FP)
* Closed timestamp
* SLA met? (Y/N)

### 3.5 SLA Definitions

Service Level Agreements define response time obligations:

| Severity | Acknowledgment | Initial Triage | Escalation (if needed) | Resolution Target |
|----------|---------------|----------------|----------------------|------------------|
| P1 (Critical) | 5 minutes | 15 minutes | 30 minutes | 4 hours |
| P2 (High) | 15 minutes | 30 minutes | 1 hour | 8 hours |
| P3 (Medium) | 1 hour | 2 hours | 4 hours | 24 hours |
| P4 (Low) | 4 hours | 8 hours | N/A | 72 hours |

SLA compliance is a primary KPI — SOCs typically target >95% SLA adherence for P1/P2 alerts.

---

## 4. SOC Playbooks

### 4.1 What Is a Playbook?

A playbook is a documented set of procedures that an analyst follows when responding to a specific type of security event.
Playbooks encode institutional knowledge, ensure consistency, and reduce the cognitive load on analysts — especially during high-pressure incidents.

**Playbook vs.
Runbook:**

* **Playbook**: Strategic, scenario-based. Covers decision logic, roles, escalation paths. "What to do when X happens."
* **Runbook**: Tactical, step-by-step operational procedures. "How to execute step Y of the playbook." Often includes specific commands, tool configurations, and verification steps.

### 4.2 Types of Playbooks

**Response Playbooks** — Guide analysts through investigating and remediating a specific threat type:

* Phishing email response
* Ransomware containment
* Brute force / credential stuffing
* Malware on endpoint
* Data exfiltration detection
* Insider threat investigation

**Escalation Playbooks** — Define when and how to escalate:

* From L1 to L2 criteria
* L2 to L3 escalation
* Incident declaration criteria
* Executive notification procedures
* Law enforcement notification criteria

**Communication Playbooks** — Govern stakeholder communication:

* Internal incident notification templates
* Customer breach notification procedures
* Regulatory notification (GDPR 72-hour requirement)
* Media/PR coordination
* Board-level reporting templates

### 4.3 Playbook Structure

A well-designed playbook contains:

```text
Playbook: [Name]
Version: [X.Y]
Last Updated: [Date]
Owner: [Team/Person]
Review Cycle: [Quarterly/Annually]

1. PURPOSE

   Brief description of when this playbook applies

2. SCOPE
   Systems, environments, alert types covered

3. PREREQUISITES
   - Access requirements
   - Tool prerequisites
   - Knowledge prerequisites

4. TRIGGER CONDITIONS
   - Which SIEM rules trigger this playbook
   - Manual trigger criteria

5. PROCEDURE
   Step 1: [Action]
      - How: [Specific instructions]
      - Tool: [Which tool to use]
      - Expected output: [What success looks like]
      - If unexpected: [Go to step X or escalate]

   Step 2: [Decision point]
      - If [condition A] → Go to Step 3
      - If [condition B] → Go to Step 7
      - If [condition C] → Escalate to L2

   [Continue for all steps...]

6. ESCALATION CRITERIA
   Explicit conditions that require L2/L3/incident declaration

7. CONTAINMENT ACTIONS
   Specific remediation steps with tool commands

8. EVIDENCE COLLECTION
   What artifacts to preserve and how

9. CLOSURE CRITERIA
   What must be true before closing the ticket

10. COMMUNICATION
    Who to notify, when, using which template

11. METRICS
    Time targets for each phase

12. APPENDIX
    Reference commands, tool quick-reference, contact list
```

### 4.4 Playbook Decision Tree Example: Phishing Email

```text
[TRIGGER: SIEM Rule "Suspicious Email Received" OR User Reported Phishing]
                │
                ▼

    1. Extract email headers, sender, subject, URLs, attachments

                │
                ▼
    2. Check sender domain against TI feeds
                │
         ┌──────┴──────┐
      Known Bad     Unknown/Clean
         │               │
         ▼               ▼
    3a. Auto-quarantine  3b. Check URL sandbox (VirusTotal/URLscan)
    all copies              │
         │           ┌─────┴──────┐
         │        URL Bad      URL Clean
         │           │              │
         │           ▼              ▼
         │    3c. Extract IOCs   3d. Check attachment hash
         │    Block URLs             │
         │           │         ┌────┴────┐
         │           │      Hash Bad   Hash Clean
         │           │         │           │
         └───────────┤         ▼           ▼
                     │   3e. Sandbox   3f. Check if user
                     │   attachment    clicked/opened
                     │        │           │
                     └────────┴─────┐     │
                                    ▼     ▼
                          4. Did user click/open?
                              │         │
                             Yes        No
                              │         │
                              ▼         ▼
                     5. Check endpoint   6. Close as
                     for compromise         "No Action"
                              │
                         ┌────┴─────┐
                    Compromise?   No Compromise
                         │           │
                         ▼           ▼
                  7. Escalate L2   8. Block IOCs
                  Incident IR      Notify user
                  Declared         Close ticket
```

### 4.5 Playbook Maintenance

Playbooks degrade over time.
A maintenance program must include:

**Triggers for immediate review:**

* A playbook step is found to be incorrect during an incident
* New tools are deployed that change procedures
* A new threat variant doesn't fit existing playbook logic
* A post-incident review identifies playbook gaps

**Scheduled review cycle:**

* All playbooks reviewed quarterly for accuracy
* Annual comprehensive review including tabletop exercise validation
* Version control all playbooks (Git recommended)
* Change log maintained for audit purposes

**Quality metrics:**

* Playbook coverage ratio: % of alert types with documented playbooks
* Playbook adherence rate: % of incidents where playbook was followed
* Average playbook execution time vs. target
* Playbook-identified FP rate (playbooks that consistently lead to FP closure may need rule tuning)

---

## 5. SOAR: Security Orchestration, Automation, and Response

### 5.1 What is SOAR?

SOAR (Security Orchestration, Automation, and Response) is a category of technology that enables SOCs to:

1. **Orchestrate** — Integrate disparate security tools into unified workflows
1. **Automate** — Execute repetitive tasks without human intervention
1. **Respond** — Take automated or semi-automated response actions

The term was coined by Gartner in 2015 to describe platforms combining Security Incident Response Platforms (SIRP), Security Orchestration and Automation (SOA), and Threat Intelligence Platforms (TIP).

### 5.2 SOAR Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     SOAR PLATFORM                           │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Playbook   │  │  Case/Alert │  │   Workflow Engine   │ │
│  │   Engine    │  │  Management │  │  (Trigger→Action)   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│  ┌──────▼──────────────────────────────────────▼──────────┐ │
│  │              Integration Bus / API Gateway              │ │
│  └──────┬──────────────────────────────────────┬──────────┘ │
│         │                                       │            │
└─────────┼───────────────────────────────────────┼───────────┘
          │                                       │
    ┌─────▼──────────────────────────────┐  ┌────▼─────────┐
    │         Security Tools              │  │  Ticketing   │
    │  ┌────────┐ ┌────────┐ ┌────────┐  │  │  ┌────────┐  │
    │  │  SIEM  │ │  TIP   │ │  EDR   │  │  │  │TheHive │  │
    │  └────────┘ └────────┘ └────────┘  │  │  └────────┘  │
    │  ┌────────┐ ┌────────┐ ┌────────┐  │  │  ┌────────┐  │
    │  │Firewall│ │VT/AV   │ │  LDAP  │  │  │  │  Jira  │  │
    │  └────────┘ └────────┘ └────────┘  │  │  └────────┘  │
    └────────────────────────────────────┘  └──────────────┘
```

**Core SOAR components:**

* **Workflow Engine**: Executes automated sequences of actions (if-this-then-that logic, branching, loops)
* **Playbook Designer**: Visual interface (usually drag-and-drop) for building automated playbooks
* **Case Management**: Tracks incidents, evidence, analyst notes, timelines
* **Integration Layer**: Pre-built connectors ("apps") for hundreds of security tools
* **Reporting & Metrics**: Dashboards showing automation rates, response times, analyst workload

### 5.3 SOAR Trigger Types

| Trigger Type | Description | Example |
|-------------|-------------|---------|
| Event-driven | New alert from SIEM/tool | SIEM fires rule → SOAR starts playbook |
| Scheduled | Time-based execution | Daily IOC enrichment job at 2AM |
| Manual | Analyst initiates | Analyst right-clicks alert → "Run playbook" |
| Webhook | External system calls SOAR API | Threat feed update triggers IOC block |
| Email | Parsed email triggers workflow | User forwarded phishing email |

### 5.4 SOAR Action Categories

SOAR actions fall into several categories:

**Enrichment actions (read-only, no impact):**

* Query VirusTotal for file hash
* Check IP reputation in threat intel feeds
* Look up user in Active Directory
* Get asset details from CMDB
* Check email headers against SPF/DKIM/DMARC

**Containment actions (impact on environment):**

* Block IP on firewall
* Quarantine endpoint (EDR isolation)
* Disable user account (AD/Azure AD)
* Revoke OAuth tokens
* Delete malicious email from all mailboxes

**Communication actions:**

* Create ticket in TheHive/Jira/ServiceNow
* Send Slack/Teams notification to analyst
* Email stakeholders with templated message
* Page on-call via PagerDuty

**Investigation actions:**

* Pull endpoint forensic data (process list, network connections)
* Collect memory dump
* Extract PCAP for network flow
* Run YARA scan on endpoint

### 5.5 Human-in-the-Loop vs. Full Automation

Not every action should be fully automated.
The decision framework:

| Criteria | Automate Fully | Human Approval Required |
|----------|---------------|------------------------|
| Impact if wrong | Low (enrichment) | High (account disable, network block) |
| Reversibility | Easily reversible | Difficult/impossible to reverse |
| False positive rate | <1% | >1% |
| Asset criticality | Non-critical | Critical business systems |
| Compliance requirement | N/A | Legal/regulatory review needed |

**Best practice**: Start with enrichment automation (zero risk), then progress to containment with human approval gates, then fully automate only high-confidence, low-impact actions.

---

## 6. SOAR Platforms

### 6.1 Shuffle (Open Source)

**Shuffle** is a free, open-source SOAR platform built for the security community.
It provides:

* Visual drag-and-drop workflow builder
* 400+ pre-built app integrations
* Docker-based deployment
* REST API for custom integrations
* OpenAPI specification import for new tools
* Cloud and self-hosted options

**Architecture:**

```text
┌─────────────────────────────────────────┐
│            Shuffle Components            │
│                                         │
│  ┌──────────┐  ┌──────────┐             │
│  │ Frontend │  │ Backend  │             │
│  │ (React)  │  │  (Go)    │             │
│  └──────────┘  └──────────┘             │
│  ┌──────────┐  ┌──────────┐             │
│  │  Orborus │  │  Worker  │             │
│  │(Scheduler│  │(Executor)│             │
│  └──────────┘  └──────────┘             │
│  ┌──────────────────────────┐           │
│  │      OpenSearch/DB       │           │
│  └──────────────────────────┘           │
└─────────────────────────────────────────┘
```

**Key Shuffle concepts:**

* **Workflow**: A collection of actions connected by triggers and conditions
* **App**: A pre-built integration with a specific tool (e.g., "TheHive", "Splunk", "VirusTotal")
* **Action**: A specific operation within an app (e.g., TheHive → Create Alert)
* **Trigger**: What starts a workflow (webhook, schedule, manual)
* **Variable**: Dynamic values passed between actions

**Shuffle Docker Compose (minimal):**

```yaml
version: '3'
services:
  frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    ports:
      - "3001:80"
      - "3443:443"
    environment:
      - BACKEND_HOSTNAME=backend

  backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    ports:
      - "5001:5001"
    environment:
      - SHUFFLE_APP_HOTLOAD_FOLDER=./shuffle-apps
      - SHUFFLE_FILE_LOCATION=./shuffle-files
      - OPENSEARCH_URL=http://opensearch:9200

  orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    environment:
      - SHUFFLE_APP_SDK_VERSION=1.1.0
      - SHUFFLE_WORKER_VERSION=latest
      - ORG_ID=default
      - ENVIRONMENT_NAME=default
      - BASE_URL=http://backend:5001

  opensearch:
    image: opensearchproject/opensearch:2.11.1
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
```

### 6.2 Palo Alto XSOAR (Cortex XSOAR)

Formerly Demisto, XSOAR is the market-leading enterprise SOAR platform.

**Key differentiators:**

* Python-based playbook scripting with full IDE
* 900+ integration packs on the Marketplace
* Multi-tenant architecture for MSSPs
* Threat intelligence management built-in
* Machine learning for alert clustering and prioritization
* Comprehensive audit trail for compliance

**XSOAR Playbook structure:**

* Tasks: Individual steps (manual, automated, conditional)
* Scripts: Python/JavaScript automation snippets
* Commands: Calls to integration functions
* Conditions: Branching logic
* Loops: Iterative processing

**Deployment options:**

* On-premises (Linux)
* Cloud (Cortex XSOAR Cloud)
* MSSP (multi-tenant cloud)

**Cost**: Enterprise licensing, typically `$50K-$500K`+/year depending on scale.

### 6.3 Splunk SOAR (formerly Phantom)

Splunk SOAR integrates tightly with Splunk SIEM to provide native orchestration.

**Key features:**

* Visual Playbook Editor (VPE) with drag-and-drop
* Mission Control for SOC overview
* 350+ apps in Splunk app catalog
* Event-driven automation from Splunk alerts
* Full Python scripting for custom actions
* REST API for external integrations

**Splunk SOAR concepts:**

* **Event**: An alert or case ingested into SOAR
* **Artifact**: Data extracted from an event (IP, hash, URL)
* **Asset**: A configured integration (your VirusTotal API key, your firewall credentials)
* **App**: The integration package (VirusTotal app, CrowdStrike app)
* **Action**: A specific function of an app (detonate file, block domain)
* **Playbook**: Automated workflow connecting actions

**Integration with Splunk SIEM:**

```text
Splunk Alert → Notable Event → SOAR Event Ingestion
    → Automated Playbook Execution
    → Analyst Review in Mission Control
    → Actions taken → Update back to Splunk
```

### 6.4 Microsoft Sentinel + Logic Apps

Microsoft Sentinel's native SOAR capability is built on Azure Logic Apps (automation rules + playbooks).

**Key features:**

* Native Azure integration (no separate SOAR deployment)
* 200+ Logic Apps connectors
* Low-code/no-code approach
* Per-execution pricing model (no flat license)
* Deep Microsoft 365 integration (Teams, Exchange, Azure AD)
* Automation rules for alert routing and auto-close

**Sentinel Playbook example trigger:**

```text
Trigger: Microsoft Sentinel Incident trigger
    └── Condition: Incident severity = High
        └── Action: Get account entity
            └── Action: Disable user in Azure AD
                └── Action: Post Teams message to SOC channel
                    └── Action: Update incident status = Active
```

**Pricing**: ~`$0.000025` per action execution.
A playbook with 10 actions running on 10,000 alerts/month = `$2.50`/month for the Logic Apps execution.

### 6.5 Platform Comparison

| Feature | Shuffle | XSOAR | Splunk SOAR | Sentinel LA |
|---------|---------|-------|-------------|-------------|
| Cost | Free (OSS) | `$$$$` | `$$$` | Pay-per-use |
| Deployment | Docker/Cloud | On-prem/Cloud | On-prem/Cloud | Azure native |
| Integrations | 400+ | 900+ | 350+ | 200+ (Azure) |
| Scripting | Python/any | Python | Python | JSON/code |
| Best for | Labs/SMB | Enterprise | Splunk shops | Azure/M365 |
| Learning curve | Low | High | Medium | Low-Medium |
| Community | Growing | Large | Large | Large |

---

## 7. Key Automation Use Cases

### 7.1 Phishing Email Triage Automation

Phishing triage is the highest-volume, most automatable SOC workflow.
A fully automated phishing playbook can handle 90%+ of phishing cases without analyst involvement.

**Automated phishing playbook steps:**

```python
# Conceptual Python logic for phishing automation

def phishing_triage_playbook(alert):
    # Step 1: Extract IOCs from email
    iocs = extract_email_iocs(alert.raw_email)
    # iocs = {sender, reply_to, urls, attachments, headers}

    # Step 2: Enrich IOCs in parallel
    reputation = parallel_enrich([
        virustotal.check_url(url) for url in iocs.urls
    ] + [
        virustotal.check_hash(h) for h in iocs.attachment_hashes
    ] + [
        threatintel.check_domain(iocs.sender_domain)
    ])

    # Step 3: Determine maliciousness score
    score = calculate_maliciousness_score(reputation)

    # Step 4: Take action based on score
    if score >= 80:  # High confidence malicious
        # Auto-quarantine all copies
        exchange.quarantine_email(iocs.message_id, all_mailboxes=True)
        # Block IOCs
        firewall.block_domains(iocs.malicious_domains)
        # Check if user clicked
        if siem.check_url_click(iocs.urls):
            # Escalate for endpoint investigation
            ticket.create(severity="High", escalate_to="L2")
        else:
            ticket.create(severity="Medium", status="Auto-resolved")

    elif score >= 40:  # Suspicious
        # Quarantine and create ticket for analyst review
        exchange.quarantine_email(iocs.message_id)
        ticket.create(severity="Medium",
                     assigned_to="L1",
                     requires_approval=True)

    else:  # Clean
        ticket.create(severity="Low", status="Auto-closed",
                     resolution="Clean email")
```

**Automation rate achievable**: 70-90% of phishing alerts auto-resolved.

**Time savings**: From ~15 min/alert to ~30 seconds/alert.

### 7.2 IOC Enrichment Automation

Every alert contains indicators (IPs, domains, hashes, URLs) that need enrichment before an analyst can assess severity.
This is pure automation territory.

**IOC enrichment workflow:**

1. **Extract IOCs** from alert (parse SIEM alert fields)
1. **Deduplicate** (don't query the same IOC twice)
1. **Check cache** (avoid re-querying recently seen IOCs)
1. **Parallel enrichment queries:**
   * VirusTotal (malware/URL reputation)
   * AbuseIPDB (IP abuse history)
   * Shodan (port/service exposure)
   * WHOIS (domain registration)
   * MISP (internal threat intel matches)
1. **Aggregate results** into enrichment report
1. **Attach to ticket** and update severity
1. **Auto-block** if reputation score above threshold

**Python enrichment script pattern:**

```python
import asyncio
import aiohttp

async def enrich_ip(session, ip_address, api_keys):
    """Async IOC enrichment for an IP address"""
    results = {}

    # VirusTotal
    async with session.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
        headers={"x-apikey": api_keys["virustotal"]}
    ) as resp:
        vt_data = await resp.json()
        results["virustotal"] = {
            "malicious": vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"],
            "total": sum(vt_data["data"]["attributes"]["last_analysis_stats"].values())
        }

    # AbuseIPDB
    async with session.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip_address, "maxAgeInDays": 90},
        headers={"Key": api_keys["abuseipdb"], "Accept": "application/json"}
    ) as resp:
        abuse_data = await resp.json()
        results["abuseipdb"] = {
            "confidence_score": abuse_data["data"]["abuseConfidenceScore"],
            "total_reports": abuse_data["data"]["totalReports"]
        }

    return results

async def enrich_multiple_ips(ip_list, api_keys):
    async with aiohttp.ClientSession() as session:
        tasks = [enrich_ip(session, ip, api_keys) for ip in ip_list]
        return await asyncio.gather(*tasks)
```

### 7.3 Account Lockout / Brute Force Response

Automated response to credential-based attacks is high-value because:

* Speed matters (attacker may be actively trying passwords)
* Response actions (lockout, alert) are well-defined
* False positive rate for successful brute force is low

**Automated brute force playbook:**

```text
Trigger: SIEM rule "Brute Force Success" (>50 failed then 1 success)
    │
    ├── Extract: username, source_ip, target_system
    │
    ├── Enrich: IP reputation (AbuseIPDB), ASN (is it a corporate IP?)
    │
    ├── Check: Is this a service account or privileged account?
    │       │
    │    Yes │                    No │
    │       ▼                       ▼
    │  IMMEDIATE:              Schedule lockout
    │  Disable account         with 15-min delay
    │  Page SOC manager        (allow false positive review)
    │       │                       │
    ├───────┘                       │
    │                               │
    ├── Block source IP on perimeter firewall
    │
    ├── Notify user via email/SMS
    │
    ├── Create P1 ticket, assign to L2
    │
    ├── Query SIEM: other systems accessed from same IP in last 24h
    │
    └── If other systems accessed → Escalate to incident
```

### 7.4 Vulnerability Alert Enrichment

For vulnerability management feeds (Qualys, Tenable, Rapid7 alerts), automation can:

* Correlate CVE with EPSS score (exploitation probability)
* Check if CVE has public PoC exploit code
* Identify affected assets and their business criticality
* Auto-create Jira ticket for patch team with SLA based on CVSS + EPSS + asset criticality
* Track patch deployment status

---

## 8. Metrics and KPIs for Workflow Optimization

### 8.1 Core SOC Metrics

Effective SOC management requires rigorous measurement.
The following metrics are industry standard.

#### Mean Time to Detect (MTTD)

**Definition**: Average time from when a threat event occurs to when the SOC detects it (generates an alert).

**Formula**: `MTTD = Σ(Detection Time - Event Time) / Number of Events`

**Target**: <24 hours for most threats; <1 hour for critical threats.

**How to improve**: Tune detection rules, add new data sources, implement threat hunting.

#### Mean Time to Respond (MTTR)

**Definition**: Average time from alert detection to full incident containment/resolution.

**Formula**: `MTTR = Σ(Resolution Time - Detection Time) / Number of Incidents`

**Target**: <4 hours for P1; <8 hours for P2; <24 hours for P3.

**How to improve**: Automate enrichment, streamline escalation, pre-approved containment actions.

#### Mean Time to Acknowledge (MTTA)

**Definition**: Time from alert generation to analyst acknowledgment (ticket creation or status change).

**Formula**: `MTTA = Σ(Acknowledge Time - Alert Time) / Number of Alerts`

**Target**: Within SLA times defined in Section 3.5.

#### False Positive Rate (FPR)

**Definition**: Percentage of alerts that are false positives.

**Formula**: `FPR = False Positives / Total Alerts × 100`

**Target**: <20% overall; <5% for high-priority rules.

**Impact**: A 50% FPR means analysts waste half their time on non-threats.
Each 10% reduction in FPR effectively increases analyst capacity by 11%.

#### Alert Volume and Trend

Track daily/weekly/monthly alert volumes.
Sudden spikes may indicate:

* New attack campaign
* New detection rule deployed
* System misconfiguration generating spurious alerts

#### Automation Rate

**Definition**: Percentage of alerts handled automatically without analyst intervention.

**Formula**: `Automation Rate = Auto-resolved Alerts / Total Alerts × 100`

**Target**: 60-80% for mature SOCs (highly automatable alert types).

**Interpretation**: A 70% automation rate means 30% of alerts require human attention, freeing analysts for complex work.

#### Analyst Alerts per Shift

**Definition**: Number of alerts each analyst handles per shift.

**Target varies**: 20-50 alerts/shift is typical; >100 may indicate analyst burnout risk.

#### SLA Compliance Rate

**Definition**: Percentage of tickets resolved within defined SLA.

**Formula**: `SLA Compliance = Tickets Resolved Within SLA / Total Tickets × 100`

**Target**: >95% for P1/P2; >90% for P3/P4.

### 8.2 Metrics Dashboard Structure

A SOC metrics dashboard should show:

```text
┌─────────────────────────────────────────────────────────────────┐
│                    SOC OPERATIONS DASHBOARD                     │
│                  [Last 24h] [Last 7d] [Last 30d]               │
├─────────┬─────────┬─────────┬─────────┬─────────┬─────────────┤
│ ALERTS  │  MTTD   │  MTTR   │  FPR    │  AUTO   │ SLA COMP.   │
│  1,247  │ 18 min  │ 2.3 hr  │  22%    │  68%    │ P1:98% P2:  │
│ ▲ +12%  │ ▼ -5min │ ▼ -30m  │ ▼ -3%   │ ▲ +5%   │ 95% P3:91% │
├─────────┴─────────┴─────────┴─────────┴─────────┴─────────────┤
│                                                                 │
│  Alert Volume by Type (7d)      │  Analyst Workload            │
│  Phishing:      ████████ 41%    │  Analyst A: ██████████ 52   │
│  Brute Force:   ████ 21%        │  Analyst B: ████████ 45     │
│  Malware:       ███ 15%         │  Analyst C: ████████████ 61 │
│  Policy Viol.:  ██ 11%          │  Analyst D: ███████ 39      │
│  Other:         ██ 12%          │                              │
├─────────────────────────────────┴──────────────────────────────┤
│  SLA Breach Risk (tickets approaching SLA)                      │
│  TKT-2847 [P2] Created: 6h ago    SLA: 8h   ████████░░ 75%    │
│  TKT-2851 [P2] Created: 7.5h ago  SLA: 8h   █████████░ 94%    │
│  TKT-2839 [P3] Created: 22h ago   SLA: 24h  █████████░ 92%    │
└─────────────────────────────────────────────────────────────────┘
```

### 8.3 Using Metrics to Drive Improvement

Metrics without action are noise.
A metrics-driven improvement cycle:

1. **Measure**: Establish baseline for all KPIs
1. **Analyze**: Identify root causes of underperformance
1. **Improve**: Implement targeted changes (rule tuning, new automation, training)
1. **Verify**: Confirm improvement in metrics
1. **Standardize**: Document what worked, update playbooks/runbooks

**Example improvement cycle:**

* *Problem*: MTTR for phishing alerts is 4.5 hours (target: 2 hours)
* *Analysis*: 60% of time is spent on IOC enrichment (manual)
* *Fix*: Implement automated IOC enrichment playbook
* *Result*: MTTR drops to 1.8 hours (target achieved)
* *Standardize*: Document the automation, add to new analyst training

---

## 9. Shift Management and 24/7 Coverage

### 9.1 Coverage Models

SOCs require 24/7/365 coverage.
Common models:

**Follow-the-Sun Model:**
Three regional teams covering 8-hour shifts aligned to business time zones:

* Americas team: covers UTC-8 to UTC+0 business hours
* EMEA team: covers UTC+0 to UTC+8 business hours
* APAC team: covers UTC+8 to UTC+16 business hours

*Advantage*: Analysts work normal business hours; good for global organizations.
*Disadvantage*: Knowledge transfer across time zones; handover complexity.

**3-Shift Rotation Model:**
One location, three shifts:

* Day shift: 07:00-15:00
* Afternoon shift: 15:00-23:00
* Night shift: 23:00-07:00

*Advantage*: Single location, easier coordination.
*Disadvantage*: Night shift is understaffed and lower effectiveness; night shift health impacts.

**12-Hour Shift Model:**
Two 12-hour shifts (day/night), teams rotate weekly:

* Day team: 07:00-19:00
* Night team: 19:00-07:00

*Advantage*: Fewer handovers; team continuity.
*Disadvantage*: 12-hour shifts are cognitively demanding.

**Hybrid On-Call Model (for smaller SOCs):**

* Daytime: Full team present
* Nights/weekends: On-call rotation with escalation SLA

*Advantage*: Cost-effective for smaller orgs.
*Disadvantage*: Slower night response times.

### 9.2 Shift Handover Procedures

A poor handover is one of the most common causes of SLA breaches and missed incidents.
A structured handover includes:

**15-minute handover meeting agenda:**

1. Open incidents (P1/P2): Status, actions taken, next steps, owner transfer
1. Active playbooks running: What automated actions are in progress
1. Ongoing investigations: Context for tickets in "In Progress" state
1. Notable observations: Anything unusual seen during shift (even if not a ticket)
1. Operational issues: Any tool outages, connectivity issues, data gaps
1. Shift metrics review: Alert volume, SLA compliance, notable FPs

**Handover documentation template:**

```text
SHIFT HANDOVER REPORT
Date: ____________  Shift: ____________
Outgoing Analyst(s): ________________
Incoming Analyst(s): ________________

OPEN P1/P2 INCIDENTS:
─────────────────────────────────────
Ticket: [ID]  Severity: [P1/P2]
Status: [Current status]
Summary: [Brief description]
Actions Taken: [What was done]
Next Actions: [What incoming analyst needs to do]
ETA to Resolution: [Estimate]

IN-PROGRESS INVESTIGATIONS:
─────────────────────────────────────
[List all tickets in "In Progress" state]

NOTABLE OBSERVATIONS:
─────────────────────────────────────
[Anything unusual, even without a ticket]

TOOL STATUS:
─────────────────────────────────────
SIEM: [OK/Degraded - describe]
SOAR: [OK/Degraded - describe]
EDR Console: [OK/Degraded - describe]

SHIFT METRICS:
─────────────────────────────────────
Alerts Received: ___
Tickets Created: ___
Tickets Resolved: ___
SLA Breaches: ___
Auto-resolved: ___
```

### 9.3 On-Call Management

For escalations outside business hours:

**On-call tool options**: PagerDuty, OpsGenie, VictorOps

**Escalation tiers**:

* Level 1: On-call Tier 1/2 analyst (responds in 15 min)
* Level 2: Senior analyst/threat hunter (if L1 cannot resolve in 1 hour)
* Level 3: SOC manager (for incident declarations, executive notifications)
* Level 4: CISO/Legal/PR (for data breach, public-facing incidents)

---

## 10. Case Management and Ticketing Systems

### 10.1 TheHive

TheHive is an open-source, scalable Security Incident Response Platform (SIRP) designed specifically for SOC operations.

**Key features:**

* Alert/case management with rich evidence tracking
* Cortex integration for automated IOC analysis
* MISP integration for threat intelligence sharing
* Multi-team and multi-tenancy support
* Audit trail for compliance
* Custom case templates and observables

**Core TheHive concepts:**

* **Alert**: Potential security event requiring triage (can become a case)
* **Case**: Confirmed security incident under investigation
* **Observable**: IOC attached to a case (IP, hash, URL, email, domain)
* **Task**: Investigation task within a case (with assignee, deadline, status)
* **Cortex Analyzer**: Automated enrichment/analysis job run on an observable

**TheHive + Cortex integration:**

```text
Observable (IP: 185.220.101.x) added to case
    │
    └── Cortex runs analyzers in parallel:
        ├── AbuseIPDB_3_0 → "Abuse confidence: 87%"
        ├── VirusTotal_GetIP_3_0 → "Detected by 12/87 engines"
        ├── Shodan_Host_2_1 → "Ports: 22, 80, 443; ASN: AS..."
        └── MaxMind_GeoIP_3_0 → "Netherlands, hosting provider"
    │
    └── Results attached to observable; analyst reviews summary
```

**Docker Compose for TheHive + Cortex:**

```yaml
version: '3'
services:
  thehive:
    image: strangebee/thehive:5.3
    depends_on:
      - cassandra
      - elasticsearch
      - cortex
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1g
    volumes:
      - ./thehive/application.conf:/etc/thehive/application.conf
      - thehive-data:/opt/thehive/data

  cortex:
    image: thehiveproject/cortex:3.1.8
    depends_on:
      - elasticsearch
    ports:
      - "9001:9001"
    volumes:
      - ./cortex/application.conf:/etc/cortex/application.conf
      - /var/run/docker.sock:/var/run/docker.sock

  cassandra:
    image: cassandra:4
    volumes:
      - cassandra-data:/var/lib/cassandra

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.14
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - elastic-data:/usr/share/elasticsearch/data

volumes:
  thehive-data:
  cassandra-data:
  elastic-data:
```

### 10.2 Jira Service Management

Many organizations already use Jira for IT operations and extend it for security:

**Advantages:**

* Single platform for IT and security tickets
* Familiar interface for non-security stakeholders
* Powerful workflow automation
* Extensive integrations (Confluence, OpsGenie, etc.)

**Security-specific configuration:**

* Custom issue type: "Security Incident"
* Custom fields: Severity, IOCs, MITRE technique, evidence links
* Workflow: New → Triaging → Investigating → Containing → Remediating → Closed
* SLA schemes per severity
* Automation rules: auto-assign by severity, escalation triggers

**Jira API integration (Python):**

```python
from jira import JIRA

def create_security_ticket(alert_data):
    jira = JIRA(
        server="https://your-company.atlassian.net",
        basic_auth=("user@company.com", "api_token")
    )

    issue_dict = {
        "project": {"key": "SEC"},
        "summary": f"[{alert_data['severity']}] {alert_data['title']}",
        "description": f"""
*Alert Source*: {alert_data['source']}
*Affected Asset*: {alert_data['asset']}
*Detection Time*: {alert_data['timestamp']}

*Alert Details*:
{alert_data['description']}

*IOCs*:
{chr(10).join(f'- {ioc}' for ioc in alert_data['iocs'])}
        """,
        "issuetype": {"name": "Security Incident"},
        "priority": {"name": alert_data["severity"]},
        "customfield_10100": alert_data["alert_id"],
    }

    new_issue = jira.create_issue(fields=issue_dict)
    return new_issue.key
```

### 10.3 ServiceNow

ServiceNow is the enterprise ITSM standard, and its Security Incident Response (SIR) module provides:

* Native Security Operations workflow
* Integration with GRC (Governance, Risk, Compliance)
* CMDB integration for asset criticality
* SLA management with escalation notifications
* Reporting to executives via dashboards

**Cost**: Enterprise licensing; typically used by large organizations already invested in ServiceNow.

### 10.4 Evidence Management

Proper evidence handling is critical for post-incident analysis and potential legal proceedings.

**Chain of custody requirements:**

* Document who collected what artifact, when, from which system
* Use hash verification (SHA-256) to prove integrity
* Store evidence in write-protected, access-controlled locations
* Log every access to evidence artifacts

**Evidence types and collection:**

| Evidence Type | Collection Method | Storage Location |
|--------------|------------------|------------------|
| Memory dump | winpmem, LiME, FTK Imager | Secure file share |
| Disk image | dd, FTK Imager, KAPE | NAS/S3 with versioning |
| Log files | Copy from SIEM, original source | Evidence repository |
| Network captures | tcpdump, Wireshark | Evidence repository |
| Email artifacts | .eml export, Exchange Admin Center | Evidence repository |
| Malware samples | Extract with ClamAV/yara, password-protect zip | Sandboxed storage |

---

## 11. SOC Automation Pitfalls

### 11.1 Over-Automation

**The risk**: Automating actions without sufficient understanding of context can cause outages and loss of trust.

**Real-world example**: A SOAR playbook that automatically blocks IPs with a VirusTotal score >50 might block legitimate CDN IPs or cloud provider IPs that are occasionally flagged due to shared hosting.
Blocking Cloudflare's IP range would take down dozens of business applications.

**Mitigation**:

* Start with enrichment automation only; add containment gradually
* Maintain IP allowlist (CDNs, internal ranges, partner networks)
* Always require human approval for blocking actions affecting production systems
* Test automation in staging/lab environments first
* Define rollback procedures for every automated action

### 11.2 False Positive Amplification

**The risk**: If your detection rules have a high FP rate and your automation auto-creates tickets and sends notifications, you multiply the noise rather than reducing it.

**Pattern to avoid**:

```text
Rule with 60% FP rate
→ SOAR auto-creates ticket
→ SOAR sends Slack notification
→ SOAR sends email to user
→ User calls helpdesk confused
→ Analyst investigates (FP)
→ 4 touchpoints wasted per false positive
```

**Better approach**:

```text
Rule with 60% FP rate
→ SOAR enriches alert (TI query, context)
→ If enrichment confirms suspicious → create ticket, notify
→ If enrichment suggests benign → auto-close with audit log
```

### 11.3 Alert Queue Backlog

**The risk**: SOAR automations can sometimes increase alert queue depth if poorly designed.
Example: a schedule that runs every 5 minutes but takes 8 minutes to complete spawns an ever-growing backlog.

**Mitigation**:

* Monitor SOAR execution times and queue depth
* Implement concurrency limits
* Use event-driven triggers instead of polling where possible
* Set execution timeouts and failure handling

### 11.4 Credential and API Key Management

**The risk**: SOAR platforms require credentials to every tool they integrate with.
Compromise of the SOAR platform could expose credentials to firewalls, EDR, Active Directory — effectively providing an attacker with keys to the kingdom.

**Mitigation**:

* Store credentials in a secrets manager (HashiCorp Vault, AWS Secrets Manager)
* Use service accounts with minimum necessary permissions
* Rotate API keys regularly
* Monitor SOAR audit logs for unusual access patterns
* Segment SOAR network access

### 11.5 Playbook Drift

**The risk**: The environment changes (new tools, new processes, new threat landscape) but playbooks remain static.
Analysts following outdated playbooks may take wrong or ineffective actions.

**Mitigation**:

* Version-control all playbooks (Git)
* Assign explicit playbook owners
* Link playbooks to change management process
* Run quarterly tabletop exercises to validate playbook effectiveness

### 11.6 Automation Without Visibility

**The risk**: Fully automated actions taken without clear logging make it impossible to audit what happened during an incident.
Regulators and legal teams may require complete action logs.

**Mitigation**:

* Log every automated action: what action, what trigger, what result, timestamp
* Maintain audit logs for all containment actions (who approved, when, outcome)
* Include automation decisions in case timeline
* Retain automation logs per data retention policy

---

## 12. Building a SOC Runbook

### 12.1 Runbook vs. Playbook (Revisited)

A **runbook** is the operational companion to a playbook.
While a playbook says "if you detect a compromised account, disable it and investigate," a runbook says "to disable an account in Active Directory, run: `Disable-ADAccount -Identity <username>`."

Runbooks are tool-specific, command-specific, and contain the actual operational "muscle memory" that analysts need in high-pressure situations.

### 12.2 Runbook Structure

```text
RUNBOOK: [Specific Task/Tool/Action]
ID: RB-[Number]
Version: [X.Y]
Created: [Date]
Last Updated: [Date]
Author: [Name]
Related Playbook(s): [PB-XXX list]

PURPOSE
-------
One sentence: what does this runbook enable?

PREREQUISITES
-------------
- [ ] Access to [System] with [Permission level]
- [ ] VPN connected to [Network]
- [ ] [Tool] installed and configured
- [ ] [API key/credential] available

PROCEDURE
---------
Step 1: [Action title]
  Command/UI Action:

    $ command --parameter value

  Expected Output:

    [What success looks like]

  If error occurs:
    - Error "XYZ": [Resolution]
    - Error "ABC": [Resolution or escalate to...]

Step 2: [Next action]
  ...

VERIFICATION
------------
How to confirm the action was successful:
  $ verification-command
  Expected: [output]

ROLLBACK
--------
How to undo this action if needed:
  $ rollback-command
  Note: [any warnings about rollback]

REFERENCES
----------
- [Documentation link]
- [Internal wiki page]
```

### 12.3 Example Runbook: Disable Compromised AD Account

```text
RUNBOOK: Disable Compromised Active Directory Account
ID: RB-005
Version: 2.1
Related Playbook: PB-003 (Account Compromise Response)

PURPOSE
-------
Disable an Active Directory user account suspected of compromise
to prevent further unauthorized access.

PREREQUISITES
-------------
- [ ] Domain Admin or Account Operator AD role
- [ ] PowerShell with Active Directory module
- [ ] Ticket number for audit trail

PROCEDURE
---------
Step 1: Verify account exists and is currently enabled

  PS> Get-ADUser -Identity "username" -Properties Enabled, LockedOut,
          LastLogonDate | Select-Object Name, Enabled, LockedOut, LastLogonDate

Step 2: Document last logon sessions (for investigation)

  PS> Get-ADUser -Identity "username" -Properties * |
          Select-Object LastLogonDate, LastBadPasswordAttempt,
          BadLogonCount, PasswordLastSet |
          Export-Csv "C:\IR\TKT-XXXX-account-evidence.csv"

Step 3: Disable the account

  PS> Disable-ADAccount -Identity "username" -Confirm:$false

  Note: Replace "username" with the SAMAccountName, NOT display name.

Step 4: Add description with ticket reference

  PS> Set-ADUser -Identity "username" -Description
          "DISABLED BY SOC - TKT-XXXX - $(Get-Date -Format 'yyyy-MM-dd')"

VERIFICATION
------------
  PS> Get-ADUser -Identity "username" -Properties Enabled |
          Select-Object Name, Enabled

  Expected: Enabled = False

ROLLBACK
--------
  PS> Enable-ADAccount -Identity "username"
  PS> Set-ADUser -Identity "username" -Description "Re-enabled - TKT-XXXX"

  IMPORTANT: Only re-enable after Tier 2 analyst and manager approval.
```

### 12.4 Runbook Library Organization

Organize runbooks into a searchable library:

```text
runbooks/
├── identity/
│   ├── RB-001-disable-ad-account.md
│   ├── RB-002-reset-ad-password.md
│   ├── RB-003-azure-ad-revoke-sessions.md
│   └── RB-004-mfa-enrollment-reset.md
├── network/
│   ├── RB-010-block-ip-palo-alto.md
│   ├── RB-011-block-ip-cisco-asa.md
│   └── RB-012-pcap-collection.md
├── endpoint/
│   ├── RB-020-crowdstrike-isolate.md
│   ├── RB-021-defender-isolate.md
│   └── RB-022-collect-forensic-triage.md
├── email/
│   ├── RB-030-exchange-quarantine.md
│   └── RB-031-o365-block-sender.md
└── evidence/
    ├── RB-040-memory-acquisition.md
    └── RB-041-disk-imaging.md
```

---

## 13. Summary

This session covered the full operational lifecycle of a modern SOC:

**Workflow**: The alert-to-ticket-to-closure pipeline is the operational backbone.
It must be documented, measured, and continuously improved.
Every step — triage, severity assignment, ticket creation, investigation, escalation, closure — should have a defined owner, time target, and documented procedure.

**Playbooks**: Standardized response playbooks convert institutional knowledge into repeatable procedures.
They reduce cognitive load, ensure consistency, and are the foundation for automation.
A good playbook library includes response, escalation, and communication playbooks with explicit decision logic.

**SOAR**: Security Orchestration, Automation, and Response platforms integrate security tools and automate repetitive workflows.
Start with low-risk enrichment automation before progressing to containment automation.
Shuffle provides an accessible open-source starting point; enterprise platforms like XSOAR and Splunk SOAR offer more capabilities at higher cost.

**Automation use cases**: Phishing triage, IOC enrichment, and brute force response offer the highest ROI.
Each automates hours of manual work per alert type.

**Metrics**: MTTD, MTTR, FPR, automation rate, and SLA compliance are the core KPIs.
Metrics without improvement cycles are noise — use them to drive targeted enhancements.

**Shift management**: 24/7 coverage requires a defined shift model, rigorous handover procedures, and clear on-call escalation paths.
Most SLA breaches trace back to poor handovers.

**Case management**: TheHive (open source), Jira, and ServiceNow serve different organizational sizes and existing tool stacks.
All require good ticket hygiene to be useful.

**Pitfalls**: Over-automation, false positive amplification, credential exposure, and playbook drift are the most common automation failures.
A conservative, measured approach to automation beats aggressive deployment.

**Runbooks**: The operational complement to playbooks, runbooks contain the specific commands and procedures analysts execute.
A well-maintained runbook library dramatically reduces time-to-action during incidents.

---

## 14. References

1. Gartner Research. "Market Guide for Security Orchestration, Automation and Response Solutions." Gartner, 2023.

1. NIST Special Publication 800-61 Rev. 2. "Computer Security Incident Handling Guide." NIST, 2012.

1. SANS Institute. "Building a World-Class Security Operations Center: A Roadmap." SANS Reading Room, 2015.

1. The Hive Project. "TheHive Documentation." https://docs.thehive-project.org/

1. Shuffle SOAR. "Shuffle Documentation." https://shuffler.io/docs

1. Palo Alto Networks. "Cortex XSOAR Administrator Guide." https://docs-cortex.paloaltonetworks.com/

1. Splunk. "Splunk SOAR Documentation." https://docs.splunk.com/Documentation/SOAR

1. Microsoft. "Microsoft Sentinel SOAR." https://learn.microsoft.com/en-us/azure/sentinel/automation

1. MITRE ATT&CK Framework. "ATT&CK for Enterprise." https://attack.mitre.org/

1. Florian Roth. "Sigma: Generic Signature Format for SIEM Systems." https://github.com/SigmaHQ/sigma

1. IBM Security. "Cost of a Data Breach Report 2023." IBM, 2023.

1. Ponemon Institute. "The Economics of Security Operations Centers." Ponemon, 2020.

1. Anton Chuvakin, et al. "Security Information and Event Management (SIEM) Implementation." McGraw-Hill, 2010.

1. Casey, Eoghan. "Digital Evidence and Computer Crime." Academic Press, 2011.

1. The Hive Project. "Cortex Documentation." https://github.com/TheHive-Project/CortexDocs
