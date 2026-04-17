# Session 01: Introduction to Security Operations Centers (SOC)

## Learning Objectives

By the end of this session, you will be able to:

* Define what a SOC is and explain its mission within an organization.
* Describe the key roles and responsibilities of SOC personnel.
* Identify the primary tools used in SOC environments (SIEM, SOAR).
* Explain the alert lifecycle from detection to resolution.
* Evaluate SOC performance using common KPIs.

---

## 1. What is a Security Operations Center (SOC)?

A **Security Operations Center (SOC)** is a centralized unit within an organization that employs people, processes, and technology to continuously monitor and improve an organization's security posture while preventing, detecting, analyzing, and responding to cybersecurity incidents.

> "A good SOC is not just about tools — it's about people, process, and proactive defense."
> — Crowley, *The SOC Handbook* (2020)

### 1.1 Mission and Scope

The SOC's mission is to:

1. **Prevent** security incidents by hardening defenses and reducing attack surface.
1. **Detect** threats as early as possible by monitoring logs, traffic, and behavior.
1. **Respond** to incidents in a timely, structured, and effective manner.
1. **Recover** from incidents and improve defenses based on lessons learned.

Modern SOCs operate around the clock (24/7/365) and serve as the nerve center for security activities.
They combine:

* Human analysts with varying levels of expertise.
* Advanced tooling such as SIEM, SOAR, EDR, and threat intelligence platforms.
* Documented processes and playbooks for handling different incident types.

### 1.2 Types of SOCs

| Type | Description |
|------|-------------|
| **Internal SOC** | Built and operated entirely by the organization. Maximum control, high cost. |
| **Outsourced SOC (MSSP)** | Managed by a third-party Managed Security Service Provider. Lower cost, less customization. |
| **Hybrid SOC** | Combination of internal staff and external services. Common in mid-sized companies. |
| **Virtual SOC** | No dedicated physical space; analysts work remotely. Common post-pandemic. |
| **Co-managed SOC** | Organization retains some staff while outsourcing specific functions. |

### 1.3 Why Does Every Organization Need a SOC?

Consider these statistics:

* The average time to identify a breach is **207 days** (IBM Cost of a Data Breach Report, 2023).
* The average cost of a data breach is **$4.45 million** (IBM, 2023).
* **83%** of organizations experienced more than one breach in 2022.

Without a SOC, organizations react to incidents rather than proactively defending against them.
The 2013 Target data breach is a classic example: the SOC received alerts about malicious activity but failed to respond in time, resulting in 40 million credit card records stolen.

---

## 2. SOC Roles and Responsibilities

A SOC operates in a tiered model, where alerts escalate from less experienced analysts to experts depending on complexity.

### 2.1 Analyst Tiers

```text
┌──────────────────────────────────────────────────┐
│                   SOC Manager                    │
│  KPIs, scheduling, team development, reporting   │
├──────────────────────────────────────────────────┤
│                Tier 3 (L3 Analyst)               │
│  Threat hunting, malware analysis, proactive def │
├──────────────────────────────────────────────────┤
│                Tier 2 (L2 Analyst)               │
│  Investigation, enrichment, case building        │
├──────────────────────────────────────────────────┤
│                Tier 1 (L1 Analyst)               │
│  Alert triage, correlation, noise reduction      │
└──────────────────────────────────────────────────┘
```

**Tier 1 (L1 Analyst)** — Entry-level position:

* Monitors dashboards and responds to alerts.
* Performs initial triage: is this alert a true positive or false positive?
* Escalates genuine threats to Tier 2.
* Documents initial findings in a ticketing system.

**Tier 2 (L2 Analyst)** — Intermediate position:

* Investigates escalated alerts in depth.
* Enriches alerts with threat intelligence (e.g., checks IP reputation).
* Builds incident cases and coordinates initial response.
* Determines if full incident response is needed.

**Tier 3 (L3 Analyst)** — Advanced position:

* Proactively hunts for threats that evade automated detection.
* Analyzes malware and reverse-engineers attacker techniques.
* Develops detection rules and improves SOC tools.
* Acts as subject matter expert for complex incidents.

**SOC Manager**:

* Oversees all SOC operations.
* Reports KPIs to executive leadership.
* Manages staffing, scheduling, and career development.
* Interfaces with IT, legal, compliance, and business units.

### 2.2 Additional SOC Roles

| Role | Responsibility |
|------|---------------|
| **Threat Intelligence Analyst** | Gathers, analyzes, and disseminates threat intel. |
| **Incident Responder** | Leads the technical response during active incidents. |
| **Forensic Analyst** | Performs detailed post-incident investigation. |
| **Vulnerability Analyst** | Identifies and tracks system vulnerabilities. |
| **Security Engineer** | Builds, configures, and maintains SOC tooling. |

---

## 3. SOC Tools: SIEM and SOAR

### 3.1 SIEM (Security Information and Event Management)

A **SIEM** is the central brain of a SOC.
It collects, aggregates, and analyzes log data from across the organization.

**Key functions:**

* **Log collection**: Ingests logs from firewalls, endpoints, servers, applications.
* **Normalization**: Standardizes log formats for consistent analysis.
* **Correlation**: Links related events to detect attack patterns.
* **Alerting**: Triggers alerts when detection rules match.
* **Dashboards**: Provides visual representation of security posture.
* **Reporting**: Generates compliance and audit reports.

**Popular SIEM platforms:**

| Platform | Type | Notes |
|----------|------|-------|
| Splunk | Commercial | Market leader; powerful query language (SPL) |
| IBM QRadar | Commercial | Strong correlation engine |
| Microsoft Sentinel | Cloud (SaaS) | Azure-native, strong Microsoft integration |
| Elastic SIEM | Open source / commercial | Based on Elasticsearch stack |
| Wazuh | Open source | Lightweight, good for small environments |

**Example Splunk query to detect failed logins:**

```spl
index=security sourcetype=WinEventLog EventCode=4625
| stats count by src_ip, user
| where count > 10
| sort -count
```

### 3.2 SOAR (Security Orchestration, Automation, and Response)

A **SOAR** platform automates repetitive SOC tasks and orchestrates workflows across multiple tools.

**Key functions:**

* **Orchestration**: Connects SIEM, ticketing, threat intel, and endpoint tools.
* **Automation**: Executes predefined playbooks without human intervention.
* **Case management**: Tracks incidents from detection to closure.

**Example automation playbook — Phishing email:**

```text
1. Email flagged as suspicious → SIEM alert

2. SOAR triggers automatically:
   a. Extract sender IP and URL from email
   b. Query VirusTotal for reputation
   c. Block sender IP at firewall
   d. Quarantine email across all mailboxes
   e. Create incident ticket in ServiceNow
   f. Notify L1 analyst for review
```

**SIEM vs SOAR:**

| Feature | SIEM | SOAR |
|---------|------|------|
| Primary function | Detection & visibility | Automation & response |
| Handles | Log aggregation, correlation | Workflow, orchestration |
| Output | Alerts, reports | Actions, ticket creation |
| Human role | Required for triage | Reduced; handles routine tasks |

---

## 4. The Alert Lifecycle

Understanding how an alert progresses from detection to resolution is fundamental for any SOC analyst.

### 4.1 Alert Lifecycle Stages

```text
Log Source
    │
    ▼
Log Collection (SIEM ingestion)
    │
    ▼
Normalization (standardize format)
    │
    ▼
Correlation (match detection rules)
    │
    ▼
Alert Generated
    │
    ▼
Triage (L1 Analyst) ──► False Positive? ──► Closed / Tuned
    │
    │ True Positive
    ▼
Investigation (L2 Analyst)
    │
    ▼
Escalation (if needed, L3/Manager)
    │
    ▼
Containment & Remediation
    │
    ▼
Documentation & Closure
    │
    ▼
Lessons Learned / Rule Improvement
```

### 4.2 Alert Triage

Triage is the process of quickly evaluating an alert to determine its priority and validity.

**Triage questions:**

1. Is this alert a **true positive** (real threat) or **false positive** (benign activity triggering a rule)?
1. What is the **severity** of the threat? (Critical / High / Medium / Low)
1. Which **systems/users** are affected?
1. Is there evidence of **lateral movement** or **data exfiltration**?
1. Does this match any **known threat actor** or attack pattern?

**Alert severity classification:**

| Severity | Response Time | Description |
|----------|---------------|-------------|
| Critical | Immediate | Active compromise, data exfiltration |
| High | < 1 hour | Potential compromise, active exploitation |
| Medium | < 4 hours | Suspicious activity requiring investigation |
| Low | < 24 hours | Informational, low-risk events |

### 4.3 Key Performance Indicators (KPIs)

SOC managers track KPIs to measure team performance and identify areas for improvement.

| KPI | Definition | Target |
|-----|-----------|--------|
| **MTTD** (Mean Time to Detect) | Average time from incident occurrence to detection | < 24 hours |
| **MTTR** (Mean Time to Respond) | Average time from detection to containment | < 4 hours |
| **MTTI** (Mean Time to Investigate) | Average time to investigate and classify an alert | < 30 minutes |
| **False Positive Rate** | Percentage of alerts that are not real threats | < 20% |
| **Alert Volume** | Total alerts generated per day | Tracked for trends |
| **Escalation Rate** | % of L1 alerts escalated to L2 | Tracked for efficiency |

### 4.4 Alert Fatigue

**Alert fatigue** is a significant challenge in SOC operations.
When analysts are overwhelmed by too many alerts (especially false positives), they may:

* Miss genuine threats buried in noise.
* Make hasty, incorrect decisions.
* Experience burnout and reduced effectiveness.

**Mitigation strategies:**

* Regularly tune detection rules to reduce false positives.
* Implement alert prioritization and deduplication.
* Use SOAR to automate handling of low-risk, repetitive alerts.
* Establish baselines and use anomaly-based detection carefully.

---

## 5. SOC Infrastructure and Physical Setup

### 5.1 Physical SOC Layout

A traditional enterprise SOC includes:

* **Operations floor**: Workstations for analysts with multiple monitors.
* **Video wall**: Large display showing overall security posture.
* **Team leads' stations**: Centrally located for quick communication.
* **Incident war room**: Dedicated space for handling major incidents.
* **Secure access control**: Restricted entry to prevent unauthorized access.

### 5.2 SOC Technology Stack

```text
┌─────────────────────────────────────────────┐
│              Data Sources                   │
│  Endpoints | Network | Cloud | Applications │
└──────────────────┬──────────────────────────┘
                   │ logs / telemetry
┌──────────────────▼──────────────────────────┐
│                  SIEM                       │
│  Collection | Normalization | Correlation   │
└──────────────────┬──────────────────────────┘
                   │ alerts
┌──────────────────▼──────────────────────────┐
│                  SOAR                       │
│  Orchestration | Automation | Case Mgmt     │
└──────────────────┬──────────────────────────┘
                   │ tickets / actions
┌──────────────────▼──────────────────────────┐
│              Analysts (Tier 1-3)            │
│  Triage | Investigation | Threat Hunting    │
└─────────────────────────────────────────────┘
```

---

## 6. Case Study: The 2013 Target Data Breach

The Target breach is one of the most studied SOC failures in history.

**Timeline:**

* November 27, 2013: Attackers installed malware on Target's POS (Point-of-Sale) systems using stolen credentials from an HVAC vendor.
* November 30, 2013: Target's SIEM (FireEye) generated alerts about malicious activity.
* December 2, 2013: FireEye generated more alerts; no response was taken.
* December 15, 2013: U.S. Department of Justice notified Target of the breach.
* December 19, 2013: Target publicly disclosed the breach.

**What went wrong:**

1. Alerts were generated but **not acted upon** by SOC analysts.
1. The SOC team was understaffed and overwhelmed with alert volume.
1. No automated response rules existed to contain the threat.
1. Third-party vendor access was not properly segmented.

**Lessons learned:**

* Automate initial containment actions for high-severity alerts.
* Implement proper network segmentation for vendor access.
* Regularly drill SOC procedures and test response time.
* Establish escalation procedures that ensure critical alerts reach decision-makers.

**Impact:** 40 million credit/debit card numbers stolen, $162 million in expenses, CEO resignation.

---

## 7. MITRE ATT&CK Framework

The **MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) framework is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.

SOC analysts use ATT&CK to:

* Understand what attackers do at each stage of an attack.
* Map detected activity to known threat actor behaviors.
* Identify gaps in detection coverage.
* Build and improve detection rules.

**ATT&CK Tactics (in attack order):**

| # | Tactic | Description |
|---|--------|-------------|
| 1 | Reconnaissance | Gathering information about the target |
| 2 | Resource Development | Establishing attacker infrastructure |
| 3 | Initial Access | Getting into the target environment |
| 4 | Execution | Running malicious code |
| 5 | Persistence | Maintaining foothold after reboot |
| 6 | Privilege Escalation | Gaining higher permissions |
| 7 | Defense Evasion | Avoiding detection |
| 8 | Credential Access | Stealing credentials |
| 9 | Discovery | Exploring the environment |
| 10 | Lateral Movement | Moving to other systems |
| 11 | Collection | Gathering data of interest |
| 12 | Command and Control | Communicating with attacker infrastructure |
| 13 | Exfiltration | Stealing data |
| 14 | Impact | Disrupting/destroying systems |

---

## 8. Summary

In this session, we covered:

1. **SOC definition and mission**: Centralized unit for monitoring, detecting, and responding to cyber threats.
1. **SOC types**: Internal, outsourced, hybrid, virtual, co-managed.
1. **Analyst tiers**: L1 (triage), L2 (investigation), L3 (threat hunting), Manager (oversight).
1. **Key tools**: SIEM (detection and visibility) and SOAR (automation and response).
1. **Alert lifecycle**: From log ingestion through triage, investigation, and closure.
1. **KPIs**: MTTD, MTTR, false positive rate — metrics to measure SOC effectiveness.
1. **Real-world case study**: Target 2013 — the cost of inaction.
1. **MITRE ATT&CK**: Framework for understanding and mapping adversary behavior.

---

## References

* Crowley, C. (2020). *The SOC Handbook*. SANS Institute.
* Muniz, J. (2015). *Security Operations Center: Building, Operating, and Maintaining Your SOC*. Cisco Press.
* IBM Security (2023). *Cost of a Data Breach Report*. IBM Corporation.
* NIST SP 800-61 Rev.2: *Computer Security Incident Handling Guide*. NIST.
* MITRE ATT&CK Framework: https://attack.mitre.org
* TryHackMe SOC1 Room: https://tryhackme.com/path/outline/soclevel1
* BlueTeamLabs Online: https://blueteamlabs.online
* Splunk Free Trial: https://www.splunk.com/en_us/trials/splunk-cloud.html
