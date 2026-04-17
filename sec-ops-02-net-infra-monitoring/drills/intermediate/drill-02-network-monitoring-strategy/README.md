# Drill 02 (Intermediate): Design a Network Monitoring Strategy

**Level:** Intermediate

**Duration:** 60–90 minutes

**Format:** Design exercise — written deliverables

**Prerequisites:** Session 02 Reading (complete), Demo 03 (Topology Analysis)

---

## Background

This drill asks you to design a complete network monitoring strategy for a fictional organisation.
Unlike Demo 03 (which analysed gaps in an existing setup), here you are starting from scratch and must make all design decisions.

Good monitoring strategy design requires balancing:

* **Coverage:** What is being monitored?
* **Depth:** How much detail is captured?
* **Cost:** Storage, hardware, licensing, staff time
* **Privacy:** What personal data is collected and how is it protected?
* **Compliance:** What regulations apply?

---

## Scenario: NovaCare Medical Group

**Organisation profile:**
NovaCare Medical Group is a healthcare company with:

* 2 hospitals (main campus and satellite campus)
* 8 outpatient clinics across the city
* A centralised data centre hosting the Electronic Health Record (EHR) system
* 1,200 employees (doctors, nurses, admin staff, IT)
* 200 concurrent remote access users (doctors accessing EHR from home)

**Regulatory environment:**

* **GDPR** (EU): All patient data is personal data; data breach notification within 72 hours
* **NIS2 Directive** (EU): Critical infrastructure requirements for healthcare
* **Internal policy:** Patient data must be encrypted in transit and at rest
* **Audit requirement:** All access to patient records must be logged for 7 years

**Current IT infrastructure:**

```text
Main Hospital Campus (Site A):
  - 300 clinical workstations
  - 50 networked medical devices (infusion pumps, monitors)
  - EHR client software (connects to central data centre via MPLS WAN)
  - Internal Wi-Fi: clinical (802.1X authenticated) + guest
  - Local servers: file server, print server, biomedical equipment management
  - Firewall: Fortinet FortiGate 500E
  - Switch infrastructure: Cisco Catalyst 9300 (managed)

Satellite Campus (Site B):
  - 80 clinical workstations
  - 15 networked medical devices
  - Connected to Site A via 1 Gbps MPLS WAN link
  - Firewall: Cisco ASA 5506-X (older, limited logging)

Centralised Data Centre (Site DC):
  - EHR Application Server (VMware): 10.100.0.10
  - EHR Database Server (VMware): 10.100.0.20
  - Active Directory / DNS: 10.100.0.5
  - Backup Server: 10.100.0.30
  - Internet uplink: 500 Mbps (for remote access VPN)
  - Firewall: Palo Alto PA-5250 (NGFW)
  - Switches: Cisco Nexus 9300

8 Outpatient Clinics:
  - Each: 10-20 workstations, 5-10 networked devices
  - Connected to Data Centre via SD-WAN over internet
  - No dedicated firewall (just consumer-grade router at each site)
  - No local logging or monitoring

Remote Access:
  - Cisco AnyConnect VPN to Data Centre
  - 200 concurrent users
  - Split tunnel: only EHR application traffic goes through VPN
```

---

## Deliverable 1: Asset Classification and Risk Matrix

Complete the following table, classifying each network segment by:

* **Data sensitivity:** None / Low / Medium / High / Critical
* **Exposure:** Internal-only / WAN-connected / Internet-facing / External
* **Compliance scope:** Which regulations specifically cover this segment?
* **Threat likelihood:** Low / Medium / High (based on exposure and attacker motivation)

| Segment | Data Sensitivity | Exposure | Compliance Scope | Threat Likelihood |
|---------|-----------------|---------|-----------------|------------------|
| Site A — Clinical workstations | ? | ? | ? | ? |
| Site A — Medical devices | ? | ? | ? | ? |
| Site A — Clinical Wi-Fi | ? | ? | ? | ? |
| Site A — Guest Wi-Fi | ? | ? | ? | ? |
| Site B — Clinical workstations | ? | ? | ? | ? |
| Site B — Medical devices | ? | ? | ? | ? |
| Data Centre — EHR Application Server | ? | ? | ? | ? |
| Data Centre — EHR Database | ? | ? | ? | ? |
| Data Centre — Active Directory | ? | ? | ? | ? |
| Data Centre — Internet uplink | ? | ? | ? | ? |
| Outpatient clinics | ? | ? | ? | ? |
| Remote Access VPN | ? | ? | ? | ? |

---

## Deliverable 2: Monitoring Tool Selection

For each monitoring need, recommend the appropriate tool(s) and justify your choice:

| Monitoring Need | Recommended Tool | Justification |
|----------------|-----------------|---------------|
| Full packet capture at internet perimeter | ? | ? |
| NSM sensor at Data Centre (EHR traffic analysis) | ? | ? |
| Flow-based monitoring across all sites | ? | ? |
| IDS/IPS at internet boundary | ? | ? |
| Log aggregation and correlation | ? | ? |
| Endpoint detection at clinical workstations | ? | ? |
| Medical device network monitoring | ? | ? |
| VPN access monitoring | ? | ? |
| Outpatient clinic monitoring (low budget) | ? | ? |

---

## Deliverable 3: Sensor Placement Design

Design the physical/logical placement of monitoring sensors.
For each sensor, specify:

1. **Location:** Where exactly is it connected?
1. **Connection type:** TAP / SPAN port / Agent / Flow collector
1. **Tool:** What runs on the sensor?
1. **Traffic covered:** What does it see?
1. **Priority:** Critical / High / Medium / Low

Complete the table:

| Sensor ID | Location | Connection | Tool | Traffic Covered | Priority |
|-----------|---------|------------|------|----------------|---------|
| SENSOR-01 | ? | ? | ? | ? | Critical |
| SENSOR-02 | ? | ? | ? | ? | Critical |
| SENSOR-03 | ? | ? | ? | ? | High |
| SENSOR-04 | ? | ? | ? | ? | High |
| SENSOR-05 | ? | ? | ? | ? | High |
| SENSOR-06 | ? | ? | ? | ? | Medium |
| SENSOR-07 | ? | ? | ? | ? | Medium |
| SENSOR-08 | ? | ? | ? | ? | Medium |

---

## Deliverable 4: Data Collection and Retention Policy

Design a data retention policy that satisfies:

* The 7-year audit requirement for EHR access
* GDPR data minimisation (collect only what is necessary)
* Practical storage constraints (budget for 10 TB storage total)

| Data Type | Collection Tool | Retention Period | Storage Estimate | Justification |
|-----------|----------------|-----------------|-----------------|---------------|
| Full PCAP (internet uplink) | ? | ? | ? | ? |
| Full PCAP (EHR server traffic) | ? | ? | ? | ? |
| Zeek logs (conn, dns, http, ssl) | ? | ? | ? | ? |
| IDS/IPS alerts | ? | ? | ? | ? |
| NetFlow records | ? | ? | ? | ? |
| Firewall logs | ? | ? | ? | ? |
| EHR access logs | ? | ? | ? | ? |
| VPN connection logs | ? | ? | ? | ? |

---

## Deliverable 5: Alert and Escalation Framework

Design the alerting and escalation process.
Define:

### 5.1 Alert Tiers

Define 3 severity tiers for NovaCare.
For each tier, specify:

* Trigger criteria (examples)
* Response time requirement
* Who is notified
* Initial action required

| Tier | Name | Examples | Response Time | Notify | Initial Action |
|------|------|---------|---------------|--------|----------------|
| P1 | Critical | ? | ? | ? | ? |
| P2 | High | ? | ? | ? | ? |
| P3 | Medium | ? | ? | ? | ? |

### 5.2 Must-Have Detection Rules

List 5 detection rules that are **mandatory** for NovaCare given its healthcare context.
For each, explain why it is specific to the healthcare sector.

1. ?
1. ?
1. ?
1. ?
1. ?

---

## Deliverable 6: GDPR and Medical Privacy Compliance

Answer the following questions in paragraph form (100–200 words each):

**6.1:** NovaCare's monitoring tools will capture network traffic that may include patient data (e.g., HL7 messages between clinical systems).
How do you design the monitoring architecture to comply with GDPR while still being effective?

**6.2:** The SOC team will have access to captured network traffic from clinical Wi-Fi, which may contain patient data.
Under GDPR, what controls must be in place for the SOC staff who can access this data?

**6.3:** NovaCare has a data breach.
The EHR database was accessed by an external attacker.
How does your monitoring strategy support the 72-hour GDPR breach notification requirement?
What data will you need from your monitoring tools to complete the breach notification?

---

## Deliverable 7: Budget Estimate and Prioritisation

Given a realistic budget constraint, prioritise your monitoring implementation in three phases:

**Phase 1 (Immediate — Month 1-2):** What must be done first?

**Phase 2 (Short-term — Month 3-6):** What comes next?

**Phase 3 (Long-term — Month 7-12):** What completes the program?

Justify your phasing decisions in terms of risk reduction.

---

## Scoring

| Deliverable | Points |
|-------------|--------|
| 1: Asset Classification | 10 |
| 2: Tool Selection | 10 |
| 3: Sensor Placement | 15 |
| 4: Retention Policy | 10 |
| 5: Alert Framework | 15 |
| 6: GDPR Compliance | 15 |
| 7: Budget/Prioritisation | 10 |
| Overall coherence and justification | 15 |
| **Total** | **100** |

Passing: 70/100
