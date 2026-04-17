# Drill 02 (Advanced): Design a Complete NSM Architecture

**Level:** Advanced

**Duration:** 120–180 minutes

**Format:** Architecture design with technical specification

**Prerequisites:** All session 02 material, session 03 (SIEM) is helpful but not required

---

## Overview

This is a capstone design exercise for the network security monitoring track.
You will design a complete, production-grade Network Security Monitoring architecture for a realistic enterprise.
Your design must be technically detailed, cost-aware, operationally realistic, and compliant with relevant regulations.

This exercise simulates the kind of work a senior security analyst or security architect would do when building an NSM program from scratch.

---

## Client: GlobalPort Logistics

**Business description:**
GlobalPort Logistics manages supply chain operations for major retailers.
They operate:

* **Global Headquarters (Frankfurt, Germany):** 400 employees, IT and operations staff
* **North America Regional Hub (Dallas, TX, USA):** 150 employees
* **Asia-Pacific Regional Hub (Singapore):** 100 employees
* **10 Port/Warehouse Sites** (various countries): 20–50 employees each, primarily operational technology (OT) environments

**Business processes:**

* Real-time cargo tracking (internet-facing web application)
* EDI (Electronic Data Interchange) with suppliers and shipping companies
* IoT sensors in warehouses (temperature, door, weight sensors on 10.0.0.0/8 network)
* Corporate email and collaboration (Microsoft 365)
* ERP system (SAP S/4HANA, on-premises at Frankfurt DC)
* Remote access for 80 mobile workers and field engineers

**Regulatory environment:**

* **GDPR** (EU): Employee and customer personal data
* **NIS2 Directive** (EU): Critical infrastructure (logistics/transport sector)
* **US CISA Guidelines** applicable for Dallas operations
* **Singapore PDPA** (Personal Data Protection Act)
* **SOC 2 Type II** audit required by major customers
* **ISO 27001** certification in progress

**Current security posture:**

* No IDS/IPS deployed anywhere
* SIEM exists at Frankfurt HQ (Splunk Free — limited to 500 MB/day)
* Firewall logs sent to SIEM (partially)
* No network flow collection
* No packet capture capability
* OT network at warehouse sites runs on flat, unmonitored network
* North America and Singapore have no local security monitoring

**Specific security concerns raised by management:**

1. Supply chain attacks (SolarWinds-style compromise of software update mechanism)
1. Ransomware targeting OT systems (could disrupt operations)
1. Insider threat (employee exfiltrating customer data before leaving)
1. Cargo theft (physical correlating with network access log)
1. EDI partner compromise (malicious EDI messages injecting bad data)

---

## Architecture Design Requirements

Your design must address all of the following:

### Requirement 1: Collection Architecture

Define the complete data collection strategy:

* What data is collected at each site (PCAP, flows, logs, endpoint)
* What collection hardware/software is used
* Network connectivity from collection points to central storage
* How to handle the OT environment (special considerations)
* How to handle Microsoft 365 cloud traffic

### Requirement 2: Analysis Platform

Design the analysis platform:

* SIEM platform selection (justify your choice vs. alternatives)
* Log parsing and normalisation (how raw logs become structured data)
* Correlation rules for the 5 specific security concerns listed above
* Alert routing and escalation
* Data storage architecture (hot/warm/cold tiers)
* Search and investigation interface

### Requirement 3: Detection Coverage

Map your detection capabilities to the MITRE ATT&CK framework.
For each of the following 8 ATT&CK techniques, specify:

* Which NSM data source detects it
* How (what specific field/pattern)
* Detection latency (real-time / near-real-time / daily)

| ATT&CK Technique | Detection Source | Detection Method | Latency |
|-----------------|-----------------|-----------------|---------|
| T1190 - Exploit Public-Facing Application | ? | ? | ? |
| T1071.004 - DNS C2 | ? | ? | ? |
| T1021.002 - SMB Lateral Movement | ? | ? | ? |
| T1048 - Exfiltration Over Alternative Protocol | ? | ? | ? |
| T1566.001 - Spearphishing Attachment | ? | ? | ? |
| T1078 - Valid Accounts (VPN with stolen creds) | ? | ? | ? |
| T1486 - Data Encrypted for Impact (Ransomware) | ? | ? | ? |
| T1195 - Supply Chain Compromise | ? | ? | ? |

### Requirement 4: OT/IoT Network Monitoring

Design a monitoring approach specifically for the OT/IoT environments at the warehouse sites.
Address:

* Why standard IT monitoring approaches may not work for OT
* Passive vs. active monitoring in OT environments
* Protocols specific to OT (Modbus, DNP3, BACNET, PROFINET)
* Risk of monitoring tool causing operational disruption
* How to baseline "normal" OT behaviour

### Requirement 5: Multi-Region Coordination

Design how monitoring works across three continents (EU, USA, APAC).
Address:

* Data residency requirements (GDPR requires EU data to stay in EU)
* Bandwidth constraints between sites
* Local vs. central analysis
* How incidents are escalated across time zones
* How to maintain consistent detection rules globally

### Requirement 6: Threat Intelligence Integration

Design a threat intelligence integration strategy:

* What threat intel feeds to subscribe to (free and commercial)
* How IOCs (indicators of compromise) are ingested into the SIEM
* How Zeek's intel framework is used
* IOC lifecycle management (how stale indicators are removed)
* How to track threat actor TTPs (tactics, techniques, procedures)

### Requirement 7: SOC Operations Model

Design the SOC operating model.
This is not just technology — it's people and process:

* SOC staffing model (follow-the-sun? On-call? Outsource?)
* Analyst workflow for Level 1, Level 2, Level 3
* Runbooks for the top 5 alert types
* Metrics and KPIs for the NSM program
* How to measure detection effectiveness (purple team, red team)

---

## Deliverables

Your submission must include:

**1.
Architecture Diagram**
Create a visual diagram (hand-drawn, draw.io, or text-art) showing:

* All sites and their monitoring sensors
* Data flow paths to central SIEM
* Separation between IT and OT monitoring
* Management network

**2.
Technology Stack Document**
A table listing every tool in your stack with:

* Tool name and version
* Purpose in the architecture
* Open source / commercial
* Licence cost estimate
* Integration method (API, syslog, agent, etc.)

**3.
Correlation Rules Specification**
For the 5 security concerns, write detailed correlation rule logic in pseudo-code or Splunk SPL / Elastic KQL:

```text
# Example format:
Rule: "Possible Insider Data Exfiltration"
Logic:
  WHEN user_identity IS KNOWN
  AND dst_bytes > 100MB
  AND destination IS external
  AND file_type IN (xls, pdf, csv, zip)
  AND time_of_day IS outside_business_hours
  WITHIN 24 hours
THEN alert WITH severity=HIGH
```

**4.
GDPR and Cross-Border Data Flow Analysis**
A legal/technical analysis of:

* What personal data is collected by your monitoring system
* Legal basis for collecting it in each jurisdiction
* How you handle data residency requirements
* Transfer mechanisms for cross-border log shipping
* Data subject rights in the context of security monitoring data

**5.
Budget Estimate**
A rough budget for Year 1 (capital + operating):

* Hardware costs
* Software licensing
* Cloud services
* Staff costs
* Training

**6.
Roadmap**
A 12-month implementation roadmap with milestones, showing how you would phase in the architecture in order of risk reduction priority.

---

## Scoring Rubric

| Criteria | Excellent (A) | Good (B) | Needs Improvement (C) |
|----------|--------------|---------|----------------------|
| Technical completeness | All requirements addressed with specific tools and configs | Most requirements addressed, some gaps | Significant gaps or vague proposals |
| Security effectiveness | Multiple detection layers, ATT&CK mapping complete | Good coverage with some blind spots | Poor coverage or theoretical only |
| Operational realism | Budget, staffing, phasing all realistic | Generally realistic, minor issues | Unrealistic (too expensive, too complex, no staff) |
| Compliance | All regulatory requirements addressed | Most requirements addressed | Compliance largely ignored |
| OT understanding | Shows clear understanding of OT constraints | Basic OT awareness | IT mindset applied to OT without adaptation |
| GDPR/Privacy | Detailed, jurisdiction-specific analysis | General GDPR principles applied | Privacy largely ignored |
| Architecture diagram | Clear, complete, professional | Legible, mostly complete | Unclear or missing |

Total: 100 points
Passing: 70 points

---

## Reference Resources

* MITRE ATT&CK for ICS (OT): https://attack.mitre.org/matrices/ics/
* SANS ICS515 (OT Monitoring): https://www.sans.org/courses/ics-visibility-detection-response/
* NIST SP 800-82 (OT Security Guide): https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
* EU NIS2 Directive: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555
* Elastic SIEM: https://www.elastic.co/siem
* Wazuh (open source SIEM): https://wazuh.com/
* MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
* Zeek Package Manager: https://packages.zeek.org/
