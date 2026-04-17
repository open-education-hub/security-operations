# Drill 01 (Advanced): Designing a SOC Architecture

## Description

Design a complete SOC architecture for a mid-sized European financial services company.
The company has 500 employees, offices in 3 countries, and processes customer payment data.
They have no existing SOC.

## Objectives

* Apply SOC design principles to a real-world scenario.
* Make technology selection decisions with justification.
* Design staffing models and escalation procedures.
* Consider compliance requirements (GDPR, PCI-DSS).

## Company Profile

**Company:** EuroPayments GmbH

**Size:** 500 employees

**Offices:** Frankfurt (HQ, 300 staff), Amsterdam (100 staff), Warsaw (100 staff)

**Industry:** Payment processing / FinTech

**Regulations:** GDPR, PCI-DSS Level 2, DORA (EU Digital Operational Resilience Act)

**Current security:** Firewall, endpoint AV, no centralized monitoring

**Budget:** €1.2M first year for SOC setup, €800K/year ongoing

**Timeline:** SOC must be operational within 6 months

## Deliverables

### 1. SOC Type Recommendation (300-500 words)

Recommend the most appropriate SOC model (Internal, MSSP, Hybrid, Virtual) for EuroPayments.
Justify your choice considering: budget, timeline, compliance requirements, and the company's risk profile.

### 2. Technology Stack (table format)

Specify the technology stack you would deploy:

* SIEM platform (with justification)
* SOAR platform (optional)
* Endpoint detection and response (EDR)
* Network monitoring
* Threat intelligence platform
* Ticketing/case management

For each tool: specify if it's open source or commercial, approximate cost, and why you chose it over alternatives.

### 3. Staffing Model

Design a staffing model for year 1:

* How many analysts at each tier?
* What are the shift schedules?
* What training is required for each role?

### 4. Detection Coverage Plan

Identify the top 10 security use cases (detection rules) that should be implemented first, given EuroPayments' profile.
Prioritize based on:

* PCI-DSS requirements (cardholder data protection)
* GDPR (personal data)
* FinTech threat landscape (financial fraud, ransomware)

### 5. Escalation and Playbook Framework

Design an escalation matrix:

* Who gets called for what severity level?
* What is the response time target for each level?
* Identify 3 incident types that should have documented playbooks.

## Hints

* PCI-DSS requires log monitoring of all systems in the cardholder data environment (CDE).
* DORA requires financial entities to report major ICT incidents within 4 hours.
* A hybrid SOC (some in-house, some outsourced) often makes sense for mid-sized companies.
* Consider 24/7 coverage requirements — 3 shifts × minimum 2 analysts = 6+ FTEs for 24/7.
* Wazuh is a solid open-source SIEM option; Microsoft Sentinel works well in Azure environments.

## Submission

Submit a structured document (500-800 words) covering all 5 deliverables.
Include diagrams where appropriate.
