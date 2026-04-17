# Drill 02 (Advanced): Designing a Threat Intelligence Program

**Level:** Advanced

**Estimated Time:** 3-4 hours

**Submission Format:** Program design document (1,800-3,000 words) + supporting artifacts

---

## Learning Objectives

* Design a comprehensive threat intelligence program from scratch
* Define Priority Intelligence Requirements aligned to business risk
* Select and integrate intelligence platforms (MISP, OpenCTI)
* Design intelligence-to-action workflows
* Measure program effectiveness with meaningful metrics
* Address operational, legal, and ethical considerations

---

## Scenario

You have been hired as the **Head of Threat Intelligence** at **EuroHealth Alliance**, a pan-European healthcare technology company operating in 12 countries.
EuroHealth Alliance:

* Develops and operates electronic health record (EHR) software used by 3,200 hospitals
* Processes health data for ~45 million patients
* Has 2,400 employees across 12 EU countries
* Revenue: €1.4 billion annually
* Is classified as a critical infrastructure entity under NIS2
* Has had NO formal threat intelligence function previously

**Your mandate:** Build a threat intelligence program from scratch with a first-year budget of **€450,000** (headcount + tools).

---

## Context

### Current Security Posture

**Existing security capabilities:**

* SOC team: 8 analysts (24/7 coverage), currently reactive only
* SIEM: Splunk Enterprise (deployed, but underutilized)
* EDR: CrowdStrike Falcon (deployed on 85% of endpoints)
* Email security: Microsoft Defender for Office 365
* Vulnerability management: Qualys (quarterly scans)
* No threat hunting program
* No threat intelligence platform
* No dark web monitoring

**Key risks identified in last security audit:**

1. Healthcare sector is heavily targeted by ransomware groups
1. Patient data has high black market value (GDPR violations)
1. EHR software supply chain: if EuroHealth is compromised, 3,200 hospitals are affected
1. No insider threat detection capability
1. Third-party risk management is manual and infrequent

---

## Tasks

### Task 1: Strategic Program Design (30 points)

Write the strategic framework for EuroHealth Alliance's threat intelligence program.

**Required sections:**

**1.1 Mission Statement (50 words max)**
Define the mission of the threat intelligence program.
What is it for?
Who does it serve?

**1.2 Priority Intelligence Requirements (PIRs)**

Define **6-8 PIRs** for EuroHealth Alliance.
For each PIR:

* State the intelligence question
* Explain the business decision it informs
* Define the target audience for the answer
* Specify the urgency (time-sensitive vs. strategic)

PIR template:

```text
PIR-X: [Intelligence Question]
Business Decision: [What decision does this enable?]
Audience: [Who needs this answer?]
Type: [Tactical / Operational / Strategic]
Urgency: [Immediate (<24h) / Near-term (1 week) / Strategic (quarterly)]
```

**1.3 Intelligence Types Matrix**

For each of the three intelligence types (Tactical, Operational, Strategic), define:

* What it means for EuroHealth
* Examples of products you will produce
* Primary consumers at EuroHealth
* Production frequency

---

### Task 2: Technology Architecture (25 points)

Design the technology stack for the intelligence program.

**2.1 Platform Selection**

Choose your primary intelligence platform (MISP, OpenCTI, or both) and justify your choice.
Address:

* How does this fit into the existing Splunk/CrowdStrike environment?
* What integrations are needed?
* What is the deployment model (on-premise vs. cloud)?

**2.2 Intelligence Sources**

Create a prioritized list of intelligence sources you will use, organized in tiers:

* **Tier 1 (Free):** What free sources will you consume first year?
* **Tier 2 (Paid):** Which 2-3 commercial feeds would you recommend? Justify based on EuroHealth's risk profile.
* **Tier 3 (Community):** Which sharing communities should EuroHealth join?

Budget constraint: You have €150,000 of your €450,000 budget for tools and subscriptions.

**2.3 Technical Integration Architecture**

Draw a simple architecture diagram (text-based ASCII art is acceptable) showing how intelligence flows from sources through your platform to operational teams.
Include:

* Intelligence sources
* Collection mechanisms
* Intelligence platform
* Downstream consumers (SIEM, EDR, firewall)
* Feedback loops

---

### Task 3: Operational Workflows (20 points)

Design two operational workflows:

**3.1 Tactical Intelligence Workflow**

Design the process for handling a critical IOC (e.g., a ransomware group's C2 IPs shared via H-ISAC):

* How does the IOC enter your system?
* Who validates it and how?
* What is the SLA for action (block, detect, hunt)?
* What is the notification chain?
* How is it tracked through its lifecycle?

Use a flowchart (text/ASCII format) or numbered steps with decision points.

**3.2 Intelligence-Driven Hunt Workflow**

Design the process for converting a threat actor report into a completed threat hunt:

* Input: New threat actor report
* Output: Completed hunt, new detections, updated MISP event
* Who is responsible at each step?
* What are the SLAs?

---

### Task 4: Metrics and Maturity (15 points)

**4.1 Year 1 Success Metrics**

Define 8-10 measurable KPIs for the threat intelligence program.
For each:

* Metric name
* What it measures
* How to calculate it
* Target value for Year 1
* Why this metric matters

**4.2 Maturity Roadmap**

Using the SANS Threat Hunting Maturity Model (Levels 0-4), describe:

* Current state: What level is EuroHealth at today?
* Year 1 target: What level should you reach?
* Year 3 target: What level should you reach?
* Key milestones for each level transition

---

### Task 5: Legal, Ethical, and Compliance Considerations (10 points)

Address these specific considerations for EuroHealth Alliance:

**5.1 GDPR Compliance**
How will you ensure your threat intelligence activities comply with GDPR?
Specifically address:

* Handling of personally identifiable information in threat reports
* Data sharing with partner organizations
* Retention periods for intelligence data

**5.2 TLP Policy**
Write a 1-page internal TLP handling policy for EuroHealth's intelligence team.

**5.3 Dark Web Monitoring**
EuroHealth wants to monitor dark web markets for mentions of their organization and compromised patient data.
Address:

* Is this legal in EU countries?
* What boundaries must you observe?
* How would you set up a compliant dark web monitoring capability?

---

## Evaluation Criteria

| Task | Points | Key Criteria |
|------|--------|-------------|
| Task 1: Strategic design | 30 | PIR quality, business alignment, completeness |
| Task 2: Technology architecture | 25 | Technical feasibility, integration thinking, budget realism |
| Task 3: Workflows | 20 | Practicality, SLA clarity, decision points |
| Task 4: Metrics and maturity | 15 | Measurability, realism, strategic thinking |
| Task 5: Legal/ethical | 10 | GDPR accuracy, TLP policy completeness |
| **Total** | **100** | |

---

## Resources

* Reading material: Full session, especially sections 7, 8, 9, 10
* NIS2 Directive: EU Directive 2022/2555
* GDPR Article 5 (data processing principles)
* SANS Threat Hunting Maturity Model
* MITRE ATT&CK Healthcare sector groups
* H-ISAC: https://h-isac.org
