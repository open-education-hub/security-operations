# Drill 02 Advanced Solution: Threat Intelligence Program Design

---

## Task 1: Strategic Program Design

### 1.1 Mission Statement

> The EuroHealth Alliance Threat Intelligence Program produces actionable, evidence-based intelligence that enables the organization to make informed security decisions, proactively identify and respond to threats to patient data and healthcare systems, and fulfill our obligations as a critical infrastructure provider under NIS2.

### 1.2 Priority Intelligence Requirements (PIRs)

**PIR-1: Ransomware Targeting Healthcare**

* Intelligence Question: "What ransomware groups are actively targeting healthcare technology providers and EHR software companies in Europe, and what are their current TTPs and infrastructure?"
* Business Decision: Prioritization of defensive controls and hunting activities; incident response pre-planning
* Audience: CISO, SOC Lead, Threat Hunt Team
* Type: Operational
* Urgency: Near-term (weekly update) + Immediate when new campaign detected

**PIR-2: EuroHealth-Specific Targeting**

* Intelligence Question: "Are there any active threats specifically targeting EuroHealth Alliance—mentions in underground forums, phishing infrastructure, credential exposure, or announced attacks?"
* Business Decision: Incident escalation decisions; proactive response before attack
* Audience: CISO, SOC, Legal (data breach notification if credentials found)
* Type: Tactical + Operational
* Urgency: Immediate (<24h) for credential exposure

**PIR-3: Third-Party and Supply Chain Risk**

* Intelligence Question: "Have any of EuroHealth's key technology partners or software vendors been compromised in the past 90 days in a way that could affect EuroHealth?"
* Business Decision: Isolation, review, or replacement of compromised third-party integrations
* Audience: CISO, Vendor Management, Architecture team
* Type: Operational
* Urgency: Near-term (72h) when partner breach reported

**PIR-4: Patient Data Exposure**

* Intelligence Question: "Is patient data processed by EuroHealth or our hospital customers available on dark web markets, paste sites, or criminal forums?"
* Business Decision: GDPR breach notification requirements (72h); hospital customer notification
* Audience: CISO, Legal, DPO, Executive leadership
* Type: Tactical
* Urgency: Immediate (<4h from discovery, given GDPR 72h notification requirement)

**PIR-5: EHR Software Vulnerability Intelligence**

* Intelligence Question: "Are there any zero-day or unpatched vulnerabilities in EuroHealth's EHR platform components (web frameworks, databases, authentication libraries) being actively exploited in the wild?"
* Business Decision: Emergency patching decisions; temporary mitigations; customer notifications
* Audience: Engineering, CISO, Customer Success
* Type: Tactical
* Urgency: Immediate for actively exploited vulnerabilities

**PIR-6: Threat Actor TTP Evolution**

* Intelligence Question: "How are threat actors (particularly those targeting healthcare and critical infrastructure) evolving their techniques, and do our current defenses cover them?"
* Business Decision: Security investment planning; detection gap prioritization
* Audience: CISO, Architecture, SOC Engineering
* Type: Strategic
* Urgency: Strategic (quarterly)

**PIR-7: Geopolitical Risk to Healthcare Infrastructure**

* Intelligence Question: "Are there nation-state or politically-motivated threats to European healthcare infrastructure that could affect EuroHealth's operations or customers?"
* Business Decision: Risk posture adjustments, board communication, business continuity planning
* Audience: Board, Executive, CISO
* Type: Strategic
* Urgency: Strategic (monthly, or ad hoc during geopolitical events)

### 1.3 Intelligence Types Matrix

| Type | Meaning for EuroHealth | Products | Primary Consumers | Frequency |
|------|------------------------|----------|-------------------|-----------|
| Tactical | Specific IOCs and attack indicators that SOC can immediately act upon | IOC feeds, Flash alerts, IDS rules, YARA/Sigma rules | SOC analysts, Firewall/EDR engineers | Continuous (IOCs), Daily (alerts) |
| Operational | Campaign and threat actor activity context that hunters and engineers need | Hunt briefings, Actor profiles, Campaign reports | Threat hunters, SOC lead, Security engineers | Weekly |
| Strategic | Threat landscape trends and business risk analysis | Quarterly threat landscape, Annual risk report, Board briefings | CISO, Board, Executive leadership | Monthly/Quarterly |

---

## Task 2: Technology Architecture

### 2.1 Platform Selection: MISP + Limited OpenCTI

**Recommendation:** Deploy **MISP** as the primary operational platform with **OpenCTI** for strategic analysis.

**Justification:**

* MISP is the de facto standard in healthcare sharing communities (H-ISAC uses MISP)
* MISP has direct integration with Splunk (via MISP-to-STIX and misp-siem connectors)
* MISP integrates with CrowdStrike for EDR indicator pushing
* MISP feeds can be consumed by SOC team immediately
* OpenCTI's strength is in relationship mapping and strategic analysis (actor profiles, campaign tracking)
* Both are open source; hosting costs are minimal

**Deployment model:** On-premise (EU-only) given GDPR requirements for data residency.
MISP on dedicated VM (8 core, 32GB RAM); OpenCTI on cloud VM in EU region (Azure West Europe).

**Key integrations:**

* MISP → Splunk: Push IOCs as lookup tables (automated every 4 hours)
* MISP → CrowdStrike: Push hashes/IPs to Falcon Intelligence via API
* MISP → Palo Alto firewall: Push IP/domain blocks via MineMeld or direct API
* H-ISAC MISP → EuroHealth MISP: Synchronized sharing (pull every 6 hours)
* MISP ↔ OpenCTI: Bidirectional sync via MISP connector

### 2.2 Intelligence Sources

**Budget allocation for sources:** €150,000

**Tier 1 (Free):**

* CIRCL OSINT Feed (MISP default)
* Abuse.ch (URLhaus, MalwareBazaar, FeodoTracker)
* CISA Known Exploited Vulnerabilities catalog
* AlienVault OTX (free API)
* MalShare, VirusTotal (free tier for enrichment)
* ENISA threat landscape reports
* H-ISAC free membership tier

**Tier 2 (Paid) — Budget: €100,000/year:**

1. **Recorded Future Intelligence Platform (€65,000/year)**
   * Healthcare-specific threat intelligence module
   * Dark web monitoring for EuroHealth mentions
   * Vulnerability intelligence (zero-days before public disclosure)
   * Justification: Best dark web monitoring + healthcare specialization; direct MISP integration

1. **Intel 471 TITAN Platform (€35,000/year)**
   * Underground forum monitoring
   * Initial access broker tracking (hospitals are high-value targets for IABs)
   * Justification: Deep criminal underground coverage; critical for detecting "for sale" access to EuroHealth systems

**Tier 3 (Community):**

* **H-ISAC Full Membership (€15,000/year):** Healthcare-specific sharing, MISP sync, working groups, annual summit
* **European Healthcare CERT Consortium (ENCS):** European healthcare-specific coordination
* **ENISA CSIRT Network:** Government coordination channel

**Total sources budget:** €115,000 (within €150,000 allocation)

### 2.3 Technical Architecture

```text
INTELLIGENCE SOURCES
====================
H-ISAC MISP ──────────────────────┐
CIRCL OSINT Feed ─────────────────┤
Abuse.ch Feeds ───────────────────┤──→  MISP (On-Premise EU)
Recorded Future API ──────────────┤         │
Intel 471 API ────────────────────┘         │
                                           ↕ (bidirectional)
OTX, VirusTotal (enrichment) ────────→  OpenCTI (Azure EU)
                                           │
                          ┌────────────────┴──────────────────┐
                          ↓                                    ↓
              SIEM (Splunk)                          REPORTS/PRODUCTS
              - IOC lookup tables                    - Hunt briefings
              - Sigma rule deployment                - Actor profiles
              - Scheduled hunt queries               - Board reports
                          ↓
              EDR (CrowdStrike)         FIREWALL/DNS
              - Hash blocking           - IP/Domain blocks
              - IOC matching            (Palo Alto + DNS filter)

FEEDBACK LOOPS:
  SOC Analysts → MISP (false positive reports, new observations)
  Hunters → MISP (hunt findings as new events)
  IR Team → MISP (incident IOCs)
```

---

## Task 3: Operational Workflows

### 3.1 Tactical IOC Workflow

```text
INPUT: Critical IOC received via H-ISAC (e.g., new ransomware C2 IPs)
│
├─ Step 1: Auto-import (MISP feed sync, every 6h)
│           OR Manual import (analyst) for flash alerts
│
├─ Step 2: Automated enrichment (< 15 min)
│    │ Query VirusTotal, OTX for reputation
│    │ Check WHOIS age
│    └ Flag: "High Confidence / Needs Review / Low Confidence"
│
├─ Step 3: Analyst Triage (SLA: 2 hours for Critical)
│    │ Is IOC relevant to EuroHealth environment?
│    │ Is it currently in our network? (check SIEM)
│    └ Set to_ids flag and confidence level
│
├─ Decision: Actively in environment?
│    ├─ YES → Escalate to INCIDENT RESPONSE (IR-ticket)
│    └─ NO → Continue to Step 4
│
├─ Step 4: Action (SLA: 4 hours for Critical TLP:AMBER)
│    │ Push IP/domain to firewall/DNS block (auto via MISP connector)
│    │ Push hash to CrowdStrike EDR (auto via MISP connector)
│    └ Add Splunk lookup table (auto, next sync)
│
├─ Step 5: Notification
│    │ SOC Team: Slack/email alert with context
│    │ Hunt Team: Flag for proactive hunting
│    └ Engineering (if vulnerability-related): Immediate notification
│
└─ Step 6: Lifecycle Management
     │ Tag IOC with expiry date (default: 60 days)
     │ Monthly review: Are blocked IPs still malicious?
     └ On expiry: Auto-review by analyst before removal
```

### 3.2 Intelligence-Driven Hunt Workflow

```text
INPUT: New threat actor report (e.g., "VIPER-HEALTH targeting EHR vendors")
│
Day 0: Intelligence Receipt
├─ Analyst reads report, extracts TTPs
├─ Maps TTPs to MITRE ATT&CK
└─ Creates draft MISP event (TLP:AMBER)

Day 0-1: Hunt Planning (Threat Intel Lead + Hunt Lead)
├─ Prioritization meeting (30 min): Is this relevant?
├─ Map TTPs to available data sources
├─ Write 3-5 hunting hypotheses
├─ Assign hunter and time estimate
└─ Create hunt tracking ticket

Day 1-3: Hunt Execution (Threat Hunter)
├─ Validate data source availability
├─ Execute queries for each hypothesis
├─ Document findings in hunt log
└─ Escalate immediately if TTP found

Day 3-5: Analysis and Reporting
├─ Compile hunt findings
├─ Write hunt report
├─ Submit any incidents found to IR
└─ Create new Sigma rules for confirmed TTPs

Day 5-7: Close and Feedback
├─ Deploy new detection rules to SIEM
├─ Update MISP event with hunt findings
├─ Update ATT&CK coverage map
├─ Brief SOC lead on new detections
└─ Schedule follow-up hunt if needed
```

---

## Task 4: Metrics and Maturity

### 4.1 Year 1 KPIs

| KPI | Description | Calculation | Year 1 Target | Why It Matters |
|-----|-------------|-------------|---------------|----------------|
| Mean Time to IOC Action | Time from IOC receipt to blocking | Avg(block_time - receive_time) | < 4 hours for Critical | Speed of response |
| Detection Coverage % | % of ATT&CK techniques covered by detections | Detected techniques / Relevant techniques × 100 | > 40% | Coverage breadth |
| Hunt Frequency | Number of hunts completed per month | Count of closed hunt reports | ≥ 4 per month | Program activity |
| True Positive Hunt Rate | % of hunts finding real threats | TPs / Total hunts × 100 | > 15% | Hunt quality |
| PIR Satisfaction Score | Quarterly consumer rating of intelligence usefulness (1-5) | Survey result | ≥ 3.5/5.0 | Intelligence relevance |
| IOC Freshness | % of active IOCs less than 60 days old | New IOCs (60d) / Total IOCs × 100 | > 70% | Intelligence currency |
| New Detections from Hunts | Number of Sigma rules created from hunt findings | Count per quarter | ≥ 6 per quarter | Hunting ROI |
| Credential Exposure Response Time | Time from dark web find to credential change | Avg response time | < 8 business hours | Proactive protection |
| MISP Event Production | Number of new intelligence events created | Monthly count | ≥ 20 per month | Production volume |
| False Positive Rate | % of automated blocks that turn out benign | FPs / (TPs + FPs) × 100 | < 10% | Block quality |

### 4.2 Maturity Roadmap

**Current State: Level 0 (Initial)**
EuroHealth has no proactive hunting or formal threat intelligence function.
Security is entirely reactive, alert-driven.

**Year 1 Target: Level 1-2 (Minimal to Procedural)**

Level 1 milestones (Q1-Q2):

* MISP deployed and connected to H-ISAC and 3 free feeds
* SOC team consuming IOC feeds (daily SIEM lookup table updates)
* Dark web monitoring active
* First 10 PIRs defined and publishing cycle established

Level 2 milestones (Q3-Q4):

* 4 hunts per month executing against ATT&CK techniques
* Sigma rules deployed for top 20 ATT&CK techniques
* Hunt documentation standard implemented
* KPI dashboard live

**Year 3 Target: Level 3 (Innovative)**

* Statistical/ML-assisted anomaly detection in hunt queries
* Custom data models for EuroHealth's specific environment
* Contribution to H-ISAC sharing (not just consuming)
* Automated hunting pipelines for high-frequency hypotheses
* Intelligence-driven security architecture reviews

---

## Task 5: Legal, Ethical, Compliance

### 5.1 GDPR Compliance

**PII in threat reports:**
EuroHealth threat intelligence activities may encounter PII in two forms:

1. Attacker identity information (names, alleged locations)
1. Victim information in shared intelligence (which organizations were breached)

**Controls:**

* All MISP events containing PII must be tagged as "personal-data" and distributed as TLP:RED or shared only with named organizations
* Incident reports containing patient data references must be immediately escalated to the DPO
* Threat intelligence staff must complete GDPR awareness training annually

**Data sharing with partners:**
Sharing intelligence with H-ISAC or ISAC partners is permitted under the "legitimate interest" basis (GDPR Article 6(1)(f)) as long as:

* The intelligence does not contain patient PII
* Sharing agreements (Data Processing Agreements) are in place with ISAC
* Only the minimum necessary data is shared
* Retention limits are applied to shared data

**Retention periods:**
| Data Type | Retention | Basis |
|-----------|-----------|-------|
| IOCs (no PII) | 24 months | Operational need |
| IOCs (with PII) | 12 months | Legitimate interest + data minimization |
| Incident reports | 5 years | Legal obligation |
| Hunt logs | 3 years | Operational need |

### 5.2 TLP Handling Policy (Summary)

**EuroHealth Alliance Threat Intelligence TLP Policy v1.0**

**TLP:RED** - EuroHealth Confidential

* May not leave the original sharing session
* Must not be stored in MISP without explicit permission from source
* Verbally shared only; no written distribution

**TLP:AMBER** - Internal + Direct Partners

* May be shared within EuroHealth (all employees with need to know)
* May be shared with H-ISAC and named partner organizations with active DPA
* Must not be posted publicly, emailed to personal addresses, or shared with vendors unless named
* Must carry TLP:AMBER marking on all copies

**TLP:AMBER+STRICT** - Internal Only

* May not be shared with clients or external parties
* Internal distribution only, with audit trail

**TLP:GREEN** - Community

* May be shared with EuroHealth's intelligence sharing community (H-ISAC, ENISA CSIRT partners)
* May not be posted on public social media or websites

**TLP:CLEAR** - Public

* No restrictions; may be shared freely

**Violations:** TLP policy violations must be reported to the CISO within 24 hours.

### 5.3 Dark Web Monitoring

**Legality in EU:**
Dark web monitoring (passive observation of publicly accessible onion sites) is generally legal in EU member states as an intelligence collection activity.
However:

* **ILLEGAL:** Purchasing illicit goods or services to verify data (even for investigative purposes)
* **ILLEGAL:** Accessing systems without authorization (even to verify if EuroHealth data is in a database)
* **LEGAL:** Passive monitoring of dark web forums for mentions
* **LEGAL:** Purchasing commercial dark web monitoring services (they handle legal risk)
* **GREY AREA:** Creating accounts on criminal forums for monitoring (consult legal counsel per jurisdiction)

**Compliant approach for EuroHealth:**

1. **Use commercial services only** (Recorded Future, Intel 471) - they are responsible for their collection methods
1. **Do not conduct personal dark web monitoring** without written legal approval and explicit boundaries
1. **If exposed data is found:** Do not access/download the data; document the finding; immediately notify DPO (72h GDPR clock starts)
1. **Document everything:** Monitoring activities, findings, and actions taken

---

## Grading Notes

**Task 1 PIRs:** PIRs should be questions, not statements.
The test: "Can I answer this question yes or no or with specific data?" If not, it's too vague.
Patient data exposure PIR should specifically acknowledge the GDPR 72-hour notification requirement (this shows understanding of compliance context).

**Task 2 Budget:** Students who recommend extremely expensive platforms on a €450,000 budget (e.g., Mandiant Premium at €300,000) should be flagged.
The budget must be realistic, with headcount considered (~€250,000 of the budget should be people; €150,000 for tools + subscriptions is realistic).

**Task 4 Metrics:** The MTTD/MTTR metrics are obvious; look for more nuanced choices (hunt effectiveness rates, PIR satisfaction).
Students who only list "number of IOCs blocked" miss the point that volume metrics are not quality metrics.

**Task 5 GDPR:** Common mistake is saying "we can share anything with H-ISAC because they're security researchers." GDPR applies regardless of who you share with.
DPA agreements are required for data sharing with external organizations processing data on EuroHealth's behalf or receiving personal data.
