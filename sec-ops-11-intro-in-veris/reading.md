# Session 11: Introduction to VERIS (Vocabulary for Event Recording and Incident Sharing)

**Estimated reading time: ~2 hours**
**Level:** Intermediate

**Prerequisites:** Sessions 1–10, incident response fundamentals, basic threat actor knowledge

---

## Table of Contents

1. [Why Standardized Incident Vocabularies Matter](#1-why-standardized-incident-vocabularies-matter)
1. [What is VERIS?](#2-what-is-veris)
1. [The VERIS 4A Taxonomy](#3-the-veris-4a-taxonomy)
1. [Actors: Who Caused the Incident?](#4-actors-who-caused-the-incident)
1. [Actions: What Did They Do?](#5-actions-what-did-they-do)
1. [Assets: What Was Affected?](#6-assets-what-was-affected)
1. [Attributes: How Was It Affected?](#7-attributes-how-was-it-affected)
1. [The Verizon DBIR: Structure and Key Findings](#8-the-verizon-dbir-structure-and-key-findings)
1. [The VERIS Community Database (VCDB)](#9-the-veris-community-database-vcdb)
1. [Creating a VERIS Record: Fields and Structure](#10-creating-a-veris-record-fields-and-structure)
1. [Using VERIS for Threat Landscape Analysis](#11-using-veris-for-threat-landscape-analysis)
1. [Integration with Other Frameworks](#12-integration-with-other-frameworks)
1. [Practical SOC Use Cases for VERIS](#13-practical-soc-use-cases-for-veris)
1. [Data Breach vs. Security Incident: The VERIS Distinction](#14-data-breach-vs-security-incident-the-veris-distinction)
1. [Summary and Key Takeaways](#15-summary-and-key-takeaways)
1. [References](#16-references)

---

## 1. Why Standardized Incident Vocabularies Matter

Every organization that responds to security incidents faces a fundamental challenge: how do you describe what happened in a way that is consistent, comparable, and useful beyond the immediate investigation?
Without a shared vocabulary, the security industry produces data that is difficult to aggregate, trend-analyze, or benchmark.

### The Problem with Ad-Hoc Reporting

Consider how different organizations might describe the same type of incident:

* Organization A: "An employee accidentally sent customer data to the wrong email address"
* Organization B: "PII exposure via misdirected email"
* Organization C: "Insider negligence resulting in unauthorized disclosure"
* Organization D: "Data leakage incident — user error"

All four describe the same type of event, but none are directly comparable in a database.
An analyst trying to answer "how common is accidental data exposure by employees?" would need to manually review each record and make judgment calls about which incidents qualify.

This problem scales massively across the industry.
When thousands of organizations report incidents using inconsistent terminology, it becomes almost impossible to:

* Calculate accurate base rates for different incident types
* Identify industry-specific risk patterns
* Benchmark your organization's incident profile against peers
* Track trends in attacker tactics and techniques over time
* Share intelligence in a machine-readable format

### The Value of Common Taxonomies

Standardized vocabularies solve this problem by providing agreed-upon definitions and categories.
When an analyst says "Actor: External, Variety: Organized crime; Action: Hacking, Variety: Use of stolen credentials; Asset: Server, Variety: Database server; Attribute: Confidentiality," every trained analyst immediately understands the nature of the incident.

This enables:

**Aggregation**: Combine incident data from hundreds of organizations to identify patterns that no single organization could detect alone.

**Benchmarking**: Compare your organization's incident profile against industry averages or peer groups.

**Trend analysis**: Track whether social engineering attacks are increasing, whether a particular industry is being targeted more heavily, or whether a specific vulnerability class is being exploited.

**Intelligence sharing**: Exchange incident data with ISACs, government agencies, and peer organizations in a machine-ingestible format.

**Research**: Build the evidence base for security investment decisions, regulatory guidance, and academic research.

### The Landscape of Security Incident Taxonomies

VERIS is not the only incident taxonomy.
Before examining it in depth, it is worth understanding where it fits:

| Framework | Primary Focus |
|-----------|--------------|
| **VERIS** | Incident/breach classification for aggregate statistical analysis |
| **STIX/TAXII** | Threat intelligence sharing, indicators of compromise |
| **MITRE ATT&CK** | Adversary TTPs at a granular technical level |
| **CAPEC** | Abstract attack patterns |
| **CVE/NVD** | Specific software vulnerabilities |
| **OWASP** | Web application security categories |

VERIS occupies a unique niche: it is specifically designed to record and share incident data at the event level, with enough structure to support statistical analysis and trend reporting.
While ATT&CK tells you *how* attackers operate in detail, VERIS tells you *what happened* in a structured way that enables aggregate analysis.

---

## 2. What is VERIS?

**VERIS** stands for **Vocabulary for Event Recording and Incident Sharing**.
It is an open framework developed and maintained by Verizon's RISK Team (now the Verizon Threat Research Advisory Center, VTRAC) primarily to support the annual Verizon Data Breach Investigations Report (DBIR).

### History and Development

VERIS emerged from Verizon's work investigating data breaches beginning in the mid-2000s.
As the DBIR team accumulated thousands of breach investigations, they recognized the need for a consistent way to encode incident data for analysis.
The resulting framework was open-sourced to allow community contribution and adoption.

Key milestones:

* **2008**: First DBIR published, using early forms of what would become VERIS
* **2010**: VERIS formally published as an open standard
* **2012**: VERIS Community Database (VCDB) launched, inviting public contributions
* **2013**: VERIS 1.3 released with expanded enumeration values
* **2016**: Informal integration with ATT&CK techniques begins
* **2021+**: Continued evolution with expanded industry and timeline tracking

### VERIS Design Philosophy

VERIS was designed with several explicit goals:

1. **Practicality over perfection**: Records should be completable with information typically available after an investigation — not require data that is rarely obtainable.

1. **Statistical utility**: Every field is designed to be useful in cross-record comparisons, not just individual record-keeping.

1. **Flexibility with structure**: Required fields ensure minimum viable records; optional fields allow additional detail when available.

1. **Common language**: Enumeration values (fixed lists) enforce consistency while the schema allows free-text supplementation.

1. **Non-attribution**: The framework does not require identifying the specific attacker, only characterizing them. This encourages sharing by reducing legal and political concerns.

### What VERIS Records

A VERIS record captures a security **incident**: any event that compromises the confidentiality, integrity, or availability of an information asset.
Within incidents, VERIS distinguishes:

* **Incident**: Any event that violates security policy
* **Breach**: A confirmed disclosure of data to an unauthorized party
* **Security event**: A potential incident requiring investigation

The framework records: who was involved (actors, victims), what happened (actions taken), what was affected (assets and their attributes), when and how it occurred (timeline, discovery), and what the impact was (loss categories).

---

## 3. The VERIS 4A Taxonomy

The heart of VERIS is the **4A taxonomy**: a four-dimensional classification system that characterizes every security incident along four axes:

```text
Actor     ──────► Who caused the incident?
Action    ──────► What did they do?
Asset     ──────► What was affected?
Attribute ──────► How was it affected?
```

This structure captures the essential "story" of an incident without requiring the level of detail that may be unavailable or confidential.

### Why Four Dimensions?

Early incident taxonomies focused on a single dimension — typically the action taken (e.g., "SQL injection," "phishing").
This produced useful technical classification but missed critical context:

A SQL injection attack by an organized crime group targeting a financial database to steal credit cards is very different from a SQL injection by a curious student who briefly accessed a blog.
Same action, completely different risk profile, impact, and response requirements.

By capturing actor, action, asset, and attribute simultaneously, VERIS creates a richer incident fingerprint that supports nuanced analysis.

### The Enumeration-Based Approach

Each dimension has a fixed **enumeration**: a hierarchical list of permitted values:

```text
Category (top level)
  └── Variety (specific type)
        └── Vector (delivery mechanism, for actions)
```

For example, for Actions:

```text
Hacking (category)
  ├── Brute force (variety)
  ├── SQLi (variety)
  ├── Use of stolen credentials (variety)
  └── Exploit vulnerability (variety)
        ├── Remote access (vector)
        └── Web application (vector)
```

This hierarchy allows analysis at multiple granularities: "What percentage of incidents involved Hacking?" or "What percentage specifically involved SQLi against web applications?"

### Beyond the 4As

A complete VERIS record also captures:

* **Victim**: Industry, size, location of the affected organization
* **Timeline**: Discovery, containment, and remediation dates
* **Discovery method**: How was the incident detected?
* **Loss categories**: Types of losses incurred
* **Impact**: Estimated financial and operational impact
* **Indicators**: Artifacts that could help detect similar incidents

---

## 4. Actors: Who Caused the Incident?

The Actor dimension answers: **who was responsible for the incident?** VERIS recognizes that incidents can be caused by parties with very different motivations and levels of access, and that who caused an incident fundamentally shapes its nature and appropriate response.

### Actor Categories

#### 4.1 External Actors

External actors have **no legitimate access** to the targeted organization's systems.
They must breach the organization's perimeter to cause harm.

**Organized crime**: Criminal groups motivated primarily by financial gain.
This is consistently the largest external actor category in the DBIR.
These groups conduct phishing campaigns, run malware-as-a-service operations, operate ransomware affiliates, and buy/sell stolen credentials.
They treat attacks as a business.

Key characteristics:

* Primarily financially motivated
* Use commodity tools and techniques
* Often operate across multiple industries simultaneously
* Move quickly once inside (ransomware deployment within hours)
* Coordinate through underground forums and dark web markets

**Nation-state / State-affiliated**: Government-sponsored or government-tolerated threat actors conducting espionage, sabotage, or influence operations.
Well-resourced, patient, and focused on strategically significant targets.

Key characteristics:

* Motivated by espionage, sabotage, or strategic advantage
* High operational security (OPSEC)
* May persist in networks for months or years before detection
* Custom tools and zero-day exploits more common
* Target government, defense, critical infrastructure, and technology companies

**Hacktivist**: Individuals or groups acting for ideological, political, or social reasons.
They want to make a statement and seek publicity.

Key characteristics:

* Ideologically motivated (not financially)
* Common tactics: DDoS, website defacement, data dumps
* Loose coordination via social media and forums
* Targets chosen for symbolic or political significance
* Variable technical sophistication

**Competitor**: A business rival seeking competitive advantage through illegitimate means (industrial espionage).

**Unknown external**: When the actor cannot be characterized further.
A legitimate response — many incidents are never fully attributed.

**Unaffiliated**: Individual actors acting for personal curiosity or ego, not fitting neatly into organized categories.

#### 4.2 Internal Actors

Internal actors are **current employees, contractors, or other authorized users**.
Internal incidents can be malicious (deliberate harm) or non-malicious (accidental).

VERIS internal varieties:

* **End-user**: Regular employees causing incidents through negligence or poor security hygiene
* **System administrator**: Technical staff whose privileged access amplifies potential impact
* **Developer**: Engineers who may introduce vulnerabilities or abuse code access
* **Finance user**: Users with financial system access (relevant for fraud scenarios)
* **Executive**: Senior leaders whose accounts are high-value targets
* **Other**: Other internal actors

Intent is recorded separately:

* **Malicious**: Actor intended to cause harm (disgruntled employee, insider threat)
* **Negligent**: Actor was careless but did not intend harm (most common)
* **Unknown**: Intent cannot be determined

#### 4.3 Partner Actors

Partners occupy a middle ground: they have **some form of authorized access** but are not employees:

* **Third-party vendors**: Software vendors, managed service providers, outsourced IT
* **Business partners**: Organizations with data sharing or system integration relationships
* **Contractors**: External workers with temporary or project-based access

Partners are increasingly significant given the rise of supply chain attacks.
The SolarWinds, Kaseya, and MOVEit incidents are high-profile examples of partner-vector breaches.

### Actor Motives

VERIS records the **motive** behind actor actions:

| Motive | Description |
|--------|-------------|
| Financial | Seeking monetary gain (most common) |
| Espionage | Seeking intelligence or competitive information |
| Convenience | Taking shortcuts, not following procedures |
| Fun | Exploration, curiosity, challenge |
| Grudge | Revenge, retaliation |
| Ideology | Political, social, or religious motivation |
| Extortion | Coercion for financial or other gain |
| Unknown | Motive cannot be determined |

### Actor Distribution in Practice

Based on DBIR data across recent years:

* **~70–80%** of breaches involve external actors
* **~20–30%** involve internal actors (most are negligent, not malicious)
* **~5–10%** involve partner actors (growing due to supply chain focus)
* Multiple actor types can be involved in a single incident

---

## 5. Actions: What Did They Do?

The Action dimension answers: **what actions were taken during the incident?** This is the most technically detailed dimension of VERIS.
Actions are the specific techniques and behaviors that led to the incident.

### Action Categories

#### 5.1 Hacking

Hacking encompasses **intentional attempts to access or harm information assets without authorization** through technical methods.

Common hacking **varieties**:

* **Brute force**: Systematically trying passwords, keys, or inputs
* **Use of stolen credentials**: Using username/password pairs from prior breaches or purchases
* **Exploit vulnerability**: Exploiting known or zero-day vulnerabilities in software
* **SQLi (SQL injection)**: Injecting SQL commands through application input fields
* **Use of backdoor or C2**: Communicating through command-and-control infrastructure
* **Password dumping**: Extracting password hashes from memory or files
* **Path traversal**: Accessing files outside the intended directory
* **DNS hijacking**: Manipulating DNS to redirect traffic

Common hacking **vectors** (how hacking was accomplished):

* Web application, Desktop sharing software, Email, Network, Command shell, Partner

#### 5.2 Malware

Malware covers **any malicious software used in the incident**.

Common malware varieties:

* **Ransomware**: Encrypts victim data and demands payment for decryption
* **Trojan**: Malicious software disguised as legitimate software
* **Backdoor**: Provides persistent unauthorized remote access
* **Rootkit**: Hides its presence and conceals other malware
* **Keylogger**: Records keystrokes to capture credentials or sensitive data
* **Spyware**: Covertly monitors and exfiltrates user activity
* **Virus / Worm**: Self-replicating malware (attached to files / network-spreading)
* **Cryptocurrency miner**: Uses victim resources for mining
* **Exploit kit**: Automated framework for exploiting browser vulnerabilities

Common malware vectors:

* Email attachment, Email link, Web drive-by, Direct install, Download by malware

#### 5.3 Social Engineering

Social engineering covers **psychological manipulation** of people into performing actions or divulging information they should not.

Common social engineering varieties:

* **Phishing**: Deceptive emails tricking recipients into revealing credentials or installing malware *(most common)*
* **Pretexting**: Fabricated scenario to extract information (impersonating IT support, auditors, executives)
* **Baiting**: Leaving infected USB drives or physical media in accessible locations
* **Vishing**: Voice/phone-based phishing
* **Smishing**: SMS-based phishing
* **Business Email Compromise (BEC)**: Impersonating executives to authorize fraudulent transfers
* **Quid pro quo**: Offering something in exchange for information or access

Social engineering is consistently among the top initial access methods in the DBIR.
Humans remain the most exploitable component of most security postures.

#### 5.4 Misuse

Misuse covers **unapproved or malicious use of organizational resources or privileges** by authorized users.

Common misuse varieties:

* **Privilege abuse**: Using legitimate access for unauthorized purposes
* **Data mishandling**: Improper handling of sensitive data (emailing files to personal accounts)
* **Unapproved hardware/software**: Installing unauthorized devices or applications
* **Unapproved workaround**: Bypassing security controls for convenience
* **Knowledge abuse**: Using organizational knowledge for unauthorized purposes
* **Illicit content**: Accessing, storing, or distributing prohibited content

#### 5.5 Physical

Physical actions involve **in-person manipulation of people, systems, or facilities**.

Common physical varieties:

* **Theft**: Stealing hardware (laptops, phones, USB drives, servers)
* **Surveillance**: Observing screens, monitoring networks, recording activity
* **Tampering**: Physically modifying systems or infrastructure
* **Skimming**: Installing devices to capture payment card data at ATMs or POS terminals
* **Destruction**: Physically destroying hardware

#### 5.6 Error

Errors are **unintentional actions or omissions** that create security incidents — a crucial category often overlooked in analyses focused on malicious actors.

Common error varieties:

* **Misconfiguration**: Incorrectly configuring systems, creating unintended exposure
* **Misdelivery**: Sending data to wrong recipient (wrong email, wrong fax)
* **Publishing error**: Accidentally making data publicly accessible (exposed S3 bucket, open Elasticsearch)
* **Gaffe**: Verbal or written disclosure of sensitive information in error
* **Loss**: Losing hardware or media containing sensitive data
* **Programming error**: Software bugs creating security vulnerabilities
* **Omission**: Failing to take a required security step

Error incidents often lack a malicious "attacker" — they represent the security impact of normal human fallibility.
They are extremely common and significantly underreported.

#### 5.7 Environmental

Environmental actions are **natural or physical world events** affecting information assets:

* **Natural disaster**: Earthquakes, floods, hurricanes affecting data centers
* **Power failure**: Extended outages affecting systems
* **Electrical problems**: Power surges, lightning strikes
* **Temperature extremes**: HVAC failures leading to hardware damage
* **Water/flood damage**: Pipe bursts, facility flooding

### Multiple Actions in One Incident

A realistic incident often involves multiple actions in sequence.
A phishing attack leading to credential theft and then database access would record:

1. Action: Social Engineering (Phishing) — initial compromise
1. Action: Hacking (Use of stolen credentials) — secondary compromise
1. Action: Hacking (SQLi or direct DB access) — data access method

VERIS allows multiple action entries per incident, with the primary action typically recorded first.

---

## 6. Assets: What Was Affected?

The Asset dimension answers: **what information assets were involved in the incident?**

### Asset Categories

#### 6.1 Server

Servers are **centralized systems providing services** to other systems and users.

Server varieties:

* **Database**: SQL Server, Oracle, MySQL, PostgreSQL — stores structured data
* **Web application**: Internet-facing application servers
* **Mail**: Email server infrastructure
* **File**: File storage and sharing servers
* **Authentication**: Active Directory, LDAP, IAM systems
* **DNS**: Domain name resolution infrastructure
* **Backup**: Systems storing backup data *(high-value ransomware targets)*
* **Log**: Security logging and monitoring systems (SIEM)

#### 6.2 Network

Network assets are **devices facilitating communication** between systems.

Network varieties:

* **Router**: Layer 3 routing devices
* **Switch**: Layer 2 switching infrastructure
* **Firewall**: Network security enforcement points
* **Wireless**: Wireless access infrastructure
* **VPN concentrator**: Remote access infrastructure

Network devices are high-value targets because compromising them enables traffic interception and lateral movement.

#### 6.3 User Device

**Computing assets directly used by end users**:

* Desktop, Laptop, Tablet, Mobile phone, Remote access terminal

#### 6.4 Person

**A human being as the primary target** — particularly relevant for social engineering and physical attacks:

* End-user, Executive, System administrator, Developer, Customer, Unknown

#### 6.5 Media

**Physical and electronic storage media** containing data:

* Documents (paper), Flash drive/USB, Disk drive (HDD/SSD), CD/DVD/Tape

#### 6.6 Kiosk / Terminal

**Semi-public computing terminals** vulnerable to physical attacks:

* **ATM**: Automated teller machines *(common skimming targets)*
* **Gas terminal**: Fuel payment terminals
* **Point of sale (POS)**: Retail payment systems
* **Electronic payment kiosk**: General payment terminals

#### 6.7 Unknown

When the specific asset type cannot be determined.

---

## 7. Attributes: How Was It Affected?

The Attribute dimension answers: **how were the affected assets impacted?** VERIS applies the classic CIA triad to incident classification.

### 7.1 Confidentiality

Confidentiality incidents involve **unauthorized disclosure of information** — data was accessed or exfiltrated by unauthorized parties.

**Data varieties** (what was disclosed):

| Data Type | Examples |
|-----------|---------|
| Personal (PII) | Names, addresses, SSNs, DOBs |
| Credentials | Usernames, passwords, auth tokens |
| Payment card data | Credit/debit numbers, CVVs |
| Bank account data | Account numbers, routing numbers |
| Medical records (PHI) | Diagnoses, treatment records, prescriptions |
| Intellectual property | Trade secrets, source code, patents |
| Internal organizational | Business plans, strategy, communications |
| Classified data | Government/military classified material |

Confidentiality is the attribute most associated with "data breaches" and drives most regulatory reporting requirements (GDPR, HIPAA, PCI DSS).

### 7.2 Integrity

Integrity incidents involve **unauthorized modification of data or systems**.

Integrity sub-types:

* **Data**: Data modified, deleted, or corrupted
* **Software**: Software modified (malware installation, code tampering)
* **Hardware**: Hardware physically tampered with (skimmer installation, firmware implants)

Integrity incidents are especially significant for financial systems (unauthorized transaction modification), healthcare (medical record tampering), and industrial control systems.

### 7.3 Availability

Availability incidents involve **disruption of access to information assets**.

Availability sub-types:

* **Loss**: Complete loss of the asset
* **Interruption**: Temporary unavailability (DDoS attack, power outage)
* **Degradation**: Reduced performance (resource exhaustion, crypto mining)
* **Destruction**: Permanent damage (wiper malware, physical destruction)

### Multiple Attributes

Many incidents affect multiple attributes simultaneously:

**Ransomware** typically records:

* Integrity: Data modified (encrypted)
* Availability: Data inaccessible (encrypted)
* Confidentiality: Data possibly exfiltrated (double-extortion ransomware)

### The Confidentiality + Data Type Combination

The combination of Confidentiality attribute + specific data type is crucial for:

* Regulatory notification thresholds (GDPR Article 33, HIPAA Breach Rule)
* Severity assessment
* Notification obligations to affected individuals
* Appropriate remediation steps

---

## 8. The Verizon DBIR: Structure and Key Findings

The **Verizon Data Breach Investigations Report (DBIR)** is arguably the most important annual publication in cybersecurity.
Published annually since 2008, it represents a massive analysis of real-world incidents and breaches using the VERIS framework.

### What the DBIR Is

The DBIR aggregates incident data from Verizon's own investigations plus contributions from dozens of partner organizations including law enforcement (FBI, US Secret Service), national CERTs/CSIRTs, industry ISACs, security vendors, and independent researchers.
Recent editions analyze **tens of thousands of incidents** from the underlying dataset.

### DBIR Structure

A typical DBIR edition includes:

**Executive summary**: High-level findings and year-over-year changes for CISO/board audiences.

**Introduction and methodology**: How data was collected, definitions used, limitations and caveats.

**Findings**: Analysis organized around:

* Incident Classification Patterns (ICPs)
* Industry-specific analysis
* Geographic analysis
* Actor, action, and asset profiles
* Timeline and discovery method analysis

**Appendices**: Full data appendix with country-level and industry-level breakdowns.

### DBIR Incident Classification Patterns (ICPs)

The DBIR uses **Incident Classification Patterns** to describe common "stories" that incidents follow.
These are derived from the VERIS data through clustering analysis:

| Pattern | Description |
|---------|-------------|
| **System Intrusion** | Multi-step attack using malware and hacking. Typically organized crime. |
| **Social Engineering** | Phishing, pretexting, BEC. Human manipulation as primary mechanism. |
| **Basic Web Application Attacks** | Stolen credentials or common vulns against web-facing apps. Often opportunistic. |
| **Denial of Service** | Attacks disrupting availability, typically volumetric DDoS. |
| **Lost and Stolen Assets** | Theft or loss of physical devices and media. |
| **Miscellaneous Errors** | Accidental incidents: misdelivery, publishing errors, misconfiguration. |
| **Privilege Misuse** | Insiders abusing legitimate access. |
| **Everything Else** | Incidents not fitting cleanly into other patterns. |

### Key Recurring DBIR Findings

While specifics vary year-to-year, several themes have been consistent:

**Organized crime dominates**: External actors motivated by financial gain are responsible for the majority of breaches, every single year since 2008.

**Credentials are the primary attack vector**: Stolen credentials are consistently the top hacking variety.
The credential-theft-then-reuse cycle is the backbone of most financially motivated breaches.

**Social engineering is pervasive**: Phishing is consistently a top initial access method.
BEC is a significant and growing financial threat.

**Most breaches are discovered late**: Typical time-to-discovery is measured in days or weeks; initial compromise often takes minutes or hours (asymmetric detection gap).

**Small organizations are disproportionately vulnerable**: While large breaches get media attention, smaller organizations with limited security resources are frequent targets.

**Ransomware has grown dramatically**: Since approximately 2020, ransomware has become the dominant breach type in many industries.

### Industry-Specific Risk Profiles

Different industries face different threat profiles based on DBIR data:

| Industry | Primary Threats | Notes |
|----------|----------------|-------|
| Financial services | Credential theft, BEC, web app attacks | High-value, well-defended |
| Healthcare | PHI-focused ransomware, internal actor incidents | PHI regulatory burden (HIPAA) |
| Manufacturing | Ransomware, OT/ICS attacks, espionage | OT/IT convergence risk |
| Education | Credential theft, ransomware, research data | Often resource-constrained |
| Government | Espionage, ransomware, web app attacks | Complex regulatory environment |
| Retail | Web skimming, credential theft, POS malware | Payment card data focus |

### Reading DBIR Statistics Critically

The DBIR team is unusually transparent about data limitations:

* **Reporting bias**: Not all incidents are reported; high-severity incidents are overrepresented
* **Selection bias**: Contributing organizations are not a random sample of all organizations
* **Jurisdictional variation**: Different reporting requirements by country
* **Definition evolution**: Some categories change between editions

The DBIR team acknowledges these limitations extensively and uses confidence intervals and A/B notation to communicate statistical uncertainty.
Learning to read DBIR statistics critically is an essential professional skill.

---

## 9. The VERIS Community Database (VCDB)

The **VERIS Community Database (VCDB)** is a public, crowd-sourced database of security incidents encoded in VERIS format.
It was launched to complement the DBIR (which uses non-public data) with a fully open dataset.

### What VCDB Contains

VCDB consists of VERIS JSON records describing publicly disclosed incidents — primarily sourced from news articles, court documents, regulatory filings, and breach notification letters.
Each record includes:

* VERIS 4A classification
* Timeline information (when available)
* Victim industry and size (anonymized where necessary)
* Discovery method
* Impact information
* References to public source documents

VCDB contains thousands of records spanning many years.

### Accessing and Using VCDB

VCDB is hosted on GitHub at `https://github.com/vz-risk/VCDB`.
The repository contains:

* Individual JSON files for each incident
* An aggregated CSV export
* Analysis scripts
* Contribution guidelines

### Contributing to VCDB

The process for contributing:

1. Find a publicly disclosed incident with sufficient detail
1. Encode it as a VERIS JSON record using the schema
1. Submit a pull request to the VCDB GitHub repository
1. A reviewer verifies the encoding and merges

This is an excellent way for security professionals to practice VERIS encoding skills, contribute to the community, and build domain knowledge through real incident analysis.

### Using VCDB for Research

VCDB supports:

**Threat intelligence**: Understanding how actor groups operate, what techniques they prefer, and what industries they target.

**Risk analysis**: Estimating base rates for specific incident types in your industry.

**Training**: Real incident examples for tabletop scenarios and training exercises.

**Security program benchmarking**: Comparing your incident experience against similar documented organizations.

### VCDB Limitations

* **Public disclosure bias**: Only publicly disclosed incidents are included
* **Detail variation**: Some records are detailed; others have minimal information
* **Encoding variability**: Different contributors may encode similar incidents differently
* **Timeliness**: Lag between public disclosure and VCDB encoding

---

## 10. Creating a VERIS Record: Fields and Structure

A VERIS record is a JSON document structured according to the VERIS schema.
Understanding the schema is essential for both creating records and analyzing the database.

### Top-Level Structure

```json
{
  "incident_id": "unique-identifier",
  "source_id": "VCDB or organizational identifier",
  "summary": "Brief narrative description of the incident",
  "confidence": "High|Medium|Low",
  "security_incident": "Confirmed|Suspected|False positive",
  "timeline": { ... },
  "victim": { ... },
  "actor": { ... },
  "action": { ... },
  "asset": { ... },
  "attribute": { ... },
  "discovery_method": { ... },
  "impact": { ... },
  "notes": "Free-text notes"
}
```

### Required vs. Optional Fields

**Required** (must be present for a valid VERIS record):

* `incident_id`: Unique identifier (UUID recommended)
* `source_id`: Identifier of the submitting organization
* `security_incident`: Confirmed, Suspected, or False positive
* At least one entry in each of `actor`, `action`, `asset`, and `attribute`

**Highly recommended**:

* `summary`: Human-readable description
* `timeline.incident.year`: Year of the incident
* `victim.industry`: NAICS code for the victim's industry
* `confidence`: Confidence level in the classification

### The Timeline Object

```json
"timeline": {
  "incident": {
    "year": 2024,
    "month": 9
  },
  "discovery": {
    "unit": "Days",
    "value": 45
  },
  "containment": {
    "unit": "Hours",
    "value": 12
  },
  "exfiltration": {
    "unit": "Hours",
    "value": 6
  }
}
```

Timeline data enables analysis of attack velocity, dwell time, and response efficiency.

### The Victim Object

```json
"victim": {
  "victim_id": "Organization name or anonymized identifier",
  "industry": "522110",
  "industry2": "Commercial Banking",
  "employee_count": "1001 to 10000",
  "revenue": {
    "iso_currency_code": "USD",
    "amount": 500000000
  },
  "country": ["US"],
  "region": ["NA"]
}
```

Industry is recorded using **NAICS** (North American Industry Classification System) codes to enable standardized industry comparisons.

### The Actor Object

```json
"actor": {
  "external": {
    "variety": ["Organized crime"],
    "motive": ["Financial"],
    "country": ["Unknown"],
    "region": ["Unknown"]
  }
}
```

Only include the actor types that were involved.
An incident with only an external actor omits `internal` and `partner`.

### The Action Object

```json
"action": {
  "social": {
    "variety": ["Phishing"],
    "vector": ["Email"],
    "target": ["End-user"]
  },
  "hacking": {
    "variety": ["Use of stolen credentials"],
    "vector": ["VPN"]
  },
  "malware": {
    "variety": ["Ransomware"],
    "vector": ["Direct install"]
  }
}
```

### The Asset Object

```json
"asset": {
  "assets": [
    { "variety": "S - Database", "amount": 2 },
    { "variety": "U - Laptop", "amount": 50 }
  ],
  "cloud": ["No"]
}
```

Asset variety uses a letter prefix: **S** (Server), **N** (Network), **U** (User Device), **P** (Person), **M** (Media), **T** (kiosk/Terminal).

### The Attribute Object

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Yes",
    "data_total": 50000,
    "data": [
      { "variety": "Personal", "amount": 45000 },
      { "variety": "Credentials", "amount": 5000 }
    ]
  },
  "integrity": {
    "variety": ["Software installation"]
  },
  "availability": {
    "variety": ["Encryption"],
    "duration": { "unit": "Days", "value": 5 }
  }
}
```

### Complete Sample VERIS Record

Here is a complete VERIS record for a realistic ransomware incident at a healthcare organization:

```json
{
  "incident_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "source_id": "vcdb",
  "summary": "External threat actor deployed ransomware to hospital systems after phishing a finance employee and using stolen VPN credentials. 200 workstations encrypted. PHI potentially exfiltrated.",
  "confidence": "High",
  "security_incident": "Confirmed",
  "timeline": {
    "incident": {
      "year": 2024,
      "month": 9
    },
    "discovery": {
      "unit": "Hours",
      "value": 4
    },
    "containment": {
      "unit": "Days",
      "value": 3
    },
    "exfiltration": {
      "unit": "Hours",
      "value": 72
    }
  },
  "victim": {
    "victim_id": "Regional Medical Center",
    "industry": "622110",
    "industry2": "General Medical and Surgical Hospitals",
    "employee_count": "1001 to 10000",
    "country": ["US"],
    "region": ["NA"]
  },
  "actor": {
    "external": {
      "variety": ["Organized crime"],
      "motive": ["Financial"],
      "country": ["Unknown"],
      "region": ["Unknown"]
    }
  },
  "action": {
    "social": {
      "variety": ["Phishing"],
      "vector": ["Email"],
      "target": ["Finance"]
    },
    "hacking": {
      "variety": ["Use of stolen credentials"],
      "vector": ["VPN"]
    },
    "malware": {
      "variety": ["Ransomware"],
      "vector": ["Direct install"],
      "name": ["Unknown"]
    }
  },
  "asset": {
    "assets": [
      { "variety": "U - Desktop", "amount": 200 },
      { "variety": "S - File",    "amount": 3   },
      { "variety": "S - Database","amount": 1   }
    ],
    "cloud": ["No"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Suspected",
      "data_total": 85000,
      "data_victim": ["Patient"],
      "data": [
        { "variety": "Medical (PHI)", "amount": 85000 }
      ]
    },
    "integrity": {
      "variety": ["Software installation", "Alter behavior"]
    },
    "availability": {
      "variety": ["Encryption"],
      "duration": { "unit": "Days", "value": 5 }
    }
  },
  "discovery_method": {
    "internal": { "variety": ["NIDS"] }
  },
  "impact": {
    "loss": [
      {
        "variety": "Operational disruption",
        "amount": 2500000,
        "iso_currency_code": "USD"
      },
      {
        "variety": "Response and remediation",
        "amount": 750000,
        "iso_currency_code": "USD"
      }
    ],
    "overall_rating": "Major",
    "notes": "Ransom demand $4M. Organization paid $1.5M after negotiation."
  },
  "notes": "Phishing email subject: 'Q3 Financial Review Required'. C2 IP 198.51.100.45 identified post-incident."
}
```

---

## 11. Using VERIS for Threat Landscape Analysis

One of VERIS's most powerful applications is **aggregate threat landscape analysis**: using a collection of VERIS records to understand the overall threat environment facing an organization, industry, or geography.

### Key Analytical Questions

A threat landscape analysis using VERIS data addresses:

1. **What are the most common incident types in my industry?**

   Cross-tabulate action varieties against victim industry codes to identify the top action patterns for your NAICS code.

1. **Who is targeting organizations like mine?**

   Analyze actor varieties and motives for incidents in your industry.

1. **What assets are most commonly affected?**

   Identify which asset types appear most frequently to focus detection and protection efforts.

1. **How are incidents typically discovered?**

   Discovery method analysis reveals detection capability gaps.
   If most incidents in your industry are discovered by external parties, your detection program may be underdeveloped.

1. **What is the typical dwell time?**

   Compare time-to-discovery against industry benchmarks from VCDB/DBIR.

### Analytical Approaches

**Frequency analysis**: Counts and percentages of each VERIS dimension value.
> "What percentage of healthcare incidents involved ransomware?"

**Cross-tabulation**: Examining relationships between dimensions.
> "When organized crime is the actor, what action types appear most often?"

**Time-series analysis**: Tracking changes in patterns over time.
> "How has the frequency of credential theft changed year-over-year?"

**Clustering**: Identifying incident types that tend to co-occur (the basis for DBIR ICPs).

**Survival analysis**: Examining time-to-discovery distributions to understand detection effectiveness.

### Building a Local VERIS Database

For SOC analysts, maintaining an internal VERIS-encoded incident database enables:

* **Internal trend analysis**: "Are we seeing more phishing this quarter?"
* **Control effectiveness measurement**: "Are our controls reducing specific incident types?"
* **Detection gap identification**: "Are we only discovering incidents via external notification?"
* **Risk reporting**: Consistent incident statistics for management and board reports

### Combining DBIR/VCDB with Internal Data

The real analytical power comes from triangulation:

1. **DBIR findings** — industry-level baseline rates
1. **VCDB data** — specific public incidents for context
1. **Internal VERIS records** — your own organization's incident history

This enables: "Is my organization's incident profile consistent with industry norms, or do we have unusual risk concentrations?"

---

## 12. Integration with Other Frameworks

VERIS does not exist in isolation.
Understanding its relationship to other frameworks is important for an integrated security operations program.

### VERIS and MITRE ATT&CK

MITRE ATT&CK provides extremely granular technical detail about adversary TTPs.
VERIS and ATT&CK are **complementary**:

| VERIS | ATT&CK | Purpose |
|-------|--------|---------|
| Action: Hacking | Tactics/Techniques | Both describe adversary actions |
| Actor varieties | Threat groups (APT28, etc.) | Both characterize adversaries |
| Asset varieties | Impact/Target | Both describe what is affected |
| Attribute: Integrity | Impact techniques | Both describe security outcomes |

**Strengths**:

* VERIS: Better for aggregate statistical analysis, incident classification, trend reporting
* ATT&CK: Better for detection engineering, threat hunting, specific TTP documentation

**Using them together**: VERIS provides the incident envelope (who, what, where, when); ATT&CK provides the technical detail within that envelope.
An emerging practice is to embed ATT&CK technique IDs directly in VERIS action records.

### VERIS and the Cyber Kill Chain

Lockheed Martin's Cyber Kill Chain describes attack stages (Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives).

VERIS Action categories map approximately to Kill Chain stages:

* Social Engineering → Delivery
* Malware → Weaponization, Installation, C2
* Hacking → Exploitation, Actions on Objectives

The Kill Chain is better for thinking about attack progression and detection opportunities; VERIS is better for incident classification and aggregate analysis.

### VERIS and STIX/TAXII

STIX describes threat intelligence objects; TAXII is the transport protocol.
VERIS records can reference STIX indicators, and STIX threat actor objects correspond to VERIS actor varieties.
They are complementary: VERIS records *what happened*; STIX describes *threat context*.

### VERIS and Regulatory Frameworks

VERIS operationalizes compliance with:

* **GDPR Article 33**: Breach notification within 72 hours. VERIS timeline fields document discovery and notification timing.
* **HIPAA Breach Rule**: VERIS Confidentiality attribute + Medical (PHI) data variety captures HIPAA-reportable incidents.
* **PCI DSS**: VERIS captures payment card data compromise through the Confidentiality attribute.
* **NIS2 Directive**: VERIS incident severity classification supports NIS2 reporting threshold determination.

---

## 13. Practical SOC Use Cases for VERIS

VERIS has direct applications in day-to-day SOC operations.

### Use Case 1: Structured Incident Classification

Incorporating VERIS 4A fields into incident tickets:

```text
Incident #12345
VERIS Actor:     External > Organized crime
VERIS Action:    Social > Phishing + Hacking > Stolen credentials
VERIS Asset:     S-Database, U-Desktop
VERIS Attribute: Confidentiality (PII, 5,000 records)
```

This enables automated severity calculation, appropriate routing, and instant visibility into incident type for management.

### Use Case 2: Metrics and KPI Reporting

VERIS-encoded incident data powers rich metrics:

**Monthly security metrics**:

* Total incidents by action type (bar chart)
* Actor variety distribution (pie chart)
* Asset type frequency (sorted list)
* CIA triad breakdown (Confidentiality / Integrity / Availability incidents)
* Trend comparison vs. previous periods

**Board-level reporting**:
> "This quarter, 65% of incidents were Errors (unintentional) and 35% were actor-driven (malicious or negligent). All actor-driven incidents involved External actors; no malicious insider incidents."

### Use Case 3: Threat Intelligence Integration

VERIS classification can trigger automated threat intelligence queries:

* External organized crime actor → pull current organized crime TTP intelligence
* Action: Exploit vulnerability → query CVE data for the specific vulnerability
* Asset: Kiosk/POS → trigger PCI incident response procedures automatically

### Use Case 4: Detection Engineering Priority

VERIS action analysis drives detection rule prioritization:

> "Our industry data shows 40% of incidents involve credential theft as an initial action — we should ensure strong detection coverage for anomalous authentication patterns."

> "Our internal VERIS data shows 15% of incidents were only discovered via external notification — we need to improve internal detection capabilities."

### Use Case 5: Tabletop Exercise Design

VCDB incidents can be used to design realistic tabletop exercises:

> "Find 3 VCDB incidents for healthcare organizations with External > Organized crime actors and Malware > Ransomware actions. Use these as tabletop scenarios for the quarterly exercise."

### Use Case 6: Third-Party Risk Assessment

When assessing vendors or partners:

> "Review VCDB incidents in the managed services provider industry. What actor types and action types are most common? Use this to inform vendor security questionnaire requirements."

### Use Case 7: Post-Incident After-Action Review

A VERIS record provides structured documentation for:

* Lessons learned discussions
* Regulatory reporting
* Insurance claim documentation
* Legal proceedings
* VCDB contribution (if publicly disclosed)

---

## 14. Data Breach vs. Security Incident: The VERIS Distinction

A critical conceptual distinction in VERIS is between a **security incident** and a **data breach**.
These terms are often used interchangeably in casual conversation but have precise meanings in VERIS and in law.

### The Hierarchy

```text
Security Events (alerts, potential incidents — not yet confirmed)
  └── Security Incidents (confirmed policy violations of any type)
        └── Data Breaches (incidents with confirmed data disclosure)
              └── Notifiable Breaches (breaches triggering regulatory notification)
```

### Security Incident

A **security incident** is any event that violates security policy or compromises CIA of an information asset.
Includes:

* Confirmed and suspected breaches
* Availability incidents (DDoS, ransomware) without confirmed data disclosure
* Integrity incidents (malware) without confirmed data disclosure
* Near-misses and blocked attempts (when policy was violated)

### Data Breach

A **data breach** (in VERIS: "confirmed data disclosure") is a security incident where:

1. Data was accessed or exfiltrated by an unauthorized party
1. This is confirmed, not merely suspected

In VERIS: `attribute.confidentiality.data_disclosure: "Yes"` designates a confirmed breach.

### Why This Distinction Matters

**Legally**: Many notification laws are triggered by confirmed breaches of specific data types.
Treating every incident as a "breach" triggers unnecessary legal obligations and erodes the term's meaning.

**Analytically**: DBIR specifically separates incidents from breaches.
These populations show different patterns.

**Operationally**: Response procedures for a confirmed PHI breach differ from procedures for a DDoS attack, even though both are incidents.

### VERIS Fields for This Distinction

* `security_incident`: `"Confirmed"` | `"Suspected"` | `"False positive"`
* `attribute.confidentiality.data_disclosure`: `"Yes"` | `"No"` | `"Potentially"` | `"Unknown"`

---

## 15. Summary and Key Takeaways

### Core Concepts

1. **VERIS provides a common language** for describing security incidents, enabling aggregate analysis, benchmarking, and intelligence sharing across organizations.

1. **The 4A taxonomy** (Actor, Action, Asset, Attribute) captures the essential who, what, where, and how of any security incident in a consistent, analyzable format.

1. **Actors span three categories**: External (organized crime, nation-state, hacktivist), Internal (employee — negligent or malicious), and Partner (vendors, third parties).

1. **Actions span seven categories**: Hacking, Malware, Social Engineering, Misuse, Physical, Error, and Environmental — each with specific varieties and vectors.

1. **Assets span six categories**: Server, Network, User Device, Person, Media, and Kiosk.

1. **Attributes apply the CIA triad**: Confidentiality (disclosure), Integrity (modification), and Availability (disruption).

1. **The DBIR is the primary application** of VERIS at scale — analyzing tens of thousands of incidents annually to identify industry patterns.

1. **VCDB is the public community dataset** — a crowd-sourced collection of publicly disclosed incidents.

1. **VERIS complements ATT&CK**: VERIS provides incident-level classification for trend analysis; ATT&CK provides technique-level detail for detection engineering.

1. **SOC applications are practical**: Incident ticketing, metrics reporting, threat intelligence, detection engineering, and tabletop design.

### Common Pitfalls

* **Confusing incident and breach**: Not every incident is a breach. Use VERIS terminology precisely.
* **Under-recording errors**: Accidental incidents are frequently underreported but represent a significant portion of real-world incidents.
* **Over-attributing actors**: Say "external, unknown" when evidence doesn't support a more specific attribution.
* **Treating DBIR percentages as universal**: The DBIR represents its contributing dataset, not a perfectly representative sample.
* **Skipping the timeline**: Timeline data is among the most valuable for analysis but is often omitted when creating records.

### Skills to Practice

* Encoding real incidents as VERIS JSON records
* Analyzing VCDB data to answer specific threat landscape questions
* Reading DBIR findings critically, including statistical limitations
* Mapping internal incident data to VERIS dimensions for trend analysis
* Integrating VERIS classification into incident response workflows

---

## 16. References

### Primary Sources

* **VERIS GitHub Repository**: https://github.com/vz-risk/veris

  Official VERIS schema, documentation, and tools

* **VERIS Community Database (VCDB)**: https://github.com/vz-risk/VCDB

  Public incident database in VERIS format

* **Verizon DBIR**: https://www.verizon.com/business/resources/reports/dbir/

  Annual Data Breach Investigations Report

* **VERIS Framework Community Site**: http://veriscommunity.net

  Documentation, getting started guides, and tools

### Complementary Frameworks

* **MITRE ATT&CK**: https://attack.mitre.org/
* **STIX 2.1 Specification**: https://docs.oasis-open.org/cti/stix/v2.1/
* **MITRE CAPEC**: https://capec.mitre.org/

### Academic and Industry Research

* Verizon RISK Team. (Annual). *Data Breach Investigations Report*. Verizon Business.
* Edwards, B., Hofmeyr, S., & Forrest, S. (2016). Hype and Heavy Tails: A Closer Look at Data Breaches. *Journal of Cybersecurity*, 2(1), 3–14.
* Romanosky, S. (2016). Examining the costs and causes of cyber incidents. *Journal of Cybersecurity*, 2(2), 121–135.

### Tools and Utilities

* **veris-tools**: Python scripts for working with VERIS data (GitHub: vz-risk/veris-tools)
* **VCDB Jupyter notebooks**: Data analysis notebooks in the VCDB repository

---

*Session 11 | Security Operations Master Class | Digital4Security*
*Content version 2.0 | April 2026*
