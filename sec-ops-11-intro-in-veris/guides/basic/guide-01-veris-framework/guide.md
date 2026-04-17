# Guide 01: Understanding the VERIS Framework

**Level:** Basic

**Estimated time:** 45 minutes

**Directory:** `guides/basic/guide-01-veris-framework/`

---

## Purpose

This guide introduces the VERIS (Vocabulary for Event Recording and Incident Sharing) framework to analysts with no prior exposure.
By the end of this guide you will understand what VERIS is, why it exists, how it is structured, and how it is used in the security industry.

---

## 1. The Problem VERIS Solves

### A Tale of Inconsistent Reporting

Imagine three security analysts at three different organizations all investigate a phishing attack that resulted in stolen credentials being used to access a database.
They each write an incident report:

* Analyst 1 writes: *"Credential compromise via social engineering, leading to unauthorized database access"*
* Analyst 2 writes: *"Phishing attack — user credentials stolen and misused for data theft"*
* Analyst 3 writes: *"BEC precursor phishing, database access event, PII at risk"*

All three describe the same type of incident.
But if you tried to aggregate these reports to answer "how many incidents this year involved phishing as an initial step?", you would need a human to manually read and categorize each report.

**VERIS solves this by providing a controlled vocabulary**: a fixed set of terms for each dimension of an incident.
When all three analysts use VERIS, they all record `action.social.variety: ["Phishing"]` — machine-readable and instantly aggregatable.

### Why This Matters at Scale

The Verizon DBIR analyzes **tens of thousands of incidents per year** from hundreds of contributing organizations.
Without a consistent encoding framework like VERIS, this analysis would be impossible.
VERIS makes large-scale, cross-organizational incident analysis feasible.

---

## 2. What VERIS Is (and Is Not)

### VERIS IS:

* A structured vocabulary for encoding security incidents
* A JSON schema for recording incident data
* A framework for aggregate statistical analysis
* The backbone of the Verizon DBIR and VCDB

### VERIS IS NOT:

* A threat intelligence format (that is STIX/TAXII)
* An attack technique database (that is MITRE ATT&CK)
* A vulnerability database (that is CVE/NVD)
* An incident response procedure or playbook
* A compliance framework

---

## 3. The VERIS 4A Taxonomy: A Mental Model

The core of VERIS is the **4A taxonomy**.
Every security incident can be described by answering four questions:

| # | Dimension | Question | Example Answer |
|---|-----------|----------|---------------|
| 1 | **Actor** | Who caused it? | External, Organized crime |
| 2 | **Action** | What did they do? | Malware, Ransomware |
| 3 | **Asset** | What was affected? | Server, Database |
| 4 | **Attribute** | How was it affected? | Availability, Encryption |

This produces a "fingerprint" of the incident: **External organized crime / Ransomware via phishing / Database and workstations / Availability (encrypted) + Confidentiality (exfiltrated data).**

### The Hierarchy Within Each Dimension

Each dimension has a two-level hierarchy:

```text
Dimension (e.g., Action)
  └── Category (e.g., Malware)
        └── Variety (e.g., Ransomware)
              └── Vector (e.g., Email attachment)
```

The category is the broad type; the variety is the specific sub-type; the vector is how it was delivered or used.

### Example: Fully Qualified Action

```text
Action: Hacking
  └── Variety: Use of stolen credentials
        └── Vector: VPN
```

This tells you: the attacker used hacking techniques, specifically by using stolen credentials, through the VPN service.

---

## 4. Actor Categories — A Quick Reference

### External Actors

External actors have no legitimate access to the organization.
They must "break in":

| Variety | Profile | Typical Motive |
|---------|---------|---------------|
| Organized crime | Criminal groups, professional | Financial |
| Nation-state | Government-sponsored | Espionage |
| Hacktivist | Ideologically motivated | Ideology |
| Competitor | Business rival | Financial/Espionage |
| Unaffiliated | Lone-wolf hackers | Fun/Notoriety |

**Key insight**: Organized crime accounts for the majority (~70%) of external actor breaches in the DBIR, consistently across years.

### Internal Actors

Internal actors have legitimate access (employees, contractors):

| Variety | Common Scenario |
|---------|----------------|
| End-user | Accidentally clicking phishing links, losing devices |
| System administrator | Misconfiguring systems, abusing privileges |
| Developer | Accidentally committing secrets, introducing vulnerabilities |
| Finance user | Falling for BEC, processing fraudulent payments |

**Key insight**: Most internal incidents are **negligent** (accidental), not malicious.

### Partner Actors

Partners have some authorized access but are not employees:

* Managed service providers (MSPs)
* Third-party vendors with system access
* Business partners in data sharing relationships

**Key insight**: Supply chain attacks involving partners are a growing threat.

---

## 5. Action Categories — A Quick Reference

| Category | What It Covers | Example Varieties |
|----------|---------------|------------------|
| **Hacking** | Technical attacks against systems | Use of stolen credentials, SQLi, Brute force |
| **Malware** | Malicious software | Ransomware, Backdoor, Keylogger, Trojan |
| **Social Engineering** | Psychological manipulation | Phishing, Pretexting, BEC |
| **Misuse** | Misuse by authorized users | Privilege abuse, Data mishandling |
| **Physical** | In-person attacks | Theft, Skimming, Tampering |
| **Error** | Accidental incidents | Misconfiguration, Misdelivery, Loss |
| **Environmental** | Natural/physical events | Natural disaster, Power failure |

### The Most Important Insight About Actions

**Errors are real incidents.** A misconfigured S3 bucket that exposes 100,000 records to the public internet is just as much a data breach as an organized crime phishing attack.
VERIS treats them with equal seriousness.
Many security programs focus exclusively on malicious actors and miss the significant risk from unintentional actions.

---

## 6. Asset Categories — A Quick Reference

| Prefix | Category | Examples |
|--------|----------|---------|
| **S** | Server | Database (S-Database), Web app, Mail, File, Auth |
| **N** | Network | Router, Firewall, VPN concentrator, Switch |
| **U** | User Device | Desktop (U-Desktop), Laptop, Mobile phone |
| **P** | Person | End-user, Executive, Admin (P-Executive) |
| **M** | Media | USB drive, Hard disk, Documents |
| **T** | Kiosk/Terminal | ATM (T-ATM), POS terminal |

**Key insight**: The prefix letter (S, N, U, P, M, T) is used in the VERIS JSON to denote the asset category.
A full asset entry looks like `"S - Database"`.

---

## 7. Attribute Categories — The CIA Triad

VERIS applies the CIA triad to classify the impact on assets:

### Confidentiality
> Data was disclosed to or accessed by an unauthorized party.

When to record: When data was confirmed or suspected to have been viewed, copied, or exfiltrated.

Sub-fields:

* `data_disclosure`: Yes / No / Potentially / Unknown
* `data_total`: Number of records affected
* `data[]`: Array of data type + amount entries

Key data types: Personal (PII), Medical (PHI), Payment (PCI), Credentials, Classified, Bank, Internal

### Integrity
> Data or systems were modified or tampered with.

When to record: When files, configurations, code, or hardware were modified without authorization.

Sub-types: Data, Software installation, Hardware modification

### Availability
> Access to data or systems was disrupted.

When to record: When systems were taken offline, data was made inaccessible, or performance was significantly degraded.

Sub-types: Interruption, Encryption, Loss, Degradation

---

## 8. The VERIS Record: Minimal Structure

A minimal valid VERIS record requires:

```json
{
  "incident_id": "unique-uuid-here",
  "source_id": "your-org-id",
  "security_incident": "Confirmed",
  "actor": { "external": { "variety": ["Unknown"] } },
  "action": { "hacking": { "variety": ["Unknown"] } },
  "asset": { "assets": [{ "variety": "S - Unknown" }] },
  "attribute": { "confidentiality": { "data_disclosure": "Unknown" } }
}
```

While this is technically valid, a useful VERIS record includes timeline, victim industry, a summary, and more detailed 4A data.
The more complete the record, the more useful it is for analysis.

---

## 9. The VERIS Ecosystem

### VERIS Schema
The official JSON schema is maintained on GitHub:
`https://github.com/vz-risk/veris`

### VERIS Community Database (VCDB)
A public database of VERIS-encoded incidents from public sources:
`https://github.com/vz-risk/VCDB`

Contains thousands of records you can study, analyze, and contribute to.

### Verizon DBIR
Annual report based on VERIS-encoded data from Verizon investigations and partners:
`https://www.verizon.com/business/resources/reports/dbir/`

The DBIR is the authoritative source for industry-level incident patterns and statistics.

---

## 10. Quick Self-Check

Before moving to the next guide, make sure you can answer these questions:

1. What does VERIS stand for? What is its primary purpose?
1. Name the four dimensions of the 4A taxonomy and the question each answers.
1. What are the three main actor categories? Give an example of each.
1. What is the difference between Hacking and Malware as action categories?
1. What does the "T" prefix mean in an asset variety like "T - ATM"?
1. In what situation would you record a Confidentiality attribute?
1. What is the VCDB and how does it differ from the DBIR?

---

## Key Terms Glossary

| Term | Definition |
|------|-----------|
| **VERIS** | Vocabulary for Event Recording and Incident Sharing |
| **4A taxonomy** | The Actor-Action-Asset-Attribute classification framework |
| **Enumeration** | A fixed list of permitted values for a VERIS field |
| **Variety** | The specific sub-type within a VERIS category |
| **Vector** | The mechanism by which an action was carried out |
| **DBIR** | Data Breach Investigations Report by Verizon |
| **VCDB** | VERIS Community Database (public, crowd-sourced) |
| **Data breach** | An incident with confirmed unauthorized data disclosure |
| **Security incident** | Any event compromising CIA of an information asset |
| **CIA triad** | Confidentiality, Integrity, Availability — core security model |

---

## Next Steps

* Continue to **Guide 02: Classifying Incidents Using VERIS Taxonomy** to practice classification
* Review `reading.md` Section 3–7 for deeper coverage of each dimension
* Explore a real VCDB record: `https://github.com/vz-risk/VCDB/tree/master/data/json`

---

*Guide 01 | Session 11 | Security Operations Master Class | Digital4Security*
