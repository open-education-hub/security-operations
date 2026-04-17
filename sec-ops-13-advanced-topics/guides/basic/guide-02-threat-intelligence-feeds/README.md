# Guide 02: Threat Intelligence Feeds — Working with STIX and TAXII

## Overview

This guide explains how threat intelligence is structured, shared, and consumed in a modern SOC.
You will learn the STIX 2.1 object model, how TAXII servers distribute intelligence, and how to operationalise threat indicators in your SIEM and firewall.

## Learning Objectives

After completing this guide you will be able to:

* Describe the STIX 2.1 object types and their relationships
* Explain how TAXII collections work
* Identify sources of free and commercial threat intelligence
* Operationalise IOCs (indicators of compromise) by blocking or monitoring them

## Estimated Time

40 minutes

---

## 1. Why Threat Intelligence Matters

Raw security alerts tell you *what happened*.
Threat intelligence tells you *who is doing it, how, and why*.
With context, your SOC can:

* Prioritise alerts involving known threat actor TTPs
* Proactively hunt for indicators of an active campaign
* Communicate risk to management in business terms
* Share findings with peers to protect the wider community

---

## 2. The STIX 2.1 Object Model

STIX (Structured Threat Information eXpression) is a JSON-based language for describing cyber threats.
Every piece of intelligence is a STIX object.

### 2.1 STIX Domain Objects (SDOs) — Key Types

| Type | Description | Example |
|------|-------------|---------|
| `indicator` | A pattern that detects malicious activity | IP address, file hash, domain |
| `threat-actor` | A person/group responsible for attacks | APT-29, FIN7 |
| `malware` | Malicious software | WannaCry, Emotet |
| `attack-pattern` | How the attack is carried out | T1059 (Command-Line Interface) |
| `campaign` | Coordinated set of activities | Operation Aurora |
| `course-of-action` | Recommended response or mitigation | Block IP, apply patch |
| `report` | Collection of objects into a report | Threat report PDF equivalent |
| `vulnerability` | A weakness (CVE) | CVE-2023-12345 |

### 2.2 STIX Relationship Objects (SROs)

Objects are connected with typed relationships:

```text
threat-actor --[uses]--> malware
campaign --[attributed-to]--> threat-actor
indicator --[indicates]--> malware
malware --[uses]--> attack-pattern
```

This relational model means a single STIX bundle can encode the full story: who did what, with what tools, via which techniques.

### 2.3 STIX Indicator Patterns

Indicators use a pattern language to describe what to match:

```stix
# Match a specific IP address
[ipv4-addr:value = '203.0.113.45']

# Match a domain
[domain-name:value = 'malicious.example.com']

# Match a file hash
[file:hashes.'SHA-256' = 'abc123...']

# Match an email subject (phishing indicator)
[email-message:subject = 'Urgent: Invoice #INV-2024-001']

# Compound pattern (AND)
[ipv4-addr:value = '203.0.113.45' AND network-traffic:dst_port = 443]
```

---

## 3. TAXII: The Transport Layer

TAXII (Trusted Automated eXchange of Indicator Information) is the HTTP-based protocol for distributing STIX objects.

### 3.1 TAXII Architecture

```text
┌──────────────────┐         ┌──────────────────┐
│   TAXII Server   │◄────────│  TAXII Client    │
│  (Intelligence   │  REST   │  (Your SIEM /    │
│    Provider)     │  over   │   TIP platform)  │
│                  │  HTTPS  │                  │
│  Collections:    │         │  Polls for new   │
│  - APT Indicators│────────►│  objects on      │
│  - Malware IOCs  │         │  schedule        │
│  - Phishing URLs │         │                  │
└──────────────────┘         └──────────────────┘
```

### 3.2 Key TAXII Endpoints

```text
GET  /taxii/                          — discovery
GET  /taxii/collections/              — list collections
GET  /taxii/collections/{id}/objects/ — get STIX objects
POST /taxii/collections/{id}/objects/ — push new objects
```

### 3.3 Authentication

TAXII servers can use:

* API keys (most common for free feeds)
* OAuth 2.0 (enterprise)
* Certificate-based (government/ISAC)

---

## 4. Threat Intelligence Sources

### 4.1 Free Open-Source Feeds

| Source | Type | URL |
|--------|------|-----|
| MITRE ATT&CK | TTP knowledge base | attack.mitre.org |
| MISP Project | Platform + feeds | misp-project.org |
| AlienVault OTX | IOC feeds | otx.alienvault.com |
| Abuse.ch | Malware/botnet IOCs | abuse.ch |
| URLhaus | Malicious URLs | urlhaus.abuse.ch |
| Feodo Tracker | C2 IPs | feodotracker.abuse.ch |
| PhishTank | Phishing URLs | phishtank.org |
| CISA KEV | Exploited vulnerabilities | cisa.gov/known-exploited-vulnerabilities |

### 4.2 Paid / Commercial Feeds

| Provider | Strengths |
|----------|-----------|
| Recorded Future | Breadth, dark web monitoring |
| Mandiant Advantage | APT-grade intelligence |
| CrowdStrike Falcon Intel | Nation-state threat actors |
| Palo Alto Unit 42 | Malware analysis |
| Secureworks CTU | Incident-derived intelligence |

### 4.3 ISACs (Information Sharing and Analysis Centers)

Sector-specific sharing organisations:

* **FS-ISAC** — Financial services
* **H-ISAC** — Healthcare
* **E-ISAC** — Energy
* **IT-ISAC** — Technology
* **EU-CERT** — European coordination

ISACs use the Traffic Light Protocol (TLP) to label sharing restrictions.

---

## 5. Traffic Light Protocol (TLP)

TLP is a simple four-level marking for controlling intelligence sharing:

| TLP Level | Colour | Meaning |
|-----------|--------|---------|
| TLP:CLEAR | White | No restriction, public |
| TLP:GREEN | Green | Share within community |
| TLP:AMBER | Amber | Share within organisation |
| TLP:AMBER+STRICT | Amber+Strict | Share only within organisation, no vendors |
| TLP:RED | Red | Do not share — recipient only |

Every piece of shared intelligence should have a TLP marking.

---

## 6. Operationalising Intelligence

Receiving intelligence is only useful if you act on it.

### 6.1 IOC-Based Detection (Tactical)

Import IOCs into your SIEM and firewall:

* **SIEM**: create lookup tables with malicious IPs, domains, hashes
* **Firewall**: block known C2 IPs
* **DNS**: sinkhole malicious domains
* **Email gateway**: block known phishing domains

Considerations:

* IOCs expire — an IP may be repurposed for legitimate use after 30 days
* Set expiry dates on IOC imports
* False positives from shared CDN IPs are common — validate before blocking

### 6.2 TTP-Based Detection (Strategic)

Higher-value but harder to implement.
Map ATT&CK techniques to SIEM detection rules:

```text
Indicator: APT-42 uses T1071.001 (C2 over HTTP)
Rule: Alert on HTTP beaconing (regular intervals, small payloads) to new/unknown IPs
```

This detects the *behaviour*, not a specific IP — much harder for attackers to evade.

### 6.3 Threat Intelligence Platform (TIP)

A TIP (e.g., MISP, OpenCTI, ThreatConnect) centralises intelligence management:

* Ingests feeds automatically
* Deduplicates and correlates objects
* Exports IOCs to SIEM/firewall
* Tracks investigation and analyst notes

---

## Summary

STIX and TAXII provide a standardised, machine-readable way to share threat intelligence.
STIX describes threats in rich detail (not just IOC lists) with relationships between actors, campaigns, malware, and indicators.
TAXII enables automated, scheduled distribution.
Effective use of threat intelligence requires both tactical IOC-based detection and strategic TTP-based hunting.
