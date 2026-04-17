# Guide 02: Threat Intelligence Feeds — Working with STIX and TAXII

**Level:** Basic

**Estimated time:** 40 minutes

**Prerequisites:** Reading for Session 13

---

## Objective

By the end of this guide, you will be able to:

* Describe the STIX 2.1 object types and their relationships
* Explain how TAXII collections work
* Identify sources of free and commercial threat intelligence
* Operationalise IOCs by blocking or monitoring them in a SOC

---

## 1. Why Threat Intelligence Matters

Raw security alerts tell you *what happened*.
Threat intelligence tells you *who is doing it, how, and why*.
With context, a SOC can:

* Prioritise alerts involving known threat actor TTPs
* Proactively hunt for indicators of an active campaign
* Communicate risk to management in business terms

---

## 2. The STIX 2.1 Object Model

STIX (Structured Threat Information eXpression) is a JSON-based language for describing cyber threats.

### Key STIX Domain Objects (SDOs)

| Type | Description | Example |
|------|-------------|---------|
| `indicator` | Detects malicious activity | IP address, file hash, domain |
| `threat-actor` | Group responsible for attacks | APT-29, FIN7 |
| `malware` | Malicious software | WannaCry, Emotet |
| `attack-pattern` | How attacks are carried out | T1059 Command-Line Interface |
| `campaign` | Coordinated attack activities | Operation Aurora |
| `course-of-action` | Recommended response | Block IP, apply patch |
| `report` | Collection of objects | Full threat report |

### STIX Relationships (SROs)

Objects connect via typed relationships:

```text
threat-actor  --[uses]-->           malware
campaign      --[attributed-to]-->  threat-actor
indicator     --[indicates]-->      malware
malware       --[uses]-->           attack-pattern
```

This means a STIX bundle can encode the full story: who did what, with what tools, via which techniques.

### STIX Indicator Patterns

```stix
# Match a specific IP address
[ipv4-addr:value = '203.0.113.45']

# Match a domain
[domain-name:value = 'malicious.example.com']

# Match a file hash
[file:hashes.'SHA-256' = 'abc123...']

# Compound pattern (AND — both must match)
[ipv4-addr:value = '203.0.113.45' AND network-traffic:dst_port = 443]
```

---

## 3. TAXII: The Transport Protocol

TAXII (Trusted Automated eXchange of Indicator Information) distributes STIX objects via HTTPS REST APIs.

### TAXII Architecture

```text
TAXII Server                TAXII Client (SIEM / TIP)
──────────────              ───────────────────────
Collections:                Polls for new objects
  - APT Indicators    ─────►  on schedule
  - Malware IOCs
  - Phishing URLs
```

### Key TAXII Endpoints

```text
GET  /taxii/                          — server discovery
GET  /taxii/collections/              — list available collections
GET  /taxii/collections/{id}/objects/ — get STIX objects
POST /taxii/collections/{id}/objects/ — push new objects
```

### Public TAXII Sources

* MITRE ATT&CK: `https://attack-taxii.mitre.org/`
* Anomali Limo: free public TAXII feed
* MISP instances with TAXII module enabled

---

## 4. Threat Intelligence Sources

### Free/Open-Source

| Source | Content | URL |
|--------|---------|-----|
| MITRE ATT&CK | TTP knowledge base | attack.mitre.org |
| AlienVault OTX | IOC feeds | otx.alienvault.com |
| Abuse.ch | Malware/botnet IOCs | abuse.ch |
| URLhaus | Malicious URLs | urlhaus.abuse.ch |
| Feodo Tracker | C2 IPs | feodotracker.abuse.ch |
| CISA KEV | Actively exploited CVEs | cisa.gov/known-exploited-vulnerabilities |

### Commercial Feeds

| Provider | Strengths |
|----------|-----------|
| Recorded Future | Breadth, dark web monitoring |
| Mandiant Advantage | APT-grade intelligence |
| CrowdStrike Falcon Intel | Nation-state threat actors |

---

## 5. Traffic Light Protocol (TLP)

TLP controls how intelligence is shared:

| Level | Meaning |
|-------|---------|
| TLP:CLEAR | No restriction, public |
| TLP:GREEN | Share within community |
| TLP:AMBER | Share within organisation only |
| TLP:RED | Do not share — named recipients only |

Every piece of shared intelligence should carry a TLP marking.

---

## 6. Operationalising Intelligence

### IOC-Based Detection (Tactical)

Import IOCs into your SIEM and security controls:

* **SIEM**: create lookup tables with malicious IPs, domains, file hashes
* **Firewall**: block known C2 IPs
* **DNS**: sinkhole malicious domains
* **Email gateway**: block known phishing domains

**Caution:** IOCs expire — set expiry dates (typically 30–90 days).
An IP used for C2 today may be a legitimate CDN node in 3 months.

### TTP-Based Detection (Strategic — Higher Value)

```text
Intelligence: APT-42 uses T1071.001 (C2 over HTTP)
Rule: Alert on HTTP beaconing — regular intervals, small payloads — to new/unknown IPs
```

TTP-based detection catches the *behaviour*, not a specific indicator.
This is much harder for attackers to evade by simply rotating IPs.

---

## Summary

STIX and TAXII provide a standardised, machine-readable way to share threat intelligence.
STIX describes threats with rich context — not just IP lists.
TAXII enables automated, scheduled distribution to SIEM and TIP platforms.
Effective intelligence use combines tactical IOC-based detection with strategic TTP-based hunting.
