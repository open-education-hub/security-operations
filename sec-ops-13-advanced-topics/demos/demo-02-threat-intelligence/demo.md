# Demo 02: Threat Intelligence — STIX Objects and IOC Enrichment

**Estimated time:** 35 minutes

---

## Overview

Work with STIX 2.1 threat intelligence objects using Python and the `stix2` library.
You will parse STIX bundles from a mock threat feed, extract IOCs, enrich them against a local mock reputation service, and create a new STIX report from scratch.

---

## Learning Objectives

* Parse and create STIX 2.1 bundles with Indicators, Threat Actors, and Malware objects
* Understand STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs)
* Extract IP addresses, domains, and file hashes from a STIX feed
* Simulate IOC enrichment against a reputation database
* Understand how TAXII servers serve STIX collections

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-02-threat-intelligence
docker compose up --build
docker compose run --rm threat-intel bash
```

The container includes Python with `stix2`, `taxii2-client`, and `requests`.

---

## Step 1: Examine the STIX Bundle

```console
python3 -m json.tool /data/threat_bundle.json | head -80
```

The bundle contains:

* **Threat Actor:** APT-42
* **Campaign:** Operation CloudStrike
* **Malware:** CloudLoader backdoor
* **Indicators:** IPs, domains, file hashes
* **Relationships:** linking all objects together

---

## Step 2: Parse the Bundle and Extract IOCs

```console
python3 /scripts/parse_stix.py
```

Expected output:

```text
=== STIX Bundle Summary ===
Threat Actor: APT-42 (motivation: espionage)
Campaign: Operation CloudStrike (2024-01-15 to present)
Malware: CloudLoader (backdoor, persistence)

=== Indicators (IOCs) ===
[IP]     203.0.113.45          — C2 server
[IP]     198.51.100.12         — exfil endpoint
[DOMAIN] update.cdn-secure.net — malicious domain
[HASH]   d41d8cd98f00b204e...  — CloudLoader dropper
[HASH]   5f4dcc3b5aa765d6...   — persistence binary
```

Notice the **relationships**: the indicators are not just a list — they are explicitly linked to the campaign and malware, telling the full story.

---

## Step 3: Enrich IOCs Against a Reputation Database

```console
python3 /scripts/enrich_iocs.py
```

Expected output:

```text
[203.0.113.45]          Score: 95/100 MALICIOUS — seen in 12 threat feeds
[198.51.100.12]         Score: 78/100 SUSPICIOUS — reported by 3 feeds
[update.cdn-secure.net] Score: 88/100 MALICIOUS — typosquat of cdn.net
[d41d8cd98f...]         Score: 100/100 MALICIOUS — known ransomware hash
```

Enrichment transforms raw IOCs into actionable intelligence with context and confidence scores.
A score of 78 may warrant monitoring rather than immediate blocking.

---

## Step 4: Create a New STIX Report

```console
python3 /scripts/create_stix.py
```

This script creates a new STIX 2.1 bundle simulating what an analyst produces after investigating an incident:

* An `Indicator` for a newly-discovered C2 IP
* A `Relationship` linking it to an existing `Malware` object
* An `AttackPattern` referencing MITRE ATT&CK T1071 (C2 over HTTP)
* A `Report` packaging all objects

The output JSON can be submitted to a MISP instance or TAXII server for sharing with your sector ISAC.

---

## Step 5: Understand TAXII Collection Structure

TAXII is the transport protocol for STIX.
Key endpoints:

```text
GET  /taxii/                                — server discovery
GET  /taxii/collections/                    — list available collections
GET  /taxii/collections/{id}/objects/       — pull all STIX objects
POST /taxii/collections/{id}/objects/       — push new objects
```

Major public TAXII servers:

* MITRE ATT&CK: `https://attack-taxii.mitre.org/`
* Anomali Limo: public free feed
* MISP instances with TAXII module

---

## Discussion Points

1. **STIX is more than an IOC list**: Relationships between objects encode the full story — who (threat actor), what (malware), how (attack patterns), and where (indicators).

1. **TAXII enables automation**: SIEM/TIP platforms can automatically poll TAXII collections every hour, keeping your indicator lists current without manual work.

1. **Enrichment multiplies IOC value**: A raw IP address is low value. That same IP linked to APT-42's CloudStrike campaign with 95/100 reputation score is high value — context drives prioritisation.

1. **IOCs expire**: An IP used as C2 today may be a legitimate CDN endpoint in 3 months. Always set expiry dates when importing IOCs.

---

## Clean Up

```console
docker compose down
```
