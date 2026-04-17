# Demo 02: Threat Intelligence — STIX Objects and IOC Enrichment

## Overview

In this demo, we work with STIX 2.1 threat intelligence objects using Python and the `stix2` library.
Students will parse STIX bundles from a mock threat feed, extract IOCs (indicators of compromise), and enrich them against a local mock reputation service.
We also explore how TAXII collections work and how to push/pull intelligence between platforms.

## Learning Objectives

* Parse and create STIX 2.1 bundles containing Indicators, Threat Actors, and Malware objects
* Understand the relationship between STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs)
* Extract IP addresses, domains, and file hashes from a STIX feed
* Simulate IOC enrichment (check an IOC against a reputation database)
* Understand how TAXII servers serve STIX collections

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-02-threat-intelligence
docker compose up --build
```

The container includes Python with `stix2`, `taxii2-client`, and `requests`.

```console
docker compose run --rm threat-intel bash
```

## Files

* `docker-compose.yml` — Python environment container
* `Dockerfile` — Python 3.11 with stix2 library
* `data/threat_bundle.json` — sample STIX 2.1 bundle (APT campaign)
* `scripts/parse_stix.py` — parse bundle and extract IOCs
* `scripts/enrich_iocs.py` — enrich IOCs against mock reputation data
* `scripts/create_stix.py` — create a STIX report from scratch

## Walk-through

### Step 1: Examine the STIX Bundle

```console
cat /data/threat_bundle.json | python3 -m json.tool | head -80
```

The bundle contains:

* A **Threat Actor** object: APT-42
* A **Campaign** object: Operation CloudStrike
* **Malware** object: CloudLoader backdoor
* Multiple **Indicator** objects: IPs, domains, file hashes
* **Relationship** objects linking them

### Step 2: Parse the Bundle and Extract IOCs

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
[IP]     203.0.113.45       — C2 server
[IP]     198.51.100.12      — exfil endpoint
[DOMAIN] update.cdn-secure.net — malicious domain
[HASH]   d41d8cd98f00b204e9800998ecf8427e — CloudLoader dropper
[HASH]   5f4dcc3b5aa765d61d8327deb882cf99 — persistence binary
```

### Step 3: Enrich IOCs

```console
python3 /scripts/enrich_iocs.py
```

The script checks each IOC against a local mock reputation database:

```text
[203.0.113.45]     Score: 95/100 MALICIOUS — seen in 12 threat feeds
[198.51.100.12]    Score: 78/100 SUSPICIOUS — reported by 3 feeds
[update.cdn-secure.net] Score: 88/100 MALICIOUS — typosquat of cdn.net
[d41d8cd98...]     Score: 100/100 MALICIOUS — known ransomware hash
```

### Step 4: Create a STIX Report

```console
python3 /scripts/create_stix.py
```

This script creates a new STIX 2.1 bundle from scratch — simulating what an analyst would produce after investigating an incident.
It creates:

* An `Indicator` for a newly-discovered C2 IP
* A `Relationship` linking it to an existing `Malware` object
* An `AttackPattern` referencing MITRE ATT&CK T1071 (C2 over HTTP)
* A `Report` packaging all objects

The output JSON can be submitted to a MISP instance or TAXII server.

### Step 5: Understand TAXII

TAXII (Trusted Automated eXchange of Indicator Information) is the transport protocol for STIX.

Key concepts:

* **TAXII Server**: hosts Collections of STIX objects
* **Collection**: a named group of STIX objects (e.g., "APT-42 indicators")
* **GET /collections/{id}/objects** — pull STIX bundles
* **POST /collections/{id}/objects** — push new objects

Major public TAXII servers:

* MITRE ATT&CK: `https://attack-taxii.mitre.org/`
* Anomali Limo: public free TAXII feed
* MISP instances with TAXII module

## Cleanup

```console
docker compose down
```

## Key Takeaways

* STIX provides a standardised language for describing threats — not just IOC lists
* Relationships between objects tell the full story (actor → campaign → malware → indicators)
* TAXII enables automated machine-to-machine intelligence sharing
* Enrichment multiplies the value of raw IOCs by adding context and confidence scores
