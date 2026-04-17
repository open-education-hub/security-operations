# Demo 01: Incident Response Lifecycle Simulation

## Overview

This demo walks through a complete simulated ransomware incident lifecycle using TheHive for case management.
Students observe a P1 incident from initial alert to post-incident review, with all documentation shown in real-time.

## Learning Objectives

* Observe a P1 incident response from start to finish
* Understand how to use TheHive for IR case management
* See how evidence is documented and linked to cases
* Understand the IR communication flow during a live incident

## Setup

```console
docker compose up -d
# Access TheHive at http://localhost:9000 (admin/secret)
```

## Pre-loaded Scenario

The container automatically imports a complete ransomware case (INC-2024-1147) with:

* Pre-created case at P1 severity
* Multiple tasks representing each IR phase
* Observables (C2 IP, ransomware hash, affected hostnames)
* Timeline of notes from incident start to closure

## Demo Walkthrough

### Part 1: Detection (5 min)

Show the incoming alert view in TheHive.
Point out:

* Alert severity and timestamp
* Pre-populated observables (from SOAR auto-import)
* How the alert becomes a case

### Part 2: Containment (5 min)

Navigate to the "Containment" task:

* Show the network isolation note with timestamp
* Show memory acquisition hash logged as an observable
* Demonstrate how to add evidence artifacts

### Part 3: Communication Log (5 min)

Show the case timeline — every 30-minute executive update is logged as a case note.
Demonstrate the SBAR format used in escalation notes.

### Part 4: Post-Incident Review Template (5 min)

Show the completed PIR report template pre-filled in the case.
Demonstrate how action items are created as follow-up tasks.

## Discussion

* Why is every action timestamped?
* What happens if the IR manager isn't available?
* How would this change if the case involved GDPR-covered personal data?

## Teardown

```console
docker compose down -v
```
