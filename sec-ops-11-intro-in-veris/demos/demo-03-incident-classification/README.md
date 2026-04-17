# Demo 03: Incident Classification with VERIS

## Overview

In this demo, students practice classifying security incidents using the VERIS 4-A framework.
A local web application presents incident scenarios (text descriptions of security events) and students select the correct Actor, Action, Asset, and Attribute categories.
The app provides immediate feedback and explains the correct VERIS coding.

## Learning Objectives

* Apply the VERIS 4-A framework to real-world incident descriptions
* Distinguish between different actor types, action varieties, and asset categories
* Recognize multi-step attacks in VERIS encoding (multiple actions)
* Understand when to use "Unknown" vs. specific values

## Prerequisites

* Docker installed and running
* Web browser

## Setup

```console
cd demos/demo-03-incident-classification
docker compose up --build
```

Open your browser at: http://localhost:5000

## Files

* `docker-compose.yml` — Flask app service
* `Dockerfile` — Python + Flask environment
* `app/app.py` — Flask web application
* `app/scenarios.json` — Incident scenarios with VERIS answers
* `app/templates/index.html` — Web UI

## Walk-through

### Scenario Set

The demo includes 5 incident scenarios:

**Scenario 1: The Phishing Breach**
> An employee received an email appearing to be from the IT department, asking them to reset their password. They clicked the link and entered their credentials on a fake login page. The attacker then used those credentials to access the HR database and download 8,000 employee records.

**Expected VERIS coding:**

* Actor: External / Organized crime
* Action: Social (Phishing) + Hacking (Use of stolen creds)
* Asset: S-Database, P-End-user
* Attribute: Confidentiality (Personal data, 8000 records)

**Scenario 2: The Misconfigured Bucket**
> A developer at an e-commerce company accidentally set an AWS S3 bucket to public while testing. The bucket contained 200,000 customer order records including names, addresses, and partial credit card numbers. The error was discovered 45 days later when a security researcher reported it.

**Expected VERIS coding:**

* Actor: Internal (Developer, negligent)
* Action: Error (Misconfiguration)
* Asset: S-Database (cloud-hosted)
* Attribute: Confidentiality (Personal + Financial data)

**Scenario 3: The Ransomware Attack**
> A ransomware email campaign targeted small businesses. An employee at an accounting firm opened an infected attachment. The malware encrypted all files on the company file server and three connected workstations. The attacker demanded payment. No data exfiltration was confirmed.

**Expected VERIS coding:**

* Actor: External / Organized crime
* Action: Social (Phishing) + Malware (Ransomware)
* Asset: S-File, U-Desktop
* Attribute: Availability (Extortion, encrypted files)

**Scenario 4: The Disgruntled Admin**
> A system administrator who had received a negative performance review used their privileged access to download the company's customer database and delete critical backups before resigning. The activity was detected during an exit review.

**Expected VERIS coding:**

* Actor: Internal (System admin, grudge)
* Action: Misuse (Privilege abuse, Data mishandling)
* Asset: S-Database, M-Backup
* Attribute: Confidentiality (disclosure) + Availability (deletion)

**Scenario 5: The Supply Chain Compromise**
> An IT service provider's remote management software was compromised by nation-state attackers. The attackers used the provider's access to deploy malicious updates to 50 of the provider's clients, including a government ministry.

**Expected VERIS coding:**

* Actor: External (Nation-state)
* Action: Hacking (Use of stolen creds/Exploit vuln) + Malware (Trojan)
* Asset: S-Other (update infrastructure), multiple customer assets
* Attribute: Integrity (Install code) + Confidentiality

### Step-by-Step Classification

For each scenario, follow this process:

1. **Read the scenario** carefully
1. **Identify the actor type**: Was this caused externally, by an insider, or a partner?
1. **List the actions**: Are multiple action types involved? (Phishing → Credential use is a two-step attack)
1. **Identify assets**: What systems and data types were accessed or affected?
1. **Determine attributes**: Was CIA confidentiality, integrity, or availability impacted? How?
1. **Note uncertainty**: What would you mark as "Unknown" due to limited information?

### Running the Classification App

The web app presents each scenario one at a time.
For each:

* Select the actor type from a dropdown
* Check boxes for action types
* Select asset varieties
* Check which CIA attributes were impacted
* Submit and see immediate feedback with explanation

### Interactive Discussion

After completing all scenarios, discuss:

1. Which scenarios were most ambiguous to classify?
1. When should you record multiple actor types?
1. How does VERIS handle the "supply chain" attack category?
1. Why is the "Error" action category important even though it's unintentional?

## Clean Up

```console
docker compose down
```
