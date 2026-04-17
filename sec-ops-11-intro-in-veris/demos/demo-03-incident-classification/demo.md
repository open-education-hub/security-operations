# Demo 03 — Incident Classification with VERIS

**Duration:** 20 minutes

**Format:** Docker-based web application

**Difficulty:** Beginner

---

## Overview

In this demo, a local web application presents incident scenarios (text descriptions of security events) and you select the correct Actor, Action, Asset, and Attribute categories.
The app provides immediate feedback and explains the correct VERIS coding.

---

## Learning Objectives

* Apply the VERIS 4-A framework to real-world incident descriptions
* Distinguish between different actor types, action varieties, and asset categories
* Recognize multi-step attacks in VERIS encoding (multiple actions)
* Understand when to use "Unknown" vs. specific values

---

## Setup

```console
cd demos/demo-03-incident-classification
docker compose up --build
```

Open your browser at: http://localhost:5000

---

## Walk-through

### The 5 Scenarios

The demo includes 5 incident scenarios to classify:

**Scenario 1: The Phishing Breach**
> An employee received an email appearing to be from the IT department, asking them to reset their password. They clicked the link and entered their credentials on a fake login page. The attacker then used those credentials to access the HR database and download 8,000 employee records.

Expected VERIS coding:

* Actor: External / Organized crime
* Action: Social (Phishing) + Hacking (Use of stolen creds)
* Asset: S-Database, P-End-user
* Attribute: Confidentiality — Personal data, 8,000 records

---

**Scenario 2: The Misconfigured Bucket**
> A developer at an e-commerce company accidentally set an AWS S3 bucket to public while testing. The bucket contained 200,000 customer order records including names, addresses, and partial credit card numbers. The error was discovered 45 days later when a security researcher reported it.

Expected VERIS coding:

* Actor: Internal (Developer, negligent)
* Action: Error (Misconfiguration)
* Asset: S-Database (cloud-hosted)
* Attribute: Confidentiality — Personal + Financial data

---

**Scenario 3: The Ransomware Attack**
> A ransomware email campaign targeted small businesses. An employee at an accounting firm opened an infected attachment. The malware encrypted all files on the company file server and three connected workstations. No data exfiltration was confirmed.

Expected VERIS coding:

* Actor: External / Organized crime
* Action: Social (Phishing) + Malware (Ransomware)
* Asset: S-File, U-Desktop
* Attribute: Availability (Extortion, encrypted files)

---

**Scenario 4: The Disgruntled Admin**
> A system administrator who had received a negative performance review used their privileged access to download the company's customer database and delete critical backups before resigning. The activity was detected during an exit review.

Expected VERIS coding:

* Actor: Internal (System admin, grudge)
* Action: Misuse (Privilege abuse, Data mishandling)
* Asset: S-Database, M-Backup
* Attribute: Confidentiality (disclosure) + Availability (deletion)

---

**Scenario 5: The Supply Chain Compromise**
> An IT service provider's remote management software was compromised by nation-state attackers. The attackers used the provider's access to deploy malicious updates to 50 of the provider's clients, including a government ministry.

Expected VERIS coding:

* Actor: External (Nation-state)
* Action: Hacking (Use of stolen creds/Exploit vuln) + Malware (Trojan)
* Asset: S-Other (update infrastructure), multiple customer assets
* Attribute: Integrity (Install code) + Confidentiality

---

### Step-by-Step Classification Process

For each scenario, follow this process:

1. **Read the scenario** carefully
1. **Identify the actor type:** Was this caused externally, by an insider, or a partner?
1. **List the actions:** Are multiple action types involved? (Phishing → Credential use is a two-step attack)
1. **Identify assets:** What systems and data types were accessed or affected?
1. **Determine attributes:** Was CIA confidentiality, integrity, or availability impacted? How?
1. **Note uncertainty:** What would you mark as "Unknown" due to limited information?

---

### Interactive Discussion

After completing all scenarios, discuss:

1. Which scenarios were most ambiguous to classify?
1. When should you record multiple actor types?
1. How does VERIS handle the "supply chain" attack category?
1. Why is the "Error" action category important even though it's unintentional?

---

## Clean Up

```console
docker compose down
```
