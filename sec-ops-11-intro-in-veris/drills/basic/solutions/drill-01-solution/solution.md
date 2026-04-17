# Solution: Drill 01 (Basic) — VERIS Classification of 10 Incident Scenarios

**Level:** Basic

**Directory:** `drills/basic/solutions/drill-01-solution/`

---

## Scenario 1: The Cloud Bucket — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | Internal |
| Actor | Variety | System administrator / Developer (DevOps engineer) |
| Actor | Motive | Negligence (Convenience) |
| Action | Category | error |
| Action | Variety | Misconfiguration (publishing error) |
| Asset | Category | S |
| Asset | Variety | S - Database (cloud: Yes) |
| Attribute | Type | confidentiality |
| Attribute | Detail | Personal (emails, password hashes — credentials) |
| Breach? | Yes — 72,000 records publicly exposed |

**Key reasoning**: No malicious external actor.
This is an `error > misconfiguration` incident.
The data was publicly exposed for 18 days — `data_disclosure: "Yes"`.

---

## Scenario 2: The Phishing HR Manager — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | External |
| Actor | Variety | Organized crime (W-2 phishing for tax fraud) |
| Actor | Motive | Financial |
| Action | Category | social |
| Action | Variety | Phishing (email impersonation / BEC) |
| Asset | Category | P |
| Asset | Variety | P - End-user (HR manager) |
| Attribute | Type | confidentiality |
| Attribute | Detail | Personal (PII, W-2 tax records with SSNs) |
| Breach? | Yes — 3,200 employee records disclosed |

**Key reasoning**: The HR manager is the targeted Person asset who was manipulated.
This is Social Engineering > Phishing (or Pretexting).
The action is NOT Misuse — the HR manager was deceived, not complicit.

---

## Scenario 3: The Crypto Miner — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | Partner |
| Actor | Variety | (IT contractor) |
| Actor | Motive | Financial |
| Action | Category | misuse |
| Action | Variety | Unapproved software installation |
| Asset | Category | S |
| Asset | Variety | S - File / production servers (x12) |
| Attribute | Type | availability + integrity |
| Attribute | Detail | Degradation (Availability); Software installation (Integrity) |
| Breach? | No — no data disclosed |

**Key reasoning**: Partner actor (contractor).
Misuse of authorized access (not Malware).
No Confidentiality breach.

---

## Scenario 4: The ATM Compromise — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | External |
| Actor | Variety | Organized crime |
| Actor | Motive | Financial |
| Action | Category | malware |
| Action | Variety | RAM scraper / ATM malware |
| Asset | Category | T |
| Asset | Variety | T - ATM (x8) |
| Attribute | Type | confidentiality |
| Attribute | Detail | Payment (1,100 debit card numbers + PINs) |
| Breach? | Yes — PCI DSS reportable |

**Key reasoning**: ATM malware is Malware category.
Asset is T - ATM (Kiosk/Terminal).
Discovery was internal (routine maintenance).

---

## Scenario 5: The Brute Force Attack — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | External |
| Actor | Variety | Unknown (or Organized crime) |
| Actor | Motive | Unknown |
| Action | Category | hacking |
| Action | Variety | Brute force (credential stuffing) |
| Asset | Category | S |
| Asset | Variety | S - Authentication (student portal) |
| Attribute | Type | confidentiality |
| Attribute | Detail | Personal (student records — FERPA) |
| Breach? | Yes — 847 accounts accessed |

**Key reasoning**: Credential stuffing = Hacking > Brute force. 847 confirmed account accesses = Confidentiality breach.
FERPA notification required.

---

## Scenario 6: The Accidental Deletion — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | Internal |
| Actor | Variety | System administrator |
| Actor | Motive | Negligence |
| Action | Category | error |
| Action | Variety | Programming error / Omission |
| Asset | Category | S |
| Asset | Variety | S - Database |
| Attribute | Type | availability + integrity |
| Attribute | Detail | Loss (Availability); Data modification/deletion (Integrity) |
| Breach? | No — data destroyed, not disclosed |

**Key reasoning**: Error incident with no malicious actor.
Destruction ≠ Confidentiality breach.
No disclosure occurred.

---

## Scenario 7: The Vendor Backdoor — Solution

**This is a multi-actor supply chain incident.**

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor 1 | Type | External — Nation-state, Espionage |
| Actor 2 | Type | Partner — EHR vendor |
| Action | Category | malware |
| Action | Variety | Backdoor, Vector: Software update |
| Asset | Category | S |
| Asset | Variety | S - Database (EHR system) |
| Attribute | Type | confidentiality |
| Attribute | Detail | Medical (PHI) — data_disclosure: "Potentially" |
| Breach? | Potentially — 4 months of potential access |

**Key reasoning**: Two actors.
Nation-state motive = Espionage.
"Potentially" because access existed but exfiltration unconfirmed.
HIPAA risk assessment required.

---

## Scenario 8: The Lost Laptop — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | External |
| Actor | Variety | Unknown (opportunistic thief) |
| Actor | Motive | Unknown |
| Action | Category | physical |
| Action | Variety | Theft |
| Asset | Category | U |
| Asset | Variety | U - Laptop |
| Attribute | Type | confidentiality |
| Attribute | Detail | Internal data (prospect info) — data_disclosure: "Potentially" |
| Breach? | Potentially — unencrypted; no confirmed access |

**Key reasoning**: Physical > Theft.
"Potentially" because unencrypted but no access confirmed.
Encrypted laptop = `data_disclosure: "No"`.

---

## Scenario 9: The Social Media Oversharer — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | Internal |
| Actor | Variety | System administrator |
| Actor | Motive | Negligence |
| Action | Category | error |
| Action | Variety | Gaffe (accidental public disclosure) |
| Asset | Category | P |
| Asset | Variety | P - System administrator |
| Attribute | Type | confidentiality |
| Attribute | Detail | System/network configuration — data_disclosure: "Potentially" |
| Breach? | Potentially — public for 6 hours; no confirmed exploitation |

**Key reasoning**: Error > Gaffe (unintentional public disclosure).
System configuration is not PII; no typical breach notification obligations.

---

## Scenario 10: The Flood — Solution

| Dimension | Field | Answer |
|-----------|-------|--------|
| Actor | Type | None / N/A |
| Action | Category | environmental |
| Action | Variety | Water/flood damage |
| Asset | Category | S |
| Asset | Variety | S - Database, S - File (x5 systems) |
| Attribute | Type | availability |
| Attribute | Detail | Loss (permanent destruction) |
| Breach? | No — data destroyed, not disclosed |

**Key reasoning**: Environmental incident — no actor.
Availability: Loss (permanent).
No confidentiality breach — data was destroyed, not disclosed.

---

## Summary Score Guide

Award yourself 1 point per correctly identified dimension (Actor Type, Action Category, Asset prefix, Attribute type, Breach determination = 5 points per scenario).

* **45–50 points**: Expert — proceed to intermediate drills
* **35–44 points**: Proficient — review missed scenarios and retake
* **25–34 points**: Developing — re-read Guide 02 and retake
* **Below 25**: Foundational — review reading.md Sections 4–7, then Guides 01 and 02

---

*Solution — Drill 01 | Session 11 | Security Operations Master Class | Digital4Security*
