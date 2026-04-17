# Drill 01 (Basic): VERIS Classification — 10 Incident Scenarios

**Level:** Basic

**Estimated time:** 30–45 minutes

**Directory:** `drills/basic/drill-01-veris-classification/`

**Prerequisites:** Reading.md, Guide 01, Guide 02

---

## Instructions

Classify each of the 10 incident scenarios below using the VERIS 4A taxonomy.
For each incident, fill in the classification table provided.

**Use the column headers below for every incident:**

| Dimension | Field | Your Answer |
|-----------|-------|-------------|
| Actor | Type | external / internal / partner |
| Actor | Variety | Organized crime / Nation-state / End-user / etc. |
| Actor | Motive | Financial / Espionage / Negligence / etc. |
| Action | Category | hacking / malware / social / misuse / physical / error / environmental |
| Action | Variety | Phishing / Ransomware / Misconfiguration / etc. |
| Asset | Category (prefix) | S / N / U / P / M / T |
| Asset | Variety | Database / Desktop / ATM / etc. |
| Attribute | Type | confidentiality / integrity / availability |
| Attribute | Detail | Data type or sub-type |
| Breach? | Yes/No/Potentially | |

---

## Scenario 1: The Cloud Bucket

A startup's DevOps engineer created an S3 bucket containing the company's entire customer database for testing purposes.
They accidentally made the bucket publicly readable.
A security researcher discovered the exposed bucket 18 days later and notified the company.
The bucket contained 72,000 customer records including emails and password hashes.

*Classify this incident.*

---

## Scenario 2: The Phishing HR Manager

A human resources manager received an email that appeared to be from the company's CEO, asking her to urgently provide a list of all employee W-2 forms and salary data.
She compiled and emailed the data.
The email was from an impersonator, not the real CEO. 3,200 employee tax records were disclosed.

*Classify this incident.*

---

## Scenario 3: The Crypto Miner

An IT contractor with remote access to a manufacturing company's servers installed a cryptocurrency mining application on 12 production servers without authorization.
The servers' performance degraded significantly.
The issue was discovered 2 weeks later during a performance review.
No data was accessed.

*Classify this incident.*

---

## Scenario 4: The ATM Compromise

Malware was discovered on 8 ATMs operated by a regional bank.
The malware, a known ATM cash-out variant, logged card data from each transaction.
Analysis revealed 1,100 debit card numbers and PINs were captured over 3 weeks before discovery during a routine ATM maintenance check.

*Classify this incident.*

---

## Scenario 5: The Brute Force Attack

A university's student portal was subjected to a credential stuffing attack using 500,000 username/password combinations harvested from other breaches.
The attack succeeded in accessing 847 accounts.
Attackers viewed grade records and personal information for those students.
Discovery was made when students reported being locked out.

*Classify this incident.*

---

## Scenario 6: The Accidental Deletion

A database administrator was performing maintenance on a production financial database late at night.
Due to a syntax error in a script, they accidentally deleted the entire transaction history table for the past 6 months.
The data was unrecoverable from backups (backups were discovered to be corrupted).
No external party was involved.

*Classify this incident.*

---

## Scenario 7: The Vendor Backdoor

A major audit of a healthcare organization's systems revealed a backdoor in an EHR (Electronic Health Records) software update deployed 4 months earlier.
The vendor had not disclosed the backdoor and it appeared to be deliberate (not a coding error).
Investigation linked the backdoor to a nation-state actor that had compromised the vendor.
Patient records may have been accessible for 4 months.

*Classify this incident.
Note: Who are the actors here?*

---

## Scenario 8: The Lost Laptop

A sales representative's unencrypted laptop was stolen from their car at a restaurant.
The laptop contained a spreadsheet with contact information and deal values for 450 prospects.
The theft was reported to HR immediately.
No evidence of access was found, but the data was unencrypted.

*Classify this incident.*

---

## Scenario 9: The Social Media Oversharer

A network engineer posted a screenshot to their personal social media account showing their work environment.
The screenshot accidentally revealed the IP addressing scheme, VLAN structure, and a partial SSH private key.
The post was discovered by a security team member 6 hours later.
No confirmed exploitation was found.

*Classify this incident.*

---

## Scenario 10: The Flood

A major storm caused flooding in the basement of a hospital's data center.
Three storage arrays and two servers were destroyed before staff could power them down safely.
Patient records stored on the affected arrays were unrecoverable.
Backup systems located in the same facility were also damaged.

*Classify this incident.*

---

## Submission

After completing your classifications, compare your answers with the solution in:
`drills/basic/solutions/drill-01-solution/solution.md`

Focus especially on any scenarios where you were uncertain.
The solution includes detailed explanations of each classification decision.

---

*Drill 01 | Session 11 | Security Operations Master Class | Digital4Security*
