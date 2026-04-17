# Drill 02 (Intermediate): Build a VERIS Incident Dataset

**Level:** Intermediate

**Estimated time:** 50 minutes

---

## Objective

Code a set of five real-world-style incident scenarios into VERIS JSON records, then write a Python script to load and analyze the resulting dataset.

---

## Background

In a real SOC, VERIS coding is done for every closed incident to enable trend analysis, metrics reporting, and benchmarking.
In this drill, you will simulate that workflow: receive incident reports, code them in VERIS, and build an analysis script.

---

## Scenarios to Code

### Scenario 1: E-Commerce Credential Stuffing

> An e-commerce platform experienced a wave of account takeovers over a weekend. Analysis showed attackers used a list of 2 million leaked username/password pairs from a previous breach at an unrelated company and tested them against the platform's login page using automated tools. Approximately 12,000 accounts were successfully accessed. Of these, about 1,800 had saved payment methods that were subsequently used for fraudulent purchases totaling €180,000. The attack was detected by the fraud prevention team when chargeback rates spiked on Monday morning. The credential stuffing began Saturday evening; detection occurred Monday morning (~36 hours later).

### Scenario 2: Insider Intellectual Property Theft

> A senior software engineer at a cybersecurity firm downloaded the source code for the company's flagship product (estimated value: €5M) over three days before resigning and taking a position at a direct competitor. The engineer used their normal developer access to the version control system. The downloads occurred during normal working hours and did not exceed daily volume thresholds. The activity was discovered during a routine quarterly DLP audit conducted two months after the engineer left.

### Scenario 3: Healthcare Ransomware

> A mid-sized hospital's radiology department was hit by ransomware. The initial infection vector was an email to an administrative assistant in radiology — the email contained a malicious Word document with macros enabled. The ransomware spread to six Windows servers including the PACS (Picture Archiving and Communication System) containing 890,000 patient imaging records. Clinical operations were disrupted for 11 days. The hospital paid the ransom (undisclosed amount) on day 7. Forensic analysis later confirmed no data was exfiltrated — only encrypted.

### Scenario 4: Cloud Misconfiguration with Data Exposure

> A SaaS company's DevOps team accidentally made an Elasticsearch cluster publicly accessible during a configuration migration. The cluster contained application logs with user activity data, including 340,000 user email addresses and hashed passwords. A security researcher found the exposed data using the Shodan search engine and notified the company. The cluster had been publicly accessible for 14 days. The company has no evidence of malicious access but cannot rule it out.

### Scenario 5: BEC (Business Email Compromise)

> An accounts payable employee at a manufacturing company received an email from what appeared to be their regular supplier requesting a change to their bank account details for future invoices. The employee updated the supplier's payment details in the ERP system without verifying the request via phone. Over the next month, four legitimate invoices totaling €220,000 were paid to the fraudulent account. The attack was discovered when the real supplier complained about unpaid invoices. The fraudulent email was sent from a spoofed domain that closely resembled the supplier's real domain.

---

## Your Tasks

### Part 1: VERIS Coding (60%)

For each scenario, produce a complete VERIS JSON record including:

* `schema_version`, `incident_id`, `summary`, `security_incident`, `confidence`
* `timeline` (all available fields)
* `victim` (industry, employee count estimate)
* `actor` (type, variety, motive)
* `action` (all applicable types with varieties and vectors)
* `asset` (all affected asset types)
* `attribute` (CIA with data varieties and amounts where stated)

### Part 2: Dataset Analysis Script (40%)

Write a Python script (`analyze.py`) that:

1. Loads all five VERIS JSON files from a directory
1. Prints a summary table:

   ```text
   Incident ID | Actor Type | Top Action | Data Disclosed | Records
   ------------|-----------|-----------|----------------|--------
   ...
```

1. Calculates and prints:
   * Total records exposed across all breaches
   * Average discovery time (in days)
   * Most common actor type
   * Most common action type

---

## Hints

* Each scenario has at least 2 action types — look for the attack chain
* Timeline values: convert all to consistent units for analysis
* Scenario 3: No data exfiltrated, but availability was heavily impacted — reflect this in attributes
* Scenario 5: This is financial fraud via social engineering — what action type maps to a spoofed email impersonating a supplier?
* For Part 2, iterate over `glob.glob('*.json')` to load files dynamically

---

## Deliverable

Five VERIS JSON files (`scenario-01.json` through `scenario-05.json`) and one `analyze.py` script.

See `solutions/drill-02-solution/` for the reference solution.
