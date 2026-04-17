# Drill 01 (Advanced) — Full SOAR Integration

## Scenario

**AeroFreight Europe GmbH** is a logistics and air freight company based in Frankfurt.
They operate 24×7 (aircraft don't stop for weekends).
They have:

* 8-person SOC running 3 shifts
* Splunk SIEM (500,000 events/day, 1,200 alerts/day)
* Shuffle SOAR (recently deployed, basic workflows only)
* CrowdStrike EDR on 800 endpoints
* Cisco ASA perimeter firewall
* Microsoft 365 / Azure AD
* ServiceNow for ticketing
* TheHive for security incident management
* MISP for threat intelligence

They have recently experienced a serious incident: a business email compromise (BEC) attack resulted in a fraudulent wire transfer of €1.2M.
Post-incident review found:

* The SOC received 3 alerts that were relevant but not correlated
* Each alert was handled in isolation as a false positive
* No playbook existed for BEC scenarios
* Mean time to detect: 72 hours (the wire transfer was already processed)

Your task is to design and implement a comprehensive BEC detection and response SOAR integration.

---

## Your Tasks

### Task 1: Root Cause Analysis (20 points)

Based on the incident description, perform a root cause analysis of why three relevant alerts were not correlated and the BEC was not detected.

Your analysis must:

* Identify at least 4 specific root causes
* Classify each as: People, Process, or Technology issue
* Propose a specific remediation for each
* Identify which MITRE ATT&CK techniques were likely used in a BEC attack

### Task 2: BEC Detection Architecture (25 points)

Design a detection architecture specifically for Business Email Compromise.
Your design must include:

1. Data sources to monitor (minimum 5)
1. Detection rules (minimum 4) — write them as pseudocode or in Sigma format
1. Correlation rule that combines signals into a BEC alert
1. How your architecture would have detected the AeroFreight incident

For the correlation rule, define:

* Time window
* Minimum signal count
* Score weighting
* Threshold for alert generation

### Task 3: BEC Response Playbook (40 points)

Design and implement a full BEC response playbook.
Your playbook must handle the following distinct BEC scenarios:

* **Scenario A**: Fraudulent email instruction detected (before payment)
* **Scenario B**: Fraudulent payment processed (after the fact)
* **Scenario C**: Account takeover enabling BEC (attacker inside email system)

For each scenario:

1. Write the playbook in Python (using mock integrations from the demos)
1. Include automated enrichment steps
1. Include appropriate human approval gates
1. Include regulatory/legal notification triggers (NIS2 for critical infrastructure, GDPR for personal data exposure)
1. Include rollback/recovery steps

### Task 4: Metrics and Detection Gap Analysis (15 points)

After implementing the BEC playbook:

1. Define 5 KPIs specific to BEC detection and response
1. Identify 3 other alert types that would benefit from cross-alert correlation (not just individual alert automation)
1. Design a correlation framework that could catch multi-stage attacks even when individual alerts appear benign

---

## Context: BEC Attack Kill Chain

For reference, a typical BEC attack follows this pattern:

```text
1. Initial Compromise

   - Phishing email → credential harvest
   - OR password spray on O365/Azure AD

2. Reconnaissance
   - Attacker reads emails to understand payment processes
   - Identifies finance team members and their roles
   - Identifies pending transactions

3. Lateral Movement (within email)
   - Sets up inbox rules to hide replies
   - Registers lookalike domain for impersonation

4. Execution
   - Sends fraudulent payment instruction email
   - Impersonates CEO/CFO or vendor
   - Requests urgent wire transfer change

5. Exfiltration (money)
   - Finance team processes payment to attacker's account
   - Attacker moves money quickly

6. Cover Tracks
   - Deletes sent emails, inbox rules
```

---

## Technical Requirements

* Python 3 implementation (mock integrations acceptable)
* Must handle at least one async operation (e.g., waiting for API response)
* Include structured logging (JSON format)
* Include a test mode that simulates all API calls
* Document all decision thresholds with justification

## Hints

* BEC is notoriously hard to detect because it often involves legitimate accounts and no malware
* The key signals are behavioral anomalies: unusual inbox rules, new email forwarding, logins from new locations, accessing executive email
* M365 Unified Audit Logs are your best friend for BEC detection
* A "New inbox rule created" alert alone is a false positive — a CEO reading their email from a new country + new inbox rule + finance team query = very suspicious
* Consider using graph analysis: if an attacker reads executive emails, then emails finance pretending to be the executive, you can detect the "impersonation chain"
* The €1.2M loss is a reportable incident under German banking regulations (BaFin) and potentially NIS2
