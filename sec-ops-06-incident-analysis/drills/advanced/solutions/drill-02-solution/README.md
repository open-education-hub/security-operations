# Drill 02 Advanced Solution: Insider Threat Analysis

## Instructor Notes

This solution contains the expected analytical framework and findings.
The insider threat scenario is intentionally ambiguous — there is evidence for BOTH a legitimate researcher completing work AND a malicious insider.

The purpose is to teach analysts that insider threat investigations require RIGOROUS baseline comparison, not just "looks suspicious to me."

---

## Pre-Investigation Legal Framework — Solutions

### Legal Check 1 — AUP Authorization

The AUP clause ("employees acknowledge that systems may be monitored") provides a **limited** authorization for monitoring:

* It authorizes monitoring of *system activity* for security purposes
* It does NOT give unlimited investigative authority
* It does NOT authorize reading email content (typically requires a separate legal basis)
* Most jurisdictions (EU under GDPR, UK under RIPA, US under ECPA) have additional requirements

**Procedural requirements before investigation:**

* HR Director authorization in writing
* Legal Counsel briefed and approving investigation scope
* IT Director authorization for log access
* Document the legal basis and purpose
* Conduct the investigation on a need-to-know basis
* Brief only those who need to know (not Dr. Chen's direct manager yet)

### Legal Check 2 — Email Content Review

Reviewing email **metadata** (from, to, subject, timestamp, attachment name/size) is generally permissible under AUP with appropriate authorization.

Reviewing email **contents** requires additional considerations:

* **GDPR (EU):** Purpose limitation — reading personal emails of a departing employee may exceed the stated monitoring purpose
* **ECPA (US):** Work email on company systems has lower expectation of privacy, but review should be proportionate
* **Recommendation:** Do NOT read email contents until Legal Counsel explicitly authorizes it. Preserve the metadata. Disclose the existence of the emails to Legal and let them authorize the next step.

### Legal Check 3 — Trade Secret Legal Theories

If the investigation confirms Dr.
Chen exfiltrated proprietary research:

* **Defend Trade Secrets Act (DTSA)** (US) — federal civil and criminal claims
* **Uniform Trade Secrets Act (UTSA)** (state level, US) — civil claims
* **Computer Fraud and Abuse Act (CFAA)** (US) — if access exceeded authorization
* **Employment contract breach** — NDA, non-compete, IP assignment clauses
* **UK Trade Secrets Regulations 2018** (if applicable)

**Critical:** Existence of these claims depends on whether the research was properly documented as confidential/trade secret at the time it was created.

---

## Investigation Part 1 Solution: Baseline Analysis

### Expected Finding: Dr. Chen's access IS elevated, but not dramatically

Historical baseline: ~120-180 file accesses per day on compound database
Post-resignation: ~400-850 files per day
**This is 3-5x above baseline — statistically significant.**

**Critical nuance:** A researcher completing projects before leaving *might* access more files.
The question is whether the access pattern matches "completing work" (accessing files she authored or worked on) vs.
"acquiring data" (accessing files outside her research area).

---

## Investigation Part 2 Solution: DLP Alert Analysis

### DLP Alert 1 — 847 File Accesses

**Expected findings:**

* 623 of 847 files are in Dr. Chen's research area (Compounds K-O) — her normal work area
* **224 files are in Compounds A-J and P-Z** — outside her research area
* The 224 files outside her area represent a significant deviation
* Access was read-only for all files (no modifications)
* Access happened between 09:00-17:00 (normal hours)

**Assessment:** SUSPICIOUS (not BENIGN) — the out-of-area access has no legitimate work explanation

### DLP Alert 2 — Large Email Attachment

**Expected findings:**

* Attachment: `compound_library_export_2024_Q3.xlsx` (11.2 MB)
* Content: Compound library data — includes synthesis pathways and efficacy data
* Historical pattern: Dr. Chen has sent emails with <2 MB attachments to personal email, 4 times in the past year, but always during business hours and typically personal items (photos, personal files)
* This is the FIRST time a data file containing research content was sent externally

**Assessment:** CONFIRMED MALICIOUS INTENT — sending compound library data to personal email with no work justification

### DLP Alert 3 — 4.2 GB USB Copy

**Expected findings:**

* Files copied include:
  * Her personal work documents (presentations, notes) — LEGITIMATE
  * 3.8 GB of compound synthesis data from the shared drive — SUSPICIOUS
  * Tool/software licenses — borderline (she may claim she needs reference tools)
* The 3.8 GB of synthesis data has no legitimate personal work reason

**Assessment:** CONFIRMED MALICIOUS — copying synthesis data to personal USB

---

## Investigation Part 4 Solution: Evidence Matrix

```text
Alert  | File Type           | Classification | Volume | Baseline? | Pattern              | Conclusion
───────┼─────────────────────┼────────────────┼────────┼───────────┼──────────────────────┼──────────────────
DLP-1  | Compound database   | CONFIDENTIAL   | 847    | 3-5x      | Includes out-of-area | SUSPICIOUS
       | files               |                | files  | above     | access (224 files)   |
DLP-2  | Compound library    | TRADE SECRET   | 11.2MB | Not normal| First external send  | CONFIRMED MALICIOUS
       | Excel export        |                |        |           | of research data     |
DLP-3  | Synthesis data +    | TRADE SECRET   | 3.8GB  | No prior  | Bulk copy of data    | CONFIRMED MALICIOUS
       | personal files      | + personal     |        | USB data  | outside personal use |
```

---

## Legal Recommendation — Example Output

```text
INVESTIGATION REPORT — PRIVILEGED AND CONFIDENTIAL
Legal Hold Notice — Do Not Distribute

To: HR Director, General Counsel
From: Security Operations
Re: Dr. Linda Chen — Insider Threat Investigation
Classification: ATTORNEY-CLIENT PRIVILEGED (distribute to Legal Counsel only)

CONFIDENCE LEVEL: HIGH — Confirmed malicious data exfiltration

FINDINGS:

1. Email (DLP-2): Dr. Chen sent a confidential compound library database

   to her personal Gmail on 2024-11-13. This is the first time research
   data was sent to a personal account in her 4-year employment history.
   Metadata preserved; content access requires General Counsel authorization.

2. USB (DLP-3): Dr. Chen copied 3.8 GB of synthesis data to a personal
   USB drive on 2024-11-15. There is no legitimate work reason to copy
   proprietary synthesis data to personal storage.

3. Access Pattern (DLP-1): Dr. Chen accessed 224 files outside her
   research area on 2024-11-10 with no documented work reason.

LEGAL THEORIES:
   Primary: Trade secret misappropriation (DTSA) — research data
            qualifies as trade secret; appropriation for use at
            competitor is apparent purpose
   Secondary: Breach of employment contract (NDA + IP assignment clauses)

RECOMMENDED ACTIONS:

1. Immediately: Place legal hold on all Dr. Chen's company email,

   file access logs, and device data — preserve as litigation evidence
2. Immediately: Consult outside counsel with trade secret litigation experience
3. This week: Consider early termination of employment with rights expressly
   reserved for all legal claims
4. Before termination: Revoke access to all systems (do not warn in advance)
5. Consider: Law enforcement referral (FBI Trade Secret Unit)
6. Consider: Emergency injunction to prevent dissemination to competitor

EVIDENCE PRESERVATION:
All evidence has been logged with chain of custody as of this report.
SHA-256 hashes recorded for all log exports.
Evidence must NOT be modified or deleted pending legal proceedings.

NOTE ON OBJECTIVITY:
Investigator notes that the escalating manager had a prior HR dispute
with Dr. Chen. All findings are log-based with no reliance on managerial
characterizations. The evidence stands independently.
```

---

## Critical Discussion — Model Answers

### Question 1: Trade Secrets vs. Privacy Rights

The balance point:

* Employers have a legitimate interest in protecting trade secrets
* This interest is proportionate to the investigation scope
* Access to email **metadata** is proportionate and generally accepted
* Access to email **contents** requires specific legal basis
* The AUP provides baseline authorization; going further requires Legal Counsel

In this case, the metadata alone (file names, sizes, destinations) is sufficient to establish the case.
Reading email contents is not necessary and should only happen with Legal Counsel authorization.

### Question 2: Legitimate Access + Insider Threat

Legitimate access does NOT negate an insider threat investigation.
Most intellectual property theft is committed by employees with legitimate access who misuse it for unauthorized purposes.

The question is not "was she authorized to access?" but "was the access consistent with legitimate work?" Accessing 224 files outside her research area and sending research data to a personal email account are uses that exceed the legitimate purpose of her access.

### Question 3: Evidence Preservation for Prosecution

Required NOW (before any remediation or termination):

1. Formal legal hold — preserve ALL evidence, no normal retention/deletion
1. Forensic copy of her workstation disk (write-protected)
1. Export of all relevant email metadata and logs (hashed, chain of custody)
1. Export of DLP alert raw data
1. Engage outside counsel before any investigative steps
1. Do NOT confront Dr. Chen — investigation must remain covert until legal strategy is set
1. Contact law enforcement only after legal strategy determined (FBI / local LE)

### Question 4: False Accusation Obligations

If investigation concludes no malicious intent:

* Destroy any evidence collected beyond what's needed for security operations
* Do NOT share findings with those outside the investigation team
* Ensure no adverse employment action was taken based on suspicion
* Consider whether Dr. Chen should be notified that monitoring occurred (GDPR right to know)
* Document the investigation conclusion and close the case formally

### Question 5: Conflicted Escalation

The prior HR dispute means:

* The escalating manager cannot be in the investigation loop
* Investigation must be conducted independently, without input from that manager
* All findings must be log-based — no reliance on that manager's characterizations
* If the investigation finds no wrongdoing, the HR dispute context must be considered when determining whether the escalation was itself a form of workplace harassment
