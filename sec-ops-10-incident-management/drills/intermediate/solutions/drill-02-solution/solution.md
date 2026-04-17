# Solution: Drill 02 (Intermediate) — GDPR Breach Notification Drafting

This solution provides model answers for all three scenarios.
For each task, the rationale is as important as the answer — regulators assess both *what* you notified and *whether* your thinking is correct.

---

## Scenario A: PrivaMed Clinic — Healthcare Phishing Attack

### Task A1: Notification Deadline

**72-hour clock calculation:**

* Breach confirmed: Wednesday, 6 November at **14:20 local time (Warsaw = CET = UTC+1)**
* 14:20 CET = **13:20 UTC**
* 72 hours later: **Saturday, 9 November at 13:20 UTC** (14:20 Warsaw time)

**Should PrivaMed file even if investigation is not complete?**

**Yes — absolutely.** GDPR Art. 33.4 explicitly allows a staged notification: if all information is not available within 72 hours, the controller should notify with the information available and provide a note that "further information will follow." It is better to file an incomplete notification on time than to file a complete notification late.
UODO will accept updates.
Missing the 72-hour deadline without justification is a direct regulatory violation that exposes PrivaMed to fines.

The 72-hour clock starts at *awareness of a likely breach*, not when the investigation is complete.

---

### Task A2: Individual Risk Assessment

| Data Category | Risk Level | Justification |
|--------------|------------|---------------|
| Name + date of birth | Medium | Alone, low risk. Combined with other data in this breach, elevates identification precision |
| National ID (PESEL) | **High** | PESEL is a unique government identifier enabling identity theft, fraudulent credit applications, and impersonation of the individual with public authorities |
| Medical diagnosis codes | **High** | Special category data under GDPR Art. 9. Exposure risks: employment discrimination, insurance denial, stigmatization, serious psychological harm to individuals |
| Appointment history | Medium-High | Reveals that the individual is a patient at this clinic; in combination with diagnosis codes, highly sensitive; reveals health-seeking behavior |

**Does Article 34 (individual notification) apply?**

**Yes — individual notification is required.** The combination of national ID numbers and medical diagnosis codes for 847 patients constitutes a high risk to the rights and freedoms of those individuals.
Specifically:

* **PESEL** creates a direct risk of identity theft and financial fraud — a concrete, material harm to individuals
* **Medical diagnosis codes** are special category data under Art. 9 — their exposure carries potential discrimination risk and psychological harm
* There is no encryption or other measure that makes the data unintelligible (it was accessed in plaintext via the PMS)
* The "subsequent measures" exception does not apply — the attacker had a 25-minute session and the data may already have been copied or shared

PrivaMed must notify all 847 affected patients under Article 34, in plain language, without undue delay.

---

### Task A3: Draft Article 33 Notification to UODO

```text
NOTIFICATION OF PERSONAL DATA BREACH
To: Urząd Ochrony Danych Osobowych (UODO)
From: PrivaMed Clinic S.A., Warsaw
Date: [Within 72 hours of 14:20, 6 November]
Reference: Art. 33 GDPR

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. NATURE OF THE BREACH

On Wednesday, 6 November, a healthcare coordinator at PrivaMed Clinic S.A. (Warsaw)
received a phishing email and provided their login credentials to an attacker via
a fraudulent login page. The attacker used the harvested credentials to access the
Clinic's Patient Management System (PMS) from approximately 14:22 to 14:47 on the
same date (approximately 25 minutes). The breach type is unauthorized access to a
healthcare information system resulting in potential unauthorized disclosure of
patient personal data including special category health data.

2. CATEGORIES AND NUMBER OF DATA SUBJECTS AFFECTED

The breach affects approximately 847 patients of PrivaMed Clinic S.A. whose records
were accessible within the Patient Management System during the unauthorized session.
Affected data subjects are adult and minor patients who attended the clinic.

3. CATEGORIES AND NUMBER OF PERSONAL DATA RECORDS

The following categories of personal data were potentially accessed:
- Patient full name
- Date of birth
- National identification number (PESEL)
- Medical diagnosis codes (ICD-10)
- Appointment history

The total number of patient records within the attacker's access scope is 847. Each
record contains all five categories listed above. Medical diagnosis codes constitute
special category data under GDPR Article 9(1). No financial payment data was stored
in the PMS system.

4. DATA PROTECTION OFFICER CONTACT DETAILS

Dr. Anna Wiśniewska
Data Protection Officer, PrivaMed Clinic S.A.
Email: dpo@privamedclinic.pl
Telephone: +48 22 555 0100

5. LIKELY CONSEQUENCES OF THE BREACH

The unauthorized access to patient records containing national identification numbers
and medical diagnosis codes creates a significant risk of harm to affected individuals,
including: identity theft and financial fraud facilitated by PESEL numbers;
discrimination in employment or insurance based on disclosed health conditions;
psychological harm from the unwanted disclosure of sensitive medical information;
and potential stigmatization for individuals with stigmatized diagnoses. The attacker's
session showed read queries; exfiltration cannot be confirmed or excluded given the
capabilities of the accessed system.

6. MEASURES TAKEN OR PROPOSED

The following measures have been taken as of 16:00 on 6 November:
(a) The phishing email domain has been blocked across the organization's email gateway
(b) The compromised account has been disabled and the employee's credentials have been
    reset
(c) All other accounts have been required to verify authentication status
(d) A forensic investigation is ongoing to determine whether data was exfiltrated

The following measures are proposed:
(e) Individual notification to all 847 affected patients pursuant to GDPR Article 34
(f) Mandatory phishing awareness training for all staff
(g) Implementation of multi-factor authentication on all systems accessing patient data
(h) Engagement of external security specialists to assess PMS access controls

Note: This notification is submitted on the basis of information available as of the
filing date. PrivaMed will submit a follow-up notification with updated findings once
the forensic investigation is complete.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Scenario B: RegioBank NV — Accidental Email

### Task B1: Classification

**1.
Is this a reportable breach under GDPR Art. 33?**

**Yes.** An accidental email disclosure constitutes a personal data breach under GDPR Art. 4(12): it is an *accidental disclosure of personal data to unauthorized recipients*.
All 1,240 employees received other employees' personal data — including salary, home address, and social security number — without authorization.
The fact that it was accidental does not remove the notification obligation.

**2.
What is the 72-hour clock start time?**

The clock starts when the **controller becomes aware** of the breach.
The email was discovered when employees started replying — the discovery time is approximately 3 hours after the email was sent.
The 72-hour clock starts from that point (time of organizational awareness), not from the time the email was sent.

**3.
Is this still a breach if everyone complied with the delete request?**

**Yes — the breach is not undone by a delete request.** Recipients have already seen and potentially read the data.
Email systems retain server-side copies.
Recipients may have forwarded or saved the data before deleting.
The breach already occurred the moment unauthorized recipients received the data.
Delete requests are a remedial measure that can reduce ongoing risk, but they do not eliminate the breach event or the notification obligation.
GDPR Art. 33.5 requires the breach to be logged regardless.

---

### Task B2: Individual Notification Analysis

**Arguments for notifying 1,240 employees under Article 34:**

The data disclosed in the accidental email includes home addresses, salary information, and social security numbers — all categories that can cause significant harm to individuals.
Home addresses, if seen by an aggressive or abusive colleague, could create physical safety risks.
Salary data exposed within the workplace can cause lasting professional and personal relationship damage.
Social security numbers can facilitate identity fraud.
The fact that the recipients are all employees of the same organization does not eliminate the harm: employees are not necessarily known to each other (a 1,240-person organization), and the harm arises precisely from colleagues having access to this information.

**Arguments against (and their limitations):**

One might argue that because the data was disclosed only to colleagues, the risk of misuse by a malicious external actor is reduced.
The Article 34 exception for "disproportionate effort" cannot be applied here because the contact details for all 1,240 affected individuals are readily available (they are all employees).
The encryption exception does not apply — the data was in plaintext.

**Recommendation: Notify all 1,240 employees under Article 34.** The combination of home address (safety risk), salary (professional harm), and social security number (identity theft potential) meets the "high risk to rights and freedoms" threshold of Art. 34(1).
The fact that recipients are colleagues does not adequately reduce that risk.
The notification should be brief, factual, apologetic in tone, and inform employees of what data was disclosed and what to do if they experience harm.

---

### Task B3: Breach Register Entry

```text
BREACH REGISTER ENTRY

Reference #: BR-2025-[sequential number, e.g., BR-2025-047]

Date of breach:     [Date and time email was sent]
Date of discovery:  [Date and time first reply received / discovery confirmed]

Description:
An HR department employee accidentally sent a batch email to all 1,240 employees of
RegioBank NV. The email contained an Excel attachment with the personal data of all
1,240 employees. The mistake was identified when employees began replying to the email.
A recall request was sent to all recipients. The root cause was the use of an
undifferentiated recipient list during a bulk HR communication process.

Categories of personal data affected:
- Full name
- Home address
- Salary / compensation details
- Employment contract type (permanent/fixed-term)
- Social security number (Belgian Rijksregisternummer)

Number of data subjects: 1,240 employees

Likely consequences:
- Salary disclosure may cause professional friction and perceived inequity among staff
- Home address disclosure may create physical safety concern for some employees
- Social security number could be misused for identity fraud or financial fraud
- Potential distress and loss of trust in the organization by affected employees

Measures taken:
- Email recall request sent to all 1,240 recipients
- HR communication process suspended pending review
- Affected employees informed via separate communication
- IT investigating whether any emails were forwarded externally
- Process review initiated to prevent recurrence

Notification to DPA (GBA): YES
  Justification: Salary data, social security numbers, and home addresses for 1,240
  individuals constitute a material breach with potential for high risk to individuals
  (identity fraud from SSN, safety risk from home address). Notification to GBA required
  within 72 hours of discovery.

Notification to individuals: YES
  Justification: Home address + SSN + salary combination creates high risk to rights
  and freedoms. Art. 34 threshold met. All 1,240 affected employees to be notified
  directly.

Also notify: NBB (National Bank of Belgium) under DORA — RegioBank is a financial
  entity; DORA operational incident notification obligations apply depending on severity
  classification.

Record completed by: [Name, Title]
Date: [Date of completion]
```

---

## Scenario C: DataStream Analytics — AWS S3 Misconfiguration

### Task C1: Is There a Reportable Breach?

**Yes — this is a reportable breach under GDPR.**

The key question is whether IP addresses constitute personal data.
Per the **Breyer judgment (CJEU C-582/14)**, IP addresses can be personal data even when isolated from names, provided that the controller has *or could reasonably obtain* the means to link them to an identified individual.
For DataStream:

* They hold user IDs (UUIDs) that are linked to registered users in their database
* User session logs tie IP addresses to user UUIDs, enabling re-identification
* Page interaction data (browsing behavior) combined with IP and UUID creates a richer personal data profile

The data is therefore **personal data** under GDPR Art. 4(1).
The S3 bucket was publicly accessible for approximately 14 days, meaning unauthorized parties *could* have accessed 2.1 million user sessions.
Absence of S3 access logging means DataStream **cannot exclude** unauthorized access — and under GDPR, uncertainty about access does not remove the breach.
A breach of confidentiality (and potentially availability) of personal data has occurred.

**Conclusion:** This is a reportable breach to the Irish DPC under Art. 33.

---

### Task C2: Individual Notification Analysis

**Best argument for NOT notifying individuals (Art. 34 does not apply):**

The data exposed consists only of IP addresses, user UUIDs (not names), and page interaction data.
The data does not include names, emails, financial data, health data, or passwords.
While re-identification is theoretically possible, the practical risk of harm to any individual is low — a malicious actor would need access to DataStream's internal database to link UUID to a real person.
The browsing behavior data (product pages viewed) does not reveal sensitive life circumstances.
The risk to individuals' rights and freedoms does not reach the "high risk" threshold of Art. 34(1).

**Best argument FOR notifying individuals:**

With 2.1 million sessions exposed, the scale suggests a material risk.
UUIDs linked to browsing profiles enable tracking and profiling.
IP addresses can reveal home location (ISP geolocation), employment status (corporate IP), and health-related behavior (if users were browsing health product pages).
A sophisticated actor with access to cross-reference databases (ISP logs, ad-tech data) could re-identify users and build profiles for targeted phishing, fraud, or harassment campaigns.
The 14-day exposure window is long enough for systematic harvesting.

**Which argument is stronger?**

**The "do not notify" argument is marginally stronger on the current facts** — but only if DataStream can credibly argue the product pages do not reveal sensitive behavior.
DPC likely expects Art. 33 notification but may accept the Art. 34 exception.
The prudent approach is: notify DPC under Art. 33, include a risk assessment in the notification explaining why individual notification was not undertaken, and document the reasoning thoroughly in the breach register.
If DPC disagrees, they will say so.

---

### Task C3: Draft "Likely Consequences" Section

```text
5. LIKELY CONSEQUENCES OF THE BREACH

The exposed data — IP addresses, user session identifiers (UUIDs), and page interaction
data — presents the following potential consequences for affected individuals:

(a) Profiling and behavioral targeting: The combination of UUID (linkable to a registered
    user account) and browsing session data (product pages viewed, session duration)
    enables the construction of behavioral profiles. Malicious actors with access to
    this data could infer user interests, purchasing intent, and usage patterns, enabling
    targeted phishing, fraudulent advertising, or manipulation campaigns.

(b) Re-identification risk: IP addresses, when combined with ISP subscriber data or
    corporate network registries, can link a session to a specific individual or
    organization. For users browsing from static home IPs, re-identification to a
    household level is feasible without requiring DataStream's internal database.

(c) Aggregated correlation: With 2.1 million sessions across an estimated 850,000
    unique users, the dataset is large enough for cross-correlation with other leaked
    datasets (e.g., compromised credential databases), potentially enabling
    re-identification of individuals who have appeared in multiple data leaks.

(d) Low probability of direct financial or physical harm: Given the absence of names,
    payment data, passwords, or health data in the exposed dataset, the probability of
    direct financial fraud or physical harm arising solely from this breach is assessed
    as low. However, the breach may contribute to harm if the data is combined with
    other stolen datasets by a sophisticated actor.

DataStream assesses the overall risk to individuals as low-to-medium, primarily driven
by re-identification and profiling potential rather than direct harm.
```

---

### Task C4: Multi-Regulator Scenario — One-Stop-Shop Mechanism

**Does DataStream need to notify French, German, or Spanish authorities?**

**No — not directly.** Under the GDPR one-stop-shop mechanism (Art. 56), the **lead supervisory authority** (LSA) is the DPA in the country where the controller has its **main establishment**.
DataStream is Irish-registered, making the **Irish DPC the LSA**.

Under the one-stop-shop:

* DataStream notifies only the **DPC** under Art. 33
* The DPC is responsible for informing "concerned supervisory authorities" in other Member States where the breach affects individuals (Art. 56(6))
* French, German, and Spanish DPAs are "concerned supervisory authorities" — they may submit comments to the DPC, but DataStream's direct notification obligation is only to the DPC

**Exception:** If the breach affects data subjects in a way that is predominantly local to one country, that country's DPA may handle it.
This is unlikely here given the cross-EU user base.

**Practical implication:** DataStream should file with the DPC only.
In the notification, they should acknowledge that users are spread across EU Member States so the DPC can involve concerned authorities as appropriate.

---

## Scoring and Self-Assessment

| Task | Key assessment criteria | Common mistakes |
|------|------------------------|----------------|
| A1 — Deadline calculation | Exact time given, staged notification principle stated | Calculating from attack start rather than awareness; missing staged notification option |
| A2 — Risk assessment | Special category data correctly identified; PESEL = High | Downgrading PESEL risk; missing Art. 34 requirement despite high risk |
| A3 — Article 33 draft | All 6 required elements present; factual language; DPO details | Missing DPO details; vague "we are investigating" without measures; no follow-up note |
| B1 — Classification | Breach confirmed despite accidental nature; clock starts at awareness | Saying "not a breach" because it was accidental; wrong clock start point |
| B2 — Individual notification | Salary + home address + SSN = high risk justified | Saying "employees = safe" without analyzing harm types |
| B3 — Breach register | All fields completed; DPA and individual notification both assessed | Missing DORA note for a bank; leaving notification fields blank |
| C1 — IP = personal data | Breyer case cited or principle applied; cannot exclude access | Saying "no personal data" because no names; saying "no breach" because access unconfirmed |
| C2 — Individual notification | Both arguments constructed; stronger argument identified | Only one-sided argument; no conclusion |
| C3 — Consequences section | Profiling + re-identification + aggregation addressed | Generic "data may be misused" with no specifics |
| C4 — One-stop-shop | LSA = DPC; one notification only; DPC informs others | Thinking they must notify all 4 DPAs directly |
