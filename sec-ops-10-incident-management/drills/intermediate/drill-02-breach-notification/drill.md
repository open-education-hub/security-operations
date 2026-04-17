# Drill 02 (Intermediate): GDPR Breach Notification Drafting

> **Level:** Intermediate
> **Estimated time:** 45–60 minutes
> **Format:** Individual written exercise
> **Reference:** GDPR Articles 33 and 34; reading material Section 10

---

## Overview

This drill focuses exclusively on the regulatory notification dimension of incident response.
You will analyze three breach scenarios and produce the required GDPR notifications.

Understanding GDPR breach notification is critical for any security professional working in the EU or handling EU citizen data.
Regulators pay close attention to:

* Whether you notified within 72 hours
* Whether your notification contains all required elements
* The quality of your risk assessment (was individual notification required?)
* Completeness of your breach register entry

---

## Legal Reference Summary

**GDPR Article 33 — Notification to supervisory authority:**

Required content (Article 33.3):

1. The nature of the personal data breach including where possible, the categories and approximate number of data subjects concerned and the categories and approximate number of personal data records concerned
1. The name and contact details of the data protection officer or other contact point
1. The likely consequences of the personal data breach
1. The measures taken or proposed to be taken by the controller to address the breach

**GDPR Article 34 — Communication to the data subject:**

Required when the breach **is likely to result in a high risk to the rights and freedoms of natural persons**

Required content: plain language description of the nature of the breach; DPO contact details; likely consequences; measures taken.

**When Article 34 (individual notification) is NOT required:**

* Technical/organizational measures were implemented that make data unintelligible (e.g., data was encrypted and key was not compromised)
* Subsequent measures ensure high risk is no longer likely to materialize
* Notification would involve disproportionate effort (use public communication instead)

---

## Scenario A: The Healthcare Phishing Attack

**Facts:**

* Organization: PrivaMed Clinic S.A. (private medical clinic in Warsaw, Poland)
* Lead supervisory authority: UODO (Poland)
* Date/time of breach: Wednesday, November 6 — confirmed at 14:20 local time
* Breach type: A healthcare coordinator opened a phishing email and provided their login credentials to an attacker via a fake login page. The attacker used the credentials to access the clinic's Patient Management System (PMS) from 14:22 to 14:47 Wednesday (25 minutes).
* Data accessed: Patient name, date of birth, national ID (PESEL), medical diagnosis codes, and appointment history for **847 patients**.
* Data categories: Health data (GDPR Article 9 — special category), National ID
* Was data exfiltrated? Unknown — the attacker's session shows read queries; no download activity detected in the DLP tool.
* Current status (as of 16:00 Wednesday): Phishing email blocked across organization, compromised account disabled, password reset completed.
* DPO: Dr. Anna Wiśniewska, dpo@privamedclinic.pl, +48 22 555 0100

**Task A1: Notification Deadline**

When exactly does the 72-hour clock expire?
Show your calculation.
Should PrivaMed file even if the investigation is not complete?
Why?

**Task A2: Individual Risk Assessment**

For each data category, assess the risk level to affected individuals:

| Data Category | Risk Level (Low/Medium/High) | Justification |
|--------------|------------------------------|---------------|
| Name + date of birth | | |
| National ID (PESEL) | | |
| Medical diagnosis codes | | |
| Appointment history | | |

Based on this, does Article 34 (individual notification) apply?
Justify your answer.

**Task A3: Draft the Article 33 Notification**

Using the required elements from Article 33.3, draft the full notification to UODO.
Structure it with these headers:

```text
1. Nature of the breach

2. Categories and number of data subjects affected
3. Categories and number of personal data records
4. Data Protection Officer contact details
5. Likely consequences of the breach
6. Measures taken or proposed
```

Write in formal, factual language (2–4 sentences per section is appropriate).

---

## Scenario B: The Accidental Email

**Facts:**

* Organization: RegioBank NV (Belgian community bank)
* Lead supervisory authority: GBA (Belgium) — also reports to NBB under DORA
* Date/time: An employee in the HR department accidentally sent a batch email to all 1,240 employees. The email contained an Excel attachment that included the personal data of 1,240 employees: full name, home address, salary, employment contract type, and social security number.
* The mistake was discovered 3 hours later when employees started replying.
* All employees have now been requested to delete the email.
* No indication any employee has used the data maliciously.
* Data categories: Financial data (salary), government ID, home address
* DPO: Legal & Compliance Team, gdpr@regiobank.be, +32 2 555 0200

**Task B1: Classification**

1. Is this a reportable breach under GDPR Art. 33? Why?
1. What is the 72-hour clock start time?
1. Is this a breach if everyone complied with the delete request? Explain.

**Task B2: Individual Notification Analysis**

Should RegioBank notify 1,240 employees under Article 34?
Consider:

* The data was only seen by other employees of the same organization
* The salary data could cause internal relationship damage
* The home addresses could create physical safety risk for some employees
* Some employees may have not opened the email

Write a 2-paragraph analysis that leads to a recommendation.

**Task B3: Breach Register Entry**

Under GDPR Art. 33.5, controllers must maintain a record of all personal data breaches (even those that are not notifiable).
Complete this breach register entry:

```text
BREACH REGISTER ENTRY

Reference #: BR-2025-[number]
Date of breach/discovery:
Description:
Categories of personal data:
Number of data subjects:
Likely consequences:
Measures taken:
Notification to DPA: Yes/No — Justification:
Notification to individuals: Yes/No — Justification:
Record completed by:
Date:
```

---

## Scenario C: The Cloud Misconfiguration

**Facts:**

* Organization: DataStream Analytics Ltd (Irish-registered company, processes data of EU customers)
* Lead supervisory authority: DPC (Ireland) — Data Protection Commission
* Discovery: On Monday at 09:00, a security researcher reported via responsible disclosure that a company AWS S3 bucket was publicly accessible. Investigation confirmed the bucket had been set to `public-read` for an estimated 14 days (since a configuration change 2 weeks ago).
* Data in bucket: Log files containing user session data: IP address, user ID (UUID, no names), and page interaction data (which product pages were viewed). No names, emails, or payment data.
* Scale: Approximately 850,000 log files covering 2.1 million unique user sessions.
* Likely access by unauthorized parties: Cannot be confirmed or denied (S3 access logging was not enabled on this bucket).
* Current status: Bucket is now private. Logging enabled going forward.
* DPO: privacy@datastreamanalytics.ie

**Task C1: Is There a Reportable Breach?**

Analyze this scenario against the GDPR breach definition.
Note: IP addresses can be personal data (see Breyer case, CJEU C-582/14).
Is this a reportable breach?
Justify.

**Task C2: Individual Notification Required?**

Can DataStream argue that notification is NOT required under Article 34?
Construct the best argument for not notifying individuals, and the best argument for notifying.
Which argument is stronger?

**Task C3: Notification to DPC (Article 33)**

If DataStream decides to notify the DPC, draft the key section: **"Likely consequences of the breach."**

Consider: What could a malicious actor do with 2.1 million browsing session logs (UUID + pages viewed)?

**Task C4: Multi-Regulator Scenario**

DataStream has customers in France, Germany, Spain, and Ireland.
The Irish DPC is the lead supervisory authority.
Do they need to notify any other supervisory authorities?
Explain the GDPR one-stop-shop mechanism.

---

## Common Notification Mistakes

After completing the scenarios, review this list of common Article 33 notification mistakes regulators have cited in enforcement decisions:

```text
TOP 10 ARTICLE 33 NOTIFICATION ERRORS:

1. Late notification (>72 hours without justification or ongoing investigation note)

2. Reporting to the wrong supervisory authority (not the lead DPA)
3. Missing DPO contact details in the notification
4. Vague description of the breach (no specific system/data type named)
5. No risk assessment provided (leaving regulators to assess themselves)
6. No list of measures taken — just "we are investigating"
7. Underestimating number of affected data subjects
8. Failing to update the notification when new information comes to light
9. Not maintaining a breach register (required even for non-notifiable events)
10. Confusing the 72h clock start: it is from awareness, not from attack start
```

---

## Evaluation Criteria

| Component | Points |
|---------|--------|
| Scenario A: Correct deadline calculation | 10 |
| Scenario A: Correct risk assessment for individual notification | 15 |
| Scenario A: Article 33 notification covers all required elements | 25 |
| Scenario B: Correct breach classification | 10 |
| Scenario B: Individual notification analysis | 15 |
| Scenario C: IP address = personal data analysis | 10 |
| Scenario C: Draft consequences section | 15 |
| Total | 100 |

---

## Solution

See: `../../solutions/drill-02-solution/solution.md`
