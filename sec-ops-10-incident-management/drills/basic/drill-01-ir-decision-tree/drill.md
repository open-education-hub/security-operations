# Drill 01 (Basic): Incident Response Decision Tree

> **Level:** Basic
> **Estimated time:** 30–40 minutes
> **Format:** Individual exercise (paper/markdown)
> **No tools required**

---

## Learning Objectives

By completing this drill, you will be able to:

* Apply a structured decision-making process when an alert is received
* Correctly classify incidents by type and severity
* Identify the appropriate first response action for each scenario
* Determine when GDPR notification obligations are triggered

---

## Instructions

For each of the 7 scenarios below, work through the decision tree and provide answers to all four questions.
Record your answers before checking the solution.

**The Decision Tree:**

```text
                    ┌─────────────────────────────┐
                    │  Alert / Report Received     │
                    └───────────────┬─────────────┘
                                    │
                    ┌───────────────▼─────────────┐
                    │  Step 1: Is this a           │
                    │  confirmed incident?          │
                    └───┬───────────────────────┬──┘
                        │ YES                   │ NO
             ┌──────────▼──────────┐   ┌────────▼──────────┐
             │ Step 2: What type?  │   │ False positive or  │
             │ (see taxonomy)      │   │ scheduled activity │
             └──────────┬──────────┘   └───────────────────┘
                        │
             ┌──────────▼──────────┐
             │ Step 3: Severity?   │
             │ P1 / P2 / P3 / P4  │
             └──────────┬──────────┘
                        │
             ┌──────────▼──────────┐
             │ Step 4: Personal    │
             │ data at risk?       │
             └──────┬──────────┬───┘
                    │ YES      │ NO
        ┌───────────▼───┐  ┌───▼────────────────┐
        │ GDPR 72h       │  │ No regulatory       │
        │ clock starts   │  │ notification needed │
        └───────────────┘  └────────────────────┘
```

**Incident taxonomy reference:**

* Malware (ransomware, trojan, wiper, cryptominer)
* Unauthorized access (credential compromise, privilege escalation)
* Data breach (exfiltration, accidental exposure)
* Denial of service (DDoS, application layer)
* Social engineering (phishing, BEC, vishing)
* Insider threat (malicious, accidental)
* Web application attack (SQLi, XSS, API abuse)
* Benign true positive (authorized activity misclassified as attack)

---

## Scenario 1: The Midnight Alert

**Alert received:** 02:14 UTC — SIEM fires correlation rule: "Mass file rename events — 500+ files renamed to .locked extension in past 60 seconds on `HR-SERVER-01`."

**Context:** HR-SERVER-01 stores all employee HR records: names, national ID numbers, salary details, medical leave records for 2,300 employees.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Is this a confirmed incident or a false positive? Justify. | |
| B. What type of incident? (use taxonomy) | |
| C. Severity (P1/P2/P3/P4)? Justify. | |
| D. Is GDPR notification likely required? Why? | |
| E. First immediate action? | |

---

## Scenario 2: The Shared Password

**Report source:** Employee self-report — "I shared my VPN password with a colleague who was working from home last week.
I realize this is against policy.
Should I tell someone?"

**Context:** The employee works in Accounting and has access to the company's SAP financial system.
The colleague has been terminated for performance reasons, effective yesterday.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Is this a confirmed incident or a potential incident? | |
| B. What type? | |
| C. Severity? Justify. | |
| D. GDPR concern? | |
| E. Most urgent first action? | |

---

## Scenario 3: The Researcher's Report

**Email received:** security@company.com inbox — "Hi, I'm a security researcher.
I found that your login page at https://app.yourcompany.com/login allows SQL injection.
I could query your user database and retrieved 5 test records.
I have attached a proof-of-concept screenshot.
I'm reporting this under responsible disclosure."

**Context:** The app database contains: username, hashed password, email address, and subscription tier for 45,000 customers.
No payment data is stored.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Incident type? | |
| B. Severity? (hint: it's already been exploited, even if by a researcher) | |
| C. Has GDPR been triggered? Why? | |
| D. Can you trust the researcher's claim that only 5 records were accessed? How would you verify? | |
| E. Two immediate actions? | |

---

## Scenario 4: The Insider

**Report source:** HR manager calls Security — "We think a departing employee (last day was Friday) downloaded a large amount of files from SharePoint on Thursday.
IT says they copied about 8GB to a personal OneDrive account before they left."

**Context:** The employee was a product engineer with access to source code repositories, product roadmap documents, and customer technical specifications.
No personal employee data was involved.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Incident type? | |
| B. Severity? | |
| C. GDPR triggered? | |
| D. Law enforcement consideration? | |
| E. Evidence challenge: the employee has left the company. What evidence sources are still available? | |

---

## Scenario 5: The API Key

**Detection source:** Threat intelligence feed alert — "GitHub secret scanner has identified a credential matching your AWS access key pattern in a public repository.
Repository: https://github.com/[developer]/test-project"

**Context:** Automated check confirms: the key belongs to a production IAM user named `ci-deploy-prod` with EC2 read/write permissions and S3 write access to a bucket containing customer-generated files.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Incident type? | |
| B. Severity? Consider: the key has been public for an unknown time. | |
| C. GDPR triggered? Justify. | |
| D. Most urgent action (before anything else)? | |
| E. What logs would you check to determine impact? | |

---

## Scenario 6: The Help Desk Call

**Report:** A user calls the IT help desk: "I got an email saying my password expired and I need to reset it.
I clicked the link and entered my old password and my new password.
But now it's asking me to enter it again, which seems weird.
I closed the browser."

**Context:** The link was to `login.company-support.com` (not `login.company.com`).
The user has standard employee access: M365, internal HR portal, and the corporate VPN.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Incident type? | |
| B. Did the attacker succeed? How would you determine this? | |
| C. Severity? | |
| D. Immediate actions (list 3 in order)? | |
| E. GDPR implications? | |

---

## Scenario 7: The Multi-Stage Alert

**SIEM alert:** At 11:03, a correlation rule fires: "Kerberoastable service account queried 5 times within 10 minutes from workstation `DEVWS-022`."

At 11:15, a second alert: "Lateral movement detected: DEVWS-022 is accessing admin shares on `APP-SERVER-04` using pass-the-hash technique."

At 11:22, a third alert: "Privilege escalation detected on APP-SERVER-04: user context changed from `svc-deploy` to `DOMAIN\Administrator`."

**Context:** APP-SERVER-04 hosts an internal application that processes and temporarily stores customer payment card data (PAN) during transaction processing.
The system is in-scope for PCI-DSS.

**Your task:**

| Question | Your Answer |
|---------|-------------|
| A. Incident type and MITRE ATT&CK tactics involved? | |
| B. Severity? | |
| C. Is this likely targeted or opportunistic? Justify. | |
| D. Regulatory implications (note all applicable frameworks)? | |
| E. Containment challenge: DEVWS-022 is a developer workstation. The developer is in a meeting you cannot interrupt. What do you do? | |

---

## Scoring Guide

After completing all scenarios, refer to the solution file.

* **Full credit**: Correct classification + severity + appropriate actions + correct regulatory assessment
* **Partial credit**: Correct incident type but incorrect severity; or correct severity but missed regulatory trigger
* **No credit**: Fundamentally wrong classification (e.g., calling ransomware "social engineering")

**Target scores:**

* 7/7 perfect: Ready for intermediate drills
* 5–6/7: Good understanding; review missed scenarios
* 3–4/7: Review Session 10 reading, specifically Sections 2 and 10
* <3/7: Re-read the full reading material before proceeding

---

## Solution

See: `../solutions/drill-01-solution/solution.md`
