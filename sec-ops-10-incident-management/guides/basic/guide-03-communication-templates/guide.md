# Guide 03 — Communication Templates for Incident Response

## Objective

By the end of this guide you will be able to:

* Draft initial, update, and resolution communications for security incidents
* Tailor message content to different audiences (technical, management, legal, regulatory, public)
* Apply GDPR Article 33/34 notification requirements
* Avoid common communication mistakes during incidents

**Estimated time:** 25 minutes

**Level:** Basic

---

## Communication Principles

1. **Accuracy over speed**: Don't send estimates as facts. "We are investigating" is better than incorrect details.
1. **Need-to-know**: Only share sensitive details with those who need them.
1. **Consistent**: All communications should tell the same story.
1. **No speculation**: Don't speculate on cause, scope, or impact until confirmed.
1. **Legal review**: Any external communication should be reviewed by legal.
1. **The ticket is the source of truth**: Summarize from the ticket — don't create separate "official" accounts.

---

## Template 1: Initial Internal Notification (Management)

Use this when escalating a P1/P2 incident to management within the first 30 minutes.

```text
SUBJECT: [SECURITY INCIDENT] [Severity] — [Brief Description] — [Case ID]

To: [CISO, IT Director, affected business unit head]
Classification: CONFIDENTIAL

INCIDENT NOTIFICATION — [Time] UTC

SUMMARY
We are investigating a [type of incident] affecting [systems/users].
This communication is being sent as part of our incident response process.

WHAT WE KNOW
- Time of detection: [Time]
- Affected systems: [List]
- Current scope: [Single host / Multiple hosts / Under assessment]
- Business impact: [Description or "Under assessment"]

ACTIONS TAKEN
- [Action 1 with timestamp]
- [Action 2 with timestamp]

ACTIONS IN PROGRESS
- [In-progress action]

DATA ASSESSMENT
[Personal data involved: YES / NO / UNDER ASSESSMENT]
[If YES: DPO has been notified]

NEXT UPDATE
Expected at [Time] or upon significant development.

Incident Commander: [Name], [Phone]
Incident Case ID: [ID]

DO NOT discuss this incident via regular email.
Use [encrypted channel] for further communications.
```

---

## Template 2: Management Update (Every 2 Hours for P1)

```text
SUBJECT: UPDATE [#X] — [Case ID] — [Brief Status]

Incident: [Case ID]
Update #: [X]
Time: [UTC]
Current Status: [ACTIVE / CONTAINED / RECOVERING / CLOSED]

EXECUTIVE SUMMARY
[2-3 sentences: what happened, current state, expected resolution]

TIMELINE UPDATE (NEW SINCE LAST UPDATE)
[HH:MM] [Action/finding]
[HH:MM] [Action/finding]

CURRENT SCOPE
[Updated assessment]

REGULATORY STATUS
[GDPR/NIS2: notification submitted? DPO engaged? Clock running?]

DECISIONS NEEDED FROM MANAGEMENT
[List any decisions that require executive authorization]

NEXT UPDATE: [Time] or upon material change
Incident Commander: [Name], [Phone]
```

---

## Template 3: Technical Escalation to Tier 2/3

```text
ESCALATION NOTE — [Case ID] → Tier [2/3]

Escalating Analyst: [Name], Tier [1/2]
Escalation Time: [UTC]
Reason: [Specific reason for escalation]

WHAT I KNOW
[Factual description of what has been confirmed]

WHAT I'VE DONE
- [Action 1]
- [Action 2]

WHAT I RECOMMEND
[Specific recommended next steps]

EVIDENCE COLLECTED
- [Link to ticket observables]
- [Any files/logs preserved]

OPEN QUESTIONS
- [Question requiring investigation]

SLA STATUS
Alert time: [Time] | ACK: [Time] | Escalation: [Time]
Tier 2 SLA: Investigate within [X] hours (deadline: [Time])
```

---

## Template 4: GDPR Article 33 Notification

For submission to the Data Protection Authority (DPA).
Must be submitted within 72 hours.

```text
NOTIFICATION OF PERSONAL DATA BREACH
[Under Article 33 of the General Data Protection Regulation]

Organization: [Name, Address, Country]
DPO Contact: [Name, Email, Phone]
Notification Date/Time: [Exact timestamp]
Breach Discovery Date/Time: [Exact timestamp]
Breach Incident Date/Time: [Estimated time breach began]

1. NATURE OF THE PERSONAL DATA BREACH

[Description of what happened]
Type of breach: [Confidentiality breach / Integrity breach / Availability breach]

2. CATEGORIES AND APPROXIMATE NUMBER OF DATA SUBJECTS
[E.g.: Approximately 5,000 EU customer records including names, email addresses,
and order history. No financial data or health data affected.]
Number of individuals: Approximately [X]
Number of records: Approximately [X]

3. LIKELY CONSEQUENCES
[What risks could this create for the affected individuals?]
[E.g.: Risk of phishing targeting affected customers; risk of identity fraud is LOW
because no financial data was included]

4. MEASURES TAKEN OR PROPOSED
[Describe technical and organizational measures]
[E.g.:
- Breach contained on [date/time]
- Compromised systems isolated and rebuilt
- Affected credentials reset
- Email security policy updated
- Individual notification to data subjects: [planned/not required/already sent]]

Signed: [Name], [Title], [Date]
```

---

## Template 5: GDPR Article 34 — Notification to Individuals

Required when breach is HIGH RISK to individual rights and freedoms.

```text
SUBJECT: Important Security Notice — [Company Name]

Dear [Customer/Employee],

We are writing to inform you about a security incident that may have affected
your personal information.

WHAT HAPPENED
On [Date], we discovered [brief plain-language description of incident].

WHAT INFORMATION WAS INVOLVED
[Specific data types: e.g., "your name and email address" — be specific]

WHAT WE ARE DOING
We have [actions taken]:
- [Action 1]
- [Action 2]
We have also reported this incident to [supervisory authority].

WHAT YOU CAN DO
We recommend you:
- [Specific action: e.g., "Be vigilant about phishing emails that may use your name"]
- [Specific action: e.g., "Change your password if you use the same password elsewhere"]

CONTACT US
If you have questions, please contact our Data Protection Officer:
[DPO Name], [Email], [Phone]
Available: [Hours]

We sincerely apologize for any concern this may cause.

[Company Name]
[Date]
```

---

## Template 6: Resolution Communication

```text
SUBJECT: RESOLVED — [Case ID] — [Brief Description]

To: [All who received initial notification]
Classification: CONFIDENTIAL

INCIDENT RESOLVED — [Time] UTC

SUMMARY
The security incident reported on [Date] has been resolved.
This is the final status update.

WHAT HAPPENED
[Clear, accurate description — now that full investigation is complete]

HOW IT WAS RESOLVED
[Steps taken]

IMPACT
- Systems affected: [List]
- Data affected: [None confirmed / Description]
- Business impact: [Description]
- Duration: [Start] to [End]

REGULATORY
[GDPR notified: YES/NO/N/A | Reference: [ID] | DPA Response: [Status]]

LESSONS LEARNED
[1-2 sentences on key improvements being made]

ACTION ITEMS TRACKING
[Reference to post-incident review report]

Thank you for your support during this incident.

Incident Commander: [Name]
Case ID: [ID]
Final Report Available: [Location]
```

---

## Common Communication Mistakes

| Mistake | Why It's Dangerous | Better Approach |
|---------|-------------------|----------------|
| "We've been hacked" in early notification | Creates alarm before scope is known | "We are investigating a potential security incident" |
| Sending GDPR notification to wrong authority | Invalids your legal compliance | Confirm jurisdiction of data subjects first |
| Over-specifying attacker identity early | Could be wrong; legal implications | "Unauthorized third party" until confirmed |
| Forgetting to update stakeholders | Creates information vacuum; management makes bad decisions | Commit to update schedule and follow it |
| Using regular email for incident comms | Attacker may be reading your email | Establish out-of-band channel before incidents |

---

## Knowledge Check

1. A P2 incident is discovered at 14:00. When should management receive their first update?
1. You suspect customer email addresses were exposed. When must the DPA be notified?
1. The breach involved encrypted data that the attacker cannot decrypt. Is GDPR Article 34 notification required?
1. What is the difference between the GDPR Article 33 and Article 34 notifications?
