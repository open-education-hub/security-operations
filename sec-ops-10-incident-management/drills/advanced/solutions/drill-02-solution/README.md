# Solution: Drill 02 — Tabletop Exercise Design

## Sample Exercise Design: Business Email Compromise (BEC)

### Scenario Selection: BEC targeting CFO — €500k wire fraud attempt

This scenario is chosen because:

* Highly realistic (BEC is #1 financial cybercrime)
* Tests cross-functional response (Finance, Legal, IT, Communications)
* Has a real-time financial decision component (approve/block wire)
* Tests both technical IR and business continuity

---

## Three Scenario Injects

### Inject 1: Initial Discovery

> **Time: Monday 09:30**
> The CFO's executive assistant, M. Laurent, forwards an email to the Head of Finance: "Per our phone call, the CFO needs an urgent wire transfer of €500,000 to a new vendor account in Lithuania for a confidential acquisition. The CFO is traveling and cannot be reached by phone. Please process this before noon."
>
> The Head of Finance notices the email is from `cfo@securebank-corp.biz` (not the usual `cfo@securebank.eu`). She is not sure if this is legitimate.

**Discussion Questions:**

1. What is the correct first action for the Head of Finance? Who should she call?
1. Does SecurBank have a process for out-of-band verification of wire requests? What is it?

---

### Inject 2: Escalation

> **Time: Monday 10:15**
> IT has confirmed the CFO's real account (`cfo@securebank.eu`) sent 3 emails to vendors last week that were unusual. Review shows the CFO's email account was accessed from an IP in Romania on Friday night. The CFO's real inbox shows all emails from that access have been deleted.
>
> Simultaneously, a journalist from a financial news outlet calls the Communications Director saying they've received an anonymous tip that "SecurBank had a major IT breach" and asks for a comment.

**Discussion Questions:**

1. Has money moved? (It hasn't yet — the wire is still pending approval.) What is your decision?
1. How do you communicate with the journalist? Who speaks for the organization?

---

### Inject 3: The Dilemma

> **Time: Monday 11:45**
> The wire was blocked. The CFO (reached in a meeting abroad) confirms his account was compromised. However, IT finds that the same Romania IP also accessed HR Manager files including all employee salary and personal data (8,500 employees).
>
> Legal confirms this triggers GDPR notification (personal data breach). The Communications Director warns: "If we notify the DPA, they may share this with the press before we've informed our employees. If employees hear this from the news, it will severely damage trust."

**Discussion Questions:**

1. Does the legal obligation override the communications concern? (Yes — but how do you handle it?)
1. How do you notify 8,500 employees about a potential personal data exposure without causing panic?

---

## Hot Wash Template

### Debrief Questions

**Process questions:**

* Did we have a verification procedure for wire transfers? Was it documented?
* Who had authority to approve blocking a €500k wire?
* How long did it take to reach the CFO? What would we do differently?

**Communication questions:**

* Who managed communication during the exercise? Was it clear?
* Did legal and communications work together effectively?
* Would your answer to the journalist be consistent with your GDPR notification?

**Gap identification:**

* What would have happened if the wire had already been processed?
* What if it were a Friday at 17:00 instead of Monday at 09:30?
* Do we have playbooks for BEC? For GDPR personal data notification?

**Action item generation:**

* List the top 3 gaps from today's exercise
* Who owns each gap?
* What's the deadline for closing it?

---

## Part C: Sample Gap Analysis (After Exercise)

### Gap 1: No Wire Transfer Verification Procedure

**Observation:** The Head of Finance did not know who to call to verify the wire.
She had no out-of-band verification process.

**Action Item:** Implement a "callback verification" procedure for all wire transfers above €10,000.
Call the requester on a phone number from the official directory (not the one in the email).
Owner: CFO's office.
Due: 30 days.

### Gap 2: No Designated Spokesperson During Incident

**Observation:** The Communications Director and Legal Counsel gave conflicting guidance during the journalist call inject.

**Action Item:** Define the "incident spokesperson" role in the IR plan.
Only the designated spokesperson speaks to media.
Owner: Communications + Legal.
Due: 14 days.

### Gap 3: GDPR Notification Decision Authority Not Defined

**Observation:** No one in the room knew who had authority to approve GDPR notification.
Exercise stalled for 8 minutes.

**Action Item:** Add "GDPR Notification Decision" to the IR Plan with named authority (Legal Counsel + CISO joint decision required).
Owner: Legal.
Due: 14 days.

---

## Part D: Reflection

**What surprised participants:** Most exercises reveal that decisions requiring cross-department coordination take much longer than expected.
The BEC scenario typically exposes that Finance teams don't know who in IT to call for account compromise verification.

**Harder to simulate in tabletop vs real incident:**

* Time pressure (exercises slow down for discussion)
* Emotional reactions (stress, disagreement in real incidents)
* Technical complexity (exercise abstracts away tool usage)
* Parallel workstreams (only one conversation at a time in tabletop)

**Exercise frequency recommendation:**

* Annual full tabletop (all scenarios, full team)
* Semi-annual mini tabletops (single department, focused scenario)
* After any significant infrastructure change
* After any real incident (to test if lessons were implemented)
