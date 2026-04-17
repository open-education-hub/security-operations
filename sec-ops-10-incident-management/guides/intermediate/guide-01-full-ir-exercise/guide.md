# Guide 04 (Intermediate): Running a Full Incident Response Exercise

> **Estimated time:** 3–4 hours (full exercise day)
> **Level:** Intermediate
> **Goal:** Design, execute, and debrief a full-scope incident response exercise, testing your IRP end-to-end against a realistic scenario.

---

## Overview

A full incident response exercise is more than a tabletop discussion.
It includes:

1. **Pre-exercise preparation** — scenario design, participant briefing, environment setup
1. **Exercise execution** — working through a realistic incident from detection to PIR
1. **Debrief** — structured review of performance, gap identification, action items
1. **Documentation** — recording outcomes and updating the IRP

This guide takes the role of the **exercise facilitator** (sometimes called the White Cell in military exercises).
The facilitator designs the scenario, delivers "injects" (new pieces of information that advance the scenario), and evaluates participant responses.

---

## Phase 1: Pre-Exercise Preparation (1 hour before)

### 1.1 Define Exercise Objectives

Before designing the scenario, define what you want to test.
Examples:

```text
EXERCISE OBJECTIVES — Example Set
══════════════════════════════════════════════════════════
Objective 1: Test P1 notification tree — can all IRT members be reached
             within 30 minutes?

Objective 2: Test the ransomware playbook — is it complete and usable
             under pressure?

Objective 3: Test GDPR assessment capability — can the team correctly
             determine within 30 minutes whether the 72h clock has started?

Objective 4: Test executive communication — can IR Lead produce a concise
             executive brief within 15 minutes of incident declaration?

Objective 5: Identify any containment authority gaps — who has pre-authorized
             to isolate a production server?
══════════════════════════════════════════════════════════
```

### 1.2 Scenario Design

Design a scenario that exercises your objectives.
A good exercise scenario has:

* A realistic initial condition
* Complications that arrive over time (injects)
* Regulatory implications (to test GDPR/NIS2 assessment)
* Communication requirements (to test templates)
* Decision points requiring authorization

**Example scenario for this exercise:**

```text
EXERCISE SCENARIO: "INVOICE NIGHTMARE"
══════════════════════════════════════
Organization: RetailCo Sp. z o.o. (online retailer, 85,000 EU customers)
Applicable regulations: GDPR, PCI-DSS (processes card payments)

Initial condition (09:00):
  Three workstations in the Customer Orders department have encrypted files.
  Desktop wallpaper shows a ransom demand: 5 BTC to decrypt.
  An IT help desk ticket was opened 8 minutes ago.

What we do NOT know at start:
  - How the ransomware entered
  - How many systems are affected
  - Whether customer data was exfiltrated before encryption
  - Whether backups are intact

Injects to deliver during exercise:
  [09:15] Security team identifies 7 more encrypted workstations
  [09:30] CEO calls asking what to tell the board
  [09:45] IT discovers backup server also shows encrypted files
  [10:00] Customer calls customer support — their email in spam shows "RetailCo has been breached"
  [10:20] Journalist sends email asking for comment on reported ransomware attack
  [10:30] IT confirms: database server with customer order history ALSO encrypted
  [10:45] Threat intel identifies ransomware as "BlackCat" — known to exfiltrate data before encrypting
  [11:00] Police call: they've received a tip that the company has been breached

Scenario conclusion (if executed well):
  - Containment achieved by 10:30
  - GDPR assessment triggers 72h clock
  - PIR scheduled for 5 days later
══════════════════════════════════════
```

### 1.3 Participant Briefing

Send participants this information 24 hours before the exercise:

```text
EXERCISE BRIEFING NOTICE

Date/Time: [Date], 09:00–13:00
Location: [Conference room / video call link]
Facilitator: [Name]

GROUND RULES:

1. This is an exercise. No real systems will be affected.

2. Role-play your actual job role as realistically as possible.
3. If you do not know what to do, say so — that is a finding, not a failure.
4. The exercise is confidential — do not discuss details outside the team.
5. Out-of-scope: We will not actually notify regulators or customers today.
   Legal decisions will be discussed but not executed.

WHAT TO BRING:
- Your copy of the IR Plan
- Any playbooks relevant to your role
- Notepad for taking notes

WHAT NOT TO DO:
- Do not "meta-game" (looking things up you wouldn't have in a real incident)
- Do not skip steps to save time — work through them
```

### 1.4 Facilitator Preparation Checklist

```text
□ Scenario document printed (keep injects hidden until delivery time)
□ Timeline sheet prepared (facilitator tracks real time vs scenario time)
□ Observer notes template ready (to record participant actions)
□ Communications channel set up (separate from participant channels)
□ "Hot wash" debrief questions prepared
□ Scoring rubric ready (see Section 3)
```

---

## Phase 2: Exercise Execution

### 2.1 Exercise Start

**Facilitator script (read aloud at 09:00):**

> "Good morning. We are beginning the incident response exercise. The time is now 09:00 on [exercise date]. You will receive an initial scenario briefing. Respond as you would in a real incident. I will provide additional information at intervals. Are there any questions before we begin? [pause] The exercise begins now."

**[Deliver Initial Inject]:**

> "It is 09:00. You receive an escalated help desk ticket: 'Three workstations in Customer Orders (Floor 2) are showing a popup that says all files are encrypted and a ransom demand of 5 BTC is displayed. Users cannot access any files.' The ticket was opened 8 minutes ago."

### 2.2 Inject Timing Guide

| Scenario Time | Exercise Time | Inject |
|--------------|---------------|--------|
| 09:00 | T+0 | Initial scenario (ransomware on 3 workstations) |
| 09:15 | T+15 min | 7 more workstations encrypted |
| 09:30 | T+30 min | CEO calls asking for board update |
| 09:45 | T+45 min | Backup server shows encrypted files |
| 10:00 | T+60 min | Customer contacts support re: breach |
| 10:20 | T+80 min | Journalist email arrives |
| 10:30 | T+90 min | Database server confirmed encrypted |
| 10:45 | T+105 min | Threat intel: BlackCat exfiltrates before encrypting |
| 11:00 | T+120 min | Police call about breach tip |

**Facilitator inject cards** (keep these printed and give them at the right time):

```text
══════════════════════ INJECT 1 (T+15 min) ══════════════════════
"The SOC analyst has expanded the search in the SIEM.
 7 additional workstations are showing identical encryption patterns.
 All are in the Customer Orders and Accounts Receivable departments.
 Total affected: 10 workstations.
 No servers have been confirmed yet."
══════════════════════════════════════════════════════════════════

══════════════════════ INJECT 3 (T+45 min) ══════════════════════
"IT has just checked the backup server.
 The last 3 days of backups appear to be encrypted.
 The offline tape backup (last Monday) is intact and accessible.
 What do you do next?"
══════════════════════════════════════════════════════════════════

══════════════════════ INJECT 5 (T+80 min) ══════════════════════
"A journalist from [newspaper name] has sent this email to press@company.com:

 'Dear [company], we have received reports that your company has suffered
 a ransomware attack affecting customer data. We plan to publish a story
 tomorrow morning. Would you like to comment?'

 The email was forwarded to the IR channel by the receptionist."
══════════════════════════════════════════════════════════════════

══════════════════════ INJECT 6 (T+90 min) ══════════════════════
"Database administrator confirms: the customer orders database server
 (DB-ORDERS-01) is also encrypted. This database contains:
 - Customer names and email addresses (85,000 records)
 - Order history
 - Partially masked payment card data (last 4 digits, card type)
 - Shipping addresses

 The last unencrypted database backup is from 48 hours ago."
══════════════════════════════════════════════════════════════════
```

### 2.3 Facilitation Tips

* **Maintain pace**: If participants are stuck for >10 minutes, give a gentle nudge: "In a real incident, your SOC vendor would already have asked about [topic]."
* **Allow for silence**: Some pauses are normal decision-making. Do not fill every silence.
* **Track decisions**: Note every key decision made and when.
* **Track gaps**: Note anything the team does NOT do that they should.
* **Stay neutral**: Do not evaluate or praise during the exercise — that is for the debrief.

---

## Phase 3: Debrief (Hot Wash)

### 3.1 Immediate Hot Wash (30 minutes after exercise)

The hot wash is a quick, unstructured debrief immediately after the exercise ends.
Goal: capture immediate impressions while memory is fresh.

**Facilitator questions:**

1. "What was the first thing you did when you received the initial alert? Was that the right move?"
1. "At what point did you decide to engage Legal/DPO? Was that too early, too late, or appropriate?"
1. "How did the backup failure (Inject 3) change your response? Were you prepared for that?"
1. "When the journalist called (Inject 5), who decided what to do and how quickly?"
1. "What was the most difficult decision you faced today?"

### 3.2 Structured Exercise Review (within 48 hours)

Complete this evaluation rubric:

```text
EXERCISE EVALUATION RUBRIC

CATEGORY: NOTIFICATION AND ESCALATION                     Score: /20
─────────────────────────────────────────────────────────────────────
□ P1 declared within 15 minutes of scenario start         (5 pts)
□ IR Lead notified within 15 minutes of declaration       (5 pts)
□ CISO notified within 30 minutes                         (5 pts)
□ Legal/DPO notified within 60 minutes                    (5 pts)

CATEGORY: CONTAINMENT                                     Score: /20
─────────────────────────────────────────────────────────────────────
□ Volatile evidence collection mentioned before isolation  (5 pts)
□ EDR/network isolation of affected hosts executed        (5 pts)
□ Account containment (if applicable) executed            (5 pts)
□ Backup isolation (protect remaining backups)            (5 pts)

CATEGORY: GDPR/REGULATORY ASSESSMENT                      Score: /20
─────────────────────────────────────────────────────────────────────
□ Team correctly identified personal data at risk         (5 pts)
□ 72h clock start time correctly identified               (5 pts)
□ Team knew who files the notification                    (5 pts)
□ Team correctly assessed: notify individuals or not?     (5 pts)

CATEGORY: COMMUNICATION                                   Score: /20
─────────────────────────────────────────────────────────────────────
□ Executive brief drafted (BLUF format, <1 page)          (5 pts)
□ Media enquiry handled correctly (PR, not SOC)           (5 pts)
□ Out-of-band comms considered when email may be infected (5 pts)
□ Customer notification plan discussed                    (5 pts)

CATEGORY: DOCUMENTATION                                   Score: /20
─────────────────────────────────────────────────────────────────────
□ Incident record opened and maintained                   (5 pts)
□ Timeline entries maintained throughout exercise         (5 pts)
□ Evidence collection documented                          (5 pts)
□ Actions documented with timestamps                      (5 pts)

TOTAL:                                                    /100
─────────────────────────────────────────────────────────────────────
90–100:  Excellent — minor gaps only
75–89:   Good — a few significant gaps
60–74:   Adequate — multiple significant gaps requiring attention
<60:     Needs improvement — plan review and retraining required
```

### 3.3 Action Item Template

For each gap identified, create an action item:

```text
EXERCISE ACTION ITEM

AI-001
Gap identified: Team did not know whether to notify PCI-DSS acquiring bank
                when database with partial card data (last-4) was confirmed encrypted.

Root cause: PCI-DSS obligations not addressed in IR Plan section on regulatory notification.

Action: Add PCI-DSS notification procedures to IR Plan Section 7.
        Consult with Legal to confirm: do last-4 digits + card type trigger PCI notification?

Owner: [Legal Counsel / DPO]
Deadline: [Date + 2 weeks]
Status: Open
```

---

## Phase 4: Post-Exercise Report

Produce a written exercise report within 5 business days:

```text
INCIDENT RESPONSE EXERCISE REPORT
════════════════════════════════════════════════════════════
Exercise Name:   "Invoice Nightmare"
Date:            [Date]
Facilitator:     [Name]
Participants:    [List roles, not names for privacy]
Duration:        4 hours
Classification:  CONFIDENTIAL — Internal Only
════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
[2–3 sentence summary: what was tested, overall performance, key finding]

EXERCISE OBJECTIVES VS OUTCOMES
[For each objective: met / partially met / not met]

SCENARIO SUMMARY
[Brief narrative of how the exercise played out]

KEY FINDINGS (Strengths)

1. [What went well]

2. [What went well]
3. [What went well]

KEY FINDINGS (Gaps)

1. [Gap identified + context]

2. [Gap identified + context]
3. [Gap identified + context]

ACTION ITEMS
[Table of all action items with owner, deadline, status]

EXERCISE SCORING
[Overall score from rubric + category breakdown]

RECOMMENDATIONS
[2–3 strategic recommendations for the IR program]

NEXT EXERCISE
[Recommended date and focus area for next exercise]
════════════════════════════════════════════════════════════
```

---

## Facilitation Tips and Pitfalls

### Common Exercise Facilitation Mistakes

1. **Too easy scenario**: Participants succeed without being stressed. Real incidents create chaos. Add complications.
1. **Too many injects too fast**: Participants lose track. Space injects at least 10 minutes apart.
1. **Facilitator giving answers**: Tempting when participants struggle, but defeats the purpose.
1. **Skipping debrief**: The debrief is where the learning happens. Never skip it.
1. **No follow-up on action items**: Exercises are useless if action items are not tracked to completion.

### Making It More Realistic

* **Interrupt participants** at decision points: "Your CISO's phone is going to voicemail. What now?"
* **Add emotional pressure**: "The CEO is in the room and very upset."
* **Introduce information overload**: Two injects at once
* **Add a technical failure**: "The SIEM is down. You're working from EDR logs only."
* **Add a personnel challenge**: "Your IR Lead is on vacation. Who takes command?"

---

## Connecting to Real Incidents

After each real incident, compare actual performance against the exercise rubric:

* Did the real incident expose gaps that the exercise should have found?
* Did the exercise correctly predict the weakest areas?
* Should the next exercise focus on the same scenario with modifications, or a completely different attack type?

This creates a virtuous cycle: exercises improve the IR program, real incidents validate and improve exercises, and both improve organizational resilience.
