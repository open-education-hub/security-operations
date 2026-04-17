# Solution: Drill 01 (Advanced) — Tabletop Exercise Design for EduPlatform

This solution provides a complete worked example of a tabletop exercise package for EduPlatform S.r.l.
Instructors should evaluate student submissions against the principles and structures demonstrated here, not as exact-match templates — good exercise design has many valid approaches.

---

## Part 1: Exercise Objectives

```text
Objective 1: Ransomware Initial Response Protocol
  What we're testing: Whether technical and non-technical staff can identify
  ransomware activity, declare an incident, and take correct first actions
  (isolate vs. shut down; preserve vs. destroy evidence) within 15 minutes.
  Observable success criterion: Team correctly isolates affected AWS instances
  WITHOUT terminating them (preserves forensic artifacts) and the Security Manager
  declares a formal incident within T+10.
  Maps to weakness: #1 — No ransomware playbook

Objective 2: GDPR Notification Obligation Recognition
  What we're testing: Whether the team can correctly identify that a breach
  involving student data triggers GDPR notification obligations and can state
  the correct timeline (72 hours to DPA, "without undue delay" to individuals
  for high-risk breaches).
  Observable success criterion: Team correctly identifies that the Italian
  Garante is the lead DPA (main establishment is Italy), and someone raises
  the 72-hour clock within T+30 of confirmed breach.
  Maps to weakness: #2 — GDPR notification obligations not understood

Objective 3: Minors' Data Heightened Obligations
  What we're testing: Whether the team knows that data of users under 18 triggers
  heightened obligations: parent/guardian notification, and that special attention
  must be given to "likely high risk" assessment for children.
  Observable success criterion: Team specifically calls out the need to notify
  parents/guardians of under-18 students (not just the students) and references
  this as a distinct obligation from standard data subject notification.
  Maps to weakness: #3 — Parent/guardian notification not addressed

Objective 4: Cloud Incident Response — AWS Isolation
  What we're testing: Whether the IT staff understand how to isolate
  compromised AWS resources (security groups, instance stop vs. terminate,
  snapshot before stop, CloudTrail log preservation) without simply
  terminating instances and destroying evidence.
  Observable success criterion: IT staff describe creating a snapshot before
  stopping instances, and modifying security groups to a "deny-all" isolating
  group rather than terminating instances.
  Maps to weakness: #4 — Cloud IR procedures not documented

Objective 5: Out-of-Band Communication Under Incident
  What we're testing: Whether the team recognizes that if AWS infrastructure
  is compromised, email and Slack (hosted in the cloud) may be compromised or
  unavailable, and pivots to an out-of-band channel.
  Observable success criterion: Someone explicitly raises the concern about
  using potentially compromised communication channels and proposes an
  alternative (phone bridge, Signal group, etc.) before sensitive IR
  discussion continues.
  Maps to weakness: #5 — No out-of-band communication channel
```

---

## Part 2: Scenario Design

### Deliverable 2a: Scenario Background Document

**Exercise scenario: "The Gradebook Attack"**

*Read to participants at the start of the exercise:*

---

It is Tuesday morning, 08:47 CEST.
Your Security Manager has just arrived at the office and is reviewing overnight monitoring alerts.
EduPlatform's production environment runs entirely on AWS eu-west-1 (Ireland).
The platform currently has 340,000 active users, including 210,000 students between ages 14 and 17 who are enrolled in school partner programs across Italy, France, Spain, Poland, and Germany.

At 08:47, the Security Manager receives an automated alert from the EDR (deployed to the 3 IT staff laptops, but not to the AWS environment directly).
The alert says: "Anomalous API activity detected: AWS IAM role `eduplat-prod-app-role` has performed 1,200 S3 GET operations in the past 10 minutes on bucket `eduplat-student-data-prod`.
Source IP: 185.234.219.44 (external, no association with EduPlatform known IPs)."

A second alert follows at 08:49: "AWS Cost Anomaly Detection: Unusual compute spending. 47 new EC2 instances of type c5.4xlarge launched in eu-west-1 in the last 12 minutes.
Estimated cost impact: USD 3,200 per hour."

By 08:52, the platform operations lead notices that students logging in are being redirected to a page showing a ransom note: "YOUR DATA HAS BEEN ENCRYPTED.
To recover your platform and prevent the release of 850,000 student records, send 15 BTC to [wallet].
You have 72 hours."

The S3 bucket `eduplat-student-data-prod` contains: student full name, date of birth, school/institution code, academic performance data (grades, teacher comments), learning disability accommodation notes (for approximately 12,000 students), and parent/guardian contact information for all under-18 students.
No payment card data is stored (Stripe handles this externally).

Your team is now online.
The Security Manager, the external DPO service provider (available by phone), and the two IT staff are present.
You have no IR playbook for this scenario.

**The exercise begins now.
It is T+0.
Your platform is down, your data may be exfiltrated, and you have no playbook.
What do you do?**

---

### Deliverable 2b: Inject Schedule

| Inject | Time | Inject content | Objective tested | Expected team response |
|--------|------|---------------|-----------------|----------------------|
| #1 | T+0 | Initial scenario brief: EDR alert + EC2 cost anomaly + ransom note on platform | O1, O4 | Declare incident; identify AWS isolation as first priority |
| #2 | T+15 | AWS CloudTrail shows IAM key `ci-deploy-prod` was committed to a public GitHub repository 6 days ago; that key was used for all 1,200 S3 GET operations | O4 | Revoke/rotate compromised IAM key; snapshot affected EC2 instances before isolation |
| #3 | T+25 | S3 bucket inventory confirms: 340,000 student records accessible. Exfiltration of approx. 15GB confirmed via CloudTrail GetObject calls. Includes 12,000 records with disability accommodation notes | O2, O3 | Recognize special category data (Art. 9 — disability); trigger GDPR clock; DPO engagement |
| #4 | T+40 | External DPO calls in: "I need to know: is this notifiable to the Garante? And what about parents?" | O2, O3 | State 72h clock started at T+25 (confirmed exfiltration); confirm Garante is lead DPA; identify parent/guardian notification for under-18 |
| #5 | T+55 | IT staff member says: "I'm going to post an update to the #incident Slack channel." | O5 | Someone should flag that Slack may be compromised or hosted on AWS infrastructure; propose out-of-band alternative |
| #6 | T+70 | Ransomware decryption offer: "We will provide the key for 15 BTC. You have 48 hours left." | O1 | Team must decide: negotiate/pay vs. restore from backup; this tests whether they know to check backup integrity first |
| #7 | T+85 | Backup check reveals last clean backup is from 6 days ago — the same day the GitHub leak occurred. Backups since that date may be encrypted or tampered | O1, O4 | Escalate to P1 (clean recovery path uncertain); update incident scope |
| #8 | T+100 | School partner from France calls: "Our students' parents are calling us — how did their children's data end up on a hacker forum?" | O2, O3 | Confirm notification obligation to French parents; coordinate with DPC (Ireland, where AWS eu-west-1 is) AND Garante (Italy, main establishment) |

---

### Deliverable 2c: Inject Cards

```text
══ INJECT #3 ══ Deliver at T+25 ══════════════════════════════════════════
You receive the following report from AWS:

  CloudTrail Summary — Past 6 days:
  IAM Role: ci-deploy-prod
  Bucket: eduplat-student-data-prod
  Operation: GetObject — 1,247 calls
  Total data retrieved: 14.7 GB
  Source IP: 185.234.219.44 (first seen 6 days ago)

The S3 bucket manifest you pull confirms the following data was in scope:
  - Student records (name, DOB, institution): 340,000 records
  - Academic performance data (grades, comments): 340,000 records
  - Learning disability accommodation notes: 12,000 records [FLAGGED: ART. 9]
  - Parent/guardian contact data for under-18 students: 217,000 records

The exfiltration appears complete. All files were retrieved.

Discussion questions:

  1. When exactly does the GDPR 72-hour clock start — and to which DPA do you

     notify first?
  2. The 12,000 disability accommodation records are special category data under
     GDPR Article 9. How does this change your notification and response obligations?
══════════════════════════════════════════════════════════════════════════

══ INJECT #5 ══ Deliver at T+55 ══════════════════════════════════════════
[IT staff member, out loud]:

"OK, I'm going to coordinate the next steps over Slack. Let me create an incident
channel — #incident-2025-ransomware. I'll add everyone there so we can document
what we're doing and keep the communication thread clean."

[Facilitator note: wait 10 seconds. If no one raises an objection, prompt with:]
"Is everyone comfortable using Slack for incident coordination right now?"

Discussion questions:

  1. Why might using Slack (or corporate email) during this incident be

     problematic?
  2. What alternative communication channels should your organization have
     pre-established for exactly this scenario?
══════════════════════════════════════════════════════════════════════════

══ INJECT #7 ══ Deliver at T+85 ══════════════════════════════════════════
The IT lead has just checked the backup system. He reports:

  "I have good news and bad news. Good news: we have daily backups going back
  3 months. Bad news: the last backup was taken each night automatically —
  including after the IAM key was compromised. The backup agent uses the same
  compromised IAM role to write to S3. I can't confirm whether backups from the
  past 6 days are clean or whether they also have encrypted files in them."

  "Our last confirmed-clean backup is from 6 days ago, before the key was
  leaked to GitHub. We would lose 6 days of student data, grades, and
  platform activity if we restore from that point."

Discussion questions:

  1. Do you restore from the 6-day-old backup, accepting the data loss?

     Or do you attempt to recover from a more recent (potentially compromised)
     backup? What is the decision framework?
  2. What does this tell you about your backup architecture and what you would
     change going forward?
══════════════════════════════════════════════════════════════════════════
```

---

## Part 3: Facilitation Guide

### Pre-Exercise Checklist

* [ ] Print inject cards and seal in envelopes labelled with deliver times
* [ ] Set up separate out-of-band communication channel (phone bridge or Signal group) — do not share until Inject #5
* [ ] Confirm DPO service provider is available by phone (for Inject #4)
* [ ] Prepare a blank whiteboard / large paper for timeline tracking
* [ ] Assign a note-taker who is not a participant
* [ ] Brief any "role-players" (e.g., someone to play the French school partner at T+100)
* [ ] Confirm participants understand: this is a no-fault exercise; all decisions are discussed, not judged
* [ ] Have printed copies of: GDPR Art. 33 text, NIS2 notification timelines, EduPlatform org chart

### Opening Script (T-5 minutes)

*Read this verbatim to participants:*

---

"Good morning.
Thank you for participating in today's exercise for EduPlatform.
My name is [facilitator name], and I'll be guiding the session.

Before we begin, a few ground rules.
First: this is a learning exercise, not an audit.
There are no wrong people in this room, only wrong decisions — and the goal is to find the decisions we haven't gotten right yet, so we can fix them before a real incident.
Second: speak freely.
If you don't know something, say so.
That's exactly the kind of gap we're here to identify.
Third: try to behave as you would in a real incident.
Don't look ahead for answers; work with what you have.

Today's scenario is a ransomware and data exfiltration incident at EduPlatform.
The scenario is realistic and based on incidents that have happened to comparable organizations.
We'll run for approximately three hours, with injects delivered at intervals.
I will occasionally pause the exercise to ask clarifying questions or guide discussion — that is normal and expected.

A note on roles: you each have your real job title for this exercise.
The Security Manager is the incident commander unless the team decides to escalate.
The IT staff are your technical responders.
The DPO will be available by phone from T+20 onward.

One last thing: the clock starts when I read you the scenario background.
From that moment, decisions have consequences.
Ready?

Let's begin."

---

### Decision Point Analysis

**Decision Point 1 (T+5): Isolate instances vs. terminate?**

* Decision: Whether to terminate (destroy) compromised EC2 instances or isolate them
* Correct action: Create snapshots of all affected EC2 instances, then modify their security groups to deny all ingress/egress. Do NOT terminate — this destroys forensic memory artifacts.
* Common mistake: "Let's just terminate the instances to stop the attack spreading"
* Intervention if off-track: "Before you terminate — once you do that, you lose the volatile memory of that instance forever. Is there anything you'd want to capture from memory first?"

**Decision Point 2 (T+28): When does the GDPR clock start?**

* Decision: Identifying the correct start time for the 72-hour notification clock
* Correct action: Clock starts at T+25 when the CloudTrail evidence confirms exfiltration — this is the moment of *awareness of a likely breach*. Not from the ransom note at T+0 (unconfirmed breach) but also not after the investigation is "complete."
* Common mistake: Starting the clock from the ransom note, or saying "we'll notify after the investigation"
* Intervention: "When exactly did EduPlatform become *aware* of a likely breach of personal data? What does GDPR say about notification timing relative to certainty?"

**Decision Point 3 (T+35): Which DPA to notify?**

* Decision: Identifying the lead supervisory authority
* Correct action: The Italian Garante (EduPlatform S.r.l. is Italian-registered = main establishment in Italy = Garante is LSA). However, because AWS is in Ireland and children in France/Spain/Germany/Poland are affected, "concerned authorities" will be involved by the Garante.
* Common mistake: "We should notify all 5 countries' DPAs directly"
* Intervention: "Where is EduPlatform's main establishment? What does the GDPR one-stop-shop mechanism say about who receives the primary notification?"

**Decision Point 4 (T+55): Using Slack for incident communication**

* Decision: Whether corporate Slack is a safe incident coordination channel
* Correct action: Raise concern that Slack may be compromised, hosted on infrastructure that is potentially under attacker control, or inaccessible. Switch to phone bridge or a pre-established out-of-band channel.
* Common mistake: Continuing to use Slack without raising the concern
* Intervention (if concern is not raised): "Quick check — where is your Slack environment hosted? Is it possible the attacker has access to your Slack workspace?"

**Decision Point 5 (T+90): Restore from 6-day-old backup or attempt recovery?**

* Decision: Whether to accept 6-day data loss vs. risk restoring from potentially compromised backup
* Correct action: Do not restore from backups whose integrity cannot be verified. Restore from the last known-clean backup (6 days ago). Accept the data loss. Document the decision and its justification. Add backup integrity verification to post-incident improvements.
* Common mistake: "Let's try the most recent backup anyway — maybe it's clean"
* Intervention: "If you restore from a backup that contains encrypted or attacker-modified files, what happens to your production environment?"

### Debrief Questions (Hot Wash)

1. "At what point did the team feel most uncertain? What information were you missing that would have helped?"
1. "Walk me through the GDPR notification decision: who are you notifying, when, and why? Where did the team agree, and where was there disagreement?"
1. "The out-of-band communication question — did anyone flag it before I introduced Inject #5? What does that tell us about our current incident communication plan?"
1. "On the backup question: what would we need to change about our backup architecture to avoid this situation in a real incident?"
1. "We processed data for 210,000 minors. What specifically is different about how you handled — or should have handled — the parent/guardian notification, compared to standard data subject notification?"

---

## Part 4: Evaluation Rubric

| Objective | Excellent (Full points) | Adequate (Partial) | Needs Work (0) | Points |
|---------|------------------------|-------------------|---------------|--------|
| O1: Ransomware initial response | Isolates instances via security groups after snapshotting; declares incident within T+10; does NOT terminate instances | Isolates instances but skips snapshots; or declaration delayed to T+20 | Terminates instances; or fails to isolate; no incident declaration | 20 |
| O2: GDPR notification timeline | Clock correctly set at T+25 (exfiltration confirmation); correct 72h deadline calculated; identifies Garante as lead DPA; staged notification mentioned | Correct DPA but wrong clock start; or correct clock but wrong DPA | No notification triggered; or wrong framework cited | 20 |
| O3: Minors' data handling | Explicitly identifies parent/guardian notification for under-18; notes disability data as Art. 9 special category; heightened risk assessment applied | Identifies parent notification but misses Art. 9 angle; or vice versa | No distinction made between adult and minor data; no parent notification |  20 |
| O4: AWS cloud isolation | Creates snapshots before stopping instances; rotates compromised IAM key; modifies security groups to deny-all; preserves CloudTrail logs | Correct isolation but missing snapshot step; or does not rotate IAM key | Terminates instances; no isolation procedure demonstrated | 20 |
| O5: Out-of-band communication | Flags Slack concern before or immediately upon Inject #5; names alternative channel; explains why | Flags concern after prompted; or names alternative but cannot explain why | Does not flag Slack issue even when prompted; no alternative proposed | 20 |
| **Total** | | | | **100** |

---

## Part 5: Exercise Report Template

```text
═══════════════════════════════════════════════════════════
TABLETOP EXERCISE REPORT
EduPlatform S.r.l. — "The Gradebook Attack"
Date: [Date]
Facilitator: [Name]
Duration: [Actual duration]
Participants: [List of roles present]
═══════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
[3–5 sentences summarizing: purpose of exercise, overall performance,
top 2 strengths, top 2 weaknesses, critical finding if any]

═══════════════════════════════════════════════════════════

EXERCISE OBJECTIVES vs. OUTCOMES

| Objective | Target | Achieved? | Notes |
|---------|--------|---------|-------|
| O1: Ransomware initial response | Instance isolation via SG; no termination | Yes / Partial / No | |
| O2: GDPR notification timeline | 72h clock set correctly; Garante identified | | |
| O3: Minors' data | Parent notification called out; Art. 9 noted | | |
| O4: AWS cloud isolation | Snapshot + SG isolation + IAM rotation | | |
| O5: Out-of-band comms | Slack concern raised; alternative identified | | |

═══════════════════════════════════════════════════════════

KEY FINDINGS

Strengths identified during exercise:

1. [Describe what the team did well with specific examples from the exercise]

2.
3.

Weaknesses / gaps identified:

1. [Describe with specific inject/moment reference and team behavior]

2.
3.

Critical finding (if any):
[Flag any finding that represents an urgent risk requiring immediate action
before the next incident, e.g., "No out-of-band communication plan exists
and the team would have continued using potentially compromised channels
throughout the incident."]

═══════════════════════════════════════════════════════════

ACTION ITEMS

| # | Action | Owner | Target Date | Priority |
|---|--------|-------|------------|---------|
| 1 | Draft and publish ransomware IR playbook | Security Manager | [30 days] | HIGH |
| 2 | Create out-of-band incident bridge (phone + Signal) | IT Lead | [7 days] | HIGH |
| 3 | Document AWS cloud IR procedure (isolation, snapshot, IAM rotation) | IT Staff | [30 days] | HIGH |
| 4 | Brief all staff on GDPR 72h notification requirement | DPO | [14 days] | HIGH |
| 5 | Add parent/guardian notification procedure for under-18 data | DPO + Legal | [21 days] | HIGH |
| 6 | Review backup IAM permissions — isolate backup role from production | IT Lead | [14 days] | HIGH |
| 7 | Test backup restore procedure to verify backup integrity | IT | [30 days] | MEDIUM |
| 8 | Conduct follow-up tabletop exercise in 6 months | Security Manager | [6 months] | MEDIUM |

═══════════════════════════════════════════════════════════

RECOMMENDATIONS FOR IR PROGRAM IMPROVEMENT

1. [Prioritized recommendation with brief justification]

2.
3.
4.
5.

Next exercise suggested: [Topic / scenario / date]

═══════════════════════════════════════════════════════════
Prepared by: [Facilitator name]
Reviewed by: [DPO / Security Manager]
Distribution: [Management / Restricted]
Date of report: [Date]
═══════════════════════════════════════════════════════════
```

---

## Advanced Challenge: Limitations of Tabletop Exercises

*Model response (500 words):*

Tabletop exercises are a foundational IR readiness tool, but their limitations are as important to understand as their strengths.

**What tabletop exercises test well:** They are excellent for testing whether participants know *what to do* — decision frameworks, regulatory obligations, escalation chains, and communication priorities.
A tabletop exercise will reliably expose whether the team knows the GDPR 72-hour clock, whether they understand who the lead DPA is, and whether they can name the right first action for a ransomware event.
They also test team dynamics: who speaks up, who defers, and whether decision authority is clear.
These social and procedural gaps are almost impossible to identify without a structured exercise.

**What tabletop exercises test poorly:** They do not test *whether people can execute* under pressure.
In a real P1 incident at 03:00, someone fumbling through the AWS console in a panic, unable to remember how to modify a security group, is a different problem than someone who correctly states "I would modify the security group" during a Tuesday morning discussion.
Tabletops cannot replicate: the cognitive load of a real incident, the physical fatigue of a night-time response, the simultaneous noise of 40 inbound Slack messages and a CEO demanding updates every 20 minutes, or the muscle memory of executing CLI commands under stress.

Specifically, tabletop exercises poorly validate: (a) technical IR capabilities — whether your forensics tooling actually works, whether your SIEM can handle the log volume, whether your backup restoration takes 2 hours or 8; (b) communication under ambiguity — in a real incident, information arrives inconsistently and contradictorily, in ways a scripted inject cannot fully simulate; (c) vendor and third-party dependencies — your IR retainer, your cloud provider's support, your legal counsel's availability at 2am.

**What should supplement tabletop exercises in a mature IR program:**

First, **functional exercises** — participants actually execute procedures.
IT staff actually isolate a VM, actually run memory capture commands, actually log in to the backup system and restore a file.
This tests whether the procedures work, not just whether people can describe them.

Second, **technical red team exercises** — a real adversary attempting real compromise of a scoped part of the environment, with the IR team responding to real alerts.
Nothing replaces the experience of seeing an EDR alert appear and having to make real decisions.

Third, **playbook drills** — timed exercises where an individual must complete a specific procedure (e.g., "contain this host using our EDR console") within a time limit.
These build muscle memory.

Fourth, **communication drills** — periodic tests of the incident notification chain: can you reach all 8 people on the escalation list within 15 minutes at any time of day?

The mature IR program treats tabletop exercises as the *entry point* to resilience testing — useful for identifying the most obvious gaps, but insufficient on their own.
Organizations that conduct only tabletops and believe they are "prepared" have created a comfortable illusion.
Real preparedness requires exercises that actually hurt a little.
