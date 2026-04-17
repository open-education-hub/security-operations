# Drill 01 (Advanced): Tabletop Exercise Design

> **Level:** Advanced
> **Estimated time:** 90–120 minutes
> **Format:** Individual or team project
> **Deliverable:** Complete, runnable tabletop exercise package

---

## Overview

This drill asks you to take the role of **exercise designer and facilitator**.
Your task is to design a complete, realistic, multi-stakeholder tabletop exercise for a specific organization and then facilitate it (or describe how you would facilitate it).

Designing a tabletop exercise is a higher-order skill than simply participating in one.
It requires you to understand:

* How to create realistic, pressurized scenarios without being unfair
* How to test specific IR plan gaps rather than just "putting on a show"
* How to structure inject timing to maximize learning
* How to evaluate and debrief effectively

---

## Organization Profile

You are the external security consultant hired by **EduPlatform S.r.l.**, an Italian ed-tech company.

**Profile:**

* 250 employees (largely remote workforce across 5 EU countries)
* 850,000 student users (ages 14–22) — all EU-based
* Product: online learning platform with video streaming, assignments, and student grades
* Revenue: EUR 25M annually
* Data processed: Student name, date of birth, school/institution, academic performance data, parent/guardian data for under-18 students, payment data (credit card via Stripe, not stored internally)
* Cloud infrastructure: AWS (eu-west-1, Ireland)
* Compliance obligations: GDPR (special attention: processing of minors' data under GDPR Art. 8 and potential Art. 9 for learning disability accommodations), NIS2 (classified as Important Entity in digital education sector)
* Security maturity: Low-to-medium. EDR deployed 3 months ago. SIEM not yet operational. IR Plan exists on paper but has never been tested.
* DPO: external DPO service provider
* No dedicated IR team — security is handled by 1 Security Manager and 2 IT staff

**Known IR weaknesses** (from a recent maturity assessment):

1. No ransomware playbook
1. GDPR notification obligations not well understood by technical staff
1. Parent/guardian notification for minors is not addressed
1. Cloud incident response procedures not documented
1. No out-of-band communication channel for major incidents

---

## Your Assignment

### Part 1: Exercise Objectives (15 minutes)

Define 5 specific, measurable exercise objectives for EduPlatform.
Each objective should:

* Be observable during the exercise (can you watch someone succeed or fail at it?)
* Map to one of the known IR weaknesses
* Include a success criterion

**Format:**

```text
Objective 1: [Title]
  What we're testing: [description]
  Observable success criterion: [specific, observable behavior]
  Maps to weakness: [which weakness from the list]
```

### Part 2: Scenario Design (30 minutes)

Design a realistic tabletop scenario for EduPlatform.
The scenario must:

* Be relevant to EduPlatform's specific threat model (ed-tech, student data, AWS cloud)
* Include personal data of minors (to test knowledge of heightened GDPR obligations)
* Create genuine uncertainty at multiple decision points
* Force technical and legal/regulatory discussions
* Be completable in a 3-hour exercise session

**Deliverable 2a: Scenario Background Document** (what facilitator reads to participants at start)

Write a 400-500 word scenario setup that introduces:

* The initial trigger event
* The immediate observable symptoms
* The relevant context (what the company was doing, what systems are affected)

**Deliverable 2b: Inject Schedule**

Design 6–8 injects timed over a 3-hour window.
For each inject, specify:

| Inject | Time | Inject content (what participants learn) | Objective tested | Expected team response |
|--------|------|------------------------------------------|-----------------|------------------------|
| #1 | T+0 | | | |
| #2 | T+20 | | | |
| ... | | | | |

**Deliverable 2c: Inject Cards**

Write 3 of your injects in full "inject card" format (ready to hand to participants):

```text
══ INJECT #[X] ══ Deliver at T+[time] ══════════════════════
[Full text of what participants are told — as if they received this information]
Discussion questions after inject:

  1. [Question to focus team discussion]

  2. [Question]
══════════════════════════════════════════════════════════════
```

### Part 3: Facilitation Guide (20 minutes)

Write a facilitation guide for the exercise.
Include:

1. **Pre-exercise checklist** (what facilitator prepares beforehand)
1. **Opening script** (verbatim, 200–300 words — what you say at 9:00 to kick off)
1. **Decision point analysis**: For each of the 5 key decision points in your scenario, describe:
   * What decision is being faced
   * What the "correct" action is
   * What common mistakes to watch for
   * How to intervene if the team goes completely off-track without giving away the answer

1. **Debrief questions** (5 specific questions for the hot wash)

### Part 4: Evaluation Rubric (15 minutes)

Design a scoring rubric for EduPlatform's exercise.
The rubric should:

* Be specific to EduPlatform (not generic)
* Test the 5 objectives you designed
* Be scorable (each item worth specified points)
* Distinguish between "excellent," "adequate," and "needs work"

### Part 5: Exercise Report Template (20 minutes)

Create a complete exercise report template that EduPlatform can use to document the results of your designed exercise.
The template should have sections for:

* Executive summary
* Exercise objectives vs outcomes
* Key findings (strengths and weaknesses)
* Action items table
* Recommendations for IR program improvement

---

## Evaluation Criteria for This Drill

| Component | Points |
|---------|--------|
| Objectives are specific, observable, and map to weaknesses | 20 |
| Scenario is realistic and relevant to EduPlatform's threat model | 20 |
| Inject schedule creates appropriate pacing and covers all objectives | 20 |
| Inject cards are written in realistic, pressurized language | 15 |
| Facilitation guide includes decision point analysis | 15 |
| Evaluation rubric is specific and measurable | 10 |
| Total | 100 |

---

## Advanced Challenge (Optional, +20 bonus points)

After designing the exercise, write a 500-word reflection on:

*"What are the limitations of tabletop exercises as a method for validating IR readiness?
What does a tabletop exercise test well, and what does it test poorly?
What should supplement tabletop exercises in a mature IR program?"*

---

## Solution

See: `../../solutions/drill-01-solution/solution.md`
