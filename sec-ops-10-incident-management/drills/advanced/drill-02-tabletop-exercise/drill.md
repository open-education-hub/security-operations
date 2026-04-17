# Drill 02 (Advanced) — Tabletop Exercise Design and Facilitation

**Estimated time:** 3–4 hours (design phase: 90 min; facilitation: 30–60 min; gap analysis: 30 min)

**Difficulty:** Advanced

**Format:** Individual design + group facilitation (in-class component)

---

## Objective

Design, facilitate, and debrief a realistic tabletop exercise for a fictional organization.
This drill develops your ability to plan structured IR exercises, identify plan gaps through simulation, and produce actionable improvement recommendations.

---

## Your Organization

**SecurBank** — a regional bank headquartered in Warsaw, Poland.

| Attribute | Details |
|-----------|---------|
| Size | 500 employees; 85,000 retail banking customers |
| Services | Retail banking, mortgage lending, investment products |
| Infrastructure | On-premises core banking system + Microsoft 365 + SaaS HR platform (PeopleSoft Cloud) |
| Regulatory | Supervised by KNF (Polish Financial Supervisory Authority); GDPR applies; NIS2 essential entity (banking sector) |
| Security maturity | IR plan exists (last updated 18 months ago); no dedicated CISO (Head of IT Security reports to CTO) |

**Exercise audience (roles to be played by participants):**

* Head of IT Security (exercise subject matter expert)
* CTO
* Head of Operations
* Legal Counsel
* Communications Director
* Head of Retail Banking (branch operations)

---

## Part A: Exercise Design (Individual — 90 minutes)

### Step 1: Choose Your Scenario

Choose ONE of the following three attack scenarios for your exercise.
Your choice will determine everything else.

**Scenario Option 1: Business Email Compromise (BEC)**
The CFO receives an email that appears to be from the CEO asking for an urgent €450,000 wire transfer to a new supplier.
The email was sent from a lookalike domain.
The CFO processes the transfer without verbal confirmation.

**Scenario Option 2: Insider Threat — Disgruntled Sysadmin**
A senior sysadmin with access to the core banking system gave notice 2 weeks ago.
On their second-to-last day, overnight, 47,000 customer records (names, IBAN numbers, balances) are found to have been copied to a personal cloud storage account.

**Scenario Option 3: Supply Chain Compromise — SaaS HR Platform**
PeopleSoft Cloud (SecurBank's SaaS HR provider) announces they experienced a breach.
The attacker accessed data for all PeopleSoft Cloud customers.
SecurBank employees' data (names, salaries, bank account numbers, tax identification numbers) may have been exposed.

---

### Step 2: Write Three Scenario Injects

For your chosen scenario, design **three staged injects** that reveal the incident progressively.
Each inject should be 1–2 paragraphs.

**Inject structure requirements:**

* **Inject 1:** Introduces the initial incident with **incomplete information** — the audience should have enough to start responding but not enough to know the full scope
* **Inject 2:** Adds complications — either the incident is spreading, or external pressure arrives (regulators, press, angry customer), or new evidence contradicts the initial assumption
* **Inject 3:** Forces a **decision with no perfect answer** — an ethical dilemma, a resource constraint, or a conflicting obligation (e.g., law enforcement asks you to delay disclosure; you suspect an insider but cannot yet prove it)

---

### Step 3: Write Discussion Questions

For each inject, write **2 discussion questions** that test specific elements of SecurBank's IR plan.
Questions should:

* Have no single "right" answer — they should generate debate
* Reveal gaps in the plan if the plan does not cover the scenario
* Force the audience to make decisions, not just describe what they "should" do

Format your questions as:

* "What does SecurBank do when...?"
* "Who has authority to...?"
* "How does SecurBank communicate with...?"

---

### Step 4: Design the Hot Wash Template

Design a post-exercise debrief format (15–20 minutes) that produces actionable output.
Your template must include:

1. **3 opening questions** to identify gaps in the IR plan
1. **2 questions** to identify communication failures observed during the exercise
1. **A structured format** for capturing action items (who, what, by when)

---

## Part B: Facilitate the Exercise (In-Class — 30–60 minutes)

During the practical session, you will facilitate your tabletop exercise with fellow students playing the organizational roles.

**Facilitator responsibilities:**

1. Present each inject clearly and pause for group discussion
1. Manage time — each inject gets approximately 10 minutes of discussion
1. Probe answers with follow-up questions when the discussion is too superficial
1. Document gaps, disagreements, and decisions during the exercise (not just the clean narrative)
1. Remain neutral — do not reveal the "right answer" during the exercise

**Facilitator technique:**

* If the group agrees too quickly, push back: "Is everyone really comfortable with that decision? What are the risks?"
* If someone gives a textbook answer, ask: "Who exactly does that in your organization? Do you have their number right now?"
* If the group focuses only on technical response, redirect: "What is the Communications Director saying to the press right now?"

---

## Part C: Gap Analysis Report (Individual — 30 minutes)

After the exercise, write a structured gap analysis report.
Your report must identify:

1. **3 IR plan gaps exposed by the exercise** — for each gap, describe:
   * What happened in the exercise that revealed the gap
   * What the current plan says (or doesn't say)
   * The risk this gap creates in a real incident

1. **2 communication failures observed** — for each failure, describe:
   * What the exercise revealed about communication breakdown
   * Who was affected
   * What the consequence would be in a real incident

1. **3 prioritized action items** — for each action item:
   * Specific action (not vague: "improve communication" is not an action)
   * Owner (by role, not name)
   * Target completion date
   * How you would measure whether the action was completed

---

## Part D: Reflection Questions (Individual — 15 minutes)

Answer the following:

1. What surprised you about how the exercise participants responded? Was there disagreement you didn't expect? Were there gaps you hadn't anticipated when designing the exercise?

1. What is genuinely harder to simulate in a tabletop exercise versus a real incident? List at least 3 elements that cannot be effectively tested in a tabletop format.

1. How often should SecurBank conduct tabletop exercises, and of what type? Justify with reference to their risk profile (banking sector, NIS2 essential entity, 18-month-old IR plan).

1. If you were to run this exercise again, what would you change about the design? Be specific.

---

## Evaluation Criteria

Your exercise design and debrief report will be evaluated on:

| Criterion | Weight |
|-----------|--------|
| Realism of the scenario and injects | 25% |
| Quality of discussion questions (do they reveal gaps?) | 20% |
| Facilitation technique (did you draw out the right discussions?) | 20% |
| Gap analysis quality (specific, accurate, actionable) | 25% |
| Reflection depth | 10% |

---

## Hints

* The best injects are ones where reasonable people disagree — if everyone immediately agrees on the right answer, the inject isn't testing anything useful
* Inject 3's "no perfect answer" works best when there is a genuine tension: legal obligation vs. law enforcement request; speed vs. accuracy in public communication; isolation vs. business continuity
* The communications questions are the ones most exercise designers skip — but in real incidents, communication failures are often more damaging than technical failures
* Action items must be SMART: Specific, Measurable, Achievable, Relevant, Time-bound. "Improve our IR plan" is not an action item.
* Good facilitation means staying curious, not leading the group to your predetermined answer
