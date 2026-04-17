# Final Practice Quiz: Endpoint Security Technologies

**Session 05 — Endpoint Security Technologies**
**Purpose:** Exam preparation — short and long answer

**Time:** 35 minutes

**Format:** 5 short-answer questions + 2 long-answer questions

---

**Instructions:**

* Short answer questions: 2–4 sentences each (5 points each)
* Long answer questions: detailed, structured response (15 points each)

---

## Short Answer Questions (5 × 5 = 25 points)

---

**Question 1 (5 points)**

Explain the difference between **fileless malware** and **traditional (file-based) malware**.
Give ONE specific example of how fileless malware executes and why it is harder to detect.

*Write your answer here.*

---

**Question 2 (5 points)**

A Windows system generates Event ID 4698 (Scheduled Task Created) at 3:15 AM.
The task name is `\Microsoft\Windows\CryptSvc\Update` and the action is:

```text
C:\ProgramData\Microsoft\Crypto\update.exe /q /autorun
```

Identify THREE red flags in this event and explain why each is suspicious.

*Write your answer here.*

---

**Question 3 (5 points)**

What is the purpose of the **Sysmon Event ID 22 (DNS Event)**, and how can it be used to detect C2 (Command and Control) communication?
Give a realistic detection scenario.

*Write your answer here.*

---

**Question 4 (5 points)**

Compare **OSSEC** and **Wazuh** as HIDS (Host-Based Intrusion Detection Systems).
What does Wazuh add beyond OSSEC's capabilities?
In what scenario would you choose one over the other?

*Write your answer here.*

---

**Question 5 (5 points)**

Explain the concept of **process injection** in the context of endpoint security.
Name TWO different process injection sub-techniques, describe how each works, and identify which Sysmon event(s) would detect each.

*Write your answer here.*

---

## Long Answer Questions (2 × 15 = 30 points)

---

**Question 6 (15 points)**

**Endpoint Monitoring Architecture Design**

You have been asked to design an endpoint security monitoring architecture for a mid-sized company (500 workstations, 50 servers including 3 Domain Controllers, 20 Linux servers) that currently has no endpoint security monitoring beyond traditional AV.

Design a complete endpoint monitoring architecture that addresses:

a) **What monitoring tools to deploy** on each endpoint type (Windows workstations, Windows servers, Linux servers) and why
b) **Which events/logs to collect** — be specific about Event IDs, Sysmon events, and auditd rules for the most critical detections
c) **How telemetry flows** from endpoints to the SIEM — include log shippers, normalization, and storage considerations
d) **The top 5 detection rules** you would implement first, based on highest return-on-investment for threat detection
e) **What you would NOT do** — one anti-pattern to avoid and why

Your answer should be structured and specific.
Generic answers will not receive full marks.

*Write your answer here.*

---

**Question 7 (15 points)**

**Incident Response Using Endpoint Evidence**

At 14:22 UTC, your SIEM generates a CRITICAL alert:

```text
Rule: LSASS Memory Access by Unsigned Process
Host: DC01.corp.local (Domain Controller)
Process: C:\Windows\Temp\wuagent.exe
Target: C:\Windows\System32\lsass.exe
Access Mask: 0x1FFFFF
Parent Process: powershell.exe
Parent CMD: powershell.exe -nop -enc [Base64]
User: corp\backup_svc
Time: 2024-05-20T14:22:01Z
```

Additionally, your SIEM shows that 10 minutes prior (14:12 UTC), `backup_svc` successfully authenticated to DC01 via an RDP session from `FILESERVER02.corp.local`.

Answer ALL of the following:

a) **Immediate triage:** Is this a true positive?
What is the confidence level, and what specific evidence supports your conclusion?
(3 points)
b) **Scope determination:** What are the worst-case implications if this attack succeeded?
What additional systems might be affected?
(3 points)
c) **Attack chain reconstruction:** Reconstruct the likely attack chain, from initial access through to this event.
What is still unknown?
(3 points)
d) **Immediate response actions:** List the first FIVE actions you take, in priority order.
Explain the reasoning for the order.
(3 points)
e) **Detection gaps:** Identify at least TWO failures in existing detection that allowed the attacker to reach a Domain Controller.
How would you fix each?
(3 points)

*Write your answer here.*

---

## Scoring Rubric

**Short Answer (5 points each):**

* 5 points: Complete, accurate, demonstrates understanding of the concept
* 3–4 points: Mostly correct with minor gaps
* 1–2 points: Partially correct, significant gaps
* 0 points: Incorrect or blank

**Long Answer (15 points each):**

* 13–15 points: Comprehensive, technically accurate, well-structured, demonstrates advanced understanding
* 10–12 points: Good coverage, minor inaccuracies or gaps
* 7–9 points: Basic coverage, some significant gaps
* 4–6 points: Limited understanding demonstrated
* 0–3 points: Major errors or very incomplete

---

*Model answers are in the final-practice-quiz.xml file.*
