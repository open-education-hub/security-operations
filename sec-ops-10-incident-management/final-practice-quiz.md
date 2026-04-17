# Final Practice Quiz: Session 10 — Incident Response and Management

**Format:** 5 short-answer + 2 long-answer questions

**Time:** 45–60 minutes

## Part A: Short Answer (5 × 10 pts)

### Q1: SANS PICERL vs NIST 800-61
Compare the SANS PICERL and NIST SP 800-61 IR frameworks.
What does SANS add that NIST groups together?
Which would you recommend and why?

**Sample Answer:** NIST has 4 phases; SANS PICERL has 6.
SANS explicitly separates "Containment" and "Eradication" (NIST groups them) and separates "Identification" from "Detection".
PICERL also uses "Lessons Learned" explicitly vs NIST's "Post-Incident Activity".
Both are equivalent in practice.
SANS terminology is more commonly used operationally; NIST is the standard for compliance frameworks.

### Q2: GDPR Notification Decision
A company's HR files (employee names, salaries, addresses) were accessed by an attacker who also encrypted the files with ransomware.
The company CEO asks: "Do we need to tell the Data Protection Authority?" What is your answer and why?

**Sample Answer:** Yes.
The encryption is a data breach under GDPR even if no data was visibly exfiltrated, because the data was made unavailable (encryption = loss of availability = Art. 4(12) breach).
Additionally, the access by an unauthorized party (the attacker) before encryption constitutes a confidentiality breach.
The notification to the DPA must be made within 72 hours.
Whether individuals must be notified depends on whether there is high risk to them (salary + address data = yes, likely).

### Q3: Evidence Collection Sequence
Why must you collect volatile evidence before performing network isolation?
Give three specific examples of volatile artifacts that would be lost if isolation happens first.

**Sample Answer:** Network isolation severs the system from the network and may cause side effects that alter system state.
Volatile artifacts lost include: (1) Active network connections (netstat output) — shows current C2 connections and attacker IP; (2) Running processes — may include malware processes that delete themselves on network loss; (3) ARP table — shows recently communicated hosts (lateral movement evidence).

### Q4: Post-Incident Review Root Cause
A phishing incident post-PIR identifies the root cause as "employee clicked a phishing link." Explain why this is NOT an adequate root cause and apply the 5 Whys to find a better one.

**Sample Answer:** "Employee clicked phishing link" is a symptom, not a root cause. 5 Whys: Why was the link clicked? → The email wasn't blocked by the gateway.
Why not? → The domain was newly registered (not yet in blocklists).
Why are new domains not caught? → No threat intel feed for newly registered domains.
Why not? → No budget allocated.
Why no budget? → No process for evaluating threat intel coverage gaps.
ROOT CAUSE: No formal process to evaluate and fund threat intelligence coverage.

### Q5: Containment Decision Trade-off
An APT group has been discovered on your network.
They have been present for 3 weeks (dwell time).
A colleague says: "We should isolate all affected systems immediately." You disagree.
Why might monitoring be preferable over immediate isolation in this scenario?

**Sample Answer:** Immediate isolation of an APT tells the attacker they've been detected, allowing them to: destroy evidence, activate dormant implants on other systems not yet identified, or launch destructive payloads.
With a 3-week dwell time, there are likely additional compromised hosts not yet identified.
Monitoring allows the SOC to: identify the full scope of compromise, observe all C2 channels, capture evidence of the attacker's full capabilities, and coordinate a simultaneous isolation of ALL compromised systems in a planned operation.

---

## Part B: Long Answer (2 × 25 pts)

### Q6: Full Incident Response Plan for Insider Threat (25 pts)

A mid-level IT engineer (access to production servers) has given 2 weeks notice.
Security monitoring detects they are transferring large amounts of files to a personal OneDrive account.
This started 3 days before they gave notice.
HR confirms the engineer had a disciplinary meeting 2 months ago.

a) (5 pts) Classify this incident and assess severity.
b) (10 pts) Write a sequenced containment and investigation plan.
c) (5 pts) What legal/HR constraints affect your response?
How do you handle them?
d) (5 pts) What evidence do you need to preserve for potential legal proceedings?

### Q7: Ransomware IR Communication Plan (25 pts)

A manufacturing company (250 employees, B2B only, processes supplier PII) has a confirmed ransomware incident.
Production line control systems are affected.
The CISO wants you to draft the communication plan.

a) (5 pts) Who needs to be notified, in what order, and within what timeframe?
b) (10 pts) Write the executive brief for the CEO (use the SBAR format).
c) (5 pts) Write the first paragraph of the GDPR notification letter to the DPA.
d) (5 pts) Draft a brief internal communication to all employees explaining the situation without causing panic.
