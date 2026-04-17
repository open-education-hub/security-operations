# Final Quiz: Session 09 — SOC Workflow and Automation

**Format:** 9 multiple-choice questions (1 correct answer each)

**Purpose:** Assess learning outcomes from the session

---

### Question 1

Which of the following alert closure classifications should trigger a rule tuning review?

A) True Positive — Escalated
B) **False Positive — rule incorrectly fired** ✓
C) Benign True Positive — authorized activity
D) True Positive — Contained

---

### Question 2

Your SOAR playbook automatically isolates any host where the AV detects malware.
A production database server triggers the detection (a false positive from a new AV signature).
The server is automatically isolated and 500 users lose database access for 2 hours.
What design flaw caused this?

A) The SOAR platform was incorrectly configured
B) The AV signature database was out of date
C) **No whitelist of critical servers was configured for automatic isolation actions** ✓
D) The isolation action should have used a different API endpoint

---

### Question 3

What is the difference between MTTD and MTTR?

A) MTTD measures false positive rate; MTTR measures true positive rate
B) MTTD measures network detection speed; MTTR measures endpoint recovery time
C) **MTTD measures the time from attack start to detection; MTTR measures the time from detection to resolution** ✓
D) They measure the same thing but for different severity levels

---

### Question 4

In a SOAR playbook, which type of action should ALWAYS require human approval before execution?

A) Querying VirusTotal for an IP address
B) Creating a ticket in the case management system
C) Sending a notification email to the SOC team
D) **Blocking an IP address at the perimeter firewall** ✓

---

### Question 5

A SOC team's P2 SLA is 4 hours MTTR.
In the past month, 12 out of 60 P2 cases breached the SLA.
What is the SLA compliance rate?

A) 12%
B) 20%
C) 60%
D) **80%** ✓

*Compliance rate = (60-12)/60 = 48/60 = 80%*

---

### Question 6

A security case has been in PENDING status for 6 hours.
The analyst put it in PENDING waiting for the system owner to confirm whether a remote login was authorized.
No response has been received.
Which action is most appropriate?

A) Close the case as a false positive
B) Continue waiting in PENDING status indefinitely
C) Escalate to Tier 3 for advanced analysis
D) **Attempt direct contact through an alternative channel (phone/Teams); escalate to Tier 2 if still no response** ✓

---

### Question 7

Which of the following is the best description of a SOAR playbook?

A) A database of known attack signatures used for detection
B) A formal contract between the SOC and the business defining response times
C) A log analysis query used in SIEM to correlate events
D) **A documented, automated workflow that responds to a specific type of security alert** ✓

---

### Question 8

A SOC analyst designs a playbook that automatically blocks a source IP at the firewall if a brute force alert fires and the IP has a VirusTotal score above 3.
The next day, a legitimate penetration test from an authorized external firm is automatically blocked, disrupting a scheduled engagement.
What automation pitfall does this illustrate?

A) Incorrect API integration between SOAR and the firewall
B) Insufficient threat intelligence data from VirusTotal
C) **Missing an exclusion list for authorized/known sources before executing destructive actions** ✓
D) The playbook trigger threshold was set too low

*Even correct automation logic fails without an allowlist of authorized IPs, scheduled maintenance windows, and known pen-test ranges.
All destructive actions must check an exclusion list first.*

---

### Question 9

A SOC classifies its playbooks into three types: *preventive* (block before impact), *detective* (enrich and alert), and *responsive* (contain and remediate).
A new playbook is triggered by a phishing email detection — it extracts URLs, checks them against a threat feed, and creates a TheHive case for analyst review.
No automated blocking or containment occurs.
Which type is this playbook?

A) Preventive
B) **Detective** ✓
C) Responsive
D) Hybrid preventive-responsive

*A detective playbook gathers intelligence and surfaces findings to an analyst without taking containment action.
It detects and informs — it does not block or remediate.*
