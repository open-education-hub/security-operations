# Entry Quiz — Session 06: Incident Analysis in a Threat-Centric SOC

**Purpose:** Assess baseline knowledge before the session

**Questions:** 5 multiple choice

**Time:** 10 minutes

**Passing score:** 3/5 (recommended minimum to proceed without pre-reading)

---

## Question 1

Which of the following best describes an **Indicator of Attack (IOA)**, as opposed to an Indicator of Compromise (IOC)?

A) A file hash of known malware
B) A suspicious IP address observed in network traffic
C) A behavioral pattern that indicates an attack is in progress (e.g., a process injection)
D) A log entry showing a failed login attempt

**Correct answer:** C

**Explanation:** An IOC is a forensic artifact that indicates a system *has been* compromised (file hash, IP, domain).
An IOA is a behavioral signal indicating an attack *is in progress* — e.g., a process injecting into another process is an IOA regardless of whether the process is a known malware file.

---

## Question 2

According to the SANS PICERL model, what phase directly follows Identification?

A) Preparation
B) Eradication
C) Lessons Learned
D) Containment

**Correct answer:** D

**Explanation:** PICERL = Preparation → Identification → **Containment** → Eradication → Recovery → Lessons Learned.
After identifying/confirming an incident, the next step is to limit the blast radius through containment.

---

## Question 3

An analyst is investigating a compromised Windows workstation.
The system is still running and the attacker may still have an active session.
In what order should the analyst prioritize evidence collection?

A) Full disk image first, then memory dump, then network connections
B) Network connections first, then memory dump, then disk image
C) Disk image first, then logs, then memory
D) All evidence types have equal priority and can be collected in any order

**Correct answer:** B

**Explanation:** The order of volatility dictates collecting the most volatile evidence first: network connections and running processes (disappear when isolated/powered off), then memory (lost on power-off), then disk (persistent).
Collecting the disk image first — while an attacker's session is still active — loses the most valuable forensic data.

---

## Question 4

A phishing email is delivered, a user clicks the link, and malware executes.
Which Cyber Kill Chain phase does the malware execution belong to?

A) Delivery
B) Weaponization
C) Exploitation
D) Command and Control

**Correct answer:** C

**Explanation:** In the Cyber Kill Chain: Delivery = the email reaching the user's inbox; Exploitation = the actual triggering of the vulnerability or user action that causes malicious code to run.
The malware execution is the exploit stage.
Command and Control comes after installation, when the malware establishes its callback.

---

## Question 5

Your SIEM generates 500 alerts per day. 490 of them are false positives.
An analyst who dismisses all alerts without investigation will technically have a 98% "correct" rate on false positives.
What is the fundamental problem with this approach?

A) It wastes too much SIEM storage
B) The 2% real incidents (10 per day) remain undetected and unresponded to
C) It increases MTTR (Mean Time to Respond) for false positives
D) It violates PCI-DSS compliance requirements

**Correct answer:** B

**Explanation:** Alert fatigue and the practice of dismissing all alerts is a real SOC failure mode.
The 10 genuine incidents per day — which could include ransomware, credential theft, or data breaches — go undetected.
The metric "false positive rate" is only meaningful if all alerts receive actual analysis.
This is the core argument for threat-centric, intelligence-driven analysis rather than purely compliance-driven alert processing.

---

*End of Entry Quiz*
