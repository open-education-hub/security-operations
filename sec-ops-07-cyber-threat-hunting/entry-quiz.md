# Entry Quiz: Session 07 — Cyber Threat Hunting and Intelligence Gathering

**Instructions:** This quiz assesses your baseline knowledge before the session.
Answer to the best of your ability.
Results help calibrate the session to your learning needs.

**Time:** 10 minutes

**Questions:** 5 multiple choice

---

## Question 1

What is the primary distinction between threat hunting and reactive security operations (e.g., responding to SIEM alerts)?

**A)** Threat hunting uses more expensive tools than reactive operations.

**B)** Threat hunting proactively searches for threats assuming they may already be present, while reactive operations wait for automated alerts to trigger before investigating.

**C)** Threat hunting is fully automated, while reactive operations require human analysts.

**D)** Threat hunting only works on endpoint data, while reactive operations use network data.

**Correct Answer:** B

**Explanation:** The defining characteristic of threat hunting is its proactive nature — hunters assume adversaries may already be in the environment and actively search for evidence, rather than waiting for signatures or rules to trigger.
Reactive operations depend on known-bad indicators and rules to generate alerts before investigation begins.

---

## Question 2

In the MITRE ATT&CK framework, what does a "Tactic" represent?

**A)** A specific implementation of an attack technique by a named threat actor.

**B)** The adversary's high-level goal or objective at a particular phase of the attack (e.g., Initial Access, Persistence).

**C)** A specific technical method used to achieve a goal, such as using PowerShell for execution.

**D)** A malware family associated with a specific threat actor group.

**Correct Answer:** B

**Explanation:** In ATT&CK, Tactics represent the adversary's tactical goal — the "why" behind an action.
Examples include Initial Access (getting into the network), Persistence (staying after reboot), and Exfiltration (stealing data).
Techniques (the "how") are subordinate to Tactics, and Procedures are specific implementations observed in the wild.

---

## Question 3

What does IOC stand for, and which of the following is the BEST example of one?

**A)** Indicator of Concern; an unusual spike in failed login attempts

**B)** Indicator of Compromise; a SHA256 hash of a confirmed malware file

**C)** Index of Capabilities; a list of ATT&CK techniques used by a threat actor

**D)** Indicator of Compromise; a behavioral pattern such as PowerShell making outbound connections

**Correct Answer:** B

**Explanation:** IOC stands for Indicator of Compromise.
It is a specific artifact left behind by an attack — a file hash, IP address, domain name, or registry key — that can be used to identify whether a specific threat has touched a system.
Option D describes an IOA (Indicator of Attack), which is behavioral.
Option A is not a standard term.

---

## Question 4

You receive a threat intelligence report marked **TLP:AMBER**.
According to the Traffic Light Protocol, who can you legally share this information with?

**A)** Anyone in the global security community, as amber means "proceed with caution."

**B)** Only the original source organization that sent you the report.

**C)** Members of your own organization and clients who have a direct need to know.

**D)** Any organization within your country, as TLP:AMBER is limited by national borders.

**Correct Answer:** C

**Explanation:** TLP:AMBER (per FIRST TLP v2.0) permits sharing with members of your own organization and with clients who have a need to know.
It does NOT permit public disclosure or sharing with the general security community (that would be TLP:GREEN or TLP:CLEAR).
TLP:RED would be even more restricted, limited to the original meeting participants.

---

## Question 5

Which of the following tools is specifically designed as an open-source platform for sharing, storing, and correlating threat intelligence indicators?

**A)** Splunk

**B)** Velociraptor

**C)** MISP (Malware Information Sharing Platform)

**D)** Osquery

**Correct Answer:** C

**Explanation:** MISP (Malware Information Sharing Platform) is specifically designed as a threat intelligence platform for storing and sharing IOCs, correlating events, and distributing intelligence across organizations.
Splunk is a SIEM/data analytics platform.
Velociraptor is a DFIR and endpoint hunting tool.
Osquery exposes OS state as a SQL-like database for endpoint queries.

---

*End of Entry Quiz*
*Review: Session 07 Reading Material*
