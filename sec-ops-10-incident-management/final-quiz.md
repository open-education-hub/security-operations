# Final Quiz: Session 10 — Incident Response and Management

**Format:** 15 multiple-choice questions (1 correct answer each)

**Purpose:** Assess mastery of Session 10 content

**Pass:** 10/15 or above (67%)

---

### Question 1

During a ransomware incident response, an analyst shuts down the infected server immediately to "stop the spread." What critical error was made?

A) The server should have been reimaged, not shut down
B) **Volatile evidence (RAM contents, active network connections) was permanently destroyed** ✓
C) Shutting down prevents forensic disk imaging
D) The action violated chain of custody requirements

---

### Question 2

You have confirmed a personal data breach at 14:00 UTC on Monday.
Customer names and email addresses were exfiltrated.
The GDPR 72-hour notification deadline expires at:

A) 14:00 UTC on Tuesday
B) 14:00 UTC on Wednesday
C) **14:00 UTC on Thursday** ✓
D) 14:00 UTC on the following Monday

---

### Question 3

What distinguishes "eradication" from "containment" in the NIST IR framework?

A) Containment addresses network threats; eradication addresses host threats
B) Containment is performed by Tier 1; eradication by Tier 3
C) **Containment stops the spread; eradication removes the threat from the environment** ✓
D) There is no meaningful difference — the terms are interchangeable in NIST

---

### Question 4

In a post-incident review, the "5 Whys" technique is used to:

A) Identify the 5 most important action items
B) Rank the 5 analysts who responded to the incident
C) Document the 5 MITRE ATT&CK techniques used by the attacker
D) **Identify the root cause of an incident by asking "why?" repeatedly until a systemic cause is found** ✓

---

### Question 5

A hospital's backup server is actively encrypting files in a ransomware incident.
Your first action should be:

A) Attempt to decrypt the files using the ransomware recovery tool
B) Pay the ransom immediately to protect patient data
C) Wait for the encryption to finish before assessing
D) **Immediately isolate the backup server from the network** ✓

---

### Question 6

An IR manager designates an "Incident Commander" for a P1 incident.
The Incident Commander's primary role is:

A) Performing the malware analysis and reverse engineering
B) Writing all the forensic collection commands
C) **Coordinating the response, managing communication, and making decisions — not performing technical tasks** ✓
D) Handling all external communications with regulators and media

---

### Question 7

Which of the following correctly describes a "Benign True Positive" in incident classification?

A) A detection rule that fired incorrectly — no real threat exists
B) A confirmed attack that was successfully blocked with no impact
C) A real attack that an analyst failed to detect
D) **A detection rule that correctly identified real activity, but the activity was authorized (e.g., a pentest)** ✓

---

### Question 8

An analyst runs the Volatility command `windows.malfind` on a memory image and finds a region in `explorer.exe` starting with the bytes `4D 5A`.
What does this most likely indicate?

A) Explorer.exe is corrupt and should be replaced
B) The memory region contains network traffic data
C) **A Windows PE (Portable Executable) has been injected into explorer.exe — a strong indicator of process injection** ✓
D) The system has a legitimate Windows update running

---

### Question 9

A company in Poland processes personal data of EU citizens.
They discover a breach on Tuesday at 10:00 UTC.
Under which timeline must they notify the supervisory authority?

A) By Wednesday 10:00 UTC
B) By Friday 22:00 UTC
C) **By Friday 10:00 UTC** ✓
D) By the following Monday 10:00 UTC

---

### Question 10

Which of the following forensic artifacts would reveal that a scheduled task was recently created for persistence on a Windows system?

A) Browser history
B) Prefetch files
C) **Windows Event Log (Event ID 4698 — scheduled task created)** ✓
D) LSASS memory dump

---

### Question 11

A security team is investigating an Advanced Persistent Threat (APT).
They have confirmed the attacker is present on one workstation.
The attacker is not yet aware they have been detected.
What is the BEST containment strategy?

A) Immediately shut down all systems across the organization
B) Block all internet access at the perimeter firewall
C) **Consider passive monitoring to gather threat intelligence before containment — the attacker being unaware is a time-limited intelligence opportunity** ✓
D) Notify the attacker via their C2 server that they have been detected

---

### Question 12

Under NIS2, an essential entity discovers a major incident.
What is the correct notification sequence and timing?

A) Single notification within 72 hours, no final report required
B) 24-hour notification only; no further reporting needed
C) Notify regulators only if customer data is involved
D) **Early warning within 24 hours, full notification within 72 hours, final report within 1 month** ✓

---

### Question 13

When collecting forensic evidence from a Linux system, which command would help identify recently added cron jobs (a common persistence mechanism)?

A) `ls -la /etc/hosts`
B) `netstat -antp`
C) **`crontab -l` and `ls -la /etc/cron*`** ✓
D) `ps auxf`

---

### Question 14

A company stores only the last 4 digits of credit card numbers and the card type (Visa/Mastercard) on their servers.
These servers are ransomware-encrypted.
Are they required to notify their acquiring bank under PCI-DSS?

A) No — partial card data (last 4 digits) is not considered cardholder data
B) No — only organizations that store full card numbers must notify
C) Yes — only if more than 1,000 cards are affected
D) **Yes — any suspected compromise of a system that processes or handles cardholder data environment triggers PCI-DSS notification requirements, regardless of whether full card numbers were stored** ✓

---

### Question 15

What is the key principle behind a "blameless" post-incident review culture?

A) No one should be held accountable for incident response failures
B) Only external attackers, not internal staff, can be blamed for incidents
C) Employees should not be informed of security incidents to prevent panic
D) **Incidents are treated as system failures rather than individual failures — focus is on improving processes, not punishing individuals who acted in good faith** ✓
