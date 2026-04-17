# Entry Quiz — Session 08: Event Correlation and Normalization

**Instructions:** Select the single best answer for each question.

**Time:** 10 minutes

**Purpose:** Assess prerequisite knowledge before the session

---

## Question 1

A Security Operations Center ingests logs from 12 different security tools.
An analyst wants to run a query to find all authentication failures regardless of which tool generated the log.
What is the primary obstacle to writing this single query?

* A) Authentication failures are too rare to query across all sources
* B) Different tools use different field names for the same concepts (e.g., source IP, username)
* C) SIEM query languages cannot handle multiple log sources simultaneously
* D) Authentication events always require real-time processing

**Correct answer: B**

*Explanation: Without normalization, each source uses its own field naming conventions (e.g., `IpAddress`, `src_ip`, `from`, `sourceIPAddress` all meaning "source IP").
A single cross-source query requires all sources to use the same field names — which is exactly what log normalization provides.*

---

## Question 2

In the syslog format `<165>1 2024-12-14T07:42:01Z host sshd 3822 - Failed password`, what does the number `165` represent?

* A) The message ID
* B) The syslog version
* C) The priority value, encoding facility and severity
* D) The process identifier (PID)

**Correct answer: C**

*Explanation: The `<PRI>` field (Priority) encodes both facility (PRI >> 3) and severity (PRI & 0x07).
Priority 165 = facility 20 (local4) × 8 + severity 5 (notice).
The actual PID is `3822`.*

---

## Question 3

Which of the following best describes the difference between **parsing** and **normalization** in log processing?

* A) Parsing is done at the source; normalization happens at the SIEM
* B) Parsing extracts structured fields from raw text; normalization maps those fields to a standard schema
* C) Parsing converts logs to JSON; normalization compresses them for storage
* D) There is no meaningful difference — the terms are interchangeable

**Correct answer: B**

*Explanation: Parsing takes unstructured text and extracts field-value pairs.
Normalization then takes those extracted fields and renames/maps them to a common schema (like ECS or CEF) so all sources use consistent field names.*

---

## Question 4

A SOC analyst notices that a detection rule for brute-force attacks generates 300 alerts per day, but upon investigation only about 15 turn out to be actual attacks.
What is this phenomenon called, and what is the TP rate?

* A) False negative storm; TP rate is 95%
* B) Alert fatigue caused by false positives; TP rate is 5%
* C) Threshold misconfiguration; TP rate is 15%
* D) Normalization error; TP rate is 50%

**Correct answer: B**

*Explanation: TP rate = true positives / total alerts = 15/300 = 5%.
This is a classic false positive problem leading to alert fatigue.
When analysts receive many more false alarms than real alerts, they become desensitized and risk missing real incidents.*

---

## Question 5

Which of the following best describes what a **correlation rule** does compared to a **single-event detection rule**?

* A) Correlation rules are faster to execute; single-event rules require more computation
* B) Correlation rules analyze relationships between multiple events over time; single-event rules evaluate one event independently
* C) Correlation rules only work with Windows event logs; single-event rules work with any log source
* D) Correlation rules require machine learning; single-event rules use regex

**Correct answer: B**

*Explanation: A single-event rule evaluates each event in isolation (e.g., "does this process name match mimikatz.exe?").
A correlation rule combines multiple events — counting failures from an IP over 5 minutes, or detecting a sequence of reconnaissance→exploitation→persistence events.*
