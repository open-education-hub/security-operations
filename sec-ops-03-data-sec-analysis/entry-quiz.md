# Entry Quiz — Session 03: Data Categories and Analysis

**Purpose:** Assess baseline knowledge before the session

**Level:** Beginner

**Questions:** 5 multiple-choice

**Time:** ~10 minutes

**Passing score:** 3/5 (you don't need to pass to proceed — this helps calibrate your starting level)

---

**Q1.** What is the primary purpose of a SIEM (Security Information and Event Management) system?

* A) Scan network hosts for open ports and vulnerabilities
* B) Collect, correlate, and analyze log data from multiple sources to detect security events
* C) Block malicious traffic at the network perimeter
* D) Encrypt communications between internal systems

**Correct answer: B**

---

**Q2.** Which of the following is an example of an Indicator of Compromise (IOC)?

* A) A misconfigured firewall rule
* B) An unpatched operating system
* C) A known malicious IP address observed in network traffic
* D) A user with excessive permissions

**Correct answer: C**

*Explanation: IOCs are artifacts (IPs, hashes, domains, etc.) that indicate a system has been compromised.
Options A, B, and D describe vulnerabilities or misconfigurations — they are risks, not indicators of active compromise.*

---

**Q3.** A log entry shows: `2024-03-15T14:23:01Z host=WORKSTATION-01 user=jsmith event=login_failed src_ip=203.0.113.10`

What format is this log entry using?

* A) CEF (Common Event Format)
* B) Syslog RFC 5424
* C) Structured key-value (JSON-like) format
* D) W3C Extended Log Format

**Correct answer: C**

*Explanation: This is key-value (KV) format — `key=value` pairs separated by spaces. CEF has a specific header format (CEF:0|vendor|...). JSON uses `{"key":"value"}` notation with curly braces.*

---

**Q4.** Which Windows Event ID records a **failed** logon attempt?

* A) 4624
* B) 4625
* C) 4688
* D) 4698

**Correct answer: B**

*Explanation:*

* *4624: Successful logon*
* *4625: Failed logon (correct answer)*
* *4688: Process creation*
* *4698: Scheduled task creation*

---

**Q5.** What does "log normalization" mean in the context of a SIEM?

* A) Deleting log entries that are outside normal parameters
* B) Converting logs from different sources into a common, consistent format
* C) Compressing log files to save storage space
* D) Encrypting log files for compliance purposes

**Correct answer: B**

*Explanation: Normalization means mapping different field names and formats from various sources to a common schema — for example, mapping `srcip`, `src`, `IpAddress`, and `id.orig_h` all to the standard field `source.ip`.*

---

## Score Interpretation

| Score | Interpretation | Recommendation |
|-------|---------------|----------------|
| 0–1 | Limited prior knowledge — that's fine! | Read the session material carefully before attempting demos |
| 2–3 | Some familiarity with concepts | Proceed normally with the session material |
| 4–5 | Solid baseline knowledge | You may be able to skim sections 2–3 of the reading |
