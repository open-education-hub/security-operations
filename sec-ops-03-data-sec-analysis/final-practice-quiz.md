# Final Practice Quiz — Session 03: Data Categories and Analysis

**Purpose:** Extended practice with short and long-answer questions

**Level:** Intermediate

**Format:** 5 short-answer + 2 long-answer

**Time:** ~45 minutes

---

## Part A: Short-Answer Questions (5 × 10 points = 50 points)

*Answer in 2–4 sentences each.*

---

**SA-1.** Explain the **Pyramid of Pain** concept and describe why detecting adversary **TTPs** (Tactics, Techniques, and Procedures) is more valuable than detecting file hashes.

**Model Answer:**
The Pyramid of Pain, developed by David Bianco, describes the relative cost that different types of IOCs impose on an adversary when their indicators are detected and blocked.
At the base (easiest for attackers to change) are IP addresses and file hashes — an attacker can change an IP in minutes and recompile a binary to change its hash trivially.
TTPs, at the top of the pyramid, describe *how* an attacker operates: their specific techniques, tools, and behaviors.
These are the hardest to change because they reflect the attacker's skills, training, and operational methods.
Detecting TTPs means the attacker must fundamentally change their approach, not just swap an IP address — this imposes maximum cost and disruption on the adversary.

---

**SA-2.** A Logstash pipeline receives a Windows Sysmon Event ID 1 (process creation) log.
The timestamp field is `UtcTime = 03/15/2024 14:23:01.843`.
Describe the Logstash filter configuration needed to correctly set the `@timestamp` field.

**Model Answer:**
The `date` filter is used to parse a source field and assign its value to `@timestamp`.
For the format `03/15/2024 14:23:01.843` (MM/dd/yyyy HH:mm:ss.SSS), the configuration would be:

```ruby
date {
  match  => ["UtcTime", "MM/dd/yyyy HH:mm:ss.SSS"]
  target => "@timestamp"
  timezone => "UTC"
}
```

Without this filter, `@timestamp` defaults to the time Logstash received the event, not when it actually occurred — which would make historical analysis and time-based correlation unreliable.
The `timezone => "UTC"` parameter ensures consistent interpretation regardless of the Logstash server's local timezone.

---

**SA-3.** Explain the difference between **tactical threat intelligence** and **strategic threat intelligence**, and give one example of how each is consumed in a SOC.

**Model Answer:**
Tactical (technical) threat intelligence consists of machine-readable, specific artifacts like IP addresses, file hashes, and Snort signatures.
It has a short lifespan (hours to weeks) and is directly consumed by security tools — for example, a firewall blocklist automatically updated with Emotet C2 IPs from a MISP feed.
Strategic threat intelligence is high-level analysis for decision-makers: threat landscape assessments, geopolitical risk analysis, and industry-specific attack trend reports.
It has a long lifespan (months to years) and is consumed by CISOs and board members — for example, a quarterly report showing that ransomware attacks against healthcare companies increased 48% this year, used to justify additional budget for backup infrastructure.

---

**SA-4.** What is **GDPR data minimization** and how does it affect log retention policy in a SOC?

**Model Answer:**
GDPR's data minimization principle states that personal data should only be collected and retained for as long as necessary for the specified purpose.
In a SOC context, many logs contain personal data: usernames, IP addresses (which can identify individuals), email addresses in proxy logs, and session tokens.
The data minimization requirement means the SOC cannot retain logs indefinitely "just in case" — it must define a retention period that balances security analysis needs against privacy rights.
A practical approach is to pseudonymize or anonymize personal data fields after the security analysis window (e.g., 90 days), replacing usernames with one-way hashes.
This satisfies the security purpose (detecting attack patterns) while reducing the personal data exposure in long-term archives.

---

**SA-5.** Describe what **alert fatigue** is, explain why it is dangerous in a SOC, and provide two concrete strategies to reduce it.

**Model Answer:**
Alert fatigue occurs when a SIEM or detection system generates so many alerts — particularly false positives — that analysts become overwhelmed and begin to dismiss or ignore alerts without proper investigation.
This is dangerous because a real threat buried in thousands of false positive alerts will go undetected, defeating the purpose of the SIEM entirely.
Two strategies to reduce alert fatigue: (1) **Tune detection rules** — for every rule that generates more than 5–10% false positives, add exclusions for known benign sources (specific service accounts, scheduled maintenance windows, or known-good IP ranges).
Track false positive rates per rule and prioritize tuning the noisiest rules first.
(2) **Use risk-based alerting** — instead of a binary alert/no-alert threshold, assign a risk score to each event and only page on-call analysts for events above a high-risk threshold; medium-risk events go into a queue for periodic review.
This ensures critical alerts receive immediate attention while lower-confidence signals are not completely ignored.

---

## Part B: Long-Answer Questions (2 × 25 points = 50 points)

*Answer each question in 300–500 words.*

---

**LA-1.** A healthcare organization has deployed a SIEM and wants to write a detection rule to identify **credential dumping attacks** (MITRE T1003).
The organization uses Active Directory with 500 employees, primarily Windows 10/11 workstations and Windows Server 2019.

Design a comprehensive detection strategy for credential dumping.
Your answer must include:

1. Which log sources to monitor and what specific events or patterns to look for
1. A sample Splunk SPL rule (or Sigma rule) for at least one detection method
1. Known limitations and potential false positives
1. Why detecting this technique is particularly critical for a healthcare organization

**Model Answer:**

**Detection Strategy for Credential Dumping (T1003)**

Credential dumping encompasses several sub-techniques, each with different observable evidence:

**1.
Log Sources and Detection Signals:**

*LSASS Memory Access (T1003.001):* Sysmon Event ID 10 (ProcessAccess) with target `lsass.exe`.
The key signal is a non-SYSTEM process with elevated access rights (`GrantedAccess = 0x1010` or `0x1038`) accessing lsass memory.
Tools like Mimikatz leave this fingerprint.

*Windows Event ID 4688/Sysmon Event 1 (Process Creation):* Command-line arguments like `sekurlsa::logonpasswords`, `lsadump::sam`, `procdump -ma lsass.exe`, or `comsvcs.dll MiniDump` are direct indicators.

*Windows Event 4656/4663 (Object Access):* Access to `%SystemRoot%\System32\config\SAM` or `NTDS.dit` — the SAM database and AD database that contain password hashes.

*Sysmon Event 8 (CreateRemoteThread):* Injecting into lsass.exe via remote thread creation is another access method.

*Network events:* After dumping credentials, attackers typically perform network reconnaissance or lateral movement.
A burst of SMB connections or Kerberos TGT requests immediately following a suspicious process on a workstation is a strong secondary indicator.

**2.
Splunk Detection Rule (LSASS Access):**

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe" earliest=-15m
| where GrantedAccess IN ("0x1010", "0x1038", "0x1fffff", "0x143a")
| where NOT match(SourceImage, "(?i)\\\\(MsMpEng|SecurityHealthService|AV_Scanner|svchost)\.exe")
| eval mitre = "T1003.001 - LSASS Memory"
| eval severity = "CRITICAL"
| table _time, Computer, SourceImage, SourceProcessId, GrantedAccess, mitre, severity
```

**3.
Limitations and False Positives:**

Some legitimate antivirus products and EDR agents access lsass for monitoring purposes — these must be excluded based on your specific AV product paths.
Windows Defender (MsMpEng.exe) regularly accesses lsass.
The exclusion list requires ongoing maintenance as AV products update.
Additionally, some backup solutions read SAM/NTDS.dit — these need to be accounted for if their processes are present.

**4.
Why This is Critical for Healthcare:**

Healthcare organizations store Protected Health Information (PHI) and are subject to HIPAA, which mandates strict access controls.
Credential dumping gives attackers the ability to impersonate any user, including healthcare staff with access to electronic health records (EHR) systems, prescription databases, and medical device management systems.
A compromised domain administrator account in a healthcare network could access every patient's medical record, potentially affecting the organization's HIPAA compliance and exposing it to significant fines.
Furthermore, healthcare has been a top ransomware target — credential dumping is often the penultimate step before deploying ransomware, making early detection critical for preventing patient harm through disruption of clinical operations.

---

**LA-2.** Explain the **threat intelligence lifecycle** and describe how a SOC would operationalize threat intelligence from a MISP feed.
Your answer should cover the full lifecycle from data collection to detection output, and include at least one concrete example using a real threat actor or malware family.

**Model Answer:**

**The Threat Intelligence Lifecycle in Practice**

The intelligence lifecycle consists of six phases that transform raw data into actionable security improvement:

**Phase 1 — Planning & Direction:** The SOC defines its intelligence requirements based on its threat model.
For a financial institution, the requirements might be: "What are the current TTPs of financially-motivated threat actors targeting our sector?" The team identifies that Emotet is actively targeting financial institutions in their region (per FS-ISAC reporting), creating a specific intelligence collection requirement.

**Phase 2 — Collection:** The SOC subscribes to MISP feeds relevant to financial threats: the CIRCL OSINT feed, the Abuse.ch Feodo Tracker (Emotet C2 IPs), and their FS-ISAC MISP community.
Collection is automated — MISP pulls feed updates every hour.
Internal collection also contributes: their own honeypots and the analyst team's investigation findings are published to their MISP instance.

**Phase 3 — Processing:** Raw feed data is ingested into MISP.
Duplicate IOCs are deduplicated.
MISP automatically correlates new IOCs against existing events (e.g., a new Emotet C2 IP added by Abuse.ch may already appear in an internal incident from last week, automatically linking the events).
Analysts review high-confidence, high-severity events flagged by MISP for potential action.

**Phase 4 — Analysis:** An analyst reviews the Emotet collection.
They find 50 new C2 IPs tagged `tlp:green` from the Feodo Tracker, 3 SHA256 hashes for new Emotet droppers, and a new C2 domain registered 2 days ago.
They enrich these with VirusTotal (confirming high detection rates for the hashes) and passive DNS data (confirming the C2 domain resolves to a known bulletproof hosting provider).
The analyst assesses confidence as HIGH.

**Phase 5 — Dissemination:** The intelligence is operationalized at two levels:

* *Tactical:* The 50 C2 IPs are pushed via MISP's RESTful API to the SIEM as a lookup table. A Splunk lookup is updated: `| lookup emotet_c2_ips dest_ip OUTPUT is_emotet_c2`. A correlation rule fires an alert whenever an internal host communicates with any IP in the list. The new domain is added to the DNS RPZ blocklist. The file hashes are pushed to the EDR for blocking.

* *Operational:* The analyst team receives a briefing: "Emotet is actively targeting financial institutions with Word macro attachments. Watch for WINWORD → PowerShell event chains."

**Phase 6 — Feedback:** Over the next two weeks, the SIEM fires 3 alerts for internal hosts communicating with Emotet C2 IPs.
Two are confirmed infections.
The feedback to the intelligence cycle: this campaign is actively reaching the organization, justifying continued priority on Emotet-related intelligence collection.
The newly-discovered internal IOCs (hashes from the compromised machines) are published back to the MISP instance, enriching the community's shared intelligence.

This cycle demonstrates that threat intelligence is not a static feed subscription — it is a continuous process requiring analyst judgment, community participation, and operational integration to generate security value.

---

## Scoring Guide

| Section | Points | Passing |
|---------|--------|---------|
| Short Answer (5 × 10) | 50 | 30/50 |
| Long Answer (2 × 25) | 50 | 30/50 |
| **Total** | **100** | **60/100** |

Answers are assessed on technical accuracy, completeness, and application of session concepts.
Partial credit is awarded for answers that demonstrate partial understanding.
