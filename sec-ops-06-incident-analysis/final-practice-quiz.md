# Final Practice Quiz — Session 06: Incident Analysis in a Threat-Centric SOC

**Purpose:** Practice exam with mixed question types — short answer and long answer

**Questions:** 5 short answer + 2 long answer

**Time:** 45 minutes

**Designed for:** Self-assessment and exam preparation

---

## Short Answer Questions (5 questions, ~5 minutes each)

---

### Short Answer 1

**Question:**
A user reports receiving an email from `ceo.office@acmecorp.support` asking her to transfer $85,000 to a new vendor account.
The company's legitimate CEO email domain is `acmecorp.com`.
The email passed the company's spam filter.

1. What type of incident is this?
1. What is the severity level (P1–P5)?
1. Name two technical indicators that should be investigated.
1. What is the one immediate action that takes absolute priority?

**Model Answer:**

1. **Incident type:** Business Email Compromise (BEC) / Social Engineering — financial fraud attempt. NIST category: Social Engineering / Multiple Components (Unauthorized Access attempted + Financial Fraud).

1. **Severity: P2 (High)** — financial fraud attempt targeting a user with payment authority. If a transfer had already been made: P1 immediately.

1. **Technical indicators to investigate:**
   * Email headers — specifically the originating IP (`X-Originating-IP`, `Received:` chain) to determine true sender origin
   * WHOIS/registration data for `acmecorp.support` — who registered this domain, when? Recently registered domains are strong phishing indicators
   * SPF/DKIM/DMARC results for `acmecorp.support`
   * Whether the same email was sent to other employees

1. **Immediate priority action:** Confirm the user has NOT made any transfer. Contact her immediately by phone (not email). If a transfer was initiated, immediately contact the finance team to stop/reverse it. Financial fraud is time-critical — wire transfers may be reversible within hours.

---

### Short Answer 2

**Question:**
Explain the difference between the **Cyber Kill Chain** and **MITRE ATT&CK**.
When would you use each in an incident analysis?

**Model Answer:**

**Cyber Kill Chain (Lockheed Martin):**

* A sequential, seven-phase model: Reconnaissance → Weaponize → Deliver → Exploit → Install → C2 → Actions on Objectives
* High-level, linear view of an attack campaign
* Useful for: Executive briefings, understanding where in the attack progression you are, determining how far an attacker has progressed
* Limitation: Too high-level for operational detection; does not capture the variety of specific techniques

**MITRE ATT&CK:**

* A knowledge base of 14 tactics and hundreds of techniques based on observed real-world adversary behavior
* Non-linear — attackers can jump between tactics; multiple techniques exist for each tactic
* Useful for: Specific detection rule development, hunting for undetected activity, communicating specific attacker behaviors between analysts, building detection coverage maps, actor profiling
* Limitation: Granularity makes executive communication difficult; requires analyst training to use effectively

**When to use each:**

* Kill Chain: Communicating "where is the attacker in the attack?" to managers, SOC managers, and executives
* ATT&CK: When you need to answer "what specifically did the attacker do?" and "how do we detect it in the future?" — used during investigation, detection engineering, and threat hunting

The two frameworks are complementary, not competing.

---

### Short Answer 3

**Question:**
You are investigating a potential ransomware incident.
The infected system is still running and encrypted files are visible.
An IT team member says: "Let me just quickly restore from backup — that will fix it faster than an investigation."

Provide three reasons why this is the wrong approach, and describe the correct process.

**Model Answer:**

**Three reasons NOT to restore immediately:**

1. **Backup integrity is unknown:** Modern ransomware specifically targets backup systems. If backups are on the same network or accessible from the infected system, they may also be encrypted or corrupted. Restoring from an encrypted backup achieves nothing and may destroy your only clean copy.

1. **Scope is unknown:** Restoring one system doesn't address other potentially compromised systems. If you don't know the initial access vector, patch it, and verify the scope, the attacker still has access and will re-encrypt after restoration.

1. **Evidence is destroyed:** Restoring overwrites forensic evidence needed to understand how the attack occurred — including volatile evidence (malware in memory, C2 session details) and non-volatile (malware executables, persistence mechanisms). Without this investigation, you cannot write the Post-Incident Report, identify root cause, or prevent recurrence.

**Correct process:**

1. Isolate the infected system (EDR network isolation) — stop active encryption spread
1. Collect volatile evidence BEFORE any remediation
1. Create a forensic disk image BEFORE restoration
1. Verify backup integrity BEFORE attempting any restoration
1. Determine full scope — are other systems affected?
1. Eradicate the attacker's presence completely (persistence mechanisms, backdoors)
1. THEN restore from a verified clean backup
1. Monitor restored systems intensively for 30+ days

---

### Short Answer 4

**Question:**
Define **chain of custody** and explain why it matters.
Describe what happens to the evidential value of digital evidence when chain of custody is broken.

**Model Answer:**

**Chain of custody** is the documented record that tracks evidence from the moment of collection through every transfer, storage, and analysis event to the point of presentation.
It records:

* Who collected the evidence
* When and where it was collected
* The collection method used
* A cryptographic hash proving integrity
* Every person who has handled the evidence since collection

**Why it matters:**
Chain of custody ensures that evidence can be proven **unmodified** since collection.
Without this proof, opposing counsel (in criminal or civil proceedings) can argue that the evidence was altered, fabricated, or contaminated — and may successfully have it excluded.

**When chain of custody is broken:**

1. **Evidence may be inadmissible in criminal proceedings** — prosecutors cannot prove the evidence presented is the same evidence collected from the crime scene
1. **Civil litigation collapses** — trade secret theft, employment disputes, and corporate fraud cases rely on the integrity of digital evidence; exclusion can end the case
1. **Disciplinary proceedings may fail** — HR investigations into insider threats require evidence that meets the organization's own procedural standards
1. **Insurance claims may be rejected** — cyber insurance claims often require forensic evidence of the breach; integrity questions may cause denial
1. **Regulatory findings are challenged** — breach notifications that rely on compromised evidence may face regulatory pushback

**The most common chain of custody breaks:** Not computing a hash at collection, writing to the suspect system (modifying file access times), leaving evidence unattended, sharing copies without a transfer log.

---

### Short Answer 5

**Question:**
A threat hunter notices that a workstation is making DNS queries for domains like:

```text
a7b2c3d4e5f6a7b8.cdn.update-checker.com
f1e2d3c4b5a6f7e8.cdn.update-checker.com
9a8b7c6d5e4f3a2b.cdn.update-checker.com
```

All queries return NXDOMAIN (non-existent domain).
What is the likely technique, what ATT&CK ID applies, and what detection query would you write?

**Model Answer:**

**Likely technique:** DNS tunneling for C2 communication.
The attacker's malware is encoding data (commands/responses) as high-entropy subdomain labels in DNS queries.
The 16-character hex strings in the subdomain are base64 or hex-encoded data chunks.
The NXDOMAIN responses may be intentional (the responses aren't needed — the data is in the query).

**ATT&CK Technique:** T1071.004 — Application Layer Protocol: DNS

Also potentially: T1041 (Exfiltration Over C2 Channel) or T1048.001 (Exfiltration Over Alternative Protocol: DNS)

**Detection query (Splunk SPL):**

```spl
index=dns
| eval subdomain_label = mvindex(split(query, "."), 0)
| eval label_length = len(subdomain_label)
| eval is_hex = if(match(subdomain_label, "^[0-9a-f]{12,}$"), 1, 0)
| where label_length > 12 AND is_hex=1
| stats count, values(query) as sample_queries, dc(query) as unique_queries
    by src_ip, mvindex(split(query, "."), -2) + "." + mvindex(split(query, "."), -1)
| where count > 10
| rename * as c2_domain
| sort -count
```

**Alternative simpler detection:**

```spl
index=dns
| eval domain_entropy_proxy = len(mvindex(split(query, "."), 0))
| where domain_entropy_proxy > 14
| stats count by src_ip, query
| where count > 5
```

**Additional context:** DNS tunneling tools include dnscat2, iodine, and custom implementations.
NXDOMAIN responses are normal in some DNS tunneling implementations — the tool only needs the DNS server to forward the query to the attacker-controlled authoritative server, which encodes the response in a legitimate DNS response or in subsequent NXDOMAIN patterns.

---

## Long Answer Questions (2 questions, ~10 minutes each)

---

### Long Answer 1

**Question:**
Your organization has just experienced a P1 incident: ransomware was deployed across 40% of your Windows workstations after an attacker gained domain admin access.
You are the senior analyst tasked with writing the Post-Incident Report (PIR).

Write the key sections of the PIR, including:

1. Executive Summary (3–4 sentences maximum)
1. Root Cause Analysis (at least 3 contributing factors)
1. Detection Gaps (at least 3 specific gaps)
1. Recommendations (at least 5 specific, actionable recommendations with rationale)

**Model Answer:**

**1.
Executive Summary:**
On [date], ransomware was deployed to 40% of company workstations following a compromise that began 14 days earlier with a phishing email to a finance department employee.
The attacker gained domain administrator credentials through credential dumping, enabling them to deploy ransomware via Group Policy to all domain-joined workstations.
Business operations in affected departments were disrupted for [X days]. 23 workstations required rebuild; all data has been restored from backup.
No customer data was exfiltrated.

---

**2.
Root Cause Analysis:**

*Primary cause:* A phishing email with a malicious Word document macro bypassed the email gateway and was opened by an employee, resulting in initial system compromise.

*Contributing factor 1: DMARC not enforced.*
The organization's DMARC policy was `p=none`.
The phishing email failed SPF and DKIM checks but was delivered because no enforcement action was configured.
DMARC `p=reject` would have blocked this specific email and all future spoofed attempts.

*Contributing factor 2: No MFA on internal privileged accounts.*
After obtaining initial access on a workstation, the attacker dumped LSASS and harvested domain admin credentials.
These credentials were usable directly (no second factor required) for lateral movement and GPO-based ransomware deployment.
MFA on privileged account usage would not have prevented credential theft but would have significantly slowed or prevented the escalation.

*Contributing factor 3: No behavioral detection for credential dumping.*
The attacker used Mimikatz (via PowerShell) to dump LSASS credentials.
No detection rule existed for LSASS process access with the Mimikatz access mask (0x1010).
If this had been detected on Day 3, containment before ransomware deployment (Day 14) would have been possible.

*Contributing factor 4: No coverage for LOLBin lateral movement.*
The attacker used only native Windows tools (net.exe, schtasks.exe, psexec-equivalent techniques) for lateral movement and deployment.
These generated no AV/EDR alerts.
Detection required behavioral analysis that was not implemented.

---

**3.
Detection Gaps:**

*Gap 1: LSASS memory access not monitored.*
No alert existed for process access to LSASS.exe with high-privilege access masks.
Detection: Sysmon EventID 10, TargetImage=lsass.exe, GrantedAccess=0x1010 or 0x143a.

*Gap 2: Outbound connections from PowerShell not alerted.*
PowerShell making direct outbound connections to external IPs is a strong C2 indicator but generated no alert.
Detection: Sysmon EventID 3, Image=*powershell.exe*, DestinationIp not in internal range.

*Gap 3: GPO modification not monitored.*
The attacker modified Group Policy to deploy ransomware.
Windows Event 5136 (Directory Service Object Modified) for `groupPolicyContainer` objects was not alerted.
This is T1484.001 and a critical detection point.

*Gap 4: No detection for mass file encryption.*
The encryption activity (thousands of file modifications per minute) was not alerted until it had been running for 3 minutes.
An EDR rule on file modification rate would have detected this 2-3 minutes earlier — not preventing the incident but potentially limiting its scope.

---

**4.
Recommendations:**

*Recommendation 1: Enforce DMARC (p=quarantine → p=reject)*
Rationale: Blocks spoofed emails at the gateway.
This addresses the initial delivery phase.
Timeline: Implement p=quarantine within 30 days; p=reject after monitoring for 60 days.
Owner: IT/Email team.
Priority: HIGH.

*Recommendation 2: Deploy LSASS protection (Credential Guard + Sysmon rule)*
Rationale: Enable Windows Credential Guard to prevent LSASS credential dumping.
Deploy Sysmon rule for LSASS access by non-system processes.
Timeline: 30 days.
Owner: IT/Security Engineering.
Priority: HIGH.

*Recommendation 3: Enforce MFA for all privileged account usage*
Rationale: Even with credentials dumped, MFA prevents direct use of stolen credentials for privileged operations.
Specifically: Privileged Access Workstations (PAW) + MFA for Domain Admin access.
Timeline: 60 days.
Owner: IT.
Priority: HIGH.

*Recommendation 4: Deploy behavioral detection rules for LOLBin lateral movement*
Rationale: Rules for net.exe, wmic.exe, schtasks.exe used from non-admin workstations.
Alert on GPO modification events (Event 5136).
Timeline: 45 days.
Owner: Detection Engineering.
Priority: MEDIUM.

*Recommendation 5: Implement network segmentation for file servers and DCs*
Rationale: The attacker moved freely from a workstation to the domain controller because they were on the same flat network.
Micro-segmentation or VLANs would require additional credentials/lateral movement steps, increasing attacker effort and detection opportunity.
Timeline: 90 days.
Owner: Network/Architecture.
Priority: MEDIUM.

---

### Long Answer 2

**Question:**
You are mentoring a new SOC analyst who has been told to "just investigate what the SIEM alerts on" and to "close tickets quickly." The analyst asks you to explain why a **threat-centric** approach is better than a **compliance-centric** approach for incident analysis, and how to apply it practically.

Write a response of approximately 300–400 words that covers:

* The core difference between the two approaches
* Why the compliance-centric approach fails against sophisticated threats
* Three practical techniques a threat-centric analyst uses that a compliance-centric analyst doesn't
* A concrete example showing the difference in outcome

**Model Answer:**

The difference between compliance-centric and threat-centric analysis comes down to what question you're trying to answer.
A compliance-centric analyst asks: "Did this match a rule?" A threat-centric analyst asks: "Is this attacker behavior, and what are they trying to achieve?"

In a compliance-centric SOC, detection logic is built to satisfy auditors — rules that demonstrate coverage of PCI-DSS or ISO 27001 requirements.
Analysts measure their performance by ticket closure rate and MTTD/MTTR metrics.
The goal is demonstrating that every alert was processed.

The problem is that sophisticated attackers know this playbook.
They deliberately operate below detection thresholds, use tools that generate zero alerts (Microsoft-signed binaries, valid credentials), and spread their activity over weeks to avoid triggering correlation rules.
Against an APT or ransomware operator, a compliance-centric SOC produces exactly the right metrics while the attacker owns the environment.

Three techniques a threat-centric analyst uses that a compliance-centric analyst doesn't:

**1.
IOA-based hunting rather than IOC matching.** Instead of searching for known-bad IPs and hashes (which the attacker changes constantly), a threat-centric analyst hunts for behavioral patterns: processes with anomalous parent chains, LSASS access from non-system processes, users authenticating from multiple continents.
These patterns persist even when tools change.

**2.
Pivot and expand from initial alert.** When the SIEM fires on one host, a compliance-centric analyst closes that one alert.
A threat-centric analyst asks: "If an attacker is here, where else might they be?" They pivot on IOCs, account names, and TTPs to find the full scope — often discovering compromised systems the attacker thought were invisible.

**3.
ATT&CK-based hypothesis generation.** Every confirmed technique generates hypotheses for unconfirmed techniques in the same tactic.
If you confirm LSASS dumping (Credential Access), you hunt for Pass-the-Hash (Lateral Movement) even before an alert fires.
This is proactive investigation rather than reactive alert processing.

**Concrete example:** A compliance-centric analyst sees a P4 alert for "Office process spawning PowerShell" and closes it as an isolated event after confirming one infected workstation.
A threat-centric analyst uses the C2 IP as an IOC, finds two other workstations beaconing to the same IP, discovers that one is an IT workstation with Domain Admin tools, and catches the attacker *before* they dump credentials — turning a cleanup job into an actual prevention outcome.

The metric for compliance-centric success is "alert closed." The metric for threat-centric success is "attacker denied their objective."

---

*End of Final Practice Quiz*
