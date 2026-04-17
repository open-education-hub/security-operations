# Final Practice Quiz — Session 13: Advanced Topics in Cybersecurity

---

## Part 1: Short Answer Questions

**Question 1:** You are reviewing AWS CloudTrail logs and see the following sequence of events from user `charlie` within 5 minutes at 01:30 UTC: (1) `iam.amazonaws.com / CreateAccessKey`, (2) `cloudtrail.amazonaws.com / StopLogging`, (3) `s3.amazonaws.com / GetObject` on bucket `hr-records-2024`.
What is the most likely attack scenario and what should you do immediately?

> **Model Answer:** This is a classic cloud account takeover and data exfiltration pattern. The sequence indicates: (1) the attacker created a new API key for persistent access — even if charlie's password is reset, the new key still works; (2) the attacker disabled CloudTrail logging to prevent further evidence collection; (3) the attacker exfiltrated HR records while unmonitored. The off-hours timing (01:30 UTC) confirms this is not normal user activity.
>
> Immediate actions:
> 1. Disable ALL of charlie's access keys (both old and newly created) and disable console login
> 2. Re-enable CloudTrail immediately (the trail was stopped, not deleted, so logs up to event 2 are preserved)
> 3. Preserve S3 server access logs for the `hr-records-2024` bucket to determine what was downloaded
> 4. Assess GDPR/NIS2 notification requirements — HR records likely contain personal data, triggering the 72-hour GDPR notification clock
> 5. Check if charlie's account was the only vector — enumerate what other resources the account touched
> 6. Initiate full incident response

---

**Question 2:** Explain the difference between MTTD and MTTR as SOC metrics.
A SOC has MTTD = 2 hours and MTTR = 48 hours.
What does this tell you about the SOC's strengths and weaknesses?

> **Model Answer:** **MTTD (Mean Time to Detect)** measures how long it takes the SOC to detect a threat after the attack begins. A 2-hour MTTD means the SOC detects attacks quickly — this indicates good detection coverage (SIEM rules, EDR, threat intel) and effective monitoring.
>
> **MTTR (Mean Time to Respond)** measures how long it takes to fully resolve an incident after detection. A 48-hour MTTR means the SOC is slow to respond — incidents remain active for 2 days on average after detection.
>
> Interpretation: This SOC detects well but responds slowly. The gap between detection and resolution (48 hours) means attackers have almost 2 days to move laterally, establish persistence, and exfiltrate data after being spotted.
>
> Likely causes of high MTTR: lack of playbooks, manual processes, insufficient staffing for incident handling, slow decision-making on containment, no automation (SOAR).
>
> Improvement priorities: (1) Create and rehearse incident response playbooks; (2) Pre-authorise containment actions (e.g., auto-isolate via EDR for critical alerts); (3) Implement SOAR for automated triage; (4) Ensure 24×7 staffing with response authority.

---

**Question 3:** What is the key difference between traditional VPN access and Zero Trust Network Access (ZTNA)?
Why does Zero Trust significantly improve lateral movement detection for the SOC?

> **Model Answer:** A **traditional VPN** grants access to the entire internal network once a user authenticates. It is an "all or nothing" model: once inside, the user can attempt to reach any internal system. The SOC sees only the VPN authentication event, not individual application accesses.
>
> **ZTNA** grants access only to the specific application(s) the user is authorised to use, for the current session only, after verifying identity, device health, and policy. Every application access is a separate, explicit authorisation decision — and each decision is logged.
>
> Benefits for lateral movement detection: In Zero Trust, if a compromised account tries to reach an application it has never accessed before, that authorisation request is logged and can be alerted on. There is no equivalent of "being inside the network" — every access attempt is visible and evaluated. A compromised VPN credential immediately grants broad access with no logging of what was accessed; a compromised ZT credential triggers alerts when used outside normal patterns and is limited to specific applications.

---

**Question 4:** A colleague argues: "We don't need to worry about quantum computing risks to our encryption — quantum computers won't be powerful enough for 20 years." How would you respond from a security operations perspective?

> **Model Answer:** The 20-year estimate for cryptographically relevant quantum computers is debated, but the "Harvest Now, Decrypt Later" (HNDL) threat is present today, not in 20 years.
>
> State-level adversaries are intercepting and storing encrypted network traffic now — communications, financial transactions, government data, health records. If quantum computers arrive in 10, 15, or even 20 years, that harvested data becomes decryptable at that time. For data that must remain confidential for more than a decade (medical records, state secrets, long-term financial data), the risk is immediate.
>
> The practical response is not to panic but to start transitioning: (1) Inventory cryptographic assets — what algorithms are used for what data; (2) Prioritise transitioning long-lived sensitive data to post-quantum algorithms (NIST has standardised ML-KEM and ML-DSA); (3) Plan for "crypto-agility" in systems — the ability to swap algorithms without full system redesigns; (4) Protect new TLS deployments with post-quantum hybrid key exchange now (supported by major browsers and cloud providers).
>
> Waiting until quantum computers arrive is too late — by then, historical data is already compromised.

---

**Question 5:** What is a "honeypot" and how does it benefit a SOC?
What are the limitations of deception technology?

> **Model Answer:** A **honeypot** is a decoy resource (system, service, file, credential) designed to attract attackers. Anything that interacts with a honeypot is definitionally malicious — no legitimate user or system should ever touch it.
>
> Benefits for SOC:
> - **Zero false positives**: Any alert from a honeypot is almost certainly a true positive
> - **Early warning**: Attackers performing reconnaissance or lateral movement often hit honeypots before reaching real targets
> - **Intelligence gathering**: Observe attacker TTPs, tools, and commands in a safe environment
> - **Low-cost detection**: A simple honeypot file or fake credential can detect insider threats or external attackers with no SIEM tuning required
>
> Types: Honeypot systems (fake servers), honey tokens (fake credentials in password managers or code repos), canary files (fake sensitive documents), DNS canaries (fake internal domain names).
>
> Limitations:
> - Sophisticated attackers may recognise and avoid honeypots, undermining their value
> - Honeypots only detect active threats that probe or move laterally — they do not detect passive eavesdropping
> - Requires careful placement — a poorly placed honeypot could cause legitimate confusion or disruption
> - Not a replacement for comprehensive detection coverage — deception is an additional layer, not a primary defence

---

## Part 2: Long Answer Questions

**Question 6:** A manufacturing company in Germany has been notified by a cybersecurity vendor that they may have been targeted by a nation-state threat actor that used supply chain compromise to install a backdoor in an accounting software update.
Describe the full incident response process, specifically addressing: (a) how to determine if the compromise actually occurred, (b) NIS2 notification obligations, (c) GDPR obligations if employee or customer personal data was accessed, and (d) how to prevent recurrence.

> **Model Answer:**
>
> **(a) Determining if compromise occurred:**
>
> 1. **Obtain IOCs from the vendor**: File hashes, network indicators (C2 IPs/domains), registry keys, process names associated with the backdoor
> 2. **Check software inventory**: Identify all systems with the compromised accounting software version installed
> 3. **Hunt for IOCs**: Query EDR for file hashes and process names; check SIEM for network connections to C2 indicators; search DNS logs for C2 domain queries
> 4. **Examine accounting software processes**: Check process trees for unexpected child processes; review network connections from the software process
> 5. **Analyse update mechanism logs**: When was the update applied? Was any unusual activity observed around that time?
> 6. **Engage forensics**: If initial hunt finds indicators, perform full memory and disk forensics on affected systems
> 7. **Contact CERT-Bund** (German national CERT) for additional context — nation-state supply chain attacks often have government threat intelligence
>
> **(b) NIS2 obligations:**
>
> Manufacturing companies meeting certain size thresholds and sector classifications are "important entities" under NIS2. If this is a "significant incident" (affecting service continuity, involving nation-state actor):
> - Report to BSI (German NIS2 authority) within 24 hours of detection — preliminary report
> - Follow-up detailed report within 30 days
> - If the incident affected cross-border supply chain partners in other EU states, report to ENISA as well
> - Note: The obligation is triggered by detection, not by confirmation of compromise — report when you detect suspicious activity, not only when you confirm it
>
> **(c) GDPR obligations:**
>
> If the backdoor accessed or exfiltrated employee data (payroll in accounting system) or customer data (invoices, contracts):
> - Notify the German Data Protection Authority (BfDI or relevant Landesbehörde) within 72 hours of becoming aware
> - If individuals are at high risk (e.g., financial data exfiltrated), notify affected individuals
> - Document the breach in the internal breach register regardless of whether notification is required
> - Work with the DPO to assess the risk to individuals — nation-state actors stealing financial data are high risk
>
> **(d) Preventing recurrence:**
>
> 1. **SBOM for all software**: Require vendors to provide Software Bills of Materials so component vulnerabilities and supply chain integrity can be assessed
> 2. **Code signing verification**: Only accept software updates signed by the vendor's known certificate; verify signatures before installation
> 3. **Software update integrity checks**: Verify checksums of update packages against vendor-published values before deployment
> 4. **Application allowlisting**: Prevent accounting software from spawning unexpected child processes (AppLocker/WDAC)
> 5. **Network segmentation for accounting systems**: Financial systems should not have direct internet access; outbound connections only to known, approved services
> 6. **Vendor security assessment**: Include supply chain security requirements in vendor contracts; request their SBOM and security practices annually
> 7. **Threat intelligence subscription**: Subscribe to ISAC feeds for the manufacturing sector and software vendor security advisories

---

**Question 7:** Design a SOC maturity improvement plan for a 200-employee telecommunications company currently at Level 1 maturity (reactive, no playbooks, SIEM deployed but rarely used, no threat intelligence, no dedicated security staff).
The company is subject to NIS2 as a telecommunications provider.
Address the people, process, and technology dimensions over an 18-month timeline, and explain how you would measure progress.

> **Model Answer:**
>
> **Current State Assessment:**
> The company is at Level 1 — reactive only. Major gaps: no dedicated staff (people), no structured processes (process), underutilised SIEM (technology), no threat intelligence (process/technology), NIS2 non-compliance (regulatory).
>
> ---
>
> **People Dimension:**
>
> *Months 1–6:* Hire one dedicated Security Analyst (L2 level, mid-career). This single hire transforms the security function from "sysadmins also doing security" to dedicated monitoring. Cross-train existing sysadmins on basic security response for out-of-hours support.
>
> *Months 7–12:* Hire a second analyst (L1 role, trainee). The L2 begins mentoring. Define job descriptions and career paths to improve retention. Establish an on-call rota.
>
> *Months 13–18:* Consider SOC Lead role (or promote L2 analyst). All staff complete at least one relevant certification (CompTIA CySA+ or equivalent). Security awareness training deployed to all 200 employees.
>
> ---
>
> **Process Dimension:**
>
> *Months 1–3 (Quick wins):*
> - Create NIS2 incident notification process and contact list (1 week effort)
> - Document the 5 most common incident types and create basic response checklists
> - Define alert triage process (who gets which alert, in which order, with what SLA)
>
> *Months 4–9:*
> - Develop full playbooks for: phishing, ransomware, account compromise, DDoS (telecom-specific), data exfiltration
> - Implement monthly metrics reporting (MTTD, MTTR, alert volume, false positive rate)
> - Conduct quarterly NIS2 notification drills (tabletop exercise)
>
> *Months 10–18:*
> - Establish threat hunting programme (monthly hypotheses, even if simple)
> - Annual purple team exercise
> - Post-incident review process for all P1/P2 incidents
>
> ---
>
> **Technology Dimension:**
>
> *Months 1–3:*
> - Tune existing SIEM: add 30+ detection rules from community content (Sigma, Splunk ES content pack)
> - Enable process creation logging (Event 4688) on all Windows endpoints via GPO — no cost
> - Enable EDR if budget allows (Microsoft Defender for Endpoint or similar)
>
> *Months 4–9:*
> - Integrate free threat intelligence feeds (MISP community, CERT-EU feeds, abuse.ch)
> - Enable cloud logging (Azure Activity Log, if Azure is used)
> - Implement SOAR for the top 3 automated tasks (IOC enrichment, ticket creation, IP blocking)
>
> *Months 10–18:*
> - ATT&CK coverage assessment — map all SIEM rules to techniques; identify and fill top gaps
> - Network detection (if not present): NDR or at minimum NetFlow analysis
> - Annual external penetration test to validate controls
>
> ---
>
> **Measuring Progress:**
>
> | KPI | Month 3 | Month 9 | Month 18 |
> |-----|---------|---------|---------|
> | MTTD | Establish baseline | < 48h | < 8h |
> | MTTR | Establish baseline | < 72h | < 24h |
> | Active SIEM rules | 3 | 50 | 100+ |
> | NIS2 notification drill pass rate | 0% (no process) | 100% | 100% |
> | ATT&CK coverage | ~3% | 25% | 45% |
> | False positive rate | Unknown | < 50% | < 25% |
> | Security awareness training completion | 0% | 50% | 100% |
>
> Success criteria at 18 months: Level 2–3 maturity. NIS2 compliant. MTTD < 8 hours. Full incident response playbooks. Purple team exercise completed with documented improvements.
