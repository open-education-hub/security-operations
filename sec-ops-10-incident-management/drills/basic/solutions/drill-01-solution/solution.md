# Solution: Drill 01 (Basic) — Incident Response Decision Tree

This solution provides model answers for all 7 scenarios.
Compare your answers against these and note where your reasoning diverged.

---

## Scenario 1: The Midnight Alert

> SIEM: Mass file rename — 500+ files renamed to `.locked` on HR-SERVER-01 in 60 seconds

| Question | Model Answer |
|---------|-------------|
| **A. Confirmed incident or false positive?** | **Confirmed incident.** 500+ files renamed to `.locked` within 60 seconds matches the unmistakable behavioral signature of ransomware encryption in progress. No authorized maintenance activity produces this pattern. There is no reasonable false positive explanation. |
| **B. Incident type?** | **Malware — Ransomware.** Active file encryption is occurring on the server right now. |
| **C. Severity?** | **P1 — Critical.** Active ransomware encrypting a server containing sensitive personal data for 2,300 employees (national IDs, salary, medical records). Real-time spread risk to other servers is high. The incident is active, not detected after the fact. |
| **D. GDPR notification likely required?** | **Yes.** HR-SERVER-01 contains special category personal data (medical leave records under GDPR Art. 9) and highly sensitive data (national IDs, salary) for 2,300 employees. Even if encryption is the compromise, availability loss to personal data is a GDPR breach. The 72-hour clock starts from the moment the incident is confirmed (02:14 UTC). |
| **E. First immediate action?** | **Network isolate HR-SERVER-01 immediately** — pull it from the network segment to prevent lateral spread to other servers while preserving memory for forensics. Do NOT shut the server down (preserves volatile evidence). Simultaneously: wake up the on-call incident commander. |

**Key learning:** The GDPR clock starts at *awareness of a likely breach*, not after investigation is complete.
With ransomware on an HR server, notification is almost certainly required — you cannot wait for full forensics to decide.

---

## Scenario 2: The Shared Password

> Employee shared VPN password with terminated colleague. Colleague was terminated yesterday.

| Question | Model Answer |
|---------|-------------|
| **A. Confirmed incident or potential?** | **Potential incident / active risk.** The credential sharing is confirmed, but unauthorized access has not been confirmed yet. However, the risk is live: the terminated employee may still be using the VPN credentials right now. |
| **B. Incident type?** | **Unauthorized access risk** (potential insider threat + credential compromise). If the ex-employee has already logged in after termination, it becomes confirmed unauthorized access. |
| **C. Severity?** | **P2 — High.** A terminated employee (motive for misuse) has credentials to VPN and potentially access to SAP financial systems. The window of compromise is right now — today. It is not P1 because there is no confirmed access yet, but P2 is appropriate given the live risk and sensitive systems involved. |
| **D. GDPR concern?** | **Yes, potentially.** SAP financial systems likely contain personal data of employees and possibly customers. If the ex-employee has accessed or could access this data, a GDPR breach may be in progress or imminent. The situation must be investigated before a notification determination can be made. |
| **E. Most urgent first action?** | **Immediately disable/revoke the VPN account** — both the password-sharing employee's credentials and any session tokens. Then check VPN logs for any logins from the ex-employee's device/IP after their termination date. This takes minutes and closes the live exposure window. Escalate to HR and Legal for the broader access rights review. |

**Key learning:** A terminated employee with live credentials is treated as P2 even without confirmed misuse.
The urgency is the live exposure window — you may be in a race against an unauthorized login happening right now.

---

## Scenario 3: The Researcher's Report

> Security researcher: SQL injection on login page, extracted 5 test records. Proof-of-concept attached.

| Question | Model Answer |
|---------|-------------|
| **A. Incident type?** | **Web application attack — SQL Injection / Unauthorized data access.** Despite being reported by a researcher in good faith, unauthorized data access via SQLi has occurred. A researcher's benign intent does not change the incident classification. |
| **B. Severity?** | **P2 — High** (verging on P1 pending scope assessment). The vulnerability is confirmed exploitable, 5 records were extracted, and 45,000 customer records are at risk. The database is live and the vulnerability may still be open. Escalate to P1 if investigation reveals more than 5 records were accessed, or if the vulnerability is being actively exploited by others. |
| **C. Has GDPR been triggered?** | **Yes.** Five customer records (email addresses, usernames) were accessed without authorization by a third party. This is a personal data breach under GDPR Art. 4(12), regardless of the researcher's intent. The 72-hour clock starts from the time you received and read this email (the moment of *awareness*). |
| **D. Can you trust the researcher's claim about only 5 records?** | **No — you must verify independently.** A researcher may have extracted more than they disclosed. You must: (1) review database query logs for the timestamp of their session, (2) check network egress logs for data volume from the database, (3) check web server access logs for the specific SQLi payload pattern across the full log history (not just today). The researcher may also have shared the technique with others. |
| **E. Two immediate actions?** | 1. **Block the SQLi endpoint immediately** — apply a WAF rule or take the login endpoint offline temporarily to stop further exploitation. 2. **Preserve all relevant logs** (web server, database, WAF) with hash verification before anything is changed. These are your forensic evidence of scope. |

**Key learning:** Responsible disclosure does not stop the GDPR clock.
The breach occurred when the researcher accessed the data — the notification window has already started.
You must scope the breach urgently.

---

## Scenario 4: The Insider

> Departing employee copied ~8 GB from SharePoint to personal OneDrive on their last day.

| Question | Model Answer |
|---------|-------------|
| **A. Incident type?** | **Insider threat — data exfiltration** (intellectual property theft). The employee had authorized access to the systems but exceeded authorized use by copying files to a personal account before departure. |
| **B. Severity?** | **P2 — High.** Source code, product roadmap, and customer technical specifications are high-value IP. Depending on company size and competitive landscape, this could cause significant business harm. Not P1 because no system is actively compromised and no customer personal data is involved. |
| **C. GDPR triggered?** | **No** (or very unlikely). The scenario explicitly states: "No personal employee data was involved." Source code and product roadmaps are not personal data. Customer technical specifications may contain personal data if they include customer names/contacts — this should be verified, but based on the facts given, GDPR is not clearly triggered. |
| **D. Law enforcement consideration?** | **Yes.** Copying IP before departure may constitute criminal data theft or breach of employment contract. However, involve Legal before contacting law enforcement — preserving the ability to pursue civil remedies may be impacted by how you handle the evidence and investigation. Do not contact law enforcement unilaterally. |
| **E. Evidence sources still available?** | Even though the employee has left: (1) **SharePoint audit logs** — record what was accessed, when, and what was downloaded; (2) **Azure AD sign-in logs** — confirm the employee's sessions and devices; (3) **OneDrive external sharing logs** — if data was shared externally it leaves a log trail; (4) **DLP logs** — if a DLP tool flagged the transfer; (5) **Email logs** — check if any files were emailed out; (6) **The employee's corporate laptop** — if returned, should be imaged before wiped. |

**Key learning:** For insider threat, evidence preservation is the top priority because the employee and their personal devices are outside your control.
Legal involvement is essential before any external action.

---

## Scenario 5: The API Key

> GitHub secret scanner detected production AWS IAM key `ci-deploy-prod` in a public repository.

| Question | Model Answer |
|---------|-------------|
| **A. Incident type?** | **Unauthorized access / credential exposure.** A production AWS key has been exposed publicly. This is both a credential compromise incident and a potential unauthorized cloud access incident. |
| **B. Severity?** | **P1 — Critical.** The key is attached to a production IAM user with EC2 read/write and S3 write access. The key has been public for an **unknown** duration — attackers scan GitHub continuously (automated scanners pick up exposed keys within minutes). Assume compromise has already occurred. Any doubt should escalate to P1, not de-escalate. |
| **C. GDPR triggered?** | **Potentially yes.** The S3 bucket contains "customer-generated files." The nature of those files determines GDPR applicability. If customer-generated files contain any personal data (names, emails, photos, documents), and if an attacker accessed the bucket, a GDPR breach may be in progress. Investigation of AWS CloudTrail logs to determine what was accessed is urgent. |
| **D. Most urgent action?** | **Immediately revoke/disable the `ci-deploy-prod` IAM key in AWS IAM console.** This is the single most time-critical action. Every second the key is active is another second an attacker can use it. Revoke first, investigate second. Do not wait for anyone's approval — this is a P1 action. |
| **E. Logs to check for impact?** | (1) **AWS CloudTrail** — all API calls made with `ci-deploy-prod` credentials, with timestamps, source IPs, and actions; (2) **S3 access logs** for the relevant bucket — what was listed, downloaded, written, or deleted; (3) **EC2 activity logs** — were any instances started, modified, or accessed?; (4) **GitHub API logs** — when was the commit made (determines exposure window start time). |

**Key learning:** With exposed credentials, revoke first — always.
The investigation can wait 30 seconds.
The key cannot.

---

## Scenario 6: The Help Desk Call

> User received fake password reset email, clicked it, entered old and new password on a phishing site.

| Question | Model Answer |
|---------|-------------|
| **A. Incident type?** | **Social engineering — phishing / credential harvest.** The attacker used a typosquatted domain (`login.company-support.com`) to capture the employee's current password (they entered their "old password") and their new intended password. |
| **B. Did the attacker succeed? How to determine?** | **Almost certainly yes** — the user entered their current password on an attacker-controlled site. To confirm: (1) Check if the attacker already attempted to use the harvested credentials — review Active Directory authentication logs and M365 sign-in logs for logins from unexpected IPs in the last hour; (2) The "asking to enter again" behavior is consistent with the phishing kit capturing the credentials and then redirecting — this is standard. The attacker likely has the credentials. |
| **C. Severity?** | **P2 — High.** A single standard user with M365, HR portal, and VPN access is compromised. Not P1 yet (no confirmed active breach, no privileged account), but must escalate to P1 if: (a) active attacker use is detected in logs, (b) the user has higher privileges than described, or (c) this is one of multiple phishing victims. |
| **D. Immediate actions (ordered)?** | 1. **Force a password reset on the compromised account immediately** AND revoke all active sessions (M365 "sign out everywhere"). 2. **Check authentication logs** for the past 60 minutes — identify if the stolen credentials have been used. 3. **Preserve the phishing URL and email headers** — report the phishing URL for takedown and share with threat intel team. |
| **E. GDPR implications?** | **Potentially yes.** The M365 account may contain emails with personal data of employees or customers. The HR portal access could expose employee personal data. If investigation confirms the attacker accessed the account (not just harvested credentials), GDPR notification must be assessed. Monitoring the account for unauthorized access is essential in the next 72 hours. |

**Key learning:** When a user has entered their password on a phishing site, treat it as a confirmed credential compromise.
Do not wait for "confirmation" — reset the password immediately.

---

## Scenario 7: The Multi-Stage Alert

> Kerberoasting → Pass-the-Hash lateral movement → Privilege escalation to Domain Admin on PCI-DSS server

| Question | Model Answer |
|---------|-------------|
| **A. Incident type and MITRE ATT&CK tactics?** | **Advanced attack — APT-pattern intrusion / Active Directory compromise.** MITRE tactics: **Credential Access** (T1558.003 — Kerberoasting), **Lateral Movement** (T1550.002 — Pass the Hash), **Privilege Escalation** (T1078 — Valid Accounts / domain admin). This is a multi-stage, targeted attack chain — not opportunistic malware. |
| **B. Severity?** | **P1 — Critical, immediate.** A threat actor has domain admin privileges on a server processing payment card data (PCI-DSS scope). Active attacker in your network with the highest possible privileges. This is the definition of P1. |
| **C. Targeted or opportunistic?** | **Almost certainly targeted.** Kerberoasting requires knowledge of your domain structure. The sequence — recon → credential theft → lateral movement → privilege escalation — in under 20 minutes reflects a prepared, experienced attacker using a pre-planned playbook. Opportunistic attackers don't typically know to move from DEVWS-022 directly to APP-SERVER-04 (PCI-DSS server) unless they've done reconnaissance. |
| **D. Regulatory implications?** | Multiple frameworks apply: (1) **PCI-DSS** — a system in-scope for card data has been compromised by a domain admin-level attacker. PCI-DSS requires notifying your acquiring bank and relevant card brands within mandated timeframes; a Qualified Security Assessor (QSA) may be needed for forensics. (2) **GDPR** — if any customer personal data was accessible from APP-SERVER-04 or through domain admin privileges on other systems, GDPR notification must be assessed within 72 hours of awareness. (3) **NIS2** (if the organization qualifies as essential/important entity) — significant incident notification required. |
| **E. Containment challenge — developer in meeting?** | **Isolate the workstation without the developer present.** You do NOT need the developer's consent or presence. Network team: immediately pull `DEVWS-022` from the network (block the port at the switch level or quarantine via EDR). The developer's meeting can wait — an active attacker with domain admin privileges cannot. Send someone to the meeting room to inform the developer their machine is being isolated; they cannot return to it until forensics is complete. Meanwhile, **reset the `svc-deploy` service account password** and the compromised domain admin credential immediately. |

**Key learning:** When an active attacker has domain admin, the entire domain is potentially compromised.
P1, immediate isolation, and parallel notification assessment are all mandatory simultaneously — you cannot do these sequentially.

---

## Summary Score Guide

| Scenario | Core concept tested |
|---------|-------------------|
| 1 — Midnight Alert | Ransomware recognition; GDPR special category data |
| 2 — Shared Password | Live credential risk; urgent response without confirmed breach |
| 3 — Researcher's Report | Good faith disclosure does not stop GDPR clock |
| 4 — The Insider | IP theft vs. personal data distinction; evidence preservation |
| 5 — API Key | Revoke first, investigate second; cloud credential exposure |
| 6 — Help Desk Call | Treat credential entry on phishing site as confirmed compromise |
| 7 — Multi-Stage Alert | APT chain recognition; multi-framework regulatory exposure |

**Score interpretation:**

* 7/7: Solid understanding of IR fundamentals — ready for intermediate drills
* 5–6/7: Good baseline; review the scenarios you missed and re-read reading material Section 2 (incident classification) and Section 10 (regulatory obligations)
* 3–4/7: Review Sessions 10 reading material Sections 2, 4, and 10 before proceeding
* <3/7: Re-read the full reading material and repeat the drill
