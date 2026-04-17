# Drill 01 Solution: Incident Classification

---

## Alert 1: The Blocked Port Scan

**False positive?** Not a false positive — this is a real event.
However, it may not warrant full incident response.

**NIST Category:** Investigation (potential precursor to Unauthorized Access — Reconnaissance)

**Severity:** P5 (Informational)

**Reasoning:**

* All probes were BLOCKED by the firewall — no actual access occurred
* No previous alerts from this IP
* This is external reconnaissance — extremely common background noise
* Port scan alone (with all traffic blocked) does not constitute an incident

**Immediate action:**

* Log and track
* Add the source IP to a watchlist for 30 days
* If the same IP appears in a subsequent, more targeted alert — re-evaluate as P3+

**Escalation triggers:** None

**Common mistake:** Upgrading this to P3 or higher.
Unblocked port scans from an IP that then exploits a vulnerability = P2+.
A blocked scan from an IP seen in no other alerts = P5.

---

## Alert 2: The Helpdesk Ticket

**False positive?** NOT a false positive.
This is an active Business Email Compromise (BEC) attempt.

**NIST Category:** Social Engineering / Unauthorized Access (attempted financial fraud)

**Severity:** P2 (High)

**Reasoning:**

* BEC targeting a manager with financial transfer authority
* CFO impersonation from external lookalike domain (`acme-finance.net` vs `acme.com`)
* $47,000 requested transfer = significant financial impact if successful
* "Keep it confidential" instruction = social engineering red flag
* The user is a Marketing Manager, not Finance — but has been specifically targeted

**Severity factors:**

* BEC + financial transfer request = HIGH regardless of asset criticality
* If transfer had already occurred: P1

**Immediate action:**

* Contact the reporting user immediately — confirm no transfer has been made
* Escalate to Finance department to freeze any pending transfers
* Forward the original email to SOC for header analysis
* Check if other employees received similar emails (campaign targeting)
* Notify CISO (P2 requires management notification)

**Escalation triggers:**

* Financial fraud attempt = escalate to CISO and Finance leadership
* If transfer occurred: elevate to P1, engage Legal, file police report

---

## Alert 3: The Crypto Miner

**False positive?** This is a real event — the mining software is real and running.

**NIST Category:** Inappropriate Usage (policy violation)

**Severity:** P4 (Low) — NOT P1

**Reasoning:**

* Cryptominer installed by the user themselves — not by an external attacker
* Low-criticality non-production asset
* User admits responsibility
* xmrig itself is not inherently malicious — it's a policy violation in a corporate context
* No lateral movement, no data exfiltration, no credential theft indicators

**Immediate action:**

* Remove xmrig and any related software from the workstation
* Document as a policy violation
* HR/manager notification per policy
* Verify the user's other systems have not been similarly affected
* Block `minexmr.com` and similar mining pool domains at the DNS level

**Escalation triggers:**

* None for this incident
* However: run threat hunt for xmrig.exe / mining pool connections across the fleet

  (other users may have installed it; or actual malware-dropped miners may be hiding in the noise)

---

## Alert 4: The Suspicious Login

**False positive?** NOT a false positive.
Impossible travel + no MFA + Finance Director = high-confidence credential compromise.

**NIST Category:** Unauthorized Access

**Severity:** P1 (Critical)

**Reasoning:**

* Finance Director account = HIGH/CRITICAL asset (financial data, strategic info)
* 8,500 km in 6h43m is physically impossible
* No MFA → credentials alone are sufficient for access
* SharePoint access to HR data = potential data breach
* The Nigerian session was almost certainly an unauthorized actor

**Immediate action:**

* IMMEDIATE: Disable the `m.johnson@acme.com` account pending investigation
* IMMEDIATE: Terminate all active sessions
* Check SharePoint access logs — what data was accessed during the Nigerian session?
* Notify CISO and the Finance Director via a separate communication channel
* Conduct forensics on what was accessed during the suspicious session
* Determine how credentials were compromised (credential stuffing? phishing?)

**Escalation triggers:**

* Finance Director compromise → escalate to CISO immediately
* SharePoint access to HR data → potential GDPR breach, engage Legal/DPO
* No MFA = **control failure** — escalate for emergency MFA deployment for Finance

---

## Alert 5: The Malware Alert with Context

**False positive?** This is a real detection but low-severity.

**NIST Category:** Malicious Code (adware, minor)

**Severity:** P5 (Informational) / P4 at most

**Reasoning:**

* Adware (not a RAT, ransomware, or targeted malware)
* Successfully quarantined — no running presence
* No network activity, no lateral movement
* Reception PC has no access to internal systems
* Known legitimate (if undesirable) software

**Immediate action:**

* Verify quarantine is complete (second scan)
* Block the download site at proxy/DNS
* User education: remind about downloading software from unknown sites
* Document as P5 — routine cleanup event

**Escalation triggers:** None

**Important nuance:** Even though the threat is low, document the user behavior.
Repeated incidents from the same user warrant an HR referral.

---

## Alert 6: The Ransomware Indicator

**False positive?** NOT a false positive.
This is active ransomware.

**NIST Category:** Malicious Code / Multiple Components (Ransomware)

**Severity:** P1 (Critical) — IMMEDIATELY

**Reasoning:**

* 1,847 file modifications in 2 minutes = active encryption
* `.locked_by_mafia` extension change = ransomware signature
* `vssadmin delete shadows` = ransomware standard anti-recovery technique
* Ransom note created
* Finance workstation = HIGH criticality (financial systems access)
* Network connections within internal range = SPREADING to network drives

**Immediate action (seconds count):**

1. **IMMEDIATELY** isolate FINANCE-WS-03 from the network (EDR isolation)
1. **IMMEDIATELY** page/call the SOC manager and CISO — do not wait for email
1. Identify all network drives accessible from this workstation — check for encryption there
1. Check other workstations in the 172.16.1.0/24 range for encryption activity
1. Do NOT power off the system (volatile evidence + encryption may accelerate offline)
1. Do NOT attempt to pay ransom without CISO and Legal authorization

**Escalation triggers:**

* Active ransomware = P1 immediately
* Finance systems access = CISO notification required
* Spread to network drives = multiple systems impacted

---

## Alert 7: The After-Hours Access

**False positive?** NOT a false positive — this requires investigation.

**NIST Category:** Investigation → Unauthorized Access (suspected) OR Inappropriate Usage

**Severity:** P2 (High)

**Reasoning:**

* Production DBA account accessing production customer data at 2am Saturday
* 47,000 customer records exported to CSV = significant data exposure
* No change control ticket = unauthorized procedure
* Completely outside baseline behavior
* Finance Director account = HIGH criticality

**Critical nuance:** MFA passed.
This means either:

1. The legitimate DBA is working unauthorized (insider threat / policy violation), OR
1. An attacker has compromised the DBA's credentials AND their MFA device

Both scenarios require P2 treatment.

**Immediate action:**

* Do NOT immediately disable the account — contact the DBA via an out-of-band channel (phone) to verify if they were working
* If DBA confirms it was them: document policy violation, HR referral, incident close as P4 (inappropriate usage)
* If DBA denies: immediate account disable, P1 upgrade (credential compromise + data breach)
* In either case: investigate the CSV file — where did it go? Was it emailed? Uploaded?

**Escalation triggers:**

* If confirmed unauthorized access: P1, breach notification assessment required
* 47,000 records = GDPR notification threshold → engage Data Protection Officer

---

## Alert 8: The VPN Brute Force

**False positive?** NOT a false positive.

**NIST Category:** Unauthorized Access (attempted brute force)

**Severity:** P3 (Medium)

**Reasoning:**

* 847 attempts against 23 accounts = systematic credential stuffing attack
* MFA deployed = significantly reduces risk even if password is correct
* No successful authentications = attack has not succeeded yet
* However: 3 accounts locked out = disruption (availability impact, minor)
* The attack is ongoing

**Why not P2?**

* MFA is deployed and working
* No successful authentications
* No confirmed credential exposure

**Why not P5?**

* Active, ongoing attack targeting real user accounts
* 23 usernames suggest access to a breach list specific to this org
* Account lockouts = small availability impact

**Immediate action:**

* Block the source IP (103.224.182.47) at the VPN gateway
* Unlock the 3 locked accounts after confirming with users
* Check if the username list matches a known external breach — search Have I Been Pwned
* Notify the 23 targeted users to change their passwords as a precaution
* Verify MFA is working correctly on all accounts

**Escalation triggers:**

* If any authentication succeeds → upgrade to P1
* If the source IP is linked to a known APT → upgrade to P2

---

## Summary Table

```text
Alert | False Positive? | NIST Category      | Severity | Key Action              | Escalation?
──────┼─────────────────┼────────────────────┼──────────┼─────────────────────────┼────────────
  1   | No (real event) | Investigation      | P5       | Log + watchlist         | None
  2   | No              | Social Engineering | P2       | Confirm no transfer made | CISO + Finance
  3   | No              | Inappropriate Use  | P4       | Remove + HR notify      | None
  4   | No              | Unauthorized Access| P1       | Disable account NOW     | CISO + Legal
  5   | No              | Malicious Code     | P5       | Verify quarantine       | None
  6   | No              | Malicious Code     | P1       | Isolate immediately     | CISO (NOW)
  7   | No              | Investigation      | P2       | Contact DBA out-of-band | DPO if confirmed
  8   | No              | Unauth Access(att) | P3       | Block IP + notify users | Upgrade if success
```
