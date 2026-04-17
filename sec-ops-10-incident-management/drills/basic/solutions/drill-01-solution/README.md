# Solution: Drill 01 — Incident Classification

## Incident 1 — Nurse Workstation

| Dimension | Value |
|-----------|-------|
| Type | Malware — possible RAT/backdoor |
| Severity | **P1** — Healthcare workstation, clinical environment, patient data access, active infection |
| Scope | Single workstation initially; possible lateral movement (unknown) |
| GDPR Notification | **Possibly Yes** — nurse has access to patient records (special category data under GDPR Art. 9) |
| Immediate Action | Isolate workstation via EDR. Notify IR manager. Preserve volatile evidence first. |

**Justification for P1:** Clinical environment where workstation compromise could affect patient care, AND patient data (special category under GDPR) is at risk.

---

## Incident 2 — Pentest SQL Injection

| Dimension | Value |
|-----------|-------|
| Type | **Benign True Positive** — Authorized penetration test |
| Severity | **P4** (informational, documented activity) |
| Scope | HR database |
| GDPR Notification | **No** — Activity was authorized under signed contract. Not a breach. |
| Immediate Action | Document the finding. Create a vulnerability remediation ticket. Ensure pentest scope is confirmed by contract. |

**Important note:** Even though this is a Benign TP, the SQL injection vulnerability requires remediation.
The PIR equivalent here is a vulnerability remediation plan.

---

## Incident 3 — Blocked Phishing Emails

| Dimension | Value |
|-----------|-------|
| Type | Attempted social engineering / phishing (blocked) |
| Severity | **P4** — No delivery, no compromise |
| Scope | Mail gateway (no systems affected) |
| GDPR Notification | **No** — No personal data accessed or at risk |
| Immediate Action | Document. Update mail gateway blocklist. Note campaign for threat intelligence. |

---

## Incident 4 — Backup Server Ransomware

| Dimension | Value |
|-----------|-------|
| Type | Malware — Ransomware |
| Severity | **P1 CRITICAL** — Patient data backup server actively encrypting |
| Scope | backup-srv-01 potentially enterprise-wide (all backups at risk) |
| GDPR Notification | **YES — MANDATORY** — Patient data (special category) is actively being encrypted/potentially exfiltrated. 72h clock has started. NIS2 24h early warning also applies (hospital = essential entity). |
| Immediate Action | Immediate network isolation of backup-srv-01. Alert IR Manager and CISO. Check if other backup nodes are affected. |

**Critical:** The 72-hour GDPR clock starts NOW.
Legal must be engaged immediately.

---

## Incident 5 — Terminated Employee Access

| Dimension | Value |
|-----------|-------|
| Type | Unauthorized access / Insider threat (possibly) |
| Severity | **P2** — Confirmed unauthorized access from a foreign country to a system with patient billing data |
| Scope | Patient billing portal |
| GDPR Notification | **Possibly Yes** — Patient billing data (includes names, dates, payment info) accessed by unauthorized person |
| Immediate Action | Immediately disable Kovacs' account across ALL systems (not just billing portal). Check session logs to determine what was accessed. Notify HR and Legal. |

**Note:** IT's failure to disable the account is the root cause — this generates an action item for off-boarding process improvement.

---

## Incident 6 — SSH Brute Force (All Blocked)

| Dimension | Value |
|-----------|-------|
| Type | Denial of service / Brute force attempt |
| Severity | **P4** — All attempts blocked, no compromise |
| Scope | External jump server (no internal systems affected) |
| GDPR Notification | **No** |
| Immediate Action | Verify all 3,000 attempts were blocked (no successful login). Consider adding rate limiting. Document source IP in threat intel. |

---

## Summary Table

| Incident | Type | Severity | GDPR Required |
|---------|------|----------|---------------|
| 1 — Nurse workstation | Malware | P1 | Possibly |
| 2 — Pentest SQL injection | Benign TP | P4 | No |
| 3 — Blocked phishing | Attempted phishing | P4 | No |
| 4 — Backup server ransomware | Ransomware | P1 Critical | **YES** |
| 5 — Terminated employee | Unauthorized access | P2 | Possibly |
| 6 — SSH brute force | Brute force (blocked) | P4 | No |
