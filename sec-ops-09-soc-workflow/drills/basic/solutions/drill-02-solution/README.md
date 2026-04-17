# Solution: Drill 02 — Ticket Management and SLA Tracking

## SLA Deadlines Table

| Case | Severity | Created | Acknowledge By | Resolve By | Status at 11:45 |
|------|----------|---------|----------------|-----------|-----------------|
| INC-501 | P1 | 09:00 | 09:15 | 11:00 | BREACHED (not acknowledged by 09:18) |
| INC-502 | P2 | 08:30 | 09:00 | 12:30 | At risk — resolve by 12:30 |
| INC-503 | P3 | 07:00 | 09:00 | 19:00 | On track |
| INC-504 | P2 | 06:00 | 06:30 | 10:00 | BREACHED — resolve SLA passed |
| INC-505 | P3 | 03:00 | 05:00 | 15:00 | On track — but nearly 7 hours without update |
| INC-506 | P2 | 09:45 | 10:15 | 13:45 | On track, but incomplete closure |

---

## Case Analysis

### INC-501 — Ransomware P1

**Problem:** Case created at 09:00, still NEW and unassigned at 09:18.
P1 acknowledge SLA is 15 minutes = 09:15. **SLA BREACHED.**

**Correct action:** This case should have been assigned and acknowledged within 15 minutes of creation.
At 09:18, an analyst should immediately:

1. Assign the case to themselves
1. Contact the IR team if ransomware is confirmed
1. Begin host isolation

**SLA breach must be documented** with a root cause (e.g., "no analyst monitoring queue at 09:00-09:18 due to shift transition overlap").

---

### INC-502 — CFO Phishing P2

**Problem:** Assigned at 08:45 (within SLA).
But the only note is "Looking at it" added at 08:45.
It is now 11:45 — over 3 hours with no update.
Resolve SLA is 12:30 — **45 minutes remaining.**

**Missing:** Specific enrichment results, enrichment timeline, current status, next action.

**Correct action:** Add detailed investigation notes immediately.
If investigation is taking this long, escalate to Tier 2 now.

---

### INC-503 — VPN Failures — s.jones

**Closure Classification:** Benign True Positive

**Rationale:** s.jones confirmed she forgot her password and locked herself out.
The detection rule correctly flagged multiple failures; the activity was legitimate.

**Corrected closure note:**

```text
[10:30 UTC] Closure — Benign True Positive

Investigation Summary:
  8 failed VPN login attempts for user s.jones observed between 07:00 and 07:22 UTC.

Verification:
  - Called s.jones directly at 09:00 UTC
  - s.jones confirmed she was attempting to log in from home and forgot her password
  - She reset her password via the self-service portal at 09:15 UTC
  - Successfully authenticated at 09:17 UTC (confirmed in VPN logs)
  - No other unusual activity on this account in the past 30 days

Classification: Benign True Positive
Root cause: User error (forgotten password)
Action taken: None required. Closed.
Tuning recommendation: Consider suppressing this rule for known users
  with a verified password reset in the same session.
```

---

### INC-504 — Large Transfer — dev-ws-044

**Problem:** Created at 06:00.
Assigned at some point.
Now at 10:15.
P2 resolve SLA was 10:00. **SLA BREACHED.**

**Additional issue:** Putting a case in PENDING and waiting passively for the dev team is not sufficient.
The analyst should have:

1. Escalated to Tier 2 at the 2-hour mark if dev team didn't respond
1. Looked up the dev on the phone directory and called directly
1. Continued independent investigation (look at destination IP, traffic content, other activity on the host)

**Correct action:** Immediately assign to Tier 2, add note documenting the SLA breach and reason.

---

### INC-505 — Admin Login After Hours

**Problem:** Created at 03:00.
One note at 03:05 ("Need to check with DBA").
It is now 10:00 — **6 hours, 55 minutes** with no update.
P3 resolve SLA is 15:00 — 5 hours remaining.

**Issue:** The analyst never followed up.
The case is drifting.
If this was a malicious admin login, 7 hours of unchecked access is extremely dangerous.

**Correct action:**

1. Contact DBA team immediately
1. If DBA confirms activity was theirs → close as Benign TP
1. If DBA denies activity → escalate P1 immediately
1. If DBA can't be reached → escalate P2 to Tier 2

---

### INC-506 — AV Detection

**Problem:** Resolution note says "Quarantined file.
Closed." This is insufficient.

**Missing information:**

* Which host is affected?
* Which user?
* Was the file actively executing or just present?
* Has the quarantine been verified?
* Was malware analysis performed?
* Are other systems affected?
* What is the malware's actual behavior?

**Corrected closure note:**

```text
[11:00 UTC] Closure — True Positive

Investigation Summary:
  AV (Windows Defender) detected Trojan.GenericKD.47234 on mkt-ws-012
  belonging to user K. Wilson (Marketing).

File details:
  Path: C:\Users\k.wilson\Downloads\invoice_nov14.exe
  SHA256: aabb1122...
  VirusTotal: 52/72 vendors detect as malware
  Malware family: Generic downloader / Trojan

Containment:
  - File automatically quarantined by Defender at 09:45 UTC
  - Quarantine confirmed active in CrowdStrike Falcon at 10:50 UTC
  - File was in Downloads folder, no evidence of execution (no child processes,
    no network connections from this file in Sysmon logs)

Scope assessment:
  - No lateral movement indicators on network
  - No other AV detections on adjacent hosts

Root cause:
  User K. Wilson received a phishing email with a malicious attachment
  and downloaded it. User did not execute it.

Actions taken:

  1. File quarantined (automatic, by AV)

  2. Phishing email deleted from user's mailbox
  3. User notified and security awareness reminder sent

Classification: True Positive
Further action required: No (contained)
```
