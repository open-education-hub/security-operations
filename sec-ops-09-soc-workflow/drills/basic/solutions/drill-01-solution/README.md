# Solution: Drill 01 — Alert Prioritization

## Step 1: Re-Prioritize the Queue

**Immediate priority order:**

| Priority | Alert # | Title | Reasoning |
|----------|---------|-------|-----------|
| 1 | #12 | RDP brute force — 342 attempts — rdp-gw-01 | Default P1 AND very high attempt count. Active attack in progress. Oldest (00:30). |
| 2 | #2 | New admin account created — AD | P2. Account created at 01:44 with no change ticket. Possible backdoor persistence. |
| 3 | #4 | PowerShell encoded — exec-ws-001 (exec assistant) | P2. Encoded PowerShell on a high-value asset (CEO assistant). May be initial access/staging. |
| 4 | #3 | Large data transfer — file-server-01 | P2. File server contains HR and financial data — exfiltration risk is real. |
| 5 | #7 | AV detection — av-mgr | P2. Confirmed malware signature. Need to verify if quarantined/active. |
| 6 | #9 | DNS DGA query — mkt-ws-009 | P3 elevated. DGA domains strongly suggest malware present. |
| 7 | #10 | Admin login after hours — srv-mgr-01 | P3. Could be legitimate, needs quick check. |
| 8 | #1 | SSH brute force — jumphost | P3. External brute force is common; assess if successful. |
| 9 | #6 | VPN failures — s.jones | P3. Low count (3), likely user error. |
| 10 | #5 | USB — ceo-laptop | P3. CEO is traveling — could be legitimate. Also, CEO is high value. |
| 11 | #8 | Port scan — dev-ws-055 | Benign TP. Known developer behavior — confirm with change record. |
| 12 | #11 | TLS cert error — prod-lb-01 | P4. Operational issue, not security. |

---

## Top 5 Triage Decisions

### Alert #12 — RDP Brute Force

**Step 1 (Read):** 342 failed RDP attempts to rdp-gw-01 starting at 00:30 UTC.

**Step 2 (Enrich):** Check source IP in VT/AbuseIPDB.
Check if any logins succeeded in Windows Event ID 4624.
**Step 3 (Context):** No maintenance. 342 attempts = sustained campaign, not random scanning.

**Step 4:** True Positive

**Step 5 (Severity):** P1 if any successful login.
P2 if all failed.
**Step 6:** If successful login → ESCALATE P1 immediately.
If no success → P2, investigate source IP, consider blocking.

---

### Alert #2 — New Admin Account

**Step 1:** New admin account created in AD at 01:44 UTC.

**Step 2:** Query AD for account name, creator, OU placement.
Check if there's a change ticket for this account creation.
**Step 3:** No scheduled maintenance. 01:44 is off-hours.
Red flag.
**Step 4:** True Positive (suspicious) — pending change ticket check

**Step 5:** P1 if no change ticket (unauthorized admin backdoor).
P2 if change ticket found.
**Step 6:** Immediately check change management.
If no ticket → ESCALATE P1.

---

### Alert #4 — PowerShell Encoded — exec-ws-001

**Step 1:** Encoded PowerShell on CEO assistant workstation at 04:12.

**Step 2:** Check full command line (decode the base64).
Check parent process.
Check VirusTotal for the decoded command/hash.
**Step 3:** CEO assistant = high-value target.
Off-hours execution.
Encoded = obfuscation attempt.
**Step 4:** True Positive

**Step 5:** P1 (high-value asset, obfuscation, off-hours)

**Step 6:** ESCALATE immediately.
Do not isolate yet pending L2 confirmation.

---

### Alert #3 — Large Data Transfer

**Step 1:** 1.2 GB transferred from file-server-01 to an unknown destination at 03:30.

**Step 2:** Check destination IP.
Check which user/process initiated the transfer.
Check SIEM for other alerts on file-server-01.
**Step 3:** Off-hours.
File server has HR + financial data.
No maintenance.
**Step 4:** True Positive (suspicious)

**Step 5:** P1 if destination is external unknown IP; P2 if internal transfer

**Step 6:** Determine source/destination.
ESCALATE P1 if external.

---

### Alert #7 — AV Detection

**Step 1:** AV flagged malware signature on an unspecified host at 05:01.

**Step 2:** Identify host.
Check if file was quarantined.
Look up hash on VirusTotal.
Check for lateral movement from that host.
**Step 3:** AV may have quarantined it automatically.
Need to verify.
**Step 4:** True Positive

**Step 5:** P2 (confirmed malware, need to assess if contained)

**Step 6:** Open case, assign to Tier 2 if malware active.

---

## Alert #8 — Port Scan from dev-ws-055

**Classification: Benign True Positive**

The developer is known to run network scans for work.
Verify against change management or ask developer directly.
If confirmed: close as Benign TP, document the expected behavior for future suppression.

---

## Handover Note (Sample)

```markdown
# Shift Handover — Nov 14, 2024 — 08:00→10:00 UTC
## Incoming: [Name]

### Critical Open Cases
| Case | Title | Status | Next Action | SLA |
|------|-------|--------|-------------|-----|
| INC-601 | RDP brute force — rdp-gw-01 | In Progress | Check for successful logins, block source IP | 10:00 |
| INC-602 | New admin account — AD | ESCALATED to L2 | L2 investigating, no change ticket found | 10:30 |
| INC-603 | PowerShell encoded — exec-ws-001 | ESCALATED to L2 | L2 reviewing decoded payload | 10:12 |

### Watch List
| Host/User | Reason |
|-----------|--------|
| rdp-gw-01 | Active brute force in progress |

### Notes
- dev-ws-055 port scan (alert #8) closed as Benign TP — confirmed developer activity
- Alert #11 (TLS cert) triaged as P4, IT team notified separately
```
