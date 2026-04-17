# Solution: Drill 02 — Playbook Design (Credential Stuffing at MedCorp)

---

## Task 1: Decision Tree

```text
[TRIGGER: Credential_Stuffing_Detected]
                │
                ▼

    1. Extract: source IPs, target accounts, success/fail counts

                │
                ▼
    2. Any SUCCESSFUL logins?
         │            │
        Yes            No
         │            │
         ▼            ▼
    3a. Were any    3b. Enrich source IPs
    successful         (AbuseIPDB)
    accounts              │
    admin/priv?     Is abuse score >50?
         │               │      │
        Yes/No          Yes     No
         │               │      │
         ▼               ▼      ▼
    4a. Admin?       Block IPs  Log + P3
    → IMMEDIATE       + P2      ticket
    disable +         ticket
    P1 escalate
         │
    4b. Regular user?
    → Disable +
    Notify +
    P2 ticket
         │
         ▼
    5. Did accounts access PHI systems?
         │            │
        Yes            No
         │            │
         ▼            ▼
    6. HIPAA breach  6b. Investigate
    assessment         scope
    (query SIEM
    for PHI access)
         │
         ▼
    7. Preserve evidence
    (HIPAA chain of custody)
         │
         ▼
    8. Close or escalate to Incident
```

---

## Task 2: Complete Playbook

```text
# Playbook: Credential Stuffing / Account Compromise Response

ID: PB-012
Version: 1.0
Last Updated: 2026-04-06
Owner: SOC Team
Review Cycle: Quarterly
Trigger Rules:
  - Credential_Stuffing_Detected
  - Multiple_Failed_Logins_Same_Src
  - Successful_Login_After_Failures

---

## 1. Purpose

Respond to credential stuffing attacks where automated tools attempt
to log in using lists of username/password combinations. Guide triage,
containment, evidence collection, and HIPAA breach assessment when PHI-
accessible accounts are involved.

---

## 2. Scope

Applies to: All Windows/cloud authentication events; Active Directory;
Exchange Online.
Does NOT apply to: Manual brute force by known attackers (separate
escalation playbook).

---

## 3. Prerequisites

Access required:
- [ ] Active Directory with Account Operator or Domain Admin role
- [ ] Splunk with access to windows:security index
- [ ] CrowdStrike Falcon console
- [ ] AbuseIPDB API key
- [ ] Jira (ticket creation)

---

## 4. Trigger Conditions

Activates when: Splunk rule fires showing:
- >20 failed logins from same source IP in 5 minutes AND/OR
- Any successful login following >10 failed attempts from same IP

---

## 5. Procedure

### Step 1: Initial Triage (Target: 5 min)

Who: L1 Analyst

1. Check alert details: how many accounts targeted, how many succeeded

2. Note source IPs
3. Query SIEM: are source IPs from known MedCorp locations?
   - Known MedCorp ranges: 10.0.0.0/8, 172.16.0.0/12
4. Query AbuseIPDB for all source IPs

Decision:
- Source IP is internal corporate range → Likely misconfigured script; P3; investigate source host
- Source IP is external + AbuseIPDB >50 + any success → P1 → Step 2 immediately
- Source IP is external + no successes → P2 → Step 2
- Source IP is external + low AbuseIPDB score + no successes → P3 → Step 2

### Step 2: Assess Successful Logins (Target: 5 min)

Who: L1 Analyst

For each successful account:

1. Check account type: admin? service account? regular user?

2. Check last legitimate login (SIEM historical)
3. Check login time vs. normal hours (3 AM login to billing account is anomalous)
4. Check access to PHI systems: did account access EHR, billing DB, PACS?

Decision:
- Admin account compromised → P1 → ESCALATE L2 IMMEDIATELY + Step 3
- Service account compromised → P1 → ESCALATE L2 IMMEDIATELY + Step 3
- Regular user with PHI access (billing, nursing) compromised → P2 → Step 3
- Regular user without PHI access compromised → P2 → Step 3

### Step 3: Contain (Target: 15 min)

Who: L1 (regular users), L2 (admin accounts)

For ALL successfully compromised accounts:
- Disable account in Active Directory (Runbook RB-001)
- Add description: "DISABLED - CREDENTIAL STUFFING - TKT-XXX - [date]"
- Invalidate active sessions

For compromised admin accounts (L2 with SOC Manager approval):
- Disable IMMEDIATELY (no delay)
- Check what the account accessed in last 2 hours (SIEM query)
- Quarantine any systems the admin account touched

Block source IPs at perimeter firewall (L1):
- Verify IPs not in corporate allowlist
- Block all 3 IPs
- Document in ticket: "Blocked IPs [list] at [time] per TKT-XXX"

### Step 4: Evidence Preservation (Target: 10 min)

Who: L1 (basic), L2 (full forensic)

Required evidence (ALWAYS preserve for HIPAA):
- [ ] SIEM log export: failed/successful logins with timestamps
  Query: index=soc_events EventCode IN (4624,4625) src_ip IN (91.108.4.1,91.108.4.2,91.108.4.3)
  Export as CSV with hash verification
- [ ] Screenshot: AbuseIPDB results for each source IP
- [ ] Screenshot: Account status before and after disable
- [ ] Export: All systems accessed by compromised accounts in last 24h

Chain of custody:
- SHA-256 hash all exported files
- Document: who collected, when, file hash
- Store in: /ir-evidence/TKT-XXX/ (access-controlled)

### Step 5: HIPAA Breach Assessment (if PHI-accessible accounts affected)

Who: L2 Analyst + Legal/Compliance consulted

1. Query SIEM: Did compromised accounts access EHR/billing/PACS after compromise time?

   Query (example for n.santos):
   index=soc_events user="n.santos" _time>=03:47 earliest=-1d
   (app=ehr OR app=billing OR dest_host IN ("ehr-server","billing-db"))
   | table _time, app, action, dest_host

2. Review access logs on PHI systems directly (EHR audit log)

3. Document findings in HIPAA breach assessment form:
   - Was PHI accessed? (Yes/No/Unknown)
   - If accessed: how many patient records?
   - Was PHI exfiltrated? (check outbound data transfers)

Decision:
- PHI was NOT accessed (confirmed by logs) → Not a breach; document findings
- PHI was accessed but not exfiltrated → Likely breach; notify Legal/CISO
- PHI was exfiltrated → CONFIRMED BREACH → P1 + Legal + CISO immediately

---

## 6. Escalation Criteria

Escalate to L2 immediately if:
- [ ] Any admin or service account successfully compromised
- [ ] More than 5 accounts successfully compromised
- [ ] Evidence of post-compromise lateral movement
- [ ] PHI access confirmed during unauthorized session
- [ ] Attack still ongoing (new attempts continuing)

Declare incident if:
- [ ] Admin account compromised with confirmed post-compromise access
- [ ] PHI exfiltration confirmed or suspected

CISO + Legal notification if:
- [ ] PHI breach confirmed or unresolvably uncertain
- [ ] >500 patient records potentially affected

---

## 7. Containment Actions

| Action | Who | Approval | Runbook |
|--------|-----|----------|---------|
| Disable regular user account | L1 | No approval | RB-001 |
| Disable admin account | L2 | SOC Manager verbal | RB-001 |
| Block source IPs at firewall | L1 | No approval (external IPs) | RB-010 |
| Isolate compromised workstation | L2 | No approval | RB-020 |
| Revoke OAuth/SSO sessions | L2 | No approval | RB-003 |
| Force password reset for org | L2+ | CISO approval | Special |

---

## 8. Communication

| Stakeholder | When | How | Template |
|-------------|------|-----|----------|
| Affected users | Within 1h of account disable | Email | MSG-003 |
| User's manager | When admin accounts involved | Email | MSG-004 |
| L2 / SOC Manager | On escalation | Slack + ticket | Standard |
| Legal/Compliance | HIPAA breach suspected | Email + phone | MSG-005 |
| CISO | P1 or confirmed breach | Phone call | None - verbal |
| HHS (external) | Confirmed breach >500 patients | Formal notification | HHS form |

---

## 9. Closure Criteria

- [ ] All compromised accounts disabled and passwords reset
- [ ] Source IPs blocked at perimeter
- [ ] Evidence preserved with chain of custody
- [ ] HIPAA breach assessment complete (documented)
- [ ] Affected users notified
- [ ] Detection rule tuned (if this was a gap)
- [ ] Post-incident review scheduled

---

## 10. Automation Candidates (for future SOAR implementation)

| Step | Automation Feasibility | Notes |
|------|----------------------|-------|
| AbuseIPDB enrichment | High (100%) | Safe enrichment; no impact |
| Source IP blocking | Medium (human approval) | Require SOC Manager approval gate |
| Account disable (regular user) | Medium (30-min delay) | Allow FP review before action |
| Account disable (admin) | Low (human only) | Too high impact for auto-action |
| SIEM log export | High (100%) | Automated evidence preservation |
| Slack notification | High (100%) | Low risk, high value |
| TheHive case creation | High (100%) | Standard enrichment action |
```

---

## Task 3: Applying the Playbook to the Scenario

**Alert data**: 847 failed logins across 23 accounts; 2 successes (n.santos billing, m.admin); source IPs from Netherlands.

**Step 1 - Initial Triage**:

* Source IPs (91.108.4.x) are external, Netherlands
* AbuseIPDB check: These are known Tor exit nodes (you would confirm in real execution)
* Successful logins detected → P1 scenario

**Severity assignment**: **P1** — reasons:

1. `m.admin` is an administrative account (Tier 1 risk)
1. Source IPs are external + Netherlands (not MedCorp location)
1. Login at 3:52 AM is highly anomalous
1. `n.santos` accesses billing/PHI data (HIPAA concern)

**First containment action**: Disable `m.admin` immediately.

* Rationale: Admin account with rights to 12 workstations = lateral movement risk. Every minute of continued access allows attacker to establish persistence or access additional systems.
* The account should be disabled before full investigation is complete.

**HIPAA breach notification analysis**:

* `n.santos` (billing) logged in at 3:47 AM — must check if billing system was accessed during this session

* Query: `index=soc_events user="n.santos" _time>=03:47 app=billing | head 50`

* **If billing records were accessed → Probable breach → Notify Legal/CISO**
* **If no billing access confirmed → Document assessment; not a breach yet**

**Evidence to preserve**:

1. Full login event logs for both accounts (EventCode 4624/4625) with timestamps
1. Any system access logs during the compromised sessions
1. Network traffic logs from 91.108.4.x to MedCorp during the attack window
1. Screenshot of AbuseIPDB results for all 3 source IPs
1. Account access history before/after disable

**Incident declaration**: YES — when:

* `m.admin` compromise confirmed → Active threat with high lateral movement potential
* Declare "Security Incident" in Jira; assign P1; L2 takes ownership; notify SOC Manager

---

## Examiner Notes

**Full credit requires:**

* Decision tree that branches on admin vs. regular user (critical distinction)
* Explicit HIPAA breach assessment in containment/evidence steps
* Recognizing that m.admin must be disabled IMMEDIATELY before full investigation
* Understanding that "n.santos accessed billing" doesn't automatically = HIPAA breach; it requires evidence of PHI actually being viewed
* At least 4 steps that could be automated (AbuseIPDB, account disable with approval, SIEM query, case creation)
