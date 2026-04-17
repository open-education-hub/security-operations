# Solution: Drill 02 — Ransomware Incident Response

## Part A: First 60 Minutes

### Minutes 0–5: Immediate Actions

1. **Confirm the incident is real** — access CrowdStrike console, verify encryption activity on multiple hosts.
1. **Escalate immediately** — call the IT Manager on their personal cell. This is a P1, Saturday morning: on-call procedures apply.
1. **Start the incident timer** — NIS2 requires 24h early warning for essential entities. Clock starts now.
1. **Do NOT touch anything yet** — until you have a plan.

### Minutes 5–15: Rapid Scope Assessment

1. Query CrowdStrike for all hosts showing file creation/modification activity matching ransomware patterns.
1. Check what systems DON'T have CrowdStrike (identify legacy systems at risk — the PACS server).
1. Check the Friday 23:30 login of `svc-backup` — this is your attacker. Pull the full authentication trail.
1. Check the NAS backup status — if backups are being encrypted, this changes everything.

**Critical insight on Friday 23:30 login:** This means the attacker had **7+ hours** before triggering encryption.
They had time to: exfiltrate data, deploy to multiple systems, disable AV, and encrypt backups.
This is not a "quick ransomware drop" — it's a planned attack with a pre-encryption phase.

### Minutes 15–30: Containment Wave 1

1. **Isolate all workstations showing encryption activity** — use CrowdStrike bulk network isolation.
1. **Isolate the PACS server** — manually if necessary (disconnect network cable, or switch ACL). This is legacy with no EDR.
1. **Disable `svc-backup` account** immediately — attacker may still have access.
1. **Block known attacker IP** (the one used for the Friday 23:30 login) at perimeter.

### Minutes 30–45: Backup Assessment

1. Check NAS backup status — what is the state of the Friday 22:00 backup?
1. If NAS is being encrypted: **isolate the NAS immediately**.
1. If Friday 22:00 backup is clean: this is your primary recovery source.
1. PACS has a weekly backup from last Saturday: check if that is accessible and clean.

**Worst case:** Friday backup is encrypted AND PACS backup is encrypted → Recovery requires going back further.
Engage vendor support for PACS recovery options.

### Minutes 45–60: Communication

1. Brief IT Manager on current scope (23+ workstations, PACS potentially affected, patient imaging data at risk).
1. Engage Legal counsel — PACS contains patient medical images (special category GDPR data). NIS2 applies (hospital).
1. Notify CISO/Hospital Management.
1. File NIS2 24-hour early warning to national CSIRT (as required for essential entities).

---

## Part B: Scope Assessment at 60 Minutes

### Data at Risk

* 23+ workstations: user files, potentially patient scheduling/admin data
* PACS system: 2.8 TB of patient medical images (X-rays, CT scans, MRI) — **special category medical data under GDPR Art. 9**
* Financial/admin data on encrypted workstations (depends on data classification)

### Recovery Scenarios

| Scenario | Recovery Time | Likelihood |
|----------|--------------|------------|
| NAS Friday backup clean + PACS last-week backup clean | 24–48 hours for workstations, 2–4 hours for PACS | Best case |
| NAS encrypted, PACS backup clean | Workstations: 2–5 days (rebuild), PACS: recoverable | Moderate |
| Both NAS and PACS backups encrypted | Workstations: full rebuild, PACS: data loss possible | Worst case |
| Pay ransom | Uncertain — ~60% of ransomware victims don't get all data back even after payment | Not recommended |

### Exfiltration Investigation

**Yes — this should be a priority investigation.** Modern ransomware operations (especially LockBit 3.0) consistently use a **double extortion** model:

1. Exfiltrate data FIRST
1. Then encrypt

The 7+ hour pre-encryption window strongly suggests data was exfiltrated. **Evidence to check:**

* Firewall logs for unusual outbound volumes between 23:30 Friday and 06:45 Saturday
* Proxy logs for cloud storage or file transfer activity
* `svc-backup` account's activity log — what did it access?

### Regulatory Timeline

| Regulation | Requirement | Deadline |
|-----------|-------------|---------|
| NIS2 (essential entity) | Early warning | **24h from awareness = Saturday 07:00** |
| NIS2 | Full notification | **72h = Tuesday 07:00** |
| GDPR Art. 33 | DPA notification | **72h from awareness = Tuesday 07:00** |
| GDPR Art. 34 | Individual notification | If high risk to individuals — "without undue delay" |

---

## Part C: Root Cause Analysis

### How did the attacker access the network?

The `svc-backup` account was compromised.
Most likely vectors:

1. **Password spray** against a service account with a weak password
1. **Credential from a previous breach** (check HaveIBeenPwned or internal breach history)
1. **Phishing of an admin** who had `svc-backup` credentials
1. **Exploitation of a vulnerability** in a system `svc-backup` had authenticated to

**Investigation:** Check `svc-backup` password age, complexity policy, and whether it had been used for MFA-exempt authentication.

### Why was `svc-backup` high-value?

Service accounts are high-value targets because:

1. They often have elevated privileges (backup = access to all data)
1. They rarely have MFA enforced
1. Their password is set once and rarely changed
1. Their authentication activity is not monitored as strictly as human accounts
1. Their lockout thresholds may be disabled to prevent backup job failures

### Why wasn't the Friday 23:30 login detected?

Likely reasons:

1. No alert rule for `svc-backup` logging in from unusual IP
1. No alert for service accounts logging in during off-hours
1. SIEM had a rule but it was set to P4 with no notification
1. Alert may have been generated but ignored/closed quickly as FP

### Action Items

| # | Action | Owner | Due |
|---|--------|-------|-----|
| 1 | Implement MFA for all service accounts (or block them from external authentication) | IT/IAM | 30 days |
| 2 | Create detection rules for service account login from unusual IP or off-hours | SOC/Detection Eng | 14 days |
| 3 | Implement offline/immutable backups (3-2-1 rule with one copy air-gapped) | IT | 60 days |
