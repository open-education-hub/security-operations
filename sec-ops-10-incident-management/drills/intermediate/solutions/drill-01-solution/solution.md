# Solution: Drill 01 (Intermediate) — Full Ransomware Response (FinServe S.A.)

> **Instructor note:** This solution provides model answers. Accept alternative approaches that demonstrate the same underlying reasoning. IR decisions are contextual — there is often more than one defensible answer.

---

## Part 1: Initial Response

### Task 1.1 — Incident Declaration

**Q1: Is this P1?**

Yes, P1 (Critical).
Justification:

* Active ransomware confirmed (ransom note + encrypted files on multiple workstations)
* Financial institution with client personal data (CNP, IBAN, portfolio data) at risk
* Potentially spreading (unknown scope, servers not yet confirmed)
* Regulatory obligations with short timelines (DORA 4h initial, GDPR 72h)
* Business operations impacted (trading floor affected)

**Q2: First 15 minutes — who to notify:**

1. **IR Lead self-activates** (this scenario: you are the IR Lead, on-call)
1. SOC Tier 1 analyst — acknowledge receipt, request scope data from SIEM/Defender
1. **CISO** — within 5 minutes (P1 mandatory)
1. **Head of IT** — activate IR team, check server status, protect backups
1. **Legal Counsel / External DPO** — within 10 minutes (DORA 4h clock and GDPR 72h clock may have already started)
1. **Cyber Insurance** — contact if required by policy (many policies require notification within hours)

Note: Do NOT notify the Board or clients yet — that is for later, with more information and legal sign-off.

**Q3: Executive notification (Signal, out-of-band):**

> "P1 SECURITY INCIDENT DECLARED — 07:42 EEST. Active LockBit 3.0 ransomware confirmed on Trading and Finance workstations. Scope being assessed. All servers currently operational but at risk. Containment in progress. DORA and GDPR notification clocks may have started. Will update at 08:15 or sooner if critical. Call me on +40-XXX-XXX for urgent decisions. — [IR Lead name]"

### Task 1.2 — Triage Questions

| Priority | Question | Data Source |
|----------|---------|-------------|
| 1 | How many systems are currently encrypted? | Microsoft Defender for Endpoint alerts; SIEM |
| 2 | Are any servers affected? Especially: backup server, client database, payment system? | IT admin / network scan / Defender |
| 3 | When was the first encryption activity (to determine dwell time)? | Defender timeline; SIEM correlation |
| 4 | Are the Monday 23:00 backups intact and accessible? | Storage admin / backup system |
| 5 | Is the attacker still active / present on any systems? | Defender active incidents; SIEM active alerts |

### Task 1.3 — Volatile Evidence

Before isolation, collect:

1. **Memory dumps of 2–3 representative encrypted workstations** — captures: ransomware binary in memory, encryption keys (if LockBit keeps keys in memory during operation — varies by variant), attacker tooling
1. **Active network connection state** (`netstat -anob` or Defender telemetry) — captures: active C2 connections, lateral movement channels, attacker-controlled pivot points
1. **Running processes** at incident declaration — identifies: any attacker tools still executing, ransomware processes still active
1. **Defender for Endpoint process execution history** — cloud-stored, less volatile but export before any Defender actions that could affect the timeline

Why this matters for ransomware: The ransom note says "do not restart servers" — follow this.
LockBit 3.0 has variants that store decryption key material in memory.
A memory dump may provide intelligence for decryption without paying ransom.

---

## Part 2: Developing Intelligence

### Task 2.1 — Scope Assessment

**Likely patient zero:** The IT admin who was active at 23:47 on Monday (coincides with first encryption activity).
The decommissioned server at `10.0.5.23` as the pivot point is consistent with the IT admin having credentials to that system.
Hypothesis: IT admin account was compromised (phishing/password reuse), attacker gained access Friday–Monday, used IT admin credentials to RDP to the forgotten/decommissioned server, then pivoted to workstations from there.

**Is the Monday 23:00 backup safe?**

The backup completed at 23:00.
First encryption activity was at 23:47.
This is good news — the backup pre-dates the encryption.
However:

Additional validation needed:

* Confirm the attacker did NOT have access during the backup window (00:00–23:00 Monday). If the attacker was present during working hours Monday, they may have tampered with backup contents before encryption.
* Hash-verify the backup: compare hashes of critical files in the backup against known-good versions from 2 weeks ago (before likely compromise).
* Test-restore to isolated environment before relying on backup for production recovery.
* Do NOT connect the backup server to any network segment with uncontained infected systems.

**8-hour dwell time activities:**

During 23:00 Monday – 07:42 Tuesday (dwell period), the attacker likely:

* Performed network reconnaissance (mapping workstations, identifying servers)
* Accessed and exfiltrated sensitive data (client database, financial files) — **this is confirmed by later intelligence**
* Deployed ransomware binary to all target systems (staged, not yet executed)
* Executed ransomware simultaneously at 23:47 after ensuring exfiltration was complete

The dwell time indicates this is a professional ransomware operation, not opportunistic script-kiddie activity.

### Task 2.2 — Containment Decisions

**Q1: Isolate all 47 workstations immediately?**

Yes, but use EDR network isolation (Defender "Isolate Device"), not physical disconnection.
Reasons:

* Isolation stops spread to remaining ~133 workstations
* Defender isolation preserves EDR telemetry and allows remote forensic investigation
* Tradeoff: 47 employees cannot work, but this is unavoidable during active ransomware
* Do NOT physically power off systems — preserves evidence and follows LockBit's warning ("do not restart")

**Q2: 6 unconfirmed servers:**

Priority order for investigation:

1. **Client database server** (PII of 12,000 clients — GDPR/DORA implications)
1. **Backup server / NAS** (recovery capability — must be protected immediately)
1. **Trading/payment processing system** (direct business impact)
1. **Azure-connected systems** (if attacker moved to cloud, scope expands dramatically)
1. **Active Directory / Domain Controllers** (compromise here means total domain control for attacker)
1. **Remaining servers** (by business criticality)

**Q3: Decommissioned server 10.0.5.23:**

Immediate network isolation (block at switch level or firewall rule).
This is the attacker's staging point.
Do not power it off — capture memory image first, then network-isolate.
The server may contain:

* Attacker tools and scripts
* Credential dumps
* Evidence of exfiltration activity
* Log entries showing attacker's initial access vector

**Q4: Backup system administrator:**

Contact BEFORE containment of the backup server.
You need the admin to:

1. Immediately take the backup server offline from any network connection to infected segments
1. Verify the Monday 23:00 backup integrity
1. Confirm no encryption has reached backup storage

If you contain (isolate) first, you may lose access to the backup system.
Call the backup admin while containment of workstations is proceeding in parallel.

### Task 2.3 — GDPR Assessment

**Q1: Has a GDPR breach occurred?**

Yes.
GDPR Article 4(12) defines a personal data breach as "a breach of security leading to the accidental or unlawful destruction, loss, alteration, unauthorised disclosure of, or access to, personal data."

The ransomware incident satisfies this definition in two ways:

1. **Unauthorized access**: The attacker accessed the client database and ran SELECT queries (exfiltration-before-encryption pattern)
1. **Unavailability**: The encrypted workstations and potential server encryption represent unavailability of personal data

**Q2: When did the 72-hour clock start?**

The 72-hour clock started when FinServe became **aware** of the breach.
The ransom note and encrypted files constituted awareness at **07:42 EEST (04:42 UTC) on Tuesday**.

72 hours from 04:42 UTC Tuesday = **04:42 UTC Friday** (local: 07:42 EEST Friday).

Note: This is awareness of the incident, not the exfiltration.
Even if exfiltration happened at 01:30, the clock starts at 07:42 when the organization became aware.

**Q3: Romanian supervisory authority:**

**ANSPDCP** — Autoritatea Națională de Supraveghere a Prelucrării Datelor cu Caracter Personal
Website: anspdcp.ro
Form: Electronic notification via their online portal

**Q4: DORA timeline:**

Yes, DORA applies — FinServe S.A. is an asset management company (financial entity under DORA Article 2).

* **Initial notification: Within 4 hours** of classifying as "major incident" (07:42 + 4h = 11:42 EEST)
* **Intermediate report: Within 72 hours** (same as GDPR: Friday 07:42 EEST)
* **Final report: Within 1 month** of incident closure

Major incident criteria under DORA include: services unavailability > 2 hours, large number of clients affected, geographic spread.
FinServe meets these criteria.

Filing to: **National Financial Regulator** (in Romania: ASF — Autoritatea de Supraveghere Financiară)

**Q5: NIS2 timeline:**

Yes, FinServe as an asset management firm may qualify as Important Entity under NIS2 Annex II (financial sector).
If classified:

* **Early warning: Within 24 hours** of awareness (by 07:42 Wednesday)
* **Full notification: Within 72 hours** (same as GDPR: Friday 07:42 EEST)
* **Final report: Within 1 month**

Filing to: National CSIRT / competent authority (CERT-RO in Romania, under ANCOM/MTIC oversight)

**Q6: GDPR Art. 33 notification headline paragraph:**

```text
On [Tuesday date] at 04:42 UTC, FinServe S.A. became aware of a ransomware
security incident affecting its information systems. The incident involved
unauthorized access to personal data of approximately 12,000 individual
investment clients. The personal data affected includes: full name,
national identification number (CNP), residential address, bank account
number (IBAN), and investment portfolio data. The unauthorized access
occurred between 00:15 and 01:30 UTC on [Tuesday date] (estimated),
before the ransomware encryption was deployed. Investigation is ongoing
to determine the full scope of the unauthorized data access.
```

---

## Part 3: Eradication and Recovery

### Task 3.1 — Eradication Checklist

| Step | Action | Justification | Owner |
|------|--------|---------------|-------|
| 1 | Collect memory images from 3 representative infected workstations | Evidence preservation before any cleaning | Forensics |
| 2 | Document all IoCs: LockBit 3.0 binary hashes, C2 IPs, malicious scheduled task names | Enable hunt across environment | Threat Intel |
| 3 | Search all systems for "WindowsUpdate_v3" scheduled task and remove from all 12 identified hosts | Known persistence mechanism | IT |
| 4 | Scan all servers for same scheduled task and any other LockBit artifacts | Persistence may extend beyond confirmed 12 hosts | IT / EDR |
| 5 | Identify and rotate ALL credentials used by the compromised IT admin account | Account was the initial access vector — all credentials may be exposed | IT Security |
| 6 | Reset krbtgt password TWICE (10 hours apart) in Active Directory | If attacker had domain admin for 8+ hours, may have created Golden Ticket | Active Directory admin |
| 7 | Audit all Active Directory service accounts for unauthorized changes (new accounts, modified permissions) | Attacker with 8h dwell time may have created backdoor accounts | AD admin |
| 8 | Patch the phishing vulnerability (root cause: IT admin clicked phishing link) — deploy anti-phishing training | Not a technical patch but a process fix; verify email security gateway | Security Team |
| 9 | Remove decommissioned server (10.0.5.23) permanently — forensic image first | Eliminate future pivot point; if not needed, it should not exist | IT |
| 10 | Rebuild all 47 encrypted workstations from standard image | Cannot trust workstations post-LockBit 3.0; rebuild is fastest path to clean state | IT |
| 11 | Verify all rebuilt systems are clean before network reconnection | Prevent re-infection | IR Lead + IT |
| 12 | Rotate all API keys, service account passwords, and cloud credentials | 8h dwell time with domain admin — all secrets must be treated as compromised | DevOps / IT |

**Root vulnerability:** IT admin clicked a phishing link on Friday.
This was the initial access vector.
The underlying vulnerabilities are: (a) no email security strong enough to block the initial phishing, (b) no MFA on VPN/RDP that would have prevented credential use, (c) no network segmentation preventing lateral movement from a single compromised account.

### Task 3.2 — Recovery Sequencing

| Priority | System | Justification |
|----------|--------|---------------|
| 1 | **Active Directory / Domain Controllers** | Everything else depends on AD; must be clean first |
| 2 | **Client database server** | Core business data; needed for operations and regulatory evidence preservation |
| 3 | **Backup system (NAS + Azure)** | Enables recovery of all other systems; verify clean state |
| 4 | **Email system** (if on-premises) | Needed for business communications during recovery |
| 5 | **Trading system** | Core business function of an asset manager |
| 6 | **CFO / CEO workstations** | Executive operations required for incident management |
| 7 | **Compliance team workstations** | Regulatory notification work must proceed |
| 8 | **Finance system** | Payroll and accounts payable |
| 9 | **Remaining workstations** (by department criticality) | Batch recovery by floor/department |
| 10 | **IT admin workstations** | Rebuild last — these are forensic evidence |

### Task 3.3 — PIR Questions

| Why question | Likely root cause | Systemic fix |
|-------------|-------------------|--------------|
| Why was a phishing email able to compromise the IT admin? | No anti-phishing training; email gateway not blocking malicious links | Security awareness training + email gateway tuning + simulated phishing program |
| Why was the decommissioned server still on the network? | No asset inventory or decommissioning procedure | Asset management policy: decommissioned = network-removed within 30 days |
| Why was the attacker present for 8 hours without detection? | No SIEM; EDR telemetry not reviewed overnight; no after-hours alerting | Implement SIEM; establish after-hours alert triage; create 24/7 SOC or retainer |
| Why was RDP between workstations and servers allowed? | No network segmentation; flat network | Implement VLAN segmentation; restrict SMB/RDP between segments |
| Why did the backup strategy not protect against ransomware? | Backup server on same network as workstations | Implement offline/air-gapped backup copy; 3-2-1 backup rule |

---

## Part 4: Communication Deliverables

### Task 4.1 — Executive Brief (Sample)

```text
INCIDENT EXECUTIVE BRIEF
Date: [Tuesday] 12:00 EEST | Incident ID: INC-2025-FS-001
Prepared by: [IR Lead] | Status: ACTIVE — CONTAINED

WHAT HAPPENED
At 07:42 this morning, we confirmed active ransomware (LockBit 3.0) on 47 workstations
in Trading, Finance, and Operations. The attacker accessed our client database
between 00:15 and 01:30, potentially accessing personal data of all 12,000 clients.
All affected systems are now isolated. The attacker's entry point (compromised
IT admin account) has been secured.

CURRENT STATUS
- 47 workstations isolated and being rebuilt
- All servers currently operational and protected
- Monday 23:00 backup confirmed intact
- Attacker has been cut off from the environment

REGULATORY OBLIGATIONS — BOARD DECISION REQUIRED
- GDPR: We must notify ANSPDCP by Friday 07:42 EEST (72h from discovery)
  Legal recommendation: file today with preliminary information
- DORA: We must notify ASF by 11:42 TODAY (4h from discovery)
- NIS2: We must file early warning by Wednesday 07:42

BUSINESS IMPACT
- 47 employees without workstations for est. 24–48 hours (recovery in progress)
- Trading operations partially affected; manual processes in place
- No customer-facing systems disrupted
- Financial impact: TBD (cyber insurance claim to be filed)

DECISIONS NEEDED FROM BOARD

1. Authorize regulatory notifications (GDPR, DORA, NIS2) — Legal draft ready

2. Authorize customer notification (12,000 clients affected — GDPR Art. 34)
3. Authorize engagement of external forensics firm for scope confirmation

NEXT UPDATE: 18:00 today
```

### Task 4.2 — Customer Notification Email

```text
Subject: Important Security Notice from FinServe S.A.

Dear [Client Name],

We are writing to inform you of a security incident that may have affected
your personal information held with FinServe S.A.

What happened:
On [date], our systems were affected by a malicious software attack.
During this incident, an unauthorized individual may have accessed
information about your investment account.

What information was involved:
Your name, national identification number, investment portfolio
information, and bank account details (IBAN) may have been accessed.

What we are doing:
We have secured our systems and are working with cybersecurity specialists
to investigate the full scope of the incident. We have also notified
the relevant data protection and financial authorities.

What you can do:
- Monitor your bank account for any unusual activity
- Be cautious of any unexpected communications from people claiming
  to be from FinServe
- Contact us immediately if you notice anything suspicious

We take the security of your information extremely seriously and sincerely
apologize for this incident.

For questions, contact: privacy@finserve-sa.ro or +40 21 555 0100

FinServe S.A. | Data Protection Officer: [Name] | [Date]
```

### Task 4.3 — Regulatory Timeline

| Regulation | Filing deadline | Filing recipient | Status |
|-----------|----------------|-----------------|--------|
| DORA initial | 11:42 EEST Today | ASF Romania | URGENT — file now |
| NIS2 early warning | Wednesday 07:42 EEST | CERT-RO | Tomorrow morning |
| GDPR Art. 33 | Friday 07:42 EEST | ANSPDCP | File by Thursday EOD |
| NIS2 full notification | Friday 07:42 EEST | CERT-RO | Same as GDPR |
| DORA intermediate | Friday 07:42 EEST | ASF Romania | Same timeline |
| GDPR Art. 34 (individuals) | Without undue delay | 12,000 clients | Board decision needed |
| DORA final | 1 month from closure | ASF Romania | TBD |
| NIS2 final | 1 month from closure | CERT-RO | TBD |
