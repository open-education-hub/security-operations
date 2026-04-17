# Solution: Drill 02 (Advanced) — SOC Improvement Roadmap

## Task 1: Maturity Assessment

| Domain | Score | Justification |
|--------|-------|---------------|
| Business | 1 | No dedicated security budget. CISO is compliance-focused, not operationally empowered. Security is afterthought, not business priority. Previous €1.2M incident did not result in structural change. |
| People | 1 | 2 sysadmins doing security part-time. No dedicated security training. No tier structure. No knowledge transfer. High burnout risk. |
| Process | 1 | No playbooks. No SLAs. No formal incident handling. NIS2 notification was violated in previous incident. Ad-hoc response only. |
| Technology | 2 | Splunk deployed (good) but only 3 rules active — essentially unused. Azure in use but no Defender for Cloud or logging enabled. EDR not deployed. |
| Services | 1 | Reactive only. No threat hunting. No threat intel. No security awareness training. No vulnerability management program. |
| **Overall** | **1.2** | Early Level 1 — reactive, fragmented, personnel-dependent |

---

## Task 2: NIS2 Gap Analysis

| NIS2 Requirement | Current State | Severity | Gap |
|-----------------|---------------|----------|-----|
| Incident detection and response | No playbooks, 3 SIEM rules, 2 part-time analysts | CRITICAL | Cannot detect most attacks; no structured response |
| 24h incident notification capability | Not complied with in last incident | CRITICAL | No process, no designated person, no template |
| Risk management (patching) | Monthly patching, often delayed | HIGH | No systematic vulnerability management |
| Supply chain security | No vendor risk program | HIGH | Medical devices, third-party systems unassessed |
| Business continuity planning | Unknown / inadequate post-incident | HIGH | No tested BCP relevant to cyber incidents |
| Cryptography and encryption | Unknown | MEDIUM | Not assessed; assume gaps |
| Network security | No segmentation described, no IDS | HIGH | Flat network enables lateral movement |
| Management body accountability | CISO compliance-focused; board not engaged | HIGH | NIS2 requires board-level responsibility for cybersecurity |

---

## Task 3: Improvement Roadmap

### Immediate Actions (30 Days) — Quick Wins (< €5,000 total)

```text
Action: Enable Azure Defender for Cloud (free tier) on all Azure subscriptions
Why:    Instantly provides CSPM findings and basic threat detection; no deployment effort
Owner:  Sysadmin (2 hours)
Cost:   €0 (included in Azure subscription)

Action: Enable audit logging on all Azure resources (Activity Log → Storage Account)
Why:    Without logging there is no investigation capability; NIS2 minimum requirement
Owner:  Sysadmin (4 hours)
Cost:   €50/month (storage costs)

Action: Enforce MFA for all Azure/M365 admin accounts immediately
Why:    Most ransomware starts with compromised admin credentials; highest ROI action
Owner:  Sysadmin (2 hours)
Cost:   €0 (included in M365)

Action: Activate 20 additional Splunk detection rules from Splunk Security Essentials
Why:    Splunk is deployed but underused; free content pack available
Owner:  Sysadmin (1 day)
Cost:   €0

Action: Create NIS2 incident notification template and designate a notification person
Why:    NIS2 requires 24h notification; previous incident violated this
Owner:  CISO (2 hours)
Cost:   €0

Action: Subscribe to CERT-RO and ENISA free threat intelligence feeds
Why:    Free, sector-relevant IOCs; import into Splunk lookup tables
Owner:  Sysadmin (4 hours)
Cost:   €0

Action: Disable legacy authentication protocols (Basic Auth) in M365
Why:    Credential spray attacks almost exclusively target legacy auth; 1-hour fix
Owner:  Sysadmin (1 hour)
Cost:   €0
```

### Phase 1 (Months 1–6): Detection Foundation (~€60,000)

**Theme: "Establish minimum viable SOC"**

* Hire 1 dedicated L1/L2 SOC analyst (full-time): €35,000/year (budget 6 months: ~€18,000)
* Deploy Microsoft Defender for Endpoint EDR on all 2,000 endpoints: €25,000/year
* Enable network segmentation (at minimum: isolate medical devices from admin network): €5,000 (switch config)
* Tune Splunk to 50+ active detection rules covering top ATT&CK techniques
* Create incident response playbooks for: ransomware, phishing, credential compromise
* Define and test NIS2 24h notification process (quarterly tabletop)

### Phase 2 (Months 7–12): Capability Building (~€60,000)

**Theme: "Active monitoring and response"**

* Second SOC analyst hire (L2 level): €40,000/year (6-month cost ~€20,000)
* Deploy Microsoft Sentinel as SIEM (replace Splunk if licensing cost is prohibitive): €15,000
* Integrate Azure Defender for Cloud alerts into SIEM
* Implement vulnerability management programme (Qualys or Tenable Essentials): €8,000
* Security awareness training platform for all 2,000 employees + phishing simulations: €8,000
* Establish monthly MTTD/MTTR metrics reporting

### Phase 3 (Months 13–18): Optimisation (~€30,000)

**Theme: "Measure, validate, and mature"**

* First external penetration test: €15,000
* Purple team exercise (internal, with external red team): €10,000
* SOC-CMM re-assessment to measure maturity improvement: €5,000
* Threat intelligence platform (MISP, self-hosted): €0 software + 5 days setup

---

## Task 4: KPI Framework

```text
KPI: Mean Time to Detect (MTTD)
Current:    Unknown / estimated 200+ hours (not measured)
6 months:   < 72 hours
12 months:  < 24 hours
18 months:  < 8 hours
Source:     SIEM alert timestamps vs. incident creation timestamps

KPI: Mean Time to Respond (MTTR)
Current:    5 days (last incident)
6 months:   < 48 hours
12 months:  < 24 hours
18 months:  < 8 hours (for critical)
Source:     Incident management system (ticket open to close)

KPI: Alert Volume / False Positive Rate
Current:    3 rules → very low volume; assumed to miss almost everything
6 months:   FPR < 50% (early tuning)
12 months:  FPR < 30%
18 months:  FPR < 20%
Source:     SIEM alert disposition records

KPI: NIS2 24h Notification Compliance Rate
Current:    0% (violated in last incident)
6 months:   100% (process in place, tested)
12 months:  100%
18 months:  100%
Source:     Post-incident review; ENISA notification records

KPI: ATT&CK Detection Coverage
Current:    ~3% (3 rules, ~3 techniques)
6 months:   25%
12 months:  40%
18 months:  55%
Source:     SIEM rule to ATT&CK mapping (ATT&CK Navigator)

KPI: Staff Security Training Completion
Current:    0% (no training program)
6 months:   80% of all employees completed Module 1
12 months:  100% annual completion
18 months:  100% + phishing simulation pass rate > 90%
Source:     Learning management system

KPI: Patch SLA Compliance (Critical Patches)
Current:    Monthly, often delayed → assume > 30 days for critical
6 months:   < 14 days for critical patches
12 months:  < 7 days for critical
18 months:  < 3 days for critical (via automated patching)
Source:     Vulnerability management platform

KPI: Endpoint EDR Coverage
Current:    0% (no EDR)
3 months:   80% of endpoints
6 months:   100%
18 months:  100% maintained (asset management)
Source:     Defender for Endpoint dashboard
```

---

## Task 5: NIS2 Incident Notification Process

**1.
What triggers the 24-hour notification?**

NIS2 Article 23: A significant incident that has a substantial impact on the provision of services.
Triggers:

* Any ransomware or destructive malware confirmed on production systems
* Unauthorised access to patient data (PHI/PII)
* Service disruption affecting any of the 3 hospitals for > 2 hours
* Compromise of an account with admin-level access

When in doubt, notify.
It is better to notify unnecessarily than to miss the deadline.

**2.
Required information in 24-hour notification:**

* Organisation name, sector, and contact details
* Date and time of detection
* Nature of incident (brief description)
* Initial assessment of impact (systems affected, potential data impact)
* Cross-border impact (are patients in other EU countries affected?)
* Current status (contained / ongoing)
* Initial mitigation measures taken

(A final, detailed report is due within 30 days — the 24h report is intentionally minimal)

**3.
Responsible person:**

CISO is the designated NIS2 contact.
If CISO is unreachable, the IT Manager is the backup.
Contact must be available 24×7 — provide a mobile number to ENISA.

**4.
Internal escalation path:**

```text
SOC Analyst detects significant incident
   ↓ (immediate)
SOC Lead notified (or on-call analyst lead)
   ↓ (within 1 hour)
CISO notified
   ↓ (within 4 hours)
CISO determines if NIS2 thresholds are met
   ↓ (if yes, within 24 hours of initial detection)
CISO submits notification to DNSC (Romanian NIS2 authority) / ENISA
```

**5. 24-Hour Notification Checklist:**

```text
[ ] 1. Confirm incident meets NIS2 significant incident definition
[ ] 2. Record exact time of initial detection (for the 24h clock)
[ ] 3. Notify CISO immediately (phone, not email)
[ ] 4. Open incident ticket with all known details
[ ] 5. Collect: affected systems list, initial attack vector assessment
[ ] 6. Determine if patient data was accessed (GDPR overlap — DPO to be notified)
[ ] 7. Draft NIS2 notification using the standard template (pre-prepared)
[ ] 8. CISO reviews and approves notification draft
[ ] 9. Submit to DNSC (dnsc.ro incident reporting portal) AND ENISA
[ ] 10. Record submission timestamp; set 30-day full report reminder
```

---

## Task 6: Board Memo

**MEMORANDUM — STRICTLY CONFIDENTIAL**

**To**: Board of Directors

**From**: CISO

**Subject**: Investment in SOC Capabilities — Business Case

---

Eight months ago, our organisation lost €1.2 million to a ransomware attack that disrupted hospital operations for 5 days.
Patient care was delayed.
Our reputation was damaged.

The root causes have not been addressed.
We currently have no system capable of detecting such an attack before it spreads, and no process to respond to it efficiently.
We are legally obligated under the NIS2 Directive — as a healthcare essential service — to implement risk management measures and to notify authorities within 24 hours of a significant incident.
We failed to meet that obligation in the last incident.

The proposed €150,000 investment over 18 months will:

* Deploy automated threat detection covering 99% of our systems (currently 0%)
* Hire two dedicated security analysts (preventing recurrence of 5-day response time)
* Implement security awareness training (most ransomware starts with a phishing email opened by an employee)
* Establish the NIS2 incident notification process (eliminating regulatory liability)

If another ransomware event occurs today, our expected loss remains €1.2 million.
After this investment, a similar event would be detected within hours, contained the same day, and reported to authorities in time — reducing expected losses by an estimated 70%.

The investment pays for itself if it prevents one incident.
The Board should authorise the budget immediately.

---

*Note: Under NIS2 Article 20, management body members are personally accountable for approving and overseeing cybersecurity risk management measures.*
