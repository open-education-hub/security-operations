# Drill 02 (Intermediate): Writing a Threat Intelligence Report

**Level:** Intermediate

**Estimated Time:** 90 minutes

**Submission Format:** Threat intelligence report (PDF or Markdown), 1,200-2,000 words

---

## Learning Objectives

* Transform raw IOCs and observations into structured threat intelligence
* Write intelligence products appropriate for different audiences
* Apply the intelligence lifecycle in producing a finished product
* Use TLP appropriately and understand sharing constraints
* Structure intelligence using established frameworks (Diamond Model)

---

## Scenario

You are the threat intelligence analyst at **GlobalBank AG**, a financial institution.
Your incident response team has just completed handling a security incident.
Your manager has asked you to convert the raw incident findings into two finished intelligence products:

1. A **tactical intelligence report** for the SOC team
1. A **strategic intelligence brief** for the CISO

You will use the following raw incident data provided by the IR team.

---

## Raw Incident Data (from IR Team)

```text
IR-2024-047 POST-INCIDENT RAW NOTES - TLP:RED (INTERNAL ONLY)

Incident detected: 2024-03-08 14:15 by SOC analyst
Detected via: UEBA alert on unusual admin logon pattern
Contained: 2024-03-09 08:30
Fully remediated: 2024-03-12

WHAT HAPPENED (IR reconstruction):

1. Initial access via compromised credentials for service account

   "svc_reporting@globalbank.ag" - credentials found for sale on
   dark web forum (Ramp forum, found by threat intel team 3 weeks
   prior but not acted on)

2. Attacker used credentials from CORP network (VPN access, source IP:
   45.152.66.234) to access internal systems

3. Established persistence via creation of:
   - New admin account: "svc_monitor_01" created on 2024-03-07 at 03:14
   - Golden ticket likely created (DC event logs missing for 6-hour window)

4. Lateral movement:
   - Moved to domain controllers using PtH (pass-the-hash)
   - 4 servers accessed including SWIFT connector server (SWIFT-RELAY-01)
   - Used legitimate admin tools: RDP, WinRM, net.exe

5. Accessed SWIFT-RELAY-01 from 2024-03-07 15:00 to 03:30 on 03-08
   - Accessed SWIFT transaction files in: D:\SWIFT\pending\
   - File access logs show 412 files opened
   - Attacker modified 3 SWIFT payment files to redirect payments
   - Attempted fraud total: €2,100,000 across 3 transactions
   - 2 of 3 transactions blocked by SWIFT anomaly detection
   - 1 transaction completed: €700,000 loss

6. Attacker IOCs:
   - Source IP: 45.152.66.234 (VPN ingress)
   - C2 domain: corporate-reporting-api[.]com
   - C2 IP: 91.92.248.115
   - Malware dropped (SVCHOST replacement on SWIFT-RELAY-01):
     SHA256: 4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
     Filename: svchost.exe (in C:\Windows\ - not System32!)
     Size: 155,648 bytes
   - Cobalt Strike beacon with teamserver: 91.92.248.115:443
   - Named pipe used: \\.\pipe\GoogleChrome (masquerading)

7. Attribution notes:
   - TTP overlap with SWIFT fraud group "DAGGER-FISH" (medium confidence)
   - Named pipe masquerading as Chrome = common DAGGER-FISH indicator
   - C2 infrastructure registered via same bulletproof hosting provider
     used in 3 prior DAGGER-FISH incidents (ASN 29550)
   - Timing of attack (weekend, overnight) consistent with DAGGER-FISH
     operational pattern
   - NOT confirmed to be DAGGER-FISH; could be copycat or tool sharing

8. Timeline:
   - Credentials listed on Ramp forum: ~2024-02-15 (estimated)
   - Initial access: 2024-03-07 (estimated, based on account creation)
   - SWIFT access: 2024-03-07 15:00
   - Detection: 2024-03-08 14:15
   - Containment: 2024-03-09 08:30
   - Dwell time: ~24-36 hours on network; ~23 hours with SWIFT access

GAPS/UNKNOWNS:
   - 6-hour gap in DC event logs (likely golden ticket creation)
   - Full scope of lateral movement unknown
   - Cannot confirm what data was exfiltrated (if any)
   - Initial vector for credential theft unknown
```

---

## Task 1: Produce a Tactical Intelligence Report (50 points)

Write a tactical intelligence report for your SOC and security engineering team.

**Requirements:**

* Length: 600-900 words
* TLP marking: **TLP:AMBER** (you are removing the TLP:RED to allow internal sharing)
* Audience: Technical security staff who need actionable intelligence
* Must include:
  * Executive summary (2-3 sentences)
  * Incident overview
  * Full IOC table with MISP attribute types and IDS flags
  * ATT&CK technique mapping
  * Immediate detection recommendations (at least 3 specific detection rules or queries)
  * Threat indicator context (what each indicator means operationally)

**Format:**

```text
Classification: TLP:AMBER
Date: [Today]
Title: [Descriptive title]
Reference: IR-2024-047

[Your report content]
```

---

## Task 2: Produce a Strategic Intelligence Brief (30 points)

Write a strategic intelligence brief for the CISO.

**Requirements:**

* Length: 400-600 words
* TLP marking: **TLP:AMBER**
* Audience: Non-technical executive; focused on business risk and strategic decisions
* Must include:
  * What happened and business impact
  * Threat landscape context (why is SWIFT fraud happening? Is this a trend?)
  * Attribution assessment with confidence level
  * Strategic recommendations (3-5 business/security decisions)
  * What remains unknown and associated risk

**Important:** The CISO does not need to know SHA256 hashes or Cobalt Strike named pipes.
Translate everything to business language.

---

## Task 3: Intelligence Quality Review (20 points)

Review your own work by answering:

1. **TLP Downgrade Justification:** You changed TLP from RED to AMBER. Explain the risk you took in doing this and what safeguards you put in place to manage that risk.

1. **Confidence Assessment:** The attribution to DAGGER-FISH is "medium confidence." How would you communicate this uncertainty in your report without undermining the intelligence value? What would you need to increase confidence to "high"?

1. **Gap Analysis:** List 3 intelligence gaps (things you don't know) that remain after this incident, and for each, describe what collection would fill the gap.

1. **Intelligence Lifecycle Reflection:** This incident shows a failure at which phase of the intelligence lifecycle? (The credentials were found on the dark web 3 weeks before the incident and not acted on.) What should have happened differently?

---

## Evaluation Criteria

| Task | Points | Criteria |
|------|--------|----------|
| Task 1: Tactical report | 50 | Completeness, IOC accuracy, detection specificity, technical accuracy |
| Task 2: Strategic brief | 30 | Audience appropriateness, business focus, clarity, recommendations quality |
| Task 3: Quality review | 20 | Critical thinking, self-assessment accuracy |
| **Total** | **100** | |

---

## Reference

* TLP Standard: https://www.first.org/tlp/
* SWIFT ISAC: https://www.swiftinstitute.org
* Reading material: Sections 7, 9, 10 (Intelligence Lifecycle, Types, TLP)
