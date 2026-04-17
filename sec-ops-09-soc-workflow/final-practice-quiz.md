# Final Practice Quiz: Session 09 — SOC Workflow and Automation

**Format:** 5 short-answer questions + 2 long-answer questions

**Time:** 45–60 minutes

**Purpose:** Consolidate practical knowledge before the final assessment

---

## Part A: Short Answer Questions (5 × 10 points = 50 points)

---

### Question 1: Triage Classification

You receive the following alert:

```text
Rule: OUTBOUND_CLEARTEXT_CREDENTIALS
Host: hr-ws-011
User: t.brown (HR Department)
Details: HTTP POST to http://192.168.50.100/login with credentials in plaintext
Destination: Internal IP in the Engineering network segment
Time: 10:15 UTC (business hours)
```

Classify this alert (TP / FP / Benign TP) and explain your reasoning.
What additional information would change your classification?

**Sample Strong Answer:**
> This alert is initially ambiguous — likely **Benign True Positive or True Positive**. The detection is correct: credentials are being sent in plaintext. However, the destination is internal (192.168.50.100) and occurs during business hours. It may be a legitimate internal web application that hasn't been configured for HTTPS.
>
> Classification: Benign TP (pending verification)
>
> Additional information that would change classification:
> - What service runs on 192.168.50.100? (query CMDB) — if it's a known internal dev app, Benign TP
> - Does the HR department have a legitimate reason to access the Engineering web app?
> - Is this user's behavior consistent with historical patterns?
> - If 192.168.50.100 is not a known/approved server: escalate to TP

---

### Question 2: SLA and Prioritization

Your queue at 09:00 contains these cases:

| Case | Severity | Created | Status |
|------|----------|---------|--------|
| A | P1 | 08:45 | NEW |
| B | P2 | 07:30 | In Progress |
| C | P3 | 01:00 | Pending |
| D | P2 | 08:55 | NEW |

List these in order of priority and explain why.
Identify any SLA risks.

**Sample Strong Answer:**
> **Priority order:** A → D → B → C
>
> - **Case A (P1, NEW, 08:45):** Highest priority. P1 acknowledge SLA is 15 min → deadline is 09:00. Already borderline. Must be acknowledged immediately.
> - **Case D (P2, NEW, 08:55):** Second. P2 acknowledge SLA is 30 min → deadline is 09:25. Needs acknowledgment next.
> - **Case B (P2, In Progress, 07:30):** P2 resolve SLA is 4h → deadline is 11:30. Currently in progress, watch for updates.
> - **Case C (P3, Pending, 01:00):** P3 resolve SLA is 12h → deadline is 13:00. Pending status may pause SLA clock — verify this is properly documented.
>
> **SLA risks:** Case A acknowledge SLA may already be breached (by 09:00 observation). Case D will breach acknowledge SLA if not addressed within 25 minutes.

---

### Question 3: Escalation Brief

Write an SBAR escalation brief for the following scenario:

> At 14:30 UTC, an alert fired for "Scheduled task created with encoded PowerShell command" on finance-ws-042. The task runs as the logged-in user (m.chen, Finance). You decoded the base64 command and found it downloads a file from `pastebin.com/raw/abc123` and executes it. The host is a standard finance workstation with access to the financial reporting system.

**Sample Strong Answer:**
> **S (Situation):** I have a confirmed malicious scheduled task on finance-ws-042, created at 14:30 UTC.
>
> **B (Background):** User m.chen (Finance) has a scheduled task that runs a PowerShell command downloading from pastebin.com/raw/abc123 and executing. The task was created today at 14:30. Decoded base64 confirms a file download-and-execute pattern. Finance workstation has access to financial reporting systems.
>
> **A (Assessment):** This is a P1 incident. The behavior matches a post-initial-access persistence mechanism (T1053.005) combined with a remote file download stager (T1105). The attacker likely already has initial access and is establishing persistence. Pastebin is commonly used as a low-cost C2 staging host.
>
> **R (Recommendation):** Immediate host isolation, memory acquisition, review of m.chen's recent email/web activity to identify initial access vector, check other hosts for same scheduled task name or same pastebin URL.

---

### Question 4: Playbook Design Gap Analysis

A SOC team has a "Phishing Email" playbook that:

1. Extracts sender IP from email headers
1. Queries VirusTotal for the IP
1. If VT score > 5: creates TheHive case and escalates to Tier 2
1. If VT score ≤ 5: closes as false positive

Identify **three weaknesses** in this playbook design and explain how you would fix each.

**Sample Strong Answer:**
> **Weakness 1:** Using only VT score to gate escalation ignores other indicators. A brand-new malicious IP may have VT score 0 (not yet reported). Fix: Add multiple enrichment sources (AbuseIPDB, domain age check, URL inspection). Combine scores or use OR logic — any one malicious indicator triggers escalation.
>
> **Weakness 2:** Closing as FP based solely on VT score ≤ 5 is dangerous. Clean IPs can host phishing pages. Fix: Never auto-close as FP. Instead, send a "likely clean" notice to analyst for quick confirmation with a 1-click approve/close button.
>
> **Weakness 3:** The playbook doesn't check attachment hashes or URLs in the email body. A clean sender IP means nothing if the attachment is malware. Fix: Add steps to extract and check attachment hashes and embedded URLs against VT and URLScan.

---

### Question 5: SOC Metrics Interpretation

Your SOC's MTTR for P3 incidents improved from 14 hours to 9 hours after implementing SOAR enrichment automation.
However, your CISO reports that a major data breach at your company was not detected for 3 weeks.
Which metric would have caught this gap?
Explain.

**Sample Strong Answer:**
> The relevant metric is **MTTD (Mean Time to Detect)** — specifically the dwell time before detection. MTTR improvement shows that once detected, incidents are resolved faster. But if the attack was not detected for 3 weeks, the detection coverage has a gap — either:
> (1) There was no detection rule for the attacker's technique (coverage gap — measure with ATT&CK heatmap coverage analysis), or
> (2) The alert fired but was closed as a false positive without investigation (measure with FP closure audit).
>
> MTTD alone doesn't identify the root cause. To complement it, the SOC should track **ATT&CK technique coverage** (what % of relevant techniques have detection rules) and perform periodic purple team exercises to identify blind spots.

---

## Part B: Long Answer Questions (2 × 25 points = 50 points)

---

### Question 6: Full Playbook Design (25 points)

Design a complete SOAR playbook for a **"Brute Force — RDP Gateway"** alert.
The alert triggers when more than 50 failed RDP attempts are detected from a single external IP within 15 minutes.

a) **(5 pts)** Define inputs, trigger, and outputs for the playbook.

b) **(10 pts)** Write all steps in YAML pseudocode, including decision gates and parallel execution where appropriate.

c) **(5 pts)** Identify which steps require human approval and justify why.

d) **(5 pts)** Describe how you would test this playbook safely (without causing real firewall blocks or disruptions).

**Sample Strong Answer:**

**a) Playbook Definition:**

```yaml
name: "Brute Force — RDP Gateway Response"
trigger: alert_type == "RDP_BRUTE_FORCE" AND failed_attempts >= 50 AND window == 15min
inputs:
  - source_ip: string
  - rdp_gateway_hostname: string
  - failed_attempt_count: int
  - attempt_timestamps: list
  - any_successful_logins: bool
outputs:
  - risk_score: int
  - case_id: string
  - action_taken: string
  - block_requested: bool
```

**b) Steps:**

```yaml
step_1: Parallel enrichment
  1a. VirusTotal IP lookup → vt_score, malicious_categories
  1b. AbuseIPDB lookup → abuse_confidence, report_count
  1c. Geo lookup → country_code
  1d. Check if any successful logins occurred in same window

step_2: Risk score calculation
  score = 0
  if vt_score > 5: score += 4
  if abuse_confidence > 70: score += 3
  if any_successful_logins: score += 5 (immediate escalation indicator)
  if country_code not in approved_countries: score += 1

step_3: Branch on any_successful_logins
  true → IMMEDIATE P1 case + escalation + PENDING analyst block approval
  false → continue

step_4: Branch on risk_score
  >= 5 → Create P2 case, present block recommendation to analyst
  1-4 → Create P3 case with enrichment, assign to L1 for review
  0 → Create P4 case, likely automated scanner

step_5 (if P1/P2): Notify #soc-alerts with enrichment summary
step_6 (if P1): Page on-call SOC manager
```

**c) Human approval required for:**

* Firewall block of source IP: potential for false positive (legitimate user from shared IP, VPN exit node). Analyst must confirm before blocking. For P1 with confirmed successful login: approval window is 5 minutes (expedited).

**d) Safe Testing:**

* Use the mock environment with a simulated Elasticsearch alert
* Test with known-malicious IPs (from public threat intel) to verify enrichment
* Test block request workflow using a test rule in a non-production firewall zone
* Verify P1 path using `any_successful_logins: true` in test input
* Never test against production firewall with real block actions

---

### Question 7: SOC Process Redesign (25 points)

A healthcare company's SOC has these characteristics:

* 4 analysts, 24/7 coverage (1 analyst per shift at night/weekend)
* 12,000 alerts/month, 92% FP rate
* Average MTTD: 6 hours
* P1 SLA: 1 hour MTTR (met 90% of the time)
* P2 SLA: 4 hours MTTR (met 65% of the time — failing)
* Night shift analyst spends 4 of 8 hours on FP alert processing
* No SOAR, no automated enrichment

a) **(5 pts)** Identify the root causes of the P2 SLA failure.
What data would you need to confirm your hypotheses?

b) **(10 pts)** Design a 90-day improvement plan with specific, measurable actions.

c) **(5 pts)** If you could implement only ONE change in week 1, what would it be and why?

d) **(5 pts)** Write 3 success metrics you would use to evaluate your improvement plan at the 90-day mark.

**Sample Strong Answer:**

**a) Root Causes of P2 SLA Failure:**
> Hypothesis 1: Night shift analyst is alone and overloaded with FP processing (4h/8h on FPs), leaving insufficient time for P2 investigation.
> Hypothesis 2: P2 alerts arrive at night and there's no second analyst to escalate to, causing delays.
> Hypothesis 3: P2 cases require enrichment steps that take too long manually.
>
> Data needed: P2 SLA breach time distribution (are they mostly at night?), per-analyst breach rate, average enrichment time per P2 case.

**b) 90-Day Plan:**
> Days 1-30: Quick wins
> - Identify and suppress/tune the top 3 FP-generating rules (target: reduce FP volume by 40%)
> - Create triage decision tree document for top 10 alert types (reduces analyst think time)
> - Implement on-call escalation procedure for night shift (backup analyst reachable by phone)
>
> Days 31-60: Automation
> - Deploy basic SOAR (Shuffle) with IP/hash enrichment playbook
> - Automate observable enrichment for top 5 alert types
> - Target: reduce triage time from 7 min to < 2 min for automated alert types
>
> Days 61-90: Optimization
> - Tune automated playbooks based on first 30 days of data
> - Add semi-automated P2 investigation playbook (enrichment + pre-drafted escalation brief)
> - Weekly FP review meeting established

**c) Week 1 Single Change:**
> **Suppress or heavily tune the top FP-generating rule.** 92% FP rate means 92% of analyst time on alerts is wasted. Even suppressing one rule that generates 3,000 FPs/month (25% of total) frees up ~150 analyst-hours/month. This immediately relieves night shift pressure and reduces the root cause of P2 SLA breaches without any new tools.

**d) Success Metrics at 90 Days:**
> 1. **P2 SLA compliance rate** — target: > 85% (from 65% baseline)
> 2. **FP rate** — target: < 75% (from 92% baseline)
> 3. **Night shift analyst FP processing time** — target: < 2h/8h shift (from 4h baseline)

---

*End of Final Practice Quiz — Session 09*
