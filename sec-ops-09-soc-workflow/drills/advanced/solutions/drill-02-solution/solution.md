# Solution: Drill 02 (Advanced) — SOC Workflow Optimization (FinServ Corp)

## Task 1: Breach Root Cause Analysis

### 1.1 Timeline with Failure Points

```text
23:14 — Phishing email arrives; Splunk alert fires
         ← TOOL: Alert correctly generated ✓
         ← PROCESS FAILURE: No priority routing for phishing alerts
           with young domains; alert goes into general queue

23:14 — Night shift: 2 L1 analysts with 180+ alerts each in queue
         ← COVERAGE FAILURE: 2 analysts insufficient for 4,500 alerts/day
         ← PROCESS FAILURE: No auto-deprioritization for confirmed-low-risk
           vs. un-triaged alerts; all sit in same queue

23:45 — User clicks link; reports to IT helpdesk
         ← PROCESS FAILURE: No documented escalation from helpdesk to SOC
         ← PROCESS FAILURE: User training gap (should report to SOC, not helpdesk)

06:20 — Helpdesk escalates to SOC (7.5 hours later)
         ← PROCESS FAILURE: No SLA for helpdesk → SOC phishing reports
         ← HUMAN FAILURE: Helpdesk classified as "generic IT issue" not security

06:25 — L1 escalates to on-call L2
         ← Process working at this point ✓ (but 6h 11m late)

10:15 — L2 disables account (4 hours after escalation)
         ← PROCESS FAILURE: 4h to disable an account is unacceptable for P1
         ← HUMAN FAILURE: L2 did not treat compromised admin account as P1
         ← PROCESS FAILURE: No explicit time-boxed procedure for account disable
         ← TOOL FAILURE: No pre-approved automation for account disable on
           confirmed compromise

10:22 — Data exfiltration confirmed (11 hours total)
         ← All prior failures compounded
```

### 1.2 Failure categorization

| Event | Type | Preventable? |
|-------|------|-------------|
| Alert not triaged for 7+ hours | Coverage failure + Process failure | YES — auto-escalation of un-triaged P2+ alerts after 15 min |
| Helpdesk didn't route to SOC | Process failure | YES — documented escalation SLA; helpdesk training |
| User clicked link, slow reporting | Process failure | YES — user security awareness training; SOC email alias |
| Account not disabled for 4h | Human failure + Process failure | YES — explicit time-boxed procedure with on-call escalation |
| Phishing scored "clean" (young domain) | Tool failure | YES — domain age check in scoring algorithm |
| Night shift overwhelmed | Coverage failure | YES — auto-defer low-risk to day shift; better triage automation |

### 1.3 SOAR Automation Failure Analysis

**Root cause**: The XSOAR playbook used a single reputation score threshold (>40) with no allowlist verification.
The playbook:

1. Did not check against a CDN/cloud provider IP range allowlist
1. Did not require human approval for blocks affecting /12 or larger subnets
1. Had no rollback procedure
1. Had no monitoring for downstream application impact

**Required safeguards that were missing**:

```text
BEFORE blocking any IP, the playbook MUST:

1. Check IP against allowlist:

   - Internal IP ranges (RFC 1918)
   - Known CDN ranges (Cloudflare, Akamai, Fastly, AWS CloudFront)
   - Partner/vendor IP ranges
   - Corporate VPN ranges

2. If subnet > /24: REQUIRE human approval (large subnet = high blast radius)

3. Log action to audit trail with:
   - Analyst name or "AUTOMATED"
   - IP/range blocked
   - Reason (rule name + score)
   - Timestamp
   - Expected rollback path

4. Monitor: check critical application health 5 min after block
   - If app goes down → auto-rollback + alert
```

**Redesigned blocking playbook logic:**

```python
def should_auto_block(ip, score):
    # Step 1: Allowlist check
    ALLOWLISTS = [
        "10.0.0.0/8",       # Internal
        "172.16.0.0/12",    # Internal
        "192.168.0.0/16",   # Internal
        "104.16.0.0/12",    # Cloudflare
        "13.32.0.0/15",     # AWS CloudFront
        "151.101.0.0/16",   # Fastly
        # Add all known CDN/partner ranges
    ]

    for allowed_range in ALLOWLISTS:
        if ip_in_range(ip, allowed_range):
            return False, "IP in allowlist - manual review only"

    # Step 2: Confidence threshold
    if score < 75:
        return False, f"Score {score} below auto-block threshold (75)"

    # Step 3: For scores 75-89: human approval required
    if score < 90:
        return "APPROVAL_REQUIRED", f"Score {score} - needs approval"

    # Step 4: Score 90+: auto-block
    return True, f"Score {score} - auto-block"
```

**Monitoring for SOAR-initiated blocks:**

```text
After any block action:
  → Wait 2 minutes
  → Check synthetic monitoring for top 10 business applications
  → If any app returns 5xx or timeout:
      → Unblock immediately
      → Create P1 incident
      → Alert SOC Manager
  → Log monitoring result with block action
```

---

## Task 2: Redesigned SOC Workflow

### 2.1 Phishing Workflow Redesign

**New scoring logic:**

```python
def calculate_phishing_score(alert_data):
    score = 0

    # VT URL check
    vt_score = get_vt_score(alert_data["url"])
    score += vt_score * 0.4  # 40% weight

    # Domain age (critical fix - this is what failed in the breach)
    domain_age_days = get_domain_age(alert_data["sender_domain"])
    if domain_age_days < 7:
        score += 40  # Strong indicator for brand new domains
    elif domain_age_days < 30:
        score += 20
    elif domain_age_days < 90:
        score += 10

    # SPF/DKIM/DMARC failure
    if alert_data["spf"] == "fail":
        score += 15
    if alert_data["dmarc"] == "fail":
        score += 10

    # Sender domain mismatch
    if alert_data["reply_to_domain"] != alert_data["sender_domain"]:
        score += 10

    return min(int(score), 100)  # Cap at 100
```

**Helpdesk → SOC integration:**

* Create shared email alias: `phishing@company.com` — forwards to SOC
* Helpdesk SLA: Any report of clicking suspicious link → escalate to SOC within 15 minutes
* Helpdesk training: 30-min training on phishing indicators + escalation procedure
* Automation: Email to `phishing@company.com` → Shuffle workflow → TheHive alert

### 2.2 Night Shift Coverage Model

```text
NIGHT SHIFT COVERAGE (No new headcount)

Auto-triage automation:
  P4 alerts: Auto-defer to day shift queue (do not alert night analysts)
  P3 alerts: Auto-triage with enrichment; notify if enrichment = suspicious
  P2 alerts: Immediate notification; 15-min response SLA
  P1 alerts: Immediate PagerDuty page + phone call

Night shift target: Reduce analyst-visible alerts by 50%
How: Defer P4 (165/day avg) + auto-close clean enrichments (P3) = ~55% reduction

On-call L2 rotation:
  Who: 3 L2 analysts in weekly rotation
  Response SLA: 20 minutes from page
  Page criteria:
    - Any P1 alert
    - Any P2 phishing alert where enrichment score > 50
    - Any confirmed account compromise
  Tool: PagerDuty with escalation ladder
```

### 2.3 Fixed SOAR IP Blocking Design

```text
IP Block Decision Matrix:

IP in internal range?     → NEVER block; alert analyst only
IP in CDN allowlist?      → NEVER block; alert analyst only
IP in partner allowlist?  → NEVER block; alert analyst only

Score 90-100 + not allowlisted + /32 (single host)?
  → Auto-block + log + notify + monitor apps

Score 75-89 + not allowlisted?
  → Queue for human approval (15-min window; if no response: escalate not auto-block)

Score <75?
  → Alert analyst; no block; enrichment in ticket only
```

---

## Task 3: Metrics and Roadmap

### 3.1 Target metrics

| Metric | Current | 3-month Target | 6-month Target |
|--------|---------|---------------|---------------|
| MTTD (phishing) | 6.2 hours | <1 hour | <30 min |
| MTTR (P1) | 8.5 hours | <6 hours | <4 hours |
| FPR (phishing) | 73% | <40% | <25% |
| P1 SLA compliance | 67% | >85% | >95% |
| Automation rate | 35% | >50% | >65% |
| Night shift alert volume | baseline | -30% | -50% |

### 3.2 Three-Phase Roadmap

**Phase 1 (Week 1-2): Quick Wins — Zero Cost**

* [ ] Create helpdesk → SOC escalation procedure and SLA (0.5 days)
* [ ] Add domain age check to phishing scoring (1 day engineering)
* [ ] Create IP allowlist in XSOAR (0.5 days)
* [ ] Define explicit P1 time-boxed procedures (0.5 days)
* [ ] Estimated metric impact: P1 SLA breach risk -30%

**Phase 2 (Month 1-3): Process Improvements**

* [ ] Rewrite phishing playbook with new scoring + domain age (2 days)
* [ ] Implement auto-deferral of P4 alerts for night shift (1 day)
* [ ] Deploy PagerDuty for L2 on-call (1 day setup)
* [ ] Helpdesk training on phishing escalation (0.5 days)
* [ ] Add application monitoring post-block (2 days)
* [ ] Estimated metric impact: MTTD -40%, automation rate +10%

**Phase 3 (Month 3-6): Technology Improvements**

* [ ] Full XSOAR playbook overhaul (all 5 playbooks) (10 days)
* [ ] Splunk → XSOAR real-time integration tuning (3 days)
* [ ] Metrics dashboard deployment (Grafana or Splunk) (2 days)
* [ ] Cortex analyzers for automated IOC enrichment (2 days)
* [ ] Estimated metric impact: Automation rate +20%, MTTR -35%

### 3.3 Executive Presentation Outline

**Slide 1: What Happened**

* Phishing email at 23:14; not investigated until 06:20 due to overnight coverage gap
* Compromised account active 11 hours; customer data exported
* Secondary issue: automated IP block caused 2-hour application outage
* Estimated financial impact: $X regulatory + $Y operational

**Slide 2: What We Found**

* SOC coverage model inadequate for 4,500 alert/day volume with 10-person team
* Phishing detection missed newly-registered domains (algorithm gap)
* SOAR automation lacked safeguards against blocking legitimate infrastructure
* Process gaps: helpdesk→SOC, account disable time-box, SOAR monitoring

**Slide 3: What We're Fixing**

* Phase 1 (2 weeks): Helpdesk integration, domain age detection, IP allowlist
* Phase 2 (3 months): Night shift automation, playbook rewrites, on-call model
* Phase 3 (6 months): Full SOAR overhaul, metrics dashboard, 65% automation rate
* No new headcount required; automation absorbs volume growth

**Slide 4: What Success Looks Like**

* Phishing MTTD: 6.2 hours → <30 min
* P1 SLA compliance: 67% → >95%
* Automation rate: 35% → 65% (same team handles 60% more alerts)
* SOAR auto-block only after: allowlist check + human approval + app monitoring

**Slide 5: What We Need**

* Engineering time: 20 days over 6 months
* PagerDuty license: ~$500/month (3 L2 on-call users)
* Security awareness training update: 1 day CISO sponsor required
* Monthly metrics review: 1-hour executive brief (sponsor commitment)
* Total investment: $15,000 over 6 months; estimated breach risk reduction: $500K+
