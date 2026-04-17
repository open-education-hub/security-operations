# Solution: Drill 02 (Intermediate) — Automation Metrics Calculations

## Task 1: MTTA and MTTR Calculations

### Individual ticket calculations (minutes):

| Ticket | Alert Time | Ack Time | Ack→Alert (MTTA) | Resolution Time | Resolution→Alert (MTTR) | SLA Target | SLA Met? |
|--------|-----------|---------|-----------------|-----------------|------------------------|-----------|---------|
| TKT-1001 | 08:15 | 08:32 | 17 min | 10:22 | 127 min (2.1h) | P2: 8h | ✓ |
| TKT-1002 | 09:42 | 10:15 | 33 min | 11:05 | 83 min (1.4h) | P3: 24h | ✓ |
| TKT-1003 | 11:20 | 11:28 | 8 min | 13:50 | 150 min (2.5h) | P2: 8h | ✓ |
| TKT-1004 | 14:00 | 14:04 | 4 min | 16:45 | 165 min (2.75h) | P1: 4h | ✓ |
| TKT-1005 | 15:30 | 16:10 | 40 min | 17:15 | 105 min (1.75h) | P2: 8h | ✓ |
| TKT-1006 | 17:00 | 18:45 | 105 min | 19:30 | 150 min (2.5h) | P3: 24h | ✓ |
| TKT-1007 | 08:05 | 09:00 | 55 min | 10:00 | 115 min (1.9h) | P3: 24h | ✓ |
| TKT-1008 | 11:15 | 11:20 | 5 min | 14:20 | 185 min (3.1h) | P2: 8h | ✓ |
| TKT-1009 | 14:30 | 17:00 | 150 min | 09:00+1d | 1110 min (18.5h) | P4: 72h | ✓ |
| TKT-1010 | 16:00 | 16:18 | 18 min | 17:45 | 105 min (1.75h) | P2: 8h | ✓ |

**Average MTTA (sample)**: (17+33+8+4+40+105+55+5+150+18) / 10 = 435/10 = **43.5 minutes**

**Average MTTR (sample)**: (127+83+150+165+105+150+115+185+1110+105) / 10 = 2295/10 = **229.5 minutes (3.8 hours)**

**Note**: TKT-1009 is a P4 resolved next morning — not a breach but it significantly skews MTTR average.
In practice, P4 tickets should be excluded when calculating P1/P2 MTTR targets.

---

## Task 2: False Positive Rate Calculations

| Alert Type | Total | True Positive | False Positive | FPR |
|-----------|-------|--------------|---------------|-----|
| Phishing | 412 | 127 | 285 | 285/412 = **69.2%** |
| Brute Force | 198 | 110 | 88 | 88/198 = **44.4%** |
| Malware | 72 | 63 | 9 | 9/72 = **12.5%** |
| Policy Violation | 165 | 124 | 41 | 41/165 = **24.8%** |
| **TOTAL** | **847** | **424** | **423** | 423/847 = **49.9%** |

**Ranked by FPR (highest first):**

1. Phishing: 69.2%
1. Brute Force: 44.4%
1. Policy Violation: 24.8%
1. Malware: 12.5%

**Analyst-hours wasted on FPs per month:**

| Type | FP Count | Avg Time | Wasted Hours |
|------|---------|---------|-------------|
| Phishing | 285 | 14 min | 285×14/60 = **66.5 hours** |
| Brute Force | 88 | 18 min | 88×18/60 = **26.4 hours** |
| Malware | 9 | 35 min | 9×35/60 = **5.25 hours** |
| Policy Viol. | 41 | 8 min | 41×8/60 = **5.47 hours** |
| **Total** | | | **103.6 hours/month** |

With 4 L1 analysts × 8h/day × 22 working days = 704 analyst-hours/month

**FP hours as % of capacity**: 103.6/704 = **14.7% of total capacity wasted on FPs**

---

## Task 3: SLA Compliance Rates

| Severity | Total | Resolved in SLA | SLA Compliance | Needed for 95% |
|----------|-------|-----------------|----------------|----------------|
| P1 | 12 | 10 | 10/12 = **83.3%** | Need 11.4 → at least 11 of 12 (**+11.7pp**) |
| P2 | 187 | 159 | 159/187 = **85.0%** | Need 177.7 → 178 of 187 (**+10pp**) |
| P3 | 445 | 398 | 398/445 = **89.4%** | Need 422.75 → 423 of 445 (**+5.6pp**) |
| P4 | 203 | 175 | 175/203 = **86.2%** | Need 192.85 → 193 of 203 (**+8.8pp**) |

**Worst performer**: P1 at 83.3% — the highest severity has the most improvement needed.

**Root cause of P1 SLA breaches**: Likely night shift coverage gap (no L2 escalation available for 8 hours).

---

## Task 4: Automation ROI

### Step 1: Automatable analyst-hours per month

| Type | Monthly Count | Avg Automatable Time | Automatable hrs/month |
|------|--------------|---------------------|----------------------|
| Phishing | 412 | 8 min | 412×8/60 = **54.9 hrs** |
| Brute Force | 198 | 7 min | 198×7/60 = **23.1 hrs** |
| Malware | 72 | 8 min | 72×8/60 = **9.6 hrs** |
| Policy Viol. | 165 | 2 min | 165×2/60 = **5.5 hrs** |
| **Total** | | | **93.1 hrs/month** |

### Step 2: Apply automation rate

| Type | Automatable hrs | Automation Rate | Saved hrs/month |
|------|----------------|-----------------|----------------|
| Phishing | 54.9 | 70% | **38.4 hrs** |
| Brute Force | 23.1 | 60% | **13.9 hrs** |
| Malware | 9.6 | 40% | **3.8 hrs** |
| Policy Viol. | 5.5 | 80% | **4.4 hrs** |
| **Total** | | | **60.5 hrs/month** |

### Step 3: Annual cost savings

* Hours saved/year: 60.5 × 12 = **726 hours/year**
* L1 analyst hourly rate: $65,000/year ÷ 2,080 hours = $31.25/hr
* **Annual savings**: 726 × $31.25 = **$22,688/year**

### Step 4: Shuffle SOAR ROI

| Cost | Amount |
|------|--------|
| Setup (40 hrs × $50/hr) | $2,000 one-time |
| Monthly maintenance (5 hrs × $31.25) | $156.25/month → $1,875/year |
| **Total Year 1 cost** | **$3,875** |
| **Year 1 savings** | **$22,688** |
| **Year 1 ROI** | ($22,688 - $3,875) / $3,875 = **485%** |
| **Payback period** | $3,875 / ($22,688/12) = **2.05 months** |

---

## Task 5: Metrics Dashboard

| Metric | Current Value | Target | Gap |
|--------|--------------|--------|-----|
| Average MTTD | ~18 min (from SIEM config) | <60 min (P1) | Within target |
| Average MTTA (P1/P2) | 43.5 min (sample) | <15 min | -28.5 min |
| Average MTTR (P1) | 2.75h (sample P1) | <4h | Within target |
| Overall FPR | 49.9% | <20% | -29.9pp |
| Phishing FPR | 69.2% | <15% | -54.2pp |
| P1 SLA Compliance | 83.3% | >95% | -11.7pp |
| P2 SLA Compliance | 85.0% | >95% | -10pp |
| Automation Rate | 0% (current) | 60% | 60pp |
| Analyst hrs/day on FPs | 103.6/22 = 4.7 hrs | <20% cap (2.8 hrs) | -1.9 hrs/day |

---

## Business Case

### Recommendation: Deploy Shuffle SOAR

**Current pain points (quantified)**:

* 49.9% false positive rate consuming 103.6 analyst-hours/month
* P1 SLA compliance at 83.3% — 2 of 12 critical incidents missed SLA last month
* MTTA averaging 43.5 minutes vs. 15-minute target
* ~$2,800/month in analyst time spent on automatable tasks

**Projected ROI with Shuffle SOAR**:

* Setup cost: $2,000 (one-time)
* Annual savings: $22,688
* Payback: ~2 months
* Year 1 ROI: 485%

**Top 3 automation use cases by ROI**:

1. **Phishing triage** (38.4 hrs/month saved; 70% automation rate): Biggest win. 70% of all phishing cases can be auto-triaged.
1. **Brute force IP enrichment** (13.9 hrs/month): IP reputation checks + alert routing are fully automatable.
1. **Policy violation enrichment** (4.4 hrs/month): Asset/user lookups are low-risk automation candidates.

**Risk of not investing**:

* Current 49.9% FPR → analyst fatigue → real threats missed
* P1 SLA at 83.3% → regulatory exposure in certain sectors
* Team capacity capped at current alert volume; as business grows, SOC cannot scale

**Why not XSOAR ($50K/year)**:

* ROI calculation shows Shuffle delivers 485% ROI at $3,875 total cost
* XSOAR would require $50K/year license → breakeven only after 2.2 years
* Shuffle is the correct choice for this organization size
