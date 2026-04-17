# Drill 02 (Advanced) — Solution: SOC Maturity Assessment and Improvement Plan

## NordLogistics AB — SOC Maturity Assessment and Improvement Plan

---

### 1. Maturity Assessment

| Domain | Current Score | Target Score (12 mo) | Key Gap |
|--------|--------------|---------------------|---------|
| Technology | 2 | 4 | Only 40% log coverage; SIEM poorly tuned; no TI integration |
| Detection Engineering | 1 | 3 | 60% FPR; rules not reviewed in 18 months; no coverage mapping |
| Incident Response | 1 | 3 | No formal IR plan; ransomware showed critical ad-hoc response weakness |
| Threat Intelligence | 1 | 3 | No TI program at all; attacker was undetected for 23 days |
| People & Training | 2 | 3 | No Tier 2/3 capacity; analysts overtriaged without investigation ability |
| Processes & Procedures | 2 | 3 | 2 untested playbooks; no escalation matrix; no post-incident review process |

**Overall Maturity: Level 1.5 (Ad-hoc → Defined)**

---

### 2. Top 5 Critical Gaps

**Gap 1: No formal Incident Response plan**

* Current state: Ad-hoc email coordination; no documented IR process
* Risk: 23-day dwell time in ransomware incident; €1.8M cost; will repeat
* Effort: Medium
* Priority: **P1** — Address within Month 1

**Gap 2: Alert rule quality (72% false positive rate)**

* Current state: Analysts cannot distinguish signal from noise; real alerts missed
* Risk: Direct cause of ransomware going undetected (12 alerts missed)
* Effort: Medium
* Priority: **P1** — Begin rule tuning immediately

**Gap 3: 60% log coverage gap**

* Current state: Only 40% of systems sending logs to SIEM
* Risk: Blind spots — attackers can move through unmonitored systems undetected
* Effort: High (requires system-by-system deployment)
* Priority: **P1** — Multi-quarter project but must start now

**Gap 4: No Tier 2/3 analyst capacity**

* Current state: Alerts triaged by Tier 1 but not deeply investigated
* Risk: Sophisticated attacks (like the ransomware) require investigation depth Tier 1 lacks
* Effort: High (hiring or training takes time)
* Priority: **P2** — Begin process in Month 2; realistic by Month 6

**Gap 5: No threat intelligence integration**

* Current state: SOC does not use external threat intelligence
* Risk: Known attacker IOCs (IPs, domains, file hashes) not automatically blocked or alerted
* Effort: Low-Medium (MISP is free; feeds are available)
* Priority: **P2** — Quick technical win once rules are cleaner

---

### 3. 12-Month Improvement Roadmap

#### Months 1-3: Quick Wins

| Action | Success Metric | Owner |
|--------|---------------|-------|
| Conduct alert rule review; suppress/remove rules contributing to FPR | FPR reduced from 72% to < 40% | SOC Manager + Tier 1 leads |
| Deploy SIEM agents to critical unmonitored systems (CDE, AD, email) | Log coverage: 40% → 65% | Security Engineer |
| Document and test Incident Response plan (expand from 2 to 6 playbooks) | 6 playbooks documented and tabletop-tested | SOC Manager |
| Establish MTTD/MTTR tracking baseline | Weekly reporting in place | SOC Manager |
| Integrate 1 threat intelligence feed (free: MISP community) | TI IOCs enriching SIEM alerts | Security Engineer |

#### Months 4-6: Foundation Building

| Action | Success Metric | Owner |
|--------|---------------|-------|
| Hire or upskill 1 Tier 2 analyst | Tier 2 capacity operational | SOC Manager / HR |
| Expand log coverage to 80% of systems | Coverage at 80% verified | Security Engineer |
| Map existing detection rules to MITRE ATT&CK; identify coverage gaps | ATT&CK coverage heatmap created | Senior Analyst |
| Implement SOAR for top 5 repetitive alert types | 30% of alerts auto-handled | Security Engineer |
| Add 1 commercial TI feed (FinTech/logistics focused) | Integration operational | Security Engineer |

#### Months 7-12: Advanced Capabilities

| Action | Success Metric | Owner |
|--------|---------------|-------|
| Launch threat hunting program (monthly hunts) | 2 proactive hunts per month; findings documented | Tier 2/3 Analyst |
| Achieve 90%+ log coverage | Verified by audit | Security Engineer |
| FPR below 20% | Measured monthly; target achieved | Detection Engineer |
| Conduct SOC red team exercise | Exercise completed; gaps documented and remediated | External red team + SOC |
| Implement behavioral analytics (UEBA) for high-value accounts | UEBA operational for admin and finance accounts | Security Engineer |

---

### 4. Target KPIs (12 months)

| KPI | Current | Target (12 mo) | Industry Benchmark |
|-----|---------|----------------|-------------------|
| MTTD | 14.5 hours | < 2 hours | < 1 hour |
| MTTR | 28 hours | < 8 hours | < 4 hours |
| False Positive Rate | 72% | < 20% | < 15% |
| Log Coverage | 40% | 90% | 95%+ |
| Documented Playbooks | 2 (untested) | 10 (tested) | 20+ |
| ATT&CK Coverage | Unknown | 60% of top techniques | 80%+ |

---

### 5. Business Case Summary

The 2024 ransomware incident cost NordLogistics €1.8M in direct recovery costs, 4 days of operational downtime, and significant reputational damage.
Post-incident analysis shows the attacker was inside the network for 23 days, and 12 SIEM alerts were generated but not acted upon — a direct result of alert fatigue caused by a 72% false positive rate and lack of investigation capacity.

The proposed 12-month SOC improvement program, estimated at €600K (staffing + tooling), directly addresses these root causes.
By reducing MTTD from 14.5 hours to under 2 hours and FPR from 72% to below 20%, the probability of a similar undetected intrusion drops significantly.
Industry data (IBM Cost of a Data Breach, 2023) shows that organizations with mature detection capabilities experience breach costs 45% lower than those with weak detection.
Applied to NordLogistics' profile, this translates to an estimated risk reduction of €800K-1.2M per potential future incident.
The investment pays for itself by preventing a single repeat incident.
