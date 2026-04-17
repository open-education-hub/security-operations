# Solution: Drill 02 (Advanced) — Threat Landscape Analysis (EduNation)

**Level:** Advanced

**Directory:** `drills/advanced/solutions/drill-02-solution/`

---

## Part 1: Internal Data Analysis — Model Calculations

### Actor Profile (50 incidents)

From the summarized dataset:

* **External**: ~30 incidents (60%)
* **Internal**: ~15 incidents (30%)
* **Partner**: 5 incidents (10%) — entirely from 2024 (incidents 46–50)

**Year-over-year trend**:

* 2022 (15 inc): External 67%, Internal 33%, Partner 0%
* 2023 (15 inc): External 67%, Internal 33%, Partner 0%
* 2024 (20 inc): External 60%, Internal 25%, Partner 25%

**Key observation**: Partner incidents emerged exclusively in 2024, representing a new and growing risk vector.

### Action Profile

| Action | Estimated Count | % |
|--------|----------------|--|
| hacking | ~18 | 36% |
| error | ~12 | 24% |
| malware | ~10 | 20% |
| social | ~7 | 14% |
| physical | ~1 | 2% |
| misuse | ~2 | 4% |

**Most common varieties**: Credential stuffing/use of stolen creds, Ransomware, Phishing, Misconfiguration/Misdelivery

### Discovery Profile

| Discovery Type | Estimated Count | % |
|---------------|----------------|--|
| Internal | ~28 | 56% |
| External | ~22 | 44% |

**Notable**: Partner incidents (all 5 in 2024) are ALL externally discovered, with days of 60, 90, 45, 30, 15.
Average for partner incidents: 48 days.
Average for other external incidents: ~20 days.

**Nation-state dwell**: Multiple nation-state incidents with 45, 60, 90, 120 days to discovery — all external.

---

## Part 2: DBIR Education Benchmarking — Model Answer

### 2a. Actor Comparison

| Actor Type | EduNation | DBIR Education Avg |
|-----------|----------|-------------------|
| External | 60% | ~75% |
| Internal | 30% | ~20% |
| Partner | 10% | ~5% |

**Finding**: EduNation has a higher internal incident rate (30% vs. ~20% industry average) and emerging partner risk.
The higher internal rate may reflect large employee/student population with widespread system access.

### 2b. Action Comparison

| Action | EduNation | DBIR Education Avg |
|--------|----------|-------------------|
| hacking | 36% | ~35–40% |
| error | 24% | ~15–20% |
| malware (ransomware) | 20% | ~20–25% |
| social | 14% | ~20–25% |

**Finding**: EduNation has higher-than-average Error incidents and slightly lower Social Engineering — possibly due to better anti-phishing controls but weaker misconfiguration management.

### 2c. Nation-State Activity

DBIR education sector consistently shows 5–10% of incidents attributed to nation-state actors, primarily targeting research institutions for intellectual property.
EduNation's data shows nation-state incidents in each year, concentrated on research database and file server assets — consistent with the DBIR pattern.
The long dwell times (45–120 days) and external discovery are classic nation-state characteristics.

### 2d. Discovery Method

DBIR education: External discovery ~50–60% (high; reflects under-resourced detection).
EduNation: 44% external — slightly better than DBIR average, but still concerning.
Partner incidents: 100% external discovery — consistent with DBIR findings on supply chain visibility.

### 2e. Areas Worse Than Industry Average

1. **Partner/supply chain incidents** (10% vs. ~5% DBIR): EduNation's vendor/partner exposure is double the DBIR average.
1. **Nation-state dwell time**: Long dwell times (90–120 days) suggest monitoring of research systems is inadequate.
1. **Error rate** (24% vs. ~15–20%): Higher-than-average misconfiguration/misdelivery incidents.

---

## Part 3: VCDB Integration — Model Answer

### 3a. Matched Public Incidents (without victim names)

**Match 1 — Research data theft via phishing**: A US university had a nation-state actor access grant research databases for 6+ months via phishing of a research coordinator.
Matches EduNation's nation-state + research data pattern.

**Match 2 — Cloud misconfiguration exposing student PII**: A large public university accidentally made a student financial aid database publicly accessible on a cloud server.
Matches EduNation's error + misconfiguration pattern.

**Match 3 — Ransomware from phishing**: A school district (NAICS 611110 adjacent) suffered ransomware after a staff member opened a phishing email.
Encrypted student records and administrative files.
Matches EduNation's ransomware pattern.

### 3b. Lessons from Each

1. **From research theft**: Long dwell time was enabled by lack of file access monitoring on research systems. Lesson: Implement DLP and file access logging on all research data repositories.

1. **From cloud misconfiguration**: The exposed database was discovered by a security researcher, not the institution. Lesson: Implement cloud security posture management (CSPM) to detect public-facing resources automatically.

1. **From ransomware**: Recovery took 2+ weeks due to inadequate backup testing. Lesson: Test backup recovery quarterly; ensure backups are isolated from network.

### 3c. Research Data in VCDB Education Incidents

Based on available VCDB data for education sector, approximately 15–20% of incidents involve research data or intellectual property as a data type — primarily in incidents with nation-state or state-affiliated actors.

---

## Part 4: Threat Prioritization Matrix — Model Answer

| Threat Scenario | Freq (3yr) | Severity | Detectability | Control Effectiveness | Priority |
|----------------|-----------|---------|--------------|----------------------|---------|
| Credential stuffing/phishing on SIS | 8 | High (PII+FERPA) | Moderate (5–14 days) | Moderate (no MFA) | **9/10** |
| Nation-state research data theft | 5 | Critical (IP+national security) | Poor (45–120 days) | Low (no DLP) | **10/10** |
| Ransomware via phishing | 6 | High (availability) | Good (1–2 days) | Moderate (no EDR) | **8/10** |
| Cloud misconfiguration (student data) | 4 | High (FERPA) | Poor (external) | Low (no CSPM) | **9/10** |
| Partner/vendor breach | 5 | High (data at third party) | Poor (all external) | Low (no vendor monitoring) | **9/10** |
| Insider privilege misuse | 3 | Medium (internal data) | Moderate (audit) | Moderate | **6/10** |
| Lost/stolen device | 3 | Medium (PII if unencrypted) | Good (immediate) | Moderate (partial encryption) | **5/10** |
| DDoS on student portal | 2 | Medium (availability) | Good (immediate) | Low (no DDoS protection) | **6/10** |

---

## Part 5: Board-Ready Threat Landscape Report — Model Answer

---

**EduNation University System**
**Annual Threat Landscape Report | Board of Trustees**
**Fiscal Year 2022–2024**

---

**Executive Summary**

Over the past three years, EduNation has experienced 50 confirmed security incidents, including data breaches affecting student personal information, research intellectual property, and faculty credentials.
The most significant and growing threat is from sophisticated nation-state actors targeting our research programs — an area that requires urgent board attention and investment.

---

**Our Threat Environment — Key Findings**

* **External attackers caused 60% of our incidents**, primarily organized criminal groups seeking financial gain through credential theft and ransomware, and nation-state actors targeting research data. This is slightly lower than peer institutions (~75%), partly because internal and vendor-related incidents are proportionally higher at EduNation.

* **Nation-state actors represent our most dangerous threat**: Five incidents involved suspected nation-state actors over three years, all targeting research data. These attackers remained undetected for an average of 75 days — compared to 5 days for other incidents. The research data compromised in these incidents potentially constitutes a national security concern.

* **Our detection capability has a critical gap**: 44% of incidents were discovered by external parties rather than our own security team. For partner/vendor-related incidents, 100% were discovered externally. This means attackers frequently know they have accessed our systems before we do.

* **Vendor and supply chain risk doubled in 2024**: All five partner-related incidents occurred in 2024, suggesting our growing cloud and vendor ecosystem has outpaced our security oversight capability.

---

**Comparison to Industry Peers**

EduNation's incident profile is broadly consistent with peer institutions but has two notable areas of concern: a higher-than-average internal incident rate (30% vs. ~20% peer average), and an emerging vendor/supply chain risk at double the peer average.
Our ransomware exposure is consistent with DBIR education sector findings.

---

**Most Significant Risks**

1. **Nation-state research theft** (Priority: Critical): Five incidents, 75-day average dwell time, 100% externally detected. Research grants, intellectual property, and government-funded research are at risk. Reputational and national security implications.

1. **Credential-based attacks on student systems** (Priority: High): Eight incidents involving credential theft targeting the student information system. FERPA obligations triggered. No multi-factor authentication currently deployed on student portals.

1. **Vendor/supply chain exposure** (Priority: High): Five incidents in 2024 alone, all involving third-party vendors with database access. No structured vendor security monitoring program currently exists.

---

**Recommended Investments**

1. **Research data security program** ($850K): Deploy data loss prevention (DLP) on all research repositories; implement network segmentation for sensitive research networks; deploy user behavior analytics (UBA) to detect anomalous access. Addresses nation-state threat directly.

1. **Multi-factor authentication (MFA) for all portals** ($250K): Enforce MFA on student portal, faculty systems, and VPN. Eliminates ~80% of credential-based attack effectiveness based on industry data.

1. **Cloud security posture management (CSPM)** ($180K/year): Automated detection of cloud misconfigurations. Would have prevented multiple misconfiguration incidents. Addresses the 44% external discovery rate for cloud incidents.

1. **Vendor security program** ($120K): Third-party security questionnaires, continuous vendor monitoring, and contractual security requirements. Addresses the doubling of supply chain incidents.

1. **Security awareness and phishing simulation** ($75K/year): Quarterly phishing simulations for all staff. Data shows social engineering as a primary initial access vector in ransomware and credential theft chains.

---

**Metrics We Will Track to Measure Progress**

| Metric | Current | 12-Month Target |
|--------|---------|----------------|
| Internal detection rate | 56% | 75% |
| Mean time to detect (MTTD) | 18 days | < 7 days |
| Nation-state dwell time | 75 days | < 14 days |
| Partner incidents discovered externally | 100% | < 50% |
| MFA enforcement across portals | 0% | 100% |

---

*The threat landscape continues to evolve.
This report will be updated annually and significant emerging threats will be escalated to the Board as they are identified.*

---

*Solution — Drill 02 (Advanced) | Session 11 | Security Operations Master Class | Digital4Security*
