# Solution: Drill 01 (Intermediate) — DBIR Analysis for Financial Services

**Level:** Intermediate

**Directory:** `drills/intermediate/solutions/drill-01-solution/`

---

## Task 1: Actor Profile Analysis — Solutions

### 1a. Actor Type Distribution

Counting from the dataset (n=30):

| Actor Type | Count | Percentage |
|-----------|-------|-----------|
| External | 22 | 73.3% |
| Internal | 6 | 20.0% |
| Partner | 2 | 6.7% |

**Matches DBIR industry norms**: External ~75%, Internal ~20%, Partner ~5–10%.

### 1b. Most Common External Variety

| External Variety | Count | % of all 30 |
|----------------|-------|------------|
| Organized crime | 16 | 53.3% |
| Unknown | 3 | 10.0% |
| Nation-state | 1 | 3.3% |
| Hacktivist | 1 | 3.3% |
| Partner (vendor) | 2 | 6.7% |

**Organized crime represents 53.3% of ALL incidents** — confirming DBIR finding that financial sector is heavily targeted by financially motivated organized crime.

### 1c. 2023 vs. 2024 Actor Trend

| Type | 2023 (n=15) | 2024 (n=15) | Change |
|------|------------|------------|--------|
| External | 10 (67%) | 12 (80%) | +13% |
| Internal | 4 (27%) | 2 (13%) | -14% |
| Partner | 1 (7%) | 1 (7%) | Stable |

Trend: External incidents increasing; internal declining (or better-controlled).

### 1d. SOC Insight

> Organized crime accounts for over half of all incidents, consistently across both years. Threat intelligence focus should be on organized crime TTPs specific to financial services: credential stuffing, phishing-for-banking-creds, BEC targeting finance teams. The partner actor incidents (both from vendors) indicate third-party risk management needs strengthening.

---

## Task 2: Action Analysis — Solutions

### 2a. Action Category Distribution

| Action Category | Count | % |
|----------------|-------|--|
| social | 8 | 26.7% |
| hacking | 10 | 33.3% |
| error | 5 | 16.7% |
| malware | 4 | 13.3% |
| misuse | 2 | 6.7% |
| physical | 0 | 0% |
| environmental | 0 | 0% |

### 2b. Top 3 Action Varieties

1. Phishing (5 incidents) — 16.7%
1. Use of stolen credentials (4 incidents) — 13.3%
1. Ransomware (4 incidents) — 13.3%
1. *(tie)* Misconfiguration (2) and Misdelivery (3) — 6.7%/10%

### 2c. External Actor Action Analysis

For 22 external incidents:

* Hacking: 8 (36.4%)
* Social: 7 (31.8%)
* Malware: 4 (18.2%)
* Environmental (DoS): 1 (4.5%)
* Other: 2 (9.1%)

**Most common for external actors: Hacking (36%), primarily credential-based attacks.**

### 2d. Ransomware Year-over-Year

* 2023: Incidents 5, 10 = 2 ransomware
* 2024: Incidents 19, 26 = 2 ransomware

**Stable at 2 per year (13.3% each year).** No significant trend in this small sample.

### 2e. SOC Recommendations (from Action Analysis)

1. **MFA on all authentication surfaces** — Use of stolen credentials and credential stuffing are top hacking varieties; MFA eliminates most credential-based attacks.

1. **Advanced email security** — Phishing is the top Social Engineering variety and a common initial access method for credential theft and ransomware. Implement DMARC + AI-based phishing detection.

---

## Task 3: Attribute and Data Analysis — Solutions

### 3a. Confidentiality Breach Rate

Incidents with Confidentiality attribute: count incidents where attribute = confidentiality.

From dataset: Incidents 1,2,3,4,6,7,8,9,11,12,13,14,15,16,17,18,20,21,22,23,24,25,27,28,29 = 25 incidents

**Breach rate: 25/30 = 83.3%** — high; typical for financially targeted industries where data is primary target.

Non-breach incidents (Availability only): 5, 10, 19, 26 (ransomware), 30 (DDoS) = 5 incidents (16.7%)

### 3b. Most Frequently Exposed Data Type

| Data Type | Count |
|-----------|-------|
| Bank (account data) | 11 |
| Credentials | 6 |
| Personal (PII) | 6 |
| Internal | 1 |
| Classified | 1 |

**Bank account data** is the most frequently exposed type — expected for financial services.

### 3c. Bank Data Incidents

Incidents with Bank data: 2, 4, 6, 11, 13, 17, 18, 20, 22, 27, *(and partial from others)* ≈ **11 incidents (36.7%)**.

### 3d. Availability Incidents

Incidents 5, 10, 19, 26 (Ransomware), 30 (DDoS) = **5 Availability incidents (16.7%)**

| Incident | Cause | Variety |
|---------|-------|---------|
| 5, 10, 19, 26 | Ransomware | Encryption |
| 30 | Hacktivist DDoS | Interruption |

### 3e. Regulatory Frameworks

Given the data types (Bank account data, Personal PII, Credentials):

* **GLBA (Gramm-Leach-Bliley Act)**: All financial institution breach notifications
* **CCPA/State privacy laws**: Personal information exposure
* **PCI DSS**: If payment card data is involved (not in this dataset, but generally for banks)
* **Federal banking regulator notifications**: FDIC, OCC incident reporting requirements
* **NYDFS Cybersecurity Regulation (23 NYCRR 500)**: If NY-based

---

## Task 4: Discovery Method Analysis — Solutions

### 4a. Internal vs. External Discovery

| Discovery Type | Count | % |
|---------------|-------|--|
| Internal | 18 | 60% |
| External | 12 | 40% |

60% internal discovery is above average for many industries — the fraud detection systems in financial services help.

### 4b. Time-to-Discovery Statistics

**All incidents (n=30):**
Total days: 14+3+0+45+1+30+60+5+2+1+120+1+0+45+0+22+4+35+2+50+180+7+3+0+20+1+90+2+1+0 = 744 days
Mean: 744/30 = **24.8 days**

**Internally detected (n=18):**
Incidents: 3(0), 5(1), 8(5), 9(2), 10(1), 12(1), 13(0), 15(0), 17(4), 19(2), 22(7), 23(3), 24(0), 26(1), 28(2), 29(1), 30(0), 2(3)
Sum = 33 days, Mean = **1.8 days**

**Externally detected (n=12):**
Incidents: 1(14), 4(45), 6(30), 7(60), 11(120), 14(45), 16(22), 18(35), 20(50), 21(180), 25(20), 27(90)
Sum = 711 days, Mean = **59.3 days**

### 4c. Detection Gap

**59.3 - 1.8 = 57.5 days** gap between externally and internally detected incidents.

Incidents discovered externally took an average of **57+ days longer** to discover.
This is a significant detection gap.

### 4d. Three Longest Time-to-Discovery

| Incident | Days | Notes |
|---------|------|-------|
| 21 | 180 | Nation-state APT — long dwell, discovered externally |
| 11 | 120 | Partner/vendor backdoor — discovered externally |
| 27 | 90 | Partner/vendor credential use — discovered externally |

**What they have in common**: All three were discovered **externally** (not by internal teams).
Two involve **Partner/supply chain** vectors.
The nation-state incident had the longest dwell time.
These high-dwell, externally-discovered incidents represent the worst detection failures.

### 4e. Detection Assessment

> **Assessment: Detection posture is partially acceptable but has critical gaps.** Internal detection of social and hacking incidents is reasonable (avg 1.8 days). However, supply chain/partner incidents and nation-state intrusions are systematically undiscovered internally — all three of the longest-dwell incidents were discovered externally.
>
> **Recommendations**: (1) Implement user behavior analytics (UBA) to detect unusual data access by third parties and insiders; (2) Deploy network traffic analysis (NTA) to catch C2 communications typical of APT dwell; (3) Conduct quarterly threat hunting focused on partner/vendor access anomalies.

---

## Task 5: Incident Classification Pattern Mapping

| Pattern | Count | % | Incidents |
|---------|-------|--|-----------|
| System Intrusion | 8 | 26.7% | 2,7,10,11,14,19,26,27 |
| Social Engineering | 5 | 16.7% | 1,4,13,16,20 |
| Basic Web App Attacks | 3 | 10.0% | 9,23,25 |
| Miscellaneous Errors | 5 | 16.7% | 3,6,12,15,18,24,28 (7→23%) |
| Privilege Misuse | 2 | 6.7% | 8,22 |
| Denial of Service | 1 | 3.3% | 30 |
| Everything Else | 2 | 6.7% | 5,21 (ransomware/APT not clean fit) |

*Note: Some incidents can plausibly fit multiple patterns; judgment calls are acceptable.*

---

## Task 6: Executive Threat Briefing — Model Answer

> **Financial Services Threat Landscape Briefing — Q1-Q4 2024**
>
> Analysis of 30 incidents over 2023–2024 reveals a threat environment dominated by organized crime (53% of incidents) with emerging supply chain and nation-state threats.
>
> **Top attack vectors**: Credential-based hacking (stolen credentials/stuffing, 33% of actions), phishing/social engineering (27%), and ransomware (13%) represent the primary attack surface. Bank account data was the most frequently targeted asset type (37% of breaches).
>
> **Detection gap**: While 60% of incidents are discovered internally, externally-discovered incidents take an average of 59 days to detect vs. 2 days for internally-detected incidents. Supply chain incidents (vendors/partners) are consistently discovered externally with dwell times exceeding 90 days — indicating a significant blind spot.
>
> **Recommendations**:
> 1. **Enforce MFA universally** — credential-based attacks represent 47% of hacking actions; MFA would neutralize most.
> 2. **Strengthen third-party monitoring** — 100% of partner incidents were discovered externally; deploy vendor behavior analytics.
> 3. **Expand phishing simulation training** — social engineering is 27% of initial access methods; quarterly simulation program recommended.

---

*Solution — Drill 01 (Intermediate) | Session 11 | Security Operations Master Class | Digital4Security*
