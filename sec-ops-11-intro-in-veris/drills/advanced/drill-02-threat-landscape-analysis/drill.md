# Drill 02 (Advanced): Threat Landscape Analysis Using VERIS Data

**Level:** Advanced

**Estimated time:** 90–120 minutes

**Directory:** `drills/advanced/drill-02-threat-landscape-analysis/`

**Prerequisites:** All prior drills, Guide 01 (Intermediate)

---

## Overview

In this drill you will conduct a comprehensive threat landscape analysis by comparing internal VERIS data against VCDB/DBIR industry benchmarks.
You will produce a board-ready threat landscape report with specific, evidence-based recommendations.

---

## Scenario

You are the head of threat intelligence at **EduNation University System**, a network of 5 universities with:

* 85,000 students, 12,000 faculty and staff
* NAICS: 611310 (Colleges and Universities)
* IT environment: hybrid (Azure + on-premises), extensive cloud-first policy
* Student information system (SIS), research databases, financial systems
* Significant research activity including government-funded research

You have been asked to produce EduNation's first annual threat landscape report for the Board of Trustees.
You have:

1. Three years of internal VERIS-encoded incident data (50 incidents)
1. Access to current DBIR education industry findings
1. Access to VCDB data filtered to education sector

---

## Part 1: Internal Data Analysis (30 minutes)

The following table represents EduNation's internal incident history (simplified):

| # | Year | Actor | Variety | Action | Variety | Asset | Attribute | Data | Disc. | Days |
|---|------|-------|---------|--------|---------|-------|-----------|------|-------|------|
| 1-5 | 2022 | external | Organized crime ×3, Unknown ×2 | hacking ×3, social ×2 | Cred stuffing, phishing | S-Auth, P-User | confidentiality | Credentials, Personal | int×3, ext×2 | 3,7,0,14,21 |
| 6-10 | 2022 | internal | End-user ×4, Sysadmin ×1 | error ×3, misuse ×2 | Misdelivery ×2, Misconfig | U-Desktop, S-DB | confidentiality, integrity | Personal, Internal | int×5 | 0,0,1,5,10 |
| 11-15 | 2022 | external | Organized crime ×2, Nation-state ×1, Unknown ×2 | hacking ×3, malware ×2 | Exploit vuln, Ransomware ×2 | S-File ×2, S-DB ×2 | availability, confidentiality | Research, Credentials | int×2, ext×3 | 4,1,1,45,30 |
| 16-20 | 2023 | external | Organized crime ×4, Unknown ×1 | social ×3, hacking ×2 | Phishing ×3, Cred stuffing ×2 | P-User, S-Auth | confidentiality | Credentials, Personal | ext×3, int×2 | 22,14,7,2,1 |
| 21-25 | 2023 | internal | End-user ×3, Developer ×1, Sysadmin ×1 | error ×4, misuse ×1 | Misconfig ×2, Misdelivery ×2, Priv abuse | S-DB, U-Laptop | confidentiality, integrity | Personal, Internal | int×5 | 0,0,3,8,1 |
| 26-30 | 2023 | external | Organized crime ×2, Hacktivist ×1, Nation-state ×1, Unknown ×1 | malware ×2, hacking ×2, physical ×1 | Ransomware ×2, Exploit ×2, Theft | S-File, N-Network | availability, confidentiality | Research, Internal | int×2, ext×3 | 2,1,30,60,1 |
| 31-35 | 2024 | external | Organized crime ×3, Nation-state ×2 | social ×2, hacking ×3 | Phishing ×2, Exploit×2, Cred ×1 | S-DB ×2, S-Auth | confidentiality | Research, Credentials | ext×3, int×2 | 30,14,3,2,5 |
| 36-40 | 2024 | internal | End-user ×4, Sysadmin ×1 | error ×3, misuse ×2 | Misdelivery ×2, Misconfig, Priv abuse ×2 | S-DB, U-Desktop | confidentiality | Personal, Internal | int×5 | 0,1,0,7,14 |
| 41-45 | 2024 | external | Organized crime ×2, Unknown ×1, Nation-state ×2 | malware ×2, hacking ×3 | Ransomware ×2, Exploit×2, Backdoor | S-File, S-DB | availability, confidentiality | Research, Credentials | int×2, ext×3 | 1,1,45,90,120 |
| 46-50 | 2024 | partner | Vendor ×3, Partner ×2 | hacking ×3, error ×2 | Use of stolen creds ×2, Exploit ×1, Misconfig ×2 | S-DB ×3 | confidentiality | Research ×3, Personal ×2 | ext×5 | 60,90,45,30,15 |

*Note: This is a summarized dataset.
For the full analysis, treat each sub-range as individual incidents with the stated distributions.*

---

## Part 2: DBIR Education Industry Benchmarking (20 minutes)

Based on DBIR education industry findings (use current/recent DBIR data for reference), answer:

2a. **Actor comparison**: How does EduNation's actor profile (internal/external/partner %) compare to DBIR education industry averages?

2b. **Action comparison**: Is EduNation's action distribution consistent with DBIR education norms?
What deviations do you see?

2c. **Nation-state presence**: The DBIR typically shows elevated nation-state activity in education (research espionage).
How does EduNation's data reflect this?

2d. **Discovery method comparison**: DBIR education sector typically shows high external discovery rates.
How does EduNation compare?

2e. **Anomaly identification**: Based on the comparison, identify any areas where EduNation's profile is WORSE than the industry average.

---

## Part 3: VCDB Data Integration (20 minutes)

From public VCDB data for the education sector, identify:

3a.
Three real incidents from VCDB that match patterns you see in EduNation's data (describe without providing actual victim names).

3b.
For each matched incident, explain what EduNation can learn from the public case about detection, response, or prevention.

3c.
Calculate: of the VCDB education incidents you can identify, what percentage involve research data or intellectual property as a data type?

*If you don't have VCDB access, use the DBIR education industry section from the current year's report to answer these questions.*

---

## Part 4: Threat Prioritization Matrix (20 minutes)

Create a **threat prioritization matrix** for EduNation using VERIS data.
The matrix should have:

**Rows (Threat scenarios)**: At least 8 scenarios derived from your data analysis, e.g.:

* Credential stuffing against student portal
* Ransomware via phishing targeting staff
* Nation-state research data theft
* Cloud misconfiguration exposing student records
* etc.

**Columns**:

* Frequency (observed incidents/3 years)
* Severity (High/Medium/Low based on CIA impact + data types)
* Detectability (how quickly discovered, based on MTTD)
* Current control effectiveness (your assessment)
* Priority Score (your composite score 1–10)

---

## Part 5: Board-Ready Threat Landscape Report (30 minutes)

Write a board-ready threat landscape report for EduNation's Board of Trustees.
The report must be:

* **~600–800 words**
* **Non-technical** (appropriate for board-level audience)
* **Evidence-based** (every claim supported by your data analysis)
* **Actionable** (specific recommendations with priority ranking)

Structure:

1. Executive Summary (2-3 sentences)
1. Our Threat Environment — Key Findings (3–4 bullet points with data)
1. Comparison to Industry Peers
1. Most Significant Risks (top 3, with supporting data)
1. Recommended Investments (3–5 with business justification)
1. Metrics to Track Progress

---

## Deliverables

1. Part 1: Actor, action, and discovery analysis tables with your calculations
1. Part 2: DBIR benchmark comparison (5 questions)
1. Part 3: VCDB integration findings
1. Part 4: Completed threat prioritization matrix
1. Part 5: Board-ready report (~600–800 words)

Compare with model answers in:
`drills/advanced/solutions/drill-02-solution/solution.md`

---

*Drill 02 (Advanced) | Session 11 | Security Operations Master Class | Digital4Security*
