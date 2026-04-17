# Drill 02 (Basic): Collecting and Categorizing Indicators of Compromise

**Level:** Basic

**Estimated Time:** 45-60 minutes

**Submission Format:** MISP event export (JSON or PDF report)

---

## Learning Objectives

By completing this drill, you will be able to:

* Identify and categorize different types of IOCs from a threat report
* Use MISP to structure and store threat intelligence
* Apply TLP and ATT&CK tags appropriately
* Distinguish between IOCs suitable for automated detection vs. contextual awareness
* Understand the Pyramid of Pain in IOC selection

---

## Scenario

You are the threat intelligence analyst at a retail company.
A partner organization has shared the following incident report with you under TLP:AMBER.
Your task is to extract all indicators, categorize them, import them into MISP (or document them in MISP event format), and analyze their operational value.

---

## The Intelligence Report

---

> **TLP: AMBER**
> **INCIDENT REPORT: SILK-SPIDER – Retail POS Attack Campaign**
> **Shared by:** FS-ISAC Member Organization
> **Date:** March 2024
>
> **Summary:**
> SILK-SPIDER conducted a successful attack against a major retail chain, compromising Point-of-Sale (POS) systems and exfiltrating ~180,000 payment card records. This report details the full attack and associated indicators.
>
> **Timeline:**
>
> **Day 1 - Initial Compromise:**
> - Attacker sent a spear-phishing email to `finance-helpdesk@victim-corp.com`
> - Email was from `payroll-support@hr-notifications-secure.com`
> - Subject: "Urgent: Payroll System Authentication Required"
> - Attachment: `payroll_q1_2024.pdf.exe` (disguised as PDF)
> - File SHA256: `3a7f4b8c2d9e5f61a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5`
> - File MD5: `9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e`
> - File size: 327,680 bytes
> - Detection on VirusTotal at time of report: 45/71
>
> **Day 1-3 - Persistence and Lateral Movement:**
> - Malware dropped `svchost32.exe` to `C:\Users\<user>\AppData\Local\Microsoft\svchost32.exe`
> - Registry persistence key: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsSystemService`
> - Registry value: `C:\Users\Administrator\AppData\Local\Microsoft\svchost32.exe -s`
> - Command-and-control server: `185.220.101.45`
> - C2 communication via port 8443 (HTTPS)
> - C2 domain: `cdn-media-services[.]com`
> - C2 domain SSL certificate SHA1: `ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01`
> - Additional domain used for data exfiltration: `data-reporting-api[.]net`
>
> **Day 4-7 - POS System Compromise:**
> - Lateral movement to POS subnet using credential: `RETAIL\pos-admin` (stolen from workstation)
> - POS malware dropped: `winsrv.dll` (injected into running POS process)
> - `winsrv.dll` SHA256: `f1e2d3c4b5a69788706050403020100f1e2d3c4b5a6978870605040302010011`
> - POS malware scraped Track 1/Track 2 data from memory
> - Staged data in: `C:\ProgramData\Microsoft\Crypto\audit.tmp`
>
> **Day 8 - Exfiltration:**
> - Used `curl.exe` renamed to `win32net.exe` to POST data to `https://data-reporting-api.net/api/v2/collect`
> - Total exfiltrated: approximately 4.7 GB
> - Exfiltration URL: `https://data-reporting-api[.]net/api/v2/collect`
> - Exfiltration timing: 03:15-04:30 AM (off-hours)
>
> **Threat Actor Information:**
> - Group suspected: SILK-SPIDER (based on TTP overlap with 3 prior incidents)
> - Motivation: Financial (credit card data for fraud)
> - Confidence: High

---

## Tasks

### Task 1: IOC Extraction and Classification (25 points)

Extract **all indicators** from the report and complete this table:

| Indicator Value | Indicator Type (MISP) | Category | For IDS? | Confidence | Notes |
|-----------------|----------------------|----------|----------|------------|-------|

**MISP indicator types to consider:**

* `ip-dst`, `domain`, `url`, `email-src`
* `md5`, `sha1`, `sha256`

* `filename`, `filename|sha256`, `filename|md5`
* `regkey|value`, `regkey`

* `uri-size`, `size-in-bytes`

**For IDS column:** Should this indicator be pushed to automated detection systems (SIEM, firewall, EDR)?
Some indicators are too risky (too many false positives) to automate.

---

### Task 2: Pyramid of Pain Analysis (25 points)

Categorize the extracted IOCs by their position on the Pyramid of Pain:

**The Pyramid of Pain (bottom to top):**

1. Hash Values (Trivial to change)
1. IP Addresses (Easy to change)
1. Domain Names (Simple to change)
1. Network Artifacts (Annoying to change)
1. Host Artifacts (Annoying to change)
1. Tools (Difficult to change)
1. TTPs (Extremely Difficult to change)

For each level of the pyramid:

1. List which IOCs from the report fall at this level
1. Explain how quickly an attacker could change this indicator
1. Rate the operational value for hunting (Low/Medium/High)
1. Recommend whether to include in automated blocking or hunting only

---

### Task 3: MISP Event Creation (30 points)

Create a MISP event (either in an actual MISP instance, or by documenting the structure) with the following requirements:

**Event metadata:**

* Info: `SILK-SPIDER POS Attack Campaign - March 2024`
* Threat Level: High
* Analysis: Complete
* Distribution: Your Organisation Only (for this exercise)
* TLP Tag: Amber

**Required elements:**

1. All IOCs as attributes with correct types
1. TLP:AMBER tag on the event
1. At least 3 relevant ATT&CK technique tags
1. One "file" MISP object grouping the `payroll_q1_2024.pdf.exe` malware
1. One "network-connection" object for the C2
1. For each attribute flagged "For IDS: Yes" in Task 1, set `to_ids=True`

**Documentation format (if not using MISP):**

```yaml
# MISP Event Structure
event:
  info: "SILK-SPIDER POS Attack Campaign - March 2024"
  threat_level: "High"
  analysis: "Complete"
  distribution: "Your Organisation Only"
  tags:
    - "tlp:amber"
    - "mitre-attack:..."  # Fill in
  attributes:
    - type: "ip-dst"
      value: "..."
      to_ids: true/false
      comment: "..."
  objects:
    - type: "file"
      attributes:
        - type: "filename"
          value: "..."
        # etc.
```

---

### Task 4: IOC Aging and Lifecycle (20 points)

Answer these questions in 2-3 sentences each:

1. **IOC Staleness:** The IP address `185.220.101.45` was observed in this incident. Why might this indicator be less valuable 6 months after this report? What should you do with it?

1. **IOC Quality:** The email sender domain `hr-notifications-secure.com` was used in this attack. What challenges would you face when adding this to an email blocklist?

1. **TLP Compliance:** This report is TLP:AMBER. Your SIEM team wants to add the C2 IP to their automated blocklist. Is this permitted under TLP:AMBER? What about sharing the hash with an external threat intel vendor?

1. **IOC vs. IOA:** Identify two indicators from this report that represent attacker **behavior** (IOA) rather than just artifacts (IOC). Why are these more valuable for detection?

---

## Submission

Submit:

1. Completed IOC table (Task 1)
1. Pyramid of Pain analysis (Task 2)
1. MISP event export (JSON) OR MISP event structure documentation (Task 3)
1. Written answers to Task 4 questions

---

## Evaluation Criteria

| Task | Points |
|------|--------|
| Task 1: IOC extraction completeness and accuracy | 25 |
| Task 2: Pyramid of Pain analysis | 25 |
| Task 3: MISP event correctness | 30 |
| Task 4: IOC lifecycle understanding | 20 |
| **Total** | **100** |
