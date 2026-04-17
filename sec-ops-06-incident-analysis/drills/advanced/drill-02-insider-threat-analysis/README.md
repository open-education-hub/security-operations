# Drill 02 (Advanced): Insider Threat Analysis

**Level:** Advanced

**Time:** 90 minutes

**Environment:** Docker (multi-source log analysis)

**Special considerations:** Legal and HR procedures — this drill includes legal/procedural elements

---

## Overview

Insider threat investigations are fundamentally different from external threat investigations:

1. **Legal constraints:** Employee privacy laws apply — collection and use of evidence must comply with employment law and data protection regulations
1. **HR involvement:** HR and legal must be engaged from the outset
1. **Behavioral analysis:** The activity may look legitimate on the surface
1. **False accusation risk:** Getting this wrong has serious consequences for both the organization and the individual

This drill presents a realistic insider threat scenario where you must investigate while navigating the procedural requirements.

---

## Lab Setup

```console
cd drills/advanced/drill-02-insider-threat-analysis
docker compose up -d
```

Access: Kibana http://localhost:5604 (elastic / changeme)

---

## Scenario Background

**Organization:** PharmaResearch Inc — a pharmaceutical research company

**Environment:** Windows AD, `pharma.local`

**Situation:**
Three weeks ago, a senior researcher (`dr.chen`, Dr.
Linda Chen) submitted her resignation with 30 days' notice.
She is leaving to join a competitor.

The DLP system has triggered three alerts in the past week:

```text
DLP Alert 1 (2024-11-10): dr.chen accessed 847 files in the Compounds database
DLP Alert 2 (2024-11-13): dr.chen sent email with >10MB attachment to personal email
DLP Alert 3 (2024-11-15): dr.chen copied 4.2 GB to USB drive
```

**Current status:**

* Dr. Chen is still employed (15 days remaining in notice period)
* She has legitimate access to all the files she has been accessing
* She has historically accessed compound data as part of her job
* The DLP alerts may represent legitimate work — she is completing projects before leaving

**You have been asked by HR and Legal to conduct a covert investigation.**

---

## Pre-Investigation: Legal Framework Questions

Before touching any logs, answer these procedural questions.
These are NOT optional — they are required before investigation begins.

### Legal Check 1

The organization's IT policy (Acceptable Use Policy) states:
"Employees acknowledge that company systems and data may be monitored for security purposes."

Does this policy authorize conducting a covert investigation of Dr.
Chen's activities?
What are the limits?

### Legal Check 2

Dr.
Chen has been sending emails via her work email account to her personal Gmail.
What laws might apply to accessing and reviewing the contents of those emails (as opposed to just the metadata)?

### Legal Check 3

The DLP Alert 2 shows an email sent to Dr.
Chen's personal email.
The attachment is suspected to contain trade secrets.
What legal theories might apply if this investigation confirms she took proprietary research?

---

## Investigation Part 1: Establish Baseline Normal Behavior

Before concluding that behavior is suspicious, you must establish what is *normal* for Dr.
Chen.

### 1.1 — Historical access pattern

```text
index=winlogs EventCode=4663 Account_Name="dr.chen"
| timechart span=1d count
| eval day_of_week = strftime(_time, "%A")
```

**Task:** Compare Dr.
Chen's daily file access volume over the past 3 months.
Is the current elevated access statistically anomalous, or within her historical range?

### 1.2 — USB usage history

```text
index=sysmon EventID=6 Computer IN (computers where dr.chen logged in)
| table _time, Computer, ImageLoaded
| sort _time
```

Also check printer usage (printing to paper is a classic exfiltration method):

```text
index=winlogs EventCode=307 User="dr.chen"
| stats count by PrinterName, DocumentName, _time
| sort _time
```

**Task:** Has Dr.
Chen previously used USB drives?
How frequently?
Is the current volume unusual?

### 1.3 — Email volume baseline

```text
index=email from_address="dr.chen@pharma.local"
| timechart span=1d count
| eval period = if(_time > relative_time(now(), "-30d"), "post_resignation", "pre_resignation")
```

**Task:** Has her email sending volume changed since resignation?
Are attachment sizes larger than baseline?

---

## Investigation Part 2: Analyze the Specific DLP Alerts

### 2.1 — DLP Alert 1: 847 Files Accessed

```text
index=winlogs EventCode=4663 Account_Name="dr.chen"
earliest="2024-11-10T00:00:00" latest="2024-11-11T00:00:00"
| where like(Object_Name, "%Compounds%")
| stats count by Object_Name, Access_Mask
| sort -count
```

**Task 2.1a:** What specific files were accessed?
Are these all within Dr.
Chen's research area?
**Task 2.1b:** Was access read-only, or were files copied/modified?

**Task 2.1c:** Is accessing 847 files in one day consistent with a researcher completing their work, or does the pattern suggest bulk acquisition?

### 2.2 — DLP Alert 2: Large Email Attachment to Personal Account

```text
index=email from_address="dr.chen@pharma.local" to_address="*gmail.com*"
earliest="2024-11-12" latest="2024-11-14"
| table _time, from_address, to_address, subject, attachment_name, attachment_size_bytes
```

**Task 2.2a:** What was the attachment?
Can you determine if it contains proprietary research data?
**Task 2.2b:** Is this the first time Dr.
Chen has sent data to a personal email account?

Check historical pattern:

```text
index=email from_address="dr.chen@pharma.local" to_address="*gmail.com*"
earliest=-90d
| stats count, sum(attachment_size_bytes) as total_bytes by to_address
```

### 2.3 — DLP Alert 3: 4.2 GB USB Copy

```text
index=sysmon EventID=11 User="dr.chen"
earliest="2024-11-15T00:00:00" latest="2024-11-16T00:00:00"
| where like(TargetFilename, "E:\\") OR like(TargetFilename, "F:\\") OR like(TargetFilename, "G:\\")
| stats count, sum(FileSize) as total_bytes, values(TargetFilename) as files_copied
| eval total_gb = round(total_bytes / 1073741824, 2)
```

**Task 2.3a:** What was copied?
Is it research data, personal files, or a mix?
**Task 2.3b:** Does the file list correspond to her research area or does it suggest broader acquisition?

---

## Investigation Part 3: Behavioral Pattern Analysis

### 3.1 — After-hours activity analysis

```text
index=winlogs EventCode=4624 Account_Name="dr.chen"
| eval hour = strftime(_time, "%H")
| eval day_of_week = strftime(_time, "%u")
| stats count by hour, day_of_week
```

**Task:** Was any of the suspicious activity after normal hours or on weekends?
Is this unusual for Dr.
Chen?

### 3.2 — Printer analysis

Did Dr.
Chen print classified research documents?

```text
index=winlogs EventCode=307 UserName="dr.chen"
earliest="2024-11-01"
| stats count, sum(JobSize) as total_pages by DocumentName
| sort -count
```

### 3.3 — Cloud storage access

Did Dr.
Chen access cloud storage services (Dropbox, Google Drive, OneDrive personal)?

```text
index=proxy user="dr.chen"
| where like(dest_domain, "*dropbox.com*") OR
        like(dest_domain, "*drive.google.com*") OR
        like(dest_domain, "*onedrive.live.com*") OR
        like(dest_domain, "*wetransfer.com*")
| stats count, sum(bytes_out) as total_bytes by dest_domain
| eval total_mb = round(total_bytes / 1048576, 2)
```

---

## Investigation Part 4: Produce the Investigation Report

### 4.1 — Evidence Matrix

Complete this matrix for each DLP alert:

```text
Alert  | File Type | Data Classification | Volume | Baseline? | Pattern     | Conclusion
───────┼───────────┼─────────────────────┼────────┼───────────┼─────────────┼────────────
DLP-1  |           |                     |        |           |             |
DLP-2  |           |                     |        |           |             |
DLP-3  |           |                     |        |           |             |
```

**Possible conclusions per alert:**

* BENIGN: Consistent with legitimate work
* SUSPICIOUS: Elevated above baseline, no clear legitimate purpose
* CONFIRMED MALICIOUS: Clear intent to exfiltrate proprietary data

### 4.2 — Insider Threat Risk Assessment

Rate Dr.
Chen on the insider threat risk indicators:

```text
INDICATOR                           | Present? | Evidence
────────────────────────────────────┼──────────┼──────────────────
Leaving for competitor              | YES      | Known — resignation
Access volume increase post-notice  |          |
External email of sensitive data    |          |
USB usage post-notice               |          |
After-hours access (anomalous)      |          |
Cloud storage usage                 |          |
Access to data outside job role     |          |
Printing large volumes              |          |
```

### 4.3 — Legal Recommendation

Based on your findings, write a 1-page legal recommendation to HR and Legal Counsel:

* State your confidence level in malicious intent (low / medium / high)
* Identify specific legal theories that may apply (trade secret theft, breach of employment contract)
* Recommend next steps (additional monitoring, early termination with rights reserved, law enforcement referral)
* Identify any evidence preservation requirements

---

## Critical Discussion Questions

1. **At what point does protecting trade secrets override employee privacy rights?** How do you balance these in your investigation approach?

1. **Dr. Chen has legitimate access to all the files she accessed.** Does legitimate access negate an insider threat investigation?

1. **If this investigation concludes Dr. Chen acted with malicious intent and the company wishes to prosecute**, what additional steps must be taken with the evidence NOW to ensure it's legally usable?

1. **How do you handle false accusations?** If the investigation concludes no malicious intent was present, what are the obligations to Dr. Chen?

1. **The manager who escalated this concern** has a personal conflict with Dr. Chen (documented HR dispute from 3 months ago). How does this affect your investigation?
