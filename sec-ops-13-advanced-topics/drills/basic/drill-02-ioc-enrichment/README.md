# Drill 02: IOC Enrichment and Triage

## Difficulty: Basic

## Estimated Time: 30 minutes

## Scenario

Your SIEM has fired three alerts in the last hour.
Each alert contains an indicator of compromise (IOC).
Your task is to enrich each IOC using available open-source intelligence (OSINT) sources, determine its severity, and decide on the appropriate response action.

You do not need live internet access for this drill — all necessary context is provided in the scenario data.

## Objectives

1. Apply a structured IOC enrichment process
1. Determine the severity of each indicator using provided context
1. Decide on the correct response action for each
1. Write a triage note for each alert

---

## Alert 1: Suspicious Outbound Connection

**SIEM Alert**: Outbound TCP connection to 185.220.101.42 on port 443 from workstation `ws-finance-07`

**Available OSINT context:**

* IP 185.220.101.42 is listed in Abuse.ch Feodo Tracker as a known Emotet C2 server (first seen: 2024-02-01, last seen: 2024-03-12)
* The IP is located in a Tor exit node range
* 14 VirusTotal vendors flag this IP as malicious
* The connection lasted 47 minutes with 2.1 MB outbound / 0.3 MB inbound

**Questions:**

1. What is the IOC type?
1. What is the likely threat? (What does Emotet do?)
1. Rate the severity: Critical / High / Medium / Low — justify your rating
1. What immediate containment actions should you take?
1. What follow-up investigation is needed?

---

## Alert 2: Suspicious File Download

**SIEM Alert**: File hash `d85e336aba9c4f2c2af7a8a4f67e23aa8cf77b82` observed on endpoint `laptop-dev-12` (downloaded from `update.cdn-secure.net`)

**Available OSINT context:**

* File hash: 6 VirusTotal vendors flag as suspicious, 3 as clean, 25 unknown
* Domain `update.cdn-secure.net` registered 3 days ago; registrant details hidden
* Domain resolves to 203.0.113.78 (not listed in any feed)
* The file is a Windows PE executable, 248KB, no digital signature
* The legitimate CDN domain is `cdn.net` — the flagged domain is a typosquat

**Questions:**

1. What TTPs (ATT&CK techniques) could this represent?
1. Is a 6/44 VirusTotal detection ratio enough to act on? Explain.
1. What additional IOC enrichment steps would you perform?
1. What is your recommended action?

---

## Alert 3: Phishing Email Indicator

**SIEM Alert**: Email gateway blocked a message from `noreply@microsoft-security-alerts.com` to 3 employees containing attachment `Q4_Security_Report.xlsm`

**Available OSINT context:**

* Domain `microsoft-security-alerts.com` registered 7 days ago, hosted in Netherlands
* The legitimate Microsoft domain is `microsoft.com`
* The `.xlsm` extension indicates a macro-enabled Excel workbook
* Similar domain `microsoft-security-alerts.net` was used in a known BEC campaign (Proofpoint report, 2024-02-15)
* PhishTank has no entry for this domain

**Questions:**

1. Is this a false positive or a genuine phishing attempt? Justify.
1. What domain-based IOC should you extract and block?
1. The 3 employees are in Finance — does this change your response? Why?
1. What should you check to determine if any user actually received and opened the attachment?
1. Write a 3-line triage note for the incident ticket.

---

## Task 4: IOC Lifecycle Management

You have 200 IP address IOCs imported into your SIEM two years ago from a public feed.
The feed has not been updated since.

**Questions:**

1. Why are 2-year-old IP IOCs a problem?
1. What is the risk of keeping them active in your SIEM?
1. What policy should govern IOC expiry and refresh?

---

## Deliverable

For each alert (1–3), produce a structured triage output:

```text
Alert ID:
IOC Type:
Severity:
Confidence (Low/Medium/High):
Immediate Actions:
Investigation Steps:
Triage Note (2-3 sentences):
```
