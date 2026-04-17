# Solution: Drill 02 — IOC Enrichment and Triage

## Alert 1: Suspicious Outbound Connection — Emotet C2

**1.
IOC Type:** IPv4 address (network indicator)

**2.
Likely threat:**
Emotet is a banking trojan and malware loader, primarily spread via phishing with malicious Word documents.
It establishes persistence, beacons to C2 servers, and downloads secondary payloads (often Cobalt Strike or ransomware like Ryuk/Conti).
The 47-minute connection with 2.1 MB outbound suggests active C2 communication and possibly data exfiltration or payload delivery.

**3.
Severity: CRITICAL**

Justification:

* Known malware C2 IP in Feodo Tracker (authoritative source)
* 14/X VirusTotal detections (high confidence)
* 47-minute active connection (not just a probe — established communication)
* Workstation is in Finance (`ws-finance-07`) — high-sensitivity asset
* Potential for lateral movement, credential theft, ransomware deployment

**4.
Immediate containment actions:**

1. Isolate `ws-finance-07` from the network immediately (EDR network isolation or VLAN quarantine)
1. Block 185.220.101.42 at the firewall for all outbound traffic
1. Create a SIEM alert for any other host connecting to this IP
1. Reset the user account password (Emotet steals credentials)
1. Notify the incident response team — this is a confirmed malware infection

**5.
Follow-up investigation:**

* Analyse the initial infection vector: what email/file triggered the Emotet infection?
* Review other endpoints for the same C2 connection
* Check for lateral movement from `ws-finance-07` (SMB connections to other hosts)
* Memory forensics to identify if secondary payload was dropped
* Review all outbound connections from `ws-finance-07` in the past 7 days

---

**Triage Output:**

```text
Alert ID:     ALERT-001
IOC Type:     IPv4 Address (C2 server)
Severity:     CRITICAL
Confidence:   HIGH (authoritative feed, 47-min connection, finance workstation)
Immediate Actions:
  - Isolate ws-finance-07 from network
  - Block 185.220.101.42 at firewall
  - Alert on other hosts connecting to this IP
  - Reset affected user credentials
Investigation Steps:
  - Identify infection vector (email logs, web proxy logs)
  - Check for lateral movement
  - Memory forensics for secondary payload
Triage Note:
  Finance workstation ws-finance-07 made a 47-minute HTTPS connection to known
  Emotet C2 server (185.220.101.42, 14/X VT detections, Feodo Tracker listed).
  Isolated host, blocked IP. Full incident response initiated. Potential ransomware
  precursor — check all connected hosts for similar IOC.
```

---

## Alert 2: Suspicious File Download — Typosquat Domain

**1.
ATT&CK TTPs:**

* T1566.002 — Spearphishing via Link (if user clicked a link to download)
* T1204.002 — User Execution: Malicious File (user ran the exe)
* T1105 — Ingress Tool Transfer (malware downloaded from attacker infrastructure)
* T1036.001 — Masquerading (typosquat of legitimate CDN domain)

**2.
Is 6/44 VirusTotal enough to act on?**

Yes, with additional context.
On its own, 6/44 would be borderline.
But combined with:

* Domain registered 3 days ago (very recent — common for malware delivery infrastructure)
* No digital signature (legitimate enterprise software is almost always signed)
* Typosquat of a real CDN (deliberate deception)
* Known typosquat pattern from similar BEC campaign domains

The compound evidence raises confidence to **HIGH**.
The absence of a digital signature alone is sufficient to quarantine and investigate.

**3.
Additional enrichment steps:**

* Submit the file to a sandboxing service (Any.run, Hybrid Analysis, Joe Sandbox) for dynamic analysis
* Check the domain's WHOIS, IP, and infrastructure for other malicious domains (passive DNS, RiskIQ)
* Review EDR telemetry: did the file execute? What processes did it spawn?
* Check if the URL was visited by other users in the organisation (proxy logs)
* Search for the file hash across all endpoints (EDR query)

**4.
Recommended action:**
Quarantine the file and isolate `laptop-dev-12` until sandbox results confirm or deny.
Block the domain at DNS and proxy level.
Alert on the file hash across all endpoints.

---

**Triage Output:**

```text
Alert ID:     ALERT-002
IOC Type:     File Hash (PE executable) + Domain
Severity:     HIGH
Confidence:   HIGH (typosquat + new domain + unsigned binary + partial AV detections)
Immediate Actions:
  - Quarantine file on laptop-dev-12
  - Block update.cdn-secure.net at DNS and proxy
  - Check if file executed (EDR process telemetry)
Investigation Steps:
  - Sandbox dynamic analysis
  - WHOIS/passive DNS for malicious infrastructure mapping
  - Search hash across all endpoints
  - Review proxy logs for other users visiting the URL
Triage Note:
  Unsigned PE binary downloaded from 3-day-old typosquat domain update.cdn-secure.net
  (mimicking cdn.net). 6/44 VT detections combined with domain age and signing status
  raise confidence to HIGH. Host quarantined, domain blocked. Sandbox analysis pending.
```

---

## Alert 3: Phishing Email — Microsoft Impersonation

**1.
False positive or genuine phishing?**

Genuine phishing.
Evidence:

* Domain `microsoft-security-alerts.com` registered only 7 days ago — legitimate Microsoft would never use such a recently registered domain
* Legitimate Microsoft email domains are `@microsoft.com` — not `microsoft-security-alerts.com`
* `.xlsm` macro-enabled attachment is a classic phishing delivery mechanism
* Similar domain used in documented BEC campaign (Proofpoint 2024-02-15)
* The sender attempts to create urgency ("Security Alerts" in the domain name) — social engineering

**2.
IOC to block:**

Domain: `microsoft-security-alerts.com` — block at email gateway, DNS, and proxy.
Also consider blocking the sending IP address at the email gateway.

**3.
Finance department context:**

Yes, this changes the response significantly:

* Finance employees are primary targets for BEC (Business Email Compromise) and invoice fraud
* If they are being targeted with "security alerts," the attacker may be attempting to harvest credentials for financial system access
* Treat this as a potential BEC attempt — notify the Finance manager and CISO

**4.
Checking for receipt/opening:**

* **Email gateway logs**: Did the gateway quarantine all 3 instances, or did any deliver?
* **Exchange/O365 message trace**: Confirm delivery status for each recipient
* **EDR/endpoint logs**: Check if `Excel.exe` was opened by any of the 3 users on the target date
* **O365 audit log**: Check if `xlsm` file was opened via Outlook web
* **Proxy logs**: If the macro tried to download a payload, a proxy connection to an external URL would appear

**5.
Triage note (incident ticket):**

Phishing email impersonating Microsoft security alerts sent to 3 Finance employees from newly registered domain `microsoft-security-alerts.com`.
Macro-enabled attachment `.xlsm` blocked by gateway.
Domain and IP blocked at email gateway and DNS.
All 3 recipients notified.
Verifying no delivery or attachment execution via EDR and email trace.
BEC risk — Finance manager and CISO informed.

---

**Triage Output:**

```text
Alert ID:     ALERT-003
IOC Type:     Phishing Domain + Malicious Attachment
Severity:     HIGH (Finance target, BEC risk)
Confidence:   HIGH (multiple corroborating factors)
Immediate Actions:
  - Block domain microsoft-security-alerts.com (email, DNS, proxy)
  - Notify 3 recipient employees and their manager
  - Confirm no delivery of the email to any user
Investigation Steps:
  - Email gateway + Exchange delivery trace
  - EDR check for Excel.exe execution
  - O365 audit log for attachment open events
  - Proxy logs for outbound calls from Finance endpoints
Triage Note:
  [See #5 above]
```

---

## Task 4: IOC Lifecycle Management

**1.
Why are 2-year-old IPs a problem?**

IP addresses are dynamically reassigned.
A C2 IP from 2 years ago may now be used by:

* A legitimate cloud service (causing false positives for every connection to that CDN)
* An innocent user who received that dynamic IP from their ISP

**2.
Risk of keeping stale IOCs:**

* **False positives**: Legitimate traffic blocked or alerted on → alert fatigue
* **Trust erosion**: Analysts learn to ignore IP alerts because they are "always noise"
* **Operational disruption**: Blocking a legitimate cloud IP can disrupt business operations

**3.
IOC expiry policy:**

```text
IOC Type          | Default Expiry | Extension Condition
------------------+----------------+---------------------
IP addresses      | 30 days        | Extend if reconfirmed in recent feed
Domains           | 90 days        | Extend if domain still active
File hashes       | 365 days       | No expiry for confirmed malware hashes
URLs              | 30 days        | —
Email addresses   | 180 days       | —
```

All IOCs should be tagged with source, date added, and date last confirmed.
Expired IOCs should be moved to a "passive" state (log only, no block) before full removal.
