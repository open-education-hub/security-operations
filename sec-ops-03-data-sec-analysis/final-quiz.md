# Final Quiz — Session 03: Data Categories and Analysis

**Purpose:** Assess knowledge gained during the session

**Level:** Intermediate

**Questions:** 7 multiple-choice

**Time:** ~15 minutes

**Passing score:** 5/7

---

**Q1.** Which of the following best describes the difference between **CEF** and **ECS** (Elastic Common Schema)?

* A) CEF is used for storage while ECS is used for transport
* B) CEF is a transport/wire format for log forwarding, while ECS is a schema standard defining field names and types for indexed data
* C) CEF is only for firewall logs, while ECS is for all log types
* D) CEF is a Splunk standard and ECS is an Elasticsearch standard — they are completely incompatible

**Correct answer: B**

*Explanation: CEF defines a wire format (typically carried over syslog) for transmitting events.
ECS defines the field schema for how data should be named and typed in an index.
CEF data can be parsed and mapped to ECS fields during ingestion.*

---

**Q2.** A security analyst sees this in a Logstash pipeline:

```ruby
geoip {
  source => "[source][ip]"
  target => "[source][geo]"
}
```

What does this Logstash filter do?

* A) Validates that the source IP is not in a private address range
* B) Looks up the geographic location of the source IP and adds it as nested fields under `source.geo`
* C) Converts the IP address to a hostname using reverse DNS
* D) Checks if the IP is in a blocklist

**Correct answer: B**

*Explanation: The `geoip` filter in Logstash uses the MaxMind GeoIP database to add geographic metadata (city, country, coordinates) for an IP address.
The `source` parameter specifies which field to look up; `target` specifies where to write the result.*

---

**Q3.** An analyst is investigating a potential DNS tunneling incident.
Which log source provides the most direct evidence?

* A) Windows Security Event Log (Event ID 4624)
* B) Sysmon Event ID 1 (process creation)
* C) DNS resolver logs showing query names and response types
* D) NetFlow records

**Correct answer: C**

*Explanation: DNS tunneling encodes data inside DNS queries.
DNS resolver logs show the actual query names (which would be abnormally long or high-entropy in a tunneling scenario) and query types (TXT records are commonly used).
NetFlow shows connection metadata but not DNS query content.
Sysmon and Windows Events don't capture DNS query content directly.*

---

**Q4.** An organization has the following log retention policy: security logs retained for 12 months online.
During an investigation, the analyst discovers that the attack began 14 months ago.
What does this reveal?

* A) Nothing — 14 months is an unusually long time for an attack, making this scenario implausible
* B) The organization likely has a compliance gap if regulations require longer retention for their industry
* C) The organization should immediately extend retention — this is a simple configuration change with no cost
* D) The attack data can be recovered from endpoint memory

**Correct answer: B**

*Explanation: A 14-month-old attack that has gone undetected is consistent with an APT (Advanced Persistent Threat).
If the organization is subject to SOX (7-year retention), HIPAA (6-year), or PCI-DSS (1-year with 3-month availability), having lost logs older than 12 months may represent a regulatory gap.
Option C is wrong because extending retention does have storage costs and may require architectural changes.*

---

**Q5.** In MISP, what does the **TLP:AMBER** tag indicate?

* A) The indicator has been confirmed by multiple independent sources
* B) The information may be shared within recipient organizations but not publicly disclosed
* C) The information is public and freely shareable
* D) The information is highly sensitive and restricted to the original recipient only

**Correct answer: B**

*Explanation:*

* *TLP:RED = Not for disclosure; recipient only*
* *TLP:AMBER = Limited disclosure; recipient organization only (can share internally)*
* *TLP:GREEN = Community-wide sharing allowed (security community, ISACs)*
* *TLP:CLEAR (formerly WHITE) = Public disclosure permitted*

---

**Q6.** Which of the following Splunk SPL queries would most effectively detect a **password spray attack** (one attacker trying many accounts with few attempts per account)?

* A) `index=windows EventCode=4625 | stats count BY src_ip | where count > 100`
* B) `index=windows EventCode=4625 | stats count AS attempts, dc(Account_Name) AS unique_accounts BY src_ip | where unique_accounts > 20`
* C) `index=windows EventCode=4625 Account_Name=Administrator | stats count BY src_ip`
* D) `index=windows EventCode=4625 | transaction Account_Name | where duration > 3600`

**Correct answer: B**

*Explanation: Password spray is characterized by targeting many accounts with few attempts each (to stay under lockout thresholds).
Query B correctly detects this pattern by counting unique targeted accounts (`dc(Account_Name)`) per source IP.
Query A would miss a spray attack that tries each account only 2-3 times.
Query C only looks at the Administrator account.
Query D groups by account, which is the wrong grouping for spray detection.*

---

**Q7.** You are reviewing an alert: "Process svchost32.exe made outbound connection to 185.220.101.5:443." You look up 185.220.101.5 in VirusTotal and find 0/90 detections.
What is the CORRECT interpretation?

* A) The connection is safe — 0 detections means VirusTotal has confirmed this IP is benign
* B) The connection is definitely malicious — VirusTotal must have an error
* C) The result is inconclusive — 0 VT detections does not rule out malicious activity, and the process name (svchost32.exe vs. legitimate svchost.exe) is itself suspicious
* D) You should immediately close the alert as a false positive

**Correct answer: C**

*Explanation: Zero VirusTotal detections only means no AV vendor currently flags this IP.
Attackers regularly rotate infrastructure, and newly stood-up C2 servers will have 0 VT detections for days or weeks.
More importantly, the process name `svchost32.exe` is suspicious — the legitimate Windows process is `svchost.exe` (no "32").
Masquerading as a Windows process by appending "32" is a known malware technique (T1036.005).*

---

## Score Interpretation

| Score | Grade | Notes |
|-------|-------|-------|
| 7/7 | Excellent | Full mastery of session material |
| 5–6/7 | Pass | Good understanding; review any missed questions |
| 3–4/7 | Near pass | Re-read relevant sections before the next session |
| 0–2/7 | Re-study recommended | Work through the demos again; review the reading |
