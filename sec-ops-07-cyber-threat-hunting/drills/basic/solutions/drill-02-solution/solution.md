# Drill 02 Solution: IOC Collection and Categorization

---

## Task 1: IOC Extraction and Classification

| Indicator Value | MISP Type | Category | For IDS? | Confidence | Notes |
|-----------------|-----------|----------|----------|------------|-------|
| `payroll-support@hr-notifications-secure.com` | `email-src` | Payload delivery | Yes | High | Phishing sender |
| `finance-helpdesk@victim-corp.com` | `email-dst` | Network activity | No | High | Victim address, no detection value |
| `Urgent: Payroll System Authentication Required` | `email-subject` | Payload delivery | No | Medium | Subject lines change easily |
| `payroll_q1_2024.pdf.exe` | `filename` | Payload delivery | No (FP risk) | High | Filename alone too generic |
| `3a7f4b8c2d9e5f61a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5` | `sha256` | Payload delivery | Yes | High | Malware dropper hash |
| `9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e` | `md5` | Payload delivery | Yes | High | Same file, MD5 |
| `327680` | `size-in-bytes` | Payload delivery | No | Medium | Size alone insufficient |
| `svchost32.exe` | `filename` | Persistence mechanism | Yes (with path) | High | Unusual process name |
| `C:\Users\<user>\AppData\Local\Microsoft\svchost32.exe` | `filename` | Artifacts dropped | Yes | High | Specific path makes this higher value |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsSystemService` | `regkey` | Persistence mechanism | Yes | High | Registry run key for persistence |
| `C:\Users\Administrator\AppData\Local\Microsoft\svchost32.exe -s` | `regkey\|value` | Persistence mechanism | Yes | High | Full reg key+value pair |
| `185.220.101.45` | `ip-dst` | Network activity | Yes | High | C2 server IP |
| `8443` | `port` | Network activity | No (alone) | Medium | Non-standard port |
| `cdn-media-services.com` | `domain` | Network activity | Yes | High | C2 domain |
| `ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01` | `x509-fingerprint-sha1` | External analysis | Yes | High | Certificate pinning for C2 |
| `data-reporting-api.net` | `domain` | Network activity | Yes | High | Exfiltration domain |
| `winsrv.dll` | `filename` | Artifacts dropped | Yes (with path context) | High | POS malware |
| `f1e2d3c4b5a69788706050403020100f1e2d3c4b5a6978870605040302010011` | `sha256` | Payload delivery | Yes | High | POS RAM scraper hash |
| `C:\ProgramData\Microsoft\Crypto\audit.tmp` | `filename` | Artifacts dropped | Yes | Medium | Staging file path |
| `https://data-reporting-api.net/api/v2/collect` | `url` | Network activity | Yes | High | Exfiltration endpoint URL |
| `win32net.exe` | `filename` | Artifacts dropped | Yes | Medium | Renamed curl.exe |

**Grading notes:**

* Full credit: All indicators found and correctly typed
* Common mistakes: Missing certificate fingerprint, missing URL vs domain distinction, incorrect MISP type names
* The email destination (victim) should NOT be For IDS; it has no detection value

---

## Task 2: Pyramid of Pain Analysis

### Level 1: Hash Values (Trivial to change)

**IOCs:**

* `3a7f4b8c...` (SHA256, dropper)
* `9b8c7d6e...` (MD5, dropper)
* `f1e2d3c4...` (SHA256, POS malware)
* `ab:cd:ef:...` (certificate SHA1)

**How quickly can attackers change this?** Minutes - just recompile with any modification (change a single byte, change a string).
Polymorphic malware generators do this automatically.

**Operational value:** LOW for hash values.
Medium for certificate fingerprint (reissuing certificates takes effort).

**Recommendation:** Add to automated blocklist but understand it will miss variants.
More valuable as a pivot point to find other infrastructure than as a stand-alone detection.

### Level 2: IP Addresses (Easy to change)

**IOCs:**

* `185.220.101.45` (C2)

**How quickly?** Hours to days - spin up new server, update DNS.
Cloud infrastructure makes this trivial.

**Operational value:** MEDIUM - useful now, stales within days to weeks.

**Recommendation:** Add to automated firewall block, but set expiry of 30 days and review.

### Level 3: Domain Names (Simple to change)

**IOCs:**

* `cdn-media-services.com`
* `data-reporting-api.net`
* `hr-notifications-secure.com`

**How quickly?** Days - register new domain (cheap, often under $10), update infrastructure.

**Operational value:** MEDIUM-HIGH - domains require more effort than IPs, and organizations often reuse naming conventions.

**Recommendation:** Add to DNS blocklist.
Also analyze naming patterns (impersonating legitimate services: "cdn", "api", "hr-notifications").

### Level 4: Network Artifacts (Annoying to change)

**IOCs:**

* C2 on port 8443 (non-standard HTTPS port)
* Certificate patterns
* User-Agent strings (if captured)
* HTTP header patterns for C2

**How quickly?** Days to weeks - requires updating malware configuration, re-deploying.

**Operational value:** HIGH - network signatures persist across infrastructure changes.

**Recommendation:** Hunt for these patterns in proxy/firewall logs.
Create IDS rules.

### Level 5: Host Artifacts (Annoying to change)

**IOCs:**

* `C:\Users\<user>\AppData\Local\Microsoft\svchost32.exe` (unusual location for svchost)
* `HKCU\...\Run\WindowsSystemService` (registry key name)
* `C:\ProgramData\Microsoft\Crypto\audit.tmp` (staging file)
* Process name `svchost32.exe` (fake svchost)

**How quickly?** Days - requires modifying malware to use different paths/names.

**Operational value:** HIGH - host artifacts indicate active malware presence.

**Recommendation:** Create host-based detections (EDR rules, Sysmon rules).
Most valuable for incident response.

### Level 6: Tools (Difficult to change)

**IOCs:**

* Rclone-based exfiltration (curl renamed to `win32net.exe`)
* RAM scraping technique targeting POS processes
* POS memory scraping tool (`winsrv.dll`)

**How quickly?** Weeks to months - requires finding, testing, and deploying alternative tools.

**Operational value:** HIGH - tool-based detection catches the actor even with new infrastructure.

**Recommendation:** YARA rules for tool signatures, behavioral EDR rules.

### Level 7: TTPs (Extremely Difficult to change)

**Identified TTPs:**

* Phishing with double-extension executable (T1204.002)
* HKCU Run key persistence (T1547.001)
* Process injection into POS software (T1055)
* Off-hours exfiltration via renamed tool (T1036.003, T1567.002)
* Staging in Crypto directory (T1074.001)

**How quickly?** Months to years - requires retraining, new toolkits, operational changes.

**Operational value:** HIGHEST - TTP-based detection works even as all other indicators rotate.

**Recommendation:** Write behavioral detection rules targeting these patterns.
Train hunters to look for this combination of behaviors.

---

## Task 3: MISP Event Structure (Solution)

```yaml
event:
  info: "SILK-SPIDER POS Attack Campaign - March 2024"
  threat_level_id: 1          # High
  analysis: 2                  # Complete
  distribution: 0              # Your organisation only
  date: "2024-03-20"

  tags:
    - name: "tlp:amber"
    - name: "mitre-attack:initial-access:T1566.001"    # Spearphishing attachment
    - name: "mitre-attack:persistence:T1547.001"        # Registry run keys
    - name: "mitre-attack:credential-access:T1055"      # Process injection
    - name: "mitre-attack:exfiltration:T1567.002"       # Exfiltration to cloud storage
    - name: "kill-chain:delivery"
    - name: "kill-chain:actions-on-objectives"

  attributes:
    - type: "email-src"
      value: "payroll-support@hr-notifications-secure.com"
      to_ids: true
      comment: "Phishing sender for initial access"

    - type: "email-subject"
      value: "Urgent: Payroll System Authentication Required"
      to_ids: false
      comment: "Phishing email subject"

    - type: "sha256"
      value: "3a7f4b8c2d9e5f61a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
      to_ids: true
      comment: "Dropper executable - payroll_q1_2024.pdf.exe"

    - type: "md5"
      value: "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"
      to_ids: true
      comment: "Dropper executable MD5"

    - type: "filename|sha256"
      value: "payroll_q1_2024.pdf.exe|3a7f4b8c2d9e5f61a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
      to_ids: true
      comment: "Dropper with filename"

    - type: "ip-dst"
      value: "185.220.101.45"
      to_ids: true
      comment: "SILK-SPIDER C2 server"

    - type: "domain"
      value: "cdn-media-services.com"
      to_ids: true
      comment: "C2 domain"

    - type: "domain"
      value: "data-reporting-api.net"
      to_ids: true
      comment: "Exfiltration domain"

    - type: "url"
      value: "https://data-reporting-api.net/api/v2/collect"
      to_ids: true
      comment: "Exfiltration endpoint"

    - type: "x509-fingerprint-sha1"
      value: "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01"
      to_ids: true
      comment: "C2 SSL certificate fingerprint"

    - type: "regkey|value"
      value: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSystemService|C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\svchost32.exe -s"
      to_ids: true
      comment: "Persistence registry key"

    - type: "sha256"
      value: "f1e2d3c4b5a69788706050403020100f1e2d3c4b5a6978870605040302010011"
      to_ids: true
      comment: "POS RAM scraper (winsrv.dll)"

    - type: "filename"
      value: "win32net.exe"
      to_ids: true
      comment: "Renamed curl.exe used for exfiltration"

  objects:
    - type: "file"
      name: "Dropper: payroll_q1_2024.pdf.exe"
      attributes:
        - type: "filename"
          value: "payroll_q1_2024.pdf.exe"
          to_ids: false
        - type: "sha256"
          value: "3a7f4b8c2d9e5f61a23b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
          to_ids: true
        - type: "md5"
          value: "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"
          to_ids: true
        - type: "size-in-bytes"
          value: "327680"
          to_ids: false
        - type: "mimetype"
          value: "application/x-msdownload"
          to_ids: false

    - type: "network-connection"
      name: "C2 Connection"
      attributes:
        - type: "ip-dst"
          value: "185.220.101.45"
          to_ids: true
        - type: "hostname-dst"
          value: "cdn-media-services.com"
          to_ids: true
        - type: "dst-port"
          value: "8443"
          to_ids: false
        - type: "layer7-protocol"
          value: "HTTPS"
          to_ids: false
```

---

## Task 4: IOC Lifecycle Answers

**1.
IOC Staleness:**
The IP address `185.220.101.45` may have been reassigned to a different organization or may now be used by a completely different threat actor after 6 months.
Cloud and VPS providers recycle IP addresses frequently.
To handle this: set an expiry date on the indicator in MISP (e.g., 60 days), review whether the IP still resolves to malicious infrastructure before acting on it, and avoid automated blocking of aged IPs without reverification.

**2.
IOC Quality - Email blocklist challenges:**
The domain `hr-notifications-secure.com` could be registered again by a different entity or even purchased by a legitimate HR company.
More importantly, adding this to an email blocklist based on a single phishing campaign risks blocking legitimate email from a domain that could be repurposed for benign use.
Better approach: block at the specific full email address level or use the domain as a detection/alerting indicator rather than a hard block, and review periodically.

**3.
TLP Compliance:**
Under TLP:AMBER, recipients may share information with "members of their own organization and clients who need to know." Adding the C2 IP to your own SIEM automated blocklist is permitted (internal use).
Sharing the hash with an external threat intel vendor would violate TLP:AMBER unless that vendor is explicitly a "client who needs to know" and is covered by a data sharing agreement.
To share with the vendor, you would need permission from the originating organization or would need to downgrade the TLP marking with their approval.

**4.
IOA vs IOC:**
Two behavioral indicators (IOAs) from this report:

1. **Off-hours exfiltration pattern (03:15-04:30 AM):** This describes attacker behavior (conducting exfiltration during off-hours to avoid detection) rather than a specific artifact. This pattern persists even when the attacker uses different tools or infrastructure. Detection: alert on large data transfers during night hours from any host.
1. **Staging data in `C:\ProgramData\Microsoft\Crypto\`:** This directory is legitimate for Windows but rarely used for staging data files. The behavior of creating archive files or large data dumps here is a pattern attackers repeat across campaigns. Detection: monitor for non-Windows processes creating files in this directory.

These IOAs are more valuable because they remain valid even after the attacker changes IP addresses, domain names, and file hashes—which can happen between campaigns.

---

## Grading Notes

**Common student mistakes:**

* Not marking email recipient as "not for IDS" (recipient has no detection value)
* Confusing `domain` and `url` types (URL includes the full path)
* Setting all indicators as `to_ids=true` without considering false positive risk
* Missing the certificate fingerprint (often overlooked)
* Task 4 Q3: Students often confuse TLP:AMBER and TLP:GREEN. Emphasize that AMBER restricts to org+clients, not public sharing.

**Accept:** Minor variations in MISP field names, reasonable alternative TLP assessments with clear justification.
