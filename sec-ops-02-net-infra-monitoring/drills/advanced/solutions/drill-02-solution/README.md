# Drill 02 Solution (Advanced): NSM Architecture — GlobalPort Logistics

**Model solution — key design decisions and justifications**

---

## 1. Architecture Overview

The GlobalPort NSM architecture follows a **federated hub-and-spoke model** with:

* Regional SIEM nodes (EU, Americas, APAC) for data residency compliance
* Central threat intelligence and policy management at Frankfurt HQ
* Lightweight sensors at all 10 port/warehouse sites
* Dedicated OT monitoring infrastructure (separated from IT)

```text
Frankfurt HQ (Primary SIEM)
├── Zeek sensor (internet uplink)
├── Suricata IPS (internet uplink)
├── Zeek sensor (SAP/ERP network)
├── Full PCAP (internet uplink, 14-day retention)
├── Active Directory Wazuh agents
└── Central Threat Intel Platform (MISP)
         │ (EU-only data stays in Frankfurt)
         │
    ┌────┼────────────────────────────┐
    │    │                            │
Dallas Hub              Singapore Hub    10x Warehouse Sites
(Regional SIEM)         (Regional SIEM)  (Lightweight sensors)
├── Zeek sensor         ├── Zeek sensor  ├── FortiGate IPS
├── Suricata            ├── Suricata     ├── NetFlow → Regional SIEM
├── NetFlow collector   └── NetFlow      └── Zeek (OT protocol monitor)
└── Wazuh agents
```

---

## 2. Technology Stack

| Tool | Version | Purpose | Type | Cost (yr1) | Integration |
|------|---------|---------|------|-----------|-------------|
| Elastic SIEM (Elasticsearch + Kibana) | 8.x | Primary SIEM (EU + regional nodes) | Commercial (self-hosted) | ~€12,000/yr | API, Filebeat, Logstash |
| Zeek | 6.x | NSM sensor (all critical sites) | Open source (free) | Hardware only | Files → Filebeat → Elastic |
| Suricata | 7.x | IDS/IPS (internet uplinks) | Open source (free) | Hardware only | EVE JSON → Filebeat → Elastic |
| Wazuh | 4.x | Endpoint detection + log collection | Open source (free) | ~€5,000/yr support | Agent-based |
| MISP | 2.4 | Threat intelligence platform | Open source (free) | ~€3,000/yr support | MISP → Zeek intel + Elastic |
| nfdump/ntopng | Latest | NetFlow collection + analysis | Open source / €3,000 | €3,000/yr | UDP NetFlow → Elastic |
| FortiGate 80F | 7.x | OT site firewall + IPS | Commercial | €2,000/site × 10 = €20,000 | Syslog → Elastic |
| tcpdump | System | PCAP capture (backup) | Open source | Free | Files → Elastic |
| Filebeat | 8.x | Log shipping agent | Open source | Free | → Elasticsearch |
| CyberChef | 10.x | Data analysis/decoding | Open source | Free | Standalone |
| TheHive | 5.x | Incident case management | Open source | ~€5,000/yr support | API ↔ Elastic |
| Velociraptor | 0.7 | EDR / threat hunting | Open source | ~€3,000/yr support | API → Elastic |

**Total estimated Year 1 cost:**

* Software/licensing: ~€55,000
* Hardware (sensors × 15 sites): ~€80,000
* Staff (see SOC model): ~€240,000
* Training: ~€15,000
* **Total Year 1: ~€390,000**

---

## 3. Detection Coverage (ATT&CK Mapping)

| ATT&CK Technique | Detection Source | Detection Method | Latency |
|-----------------|-----------------|-----------------|---------|
| T1190 - Exploit Public-Facing Application | Suricata IPS (internet uplink) + Zeek http.log | IPS signature match for known CVEs; HTTP 500 errors + SQL injection patterns in URI; anomalous response sizes | Real-time (Suricata); Near-real-time (Zeek → SIEM, 60s) |
| T1071.004 - DNS C2 | Zeek dns.log | Long subdomain names (>25 chars), TXT record queries to new domains, NXDOMAIN volume spikes, query to non-corporate DNS resolvers | Near-real-time |
| T1021.002 - SMB Lateral Movement | Zeek conn.log (internal sensors) | Connections from workstations to other workstations on port 445; new SMB connections to servers outside baseline | Near-real-time |
| T1048 - Exfiltration Over Alt Protocol | Zeek conn.log + dns.log | Large outbound byte counts on non-standard ports; DNS TXT record transfers; volume anomalies vs baseline | Daily (volume) / Real-time (Suricata signatures) |
| T1566.001 - Spearphishing Attachment | Zeek smtp.log + files.log | Executable/macro attachments (.docm, .xlsm, .ps1, .zip with .exe) delivered via SMTP; sender reputation | Near-real-time |
| T1078 - Valid Accounts (VPN stolen creds) | VPN connection logs + Wazuh | Login from new country; login outside business hours; multiple failed VPN attempts followed by success | Real-time (Suricata + Elastic alert rule) |
| T1486 - Ransomware (Data Encrypted for Impact) | Zeek conn.log + Wazuh | Sudden spike in SMB connections from a single host; Wazuh file integrity monitoring detecting mass file renames (extension change); CPU spike | Real-time (Wazuh FIM); Near-real-time (Zeek) |
| T1195 - Supply Chain Compromise | Zeek http.log + files.log + Suricata | Software update downloads (hash verification against known-good baseline); unexpected outbound connections from software update processes; new DLL loaded by updater | Near-real-time |

---

## 4. OT/IoT Network Monitoring

**Why standard IT monitoring doesn't work for OT:**

1. **Safety-critical systems:** An IDS that sends a RST to a PLC could disrupt a physical process (pump stops, conveyor halts). Monitoring must be 100% passive.
1. **Legacy protocols:** OT uses Modbus, DNP3, PROFINET, BACnet — standard Zeek doesn't dissect these. Zeek packages and specialised tools (Claroty, Dragos, Nozomi) are needed.
1. **No-downtime requirement:** You cannot reboot an industrial controller to install an agent; patching cycles are years long.
1. **Air gaps (partial):** Some OT networks are semi-isolated — monitoring infrastructure must be designed to work across this boundary.

**Recommended approach:**

```text
OT Network (Warehouse)
├── Hardware TAP on OT backbone (between PLC network and HMI network)
│   └── Zeek + Zeek-ICS packages (passive only)
│       ├── Modbus dissector
│       ├── DNP3 dissector
│       └── Generates: modbus.log, dnp3.log, conn.log
├── OT-specific IDS: Claroty or Nozomi (if budget allows)
│   └── Passive network discovery + anomaly detection
├── FortiGate firewall (segmentation between OT and IT)
│   └── Syslog to regional SIEM
└── Asset discovery: Zeek passively identifies all OT devices
```

**Baselining "normal" OT behaviour:**

* OT networks are highly deterministic — the same PLC talks to the same HMI, at the same times, with the same commands
* Run Zeek for 2–4 weeks in observation mode to establish baseline: which devices communicate, which Modbus function codes are normal, what timing patterns are expected
* Any deviation from baseline (new device, new function code, new source IP) triggers an alert

**Key OT detection rules:**

1. New IP appearing on OT network (never seen before)
1. Modbus write commands from IT network (should never happen)
1. HMI connecting to internet (should never happen)
1. PLC responding to external queries (injection attempt)

---

## 5. Multi-Region Data Strategy

**Data residency design:**

* Frankfurt Elastic cluster stores all EU data (GDPR requirement)
* Dallas Elastic cluster stores Americas data (US regulations)
* Singapore Elastic cluster stores APAC data (PDPA requirement)
* Each cluster is logically isolated — no cross-border data replication for personal data

**Normalised security data (aggregated statistics, anonymised alerts) CAN be shared:**

* Threat intel IOCs shared globally via MISP
* Statistical baselines shared for cross-region anomaly detection
* Incident data shared (not containing personal data) for correlation

**Cross-border log shipping where legally required:**
For cloud-hosted infrastructure (Microsoft 365 logs), use **EU Standard Contractual Clauses (SCCs)** or equivalent transfer mechanisms.

**Follow-the-sun SOC:**

* Frankfurt: 06:00–14:00 UTC (covers EU business hours)
* Dallas: 14:00–22:00 UTC (covers Americas)
* Singapore: 22:00–06:00 UTC (covers APAC)
* P1 alerts trigger immediate escalation regardless of shift

---

## 6. Correlation Rules for 5 Security Concerns

### Concern 1: Supply Chain Attack (SolarWinds-style)

```splunk
# Splunk SPL
index=network sourcetype=zeek_http
| where user_agent LIKE "%SolarWinds%" OR user_agent LIKE "%update%"
| join conn_uid [
    search index=network sourcetype=zeek_files
    | where mime_type = "application/x-pe-i386" OR mime_type = "application/x-dosexec"
]
| lookup known_software_hashes md5 OUTPUT known
| where known = "false"
| stats count by src_ip, dest_ip, filename, md5
| where count > 0
```

Plain logic: Alert when a software update process downloads a new executable binary whose hash doesn't match the known-good baseline.

### Concern 2: Ransomware on OT

```text
Rule: Ransomware Spread Indicator
WHEN:
  - Single source IP on OT network has SMB connections to > 10 unique destinations
    within a 5-minute window
  AND Wazuh file integrity alert shows > 100 file renames per minute
  on any connected HMI
THEN: CRITICAL ALERT
  Action: Automatically isolate the source IP at the FortiGate firewall
  Notify: OT Operations Manager + SOC + CISO
```

### Concern 3: Insider Threat (Data Exfiltration)

```text
Rule: Possible Insider Data Exfiltration
WHEN:
  - User identity known (from AD logs via Wazuh)
  AND destination is external (not 10.0.0.0/8 or 172.16.0.0/12)
  AND total bytes outbound > 500 MB within 1 hour
  AND file_type in (7z, zip, tar, csv, xls, pdf)
  AND (time_of_day NOT IN business_hours
       OR hr_system.employee_status = "resignation_notice")
WITHIN 24 hours
THEN alert HIGH with identity enrichment
```

### Concern 4: Cargo Theft (Physical + Network)

```text
Rule: Suspicious Physical + Network Correlation
WHEN:
  - Physical access log: badge swipe to warehouse cargo area
  AND network log: same user's workstation connects to cargo tracking DB
  AND cargo tracking DB query returns > 50 records (bulk lookup)
  AND time is outside normal shift hours
WITHIN 30 minutes of badge swipe
THEN alert HIGH
```

*Requires integration between physical access control system and SIEM*

### Concern 5: EDI Partner Compromise

```text
Rule: Anomalous EDI Message
WHEN:
  - EDI sender is known partner
  AND message volume > 5x partner's daily baseline
  OR message contains unexpected transaction types
  OR message values outside normal ranges (e.g., quantity > 10x max historical)
  OR sender IP ≠ known partner IP range
THEN alert MEDIUM with EDI analyst review required
```

---

## 7. SOC Operations Model

### Staffing

**Total SOC headcount: 9 analysts + 1 SOC Manager**

| Role | Count | Shift | Responsibilities |
|------|-------|-------|-----------------|
| SOC Manager | 1 | Business hours (+ on-call) | Program management, escalation, reporting |
| L1 Analyst | 3 | Rotating 8-hour shifts (24/7) | Alert triage, initial investigation, escalation |
| L2 Analyst | 3 | Business hours per region | Deep investigation, containment, runbook execution |
| L3/Threat Hunter | 2 | Business hours (EU) | Threat hunting, rule tuning, playbook development |
| OT Security Specialist | 1 | Business hours | OT-specific monitoring, warehouse site support |

### Key KPIs

| Metric | Target |
|--------|--------|
| Mean Time to Detect (MTTD) | < 4 hours |
| Mean Time to Respond (MTTR) | < 2 hours (P1) |
| Alert false positive rate | < 20% |
| Alert coverage (% ATT&CK techniques detectable) | > 70% |
| SIEM uptime | > 99.5% |
| % of critical assets with logging | 100% |
| Purple team coverage (quarterly) | ≥ 3 campaigns per year |

### Detection Effectiveness Measurement

* **Quarterly purple team exercises:** Red team simulates the 5 specific threat scenarios; blue team uses NSM to detect
* **Monthly rule review:** Any rule with >90% false positive rate is reviewed and tuned
* **Annual red team assessment:** Full adversary simulation targeting the supply chain and OT systems
* **Threat intelligence feedback loop:** When a breach at another logistics company is disclosed, check whether GlobalPort's controls would have detected the same TTPs
