# Drill 02 Solution (Intermediate): Network Monitoring Strategy — NovaCare

**Model solution — key decisions and justifications**

---

## Deliverable 1: Asset Classification — Model Solution

| Segment | Data Sensitivity | Exposure | Compliance Scope | Threat Likelihood |
|---------|-----------------|---------|-----------------|------------------|
| Site A — Clinical workstations | Critical (ePHI) | Internal | GDPR, NIS2 | High |
| Site A — Medical devices | High (patient safety) | Internal | GDPR, Medical Device Regulation | High |
| Site A — Clinical Wi-Fi | Critical (ePHI in transit) | Internal (wireless) | GDPR, NIS2 | High |
| Site A — Guest Wi-Fi | None–Low | Semi-public | GDPR | Medium |
| Site B — Clinical workstations | Critical (ePHI) | WAN-connected | GDPR, NIS2 | High |
| Site B — Medical devices | High (patient safety) | WAN-connected | GDPR, MDR | High |
| Data Centre — EHR Application Server | Critical (all ePHI) | Internet-facing (VPN) | GDPR, NIS2, 7yr audit | Critical |
| Data Centre — EHR Database | Critical (all ePHI) | Internal-only | GDPR, NIS2, 7yr audit | Critical |
| Data Centre — Active Directory | Critical (auth) | Internal | NIS2 | Critical |
| Data Centre — Internet uplink | N/A | Internet-facing | NIS2 | Critical |
| Outpatient clinics | Critical (ePHI) | Internet (SD-WAN) | GDPR, NIS2 | Critical |
| Remote Access VPN | Critical (ePHI) | Internet | GDPR, NIS2 | High |

**Key insight:** The outpatient clinics are rated Critical threat likelihood because they have consumer-grade routers, no dedicated firewalls, and no monitoring — they are the weakest link in the network.

---

## Deliverable 2: Tool Selection — Model Solution

| Monitoring Need | Recommended Tool | Justification |
|----------------|-----------------|---------------|
| Full packet capture at internet perimeter | tcpdump + Zeek | PCAP for forensics; Zeek for structured logs. Short retention due to storage. |
| NSM sensor at DC (EHR traffic analysis) | Zeek | Structured logs for EHR protocol detection; SSL/TLS log for certificate anomalies |
| Flow-based monitoring across all sites | NetFlow (nfcapd) from firewalls | 7+ years of flow data feasible; low storage; works on limited WAN links |
| IDS/IPS at internet boundary | Suricata (inline IPS mode) | Multi-threaded, supports 500 Mbps+; compatible with Emerging Threats healthcare rules |
| Log aggregation and correlation | Wazuh or Elastic SIEM | Open source, GDPR-friendly (self-hosted); supports all log types |
| Endpoint detection at clinical workstations | Wazuh Agent | Open source EDR; file integrity monitoring for ePHI; GDPR audit log |
| Medical device network monitoring | Zeek + flow records only | No endpoint agents possible on medical devices; passive monitoring only |
| VPN access monitoring | Firewall VPN logs + NetFlow | Connection start/end, duration, bytes — sufficient for access auditing |
| Outpatient clinic monitoring (low budget) | FortiGate virtual appliance + syslog | Replace consumer router; syslog to central SIEM; no local storage needed |

---

## Deliverable 3: Sensor Placement — Model Solution

| Sensor ID | Location | Connection | Tool | Traffic Covered | Priority |
|-----------|---------|------------|------|----------------|---------|
| SENSOR-01 | DC internet uplink (after Palo Alto) | Hardware TAP | Zeek + Suricata | All internet-bound traffic | Critical |
| SENSOR-02 | DC EHR application server VLAN | SPAN on Nexus switch | Zeek | EHR application ↔ database traffic | Critical |
| SENSOR-03 | Site A core switch | SPAN port | Zeek (east-west) | All inter-VLAN clinical traffic | High |
| SENSOR-04 | Medical device VLAN (Site A) | SPAN on VLAN 40 | Zeek | All medical device traffic | High |
| SENSOR-05 | MPLS WAN termination (Site A) | SPAN on WAN port | NetFlow collector | Site A ↔ Site B + DC traffic | High |
| SENSOR-06 | Outpatient clinic hub (SD-WAN collector) | FortiGate appliance | Syslog + NetFlow | Clinic internet + DC traffic | Medium |
| SENSOR-07 | Remote Access VPN concentrator | Log integration | VPN logs → SIEM | VPN connection events | Medium |
| SENSOR-08 | Active Directory server | Wazuh agent | Wazuh SIEM | Auth events, AD changes | Medium |

**Notes on sensor placement choices:**

* **SENSOR-01 uses a hardware TAP** (not SPAN) because the internet uplink is a critical forensic point — no packet loss acceptable
* **SENSOR-02 is inside the DC** monitoring EHR internal traffic — this provides visibility into potential database exfiltration that perimeter sensors would miss
* **Medical device VLAN is separate** (SENSOR-04) because medical devices should never communicate with general workstations — any cross-VLAN traffic to/from medical devices is immediately suspicious

---

## Deliverable 4: Data Retention Policy — Model Solution

**Assumptions:**

* Internet uplink: 500 Mbps average; 30% utilisation = ~150 Mbps actual
* Zeek generates ~0.5 GB/hour of logs per 100 Mbps monitored
* NetFlow: ~50 MB/hour per 1 Gbps
* Total storage budget: 10 TB

| Data Type | Collection Tool | Retention | Storage Estimate | Justification |
|-----------|----------------|-----------|-----------------|---------------|
| Full PCAP (internet uplink) | tcpdump | 7 days | 150 Mbps × 3600s × 24h × 7d / 8 bits ≈ 1.1 TB | Forensic detail for recent incidents; longer not feasible |
| Full PCAP (EHR server traffic) | tcpdump | 30 days | ~50 Mbps × 30d ≈ 1.6 TB | PCI/breach evidence; lower volume than perimeter |
| Zeek logs (all sensors) | Zeek → Wazuh | 1 year | ~50 GB/month × 12 ≈ 600 GB | Connection/protocol metadata; GDPR minimisation |
| IDS/IPS alerts | Suricata → Wazuh | 7 years | ~5 GB/year ≈ 35 GB | NIS2 + 7-year audit requirement |
| NetFlow records | nfcapd | 3 years | ~10 GB/month × 36 ≈ 360 GB | Traffic baseline + anomaly history |
| Firewall logs | Syslog → Wazuh | 7 years | ~20 GB/year ≈ 140 GB | NIS2 + 7-year audit requirement |
| EHR access logs | Application logs | 7 years | ~10 GB/year ≈ 70 GB | Statutory requirement (patient record audit) |
| VPN connection logs | Syslog → Wazuh | 7 years | ~1 GB/year ≈ 7 GB | User access audit trail |

**Total: ~3.9 TB** — within the 10 TB budget, with ~6 TB headroom.

**GDPR note:** PCAP files containing patient communication data must be treated as special category data (Article 9).
Access must be logged, restricted to authorised security staff, and subject to a Data Protection Impact Assessment (DPIA).

---

## Deliverable 5: Alert Framework — Model Solution

### 5.1 Alert Tiers

| Tier | Name | Examples | Response Time | Notify | Initial Action |
|------|------|---------|---------------|--------|----------------|
| P1 | Critical | Ransomware signature; Active exfiltration >100MB; Medical device compromised; EHR database accessed from external IP | 15 minutes (24/7) | SOC + CISO + CISO + Business Continuity + On-call IT | Isolate affected system; invoke IR plan; notify legal |
| P2 | High | SSH brute force >10 attempts; Lateral movement to EHR VLAN; Outpatient clinic new external connection; Malware IOC match | 1 hour (business hours), 2 hours (off-hours) | SOC Tier 2 + IT Security Manager | Investigate source; block if confirmed; escalate to P1 if breach confirmed |
| P3 | Medium | Port scan from external; Failed authentication spike; Unusual DNS queries; New device on medical device VLAN | 4 hours | SOC Tier 1 | Log, triage, monitor for escalation |

### 5.2 Healthcare-Specific Detection Rules

1. **Medical device unexpected outbound connection:** Rule detects medical device VLANs (known IP ranges) connecting to the internet or other non-clinical VLANs. Medical devices should only talk to specific clinical systems. **Healthcare relevance:** Medical devices are high-value ransomware targets; they rarely need to talk to the internet.

1. **EHR database accessed from non-application-server IP:** Any TCP connection to the EHR database server (port 1433/5432) from an IP other than the known application server IP should alert immediately. **Healthcare relevance:** Direct database access bypasses the EHR application's access controls and audit logging.

1. **Bulk HL7 message extraction:** Alert when a single user session downloads an unusual volume of HL7 messages (patient records) compared to their historical baseline. **Healthcare relevance:** HL7 is the healthcare data exchange standard; bulk extraction = potential mass patient data breach.

1. **Authentication from unusual geography:** VPN login from a country where NovaCare has no staff. **Healthcare relevance:** Remote access to EHR systems with stolen credentials is a primary attack vector in healthcare breaches.

1. **Scanning of medical device network:** Any host performing a port scan against the medical device VLAN. **Healthcare relevance:** Attackers who compromise a workstation may attempt to reach networked infusion pumps or monitors; disrupting these could endanger patients.

---

## Deliverable 6: GDPR and Medical Privacy

### 6.1 Monitoring Architecture and GDPR

The monitoring architecture must be designed with GDPR's Article 6 "legitimate interests" basis and Articles 9/10 (special categories) in mind, since patient data may appear in captured traffic.

**Key design principles:**

* Deploy Zeek and NetFlow **in preference to full PCAP** wherever possible — these generate metadata without capturing patient data payloads
* Full PCAP should be limited to the internet uplink and EHR server segment, with strict access controls
* Implement automatic data minimisation: after 7 days, full PCAP files should be deleted unless an incident is under investigation
* A DPIA (Data Protection Impact Assessment) must be conducted before deploying monitoring in clinical networks
* Staff must be informed via the employee handbook/AUP that network monitoring occurs, what is collected, and that it is for security purposes only
* Monitoring data must not be repurposed for performance management, HR decisions, or any purpose other than security

### 6.2 SOC Staff Controls for Patient Data Access

SOC staff accessing network traffic logs that may contain patient data are acting as data processors under GDPR.
Controls required:

* **Role-based access control:** Only Tier 2+ analysts can access raw PCAP; Tier 1 sees alerts and log summaries only
* **Access logging:** Every access to PCAP files must be logged with user, timestamp, reason
* **Need-to-know principle:** Analysts may only access captures relevant to an active investigation
* **Data Processing Agreement:** SOC staff handling patient data need documented authorisation
* **Training:** All SOC staff must complete GDPR training specific to healthcare data
* **Pseudonymisation:** Where possible, anonymise patient identifiers in log summaries before Tier 1 review

### 6.3 Supporting 72-hour GDPR Breach Notification

The 72-hour clock starts when the organisation becomes "aware" of the breach.
Your monitoring strategy supports this by:

**From IDS/Suricata:** Immediate alert when known exfiltration signatures trigger → reduces time to awareness

**From Zeek files.log:** Records file hashes and MIME types of all transferred files → can confirm whether patient data was in the exfiltrated files

**From Zeek conn.log:** Exact start/end time, source/destination, bytes transferred → supports "what was taken and when" for the notification

**From EHR access logs (7-year retention):** Exactly which patient records were accessed during the intrusion → required for Article 33 notification (which categories of personal data, approximate number of records, approximate number of data subjects)

**From NetFlow:** Long-term baseline to determine if exfiltration had been occurring before the detected incident window

The notification must include: nature of the breach, categories and approximate number of individuals, contact details of DPO, likely consequences, measures taken.
Your monitoring data supplies all of this.

---

## Deliverable 7: Phased Implementation

**Phase 1 (Month 1-2): Critical risk reduction**

1. Replace outpatient clinic consumer routers with FortiGate appliances configured to send syslog to SIEM — these are the most exposed, least monitored, and cheapest to fix
1. Deploy Suricata IPS at the Data Centre internet uplink — this protects the most critical asset (EHR) immediately
1. Configure EHR application and database audit logging to the SIEM

**Rationale:** Addresses the two highest-risk areas (internet exposure at DC; blind outpatient clinics) with medium-cost, high-impact changes.

**Phase 2 (Month 3-6): NSM foundation**

1. Deploy hardware TAP and Zeek sensor at DC internet uplink
1. Deploy Zeek on SPAN port of DC core switch (EHR server traffic)
1. Configure NetFlow on all Site A and Site B switches
1. Deploy Wazuh agents on clinical workstations
1. Isolate medical device VLAN with dedicated monitoring (Zeek)

**Rationale:** Builds the core NSM capability across the most critical sites.

**Phase 3 (Month 7-12): Complete coverage and optimisation**

1. Deploy Zeek at Site A core switch (east-west monitoring)
1. Implement full PCAP with 7-day retention at internet uplink
1. Tune IDS rules based on 6 months of operational experience
1. Implement threat intelligence feeds
1. Conduct purple team exercise to validate detection capability
1. Complete GDPR DPIA and staff training

**Rationale:** Completes coverage, optimises based on real data, validates effectiveness.
