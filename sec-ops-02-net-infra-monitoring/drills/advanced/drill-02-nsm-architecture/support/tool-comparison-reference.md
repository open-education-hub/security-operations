# NSM Tool Comparison Reference
# ================================
# For use with Drill 02 (Advanced): Design a Complete NSM Architecture
#
# Use this table to help select appropriate tools for your architecture design.
# All cost estimates are approximate Year-1 figures (USD/EUR).
#
# ─────────────────────────────────────────────────────────────────────────────

## PACKET CAPTURE / NSM SENSORS

| Tool          | Type       | Use Case                          | Cost        | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| tcpdump       | CLI PCAP   | Raw packet capture to file        | Free        | Standard on all Linux; no analysis capability |
| tshark        | CLI PCAP   | Packet analysis (Wireshark CLI)   | Free        | Best for scripted analysis |
| Zeek          | NSM        | Full NSM — generates structured logs | Free     | Industry standard; excellent for long-term |
| Suricata      | IDS/IPS    | Signature-based detection + PCAP  | Free        | Can run inline (IPS) or passive (IDS) |
| Snort 3       | IDS/IPS    | Signature-based detection         | Free (rules extra) | Cisco-supported; large community |
| NetworkMiner  | PCAP anal. | File/credential extraction        | Free/€900   | Good for incident response |
| Arkime (Moloch) | Full PCAP  | Search full packet capture at scale | Free     | Excellent for multi-TB PCAP archives |
| Security Onion | NSM suite | Zeek + Suricata + SIEM bundled    | Free        | Pre-integrated SOC platform |


## FLOW COLLECTION

| Tool          | Type       | Use Case                          | Cost        | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| nfcapd/nfdump | NetFlow v5/v9 | Collect and query NetFlow      | Free        | Classic, lightweight, well-supported |
| ntopng        | NetFlow/sFlow | Flow analysis + web UI         | Free–€3,000 | Good visualisation; Enterprise version for alerts |
| ElastiFlow    | NetFlow/IPFIX | Ship flows to Elasticsearch    | Free–$6,000 | Easy SIEM integration |
| pmacct        | sFlow/NetFlow | Multi-protocol flow collector  | Free        | Very configurable; scripting-friendly |
| SolarWinds NTA | NetFlow  | Enterprise flow analysis          | ~$3,000/yr  | Commercial; good dashboards |


## SIEM PLATFORMS

| Tool          | Type       | Use Case                          | Cost (yr1)  | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| Elastic SIEM  | Self-hosted| Full-featured SIEM (Kibana + ES)  | ~€0–€15,000 | Open source core; free for self-hosted |
| Wazuh         | Self-hosted| SIEM + EDR + FIM + compliance     | Free + support | Open source; active community |
| Splunk Enterprise | Self-hosted | Powerful search + alerting  | ~€20,000/yr | Expensive but industry-leading search |
| Splunk Free   | Self-hosted | Limited SIEM (500 MB/day)        | Free        | ONLY for small environments |
| IBM QRadar    | Commercial | Enterprise SIEM                   | ~€30,000/yr | Complex but powerful; EPS-based pricing |
| Microsoft Sentinel | Cloud | Azure-native SIEM              | ~€8,000/yr  | Excellent for Microsoft-heavy environments |
| Graylog       | Self-hosted | Log management + alerting        | Free–€5,000 | Good UI; less security-focused than others |
| Humio/LogScale | Cloud/self | Fast log search                   | ~€10,000/yr | CrowdStrike-owned; excellent performance |


## ENDPOINT DETECTION AND RESPONSE (EDR)

| Tool          | Type       | Use Case                          | Cost (yr1)  | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| Wazuh Agent   | Open source| FIM + audit + SIEM integration    | Free        | Good for Linux/Windows; no EDR sophistication |
| Velociraptor  | Open source| Hunt + EDR + forensics            | Free        | Powerful for threat hunting |
| CrowdStrike Falcon | SaaS  | Full enterprise EDR              | ~€25/endpoint/mo | Industry-leading detection |
| SentinelOne   | SaaS       | EDR + XDR                         | ~€20/endpoint/mo | Strong autonomous response |
| Microsoft Defender | Built-in | Windows EDR                 | Included in M365 E5 | Excellent for Microsoft environments |
| OSQuery       | Open source| Endpoint visibility (SQL-like)    | Free        | Query endpoint state in real-time |


## THREAT INTELLIGENCE PLATFORMS

| Tool          | Type       | Use Case                          | Cost        | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| MISP          | Open source| TI sharing + IOC management       | Free        | Industry standard for TI sharing |
| OpenCTI       | Open source| Advanced TI with ATT&CK mapping   | Free        | More complex than MISP but more powerful |
| AlienVault OTX | Cloud     | Free community TI feeds           | Free        | Good starting point for IOCs |
| Recorded Future | Commercial | Premium TI + SIEM integration  | ~€40,000/yr | Excellent; expensive |
| VirusTotal Enterprise | Cloud | Hash/URL/domain lookups       | ~€10,000/yr | Essential for malware investigation |


## OT/ICS-SPECIFIC MONITORING

| Tool          | Type       | Use Case                          | Cost        | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| Claroty       | Commercial | OT network discovery + monitoring | ~€30,000/yr | Market leader for ICS security |
| Nozomi Networks | Commercial | OT/IoT visibility + threat detect| ~€25,000/yr | Strong AI-based anomaly detection |
| Dragos        | Commercial | ICS threat intelligence + monitoring | ~€50,000/yr | Best ICS threat intel; industrial protocols |
| Zeek + ICS pkgs | Open source | Modbus/DNP3/PROFINET dissection | Free       | Passive only; needs Zeek expertise |
| SecurityOnion | Open source | Zeek + Suricata for OT networks   | Free        | Can be tuned for OT with care |
| Claroty Edge  | Hardware   | Passive OT sensor (on-prem)       | ~€5,000/site | Plug-in appliance; Claroty subscription needed |


## INCIDENT RESPONSE AND FORENSICS

| Tool          | Type       | Use Case                          | Cost        | Notes |
|---------------|------------|-----------------------------------|-------------|-------|
| TheHive       | Open source| Incident case management          | Free        | Integrates with MISP and Cortex |
| GRR           | Open source| Remote live forensics             | Free        | Google-developed; powerful |
| Velociraptor  | Open source| Hunt + collect endpoint artefacts | Free        | Excellent for IR teams |
| KAPE          | Free       | Collect forensic artefacts         | Free        | Windows-focused; very fast |
| Autopsy/Sleuth| Open source| Disk forensics                    | Free        | Standard for disk image analysis |
| Volatility    | Open source| Memory forensics                  | Free        | Best for malware in memory |


## MITRE ATT&CK COVERAGE BY DATA SOURCE

| ATT&CK Technique                | Zeek | Suricata | NetFlow | SIEM | EDR |
|---------------------------------|------|----------|---------|------|-----|
| T1190 Exploit public-facing     |  ✓   |    ✓     |         |  ✓   |  ✓  |
| T1071.004 DNS C2                |  ✓   |    ✓     |         |  ✓   |     |
| T1021.002 SMB lateral movement  |  ✓   |    ✓     |    ✓    |  ✓   |  ✓  |
| T1048 Exfiltration alt protocol |  ✓   |          |    ✓    |  ✓   |  ✓  |
| T1566.001 Spearphishing attach. |  ✓   |    ✓     |         |  ✓   |  ✓  |
| T1078 Valid accounts (VPN)      |      |          |         |  ✓   |  ✓  |
| T1486 Ransomware encryption     |  ✓   |          |    ✓    |  ✓   |  ✓  |
| T1195 Supply chain compromise   |  ✓   |    ✓     |         |  ✓   |  ✓  |


## SENSOR PLACEMENT DECISION GUIDE

+---------------------------+-----------------------------+------------------+
| Location                  | Best connection method      | What you can see |
+---------------------------+-----------------------------+------------------+
| Internet uplink           | Hardware TAP (preferred)    | All ext. traffic |
|                           | SPAN on border router       | (may drop pkts)  |
+---------------------------+-----------------------------+------------------+
| Core switch (LAN)         | SPAN port (monitor port)    | All VLAN traffic |
|                           | Hardware TAP on trunk link  | on that switch   |
+---------------------------+-----------------------------+------------------+
| Server VLAN               | SPAN on server VLAN port    | N/S + E/W to svr |
+---------------------------+-----------------------------+------------------+
| Wi-Fi                     | Mirror on wireless AP/ctrlr | All wireless     |
|                           | SPAN on uplink to WLC       | traffic          |
+---------------------------+-----------------------------+------------------+
| OT/PLC network            | Hardware TAP (passive only!)| OT protocols     |
|                           | NEVER use SPAN if it could  | (Modbus, DNP3)   |
|                           | disrupt OT device           |                  |
+---------------------------+-----------------------------+------------------+
| Between firewall zones    | Hardware TAP on inter-zone  | Inter-zone flows |
|                           | link                        |                  |
+---------------------------+-----------------------------+------------------+


## STORAGE ESTIMATES FOR REFERENCE

| Data Type         | Rate                    | 1 Month      | 1 Year       |
|-------------------|-------------------------|--------------|--------------|
| Full PCAP (1 Gbps)| ~450 GB/hr avg 50% util | ~162 TB      | ~1.9 PB      |
| Full PCAP (100Mbps)| ~45 GB/hr              | ~16 TB       | ~190 TB      |
| Zeek logs         | ~0.5 GB/hr / 100 Mbps   | ~180 GB      | ~2.2 TB      |
| Suricata alerts   | ~1 MB/hr (typical)      | ~720 MB      | ~8.7 GB      |
| NetFlow records   | ~50 MB/hr / 1 Gbps      | ~36 GB       | ~432 GB      |
| Firewall syslog   | ~10 MB/hr               | ~7.2 GB      | ~87 GB       |
| Endpoint (EDR)    | ~100 MB/day / endpoint  | ~3 GB/ep     | ~36 GB/ep    |
