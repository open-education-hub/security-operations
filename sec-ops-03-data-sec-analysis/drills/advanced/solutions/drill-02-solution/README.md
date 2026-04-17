# Solution: Drill 02 (Advanced) — Data Lake Security Architecture

## Task 1: Log Source Inventory (Reference)

| Source | Format | Est. Volume | Collection Method | Priority | Retention |
|--------|--------|-------------|-------------------|----------|-----------|
| Windows Security Events (2000 endpoints) | XML/JSON | ~1GB/day | Splunk UF / Winlogbeat | Critical | 7 years (SOX) |
| Sysmon Events (2000 endpoints) | XML/JSON | ~2GB/day | Splunk UF / Winlogbeat | Critical | 12 months |
| Linux auditd (200 servers) | text/JSON | ~400MB/day | Filebeat / Fluent Bit | Critical | 7 years (SOX for prod) |
| Palo Alto NGFW (3 firewalls) | CEF/Syslog | ~1.2GB/day | Syslog → Logstash | Critical | 12 months |
| AWS CloudTrail (all regions) | JSON → S3 | ~50MB/day | S3 event triggers | Critical | 7 years (SOX) |
| AWS VPC Flow Logs | text/JSON | ~500MB/day | CloudWatch → Kinesis | High | 12 months |
| Web Proxy (Zscaler) | JSON/LEEF | ~1GB/day | API pull / webhook | High | 12 months |
| Active Directory / Domain Controllers | WinEventLog | ~300MB/day | Splunk UF | Critical | 7 years (SOX) |
| M365 Audit Logs | JSON API | ~200MB/day | Microsoft Graph API pull | High | 12 months |
| Azure AD Sign-in Logs | JSON | ~100MB/day | Azure Monitor → Event Hub | Critical | 12 months |
| Palo Alto Cortex XDR (EDR) | JSON API | ~500MB/day | API pull | High | 12 months |
| Web Application Firewall (AWS WAF) | JSON | ~100MB/day | CloudWatch → Kinesis | Medium | 12 months |
| DNS Resolver Logs (Infoblox) | text | ~200MB/day | Syslog | High | 6 months |
| VPN (Cisco AnyConnect) | Syslog | ~50MB/day | Syslog | Critical | 7 years (SOX) |
| Database Audit Logs (Oracle, SQL Server) | text/JSON | ~100MB/day | Agent or JDBC | High (PCI) | 7 years (SOX) |
| Email Gateway (Proofpoint) | JSON | ~50MB/day | API pull | High | 12 months |
| S3 Access Logs (AWS) | text | ~200MB/day | S3 server access logging | High (PCI) | 1 year |

**Total estimated raw volume: ~8.1 GB/day**

---

## Task 2: Architecture (Reference Design)

### Architecture Overview

```text
COLLECTION LAYER (Regional)
┌──────────────────────────────────────────────────────────────────────┐
│  NYC Office (Primary)      London Office         Singapore Office    │
│  ┌─────────────────┐       ┌──────────────┐      ┌──────────────┐   │
│  │ Splunk UF        │       │ Splunk UF    │      │ Splunk UF    │   │
│  │ (Windows/Linux)  │       │              │      │              │   │
│  │ rsyslog (NGFW)   │       │ rsyslog      │      │ rsyslog      │   │
│  └────────┬─────────┘       └──────┬───────┘      └──────┬───────┘  │
│           │                        │                      │          │
│           │    TLS/9997            │  TLS/9997            │          │
└───────────┼────────────────────────┼──────────────────────┼──────────┘
            │                        │                      │
            ▼                        ▼                      ▼
NORMALIZATION LAYER
┌──────────────────────────────────────────────────────────────────────┐
│  Logstash Cluster (3 nodes, high availability)                       │
│  - Input: Splunk UF (TCP 5514), syslog (UDP/TCP 514/6514)           │
│  - Input: API pollers (CloudTrail, M365, Azure AD, Proofpoint)       │
│  - Filters: grok, CEF parser, JSON, GeoIP, mutate (ECS mapping)     │
│  - Output: Elasticsearch (security-*), Kafka (raw backup stream)    │
└──────────────────────────────────────────────────────────────────────┘
            │                    │
            ▼                    ▼
STORAGE LAYER                   MESSAGE QUEUE
┌───────────────────────┐       ┌────────────────┐
│ HOT TIER (0-90 days)  │       │ Kafka / Kinesis │
│ Elasticsearch 8.x     │       │ Raw event       │
│ 3-node cluster        │       │ buffer (24h)    │
│ SSD, fully indexed    │       └────────────────┘
│ Cost: ~$3,000/month   │
└───────────┬───────────┘
            │ ILM Policy
            ▼
┌───────────────────────┐
│ WARM TIER (90d-12mo)  │
│ Elasticsearch         │
│ HDD nodes, read-only  │
│ Cost: ~$800/month     │
└───────────┬───────────┘
            │ ILM Policy
            ▼
┌───────────────────────┐
│ COLD ARCHIVE (1y-7y)  │
│ AWS S3 Standard-IA    │
│ + Glacier (>2yr)      │
│ Cost: ~$200/month     │
└───────────────────────┘

ANALYSIS LAYER
┌──────────────────────────────────────────────────────────────────────┐
│ Elastic Security / SIEM                                               │
│ - Detection rules (Sigma → KQL conversion)                           │
│ - Timeline investigation                                              │
│ - Case management                                                     │
│                                                                       │
│ SOC Access:                                                           │
│ - NYC: Primary SOC (Tier 2/3), all data                              │
│ - London: Regional Kibana dashboards (GDPR-compliant data views)     │
│ - Singapore: Regional dashboards (APAC-scoped indexes)               │
│                                                                       │
│ TI Integration: MISP → Elastic TI enrichment → alert context         │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Logstash for normalization** — Elastic Common Schema (ECS) adopted as the standard. All field names mapped to ECS at ingest time, enabling cross-source correlation in Elastic SIEM without field aliasing.

1. **Kafka buffer** — Raw events are written to Kafka before processing. This provides replay capability if a Logstash filter bug corrupts data, and decouples collection from storage.

1. **Elasticsearch ILM** — Index Lifecycle Management automatically moves indices: hot (0-90d, SSD) → warm (90d-12mo, HDD) → cold/frozen (S3 Searchable Snapshots) → delete.

1. **Regional indexes** — Separate Elasticsearch data streams by region prefix (`nyc-security-*`, `lon-security-*`, `sgp-security-*`) allows GDPR-compliant access controls per region.

1. **PCI-DSS scope** — Separate index/data stream for CDE-scoped sources: `pci-security-*`. Access restricted to PCI compliance team.

---

## Task 3: Storage Calculations

**Daily volumes:**

* Windows endpoints: 2000 × 500KB = 1,000MB = ~1GB/day
* Linux servers: 200 × 200KB = 40MB/day
* Firewalls: 3 × 400MB = 1.2GB/day (compressed)
* CloudTrail: 50MB/day
* Web proxy: 1GB/day
* All other sources: ~1GB/day
* **Total compressed: ~4.3GB/day**

**Calculations:**

| Tier | Duration | Volume | Storage Cost |
|------|----------|--------|-------------|
| Hot (Elasticsearch SSD) | 90 days | 4.3 × 90 = 387GB | ~$45/month (S3 + compute) |
| Warm (Elasticsearch HDD) | 9 months (270 days) | 4.3 × 270 = 1,161GB ≈ 1.1TB | ~$25/month |
| Cold S3 Standard-IA (1-2yr) | 1 year | 4.3 × 365 = 1,570GB ≈ 1.5TB | $35/month ($0.023/GB) |
| Glacier (2-7yr) | 5 years | 4.3 × 365 × 5 = 7.8TB | $31/month ($0.004/GB) |

**Total monthly storage cost: ~$136/month** — well within budget (this is storage cost only; compute/licensing adds significantly more).

Note: In a real enterprise, log volume estimates often run 2-5× higher than initial estimates once all sources are connected.
Budget $500-1000/month for storage.

---

## Task 4: Compliance Mapping

**SOX (7-year retention):**

* In-scope: AD/DC logs, VPN logs, privileged access logs, change management logs, financial application logs, AWS CloudTrail (financial systems)
* Log integrity: Write-once S3 Object Lock (Compliance mode) prevents deletion or modification even by S3 admin. SHA256 hash of each log batch stored in separate immutable DynamoDB table.

**PCI-DSS:**

* CDE scope: Payment processing servers, card vault (HSM), payment gateway, databases with card data
* 3-month online = hot tier covers this automatically
* 1-year available = warm tier covers this
* Separate `pci-security-*` index with access controls

**GDPR:**

* Personal data in logs: usernames (AD), email addresses (proxy/email logs), VPN IPs (if static)
* Data minimization: After 90 days in hot tier, pseudonymize usernames and email addresses before moving to warm tier. Replace `username@acme.com` with SHA256 hash of the username.
* Right to erasure: Maintain a mapping table; when erasure is requested, delete the mapping so the hashed identifier can no longer be linked. This satisfies GDPR without destroying the log integrity.

---

## Task 5: Top 10 Detection Rules for ACME Financial

| Priority | Rule Name | Data Source | MITRE | Justification |
|----------|-----------|-------------|-------|---------------|
| 1 | DCSync Attack | Windows Event 4662 (DC) | T1003.006 | Full domain compromise; financial sector is prime target |
| 2 | Kerberoasting | Windows Event 4769 | T1558.003 | Widely-used for credential access in AD environments |
| 3 | CloudTrail: IAM Privilege Escalation | CloudTrail | T1078.004 | Cloud account takeover is primary attack vector for financial firms |
| 4 | Large S3 Data Access | CloudTrail data events | T1530 | Data exfiltration from cloud storage; PCI-DSS concern |
| 5 | Office Macro → Shell Execution | Sysmon Event 1 | T1566.001, T1059 | Ransomware initial access; most common attack against financial sector |
| 6 | Brute Force + Successful Logon | AD Security Events | T1110 | Credential stuffing; financial sector accounts are highly targeted |
| 7 | Impossible Travel | VPN + Azure AD logs | T1078 | Account takeover indicator; critical for remote work environments |
| 8 | M365 Forwarding Rules Created | M365 Audit | T1114.003 | Business email compromise (BEC); huge financial sector risk |
| 9 | Mass File Renaming | Sysmon Event 11 | T1486 | Ransomware encryption indicator; financial sector high-value target |
| 10 | Anomalous Database Queries | DB Audit Logs | T1213 | Insider threat / account compromise accessing financial data |
