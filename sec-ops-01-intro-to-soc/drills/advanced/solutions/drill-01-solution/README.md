# Drill 01 (Advanced) — Solution: SOC Architecture Design

## Sample Solution for EuroPayments GmbH

---

### 1. SOC Type Recommendation: Hybrid SOC

**Recommendation: Co-managed / Hybrid SOC**

Given EuroPayments' profile, a pure internal SOC is not feasible in 6 months with limited staff on hand.
A fully outsourced MSSP loses the compliance control required for PCI-DSS and DORA (which require direct accountability).
A **hybrid model** — where EuroPayments manages compliance-critical detection internally but augments with MSSP coverage for 24/7 operations — is the optimal choice.

**Year 1 Structure:**

* **Internal team (Frankfurt HQ)**: 3 FTEs — SOC Manager + 2 senior analysts (Tier 2/3). Own the SIEM, build detection rules, handle compliance reporting, manage the MSSP relationship.
* **MSSP coverage**: 24/7 Tier 1 alert monitoring. SLA: 15-minute MTTD for Critical, 1-hour for High.

**Justification:**

* €1.2M budget is insufficient for a full 24/7 internal SOC (requires 8-10 FTEs plus tooling).
* DORA's 4-hour reporting obligation means 24/7 coverage is mandatory — MSSP provides this.
* PCI-DSS compliance is maintained because cardholder data environment (CDE) is monitored by the internal team.
* After Year 2, once processes mature, the MSSP relationship can be reduced and more internal capacity built.

---

### 2. Technology Stack

| Category | Tool | Type | Est. Cost/Year | Justification |
|----------|------|------|----------------|---------------|
| SIEM | Microsoft Sentinel | Commercial (SaaS) | €80-120K | Azure-native, minimal infrastructure, strong compliance reporting |
| SOAR | Microsoft Sentinel Playbooks | Included in Sentinel | — | Native integration, sufficient for Year 1 automation |
| EDR | Microsoft Defender for Endpoint | Commercial | €60K | Already in M365 stack likely; PCI-DSS compliant; excellent ransomware protection |
| Network Monitoring | Zeek + Elastic Stack | Open source | €15K (infrastructure) | Deep packet inspection, protocol analysis, CDE network visibility |
| Threat Intel | MISP (self-hosted) + Commercial feed | Hybrid | €20K | MISP is free; add 1-2 commercial feeds for FinTech-specific IOCs |
| Ticketing | Jira Service Management | Commercial | €15K | Integrates with Sentinel; good audit trail for DORA reporting |

**Total tooling budget estimate:** €200-250K/year (within budget for Year 1)

---

### 3. Staffing Model

**Year 1 Internal Staff: 4 FTEs**

| Role | Count | Shift | Salary (est.) |
|------|-------|-------|---------------|
| SOC Manager | 1 | Business hours + on-call | €90K |
| Senior Analyst (Tier 2/3) | 2 | Business hours + on-call rotation | €70K each |
| Junior Analyst (Tier 1) | 1 | Business hours | €45K |

**MSSP**: Handles 24/7 Tier 1 coverage — estimated €250-350K/year contract.

**Training Budget**: €40K/year (CompTIA Security+, Splunk Core Certified User, SANS SOC courses)

---

### 4. Top 10 Detection Use Cases

1. **Unauthorized access to CDE** (PCI-DSS req. 10.2): Any access to cardholder data systems outside authorized hours or from non-approved IPs.
1. **Brute force on payment systems**: Multiple failed logins against CDE hosts.
1. **Ransomware indicators**: Rapid mass file modification/encryption, shadow copy deletion.
1. **Data exfiltration**: Large outbound transfers from CDE systems.
1. **Privileged account misuse**: Admin account used outside business hours or from unusual locations.
1. **Lateral movement**: Internal host scanning, pass-the-hash, remote service exploitation.
1. **Phishing email delivery**: Attachments with double extensions or macros, malicious URLs.
1. **Malware detection**: EDR alerts requiring correlation and response.
1. **Third-party vendor anomalies**: Unusual activity from partner VPN connections (PCI-DSS req. 12.8).
1. **GDPR breach indicators**: Personal data directory access spikes, bulk export of customer records.

---

### 5. Escalation Matrix

| Severity | Response Time | Escalation Path | DORA Reporting |
|----------|---------------|-----------------|----------------|
| Critical | 15 min (MSSP) → 30 min (internal) | MSSP → Internal Tier 2 → SOC Manager → CISO → Legal | Yes, if ICT incident — 4hr initial report |
| High | 1 hour | MSSP → Internal Tier 2 → SOC Manager | Yes, if significant |
| Medium | 4 hours | MSSP triage → Internal review next business day | No |
| Low | 24 hours | MSSP close or defer to weekly review | No |

**Playbooks to develop first:**

1. **Ransomware Response**: Isolation, backup verification, DORA reporting, communication.
1. **Payment Card Data Breach**: PCI-DSS breach notification procedure (within 24 hrs to card brands).
1. **Phishing Campaign**: Email quarantine, IOC extraction, affected user notification, password reset.
