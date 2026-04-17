# Drill 02 Solution (Advanced): Correlation Architecture Design

---

## Part 1 Solution: Architecture Design

### Task 1.1: Log Ingestion and Normalization Pipeline

**Schema Choice: ECS (Elastic Common Schema)**

Rationale:

* Existing Splunk ES investment can be migrated to Elastic Stack, reducing licensing costs
* ECS has the broadest community rule coverage (Elastic Security, Sigma)
* AWS CloudWatch, GuardDuty, and Azure Monitor all have ECS integration modules
* ECS is open source, avoiding vendor lock-in

**Pipeline Design:**

```text
┌─────────────────────────────────────────────────────────────────────┐
│                    LOG INGESTION PIPELINE                           │
├─────────────┬───────────────┬─────────────────┬────────────────────┤
│ LAYER 1     │ COLLECTION    │ NORMALIZATION   │ DESTINATION        │
├─────────────┼───────────────┼─────────────────┼────────────────────┤
│ Endpoints   │ Elastic Agent │ Built-in        │ Elasticsearch      │
│ (3000 hosts)│ (lightweight) │ integration     │ Hot tier           │
├─────────────┼───────────────┼─────────────────┼────────────────────┤
│ AWS         │ Kinesis       │ Lambda          │ Elasticsearch      │
│ (CloudTrail,│ Data Firehose │ (ECS transform) │ via ES Service     │
│  GuardDuty) │               │                 │                    │
├─────────────┼───────────────┼─────────────────┼────────────────────┤
│ Azure       │ Event Hub     │ Logstash        │ Elasticsearch      │
│ (AD, Defdr) │               │ (ECS pipeline)  │                    │
├─────────────┼───────────────┼─────────────────┼────────────────────┤
│ Firewalls/  │ Syslog UDP/   │ Logstash        │ Elasticsearch      │
│ Network     │ 514, TCP/601  │ (Grok + ECS)    │                    │
├─────────────┼───────────────┼─────────────────┼────────────────────┤
│ Legacy Apps │ Syslog        │ Vector          │ S3 + Elasticsearch │
│ (mainframe) │ (RFC 5424)    │ (VRL)           │ (filtered subset)  │
└─────────────┴───────────────┴─────────────────┴────────────────────┘
```

**Answers to design questions:**

1. **Normalization schema: ECS** (see rationale above)

1. **Where normalization happens**: At the **collection layer** (Elastic Agent for endpoints, Lambda for AWS, Logstash for network). Do NOT normalize in the SIEM — normalizing at ingest reduces SIEM processing load and enables reindexing without re-collection.

1. **7-year retention at 500 GB/day**:
   * Days 0–30: Elasticsearch hot tier (SSD, 3-shard, 1-replica) — 15 TB
   * Days 31–90: Elasticsearch warm tier (HDD, 1-shard) — 45 TB
   * Days 91–365: Elasticsearch cold tier (frozen indices, searchable) — 275 TB
   * Year 2–7: S3 Glacier Instant Retrieval + Elasticsearch searchable snapshots
   * Compliance queries: Elasticsearch snapshot search (no need to restore)

1. **AWS strategy**: Deploy Elastic Agent in EC2 and ECS/Fargate. Use Kinesis Data Firehose for CloudTrail, VPC Flow Logs, GuardDuty findings. Lambda transforms to ECS before forwarding. Enables near-real-time detection with AWS-native delivery.

### Task 1.2: Three-Tier Detection Architecture

**Tier 1: SIEM — Elastic SIEM with Elastic Security**

* Detection: Sigma-based detection rules compiled to Elastic EQL/KQL
* Rule types: Single-event (IOC), threshold (brute force, scan), sequence (lateral movement)
* Alert routing: P1/P2 → immediate analyst page; P3/P4 → analyst queue
* Expected volume: 150 alerts/day (tuned, ≤10% FP rate)
* Coverage: Known TTPs, compliance detections (PCI-DSS required)

**Tier 2: UEBA — Elastic SIEM + ML Jobs**

* Detection: Machine learning anomaly detection (Elastic ML)
* Models: Rare process, unusual network destination, high bytes out, login time anomaly
* Alert routing: Risk score accumulated → entity risk score → alert at threshold 70+
* Expected volume: 30 alerts/day (ML anomaly aggregated to entity risk)
* Coverage: Account compromise, insider threat, credential abuse

**Tier 3: EDR/XDR — CrowdStrike Falcon (already deployed)**

* Detection: CrowdStrike's ML-based endpoint detections + custom IOA rules
* Alert routing: Critical detections → auto-isolate + page on-call; others → Tier 1 SIEM
* Expected volume: 20 alerts/day (high-fidelity endpoint)
* Coverage: Malware execution, memory injection, ransomware pre-deployment

**Total target: 200 alerts/day → 180 actionable → ≤15/analyst/shift**

---

## Part 2 Solution: Detection Priority Planning

### Task 2.1: Ransomware Coverage Plan

| Rank | Technique | Data Source | Rule Type | Priority | Gap to Close |
|------|-----------|------------|-----------|----------|-------------|
| 1 | T1078 Valid Accounts | Auth logs (Windows 4624/4625, AWS CloudTrail, VPN) | Threshold + UEBA behavioral | HIGH | Implement impossible travel + after-hours login + UEBA baseline |
| 2 | T1566.001 Phishing Attachment | Email gateway (O365), EDR (Office process spawning) | Single-event (Office→shell spawn), sequence | HIGH | Deploy Elastic rule: office_child_process |
| 3 | T1059.001 PowerShell | Sysmon EID 1 + PowerShell ScriptBlock (EID 4104) | Single-event (encoded cmd, download cradle), threshold | HIGH | Enable PSScriptBlock logging (EID 4104) - currently disabled |
| 4 | T1490 VSS Deletion | Sysmon EID 1 (vssadmin, wmic, bcdedit, wbadmin) | Single-event (immediate alert) | CRITICAL | Already have rule; validate it works with Shadow Copy WMI method |
| 5 | T1486 Data Encrypted | Sysmon EID 2/11 (file creation burst), EDR | Threshold (file modification rate), EDR ML | HIGH | EDR handles; add Sysmon file rename rate rule as backup |
| 6 | T1021.002 SMB Shares | Network flow (port 445), Sysmon EID 3 | Threshold (SMB to many hosts) + sequence (after auth) | HIGH | MISSING: No current SMB lateral movement detection. Build now. |
| 7 | T1003 Credential Dump | Sysmon EID 10 (lsass access), EID 1 (procdump, mimikatz) | Single-event (lsass access from non-AV), threshold | HIGH | Rule exists; tune AV exclusions, add LSASS handle count monitoring |
| 8 | T1053.005 Scheduled Task | Windows Security 4698/4702, Sysmon EID 1 | Single-event (unusual creator or path) | MEDIUM | Missing EID 4698 collection from servers; add data source |
| 9 | T1547.001 Registry Autorun | Sysmon EID 13 (registry set) | Single-event (run key in non-standard path) | MEDIUM | Sysmon EID 13 enabled but rule not yet written |
| 10 | T1048 Exfil over Web | Proxy logs (Bluecoat), cloud flow logs | Threshold (large upload to cloud storage) | MEDIUM | Proxy logs not yet in SIEM; ingest needed first |

**Key gaps to close immediately (this sprint):**

1. T1021.002 SMB detection (rank 6 — completely missing)
1. T1059.001 PSScriptBlock logging enable (rank 3 — improves fidelity significantly)
1. T1048 proxy log ingestion (rank 10 — data source missing entirely)

### Task 2.2: MTTD Achievement Design

**Scenario A: Compromised Credential (MTTD ≤ 15 min)**

```text
Detection Chain:

Rule A1 (fires T+0 to T+2 min after login):
  "Login from previously unseen country for user X"
  Trigger: auth.success AND source.geo.country NOT IN user_baseline_countries
  Output: P2 alert → analyst queue
  Implementation: Elasticsearch ML rare_source_ip_for_user + ECS geo enrichment

Rule A2 (fires T+0 immediately if TI match):
  "Login from known-malicious IP or Tor exit node"
  Trigger: auth.success AND source.ip IN threat_intel_feed
  Output: P1 alert → immediate page

Rule A3 (fires if credential stuffing preceded):
  "Successful login following credential stuffing from same IP"
  Trigger: auth.success where auth.failure count from same IP in last 30m > 5
  Output: P1 alert → immediate page

Response Playbook (15-min target):
  T+0:  Alert fires → auto-create ticket → page on-call analyst
  T+5:  Analyst reviews: confirm foreign IP, check recent user activity
  T+10: Analyst confirms compromise: disable account, force password reset
  T+15: Account contained; begin investigation

Additional controls for MTTD:
  - PagerDuty integration for P1 alerts (5-second page latency)
  - Pre-built playbook in SOAR (Elastic SOAR or Splunk SOAR)
  - Pre-authorized response actions: account disable without manager approval
    (approved by CISO for P1 credential compromise alerts)
```

**Scenario B: Ransomware Pre-Deployment (MTTD ≤ 30 min)**

```text
Detection Chain:

Rule B1 (fires T+5 min after step 1):
  "Discovery commands on domain controller"
  Trigger: process.name IN (net.exe, whoami.exe, nltest.exe, dsquery.exe, BloodHound)
         AND host.type = "domain_controller"
  Output: P2 alert + enrichment (is this account normally on DC?)

Rule B2 (fires T+10 min - CRITICAL):
  "VSS / Shadow Copy deletion attempt"
  Trigger: process.command_line MATCHES (vssadmin delete|wmic shadowcopy delete|bcdedit /set)
  Output: P1 IMMEDIATE alert + auto-isolate host + page CISO

Correlation Rule (fires by T+10 min):
  "DC Discovery followed by VSS deletion"
  Trigger: B1 fires for host X, then B2 fires for any host in same subnet within 15 min
  Output: P1 CRITICAL - Ransomware imminent
  Auto-response: Network isolation via CrowdStrike, disable implicated accounts

Goal achieved:
  T=0m:  Initial access
  T=5m:  Rule B1 fires → P2 ticket created
  T=8m:  Analyst reviews B1, sees DC + unusual account → escalates to P1
  T=10m: Rule B2 fires → auto-isolation triggered (MTTD = 10 min)
  T=15m: Analyst confirms; ransomware blocked before deployment
```

---

## Part 3 Solution: Rule Governance

### Task 3.1: Rule Lifecycle State Machine

```text
                    ┌──────────────────────────────────────────────┐
                    │              RULE LIFECYCLE                  │
                    └──────────────────────────────────────────────┘

[INTAKE]                [DEVELOPMENT]           [VALIDATION]
  │                        │                        │
Proposal                 Author                  QA Testing
(threat intel,           writes Sigma ──────►  TP/TN test
purple team,             + test cases            CI pipeline
ISAC feed)                                        │
  │                                           Peer review
  ▼                                           (2nd analyst)
Rule backlog                                      │
  │                                               ▼
  ├─ Accepted?──► [DEVELOPMENT]          All tests pass?
  └─ Rejected ──► Documented/deferred         │
                                              YES
                                               │
                                               ▼
                                    [STAGING DEPLOYMENT]
                                    Silent mode (no alerts)
                                    Compare vs real traffic
                                    7-day observation window
                                               │
                                    FP rate < 20%?
                                               │
                                              YES
                                               │
                                               ▼
                                    [PRODUCTION]
                                    Alert mode enabled
                                    FP rate monitored
                                    30-day review trigger
                                               │
                              ┌────────────────┤
                         FP > 30%         FP < 10%
                              │                │
                              ▼                ▼
                        [TUNING]         [STABLE]
                         Analyst          Annual review
                         tunes rule       only
                              │
                         All tests
                         still pass?
                              │
                             YES
                              ▼
                         Return to
                         [PRODUCTION]

                    [DEPRECATED]
                    ← Replaced by better rule
                    ← Threat no longer relevant
                    ← Data source decommissioned
                    Kept for 90 days (audit trail)
                    then archived
```

**Approval requirements:**

* Experimental → Staging: 1 analyst author + CI pass
* Staging → Production: Senior analyst review + security team lead sign-off
* Any filter/exclusion change: Peer review + ticket reference
* Rule retirement: Security team lead approval

### Task 3.2: Repository Structure

```text
corpbank-detections/
├── .github/
│   ├── workflows/
│   │   ├── test.yml         # Run pytest against all rules on PR
│   │   ├── compile.yml      # Sigma → SIEM format compilation
│   │   ├── coverage.yml     # Update ATT&CK Navigator layer
│   │   └── deploy.yml       # Deploy to SIEM on merge to main
│   └── PULL_REQUEST_TEMPLATE.md
│
├── rules/
│   ├── by_tactic/
│   │   ├── initial_access/
│   │   ├── execution/
│   │   ├── persistence/
│   │   ├── privilege_escalation/
│   │   ├── defense_evasion/
│   │   ├── credential_access/
│   │   ├── discovery/
│   │   ├── lateral_movement/
│   │   ├── collection/
│   │   ├── exfiltration/
│   │   └── command_and_control/
│   └── by_platform/         # Symlinks to by_tactic for cross-reference
│
├── tests/
│   ├── fixtures/            # Sample events (NDJSON)
│   │   ├── true_positives/
│   │   └── true_negatives/
│   ├── conftest.py
│   └── test_rules.py
│
├── compiled/                # Auto-generated by CI
│   ├── elastic/
│   ├── splunk/
│   └── sentinel/
│
├── lookups/                 # Reference data
│   ├── authorized_scanners.csv
│   ├── privileged_accounts.csv
│   └── cloud_storage_domains.csv
│
├── parsers/                 # Logstash/Vector pipeline configs
│   ├── windows/
│   ├── linux/
│   └── cloud/
│
├── coverage/
│   ├── current_layer.json   # Auto-updated ATT&CK Navigator layer
│   └── generate_layer.py    # Script to build layer from rule tags
│
├── docs/
│   ├── CONTRIBUTING.md
│   ├── RULE_TEMPLATE.md
│   └── TUNING_GUIDE.md
│
└── metrics/                 # Dashboard configs for rule performance
    └── grafana_dashboard.json
```

**CI/CD pipeline (GitHub Actions):**

1. On PR: `pytest` validates all rules against fixture events
1. On PR: `sigma convert` validates syntax for all target backends
1. On merge to `main`: Auto-compile and push to SIEM staging environment
1. On tag `v*`: Deploy to production SIEM + update ATT&CK coverage layer

---

## Part 4 Solution: Capacity and Cost

### Task 4.1: Alert Volume Budget

```text
Maximum actionable alerts/shift (total):
  6 analysts × 15 alerts = 90 actionable alerts/shift
  2 shifts = 180 actionable alerts/day

Available analyst time per alert:
  480 min/shift × 70% active = 336 min active/analyst
  336 / 15 = 22 min/alert average (feasible with playbooks)

Current state analysis:
  Current alerts: 2,000/day
  TP rate: 5% → 100 true positives/day
  FP rate: 95% → 1,900 FP/day

  FPs requiring investigation time: assume analysts investigate 10% of FPs before closing
  = 190 FP investigations + 100 TP investigations = 290 investigations/day

  At 20 min each: 5,800 analyst-minutes/day needed
  Available: 6 analysts × 336 min × 2 shifts = 4,032 analyst-minutes/day

  CURRENT GAP: 1,768 analyst-minutes/day SHORT → analysts are burning out!

To achieve target:
  180 actionable/day × 20 min = 3,600 analyst-min needed
  Buffer: 4,032 - 3,600 = 432 min/day for escalations/documentation → feasible!

  Required: Reduce total alerts from 2,000 to ≤ 200/day (90% reduction)
  AND: Increase TP rate from 5% to ≥ 80% (tuning required for all existing rules)
```

### Task 4.2: Storage Cost Model

```text
Assumptions:
  Raw ingest: 500 GB/day (projected)
  After compression+normalization: 125 GB/day (4:1 ratio typical)

  Hot tier (0-30 days): 30 × 125 = 3,750 GB = 3.75 TB
    Cost: 3,750 × $0.23 = $862.50/month

  Warm tier (31-90 days): 60 × 125 = 7,500 GB = 7.5 TB
    Cost: 7,500 × $0.07 = $525/month

  Cold tier (91 days - 7 years):
    = (7 × 365 - 90) × 125 GB = 2,460 days × 125 = 307,500 GB = 307.5 TB
    (building up over 7 years; steady-state capacity = full 7yr × daily rate)
    Steady-state: 2,556 days × 125 = 319,500 GB = 319.5 TB
    Cost: 319,500 × $0.004 = $1,278/month

  Total monthly storage: $862.50 + $525 + $1,278 = $2,665.50/month
  Annual TCO (storage only): ~$32,000/year

  Additional costs:
  - Elasticsearch compute (3-node cluster): ~$2,000/month
  - Logstash/Vector processing: ~$500/month
  - AWS S3 + retrieval for cold: included in $0.004/GB estimate

  Total annual platform cost estimate: ~$92,000/year
  (vs. Splunk ES licensing at ~$200-300K/year for equivalent volume)

  Migration savings: ~$150,000/year → ROI positive in Year 1
```

---

## Part 5 Solution: Architecture Document

### Executive Summary

CorpBank's current Splunk ES deployment achieves 5% true positive rate and creates analyst burnout.
This architecture migrates to **Elastic SIEM + Elastic ML + CrowdStrike XDR** to achieve: 90% reduction in alert volume, 80%+ TP rate, MTTD ≤ 15 min for account compromise, and $150K/year cost savings vs. continuing with Splunk.

### Architecture Diagram (Data Flow)

```text
SOURCES → COLLECTION → NORMALIZATION → ENRICHMENT → DETECTION → ALERTS

Endpoints(3000) → Elastic Agent → ECS (built-in) ─────────────────────┐
AWS Workloads   → Kinesis/Lambda → ECS (Lambda)  ─────────────────────┤
Azure Workloads → Event Hub/Logstash → ECS ───────────────────────────┤
Network Devices → Syslog → Logstash+Grok → ECS ──────────────────────┤
                                                                       ▼
                                                            ELASTICSEARCH
                                                            Hot/Warm/Cold
                                                            (3-Tier Storage)
                                                                       │
                                              ┌────────────────────────┤
                                              ▼                        ▼
                                      ELASTIC SIEM               ELASTIC ML
                                      (Rule-based)           (Behavioral/UEBA)
                                              │                        │
                                              └──────────┬─────────────┘
                                                         ▼
                                                  ELASTIC SOAR
                                                 (Alert triage +
                                                  Auto-response)
                                                         │
                                         ┌───────────────┼───────────────┐
                                         ▼               ▼               ▼
                                    P1 Critical      P2 High        P3/P4 Medium/Low
                                    Auto-isolate     On-call page   Analyst queue
                                    + page CISO      + ticket       next business day
```

### Technology Choices

| Decision | Choice | Alternative Rejected | Reason |
|----------|--------|---------------------|--------|
| SIEM | Elastic Security | Continue Splunk ES | 60% cost reduction, ECS native, open rules |
| Schema | ECS | OCSF | Broader tooling adoption, existing rule ecosystem |
| EDR | Keep CrowdStrike | Replace with Elastic Defend | CrowdStrike investment not expired, best-in-class |
| UEBA | Elastic ML Jobs | Exabeam, Securonix | Avoid additional vendor, built into Elastic |
| Pipeline | Elastic Agent + Logstash | Fluentd, Vector | Elastic native integration, single vendor support |

### Detection Strategy

Tier 1 (SIEM): 100 Sigma rules covering top-20 ATT&CK techniques; ≤200 alerts/day
Tier 2 (UEBA): 15 ML anomaly jobs for entity behavior; ≤30 risk-based alerts/day
Tier 3 (EDR): CrowdStrike native ML; ≤20 endpoint alerts/day
Total: ≤250 alerts/day → tuned to ≤180 actionable (≤15/analyst/shift)

### Risks and Limitations

1. **Elastic migration risk**: 3-month transition period where both platforms run in parallel — increased cost
1. **ML cold start**: UEBA requires 30-day baselining period before producing alerts — reduced coverage initially
1. **Legacy applications**: 15% of log sources use proprietary formats requiring custom parsers
1. **Insider threat**: UEBA covers behavioral anomalies but cannot detect exfiltration by administrators with legitimate access to all data — requires DLP investment

### Roadmap

* **Month 1–3**: Pilot Elastic Security on 500 endpoints, build ECS pipelines, migrate top-10 rules from Splunk
* **Month 3–6**: Full Elastic deployment, decommission Splunk (cost savings activate), complete ATT&CK gap analysis
* **Month 6–12**: UEBA baselining and ML model tuning, achieve 60% ATT&CK coverage
* **Month 12–24**: Threat hunting program, Detection-as-Code maturity, 80% ATT&CK coverage for ransomware techniques
