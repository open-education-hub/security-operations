# Solution Guide — Project 02: Incident Analysis

> **Instructor use only. Do not distribute to students before submission.**

---

## Attack Overview (Scenario Design)

The logs depict a 3-day attack chain:

**Day 1 (2024-03-12):**

* 09:23: Phishing email with `.xlsm` attachment sent to `j.popescu@translog.ro` (email gateway)
* 09:47: User opens attachment (no email gateway alert — sandbox missed it)
* 09:52: Macro executes `mshta.exe`, which downloads loader from `update.softcheck.net`
* 10:01: C2 beaconing begins — DNS queries to `api.softcheck.net` every 10 minutes
* 10:05: First C2 callback — firewall logs show HTTPS to `185.220.101.55:443`
* 14:30: Attacker begins local enumeration (Windows commands via C2)

**Day 2 (2024-03-13):**

* 08:15: Mimikatz-style credential access (LSASS process access in Sysmon/EDR)
* 08:22: Credentials of `admin-backup` obtained (domain admin equivalent)
* 09:10: Lateral movement via PsExec to `db-server-01` (Windows 4648 + 7045 events)
* 09:15: Attacker logs into database server with admin-backup credentials
* 10:30: Database reconnaissance — queries to `information_schema`, `SHOW TABLES`
* 14:00: Large query — SELECT all from `customers` table (45,000 records)

**Day 3 (2024-03-15):**

* 08:00: Attacker reconnects via C2
* 10:15: Exfiltration begins — 45k customer records exported via POST to `185.220.101.55`
* 16:00: Database anomaly alert fires (unusual query volume from `db-server-01`)
* 16:12: IT team isolates `db-server-01`
* Attacker dwell time: **~3 days, 6 hours**

---

## Task 1: Expected Timeline

Key events students should find (15-point scale: 1 point per correct event, up to 25):

```text
2024-03-12 09:23  | email-gw   | Phishing email to j.popescu — .xlsm attachment       | T1566.001
2024-03-12 09:52  | firewall   | HTTPS to update.softcheck.net (payload download)       | T1105
2024-03-12 10:01  | dns        | Repeated queries to api.softcheck.net (C2 domain)      | T1568
2024-03-12 10:05  | firewall   | First HTTPS beacon to 185.220.101.55:443               | T1071.001
2024-03-12 14:30  | windows    | Discovery commands: net user, net group, whoami         | T1087, T1069
2024-03-13 08:15  | windows    | lsass.exe memory access from non-system process         | T1003.001
2024-03-13 08:22  | windows    | New successful logon for admin-backup (first time)      | —
2024-03-13 09:10  | windows    | 4648 — explicit logon to db-server-01 as admin-backup   | T1021.002
2024-03-13 09:10  | windows    | 7045 — new service installed (PSEXESVC) on db-server-01| T1569.002
2024-03-13 10:30  | db_audit   | SHOW DATABASES; SHOW TABLES; SELECT from info_schema    | T1082
2024-03-13 14:00  | db_audit   | SELECT * FROM customers (45,000 rows returned)          | T1213
2024-03-15 08:00  | firewall   | C2 reconnection (beacon resumes)                        | T1071.001
2024-03-15 10:15  | firewall   | Large HTTPS upload 185.220.101.55:443 (2.1GB out)       | T1041
2024-03-15 16:00  | db_audit   | Anomaly alert: query volume spike (detection trigger)   | —
```

**Dwell time:** 3 days, 6 hours, 37 minutes (from first C2 beacon to isolation)

---

## Task 2: ATT&CK Mapping — Expected Minimum

| Technique | ID | Evidence |
|-----------|-----|---------|
| Spearphishing Attachment | T1566.001 | Email gateway log — `.xlsm` from external sender |
| User Execution: Malicious File | T1204.002 | No direct log evidence — inferred from C2 appearing shortly after email |
| Ingress Tool Transfer | T1105 | Firewall: outbound HTTPS to `update.softcheck.net` 8 minutes after email |
| C2: Application Layer Protocol | T1071.001 | DNS + firewall: regular 10-minute beacon intervals |
| OS Credential Dumping: LSASS | T1003.001 | Windows Sysmon Event 10 (or EDR alert) on lsass memory access |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Event 4648 + PSEXESVC service install (Event 7045) |
| Service Execution | T1569.002 | Event 7045 — PSEXESVC installed on db-server-01 |
| Account Discovery | T1087 | `net user`, `net group` commands in process creation logs |
| Data from Information Repositories | T1213 | DB audit log — SELECT from customers table |
| Exfiltration Over C2 Channel | T1041 | Firewall — 2.1GB outbound upload to C2 IP |
| Dynamic Resolution: DNS | T1568 | DNS log — high-frequency queries to `api.softcheck.net` |
| Masquerading | T1036 | C2 domain `softcheck.net` mimics legitimate software update domain |

---

## Task 3: Diamond Model — Expected Analysis

**Adversary:**

* Motivation: Financial (customer data exfiltration — likely for sale or fraud)
* Sophistication: Medium — used commodity C2, Mimikatz, PsExec (all publicly available tools)
* Likely: Criminal group, not nation-state (techniques are not sophisticated enough, target is a logistics company not critical infrastructure)

**Infrastructure:**

* C2 IP: `185.220.101.55` (Tor exit node range — common for criminal groups)
* Domains: `update.softcheck.net`, `api.softcheck.net` (typosquat — commodity tactic)
* Tools: Mimikatz (credential dumping), PsExec (lateral movement) — both freely available

**Capability:**

* Medium capability. Used known tools, standard phishing delivery.
* No custom malware observed. No zero-day exploitation.
* However, the 3-day dwell without detection suggests patience and operational awareness.

**Victim:**

* TransLog SA — logistics company with customer database (names, addresses, contact info for 45,000 customers)
* Target value: customer PII for fraud or dark web sale
* Why targeted: low security maturity (no EDR alert, 3-day dwell), valuable PII dataset

---

## Task 4: Log Normalization — Expected Script

```python
import pandas as pd
import json

# Parse web access log (Apache JSON)
web_logs = []
with open('/data/logs/web_access.log') as f:
    for line in f:
        entry = json.loads(line)
        web_logs.append({
            '@timestamp': pd.to_datetime(entry['time']),
            'source.ip': entry['remote_ip'],
            'destination.port': 80,
            'http.request.method': entry['method'],
            'http.response.status_code': entry['status'],
            'url.path': entry['path'],
            'event.action': 'http-request',
            'event.outcome': 'success' if entry['status'] < 400 else 'failure',
            'log_source': 'web'
        })

# Parse firewall log (CSV)
fw_raw = pd.read_csv('/data/logs/firewall.log')
fw_logs = []
for _, row in fw_raw.iterrows():
    fw_logs.append({
        '@timestamp': pd.to_datetime(row['timestamp']),
        'source.ip': row['src_ip'],
        'destination.ip': row['dst_ip'],
        'destination.port': int(row['dst_port']),
        'http.request.method': None,
        'http.response.status_code': None,
        'url.path': None,
        'event.action': row['action'],
        'event.outcome': 'success' if row['action'] == 'allow' else 'failure',
        'log_source': 'firewall'
    })

web_df = pd.DataFrame(web_logs)
fw_df = pd.DataFrame(fw_logs)

# Merge: find firewall events within 60 seconds of web requests from same source IP
web_df['ts_numeric'] = web_df['@timestamp'].astype('int64') // 1e9
fw_df['ts_numeric'] = fw_df['@timestamp'].astype('int64') // 1e9

# Tolerance join
merged = pd.merge_asof(
    web_df.sort_values('ts_numeric'),
    fw_df[['source.ip', 'ts_numeric', 'destination.ip', 'event.action']].sort_values('ts_numeric'),
    on='ts_numeric',
    by='source.ip',
    tolerance=60,
    direction='nearest',
    suffixes=('_web', '_fw')
)

merged.drop(columns=['ts_numeric']).to_csv('/data/normalised_events.csv', index=False)
print(f"Normalised {len(merged)} events")
```

---

## Task 5: Threat Hunt — Expected Results

**Hunt 1 (Other hosts communicating with C2):**

* Search `firewall.log` for all internal IPs connecting to `185.220.101.55`
* Expected finding: only `10.0.0.45` (j.popescu's workstation) and after lateral movement, `10.0.0.20` (db-server-01)
* Interpretation: database server was used as pivot for exfiltration — important finding that expands scope

**Hunt 2 (Credential reuse after credential dumping):**

* Search `windows_security.evtx.json` for Event 4624 (logon success) for `admin-backup` after 2024-03-13 08:22 (credential dump time)
* Expected: logon to `db-server-01` and `file-server-01` within 2 hours of the credential dump
* Interpretation: confirms lateral movement scope; `file-server-01` access may indicate additional data at risk not initially scoped

**Hunt 3 (Earlier exfiltration):**

* Search firewall for large outbound flows to `185.220.101.55` before the known 2024-03-15 10:15 event
* Expected: No evidence of earlier bulk exfiltration, but on Day 2 there is a 45KB outbound upload (configuration/credential dump sent to C2 — not the customer records themselves)
* Interpretation: The customer data exfiltration occurred as a single event. The 45KB on Day 2 was likely credential/config staging data.

---

## Task 6: Post-Incident Report — Grading Notes

**Strong reports will:**

* State GDPR implications clearly: 45,000 customer records = mandatory notification to ANSPDCP (Romanian DPA) within 72 hours; customer notification may be required if high risk
* Identify dwell time (3+ days) as the primary indicator of detection failure
* Root causes: no EDR, no DNS monitoring for C2 beaconing patterns, no database activity baseline, no alert on LSASS access
* Recommendations: Deploy EDR, enable DNS query logging with C2 detection, implement database activity monitoring, enable Windows Advanced Audit Policy, SIEM correlation rules for PsExec service install

**Common student errors:**

* Treating each log source in isolation rather than correlating across sources
* Missing the `file-server-01` lateral movement found in Hunt 2 (expands scope)
* Not mentioning GDPR at all, or getting the notification timeline wrong (72h not 24h for GDPR)
* Recommendations that are too vague ("improve security") rather than specific
