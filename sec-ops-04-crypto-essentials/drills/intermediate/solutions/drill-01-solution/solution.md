# Solution: Drill 01 (Intermediate) — TLS Traffic Analysis

---

## Task 1: Initial Triage — Suspicious Connections

**Immediately suspicious connections:**

1. **185.220.101.47 (updates.telemetry-cdn.net)** — Appears 4 times in 3 minutes. Extremely regular timing. Small bytes in both directions. Domain name sounds legitimate but isn't a recognizable service.

1. **91.198.174.222 (secure-files.dropbox-storage.net)** — "dropbox-storage.net" is NOT the real Dropbox domain. Nearly 2.8 MB sent, only 4.8 KB received. 1-day-old certificate. Classic exfiltration pattern.

1. **10.0.1.15 (legacy-app.internal)** — Uses TLS 1.0 (deprecated). Self-signed certificate from 2018. Internal host using ancient TLS.

---

## Task 2: Beaconing Detection

**Beaconing destination:** `185.220.101.47` (updates.telemetry-cdn.net)

**Pattern:**

```text
09:00:01 → 09:01:01 → 09:02:01 → 09:03:01
Interval: 60 seconds (exactly)
```

**Significance:** The perfectly regular 60-second interval is a classic beaconing pattern.
Human-generated traffic is irregular; automated C2 check-ins are regular.

**Cobalt Strike default beacon interval:** 60 seconds.
This is the Cobalt Strike default "sleep" time before checking in with the C2 server.
This is a major red flag.

**Answer:** Cobalt Strike (or similar post-exploitation framework) uses regular-interval beaconing.
The exact 60-second interval matches the Cobalt Strike default configuration.

---

## Task 3: Certificate Analysis

**Suspicious certificates:**

| Domain | Issue | Explanation |
|--------|-------|-------------|
| `updates.telemetry-cdn.net` | 2-day-old cert | Freshly issued for beaconing C2 |
| `secure-files.dropbox-storage.net` | 1-day-old cert | Brand new cert for suspicious lookalike domain |

**Why fresh Let's Encrypt certs on unknown domains are suspicious:**

1. Let's Encrypt issues certificates for free within minutes — ideal for malware infrastructure
1. Legitimate services on established domains don't suddenly get brand-new certificates
1. Malware operators constantly register new domains and get certificates to evade blocklists
1. Certificates <7 days old on unknown domains are a high-confidence IOC of malware infrastructure
1. The "telemetry-cdn.net" and "dropbox-storage.net" names are designed to sound legitimate (typosquatting/lookalike)

---

## Task 4: Data Volume Analysis

**Suspicious connection:** `91.198.174.222` (secure-files.dropbox-storage.net)

```text
Bytes out: 2,847,293 bytes (~2.7 MB)
Bytes in:      4,820 bytes (~4.7 KB)
Ratio: ~591:1 (outbound:inbound)
```

**What high upload ratio suggests:**

* Data exfiltration — the endpoint is sending data to an external server
* For comparison, browsing a website produces much more inbound than outbound traffic
* A ~2.7 MB upload over HTTPS to an unknown domain with a 1-day-old certificate is almost certainly exfiltration
* 2.7 MB could contain: a compressed archive of documents, a credential database, a keylogger log

**Additional red flags:**

* Duration: 287 seconds (nearly 5 minutes) — suggests a sustained transfer
* Timestamp: 11:42 (lunch hour — attackers often time exfiltration when analysts are distracted)

---

## Task 5: TLS Version Audit

**Deprecated TLS connections:**

| Connection | Version | Issue |
|-----------|---------|-------|
| legacy-app.internal | **TLS 1.0** | Deprecated 2021; vulnerable to BEAST, POODLE |

**Risk:** TLS 1.0 on an internal application indicates a legacy system that hasn't been updated.
This itself may not be an attack, but it's a vulnerability requiring remediation.
Could also facilitate a downgrade attack if external traffic is involved.

---

## Task 6: JA3 Fingerprint Analysis

**Malware JA3 matches:**

| JA3 Hash | Intelligence | Connections |
|----------|-------------|------------|
| `c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a` | **Cobalt Strike Beacon** | 4× to 185.220.101.47 |
| `a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c` | **APT29 custom C2 implant** | 1× to 91.198.174.222 |

**Significance:**

* The Cobalt Strike JA3 match confirms the beaconing activity is a Cobalt Strike implant
* The APT29-associated JA3 during the exfiltration is extremely serious — APT29 (Cozy Bear) is a Russian state-sponsored threat actor

---

## Task 7: Incident Report

### IR-2024-TLS-117 — Incident Report

**Summary**

Workstation WS-117 (10.0.5.117) used by a financial analyst shows strong evidence of compromise by an advanced threat actor.
Analysis of TLS connection metadata reveals: (1) a Cobalt Strike beacon communicating to external C2 infrastructure at 60-second intervals, and (2) a subsequent data exfiltration of approximately 2.7 MB to an APT29-associated C2 server, all masked as HTTPS traffic.

**Indicators of Compromise (IOCs)**

| Type | Value | Description |
|------|-------|-------------|
| IP | 185.220.101.47 | Cobalt Strike C2 server |
| IP | 91.198.174.222 | APT29 exfiltration server |
| Domain | updates.telemetry-cdn.net | Cobalt Strike C2 domain |
| Domain | secure-files.dropbox-storage.net | Exfiltration staging domain |
| JA3 | c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a | Cobalt Strike Beacon fingerprint |
| JA3 | a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c | APT29 C2 implant fingerprint |

**Timeline**

| Time | Event |
|------|-------|
| 08:14–09:15 | Normal business activity (Office365, Teams) |
| 09:00–09:03 | Cobalt Strike beacon begins, 60s interval |
| 11:42 | 2.7 MB exfiltration to APT29-linked server (4+ min transfer) |
| 14:02 | Connection to legacy internal app (TLS 1.0 — potentially attacker reconnaissance) |

**Risk Assessment**

* The 2.7 MB exfiltration may contain sensitive financial documents, credentials, or internal data
* Cobalt Strike access means the attacker had interactive control over WS-117
* APT29 attribution (if confirmed) suggests state-sponsored espionage

**Immediate Recommendations**

1. **IMMEDIATE:** Isolate WS-117 from the network. Preserve forensic image before any changes.
1. **URGENT:** Block 185.220.101.47 and 91.198.174.222 at all perimeter firewalls and proxies. Search SIEM for any other hosts connecting to these IPs.
1. **TODAY:** Search all endpoint logs for JA3 hashes `c9e4e0bd...` and `a5b2f81c...` to identify other potentially compromised hosts. Check if the analyst's credentials were used from other locations.
