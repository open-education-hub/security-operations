# Drill: Threat Hunting with STIX IOCs

**Level:** Intermediate

**Estimated time:** 60–75 minutes

**Session:** 13 — Advanced Topics in Security Operations

---

## Scenario

You are a threat hunter at **Ironclad Shipping Co.** The threat intelligence team has published a new STIX 2.1 report describing a campaign by a threat actor called **GHOST ANCHOR** — believed to be targeting logistics and shipping companies for supply chain intelligence.
The report includes indicators linked to the group's infrastructure.

Your task is to hunt for evidence of GHOST ANCHOR activity in Ironclad's network telemetry.
You have been given a week's worth of proxy logs, DNS query logs, and endpoint process-creation events.
All data has been anonymised and loaded into the Docker environment.

---

## Learning Objectives

* Extract threat actor TTPs from a STIX report
* Cross-reference STIX indicators against network and endpoint telemetry
* Prioritise findings by confidence and impact
* Produce a hunting report distinguishing confirmed hits from suspicious leads

---

## Environment Setup

```console
cd demos/demo-02-threat-intelligence
docker compose up -d
docker compose exec app bash
```

Available datasets inside the container:

* `/data/ghost_anchor_report.json` — STIX 2.1 bundle for GHOST ANCHOR campaign
* `/data/proxy_logs.json` — 7 days of outbound HTTP/HTTPS proxy logs
* `/data/dns_logs.json` — 7 days of internal DNS resolution logs
* `/data/endpoint_events.json` — Process creation events from 12 endpoints

---

## STIX Report Overview

The GHOST ANCHOR STIX bundle contains:

* 1 `threat-actor` object
* 1 `campaign` object
* 2 `malware` objects (a loader and a RAT)
* 8 `indicator` objects (IPs, domains, file hashes, and a URL pattern)
* 2 `attack-pattern` objects (ATT&CK techniques)
* Relationships linking all the above

---

## Tasks

### Task 1 — Extract IOCs from the STIX Bundle

1. Load `/data/ghost_anchor_report.json`.
1. Extract all `indicator` objects. For each, record:
   * `id`, `name`, `pattern`, `valid_from`, `confidence` (if present)
1. Separate the IOCs into categories: IPv4, domain, URL, file hash.
1. Build a lookup dictionary: `{ ioc_value: indicator_object }` for each category.
1. Print a summary: how many IOCs per type.

**Hint:** Parse the STIX pattern string to extract the actual indicator value.
For example:

* `[ipv4-addr:value = '1.2.3.4']` → extract `1.2.3.4`
* `[domain-name:value = 'evil.example.com']` → extract `evil.example.com`
* `[file:hashes.MD5 = 'abc123']` → extract `abc123`

Use a regex: `r"= '([^']+)'"` to extract the value.

### Task 2 — Hunt in Proxy Logs

Each proxy log entry looks like:

```json
{
  "timestamp": "2024-11-12T09:33:21Z",
  "src_ip": "10.10.5.22",
  "dest_ip": "198.51.100.34",
  "dest_host": "updates.microsooft-cdn.net",
  "url": "https://updates.microsooft-cdn.net/v2/check",
  "http_method": "GET",
  "response_code": 200,
  "bytes_out": 412,
  "bytes_in": 8843,
  "user_agent": "Mozilla/5.0 (compatible)"
}
```

1. Load `/data/proxy_logs.json`.
1. For each log entry, check if `dest_ip` matches any IOC IP, OR if `dest_host` matches any IOC domain.
1. Also check the full URL against any URL pattern IOCs.
1. For each match, record: timestamp, src_ip, dest_host, dest_ip, matched_ioc, indicator_name.
1. Deduplicate by `src_ip` — show which internal hosts connected to threat actor infrastructure.

### Task 3 — Hunt in DNS Logs

Each DNS log entry:

```json
{
  "timestamp": "2024-11-12T09:32:58Z",
  "client_ip": "10.10.5.22",
  "query_name": "updates.microsooft-cdn.net",
  "query_type": "A",
  "response_ip": "198.51.100.34",
  "rcode": "NOERROR"
}
```

1. Load `/data/dns_logs.json`.
1. Check `query_name` against domain IOCs.
1. Also check `response_ip` against IP IOCs.
1. For matches, note the `client_ip` making the query.
1. Correlate with proxy log matches — do the same internal IPs appear in both?

**Hint:** DNS queries often precede the proxy connection by seconds.
If you see the DNS query from the same host shortly before the proxy connection, that's a strong confirmation.

### Task 4 — Hunt in Endpoint Events

Each endpoint event:

```json
{
  "timestamp": "2024-11-12T09:34:05Z",
  "hostname": "WS-IRONCLAD-017",
  "user": "ironclad\\mwilliams",
  "image": "C:\\Windows\\Temp\\svchost32.exe",
  "md5": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "sha256": "abcdef1234567890...",
  "commandline": "svchost32.exe -c config.ini",
  "parent_image": "C:\\Windows\\explorer.exe"
}
```

1. Load `/data/endpoint_events.json`.
1. Check `md5` and `sha256` fields against hash IOCs.
1. Also check `image` (process path) for any filename matching IOC filenames.
1. For matches, record hostname, user, timestamp, matched IOC.
1. Check if the matched hostname also appears in proxy/DNS log findings from Tasks 2–3.

### Task 5 — Produce a Hunting Report

Write `/tmp/hunt_report.md` with the following sections:

1. **Executive Summary** — Was GHOST ANCHOR activity confirmed? How many hosts are affected?
1. **IOC Hit Summary** — Table of each matched IOC with: IOC value, type, data source, affected hosts
1. **Timeline of Events** — Chronological list of confirmed hits from all three data sources
1. **Affected Hosts** — List of internal hosts with evidence of compromise or contact
1. **Recommended Actions** — Minimum 4 specific containment/remediation steps

---

## Deliverables

* Terminal output showing hits in each data source
* `/tmp/hunt_report.md` — structured hunting report

---

## Hints

* The GHOST ANCHOR report uses typosquatted domain names (e.g., `microsooft` with an extra `o`). This is intentional — real threat actors use these tricks.
* Not all 8 IOCs will generate hits. Some may be from an older campaign phase not yet active in Ironclad's environment. A "no hit" result is still valid and should be noted.
* DNS resolution (`query_name`) is more reliable for domain matching than proxy `dest_host` because some proxy entries use the resolved IP directly.
* When correlating across data sources, use `src_ip`/`client_ip`/`hostname` as correlation keys — but note that `src_ip` in proxy logs is the internal IP, while `hostname` in endpoint events is the machine name. You may need to maintain an IP-to-hostname mapping if one is provided.

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Task 1: All IOCs correctly extracted and categorised | 15 |
| Task 2: All proxy log hits found; internal hosts identified | 20 |
| Task 3: DNS hits found; correlation with proxy hits noted | 20 |
| Task 4: Hash matches found on endpoint; correlated with network findings | 20 |
| Task 5: Hunt report complete with all 5 sections; actionable recommendations | 25 |

**Total: 100 points**
