# Drill: IOC Enrichment with STIX Feeds

**Level:** Basic

**Estimated time:** 45–60 minutes

**Session:** 13 — Advanced Topics in Security Operations

---

## Scenario

You are a Tier-1 analyst at **Meridian Financial Services**.
The threat intelligence team has shared a batch of indicators of compromise (IOCs) extracted from a recent phishing campaign targeting banking customers in the region.

Your task is to enrich these IOCs using a local STIX 2.1 threat feed and a mock reputation service, then produce a triage summary that helps the incident response team decide which indicators to block immediately.

The environment is pre-built with Docker.
The STIX feed and reputation API are mocked locally — no external internet access is required.

---

## Learning Objectives

* Parse a STIX 2.1 bundle and extract indicator objects
* Cross-reference raw IOCs against a structured threat feed
* Use a simple reputation API to score each IOC
* Produce a structured triage report in JSON

---

## Environment Setup

```console
cd demos/demo-02-threat-intelligence
docker compose up -d
docker compose exec app bash
```

The container provides:

* Python 3.11 with `stix2`, `requests`, `rich` libraries
* A local mock TAXII-like server at `http://localhost:8000` (mapped inside container)
* Sample STIX bundle at `/data/threat_bundle.json`
* Mock reputation API at `http://reputation-api:5000/check?ioc=<value>`

---

## Task Dataset

The following raw IOCs were extracted from email headers, proxy logs, and endpoint telemetry.
Save them to `/tmp/raw_iocs.txt` inside the container:

```text
185.220.101.47
paypal-secure-login.ru
hxxps://cdn-update.net/flash/install.exe
d41d8cd98f00b204e9800998ecf8427e
invoice_Q3_2024.docx.exe
185.220.101.89
microsoftonline-verify.com
6b86b273ff34fce19d6b804eff5a3f57
```

---

## Tasks

### Task 1 — Parse the STIX Feed

1. Load `/data/threat_bundle.json` using the `stix2` library.
1. Extract all `indicator` objects from the bundle.
1. Print each indicator's `name`, `pattern`, `valid_from`, and `confidence` (if present).
1. Count how many indicators match each pattern type (`[domain-name:value`, `[ipv4-addr:value`, `[file:hashes`).

**Hint:** Use `stix2.parse()` or load the JSON directly and iterate over `bundle.objects`.
Filter by `type == "indicator"`.

### Task 2 — Match Raw IOCs Against the STIX Feed

1. For each IOC in `/tmp/raw_iocs.txt`, check whether it appears in any STIX indicator pattern.
1. A match counts if the IOC value appears anywhere in the `pattern` string field.
1. Record which STIX indicator matched (name + id) for each hit.
1. Record "no match" for IOCs not found in the feed.

**Hint:** Use simple string containment (`ioc_value in indicator.pattern`) as a first approximation.
Pay attention to pattern escaping.

### Task 3 — Query the Reputation API

For each IOC that produced a STIX match in Task 2, call the mock reputation API:

```console
curl "http://reputation-api:5000/check?ioc=185.220.101.47"
```

The API returns JSON like:

```json
{
  "ioc": "185.220.101.47",
  "score": 87,
  "category": "c2",
  "last_seen": "2024-11-14",
  "source": "MockThreatDB"
}
```

Collect the `score` and `category` for each matched IOC.
If the API returns a 404 or score of 0, mark as "unknown".

**Hint:** Use `requests.get()`.
Handle connection errors gracefully with try/except.

### Task 4 — Produce a Triage Report

Create a JSON file `/tmp/triage_report.json` with the following structure for each IOC:

```json
{
  "ioc": "<value>",
  "type": "<ip|domain|url|hash|filename>",
  "stix_match": true,
  "stix_indicator_name": "<name or null>",
  "reputation_score": 87,
  "category": "c2",
  "recommendation": "BLOCK"
}
```

Apply this recommendation logic:

* `reputation_score >= 70` → `"BLOCK"`
* `stix_match == true` but `reputation_score < 70` → `"MONITOR"`
* No match and no score → `"INVESTIGATE"`

### Task 5 — Summarise Results

Print a summary table to the terminal showing:

* Total IOCs processed
* How many had STIX matches
* How many scored >= 70 (BLOCK)
* How many scored 1–69 (MONITOR)
* How many had no data (INVESTIGATE)

---

## Deliverables

* `/tmp/triage_report.json` — structured triage output
* A brief written summary (3–5 sentences) in `/tmp/analyst_notes.txt` describing the most suspicious IOC and why

---

## Hints

* The STIX bundle uses STIX 2.1 format. Use `stix2.parse(json_str, allow_custom=True)` if you encounter custom properties.
* IP addresses in STIX patterns look like: `[ipv4-addr:value = '185.220.101.47']`
* Domain patterns look like: `[domain-name:value = 'paypal-secure-login.ru']`
* Hash patterns look like: `[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']`
* The mock reputation API is accessible only from inside the Docker network as `reputation-api` hostname.
* Use `rich.console` or `rich.table` for formatted terminal output if you wish.

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Correctly parsed STIX bundle and counted indicators by type | 20 |
| Correctly matched at least 4 of 8 IOCs against the feed | 20 |
| Correctly queried reputation API and handled errors | 20 |
| Produced valid JSON triage report with correct recommendation logic | 30 |
| Written analyst notes are coherent and reference specific evidence | 10 |

**Total: 100 points**
