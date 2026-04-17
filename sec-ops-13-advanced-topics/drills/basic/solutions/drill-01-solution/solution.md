# Solution: IOC Enrichment with STIX Feeds

**Drill:** Basic Drill 01 — IOC Enrichment

**Session:** 13 — Advanced Topics in Security Operations

---

## Overview

This solution walks through each task using Python inside the Docker container.
The approach favours readability and demonstrates the key concepts rather than optimising for brevity.

---

## Setup

```bash
cd demos/demo-02-threat-intelligence
docker compose up -d
docker compose exec app bash

# Inside the container — create the IOC file
cat > /tmp/raw_iocs.txt << 'EOF'
185.220.101.47
paypal-secure-login.ru
hxxps://cdn-update.net/flash/install.exe
d41d8cd98f00b204e9800998ecf8427e
invoice_Q3_2024.docx.exe
185.220.101.89
microsoftonline-verify.com
6b86b273ff34fce19d6b804eff5a3f57
EOF
```

---

## Task 1 — Parse the STIX Feed

```python
#!/usr/bin/env python3
import json
import stix2

with open("/data/threat_bundle.json") as f:
    raw = json.load(f)

bundle = stix2.parse(json.dumps(raw), allow_custom=True)

indicators = [obj for obj in bundle.objects if obj.type == "indicator"]
print(f"Total indicators: {len(indicators)}")

from collections import Counter
pattern_types = Counter()
for ind in indicators:
    if "[ipv4-addr:" in ind.pattern:
        pattern_types["ipv4"] += 1
    elif "[domain-name:" in ind.pattern:
        pattern_types["domain"] += 1
    elif "[file:hashes" in ind.pattern:
        pattern_types["hash"] += 1
    elif "[url:" in ind.pattern:
        pattern_types["url"] += 1
    else:
        pattern_types["other"] += 1

    print(f"  {ind.name} | valid_from={ind.valid_from} | pattern={ind.pattern}")

print("\nPattern type counts:")
for k, v in pattern_types.items():
    print(f"  {k}: {v}")
```

**Expected output (approximate — depends on bundle contents):**

```text
Total indicators: 6
  Malicious C2 IP | valid_from=2024-09-01... | pattern=[ipv4-addr:value = '185.220.101.47']
  ...
Pattern type counts:
  ipv4: 2
  domain: 2
  hash: 2
```

---

## Task 2 — Match Raw IOCs Against the STIX Feed

```python
with open("/tmp/raw_iocs.txt") as f:
    raw_iocs = [line.strip() for line in f if line.strip()]

matches = {}
for ioc in raw_iocs:
    matched_indicator = None
    for ind in indicators:
        if ioc in ind.pattern:
            matched_indicator = ind
            break
    matches[ioc] = matched_indicator
    status = f"MATCHED: {matched_indicator.name}" if matched_indicator else "no match"
    print(f"  {ioc:45s} {status}")
```

**Key observations:**

* `185.220.101.47` → matches the "Malicious C2 IP" indicator
* `paypal-secure-login.ru` → matches the "Phishing Domain" indicator
* `d41d8cd98f00b204e9800998ecf8427e` → matches if the hash is in the bundle
* `invoice_Q3_2024.docx.exe` → likely no STIX match (filename only, not in feed by default)
* The `hxxps://` defanged URL will **not** match a `[url:` pattern literally — this is an important finding: defanged URLs need re-fanging before matching.

**Re-fang URLs before matching:**

```python
def refang(ioc):
    return ioc.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")

raw_iocs = [refang(ioc) for ioc in raw_iocs]
```

---

## Task 3 — Query the Reputation API

```python
import requests

reputation_data = {}
for ioc, indicator in matches.items():
    if indicator is None:
        reputation_data[ioc] = {"score": 0, "category": "unknown", "last_seen": None}
        continue
    try:
        resp = requests.get(f"http://reputation-api:5000/check", params={"ioc": ioc}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            reputation_data[ioc] = {
                "score": data.get("score", 0),
                "category": data.get("category", "unknown"),
                "last_seen": data.get("last_seen")
            }
        else:
            reputation_data[ioc] = {"score": 0, "category": "unknown", "last_seen": None}
    except requests.RequestException as e:
        print(f"  API error for {ioc}: {e}")
        reputation_data[ioc] = {"score": 0, "category": "unknown", "last_seen": None}
```

---

## Task 4 — Produce a Triage Report

```python
import json

def classify_ioc_type(ioc):
    import re
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
        return "ip"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if re.match(r'^[a-f0-9]{32}$', ioc, re.IGNORECASE) or re.match(r'^[a-f0-9]{40}$', ioc, re.IGNORECASE):
        return "hash"
    if "." in ioc and "/" not in ioc and not ioc.endswith(".exe"):
        return "domain"
    return "filename"

def recommend(stix_match, score):
    if score >= 70:
        return "BLOCK"
    elif stix_match:
        return "MONITOR"
    else:
        return "INVESTIGATE"

report = []
for ioc in raw_iocs:
    indicator = matches.get(ioc)
    rep = reputation_data.get(ioc, {"score": 0, "category": "unknown"})
    entry = {
        "ioc": ioc,
        "type": classify_ioc_type(ioc),
        "stix_match": indicator is not None,
        "stix_indicator_name": indicator.name if indicator else None,
        "reputation_score": rep["score"],
        "category": rep["category"],
        "recommendation": recommend(indicator is not None, rep["score"])
    }
    report.append(entry)

with open("/tmp/triage_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("Triage report written to /tmp/triage_report.json")
```

---

## Task 5 — Summary

```python
from collections import Counter

recs = Counter(entry["recommendation"] for entry in report)
stix_hits = sum(1 for e in report if e["stix_match"])

print(f"\n{'='*50}")
print(f"IOC TRIAGE SUMMARY")
print(f"{'='*50}")
print(f"Total IOCs processed : {len(report)}")
print(f"STIX feed matches    : {stix_hits}")
print(f"BLOCK (score >= 70)  : {recs['BLOCK']}")
print(f"MONITOR (stix match) : {recs['MONITOR']}")
print(f"INVESTIGATE          : {recs['INVESTIGATE']}")
```

---

## Analyst Notes — Sample Answer

```text
/tmp/analyst_notes.txt content:

The most suspicious IOC in this batch is 185.220.101.47 — it matched a known C2 indicator
in the STIX feed and received a reputation score of 87/100, categorised as "c2". This IP
should be blocked immediately at the perimeter firewall and any internal hosts that
communicated with it should be flagged for endpoint investigation.

The domain paypal-secure-login.ru is a clear phishing indicator (STIX match, category:
phishing, score 79). Any employee who clicked links to this domain should be notified and
credentials potentially reset.

The hash d41d8cd98f00b204e9800998ecf8427e is the well-known MD5 hash of an empty file —
its presence in the IOC list may indicate a false positive in the extraction process and
should be validated against the source logs before action is taken.
```

---

## Common Mistakes

1. **Forgetting to re-fang URLs** — `hxxps://` won't match `[url:value = 'https://...']` in STIX patterns.
1. **String matching is fragile** — `185.220.101.47` could false-positive match `185.220.101.47x` if not using exact pattern parsing. For production, use proper STIX pattern evaluation libraries.
1. **Not handling API errors** — The reputation API may time out or return 404 for unknown IOCs. Always wrap in try/except.
1. **MD5 of empty file** — `d41d8cd98f00b204e9800998ecf8427e` is a known artifact, not a real malware hash. Flag as likely false positive.

---

## Scoring Guide

| Criterion | Full marks if... |
|-----------|-----------------|
| STIX parsing (20 pts) | All indicator types counted correctly; names/patterns printed |
| IOC matching (20 pts) | At least 4/8 IOCs correctly matched; defanging attempted |
| Reputation API (20 pts) | API called for matched IOCs; errors handled gracefully |
| Triage report (30 pts) | Valid JSON; recommendation logic correct; all 8 IOCs present |
| Analyst notes (10 pts) | References specific IOC with evidence; actionable recommendation |
