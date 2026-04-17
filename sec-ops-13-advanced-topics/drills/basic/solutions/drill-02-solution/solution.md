# Solution: Cloud Log Analysis

**Drill:** Basic Drill 02 — Cloud Log Analysis

**Session:** 13 — Advanced Topics in Security Operations

---

## Overview

This solution demonstrates a systematic approach to CloudTrail log analysis using Python.
The full script can be run as `/tmp/analyze.py` inside the container.

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
CloudTrail Incident Analysis — NovaTech Logistics
Drill 02 Solution
"""

import json
from datetime import datetime, timezone
from collections import Counter, defaultdict

# ─── Load logs ────────────────────────────────────────────────────────────────
with open("/data/cloudtrail_sample.json") as f:
    records = json.load(f)

print(f"Total records: {len(records)}")

# ─── Task 1: Explore ──────────────────────────────────────────────────────────
services = set(r.get("eventSource", "unknown") for r in records)
print(f"\nUnique event sources ({len(services)}):")
for s in sorted(services):
    print(f"  {s}")

def get_username(r):
    uid = r.get("userIdentity", {})
    utype = uid.get("type", "")
    if utype == "IAMUser":
        return uid.get("userName", "unknown")
    elif utype == "AssumedRole":
        arn = uid.get("arn", "")
        # arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
        parts = arn.split("/")
        return f"role/{parts[1]}" if len(parts) >= 2 else arn
    elif utype == "Root":
        return "ROOT"
    return uid.get("arn", "unknown")

usernames = set(get_username(r) for r in records)
print(f"\nUnique user identities ({len(usernames)}):")
for u in sorted(usernames):
    print(f"  {u}")

ips = set(r.get("sourceIPAddress", "unknown") for r in records)
print(f"\nUnique source IPs ({len(ips)}):")
for ip in sorted(ips):
    print(f"  {ip}")

# ─── Task 2: Identify suspicious IP ──────────────────────────────────────────
ip_counts = Counter(r.get("sourceIPAddress") for r in records)
print(f"\nEvents per source IP:")
for ip, count in ip_counts.most_common():
    print(f"  {ip:20s}  {count} events")

suspicious_ip = ip_counts.most_common(1)[0][0]
print(f"\nSuspicious IP: {suspicious_ip}")

sus_records = [r for r in records if r.get("sourceIPAddress") == suspicious_ip]

def parse_time(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))

sus_times = sorted(parse_time(r["eventTime"]) for r in sus_records)
print(f"Activity window: {sus_times[0]} → {sus_times[-1]}")
print(f"Duration: {sus_times[-1] - sus_times[0]}")

sus_events = Counter(r.get("eventName") for r in sus_records)
print(f"\nEvent names from {suspicious_ip}:")
for evt, cnt in sus_events.most_common():
    print(f"  {evt:40s} {cnt}")

# ─── Task 3: Attack timeline ──────────────────────────────────────────────────
RECON_PREFIXES = ("Describe", "List", "Get")
PRIVESC_EVENTS = {
    "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
    "CreateRole", "AttachRolePolicy", "PutRolePolicy"
}
PERSISTENCE_EVENTS = {"CreateUser", "CreateLoginProfile", "UpdateLoginProfile"}
EXFIL_EVENTS = {"GetObject", "CopyObject", "GetSecretValue", "GetParameter", "GetParameters"}

def classify_phase(event_name):
    if event_name in EXFIL_EVENTS:
        return "EXFILTRATION"
    if event_name in PRIVESC_EVENTS:
        return "PRIV-ESC"
    if event_name in PERSISTENCE_EVENTS:
        return "PERSISTENCE"
    if any(event_name.startswith(p) for p in RECON_PREFIXES):
        return "RECON"
    return "OTHER"

sorted_sus = sorted(sus_records, key=lambda r: r["eventTime"])

print(f"\n{'TIME':25s} {'EVENT':40s} {'PHASE':15s} {'ERROR'}")
print("-" * 100)
for r in sorted_sus:
    t = r["eventTime"]
    evt = r.get("eventName", "?")
    phase = classify_phase(evt)
    err = r.get("errorCode") or "-"
    print(f"{t:25s} {evt:40s} {phase:15s} {err}")

# ─── Task 4: Impacted resources ───────────────────────────────────────────────
buckets = set()
iam_created = []
secrets_read = []
succeeded = []
failed = []

for r in sus_records:
    params = r.get("requestParameters") or {}
    evt = r.get("eventName", "")
    err = r.get("errorCode")

    if err:
        failed.append(evt)
    else:
        succeeded.append(evt)

    # S3 buckets
    if "bucketName" in params:
        buckets.add(params["bucketName"])

    # IAM creations
    if evt in ("CreateUser", "CreateAccessKey"):
        username = params.get("userName") or params.get("userNames", ["?"])[0]
        iam_created.append(f"{evt}: {username}")

    # Secrets / SSM
    if evt in ("GetSecretValue",):
        secrets_read.append(params.get("secretId") or "unknown")
    if evt in ("GetParameter", "GetParameters"):
        secrets_read.append(params.get("name") or str(params.get("names", ["unknown"])))

print(f"\nS3 buckets accessed: {buckets or 'none found'}")
print(f"IAM actions performed: {iam_created or 'none found'}")
print(f"Secrets/parameters read: {secrets_read or 'none found'}")
print(f"Successful actions: {len(succeeded)} | Failed actions: {len(failed)}")

# ─── Task 5: Write incident summary ──────────────────────────────────────────
phases_seen = set(classify_phase(r.get("eventName","")) for r in sus_records if classify_phase(r.get("eventName","")) != "OTHER")

summary = f"""INCIDENT SUMMARY — NovaTech Logistics CloudTrail Analysis
==========================================================
Date of analysis : {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

ATTACKER PROFILE
  Source IP      : {suspicious_ip}
  Identity used  : {get_username(sus_records[0])}
  Activity start : {sus_times[0].isoformat()}
  Activity end   : {sus_times[-1].isoformat()}
  Duration       : {sus_times[-1] - sus_times[0]}

ATTACK PHASES OBSERVED
  {', '.join(sorted(phases_seen))}

  Reconnaissance examples   : ListBuckets, DescribeInstances, GetCallerIdentity
  Privilege escalation      : CreateAccessKey, AttachUserPolicy
  Exfiltration              : GetObject (sensitive S3 objects), GetSecretValue

IMPACTED RESOURCES
  S3 buckets  : {', '.join(sorted(buckets)) or 'see log for details'}
  IAM actions : {', '.join(iam_created) or 'none confirmed'}
  Secrets     : {', '.join(secrets_read) or 'none confirmed'}

RECOMMENDED CONTAINMENT ACTIONS

  1. Immediately disable or delete any access keys created during the incident.

  2. Revoke all active sessions for the compromised identity (backup-svc).
  3. Block source IP {suspicious_ip} at the WAF and security group level.
  4. Enable MFA on all IAM users; rotate credentials for affected service accounts.
  5. Review S3 bucket policies for any buckets listed in impacted resources and
     enable access logging if not already in place.
  6. Notify data owners of any buckets or secrets that were read.
"""

with open("/tmp/incident_summary.txt", "w") as f:
    f.write(summary)

print("\nIncident summary written to /tmp/incident_summary.txt")
print(summary)
```

---

## Running the Script

```console
python3 /tmp/analyze.py
```

---

## Key Findings to Expect

The log dataset is designed to show:

1. **Reconnaissance phase** — a burst of `List*` and `Describe*` calls in the first 2–3 minutes
1. **Privilege escalation** — `CreateAccessKey` called for an existing service account (`backup-svc`), giving the attacker persistent credentials
1. **Exfiltration** — `GetObject` calls fetching `.csv` and `.sql` files from the `novatech-backups` bucket
1. All actions originate from IP `203.0.113.77` (TEST-NET range — safe for demos)

---

## Common Mistakes

1. **Ignoring failed events** — Failed API calls still tell us what the attacker tried. `AccessDenied` errors on sensitive API calls are high-signal.
1. **Not accounting for AssumedRole identity type** — Service accounts often assume roles; check `userIdentity.type` before extracting a username.
1. **Ignoring `CreateAccessKey`** — This is often the most critical finding because it means the attacker has persistent access that survives password resets.
1. **Not normalising timestamps** — CloudTrail uses UTC; local time comparisons without timezone handling will produce incorrect durations.

---

## Scoring Guide

| Criterion | Full marks if... |
|-----------|-----------------|
| Task 1 (15 pts) | Correct total count; all unique services, usernames, and IPs listed |
| Task 2 (20 pts) | Correct suspicious IP with event count and time window |
| Task 3 (25 pts) | Correctly sorted timeline; all 4 phases classified; error codes shown |
| Task 4 (20 pts) | S3 buckets, IAM actions, and secrets identified |
| Task 5 (20 pts) | Summary covers all 5 required elements; containment actions are specific |
