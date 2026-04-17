# Solution: Drill 01 (Advanced) — SIEM Detection Engineering (DCSync)

## Task 1: Research Summary

DCSync (T1003.006) abuses the Active Directory replication protocol.
Windows Event ID 4662 is generated on domain controllers when an object's properties are accessed.
A DCSync attack is detectable because:

1. The access rights GUIDs `{1131f6aa...}` (DS-Replication-Get-Changes) and `{1131f6ad...}` (DS-Replication-Get-Changes-All) are specific to replication operations
1. Legitimate replication ONLY occurs from accounts ending in `$` (machine accounts of other DCs)
1. When a non-DC workstation requests these rights, it is almost certainly DCSync

The primary detection from MITRE ATT&CK T1003.006: *"Monitor for Windows Event ID 4662 with access type `DS-Replication-Get-Changes-All` where the subject account is not a domain controller machine account."*

Existing Sigma rules: `win_ad_replication_non_machine_account.yml` in the SigmaHQ repository covers this detection.

---

## Task 2a: Complete Splunk SPL Rule

```spl
index=windows EventCode=4662 earliest=-15m
| where match(Properties, "(?i)1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2")
| where ObjectType="{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
| where NOT match(SubjectUserName, "(?i)(^(SERVER-DC01|SERVER-DC02))\$$")
| where NOT SubjectUserName="MSOL_*"
| eval mitre_technique = "T1003.006 - DCSync"
| eval severity = "CRITICAL"
| eval alert_title = "DCSync Attack Detected — " . SubjectUserName . " requested AD replication rights"
| table _time, ComputerName, SubjectUserName, SubjectDomainName, Properties, severity, mitre_technique, alert_title
```

**Key decisions:**

* `match(Properties, ...)` catches either `1131f6aa` (Get-Changes) or `1131f6ad` (Get-Changes-All)
* The regex exclusion `NOT match(SubjectUserName, ...)` excludes known DC machine accounts (end with `$`)
* `MSOL_*` exclusion covers Azure AD Connect service accounts which legitimately perform replication
* ObjectType filter ensures we only match directory objects, not general resource access

---

## Task 2b: Sigma Rule

```yaml
title: DCSync Active Directory Replication Rights Request
id: a6c3b3d2-5e4f-4b2a-9c1d-0e7f8g9h0i1j
status: stable
description: |
  Detects DCSync attacks by monitoring for Event ID 4662 where a non-domain-controller
  account requests Active Directory replication rights (DS-Replication-Get-Changes-All).
  DCSync allows an attacker to extract NTLM password hashes for any AD account including
  domain admins and the krbtgt account, enabling Golden Ticket attacks.
references:
  - https://attack.mitre.org/techniques/T1003/006/
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
  - https://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-opsec-oh-my/
author: "Security Operations Team"
date: 2024/03/15
tags:
  - attack.credential_access
  - attack.t1003.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType:
      - '{19195a5b-6da0-11d0-afd3-00c04fd930c9}'  # domainDNS
      - '19195a5b-6da0-11d0-afd3-00c04fd930c9'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
  filter_dc_accounts:
    SubjectUserName|endswith: '$'
  filter_azure_ad_connect:
    SubjectUserName|startswith: 'MSOL_'
  filter_system:
    SubjectUserName: 'SYSTEM'
  condition: selection and not (filter_dc_accounts or filter_azure_ad_connect or filter_system)
falsepositives:
  - Azure AD Connect accounts (MSOL_*)
  - Domain Controller machine accounts (ending in $)
  - Legitimate replication from trusted partner DCs (add to filter_dc_accounts)
level: critical
fields:
  - SubjectUserName
  - SubjectDomainName
  - ComputerName
  - Properties
  - ObjectType
```

---

## Task 3: Complete Test Data Generator

```python
#!/usr/bin/env python3
"""
generate_dcsync_test_data.py
Generates synthetic Windows Event 4662 logs for testing DCSync detection.
"""
import json
import random
import sys
from datetime import datetime, timezone, timedelta

DOMAIN_CONTROLLERS = ["SERVER-DC01$", "SERVER-DC02$"]
WORKSTATIONS       = ["WORKSTATION-042$", "LAPTOP-HR-01$", "ATTACKER-WS01$"]
MSOL_ACCOUNTS      = ["MSOL_abc123def456"]
DOMAIN             = "CORP"
DC_HOSTNAME        = "SERVER-DC01"

DCSYNC_ACCESSES = [
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
]
LEGIT_ACCESSES  = [
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",  # Get-Changes only (no All)
    "{bf967aba-0de6-11d0-a285-00aa003049e2}",    # user class
]
OBJECT_TYPE = "{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
BASE_TIME   = datetime.now(timezone.utc)

def ts(offset_seconds=0):
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat()

def gen_event_4662(subject_user, subject_domain, properties, is_malicious=False):
    return {
        "EventCode": "4662",
        "EventID":   4662,
        "ComputerName": DC_HOSTNAME,
        "SubjectUserName": subject_user,
        "SubjectDomainName": subject_domain,
        "ObjectType": OBJECT_TYPE,
        "Properties": " ".join(properties),
        "_is_malicious_test": is_malicious,
        "_time": ts(random.randint(0, 3600)),
        "sourcetype": "XmlWinEventLog:Security",
    }

def gen_legitimate_replication():
    """DC-to-DC replication — should NOT trigger rule."""
    dc = random.choice(DOMAIN_CONTROLLERS)
    props = [LEGIT_ACCESSES[0]]  # Only Get-Changes, not Get-Changes-All
    return gen_event_4662(dc, DOMAIN, props, is_malicious=False)

def gen_azure_ad_connect():
    """MSOL account sync — should NOT trigger rule."""
    return gen_event_4662(
        MSOL_ACCOUNTS[0], DOMAIN,
        DCSYNC_ACCESSES, is_malicious=False
    )

def gen_dcsync_attack():
    """Attacker from workstation — SHOULD trigger rule."""
    attacker_users = ["hacker", "compromised_user", "contractor01"]
    user = random.choice(attacker_users)
    return gen_event_4662(
        user, DOMAIN,
        DCSYNC_ACCESSES, is_malicious=True
    )

def generate_dataset(total=1000, malicious_ratio=0.05):
    dataset = []
    malicious_count = int(total * malicious_ratio)
    benign_count    = total - malicious_count

    for _ in range(malicious_count):
        dataset.append(gen_dcsync_attack())

    for _ in range(int(benign_count * 0.7)):
        dataset.append(gen_legitimate_replication())
    for _ in range(int(benign_count * 0.3)):
        dataset.append(gen_azure_ad_connect())

    random.shuffle(dataset)
    return dataset

if __name__ == "__main__":
    dataset = generate_dataset(total=1000, malicious_ratio=0.05)
    malicious = [e for e in dataset if e["_is_malicious_test"]]
    benign    = [e for e in dataset if not e["_is_malicious_test"]]
    print(f"Generated {len(dataset)} events: {len(malicious)} malicious, {len(benign)} benign",
          file=sys.stderr)

    for event in dataset:
        clean = {k: v for k, v in event.items() if not k.startswith("_")}
        print(json.dumps(clean))
```

---

## Rule Documentation

```markdown
## Rule: DCSync Attack — AD Replication Rights from Non-DC

**MITRE Technique:** T1003.006 — OS Credential Dumping: DCSync
**Severity:** CRITICAL
**Data Source:** Windows Security Event Log on Domain Controllers
**Event ID:** 4662 (Directory Service Access)
**Schedule:** Real-time or every 5 minutes

**What it detects:**
A non-domain-controller account requesting Active Directory replication rights
(DS-Replication-Get-Changes-All). This is the primary mechanism for DCSync attacks
using tools like Mimikatz or Impacket secretsdump.

**Why it's CRITICAL:**
Successful DCSync gives the attacker password hashes for ALL domain accounts, enabling:
- Pass-the-hash against any account
- Kerberoast any service account offline
- Create Golden Tickets (krbtgt hash) — complete domain compromise
- Persist indefinitely even after password resets

**Known false positives:**
- Azure AD Connect (MSOL_* accounts) — excluded by rule
- Domain Controller machine accounts (ending in $) — excluded by rule
- Third-party backup/sync solutions that replicate AD — add to exclusion list

**Investigation steps when fired:**

1. Identify SubjectUserName — what account made the request?

2. Check ComputerName — which DC received the request?
3. Verify SubjectUserName's recent logon history — is it unusual?
4. Check if Mimikatz or secretsdump output files exist on nearby hosts
5. If confirmed: IMMEDIATELY rotate krbtgt password TWICE (invalidates any Golden Tickets)
6. Rotate all domain admin passwords
7. Review all accounts that have DCSync privileges (check with: Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"})

**Remediation:**
- Rotate compromised account passwords
- Rotate krbtgt password twice (72-hour interval to allow replication)
- Review and reduce accounts with DS-Replication-Get-Changes-All rights
```
