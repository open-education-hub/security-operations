# Drill 01 (Advanced): SIEM Detection Engineering

**Estimated time:** 90 minutes

**Difficulty:** Advanced

**Tools required:** Splunk or Elastic (Docker environment), Python 3.x

## Objective

Build a complete, production-quality detection rule from scratch using the full detection engineering lifecycle: threat research → observable identification → rule writing → testing → tuning → documentation.
You will also convert the rule to Sigma format.

---

## The Threat: DCSync Attack (T1003.006)

**DCSync** is a technique where an attacker mimics a domain controller replication request to extract password hashes for any domain account, including domain administrator accounts.
It does not require local admin access on the DC — only certain AD privileges (typically `DS-Replication-Get-Changes-All`).

Tools that perform DCSync: Mimikatz (`lsadump::dcsync`), Impacket `secretsdump.py`

### Attack Flow

```text
1. Attacker compromises domain user account

2. Attacker grants their account DS-Replication-Get-Changes-All privilege
   (or compromises an account that already has it — e.g., Domain Admin)
3. Attacker's workstation sends DRSUAPI RPC request to the DC
4. DC responds as if it's replicating to another DC — sends password hashes
5. Attacker now has NTLM hashes for all accounts (including krbtgt)
6. Golden ticket attack or pass-the-hash becomes possible
```

### Observable Evidence

DCSync generates **Event ID 4662** on the domain controller:

* Object Type: `domainDNS` (`{19195a5b-6da0-11d0-afd3-00c04fd930c9}`)
* Access: `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes)
* Access: `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All)

The key indicator: the request comes from a **workstation** (not another DC).
Legitimate replication only happens between domain controllers.

---

## Task 1: Research Phase (20 min)

Before writing the rule, research the detection:

1. Look up MITRE ATT&CK T1003.006. What is the primary detection recommendation?
1. Search for existing Sigma rules for DCSync on GitHub (https://github.com/SigmaHQ/sigma)
1. Find the Event ID 4662 documentation on Microsoft's website
1. Identify the specific Access GUIDs that indicate DCSync vs. legitimate replication

**Write a 1-paragraph summary of your research findings.**

---

## Task 2: Write the Detection Logic (25 min)

### 2a: Write the Splunk SPL rule

Requirements:

* Must fire on Event 4662 with DCSync-specific access rights
* Must **exclude** legitimate replication (from known DC machine accounts)
* Must include MITRE technique in output
* Must have a severity field

```spl
# Write your complete Splunk rule here
index=windows EventCode=4662 earliest=-15m
| [complete the rule]
```

### 2b: Write the Sigma YAML rule

Write a complete, valid Sigma rule for DCSync detection:

```yaml
title: [your title]
id: [generate a UUID]
status: [stable/experimental/test]
description: [complete description]
# ... complete all required fields
```

---

## Task 3: Generate Test Data (20 min)

Write a Python script that generates synthetic DCSync event logs for testing your rule.

The script must generate:

1. **True positive events:** DCSync from a workstation (should trigger the rule)
1. **True negative events:** Legitimate DC replication (should NOT trigger the rule)
1. **Mixed dataset:** 90% legit, 10% DCSync (realistic ratio)

```python
#!/usr/bin/env python3
"""
generate_dcsync_test_data.py
Generates synthetic Windows Event 4662 logs for testing DCSync detection.
"""
import json
import random
from datetime import datetime, timezone

# Complete the script
DOMAIN_CONTROLLERS = ["SERVER-DC01$", "SERVER-DC02$"]
WORKSTATIONS = ["WORKSTATION-042$", "LAPTOP-HR-01$"]
DCSYNC_ACCESSES = [
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",  # DS-Replication-Get-Changes
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",  # DS-Replication-Get-Changes-All
]
OBJECT_TYPE = "{19195a5b-6da0-11d0-afd3-00c04fd930c9}"  # domainDNS

def gen_legitimate_replication():
    # TODO: Complete this function
    pass

def gen_dcsync_attack():
    # TODO: Complete this function
    pass

def generate_dataset(total=1000, malicious_ratio=0.05):
    # TODO: Complete this function
    pass

if __name__ == "__main__":
    dataset = generate_dataset(total=1000, malicious_ratio=0.05)
    print(f"Generated {len(dataset)} events")
    # Save to file for Splunk ingestion
```

---

## Task 4: Test and Tune (20 min)

Load your test data into Splunk (use the HEC endpoint from Demo 03) and test your rule.

### Test Procedure

```console
# Send test data to Splunk
python3 generate_dcsync_test_data.py | python3 send_to_splunk.py

# Or use the curl command:
curl -k -X POST http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk demo03-token" \
  -d '{"event": {"EventCode": "4662", ...}, "sourcetype": "xmlwineventlog"}'
```

**Verify:**

* True positive rate: Does your rule catch all 50 simulated DCSync events?
* False positive rate: Does your rule fire on any legitimate replication events?

If you have false positives, add an exclusion and document why.

---

## Task 5: Documentation (5 min)

Write the production documentation for your rule following the template from Guide 04.

---

## Grading Criteria

| Criterion | Points |
|-----------|--------|
| SPL rule correctly identifies DCSync GUIDs | 20 |
| SPL rule correctly excludes legitimate replication | 15 |
| Sigma rule is syntactically valid | 15 |
| Test data script generates correct true positives | 20 |
| Test data script generates correct true negatives | 10 |
| Zero false positives on test data | 10 |
| Documentation is complete | 10 |

See `../solutions/drill-01-solution/README.md` for complete reference implementation.
