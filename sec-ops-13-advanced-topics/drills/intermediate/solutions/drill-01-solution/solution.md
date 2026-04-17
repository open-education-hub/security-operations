# Solution: Write a Sigma Detection Rule

**Drill:** Intermediate Drill 01 — Detection Rule Writing

**Session:** 13 — Advanced Topics in Security Operations

---

## Task 1 — Log Analysis Script

```python
#!/usr/bin/env python3
import json
from collections import Counter

with open("/data/windows_events.json") as f:
    events = json.load(f)

print(f"Total events: {len(events)}")

# All unique images
images = Counter(e.get("Image","").split("\\")[-1].lower() for e in events)
print("\nUnique process images:")
for img, count in images.most_common():
    print(f"  {img:40s} {count}")

# CertUtil events
print("\n--- CertUtil events ---")
for e in events:
    if e.get("Image","").lower().endswith("certutil.exe"):
        print(f"  [{e['TimeCreated']}] {e['CommandLine']}")

# WScript events
print("\n--- WScript events ---")
for e in events:
    if e.get("Image","").lower().endswith("wscript.exe"):
        print(f"  [{e['TimeCreated']}] {e['CommandLine']}")

# Office → shell chains
OFFICE = ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mspub.exe")
SHELLS = ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe")
print("\n--- Office → Shell chains ---")
for e in events:
    parent = e.get("ParentImage","").lower().split("\\")[-1]
    child  = e.get("Image","").lower().split("\\")[-1]
    if parent in OFFICE and child in SHELLS:
        print(f"  {parent} → {child}")
        print(f"    CMD: {e['CommandLine']}")
```

**Expected findings:**

* 4 certutil events, all using `-urlcache -split -f <http://...>` pattern
* 2 wscript events executing `.vbs` files from `C:\Temp\`
* 2 Office→shell chains: `WINWORD.EXE` → `cmd.exe` → `certutil.exe` (grandchild)

---

## Task 2 — CertUtil Download Rule

```yaml
# /tmp/rule_certutil_download.yml
title: CertUtil Used for File Download
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects certutil.exe being used to download files from remote URLs using
  the -urlcache flag. This is a common Living-off-the-Land technique for
  bypassing application whitelisting and downloading malware payloads.
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/techniques/T1218/
author: SOC Team
date: 2024/11/15
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|any:
      - '-urlcache'
      - '-verifyctl'
      - 'http://'
      - 'https://'
  filter_legitimate:
    CommandLine|contains:
      - 'microsoft.com'
      - 'windows.com'
  condition: selection and not filter_legitimate
falsepositives:
  - Software deployment tools using certutil to verify Microsoft certificate chains
  - Windows Update certificate validation
level: high
```

**Note on the filter:** The `filter_legitimate` block is initially absent in Task 2 and added in Task 5.
Present both versions.

---

## Task 3 — Office Macro Shell Spawn Rule

```yaml
# /tmp/rule_office_macro_shell.yml
title: Office Application Spawning Command Shell
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
description: >
  Detects Microsoft Office applications spawning command interpreters or
  scripting engines. This behaviour is characteristic of malicious macro
  execution following a spearphishing email with a weaponised attachment.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/001/
author: SOC Team
date: 2024/11/15
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1059.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith|any:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
      - '\MSPUB.EXE'
  selection_child:
    Image|endswith|any:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  condition: all of selection_*
falsepositives:
  - Legitimate Office Add-ins that launch command-line tools (rare)
  - Macro-enabled templates used by IT departments (should be whitelisted)
level: critical
```

---

## Task 4 — Python Rule Tester

```python
#!/usr/bin/env python3
# /tmp/rule_tester.py
import json
import yaml
from pathlib import Path

def load_rule(path):
    with open(path) as f:
        return yaml.safe_load(f)

def field_matches(record, field_expr, value):
    """Evaluate a single field|modifier condition against a record."""
    parts = field_expr.split("|")
    field = parts[0]
    modifiers = parts[1:]

    record_val = record.get(field, "") or ""

    if "any" in modifiers:
        # value is a list; any element must match
        values = value if isinstance(value, list) else [value]
        return any(field_matches(record, "|".join([field] + [m for m in modifiers if m != "any"]), v) for v in values)

    if isinstance(value, list):
        # Without 'any', it's an AND — all must match (rare but valid)
        return all(field_matches(record, field_expr, v) for v in value)

    str_val = str(record_val)

    if "endswith" in modifiers:
        return str_val.lower().endswith(str(value).lower())
    if "startswith" in modifiers:
        return str_val.lower().startswith(str(value).lower())
    if "contains" in modifiers:
        return str(value).lower() in str_val.lower()
    if "re" in modifiers:
        import re
        return bool(re.search(value, str_val, re.IGNORECASE))

    # exact match
    return str_val.lower() == str(value).lower()

def evaluate_selection(record, selection):
    """All conditions in selection must be True (AND logic)."""
    for field_expr, value in selection.items():
        if not field_matches(record, field_expr, value):
            return False
    return True

def evaluate_rule(record, rule):
    detection = rule.get("detection", {})
    condition_str = detection.get("condition", "")

    # Evaluate all named blocks
    block_results = {}
    for name, block in detection.items():
        if name == "condition":
            continue
        if isinstance(block, dict):
            block_results[name] = evaluate_selection(record, block)
        elif isinstance(block, list):
            # List of dicts — treat as OR
            block_results[name] = any(
                evaluate_selection(record, item) if isinstance(item, dict) else False
                for item in block
            )
        else:
            block_results[name] = False

    # Parse condition
    # Supports: "selection", "all of selection_*", "selection and not filter"
    if condition_str == "selection":
        return block_results.get("selection", False)

    if "all of selection_*" in condition_str:
        sel_blocks = [v for k, v in block_results.items() if k.startswith("selection")]
        return all(sel_blocks)

    if " and not " in condition_str:
        parts = condition_str.split(" and not ")
        pos_block = parts[0].strip()
        neg_block = parts[1].strip()
        return block_results.get(pos_block, False) and not block_results.get(neg_block, False)

    return block_results.get("selection", False)

# Load rules and events
rules = [load_rule("/tmp/rule_certutil_download.yml"),
         load_rule("/tmp/rule_office_macro_shell.yml")]

with open("/data/windows_events.json") as f:
    events = json.load(f)

print(f"{'TIME':25s} {'HOSTNAME':20s} {'USER':20s} {'IMAGE':30s} {'RULE'}")
print("-" * 120)
total_matches = 0
for event in events:
    for rule in rules:
        if evaluate_rule(event, rule):
            image = event.get("Image","").split("\\")[-1]
            print(f"{event.get('TimeCreated','?'):25s} "
                  f"{event.get('Hostname','?'):20s} "
                  f"{event.get('User','?'):20s} "
                  f"{image:30s} "
                  f"{rule['title']}")
            total_matches += 1

print(f"\nTotal matches: {total_matches}")
```

---

## Task 5 — Filter Tuning

The original certutil rule may match a legitimate Windows Defender update process:

```text
certutil.exe -urlcache -split -f https://www.microsoft.com/pkiops/certs/...
```

The filter already added in the Task 2 solution above handles this:

```yaml
  filter_legitimate:
    CommandLine|contains:
      - 'microsoft.com'
      - 'windows.com'
  condition: selection and not filter_legitimate
```

**Updated rule comment:**

```yaml
# filter_legitimate: Excludes certutil calls to Microsoft PKI infrastructure
# (certificate chain updates via Windows Update). These are initiated by
# the Windows CryptSvc service and are expected in enterprise environments.
```

After adding the filter, re-run `rule_tester.py` and confirm the Windows Update certutil calls no longer appear in the match output.

---

## Common Mistakes

1. **Using AND logic when OR is needed** — For `CommandLine|contains|any:` you need the `any` modifier. Without it, Sigma requires ALL listed values to be in the command line simultaneously, which is usually not what you want.

1. **Missing `all of selection_*`** — When using named selection blocks (e.g., `selection_parent`, `selection_child`), you must use `all of selection_*` in the condition, not just `selection`.
1. **Case sensitivity** — Sigma is case-insensitive by default. In Python testing, use `.lower()` for comparisons.
1. **Overly broad conditions** — Detecting `certutil.exe` alone (without command-line conditions) will generate thousands of false positives in environments with active certificate management.

---

## Scoring Guide

| Criterion | Full marks if... |
|-----------|-----------------|
| Task 1 (20 pts) | All certutil/wscript events found; at least 1 Office→shell chain identified |
| Task 2 (20 pts) | Valid YAML; correct logsource; CommandLine conditions use `\|contains\|any:` |
| Task 3 (20 pts) | Valid YAML; uses `all of selection_*`; both parent and child lists complete |
| Task 4 (25 pts) | Script handles all modifier types; correctly matches ≥ 3 events per rule |
| Task 5 (15 pts) | Filter added with `and not`; comment explains what is excluded and why |
