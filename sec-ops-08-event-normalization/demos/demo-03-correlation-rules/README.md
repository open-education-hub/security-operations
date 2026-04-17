# Demo 03: Writing Correlation Rules in Splunk and Sigma

**Duration:** ~50 minutes

**Difficulty:** Intermediate

**Prerequisites:** Docker, Splunk trial license (or Splunk free), and pySigma installed

---

## Overview

In this demo you will write detection correlation rules in two formats:

1. **Splunk SPL** — rules deployed directly into Splunk Enterprise Security
1. **Sigma YAML** — portable rules that compile to any SIEM's query language

You will implement four common detection scenarios:

* **Rule A**: Brute force login detection (threshold-based)
* **Rule B**: Reconnaissance scan detection (statistical cardinality)
* **Rule C**: Lateral movement sequence detection (multi-event sequence)
* **Rule D**: PowerShell encoded command execution (single-event IOC)

---

## Part 1: Splunk Rules

### Environment

```bash
# Start Splunk in Docker (free tier: 500 MB/day)
docker run -d \
  --name demo03-splunk \
  -p 8000:8000 \
  -p 8088:8088 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='SplunkDemo123!' \
  splunk/splunk:9.2

# Wait ~2 minutes for Splunk to start
docker logs -f demo03-splunk | grep "Splunk is started"

# Open Splunk: http://localhost:8000
# Login: admin / SplunkDemo123!
```

### Loading Sample Data

```bash
# Copy sample data into the container
docker cp sample-data/auth_events.csv demo03-splunk:/tmp/
docker cp sample-data/network_events.csv demo03-splunk:/tmp/
docker cp sample-data/process_events.csv demo03-splunk:/tmp/

# Index the data via Splunk CLI
docker exec demo03-splunk /opt/splunk/bin/splunk add oneshot \
  /tmp/auth_events.csv \
  -index security \
  -sourcetype csv_auth \
  -auth admin:SplunkDemo123!
```

### sample-data/auth_events.csv

```csv
_time,src_ip,dest_ip,user,action,failure_reason
2024-12-14T07:40:00Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:05Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:10Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:15Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:20Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:25Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:30Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:35Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:40Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:45Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:40:50Z,203.0.113.42,10.0.0.5,administrator,failed,wrong_password
2024-12-14T07:41:00Z,203.0.113.42,10.0.0.5,administrator,success,
2024-12-14T08:00:00Z,10.0.1.100,10.0.0.5,jdoe,failed,wrong_password
2024-12-14T08:00:30Z,10.0.1.100,10.0.0.5,jdoe,failed,wrong_password
2024-12-14T08:01:00Z,10.0.1.100,10.0.0.5,jdoe,success,
```

### sample-data/network_events.csv

```csv
_time,src_ip,dest_ip,dest_port,action,bytes
2024-12-14T07:00:00Z,10.0.2.50,192.168.1.1,80,allow,1024
2024-12-14T07:00:01Z,10.0.2.50,192.168.1.1,443,allow,2048
2024-12-14T07:00:02Z,10.0.2.50,192.168.1.1,22,deny,0
2024-12-14T07:00:03Z,10.0.2.50,192.168.1.2,80,deny,0
2024-12-14T07:00:04Z,10.0.2.50,192.168.1.3,80,deny,0
2024-12-14T07:00:05Z,10.0.2.50,192.168.1.4,80,deny,0
2024-12-14T07:00:06Z,10.0.2.50,192.168.1.5,80,deny,0
2024-12-14T07:00:07Z,10.0.2.50,192.168.1.6,80,deny,0
2024-12-14T07:00:08Z,10.0.2.50,192.168.1.7,80,deny,0
2024-12-14T07:00:09Z,10.0.2.50,192.168.1.8,80,deny,0
2024-12-14T07:00:10Z,10.0.2.50,192.168.1.9,443,deny,0
2024-12-14T07:00:11Z,10.0.2.50,192.168.1.10,8080,deny,0
2024-12-14T07:00:12Z,10.0.2.50,192.168.1.11,8443,deny,0
```

### sample-data/process_events.csv

```csv
_time,host,user,process_name,parent_process,command_line,pid,ppid
2024-12-14T07:41:05Z,WORKSTATION01,administrator,cmd.exe,explorer.exe,cmd.exe,1234,800
2024-12-14T07:41:06Z,WORKSTATION01,administrator,net.exe,cmd.exe,"net user /domain",1235,1234
2024-12-14T07:41:07Z,WORKSTATION01,administrator,net.exe,cmd.exe,"net group ""Domain Admins"" /domain",1236,1234
2024-12-14T07:41:10Z,WORKSTATION01,administrator,powershell.exe,cmd.exe,"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQB5AHMAXQA3ADUAMQAU",1237,1234
2024-12-14T07:41:11Z,WORKSTATION01,administrator,whoami.exe,cmd.exe,whoami /all,1238,1234
```

---

### Rule A: Brute Force Detection (SPL)

```splunk
| tstats count AS failure_count
    WHERE index=security sourcetype=csv_auth action=failed
    BY src_ip, user, span=5m
| where failure_count > 10
| eval
    alert_name = "Brute Force Login Attempt",
    severity = case(failure_count > 50, "critical",
                    failure_count > 20, "high",
                    true(), "medium"),
    mitre_technique = "T1110"
| table _time, src_ip, user, failure_count, severity, alert_name, mitre_technique
| sort -failure_count
```

### Rule A Extended: Brute Force Followed by Success

```splunk
index=security sourcetype=csv_auth
| eval bucket_5m = floor(_time/300)*300
| stats
    count(eval(action="failed")) AS fail_count
    count(eval(action="success")) AS success_count
    BY bucket_5m, src_ip, user
| where fail_count > 5 AND success_count > 0
| eval
    alert_name = "Brute Force Succeeded",
    severity = "high",
    mitre_technique = "T1110"
    _time = bucket_5m
| table _time, src_ip, user, fail_count, success_count, alert_name, severity
```

---

### Rule B: Port Scan / Reconnaissance Detection (SPL)

```splunk
index=security sourcetype=csv_network
| bucket _time span=1m
| stats
    dc(dest_ip)   AS unique_dest_ips
    dc(dest_port) AS unique_dest_ports
    count         AS total_connections
    BY _time, src_ip
| where unique_dest_ips > 20 OR unique_dest_ports > 50
| eval
    scan_type = case(
        unique_dest_ips > 20 AND unique_dest_ports > 10, "combined_scan",
        unique_dest_ips > 20, "horizontal_scan",
        unique_dest_ports > 50, "vertical_scan",
        true(), "unknown"),
    alert_name = "Reconnaissance Scan Detected",
    severity = "medium",
    mitre_technique = "T1046"
| table _time, src_ip, unique_dest_ips, unique_dest_ports, scan_type, alert_name, mitre_technique
```

---

### Rule C: Lateral Movement Sequence (SPL with Transaction)

```splunk
(index=security sourcetype=csv_auth action=success) OR
(index=security sourcetype=csv_network) OR
(index=security sourcetype=csv_process)
| eval event_type = case(
    sourcetype="csv_auth" AND action="success", "auth_success",
    sourcetype="csv_network" AND dest_port IN (445, 139), "smb_connection",
    sourcetype="csv_process" AND process_name IN ("net.exe","net1.exe","whoami.exe"), "discovery_tool",
    true(), "other")
| where event_type != "other"
| transaction host maxspan=10m maxpause=2m startswith="auth_success"
| where eventcount >= 3
  AND match(_raw, "auth_success")
  AND match(_raw, "discovery_tool")
| eval
    alert_name = "Suspected Lateral Movement",
    severity = "high",
    mitre_tactics = "Lateral Movement, Discovery"
| table _time, host, src_ip, user, eventcount, alert_name, severity, mitre_tactics
```

---

### Rule D: PowerShell Encoded Command (SPL)

```splunk
index=security sourcetype=csv_process process_name="powershell.exe"
| regex command_line="(?i)(-enc|-encodedCommand|-EncodedCommand)\s+[A-Za-z0-9+/]{50,}"
| eval
    b64_payload = replace(command_line, "(?i).*(?:-enc|-encodedCommand)\s+", ""),
    decoded_preview = urldecode(b64_payload),
    alert_name = "PowerShell Encoded Command Execution",
    severity = "high",
    mitre_technique = "T1059.001",
    mitre_tactic = "Execution"
| table _time, host, user, process_name, parent_process, alert_name, severity, mitre_technique
| sort -_time
```

---

## Part 2: Sigma Rules

### Install pySigma

```console
pip install pySigma pySigma-backend-splunk pySigma-backend-elasticsearch pySigma-pipeline-sysmon
sigma --version
```

### sigma-rules/rule_A_brute_force.yml

```yaml
title: SSH Brute Force Attack
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: |
  Detects a brute force attack against SSH by identifying multiple failed
  authentication attempts from the same source IP within a short time window.
  Based on MITRE ATT&CK T1110 - Brute Force.
references:
  - https://attack.mitre.org/techniques/T1110/
  - https://www.elastic.co/guide/en/siem/guide/current/potential-ssh-brute-force.html
author: SOC Team
date: 2024/12/14
modified: 2024/12/14
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.001
logsource:
  category: authentication
  product: linux
detection:
  selection:
    event.outcome: failure
    event.category: authentication
    process.name: sshd
  timeframe: 5m
  condition: selection | count() by source.ip > 10
fields:
  - source.ip
  - user.name
  - host.name
falsepositives:
  - Automated deployment tools using password authentication
  - Security scanners
  - Legitimate users who have forgotten their password
level: medium
```

### sigma-rules/rule_B_recon_scan.yml

```yaml
title: Network Port Scan Detected
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
description: |
  Detects a network port scan by identifying a single source IP connecting to
  an unusually high number of distinct destination ports within one minute.
  This pattern is consistent with MITRE ATT&CK T1046 - Network Service Scanning.
references:
  - https://attack.mitre.org/techniques/T1046/
author: SOC Team
date: 2024/12/14
tags:
  - attack.discovery
  - attack.t1046
logsource:
  category: firewall
  product: generic
detection:
  selection:
    event.category: network
  timeframe: 1m
  condition: selection | count(destination.port) by source.ip > 50
fields:
  - source.ip
  - destination.ip
  - destination.port
falsepositives:
  - Vulnerability scanners (Nessus, OpenVAS)
  - Network discovery tools (Nmap)
  - Asset management tools
level: medium
```

### sigma-rules/rule_C_powershell_encoded.yml

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
description: |
  Detects PowerShell execution with encoded commands using the -EncodedCommand
  or -enc parameter. Attackers frequently encode commands to bypass simple
  string-based detection. This matches MITRE ATT&CK T1059.001.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://lolbas-project.github.io/lolbas/Binaries/Powershell/
author: SOC Team
date: 2024/12/14
modified: 2024/12/14
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
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
      - ' -enc '
      - ' -EncodedCommand '
      - ' -encodedcommand '
  filter_legitimate_b64:
    # Exclude very short base64 strings that are unlikely to be malicious
    CommandLine|re: '(?i)-enc\s+[A-Za-z0-9+/]{200,}={0,2}'
  condition: selection_image and selection_encoded and not filter_legitimate_b64
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - ComputerName
falsepositives:
  - Software installers that use encoded PS commands (document specific known-good)
  - SCCM/Intune management tools
  - Backup software
level: high
```

### sigma-rules/rule_D_lateral_movement.yml

```yaml
title: Potential Lateral Movement via Remote Execution
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: |
  Detects potential lateral movement by correlating a successful remote
  authentication with subsequent remote service execution commands on the
  target host. This is consistent with T1021 - Remote Services.
references:
  - https://attack.mitre.org/techniques/T1021/
author: SOC Team
date: 2024/12/14
tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.t1021.002
logsource:
  product: windows
  service: security
detection:
  # Event 1: Successful network logon (Type 3)
  logon_success:
    EventID: 4624
    LogonType: 3
  # Event 2: Service installation shortly after
  service_install:
    EventID: 7045
  timeframe: 5m
  condition: logon_success | near service_install by ComputerName
fields:
  - ComputerName
  - TargetUserName
  - IpAddress
  - ServiceName
falsepositives:
  - Legitimate remote administration (SCCM, Ansible, remote backup)
  - IT ops deploying services during maintenance windows
level: high
```

---

### Compiling Sigma Rules to SIEM Queries

```bash
# Convert to Splunk SPL
sigma convert \
  -t splunk \
  -p splunk_windows \
  sigma-rules/rule_C_powershell_encoded.yml

# Expected output:
# (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") CommandLine IN (" -enc ", " -EncodedCommand ", " -encodedcommand ") NOT (CommandLine regex "(?i)-enc\s+[A-Za-z0-9+/]{200,}={0,2}")

# Convert to Elasticsearch/KQL
sigma convert \
  -t elasticsearch \
  -p ecs_windows \
  sigma-rules/rule_C_powershell_encoded.yml

# Convert to Microsoft Sentinel KQL
sigma convert \
  -t microsoft365defender \
  sigma-rules/rule_C_powershell_encoded.yml

# Batch convert all rules to Splunk
sigma convert \
  -t splunk \
  -p splunk_windows \
  -o compiled_splunk_rules.conf \
  sigma-rules/*.yml

# List available backends
sigma list backends

# List available pipelines
sigma list pipelines
```

---

## Part 3: Cross-Validation

After converting Sigma rules, validate them by running the compiled queries against your sample data in Splunk:

```console
# Run compiled SPL rule against Splunk
curl -s -k \
  -u 'admin:SplunkDemo123!' \
  -X POST 'https://localhost:8089/services/search/jobs' \
  -d "search=search index=security sourcetype=csv_process (Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\pwsh.exe\") CommandLine IN (\" -enc \", \" -EncodedCommand \")" \
  -d 'output_mode=json'
```

---

## Key Takeaways

1. SPL is powerful for interactive investigation but is Splunk-proprietary.
1. Sigma rules are portable — write once, deploy anywhere by compiling to the target SIEM language.
1. Always tag Sigma rules with ATT&CK tactics and techniques for coverage mapping.
1. The `status` field in Sigma tracks rule maturity: `experimental` → `test` → `stable`.
1. False positive documentation in Sigma rules enables future tuning decisions.
1. Sequence-based rules (lateral movement) require understanding of Splunk transaction or SIEM join capabilities.
