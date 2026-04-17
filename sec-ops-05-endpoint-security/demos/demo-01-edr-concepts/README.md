# Demo 01: EDR Concepts — Understanding Endpoint Telemetry

## Overview

This demo walks through the **categories of telemetry** that EDR platforms capture.
Because we cannot install a commercial EDR agent in a classroom environment, we simulate the data using a Python-based event generator inside Docker, and analyze the resulting events.

**What you will learn:**

* What data EDR agents collect and why each category matters
* How to read and interpret EDR-style telemetry events
* How individual events chain together to tell a complete attack story
* The difference between a true positive and a benign event

**Time required:** 30 minutes

**Prerequisites:** Docker installed, basic command-line familiarity

---

## Architecture

```text
┌────────────────────────────────────────────────────────┐
│                  Docker Container                       │
│                                                         │
│  Python Event Generator                                 │
│  (simulates EDR telemetry for attack scenario)          │
│         │                                               │
│         ▼                                               │
│  event_log.jsonl  ← append-only JSON events             │
│         │                                               │
│         ▼                                               │
│  Python Analyzer                                        │
│  (parses events, shows attack timeline, IoCs)           │
└────────────────────────────────────────────────────────┘
```

---

## Files

```text
demo-01-edr-concepts/
├── docker-compose.yml
├── Dockerfile
├── edr_simulator.py       ← generates synthetic EDR events
├── edr_analyzer.py        ← analyzes and displays events
├── sample_events.jsonl    ← pre-generated events for the demo
└── README.md              ← this file
```

---

## Step 1: Understand the Sample Events

The file `sample_events.jsonl` contains EDR telemetry from a simulated attack.
Each line is a JSON object representing one event.
This mirrors how real EDR platforms store and forward telemetry.

### Event Categories in the Sample Data

Open `sample_events.jsonl` and note the different event types:

```text
process_create   — a new process was started
network_connect  — a process made a network connection
file_create      — a file was written to disk
registry_set     — a registry value was modified
dns_query        — a DNS lookup was performed
process_access   — one process accessed another's memory
script_execute   — a scripting engine ran code
```

---

## Step 2: Run the Demo

```console
# Build and start the container
docker-compose up --build

# The analyzer will print the attack timeline automatically
# To run interactively:
docker-compose run edr-demo bash
python3 edr_analyzer.py --mode timeline
python3 edr_analyzer.py --mode ioc
python3 edr_analyzer.py --mode hunt --query "powershell"
```

---

## Step 3: Walk Through the Attack Timeline

The sample events represent a realistic spear-phishing attack.
Let's walk through each stage:

### Stage 1: Initial Access — Malicious Word Document

```json
{
  "timestamp": "2024-03-15T14:20:01.123Z",
  "event_type": "process_create",
  "hostname": "WORKSTATION01",
  "user": "corp\\jdoe",
  "process": {
    "pid": 3120,
    "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "command_line": "\"WINWORD.EXE\" /n \"C:\\Users\\jdoe\\Downloads\\invoice_march.docm\"",
    "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "parent_pid": 2104,
    "md5": "A1B2C3D4E5F67890ABCDEF1234567890",
    "sha256": "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
  },
  "mitre_technique": "T1566.001",
  "severity": "info"
}
```

**Analysis:** Word opened a `.docm` file (macro-enabled document) from the Downloads folder, launched from Outlook.
This alone is not suspicious — but it sets the scene.

### Stage 2: Execution — Macro Spawns PowerShell

```json
{
  "timestamp": "2024-03-15T14:20:15.456Z",
  "event_type": "process_create",
  "hostname": "WORKSTATION01",
  "user": "corp\\jdoe",
  "process": {
    "pid": 4592,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==",
    "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "parent_pid": 3120,
    "current_directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\"
  },
  "mitre_technique": "T1059.001",
  "severity": "critical"
}
```

**Analysis — RED FLAGS:**

1. `powershell.exe` spawned by `WINWORD.EXE` — macro execution
1. `-nop` (NoProfile): skips profile scripts to avoid detection
1. `-w hidden` (WindowStyle Hidden): no visible window
1. `-enc`: Base64-encoded command (obfuscation)
1. Current directory is `%TEMP%` — staging area

**Decode the Base64 command:**

```console
echo "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==" | base64 -d | iconv -f utf-16le
# Output: $client = New-Object System.Net.WebClient
```

### Stage 3: C2 Callback — DNS and Network

```json
{
  "timestamp": "2024-03-15T14:20:18.789Z",
  "event_type": "dns_query",
  "hostname": "WORKSTATION01",
  "process": {
    "pid": 4592,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  },
  "dns": {
    "query": "update.microsoft-cdn-delivery.com",
    "query_type": "A",
    "response": "185.234.219.47"
  },
  "mitre_technique": "T1071.004",
  "severity": "high"
}
```

```json
{
  "timestamp": "2024-03-15T14:20:19.012Z",
  "event_type": "network_connect",
  "hostname": "WORKSTATION01",
  "process": {
    "pid": 4592,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  },
  "network": {
    "destination_ip": "185.234.219.47",
    "destination_port": 443,
    "protocol": "TCP",
    "direction": "outbound",
    "bytes_sent": 0,
    "bytes_received": 45312
  },
  "mitre_technique": "T1071.001",
  "severity": "high"
}
```

**Analysis:** PowerShell resolved a domain that **looks legitimate** (`microsoft-cdn-delivery.com`) but is attacker-controlled.
It then made an HTTPS connection and downloaded 45KB — likely the second-stage payload.

### Stage 4: Payload Dropped to Disk

```json
{
  "timestamp": "2024-03-15T14:20:22.345Z",
  "event_type": "file_create",
  "hostname": "WORKSTATION01",
  "process": {
    "pid": 4592,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  },
  "file": {
    "path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\WinUpdate.exe",
    "size_bytes": 45312,
    "md5": "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
    "sha256": "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE",
    "is_pe": true,
    "signed": false,
    "vt_detections": "47/72"
  },
  "mitre_technique": "T1105",
  "severity": "critical"
}
```

**Analysis — RED FLAGS:**

1. PE (executable) written to `%TEMP%` — classic staging location
1. Unsigned binary
1. VirusTotal shows 47/72 engines detect it as malicious

### Stage 5: Persistence — Registry Run Key

```json
{
  "timestamp": "2024-03-15T14:20:25.678Z",
  "event_type": "registry_set",
  "hostname": "WORKSTATION01",
  "process": {
    "pid": 5891,
    "image": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\WinUpdate.exe",
    "parent_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  },
  "registry": {
    "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "WindowsUpdateHelper",
    "value_data": "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\wuhelper.exe",
    "operation": "SetValue"
  },
  "mitre_technique": "T1547.001",
  "severity": "critical"
}
```

**Analysis:** The malware added itself to the Registry Run key for persistence.
Note how it:

1. Chose a convincing name ("WindowsUpdateHelper")
1. Copied itself to `AppData\Roaming\Microsoft\` (looks like a legitimate MS app location)

### Stage 6: Credential Theft — LSASS Access

```json
{
  "timestamp": "2024-03-15T14:22:01.901Z",
  "event_type": "process_access",
  "hostname": "WORKSTATION01",
  "process": {
    "pid": 5891,
    "image": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\WinUpdate.exe"
  },
  "target": {
    "pid": 648,
    "image": "C:\\Windows\\System32\\lsass.exe",
    "access_mask": "0x1FFFFF",
    "access_description": "PROCESS_ALL_ACCESS"
  },
  "mitre_technique": "T1003.001",
  "severity": "critical"
}
```

**Analysis:** The malware requested `PROCESS_ALL_ACCESS` on `lsass.exe`.
This is the standard behavior of credential dumping tools like Mimikatz.
The access mask `0x1FFFFF` means it wants full control of the LSASS process, enabling it to read password hashes and Kerberos tickets from memory.

---

## Step 4: Correlate the Events — The Attack Chain

```text
[14:20:01] WINWORD.EXE ← Outlook         [Stage: Initial Access]
     │
     ▼
[14:20:15] powershell.exe -enc ...        [Stage: Execution / T1059.001]
     │
     ├─ [14:20:18] DNS: update.microsoft-cdn-delivery.com  [T1071.004]
     │
     └─ [14:20:19] TCP:185.234.219.47:443  45KB download   [T1071.001]
              │
              ▼
         [14:20:22] C:\...\Temp\WinUpdate.exe (dropped)    [T1105]
              │
              ├─ [14:20:25] HKCU\Run\WindowsUpdateHelper   [T1547.001]
              │
              └─ [14:22:01] lsass.exe PROCESS_ALL_ACCESS   [T1003.001]
```

**This is exactly how EDR platforms construct an "incident storyline."**

---

## Step 5: Identify Indicators of Compromise (IoCs)

From the telemetry above, we extract these IoCs:

| Type | Value | Confidence |
|------|-------|-----------|
| SHA256 hash | `DEADBEEFDEADBEEF...` | High |
| MD5 hash | `DEADBEEFDEADBEEF` | High |
| IP address | `185.234.219.47` | High |
| Domain | `update.microsoft-cdn-delivery.com` | High |
| File path | `%TEMP%\WinUpdate.exe` | Medium |
| Registry key | `HKCU\...\Run\WindowsUpdateHelper` | Medium |
| Parent-child | `WINWORD.EXE` → `powershell.exe` | High |

These IoCs can be fed into:

1. Your SIEM for retrospective search (did any other hosts connect to this IP?)
1. Your firewall for blocking
1. Your EDR for fleet-wide hunting
1. Threat intelligence platforms for enrichment

---

## Docker Setup

### docker-compose.yml

```yaml
version: '3.8'
services:
  edr-demo:
    build: .
    container_name: edr-concepts-demo
    volumes:
      - ./sample_events.jsonl:/app/sample_events.jsonl:ro
    command: python3 edr_analyzer.py --mode timeline
```

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY edr_analyzer.py sample_events.jsonl ./
RUN pip install rich
CMD ["python3", "edr_analyzer.py", "--mode", "timeline"]
```

---

## Key Takeaways

1. **EDR telemetry tells a story.** Individual events may not be alarming, but chaining them reveals the full attack.

1. **Context is everything.** `powershell.exe` running is normal. `WINWORD.EXE` spawning `powershell.exe -enc` is not.

1. **The four most critical event types for detection:**
   * Process creation (with parent context)
   * Network connections (per-process)
   * File creation in temp/user-writable paths
   * LSASS memory access

1. **EDR vs AV:** AV would only detect `WinUpdate.exe` if it had a signature. EDR detected the attack at Stage 2 (PowerShell with encoded command) — before the file was even written to disk.

1. **MITRE ATT&CK mapping** allows you to communicate about this attack precisely and compare it to other incidents.
