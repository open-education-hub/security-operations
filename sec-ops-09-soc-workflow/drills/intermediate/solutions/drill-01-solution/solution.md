# Solution: Drill 01 (Intermediate) — SOAR Implementation (Malware Hash Enrichment)

## Complete Shuffle Workflow

### Step 1: Webhook Trigger Configuration

```text
Trigger Type: Webhook
Name: edr_malware_alert

Test payload:
{
  "alert_id": "EDR-2026-001",
  "host": "workstation-42",
  "user": "bob.smith",
  "file_path": "C:\\Users\\bob.smith\\Downloads\\invoice.exe",
  "file_hash_sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "file_hash_md5": "44d88612fea8a8f36de82e1278abb02f",
  "process_name": "invoice.exe",
  "parent_process": "explorer.exe",
  "timestamp": "2026-04-06T09:15:33Z",
  "severity": "high",
  "asset_tier": "3"
}
```

### Step 2: VirusTotal Hash Check

```text
App: HTTP
Method: GET
URL: https://www.virustotal.com/api/v3/files/$exec.file_hash_sha256
Headers:
  x-apikey: <your-vt-api-key>
Name: vt_hash_check
```

### Step 3: Calculate Verdict (Python)

```python
# Action: calculate_verdict
import json

vt_raw = $vt_hash_check
vt_data = json.loads(vt_raw) if isinstance(vt_raw, str) else vt_raw

try:
    stats = vt_data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    detection_rate = int((malicious / max(total, 1)) * 100)
except (KeyError, TypeError):
    malicious = 0
    total = 0
    detection_rate = 0
    stats = {}

if detection_rate >= 50:
    verdict = "MALICIOUS"
    thehive_severity = 3
elif detection_rate >= 10:
    verdict = "SUSPICIOUS"
    thehive_severity = 2
else:
    verdict = "CLEAN"
    thehive_severity = 1

return json.dumps({
    "verdict": verdict,
    "detection_rate": detection_rate,
    "malicious_count": malicious,
    "total_engines": total,
    "thehive_severity": thehive_severity
})
```

### Step 4: TheHive Create Alert

```text
App: TheHive
Action: Create Alert

title: "[MALWARE] $exec.process_name on $exec.host - $calculate_verdict.verdict"
description: |
  ## EDR Malware Detection
  Host: $exec.host | User: $exec.user
  File: $exec.file_path
  SHA-256: $exec.file_hash_sha256

  ## VirusTotal
  Verdict: $calculate_verdict.verdict
  Detection Rate: $calculate_verdict.detection_rate%
  Malicious Engines: $calculate_verdict.malicious_count / $calculate_verdict.total_engines

severity: $calculate_verdict.thehive_severity
tags: ["malware", "edr-alert", "auto-enriched"]
type: external
sourceRef: $exec.alert_id
```

---

## Expected Test Results

| Test | SHA-256 | Expected Verdict | TheHive Severity |
|------|---------|-----------------|-----------------|
| EICAR test | `275a021b...` | MALICIOUS | 3 (High) |
| notepad.exe | (system hash) | CLEAN | 1 (Low) |
| Random new hash | (generated) | CLEAN | 1 (Low) |

---

## Bonus: MalwareBazaar Lookup

```python
# Parallel action: malwarebazaar_check
# App: HTTP, Method: POST
# URL: https://mb-api.abuse.ch/api/v1/
# Body: query=get_info&hash=$exec.file_hash_sha256

import json

mb_raw = $malwarebazaar_check
mb_data = json.loads(mb_raw) if isinstance(mb_raw, str) else mb_raw

if mb_data.get("query_status") == "ok":
    info = mb_data.get("data", [{}])[0]
    result = {
        "found": True,
        "malware_name": info.get("signature", "Unknown"),
        "file_type": info.get("file_type", "Unknown"),
        "first_seen": info.get("first_seen", "Unknown")
    }
else:
    result = {"found": False, "malware_name": "Not in MalwareBazaar"}

return json.dumps(result)
```

---

## Common Mistakes

| Mistake | Correct Approach |
|---------|-----------------|
| VT 404 for unknown hash | Catch KeyError; set detection_rate=0 |
| TheHive severity must be integer | Use Python `int()` conversion |
| VT rate limit (429) | Add Wait action: 15000ms before VT call |
| Parse fails on dict | `json.loads(x) if isinstance(x, str) else x` |
