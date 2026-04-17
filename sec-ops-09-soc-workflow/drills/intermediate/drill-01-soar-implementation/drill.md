# Drill 01 (Intermediate): Implement a Basic SOAR Automation

**Level**: Intermediate

**Estimated time**: 90-120 minutes

**Type**: Hands-on lab

**Prerequisites**: Shuffle SOAR running (Demo 03); TheHive running (Demo 04); VirusTotal API key

---

## Learning Objectives

* Build a complete SOAR workflow from scratch in Shuffle
* Handle real API responses and extract data using JSONPath
* Implement conditional branching based on enrichment results
* Create cases in TheHive programmatically
* Test and debug a SOAR workflow end-to-end

---

## Scenario: Malware Hash Enrichment Automation

Your SOC receives multiple alerts per day where an EDR detects a suspicious file.
The current manual process takes ~12 minutes per alert:

1. Analyst copies the file hash from the alert (2 min)
1. Analyst manually queries VirusTotal (2 min)
1. Analyst queries MalwareBazaar (2 min)
1. Analyst looks up file metadata (2 min)
1. Analyst writes up findings in TheHive case (4 min)

**Your task**: Build a Shuffle SOAR workflow that automates steps 1-5.

---

## Technical Specification

### Input (webhook payload)

Your workflow will receive this JSON when triggered:

```json
{
  "alert_id": "EDR-2026-001",
  "detection_type": "malware_detection",
  "host": "workstation-42",
  "user": "bob.smith",
  "file_path": "C:\\Users\\bob.smith\\Downloads\\invoice.exe",
  "file_hash_md5": "44d88612fea8a8f36de82e1278abb02f",
  "file_hash_sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "process_name": "invoice.exe",
  "parent_process": "explorer.exe",
  "timestamp": "2026-04-06T09:15:33Z",
  "severity": "high",
  "asset_tier": "3"
}
```

(Note: The SHA-256 hash above is EICAR test string hash — safe for VT testing)

### Expected workflow output

A TheHive alert with:

* Title: `[MALWARE] invoice.exe on workstation-42 - [verdict]`
* Severity: Based on VT score
* Description: Formatted report with VT results, file metadata
* Observables: SHA-256 hash, MD5 hash, file path
* Tags: Based on VT categories detected

---

## Required Workflow Steps

Build a workflow with at least these actions:

1. **Webhook trigger** — receives the EDR alert
1. **VirusTotal hash check** — query VT for the SHA-256
1. **Calculate verdict** (Python) — determine malicious/suspicious/clean
1. **Condition branch** — route based on verdict
1. **TheHive: Create Alert** — create case with enrichment data
1. **Shuffle Tools: Wait** (optional) — handle VT rate limits

### Bonus objectives (additional credit):

* Add MalwareBazaar lookup as a parallel action
* Add a Slack notification for MALICIOUS verdicts
* Add retry logic for VT rate limit errors
* Add observable tagging (IOC = true for MALICIOUS, false for CLEAN)

---

## Testing Requirements

### Test Case 1: Malicious hash

Use the EICAR test hash (detected by all AV engines):

```text
SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Expected: Verdict = MALICIOUS; TheHive alert severity = High (3)

### Test Case 2: Clean hash

Use a known clean system file hash (get from a Windows system):

```console
# On Windows:
Get-FileHash C:\Windows\System32\notepad.exe -Algorithm SHA256
```

Expected: Verdict = CLEAN; TheHive alert severity = Low (1)

### Test Case 3: Unknown hash

Create a hash of a new random file:

```console
echo "test content $(date)" | sha256sum | awk '{print $1}'
```

Expected: VT returns 0 detections; Verdict = CLEAN/UNKNOWN

---

## Verification Checklist

* [ ] Workflow has a working webhook trigger (URL obtainable)
* [ ] VirusTotal action returns data successfully (check execution logs)
* [ ] Python scoring action correctly calculates percentage
* [ ] Condition branch correctly separates MALICIOUS from non-MALICIOUS
* [ ] TheHive alert is created with correct severity for each test case
* [ ] Alert description contains formatted VT results
* [ ] SHA-256 observable added to TheHive alert
* [ ] Workflow execution completes in <60 seconds per alert

---

## Submission Requirements

Submit:

1. Exported Shuffle workflow JSON
1. Screenshot of execution for each test case (3 screenshots)
1. Screenshot of TheHive alert for EICAR test
1. Brief write-up (max 300 words): What was the hardest part? What would you improve?

---

## Hints

* The VirusTotal response for a file hash has this structure: `data.attributes.last_analysis_stats`
* TheHive expects severity as integer: 1=Low, 2=Medium, 3=High, 4=Critical
* The EICAR hash may return many malicious detections — use this to test your scoring
* If VT rate limits you (free tier), add "Shuffle Tools → Wait" with 15000ms (15 sec)
* To add observables to a TheHive alert in the same workflow, use the alert `_id` returned by the Create Alert action
