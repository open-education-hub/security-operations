# Guide 01 (Intermediate): Full Incident Response Process

## Objective

Execute a complete IR process for a phishing-to-malware incident, from detection through post-incident review, using TheHive for case management.

## Estimated Time: 60–90 minutes

## Scenario

A user (T.
Smith, Finance) reported receiving a phishing email with an attachment.
They opened the attachment and saw nothing happen.
Your EDR has since detected PowerShell execution with an encoded command and an outbound connection.
A DFIR investigation is needed.

## Phase 1: Detection and Initial Assessment (10 min)

### Initial Alert Information

```text
Alert: PowerShell Encoded Command + C2 Connection
Host: finance-ws-022 (T. Smith, Finance)
User: t.smith
Time: 2024-11-14 11:14 UTC
Parent: OUTLOOK.EXE → powershell.exe -EncodedCommand SGVsbG8gV29ybGQh
Outbound: 92.118.36.199:443 (ESTABLISHED)
```

### Step 1: Create TheHive Case

```bash
# Start TheHive from Demo 01 if not already running
# Or use the Demo 03 TheHive instance

curl -u admin:secret -H "Content-Type: application/json" \
  -X POST http://localhost:9000/api/case \
  -d '{
    "title": "Phishing → Malware Execution — finance-ws-022 — T.Smith",
    "severity": 2,
    "description": "PowerShell execution from Outlook parent process with C2 connection. User reports opening email attachment.",
    "tags": ["phishing", "malware", "initial-access"]
  }'
```

### Step 2: Add Observables

Add these observables to the case:

* IP: `92.118.36.199` (outbound C2)
* Host: `finance-ws-022`
* User: `t.smith`
* Process: `powershell.exe -EncodedCommand SGVsbG8gV29ybGQh`

### Step 3: Enrich and Assess

1. Check `92.118.36.199` on VirusTotal (or simulate with Demo 03 Cortex)

1. Decode the base64: `echo "SGVsbG8gV29ybGQh" | base64 -d` (this is "Hello World" for demo purposes — in reality would be a stager)

1. Check if any other hosts contacted the same IP (SIEM query)
1. Assess: P1 or P2? (Finance user, potential C2 active → P2 minimum, potentially P1)

## Phase 2: Containment (10 min)

### Volatile Evidence Collection

```console
# Simulate evidence collection (using the Demo 02 environment if available)
# Document that you would run this before containment:

# On Windows target:
# netstat -anob > evidence/network.txt
# tasklist /v > evidence/processes.txt
# sha256sum evidence/* > evidence/HASHES.sha256
```

### Containment Actions

1. Isolate `finance-ws-022` via EDR
1. Disable T. Smith's account temporarily (prevent attacker reuse)
1. Add `92.118.36.199` to firewall blocklist

Document each action as a case note with timestamp.

## Phase 3: Investigation (20 min)

### Investigate the Phishing Email

1. Retrieve the original email from T. Smith's mailbox (or email security gateway)
1. Extract headers: sender IP, originating mail server, envelope-from
1. Extract attachment: hash, file type, macro presence
1. Check attachment hash on VirusTotal

### Investigate the PowerShell Execution

1. Retrieve full command line from EDR
1. Decode base64 payload (in a safe environment)
1. Identify stager behavior: what does it download? From where?
1. Check for subsequent processes spawned by PowerShell

### MITRE ATT&CK Mapping

Map findings to ATT&CK:

* Initial Access: T1566.001 (Spearphishing Attachment)
* Execution: T1059.001 (PowerShell) + T1204.002 (User Execution)
* Command and Control: T1071.001 (Application Layer Protocol)

## Phase 4: Eradication (10 min)

### Eradication Checklist

```text
□ Original phishing email deleted from user's mailbox
□ Same email identified and deleted from all recipients (if mass phishing)
□ Malicious attachment quarantined / deleted
□ PowerShell process terminated (if still running)
□ C2 IP blocked in perimeter firewall and DNS filter
□ T. Smith's credentials reset (password change + MFA re-enrollment)
□ EDR agent verified: no persistence mechanisms found
□ Full AV scan of finance-ws-022: clean
```

## Phase 5: Recovery (5 min)

1. Re-enable T. Smith's account with new credentials
1. Remove finance-ws-022 from isolation
1. Monitor closely for 24 hours (watch for re-infection signs)
1. Confirm T. Smith can access workstation and email

## Phase 6: Post-Incident Review (10 min)

### 5 Whys Analysis

Start from: "How did a phishing email result in malware execution?"

Work through at least 3 levels to find a systemic root cause.

### Document Action Items

Generate at least 2 action items to prevent recurrence.

### GDPR Check

Assess: Does this incident require GDPR notification?

* Was personal data accessed? (Finance user has access to employee payroll data)
* Was data exfiltrated? (PowerShell connected to C2 — unknown what was sent)
* Conclusion: **Yes, this likely requires GDPR notification** to the DPA within 72 hours.

Write the first paragraph of the DPA notification.

## Key Takeaways

1. The full IR process requires coordination across detection, containment, investigation, and communication simultaneously
1. ATT&CK mapping provides structure and helps identify missed detections
1. GDPR implications must be assessed early (72-hour clock)
1. The PIR root cause is rarely "user clicked phishing" — it's usually a system/process gap
