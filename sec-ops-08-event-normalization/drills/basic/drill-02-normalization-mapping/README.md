# Drill 02 (Basic): Normalization Mapping Exercise

**Level:** Basic

**Estimated time:** 30 minutes

**Deliverable:** A completed field mapping table and a Logstash normalization snippet

---

## Instructions

You are given three parsed event sets (fields already extracted from raw logs).
Your task is to map each field to the correct ECS field name, determine the correct data type, and write any required transformation logic.

---

## Event Set A: AWS VPC Flow Log (Pre-Parsed Fields)

AWS VPC Flow Logs record network traffic metadata in your AWS Virtual Private Cloud.

**Parsed fields from a DENY event:**

```text
version           = 2
account_id        = 123456789012
interface_id      = eni-0a1b2c3d4e5f
srcaddr           = 203.0.113.42
dstaddr           = 10.0.1.100
srcport           = 55234
dstport           = 22
protocol          = 6              (IANA protocol number: 6 = TCP)
packets           = 3
bytes             = 180
start             = 1734161000     (Unix epoch seconds)
end               = 1734161010
action            = REJECT
log_status        = OK
vpc_id            = vpc-12345678
```

**Your task:** Complete this mapping table:

| Source Field | Source Value | ECS Field | ECS Value | Type | Transformation Needed? |
|-------------|-------------|-----------|-----------|------|----------------------|
| `srcaddr` | `203.0.113.42` | | | ip | |
| `dstaddr` | `10.0.1.100` | | | | |
| `srcport` | `55234` | | | | |
| `dstport` | `22` | | | | |
| `protocol` | `6` | | `tcp` | keyword | Map IANA number to name |
| `bytes` | `180` | | | | |
| `start` | `1734161000` | `@timestamp` | | date | Convert epoch to ISO8601 |
| `action` | `REJECT` | | `failure` | keyword | Map REJECT→failure, ACCEPT→success |
| — | — | `event.category` | `network` | keyword | Static value |
| — | — | `cloud.provider` | `aws` | keyword | Static value |
| `vpc_id` | `vpc-12345678` | | | | |

---

## Event Set B: Cisco ASA LEEF Log (Pre-Parsed Fields)

Cisco ASA firewall events in LEEF format.

**Parsed fields:**

```text
leef_version   = 1.0
vendor         = Cisco
product        = ASA
version        = 9.8
event_id       = 113019
src            = 10.0.5.22
dst            = 192.168.100.5
srcPort        = 44321
dstPort        = 443
proto          = TCP
usrName        = vpnuser@corp.com
devTime        = Dec 14 2024 09:15:00
cat            = /Authentication/VPN
sev            = 5
msg            = AAA authentication failed for user vpnuser@corp.com
```

**Your task:** Complete this mapping table:

| Source Field | Source Value | ECS Field | Type |
|-------------|-------------|-----------|------|
| `src` | `10.0.5.22` | | ip |
| `dst` | `192.168.100.5` | | |
| `srcPort` | `44321` | | |
| `dstPort` | `443` | | |
| `proto` | `TCP` | | |
| `usrName` | `vpnuser@corp.com` | | |
| `devTime` | `Dec 14 2024 09:15:00` | | |
| `cat` | `/Authentication/VPN` | | |
| `sev` | `5` (0–10 scale) | `event.severity` (0–100 scale) | |
| `msg` | `AAA authentication failed...` | | |
| — | — | `event.outcome` | |

**Additional question:** The `sev` field uses a 0–10 scale.
Write the formula to convert it to the ECS 0–100 scale:

```text
ECS severity = [YOUR FORMULA]
```

---

## Event Set C: CrowdStrike EDR Event (Pre-Parsed JSON Fields)

CrowdStrike Falcon EDR events delivered via their API.

**Parsed fields:**

```json
{
  "event_type": "ProcessRollup2",
  "timestamp": 1734161521000,
  "aid": "abc123def456",
  "cid": "mycorp123",
  "ComputerName": "WIN10-USER05",
  "UserName": "CORP\\jsmith",
  "FileName": "powershell.exe",
  "FilePath": "\\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
  "CommandLine": "powershell -NonInteractive -NoProfile -ExecutionPolicy Bypass -enc JABjAD0A...",
  "ParentImageFileName": "cmd.exe",
  "ParentCommandLine": "cmd.exe /c script.bat",
  "ProcessId_decimal": 4532,
  "ParentProcessId_decimal": 2100,
  "MD5HashData": "d41d8cd98f00b204e9800998ecf8427e",
  "SHA256HashData": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

**Your task:** Map to ECS.
Fill in the ECS field names and types:

| Source Field | ECS Field | Type | Notes |
|-------------|-----------|------|-------|
| `timestamp` | `@timestamp` | date | Divide by 1000 (ms → s) or use epoch_millis |
| `ComputerName` | | | |
| `UserName` | | | Strip domain prefix `CORP\\` |
| `FileName` | | | |
| `FilePath` + `FileName` | | | Concatenate for full path |
| `CommandLine` | | | |
| `ParentImageFileName` | | | |
| `ParentCommandLine` | | | |
| `ProcessId_decimal` | | | |
| `ParentProcessId_decimal` | | | |
| `MD5HashData` | | | |
| `SHA256HashData` | | | |
| — | `event.category` | keyword | What value? |
| — | `event.type` | keyword | What value? |

---

## Part 2: Write the Logstash Normalization Snippet

Using your completed mapping tables, write the Logstash `filter { }` block for **Event Set C** (CrowdStrike EDR events).

Requirements:

* Set `@timestamp` correctly from `timestamp` field (milliseconds since epoch)
* Extract username without the domain prefix
* Set `process.executable` from concatenation of `FilePath` and `FileName`
* Rename all required fields to ECS
* Set `event.category = "process"` and `event.type = "start"`

**Write your filter block:**

```ruby
filter {
  # YOUR CODE HERE
}
```

---

## Submission Checklist

* [ ] Event Set A mapping table completed
* [ ] Event Set B mapping table completed (including severity formula)
* [ ] Event Set C mapping table completed
* [ ] Logstash filter block for Event Set C written
* [ ] All ECS field types are correct
* [ ] `@timestamp` conversion logic is correct for all three sources
