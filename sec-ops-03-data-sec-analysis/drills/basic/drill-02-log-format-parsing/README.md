# Drill 02 (Basic): Log Format Parsing

**Estimated time:** 25 minutes

**Difficulty:** Basic

**Tools:** Text editor (no SIEM required)

## Objective

Practice reading and extracting information from raw security log entries in different formats.
A core analyst skill is the ability to read log data without relying on a UI to present it.

---

## Task 1: Parse a CEF Log

Analyze this raw CEF event and answer the questions:

```text
CEF:0|Fortinet|FortiGate|7.2|0004000013|traffic forward|6|deviceExternalId=FGT80F logver=600 dvchost=FW-EDGE-01 ad.vd=root date=2024-03-15 time=14:23:01 devid=FGT80F0000000000 vd=root tz=+0000 type=traffic subtype=forward level=notice srcip=192.168.5.101 srcport=54321 srcintf=LAN srcintfrole=lan dstip=185.220.101.5 dstport=443 dstintf=WAN dstintfrole=wan policyid=1 proto=6 action=deny crscore=50 craction=1 duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 appcat=unscanned
```

**Questions:**

1. What is the source IP address and port?
1. What is the destination IP address and port?
1. What action did the firewall take?
1. What interface was the traffic entering from?
1. What CEF severity level is this (0–10)?
1. Was data transferred? How many bytes?
1. What time did this event occur (UTC)?

---

## Task 2: Parse a JSON Log

Analyze this AWS CloudTrail JSON event and answer the questions:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI3FHNTEXAMPLEID",
    "arn": "arn:aws:iam::123456789012:user/contractor01",
    "accountId": "123456789012",
    "userName": "contractor01"
  },
  "eventTime": "2024-03-15T02:33:17Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "AttachUserPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.42",
  "userAgent": "aws-cli/2.15.0 Python/3.12.0",
  "requestParameters": {
    "userName": "contractor01",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  },
  "responseElements": null,
  "requestID": "example-request-id",
  "eventID": "example-event-id",
  "readOnly": false,
  "eventType": "AwsApiCall"
}
```

**Questions:**

1. What did the user `contractor01` do?
1. Is this event read-only?
1. What is the security significance of the `policyArn` value?
1. What time did this happen?
1. Is this time suspicious from a behavioral perspective? Why?
1. What MITRE ATT&CK technique does this map to?

---

## Task 3: Map Fields to ECS

Given the following raw Zeek HTTP log (TSV format):

```text
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	method	host	uri	user_agent	request_body_len	response_body_len	status_code
1710500000.123	CxABCD123	192.168.1.50	54321	203.0.113.10	80	POST	malicious-c2.example.com	/update	Go-http-client/1.1	2048	128	200
```

Map each field to its Elastic Common Schema (ECS) equivalent:

| Zeek Field | Value | ECS Field Name |
|-----------|-------|---------------|
| `ts` | `1710500000.123` | ? |
| `id.orig_h` | `192.168.1.50` | ? |
| `id.orig_p` | `54321` | ? |
| `id.resp_h` | `203.0.113.10` | ? |
| `id.resp_p` | `80` | ? |
| `method` | `POST` | ? |
| `host` | `malicious-c2.example.com` | ? |
| `uri` | `/update` | ? |
| `user_agent` | `Go-http-client/1.1` | ? |
| `status_code` | `200` | ? |

---

## Task 4: Identify the Threat

Looking at the following sequence of events from the same host (`192.168.1.50`) within 5 minutes, identify what attack is likely taking place and which events are the most significant indicators:

```text
2024-03-15T14:23:00Z  Windows Event 4624  User: jsmith  Logon_Type=3  From: 192.168.1.10
2024-03-15T14:23:12Z  Sysmon Event 1      Image: WINWORD.EXE  Spawned: powershell.exe  Cmdline: "powershell -nop -w hidden -enc JABj..."
2024-03-15T14:23:15Z  Sysmon Event 3      Image: powershell.exe  DestinationIp: 185.220.101.5  DestinationPort: 443
2024-03-15T14:23:18Z  DNS Query           QueryName: update-services.ru  Result: 185.220.101.5
2024-03-15T14:25:01Z  Sysmon Event 11     Image: powershell.exe  TargetFile: C:\Users\jsmith\AppData\Roaming\svchost32.exe
2024-03-15T14:27:44Z  Windows Event 4698  TaskName: \Microsoft\Windows\UpdateCheck  Command: C:\...\svchost32.exe
```

**Questions:**

1. What type of attack is this?
1. Which event is the "patient zero" — the first event indicating compromise?
1. Which event indicates **persistence** was established?
1. What MITRE ATT&CK techniques are represented?
1. What immediate action should an analyst take?

---

See `../solutions/drill-02-solution/README.md` for answers.
