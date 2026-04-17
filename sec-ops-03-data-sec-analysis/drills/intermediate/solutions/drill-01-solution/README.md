# Solution: Drill 01 (Intermediate) — Correlation Analysis

## Challenge 1: Finding the Compromised Host

**Query:**

```spl
index=main sourcetype=attack_sim earliest=-2h
| where EventID=1 AND match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT)\.EXE")
| stats count BY host, User
| sort -count
```

**Or a broader suspicious activity finder:**

```spl
index=main sourcetype=attack_sim earliest=-2h
| where attack_step != "background_noise"
| stats
    dc(attack_step) AS unique_attack_steps
    count AS total_events
    values(attack_step) AS steps
    BY host
| where unique_attack_steps >= 2
| sort -unique_attack_steps
```

**Answer:** Host `WORKSTATION-042`, User `CORP\jsmith`

---

## Challenge 2: Attack Timeline

**Query:**

```spl
index=main sourcetype=attack_sim host="WORKSTATION-042"
    attack_step!="background_noise" earliest=-2h
| sort _time
| table _time, attack_step, description, EventID, Image, CommandLine, DestinationIp, TargetFilename, TaskName
```

**Completed Timeline:**

| Time | Event Type | What Happened | Attack Stage |
|------|-----------|---------------|-------------|
| T+0 | Sysmon Event 1 | WINWORD.EXE opened `Invoice_March2024.docm` | Delivery |
| T+12 | Sysmon Event 1 | WINWORD.EXE spawned `powershell.exe -nop -w hidden -EncodedCommand ...` | Execution |
| T+15 | Sysmon Event 3 | `powershell.exe` connected to `185.220.101.5:443` | C2 Establishment |
| T+18 | Sysmon Event 22 | DNS query for `update-services.ru` → resolved to `185.220.101.5` | C2 Domain Resolution |
| T+45 | Sysmon Event 11 | `powershell.exe` created `C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\svchost32.exe` | Payload Drop |
| T+60 | Windows Event 4698 | Scheduled task `\Microsoft\Windows\UpdateCheck` created | Persistence |
| T+70 | Sysmon Event 3 | `net.exe` made SMB connection to `192.168.1.10:445` (SERVER-DC01) | Lateral Movement Attempt |

---

## Challenge 3: Correlation Rule

```spl
# Step 1: Find Office processes that spawn scripting engines
[
  index=main sourcetype=attack_sim EventID=1 earliest=-2h
  | where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE")
  | where match(Image, "(?i)(powershell|cmd|wscript|cscript)\.exe")
  | eval correlation_key = host . "|" . User
  | eval phase1_time = _time
  | eval phase = "office_spawn"
  | fields correlation_key, phase1_time, Image, ParentImage, CommandLine, phase
]

# Combined correlation approach using transaction:
index=main sourcetype=attack_sim (EventID=1 OR EventID=3) earliest=-2h
| eval is_office_spawn = if(
    EventID=1 AND
    match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT)\.EXE") AND
    match(Image, "(?i)(powershell|cmd|wscript)\.exe"),
    1, 0)
| eval is_external_connection = if(
    EventID=3 AND
    match(Image, "(?i)powershell\.exe") AND
    NOT cidrmatch("10.0.0.0/8", DestinationIp) AND
    NOT cidrmatch("192.168.0.0/16", DestinationIp),
    1, 0)
| transaction host maxspan=5m
| where max(is_office_spawn) = 1 AND max(is_external_connection) = 1
| eval alert = "CRITICAL: Office → Shell → External Connection"
| eval mitre = "T1566.001 → T1059.001 → T1071.001"
| table _time, host, User, alert, mitre, DestinationIp
```

**Explanation of key sections:**

* `transaction host maxspan=5m` — Groups events by host within a 5-minute window
* `where max(is_office_spawn) = 1 AND max(is_external_connection) = 1` — Requires BOTH conditions to be present in the same transaction
* The `eval` fields flag each event type, allowing us to check both are present without writing a complex sequence join
* MITRE mapping shows the chain: Spearphishing → PowerShell execution → C2 over web protocols

---

## Challenge 4: Persistence Mechanisms

**Query:**

```spl
index=main sourcetype=attack_sim host="WORKSTATION-042"
    (EventID=4698 OR EventID=11) earliest=-2h
| eval finding = case(
    EventID=4698, "Scheduled Task: " . TaskName . " → " . TaskContent,
    EventID=11,   "File Created: " . TargetFilename,
    true(), "Other"
  )
| table _time, EventID, finding
```

**Findings:**

1. **Scheduled Task (EventID 4698):** `\Microsoft\Windows\UpdateCheck` running `C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\svchost32.exe`
1. **Malware binary (EventID 11):** `C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\svchost32.exe` (created by powershell.exe)

---

## Complete Incident Summary

```text
Incident Summary:
- Compromised Host: WORKSTATION-042
- Compromised User: CORP\jsmith
- Initial Access Time: T+0 (document opened)
- First Malicious Event: T+12 — WINWORD spawned encoded PowerShell
- C2 Server IP: 185.220.101.5
- C2 Domain: update-services.ru
- Persistence: Scheduled task \Microsoft\Windows\UpdateCheck
- Malware Path: C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\svchost32.exe
- Estimated Impact: Active C2 connection, persistence established, lateral movement attempted to DC

MITRE ATT&CK Mapping:
- TA0001 Initial Access:       T1566.001 — Spearphishing Attachment
- TA0002 Execution:            T1059.001 — PowerShell
- TA0011 Command and Control:  T1071.001 — Web Protocols (HTTPS)
- TA0003 Persistence:          T1053.005 — Scheduled Task
- TA0008 Lateral Movement:     T1021.002 — SMB/Windows Admin Shares (attempt)
```
