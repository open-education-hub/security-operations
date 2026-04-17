# Guide 03: Building an Attack Timeline from Logs

**Level:** Basic

**Estimated time:** 25 minutes

**Prerequisites:** Reading — Section 8 (Timeline Reconstruction Techniques), Guide 02

---

## Purpose

By the end of this guide, you will be able to:

* Extract relevant log entries from multiple sources
* Normalize timestamps to UTC
* Build a structured incident timeline
* Identify attack kill chain phases within the timeline
* Spot coverage gaps (periods with no log data)

---

## Part 1: Why Timelines Matter

A timeline is the backbone of every incident investigation.
Without it, you have a pile of unrelated log entries.
With it, you have a story — one that tells you:

* **When** the incident began (not just when you detected it)
* **How** the attacker progressed through the environment
* **What** data or systems were at risk
* **Where** the gaps in your visibility are
* **Why** certain detections did or did not fire

A good timeline also **tells you what you don't see**.
Gaps between confirmed events suggest either that no activity occurred, or that you have a logging gap.
Both are important to understand.

---

## Part 2: Timeline Structure

A useful incident timeline has these columns:

| Column | Content |
|--------|---------|
| DateTime (UTC) | ISO 8601 format — `2024-11-15T09:42:11Z` |
| System | Hostname or IP of the system generating the event |
| Log Source | Where the log came from (mail server, EDR, firewall...) |
| Event | Human-readable description of what happened |
| Kill Chain Phase | Recon / Weaponize / Delivery / Exploit / Install / C2 / Actions |
| ATT&CK Technique | Optional: T-code if mapped |
| Confidence | HIGH / MEDIUM / LOW / INFERRED |
| Notes | Analyst annotation |

---

## Part 3: Timestamp Normalization

All timestamps **must** be in UTC before building a timeline.
Mixed timezones cause misaligned events and wrong conclusions.

### Common timezone issues

| Issue | Example | Fix |
|-------|---------|-----|
| Local time in log | `Nov 15 09:44:35` (EST = UTC-5) | Add 5 hours → `14:44:35 UTC` |
| Ambiguous DST | Is `Oct 30 01:30:00` pre or post clock change? | Check DST rules for that date |
| Windows logs in local time | Event log stores local time by default | Check system timezone in registry |
| Log rotation using local time | Midnight file rotation in PST creates wrong day boundary in UTC | Document the conversion |
| NTP not synchronized | System clock 8 minutes behind | Note clock skew in timeline |

### Document clock skew

Always record the system clock offset when collecting evidence:

```console
# Check system time vs. reference time
date -u                          # System time
ntpdate -q pool.ntp.org          # Offset from NTP
timedatectl                      # Linux: timezone and sync status
```

If a system's clock was 5 minutes fast, all events from that system are 5 minutes earlier than logged.
Note this in the timeline.

---

## Part 4: Step-by-Step Timeline Construction

### Step 1: Scope the investigation

Before touching logs, answer:

* What systems are definitely involved?
* What is the earliest possible compromise date?
* What log sources are available for those systems?
* What is the retention period for each log source?

### Step 2: Extract log data

For each relevant system and log source, extract events in a time window around the incident.
Start wider than you think necessary — attacker activity before detection is the hardest to find.

**Sample log extraction (Splunk SPL):**

```spl
(host="WS-JSMITH" OR host="FILE-SRV01" OR host="DC01")
earliest="2024-11-14T00:00:00" latest="2024-11-16T00:00:00"
| table _time, host, sourcetype, EventID, User, CommandLine, DestinationIp
| sort _time
```

### Step 3: Normalize and merge

Export all log sources to a spreadsheet or tool like Timesketch.
Normalize:

* All timestamps to UTC
* Hostname naming (same system may have multiple names in logs)
* User naming (DOMAIN\user vs user@domain.com vs UID)

### Step 4: First pass — mark the obvious

Highlight clearly suspicious events:

* Known-bad IPs or domains
* Known attack tool names (mimikatz, psexec, cobalt, meterpreter)
* Unusual process chains (office → shell → powershell)
* Authentication events from unusual sources

### Step 5: Work backward from known events

You usually start with one confirmed malicious event (the alert).
Work *backward* in time:

* What caused this event?
* What happened 5 minutes before?
* What happened 1 hour before?
* What was the *first* suspicious event?

### Step 6: Work forward from the earliest event

Once you've identified the earliest compromise, trace forward:

* What did the attacker do after gaining access?
* Did they pivot to other systems?
* When did they access sensitive data?
* When (if at all) did they exfiltrate?

---

## Part 5: Example — Building the Phishing Incident Timeline

Using the scenario from Demo 01, here is the timeline construction process:

**Available log sources:**

* `mail.log` — email delivery logs
* `proxy.log` — web proxy access logs
* `sysmon.log` — Sysmon process/network events (WS-JSMITH)
* `firewall.log` — perimeter firewall connections
* `winlogs.log` — Windows Security Event Log (all systems)

**Raw events (unsorted, different sources):**

```text
[sysmon]   09:44:35  WS-JSMITH  EventID=1  WINWORD→CMD→POWERSHELL -Enc
[firewall] 09:45:02  WS-JSMITH  → 185.220.101.47:4444 TCP ALLOW
[proxy]    09:44:22  WS-JSMITH  GET http://185.220.101.47/track 200
[mail]     09:42:11  MAIL01     DELIVERED invoice.docm to jsmith
[sysmon]   09:48:03  WS-JSMITH  EventID=1  net.exe "net user /domain"
[sysmon]   09:52:08  WS-JSMITH  EventID=11 svchost32.exe created in C:\Temp
[sysmon]   10:12:44  WS-JSMITH  EventID=10 LSASS read by C:\Temp\svchost32.exe
[winlogs]  10:31:05  FILE-SRV01 EventID=4624 Logon Type 3 from 192.168.10.42
```

**Normalized timeline:**

```text
DateTime (UTC)       System      Source      Event                           Phase       ATT&CK          Confidence
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
2024-11-15 09:42:11  MAIL01      mail.log    Phishing email delivered        Delivery    T1566.001       HIGH
                                             invoice.docm (SPF FAIL)
2024-11-15 09:44:22  WS-JSMITH   proxy.log   HTTP GET http://185.20../track  Delivery    T1566.001       HIGH
                                             (user clicked link in email)
2024-11-15 09:44:35  WS-JSMITH   sysmon      WINWORD→CMD→PS -NoP -W Hidden   Exploit     T1204.002       HIGH
                                             -Enc JABj... (macro execution)             T1059.001
2024-11-15 09:45:02  WS-JSMITH   firewall    TCP → 185.220.101.47:4444       C2          T1095           HIGH
                                             (reverse shell established)
2024-11-15 09:48:03  WS-JSMITH   sysmon      net user /domain                Discovery   T1087.002       HIGH
2024-11-15 09:52:08  WS-JSMITH   sysmon      C:\Temp\svchost32.exe created   Install     T1036.005       HIGH
                                             (masquerading as svchost)
2024-11-15 10:12:44  WS-JSMITH   sysmon      LSASS memory read               Credential  T1003.001       HIGH
                                             by svchost32.exe               Dump
2024-11-15 10:31:05  FILE-SRV01  winlogs     4624 Type3 logon from           Lateral     T1021.002       HIGH
                                             192.168.10.42 (WS-JSMITH)      Movement
```

**Coverage gap analysis:**

```text
09:45:02 → 09:48:03 (3 minutes): No Sysmon events
  → Gap in process activity logging?
  → Attacker may have been establishing persistence or waiting
  → INFERRED: Scheduled task creation (confirmed later in disk forensics)

10:12:44 → 10:31:05 (18 minutes): No events on FILE-SRV01
  → What did attacker do during this period after credential dump?
  → HUNT: Check DC01 and other server logs for same IP
```

---

## Part 6: Identifying Kill Chain Phases

Map each timeline entry to a kill chain phase:

```text
Kill Chain Phase → Timeline Events
─────────────────────────────────────────────────────────
Reconnaissance    No events (gap — attacker recon happened earlier)
Weaponize         No events (attacker built payload off-network)
Delivery          09:42:11 Email delivered
                  09:44:22 User clicked link
Exploitation      09:44:35 Macro executed → PowerShell
Installation      09:52:08 svchost32.exe dropped to C:\Temp
C2                09:45:02 Reverse shell to 185.220.101.47:4444
Actions on Obj    10:12:44 Credential dumping
                  10:31:05 Lateral movement to FILE-SRV01
```

**Insight from kill chain mapping:** The attacker was at "Actions on Objectives" within 48 minutes of initial delivery.
This is a fast-moving threat.
Typical APT dwell time is weeks to months — this speed suggests either automation or a focused, pre-planned attack.

---

## Summary Template

Use this template for your timelines.
Save as a spreadsheet or import to Timesketch.

```csv
datetime_utc,system,log_source,event_description,kill_chain_phase,attck_technique,confidence,analyst_notes
2024-11-15T09:42:11Z,MAIL01,mail.log,"Phishing email delivered (SPF FAIL) invoice.docm",Delivery,T1566.001,HIGH,""
2024-11-15T09:44:22Z,WS-JSMITH,proxy.log,"HTTP GET to http://185.220.101.47/track",Delivery,T1566.001,HIGH,"User clicked link in email"
2024-11-15T09:44:35Z,WS-JSMITH,sysmon,"WINWORD→CMD→POWERSHELL -NoP -W Hidden -Enc",Exploitation,"T1204.002,T1059.001",HIGH,""
```
