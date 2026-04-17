# Drill 01 (Basic): Log Parsing Exercise

**Level:** Basic

**Estimated time:** 30 minutes

**Deliverable:** Grok patterns that correctly parse all provided log samples

---

## Instructions

For each of the 5 log samples below, write a Grok pattern that extracts the required fields.
Test your patterns using the Kibana Grok Debugger (Dev Tools → Grok Debugger) or the online tool at https://grokdebug.herokuapp.com.

You may use any built-in Grok pattern.
Refer to Guide 01 for the list of common patterns.

---

## Sample 1: Linux su Command Log

**Raw log line:**

```text
Dec 14 10:15:33 server01 su[2341]: pam_unix(su:auth): authentication failure; logname=jdoe uid=1001 euid=0 tty=/dev/pts/1 ruser=jdoe rhost=  user=root
```

**Required extracted fields:**

* `timestamp` — the syslog timestamp
* `hostname` — the reporting host
* `pid` — the PID of the su process
* `logname` — the user who ran su
* `uid` — the UID of the user running su
* `target_user` — the user they tried to become

**Write your Grok pattern here:**

```text
[YOUR PATTERN]
```

---

## Sample 2: Nginx Access Log

**Raw log line:**

```text
2024-12-14T10:22:01+00:00 10.0.0.1 - admin [14/Dec/2024:10:22:01 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 403 153 "https://example.com/wp-admin/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

**Required extracted fields:**

* `client_ip` — the client IP address
* `auth_user` — the authenticated user (or `-`)
* `access_time` — the timestamp in brackets
* `http_method` — POST, GET, etc.
* `uri` — the request URI
* `status_code` — the HTTP response code (as integer)
* `bytes` — response bytes (as integer)
* `user_agent` — the user agent string (without quotes)

**Write your Grok pattern here:**

```text
[YOUR PATTERN]
```

---

## Sample 3: Windows DNS Debug Log

**Raw log line:**

```text
12/14/2024 10:30:15 AM 0F54 PACKET  000000B5C3FABDE0 UDP Snd 192.168.1.100    0001 Q [0001   D   NOERROR] A      (7)banking(4)corp(3)com(0)
```

**Required extracted fields:**

* `event_date` — the date portion `12/14/2024`
* `event_time` — the time portion `10:30:15 AM`
* `thread_id` — the hex thread ID `0F54`
* `packet_type` — `PACKET`
* `direction` — `Snd` (send) or `Rcv` (receive)
* `client_ip` — `192.168.1.100`
* `query_id` — the hex query ID `0001`
* `query_type` — the record type `A`

**Write your Grok pattern here:**

```text
[YOUR PATTERN]
```

---

## Sample 4: Palo Alto Firewall Log (CSV-like format)

**Raw log line:**

```text
1,2024/12/14 10:45:00,PA-VM,THREAT,vulnerability,2049,2024/12/14 10:45:00,10.0.1.5,203.0.113.42,10.0.1.5,203.0.113.42,allow-outbound,jdoe,web-browsing,vsys1,trust,untrust,ethernet1/1,,1234567,1,53210,80,0,0,0x0,tcp,alert,"CVE-2021-44228 Log4Shell",log4j,critical,server-to-client,12345,0x0,US,10.0.0.0-10.255.255.255,0,1,0,
```

**Required extracted fields:**

* `timestamp` — the second timestamp field
* `src_ip` — source IP (field 7: `10.0.1.5`)
* `dst_ip` — destination IP (field 8: `203.0.113.42`)
* `action` — `allow-outbound`
* `user` — `jdoe`
* `application` — `web-browsing`
* `src_zone` — `trust`
* `dst_zone` — `untrust`
* `transport_proto` — `tcp`
* `threat_name` — `CVE-2021-44228 Log4Shell`
* `severity` — `critical`

**Hint:** Use `%{DATA:fieldname}` separated by commas for CSV-like formats.

**Write your Grok pattern here:**

```text
[YOUR PATTERN]
```

---

## Sample 5: Windows Event Log (Single-line format from SIEM export)

**Raw log line:**

```text
EventTime=2024-12-14 11:00:00, Hostname=WORKSTATION01, EventID=4688, UserName=CORP\jdoe, NewProcessName=C:\Windows\System32\whoami.exe, CommandLine=whoami /all, ParentProcessName=C:\Windows\System32\cmd.exe, ParentProcessId=0x1234, ProcessId=0x1238
```

**Required extracted fields:**

* `event_time` — `2024-12-14 11:00:00`
* `hostname` — `WORKSTATION01`
* `event_id` — `4688` (as integer)
* `username` — `CORP\jdoe`
* `new_process` — `C:\Windows\System32\whoami.exe`
* `command_line` — `whoami /all`
* `parent_process` — `C:\Windows\System32\cmd.exe`
* `process_id` — the hex value `0x1238`

**Write your Grok pattern here:**

```text
[YOUR PATTERN]
```

---

## Submission Checklist

* [ ] All 5 Grok patterns written
* [ ] Each pattern tested in the Grok Debugger
* [ ] All required fields are extracted with correct names
* [ ] Fields requiring integer type are cast with `:int`
* [ ] Patterns handle edge cases (optional fields, variable whitespace)

---

## Bonus Challenge

Write a Logstash pipeline configuration that:

1. Reads all 5 log types from files
1. Applies the appropriate Grok pattern based on log source identification
1. Tags events that fail to parse
1. Renames at least 3 fields to their ECS equivalents
