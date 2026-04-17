# Drill 01 Solution: Log Parsing Exercise

---

## Sample 1 Solution: Linux su Command Log

**Input:**

```text
Dec 14 10:15:33 server01 su[2341]: pam_unix(su:auth): authentication failure; logname=jdoe uid=1001 euid=0 tty=/dev/pts/1 ruser=jdoe rhost=  user=root
```

**Grok Pattern:**

```text
%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{WORD:program}\[%{INT:pid:int}\]: pam_unix\(%{DATA:pam_module}\): authentication failure; logname=%{USERNAME:logname} uid=%{INT:uid:int} euid=%{INT:euid:int} tty=%{DATA:tty} ruser=%{USERNAME:ruser} rhost=\s* user=%{USERNAME:target_user}
```

**Extracted fields:**

```json
{
  "timestamp": "Dec 14 10:15:33",
  "hostname": "server01",
  "program": "su",
  "pid": 2341,
  "pam_module": "su:auth",
  "logname": "jdoe",
  "uid": 1001,
  "euid": 0,
  "tty": "/dev/pts/1",
  "ruser": "jdoe",
  "target_user": "root"
}
```

**Key points:**

* `\[` escapes the literal bracket
* `\s*` handles the empty `rhost=` field (zero or more whitespace)
* `pam_unix\(su:auth\)` escapes both parentheses since `(` and `)` are regex metacharacters

---

## Sample 2 Solution: Nginx Access Log

**Input:**

```text
2024-12-14T10:22:01+00:00 10.0.0.1 - admin [14/Dec/2024:10:22:01 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 403 153 "https://example.com/wp-admin/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

**Grok Pattern:**

```text
%{TIMESTAMP_ISO8601:server_time} %{IPORHOST:server_ip} %{DATA:ident} %{DATA:auth_user} \[%{HTTPDATE:access_time}\] "%{WORD:http_method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:http_version}" %{INT:status_code:int} %{INT:bytes:int} "%{DATA:referer}" "%{DATA:user_agent}"
```

**Extracted fields:**

```json
{
  "server_time": "2024-12-14T10:22:01+00:00",
  "server_ip": "10.0.0.1",
  "ident": "-",
  "auth_user": "admin",
  "access_time": "14/Dec/2024:10:22:01 +0000",
  "http_method": "POST",
  "uri": "/wp-admin/admin-ajax.php",
  "http_version": "1.1",
  "status_code": 403,
  "bytes": 153,
  "referer": "https://example.com/wp-admin/",
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}
```

**Key points:**

* `%{IPORHOST}` handles both IP and hostname for the server IP
* `%{HTTPDATE}` handles the Apache/Nginx combined log timestamp format
* Use `%{DATA}` inside quotes to capture everything between the quotes
* `status_code` and `bytes` use `:int` to ensure integer type

---

## Sample 3 Solution: Windows DNS Debug Log

**Input:**

```text
12/14/2024 10:30:15 AM 0F54 PACKET  000000B5C3FABDE0 UDP Snd 192.168.1.100    0001 Q [0001   D   NOERROR] A      (7)banking(4)corp(3)com(0)
```

**Grok Pattern:**

```text
%{DATA:event_date} %{TIME:event_time} %{DATA:ampm} %{WORD:thread_id} %{WORD:packet_type}\s+%{BASE16NUM:packet_id} %{WORD:transport} %{WORD:direction} %{IP:client_ip}\s+%{BASE16NUM:query_id} %{WORD:operation} \[%{DATA:flags}\] %{WORD:query_type}\s+%{GREEDYDATA:query_name}
```

**Extracted fields:**

```json
{
  "event_date": "12/14/2024",
  "event_time": "10:30:15",
  "ampm": "AM",
  "thread_id": "0F54",
  "packet_type": "PACKET",
  "packet_id": "000000B5C3FABDE0",
  "transport": "UDP",
  "direction": "Snd",
  "client_ip": "192.168.1.100",
  "query_id": "0001",
  "operation": "Q",
  "flags": "0001   D   NOERROR",
  "query_type": "A",
  "query_name": "(7)banking(4)corp(3)com(0)"
}
```

**Key points:**

* `\s+` handles variable whitespace (multiple spaces) between fields
* `%{BASE16NUM}` matches hexadecimal numbers
* `\[%{DATA:flags}\]` captures the bracketed flags section

---

## Sample 4 Solution: Palo Alto Firewall Log

**Input:**

```text
1,2024/12/14 10:45:00,PA-VM,THREAT,vulnerability,2049,2024/12/14 10:45:00,10.0.1.5,203.0.113.42,10.0.1.5,203.0.113.42,allow-outbound,jdoe,web-browsing,vsys1,trust,untrust,ethernet1/1,,1234567,1,53210,80,0,0,0x0,tcp,alert,"CVE-2021-44228 Log4Shell",log4j,critical,server-to-client,12345,0x0,US,10.0.0.0-10.255.255.255,0,1,0,
```

**Grok Pattern:**

```text
%{INT:log_version},%{DATA:receive_time},%{DATA:device_name},%{DATA:log_type},%{DATA:subtype},%{DATA:config_version},%{DATA:timestamp},%{IP:src_ip},%{IP:dst_ip},%{IP:nat_src_ip},%{IP:nat_dst_ip},%{DATA:action},%{DATA:user},%{DATA:application},%{DATA:vsys},%{DATA:src_zone},%{DATA:dst_zone},%{DATA:inbound_if},%{DATA:outbound_if},%{DATA:log_id},%{DATA:serial},%{INT:src_port},%{INT:dst_port},%{DATA:nat_src_port},%{DATA:nat_dst_port},%{DATA:flags},%{WORD:transport_proto},%{WORD:pa_severity},"%{DATA:threat_name}",%{DATA:threat_category},%{WORD:severity},%{GREEDYDATA:remaining}
```

**Extracted fields:**

```json
{
  "timestamp": "2024/12/14 10:45:00",
  "src_ip": "10.0.1.5",
  "dst_ip": "203.0.113.42",
  "action": "allow-outbound",
  "user": "jdoe",
  "application": "web-browsing",
  "src_zone": "trust",
  "dst_zone": "untrust",
  "transport_proto": "tcp",
  "threat_name": "CVE-2021-44228 Log4Shell",
  "severity": "critical"
}
```

**Key points:**

* For CSV formats, chain `%{DATA:fieldN},` for most fields
* The threat name is quoted — use `"%{DATA:threat_name}"` to capture the content without quotes
* Use `%{GREEDYDATA}` for the trailing fields you don't need to parse individually

---

## Sample 5 Solution: Windows Event Log (Key=Value format)

**Input:**

```text
EventTime=2024-12-14 11:00:00, Hostname=WORKSTATION01, EventID=4688, UserName=CORP\jdoe, NewProcessName=C:\Windows\System32\whoami.exe, CommandLine=whoami /all, ParentProcessName=C:\Windows\System32\cmd.exe, ParentProcessId=0x1234, ProcessId=0x1238
```

**Option A: Logstash `kv` filter (preferred for key=value logs)**

```ruby
kv {
  field_split  => ", "
  value_split  => "="
  # Fields are automatically extracted as key=value pairs
}
# Then rename/cast as needed:
mutate {
  rename  => { "Hostname"        => "hostname" }
  rename  => { "EventTime"       => "event_time" }
  rename  => { "EventID"         => "event_id" }
  rename  => { "UserName"        => "username" }
  rename  => { "NewProcessName"  => "new_process" }
  rename  => { "CommandLine"     => "command_line" }
  rename  => { "ParentProcessName" => "parent_process" }
  rename  => { "ProcessId"       => "process_id" }
  convert => { "event_id" => "integer" }
}
```

**Option B: Grok pattern (for completeness)**

```text
EventTime=%{DATA:event_time}, Hostname=%{HOSTNAME:hostname}, EventID=%{INT:event_id:int}, UserName=%{DATA:username}, NewProcessName=%{DATA:new_process}, CommandLine=%{DATA:command_line}, ParentProcessName=%{DATA:parent_process}, ParentProcessId=%{BASE16NUM:parent_process_id}, ProcessId=%{BASE16NUM:process_id}
```

**Extracted fields:**

```json
{
  "event_time": "2024-12-14 11:00:00",
  "hostname": "WORKSTATION01",
  "event_id": 4688,
  "username": "CORP\\jdoe",
  "new_process": "C:\\Windows\\System32\\whoami.exe",
  "command_line": "whoami /all",
  "parent_process": "C:\\Windows\\System32\\cmd.exe",
  "process_id": "0x1238"
}
```

**Key points:**

* For key=value formatted logs, the Logstash `kv` filter is far simpler than a complex Grok pattern.
* Windows paths contain backslashes — these are fine in Grok `%{DATA}` but the `kv` filter handles them correctly too.
* The process IDs are in hex (`0x1238`) — keep as string with `%{BASE16NUM}` or convert to integer with a `ruby` block.

---

## Bonus Challenge Solution

```ruby
# pipeline/multi-source.conf

input {
  file { path => "/logs/su.log";          type => "su_auth";       start_position => "beginning"; sincedb_path => "/dev/null" }
  file { path => "/logs/nginx.log";       type => "nginx_access";  start_position => "beginning"; sincedb_path => "/dev/null" }
  file { path => "/logs/dns_debug.log";   type => "win_dns";       start_position => "beginning"; sincedb_path => "/dev/null" }
  file { path => "/logs/paloalto.log";    type => "palo_threat";   start_position => "beginning"; sincedb_path => "/dev/null" }
  file { path => "/logs/winevent.log";    type => "win_event_kv";  start_position => "beginning"; sincedb_path => "/dev/null" }
}

filter {
  if [type] == "su_auth" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_ts} %{HOSTNAME:hostname} %{WORD:program}\[%{INT:pid:int}\]: pam_unix\(%{DATA:pam_module}\): authentication failure; logname=%{USERNAME:logname} uid=%{INT:uid:int} euid=%{INT:euid:int} tty=%{DATA:tty} ruser=%{USERNAME:ruser} rhost=\s* user=%{USERNAME:target_user}" }
      tag_on_failure => ["_grokparsefailure_su"]
    }
    date { match => ["syslog_ts", "MMM dd HH:mm:ss", "MMM  d HH:mm:ss"]; target => "@timestamp" }
    mutate {
      rename => { "hostname" => "[host][name]"; "logname" => "[user][name]"; "pid" => "[process][pid]" }
      add_field => { "[event][category]" => "authentication"; "[event][outcome]" => "failure" }
    }
  }

  if [type] == "nginx_access" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:server_time} %{IPORHOST:server_ip} %{DATA:ident} %{DATA:auth_user} \[%{HTTPDATE:access_time}\] \"%{WORD:http_method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:http_version}\" %{INT:status_code:int} %{INT:bytes:int} \"%{DATA:referer}\" \"%{DATA:user_agent}\"" }
      tag_on_failure => ["_grokparsefailure_nginx"]
    }
    date { match => ["access_time", "dd/MMM/yyyy:HH:mm:ss Z"]; target => "@timestamp" }
    mutate {
      rename => { "server_ip" => "[host][ip]"; "http_method" => "[http][request][method]"; "status_code" => "[http][response][status_code]" }
      add_field => { "[event][category]" => "web"; "[event][type]" => "access" }
    }
    if [auth_user] and [auth_user] != "-" { mutate { rename => { "auth_user" => "[user][name]" } } }
  }

  if [type] == "win_event_kv" {
    kv { field_split => ", "; value_split => "=" }
    mutate {
      rename  => { "Hostname" => "[host][name]"; "UserName" => "[user][name]"; "CommandLine" => "[process][command_line]" }
      convert => { "EventID" => "integer" }
      add_field => { "[event][category]" => "process"; "[event][kind]" => "event" }
    }
  }
}

output {
  elasticsearch { hosts => ["http://elasticsearch:9200"]; index => "drill01-%{type}-%{+YYYY.MM.dd}" }
  if "_grokparsefailure" in [tags] { stdout { codec => rubydebug } }
}
```

**Grading rubric:**

* 5 patterns correct: 50 points
* ECS field renaming: 20 points
* Type casting: 10 points
* Failure tagging: 10 points
* Bonus pipeline: 10 points extra credit
