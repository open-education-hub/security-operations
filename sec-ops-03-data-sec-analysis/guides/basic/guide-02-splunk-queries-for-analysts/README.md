# Guide 02: Writing Effective Splunk Queries for Security Analysis

**Level:** Basic

**Time:** ~40 minutes

**Prerequisites:** Guide 01 completed or access to a Splunk instance with security data

## What You Will Learn

* SPL (Search Processing Language) fundamentals
* Key commands for security analysis: `stats`, `eval`, `where`, `transaction`, `lookup`
* Building a library of useful security queries
* Query optimization tips

## SPL Fundamentals

SPL is a pipeline language. Each command receives the results of the previous command and passes its output to the next. Commands are separated by `|` (pipe).

```text
search terms [pipe command [pipe command [...]]]
```

### Basic Search Syntax

```spl
# Search for a keyword in all indexed data
malware

# Search in a specific index
index=windows malware

# Search for an exact field value
index=windows EventCode=4625

# Combine conditions (implicit AND)
index=windows EventCode=4625 src_ip=192.168.1.*

# OR condition
index=windows (EventCode=4624 OR EventCode=4625)

# NOT condition
index=windows EventCode=4624 NOT Account_Name=SYSTEM

# Wildcard
index=windows Image="*powershell*"

# Time range (relative)
index=windows EventCode=4625 earliest=-1h latest=now
```

### The Four Most Important SPL Commands

#### 1. `stats` — Aggregation

`stats` is the workhorse of security analysis.
It computes statistics over groups of events.

```spl
# Count events by field
index=windows EventCode=4625
| stats count by src_ip

# Multiple statistics at once
index=windows EventCode=4624
| stats
    count AS total_logons
    dc(Account_Name) AS unique_users
    values(src_ip) AS source_ips
    BY Computer

# Time-bucketed stats
index=windows EventCode=4625
| bin _time span=1h
| stats count BY _time, src_ip
```

#### 2. `eval` — Calculate and Transform Fields

`eval` creates new fields or modifies existing ones using expressions.

```spl
# Create a new field based on condition
index=windows EventCode=4625
| eval severity = case(
    count > 100, "CRITICAL",
    count > 20,  "HIGH",
    count > 5,   "MEDIUM",
    true(),      "LOW"
  )

# String concatenation
| eval full_user = Domain + "\\" + Account_Name

# Regex extraction
| eval domain = replace(CommandLine, ".*-url\\s+(https?://[^\\s]+).*", "\\1")

# Calculate time difference
| eval time_delta = _time - strptime(LogonTime, "%Y-%m-%d %H:%M:%S")
```

#### 3. `where` — Filter Results

`where` filters the result set after other commands.
Use it after `stats` or `eval`.

```spl
# Filter on a computed field
index=windows EventCode=4625
| stats count BY src_ip
| where count > 10

# Multiple conditions
| where count > 5 AND isnotnull(src_ip) AND src_ip != "127.0.0.1"

# Regular expression filter
| where match(CommandLine, "(?i)-encodedcommand")
```

#### 4. `table` — Display Specific Fields

```spl
index=windows EventCode=4624
| table _time, Computer, Account_Name, src_ip, Logon_Type
```

---

## Security Query Library

### Authentication Analysis

**Brute force detection — top attacking IPs:**

```spl
index=windows EventCode=4625 earliest=-1h
| stats count AS failures BY src_ip
| where failures > 20
| sort -failures
| eval severity = if(failures > 100, "CRITICAL", "HIGH")
| table src_ip, failures, severity
```

**Password spray detection (many accounts from one IP):**

```spl
index=windows EventCode=4625 earliest=-30m
| stats
    count AS attempts
    dc(Account_Name) AS unique_targets
    values(Account_Name) AS targeted_accounts
    BY src_ip
| where unique_targets > 10
| eval attack_type = "Password Spray"
| table src_ip, attempts, unique_targets, targeted_accounts
```

**Successful logon after failures (compromised account):**

```spl
index=windows (EventCode=4625 OR EventCode=4624) earliest=-1h
| eval event_type = case(EventCode=4625, "failure", EventCode=4624, "success")
| stats
    count(eval(event_type="failure")) AS failures
    count(eval(event_type="success")) AS successes
    BY Account_Name, src_ip
| where failures >= 5 AND successes >= 1
| eval risk = "Possible credential stuffing success"
| table Account_Name, src_ip, failures, successes, risk
```

**Impossible travel (same user, two distant IPs in short time):**

```spl
index=vpn_logs sourcetype=vpn_access
| stats
    values(src_ip) AS ips
    values(country) AS countries
    min(_time) AS first_login
    max(_time) AS last_login
    BY username
| where mvcount(countries) > 1
| eval time_diff_minutes = round((last_login - first_login) / 60, 0)
| where time_diff_minutes < 120
| eval alert = "Impossible Travel Detected"
| table username, ips, countries, time_diff_minutes, alert
```

### Process and Endpoint Analysis

**Office applications spawning scripting engines:**

```spl
index=sysmon EventCode=1 earliest=-24h
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE")
| where match(Image, "(?i)(powershell|cmd|wscript|cscript|mshta|regsvr32)\.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

**Encoded PowerShell commands:**

```spl
index=sysmon EventCode=1 Image="*powershell*" earliest=-24h
| where match(CommandLine, "(?i)(-enc|-encodedcommand|-ec)\\s+[A-Za-z0-9+/=]{20,}")
| eval encoded_length = len(replace(CommandLine, ".*(-enc|-encodedcommand|-ec)\\s+([A-Za-z0-9+/=]+).*", "\\2"))
| eval risk_level = if(encoded_length > 500, "HIGH", "MEDIUM")
| table _time, Computer, User, CommandLine, encoded_length, risk_level
```

**Rare processes (potential malware):**

```spl
index=sysmon EventCode=1 earliest=-7d
| stats count BY Image
| where count < 3
| sort count
| eval note = "Rarely seen — investigate"
| table Image, count, note
```

**Process running from suspicious paths:**

```spl
index=sysmon EventCode=1 earliest=-24h
| where match(Image, "(?i)(\\\\temp\\\\|\\\\appdata\\\\roaming\\\\|\\\\programdata\\\\|\\\\users\\\\public\\\\)")
| where NOT match(Image, "(?i)(\\\\microsoft\\\\|\\\\windows\\\\|\\\\chrome\\\\)")
| table _time, Computer, User, Image, CommandLine, ParentImage
```

### Network Traffic Analysis

**Top external connections (data exfiltration risk):**

```spl
index=netflow OR index=firewall earliest=-1h
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
    AND NOT cidrmatch("172.16.0.0/12", dest_ip)
    AND NOT cidrmatch("192.168.0.0/16", dest_ip)
| stats sum(bytes_out) AS total_bytes BY src_ip, dest_ip
| eval mb_out = round(total_bytes / 1048576, 2)
| where mb_out > 100
| sort -mb_out
| table src_ip, dest_ip, total_bytes, mb_out
```

**DNS DGA detection (high entropy domains):**

```spl
index=dns earliest=-1h
| eval domain_part = replace(query, "\.[^.]+$", "")
| eval domain_len = len(domain_part)
| eval entropy = -sum_entropy   /* simplified — use lookup for real entropy */
| where domain_len > 12
| stats count AS queries, values(answers) AS resolutions BY domain_part
| where queries < 3
| sort -domain_len
| table domain_part, domain_len, queries, resolutions
```

### Web Application Analysis

**HTTP brute force against login endpoint:**

```spl
index=web sourcetype=access_combined earliest=-1h
(uri="/login" OR uri="/wp-login.php" OR uri="/admin/login")
| stats count AS requests, dc(user) AS unique_users BY clientip
| where requests > 50
| eval attack_type = "Login brute force"
| table clientip, requests, unique_users, attack_type
```

**Scanner user agents:**

```spl
index=web sourcetype=access_combined earliest=-24h
| where match(useragent, "(?i)(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|burpsuite)")
| stats count BY clientip, useragent
| table clientip, useragent, count
```

---

## Advanced SPL: Transactions

The `transaction` command groups related events within a time window — essential for multi-step detection.

**Example: Correlate failed logins with subsequent success:**

```spl
index=windows (EventCode=4625 OR EventCode=4624) earliest=-2h
| transaction Account_Name maxspan=30m keepevicted=true
| where mvcount(EventCode) > 1
| where mvcount(eval(if(EventCode=4624, EventCode, null()))) > 0
| table _time, Account_Name, src_ip, duration, eventcount
```

**Example: Track a user's movement across systems:**

```spl
index=windows EventCode=4624 Logon_Type=3 earliest=-1h
| transaction Account_Name maxspan=1h
| where mvcount(Computer) > 3
| eval systems_visited = Computer
| table Account_Name, systems_visited, duration
```

---

## Query Optimization Tips

| Practice | Why It Helps |
|----------|-------------|
| Specify `index=` | Limits search scope to relevant indexes |
| Use `earliest=` and `latest=` | Limits time range; most important optimization |
| Put restrictive filters first | Splunk evaluates left-to-right |
| Use `tstats` for data model queries | 10–100× faster than raw search |
| Avoid `*` as sole search term | Searches everything; always add more context |
| Use `fields` to project early | Reduces memory and I/O for subsequent pipes |

**Example: Optimized vs. unoptimized**

```spl
-- Slow (no index, no time range, late filter):
search EventCode=4625 | table _time, Account_Name | where src_ip="192.168.1.1"

-- Fast (specific index, time range, early filter):
index=windows EventCode=4625 src_ip=192.168.1.1 earliest=-1h
| table _time, Account_Name, src_ip
```

---

## Practice Exercises

1. Write a query to find the top 10 source IPs generating HTTP 404 errors in the last 24 hours.
1. Find all processes that made network connections within 30 seconds of being created by a parent process.
1. Identify users who logged in from more than 3 different workstations in the last hour.
1. Find any scheduled task creation events (EventCode=4698) that occurred within 10 minutes of a successful logon from an external IP.
