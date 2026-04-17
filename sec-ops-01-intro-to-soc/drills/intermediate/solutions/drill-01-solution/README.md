# Drill 01 (Intermediate) — Solution: SIEM Query Writing

## Scenario 1: Password Spray Detection

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (?<user>\w+) from (?<src_ip>[^\s]+)"
| stats count as attempts by src_ip, user
| stats
    count(user) as unique_users,
    avg(attempts) as avg_attempts_per_user,
    sum(attempts) as total_attempts
    by src_ip
| where unique_users >= 5 AND avg_attempts_per_user < 3
| eval attack_type="Password Spray"
| sort -unique_users
```

**What it detects:** An IP targeting many accounts with few attempts each — the signature of password spraying, designed to avoid per-account lockout thresholds.

**False positive considerations:** Automated systems (backup clients, monitoring agents) may attempt multiple accounts.
Add a lookup table to exclude known service accounts and IPs.

---

## Scenario 2: After-Hours Login Detection

```spl
index=main sourcetype=linux_secure "Accepted password"
| rex "Accepted password for (?<user>\w+) from (?<src_ip>[^\s]+)"
| eval hour=strftime(_time, "%H")
| eval is_after_hours=if(hour < "07" OR hour >= "20", "YES", "NO")
| where is_after_hours="YES"
| table _time, user, src_ip, hour
| sort _time
```

**What it detects:** Successful logins outside business hours (before 07:00 or at/after 20:00).

**False positive considerations:** Remote workers in different time zones, scheduled jobs, administrators doing maintenance.
Requires per-user baseline or exception list for known after-hours workers.

---

## Scenario 3: Privilege Escalation via Sudo

```spl
index=main sourcetype=syslog sudo
| rex "sudo:\s+(?<user>\w+)\s+:.*COMMAND=(?<command>.*)"
| where match(command, "passwd|adduser|visudo|chmod 777")
| eval mitre="T1548.003 - Sudo and Sudo Caching"
| table _time, user, command, mitre
| sort _time
```

**What it detects:** Users running sensitive commands via sudo — potential privilege escalation or unauthorized system modification.

**False positive considerations:** IT administrators legitimately use these commands.
Correlate with change management tickets; alert on non-IT users or unexpected systems.

---

## Scenario 4: Data Exfiltration Baseline Anomaly

```spl
index=main sourcetype=firewall
| eval day=strftime(_time, "%Y-%m-%d")
| stats sum(bytes_out) as daily_bytes by src_ip, day
| eventstats avg(daily_bytes) as historical_avg, stdev(daily_bytes) as stdev by src_ip
| eval latest_day=strftime(now(), "%Y-%m-%d")
| where day=latest_day
| eval deviation_ratio=daily_bytes/historical_avg
| where deviation_ratio > 3
| eval risk_score=round(deviation_ratio, 2)
| table src_ip, daily_bytes, historical_avg, deviation_ratio, risk_score
| sort -deviation_ratio
```

**What it detects:** IPs sending significantly more data than their historical baseline on the most recent day — a behavioral signal for data exfiltration.

**False positive considerations:** Legitimate large backups, software updates, video conferencing.
Build a calendar of expected high-bandwidth events and exclude them.

---

## Key Insights

1. **Password spray vs brute force**: Detection logic is fundamentally different. Spray = wide, brute force = deep.
1. **Behavioral baselines** are more robust than static thresholds for detecting exfiltration.
1. **Every query needs a false positive plan** — good detection is about signal quality, not just catching threats.
1. **MITRE ATT&CK tagging** in queries makes reporting and escalation cleaner.
