# Solution Guide — Project 01: SOC Basics

> **Instructor use only. Do not distribute to students before submission.**

---

## Overview of Expected Outcomes

This project tests students' ability to set up monitoring, write detection rules, investigate alerts, perform basic network forensics, and produce professional documentation.
The 5 simulated events are designed with increasing difficulty.

---

## Task 1: Log Collection — Expected Solution

Students should see 3 index patterns in Kibana:

* `patient-portal-*` — Apache/Nginx access logs in JSON format
* `syslog-*` — Generic syslog from the patient-portal container
* `network-*` — Simulated NetFlow-style records

Common issues:

* Elasticsearch index not created: `docker compose exec elasticsearch curl -X GET http://localhost:9200/_cat/indices`
* Filebeat not running: `docker compose logs filebeat`
* Time filter wrong: students often forget to set "Last 1 hour" to "Last 30 minutes"

---

## Task 2: Detection Rules — Model Solutions

**Rule 1: Brute Force Detection**

```json
{
  "name": "HTTP Brute Force",
  "query": "status:401",
  "timeframe": {"minutes": 1},
  "threshold": 10,
  "group_by": ["source_ip"],
  "alert_type": "frequency"
}
```

**Rule 2: Known Malicious IP**

```json
{
  "name": "Connection to Known Malicious IP",
  "query": "destination_ip:(104.21.0.5 OR 185.220.101.0 OR 192.0.2.100)",
  "alert_type": "any"
}
```

**Rule 3: Login from Attacker IP**

```json
{
  "name": "Successful Login After Failures",
  "query": "status:200 AND uri:/login",
  "condition": "source_ip in recent_failed_logins within 5 minutes"
}
```

*Note: Rule 3 requires correlation across events.
Students using pure Kibana/ElastAlert may need to use a two-stage rule or Python script.
Accept any working implementation.*

---

## Task 3: Security Events — Expected Findings

### Event 1: Brute Force

**What triggered the alert:** >10 HTTP 401 responses within 1 minute from IP `172.20.0.99`

**Source/target:** `172.20.0.99` → `patient-portal:8080/login`

**Context:** Log shows 250+ failed login attempts with usernames `admin`, `user`, `test`, `patient1` over 3 minutes.
Classic dictionary/credential stuffing attack.

**True positive.** Confirmed brute force — rapid sequential requests with different username/password combinations.

**Recommended response:** Block source IP at firewall; consider implementing rate limiting and account lockout on the portal.

---

### Event 2: Successful Login After Brute Force

**What triggered the alert:** Rule 3 — successful HTTP 200 to `/login` from `172.20.0.99` (same IP that generated 250 failures).

**What happened:** After 250 failures, the attacker succeeded with username `dr.popescu`, password `Welcome123` (weak password, no lockout policy).

**True positive.** Compromised account — brute force succeeded.

**Recommended response:** Immediately invalidate the session token for `dr.popescu`; reset password; determine what the attacker accessed after login; check for account lockout policy enforcement.

---

### Event 3: SQL Injection

**What triggered the alert:** Stretch rule 4 OR manual investigation — URI contains `'` and `UNION SELECT` pattern.

**Payload:** `GET /search?q=' UNION SELECT username,password FROM users--`

**True positive.** Classic UNION-based SQL injection.
The application likely returned database content in the response.

**Recommended response:** Immediately check if data was returned (response body in logs); patch the application with parameterised queries; consider WAF deployment; check if any sensitive query was successful.

---

### Event 4: Large File Download

**What triggered the alert:** Stretch rule 5 OR manual filter — response body size >1MB on URI `/export?file=patient_appointments_all_2024.csv`.

**Context:** The attacker's session (`dr.popescu`) made this request.
Response was HTTP 200, 2.4MB.

**True positive.** Insider threat or compromised account data exfiltration.
The patient database export was successfully downloaded.

**Recommended response:** This is the most severe event — a GDPR data breach.
Notify the DPO; assess if GDPR 72h notification to the supervisory authority is required; revoke the session; preserve evidence.

---

### Event 5: Connection to Malicious IP

**What triggered the alert:** Rule 2 — outbound connection from `172.20.0.50` (internal server) to `192.0.2.100` (in IOC list).

**True positive.** Possible malware C2 beacon or compromised dependency making an outbound call.

**Recommended response:** Investigate the process making the connection from `172.20.0.50`; check if it is the patient-portal application (possible server-side request forgery from the SQL injection).

---

## Task 4: Network Analysis — Model Findings

**Brute force source and count:**
Using filter `http.response.code == 401`, students should find IP `172.20.0.99` with 252 requests.

**SQL injection in HTTP traffic:**
Filter `http.request.method == GET && http contains "UNION"` will show the payload:
`GET /search?q=%27+UNION+SELECT+username%2Cpassword+FROM+users--`
(URL-encoded `'`)

**Unencrypted sensitive data:**
The patient portal runs on HTTP (not HTTPS) — all traffic including login credentials and the patient CSV export is in cleartext.
Students should flag this as a critical finding.

**File download bytes:**
Filter `http.request.uri contains "export"` and follow the TCP stream → `Content-Length: 2457600` (approximately 2.4 MB).

---

## Task 5: Incident Report — Grading Notes

The strongest reports will:

* Identify Event 4 (data exfiltration) as the highest severity event
* Correctly sequence the attack chain: brute force → credential compromise → SQL injection → data exfiltration
* Mention GDPR implications (personal health data of patients = sensitive data under GDPR Article 9)
* Recommend: password policy / account lockout, HTTPS enforcement, input validation/parameterised queries, data export authorisation controls

Deduct points for:

* Reports that miss the attack chain (treating events as isolated)
* Reports with no GDPR mention
* Executive summary too technical for management audience

---

## Task 6: Reflection — Model Answers

**1.
Hardest event to detect:** Event 5 (malicious IP connection) — because it requires an IOC feed, which is easily missed if the IOC list is not configured in the detection rule.
Also Event 3 (SQL injection) if stretch rules were not written.

**2.
Missing log sources:**

* Application error logs (to see SQL error responses confirming injection success)
* Database query logs (to see the actual query executed)
* Authentication server logs with more detail (session IDs, MFA status)

**3.
One improvement:** HTTPS enforcement — all traffic is currently unencrypted, meaning credentials and exported data travel in cleartext.
This is the highest-impact fix.

**4.
False positives for Rule 3:** A user who mistyped their password once and then successfully logged in would trigger this rule.
Tuning: increase the failure threshold (e.g., require 5+ failures before correlating with success, not just 1).

**5.
Difference from production SOC:**

* Volume: production SOC processes thousands of alerts per day, not 5
* Noise: production has many false positives that students did not experience
* 24×7: production SOC operates around the clock
* Tooling: production has mature SIEM with years of tuning, not a fresh install
* Escalation: production has defined escalation paths, legal teams, management approval for containment
