# Drill 01 — Incident Classification Exercise

## Scenario

You are the senior on-call analyst at **EuroBank SA**, a French retail bank with 2.1M customers and 4,500 employees.
You receive the following 6 alerts between 08:00 and 09:00 on a Tuesday morning.

For each alert, provide a complete classification and initial response plan.

---

## Alerts

### Alert 1

```text
Source: Microsoft Sentinel
Time: 08:03 UTC
Rule: Azure AD — Sign-in from impossible travel

Details:
User: pierre.martin@eurobank.fr (Branch Manager, Paris)
Event 1: Successful login from IP 82.45.23.11 (Paris, France) at 07:45 UTC
Event 2: Successful login from IP 203.0.113.45 (Bangkok, Thailand) at 07:52 UTC
Time between logins: 7 minutes
Distance: ~9,100 km (impossible to travel in 7 minutes)
MFA: NOT configured for this account
Last password change: 8 months ago
```

### Alert 2

```text
Source: Proofpoint Email Security
Time: 08:17 UTC
Rule: Large-scale phishing campaign detected

Details:
Phishing email sent to: 847 EuroBank employees
Subject: "URGENT: EuroBank IT Security Update Required"
Link: https://eurobank-security-update.tk/login
Confirmed clicks: 23 employees (Proofpoint click tracking)
Credentials entered: Unknown (no logging on phishing site)
Email gateway: blocked and removed from inboxes at 08:19
```

### Alert 3

```text
Source: CrowdStrike EDR
Time: 08:24 UTC
Rule: Potential credential dumping — LSASS

Details:
Process: TaskManager.exe attempting to access lsass.exe
Host: WORKSTATION-AUDIT-02
User: marie.dupont@eurobank.fr (Internal Auditor)
Command: taskmgr.exe /PID:764 (LSASS PID)
Parent process: explorer.exe
EDR action: BLOCKED and quarantined
Hash: e3b0c44298fc1c149afbf4c8996fb924... (very low VT)
```

### Alert 4

```text
Source: DLP (Digital Guardian)
Time: 08:31 UTC
Rule: Sensitive data exfiltration — financial data

Details:
User: jean.bernard@eurobank.fr (IT Systems Admin)
Action: Uploaded 4.7 GB to personal Google Drive (personal account, not corporate)
Content: Multiple .xlsx files — DLP classified as "Customer Financial Records"
Transfer duration: 12 minutes
Time: Outside business hours (previous night, 23:45–00:00)

Note: jean.bernard submitted resignation last week, final day is tomorrow.
```

### Alert 5

```text
Source: Network IDS (Suricata)
Time: 08:45 UTC
Rule: DNS tunneling detected

Details:
Source host: PAYMENT-PROC-01 (payment processing server — critical)
DNS queries: 8,400 queries in 2 hours to: *.xkzq8j-tunnel.ru
Query length: Average 127 characters (normal: <20)
Domain age: 3 days
VT scan: Domain flagged by 15/90 engines as "malware"
Outbound DNS: blocked at firewall (DNS restricted to internal resolvers)
Note: queries are arriving from inside but being blocked
```

### Alert 6

```text
Source: User report via email to security@eurobank.fr
Time: 09:00 UTC
Reporter: helene.rousseau@eurobank.fr (Finance Director)
Message: "Someone just called me claiming to be from IT support.
They asked me to install a 'security update' by running a .exe file
they sent via WhatsApp. I haven't done it yet. Is this legitimate?"
```

---

## Your Tasks

### Task 1: Complete Classification (30 points)

For EACH of the 6 alerts, provide:

* **Category** (malware, unauthorized access, phishing/social engineering, data breach, insider threat, etc.)
* **Severity** (P1–P5 with justification)
* **Is GDPR relevant?** (YES/NO — why)
* **Top 3 immediate actions** (in priority order)

### Task 2: Priority Ranking (15 points)

You have two analysts (yourself + one colleague).
Rank the 6 alerts in the order you will handle them.
Explain your reasoning.
What are you doing first?

### Task 3: Regulatory Assessment (20 points)

For any alerts where personal customer data may have been exposed:

1. Identify the data at risk (category and approximate scope)
1. Calculate the GDPR notification deadline
1. Identify which DPA (supervisory authority) to notify (France = CNIL)
1. State whether GDPR Article 34 (individual notification) is likely required

### Task 4: Crisis Communication Draft (20 points)

For the most severe incident you identified:

* Write an initial management notification (5 minutes after discovery — internal, confidential)
* Write the GDPR Article 33 notification outline (what sections you would fill in)

### Task 5: Interconnected Incidents? (15 points)

Looking at all 6 alerts together — do any of them appear to be part of a coordinated attack?
Which ones?
Build a hypothesis about what the attacker's goal might be.

---

## Hints

* Alert 4 involves data that was already exfiltrated — timing affects GDPR assessment
* Alert 5 is blocked but still alarming — what does DNS tunneling from a payment server mean?
* Alert 6 might be connected to other alerts — think about who the Finance Director is
* Some alerts might be false positives — which one is most likely?
* Branch Manager credentials + phishing campaign + Finance Director vishing = possible coordinated attack targeting finance
