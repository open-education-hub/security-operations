# Drill 01 (Basic): Data Source Classification

**Estimated time:** 20 minutes

**Difficulty:** Basic

**No tools required** — pen-and-paper or text editor

## Objective

Practice classifying security log sources into the correct categories and understanding what evidence each source provides for a given attack scenario.

---

## Task 1: Classify the Data Sources

For each log source below, identify:

1. The **category** (Endpoint / Network / Authentication / Application / DNS / Cloud)
1. The **primary security use case** (Detection / Investigation / Compliance)
1. One **specific attack** it helps detect

| # | Log Source | Category | Primary Use Case | Attack Detected |
|---|-----------|----------|-----------------|----------------|
| 1 | Windows Security Event Log (Event ID 4625) | ? | ? | ? |
| 2 | Zeek conn.log | ? | ? | ? |
| 3 | Apache access.log | ? | ? | ? |
| 4 | AWS CloudTrail | ? | ? | ? |
| 5 | Corporate DNS resolver logs | ? | ? | ? |
| 6 | Sysmon Event ID 1 (process creation) | ? | ? | ? |
| 7 | Azure AD Sign-in logs | ? | ? | ? |
| 8 | NetFlow records | ? | ? | ? |
| 9 | Web proxy logs | ? | ? | ? |
| 10 | Kubernetes API audit log | ? | ? | ? |

---

## Task 2: Gap Analysis

An organization's SOC currently collects:

* Windows Event Logs (security events only)
* Firewall allow/deny logs
* Web proxy logs

**Question:** A threat actor compromised a Linux web server, escalated privileges using a local kernel exploit, and exfiltrated customer data via DNS tunneling.

For each stage of this attack, identify whether the current log sources would detect it and what log source is **missing**:

| Attack Stage | Detected by Current Sources? | Missing Log Source |
|-------------|-----------------------------|--------------------|
| Initial compromise of Linux web server | ? | ? |
| Privilege escalation via kernel exploit | ? | ? |
| DNS tunneling exfiltration | ? | ? |

---

## Task 3: Log Source Priority

You are a new SOC analyst at a financial services company.
You have budget to add **two** new log sources.
The company currently has:

* No endpoint detection (no Sysmon, no EDR)
* Palo Alto firewall logs (already collected)
* VPN access logs (already collected)

The company's threat model identifies these as top risks:

1. Ransomware via phishing email
1. Insider threat from privileged administrators
1. Cloud account takeover (AWS)

**Question:** Which two log sources would you prioritize adding and why?

Write a 3–5 sentence justification for each choice.

---

## Submission

Write your answers in a text file or markdown document.
There is no automated grading — compare your answers against the solution file.

See `../solutions/drill-01-solution/README.md` for the complete answer key.
