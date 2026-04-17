# Drill 02 (Basic): Alert Classification Practice

## Description

You are a Tier 1 SOC analyst working the morning shift.
Your alert queue has 6 alerts.
For each alert, classify it and decide on an action.

## Objectives

* Practice rapid alert triage.
* Apply severity classification rules.
* Make classification decisions with limited information (just like real-world triage).

## Alert Queue

### Alert A

```text
Time:     2024-03-10 06:45:00
Rule:     High CPU usage detected
Host:     PROD-WEB-01
Details:  CPU at 98% for 15 minutes. Process: nginx
Severity: Medium (automated)
```

### Alert B

```text
Time:     2024-03-10 07:02:00
Rule:     Antivirus - Malware Quarantined
Host:     LAPTOP-ACCT-007
User:     sarah.jones
Details:  Trojan.GenericKD.46 detected and quarantined in
          C:\Users\sarah.jones\Downloads\invoice_march.pdf.exe
Severity: High (automated)
```

### Alert C

```text
Time:     2024-03-10 07:15:00
Rule:     Scheduled scan completed
Host:     VULN-SCANNER-01
Details:  Weekly vulnerability scan finished. 247 hosts scanned.
          12 Critical findings, 34 High findings.
Severity: Low (automated)
```

### Alert D

```text
Time:     2024-03-10 07:30:00
Rule:     Port scan detected
Source:   10.0.0.200 (known: IT team's Nessus scanner)
Details:  TCP SYN scan from 10.0.0.200 against 192.168.0.0/24
Severity: High (automated)
```

### Alert E

```text
Time:     2024-03-10 07:55:00
Rule:     Outbound connection to Tor network
Host:     WKSTN-DEV-015
User:     dev_mike
Details:  TCP connection to 176.10.104.240:9001 (known Tor relay)
Severity: Critical (automated)
```

### Alert F

```text
Time:     2024-03-10 08:10:00
Rule:     New local admin account created
Host:     FILESERVER-01
Details:  Account 'helpdesk_temp' created in Administrators group
          by user DOMAIN\admin_ops
Severity: High (automated)
```

## Your Task

For each alert, fill in the table:

| Alert | True/False/Needs Inv. | Final Severity | Action (Close/Monitor/Escalate) | One-line note |
|-------|----------------------|----------------|----------------------------------|---------------|
| A | | | | |
| B | | | | |
| C | | | | |
| D | | | | |
| E | | | | |
| F | | | | |

## Hints

* Check if the source is a known legitimate system.
* Consider what a file named `*.pdf.exe` implies.
* High CPU on a web server could be legitimate load or cryptomining.
* Tor connections from corporate workstations are almost always policy violations.
* Creating admin accounts outside change management is suspicious.
* Vulnerability scan alerts are expected and planned.
