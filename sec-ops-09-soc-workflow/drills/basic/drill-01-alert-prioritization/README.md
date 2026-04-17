# Drill 01 (Basic): Alert Prioritization

## Scenario

You are a Tier 1 SOC analyst at AcmeCorp (1,200 employees, financial services).
It is Monday morning, 08:00 UTC.
You have just logged in and your alert queue contains 12 alerts that arrived overnight.
You have 2 hours until the SLA deadlines start expiring for the oldest alerts.

Your task is to prioritize this queue and triage the top 5 alerts using the framework from Guide 01.

## The Alert Queue

| # | Alert Title | Rule | Fired At | Default Sev |
|---|-------------|------|----------|-------------|
| 1 | Failed SSH — jumphost-01 (12 attempts) | SSH_BRUTE_EXT | 02:15 | P3 |
| 2 | New admin account created — AD | AD_ADMIN_ACCOUNT | 01:44 | P2 |
| 3 | Large data transfer — file-server-01 | DATA_EXFIL_VOLUME | 03:30 | P2 |
| 4 | PowerShell — encoded command — exec-ws-001 | PS_ENCODED | 04:12 | P2 |
| 5 | USB device inserted — ceo-laptop | USB_DEVICE | 07:55 | P3 |
| 6 | Failed login x3 — vpn-gateway (user: s.jones) | VPN_FAIL_MULTI | 06:44 | P3 |
| 7 | Malware signature detected — av-mgr | AV_DETECTION | 05:01 | P2 |
| 8 | Port scan from internal host — dev-ws-055 | PORTSCAN_INTERNAL | 03:15 | P3 |
| 9 | DNS query to known DGA domain — mkt-ws-009 | DNS_DGA | 04:55 | P3 |
| 10 | Admin logged in after hours — srv-mgr-01 | ADMIN_OFFHOURS | 23:58 (Sun) | P3 |
| 11 | TLS certificate error — prod-lb-01 | CERT_ERROR | 07:10 | P4 |
| 12 | RDP brute force — rdp-gw-01 (342 attempts) | RDP_BRUTE | 00:30 | P1 |

## Additional Context Available

* `exec-ws-001` belongs to the CEO's executive assistant
* `file-server-01` contains employee HR records and financial data
* `ceo-laptop` belongs to the CEO (traveling internationally this week)
* `dev-ws-055` — developer workstation, the developer is known to run network scans for their work
* Change management: No scheduled maintenance over the weekend
* No pentest activity scheduled

## Objectives

1. **Re-prioritize** the queue — identify which alerts need immediate attention vs can wait
1. **Triage** the top 5 alerts using the 6-step framework
1. **Document** your triage decisions (TP/FP/Benign TP, severity, action)
1. **Identify** any alerts that can be closed as FP or Benign TP without full investigation
1. **Write** a brief handover note for your colleague arriving at 10:00 UTC

## Deliverables

* Prioritized list with justification
* Triage summary for top 5 alerts
* Proposed actions for each triaged alert

## Hints

* Consider the asset value when assessing severity
* "Default severity" is the rule's default — you can override it with context
* Some alerts may look scary but have obvious benign explanations — which ones?
* RDP brute force at 342 attempts is unusually high — what does that suggest?
