# Drill 02 (Intermediate) — Solution: Incident Triage and Escalation Report

## Attack Narrative Analysis

**All three alerts are clearly related.** They form a coherent attack chain:

1. **Alert 1 (22:05)**: Attacker logs in using finance_tom's stolen credentials from a Russian IP. The login succeeds — no MFA, or MFA was bypassed.
1. **Alert 2 (22:09)**: 4 minutes after login, the attacker immediately begins mass-downloading financial files — 847 files in under 10 minutes (vs. normal 12/hour = ~70x baseline).
1. **Alert 3 (22:18)**: 13 minutes after initial access, 2.3GB of data is pushed out over Tor to evade detection of the destination.

**This is a complete data theft attack**: Credential compromise → Data collection → Exfiltration.

---

## Sample Escalation Report

```text
INCIDENT ESCALATION REPORT
===========================
Incident ID:          INC-2024-0315-001
Analyst:              [Analyst Name]
Date/Time:            2024-03-15 22:30:00
Classification:       TRUE POSITIVE
Severity:             CRITICAL

SUMMARY:
The account finance_tom was used to access and exfiltrate 2.3GB of sensitive financial
Q1 reports from outside business hours. The login originated from a Russian IP address,
suggesting credential theft. The data was exfiltrated via a Tor exit node, indicating
deliberate evasion of network monitoring. This constitutes a critical data breach of
confidential pre-release financial information.

TIMELINE OF EVENTS:
22:05:00 - Successful login to WKSTN-FIN-003 as finance_tom from 45.142.212.100 (Russia)
22:05:xx - Session established; attacker begins reconnaissance
22:09:00 - Mass file access begins: 847 files in /Finance/Q1-Reports/
22:18:00 - 2.3GB outbound transfer to 185.220.101.34 (Tor exit node) begins
22:18:xx - Data exfiltration complete (estimated based on transfer size)

AFFECTED ASSETS:
- User account: finance_tom (DOMAIN\finance_tom)
- Workstation: WKSTN-FIN-003
- File server: FILESERVER-FIN
- Data: /Finance/Q1-Reports/ (847 files, ~2.3GB)
- Network: External connection to 185.220.101.34

ATTACK NARRATIVE:
An attacker obtained the credentials for finance_tom (likely via phishing, credential
stuffing, or purchase on dark web). At 22:05 on a Friday evening, outside business hours,
the attacker logged into finance_tom's workstation from a Russian IP address. They
immediately located and mass-downloaded 847 financial report files from the Q1 Reports
directory — 70x the user's normal access rate — suggesting they knew exactly what they
were looking for. Within 13 minutes of initial access, they exfiltrated 2.3GB of data
through an encrypted Tor connection to evade network-based detection. The speed and
precision of the attack suggests a targeted, pre-planned operation rather than opportunistic
access.

MITRE ATT&CK MAPPING:
T1078   - Valid Accounts: Used finance_tom's legitimate credentials to bypass authentication
T1083   - File and Directory Discovery: Navigated to specific directory with financial data
T1048.003 - Exfiltration Over Alternative Protocol: Used Tor (encrypted) for data exfiltration
T1090.003 - Proxy: Multi-hop Proxy (Tor): Obscured exfiltration destination
T1539   - Steal Web Session Cookie (possible): If credentials were stolen via browser

POTENTIAL IMPACT:
- Confidential Q1 financial reports (847 files, 2.3GB)
- Pre-release earnings data may be used for insider trading
- Regulatory implications: GDPR/financial regulation breach notification likely required
- Reputational risk if data is leaked or sold

RECOMMENDED IMMEDIATE ACTIONS:

1. DISABLE finance_tom's account immediately

2. BLOCK outbound traffic to 185.220.101.34 and all Tor exit nodes
3. ISOLATE WKSTN-FIN-003 from the network
4. PRESERVE all logs from WKSTN-FIN-003 and FILESERVER-FIN for forensic analysis
5. NOTIFY legal team: potential regulatory reporting obligations (GDPR 72-hour notification)
6. INVESTIGATE how credentials were compromised (check for phishing emails to finance_tom)
7. AUDIT all financial directory access for the last 30 days
8. REVIEW MFA implementation: why did a foreign login succeed without MFA challenge?

ESCALATION TO:
- Incident Response Team Lead
- SOC Manager
- Legal/Compliance Team
- CISO (for regulatory notification decision)
```

---

## Scoring Notes

Full marks require:

* Correct identification that all 3 alerts are related (1 incident, not 3)
* Complete timeline of attack stages
* At least 3 MITRE ATT&CK techniques correctly mapped
* Identification of specific data at risk (/Finance/Q1-Reports/)
* At least 4 specific, actionable containment recommendations
* Recognition of regulatory notification requirements
