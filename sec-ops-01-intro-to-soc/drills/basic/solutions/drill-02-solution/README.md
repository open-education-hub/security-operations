# Drill 02 (Basic) — Solution: Alert Classification Practice

## Solution Table

| Alert | True/False/Needs Inv. | Final Severity | Action | Note |
|-------|----------------------|----------------|--------|------|
| A | Needs Investigation | Medium | Monitor | High CPU on nginx could be load spike or cryptomining — monitor and check process tree |
| B | True Positive | High | Escalate | `.pdf.exe` double extension = malware lure; AV quarantined but investigate how it arrived |
| C | False Positive | Low | Close | Scheduled scan completing is expected; review findings separately but not an incident |
| D | False Positive | Low | Close | Nessus scanner is a known IT tool; confirm with IT team if scan was authorized today |
| E | True Positive | Critical | Escalate + Contain | Tor connection from dev workstation — possible data exfiltration or policy violation; isolate |
| F | Needs Investigation | High | Escalate | Admin account creation requires change management approval — verify with admin_ops if authorized |

## Detailed Reasoning

### Alert A — High CPU on nginx

* nginx is a legitimate web server process.
* High CPU could be: normal traffic spike, DDoS attack, cryptomining malware.
* **Action**: Check process tree for unusual child processes. Check network connections. If nginx is serving legitimate traffic at high volume, it's benign. If unexpected outbound connections exist, escalate.

### Alert B — Malware Quarantined

* The filename `invoice_march.pdf.exe` uses a double extension to trick users into thinking it's a PDF.
* This is a classic phishing/malware delivery technique.
* **Action**: Even though it's quarantined, investigate how it arrived (email? download?), check if any other machines received the same file, and determine if it executed before quarantine.

### Alert C — Vulnerability Scan Complete

* Scheduled scans are operational, not security incidents.
* **Action**: Close this alert. The critical and high findings in the scan should be tracked separately in a vulnerability management system, not as SOC incidents.

### Alert D — Port Scan from Known Nessus Scanner

* The source `10.0.0.200` is documented as the IT team's Nessus vulnerability scanner.
* **Action**: Confirm with IT that the scan was authorized for this week. If yes, close. If the scan wasn't scheduled, investigate who initiated it.

### Alert E — Tor Connection

* Tor usage on a corporate network is almost always a policy violation.
* Possible reasons: user bypassing content filtering, malware C2 traffic.
* **Action**: Critical — isolate the workstation immediately, investigate dev_mike's recent activity, check what was transferred over the Tor connection.

### Alert F — New Local Admin Account

* Creating admin accounts outside normal processes violates the principle of least privilege.
* Could be: IT doing emergency maintenance, insider threat, or attacker maintaining persistence.
* **Action**: Contact admin_ops to verify if this was authorized. If no change ticket exists, treat as suspicious and escalate.

## Key Learning Points

* **Context transforms classification**: the same event can be benign or critical depending on what you know about the environment.
* **False positives are normal** but should be documented and used to tune detection rules.
* **Tor and double extensions** are near-universal red flags.
* **Always verify before closing** — a quick check saves a big headache later.
