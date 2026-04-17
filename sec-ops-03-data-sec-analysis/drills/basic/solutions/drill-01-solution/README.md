# Solution: Drill 01 — Data Source Classification

## Task 1: Answers

| # | Log Source | Category | Primary Use Case | Attack Detected |
|---|-----------|----------|-----------------|----------------|
| 1 | Windows Security Event Log (4625) | Endpoint / Authentication | Detection | Brute-force, credential stuffing |
| 2 | Zeek conn.log | Network | Detection / Investigation | Port scanning, C2 beacons, lateral movement (SMB) |
| 3 | Apache access.log | Application | Detection / Investigation | Web scanning, SQLi attempts, directory traversal |
| 4 | AWS CloudTrail | Cloud | Detection / Compliance | Privilege escalation, data exfiltration from S3, IAM abuse |
| 5 | Corporate DNS resolver logs | DNS | Detection | C2 communication via DGA domains, DNS tunneling |
| 6 | Sysmon Event ID 1 | Endpoint | Detection / Investigation | Malware execution, living-off-the-land (LOLBin) attacks |
| 7 | Azure AD Sign-in logs | Authentication / Cloud | Detection / Compliance | Account takeover, MFA bypass, impossible travel |
| 8 | NetFlow records | Network | Investigation | Data exfiltration volume, lateral movement patterns |
| 9 | Web proxy logs | Network / Application | Detection | Malware C2 over HTTP, suspicious user agents, phishing |
| 10 | Kubernetes API audit log | Cloud | Detection / Compliance | Container escape, RBAC abuse, secret enumeration |

**Notes on grading:**

* For "Primary Use Case," multiple answers may be correct. Detection + Investigation overlap significantly.
* Category "Authentication" is a subset of Endpoint or Cloud but is correct as a standalone category.

## Task 2: Gap Analysis Answers

| Attack Stage | Detected? | Missing Log Source |
|-------------|-----------|-------------------|
| Initial compromise of Linux web server | **Partially** — firewall allows inbound traffic but doesn't log app-layer detail. Web proxy only covers outbound. | **Linux application logs + auditd logs** from the web server |
| Privilege escalation via kernel exploit | **No** — Windows Event Logs don't cover Linux; firewall is perimeter-only | **Linux auditd logs** (tracks execve syscalls, setuid events, privilege changes) |
| DNS tunneling exfiltration | **No** — Firewall typically allows DNS outbound; proxy logs only cover HTTP/HTTPS | **DNS resolver logs** (to detect high-volume TXT queries, long hostnames, and NXDomain storms indicative of DGA/tunneling) |

**Key insight:** The existing log collection has a complete blind spot for Linux endpoint activity and DNS-based exfiltration — two of the most common attack vectors.

## Task 3: Priority Recommendations (Model Answer)

### Priority 1: Endpoint Detection — Sysmon or EDR

**Justification:** Ransomware delivered via phishing is the top threat.
The kill chain for ransomware requires: (1) a phishing email executes a macro, (2) the macro spawns PowerShell or another shell, (3) a payload is downloaded and executed. **None of these steps are visible** without endpoint logging.
Sysmon provides free, high-fidelity process creation logs that would catch macro → PowerShell spawning (the most reliable ransomware indicator).
An EDR like Microsoft Defender for Endpoint adds behavioral blocking on top of logging.
Without endpoint visibility, the organization is blind to the most critical attack phase.

### Priority 2: AWS CloudTrail

**Justification:** The organization operates in AWS, and cloud account takeover is listed as a top-3 risk.
CloudTrail records all API calls — including `ConsoleLogin`, `CreateUser`, `AttachUserPolicy`, and `GetObject` — making it essential for detecting credential compromise, privilege escalation, and data exfiltration from S3.
It must be enabled in **all regions** (not just the primary region) because attackers often create resources in unused regions to avoid detection.
CloudTrail is free for management events and extremely low-volume, making it one of the highest-value, lowest-cost log sources available.

**Why not Active Directory audit logs?** AD logs are valuable for privileged admin monitoring, but they require Windows DC access to collect at full fidelity.
They are the third priority — important but superseded by the ransomware and cloud attack risks listed.
