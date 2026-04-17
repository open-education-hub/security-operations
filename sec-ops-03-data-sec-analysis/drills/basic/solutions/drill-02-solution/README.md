# Solution: Drill 02 — Log Format Parsing

## Task 1: CEF Log Answers

1. **Source IP and port:** `192.168.5.101:54321` (fields `srcip` and `srcport`)
1. **Destination IP and port:** `185.220.101.5:443` (fields `dstip` and `dstport`)
1. **Action:** `deny` — the firewall blocked this connection
1. **Entering interface:** `LAN` (field `srcintf=LAN`)
1. **CEF severity:** `6` — the 7th field in the CEF header (severity ranges 0–10; 6 is medium-high)
1. **Data transferred:** No — `sentbyte=0` and `rcvdbyte=0`; the connection was denied before any data was sent
1. **Time (UTC):** `2024-03-15T14:23:01Z` (fields `date=2024-03-15` and `time=14:23:01`, `tz=+0000`)

**Security significance:** An internal host (`192.168.5.101`) attempted to connect to `185.220.101.5` on port 443.
The destination IP (`185.220.101.5`) is a known TOR exit node / malicious host (as seen in Demo 03 and 04).
The firewall denied it — this is a good sign that blocking is in place — but the analyst should still investigate *why* the internal host is trying to reach this IP.
It may indicate a prior compromise where malware was installed but C2 is being blocked.

---

## Task 2: JSON CloudTrail Answers

1. **What did contractor01 do?** Attached the `AdministratorAccess` policy to their own IAM user account. This grants full administrative access to the AWS account.

1. **Is this event read-only?** **No** — `"readOnly": false`. This is a write/modify operation.

1. **Security significance of policyArn:** `arn:aws:iam::aws:policy/AdministratorAccess` is AWS's built-in policy granting **unrestricted access to all AWS services and resources**. Attaching this to any user — especially a contractor — is a severe privilege escalation. This is equivalent to making someone a domain admin.

1. **Time:** `2024-03-15T02:33:17Z` — 2:33 AM UTC

1. **Is this suspicious?** **Yes, very.** 2:33 AM UTC is outside normal business hours for most North American and European organizations. A contractor attaching the most powerful AWS policy to their own account at 2:33 AM is a major red flag. This pattern matches account takeover behavior: attackers compromise credentials, then escalate privileges during off-hours to avoid immediate detection.

1. **MITRE ATT&CK technique:**
   * **T1098.001 — Account Manipulation: Additional Cloud Credentials**
   * More specifically: **T1078.004 — Valid Accounts: Cloud Accounts** (using a legitimate account to escalate)
   * Also: **T1548.005 — Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access** (IAM privilege escalation)

---

## Task 3: ECS Field Mapping

| Zeek Field | Value | ECS Field Name |
|-----------|-------|---------------|
| `ts` | `1710500000.123` | `@timestamp` |
| `id.orig_h` | `192.168.1.50` | `source.ip` |
| `id.orig_p` | `54321` | `source.port` |
| `id.resp_h` | `203.0.113.10` | `destination.ip` |
| `id.resp_p` | `80` | `destination.port` |
| `method` | `POST` | `http.request.method` |
| `host` | `malicious-c2.example.com` | `url.domain` |
| `uri` | `/update` | `url.path` |
| `user_agent` | `Go-http-client/1.1` | `user_agent.original` |
| `status_code` | `200` | `http.response.status_code` |

---

## Task 4: Threat Identification

1. **Attack type:** This is a **spear-phishing → macro execution → PowerShell C2 → persistence** attack chain. Specifically, it appears to be an **Emotet-style** initial access and installation sequence.

1. **Patient zero (first indicator of compromise):**
   * `2024-03-15T14:23:12Z` — **Sysmon Event 1** where WINWORD.EXE spawned powershell.exe with an encoded command.
   * The `4624` logon at 14:23:00 may be normal user activity (the user opened their machine). The compromise moment is when Office spawned PowerShell.

1. **Persistence indicator:**
   * `2024-03-15T14:27:44Z` — **Windows Event 4698** (Scheduled task created): `\Microsoft\Windows\UpdateCheck` running `svchost32.exe`. This is the persistence mechanism — the attacker established a scheduled task to ensure their malware survives reboots.

1. **MITRE ATT&CK techniques:**
   * **T1566.001** — Phishing: Spearphishing Attachment (implied by WINWORD opening document with macro)
   * **T1059.001** — Command and Scripting Interpreter: PowerShell (powershell.exe spawned with encoded command)
   * **T1071.001** — Application Layer Protocol: Web Protocols (HTTPS C2 over port 443)
   * **T1547.001** — Boot or Logon Autostart Execution: Scheduled Task/Job
   * **T1105** — Ingress Tool Transfer (PowerShell downloaded payload to AppData)

1. **Immediate analyst actions:**

   a. **Isolate the host** `192.168.1.50` from the network via EDR or network segmentation (stop active C2)
   b. **Block the C2 IP** `185.220.101.5` and domain `update-services.ru` at the firewall and DNS resolver
   c. **Search for lateral movement** — check if `jsmith`'s account was used to log into other systems after 14:23
   d. **Preserve evidence** — collect memory dump and disk image before remediation
   e. **Check for other compromised hosts** — search for other internal hosts communicating with the same C2 IP
   f. **Escalate to Tier 2 / IR team** — this is a confirmed active compromise, not just an alert
