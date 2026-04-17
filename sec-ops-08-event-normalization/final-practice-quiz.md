# Final Practice Quiz — Session 08: Event Correlation and Normalization

**Instructions:**

* Questions 1–5: Short answer (1–4 sentences each). Show reasoning.
* Questions 6–7: Long answer (1–2 paragraphs each). Depth and accuracy are scored.

**Time:** 30 minutes

**Scoring:** Short questions 10 pts each, long questions 25 pts each = 100 pts

---

## Short Answer Questions

### Question 1

**(10 points)**

A CEF log contains the field `cs1=admin_policy` with `cs1Label=PolicyName`.
Why does CEF use `cs1`/`cs1Label` pairs instead of just naming the field `PolicyName` directly?
What is the drawback of this approach from a normalization perspective?

**Space for your answer:**

---

**Model Answer:**
CEF was designed to be a generic format usable by any vendor without requiring schema coordination between vendors.
Rather than defining thousands of possible application-specific field names, CEF reserves 6 custom string slots (`cs1`–`cs6`) that vendors can reuse for whatever fields their product needs.
The `csNLabel` field tells the human reader what the data actually means.

The normalization drawback is significant: two different vendors can use `cs1` for completely different data.
Vendor A uses `cs1` for firewall policy name; vendor B uses `cs1` for username.
When normalizing to ECS, the pipeline must know the vendor identity to correctly map `cs1` to its actual semantic meaning.
Without source context, `cs1` values cannot be normalized automatically.

---

### Question 2

**(10 points)**

In Logstash, you have a filter that parses syslog messages with two grok patterns in an array (Pattern A for failed logins, Pattern B for successful logins).
A log message arrives that matches neither pattern and gets tagged `_grokparsefailure`.
List two actions you should take and explain why each is important.

**Space for your answer:**

---

**Model Answer:**

1. **Log the parse failure and monitor the failure rate**: The `_grokparsefailure` tag allows you to count parse failures over time. A sudden spike in failures indicates the log format changed upstream (e.g., an application update changed the message format), which would silently blind your detections. Track parse failure rate as a pipeline health metric.

1. **Investigate the unmatched event and add a pattern**: Every parse failure means an event that cannot be correlated or searched by field. You should retrieve a sample of the failing events, understand why they don't match, and add a new grok pattern to handle the new format. Do NOT discard parse failures — they should be forwarded as-is to storage so you can still retroactively parse them after fixing the pipeline.

---

### Question 3

**(10 points)**

Explain the difference between a **sliding window** and a **tumbling window** for correlation, and give one use case where a sliding window is more appropriate than a tumbling window.

**Space for your answer:**

---

**Model Answer:**
A **tumbling window** divides time into fixed, non-overlapping intervals (e.g., every 5 minutes: [0:00–0:05), [0:05–0:10)...).
Events are evaluated once per window; an attack that straddles the window boundary (e.g., 3 failures in one window, 8 in the next) may not trigger a threshold-10 alert in either window even though there were 11 total failures in 10 minutes.

A **sliding window** continuously re-evaluates as each new event arrives.
If the window is 5 minutes, any 5-minute span containing 10+ failures triggers the alert, regardless of when it starts.

**Better use case for sliding window**: Detecting a brute force attack in real time.
If an attacker sends exactly 5 failed logins per 5-minute tumbling window to stay below the threshold, they would evade detection.
A sliding window catches the true 10-in-5-min pattern by evaluating the window anchored to each new event.

---

### Question 4

**(10 points)**

What is the MITRE ATT&CK **sub-technique** for brute force using a list of common passwords tried across many accounts (as opposed to many passwords tried on one account)?
Why does this distinction matter for detection rule design?

**Space for your answer:**

---

**Model Answer:**
The technique is **T1110.003 — Brute Force: Password Spraying**.
This is distinct from T1110.001 (Password Guessing against one account) and T1110.004 (Credential Stuffing using breached credentials).

This distinction matters for detection because the observable pattern is different:

* **T1110.001 (traditional brute force)**: Many attempts on ONE account → threshold by `user.name`
* **T1110.003 (password spray)**: Few attempts (1–3) on MANY accounts → threshold by `source.ip` counting `distinct(user.name)`
* **T1110.004 (credential stuffing)**: Many username/password pairs from breach lists → high distinct accounts + external IP + pattern from known breach list

A rule that only counts failures per-user will miss password spraying entirely.
Detection requires counting distinct users targeted per source IP within a time window.

---

### Question 5

**(10 points)**

A new analyst argues: "We should whitelist our entire `10.0.0.0/8` internal IP range from authentication-failure alerts since all real attacks come from the internet." What is wrong with this reasoning?

**Space for your answer:**

---

**Model Answer:**
This reasoning is flawed for two critical reasons:

1. **Insider threats originate internally**: Malicious insiders, employees with compromised machines, or contractors with internal access can launch brute force attacks from internal IPs. Whitelisting the entire internal range would completely blind the SOC to these threats.

1. **Attackers already inside the network**: Once an attacker achieves initial access (via phishing, VPN compromise, etc.), they operate entirely from internal IP addresses during lateral movement. Their brute force attempts against other internal hosts would come from `10.x.x.x` addresses. This is precisely the lateral movement scenario where detection is most critical.

The correct approach is contextual whitelisting: exclude specific known-good sources like authorized scanners, management servers, or LDAP health check systems — not entire subnets.

---

## Long Answer Questions

### Question 6

**(25 points)**

You are a detection engineer designing a Sigma rule for **T1053.005 — Scheduled Task Creation**.

Describe the complete detection engineering process: (1) which data sources you would use and why, (2) what specific fields/patterns would form the detection logic, (3) at least three legitimate use cases that would generate false positives and how you would handle each, and (4) what ATT&CK tags and severity level you would assign.

**Space for your answer:**

---

**Model Answer:**

**Data Sources:**

* **Windows Security Event ID 4698** (A scheduled task was created): Captures task name, subject user, task content XML. Requires Audit Object Access enabled in Group Policy. Available on all Windows versions.
* **Windows Security Event ID 4702** (Task updated): For detecting modifications to existing tasks.
* **Sysmon EventID 1** (Process creation) for `schtasks.exe` or `at.exe` command-line execution: Captures the command-line arguments.
* **Windows Security Event ID 4688** with command-line auditing: Alternative to Sysmon for process creation.

Prefer EID 4698 as primary: it provides the task XML (which may contain the command to execute), the registering user, and the task name.
Sysmon EID 1 for `schtasks.exe` adds the command-line context.

**Detection Logic:**

```yaml
detection:
  selection_event:
    EventID: 4698     # Scheduled task created
  selection_schtasks:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains|all:
      - '/create'
    CommandLine|contains:
      - '/sc minute'    # Frequent execution
      - '/sc onlogon'   # On user logon
      - '/sc onstart'   # On system start
      - 'powershell'    # PS in task
      - 'cmd /c'        # Cmd in task
  condition: selection_event or selection_schtasks
```

Filters needed:

* Tasks created by `SYSTEM` account for known Windows maintenance tasks
* Tasks in `\Microsoft\Windows\` path (Windows built-in tasks)
* Tasks created by `svchost.exe` (Windows Update, etc.)

**False Positive Sources:**

1. **Windows Update and Windows Defender**: Automatically create/modify scheduled tasks regularly. Handle by: filter `TaskName` starting with `\Microsoft\Windows\` and created by `SYSTEM`/`LOCAL SERVICE`.
1. **Software installation**: Many installers (antivirus, endpoint management, monitoring agents) create scheduled tasks during setup. Handle by: whitelist specific task names after validation with IT, or suppress during maintenance windows identified via change management integration.
1. **IT automation tools** (SCCM, Ansible, Chef): Create tasks for software deployment. Handle by: add lookup table of authorized task-creating service accounts; any task created by `svc-sccm` or `svc-ansible` from known management hosts should be suppressed.

**ATT&CK Tags and Severity:**

* `attack.persistence` (tactic)
* `attack.t1053.005` (Scheduled Task: Windows Task Scheduler)
* `attack.privilege_escalation` (if creating task to run as SYSTEM)

Severity: **Medium** (persistence mechanism — important to detect but not immediately critical; attacker already has code execution).
Escalate to High if: task executes PowerShell with encoded command, or task runs as SYSTEM when created by non-admin.

---

### Question 7

**(25 points)**

Your SOC currently has the following detection coverage for ransomware-relevant techniques:

* **T1078 (Valid Accounts)**: Coverage via threshold brute-force rule only
* **T1059.001 (PowerShell)**: No coverage
* **T1490 (VSS Deletion)**: Full coverage with high-confidence rule
* **T1486 (Data Encrypted)**: Partial coverage via EDR

Explain what gaps exist in this coverage, why each gap matters for ransomware detection, and design a **3-rule detection chain** that would significantly improve the ability to detect a ransomware attack before it reaches the encryption stage (T1486).

**Space for your answer:**

---

**Model Answer:**

**Gap Analysis:**

T1078 is the most critical gap.
A brute-force threshold rule only catches unsophisticated attackers.
Modern ransomware groups (RansomHub, LockBit, BlackCat) buy stolen credentials from initial access brokers and use them directly — no brute force, just a valid credential from an unknown location.
A behavioral detection (impossible travel, first-time country login, login outside baseline hours) is needed to catch these.

T1059.001 is a critical coverage gap because PowerShell is the most common execution mechanism for ransomware's initial staging: downloading the main payload, running discovery scripts, and executing lateral movement modules.
Without PowerShell detection (especially encoded commands, download cradles, and bypass flags), the entire execution phase is invisible.

These gaps matter specifically because: T1078→T1059.001 is the most common ransomware kill chain entry: attacker logs in with stolen credentials, runs a PowerShell download cradle, executes the ransomware loader.
Without detection at either stage, the first visible alert is T1490 (VSS deletion) — at that point, deployment is imminent and there may be as little as 2-5 minutes before encryption begins.

**Three-Rule Detection Chain:**

**Rule 1: Suspicious Login from New Location (T1078)**

```text
Trigger: auth.success AND source.geo.country NOT IN user_baseline_countries[last 30 days]
         AND NOT source.ip IN corporate_vpn_ranges
Severity: High
Output: Entity risk += 50 (feeds into risk score aggregation)
```

This catches credential theft usage without requiring brute force.

**Rule 2: PowerShell Download Cradle (T1059.001)**

```text
Trigger: process.name = powershell.exe AND
         process.command_line MATCHES /(DownloadString|DownloadFile|IEX|Invoke-Expression)/
Severity: High → P1 immediate alert
Output: Auto-create ticket, page on-call analyst
```

This is the most reliable indicator of ransomware staging.
No legitimate business process needs to download and execute code in a single PowerShell invocation without a file on disk.

**Rule 3: Discovery Chain Before VSS Deletion (Sequence)**

```text
Step 1: Discovery tool execution (net.exe, whoami.exe, nltest.exe) on any host
Step 2: VSS deletion command within 30 minutes on same or adjacent host
Trigger: SEQUENCE(step1, step2) BY host.name|subnet WITHIN 30m
Severity: CRITICAL → auto-isolate host, page CISO
```

This catches the reconnaissance-to-deployment sequence in the 15–30 minute window before encryption.
If VSS deletion is triggered, the attacker is moments away from deploying ransomware.
The auto-isolation response is pre-authorized to contain without waiting for analyst review.

**Chain effectiveness**: Rule 1 catches initial access within minutes.
Rule 2 catches staging.
Rule 3 provides a backstop before destruction.
Together, they provide 3 independent opportunities to detect and contain a ransomware attack before encryption — which is the only moment that prevents data loss.
