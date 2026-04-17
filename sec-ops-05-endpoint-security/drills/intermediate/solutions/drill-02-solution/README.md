# Drill 02 (Intermediate) Solution: Endpoint Forensics Scenario

---

## Q1 — Login Context Analysis (2 points)

**a) Login details:**

From Block 1 (audit log):

* **Who:** `alice` (uid=1000)
* **From:** `10.20.30.100` (internal IP address)
* **How:** SSH with password authentication (PAM: `pam_unix` used, which is password-based)
* **Time:** 13:55 UTC
* **Session ID:** ses=42

**b) Is this suspicious?
Additional context needed:**

The login itself is not conclusively suspicious — it could be:

* Alice working remotely from another machine (`10.20.30.100`)
* An administrator connecting to Alice's machine to provide support
* An attacker who obtained Alice's credentials

Additional context needed:

1. **Is `10.20.30.100` Alice's regular machine?** If she usually connects from a different IP, this is anomalous.
1. **Is SSH access normal for Alice?** Nurses typically don't SSH into their own workstations.
1. **Is 13:55 during Alice's normal working hours?**
1. **Has Alice connected via SSH before?** Historical baseline comparison.
1. **Is `10.20.30.100` an IT/admin asset?** If an admin connected, there should be a change ticket.

---

## Q2 — Privilege Escalation (2 points)

**a) How attacker escalated to root:**

Block 3 shows: `sudo bash` executed by `auid=1000` (alice's login session), resulting in a bash shell with `uid=0, euid=0` (root).
The attacker simply ran `sudo bash` — no exploit needed.

**b) auid=1000 but uid=0, euid=0 meaning:**

* `auid=1000` = the **audit UID** — this is Alice's original login identity, recorded at login time and immutable for the session
* `uid=0` = the **current UID** — the process is running as root after the `sudo` operation
* `euid=0` = the **effective UID** — the effective permissions are root

This means: Alice's account (or the attacker using Alice's credentials) used `sudo` to gain a root shell.
The audit system correctly records that while the process has root privileges, it originated from Alice's session.

**c) Why sudo bash is a serious configuration problem:**

`sudo bash` gives the user an **unrestricted root shell** — effectively full administrative control of the system.
This is the most dangerous sudo permission that can be granted.

Problems:

1. A regular nurse needs no administrative access to the OS. Principle of Least Privilege is violated.
1. `sudo bash` bypasses any restrictions in sudoers — the user gets a full shell, not a controlled command
1. It means if Alice's password is compromised, the attacker immediately gets root (as happened here)
1. HIPAA requires access controls proportional to role — nurses should have minimal OS-level access

Proper configuration: nurses should have no sudo access at all.
Administrative tasks should be done by IT staff via their own accounts.

---

## Q3 — Timeline Reconstruction (4 points)

| Time (UTC) | Event | Evidence | MITRE ATT&CK |
|-----------|-------|----------|-------------|
| 13:55:00 | Attacker SSH-authenticates as `alice` from 10.20.30.100 | Audit Block 1 | T1078 — Valid Accounts |
| 13:58:00 | Interactive bash shell started | Audit Block 2 | — |
| 14:02:00 | `sudo bash` executed — root shell gained | Audit Block 3 | T1548.003 — Sudo and Sudo Caching |
| 14:03:00 | New user `sysadmin` created with bash shell | Audit Block 5, bash history | T1136.001 — Create Account: Local Account |
| 14:03:10 | `sysadmin` added to `sudo` group | Audit Block 6, bash history | T1098 — Account Manipulation |
| 14:04:00 | Backdoor SSH key added to `/root/.ssh/authorized_keys` | Audit Block 7, bash history | T1098.004 — SSH Authorized Keys |
| 14:05:00 | Cron job written: `/etc/cron.d/update-agent` → runs `/tmp/.x/agent` every minute as root | Audit Block 8, bash history | T1053.003 — Cron |
| 14:06:00 | `/tmp/.x/agent` downloaded from 185.234.219.47 via wget | Audit Block 9, bash history | T1105 — Ingress Tool Transfer |
| ~14:09 | `/tmp/.x/agent` starts listening on port 4444 (C2 listener/reverse shell server) | Network evidence, ss output | T1071 — Application Layer Protocol |
| 14:10+ | `.local` directory made world-writable (possible staging area) | File listing | — |

---

## Q4 — Persistence Analysis (3 points)

**Persistence mechanism 1: Backdoor User Account (`sysadmin`)**

* **What it is:** A new local user account `sysadmin` (uid=1002) with `/bin/bash` shell, added to the `sudo` group
* **How attacker uses it:** Even after Alice's password is reset, the `sysadmin` account with its own password remains. The attacker can SSH in as `sysadmin` and immediately `sudo` to root.
* **Detection:** Compare `/etc/passwd` to a known-good baseline. Look for users not in HR system/CMDB. `ausearch -k identity` in audit log.

**Persistence mechanism 2: Root SSH Authorized Key**

* **What it is:** An SSH public key added to `/root/.ssh/authorized_keys` for key `backdoor@attacker.com`
* **How attacker uses it:** The attacker can SSH directly as `root` from any machine where they have the corresponding private key — no password needed. This is completely invisible to normal authentication monitoring.
* **Detection:** `ausearch -k ssh_keys`, check `/root/.ssh/authorized_keys` content and modification time. Compare against known-good state.

**Persistence mechanism 3: Cron-Based C2 Agent (`/etc/cron.d/update-agent`)**

* **What it is:** A cron entry running `/tmp/.x/agent -d -q` every minute (`* * * * *`) as `root`
* **How attacker uses it:** Even if the agent process is killed (or the system reboots), cron will restart it within 60 seconds. The agent then calls back to the attacker's C2 or listens on port 4444.
* **Detection:** `ausearch -k cron`, check all files in `/etc/cron.d/` against baseline. `crontab -l` and `cat /etc/cron.d/*`.

**Note:** Three independent persistence mechanisms means removing one does not remove the threat.
All three must be addressed.

---

## Q5 — Attacker Capability Assessment (2 points)

**a) Agent on port 4444:**

The agent listening on `0.0.0.0:4444` with a name `.x/agent` (hidden directory, hidden name) running as root suggests:

* Full-featured C2 implant with reverse shell or interactive session capabilities
* The `-d` flag likely means "daemonize" (run in background)
* The `-q` flag likely means "quiet" (no console output)
* It's waiting for inbound connections on port 4444 OR preparing to make outbound connections to a C2 server

Combined with the cron job (which re-runs it every minute), this is a **persistent, root-privilege backdoor agent**.

**b) HIPAA/Healthcare compliance concern:**

This is an extreme compliance breach:

1. **PHI exposure:** A nurse's workstation may contain or have access to patient health records. A backdoor on this machine means an unauthorized party may have read/exfiltrated patient data — a HIPAA breach requiring mandatory notification.
1. **Hospital network pivot:** The workstation may be on the clinical network segment with access to medical devices, EHR servers, medication dispensing systems (e.g., Pyxis), and radiology/imaging systems.
1. **Healthcare infrastructure risk:** Medical devices on the same network segment could potentially be targeted (insulin pumps, patient monitors — though this is extreme, it is a real concern in healthcare security).
1. **Mandatory breach reporting:** HIPAA requires breach notification to HHS within 60 days and patient notification if PHI was accessed.

---

## Q6 — How Did the Attacker Get In? (3 points)

**a) How attacker obtained alice's SSH credentials:**

Several possibilities (and evidence suggests a combination):

1. **Social engineering/phishing:** Most likely for a nurse. A phishing email or fake IT portal could have harvested Alice's credentials. The attacker then used those same credentials to SSH in.

1. **Credential reuse:** Alice may have used the same password across multiple services, and a credential was obtained from a previous breach (credential stuffing).

1. **Shoulder surfing or observation:** Possible in a hospital environment where staff may use terminals in public areas.

1. **Insider threat:** Someone with access to `10.20.30.100` used Alice's credentials, possibly obtained by observation or from a shared password list.

**b) Why a nurse has SSH enabled with sudo:**

This is a configuration management failure:

* IT likely enabled SSH and sudo for troubleshooting or remote support purposes and never removed it after the need passed
* Or the workstation was provisioned from a "developer" or "IT admin" image that includes these configurations
* Nurses don't need SSH access or sudo rights; this is a violation of least privilege
* This suggests the organization lacks proper endpoint hardening standards for clinical workstations

**c) Attacker profile:**

The evidence slightly favors an **external attacker who obtained credentials**, but an insider threat cannot be ruled out:

**For external attacker:**

* The systematic post-exploitation (backdoor user, SSH key, C2 agent, cron job) is consistent with a scripted attack — this matches an organized external threat actor running a playbook
* The C2 infrastructure (`185.234.219.47`) appearing in other cases (seen in demos/drills) suggests a known threat actor or toolkit
* External attackers who obtain a password via phishing follow exactly this pattern

**For insider threat:**

* The attacker knew Alice's credentials and connected from an internal IP (`10.20.30.100`)
* 13:55 login followed by immediate root escalation and backdoor installation suggests someone comfortable with the system

**Investigation needed:** Identify what machine `10.20.30.100` is.
If it's Alice's personal device or another clinical workstation, the source could help identify whether this was targeted at Alice specifically or a random credential harvest.

---

## Q7 — Remediation and Hardening (4 points)

**Immediate Actions (Crisis Response):**

1. **Isolate NURSE-WS04** — disconnect from network immediately (but preserve evidence first: snapshot memory, collect audit logs, run `ss -tlnp`, `ps aux`)

1. **Kill `/tmp/.x/agent`** — but know it will restart via cron within 60 seconds

1. **Remove the cron job:** `rm /etc/cron.d/update-agent`

1. **Remove backdoor user:** `userdel -r sysadmin`

1. **Remove backdoor SSH key** from `/root/.ssh/authorized_keys`

1. **Reset Alice's password** (and audit for where credentials may have been compromised)

1. **Block 185.234.219.47** at the firewall

**Medium-term Remediation:**

1. **Reinstall the OS** — three persistence mechanisms plus an unknown C2 agent mean you cannot trust the system's integrity. A fresh deployment from a known-good image is the only trustworthy remediation.

1. **Audit all clinical workstations** for similar backdoors, unauthorized accounts, and unexpected cron jobs.

1. **Investigate PHI access** — review EHR access logs for any unusual queries or data exports during the compromise window (13:55–14:15 UTC on April 9). Determine if PHI was accessed and initiate HIPAA breach assessment.

**Hardening (Root Cause Fix):**

1. **Remove sudo from Alice's account** — nurses have no legitimate need for sudo access.

1. **Disable SSH on clinical workstations** or restrict to known IT admin jump hosts only:

    ```text
    # /etc/ssh/sshd_config
    AllowUsers alice@192.168.1.0/24  # Only IT subnet
    # Or disable entirely:
    systemctl disable --now sshd
```

1. **Implement a privileged access workstation (PAW)** model — administrative tasks are performed from dedicated IT admin machines, not from clinical workstations.

1. **Deploy auditd with immutable rules** (`-e 2`) across all clinical workstations so an attacker with root cannot disable logging.

1. **Endpoint monitoring** — deploy Wazuh or similar HIDS agent on clinical workstations with alerts for new cron jobs, user account creation, and SSH key modifications.

1. **Security awareness training** for clinical staff on phishing and credential security.

1. **HIPAA breach notification process** — if PHI exposure cannot be ruled out, notify the Privacy Officer immediately to start the breach assessment process.
