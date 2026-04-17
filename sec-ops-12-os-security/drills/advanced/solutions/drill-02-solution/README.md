# Solution: Drill 02 (Advanced) — Incident Triage

## 30-Minute Triage Report

### Summary of Findings

1. Active outbound connection to 185.220.X.X:8443 from process `python3 /tmp/.x/agent.py` (PID 2847) — **attacker is still active**
1. Process binary is marked as deleted (`/proc/2847/exe -> /tmp/.x/agent.py (deleted)`) — anti-forensics technique
1. New account `sysmon` created at 09:19 UTC with sudo rights — backdoor account
1. SSH key added to `/root/.ssh/authorized_keys` at 09:21 UTC
1. Large read operation on `/var/lib/mysql/customers.ibd` at 09:23 UTC — potential data access

### Confirmation: Was compromise confirmed?

**YES — Confirmed**

Evidence:

* Active malicious process confirmed
* Backdoor account created
* Data access to customer database

### Scope Assessment

**LIKELY LIMITED TO THIS HOST but lateral movement possible**

Evidence of lateral movement attempts:

* SSH connection attempts from this machine to 10.0.1.55 and 10.0.1.60 at 09:25 UTC
* Both attempts failed (connection refused), but demonstrates attacker intent

Internal connections to investigate: 10.0.1.55, 10.0.1.60 — check their auth logs.

### Recommendation: **ISOLATE IMMEDIATELY**

Active attacker session means:

* Every minute of delay risks more data exfiltration
* Attacker is still trying lateral movement
* More persistence mechanisms may still be planted

**Isolation steps:**

```console
# Network isolation (block all non-SSH traffic for investigation)
# In production: coordinate with network team for VLAN quarantine
iptables -I OUTPUT -j DROP
iptables -I INPUT -j DROP
iptables -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT
```

**DO NOT kill the malicious process yet** — preserve memory evidence first:

```console
# Dump memory of malicious process
cat /proc/2847/mem > /tmp/evidence_2847_mem.bin 2>/dev/null
cp /proc/2847/exe /tmp/evidence_2847_binary
```

### Evidence Collected

```text
/tmp/triage_processes.txt        # Process snapshot
/tmp/triage_connections.txt      # Network connections
/tmp/triage_users.txt            # Logged-in users
/tmp/triage_logins.txt           # Login history
/tmp/triage_recent_files.txt     # Recently modified files
/tmp/evidence_2847_binary        # Malware binary copy
/tmp/triage_evidence_[ts].tar.gz # Complete evidence package

SHA256: a3b4c5d6e7f8... (evidence tarball)
```

### VERIS Preliminary Classification

```json
{
  "actor": {
    "external": {
      "variety": ["Unknown"],
      "motive": ["Unknown"],
      "country": ["Unknown"]
    }
  },
  "action": {
    "hacking": {
      "variety": ["Use of stolen creds"],
      "vector": ["Remote access (VPN or compromised credentials)"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "U - Desktop"},
      {"variety": "S - Database"}
    ]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Suspected",
      "data": [{"variety": "Personal", "amount": 0}]
    },
    "integrity": {
      "variety": ["Create account", "Install code"]
    }
  }
}
```

**Note:** This is a preliminary classification.
Full VERIS coding should be completed after the incident is fully investigated and contained.
