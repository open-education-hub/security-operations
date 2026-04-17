# Guide 02 (Basic): Containment Procedures

## Objective

Apply containment procedures for a confirmed incident.
Practice network isolation, account containment, and evidence preservation in the correct order.

## Estimated Time: 30–40 minutes

## The Containment Sequence

Always follow this order:

```text
1. CAPTURE volatile evidence (before anything changes)

2. ASSESS containment options (network vs endpoint vs account)
3. EXECUTE containment (least disruptive that stops the threat)
4. VERIFY containment (confirm attacker is cut off)
5. DOCUMENT every action with timestamp
```

## Volatile Evidence — First Priority

Before any containment action:

### Windows Quick Collection

```powershell
# Create evidence directory with timestamp
$EVID = "C:\Evidence\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $EVID

# 1. Network connections
netstat -anob > "$EVID\network.txt"

# 2. Running processes
Get-Process | Select-Object Id,ProcessName,Path,StartTime | Export-Csv "$EVID\processes.csv"

# 3. Logged-in users
query user > "$EVID\users.txt"

# 4. Recent files accessed by suspect process
# (Check event viewer or Sysmon)

# 5. Hash everything collected
Get-ChildItem $EVID | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    "$hash  $($_.Name)" >> "$EVID\HASHES.sha256"
}
```

### Linux Quick Collection

```bash
EVID="/tmp/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVID"

# Network
ss -antp > "$EVID/network.txt"
ip route > "$EVID/routing.txt"
arp -n > "$EVID/arp.txt"

# Processes
ps auxf > "$EVID/processes.txt"
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' > "$EVID/proc_cmdlines.txt"

# Crontabs and startup
crontab -l > "$EVID/crontab.txt" 2>/dev/null
ls -la /etc/cron* >> "$EVID/crontab.txt"

# Hash all collected files
sha256sum "$EVID"/* > "$EVID/HASHES.sha256"
```

## Containment Options

### Option 1: Full Network Isolation

**When:** Ransomware spreading, active exfiltration, critical systems at risk

**How (via EDR):** Most EDR tools have a "Network Isolation" feature that isolates the host but keeps the EDR connection alive for remote investigation.

**How (via firewall):**

```console
# Block all traffic from/to host
# (Replace with actual host IP)
iptables -A INPUT  -s 192.168.10.42 -j DROP
iptables -A OUTPUT -d 192.168.10.42 -j DROP
```

**Tradeoff:** Attacker loses access but you also lose visibility (unless using EDR isolation that preserves agent connection).

### Option 2: Block Specific C2 Communication

**When:** APT investigation — you want to keep watching the attacker

**How:**

```console
# Block only the known C2 IP
iptables -A OUTPUT -d 185.220.101.5 -j DROP
```

**Tradeoff:** Less disruptive, but attacker may have multiple C2 channels.

### Option 3: Account Containment

**When:** Compromised credentials, insider threat

**How (Active Directory):**

```powershell
# Disable the account
Disable-ADAccount -Identity "t.compromised"

# Revoke all active Kerberos tickets
(The account is locked — no new tickets issued)

# For M365: revoke refresh tokens
# az ad user revoke-signin-sessions --id user@domain.com
```

**Tradeoff:** Attacker loses authenticated access but host may still have persistence.

## Guided Exercise

Scenario: Ransomware has been confirmed on `acct-ws-033` (IP: 192.168.10.55).
The EDR agent is still active on the host.
No other hosts are affected yet.
The host belongs to an accounts payable employee.

**Task 1:** What volatile evidence should you collect before containment?
List 4 items.

**Task 2:** Which containment method is most appropriate?
Justify.

**Task 3:** Write the sequence of actions you would take, with timestamps, as if you were updating the case notes.

**Sample case note:**

```text
[14:22 UTC] Volatile evidence collection initiated on acct-ws-033.
  - network connections captured to /evidence/EVID-001/network.txt
  - running processes captured
  - hashes: EVID-001/HASHES.sha256 — SHA256: 4abc...

[14:26 UTC] EDR network isolation applied to acct-ws-033 via CrowdStrike Falcon.
  - Isolation confirmed: status = "contained" in CrowdStrike console
  - Rationale: active ransomware, prevent lateral spread
  - Note: EDR connection preserved for remote forensics

[14:30 UTC] Verified no new encryption activity after isolation (no new .locked files)
```

## Key Takeaways

1. Volatile evidence capture before containment is non-negotiable
1. EDR isolation is usually preferable to firewall blocks (preserves investigation access)
1. Account containment alone is insufficient if malware has persistence
1. Every containment action must be timestamped and documented
