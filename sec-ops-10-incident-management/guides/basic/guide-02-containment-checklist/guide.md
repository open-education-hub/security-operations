# Guide 02 — Containment Checklist

## Objective

By the end of this guide you will be able to:

* Apply a structured containment decision process
* Choose appropriate containment actions for different incident types
* Execute containment steps in the correct order
* Document containment actions with complete audit trail

**Estimated time:** 30 minutes

**Level:** Basic

---

## Pre-Containment Decision Checklist

Before containing, answer these questions:

```text
□ Has the scope been reasonably assessed? (What is affected?)
□ Will containment tip off the attacker (and cause escalation)?
□ Does containment risk destroying critical evidence?
□ Can the business tolerate the containment action (e.g., taking a production server offline)?
□ Is authorization obtained? (Tier 2 or IR Manager sign-off for high-impact actions)
□ Has legal been notified? (For incidents with regulatory implications)
```

---

## Containment Checklist by Incident Type

### Ransomware Containment

```text
IMMEDIATE (within 5 minutes):
□ Identify patient zero (first encrypted host)
□ Identify all currently infected hosts
□ Isolate ALL infected hosts from the network simultaneously
  - Using EDR: isolate each host
  - Using network: move to quarantine VLAN or pull cable
□ Disable file shares on unaffected servers (attacker may not have reached them yet)
□ Alert IT storage team to protect backups

WITHIN 30 MINUTES:
□ Verify backup systems are not encrypted
□ Identify encryption scope (how many files, which directories)
□ Check for data exfiltration (double-extortion check):
  - DLP alerts for large outbound transfers in last 72 hours
  - Cloud storage uploads
□ Notify management (P1 requires immediate management briefing)
□ Check nomoreransom.org for available free decryptors

WITHIN 1 HOUR:
□ Preserve memory on at least one infected host (decryptor keys may be in RAM)
□ Identify ransomware family (check ransom note, file extension, encryption style)
□ Assess whether domain credentials may have been compromised
□ Consider emergency AD password reset for all privileged accounts
```

### Account Compromise Containment

```text
IMMEDIATE:
□ Revoke all active sessions for the compromised account
□ Reset the account password
□ Disable MFA recovery options (attacker may have registered backup phone/email)

WITHIN 15 MINUTES:
□ Check all emails sent from compromised account in last 24h
□ Check for inbox rules (forwarding, deletion, marking as read)
□ Check for external collaborator additions or permission changes
□ Check cloud storage shares created from compromised account
□ Identify source of compromise (phishing, credential spray, insider)

WITHIN 1 HOUR:
□ Search for other accounts with same password (if breach was from credential stuffing)
□ Check if account was used to access other systems
□ Review all actions taken by the account since compromise
□ Consider notifying affected parties (if emails were read that contain sensitive info)
```

### C2 Beacon Containment

```text
IMMEDIATE:
□ Block C2 IP and domain at perimeter firewall AND web proxy
□ Verify block is confirmed by network team

WITHIN 15 MINUTES:
□ Identify all hosts communicating with C2 (SIEM query)
□ For EACH identified host:
  - Review process tree for beacon parent process
  - Check for additional lateral movement indicators

WITHIN 30 MINUTES:
□ Isolate confirmed infected hosts (coordinate with business owners if production)
□ Reset credentials for any accounts accessed from infected hosts
□ Check for lateral movement: which other systems did the infected host reach?
□ Check for persistence mechanisms on each isolated host

DOCUMENTED:
□ C2 IP/domain added to MISP as IOC
□ Containment actions logged in ticket with timestamps
□ Management notified of scope
```

---

## Worked Containment Example

**Scenario:** Tier 2 is responding to a Cobalt Strike beacon on FINANCE-WORKSTATION-07.

**Step 1: Pre-containment assessment**

```text
Questions:

1. How long has this been active? SIEM: first contact 14:30 UTC (18 minutes ago) ✓

2. Lateral movement? SIEM query for other hosts → 185.220.101.73: NONE ✓
3. Attacker aware? Unknown — assume not
4. Evidence risk? Memory capture not yet done — collect before isolating
5. Business impact? Finance workstation — user can work on another machine ✓
6. Authorization? IR Manager approval obtained at 14:49 ✓

Decision: Collect memory → Isolate → Block C2
```

**Step 2: Evidence preservation first**

```text
14:49 UTC — Memory capture initiated via EDR
14:52 UTC — Memory capture complete (4.2GB, SHA256 hash recorded)
           Hash: a665a45920422f9d417e4867efdc4fb8...
```

**Step 3: Isolation**

```text
14:52 UTC — EDR isolation command submitted
            crowdstrike-isolate --host FINANCE-WORKSTATION-07
14:53 UTC — Isolation confirmed by EDR console
```

**Step 4: Perimeter block**

```text
14:53 UTC — Firewall block request submitted:
            Block 185.220.101.73/32 all ports all directions
            Rule ID: FW-BLOCK-2025-1047
14:56 UTC — Confirmed blocked by network team
```

**Step 5: Documentation in ticket**

```text
[14:49] Memory capture initiated (4.2GB)
[14:52] Memory capture complete — hash recorded
[14:52] EDR isolation submitted
[14:53] EDR isolation confirmed
[14:53] Firewall block request submitted to network team
[14:56] Firewall block confirmed — Rule FW-BLOCK-2025-1047
[14:58] anna.schmidt notified: workstation unavailable for security investigation
[15:05] IT notified: provide anna.schmidt with temporary loaner workstation
```

---

## Common Containment Mistakes

| Mistake | Consequence | Prevention |
|---------|-------------|------------|
| Isolating before scope assessment | Other infected hosts continue C2 comms | Always check for lateral movement first |
| Alerting attacker via hasty action | Attacker escalates to ransomware | Controlled, coordinated containment |
| No evidence preservation | Cannot determine root cause | Always collect memory first if time allows |
| Not blocking C2 at perimeter | Attacker can move to another host | Block C2 simultaneously with host isolation |
| Taking down production without authorization | Business disruption | Get IR Manager approval for high-impact actions |

---

## Knowledge Check

1. You detect ransomware encrypting files on a file server. Should you isolate immediately or collect evidence first?
1. A compromised account belongs to the CEO. What additional containment steps are required compared to a standard user account?
1. After isolating a host, you realize there are 5 more hosts communicating with the same C2. What should you have done differently?
1. Why should you block C2 at the perimeter firewall even after isolating all infected hosts?
