# Demo 02: Containment Strategies

## Overview

This demo demonstrates three containment strategies in a sandboxed environment:

1. Network-level isolation using iptables firewall rules
1. Account-level containment using Active Directory commands (simulated)
1. Endpoint isolation via a mock EDR API

Students see the command sequences, understand the tradeoffs, and observe how containment preserves volatile evidence.

## Learning Objectives

* Apply the three primary containment strategies
* Understand the tradeoffs between isolation speed and evidence preservation
* Practice the sequence: capture volatile evidence THEN contain
* Understand the blast radius consideration for each method

## Setup

```console
docker compose up -d
```

This starts a simulated environment with:

* A "compromised" Linux container running simulated malware traffic
* A firewall simulation container with iptables
* A mock AD PowerShell endpoint
* A mock EDR API

## Demo Walkthrough

### Phase 1: Volatile Evidence Before Containment (5 min)

Before any containment, run the evidence collection script:

```console
docker exec compromised-host /evidence/collect.sh
```

This captures: active network connections, running processes, listening ports.
Output is saved to `/evidence/EVID-001/`.

**Key teaching point:** This step MUST happen before isolation.
After network isolation, we lose the C2 connection record.

### Phase 2: Network-Level Containment (5 min)

```bash
# Access the firewall container
docker exec -it firewall bash

# View current connections
netstat -an | grep ESTABLISHED

# Block attacker C2 IP
iptables -A INPUT  -s 185.220.101.5 -j DROP
iptables -A OUTPUT -d 185.220.101.5 -j DROP

# Verify block
iptables -L -n
```

### Phase 3: Account Containment (5 min)

```console
# Mock PowerShell AD commands (shown as simulation)
docker exec mock-ad powershell.exe \
  -Command "Disable-ADAccount -Identity m.compromised"

docker exec mock-ad powershell.exe \
  -Command "Get-ADUser m.compromised -Properties Enabled,LastLogonDate"
```

### Phase 4: Endpoint Isolation via EDR API (5 min)

```console
# Simulate CrowdStrike-style API call
curl -X POST http://localhost:8080/api/devices/actions \
  -H "Content-Type: application/json" \
  -d '{"action": "contain", "device_id": "host-finance-ws-042"}'

# Verify isolation status
curl http://localhost:8080/api/devices/host-finance-ws-042
```

### Discussion

After the demo: Which containment method is most appropriate for a domain controller?
For a workstation?
For a shared database server?

## Teardown

```console
docker compose down -v
```
