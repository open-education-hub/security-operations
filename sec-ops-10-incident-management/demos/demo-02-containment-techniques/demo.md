# Demo 02 — Containment Techniques: Network Isolation and Evidence Preservation

## Overview

This demo shows practical containment techniques using a mock EDR API and network simulation.
We practice isolating hosts, blocking IOCs, and preserving evidence without contaminating it.

**Duration:** 35 minutes

**Tools:** Docker, Python mock EDR, Wireshark concepts

**Scenario:** Ransomware precursor (cobalt strike) — containment decision walkthrough

---

## Setup

The existing demo has a Docker setup.
This demo.md provides guided instructor walkthrough.

```bash
# Start the mock EDR environment
docker compose up -d

# The mock EDR API runs on http://localhost:8080
# Endpoints:
#   POST /api/hosts/{hostname}/isolate
#   POST /api/hosts/{hostname}/unisolate
#   GET  /api/hosts/{hostname}/processes
#   GET  /api/hosts/{hostname}/network
#   POST /api/firewall/block
```

---

## Part 1: The Containment Decision Framework (10 minutes)

### The "STOP-ASSESS-ACT" Framework

Before taking any containment action, apply this framework:

**STOP**: Pause — don't react immediately unless lives or critical systems are at immediate risk.

**ASSESS**:

* What is the current attacker capability? (what can they do right now?)
* What is the current damage? (what has already happened?)
* Will containment tip off the attacker? (do they know we're watching?)
* What evidence will be lost if we act? (will isolation destroy evidence?)

**ACT**: Choose the least-invasive effective containment.

### Containment Decision Matrix

```python
# containment_decision.py

def recommend_containment(incident):
    """
    Input: incident dict with threat type, scope, data risk, attacker awareness
    Output: recommended containment action
    """
    threat_type = incident.get("threat_type")
    hosts_affected = incident.get("hosts_affected", 1)
    data_at_risk = incident.get("data_at_risk", False)
    ransomware_active = incident.get("ransomware_encrypting", False)
    attacker_aware = incident.get("attacker_aware", False)
    dwell_hours = incident.get("dwell_hours", 0)

    # Ransomware actively encrypting → immediate full isolation
    if ransomware_active:
        return {
            "action": "IMMEDIATE_FULL_NETWORK_ISOLATION",
            "reason": "Ransomware active — every minute costs more encrypted files",
            "urgency": "seconds"
        }

    # Large-scale attack
    if hosts_affected > 10:
        return {
            "action": "SEGMENT_AFFECTED_VLAN",
            "reason": "Too many hosts to isolate individually — VLAN quarantine",
            "urgency": "minutes"
        }

    # Attacker unaware, long dwell → controlled monitoring first
    if not attacker_aware and dwell_hours > 24 and not data_at_risk:
        return {
            "action": "CONTROLLED_MONITORING_BEFORE_ISOLATION",
            "reason": "Attacker unaware — monitor 30-60 min to understand full scope before containing",
            "urgency": "30-60 minutes"
        }

    # Standard: isolate soon
    return {
        "action": "EDR_ISOLATION_WITH_EVIDENCE_COLLECTION",
        "reason": "Standard containment — collect memory first if possible",
        "urgency": "15-30 minutes"
    }

# Test different scenarios
scenarios = [
    {"threat_type": "ransomware", "ransomware_encrypting": True, "hosts_affected": 3},
    {"threat_type": "cobalt_strike", "attacker_aware": False, "dwell_hours": 6, "hosts_affected": 1},
    {"threat_type": "data_exfil", "data_at_risk": True, "hosts_affected": 1, "dwell_hours": 0.5},
    {"threat_type": "c2_beacon", "attacker_aware": False, "dwell_hours": 72, "hosts_affected": 1}
]

for scenario in scenarios:
    result = recommend_containment(scenario)
    print(f"\nScenario: {scenario['threat_type']}")
    print(f"  Action: {result['action']}")
    print(f"  Reason: {result['reason']}")
    print(f"  Urgency: {result['urgency']}")
```

Run with: `python containment_decision.py`

---

## Part 2: EDR Isolation Demo (15 minutes)

### Using the mock EDR API

```console
# List hosts in environment
curl http://localhost:8080/api/hosts | python3 -m json.tool

# Get current network connections for a host
curl http://localhost:8080/api/hosts/WORKSTATION-FINANCE-03/network | python3 -m json.tool

# Get running processes
curl http://localhost:8080/api/hosts/WORKSTATION-FINANCE-03/processes | python3 -m json.tool
```

### Isolate the host

```console
curl -X POST http://localhost:8080/api/hosts/WORKSTATION-FINANCE-03/isolate \
  -H "Content-Type: application/json" \
  -d '{"reason": "Cobalt Strike beacon detected", "analyst": "ir.analyst@medsupply.de"}'
```

**Expected response:**

```json
{
  "hostname": "WORKSTATION-FINANCE-03",
  "status": "isolated",
  "isolation_time": "2025-04-10T14:55:00Z",
  "note": "All network connections severed except EDR communications"
}
```

### Verify isolation

```console
# Network connections should now only show EDR comms
curl http://localhost:8080/api/hosts/WORKSTATION-FINANCE-03/network
```

### Block the C2 at perimeter

```console
curl -X POST http://localhost:8080/api/firewall/block \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "185.220.101.73",
    "reason": "Cobalt Strike C2 — incident INC-2025-04712",
    "duration": "30d",
    "analyst": "ir.analyst@medsupply.de"
  }'
```

---

## Part 3: Evidence Preservation Concepts (10 minutes)

### What is destroyed when you isolate?

**Lost immediately:**

* Active network connections (active C2 session data)
* In-transit network packets

**Preserved by isolation:**

* Memory state (still running on isolated host)
* Disk contents
* Running processes (still visible via EDR)
* Registry state

### The Memory Collection Dilemma

```text
Timeline:
14:32 - Alert generated
14:37 - Analyst escalates (5 min triage)
14:42 - Tier 2 begins investigation
14:52 - Decision: isolate

Between 14:37 and 14:52, the attacker could:
- Dump LSASS (steal credentials)
- Execute additional payloads
- Delete log files
- Establish additional persistence

But during that same time:
- We can collect memory with Cobalt Strike implant loaded
- We can capture the full process tree
- We can see the C2 connection details in netstat
```

**The rule:** For EDR-detectable threats, collect evidence BEFORE isolating if the host is not actively causing wider damage.

### Forensic memory collection script

```bash
#!/bin/bash
# collect_evidence.sh — run BEFORE isolation if time permits

HOSTNAME=$1
CASE_ID=$2
EVIDENCE_DIR="/mnt/evidence/$CASE_ID"
mkdir -p $EVIDENCE_DIR

echo "Collecting evidence from $HOSTNAME..."
echo "Analyst: $USER" >> $EVIDENCE_DIR/collection_log.txt
echo "Time: $(date -u)" >> $EVIDENCE_DIR/collection_log.txt

# Process list with full command lines
echo "[+] Collecting process list..."
# In real IR: would query EDR API for process snapshot
echo "Process collection completed" >> $EVIDENCE_DIR/collection_log.txt

# Network connections
echo "[+] Collecting network state..."
# In real IR: would query EDR API for netstat snapshot

# System information
echo "[+] Recording system info..."
echo "Hostname: $HOSTNAME" >> $EVIDENCE_DIR/system_info.txt

echo "[+] Evidence collection complete for $HOSTNAME"
echo "Evidence location: $EVIDENCE_DIR"
```

---

## Discussion: What Could Go Wrong?

Walk through these containment mistakes with the class:

1. **Isolating without understanding scope** → Other hosts maintain C2 connection, attacker pivots
1. **Alerting the attacker** → They delete logs, drop ransomware early, cover tracks
1. **Isolating too late** → 6 hours of dwell time enables full credential harvest
1. **Not preserving memory** → No forensic evidence of how the attack happened
1. **Blocking too broadly** → Block a /16 instead of a /32, take down legitimate services

---

## Cleanup

```console
docker compose down -v
```
