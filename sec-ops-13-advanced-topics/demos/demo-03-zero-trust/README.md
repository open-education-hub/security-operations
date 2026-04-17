# Demo 03: Zero Trust Architecture — Identity-Aware Proxy and Micro-Segmentation

## Overview

In this demo, we simulate a Zero Trust network using Docker containers.
An identity-aware proxy (simple Python service) sits in front of application services and enforces authentication and device health checks before granting access.
Students observe how traditional perimeter-based access differs from Zero Trust access, and experiment with micro-segmentation using Docker networks.

## Learning Objectives

* Understand the difference between implicit-trust (VPN) and Zero Trust access models
* Observe how an identity-aware proxy enforces per-request authentication
* Experiment with Docker network micro-segmentation to isolate services
* Understand the role of device posture in Zero Trust access decisions

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-03-zero-trust
docker compose up --build -d
```

Wait for services to start:

```console
docker compose ps
```

## Services

| Service | Description | Port |
|---------|-------------|------|
| `app-backend` | Protected application (isolated network) | internal only |
| `zt-proxy` | Zero Trust identity-aware proxy | 8080 |
| `attacker` | Simulated attacker container (no credentials) | — |
| `legit-user` | Simulated legitimate user with valid token | — |

## Walk-through

### Step 1: Attempt Direct Access (Traditional Perimeter Model)

In a traditional perimeter model, once inside the network you can reach any service.

```console
# Try to access the backend directly from the attacker container
docker compose exec attacker curl http://app-backend:9000/secret-data
```

Expected output: **Connection refused** — because `app-backend` is on a separate Docker network (`internal-net`) that `attacker` cannot reach.
This is micro-segmentation in action.

### Step 2: Attempt Access via Proxy Without Credentials

```console
docker compose exec attacker curl http://zt-proxy:8080/api/secret-data
```

Expected output:

```json
{"error": "Authentication required", "code": 401}
```

The proxy enforces authentication even for requests from within the same Docker network.

### Step 3: Access with Valid Credentials

```console
docker compose exec legit-user curl -H "Authorization: Bearer valid-user-token-abc123" \
  http://zt-proxy:8080/api/secret-data
```

Expected output:

```json
{
  "data": "Confidential: Q4 financial results",
  "accessed_by": "alice@company.com",
  "device_trust": "compliant",
  "access_time": "2024-01-15T10:30:00Z"
}
```

### Step 4: Observe Device Posture Check

The proxy also checks a `X-Device-Health` header (simulating an endpoint agent reporting device status).

```bash
# Compliant device
docker compose exec legit-user curl \
  -H "Authorization: Bearer valid-user-token-abc123" \
  -H "X-Device-Health: compliant" \
  http://zt-proxy:8080/api/admin

# Non-compliant device (e.g., outdated OS)
docker compose exec legit-user curl \
  -H "Authorization: Bearer valid-user-token-abc123" \
  -H "X-Device-Health: non-compliant" \
  http://zt-proxy:8080/api/admin
```

Non-compliant devices are denied access to sensitive endpoints even with valid credentials.

### Step 5: Inspect the Audit Log

```console
docker compose exec zt-proxy cat /var/log/zt-access.log
```

Every request is logged with:

* Timestamp
* Source IP
* User identity (from token)
* Requested resource
* Device health status
* Access decision (ALLOW/DENY)
* Reason for denial

This log is what feeds a SIEM for Zero Trust monitoring.

### Step 6: Map to NIST SP 800-207 Principles

The demo illustrates:

1. **All data sources and computing services are considered resources** — backend service is explicitly declared
1. **All communication is secured** — proxy requires bearer token
1. **Access to individual enterprise resources is granted on a per-session basis** — each request is independently evaluated
1. **Access to resources is determined by dynamic policy** — device health influences decision
1. **No implicit trust is granted based on network location** — being in the same Docker network is not enough

## Cleanup

```console
docker compose down
```

## Key Takeaways

* Zero Trust removes the concept of a "trusted network interior"
* Identity is verified on every request, not just at the VPN login
* Device health is part of the access decision — a compromised device loses access
* Every access decision is logged for audit purposes
* Micro-segmentation limits lateral movement even when an attacker is "inside"
