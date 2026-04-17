# Demo 03: Zero Trust Architecture — Identity-Aware Proxy and Micro-Segmentation

**Estimated time:** 30 minutes

---

## Overview

Simulate a Zero Trust network using Docker containers.
An identity-aware proxy (Python service) sits in front of application services and enforces authentication and device health checks before granting access.
You will observe how traditional implicit-trust access differs from Zero Trust, and experiment with micro-segmentation.

---

## Learning Objectives

* Understand the difference between implicit-trust (VPN model) and Zero Trust access
* Observe how an identity-aware proxy enforces per-request authentication
* Experiment with Docker network micro-segmentation to isolate services
* Understand the role of device posture in Zero Trust access decisions

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-03-zero-trust
docker compose up --build -d
docker compose ps
```

Services:
| Service | Description | Port |
|---------|-------------|------|
| `app-backend` | Protected application (isolated network) | internal only |
| `zt-proxy` | Zero Trust identity-aware proxy | 8080 |
| `attacker` | Simulated attacker with no credentials | — |
| `legit-user` | Simulated user with valid token | — |

---

## Step 1: Attempt Direct Access (Traditional Perimeter Assumption)

In a traditional network, being "inside" means you can reach any service.

```console
docker compose exec attacker curl http://app-backend:9000/secret-data
```

Expected: **Connection refused** — `app-backend` is on a separate Docker network (`internal-net`) that the `attacker` container cannot reach.
This is **micro-segmentation** in action — network isolation limits lateral movement.

---

## Step 2: Attempt Access Through the Proxy Without Credentials

```console
docker compose exec attacker curl http://zt-proxy:8080/api/secret-data
```

Expected response:

```json
{"error": "Authentication required", "code": 401}
```

The proxy enforces authentication on every request — even from containers on the same Docker network. **Network location provides no trust.**

---

## Step 3: Access with Valid Credentials

```console
docker compose exec legit-user curl \
  -H "Authorization: Bearer valid-user-token-abc123" \
  http://zt-proxy:8080/api/secret-data
```

Expected response:

```json
{
  "data": "Confidential: Q4 financial results",
  "accessed_by": "alice@company.com",
  "device_trust": "compliant",
  "access_time": "2026-01-15T10:30:00Z"
}
```

---

## Step 4: Observe the Device Posture Check

The proxy also validates a `X-Device-Health` header simulating an endpoint compliance agent.

```bash
# Compliant device — access granted
docker compose exec legit-user curl \
  -H "Authorization: Bearer valid-user-token-abc123" \
  -H "X-Device-Health: compliant" \
  http://zt-proxy:8080/api/admin

# Non-compliant device (outdated OS, no encryption) — access denied
docker compose exec legit-user curl \
  -H "Authorization: Bearer valid-user-token-abc123" \
  -H "X-Device-Health: non-compliant" \
  http://zt-proxy:8080/api/admin
```

A valid user on a non-compliant device is **denied access to sensitive endpoints**.
Identity alone is not sufficient — device health matters too.

---

## Step 5: Inspect the Access Audit Log

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
* Denial reason

This log feeds a SIEM for Zero Trust monitoring — providing full visibility into every access attempt, allowed or denied.

---

## Step 6: Map to NIST SP 800-207

This demo illustrates five of NIST's seven Zero Trust tenets:

1. **All resources are treated explicitly** — backend service is named and access-controlled
1. **All communication is secured** — proxy requires bearer token (simulates TLS + auth)
1. **Access is per-session** — each HTTP request is independently evaluated
1. **Dynamic policy** — device health influences the decision
1. **No implicit trust from network location** — being on the same Docker network is insufficient

---

## Discussion Points

1. **The "trusted network interior" no longer exists**: Zero Trust assumes any node inside the network may be compromised.

1. **Identity is verified on every request**: Unlike VPN (authenticate once, access everything), Zero Trust re-verifies on each resource access.

1. **Device health is a trust signal**: A compromised endpoint should lose access even if the user credentials are valid — EDR detection can trigger access revocation.

1. **Comprehensive logging is a feature**: In Zero Trust, every access decision is logged. This is essential for incident investigation and audit compliance.

---

## Clean Up

```console
docker compose down
```
