# Guide 03: Zero Trust Architecture — Concepts and SOC Implications

**Level:** Basic

**Estimated time:** 40 minutes

**Prerequisites:** Reading for Session 13

---

## Objective

By the end of this guide, you will be able to:

* Explain the core principles of Zero Trust Architecture (ZTA)
* Identify the key components of a Zero Trust implementation
* Describe how Zero Trust monitoring differs from traditional network monitoring
* Map Zero Trust to the NIST SP 800-207 framework

---

## 1. Why the Traditional Perimeter Failed

Traditional security assumed:

* Everything inside the network is trusted
* Everything outside is untrusted
* A firewall separating inside from outside provides protection

**The model has fundamental problems:**

**Problem 1: The perimeter dissolved**

* Remote workers access from home and coffee shops
* SaaS applications run outside your network entirely
* Partners access your systems from their environments

**Problem 2: Attackers get inside**

* Phishing compromises an endpoint inside the perimeter
* Once inside, attackers move laterally with little resistance
* Average dwell time before detection was 197 days (IBM 2023)

**Problem 3: Privileged insiders**

* A malicious or negligent insider already has trusted access
* Perimeter controls provide no protection against insider threats

---

## 2. Zero Trust Core Principles (NIST SP 800-207)

NIST defines Zero Trust around seven tenets:

### Tenet 1: All Resources Are Explicitly Identified
Every device, application, and data store is treated as a resource that must be explicitly accessed — not implicitly trusted because it is "on the network."

### Tenet 2: All Communication Is Secured Regardless of Location
Encrypt traffic between all components, even within the "trusted" internal network. **TLS everywhere.**

### Tenet 3: Access Is Granted Per-Session
Access is granted for a specific session, based on the current context.
Yesterday's approval does not carry over.

### Tenet 4: Access Is Determined by Dynamic Policy
The access decision considers:

* **Identity**: Who is this? (verified with MFA)
* **Device health**: Is the device patched, encrypted, running EDR?
* **Context**: Time, location, behaviour normality
* **Resource sensitivity**: How sensitive is the resource?

### Tenet 5: All Devices Are Continuously Monitored
Every device is assessed for: OS patch level, disk encryption, EDR running, registration status.

### Tenet 6: Authentication and Authorisation Are Dynamic
Continuous re-evaluation — not just at login.
If device becomes non-compliant, revoke access mid-session.

### Tenet 7: All Access Data Is Collected
Log every access attempt (allowed and denied) to continuously improve the model.

---

## 3. Zero Trust Components

### Identity Provider (IdP)
Foundation of Zero Trust.
Requires:

* **MFA** for all accounts
* **Conditional access policies** (deny login from unusual location without extra verification)
* Examples: Microsoft Entra ID, Okta, Google Workspace

### Zero Trust Network Access (ZTNA)
Replaces VPN.
Instead of network access, grants access to specific applications only:

* User authenticates to ZTNA controller
* Controller verifies identity, device health, and policy
* Encrypted tunnel created to the specific application only
* User cannot reach any other application

Products: Zscaler Private Access, Cloudflare Access, Google BeyondCorp

### Identity-Aware Proxy (IAP)
Sits in front of applications and enforces identity/policy checks on every request:

* Verifies JWT/token on every HTTP request
* Checks device posture from endpoint agent
* Logs every access attempt

### Micro-Segmentation
Divides the network into small zones with explicit allow-rules:

* Service A cannot reach Service B without an explicit rule
* If an attacker compromises Service A, lateral movement is blocked

### EDR Integration
EDR provides continuous device health signals:

* Reports patch level, encryption status, agent status
* Can trigger dynamic access revocation (EDR detects malware → session revoked)

---

## 4. Zero Trust SOC Monitoring

### Traditional SOC

* Monitor **network perimeter** (firewall, IDS)
* Trust internal traffic by default
* Limited visibility into lateral movement

### Zero Trust SOC

| Area | What to Monitor |
|------|----------------|
| Identity | All auth events (success/failure, location, MFA method) |
| Device health | Compliance scores, policy violations |
| Application | Per-session authorisation decisions (ALLOW/DENY + reason) |
| Network | All flows (no "trusted" internal traffic) |
| Data | Who accessed what data, from where, with which device |

**New alert types in Zero Trust:**

* Access denied due to non-compliant device
* Unusual access pattern for user (UEBA)
* Admin access from unregistered device
* Impossible travel: login from two countries within 1 hour

---

## 5. Zero Trust Maturity Model (CISA)

CISA defines three maturity stages across five pillars:

| Stage | Description |
|-------|-------------|
| 1: Traditional | Perimeter-based, implicit trust |
| 2: Advanced | Some ZT controls (MFA, some segmentation) |
| 3: Optimal | Full ZT across all pillars, automated enforcement |

**Pillars:** Identity, Devices, Networks, Applications & Workloads, Data

Most organisations are currently at stage 1.5–2.

---

## Summary

Zero Trust replaces implicit trust with continuous verification.
Built on three ideas: **never trust, always verify; assume breach; use least-privilege access.** For SOC analysts, Zero Trust improves visibility dramatically — every access is logged — while requiring new monitoring strategies focused on identity events and policy decisions rather than network perimeter traffic.
