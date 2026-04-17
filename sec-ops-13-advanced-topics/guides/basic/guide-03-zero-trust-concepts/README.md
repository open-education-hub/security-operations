# Guide 03: Zero Trust Architecture — Concepts and SOC Implications

## Overview

This guide explains the Zero Trust security model, its core principles, and how it changes the role of the SOC.
You will learn why traditional perimeter-based security is insufficient, what Zero Trust components look like in practice, and how monitoring changes in a Zero Trust environment.

## Learning Objectives

After completing this guide you will be able to:

* Explain the core principles of Zero Trust Architecture (ZTA)
* Identify the key components of a Zero Trust implementation
* Describe how Zero Trust monitoring differs from traditional network monitoring
* Map Zero Trust to the NIST SP 800-207 framework

## Estimated Time

40 minutes

---

## 1. Why the Traditional Perimeter Failed

Traditional security assumed that:

* Everything inside the network is trusted
* Everything outside is untrusted
* A firewall separating inside from outside provides protection

This model has fundamental problems:

**Problem 1: The perimeter dissolved**

* Remote workers access from home networks and coffee shops
* SaaS applications run outside your network entirely
* Partners and contractors access your systems from their own environments

**Problem 2: Attackers get inside**

* Phishing compromises an endpoint inside the perimeter
* Once inside, attackers move laterally with little resistance
* The average dwell time before detection was 197 days (IBM Cost of a Data Breach 2023)

**Problem 3: Privileged insiders**

* A malicious or negligent insider already has trusted access
* Perimeter controls provide no protection against insider threats

---

## 2. Zero Trust Core Principles

NIST SP 800-207 defines Zero Trust around seven tenets:

### Tenet 1: All Data Sources and Services Are Resources

Every device, application, and data store is treated as a resource that must be explicitly accessed — not implicitly trusted because it is "on the network."

### Tenet 2: All Communication Is Secured Regardless of Location

Encrypt traffic between all components, even within what used to be the "trusted" internal network.
TLS everywhere.

### Tenet 3: Access Is Granted Per-Session

Access to a resource is granted for a specific session, based on the current context.
Yesterday's approval does not carry over.

### Tenet 4: Access Is Determined by Dynamic Policy

The decision to allow or deny access considers:

* **Identity**: Who is this? (verified with MFA)
* **Device health**: Is the device patched, encrypted, running EDR?
* **Context**: What time is it? Where are they located? Is this behaviour normal?
* **Resource sensitivity**: How sensitive is what they're accessing?

### Tenet 5: All Devices Are Monitored for Security Posture

No device is inherently trusted.
Every device is continuously assessed:

* Is the OS patched?
* Is disk encryption enabled?
* Is EDR running?
* Is the device registered?

### Tenet 6: Authentication and Authorisation Are Dynamic and Strictly Enforced

Continuous re-evaluation, not just at login:

* If user behaviour becomes anomalous mid-session, require step-up authentication
* If device becomes non-compliant mid-day, revoke access

### Tenet 7: Data About Asset Security Posture Is Collected

Log everything to improve the model:

* All access requests (allowed and denied)
* Device health reports
* Authentication events
* Network flows

---

## 3. Zero Trust Components

### 3.1 Identity Provider (IdP)

The foundation of Zero Trust is strong identity:

* **MFA** (Multi-Factor Authentication) for all accounts
* **Passwordless** authentication (FIDO2/WebAuthn) where possible
* **Conditional access policies** (deny login from unusual location without additional verification)
* Examples: Microsoft Entra ID (Azure AD), Okta, Google Workspace

### 3.2 Zero Trust Network Access (ZTNA)

Replaces VPN.
Instead of granting access to the entire network, ZTNA grants access to specific applications only:

* User authenticates to ZTNA controller
* Controller verifies identity, device health, and policy
* Controller creates an encrypted tunnel to the specific application
* User cannot reach any other application or resource

Products: Zscaler Private Access, Cloudflare Access, BeyondCorp (Google), Palo Alto Prisma Access.

### 3.3 Identity-Aware Proxy (IAP)

Sits in front of applications and enforces identity and policy checks on every request:

* **No network access is required** — the proxy handles the connection
* Verifies the JWT/token from the IdP on every HTTP request
* Checks device posture from the endpoint agent
* Logs every access attempt

Google's BeyondCorp was the first major IAP deployment.

### 3.4 Micro-Segmentation

Divides the network into small zones with explicit allow-rules between them:

* Service A cannot reach Service B unless there is an explicit rule
* If an attacker compromises Service A, they cannot move laterally
* Implementation: network policies in Kubernetes, NSX (VMware), or cloud security groups

### 3.5 Endpoint Detection and Response (EDR)

EDR provides continuous device health signals to the Zero Trust policy engine:

* Reports OS patch level, encryption status, agent running status
* Detects malware and behavioural anomalies
* Can trigger dynamic access revocation (if EDR detects compromise → revoke session)

---

## 4. Zero Trust vs. Traditional SOC Monitoring

### Traditional SOC

* Monitor **network perimeter** (firewall, IDS)
* Trust internal traffic by default
* Alert on inbound threats from internet
* Limited visibility into lateral movement

### Zero Trust SOC

| Area | What to Monitor |
|------|----------------|
| Identity plane | All authentication events (success/failure, location, time, MFA method) |
| Device health | Device compliance scores, policy violations |
| Application access | Per-session authorisation decisions (allow/deny + reason) |
| Network | All flows (no "trusted" internal traffic) |
| Data access | Who accessed what data, from where, with which device |

**New alert types in Zero Trust:**

* Access denied due to non-compliant device
* Unusual access pattern for user (UEBA)
* Policy violation: admin access from unregistered device
* Impossible travel: login from two countries within 1 hour

---

## 5. Zero Trust and GDPR/Privacy

Zero Trust's continuous logging creates tension with privacy law:

* Every access request is logged (user + resource + time + location + device)
* This data is personal data under GDPR
* **Requirements**: lawful basis for processing (typically legitimate interest for security), data minimisation (log what is needed for security, not more), retention limits

SOC analysts should work with the DPO (Data Protection Officer) to define:

* What access log data is retained and for how long
* Who can query the logs
* How access log data is protected from misuse

---

## 6. Zero Trust Maturity Model (CISA)

CISA (US Cybersecurity and Infrastructure Security Agency) defines five pillars and three maturity stages:

**Pillars**: Identity, Devices, Networks, Applications & Workloads, Data

**Stages**:

1. **Traditional**: Perimeter-based, implicit trust
1. **Advanced**: Some ZT controls (MFA, some segmentation)
1. **Optimal**: Full ZT across all pillars, automated enforcement

Most organisations are currently at stage 1.5–2.

---

## Summary

Zero Trust replaces implicit trust with continuous verification.
It is built on three ideas: never trust, always verify; assume breach; and use least-privilege access.
For SOC analysts, Zero Trust dramatically improves visibility (every access is logged) while requiring new monitoring strategies focused on identity events and policy decisions rather than network perimeter events.
