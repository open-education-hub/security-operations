# Solution: Drill 02 (Intermediate) — Zero Trust Architecture Design

## Task 1: Architecture Components

```text
COMPONENT: Identity Provider (IdP)
PURPOSE:   Centralise authentication, enforce MFA, conditional access
TECHNOLOGY: Microsoft Entra ID (Azure AD) — integrates with existing AD via AD Connect
CONNECTS TO: ZTNA controller, IAP, all applications
LOGS TO:   Azure Sentinel / SIEM (sign-in logs, risk events, MFA failures)

COMPONENT: Mobile Device Management (MDM)
PURPOSE:   Manage and attest device health for both corporate and BYOD
TECHNOLOGY: Microsoft Intune (integrates with Entra ID)
CONNECTS TO: IdP (device compliance signals), ZTNA policy engine
LOGS TO:   SIEM (compliance status changes, non-compliant device events)

COMPONENT: Zero Trust Network Access (ZTNA) Controller
PURPOSE:   Replace VPN; grant per-application access based on identity + device health
TECHNOLOGY: Entra Private Access (or Zscaler Private Access)
CONNECTS TO: IdP, MDM, on-premises applications
LOGS TO:   SIEM (access allowed/denied events per user per application)

COMPONENT: Identity-Aware Proxy (IAP)
PURPOSE:   Protect Azure PaaS applications with per-request auth enforcement
TECHNOLOGY: Azure App Proxy / Entra Application Proxy
CONNECTS TO: IdP, Azure PaaS apps
LOGS TO:   Azure Monitor / SIEM

COMPONENT: EDR (Endpoint Detection and Response)
PURPOSE:   Continuous device health monitoring; provides compliance signals
TECHNOLOGY: Microsoft Defender for Endpoint
CONNECTS TO: MDM (compliance reports), ZTNA (health attestation)
LOGS TO:   SIEM (alerts, device health changes)

COMPONENT: SIEM / SOC Monitoring
PURPOSE:   Aggregate all ZT access logs for threat detection and incident response
TECHNOLOGY: Microsoft Sentinel (natural fit with Entra / Defender ecosystem)
CONNECTS TO: All above components
LOGS TO:   Analyst dashboards, alerting rules
```

---

## Task 2: Access Policy Decisions

| Scenario | Decision | Reason |
|----------|----------|--------|
| Alice, company laptop, MFA passed, 10:00 CET | **Allow** | Normal working hours, managed device, valid MFA — all checks pass |
| Alice, personal phone, MFA passed, 10:00 CET | **Allow (read-only) / Deny full access** | BYOD device not enrolled in Intune → no device health attestation → limit to read-only or block. Policy choice. |
| Alice, company laptop, NO MFA, 10:00 CET | **Deny** | MFA is mandatory for all access. No exceptions for Finance ERP. Prompt to complete MFA. |
| Alice, company laptop, MFA passed, 02:00 CET | **Allow with step-up auth** | Off-hours access to Finance system is unusual. Require additional MFA prompt (step-up) and generate a SIEM alert for analyst review. |
| Bob (IT admin), company laptop, MFA passed, 10:00 CET | **Deny (Finance ERP)** | Bob is IT admin — he has no legitimate business reason to access Finance ERP. Least-privilege: IT admins access IT systems, not Finance systems. Requires business justification and just-in-time access grant. |
| Alice, company laptop flagged by EDR as compromised, MFA passed | **Deny** | Device posture check fails. Even with valid MFA, a compromised device cannot be trusted. Revoke session, isolate device, alert SOC. |
| Alice, login from Romania (unusual) + MFA passed, 10:00 CET | **Allow with step-up auth + SIEM alert** | Unusual location triggers Conditional Access risk score. Require additional verification (authenticator app push). Generate medium-severity SOC alert for investigation. |

---

## Task 3: SOC Monitoring Improvements

| Monitoring Capability | VPN Model | Zero Trust Model |
|----------------------|-----------|-----------------|
| Can you see who accessed which application? | No — only who is connected to VPN | Yes — every application access is logged with user, device, timestamp |
| Can you see failed access attempts? | Limited — only VPN auth failures | Yes — all failed access decisions logged with reason (bad MFA, non-compliant device, off-hours, etc.) |
| Can you detect access from a compromised device? | No — any VPN connection appears normal | Yes — EDR signals non-compliant/compromised device → automatic denial + SOC alert |
| Can you detect impossible travel? | Only at VPN login | Yes — Entra ID Conditional Access detects impossible travel continuously |
| Can you detect lateral movement to unauthorised system? | No — flat network means all internal movement is invisible | Yes — lateral movement requires new access requests, each evaluated by policy and logged |
| Can you detect off-hours access to sensitive data? | No — VPN connection is all-or-nothing | Yes — time-based access policy + step-up auth + SOC alert |

**Summary**: Zero Trust dramatically improves SOC visibility.
The current VPN model has almost no application-layer visibility.
Zero Trust logs every access decision.

---

## Task 4: GDPR Considerations

**1.
Is this personal data?**

Yes.
Access logs contain: user identity (name/email) linked to specific resource access, device ID, IP address (location), and timestamps.
All of these individually or combined constitute personal data under GDPR Article 4(1).

**2.
Lawful basis:**

`Legitimate Interests` (GDPR Article 6(1)(f)) — processing is necessary for the legitimate interest of security monitoring, intrusion detection, and compliance obligations.
This must be balanced against employees' privacy rights via a Legitimate Interests Assessment (LIA).
For financial institutions also subject to DORA, `Legal Obligation` (Article 6(1)(c)) applies for security logging.

**3.
Retention:**

* Security logs: 12 months active, 24 months cold storage — balancing investigation needs with data minimisation
* Consult with DPO; document the retention decision in the Record of Processing Activities (RoPA)

**4.
Who has access:**

* SOC analysts: read access (alert investigation only)
* SOC Lead / CISO: read + export for incidents
* HR / Legal: only via formal process for specific investigations
* IT administrators: no access to security logs (separation of duties)

**5.
Measures against insider abuse:**

* All access to log systems is itself logged (meta-logging)
* Privileged access workstations for log query tools
* Dual authorisation for export of personal data
* Regular access reviews for SOC log access
* Alerts on bulk export of user access data

---

## Task 5: Implementation Roadmap

**Phase 1 (Months 1–3): Identity Foundation (~€50,000)**

*Rationale*: The breach happened due to no MFA on VPN credentials.
Fix the root cause first.

* Deploy Microsoft Entra ID Connect (sync AD to cloud IdP): €5,000
* Enable MFA for all 500 users (Microsoft Authenticator): €10,000 licenses/year
* Create Conditional Access policies (block legacy auth, require MFA): included in Entra P1
* Deploy Microsoft Defender for Endpoint EDR on all corporate devices: €15,000/year
* Success metric: 100% of logins protected by MFA within 60 days

**Phase 2 (Months 4–6): Network Access Replacement (~€60,000)**

* Replace VPN with Entra Private Access (ZTNA): €20,000
* Define application access policies per application and user group
* Pilot with IT team (20 users) before full rollout
* Onboard all applications to ZTNA policy: €15,000 professional services
* Success metric: VPN decommissioned; 100% application access via ZTNA

**Phase 3 (Months 7–9): SOC Visibility (~€50,000)**

* Deploy Microsoft Sentinel as SIEM (if not already present): €20,000
* Create detection rules for ZT-specific alerts (impossible travel, non-compliant device, off-hours admin access)
* Connect all ZT logs to Sentinel
* Train SOC analysts on ZT alert types
* Success metric: 100% of ZT access events flowing to SIEM; 10 new detection rules active

**Phase 4 (Months 10–12): Optimisation (~€40,000)**

* Enrol BYOD devices in Intune (optional/recommended — not mandatory)
* Implement Just-In-Time (JIT) privileged access for admin accounts
* Purple team exercise to validate ZT detection coverage
* Success metric: No VPN credential attacks possible (VPN is gone); impossible travel detection operational
