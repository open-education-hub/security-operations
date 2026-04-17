# Solution: Drill 02 (Advanced) — Post-Quantum Readiness Assessment

---

## Part 2: Quantum Vulnerability Analysis by System

| System | Vulnerable Algorithms | Quantum Threat | Harvest Risk | Migration Priority |
|--------|----------------------|----------------|-------------|-------------------|
| Corporate Email | RSA-2048 (cert), TLS | Shor's | HIGH — 10yr archive | P1 |
| VPN Gateway | ECDH P-256, RSA-4096 | Shor's | LOW — no retention | P2 |
| Code Signing | RSA-4096 | Shor's | CRITICAL — 15yr binaries | P1 |
| Database TDE | RSA-2048 (key wrap) | Shor's | CRITICAL — 25yr PII | P0 |
| SSH Infrastructure | ECDH Curve25519, Ed25519 | Shor's | LOW — no retention | P3 |
| PKI / CA | RSA-4096, RSA-2048 | Shor's | CRITICAL — trust anchor | P0 |
| Encrypted Backups | RSA-2048 (key transport) | Shor's | HIGH — 7yr retention | P1 |
| API Auth (JWTs) | ECDSA P-256 | Shor's | LOW — 1hr tokens | P3 |
| IoT Sensors | ECDH P-256, RSA-2048 | Shor's | MEDIUM — 5yr data | P2 |
| Document Archive | RSA-2048, SHA-1 (legacy) | Shor's | CRITICAL — 30yr docs | P0 |

---

## Part 3: Harvest Now, Decrypt Later Analysis

**Critical findings:**

1. **Document Archive (30-year retention):** Any adversary who captures encrypted archive traffic/data today can decrypt it in ~10 years when quantum computers emerge. 30 years of retention means documents encrypted today in 2024 are stored until 2054 — well into the quantum computing era.

1. **Database TDE (25-year retention):** Customer PII and financial records with 25-year retention are at extreme risk. If RSA-2048 key wrapping is compromised by a quantum computer, all encrypted data becomes accessible.

1. **Code Signing (15-year signatures):** Code signed with RSA-4096 today may need to be verified and trusted for 15 years. If RSA-4096 is broken, the trust chain for signed software collapses.

1. **Encrypted Backups (7-year retention):** 7 years is close to the quantum threat horizon. Backups from 2024 may be decryptable by 2031-2034.

**Not at immediate harvest risk:**

* VPN, SSH, JWT tokens — no persistent data retention; session keys discarded immediately
* Forward secrecy in VPN/SSH means even if ECDH is broken, individual sessions aren't retroactively exposed if ephemeral keys were deleted

---

## Part 5: IoT Special Challenge — Answers

### Q1: Why is IoT particularly problematic?

Multiple compounding factors:

* **No OTA update capability:** Cannot push software updates to install PQC-capable code
* **10-year device lifetime:** Devices purchased today will be operational well into the quantum computing era (2024 + 10 = 2034)
* **Resource constraints:** PQC algorithms (especially ML-KEM/ML-DSA) have larger key sizes and higher memory requirements
* **Legacy microcontrollers:** May not have sufficient RAM/flash for PQC implementations
* **Proprietary protocols:** DTLS 1.2 on embedded systems may not have PQC support

### Q2: Options for IoT without OTA updates

1. **Hardware replacement:** Replace all 2000 sensors at end-of-life (most secure, most expensive)
1. **PQC gateway/proxy:** Deploy a gateway that terminates IoT connections using classical crypto and re-establishes PQC connections to the backend. The gateway handles PQC complexity.
1. **Preshared keys (PSK):** For devices that cannot do PQC, use pre-provisioned symmetric AES-256 keys (quantum-resistant) instead of asymmetric key exchange. Requires secure key provisioning infrastructure.
1. **Network segmentation:** Isolate IoT network; minimize exposure window; accept residual risk for legacy devices with defined sunset date.
1. **Protocol gateway:** Deploy an edge device that speaks classical DTLS to the IoT sensors and PQC TLS to the backend, acting as a translation/termination layer.

### Q3: ML-KEM implications for constrained IoT

| Parameter | ECDH P-256 | ML-KEM-512 | Impact |
|-----------|-----------|------------|--------|
| Public key | 64 bytes | 800 bytes | 12.5× larger — network overhead |
| Ciphertext | 64 bytes | 768 bytes | 12× larger — MTU concerns |
| RAM needed | ~256 bytes | ~2-4 KB | May exceed constrained MCU RAM |
| Computation | ~5ms (Cortex-M4) | ~2ms (Cortex-M4) | Actually faster! |

**Key issue:** The larger message sizes may exceed Zigbee/Z-Wave MTUs, requiring fragmentation.
CoAP over DTLS has message size constraints.
Memory footprint is the primary concern for Class 0/1 IoT devices (< 10 KB RAM).

**Mitigation:** ML-KEM-512 is the smallest variant.
NIST Lightweight Cryptography (LWC) standardization process addresses constrained devices with ASCON for symmetric and work is ongoing for PQC KEM.

### Q4: PQC Gateway security trade-offs

**Advantages:**

* Allows legacy IoT devices to remain operational without modification
* Backend security is fully PQC
* Centralized management and monitoring

**Disadvantages:**

* **MITM by design:** The gateway decrypts and re-encrypts traffic — it has access to all IoT data in plaintext
* **Single point of failure:** Compromise of the gateway = compromise of all IoT traffic
* **Weakens end-to-end security:** Data is vulnerable at the gateway and in its memory
* **Trust boundary:** You're trusting the gateway's security posture to protect the data it's decrypting
* **Partial solution:** The classical-crypto IoT-to-gateway segment remains vulnerable to quantum harvest attacks (though this segment is local network, reducing exposure)

**Recommendation:** PQC gateway is acceptable for non-critical IoT (HVAC, lighting) but not for high-security applications (medical devices, critical infrastructure).
For critical IoT, device replacement is preferred.

---

## Part 6: Executive Briefing

### POST-QUANTUM CRYPTOGRAPHY RISK BRIEFING

**To:** CISO, Board Risk Committee

**From:** Security Engineering Team

**Date:** January 2024

**Classification:** CONFIDENTIAL

#### The Threat

In the coming 5-15 years, quantum computers are expected to become powerful enough to break the mathematical foundations of today's encryption.
Specifically, RSA and elliptic curve encryption — which protect virtually all of our secure communications — would be rendered ineffective.
This is not speculation: the US government (NIST) completed a 6-year effort in 2024 to standardize replacement algorithms, anticipating this threat.

#### Our Specific Risk

Of particular concern is the **"harvest now, decrypt later"** attack: foreign intelligence services (and sophisticated criminal groups) may be recording our encrypted network traffic TODAY, storing it, and planning to decrypt it in the future when quantum computers become available. **This means data we encrypted 3, 5, or 10 years ago — and data we encrypt today — may eventually be readable by adversaries.** Our document archive (30-year retention), customer database (25-year retention), and encrypted backups are all at risk under this threat model.

#### Recommended Action

We recommend a phased 4-year migration to "post-quantum cryptography" standards (NIST FIPS 203/204).
In the first year, we will deploy hybrid encryption (combining current and new algorithms) across our most sensitive systems — requiring no changes for end users.
Over years 2-4, we will systematically replace all quantum-vulnerable cryptography.
The most urgent priority is re-encrypting the long-term document archive and ensuring new data is protected with quantum-resistant algorithms.

**Estimated investment:** $800K–$2M over 4 years (infrastructure, tooling, staff training, IoT hardware replacement).
This is comparable to the cost of a single significant data breach.

#### If No Action Is Taken

Organizations that do not migrate to post-quantum cryptography face a scenario where adversaries retroactively decrypt years of accumulated sensitive data — contracts, customer information, strategic plans — with no warning and no ability to respond.
For an organization handling government contracts, this represents both a regulatory compliance risk and a national security concern.
NIST, NSA, and CISA have all issued guidance that organizations should begin migration immediately.

---

## Migration Priority Summary

| Priority | System | Timeline | Rationale |
|----------|--------|----------|-----------|
| P0 (Immediate) | Document Archive, Database TDE, PKI | 0-6 months | Highest sensitivity + longest retention |
| P1 | Email archive, Code signing, Backups | 6-18 months | Long retention + high sensitivity |
| P2 | VPN, IoT (gateway approach) | 12-24 months | Session security; no harvest risk today |
| P3 | SSH, JWT, API auth | 24-36 months | Low harvest risk; session-based |
