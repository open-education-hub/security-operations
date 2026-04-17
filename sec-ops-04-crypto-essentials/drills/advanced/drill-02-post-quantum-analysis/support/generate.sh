#!/usr/bin/env bash
# generate.sh — Regenerate support files for drill-02-post-quantum-analysis
#
# Creates the asset inventory JSON, algorithm reference table, and a
# migration roadmap as standalone files for the PQC readiness assessment drill.
#
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating support files for drill-02-post-quantum-analysis ==="

# ── Cryptographic Asset Inventory ────────────────────────────────────────────
python3 - << 'PYEOF'
import json

assets = [
    {
        "id": 1,
        "system": "Corporate email (Exchange)",
        "protocols": ["TLS 1.2", "S/MIME"],
        "algorithms": ["RSA-2048 (cert)", "AES-256 (content)", "SHA-256"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 10,
        "notes": "Encrypted emails are archived for compliance"
    },
    {
        "id": 2,
        "system": "VPN Gateway",
        "protocols": ["IPSec IKEv2"],
        "algorithms": ["ECDH P-256 (key exchange)", "AES-256-GCM (data)", "RSA-4096 (cert)"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 0,
        "notes": "Real-time traffic; no persistent storage"
    },
    {
        "id": 3,
        "system": "Code Signing Infrastructure",
        "protocols": ["Authenticode"],
        "algorithms": ["RSA-4096 (signatures)", "SHA-256"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 15,
        "notes": "Signed binaries deployed to 50,000+ endpoints"
    },
    {
        "id": 4,
        "system": "Database Encryption (TDE)",
        "protocols": ["AES-256-CBC"],
        "algorithms": ["AES-256 (data)", "RSA-2048 (key wrapping)"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 25,
        "notes": "Customer PII and financial records; 25-year retention"
    },
    {
        "id": 5,
        "system": "SSH Infrastructure",
        "protocols": ["SSH-2"],
        "algorithms": ["ECDH Curve25519 (key exchange)", "Ed25519 (host keys)", "AES-256-GCM"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 0,
        "notes": "Admin access to all servers"
    },
    {
        "id": 6,
        "system": "PKI / Certificate Authority",
        "protocols": ["X.509 v3"],
        "algorithms": ["RSA-4096 (Root CA)", "RSA-2048 (Intermediate)", "SHA-256"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 20,
        "notes": "Issues all internal and customer-facing certificates"
    },
    {
        "id": 7,
        "system": "Encrypted Backups",
        "protocols": ["Custom"],
        "algorithms": ["AES-256-CBC (data)", "RSA-2048 (key transport)"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 7,
        "notes": "Daily encrypted backups stored offsite; 7-year retention"
    },
    {
        "id": 8,
        "system": "API Authentication (JWTs)",
        "protocols": ["REST/HTTP"],
        "algorithms": ["ECDSA P-256 (signatures)", "HS256 HMAC"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 1,
        "notes": "Tokens expire after 1 hour; logs retained 1 year"
    },
    {
        "id": 9,
        "system": "IoT Sensor Network",
        "protocols": ["DTLS 1.2", "CoAP"],
        "algorithms": ["ECDH P-256", "AES-128-GCM", "RSA-2048 (provisioning)"],
        "data_sensitivity": "MEDIUM",
        "data_retention_years": 5,
        "notes": "2000 sensors; 10-year device lifetime; no OTA update capability"
    },
    {
        "id": 10,
        "system": "Long-term Document Archive",
        "protocols": ["CMS/PKCS#7"],
        "algorithms": ["RSA-2048 (enveloping)", "AES-256 (content)", "SHA-1 (legacy docs pre-2017)"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 30,
        "notes": "Legal documents; 30-year retention required; cannot be re-encrypted easily"
    },
]

with open('asset_inventory.json', 'w') as f:
    json.dump(assets, f, indent=2)
print(f'[+] asset_inventory.json created ({len(assets)} systems)')
PYEOF

# ── Algorithm quantum-vulnerability reference ─────────────────────────────────
python3 - << 'PYEOF'
import json

algorithms = {
    "RSA-2048":        {"quantum_attack": "Shor's", "classical_bits": 112, "quantum_bits": 0,   "status": "VULNERABLE"},
    "RSA-4096":        {"quantum_attack": "Shor's", "classical_bits": 140, "quantum_bits": 0,   "status": "VULNERABLE"},
    "ECDH P-256":      {"quantum_attack": "Shor's", "classical_bits": 128, "quantum_bits": 0,   "status": "VULNERABLE"},
    "ECDSA P-256":     {"quantum_attack": "Shor's", "classical_bits": 128, "quantum_bits": 0,   "status": "VULNERABLE"},
    "Ed25519":         {"quantum_attack": "Shor's", "classical_bits": 128, "quantum_bits": 0,   "status": "VULNERABLE"},
    "ECDH Curve25519": {"quantum_attack": "Shor's", "classical_bits": 128, "quantum_bits": 0,   "status": "VULNERABLE"},
    "AES-128":         {"quantum_attack": "Grover's","classical_bits": 128, "quantum_bits": 64,  "status": "CAUTION"},
    "AES-256":         {"quantum_attack": "Grover's","classical_bits": 256, "quantum_bits": 128, "status": "SECURE"},
    "AES-256-GCM":     {"quantum_attack": "Grover's","classical_bits": 256, "quantum_bits": 128, "status": "SECURE"},
    "AES-256-CBC":     {"quantum_attack": "Grover's","classical_bits": 256, "quantum_bits": 128, "status": "SECURE"},
    "SHA-256":         {"quantum_attack": "Grover's","classical_bits": 256, "quantum_bits": 128, "status": "SECURE"},
    "SHA-1":           {"quantum_attack": "Grover's+","classical_bits": 80,"quantum_bits": 40,  "status": "BROKEN"},
    "HMAC-SHA256":     {"quantum_attack": "Grover's","classical_bits": 256, "quantum_bits": 128, "status": "SECURE"},
    "ML-KEM-768":      {"quantum_attack": "None known","classical_bits": 192,"quantum_bits": 192,"status": "PQC-SECURE"},
    "ML-KEM-1024":     {"quantum_attack": "None known","classical_bits": 256,"quantum_bits": 256,"status": "PQC-SECURE"},
    "ML-DSA-65":       {"quantum_attack": "None known","classical_bits": 192,"quantum_bits": 192,"status": "PQC-SECURE"},
    "SLH-DSA-128s":    {"quantum_attack": "None known","classical_bits": 128,"quantum_bits": 128,"status": "PQC-SECURE"},
}

with open('algorithm_reference.json', 'w') as f:
    json.dump(algorithms, f, indent=2)
print(f'[+] algorithm_reference.json created ({len(algorithms)} algorithms)')
PYEOF

# ── NIST PQC Standards Reference ─────────────────────────────────────────────
cat > nist_pqc_standards.txt << 'TXT'
# NIST Post-Quantum Cryptography Standards (as of 2024)
# =======================================================
# NIST finalised the first three PQC standards in August 2024.

== Key Encapsulation Mechanisms (KEM) — replaces RSA/ECDH for key exchange ==

ML-KEM (Module-Lattice-Based KEM)
  Standard: FIPS 203 (formerly CRYSTALS-Kyber)
  Variants: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5)
  Use case: TLS key exchange, VPN IKE, email encryption
  Public key size: ML-KEM-768 = 1184 bytes (vs ECDH P-256 = 64 bytes)
  Recommendation: ML-KEM-768 for most use cases (Level 3 = equivalent to AES-192)

== Digital Signatures — replaces RSA/ECDSA for signing ==

ML-DSA (Module-Lattice-Based DSA)
  Standard: FIPS 204 (formerly CRYSTALS-Dilithium)
  Variants: ML-DSA-44, ML-DSA-65, ML-DSA-87
  Use case: Code signing, TLS certificates, JWT signing
  Public key size: ML-DSA-65 = 1952 bytes (vs RSA-4096 = 512 bytes)

SLH-DSA (Stateless Hash-Based DSA)
  Standard: FIPS 205 (formerly SPHINCS+)
  Variants: SLH-DSA-128s/f, SLH-DSA-192s/f, SLH-DSA-256s/f
  Use case: Long-lived signatures (root CA, code signing, archival)
  Key generation: Slow (stateless — no state management needed)
  Advantage: Security based on hash functions only — extremely well-understood

== Migration Strategy ==

Hybrid approach (recommended during transition):
  - Run classical + PQC in parallel (X25519+ML-KEM-768 for TLS)
  - This protects against classical AND quantum attackers simultaneously
  - Standard: IETF draft-ietf-tls-hybrid-design

Timeline:
  2024: NIST standards published (FIPS 203/204/205)
  2025: Major TLS libraries add PQC support (OpenSSL 3.4+, BoringSSL)
  2026: Government systems required to begin PQC migration (CNSA 2.0)
  2030: Classical asymmetric crypto deprecated for sensitive government use
TXT
echo "[+] nist_pqc_standards.txt created"

# ── Instructor answer key ─────────────────────────────────────────────────────
cat > INSTRUCTOR_ANSWERS.txt << 'ANS'
# INSTRUCTOR ANSWERS — drill-02-post-quantum-analysis
# DO NOT distribute to students

== Part 1: Asset Inventory Analysis ==

System Classification:
  ID 1  Corporate email:     RSA-2048 VULNERABLE, AES-256 SECURE, SHA-256 SECURE
         Harvest risk: HIGH (10yr retention > ~10yr to quantum threat)
  ID 2  VPN Gateway:         ECDH P-256 VULNERABLE, AES-256-GCM SECURE
         Harvest risk: LOW (no persistent data; but upgrade key exchange!)
  ID 3  Code Signing:        RSA-4096 VULNERABLE (still breakable by Shor's)
         Harvest risk: CRITICAL (15yr signed binary trust; forge signatures in future)
  ID 4  Database TDE:        AES-256 SECURE, RSA-2048 key-wrap VULNERABLE
         Harvest risk: CRITICAL (25yr retention >> quantum timeline)
  ID 5  SSH:                 Curve25519 VULNERABLE (key exchange), Ed25519 VULNERABLE
         Harvest risk: LOW (no persistent sessions stored)
  ID 6  PKI / CA:            RSA-4096 VULNERABLE, SHA-256 SECURE
         Harvest risk: CRITICAL (CA compromise = all certs untrustworthy for 20yr)
  ID 7  Encrypted Backups:   AES-256 SECURE, RSA-2048 key-wrap VULNERABLE
         Harvest risk: CRITICAL (7yr retention; may still be active when QC arrives)
  ID 8  API JWTs:            ECDSA P-256 VULNERABLE, HMAC SECURE
         Harvest risk: LOW (1yr retention; tokens short-lived)
  ID 9  IoT Sensors:         ECDH P-256 VULNERABLE, AES-128 CAUTION
         Special problem: 10-year device lifetime, no OTA
  ID 10 Document Archive:    RSA-2048 VULNERABLE, SHA-1 BROKEN
         Harvest risk: CRITICAL (30yr retention — most at risk)

== Part 4: IoT Challenge ==
Q1: IoT problems — no OTA update, long device lifetime, constrained resources
Q2: Options: (a) PQC gateway terminating IoT TLS; (b) device replacement program;
    (c) isolate IoT network and accept residual risk for medium-sensitivity data
Q3: ML-KEM-768 pubkey = 1184 bytes vs P-256 = 64 bytes; constrained devices may
    lack memory/CPU for lattice operations; may require ML-KEM-512 or custom HW
Q4: PQC gateway trade-off: breaks end-to-end encryption for the IoT→gateway hop.
    Security relies on gateway integrity. Increases attack surface at gateway.
    Acceptable for LOW/MEDIUM sensitivity data; not for CRITICAL.

== Part 3: Harvest Now, Decrypt Later — Highest Risk Systems ==
Priority order (retention > estimated quantum timeline of 10 years):
  1. Long-term Document Archive (30yr) — CRITICAL PRIORITY
  2. Database TDE (25yr) — CRITICAL PRIORITY
  3. PKI / CA (20yr) — CRITICAL PRIORITY
  4. Code Signing (15yr) — HIGH PRIORITY
  5. Corporate Email (10yr) — HIGH PRIORITY (borderline)
  6. Encrypted Backups (7yr) — MEDIUM (may be safe but start migrating)

Low-risk (no persistent storage): VPN Gateway, SSH Infrastructure
ANS
echo "[+] INSTRUCTOR_ANSWERS.txt created"

echo ""
echo "=== Generation complete ==="
ls -lh "$SCRIPT_DIR"
