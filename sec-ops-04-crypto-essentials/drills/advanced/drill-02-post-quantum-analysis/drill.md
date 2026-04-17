# Drill 02 (Advanced): Post-Quantum Readiness Assessment

> **Level:** Advanced
> **Time:** 90 minutes
> **Tools:** Docker, Python, OpenSSL
> **Prerequisites:** Reading section 11 (Post-Quantum Cryptography)

---

## Scenario

Your organization's CISO has tasked you with leading the Post-Quantum Cryptography (PQC) readiness assessment.
A national intelligence assessment suggests that cryptographically relevant quantum computers may be available to nation-state adversaries within 5 years.
Your organization handles classified government contracts.

You must:

1. Inventory all cryptographic assets in the provided system descriptions
1. Classify each by quantum vulnerability
1. Model the "harvest now, decrypt later" threat
1. Develop a migration roadmap
1. Present findings in an executive briefing format

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y python3 openssl 2>/dev/null | tail -3
mkdir -p /pq-assessment && cd /pq-assessment
```

---

## Part 1: Cryptographic Asset Inventory

The following systems have been identified during your assessment.
For each, determine the quantum vulnerability and migration priority.

```python
# run this to see the asset list
python3 << 'EOF'
assets = [
    {
        "system": "Corporate email (Exchange)",
        "protocols": ["TLS 1.2", "S/MIME"],
        "algorithms": ["RSA-2048 (cert)", "AES-256 (content)", "SHA-256"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 10,
        "notes": "Encrypted emails are archived for compliance"
    },
    {
        "system": "VPN Gateway",
        "protocols": ["IPSec IKEv2"],
        "algorithms": ["ECDH P-256 (key exchange)", "AES-256-GCM (data)", "RSA-4096 (cert)"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 0,
        "notes": "Real-time traffic; no persistent storage"
    },
    {
        "system": "Code Signing Infrastructure",
        "protocols": ["Authenticode"],
        "algorithms": ["RSA-4096 (signatures)", "SHA-256"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 15,
        "notes": "Signed binaries deployed to 50,000+ endpoints"
    },
    {
        "system": "Database Encryption (TDE)",
        "protocols": ["AES-256-CBC"],
        "algorithms": ["AES-256 (data)", "RSA-2048 (key wrapping)"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 25,
        "notes": "Customer PII and financial records; 25-year retention"
    },
    {
        "system": "SSH Infrastructure",
        "protocols": ["SSH-2"],
        "algorithms": ["ECDH Curve25519 (key exchange)", "Ed25519 (host keys)", "AES-256-GCM"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 0,
        "notes": "Admin access to all servers"
    },
    {
        "system": "PKI / Certificate Authority",
        "protocols": ["X.509 v3"],
        "algorithms": ["RSA-4096 (Root CA)", "RSA-2048 (Intermediate)", "SHA-256"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 20,
        "notes": "Issues all internal and customer-facing certificates"
    },
    {
        "system": "Encrypted Backups",
        "protocols": ["Custom"],
        "algorithms": ["AES-256-CBC (data)", "RSA-2048 (key transport)"],
        "data_sensitivity": "CRITICAL",
        "data_retention_years": 7,
        "notes": "Daily encrypted backups stored offsite; 7-year retention"
    },
    {
        "system": "API Authentication (JWTs)",
        "protocols": ["REST/HTTP"],
        "algorithms": ["ECDSA P-256 (signatures)", "HS256 HMAC"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 1,
        "notes": "Tokens expire after 1 hour; logs retained 1 year"
    },
    {
        "system": "IoT Sensor Network",
        "protocols": ["DTLS 1.2", "CoAP"],
        "algorithms": ["ECDH P-256", "AES-128-GCM", "RSA-2048 (provisioning)"],
        "data_sensitivity": "MEDIUM",
        "data_retention_years": 5,
        "notes": "2000 sensors; 10-year device lifetime; no OTA update capability"
    },
    {
        "system": "Long-term Document Archive",
        "protocols": ["CMS/PKCS#7"],
        "algorithms": ["RSA-2048 (enveloping)", "AES-256 (content)", "SHA-1 (legacy documents pre-2017)"],
        "data_sensitivity": "HIGH",
        "data_retention_years": 30,
        "notes": "Legal documents; 30-year retention required; cannot be re-encrypted easily"
    },
]

for a in assets:
    print(f"\n{'='*60}")
    print(f"System: {a['system']}")
    print(f"  Protocols:   {', '.join(a['protocols'])}")
    print(f"  Algorithms:  {', '.join(a['algorithms'])}")
    print(f"  Sensitivity: {a['data_sensitivity']}")
    print(f"  Retention:   {a['data_retention_years']} years")
    print(f"  Notes:       {a['notes']}")
EOF
```

---

## Part 2: Quantum Vulnerability Analysis

For each algorithm, determine:

```python
python3 << 'EOF'
algorithms = {
    "RSA-2048":        {"quantum_attack": "Shor's", "classical_security": 112, "quantum_security": 0, "status": "VULNERABLE"},
    "RSA-4096":        {"quantum_attack": "Shor's", "classical_security": 140, "quantum_security": 0, "status": "VULNERABLE"},
    "ECDH P-256":      {"quantum_attack": "Shor's", "classical_security": 128, "quantum_security": 0, "status": "VULNERABLE"},
    "ECDSA P-256":     {"quantum_attack": "Shor's", "classical_security": 128, "quantum_security": 0, "status": "VULNERABLE"},
    "Ed25519":         {"quantum_attack": "Shor's", "classical_security": 128, "quantum_security": 0, "status": "VULNERABLE"},
    "Curve25519 ECDH": {"quantum_attack": "Shor's", "classical_security": 128, "quantum_security": 0, "status": "VULNERABLE"},
    "AES-128":         {"quantum_attack": "Grover's", "classical_security": 128, "quantum_security": 64, "status": "CAUTION"},
    "AES-256":         {"quantum_attack": "Grover's", "classical_security": 256, "quantum_security": 128, "status": "SECURE"},
    "AES-256-GCM":     {"quantum_attack": "Grover's", "classical_security": 256, "quantum_security": 128, "status": "SECURE"},
    "AES-256-CBC":     {"quantum_attack": "Grover's", "classical_security": 256, "quantum_security": 128, "status": "SECURE"},
    "SHA-256":         {"quantum_attack": "Grover's", "classical_security": 256, "quantum_security": 128, "status": "SECURE"},
    "SHA-1":           {"quantum_attack": "Grover's+", "classical_security": 80, "quantum_security": 40, "status": "BROKEN"},
    "HMAC-SHA256":     {"quantum_attack": "Grover's", "classical_security": 256, "quantum_security": 128, "status": "SECURE"},
    "HS256 HMAC":      {"quantum_attack": "Grover's", "classical_security": 256, "quantum_security": 128, "status": "SECURE"},
}

print(f"{'Algorithm':<20} {'Classical':>12} {'Quantum':>10} {'Status'}")
print("-" * 60)
for alg, info in algorithms.items():
    status_sym = {"VULNERABLE": "⚠ MIGRATE", "SECURE": "✓ OK", "CAUTION": "~ CAUTION", "BROKEN": "✗ BROKEN"}.get(info['status'], info['status'])
    print(f"{alg:<20} {info['classical_security']:>10}-bit {info['quantum_security']:>8}-bit  {status_sym}")
EOF
```

---

## Part 3: Harvest Now, Decrypt Later Analysis

Some data collected TODAY will still be sensitive in 5-15 years when quantum computers may exist.

```python
python3 << 'EOF'
from datetime import datetime, timedelta

CURRENT_YEAR = 2024
QUANTUM_YEAR_ESTIMATE = 2034  # Conservative estimate for CRQC

print("HARVEST NOW, DECRYPT LATER RISK MODEL")
print("=" * 60)
print(f"Assessment year:           {CURRENT_YEAR}")
print(f"Estimated CRQC year:       {QUANTUM_YEAR_ESTIMATE}")
print(f"Years until quantum threat: {QUANTUM_YEAR_ESTIMATE - CURRENT_YEAR}")
print()

systems_at_risk = [
    ("Corporate email archive",     "RSA-2048/TLS",  10, "HIGH"),
    ("Database TDE",                "RSA-2048",      25, "CRITICAL"),
    ("Long-term document archive",  "RSA-2048",      30, "CRITICAL"),
    ("Encrypted backups",           "RSA-2048",       7, "CRITICAL"),
    ("VPN traffic (today)",         "ECDH P-256",     0, "LOW"),  # no retention
    ("Code signatures",             "RSA-4096",      15, "CRITICAL"),
]

print(f"{'System':<35} {'Algorithm':<20} {'Retention':>10} {'Risk':<12} {'Vulnerable?'}")
print("-" * 90)

for system, alg, retention, sensitivity in systems_at_risk:
    data_expires = CURRENT_YEAR + retention
    vulnerable = "YES - PRIORITY" if retention > (QUANTUM_YEAR_ESTIMATE - CURRENT_YEAR) else "Low (expires before Q)"
    if retention == 0:
        vulnerable = "No (no retention)"
    print(f"{system:<35} {alg:<20} {retention:>9}yr {sensitivity:<12} {vulnerable}")

print()
print("KEY INSIGHT: Any data retained beyond 2034 AND protected with RSA/ECC")
print("is vulnerable to 'harvest now, decrypt later' attacks.")
print("Adversaries may ALREADY be recording your encrypted traffic for future decryption.")
EOF
```

---

## Part 4: Migration Roadmap

```python
python3 << 'EOF'
print("POST-QUANTUM MIGRATION ROADMAP")
print("=" * 60)
print()

phases = [
    {
        "phase": "Phase 0: Inventory & Crypto Agility (Now)",
        "duration": "3-6 months",
        "actions": [
            "Complete cryptographic asset inventory (this assessment)",
            "Add crypto agility to all systems (algorithm negotiation capability)",
            "Identify systems that CANNOT be easily updated (IoT!)",
            "Establish PQC governance: assign owners, budget, timeline",
            "Monitor NIST FIPS 203/204/205 for finalized standards",
        ]
    },
    {
        "phase": "Phase 1: Hybrid Deployment (Year 1-2)",
        "duration": "12-18 months",
        "actions": [
            "Deploy X25519+ML-KEM-768 hybrid key exchange in TLS for new connections",
            "Update PKI: add ML-DSA signatures to new certificates (dual-sign with RSA)",
            "Update VPN: enable hybrid ECDH+ML-KEM for IKEv2",
            "Begin re-encrypting highest-sensitivity data with AES-256 (post-quantum safe)",
            "SSH: upgrade to PQC-capable version (OpenSSH 9.0+ supports CRYSTALS-Kyber)",
        ]
    },
    {
        "phase": "Phase 2: Full PQC Transition (Year 2-4)",
        "duration": "24 months",
        "actions": [
            "Migrate all TLS connections to ML-KEM key exchange",
            "Replace RSA certificates with ML-DSA or SLH-DSA signed certificates",
            "Re-encrypt encrypted backups and long-term archives",
            "Replace IoT devices that cannot be updated (or add PQC gateways)",
            "Retire RSA/ECC for all new use cases",
        ]
    },
    {
        "phase": "Phase 3: Legacy Decommission (Year 4-5)",
        "duration": "12 months",
        "actions": [
            "Disable RSA/ECC key exchange in all protocols (TLS, SSH, VPN)",
            "Archive RSA keys for verification of old signatures only",
            "Full PQC audit and certification",
            "Update incident response procedures for PQC era",
        ]
    },
]

for p in phases:
    print(f"{'─'*60}")
    print(f"  {p['phase']} ({p['duration']})")
    for action in p['actions']:
        print(f"    → {action}")
    print()
EOF
```

---

## Part 5: IoT Special Challenge

The IoT sensor network represents a unique challenge.
Analyze it:

**Questions:**

1. Why is the IoT system particularly problematic for PQC migration?
1. The devices have a 10-year operational lifetime and no OTA update capability. What options exist?
1. ML-KEM (Kyber) has larger key sizes than ECDH. What are the implications for resource-constrained IoT devices?
1. A proposed solution is a "PQC gateway" that terminates IoT connections and re-establishes PQC-secured connections to the backend. What are the security trade-offs of this approach?

---

## Part 6: Executive Briefing

Write a 1-page executive briefing (suitable for the CISO and board) that:

1. Explains the quantum threat in non-technical terms
1. States the risk to YOUR organization's specific data
1. Describes the recommended migration approach
1. States the estimated cost/timeline (you may estimate)
1. Describes what happens if NO action is taken

---

## Part 7: Technical Deep Dive — ML-KEM vs ECDH

```python
python3 << 'EOF'
print("ML-KEM vs ECDH Comparison")
print("=" * 60)
print()

comparison = {
    "Algorithm": ["ECDH P-256", "ECDH P-384", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    "Classical Security (bits)": [128, 192, 128, 192, 256],
    "Quantum Security (bits)":   [0, 0, 128, 192, 256],
    "Public Key Size":  ["64 B", "96 B", "800 B", "1184 B", "1568 B"],
    "Ciphertext Size":  ["64 B", "96 B", "768 B", "1088 B", "1568 B"],
    "Key Gen Speed":    ["~0.05ms", "~0.1ms", "~0.05ms", "~0.07ms", "~0.09ms"],
}

col_w = 25
print(f"{'Metric':<25}", end="")
for alg in comparison["Algorithm"]:
    print(f"{alg:>14}", end="")
print()
print("-" * (25 + 14 * len(comparison["Algorithm"])))

for metric in ["Classical Security (bits)", "Quantum Security (bits)",
               "Public Key Size", "Ciphertext Size", "Key Gen Speed"]:
    print(f"{metric:<25}", end="")
    for val in comparison[metric]:
        print(f"{str(val):>14}", end="")
    print()

print()
print("Note: ML-KEM key sizes are larger than ECDH but still manageable for most protocols.")
print("The TLS 1.3 ClientHello with ML-KEM-768 key_share is ~1KB larger.")
print("This is acceptable for most applications but may impact constrained IoT devices.")
EOF
```

---

**Time limit:** 90 minutes
**Pass criteria:**

* Correctly classify all 10 systems for quantum vulnerability
* Identify all "harvest now" high-risk scenarios
* Provide a credible migration roadmap
* Complete executive briefing
* Answer all IoT challenge questions
