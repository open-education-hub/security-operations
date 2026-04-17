#!/usr/bin/env bash
# generate.sh — Regenerate support files for drill-02-crypto-attack-scenarios
#
# Creates the five vulnerable code modules as standalone Python files so
# students can run, audit, and fix them locally.
#
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating support files for drill-02-crypto-attack-scenarios ==="

# ── Scenario 1: CTR nonce-reuse chat application ─────────────────────────────
cat > scenario_01_chat_crypto.py << 'PYEOF'
#!/usr/bin/env python3
"""
Scenario 1: Chat Application with AES-CTR Nonce Reuse
======================================================
This code implements message encryption with a critical vulnerability:
the CTR nonce is FIXED (never changes), which allows keystream recovery.

Run this file to see the nonce-reuse attack demonstrated.
"""

# ── Vulnerable implementation ─────────────────────────────────────────────────
FIXED_KEY   = b"MySuperSecretKey"   # 16 bytes = AES-128
FIXED_NONCE = b"\x00" * 16         # NEVER changes — same nonce always used!


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_message_vulnerable(plaintext: bytes, keystream: bytes) -> bytes:
    """Simulates AES-CTR with a fixed nonce — XOR with a fixed keystream."""
    # In real CTR mode: keystream = AES(key, nonce || counter)
    # If nonce never changes, the keystream is always identical
    return xor_bytes(plaintext, keystream[:len(plaintext)])


if __name__ == "__main__":
    # Simulate a fixed keystream (as if from AES-CTR with a fixed nonce)
    import hashlib
    keystream = hashlib.sha256(FIXED_KEY + FIXED_NONCE).digest() * 4  # fake keystream

    print("=" * 60)
    print("CTR Nonce-Reuse Attack Demonstration")
    print("=" * 60)
    print()

    # Victim messages
    msg_alice = b"Transfer $1000 to Bob's account"
    msg_bob   = b"CONFIDENTIAL: Password is P@ssw0rd"

    c_alice = encrypt_message_vulnerable(msg_alice, keystream)
    c_bob   = encrypt_message_vulnerable(msg_bob,   keystream)

    print(f"Alice's ciphertext (hex): {c_alice.hex()}")
    print(f"Bob's   ciphertext (hex): {c_bob.hex()}")
    print()

    # Attack: XOR two ciphertexts → P1 XOR P2 (key cancels out)
    min_len = min(len(c_alice), len(c_bob))
    xor_ct = xor_bytes(c_alice[:min_len], c_bob[:min_len])
    print("C_alice XOR C_bob =", xor_ct.hex())
    print()

    # If attacker knows part of P1, they can extract P2
    known_prefix_alice = msg_alice[:15]
    recovered_prefix_bob = xor_bytes(xor_ct[:15], known_prefix_alice)
    print(f"Attacker knows first 15 bytes of Alice's plaintext: {known_prefix_alice}")
    print(f"Attacker recovers first 15 bytes of Bob's message:  {recovered_prefix_bob}")
    print()
    print("VULNERABILITY: Nonce reuse in CTR/stream mode leaks XOR of plaintexts.")
    print()
    print("QUESTIONS:")
    print("  1. What are the two critical vulnerabilities in this implementation?")
    print("  2. What is the correct fix?")
PYEOF
echo "[+] scenario_01_chat_crypto.py created"

# ── Scenario 2: Predictable password reset tokens ────────────────────────────
cat > scenario_02_password_reset.py << 'PYEOF'
#!/usr/bin/env python3
"""
Scenario 2: Predictable Password Reset Token Generation
========================================================
This implementation uses MD5 and a timestamp as the only entropy source,
making tokens brute-forceable in seconds.

Run this file to see the timing-based brute-force attack.
"""
import hashlib
import time


# ── Vulnerable implementation ─────────────────────────────────────────────────
def generate_reset_token(user_email: str) -> str:
    """Generate a password reset token — VULNERABLE."""
    timestamp = int(time.time())
    token = hashlib.md5(f"{user_email}{timestamp}".encode()).hexdigest()
    return token


def verify_token(email: str, token: str, max_age_seconds: int = 3600) -> bool:
    """Verify a password reset token — tries all timestamps in last hour."""
    current_time = int(time.time())
    for t in range(current_time - max_age_seconds, current_time + 1):
        expected = hashlib.md5(f"{email}{t}".encode()).hexdigest()
        if expected == token:
            return True
    return False


if __name__ == "__main__":
    print("=" * 60)
    print("Password Reset Token Brute-Force Demonstration")
    print("=" * 60)
    print()

    target_email = "ceo@company.com"

    print(f"Brute-forcing tokens for: {target_email}")
    print("(Attacker knows approximate token generation time)")
    print()

    now = int(time.time())
    start = time.perf_counter()
    count = 0

    for t in range(now - 300, now + 1):   # last 5 minutes
        token = hashlib.md5(f"{target_email}{t}".encode()).hexdigest()
        count += 1

    elapsed = time.perf_counter() - start
    rate = count / elapsed

    print(f"Tried {count} timestamps in {elapsed*1000:.1f} ms")
    print(f"Rate: {rate:,.0f} hashes/second")
    print(f"Full 1-hour window: {rate * 3600:,.0f} hashes/second → trivial!")
    print()
    print("VULNERABILITIES (find at least 3):")
    print("  1. ???")
    print("  2. ???")
    print("  3. ???")
    print()
    print("QUESTION: What is the correct fix?")
PYEOF
echo "[+] scenario_02_password_reset.py created"

# ── Scenario 3: HMAC timing side-channel ─────────────────────────────────────
cat > scenario_03_api_auth.py << 'PYEOF'
#!/usr/bin/env python3
"""
Scenario 3: HMAC Timing Side-Channel in API Authentication
===========================================================
The verify_request function uses == for HMAC comparison, which short-circuits
on first mismatch, leaking timing information an attacker can exploit.

Run this file to see the timing difference between secure and insecure comparison.
"""
import hmac
import hashlib
import time

SECRET_KEY = "shared_api_secret"


# ── Vulnerable implementation ─────────────────────────────────────────────────
def verify_request_vulnerable(body: str, provided_hmac: str) -> bool:
    """Verify HMAC — VULNERABLE: uses == (short-circuits on first mismatch)."""
    expected_hmac = hmac.new(
        SECRET_KEY.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()
    return expected_hmac == provided_hmac  # BUG


def insecure_compare(a: str, b: str) -> bool:
    """Returns False on first differing character — leaks position info."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def secure_compare(a: str, b: str) -> bool:
    """Constant-time comparison — always processes all bytes."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


if __name__ == "__main__":
    print("=" * 60)
    print("Timing Side-Channel Demonstration")
    print("=" * 60)
    print()

    correct_hmac = "a" * 64   # 64 hex chars for SHA-256

    def time_fn(func, prefix_correct: int, iterations: int = 200_000) -> float:
        guess = "a" * prefix_correct + "b" * (64 - prefix_correct)
        start = time.perf_counter()
        for _ in range(iterations):
            func(correct_hmac, guess)
        return (time.perf_counter() - start) * 1000  # ms

    print("Insecure comparison (exits early on mismatch):")
    for prefix in [0, 16, 32, 48, 63, 64]:
        t = time_fn(insecure_compare, prefix)
        print(f"  {prefix:>2} correct chars: {t:>8.2f} ms")

    print()
    print("Secure constant-time comparison:")
    for prefix in [0, 16, 32, 48, 63, 64]:
        t = time_fn(secure_compare, prefix)
        print(f"  {prefix:>2} correct chars: {t:>8.2f} ms")

    print()
    print("QUESTION 1: What vulnerability exists in verify_request_vulnerable?")
    print("QUESTION 2: Provide the corrected implementation.")
PYEOF
echo "[+] scenario_03_api_auth.py created"

# ── Scenario 4: ECB mode healthcare database ──────────────────────────────────
cat > scenario_04_db_encrypt.py << 'PYEOF'
#!/usr/bin/env python3
"""
Scenario 4: Healthcare Database Using AES-ECB Mode
===================================================
ECB mode produces identical ciphertext for identical plaintext blocks,
allowing an attacker to detect duplicate records even without the key.

Run this file to see the ECB pattern leak.
NOTE: Uses a simple XOR simulation since pycryptodome may not be available.
"""


def ecb_simulate(block: bytes, key: int = 42) -> bytes:
    """Simulates ECB determinism: same input → same output (using XOR for demo)."""
    return bytes(b ^ key for b in block)


def bad_encrypt_ssn(ssn: str, key: int = 42) -> str:
    padded = ssn.ljust(16)[:16].encode()
    return ecb_simulate(padded, key).hex()


if __name__ == "__main__":
    print("=" * 60)
    print("ECB Mode — Pattern Leakage Demonstration")
    print("=" * 60)
    print()

    patient_records = [
        ("Alice",   "123-45-6789", "Hypertension"),
        ("Bob",     "123-45-6789", "Diabetes"),       # same SSN as Alice
        ("Carol",   "987-65-4321", "Asthma"),
        ("David",   "456-78-9012", "Arthritis"),
        ("Eve",     "123-45-6789", "Anxiety"),          # same SSN again
    ]

    print(f"{'Patient':<10} {'SSN':<15} {'Encrypted SSN'}")
    print("-" * 55)
    for name, ssn, _ in patient_records:
        enc = bad_encrypt_ssn(ssn)
        print(f"{name:<10} {ssn:<15} {enc}")

    print()
    print("An attacker with no key can see that Alice, Bob, and Eve share an SSN.")
    print("In real ECB-AES, identical 16-byte blocks produce identical ciphertext.")
    print()
    print("VULNERABILITIES (find at least 3):")
    print("  1. AES-ECB — identical plaintext blocks → identical ciphertext blocks")
    print("  2. ???")
    print("  3. ???")
    print()
    print("QUESTION: Provide a corrected implementation outline (use AES-256-GCM).")
PYEOF
echo "[+] scenario_04_db_encrypt.py created"

# ── Scenario 5: VPN configuration audit reference ────────────────────────────
cat > scenario_05_vpn_audit.txt << 'EOF'
# VPN Configuration Audit — drill-02 Scenario 5
# ------------------------------------------------
# Analyse each setting and identify the security weakness.

[VPN Audit Report]
Protocol: IPSec IKEv2
Phase 1 (IKE) settings:
  Encryption: 3DES-168
  Integrity:  SHA-1
  DH Group:   Group 1 (768-bit MODP)

Phase 2 (ESP) settings:
  Encryption: 3DES
  Integrity:  MD5-96
  PFS:        Disabled

Certificate:
  Signature:  SHA-1 with RSA-1024
  Validity:   Not After: 2019-08-14 (EXPIRED)

----------------------------------------------------------------------
TASK: List every weakness. For each one state:
  - The specific problem
  - The actual risk
  - The correct replacement value

Expected count: at least 7 weaknesses.
----------------------------------------------------------------------
EOF
echo "[+] scenario_05_vpn_audit.txt created"

# ── Instructor answer key ─────────────────────────────────────────────────────
cat > INSTRUCTOR_ANSWERS.txt << 'ANS'
# INSTRUCTOR ANSWERS — drill-02-crypto-attack-scenarios
# DO NOT distribute to students

== Scenario 1: CTR Nonce Reuse ==
Vulnerabilities:
  1. FIXED_NONCE: Never-changing nonce means the keystream is identical for every message.
     If two messages are encrypted: C1=P1⊕K, C2=P2⊕K, then C1⊕C2 = P1⊕P2.
     With one known plaintext, the other is trivially recovered.
  2. FIXED_KEY: Hardcoded key in source code — leaked in repository, binary, or memory dump.
Fix:
  - Use secrets.token_bytes(16) or os.urandom(16) as a fresh nonce per message.
  - Use AES-GCM instead of CTR — adds authentication AND enforces nonce uniqueness.
  - Rotate keys; never embed keys in source code.

== Scenario 2: Password Reset Token ==
Vulnerabilities:
  1. MD5: Cryptographically broken; no longer suitable for security tokens.
  2. Timestamp as only entropy: Only 3600 possible tokens per hour — trivially brute-forced.
  3. Predictable token: Attacker knowing approximate generation time → <300 guesses needed.
  4. Token length: 32 hex chars = 128 bits, but real entropy ≈ 11 bits (log2(3600)).
Fix:
  - token = secrets.token_urlsafe(32)   # 32 bytes = 256 bits of entropy
  - Store hash(token) in DB; compare with hmac.compare_digest()
  - Set short expiry (15-30 min) and enforce one-time use.

== Scenario 3: HMAC Timing Side-Channel ==
Vulnerability:
  str1 == str2 exits as soon as it finds a mismatch, taking less time for
  early mismatches. An attacker sending millions of guesses can time responses
  to discover correct prefix bytes one at a time.
Fix:
  Use hmac.compare_digest(expected, provided) — constant-time comparison.
  Python stdlib: import hmac; return hmac.compare_digest(expected_hmac, provided_hmac)

== Scenario 4: ECB Healthcare Database ==
Vulnerabilities:
  1. AES-ECB mode: identical plaintext blocks → identical ciphertext blocks.
  2. No IV/nonce: deterministic encryption — same record always encrypted to same output.
  3. Fixed hardcoded key in source: DB_ENCRYPTION_KEY = "FinancialAppKey!"
  4. Padding with spaces: non-standard, could expose record length.
  5. Logging decrypted data: decrypt_and_log() prints plaintext to logs.
  6. Logging key material on error: logs key.hex() in the except block.
Fix:
  - Use AES-256-GCM with a unique nonce per record.
  - Store nonce alongside ciphertext.
  - Load key from environment variable or HSM, never source code.
  - Remove debug logging of sensitive data.

== Scenario 5: VPN Weaknesses ==
  1. 3DES-168:       Vulnerable to Sweet32 (birthday attack after 2^32 blocks). Replace: AES-256-GCM.
  2. SHA-1 integrity: Broken collision resistance. Replace: SHA-256 or SHA-384.
  3. DH Group 1 (768-bit MODP): Far below 80-bit security; broken by nation-states. Replace: DH Group 20 (ECDH P-384) or DH Group 19 (P-256).
  4. 3DES (Phase 2):  Same as #1. Replace: AES-256-GCM.
  5. MD5-96:          MD5 is cryptographically broken. Replace: HMAC-SHA-256-128.
  6. PFS disabled:    If long-term key is compromised, all past sessions are decryptable. Replace: Enable PFS (Perfect Forward Secrecy) using ephemeral DH.
  7. RSA-1024 cert:   Below minimum 2048-bit; breakable with sufficient resources. Replace: RSA-4096 or ECDSA P-384.
  8. SHA-1 certificate signature: Deprecated. Replace: SHA-256 or SHA-384.
  9. Expired certificate: Expired 2019-08-14 — VPN should reject authentication.

Executive Finding (3-5 sentences):
  The corporate VPN uses outdated cryptographic algorithms that are considered
  broken by modern security standards. An attacker with nation-state resources
  could decrypt all VPN traffic recorded since the VPN was deployed. The
  expired certificate means the VPN may already be rejecting legitimate
  connections or is configured to ignore certificate errors. Immediate
  remediation is required: replace 3DES with AES-256-GCM, upgrade DH groups,
  enable PFS, and renew the certificate.
ANS
echo "[+] INSTRUCTOR_ANSWERS.txt created"

echo ""
echo "=== Generation complete ==="
ls -lh "$SCRIPT_DIR"
