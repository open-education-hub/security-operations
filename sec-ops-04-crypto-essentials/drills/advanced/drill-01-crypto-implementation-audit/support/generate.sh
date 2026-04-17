#!/usr/bin/env bash
# generate.sh — Regenerate support files for drill-01-crypto-implementation-audit
#
# Creates the four vulnerable Python modules as standalone files so students
# can read, run demonstrations, and write remediation code.
#
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating support files for drill-01-crypto-implementation-audit ==="

# ── Module 1: auth_module.py ──────────────────────────────────────────────────
cat > auth_module.py << 'PYEOF'
#!/usr/bin/env python3
"""
auth_module.py — User Authentication
=====================================
This module handles user registration, authentication, and session/token generation.

AUDIT TASK: Find all cryptographic vulnerabilities and classify by severity.
"""
import hashlib
import os
import time
import secrets

DATABASE = {}  # In-memory user store for demo


def register_user(username: str, password: str) -> bool:
    """Register a new user with password."""
    # Hash password for storage
    password_hash = hashlib.sha256(password.encode()).hexdigest()  # FINDING #1
    DATABASE[username] = {
        'hash': password_hash,
        'created': time.time()
    }
    return True


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user."""
    if username not in DATABASE:
        return False

    stored_hash = DATABASE[username]['hash']
    input_hash = hashlib.sha256(password.encode()).hexdigest()

    return stored_hash == input_hash  # FINDING #2: non-constant-time comparison


def generate_session_token(username: str) -> str:
    """Generate session token."""
    timestamp = int(time.time())
    token_data = f"{username}:{timestamp}"
    return hashlib.md5(token_data.encode()).hexdigest()  # FINDING #3


def reset_password_token(email: str) -> str:
    """Generate password reset token."""
    return hashlib.sha256(f"{email}{time.time()}".encode()).hexdigest()[:16]  # FINDING #4


# ── Demo ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Auth Module — Vulnerability Demonstrations")
    print("=" * 50)

    # Demo 1: SHA-256 password hash is fast — easily brute-forced
    import time as _time
    target = hashlib.sha256("password".encode()).hexdigest()
    wordlist = ["password", "123456", "admin", "qwerty", "letmein", "Password1"]
    t0 = _time.perf_counter()
    for w in wordlist:
        if hashlib.sha256(w.encode()).hexdigest() == target:
            elapsed = (_time.perf_counter() - t0) * 1000
            print(f"[FINDING #1] Password 'password' cracked in {elapsed:.2f}ms")
            print(f"  SHA-256 is NOT appropriate for passwords (use bcrypt/scrypt/argon2)")
            break

    # Demo 2: MD5 session token is weak and predictable
    token = generate_session_token("alice")
    print(f"\n[FINDING #3] Session token: {token}")
    print(f"  MD5 output is only 128 bits; timestamp limits entropy further")

    # Demo 3: Short reset token (16 chars = 64 bits; timestamp reduces real entropy)
    reset = reset_password_token("user@example.com")
    print(f"\n[FINDING #4] Reset token: {reset}")
    print(f"  Only {len(reset)} hex chars, generated from predictable timestamp")
PYEOF
echo "[+] auth_module.py created"

# ── Module 2: encryption_module.py ───────────────────────────────────────────
cat > encryption_module.py << 'PYEOF'
#!/usr/bin/env python3
"""
encryption_module.py — Data Encryption
========================================
Handles encryption of financial records and API keys.

AUDIT TASK: Find all cryptographic vulnerabilities and classify by severity.

NOTE: pycryptodome required for full demo: pip install pycryptodome
      If not installed, the module stubs out encryption with error messages.
"""
import base64
import os

# Configuration
DB_ENCRYPTION_KEY = "FinancialAppKey!"  # FINDING #5: hardcoded key

try:
    from Crypto.Cipher import AES, DES
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def encrypt_financial_record(data: str) -> str:
    """Encrypt sensitive financial data for database storage."""
    if not CRYPTO_AVAILABLE:
        return f"[demo] ECB-encrypted({data!r})"
    key = DB_ENCRYPTION_KEY.encode()   # 16 bytes
    padded = data + " " * (16 - len(data) % 16)
    cipher = AES.new(key, AES.MODE_ECB)  # FINDING #6: ECB mode
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()


def encrypt_api_key(api_key: str) -> str:
    """Encrypt API keys for storage."""
    if not CRYPTO_AVAILABLE:
        return f"[demo] DES-ECB-encrypted({api_key!r})"
    key = b"APIKey00"  # 8 bytes for DES — FINDING #7: DES is broken
    padded = api_key + "\x00" * (8 - len(api_key) % 8)
    cipher = DES.new(key, DES.MODE_ECB)  # FINDING #8: DES + ECB
    return base64.b64encode(cipher.encrypt(padded.encode()[:8])).decode()


def generate_encryption_key() -> bytes:
    """Generate a new encryption key."""
    import random
    random.seed(12345)  # FINDING #9: seeded PRNG produces same key every time
    return bytes([random.randint(0, 255) for _ in range(32)])


def decrypt_and_log(ciphertext: str, key: bytes) -> str:
    """Decrypt and log for debugging."""
    if not CRYPTO_AVAILABLE:
        print(f"[DEBUG] Would decrypt: {ciphertext[:20]}...")
        return "demo-plaintext"
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        plaintext = decrypted.decode().strip()
        print(f"[DEBUG] Decrypted: {plaintext}")  # FINDING #10: logs sensitive data
        return plaintext
    except Exception as e:
        print(f"[DEBUG] Decryption key was: {key.hex()}")  # FINDING #11: logs key!
        raise


# ── Demo ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import random

    print("Encryption Module — Vulnerability Demonstrations")
    print("=" * 50)

    # Demo 1: ECB pattern leakage
    print("\n[FINDING #6] AES-ECB pattern leakage:")
    records = ["SSN:123-45-6789 ", "SSN:123-45-6789 ", "SSN:987-65-4321 "]
    for r in records:
        enc = encrypt_financial_record(r)
        print(f"  {r!r} → {enc}")
    print("  Note: identical records produce identical ciphertext")

    # Demo 2: Deterministic key generation
    print("\n[FINDING #9] Fixed-seed PRNG generates same key every time:")
    random.seed(12345)
    key1 = bytes([random.randint(0, 255) for _ in range(32)])
    random.seed(12345)
    key2 = bytes([random.randint(0, 255) for _ in range(32)])
    print(f"  Key 1: {key1.hex()}")
    print(f"  Key 2: {key2.hex()}")
    print(f"  Identical: {key1 == key2} — attacker who knows seed=12345 precomputes all keys")
PYEOF
echo "[+] encryption_module.py created"

# ── Module 3: tls_config.py ───────────────────────────────────────────────────
cat > tls_config.py << 'PYEOF'
#!/usr/bin/env python3
"""
tls_config.py — TLS Configuration
===================================
Configures SSL contexts for server and client connections.

AUDIT TASK: Find all cryptographic vulnerabilities and classify by severity.
"""
import ssl
import hashlib


def create_ssl_context_server() -> ssl.SSLContext:
    """Create SSL context for the API server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # NOTE: In a real audit you would load an actual cert:
    # ctx.load_cert_chain('server.crt', 'server.key')

    # FINDING #12: TLS 1.0 and 1.1 are not explicitly disabled
    ctx.options |= ssl.OP_NO_SSLv2   # disables SSL 2.0 only

    # FINDING #13: Weak cipher suites allowed
    ctx.set_ciphers('ALL:!aNULL')    # allows RC4, DES, 3DES, export ciphers

    # FINDING #14: Client certificate verification disabled
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


def create_ssl_context_client() -> ssl.SSLContext:
    """Create SSL context for outbound connections."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # FINDING #15: Certificate verification completely disabled — MITM risk
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


def verify_certificate_pinning(cert_der: bytes, expected_fp: str) -> bool:
    """Certificate pinning check."""
    # FINDING #16: MD5 used for certificate fingerprinting (not SHA-256)
    actual_fp = hashlib.md5(cert_der).hexdigest()
    return actual_fp == expected_fp   # FINDING #17: non-constant-time comparison


# ── Demo ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("TLS Config Module — Vulnerability Analysis")
    print("=" * 50)

    print("\n[FINDING #15] Client SSL context disables certificate verification:")
    ctx = create_ssl_context_client()
    print(f"  check_hostname: {ctx.check_hostname}  (should be True)")
    print(f"  verify_mode:    {ctx.verify_mode}     (should be ssl.CERT_REQUIRED = 2)")
    print("  Effect: any TLS certificate is accepted → trivial MITM attack")

    print("\n[FINDING #16] MD5 used for certificate pinning:")
    fake_cert = b"example certificate DER bytes"
    md5_fp  = hashlib.md5(fake_cert).hexdigest()
    sha256_fp = hashlib.sha256(fake_cert).hexdigest()
    print(f"  MD5    fingerprint: {md5_fp}  (32 hex = 128 bits, weak)")
    print(f"  SHA256 fingerprint: {sha256_fp}  (64 hex = 256 bits, correct)")
PYEOF
echo "[+] tls_config.py created"

# ── Module 4: jwt_module.py ───────────────────────────────────────────────────
cat > jwt_module.py << 'PYEOF'
#!/usr/bin/env python3
"""
jwt_module.py — JWT Token Handling
====================================
Creates and verifies JWT tokens for API authentication.

AUDIT TASK: Find all cryptographic vulnerabilities and classify by severity.
"""
import base64
import json
import hmac
import hashlib

JWT_SECRET = "secret"  # FINDING #18: trivially weak secret


def create_jwt(payload: dict) -> str:
    """Create a JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}

    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()

    signature = hmac.new(
        JWT_SECRET.encode(),
        f"{h}.{p}".encode(),
        hashlib.sha256
    ).digest()

    s = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    return f"{h}.{p}.{s}"


def verify_jwt(token: str) -> dict:
    """Verify and decode a JWT token."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")

    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))

    # FINDING #19: Accepts 'none' algorithm — bypasses HMAC entirely!
    if header['alg'] == 'none':
        return json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))

    expected_sig = hmac.new(
        JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()

    actual_sig = base64.urlsafe_b64decode(sig_b64 + '==')

    if expected_sig == actual_sig:  # FINDING #20: non-constant-time comparison
        return json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
    raise ValueError("Invalid signature")


# ── Demo ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("JWT Module — Vulnerability Demonstrations")
    print("=" * 50)

    # Demo 1: Create a legitimate token
    legit_token = create_jwt({"sub": "alice", "role": "analyst", "user_id": 42})
    print(f"\nLegitimate token: {legit_token[:40]}...")

    # Demo 2: Algorithm confusion — forge admin token with alg:none
    print("\n[FINDING #19] Algorithm confusion attack (alg:none):")
    forged_header = {"alg": "none", "typ": "JWT"}
    forged_payload = {"sub": "attacker", "role": "admin", "user_id": 999}

    fh = base64.urlsafe_b64encode(json.dumps(forged_header).encode()).rstrip(b'=').decode()
    fp = base64.urlsafe_b64encode(json.dumps(forged_payload).encode()).rstrip(b'=').decode()
    forged_token = f"{fh}.{fp}."   # Empty signature

    print(f"  Forged token:   {forged_token[:60]}...")
    try:
        decoded = verify_jwt(forged_token)
        print(f"  Verification result: {decoded}")
        print(f"  *** ADMIN ACCESS GRANTED WITHOUT VALID SIGNATURE ***")
    except Exception as e:
        print(f"  Error: {e}")

    # Demo 3: Weak secret brute-force
    print("\n[FINDING #18] Weak JWT secret 'secret':")
    print("  An attacker can brute-force HS256 secrets with tools like hashcat:")
    print("  $ hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt")
    print("  The word 'secret' is in every common wordlist and cracks instantly.")
PYEOF
echo "[+] jwt_module.py created"

# ── Instructor vulnerability table ───────────────────────────────────────────
cat > INSTRUCTOR_VULNERABILITY_TABLE.txt << 'TABLE'
# INSTRUCTOR VULNERABILITY TABLE — drill-01-crypto-implementation-audit
# DO NOT distribute to students
# 
# Format: #  | Module/Function          | Vulnerability               | CWE  | Severity
#
# Students must find at least 15. This table has 20.

 #  | Module / Function              | Vulnerability Description                        | CWE     | Severity
----|--------------------------------|--------------------------------------------------|---------|----------
 1  | auth / register_user           | SHA-256 for passwords (no salt, fast)            | CWE-916 | CRITICAL
 2  | auth / authenticate_user       | Non-constant-time password comparison            | CWE-208 | HIGH
 3  | auth / generate_session_token  | MD5 for session tokens (cryptographically broken) | CWE-327 | CRITICAL
 4  | auth / reset_password_token    | Timestamp-seeded token (only 16 hex chars entropy)| CWE-330 | CRITICAL
 5  | enc  / DB_ENCRYPTION_KEY       | Hardcoded encryption key in source code          | CWE-321 | CRITICAL
 6  | enc  / encrypt_financial_record| AES-ECB mode (leaks patterns)                    | CWE-327 | HIGH
 7  | enc  / encrypt_api_key         | DES cipher (broken since 1998)                   | CWE-327 | CRITICAL
 8  | enc  / encrypt_api_key         | DES-ECB mode (deterministic + weak cipher)       | CWE-327 | CRITICAL
 9  | enc  / generate_encryption_key | Fixed PRNG seed (key is deterministic)           | CWE-338 | CRITICAL
10  | enc  / decrypt_and_log         | Logs decrypted sensitive data in plaintext        | CWE-312 | HIGH
11  | enc  / decrypt_and_log         | Logs encryption key on error                     | CWE-312 | CRITICAL
12  | tls  / create_ssl_context_server | TLS 1.0 + 1.1 not disabled                     | CWE-326 | HIGH
13  | tls  / create_ssl_context_server | Weak ciphers allowed (ALL:!aNULL)              | CWE-327 | HIGH
14  | tls  / create_ssl_context_server | Client cert verification disabled               | CWE-295 | MEDIUM
15  | tls  / create_ssl_context_client | Certificate verification disabled (MITM risk)  | CWE-295 | CRITICAL
16  | tls  / verify_certificate_pinning| MD5 for cert fingerprinting                   | CWE-327 | HIGH
17  | tls  / verify_certificate_pinning| Non-constant-time fingerprint comparison       | CWE-208 | MEDIUM
18  | jwt  / JWT_SECRET               | Trivially weak secret ("secret")               | CWE-321 | CRITICAL
19  | jwt  / verify_jwt               | Accepts alg:none — bypasses signature check     | CWE-347 | CRITICAL
20  | jwt  / verify_jwt               | Non-constant-time signature comparison          | CWE-208 | HIGH

== RISK RATING ==
Critical: 10 findings
High:      7 findings
Medium:    3 findings
AGGREGATE: This application should NOT be deployed. Mandatory remediation required.

== TOP 3 PRIORITIES ==
1. Fix alg:none JWT (Finding #19) — actively exploitable without credentials
2. Disable certificate verification (Finding #15) — MITM on all outbound traffic
3. Replace SHA-256 with bcrypt/argon2 for passwords (Finding #1) — cracked trivially
TABLE
echo "[+] INSTRUCTOR_VULNERABILITY_TABLE.txt created"

echo ""
echo "=== Generation complete ==="
ls -lh "$SCRIPT_DIR"
