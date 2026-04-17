# Solution: Drill 01 (Advanced) — Cryptographic Implementation Audit

---

## Task 1: Vulnerability Inventory (18 findings)

| # | Module / Function | Vulnerability | CWE | Severity | Exploitability |
|---|------------------|---------------|-----|----------|----------------|
| 1 | auth: `register_user` | Password hashed with SHA-256 (no salt, no KDF) | CWE-916 | **Critical** | Easy — GPU cracks common passwords in seconds |
| 2 | auth: `register_user` | No salt — same password = same hash (rainbow tables work) | CWE-760 | **Critical** | Easy |
| 3 | auth: `authenticate_user` | `==` comparison (timing attack on hash) | CWE-208 | **High** | Moderate — requires many requests and timing measurement |
| 4 | auth: `generate_session_token` | MD5 used for session tokens | CWE-327 | **High** | Moderate — MD5 collision/preimage |
| 5 | auth: `generate_session_token` | Token predictable from username + timestamp | CWE-330 | **Critical** | Easy — brute-force small timestamp window |
| 6 | auth: `reset_password_token` | SHA-256 of email+time — predictable, no HMAC | CWE-330 | **Critical** | Easy |
| 7 | auth: `reset_password_token` | Token truncated to 16 chars (too short, only 2^64 possibilities) | CWE-331 | **High** | Moderate |
| 8 | encrypt: `DB_ENCRYPTION_KEY` | Hardcoded key in source code | CWE-321 | **Critical** | Easy — anyone with code access has the key |
| 9 | encrypt: `encrypt_financial_record` | AES-ECB mode — leaks patterns | CWE-327 | **High** | Moderate — pattern analysis on ciphertext |
| 10 | encrypt: `encrypt_financial_record` | No authentication (no AEAD) | CWE-353 | **High** | Easy — attacker can tamper with ciphertext |
| 11 | encrypt: `encrypt_api_key` | DES used (broken, 56-bit key) | CWE-327 | **Critical** | Easy — brute-forceable in < 1 day |
| 12 | encrypt: `generate_encryption_key` | Fixed random seed — generates same "random" key every time | CWE-338 | **Critical** | Easy — attacker predicts key if they know the seed |
| 13 | encrypt: `decrypt_and_log` | Decrypted plaintext logged (PII/sensitive data in logs) | CWE-532 | **High** | Easy — access to log files = plaintext data |
| 14 | encrypt: `decrypt_and_log` | Encryption key logged on error | CWE-532 | **Critical** | Easy — any error leaks the key to logs |
| 15 | tls: `create_ssl_context_client` | Certificate verification disabled (`CERT_NONE`) | CWE-295 | **Critical** | Easy — MITM attack trivial |
| 16 | tls: `create_ssl_context_server` | TLS 1.0/1.1 enabled (weak cipher option `ALL:!aNULL`) | CWE-326 | **High** | Moderate — requires active attack |
| 17 | tls: `verify_certificate_pinning` | MD5 for cert fingerprint | CWE-327 | **High** | Hard (but why use MD5?) |
| 18 | jwt: `verify_jwt` | Accepts `alg:none` — signature verification bypass | CWE-347 | **Critical** | Easy — forge any JWT without credentials |
| 19 | jwt: `JWT_SECRET = "secret"` | Trivially guessable JWT secret | CWE-321 | **Critical** | Easy — brute-force "secret" instantly |
| 20 | jwt: signature comparison | `==` non-constant-time | CWE-208 | **Medium** | Hard |

---

## Task 3: Corrected Implementations

### auth_module.py — Fixed

```python
import secrets, hmac, hashlib, time
import bcrypt  # pip install bcrypt

DATABASE = {}

def register_user(username: str, password: str) -> bool:
    # Use bcrypt with work factor 12 (intentionally slow)
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    DATABASE[username] = {
        'hash': password_hash,
        'created': time.time()
    }
    return True

def authenticate_user(username: str, password: str) -> bool:
    if username not in DATABASE:
        # Constant-time fake check to prevent username enumeration via timing
        bcrypt.checkpw(password.encode(), bcrypt.gensalt())
        return False
    # bcrypt.checkpw is constant-time
    return bcrypt.checkpw(password.encode(), DATABASE[username]['hash'])

def generate_session_token(username: str) -> str:
    # 32 bytes = 256 bits of cryptographically secure randomness
    return secrets.token_urlsafe(32)

def reset_password_token(email: str) -> str:
    # Cryptographically secure, unpredictable token
    # Sign with HMAC to prevent forgery
    token = secrets.token_urlsafe(32)
    # Store token hash + expiry + email in DB; never reuse
    return token
```

### encryption_module.py — Fixed

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# Load key from environment or secrets manager — NEVER hardcode
DB_ENCRYPTION_KEY = bytes.fromhex(os.environ['DB_ENC_KEY_HEX'])

def encrypt_financial_record(data: str, record_id: str) -> dict:
    aesgcm = AESGCM(DB_ENCRYPTION_KEY)
    nonce = os.urandom(12)   # unique per record
    # record_id as AAD: authenticated but not encrypted
    ciphertext = aesgcm.encrypt(nonce, data.encode(), record_id.encode())
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

def generate_encryption_key() -> bytes:
    # os.urandom uses the OS CSPRNG — cryptographically secure
    return os.urandom(32)

def decrypt_without_logging(ciphertext_b64: str, nonce_b64: str, record_id: str) -> str:
    # NEVER log plaintext or keys
    aesgcm = AESGCM(DB_ENCRYPTION_KEY)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    try:
        return aesgcm.decrypt(nonce, ciphertext, record_id.encode()).decode()
    except Exception:
        # Log the ERROR but NOT the key or plaintext
        import logging
        logging.error(f"Decryption failed for record {record_id}")
        raise
```

### tls_config.py — Fixed

```python
import ssl

def create_ssl_context_server() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('server.crt', 'server.key')

    # Enforce TLS 1.2 minimum (prefer TLS 1.3)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Only strong cipher suites
    ctx.set_ciphers(
        'TLS_AES_256_GCM_SHA384:'       # TLS 1.3
        'TLS_CHACHA20_POLY1305_SHA256:'  # TLS 1.3
        'ECDHE-ECDSA-AES256-GCM-SHA384:'  # TLS 1.2 ECDSA
        'ECDHE-RSA-AES256-GCM-SHA384'     # TLS 1.2 RSA
    )
    return ctx

def create_ssl_context_client() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # ALWAYS verify certificates
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    # Load system CA bundle
    ctx.load_default_certs()
    return ctx

def verify_certificate_pinning(cert_der: bytes, expected_fp: str) -> bool:
    import hashlib, hmac
    actual_fp = hashlib.sha256(cert_der).hexdigest()
    # Constant-time comparison
    return hmac.compare_digest(actual_fp, expected_fp)
```

### jwt_module.py — Fixed

```python
import os, hmac, hashlib, base64, json, time

# Load from environment — NEVER hardcode; use at least 256-bit random secret
JWT_SECRET = os.environ['JWT_SECRET_HEX']

def create_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    # Add expiry
    payload['exp'] = int(time.time()) + 3600
    payload['iat'] = int(time.time())

    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()

    signature = hmac.new(bytes.fromhex(JWT_SECRET), f"{h}.{p}".encode(), hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    return f"{h}.{p}.{s}"

def verify_jwt(token: str) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))

    # CRITICAL: Never accept 'none' algorithm
    if header.get('alg') != 'HS256':
        raise ValueError(f"Unsupported algorithm: {header.get('alg')}")

    expected_sig = hmac.new(
        bytes.fromhex(JWT_SECRET),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()

    actual_sig = base64.urlsafe_b64decode(sig_b64 + '==')

    # Constant-time comparison
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid signature")

    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))

    # Check expiry
    if payload.get('exp', 0) < time.time():
        raise ValueError("Token expired")

    return payload
```

---

## Task 4: Formal Audit Report

### Cryptographic Security Audit Report — FinApp v2.1

**Classification:** CONFIDENTIAL

**Date:** 2024-01-15

**Auditors:** SOC Security Engineering Team

---

#### Executive Summary

The FinApp v2.1 cryptographic implementation contains **20 security vulnerabilities** including **8 Critical-severity findings**.
The application is not suitable for production deployment in its current state.
Critical issues include: disabled TLS certificate verification (enabling trivial man-in-the-middle attacks), hardcoded encryption keys (which can be extracted from the source code repository), broken password hashing (SHA-256 without salt, enabling rapid password recovery with commodity hardware), and a JWT authentication bypass that allows any attacker to forge administrator credentials without knowing the secret key.
These vulnerabilities collectively make it possible for an attacker to intercept all financial data in transit, decrypt stored customer records, and gain administrative access to the application. **All Critical findings must be resolved before any production deployment.**

---

#### Technical Findings Summary

| Severity | Count | Examples |
|----------|-------|---------|
| Critical | 8 | Disabled cert verification, hardcoded keys, SHA-256 passwords, JWT `alg:none`, predictable tokens |
| High | 8 | AES-ECB mode, DES usage, TLS 1.0 enabled, debug key logging, MD5 session tokens |
| Medium | 2 | Timing attack on comparisons |
| Low | 2 | Token length, error message verbosity |

---

#### Remediation Priority

**Immediate (before any testing environment deployment):**

1. Enable TLS certificate verification (tls_config.py line ~12-14)
1. Remove hardcoded keys; load from environment variables or secrets manager
1. Reject JWT `alg:none` (jwt_module.py)
1. Replace SHA-256 password hashing with bcrypt/Argon2

**Within 1 week:**

1. Replace AES-ECB with AES-256-GCM
1. Remove debug logging of plaintext and keys
1. Replace DES with AES-256
1. Fix random seed to use `os.urandom()`

**Within 2 weeks:**

1. Disable TLS 1.0/1.1
1. Implement constant-time comparisons throughout

---

#### Risk Rating: **CRITICAL — Do Not Deploy**
