# Drill 01 (Advanced): Cryptographic Implementation Audit

> **Level:** Advanced
> **Time:** 90 minutes
> **Tools:** Docker, Python, OpenSSL, static analysis
> **Prerequisites:** All previous content completed

---

## Scenario

You are a senior security engineer tasked with auditing the cryptographic implementation of a financial services application before it goes to production.
The development team claims it uses "strong encryption throughout."

You have been given access to the relevant code modules.
Your task is to:

1. Find all cryptographic vulnerabilities
1. Classify each by severity (Critical / High / Medium / Low)
1. Provide a remediation for each finding
1. Write a formal audit report

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y python3 python3-pip openssl 2>/dev/null | tail -3
pip3 install cryptography pycryptodome 2>/dev/null | tail -3
mkdir -p /audit && cd /audit
```

---

## Code Module 1: User Authentication

```python
# auth_module.py
import hashlib, os, time, secrets

DATABASE = {}  # In-memory for demo

def register_user(username: str, password: str) -> bool:
    """Register a new user with password"""
    # Hash password for storage
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    DATABASE[username] = {
        'hash': password_hash,
        'created': time.time()
    }
    return True

def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user"""
    if username not in DATABASE:
        return False

    stored_hash = DATABASE[username]['hash']
    input_hash = hashlib.sha256(password.encode()).hexdigest()

    # Verify password
    return stored_hash == input_hash  # BUG

def generate_session_token(username: str) -> str:
    """Generate session token"""
    timestamp = int(time.time())
    token_data = f"{username}:{timestamp}"
    return hashlib.md5(token_data.encode()).hexdigest()

def reset_password_token(email: str) -> str:
    """Generate password reset token"""
    return hashlib.sha256(f"{email}{time.time()}".encode()).hexdigest()[:16]
```

---

## Code Module 2: Data Encryption

```python
# encryption_module.py
from Crypto.Cipher import AES, DES
import base64, os

# Configuration
DB_ENCRYPTION_KEY = "FinancialAppKey!"  # BUG

def encrypt_financial_record(data: str) -> str:
    """Encrypt sensitive financial data for database storage"""
    key = DB_ENCRYPTION_KEY.encode()  # 16 bytes
    # Pad data to 16-byte boundary
    padded = data + " " * (16 - len(data) % 16)
    cipher = AES.new(key, AES.MODE_ECB)  # BUG
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def encrypt_api_key(api_key: str) -> str:
    """Encrypt API keys for storage"""
    # Use DES for API keys (BUG: legacy)
    key = b"APIKey00"  # 8 bytes for DES
    padded = api_key + "\x00" * (8 - len(api_key) % 8)
    cipher = DES.new(key, DES.MODE_ECB)  # BUG
    return base64.b64encode(cipher.encrypt(padded.encode()[:8])).decode()

def generate_encryption_key() -> bytes:
    """Generate a new encryption key"""
    import random
    random.seed(12345)  # BUG: seeded with fixed value!
    return bytes([random.randint(0, 255) for _ in range(32)])

def decrypt_and_log(ciphertext: str, key: bytes) -> str:
    """Decrypt and log for debugging"""
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        plaintext = decrypted.decode().strip()
        print(f"[DEBUG] Decrypted: {plaintext}")  # BUG: logs sensitive data
        return plaintext
    except Exception as e:
        print(f"[DEBUG] Decryption key was: {key.hex()}")  # BUG: logs key!
        raise
```

---

## Code Module 3: TLS Configuration

```python
# tls_config.py
import ssl

def create_ssl_context_server() -> ssl.SSLContext:
    """Create SSL context for the API server"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('server.crt', 'server.key')

    # Allow all TLS versions for compatibility (BUG)
    ctx.options |= ssl.OP_NO_SSLv2  # disable SSL 2.0
    # TLS 1.0 and 1.1 remain enabled!

    # Set cipher suites (BUG: includes weak ciphers)
    ctx.set_ciphers('ALL:!aNULL')  # allows RC4, DES, export ciphers

    # Verify client certificates? (BUG: disabled)
    ctx.verify_mode = ssl.CERT_NONE

    return ctx

def create_ssl_context_client() -> ssl.SSLContext:
    """Create SSL context for outbound connections"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Disable certificate verification (BUG: CRITICAL)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx

def verify_certificate_pinning(cert_der: bytes, expected_fp: str) -> bool:
    """Certificate pinning check"""
    import hashlib
    actual_fp = hashlib.md5(cert_der).hexdigest()  # BUG: should use SHA-256
    return actual_fp == expected_fp  # BUG: non-constant-time
```

---

## Code Module 4: JWT Token Handling

```python
# jwt_module.py
import base64, json, hmac, hashlib

JWT_SECRET = "secret"  # BUG: weak secret

def create_jwt(payload: dict) -> str:
    """Create a JWT token"""
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
    """Verify and decode a JWT token"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")

    header_b64, payload_b64, sig_b64 = parts

    # Decode header to check algorithm
    header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))

    # BUG: accepts 'none' algorithm
    if header['alg'] == 'none':
        return json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))

    # Verify signature
    expected_sig = hmac.new(
        JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()

    actual_sig = base64.urlsafe_b64decode(sig_b64 + '==')

    if expected_sig == actual_sig:  # BUG: non-constant-time
        return json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
    raise ValueError("Invalid signature")
```

---

## Your Tasks

### Task 1: Vulnerability Inventory

Create a vulnerability table with these columns:

* Module / Function
* Vulnerability Description
* CWE Reference (look up relevant CWEs)
* Severity: Critical / High / Medium / Low
* Exploitability (how hard is it to exploit?)

Aim to find **at least 15 distinct vulnerabilities**.

### Task 2: Demonstrate Key Vulnerabilities

Run these demonstrations:

```bash
python3 << 'DEMO_EOF'
# Demo 1: SHA-256 password hashing is NOT adequate
import hashlib, time

# Show how fast SHA-256 can be reversed
common_passwords = ["password", "123456", "admin", "qwerty", "Password1"]
target_hash = hashlib.sha256("password".encode()).hexdigest()
print(f"Target hash: {target_hash}")
start = time.perf_counter()
for pwd in common_passwords:
    if hashlib.sha256(pwd.encode()).hexdigest() == target_hash:
        print(f"Cracked: '{pwd}' in {(time.perf_counter()-start)*1000:.2f}ms")
        break
DEMO_EOF
```

```bash
python3 << 'DEMO_EOF'
# Demo 2: Fixed random seed produces predictable "random" bytes
import random

random.seed(12345)
key1 = bytes([random.randint(0, 255) for _ in range(32)])

random.seed(12345)
key2 = bytes([random.randint(0, 255) for _ in range(32)])

print(f"Key 1: {key1.hex()}")
print(f"Key 2: {key2.hex()}")
print(f"Keys identical: {key1 == key2}")
print("An attacker who knows you use seed=12345 generates the same key!")
DEMO_EOF
```

```bash
python3 << 'DEMO_EOF'
# Demo 3: JWT algorithm confusion attack
import base64, json

# Create a "token" with alg:none — bypasses HMAC verification entirely
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "attacker", "role": "admin", "user_id": 999}

h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()

# No signature needed with alg:none
forged_token = f"{h}.{p}."

print(f"Forged JWT (no signature): {forged_token}")
decoded_payload = json.loads(base64.urlsafe_b64decode(p + '=='))
print(f"Payload: {decoded_payload}")
print(f"Role in forged token: {decoded_payload['role']}")
print("If server accepts alg:none, this grants admin access without credentials!")
DEMO_EOF
```

### Task 3: Write Remediation Code

For the most critical vulnerabilities, provide corrected implementations.

### Task 4: Formal Audit Report

Write a 1-2 page audit report including:

* Executive Summary (non-technical, 1 paragraph)
* Technical Findings (use your vulnerability table)
* Risk Rating (aggregate severity)
* Remediation Priority (what to fix first)
* Timeline Recommendation

---

**Time limit:** 90 minutes

**Pass criteria:** Find ≥12 vulnerabilities correctly classified, provide at least 3 corrected implementations, complete audit report
