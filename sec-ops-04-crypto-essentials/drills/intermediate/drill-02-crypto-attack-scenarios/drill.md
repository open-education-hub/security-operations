# Drill 02 (Intermediate): Cryptographic Attack Scenarios

> **Level:** Intermediate
> **Time:** 45–60 minutes
> **Tools:** Docker, Python, OpenSSL
> **Prerequisites:** Reading section 10 (Cryptographic Attacks)

---

## Overview

You are a security consultant reviewing five real-world scenarios.
Each scenario describes a system's cryptographic implementation.
Your job is to:

1. Identify the cryptographic vulnerability
1. Explain how an attacker could exploit it
1. Describe the correct fix

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl python3 xxd 2>/dev/null | tail -3
mkdir -p /drill && cd /drill
```

---

## Scenario 1: The Chat Application

A developer built a chat application with end-to-end encryption using AES-128-CTR mode.
After reviewing the code, you find:

```python
# chat_crypto.py (simplified)
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FIXED_KEY = b"MySuperSecretKey"  # 16 bytes = AES-128
FIXED_NONCE = b"\x00" * 16      # NEVER changes — same nonce always used!

def encrypt_message(plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(FIXED_KEY), modes.CTR(FIXED_NONCE))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
```

**Questions:**

1. What are the TWO critical vulnerabilities in this implementation?
1. Demonstrate the nonce reuse vulnerability:

```bash
python3 << 'EOF'
# Simulate the attack
KEY = b"MySuperSecretKey"
NONCE = b"\x00" * 16

# XOR helper
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Alice sends a message, Eve intercepts
msg_alice = b"Transfer $1000 to Bob's account"
# Attacker intercepts both ciphertexts
ciphertext_alice = xor_bytes(msg_alice, b"\x5a\x3f\x71" * (len(msg_alice) // 3 + 1))[:len(msg_alice)]

# Bob sends another message with SAME nonce+key (CTR reuse!)
msg_bob = b"CONFIDENTIAL: Password is P@ssw0rd"
ciphertext_bob = xor_bytes(msg_bob, b"\x5a\x3f\x71" * (len(msg_bob) // 3 + 1))[:len(msg_bob)]

# In real CTR mode attack: if attacker XORs two ciphertexts...
# C1 XOR C2 = (P1 XOR K) XOR (P2 XOR K) = P1 XOR P2
# The key cancels out! With knowledge of P1, attacker can find P2
xor_of_ciphertexts = xor_bytes(ciphertext_alice, ciphertext_bob[:len(ciphertext_alice)])
print("CTR Nonce Reuse Attack:")
print(f"If attacker knows P1='{msg_alice[:10]}...'")
print(f"Attacker can XOR C1⊕C2 to get P1⊕P2")
print(f"Then XOR with known P1 bits to get P2 bits")
print(f"This is why nonce MUST be unique for each message!")
EOF
```

1. What is the correct fix?

---

## Scenario 2: The Password Reset System

Review this password reset token generation:

```python
# password_reset.py (simplified)
import hashlib, time

def generate_reset_token(user_email: str) -> str:
    """Generate a password reset token"""
    timestamp = int(time.time())
    token = hashlib.md5(f"{user_email}{timestamp}".encode()).hexdigest()
    return token

def verify_token(email: str, token: str, max_age_seconds: int = 3600) -> bool:
    """Verify a password reset token"""
    current_time = int(time.time())
    # Try timestamps in the past hour
    for t in range(current_time - max_age_seconds, current_time + 1):
        expected = hashlib.md5(f"{email}{t}".encode()).hexdigest()
        if expected == token:
            return True
    return False
```

**Questions:**

1. List ALL vulnerabilities in this implementation (there are at least 3).
1. Demonstrate the timing attack:

```bash
python3 << 'EOF'
import hashlib, time

# Simulate brute-forcing a token for a known user
target_email = "ceo@company.com"
# Assume we know token was generated approximately 5 minutes ago
now = int(time.time())

print("Brute-forcing reset token...")
start = time.time()
found = False

# In a real attack, attacker knows approximate generation time
# and just tries all timestamps in that window
for t in range(now - 300, now + 1):
    token = hashlib.md5(f"{target_email}{t}".encode()).hexdigest()
    # In a real attack: try submitting this token to the reset API

elapsed = time.time() - start
print(f"Tried {301} timestamps in {elapsed:.3f} seconds")
print(f"An attacker could brute-force all tokens in the last HOUR in ~{301/elapsed * 3600:.0f} tokens/second")
print(f"That's 3600 tokens — trivially fast!")
EOF
```

1. What is the correct fix?

---

## Scenario 3: The API Authentication

An API uses HMAC-SHA256 for request authentication:

```python
# api_auth.py (simplified)
import hmac, hashlib

SECRET_KEY = "shared_api_secret"

def verify_request(body: str, provided_hmac: str) -> bool:
    """Verify HMAC on incoming API request"""
    expected_hmac = hmac.new(
        SECRET_KEY.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()

    # BUG: using == for comparison
    return expected_hmac == provided_hmac
```

**Questions:**

1. What vulnerability exists in the `verify_request` function?
1. Demonstrate the timing side-channel:

```bash
python3 << 'EOF'
import time

def insecure_compare(a: str, b: str) -> bool:
    """Insecure: exits early on first mismatch"""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True

def secure_compare(a: str, b: str) -> bool:
    """Secure: always compares all bytes"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

correct_hmac = "a" * 64  # 64 hex chars for SHA-256

# Time the comparison at different positions
def time_comparison(func, prefix_correct_chars: int, iterations: int = 100000):
    guess = "a" * prefix_correct_chars + "b" * (64 - prefix_correct_chars)
    start = time.perf_counter()
    for _ in range(iterations):
        func(correct_hmac, guess)
    return time.perf_counter() - start

print("Timing attack on string comparison:")
print("(Insecure == exits early; more correct prefix = slightly more time)")
for prefix in [0, 32, 63, 64]:
    t = time_comparison(insecure_compare, prefix)
    print(f"  {prefix:>2} correct chars: {t*1000:.2f}ms for 100k comparisons")

print()
print("Secure comparison (constant time):")
for prefix in [0, 32, 63, 64]:
    t = time_comparison(secure_compare, prefix)
    print(f"  {prefix:>2} correct chars: {t*1000:.2f}ms for 100k comparisons")
EOF
```

1. What is the correct fix? Provide the corrected code.

---

## Scenario 4: The Encrypted Database

A healthcare application stores patient data:

```python
# db_encrypt.py (simplified)
from Crypto.Cipher import AES

KEY = b"DatabaseSecretKey12345678901234"  # 31 bytes? (bug: should be 16/24/32)
KEY = KEY[:32]  # Padded/truncated to 32 bytes

def encrypt_patient_record(ssn: str, diagnosis: str) -> bytes:
    """Encrypt patient data"""
    # BUG: Encrypts SSN and diagnosis SEPARATELY with same key and NO IV
    cipher = AES.new(KEY, AES.MODE_ECB)  # ECB mode!

    padded_ssn = ssn.ljust(16)[:16].encode()
    encrypted_ssn = cipher.encrypt(padded_ssn)
    return encrypted_ssn
```

**Questions:**

1. What are the vulnerabilities? (At least 3)
1. Run this demonstration of ECB mode leaking patterns:

```bash
python3 << 'EOF'
import hashlib

# Simulate ECB behavior: same input → same output (even without a key)
# We'll use a simple XOR cipher for illustration
def bad_ecb_cipher(block: bytes, key: int = 42) -> bytes:
    return bytes(b ^ key for b in block)

# Two patients with same SSN get identical encrypted records
ssns = ["123-45-6789", "123-45-6789", "987-65-4321"]

print("ECB mode — same plaintext → same ciphertext:")
print()
for ssn in ssns:
    padded = ssn.ljust(16)[:16].encode()
    encrypted = bad_ecb_cipher(padded).hex()
    print(f"  SSN '{ssn}' → encrypted: {encrypted}")

print()
print("An attacker can see which patients share the same SSN")
print("even WITHOUT knowing the key!")
print()
print("Correct fix: AES-256-GCM with unique per-record nonce")
EOF
```

1. Provide a corrected implementation outline.

---

## Scenario 5: The VPN Configuration

Audit report from a corporate VPN:

```text
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
```

**Questions:**

1. List every cryptographic weakness in this VPN configuration (there are at least 7).
1. For each weakness, state:
   * The specific problem
   * The actual risk
   * The correct replacement
1. Write an "Executive Finding" summary (3-5 sentences, non-technical) explaining the business risk.

---

**Time limit:** 60 minutes

**Pass criteria:** Identify all major vulnerabilities in each scenario with correct explanations and fixes
