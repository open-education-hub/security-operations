# Solution: Drill 02 (Intermediate) — Cryptographic Attack Scenarios

---

## Scenario 1: The Chat Application

### Vulnerabilities

1. **Fixed/hardcoded key** — `FIXED_KEY = b"MySuperSecretKey"` is hardcoded in source code. Anyone with access to the source code (repository, decompiled binary) has the key and can decrypt all past and future messages.

1. **Nonce reuse with CTR mode** — `FIXED_NONCE = b"\x00" * 16` never changes. In CTR mode, the keystream `K = AES(key, nonce || counter)` is the same every time. Two ciphertexts encrypted with the same key+nonce allows:

   * `C1 = P1 XOR K` and `C2 = P2 XOR K`
   * `C1 XOR C2 = P1 XOR P2` (the key cancels!)
   * If attacker knows P1 or part of P1, they can recover P2

### Correct Fix

```python
import os, secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureChat:
    def __init__(self, key: bytes = None):
        # Never hardcode keys; load from secure key management
        self.key = key or AESGCM.generate_key(bit_length=256)

    def encrypt_message(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        # AES-GCM: nonce MUST be unique (random 96-bit)
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext  # prepend nonce for decryption

    def decrypt_message(self, data: bytes, associated_data: bytes = b"") -> bytes:
        nonce, ciphertext = data[:12], data[12:]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
        # GCM also authenticates — raises InvalidTag if tampered
```

---

## Scenario 2: The Password Reset System

### Vulnerabilities

1. **Predictable token** — Token is entirely deterministic from known inputs (email + timestamp). With a known user's email, an attacker can brute-force all possible timestamps in the validity window (~3600 attempts for 1-hour window — trivially fast).

1. **MD5 for token hashing** — MD5 is broken and extremely fast (billions/second on GPU). Even if randomness were added, MD5 should never be used for security tokens.

1. **No HMAC secret** — The token isn't signed with a secret. Anyone who knows the email can compute valid tokens.

1. **Timing leak in verify** — The loop exits early when found, leaking information about token validity window.

### Correct Fix

```python
import secrets, hmac, hashlib, time

SECRET_KEY = os.environ['RESET_TOKEN_SECRET']  # loaded from secure config

def generate_reset_token(user_email: str) -> str:
    """Generate a cryptographically secure reset token"""
    # Use secrets.token_urlsafe() — 32 bytes = 256 bits of randomness
    token = secrets.token_urlsafe(32)
    # Sign it with HMAC to prevent forgery
    mac = hmac.new(SECRET_KEY.encode(), f"{user_email}:{token}".encode(), hashlib.sha256).hexdigest()
    # Store (token_hash, expiry, user_email) in database
    # Return token to user — NOT stored directly (store only hash)
    return f"{token}.{mac[:16]}"

def verify_token(email: str, token: str) -> bool:
    """Verify using constant-time comparison"""
    # Look up token hash in database with expiry check
    # Use hmac.compare_digest() — constant-time comparison
    # Never brute-force timestamps
    pass  # implementation depends on your database schema
```

---

## Scenario 3: The API Authentication

### Vulnerability

**Timing side-channel attack on string comparison.**

The `==` operator in Python (and most languages) compares strings character by character and **returns False as soon as it finds the first mismatch**.
This means:

* A guess that shares 0 characters with the correct HMAC: comparison returns very quickly
* A guess that shares 60/64 characters: comparison takes slightly longer
* An attacker making thousands of requests and measuring response time can gradually discover the correct HMAC character by character

This attack is difficult but possible against authentication systems that:

* Allow many rapid requests
* Have a consistent, low-latency response
* Use a predictable string comparison

### Correct Fix

```python
import hmac, hashlib

def verify_request(body: str, provided_hmac: str) -> bool:
    expected_hmac = hmac.new(
        SECRET_KEY.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()

    # CORRECT: use hmac.compare_digest() — constant-time comparison
    return hmac.compare_digest(expected_hmac, provided_hmac)

    # OR in Python 3.7+:
    # import secrets
    # return secrets.compare_digest(expected_hmac, provided_hmac)
```

`hmac.compare_digest` always takes the same amount of time regardless of where the first mismatch occurs, preventing timing attacks.

---

## Scenario 4: The Encrypted Database

### Vulnerabilities

1. **AES-ECB mode** — ECB encrypts each 16-byte block independently. Two patients with the same SSN (or same 16-byte data) produce the same ciphertext. An attacker with access to the encrypted database can:
   * Identify patients with the same SSN
   * Perform statistical analysis to correlate records
   * Potentially replay blocks

1. **No IV/nonce** — Without an IV, the encryption is deterministic. Same input always → same output.

1. **No authentication** — An attacker who can modify the database can flip bytes in the ciphertext without detection.

1. **Hardcoded key** — Key is embedded in source code (same problem as Scenario 1).

1. **Key size confusion** — Comment says "31 bytes" but code truncates to 32. Code comments that contradict reality indicate low-quality code review.

### Correct Implementation Outline

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecurePatientDB:
    def __init__(self):
        self.key = self._load_key_from_hsm()  # or secrets manager

    def encrypt_patient_record(self, patient_id: str, ssn: str, diagnosis: str) -> dict:
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # unique per record

        # Include patient_id as authenticated associated data (not encrypted but authenticated)
        plaintext = json.dumps({"ssn": ssn, "diagnosis": diagnosis}).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, patient_id.encode())

        return {
            "patient_id": patient_id,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
            # Store nonce with ciphertext; nonce doesn't need to be secret
        }
```

---

## Scenario 5: The VPN Configuration

### Weaknesses (7+ found)

| # | Setting | Problem | Risk | Fix |
|---|---------|---------|------|-----|
| 1 | **3DES-168** (Phase 1) | 3DES deprecated 2019, NIST-disallowed 2023. Slow. Sweet32 attack | Potential decryption of sessions | AES-256 |
| 2 | **SHA-1** (Phase 1 integrity) | Collision attacks demonstrated (SHAttered 2017) | Forged authentication data | SHA-256 |
| 3 | **DH Group 1 (768-bit)** | 768-bit MODP is trivially factorable; nation-state broke it in 2015 | Session keys can be recovered | DH Group 20 (384-bit ECC) or Group 14 (2048-bit) minimum |
| 4 | **3DES** (Phase 2 ESP) | Same as above | Encrypted traffic may be decryptable | AES-256-GCM |
| 5 | **MD5-96** (Phase 2 integrity) | MD5 is broken | Attacker can forge integrity checks | SHA-256 |
| 6 | **PFS Disabled** | Without Perfect Forward Secrecy, compromising the long-term key decrypts ALL past sessions | One key compromise = all historical traffic exposed | Enable PFS (DH/ECDH key exchange per session) |
| 7 | **SHA-1 with RSA-1024 certificate** | RSA-1024 is factored in days on academic hardware; SHA-1 deprecated | Certificate forged or impersonated | RSA-4096 or ECC P-256 with SHA-256 |
| 8 | **EXPIRED CERTIFICATE (2019!)** | Certificate expired 5+ years ago | VPN should refuse connections; if accepting expired certs, authentication is bypassed | Replace immediately |

### Executive Finding Summary

The corporate VPN uses cryptographic algorithms that were deprecated or broken years ago, creating a high risk of complete session compromise.
The combination of 768-bit Diffie-Hellman key exchange (which nation-state actors can break in real time) and 3DES encryption (vulnerable to sweet32 attacks) means an attacker recording VPN traffic today could decrypt it.
Additionally, the VPN certificate expired in 2019, indicating the system has not been properly maintained.
This effectively renders the VPN's security guarantees void and puts all data transmitted over VPN at risk.
Immediate remediation is required to upgrade to AES-256-GCM, modern DH groups, and a valid certificate.
