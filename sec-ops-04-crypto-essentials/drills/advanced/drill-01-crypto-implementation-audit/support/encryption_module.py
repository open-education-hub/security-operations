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
