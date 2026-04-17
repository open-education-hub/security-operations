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
