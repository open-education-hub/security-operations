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
