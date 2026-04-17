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
