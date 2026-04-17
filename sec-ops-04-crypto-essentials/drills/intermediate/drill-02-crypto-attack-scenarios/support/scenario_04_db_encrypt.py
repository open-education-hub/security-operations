#!/usr/bin/env python3
"""
Scenario 4: Healthcare Database Using AES-ECB Mode
===================================================
ECB mode produces identical ciphertext for identical plaintext blocks,
allowing an attacker to detect duplicate records even without the key.

Run this file to see the ECB pattern leak.
NOTE: Uses a simple XOR simulation since pycryptodome may not be available.
"""


def ecb_simulate(block: bytes, key: int = 42) -> bytes:
    """Simulates ECB determinism: same input → same output (using XOR for demo)."""
    return bytes(b ^ key for b in block)


def bad_encrypt_ssn(ssn: str, key: int = 42) -> str:
    padded = ssn.ljust(16)[:16].encode()
    return ecb_simulate(padded, key).hex()


if __name__ == "__main__":
    print("=" * 60)
    print("ECB Mode — Pattern Leakage Demonstration")
    print("=" * 60)
    print()

    patient_records = [
        ("Alice",   "123-45-6789", "Hypertension"),
        ("Bob",     "123-45-6789", "Diabetes"),       # same SSN as Alice
        ("Carol",   "987-65-4321", "Asthma"),
        ("David",   "456-78-9012", "Arthritis"),
        ("Eve",     "123-45-6789", "Anxiety"),          # same SSN again
    ]

    print(f"{'Patient':<10} {'SSN':<15} {'Encrypted SSN'}")
    print("-" * 55)
    for name, ssn, _ in patient_records:
        enc = bad_encrypt_ssn(ssn)
        print(f"{name:<10} {ssn:<15} {enc}")

    print()
    print("An attacker with no key can see that Alice, Bob, and Eve share an SSN.")
    print("In real ECB-AES, identical 16-byte blocks produce identical ciphertext.")
    print()
    print("VULNERABILITIES (find at least 3):")
    print("  1. AES-ECB — identical plaintext blocks → identical ciphertext blocks")
    print("  2. ???")
    print("  3. ???")
    print()
    print("QUESTION: Provide a corrected implementation outline (use AES-256-GCM).")
