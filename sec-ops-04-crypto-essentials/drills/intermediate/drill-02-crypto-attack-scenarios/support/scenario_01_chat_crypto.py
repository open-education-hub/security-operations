#!/usr/bin/env python3
"""
Scenario 1: Chat Application with AES-CTR Nonce Reuse
======================================================
This code implements message encryption with a critical vulnerability:
the CTR nonce is FIXED (never changes), which allows keystream recovery.

Run this file to see the nonce-reuse attack demonstrated.
"""

# ── Vulnerable implementation ─────────────────────────────────────────────────
FIXED_KEY   = b"MySuperSecretKey"   # 16 bytes = AES-128
FIXED_NONCE = b"\x00" * 16         # NEVER changes — same nonce always used!


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_message_vulnerable(plaintext: bytes, keystream: bytes) -> bytes:
    """Simulates AES-CTR with a fixed nonce — XOR with a fixed keystream."""
    # In real CTR mode: keystream = AES(key, nonce || counter)
    # If nonce never changes, the keystream is always identical
    return xor_bytes(plaintext, keystream[:len(plaintext)])


if __name__ == "__main__":
    # Simulate a fixed keystream (as if from AES-CTR with a fixed nonce)
    import hashlib
    keystream = hashlib.sha256(FIXED_KEY + FIXED_NONCE).digest() * 4  # fake keystream

    print("=" * 60)
    print("CTR Nonce-Reuse Attack Demonstration")
    print("=" * 60)
    print()

    # Victim messages
    msg_alice = b"Transfer $1000 to Bob's account"
    msg_bob   = b"CONFIDENTIAL: Password is P@ssw0rd"

    c_alice = encrypt_message_vulnerable(msg_alice, keystream)
    c_bob   = encrypt_message_vulnerable(msg_bob,   keystream)

    print(f"Alice's ciphertext (hex): {c_alice.hex()}")
    print(f"Bob's   ciphertext (hex): {c_bob.hex()}")
    print()

    # Attack: XOR two ciphertexts → P1 XOR P2 (key cancels out)
    min_len = min(len(c_alice), len(c_bob))
    xor_ct = xor_bytes(c_alice[:min_len], c_bob[:min_len])
    print("C_alice XOR C_bob =", xor_ct.hex())
    print()

    # If attacker knows part of P1, they can extract P2
    known_prefix_alice = msg_alice[:15]
    recovered_prefix_bob = xor_bytes(xor_ct[:15], known_prefix_alice)
    print(f"Attacker knows first 15 bytes of Alice's plaintext: {known_prefix_alice}")
    print(f"Attacker recovers first 15 bytes of Bob's message:  {recovered_prefix_bob}")
    print()
    print("VULNERABILITY: Nonce reuse in CTR/stream mode leaks XOR of plaintexts.")
    print()
    print("QUESTIONS:")
    print("  1. What are the two critical vulnerabilities in this implementation?")
    print("  2. What is the correct fix?")
