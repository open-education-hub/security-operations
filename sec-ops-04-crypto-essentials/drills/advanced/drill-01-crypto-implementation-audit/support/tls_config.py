#!/usr/bin/env python3
"""
tls_config.py — TLS Configuration
===================================
Configures SSL contexts for server and client connections.

AUDIT TASK: Find all cryptographic vulnerabilities and classify by severity.
"""
import ssl
import hashlib


def create_ssl_context_server() -> ssl.SSLContext:
    """Create SSL context for the API server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # NOTE: In a real audit you would load an actual cert:
    # ctx.load_cert_chain('server.crt', 'server.key')

    # FINDING #12: TLS 1.0 and 1.1 are not explicitly disabled
    ctx.options |= ssl.OP_NO_SSLv2   # disables SSL 2.0 only

    # FINDING #13: Weak cipher suites allowed
    ctx.set_ciphers('ALL:!aNULL')    # allows RC4, DES, 3DES, export ciphers

    # FINDING #14: Client certificate verification disabled
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


def create_ssl_context_client() -> ssl.SSLContext:
    """Create SSL context for outbound connections."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # FINDING #15: Certificate verification completely disabled — MITM risk
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


def verify_certificate_pinning(cert_der: bytes, expected_fp: str) -> bool:
    """Certificate pinning check."""
    # FINDING #16: MD5 used for certificate fingerprinting (not SHA-256)
    actual_fp = hashlib.md5(cert_der).hexdigest()
    return actual_fp == expected_fp   # FINDING #17: non-constant-time comparison


# ── Demo ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("TLS Config Module — Vulnerability Analysis")
    print("=" * 50)

    print("\n[FINDING #15] Client SSL context disables certificate verification:")
    ctx = create_ssl_context_client()
    print(f"  check_hostname: {ctx.check_hostname}  (should be True)")
    print(f"  verify_mode:    {ctx.verify_mode}     (should be ssl.CERT_REQUIRED = 2)")
    print("  Effect: any TLS certificate is accepted → trivial MITM attack")

    print("\n[FINDING #16] MD5 used for certificate pinning:")
    fake_cert = b"example certificate DER bytes"
    md5_fp  = hashlib.md5(fake_cert).hexdigest()
    sha256_fp = hashlib.sha256(fake_cert).hexdigest()
    print(f"  MD5    fingerprint: {md5_fp}  (32 hex = 128 bits, weak)")
    print(f"  SHA256 fingerprint: {sha256_fp}  (64 hex = 256 bits, correct)")
