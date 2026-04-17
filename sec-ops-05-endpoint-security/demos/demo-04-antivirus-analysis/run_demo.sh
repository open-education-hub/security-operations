#!/bin/bash
# run_demo.sh — ClamAV Demo orchestrator

set -e

echo "========================================"
echo "  Demo 04: Antivirus Analysis — ClamAV"
echo "========================================"
echo ""

# Update ClamAV signatures (may take a while on first run)
echo "[*] Updating ClamAV signature databases..."
if freshclam --quiet 2>/dev/null; then
    echo "[+] Signatures updated successfully"
else
    echo "[!] Signature update skipped (offline or rate limited) — using existing DB"
fi
echo ""

echo "========================================"
echo "  STEP 1: Standard ClamAV Scan"
echo "========================================"
echo ""
echo "[*] Scanning /scan_targets/ with default signatures..."
echo ""
clamscan -r -v /scan_targets/ 2>/dev/null || true
echo ""

echo "========================================"
echo "  STEP 2: YARA Custom Rules Scan"
echo "========================================"
echo ""
echo "[*] Scanning with YARA rules: /app/custom_rules.yara"
echo ""
# Use yara directly for YARA rule scanning
if command -v yara >/dev/null 2>&1; then
    yara -r /app/custom_rules.yara /scan_targets/ 2>/dev/null && echo "" || echo "[i] Some files had no YARA matches (expected)"
else
    echo "[!] yara command not found — try: apt install yara"
fi
echo ""

echo "========================================"
echo "  STEP 3: Analysis Summary"
echo "========================================"
cat << 'EOF'

File Results:
  eicar.com           → DETECTED by ClamAV standard signatures (Win.Test.EICAR_HDB-1)
  malicious_macro.vba → DETECTED by YARA (Suspicious_Office_Macro) — MISSED by AV
  lolbin_abuse.bat    → DETECTED by YARA (LOLBin_CertUtil_Download) — MISSED by AV
  encoded_payload.b64 → Partial YARA match — MISSED by AV signatures
  benign_script.ps1   → Clean (no detections)

Key Observations:
  1. AV catches known-bad signatures but misses novel/obfuscated content
  2. Custom YARA rules add targeted detection for observed attack patterns
  3. Fileless attacks (in-memory PowerShell) have no file for AV to scan
  4. LOLBins are legitimate tools — AV cannot tell good from bad usage
  5. Combined AV + YARA + EDR = defense-in-depth

Next Steps for a Real Environment:
  - Deploy ClamAV on mail/file servers to catch commodity threats
  - Add custom YARA rules based on your threat intelligence
  - Layer with EDR for behavioral detection of what AV misses
  - Use VirusTotal API to cross-check suspicious files
EOF
echo ""
echo "[+] Demo complete."
