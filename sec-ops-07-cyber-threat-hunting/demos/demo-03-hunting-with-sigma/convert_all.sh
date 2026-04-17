#!/usr/bin/env bash
# convert_all.sh — Convert all Sigma rules in ./rules/ to multiple SIEM formats.
#
# Usage:
#   chmod +x convert_all.sh
#   ./convert_all.sh
#
# Prerequisites:
#   pip install sigma-cli
#   sigma-cli plugin install splunk
#   sigma-cli plugin install elasticsearch-eql
#   sigma-cli plugin install azure-monitor

set -euo pipefail

RULES_DIR="./rules"
OUTPUT_DIR="./converted"
BACKENDS=("splunk" "elasticsearch-eql" "azure-monitor")

mkdir -p "$OUTPUT_DIR"

echo "=== Sigma Rule Conversion ==="
echo "Date: $(date)"
echo ""

for backend in "${BACKENDS[@]}"; do
    echo "[*] Converting to backend: $backend"
    mkdir -p "$OUTPUT_DIR/$backend"

    for rule in "$RULES_DIR"/*.yml; do
        rulename=$(basename "$rule" .yml)
        outfile="$OUTPUT_DIR/$backend/${rulename}.txt"

        if sigma-cli convert \
               -t "$backend" \
               -p sysmon \
               "$rule" \
               > "$outfile" 2>/dev/null; then
            echo "  [✓] $rulename → ${backend}/${rulename}.txt"
        else
            echo "  [✗] Conversion failed: $rulename (backend: $backend)"
            rm -f "$outfile"
        fi
    done

    echo "    Done."
    echo ""
done

echo "=== Conversion complete ==="
echo ""
echo "Converted files:"
find "$OUTPUT_DIR" -name "*.txt" | sort
