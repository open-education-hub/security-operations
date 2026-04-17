#!/usr/bin/env bash
# sigma_pipeline.sh — Validate, convert, and generate a hunt playbook
#                     for all Sigma rules in ./rules/.
#
# Usage:
#   chmod +x sigma_pipeline.sh
#   ./sigma_pipeline.sh
#
# Prerequisites:
#   pip install sigma-cli
#   sigma-cli plugin install splunk
#   sigma-cli plugin install elasticsearch-eql
#   sigma-cli plugin install azure-monitor

set -euo pipefail

RULES="./rules"
OUTPUT="./hunting_queries"
mkdir -p "$OUTPUT"

echo "=== Sigma Threat Hunting Pipeline ==="
echo "Date: $(date)"
echo ""

# ── 1. Validate all rules ──────────────────────────────────────────────────
echo "[1/4] Validating rules..."
if sigma-cli check "$RULES"/*.yml; then
    echo "      All rules validated OK."
else
    echo "      [!] Some rules have validation warnings — review output above."
fi
echo ""

# ── 2. Convert to Splunk SPL ───────────────────────────────────────────────
echo "[2/4] Converting to Splunk SPL..."
for rule in "$RULES"/*.yml; do
    name=$(basename "$rule" .yml)
    out="$OUTPUT/splunk_${name}.spl"
    if sigma-cli convert -t splunk -p sysmon "$rule" > "$out" 2>/dev/null; then
        echo "  [✓] ${name}.yml → splunk_${name}.spl"
    else
        echo "  [✗] Failed: ${name}.yml"
        rm -f "$out"
    fi
done
echo ""

# ── 3. Convert to Elasticsearch EQL ───────────────────────────────────────
echo "[3/4] Converting to Elasticsearch EQL..."
for rule in "$RULES"/*.yml; do
    name=$(basename "$rule" .yml)
    out="$OUTPUT/elastic_${name}.eql"
    if sigma-cli convert -t elasticsearch-eql "$rule" > "$out" 2>/dev/null; then
        echo "  [✓] ${name}.yml → elastic_${name}.eql"
    else
        # EQL not supported for all rule types (e.g., registry events); skip quietly
        rm -f "$out"
    fi
done
echo ""

# ── 4. Generate hunt playbook ──────────────────────────────────────────────
echo "[4/4] Generating hunt playbook..."
PLAYBOOK="$OUTPUT/hunt_playbook.md"

{
    echo "# FIN-STORM Threat Hunt Playbook"
    echo "**Generated:** $(date)"
    echo ""
    echo "## Detection Rules"
    echo ""
} > "$PLAYBOOK"

for rule in "$RULES"/*.yml; do
    name=$(basename "$rule" .yml)
    title=$(grep "^title:" "$rule" | head -1 | cut -d':' -f2- | xargs)
    level=$(grep "^level:" "$rule" | head -1 | cut -d':' -f2 | xargs)
    spl_file="$OUTPUT/splunk_${name}.spl"

    {
        echo "### ${title} (Level: ${level})"
        echo ""
        echo "**Sigma rule:** \`rules/${name}.yml\`"
        echo ""
        echo "**Splunk Query:**"
        echo '```splunk'
        if [[ -f "$spl_file" ]]; then
            cat "$spl_file"
        else
            echo "# Conversion not available for this rule type in Splunk"
        fi
        echo '```'
        echo ""
    } >> "$PLAYBOOK"
done

echo ""
echo "=== Pipeline Complete ==="
echo ""
echo "Output files in: $OUTPUT/"
ls -lh "$OUTPUT/"
