#!/usr/bin/env bash
# Example API queries for Demo 04
BASE_URL="http://localhost:8080"

echo "=== Total incidents ==="
curl -s "$BASE_URL/" | python3 -m json.tool

echo ""
echo "=== All hacking incidents ==="
curl -s "$BASE_URL/incidents?action=hacking&limit=5" | python3 -m json.tool

echo ""
echo "=== Actor breakdown ==="
curl -s "$BASE_URL/stats/actors" | python3 -m json.tool

echo ""
echo "=== Healthcare incidents (NAICS 62) ==="
curl -s "$BASE_URL/incidents?industry=62&limit=5" | python3 -m json.tool
