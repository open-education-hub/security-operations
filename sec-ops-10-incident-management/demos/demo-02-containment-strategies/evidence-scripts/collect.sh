#!/bin/bash
# Volatile evidence collection script
EVID_DIR="/evidence/EVID-001"
mkdir -p "$EVID_DIR"
DATE=$(date -u +"%Y%m%dT%H%M%SZ")

echo "=== Evidence Collection: $DATE ===" | tee "$EVID_DIR/collection.log"

echo "[+] Network connections" | tee -a "$EVID_DIR/collection.log"
netstat -anp > "$EVID_DIR/network_connections.txt" 2>/dev/null || ss -anp > "$EVID_DIR/network_connections.txt"

echo "[+] Running processes" | tee -a "$EVID_DIR/collection.log"
ps auxf > "$EVID_DIR/processes.txt"

echo "[+] Open files" | tee -a "$EVID_DIR/collection.log"
lsof -n > "$EVID_DIR/open_files.txt" 2>/dev/null

echo "[+] ARP table" | tee -a "$EVID_DIR/collection.log"
arp -n > "$EVID_DIR/arp_table.txt" 2>/dev/null

echo "[+] Routing table" | tee -a "$EVID_DIR/collection.log"
ip route > "$EVID_DIR/routing_table.txt" 2>/dev/null

echo "[+] Environment" | tee -a "$EVID_DIR/collection.log"
env > "$EVID_DIR/environment.txt"

echo "[+] Hash collection complete" | tee -a "$EVID_DIR/collection.log"
sha256sum "$EVID_DIR"/*.txt > "$EVID_DIR/EVIDENCE_HASHES.sha256"

echo "Evidence collected to $EVID_DIR"
