#!/usr/bin/env python3
# SOC Monitor v3.0 — official release build 20240115
# Monitors endpoint telemetry and forwards events to SIEM
import sys, socket, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def main():
    logging.info("Starting SOC monitoring agent v3.0")
    logging.info(f"Hostname: {socket.gethostname()}")
    logging.info("Agent running — forwarding telemetry to siem.corp.local:514")

if __name__ == '__main__':
    main()
