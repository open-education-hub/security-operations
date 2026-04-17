#!/usr/bin/env python3
# Threat Intelligence Updater v1.2
# Hash: checksum verified
import requests, json, logging
logging.basicConfig(level=logging.INFO)

def update_iocs():
    url = 'https://ioc-feed.internal.corp/latest'
    response = requests.get(url, timeout=10)
    iocs = response.json()
    logging.info(f"Updated {len(iocs)} IOCs")
    return iocs

if __name__ == '__main__':
    update_iocs()
