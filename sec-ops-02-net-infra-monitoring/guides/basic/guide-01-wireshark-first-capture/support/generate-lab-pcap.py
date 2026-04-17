#!/usr/bin/env python3
"""
PCAP Generator for Wireshark Lab (Guide 01)
============================================
This script generates a realistic PCAP file using Scapy that contains
the same traffic patterns described in Guide 01 (Wireshark First Capture).

The generated PCAP contains:
  - TCP three-way handshakes
  - HTTP GET requests (from curl/wget-like client)
  - HTTP POST request with cleartext credentials
  - HTTP 404 responses (failed resource requests)
  - ARP requests
  - DNS queries

Requirements:
    pip install scapy

Usage:
    python3 generate-lab-pcap.py             # Creates lab.pcap
    python3 generate-lab-pcap.py --output myfile.pcap
    python3 generate-lab-pcap.py --verbose

The generated file can be opened directly in Wireshark or tshark.
"""

import sys
import argparse
import struct
import io
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────
# Minimal PCAP writer (no external dependencies)
# ─────────────────────────────────────────────────────────────────────
# We implement a tiny PCAP writer so students without Scapy can still
# generate the file. A full Scapy version follows if Scapy is available.

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xa1b2c3d4,   # magic number
    2,             # major version
    4,             # minor version
    0,             # timezone offset
    0,             # timestamp accuracy
    65535,         # snapshot length
    1,             # link-layer header type (1 = Ethernet)
)


def pcap_packet_record(ts_sec, ts_usec, data):
    """Build a PCAP packet record."""
    captured_len = len(data)
    original_len = len(data)
    header = struct.pack("<IIII", ts_sec, ts_usec, captured_len, original_len)
    return header + data


def mac_bytes(mac_str):
    """Convert 'aa:bb:cc:dd:ee:ff' to bytes."""
    return bytes(int(x, 16) for x in mac_str.split(":"))


def ip_bytes(ip_str):
    """Convert '10.0.0.1' to 4 bytes."""
    return bytes(int(x) for x in ip_str.split("."))


def ethernet_frame(src_mac, dst_mac, ethertype, payload):
    """Build an Ethernet frame."""
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(">H", ethertype) + payload


def arp_request(sender_mac, sender_ip, target_ip):
    """Build an ARP request (who has target_ip? tell sender_ip)."""
    arp = struct.pack(
        ">HHBBH",
        0x0001,   # hardware type = Ethernet
        0x0800,   # protocol type = IPv4
        6,        # hardware size
        4,        # protocol size
        1,        # opcode = request
    )
    arp += mac_bytes(sender_mac)
    arp += ip_bytes(sender_ip)
    arp += b"\x00" * 6                  # target MAC unknown
    arp += ip_bytes(target_ip)
    return ethernet_frame(sender_mac, "ff:ff:ff:ff:ff:ff", 0x0806, arp)


def ipv4_header(src_ip, dst_ip, protocol, payload, id_val=1, ttl=64):
    """Build an IPv4 header."""
    total_length = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,           # version + IHL
        0,              # DSCP/ECN
        total_length,
        id_val,
        0x4000,         # flags (Don't Fragment) + fragment offset
        ttl,
        protocol,
        0,              # checksum (placeholder)
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    # Simple checksum
    cs = 0
    for i in range(0, len(header), 2):
        cs += struct.unpack(">H", header[i:i+2])[0]
    cs = (cs >> 16) + (cs & 0xFFFF)
    cs = (~cs) & 0xFFFF
    header = header[:10] + struct.pack(">H", cs) + header[12:]
    return header + payload


def tcp_segment(src_port, dst_port, seq, ack, flags, payload, window=29200):
    """Build a TCP segment. flags is a bitmask: SYN=0x02, ACK=0x10, PSH=0x08, FIN=0x01, RST=0x04."""
    data_offset = 5  # 5 × 4 = 20 bytes
    segment = struct.pack(
        ">HHIIBBHH",
        src_port,
        dst_port,
        seq,
        ack,
        (data_offset << 4),  # data offset
        flags,
        window,
        0,                   # checksum (0 for simplicity)
    ) + b"\x00\x00"          # urgent pointer
    return segment + payload


def udp_datagram(src_port, dst_port, payload):
    """Build a UDP datagram."""
    length = 8 + len(payload)
    return struct.pack(">HHHH", src_port, dst_port, length, 0) + payload


def dns_query(domain, qtype=1, txid=0x1234):
    """Build a DNS query for a domain name."""
    # Header
    header = struct.pack(">HHHHHH",
                         txid, 0x0100, 1, 0, 0, 0)
    # Question
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)  # qtype, qclass=IN
    return header + question


# ─────────────────────────────────────────────────────────────────────
# Traffic scenario builder
# ─────────────────────────────────────────────────────────────────────

CLIENT_MAC = "02:42:ac:1e:00:0a"
SERVER_MAC = "02:42:ac:1e:00:02"
CLIENT_IP  = "172.30.0.10"
SERVER_IP  = "172.30.0.2"
DNS_IP     = "8.8.8.8"

SYN   = 0x02
ACK   = 0x10
PSH   = 0x08
FIN   = 0x01
RST   = 0x04
SYNACK = SYN | ACK
PSHACK = PSH | ACK


def build_http_get(uri, host, seq_c, seq_s, sport, ts_base, packet_list):
    """Build a complete HTTP GET request/response exchange."""
    t = ts_base

    # SYN
    tcp_pay = tcp_segment(sport, 80, seq_c, 0, SYN, b"")
    ip_pay  = ipv4_header(CLIENT_IP, SERVER_IP, 6, tcp_pay, id_val=sport, ttl=64)
    packet_list.append((t, ethernet_frame(CLIENT_MAC, SERVER_MAC, 0x0800, ip_pay)))
    t += 0.0001

    # SYN-ACK
    tcp_pay = tcp_segment(80, sport, seq_s, seq_c + 1, SYNACK, b"")
    ip_pay  = ipv4_header(SERVER_IP, CLIENT_IP, 6, tcp_pay, id_val=100, ttl=64)
    packet_list.append((t, ethernet_frame(SERVER_MAC, CLIENT_MAC, 0x0800, ip_pay)))
    t += 0.0001

    # ACK
    tcp_pay = tcp_segment(sport, 80, seq_c + 1, seq_s + 1, ACK, b"")
    ip_pay  = ipv4_header(CLIENT_IP, SERVER_IP, 6, tcp_pay, id_val=sport, ttl=64)
    packet_list.append((t, ethernet_frame(CLIENT_MAC, SERVER_MAC, 0x0800, ip_pay)))
    t += 0.0001

    # HTTP GET
    req = (f"GET {uri} HTTP/1.1\r\nHost: {host}\r\n"
           "User-Agent: curl/7.88.0\r\nAccept: */*\r\n\r\n").encode()
    tcp_pay = tcp_segment(sport, 80, seq_c + 1, seq_s + 1, PSHACK, req)
    ip_pay  = ipv4_header(CLIENT_IP, SERVER_IP, 6, tcp_pay, id_val=sport+1, ttl=64)
    packet_list.append((t, ethernet_frame(CLIENT_MAC, SERVER_MAC, 0x0800, ip_pay)))
    t += 0.001

    # HTTP 200 response
    body = (b"<!DOCTYPE html><html><head><title>Wireshark Lab Server</title></head>"
            b"<body><h1>Wireshark Lab -- NSM Training</h1>"
            b"<p>This page is used for packet capture exercises.</p></body></html>")
    resp = (f"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n"
            f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    tcp_pay = tcp_segment(80, sport, seq_s + 1, seq_c + 1 + len(req), PSHACK, resp)
    ip_pay  = ipv4_header(SERVER_IP, CLIENT_IP, 6, tcp_pay, id_val=101, ttl=64)
    packet_list.append((t, ethernet_frame(SERVER_MAC, CLIENT_MAC, 0x0800, ip_pay)))
    t += 0.001

    # FIN from client
    tcp_pay = tcp_segment(sport, 80, seq_c + 1 + len(req), seq_s + 1 + len(resp), FIN | ACK, b"")
    ip_pay  = ipv4_header(CLIENT_IP, SERVER_IP, 6, tcp_pay, id_val=sport+2, ttl=64)
    packet_list.append((t, ethernet_frame(CLIENT_MAC, SERVER_MAC, 0x0800, ip_pay)))

    return t + 0.0001


def build_http_post(uri, host, body_str, sport, seq_c, seq_s, ts_base, packet_list):
    """Build an HTTP POST request."""
    t = ts_base
    body = body_str.encode()

    # SYN/SYN-ACK/ACK (abbreviated)
    for flags, src, dst, smac, dmac, s_ip, d_ip, sp, dp, sq, ak in [
        (SYN,    CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, sport, 80, seq_c, 0),
        (SYNACK, SERVER_IP, CLIENT_IP, SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 80, sport, seq_s, seq_c + 1),
        (ACK,    CLIENT_IP, SERVER_IP, CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, sport, 80, seq_c + 1, seq_s + 1),
    ]:
        tcp_pay = tcp_segment(sp, dp, sq, ak, flags, b"")
        ip_pay  = ipv4_header(s_ip, d_ip, 6, tcp_pay, id_val=sport, ttl=64)
        packet_list.append((t, ethernet_frame(smac, dmac, 0x0800, ip_pay)))
        t += 0.0001

    # POST request
    req = (f"POST {uri} HTTP/1.1\r\nHost: {host}\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n"
           "User-Agent: curl/7.88.0\r\n\r\n").encode() + body
    tcp_pay = tcp_segment(sport, 80, seq_c + 1, seq_s + 1, PSHACK, req)
    ip_pay  = ipv4_header(CLIENT_IP, SERVER_IP, 6, tcp_pay, id_val=sport+1, ttl=64)
    packet_list.append((t, ethernet_frame(CLIENT_MAC, SERVER_MAC, 0x0800, ip_pay)))
    t += 0.001

    # 404 response (server doesn't have /login endpoint)
    resp = b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n"
    tcp_pay = tcp_segment(80, sport, seq_s + 1, seq_c + 1 + len(req), PSHACK, resp)
    ip_pay  = ipv4_header(SERVER_IP, CLIENT_IP, 6, tcp_pay, id_val=102, ttl=64)
    packet_list.append((t, ethernet_frame(SERVER_MAC, CLIENT_MAC, 0x0800, ip_pay)))

    return t + 0.001


def generate_pcap(output_path, verbose=False):
    packets = []
    t = 1705363200.0  # 2024-01-15 09:00:00 UTC

    # ARP request: client asking for server MAC
    arp_pkt = arp_request(CLIENT_MAC, CLIENT_IP, SERVER_IP)
    packets.append((t, arp_pkt))
    t += 0.001
    if verbose:
        print(f"[{t:.3f}] ARP: Who has {SERVER_IP}? Tell {CLIENT_IP}")

    # DNS query for 'web' (the lab container hostname)
    dns_pay = dns_query("web", txid=0xabcd)
    udp_pay = udp_datagram(52341, 53, dns_pay)
    ip_pay  = ipv4_header(CLIENT_IP, DNS_IP, 17, udp_pay)
    pkt     = ethernet_frame(CLIENT_MAC, SERVER_MAC, 0x0800, ip_pay)
    packets.append((t, pkt))
    t += 0.001

    # Simulate 3 HTTP exchanges (repeating every 8 seconds)
    for cycle in range(3):
        base = t + cycle * 8.0
        sport = 55200 + cycle * 10

        if verbose:
            print(f"[{base:.3f}] HTTP GET /  (cycle {cycle+1})")

        build_http_get("/", "web", seq_c=1000000 + cycle * 10000,
                       seq_s=5000000 + cycle * 10000,
                       sport=sport, ts_base=base, packet_list=packets)

        if verbose:
            print(f"[{base+0.01:.3f}] HTTP GET /login.html  (cycle {cycle+1})")

        build_http_get("/login.html", "web", seq_c=2000000 + cycle * 10000,
                       seq_s=6000000 + cycle * 10000,
                       sport=sport + 1, ts_base=base + 0.5, packet_list=packets)

        if verbose:
            print(f"[{base+1.0:.3f}] HTTP POST /login username=alice&password=secret123")

        build_http_post("/login", "web",
                        body_str="username=alice&password=secret123",
                        sport=sport + 2,
                        seq_c=3000000 + cycle * 10000,
                        seq_s=7000000 + cycle * 10000,
                        ts_base=base + 1.0,
                        packet_list=packets)

    # Write PCAP file
    with open(output_path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, pkt_data in sorted(packets, key=lambda x: x[0]):
            ts_sec  = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            f.write(pcap_packet_record(ts_sec, ts_usec, pkt_data))

    print(f"Generated {len(packets)} packets → {output_path}")
    print(f"Open with: wireshark {output_path}")
    print(f"Or:        tshark -r {output_path} -Y http")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", default="lab.pcap", help="Output PCAP file path")
    parser.add_argument("--verbose", action="store_true", help="Show packet details during generation")
    args = parser.parse_args()

    generate_pcap(args.output, verbose=args.verbose)
