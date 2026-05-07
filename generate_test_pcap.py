"""
generate_test_pcap.py - Create a test PCAP with simulated traffic.
Equivalent to generate_test_pcap.py in the original repo.

Generates packets for:
  - YouTube (TLS with SNI www.youtube.com)
  - Facebook (TLS with SNI www.facebook.com)
  - Google (TLS with SNI www.google.com)
  - GitHub (TLS with SNI github.com)
  - HTTP (plain HTTP with Host header)
  - DNS (UDP port 53)
  - Unknown TCP

Usage:
    python generate_test_pcap.py [output_file.pcap]
"""

from __future__ import annotations
import struct
import socket
import sys
import random

OUTPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else "test_dpi.pcap"

MAGIC_LE = 0xa1b2c3d4


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _build_ethernet(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def _build_ipv4(src_ip: str, dst_ip: str, protocol: int, payload: bytes) -> bytes:
    src = _ip_to_bytes(src_ip)
    dst = _ip_to_bytes(dst_ip)
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # version=4, IHL=5
        0,               # DSCP/ECN
        total_len,
        random.randint(0, 65535),  # identification
        0x4000,          # DF flag
        64,              # TTL
        protocol,
        0,               # checksum (0 = unchecked)
        src,
        dst,
    )
    return header + payload


def _build_tcp(src_port: int, dst_port: int, payload: bytes,
               seq: int = 1000, ack: int = 0, flags: int = 0x018) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        0x50,   # data offset = 5 (20 bytes), reserved=0
        flags,  # PSH+ACK default
        65535,  # window
        0,      # checksum (unchecked)
        0,      # urgent
    )
    return header + payload


def _build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return header + payload


def _build_pcap_packet(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 Client Hello with the given SNI."""
    sni_bytes = sni.encode()
    sni_len = len(sni_bytes)

    sni_ext_data = (
        struct.pack("!H", sni_len + 3) +   # SNI list length
        b"\x00" +                           # hostname type
        struct.pack("!H", sni_len) +        # SNI hostname length
        sni_bytes
    )
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    # Supported versions extension (TLS 1.3 hint)
    supported_versions_ext = b"\x00\x2b\x00\x03\x02\x03\x04"

    extensions = sni_ext + supported_versions_ext
    ext_total = struct.pack("!H", len(extensions)) + extensions

    # Minimal cipher suite: TLS_AES_128_GCM_SHA256
    cipher_suites = b"\x00\x02\x13\x01"

    client_hello_body = (
        b"\x03\x03" +            # client version TLS 1.2
        b"\xde\xad" * 16 +       # random (32 bytes)
        b"\x00" +                # session ID length = 0
        cipher_suites +
        b"\x01\x00" +            # compression: 1 method, null
        ext_total
    )

    handshake = (
        b"\x01" +                # Client Hello
        struct.pack("!I", len(client_hello_body))[1:] +  # 3-byte length
        client_hello_body
    )

    record = (
        b"\x16" +                # Content-Type: Handshake
        b"\x03\x01" +            # Legacy version: TLS 1.0
        struct.pack("!H", len(handshake)) +
        handshake
    )
    return record


def _http_request(host: str, path: str = "/") -> bytes:
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    return req.encode()


def _dns_query(domain: str) -> bytes:
    """Minimal DNS A-record query."""
    txid = random.randint(1, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)  # QTYPE A, QCLASS IN
    return header + question


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

SCENARIOS = [
    # (src_ip, dst_ip, src_port, dst_port, proto, payload_builder, count)
    ("192.168.1.100", "142.250.185.206", 54321, 443, "tls", "www.youtube.com",  4),
    ("192.168.1.101", "157.240.22.35",   54322, 443, "tls", "www.facebook.com", 3),
    ("192.168.1.102", "142.250.180.78",  54323, 443, "tls", "www.google.com",   5),
    ("192.168.1.103", "140.82.121.4",    54324, 443, "tls", "github.com",       3),
    ("192.168.1.104", "151.101.65.69",   54325, 443, "tls", "www.reddit.com",   2),
    ("192.168.1.105", "44.238.27.100",   54326, 443, "tls", "www.amazon.com",   3),
    ("192.168.1.50",  "142.250.185.206", 54327, 443, "tls", "www.youtube.com",  4),  # blocked IP
    ("192.168.1.106", "93.184.216.34",   54328,  80, "http","example.com",      3),
    ("192.168.1.107", "1.1.1.1",         12345,  53, "dns", "example.com",      4),
    ("192.168.1.108", "10.0.0.1",        54329, 8080,"http","internal.local",   2),
    ("192.168.1.109", "172.217.3.110",   54330, 443, "tls", "www.tiktok.com",   3),
    ("192.168.1.110", "157.240.22.36",   54331, 443, "tls", "www.instagram.com",3),
    ("192.168.1.111", "20.42.65.90",     54332, 443, "tls", "outlook.live.com", 2),
    ("192.168.1.112", "52.26.198.102",   54333, 443, "tls", "api.zoom.us",      2),
    ("192.168.1.113", "10.0.0.2",        54334, 12345,"tcp","",                 4),
]

SRC_MAC = bytes.fromhex("001122334455")
DST_MAC = bytes.fromhex("aabbccddeeff")


def main():
    packets = []
    ts_sec = 1700000000
    ts_usec = 0

    for (src_ip, dst_ip, src_port, dst_port, proto, host, count) in SCENARIOS:
        for i in range(count):
            if proto == "tls":
                payload = _tls_client_hello(host)
            elif proto == "http":
                payload = _http_request(host)
            elif proto == "dns":
                payload = _dns_query(host)
            else:
                payload = b"\x00" * 32  # unknown TCP data

            if proto == "dns":
                transport = _build_udp(src_port, dst_port, payload)
                ip_proto = 17
            else:
                transport = _build_tcp(src_port, dst_port, payload, seq=1000 + i)
                ip_proto = 6

            ip = _build_ipv4(src_ip, dst_ip, ip_proto, transport)
            eth = _build_ethernet(SRC_MAC, DST_MAC) + ip
            pkt = _build_pcap_packet(ts_sec, ts_usec, eth)
            packets.append(pkt)

            ts_usec += 100_000
            if ts_usec >= 1_000_000:
                ts_usec = 0
                ts_sec += 1

    # Write PCAP file
    global_header = struct.pack("<IHHiIII", MAGIC_LE, 2, 4, 0, 65535, 0, 1)
    with open(OUTPUT_FILE, "wb") as f:
        f.write(global_header)
        for pkt in packets:
            f.write(pkt)

    print(f"[+] Generated {len(packets)} packets -> {OUTPUT_FILE}")
    print(f"    Scenarios include: YouTube, Facebook, Google, GitHub, TikTok,")
    print(f"    Instagram, HTTP, DNS, Zoom, unknown TCP, blocked IP 192.168.1.50")


if __name__ == "__main__":
    main()
