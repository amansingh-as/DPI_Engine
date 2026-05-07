"""
packet_parser.py - Parse raw Ethernet/IP/TCP/UDP bytes into structured fields.
Equivalent to packet_parser.h / packet_parser.cpp in the C++ version.

Packet layout (Ethernet frame):
  Bytes 0-5:   Destination MAC
  Bytes 6-11:  Source MAC
  Bytes 12-13: EtherType  (0x0800 = IPv4)
  Bytes 14+:   IP Header  (min 20 bytes)
                 Byte 0:      Version(4 bits) | IHL(4 bits)
                 Byte 9:      Protocol  (6=TCP, 17=UDP)
                 Bytes 12-15: Source IP
                 Bytes 16-19: Destination IP
  IP+IHL bytes: TCP/UDP Header
"""

from __future__ import annotations
import struct
import socket
from typing import Optional
from dpi_types import RawPacket, ParsedPacket

ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17

ETH_HEADER_LEN = 14


class PacketParser:
    """
    Stateless packet parser.  Call PacketParser.parse(raw) to get a ParsedPacket.
    Returns None when the packet cannot be parsed (non-IPv4, truncated, etc.).
    """

    @staticmethod
    def parse(raw: RawPacket) -> Optional[ParsedPacket]:
        data = raw.data
        parsed = ParsedPacket(raw=raw)

        # ---- Ethernet (14 bytes) ----------------------------------------
        if len(data) < ETH_HEADER_LEN:
            return None

        parsed.dst_mac = PacketParser._format_mac(data[0:6])
        parsed.src_mac = PacketParser._format_mac(data[6:12])
        parsed.ether_type = struct.unpack("!H", data[12:14])[0]

        if parsed.ether_type != ETHERTYPE_IPV4:
            return None   # only handle IPv4

        # ---- IP (min 20 bytes) ------------------------------------------
        ip_start = ETH_HEADER_LEN
        if len(data) < ip_start + 20:
            return None

        ihl = (data[ip_start] & 0x0F) * 4   # header length in bytes
        if ihl < 20:
            return None

        parsed.ip_header_len = ihl
        parsed.ttl = data[ip_start + 8]
        parsed.ip_protocol = data[ip_start + 9]
        parsed.src_ip_int = struct.unpack("!I", data[ip_start + 12: ip_start + 16])[0]
        parsed.dst_ip_int = struct.unpack("!I", data[ip_start + 16: ip_start + 20])[0]
        parsed.src_ip = socket.inet_ntoa(data[ip_start + 12: ip_start + 16])
        parsed.dst_ip = socket.inet_ntoa(data[ip_start + 16: ip_start + 20])

        transport_start = ip_start + ihl

        # ---- TCP ---------------------------------------------------------
        if parsed.ip_protocol == PROTO_TCP:
            if len(data) < transport_start + 20:
                return None
            tcp = data[transport_start:]
            parsed.src_port = struct.unpack("!H", tcp[0:2])[0]
            parsed.dst_port = struct.unpack("!H", tcp[2:4])[0]
            parsed.tcp_seq = struct.unpack("!I", tcp[4:8])[0]
            parsed.tcp_ack = struct.unpack("!I", tcp[8:12])[0]
            data_offset = (tcp[12] >> 4) * 4
            parsed.tcp_flags = tcp[13]
            parsed.tcp_header_len = data_offset
            parsed.has_tcp = True

            payload_start = transport_start + data_offset
            parsed.payload = data[payload_start:]

        # ---- UDP ---------------------------------------------------------
        elif parsed.ip_protocol == PROTO_UDP:
            if len(data) < transport_start + 8:
                return None
            udp = data[transport_start:]
            parsed.src_port = struct.unpack("!H", udp[0:2])[0]
            parsed.dst_port = struct.unpack("!H", udp[2:4])[0]
            parsed.has_udp = True
            parsed.payload = data[transport_start + 8:]

        return parsed

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _format_mac(b: bytes) -> str:
        return ":".join(f"{x:02x}" for x in b)
