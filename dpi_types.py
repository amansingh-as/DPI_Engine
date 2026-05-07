"""
types.py - Data structures and enums for the DPI Engine.
Equivalent to types.h / types.cpp in the C++ version.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import socket
import struct


# ---------------------------------------------------------------------------
# AppType enum
# ---------------------------------------------------------------------------

class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    GOOGLE = auto()
    YOUTUBE = auto()
    FACEBOOK = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    TIKTOK = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    GITHUB = auto()
    REDDIT = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    ZOOM = auto()
    CLOUDFLARE = auto()


# ---------------------------------------------------------------------------
# Five-tuple  (hashable so it can be used as dict key)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FiveTuple:
    src_ip: int       # packed uint32
    dst_ip: int       # packed uint32
    src_port: int
    dst_port: int
    protocol: int     # 6 = TCP, 17 = UDP

    def __str__(self) -> str:
        src = socket.inet_ntoa(struct.pack("!I", self.src_ip))
        dst = socket.inet_ntoa(struct.pack("!I", self.dst_ip))
        proto = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else str(self.protocol))
        return f"{src}:{self.src_port} -> {dst}:{self.dst_port} [{proto}]"


# ---------------------------------------------------------------------------
# Flow – tracks state for a single connection
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    tuple: Optional[FiveTuple] = None
    sni: str = ""
    http_host: str = ""
    app_type: AppType = AppType.UNKNOWN
    blocked: bool = False
    packet_count: int = 0
    byte_count: int = 0
    classified: bool = False


# ---------------------------------------------------------------------------
# Raw / parsed packet structures
# ---------------------------------------------------------------------------

@dataclass
class RawPacket:
    ts_sec: int = 0
    ts_usec: int = 0
    incl_len: int = 0
    orig_len: int = 0
    data: bytes = b""


@dataclass
class ParsedPacket:
    # Ethernet
    src_mac: str = ""
    dst_mac: str = ""
    ether_type: int = 0

    # IP
    src_ip: str = ""
    dst_ip: str = ""
    src_ip_int: int = 0
    dst_ip_int: int = 0
    ip_protocol: int = 0
    ttl: int = 0
    ip_header_len: int = 0

    # TCP / UDP
    src_port: int = 0
    dst_port: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_header_len: int = 0

    # Payload
    payload: bytes = b""

    # Raw ref
    raw: Optional[RawPacket] = None


# ---------------------------------------------------------------------------
# SNI  →  AppType mapping
# ---------------------------------------------------------------------------

_SNI_MAP = {
    "youtube": AppType.YOUTUBE,
    "googlevideo": AppType.YOUTUBE,
    "ytimg": AppType.YOUTUBE,
    "facebook": AppType.FACEBOOK,
    "fbcdn": AppType.FACEBOOK,
    "instagram": AppType.INSTAGRAM,
    "cdninstagram": AppType.INSTAGRAM,
    "twitter": AppType.TWITTER,
    "twimg": AppType.TWITTER,
    "tiktok": AppType.TIKTOK,
    "netflix": AppType.NETFLIX,
    "nflxvideo": AppType.NETFLIX,
    "amazon": AppType.AMAZON,
    "amazonaws": AppType.AMAZON,
    "microsoft": AppType.MICROSOFT,
    "office365": AppType.MICROSOFT,
    "live.com": AppType.MICROSOFT,
    "outlook": AppType.MICROSOFT,
    "apple": AppType.APPLE,
    "icloud": AppType.APPLE,
    "github": AppType.GITHUB,
    "reddit": AppType.REDDIT,
    "whatsapp": AppType.WHATSAPP,
    "telegram": AppType.TELEGRAM,
    "zoom": AppType.ZOOM,
    "cloudflare": AppType.CLOUDFLARE,
    "google": AppType.GOOGLE,
    "gstatic": AppType.GOOGLE,
    "googleapis": AppType.GOOGLE,
}


def sni_to_app_type(sni: str) -> AppType:
    """Map a hostname/SNI string to an AppType."""
    lower = sni.lower()
    for keyword, app in _SNI_MAP.items():
        if keyword in lower:
            return app
    return AppType.UNKNOWN
