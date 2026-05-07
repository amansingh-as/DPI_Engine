"""
rule_manager.py - Manage blocking rules (IPs, Apps, Domains).
Equivalent to rule_manager.h in the C++ multi-threaded version.

Rule types:
  - IP address:    block all traffic from a source IP
  - App type:      block all traffic classified as a particular application
  - Domain string: block any connection whose SNI contains this substring
"""

from __future__ import annotations
import socket
import struct
from typing import Set
from dpi_types import AppType


class RuleManager:
    """
    Thread-safe (Python GIL) rule manager.

    Usage:
        rules = RuleManager()
        rules.block_ip("192.168.1.50")
        rules.block_app(AppType.YOUTUBE)
        rules.block_domain("tiktok")
        ...
        if rules.is_blocked(src_ip_int, app_type, sni):
            drop_packet()
    """

    def __init__(self):
        self._blocked_ips: Set[int] = set()         # packed uint32
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()     # lowercase substrings

    # ------------------------------------------------------------------
    # Add rules
    # ------------------------------------------------------------------

    def block_ip(self, ip: str) -> None:
        """Block all packets with this source IP (dotted-decimal string)."""
        packed = struct.unpack("!I", socket.inet_aton(ip))[0]
        self._blocked_ips.add(packed)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: AppType) -> None:
        """Block all flows classified as this application type."""
        self._blocked_apps.add(app)
        print(f"[Rules] Blocked app: {app.name}")

    def block_domain(self, domain: str) -> None:
        """Block any flow whose SNI contains this substring (case-insensitive)."""
        self._blocked_domains.add(domain.lower())
        print(f"[Rules] Blocked domain pattern: {domain}")

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def is_blocked(self, src_ip_int: int, app: AppType, sni: str) -> bool:
        """
        Returns True if this flow should be dropped based on current rules.
        """
        if src_ip_int in self._blocked_ips:
            return True
        if app in self._blocked_apps:
            return True
        sni_lower = sni.lower()
        for dom in self._blocked_domains:
            if dom in sni_lower:
                return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def has_rules(self) -> bool:
        return bool(self._blocked_ips or self._blocked_apps or self._blocked_domains)

    def summary(self) -> str:
        lines = []
        for ip_int in sorted(self._blocked_ips):
            ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
            lines.append(f"  Blocked IP:     {ip_str}")
        for app in sorted(self._blocked_apps, key=lambda a: a.name):
            lines.append(f"  Blocked App:    {app.name}")
        for dom in sorted(self._blocked_domains):
            lines.append(f"  Blocked Domain: {dom}")
        return "\n".join(lines) if lines else "  (no rules)"
