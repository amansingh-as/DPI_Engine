"""
sni_extractor.py - Extract domain names from TLS Client Hello (SNI) and HTTP Host headers.
Equivalent to sni_extractor.h / sni_extractor.cpp in the C++ version.

TLS Client Hello structure:
  Byte 0:     Content Type = 0x16 (Handshake)
  Bytes 1-2:  Legacy version
  Bytes 3-4:  Record length
  Byte 5:     Handshake type = 0x01 (Client Hello)
  Bytes 6-8:  Handshake length (3 bytes)
  Bytes 9-10: Client version
  Bytes 11-42: Random (32 bytes)
  Byte 43:    Session ID length (N)
  ...         Session ID (N bytes)
  ...         Cipher suites length (2) + suites
  ...         Compression methods length (1) + methods
  ...         Extensions length (2)
    SNI extension type = 0x0000
      Extension length (2)
      SNI list length (2)
      SNI type = 0x00 (hostname)
      SNI length (2)
      SNI value  ← we extract this
"""

from __future__ import annotations
import struct
from typing import Optional

TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXT_SNI = 0x0000
TLS_SNI_TYPE_HOSTNAME = 0x00


class SNIExtractor:
    """Extract the SNI hostname from a TLS Client Hello payload."""

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Returns the SNI hostname string if found, else None.
        payload  = TCP payload bytes (starting at the TLS record).
        """
        if len(payload) < 10:
            return None

        # ---- TLS record layer -------------------------------------------
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return None

        # Bytes 3-4: record length (we accept whatever the payload has)
        # ---- Handshake layer (starts at byte 5) -------------------------
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        # Handshake length is 3 bytes big-endian at bytes 6-8
        # Client Hello body starts at byte 9
        offset = 9

        # Client version (2 bytes) + random (32 bytes) = 34 bytes
        offset += 34
        if offset >= len(payload):
            return None

        # Session ID
        session_len = payload[offset]
        offset += 1 + session_len
        if offset + 2 > len(payload):
            return None

        # Cipher suites
        cipher_len = struct.unpack("!H", payload[offset: offset + 2])[0]
        offset += 2 + cipher_len
        if offset >= len(payload):
            return None

        # Compression methods
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload):
            return None

        # Extensions total length
        ext_total = struct.unpack("!H", payload[offset: offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total

        # Walk extensions
        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[offset: offset + 2])[0]
            ext_len = struct.unpack("!H", payload[offset + 2: offset + 4])[0]
            offset += 4

            if ext_type == TLS_EXT_SNI:
                # SNI list length (2) + SNI type (1) + SNI length (2) + hostname
                if offset + 5 > len(payload):
                    return None
                # sni_list_len = struct.unpack("!H", payload[offset:offset+2])[0]
                sni_type = payload[offset + 2]
                if sni_type != TLS_SNI_TYPE_HOSTNAME:
                    return None
                sni_len = struct.unpack("!H", payload[offset + 3: offset + 5])[0]
                name_start = offset + 5
                if name_start + sni_len > len(payload):
                    return None
                return payload[name_start: name_start + sni_len].decode("ascii", errors="ignore")

            offset += ext_len

        return None


class HTTPHostExtractor:
    """Extract the Host header value from an HTTP/1.x request."""

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Returns the Host header value or None.
        Works for HTTP/1.0 and HTTP/1.1 requests.
        """
        try:
            text = payload.decode("ascii", errors="ignore")
        except Exception:
            return None

        # Only handle HTTP requests
        http_methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                        "OPTIONS ", "PATCH ", "CONNECT ")
        if not any(text.startswith(m) for m in http_methods):
            return None

        lower = text.lower()
        host_idx = lower.find("\r\nhost:")
        if host_idx == -1:
            host_idx = lower.find("\nhost:")
            if host_idx == -1:
                return None
            value_start = host_idx + len("\nhost:")
        else:
            value_start = host_idx + len("\r\nhost:")

        end = text.find("\r\n", value_start)
        if end == -1:
            end = text.find("\n", value_start)
        if end == -1:
            end = len(text)

        host = text[value_start:end].strip()
        # Remove port if present (e.g., "example.com:80")
        if ":" in host:
            host = host.split(":")[0]
        return host if host else None
