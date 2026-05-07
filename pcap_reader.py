"""
pcap_reader.py - Read libpcap (.pcap) capture files.
Equivalent to pcap_reader.h / pcap_reader.cpp in the C++ version.

PCAP file format:
  Global Header (24 bytes)
  Packet Header (16 bytes) + Packet Data  [repeated]

Magic numbers:
  0xa1b2c3d4  -> big-endian timestamps (microseconds)
  0xd4c3b2a1  -> little-endian (byte-swapped)
"""

from __future__ import annotations
import struct
from typing import Iterator, Optional
from dpi_types import RawPacket   # local module (renamed to avoid clash with builtins)


# libpcap global header layout
_GLOBAL_HEADER_FMT_LE = "<IHHiIII"   # little-endian
_GLOBAL_HEADER_FMT_BE = ">IHHiIII"
_GLOBAL_HEADER_SIZE = 24

# libpcap per-packet header
_PKT_HEADER_FMT_LE = "<IIII"
_PKT_HEADER_FMT_BE = ">IIII"
_PKT_HEADER_SIZE = 16

MAGIC_LE = 0xa1b2c3d4
MAGIC_BE = 0xd4c3b2a1


class PcapReader:
    """
    Reads packets from a libpcap (.pcap) file one at a time.

    Usage:
        reader = PcapReader()
        reader.open("capture.pcap")
        for pkt in reader:
            ...  # pkt is a RawPacket
        reader.close()

    Or use as context manager:
        with PcapReader("capture.pcap") as reader:
            for pkt in reader:
                ...
    """

    def __init__(self, filename: Optional[str] = None):
        self._file = None
        self._little_endian = True
        self.snaplen: int = 0
        self.network: int = 0   # 1 = Ethernet
        self.version_major: int = 0
        self.version_minor: int = 0
        if filename:
            self.open(filename)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def open(self, filename: str) -> None:
        """Open and validate a PCAP file."""
        self._file = open(filename, "rb")
        self._read_global_header()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def read_next_packet(self) -> Optional[RawPacket]:
        """Return the next RawPacket, or None at EOF."""
        if self._file is None:
            raise RuntimeError("PcapReader: file not open")

        hdr_bytes = self._file.read(_PKT_HEADER_SIZE)
        if len(hdr_bytes) < _PKT_HEADER_SIZE:
            return None  # EOF

        fmt = _PKT_HEADER_FMT_LE if self._little_endian else _PKT_HEADER_FMT_BE
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, hdr_bytes)

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            return None  # truncated file

        return RawPacket(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=incl_len,
            orig_len=orig_len,
            data=data,
        )

    def __iter__(self) -> Iterator[RawPacket]:
        pkt = self.read_next_packet()
        while pkt is not None:
            yield pkt
            pkt = self.read_next_packet()

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_global_header(self) -> None:
        raw = self._file.read(_GLOBAL_HEADER_SIZE)
        if len(raw) < _GLOBAL_HEADER_SIZE:
            raise ValueError("PcapReader: file too small to be a valid PCAP")

        magic = struct.unpack("<I", raw[:4])[0]
        if magic == MAGIC_LE:
            self._little_endian = True
        elif magic == MAGIC_BE:
            self._little_endian = False
        else:
            raise ValueError(
                f"PcapReader: invalid magic number 0x{magic:08x}; not a PCAP file"
            )

        fmt = _GLOBAL_HEADER_FMT_LE if self._little_endian else _GLOBAL_HEADER_FMT_BE
        (_, v_maj, v_min, _, snaplen, _, network) = struct.unpack(fmt, raw)
        self.version_major = v_maj
        self.version_minor = v_min
        self.snaplen = snaplen
        self.network = network


# ---------------------------------------------------------------------------
# PCAP Writer  (used to produce filtered output.pcap)
# ---------------------------------------------------------------------------

class PcapWriter:
    """
    Writes packets to a libpcap (.pcap) file.

    Usage:
        with PcapWriter("output.pcap") as writer:
            writer.write_packet(raw_packet)
    """

    def __init__(self, filename: Optional[str] = None):
        self._file = None
        if filename:
            self.open(filename)

    def open(self, filename: str) -> None:
        self._file = open(filename, "wb")
        self._write_global_header()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def write_packet(self, pkt: RawPacket) -> None:
        if self._file is None:
            raise RuntimeError("PcapWriter: file not open")
        header = struct.pack(
            "<IIII", pkt.ts_sec, pkt.ts_usec, pkt.incl_len, pkt.orig_len
        )
        self._file.write(header)
        self._file.write(pkt.data)

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _write_global_header(self) -> None:
        # magic, version 2.4, timezone 0, sig figs 0, snaplen 65535, Ethernet (1)
        header = struct.pack("<IHHiIII", MAGIC_LE, 2, 4, 0, 65535, 0, 1)
        self._file.write(header)
