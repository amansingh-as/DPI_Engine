"""
dpi_engine_simple.py - Single-threaded DPI Engine.
Equivalent to src/main_working.cpp in the C++ version.

Usage:
    python dpi_engine_simple.py <input.pcap> <output.pcap> [OPTIONS]

Options:
    --block-app <AppName>      Block all flows of this app (e.g., YouTube)
    --block-ip  <IP>           Block all flows from this source IP
    --block-domain <substring> Block flows whose SNI contains this string

Example:
    python dpi_engine_simple.py capture.pcap filtered.pcap \\
        --block-app YouTube --block-ip 192.168.1.50 --block-domain tiktok
"""

from __future__ import annotations
import sys
import struct
import socket
import argparse
from collections import defaultdict
from typing import Dict

# Local modules
from dpi_types import FiveTuple, Flow, AppType, sni_to_app_type
from pcap_reader import PcapReader, PcapWriter
from packet_parser import PacketParser
from sni_extractor import SNIExtractor, HTTPHostExtractor
from rule_manager import RuleManager


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

def run(input_path: str, output_path: str, rules: RuleManager) -> None:
    flows: Dict[FiveTuple, Flow] = {}

    total_packets = 0
    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = defaultdict(int)
    detected_snis: Dict[str, AppType] = {}

    print(f"\n[Reader] Processing packets from: {input_path}")

    with PcapReader(input_path) as reader, PcapWriter(output_path) as writer:
        for raw in reader:
            total_packets += 1
            total_bytes += raw.orig_len

            # ---- Parse packet headers ------------------------------------
            parsed = PacketParser.parse(raw)
            if parsed is None:
                # Non-IPv4 or malformed — forward as-is
                writer.write_packet(raw)
                forwarded += 1
                continue

            if parsed.has_tcp:
                tcp_count += 1
            elif parsed.has_udp:
                udp_count += 1

            # ---- Build / look up flow ------------------------------------
            tup = FiveTuple(
                src_ip=parsed.src_ip_int,
                dst_ip=parsed.dst_ip_int,
                src_port=parsed.src_port,
                dst_port=parsed.dst_port,
                protocol=parsed.ip_protocol,
            )
            if tup not in flows:
                flows[tup] = Flow(tuple=tup)
            flow = flows[tup]
            flow.packet_count += 1
            flow.byte_count += raw.orig_len

            # ---- Deep Packet Inspection ----------------------------------
            if not flow.classified and parsed.payload:
                _classify_flow(parsed.payload, parsed.dst_port, flow, detected_snis)

            # ---- Apply blocking rules ------------------------------------
            if not flow.blocked and rules.has_rules():
                if rules.is_blocked(tup.src_ip, flow.app_type, flow.sni or flow.http_host):
                    flow.blocked = True

            # ---- Track per-app stats -------------------------------------
            app_stats[flow.app_type] += 1

            # ---- Forward or drop -----------------------------------------
            if flow.blocked:
                dropped += 1
            else:
                writer.write_packet(raw)
                forwarded += 1

    # ---- Print report -------------------------------------------------------
    _print_report(
        total_packets, total_bytes, tcp_count, udp_count,
        forwarded, dropped, app_stats, detected_snis,
    )


# ---------------------------------------------------------------------------
# Classification helper
# ---------------------------------------------------------------------------

def _classify_flow(payload: bytes, dst_port: int, flow: Flow, detected: dict) -> None:
    """Try to extract SNI or HTTP Host and set flow.app_type."""

    # TLS (HTTPS) — port 443 or payload starts with TLS handshake
    if dst_port == 443 or (len(payload) >= 1 and payload[0] == 0x16):
        sni = SNIExtractor.extract(payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            flow.classified = True
            detected[sni] = flow.app_type
            return

    # HTTP — port 80 or look for plain HTTP Host header
    if dst_port == 80 or dst_port == 8080:
        host = HTTPHostExtractor.extract(payload)
        if host:
            flow.http_host = host
            flow.app_type = sni_to_app_type(host)
            if flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.HTTP
            flow.classified = True
            detected[host] = flow.app_type
            return

    # DNS
    if dst_port == 53 or (len(payload) >= 1 and flow.app_type == AppType.UNKNOWN):
        if dst_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

    # Fallback based on port
    if dst_port == 443:
        flow.app_type = AppType.HTTPS
    elif dst_port == 80:
        flow.app_type = AppType.HTTP


# ---------------------------------------------------------------------------
# Pretty report
# ---------------------------------------------------------------------------

def _print_report(total, total_bytes, tcp, udp, forwarded, dropped, app_stats, snis):
    bar = "═" * 62
    print(f"\n╔{bar}╗")
    print(f"║{'DPI ENGINE - SIMPLE (Single-threaded)':^62}║")
    print(f"╠{bar}╣")
    print(f"║  {'Total Packets:':<30}{total:>10}{'':>20}║")
    print(f"║  {'Total Bytes:':<30}{total_bytes:>10}{'':>20}║")
    print(f"║  {'TCP Packets:':<30}{tcp:>10}{'':>20}║")
    print(f"║  {'UDP Packets:':<30}{udp:>10}{'':>20}║")
    print(f"╠{bar}╣")
    print(f"║  {'Forwarded:':<30}{forwarded:>10}{'':>20}║")
    print(f"║  {'Dropped:':<30}{dropped:>10}{'':>20}║")
    print(f"╠{bar}╣")
    print(f"║{'APPLICATION BREAKDOWN':^62}║")
    print(f"╠{bar}╣")

    total_classified = sum(app_stats.values()) or 1
    sorted_apps = sorted(app_stats.items(), key=lambda x: -x[1])
    for app, count in sorted_apps:
        pct = count / total_classified * 100
        bar_len = int(pct / 5)
        bar_str = "#" * bar_len
        blocked_tag = " (BLOCKED)" if app in _blocked_apps_display else ""
        line = f"  {app.name:<18} {count:>5}  {pct:>5.1f}% {bar_str}{blocked_tag}"
        print(f"║{line:<62}║")

    print(f"╠{bar}╣")
    print(f"║{'DETECTED DOMAINS / SNIs':^62}║")
    print(f"╠{bar}╣")
    for sni, app in sorted(snis.items()):
        line = f"  {sni[:35]:<35} -> {app.name}"
        print(f"║{line:<62}║")
    print(f"╚{bar}╝\n")


_blocked_apps_display: set = set()   # populated by main() for report display


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    global _blocked_apps_display

    parser = argparse.ArgumentParser(
        description="DPI Engine (Python) - Deep Packet Inspection on PCAP files"
    )
    parser.add_argument("input",  help="Input PCAP file")
    parser.add_argument("output", help="Output (filtered) PCAP file")
    parser.add_argument("--block-app",    action="append", default=[], metavar="APP",
                        help="Block application (e.g., YouTube, TikTok, Facebook)")
    parser.add_argument("--block-ip",     action="append", default=[], metavar="IP",
                        help="Block source IP address")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN",
                        help="Block domain substring in SNI")

    args = parser.parse_args()

    rules = RuleManager()

    for app_name in args.block_app:
        try:
            app = AppType[app_name.upper()]
            rules.block_app(app)
            _blocked_apps_display.add(app)
        except KeyError:
            print(f"[Warning] Unknown app type: {app_name}. Available: "
                  + ", ".join(a.name for a in AppType))

    for ip in args.block_ip:
        rules.block_ip(ip)

    for domain in args.block_domain:
        rules.block_domain(domain)

    run(args.input, args.output, rules)


if __name__ == "__main__":
    main()
