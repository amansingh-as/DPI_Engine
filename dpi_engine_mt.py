"""
dpi_engine_mt.py - Multi-threaded DPI Engine.
Equivalent to src/dpi_mt.cpp in the C++ version.

Architecture:
    Reader Thread
        └─► Load Balancer Threads  (hash(5-tuple) % n_lbs)
                └─► Fast Path Threads   (hash(5-tuple) % n_fps)
                        └─► Output Queue
                                └─► Output Writer Thread

All inter-thread communication uses TSQueue (thread_safe_queue.py).
Consistent hashing ensures all packets of the same flow go to the same
Fast Path thread, which owns that flow's state without locking.

Usage:
    python dpi_engine_mt.py <input.pcap> <output.pcap> [OPTIONS]

Options:
    --lbs  <N>             Number of Load Balancer threads (default: 2)
    --fps  <N>             Number of Fast Path threads per LB (default: 2)
    --block-app <AppName>
    --block-ip  <IP>
    --block-domain <str>
"""

from __future__ import annotations
import sys
import argparse
import threading
import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Local modules
from dpi_types import FiveTuple, Flow, AppType, RawPacket, sni_to_app_type
from pcap_reader import PcapReader, PcapWriter
from packet_parser import PacketParser
from sni_extractor import SNIExtractor, HTTPHostExtractor
from rule_manager import RuleManager
from thread_safe_queue import TSQueue


# ---------------------------------------------------------------------------
# Per-thread statistics (avoid shared state / locks)
# ---------------------------------------------------------------------------

@dataclass
class ThreadStats:
    name: str
    dispatched: int = 0
    processed: int = 0
    forwarded: int = 0
    dropped: int = 0


# ---------------------------------------------------------------------------
# Helper: consistent hash for FiveTuple
# ---------------------------------------------------------------------------

def _hash_tuple(tup: FiveTuple) -> int:
    key = struct.pack("!IIHHB", tup.src_ip, tup.dst_ip,
                      tup.src_port, tup.dst_port, tup.protocol)
    return int.from_bytes(hashlib.md5(key).digest()[:4], "big")


# ---------------------------------------------------------------------------
# Fast Path Thread
# ---------------------------------------------------------------------------

class FastPath(threading.Thread):
    """
    Processes packets: parses, classifies, applies rules, forwards or drops.
    Each FP owns its own flow table — no locking needed for flow state.
    """

    def __init__(self, fp_id: int, input_queue: TSQueue,
                 output_queue: TSQueue, rules: RuleManager):
        super().__init__(name=f"FP-{fp_id}", daemon=True)
        self.fp_id = fp_id
        self._in = input_queue
        self._out = output_queue
        self._rules = rules
        self.stats = ThreadStats(name=f"FP{fp_id}")
        self._flows: Dict[FiveTuple, Flow] = {}

    def run(self):
        while True:
            item = self._in.get()
            if item is None:
                break  # sentinel → shutdown
            raw, parsed = item
            self.stats.processed += 1
            self._process(raw, parsed)

    def _process(self, raw: RawPacket, parsed):
        tup = FiveTuple(
            src_ip=parsed.src_ip_int,
            dst_ip=parsed.dst_ip_int,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            protocol=parsed.ip_protocol,
        )
        if tup not in self._flows:
            self._flows[tup] = Flow(tuple=tup)
        flow = self._flows[tup]
        flow.packet_count += 1
        flow.byte_count += raw.orig_len

        # Classify
        if not flow.classified and parsed.payload:
            _classify_flow(parsed.payload, parsed.dst_port, flow)

        # Check rules
        if not flow.blocked and self._rules.has_rules():
            if self._rules.is_blocked(tup.src_ip, flow.app_type,
                                       flow.sni or flow.http_host):
                flow.blocked = True

        if flow.blocked:
            self.stats.dropped += 1
        else:
            self._out.put(raw)
            self.stats.forwarded += 1

    def get_flows(self) -> Dict[FiveTuple, Flow]:
        return self._flows


# ---------------------------------------------------------------------------
# Load Balancer Thread
# ---------------------------------------------------------------------------

class LoadBalancer(threading.Thread):
    """
    Receives pre-parsed packets from the reader and distributes them
    to Fast Path threads using consistent hashing on the 5-tuple.
    """

    def __init__(self, lb_id: int, input_queue: TSQueue,
                 fast_paths: List[FastPath]):
        super().__init__(name=f"LB-{lb_id}", daemon=True)
        self.lb_id = lb_id
        self._in = input_queue
        self._fps = fast_paths
        self.stats = ThreadStats(name=f"LB{lb_id}")

    def run(self):
        while True:
            item = self._in.get()
            if item is None:
                # Propagate shutdown to all FPs
                for fp in self._fps:
                    fp._in.close()
                break
            raw, parsed = item
            self.stats.dispatched += 1
            fp_idx = _hash_tuple(FiveTuple(
                src_ip=parsed.src_ip_int,
                dst_ip=parsed.dst_ip_int,
                src_port=parsed.src_port,
                dst_port=parsed.dst_port,
                protocol=parsed.ip_protocol,
            )) % len(self._fps)
            self._fps[fp_idx]._in.put((raw, parsed))


# ---------------------------------------------------------------------------
# Output Writer Thread
# ---------------------------------------------------------------------------

class OutputWriter(threading.Thread):
    """Drains the shared output queue and writes packets to a PCAP file."""

    def __init__(self, output_path: str, output_queue: TSQueue):
        super().__init__(name="OutputWriter", daemon=True)
        self._path = output_path
        self._q = output_queue
        self.written = 0

    def run(self):
        with PcapWriter(self._path) as writer:
            while True:
                raw = self._q.get()
                if raw is None:
                    break
                writer.write_packet(raw)
                self.written += 1


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

def run(input_path: str, output_path: str, rules: RuleManager,
        n_lbs: int = 2, fps_per_lb: int = 2) -> None:

    total_fps = n_lbs * fps_per_lb

    print(f"\n╔{'═'*62}╗")
    print(f"║{'DPI ENGINE v2.0 (Multi-threaded)':^62}║")
    print(f"╠{'═'*62}╣")
    print(f"║  Load Balancers: {n_lbs:<4}  FPs per LB: {fps_per_lb:<4}  Total FPs: {total_fps:<16}║")
    print(f"╚{'═'*62}╝\n")

    # ---- Create output queue + writer -----------------------------------
    output_queue: TSQueue = TSQueue(maxsize=10_000)
    writer_thread = OutputWriter(output_path, output_queue)
    writer_thread.start()

    # ---- Create Fast Path threads (fps_per_lb * n_lbs) ------------------
    all_fps: List[FastPath] = []
    for i in range(total_fps):
        fp_q: TSQueue = TSQueue(maxsize=5_000)
        fp = FastPath(fp_id=i, input_queue=fp_q,
                      output_queue=output_queue, rules=rules)
        all_fps.append(fp)
        fp.start()

    # ---- Create Load Balancer threads -----------------------------------
    lb_list: List[LoadBalancer] = []
    for i in range(n_lbs):
        lb_q: TSQueue = TSQueue(maxsize=5_000)
        # Each LB is assigned its slice of Fast Paths
        fps_slice = all_fps[i * fps_per_lb: (i + 1) * fps_per_lb]
        lb = LoadBalancer(lb_id=i, input_queue=lb_q, fast_paths=fps_slice)
        lb_list.append(lb)
        lb.start()

    # ---- Reader (main thread) -------------------------------------------
    total_packets = 0
    total_bytes = 0
    tcp_count = 0
    udp_count = 0

    print(f"[Reader] Processing packets from: {input_path}")

    with PcapReader(input_path) as reader:
        for raw in reader:
            total_packets += 1
            total_bytes += raw.orig_len

            parsed = PacketParser.parse(raw)
            if parsed is None:
                # Non-IPv4: write directly to output (bypass DPI)
                output_queue.put(raw)
                continue

            if parsed.has_tcp:
                tcp_count += 1
            elif parsed.has_udp:
                udp_count += 1

            # Route to a Load Balancer using hash of 5-tuple
            tup_hash = _hash_tuple(FiveTuple(
                src_ip=parsed.src_ip_int,
                dst_ip=parsed.dst_ip_int,
                src_port=parsed.src_port,
                dst_port=parsed.dst_port,
                protocol=parsed.ip_protocol,
            ))
            lb_idx = tup_hash % n_lbs
            lb_list[lb_idx]._in.put((raw, parsed))

    print(f"[Reader] Done reading {total_packets} packets")

    # ---- Shutdown pipeline -----------------------------------------------
    for lb in lb_list:
        lb._in.close()
    for lb in lb_list:
        lb.join()
    for fp in all_fps:
        fp.join()
    output_queue.close()
    writer_thread.join()

    # ---- Collect stats ---------------------------------------------------
    forwarded = writer_thread.written
    dropped = sum(fp.stats.dropped for fp in all_fps)

    # Merge flow tables from all FPs for app stats
    app_stats: Dict[AppType, int] = defaultdict(int)
    detected_snis: Dict[str, AppType] = {}
    for fp in all_fps:
        for flow in fp.get_flows().values():
            app_stats[flow.app_type] += flow.packet_count
            if flow.sni:
                detected_snis[flow.sni] = flow.app_type
            elif flow.http_host:
                detected_snis[flow.http_host] = flow.app_type

    # ---- Print report -------------------------------------------------------
    _print_report(
        total_packets, total_bytes, tcp_count, udp_count,
        forwarded, dropped, app_stats, detected_snis,
        lb_list, all_fps,
    )


# ---------------------------------------------------------------------------
# Classification helper (shared between simple and MT engines)
# ---------------------------------------------------------------------------

def _classify_flow(payload: bytes, dst_port: int, flow: Flow) -> None:
    if dst_port == 443 or (len(payload) >= 1 and payload[0] == 0x16):
        sni = SNIExtractor.extract(payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            flow.classified = True
            return

    if dst_port in (80, 8080):
        host = HTTPHostExtractor.extract(payload)
        if host:
            flow.http_host = host
            flow.app_type = sni_to_app_type(host)
            if flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.HTTP
            flow.classified = True
            return

    if dst_port == 53:
        flow.app_type = AppType.DNS
        flow.classified = True
        return

    if dst_port == 443:
        flow.app_type = AppType.HTTPS
    elif dst_port == 80:
        flow.app_type = AppType.HTTP


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(total, total_bytes, tcp, udp, forwarded, dropped,
                  app_stats, snis, lb_list, all_fps):
    W = 62
    bar = "═" * W
    print(f"\n╔{bar}╗")
    print(f"║{'PROCESSING REPORT':^{W}}║")
    print(f"╠{bar}╣")
    print(f"║  {'Total Packets:':<30}{total:>10}{'':>{W-42}}║")
    print(f"║  {'Total Bytes:':<30}{total_bytes:>10}{'':>{W-42}}║")
    print(f"║  {'TCP Packets:':<30}{tcp:>10}{'':>{W-42}}║")
    print(f"║  {'UDP Packets:':<30}{udp:>10}{'':>{W-42}}║")
    print(f"╠{bar}╣")
    print(f"║  {'Forwarded:':<30}{forwarded:>10}{'':>{W-42}}║")
    print(f"║  {'Dropped:':<30}{dropped:>10}{'':>{W-42}}║")
    print(f"╠{bar}╣")
    print(f"║{'THREAD STATISTICS':^{W}}║")
    print(f"╠{bar}╣")
    for lb in lb_list:
        line = f"  {lb.stats.name} dispatched: {lb.stats.dispatched}"
        print(f"║{line:<{W}}║")
    for fp in all_fps:
        line = f"  {fp.stats.name} processed:  {fp.stats.processed}"
        print(f"║{line:<{W}}║")
    print(f"╠{bar}╣")
    print(f"║{'APPLICATION BREAKDOWN':^{W}}║")
    print(f"╠{bar}╣")
    total_c = sum(app_stats.values()) or 1
    for app, count in sorted(app_stats.items(), key=lambda x: -x[1]):
        pct = count / total_c * 100
        blen = int(pct / 5)
        line = f"  {app.name:<18} {count:>5}  {pct:>5.1f}% {'#'*blen}"
        print(f"║{line:<{W}}║")
    print(f"╠{bar}╣")
    print(f"║{'DETECTED DOMAINS / SNIs':^{W}}║")
    print(f"╠{bar}╣")
    for sni, app in sorted(snis.items()):
        line = f"  {sni[:35]:<35} -> {app.name}"
        print(f"║{line:<{W}}║")
    print(f"╚{bar}╝\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DPI Engine MT (Python) - Multi-threaded Deep Packet Inspection"
    )
    parser.add_argument("input",  help="Input PCAP file")
    parser.add_argument("output", help="Output (filtered) PCAP file")
    parser.add_argument("--lbs",  type=int, default=2, help="Number of Load Balancer threads")
    parser.add_argument("--fps",  type=int, default=2, help="Number of Fast Path threads per LB")
    parser.add_argument("--block-app",    action="append", default=[], metavar="APP")
    parser.add_argument("--block-ip",     action="append", default=[], metavar="IP")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN")

    args = parser.parse_args()
    rules = RuleManager()

    for app_name in args.block_app:
        try:
            rules.block_app(AppType[app_name.upper()])
        except KeyError:
            print(f"[Warning] Unknown app type: {app_name}")

    for ip in args.block_ip:
        rules.block_ip(ip)

    for domain in args.block_domain:
        rules.block_domain(domain)

    run(args.input, args.output, rules, n_lbs=args.lbs, fps_per_lb=args.fps)


if __name__ == "__main__":
    main()
