# DPI Engine

Deep Packet Inspection system that reads PCAP files, classifies traffic by application (YouTube, Facebook, TikTok, etc.), applies blocking rules, and writes filtered output.

---

## Project Structure

```
dpi_engine_python/
├── dpi_types.py            # Data structures: FiveTuple, Flow, AppType, enums
├── pcap_reader.py          # PCAP file reader & writer
├── packet_parser.py        # Ethernet / IP / TCP / UDP parser
├── sni_extractor.py        # TLS SNI & HTTP Host extraction
├── rule_manager.py         # Blocking rules (IP / App / Domain)
├── thread_safe_queue.py    # Thread-safe bounded queue
├── dpi_engine_simple.py    # ★ Single-threaded engine (simple version)
├── dpi_engine_mt.py        # ★ Multi-threaded engine (production version)
├── generate_test_pcap.py   # Test data generator
└── README.md
```

---

## Requirements

- Python 3.8+
- No external libraries required (pure stdlib)

---

## Usage

### Generate test data
```bash
python generate_test_pcap.py test_dpi.pcap
```

### Simple (single-threaded) engine
```bash
python dpi_engine_simple.py <input.pcap> <output.pcap> [OPTIONS]
```

### Multi-threaded engine
```bash
python dpi_engine_mt.py <input.pcap> <output.pcap> [OPTIONS]
```

### Options
| Flag | Description | Example |
|------|-------------|---------|
| `--block-app APP` | Block all flows of this app | `--block-app YOUTUBE` |
| `--block-ip IP` | Block all packets from this source IP | `--block-ip 192.168.1.50` |
| `--block-domain STR` | Block flows whose SNI contains this substring | `--block-domain tiktok` |
| `--lbs N` | Number of Load Balancer threads (MT only) | `--lbs 4` |
| `--fps N` | Number of Fast Path threads per LB (MT only) | `--fps 4` |

### Full example
```bash
python dpi_engine_mt.py capture.pcap filtered.pcap \
    --block-app YOUTUBE \
    --block-app TIKTOK \
    --block-ip 192.168.1.50 \
    --block-domain facebook \
    --lbs 2 --fps 2
```

---

## Supported App Types

`YOUTUBE`, `FACEBOOK`, `INSTAGRAM`, `TWITTER`, `TIKTOK`, `NETFLIX`, `AMAZON`,
`MICROSOFT`, `APPLE`, `GITHUB`, `REDDIT`, `WHATSAPP`, `TELEGRAM`, `ZOOM`,
`CLOUDFLARE`, `GOOGLE`, `HTTP`, `HTTPS`, `DNS`, `UNKNOWN`

---

## Architecture

### Single-threaded
```
PcapReader → PacketParser → SNIExtractor → RuleManager → PcapWriter
```

### Multi-threaded
```
Reader Thread
    └─► Load Balancer Threads  [hash(5-tuple) % n_lbs]
            └─► Fast Path Threads   [hash(5-tuple) % n_fps]
                    └─► Output Queue
                            └─► Output Writer Thread
```

Consistent hashing ensures all packets of the same TCP/UDP flow are always
processed by the same Fast Path thread — no locking needed for flow state.

---

