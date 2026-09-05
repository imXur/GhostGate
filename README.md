# GhostGate

<p align="center">
  <strong>High-Performance Kernel-Level eBPF / XDP Intrusion Prevention & Hardware Behavioral Gateway</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C%20%2F%20Go-00ADD8?style=for-the-badge&logo=go" alt="Language" />
  <img src="https://img.shields.io/badge/Kernel-eBPF%20%2F%20XDP-orange?style=for-the-badge&logo=linux" alt="eBPF" />
  <img src="https://img.shields.io/badge/Throughput-Line--Rate%20Zero--Copy-success?style=for-the-badge" alt="Performance" />
  <img src="https://img.shields.io/badge/License-GPL--2.0-blue?style=for-the-badge" alt="License" />
</p>

---

## Overview

**GhostGate** is an ultra-low latency, in-kernel network intrusion prevention system (IPS) designed to detect and neutralize machine beaconing, command-and-control (C2) heartbeats, and rogue IoT devices before they impact host infrastructure.

Operating directly inside the Linux Network Interface Card (NIC) driver space via **eXpress Data Path (XDP)**, GhostGate evaluates and drops anomalous packets before socket buffer memory allocations (`sk_buff`) ever occur. Telemetry metadata is streamed asynchronously to a userspace behavioral heuristics engine via zero-copy ring buffers, enabling sub-microsecond threat scoring and dynamic kernel map updates without context-switch overhead.

---

## Architecture & Flow

```text
                  [ Physical Network Interface (NIC) ]
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   xdp_ghostgate.bpf   │
                       │   (Linux Kernel / XDP)│
                       └───────────┬───────────┘
                                   │
               ┌───────────────────┴───────────────────┐
               ▼                                       ▼
       [ BPF Hash Map ]                        [ BPF Ring Buffer ]
       - Check banned IPs                      - Zero-copy flow telemetry
       - If MATCH -> XDP_DROP                  - (Src/Dst IP, Port, Window, Ts)
       - If MISS  -> XDP_PASS                          │
                                                       ▼
                                            ┌─────────────────────┐
                                            │ GhostGate Daemon    │
                                            │ (Go Engine)         │
                                            └──────────┬──────────┘
                                                       │
                      ┌────────────────────────────────┴────────────────────────────────┐
                      ▼                                                                 ▼
           [ Heuristic Analyzer ]                                            [ Terminal TUI ]
           - Sliding window variance (Welford's)                             - Real-time metrics
           - Inter-arrival jitter detection                                  - Active flow waterfall
           - TCP window exhaustion scans                                     - Kernel drop counters
                      │
                      ▼ (Risk > Threshold)
           [ Auto-Ban to BPF Map ] ─────────────────────────► Line-rate NIC Drop Active

```

---

## Key Features

* **Line-Rate In-Kernel Mitigation (`XDP_DROP`):** Drops malicious frames directly at the NIC driver level, bypassing OS socket allocations and preventing CPU saturation during volumetric floods.
* **Zero-Copy Telemetry Streaming:** Leverages `BPF_MAP_TYPE_RINGBUF` for lockless, bounded-memory event transfers to userspace.
* **Behavioral Jitter Analysis:** Detects synthetic machine beacons and botnet heartbeats by calculating standard deviation ($\sigma$) and variance across inter-packet arrival times.
* **TCP Window Starvation Detection:** Flags and mitigates anomalous micro-burst connection exhaustion attempts.
* **Dynamic BPF Map Updates:** Automatically injects offending IP addresses into a `BPF_MAP_TYPE_HASH` from userspace in microseconds.
* **Interactive Terminal UI (TUI):** Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss) for full-screen, real-time observability.

---

## Repository Structure

```text
GhostGate/
├── Makefile                 # Clang/BPF compilation targets and loader scripts
├── go.mod                   # Go module definitions
├── kernel/
│   ├── ghostgate.bpf.c      # Pure C eBPF source code targeting XDP
│   └── ghostgate.h          # Shared memory layouts between kernel and userspace
├── userspace/
│   ├── cmd/
│   │   ├── main.go          # Daemon entrypoint, ring buffer reader, and XDP loader
│   │   └── ...              # Auto-generated bpf2go bindings
│   ├── engine/
│   │   └── analyzer.go      # Sliding-window statistical heuristic engine
│   └── ui/
│       └── dashboard.go     # Interactive full-screen terminal interface
└── test/
    └── traffic_generator.py # Python/Scapy packet generator & beacon simulator

```

---

## Prerequisites

* **Linux Kernel:** Version 5.8 or higher with eBPF/XDP support enabled (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_XDP_SOCKETS=y`).
* **Toolchain:** `clang` (>= 11), `llvm`, `libbpf-dev`, `gcc`, `make`.
* **Go Runtime:** Go 1.22+.
* **Python (Optional for Testing):** Python 3.8+ with `scapy`.

On Debian / Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev gcc make

```

---

## Quickstart

### 1. Clone & Dependencies

```bash
git clone [https://github.com/imxur/GhostGate.git](https://github.com/imxur/GhostGate.git)
cd GhostGate
go mod tidy

```

### 2. Compile eBPF Bytecode & Build Userspace Daemon

```bash
make build

```

This triggers `bpf2go` to compile `kernel/ghostgate.bpf.c` into BPF bytecode, produces the Go bindings, and builds the executable at `bin/ghostgate`.

### 3. Run GhostGate

Attach the XDP filter to your target network interface (e.g., `eth0` or `wlan0`):

```bash
sudo ./bin/ghostgate -iface eth0

```

---

## Validation & Testing

Use the bundled Scapy script to generate synthetic low-jitter machine beacons against the protected interface:

```bash
# In a separate terminal or client machine:
sudo python3 test/traffic_generator.py --target-ip <YOUR_GHOSTGATE_IP> --mode jitter-beacon

```

Within 15–20 packets, GhostGate detects the synthetic cadence (`mean < 5.0ms`, `stdDev < 0.2`), alerts the TUI dashboard, and immediately begins dropping subsequent packets at the NIC driver.

---

## License

Distributed under the **GNU General Public License v2.0 (GPL-2.0)** to adhere to Linux eBPF kernel helper constraints.

```
