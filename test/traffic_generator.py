#!/usr/bin/env python3
"""GhostGate Validation Suite: Anomalous Traffic & Beacon Simulator.

Sends high-frequency, near-zero jitter TCP packets to trip the AnomalyEngine.
"""

import argparse
import sys
import time
from scapy.all import IP, TCP, send


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simulate anomalous machine traffic to trigger GhostGate."
    )
    parser.add_argument(
        "--target-ip",
        required=True,
        help="Target IP address protected by GhostGate (e.g., 192.168.1.100)",
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=8080,
        help="Target destination port (default: 8080)",
    )
    parser.add_argument(
        "--mode",
        choices=["jitter-beacon", "window-starvation"],
        default="jitter-beacon",
        help="Attack vector mode to trigger specific heuristics",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=40,
        help="Number of packets to emit (default: 40, threshold needs >= 15)",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface to transmit over (optional)",
    )
    return parser.parse_args()


def simulate_jitter_beacon(target_ip, target_port, count, iface):
    """Fires periodic packets with < 2ms interval and near-zero jitter (mean < 5.0, stdDev < 0.2)."""
    print(
        f"[+] Starting Low-Jitter Machine Beaconing against {target_ip}:{target_port}..."
    )
    print("    Expected Metric Trip: mean < 5.0ms, stdDev < 0.2 -> Score += 50.0")

    # Precise sleep interval (approx 2 milliseconds)
    target_interval = 0.002

    for i in range(count):
        # TCP SYN frame with fixed window
        pkt = (
            IP(dst=target_ip)
            / TCP(
                sport=50000 + (i % 1000),
                dport=target_port,
                flags="S",
                window=64240,
                seq=1000 + i,
            )
        )

        send(pkt, iface=iface, verbose=False)
        time.sleep(target_interval)

        if (i + 1) % 10 == 0:
            print(f"    Sent {i + 1}/{count} frames...")

    print("[+] Transmission complete. Verify GhostGate daemon output for XDP ACTION ban.")


def simulate_window_starvation(target_ip, target_port, count, iface):
    """Sends frames with TCP Window = 0 to trigger window starvation heuristic."""
    print(
        f"[+] Starting Zero-Window Exhaustion Stream against {target_ip}:{target_port}..."
    )
    print("    Expected Metric Trip: Zero-Window Ratio > 30% -> Score += 30.0")

    interval = 0.003  # 3ms

    for i in range(count):
        # Inject Window Size = 0 on more than 50% of frames
        win_size = 0 if (i % 2 == 0) else 1024

        pkt = (
            IP(dst=target_ip)
            / TCP(
                sport=55000,
                dport=target_port,
                flags="A",
                window=win_size,
                seq=2000 + i,
            )
        )

        send(pkt, iface=iface, verbose=False)
        time.sleep(interval)

        if (i + 1) % 10 == 0:
            print(f"    Sent {i + 1}/{count} frames...")

    print("[+] Transmission complete. Verify GhostGate daemon output.")


def main():
    args = parse_args()

    # Scapy raw sockets require root / Administrator privileges
    try:
        if args.mode == "jitter-beacon":
            simulate_jitter_beacon(
                args.target_ip, args.target_port, args.count, args.iface
            )
        elif args.mode == "window-starvation":
            simulate_window_starvation(
                args.target_ip, args.target_port, args.count, args.iface
            )
    except PermissionError:
        sys.exit("[!] Error: Raw packet generation requires root. Re-run with sudo.")


if __name__ == "__main__":
    main()