"""Generate clearly labeled synthetic metadata; this is not live traffic."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402

from src.export import CSVExportError, export_csv  # noqa: E402
from src.parser import packet_summary  # noqa: E402


def build_synthetic_packets():
    specifications = [
        (
            IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=51514, dport=443),
            datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        ),
        (
            IP(src="192.0.2.53", dst="198.51.100.20")
            / UDP(sport=53, dport=53000),
            datetime(2025, 1, 1, 12, 0, 1, tzinfo=timezone.utc),
        ),
        (
            IP(src="203.0.113.7", dst="192.0.2.10") / ICMP(),
            datetime(2025, 1, 1, 12, 0, 2, tzinfo=timezone.utc),
        ),
    ]

    packets = []
    for packet, timestamp in specifications:
        packet.time = timestamp.timestamp()
        packets.append(packet)
    return packets


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write a synthetic metadata CSV; no real traffic is used."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/synthetic_demo.csv"),
        help="destination CSV path",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="explicitly replace an existing output file",
    )
    args = parser.parse_args()

    summaries = [
        packet_summary(packet) for packet in build_synthetic_packets()
    ]

    try:
        output_path = export_csv(
            summaries,
            args.output,
            overwrite=args.force,
        )
    except CSVExportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("Synthetic demonstration data generated; it is not captured traffic.")
    print(f"CSV exported to: {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
