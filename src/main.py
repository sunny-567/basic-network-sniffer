"""Command-line interface for the Basic Network Sniffer."""

from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from .capture import (
    DEFAULT_COUNT,
    DEFAULT_TIMEOUT,
    MAX_COUNT,
    MAX_TIMEOUT_SECONDS,
    CaptureError,
    PcapReadError,
    capture_metadata,
    read_pcap_metadata,
)
from .export import CSVExportError, export_csv
from .parser import PacketSummary


TABLE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("TIME", "timestamp"),
    ("SOURCE IP", "source_ip"),
    ("DESTINATION IP", "destination_ip"),
    ("PROTOCOL", "protocol"),
    ("SOURCE PORT", "source_port"),
    ("DESTINATION PORT", "destination_port"),
    ("LENGTH", "length"),
)


def _positive_count(raw_value: str) -> int:
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "count must be a positive integer"
        ) from exc

    if not 1 <= value <= MAX_COUNT:
        raise argparse.ArgumentTypeError(
            f"count must be between 1 and {MAX_COUNT}"
        )
    return value


def _positive_timeout(raw_value: str) -> float:
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "timeout must be a positive finite number"
        ) from exc

    if not math.isfinite(value) or not (
        0 < value <= MAX_TIMEOUT_SECONDS
    ):
        raise argparse.ArgumentTypeError(
            f"timeout must be greater than 0 and no more than "
            f"{MAX_TIMEOUT_SECONDS:g} seconds"
        )
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture or read packets for authorized security education and "
            "troubleshooting. The application outputs metadata only."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--count",
        type=_positive_count,
        default=DEFAULT_COUNT,
        help=f"maximum packet count (1 to {MAX_COUNT})",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT,
        help=(
            "maximum capture/read duration in seconds "
            f"(at most {MAX_TIMEOUT_SECONDS:g})"
        ),
    )
    parser.add_argument(
        "--interface",
        help=(
            "interface for authorized live capture; if omitted, Scapy uses "
            "its configured default"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/packet_metadata.csv"),
        help="destination CSV path",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="explicitly allow replacing an existing output file",
    )
    parser.add_argument(
        "--read-pcap",
        type=Path,
        metavar="PCAP",
        help="read an existing authorized PCAP file instead of live capture",
    )
    return parser


def _cell(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def display_table(
    summaries: Sequence[PacketSummary],
    stream: TextIO | None = None,
) -> None:
    if stream is None:
        stream = sys.stdout

    if not summaries:
        print("No packets were captured or read.", file=stream)

    rows = [
        [_cell(summary[field]) for _, field in TABLE_COLUMNS]
        for summary in summaries
    ]
    headers = [label for label, _ in TABLE_COLUMNS]
    widths = [
        max([len(headers[index])] + [len(row[index]) for row in rows])
        for index in range(len(headers))
    ]

    def format_row(values: Sequence[str]) -> str:
        cells = [
            f" {value:<{widths[index]}} "
            for index, value in enumerate(values)
        ]
        return "|" + "|".join(cells) + "|"

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    print(border, file=stream)
    print(format_row(headers), file=stream)
    print(border, file=stream)
    for row in rows:
        print(format_row(row), file=stream)
    print(border, file=stream)


def display_summary(
    summaries: Sequence[PacketSummary],
    stream: TextIO | None = None,
) -> None:
    if stream is None:
        stream = sys.stdout

    counts = Counter(summary["protocol"] for summary in summaries)
    print(f"Total packets: {len(summaries)}", file=stream)

    if not counts:
        print("Protocol counts: none", file=stream)
        return

    rendered_counts = ", ".join(
        f"{protocol}: {counts[protocol]}" for protocol in sorted(counts)
    )
    print(f"Protocol counts: {rendered_counts}", file=stream)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.read_pcap is not None and args.interface is not None:
        parser.error("--interface cannot be used together with --read-pcap")

    try:
        if args.read_pcap is not None:
            summaries = read_pcap_metadata(
                args.read_pcap,
                count=args.count,
                timeout=args.timeout,
            )
        else:
            summaries = capture_metadata(
                count=args.count,
                timeout=args.timeout,
                interface=args.interface,
            )

        display_table(summaries)
        display_summary(summaries)

        exported_path = export_csv(
            summaries,
            args.output,
            overwrite=args.force,
        )
        print(f"CSV exported to: {exported_path.resolve()}")
        return 0
    except (CaptureError, PcapReadError, CSVExportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
