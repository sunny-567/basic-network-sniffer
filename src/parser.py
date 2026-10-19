"""Extract metadata from a Scapy packet without returning payload contents."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from struct import error as StructError
from typing import TypedDict

from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


METADATA_FIELDS: tuple[str, ...] = (
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "length",
)


class PacketSummary(TypedDict):
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: str
    destination_port: str
    length: int | str


def _format_timestamp(pkt: Packet) -> str:
    """Format Scapy's packet timestamp as UTC ISO-8601 with milliseconds."""
    raw_timestamp = getattr(pkt, "time", None)
    if raw_timestamp is None:
        return ""

    try:
        timestamp = float(raw_timestamp)
    except (TypeError, ValueError, OverflowError):
        return ""

    if not math.isfinite(timestamp):
        return ""

    try:
        formatted = datetime.fromtimestamp(
            timestamp, tz=timezone.utc
        ).isoformat(timespec="milliseconds")
    except (OverflowError, OSError, ValueError):
        return ""

    return formatted.replace("+00:00", "Z")


def _packet_length(pkt: Packet) -> int | str:
    """Return the Scapy packet representation length, or blank if unavailable."""
    try:
        return len(pkt)
    except (
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        StructError,
        Scapy_Exception,
    ):
        return ""


def packet_summary(pkt: Packet) -> PacketSummary:
    """Return timestamp, IP/transport metadata, and length for a Scapy packet.

    The parser does not return or inspect application payload contents. Packet
    length is calculated from Scapy's packet representation.
    """
    if not isinstance(pkt, Packet):
        raise TypeError("packet_summary expects a Scapy Packet")

    timestamp = _format_timestamp(pkt)
    length = _packet_length(pkt)

    ip_layer = pkt.getlayer(IP)
    ip_version = 4

    if ip_layer is None:
        ip_layer = pkt.getlayer(IPv6)
        ip_version = 6

    if ip_layer is None:
        return {
            "timestamp": timestamp,
            "source_ip": "",
            "destination_ip": "",
            "protocol": "OTHER",
            "source_port": "",
            "destination_port": "",
            "length": length,
        }

    source_ip = str(getattr(ip_layer, "src", "") or "")
    destination_ip = str(getattr(ip_layer, "dst", "") or "")

    # Classify the upper layer immediately below the selected IP layer. For
    # IPv6, skip Scapy-decoded extension headers. This avoids accidentally
    # reporting a transport layer belonging to an encapsulated inner packet.
    transport = ip_layer.payload
    if ip_version == 6:
        visited: set[int] = set()
        while (
            transport is not None
            and type(transport).__name__.startswith("IPv6ExtHdr")
            and id(transport) not in visited
        ):
            visited.add(id(transport))
            transport = transport.payload

    protocol = "OTHER"
    source_port = ""
    destination_port = ""

    if isinstance(transport, TCP):
        protocol = "TCP"
        source_port = str(transport.sport)
        destination_port = str(transport.dport)
    elif isinstance(transport, UDP):
        protocol = "UDP"
        source_port = str(transport.sport)
        destination_port = str(transport.dport)
    elif isinstance(transport, ICMP) and ip_version == 4:
        protocol = "ICMP"
    elif (
        ip_version == 6
        and type(transport).__name__.startswith("ICMPv6")
    ):
        protocol = "ICMPv6"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "length": length,
    }
