"""Bounded live and offline capture that retains metadata summaries only."""

from __future__ import annotations

import errno
import math
import time
from collections.abc import Callable
from pathlib import Path

from scapy.all import get_if_list, sniff
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapReader

from .parser import PacketSummary, packet_summary


DEFAULT_COUNT = 100
DEFAULT_TIMEOUT = 30.0
MAX_COUNT = 100_000
MAX_TIMEOUT_SECONDS = 3_600.0

StatusCallback = Callable[[str], None]


class CaptureError(RuntimeError):
    """Base class for live-capture failures."""


class InterfaceNotFoundError(CaptureError):
    """Raised when the requested interface is not available."""


class CapturePermissionError(CaptureError):
    """Raised when the operating system denies packet-capture access."""


class CaptureDriverError(CaptureError):
    """Raised when a supported packet-capture driver is unavailable."""


class PcapReadError(RuntimeError):
    """Raised when an offline PCAP cannot be read."""


def _validate_bounds(count: int, timeout: float) -> float:
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("count must be an integer")
    if not 1 <= count <= MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")

    if isinstance(timeout, bool):
        raise ValueError("timeout must be a positive finite number")
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("timeout must be a positive finite number") from exc

    if not math.isfinite(timeout_value) or not (
        0 < timeout_value <= MAX_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"timeout must be greater than 0 and no more than "
            f"{MAX_TIMEOUT_SECONDS:g} seconds"
        )

    return timeout_value


def _translate_capture_error(
    exc: Exception, interface: str | None
) -> CaptureError:
    message = str(exc).strip() or exc.__class__.__name__
    lower_message = message.lower()

    if isinstance(exc, PermissionError) or getattr(exc, "errno", None) in {
        errno.EACCES,
        errno.EPERM,
    }:
        return CapturePermissionError(
            "The operating system denied packet capture. Use an approved "
            "account and permitted interface; do not bypass security policy. "
            "On Windows, verify that an approved Npcap installation is "
            "available."
        )

    driver_markers = (
        "npcap",
        "winpcap",
        "libpcap",
        "no libpcap provider",
        "packet capture driver",
    )
    if any(marker in lower_message for marker in driver_markers):
        return CaptureDriverError(
            "A packet-capture driver/backend is unavailable. On Windows, "
            "install or repair Npcap using your organization's approved "
            "installation process."
        )

    interface_markers = (
        "no such device",
        "unknown interface",
        "invalid interface",
        "interface not found",
        "device not found",
    )
    if interface and any(
        marker in lower_message for marker in interface_markers
    ):
        return InterfaceNotFoundError(
            f"Could not use interface {interface!r}: {message}"
        )

    return CaptureError(f"Packet capture failed: {message}")


def capture_metadata(
    count: int = DEFAULT_COUNT,
    timeout: float = DEFAULT_TIMEOUT,
    interface: str | None = None,
    *,
    status: StatusCallback = print,
) -> list[PacketSummary]:
    """Capture live traffic and retain only packet metadata summaries.

    Scapy receives a packet transiently in its callback, but ``store=False``
    prevents Scapy from retaining a packet list. The callback immediately
    converts each packet to metadata.
    """
    timeout_value = _validate_bounds(count, timeout)

    interface_description = (
        repr(interface) if interface is not None else "Scapy default"
    )
    status(
        f"Starting bounded live capture: max_packets={count}, "
        f"timeout={timeout_value:g}s, interface={interface_description}."
    )

    if interface is not None:
        try:
            available_interfaces = [str(item) for item in get_if_list()]
        except Exception as exc:
            raise _translate_capture_error(exc, interface) from exc

        if (
            available_interfaces
            and interface not in available_interfaces
        ):
            available = ", ".join(available_interfaces)
            raise InterfaceNotFoundError(
                f"Interface {interface!r} was not found. Available interfaces: "
                f"{available}"
            )

    summaries: list[PacketSummary] = []

    def record_metadata(pkt: Packet) -> None:
        summaries.append(packet_summary(pkt))

    sniff_options: dict[str, object] = {
        "count": count,
        "timeout": timeout_value,
        "store": False,
        "prn": record_metadata,
    }
    if interface is not None:
        sniff_options["iface"] = interface

    try:
        sniff(**sniff_options)
    except KeyboardInterrupt:
        status(
            "Capture interrupted by Ctrl+C; keeping "
            f"{len(summaries)} metadata record(s) already processed."
        )
        return summaries
    except Exception as exc:
        raise _translate_capture_error(exc, interface) from exc

    status(
        f"Capture completed: {len(summaries)} metadata record(s)."
    )
    return summaries


def read_pcap_metadata(
    path: str | Path,
    count: int = DEFAULT_COUNT,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    status: StatusCallback = print,
) -> list[PacketSummary]:
    """Read a bounded number of packets from an authorized PCAP file.

    Packet objects are summarized one at a time and are not retained in the
    returned list. The timeout is checked between packets.
    """
    timeout_value = _validate_bounds(count, timeout)
    pcap_path = Path(path).expanduser()

    if not pcap_path.is_file():
        raise PcapReadError(f"PCAP file does not exist or is not a file: {pcap_path}")

    status(
        f"Reading authorized PCAP: {pcap_path} "
        f"(max_packets={count}, timeout={timeout_value:g}s)."
    )

    summaries: list[PacketSummary] = []
    reader = None
    started = time.monotonic()
    interrupted = False

    try:
        reader = PcapReader(str(pcap_path))
        while (
            len(summaries) < count
            and time.monotonic() - started < timeout_value
        ):
            try:
                pkt = next(reader)
            except StopIteration:
                break

            summaries.append(packet_summary(pkt))
            del pkt
    except KeyboardInterrupt:
        interrupted = True
        status(
            "PCAP reading interrupted by Ctrl+C; keeping "
            f"{len(summaries)} metadata record(s) already processed."
        )
    except (OSError, Scapy_Exception, ValueError) as exc:
        raise PcapReadError(
            f"Could not read PCAP file {pcap_path}: {exc}"
        ) from exc
    except Exception as exc:
        raise PcapReadError(
            f"PCAP processing failed for {pcap_path}: {exc}"
        ) from exc
    finally:
        if reader is not None:
            reader.close()

    if not interrupted:
        status(
            f"PCAP read completed: {len(summaries)} metadata record(s)."
        )

    return summaries
