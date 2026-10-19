"""Validated, metadata-only CSV export."""

from __future__ import annotations

import csv
import ipaddress
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path

from .parser import METADATA_FIELDS, PacketSummary


CSV_HEADERS: tuple[str, ...] = (
    "TIME",
    "SOURCE IP",
    "DESTINATION IP",
    "PROTOCOL",
    "SOURCE PORT",
    "DESTINATION PORT",
    "LENGTH",
)

_ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPv6", "OTHER"}
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


class CSVExportError(RuntimeError):
    """Raised when a metadata CSV cannot be safely exported."""


def _validate_ip(value: str, field: str, row_number: int) -> None:
    if not value:
        return
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise CSVExportError(
            f"Row {row_number}: {field} is not a valid IP address"
        ) from exc


def _validate_port(value: str, field: str, row_number: int) -> None:
    if value == "":
        return
    if not value.isascii() or not value.isdecimal():
        raise CSVExportError(
            f"Row {row_number}: {field} must be blank or a numeric port"
        )
    if not 0 <= int(value) <= 65535:
        raise CSVExportError(
            f"Row {row_number}: {field} is outside the valid port range"
        )


def _validated_rows(
    summaries: Iterable[Mapping[str, object]],
) -> list[PacketSummary]:
    rows: list[PacketSummary] = []
    expected_fields = set(METADATA_FIELDS)

    for row_number, summary in enumerate(summaries, start=1):
        if not isinstance(summary, Mapping):
            raise CSVExportError(f"Row {row_number} is not a metadata mapping")

        if set(summary.keys()) != expected_fields:
            raise CSVExportError(
                f"Row {row_number} must contain exactly these metadata fields: "
                f"{', '.join(METADATA_FIELDS)}. Payload or extra fields are "
                "not accepted."
            )

        values: dict[str, object] = {
            field: summary[field] for field in METADATA_FIELDS
        }

        for field in METADATA_FIELDS[:-1]:
            if type(values[field]) is not str:
                raise CSVExportError(
                    f"Row {row_number}: {field} must be a string"
                )

        timestamp = values["timestamp"]
        assert isinstance(timestamp, str)
        if timestamp:
            if not _TIMESTAMP_RE.fullmatch(timestamp):
                raise CSVExportError(
                    f"Row {row_number}: timestamp must use UTC ISO-8601 "
                    "with milliseconds"
                )
            try:
                from datetime import datetime

                datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError as exc:
                raise CSVExportError(
                    f"Row {row_number}: timestamp is not a valid date/time"
                ) from exc

        source_ip = values["source_ip"]
        destination_ip = values["destination_ip"]
        protocol = values["protocol"]
        source_port = values["source_port"]
        destination_port = values["destination_port"]
        length = values["length"]

        assert isinstance(source_ip, str)
        assert isinstance(destination_ip, str)
        assert isinstance(protocol, str)
        assert isinstance(source_port, str)
        assert isinstance(destination_port, str)

        _validate_ip(source_ip, "source_ip", row_number)
        _validate_ip(destination_ip, "destination_ip", row_number)

        if protocol not in _ALLOWED_PROTOCOLS:
            raise CSVExportError(
                f"Row {row_number}: unrecognized protocol value"
            )

        _validate_port(source_port, "source_port", row_number)
        _validate_port(destination_port, "destination_port", row_number)

        if protocol not in {"TCP", "UDP"} and (
            source_port or destination_port
        ):
            raise CSVExportError(
                f"Row {row_number}: ports are only allowed for TCP or UDP"
            )

        if length != "" and (type(length) is not int or length < 0):
            raise CSVExportError(
                f"Row {row_number}: length must be a non-negative integer "
                "or blank"
            )

        rows.append(
            {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "length": length,
            }
        )

    return rows


def _write_csv(stream, rows: list[PacketSummary]) -> None:
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(CSV_HEADERS)
    for row in rows:
        writer.writerow([row[field] for field in METADATA_FIELDS])


def _write_exclusive(destination: Path, rows: list[PacketSummary]) -> None:
    """Create a new file atomically with restrictive permissions where supported."""
    descriptor: int | None = None
    created = False

    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        created = True

        with os.fdopen(
            descriptor, "w", newline="", encoding="utf-8-sig"
        ) as stream:
            descriptor = None
            _write_csv(stream, rows)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _write_replacement(destination: Path, rows: list[PacketSummary]) -> None:
    """Write a temporary file and replace the destination only after success."""
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8-sig",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            _write_csv(stream, rows)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def export_csv(
    summaries: Iterable[Mapping[str, object]],
    path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
) -> Path:
    """Export validated metadata to CSV.

    Existing files are never overwritten unless ``overwrite=True``. The CSV
    contains only the defined metadata columns.
    """
    rows = _validated_rows(summaries)

    try:
        raw_path = os.fspath(path)
        if not raw_path:
            raise CSVExportError("The output path cannot be empty")
        destination = Path(raw_path).expanduser()
    except (TypeError, ValueError) as exc:
        if isinstance(exc, CSVExportError):
            raise
        raise CSVExportError("The output path is invalid") from exc

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if overwrite:
            _write_replacement(destination, rows)
        else:
            _write_exclusive(destination, rows)
    except FileExistsError as exc:
        if destination.exists():
            message = (
                f"{destination} already exists. Choose another --output path "
                "or pass --force to explicitly overwrite it."
            )
        else:
            message = f"Could not create the output path {destination}: {exc}"
        raise CSVExportError(message) from exc
    except (OSError, csv.Error, UnicodeError) as exc:
        raise CSVExportError(
            f"Could not write CSV to {destination}: {exc}"
        ) from exc

    return destination
