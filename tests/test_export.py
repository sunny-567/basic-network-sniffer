import csv
import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP

from src.export import CSVExportError, CSV_HEADERS, export_csv
from src.parser import packet_summary


class CSVExportTests(unittest.TestCase):
    def setUp(self):
        pkt = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
            sport=51514, dport=443
        )
        pkt.time = 1_700_000_000.123456
        self.summary = packet_summary(pkt)

    def test_csv_header_and_metadata_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.csv"
            exported = export_csv([self.summary], path)

            with exported.open(
                "r", newline="", encoding="utf-8-sig"
            ) as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(tuple(rows[0]), CSV_HEADERS)
        self.assertEqual(rows[1][0], "2023-11-14T22:13:20.123Z")
        self.assertEqual(rows[1][1:6], [
            "192.0.2.10",
            "198.51.100.20",
            "TCP",
            "51514",
            "443",
        ])
        self.assertEqual(rows[1][6], str(len(
            IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=51514, dport=443)
        )))

    def test_existing_file_is_not_overwritten_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.csv"
            export_csv([self.summary], path)

            with self.assertRaises(CSVExportError):
                export_csv([self.summary], path)

    def test_force_allows_explicit_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.csv"
            export_csv([self.summary], path)
            export_csv([], path, overwrite=True)

            with path.open(
                "r", newline="", encoding="utf-8-sig"
            ) as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(rows, [list(CSV_HEADERS)])

    def test_extra_payload_field_is_rejected(self):
        unsafe_row = dict(self.summary)
        unsafe_row["payload"] = "must-not-be-exported"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.csv"
            with self.assertRaises(CSVExportError):
                export_csv([unsafe_row], path)

    def test_empty_export_still_writes_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.csv"
            export_csv([], path)

            with path.open(
                "r", newline="", encoding="utf-8-sig"
            ) as stream:
                rows = list(csv.reader(stream))

        self.assertEqual(rows, [list(CSV_HEADERS)])

    def test_invalid_parent_path_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            parent_file = Path(directory) / "not_a_directory"
            parent_file.write_text("file", encoding="utf-8")
            output_path = parent_file / "metadata.csv"

            with self.assertRaises(CSVExportError):
                export_csv([self.summary], output_path)


if __name__ == "__main__":
    unittest.main()
