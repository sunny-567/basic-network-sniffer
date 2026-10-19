import contextlib
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.export import CSV_HEADERS
from src.main import build_arg_parser, main


class CommandLineTests(unittest.TestCase):
    def test_invalid_count_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build_arg_parser().parse_args(["--count", "0"])

    def test_invalid_timeout_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build_arg_parser().parse_args(["--timeout", "nan"])

    def test_interface_and_pcap_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "example.pcap"
            pcap_path.write_bytes(b"not-read-by-this-argument-test")

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(
                        [
                            "--read-pcap",
                            str(pcap_path),
                            "--interface",
                            "eth0",
                        ]
                    )

    def test_empty_capture_prints_summary_and_exports_header(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "empty.csv"
            console = io.StringIO()

            with (
                patch("src.main.capture_metadata", return_value=[]),
                contextlib.redirect_stdout(console),
            ):
                result = main(
                    [
                        "--count",
                        "1",
                        "--timeout",
                        "1",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(result, 0)
            self.assertIn("No packets were captured", console.getvalue())
            self.assertIn("Total packets: 0", console.getvalue())

            with output_path.open(
                "r", newline="", encoding="utf-8-sig"
            ) as stream:
                rows = list(csv.reader(stream))

            self.assertEqual(rows, [list(CSV_HEADERS)])


if __name__ == "__main__":
    unittest.main()
