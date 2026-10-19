import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from src.capture import (
    CapturePermissionError,
    InterfaceNotFoundError,
    capture_metadata,
    read_pcap_metadata,
)


class CaptureTests(unittest.TestCase):
    def test_capture_uses_count_timeout_and_does_not_store_packets(self):
        pkt = IP(src="192.0.2.1", dst="198.51.100.1") / TCP(
            sport=1000, dport=443
        )
        messages = []

        def fake_sniff(**options):
            options["prn"](pkt)

        with (
            patch("src.capture.get_if_list", return_value=["eth0"]),
            patch("src.capture.sniff", side_effect=fake_sniff) as sniff_mock,
        ):
            summaries = capture_metadata(
                count=5,
                timeout=2.5,
                interface="eth0",
                status=messages.append,
            )

        options = sniff_mock.call_args.kwargs
        self.assertEqual(options["count"], 5)
        self.assertEqual(options["timeout"], 2.5)
        self.assertIs(options["store"], False)
        self.assertEqual(options["iface"], "eth0")
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["protocol"], "TCP")
        self.assertIn("Capture completed", messages[-1])

    def test_omitted_interface_uses_scapy_default(self):
        with patch("src.capture.sniff", return_value=None) as sniff_mock:
            summaries = capture_metadata(
                count=1, timeout=1, status=lambda _: None
            )

        self.assertEqual(summaries, [])
        self.assertNotIn("iface", sniff_mock.call_args.kwargs)

    def test_empty_capture_returns_empty_metadata_list(self):
        with patch("src.capture.sniff", return_value=None):
            summaries = capture_metadata(
                count=2, timeout=1, status=lambda _: None
            )

        self.assertEqual(summaries, [])

    def test_invalid_interface_is_reported(self):
        with (
            patch("src.capture.get_if_list", return_value=["eth0"]),
            patch("src.capture.sniff") as sniff_mock,
        ):
            with self.assertRaises(InterfaceNotFoundError):
                capture_metadata(
                    count=1,
                    timeout=1,
                    interface="missing0",
                    status=lambda _: None,
                )

        sniff_mock.assert_not_called()

    def test_permission_error_is_reported(self):
        with (
            patch("src.capture.get_if_list", return_value=["eth0"]),
            patch(
                "src.capture.sniff",
                side_effect=PermissionError("permission denied"),
            ),
        ):
            with self.assertRaises(CapturePermissionError):
                capture_metadata(
                    count=1,
                    timeout=1,
                    interface="eth0",
                    status=lambda _: None,
                )

    def test_ctrl_c_returns_already_processed_metadata(self):
        pkt = IP() / TCP()
        messages = []

        def fake_sniff(**options):
            options["prn"](pkt)
            raise KeyboardInterrupt

        with patch("src.capture.sniff", side_effect=fake_sniff):
            summaries = capture_metadata(
                count=5, timeout=10, status=messages.append
            )

        self.assertEqual(len(summaries), 1)
        self.assertIn("interrupted by Ctrl+C", messages[-1])

    def test_invalid_capture_bounds_are_rejected(self):
        with self.assertRaises(ValueError):
            capture_metadata(count=0, status=lambda _: None)
        with self.assertRaises(ValueError):
            capture_metadata(count=1, timeout=0, status=lambda _: None)

    def test_pcap_read_uses_same_metadata_parser_and_count_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "synthetic.pcap"
            packets = [
                IP(src="192.0.2.1", dst="198.51.100.1")
                / TCP(sport=1000, dport=443),
                IP(src="192.0.2.2", dst="198.51.100.2")
                / TCP(sport=1001, dport=443),
            ]
            wrpcap(str(pcap_path), packets)

            summaries = read_pcap_metadata(
                pcap_path,
                count=1,
                timeout=10,
                status=lambda _: None,
            )

        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["protocol"], "TCP")
        self.assertEqual(summaries[0]["source_port"], "1000")


if __name__ == "__main__":
    unittest.main()
