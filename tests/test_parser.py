import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from src.parser import METADATA_FIELDS, packet_summary


class PacketSummaryTests(unittest.TestCase):
    def test_ipv4_tcp_metadata_and_length(self):
        pkt = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
            sport=49152, dport=443
        )
        pkt.time = 1_700_000_000.123456

        summary = packet_summary(pkt)

        self.assertEqual(summary["timestamp"], "2023-11-14T22:13:20.123Z")
        self.assertEqual(summary["source_ip"], "192.0.2.10")
        self.assertEqual(summary["destination_ip"], "198.51.100.20")
        self.assertEqual(summary["protocol"], "TCP")
        self.assertEqual(summary["source_port"], "49152")
        self.assertEqual(summary["destination_port"], "443")
        self.assertEqual(summary["length"], len(pkt))

    def test_ipv4_udp_metadata(self):
        pkt = IP(src="192.0.2.1", dst="198.51.100.2") / UDP(
            sport=53000, dport=53
        )

        summary = packet_summary(pkt)

        self.assertEqual(summary["protocol"], "UDP")
        self.assertEqual(summary["source_port"], "53000")
        self.assertEqual(summary["destination_port"], "53")
        self.assertEqual(summary["length"], len(pkt))

    def test_icmp_has_blank_ports(self):
        pkt = IP(src="203.0.113.1", dst="192.0.2.2") / ICMP()

        summary = packet_summary(pkt)

        self.assertEqual(summary["protocol"], "ICMP")
        self.assertEqual(summary["source_port"], "")
        self.assertEqual(summary["destination_port"], "")
        self.assertEqual(summary["length"], len(pkt))

    def test_packet_without_ip_layer_is_safe(self):
        pkt = Ether() / ARP()

        summary = packet_summary(pkt)

        self.assertEqual(summary["protocol"], "OTHER")
        self.assertEqual(summary["source_ip"], "")
        self.assertEqual(summary["destination_ip"], "")
        self.assertEqual(summary["source_port"], "")
        self.assertEqual(summary["destination_port"], "")
        self.assertEqual(summary["length"], len(pkt))

    def test_unknown_ipv4_protocol_is_other(self):
        pkt = IP(src="192.0.2.1", dst="198.51.100.1", proto=47) / Raw(
            load=b"synthetic"
        )

        summary = packet_summary(pkt)

        self.assertEqual(summary["protocol"], "OTHER")
        self.assertEqual(summary["source_port"], "")
        self.assertEqual(summary["destination_port"], "")

    def test_ipv6_tcp_is_supported(self):
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
            sport=12345, dport=443
        )

        summary = packet_summary(pkt)

        self.assertEqual(summary["source_ip"], "2001:db8::1")
        self.assertEqual(summary["destination_ip"], "2001:db8::2")
        self.assertEqual(summary["protocol"], "TCP")
        self.assertEqual(summary["source_port"], "12345")
        self.assertEqual(summary["destination_port"], "443")

    def test_ipv6_icmp_has_no_ports(self):
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()

        summary = packet_summary(pkt)

        self.assertEqual(summary["protocol"], "ICMPv6")
        self.assertEqual(summary["source_port"], "")
        self.assertEqual(summary["destination_port"], "")

    def test_payload_contents_are_not_returned(self):
        marker = "synthetic-not-a-real-password"
        pkt = (
            IP(src="192.0.2.1", dst="198.51.100.1")
            / TCP(sport=1234, dport=443)
            / Raw(load=marker.encode("ascii"))
        )

        summary = packet_summary(pkt)

        self.assertNotIn(marker, repr(summary))
        self.assertEqual(tuple(summary.keys()), METADATA_FIELDS)
        self.assertEqual(summary["length"], len(pkt))

    def test_invalid_timestamp_is_blank(self):
        pkt = IP() / UDP()
        pkt.time = float("nan")

        self.assertEqual(packet_summary(pkt)["timestamp"], "")

    def test_dictionary_keys_and_order_are_consistent(self):
        summaries = [
            packet_summary(IP() / TCP()),
            packet_summary(IP() / UDP()),
            packet_summary(Ether() / ARP()),
        ]

        for summary in summaries:
            self.assertEqual(tuple(summary.keys()), METADATA_FIELDS)

    def test_non_scapy_input_is_rejected(self):
        with self.assertRaises(TypeError):
            packet_summary(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
