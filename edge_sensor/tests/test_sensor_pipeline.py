"""
Edge Sensor Agent — Unit Test Suite
Verifies packet dissection, bidirectional flow tracking, 54-D state vector extraction,
and zero-latency edge sentinel heuristic alerts.
"""

import os
import struct
import unittest
from edge_sensor.core.packet_ingress import PacketIngress, RawPacket
from edge_sensor.core.flow_tracker import FlowTracker
from edge_sensor.core.feature_extractor import FeatureExtractor, FEATURE_NAMES
from edge_sensor.core.edge_sentinel import EdgeSentinel


class TestEdgeSensorPipeline(unittest.TestCase):

    def _create_synthetic_raw_frame(
        self,
        src_ip: str = "192.168.10.44",
        dst_ip: str = "192.168.10.12",
        src_port: int = 51200,
        dst_port: int = 445,
        flags: int = 0x02,  # SYN
        payload: bytes = b"TEST",
    ) -> bytes:
        """Constructs an Ethernet + IPv4 + TCP raw byte frame."""
        # 1. Ethernet Header (14 bytes): Dst MAC, Src MAC, EtherType (0x0800 IPv4)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

        # 2. IPv4 Header (20 bytes)
        src_bytes = bytes(map(int, src_ip.split(".")))
        dst_bytes = bytes(map(int, dst_ip.split(".")))
        total_ip_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total_ip_len, 0x1234, 0x4000, 64, 6, 0x0000,
            src_bytes, dst_bytes
        )

        # 3. TCP Header (20 bytes)
        data_offset_and_reserved = (5 << 4)  # 5 32-bit words = 20 bytes
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port, 1000, 0, data_offset_and_reserved, flags, 65535, 0x0000, 0
        )

        return eth_hdr + ip_hdr + tcp_hdr + payload

    def test_packet_dissection(self):
        frame = self._create_synthetic_raw_frame(
            src_ip="10.0.4.15", dst_ip="10.0.4.100", src_port=54321, dst_port=80, flags=0x12  # SYN ACK
        )
        packet = PacketIngress.dissect_ethernet_frame(frame, ts=1718000000.5)
        self.assertIsNotNone(packet)
        self.assertEqual(packet.src_ip, "10.0.4.15")
        self.assertEqual(packet.dst_ip, "10.0.4.100")
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.src_port, 54321)
        self.assertEqual(packet.dst_port, 80)
        self.assertIn("SYN", packet.tcp_flags)
        self.assertIn("ACK", packet.tcp_flags)
        self.assertEqual(packet.payload_len, 4)

    def test_bidirectional_flow_tracking(self):
        tracker = FlowTracker()

        # Forward SYN from Client -> Server
        fwd_frame = self._create_synthetic_raw_frame(
            src_ip="192.168.1.50", dst_ip="192.168.1.1", src_port=50000, dst_port=443, flags=0x02
        )
        p1 = PacketIngress.dissect_ethernet_frame(fwd_frame, ts=100.0)
        flow1 = tracker.update(p1)

        # Reverse SYN-ACK from Server -> Client
        rev_frame = self._create_synthetic_raw_frame(
            src_ip="192.168.1.1", dst_ip="192.168.1.50", src_port=443, dst_port=50000, flags=0x12
        )
        p2 = PacketIngress.dissect_ethernet_frame(rev_frame, ts=100.02)
        flow2 = tracker.update(p2)

        # Assert grouped into same flow session
        self.assertEqual(flow1.flow_id, flow2.flow_id)
        self.assertEqual(flow2.fwd_packets, 1)
        self.assertEqual(flow2.bwd_packets, 1)
        self.assertEqual(flow2.total_packets, 2)
        self.assertEqual(flow2.tcp_state, "SYN_ACK_RECEIVED")

    def test_feature_extraction_54d(self):
        extractor = FeatureExtractor(window_seconds=2.0)
        tracker = FlowTracker()

        # Ingest 15 packets spanning various ports
        for i in range(15):
            frame = self._create_synthetic_raw_frame(
                src_ip="192.168.1.10", dst_ip="192.168.1.20", src_port=49000 + i, dst_port=80 if i % 2 == 0 else 445
            )
            pkt = PacketIngress.dissect_ethernet_frame(frame, ts=100.0 + i * 0.1)
            flow = tracker.update(pkt)
            extractor.add_packet(pkt, flow)

        window = extractor.flush()
        self.assertIsNotNone(window)
        self.assertEqual(len(window.vector_54), 54)
        self.assertEqual(len(FEATURE_NAMES), 54)
        self.assertEqual(window.packet_count, 15)
        self.assertGreater(window.feature_dict["byte_rate"], 0.0)
        self.assertGreater(window.feature_dict["auth_port_ratio"], 0.0)  # Port 445 present

    def test_edge_sentinel_heuristics(self):
        extractor = FeatureExtractor(window_seconds=2.0)
        tracker = FlowTracker()
        sentinel = EdgeSentinel()

        # Simulate Port Sweep (many unique ports -> high entropy)
        ports = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3389]
        for idx, p in enumerate(ports):
            frame = self._create_synthetic_raw_frame(
                src_ip="10.0.0.99", dst_ip="10.0.0.1", src_port=40000 + idx, dst_port=p, flags=0x02
            )
            pkt = PacketIngress.dissect_ethernet_frame(frame, ts=200.0 + idx * 0.05)
            flow = tracker.update(pkt)
            extractor.add_packet(pkt, flow)

        window = extractor.flush()
        alerts = sentinel.evaluate(window)

        self.assertGreater(len(alerts), 0)
        recon_alert = next((a for a in alerts if a.technique_id == "T1046"), None)
        self.assertIsNotNone(recon_alert)
        self.assertEqual(recon_alert.threat_type, "Reconnaissance Sweep")

    def test_pcap_read_sample(self):
        sample_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../sample_captures/sample_2_ransomware_eternalblue_smb.pcap")
        )
        if os.path.exists(sample_path):
            packets = list(PacketIngress.read_pcap(sample_path))
            self.assertGreater(len(packets), 50)
            self.assertEqual(packets[0].protocol, "TCP")
            self.assertTrue(any(p.dst_port == 445 for p in packets))


if __name__ == "__main__":
    unittest.main()
