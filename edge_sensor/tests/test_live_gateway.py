"""
Unit tests for LiveEdgeGateway and interactive ingress verification.
"""

import json
import os
import unittest
import urllib.request
from edge_sensor.core.live_gateway import LiveEdgeGateway, get_lan_ip, get_device_summary


class TestLiveGateway(unittest.TestCase):

    def setUp(self):
        self.port = 8899
        self.log_path = "test_live_ingress.log"
        self.gateway = LiveEdgeGateway(
            host="127.0.0.1",
            port=self.port,
            log_path=self.log_path,
            sensor_id="test-sensor-gw-01",
        )
        self.gateway.start()

    def tearDown(self):
        self.gateway.stop()
        if os.path.exists(self.log_path):
            try:
                os.remove(self.log_path)
            except Exception:
                pass

    def test_lan_ip_detection(self):
        ip = get_lan_ip()
        self.assertIsInstance(ip, str)
        self.assertTrue(len(ip.split(".")) == 4)

    def test_user_agent_parser(self):
        self.assertIn("iPhone", get_device_summary("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"))
        self.assertIn("Android", get_device_summary("Mozilla/5.0 (Linux; Android 14; Pixel 8)"))
        self.assertIn("Windows", get_device_summary("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))
        self.assertIn("Mac", get_device_summary("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"))

    def test_get_mobile_portal(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/",
            headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile/15E148"},
        )
        with urllib.request.urlopen(req) as response:
            self.assertEqual(response.status, 200)
            content = response.read().decode("utf-8")
            self.assertIn("Aegis Vantage Edge Sensor", content)
            self.assertIn("predictionChart", content)

        # Verify packet was placed in ingress queue
        self.assertFalse(self.gateway.packet_queue.empty())
        pkt = self.gateway.packet_queue.get()
        self.assertEqual(pkt.protocol, "TCP")
        self.assertEqual(pkt.src_ip, "127.0.0.1")
        self.assertEqual(pkt.dst_port, self.port)

        # Verify device registration
        devices = self.gateway.get_connected_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "127.0.0.1")
        self.assertEqual(devices[0]["device"], "Apple iPhone (iOS)")

    def test_post_action_burst(self):
        payload = json.dumps({"action": "recon"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/action",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Judge Mobile Node"},
        )
        with urllib.request.urlopen(req) as response:
            self.assertEqual(response.status, 200)
            res_json = json.loads(response.read().decode("utf-8"))
            self.assertEqual(res_json["status"], "success")
            self.assertGreater(res_json["packets_injected"], 0)

        # Drain injected packets
        packets = []
        while not self.gateway.packet_queue.empty():
            packets.append(self.gateway.packet_queue.get())
        self.assertGreater(len(packets), 5)

        # Verify structured log write
        logs = self.gateway.get_recent_logs()
        self.assertTrue(any("RECON_SWEEP" in l for l in logs))

    def test_get_telemetry(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/telemetry")
        with urllib.request.urlopen(req) as response:
            self.assertEqual(response.status, 200)
            data = json.loads(response.read().decode("utf-8"))
            self.assertIn("probability", data)
            self.assertIn("timeline", data)
            self.assertIn("stage", data)
            self.assertIn("entropy", data)
            self.assertIsInstance(data["timeline"], list)


if __name__ == "__main__":
    unittest.main()
