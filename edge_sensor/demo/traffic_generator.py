"""
Synthetic Multi-Stage Traffic Generator
Generates realistic multi-stage enterprise telemetry for standalone edge sensor demonstration.
"""

import math
import random
import time
from typing import Generator
try:
    from ..core.packet_ingress import RawPacket
except (ImportError, ValueError):
    from core.packet_ingress import RawPacket


def generate_synthetic_traffic_stream(duration_seconds: float = 30.0, speed_multiplier: float = 1.0) -> Generator[RawPacket, None, None]:
    """
    Generates a live stream of raw packets cycling through MITRE ATT&CK stages:
    - 0s - 8s: Normal Enterprise Baseline (Web, DNS, Email)
    - 8s - 16s: Reconnaissance (SYN Port Sweeps across internal subnet)
    - 16s - 24s: Lateral Movement (SMB EternalBlue MS17-010 on port 445)
    - 24s - 30s: Exfiltration & Cooldown
    """
    start_time = time.time()
    current_time = start_time
    packet_seq = 0

    internal_hosts = ["192.168.10.12", "192.168.10.15", "192.168.10.19", "192.168.10.25"]
    victim_server = "192.168.10.50"
    attacker_ip = "192.168.10.44"

    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080]

    while (current_time - start_time) < duration_seconds:
        elapsed = current_time - start_time

        # Pacing delay
        if speed_multiplier > 0:
            sleep_time = random.uniform(0.015, 0.045) / speed_multiplier
            time.sleep(sleep_time)

        current_time = time.time()
        packet_seq += 1
        ts = current_time
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)

        # Stage 1: Benign Enterprise Baseline
        if elapsed < 8.0:
            client_ip = random.choice(internal_hosts)
            proto = "TCP" if random.random() < 0.85 else "UDP"
            if proto == "TCP":
                dst_port = 80 if random.random() < 0.6 else 443
                wire_len = random.randint(64, 1460)
                flags = "ACK" if random.random() < 0.7 else "SYN ACK"
            else:
                dst_port = 53
                wire_len = random.randint(70, 200)
                flags = ""

            yield RawPacket(
                timestamp=ts,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                wire_len=wire_len,
                cap_len=wire_len,
                eth_proto=0x0800,
                src_ip=client_ip,
                dst_ip="10.0.0.1" if dst_port == 53 else "172.217.16.206",
                protocol=proto,
                proto_num=6 if proto == "TCP" else 17,
                src_port=random.randint(49152, 65535),
                dst_port=dst_port,
                tcp_flags=flags,
                tcp_flag_bits=0x10 if "ACK" in flags else 0x02,
                payload_len=max(0, wire_len - 54),
                payload_preview=b"GET /index.html HTTP/1.1\r\n" if dst_port == 80 else b"",
            )

        # Stage 2: Reconnaissance Port Sweep
        elif elapsed < 16.0:
            target_port = scan_ports[packet_seq % len(scan_ports)]
            wire_len = 60
            yield RawPacket(
                timestamp=ts,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                wire_len=wire_len,
                cap_len=wire_len,
                eth_proto=0x0800,
                src_ip=attacker_ip,
                dst_ip=victim_server,
                protocol="TCP",
                proto_num=6,
                src_port=random.randint(40000, 60000),
                dst_port=target_port,
                tcp_flags="SYN",
                tcp_flag_bits=0x02,
                payload_len=0,
                payload_preview=b"",
            )

        # Stage 3: Lateral Movement / SMB Exploitation
        elif elapsed < 24.0:
            wire_len = random.randint(300, 1400)
            yield RawPacket(
                timestamp=ts,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                wire_len=wire_len,
                cap_len=wire_len,
                eth_proto=0x0800,
                src_ip=attacker_ip,
                dst_ip=victim_server,
                protocol="TCP",
                proto_num=6,
                src_port=49152 + (packet_seq % 10),
                dst_port=445,
                tcp_flags="PSH ACK",
                tcp_flag_bits=0x18,
                payload_len=wire_len - 54,
                payload_preview=b"\xffSMBs\x00\x00\x00\x00\x18\x07\xc8\x00\x00",
            )

        # Stage 4: Exfiltration & Cooldown
        else:
            wire_len = random.randint(600, 1400)
            yield RawPacket(
                timestamp=ts,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                wire_len=wire_len,
                cap_len=wire_len,
                eth_proto=0x0800,
                src_ip=attacker_ip,
                dst_ip="203.0.113.15",
                protocol="TCP",
                proto_num=6,
                src_port=random.randint(50000, 60000),
                dst_port=8080,
                tcp_flags="ACK PSH",
                tcp_flag_bits=0x18,
                payload_len=wire_len - 54,
                payload_preview=b"POST /upload HTTP/1.1\r\nHost: c2\r\n",
            )
