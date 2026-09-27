"""
Packet Ingress Engine
High-performance raw packet parser supporting binary libpcap streams and live interface taps.
Zero third-party dependencies: uses standard library struct and socket modules.
"""

import os
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Generator, Optional, Tuple


@dataclass
class RawPacket:
    """Dissected packet metadata extracted at network edge."""
    timestamp: float        # Epoch seconds (float with microsecond precision)
    ts_sec: int
    ts_usec: int
    wire_len: int           # Original wire length
    cap_len: int            # Captured length
    eth_proto: int          # 0x0800 (IPv4), 0x86DD (IPv6), etc.
    src_ip: str
    dst_ip: str
    protocol: str           # 'TCP', 'UDP', 'ICMP', or 'OTHER'
    proto_num: int          # 6 (TCP), 17 (UDP), 1 (ICMP)
    src_port: int
    dst_port: int
    tcp_flags: str          # Space-separated: 'SYN ACK PSH' etc.
    tcp_flag_bits: int      # Raw 8-bit TCP flag mask
    payload_len: int
    payload_preview: bytes  # First up to 32 bytes of payload


class PacketIngress:
    """
    Edge packet capture and replay engine.
    Supports streaming from physical libpcap dump files or opening live raw sockets.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.running = False
        self.packets_captured = 0
        self.bytes_captured = 0

    @staticmethod
    def dissect_ethernet_frame(data: bytes, ts: float = 0.0, ts_sec: int = 0, ts_usec: int = 0) -> Optional[RawPacket]:
        """Dissects a raw Ethernet frame into an IPv4/TCP/UDP RawPacket."""
        if len(data) < 14:
            return None

        # Ethernet Header: Dest MAC (6), Src MAC (6), EtherType (2)
        eth_type = struct.unpack("!H", data[12:14])[0]
        offset = 14

        # 802.1Q VLAN Tag check (0x8100)
        if eth_type == 0x8100 and len(data) >= 18:
            eth_type = struct.unpack("!H", data[16:18])[0]
            offset = 18

        if eth_type != 0x0800:
            # Non-IPv4 (IPv6 0x86DD, ARP 0x0806, etc.)
            return None

        if len(data) < offset + 20:
            return None

        # IPv4 Header
        ip_header = data[offset:offset + 20]
        v_ihl = ip_header[0]
        ihl = (v_ihl & 0x0F) * 4
        if len(data) < offset + ihl:
            return None

        total_ip_len = struct.unpack("!H", ip_header[2:4])[0]
        proto_num = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        transport_offset = offset + ihl
        transport_data = data[transport_offset:]

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        tcp_flags = ""
        tcp_flag_bits = 0
        payload_len = 0
        payload_preview = b""

        if proto_num == 6 and len(transport_data) >= 14:
            # TCP Header (min 20 bytes for full header, but ports + flags need 14 bytes)
            protocol = "TCP"
            src_port, dst_port = struct.unpack("!HH", transport_data[0:4])
            if len(transport_data) >= 14:
                data_offset_byte = transport_data[12]
                tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4
                tcp_flag_bits = transport_data[13]

                flag_parts = []
                if tcp_flag_bits & 0x02: flag_parts.append("SYN")
                if tcp_flag_bits & 0x10: flag_parts.append("ACK")
                if tcp_flag_bits & 0x04: flag_parts.append("RST")
                if tcp_flag_bits & 0x01: flag_parts.append("FIN")
                if tcp_flag_bits & 0x08: flag_parts.append("PSH")
                if tcp_flag_bits & 0x20: flag_parts.append("URG")
                tcp_flags = " ".join(flag_parts)

                payload_start = transport_offset + tcp_header_len
                payload_len = max(0, len(data) - payload_start)
                payload_preview = data[payload_start:payload_start + 32]

        elif proto_num == 17 and len(transport_data) >= 8:
            # UDP Header: SrcPort (2), DstPort (2), Length (2), Checksum (2)
            protocol = "UDP"
            src_port, dst_port, udp_len = struct.unpack("!HHH", transport_data[0:6])
            payload_start = transport_offset + 8
            payload_len = max(0, udp_len - 8)
            payload_preview = data[payload_start:payload_start + 32]

        elif proto_num == 1:
            protocol = "ICMP"
            if len(transport_data) >= 4:
                src_port = transport_data[0] # ICMP Type
                dst_port = transport_data[1] # ICMP Code

        return RawPacket(
            timestamp=ts if ts > 0 else time.time(),
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            wire_len=len(data),
            cap_len=len(data),
            eth_proto=eth_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            proto_num=proto_num,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            tcp_flag_bits=tcp_flag_bits,
            payload_len=payload_len,
            payload_preview=payload_preview,
        )

    @classmethod
    def read_pcap(cls, file_path: str) -> Generator[RawPacket, None, None]:
        """
        Reads and dissects packets from a standard binary libpcap capture file.
        Supports both little-endian and big-endian PCAP encodings.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        with open(file_path, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic = struct.unpack("<I", global_header[0:4])[0]
            if magic in (0xA1B2C3D4, 0xA1B23C4D):
                endianness = "<"
            elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
                endianness = ">"
            else:
                # Try raw parsing or fallback
                return

            while True:
                packet_hdr = f.read(16)
                if len(packet_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    f"{endianness}IIII", packet_hdr
                )
                packet_bytes = f.read(incl_len)
                if len(packet_bytes) < incl_len:
                    break

                ts = ts_sec + (ts_usec / 1e6)
                packet = cls.dissect_ethernet_frame(packet_bytes, ts=ts, ts_sec=ts_sec, ts_usec=ts_usec)
                if packet:
                    packet.wire_len = orig_len
                    packet.cap_len = incl_len
                    yield packet

    @classmethod
    def stream_pcap_paced(
        cls, file_path: str, speed_multiplier: float = 1.0
    ) -> Generator[RawPacket, None, None]:
        """
        Streams a PCAP file at a realistic pacing rate.
        speed_multiplier: 1.0 = real-time, 5.0 = 5x faster, 0.0 = unthrottled maximum speed.
        """
        last_pkt_ts: Optional[float] = None
        last_wall_time: Optional[float] = None

        for packet in cls.read_pcap(file_path):
            if speed_multiplier > 0.0 and last_pkt_ts is not None and last_wall_time is not None:
                delta_pkt = packet.timestamp - last_pkt_ts
                if 0 < delta_pkt < 10.0:  # Cap at reasonable sleep to avoid stalls
                    target_sleep = delta_pkt / speed_multiplier
                    elapsed = time.time() - last_wall_time
                    remaining = target_sleep - elapsed
                    if remaining > 0.001:
                        time.sleep(remaining)

            last_pkt_ts = packet.timestamp
            last_wall_time = time.time()
            yield packet

    @classmethod
    def open_live_interface(
        cls, interface: Optional[str] = None, stop_event: Optional[Any] = None
    ) -> Generator[RawPacket, None, None]:
        """
        Passively sniffs real live network frames directly from the host operating system's network interface.
        - On Linux (servers/containers): uses socket.AF_PACKET for high-speed zero-copy raw capture.
        - On Windows: uses socket.IPPROTO_IP with SIO_RCVALL promiscuous mode.
        """
        # 1. Linux / Container Raw AF_PACKET Tap
        if hasattr(socket, "AF_PACKET"):
            try:
                # 0x0003 = ETH_P_ALL (capture all protocols: IPv4, IPv6, ARP)
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if interface:
                    s.bind((interface, 0))
            except PermissionError as e:
                print(f"\n[!] Access Denied: Raw packet capture on Linux requires root or CAP_NET_RAW capability: {e}")
                print("[*] In Docker / Kubernetes: Add '--cap-add=NET_RAW --net=host' to container flags.\n")
                return
            try:
                s.settimeout(0.2)
                while True:
                    if stop_event and stop_event.is_set():
                        break
                    try:
                        data = s.recv(65535)
                    except socket.timeout:
                        continue
                    now = time.time()
                    pkt = cls.dissect_ethernet_frame(data, ts=now, ts_sec=int(now), ts_usec=int((now % 1) * 1e6))
                    if pkt:
                        yield pkt
            finally:
                s.close()

        # 2. Windows Raw IP Socket Tap
        elif sys.platform == "win32":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                host_ip = interface if interface else socket.gethostbyname(socket.gethostname())
                s.bind((host_ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except (PermissionError, OSError) as e:
                print("\n[!] Access Denied: Windows raw packet interface sniffing requires Administrator privileges.")
                print(f"[*] Details: {e}")
                print("[*] To sniff raw interface on Windows: Open PowerShell as Administrator and run the command.")
                print("[*] Alternatively: Use '--mode live' for interactive user gateway without elevated privileges.\n")
                return
            try:
                s.settimeout(0.2)
                while True:
                    if stop_event and stop_event.is_set():
                        break
                    try:
                        data = s.recv(65535)
                    except socket.timeout:
                        continue
                    now = time.time()
                    eth_frame = b"\x00" * 12 + struct.pack("!H", 0x0800) + data
                    pkt = cls.dissect_ethernet_frame(eth_frame, ts=now, ts_sec=int(now), ts_usec=int((now % 1) * 1e6))
                    if pkt:
                        yield pkt
            finally:
                try:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
                s.close()
        else:
            raise NotImplementedError(f"Live interface capture not supported on platform: {sys.platform}")
