"""
Stateful Flow Engine
Tracks bidirectional 5-tuple conversations, packet dynamics, TCP handshakes, and IAT statistics.
"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from .packet_ingress import RawPacket


@dataclass
class FlowRecord:
    """Stateful bidirectional 5-tuple flow record."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_time: float
    last_time: float
    duration: float = 0.0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    fwd_pkt_lens: List[int] = field(default_factory=list)
    bwd_pkt_lens: List[int] = field(default_factory=list)
    fwd_iats: List[float] = field(default_factory=list)
    bwd_iats: List[float] = field(default_factory=list)

    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    psh_count: int = 0

    tcp_state: str = "UNKNOWN"
    handshake_complete: bool = False
    is_active: bool = True

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def pkt_len_mean(self) -> float:
        all_lens = self.fwd_pkt_lens + self.bwd_pkt_lens
        return sum(all_lens) / len(all_lens) if all_lens else 0.0

    @property
    def iat_mean(self) -> float:
        all_iats = self.fwd_iats + self.bwd_iats
        return (sum(all_iats) / len(all_iats)) * 1000.0 if all_iats else 0.0  # in ms


class FlowTracker:
    """
    Edge stateful flow table.
    Consumes raw packets, associates forward/reverse flows, maintains TCP states, and handles eviction.
    """

    def __init__(self, idle_timeout: float = 60.0, active_timeout: float = 120.0):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.flows: Dict[Tuple[str, str, int, int, str], FlowRecord] = {}
        self.flow_count_cumulative = 0

    @staticmethod
    def _make_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """
        Returns a canonical bidirectional key and a boolean indicating if this direction is forward.
        """
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)
        if endpoint_a <= endpoint_b:
            return (src_ip, dst_ip, src_port, dst_port, proto), True
        else:
            return (dst_ip, src_ip, dst_port, src_port, proto), False

    def update(self, packet: RawPacket) -> FlowRecord:
        """Updates flow state with an incoming packet."""
        canon_key, is_forward = self._make_key(
            packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol
        )

        flow = self.flows.get(canon_key)
        if flow is None:
            self.flow_count_cumulative += 1
            flow_id = f"flow-{self.flow_count_cumulative:06d}"
            flow = FlowRecord(
                flow_id=flow_id,
                src_ip=packet.src_ip if is_forward else packet.dst_ip,
                src_port=packet.src_port if is_forward else packet.dst_port,
                dst_ip=packet.dst_ip if is_forward else packet.src_ip,
                dst_port=packet.dst_port if is_forward else packet.src_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                last_time=packet.timestamp,
            )
            self.flows[canon_key] = flow

        # Inter-arrival time calculation
        prev_time = flow.last_time
        iat = max(0.0, packet.timestamp - prev_time)
        flow.last_time = packet.timestamp
        flow.duration = max(0.0, flow.last_time - flow.start_time)

        # Byte & packet accounting
        pkt_len = packet.wire_len
        if is_forward:
            flow.fwd_packets += 1
            flow.fwd_bytes += pkt_len
            flow.fwd_pkt_lens.append(pkt_len)
            flow.fwd_iats.append(iat)
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes += pkt_len
            flow.bwd_pkt_lens.append(pkt_len)
            flow.bwd_iats.append(iat)

        # TCP Flag parsing & Handshake State Machine
        if packet.protocol == "TCP":
            flags = packet.tcp_flags
            if "SYN" in flags: flow.syn_count += 1
            if "ACK" in flags: flow.ack_count += 1
            if "RST" in flags: flow.rst_count += 1
            if "FIN" in flags: flow.fin_count += 1
            if "PSH" in flags: flow.psh_count += 1

            if "RST" in flags:
                flow.tcp_state = "RESET"
            elif "FIN" in flags:
                flow.tcp_state = "CLOSING"
            elif "SYN" in flags and "ACK" not in flags:
                flow.tcp_state = "SYN_SENT"
            elif "SYN" in flags and "ACK" in flags:
                flow.tcp_state = "SYN_ACK_RECEIVED"
            elif "ACK" in flags and flow.tcp_state in ("SYN_ACK_RECEIVED", "SYN_SENT"):
                flow.tcp_state = "ESTABLISHED"
                flow.handshake_complete = True
            elif flow.tcp_state == "UNKNOWN":
                flow.tcp_state = "ESTABLISHED"
        else:
            flow.tcp_state = "UDP_STATELESS"

        return flow

    def get_active_flows(self) -> List[FlowRecord]:
        """Returns currently active flows."""
        return [f for f in self.flows.values() if f.is_active]

    def evict_idle_flows(self, current_time: float) -> int:
        """Evicts flows that have been idle past idle_timeout."""
        to_delete = []
        for key, flow in self.flows.items():
            if current_time - flow.last_time > self.idle_timeout or flow.tcp_state in ("RESET", "CLOSED"):
                to_delete.append(key)

        for key in to_delete:
            del self.flows[key]
        return len(to_delete)

    def reset_window_counters(self):
        """Clears memory buffers between major sessions if desired."""
        self.flows.clear()
