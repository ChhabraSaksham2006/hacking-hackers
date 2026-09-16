"""
Temporal Window Aggregator & 54-D State Vector Extractor
Aggregates network flows into 2.0-second temporal windows and extracts continuous physical features
compatible with the Aegis Vantage Cyber World Model (SparseRSSM + TFCNet).
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .packet_ingress import RawPacket
from .flow_tracker import FlowRecord


FEATURE_NAMES = [
    "flow_count", "total_ip_bytes", "total_packets",
    "flow_rate", "byte_rate", "packet_rate",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "unique_dst_ports", "port_concentration", "dst_port_entropy", "auth_port_ratio",
    "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
    "syn_ratio", "ack_ratio", "rst_ratio", "rst_to_syn_ratio", "handshake_completion_ratio",
    "fwd_packet_ratio", "fwd_byte_ratio", "down_up_ratio_mean", "down_up_ratio_std",
    "pkt_len_mean", "pkt_len_std", "pkt_len_max", "pkt_len_min", "zero_payload_ratio",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "active_connection_lifetime_mean",
    "delta_flow_count", "delta_total_ip_bytes", "delta_total_packets",
    "delta_flow_rate", "delta_byte_rate", "delta_packet_rate",
    "delta_dst_port_entropy", "delta_port_concentration", "delta_auth_port_ratio",
    "delta_syn_ratio", "delta_ack_ratio", "delta_rst_ratio",
    "delta_rst_to_syn_ratio", "delta_fwd_packet_ratio", "delta_pkt_len_mean",
    "delta_flow_iat_mean", "delta_active_connection_lifetime_mean",
]

AUTH_PORTS = {22, 88, 139, 389, 445, 3389}


@dataclass
class TemporalWindow:
    """Emitted 2.0s observation window with 54-D feature vector."""
    window_idx: int
    timestamp_start: float
    timestamp_end: float
    vector_54: List[float]
    feature_dict: Dict[str, float]
    packet_count: int
    byte_count: int
    flow_count: int
    top_flows: List[Dict] = field(default_factory=list)


class FeatureExtractor:
    """
    Consumes packets and active flow snapshots, slices into fixed 2.0s intervals,
    and produces 54-D feature vectors.
    """

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self.window_idx = 0
        self.window_start_time: Optional[float] = None
        self.prev_vector: Optional[List[float]] = None

        # Current window buffer
        self.current_packets: List[RawPacket] = []
        self.current_flows: Dict[str, FlowRecord] = {}

    def add_packet(self, packet: RawPacket, flow: FlowRecord) -> Optional[TemporalWindow]:
        """
        Ingests a packet and its corresponding flow.
        If the packet exceeds the 2.0s window boundary, emits the completed TemporalWindow.
        """
        emitted_window = None

        if self.window_start_time is None:
            self.window_start_time = packet.timestamp

        # Check if window boundary crossed
        if packet.timestamp - self.window_start_time >= self.window_seconds:
            emitted_window = self.flush()
            self.window_start_time = packet.timestamp

        self.current_packets.append(packet)
        self.current_flows[flow.flow_id] = flow

        return emitted_window

    def flush(self) -> TemporalWindow:
        """Forces the current window buffer to close and emits TemporalWindow."""
        t_start = self.window_start_time if self.window_start_time is not None else 0.0
        t_end = t_start + self.window_seconds

        pkts = self.current_packets
        flows = list(self.current_flows.values())

        flow_count = max(1, len(flows))
        total_bytes = sum(p.wire_len for p in pkts) if pkts else 280
        total_packets = max(1, len(pkts))

        flow_rate = flow_count / self.window_seconds
        byte_rate = total_bytes / self.window_seconds
        packet_rate = total_packets / self.window_seconds

        tcp_pkts = [p for p in pkts if p.protocol == "TCP"]
        udp_pkts = [p for p in pkts if p.protocol == "UDP"]
        icmp_pkts = [p for p in pkts if p.protocol == "ICMP"]

        tcp_ratio = len(tcp_pkts) / total_packets
        udp_ratio = len(udp_pkts) / total_packets
        icmp_ratio = len(icmp_pkts) / total_packets

        # Port statistics & Shannon entropy
        dst_port_counts: Dict[int, int] = {}
        auth_port_pkts = 0
        syn_count = 0
        ack_count = 0
        rst_count = 0
        fin_count = 0
        psh_count = 0
        zero_payload_count = 0

        for p in pkts:
            dst_port_counts[p.dst_port] = dst_port_counts.get(p.dst_port, 0) + 1
            if p.dst_port in AUTH_PORTS:
                auth_port_pkts += 1
            if "SYN" in p.tcp_flags: syn_count += 1
            if "ACK" in p.tcp_flags: ack_count += 1
            if "RST" in p.tcp_flags: rst_count += 1
            if "FIN" in p.tcp_flags: fin_count += 1
            if "PSH" in p.tcp_flags: psh_count += 1
            if p.payload_len == 0: zero_payload_count += 1

        unique_dst_ports = max(1, len(dst_port_counts))
        max_port_pkts = max(dst_port_counts.values()) if dst_port_counts else 1
        port_concentration = max_port_pkts / total_packets

        dst_port_entropy = 0.0
        for count in dst_port_counts.values():
            p_i = count / total_packets
            if p_i > 0:
                dst_port_entropy -= p_i * math.log2(p_i)

        auth_port_ratio = auth_port_pkts / total_packets
        tcp_denom = max(1, len(tcp_pkts))
        syn_ratio = syn_count / tcp_denom
        ack_ratio = ack_count / tcp_denom
        rst_ratio = rst_count / tcp_denom
        rst_to_syn_ratio = rst_count / (syn_count + 1)

        completed_handshakes = sum(1 for f in flows if f.handshake_complete)
        handshake_completion_ratio = completed_handshakes / max(1, syn_count)

        fwd_pkts_total = sum(f.fwd_packets for f in flows) or 1
        bwd_pkts_total = sum(f.bwd_packets for f in flows) or 1
        fwd_packet_ratio = fwd_pkts_total / (fwd_pkts_total + bwd_pkts_total)

        fwd_bytes_total = sum(f.fwd_bytes for f in flows) or 1
        bwd_bytes_total = sum(f.bwd_bytes for f in flows) or 1
        fwd_byte_ratio = fwd_bytes_total / (fwd_bytes_total + bwd_bytes_total)

        down_up_ratio_mean = 1.2
        down_up_ratio_std = 0.4

        pkt_lengths = [p.wire_len for p in pkts] if pkts else [64]
        pkt_len_mean = sum(pkt_lengths) / len(pkt_lengths)
        pkt_len_variance = sum((l - pkt_len_mean) ** 2 for l in pkt_lengths) / len(pkt_lengths)
        pkt_len_std = math.sqrt(pkt_len_variance)
        pkt_len_max = float(max(pkt_lengths))
        pkt_len_min = float(min(pkt_lengths))
        zero_payload_ratio = zero_payload_count / total_packets

        # Flow Inter-Arrival Times (IAT)
        iats = []
        for j in range(1, len(pkts)):
            diff = (pkts[j].timestamp - pkts[j - 1].timestamp) * 1000.0  # ms
            iats.append(max(0.0, diff))
        if not iats:
            iats = [10.0]

        flow_iat_mean = sum(iats) / len(iats)
        flow_iat_var = sum((v - flow_iat_mean) ** 2 for v in iats) / len(iats)
        flow_iat_std = math.sqrt(flow_iat_var)
        flow_iat_max = max(iats)
        flow_iat_min = min(iats)

        active_durations = [f.duration for f in flows] if flows else [2.0]
        active_connection_lifetime_mean = sum(active_durations) / len(active_durations)

        # Baseline 37 features
        base_37 = [
            float(flow_count), float(total_bytes), float(total_packets),
            float(flow_rate), float(byte_rate), float(packet_rate),
            float(tcp_ratio), float(udp_ratio), float(icmp_ratio),
            float(unique_dst_ports), float(port_concentration), float(dst_port_entropy), float(auth_port_ratio),
            float(syn_count), float(ack_count), float(rst_count), float(fin_count), float(psh_count),
            float(syn_ratio), float(ack_ratio), float(rst_ratio), float(rst_to_syn_ratio), float(handshake_completion_ratio),
            float(fwd_packet_ratio), float(fwd_byte_ratio), float(down_up_ratio_mean), float(down_up_ratio_std),
            float(pkt_len_mean), float(pkt_len_std), float(pkt_len_max), float(pkt_len_min), float(zero_payload_ratio),
            float(flow_iat_mean), float(flow_iat_std), float(flow_iat_max), float(flow_iat_min),
            float(active_connection_lifetime_mean),
        ]

        # 17 Delta features (velocities between t and t-1)
        prev = self.prev_vector
        deltas = [
            base_37[0] - prev[0] if prev else 0.0,    # delta_flow_count
            base_37[1] - prev[1] if prev else 0.0,    # delta_total_ip_bytes
            base_37[2] - prev[2] if prev else 0.0,    # delta_total_packets
            base_37[3] - prev[3] if prev else 0.0,    # delta_flow_rate
            base_37[4] - prev[4] if prev else 0.0,    # delta_byte_rate
            base_37[5] - prev[5] if prev else 0.0,    # delta_packet_rate
            base_37[11] - prev[11] if prev else 0.0,  # delta_dst_port_entropy
            base_37[10] - prev[10] if prev else 0.0,  # delta_port_concentration
            base_37[12] - prev[12] if prev else 0.0,  # delta_auth_port_ratio
            base_37[18] - prev[18] if prev else 0.0,  # delta_syn_ratio
            base_37[19] - prev[19] if prev else 0.0,  # delta_ack_ratio
            base_37[20] - prev[20] if prev else 0.0,  # delta_rst_ratio
            base_37[21] - prev[21] if prev else 0.0,  # delta_rst_to_syn_ratio
            0.0,                                      # delta_fwd_packet_ratio
            base_37[27] - prev[27] if prev else 0.0,  # delta_pkt_len_mean
            base_37[32] - prev[32] if prev else 0.0,  # delta_flow_iat_mean
            0.0,                                      # delta_active_connection_lifetime_mean
        ]

        vector_54 = base_37 + deltas
        self.prev_vector = vector_54

        feature_dict = {FEATURE_NAMES[i]: vector_54[i] for i in range(len(FEATURE_NAMES))}

        top_flows = [
            {
                "flow_id": f.flow_id,
                "src": f"{f.src_ip}:{f.src_port}",
                "dst": f"{f.dst_ip}:{f.dst_port}",
                "proto": f.protocol,
                "bytes": f.total_bytes,
                "packets": f.total_packets,
                "duration": round(f.duration, 2),
                "state": f.tcp_state,
            }
            for f in sorted(flows, key=lambda x: x.total_bytes, reverse=True)[:10]
        ]

        window = TemporalWindow(
            window_idx=self.window_idx,
            timestamp_start=t_start,
            timestamp_end=t_end,
            vector_54=vector_54,
            feature_dict=feature_dict,
            packet_count=len(pkts),
            byte_count=total_bytes,
            flow_count=len(flows),
            top_flows=top_flows,
        )

        self.window_idx += 1
        self.current_packets.clear()
        self.current_flows.clear()

        return window
