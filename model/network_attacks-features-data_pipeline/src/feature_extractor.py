"""
Feature Extraction Engine — v3 (Anomaly & Stealth Attack Aware)

Extracts comprehensive flow-level and packet-level features based on info.txt
and adds specific Layer-3/Layer-4 anomaly detectors for single-packet stealth attacks:
  - Fragmentation anomaly features (teardrop, overlapping offset, MF flag)
  - Oversized ICMP anomaly features (Ping of Death / pod)
  - Authentication service concentration (Telnet/SSH/FTP brute-force dict_simple)
"""

import math
import numpy as np
from collections import Counter, defaultdict
from typing import List, Dict, Any
from scapy.all import IP, TCP, UDP, ICMP, Packet

# Common authentication ports for initial access & brute force detection
AUTH_PORTS = {21, 22, 23, 110, 143, 512, 513, 514, 3389}


def compute_entropy(labels: List[Any]) -> float:
    """Shannon entropy of a categorical list."""
    if not labels:
        return 0.0
    total = len(labels)
    counts = Counter(labels)
    return float(-sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0))


class FeatureExtractor:
    """
    Extracts multi-family telemetry features from raw Scapy packets.
    All per-window computations are stateless and fully vectorized.
    """

    @staticmethod
    def extract_packet_metadata(pkt: Packet) -> Dict[str, Any]:
        """Extract protocol metadata from a single Scapy packet."""
        meta = {
            "timestamp": float(pkt.time),
            "frame_len": len(pkt),          # Full frame
            "ip_bytes": 0,                  # IP-layer byte count
            "is_ip": False,
            "src_ip": None,
            "dst_ip": None,
            "proto": None,
            "ttl": 0,
            "sport": 0,
            "dport": 0,
            "tcp_flags": 0,
            "tcp_window": 0,
            "seq": 0,
            "ack_seq": 0,
            "payload_len": 0,
            # TCP flags
            "is_syn": False,
            "is_ack": False,
            "is_fin": False,
            "is_rst": False,
            "is_psh": False,
            "is_urg": False,
            "is_pure_syn": False,
            # Anomaly & stealth flags
            "is_fragment": False,
            "frag_offset": 0,
            "is_oversized_icmp": False,
            "is_auth_port": False,
        }

        if IP in pkt:
            meta["is_ip"] = True
            meta["src_ip"] = pkt[IP].src
            meta["dst_ip"] = pkt[IP].dst
            meta["ttl"] = int(pkt[IP].ttl)
            ip_len = int(pkt[IP].len)
            meta["ip_bytes"] = ip_len
            ip_hdr_len = int(pkt[IP].ihl) * 4

            # IP Fragmentation (teardrop, jolt, fragmented probe detection)
            ip_flags = int(pkt[IP].flags)
            frag_off = int(pkt[IP].frag)
            meta["frag_offset"] = frag_off
            meta["is_fragment"] = bool((ip_flags & 0x01) or (frag_off > 0))

            if TCP in pkt:
                meta["proto"] = "TCP"
                meta["sport"] = int(pkt[TCP].sport)
                meta["dport"] = int(pkt[TCP].dport)
                meta["tcp_flags"] = int(pkt[TCP].flags)
                meta["tcp_window"] = int(pkt[TCP].window)
                meta["seq"] = int(pkt[TCP].seq)
                meta["ack_seq"] = int(pkt[TCP].ack)
                tcp_hdr_len = int(pkt[TCP].dataofs) * 4
                meta["payload_len"] = max(0, ip_len - ip_hdr_len - tcp_hdr_len)

                flags = meta["tcp_flags"]
                meta["is_fin"] = bool(flags & 0x01)
                meta["is_syn"] = bool(flags & 0x02)
                meta["is_rst"] = bool(flags & 0x04)
                meta["is_psh"] = bool(flags & 0x08)
                meta["is_ack"] = bool(flags & 0x10)
                meta["is_urg"] = bool(flags & 0x20)
                meta["is_pure_syn"] = meta["is_syn"] and not meta["is_ack"]
                meta["is_auth_port"] = meta["dport"] in AUTH_PORTS

            elif UDP in pkt:
                meta["proto"] = "UDP"
                meta["sport"] = int(pkt[UDP].sport)
                meta["dport"] = int(pkt[UDP].dport)
                meta["payload_len"] = max(0, ip_len - ip_hdr_len - 8)
                meta["is_auth_port"] = meta["dport"] in AUTH_PORTS

            elif ICMP in pkt:
                meta["proto"] = "ICMP"
                meta["sport"] = 0
                meta["dport"] = 0
                meta["payload_len"] = max(0, ip_len - ip_hdr_len - 8)
                # Ping of Death detection (> 500 bytes ICMP payload)
                meta["is_oversized_icmp"] = bool(ip_len > 500 or meta["payload_len"] > 500)

        return meta

    @classmethod
    def extract_window_state_features(
        cls,
        packet_metas: List[Dict[str, Any]],
        window_duration: float = 10.0
    ) -> Dict[str, float]:
        """
        Compute the System State Vector S_t for a time window.
        All features derived from per-packet metadata dicts.
        """
        if not packet_metas:
            return cls._get_empty_state_features()

        total_pkts = len(packet_metas)
        total_ip_bytes = sum(m["ip_bytes"] for m in packet_metas)

        timestamps = sorted(m["timestamp"] for m in packet_metas)
        actual_span = max(timestamps[-1] - timestamps[0], 1e-4)
        rate_denom = actual_span

        # ── Protocol split ──────────────────────────────────────────────────
        tcp_pkts = [m for m in packet_metas if m["proto"] == "TCP"]
        udp_pkts = [m for m in packet_metas if m["proto"] == "UDP"]
        icmp_pkts = [m for m in packet_metas if m["proto"] == "ICMP"]
        tcp_count = len(tcp_pkts)
        udp_count = len(udp_pkts)
        icmp_count = len(icmp_pkts)

        # ── Connectivity / Fanout ───────────────────────────────────────────
        src_ips = [m["src_ip"] for m in packet_metas if m["src_ip"]]
        dst_ips = [m["dst_ip"] for m in packet_metas if m["dst_ip"]]
        dst_ports = [m["dport"] for m in packet_metas if m["dport"] > 0]

        unique_src_ips = len(set(src_ips))
        unique_dst_ips = len(set(dst_ips))
        unique_dst_ports = len(set(dst_ports))

        dst_ip_to_ports = defaultdict(set)
        for m in packet_metas:
            if m["dst_ip"] and m["dport"] > 0:
                dst_ip_to_ports[m["dst_ip"]].add(m["dport"])

        max_dst_ports_per_ip = max((len(p) for p in dst_ip_to_ports.values()), default=0)
        avg_dst_ports_per_ip = float(np.mean([len(p) for p in dst_ip_to_ports.values()])) if dst_ip_to_ports else 0.0
        port_entropy = compute_entropy(dst_ports)

        # Bidirectional flow count
        bidi_flows = set()
        for m in packet_metas:
            if m["is_ip"] and m["proto"]:
                ip_pair = tuple(sorted([m["src_ip"], m["dst_ip"]]))
                bidi_flows.add((ip_pair, m["dport"], m["proto"]))
        flow_count = len(bidi_flows)

        # ── TCP Flags ───────────────────────────────────────────────────────
        pure_syn_count = sum(1 for m in tcp_pkts if m["is_pure_syn"])
        syn_ack_count  = sum(1 for m in tcp_pkts if m["is_syn"] and m["is_ack"])
        ack_count      = sum(1 for m in tcp_pkts if m["is_ack"])
        rst_count      = sum(1 for m in tcp_pkts if m["is_rst"])
        fin_count      = sum(1 for m in tcp_pkts if m["is_fin"])
        psh_count      = sum(1 for m in tcp_pkts if m["is_psh"])
        urg_count      = sum(1 for m in tcp_pkts if m["is_urg"])

        syn_ratio   = pure_syn_count / (tcp_count + 1e-5)
        ack_ratio   = ack_count      / (tcp_count + 1e-5)
        rst_ratio   = rst_count      / (tcp_count + 1e-5)
        fin_ratio   = fin_count      / (tcp_count + 1e-5)
        rst_to_syn_ratio = rst_count / (pure_syn_count + 1e-5)
        handshake_completion_ratio = syn_ack_count / (pure_syn_count + 1e-5)

        # ── Retransmissions ─────────────────────────────────────────────────
        seen_seqs = set()
        retrans_count = 0
        for m in tcp_pkts:
            if m["payload_len"] > 0 or m["is_syn"] or m["is_fin"]:
                sig = (m["src_ip"], m["dst_ip"], m["sport"], m["dport"], m["seq"], m["payload_len"])
                if sig in seen_seqs:
                    retrans_count += 1
                else:
                    seen_seqs.add(sig)
        retransmission_rate = retrans_count / (tcp_count + 1e-5)

        # ── Window size ─────────────────────────────────────────────────────
        windows = [m["tcp_window"] for m in tcp_pkts]
        win_mean = float(np.mean(windows)) if windows else 0.0
        win_std  = float(np.std(windows))  if len(windows) > 1 else 0.0

        # ── TTL ─────────────────────────────────────────────────────────────
        ttls = [m["ttl"] for m in packet_metas if m["is_ip"]]
        ttl_mean = float(np.mean(ttls)) if ttls else 0.0
        ttl_std  = float(np.std(ttls))  if len(ttls) > 1 else 0.0

        # ── Payload ─────────────────────────────────────────────────────────
        payloads = [m["payload_len"] for m in packet_metas if m["is_ip"]]
        payload_mean = float(np.mean(payloads)) if payloads else 0.0
        payload_std  = float(np.std(payloads))  if len(payloads) > 1 else 0.0
        payload_max  = float(np.max(payloads))  if payloads else 0.0
        zero_payload_ratio = sum(1 for p in payloads if p == 0) / (total_pkts + 1e-5)

        # ── Anomaly & Stealth Signatures (teardrop, pod, brute force) ───────
        fragment_count = sum(1 for m in packet_metas if m["is_fragment"])
        fragment_ratio = fragment_count / (total_pkts + 1e-5)
        max_frag_offset = float(max((m["frag_offset"] for m in packet_metas), default=0))

        oversized_icmp_count = sum(1 for m in packet_metas if m["is_oversized_icmp"])
        icmp_payloads = [m["payload_len"] for m in icmp_pkts]
        icmp_payload_max = float(max(icmp_payloads, default=0.0))

        auth_packet_count = sum(1 for m in packet_metas if m["is_auth_port"])
        auth_packet_ratio = auth_packet_count / (total_pkts + 1e-5)

        # ── Per-flow IAT ────────────────────────────────────────────────────
        flow_timestamps: Dict[tuple, List[float]] = defaultdict(list)
        for m in packet_metas:
            if m["is_ip"] and m["proto"]:
                ip_pair = tuple(sorted([m["src_ip"], m["dst_ip"]]))
                key = (ip_pair, m["dport"], m["proto"])
                flow_timestamps[key].append(m["timestamp"])

        flow_iat_means = []
        all_iats = []
        for flow_key, ftimes in flow_timestamps.items():
            if len(ftimes) < 2:
                continue
            ftimes_sorted = sorted(ftimes)
            iats = [ftimes_sorted[i+1] - ftimes_sorted[i] for i in range(len(ftimes_sorted)-1)]
            flow_iat_means.append(float(np.mean(iats)))
            all_iats.extend(iats)

        iat_mean_min_flow = float(np.min(flow_iat_means)) if flow_iat_means else 0.0
        iat_global_mean = float(np.mean(all_iats)) if all_iats else 0.0
        iat_global_std  = float(np.std(all_iats))  if len(all_iats) > 1 else 0.0
        iat_global_max  = float(np.max(all_iats))  if all_iats else 0.0

        return {
            # 1. Volume & Rates
            "packet_count":      float(total_pkts),
            "ip_byte_count":     float(total_ip_bytes),
            "flow_count":        float(flow_count),
            "packet_rate":       float(total_pkts / rate_denom),
            "byte_rate":         float(total_ip_bytes / rate_denom),
            "tcp_ratio":         float(tcp_count  / total_pkts),
            "udp_ratio":         float(udp_count  / total_pkts),
            "icmp_ratio":        float(icmp_count / total_pkts),

            # 2. Connectivity & Scan Signatures
            "unique_src_ips":        float(unique_src_ips),
            "unique_dst_ips":        float(unique_dst_ips),
            "unique_dst_ports":      float(unique_dst_ports),
            "max_dst_ports_per_ip":  float(max_dst_ports_per_ip),
            "avg_dst_ports_per_ip":  float(avg_dst_ports_per_ip),
            "port_entropy":          float(port_entropy),

            # 3. TCP Flags & Handshake
            "pure_syn_count":              float(pure_syn_count),
            "ack_count":                   float(ack_count),
            "rst_count":                   float(rst_count),
            "fin_count":                   float(fin_count),
            "psh_count":                   float(psh_count),
            "urg_count":                   float(urg_count),
            "syn_ratio":                   float(syn_ratio),
            "ack_ratio":                   float(ack_ratio),
            "rst_ratio":                   float(rst_ratio),
            "fin_ratio":                   float(fin_ratio),
            "rst_to_syn_ratio":            float(rst_to_syn_ratio),
            "handshake_completion_ratio":  float(handshake_completion_ratio),

            # 4. Reliability & Flow Control
            "retransmission_count": float(retrans_count),
            "retransmission_rate":  float(retransmission_rate),
            "win_mean":             float(win_mean),
            "win_std":              float(win_std),

            # 5. Payload & Packet Attributes
            "ttl_mean":          float(ttl_mean),
            "ttl_std":           float(ttl_std),
            "payload_mean":      float(payload_mean),
            "payload_std":       float(payload_std),
            "payload_max":       float(payload_max),
            "zero_payload_ratio":float(zero_payload_ratio),

            # 6. Timing & IAT
            "iat_min_flow_mean": float(iat_mean_min_flow),
            "iat_global_mean":   float(iat_global_mean),
            "iat_global_std":    float(iat_global_std),
            "iat_global_max":    float(iat_global_max),

            # 7. Anomaly & Stealth Signatures (teardrop, pod, brute-force)
            "fragment_count":       float(fragment_count),
            "fragment_ratio":       float(fragment_ratio),
            "max_frag_offset":      float(max_frag_offset),
            "oversized_icmp_count": float(oversized_icmp_count),
            "icmp_payload_max":     float(icmp_payload_max),
            "auth_packet_count":    float(auth_packet_count),
            "auth_packet_ratio":    float(auth_packet_ratio),
        }

    @classmethod
    def _get_empty_state_features(cls) -> Dict[str, float]:
        keys = [
            "packet_count", "ip_byte_count", "flow_count", "packet_rate", "byte_rate",
            "tcp_ratio", "udp_ratio", "icmp_ratio",
            "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
            "max_dst_ports_per_ip", "avg_dst_ports_per_ip", "port_entropy",
            "pure_syn_count", "ack_count", "rst_count", "fin_count", "psh_count", "urg_count",
            "syn_ratio", "ack_ratio", "rst_ratio", "fin_ratio",
            "rst_to_syn_ratio", "handshake_completion_ratio",
            "retransmission_count", "retransmission_rate",
            "win_mean", "win_std",
            "ttl_mean", "ttl_std",
            "payload_mean", "payload_std", "payload_max", "zero_payload_ratio",
            "iat_min_flow_mean", "iat_global_mean", "iat_global_std", "iat_global_max",
            "fragment_count", "fragment_ratio", "max_frag_offset",
            "oversized_icmp_count", "icmp_payload_max",
            "auth_packet_count", "auth_packet_ratio"
        ]
        return {k: 0.0 for k in keys}
