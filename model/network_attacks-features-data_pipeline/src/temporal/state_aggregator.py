"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Module: src.temporal.state_aggregator

High-Performance Vectorized Temporal State Aggregator.
Aggregates micro-level flow telemetry records into canonical 54-dimensional
macro-behavioral network state vectors S_t over sliding temporal windows.
"""

import math
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd


# Canonical MITRE and Family Mappings
ATTACK_FAMILY_MAP = {
    'BENIGN': 'Benign',
    'FTP-BRUTEFORCE': 'BruteForce',
    'SSH-BRUTEFORCE': 'BruteForce',
    'BRUTE FORCE -WEB': 'WebAttack',
    'BRUTE FORCE -XSS': 'WebAttack',
    'SQL INJECTION': 'WebAttack',
    'DOS ATTACKS-SLOWLORIS': 'DoS',
    'DOS ATTACKS-SLOWHTTPTEST': 'DoS',
    'DOS ATTACKS-HULK': 'DoS',
    'DOS ATTACKS-GOLDENEYE': 'DoS',
    'DDOS ATTACK-LOIC-UDP': 'DDoS',
    'DDOS ATTACK-HOIC': 'DDoS',
    'INFILTERATION': 'Infiltration',
    'BOT': 'Botnet'
}

MITRE_TECHNIQUE_MAP = {
    'BENIGN': 'None',
    'FTP-BRUTEFORCE': 'T1110.001',
    'SSH-BRUTEFORCE': 'T1110.001',
    'BRUTE FORCE -WEB': 'T1110.001',
    'BRUTE FORCE -XSS': 'T1190',
    'SQL INJECTION': 'T1190',
    'DOS ATTACKS-SLOWLORIS': 'T1499.003',
    'DOS ATTACKS-SLOWHTTPTEST': 'T1499.003',
    'DOS ATTACKS-HULK': 'T1498.001',
    'DOS ATTACKS-GOLDENEYE': 'T1499.003',
    'DDOS ATTACK-LOIC-UDP': 'T1498.001',
    'DDOS ATTACK-HOIC': 'T1498.001',
    'INFILTERATION': 'T1210',
    'BOT': 'T1071.001'
}

# Standardized Family ID to Integer Index for ML Classifiers
FAMILY_TO_IDX = {
    'Benign': 0,
    'BruteForce': 1,
    'DoS': 2,
    'DDoS': 3,
    'WebAttack': 4,
    'Infiltration': 5,
    'Botnet': 6
}

# 37 Base Feature Names
BASE_FEATURE_NAMES = [
    # 1. Volume & Density (3)
    'flow_count',
    'total_ip_bytes',
    'total_packets',
    # 2. Velocity Rates (3)
    'flow_rate',
    'byte_rate',
    'packet_rate',
    # 3. Protocol Distribution (3)
    'tcp_ratio',
    'udp_ratio',
    'icmp_ratio',
    # 4. Port Targeting & Entropy (4)
    'unique_dst_ports',
    'port_concentration',
    'dst_port_entropy',
    'auth_port_ratio',
    # 5. TCP Flags & Health (10)
    'syn_count',
    'ack_count',
    'rst_count',
    'fin_count',
    'psh_count',
    'syn_ratio',
    'ack_ratio',
    'rst_ratio',
    'rst_to_syn_ratio',
    'handshake_completion_ratio',
    # 6. Directional Asymmetry (4)
    'fwd_packet_ratio',
    'fwd_byte_ratio',
    'down_up_ratio_mean',
    'down_up_ratio_std',
    # 7. Packet Length Moments (5)
    'pkt_len_mean',
    'pkt_len_std',
    'pkt_len_max',
    'pkt_len_min',
    'zero_payload_ratio',
    # 8. IAT Pacing & Jitter (5)
    'flow_iat_mean',
    'flow_iat_std',
    'flow_iat_max',
    'flow_iat_min',
    'active_connection_lifetime_mean'
]

# 17 Delta Feature Names
DELTA_FEATURE_NAMES = [
    'delta_flow_count',
    'delta_total_ip_bytes',
    'delta_total_packets',
    'delta_flow_rate',
    'delta_byte_rate',
    'delta_packet_rate',
    'delta_dst_port_entropy',
    'delta_port_concentration',
    'delta_auth_port_ratio',
    'delta_syn_ratio',
    'delta_ack_ratio',
    'delta_rst_ratio',
    'delta_rst_to_syn_ratio',
    'delta_fwd_packet_ratio',
    'delta_pkt_len_mean',
    'delta_flow_iat_mean',
    'delta_active_connection_lifetime_mean'
]

# Full 54 Feature Names
STATE_FEATURE_NAMES = BASE_FEATURE_NAMES + DELTA_FEATURE_NAMES
assert len(STATE_FEATURE_NAMES) == 54, f"Expected 54 features, got {len(STATE_FEATURE_NAMES)}"


class TemporalStateAggregator:
    """
    Constructs continuous sliding temporal state representations S_t in R^54
    from chronologically sorted flow telemetry DataFrames.
    """

    def __init__(
        self,
        window_duration_seconds: float = 10.0,
        stride_seconds: float = 2.0,
        tau_cap_seconds: float = 300.0,
        auth_ports: Optional[set] = None
    ):
        self.window_duration = float(window_duration_seconds)
        self.stride = float(stride_seconds)
        self.tau_cap = float(tau_cap_seconds)
        self.auth_ports = auth_ports or {20, 21, 22, 23, 3389}

    def aggregate_session(
        self,
        df: pd.DataFrame,
        day_identifier: str = ""
    ) -> pd.DataFrame:
        """
        Aggregates a single day/session flow DataFrame into continuous state windows.

        Parameters
        ----------
        df : pd.DataFrame
            Canonical flow records with Timestamp, Label, and flow telemetry columns.
            Must be sorted by Timestamp.
        day_identifier : str
            Identifier string (e.g. filename) for session tracking.

        Returns
        -------
        pd.DataFrame
            DataFrame containing window metadata, 54 continuous state features S_t,
            and multi-horizon target labels.
        """
        if df.empty:
            raise ValueError(f"Session DataFrame for '{day_identifier}' is empty.")

        n_flows = len(df)
        t_origin = df['Timestamp'].min()
        t_max = df['Timestamp'].max()
        session_duration_sec = (t_max - t_origin).total_seconds()

        if session_duration_sec < self.window_duration:
            raise ValueError(
                f"Session duration ({session_duration_sec:.1f}s) shorter than "
                f"window size ({self.window_duration:.1f}s)."
            )

        # Relative seconds from origin
        ts_seconds = (df['Timestamp'] - t_origin).dt.total_seconds().values
        labels = df['Label'].astype(str).values

        # Generate window boundaries
        n_windows = int((session_duration_sec - self.window_duration) / self.stride) + 1
        w_starts = np.arange(n_windows) * self.stride
        w_ends = w_starts + self.window_duration

        # Compute flow slice indices via searchsorted (O(W log N))
        idx_starts = np.searchsorted(ts_seconds, w_starts, side='left')
        idx_ends = np.searchsorted(ts_seconds, w_ends, side='left')

        flow_counts = (idx_ends - idx_starts).astype(np.float32)
        non_empty = flow_counts > 0

        # Helper for fast window sum via cumsum (O(1) per window)
        def get_window_sums(arr: np.ndarray) -> np.ndarray:
            c = np.empty(len(arr) + 1, dtype=np.float64)
            c[0] = 0.0
            np.cumsum(arr, out=c[1:])
            return (c[idx_ends] - c[idx_starts]).astype(np.float32)

        # 1. Volume & Density
        fwd_b = get_window_sums(df['TotLen Fwd Pkts'].values.astype(np.float64))
        bwd_b = get_window_sums(df['TotLen Bwd Pkts'].values.astype(np.float64))
        total_ip_bytes = fwd_b + bwd_b

        fwd_p = get_window_sums(df['Tot Fwd Pkts'].values.astype(np.float64))
        bwd_p = get_window_sums(df['Tot Bwd Pkts'].values.astype(np.float64))
        total_packets = fwd_p + bwd_p

        # 2. Velocity Rates
        flow_rate = flow_counts / self.window_duration
        byte_rate = total_ip_bytes / self.window_duration
        packet_rate = total_packets / self.window_duration

        # 3. Protocol Distribution
        protocols = df['Protocol'].values
        tcp_c = get_window_sums((protocols == 6).astype(np.float64))
        udp_c = get_window_sums((protocols == 17).astype(np.float64))
        icmp_c = get_window_sums((protocols == 1).astype(np.float64))

        tcp_ratio = np.where(non_empty, tcp_c / (flow_counts + 1e-5), 0.0).astype(np.float32)
        udp_ratio = np.where(non_empty, udp_c / (flow_counts + 1e-5), 0.0).astype(np.float32)
        icmp_ratio = np.where(non_empty, icmp_c / (flow_counts + 1e-5), 0.0).astype(np.float32)

        # 4. Port Targeting & Entropy (slice-based for entropy/unique)
        dst_ports = df['Dst Port'].values
        is_auth_arr = np.isin(dst_ports, list(self.auth_ports)).astype(np.float64)
        auth_c = get_window_sums(is_auth_arr)
        auth_port_ratio = np.where(non_empty, auth_c / (flow_counts + 1e-5), 0.0).astype(np.float32)

        # 5. TCP Flags & Health
        syn_cnt = get_window_sums(df['SYN Flag Cnt'].values.astype(np.float64))
        ack_cnt = get_window_sums(df['ACK Flag Cnt'].values.astype(np.float64))
        rst_cnt = get_window_sums(df['RST Flag Cnt'].values.astype(np.float64))
        fin_cnt = get_window_sums(df['FIN Flag Cnt'].values.astype(np.float64))
        psh_cnt = get_window_sums(df['PSH Flag Cnt'].values.astype(np.float64))

        syn_ratio = np.where(total_packets > 0, syn_cnt / (total_packets + 1e-5), 0.0).astype(np.float32)
        ack_ratio = np.where(total_packets > 0, ack_cnt / (total_packets + 1e-5), 0.0).astype(np.float32)
        rst_ratio = np.where(total_packets > 0, rst_cnt / (total_packets + 1e-5), 0.0).astype(np.float32)
        rst_to_syn_ratio = np.where(syn_cnt > 0, (rst_cnt + 1e-5) / (syn_cnt + 1e-5), 0.0).astype(np.float32)
        handshake_completion_ratio = np.where(syn_cnt > 0, (ack_cnt + 1e-5) / (syn_cnt + 1e-5), 0.0).astype(np.float32)

        # 6. Directional Asymmetry
        fwd_packet_ratio = np.where(total_packets > 0, fwd_p / (total_packets + 1e-5), 0.0).astype(np.float32)
        fwd_byte_ratio = np.where(total_ip_bytes > 0, fwd_b / (total_ip_bytes + 1e-5), 0.0).astype(np.float32)

        down_up = df['Down/Up Ratio'].values.astype(np.float64)
        down_up_mean = np.where(non_empty, get_window_sums(down_up) / (flow_counts + 1e-5), 0.0).astype(np.float32)
        down_up_sq = np.where(non_empty, get_window_sums(down_up ** 2) / (flow_counts + 1e-5), 0.0)
        down_up_std = np.sqrt(np.maximum(0.0, down_up_sq - down_up_mean ** 2)).astype(np.float32)

        # 7. Packet Length Moments
        pkt_len_m_col = df['Pkt Len Mean'].values.astype(np.float64)
        pkt_len_mean = np.where(non_empty, get_window_sums(pkt_len_m_col) / (flow_counts + 1e-5), 0.0).astype(np.float32)

        pkt_len_s_col = df['Pkt Len Std'].values.astype(np.float64)
        pkt_len_std = np.where(non_empty, get_window_sums(pkt_len_s_col) / (flow_counts + 1e-5), 0.0).astype(np.float32)

        zero_payload = ((df['TotLen Fwd Pkts'].values == 0) & (df['TotLen Bwd Pkts'].values == 0)).astype(np.float64)
        zero_payload_ratio = np.where(non_empty, get_window_sums(zero_payload) / (flow_counts + 1e-5), 0.0).astype(np.float32)

        # 8. IAT Pacing & Lifetime
        flow_iat_m_col = df['Flow IAT Mean'].values.astype(np.float64)
        flow_iat_mean = np.where(non_empty, get_window_sums(flow_iat_m_col) / (flow_counts + 1e-5), 0.0).astype(np.float32)

        flow_iat_s_col = df['Flow IAT Std'].values.astype(np.float64)
        flow_iat_std = np.where(non_empty, get_window_sums(flow_iat_s_col) / (flow_counts + 1e-5), 0.0).astype(np.float32)

        dur_col = df['Flow Duration'].values.astype(np.float64)
        active_connection_lifetime_mean = np.where(non_empty, get_window_sums(dur_col) / (flow_counts + 1e-5), 0.0).astype(np.float32)

        # Slice-based arrays for max/min and entropy
        pkt_max_arr = df['Pkt Len Max'].values
        pkt_min_arr = df['Pkt Len Min'].values
        iat_max_arr = df['Flow IAT Max'].values
        iat_min_arr = df['Flow IAT Min'].values

        unique_dst_ports = np.zeros(n_windows, dtype=np.float32)
        port_concentration = np.zeros(n_windows, dtype=np.float32)
        dst_port_entropy = np.zeros(n_windows, dtype=np.float32)
        pkt_len_max = np.zeros(n_windows, dtype=np.float32)
        pkt_len_min = np.zeros(n_windows, dtype=np.float32)
        flow_iat_max = np.zeros(n_windows, dtype=np.float32)
        flow_iat_min = np.zeros(n_windows, dtype=np.float32)

        # Window ground truth arrays
        is_attack = np.zeros(n_windows, dtype=np.int32)
        attack_fraction = np.zeros(n_windows, dtype=np.float32)
        dominant_attack_family = ['Benign'] * n_windows
        dominant_attack_type = ['Benign'] * n_windows
        dominant_mitre_technique = ['None'] * n_windows

        for i in range(n_windows):
            s = idx_starts[i]
            e = idx_ends[i]
            cnt = e - s
            if cnt == 0:
                continue

            # Port distribution & entropy
            p_slice = dst_ports[s:e]
            unq, counts = np.unique(p_slice, return_counts=True)
            unique_dst_ports[i] = len(unq)
            port_concentration[i] = counts.max() / cnt
            probs = counts / cnt
            dst_port_entropy[i] = -np.sum(probs * np.log2(probs + 1e-12))

            # Extrema
            pkt_len_max[i] = pkt_max_arr[s:e].max()
            pkt_len_min[i] = pkt_min_arr[s:e].min()
            flow_iat_max[i] = iat_max_arr[s:e].max()
            flow_iat_min[i] = iat_min_arr[s:e].min()

            # Window Ground Truth
            l_slice = labels[s:e]
            non_benign = [lbl for lbl in l_slice if lbl.upper() != 'BENIGN']
            if non_benign:
                is_attack[i] = 1
                attack_fraction[i] = len(non_benign) / cnt
                # Find most frequent attack label in slice
                vals, vcounts = np.unique(non_benign, return_counts=True)
                dom_atk = vals[np.argmax(vcounts)]
                dominant_attack_type[i] = dom_atk
                dom_atk_norm = dom_atk.upper()
                dominant_attack_family[i] = ATTACK_FAMILY_MAP.get(dom_atk_norm, 'Benign')
                dominant_mitre_technique[i] = MITRE_TECHNIQUE_MAP.get(dom_atk_norm, 'None')

        # 9. Compute First-Order Velocity Deltas (Delta S_t = S_t - S_{t-1})
        def compute_delta(feat_arr: np.ndarray) -> np.ndarray:
            d = np.zeros_like(feat_arr)
            d[1:] = feat_arr[1:] - feat_arr[:-1]
            return d

        delta_flow_count = compute_delta(flow_counts)
        delta_total_ip_bytes = compute_delta(total_ip_bytes)
        delta_total_packets = compute_delta(total_packets)
        delta_flow_rate = compute_delta(flow_rate)
        delta_byte_rate = compute_delta(byte_rate)
        delta_packet_rate = compute_delta(packet_rate)
        delta_dst_port_entropy = compute_delta(dst_port_entropy)
        delta_port_concentration = compute_delta(port_concentration)
        delta_auth_port_ratio = compute_delta(auth_port_ratio)
        delta_syn_ratio = compute_delta(syn_ratio)
        delta_ack_ratio = compute_delta(ack_ratio)
        delta_rst_ratio = compute_delta(rst_ratio)
        delta_rst_to_syn_ratio = compute_delta(rst_to_syn_ratio)
        delta_fwd_packet_ratio = compute_delta(fwd_packet_ratio)
        delta_pkt_len_mean = compute_delta(pkt_len_mean)
        delta_flow_iat_mean = compute_delta(flow_iat_mean)
        delta_active_connection_lifetime_mean = compute_delta(active_connection_lifetime_mean)

        # 10. Backward pass for Time-To-Attack onset (tau)
        tau_onset = np.full(n_windows, self.tau_cap, dtype=np.float32)
        next_attack_idx = -1
        for i in range(n_windows - 1, -1, -1):
            if is_attack[i] == 1:
                next_attack_idx = i
                tau_onset[i] = 0.0
            elif next_attack_idx != -1:
                dist_seconds = (next_attack_idx - i) * self.stride
                tau_onset[i] = min(float(dist_seconds), self.tau_cap)

        # 11. Multi-Horizon Targets for the expanded 2-second-step benchmark.
        horizons = [1, 3, 5, 10, 25, 50, 100, 200]
        target_dict: Dict[str, Any] = {}

        for k in horizons:
            t_atk = np.full(n_windows, -1, dtype=np.int32)
            t_fam = ['Unknown'] * n_windows
            t_idx = np.full(n_windows, -1, dtype=np.int32)

            if k < n_windows:
                t_atk[:-k] = is_attack[k:]
                t_fam[:-k] = dominant_attack_family[k:]
                fam_indices = [FAMILY_TO_IDX.get(f, 0) for f in dominant_attack_family[k:]]
                t_idx[:-k] = fam_indices

            target_dict[f'target_is_attack_k{k}'] = t_atk
            target_dict[f'target_family_k{k}'] = t_fam
            target_dict[f'target_family_idx_k{k}'] = t_idx

        # Assemble Output DataFrame
        # Window Wallclock Timestamps
        wall_starts = t_origin + pd.to_timedelta(w_starts, unit='s')
        wall_ends = t_origin + pd.to_timedelta(w_ends, unit='s')

        data = {
            # Metadata
            'session_id': [day_identifier] * n_windows,
            'window_idx': np.arange(n_windows, dtype=np.int32),
            'timestamp_start': wall_starts,
            'timestamp_end': wall_ends,
            'window_start_sec': w_starts.astype(np.float32),
            'window_end_sec': w_ends.astype(np.float32),
            'flow_count': flow_counts,
            # Ground Truth Current Window
            'is_attack': is_attack,
            'attack_fraction': attack_fraction,
            'dominant_attack_family': dominant_attack_family,
            'dominant_attack_type': dominant_attack_type,
            'dominant_mitre_technique': dominant_mitre_technique,
            'family_idx': np.array([FAMILY_TO_IDX.get(f, 0) for f in dominant_attack_family], dtype=np.int32),
            'time_to_attack_onset_sec': tau_onset,
            # Continuous State Features S_t in R^54 (37 Base + 17 Delta)
            # Volume & Velocity
            'total_ip_bytes': total_ip_bytes,
            'total_packets': total_packets,
            'flow_rate': flow_rate,
            'byte_rate': byte_rate,
            'packet_rate': packet_rate,
            # Protocols
            'tcp_ratio': tcp_ratio,
            'udp_ratio': udp_ratio,
            'icmp_ratio': icmp_ratio,
            # Ports
            'unique_dst_ports': unique_dst_ports,
            'port_concentration': port_concentration,
            'dst_port_entropy': dst_port_entropy,
            'auth_port_ratio': auth_port_ratio,
            # TCP Flags
            'syn_count': syn_cnt,
            'ack_count': ack_cnt,
            'rst_count': rst_cnt,
            'fin_count': fin_cnt,
            'psh_count': psh_cnt,
            'syn_ratio': syn_ratio,
            'ack_ratio': ack_ratio,
            'rst_ratio': rst_ratio,
            'rst_to_syn_ratio': rst_to_syn_ratio,
            'handshake_completion_ratio': handshake_completion_ratio,
            # Directional
            'fwd_packet_ratio': fwd_packet_ratio,
            'fwd_byte_ratio': fwd_byte_ratio,
            'down_up_ratio_mean': down_up_mean,
            'down_up_ratio_std': down_up_std,
            # Packet Length Moments
            'pkt_len_mean': pkt_len_mean,
            'pkt_len_std': pkt_len_std,
            'pkt_len_max': pkt_len_max,
            'pkt_len_min': pkt_len_min,
            'zero_payload_ratio': zero_payload_ratio,
            # IAT Moments & Duration
            'flow_iat_mean': flow_iat_mean,
            'flow_iat_std': flow_iat_std,
            'flow_iat_max': flow_iat_max,
            'flow_iat_min': flow_iat_min,
            'active_connection_lifetime_mean': active_connection_lifetime_mean,
            # Velocity Deltas
            'delta_flow_count': delta_flow_count,
            'delta_total_ip_bytes': delta_total_ip_bytes,
            'delta_total_packets': delta_total_packets,
            'delta_flow_rate': delta_flow_rate,
            'delta_byte_rate': delta_byte_rate,
            'delta_packet_rate': delta_packet_rate,
            'delta_dst_port_entropy': delta_dst_port_entropy,
            'delta_port_concentration': delta_port_concentration,
            'delta_auth_port_ratio': delta_auth_port_ratio,
            'delta_syn_ratio': delta_syn_ratio,
            'delta_ack_ratio': delta_ack_ratio,
            'delta_rst_ratio': delta_rst_ratio,
            'delta_rst_to_syn_ratio': delta_rst_to_syn_ratio,
            'delta_fwd_packet_ratio': delta_fwd_packet_ratio,
            'delta_pkt_len_mean': delta_pkt_len_mean,
            'delta_flow_iat_mean': delta_flow_iat_mean,
            'delta_active_connection_lifetime_mean': delta_active_connection_lifetime_mean,
        }

        # Merge multi-horizon targets
        data.update(target_dict)

        out_df = pd.DataFrame(data)
        return out_df
