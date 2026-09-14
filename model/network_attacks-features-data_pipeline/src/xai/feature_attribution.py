"""
feature_attribution.py
======================
SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data
Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening

Precursor Feature Attribution Engine.
Maps temporal attributions to physical network feature groups,
computes anomaly z-scores, and generates structured human-readable explanations.
"""

from __future__ import annotations
import os
import yaml
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any


FEATURE_GROUP_DEFINITIONS = {
    "volumetric_rates": [
        "flow_count", "total_ip_bytes", "total_packets", "flow_rate", "byte_rate",
        "packet_rate", "delta_flow_count", "delta_total_ip_bytes", "delta_total_packets",
        "delta_flow_rate", "delta_byte_rate", "delta_packet_rate"
    ],
    "tcp_handshake_flags": [
        "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
        "syn_ratio", "ack_ratio", "rst_ratio", "rst_to_syn_ratio",
        "handshake_completion_ratio", "delta_syn_ratio", "delta_ack_ratio", "delta_rst_ratio"
    ],
    "port_entropy_scanners": [
        "unique_dst_ports", "port_concentration", "dst_port_entropy", "auth_port_ratio",
        "delta_dst_port_entropy", "delta_port_concentration", "delta_auth_port_ratio"
    ],
    "packet_size_dynamics": [
        "pkt_len_mean", "pkt_len_std", "pkt_len_max", "pkt_len_min", "zero_payload_ratio",
        "fwd_packet_ratio", "fwd_byte_ratio", "down_up_ratio_mean", "down_up_ratio_std",
        "delta_pkt_len_mean", "delta_zero_payload_ratio"
    ],
    "flow_timing_iat": [
        "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "active_connection_lifetime_mean", "delta_flow_iat_mean", "delta_active_connection_lifetime_mean"
    ],
    "protocol_composition": [
        "tcp_ratio", "udp_ratio", "icmp_ratio", "delta_tcp_ratio", "delta_udp_ratio"
    ]
}


class PrecursorAttributionEngine:
    """
    Analyzes temporal attributions from Integrated Gradients and maps them
    to structured physical feature groups, generating explanation cards.
    """
    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.feature_to_idx = {name: i for i, name in enumerate(feature_names)}
        
        # Build index sets for groups
        self.group_to_indices = {}
        for grp, feat_list in FEATURE_GROUP_DEFINITIONS.items():
            self.group_to_indices[grp] = [
                self.feature_to_idx[f] for f in feat_list if f in self.feature_to_idx
            ]

    def explain_precursor_window(
        self,
        attributions: np.ndarray,          # (P=10, D)
        input_values: np.ndarray,          # (P=10, D)
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Generates full explainability report for a specific forecasting window.
        """
        D = attributions.shape[-1]
        
        # Feature-level total absolute attribution
        feat_importance = np.sum(np.abs(attributions), axis=0)  # (D,)
        total_imp = max(1e-8, float(np.sum(feat_importance)))
        normalized_feat_imp = feat_importance / total_imp

        # Group-level attribution
        group_scores = {}
        for grp, idxs in self.group_to_indices.items():
            valid_idxs = [i for i in idxs if i < D]
            if len(valid_idxs) > 0:
                group_scores[grp] = float(np.sum(normalized_feat_imp[valid_idxs]))
            else:
                group_scores[grp] = 0.0

        # Normalize group scores if needed
        total_grp_score = sum(group_scores.values())
        if total_grp_score > 0:
            group_scores = {k: v / total_grp_score for k, v in group_scores.items()}

        # Rank features
        ranked_indices = np.argsort(feat_importance)[::-1]
        top_features = []
        for i in range(min(top_k, len(ranked_indices))):
            idx = int(ranked_indices[i])
            fname = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            
            # Find group
            fgroup = "other"
            for grp, feat_list in FEATURE_GROUP_DEFINITIONS.items():
                if fname in feat_list:
                    fgroup = grp
                    break

            latest_val = float(input_values[-1, idx]) if idx < input_values.shape[-1] else 0.0
            mean_val = float(np.mean(input_values[:, idx])) if idx < input_values.shape[-1] else 0.0
            attribution_score = float(normalized_feat_imp[idx])
            
            top_features.append({
                "feature": fname,
                "group": fgroup,
                "attribution_weight": round(attribution_score, 4),
                "latest_value": round(latest_val, 4),
                "window_mean": round(mean_val, 4)
            })

        # Identify dominant group
        dominant_group = max(group_scores.items(), key=lambda x: x[1])[0] if group_scores else "volumetric_rates"

        return {
            "dominant_feature_group": dominant_group,
            "group_attributions": {k: round(v, 4) for k, v in group_scores.items()},
            "top_salient_features": top_features
        }
