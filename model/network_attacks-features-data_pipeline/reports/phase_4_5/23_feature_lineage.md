# Phase 4.5 Forensic Audit: Report 23 — 54-Dimensional Feature Lineage & Rationale

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Feature Lineage & Engineering Design Rationale

The 54-dimensional representation was engineered to capture the full macroscopic behavioral envelope of network flow telemetry over sliding temporal windows, condensing 80 raw flow features into 37 base statistics + 17 velocity deltas.

> [!IMPORTANT]
> **Non-Optimality Statement:** The 54 features are an engineered domain-specific behavioral macro-state representation, not a proven globally optimal feature set. They provide a standardized, leakage-free continuous coordinate space for temporal dynamics modeling.

## 2. Feature Category Breakdown

1. **Volume & Density (3):** `flow_count`, `total_ip_bytes`, `total_packets`
2. **Velocity Rates (3):** `flow_rate`, `byte_rate`, `packet_rate`
3. **Protocol Distribution (3):** `tcp_ratio`, `udp_ratio`, `icmp_ratio`
4. **Port Targeting & Entropy (4):** `unique_dst_ports`, `port_concentration`, `dst_port_entropy`, `auth_port_ratio`
5. **TCP Flags & Health (10):** `syn_count`, `ack_count`, `rst_count`, `fin_count`, `psh_count`, `syn_ratio`, `ack_ratio`, `rst_ratio`, `rst_to_syn_ratio`, `handshake_completion_ratio`
6. **Directional Asymmetry (4):** `fwd_packet_ratio`, `fwd_byte_ratio`, `down_up_ratio_mean`, `down_up_ratio_std`
7. **Packet Length Moments (5):** `pkt_len_mean`, `pkt_len_std`, `pkt_len_max`, `pkt_len_min`, `zero_payload_ratio`
8. **IAT Pacing & Lifetime (5):** `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min`, `active_connection_lifetime_mean`
9. **Velocity Deltas (17):** First-order backward differences $\Delta S_t = S_t - S_{t-1}$

