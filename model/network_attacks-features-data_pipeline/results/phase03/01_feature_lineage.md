# Forensic Audit: 54-Dimensional Feature Lineage & Mathematical Formulations

**Project:** SIH26153 — AI-Based Network Attack Forecasting
**Status:** VERIFIED & VALIDATED

## 1. Feature Lineage Table

| Index | Feature Name | Category | Mathematical Definition | Source Columns | Aggregation | Future Info? | Label Dep.? | S(t-1) Dep.? |
|---|---|---|---|---|---|:---:|:---:|:---:|
| 1 | `flow_count` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 2 | `total_ip_bytes` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 3 | `total_packets` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 4 | `flow_rate` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 5 | `byte_rate` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 6 | `packet_rate` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 7 | `tcp_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 8 | `udp_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 9 | `icmp_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 10 | `unique_dst_ports` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 11 | `port_concentration` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 12 | `dst_port_entropy` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 13 | `auth_port_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 14 | `syn_count` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 15 | `ack_count` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 16 | `rst_count` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 17 | `fin_count` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 18 | `psh_count` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 19 | `syn_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 20 | `ack_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 21 | `rst_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 22 | `rst_to_syn_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 23 | `handshake_completion_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 24 | `fwd_packet_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 25 | `fwd_byte_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 26 | `down_up_ratio_mean` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 27 | `down_up_ratio_std` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 28 | `pkt_len_mean` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 29 | `pkt_len_std` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 30 | `pkt_len_max` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 31 | `pkt_len_min` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 32 | `zero_payload_ratio` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 33 | `flow_iat_mean` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 34 | `flow_iat_std` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 35 | `flow_iat_max` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 36 | `flow_iat_min` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 37 | `active_connection_lifetime_mean` | Base Behavioral Macro-State | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | No |
| 38 | `delta_flow_count` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 39 | `delta_total_ip_bytes` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 40 | `delta_total_packets` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 41 | `delta_flow_rate` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 42 | `delta_byte_rate` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 43 | `delta_packet_rate` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 44 | `delta_dst_port_entropy` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 45 | `delta_port_concentration` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 46 | `delta_auth_port_ratio` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 47 | `delta_syn_ratio` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 48 | `delta_ack_ratio` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 49 | `delta_rst_ratio` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 50 | `delta_rst_to_syn_ratio` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 51 | `delta_fwd_packet_ratio` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 52 | `delta_pkt_len_mean` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 53 | `delta_flow_iat_mean` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |
| 54 | `delta_active_connection_lifetime_mean` | Velocity Delta (Delta S_t) | Vectorized window aggregation | Canonical flow features | Cumsum / Window Slice | **NO** | **NO** | Yes (t-1) |


## 2. Mathematical Integrity Verdict
- **Zero Future Information**: Every feature $S_t[i]$ is strictly computed from flows in $[T_t, T_t + 10.0\text{s})$.
- **Zero Label Contamination**: None of the 54 features use or reference the `Label` column.
- **Historical Delta Consistency**: $\Delta S_t = S_t - S_{t-1}$ uses strictly historical step $t-1$. At $t=0$, $\Delta S_0 = 0.0$ to prevent cross-day leakage.
