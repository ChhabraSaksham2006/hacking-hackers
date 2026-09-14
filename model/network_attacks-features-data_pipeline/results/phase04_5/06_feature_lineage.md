# 06 — Complete 54-Dimensional Feature Lineage Audit

Source code location: `src/temporal/state_aggregator.py` (Lines 62–135).

## Complete Feature Lineage Table (All 54 Features)

| # | Feature Name | Functional Category | Source Raw Column(s) | Aggregation Type | Formula / Definition | Normalization | Feature Type | Possible Leakage | Status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `flow_count` | Volume & Density | `Flow Index / Count` | Sum | `Count of flow arrivals in window` | StandardScaler | Base | **NO** | Active |
| 2 | `total_ip_bytes` | Volume & Density | `TotLen Fwd Pkts, TotLen Bwd Pkts` | Sum | `fwd_bytes + bwd_bytes` | StandardScaler | Base | **NO** | Active |
| 3 | `total_packets` | Volume & Density | `Tot Fwd Pkts, Tot Bwd Pkts` | Sum | `fwd_packets + bwd_packets` | StandardScaler | Base | **NO** | Active |
| 4 | `flow_rate` | Velocity Rates | `Flow Count, Window Duration` | Rate | `flow_count / 10.0s` | StandardScaler | Base | **NO** | Active |
| 5 | `byte_rate` | Velocity Rates | `Total Bytes, Window Duration` | Rate | `total_ip_bytes / 10.0s` | StandardScaler | Base | **NO** | Active |
| 6 | `packet_rate` | Velocity Rates | `Total Packets, Window Duration` | Rate | `total_packets / 10.0s` | StandardScaler | Base | **NO** | Active |
| 7 | `tcp_ratio` | Protocol Distribution | `Protocol` | Ratio | `count(Protocol==6) / (flow_count + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 8 | `udp_ratio` | Protocol Distribution | `Protocol` | Ratio | `count(Protocol==17) / (flow_count + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 9 | `icmp_ratio` | Protocol Distribution | `Protocol` | Ratio | `count(Protocol==1) / (flow_count + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 10 | `unique_dst_ports` | Port Targeting & Entropy | `Dst Port` | Cardinality | `len(unique(Dst Port))` | StandardScaler | Base | **NO** | Active |
| 11 | `port_concentration` | Port Targeting & Entropy | `Dst Port` | Max Ratio | `max_count(Dst Port) / flow_count` | StandardScaler | Base | **NO** | Active |
| 12 | `dst_port_entropy` | Port Targeting & Entropy | `Dst Port` | Entropy | `-sum(p * log2(p + 1e-12))` | StandardScaler | Base | **NO** | Active |
| 13 | `auth_port_ratio` | Port Targeting & Entropy | `Dst Port` | Ratio | `count(Dst Port in {20,21,22,23,3389}) / flow_count` | StandardScaler | Base | **NO** | Active |
| 14 | `syn_count` | TCP Flags & Health | `SYN Flag Cnt` | Sum | `sum(SYN Flag Cnt)` | StandardScaler | Base | **NO** | Active |
| 15 | `ack_count` | TCP Flags & Health | `ACK Flag Cnt` | Sum | `sum(ACK Flag Cnt)` | StandardScaler | Base | **NO** | Active |
| 16 | `rst_count` | TCP Flags & Health | `RST Flag Cnt` | Sum | `sum(RST Flag Cnt)` | StandardScaler | Base | **NO** | Active |
| 17 | `fin_count` | TCP Flags & Health | `FIN Flag Cnt` | Sum | `sum(FIN Flag Cnt)` | StandardScaler | Base | **NO** | Active |
| 18 | `psh_count` | TCP Flags & Health | `PSH Flag Cnt` | Sum | `sum(PSH Flag Cnt)` | StandardScaler | Base | **NO** | Active |
| 19 | `syn_ratio` | TCP Flags & Health | `SYN Flag Cnt, Total Packets` | Ratio | `syn_count / (total_packets + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 20 | `ack_ratio` | TCP Flags & Health | `ACK Flag Cnt, Total Packets` | Ratio | `ack_count / (total_packets + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 21 | `rst_ratio` | TCP Flags & Health | `RST Flag Cnt, Total Packets` | Ratio | `rst_count / (total_packets + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 22 | `rst_to_syn_ratio` | TCP Flags & Health | `RST Count, SYN Count` | Ratio | `(rst_count + 1e-5) / (syn_count + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 23 | `handshake_completion_ratio` | TCP Flags & Health | `ACK Count, SYN Count` | Ratio | `(ack_count + 1e-5) / (syn_count + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 24 | `fwd_packet_ratio` | Directional Asymmetry | `Tot Fwd Pkts, Total Packets` | Ratio | `fwd_packets / (total_packets + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 25 | `fwd_byte_ratio` | Directional Asymmetry | `TotLen Fwd Pkts, Total Bytes` | Ratio | `fwd_bytes / (total_ip_bytes + 1e-5)` | StandardScaler | Base | **NO** | Active |
| 26 | `down_up_ratio_mean` | Directional Asymmetry | `Down/Up Ratio` | Mean | `mean(Down/Up Ratio)` | StandardScaler | Base | **NO** | Active |
| 27 | `down_up_ratio_std` | Directional Asymmetry | `Down/Up Ratio` | Std | `std(Down/Up Ratio)` | StandardScaler | Base | **NO** | Active |
| 28 | `pkt_len_mean` | Packet Length Moments | `Pkt Len Mean` | Mean | `mean(Pkt Len Mean)` | StandardScaler | Base | **NO** | Active |
| 29 | `pkt_len_std` | Packet Length Moments | `Pkt Len Std` | Mean | `mean(Pkt Len Std)` | StandardScaler | Base | **NO** | Active |
| 30 | `pkt_len_max` | Packet Length Moments | `Pkt Len Max` | Max | `max(Pkt Len Max)` | StandardScaler | Base | **NO** | Active |
| 31 | `pkt_len_min` | Packet Length Moments | `Pkt Len Min` | Min | `min(Pkt Len Min)` | StandardScaler | Base | **NO** | Active |
| 32 | `zero_payload_ratio` | Packet Length Moments | `TotLen Fwd/Bwd Pkts` | Ratio | `count(fwd_bytes==0 and bwd_bytes==0) / flow_count` | StandardScaler | Base | **NO** | Active |
| 33 | `flow_iat_mean` | IAT Pacing & Lifetime | `Flow IAT Mean` | Mean | `mean(Flow IAT Mean)` | StandardScaler | Base | **NO** | Active |
| 34 | `flow_iat_std` | IAT Pacing & Lifetime | `Flow IAT Std` | Mean | `mean(Flow IAT Std)` | StandardScaler | Base | **NO** | Active |
| 35 | `flow_iat_max` | IAT Pacing & Lifetime | `Flow IAT Max` | Max | `max(Flow IAT Max)` | StandardScaler | Base | **NO** | Active |
| 36 | `flow_iat_min` | IAT Pacing & Lifetime | `Flow IAT Min` | Min | `min(Flow IAT Min)` | StandardScaler | Base | **NO** | Active |
| 37 | `active_connection_lifetime_mean` | IAT Pacing & Lifetime | `Flow Duration` | Mean | `mean(Flow Duration)` | StandardScaler | Base | **NO** | Active |
| 38 | `delta_flow_count` | Velocity Deltas | `flow_count` | Delta | `flow_count_t - flow_count_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 39 | `delta_total_ip_bytes` | Velocity Deltas | `total_ip_bytes` | Delta | `total_ip_bytes_t - total_ip_bytes_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 40 | `delta_total_packets` | Velocity Deltas | `total_packets` | Delta | `total_packets_t - total_packets_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 41 | `delta_flow_rate` | Velocity Deltas | `flow_rate` | Delta | `flow_rate_t - flow_rate_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 42 | `delta_byte_rate` | Velocity Deltas | `byte_rate` | Delta | `byte_rate_t - byte_rate_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 43 | `delta_packet_rate` | Velocity Deltas | `packet_rate` | Delta | `packet_rate_t - packet_rate_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 44 | `delta_dst_port_entropy` | Velocity Deltas | `dst_port_entropy` | Delta | `dst_port_entropy_t - dst_port_entropy_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 45 | `delta_port_concentration` | Velocity Deltas | `port_concentration` | Delta | `port_concentration_t - port_concentration_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 46 | `delta_auth_port_ratio` | Velocity Deltas | `auth_port_ratio` | Delta | `auth_port_ratio_t - auth_port_ratio_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 47 | `delta_syn_ratio` | Velocity Deltas | `syn_ratio` | Delta | `syn_ratio_t - syn_ratio_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 48 | `delta_ack_ratio` | Velocity Deltas | `ack_ratio` | Delta | `ack_ratio_t - ack_ratio_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 49 | `delta_rst_ratio` | Velocity Deltas | `rst_ratio` | Delta | `rst_ratio_t - rst_ratio_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 50 | `delta_rst_to_syn_ratio` | Velocity Deltas | `rst_to_syn_ratio` | Delta | `rst_to_syn_ratio_t - rst_to_syn_ratio_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 51 | `delta_fwd_packet_ratio` | Velocity Deltas | `fwd_packet_ratio` | Delta | `fwd_packet_ratio_t - fwd_packet_ratio_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 52 | `delta_pkt_len_mean` | Velocity Deltas | `pkt_len_mean` | Delta | `pkt_len_mean_t - pkt_len_mean_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 53 | `delta_flow_iat_mean` | Velocity Deltas | `flow_iat_mean` | Delta | `flow_iat_mean_t - flow_iat_mean_{t-1}` | StandardScaler | Delta | **NO** | Active |
| 54 | `delta_active_connection_lifetime_mean` | Velocity Deltas | `active_connection_lifetime_mean` | Delta | `act_life_t - act_life_{t-1}` | StandardScaler | Delta | **NO** | Active |
