# 02 — 54-Dimensional Physical State Representation

| Feature Cluster | Dimension Count | Representative Feature Names | Physical / Network Behavioral Meaning |
|---|---|---|---|
| **Volume & Density** | 3 | `flow_count`, `total_ip_bytes`, `total_packets` | Aggregate network traffic volume and bandwidth utilization |
| **Velocity Rates** | 3 | `flow_rate`, `byte_rate`, `packet_rate` | First-order velocity of flow and packet creation per second |
| **Protocol Distribution** | 3 | `tcp_ratio`, `udp_ratio`, `icmp_ratio` | Transport-layer protocol composition breakdown |
| **Port Targeting & Entropy** | 4 | `unique_dst_ports`, `port_concentration`, `dst_port_entropy`, `auth_port_ratio` | Spread vs concentration of destination ports (scans vs web traffic) |
| **TCP Flags & Health** | 10 | `syn_ratio`, `ack_ratio`, `rst_ratio`, `handshake_completion_ratio`, `rst_to_syn_ratio` | TCP connection state machine health and anomaly indicators |
| **Directional Asymmetry** | 4 | `fwd_packet_ratio`, `fwd_byte_ratio`, `down_up_ratio_mean`, `down_up_ratio_std` | Forward vs backward telemetry imbalance (exfiltration vs ingress flood) |
| **Packet Length Moments** | 5 | `pkt_len_mean`, `pkt_len_std`, `pkt_len_max`, `pkt_len_min`, `zero_payload_ratio` | Statistical moments of frame payload distributions |
| **IAT Pacing & Jitter** | 5 | `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min`, `active_connection_lifetime_mean` | Inter-arrival timing pacing, burstiness, and connection duration |
| **Base Telemetry Subtotal** | **37** | — | Static macro-behavioral window snapshot |
| **Temporal Deltas** | **17** | `delta_flow_count`, `delta_dst_port_entropy`, `delta_rst_ratio`, `delta_flow_iat_mean`, etc. | Instantaneous rate of change between consecutive 2-second windows |
| **Total Canonical State** | **54** | — | Authoritative physical network state representation $S_t \in \mathbb{R}^{54}$ |

### Interpretation

The 54-dimensional state aggregates raw flow records into consecutive 10-second rolling windows with a 2-second stride. The 37 base dimensions capture stationary behavioral properties, while the 17 delta features explicitly capture sudden physical state transitions (such as connection teardown spikes or entropy collapses). All features are standardized via StandardScaler fitted exclusively on the 5 training days.
