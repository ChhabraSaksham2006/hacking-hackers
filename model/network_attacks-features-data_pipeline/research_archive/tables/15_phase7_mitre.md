# 15 — Behavioral Attribution to MITRE ATT&CK Mapping

| MITRE Technique ID | Technique Name | MITRE Tactic | Contributing Feature Clusters | Physical Triggering Telemetry Signature |
|---|---|---|---|---|
| **T1046** | Network Service Scanning | Discovery | Port Targeting & TCP Flags | Rapid rise in `dst_port_entropy`, drop in `port_concentration`, elevation in `syn_ratio` |
| **T1110** | Brute Force | Credential Access | Port Targeting & TCP Flags | Spikes in `auth_port_ratio` (ports 21/22), elevation in `rst_ratio` from repeated failed logins |
| **T1498** | Network Denial of Service | Impact | Volume & Payload Asymmetry | Extreme spikes in `packet_rate`, `byte_rate`, dominance of `zero_payload_ratio` |
| **T1071** | Application Layer Protocol | Command & Control | Timing Jitter & Payload Asymmetry | Periodic pacing in `flow_iat_mean`, high IAT std dev, small uniform packet sizes |
| **T1190** | Exploit Public-Facing App | Initial Access | TCP Flags & Payload Asymmetry | Elevated `psh_count`, asymmetry in `fwd_byte_ratio`, anomalous handshake completion |

### Interpretation

The behavioral attribution layer computes the forecasted physical network shift Delta S_{t+K} = S_hat_{t+K} - S_t and scores it across 5 domain clusters. This mapping is explicitly a deterministic, evidence-based attribution heuristic—NOT a trained MITRE classifier or causal inference engine. It provides SOC analysts with transparent physical reasoning for why an early warning was emitted.
