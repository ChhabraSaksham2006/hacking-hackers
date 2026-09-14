# Precursor Feature Attribution & XAI Audit Report
**SIH26153 | AI-Based Network Attack Forecasting from Network Traffic Data**
**Date:** 2026-09-12 | **Method:** Path-Integrated Gradients across 6 Canonical Physical Telemetry Groups

---

## 1. Precursor Attribution Matrix by Attack Category

| Attack Type | Dominant Precursor Group | Group Weight | Top Salient Diagnostic Feature | Top Feature Weight | MITRE ATT&CK Tactic | MITRE ATT&CK Technique |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PortScan** | `port_entropy_scanners` | 70.7% | `dst_port_entropy` | 0.112 | TA0043 (Reconnaissance) | T1046 (Network Service Discovery) |
| **DoS Hulk** | `volumetric_rates` | 82.3% | `delta_byte_rate` | 0.072 | TA0040 (Impact) | T1498.001 (Direct Network Flood) |
| **DoS GoldenEye** | `flow_timing_iat` | 70.0% | `active_connection_lifetime_mean` | 0.115 | TA0040 (Impact) | T1499.003 (Application Exhaustion Flood) |
| **DDoS LOIC** | `volumetric_rates` | 82.3% | `delta_total_packets` | 0.072 | TA0040 (Impact) | T1498 (Network Denial of Service) |
| **SSH-Patator** | `port_entropy_scanners` | 70.8% | `delta_dst_port_entropy` | 0.108 | TA0006 (Credential Access) | T1110.001 (Password Guessing) |
| **FTP-Patator** | `port_entropy_scanners` | 71.1% | `auth_port_ratio` | 0.109 | TA0006 (Credential Access) | T1110.001 (Password Guessing) |
| **Web Attack** | `packet_size_dynamics` | 80.6% | `pkt_len_mean` | 0.084 | TA0001 (Initial Access) | T1190 (Exploit Public Application) |
| **Infiltration** | `flow_timing_iat` | 71.9% | `flow_iat_mean` | 0.109 | TA0011 (Command & Control) | T1071.001 (Web Protocols) |
| **Heartbleed** | `packet_size_dynamics` | 79.9% | `pkt_len_max` | 0.081 | TA0001 (Initial Access) | T1190 (Exploit Public Application) |
| **Botnet** | `protocol_composition` | 62.0% | `delta_tcp_ratio` | 0.131 | TA0011 (Command & Control) | T1071 (Application Layer Protocol) |

---

## 2. Canonical Telemetry Feature Groups & Physical Interpretability

1. **`volumetric_rates` (DoS / DDoS Flood Forecasters):**
   - Captures anomalous surges in flow rates, IP bytes, packet counts, and 1st-order discrete deltas $\Delta$.
   - **Key Indicator:** Rapid divergence of $\Delta \text{packet\_rate} > 2.5\sigma$ prior to saturating socket exhaustion.

2. **`tcp_handshake_flags` (Scan / Exploit Forecasters):**
   - Monitors stateful TCP handshake asymmetry (SYN vs ACK vs RST vs FIN ratios).
   - **Key Indicator:** Sharp escalation in `syn_ratio` with zero corresponding `ack_ratio` completion.

3. **`port_entropy_scanners` (Reconnaissance & Brute-Force Forecasters):**
   - Measures Shannon entropy across destination port distributions and authorization port concentrations.
   - **Key Indicator:** Elevated `dst_port_entropy` and sudden spikes in `unique_dst_ports`.

4. **`packet_size_dynamics` (Web Exploits & Buffer Attacks):**
   - Quantifies packet length distributions, zero-payload ratios, and forward/backward byte imbalances.
   - **Key Indicator:** Shift in `zero_payload_ratio` coupled with high variance in `pkt_len_max`.

5. **`flow_timing_iat` (Slowloris / Application Exhaustion / C2 Beaconing):**
   - Measures inter-arrival times (mean, std, min, max) and active TCP connection lifetime persistence.
   - **Key Indicator:** Extreme `active_connection_lifetime_mean` expansion with low periodic flow IAT variance.

6. **`protocol_composition` (Botnet Command & Control / Protocol Inversion):**
   - Detects abnormal shifts in protocol ratios (TCP vs UDP vs ICMP).
   - **Key Indicator:** Sudden skew in `udp_ratio` or rapid socket churn `delta_flow_count`.
