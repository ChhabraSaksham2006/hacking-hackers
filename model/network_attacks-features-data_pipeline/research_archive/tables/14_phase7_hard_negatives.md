# 14 — Forensic Root Cause Analysis of Hard Negative False Alarms

| Trigger Cause Category | Sample Occurrence (%) | Dominant Behavioral Feature | Physical Telemetry Mechanism | SOC Operational Remediation |
|---|---|---|---|---|
| **Benign Multi-Port Service Discovery** | **36.0%** | `unique_dst_ports`, `dst_port_entropy` | Internal network mDNS, LLMNR, and NetBIOS broadcasts query multiple ports | Whitelist internal broadcast CIDR subnets |
| **TCP Reset Teardown Spikes** | **34.0%** | `rst_ratio`, `rst_to_syn_ratio` | Clean application terminations, browser timeouts, and proxy resets | Add connection completion ratio gating |
| **Volumetric Background Bursts** | **30.0%** | `byte_rate`, `delta_total_ip_bytes` | Routine database backups, large OS update downloads, and file sharing | Combine volume with asymmetry features |

### Interpretation

Forensic profiling of 27,721 test false alarm windows (50 detailed profiles in `reports/phase_7/03_hard_negative_analysis.csv`) reveals that 70% of false alarms originate from benign network administration protocols (NetBIOS/mDNS broadcasts and TCP reset bursts). These benign patterns physically mirror early-stage reconnaissance scanning and brute-force resets.
