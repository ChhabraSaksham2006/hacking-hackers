import pandas as pd

comparison_features = [
    # Category, Feature Name, Present in 80-CICFlowMeter, Present in 43-NetFlow, Present in Senior 47-D Schema, Role in Temporal Forecasting, Recommendation
    ("Flow Identification", "Dst Port", "YES (`Dst Port`)", "YES (`L4_DST_PORT`)", "YES (`unique_dst_ports`)", "Identifies targeted service (SSH=22, HTTP=80)", "Keep"),
    ("Flow Identification", "Protocol", "YES (`Protocol`)", "YES (`PROTOCOL`)", "YES (`tcp_ratio`, `udp_ratio`)", "Distinguishes TCP, UDP, ICMP dynamics", "Keep"),
    ("Timing", "Timestamp / Start Time", "YES (`Timestamp`)", "NO in ML Parquet", "YES (Window epoch)", "Critical for chronological sorting & windowing", "Keep (Essential)"),
    ("Timing", "Flow Duration", "YES (`Flow Duration`)", "YES (`FLOW_DURATION_MILLISECONDS`)", "YES (Derived)", "Duration of network conversation", "Keep"),
    ("Volume", "Total Fwd Packets", "YES (`Tot Fwd Pkts`)", "YES (`IN_PKTS`)", "YES (`packet_count`)", "Inbound packet rate & volume", "Keep"),
    ("Volume", "Total Bwd Packets", "YES (`Tot Bwd Pkts`)", "YES (`OUT_PKTS`)", "YES (`packet_count`)", "Outbound packet rate & response symmetry", "Keep"),
    ("Volume", "Total Length of Fwd Packets", "YES (`TotLen Fwd Pkts`)", "YES (`IN_BYTES`)", "YES (`ip_byte_count`)", "Upload bandwidth consumption", "Keep"),
    ("Volume", "Total Length of Bwd Packets", "YES (`TotLen Bwd Pkts`)", "YES (`OUT_BYTES`)", "YES (`ip_byte_count`)", "Download / Exfiltration volume", "Keep"),
    ("Packet Statistics", "Fwd Packet Length Max", "YES", "NO", "YES (`payload_max`)", "Identifies jumbo frames / buffer overflows", "Keep"),
    ("Packet Statistics", "Fwd Packet Length Mean", "YES", "NO", "YES (`payload_mean`)", "Distinguishes interactive vs bulk traffic", "Keep"),
    ("Packet Statistics", "Fwd Packet Length Std", "YES", "NO", "YES (`payload_std`)", "Packet size jitter / protocol variance", "Keep"),
    ("Rate", "Flow Bytes/s", "YES", "NO", "YES (`byte_rate`)", "Bandwidth consumption velocity", "Keep (Impute 0-div infs)"),
    ("Rate", "Flow Packets/s", "YES", "NO", "YES (`packet_rate`)", "Volumetric packet flooding indicator", "Keep (Impute 0-div infs)"),
    ("Inter-Arrival Time", "Flow IAT Mean", "YES", "NO", "YES (`iat_global_mean`)", "Pacing & automation detection", "Keep"),
    ("Inter-Arrival Time", "Flow IAT Std", "YES", "NO", "YES (`iat_global_std`)", "Beaconing jitter / human vs bot variance", "Keep"),
    ("Inter-Arrival Time", "Flow IAT Max", "YES", "NO", "YES (`iat_global_max`)", "Idle timeout & long-lived session tracker", "Keep"),
    ("Inter-Arrival Time", "Flow IAT Min", "YES", "NO", "YES (`iat_min_flow_mean`)", "Micro-burst detection in DDoS", "Keep"),
    ("TCP Flags", "SYN Flag Count", "YES", "NO (Aggregated in `TCP_FLAGS`)", "YES (`pure_syn_count`, `syn_ratio`)", "SYN flood / connection attempt signature", "Keep"),
    ("TCP Flags", "RST Flag Count", "YES", "NO (Aggregated in `TCP_FLAGS`)", "YES (`rst_count`, `rst_ratio`)", "Connection rejection / scan response", "Keep"),
    ("TCP Flags", "ACK Flag Count", "YES", "NO (Aggregated in `TCP_FLAGS`)", "YES (`ack_count`, `ack_ratio`)", "Established session throughput", "Keep"),
    ("TCP Flags", "FIN Flag Count", "YES", "NO (Aggregated in `TCP_FLAGS`)", "YES (`fin_count`, `fin_ratio`)", "Clean session termination rate", "Keep"),
    ("TCP Flags", "PSH Flag Count", "YES", "NO (Aggregated in `TCP_FLAGS`)", "YES (`psh_count`)", "Immediate application push data", "Keep"),
    ("TCP Flags", "URG Flag Count", "YES", "NO (Aggregated in `TCP_FLAGS`)", "YES (`urg_count`)", "Rarely used; zero-variance in modern traffic", "Drop (Zero variance)"),
    ("Flow Control", "Init Fwd Win Byts", "YES", "NO", "YES (`win_mean`)", "OS TCP stack fingerprinting", "Keep"),
    ("Flow Control", "Init Bwd Win Byts", "YES", "NO", "YES (`win_mean`)", "Server receiver buffer health", "Keep"),
    ("Subflow", "Subflow Fwd Pkts", "YES", "NO", "NO", "Exact duplicate of `Tot Fwd Pkts` (r=1.0)", "Drop (Multicollinear)"),
    ("Subflow", "Subflow Fwd Byts", "YES", "NO", "NO", "Exact duplicate of `TotLen Fwd Pkts` (r=1.0)", "Drop (Multicollinear)"),
    ("Subflow", "Subflow Bwd Pkts", "YES", "NO", "NO", "Exact duplicate of `Tot Bwd Pkts` (r=1.0)", "Drop (Multicollinear)"),
    ("Subflow", "Subflow Bwd Byts", "YES", "NO", "NO", "Exact duplicate of `TotLen Bwd Pkts` (r=1.0)", "Drop (Multicollinear)"),
    ("Active/Idle", "Active Mean", "YES", "NO", "NO", "Burst transmission periods", "Keep"),
    ("Active/Idle", "Idle Mean", "YES", "NO", "NO", "Silence periods between commands", "Keep"),
    ("NetFlow Specific", "L7_PROTO", "NO", "YES", "NO", "Numeric Layer 7 protocol ID (e.g. HTTP=7)", "Valuable if present"),
    ("NetFlow Specific", "MIN_TTL", "NO", "YES", "YES (`ttl_mean`)", "Hop distance / routing anomaly indicator", "Keep if present"),
    ("DARPA Specific", "fragment_count", "NO", "NO", "YES (Hardcoded in CIC)", "Layer-3 IP fragmentation (Teardrop)", "Drop (Absent in CIC)"),
    ("DARPA Specific", "oversized_icmp_count", "NO", "NO", "YES (Hardcoded in CIC)", "Ping of Death anomaly", "Drop (Absent in CIC)")
]

df_feats = pd.DataFrame(comparison_features, columns=[
    "Feature Category", "Feature Name", "Present in 80-CICFlowMeter", 
    "Present in 43-NetFlow", "Present in Senior 47-D Schema", 
    "Role in Temporal Forecasting", "Forensic Recommendation"
])

df_feats.to_csv("reports/dataset_selection/04_feature_comparison.csv", index=False)
print("Saved 04_feature_comparison.csv")
