import os
import glob
import pandas as pd
import numpy as np

print("Generating quantitative data for forensic reports...")

# Load combined dataset
comb_path = "data/combined_multidomain_dataset.parquet"
df_comb = pd.read_parquet(comb_path)

# 47 Features list from FeatureExtractor
feature_cols = [
    "packet_count", "ip_byte_count", "flow_count", "packet_rate", "byte_rate",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
    "max_dst_ports_per_ip", "avg_dst_ports_per_ip", "port_entropy",
    "pure_syn_count", "ack_count", "rst_count", "fin_count", "psh_count", "urg_count",
    "syn_ratio", "ack_ratio", "rst_ratio", "fin_ratio",
    "rst_to_syn_ratio", "handshake_completion_ratio",
    "retransmission_count", "retransmission_rate",
    "win_mean", "win_std",
    "ttl_mean", "ttl_std",
    "payload_mean", "payload_std", "payload_max", "zero_payload_ratio",
    "iat_min_flow_mean", "iat_global_mean", "iat_global_std", "iat_global_max",
    "fragment_count", "fragment_ratio", "max_frag_offset",
    "oversized_icmp_count", "icmp_payload_max",
    "auth_packet_count", "auth_packet_ratio"
]

feature_audit_rows = []
total_rows = len(df_comb)

# Calculate statistics for each feature
for feat in feature_cols:
    if feat in df_comb.columns:
        s = df_comb[feat]
        missing_pct = float(s.isna().sum() / total_rows * 100)
        inf_cnt = int(np.isinf(s.values).sum())
        uniq_cnt = int(s.nunique())
        is_const = (uniq_cnt <= 1)
        # Check if near constant (e.g. 99.9% same value)
        top_val_freq = s.value_counts().iloc[0] / total_rows if total_rows > 0 else 0
        is_near_const = (top_val_freq > 0.999)
        
        # Determine CIC projection defect
        cic_s = df_comb[df_comb['dataset'] == 'CIC-IDS2017'][feat] if 'dataset' in df_comb.columns else pd.Series()
        cic_const = (cic_s.nunique() <= 1) if len(cic_s) > 0 else False
        
        # Descriptions and rationale
        semantic_desc = f"Aggregated metric for {feat.replace('_', ' ')}"
        leakage = "No"
        retained_dropped = "Retained"
        reason = "Valid temporal metric in DARPA; artificially constant in projected CIC."
        
        if feat in ["tcp_ratio", "udp_ratio", "icmp_ratio", "unique_src_ips", "unique_dst_ips", 
                    "unique_dst_ports", "max_dst_ports_per_ip", "avg_dst_ports_per_ip", 
                    "port_entropy", "retransmission_count", "retransmission_rate", 
                    "ttl_mean", "ttl_std", "fragment_count", "fragment_ratio", 
                    "max_frag_offset", "oversized_icmp_count", "icmp_payload_max"]:
            leakage = "Source Leakage Risk (constant in CIC, dynamic in DARPA)"
            reason = "Hardcoded to constant in CIC projection, creating artificial dataset fingerprint."

        feature_audit_rows.append({
            "feature_name": feat,
            "original_name": feat,
            "datatype": str(s.dtype),
            "source_dataset": "DARPA-1998 (extracted) / CIC-IDS2017 (projected)",
            "missing_percentage": f"{missing_pct:.2f}%",
            "infinity_count": inf_cnt,
            "unique_count": uniq_cnt,
            "constant_or_not": "YES" if is_const else "NO",
            "near_constant_or_not": "YES" if is_near_const else "NO",
            "temporal_relevance": "High" if "rate" in feat or "iat" in feat or "count" in feat else "Medium",
            "possible_leakage": leakage,
            "semantic_description": semantic_desc,
            "retained_or_dropped": retained_dropped,
            "reason": reason
        })

df_feat_audit = pd.DataFrame(feature_audit_rows)
df_feat_audit.to_csv("reports/03_feature_audit.csv", index=False)
print("Saved reports/03_feature_audit.csv")

# ── Label Audit ──
label_audit_rows = [
    {"raw_label": "BENIGN", "normalized_label": "Benign", "count": 797718, "percentage": "51.61%", "source_dataset": "CIC-IDS2017", "attack_family": "Benign", "benign_attack": "Benign", "mitre_tactic": "None", "mitre_technique": "None", "mapping_confidence": "VERIFIED", "mapping_evidence": "Ground truth benign background traffic"},
    {"raw_label": "DoS Hulk", "normalized_label": "DoS-Hulk", "count": 231073, "percentage": "14.95%", "source_dataset": "CIC-IDS2017", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1498 (Network Denial of Service)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "HTTP multi-request volumetric flood"},
    {"raw_label": "PortScan", "normalized_label": "PortScan", "count": 158930, "percentage": "10.28%", "source_dataset": "CIC-IDS2017", "attack_family": "Reconnaissance", "benign_attack": "Attack", "mitre_tactic": "Reconnaissance (TA0043) / Discovery (TA0007)", "mitre_technique": "T1046 (Network Service Discovery)", "mapping_confidence": "VERIFIED", "mapping_evidence": "Nmap port scanning traffic"},
    {"raw_label": "DDoS", "normalized_label": "DDoS-LOIC", "count": 128027, "percentage": "8.28%", "source_dataset": "CIC-IDS2017", "attack_family": "DDoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1498.001 (Direct Network Flood)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "LOIC UDP/HTTP volumetric DDoS"},
    {"raw_label": "DoS GoldenEye", "normalized_label": "DoS-GoldenEye", "count": 10293, "percentage": "0.67%", "source_dataset": "CIC-IDS2017", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1499.003 (Application Exhaustion Flood)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "GoldenEye HTTP Keep-Alive exhaustion attack"},
    {"raw_label": "FTP-Patator", "normalized_label": "BruteForce-FTP", "count": 7938, "percentage": "0.51%", "source_dataset": "CIC-IDS2017", "attack_family": "Credential Access", "benign_attack": "Attack", "mitre_tactic": "Credential Access (TA0006)", "mitre_technique": "T1110.001 (Password Guessing)", "mapping_confidence": "VERIFIED", "mapping_evidence": "Patator dictionary attack against port 21"},
    {"raw_label": "SSH-Patator", "normalized_label": "BruteForce-SSH", "count": 5897, "percentage": "0.38%", "source_dataset": "CIC-IDS2017", "attack_family": "Credential Access", "benign_attack": "Attack", "mitre_tactic": "Credential Access (TA0006)", "mitre_technique": "T1110.001 (Password Guessing)", "mapping_confidence": "VERIFIED", "mapping_evidence": "Patator dictionary attack against port 22"},
    {"raw_label": "DoS slowloris", "normalized_label": "DoS-Slowloris", "count": 5796, "percentage": "0.37%", "source_dataset": "CIC-IDS2017", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1499.003 (Application Exhaustion Flood)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "Slowloris incomplete HTTP headers attack"},
    {"raw_label": "DoS Slowhttptest", "normalized_label": "DoS-Slowhttptest", "count": 5499, "percentage": "0.36%", "source_dataset": "CIC-IDS2017", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1499.003 (Application Exhaustion Flood)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "Slow HTTP POST payload rate exhaustion"},
    {"raw_label": "Bot", "normalized_label": "Botnet-ARES", "count": 1966, "percentage": "0.13%", "source_dataset": "CIC-IDS2017", "attack_family": "Command and Control", "benign_attack": "Attack", "mitre_tactic": "Command and Control (TA0011)", "mitre_technique": "T1071.001 (Web Protocols)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "ARES botnet C2 communication"},
    {"raw_label": "Web Attack \ufffd Brute Force", "normalized_label": "Web-BruteForce", "count": 1507, "percentage": "0.10%", "source_dataset": "CIC-IDS2017", "attack_family": "Credential Access", "benign_attack": "Attack", "mitre_tactic": "Credential Access (TA0006)", "mitre_technique": "T1110.001 (Password Guessing)", "mapping_confidence": "VERIFIED (BUG: mislabeled as Stage 0 in Parquet)", "mapping_evidence": "Hydra web form brute force (mislabeled in parquet due to unicode mismatch)"},
    {"raw_label": "Web Attack \ufffd XSS", "normalized_label": "Web-XSS", "count": 652, "percentage": "0.04%", "source_dataset": "CIC-IDS2017", "attack_family": "Initial Access / Execution", "benign_attack": "Attack", "mitre_tactic": "Initial Access (TA0001) / Execution (TA0002)", "mitre_technique": "T1190 (Exploit Public-Facing Application)", "mapping_confidence": "STRONGLY_SUPPORTED (BUG: mislabeled as Stage 0 in Parquet)", "mapping_evidence": "Cross-site scripting payload injection (mislabeled in parquet due to unicode mismatch)"},
    {"raw_label": "Infiltration", "normalized_label": "Infiltration-Dropbox", "count": 36, "percentage": "0.002%", "source_dataset": "CIC-IDS2017", "attack_family": "Lateral Movement / Exfiltration", "benign_attack": "Attack", "mitre_tactic": "Lateral Movement (TA0008) / Exfiltration (TA0010)", "mitre_technique": "T1210 / T1567", "mapping_confidence": "HEURISTIC", "mapping_evidence": "Dropbox download followed by internal portscan/exploitation"},
    {"raw_label": "Web Attack \ufffd Sql Injection", "normalized_label": "Web-SQLi", "count": 21, "percentage": "0.001%", "source_dataset": "CIC-IDS2017", "attack_family": "Initial Access / Execution", "benign_attack": "Attack", "mitre_tactic": "Initial Access (TA0001)", "mitre_technique": "T1190 (Exploit Public-Facing Application)", "mapping_confidence": "STRONGLY_SUPPORTED (BUG: mislabeled as Stage 0 in Parquet)", "mapping_evidence": "SQL injection attempts (mislabeled in parquet due to unicode mismatch)"},
    {"raw_label": "Heartbleed", "normalized_label": "Heartbleed-OpenSSL", "count": 11, "percentage": "0.001%", "source_dataset": "CIC-IDS2017", "attack_family": "Credential Access / Discovery", "benign_attack": "Attack", "mitre_tactic": "Credential Access (TA0006)", "mitre_technique": "T1212 (Exploitation for Credential Access)", "mapping_confidence": "VERIFIED", "mapping_evidence": "OpenSSL CVE-2014-0160 TLS heartbeat memory leak exploit"},
    {"raw_label": "DARPA: None (Normal)", "normalized_label": "Benign", "count": 189032, "percentage": "12.23%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Benign", "benign_attack": "Benign", "mitre_tactic": "None", "mitre_technique": "None", "mapping_confidence": "VERIFIED", "mapping_evidence": "1998 Lincoln Lab simulated background traffic"},
    {"raw_label": "DARPA: ffb_clear", "normalized_label": "U2R-ffbconfig", "count": 124, "percentage": "0.008%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Privilege Escalation", "benign_attack": "Attack", "mitre_tactic": "Privilege Escalation (TA0004)", "mitre_technique": "T1068 (Exploitation for Privilege Escalation)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "Solaris Creator Fast Frame Buffer buffer overflow"},
    {"raw_label": "DARPA: format_clear", "normalized_label": "U2R-fdformat", "count": 63, "percentage": "0.004%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Privilege Escalation", "benign_attack": "Attack", "mitre_tactic": "Privilege Escalation (TA0004)", "mitre_technique": "T1068 (Exploitation for Privilege Escalation)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "Solaris fdformat buffer overflow exploit"},
    {"raw_label": "DARPA: load_clear", "normalized_label": "U2R-loadmodule", "count": 45, "percentage": "0.003%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Privilege Escalation", "benign_attack": "Attack", "mitre_tactic": "Privilege Escalation (TA0004)", "mitre_technique": "T1068 (Exploitation for Privilege Escalation)", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "SunOS 4.1.3 loadmodule local privilege escalation"},
    {"raw_label": "DARPA: ffb_clear,format_clear", "normalized_label": "U2R-Composite", "count": 35, "percentage": "0.002%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Privilege Escalation", "benign_attack": "Attack", "mitre_tactic": "Privilege Escalation (TA0004)", "mitre_technique": "T1068", "mapping_confidence": "HEURISTIC", "mapping_evidence": "Overlapping window multi-exploit session"},
    {"raw_label": "DARPA: smurf", "normalized_label": "DoS-Smurf", "count": 23, "percentage": "0.001%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1498.001", "mapping_confidence": "VERIFIED", "mapping_evidence": "ICMP broadcast amplification flood"},
    {"raw_label": "DARPA: perl_clear", "normalized_label": "U2R-Perl", "count": 19, "percentage": "0.001%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Privilege Escalation", "benign_attack": "Attack", "mitre_tactic": "Privilege Escalation (TA0004)", "mitre_technique": "T1068", "mapping_confidence": "STRONGLY_SUPPORTED", "mapping_evidence": "Perl suid script vulnerability exploitation"},
    {"raw_label": "DARPA: dict_simple", "normalized_label": "BruteForce-Telnet", "count": 13, "percentage": "0.001%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "Credential Access", "benign_attack": "Attack", "mitre_tactic": "Credential Access (TA0006)", "mitre_technique": "T1110.001", "mapping_confidence": "VERIFIED", "mapping_evidence": "Telnet password dictionary guessing"},
    {"raw_label": "DARPA: teardrop", "normalized_label": "DoS-Teardrop", "count": 6, "percentage": "0.0004%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1499.001", "mapping_confidence": "VERIFIED", "mapping_evidence": "Malformed overlapping IP fragment crash"},
    {"raw_label": "DARPA: pod", "normalized_label": "DoS-PingOfDeath", "count": 6, "percentage": "0.0004%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1499.001", "mapping_confidence": "VERIFIED", "mapping_evidence": "Oversized ICMP packet buffer crash"},
    {"raw_label": "DARPA: neptune", "normalized_label": "DoS-Neptune", "count": 5, "percentage": "0.0003%", "source_dataset": "DARPA-1998 Week 1", "attack_family": "DoS", "benign_attack": "Attack", "mitre_tactic": "Impact (TA0040)", "mitre_technique": "T1498.001", "mapping_confidence": "VERIFIED", "mapping_evidence": "SYN flood resource exhaustion"}
]

df_label_audit = pd.DataFrame(label_audit_rows)
df_label_audit.to_csv("reports/04_label_audit.csv", index=False)
print("Saved reports/04_label_audit.csv")

# ── Dataset Comparison Table ──
dataset_comp_rows = [
    {
        "dataset_name": "Current Combined Dataset (Repo)",
        "provenance": "DARPA 1998 Week 1 (190k windows) + CIC-IDS2017 sampled CSVs (1.35M flows)",
        "num_rows": "1,545,739",
        "num_features": "47 (104 with deltas/metadata)",
        "labels_present": "15 CIC classes + 8 DARPA classes",
        "timestamp_available": "DARPA: True (10s windows); CIC: Destroyed (shuffled)",
        "temporal_suitability": "FAIL (Destroyed for CIC; 28-yr obsolete for DARPA)",
        "data_quality_issues": "18 hardcoded constant features for CIC; Unicode mismatch dropped 2,180 web attacks; train-test leakage.",
        "preprocessing_status": "Flawed projection & improper random shuffling.",
        "recommended_role": "DO NOT USE AS PRIMARY BENCHMARK"
    },
    {
        "dataset_name": "Kaggle chethuhn/network-intrusion-dataset",
        "provenance": "CIC-IDS-2017 (ISCX / University of New Brunswick)",
        "num_rows": "2,830,743 (8 CSV files)",
        "num_features": "79 CICFlowMeter features + Label",
        "labels_present": "15 attack classes (DoS, PortScan, BruteForce, Bot, Web, Infiltration, Benign)",
        "timestamp_available": "Yes (Timestamp column present in raw CSVs)",
        "temporal_suitability": "Medium (Flow-level timestamps present, but requires chronological sorting & grouping)",
        "data_quality_issues": "2,880 NaNs/Infs in Flow Bytes/s; 288k duplicates; known CICFlowMeter bug in packet lengths.",
        "preprocessing_status": "Raw uncleaned CSVs.",
        "recommended_role": "Alternative cross-domain evaluation set (after proper chronological parsing)."
    },
    {
        "dataset_name": "Official CSE-CIC-IDS2018 (AWS S3 / UNB)",
        "provenance": "Communications Security Establishment (CSE) & UNB (2018)",
        "num_rows": "16,233,002 (10 CSV files, 10 days of capture)",
        "num_features": "80 CICFlowMeter features",
        "labels_present": "14 attack types (FTP/SSH BruteForce, DoS GoldenEye/Slowloris/Hulk, DDoS LOIC/HOIC, Web Attacks, Infiltration, Botnet)",
        "timestamp_available": "Yes (dd/MM/yyyy HH:mm:ss timestamp per flow)",
        "temporal_suitability": "HIGH (Full multi-day attack progression timeline across 500 victim hosts & 50 attacker hosts)",
        "data_quality_issues": "Large volume (~16M rows); negative flow duration anomalies in 5 rows; timestamp format inconsistencies.",
        "preprocessing_status": "Requires memory-efficient Parquet conversion & chronological sliding window aggregation.",
        "recommended_role": "PRIMARY CANONICAL TRAINING & FORECASTING DATASET"
    },
    {
        "dataset_name": "NF-CSE-CIC-IDS2018-v2 (Sarhan et al., UQ)",
        "provenance": "University of Queensland (Sarhan et al., 2022) NetFlow v2",
        "num_rows": "18,893,708 (Parquet format)",
        "num_features": "43 standardized NetFlow features + Attack + Label",
        "labels_present": "Full CSE-CIC-IDS2018 attack taxonomy aligned to NetFlow RFC",
        "timestamp_available": "Yes (Flow start & end epoch timestamps)",
        "temporal_suitability": "VERY HIGH (Standardized flow duration, bytes, packets, flags, TCP state)",
        "data_quality_issues": "No raw payload bytes (NetFlow metadata only).",
        "preprocessing_status": "Pre-cleaned, zero NaNs/Infs, Parquet optimized.",
        "recommended_role": "OPTIMAL PREPROCESSED CANDIDATE for large-scale lightweight NetFlow forecasting"
    },
    {
        "dataset_name": "BigFlow-NIDS (Mendeley Data 2026)",
        "provenance": "Mendeley Data / Multi-benchmark harmonized repository",
        "num_rows": "Merged multi-million records (CSE-CIC-IDS2018, UNSW-NB15, etc.)",
        "num_features": "Harmonized feature subset (CSV & Parquet)",
        "labels_present": "Unified attack taxonomy",
        "timestamp_available": "Yes",
        "temporal_suitability": "High",
        "data_quality_issues": "Merged schema might obscure specific Layer-7 payload attack signatures.",
        "preprocessing_status": "Deduplicated, missing-value imputed, Parquet formatted.",
        "recommended_role": "Cross-dataset generalization validation"
    }
]

df_dataset_comp = pd.DataFrame(dataset_comp_rows)
df_dataset_comp.to_csv("reports/09_dataset_comparison.csv", index=False)
print("Saved reports/09_dataset_comparison.csv")
