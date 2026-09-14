"""
CIC-IDS2017 Feature Adapter & Projection Engine

Transforms CICFlowMeter flow records into the canonical 47-dimensional State Vector (S_t)
used across the entire World Model architecture.

Includes detailed mathematical reasoning for every feature projection:
  1. Flow Volume & Rates (Packets, Bytes, Rates)
  2. Protocol Distributions & Port Targeting (SSH/FTP auth targeting)
  3. Directional Flow & Asymmetry (Down/Up, Subflow stats)
  4. Layer-4 TCP Flag Signatures & Handshake Health
  5. Inter-Arrival Time (IAT) Pacing Dynamics
  6. Packet & Payload Length Distributions
  7. Window & Active/Idle Dynamics
"""

import os
import sys
import glob
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.cic_mapping import map_cic_label_to_stage, STAGE_NAMES_CIC


AUTH_PORTS = {21, 22, 23}  # FTP, SSH, Telnet


def adapt_cic_dataframe(df: pd.DataFrame, session_name: str) -> pd.DataFrame:
    """
    Projects a raw CIC-IDS2017 DataFrame (79 columns) into the canonical
    47-dimensional State Vector representation matching DARPA schema.
    """
    # ── 1. Clean Column Names & Handle Infs / NaNs ─────────────────────────
    df.columns = [c.strip() for c in df.columns]
    
    # Replace inf and -inf with NaN, then fill with 0 or column medians
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Identify Label column
    label_col = [c for c in df.columns if 'label' in c.lower()][0]
    raw_labels = df[label_col].values
    mitre_stage_codes = np.array([map_cic_label_to_stage(l) for l in raw_labels], dtype=int)
    
    n_rows = len(df)
    adapted = pd.DataFrame(index=df.index)

    # ── 2. Volume & Rate Telemetry (Features 0..4) ─────────────────────────
    # Total packets across forward and backward directions
    fwd_pkts = df['Total Fwd Packets'].fillna(0).values
    bwd_pkts = df['Total Backward Packets'].fillna(0).values
    total_pkts = fwd_pkts + bwd_pkts
    adapted['packet_count'] = total_pkts

    # Total IP payload and header bytes
    fwd_bytes = df['Total Length of Fwd Packets'].fillna(0).values
    bwd_bytes = df['Total Length of Bwd Packets'].fillna(0).values
    total_bytes = fwd_bytes + bwd_bytes
    adapted['ip_byte_count'] = total_bytes

    # Flow count (each record in CIC is 1 bidirectional conversation)
    adapted['flow_count'] = np.ones(n_rows, dtype=np.float32)

    # Packet rate and Byte rate (clamped to prevent overflow)
    flow_duration_sec = (df['Flow Duration'].fillna(0).values / 1e6).clip(min=1e-5)
    adapted['packet_rate'] = (total_pkts / flow_duration_sec).clip(max=1e6)
    adapted['byte_rate'] = (total_bytes / flow_duration_sec).clip(max=1e8)

    # ── 3. Protocol & Port Distribution (Features 5..13) ───────────────────
    # CIC-IDS is predominantly TCP/UDP network flows
    adapted['tcp_ratio'] = np.ones(n_rows, dtype=np.float32)  # Predominantly TCP in intrusion sessions
    adapted['udp_ratio'] = np.zeros(n_rows, dtype=np.float32)
    adapted['icmp_ratio'] = np.zeros(n_rows, dtype=np.float32)

    dst_ports = df['Destination Port'].fillna(0).values
    adapted['unique_src_ips'] = np.ones(n_rows, dtype=np.float32)
    adapted['unique_dst_ips'] = np.ones(n_rows, dtype=np.float32)
    adapted['unique_dst_ports'] = np.ones(n_rows, dtype=np.float32)
    adapted['max_dst_ports_per_ip'] = np.ones(n_rows, dtype=np.float32)
    adapted['avg_dst_ports_per_ip'] = np.ones(n_rows, dtype=np.float32)
    adapted['port_entropy'] = np.zeros(n_rows, dtype=np.float32)

    # ── 4. TCP Flag Signatures & State (Features 14..25) ───────────────────
    syn_cnt = df.get('SYN Flag Count', pd.Series(0, index=df.index)).fillna(0).values
    ack_cnt = df.get('ACK Flag Count', pd.Series(0, index=df.index)).fillna(0).values
    rst_cnt = df.get('RST Flag Count', pd.Series(0, index=df.index)).fillna(0).values
    fin_cnt = df.get('FIN Flag Count', pd.Series(0, index=df.index)).fillna(0).values
    psh_cnt = df.get('PSH Flag Count', pd.Series(0, index=df.index)).fillna(0).values
    urg_cnt = df.get('URG Flag Count', pd.Series(0, index=df.index)).fillna(0).values

    adapted['pure_syn_count'] = syn_cnt
    adapted['ack_count'] = ack_cnt
    adapted['rst_count'] = rst_cnt
    adapted['fin_count'] = fin_cnt
    adapted['psh_count'] = psh_cnt
    adapted['urg_count'] = urg_cnt

    safe_pkts = np.maximum(total_pkts, 1.0)
    adapted['syn_ratio'] = (syn_cnt / safe_pkts).clip(0.0, 1.0)
    adapted['ack_ratio'] = (ack_cnt / safe_pkts).clip(0.0, 1.0)
    adapted['rst_ratio'] = (rst_cnt / safe_pkts).clip(0.0, 1.0)
    adapted['fin_ratio'] = (fin_cnt / safe_pkts).clip(0.0, 1.0)
    adapted['rst_to_syn_ratio'] = (rst_cnt / (syn_cnt + 1e-5)).clip(0.0, 100.0)
    adapted['handshake_completion_ratio'] = np.minimum(syn_cnt, ack_cnt) / (np.maximum(syn_cnt, ack_cnt) + 1e-5)

    # ── 5. TCP Window & Retransmissions (Features 26..31) ──────────────────
    adapted['retransmission_count'] = np.zeros(n_rows, dtype=np.float32)
    adapted['retransmission_rate'] = np.zeros(n_rows, dtype=np.float32)

    init_win_fwd = df.get('Init_Win_bytes_forward', pd.Series(0, index=df.index)).fillna(0).values
    init_win_bwd = df.get('Init_Win_bytes_backward', pd.Series(0, index=df.index)).fillna(0).values
    adapted['win_mean'] = (init_win_fwd + init_win_bwd) / 2.0
    adapted['win_std'] = np.abs(init_win_fwd - init_win_bwd) / 2.0

    # Default TTL baseline (standard OS baseline = 64/128)
    adapted['ttl_mean'] = np.full(n_rows, 64.0, dtype=np.float32)
    adapted['ttl_std'] = np.zeros(n_rows, dtype=np.float32)

    # ── 6. Payload & Packet Length Statistics (Features 32..35) ───────────
    adapted['payload_mean'] = df.get('Packet Length Mean', pd.Series(0, index=df.index)).fillna(0).values
    adapted['payload_std'] = df.get('Packet Length Std', pd.Series(0, index=df.index)).fillna(0).values
    adapted['payload_max'] = df.get('Max Packet Length', pd.Series(0, index=df.index)).fillna(0).values
    
    min_pkt_len = df.get('Min Packet Length', pd.Series(0, index=df.index)).fillna(0).values
    adapted['zero_payload_ratio'] = (min_pkt_len == 0).astype(np.float32)

    # ── 7. Inter-Arrival Time (IAT) Dynamics (Features 36..39) ─────────────
    # Flow IAT statistics in microseconds converted to seconds
    iat_mean_s = (df.get('Flow IAT Mean', pd.Series(0, index=df.index)).fillna(0).values / 1e6).clip(0, 1000)
    iat_std_s = (df.get('Flow IAT Std', pd.Series(0, index=df.index)).fillna(0).values / 1e6).clip(0, 1000)
    iat_max_s = (df.get('Flow IAT Max', pd.Series(0, index=df.index)).fillna(0).values / 1e6).clip(0, 1000)
    iat_min_s = (df.get('Flow IAT Min', pd.Series(0, index=df.index)).fillna(0).values / 1e6).clip(0, 1000)

    adapted['iat_min_flow_mean'] = iat_min_s
    adapted['iat_global_mean'] = iat_mean_s
    adapted['iat_global_std'] = iat_std_s
    adapted['iat_global_max'] = iat_max_s

    # ── 8. Stealth, Fragmentation & ICMP Telemetry (Features 40..44) ──────
    adapted['fragment_count'] = np.zeros(n_rows, dtype=np.float32)
    adapted['fragment_ratio'] = np.zeros(n_rows, dtype=np.float32)
    adapted['max_frag_offset'] = np.zeros(n_rows, dtype=np.float32)
    adapted['oversized_icmp_count'] = np.zeros(n_rows, dtype=np.float32)
    adapted['icmp_payload_max'] = np.zeros(n_rows, dtype=np.float32)

    # ── 9. Authentication Port Targeting (Features 45..46) ────────────────
    # Identifies targeted brute-force attacks on FTP (21), SSH (22), Telnet (23)
    is_auth_target = np.isin(dst_ports, list(AUTH_PORTS)).astype(np.float32)
    adapted['auth_packet_count'] = is_auth_target * total_pkts
    adapted['auth_packet_ratio'] = is_auth_target

    # ── 10. Fill Remaining NaNs and Metadata ──────────────────────────────
    adapted = adapted.fillna(0.0)
    
    # Metadata columns matching DARPA format
    adapted.insert(0, 'session', session_name)
    adapted.insert(1, 'dataset', 'CIC-IDS2017')
    adapted.insert(2, 'raw_attack_type', raw_labels)
    adapted.insert(3, 'mitre_stage_code', mitre_stage_codes)
    adapted.insert(4, 'mitre_stage_name', [STAGE_NAMES_CIC.get(c, 'Unknown') for c in mitre_stage_codes])

    return adapted


def process_all_cic_files(
    cic_dir: str = "data/CIC-IDS2017",
    out_dir: str = "data/processed_cic",
    max_samples_per_file: int = 100000
) -> List[str]:
    """
    Processes all 8 CIC-IDS2017 CSV files, samples/adapts them into clean Parquet files.
    """
    os.makedirs(out_dir, exist_ok=True)
    csv_files = glob.glob(os.path.join(cic_dir, "*.csv"))
    print(f"Found {len(csv_files)} CIC-IDS2017 files in {cic_dir}")

    parquet_paths = []

    for f in sorted(csv_files):
        session_name = os.path.basename(f).replace('.pcap_ISCX.csv', '').replace('.csv', '')
        out_pq = os.path.join(out_dir, f"windows_cic_{session_name}.parquet")
        
        print(f"\nProcessing CIC Session: {session_name} ...")
        # Read CSV with robust encoding
        df_raw = pd.read_csv(f, encoding='cp1252', low_memory=False)
        print(f"  Raw records: {len(df_raw):,}")

        # If file is very large, sample intelligently (preserving all attacks)
        label_col = [c for c in df_raw.columns if 'label' in c.lower()][0]
        df_attacks = df_raw[df_raw[label_col].str.strip() != 'BENIGN']
        df_benign = df_raw[df_raw[label_col].str.strip() == 'BENIGN']

        # Sample benign to keep dataset balanced and fast to train
        if len(df_benign) > max_samples_per_file:
            df_benign = df_benign.sample(n=max_samples_per_file, random_state=42)

        df_sampled = pd.concat([df_attacks, df_benign], ignore_index=True)
        # Shuffle sampled dataset so attacks are uniformly distributed across train/test splits
        df_sampled = df_sampled.sample(frac=1.0, random_state=42).reset_index(drop=True)
        print(f"  Sampled dataset: {len(df_sampled):,} (Attacks: {len(df_attacks):,}, Benign: {len(df_benign):,})")

        # Project features
        df_adapted = adapt_cic_dataframe(df_sampled, session_name)
        df_adapted.to_parquet(out_pq, index=False)
        size_mb = os.path.getsize(out_pq) / (1024 * 1024)
        print(f"  Saved Parquet: {out_pq} ({size_mb:.2f} MB)")
        parquet_paths.append(out_pq)

    return parquet_paths


if __name__ == "__main__":
    process_all_cic_files()
