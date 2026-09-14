"""
SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
Script: scripts/preprocessing/build_temporal_states.py

Processes all 9 canonical daily Parquet files and generates 54-dimensional
macro-behavioral temporal state datasets S_t (Delta t = 10.0s, stride = 2.0s)
with multi-horizon target labels and attack onset timers.
"""

import os
import sys
import glob
import time
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import numpy as np
import pandas as pd

from src.temporal.state_aggregator import (
    TemporalStateAggregator,
    STATE_FEATURE_NAMES,
    BASE_FEATURE_NAMES,
    DELTA_FEATURE_NAMES
)

INTERIM_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\interim\cse_cic_ids2018"
PROCESSED_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\processed\temporal_states"
METADATA_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\metadata"
REPORTS_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\reports\temporal_states"

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def compute_sha256(filepath: str) -> str:
    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def main():
    print("=" * 85)
    print("      CANONICAL TEMPORAL STATE AGGREGATION & HORIZON TARGET GENERATION      ")
    print("=" * 85)

    parquet_files = sorted(glob.glob(os.path.join(INTERIM_DIR, "*.parquet")))
    print(f"Discovered {len(parquet_files)} canonical daily Parquet files.")

    aggregator = TemporalStateAggregator(
        window_duration_seconds=10.0,
        stride_seconds=2.0,
        tau_cap_seconds=300.0
    )

    manifest_records = []
    total_raw_flows = 0
    total_generated_windows = 0
    total_attack_windows = 0
    total_benign_windows = 0

    t_pipeline_start = time.time()

    for idx, pq_path in enumerate(parquet_files, 1):
        filename = os.path.basename(pq_path)
        day_id = filename.replace(".parquet", "")
        out_pq_path = os.path.join(PROCESSED_DIR, f"{day_id}_states.parquet")

        print(f"\n[{idx}/{len(parquet_files)}] Processing {filename}...")
        t_load = time.time()
        df_flows = pd.read_parquet(pq_path)
        load_sec = time.time() - t_load
        n_flows = len(df_flows)
        total_raw_flows += n_flows

        print(f"  Loaded {n_flows:,} flows in {load_sec:.2f}s")
        t_agg = time.time()
        df_states = aggregator.aggregate_session(df_flows, day_identifier=day_id)
        agg_sec = time.time() - t_agg

        n_windows = len(df_states)
        n_atk_windows = int(df_states['is_attack'].sum())
        n_ben_windows = n_windows - n_atk_windows
        total_generated_windows += n_windows
        total_attack_windows += n_atk_windows
        total_benign_windows += n_ben_windows

        # Save to Parquet
        df_states.to_parquet(out_pq_path, engine='pyarrow', compression='snappy', index=False)
        out_size_mb = os.path.getsize(out_pq_path) / (1024 * 1024)
        out_hash = compute_sha256(out_pq_path)

        attack_families = df_states[df_states['is_attack'] == 1]['dominant_attack_family'].value_counts().to_dict()

        print(f"  Aggregated {n_windows:,} windows ({n_atk_windows:,} attack, {n_ben_windows:,} benign) in {agg_sec:.2f}s")
        print(f"  Attack Families in Windows: {attack_families}")
        print(f"  Saved -> {out_pq_path} ({out_size_mb:.2f} MB, SHA-256: {out_hash[:12]}...)")

        manifest_records.append({
            'session_id': day_id,
            'source_parquet': filename,
            'processed_parquet': f"{day_id}_states.parquet",
            'source_flows': n_flows,
            'state_windows': n_windows,
            'attack_windows': n_atk_windows,
            'benign_windows': n_ben_windows,
            'attack_percentage': f"{(n_atk_windows / n_windows) * 100.0:.2f}%",
            'feature_dim': len(STATE_FEATURE_NAMES),
            'start_timestamp': str(df_states['timestamp_start'].min()),
            'end_timestamp': str(df_states['timestamp_end'].max()),
            'file_size_mb': round(out_size_mb, 2),
            'sha256_hash': out_hash
        })

    total_time = time.time() - t_pipeline_start

    # Save Manifest
    manifest_df = pd.DataFrame(manifest_records)
    manifest_path = os.path.join(METADATA_DIR, "temporal_states_manifest.csv")
    manifest_df.to_csv(manifest_path, index=False)
    print(f"\nManifest saved -> {manifest_path}")

    print("\n" + "=" * 85)
    print("                     TEMPORAL AGGREGATION SUMMARY                    ")
    print("=" * 85)
    print(f"Total Daily Datasets Processed: {len(parquet_files)}")
    print(f"Total Network Flows Ingested:   {total_raw_flows:,}")
    print(f"Total State Windows Generated:  {total_generated_windows:,}")
    print(f"Attack State Windows:           {total_attack_windows:,} ({(total_attack_windows/total_generated_windows)*100:.2f}%)")
    print(f"Benign State Windows:           {total_benign_windows:,} ({(total_benign_windows/total_generated_windows)*100:.2f}%)")
    print(f"State Dimension per Window:     54 continuous features")
    print(f"Total Pipeline Execution Time:  {total_time:.2f}s")
    print("=" * 85)


if __name__ == '__main__':
    main()
