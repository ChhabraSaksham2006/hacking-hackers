"""
Day-by-day PCAP processing pipeline for DARPA Week1 dataset.

Processes each day's PCAP independently (memory efficient), saves
window-level feature DataFrames as Parquet files, then merges into
a single training-ready dataset using temporal train/val/test splits.

Usage:
    python src/build_dataset.py --data_dir data/week1 --delta_t 10 --step 2 --out_dir data/processed
"""

import os
import sys
import gzip
import shutil
import argparse
import tempfile
import datetime
import numpy as np
import pandas as pd
from typing import List, Tuple, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.temporal_aggregator import TemporalStateAggregator, parse_session_list
from src.mitre_mapping import STAGE_NAMES

# ── Ordered day schedule ────────────────────────────────────────────────────
WEEK1_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]

# Temporal train / val / test split by day
TRAIN_DAYS = ["monday", "tuesday", "wednesday"]
VAL_DAYS   = ["thursday"]
TEST_DAYS  = ["friday"]


def decompress_gz(gz_path: str, out_path: str):
    """Decompress a .gz file to out_path."""
    print(f"    Decompressing {os.path.basename(gz_path)} ...")
    with gzip.open(gz_path, "rb") as f_in, open(out_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"    Done — {size_mb:.1f} MB uncompressed")


def process_day(
    day: str,
    data_dir: str,
    out_dir: str,
    delta_t: float,
    step_size: float,
    tmp_dir: str,
    overwrite: bool = False
) -> Optional[str]:
    """
    Process one day: decompress PCAP, build windows, save Parquet, clean up.
    Returns path to saved Parquet file.
    """
    day_dir  = os.path.join(data_dir, day)
    pcap_gz  = os.path.join(day_dir, "tcpdump.gz")
    list_gz  = os.path.join(day_dir, "tcpdump.list.gz")
    out_pq   = os.path.join(out_dir, f"windows_{day}_dt{int(delta_t)}s.parquet")

    if not os.path.exists(pcap_gz):
        print(f"  [SKIP] {day}: tcpdump.gz not found")
        return None

    if os.path.exists(out_pq) and not overwrite:
        print(f"  [CACHED] {day}: parquet already exists at {out_pq}")
        return out_pq

    print(f"\n{'='*60}")
    print(f"  Processing: {day.upper()}")
    print(f"{'='*60}")

    # ── 1. Decompress list file ──────────────────────────────────────────
    list_path = os.path.join(tmp_dir, f"{day}_tcpdump.list")
    decompress_gz(list_gz, list_path)

    # ── 2. Decompress PCAP ──────────────────────────────────────────────
    pcap_path = os.path.join(tmp_dir, f"{day}.pcap")
    decompress_gz(pcap_gz, pcap_path)

    # ── 3. Aggregate windows ─────────────────────────────────────────────
    print(f"    Building {delta_t}s windows (step={step_size}s) ...")
    agg = TemporalStateAggregator(pcap_path, list_path)
    df = agg.aggregate_windows(delta_t=delta_t, step_size=step_size, include_deltas=True)

    # Add metadata columns
    df.insert(0, "day", day)
    df.insert(1, "split", "train" if day in TRAIN_DAYS else ("val" if day in VAL_DAYS else "test"))

    print(f"    Windows generated: {len(df)}")
    print(f"    Stage distribution:")
    for code, cnt in df["mitre_stage_code"].value_counts().sort_index().items():
        print(f"      Stage {code} ({STAGE_NAMES.get(code,'?')}): {cnt}")

    # ── 4. Save Parquet ──────────────────────────────────────────────────
    os.makedirs(out_dir, exist_ok=True)
    df.to_parquet(out_pq, index=False)
    size_kb = os.path.getsize(out_pq) / 1024
    print(f"    Saved: {out_pq} ({size_kb:.0f} KB)")

    # ── 5. Clean up temp files ───────────────────────────────────────────
    if os.path.exists(pcap_path):
        os.remove(pcap_path)
    if os.path.exists(list_path):
        os.remove(list_path)
    print(f"    Cleaned up temp files for {day}")

    return out_pq


def build_and_merge(
    data_dir: str,
    out_dir: str,
    delta_t: float = 10.0,
    step_size: float = 2.0,
    days: Optional[List[str]] = None,
    overwrite: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Process all days one at a time, merge into train/val/test splits.
    Returns (df_train, df_val, df_test).
    """
    if days is None:
        days = WEEK1_DAYS

    tmp_dir = tempfile.mkdtemp(prefix="darpa_pcap_")
    print(f"Temp directory: {tmp_dir}")

    parquet_paths = []
    for day in days:
        pq = process_day(day, data_dir, out_dir, delta_t, step_size, tmp_dir, overwrite=overwrite)
        if pq:
            parquet_paths.append(pq)

    shutil.rmtree(tmp_dir, ignore_errors=True)
    print(f"\nTemp directory cleaned: {tmp_dir}")

    # Merge all parquets
    print("\n" + "="*60)
    print("Merging all day DataFrames ...")
    all_dfs = [pd.read_parquet(p) for p in parquet_paths]
    df_all = pd.concat(all_dfs, ignore_index=True)

    df_train = df_all[df_all["split"] == "train"].reset_index(drop=True)
    df_val   = df_all[df_all["split"] == "val"].reset_index(drop=True)
    df_test  = df_all[df_all["split"] == "test"].reset_index(drop=True)

    print(f"\nFinal dataset summary (delta_t={delta_t}s, step={step_size}s):")
    print(f"  Train ({'/'.join(TRAIN_DAYS)}): {len(df_train)} windows")
    print(f"  Val   ({'/'.join(VAL_DAYS)}):   {len(df_val)} windows")
    print(f"  Test  ({'/'.join(TEST_DAYS)}):  {len(df_test)} windows")

    print(f"\nOverall stage distribution:")
    stage_counts = df_all["mitre_stage_code"].value_counts().sort_index()
    for code, cnt in stage_counts.items():
        pct = 100 * cnt / len(df_all)
        print(f"  Stage {code} ({STAGE_NAMES.get(code,'?')}): {cnt} ({pct:.1f}%)")

    # Save merged splits
    for split_name, split_df in [("train", df_train), ("val", df_val), ("test", df_test)]:
        path = os.path.join(out_dir, f"split_{split_name}_dt{int(delta_t)}s.parquet")
        split_df.to_parquet(path, index=False)
        print(f"  Saved {split_name} split: {path}")

    return df_train, df_val, df_test


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build DARPA Week1 window dataset")
    parser.add_argument("--data_dir",  default="data/week1",     help="Root data directory")
    parser.add_argument("--out_dir",   default="data/processed",  help="Output directory for Parquet files")
    parser.add_argument("--delta_t",   type=float, default=10.0,  help="Window size in seconds")
    parser.add_argument("--step",      type=float, default=2.0,   help="Sliding step in seconds")
    parser.add_argument("--days",      nargs="+",  default=None,  help="Which days to process (default: all)")
    parser.add_argument("--overwrite", action="store_true",        help="Overwrite existing Parquet files")
    args = parser.parse_args()

    df_train, df_val, df_test = build_and_merge(
        data_dir=args.data_dir,
        out_dir=args.out_dir,
        delta_t=args.delta_t,
        step_size=args.step,
        days=args.days,
        overwrite=args.overwrite
    )
    print("\nDataset build complete.")
