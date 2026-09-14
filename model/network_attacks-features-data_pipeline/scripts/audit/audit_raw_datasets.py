import os
import glob
import time
import datetime
import numpy as np
import pandas as pd
from collections import Counter

RAW_DIR = "C:/CyberSecurityNetworkingAttackPredictionModel/data/raw/cse_cic_ids2018"
CSV_FILES = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

print(f"Auditing {len(CSV_FILES)} raw CSV files chunk-by-chunk...")

audit_records = []
attack_timelines = []

for fpath in CSV_FILES:
    fname = os.path.basename(fpath)
    print(f"\nProcessing {fname} ...")
    t0 = time.time()
    
    total_rows = 0
    total_cols = 0
    cols = []
    
    nan_count = 0
    inf_count = 0
    neg_duration_count = 0
    zero_duration_count = 0
    repeated_header_count = 0
    
    label_counter = Counter()
    timestamps = []
    
    chunk_size = 100_000
    chunk_idx = 0
    
    for chunk in pd.read_csv(fpath, chunksize=chunk_size, low_memory=False, encoding='utf-8', on_bad_lines='skip'):
        if chunk_idx == 0:
            cols = list(chunk.columns)
            total_cols = len(cols)
        
        chunk.columns = [c.strip() for c in chunk.columns]
        
        # Check repeated header rows
        header_mask = chunk[chunk.columns[0]].astype(str).str.strip() == chunk.columns[0]
        rep_headers = int(header_mask.sum())
        if rep_headers > 0:
            repeated_header_count += rep_headers
            chunk = chunk[~header_mask]
            
        if len(chunk) == 0:
            continue
            
        total_rows += len(chunk)
        
        # Label column
        label_col = [c for c in chunk.columns if 'label' in c.lower()][0]
        cleaned_labels = chunk[label_col].astype(str).str.strip()
        label_counter.update(cleaned_labels)
        
        # Flow Duration
        dur_col = [c for c in chunk.columns if 'duration' in c.lower()]
        if dur_col:
            durations = pd.to_numeric(chunk[dur_col[0]], errors='coerce')
            neg_duration_count += int((durations < 0).sum())
            zero_duration_count += int((durations == 0).sum())
            
        # NaNs
        nan_count += int(chunk.isna().sum().sum())
        
        # Check infinite values in rate columns
        for c in chunk.columns:
            if pd.api.types.is_numeric_dtype(chunk[c]):
                inf_count += int(np.isinf(chunk[c].values).sum())
            else:
                if c.lower() != 'timestamp' and c.lower() != label_col.lower():
                    conv = pd.to_numeric(chunk[c], errors='coerce')
                    inf_count += int(np.isinf(conv.dropna().values).sum())
                    
        # Collect timestamps
        ts_col = [c for c in chunk.columns if 'timestamp' in c.lower()]
        if ts_col:
            ts_series = chunk[[ts_col[0], label_col]].copy()
            ts_series.columns = ['timestamp_str', 'label']
            timestamps.append(ts_series)
            
        chunk_idx += 1
        
    print(f"  Rows: {total_rows:,} | Cols: {total_cols} | Duration: {time.time()-t0:.1f}s")
    
    # Process timestamps for full day
    df_ts = pd.concat(timestamps, ignore_index=True) if timestamps else pd.DataFrame()
    ts_min_str, ts_max_str = "N/A", "N/A"
    out_of_order_count = 0
    duplicate_ts_count = 0
    max_gap_seconds = 0.0
    day_coverage_hours = 0.0
    
    if not df_ts.empty:
        # Robust parsing of multi-format timestamps in CSE-CIC-IDS2018
        df_ts['dt'] = pd.to_datetime(df_ts['timestamp_str'], format='%d/%m/%Y %H:%M:%S', errors='coerce')
        if df_ts['dt'].isna().sum() > 0:
            fallback = pd.to_datetime(df_ts['timestamp_str'], errors='coerce')
            df_ts['dt'] = df_ts['dt'].fillna(fallback)
            
        valid_dts = df_ts['dt'].dropna()
        if not valid_dts.empty:
            ts_min = valid_dts.min()
            ts_max = valid_dts.max()
            ts_min_str = ts_min.strftime('%Y-%m-%d %H:%M:%S')
            ts_max_str = ts_max.strftime('%Y-%m-%d %H:%M:%S')
            day_coverage_hours = (ts_max - ts_min).total_seconds() / 3600.0
            
            dt_diffs = valid_dts.diff().dt.total_seconds()
            out_of_order_count = int((dt_diffs < 0).sum())
            duplicate_ts_count = int((dt_diffs == 0).sum())
            max_gap_seconds = float(dt_diffs.max()) if not dt_diffs.empty else 0.0
            
            non_benign = df_ts[df_ts['label'].str.upper() != 'BENIGN']
            if not non_benign.empty:
                for lbl in non_benign['label'].unique():
                    lbl_dts = df_ts[df_ts['label'] == lbl]['dt'].dropna()
                    if not lbl_dts.empty:
                        attack_timelines.append({
                            "file": fname,
                            "attack_label": lbl,
                            "count": len(lbl_dts),
                            "start_time": lbl_dts.min().strftime('%Y-%m-%d %H:%M:%S'),
                            "end_time": lbl_dts.max().strftime('%Y-%m-%d %H:%M:%S'),
                            "duration_minutes": (lbl_dts.max() - lbl_dts.min()).total_seconds() / 60.0
                        })

    audit_records.append({
        "filename": fname,
        "total_rows": total_rows,
        "total_columns": total_cols,
        "timestamp_min": ts_min_str,
        "timestamp_max": ts_max_str,
        "coverage_hours": f"{day_coverage_hours:.2f}",
        "unique_labels_count": len(label_counter),
        "labels_distribution": str(dict(label_counter)),
        "nan_values_count": nan_count,
        "infinity_values_count": inf_count,
        "negative_duration_count": neg_duration_count,
        "zero_duration_count": zero_duration_count,
        "repeated_header_rows": repeated_header_count,
        "out_of_order_timestamps": out_of_order_count,
        "duplicate_timestamps": duplicate_ts_count,
        "max_time_gap_seconds": f"{max_gap_seconds:.1f}"
    })

df_audit = pd.DataFrame(audit_records)
df_audit.to_csv("C:/CyberSecurityNetworkingAttackPredictionModel/reports/data_pipeline/03_raw_data_audit.csv", index=False)
print("\nSaved reports/data_pipeline/03_raw_data_audit.csv")

df_attacks = pd.DataFrame(attack_timelines)
df_attacks.to_csv("C:/CyberSecurityNetworkingAttackPredictionModel/data/metadata/attack_timelines.csv", index=False)
print("Saved data/metadata/attack_timelines.csv")
