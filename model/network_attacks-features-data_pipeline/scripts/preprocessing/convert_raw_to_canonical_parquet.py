import os
import glob
import time
import hashlib
import datetime
import yaml
import numpy as np
import pandas as pd
from collections import Counter, defaultdict

RAW_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\raw\cse_cic_ids2018"
INTERIM_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\interim\cse_cic_ids2018"
METADATA_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\metadata"
REPORTS_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\reports\data_pipeline"

os.makedirs(INTERIM_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

CSV_FILES = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024 * 8):
            h.update(chunk)
    return h.hexdigest()

# Define zero-variance and duplicate feature classifications for schema metadata
ZERO_VAR_COLS = {'Bwd PSH Flags', 'Bwd URG Flags', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg'}
DUPLICATE_COLS = {'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Fwd Header Len', 'Bwd Header Len'}

print(f"Found {len(CSV_FILES)} raw CSV files to process.\n")

cleaning_manifest_rows = []
day_statistics_rows = []
schema_column_stats = defaultdict(lambda: {"missing": 0, "inf": 0, "sample_dtype": None, "zero_var": False})

for fpath in CSV_FILES:
    raw_fname = os.path.basename(fpath)
    # Output name: e.g. Wednesday-14-02-2018.parquet
    day_name = raw_fname.replace("_TrafficForML_CICFlowMeter.csv", "")
    out_parquet_name = f"{day_name}.parquet"
    out_parquet_path = os.path.join(INTERIM_DIR, out_parquet_name)
    
    print("=" * 80)
    print(f"PROCESSING DAY: {day_name}")
    print(f"  Input:  {fpath}")
    print(f"  Output: {out_parquet_path}")
    print("=" * 80)
    
    t_start = time.time()
    
    # 1. Compute input SHA-256
    sha256_in = compute_sha256(fpath)
    
    # 2. Chunked reading and cleaning
    chunks = []
    chunk_size = 100_000
    chunk_idx = 0
    
    rows_input = 0
    repeated_headers_removed = 0
    invalid_timestamps = 0
    suspicious_timestamps_count = 0
    negative_durations_count = 0
    inf_count_day = 0
    
    suspicious_rows_sample = []
    negative_duration_sample = []
    
    for chunk in pd.read_csv(fpath, chunksize=chunk_size, low_memory=False, encoding='utf-8', on_bad_lines='skip'):
        rows_input += len(chunk)
        chunk.columns = [c.strip() for c in chunk.columns]
        
        # A. Detect and remove repeated header rows
        header_mask = chunk['Dst Port'].astype(str).str.strip() == 'Dst Port'
        rep_cnt = int(header_mask.sum())
        if rep_cnt > 0:
            repeated_headers_removed += rep_cnt
            chunk = chunk[~header_mask]
            
        if len(chunk) == 0:
            continue
            
        # Clean string whitespace
        for c in chunk.columns:
            if chunk[c].dtype == object and c != 'Timestamp':
                chunk[c] = chunk[c].astype(str).str.strip()
                
        # B & C. Parse Timestamps
        dt_parsed = pd.to_datetime(chunk['Timestamp'], format='%d/%m/%Y %H:%M:%S', errors='coerce')
        if dt_parsed.isna().sum() > 0:
            fallback = pd.to_datetime(chunk['Timestamp'], errors='coerce')
            dt_parsed = dt_parsed.fillna(fallback)
            
        invalids = dt_parsed.isna().sum()
        if invalids > 0:
            invalid_timestamps += int(invalids)
            
        chunk['Timestamp'] = dt_parsed
        
        # D. Detect 1970-epoch suspicious timestamps (< 2018)
        suspicious_mask = (chunk['Timestamp'].notna()) & (chunk['Timestamp'].dt.year < 2018)
        susp_cnt = int(suspicious_mask.sum())
        if susp_cnt > 0:
            suspicious_timestamps_count += susp_cnt
            for _, r in chunk[suspicious_mask].iterrows():
                suspicious_rows_sample.append({
                    "timestamp": str(r['Timestamp']),
                    "label": r['Label'],
                    "duration": r['Flow Duration']
                })
                
        # E. Detect negative Flow Duration
        dur_numeric = pd.to_numeric(chunk['Flow Duration'], errors='coerce')
        neg_dur_mask = (dur_numeric < 0)
        neg_cnt = int(neg_dur_mask.sum())
        if neg_cnt > 0:
            negative_durations_count += neg_cnt
            for _, r in chunk[neg_dur_mask].iterrows():
                negative_duration_sample.append({
                    "timestamp": str(r['Timestamp']),
                    "label": r['Label'],
                    "duration": str(r['Flow Duration'])
                })
                
        # F. Detect infinities and replace with NaN
        for col in chunk.columns:
            if col not in ['Timestamp', 'Label']:
                num_s = pd.to_numeric(chunk[col], errors='coerce')
                infs = int(np.isinf(num_s.values).sum())
                if infs > 0:
                    inf_count_day += infs
                    schema_column_stats[col]["inf"] += infs
                    num_s = num_s.replace([np.inf, -np.inf], np.nan)
                schema_column_stats[col]["missing"] += int(num_s.isna().sum())
                chunk[col] = num_s
                
        chunks.append(chunk)
        chunk_idx += 1

    print(f"  Finished chunked read: {rows_input:,} input rows ({time.time()-t_start:.1f}s)")
    
    df_day = pd.concat(chunks, ignore_index=True)
    
    # Filtering rules:
    # 1. Drop rows with invalid timestamps (NaN)
    # 2. Drop rows with suspicious 1970 timestamps (Timestamp.dt.year < 2018)
    # 3. Drop rows with negative Flow Duration (Flow Duration < 0)
    drop_mask = (
        (df_day['Timestamp'].isna()) | 
        (df_day['Timestamp'].dt.year < 2018) | 
        (df_day['Flow Duration'] < 0)
    )
    rows_removed_filter = int(drop_mask.sum())
    total_rows_removed = repeated_headers_removed + rows_removed_filter
    
    df_cleaned = df_day[~drop_mask].copy()
    rows_retained = len(df_cleaned)
    
    print(f"  Cleaning results:")
    print(f"    Repeated headers removed: {repeated_headers_removed}")
    print(f"    Suspicious/1970 timestamp rows: {suspicious_timestamps_count}")
    print(f"    Negative duration rows: {negative_durations_count}")
    print(f"    Infinities converted to NaN: {inf_count_day:,}")
    print(f"    Total rows removed: {total_rows_removed}")
    print(f"    Rows retained: {rows_retained:,}")
    
    # 4. Duplicate Analysis on Cleaned Data
    print(f"  Analyzing duplicates...")
    dup_mask = df_cleaned.duplicated()
    dup_count = int(dup_mask.sum())
    dup_pct = (dup_count / rows_retained * 100.0) if rows_retained > 0 else 0.0
    
    dup_same_ts = int(df_cleaned.duplicated(subset=['Timestamp']).sum())
    dup_key_tuple = int(df_cleaned.duplicated(subset=['Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts']).sum())
    
    print(f"    Exact duplicate rows: {dup_count:,} ({dup_pct:.2f}%) [Preserved as genuine network bursts]")
    print(f"    Duplicates sharing same timestamp: {dup_same_ts:,}")
    print(f"    Duplicates sharing key 4-tuple: {dup_key_tuple:,}")
    
    # 5. Chronological Analysis & Sorting
    print(f"  Measuring chronological ordering...")
    ts_original = df_cleaned['Timestamp'].copy()
    dt_diffs = ts_original.diff().dt.total_seconds()
    
    out_of_order_orig = int((dt_diffs < 0).sum())
    ties_count = int((dt_diffs == 0).sum())
    max_backward_jump = float(dt_diffs[dt_diffs < 0].min()) if (dt_diffs < 0).any() else 0.0
    
    print(f"    Original out-of-order transitions: {out_of_order_orig:,}")
    print(f"    Original timestamp ties: {ties_count:,}")
    print(f"    Max backward jump: {max_backward_jump:.1f}s")
    
    # Stable chronological sort
    df_cleaned.sort_values(by='Timestamp', kind='mergesort', inplace=True)
    df_cleaned.reset_index(drop=True, inplace=True)
    
    # Verify monotonic non-decreasing order
    diffs_sorted = df_cleaned['Timestamp'].diff().dt.total_seconds()
    out_of_order_after = int((diffs_sorted < 0).sum())
    assert out_of_order_after == 0, "ERROR: Sorting failed to produce non-decreasing timestamp order!"
    print(f"    VERIFIED: Post-sort chronological ordering is strictly non-decreasing (0 backward steps).")
    
    # 6. Canonical Type Casting
    print(f"  Casting to canonical schema types...")
    df_cleaned['Dst Port'] = pd.to_numeric(df_cleaned['Dst Port'], errors='coerce').fillna(0).astype('int32')
    df_cleaned['Protocol'] = pd.to_numeric(df_cleaned['Protocol'], errors='coerce').fillna(0).astype('int32')
    df_cleaned['Label'] = df_cleaned['Label'].astype('string')
    
    for c in df_cleaned.columns:
        if c not in ['Timestamp', 'Label', 'Dst Port', 'Protocol']:
            df_cleaned[c] = df_cleaned[c].astype('float32')
            
    # 7. Write to Canonical Parquet
    print(f"  Writing Parquet to {out_parquet_path} ...")
    df_cleaned.to_parquet(out_parquet_path, index=False, engine='pyarrow', compression='snappy')
    out_size_bytes = os.path.getsize(out_parquet_path)
    sha256_out = compute_sha256(out_parquet_path)
    
    print(f"  Saved {out_parquet_name} ({out_size_bytes/(1024*1024):.2f} MB)")
    print(f"  Parquet SHA-256: {sha256_out}")
    print(f"  Day processing completed in {time.time()-t_start:.1f}s\n")
    
    ts_min_str = df_cleaned['Timestamp'].min().strftime('%Y-%m-%d %H:%M:%S')
    ts_max_str = df_cleaned['Timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
    coverage_hours = (df_cleaned['Timestamp'].max() - df_cleaned['Timestamp'].min()).total_seconds() / 3600.0
    
    # Record manifest
    cleaning_manifest_rows.append({
        "source_file": raw_fname,
        "rows_input": rows_input,
        "rows_output": rows_retained,
        "repeated_headers_removed": repeated_headers_removed,
        "invalid_timestamps": invalid_timestamps,
        "suspicious_timestamps": suspicious_timestamps_count,
        "negative_durations": negative_durations_count,
        "infinities": inf_count_day,
        "duplicates": dup_count,
        "rows_removed": total_rows_removed,
        "rows_retained": rows_retained,
        "sha256_input": sha256_in,
        "sha256_output": sha256_out
    })
    
    # Record daily stats
    label_dist = dict(df_cleaned['Label'].value_counts())
    day_statistics_rows.append({
        "day_name": day_name,
        "parquet_filename": out_parquet_name,
        "parquet_size_mb": f"{out_size_bytes/(1024*1024):.2f}",
        "flow_count": rows_retained,
        "timestamp_start": ts_min_str,
        "timestamp_end": ts_max_str,
        "coverage_hours": f"{coverage_hours:.2f}",
        "label_distribution": str(label_dist),
        "exact_duplicates": dup_count,
        "duplicate_pct": f"{dup_pct:.2f}%",
        "infinities_handled": inf_count_day
    })

# Save cleaning_manifest.csv
df_manifest = pd.DataFrame(cleaning_manifest_rows)
manifest_csv_path = os.path.join(METADATA_DIR, "cleaning_manifest.csv")
df_manifest.to_csv(manifest_csv_path, index=False)
print(f"Saved {manifest_csv_path}")

# Save canonical_dataset_statistics.csv
df_day_stats = pd.DataFrame(day_statistics_rows)
day_stats_path = os.path.join(REPORTS_DIR, "14_canonical_dataset_statistics.csv")
df_day_stats.to_csv(day_stats_path, index=False)
print(f"Saved {day_stats_path}")

# Build canonical_schema.yaml
schema_yaml_dict = {"canonical_schema": {}}
sample_parquet = pd.read_parquet(os.path.join(INTERIM_DIR, "Wednesday-14-02-2018.parquet"))

for col in sample_parquet.columns:
    if col == 'Timestamp':
        sem_type = "TemporalWallClock"
        role = "Metadata (Chronological Index)"
        orig_dt = "object (string)"
        canon_dt = "datetime64[ns]"
    elif col == 'Label':
        sem_type = "GroundTruthCategorical"
        role = "Target / Ground Truth"
        orig_dt = "object (string)"
        canon_dt = "string (category)"
    elif col == 'Dst Port':
        sem_type = "NetworkIdentifier (L4 Service Port)"
        role = "Feature (Service Identifier)"
        orig_dt = "int64 / float64"
        canon_dt = "int32"
    elif col == 'Protocol':
        sem_type = "NetworkIdentifier (IP Protocol Number)"
        role = "Feature (Protocol Type: TCP=6, UDP=17, ICMP=1)"
        orig_dt = "int64 / float64"
        canon_dt = "int32"
    else:
        sem_type = "ContinuousFlowTelemetry"
        role = "Feature"
        orig_dt = "float64"
        canon_dt = "float32"
        
    is_zero_var = col in ZERO_VAR_COLS
    is_duplicate = col in DUPLICATE_COLS
    
    notes = "Active behavioral feature"
    if is_zero_var:
        notes = "Zero variance column across full benchmark; candidate for drop"
    elif is_duplicate:
        notes = "Exact multicollinear duplicate (r = 1.0); candidate for drop"
        
    schema_yaml_dict["canonical_schema"][col] = {
        "original_dtype": orig_dt,
        "canonical_dtype": canon_dt,
        "semantic_type": sem_type,
        "role": role,
        "missing_count": int(schema_column_stats[col]["missing"]),
        "inf_count": int(schema_column_stats[col]["inf"]),
        "zero_variance": is_zero_var,
        "multicollinear_duplicate": is_duplicate,
        "notes": notes
    }

schema_yaml_path = os.path.join(METADATA_DIR, "canonical_schema.yaml")
with open(schema_yaml_path, "w", encoding="utf-8") as f:
    yaml.dump(schema_yaml_dict, f, default_flow_style=False, sort_keys=False)
print(f"Saved {schema_yaml_path}")
