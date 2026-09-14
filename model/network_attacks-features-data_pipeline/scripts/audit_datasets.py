import os
import glob
import pandas as pd
import numpy as np

def run_audit():
    print("================================================================================")
    print("                    FORENSIC AUDIT OF ALL DATASET ARTIFACTS                     ")
    print("================================================================================")
    
    parquet_files = sorted(glob.glob("data/**/*.parquet", recursive=True))
    print(f"Total Parquet files found: {len(parquet_files)}\n")
    
    for p in parquet_files:
        p_rel = os.path.relpath(p, ".")
        df = pd.read_parquet(p)
        fsize_mb = os.path.getsize(p) / (1024 * 1024)
        print(f"--- File: {p_rel} ({fsize_mb:.2f} MB) ---")
        print(f"Shape: {df.shape[0]:,} rows x {df.shape[1]} columns")
        
        # Check nulls and infs
        num_cols = df.select_dtypes(include=[np.number]).columns
        nan_count = int(df.isna().sum().sum())
        inf_count = 0
        if len(num_cols) > 0:
            inf_count = int(np.isinf(df[num_cols].values).sum())
        dup_count = int(df.duplicated().sum())
        
        print(f"NaNs: {nan_count:,} | Infs: {inf_count:,} | Duplicate rows: {dup_count:,} ({dup_count/len(df)*100:.2f}%)")
        
        # Categorical summaries
        if "dataset" in df.columns:
            print(f"Dataset column: {dict(df['dataset'].value_counts())}")
        if "session" in df.columns:
            print(f"Session column top 5: {dict(df['session'].value_counts().head(5))}")
        if "day" in df.columns:
            print(f"Day column: {dict(df['day'].value_counts())}")
        if "split" in df.columns:
            print(f"Split column: {dict(df['split'].value_counts())}")
        if "mitre_stage_code" in df.columns:
            print(f"Stage codes: {dict(df['mitre_stage_code'].value_counts().sort_index())}")
        if "mitre_stage_name" in df.columns:
            print(f"Stage names: {dict(df['mitre_stage_name'].value_counts())}")
        if "raw_attack_type" in df.columns:
            print(f"Raw attack types: {dict(df['raw_attack_type'].value_counts())}")
        if "active_attack_names" in df.columns:
            print(f"Active attack names (top 10): {dict(df['active_attack_names'].value_counts().head(10))}")
        if "window_start_time" in df.columns:
            print(f"Window start time range: min={df['window_start_time'].min():.2f}, max={df['window_start_time'].max():.2f}")
        print()

if __name__ == "__main__":
    run_audit()
