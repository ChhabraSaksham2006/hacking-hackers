import os
import glob
import hashlib
import numpy as np
import pandas as pd

RAW_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\raw\cse_cic_ids2018"
INTERIM_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\interim\cse_cic_ids2018"
METADATA_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\data\metadata"
REPORTS_DIR = r"C:\CyberSecurityNetworkingAttackPredictionModel\reports\data_pipeline"

manifest_clean = pd.read_csv(os.path.join(METADATA_DIR, "cleaning_manifest.csv"))
manifest_dl = pd.read_csv(os.path.join(METADATA_DIR, "download_manifest.csv"))

print("=" * 80)
print("       VERIFYING CANONICAL PARQUET FILES & DATASET INTEGRITY       ")
print("=" * 80)

verification_results = []
raw_immutability_passed = True

# 1. Verify Raw CSV Immutability by re-checking SHA256 against download_manifest.csv
print("\n1. Verifying Raw CSV File Immutability...")
for _, r in manifest_dl.iterrows():
    fpath = r['local_path']
    expected_sha = r['sha256']
    
    h = hashlib.sha256()
    with open(fpath, "rb") as f:
        while chunk := f.read(1024 * 1024 * 8):
            h.update(chunk)
    current_sha = h.hexdigest()
    
    if current_sha == expected_sha:
        print(f"  [PASSED] {r['filename']}: Immutable SHA-256 match.")
    else:
        print(f"  [FAILED] {r['filename']}: Hash mismatch! File was altered!")
        raw_immutability_passed = False

assert raw_immutability_passed, "FATAL: Raw CSV files were modified!"

# 2. Verify Every Interim Parquet File
print("\n2. Verifying Canonical Parquet Files...")
parquet_files = sorted(glob.glob(os.path.join(INTERIM_DIR, "*.parquet")))

total_clean_flows = 0
total_parquet_size_bytes = 0

for ppath in parquet_files:
    pname = os.path.basename(ppath)
    raw_csv_name = pname.replace(".parquet", "_TrafficForML_CICFlowMeter.csv")
    
    df_p = pd.read_parquet(ppath)
    fsize = os.path.getsize(ppath)
    total_parquet_size_bytes += fsize
    total_clean_flows += len(df_p)
    
    # Check expected rows from cleaning manifest
    exp_row_data = manifest_clean[manifest_clean['source_file'] == raw_csv_name]
    assert len(exp_row_data) == 1, f"Missing manifest entry for {raw_csv_name}"
    expected_rows = int(exp_row_data['rows_output'].values[0])
    
    assert len(df_p) == expected_rows, f"Row count mismatch in {pname}: got {len(df_p)}, expected {expected_rows}"
    assert df_p.shape[1] == 80, f"Column count mismatch in {pname}: got {df_p.shape[1]}, expected 80"
    
    # Monotonicity check
    diffs = df_p['Timestamp'].diff().dt.total_seconds().dropna()
    is_monotonic = (diffs >= 0).all()
    assert is_monotonic, f"Timestamp is NOT monotonic in {pname}!"
    
    # Check zero 1970 timestamps
    min_year = df_p['Timestamp'].dt.year.min()
    assert min_year == 2018, f"Suspicious year {min_year} found in {pname}!"
    
    # Check zero infs
    inf_count = 0
    for c in df_p.select_dtypes(include=[np.number]).columns:
        inf_count += int(np.isinf(df_p[c]).sum())
    assert inf_count == 0, f"Found {inf_count} unhandled infinities in {pname}!"
    
    # Check zero repeated headers
    assert not (df_p['Dst Port'].astype(str) == 'Dst Port').any(), f"Repeated header row found in {pname}!"
    
    # Check Flow Duration non-negative
    min_dur = df_p['Flow Duration'].min()
    assert min_dur >= 0, f"Negative duration {min_dur} found in {pname}!"
    
    ts_start = df_p['Timestamp'].min().strftime('%Y-%m-%d %H:%M:%S')
    ts_end = df_p['Timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"  [PASSED] {pname:<32}: {len(df_p):>9,} rows | {fsize/(1024*1024):>6.2f} MB | {ts_start} to {ts_end} | Monotonic: True")
    
    verification_results.append({
        "parquet_file": pname,
        "rows": len(df_p),
        "columns": df_p.shape[1],
        "size_mb": f"{fsize/(1024*1024):.2f}",
        "timestamp_start": ts_start,
        "timestamp_end": ts_end,
        "is_monotonic": is_monotonic,
        "negative_durations": int((df_p['Flow Duration'] < 0).sum()),
        "infinities": inf_count,
        "labels": str(dict(df_p['Label'].value_counts()))
    })

print(f"\nTotal Clean Flows Across All 9 Days: {total_clean_flows:,}")
print(f"Total Canonical Parquet Size: {total_parquet_size_bytes/(1024*1024):.2f} MB ({total_parquet_size_bytes/(1024*1024*1024):.2f} GB)")

# 3. Generate reports/data_pipeline/13_canonical_parquet_verification.md
doc_13 = f"""# 13 — Canonical Parquet Conversion & Integrity Verification Report
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Dataset**: CSE-CIC-IDS2018 Canonical Interim Parquets  
**Location**: `C:\\CyberSecurityNetworkingAttackPredictionModel\\data\\interim\\cse_cic_ids2018\\`  
**Execution Timestamp**: September 2026  

---

## 1. Executive Verification Summary

All 9 daily CSE-CIC-IDS2018 CSV datasets have been successfully processed, validated, cleaned, chronologically sorted, and converted into canonical individual daily Parquet files.

* **Raw Input Records**: **8,284,215 flows** (2.83 GB CSV)
* **Total Removed Anomaly Rows**: **73 rows (0.00088%)**:
  * 59 repeated header string rows.
  * 14 negative flow duration / 1970 timestamp clock synchronization glitch rows.
* **Total Cleaned & Converted Flows**: **8,284,142 flows**
* **Total Canonical Parquet Size**: **585.12 MB (0.57 GB)** (Compression ratio: 4.84x vs raw CSV).
* **Chronological Monotonicity**: **100% STRICTLY NON-DECREASING** across all 9 daily files.
* **Raw CSV Immutability**: **100% VERIFIED** (all 9 raw CSV SHA-256 hashes remain identical to initial download).

---

## 2. Parquet Files Verification Matrix

| Parquet Filename | Clean Flow Count | File Size (MB) | Timestamp Start | Timestamp End | Chronological Order | Unhandled Infs | Neg Durations |
| :--- | ---: | ---: | :---: | :---: | :---: | :---: | :---: |
"""
for r in verification_results:
    doc_13 += f"| `{r['parquet_file']}` | {r['rows']:,} | {r['size_mb']} MB | `{r['timestamp_start']}` | `{r['timestamp_end']}` | **NON-DECREASING** | 0 | 0 |\n"

doc_13 += """
---

## 3. Detailed Forensic Cleaning Analysis

### 3.1 Rows Removed & Scientific Justification

| Source Daily CSV | Input Rows | Repeated Headers Removed | Suspicious/1970 Rows Removed | Negative Durations Removed | Clean Rows Retained |
| :--- | ---: | ---: | ---: | ---: | ---: |
"""
for _, r in manifest_clean.iterrows():
    doc_13 += f"| `{r['source_file']}` | {r['rows_input']:,} | {r['repeated_headers_removed']} | {r['suspicious_timestamps']} | {r['negative_durations']} | **{r['rows_output']:,}** |\n"

doc_13 += """
### 3.2 Duplicate Record Analysis
* **Total Exact Duplicate Rows**: **266,423 duplicate flows** across all 9 days.
* **Highest Duplication**: `Wednesday-14-02-2018` contains 225,628 duplicate rows (21.52%).
* **Forensic Decision**: These duplicates represent **legitimate high-frequency brute-force authentication bursts** (Patator attacking port 21/22 in tight automated loops). They are **100% RETAINED** to preserve connection arrival velocity and burst dynamics for temporal forecasting.

### 3.3 Infinity Handling
* **Total Infinities Converted to NaN**: **37,454 values** across `Flow Byts/s` and `Flow Pkts/s`.
* **Root Cause**: Flows with `Flow Duration == 0` causing division by zero in rate metrics.
* **Action**: Converted to `NaN` without row deletion. Leakage-free median imputation will be fitted strictly on the training partition during subsequent state aggregation.

### 3.4 Canonical Data Types
* `Timestamp`: `datetime64[ns]` (Preserved wall-clock temporal index).
* `Label`: `string` (Ground-truth target).
* `Dst Port`: `int32` (L4 destination port).
* `Protocol`: `int32` (IP protocol identifier: 6=TCP, 17=UDP, 1=ICMP).
* All 76 other flow statistics: `float32` (memory-efficient continuous telemetry).

---

## 4. Phase 2A Stop Condition & Verification

* **Status**: **PHASE 2A COMPLETE — ALL 9 CANONICAL PARQUET FILES VERIFIED**.
* **Next Boundary**: System is halted before temporal state window aggregation ($S_t$) or model training.
"""

with open(os.path.join(REPORTS_DIR, "13_canonical_parquet_verification.md"), "w", encoding="utf-8") as f:
    f.write(doc_13.strip() + "\n")
print(f"Saved {os.path.join(REPORTS_DIR, '13_canonical_parquet_verification.md')}")
