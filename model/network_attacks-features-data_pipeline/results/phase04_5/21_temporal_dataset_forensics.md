# Phase 4.5 Forensic Audit: Report 21 — Dataset Integrity & Temporal Consistency Audit

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Verified Dataset Pipeline Scale

- **Raw CSE-CIC-IDS2018 CSVs:** 9 files, 8,284,254 total rows (2.70 GB)
- **Cleaned Canonical Parquets:** 9 files, 8,284,181 rows (670.75 MB), 73 invalid/corrupt rows removed.
- **Temporal State Parquets (10s/2s):** 9 files, 210,115 temporal states (88.24 MB), 54 continuous dimensions.
- **Sliding Lookback Sequences ($P=10, K \le 10$):** 188,349 continuous sequences.

## 2. Verification of Boundary Isolation & Data Leakage Prevention

1. **Daily Session Isolation:** Sequences are constructed strictly within daily capture bounds. Zero sequences cross across midnight or combine data from different days.
2. **Leakage-Free Standard Scaling:** `StandardScaler` is fitted **strictly on the 5 Training days** (102,045 sequences) and applied without modification to Validation (21,576 sequences) and Test (64,728 sequences).
3. **Threshold Selection Integrity:** Classification decision thresholds were selected by optimizing $F_1$ strictly on the Validation set (Feb 23) and frozen for Test evaluation without test label exposure.
