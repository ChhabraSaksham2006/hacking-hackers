# 10 — Data Quality, Anomaly & Distribution Report
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Comprehensive Anomaly & Quality Metrics

| Dataset Partition | Total Records | Missing / NaN Values | Infinite ($\pm \infty$) Values | Duplicate Rows | Zero-Variance Columns | Timestamp Integrity |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `CSE-CIC-IDS2018 (Wednesday)` | 1,048,575 | 2,277 (`Flow Byts/s`) | 5,371 (`Flow Byts/s`, `Flow Pkts/s`) | 296,673 (28.3%) | 10 columns | 5 records with negative duration & 1970 timestamps |
| `Projected CIC-IDS2017 (8 Parquets)` | 1,355,364 | 0 (Imputed) | 0 (Clamped) | 299,491 (22.1%) | 18 columns (Hardcoded) | Destroyed (Randomly shuffled) |
| `DARPA 1998 Week 1 (5 Parquets)` | 190,375 | 0 | 0 | 0 (0.0%) | 0 columns | Valid 10s monotonic sliding windows |
| `Combined Multidomain Parquet` | 1,545,739 | 0 | 0 | 299,491 (19.4%) | 0 columns | Incoherent (Mixed scales & destroyed order) |

---

## 2. Duplicate Flow Forensic Analysis

* In `windows_cic_Friday-WorkingHours-Afternoon-PortScan.parquet`, **63.67% of records are exact duplicates**.
* **Forensic Verdict**: These are **legitimate high-frequency network attack artifacts**. Port scanners (like Nmap) emit identical TCP SYN probe packets with identical window sizes, flags, and headers to consecutive destination ports.
* **Handling Decision**: Duplicates must **NOT be blindly deleted**, as deleting them destroys true packet arrival rates and connection velocity metrics essential for forecasting.
