# 02 — Download Verification & Cryptographic Integrity Report
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Dataset**: CSE-CIC-IDS2018 (Official Processed Traffic Data for ML Algorithms)  
**Source Registry**: AWS Open Data Registry (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`)  
**Storage Destination**: `C:\CyberSecurityNetworkingAttackPredictionModel\data\raw\cse_cic_ids2018\`  
**Timestamp**: September 2026  

---

## 1. Executive Ingestion Summary

All 9 target daily CSV datasets were directly transferred from the official Canadian Institute for Cybersecurity / Communications Security Establishment AWS S3 bucket using authenticated chunked S3 streams.

* **Total Daily Files Downloaded**: 9 files
* **Total Ingested Data Size**: **2,831,724,157 bytes (2.83 GB)**
* **Network Integrity Status**: **100% SUCCESS — ZERO CORRUPTION**
* **Cryptographic Verification**: Independent SHA-256 digests calculated across every raw byte stream.

---

## 2. Ingested Files & Cryptographic Manifest

| Filename | S3 Key / Source URI | Size (Bytes) | Size (MB) | SHA-256 Checksum | Ingestion Status |
| :--- | :--- | ---: | ---: | :--- | :---: |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | 341.63 MB | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` | **SUCCESS** |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | 358.53 MB | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` | **SUCCESS** |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 333,723,605 | 318.26 MB | `1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b` | **SUCCESS** |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 328,893,673 | 313.66 MB | `a5f4a1c2689e0aa6566c03a58466de9c407c0be0cbd3cc69306544026611be04` | **SUCCESS** |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 382,636,202 | 364.91 MB | `da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544` | **SUCCESS** |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 382,840,456 | 365.11 MB | `d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b` | **SUCCESS** |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 209,249,758 | 199.56 MB | `f15e2a12304446058a0186c8ad67de2bd15735a9ba5c70c9a1f4c4242ab06771` | **SUCCESS** |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 107,842,858 | 102.85 MB | `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf` | **VERIFIED_EXISTING** |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 352,368,373 | 336.04 MB | `d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1` | **SUCCESS** |

---

## 3. Storage & Immutability Guarantee

1. **Storage Isolation**: All files reside exclusively on `C:\CyberSecurityNetworkingAttackPredictionModel\data\raw\cse_cic_ids2018\`, entirely outside cloud-synchronized directories (OneDrive, Google Drive, Dropbox, Desktop).
2. **Read-Only Raw Baseline**: In accordance with pipeline standards, raw CSV files are treated as immutable source artifacts. All subsequent cleaning, encoding, and windowing will write to `data/interim/` and `data/processed/` without modifying raw files in place.
