# 01 — Clean Data Pipeline Branch Policy & Isolation Architecture
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Branch**: `feature/data-pipeline`  
**Execution Environment**: `C:\CyberSecurityNetworkingAttackPredictionModel`  
**Timestamp**: September 2026  

---

## 1. Clean Room Isolation Principles

To eliminate contamination from legacy experimental implementations:

1. **Independent Provenance**: The data engineering pipeline implemented in this branch does not import, inherit, or reuse old preprocessing modules from `feature/world-model-dataset-darpaWithCICIDS` or `features/lakshay_ml`.
2. **Historical Preservation**: All previous Git branches (`main`, `features/lakshay_ml`, `feature/world-model-dataset-darpaWithCICIDS`) remain intact as reference archives.
3. **No Hybrid Dataset Reuse**: The corrupt hybrid `combined_multidomain_dataset.parquet` and the DARPA 1998 PCAP extractions are strictly quarantined and never loaded by the new pipeline.
4. **Zero Shuffling Policy**: Flow records must be parsed and processed in strict chronological order based on authentic start timestamps.

---

## 2. Directory Separation & Responsibility Matrix

```
C:/CyberSecurityNetworkingAttackPredictionModel/
├── configs/                   # Declarative YAML configurations for data ingestion & features
│   ├── dataset.yaml
│   ├── features.yaml
│   └── temporal.yaml
│
├── data/
│   ├── raw/                   # Immutable downloaded official CSVs (Git-ignored)
│   │   └── cse_cic_ids2018/
│   ├── interim/               # Cleaned & standardized intermediate Parquets (Git-ignored)
│   ├── processed/             # Temporal state window matrices S_t (Git-ignored)
│   └── metadata/              # Download manifests, checksums, MITRE mappings (Git-tracked)
│
├── notebooks/                 # Clean, reproducible Jupyter analysis notebooks
│   ├── 01_dataset_eda.ipynb
│   ├── 02_data_quality_and_feature_audit.ipynb
│   ├── 03_logistic_regression_baseline.ipynb
│   ├── 04_temporal_state_construction.ipynb
│   ├── 05_attack_mapping.ipynb
│   ├── 06_temporal_transformer.ipynb
│   └── 07_forecasting_evaluation.ipynb
│
├── reports/                   # Audit reports, evaluation matrices, decision records
│   └── data_pipeline/
│
├── scripts/                   # Standalone CLI tools for download, audit, and verification
│   ├── download/
│   ├── audit/
│   ├── preprocessing/
│   └── verification/
│
├── src/                       # Production Python package
│   ├── data/                  # Memory-efficient chunked loaders & Parquet encoders
│   ├── features/              # 54-feature behavioral extractor & imputer
│   ├── temporal/              # Discrete window state builder (S_t) & sequence windowing
│   ├── mitre/                 # Decoupled MITRE ATT&CK interpretation engine
│   └── utils/                 # Logging, hashing, validation helpers
│
└── tests/                     # Automated unit and integration test suites
```
