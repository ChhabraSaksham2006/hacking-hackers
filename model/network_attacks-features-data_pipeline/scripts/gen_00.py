import os
import glob
import subprocess

doc = """# 00 — Pre-Migration Repository Inventory & Safety Audit
**Project**: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
**Subsystem**: Data Engineering & Reproducibility Pipeline  
**Timestamp**: September 2026  

---

## 1. Environment & Location Inspection

* **Current Working Directory**: `C:\\Users\\Lakshay\\OneDrive\\Desktop\\CyberSecurityNetworkingAttackPredictionModel`
* **Absolute Repository Root**: `C:\\Users\\Lakshay\\OneDrive\\Desktop\\CyberSecurityNetworkingAttackPredictionModel`
* **Location Risk**: **CRITICAL (Under OneDrive Desktop)**. Active OneDrive background sync can cause file locks, corrupt multi-gigabyte CSV/Parquet downloads, and cause sync throttling.
* **Target Migration Location**: `C:\\CyberSecurityNetworkingAttackPredictionModel` (Local NVMe/SSD, zero cloud sync interference).
* **Git Remote URL**: `https://github.com/ArihantSrivastava2225/network_attacks`
* **Current Active Branch**: `feature/world-model-dataset-darpaWithCICIDS`

---

## 2. Git Branch & Commit Inventory

| Branch Name | Tracking Remote | Commit Hash | Commit Subject |
| :--- | :--- | :--- | :--- |
| `main` | `origin/main` | `6b422e7` | `first commit` |
| `feature/world-model-dataset-darpaWithCICIDS` | `origin/feature/world-model-dataset-darpaWithCICIDS` | `a03c477` | `fix: Update Section 3 signature bar plots and Section 5 active timeline transition in data_visualizer.ipynb` |
| `features/lakshay_ml` | `origin/features/lakshay_ml` | `d03a94f` | `feat(ml): complete EDA, anomaly audit, preprocessing pipeline, and Logistic Regression baseline for SIH26153` |

---

## 3. Dataset Artifacts Present in Workspace

| Artifact Path | Format | Size (MB) | Provenance & Contents | Forensic Status |
| :--- | :---: | :---: | :--- | :--- |
| `data/combined_multidomain_dataset.parquet` | Parquet | 88.16 MB | 1,545,739 rows x 107 cols (DARPA 1998 + Shuffled CIC-IDS2017) | **STATUS G (Corrupted hybrid; retired)** |
| `data/backup_darpa_week1/` (5 files) | Parquet | ~31.0 MB | 190,375 10s windows from 1998 DARPA PCAP Week 1 | **Legacy reference only** |
| `data/processed/` (8 files) | Parquet | ~43.0 MB | Processed day & split Parquets for DARPA Week 1 | **Legacy reference only** |
| `data/processed_cic/` (8 files) | Parquet | ~55.0 MB | Subsampled & randomly shuffled CIC-IDS-2017 CSVs projected into 47 features | **Corrupted (18 constant cols, web attack bug)** |
| `DARPA_eval_b/` | GZ/PCAP | ~5.2 MB | Raw 1998 DARPA sample PCAPs and BSM audit logs | **Legacy reference only** |

---

## 4. Code & Model Artifacts Inventory

### 4.1 Python Scripts (`src/`)
* `src/temporal_aggregator.py`: PCAP sliding window builder for DARPA.
* `src/feature_extractor.py`: 47-D packet feature extraction engine.
* `src/cic_feature_adapter.py`: Projection adapter (contained random shuffling and constant feature hardcoding).
* `src/cic_mapping.py`: 5-stage mapping (contained Unicode bug dropping web attacks).
* `src/mitre_mapping.py`: DARPA 5-stage mapping.
* `src/build_dataset.py`: Multi-day DARPA builder.
* `src/dataset_sequence.py` & `src/dataset_unified_sequence.py`: PyTorch sequence datasets.
* `src/world_model.py`: Dual-head LSTM / Transformer World Model architecture.
* `src/train_unified_world_model.py` & `src/train_world_model.py`: Model training scripts.
* `src/inference_engine.py`, `src/inference_stream.py`, `src/inference_batch.py`: Inference pipelines.

### 4.2 Notebooks
* `data_visualizer.ipynb`: Interactive visualization notebook for session trajectories.
* `data_exploration.ipynb`: Initial exploration notebook on `main`.

### 4.3 Saved Model Weights (`models/`)
* `models/unified_world_model_best.pt`: 1.2 MB PyTorch checkpoint.
* `models/world_model_lstm_best.pt`: 3.6 MB PyTorch checkpoint.

---

## 5. Migration Safety Policy

1. **Zero Data Loss**: The entire Git history (`.git`) and all existing files will be safely mirrored to `C:\\CyberSecurityNetworkingAttackPredictionModel`.
2. **Immutability of Historical Branches**: `main`, `features/lakshay_ml`, and `feature/world-model-dataset-darpaWithCICIDS` remain preserved.
3. **Clean Foundation**: A new branch `feature/data-pipeline` will be initialized to build the clean, production-grade CSE-CIC-IDS2018 pipeline.
"""

with open("reports/data_pipeline/00_pre_migration_inventory.md", "w", encoding="utf-8") as f:
    f.write(doc.strip() + "\n")
print("Saved 00_pre_migration_inventory.md")
