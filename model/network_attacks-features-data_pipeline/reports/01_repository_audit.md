# 01 — Comprehensive Repository Forensic Audit
**Project**: SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data  
**Audited Repository**: `https://github.com/ArihantSrivastava2225/network_attacks`  
**Audit Date**: September 2026  
**Auditor**: Antigravity Autonomous Forensic Engine  

---

## 1. Executive Summary

A comprehensive forensic audit of the Git history, commit graph, source files, and dataset artifacts was conducted across all branches of `ArihantSrivastava2225/network_attacks`.

The repository contains three primary Git branches that represent fragmented and diverging attempts at solving SIH26153:
1. `main` (commit `6b422e7`): The bare initial commit containing only raw DARPA PCAP sample slices and rudimentary Jupyter notebooks.
2. `feature/world-model-dataset-darpaWithCICIDS` (commit `a03c477`): Contains a 47-dimensional multi-domain dataset pipeline attempting to merge 1998 DARPA PCAP temporal windows with 2017 CIC-IDS flow CSVs, alongside an LSTM-based world model.
3. `features/lakshay_ml` (commit `d03a94f`): Contains a standalone exploratory data analysis (EDA), anomaly audit, feature engineering, and Logistic Regression baseline pipeline built on a single day of CSE-CIC-IDS2018 (`Wednesday-14-02-2018`).

---

## 2. Branch Topology & Responsibility Mapping

| Branch Name | Latest Commit | Author & Date | Primary Purpose / Contents | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| `main` | `6b422e7` | Arihant Srivastava (Aug 29, 2026) | Initial commit: `DARPA_eval_b` PCAPs, `create_notebook.py`, `data_exploration.ipynb`. | Obsolete / Incomplete |
| `feature/world-model-dataset-darpaWithCICIDS` | `a03c477` | Arihant Srivastava (Sep 2, 2026) | 47-D State Vector engine, Parquet files (`combined_multidomain_dataset.parquet`), Dual-Head LSTM World Model (`world_model.py`), MITRE mapping. | Severely Flawed Pipeline (Shuffled flows, Hardcoded features, Unicode bug) |
| `features/lakshay_ml` | `d03a94f` | Lakshay (Sep 3, 2026) | Clean Scikit-Learn baseline pipeline, memory-efficient loader, 80-feature EDA, Logistic Regression baseline on 1M CSE-CIC-IDS2018 flows. | Methodologically Sound Baseline (Static Classification Only) |

---

## 3. Answers to Core Repository Inquiries

### Q1: What branch is considered the main/primary branch?
**`main`** is configured as the default GitHub branch, but it contains **only the initial skeletal commit** (`6b422e7`). It does not contain any of the finished ML pipelines or dataset transformations.

### Q2: What branch contains the latest ML work?
* **For Temporal World Modeling**: `feature/world-model-dataset-darpaWithCICIDS` (commit `a03c477`, Sep 2, 2026).
* **For Rigorous Baseline & EDA**: `features/lakshay_ml` (commit `d03a94f`, Sep 3, 2026).

### Q3: What branch contains the complete dataset?
`feature/world-model-dataset-darpaWithCICIDS` contains the 92.4 MB `combined_multidomain_dataset.parquet` (1,545,739 rows) and 13 individual Parquet files (5 DARPA Week 1 days + 8 CIC session parquets).

### Q4: What branch contains preprocessing?
* `feature/world-model-dataset-darpaWithCICIDS`: `src/temporal_aggregator.py`, `src/feature_extractor.py`, `src/cic_feature_adapter.py`, `src/build_dataset.py`.
* `features/lakshay_ml`: `src/preprocessing.py`, `src/data_loader.py`, `src/feature_engineering.py`.

### Q5: What branch contains MITRE mappings?
`feature/world-model-dataset-darpaWithCICIDS` (`src/mitre_mapping.py`, `src/cic_mapping.py`).

### Q6: What branch contains DARPA integration?
`feature/world-model-dataset-darpaWithCICIDS` (`src/build_dataset.py`, `src/temporal_aggregator.py`, `data/backup_darpa_week1/`).

### Q7: What branch contains trained models?
* `feature/world-model-dataset-darpaWithCICIDS`: `models/unified_world_model_best.pt` (1.2 MB PyTorch checkpoint) and `models/world_model_lstm_best.pt` (3.6 MB).
* `features/lakshay_ml`: `models/logistic_regression_pipeline.joblib` (10 KB Scikit-Learn pipeline).

### Q8: What branch contains reports/results?
* `features/lakshay_ml`: `reports/baseline_results.md`, `reports/eda_report.md`, `reports/feature_audit.csv`, and visualization heatmaps.
* `feature/world-model-dataset-darpaWithCICIDS`: `results/batch_thursday_test.json`, `results/live_stream_alerts.jsonl`.
