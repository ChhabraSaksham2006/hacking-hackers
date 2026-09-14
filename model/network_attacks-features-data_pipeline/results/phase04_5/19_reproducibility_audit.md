# 19 — Reproducibility & Pipeline Integrity Audit

## 1. Comprehensive Reproducibility Checklist

| Item | Requirement | Code / Manifest Verification | Status |
|---|---|---|---|
| **Deterministic Seed** | Fixed global seed across all libraries | `seed_all(42)` sets Python, NumPy, PyTorch CPU/GPU seeds. | **PASS** |
| **Download Verification** | Cryptographic SHA-256 hashes for all raw files | `data/metadata/download_manifest.csv` records all SHA-256 hashes. | **PASS** |
| **Data Manifests** | Cleaning and processing manifests recorded | `cleaning_manifest.csv` and `temporal_states_manifest.csv` verified. | **PASS** |
| **Chronological Partitions** | Disjoint train, validation, and test days | Explicit day lists in `src/temporal/dataset_builder.py`. | **PASS** |
| **Scaling Policy** | `StandardScaler` fit strictly on train | Verified in `TemporalSequenceBuilder.fit_scaler(train_dfs)`. | **PASS** |
| **Model Checkpoints** | Model weights and configurations persisted | PyTorch `.pt` checkpoints present in `results_final_selected_k/`. | **PASS** |
| **Evaluation Scripts** | Standalone benchmark reproduction runners | `run_baseline_suite.py` and `run_sparse_rssm.py` present. | **PASS** |
| **Sample Size Consistency** | Identical test sample count across horizons | Mismatch identified: RSSM K=1 has 64,755; K=300 has 63,858 rows. | **WARNING** |
| **Loss Supervision** | Attack head included in model loss | Attack head omitted from `SparseRSSM.loss()`. | **FAIL** |
