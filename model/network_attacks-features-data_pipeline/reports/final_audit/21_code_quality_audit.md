# 21 — Code Quality & Experiment Hygiene Audit

## 1. Identified Issues & Code Hygiene Findings

1. **Untrained Attack Head (`src/models/sparse_rssm.py`):**
   - In `SparseRSSM.loss()`, `out['attack']` and `out['stage']` are not included in the optimization loss.
   - `self.attack_head` never updates during training.
2. **Dynamic $K_{\max}$ Dataset Truncation (`scripts/experiments/run_sparse_rssm.py`):**
   - `load_data(data_dir, max_h)` uses `max_h=K` rather than a fixed global maximum horizon ($K_{\max}=300$).
   - This causes test sample counts to vary from 64,755 at $K=1$ down to 63,858 at $K=300$.
3. **Hardcoded Windows Directory Paths (`scripts/experiments/run_baseline_suite.py` & results JSONs):**
   - Certain log files and scripts contain hardcoded absolute paths (`D:\network_attacks-feature-data-pipeline\...`).
   - Portable relative path resolution via `Path(__file__).resolve()` is implemented in newer runners.
4. **Empty Summary CSVs in Baseline Directory:**
   - `reports/baselines/02_logistic_regression_results.csv` and `reports/baselines/04_gru_results.csv` are 2-byte empty files (overwritten during an interrupted sweep).
   - The actual results are preserved in `07_temporal_ablation.csv` and result logs.
