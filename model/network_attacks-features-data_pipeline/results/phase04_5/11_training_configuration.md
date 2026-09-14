# 11 — Training Configuration & Execution Audit

## 1. Master Training Configuration Matrix

| Model | Variant | Dataset | Sequence Length ($P$) | Horizons ($K$) | Batch Size | Learning Rate | Optimizer | Loss Function | Epochs | Random Seed | Checkpoint Path |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Dense RSSM** | Dense 128D | Canonical 54D | 10 steps (28s) | 1, 50, 100, 200, 250, 300 | 512 | 1e-3 | AdamW | State MSE (Recon + Rollout) | 5 / 10 | 42 | `results_final_selected_k/sparse_rssm/dense/k*/checkpoint.pt` |
| **Sparse RSSM** | Top-50 (64D) | Canonical 54D | 10 steps (28s) | 1, 50, 100 | 512 | 1e-3 | AdamW | State MSE (Recon + Rollout) | 5 | 42 | `results_selected_benchmark/sparse_rssm/top50/k*/checkpoint.pt` |
| **Sparse RSSM** | Top-10 (13D) | Canonical 54D | 10 steps (28s) | 1, 50, 100 | 512 | 1e-3 | AdamW | State MSE (Recon + Rollout) | 5 | 42 | `results_selected_benchmark/sparse_rssm/top10/k*/checkpoint.pt` |
| **Random Forest** | Static 54D | Canonical 54D | 1 step (10s) | 1, 50, 100, 200, 250, 300 | N/A | N/A | Scikit-Learn | Gini Impurity (100 Trees) | N/A | 42 | In-memory |
| **Logistic Reg.** | Static 54D | Canonical 54D | 1 step (10s) | 1, 50, 100 | N/A | N/A | L-BFGS | Logistic Loss (BCE) | 500 iter | 42 | In-memory |
| **Transformer** | Full 10step | Canonical 54D | 10 steps (28s) | 1, 50, 100 | 256 | 1e-3 | AdamW | Multi-head BCE + MSE | 10 | 42 | In-memory |
