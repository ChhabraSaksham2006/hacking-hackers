# Phase 4.5 Forensic Audit: Report 24 — Baseline Reproducibility Audit & Configurations

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Reproducibility Configuration Matrix

| Model Family | Architectures / Variants | Random Seed | Input Dimensions | Sequence Length | Batch Size | Learning Rate | Optimal Epochs / Convergence |
|---|---|---|---|---|---|---|---|
| **Majority Class** | Constant 0 | 42 | N/A | N/A | N/A | N/A | Instant |
| **Persistence** | $y_{t+K} = y_t$ | 42 | N/A | 1 | N/A | N/A | Instant |
| **Logistic Regression** | Static 54D, 37D, Flattened 540D, Balanced | 42 | 54, 37, 540 | 1 or 10 | Full | L-BFGS | Converted at Max Iter = 500 |
| **Random Forest** | Static 54D, 37D, Flattened 540D | 42 | 54, 37, 540 | 1 or 10 | 100 Trees | Depth=15 | Parallelized across all CPU cores |
| **GRU Forecaster** | Full 54D, Base 37D, Short 3-step, Weighted | 42 | 54, 37 | 10 or 3 | 256 | 0.001 (AdamW) | Early stopping patience=4, ~10 epochs |
| **Transformer** | Full 54D, Base 37D, Short 3-step, Weighted | 42 | 54, 37 | 10 or 3 | 256 | 0.001 (AdamW) | Early stopping patience=4, ~8 epochs |

