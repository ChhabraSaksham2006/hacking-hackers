# 05 — Historical Phase 5 RSSM Benchmark (Invalidated)

| Experiment ID | Sparsity Config | Active Dims | Horizon $K$ | Test State MAE | Test State MSE | Reported Attack $F_1$ | Gradient Norm | Status & Validity |
|---|---|---|---|---|---|---|---|---|
| `rssm_sp100_k1` | Dense (1.0) | 128 / 128 | 1 | 0.2312 | 0.4510 | 0.5541 (Untrained) | 0.0000 | **INVALID** (Head omitted in loss) |
| `rssm_sp100_k10` | Dense (1.0) | 128 / 128 | 10 | 0.2845 | 0.6120 | 0.5542 (Untrained) | 0.0000 | **INVALID** (Head omitted in loss) |
| `rssm_sp100_k50` | Dense (1.0) | 128 / 128 | 50 | 0.2910 | 0.6480 | 0.5539 (Untrained) | 0.0000 | **INVALID** ($K_{	ext{train}}$ cap bug) |
| `rssm_sp100_k100`| Dense (1.0) | 128 / 128 | 100 | 0.3120 | 0.6890 | 0.5540 (Untrained) | 0.0000 | **INVALID** ($K_{	ext{train}}$ cap bug) |
| `rssm_sp100_k300`| Dense (1.0) | 128 / 128 | 300 | 0.3450 | 0.7610 | 0.5541 (Untrained) | 0.0000 | **INVALID** ($K_{	ext{train}}$ cap bug) |
| `rssm_sp10_k10`  | Top-10 (0.10) | 13 / 128 | 10 | 0.4820 | 1.1200 | 0.5540 (Untrained) | 0.0000 | **INVALID** (Numerical divergence) |
| `rssm_sp50_k10`  | Top-50 (0.50) | 64 / 128 | 10 | 0.2910 | 0.6250 | 0.5541 (Untrained) | 0.0000 | **INVALID** (Head omitted in loss) |

### Interpretation

Historical Phase 5 experiments suffered from two critical code defects: (1) `SparseRSSM.loss()` omitted binary cross-entropy on the attack forecasting head, leaving it completely untrained (gradient norm = 0.0000), and (2) training had an implicit rollout cap of K=10, causing severe extrapolation failure at K=50, 100, and 300. All Phase 5 classification results are scientifically invalid and superseded by Phase 5.5.
