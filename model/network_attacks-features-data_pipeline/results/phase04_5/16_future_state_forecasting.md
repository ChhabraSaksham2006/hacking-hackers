# 16 — Continuous Future-State Forecasting Audit

## 1. Continuous State Prediction Objective

In addition to binary attack classification, the system models the continuous evolution of the physical network state:
$$\hat{S}_{t+K} = 	ext{StateDecoder}(z_{t+K})$$
where $S \in \mathbb{R}^{54}$ represents normalized physical telemetry.

## 2. Verified State Forecasting Errors

| Model | Horizon ($K$) | Lead Time | Val State MSE | Test State MAE | Test State RMSE | Source |
|---|---|---|---|---|---|---|
| **Persistence** | $K=1$ | 2.0s | N/A | **0.1924** | **0.7909** | `05_feature_group_state_errors.csv` |
| **Persistence** | $K=3$ | 6.0s | N/A | 0.2743 | 0.9374 | `05_feature_group_state_errors.csv` |
| **Persistence** | $K=5$ | 10.0s | N/A | 0.3342 | 1.1157 | `05_feature_group_state_errors.csv` |
| **Persistence** | $K=10$ | 20.0s | N/A | 0.3243 | 1.0368 | `05_feature_group_state_errors.csv` |
| **Temporal Transformer** | $K=100$ | 200.0s | N/A | 0.2880 | 0.7910 | `05_transformer_results.csv` |
| **Dense RSSM** | $K=1$ | 2.0s | **0.3607** | N/A | N/A | `metrics.json` |
| **Dense RSSM** | $K=50$ | 100.0s | 0.5930 | N/A | N/A | `metrics.json` |
| **Dense RSSM** | $K=100$ | 200.0s | 0.6087 | N/A | N/A | `metrics.json` |
| **Dense RSSM** | $K=200$ | 400.0s | 0.6171 | N/A | N/A | `metrics.json` |
| **Dense RSSM** | $K=300$ | 600.0s | 0.6279 | N/A | N/A | `metrics.json` |
| **Sparse RSSM Top-50** | $K=1$ | 2.0s | 0.4006 | N/A | N/A | `metrics.json` |
| **Sparse RSSM Top-50** | $K=100$ | 200.0s | 0.6117 | N/A | N/A | `metrics.json` |
| **Sparse RSSM Top-10** | $K=1$ | 2.0s | 0.4115 | N/A | N/A | `metrics.json` |
| **Sparse RSSM Top-10** | $K=100$ | 200.0s | **1.0e+99** (Diverged) | N/A | N/A | `metrics.json` |

## 3. Findings

1. Dense RSSM validation state MSE increases monotonically with horizon ($0.3607 	o 0.6279$), verifying that continuous rollout error compounds over recursive steps.
2. Sparse RSSM Top-10 at $K=100$ suffered numerical divergence (`val_state_mse = 1e99`), proving that 10% sparsity (13 dims) without stabilizing regularizers is unstable over 100 recursive rollout steps.
3. Test-set continuous state MAE was not saved in RSSM `metrics.json`; only validation MSE was tracked.
