# 18 — Final Research Benchmark: Model vs Baselines

| Model / Pipeline System | Architectural Family | Operational Layer | Test Event Recall | Events Detected | Window FPR | False Alarms / hr | Median Lead Time | Continuous State MAE | Continuous State MSE |
|---|---|---|---|---|---|---|---|---|---|
| **Majority Baseline** | Constant Predictor | Raw 0.50 Threshold | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s | N/A | N/A |
| **Logistic Regression** | Linear Lookback (540-D) | Calibrated 0.22 Threshold | 42.86% | 3 / 7 | 13.99% | 251.48 | 6.0s | N/A | N/A |
| **Random Forest** | Non-Linear Tree Ensemble | Calibrated 0.04 Threshold | 85.71% | 6 / 7 | 38.31% | 688.73 | 19.0s | N/A | N/A |
| **SparseRSSM (Phase 6 Raw)** | Temporal World Model | Raw 0.07 Threshold | **100.0%** | **7 / 7** | 61.26% | 1,101.27 | **20.0s** | 0.2753 | 0.6170 |
| **SparseRSSM (Phase 7 Tier 1)**| Temporal World Model | **10s Alert Cooldown** | **100.0%** | **7 / 7** | 12.74% | **229.02** | **14.0s** | **0.2766** | **0.6155** |
| **SparseRSSM (Phase 7 Tier 2)**| Temporal World Model | **30s Alert Cooldown** | **71.43%** | 5 / 7 | 4.39% | **78.95** | 6.0s | **0.2766** | **0.6155** |
| **SparseRSSM (Phase 7 Tier 3)**| Temporal World Model | **60s Alert Cooldown** | **57.14%** | 4 / 7 | **2.22%** | **39.89** | 12.0s | **0.2766** | **0.6155** |
| **SparseRSSM (Champion Agg)** | Temporal World Model | **Consec-2 + Cooldown 60s**| 28.57% | 2 / 7 | **2.20%** | **39.57** | 5.0s | **0.2766** | **0.6155** |

### Interpretation

This is the master comparative benchmark of the research project. SparseRSSM outperforms all classical baselines. Compared to Random Forest (85.71% recall, 688 FA/hr), SparseRSSM Tier 1 achieves higher recall (100.0%) with 67% fewer false alarms (229 FA/hr). Unlike static baselines, SparseRSSM concurrently outputs accurate continuous physical state rollouts (MAE=0.2766).
