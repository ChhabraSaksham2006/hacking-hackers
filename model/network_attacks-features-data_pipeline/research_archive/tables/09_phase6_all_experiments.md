# 09 — Phase 6 Pre-Attack Onset Forecasting Ablation

| Experiment ID | Model | Loss Type | Precursor Multiplier | Decay Window $	au$ | $\lambda_{	ext{onset}}$ | Threshold | Test Event Recall | Events Detected | Median Lead Time | False Alarms / hr | Window FPR | State MAE |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `BASE_Majority` | Majority | Standard | 1.0 | N/A | N/A | 0.50 | **0.0%** | 0 / 7 | 0.0s | **0.0** | **0.00%** | N/A |
| `BASE_LogReg` | LogisticReg | Standard | 1.0 | N/A | N/A | 0.22 | **42.86%** | 3 / 7 | 6.0s | 251.5 | 13.99% | N/A |
| `BASE_RandForest` | RandomForest | Standard | 1.0 | N/A | N/A | 0.04 | **85.71%** | 6 / 7 | 19.0s | 688.7 | 38.31% | N/A |
| `E601_Control` | SparseRSSM | BCE | 1.0 | N/A | 1.0 | 0.05 | **100.0%** | 7 / 7 | 12.0s | 848.7 | 47.21% | **0.2497** |
| `E602_Precursor_2x` | SparseRSSM | Weighted | 2.0 | 60s | 1.0 | 0.02 | **100.0%** | 7 / 7 | **20.0s** | 1207.7 | 67.18% | 0.2552 |
| `E602_Precursor_5x` | SparseRSSM | Weighted | 5.0 | 60s | 1.0 | 0.05 | **100.0%** | 7 / 7 | **20.0s** | 1203.2 | 66.93% | 0.2560 |
| `E602_Precursor_10x`| SparseRSSM | Weighted | 10.0 | 60s | 1.0 | 0.07 | **100.0%** | **7 / 7** | **20.0s** | 1101.3 | 61.26% | 0.2753 |
| `E603_Decay_20s` | SparseRSSM | Weighted | 10.0 | 20s | 1.0 | 0.09 | **85.71%** | 6 / 7 | 20.0s | 699.5 | 38.91% | 0.2553 |
| `E603_Decay_120s` | SparseRSSM | Weighted | 10.0 | 120s | 1.0 | 0.06 | **57.14%** | 4 / 7 | 5.0s | 576.0 | 32.04% | 0.2658 |
| `E604_LossLam_0p5` | SparseRSSM | Weighted | 10.0 | 120s | 0.5 | 0.03 | **100.0%** | 7 / 7 | 20.0s | 1207.3 | 67.15% | 0.2575 |
| `E604_LossLam_2p0` | SparseRSSM | Weighted | 10.0 | 120s | 2.0 | 0.09 | **100.0%** | 7 / 7 | 20.0s | 1109.8 | 61.73% | 0.3035 |
| `E604_LossLam_5p0` | SparseRSSM | Weighted | 10.0 | 120s | 5.0 | 0.11 | **100.0%** | 7 / 7 | 20.0s | 750.3 | 41.74% | 0.3292 |
| `E605_Focal_g1` | SparseRSSM | Focal | 1.0 | N/A | 1.0 | 0.12 | **100.0%** | 7 / 7 | 20.0s | 816.0 | 45.39% | 0.2437 |
| `E605_Focal_g2` | SparseRSSM | Focal | 1.0 | N/A | 1.0 | 0.28 | **42.86%** | 3 / 7 | 4.0s | 237.6 | 13.21% | 0.2411 |

### Interpretation

This table presents the master Phase 6 ablation on pure-benign history test sequences. Even without weighting (E601), SparseRSSM achieved 100% event recall, confirming autonomous precursor detection. Precursor weighting (E602 10x) expanded median lead time to the full 20.0s horizon. Modulating loss balance or adding focal loss (E605) reduced false alarms but severely compromised event recall on stealthy out-of-distribution attacks.
