# 03 — Authoritative Baseline Suite Comparison

| Model / Algorithm | Horizon $K$ | Lead Time | Precision | Recall | $F_1$ Score | PR-AUC | ROC-AUC | Window FPR | False Alarms/hr |
|---|---|---|---|---|---|---|---|---|---|
| **Majority Baseline** | 1 | 2.0s | 0.00% | 0.00% | 0.0000 | 0.2912 | 0.5000 | 0.00% | 0.00 |
| **Persistence Forecaster** | 1 | 2.0s | **99.96%** | **99.96%** | **0.9996** | **0.9997** | **0.9997** | **0.02%** | **0.20** |
| **Persistence Forecaster** | 10 | 20.0s | **99.65%** | **99.65%** | **0.9965** | **0.9970** | **0.9976** | **0.14%** | **1.81** |
| **Persistence Forecaster** | 50 | 100.0s | **98.61%** | **98.61%** | **0.9861** | **0.9881** | **0.9902** | **0.57%** | **7.27** |
| **Logistic Regression** | 1 | 2.0s | 80.75% | 11.93% | 0.2078 | 0.5447 | 0.7548 | 1.17% | 14.91 |
| **Logistic Regression** | 10 | 20.0s | 62.62% | 4.85% | 0.0901 | 0.4230 | 0.6902 | 1.19% | 15.18 |
| **Logistic Regression** | 50 | 100.0s | 58.59% | 3.23% | 0.0612 | 0.3238 | 0.4901 | 0.94% | 11.95 |
| **Random Forest** | 1 | 2.0s | 93.68% | 11.42% | 0.2035 | 0.6451 | 0.8136 | 0.32% | 4.04 |
| **Random Forest** | 10 | 20.0s | 40.60% | 89.67% | 0.5589 | 0.5843 | 0.7796 | 53.91% | 687.73 |
| **Random Forest** | 50 | 100.0s | 72.50% | 19.99% | 0.3134 | 0.6329 | 0.7951 | 3.12% | 39.76 |

### Interpretation

This table presents the authoritative baseline benchmark re-evaluated in Phase 5.5 across 64,608 test sequences. Persistence dominates standard window-level metrics due to continuation autocorrelation. Random Forest achieves high recall at K=10 (89.67%) but generates massive false positive rates (53.91%, 687.7 false alarms/hr). Linear models degrade rapidly as the forecast horizon expands.
