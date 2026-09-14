# Final Comparative Benchmark

## SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Rigorous Separation of Evaluation Tasks: Continuation vs Onset Early Warning**

---

## 1. The Critical Distinction Between Evaluation Tasks

A central finding of this research is that naive window classification metrics (such as Precision, Recall, and $F_1$) are fundamentally deceptive when evaluated on datasets with long contiguous attack sessions. Models must be benchmarked under their proper task category:

- **Task A (Continuation Classification):** Evaluated over all sequences regardless of history. Attack sessions last 500–700 minutes; persistence achieves $F_1 \approx 0.9996$ simply by repeating the active label.
- **Task B (Pre-Attack Onset Early Warning):** Evaluated strictly on pure-benign history sequences ($\max y_{t-9:t} = 0$). Tests whether a model anticipates the attack before any malicious traffic manifests.
- **Task C (Continuous Physical State Forecasting):** Measures multi-step autoregressive rollout error ($S_t \to \hat{S}_{t+K}$) across physical network dimensions.

---

## 2. Comprehensive Multi-Task Benchmark Table

| Model / Algorithm | Task Category | Forecast Horizon | Window Precision | Window Recall | Window $F_1$ | Test Event Recall | Events Detected | Window FPR | False Alarms / hr | Median Lead Time | State MAE | State MSE |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Majority Baseline** | Task A (Continuation) | 2.0s ($K=1$) | 0.00% | 0.00% | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s | N/A | N/A |
| **Majority Baseline** | Task B (Pre-Onset) | 20.0s ($K=10$) | 0.00% | 0.00% | 0.0000 | 0.0% | 0 / 7 | 0.00% | 0.00 | 0.0s | N/A | N/A |
| **Persistence Forecaster**| Task A (Continuation) | 2.0s ($K=1$) | **99.96%** | **99.96%** | **0.9996** | N/A | N/A | **0.02%** | **0.20** | 0.0s | N/A | N/A |
| **Persistence Forecaster**| Task A (Continuation) | 20.0s ($K=10$)| **99.65%** | **99.65%** | **0.9965** | N/A | N/A | **0.14%** | **1.81** | 0.0s | N/A | N/A |
| **Persistence Forecaster**| Task B (Pre-Onset) | 20.0s ($K=10$)| 0.00% | 0.00% | 0.0000 | **0.0%** | **0 / 7** | **0.00%** | **0.00** | **0.0s** | N/A | N/A |
| **Logistic Regression** | Task A (Continuation) | 2.0s ($K=1$) | 80.75% | 11.93% | 0.2078 | N/A | N/A | 1.17% | 14.91 | N/A | N/A | N/A |
| **Logistic Regression** | Task B (Pre-Onset) | 20.0s ($K=10$)| 0.24% | 27.27% | 0.0047 | **42.86%** | 3 / 7 | 13.99% | 251.48 | 6.0s | N/A | N/A |
| **Random Forest** | Task A (Continuation) | 2.0s ($K=1$) | **93.68%** | 11.42% | 0.2035 | N/A | N/A | 0.32% | 4.04 | N/A | N/A | N/A |
| **Random Forest** | Task A (Continuation) | 20.0s ($K=10$)| 40.60% | **89.67%** | 0.5589 | N/A | N/A | 53.91% | 687.73 | N/A | N/A | N/A |
| **Random Forest** | Task B (Pre-Onset) | 20.0s ($K=10$)| 0.19% | 61.82% | 0.0039 | **85.71%** | 6 / 7 | 38.31% | 688.73 | 19.0s | N/A | N/A |
| **SparseRSSM (Phase 5.5)** | Task A (Continuation) | 20.0s ($K=10$)| 47.23% | 49.47% | 0.4832 | N/A | N/A | 22.70% | 289.66 | 20.0s | 0.2920 | 0.6456 |
| **SparseRSSM (Phase 6 Raw)**| Task B (Pre-Onset) | 20.0s ($K=10$)| 0.20% | **100.0%** | 0.0039 | **100.0%** | **7 / 7** | 61.26% | 1101.27 | **20.0s** | **0.2753** | **0.6170** |
| **SparseRSSM (Phase 7 Tier 1)**| **Task B (Early Warning)**| **20.0s ($K=10$)**| 0.20% | **100.0%** | 0.0039 | **100.0%** | **7 / 7** | **12.74%** | **229.02** | **14.0s** | **0.2766** | **0.6155** |
| **SparseRSSM (Phase 7 Tier 2)**| **Task B (Early Warning)**| **20.0s ($K=10$)**| 0.22% | 71.43% | 0.0042 | **71.43%** | 5 / 7 | **4.39%** | **78.95** | **6.0s** | **0.2766** | **0.6155** |
| **SparseRSSM (Phase 7 Tier 3)**| **Task B (Early Warning)**| **20.0s ($K=10$)**| 0.23% | 57.14% | 0.0045 | **57.14%** | 4 / 7 | **2.22%** | **39.89** | **12.0s** | **0.2766** | **0.6155** |
| **SparseRSSM (Champion Agg)** | **Task B (Early Warning)**| **20.0s ($K=10$)**| 0.20% | 3.64% | 0.0038 | **28.57%** | 2 / 7 | **2.20%** | **39.57** | **5.0s** | **0.2766** | **0.6155** |

---

## 3. Detailed Comparative Findings

1. **Why Persistence Fails Operationally:**
   - Persistence achieves $F_1 = 0.9996$ on the continuation task because 99.96% of positive windows occur in prolonged bursts.
   - On the early warning task, Persistence achieves 0.0% recall with 0.0s lead time. It never raises an alert before an attack begins.

2. **Why SparseRSSM Outperforms Random Forest:**
   - On the early warning task, Random Forest achieves 85.71% event recall (detecting 6/7 episodes), but at an unacceptable false alarm rate of 688.73 FA/hr (FPR = 38.31%).
   - SparseRSSM Tier 1 achieves **100.0% event recall (detecting 7/7 episodes)** while generating **only 229.02 FA/hr**—a 67% reduction in false alarms compared to Random Forest.
   - Random Forest cannot forecast future continuous state vectors. SparseRSSM accurately rolls out 54-D physical network telemetry (MAE = 0.2766), providing the physical basis for behavioral explanation.
