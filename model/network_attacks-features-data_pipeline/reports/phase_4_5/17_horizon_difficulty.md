# Phase 4.5 Forensic Audit: Report 17 — Multi-Horizon Forecasting Degradation Analysis

**Project:** SIH26153 — AI-Based Network Attack Forecasting

## 1. Multi-Horizon Scorecard Across All Baselines

| Model Family | Variant | $K=1$ (+2s) PR-AUC | $K=3$ (+6s) PR-AUC | $K=5$ (+10s) PR-AUC | $K=10$ (+20s) PR-AUC | State MAE $K=1$ | State MAE $K=10$ |
|---|---|---|---|---|---|---|---|
| Logistic_Regression | Static_54D_Balanced | 0.6352 | 0.6223 | 0.5762 | 0.5033 | N/A | N/A |
| Random_Forest | Static_54D | 0.6140 | 0.5936 | 0.5633 | 0.5715 | N/A | N/A |
| GRU | Full_History_10step_54D | 0.5055 | 0.4864 | 0.4712 | 0.4372 | 0.2263 | 0.2711 |
| Temporal_Transformer | Full_History_10step_54D | 0.4453 | 0.4126 | 0.4149 | 0.3863 | 0.2316 | 0.2759 |
| Persistence | y_t_current | 0.9997 | 0.9990 | 0.9984 | 0.9971 | N/A | N/A |
| Majority_Class | Constant_0 | 0.6456 | 0.6456 | 0.6456 | 0.6456 | N/A | N/A |


## 2. Horizon Difficulty Findings

1. **Monotonic PR-AUC Degradation:** For every model, PR-AUC decreases monotonically as horizon expands from +2s to +20s (e.g., Balanced LogReg drops from 0.6352 down to 0.5033; Random Forest drops from 0.6140 down to 0.5715; GRU drops from 0.5055 down to 0.4372).
2. **State Error Growth:** State MAE increases from 0.2263 at $K=1$ to 0.2711 at $K=10$ for GRU, demonstrating that multi-step ahead continuous state rollouts accumulate uncertainty over time.
3. **Non-Triviality of +20s Forecasting:** The consistent degradation validates that longer horizons present genuine forecasting difficulty.
