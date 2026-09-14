# 15 — Pre-Onset Attack Forecasting Audit

## 1. Definition of Pre-Onset Forecasting

A genuine attack early-warning forecaster must predict attack onset ahead of time from benign baseline conditions:
$$	ext{Condition: } Y_t = 0 \quad (	ext{Current state is BENIGN})$$
$$	ext{Target: } Y_{t+K} = 1 \quad (	ext{Attack begins within } K 	ext{ steps})$$

## 2. Persistence on Pre-Onset Transitions

When evaluated strictly on pre-onset windows ($Y_t = 0, Y_{t+K} = 1$), Persistence fails completely:

| Test Split | Horizon ($K$) | Lead Time | Pre-Onset Positive Events | Persistence Recall | Persistence Precision | Persistence F1 |
|---|---|---|---|---|---|---|
| **Test (Infiltration)** | $K=1$ | 2.0s | 4 | **0.0000** | **0.0000** | **0.0000** |
| **Test (Infiltration)** | $K=10$ | 20.0s | 40 | **0.0000** | **0.0000** | **0.0000** |
| **Test (Botnet)** | $K=1$ | 2.0s | 3 | **0.0000** | **0.0000** | **0.0000** |
| **Test (Botnet)** | $K=10$ | 20.0s | 12 | **0.0000** | **0.0000** | **0.0000** |
| **Total Test** | $K=1$ | 2.0s | 7 | **0.0000** | **0.0000** | **0.0000** |
| **Total Test** | $K=10$ | 20.0s | 52 | **0.0000** | **0.0000** | **0.0000** |

## 3. ML & RSSM Pre-Onset Implementation Status

> [!IMPORTANT]
> **Implementation Status: NOT IMPLEMENTED FOR ML / RSSM MODELS.**
> While pre-onset evaluation was mathematically audited for the Persistence baseline in Phase 4.5 (`reports/phase_4_5/03_pre_onset_evaluation.csv`), dedicated pre-onset evaluation slices were NOT integrated into `run_sparse_rssm.py` or `run_baseline_suite.py`. All reported ML/RSSM metrics reflect full-test continuation evaluations.
