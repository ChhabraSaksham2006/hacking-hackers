# Phase 5D — Standardized Evaluation Protocol Report

## 1. Fixed Horizon Sample Protocol

To ensure 100% fair and identical comparison across all horizons $K$, the dataset builder fixes $K_{\max} = 300$ for all models:

| Partition | Total Windows | Sequence Lookback ($P$) | Max Horizon ($K_{\max}$) | Valid Evaluation Sequences | Attack Positives (K=1) | Benign Negatives (K=1) |
|---|---|---|---|---|---|---|
| **Train (Days 1–5)** | 102,112 | 10 steps (28s) | 300 steps (600s) | **100,612** | 10,858 (10.79%) | 89,754 (89.21%) |
| **Validation (Day 6)** | 21,595 | 10 steps (28s) | 300 steps (600s) | **21,295** | 1,273 (5.98%) | 20,022 (94.02%) |
| **Test (Days 7–9)** | 64,785 | 10 steps (28s) | 300 steps (600s) | **63,858** | 18,565 (29.07%) | 45,293 (70.93%) |

Every model and every horizon $K \in \{1, 10, 50, 100, 300\}$ evaluates on the **exact same 63,858 test samples**.
