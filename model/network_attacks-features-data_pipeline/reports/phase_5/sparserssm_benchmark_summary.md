# Phase 5: SparseRSSM Benchmark Results Across Settings A, B, and C

## Project: SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data
**Smart India Hackathon (SIH) 2026 | NTRO Benchmark Hardening**

---

## 1. Master Comparative Benchmark Table

| Metric Domain | Primary Metric | Setting A (Seen Attacks) | Setting B (Mixed Traffic) | Setting C (Zero-Day OOD) |
| :--- | :--- | :--- | :--- | :--- |
| **State Forecasting** | Overall State MAE | **0.223383** | **0.284118** | **0.316644** |
| | Overall State MSE | **0.37786** | **0.377503** | **0.476619** |
| | Horizon $k=1$ (2s) MAE | 0.223479 | 0.278382 | 0.30998 |
| | Horizon $k=10$ (20s) MAE | 0.223339 | 0.289776 | 0.324966 |
| **Occurrence Forecast ($t+10$)** | Calibrated Threshold $\tau^*$ | $\tau=0.74$ | $\tau=0.46$ | $\tau=0.01$ |
| | **Macro F1 Score** | **0.6729** | **0.3732** | **0.5537** |
| | Precision | 0.5106 | 0.4671 | 0.3890 |
| | Recall | 0.9867 | 0.3108 | 0.9605 |
| | PR-AUC | 0.9678 | 0.4803 | 0.5100 |
| | False Positive Rate (FPR) | 0.1786 | 0.1457 | 0.6202 |
| **Threat Family** | 7-Class Macro F1 | **0.5372** | **0.1197** | **0.1688** |
| **Onset Early Warning** | **Onset Event Recall** | **0.9310** | **0.4286** | **1.0000** |
| | Median Lead Time | **20.0s** | **20.0s** | **20.0s** |
| | False Alarms / Hour | **303.68 FA/hr** | **261.93 FA/hr** | **1115.38 FA/hr** |

---

## 2. Scientific Analysis Across Settings

### Setting A (Seen Attack Generalization):
- Evaluates how accurately SparseRSSM can forecast future states and attack occurrences when recurring instances of the same attack family are encountered.
- The model achieved **F1 = 0.6729** and **Onset Event Recall = 0.9310** with a median lead time of **20.0s**.

### Setting B (Mixed Generalization):
- Evaluates enterprise deployment where the model trains on earlier operational days and forecasts subsequent operational days containing mixed known and emerging attack patterns.
- The model achieved **F1 = 0.3732** and **Onset Event Recall = 0.4286**.

### Setting C (Strict Out-of-Distribution / Zero-Day Generalization):
- Evaluates zero-day intrusion forecasting where Infiltration and Botnet threats were 100% excluded from training.
- Demonstrates generalized physical trajectory forecasting across zero-day campaigns with **Onset Event Recall = 1.0000** and a false alarm rate of **1115.38 FA/hr**.

_Generated automatically by `scripts/experiments/train_benchmark_sparserssm.py`._